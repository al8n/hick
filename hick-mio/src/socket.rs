//! The mio socket pair: bind + multicast join, cmsg-aware receive, the Windows
//! AFD re-arm, and a strictly non-blocking send.
//!
//! This is the only module in the crate that touches the operating system, and
//! it is where two facts specific to a *synchronous, readiness-based* driver
//! live.
//!
//! **The Windows AFD re-arm.** mio documents that all I/O on an `IoSource` must
//! go through `IoSource::do_io`. On Unix that is a passthrough — epoll/kqueue
//! readiness is the kernel's business — but on Windows `do_io` re-arms the AFD
//! registration whenever the operation returns `WouldBlock`. We read with
//! `hick_udp::recv_with_meta` on the *raw* socket so we recover the cmsg
//! metadata (`PKTINFO`, TTL, receive timestamp) that `mio::net::UdpSocket` has
//! no API for, which bypasses `do_io` entirely. [`rearm_readiness`] performs the
//! same re-arm by hand; without it Windows would report each socket readable
//! exactly once and the responder would go permanently deaf. Sends go through
//! `mio::net::UdpSocket::send_to`, which *is* `do_io`-wrapped, so mio re-arms
//! those itself and we must not duplicate it there.
//!
//! **A refused send is over.** A `send_to` that returns `WouldBlock` handed
//! **nothing** to the kernel, so abandoning that attempt is a *fact*, not a
//! guess: the family reports [`SendOutcome::Failed`], the driver reports it to
//! the core as `Missed`, and the core re-arms the same datagram on its own
//! schedule. Nothing is parked, nothing is retried behind the core's back, and
//! `WRITABLE` is never armed — the registration is `READABLE` for the life of
//! the socket.
//!
//! That licence belongs to readiness I/O specifically. A completion-based driver
//! submits the operation to the kernel *before* it waits, so abandoning the wait
//! does not abandon the datagram; `hick-compio` therefore awaits every send to
//! completion. Do not carry that shape back into this module.

use std::{
  io,
  net::{SocketAddr, SocketAddrV4, SocketAddrV6},
  time::{Instant as StdInstant, SystemTime},
};

use hick_udp::{
  MulticastOptionsV4, MulticastOptionsV6, RecvMeta,
  constants::{MDNS_IPV4_GROUP, MDNS_IPV6_GROUP, MDNS_PORT},
  try_bind_v4, try_bind_v6, try_join_v4, try_join_v6,
};
use mio::{Interest, Registry, Token, net::UdpSocket};

use crate::{error::ServerError, options::ServerOptions};

/// RFC 6762 §3 IPv4 destination for every multicast mDNS transmit.
pub(crate) const MDNS_V4_DST: SocketAddr =
  SocketAddr::V4(SocketAddrV4::new(MDNS_IPV4_GROUP, MDNS_PORT));

/// RFC 6762 §3 IPv6 destination. Scope id `0`: the socket's `IPV6_MULTICAST_IF`
/// (set by [`MulticastOptionsV6`]) already pins the egress interface, so a
/// per-datagram scope would be redundant. Same value `hick-reactor` uses.
pub(crate) const MDNS_V6_DST: SocketAddr =
  SocketAddr::V6(SocketAddrV6::new(MDNS_IPV6_GROUP, MDNS_PORT, 0, 0));

/// How many datagrams one [`Sockets::recv`] call may consume-and-discard
/// (oversized or unparseable) or retry after `EINTR` before handing control
/// back to the caller.
///
/// Each such datagram is already out of the kernel queue, so looping is what
/// makes progress — but `recv` runs inside the caller's own event loop, and an
/// unbounded loop would let a peer flooding oversized datagrams starve every
/// other token the caller is polling. On exhaustion `recv` returns `None` with
/// the readable flag still set, so [`Sockets::has_readable`] keeps reporting
/// work and the drain resumes on the next tick.
///
/// **Per `recv` call, not per tick**, and therefore composed with
/// [`RECV_BUDGET`](crate::driver::RECV_BUDGET), which bounds how many times one
/// [`Mdns::tick`](crate::Mdns::tick) calls [`Sockets::recv`]: the two multiply,
/// so a tick facing an interleaved oversized/valid stream can reach ~4096
/// `recvmsg` calls. See `RECV_BUDGET` for why that product is accepted rather
/// than capped.
pub(crate) const MAX_DISCARDED_PER_RECV: usize = 64;

/// Transient receive errors one family may return, within one
/// [`Mdns::tick`](crate::Mdns::tick), before [`Sockets::recv`] stops selecting
/// it for the rest of that tick.
///
/// A non-consuming receive error (`ENOBUFS`, Windows `WSAECONNRESET` after an
/// ICMP port-unreachable for one of our own sends) says nothing about whether
/// the kernel queue is empty, so the flag must **not** be cleared: under
/// edge-triggered readiness an already-queued datagram behind the error
/// generates no second edge, and clearing readiness without having drained to
/// `WouldBlock` leaves the family deaf with nothing to wake it. Retrying is
/// therefore the only thing that makes progress.
///
/// The cap is what keeps that retry bounded. A family that exhausts it keeps
/// `readable` set — so the drain resumes — but drops out of
/// [`Sockets::has_readable`], so the caller takes
/// [`Sockets::recv_error_backoff_level`]'s bounded wakeup instead of a zero
/// timeout that would spin a core on a socket erroring every time.
pub(crate) const MAX_RECV_ERRORS_PER_ROUND: u32 = 4;

/// Serialises every test in the crate that binds a real socket.
///
/// [`Sockets::bind`] always lands on the fixed mDNS port and joins the same
/// group, so two live pairs share one `SO_REUSEPORT` group. macOS then delivers
/// a datagram sent to that group to only **one** of them, which made
/// `readiness_is_recorded_then_cleared_by_draining_to_wouldblock` fail about
/// half the time under `cargo test`'s default parallelism: our own loopback copy
/// landed in another test's socket. One binder at a time removes the contention.
/// These tests take microseconds, so the serialisation costs nothing.
///
/// It lives here, not in a test module, because every module whose tests bind —
/// `socket/tests.rs`, `endpoint/tests.rs`, `driver/tests.rs` — shares one test
/// binary and therefore must share one lock.
#[cfg(test)]
pub(crate) static BIND_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Which of the two sockets an operation applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
  V4,
  V6,
}

impl Family {
  /// The family a destination address belongs to.
  const fn of(dst: SocketAddr) -> Self {
    match dst {
      SocketAddr::V4(_) => Self::V4,
      SocketAddr::V6(_) => Self::V6,
    }
  }

  /// `via_v4` in the shape `recv` and the trace fields want.
  pub(crate) const fn is_v4(self) -> bool {
    matches!(self, Self::V4)
  }

  /// This family's index in every per-family array, matching
  /// [`mdns_proto::TransmitDelivery`]'s own ordering so a driver-side array and
  /// a confirm can never be indexed differently.
  pub(crate) const fn index(self) -> usize {
    match self {
      Self::V4 => 0,
      Self::V6 => 1,
    }
  }

  /// The family this one is not.
  const fn other(self) -> Self {
    match self {
      Self::V4 => Self::V6,
      Self::V6 => Self::V4,
    }
  }
}

/// Round-robin cursor over the two receive sockets.
///
/// Which socket [`Sockets::recv`] reads has to rotate, and a per-tick receive
/// budget does not make it rotate. `readable` clears only on `WouldBlock`, so a
/// family under a sustained on-link flood is readable at the top of *every*
/// tick; a fixed preference then spends every tick's whole budget on it and the
/// other family's questions, answers and conflict probes never reach the proto
/// layer at all. The budget bounds the work inside one tick and says nothing
/// about which family wins the next one.
///
/// The rotation is on **selection**, not on a successful read, and that is what
/// makes it hold under every outcome. One `recv` call performs at most one
/// usable read before returning, so with both families readable the calls
/// strictly alternate; a selection that turns out to be `WouldBlock`, an
/// oversized discard, or a transient error has still moved the cursor, so it
/// cannot be repeated in a loop either.
///
/// Preference never means idling: a preferred family that is not readable falls
/// through to the other one, so a single-family endpoint reads on every call.
#[derive(Debug, Clone, Copy)]
struct RecvRotor {
  /// The family the next selection prefers.
  next: Family,
}

impl RecvRotor {
  const fn new() -> Self {
    Self { next: Family::V4 }
  }

  /// The family to read from, given which are currently flagged readable.
  /// `None` when neither is.
  fn pick(&mut self, v4_readable: bool, v6_readable: bool) -> Option<Family> {
    let readable = |f: Family| match f {
      Family::V4 => v4_readable,
      Family::V6 => v6_readable,
    };
    let picked = if readable(self.next) {
      self.next
    } else if readable(self.next.other()) {
      self.next.other()
    } else {
      return None;
    };
    self.next = picked.other();
    Some(picked)
  }
}

/// Outcome of one family's send.
///
/// The four are the whole vocabulary, and none may be collapsed into another:
/// the driver maps them one-to-one onto [`mdns_proto::FamilyDelivery`], and the
/// §10.1 withdrawal pump maps them onto per-family goodbye debt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
  /// The datagram reached the kernel, carrying the two stamps taken immediately
  /// **before** the `send_to` — never after it.
  ///
  /// The [`SystemTime`] is the self-send credit's stamp, and the direction is
  /// what makes the credit usable: an entry stamped early can never postdate the
  /// kernel's stamp on the multicast loopback copy, so the tracker's
  /// `sent <= kernel rx` test still admits our own copy. One exception is worth
  /// naming: [`send_with_eintr_retry`] retries once on `EINTR`, so on that path
  /// the stamp precedes the attempt that actually succeeded by one interrupted
  /// syscall. Early is the safe side, at the cost of one extra syscall's worth
  /// of window in which a byte-identical peer datagram could take the credit —
  /// sub-microsecond, and bounded above by `SELF_SEND_TTL` either way.
  ///
  /// The [`StdInstant`] is **this family's own acceptance instant**, which the
  /// driver needs for two things a single post-fan-out clock read would get
  /// wrong: the per-family wire gate
  /// ([`FamilyWireGate`](crate::driver::FamilyWireGate)) records the family that
  /// actually carried the datagram, and the confirm anchors at the *earliest*
  /// acceptance across families so no delivered family's refresh schedule is
  /// backdated by however long the other family took.
  Sent(SystemTime, StdInstant),
  /// A bound socket was **not offered** the datagram, because the caller's
  /// per-producer wire gate had not yet paid this family the minimum gap the
  /// core asked for ([`Transmit::min_family_gap`](mdns_proto::Transmit)).
  ///
  /// Obligated and did not carry it, exactly like [`SendOutcome::Failed`] — but
  /// it is this driver's own deliberate spacing rather than an I/O error, so it
  /// bumps no error counter and is no evidence at all about the link. **The
  /// socket layer only reports it; the decision is the caller's**, handed in as
  /// the `allow` mask.
  Gated,
  /// A bound socket did not carry it, and nothing here will retry it. Three
  /// paths reach this, and the first is the one that matters:
  ///
  /// * `WouldBlock` — the send buffer is full. **Nothing was handed to the
  ///   kernel**, so this is a definitive non-delivery rather than an unknown
  ///   fate, and the core re-arms the same datagram on its own schedule. It is
  ///   not counted as `send_errors`: backpressure is not an error.
  /// * a `send_to` the kernel rejected for some other reason — `ENETUNREACH`
  ///   when a family's route goes away, `ENOBUFS`, `EPERM` from a local
  ///   firewall, `EMSGSIZE`. `send_errors` is bumped.
  /// * [`Sockets::send_one`] called with a `dst` whose family is not the one
  ///   selected. **Nothing was attempted at all** — that guard fires before
  ///   boundness is even checked, so the family may or may not be bound — and it
  ///   is deliberately NOT counted as `send_errors`, because a caller-error
  ///   guard is not a network failure. No call site in this crate produces it.
  ///
  /// The §10.1 withdrawal pump maps this to a retry, never a write-off: see
  /// [`SendOutcome::NoSocket`], which exists precisely so the two can differ.
  Failed,
  /// Nothing was attempted on this family: it is **not bound**, or it is **not
  /// applicable to this destination** (the family a unicast destination did not
  /// select, which on a dual-stack host is reported even though that socket is
  /// bound and healthy).
  ///
  /// Distinct from [`SendOutcome::Failed`] on purpose. The §10.1 withdrawal
  /// pump keeps a per-family goodbye debt: a bound family that failed must
  /// retry (`WithdrawalSend::Retry`), while a family that was never attempted
  /// must be written off so its debt never pins the withdrawal past the other
  /// family. Conflating the two frees the route while a bound family still owes
  /// its goodbye, stranding that family's peers on stale positive-TTL records.
  NoSocket,
}

impl SendOutcome {
  /// This family's own acceptance instant, if it accepted the datagram.
  pub(crate) const fn accepted_at(self) -> Option<StdInstant> {
    match self {
      Self::Sent(_, at) => Some(at),
      _ => None,
    }
  }
}

/// The result of one logical [`Sockets::send_to`]: what each family did with the
/// datagram, and whether the datagram is one that comes back.
///
/// An mDNS multicast transmit is **two** syscalls and therefore **two**
/// multicast loopback copies, one per joined socket. Reporting the families
/// separately is what lets the caller record one self-send credit per actual
/// syscall — a single merged outcome would leave one loopback copy uncredited,
/// and the take-once tracker would then ingest it as a peer datagram and see a
/// phantom conflict against itself. It is also what the core's per-family
/// confirm is made of: which family missed decides when the next announcement is
/// due on which link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SendReport {
  pub(crate) v4: SendOutcome,
  pub(crate) v6: SendOutcome,
  /// This datagram went to a multicast group this endpoint joined, so the
  /// kernel hands a copy back per family that carried it and each such copy
  /// needs a self-send credit.
  ///
  /// Carried here rather than re-derived by the caller so the credit and the
  /// syscalls it accounts for come from **one** classification of the
  /// destination — [`is_mdns_multicast`], the same test that decides the
  /// fan-out. A unicast reply (RFC 6762 §6.7 legacy, or a directed response)
  /// leaves for the querier's own address and never returns, so a credit
  /// recorded for it could never be consumed; see
  /// [`send_and_credit`](crate::driver::send_and_credit) for why an unclaimable
  /// credit is worse than no credit.
  pub(crate) loops_back: bool,
}

impl SendReport {
  /// Each family paired with its own outcome, so a caller that must act per
  /// family (a self-send credit per loopback copy, a per-family delivery
  /// result) never has to re-derive which socket an outcome came from.
  pub(crate) fn per_family(&self) -> [(Family, SendOutcome); 2] {
    [(Family::V4, self.v4), (Family::V6, self.v6)]
  }
}

/// Which bound families a send may be offered, indexed by [`Family::index`].
///
/// The caller's per-producer wire gate is the only thing that closes an entry;
/// see [`SendOutcome::Gated`]. `[true, true]` is the ungated case and the only
/// value the RFC 6762 §10.1 withdrawal pump ever uses.
pub(crate) type FamilyAllow = [bool; 2];

/// Both families open — a one-shot datagram, or a goodbye.
pub(crate) const ALLOW_BOTH: FamilyAllow = [true, true];

/// One bound family: the socket plus the readiness bookkeeping the caller's
/// `Poll` does not keep for us.
struct BoundSocket {
  sock: UdpSocket,
  /// `Some` exactly while this socket is registered in the caller's `Registry`.
  token: Option<Token>,
  /// The interest registered with the selector. Always [`Interest::READABLE`]:
  /// a `WouldBlock` send is a definitive non-delivery this driver reports at
  /// once, so there is no parked datagram for `WRITABLE` to wake and arming it
  /// would only spin the caller's `Poll` on an always-writable socket.
  interest: Interest,
  /// The registration the selector holds for this socket is not the one we
  /// need, and the call that would have fixed it failed: a receive re-arm that
  /// failed in [`Sockets::recv`].
  ///
  /// The recovery is a *re-registration*, not a flag: the interest we want is
  /// the plain `READABLE` already recorded, and the point of the retry is the
  /// edge the `reregister` regenerates rather than the interest it sets — which
  /// is why [`Sockets::retry_stale_registrations`] cannot short-circuit on
  /// "the interest is already what we want".
  interest_stale: bool,
  /// mio reported this socket readable and we have not since drained it to
  /// `WouldBlock`.
  readable: bool,
  /// Non-consuming transient receive errors on this family in the current
  /// receive round (one round per [`Mdns::tick`](crate::Mdns::tick)). Reset by
  /// [`Sockets::begin_recv_round`], and by any read that proves something about
  /// the kernel queue — a datagram, or the `WouldBlock` that says it is empty.
  /// At [`MAX_RECV_ERRORS_PER_ROUND`] the family stops being selected for the
  /// rest of the round.
  recv_error_streak: u32,
  /// Consecutive receive rounds this family ended having exhausted
  /// [`MAX_RECV_ERRORS_PER_ROUND`]. Drives the escalating wakeup backoff so a
  /// socket erroring on every call costs a bounded trickle of wakeups rather
  /// than a core. Reset alongside `recv_error_streak` by a read that reaches
  /// the kernel queue.
  recv_error_rounds: u32,
  /// This family's receive path failed **structurally** — see
  /// [`is_permanent_recv_error`] — so it is never read again.
  ///
  /// One-way for the life of the socket, and deliberately so: the errors that
  /// set it describe the socket itself rather than the traffic on it, and there
  /// is no event that would prove one had gone away. Retrying instead is what
  /// leaves the family silently deaf while every public accessor still calls it
  /// bound, which is why this is surfaced through
  /// [`Mdns::degraded_families`](crate::Mdns::degraded_families).
  ///
  /// The send path is untouched: a socket that cannot receive can still put
  /// datagrams on the wire, and a responder that has gone deaf but still
  /// announces is strictly better for its peers than one that also goes silent.
  recv_dead: bool,
  /// Make the next [`BoundSocket::rearm`] fail. The re-arm is a no-op on every
  /// non-Windows target and cannot be made to fail from a test on Windows
  /// either, so the deafness it guards against is otherwise unreachable in a
  /// unit test — and it is exactly the path that must not be left untested.
  #[cfg(test)]
  force_rearm_error: bool,
  /// Fail this family's next `n` raw receives with a synthetic transient error.
  /// `ENOBUFS` and a Windows `WSAECONNRESET` are not reproducible against a
  /// healthy loopback socket, and the retain-readiness-and-retry path they
  /// drive is exactly the one whose absence leaves a family permanently deaf.
  #[cfg(test)]
  forced_recv_errors: u32,
  /// Fail this family's receives with a synthetic **permanent** error. A
  /// healthy socket cannot be made to return `ENOTCONN` on demand either, and
  /// the give-up path is the one that must not be reached by an error that is
  /// merely transient.
  #[cfg(test)]
  forced_permanent_recv_error: bool,
  /// Make every send on this family answer `WouldBlock`.
  ///
  /// A real full send buffer is not reproducible against a healthy loopback
  /// socket, and the `WouldBlock` path is the whole subject of this driver's
  /// send design: it is a *definitive* non-delivery, reported to the core at
  /// once rather than parked. Everything that hangs off that — the family
  /// reported `Missed`, the lifecycle phase held back, the failure streak that
  /// eventually writes the family off — is unreachable in a test without it.
  #[cfg(test)]
  forced_send_wouldblock: bool,
  /// Successful `reregister` calls, counted so a test can tell an interest
  /// toggle that was actually issued from one short-circuited as unchanged.
  /// That difference is the whole of the receive re-arm retry, and it is
  /// invisible from outside: the interest before and after is the same value.
  #[cfg(test)]
  reregisters: u32,
}

impl BoundSocket {
  fn new(sock: UdpSocket) -> Self {
    Self {
      sock,
      token: None,
      interest: Interest::READABLE,
      interest_stale: false,
      readable: false,
      recv_error_streak: 0,
      recv_error_rounds: 0,
      recv_dead: false,
      #[cfg(test)]
      force_rearm_error: false,
      #[cfg(test)]
      forced_recv_errors: 0,
      #[cfg(test)]
      forced_permanent_recv_error: false,
      #[cfg(test)]
      forced_send_wouldblock: false,
      #[cfg(test)]
      reregisters: 0,
    }
  }

  /// Whether this family may be selected for a read right now: mio reported it
  /// readable, its receive path is not structurally dead, and it has not
  /// exhausted this round's transient-error budget.
  const fn recv_selectable(&self) -> bool {
    self.readable && !self.recv_dead && self.recv_error_streak < MAX_RECV_ERRORS_PER_ROUND
  }

  /// A read reached the kernel queue — a datagram, or the `WouldBlock` that
  /// proves it empty. Either way this family is healthy, so both error counters
  /// go back to zero.
  const fn note_recv_progress(&mut self) {
    self.recv_error_streak = 0;
    self.recv_error_rounds = 0;
  }

  /// One `recvmsg`/`WSARecvMsg` with cmsg metadata on this family's socket.
  ///
  /// Wraps the free [`raw_recv`] purely so a test can inject the transient,
  /// non-consuming receive error that no healthy loopback socket will produce.
  fn raw_recv(&mut self, buf: &mut [u8], is_v4: bool) -> io::Result<RecvMeta> {
    #[cfg(test)]
    if self.forced_permanent_recv_error {
      return Err(io::Error::from(io::ErrorKind::NotConnected));
    }
    #[cfg(test)]
    if self.forced_recv_errors > 0 {
      self.forced_recv_errors -= 1;
      return Err(io::Error::other("forced transient recv failure"));
    }
    raw_recv(&self.sock, buf, is_v4)
  }

  /// One `send_to` on this family's socket, retrying once on `EINTR`.
  ///
  /// Wraps the free [`send_with_eintr_retry`] purely so a test can inject the
  /// `WouldBlock` no healthy loopback socket will produce. See
  /// [`BoundSocket::forced_send_wouldblock`].
  fn raw_send(&self, body: &[u8], dst: SocketAddr) -> io::Result<usize> {
    #[cfg(test)]
    if self.forced_send_wouldblock {
      return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    send_with_eintr_retry(self, body, dst)
  }

  /// Re-arm this socket's readiness after we stopped reading it. No-op when the
  /// socket is not registered — there is nothing to re-arm.
  fn rearm(&mut self, registry: Option<&Registry>) -> io::Result<()> {
    #[cfg(test)]
    if self.force_rearm_error {
      return Err(io::Error::other("forced re-arm failure"));
    }
    let (Some(registry), Some(token)) = (registry, self.token) else {
      return Ok(());
    };
    rearm_readiness(registry, &mut self.sock, token, self.interest)
  }

  /// Stop reading this family and re-arm it, recording a failed re-arm as a
  /// stale registration so the next [`Sockets::sync_interests`] retries it.
  ///
  /// **Called only from the `WouldBlock` arm of [`Sockets::recv`]**, and that
  /// restriction is the invariant: readiness is cleared exactly when the kernel
  /// has told us its queue is empty, never on the strength of an error that
  /// says nothing about it. A transient receive error is retried with readiness
  /// retained — see [`MAX_RECV_ERRORS_PER_ROUND`] — because under
  /// edge-triggered readiness a datagram already queued behind that error
  /// produces no second edge, so a family whose flag was cleared without
  /// draining has nothing left to wake it.
  ///
  /// The raw `WSARecvMsg` bypasses mio's `IoSource::do_io`, so on Windows this
  /// re-arm is the **only** thing that regenerates a readiness edge for this
  /// socket. If it fails and nothing records that, the family goes permanently
  /// deaf: `readable` has just been cleared and no edge is coming. The recovery
  /// is the registration, not the flag: `interest_stale` makes the next
  /// [`Sockets::retry_stale_registrations`] — which every `tick` ends with —
  /// reregister unconditionally, makes [`Sockets::needs_interest_retry`] bring
  /// an otherwise idle caller back on the bounded backoff, and surfaces a
  /// re-arm that keeps failing as the error `tick` returns.
  fn stop_reading(&mut self, registry: Option<&Registry>) {
    self.readable = false;
    self.note_recv_progress();
    if let Err(_e) = self.rearm(registry) {
      self.interest_stale = true;
      hick_trace::debug!(error = %_e, "re-arming a socket's readiness failed");
    }
  }
}

/// The bound mDNS socket pair.
pub(crate) struct Sockets {
  v4: Option<BoundSocket>,
  v6: Option<BoundSocket>,
  interface_index: u32,
  /// Clone of the caller's `Registry`, taken in [`Sockets::register`]. Every
  /// platform's `Selector::try_clone` deliberately preserves the selector id,
  /// so a `reregister` through this clone reaches the same selector state the
  /// caller's `Poll` owns and mio's association debug-assertion still holds.
  registry: Option<Registry>,
  /// The two tokens the caller reserved for us, recorded even for a family that
  /// is not bound: [`Sockets::owns`] must claim both, or the caller would route
  /// a token it gave away back into its own handler.
  tokens: Option<(Token, Token)>,
  /// Which family the next [`Sockets::recv`] reads from. Lives here, not in the
  /// call, because the starvation it prevents is across ticks: a per-call or
  /// per-tick preference resets to the same family every time.
  recv_rotor: RecvRotor,
  /// Shared counters. The **same** `Arc` [`crate::endpoint::Mdns::stats`] holds
  /// and `mdns-proto`'s `Endpoint::handle()` bumps `packets_rx`/`bytes_rx` on
  /// (both clone the handle `ProtoEndpoint::stats_handle()` mints) — never a
  /// private set, or a socket-layer send would go uncounted in
  /// [`crate::Mdns::stats`]. [`Mdns::new`](crate::endpoint::Mdns::new)
  /// constructs the endpoint before calling [`Sockets::bind`] specifically so
  /// this field can be wired to that same `Arc` at construction time.
  ///
  /// Bumped **here**, not by the driver: [`Sockets::send_one`] is the only
  /// place an actual `send_to` syscall happens, so this is the single choke
  /// point for `packets_tx` / `bytes_tx` / `send_errors` regardless of which of
  /// the driver's call sites (`send_and_credit`, `send_withdrawal`) triggered
  /// the send. Keeping the field here, rather than threading a `&Arc<Stats>`
  /// parameter through every method the way `hick-reactor`'s free functions do,
  /// means the existing unit tests that call `send_to` / `send_one` and do not
  /// care about stats need no signature change at all — only [`Sockets::bind`]
  /// gained a parameter, and it has exactly one production call site.
  #[cfg(feature = "stats")]
  stats: std::sync::Arc<hick_trace::stats::Stats>,
}

impl Sockets {
  /// Bind and join the mDNS multicast groups for every enabled family.
  ///
  /// Mirrors `hick-reactor/src/endpoint.rs:39-127`, including the graceful
  /// single-family degradation: if the chosen interface has no address in one
  /// requested family, that family is skipped rather than failing the whole
  /// endpoint, so `with_ipv4(true).with_ipv6(true)` still works on a host with
  /// no global IPv6.
  pub(crate) fn bind(
    opts: &ServerOptions,
    #[cfg(feature = "stats")] stats: std::sync::Arc<hick_trace::stats::Stats>,
  ) -> Result<Self, ServerError> {
    if !opts.ipv4() && !opts.ipv6() {
      return Err(ServerError::NoFamilyEnabled);
    }

    let interface_index = match opts.interface_index() {
      Some(i) => i,
      None => pick_default_interface_index(opts.ipv4(), opts.ipv6()).ok_or_else(|| {
        ServerError::Io(io::Error::new(
          io::ErrorKind::NotFound,
          "no multicast-capable interface found",
        ))
      })?,
    };

    // The three outcomes are kept apart on purpose. An index that names no
    // interface, and an enumeration that failed, are NOT "this interface has no
    // address in a requested family" — collapsing all three into `(false, false)`
    // reports the address error below, which sends a caller who passed a stale
    // index looking for missing addresses on an interface that does not exist.
    let (iface_has_v4, iface_has_v6) = match getifs::interface_by_index(interface_index) {
      Ok(Some(i)) => (
        matches!(i.ipv4_addrs(), Ok(ref a) if !a.is_empty()),
        matches!(i.ipv6_addrs(), Ok(ref a) if !a.is_empty()),
      ),
      Ok(None) => {
        return Err(ServerError::Io(io::Error::new(
          io::ErrorKind::NotFound,
          format!("no interface with index {interface_index}"),
        )));
      }
      // The kind is carried over rather than flattened, so a caller matching on
      // it still sees what the platform reported; the index is what the message
      // adds.
      Err(e) => {
        return Err(ServerError::Io(io::Error::new(
          e.kind(),
          format!("looking up interface {interface_index}: {e}"),
        )));
      }
    };
    let bind_v4 = opts.ipv4() && iface_has_v4;
    let bind_v6 = opts.ipv6() && iface_has_v6;
    if !bind_v4 && !bind_v6 {
      return Err(ServerError::Io(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "interface has no address in any requested family",
      )));
    }

    let v4 = if bind_v4 {
      Some(bind_v4_family(interface_index)?)
    } else {
      None
    };
    let v6 = if bind_v6 {
      Some(bind_v6_family(interface_index)?)
    } else {
      None
    };

    Ok(Self {
      v4,
      v6,
      interface_index,
      registry: None,
      tokens: None,
      recv_rotor: RecvRotor::new(),
      #[cfg(feature = "stats")]
      stats,
    })
  }

  /// The interface both sockets are scoped to. The RFC 6762 §11 fallback needs
  /// it to scope a link-local source to the link we actually joined.
  pub(crate) const fn interface_index(&self) -> u32 {
    self.interface_index
  }

  /// Which families actually bound, as `(ipv4, ipv6)`.
  ///
  /// [`Sockets::bind`] degrades rather than failing when the chosen interface
  /// has no address in one requested family, so a `with_ipv4(true).with_ipv6(true)`
  /// endpoint may be serving only one of them. Surfaced through
  /// [`Mdns::bound_families`](crate::Mdns::bound_families).
  pub(crate) const fn bound_families(&self) -> (bool, bool) {
    (self.v4.is_some(), self.v6.is_some())
  }

  /// Register both sockets into the caller's `Registry` and keep a clone of it,
  /// so the receive re-arm can be retried through the same selector.
  ///
  /// `v4` and `v6` must be **distinct**: one token cannot address two sockets,
  /// because readiness would then be unattributable. Both are remembered by
  /// [`Sockets::owns`] even when only one family is bound, so the caller can
  /// reserve the pair unconditionally.
  pub(crate) fn register(&mut self, registry: &Registry, v4: Token, v6: Token) -> io::Result<()> {
    if v4 == v6 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "hick-mio needs two distinct tokens: one token cannot address both sockets",
      ));
    }
    if self.registry.is_some() {
      return Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "hick-mio sockets are already registered; deregister first",
      ));
    }
    // Clone first: a failure here after registering would leave the sockets in
    // the caller's selector with no way for us to re-arm or toggle them.
    let cloned = registry.try_clone()?;
    register_family(self.v4.as_mut(), registry, v4)?;
    if let Err(e) = register_family(self.v6.as_mut(), registry, v6) {
      // Never sit half-registered: the caller would receive readiness for one
      // family while `owns`/`deregister` disagree about what we hold.
      let _ = deregister_family(self.v4.as_mut(), registry);
      return Err(e);
    }
    self.registry = Some(cloned);
    self.tokens = Some((v4, v6));
    Ok(())
  }

  /// Remove both sockets from the caller's `Registry` and drop our clone of it.
  pub(crate) fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
    let v4 = deregister_family(self.v4.as_mut(), registry);
    let v6 = deregister_family(self.v6.as_mut(), registry);
    self.registry = None;
    self.tokens = None;
    v4.and(v6)
  }

  /// Whether `token` is one of the two the caller handed us in
  /// [`Sockets::register`].
  pub(crate) fn owns(&self, token: Token) -> bool {
    self
      .tokens
      .is_some_and(|(v4, v6)| token == v4 || token == v6)
  }

  /// Record readiness for one of our sockets. Deliberately does no I/O: all
  /// work happens in `tick`, so the caller's ordering cannot break the
  /// drain-before-stamp invariant the self-send tracker depends on.
  pub(crate) fn note_readiness(&mut self, ev: &mio::event::Event) {
    let token = ev.token();
    for fam in [self.v4.as_mut(), self.v6.as_mut()].into_iter().flatten() {
      if fam.token != Some(token) {
        continue;
      }
      // Readability is the only edge this crate registers for, and the only one
      // it acts on. A writable event cannot arrive through our own registration,
      // and nothing is waiting on one: a refused send is reported at once rather
      // than parked.
      if ev.is_readable() {
        fam.readable = true;
      }
    }
  }

  /// Whether either socket has readable data this tick can still make progress
  /// on.
  ///
  /// The caller's `next_timeout` must report zero while this is true: a socket
  /// we stopped draining before `WouldBlock` has had its edge consumed, so
  /// blocking in `Poll::poll` would go deaf until unrelated traffic arrives.
  ///
  /// A family that exhausted [`MAX_RECV_ERRORS_PER_ROUND`] is deliberately
  /// excluded even though it is still flagged readable. Its data is not lost —
  /// the flag is retained precisely so the next round resumes the drain — but
  /// returning zero for it would re-enter a read that fails the same way and
  /// spin a core. [`Sockets::recv_error_backoff_level`] is what brings the
  /// caller back for it instead.
  pub(crate) fn has_readable(&self) -> bool {
    self.families().any(|f| f.recv_selectable())
  }

  /// Both bound families, for the predicates that treat them alike.
  fn families(&self) -> impl Iterator<Item = &BoundSocket> {
    [self.v4.as_ref(), self.v6.as_ref()].into_iter().flatten()
  }

  /// Open a new receive round: hand every family back its transient-error
  /// budget, counting a family that exhausted the last one toward its
  /// escalating backoff.
  ///
  /// Called once per [`Mdns::tick`](crate::Mdns::tick), which is what makes the
  /// retry *bounded* rather than merely repeated: one budget per tick, and the
  /// ticks themselves are paced by [`Sockets::recv_error_backoff_level`].
  pub(crate) fn begin_recv_round(&mut self) {
    for fam in [self.v4.as_mut(), self.v6.as_mut()].into_iter().flatten() {
      // A structurally dead receive path is never retried, so handing it a
      // fresh budget would only make it look like a family still in transient
      // backoff and keep paying it a wakeup forever.
      if fam.recv_dead {
        continue;
      }
      if fam.recv_error_streak >= MAX_RECV_ERRORS_PER_ROUND {
        fam.recv_error_rounds = fam.recv_error_rounds.saturating_add(1);
      }
      fam.recv_error_streak = 0;
    }
  }

  /// Which families have given up on receiving, as `(ipv4, ipv6)`.
  ///
  /// A family here is still bound and still sending; it simply cannot be read
  /// any more. Surfaced through
  /// [`Mdns::degraded_families`](crate::Mdns::degraded_families).
  pub(crate) const fn deaf_families(&self) -> (bool, bool) {
    (
      match &self.v4 {
        Some(fam) => fam.recv_dead,
        None => false,
      },
      match &self.v6 {
        Some(fam) => fam.recv_dead,
        None => false,
      },
    )
  }

  /// How hard a family is currently failing to receive, as a backoff level.
  ///
  /// `0` means no family exhausted this round's transient-error budget and
  /// nothing here needs a timer. Otherwise it is one more than the number of
  /// **consecutive earlier rounds** that also exhausted it, so the first
  /// failing round already reports `1` — a family that has just gone quiet must
  /// never leave the caller with no wakeup at all, and `has_readable` has
  /// already stopped speaking for it.
  pub(crate) fn recv_error_backoff_level(&self) -> u32 {
    self
      .families()
      .filter(|f| f.recv_error_streak >= MAX_RECV_ERRORS_PER_ROUND)
      .map(|f| f.recv_error_rounds.saturating_add(1))
      .max()
      .unwrap_or(0)
  }

  /// Drain the next datagram from a socket flagged readable, with its cmsg
  /// metadata. The `bool` is `via_v4`: which family it arrived on.
  ///
  /// **Which family is read rotates on every selection** — see [`RecvRotor`],
  /// which owns that policy and the reason a per-tick budget is not a substitute
  /// for it.
  ///
  /// Returns `None` once nothing is readable, having cleared each drained
  /// family's flag and re-armed it. Error handling follows the design's §8
  /// table:
  ///
  /// * `WouldBlock` — the kernel queue is empty. **The only outcome that clears
  ///   the readable flag**: clear it, re-arm, try the other family.
  /// * `InvalidData` (`MSG_TRUNC` or an unparseable source) and Windows
  ///   `WSAEMSGSIZE` — the datagram was **already consumed**, so drop it and
  ///   keep serving. Never fatal: treating one oversized LAN packet as fatal
  ///   would blind the responder until restart. Counted toward `packets_rx` /
  ///   `bytes_rx` / `packets_dropped` — see [`is_consumed_but_unusable`] — so
  ///   `packets_rx` stays a reliable denominator for a datagram that truly left
  ///   the kernel queue, mirroring `hick-reactor`'s `count_consumed_oversized`.
  ///   `buf.len()` is the best-effort byte count: recvmsg truncates the
  ///   datagram to fill exactly the buffer we supplied, but the exact
  ///   pre-truncation length is not exposed to this call site on any platform.
  /// * anything else — a transient error that consumed nothing. **Readiness is
  ///   retained** and the read is retried, up to
  ///   [`MAX_RECV_ERRORS_PER_ROUND`] per family per round; see that constant
  ///   for why clearing the flag here strands whatever is queued behind the
  ///   error.
  ///
  /// A caller-visible datagram (the `Ok` arm) is deliberately **not** counted
  /// here at all: `packets_rx` / `bytes_rx` for those are bumped once, by
  /// `mdns-proto`'s `Endpoint::handle()`, on the same shared `Arc` this
  /// module's `stats` field points to. Counting them here too would double
  /// them. Nor is a bare `Interrupted` — no bytes were consumed, so it has
  /// nothing to add to either counter; only the arm that reads a datagram off
  /// the kernel queue and then finds it unusable does.
  pub(crate) fn recv(&mut self, buf: &mut [u8]) -> Option<(RecvMeta, Family)> {
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();
    let mut discarded = 0usize;
    loop {
      // Round-robin, never a fixed preference: see [`RecvRotor`] for why a
      // per-tick budget does not stop one family starving the other.
      let v4_readable = self.v4.as_ref().is_some_and(BoundSocket::recv_selectable);
      let v6_readable = self.v6.as_ref().is_some_and(BoundSocket::recv_selectable);
      let family = self.recv_rotor.pick(v4_readable, v6_readable)?;
      let via_v4 = family.is_v4();
      // Disjoint field borrows: the family we read from and the registry we
      // re-arm through.
      let Self {
        v4, v6, registry, ..
      } = self;
      // The readable test above already proved this family is bound, so the
      // `?` never actually short-circuits.
      let fam = (if via_v4 { v4.as_mut() } else { v6.as_mut() })?;

      match fam.raw_recv(buf, via_v4) {
        Ok(meta) => {
          fam.note_recv_progress();
          return Some((meta, family));
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
          fam.stop_reading(registry.as_ref());
        }
        // Interrupted before anything was consumed: nothing landed in `buf`, so
        // there is nothing to add to packets_rx/bytes_rx. Budgeted the same way
        // as the arm below — both make progress only by looping.
        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
          hick_trace::debug!(error = %e, via_v4, "retrying an interrupted recv");
          discarded = discarded.saturating_add(1);
          if discarded >= MAX_DISCARDED_PER_RECV {
            // Flag deliberately left set: `has_readable` keeps reporting work
            // so the caller ticks again instead of blocking.
            return None;
          }
        }
        // Consumed but unusable (oversized / MSG_TRUNC / unparseable source):
        // the datagram DID leave the kernel queue, so — unlike `Interrupted`
        // above — it counts toward packets_rx/bytes_rx, with packets_dropped
        // marking the reject. See this method's doc comment for why.
        Err(e) if is_consumed_but_unusable(&e) => {
          hick_trace::debug!(error = %e, via_v4, "dropping an unusable datagram");
          #[cfg(feature = "stats")]
          {
            stats.packets_rx(1);
            stats.bytes_rx(buf.len() as u64);
            stats.packets_dropped(1);
          }
          discarded = discarded.saturating_add(1);
          if discarded >= MAX_DISCARDED_PER_RECV {
            // Flag deliberately left set: `has_readable` keeps reporting work
            // so the caller ticks again instead of blocking.
            return None;
          }
        }
        // Structurally broken rather than merely unlucky: this socket will
        // answer every read the same way for as long as it exists, so retrying
        // it is a busy-loop that leaves the family deaf and says so nowhere.
        // Stop reading it, and let `deaf_families` make the state public.
        Err(e) if is_permanent_recv_error(&e) => {
          hick_trace::warn!(
            error = %e,
            via_v4,
            "a socket's receive path failed permanently; this family will not be read again"
          );
          fam.recv_dead = true;
          fam.readable = false;
          // It is not in transient backoff any more, so it must stop asking for
          // the wakeups that backoff pays for — see `recv_error_backoff_level`.
          fam.recv_error_streak = 0;
          fam.recv_error_rounds = 0;
        }
        Err(_e) => {
          // A bound UDP socket can fail transiently (`ENOBUFS`, or Windows
          // `WSAECONNRESET` after an ICMP port-unreachable for one of our
          // sends) without consuming anything. Readiness is deliberately
          // RETAINED: the error says nothing about the kernel queue, and under
          // edge-triggered readiness a datagram already sitting behind it
          // generates no second edge — so clearing the flag would strand that
          // datagram with nothing left to wake the family. Retry instead,
          // bounded by MAX_RECV_ERRORS_PER_ROUND.
          hick_trace::debug!(error = %_e, via_v4, "recv_with_meta failed");
          fam.recv_error_streak = fam.recv_error_streak.saturating_add(1);
          if fam.recv_error_streak >= MAX_RECV_ERRORS_PER_ROUND {
            hick_trace::warn!(
              via_v4,
              rounds = fam.recv_error_rounds.saturating_add(1),
              "a socket kept failing to receive; backing off with its readiness retained"
            );
          }
          discarded = discarded.saturating_add(1);
          if discarded >= MAX_DISCARDED_PER_RECV {
            // Flag deliberately left set: the drain resumes next round.
            return None;
          }
        }
      }
    }
  }

  /// Send `body` to `dst`, reporting **each family separately**.
  ///
  /// An mDNS multicast destination fans out to **both** bound families (RFC
  /// 6762 §6: a dual-stack host answers on each group); the proto layer always
  /// hands back the IPv4 marker, so the fan-out belongs here. Any other
  /// destination selects the socket by family, and the family it did not use is
  /// reported as [`SendOutcome::NoSocket`].
  ///
  /// The per-family report is load-bearing, not cosmetic: the fan-out is two
  /// syscalls and two loopback copies, so the caller must take one self-send
  /// credit per [`SendOutcome::Sent`], and each family carries its own share of
  /// the transmit's delivery obligation.
  ///
  /// `allow` is the caller's per-producer wire gate, indexed by
  /// [`Family::index`]: a bound family whose entry is `false` is not offered the
  /// datagram at all and comes back [`SendOutcome::Gated`]. The gate's *value*
  /// is protocol policy the core computes; enforcing it per family is the
  /// driver's job, and reporting it is this method's.
  pub(crate) fn send_to(&mut self, body: &[u8], dst: SocketAddr, allow: FamilyAllow) -> SendReport {
    if is_mdns_multicast(dst) {
      let v4 = self.send_one(Family::V4, body, MDNS_V4_DST, allow);
      let v6 = self.send_one(Family::V6, body, MDNS_V6_DST, allow);
      return SendReport {
        v4,
        v6,
        loops_back: true,
      };
    }
    match Family::of(dst) {
      Family::V4 => SendReport {
        v4: self.send_one(Family::V4, body, dst, allow),
        v6: SendOutcome::NoSocket,
        loops_back: false,
      },
      Family::V6 => SendReport {
        v4: SendOutcome::NoSocket,
        v6: self.send_one(Family::V6, body, dst, allow),
        loops_back: false,
      },
    }
  }

  /// Whether this socket pair is waiting on something **no mio event will
  /// deliver**, so the caller must come back on a timer rather than block.
  ///
  /// This is the third arm of `next_timeout`, and after the parking machinery
  /// went it has exactly one cause: `interest_stale`. The selector's
  /// registration for a family is not the one we need and the receive re-arm
  /// that would have fixed it failed, so `readable` is clear, no edge is coming,
  /// and the family owes nothing that any deadline announces. Reporting `false`
  /// here would leave that family deaf for good; a zero timeout instead of a
  /// bounded backoff would busy-spin on it.
  ///
  /// Nothing about *sending* reaches this predicate any more. A refused send is
  /// reported to the core at once and re-armed on the core's own schedule, which
  /// `next_timeout` already folds in.
  pub(crate) fn needs_interest_retry(&self) -> bool {
    self.families().any(|fam| fam.interest_stale)
  }

  /// The socket for one family, or `None` when that family is not bound.
  fn family_mut(&mut self, family: Family) -> Option<&mut BoundSocket> {
    match family {
      Family::V4 => self.v4.as_mut(),
      Family::V6 => self.v6.as_mut(),
    }
  }

  /// Send one datagram on **one** family, queueing it if the socket is not
  /// Send one datagram on **one** family. The per-family primitive behind
  /// [`Sockets::send_to`], and the entry point the RFC 6762 §10.1 withdrawal
  /// pump needs to map each family's result onto its own goodbye debt.
  ///
  /// Strictly non-blocking, and **nothing is retried behind the caller's back**.
  /// A socket that answers `WouldBlock` has been handed nothing, so the family
  /// reports [`SendOutcome::Failed`] and the caller reports that to the core,
  /// which re-arms the same datagram on its own schedule. Parking it here
  /// instead would leave a datagram whose owner may since have been renamed away
  /// or withdrawn, transmitting it after the retraction that was supposed to
  /// supersede it.
  ///
  /// `allow` is the caller's wire gate: a bound family whose entry is `false` is
  /// not offered the datagram and reports [`SendOutcome::Gated`]. It is checked
  /// after the destination-family guard and before boundness, so an unbound
  /// family still reports [`SendOutcome::NoSocket`] — a gate cannot invent an
  /// obligation for a link that does not exist.
  ///
  /// `dst` must belong to `family`; a mismatch is reported as
  /// [`SendOutcome::Failed`] rather than sent. That early mismatch is **not**
  /// counted as `send_errors`: no syscall was attempted, every real call site in
  /// this crate already passes a matching pair, and counting it would credit a
  /// caller-error guard as a network failure. Nor is `WouldBlock`: backpressure
  /// is not an error. Only a `send_to` the kernel rejected for some other reason
  /// — the catch-all `Err` arm below — bumps `send_errors`.
  pub(crate) fn send_one(
    &mut self,
    family: Family,
    body: &[u8],
    dst: SocketAddr,
    allow: FamilyAllow,
  ) -> SendOutcome {
    if Family::of(dst) != family {
      hick_trace::debug!(dst = %dst, "dropping a datagram: destination family does not match the selected socket");
      return SendOutcome::Failed;
    }
    // Boundness first: a family with no socket was never obligated, and a shut
    // gate must not be able to report it as one that merely missed a round.
    if self.family_mut(family).is_none() {
      return SendOutcome::NoSocket;
    }
    if !allow.get(family.index()).copied().unwrap_or(true) {
      return SendOutcome::Gated;
    }

    // Cloned (a refcount bump, not a snapshot) before the family borrow below:
    // `family_mut` takes `&mut self`, so the returned `&mut BoundSocket` is tied
    // to the WHOLE of `self` from the borrow checker's view, not just the
    // `v4`/`v6` field it actually reads. An owned `Arc` sidesteps that entirely
    // instead of destructuring `Self` disjointly the way the driver's stages do.
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();
    // Boundness was established above.
    let Some(fam) = self.family_mut(family) else {
      return SendOutcome::NoSocket;
    };
    // Captured as late as possible — the next statement is the syscall — so the
    // credit's stamp cannot postdate the kernel's stamp on the loopback copy,
    // and the monotonic instant is this family's own acceptance time rather than
    // a later point in the fan-out.
    let at = SystemTime::now();
    let accepted = StdInstant::now();
    match fam.raw_send(body, dst) {
      Ok(_) => {
        hick_trace::trace!(dst = %dst, len = body.len(), via_v4 = family.is_v4(), "send_to");
        #[cfg(feature = "stats")]
        {
          stats.packets_tx(1);
          stats.bytes_tx(body.len() as u64);
        }
        SendOutcome::Sent(at, accepted)
      }
      // The send buffer is full. NOTHING reached the kernel, so this family
      // definitively did not carry the datagram — there is no in-flight
      // datagram whose fate is unknown and nothing to wait for. Not an error
      // count: backpressure is not a failure of the socket.
      Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
        hick_trace::debug!(dst = %dst, via_v4 = family.is_v4(), "send_to would block; reporting the family missed");
        SendOutcome::Failed
      }
      // Interrupted twice (the helper already retried once). Like `WouldBlock`,
      // nothing was handed to the kernel on the final attempt.
      Err(e) if e.kind() == io::ErrorKind::Interrupted => {
        hick_trace::debug!(dst = %dst, via_v4 = family.is_v4(), "send_to kept being interrupted; reporting the family missed");
        SendOutcome::Failed
      }
      Err(_e) => {
        hick_trace::debug!(error = %_e, dst = %dst, "send_to failed");
        #[cfg(feature = "stats")]
        stats.send_errors(1);
        SendOutcome::Failed
      }
    }
  }

  /// Re-register every family whose registration the selector holds is not the
  /// one we need.
  ///
  /// The interest is always [`Interest::READABLE`] — nothing here toggles
  /// `WRITABLE` — so this exists solely for the re-arm: on Windows the raw
  /// `WSARecvMsg` bypasses mio's `IoSource::do_io`, and a `reregister` is the
  /// only thing that regenerates a readable edge after
  /// [`BoundSocket::stop_reading`]'s own re-arm failed. It therefore cannot
  /// short-circuit on "the interest already equals what we want": that is
  /// precisely the case it has to act on.
  ///
  /// Called at the end of every [`Mdns::tick`](crate::Mdns::tick), which is what
  /// makes the retry happen at all, and its error is what surfaces a family
  /// that has gone deaf.
  fn retry_stale_registrations(&mut self) -> io::Result<()> {
    let Self {
      v4, v6, registry, ..
    } = self;
    let Some(registry) = registry.as_ref() else {
      return Ok(());
    };
    let mut first_err = None;
    for (fam, family) in [(v4.as_mut(), Family::V4), (v6.as_mut(), Family::V6)] {
      let Some(fam) = fam else { continue };
      let Some(token) = fam.token else { continue };
      if !fam.interest_stale {
        continue;
      }
      match registry.reregister(&mut fam.sock, token, fam.interest) {
        Ok(()) => {
          fam.interest_stale = false;
          #[cfg(test)]
          {
            fam.reregisters = fam.reregisters.saturating_add(1);
          }
        }
        Err(e) => {
          hick_trace::debug!(error = %e, via_v4 = family.is_v4(), "reregister failed");
          if first_err.is_none() {
            first_err = Some(e);
          }
        }
      }
    }
    match first_err {
      Some(e) => Err(e),
      None => Ok(()),
    }
  }

  /// Retry any registration a failed receive re-arm left stale. The last thing
  /// [`Mdns::tick`](crate::Mdns::tick) does, and the only fallible one.
  pub(crate) fn end_tick(&mut self) -> io::Result<()> {
    self.retry_stale_registrations()
  }

  /// Make this family's next `n` raw receives fail with a transient,
  /// non-consuming error. See [`BoundSocket::forced_recv_errors`] for why no
  /// real socket produces one on demand.
  #[cfg(test)]
  pub(crate) fn force_recv_errors_for_test(&mut self, family: Family, n: u32) {
    if let Some(fam) = self.family_mut(family) {
      fam.forced_recv_errors = n;
    }
  }

  /// Make every raw receive on this family fail with a **permanent** error. See
  /// [`BoundSocket::forced_permanent_recv_error`].
  #[cfg(test)]
  pub(crate) fn force_permanent_recv_error_for_test(&mut self, family: Family) {
    if let Some(fam) = self.family_mut(family) {
      fam.forced_permanent_recv_error = true;
    }
  }

  /// Make every send on this family answer `WouldBlock`. See
  /// [`BoundSocket::forced_send_wouldblock`] for why no real socket can be made
  /// to do it on demand, and why the path must not go untested.
  #[cfg(test)]
  pub(crate) fn force_send_wouldblock_for_test(&mut self, family: Family, fail: bool) {
    if let Some(fam) = self.family_mut(family) {
      fam.forced_send_wouldblock = fail;
    }
  }

  /// This family's transient-receive-error count for the current round, so a
  /// test can tell a retained-readiness backoff from a cleared flag.
  #[cfg(test)]
  pub(crate) fn recv_error_streak_for_test(&self, family: Family) -> u32 {
    match family {
      Family::V4 => self.v4.as_ref(),
      Family::V6 => self.v6.as_ref(),
    }
    .map_or(0, |fam| fam.recv_error_streak)
  }

  /// Whether mio's readable flag is still set for this family, independent of
  /// whether [`Sockets::has_readable`] is currently willing to speak for it.
  /// The distinction is the whole of the transient-error fix.
  #[cfg(test)]
  pub(crate) fn is_readable_for_test(&self, family: Family) -> bool {
    match family {
      Family::V4 => self.v4.as_ref(),
      Family::V6 => self.v6.as_ref(),
    }
    .is_some_and(|fam| fam.readable)
  }

  /// Drive a family into the "mio reported this readable and we have not
  /// drained it" state that a budget-capped recv leaves behind. That state is
  /// the sole justification for a zero timeout, and a real budget-capped drain
  /// needs a peer flooding oversized datagrams to reproduce.
  #[cfg(test)]
  pub(crate) fn set_readable_for_test(&mut self, family: Family, readable: bool) {
    if let Some(fam) = self.family_mut(family) {
      fam.readable = readable;
    }
  }

  /// The family the next [`Sockets::recv`] selection prefers. Proves that
  /// `recv` really consults and advances [`RecvRotor`], which is otherwise
  /// invisible: a single-family endpoint reads the same socket either way.
  #[cfg(test)]
  pub(crate) const fn recv_rotor_next_for_test(&self) -> Family {
    self.recv_rotor.next
  }

  /// Make this family's next receive re-arm fail, reproducing the Windows AFD
  /// re-arm failure that would otherwise leave it permanently deaf. The re-arm
  /// is a kernel-maintained no-op on every non-Windows target, so nothing a test
  /// can do to a real socket produces it.
  #[cfg(test)]
  pub(crate) fn force_rearm_error_for_test(&mut self, family: Family, fail: bool) {
    if let Some(fam) = self.family_mut(family) {
      fam.force_rearm_error = fail;
    }
  }

  /// Stop reading this family exactly as a `WouldBlock` or a transient receive
  /// error does. Both `recv` arms funnel through the same helper, and this is
  /// what lets a test pin that they still do.
  #[cfg(test)]
  pub(crate) fn stop_reading_for_test(&mut self, family: Family) {
    let Self {
      v4, v6, registry, ..
    } = self;
    let fam = match family {
      Family::V4 => v4.as_mut(),
      Family::V6 => v6.as_mut(),
    };
    if let Some(fam) = fam {
      fam.stop_reading(registry.as_ref());
    }
  }

  /// How many times this family's registration has been successfully
  /// reregistered. The only way to tell a re-arm that was actually issued from
  /// one [`Sockets::retry_stale_registrations`] skipped as unnecessary — the
  /// interest is the same `READABLE` either way.
  #[cfg(test)]
  pub(crate) fn reregisters_for_test(&self, family: Family) -> u32 {
    match family {
      Family::V4 => self.v4.as_ref(),
      Family::V6 => self.v6.as_ref(),
    }
    .map_or(0, |fam| fam.reregisters)
  }

  /// One family's half of [`Sockets::bound_families`], so a test can name the
  /// family it means instead of indexing a tuple.
  #[cfg(test)]
  pub(crate) const fn is_bound_for_test(&self, family: Family) -> bool {
    let (v4, v6) = self.bound_families();
    match family {
      Family::V4 => v4,
      Family::V6 => v6,
    }
  }

  /// The interest a family currently has registered, or `None` when it is not
  /// bound or not registered. The only way to assert the interest state
  /// machine from a test.
  #[cfg(test)]
  pub(crate) fn interest_for_test(&self, family: Family) -> Option<Interest> {
    let fam = match family {
      Family::V4 => self.v4.as_ref(),
      Family::V6 => self.v6.as_ref(),
    }?;
    fam.token.map(|_| fam.interest)
  }
}

/// One `send_to`, retrying once on `EINTR`.
///
/// `EINTR` means a signal landed mid-syscall; it is not backpressure, so the
/// socket is still writable and an immediate retry normally succeeds. Retrying
/// here is what keeps a signal from costing the datagram a whole re-arm cycle,
/// since a family this driver reports as missed is not tried again until the
/// core re-offers it. Exactly one retry: a signal storm must not spin inside a
/// syscall wrapper.
fn send_with_eintr_retry(fam: &BoundSocket, body: &[u8], dst: SocketAddr) -> io::Result<usize> {
  match fam.sock.send_to(body, dst) {
    Err(e) if e.kind() == io::ErrorKind::Interrupted => fam.sock.send_to(body, dst),
    other => other,
  }
}

/// Register one family, recording the token and interest it now holds.
fn register_family(
  fam: Option<&mut BoundSocket>,
  registry: &Registry,
  token: Token,
) -> io::Result<()> {
  let Some(fam) = fam else { return Ok(()) };
  registry.register(&mut fam.sock, token, Interest::READABLE)?;
  fam.token = Some(token);
  fam.interest = Interest::READABLE;
  // A fresh registration succeeded, so the kernel's interest is known exactly;
  // any earlier toggle failure is no longer outstanding.
  fam.interest_stale = false;
  Ok(())
}

/// Deregister one family and reset it to its freshly-bound state, so a later
/// [`Sockets::register`] starts from the same assumptions `bind` did.
fn deregister_family(fam: Option<&mut BoundSocket>, registry: &Registry) -> io::Result<()> {
  let Some(fam) = fam else { return Ok(()) };
  if fam.token.is_none() {
    return Ok(());
  }
  let res = registry.deregister(&mut fam.sock);
  fam.token = None;
  fam.interest = Interest::READABLE;
  // Nothing is registered any more, so there is no outstanding re-arm to retry.
  fam.interest_stale = false;
  fam.readable = false;
  res
}

/// Whether `dst` is an mDNS multicast group, which must fan out to both
/// families. Same test as `hick-reactor/src/driver/mod.rs:1499`.
///
/// Also the predicate behind [`SendReport::loops_back`]: we joined these groups,
/// so the kernel returns a copy on every socket that carried the datagram, and
/// only such a copy needs a self-send credit.
fn is_mdns_multicast(dst: SocketAddr) -> bool {
  match dst {
    SocketAddr::V4(a) => a.ip().is_multicast() && a.port() == MDNS_PORT,
    SocketAddr::V6(a) => a.ip().is_multicast() && a.port() == MDNS_PORT,
  }
}

/// Whether this receive error means the datagram left the kernel queue but is
/// unusable — drop it and keep serving, never fatal.
fn is_consumed_but_unusable(e: &io::Error) -> bool {
  // `hick_udp::recv_with_meta` maps `MSG_TRUNC` (an oversized datagram, already
  // truncated into our buffer) and an unparseable source address to
  // `InvalidData`.
  if e.kind() == io::ErrorKind::InvalidData {
    return true;
  }
  // Winsock reports the same oversized-datagram case as `WSAEMSGSIZE` after
  // `WSARecvMsg` consumed and truncated it. `hick-reactor` learned this the
  // hard way: treating it as fatal lets one oversized LAN packet blind the
  // responder until restart.
  #[cfg(windows)]
  {
    const WSAEMSGSIZE: i32 = 10040;
    if e.raw_os_error() == Some(WSAEMSGSIZE) {
      return true;
    }
  }
  false
}

/// Whether this receive error is a property of the **socket** rather than of a
/// datagram, so no number of retries will ever get past it.
///
/// The default for an unrecognised error must stay "transient": a receive path
/// abandoned by mistake is deaf until the process restarts, whereas a permanent
/// error mis-classified as transient merely costs the bounded retry budget
/// [`MAX_RECV_ERRORS_PER_ROUND`] already caps. So this list is deliberately the
/// small set whose meaning is unambiguous for a bound UDP socket:
///
/// * `NotConnected` — `ENOTSOCK`/`ENOTCONN`: the descriptor is not a socket we
///   can read, which no later event changes.
/// * `PermissionDenied` — the kernel refuses this receive outright (a sandbox or
///   MAC policy); nothing about it is rate-related.
/// * `Unsupported` — `EOPNOTSUPP`/`ENOSYS`, or a Winsock `WSARecvMsg` this
///   platform does not provide. The call itself is unavailable, so every retry
///   fails identically.
/// * `InvalidInput` — `EINVAL` on the receive call. The arguments this crate
///   passes are fixed, so a rejection is structural. Note that this is **not**
///   `InvalidData`, which [`is_consumed_but_unusable`] handles as a discarded
///   datagram and which is checked first.
///
/// Deliberately absent: `AddrNotAvailable` and `NetworkDown`, which an interface
/// coming back up resolves, and every rate- or buffer-related error.
fn is_permanent_recv_error(e: &io::Error) -> bool {
  matches!(
    e.kind(),
    io::ErrorKind::NotConnected
      | io::ErrorKind::PermissionDenied
      | io::ErrorKind::Unsupported
      | io::ErrorKind::InvalidInput
  )
}

/// One `recvmsg` with cmsg metadata, straight on the raw socket.
///
/// `mio::net::UdpSocket` has no API for ancillary data, so this goes around it
/// — which is exactly why [`rearm_readiness`] exists.
#[cfg(unix)]
fn raw_recv(sock: &UdpSocket, buf: &mut [u8], is_v4: bool) -> io::Result<RecvMeta> {
  use std::os::fd::AsRawFd;
  hick_udp::recv_with_meta(sock.as_raw_fd(), buf, is_v4)
}

/// One `WSARecvMsg` with cmsg metadata, straight on the raw socket. See the
/// Unix twin.
#[cfg(windows)]
fn raw_recv(sock: &UdpSocket, buf: &mut [u8], is_v4: bool) -> io::Result<RecvMeta> {
  use std::os::windows::io::AsRawSocket;
  hick_udp::recv_with_meta(sock.as_raw_socket(), buf, is_v4)
}

/// Re-arm a socket's readiness registration after we stopped reading it.
///
/// mio's `IoSource::do_io` re-arms the AFD registration on `WouldBlock`. We read
/// via `WSARecvMsg` on the raw socket to recover cmsg metadata, which bypasses
/// `do_io` — so we must perform the same re-arm ourselves or mio never reports
/// this socket readable again. `Registry::reregister` reaches the same
/// `selector.reregister(...)` call `do_io` makes.
///
/// Called from **every** path that stops reading a socket, not just the
/// `WouldBlock` one: a transient error (`WSAECONNRESET` after an ICMP
/// port-unreachable for one of our own sends) also leaves mio unarmed, because
/// the `WouldBlock` that would have re-armed it was never reached.
#[cfg(windows)]
fn rearm_readiness(
  registry: &Registry,
  sock: &mut UdpSocket,
  token: Token,
  interests: Interest,
) -> io::Result<()> {
  registry.reregister(sock, token, interests)
}

/// No-op twin of the Windows re-arm: epoll/kqueue readiness is maintained by
/// the kernel, so there is nothing to re-arm.
#[cfg(not(windows))]
#[inline]
fn rearm_readiness(
  _registry: &Registry,
  _sock: &mut UdpSocket,
  _token: Token,
  _interests: Interest,
) -> io::Result<()> {
  Ok(())
}

/// Bind + join the IPv4 mDNS group on `interface_index`.
fn bind_v4_family(interface_index: u32) -> Result<BoundSocket, ServerError> {
  let std_sock = match try_bind_v4(MulticastOptionsV4::new(interface_index)) {
    Ok(s) => s,
    Err(e) => {
      hick_trace::warn!(error = %e, interface_index, "failed to bind v4 mDNS socket");
      return Err(ServerError::BindV4(e));
    }
  };
  hick_trace::debug!(interface_index, "bound v4 mDNS socket");
  if let Err(e) = try_join_v4(&std_sock, interface_index) {
    hick_trace::warn!(error = %e, interface_index, "failed to join v4 mDNS multicast group");
    return Err(map_join_to_bind_v4(e));
  }
  hick_trace::debug!(interface_index, "joined v4 mDNS multicast group");
  // `mio::net::UdpSocket::from_std` assumes nothing about blocking mode, so the
  // non-blocking flag is ours to set.
  std_sock.set_nonblocking(true)?;
  Ok(BoundSocket::new(UdpSocket::from_std(std_sock)))
}

/// Bind + join the IPv6 mDNS group on `interface_index`.
fn bind_v6_family(interface_index: u32) -> Result<BoundSocket, ServerError> {
  let std_sock = match try_bind_v6(MulticastOptionsV6::new(interface_index)) {
    Ok(s) => s,
    Err(e) => {
      hick_trace::warn!(error = %e, interface_index, "failed to bind v6 mDNS socket");
      return Err(ServerError::BindV6(e));
    }
  };
  hick_trace::debug!(interface_index, "bound v6 mDNS socket");
  if let Err(e) = try_join_v6(&std_sock, interface_index) {
    hick_trace::warn!(error = %e, interface_index, "failed to join v6 mDNS multicast group");
    return Err(map_join_to_bind_v6(e));
  }
  hick_trace::debug!(interface_index, "joined v6 mDNS multicast group");
  std_sock.set_nonblocking(true)?;
  Ok(BoundSocket::new(UdpSocket::from_std(std_sock)))
}

fn map_join_to_bind_v4(e: hick_udp::JoinError) -> ServerError {
  match e {
    hick_udp::JoinError::Io(io) => ServerError::BindV4(hick_udp::BindError::Io(io)),
    hick_udp::JoinError::InterfaceNotFound(d) => {
      ServerError::BindV4(hick_udp::BindError::InterfaceNotFound(d))
    }
    _ => ServerError::Io(io::Error::other("unknown JoinError variant")),
  }
}

fn map_join_to_bind_v6(e: hick_udp::JoinError) -> ServerError {
  match e {
    hick_udp::JoinError::Io(io) => ServerError::BindV6(hick_udp::BindError::Io(io)),
    hick_udp::JoinError::InterfaceNotFound(d) => {
      ServerError::BindV6(hick_udp::BindError::InterfaceNotFound(d))
    }
    _ => ServerError::Io(io::Error::other("unknown JoinError variant")),
  }
}

/// Pick the interface to bind when the caller pinned none.
///
/// Prefers an up, multicast-capable, non-loopback interface that satisfies
/// **all** requested families, then one that satisfies at least one, then the
/// same two rules over loopback. The loose fallback matters: without it an
/// IPv4-only NIC on a host with no global IPv6 would be rejected even though it
/// serves `with_ipv4(true).with_ipv6(true)` over v4 perfectly well. Reimplements
/// `hick-reactor/src/endpoint.rs:254-289`, which is private to that crate.
fn pick_default_interface_index(want_v4: bool, want_v6: bool) -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  let has_v4 = |i: &getifs::Interface| matches!(i.ipv4_addrs(), Ok(ref v) if !v.is_empty());
  let has_v6 = |i: &getifs::Interface| matches!(i.ipv6_addrs(), Ok(ref v) if !v.is_empty());
  let multicast_up_non_loopback = |i: &getifs::Interface| -> bool {
    let f = i.flags();
    f.contains(getifs::Flags::UP)
      && f.contains(getifs::Flags::MULTICAST)
      && !f.contains(getifs::Flags::LOOPBACK)
      && i.index() != 0
  };
  let loopback_up = |i: &getifs::Interface| -> bool {
    i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP)
  };
  let strict =
    |i: &&getifs::Interface| -> bool { (!want_v4 || has_v4(i)) && (!want_v6 || has_v6(i)) };
  let loose = |i: &&getifs::Interface| -> bool { (want_v4 && has_v4(i)) || (want_v6 && has_v6(i)) };
  let strict_non_loopback = ifs
    .iter()
    .find(|i| multicast_up_non_loopback(i) && strict(i));
  let loose_non_loopback = ifs
    .iter()
    .find(|i| multicast_up_non_loopback(i) && loose(i));
  let strict_loopback = ifs.iter().find(|i| loopback_up(i) && strict(i));
  let loose_loopback = ifs.iter().find(|i| loopback_up(i) && loose(i));
  strict_non_loopback
    .or(loose_non_loopback)
    .or(strict_loopback)
    .or(loose_loopback)
    .map(|i| i.index())
}

#[cfg(test)]
mod tests;

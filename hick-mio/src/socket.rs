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
///
/// `hick-udp`'s type rather than one of this crate's own, because the self-send
/// tracker it keys credits on lives there too — one definition, so a credit
/// recorded on this crate's IPv4 and one claimed on the tracker's cannot drift
/// apart. [`Family::index`] fixes the per-family array order, and it matches
/// [`mdns_proto::TransmitDelivery`]'s own so a driver-side array and a confirm
/// can never be indexed differently.
pub(crate) use hick_udp::Family;

/// The largest UDP payload `family` can **ever** carry, and therefore the only
/// sound proof that a refused datagram can never be sent. See
/// [`SendOutcome::TooLarge`] for why an errno is not one.
///
/// Both numbers fall out of the wire formats and neither is a tunable:
///
/// * IPv4 — a 16-bit total-length field caps the whole datagram at 65 535
///   bytes, of which a minimal IPv4 header takes 20 and the UDP header 8:
///   **65 507**. Options make the real ceiling lower, never higher.
/// * IPv6 — the 16-bit payload-length field caps everything after the fixed
///   header at 65 535, of which the UDP header takes 8: **65 527**. Extension
///   headers count against that payload length, so the real ceiling is again
///   only ever lower.
///
/// Both are therefore upper bounds that a host may not reach and can never
/// exceed, which is the direction that matters: a datagram *below* the bound
/// may still be refused for a reason that clears — a path MTU with DF set, on
/// Linux, reports the very same `EMSGSIZE` — and is classified transient, while
/// one above it is impossible on any route, at any MTU, forever.
///
/// RFC 2675 IPv6 jumbograms are deliberately not modelled. They need a
/// hop-by-hop option and a jumbo-capable path end to end, an mDNS message is
/// six orders of magnitude smaller than the threshold, and reading the bound
/// too low is the expensive direction — it would retire a producer whose
/// datagram the kernel would have accepted.
///
/// A free function rather than a method: [`Family`] is `hick-udp`'s type, and
/// this ceiling is `mdns-proto`'s constant, which that crate deliberately does
/// not depend on.
pub(crate) const fn max_udp_payload(family: Family) -> usize {
  match family {
    Family::V4 => mdns_proto::constants::MAX_UDP_PAYLOAD_V4,
    Family::V6 => mdns_proto::constants::MAX_UDP_PAYLOAD_V6,
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

/// The clock reads of ONE successful `send_to` attempt, on their way from
/// [`BoundSocket::send_attempt`] into [`SendOutcome::Sent`].
///
/// It exists so the `EINTR` retry has something to return: the attempt that
/// succeeded owns all three reads, and an interrupted attempt's are discarded
/// with it. See [`SendOutcome::Sent`] for what each one is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendStamps {
  submitted_wall: SystemTime,
  submitted_at: StdInstant,
  wire_at: StdInstant,
}

impl SendStamps {
  /// The [`SendOutcome`] a family that carried the datagram reports.
  const fn into_sent(self) -> SendOutcome {
    SendOutcome::Sent {
      submitted_wall: self.submitted_wall,
      submitted_at: self.submitted_at,
      wire_at: self.wire_at,
    }
  }
}

/// Outcome of one family's send.
///
/// The five are the whole vocabulary, and none may be collapsed into another:
/// the driver maps them one-to-one onto [`mdns_proto::FamilyDelivery`], and the
/// §10.1 withdrawal pump maps them onto per-family goodbye debt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
  /// The datagram reached the kernel, carrying **three** separate clock reads,
  /// one per consumer that needs a stamp from the send itself.
  ///
  /// Three, not one, and not two: each stamp is allowed to be wrong in exactly
  /// one direction, and the directions do not all agree. Folding any pair
  /// together silently breaks whichever consumer needed the other direction, so
  /// read the field docs before "simplifying" them. `hick-compio`'s
  /// `SendAttempt::Answered` carries the same three for the same reasons.
  ///
  /// There is a **fourth** use of a monotonic instant in the credit's lifetime —
  /// the [`SELF_SEND_TTL`](crate::selfsend::SELF_SEND_TTL) ageing — and it is
  /// deliberately not a fourth read here, nor a second consumer of `wire_at`. No
  /// instant belonging to the send can anchor it: the driver's receive stage has
  /// already run by the time any of these are taken, so the credit is unclaimable
  /// for the rest of its own tick and every such instant charges claim-free time
  /// to the window. It is anchored instead at the top of the following tick, on
  /// the same monotonic clock and in the same late-safe direction, by
  /// [`SelfSendTracker::seal`](crate::selfsend::SelfSendTracker::seal).
  ///
  /// **`submitted_wall` and `submitted_at` are read on consecutive statements,
  /// and that adjacency is load-bearing.** Together they are one reading of both
  /// clocks at one instant, which is what lets the self-send credit tell real
  /// elapsed time from a wall clock that stepped under it — see
  /// [`ClockPair`](crate::selfsend::ClockPair) and
  /// [`WALL_STEP_TOLERANCE`](crate::selfsend::WALL_STEP_TOLERANCE). A stall
  /// inserted between the two reads is charged to the credit as skew, so nothing
  /// may come between them.
  ///
  /// **All three come from the attempt that actually succeeded.** See
  /// [`BoundSocket::send_attempt`]: the `EINTR` retry re-reads its own
  /// pre-syscall clocks rather than carrying the interrupted attempt's forward.
  Sent {
    /// Wall clock, read **before** the syscall. Orders our own multicast
    /// loopback echo against the send that produced it, and nothing else.
    ///
    /// EARLY is the safe direction, and pre-syscall is the only way to get it:
    /// suppression compares this against the kernel's receive stamp on the echo,
    /// so `submitted_wall <= kernel send time <= echo rx time` must hold or the
    /// echo looks like a peer datagram that predated our send and this host
    /// processes its own probe or announcement as peer traffic.
    ///
    /// It is **not** how the credit ages.
    /// [`SELF_SEND_TTL`](crate::selfsend::SELF_SEND_TTL) runs off the tick-top
    /// instant instead, precisely because the gap between this read and the
    /// syscall is unbounded — a preemption, a page fault, or the `EINTR` retry
    /// all widen it — and charging that gap to the credit's life is what expires
    /// a credit before its echo can claim it.
    submitted_wall: SystemTime,
    /// Monotonic, read **before** the syscall and immediately after
    /// `submitted_wall`. Anchors the **core's** refresh schedule, and is the
    /// wall stamp's partner in the self-send credit's step check.
    ///
    /// EARLY is the safe direction here too: an anchor at or before the true
    /// acceptance can only understate how fresh a family's peers are, so the
    /// next refresh lands sooner than strictly needed. A late anchor would push
    /// a refresh past the records' own TTL.
    ///
    /// The second consumer needs no direction at all, only the adjacency: it
    /// subtracts this from a later monotonic reading to get real elapsed time,
    /// and compares that against what the wall clock claims elapsed. Moving this
    /// read away from `submitted_wall` breaks it — see the type-level note.
    submitted_at: StdInstant,
    /// Monotonic, read **after** the syscall returned success. Anchors
    /// [`FamilyWireGate`](crate::driver::FamilyWireGate), and nothing else.
    ///
    /// EARLY is the UNSAFE direction here — the opposite of the two above, and
    /// the whole reason this is a third stamp rather than `submitted_at` reused.
    /// The gate measures the real spacing between bytes on ONE family's wire.
    /// Nothing bounds the delay between a pre-syscall clock read and the syscall
    /// that follows it: a preempted thread, a signal handler, or a page fault
    /// puts the datagram on the wire long after the stamp. Anchored at
    /// `submitted_at`, a send stalled by `P` re-opens its own family `P` early —
    /// at RFC 6762 §8.1's 250 ms inter-probe interval a 200 ms stall would leave
    /// 50 ms of true spacing, and it would do so on exactly the loaded host the
    /// spacing exists to protect.
    ///
    /// The self-send credit's ageing used to share this stamp. It no longer may:
    /// the gate is asking "when did these bytes leave", which is a property of
    /// this send, while the credit is asking "how long has the echo had to come
    /// back", which cannot start before the next tick lets it. Same direction,
    /// different question — see the type-level note above.
    wire_at: StdInstant,
  },
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
  ///   firewall. `send_errors` is bumped.
  /// * [`Sockets::send_one`] called with a `dst` whose family is not the one
  ///   selected. **Nothing was attempted at all** — that guard fires before
  ///   boundness is even checked, so the family may or may not be bound — and it
  ///   is deliberately NOT counted as `send_errors`, because a caller-error
  ///   guard is not a network failure. No call site in this crate produces it.
  ///
  /// Every one of them is a **may-clear** failure, and that is what separates
  /// this from [`SendOutcome::TooLarge`]: a route comes back, a buffer drains, a
  /// firewall rule is withdrawn. Nothing may read this variant as evidence that
  /// a datagram can never be sent — see [`SendReport::undeliverable`].
  ///
  /// The §10.1 withdrawal pump maps this to a retry, never a write-off: see
  /// [`SendOutcome::NoSocket`], which exists precisely so the two can differ.
  Failed,
  /// A bound socket refused the datagram, and its body is past
  /// [`max_udp_payload`] — the hard limit UDP on this family can ever
  /// carry.
  ///
  /// A non-delivery like [`SendOutcome::Failed`] in every respect the wire cares
  /// about: the family is obligated, reported [`FamilyDelivery::Missed`], and
  /// charged a send failure and a `send_errors` bump. It differs in exactly one
  /// thing, and that thing is the reason it is a separate variant — **a retry
  /// cannot help**. The datagram's size is a property of the datagram, so the
  /// identical bytes re-offered to the identical socket are refused identically,
  /// forever.
  ///
  /// # Permanence is proved by the SIZE, and never by the errno
  ///
  /// This variant used to be decided by an OS-keyed `EMSGSIZE` table, and that is
  /// unsound in both directions.
  ///
  /// **An errno cannot prove permanence.** Linux UDP answers `EMSGSIZE` both for
  /// a payload past the hard maximum — permanent — and for a write past the
  /// *currently known* path MTU with `DF` set, which the next attempt may get
  /// past after an MTU probe or a route change (udp(7), ip(7) `IP_MTU_DISCOVER`).
  /// One errno, two meanings, and the table read the transient one as permanent:
  /// enough to retire a perfectly healthy service over a link whose MTU had just
  /// dropped.
  ///
  /// **And a table cannot prove impossibility either.** A target it does not
  /// list, or lists wrongly, answers "not permanent" for a datagram that is
  /// genuinely impossible, and the sustained producer re-arms it until the
  /// process ends — the defect this variant was introduced to close, quietly
  /// restored on every platform the table missed.
  ///
  /// So the question asked is `body.len() > max_udp_payload(family)`: exact,
  /// platform-independent, and a property of the datagram rather than of the
  /// moment. The kernel's refusal is still required — it is what proves these
  /// bytes did not go out, and a host that somehow accepted them has manifestly
  /// contradicted the classification — but *which* refusal it was decides
  /// nothing. Every refusal of a datagram within the limit is
  /// [`SendOutcome::Failed`], `EMSGSIZE` included, which is the cheap direction:
  /// a retry costs one datagram per round, a wrong retirement costs the service.
  ///
  /// This crate can produce such a datagram: [`ServerOptions::with_max_payload_size`]
  /// admits any size up to the IPv6 hard limit, which is 20 bytes above IPv4's, so
  /// a v4 family can be handed an encoded message it can never carry.
  /// `an_oversized_datagram_the_kernel_can_never_carry_is_reported_too_large`
  /// pins the kernel's deterministic refusal of exactly that, and
  /// `an_emsgsize_below_the_hard_limit_is_transient_and_retried` pins the
  /// direction that must not be taken wrongly.
  ///
  /// What it costs the PRODUCER depends on whether the core will re-offer the
  /// datagram, which is [`Transmit::obligation`](mdns_proto::Transmit::obligation)'s
  /// question and not this layer's. See [`SendReport::undeliverable`] for the
  /// aggregate, and `Mdns::drain_transmits` for the asymmetry it feeds.
  ///
  /// [`FamilyDelivery::Missed`]: mdns_proto::FamilyDelivery::Missed
  /// [`ServerOptions::with_max_payload_size`]: crate::ServerOptions::with_max_payload_size
  TooLarge,
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
  /// The stamps that ORDER the self-send credit against its echo, if this family
  /// carried the datagram: the pre-syscall wall reading and the monotonic
  /// partner read next to it.
  ///
  /// Both, never just the wall one. The wall stamp alone cannot say whether it
  /// is still on the timeline the echo's kernel receive stamp will be taken on —
  /// see [`ClockPair`](crate::selfsend::ClockPair) — and neither is an age. See
  /// [`SendOutcome::Sent`].
  pub(crate) const fn credit_stamp(self) -> Option<crate::selfsend::ClockPair> {
    match self {
      Self::Sent {
        submitted_wall,
        submitted_at,
        ..
      } => Some(crate::selfsend::ClockPair::new(
        submitted_wall,
        submitted_at,
      )),
      _ => None,
    }
  }

  /// The instant this family's bytes were actually on its wire, if they were.
  ///
  /// The **wire gate's** anchor, read after the syscall succeeded.
  ///
  /// Never fold this into [`SendOutcome::confirm_anchor`]. The two answer
  /// different questions — "when may the core assume peers heard us" versus
  /// "when did this wire last carry bytes" — and they are wrong in opposite
  /// directions, so each consumer can absorb only its own.
  pub(crate) const fn wire_time(self) -> Option<StdInstant> {
    match self {
      Self::Sent { wire_at, .. } => Some(wire_at),
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

/// Whether one family may be offered this datagram, **asked at the moment it
/// would be offered**: inside [`Sockets::send_one`], with that family's `sendto`
/// as the next statement.
///
/// # Why this is a trait and not a `[bool; 2]`
///
/// It replaces a mask the caller computed once for the whole fan-out, and the
/// reason is that the fan-out is SEQUENTIAL. The IPv4 syscall — and any
/// preemption around it — ran between the mask's IPv6 entry being decided and
/// that entry being applied. A gap IPv6 had genuinely paid by then still read as
/// unpaid, so the family came back [`SendOutcome::Gated`], which the driver's
/// projection reports to the core as `Missed`: it spends the core's
/// partial-round patience and holds the RFC 6762 §8 phase for a wire that was
/// ready.
///
/// **A reading is spent by its first consumer; a decision is spent by its first
/// application.** A per-family decision has exactly one application — that
/// family's own syscall — and as a trait it cannot reach any other. As a
/// `[bool; 2]` it had two applications, and the second one travelled across a
/// syscall to reach its own.
///
/// # Where it is asked, and why there
///
/// [`Sockets::send_one`] asks **after** boundness and immediately **before** the
/// syscall.
///
/// * After boundness, so an unbound family reports [`SendOutcome::NoSocket`]
///   whatever this answers. No admission can invent an obligation for a link
///   that does not exist, and `NoSocket` is what the RFC 6762 §10.1 per-family
///   goodbye debt writes off.
/// * Immediately before the syscall, so nothing — least of all the other
///   family's `sendto` — runs between the answer and the send it governs.
pub(crate) trait FamilyAdmission {
  /// Called once per family, immediately before that family's `sendto`, and
  /// nowhere else. An implementation that reads a clock reads it here.
  fn admits(&self, family: Family) -> bool;
}

/// Every family open.
///
/// `#[cfg(test)]`, because **no production send is unconditional**. The two that
/// exist each carry a real answer: a transmit is admitted by its producer's wire
/// gate (whose zero-`min_gap` case is what makes a one-shot §6 reply ungated,
/// rather than a separate admission), and an RFC 6762 §10.1 goodbye is admitted
/// by its outstanding per-family debt. Nothing in the crate wants "yes" as a
/// constant, and the old `ALLOW_BOTH` that did was the withdrawal pump's
/// unknown-token fallback, which is now a `true` inside the debt lookup itself.
#[cfg(test)]
pub(crate) struct Ungated;

#[cfg(test)]
impl FamilyAdmission for Ungated {
  fn admits(&self, _family: Family) -> bool {
    true
  }
}

/// A fixed per-family answer, for the tests that are about what
/// [`Sockets::send_one`] does with a closed family rather than about what closed
/// it.
///
/// `#[cfg(test)]` permanently. A frozen per-family decision is precisely the
/// shape [`FamilyAdmission`] exists to keep out of production, so the one place
/// it survives is behind a door no production build has.
#[cfg(test)]
pub(crate) struct Mask(pub(crate) [bool; 2]);

#[cfg(test)]
impl FamilyAdmission for Mask {
  fn admits(&self, family: Family) -> bool {
    self.0.get(family.index()).copied().unwrap_or(true)
  }
}

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
  /// Per-call stalls injected **inside** this family's raw receive, consumed one
  /// per read; once exhausted every receive proceeds at full speed.
  ///
  /// It stands in for the one thing no test can ask a real host for: the drain
  /// thread losing the CPU between the tick's `SelfSendTracker::seal` and the
  /// read whose claim is weighed against it. That stretch is post-opportunity
  /// time, which [`SELF_SEND_TTL`](crate::selfsend::SELF_SEND_TTL) requires be
  /// charged in full — and a claim that ignores it is exactly what pushes the
  /// false-suppression window past its bound.
  #[cfg(test)]
  forced_recv_delays: std::collections::VecDeque<std::time::Duration>,
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
  /// Stand in for this family's [`max_udp_payload`], so an ordinary
  /// datagram a live producer emits is genuinely oversize for it.
  ///
  /// The real condition IS reproducible — a 70 000-byte payload, which
  /// `an_oversized_datagram_the_kernel_can_never_carry_is_reported_too_large`
  /// uses — but only against one socket at a time and only for bytes the driver
  /// would never encode by itself. Reaching the driver's own decision needs the
  /// datagram a live producer emits to be refused, on every bound family, at a
  /// moment the test chooses, which is what this gives.
  ///
  /// It lowers the ceiling rather than returning the outcome, so the refusal is
  /// classified by the very comparison a real oversized send goes through. A
  /// hook that answered [`SendOutcome::TooLarge`] directly would still pass if
  /// that comparison, or the constants behind it, were wrong.
  #[cfg(test)]
  forced_payload_ceiling: Option<usize>,
  /// Fail every send on this family with the platform's own oversized-datagram
  /// errno, **whatever the body's size**.
  ///
  /// The one condition no test can otherwise provoke: Linux reports `EMSGSIZE`
  /// for a write past the current path MTU with `DF` set, on a datagram far
  /// below the hard limit and on a link whose next probe may carry it. It must
  /// be [`SendOutcome::Failed`], and this is what puts it in front of the
  /// classification.
  #[cfg(test)]
  forced_send_emsgsize: bool,
  /// How many sends the two hooks above have actually refused.
  ///
  /// A test asserting that a producer SURVIVED an undeliverable datagram is
  /// vacuous unless the datagram was really offered; this is what proves it was.
  #[cfg(test)]
  forced_send_refusals: u32,
  /// Fail this family's next `n` send **attempts** with `EINTR`, consumed one
  /// per attempt.
  ///
  /// A signal landing between a `sendto` entering the kernel and returning is
  /// not something a test can arrange against a healthy socket, and the retry it
  /// drives is the one path on which a single send reads its pre-syscall clocks
  /// twice. Which of the two readings survives into [`SendOutcome::Sent`] is the
  /// whole question — an interrupted attempt's stamps can precede the successful
  /// syscall by an unbounded stall — so the path must not go untested.
  #[cfg(test)]
  forced_send_eintr: u32,
  /// Per-call stalls injected **between an attempt's pre-syscall stamps and its
  /// syscall**, consumed one per attempt; once exhausted every send proceeds at
  /// full speed.
  ///
  /// It stands in for the one thing no test can ask a real host for: the thread
  /// losing the CPU after [`BoundSocket::send_attempt`] reads its pre-syscall
  /// clocks and before `sendto` runs. That window is what a wire gate anchored
  /// at a pre-syscall stamp gives back — a family re-armed inside the minimum
  /// spacing RFC 6762 gives its wire — and equally what a self-send credit aged
  /// from a pre-syscall stamp gives back: a credit that expires before its own
  /// echo can claim it. Neither path is reachable in a test without this.
  #[cfg(test)]
  forced_send_delays: std::collections::VecDeque<std::time::Duration>,
  /// When each successful send actually put bytes on this family's wire, read
  /// **inside** the send path after any injected stall.
  ///
  /// This is the wire's own history and owes nothing to how `send_one` stamps
  /// anything, which is what lets a test assert real spacing rather than the
  /// driver's account of it.
  #[cfg(test)]
  wire_times: Vec<StdInstant>,
  /// Make this family's next `Registry::deregister` fail.
  ///
  /// A partial deregistration failure is what leaves a ghost registration in the
  /// caller's selector, and a healthy socket in a live `Poll` cannot be made to
  /// produce one on demand.
  #[cfg(test)]
  forced_deregister_error: bool,
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
      forced_recv_delays: std::collections::VecDeque::new(),
      #[cfg(test)]
      forced_send_wouldblock: false,
      #[cfg(test)]
      forced_payload_ceiling: None,
      #[cfg(test)]
      forced_send_emsgsize: false,
      #[cfg(test)]
      forced_send_refusals: 0,
      #[cfg(test)]
      forced_send_eintr: 0,
      #[cfg(test)]
      forced_send_delays: std::collections::VecDeque::new(),
      #[cfg(test)]
      wire_times: Vec::new(),
      #[cfg(test)]
      forced_deregister_error: false,
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
  /// Wraps the free [`raw_recv`] purely so a test can inject what no healthy
  /// loopback socket will produce: the transient, non-consuming receive error of
  /// [`BoundSocket::forced_recv_errors`], and the mid-drain stall of
  /// [`BoundSocket::forced_recv_delays`].
  fn raw_recv(&mut self, buf: &mut [u8], is_v4: bool) -> io::Result<RecvMeta> {
    // Deliberately BEFORE the read, and before the injected errors: that is
    // where a preempted drain thread really loses the CPU, and the stall has to
    // be charged whether or not this particular read yields a datagram.
    #[cfg(test)]
    if let Some(stall) = self.forced_recv_delays.pop_front()
      && !stall.is_zero()
    {
      std::thread::sleep(stall);
    }
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

  /// One `send_to` on this family's socket, retrying once on `EINTR`, and the
  /// clock reads of the attempt that actually **succeeded**.
  ///
  /// `EINTR` means a signal landed mid-syscall; it is not backpressure, so the
  /// socket is still writable and an immediate retry normally succeeds. Retrying
  /// here is what keeps a signal from costing the datagram a whole re-arm cycle,
  /// since a family this driver reports as missed is not tried again until the
  /// core re-offers it. Exactly one retry: a signal storm must not spin inside a
  /// syscall wrapper.
  ///
  /// # Why the stamps are read here and not by the caller
  ///
  /// A retry makes "the pre-syscall instant" ambiguous, and the wrong answer is
  /// silently wrong. Carrying the interrupted attempt's stamps forward backdates
  /// every consumer by an entire failed syscall plus whatever preempted the
  /// thread between the two: `submitted_wall` would order the self-send credit
  /// against an instant a whole stall before the datagram existed, widening the
  /// window in which a co-resident peer's byte-identical datagram can steal that
  /// credit, and `submitted_at` would tell the core its peers were refreshed
  /// before they were. Reading them per attempt in
  /// [`BoundSocket::send_attempt`] and returning the survivor's keeps every
  /// stamp's documented direction true of the syscall it actually describes.
  ///
  /// Also the seam for what no healthy loopback socket will produce: the
  /// `WouldBlock` of [`BoundSocket::forced_send_wouldblock`], and the refusals of
  /// [`BoundSocket::forced_payload_ceiling`] and
  /// [`BoundSocket::forced_send_emsgsize`].
  fn raw_send(&mut self, body: &[u8], dst: SocketAddr) -> io::Result<SendStamps> {
    #[cfg(test)]
    if self.forced_send_wouldblock {
      return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    // Raised as an error from the syscall rather than as a `SendOutcome`, so the
    // injected refusal is classified by the very comparison a real kernel
    // refusal goes through. Both hooks raise the SAME error, which is the point:
    // what separates them is the body's size against the ceiling, and nothing
    // about the errno.
    #[cfg(test)]
    if self.forced_send_emsgsize || self.forced_payload_ceiling.is_some_and(|c| body.len() > c) {
      self.forced_send_refusals = self.forced_send_refusals.saturating_add(1);
      return Err(emsgsize_for_test());
    }
    match self.send_attempt(body, dst) {
      Err(e) if e.kind() == io::ErrorKind::Interrupted => self.send_attempt(body, dst),
      other => other,
    }
  }

  /// The largest body this family will accept, which is
  /// [`max_udp_payload`] unless a test has lowered it. See
  /// [`BoundSocket::forced_payload_ceiling`].
  fn payload_ceiling(&self, family: Family) -> usize {
    #[cfg(test)]
    if let Some(ceiling) = self.forced_payload_ceiling {
      return ceiling;
    }
    max_udp_payload(family)
  }

  /// One `send_to` attempt: its own pre-syscall clock reads, the syscall, and —
  /// only if the kernel accepted the datagram — the post-syscall read.
  ///
  /// The two pre-syscall stamps are captured as late as possible, with the
  /// syscall as the next statement; the post-syscall one as early as possible,
  /// before any telemetry, which is not free and would otherwise be charged to
  /// the next datagram's wire gap. See [`SendOutcome::Sent`] for what each is
  /// for and the one direction each may be wrong in.
  ///
  /// Also the seam for the two things no healthy loopback socket will produce:
  /// the pre-syscall stall of [`BoundSocket::forced_send_delays`] and the
  /// interruption of [`BoundSocket::forced_send_eintr`]. Both are consumed
  /// **per attempt**, exactly as the real conditions occur.
  fn send_attempt(&mut self, body: &[u8], dst: SocketAddr) -> io::Result<SendStamps> {
    let submitted_wall = SystemTime::now();
    let submitted_at = StdInstant::now();
    // Deliberately AFTER this attempt's pre-syscall stamps and BEFORE its
    // syscall: that is the window a preempted thread opens for real.
    #[cfg(test)]
    if let Some(stall) = self.forced_send_delays.pop_front()
      && !stall.is_zero()
    {
      std::thread::sleep(stall);
    }
    #[cfg(test)]
    if self.forced_send_eintr > 0 {
      self.forced_send_eintr -= 1;
      return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    self.sock.send_to(body, dst)?;
    let wire_at = StdInstant::now();
    #[cfg(test)]
    self.wire_times.push(wire_at);
    Ok(SendStamps {
      submitted_wall,
      submitted_at,
      wire_at,
    })
  }

  /// Remove this socket from `registry`.
  ///
  /// Wraps `Registry::deregister` purely so a test can inject the partial
  /// failure that leaves a ghost registration behind. See
  /// [`BoundSocket::forced_deregister_error`].
  fn raw_deregister(&mut self, registry: &Registry) -> io::Result<()> {
    #[cfg(test)]
    if self.forced_deregister_error {
      return Err(io::Error::other("forced deregister failure"));
    }
    registry.deregister(&mut self.sock)
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
  ///
  /// **It is also the only registry anything here deregisters through.** A
  /// caller driving more than one `Poll` could otherwise hand
  /// [`Sockets::deregister`] a foreign one, and the platforms disagree about
  /// what that means: kqueue ignores the absent filter and reports success,
  /// epoll returns `ENOENT`. Either way the registration the *original*
  /// selector holds survives, so honouring a caller-supplied registry could only
  /// ever forget a registration that still exists.
  ///
  /// INVARIANT: `Some` whenever either family holds a token. A family is only
  /// given a token by a `register` that succeeded through this registry, and
  /// only stripped of one by a `deregister` through it that the selector
  /// confirmed — including the rollback of a partial `register`, which restores
  /// this field when its own cleanup fails.
  registry: Option<Registry>,
  /// The two tokens the caller reserved for us, recorded even for a family that
  /// is not bound: [`Sockets::owns`] must claim both, or the caller would route
  /// a token it gave away back into its own handler.
  tokens: Option<(Token, Token)>,
  /// Which family the next [`Sockets::recv`] reads from. Lives here, not in the
  /// call, because the starvation it prevents is across ticks: a per-call or
  /// per-tick preference resets to the same family every time.
  recv_rotor: RecvRotor,
  /// Make the IPv6 half of the next [`Sockets::register`] fail, so the partial
  /// registration and its rollback can be exercised.
  ///
  /// It lives here rather than on a [`BoundSocket`] because the rollback has to
  /// be testable on a host with no IPv6 socket to fail — which is most CI
  /// runners, and macOS in particular.
  #[cfg(test)]
  forced_v6_register_error: bool,
  /// Report this index as the interface every received datagram arrived on,
  /// overriding the cmsg metadata. See [`Sockets::rx_interface`].
  ///
  /// The ingress trust boundary drops a datagram whose interface index is not
  /// the one this endpoint bound, and no unit test can make a datagram arrive on
  /// a NIC — real or otherwise — that the host does not route to this socket.
  /// The gate is the difference between a responder that answers only its own
  /// link and one an adjacent network can drive, so it must not go untested.
  #[cfg(test)]
  forced_rx_interface: Option<u32>,
  /// Report this address as the peer every received datagram came from,
  /// overriding the cmsg metadata. See [`Sockets::rx_peer`].
  ///
  /// The other half of [`Sockets::forced_rx_interface`], and there for the same
  /// reason: an IPv6 source address carries a scope id naming the link it came
  /// from, the trust boundary weighs it exactly as it weighs the receive
  /// interface, and no unit test can make a host deliver a datagram from a link
  /// it is not on. A loopback fixture only ever sees `127.0.0.1` / `::1`, which
  /// the boundary admits by construction, so without this the scope witness is
  /// unreachable through the real receive path on every platform.
  #[cfg(test)]
  forced_rx_peer: Option<SocketAddr>,
  /// Report every received datagram as carrying no kernel receive timestamp,
  /// overriding the cmsg metadata. See [`Sockets::rx_time`].
  ///
  /// [`MatchMode::Degraded`](crate::selfsend::MatchMode::Degraded) is the whole
  /// of the self-send match on Windows and on any Unix kernel that delivers no
  /// timestamp cmsg — and every Unix host a test runs on does deliver one, so
  /// without this the degraded arm of the drain's claim is unreachable from a
  /// test on every platform that can run one.
  #[cfg(test)]
  forced_no_rx_time: bool,
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
  ///
  /// **The degradation is keyed to `Ok(empty)` and to nothing else.** A family
  /// whose address enumeration *failed* is not a family this interface has no
  /// address in — see [`has_addr_in`] — and it fails the bind rather than
  /// quietly dropping the family.
  ///
  /// **Only a requested family is probed at all**, which is what keeps that
  /// strictness from costing availability elsewhere: an IPv6 enumeration error
  /// says nothing about an IPv4-only bind, so failing one on it would be a
  /// refusal bought with no decision.
  pub(crate) fn bind(
    opts: &ServerOptions,
    #[cfg(feature = "stats")] stats: std::sync::Arc<hick_trace::stats::Stats>,
  ) -> Result<Self, ServerError> {
    if !opts.ipv4() && !opts.ipv6() {
      return Err(ServerError::NoFamilyEnabled);
    }

    let interface_index = match opts.interface_index() {
      Some(i) => i,
      None => pick_default_interface_index(opts.ipv4(), opts.ipv6())
        .map_err(ServerError::Io)?
        .ok_or_else(|| {
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
    //
    // `&&` short-circuits, so a family the caller switched off is never probed
    // and therefore cannot fail: the availability property is the operator's,
    // not a promise some later reader has to keep.
    let (bind_v4, bind_v6) = match getifs::interface_by_index(interface_index) {
      Ok(Some(i)) => (
        opts.ipv4() && has_addr_in(&i, Family::V4).map_err(ServerError::Io)?,
        opts.ipv6() && has_addr_in(&i, Family::V6).map_err(ServerError::Io)?,
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
      #[cfg(test)]
      forced_v6_register_error: false,
      #[cfg(test)]
      forced_rx_interface: None,
      #[cfg(test)]
      forced_rx_peer: None,
      #[cfg(test)]
      forced_no_rx_time: false,
      #[cfg(feature = "stats")]
      stats,
    })
  }

  /// The interface a received datagram arrived on, as the ingress trust
  /// boundary must read it.
  ///
  /// Production reads it straight off the cmsg metadata; the `#[cfg(test)]`
  /// override is the only way to present a datagram from an interface this host
  /// does not deliver on. See [`Sockets::forced_rx_interface`].
  pub(crate) fn rx_interface(&self, meta: &RecvMeta) -> u32 {
    #[cfg(test)]
    if let Some(idx) = self.forced_rx_interface {
      return idx;
    }
    meta.interface_index()
  }

  /// The peer a datagram came from, as the ingress trust boundary must read it:
  /// the WHOLE address, scope id included.
  ///
  /// `RecvMeta::peer` already carries the scope id on every platform this crate
  /// supports — it is the boundary that used to discard it by taking `.ip()`,
  /// and with it the only proof an IPv6 link-local source offers of which link
  /// it is actually on.
  ///
  /// Production reads it straight off the cmsg metadata; the `#[cfg(test)]`
  /// override is the only way to present a peer from a link this host is not on.
  /// See [`Sockets::forced_rx_peer`].
  pub(crate) fn rx_peer(&self, meta: &RecvMeta) -> SocketAddr {
    #[cfg(test)]
    if let Some(peer) = self.forced_rx_peer {
      return peer;
    }
    meta.peer()
  }

  /// The kernel receive timestamp a datagram carried, as the self-send match
  /// must read it — `None` when the platform delivered no timestamp cmsg, which
  /// is what degrades that match to
  /// [`MatchMode::Degraded`](crate::selfsend::MatchMode::Degraded).
  ///
  /// Production reads it straight off the cmsg metadata; the `#[cfg(test)]`
  /// override is the only way to present the timestamp-less datagram a Windows
  /// host hands the drain on every single receive. See
  /// [`Sockets::forced_no_rx_time`].
  pub(crate) fn rx_time(&self, meta: &RecvMeta) -> Option<SystemTime> {
    #[cfg(test)]
    if self.forced_no_rx_time {
      return None;
    }
    meta.rx_time()
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
    if let Err(e) = self.register_v6(registry, v6) {
      // Never sit half-registered: the caller would receive readiness for one
      // family while `owns`/`deregister` disagree about what we hold.
      if let Err(_rollback) = deregister_family(self.v4.as_mut(), registry) {
        // The rollback ITSELF failed, so IPv4 is still in the caller's selector
        // under `v4`. Adopt the registration state we were about to discard:
        // `owns` must keep claiming a token the selector still routes to us, and
        // `deregister` must have the clone it needs to retry the removal. The
        // caller sees `register` fail and — because this leaves us registered —
        // is told by the `AlreadyExists` above to deregister before retrying,
        // which is precisely the cleanup that is outstanding.
        hick_trace::debug!(
          error = %_rollback,
          "rolling back a partial registration failed; keeping the registration \
           state so the leftover family can still be deregistered"
        );
        self.registry = Some(cloned);
        self.tokens = Some((v4, v6));
      }
      return Err(e);
    }
    self.registry = Some(cloned);
    self.tokens = Some((v4, v6));
    Ok(())
  }

  /// Register the IPv6 family, or the injected failure standing in for it.
  fn register_v6(&mut self, registry: &Registry, token: Token) -> io::Result<()> {
    #[cfg(test)]
    if self.forced_v6_register_error {
      return Err(io::Error::other("forced v6 registration failure"));
    }
    register_family(self.v6.as_mut(), registry, token)
  }

  /// Remove both sockets from the selector they were registered into, and drop
  /// our clone of it.
  ///
  /// It takes no `Registry`, and that absence is the guarantee: the removal goes
  /// through the clone taken at [`Sockets::register`], so a caller driving two
  /// `Poll`s cannot deregister us from the wrong one. See [`Sockets::registry`].
  ///
  /// Both families are always attempted and the first failure is reported. A
  /// family the selector did not confirm keeps its token, its readiness and its
  /// interest, and the clone and the token pair are kept alongside — so `owns`
  /// still claims a token the selector still routes to us, and calling this
  /// again retries exactly the removal that is outstanding. Forgetting the pair
  /// on a failure would strand that registration: no token to recognise its
  /// events by, and no registry to remove it with.
  pub(crate) fn deregister(&mut self) -> io::Result<()> {
    let Self {
      v4,
      v6,
      registry,
      tokens,
      ..
    } = self;
    // Nothing was ever registered through us, so there is nothing to remove and
    // no clone to drop. By the invariant on `registry`, neither family can be
    // holding a token here.
    let Some(reg) = registry.as_ref() else {
      return Ok(());
    };
    let r4 = deregister_family(v4.as_mut(), reg);
    let r6 = deregister_family(v6.as_mut(), reg);
    r4.and(r6)?;
    *registry = None;
    *tokens = None;
    Ok(())
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
  /// `admission` is the caller's per-family gate. It is **not** consulted here:
  /// each family is asked inside its own [`Sockets::send_one`], immediately
  /// before that family's syscall, so this fan-out carries no decision from one
  /// family across to the other. A family that answers `false` is not offered
  /// the datagram and comes back [`SendOutcome::Gated`]. See
  /// [`FamilyAdmission`].
  pub(crate) fn send_to(
    &mut self,
    body: &[u8],
    dst: SocketAddr,
    admission: &impl FamilyAdmission,
  ) -> SendReport {
    if is_mdns_multicast(dst) {
      let v4 = self.send_one(Family::V4, body, MDNS_V4_DST, admission);
      let v6 = self.send_one(Family::V6, body, MDNS_V6_DST, admission);
      return SendReport {
        v4,
        v6,
        loops_back: true,
      };
    }
    match Family::of(dst) {
      Family::V4 => SendReport {
        v4: self.send_one(Family::V4, body, dst, admission),
        v6: SendOutcome::NoSocket,
        loops_back: false,
      },
      Family::V6 => SendReport {
        v4: SendOutcome::NoSocket,
        v6: self.send_one(Family::V6, body, dst, admission),
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
  /// `admission` is the caller's per-family gate: a bound family it declines is
  /// not offered the datagram and reports [`SendOutcome::Gated`]. It is asked
  /// **after** boundness — so an unbound family still reports
  /// [`SendOutcome::NoSocket`], and no gate can invent an obligation for a link
  /// that does not exist — and immediately **before** the syscall, so nothing
  /// runs between the answer and the send it governs. See [`FamilyAdmission`].
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
    admission: &impl FamilyAdmission,
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
    // The hard ceiling this family's wire format imposes, read BEFORE the
    // admission so that nothing at all stands between that decision and the
    // syscall it governs. Placement is all this costs: it is a constant of the
    // address family rather than a reading of anything that can change, so no
    // amount of time passing over it could make it stale.
    let ceiling = fam.payload_ceiling(family);
    // Asked HERE, with this family's syscall as the next statement. Nothing runs
    // between the two — least of all the OTHER family's `sendto`, which is what
    // a fan-out-wide mask put there. See `FamilyAdmission`.
    if !admission.admits(family) {
      return SendOutcome::Gated;
    }
    // Every clock read belongs to the attempt that succeeded, and is taken
    // inside `send_attempt` for that reason — the `EINTR` retry is a second
    // syscall, and a stamp read out here would describe the first one. See
    // [`SendOutcome::Sent`].
    match fam.raw_send(body, dst) {
      Ok(stamps) => {
        hick_trace::trace!(dst = %dst, len = body.len(), via_v4 = family.is_v4(), "send_to");
        #[cfg(feature = "stats")]
        {
          stats.packets_tx(1);
          stats.bytes_tx(body.len() as u64);
        }
        stamps.into_sent()
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
      Err(e) => {
        hick_trace::debug!(error = %e, dst = %dst, "send_to failed");
        #[cfg(feature = "stats")]
        stats.send_errors(1);
        // Both are a non-delivery on an obligated family and both are counted
        // above; they are told apart for one question only — can these bytes
        // EVER leave on this socket. The refusal proves they did not leave now;
        // the SIZE is the only thing that proves they never can. `e` is
        // deliberately not consulted: an `EMSGSIZE` is equally what Linux
        // reports for a write past the current path MTU, which the next attempt
        // may get past. See `SendOutcome::TooLarge`.
        if body.len() > ceiling {
          SendOutcome::TooLarge
        } else {
          SendOutcome::Failed
        }
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

  /// Stall this family's next raw receives, one entry per **read**. See
  /// [`BoundSocket::forced_recv_delays`].
  #[cfg(test)]
  pub(crate) fn force_recv_delays_for_test(
    &mut self,
    family: Family,
    stalls: &[std::time::Duration],
  ) {
    if let Some(fam) = self.family_mut(family) {
      fam.forced_recv_delays = stalls.iter().copied().collect();
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

  /// Lower this family's hard UDP payload ceiling, so an ordinary datagram is
  /// genuinely too large for it. `None` restores the family's real limit. See
  /// [`BoundSocket::forced_payload_ceiling`].
  #[cfg(test)]
  pub(crate) fn force_payload_ceiling_for_test(&mut self, family: Family, ceiling: Option<usize>) {
    if let Some(fam) = self.family_mut(family) {
      fam.forced_payload_ceiling = ceiling;
    }
  }

  /// Fail every send on this family with the platform's own oversized-datagram
  /// errno, whatever the body's size. See
  /// [`BoundSocket::forced_send_emsgsize`].
  #[cfg(test)]
  pub(crate) fn force_send_emsgsize_for_test(&mut self, family: Family, fail: bool) {
    if let Some(fam) = self.family_mut(family) {
      fam.forced_send_emsgsize = fail;
    }
  }

  /// How many sends the two hooks above have refused on this family. An unbound
  /// family has refused nothing. See [`BoundSocket::forced_send_refusals`].
  #[cfg(test)]
  pub(crate) fn forced_send_refusals_for_test(&mut self, family: Family) -> u32 {
    self
      .family_mut(family)
      .map_or(0, |fam| fam.forced_send_refusals)
  }

  /// Stall this family's next send attempts between their pre-syscall stamps
  /// and the syscall, one entry per **attempt**. See
  /// [`BoundSocket::forced_send_delays`].
  #[cfg(test)]
  pub(crate) fn force_send_delays_for_test(
    &mut self,
    family: Family,
    stalls: &[std::time::Duration],
  ) {
    if let Some(fam) = self.family_mut(family) {
      fam.forced_send_delays = stalls.iter().copied().collect();
    }
  }

  /// Interrupt this family's next `n` send attempts with `EINTR`. See
  /// [`BoundSocket::forced_send_eintr`].
  #[cfg(test)]
  pub(crate) fn force_send_eintr_for_test(&mut self, family: Family, n: u32) {
    if let Some(fam) = self.family_mut(family) {
      fam.forced_send_eintr = n;
    }
  }

  /// Report `idx` as the interface every subsequent receive arrived on. See
  /// [`Sockets::forced_rx_interface`].
  #[cfg(test)]
  pub(crate) const fn force_rx_interface_for_test(&mut self, idx: Option<u32>) {
    self.forced_rx_interface = idx;
  }

  /// Report `peer` as the source of every subsequent receive, scope id and all.
  /// See [`Sockets::forced_rx_peer`].
  #[cfg(test)]
  pub(crate) const fn force_rx_peer_for_test(&mut self, peer: Option<SocketAddr>) {
    self.forced_rx_peer = peer;
  }

  /// Present every subsequent receive as carrying no kernel timestamp, which is
  /// what drives the drain's degraded self-send claim. See
  /// [`Sockets::forced_no_rx_time`].
  #[cfg(test)]
  pub(crate) const fn force_no_rx_time_for_test(&mut self) {
    self.forced_no_rx_time = true;
  }

  /// When this family's sends actually reached its wire, in order. Recorded
  /// inside the send path, so it is the wire's own history rather than the
  /// driver's account of it. See [`BoundSocket::wire_times`].
  #[cfg(test)]
  pub(crate) fn wire_times_for_test(&self, family: Family) -> Vec<StdInstant> {
    match family {
      Family::V4 => self.v4.as_ref(),
      Family::V6 => self.v6.as_ref(),
    }
    .map_or_else(Vec::new, |fam| fam.wire_times.clone())
  }

  /// Make this family's next `Registry::deregister` fail. See
  /// [`BoundSocket::forced_deregister_error`].
  #[cfg(test)]
  pub(crate) fn force_deregister_error_for_test(&mut self, family: Family, fail: bool) {
    if let Some(fam) = self.family_mut(family) {
      fam.forced_deregister_error = fail;
    }
  }

  /// Make the IPv6 half of the next [`Sockets::register`] fail. See
  /// [`Sockets::forced_v6_register_error`].
  #[cfg(test)]
  pub(crate) const fn force_v6_register_error_for_test(&mut self, fail: bool) {
    self.forced_v6_register_error = fail;
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
///
/// **The reset happens only once the selector has confirmed the removal.** A
/// family whose `deregister` failed is still registered, and clearing its token
/// would leave that registration with nothing left to recognise its events by
/// and nothing to retry the removal with — a ghost in the caller's selector,
/// under a token `Sockets::owns` has stopped claiming.
fn deregister_family(fam: Option<&mut BoundSocket>, registry: &Registry) -> io::Result<()> {
  let Some(fam) = fam else { return Ok(()) };
  if fam.token.is_none() {
    return Ok(());
  }
  fam.raw_deregister(registry)?;
  fam.token = None;
  fam.interest = Interest::READABLE;
  // Nothing is registered any more, so there is no outstanding re-arm to retry.
  fam.interest_stale = false;
  fam.readable = false;
  Ok(())
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

/// The platform's own oversized-datagram refusal, synthesised for the send hooks
/// on [`BoundSocket`].
///
/// `#[cfg(test)]`, and that is the whole change of status: the classification no
/// longer reads an errno, so this table decides nothing in any shipping build.
/// It exists so an injected refusal *looks* like the real one — the same code a
/// kernel raises for a datagram past the hard limit and, on Linux, for one merely
/// past the current path MTU — which is what lets
/// `an_emsgsize_below_the_hard_limit_is_transient_and_retried` state its subject
/// exactly.
///
/// A target this does not name is not a gap any more: the refusal falls back to a
/// plain error, the size comparison is unchanged by it, and no test is skipped.
/// Stable ABI numbers, not header lookups: this crate takes no `libc` dependency.
#[cfg(test)]
fn emsgsize_for_test() -> io::Error {
  // EMSGSIZE: 90 on Linux/Android, 40 on the BSDs, 97 on Solaris/illumos, and
  // Winsock's WSAEMSGSIZE, which does not share the C errno space.
  #[cfg(any(target_os = "linux", target_os = "android"))]
  const CODE: Option<i32> = Some(90);
  #[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
  ))]
  const CODE: Option<i32> = Some(40);
  #[cfg(any(target_os = "solaris", target_os = "illumos"))]
  const CODE: Option<i32> = Some(97);
  #[cfg(windows)]
  const CODE: Option<i32> = Some(10040);
  #[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
    windows,
  )))]
  const CODE: Option<i32> = None;

  match CODE {
    Some(code) => io::Error::from_raw_os_error(code),
    None => io::Error::other("forced oversized-datagram refusal"),
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

/// Whether `iface` has any address in `family`, or why the platform could not
/// say.
///
/// # A failure is not an absence
///
/// The accessor is a fallible syscall, and answering `false` for an `Err` is the
/// defect this exists to prevent: it makes a family whose enumeration FAILED
/// indistinguishable from one that genuinely has no address. Downstream that is
/// a family silently dropped from a dual-stack bind that then *succeeds*, and —
/// when both fail — an `AddrNotAvailable` that names the wrong cause and sends
/// the caller auditing addresses on an interface nobody managed to read. The
/// same confusion of *failing* with *absent* has cost this crate twice before,
/// so `false` is reserved for `Ok` with nothing in it and everything else
/// propagates.
///
/// # Which is why it is asked one family at a time
///
/// An error only means something to a decision the answer feeds. Asking both
/// families together made every caller carry an error it could not use: an IPv6
/// read that failed aborted an IPv4-only bind, and it aborted a pick whose
/// winner the candidate could no longer outrank. Both callers therefore ask per
/// family, behind the condition that makes the answer matter — see
/// [`Sockets::bind`] and [`rank_candidates`] — so an error propagates exactly
/// when the decision needed the answer.
///
/// The error carries the interface index and the family it could not read, on
/// top of the kind the platform reported, because "permission denied" alone
/// names neither.
fn has_addr_in(iface: &getifs::Interface, family: Family) -> io::Result<bool> {
  let index = iface.index();
  let (label, addrs) = match family {
    Family::V4 => ("IPv4", iface.ipv4_addrs().map(|a| !a.is_empty())),
    Family::V6 => ("IPv6", iface.ipv6_addrs().map(|a| !a.is_empty())),
  };
  // Injected after the accessor rather than in place of it, so a forced failure
  // travels the very path a real one does — the kind carried over, the context
  // below added — instead of a shortcut that would pass while that path rotted.
  #[cfg(test)]
  let addrs = match forced_enumeration_error() {
    Some(forced) if forced == family => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    _ => addrs,
  };
  addrs.map_err(|e| {
    io::Error::new(
      e.kind(),
      format!("reading the {label} addresses of interface {index}: {e}"),
    )
  })
}

#[cfg(test)]
thread_local! {
  /// Force one family's address enumeration to fail inside [`has_addr_in`], for
  /// the current thread.
  ///
  /// A thread-local rather than a `#[cfg(test)]` field, because neither consumer
  /// has a receiver to hang one on: [`Sockets::bind`] is a constructor and
  /// [`pick_default_interface_index`] is a free function, and the failure has to
  /// be visible from inside both. Thread-local rather than global so tests
  /// running in parallel cannot see each other's injection — libtest gives every
  /// `#[test]` its own thread.
  ///
  /// The condition is otherwise unreachable: `getifs` reads addresses straight
  /// from the kernel and no healthy host refuses. It is also exactly the
  /// condition whose mishandling this file has had to fix repeatedly, so it must
  /// not go untested.
  static FORCED_ENUMERATION_ERROR: core::cell::Cell<Option<Family>> =
    const { core::cell::Cell::new(None) };
}

#[cfg(test)]
fn forced_enumeration_error() -> Option<Family> {
  FORCED_ENUMERATION_ERROR.with(core::cell::Cell::get)
}

/// Make `family`'s address enumeration fail on this thread until the returned
/// guard is dropped. See [`FORCED_ENUMERATION_ERROR`].
///
/// A guard rather than a pair of calls, so a failing assertion cannot leave the
/// injection armed for whatever else runs on this thread.
#[cfg(test)]
pub(crate) fn force_enumeration_error_for_test(family: Family) -> ForcedEnumerationError {
  FORCED_ENUMERATION_ERROR.with(|c| c.set(Some(family)));
  ForcedEnumerationError
}

/// Disarms [`FORCED_ENUMERATION_ERROR`] on drop.
#[cfg(test)]
pub(crate) struct ForcedEnumerationError;

#[cfg(test)]
impl Drop for ForcedEnumerationError {
  fn drop(&mut self) {
    FORCED_ENUMERATION_ERROR.with(|c| c.set(None));
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
///
/// # `Ok(None)` is "nothing qualified"; an error is an error
///
/// The three answers are distinct and the return type keeps them so. Enumerating
/// the interfaces can fail, and so can reading one candidate's addresses, and
/// neither is evidence that no interface qualifies — folding either into `None`
/// produced a `NotFound` naming the wrong cause, or, worse, ranked a candidate
/// as having no address in a family nobody managed to read and picked a
/// different NIC. A responder bound to the wrong link looks exactly like a
/// working one until nothing is ever discovered, so the failure is raised where
/// a caller can see it and pin an interface instead.
///
/// # An error is retained only while it could still change the answer
///
/// Propagating one that cannot is not strictness, it is availability spent for
/// nothing. Two conditions decide whether an address read matters at all, and
/// both are applied before every read rather than after it: the family must have
/// been requested, and the best tier the candidate can still reach must still
/// outrank the interface already chosen — see [`rank_candidates`]. That reach
/// narrows as the candidate's own families come back absent, so the second
/// condition is worth re-testing between one candidate's probes and not only
/// between candidates. The flag filter is the same rule one step earlier, and it
/// was already here: a down or non-multicast interface is never probed, so it
/// can never fail the pick.
fn pick_default_interface_index(want_v4: bool, want_v6: bool) -> io::Result<Option<u32>> {
  let ifs = getifs::interfaces()
    .map_err(|e| io::Error::new(e.kind(), format!("enumerating network interfaces: {e}")))?;
  rank_candidates(
    ifs
      .iter()
      .filter_map(|i| Some((tier_base(i)?, i.index(), i))),
    want_v4,
    want_v6,
    |iface, family| has_addr_in(iface, family),
  )
}

/// The best tier `iface`'s FLAGS alone can qualify it for, or `None` when they
/// disqualify it outright.
///
/// Tier 0 is an up, multicast-capable, non-loopback interface and tier 2 is an
/// up loopback one; each tier's odd neighbour above it is the same interface
/// serving only some of the requested families. Reading no address here is what
/// keeps an interface the picker would never choose from costing a syscall — or
/// failing one.
fn tier_base(iface: &getifs::Interface) -> Option<u8> {
  let f = iface.flags();
  if f.contains(getifs::Flags::UP)
    && f.contains(getifs::Flags::MULTICAST)
    && !f.contains(getifs::Flags::LOOPBACK)
    && iface.index() != 0
  {
    Some(0)
  } else if f.contains(getifs::Flags::LOOPBACK) && f.contains(getifs::Flags::UP) {
    Some(2)
  } else {
    None
  }
}

/// Rank already-classified candidates and return the winner's interface index.
///
/// `candidates` yields `(tier_base, index, subject)`, where `subject` is
/// whatever `has_addr` needs to read that candidate's addresses. Split out of
/// [`pick_default_interface_index`] because a `getifs::Interface` cannot be
/// constructed by a test, while everything below — which candidates are probed,
/// which failures propagate, and which one wins — is a property of this walk and
/// not of the host it runs on.
///
/// One pass over four preference tiers, lowest wins, first-seen wins within a
/// tier — the order four separate `find` passes used to produce. Ranked in one
/// walk because each candidate's families cost fallible syscalls that must be
/// asked once and propagated, not re-asked per tier.
fn rank_candidates<S>(
  candidates: impl IntoIterator<Item = (u8, u32, S)>,
  want_v4: bool,
  want_v6: bool,
  mut has_addr: impl FnMut(&S, Family) -> io::Result<bool>,
) -> io::Result<Option<u32>> {
  let mut best: Option<(u8, u32)> = None;
  'candidates: for (tier_base, index, subject) in candidates {
    // The best tier this candidate can still reach, narrowed as its families are
    // read. It starts at the strict tier its flags allow; a requested family it
    // has no address in puts that tier out of reach for good, leaving the loose
    // tier immediately above.
    let mut reachable = tier_base;
    let mut serves_any = false;
    for (family, wanted) in [(Family::V4, want_v4), (Family::V6, want_v6)] {
      // A family is probed only while its answer could still change the winner.
      // Displacing the incumbent takes a strictly lower tier, first-seen-wins
      // within a tier being what makes `>=` the test rather than `>`, so a
      // candidate already out of reach of that cannot alter the pick whatever
      // its remaining addresses turn out to be — and a failure to read them is
      // exactly as uninformative. Re-tested per family rather than once per
      // candidate because the reach narrows mid-candidate: a tier-0 incumbent is
      // unbeatable before the first probe, while a candidate whose first family
      // came back absent has just lost the only tier that beat a tier-1 one.
      //
      // A candidate that COULD still outrank the incumbent is probed, and its
      // failure still propagates. That is the half a fix in this direction gets
      // backwards: reading it as "no address in that family" ranks a candidate
      // on an answer nobody obtained and can bind the wrong link, which looks
      // exactly like a working responder until nothing is ever discovered.
      if best.is_some_and(|(seen, _)| reachable >= seen) {
        continue 'candidates;
      }
      // "Requested AND present": the short circuit is what keeps a family nobody
      // asked for from being read at all, so a `false` there is for want of a
      // question rather than for want of an address, and cannot cost the strict
      // tier below.
      let serves = wanted && has_addr(&subject, family)?;
      serves_any |= serves;
      if wanted && !serves {
        reachable = tier_base + 1;
      }
    }
    // Every requested family has been read, so the tier still within reach is
    // the tier earned — except by a candidate serving none of them, which is no
    // candidate at all rather than one ranked last.
    if !serves_any && reachable > tier_base {
      continue;
    }
    if best.is_none_or(|(seen, _)| reachable < seen) {
      best = Some((reachable, index));
    }
  }
  Ok(best.map(|(_, index)| index))
}

#[cfg(test)]
mod tests;

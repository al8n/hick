//! The runtime-agnostic mDNS engine: a synchronous *pump* that drives the
//! [`mdns_proto::Endpoint`] (plus the per-service / per-query state machines it
//! hands back) over a [`UdpIo`] transport.
//!
//! A driver (e.g. `hick-embassy`, or a bare poll loop) calls [`Engine::pump`]
//! whenever a packet arrives or a timer fires, sends nothing itself, and reads
//! back the next deadline to sleep until.

#[cfg(feature = "stats")]
use alloc::sync::Arc;
use alloc::{
  collections::{BTreeMap, VecDeque},
  vec::Vec,
};
use core::{net::SocketAddr, time::Duration};

use mdns_proto::{
  CollectedAnswer, EndpointConfig, Instant, QueryHandle, QuerySpec, ServiceHandle, ServiceSpec,
  cache::CacheEntry,
  endpoint::{Endpoint, EndpointEventEntry, FamilyDebt, ServiceRoute},
  error::{RegisterServiceError, StartQueryError},
  event::{EndpointEvent, QueryUpdate, RouteEvent, ServiceUpdate},
  query::Query,
  service::Service,
  slab::Slab,
  transmit::{FamilyAttempt, Transmit, TransmitConfirm, TransmitObligation},
};
use rand_core::Rng;
use smoltcp::wire::IpCidr;

use crate::{
  constants::{MDNS_SOCKET_V4, MDNS_SOCKET_V6},
  onlink,
  udpio::{SendError, UdpIo},
};

#[cfg(feature = "stats")]
use hick_trace::stats::{Stats, StatsSnapshot};

#[cfg(test)]
mod tests;

/// RFC 6762 §17 single-message ceiling — the cap applied to every encoded
/// multicast in the normal TX path, so a service announced with a large record
/// set can never advertise records that the endpoint-owned TTL=0 withdrawal
/// (which encodes into the caller's `scratch`, capped to this same ceiling)
/// could not later retract.
const MAX_MDNS_MESSAGE: usize = 9000;
/// Per-service cap on queued app-facing updates, so a peer flooding conflict
/// events cannot drive unbounded allocation on the receive path.
const MAX_SERVICE_UPDATES: usize = 16;
/// Max inbound datagrams processed in ONE pump before yielding. `MAX_SERVICE_UPDATES`
/// caps the app-facing `ServiceSlot::updates` queue, but a service's mdns-proto
/// `pending_updates` pool accumulates DURING the RX drain — before `drain_service_updates`
/// coalesces and caps it — so an on-link conflict flood could otherwise grow it
/// proportional to the whole RX backlog (bounded only by the socket RX buffer, which
/// the caller may size large) in a single pump. Capping the batch bounds that peak to
/// a constant; when the cap is hit the pump asks for an immediate re-pump so a real
/// backlog is still drained promptly.
const MAX_RX_PER_PUMP: usize = 64;
/// Byte budget for buffered self-sends (loopback detection). Bounds memory while
/// preserving the FRESHEST sends, so a burst of many outstanding multicasts in
/// one pump is still covered until their loopbacks arrive — a fixed small count
/// would evict fresh entries mid-burst. Exact bytes are stored.
const RECENT_SEND_BYTES: usize = 16 * 1024;
/// How long a recorded self-send stays eligible to match a loopback — bounds the
/// window in which a byte-identical peer datagram could be misread as self.
const RECENT_SEND_TTL: Duration = Duration::from_secs(5);
/// A recent multicast datagram we handed to the transport, kept (exact bytes +
/// send time) for self-loopback detection.
struct SelfSend<I> {
  data: Vec<u8>,
  at: I,
}

// Slab-backed pools (the `alloc` tier). Mirrors `hick-reactor`'s `ProtoEndpoint`.
type AnswerPool = Slab<CollectedAnswer>;
type UpdatePool = Slab<QueryUpdate>;
type ProtoQuery<I> = Query<I, AnswerPool, UpdatePool>;
type ProtoService<I> = Service<I, Slab<Transmit>, Slab<ServiceUpdate>>;
type ProtoEndpoint<I, R> = Endpoint<
  I,
  R,
  Slab<CacheEntry<I>>,
  Slab<ServiceRoute>,
  Slab<ProtoQuery<I>>,
  Slab<EndpointEventEntry>,
  AnswerPool,
  UpdatePool,
>;

/// Per-service driver-side state: the proto state machine, a queue of
/// app-facing updates, and an `errored` flag that drops a structurally-dead
/// service out of every pump (so it can't busy-spin).
struct ServiceSlot<I: Instant> {
  proto: ProtoService<I>,
  updates: VecDeque<ServiceUpdate>,
  errored: bool,
  /// When each family last ACCEPTED one of THIS service's gated datagrams, so
  /// the RFC 6762 §8.1 / §8.3 spacing is honoured per family. See
  /// [`FamilyWireGate`], which is also where what that acceptance does and does
  /// not prove about the wire is written down.
  wire_gate: FamilyWireGate<I>,
  /// Set when the endpoint-owned withdrawal for this service has COMPLETED (its
  /// route is already freed) but the slot is RETAINED because it still holds
  /// un-polled app-facing updates — typically the `Conflict` queued at an internal
  /// retirement. Such a slot is GC'd lazily: by [`Engine::pump`] (or
  /// [`Engine::poll_service_update`]) once its `updates` queue drains. This keeps
  /// the `Conflict` deliverable even when the withdrawal completes in the SAME pump
  /// that began it (an empty, never-announced withdrawal completes immediately).
  route_freed: bool,
  /// Set when the CALLER explicitly retired this service via
  /// [`Engine::unregister_service`] and may discard the handle WITHOUT polling its
  /// updates. Unlike an internal retirement, no reader is guaranteed, so the
  /// completed-withdrawal GC removes the slot regardless of pending updates —
  /// `route_freed` deferral would otherwise pin it forever and grow `services`
  /// without bound under register/unregister churn.
  caller_gone: bool,
}

impl<I: Instant> ServiceSlot<I> {
  /// Queue an app-facing update with allocation discipline. Conflict
  /// notifications are peer-floodable and idempotent, so keep at most one of each
  /// variant; the backstop cap then evicts conflict noise BEFORE any actionable
  /// transition (`Established` / `Renamed`), which the application must not miss.
  /// Prevents a hostile on-link peer from forcing unbounded growth or evicting
  /// real lifecycle state on the RX path.
  fn push_update(&mut self, update: ServiceUpdate) {
    if matches!(
      update,
      ServiceUpdate::Conflict | ServiceUpdate::HostConflict
    ) {
      let kind = core::mem::discriminant(&update);
      if self
        .updates
        .iter()
        .any(|u| core::mem::discriminant(u) == kind)
      {
        return;
      }
    }
    if self.updates.len() >= MAX_SERVICE_UPDATES {
      let victim = self
        .updates
        .iter()
        .position(|u| matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict));
      match victim {
        Some(pos) => {
          self.updates.remove(pos);
        }
        None => {
          self.updates.pop_front();
        }
      }
    }
    self.updates.push_back(update);
  }
}

/// Per-query driver-side state. Answers are applied inside `Endpoint::handle`;
/// this only tracks the `errored` flag — a query the driver retired (its question
/// is un-encodable, or permanently unsendable on every family) which every pump
/// skips. A retired query is ALSO forced to its proto-level TIMEOUT terminal (see
/// [`Engine::retire_query`]), so its terminal update and frozen answers come from
/// the proto, not a synthetic driver-side signal.
struct QuerySlot<I> {
  errored: bool,
  /// When each family last ACCEPTED one of THIS question's transmissions, so
  /// RFC 6762 §5.2's one-second floor is honoured per family. See
  /// [`FamilyWireGate`].
  wire_gate: FamilyWireGate<I>,
}

/// One PRODUCER's per-family earliest-next-send gate: when each address family
/// ([0] = v4, [1] = v6) last carried a datagram from this service or query.
///
/// The rule it enforces is RFC 6762's — §6 and §8.3 forbid re-multicasting a
/// record on an interface inside one second of the last time it went out on that
/// same interface, and §8.1 spaces probes 250 ms apart — but what this gate
/// MEASURES on this transport is the ENQUEUE and never the wire: every instant it
/// holds is a [`UdpIo::try_send`] acceptance, and the section below is what that
/// costs. The
/// MINIMUM is protocol policy and arrives from the core on
/// [`Transmit::min_family_gap`]; only the driver knows when each family last
/// satisfied it, which is why the two halves live on opposite sides of the seam.
///
/// The instants here are read immediately after the [`UdpIo::try_send`] that
/// ACCEPTED the datagram — never the pass instant [`Engine::pump`] opened with.
/// A pump reaches a send having already spent time (an RX drain of up to
/// [`MAX_RX_PER_PUMP`] datagrams, every earlier producer in the same transmit
/// loop), and a gate stamped from before that spending counts it as interval
/// already elapsed. The core's re-arm off the confirm anchor discounts the same
/// spending independently, so one stale reading shortens the gap twice over —
/// see [`Self::record`].
///
/// It is enforced identically to the readiness/completion drivers, because the
/// rule is about the transmission rather than about how a particular driver
/// reaches it: a fan-out that ever defers one family — [`family_order`] already
/// exists to hand a one-slot transport to the longest-blocked family — would
/// otherwise take that family's spacing with it.
///
/// # What this gate measures: the ENQUEUE, not the wire
///
/// A [`UdpIo::try_send`] that returns `Ok` has QUEUED the datagram, not put it on
/// the wire. The concrete smoltcp transport calls `udp::Socket::send_slice` and
/// the device dispatch happens afterwards, inside the caller's `Interface::poll`;
/// embassy-net has the same queued socket model behind its own network task. So
/// every instant recorded here is an enqueue acceptance, and the floor this gate
/// enforces is measured from the enqueue.
///
/// The two differ by however long the interface poll (or the embassy network
/// task) takes to run, which nothing on this seam bounds. Should that runner
/// stall for at least the floor, a later pump finds the gate open and queues a
/// second datagram, and one poll can then drain both back-to-back — two copies of
/// the same records reaching the device inside the interval RFC 6762 §6 / §8.3
/// gives one interface. The readiness and completion drivers have no such gap:
/// their `sendto` returning `Ok` means the kernel already owns the datagram.
///
/// Closing it needs a per-family egress ACKNOWLEDGEMENT — the transport telling
/// the engine when a queued datagram actually left — which is an addition to the
/// public [`UdpIo`] trait that every bare-smoltcp implementor would have to
/// satisfy, so it is deliberately not attempted here. Until then this gate bounds
/// spacing at the enqueue, which is the strongest thing this transport can
/// currently prove, and nothing in this engine claims more than that. Poll the
/// interface promptly and the two coincide.
///
/// Kept PER PRODUCER because the rules are per record set: two different services
/// announcing inside the same second are two different records and pace each
/// other not at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FamilyWireGate<I> {
  /// Indexed [v4, v6]. `None` until that family has carried a GATED datagram from
  /// this producer — an ungated (one-shot) send never writes here, so a §6 reply
  /// cannot defer the announcement that follows it.
  last_sent: [Option<I>; 2],
}

impl<I: Instant> FamilyWireGate<I> {
  fn new() -> Self {
    Self {
      last_sent: [None, None],
    }
  }

  /// Whether family `idx` may be offered a datagram at `now` under `min_gap`.
  ///
  /// `now` is read at the OFFER, immediately before this family's send attempt,
  /// so the gap weighed is the one this family has actually had by then. An older
  /// reading is not harmless conservatism: it withholds a family whose gap has
  /// genuinely elapsed, and [`FamilySend::Gated`] reaches the core as a miss that
  /// spends its partial-round patience and holds the RFC 6762 §8 phase back.
  ///
  /// A zero `min_gap` is ungated and always open. A family that has carried
  /// nothing yet is open. A clock that reads BEFORE the recorded send closes the
  /// gate: the elapsed gap is then unknown, and the conservative answer is the
  /// one that cannot re-offer a record too soon.
  fn open(&self, idx: usize, now: I, min_gap: Duration) -> bool {
    if min_gap.is_zero() {
      return true;
    }
    match self.last_sent.get(idx).copied().flatten() {
      Some(last) => now
        .checked_duration_since(last)
        .is_some_and(|gap| gap >= min_gap),
      None => true,
    }
  }

  /// Record that family `idx` accepted a GATED datagram for egress at `at`.
  ///
  /// `at` must be read AFTER the call that accepted the datagram, and it is the
  /// one instant in this driver that must be: the value is a measurement of when
  /// this family's transmit queue last took a datagram, and nothing bounds the
  /// delay between a clock read and the send it precedes. A stamp taken on the
  /// near side of that delay hands the whole of it back to the next datagram's
  /// spacing — and the core's own re-arm, anchored at the PRE-send acceptance,
  /// has already discounted it once, so the two errors compound into a gap the
  /// elapsed time is subtracted from twice. What that measurement does and does
  /// not prove about the wire is on the type: this transport queues.
  ///
  /// The confirm anchor is the pre-send instant and correctly so
  /// ([`FamilyAttempt::Accepted`]); the two are wrong in opposite directions and
  /// are not interchangeable.
  fn record(&mut self, idx: usize, at: I, min_gap: Duration) {
    if min_gap.is_zero() {
      return;
    }
    if let Some(slot) = self.last_sent.get_mut(idx) {
      *slot = Some(at);
    }
  }
}

/// The outcome of a single per-family send attempt in a multicast fan-out or
/// goodbye burst, carrying exactly what happened to that one family's socket call.
///
/// `Sent`     — the datagram was queued for egress, at this family's own instant.
/// `Failed`   — a real I/O error (e.g. TooLarge in the normal TX path).
/// `Unsupported` — no socket for this family; not an error.
/// `Busy`     — the socket is transiently full; will be retried.
///
/// Separating these four cases lets accounting sites be exact: `packets_tx` /
/// `bytes_tx` increment only for `Sent`, `send_errors` only for `Failed`.
#[derive(Debug, Clone, Copy)]
enum FamilySend<I> {
  /// Datagram accepted by this family's transport, which on this transport means
  /// queued for egress rather than put on the wire (see [`FamilyWireGate`]).
  Sent {
    /// Payload byte count, for `bytes_tx`.
    bytes: usize,
    /// This family's OWN acceptance instant, read immediately BEFORE the call
    /// that took the datagram — what [`FamilyAttempt::Accepted`] anchors on. Not
    /// the instant [`FamilyWireGate::record`] wants, which is read after that
    /// same call.
    at: I,
  },
  /// A present socket was NOT offered the datagram because the producer's
  /// previous one is still inside [`Transmit::min_family_gap`] on THIS family's
  /// egress path (see [`FamilyWireGate`]). Obligated and did not carry it, like
  /// `Busy` — but a deliberate deferral rather than a full transmit queue, so it
  /// is neither an error nor a retry candidate.
  Gated,
  /// Real I/O failure — the socket exists but permanently rejected the datagram.
  Failed,
  /// No socket for this family; not an error, not a retry candidate.
  Unsupported,
  /// Socket transiently full; will be retried.
  Busy,
  /// A present socket was NOT offered an RFC 6762 §10.1 goodbye because the
  /// core's [`FamilyDebt`] says this family has already paid every round it owed.
  /// Withdrawal-only ([`Tx::burst`]): the positive-TTL path has no per-family
  /// debt, so nothing there can produce it.
  ///
  /// Distinct from every other variant because each of the others is a claim
  /// about the transport. This one is a claim about the item: the socket is
  /// healthy and would have carried the datagram, there was simply nothing left
  /// for it to retract.
  NotOwed,
}

impl<I: Copy> FamilySend<I> {
  /// Whether the datagram actually reached this family's socket.
  fn is_sent(self) -> bool {
    matches!(self, FamilySend::Sent { .. })
  }

  /// This family's acceptance instant, if it accepted.
  fn accepted_at(self) -> Option<I> {
    match self {
      FamilySend::Sent { at, .. } => Some(at),
      _ => None,
    }
  }

  /// Restate this family's outcome in the core's I/O-world vocabulary — the ONE
  /// mapping this driver makes, used by the positive-TTL fan-out and the RFC 6762
  /// §10.1 goodbye burst alike. What a socket did means the same thing whatever
  /// the datagram was for; what it MEANS for a lifecycle phase or for a goodbye
  /// debt is the core's, and this driver no longer keeps a second table for the
  /// second question.
  ///
  /// That second table is where this driver disagreed with the socket drivers: a
  /// permanently-too-large goodbye used to WRITE ITS DEBT OFF here, freeing the
  /// route while a bound family's peers stayed pinned to stale positive-TTL
  /// records. It is a refusal like any other now, and only an absent socket
  /// writes a debt off.
  ///
  /// `permanent` comes from `smoltcp`'s own `SendError::TooLarge`, which this
  /// transport raises against the SOCKET BUFFER rather than a wire-format
  /// ceiling. That is a driver-local fact the core cannot compute — it is exactly
  /// why the bit crosses the boundary rather than the datagram's size.
  ///
  /// `NotOwed` is not an I/O fact at all: no send was made, and the only thing
  /// that happened is this driver honouring the core's own [`FamilyDebt`]. It is
  /// reported as the deferral it is, and the core discards any report for a
  /// family whose debt was already zero, so it cannot cost a debt either way.
  ///
  /// An acceptance carries the instant the sending family stamped it with, so
  /// this restatement supplies none: the anchor a fan-out reaches the core with
  /// is a per-family measurement, and there is no fan-out-wide instant that could
  /// stand in for one.
  const fn attempt(self) -> FamilyAttempt<I> {
    match self {
      FamilySend::Sent { at, .. } => FamilyAttempt::Accepted { at },
      FamilySend::Busy => FamilyAttempt::Refused { permanent: false },
      FamilySend::Failed => FamilyAttempt::Refused { permanent: true },
      FamilySend::Gated | FamilySend::NotOwed => FamilyAttempt::GateShut,
      FamilySend::Unsupported => FamilyAttempt::NoSocket,
    }
  }
}

/// The per-family results of a multicast fan-out: one [`FamilySend`] for v4
/// and one for v6. Carry this from `send_multicast`/`burst` to the accounting
/// site so counters are bumped from explicit per-family outcomes rather than
/// from a coarse aggregate.
#[derive(Debug, Clone, Copy)]
struct Fanout<I> {
  v4: FamilySend<I>,
  v6: FamilySend<I>,
}

impl<I: Copy> Fanout<I> {
  /// Returns `true` if at least one family sent the datagram successfully.
  ///
  /// Observability only now that the self-send credit takes the earliest
  /// ACCEPTANCE INSTANT rather than a bare "something went out" bit; a build with
  /// neither counter nor trace has nothing left to ask it.
  #[cfg_attr(not(any(feature = "stats", feature = "defmt")), allow(dead_code))]
  fn any_sent(self) -> bool {
    self.v4.is_sent() || self.v6.is_sent()
  }

  /// Total number of per-family sends whose transport actually took the datagram
  /// (0, 1, or 2). Used for `packets_tx`.
  #[cfg_attr(not(feature = "stats"), allow(dead_code))]
  fn sent_count(self) -> u32 {
    u32::from(self.v4.is_sent()) + u32::from(self.v6.is_sent())
  }

  /// Total bytes accepted for egress (sum across sending families). Used for
  /// `bytes_tx`; the byte count is per-family because both families encode the
  /// same datagram, so a dual-stack send doubles the bytes queued.
  #[cfg_attr(not(feature = "stats"), allow(dead_code))]
  fn bytes_accepted(self) -> u64 {
    let mut n = 0u64;
    if let FamilySend::Sent { bytes, .. } = self.v4 {
      n += bytes as u64;
    }
    if let FamilySend::Sent { bytes, .. } = self.v6 {
      n += bytes as u64;
    }
    n
  }

  /// Count of families that returned a real I/O failure (`Failed`). Does NOT
  /// count `Unsupported` (absent socket) or `Busy` (transient). Used for
  /// `send_errors`, and for nothing else now that whether such a round is worth
  /// re-arming is the core's question rather than this driver's.
  #[cfg_attr(not(feature = "stats"), allow(dead_code))]
  fn failed_count(self) -> u32 {
    u32::from(matches!(self.v4, FamilySend::Failed))
      + u32::from(matches!(self.v6, FamilySend::Failed))
  }

  /// Hand the per-family fan-out to the core VERBATIM, one [`FamilyAttempt`] per
  /// family — the honest, unexcused I/O facts.
  ///
  /// Nothing is projected onto an aggregate here, and this driver is where that
  /// matters most: [`family_order`] hands the one free slot of a constrained
  /// transport to the longest-blocked family, so under capacity one the families
  /// ALTERNATE and every round is partial. An aggregate confirm cannot tell that
  /// apart from one chronically dead family, and the core would refresh each
  /// family at twice the periodic interval — past the TTL — while every per-round
  /// invariant still held.
  ///
  /// A family that keeps missing is never written off here, and this driver has
  /// no other place that could: the confirm is the honest I/O facts and nothing
  /// more. Bounding how long the lifecycle waits for it is the core's own
  /// patience, and deciding whether a permanently-refused datagram is worth
  /// re-arming at all is the core's too — both applied inside the confirm.
  ///
  /// Every acceptance carries the instant its OWN family stamped it with, read
  /// immediately before that family's send call, and the core folds the earliest
  /// across the pair. Handing over one fan-out-wide instant is what let a stale
  /// reading anchor a family that accepted much later.
  const fn into_attempts(self) -> (FamilyAttempt<I>, FamilyAttempt<I>) {
    (self.v4.attempt(), self.v6.attempt())
  }
}

/// Which state machine produced an outgoing datagram, so the matching
/// `note_*_transmit_result` advances the right lifecycle after the send.
#[derive(Debug, Clone, Copy)]
enum Origin {
  Service(ServiceHandle),
  Query(QueryHandle),
}

/// Order the two families for a fan-out so the one that has been waiting LONGEST
/// (the oldest failing streak) is tried FIRST. A non-blocking transport with room
/// for only one datagram per poll cycle would otherwise always fill the family in
/// fixed position 0 (v4) and perpetually starve the other: v4 wins the lone
/// slot on every probe/announce while v6 reports busy, so the proto reaches
/// `Established` with v6 having seen nothing. Handing the next free slot to the
/// longest-blocked family makes both groups advance in turn. With ample capacity
/// both sends succeed regardless of order, so this is a no-op in the common case.
///
/// This is the driver half of [`TransmitDelivery`]'s normative fair-service
/// obligation: offer every obligated family on every round, and under a
/// constrained slot prefer the longest-blocked one. The core says WHEN the
/// stalest family is due; without the rotation it would say so about a family
/// this driver never gets around to serving.
fn family_order<I: Instant>(failing_since: &[Option<I>; 2]) -> [(usize, SocketAddr); 2] {
  let v4 = (0usize, MDNS_SOCKET_V4);
  let v6 = (1usize, MDNS_SOCKET_V6);
  let v6_first = match (failing_since[0], failing_since[1]) {
    // Both behind: serve whichever started failing earlier (has waited longer).
    (Some(v4_since), Some(v6_since)) => v6_since < v4_since,
    // Only v6 is behind → give it the first slot.
    (None, Some(_)) => true,
    // v4 behind, or neither → keep the default v4-first order.
    _ => false,
  };
  if v6_first { [v6, v4] } else { [v4, v6] }
}

/// Record a sent datagram (exact bytes + time) for self-loopback detection,
/// pruning expired entries then evicting oldest to fit the byte budget —
/// preserving the freshest sends so a large simultaneous burst stays covered
/// until its loopbacks arrive.
fn record_into<I: Instant>(
  recent: &mut VecDeque<SelfSend<I>>,
  recent_bytes: &mut usize,
  data: &[u8],
  now: I,
) {
  while let Some(front) = recent.front() {
    if now
      .checked_duration_since(front.at)
      .is_some_and(|age| age > RECENT_SEND_TTL)
    {
      if let Some(old) = recent.pop_front() {
        *recent_bytes -= old.data.len();
      }
    } else {
      break;
    }
  }
  while !recent.is_empty() && recent_bytes.saturating_add(data.len()) > RECENT_SEND_BYTES {
    if let Some(old) = recent.pop_front() {
      *recent_bytes -= old.data.len();
    }
  }
  *recent_bytes = recent_bytes.saturating_add(data.len());
  recent.push_back(SelfSend {
    data: data.to_vec(),
    at: now,
  });
}

/// The multicast transmit path: a SYNCHRONOUS per-family fan-out that honors the
/// proto's confirm-on-send contract (each transmit is confirmed within the same
/// pump). Tracks each family's failing streak for fair fan-out ordering (so a
/// constrained transport does not starve one family) and owns the self-loopback
/// fingerprint store.
struct Multicaster<I> {
  /// When each family ([0] = v4, [1] = v6) started its current failing streak, so
  /// [`family_order`] serves the longest-waiting family first. `None` when the
  /// family last succeeded.
  failing_since: [Option<I>; 2],
  /// Recent sent datagrams (exact bytes + time), for self-loopback detection.
  recent: VecDeque<SelfSend<I>>,
  /// Total bytes buffered in `recent` (for the byte budget).
  recent_bytes: usize,
}

impl<I: Instant> Multicaster<I> {
  fn new() -> Self {
    Self {
      failing_since: [None; 2],
      recent: VecDeque::new(),
      recent_bytes: 0,
    }
  }

  /// Fan a multicast datagram out to BOTH mDNS groups and report per-family
  /// outcomes exactly. Returns a [`Fanout`] describing what happened to each
  /// family's socket call; the caller derives both the [`MulticastOutcome`] for
  /// the proto confirm-on-send contract and the per-family stats from it.
  ///
  /// **Confirm-on-send contract** (the proto's own): the pump reports the
  /// per-family [`FamilyAttempt`]s this fan-out actually produced, and the CORE
  /// decides what they mean. The two questions it asks have different answers
  /// under partial delivery, which is why the per-family shape must survive to
  /// the confirm rather than being folded to one bit here:
  ///
  /// * goodbye ownership latches on `any_delivered` — if v4 queued the datagram,
  ///   v4 peers may now cache those records, and a later unregister/conflict owes
  ///   them a §10.1 withdrawal whether or not v6 also heard it;
  /// * the §8.1 / §8.3 phase advances only on `all_delivered` — a family that
  ///   never saw the probe has not been asked, and one that never saw the
  ///   announcement has not been told.
  ///
  /// The family that missed this round is tried FIRST on the next fan-out
  /// ([`family_order`]), so even a one-datagram-per-cycle transport reaches both
  /// groups instead of starving one, and the core's re-arm is lossless (same
  /// probe index, same announcement count). A family that keeps missing is
  /// eventually excused by the core's own patience bound, so a chronically
  /// half-broken link cannot pin the lifecycle.
  ///
  /// The endpoint-owned withdrawal send uses [`Self::burst`] instead — the
  /// endpoint owns that retry schedule, so the driver just fans one due goodbye
  /// datagram to both families per round and reports `any_sent` back.
  ///
  /// Records a self-send credit for every family that sent. Uses `data.len()` as
  /// the byte count for both families (they encode the same datagram).
  ///
  /// # Three readings, three different questions
  ///
  /// `clock` is the caller's live clock rather than an instant, because no single
  /// instant answers all three questions this fan-out asks, and the pass instant
  /// [`Engine::pump`] opened with answers none of them:
  ///
  /// * **before each attempt** — whether that family has had its gap
  ///   ([`FamilyWireGate::open`]), and the instant its acceptance anchors on;
  /// * **after each successful attempt** — when that family's transport took the
  ///   datagram ([`FamilyWireGate::record`]), which on this transport is the
  ///   enqueue and not the wire;
  /// * **after the fan-out**, at the caller — the anchor a round no family
  ///   accepted is re-armed from.
  ///
  /// The first two are wrong in opposite directions if collapsed to one reading,
  /// and all three are wrong together if taken at pump entry: a pass may drain
  /// [`MAX_RX_PER_PUMP`] datagrams and serve every earlier producer before
  /// reaching this send, and nothing in a non-blocking `try_send` bounds that.
  fn send_multicast<T: UdpIo, C: FnMut() -> I>(
    &mut self,
    io: &mut T,
    data: &[u8],
    clock: &mut C,
    gate: &mut FamilyWireGate<I>,
    min_gap: Duration,
  ) -> Fanout<I> {
    let mut results = [FamilySend::Unsupported; 2];
    let mut earliest_accepted: Option<I> = None;
    for (idx, group) in family_order(&self.failing_since) {
      // Read at this family's offer, and used for both halves of the pre-send
      // question: whether it has had its gap, and — should the socket take the
      // datagram — what its acceptance anchors on.
      let offered_at = clock();
      // The producer's own per-family spacing, checked BEFORE the socket call so
      // a deferred family makes no send and reports the deferral honestly.
      if !gate.open(idx, offered_at, min_gap) {
        results[idx] = FamilySend::Gated;
        continue;
      }
      let outcome = match io.try_send(data, group) {
        Ok(()) => {
          self.failing_since[idx] = None;
          // Re-read: this stamp measures when the transmit queue took the
          // datagram, so it belongs on the far side of the call that queued it.
          gate.record(idx, clock(), min_gap);
          FamilySend::Sent {
            bytes: data.len(),
            at: offered_at,
          }
        }
        // Busy is TRANSIENT — a momentarily-full TX queue, or an embassy
        // NoRoute/SocketNotBound that can clear. Track the failing streak for
        // fair fan-out ordering.
        Err(SendError::Busy) => {
          self.failing_since[idx].get_or_insert(offered_at);
          FamilySend::Busy
        }
        // No socket for this family — absent, but the other family may carry it.
        Err(SendError::Unsupported) => FamilySend::Unsupported,
        // Permanently larger than this socket buffer — retrying cannot help.
        // Map TooLarge to Failed so the caller can count it as a send error and
        // test permanent undeliverability.
        Err(SendError::TooLarge) => FamilySend::Failed,
      };
      if let Some(at) = outcome.accepted_at() {
        earliest_accepted = Some(earliest_accepted.map_or(at, |first| first.min(at)));
      }
      results[idx] = outcome;
    }
    // The self-send credit is stamped at the EARLIEST family's pre-send
    // instant: one fingerprint covers both families' loopbacks, and a stamp that
    // outran a copy already echoed back would leave it unmatched and read as a
    // conflicting peer.
    if let Some(at) = earliest_accepted {
      self.record(data, at);
    }
    Fanout {
      v4: results[0],
      v6: results[1],
    }
  }

  /// Fan ONE endpoint-owned withdrawal (TTL=0 goodbye) datagram out to every
  /// family `debt` says still owes a goodbye for this item, in priority order
  /// ([`family_order`], so a one-slot transport stays fair).
  ///
  /// `debt` comes from the core on the round itself
  /// ([`mdns_proto::endpoint::WithdrawalTransmit::debt`]) and is the whole of the
  /// admission decision. It is not a schedule: the multi-round resend schedule is
  /// owned by [`Endpoint::note_withdrawal_result`], and this method holds no state
  /// about it. An item stays selectable while EITHER family owes, so a family that
  /// has paid every round it owed would otherwise be handed each round the other
  /// family's retries produce — a retraction of records no peer on that family
  /// still holds, at whatever cadence the other family's failures set.
  ///
  /// A family with NO socket (`Unsupported`) has its debt written off by the
  /// core; every other outcome — a busy socket, and now a permanently-too-large
  /// datagram alike — KEEPS its debt and is re-armed, with the item's own anti-pin
  /// ceiling as the backstop. Maintains `failing_since` so the prioritisation
  /// favours whichever family is behind. Not fingerprinted (a goodbye loopback is
  /// harmless — it withdraws records already being withdrawn).
  ///
  /// Returns a [`Fanout`] with the per-family outcome so the caller can derive
  /// EXACT stats: `packets_tx`/`bytes_tx` for `Sent`, `send_errors` for `Failed`,
  /// and nothing for `Unsupported`/`Busy`/`NotOwed`. The same outcome is restated
  /// as a [`FamilyAttempt`] pair for [`Endpoint::note_withdrawal_result`].
  ///
  /// `now` is the pass instant, and stamps every acceptance. It precedes every
  /// send this round makes, which is the required direction for an anchor —
  /// unlike the normal fan-out there is no gate here (a goodbye burst is
  /// deliberately ungated), so nothing in this path reads an instant back as an
  /// egress measurement and the §10.1 resend schedule is re-armed from the
  /// caller's own post-burst reading instead.
  fn burst<T: UdpIo>(&mut self, io: &mut T, data: &[u8], debt: FamilyDebt, now: I) -> Fanout<I> {
    let owed = [debt.v4_owed(), debt.v6_owed()];
    let mut results = [FamilySend::NotOwed; 2];
    for (idx, group) in family_order(&self.failing_since) {
      if !owed.get(idx).copied().unwrap_or(false) {
        // This family has already retracted everything the item withdraws — no
        // send, no packet, no send_errors, and reported as a deferral so the
        // core's (already-zero) debt is left exactly as it is.
        continue;
      }
      let outcome = match io.try_send(data, group) {
        Ok(()) => {
          self.failing_since[idx] = None;
          FamilySend::Sent {
            bytes: data.len(),
            at: now,
          }
        }
        // No socket for this family: write it off (no withdrawal possible, no
        // error — there's simply no socket to fail). Do NOT count as send_errors.
        Err(SendError::Unsupported) => FamilySend::Unsupported,
        // Permanently too large for this socket's buffer: write it off and
        // count as a real send error (the socket exists but rejects the datagram).
        // (A queued goodbye is a subset of records already announced within the
        // §17 ceiling, so TooLarge here is defensive, but still a real failure.)
        Err(SendError::TooLarge) => FamilySend::Failed,
        // Busy (transiently or persistently): keep the debt and retry next round.
        Err(SendError::Busy) => {
          self.failing_since[idx].get_or_insert(now);
          FamilySend::Busy
        }
      };
      results[idx] = outcome;
    }
    Fanout {
      v4: results[0],
      v6: results[1],
    }
  }

  /// Whether `data` exactly matches a recent self-send within the recency window
  /// — no hash collisions, bounded false-positive window. A byte-identical peer
  /// could match, but suppressing it is harmless: a duplicate query is re-asked
  /// anyway (§7.3), and our unique probe/announce records would only match an
  /// impersonator.
  fn is_self(&self, data: &[u8], now: I) -> bool {
    self.recent.iter().any(|s| {
      s.data.as_slice() == data
        && now
          .checked_duration_since(s.at)
          .is_some_and(|age| age <= RECENT_SEND_TTL)
    })
  }

  /// Record a sent datagram for self-loopback detection (see [`record_into`]).
  fn record(&mut self, data: &[u8], now: I) {
    record_into(&mut self.recent, &mut self.recent_bytes, data, now);
  }
}

/// The runtime-agnostic mDNS engine.
///
/// Generic over the monotonic clock `I` (an [`mdns_proto::Instant`]) and the
/// RNG `R`; the storage pools are fixed to the `alloc`-tier slab backing.
pub struct Engine<I: Instant, R> {
  endpoint: ProtoEndpoint<I, R>,
  services: BTreeMap<ServiceHandle, ServiceSlot<I>>,
  queries: BTreeMap<QueryHandle, QuerySlot<I>>,
  subnets: Vec<IpCidr>,
  /// Reusable scratch for the handles of endpoint-owned withdrawals that
  /// completed in a pump (so [`Endpoint::drain_completed_withdrawals`] can push
  /// into it and the pump can GC each one's driver slot). Kept on the engine and
  /// `clear()`ed each pump so the per-pump GC allocates nothing in steady state.
  completed_withdrawals: Vec<ServiceHandle>,
  /// Reusable scratch for the service/query handle snapshots taken by the
  /// transmit pump (`poll_one_transmit`) and `drain_service_updates`: those loops
  /// early-`return` and call `&mut self` withdrawal methods mid-iteration, so they
  /// can't hold a map borrow across the body — they reuse these buffers instead of
  /// allocating a fresh `Vec` per pump call. `clear()`ed at the start of each use.
  svc_handle_scratch: Vec<ServiceHandle>,
  query_handle_scratch: Vec<QueryHandle>,
  /// The multicast transmit path: per-family fan-out, fan-out ordering, and
  /// self-loopback detection.
  tx: Multicaster<I>,
  /// Shared I/O counters. Constructed once in [`Engine::new`] and handed out via
  /// [`Engine::stats_handle`] so callers (e.g. an embassy task, a metrics poller)
  /// can read the same counters without borrowing the engine.
  #[cfg(feature = "stats")]
  stats: Arc<Stats>,
}

impl<I, R> Engine<I, R>
where
  I: Instant,
  R: Rng,
{
  /// Create an engine from a proto-layer config and an RNG (used for probe
  /// tiebreak seeds and query transaction ids).
  pub fn new(config: EndpointConfig, rng: R) -> Self {
    let endpoint = ProtoEndpoint::try_new(config, rng);
    // Unify the engine's I/O stats with the proto endpoint's stats Arc so that
    // engine.stats() / engine.stats_handle() returns a snapshot that includes
    // both transport-level (packets_tx, send_errors, …) and protocol-level
    // (packets_rx, answers_rx, …) counters.
    #[cfg(feature = "stats")]
    let stats = endpoint.stats_handle();
    Self {
      endpoint,
      services: BTreeMap::new(),
      queries: BTreeMap::new(),
      subnets: Vec::new(),
      completed_withdrawals: Vec::new(),
      svc_handle_scratch: Vec::new(),
      query_handle_scratch: Vec::new(),
      tx: Multicaster::new(),
      #[cfg(feature = "stats")]
      stats,
    }
  }

  /// Return a cloned handle to the unified stats Arc for this engine.
  ///
  /// The returned `Arc` is shared with the proto endpoint, so it captures both
  /// transport-level (packets_tx, send_errors, …) and protocol-level
  /// (packets_rx, answers_rx, …) counters in one consistent snapshot.
  #[cfg(feature = "stats")]
  #[cfg_attr(docsrs, doc(cfg(feature = "stats")))]
  pub fn stats_handle(&self) -> Arc<Stats> {
    self.stats.clone()
  }

  /// Take a consistent point-in-time snapshot of every counter and gauge.
  #[cfg(feature = "stats")]
  #[cfg_attr(docsrs, doc(cfg(feature = "stats")))]
  pub fn stats(&self) -> StatsSnapshot {
    self.stats.snapshot()
  }

  /// Set the device's local subnets — consulted by the RFC 6762 §11 on-link gate
  /// when the transport cannot surface the received hop-limit (neither supplied
  /// transport can; smoltcp's `UdpMetadata` carries no RX TTL). The gate falls
  /// through in order: a present hop-limit is decisive; otherwise a datagram
  /// addressed to the mDNS group is admitted outright (arrival at the group is
  /// its own §11 admission ground; a peer outside your configured subnets is
  /// still on your link if its multicast reached you); otherwise, for a
  /// non-group destination, subnet membership decides; otherwise reject.
  ///
  /// OPTIONAL. With no subnets AND no received hop limit — true of both
  /// supplied transports, whose underlying `UdpMetadata` never carries an RX
  /// TTL — the group and reject steps above still apply: a default node admits
  /// group-destined mDNS and is not deaf, but not unicast. A caller supplying
  /// its own [`UdpIo`] whose transport DOES report a hop limit can have a
  /// conforming (255) unicast datagram admitted regardless of subnets, since
  /// the hop-limit step above is decisive first. Configure local subnets to
  /// admit on-subnet unicast when the hop limit is not reported.
  pub fn set_local_subnets(&mut self, subnets: Vec<IpCidr>) {
    self.subnets = subnets;
  }

  /// Register a service. The proto state machine is owned by the engine and
  /// driven by [`Self::pump`]; updates are read via [`Self::poll_service_update`].
  pub fn register_service(
    &mut self,
    spec: ServiceSpec,
    now: I,
  ) -> Result<ServiceHandle, RegisterServiceError> {
    let (handle, proto) = self
      .endpoint
      .try_register_service::<Slab<Transmit>, Slab<ServiceUpdate>>(spec, now)?;
    self.services.insert(
      handle,
      ServiceSlot {
        proto,
        updates: VecDeque::new(),
        errored: false,
        route_freed: false,
        caller_gone: false,
        wire_gate: FamilyWireGate::new(),
      },
    );
    Ok(handle)
  }

  /// Unregister a service, beginning its RFC 6762 §10.1 endpoint-owned
  /// withdrawal. The endpoint KEEPS the route (holding the name against a
  /// same-name re-registration) and drives the TTL=0 goodbye resend schedule;
  /// [`Self::pump`] pumps each due goodbye datagram and, on completion, frees the
  /// route and GCs the driver slot.
  ///
  /// The withdrawal covers whatever the service must retract: the records it
  /// confirmed-emitted under its current name (host A/AAAA filtered against
  /// same-host siblings by the endpoint), AND — if a conflict rename left an
  /// old-name withdrawal still pending — that old instance name too, in the SAME
  /// goodbye ([`Service::withdrawal_snapshot`] captures both). A never-announced
  /// service has an empty snapshot and completes on the next pump with no
  /// datagram queued.
  ///
  /// The driver slot is NOT removed here: it is kept (marked `errored`) so any
  /// already-queued `ServiceUpdate::Conflict` still reaches the host, and is GC'd
  /// when the endpoint reports the withdrawal complete.
  pub fn unregister_service(&mut self, handle: ServiceHandle, now: I) {
    // An already-`route_freed` slot (an internal retirement whose withdrawal
    // completed, retained only for an un-polled update) has its route freed
    // already, so an explicit retire that may discard the handle GCs it now rather
    // than leak it. Otherwise mark the slot errored (so no further pump polls the
    // now-gone service for transmits) and `caller_gone` (so the completed-
    // withdrawal GC removes it regardless of pending updates — no reader is
    // guaranteed), then begin its endpoint-owned withdrawal.
    let route_freed = match self.services.get_mut(&handle) {
      Some(slot) if slot.route_freed => true,
      Some(slot) => {
        slot.errored = true;
        slot.caller_gone = true;
        false
      }
      None => return,
    };
    if route_freed {
      self.services.remove(&handle);
    } else {
      self.begin_service_withdrawal(handle, now);
    }
  }

  /// Start a query. Updates are read via [`Self::poll_query_update`].
  pub fn start_query(&mut self, spec: QuerySpec, now: I) -> Result<QueryHandle, StartQueryError> {
    let handle = self.endpoint.try_start_query(spec, now)?;
    self.queries.insert(
      handle,
      QuerySlot {
        errored: false,
        wire_gate: FamilyWireGate::new(),
      },
    );
    Ok(handle)
  }

  /// Cancel a query and free its pool slot.
  pub fn cancel_query(&mut self, handle: QueryHandle) {
    self.queries.remove(&handle);
    let _ = self.endpoint.cancel_query(handle);
  }

  /// Iterate the answers a query has collected so far — the browse / discovery
  /// results. Empty if `handle` is not an active query. Read this after any
  /// [`Self::pump`] (or a [`Self::poll_query_update`]); the proto keeps a bounded
  /// snapshot, so compare its length against [`Self::query_accepted_count`] to
  /// detect answers the `max_answers` cap evicted before you read them.
  pub fn collected_answers(
    &self,
    handle: QueryHandle,
  ) -> impl Iterator<Item = &CollectedAnswer> + '_ {
    self.endpoint.collected_answers(handle)
  }

  /// Total answers ever accepted by a query (including ones the `max_answers` cap
  /// has since evicted from [`Self::collected_answers`]). `None` if `handle` is not
  /// an active query.
  pub fn query_accepted_count(&self, handle: QueryHandle) -> Option<u64> {
    self.endpoint.query_accepted_count(handle)
  }

  /// Step the engine once: fire due timers, drain all ready RX through the
  /// §11 gate into the proto, surface service updates, drain all pending TX via
  /// `io`, pump any due endpoint-owned withdrawal goodbyes, and return the next
  /// deadline to sleep until.
  ///
  /// `clock` is the caller's monotonic clock — a reading, not a pre-sampled
  /// instant, so this pump can measure how long it has been running instead of
  /// charging that to the protocol. It is read once at entry for the PASS
  /// instant, the single reference every due-list comparison in the pass shares,
  /// and again at every point where an instant describes an EVENT ON THE EGRESS
  /// PATH rather than answering a due-list question — on this transport that
  /// event is a datagram entering a socket's transmit queue, which is as close to
  /// the wire as this seam can see ([`UdpIo::try_send`] says what that does and
  /// does not bound):
  ///
  /// * immediately before each per-family send attempt — whether that family has
  ///   had its RFC 6762 §8.1 / §8.3 gap, and what its acceptance anchors on;
  /// * immediately after each successful attempt — what that family's gate
  ///   records;
  /// * after each fan-out, normal transmit and §10.1 goodbye alike — the anchor a
  ///   round no family accepted is re-armed from.
  ///
  /// Give it a cheap, non-decreasing read: a clock that goes backwards only makes
  /// gates close and schedules re-arm early, never late, but a `pump` that spends
  /// a syscall per read pays it several times per datagram.
  ///
  /// A caller CAN hand back a captured instant instead of reading one, and
  /// nothing here can tell an honest reading from a stale one. The parameter is a
  /// clock rather than an instant so that correct sampling is what is natural to
  /// write, which is as far as a sans-io API can go.
  ///
  /// **Graceful shutdown.** There is no separate flush path: `unregister_service`
  /// begins each service's endpoint-owned §10.1 withdrawal, and `pump` drives the
  /// goodbye sends + frees the route on completion. To flush all pending
  /// withdrawals before exiting, drive `pump` until [`Self::poll_deadline`] returns
  /// `None` (no service, query, cache, or withdrawal deadline remains) — at which
  /// point every withdrawal has completed (sent its budget or hit its 2 s anti-pin
  /// ceiling) and its route is freed.
  pub fn pump<T: UdpIo, C: FnMut() -> I>(
    &mut self,
    mut clock: C,
    io: &mut T,
    scratch: &mut [u8],
  ) -> Option<I> {
    // The pass instant: read once, then held for every due-list question this
    // pump asks, so the order in which producers and datagrams are visited cannot
    // change which of them the pass considers due.
    let now = clock();
    self.fire_timeouts(now);

    // Drain queued inbound datagrams, capped at MAX_RX_PER_PUMP so a flood can't grow
    // a service's proto update pool proportional to the whole RX backlog before
    // `drain_service_updates` coalesces/caps it. `try_recv` returns owned
    // (`Copy`) metadata, so the mutable borrow of `scratch` ends before `handle_one`
    // re-borrows it immutably alongside `&mut self`.
    let mut rx_processed = 0usize;
    while rx_processed < MAX_RX_PER_PUMP {
      let Some(meta) = io.try_recv(scratch) else {
        break;
      };
      rx_processed += 1;
      let len = meta.len;
      // A zero-length receive is a transport drop marker (e.g. smoltcp truncating an
      // oversized datagram): it still counts against the per-pump RX cap so a flood of
      // oversized packets can't drain the whole socket backlog in one uncapped pass
      //, but there is nothing to deliver.
      if len == 0 {
        // A zero-length marker means smoltcp dequeued + discarded an oversized
        // datagram before we saw it — the datagram WAS consumed from the
        // transport queue, so bump packets_rx as a reliable denominator plus
        // the usual packets_dropped reject counter. bytes_rx is NOT bumped
        // because smoltcp discards the oversized payload before reporting to
        // us; the original datagram length is not recoverable here.
        #[cfg(feature = "stats")]
        {
          self.stats.packets_rx(1);
          self.stats.packets_dropped(1);
        }
        #[cfg(feature = "defmt")]
        defmt::debug!("rx drop: oversized/truncated datagram (len=0 marker)");
        continue;
      }
      // NOTE: packets_rx / bytes_rx are bumped by ProtoEndpoint::handle()
      // on the shared Arc — do NOT bump them here too (double-count).
      #[cfg(feature = "defmt")]
      defmt::trace!("rx {} bytes", len);
      if onlink::on_link(meta.hop_limit, meta.src.ip(), meta.local, &self.subnets) {
        self.handle_one(now, meta.src, meta.local, &scratch[..len]);
      } else {
        // RFC 6762 §11: off-link datagram — a present hop limit other than
        // 255, or an absent one with neither an mDNS-group destination nor an
        // on-subnet source. Discard without calling into the proto layer. The
        // datagram WAS received off the socket, so count packets_rx/bytes_rx
        // here (handle() never runs for it) plus the packets_dropped reject —
        // matching the reactor/compio pre-handle drop accounting so receive
        // volume and the drop stay driver-consistent rather than hidden here.
        #[cfg(feature = "stats")]
        {
          self.stats.packets_rx(1);
          self.stats.bytes_rx(len as u64);
          self.stats.packets_dropped(1);
        }
        #[cfg(feature = "defmt")]
        defmt::debug!("rx drop: off-link datagram (RFC 6762 §11 trust boundary)");
      }
    }
    // Hit the cap → more datagrams may be buffered; re-pump immediately (below)
    // rather than sleeping to the next timer.
    let rx_capped = rx_processed == MAX_RX_PER_PUMP;

    self.drain_service_updates(now);

    // The free-name goodbye ORDERING (a stale TTL=0 must precede a same-name
    // replacement's fresh positive TTL) is now enforced by the endpoint: it KEEPS
    // the route while a withdrawal is in flight, so a same-name `register_service`
    // is rejected (`NameAlreadyRegistered`) until `drain_completed_withdrawals`
    // frees the name. No replacement can announce ahead of the withdrawal, so the
    // old pre-TX barrier gate is gone and the normal TX loop runs unconditionally.
    while let Some((transmit, origin)) = self.poll_one_transmit(now, scratch) {
      let (dst, len) = (transmit.dst(), transmit.size());
      if dst == MDNS_SOCKET_V4 || dst == MDNS_SOCKET_V6 {
        // Multicast: fan out to BOTH groups and confirm synchronously this pump
        // (honors the proto's confirm-on-send contract). `fanout` carries the
        // per-family outcome so stats are bumped from EXPLICIT sends, not a
        // coarse aggregate — consistent with reactor/compio.
        #[cfg_attr(
          not(any(feature = "stats", feature = "defmt")),
          allow(unused_variables)
        )]
        // The producing service's / query's own per-family egress spacing. Copied
        // out and written back because `self.tx` and the slot maps are disjoint
        // fields and the fan-out borrows the former mutably.
        let mut gate = self.wire_gate(origin);
        let fanout = self.tx.send_multicast(
          io,
          &scratch[..len],
          &mut clock,
          &mut gate,
          transmit.min_family_gap(),
        );
        self.set_wire_gate(origin, gate);
        // ── Per-family accounting, INDEPENDENT of the coarse outcome ────────────
        // A partial fan-out (v4 Sent + v6 TooLarge) queues one datagram AND
        // raises one error; keying either counter off the outcome arm would
        // silently drop one of them. Bump both here, before the match, from the
        // explicit per-family results — consistent with the withdrawal send below
        // and with reactor/compio, which bump once per per-family send_to call.
        // Busy/Unsupported are never errors, and "nothing sent" stays visible as
        // zero packets_tx rather than as a fabricated error.
        #[cfg(feature = "stats")]
        {
          let sent = fanout.sent_count();
          if sent > 0 {
            self.stats.packets_tx(u64::from(sent));
            self.stats.bytes_tx(fanout.bytes_accepted());
          }
          let failed = fanout.failed_count();
          if failed > 0 {
            self.stats.send_errors(u64::from(failed));
          }
        }
        #[cfg(feature = "defmt")]
        if fanout.any_sent() {
          defmt::trace!(
            "tx multicast {} bytes ({} families)",
            len,
            fanout.sent_count()
          );
        }
        // The honest per-family I/O facts, verbatim. A family that keeps missing
        // is eventually excused inside the confirm by the core's own patience
        // bound, and a datagram no reachable socket can ever carry is weighed
        // there against the transmit's own obligation — so nothing here needs to
        // read a meaning into the fan-out first.
        //
        // Resolve the commit token FIRST, then act on the verdict. A service's
        // `withdrawal_snapshot` reports only what a confirm has already latched,
        // and a query's terminal transition is bound by the same contract, so
        // retiring under a live token would build the §10.1 goodbye from a
        // producer the core still considers mid-datagram.
        //
        // Each acceptance already carries its own pre-send instant; what is read
        // here is the FALLBACK — the anchor a round no family accepted is
        // re-armed from. It is an egress spacing like the §10.1 one below, so it
        // is read after the fan-out rather than taken from the pass instant:
        // this pass may have drained `MAX_RX_PER_PUMP` datagrams and served every
        // earlier producer first, and charging that to the retry pulls the next
        // §8.1 probe or §8.3 announcement onto the heels of the attempt that
        // missed.
        let (v4, v6) = fanout.into_attempts();
        let fanned_out_at = clock();
        let confirm = self.note_transmit_outcome(origin, fanned_out_at, v4, v6);
        if confirm.retire_producer() {
          // The core re-arms this datagram forever and no reachable socket can
          // carry it, so the producer would probe/announce (or re-question)
          // indefinitely with nothing on the wire. Retire it, so the app sees an
          // actionable update instead of a silent stall.
          #[cfg(feature = "defmt")]
          defmt::warn!("tx multicast {} bytes undeliverable (too large)", len);
          self.retire_origin(origin, now);
        }
      } else {
        // Unicast (legacy §6.7 reply): one destination, no fan-out. A failed
        // one-shot reply is best-effort (the querier re-asks), never service-fatal.
        // Match on the error variant so Busy/Unsupported (transient/not-applicable)
        // are NOT counted as send_errors — consistent with multicast and reactor/compio.
        // Only a real socket failure (TooLarge → Failed semantics) is an error.
        //
        // Pre-send, like the fan-out's: the pass instant would anchor this
        // reply's acceptance at whenever the pump started rather than at the
        // offer, and one reference for both is exactly what the multicast path
        // above no longer does.
        let offered_at = clock();
        let result = io.try_send(&scratch[..len], dst);
        // RFC 6762 §6.7 legacy unicast: exactly ONE obligated link (the
        // destination's family), so this is AllDelivered or NoneDelivered by
        // construction and can never be partial. An absent socket
        // (`Unsupported`) is an EMPTY obligated set, which is NoneDelivered too —
        // never a vacuous "all".
        //
        // A failed reply is reported as-is and costs the service nothing: this
        // datagram is `TransmitObligation::OneShot`, so the core never re-arms it
        // and the querier simply re-asks. The multicast branch above reaches the
        // same conclusion for its own undeliverable one-shots.
        debug_assert_eq!(transmit.obligation(), TransmitObligation::OneShot);
        let served = match &result {
          Ok(()) => FamilyAttempt::Accepted { at: offered_at },
          // No socket for the destination's family: it was never obligated, so
          // the obligated set is EMPTY rather than failed.
          Err(SendError::Unsupported) => FamilyAttempt::NoSocket,
          // Past this socket buffer's ceiling: refused, and no later attempt at
          // these exact bytes can get past it. A one-shot reply is never re-armed,
          // so the core retires nothing for it.
          Err(SendError::TooLarge) => FamilyAttempt::Refused { permanent: true },
          Err(SendError::Busy) => FamilyAttempt::Refused { permanent: false },
        };
        // The family this reply was not addressed to may well be bound and
        // healthy; it was simply not for it.
        let (v4, v6) = match dst {
          SocketAddr::V4(_) => (served, FamilyAttempt::NotAddressed),
          SocketAddr::V6(_) => (FamilyAttempt::NotAddressed, served),
        };
        match result {
          Ok(()) => {
            #[cfg(feature = "stats")]
            {
              self.stats.packets_tx(1);
              self.stats.bytes_tx(len as u64);
            }
            #[cfg(feature = "defmt")]
            defmt::trace!("tx unicast {} bytes delivered", len);
          }
          Err(SendError::TooLarge) => {
            // Permanent failure (datagram too large for socket buffer): count as error.
            #[cfg(feature = "stats")]
            self.stats.send_errors(1);
          }
          Err(SendError::Busy) | Err(SendError::Unsupported) => {
            // Transient (Busy) or absent socket (Unsupported): not an error,
            // the querier will re-ask if it needs the answer.
          }
        }
        let _ = self.note_transmit_outcome(origin, clock(), v4, v6);
      }
    }

    // A confirmed final announcement sets `Established` (and other transitions)
    // INSIDE the TX loop above, AFTER the pre-loop drain. The next deadline is then
    // the distant re-announce, so without a second drain the application could not
    // observe `Established` until the next pump ~80% of a TTL away. Drain
    // again so confirmed transitions are visible to `poll_service_update` now.
    self.drain_service_updates(now);

    // ── Endpoint-owned withdrawals (RFC 6762 §10.1 goodbyes) ─────────────────
    // Pump every due TTL=0 goodbye datagram. The endpoint encodes each (with
    // fresh sibling host-address retention computed internally), hands back the
    // multicast datagram + the item's opaque withdrawal token and per-family debt;
    // the driver fans it out to the groups that debt names (`tx.burst`, the SAME
    // per-family send path the old goodbye burst used) and reports back each
    // family's outcome so the endpoint can spend / re-arm the resend round.
    while let Some(round) = self.endpoint.poll_withdrawal_transmit(now, scratch) {
      let (len, token, debt) = (round.len(), round.token(), round.debt());
      // The endpoint always returns the multicast marker; the driver fans the
      // datagram to every group the debt still names. Assert the contract in debug
      // builds.
      debug_assert_eq!(
        round.dst(),
        MDNS_SOCKET_V4,
        "withdrawal dst must be the multicast marker"
      );
      // Split borrow: `tx` and `endpoint` are disjoint fields. Re-borrow `scratch`
      // immutably here (the `poll_withdrawal_transmit` borrow ended on return).
      let fanout = self.tx.burst(io, &scratch[..len], debt, now);
      #[cfg(feature = "stats")]
      {
        // packets_tx / bytes_tx: one per family that returned Sent.
        let sent_count = fanout.sent_count();
        if sent_count > 0 {
          self.stats.packets_tx(u64::from(sent_count));
          self.stats.bytes_tx(fanout.bytes_accepted());
        }
        // send_errors: real I/O failures only (Failed = TooLarge write-off).
        let failed_count = fanout.failed_count();
        if failed_count > 0 {
          self.stats.send_errors(u64::from(failed_count));
        }
        // goodbyes_tx: one logical RFC 6762 retransmit round per DELIVERED round
        // (at least one family accepted it); a fully-failed round is re-armed by
        // the endpoint without spending and must NOT be counted.
        if fanout.any_sent() {
          self.stats.goodbyes_tx(1);
        }
      }
      #[cfg(feature = "defmt")]
      if fanout.any_sent() {
        defmt::trace!(
          "tx withdrawal {} bytes ({} families)",
          len,
          fanout.sent_count()
        );
      }
      // Report EACH family's outcome so the endpoint tracks per-family debt: a
      // withdrawal frees only once every reachable family has withdrawn its
      // records. v4-Sent + v6-Busy keeps v6's debt so a v6 recovery before
      // the 2 s ceiling still emits its TTL=0 goodbye.
      //
      // The instant re-arms the §10.1 resend SCHEDULE: a real-time spacing bound
      // on the egress path, and the only thing pacing consecutive goodbyes, since
      // this fan-out is deliberately ungated. It is therefore read from `clock`
      // AFTER the burst rather than taken from the pass instant. Everything this
      // pump spent before reaching here — up to `MAX_RX_PER_PUMP` inbound
      // datagrams, the whole normal transmit loop, every earlier withdrawal round
      // — would otherwise be charged to the NEXT round, and once that total
      // approaches the interval the next goodbye is already due at the moment this
      // one is queued, collapsing §10.1's three loss-resilience sends into
      // near-adjacent transmissions. Like every other egress instant here it is an
      // enqueue acceptance, so what it paces is the spacing between enqueues (see
      // `FamilyWireGate`). `try_send` being non-blocking bounds how long a send can
      // park and nothing else: not the CPU this pass spends, not how many producers
      // it serves, not preemption.
      //
      // The pass instant keeps every question it is the right reference for: which
      // items are due (`poll_withdrawal_transmit`), which have run out
      // (`drain_completed_withdrawals`), and the deadline this pump reports. Those
      // are due-list comparisons that must agree across the pass; this one is an
      // egress measurement. The two are wrong in opposite directions and are not
      // interchangeable.
      //
      // `burst` stamps each acceptance at the pass instant, which precedes every
      // send this round made: an acceptance anchor can only understate how fresh
      // a family's peers are, and can never fall after the confirm instant that
      // must not precede it. A goodbye burst is ungated, so unlike the normal
      // fan-out it reads no instant back as an egress measurement and needs no
      // per-family stamp of its own.
      let (v4, v6) = fanout.into_attempts();
      let fanned_out_at = clock();
      self
        .endpoint
        .note_withdrawal_result(token, fanned_out_at, v4, v6);
    }
    // Free completed withdrawals (budget spent or ceiling reached): the endpoint
    // releases each route (decrementing services_active) and reports the handle;
    // GC its driver slot. The scratch Vec is reused across pumps — `endpoint` and
    // `completed_withdrawals` are disjoint fields, so the borrow is accepted.
    self.completed_withdrawals.clear();
    self
      .endpoint
      .drain_completed_withdrawals(now, &mut self.completed_withdrawals);
    while let Some(handle) = self.completed_withdrawals.pop() {
      // GC the driver slot — but ONLY once its app-facing updates are drained, so a
      // `Conflict` queued at an internal retirement still reaches the host even
      // when the (empty, never-announced) withdrawal completes in the same pump
      // that began it. A slot with pending updates is marked `route_freed` and GC'd
      // lazily (here on a later pump, or by `poll_service_update` when it drains).
      match self.services.get_mut(&handle) {
        // No pending updates, OR the caller explicitly retired and may have
        // discarded the handle (`caller_gone`): GC now. Deferring a caller-gone
        // slot via `route_freed` would leak it forever — no reader remains.
        Some(slot) if slot.updates.is_empty() || slot.caller_gone => {
          self.services.remove(&handle);
        }
        Some(slot) => slot.route_freed = true,
        None => {}
      }
    }

    let deadline = self.poll_deadline();
    if rx_capped {
      // A capped RX drain left datagrams buffered: wake immediately (no later than
      // `now`) to drain the rest, instead of sleeping to a possibly-distant timer.
      Some(deadline.map_or(now, |d| d.min(now)))
    } else {
      deadline
    }
  }

  /// Feed one received datagram to the endpoint and route its `ToService`
  /// events to the owning service state machine.
  ///
  /// `now` carries a caller-facing bound as well as the core's schedules:
  /// `Endpoint::handle` weighs a query's `QuerySpec::with_timeout` window against
  /// it, so an answer is collected — and an RFC 6762 §7.3 slot spent — only while
  /// that window is open. It is the PASS instant, and deliberately so although
  /// [`Self::pump`] holds a live clock: this is a due-list comparison, and one
  /// drain must weigh every datagram against one reference or the RX order would
  /// decide which answers a closing window still admits. The overshoot it leaves
  /// is this drain, bounded by `MAX_RX_PER_PUMP` datagrams and whatever the
  /// caller's `UdpIo` spends handing them over, and it errs toward admitting an
  /// answer slightly late rather than dropping one early — the same position the
  /// admission side takes in `poll_one_transmit`. A fresh reading belongs where
  /// an instant describes an event on the egress path — every send attempt's own
  /// acceptance and gate stamp, and the anchor each fan-out re-arms from — and
  /// nowhere on this path.
  fn handle_one(&mut self, now: I, src: SocketAddr, local: Option<core::net::IpAddr>, data: &[u8]) {
    // `local_ip` is only used by the proto for tracing / the opt-in
    // advertised-source check; any valid address is acceptable.
    let local_ip = local.unwrap_or_else(|| src.ip());
    // RFC 6762 self-loopback guard: a datagram matching one we just multicast is
    // our own loopback (some stacks echo multicast to local sockets). Tell the
    // proto via `caller_is_self` so it does not interpret our own
    // probe/announcement as a conflicting peer — independent of the source
    // address, which the proto's advertised-source fallback cannot always match
    // (e.g. an IPv6 link-local source).
    let caller_is_self = self.tx.is_self(data, now);
    // Split borrow: `endpoint.handle` holds `&mut self.endpoint` while the
    // route-event iterator is alive, so per-service routing reads
    // `self.services` through the disjoint field.
    let Self {
      endpoint, services, ..
    } = self;
    let events = match endpoint.handle(now, src, local_ip, 0, data, caller_is_self) {
      Ok(events) => events,
      Err(_) => return,
    };
    for event in events {
      match event {
        Ok(RouteEvent::ToService(to_service)) => {
          if let Some(slot) = services.get_mut(&to_service.handle())
            && !slot.errored
          {
            slot.proto.handle_event(to_service.into_event(), now);
          }
        }
        Ok(_) => {}
        Err(_) => break,
      }
    }
  }

  /// Fire any due endpoint / query / service timers.
  fn fire_timeouts(&mut self, now: I) {
    let _ = self.endpoint.handle_timeout(now);

    // Split-borrow so the query sweep reads `queries` in place and ticks via the
    // disjoint `endpoint` field — no per-tick Vec snapshot.
    let Self {
      endpoint, queries, ..
    } = &mut *self;
    for (&handle, slot) in queries.iter() {
      if slot.errored {
        continue;
      }
      let _ = endpoint.handle_query_timeout(handle, now);
    }

    for slot in self.services.values_mut() {
      if !slot.errored {
        let _ = slot.proto.handle_timeout(now);
      }
    }
  }

  /// Drain each service's proto updates into its app-facing queue, performing
  /// the RFC 6762 §9 auto-rename routing (`handle_service_renamed`) before
  /// surfacing a `Renamed` update.
  ///
  /// A §9 rename of an ANNOUNCED service needs a TTL=0 withdrawal of the OLD
  /// instance name. The proto hands it off the instant the rename happens
  /// (`Service::take_rename_goodbye_handoff`); this driver enqueues it as an
  /// INDEPENDENT detached withdrawal item via
  /// [`Endpoint::enqueue_rename_withdrawal`], for BOTH a surviving rename and a
  /// collision teardown. The endpoint drives that item's goodbye schedule on the
  /// normal withdrawal pump; the proto no longer emits the old-name goodbye from
  /// its own `poll_transmit`.
  ///
  /// When the NEW name additionally collides with another LOCAL service
  /// (`handle_service_renamed` returns Err) the service is also torn down: its
  /// CURRENT name is withdrawn via the endpoint-owned withdrawal lifecycle
  /// ([`Self::begin_service_withdrawal`]), which holds the route and resends
  /// before freeing the name. (The old-name detached item was already enqueued.)
  fn drain_service_updates(&mut self, now: I) {
    self.svc_handle_scratch.clear();
    self
      .svc_handle_scratch
      .extend(self.services.keys().copied());
    let mut i = 0;
    while i < self.svc_handle_scratch.len() {
      let handle = self.svc_handle_scratch[i];
      i += 1;
      while let Some(update) = self
        .services
        .get_mut(&handle)
        .filter(|slot| !slot.errored)
        .and_then(|slot| slot.proto.poll())
      {
        if let ServiceUpdate::Renamed(ref renamed) = update {
          let new_name = renamed.new_name().clone();
          let rename_result = self.endpoint.handle_service_renamed(handle, new_name);
          // The §9 rename of an announced service hands its OLD-name TTL=0 goodbye
          // off as an INDEPENDENT detached withdrawal item, both for a SURVIVING
          // rename and a COLLISION teardown. Take it from the proto the instant the
          // rename is observed (into a local, releasing the `self.services` borrow
          // before re-borrowing `self.endpoint`) and enqueue it — the Service no
          // longer drains the old-name goodbye itself.
          let handoff = self
            .services
            .get_mut(&handle)
            .and_then(|slot| slot.proto.take_rename_goodbye_handoff());
          if let Some(handoff) = handoff {
            // A rename COLLISION (rename_result Err) tears the service down: its old
            // name must HOLD until the goodbye completes so a quick re-register
            // cannot cancel the only retraction. A SURVIVING rename
            // stays reclaimable.
            self
              .endpoint
              .enqueue_rename_withdrawal(handoff, now, rename_result.is_err());
          }
          if rename_result.is_err() {
            // The new name collides with another local service; the service has
            // already rebranded and can't be kept. Surface `Conflict` and mark it
            // errored so every pump skips it for transmits. Begin the endpoint-owned
            // withdrawal for the CURRENT name, which holds the route (keeping the
            // name reserved) while it resends, and frees the name on completion. The
            // OLD name's goodbye was already enqueued above as its own detached item.
            // The slot stays until then so this queued `Conflict` still reaches the
            // host (GC'd in `pump`).
            if let Some(slot) = self.services.get_mut(&handle) {
              slot.push_update(ServiceUpdate::Conflict);
              slot.errored = true;
            }
            self.begin_service_withdrawal(handle, now);
            break;
          }
        }
        // A terminal emitted DIRECTLY by the proto state machine (an unresolvable
        // §9 conflict, or the host name claimed during probing) RETIRES the
        // service, exactly like the rebrand-collision path above: queue the
        // terminal, mark the slot errored so every pump skips it, begin the
        // endpoint-owned §10.1 withdrawal (which holds the route and drives the
        // goodbye resend, GC'ing the slot on completion), and stop draining.
        // Without this a proto-emitted terminal left the smoltcp route registered
        // and still answered/driven after the caller saw the terminal.
        let is_terminal = update.is_conflict() || update.is_host_conflict();
        if let Some(slot) = self.services.get_mut(&handle) {
          slot.push_update(update);
          if is_terminal {
            slot.errored = true;
          }
        }
        if is_terminal {
          self.begin_service_withdrawal(handle, now);
          break;
        }
      }
    }
  }

  /// Begin the endpoint-owned RFC 6762 §10.1 withdrawal for `handle`: snapshot
  /// what its CURRENT name's goodbye must retract
  /// ([`Service::withdrawal_snapshot`]) and hand it to
  /// [`Endpoint::begin_withdrawal`]. The endpoint KEEPS the route (holding the
  /// name) and drives the resend schedule; the route is freed and the driver slot
  /// GC'd when [`Endpoint::drain_completed_withdrawals`] reports completion in
  /// [`Self::pump`]. Any in-flight §9 rename old-name goodbye is a SEPARATE
  /// detached item already enqueued via [`Endpoint::enqueue_rename_withdrawal`].
  ///
  /// The driver slot is left in place (the caller marks it `errored`) so a queued
  /// `ServiceUpdate::Conflict` still reaches the host before the slot is GC'd.
  /// `begin_withdrawal` is idempotent, so calling this for an already-withdrawing
  /// service is a no-op. A no-op for an unknown driver handle.
  fn begin_service_withdrawal(&mut self, handle: ServiceHandle, now: I) {
    // Scope the `slot` borrow so it ends before `self.endpoint` is touched (the
    // snapshot is owned, so no borrow of `self.services` outlives this block).
    // ALSO take any pending §9 rename handoff here: a retirement that races a
    // queued `Renamed` update (closed receiver / explicit unregister) never
    // reaches the update-drain site that normally enqueues it, which would strand
    // the old-name goodbye in a proto being GC'd. `.take()` makes the handoff
    // exactly-once vs the update-drain path.
    let (snap, handoff) = match self.services.get_mut(&handle) {
      Some(slot) => {
        let handoff = slot.proto.take_rename_goodbye_handoff();
        (slot.proto.withdrawal_snapshot(), handoff)
      }
      None => return,
    };
    if let Some(handoff) = handoff {
      // Retirement = the service is dead: hold its old name until the goodbye
      // completes so a re-register cannot cancel it.
      self.endpoint.enqueue_rename_withdrawal(handoff, now, true);
    }
    self.endpoint.begin_withdrawal(handle, snap, now);
  }

  /// This producer's per-family wire gate, copied out for a fan-out.
  ///
  /// Copied rather than borrowed because the fan-out borrows `self.tx` mutably at
  /// the same time. A producer retired mid-pump yields the default gate, which is
  /// open — the same answer as a producer that has sent nothing — and the
  /// write-back is then a no-op.
  fn wire_gate(&self, origin: Origin) -> FamilyWireGate<I> {
    match origin {
      Origin::Service(h) => self.services.get(&h).map(|s| s.wire_gate),
      Origin::Query(h) => self.queries.get(&h).map(|s| s.wire_gate),
    }
    .unwrap_or_else(FamilyWireGate::new)
  }

  /// Write a fan-out's updated wire gate back onto its producer.
  fn set_wire_gate(&mut self, origin: Origin, gate: FamilyWireGate<I>) {
    match origin {
      Origin::Service(h) => {
        if let Some(slot) = self.services.get_mut(&h) {
          slot.wire_gate = gate;
        }
      }
      Origin::Query(h) => {
        if let Some(slot) = self.queries.get_mut(&h) {
          slot.wire_gate = gate;
        }
      }
    }
  }

  /// Extract one outgoing datagram into `scratch`: services first, then
  /// queries. Skips errored state machines. Returns `None` when nothing is
  /// pending.
  /// The whole [`Transmit`] is returned rather than just its destination and
  /// length because [`Transmit::obligation`] must survive to the send: it decides
  /// what a PERMANENTLY undeliverable datagram means for the producer (see the
  /// [`MulticastOutcome::Undeliverable`] arm of [`Self::pump`]).
  fn poll_one_transmit(&mut self, now: I, scratch: &mut [u8]) -> Option<(Transmit, Origin)> {
    // Cap every encoded multicast at the RFC 6762 §17 ceiling, so the normal
    // transmit path never emits a datagram larger than the goodbye encode scratch
    // can later withdraw. A record set that would exceed MAX_MDNS_MESSAGE
    // then fails to encode here and the service is retired below (the `Err` arm),
    // rather than being advertised with records no §10.1 goodbye could retract.
    let cap = scratch.len().min(MAX_MDNS_MESSAGE);
    let scratch = &mut scratch[..cap];
    self.svc_handle_scratch.clear();
    self
      .svc_handle_scratch
      .extend(self.services.keys().copied());
    let mut i = 0;
    while i < self.svc_handle_scratch.len() {
      let handle = self.svc_handle_scratch[i];
      i += 1;
      // NLL note: the `slot` borrow is scoped to the `match` block so it ends
      // before the post-match in-iteration `begin_withdrawal` call below.
      let escalated = {
        let Some(slot) = self.services.get_mut(&handle) else {
          continue;
        };
        if slot.errored {
          continue;
        }
        match slot.proto.poll_transmit(now, scratch) {
          Ok(Some(transmit)) => {
            return Some((transmit, Origin::Service(handle)));
          }
          Ok(None) => false,
          Err(_) => {
            // The pending datagram can't be encoded into `scratch`; the proto
            // re-offers it forever, so retire the service to avoid a stall.
            // Queue Conflict for the caller (unchanged — the host still learns the
            // service died) and mark the slot errored so every subsequent pump
            // skips it (no busy-spin). The `slot` borrow ends here, so the
            // in-iteration `begin_withdrawal` call below is borrow-safe.
            slot.push_update(ServiceUpdate::Conflict);
            slot.errored = true;
            true
          }
        }
      };
      if escalated {
        // Begin the endpoint-owned withdrawal immediately — in-iteration and
        // non-bypassable — so an `Ok(Some)` early-return for a LATER service
        // cannot skip it. The endpoint KEEPS the route (holding the name) and
        // frees it when the goodbye completes; the slot is GC'd then. This
        // touches only `self.endpoint`, not `self.services`, so there is no
        // iterator invalidation, and `begin_withdrawal` is idempotent. The slot
        // is NOT removed here, so a queued `Conflict` still reaches the host.
        self.begin_service_withdrawal(handle, now);
      }
    }

    self.query_handle_scratch.clear();
    self
      .query_handle_scratch
      .extend(self.queries.keys().copied());
    let mut i = 0;
    while i < self.query_handle_scratch.len() {
      let handle = self.query_handle_scratch[i];
      i += 1;
      if self.queries.get(&handle).is_some_and(|slot| slot.errored) {
        continue;
      }
      // The PASS instant, not a fresh reading from `pump`'s clock. A query's
      // `QuerySpec::with_timeout` deadline bounds ADMISSION, which is a due-list
      // comparison: every producer one pass offers must be weighed against one
      // reference, or the iteration order would decide whose window is still open.
      // A fresh reading belongs where an instant describes an event on the
      // egress path — the send attempts and confirms in `pump` — not here.
      match self.endpoint.poll_query_transmit(handle, || now, scratch) {
        Ok(Some(transmit)) => {
          return Some((transmit, Origin::Query(handle)));
        }
        Ok(None) => {}
        Err(_) => {
          // The question can't be encoded into `scratch`; the proto re-offers it
          // forever, so retire the query (driver-skip + proto TIMEOUT terminal).
          self.retire_query(handle);
        }
      }
    }

    None
  }

  /// Confirm a previously polled transmit, so the proto latches goodbye ownership
  /// for whatever a family carried (§10.1) and advances its §8.1 probe / §8.3
  /// announce / §5.2 query-backoff lifecycle only once every obligated family
  /// heard it.
  ///
  /// `fallback_at` anchors a round NO family accepted — the core folds the
  /// earliest acceptance instead whenever there is one. It re-arms a real-time
  /// spacing, so the caller reads it AFTER the fan-out: the pass instant would
  /// charge everything the pump spent getting here to the retry, and the datagram
  /// that missed would be re-offered inside its own kind's minimum.
  fn note_transmit_outcome(
    &mut self,
    origin: Origin,
    fallback_at: I,
    v4: FamilyAttempt<I>,
    v6: FamilyAttempt<I>,
  ) -> TransmitConfirm {
    match origin {
      Origin::Service(handle) => {
        let Some(slot) = self.services.get_mut(&handle) else {
          return TransmitConfirm::default();
        };
        {
          let confirm = slot.proto.note_transmit_outcome(fallback_at, v4, v6);
          // Mirror the service's CONFIRMED-ADVERTISED host set into the endpoint
          // route so sibling host-address retention (during a same-host
          // withdrawal) honours what this service ACTUALLY announced, not its
          // configured addresses. That set grows exactly when ownership latches,
          // i.e. on any delivery, so a round that reached no wire has nothing to
          // mirror and nothing to gate. Idempotent overwrite. `slot.proto` (read)
          // and `self.endpoint` (mut) are disjoint fields, so this borrow is fine.
          if confirm.any_delivered() {
            // The reclaim-cancel gate is the ALL-delivered announcement fact the
            // CORE computes, ferried verbatim. It is emphatically NOT
            // `advertises_instance()` — that latch fires on any delivery by any
            // transmit kind, so a v4-only announcement (or a §6.7 legacy unicast
            // reply, which has one obligated link and is therefore all-delivered
            // by construction) would cancel a renamed-away name's goodbye that
            // the unserved family still needs. `FullyAnnounced` has no public
            // constructor precisely so that substitution cannot compile, and it
            // names the service it was minted from, so it cannot be applied to a
            // different one either.
            self.endpoint.note_service_announced(
              slot.proto.has_fully_announced(),
              slot.proto.advertised_a_addrs(),
              slot.proto.advertised_aaaa_addrs(),
            );
          }
          confirm
        }
      }
      Origin::Query(handle) => {
        self
          .endpoint
          .note_query_transmit_outcome(handle, fallback_at, v4, v6)
      }
    }
  }

  /// Retire the state machine that produced a permanently-undeliverable
  /// [`TransmitObligation::Sustained`] transmit (a datagram too large for every
  /// reachable socket — a TX-buffer misconfig). The producer is marked errored so
  /// every pump skips it, and a service surfaces an actionable `Conflict` (the
  /// same retirement signal as an un-encodable datagram) instead of
  /// probing/announcing forever.
  ///
  /// Reserved for `Sustained` producers. A one-shot reply that cannot be sent is
  /// simply an unanswered question; retiring on one would make an established
  /// service destructible by any peer that asks it something.
  fn retire_origin(&mut self, origin: Origin, now: I) {
    match origin {
      Origin::Service(handle) => {
        if let Some(slot) = self.services.get_mut(&handle) {
          slot.push_update(ServiceUpdate::Conflict);
          slot.errored = true;
        }
        // Begin the endpoint-owned withdrawal: it KEEPS the route (holding the
        // name) and frees it on goodbye completion, decrementing services_active
        // then. The slot is NOT removed here, so the queued `Conflict` still
        // reaches the host; it is GC'd in `pump` on completion.
        // `begin_withdrawal` is idempotent (safe on a double retirement) and a
        // no-op for an unknown handle.
        self.begin_service_withdrawal(handle, now);
      }
      Origin::Query(handle) => self.retire_query(handle),
    }
  }

  /// Retire a query the driver cannot transmit (un-encodable question, or a
  /// permanently-too-large datagram on every reachable family). It is skipped by
  /// every pump (`errored`) AND forced to its proto-level TIMEOUT terminal, so the
  /// caller observes one `QueryUpdate::Timeout` (via `poll_query_update` →
  /// `Endpoint::poll_query`), late answers are frozen, and `collected_answers` stay
  /// readable until the caller cancels — instead of the query hanging forever (kept in sync with proto state).
  fn retire_query(&mut self, handle: QueryHandle) {
    self.endpoint.retire_query(handle);
    if let Some(slot) = self.queries.get_mut(&handle) {
      slot.errored = true;
    }
  }

  /// The earliest deadline across the endpoint, services, and queries.
  ///
  /// Endpoint-owned withdrawal deadlines (the next due goodbye round and the
  /// anti-pin ceiling) are already folded into [`Endpoint::poll_timeout`], so the
  /// driver no longer tracks them here.
  pub fn poll_deadline(&self) -> Option<I> {
    let mut best = self.endpoint.poll_timeout();
    for slot in self.services.values() {
      if slot.errored {
        continue;
      }
      if let Some(deadline) = slot.proto.poll_timeout() {
        best = Some(best.map_or(deadline, |b| b.min(deadline)));
      }
    }
    for (handle, slot) in &self.queries {
      if slot.errored {
        continue;
      }
      if let Some(deadline) = self.endpoint.poll_query_timeout(*handle) {
        best = Some(best.map_or(deadline, |b| b.min(deadline)));
      }
    }
    best
  }

  /// Pop one app-facing update for a registered service.
  ///
  /// If this drains the LAST update of a slot whose endpoint-owned withdrawal has
  /// already completed (`route_freed`), the slot is GC'd here — the deferred GC
  /// that lets a retirement `Conflict` survive a withdrawal which completed in the
  /// same pump that began it (see the `ServiceSlot::route_freed` field).
  pub fn poll_service_update(&mut self, handle: ServiceHandle) -> Option<ServiceUpdate> {
    let slot = self.services.get_mut(&handle)?;
    let update = slot.updates.pop_front();
    if update.is_some() && slot.route_freed && slot.updates.is_empty() {
      self.services.remove(&handle);
    }
    update
  }

  /// Pop one app-facing update for a query. A query the driver RETIRED (its
  /// question is un-encodable, or permanently unsendable on every reachable
  /// family) was forced to the proto's TIMEOUT terminal when the driver retired it,
  /// so it surfaces one [`QueryUpdate::Timeout`] here — the caller learns it died
  /// (and can read [`Self::collected_answers`], frozen, then cancel) instead of
  /// waiting forever for a result it can never request.
  pub fn poll_query_update(&mut self, handle: QueryHandle) -> Option<QueryUpdate> {
    self.endpoint.poll_query(handle)
  }

  /// Pop one endpoint-level event.
  pub fn poll_endpoint_event(&mut self) -> Option<EndpointEvent> {
    self.endpoint.poll()
  }
}

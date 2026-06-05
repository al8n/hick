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
  endpoint::{Endpoint, EndpointEventEntry, ServiceRoute, WithdrawalSend},
  error::{RegisterServiceError, StartQueryError},
  event::{EndpointEvent, QueryUpdate, RouteEvent, ServiceUpdate},
  query::Query,
  service::Service,
  slab::Slab,
  transmit::Transmit,
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

/// A recent multicast datagram we put on the wire, kept (exact bytes + send time)
/// for self-loopback detection.
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
struct QuerySlot {
  errored: bool,
}

/// The outcome of a single per-family send attempt in a multicast fan-out or
/// goodbye burst, carrying exactly what happened to that one family's socket call.
///
/// `Sent(n)` — the datagram was queued: `n` bytes went on the wire.
/// `Failed`   — a real I/O error (e.g. TooLarge in the normal TX path).
/// `Unsupported` — no socket for this family; not an error.
/// `Busy`     — the socket is transiently full; will be retried.
///
/// Separating these four cases lets accounting sites be exact: `packets_tx` /
/// `bytes_tx` increment only for `Sent`, `send_errors` only for `Failed`.
#[derive(Debug, Clone, Copy)]
enum FamilySend {
  /// Datagram placed on the wire; payload byte count is carried for `bytes_tx`.
  Sent(usize),
  /// Real I/O failure — the socket exists but permanently rejected the datagram.
  Failed,
  /// No socket for this family; not an error, not a retry candidate.
  Unsupported,
  /// Socket transiently full; will be retried.
  Busy,
}

impl FamilySend {
  /// Whether the datagram actually reached this family's socket.
  fn is_sent(self) -> bool {
    matches!(self, FamilySend::Sent(_))
  }

  /// Map this family's send outcome to the per-family withdrawal debt result the
  /// endpoint consumes: a queued send spends one of the family's owed rounds
  /// (`Sent`); a transiently-full socket keeps its debt to retry (`Busy` →
  /// `Retry`); an absent socket or a real I/O failure writes the debt off
  /// (`Unsupported`/`Failed` → `WriteOff`), since that family has no reachable
  /// peers to withdraw from.
  fn withdrawal_send(self) -> WithdrawalSend {
    match self {
      FamilySend::Sent(_) => WithdrawalSend::Sent,
      FamilySend::Busy => WithdrawalSend::Retry,
      FamilySend::Unsupported | FamilySend::Failed => WithdrawalSend::WriteOff,
    }
  }
}

/// The per-family results of a multicast fan-out: one [`FamilySend`] for v4
/// and one for v6. Carry this from `send_multicast`/`burst` to the accounting
/// site so counters are bumped from explicit per-family outcomes rather than
/// from a coarse aggregate.
#[derive(Debug, Clone, Copy)]
struct Fanout {
  v4: FamilySend,
  v6: FamilySend,
}

impl Fanout {
  /// Returns `true` if at least one family sent the datagram successfully.
  fn any_sent(self) -> bool {
    self.v4.is_sent() || self.v6.is_sent()
  }

  /// Total number of per-family sends that actually placed bytes on the wire
  /// (0, 1, or 2). Used for `packets_tx`.
  #[cfg_attr(not(feature = "stats"), allow(dead_code))]
  fn sent_count(self) -> u32 {
    u32::from(self.v4.is_sent()) + u32::from(self.v6.is_sent())
  }

  /// Total bytes placed on the wire (sum across sending families). Used for
  /// `bytes_tx`; the byte count is per-family because both families encode the
  /// same datagram, so a dual-stack send doubles the on-wire bytes.
  #[cfg_attr(not(feature = "stats"), allow(dead_code))]
  fn bytes_on_wire(self) -> u64 {
    let mut n = 0u64;
    if let FamilySend::Sent(b) = self.v4 {
      n += b as u64;
    }
    if let FamilySend::Sent(b) = self.v6 {
      n += b as u64;
    }
    n
  }

  /// Count of families that returned a real I/O failure (`Failed`). Does NOT
  /// count `Unsupported` (absent socket) or `Busy` (transient). Used for
  /// `send_errors`.
  #[cfg_attr(not(feature = "stats"), allow(dead_code))]
  fn failed_count(self) -> u32 {
    u32::from(matches!(self.v4, FamilySend::Failed))
      + u32::from(matches!(self.v6, FamilySend::Failed))
  }

  /// `true` if at least one family is transiently `Busy` and should be retried.
  fn any_busy(self) -> bool {
    matches!(self.v4, FamilySend::Busy) || matches!(self.v6, FamilySend::Busy)
  }

  /// Derive the coarse [`MulticastOutcome`] the state machine needs for the
  /// proto confirm-on-send contract.
  fn into_multicast_outcome(self, any_too_large: bool) -> MulticastOutcome {
    if self.any_sent() {
      MulticastOutcome::Delivered
    } else if self.any_busy() {
      MulticastOutcome::Retry
    } else if any_too_large {
      MulticastOutcome::Undeliverable
    } else {
      // Every family absent (Unsupported); keep re-offering without retiring.
      MulticastOutcome::Retry
    }
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

/// The result of a synchronous multicast fan-out, deciding how the pump confirms.
enum MulticastOutcome {
  /// At least one family queued the datagram → confirm the proto transmit.
  Delivered,
  /// Nothing queued, but a family is transiently busy (or merely absent) → leave
  /// it unconfirmed; the proto re-offers and the next pump retries.
  Retry,
  /// Nothing queued and a family reported the datagram permanently TooLarge, with
  /// no transient family left to wait for → it can never be sent, so the producing
  /// service/query is retired rather than re-offered forever.
  Undeliverable,
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
  /// **Confirm-on-send contract** (the proto's own): `delivered = true` iff at
  /// least one socket send succeeded. So `Fanout::any_sent()` decides whether
  /// the pump confirms — NOT whether every family succeeded.
  ///
  /// That `sent_any` (not all-families) rule is load-bearing for one-shot
  /// transmits. The proto re-offers a probe/announcement on `delivered = false`
  /// (its own schedule retries the family that missed this round), but it
  /// CONSUMES a one-shot multicast response — and spends a conflict-rename
  /// goodbye — on the first result, latching goodbye ownership ONLY on
  /// `delivered = true`. If a partial fan-out (v4 queued, v6 transiently busy)
  /// reported `false`, the records v4 already put on the wire would be cached by
  /// v4 peers yet never latched, so a later unregister/conflict would omit their
  /// §10.1 withdrawal and leave stale peer caches. Reporting `sent_any` latches
  /// exactly what reached the link; the family that missed this round is tried
  /// FIRST on the next fan-out ([`family_order`]) so even a one-datagram-per-cycle
  /// transport reaches both groups instead of starving one, and a one-shot
  /// response is re-asked by the querier if its family missed. Only an
  /// all-families failure (nothing queued) returns `false`, correctly re-offering
  /// a probe/announce and latching nothing for a response that never left the
  /// host.
  ///
  /// The endpoint-owned withdrawal send uses [`Self::burst`] instead — the
  /// endpoint owns that retry schedule, so the driver just fans one due goodbye
  /// datagram to both families per round and reports `any_sent` back.
  ///
  /// Records a self-send credit for every family that sent. Uses `data.len()` as
  /// the byte count for both families (they encode the same datagram).
  fn send_multicast<T: UdpIo>(
    &mut self,
    io: &mut T,
    data: &[u8],
    now: I,
  ) -> (MulticastOutcome, Fanout) {
    let mut results = [FamilySend::Unsupported; 2];
    let mut any_too_large = false;
    for (idx, group) in family_order(&self.failing_since) {
      let outcome = match io.try_send(data, group) {
        Ok(()) => {
          self.failing_since[idx] = None;
          FamilySend::Sent(data.len())
        }
        // Busy is TRANSIENT — a momentarily-full TX queue, or an embassy
        // NoRoute/SocketNotBound that can clear. Track the failing streak for
        // fair fan-out ordering.
        Err(SendError::Busy) => {
          self.failing_since[idx].get_or_insert(now);
          FamilySend::Busy
        }
        // No socket for this family — absent, but the other family may carry it.
        Err(SendError::Unsupported) => FamilySend::Unsupported,
        // Permanently larger than this socket buffer — retrying cannot help.
        Err(SendError::TooLarge) => {
          any_too_large = true;
          // Map TooLarge to Failed so the caller can count it as a send error.
          FamilySend::Failed
        }
      };
      results[idx] = outcome;
    }
    let fanout = Fanout {
      v4: results[0],
      v6: results[1],
    };
    if fanout.any_sent() {
      self.record(data, now);
    }
    (fanout.into_multicast_outcome(any_too_large), fanout)
  }

  /// Fan ONE endpoint-owned withdrawal (TTL=0 goodbye) datagram out to every
  /// family that still owes a send this round, in priority order ([`family_order`],
  /// so a one-slot transport stays fair). `owed` is a per-family one-shot gate for
  /// THIS round (the driver passes `[1, 1]` and discards the result) — the
  /// multi-round resend schedule is owned by [`Endpoint::note_withdrawal_result`],
  /// NOT by this method. A family that queues decrements its gate (to 0); a family
  /// with NO socket (`Unsupported`) or a permanently-too-large datagram (`TooLarge`)
  /// is written off; a busy family keeps its gate but, since the driver discards
  /// `owed`, simply reports `Busy` for this round (the endpoint re-arms it).
  /// Maintains `failing_since` so the prioritisation favours whichever family is
  /// behind. Not fingerprinted (a goodbye loopback is harmless — it withdraws
  /// records already being withdrawn).
  ///
  /// Returns a [`Fanout`] with the per-family outcome so the caller can derive
  /// EXACT stats: `packets_tx`/`bytes_tx` for `Sent`, `send_errors` for `Failed`,
  /// nothing for `Unsupported`/`Busy`, and `any_sent` for the
  /// [`Endpoint::note_withdrawal_result`] delivery confirmation.
  fn burst<T: UdpIo>(&mut self, io: &mut T, data: &[u8], owed: &mut [u8; 2], now: I) -> Fanout {
    let mut results = [FamilySend::Unsupported; 2];
    for (idx, group) in family_order(&self.failing_since) {
      if owed[idx] == 0 {
        // Already finished for this family — leave result as Unsupported
        // (finished-not-owed, not an error, no packet, no send_errors).
        continue;
      }
      let outcome = match io.try_send(data, group) {
        Ok(()) => {
          self.failing_since[idx] = None;
          owed[idx] = owed[idx].saturating_sub(1);
          FamilySend::Sent(data.len())
        }
        // No socket for this family: write it off (no withdrawal possible, no
        // error — there's simply no socket to fail). Do NOT count as send_errors.
        Err(SendError::Unsupported) => {
          owed[idx] = 0;
          FamilySend::Unsupported
        }
        // Permanently too large for this socket's buffer: write it off and
        // count as a real send error (the socket exists but rejects the datagram).
        // (A queued goodbye is a subset of records already announced within the
        // §17 ceiling, so TooLarge here is defensive, but still a real failure.)
        Err(SendError::TooLarge) => {
          owed[idx] = 0;
          FamilySend::Failed
        }
        // Busy (transiently or persistently): keep the count and retry next call.
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
  queries: BTreeMap<QueryHandle, QuerySlot>,
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

  /// Set the device's local subnets — the RFC 6762 §11 on-link heuristic used when
  /// the transport cannot surface the received hop-limit (neither supplied transport
  /// can; smoltcp's `UdpMetadata` carries no RX TTL).
  ///
  /// OPTIONAL. With no subnets configured the §11 gate accepts every inbound mDNS
  /// datagram (the groups are link-scoped multicast routers do not forward, so it is
  /// on-link by IP design) rather than dropping all of it and going deaf. Configure
  /// the device's own subnets to additionally REJECT sources outside them — a
  /// best-effort defence against a same-link host spoofing on-link traffic.
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
  /// datagram on the wire.
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
    self.queries.insert(handle, QuerySlot { errored: false });
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
  /// **Graceful shutdown.** There is no separate flush path: `unregister_service`
  /// begins each service's endpoint-owned §10.1 withdrawal, and `pump` drives the
  /// goodbye sends + frees the route on completion. To flush all pending
  /// withdrawals before exiting, drive `pump` until [`Self::poll_deadline`] returns
  /// `None` (no service, query, cache, or withdrawal deadline remains) — at which
  /// point every withdrawal has completed (sent its budget or hit its 2 s anti-pin
  /// ceiling) and its route is freed.
  pub fn pump<T: UdpIo>(&mut self, now: I, io: &mut T, scratch: &mut [u8]) -> Option<I> {
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
        // RFC 6762 §11: off-link datagram (hop-limit ≠ 255 or src not on a
        // known subnet). Discard without calling into the proto layer. The
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
    while let Some((dst, len, origin)) = self.poll_one_transmit(now, scratch) {
      if dst == MDNS_SOCKET_V4 || dst == MDNS_SOCKET_V6 {
        // Multicast: fan out to BOTH groups and confirm synchronously this pump
        // (honors the proto's confirm-on-send contract). `fanout` carries the
        // per-family outcome so stats are bumped from EXPLICIT sends, not a
        // coarse aggregate — consistent with reactor/compio.
        #[cfg_attr(
          not(any(feature = "stats", feature = "defmt")),
          allow(unused_variables)
        )]
        let (outcome, fanout) = self.tx.send_multicast(io, &scratch[..len], now);
        // ── send_errors: count per-family Failed, INDEPENDENT of coarse outcome ──
        // A partial fan-out (v4 Sent + v6 TooLarge) yields MulticastOutcome::Delivered
        // but still has failed_count() == 1. Counting only inside the Undeliverable
        // arm would silently drop that error. Count here, unconditionally, before the
        // outcome match — consistent with the withdrawal send below and reactor/compio
        // (Busy/Unsupported are never errors; only Failed counts).
        #[cfg(feature = "stats")]
        {
          let fc = fanout.failed_count();
          if fc > 0 {
            self.stats.send_errors(fc as u64);
          }
        }
        match outcome {
          MulticastOutcome::Delivered => {
            // Bump per ACTUAL datagram sent: one per family that returned Sent.
            // `fanout.sent_count()` is 2 on dual-stack (both Sent), 1 on a
            // partial fan-out. This matches reactor/compio which each bump
            // packets_tx once per per-family successful send_to call.
            // `fanout.bytes_on_wire()` sums the bytes per sending family.
            #[cfg(feature = "stats")]
            {
              self.stats.packets_tx(fanout.sent_count() as u64);
              self.stats.bytes_tx(fanout.bytes_on_wire());
            }
            #[cfg(feature = "defmt")]
            defmt::trace!(
              "tx multicast {} bytes delivered ({} families)",
              len,
              fanout.sent_count()
            );
            self.note_transmit_result(origin, now, true);
          }
          MulticastOutcome::Retry => self.note_transmit_result(origin, now, false),
          // Permanently undeliverable (too large for every reachable socket): retire
          // the producer so it stops re-offering forever and the app sees an
          // actionable update, instead of probing/announcing indefinitely.
          MulticastOutcome::Undeliverable => {
            #[cfg(feature = "defmt")]
            defmt::warn!("tx multicast {} bytes undeliverable (too large)", len);
            // send_errors was already counted per Failed family above. The
            // all-Unsupported case (no socket on any family) is NOT a send error —
            // Unsupported is never an error, consistent with the per-family rule
            // and reactor/compio; "nothing sent" is visible as zero packets_tx.
            self.retire_origin(origin, now);
          }
        }
      } else {
        // Unicast (legacy §6.7 reply): one destination, no fan-out. A failed
        // one-shot reply is best-effort (the querier re-asks), never service-fatal.
        // Match on the error variant so Busy/Unsupported (transient/not-applicable)
        // are NOT counted as send_errors — consistent with multicast and reactor/compio.
        // Only a real socket failure (TooLarge → Failed semantics) is an error.
        let result = io.try_send(&scratch[..len], dst);
        let delivered = result.is_ok();
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
        self.note_transmit_result(origin, now, delivered);
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
    // multicast datagram + the item's opaque withdrawal token; the driver fans it
    // out to BOTH groups (`tx.burst`, the SAME per-family send path the old goodbye
    // burst used) and reports back whether at least one family sent so the endpoint
    // can spend / re-arm the resend round.
    while let Some((dst, len, token)) = self.endpoint.poll_withdrawal_transmit(now, scratch) {
      // The endpoint always returns the multicast marker; the driver fans the
      // datagram to both groups regardless. Assert the contract in debug builds.
      debug_assert_eq!(
        dst, MDNS_SOCKET_V4,
        "withdrawal dst must be the multicast marker"
      );
      let _ = dst;
      // `owed = [1, 1]` is a throwaway one-shot-per-family gate for THIS round —
      // the endpoint owns the multi-round schedule, so the mutation is discarded.
      let mut owed = [1u8; 2];
      // Split borrow: `tx` and `endpoint` are disjoint fields. Re-borrow `scratch`
      // immutably here (the `poll_withdrawal_transmit` borrow ended on return).
      let fanout = self.tx.burst(io, &scratch[..len], &mut owed, now);
      #[cfg(feature = "stats")]
      {
        // packets_tx / bytes_tx: one per family that returned Sent.
        let sent_count = fanout.sent_count();
        if sent_count > 0 {
          self.stats.packets_tx(u64::from(sent_count));
          self.stats.bytes_tx(fanout.bytes_on_wire());
        }
        // send_errors: real I/O failures only (Failed = TooLarge write-off).
        let failed_count = fanout.failed_count();
        if failed_count > 0 {
          self.stats.send_errors(u64::from(failed_count));
        }
        // goodbyes_tx: one logical RFC 6762 retransmit round per DELIVERED round
        // (at least one family on the wire); a fully-failed round is re-armed by
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
      self.endpoint.note_withdrawal_result(
        token,
        now,
        fanout.v4.withdrawal_send(),
        fanout.v6.withdrawal_send(),
      );
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

  /// Extract one outgoing datagram into `scratch`: services first, then
  /// queries. Skips errored state machines. Returns `None` when nothing is
  /// pending.
  fn poll_one_transmit(
    &mut self,
    now: I,
    scratch: &mut [u8],
  ) -> Option<(SocketAddr, usize, Origin)> {
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
            return Some((transmit.dst(), transmit.size(), Origin::Service(handle)));
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
      match self.endpoint.poll_query_transmit(handle, now, scratch) {
        Ok(Some(transmit)) => {
          return Some((transmit.dst(), transmit.size(), Origin::Query(handle)));
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

  /// Confirm a previously polled transmit so the proto advances its §8.1 probe /
  /// §8.3 announce / §5.2 query-backoff lifecycle only on a delivered send.
  fn note_transmit_result(&mut self, origin: Origin, now: I, delivered: bool) {
    match origin {
      Origin::Service(handle) => {
        if let Some(slot) = self.services.get_mut(&handle) {
          slot.proto.note_transmit_result(now, delivered);
          // Mirror the service's CONFIRMED-ADVERTISED host set into the endpoint
          // route so sibling host-address retention (during a same-host
          // withdrawal) honours what this service ACTUALLY announced, not its
          // configured addresses. Idempotent overwrite; only meaningful after a
          // delivered announce, harmless otherwise. `slot.proto` (read) and
          // `self.endpoint` (mut) are disjoint fields, so this borrow is fine.
          if delivered {
            self.endpoint.note_service_advertised(
              handle,
              slot.proto.advertised_a_addrs(),
              slot.proto.advertised_aaaa_addrs(),
              slot.proto.advertises_instance(),
            );
          }
        }
      }
      Origin::Query(handle) => {
        self
          .endpoint
          .note_query_transmit_result(handle, now, delivered);
      }
    }
  }

  /// Retire the state machine that produced a permanently-undeliverable transmit
  /// (a datagram too large for every reachable socket — a TX-buffer misconfig).
  /// The producer is marked errored so every pump skips it, and a service surfaces
  /// an actionable `Conflict` (the same retirement signal as an un-encodable
  /// datagram) instead of probing/announcing forever.
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

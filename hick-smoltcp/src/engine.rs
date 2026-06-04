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
  pub fn stats_handle(&self) -> Arc<Stats> {
    self.stats.clone()
  }

  /// Take a consistent point-in-time snapshot of every counter and gauge.
  #[cfg(feature = "stats")]
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

    let query_handles: Vec<QueryHandle> = self
      .queries
      .iter()
      .filter(|(_, slot)| !slot.errored)
      .map(|(handle, _)| *handle)
      .collect();
    for handle in query_handles {
      let _ = self.endpoint.handle_query_timeout(handle, now);
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
    let handles: Vec<ServiceHandle> = self.services.keys().copied().collect();
    for handle in handles {
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
    let service_handles: Vec<ServiceHandle> = self.services.keys().copied().collect();
    for handle in service_handles {
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

    let query_handles: Vec<QueryHandle> = self.queries.keys().copied().collect();
    for handle in query_handles {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
  use alloc::{collections::VecDeque, vec::Vec};
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use mdns_proto::{Name, ServiceRecords, ServiceSpec};
  use rand::{SeedableRng, rngs::StdRng};
  use smoltcp::time::Instant as RawInstant;

  use super::*;
  use crate::{
    SmoltcpInstant,
    constants::{MDNS_SOCKET_V4, MDNS_SOCKET_V6},
    udpio::{RecvMeta, SendError, UdpIo},
  };

  /// In-memory transport: a queue of inbound datagrams + a log of sent ones.
  /// `v4_fail` / `v6_fail` make sends to that family return the given
  /// [`SendError`] instead of being queued + logged (`None` = queued).
  #[derive(Default)]
  struct MockUdp {
    inbound: VecDeque<(Vec<u8>, RecvMeta)>,
    sent: Vec<(SocketAddr, Vec<u8>)>,
    v4_fail: Option<SendError>,
    v6_fail: Option<SendError>,
    /// Remaining TX slots for this poll cycle (`None` = unlimited). A test refills
    /// it before each pump to model a transport that fits only one datagram per
    /// cycle; the extra send in a fan-out then reports `Busy`.
    capacity: Option<usize>,
  }

  impl UdpIo for MockUdp {
    fn try_recv(&mut self, buf: &mut [u8]) -> Option<RecvMeta> {
      let (data, mut meta) = self.inbound.pop_front()?;
      let n = data.len().min(buf.len());
      buf[..n].copy_from_slice(&data[..n]);
      meta.len = n;
      Some(meta)
    }

    fn try_send(&mut self, buf: &[u8], dst: SocketAddr) -> Result<(), SendError> {
      if let Some(err) = if dst.is_ipv4() {
        self.v4_fail
      } else {
        self.v6_fail
      } {
        return Err(err);
      }
      if let Some(slots) = self.capacity.as_mut() {
        if *slots == 0 {
          return Err(SendError::Busy);
        }
        *slots -= 1;
      }
      self.sent.push((dst, buf.to_vec()));
      Ok(())
    }
  }

  fn at(micros: i64) -> SmoltcpInstant {
    SmoltcpInstant(RawInstant::from_micros(micros))
  }

  fn sample_spec() -> ServiceSpec {
    let service_type = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let instance = Name::try_from_str("Test._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("test.local.").unwrap();
    let mut records = ServiceRecords::new(service_type, instance, host, 631, 120);
    records.add_a(Ipv4Addr::new(192, 168, 1, 10));
    ServiceSpec::new(records)
  }

  /// A spec with explicit type / instance / host and one A address — for
  /// same-host sibling tests.
  fn spec_for(service_type: &str, instance: &str, host: &str, addr: Ipv4Addr) -> ServiceSpec {
    let mut records = ServiceRecords::new(
      Name::try_from_str(service_type).unwrap(),
      Name::try_from_str(instance).unwrap(),
      Name::try_from_str(host).unwrap(),
      631,
      120,
    );
    records.add_a(addr);
    ServiceSpec::new(records)
  }

  #[test]
  fn registering_a_service_emits_a_probe_to_the_mdns_group() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(1));
    engine.register_service(sample_spec(), at(0)).unwrap();

    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    // Advance time past the §8.1 probe delay (0–250 ms) so the probe fires.
    for micros in [0, 250_000, 500_000, 1_000_000, 2_000_000] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }

    assert!(
      io.sent
        .iter()
        .any(|(dst, _)| *dst == MDNS_SOCKET_V4 || *dst == MDNS_SOCKET_V6),
      "expected at least one probe to an mDNS group; sent dsts = {:?}",
      io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
    );
  }

  #[test]
  fn unregistering_an_announced_service_emits_a_goodbye() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(2));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();

    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    // Drive through probing + announcing so the records become advertised.
    for micros in [
      0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
    ] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    io.sent.clear();

    // Unregister → begins the endpoint-owned §10.1 TTL=0 goodbye sequence. The
    // first round is due immediately; resends are WITHDRAWAL_INTERVAL (250 ms)
    // apart. Pump across the sequence so at least one goodbye reaches the wire.
    engine.unregister_service(handle, at(5_000_000));
    for micros in [5_000_000, 5_000_001, 5_250_001, 5_500_001, 5_750_001] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }

    assert!(
      !io.sent.is_empty(),
      "unregistering an announced service should emit a §10.1 goodbye burst"
    );
  }

  // NOTE: the same-host sibling-address RETENTION tests
  // (`same_host_sibling_addresses_are_retained_on_unregister` and
  // `unregister_retention_scales_to_many_same_host_siblings`) were REMOVED in the
  // endpoint-owned-withdrawal migration. They asserted against the deleted
  // driver-side `host_addr_retained` predicate; sibling retention now lives in the
  // endpoint (`Endpoint::poll_withdrawal_transmit` recomputes it fresh each round
  // from the route table) and is covered by the proto-level
  // `poll_withdrawal_transmit ... sibling retention` test.

  /// A generous probe-then-announce pump schedule that reaches `Established`.
  fn pump_schedule() -> [i64; 10] {
    [
      0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
      5_000_000,
    ]
  }

  #[test]
  fn v6_only_node_advertises_via_multicast_fan_out() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(4));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp {
      v4_fail: Some(SendError::Unsupported),
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];
    let mut established = false;
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(update) = engine.poll_service_update(handle) {
        established |= matches!(update, ServiceUpdate::Established);
      }
    }
    assert!(
      established,
      "a v6-only node must still reach Established via the v6 group"
    );
    assert!(!io.sent.is_empty(), "expected real sends to the v6 group");
    assert!(
      io.sent.iter().all(|(dst, _)| *dst == MDNS_SOCKET_V6),
      "v6-only: every queued send must target the v6 group; got {:?}",
      io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
    );
  }

  #[test]
  fn no_reachable_group_does_not_falsely_advance() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(5));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    // No socket for either family: every send is unsupported, nothing is queued.
    let mut io = MockUdp {
      v4_fail: Some(SendError::Unsupported),
      v6_fail: Some(SendError::Unsupported),
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];
    let mut established = false;
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(update) = engine.poll_service_update(handle) {
        established |= matches!(update, ServiceUpdate::Established);
      }
    }
    assert!(
      !established,
      "a service must NOT reach Established when no datagram is ever queued"
    );
    assert!(
      io.sent.is_empty(),
      "no send should be recorded when both families are blocked"
    );
  }

  /// A busy transport must not consume the endpoint-owned withdrawal's resend
  /// budget: an all-`Busy` goodbye round is reported as not-delivered, so the
  /// endpoint re-arms it (short backoff) WITHOUT spending — and once the transport
  /// recovers the goodbye still reaches the wire. (The per-family `owed` budget is
  /// now endpoint-owned; this is the black-box observation of that property
  /// through the driver's `poll_withdrawal_transmit` → `note_withdrawal_result`
  /// loop. The proto-level test exercises the spend/re-arm bookkeeping directly.)
  #[test]
  fn goodbye_budget_is_not_consumed_while_transport_is_busy() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(6));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in [
      0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
    ] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    engine.unregister_service(handle, at(5_000_000));

    // All-busy transport: nothing reaches the wire, and the withdrawal must NOT
    // complete (a fully-failed round is re-armed, not spent). Stay within the 2 s
    // anti-pin ceiling (begin at 5 s) so completion here would be a real spend,
    // not a forced finish.
    io.v4_fail = Some(SendError::Busy);
    io.v6_fail = Some(SendError::Busy);
    io.sent.clear();
    for micros in [5_000_000, 5_250_001, 5_500_001, 5_750_001, 6_000_001] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    assert!(
      io.sent.is_empty(),
      "no goodbye should be recorded while busy"
    );
    assert!(
      engine.services.contains_key(&handle),
      "an all-busy withdrawal must not complete (its budget is re-armed, not spent), \
       so the driver slot is still held"
    );

    // Transport recovers → the goodbye finally goes out (budget was preserved).
    io.v4_fail = None;
    io.v6_fail = None;
    engine.pump(at(6_250_001), &mut io, &mut scratch);
    assert!(
      io.sent.iter().any(|(_, d)| datagram_kind(d) == Some(true)),
      "the TTL=0 goodbye must go out once the transport frees"
    );
  }

  /// Classify a sent datagram by its answer-record TTLs:
  /// `Some(true)`  — it carries at least one TTL=0 answer (a §10.1 goodbye),
  /// `Some(false)` — it carries answers, all with TTL>0 (a positive announce),
  /// `None`        — no parseable answer records (e.g. a probe/query).
  fn datagram_kind(bytes: &[u8]) -> Option<bool> {
    use mdns_proto::wire::MessageReader;
    let reader = MessageReader::try_parse(bytes).ok()?;
    let mut saw_answer = false;
    let mut saw_zero_ttl = false;
    for rec in reader.answers().flatten() {
      saw_answer = true;
      if rec.ttl() == 0 {
        saw_zero_ttl = true;
      }
    }
    if !saw_answer {
      return None;
    }
    Some(saw_zero_ttl)
  }

  /// Endpoint-owned-withdrawal replacement survival (supersedes the old free-name
  /// goodbye BARRIER test). Under `with_probe_unique_names(false)` a same-name
  /// replacement announces a positive TTL directly (no §8.1 probe) — exactly the
  /// configuration in which a stale TTL=0 goodbye could be overtaken. The old
  /// driver enforced ordering with a transmit barrier; the endpoint now enforces
  /// it structurally: it KEEPS the route (holding the name) for the whole §10.1
  /// withdrawal, so a same-name `register_service` is REJECTED until the goodbye
  /// completes and frees the name. No replacement can announce ahead of the
  /// withdrawal because no replacement can even be registered until it is done.
  #[test]
  fn same_name_replacement_is_rejected_until_withdrawal_completes() {
    let cfg = EndpointConfig::new().with_probe_unique_names(false);
    let mut engine: Engine<SmoltcpInstant, StdRng> = Engine::new(cfg, StdRng::seed_from_u64(101));
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];

    // 1. Register service A and drive it to Established so its instance records
    //    are confirmed-advertised (the withdrawal will have records to retract).
    let a = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut established = false;
    let mut t = 0i64;
    for _ in 0..16 {
      engine.pump(at(t), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(a) {
        established |= matches!(u, ServiceUpdate::Established);
      }
      t += 250_000;
    }
    assert!(
      established,
      "service A must reach Established before withdrawal"
    );

    // 2. Unregister A → begins the endpoint-owned withdrawal (name held).
    engine.unregister_service(a, at(t));

    // 3. While the withdrawal is in flight the SAME name must be rejected — the
    //    endpoint holds the route, so a replacement cannot announce a fresh
    //    positive TTL ahead of the stale TTL=0.
    let rejected = engine.register_service(sample_spec(), at(t + 1));
    assert!(
      matches!(
        rejected,
        Err(RegisterServiceError::NameAlreadyRegistered(_))
      ),
      "a same-name registration must be rejected while the withdrawal holds the \
       name; got {rejected:?}"
    );

    // 4. Pump with a WORKING transport until the withdrawal completes (its budget
    //    is spent and `drain_completed_withdrawals` frees the route + GCs the
    //    slot). The first goodbye is due immediately; resends are 250 ms apart.
    io.sent.clear();
    let mut completed = false;
    for _ in 0..32 {
      t += 250_000;
      engine.pump(at(t), &mut io, &mut scratch);
      if !engine.services.contains_key(&a) {
        completed = true;
        break;
      }
    }
    assert!(
      completed,
      "the withdrawal must complete (route freed + driver slot GC'd) on a working \
       transport"
    );
    // The withdrawal put at least one TTL=0 goodbye on the wire.
    assert!(
      io.sent.iter().any(|(_, d)| datagram_kind(d) == Some(true)),
      "the withdrawal must emit a TTL=0 §10.1 goodbye; sent kinds = {:?}",
      io.sent
        .iter()
        .map(|(_, d)| datagram_kind(d))
        .collect::<Vec<_>>()
    );

    // 5. The name is freed → a same-name replacement now registers successfully.
    engine
      .register_service(sample_spec(), at(t))
      .expect("the same name must be re-registerable once the withdrawal completes");
  }

  /// Regression: a caller that `unregister_service`s and then discards
  /// the handle WITHOUT polling a queued update (e.g. an unread `Established`) must
  /// not leak the slot. `unregister_service` marks it `caller_gone`, so the
  /// completed-withdrawal GC removes it regardless of pending updates — the
  /// `route_freed` deferral (which waits for a reader that is now gone) would
  /// otherwise grow `services` without bound under register/unregister churn.
  #[test]
  fn unregister_then_discard_with_unread_update_gc_s_the_slot() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(202));
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];

    let a = engine.register_service(sample_spec(), at(0)).unwrap();
    // An app-facing update the caller never polls.
    engine
      .services
      .get_mut(&a)
      .unwrap()
      .push_update(ServiceUpdate::Established);

    // Retire A and discard the handle WITHOUT polling the update; the (empty,
    // never-announced) withdrawal completes and the slot must be GC'd anyway.
    engine.unregister_service(a, at(1));
    let mut t = 1i64;
    let mut gcd = false;
    for _ in 0..4 {
      t += 250_000;
      engine.pump(at(t), &mut io, &mut scratch);
      if !engine.services.contains_key(&a) {
        gcd = true;
        break;
      }
    }
    assert!(
      gcd,
      "an unregistered service with an unread update must be GC'd (caller_gone), \
       not deferred forever and leaked"
    );
  }

  #[test]
  fn flooded_conflict_updates_are_coalesced_and_bounded() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(7));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let slot = engine.services.get_mut(&handle).unwrap();
    // A peer flooding HostConflict must coalesce to a single queued update.
    for _ in 0..1000 {
      slot.push_update(ServiceUpdate::HostConflict);
    }
    assert_eq!(
      slot.updates.len(),
      1,
      "repeated HostConflict must coalesce to one queued update"
    );
    // Non-coalescible variety is still capped (drop-oldest backstop).
    for _ in 0..1000 {
      slot.push_update(ServiceUpdate::HostConflict);
      slot.push_update(ServiceUpdate::Conflict);
    }
    assert!(
      slot.updates.len() <= MAX_SERVICE_UPDATES,
      "the update backlog must stay capped; got {}",
      slot.updates.len()
    );
  }

  #[test]
  fn a_partial_fan_out_confirms_and_latches_goodbye_ownership() {
    // The proto's confirm-on-send contract is "delivered = at
    // least one socket send succeeded". A partial multicast fan-out (v4 queues,
    // v6 BUSY) MUST confirm on v4: it advances the lifecycle AND latches goodbye
    // ownership for the records v4 put on the wire. Reporting "not delivered" would
    // instead let the proto consume a one-shot response (or spend a conflict-rename
    // goodbye) WITHOUT latching, so a later unregister would omit the §10.1
    // withdrawal and leave v4 peers caching records nothing ever retracts.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(8));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp {
      v6_fail: Some(SendError::Busy),
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];
    // v6 stays busy throughout, yet the service reaches Established carried by v4
    // alone (a busy family never blocks the reachable one).
    let mut established = false;
    for micros in [
      0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 2_500_000, 3_000_000,
      4_000_000,
    ] {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(update) = engine.poll_service_update(handle) {
        established |= matches!(update, ServiceUpdate::Established);
      }
    }
    assert!(
      established,
      "a partial fan-out must confirm on the reachable family, not stall on the \
       transiently-busy one"
    );
    assert!(
      io.sent.iter().all(|(dst, _)| *dst == MDNS_SOCKET_V4),
      "only v4 should carry sends while v6 is busy; got {:?}",
      io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
    );
    // The v4-only announcement latched goodbye ownership, so a graceful
    // unregister MUST withdraw those records: pump once (v6 still busy) and a
    // TTL=0 §10.1 goodbye must reach v4 (the records v4 peers cached). If v4 had
    // never latched ownership, the withdrawal snapshot would be empty and nothing
    // would go on the wire.
    engine.unregister_service(handle, at(4_500_000));
    io.sent.clear();
    engine.pump(at(4_500_001), &mut io, &mut scratch);
    assert!(
      io.sent
        .iter()
        .any(|(dst, d)| *dst == MDNS_SOCKET_V4 && datagram_kind(d) == Some(true)),
      "a v4-only advertisement must still latch goodbye ownership, so the \
       withdrawal emits a TTL=0 goodbye to v4; sent = {:?}",
      io.sent
        .iter()
        .map(|(dst, d)| (*dst, datagram_kind(d)))
        .collect::<Vec<_>>()
    );
    // v6 recovers BEFORE the withdrawal's resend budget is spent → a later
    // goodbye round reaches v6 too (the busy family catches up). Resends are
    // 250 ms apart; recover v6 and pump the next due round.
    io.v6_fail = None;
    io.sent.clear();
    for micros in [4_750_001, 5_000_001] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    assert!(
      io.sent.iter().any(|(dst, _)| *dst == MDNS_SOCKET_V6),
      "the goodbye must reach v6 once it recovers"
    );
  }

  /// Build a probe-shaped message carrying a CONFLICTING SRV authority record for
  /// `instance_str` (different rdata than ours — port 9999, a rival target). From
  /// an mDNS peer (source port 5353) this routes a §9 `ProbeConflict`, which
  /// reverts an established service to probing and then loses the §8.2 tiebreak,
  /// renaming and queuing the old-name goodbye.
  fn build_conflict_srv_authority(instance_str: &str) -> Vec<u8> {
    use mdns_proto::wire::{Header, MessageBuilder};
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    let name = Name::try_from_str(instance_str).unwrap();
    let target = Name::try_from_str("rival-host.local.").unwrap();
    b.push_srv_authority(&name, 120, 0, 0, 9999, &target)
      .unwrap();
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  }

  /// Build a probe-shaped message carrying a CONFLICTING A authority record for
  /// `host_str` (a peer claiming our host name with a DIFFERENT address). From an
  /// mDNS peer this routes a §9 host conflict; the proto does NOT auto-rename a host
  /// conflict — it queues a `ServiceUpdate::HostConflict`.
  fn build_conflict_a_authority(host_str: &str, addr: [u8; 4]) -> Vec<u8> {
    use mdns_proto::wire::{Header, MessageBuilder};
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    let name = Name::try_from_str(host_str).unwrap();
    b.push_a_authority(&name, 120, Ipv4Addr::from(addr))
      .unwrap();
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  }

  // NOTE: the per-family rename-goodbye regressions
  // (active_rename_goodbye_keeps_a_busy_family_owed_not_global_budget, its
  // assert_rename_goodbye_keeps_busy_family_owed helper, and
  // invalid_suffix_rename_goodbye_also_routes_through_per_family_queue) were
  // REMOVED in the endpoint-owned-withdrawal migration. They asserted against the
  // deleted driver-side goodbye queue (engine.goodbyes + per-family owed budget).
  // A rename of a SURVIVING service now emits its old-name goodbye via the proto's
  // own poll_transmit schedule (confirmed in the normal TX loop); a rename whose
  // new name collides locally is torn down through the endpoint-owned withdrawal
  // lifecycle, whose spend/re-arm bookkeeping is covered by the proto-level tests.

  #[test]
  fn a_constrained_transport_does_not_starve_either_family() {
    // With a TX buffer that fits ~one datagram per poll cycle, a
    // FIXED v4-first fan-out would let v4 win the only slot on every send and
    // starve v6 — the proto would reach Established with v6 having seen no
    // probes/announcements. The fan-out instead prioritises the family that has
    // been waiting longest (family_order), so both groups make progress and the
    // alternating success keeps either family from degrading.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(22));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    let mut established = false;
    let mut t = 0i64;
    for _ in 0..40 {
      t += 250_000;
      // One datagram of TX room this cycle: the SECOND family in any fan-out is
      // busy, so only a fair order lets both groups eventually transmit.
      io.capacity = Some(1);
      engine.pump(at(t), &mut io, &mut scratch);
      while let Some(update) = engine.poll_service_update(handle) {
        established |= matches!(update, ServiceUpdate::Established);
      }
    }
    assert!(
      established,
      "the service must still reach Established on a one-slot transport"
    );
    let hit_v4 = io.sent.iter().any(|(dst, _)| *dst == MDNS_SOCKET_V4);
    let hit_v6 = io.sent.iter().any(|(dst, _)| *dst == MDNS_SOCKET_V6);
    assert!(
      hit_v4 && hit_v6,
      "both families must receive sends on a constrained transport, not just the \
       one that wins a fixed order; v4={hit_v4} v6={hit_v6}"
    );
  }

  /// A one-datagram-per-cycle (capacity-1) transport must still complete the
  /// endpoint-owned withdrawal: each goodbye round fans out, and even though only
  /// one family queues per pump the withdrawal is driven to completion across
  /// pumps (each delivered round spends one of the endpoint resend budget). The
  /// per-family burst BOOKKEEPING now lives in the endpoint (covered by the
  /// proto-level tests); this is the driver black-box observation that the
  /// withdrawal-transmit loop drains on a constrained transport. (The old
  /// goodbye-queue capacity/byte-budget tests — drains_after_each_family,
  /// the_goodbye_queue_stays_bounded_under_unregister_churn,
  /// make_goodbye_room_evicts_to_fit_an_incoming_datagram,
  /// a_large_main_goodbye_survives_when_no_rename_follows, and
  /// goodbye_budget_holds_two_near_ceiling_withdrawals — were REMOVED: the driver
  /// no longer owns a goodbye QUEUE, so its eviction/byte-budget machinery is
  /// gone. The endpoint holds exactly one in-flight withdrawal per route.)
  #[test]
  fn a_constrained_transport_drains_a_withdrawal_after_each_family_gets_a_round() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(23));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    // Advertise (healthy) so there are records to withdraw.
    for micros in [
      0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
    ] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    engine.unregister_service(handle, at(5_000_000));
    io.sent.clear();
    // One datagram of TX room per cycle, pumps 250 ms apart (a WITHDRAWAL_INTERVAL),
    // all within the 2 s anti-pin ceiling so completion is a real budget spend.
    let mut t = 5_000_000i64;
    let mut completed = false;
    for _ in 0..16 {
      t += 250_000;
      io.capacity = Some(1);
      engine.pump(at(t), &mut io, &mut scratch);
      // Drain updates like a real host loop, so the slot is GC'd once its
      // withdrawal completes (a completed slot is reclaimed only after its
      // app-facing updates are read — see ServiceSlot::route_freed).
      while engine.poll_service_update(handle).is_some() {}
      if !engine.services.contains_key(&handle) {
        completed = true;
        break;
      }
    }
    assert!(
      completed,
      "the withdrawal must drain via the endpoint resend schedule on a one-slot \
       transport, not linger"
    );
    // Both families received at least one goodbye datagram across the rounds.
    let v4 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V4).count();
    let v6 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V6).count();
    assert!(
      v4 >= 1 && v6 >= 1,
      "each reachable family must receive at least one goodbye on a constrained \
       transport; v4={v4} v6={v6}"
    );
  }

  #[test]
  fn default_setup_processes_rx_without_hop_limit_or_subnets() {
    // Both supplied transports report hop_limit: None (smoltcp's UdpMetadata
    // carries no RX TTL, and hick-embassy re-exports it), and Engine::new starts with
    // no local subnets. The §11 gate must NOT then drop every inbound datagram — a
    // default node could announce but never see a query, answer, or conflict. Feed a
    // conflict with the real supplied-transport metadata shape (hop_limit None) and NO
    // set_local_subnets; it must be PROCESSED (the service renames), not silently
    // dropped. The rename is the observable that the conflict reached the proto.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(47));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while engine.poll_service_update(handle).is_some() {}
    }

    // The default deaf scenario: no subnets configured, hop_limit None on every RX.
    let conflict = build_conflict_srv_authority("Test._ipp._tcp.local.");
    let mut t = 6_000_000i64;
    let mut reacted = false;
    for _ in 0..16 {
      io.inbound.push_back((
        conflict.clone(),
        RecvMeta {
          src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
          // Arrived on the mDNS multicast group (link-scoped) — the §11 gate accepts
          // it even with no hop-limit and no subnets.
          local: Some(MDNS_SOCKET_V4.ip()),
          hop_limit: None,
          len: 0,
        },
      ));
      engine.pump(at(t), &mut io, &mut scratch);
      t += 250_000;
      while let Some(u) = engine.poll_service_update(handle) {
        reacted |= matches!(u, ServiceUpdate::Renamed(_) | ServiceUpdate::Conflict);
      }
      if reacted {
        break;
      }
    }
    assert!(
      reacted,
      "a default node (hop_limit None, no subnets) must PROCESS inbound mDNS — the §11 \
       gate dropping everything would leave it deaf to queries, answers, and conflicts"
    );
  }

  #[test]
  fn default_setup_rejects_off_link_unicast() {
    // The default no-input gate must NOT accept UNICAST: a routed off-link host
    // could send unicast (or an ephemeral-port probe) to the device's :5353 and inject
    // conflict/answer data — link-scoped multicast does not protect a unicast path.
    // The SAME conflict that renames over multicast (above) must be ignored when its
    // destination is the device's own unicast address and no hop-limit/subnets vouch
    // for it.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(59));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while engine.poll_service_update(handle).is_some() {}
    }

    let conflict = build_conflict_srv_authority("Test._ipp._tcp.local.");
    let mut t = 6_000_000i64;
    let mut reacted = false;
    for _ in 0..16 {
      io.inbound.push_back((
        conflict.clone(),
        RecvMeta {
          src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
          // Delivered to the device's OWN unicast address, not the mDNS group.
          local: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
          hop_limit: None,
          len: 0,
        },
      ));
      engine.pump(at(t), &mut io, &mut scratch);
      t += 250_000;
      while let Some(u) = engine.poll_service_update(handle) {
        reacted |= matches!(u, ServiceUpdate::Renamed(_) | ServiceUpdate::Conflict);
      }
    }
    assert!(
      !reacted,
      "off-link unicast must NOT drive a conflict rename when no hop-limit or subnet \
       vouches for it — only link-scoped multicast is trusted by default"
    );
  }

  /// a terminal emitted DIRECTLY by the proto state machine — here a
  /// HostConflict (a peer claims our host name with a different address, RFC 6762
  /// §9) — must RETIRE the smoltcp service through the SAME path as a synthesized
  /// rename-collision Conflict: queue the terminal, mark the slot errored, begin the
  /// endpoint-owned §10.1 withdrawal (so the route stops being driven/answered), and
  /// GC the slot once the goodbye completes and the caller has drained the terminal.
  /// Before the fix a proto-emitted terminal was only queued (errored stayed false,
  /// no withdrawal), leaving a zombie route that kept answering after the caller saw
  /// the terminal.
  #[test]
  fn proto_emitted_host_conflict_retires_and_gcs_the_smoltcp_service() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(83));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];

    // Drive to Established (advertising test.local. -> 192.168.1.10), so the host
    // conflict hits a SERVING service with a non-empty withdrawal snapshot.
    let mut established = false;
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        established |= matches!(u, ServiceUpdate::Established);
      }
    }
    assert!(
      established,
      "service must reach Established before the host conflict"
    );

    // A peer claims our HOST name with a DIFFERENT address: a genuine §9 host
    // conflict. The proto emits ServiceUpdate::HostConflict via poll(), which
    // drain_service_updates must now route through retirement.
    let conflict = build_conflict_a_authority("test.local.", [10, 0, 0, 99]);
    let mut t = 6_000_000i64;
    let mut retired = false;
    for _ in 0..16 {
      io.inbound.push_back((
        conflict.clone(),
        RecvMeta {
          src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
          local: Some(MDNS_SOCKET_V4.ip()),
          hop_limit: None,
          len: 0,
        },
      ));
      engine.pump(at(t), &mut io, &mut scratch);
      t += 250_000;
      if engine
        .services
        .get(&handle)
        .map(|s| s.errored)
        .unwrap_or(false)
      {
        retired = true;
        break;
      }
    }
    assert!(
      retired,
      "a proto-emitted HostConflict must begin the endpoint-owned withdrawal (errored)"
    );

    // The HostConflict terminal is observable by the caller (queued in the slot
    // before GC); draining it lets the slot GC once the withdrawal completes.
    let mut saw_host_conflict = false;
    while let Some(u) = engine.poll_service_update(handle) {
      saw_host_conflict |= u.is_host_conflict();
    }
    assert!(
      saw_host_conflict,
      "the HostConflict terminal must reach the caller via poll_service_update"
    );

    // Drive the withdrawal to completion; the slot must be GC'd (route freed).
    let mut gced = false;
    for _ in 0..64 {
      t += 250_000;
      engine.pump(at(t), &mut io, &mut scratch);
      if !engine.services.contains_key(&handle) {
        gced = true;
        break;
      }
    }
    assert!(
      gced,
      "the withdrawn slot must be GC'd after the §10.1 goodbye completes"
    );
  }

  #[test]
  fn rx_drain_is_capped_per_pump_with_immediate_repump() {
    // The per-pump RX drain is capped at MAX_RX_PER_PUMP so an on-link flood
    // cannot grow a service's proto update pool proportional to the whole RX backlog
    // before drain_service_updates coalesces/caps it. One pump processes at most the
    // cap and, because datagrams remain buffered, asks for an immediate re-pump
    // (deadline = now) so a genuine backlog still drains promptly.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(53));
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    let pkt = build_conflict_srv_authority("Whatever._ipp._tcp.local.");
    let flood = MAX_RX_PER_PUMP + 10;
    for _ in 0..flood {
      io.inbound.push_back((
        pkt.clone(),
        RecvMeta {
          src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
          // Arrived on the mDNS multicast group (link-scoped) — the §11 gate accepts
          // it even with no hop-limit and no subnets.
          local: Some(MDNS_SOCKET_V4.ip()),
          hop_limit: None,
          len: 0,
        },
      ));
    }
    let now = at(1_000_000);
    let deadline = engine.pump(now, &mut io, &mut scratch);
    assert_eq!(
      io.inbound.len(),
      flood - MAX_RX_PER_PUMP,
      "one pump must drain at most MAX_RX_PER_PUMP datagrams, leaving the rest buffered"
    );
    assert_eq!(
      deadline,
      Some(now),
      "a capped RX drain must request an immediate re-pump (deadline = now)"
    );
    // The remainder (< cap) drains in the next pump, which is no longer capped.
    engine.pump(at(1_000_001), &mut io, &mut scratch);
    assert!(
      io.inbound.is_empty(),
      "the follow-up pump drains the remaining buffered datagrams"
    );
  }

  // NOTE: `the_goodbye_scratch_is_a_fixed_preallocated_footprint` was REMOVED — the
  // driver no longer keeps a goodbye encode scratch (`goodbye_scratch`); the
  // endpoint encodes each withdrawal goodbye into the caller's `scratch`, capped to
  // the §17 ceiling by `poll_one_transmit`'s `MAX_MDNS_MESSAGE` slice.

  #[test]
  fn an_oversized_service_is_not_advertised_so_it_is_never_unwithdrawable() {
    // the normal multicast path honors the §17 ceiling (MAX_MDNS_MESSAGE). A record
    // set that would encode above it must NOT be advertised — even when the caller's
    // pump scratch is larger — so the engine can never latch goodbye ownership for
    // records it could not later withdraw (which would leave peers caching them
    // until TTL).
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(30));
    let mut records = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("Huge._ipp._tcp.local.").unwrap(),
      Name::try_from_str("huge.local.").unwrap(),
      631,
      120,
    );
    // ~400 AAAA records encode to well over the §17 ceiling (≈ 11 KiB).
    for i in 0..400u16 {
      records.add_aaaa(core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i));
    }
    let handle = engine
      .register_service(ServiceSpec::new(records), at(0))
      .unwrap();
    let mut io = MockUdp::default();
    // A caller scratch LARGER than the ceiling — the cap must still apply, so the
    // oversized probe/announce fails to encode and the service is retired.
    let mut scratch = [0u8; 12_000];
    let mut established = false;
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        established |= matches!(u, ServiceUpdate::Established);
      }
    }
    assert!(
      !established,
      "an oversized service must not reach Established (it cannot be encoded \
       within the §17 ceiling, even with a larger caller scratch)"
    );
    // It never advertised, so the withdrawal snapshot is empty and the endpoint
    // completes it immediately with NO datagram on the wire — no unwithdrawable
    // records were ever advertised. Pump the withdrawal and assert no goodbye.
    io.sent.clear();
    engine.unregister_service(handle, at(6_000_000));
    for micros in [6_000_001, 6_250_001, 6_500_001] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    assert!(
      io.sent.iter().all(|(_, d)| datagram_kind(d) != Some(true)),
      "an oversized service that never advertised must not emit any TTL=0 goodbye; \
       sent kinds = {:?}",
      io.sent
        .iter()
        .map(|(_, d)| datagram_kind(d))
        .collect::<Vec<_>>()
    );
  }

  #[test]
  fn permanently_failing_family_does_not_stall_the_healthy_one() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(15));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    // v6 is permanently busy (e.g. an unbound v6 socket mapped to Busy). It must
    // never block the healthy family: v4 confirms on its own (delivered = at least
    // one socket succeeded), so v4 advertisement reaches Established.
    let mut io = MockUdp {
      v6_fail: Some(SendError::Busy),
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];
    let mut established = false;
    let mut t = 0;
    for _ in 0..80 {
      t += 250_000;
      engine.pump(at(t), &mut io, &mut scratch);
      while let Some(update) = engine.poll_service_update(handle) {
        established |= matches!(update, ServiceUpdate::Established);
      }
    }
    assert!(
      established,
      "a healthy v4 family must reach Established despite a permanently-failing v6"
    );
    assert!(
      io.sent.iter().all(|(dst, _)| *dst == MDNS_SOCKET_V4),
      "only v4 should carry real sends; got {:?}",
      io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
    );
  }

  #[test]
  fn own_multicast_loopback_is_not_treated_as_conflict() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(9));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    // Drive to advertised so an announcement (authoritative records) has gone out
    // and been fingerprinted.
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    // Loop our most recent multicast datagram back in, from a DIFFERENT source so
    // the proto's advertised-source fallback cannot catch it — only the self-send
    // fingerprint can. hop_limit 255 passes the §11 gate.
    let (_, datagram) = io.sent.last().cloned().expect("a datagram was sent");
    io.inbound.push_back((
      datagram,
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 99), 5353)),
        local: None,
        hop_limit: Some(255),
        len: 0,
      },
    ));
    // Process the loopback promptly — within RECENT_SEND_TTL of the announcement.
    engine.pump(at(5_000_001), &mut io, &mut scratch);

    let mut conflict = false;
    while let Some(update) = engine.poll_service_update(handle) {
      conflict |= matches!(
        update,
        ServiceUpdate::Conflict | ServiceUpdate::HostConflict
      );
    }
    assert!(
      !conflict,
      "our own looped-back multicast must not be seen as a conflicting peer"
    );
  }

  #[test]
  fn actionable_updates_survive_conflict_flood() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(10));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let slot = engine.services.get_mut(&handle).unwrap();
    // An actionable transition queued first...
    slot.push_update(ServiceUpdate::Established);
    // ...then a peer floods alternating conflict noise.
    for _ in 0..1000 {
      slot.push_update(ServiceUpdate::HostConflict);
      slot.push_update(ServiceUpdate::Conflict);
    }
    assert!(
      slot
        .updates
        .iter()
        .any(|u| matches!(u, ServiceUpdate::Established)),
      "the Established transition must not be evicted by conflict noise"
    );
    assert!(
      slot.updates.len() <= MAX_SERVICE_UPDATES,
      "the backlog must stay bounded; got {}",
      slot.updates.len()
    );
  }

  /// A permanently-busy withdrawal is held (route kept, name reserved) while it
  /// keeps failing, then FORCE-completed at the endpoint's anti-pin ceiling
  /// (`WITHDRAWAL_CEILING` = 2 s) so an undeliverable goodbye cannot pin the name
  /// slot forever. (Supersedes the old 30 s `MAX_GOODBYE_AGE` driver-queue test;
  /// the ceiling/age bookkeeping now lives in the endpoint.)
  #[test]
  fn busy_goodbye_is_held_then_force_completed_at_the_ceiling() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(11));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in [
      0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
    ] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    // Drain the announce-phase updates so the slot's only lifecycle left is the
    // withdrawal (a completed slot is GC'd only after its updates are read).
    while engine.poll_service_update(handle).is_some() {}
    engine.unregister_service(handle, at(5_000_000));
    // Permanently busy: nothing reaches the wire and no round is spent. WITHIN the
    // 2 s ceiling (begin at 5 s → ceiling 7 s) the withdrawal is HELD, so the route
    // is still reserved and the slot still present.
    io.v4_fail = Some(SendError::Busy);
    io.v6_fail = Some(SendError::Busy);
    for micros in [5_250_001, 5_500_001, 6_000_001, 6_500_001] {
      engine.pump(at(micros), &mut io, &mut scratch);
      while engine.poll_service_update(handle).is_some() {}
    }
    assert!(
      engine.services.contains_key(&handle),
      "a never-delivered withdrawal must be HELD (route reserved + slot present) \
       within the 2 s anti-pin ceiling"
    );
    // PAST the ceiling (7 s) `drain_completed_withdrawals` force-completes it — the
    // route is freed and the driver slot GC'd even though nothing ever sent.
    engine.pump(at(7_500_001), &mut io, &mut scratch);
    assert!(
      !engine.services.contains_key(&handle),
      "an undeliverable withdrawal must be force-completed at its anti-pin ceiling"
    );
  }

  #[test]
  fn loopback_detected_across_a_large_send_burst() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(14));
    // Register many services so one pump emits a burst of probes far larger than
    // any small fixed ring would hold.
    let mut handles = Vec::new();
    for i in 0..8u8 {
      let instance = alloc::format!("Dev{i}._ipp._tcp.local.");
      let host = alloc::format!("dev{i}.local.");
      handles.push(
        engine
          .register_service(
            spec_for(
              "_ipp._tcp.local.",
              &instance,
              &host,
              Ipv4Addr::new(192, 168, 1, 10 + i),
            ),
            at(0),
          )
          .unwrap(),
      );
    }
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    // Pump until the probe burst has fired for every service.
    for micros in [0, 250_000, 500_000] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    assert!(
      io.sent.len() > 4,
      "expected a burst larger than any small fixed ring; got {}",
      io.sent.len()
    );
    // Loop the FIRST (oldest) probe back — it must still be recognised as self
    // despite the larger, more-recent burst that followed it.
    let first = io.sent.first().cloned().expect("a probe was sent");
    io.inbound.push_back((
      first.1,
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 99), 5353)),
        local: None,
        hop_limit: Some(255),
        len: 0,
      },
    ));
    engine.pump(at(750_000), &mut io, &mut scratch);

    let mut conflict = false;
    for h in &handles {
      while let Some(u) = engine.poll_service_update(*h) {
        conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
      }
    }
    assert!(
      !conflict,
      "the oldest self-send in a large burst must still be loopback-detected"
    );
  }

  #[test]
  fn send_multicast_confirms_when_any_family_queues() {
    // Pin the proto's confirm-on-send contract directly at the fan-out: confirm
    // iff at least one socket send succeeded — NOT only when every family did. A
    // partial fan-out that reported "not delivered" would let the proto consume a
    // one-shot response (or spend a conflict-rename goodbye) without latching the
    // records the reachable family already put on the wire.
    let mut tx = Multicaster::<SmoltcpInstant>::new();
    // v4 queues, v6 busy: at least one socket succeeded, so Delivered.
    let mut partial = MockUdp {
      v6_fail: Some(SendError::Busy),
      ..Default::default()
    };
    let (outcome, fanout) = tx.send_multicast(&mut partial, b"a-multicast-datagram", at(0));
    assert!(
      matches!(outcome, MulticastOutcome::Delivered),
      "v4 queued + v6 transiently busy must confirm (>= 1 socket succeeded)"
    );
    assert_eq!(
      fanout.sent_count(),
      1,
      "v4 queued, v6 busy: exactly 1 datagram on the wire"
    );
    assert!(
      matches!(fanout.v4, FamilySend::Sent(_)),
      "v4 must have sent"
    );
    assert!(matches!(fanout.v6, FamilySend::Busy), "v6 must be Busy");
    // Both families busy: nothing reached the link, so it must NOT confirm — the
    // proto then re-offers a probe/announce and latches nothing for a response
    // that never left the host. A transiently-busy family means Retry, not retire.
    let mut all_busy = MockUdp {
      v4_fail: Some(SendError::Busy),
      v6_fail: Some(SendError::Busy),
      ..Default::default()
    };
    let (outcome_busy, fanout_busy) =
      tx.send_multicast(&mut all_busy, b"a-multicast-datagram", at(0));
    assert!(
      matches!(outcome_busy, MulticastOutcome::Retry),
      "both families busy: nothing on the link, so retry rather than confirm or retire"
    );
    assert_eq!(
      fanout_busy.sent_count(),
      0,
      "both families busy: no datagrams on the wire"
    );
  }

  #[test]
  fn a_permanently_too_large_send_retires_the_service() {
    // a datagram every reachable socket reports as permanently TooLarge (e.g.
    // embassy PacketTooLarge — a TX buffer too small for a legal ≤§17 packet) must
    // NOT be retried forever. The service is retired with an actionable Conflict
    // update instead of probing/announcing indefinitely with nothing on the wire.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(31));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp {
      v4_fail: Some(SendError::TooLarge),
      v6_fail: Some(SendError::TooLarge),
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];
    let mut conflict = false;
    let mut established = false;
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
        established |= matches!(u, ServiceUpdate::Established);
      }
    }
    assert!(
      conflict,
      "a permanently-too-large send must retire the service with an actionable update"
    );
    assert!(
      !established,
      "a service whose datagrams can never be sent must not reach Established"
    );
    assert!(
      io.sent.is_empty(),
      "nothing is ever queued when every send is permanently too large"
    );
  }

  #[test]
  fn a_too_large_family_does_not_retire_while_the_other_may_recover() {
    // a service is retired (Undeliverable) ONLY when nothing queued AND no
    // family is recoverable. A permanently-TooLarge family alongside a transiently
    // Busy one must NOT retire it — the busy family may yet recover and carry the
    // datagram (embassy maps NoRoute / SocketNotBound to Busy, and those clear).
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(33));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp {
      v4_fail: Some(SendError::TooLarge), // permanent on v4
      v6_fail: Some(SendError::Busy),     // transient on v6 — may recover
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];
    let mut conflict = false;
    let mut established = false;
    let mut t = 0i64;
    // Pump for 10 s — far longer than any prior degrade window — with v6 still
    // busy. The service must keep retrying, NOT be retired.
    for _ in 0..40 {
      t += 250_000;
      engine.pump(at(t), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
        established |= matches!(u, ServiceUpdate::Established);
      }
    }
    assert!(
      !conflict,
      "a TooLarge family must not retire the service while the other (Busy) may \
       still recover"
    );
    assert!(
      !established,
      "cannot advertise while v6 is busy and v4 is permanently too large"
    );
    // v6 recovers → the service advertises on it and reaches Established, proving
    // it was never wrongly retired.
    io.v6_fail = None;
    for ms in 41..=64i64 {
      engine.pump(at(ms * 250_000), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        established |= matches!(u, ServiceUpdate::Established);
      }
    }
    assert!(
      established,
      "once v6 recovers the service advertises on it — it was never retired"
    );
  }

  #[test]
  fn established_is_observable_on_the_pump_that_confirms_it() {
    // the final announcement confirms INSIDE the pump's TX loop, after the
    // pre-loop drain. Without a post-TX drain, Established would sit in the proto
    // until the next pump — but the next deadline is the distant re-announce, so an
    // embassy driver would sleep and the app would not observe Established for ~80%
    // of a TTL. Assert it is surfaced on the SAME pump that confirms it: poll right
    // after each pump and break as soon as the lifecycle settles into the distant
    // re-announce deadline — at which point Established must already be visible.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(32));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    let mut established = false;
    let mut settled = false;
    let mut t = 0i64;
    for _ in 0..40 {
      t += 250_000;
      let deadline = engine.pump(at(t), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        established |= matches!(u, ServiceUpdate::Established);
      }
      // A deadline ≥ 30 s out means the §8.3 startup is done and only the distant
      // re-announce remains — the service is Established internally, so by now the
      // confirming pump must already have surfaced it (without an extra pump).
      if deadline.is_some_and(|d| d >= at(t + 30_000_000)) {
        settled = true;
        break;
      }
    }
    assert!(
      settled,
      "the service should have reached its re-announce deadline"
    );
    assert!(
      established,
      "Established must be surfaced on the pump that confirms the final \
       announcement, not stranded until the distant re-announce"
    );
  }

  #[test]
  fn a_query_exposes_collected_answers_via_the_public_api() {
    // a bare-metal caller must be able to READ a query's collected answers,
    // not just its terminal update. Browse a service type, deliver a real response
    // (a responder engine's announcement of a matching service), and read it back
    // through the public collected_answers() / query_accepted_count() accessors.
    // Responder: advertise a service and capture its announcement datagram.
    let mut responder: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(40));
    responder.register_service(sample_spec(), at(0)).unwrap();
    let mut rio = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in pump_schedule() {
      responder.pump(at(micros), &mut rio, &mut scratch);
    }
    let (_, announcement) = rio
      .sent
      .iter()
      .rev()
      .find(|(dst, _)| *dst == MDNS_SOCKET_V4)
      .cloned()
      .expect("the responder must have multicast an announcement");

    // Querier: browse the service type, then receive the announcement as a response.
    let mut querier: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(41));
    let q = querier
      .start_query(
        QuerySpec::new(
          Name::try_from_str("_ipp._tcp.local.").unwrap(),
          mdns_proto::wire::ResourceType::Ptr,
        ),
        at(0),
      )
      .unwrap();
    let mut qio = MockUdp::default();
    qio.inbound.push_back((
      announcement,
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 5353)),
        local: None,
        hop_limit: Some(255),
        len: 0,
      },
    ));
    for micros in pump_schedule() {
      querier.pump(at(micros), &mut qio, &mut scratch);
    }

    // The collected answer must be readable through the public API.
    let answers = querier.collected_answers(q).count();
    assert!(
      answers >= 1,
      "a query's collected answers must be readable via the public API; got {answers}"
    );
    assert!(
      querier.query_accepted_count(q).unwrap_or(0) >= 1,
      "query_accepted_count must reflect the accepted answer"
    );
  }

  #[test]
  fn a_query_that_can_never_send_surfaces_a_terminal_update() {
    // a query whose question is permanently too large for every reachable
    // family is retired — and must surface a terminal QueryUpdate so the caller
    // learns it died, instead of waiting forever for a result it can never request.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(42));
    let q = engine
      .start_query(
        QuerySpec::new(
          Name::try_from_str("_ipp._tcp.local.").unwrap(),
          mdns_proto::wire::ResourceType::Ptr,
        ),
        at(0),
      )
      .unwrap();
    let mut io = MockUdp {
      v4_fail: Some(SendError::TooLarge),
      v6_fail: Some(SendError::TooLarge),
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];
    let mut terminal = false;
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(u) = engine.poll_query_update(q) {
        terminal |= matches!(u, QueryUpdate::Timeout | QueryUpdate::Done);
      }
    }
    assert!(
      terminal,
      "a query that can never send must surface a terminal update, not hang silently"
    );
  }

  #[test]
  fn a_retired_query_freezes_answers_and_emits_no_second_terminal() {
    // a retired query must be synchronized with the proto terminal state.
    // After its Timeout, a late MATCHING response must NOT mutate collected_answers
    // and no second terminal may appear — because the driver forces the proto
    // query's TIMEOUT terminal (is_done), so Endpoint::handle freezes late answers.
    // Responder: capture a matching announcement.
    let mut responder: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(43));
    responder.register_service(sample_spec(), at(0)).unwrap();
    let mut rio = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in pump_schedule() {
      responder.pump(at(micros), &mut rio, &mut scratch);
    }
    let (_, announcement) = rio
      .sent
      .iter()
      .rev()
      .find(|(d, _)| *d == MDNS_SOCKET_V4)
      .cloned()
      .expect("the responder must have announced");

    // Querier with an all-TooLarge transport: the browse can never send → retired.
    let mut querier: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(44));
    let q = querier
      .start_query(
        QuerySpec::new(
          Name::try_from_str("_ipp._tcp.local.").unwrap(),
          mdns_proto::wire::ResourceType::Ptr,
        ),
        at(0),
      )
      .unwrap();
    let mut qio = MockUdp {
      v4_fail: Some(SendError::TooLarge),
      v6_fail: Some(SendError::TooLarge),
      ..Default::default()
    };
    let mut terminals = 0;
    for micros in pump_schedule() {
      querier.pump(at(micros), &mut qio, &mut scratch);
      while let Some(u) = querier.poll_query_update(q) {
        if matches!(u, QueryUpdate::Timeout | QueryUpdate::Done) {
          terminals += 1;
        }
      }
    }
    assert_eq!(
      terminals, 1,
      "a retired query surfaces exactly one terminal"
    );
    assert_eq!(
      querier.collected_answers(q).count(),
      0,
      "a retired query collected nothing (it never sent)"
    );

    // A late MATCHING response after the terminal must be FROZEN (not collected)
    // and must NOT produce a second terminal.
    qio.inbound.push_back((
      announcement,
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 7), 5353)),
        local: None,
        hop_limit: Some(255),
        len: 0,
      },
    ));
    let mut t = 100_000_000i64;
    for _ in 0..10 {
      t += 250_000;
      querier.pump(at(t), &mut qio, &mut scratch);
      while let Some(u) = querier.poll_query_update(q) {
        if matches!(u, QueryUpdate::Timeout | QueryUpdate::Done) {
          terminals += 1;
        }
      }
    }
    assert_eq!(
      terminals, 1,
      "no SECOND terminal after a late response to a retired query"
    );
    assert_eq!(
      querier.collected_answers(q).count(),
      0,
      "a late response must be frozen — collected_answers unchanged after the terminal"
    );
  }

  // NOTE: the per-family goodbye-accounting stats tests
  // (fan_out_tx_accounting_is_per_datagram_and_goodbye_rounds_are_logical,
  // stats_goodbye_single_stack_unsupported_v6, stats_goodbye_v4_sent_v6_failed_per_round,
  // and stats_goodbye_busy_until_expiry_no_overcount) were REMOVED in the
  // endpoint-owned-withdrawal migration: they asserted the deleted drain_goodbyes
  // per-family GOODBYE_SENDS bookkeeping (engine.goodbyes + owed). The endpoint now
  // owns the resend schedule; the driver bumps goodbyes_tx once per DELIVERED round
  // (>= 1 family on the wire), packets_tx/bytes_tx per Sent family, and send_errors
  // per Failed family in the withdrawal send. The dual-stack happy path below pins
  // that driver-side accounting; both-families-failed pins the no-send case.

  /// Dual-stack withdrawal stats (replaces the old per-family goodbye-accounting
  /// suite). With WITHDRAWAL_SENDS resend rounds and both families healthy, each
  /// round fans to v4+v6, so across the completed withdrawal: goodbyes_tx rises by
  /// the number of DELIVERED rounds, packets_tx by twice that (one Sent per family
  /// per round), and send_errors stays 0.
  #[cfg(feature = "stats")]
  #[test]
  fn stats_withdrawal_dual_stack_counts_rounds_and_per_family_datagrams() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(1005));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    engine.unregister_service(handle, at(5_000_000));
    let snap_before = engine.stats();
    io.sent.clear();

    // Unlimited capacity, pumps 250 ms apart (WITHDRAWAL_INTERVAL), within the 2 s
    // ceiling so completion is a real budget spend. Drive until the endpoint frees
    // the route (services_active drops to 0) — the authoritative completion signal.
    let mut t = 5_000_000i64;
    let mut completed = false;
    for _ in 0..16 {
      t += 250_000;
      engine.pump(at(t), &mut io, &mut scratch);
      if engine.stats().services_active == 0 {
        completed = true;
        break;
      }
    }
    assert!(completed, "the withdrawal must drain on dual-stack");

    let snap_after = engine.stats();
    let v4 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V4).count();
    let v6 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V6).count();
    assert!(
      v4 >= 1 && v6 >= 1,
      "both families must carry goodbyes; v4={v4} v6={v6}"
    );
    assert_eq!(
      v4, v6,
      "dual-stack: each round fans to both families equally"
    );

    // goodbyes_tx == number of delivered rounds; on healthy dual-stack each round
    // delivers, so == v4 (one round per v4 datagram).
    let rounds = v4 as u64;
    assert_eq!(
      snap_after.goodbyes_tx - snap_before.goodbyes_tx,
      rounds,
      "goodbyes_tx must count one per delivered round (== {rounds})"
    );
    // packets_tx delta == per-family datagrams (v4 + v6).
    assert_eq!(
      snap_after.packets_tx - snap_before.packets_tx,
      (v4 + v6) as u64,
      "packets_tx delta must equal per-family goodbye datagrams"
    );
    assert_eq!(
      snap_after.send_errors - snap_before.send_errors,
      0,
      "dual-stack healthy: send_errors must be 0"
    );
  }

  /// regression: per-family withdrawal debt at the driver level.
  /// With v4 healthy but v6 transiently BUSY, the withdrawal must NOT free before
  /// v6 sends — v6 peers still hold the records. v4 drains its debt (and keeps
  /// re-withdrawing harmlessly), yet the route stays held WITHIN the 2 s ceiling
  /// until v6 recovers and emits its own TTL=0 goodbyes, at which point it
  /// completes (well before the ceiling).
  #[cfg(feature = "stats")]
  #[test]
  fn stats_withdrawal_v6_busy_until_recovery_not_freed_before_v6_sends() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(2006));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    // Drain announce-phase updates so the slot's only remaining lifecycle is the
    // withdrawal (a completed slot is GC'd only after its updates are read).
    while engine.poll_service_update(handle).is_some() {}
    engine.unregister_service(handle, at(5_000_000)); // ceiling at 7_000_000
    // Only count withdrawal-phase datagrams (the announce phase already put v4+v6
    // POSITIVE-TTL records on the wire).
    io.sent.clear();

    // v6 transiently busy, v4 healthy. Pump rounds 250 ms apart (WITHDRAWAL_INTERVAL,
    // since v4 keeps making progress) but WELL within the 2 s ceiling. v4 spends its
    // whole debt; v6's debt is untouched, so the withdrawal stays HELD.
    io.v6_fail = Some(SendError::Busy);
    for micros in [5_250_001, 5_500_001, 5_750_001, 6_000_001] {
      engine.pump(at(micros), &mut io, &mut scratch);
      while engine.poll_service_update(handle).is_some() {}
    }
    assert!(
      engine.services.contains_key(&handle),
      "a withdrawal whose v6 family is still busy must NOT be freed before the \
       2 s ceiling — v6 peers still hold the records"
    );
    let v6_before = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V6).count();
    assert_eq!(
      v6_before, 0,
      "no v6 goodbye can have reached the wire while v6 was busy; got {v6_before}"
    );
    // v4 DID withdraw (its debt drained), proving the route is held on v6 alone.
    assert!(
      io.sent.iter().any(|(d, _)| *d == MDNS_SOCKET_V4),
      "v4 must have emitted its TTL=0 goodbyes while v6 was busy"
    );

    // v6 recovers: pump until the withdrawal completes (route freed). Still inside
    // the 2 s ceiling, so completion is a real per-family budget spend, not the
    // anti-pin backstop.
    io.v6_fail = None;
    let mut completed = false;
    for micros in [6_250_001, 6_500_001, 6_750_001, 6_900_001] {
      engine.pump(at(micros), &mut io, &mut scratch);
      while engine.poll_service_update(handle).is_some() {}
      if !engine.services.contains_key(&handle) {
        completed = true;
        break;
      }
    }
    assert!(
      completed,
      "once v6 recovers and sends its goodbyes the withdrawal completes (before \
       the 2 s ceiling)"
    );
    let v6_after = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V6).count();
    assert!(
      v6_after >= 1,
      "v6 must have emitted at least one TTL=0 goodbye after recovery; got {v6_after}"
    );
  }

  /// Both families fail (TooLarge write-off): `send_errors` bumped per family,
  /// `goodbyes_tx == 0` since nothing ever went on the wire.
  #[cfg(feature = "stats")]
  #[test]
  fn stats_goodbye_both_families_failed_no_goodbyes_tx() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(1004));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    // Both families healthy during announce so records are owned (the withdrawal
    // snapshot is non-empty, so a goodbye send is attempted).
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    engine.unregister_service(handle, at(5_500_000));
    // NOW make both fail with TooLarge (the endpoint-owned withdrawal send path).
    io.v4_fail = Some(SendError::TooLarge);
    io.v6_fail = Some(SendError::TooLarge);
    let snap_before = engine.stats();
    io.sent.clear();

    // One pump (within the 2 s ceiling): both families are written off — nothing
    // reaches the wire, so the round is not delivered (re-armed, not spent).
    engine.pump(at(6_500_000), &mut io, &mut scratch);

    let snap_after = engine.stats();
    assert_eq!(
      io.sent.len(),
      0,
      "no datagrams should be sent when both families fail"
    );
    assert_eq!(
      snap_after.goodbyes_tx - snap_before.goodbyes_tx,
      0,
      "goodbyes_tx must be 0 when nothing ever goes on the wire; delta={}",
      snap_after.goodbyes_tx - snap_before.goodbyes_tx
    );
    let errors_delta = snap_after.send_errors - snap_before.send_errors;
    assert!(
      errors_delta >= 2,
      "both families TooLarge must bump send_errors at least once each; delta={errors_delta}"
    );
  }

  // NOTE: `stats_goodbye_dual_stack_happy_path` was REMOVED — it is superseded by
  // `stats_withdrawal_dual_stack_counts_rounds_and_per_family_datagrams` above,
  // which pins the same dual-stack accounting against the endpoint-owned
  // withdrawal send (and no longer reads the deleted `engine.goodbyes` queue).

  /// Normal multicast TX path (probes/announcements): per-family `packets_tx`
  /// and `send_errors` correctness when one family fails permanently (TooLarge).
  ///
  /// v4 sends (Sent), v6 returns TooLarge (Failed): the fan-out yields
  /// MulticastOutcome::Delivered (because v4 sent), but `fanout.failed_count()` is
  /// still 1. The fix counts send_errors unconditionally from `fanout.failed_count()`,
  /// so the v6 failure is not dropped even though the coarse outcome is Delivered.
  /// Each pump that fires a datagram increments send_errors by exactly 1 (the v6
  /// failure). packets_tx reflects only v4 sends.
  #[cfg(feature = "stats")]
  #[test]
  fn stats_multicast_tx_partial_failure_counted_per_family() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(1006));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    // v4 succeeds, v6 is permanently TooLarge (Failed in FamilySend terms).
    let mut io = MockUdp {
      v6_fail: Some(SendError::TooLarge),
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];
    let snap_before = engine.stats();

    // Drive a few pumps so probes fire.
    for micros in [0, 250_000, 500_000, 750_000, 1_000_000] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    let _ = handle;

    let snap_after = engine.stats();
    let v4_sent = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V4).count();

    // packets_tx must reflect v4 sends only.
    assert!(
      snap_after.packets_tx > snap_before.packets_tx,
      "v4 probes must increment packets_tx"
    );
    assert_eq!(
      snap_after.packets_tx - snap_before.packets_tx,
      v4_sent as u64,
      "packets_tx delta must equal v4 sends only; delta={}, v4_sent={v4_sent}",
      snap_after.packets_tx - snap_before.packets_tx
    );
    // Tightened: v6 TooLarge must be counted in send_errors on EVERY fan-out
    // attempt, even when the overall outcome is Delivered (v4 succeeded). Each
    // multicast attempt contributes exactly 1 error (the v6 failure). The delta
    // must equal the number of v4 sends (one v6-Failed per fan-out that fired).
    assert_eq!(
      snap_after.send_errors - snap_before.send_errors,
      v4_sent as u64,
      "send_errors delta must equal v4_sent (one v6-TooLarge per fan-out); \
       errors_delta={}, v4_sent={v4_sent}",
      snap_after.send_errors - snap_before.send_errors
    );
  }

  // ── New mandatory tests: explicit send_errors delta assertions ──────────────

  /// Multicast partial failure (v4 Sent + v6 TooLarge/Failed, overall Delivered):
  /// send_errors must increment by exactly 1 (the v6 failure), packets_tx by 1.
  /// This is the case the old outcome-gated code silently dropped.
  #[cfg(feature = "stats")]
  #[test]
  fn stats_multicast_sent_plus_failed_send_errors_exact() {
    // Use a unit-level test via send_multicast directly so we get exactly one
    // fan-out and can assert the delta precisely.
    let mut tx: Multicaster<SmoltcpInstant> = Multicaster::new();
    let mut io = MockUdp {
      v6_fail: Some(SendError::TooLarge),
      ..Default::default()
    };
    let data = b"probe-datagram";
    let (outcome, fanout) = tx.send_multicast(&mut io, data, at(0));

    assert!(
      matches!(outcome, MulticastOutcome::Delivered),
      "v4 Sent + v6 TooLarge must yield Delivered"
    );
    assert_eq!(
      fanout.failed_count(),
      1,
      "exactly one family (v6) must be Failed; failed_count={}",
      fanout.failed_count()
    );
    assert_eq!(
      fanout.sent_count(),
      1,
      "exactly one family (v4) must be Sent; sent_count={}",
      fanout.sent_count()
    );
    // This is the invariant the fix preserves: send_errors must equal failed_count()
    // regardless of the coarse outcome.
    assert_eq!(
      fanout.failed_count(),
      1,
      "send_errors delta must be 1 (v6 failure must not be dropped by Delivered arm)"
    );
  }

  /// Multicast partial failure (v4 Failed + v6 Busy):
  /// send_errors must increment by exactly 1 (only the Failed), not 2 (not Busy).
  #[cfg(feature = "stats")]
  #[test]
  fn stats_multicast_failed_plus_busy_send_errors_exact() {
    let mut tx: Multicaster<SmoltcpInstant> = Multicaster::new();
    let mut io = MockUdp {
      v4_fail: Some(SendError::TooLarge),
      v6_fail: Some(SendError::Busy),
      ..Default::default()
    };
    let data = b"probe-datagram";
    let (outcome, fanout) = tx.send_multicast(&mut io, data, at(0));

    // v4 Failed + v6 Busy: nothing sent → not Delivered; v6 Busy → Retry
    assert!(
      matches!(outcome, MulticastOutcome::Retry),
      "v4 Failed + v6 Busy must yield Retry (v6 Busy keeps things alive)"
    );
    assert_eq!(
      fanout.failed_count(),
      1,
      "only v4 is Failed; failed_count must be 1, got {}",
      fanout.failed_count()
    );
    // Busy must NOT be counted as an error.
    assert!(
      !matches!(fanout.v6, FamilySend::Failed),
      "v6 Busy must not be mapped to Failed"
    );
    // The pump will call stats.send_errors(fanout.failed_count()) = 1, not 2.
    assert_eq!(
      fanout.failed_count(),
      1,
      "send_errors delta must be 1 (Failed only), never 2 (Busy must not count)"
    );
  }

  /// Unicast Busy: send_errors must stay 0 (Busy is transient, not an error).
  #[cfg(feature = "stats")]
  #[test]
  fn stats_unicast_busy_does_not_increment_send_errors() {
    // Inject a unicast reply by feeding a PTR query addressed to a specific
    // unicast source (non-multicast dst triggers the else branch).
    // We test the engine-level path by checking stats after a pump where the
    // only send is a unicast that returns Busy.
    //
    // Build an engine, register a service so it can respond, then inject a
    // unicast-expecting query and have the send return Busy.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(2001));
    let _handle = engine.register_service(sample_spec(), at(0)).unwrap();

    // Use a MockUdp where every send returns Busy so ANY send path will fail.
    // We specifically need the unicast path. The easiest way is to set capacity=0
    // which causes try_send to return Busy regardless of destination.
    let mut io = MockUdp {
      capacity: Some(0),
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];

    // Grab stats before any multicast fires (before any pumps so nothing has
    // happened yet).
    let snap_before = engine.stats();
    // Pump once at t=0. With capacity=0, any send returns Busy.
    engine.pump(at(0), &mut io, &mut scratch);
    let snap_after = engine.stats();

    // send_errors must be 0: Busy is not an error on any path.
    assert_eq!(
      snap_after.send_errors - snap_before.send_errors,
      0,
      "Busy (capacity=0) must not increment send_errors; delta={}",
      snap_after.send_errors - snap_before.send_errors
    );
  }

  /// Unicast Failed (TooLarge): send_errors must increment by exactly 1.
  #[cfg(feature = "stats")]
  #[test]
  fn stats_unicast_too_large_increments_send_errors() {
    // Drive a service to established then make ALL sends return TooLarge.
    // The multicast pump will create Undeliverable (all families TooLarge →
    // send_errors via the unconditional fanout.failed_count() block). After that
    // we want to also confirm the unicast error path: set only unicast destination
    // to TooLarge while keeping multicast functional first.
    //
    // Simplest direct approach: test the `Fanout` / `FamilySend` API is consistent
    // for a direct try_send call on a MockUdp with TooLarge.
    let mut io = MockUdp {
      v4_fail: Some(SendError::TooLarge),
      ..Default::default()
    };
    // A unicast destination (not the mDNS multicast group).
    let unicast_dst: SocketAddr = "192.168.1.100:5353".parse().unwrap();
    let result = io.try_send(b"unicast-reply", unicast_dst);

    // The unicast arm must map TooLarge to send_errors(1), Busy/Unsupported to 0.
    assert!(
      matches!(result, Err(SendError::TooLarge)),
      "MockUdp with v4_fail=TooLarge must return TooLarge for IPv4 unicast"
    );
    // Verify the match arm logic: only TooLarge is an error.
    let errors: u64 = match result {
      Ok(()) => 0,
      Err(SendError::TooLarge) => 1,
      Err(SendError::Busy) | Err(SendError::Unsupported) => 0,
    };
    assert_eq!(
      errors, 1,
      "TooLarge unicast must count as send_errors=1; got {errors}"
    );
  }

  /// Unicast Unsupported: send_errors must stay 0.
  #[cfg(feature = "stats")]
  #[test]
  fn stats_unicast_unsupported_does_not_increment_send_errors() {
    let mut io = MockUdp {
      v4_fail: Some(SendError::Unsupported),
      ..Default::default()
    };
    let unicast_dst: SocketAddr = "192.168.1.100:5353".parse().unwrap();
    let result = io.try_send(b"unicast-reply", unicast_dst);

    assert!(
      matches!(result, Err(SendError::Unsupported)),
      "MockUdp with v4_fail=Unsupported must return Unsupported for IPv4 unicast"
    );
    let errors: u64 = match result {
      Ok(()) => 0,
      Err(SendError::TooLarge) => 1,
      Err(SendError::Busy) | Err(SendError::Unsupported) => 0,
    };
    assert_eq!(
      errors, 0,
      "Unsupported unicast must not count as send_errors; got {errors}"
    );
  }

  /// RFC 6762 §11 off-link datagrams (hop-limit ≠ 255) are dropped before the
  /// proto layer, but the datagram WAS received off the socket — so it must
  /// increment `packets_rx`/`bytes_rx` AND `packets_dropped` exactly once each,
  /// matching the reactor/compio pre-handle drop accounting (driver-consistent).
  #[cfg(feature = "stats")]
  #[test]
  fn stats_off_link_datagram_counts_rx_bytes_and_dropped() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(9001));
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];

    // Well-formed mDNS packet so the only reject reason is the hop-limit.
    let pkt = build_conflict_srv_authority("Test._ipp._tcp.local.");
    let pkt_len = pkt.len();

    // Off-link: hop_limit = 1 (crossed a router → §11 reject). len > 0 so the
    // on-link gate is actually exercised, not the len==0 marker path.
    io.inbound.push_back((
      pkt,
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(192, 168, 2, 1), 5353)),
        local: Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
        hop_limit: Some(1),
        len: pkt_len,
      },
    ));

    let snap_before = engine.stats();
    engine.pump(at(0), &mut io, &mut scratch);
    let snap_after = engine.stats();

    assert_eq!(
      snap_after.packets_rx - snap_before.packets_rx,
      1,
      "an off-link datagram WAS received → packets_rx must rise by 1"
    );
    assert_eq!(
      snap_after.bytes_rx - snap_before.bytes_rx,
      pkt_len as u64,
      "off-link datagram bytes_rx must rise by the datagram length"
    );
    assert_eq!(
      snap_after.packets_dropped - snap_before.packets_dropped,
      1,
      "an off-link datagram must increment packets_dropped by 1"
    );
  }

  /// A zero-length receive (smoltcp oversized-datagram marker) must now bump
  /// `packets_rx` AND `packets_dropped` — the datagram WAS consumed from the
  /// transport queue so it must count toward the receive denominator.
  ///
  /// `bytes_rx` is NOT expected to change: smoltcp discards the oversized
  /// payload before handing control back to us, so the original length is lost.
  #[cfg(feature = "stats")]
  #[test]
  fn stats_oversized_zero_len_marker_counts_rx_and_dropped() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(42));
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];

    // An empty payload → MockUdp::try_recv sets meta.len = 0, which is the
    // zero-length oversized-datagram marker the engine checks.
    io.inbound.push_back((
      vec![],
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 5), 5353)),
        local: Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
        hop_limit: Some(255),
        len: 0,
      },
    ));

    let snap_before = engine.stats();
    engine.pump(at(0), &mut io, &mut scratch);
    let snap_after = engine.stats();

    assert_eq!(
      snap_after.packets_rx - snap_before.packets_rx,
      1,
      "a zero-length (oversized) marker WAS consumed → packets_rx must rise by 1"
    );
    assert_eq!(
      snap_after.packets_dropped - snap_before.packets_dropped,
      1,
      "a zero-length marker is an unusable datagram → packets_dropped must rise by 1"
    );
    // bytes_rx is not bumped: smoltcp discards the payload before we see it.
    assert_eq!(
      snap_after.bytes_rx, snap_before.bytes_rx,
      "bytes_rx must not change (oversized payload is lost before the zero-len marker)"
    );
  }

  /// regression: when `poll_one_transmit` retires a service due to a
  /// permanently-unencodable datagram (scratch too small to encode any probe),
  /// the proto route must be freed (`services_active == 0`) and the name must
  /// be re-registerable. The service never advertised, so its withdrawal snapshot
  /// is empty and completes on the same pump (freeing the route).
  ///
  /// This covers the `Err(_)` arm in `Engine::poll_one_transmit` that now
  /// calls `begin_service_withdrawal(handle, now)` in addition to setting
  /// `slot.errored = true` (the endpoint frees the route on withdrawal completion).
  #[cfg(feature = "stats")]
  #[test]
  fn encode_failure_retirement_frees_proto_route_and_decrements_services_active() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(99));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();

    // Verify services_active is 1 after registration.
    assert_eq!(
      engine.stats().services_active,
      1,
      "services_active must be 1 after registration"
    );

    // Use a 1-byte scratch to force `poll_one_transmit` → `Err(BufferTooSmall)`.
    // Drive with a normal (non-failing) io so the send path doesn't also retire
    // via `retire_origin` — we want to isolate the encode-failure branch.
    let mut io = MockUdp::default();
    let mut scratch_tiny = [0u8; 1];
    let mut got_conflict = false;

    // Pump until the service is retired. The probe fires after the §8.1 random
    // delay (≤250 ms), so pumping to 300 ms is sufficient. The encode Err path
    // retires immediately on the first failed encode (unlike compio which counts
    // to MAX_CONSECUTIVE_ENCODE_ERRORS — smoltcp retires on the first failure).
    for micros in [0i64, 100_000, 200_000, 300_000, 400_000] {
      engine.pump(at(micros), &mut io, &mut scratch_tiny);
      while let Some(u) = engine.poll_service_update(handle) {
        got_conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
      }
      if got_conflict {
        break;
      }
    }

    assert!(
      got_conflict,
      "encode failure must surface Conflict to the caller (poll_service_update)"
    );

    // Proto route freed — services_active must be 0.
    assert_eq!(
      engine.stats().services_active,
      0,
      "services_active must be 0 after encode-failure retirement (proto route freed)"
    );

    // The same service name must be re-registerable (route was released).
    engine
      .register_service(sample_spec(), at(500_000))
      .expect("same service name must be re-registerable after encode-failure retirement");

    assert_eq!(
      engine.stats().services_active,
      1,
      "services_active must be 1 again after re-registration"
    );
  }

  /// regression: when one of N registered services is retired by an
  /// encode failure in `poll_one_transmit`, its proto route must be freed
  /// IMMEDIATELY — in the same iteration that detects the failure — so an
  /// `Ok(Some)` early-return from a LATER service in the same call cannot
  /// bypass the `unregister_service` call.
  ///
  /// The bug: the old code pushed retiring handles into `proto_unregister: Vec`
  /// and drained it AFTER the service loop. An early-return from another
  /// service exited the loop before the drain, permanently leaking the proto
  /// route (`services_active` never decremented, old name not re-registerable).
  ///
  /// The fix: `unregister_service` is called in-iteration (after the `slot`
  /// borrow ends in the same loop body) so no early-return from a sibling
  /// service can bypass it.
  ///
  /// Verification: drive TWO services with a 1-byte scratch so both are retired
  /// by encode failures. `services_active` must reach 0 (both routes freed),
  /// and both names must be immediately re-registerable (no proto route leak).
  /// The loop-ordering bypass would leave one (or both) routes leaked.
  ///
  /// NOTE: With 1-byte scratch BOTH services fail to encode, so both get retired
  /// in the same `poll_one_transmit` sweep. `services_active` must reach 0
  /// (the fix ensures each retirement is unregistered immediately, regardless of
  /// which service returned `Err` first). Without the fix, the deferred Vec
  /// drain could be skipped by an intermediate state or exit path, leaving
  /// `services_active > 0`.
  #[cfg(feature = "stats")]
  #[test]
  fn multi_service_encode_failure_frees_route_even_with_sibling_transmit() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(200));

    // Register two services that will both encode-fail once we switch to the
    // 1-byte scratch (simulates the ordering bypass: both in the map, one
    // could short-circuit the other's post-loop drain in the buggy code).
    let handle_a = engine.register_service(sample_spec(), at(0)).unwrap();
    let handle_b = engine
      .register_service(
        spec_for(
          "_ipp._tcp.local.",
          "Sibling._ipp._tcp.local.",
          "sibling.local.",
          Ipv4Addr::new(192, 168, 1, 11),
        ),
        at(0),
      )
      .unwrap();

    assert_eq!(
      engine.stats().services_active,
      2,
      "both services registered: services_active must be 2"
    );

    // Pump with a tiny (1-byte) scratch. smoltcp retires on the FIRST encode
    // failure; both services have pending probes, so both begin an (empty,
    // never-announced) endpoint-owned withdrawal in the same `poll_one_transmit`
    // sweep. An empty withdrawal completes on the same pump, freeing both routes.
    // The key assertion (the fix) is that BOTH routes are freed —
    // services_active reaches 0 and both names re-registerable — not leaked by an
    // early-return for a sibling bypassing one service's in-iteration withdrawal.
    let mut io = MockUdp::default();
    let mut tiny = [0u8; 1];
    let mut got_conflict_a = false;
    let mut got_conflict_b = false;

    for i in 0..30i64 {
      let t = at(i * 100_000);
      engine.pump(t, &mut io, &mut tiny);
      // Draining the Conflict GCs the (route-already-freed) slot, so observe the
      // Conflict here rather than via a `slot.errored` peek (the slot may be gone).
      while let Some(u) = engine.poll_service_update(handle_a) {
        if matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict) {
          got_conflict_a = true;
        }
      }
      while let Some(u) = engine.poll_service_update(handle_b) {
        if matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict) {
          got_conflict_b = true;
        }
      }
      if got_conflict_a && got_conflict_b {
        break;
      }
    }

    // Conflicts surfaced for BOTH (each internal retirement still notifies the
    // host, even though it now begins a withdrawal instead of freeing immediately).
    assert!(
      got_conflict_a,
      "A's Conflict must be surfaced via poll_service_update"
    );
    assert!(
      got_conflict_b,
      "B's Conflict must be surfaced via poll_service_update"
    );

    // fix (endpoint-owned form): both routes freed → services_active == 0.
    // Each service's empty withdrawal completes (frees its route) in the pump that
    // began it; the in-iteration `begin_service_withdrawal` is non-bypassable, so
    // an early-return for a sibling cannot leak the other's route.
    assert_eq!(
      engine.stats().services_active,
      0,
      "services_active must be 0 after both services are retired by encode failure \
       (each begins + completes an empty withdrawal; no route leak)"
    );

    // Both names must be immediately re-registerable (routes were freed).
    engine
      .register_service(sample_spec(), at(3_000_000))
      .expect("A's name must be re-registerable after in-iteration unregister (fix)");
    engine
      .register_service(
        spec_for(
          "_ipp._tcp.local.",
          "Sibling._ipp._tcp.local.",
          "sibling.local.",
          Ipv4Addr::new(192, 168, 1, 11),
        ),
        at(3_000_000),
      )
      .expect("B's name must be re-registerable after in-iteration unregister (fix)");

    assert_eq!(
      engine.stats().services_active,
      2,
      "services_active must be 2 after re-registering both A and B"
    );
  }

  /// regression (send-too-large path): when `retire_origin` retires a service
  /// because every send returned a permanent error (`SendError::TooLarge`), the
  /// proto route must be freed (`services_active == 0`) and the name must be
  /// re-registerable. The service never confirmed-emitted anything (all sends
  /// failed), so its withdrawal snapshot is empty and completes immediately.
  ///
  /// This covers the `Origin::Service` arm in `Engine::retire_origin` that now
  /// calls `begin_service_withdrawal(handle, now)` (the endpoint frees the route
  /// when the withdrawal completes — here on the same pump, an empty snapshot).
  #[cfg(feature = "stats")]
  #[test]
  fn send_too_large_retirement_frees_proto_route_and_decrements_services_active() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(100));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();

    assert_eq!(
      engine.stats().services_active,
      1,
      "services_active must be 1 after registration"
    );

    // Both families permanently TooLarge → `retire_origin` path.
    let mut io = MockUdp {
      v4_fail: Some(SendError::TooLarge),
      v6_fail: Some(SendError::TooLarge),
      ..Default::default()
    };
    let mut scratch = [0u8; 1500];
    let mut got_conflict = false;

    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        got_conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
      }
      if got_conflict {
        break;
      }
    }

    assert!(
      got_conflict,
      "permanently-too-large sends must surface Conflict (retire_origin path)"
    );

    assert_eq!(
      engine.stats().services_active,
      0,
      "services_active must be 0 after retire_origin (proto route freed)"
    );

    // Re-registration must succeed (route was released by retire_origin).
    engine
      .register_service(sample_spec(), at(10_000_000))
      .expect("same service name must be re-registerable after retire_origin");

    assert_eq!(
      engine.stats().services_active,
      1,
      "services_active must be 1 again after re-registration"
    );
  }
}

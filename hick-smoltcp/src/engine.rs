//! The runtime-agnostic mDNS engine: a synchronous *pump* that drives the
//! [`mdns_proto::Endpoint`] (plus the per-service / per-query state machines it
//! hands back) over a [`UdpIo`] transport.
//!
//! A driver (e.g. `hick-embassy`, or a bare poll loop) calls [`Engine::pump`]
//! whenever a packet arrives or a timer fires, sends nothing itself, and reads
//! back the next deadline to sleep until.

use alloc::{
  collections::{BTreeMap, VecDeque},
  vec::Vec,
};
use core::{net::SocketAddr, time::Duration};

use mdns_proto::{
  CollectedAnswer, EndpointConfig, Instant, QueryHandle, QuerySpec, ServiceHandle, ServiceSpec,
  cache::CacheEntry,
  endpoint::{Endpoint, EndpointEventEntry, ServiceRoute},
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

/// RFC 6762 §10.1: repeat the TTL=0 goodbye a few times to improve delivery.
const GOODBYE_SENDS: u8 = 2;
/// Spacing between goodbye repeats.
const GOODBYE_INTERVAL: Duration = Duration::from_secs(1);
/// RFC 6762 §17 single-message ceiling — the size of the reusable goodbye encode
/// scratch, so a service announced with a large record set is still withdrawn
/// rather than silently dropped.
const MAX_MDNS_MESSAGE: usize = 9000;
/// How long a queued goodbye keeps retrying before it is given up — bounds the
/// lifetime of an undeliverable withdrawal WITHOUT dropping a transiently-busy
/// one before it can send (a permanently-unroutable transport means the node is
/// effectively offline and the records expire by TTL anyway).
const MAX_GOODBYE_AGE: Duration = Duration::from_secs(30);
/// Max pending goodbyes retained at once. With `MAX_GOODBYE_BYTES` this bounds
/// the backlog under unregister churn: the age bound only caps an entry's
/// lifetime once `drain_goodbyes` runs, so a burst of register/unregister (or a
/// jammed transport) could otherwise grow the queue until the heap is exhausted
/// on a `no_std + alloc` target. Past the cap the OLDEST best-effort goodbyes are
/// evicted (their records expire by TTL — acceptable under resource pressure).
const MAX_GOODBYE_ENTRIES: usize = 32;
/// Byte budget across all pending goodbyes (each datagram up to
/// `MAX_MDNS_MESSAGE`). At least `2 * MAX_MDNS_MESSAGE` so a single service's TWO
/// independently-required TTL=0 withdrawals — the old-name conflict-rename goodbye
/// (queued via `drain_service_updates`) and a later unregister/current-name
/// goodbye — BOTH at the §17 ceiling, coexist without `make_goodbye_room` evicting
/// one to fit the other. A tighter budget (< 2×) drops a required withdrawal with NO
/// unrelated churn, reintroducing the stale-name-until-TTL failure the rename-goodbye
/// work prevents. Beyond a pair, the OLDEST best-effort entries are still
/// evicted under genuine multi-service churn (their records expire by TTL).
const MAX_GOODBYE_BYTES: usize = 2 * MAX_MDNS_MESSAGE;
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

/// A pending TTL=0 goodbye, (re)sent a few times after a service is removed.
struct PendingGoodbye<I> {
  data: Vec<u8>,
  /// Per-family sends still owed ([0]=v4, [1]=v6), each decremented only on a
  /// REAL send to that family. Tracking the burst budget per family — rather than
  /// per all-families attempt — lets a one-datagram-per-cycle transport deliver
  /// v4 on one cycle and v6 on the next and still complete the budget, instead of
  /// wedging until the age bound. A family with no socket is written off
  /// (set to 0); a busy family keeps its count and is retried until the age bound.
  owed: [u8; 2],
  /// When the next (re)send attempt is due.
  next_at: I,
  /// Hard deadline after which the entry is given up even if never delivered.
  expires_at: I,
}

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

  /// Fan a multicast datagram out to BOTH mDNS groups and report whether the
  /// proto may confirm it NOW (synchronous — no deferral, so the confirm-on-send
  /// contract holds). The contract is the proto's own: `delivered = true` iff at
  /// least one socket send succeeded (`Service::note_transmit_result`). So this
  /// returns whether ANY family queued the datagram — NOT whether every family
  /// did.
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
  /// The driver-owned goodbye queue uses the stricter all-families rule instead
  /// ([`Self::burst`]) — there the driver, not the proto, owns retry, so it keeps
  /// re-bursting until every family flushes (age-bounded).
  ///
  /// Returns [`MulticastOutcome`]: `Delivered` confirms; `Retry` leaves it for the
  /// proto to re-offer; `Undeliverable` (a permanently TooLarge datagram with no
  /// transient family left) tells the pump to retire the producer. Records a
  /// self-send credit whenever the datagram reached a family.
  fn send_multicast<T: UdpIo>(&mut self, io: &mut T, data: &[u8], now: I) -> MulticastOutcome {
    let mut sent_any = false;
    let mut any_recoverable = false;
    let mut any_too_large = false;
    for (idx, group) in family_order(&self.failing_since) {
      match io.try_send(data, group) {
        Ok(()) => {
          self.failing_since[idx] = None;
          sent_any = true;
        }
        // Busy is TRANSIENT — a momentarily-full TX queue, or an embassy
        // NoRoute/SocketNotBound that can clear. The family may yet send this
        // datagram, so it is RECOVERABLE: never retire on it, however long it has
        // been failing. Track the failing streak for fair fan-out ordering.
        Err(SendError::Busy) => {
          self.failing_since[idx].get_or_insert(now);
          any_recoverable = true;
        }
        // No socket for this family — absent, but the other family may carry it.
        Err(SendError::Unsupported) => {}
        // Permanently larger than this socket buffer — retrying cannot help.
        Err(SendError::TooLarge) => any_too_large = true,
      }
    }
    if sent_any {
      self.record(data, now);
      MulticastOutcome::Delivered
    } else if any_recoverable {
      // A transiently-failing (Busy) family may recover — let the proto re-offer.
      MulticastOutcome::Retry
    } else if any_too_large {
      // Nothing queued, nothing recoverable, and a family is permanently too large
      // — the producer can never send this datagram, so retire it.
      MulticastOutcome::Undeliverable
    } else {
      // Every family is merely absent (no socket): keep re-offering (a no-transport
      // setup never reaches Established, as before) rather than retiring.
      MulticastOutcome::Retry
    }
  }

  /// Attempt this goodbye on every family that still OWES a send, in priority
  /// order ([`family_order`], so a one-slot transport stays fair), decrementing a
  /// family's `owed` count when it actually queues. A family with NO socket
  /// (`Unsupported`) is written off (set to 0) so a single-stack node does not
  /// wait on an absent family; a busy family keeps its count and is retried on the
  /// next call — a family that frees within the age bound, including one that
  /// recovers after a long stall, still gets its withdrawal. Maintains
  /// `failing_since` so the prioritisation favours whichever family is behind.
  /// Not fingerprinted (a goodbye loopback is harmless — it withdraws records
  /// already being withdrawn).
  fn burst<T: UdpIo>(&mut self, io: &mut T, data: &[u8], owed: &mut [u8; 2], now: I) {
    for (idx, group) in family_order(&self.failing_since) {
      if owed[idx] == 0 {
        continue;
      }
      match io.try_send(data, group) {
        Ok(()) => {
          self.failing_since[idx] = None;
          owed[idx] = owed[idx].saturating_sub(1);
        }
        // No socket for this family, or a datagram permanently too large for its
        // buffer — it can never receive the withdrawal, so give up on it. (A queued
        // goodbye is a subset of records that already announced within the §17
        // ceiling, so TooLarge here is defensive; either way, do not loop on it.)
        Err(SendError::Unsupported | SendError::TooLarge) => owed[idx] = 0,
        // Busy (transiently or persistently): keep the count and retry next call.
        Err(SendError::Busy) => {
          self.failing_since[idx].get_or_insert(now);
        }
      }
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

/// Encode a §10.1 goodbye into `scratch` (the engine's reusable buffer, sized to
/// the §17 ceiling `MAX_MDNS_MESSAGE`). Returns the encoded length (the caller
/// copies `scratch[..len]` out), `None` when nothing is withdrawable, or `None` on
/// `BufferTooSmall` — a goodbye that exceeds even the ceiling cannot be sent.
/// Writing into the pre-allocated shared buffer — not a fresh per-call `Vec` —
/// means a large unregister never reallocates while the backlog is full.
/// `is_retained` is the shared-host retention PREDICATE (not a materialised set),
/// so unregister allocates no retention `Vec` regardless of sibling count.
fn encode_goodbye_into<I: Instant>(
  proto: &ProtoService<I>,
  is_retained: impl Fn(core::net::IpAddr) -> bool,
  scratch: &mut [u8],
) -> Option<usize> {
  match proto.encode_goodbye_filtered(scratch, is_retained) {
    Ok(Some(len)) => Some(len),
    Ok(None) | Err(_) => None,
  }
}

/// Drain a pending conflict-rename goodbye into `scratch` (the ceiling-sized
/// reusable buffer). Returns the encoded length, or `None` when there is no
/// pending rename goodbye (or it exceeds the ceiling). On `BufferTooSmall` the
/// proto preserves the pending state, but the service is being removed, so a
/// rename goodbye larger than the ceiling is dropped (its records expire by TTL).
fn take_rename_goodbye_into<I: Instant>(
  proto: &mut ProtoService<I>,
  scratch: &mut [u8],
) -> Option<usize> {
  match proto.take_pending_rename_goodbye(scratch) {
    Ok(Some(len)) => Some(len),
    Ok(None) | Err(_) => None,
  }
}

/// Whether some OTHER same-host service in `services` still advertises `addr` —
/// the RFC 6762 §10.1 shared-host retention check, evaluated as a PREDICATE over
/// the service table rather than by materialising a retained-address set. So a
/// withdrawing service retracts only addresses no remaining same-host service
/// announced, while allocating nothing for retention regardless of how many
/// same-host siblings (or addresses) exist.
fn host_addr_retained<I: Instant>(
  services: &BTreeMap<ServiceHandle, ServiceSlot<I>>,
  handle: ServiceHandle,
  addr: core::net::IpAddr,
) -> bool {
  let host = match services.get(&handle) {
    Some(slot) => slot.proto.records().host(),
    None => return false,
  };
  services.iter().any(|(other, slot)| {
    *other != handle
      && slot.proto.records().host() == host
      && match addr {
        core::net::IpAddr::V4(v4) => slot.proto.advertised_a_addrs().contains(&v4),
        core::net::IpAddr::V6(v6) => slot.proto.advertised_aaaa_addrs().contains(&v6),
      }
  })
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
  goodbyes: Vec<PendingGoodbye<I>>,
  /// Reusable buffer for encoding a §10.1 goodbye before it is copied (exactly
  /// sized) into `goodbyes`. PRE-ALLOCATED to the §17 ceiling (`MAX_MDNS_MESSAGE`)
  /// at construction — a FIXED footprint, never grown or shrunk during operation.
  /// Encoding into this shared buffer rather than a fresh per-call `Vec` means the
  /// goodbye subsystem's peak is exactly `MAX_GOODBYE_BYTES` plus this buffer, with
  /// no per-unregister datagram spike and — because it is sized up front,
  /// before any backlog accumulates — no reallocation while the backlog is full on
  /// the first large goodbye.
  goodbye_scratch: Vec<u8>,
  /// The multicast transmit path: per-family fan-out, fan-out ordering, and
  /// self-loopback detection.
  tx: Multicaster<I>,
}

impl<I, R> Engine<I, R>
where
  I: Instant,
  R: Rng,
{
  /// Create an engine from a proto-layer config and an RNG (used for probe
  /// tiebreak seeds and query transaction ids).
  pub fn new(config: EndpointConfig, rng: R) -> Self {
    Self {
      endpoint: ProtoEndpoint::try_new(config, rng),
      services: BTreeMap::new(),
      queries: BTreeMap::new(),
      subnets: Vec::new(),
      goodbyes: Vec::new(),
      // Fixed footprint, sized up front so a large goodbye never reallocates the
      // scratch while the backlog is full.
      goodbye_scratch: alloc::vec![0u8; MAX_MDNS_MESSAGE],
      tx: Multicaster::new(),
    }
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
      },
    );
    Ok(handle)
  }

  /// Unregister a service, emitting its RFC 6762 §10.1 goodbyes before releasing
  /// the route slot. Two withdrawals may be queued, each bursted `GOODBYE_SENDS`
  /// times by the pump:
  ///
  /// * a TTL=0 goodbye for the records it announced — but host addresses a
  ///   same-host sibling still advertises are RETAINED (withdrawing them would
  ///   evict a record peers legitimately still hold for the shared host);
  /// * any queued conflict-rename goodbye for an old instance name. A service
  ///   removed mid-rename is never polled again, so its proto state would
  ///   otherwise drop that pending withdrawal silently.
  pub fn unregister_service(&mut self, handle: ServiceHandle, now: I) {
    // Encode each goodbye into the reusable scratch FIRST, then — only if one was
    // produced — make exact backlog room and queue an owned copy (commit_goodbye).
    // Deciding eviction after a successful encode, by exact size, means a service
    // with nothing to withdraw never evicts a queued goodbye; reusing the
    // pre-allocated scratch avoids a fresh per-unregister datagram allocation
    //; and shared-host retention is a PREDICATE over the service table,
    // not a materialised set, so unregister allocates no retention Vec however many
    // same-host siblings exist. The slot borrow is scoped to each encode so
    // it ends before `self.goodbyes` and `self.goodbye_scratch` are touched
    // together; the main goodbye is copied out before the rename encode reuses the
    // scratch.
    let main_len = match self.services.get(&handle) {
      Some(slot) => {
        let services = &self.services;
        encode_goodbye_into(
          &slot.proto,
          |addr| host_addr_retained(services, handle, addr),
          &mut self.goodbye_scratch,
        )
      }
      None => None,
    };
    if let Some(len) = main_len {
      self.commit_goodbye(len, now);
    }
    let rename_len = match self.services.get_mut(&handle) {
      Some(slot) => take_rename_goodbye_into(&mut slot.proto, &mut self.goodbye_scratch),
      None => None,
    };
    if let Some(len) = rename_len {
      self.commit_goodbye(len, now);
    }
    self.services.remove(&handle);
    let _ = self.endpoint.unregister_service(handle);
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
  /// `io`, and return the next deadline to sleep until.
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
        continue;
      }
      if onlink::on_link(meta.hop_limit, meta.src.ip(), meta.local, &self.subnets) {
        self.handle_one(now, meta.src, meta.local, &scratch[..len]);
      }
    }
    // Hit the cap → more datagrams may be buffered; re-pump immediately (below)
    // rather than sleeping to the next timer.
    let rx_capped = rx_processed == MAX_RX_PER_PUMP;

    self.drain_service_updates(now);

    while let Some((dst, len, origin)) = self.poll_one_transmit(now, scratch) {
      if dst == MDNS_SOCKET_V4 || dst == MDNS_SOCKET_V6 {
        // Multicast: fan out to BOTH groups and confirm synchronously this pump
        // (honors the proto's confirm-on-send contract).
        match self.tx.send_multicast(io, &scratch[..len], now) {
          MulticastOutcome::Delivered => self.note_transmit_result(origin, now, true),
          MulticastOutcome::Retry => self.note_transmit_result(origin, now, false),
          // Permanently undeliverable (too large for every reachable socket): retire
          // the producer so it stops re-offering forever and the app sees an
          // actionable update, instead of probing/announcing indefinitely.
          MulticastOutcome::Undeliverable => self.retire_origin(origin),
        }
      } else {
        // Unicast (legacy §6.7 reply): one destination, no fan-out. A failed
        // one-shot reply is best-effort (the querier re-asks), never service-fatal.
        let delivered = io.try_send(&scratch[..len], dst).is_ok();
        self.note_transmit_result(origin, now, delivered);
      }
    }

    // A confirmed final announcement sets `Established` (and other transitions)
    // INSIDE the TX loop above, AFTER the pre-loop drain. The next deadline is then
    // the distant re-announce, so without a second drain the application could not
    // observe `Established` until the next pump ~80% of a TTL away. Drain
    // again so confirmed transitions are visible to `poll_service_update` now.
    self.drain_service_updates(now);

    self.drain_goodbyes(now, io);

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
  /// surfacing a `Renamed` update, then stealing any conflict-rename goodbye into
  /// the per-family-owed queue.
  ///
  /// A §9 rename of an ANNOUNCED service queues a TTL=0 withdrawal of the OLD
  /// instance name. After draining each service's updates this hands that
  /// withdrawal to the per-family-owed goodbye queue (`commit_goodbye`) rather than
  /// leaving it to the proto's single global resend budget. The engine fans every
  /// multicast to BOTH groups and confirms on `delivered = sent_any`, so on that
  /// global budget a partial fan-out — one family queues both rename-goodbye sends
  /// while the other stays busy through the window — would exhaust the budget and
  /// clear the pending withdrawal even though the busy family never saw a TTL=0
  /// record, leaving its peers caching the ghost old name until TTL. The
  /// queue tracks each family's sends independently, so a busy family keeps its
  /// budget until it actually transmits — the same per-family path the
  /// mid-rename-removal goodbye takes in `unregister_service`.
  ///
  /// The steal is per service AFTER its update drain — NOT gated on the `Renamed`
  /// update — because the proto sets `pending_rename_goodbye` BEFORE it knows the
  /// suffixed name is valid: an announced near-length-limit instance whose `-1`
  /// suffix overflows the 63-byte label surfaces `Conflict` (not `Renamed`) yet
  /// still leaves the old-name withdrawal pending. Stealing it for every terminal
  /// path (rename success, invalid-suffix `Conflict`, and the local-collision
  /// `Conflict` from a failed `handle_service_renamed`) — and before the TX loop —
  /// guarantees it can never reach `poll_transmit`'s global-budget fallback.
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
          if self
            .endpoint
            .handle_service_renamed(handle, new_name)
            .is_err()
          {
            // The new name collides with another local service; the service has
            // already rebranded and can't be kept. Surface `Conflict` and mark
            // it errored so every pump skips it. The old-name withdrawal it queued
            // is still stolen below (the steal does not skip errored slots).
            if let Some(slot) = self.services.get_mut(&handle) {
              slot.push_update(ServiceUpdate::Conflict);
              slot.errored = true;
            }
            break;
          }
        }
        if let Some(slot) = self.services.get_mut(&handle) {
          slot.push_update(update);
        }
      }
      // Steal any pending conflict-rename withdrawal into the per-family queue —
      // for ANY terminal path (success or either `Conflict`), errored or not — so
      // it never falls through to the proto's `poll_transmit` global budget. A
      // no-op (`take` returns `None`) for the services that did not just rename.
      let rename_len = match self.services.get_mut(&handle) {
        Some(slot) => take_rename_goodbye_into(&mut slot.proto, &mut self.goodbye_scratch),
        None => None,
      };
      if let Some(len) = rename_len {
        self.commit_goodbye(len, now);
      }
    }
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
    // transmit path never emits a datagram larger than the fixed goodbye scratch
    // can later withdraw. A record set that would exceed MAX_MDNS_MESSAGE
    // then fails to encode here and the service is retired below (the `Err` arm),
    // rather than being advertised with records no §10.1 goodbye could retract.
    let cap = scratch.len().min(MAX_MDNS_MESSAGE);
    let scratch = &mut scratch[..cap];
    let service_handles: Vec<ServiceHandle> = self.services.keys().copied().collect();
    for handle in service_handles {
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
        Ok(None) => {}
        Err(_) => {
          // The pending datagram can't be encoded into `scratch`; the proto
          // re-offers it forever, so retire the service to avoid a stall.
          slot.push_update(ServiceUpdate::Conflict);
          slot.errored = true;
        }
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
  fn retire_origin(&mut self, origin: Origin) {
    match origin {
      Origin::Service(handle) => {
        if let Some(slot) = self.services.get_mut(&handle) {
          slot.push_update(ServiceUpdate::Conflict);
          slot.errored = true;
        }
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

  /// Prune expired goodbyes, then evict the OLDEST best-effort entries until the
  /// backlog has room for an `incoming`-byte datagram within BOTH the count and
  /// byte budgets (evicted withdrawals expire by TTL — acceptable under resource
  /// pressure). Call this BEFORE the (infallible) encode that allocates the new
  /// datagram, reserving `MAX_MDNS_MESSAGE`, so the backlog is never held at full
  /// cap WHILE a freshly-encoded goodbye is also live: the byte budget then bounds
  /// the actual peak on a `no_std + alloc` target, not just the retained set after
  /// the fact. Each entry owns a datagram up to `MAX_MDNS_MESSAGE`.
  fn make_goodbye_room(&mut self, incoming: usize, now: I) {
    self.goodbyes.retain(|g| g.expires_at > now);
    let mut cur_bytes: usize = self.goodbyes.iter().map(|g| g.data.len()).sum();
    while !self.goodbyes.is_empty()
      && (self.goodbyes.len() >= MAX_GOODBYE_ENTRIES
        || cur_bytes.saturating_add(incoming) > MAX_GOODBYE_BYTES)
    {
      let evicted = self.goodbyes.remove(0);
      cur_bytes = cur_bytes.saturating_sub(evicted.data.len());
    }
  }

  /// Queue an owned copy of the `len`-byte goodbye currently in `goodbye_scratch`.
  /// Makes EXACT room first (see [`Self::make_goodbye_room`]), then allocates the
  /// copy — so a full backlog is trimmed before the owned datagram exists, not
  /// after. Called ONLY after an encode produced `len` bytes, so a service with
  /// nothing to withdraw never triggers eviction of a queued goodbye.
  fn commit_goodbye(&mut self, len: usize, now: I) {
    self.make_goodbye_room(len, now);
    let expires_at = now.checked_add_duration(MAX_GOODBYE_AGE).unwrap_or(now);
    let data = self.goodbye_scratch[..len].to_vec();
    self.goodbyes.push(PendingGoodbye {
      data,
      owed: [GOODBYE_SENDS; 2],
      next_at: now,
      expires_at,
    });
  }

  /// Send any due §10.1 goodbyes, fanned out to both mDNS groups in priority
  /// order. Each family independently spends down its burst budget on a real send
  /// (tracked per family across attempts, so a one-datagram-per-cycle transport
  /// still completes the budget instead of wedging); an all-busy attempt spends
  /// nothing. The entry drops once every family is done — delivered its budget,
  /// or written off for having no socket. A hard age bound (`MAX_GOODBYE_AGE`)
  /// gives up an entry still owed by a never-freeing family without dropping a
  /// transiently-busy one before it can send.
  fn drain_goodbyes<T: UdpIo>(&mut self, now: I, io: &mut T) {
    let mut idx = 0;
    while idx < self.goodbyes.len() {
      if self.goodbyes[idx].expires_at <= now {
        self.goodbyes.remove(idx);
        continue;
      }
      if self.goodbyes[idx].next_at <= now {
        let entry = &mut self.goodbyes[idx];
        self.tx.burst(io, &entry.data, &mut entry.owed, now);
        entry.next_at = now.checked_add_duration(GOODBYE_INTERVAL).unwrap_or(now);
        if entry.owed == [0, 0] {
          self.goodbyes.remove(idx);
          continue;
        }
      }
      idx = idx.saturating_add(1);
    }
  }

  /// The earliest deadline across the endpoint, services, and queries.
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
    for goodbye in &self.goodbyes {
      let wake = goodbye.next_at.min(goodbye.expires_at);
      best = Some(best.map_or(wake, |b| b.min(wake)));
    }
    best
  }

  /// Pop one app-facing update for a registered service.
  pub fn poll_service_update(&mut self, handle: ServiceHandle) -> Option<ServiceUpdate> {
    self
      .services
      .get_mut(&handle)
      .and_then(|slot| slot.updates.pop_front())
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

    // Unregister → an RFC 6762 §10.1 TTL=0 goodbye burst.
    engine.unregister_service(handle, at(5_000_000));
    for micros in [5_000_000, 5_000_001, 6_000_001, 7_000_001] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }

    assert!(
      !io.sent.is_empty(),
      "unregistering an announced service should emit a §10.1 goodbye burst"
    );
  }

  #[test]
  fn same_host_sibling_addresses_are_retained_on_unregister() {
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(3));
    let shared = Ipv4Addr::new(192, 168, 1, 10);
    let a = engine
      .register_service(
        spec_for(
          "_ipp._tcp.local.",
          "Dev._ipp._tcp.local.",
          "dev.local.",
          shared,
        ),
        at(0),
      )
      .unwrap();
    let b = engine
      .register_service(
        spec_for(
          "_http._tcp.local.",
          "Dev._http._tcp.local.",
          "dev.local.",
          shared,
        ),
        at(0),
      )
      .unwrap();

    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    // Drive both services through probing + announcing so the shared host
    // address is confirmed-advertised by each.
    for micros in [
      0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
      5_000_000,
    ] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }

    // Withdrawing A must RETAIN the shared address: same-host sibling B still
    // advertises it (RFC 6762 §10.1 shared-host records).
    let shared_addr = core::net::IpAddr::V4(shared);
    assert!(
      host_addr_retained(&engine.services, a, shared_addr),
      "shared host address must be retained while sibling B advertises it"
    );

    // Once B is gone too, nothing retains the address any more.
    engine.unregister_service(b, at(6_000_000));
    assert!(
      !host_addr_retained(&engine.services, a, shared_addr),
      "with no sibling advertising it, the address is not retained"
    );
  }

  #[test]
  fn unregister_retention_scales_to_many_same_host_siblings() {
    // shared-host retention is a predicate over the service table, so an
    // unregister handles many same-host siblings without materialising a
    // retained-address set. Verify retention stays correct at scale — a shared
    // address is retained while ANY sibling still advertises it, dropped once none
    // do — exercising the allocation-free path with many siblings.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(29));
    let shared = Ipv4Addr::new(192, 168, 1, 50);
    let mut handles = Vec::new();
    for i in 0..8u32 {
      let instance = alloc::format!("Svc{i}._ipp._tcp.local.");
      handles.push(
        engine
          .register_service(
            spec_for("_ipp._tcp.local.", &instance, "shared.local.", shared),
            at(0),
          )
          .unwrap(),
      );
    }
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    let shared_addr = core::net::IpAddr::V4(shared);
    let a = handles[0];
    assert!(
      host_addr_retained(&engine.services, a, shared_addr),
      "the shared address must be retained while sibling services advertise it"
    );
    // Drop every sibling but `a`; the shared address is retained until the last.
    for &h in &handles[1..] {
      engine.unregister_service(h, at(6_000_000));
    }
    assert!(
      !host_addr_retained(&engine.services, a, shared_addr),
      "once every same-host sibling is gone, the shared address is not retained"
    );
  }

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
    assert_eq!(engine.goodbyes.len(), 1, "a goodbye should be queued");
    let budget = engine.goodbyes[0].owed;
    assert!(budget.iter().any(|&n| n > 0));

    // All-busy transport: the per-family send budget must NOT be spent.
    io.v4_fail = Some(SendError::Busy);
    io.v6_fail = Some(SendError::Busy);
    io.sent.clear();
    for micros in [5_000_000, 6_000_001, 7_000_001] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    assert!(
      io.sent.is_empty(),
      "no goodbye should be recorded while busy"
    );
    assert_eq!(
      engine.goodbyes.first().map(|g| g.owed),
      Some(budget),
      "the per-family send budget must be unchanged after all-busy attempts"
    );

    // Transport recovers → the goodbye finally goes out.
    io.v4_fail = None;
    io.v6_fail = None;
    engine.pump(at(8_000_001), &mut io, &mut scratch);
    assert!(
      !io.sent.is_empty(),
      "the goodbye must go out once the transport frees"
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
    // unregister MUST queue a §10.1 withdrawal for those records.
    engine.unregister_service(handle, at(4_500_000));
    assert!(
      !engine.goodbyes.is_empty(),
      "a v4-only advertisement must still latch goodbye ownership, so unregister \
       withdraws the records v4 peers cached"
    );
    // v6 recovers → the goodbye fan-out reaches it too (the busy family catches
    // up on the next driver-owned send).
    io.v6_fail = None;
    io.sent.clear();
    for micros in [4_600_000, 4_700_000, 5_700_000] {
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

  #[test]
  fn active_rename_goodbye_keeps_a_busy_family_owed_not_global_budget() {
    // A §9 conflict rename of an ANNOUNCED service withdraws the
    // OLD instance name with a TTL=0 goodbye. The engine fans every multicast to
    // BOTH groups and confirms on `sent_any`, so if that withdrawal rode the
    // proto's single global resend budget, a partial fan-out (v4 queues both sends
    // while v6 stays busy through the whole window) would spend the entire budget
    // on v4 and clear the pending withdrawal — leaving v6 peers caching the ghost
    // old name until TTL. The driver must instead route the rename goodbye through
    // the per-family-owed queue, so v6 keeps its full send budget until it actually
    // transmits.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(37));
    let handle = engine.register_service(sample_spec(), at(0)).unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];

    // Establish on BOTH families so the instance name is confirmed-advertised
    // (goodbye ownership latched) — only an announced name's rename emits a goodbye.
    let mut established = false;
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        established |= matches!(u, ServiceUpdate::Established);
      }
    }
    assert!(
      established,
      "service must be Established before the conflict"
    );

    // v6 is busy for the entire rename-goodbye window; v4 is reachable.
    io.sent.clear();
    io.v6_fail = Some(SendError::Busy);

    // A peer (port 5353) keeps claiming our instance name with different SRV rdata.
    // The first conflict reverts us to probing; a further conflict loses the §8.2
    // tiebreak (our TXT sorts before the peer's SRV, so any peer SRV wins) and
    // renames, queuing the old-name goodbye. Inject until the goodbye appears.
    let conflict = build_conflict_srv_authority("Test._ipp._tcp.local.");
    let mut t = 6_000_000i64;
    let mut renamed = false;
    for _ in 0..16 {
      io.inbound.push_back((
        conflict.clone(),
        RecvMeta {
          src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
          local: None,
          hop_limit: Some(255),
          len: 0,
        },
      ));
      engine.pump(at(t), &mut io, &mut scratch);
      t += 250_000;
      if !engine.goodbyes.is_empty() {
        renamed = true;
        break;
      }
    }
    assert!(
      renamed,
      "a §9 conflict must rename the announced service and queue an old-name goodbye"
    );
    // Only the rename goodbye is queued (no unregister happened, and a re-probe of
    // the never-announced new name latches no further goodbye ownership).
    assert_eq!(
      engine.goodbyes.len(),
      1,
      "exactly the old-name rename goodbye should be queued"
    );

    // v6 Busy throughout: v4 must drain while v6 keeps its full per-family budget,
    // then complete once v6 recovers — the property the global budget would break.
    assert_rename_goodbye_keeps_busy_family_owed(&mut engine, &mut io, &mut scratch, t);
  }

  /// Shared tail for the rename-goodbye partial-fan-out regressions: the
  /// old-name withdrawal is already queued and v6 is Busy. Asserts v4 drains its
  /// send budget while v6 keeps its FULL share (the per-family `owed` property the
  /// proto's single global budget would break), then that v6's recovery completes
  /// the budget and drops the entry. `t` is the current pump clock (microseconds).
  fn assert_rename_goodbye_keeps_busy_family_owed(
    engine: &mut Engine<SmoltcpInstant, StdRng>,
    io: &mut MockUdp,
    scratch: &mut [u8],
    mut t: i64,
  ) {
    // Spend several GOODBYE_INTERVALs with v6 still busy. v4 drains its full budget,
    // but v6's share MUST be untouched: under the global-budget bug v4's two
    // deliveries would have exhausted the budget and dropped the whole withdrawal.
    for _ in 0..5 {
      t += 1_000_000;
      engine.pump(at(t), io, scratch);
    }
    let owed = engine.goodbyes.first().map(|g| g.owed);
    assert_eq!(
      owed,
      Some([0, GOODBYE_SENDS]),
      "v4 must drain to 0 while v6 keeps its FULL budget — v4 delivery must not \
       consume v6's share of the rename goodbye; got {owed:?}"
    );

    // v6 recovers → it finally receives the withdrawal and the entry drains. The
    // empty queue proves v6 spent its full per-family budget on real sends.
    io.v6_fail = None;
    io.sent.clear();
    for _ in 0..3 {
      t += 1_000_000;
      engine.pump(at(t), io, scratch);
    }
    assert!(
      engine.goodbyes.is_empty(),
      "once v6 recovers, its rename-goodbye budget completes and the entry drops"
    );
    assert!(
      io.sent.iter().any(|(dst, _)| *dst == MDNS_SOCKET_V6),
      "the old-name withdrawal must finally reach v6; got {:?}",
      io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
    );
  }

  #[test]
  fn invalid_suffix_rename_goodbye_also_routes_through_per_family_queue() {
    // The proto sets `pending_rename_goodbye` BEFORE it knows the
    // suffixed name is valid. An announced instance whose first label is the max 63
    // bytes renames to a 65-byte label ("-1" appended) → invalid → the proto goes
    // Conflicting and surfaces `Conflict` (NOT `Renamed`) while leaving the old-name
    // withdrawal pending. The engine must STILL route that withdrawal through the
    // per-family-owed queue, not the proto's global `poll_transmit` budget, or a
    // v4-delivered / v6-Busy fan-out drops it before v6 ever sends.
    let long_label = "a".repeat(63);
    let instance = alloc::format!("{long_label}._ipp._tcp.local.");
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(41));
    let handle = engine
      .register_service(
        spec_for(
          "_ipp._tcp.local.",
          &instance,
          "host.local.",
          Ipv4Addr::new(192, 168, 1, 10),
        ),
        at(0),
      )
      .unwrap();
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];

    // Establish on both families (goodbye ownership latched on the long name).
    let mut established = false;
    for micros in pump_schedule() {
      engine.pump(at(micros), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        established |= matches!(u, ServiceUpdate::Established);
      }
    }
    assert!(
      established,
      "the long-named service must Establish before the conflict"
    );

    io.sent.clear();
    io.v6_fail = Some(SendError::Busy);

    // A peer claims the long instance name with different SRV rdata. Reverting to
    // probe then losing the §8.2 tiebreak attempts a rename; the "-1" suffix is an
    // invalid 65-byte label, so the proto goes Conflicting and surfaces `Conflict` —
    // but the old-name withdrawal is still queued and must reach the family queue.
    let conflict = build_conflict_srv_authority(&instance);
    let mut t = 6_000_000i64;
    let mut conflicted = false;
    for _ in 0..16 {
      io.inbound.push_back((
        conflict.clone(),
        RecvMeta {
          src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
          local: None,
          hop_limit: Some(255),
          len: 0,
        },
      ));
      engine.pump(at(t), &mut io, &mut scratch);
      while let Some(u) = engine.poll_service_update(handle) {
        conflicted |= matches!(u, ServiceUpdate::Conflict);
      }
      t += 250_000;
      if !engine.goodbyes.is_empty() {
        break;
      }
    }
    assert!(
      conflicted,
      "an invalid-suffix rename must surface Conflict (not Renamed)"
    );
    assert_eq!(
      engine.goodbyes.len(),
      1,
      "the old-name withdrawal must be queued even though the rename suffix was invalid"
    );

    // The withdrawal rode the Conflict path, not Renamed — verify it still gets the
    // per-family-owed treatment (v6 Busy keeps its share, completes on recovery).
    assert_rename_goodbye_keeps_busy_family_owed(&mut engine, &mut io, &mut scratch, t);
  }

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

  #[test]
  fn a_constrained_transport_drains_a_goodbye_after_each_family_gets_the_budget() {
    // On a one-datagram-per-cycle transport the goodbye fan-out
    // delivers v4 on one cycle and v6 on the next, so no single attempt queues
    // BOTH families. The per-family `owed` budget must spend down across attempts:
    // the entry drains once GOODBYE_SENDS have reached EACH family, rather than
    // lingering to MAX_GOODBYE_AGE and emitting one datagram per interval until.
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
    // One datagram of TX room per cycle: each pump, only the first family queues.
    let mut t = 5_000_000i64;
    for _ in 0..16 {
      t += 1_000_000; // a GOODBYE_INTERVAL apart, all within MAX_GOODBYE_AGE
      io.capacity = Some(1);
      engine.pump(at(t), &mut io, &mut scratch);
      if engine.goodbyes.is_empty() {
        break;
      }
    }
    assert!(
      engine.goodbyes.is_empty(),
      "the goodbye must drain via its per-family budget, not linger to its max age"
    );
    let v4 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V4).count();
    let v6 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V6).count();
    assert_eq!(
      (v4, v6),
      (usize::from(GOODBYE_SENDS), usize::from(GOODBYE_SENDS)),
      "each reachable family must receive exactly the configured goodbye burst \
       count; v4={v4} v6={v6}"
    );
  }

  #[test]
  fn the_goodbye_queue_stays_bounded_under_unregister_churn() {
    // Each unregister queues an OWNED goodbye datagram. The age
    // bound only caps an entry's lifetime once drain_goodbyes runs, so churning
    // register/unregister faster than the transport drains — here it is jammed —
    // would otherwise grow the queue until the heap is exhausted on a no_std
    // target. The backlog must stay within its count + byte budget.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(24));
    let mut io = MockUdp::default();
    let mut scratch = [0u8; 1500];
    // Register more services than the cap and advertise them on a healthy
    // transport so each OWNS records — only then does unregister queue a goodbye.
    let n = MAX_GOODBYE_ENTRIES + 8;
    let mut handles = Vec::new();
    for i in 0..n {
      let instance = alloc::format!("Dev{i}._ipp._tcp.local.");
      let host = alloc::format!("dev{i}.local.");
      handles.push(
        engine
          .register_service(
            spec_for(
              "_ipp._tcp.local.",
              &instance,
              &host,
              Ipv4Addr::new(192, 168, 1, 10),
            ),
            at(0),
          )
          .unwrap(),
      );
    }
    for micros in [
      0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
    ] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    // The transport jams and every service is unregistered before anything drains.
    io.v4_fail = Some(SendError::Busy);
    io.v6_fail = Some(SendError::Busy);
    for handle in handles {
      engine.unregister_service(handle, at(5_000_000));
    }
    assert!(
      engine.goodbyes.len() <= MAX_GOODBYE_ENTRIES,
      "the goodbye backlog count must stay capped under churn; got {}",
      engine.goodbyes.len()
    );
    let bytes: usize = engine.goodbyes.iter().map(|g| g.data.len()).sum();
    assert!(
      bytes <= MAX_GOODBYE_BYTES,
      "the goodbye backlog bytes must stay capped under churn; got {bytes}"
    );
    // Eviction must have bitten: far more services churned than the bounded
    // backlog retains.
    assert!(
      engine.goodbyes.len() < n,
      "eviction should hold the backlog below the number churned; queued {} of {n}",
      engine.goodbyes.len()
    );
  }

  #[test]
  fn make_goodbye_room_evicts_to_fit_an_incoming_datagram() {
    // make_goodbye_room(incoming) must evict the oldest entries until the retained
    // bytes leave room for an `incoming`-byte datagram within the byte budget — so
    // commit_goodbye(len) can copy the encoded goodbye in without breaching the cap.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(25));
    let chunk = 2000usize;
    while engine.goodbyes.iter().map(|g| g.data.len()).sum::<usize>() + chunk <= MAX_GOODBYE_BYTES {
      engine.goodbyes.push(PendingGoodbye {
        data: alloc::vec![0u8; chunk],
        owed: [GOODBYE_SENDS; 2],
        next_at: at(0),
        expires_at: at(60_000_000),
      });
    }
    let before: usize = engine.goodbyes.iter().map(|g| g.data.len()).sum();
    assert!(
      before + MAX_MDNS_MESSAGE > MAX_GOODBYE_BYTES,
      "precondition: backlog must be too full to also hold a max-size datagram"
    );
    engine.make_goodbye_room(MAX_MDNS_MESSAGE, at(0));
    let after: usize = engine.goodbyes.iter().map(|g| g.data.len()).sum();
    assert!(
      after + MAX_MDNS_MESSAGE <= MAX_GOODBYE_BYTES && engine.goodbyes.len() < MAX_GOODBYE_ENTRIES,
      "make_goodbye_room must evict to fit an incoming datagram; retained {after} \
       bytes leaves no room for {MAX_MDNS_MESSAGE}"
    );
  }

  #[test]
  fn a_large_main_goodbye_survives_when_no_rename_follows() {
    // Eviction (make_goodbye_room) must run only AFTER an encode
    // produces a goodbye, by its EXACT size — never speculatively reserving a
    // worst-case MAX_MDNS_MESSAGE for a rename goodbye that may not exist. With a
    // near-full backlog, a speculative reserve would evict an older still-owed
    // withdrawal to make room for a rename that never comes; the exact-size commit
    // must not. At MAX_GOODBYE_BYTES = 2 * MAX_MDNS_MESSAGE this is observable only
    // when the backlog already holds a near-ceiling entry, so prime one first.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(27));
    // Many host addresses → a large main goodbye (still under the §17 ceiling).
    let mut records = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("Big._ipp._tcp.local.").unwrap(),
      Name::try_from_str("big.local.").unwrap(),
      631,
      120,
    );
    for i in 0..280u16 {
      records.add_aaaa(core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i));
    }
    let handle = engine
      .register_service(ServiceSpec::new(records), at(0))
      .unwrap();
    let mut io = MockUdp::default();
    // The announcement carries every address, so the scratch must reach the §17
    // ceiling for the records to be advertised (hence owned for the goodbye).
    let mut scratch = [0u8; MAX_MDNS_MESSAGE];
    for micros in [
      0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
    ] {
      engine.pump(at(micros), &mut io, &mut scratch);
    }
    // Prime a pre-existing near-ceiling withdrawal still owed by a busy family (added
    // AFTER establishment, with no pump before the unregister, so drain_goodbyes can't
    // send/drop it first). main + this fits the budget, but main + this + a speculative
    // MAX_MDNS_MESSAGE reserve would NOT — so a speculative reserve would evict it.
    engine.goodbyes.push(PendingGoodbye {
      data: alloc::vec![0u8; MAX_MDNS_MESSAGE],
      owed: [GOODBYE_SENDS; 2],
      next_at: at(5_000_000),
      expires_at: at(60_000_000),
    });
    // No rename: just a graceful unregister. The large main goodbye must be committed
    // by its EXACT size — the pre-existing entry must NOT be evicted by a speculative
    // reserve for the absent rename goodbye. Both withdrawals survive.
    engine.unregister_service(handle, at(5_000_000));
    assert_eq!(
      engine.goodbyes.len(),
      2,
      "exact-size commit must keep BOTH the pre-existing withdrawal and the large main \
       goodbye; a speculative rename reserve would have evicted one"
    );
    // Precondition: the two real withdrawals fit the budget, but together with a
    // speculative MAX_MDNS_MESSAGE reserve they would not — so a speculative reserve
    // WOULD have evicted one (what this guards against).
    let queued: usize = engine.goodbyes.iter().map(|g| g.data.len()).sum();
    assert!(
      queued <= MAX_GOODBYE_BYTES && queued + MAX_MDNS_MESSAGE > MAX_GOODBYE_BYTES,
      "precondition: both fit ({queued} <= {MAX_GOODBYE_BYTES}) but a speculative \
       reserve would not ({queued} + {MAX_MDNS_MESSAGE} > {MAX_GOODBYE_BYTES})"
    );
    // Encoding the large goodbye must NOT have grown the scratch — it is a fixed
    // footprint, so it never reallocates while the backlog is full.
    assert_eq!(
      engine.goodbye_scratch.len(),
      MAX_MDNS_MESSAGE,
      "the goodbye scratch is a fixed footprint and must not grow during operation"
    );
  }

  #[test]
  fn goodbye_budget_holds_two_near_ceiling_withdrawals() {
    // A single service can leave TWO independently-required TTL=0 withdrawals
    // queued — an old-name conflict-rename goodbye (routed through this queue by
    // drain_service_updates) plus a later unregister/current-name goodbye —
    // each up to the §17 ceiling. If MAX_GOODBYE_BYTES < 2 * MAX_MDNS_MESSAGE,
    // make_goodbye_room evicts the first to fit the second with NO unrelated churn,
    // dropping a required withdrawal before still-owed families see it (the
    // stale-name-until-TTL failure). The budget must hold the pair.
    let mut engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(43));
    // commit_goodbye copies `len` bytes from the pre-sized scratch (MAX_MDNS_MESSAGE).
    let near_ceiling = MAX_MDNS_MESSAGE - 8;
    engine.commit_goodbye(near_ceiling, at(0));
    engine.commit_goodbye(near_ceiling, at(1_000));
    assert_eq!(
      engine.goodbyes.len(),
      2,
      "the byte budget must hold two near-ceiling withdrawals without evicting one"
    );
    let queued: usize = engine.goodbyes.iter().map(|g| g.data.len()).sum();
    assert!(
      queued <= MAX_GOODBYE_BYTES,
      "queued goodbye bytes ({queued}) must stay within budget ({MAX_GOODBYE_BYTES})"
    );
  }

  #[test]
  fn default_setup_processes_rx_without_hop_limit_or_subnets() {
    // Both supplied transports report hop_limit: None (smoltcp's UdpMetadata
    // carries no RX TTL, and hick-embassy re-exports it), and Engine::new starts with
    // no local subnets. The §11 gate must NOT then drop every inbound datagram — a
    // default node could announce but never see a query, answer, or conflict. Feed a
    // conflict with the real supplied-transport metadata shape (hop_limit None) and NO
    // set_local_subnets; it must be PROCESSED (the service renames and queues an
    // old-name goodbye), not silently dropped.
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
      if !engine.goodbyes.is_empty() {
        break;
      }
    }
    assert!(
      !engine.goodbyes.is_empty(),
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
    }
    assert!(
      engine.goodbyes.is_empty(),
      "off-link unicast must NOT drive a conflict rename when no hop-limit or subnet \
       vouches for it — only link-scoped multicast is trusted by default"
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

  #[test]
  fn the_goodbye_scratch_is_a_fixed_preallocated_footprint() {
    // the goodbye encode scratch is sized to the §17 ceiling at construction,
    // before any backlog can accumulate, so a large goodbye never reallocates it
    // while the backlog is full.
    let engine: Engine<SmoltcpInstant, StdRng> =
      Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(28));
    assert_eq!(
      engine.goodbye_scratch.len(),
      MAX_MDNS_MESSAGE,
      "the goodbye scratch must be pre-allocated to the §17 ceiling"
    );
  }

  #[test]
  fn an_oversized_service_is_not_advertised_so_it_is_never_unwithdrawable() {
    // the normal multicast path honors the SAME §17 ceiling as the fixed
    // goodbye scratch. A record set that would encode above MAX_MDNS_MESSAGE must
    // NOT be advertised — even when the caller's pump scratch is larger — so the
    // engine can never latch goodbye ownership for records it could not later
    // withdraw (which would leave peers caching them until TTL).
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
    // It never advertised, so unregister latches no ownership and queues no
    // goodbye — there are no unwithdrawable records on the wire.
    engine.unregister_service(handle, at(6_000_000));
    assert!(
      engine.goodbyes.is_empty(),
      "an oversized service that never advertised must not produce a goodbye"
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

  #[test]
  fn busy_goodbye_survives_many_attempts_then_age_bounds_it() {
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
    engine.unregister_service(handle, at(5_000_000));
    // Busy for many attempts (well past the old 8-attempt cap), all within
    // MAX_GOODBYE_AGE: a never-delivered goodbye must NOT be dropped early.
    io.v4_fail = Some(SendError::Busy);
    io.v6_fail = Some(SendError::Busy);
    for s in 5..=20 {
      engine.pump(at(s * 1_000_000), &mut io, &mut scratch);
    }
    assert_eq!(
      engine.goodbyes.len(),
      1,
      "a never-delivered goodbye must survive busy attempts within its age window"
    );
    // Past MAX_GOODBYE_AGE (queued at 5 s) the undeliverable entry is given up.
    engine.pump(at(36_000_000), &mut io, &mut scratch);
    assert!(
      engine.goodbyes.is_empty(),
      "an undeliverable goodbye must be given up after its max age"
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
    assert!(
      matches!(
        tx.send_multicast(&mut partial, b"a-multicast-datagram", at(0)),
        MulticastOutcome::Delivered
      ),
      "v4 queued + v6 transiently busy must confirm (>= 1 socket succeeded)"
    );
    // Both families busy: nothing reached the link, so it must NOT confirm — the
    // proto then re-offers a probe/announce and latches nothing for a response
    // that never left the host. A transiently-busy family means Retry, not retire.
    let mut all_busy = MockUdp {
      v4_fail: Some(SendError::Busy),
      v6_fail: Some(SendError::Busy),
      ..Default::default()
    };
    assert!(
      matches!(
        tx.send_multicast(&mut all_busy, b"a-multicast-datagram", at(0)),
        MulticastOutcome::Retry
      ),
      "both families busy: nothing on the link, so retry rather than confirm or retire"
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
}

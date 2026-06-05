//! `Endpoint` orchestrator: demuxes incoming datagrams, holds routing
//! metadata + cache, drives Service/Query registration.

#[cfg(all(test, feature = "std", feature = "slab"))]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::panic,
  clippy::indexing_slicing,
  clippy::arithmetic_side_effects
)]
mod tests;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand_core::Rng;

use crate::{
  Instant, Name, Pool, QueryHandle, ServiceHandle,
  cache::{Cache, CacheEntry},
  config::{EndpointConfig, QuerySpec, ServiceSpec},
  error::{
    CancelQueryError, HandleError, HandleServiceRenamedError, HandleTimeoutError,
    RegisterServiceError, StartQueryError, StorageFullError, TransmitError,
  },
  event::{
    EndpointEvent, HostConflict, KnownAnswer, ProbeConflict, QueryEvent, QueryUpdate, RouteEvent,
    ServiceEvent, ServiceQuestion, ToQuery, ToService,
  },
  query::{CollectedAnswer, Query},
  service::Service,
  trace::*,
  transmit::Transmit,
  wire::{MessageReader, NameRef, ResourceClass, ResourceType},
};

/// Number of goodbye sends during an orderly withdrawal (RFC 6762 §10.1),
/// counted PER FAMILY so each reachable family withdraws its records.
#[cfg(any(feature = "alloc", feature = "std"))]
const WITHDRAWAL_SENDS: u8 = 3;

/// Spacing between successive withdrawal goodbye resends (loss resilience).
// Used by `poll_withdrawal_transmit`.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(dead_code)]
const WITHDRAWAL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(250);

/// Back-off added to `next_at` on a missed send (delivery not yet confirmed).
// Used by `note_withdrawal_result`.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(dead_code)]
const WITHDRAWAL_RETRY_BACKOFF: core::time::Duration = core::time::Duration::from_millis(20);

/// Hard deadline by which a withdrawal is force-completed regardless of
/// pending sends, to prevent a stale withdrawing route from pinning the name
/// slot indefinitely.
#[cfg(any(feature = "alloc", feature = "std"))]
const WITHDRAWAL_CEILING: core::time::Duration = core::time::Duration::from_secs(2);

/// Per-family result of sending one withdrawal (RFC 6762 §10.1 goodbye)
/// datagram, reported to [`Endpoint::note_withdrawal_result`] for EACH address
/// family so a withdrawal only completes once every reachable family has
/// withdrawn its records.
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, derive_more::Display)]
#[display("{}", self.as_str())]
pub enum WithdrawalSend {
  /// The datagram reached the wire on this family — spend one of its owed rounds.
  Sent,
  /// Transiently undeliverable (socket busy) — keep this family's debt, retry.
  Retry,
  /// This family is permanently unavailable (no socket / permanent send error) —
  /// write its debt off (it has no reachable peers to withdraw from).
  WriteOff,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl WithdrawalSend {
  /// Canonical lowercase slug for this per-family send outcome.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Sent => "sent",
      Self::Retry => "retry",
      Self::WriteOff => "write_off",
    }
  }
}

/// Opaque identity for a single in-progress `WithdrawalItem`, handed back by
/// [`Endpoint::poll_withdrawal_transmit`] and round-tripped to
/// [`Endpoint::note_withdrawal_result`] to confirm exactly that item's send.
///
/// A monotonic counter (`next_withdrawal_token`) mints a fresh value
/// per item and never reuses one, so a token can only ever name the item it was
/// minted for (or no item, once that item has been drained). It is deliberately
/// distinct from [`ServiceHandle`]: one teardown can spawn TWO items (a
/// route-attached current-name goodbye and a detached old-name rename goodbye),
/// so the poll/note key cannot be the handle.
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WithdrawalToken(u64);

/// In-progress withdrawal state for ONE name (one TTL=0 goodbye lifecycle).
/// Stored in [`Endpoint::withdrawals`] keyed by an opaque [`WithdrawalToken`].
/// The `I` type parameter is the [`Instant`] type of the enclosing endpoint.
///
/// A single name — never a dual current+rename pair. A teardown DURING a §9
/// rename therefore enqueues TWO independent items: a route-attached one for the
/// current (re-announced) name, and a detached one for the old name still draining
/// its rename goodbye. Modelling each goodbye as its own item means neither can
/// starve the other, and two names that each fit `scratch` individually are both
/// emitted even when their combined message would not.
///
/// `route` carries the item's relationship to a [`ServiceRoute`]:
///   * `Some(handle)` — a TEARDOWN item. It HOLDS the route `handle`: the name
///     stays blocked against re-registration until the item settles, and on
///     completion [`Endpoint::drain_completed_withdrawals`] frees the route
///     (releasing the name, decrementing `services_active`) and reports `handle`
///     to the driver. Only these items withdraw host A/AAAA (and so honour
///     sibling host-address retention).
///   * `None` — a DETACHED item (a renamed-away OLD name). It owns no route and
///     no host addresses (`host_a`/`host_aaaa` are always empty); when it settles
///     it is simply removed, reported to NOBODY.
///
/// Stored as a parallel `Vec` rather than inline on [`ServiceRoute`] because
/// `ServiceRoute` has no generic parameter: it is a public struct used by
/// every downstream crate as `Pool<ServiceRoute>`, and adding `I` would
/// require updating every type alias / `Slab<ServiceRoute>` declaration
/// across the whole workspace — including external users.
#[cfg(any(feature = "alloc", feature = "std"))]
struct WithdrawalItem<I> {
  /// The service records (names, port, TXT) for this name's goodbye sends.
  // Read by `poll_withdrawal_transmit`.
  #[allow(dead_code)]
  records: crate::records::ServiceRecords,
  /// Which instance record kinds (PTR/SRV/TXT/subtypes) this name put on the
  /// wire — only these are withdrawn (§7.1 KAS can suppress a subset).
  #[allow(dead_code)]
  owned: crate::service::EmittedRecords,
  /// Host A (IPv4) addresses confirmed-emitted; sibling-filtered per round before
  /// encoding. ALWAYS empty for a detached item (`route == None`) — a rename
  /// never withdraws host A/AAAA (the host name is invariant across renames).
  #[allow(dead_code)]
  host_a: std::vec::Vec<Ipv4Addr>,
  /// Host AAAA (IPv6) addresses confirmed-emitted. Always empty for a detached
  /// item (see `host_a`).
  #[allow(dead_code)]
  host_aaaa: std::vec::Vec<Ipv6Addr>,
  /// PER-FAMILY goodbye-send debt: `[0]` IPv4, `[1]` IPv6, each initialised to
  /// `WITHDRAWAL_SENDS` (or `[0, 0]` when this name has nothing to withdraw —
  /// never announced, no host addrs). A family's counter is decremented only when
  /// THAT family confirms a send ([`WithdrawalSend::Sent`]) and zeroed on a
  /// permanent write-off ([`WithdrawalSend::WriteOff`]).
  // Read and mutated by `note_withdrawal_result`.
  #[allow(dead_code)]
  owed: [u8; 2],
  /// When the next send is due.  Set to `now` at construction so the first
  /// send fires immediately.
  // Read by `poll_withdrawal_transmit`.
  #[allow(dead_code)]
  next_at: I,
  /// Hard force-complete deadline.  The item is terminated at or after this
  /// instant regardless of debt (anti-pin guard).
  // Read by `drain_completed_withdrawals`.
  #[allow(dead_code)]
  ceiling_at: I,
  /// `true` once a FINAL goodbye has been emitted AT/just-before the ceiling for
  /// a still-owed item.  Without this, a family that becomes
  /// reachable only in the `[last_attempt, ceiling]` window — because the last
  /// backoff overshot `ceiling_at` — would never get a try: `poll_withdrawal_transmit`
  /// only emits while `now < ceiling_at`, so the route would be force-completed
  /// with debt still owed.  When an item is past its ceiling but still owes AND
  /// has not yet been final-attempted, `poll_withdrawal_transmit` emits ONE last
  /// goodbye and sets this flag; `drain_completed_withdrawals` then force-completes
  /// a past-ceiling item only once this is set (or its debt already reached
  /// `[0, 0]`).  The flag also guarantees termination: the past-ceiling branch
  /// fires at most once per item, so the pump loop can never re-select the same
  /// item for another final attempt.
  // Read/written by `poll_withdrawal_transmit`; read by
  // `drain_completed_withdrawals`.
  #[allow(dead_code)]
  final_attempt: bool,
  /// The route this item relates to. `Some(handle)` is a teardown item HOLDING
  /// the route (blocks name-reuse, freed + reported on completion, withdraws host
  /// addresses); `None` is a detached old-name item (no route, no host, completes
  /// silently). See the type-level docs.
  #[allow(dead_code)]
  route: Option<ServiceHandle>,
  /// Whether this DETACHED item must HOLD its instance name against fresh
  /// `try_register_service` reuse until its goodbye completes (`route: None` items
  /// only — a route-attached item already holds via the route table).
  ///
  /// `false` (the default) is a SURVIVING rename's old name: reclaimable, so a
  /// fresh registration of the vacated name cancels the goodbye rather than being
  /// blocked. `true` is a rename-COLLISION teardown's old
  /// name: the service is DEAD, so its stale records must be retracted BEFORE the
  /// name is reused; without the hold, the empty route-attached current-name
  /// withdrawal completes first and a quick re-register cancels the only real
  /// goodbye, leaving peers with stale PTR/SRV/TXT until TTL. Auto-
  /// rename reclaim via `handle_service_renamed` still CANCELS even a held name —
  /// that path must not reject (it would kill the renaming service), and
  /// the reclaiming service re-announces the name.
  #[allow(dead_code)]
  holds_name: bool,
}

/// Routing metadata for a registered service.
#[derive(Debug, Clone)]
pub struct ServiceRoute {
  /// DNS-SD service-type PTR owner (e.g. `_ipp._tcp.local.`).
  service_type: Name,
  /// Instance name (e.g. `MyPrinter._ipp._tcp.local.`).
  name: Name,
  /// Host name that owns the A/AAAA records (e.g. `printer-host.local.`).
  host: Name,
  handle: ServiceHandle,
  /// IPv4 addresses advertised in this service's A records.  Used by
  /// `Endpoint::handle` to recognise multicast-loopback datagrams whose
  /// source IP matches an address we are publishing.  IPv6
  /// PKTINFO carries the multicast destination rather than the local
  /// interface address, so the IPv4-only `src == local_ip` shortcut from
  /// cannot detect IPv6 self-packets — membership against this
  /// list is the positive signal for both v4 and v6.
  a_addrs: std::vec::Vec<Ipv4Addr>,
  /// IPv6 addresses advertised in this service's AAAA records.  See
  /// `a_addrs` for the rationale.
  aaaa_addrs: std::vec::Vec<Ipv6Addr>,
  /// Parallel to `aaaa_addrs`: interface scope id for each AAAA (0 = any).
  /// IPv6 link-local addresses are scoped per interface; a peer
  /// reusing the same `fe80::*` on a different interface must NOT be
  /// classified as self.  A non-zero scope binds the address to a
  /// specific receiving `interface_index` in [`Endpoint::handle`].
  aaaa_scopes: std::vec::Vec<u32>,
  /// RFC 6763 §7.1 subtype browse names (`<sub>._sub.<service_type>`). A browse
  /// question for any of these routes to this service so it can answer with the
  /// shared subtype PTR.
  subtypes: std::vec::Vec<Name>,
  /// IPv4 host addresses this service has actually CONFIRMED-ADVERTISED on the
  /// wire — the subset of `a_addrs` a peer truly holds in its cache.  EMPTY at
  /// registration (a never-announced service has advertised nothing); the
  /// driver mirrors the live `Service::advertised_a_addrs` set here via
  /// [`Endpoint::note_service_advertised`] after each confirmed announce.  This
  /// (NOT the configured `a_addrs`) is what `sibling_retained_addrs` honours so
  /// a withdrawing service only retains addresses a LIVE same-host sibling
  /// genuinely owns in peer caches.
  #[cfg(any(feature = "alloc", feature = "std"))]
  advertised_a: std::vec::Vec<Ipv4Addr>,
  /// IPv6 host addresses this service has actually CONFIRMED-ADVERTISED.  See
  /// `advertised_a`; this is the AAAA counterpart, also EMPTY at registration.
  #[cfg(any(feature = "alloc", feature = "std"))]
  advertised_aaaa: std::vec::Vec<Ipv6Addr>,
  /// `true` once [`Endpoint::begin_withdrawal`] has been called for this
  /// service.  The route is kept alive (name guard + dispatch) until the
  /// goodbye sequence completes; this flag lets downstream code distinguish a
  /// live service from one that is in the process of being torn down.
  // Read by `poll_timeout` dispatch skip.
  #[allow(dead_code)]
  withdrawing: bool,
}

impl ServiceRoute {
  /// The DNS-SD service-type (PTR owner), e.g. `_ipp._tcp.local.`.
  #[inline(always)]
  pub fn service_type(&self) -> &Name {
    &self.service_type
  }

  /// The service's instance name.
  #[inline(always)]
  pub fn name(&self) -> &Name {
    &self.name
  }

  /// The service's host name (owner of A/AAAA records).
  #[inline(always)]
  pub fn host(&self) -> &Name {
    &self.host
  }

  /// The handle assigned to this service.
  #[inline(always)]
  pub const fn handle(&self) -> ServiceHandle {
    self.handle
  }

  /// Advertised IPv4 addresses for this service (A records).
  #[inline(always)]
  pub fn a_addrs(&self) -> &[Ipv4Addr] {
    &self.a_addrs
  }

  /// Advertised IPv6 addresses for this service (AAAA records).
  #[inline(always)]
  pub fn aaaa_addrs(&self) -> &[Ipv6Addr] {
    &self.aaaa_addrs
  }

  /// Per-AAAA interface scope ids (parallel to [`Self::aaaa_addrs`]).
  /// A scope of `0` matches any receiving interface; a non-zero scope
  /// matches only the same `interface_index` passed to
  /// [`Endpoint::handle`].
  #[inline(always)]
  pub fn aaaa_scopes(&self) -> &[u32] {
    &self.aaaa_scopes
  }

  /// IPv4 host addresses this service has CONFIRMED-ADVERTISED on the wire.
  /// Distinct from [`Self::a_addrs`] (the configured set used for self-/
  /// loopback detection): this is the subset peers actually hold in cache, kept
  /// current by [`Endpoint::note_service_advertised`] and consumed by
  /// sibling host-address retention during withdrawal.
  #[cfg(any(feature = "alloc", feature = "std"))]
  #[inline(always)]
  pub(crate) fn advertised_a(&self) -> &[Ipv4Addr] {
    &self.advertised_a
  }

  /// IPv6 host addresses this service has CONFIRMED-ADVERTISED on the wire (the
  /// AAAA counterpart of [`Self::advertised_a`]).
  #[cfg(any(feature = "alloc", feature = "std"))]
  #[inline(always)]
  pub(crate) fn advertised_aaaa(&self) -> &[Ipv6Addr] {
    &self.advertised_aaaa
  }
}

/// Internal queued endpoint event.
#[derive(Debug, Clone)]
pub struct EndpointEventEntry(EndpointEvent);

impl EndpointEventEntry {
  /// Borrow the inner event.
  #[inline(always)]
  pub const fn event(&self) -> &EndpointEvent {
    &self.0
  }
}

/// The orchestrator. Holds routing metadata + cache + per-handle state
/// machines for Service (caller-driven) and Query (Endpoint-owned).
///
/// The `Query` state machines live in the `QS` pool — callers receive only
/// a `QueryHandle` from [`Self::try_start_query`] and drive each query via
/// the `*_query*` accessors on `Endpoint`.
///
/// # Query lifecycle and cleanup
///
/// Queries are NOT auto-pruned.  After
/// [`Self::poll_query`] returns the terminal `QueryUpdate` for a handle,
/// the underlying state machine is RETAINED so the caller can drain
/// final results via [`Self::collected_answers`].  Late matching
/// responses arriving after terminal are frozen out: they do not
/// mutate `collected_answers` or trigger fan-out events.
///
/// Cleanup is the caller's responsibility — terminated queries leak
/// pool slots until explicitly freed.  Two equivalent options:
///
///   * [`Self::cancel_query`] — drop a specific handle.
///   * [`Self::sweep_terminated_queries`] — drop every query whose
///     terminal has already been delivered.
///
/// Failing to clean up exhausts a fixed-capacity `QS` pool just as the
/// leak would have, so this contract must be honoured.
pub struct Endpoint<I, R, C, SR, QS, EV, AN, EvQ> {
  config: EndpointConfig,
  rng: R,
  services: SR,
  queries: QS,
  cache: Cache<I, C>,
  pending_events: EV,
  next_service_handle: u32,
  next_query_handle: u32,
  next_txid: u16,
  /// In-progress withdrawal items, keyed by an opaque [`WithdrawalToken`].  Each
  /// entry is ONE name's TTL=0 goodbye lifecycle; a route-attached item keeps its
  /// route in `self.services` alive until the goodbye sequence completes (so the
  /// name guard continues to reject same-name re-registration).
  ///
  /// Stored as a `Vec` rather than as an inline field on [`ServiceRoute`]
  /// because `ServiceRoute` is non-generic (adding `I` there would require
  /// updating every `Pool<ServiceRoute>` / `Slab<ServiceRoute>` site across
  /// the whole workspace, including external users).
  #[cfg(any(feature = "alloc", feature = "std"))]
  withdrawals: std::vec::Vec<(WithdrawalToken, WithdrawalItem<I>)>,
  /// Monotonic source of [`WithdrawalToken`] values. Incremented on every item
  /// insert and NEVER reused, so a token names exactly the item it was minted for
  /// (or nothing, once that item drained) — there is no ABA on the poll/note key.
  #[cfg(any(feature = "alloc", feature = "std"))]
  next_withdrawal_token: u64,
  #[cfg(feature = "stats")]
  stats: std::sync::Arc<hick_trace::stats::Stats>,
  _phantom: core::marker::PhantomData<(AN, EvQ)>,
}

impl<I, R, C, SR, QS, EV, AN, EvQ> Endpoint<I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: Rng,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  /// Build a new endpoint.
  pub fn try_new(config: EndpointConfig, mut rng: R) -> Self {
    let raw_txid = rng.next_u32() as u16;
    let next_txid = if raw_txid == 0 { 1 } else { raw_txid };
    #[cfg(feature = "stats")]
    let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
    #[cfg(feature = "stats")]
    let mut cache = Cache::new();
    #[cfg(feature = "stats")]
    cache.set_stats(stats.clone());
    #[cfg(not(feature = "stats"))]
    let cache = Cache::new();
    Self {
      config,
      rng,
      services: SR::new(),
      queries: QS::new(),
      cache,
      pending_events: EV::new(),
      next_service_handle: 0,
      next_query_handle: 0,
      next_txid,
      #[cfg(any(feature = "alloc", feature = "std"))]
      withdrawals: std::vec::Vec::new(),
      #[cfg(any(feature = "alloc", feature = "std"))]
      next_withdrawal_token: 0,
      #[cfg(feature = "stats")]
      stats,
      _phantom: core::marker::PhantomData,
    }
  }

  /// Return a point-in-time snapshot of all counters and gauges.
  #[cfg(feature = "stats")]
  pub fn stats(&self) -> hick_trace::stats::StatsSnapshot {
    self.stats.snapshot()
  }

  /// Return a cloned handle to the shared [`hick_trace::stats::Stats`] so the I/O driver can
  /// bump transport-level counters (e.g. `bytes_tx`, `packets_tx`).
  #[cfg(feature = "stats")]
  pub fn stats_handle(&self) -> std::sync::Arc<hick_trace::stats::Stats> {
    self.stats.clone()
  }

  /// Returns the configuration.
  #[inline(always)]
  pub const fn config(&self) -> &EndpointConfig {
    &self.config
  }

  /// Register a new service. Returns the handle and a `Service` state-machine.
  pub fn try_register_service<TQ, EvS>(
    &mut self,
    spec: ServiceSpec,
    now: I,
  ) -> Result<(ServiceHandle, Service<I, TQ, EvS>), RegisterServiceError>
  where
    TQ: Pool<Transmit>,
    EvS: Pool<crate::event::ServiceUpdate>,
  {
    // Reject duplicate names.
    for (_, route) in self.services.iter() {
      if route.name().as_str() == spec.records().instance().as_str() {
        return Err(RegisterServiceError::NameAlreadyRegistered(
          spec.records().instance().clone(),
        ));
      }
    }
    // Also reject if a rename-COLLISION teardown's detached goodbye is still
    // HOLDING this name: the dead service's stale records must be retracted before
    // the name is reused, or a quick re-register would cancel the only TTL=0
    // goodbye and leave peers with stale PTR/SRV/TXT until TTL. A
    // SURVIVING rename's detached old name does NOT hold — it is reclaimed/
    // cancelled by the retain below.
    #[cfg(any(feature = "alloc", feature = "std"))]
    for (_, item) in self.withdrawals.iter() {
      if item.route.is_none()
        && item.holds_name
        && item.records.instance().as_str() == spec.records().instance().as_str()
      {
        return Err(RegisterServiceError::NameAlreadyRegistered(
          spec.records().instance().clone(),
        ));
      }
    }
    let new_h = self.next_service_handle;
    self.next_service_handle = self.next_service_handle.saturating_add(1);
    let handle = ServiceHandle::from_raw(new_h);

    self
      .services
      .insert(ServiceRoute {
        service_type: spec.records().service_type().clone(),
        name: spec.records().instance().clone(),
        host: spec.records().host().clone(),
        handle,
        a_addrs: spec.records().a_addrs_slice().to_vec(),
        aaaa_addrs: spec.records().aaaa_addrs_slice().to_vec(),
        aaaa_scopes: spec.records().aaaa_scopes_slice().to_vec(),
        subtypes: spec.records().subtype_names().to_vec(),
        // EMPTY at registration: a service has CONFIRMED-ADVERTISED nothing
        // until its first announce is delivered (then mirrored in here via
        // `note_service_advertised`).
        #[cfg(any(feature = "alloc", feature = "std"))]
        advertised_a: std::vec::Vec::new(),
        #[cfg(any(feature = "alloc", feature = "std"))]
        advertised_aaaa: std::vec::Vec::new(),
        withdrawing: false,
      })
      .map_err(|_| RegisterServiceError::StorageFull(StorageFullError))?;

    // NOTE: a reclaimable detached old-name goodbye for this instance name is NOT
    // cancelled here. Registration only RESERVES the name; the reclaiming service
    // probes (~750 ms, RFC 6762 §8.1) before it advertises. The reclaim-cancel now
    // fires on the CERTAIN live event — `note_service_advertised`, when this service
    // confirms it is announcing the name — not at register time, because the
    // reactor only async-commits a registration across its reply boundary and
    // cancelling here could lose the goodbye when the caller drops the registration
    // before owning the service. Until then the old goodbye keeps
    // draining; if this registration is orphaned or renames away before announcing,
    // the goodbye completes normally and retracts the old records. A name-HOLDING
    // collision goodbye still blocks reuse via the duplicate-name + holds_name scans
    // above. Auto-rename onto a reclaimable detached name is still
    // reclaimed synchronously in `handle_service_renamed`.

    let mut seed = [0u8; 32];
    self.rng.fill_bytes(&mut seed);
    // honor EndpointConfig::probe_unique_names — when disabled the
    // service skips the §8.1 probe sequence and announces immediately.
    let svc = {
      #[allow(unused_mut)]
      let mut s = Service::try_new(
        handle,
        spec.into_records(),
        now,
        seed,
        self.config.probe_unique_names(),
      );
      #[cfg(feature = "stats")]
      s.set_stats(self.stats.clone());
      s
    };
    debug!(
      target: "mdns_proto::endpoint",
      handle = handle.raw(),
      "try_register_service: service registered"
    );
    #[cfg(feature = "stats")]
    {
      self.stats.services_registered(1);
      self.stats.incr_services_active(1);
    }
    Ok((handle, svc))
  }

  /// **Force-remove** the registered service for `handle` IMMEDIATELY, with NO
  /// RFC 6762 §10.1 goodbye.
  ///
  /// This drops the route and decrements `services_active` at once: it does NOT
  /// send a TTL=0 goodbye, so peers keep the service in their caches until the
  /// records' own TTLs expire, AND the instance name is released for re-use the
  /// moment this returns. It is intended ONLY for forced / non-graceful removal
  /// (e.g. an abort path, or after a confirmed goodbye has already drained).
  ///
  /// # Prefer the graceful withdrawal lifecycle
  ///
  /// For normal teardown use the withdrawal lifecycle, which announces a §10.1
  /// goodbye AND holds the name until that goodbye is confirmed-sent — closing
  /// the same-name-reuse race this primitive deliberately does not guard:
  ///
  /// 1. [`Service::withdrawal_snapshot`](crate::service::Service::withdrawal_snapshot)
  ///    — capture the goodbye-owned records.
  /// 2. [`Self::begin_withdrawal`] — mark the route withdrawing and queue the
  ///    goodbye schedule (the route, and thus the name guard, is KEPT).
  /// 3. Pump [`Self::poll_withdrawal_transmit`] / confirm each round via
  ///    [`Self::note_withdrawal_result`] until the budget is spent.
  /// 4. [`Self::drain_completed_withdrawals`] — frees the route (releasing the
  ///    name and decrementing `services_active`) only AFTER the goodbye is
  ///    confirmed-sent, and returns the handle for driver-side GC.
  ///
  /// The drivers retire services via that lifecycle, NOT this method.
  ///
  /// # Behaviour
  ///
  /// Returns `true` if a route was found and removed, `false` if the handle
  /// was already unknown (idempotent). When this returns, re-registering the
  /// same instance name via [`Self::try_register_service`] succeeds immediately
  /// (no [`RegisterServiceError::NameAlreadyRegistered`] guard remains), and
  /// inbound packets no longer match the removed route.
  pub fn unregister_service(&mut self, handle: ServiceHandle) -> bool {
    let key = self
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle)
      .map(|(k, _)| k);
    if let Some(k) = key {
      let removed = self.services.try_remove(k).is_some();
      // Force-remove is a NO-goodbye primitive: also drop any ROUTE-attached
      // withdrawal item for this handle. Otherwise removing the route (and thus
      // the name guard) would let the same name be re-registered while a stale
      // route-attached item still owes a TTL=0 goodbye — a late goodbye would
      // then flush the same-name replacement, contradicting "no goodbye". Detached items (renamed-away OLD names) are independent of this
      // handle's route and are left to drain / be cancelled on reclaim.
      #[cfg(any(feature = "alloc", feature = "std"))]
      self
        .withdrawals
        .retain(|(_, item)| item.route != Some(handle));
      #[cfg(feature = "stats")]
      if removed {
        self.stats.decr_services_active(1);
      }
      removed
    } else {
      false
    }
  }

  /// Mint the next monotonic [`WithdrawalToken`]. Never reused.
  #[cfg(any(feature = "alloc", feature = "std"))]
  fn mint_withdrawal_token(&mut self) -> WithdrawalToken {
    let t = WithdrawalToken(self.next_withdrawal_token);
    self.next_withdrawal_token = self.next_withdrawal_token.saturating_add(1);
    t
  }

  /// Begin terminal withdrawal for `handle`.
  ///
  /// Enqueues ONE route-attached withdrawal item for the current (live /
  /// re-announced) name. The OLD instance name of an in-flight §9 rename is NOT
  /// handled here — a rename hands its old-name goodbye off the instant it
  /// happens (the driver calls [`Self::enqueue_rename_withdrawal`] after
  /// [`Self::handle_service_renamed`]), so it is already its own INDEPENDENT
  /// detached item. A teardown DURING the rename window is therefore simply two
  /// independent single-name items — that earlier detached old-name one plus this
  /// route-attached current-name one: the two never share a
  /// schedule or a datagram, so the old-name goodbye can never be starved by the
  /// current one nor dropped because their combined message overflowed `scratch`.
  ///
  /// # Route retention
  ///
  /// The route is **kept** in `self.services`: the name guard continues to
  /// reject a same-name re-registration while the route-attached item is in
  /// flight.  `services_active` is **not** decremented here — that happens in
  /// [`Self::drain_completed_withdrawals`] when that item completes.
  ///
  /// # Timing
  ///
  /// The item's `next_at` is set to `now` so its first goodbye fires
  /// immediately. `ceiling_at` is `now + WITHDRAWAL_CEILING` (2 s) — if a
  /// sequence has not completed by then it is force-finished to avoid pinning the
  /// name slot indefinitely.
  ///
  /// # Idempotency
  ///
  /// If a route-attached item already exists for `handle` (`route ==
  /// Some(handle)`) the call is a no-op: a driver may retire the same service
  /// more than once (e.g. an encode-failure escalation on an already-cancelled
  /// service) and must not enqueue a duplicate. If `handle` has no registered
  /// route the call is likewise a silent no-op.
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub fn begin_withdrawal(
    &mut self,
    handle: ServiceHandle,
    snapshot: crate::service::WithdrawalSnapshot,
    now: I,
  ) {
    // Locate the route.
    let route_key = self
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle)
      .map(|(k, _)| k);
    let Some(key) = route_key else { return };

    // Idempotency: a route-attached item already exists for this handle → do not
    // enqueue a second (a driver may retire the same service more than once).
    if self
      .withdrawals
      .iter()
      .any(|(_, w)| w.route == Some(handle))
    {
      return;
    }

    let Some(route) = self.services.get_mut(key) else {
      return;
    };
    route.withdrawing = true;

    // next_at = now (first send fires immediately); ceiling_at = now +
    // WITHDRAWAL_CEILING (hard anti-pin deadline).
    let ceiling_at = now.checked_add_duration(WITHDRAWAL_CEILING).unwrap_or(now);

    // ── route-attached item: the CURRENT (live / re-announced) name ──────────
    // Owes a goodbye iff it actually advertised an instance record OR a host
    // address; otherwise `[0, 0]` so the next `drain_completed_withdrawals` frees
    // the name at once with no spurious goodbye and no 2 s ceiling wait.
    let current_has_something =
      !snapshot.owned.is_empty() || !snapshot.host_a.is_empty() || !snapshot.host_aaaa.is_empty();
    let current_owed = if current_has_something {
      [WITHDRAWAL_SENDS, WITHDRAWAL_SENDS]
    } else {
      [0, 0]
    };

    let crate::service::WithdrawalSnapshot {
      records,
      owned,
      host_a,
      host_aaaa,
    } = snapshot;

    let token = self.mint_withdrawal_token();
    self.withdrawals.push((
      token,
      WithdrawalItem {
        records,
        owned,
        host_a,
        host_aaaa,
        owed: current_owed,
        next_at: now,
        ceiling_at,
        final_attempt: false,
        route: Some(handle),
        // Route-attached: already holds its name via the route table (the
        // duplicate-name scan in `try_register_service`), so the detached-only
        // name hold does not apply.
        holds_name: false,
      },
    ));

    debug!(
      target: "mdns_proto::endpoint",
      handle = handle.raw(),
      "begin_withdrawal: route held, goodbye schedule queued"
    );
  }

  /// Enqueue a DETACHED withdrawal item for the OLD instance name of a §9
  /// conflict rename (the renamed-away old name's TTL=0 goodbye).
  ///
  /// The driver calls this immediately after [`Self::handle_service_renamed`],
  /// passing the
  /// [`RenameGoodbyeHandoff`](crate::service::RenameGoodbyeHandoff) it took from
  /// [`Service::take_rename_goodbye_handoff`](crate::service::Service::take_rename_goodbye_handoff)
  /// (the old name's records + the per-record ownership of what it advertised).
  /// This models the old-name goodbye as an INDEPENDENT single-name withdrawal
  /// item — its own per-family debt, schedule, ceiling, and loss-resilience
  /// resends — exactly like a teardown's detached item. A teardown DURING the
  /// rename window is therefore simply two independent items (this detached
  /// old-name one, plus the route-attached current-name one from
  /// [`Self::begin_withdrawal`]); neither can starve the other nor be dropped
  /// because their combined message overflowed `scratch`.
  ///
  /// The item holds NO route (it frees nothing and is reported to nobody on
  /// completion) and NO host addresses (a rename never withdraws host A/AAAA —
  /// the host name is invariant across an instance rename). It is a **no-op when
  /// the handoff owned nothing** (the old name never advertised an instance
  /// record, so there is nothing for peers to evict).
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub fn enqueue_rename_withdrawal(
    &mut self,
    handoff: crate::service::RenameGoodbyeHandoff,
    now: I,
    holds_name: bool,
  ) {
    let crate::service::RenameGoodbyeHandoff { records, owned } = handoff;
    // Nothing for peers to evict → no item.
    if owned.is_empty() {
      return;
    }
    let ceiling_at = now.checked_add_duration(WITHDRAWAL_CEILING).unwrap_or(now);
    let token = self.mint_withdrawal_token();
    self.withdrawals.push((
      token,
      WithdrawalItem {
        records,
        owned,
        host_a: std::vec::Vec::new(),
        host_aaaa: std::vec::Vec::new(),
        owed: [WITHDRAWAL_SENDS, WITHDRAWAL_SENDS],
        next_at: now,
        ceiling_at,
        final_attempt: false,
        route: None,
        // A rename-COLLISION teardown's old name must be retracted before reuse
        // (the dead service has no live re-announcer); a SURVIVING rename's old
        // name stays reclaimable.
        holds_name,
      },
    ));
    debug!(
      target: "mdns_proto::endpoint",
      "enqueue_rename_withdrawal: detached old-name goodbye queued"
    );
  }

  /// Pump one due withdrawal datagram.  Mirrors [`Self::poll_query_transmit`]:
  /// the driver sends the returned datagram (fanned to every bound family) and
  /// then confirms it via [`Self::note_withdrawal_result`].
  ///
  /// Encodes a SINGLE `WithdrawalItem`'s TTL=0 goodbye per call. For a
  /// route-attached item (`route == Some`) a host address is withdrawn ONLY if no
  /// OTHER live route still advertises it — same-host sibling retention is
  /// recomputed FRESH each call from the route table, so siblings joining or
  /// leaving during the multi-round window are always honoured. A detached item
  /// (`route == None`) holds no host addresses, so retention does not apply and
  /// its goodbye is purely instance-only (the renamed-away old name).
  ///
  /// # Independent single-name items
  ///
  /// A teardown DURING a still-draining §9 rename owes goodbyes for TWO names —
  /// but each is its OWN item with its OWN per-family debt and schedule, so they
  /// are emitted as SEPARATE datagrams chosen independently by this scan. That
  /// fixes two bugs at the root:
  ///   * a rename-ONLY teardown still emits the old name (it is a separate
  ///     detached item that owes a full budget, never folded into an empty
  ///     current item); and
  ///   * neither datagram can be "combined too large" — each carries one name, so
  ///     two names that each fit `scratch` individually are BOTH emitted even when
  ///     their combined message would not, and an unencodable item never starves
  ///     the other.
  ///
  /// # Retained-only / empty items do not head-of-line block
  ///
  /// A route-attached item can have NOTHING left to put on the wire — it owns no
  /// instance records and every host address it advertised is still retained by
  /// a LIVE same-host sibling.  Such an item is COMPLETED in place
  /// (`owed = [0, 0]`, freed by the next [`Self::drain_completed_withdrawals`])
  /// and the scan CONTINUES, rather than returning `None`.  Completing it at once
  /// is correct: a live sibling legitimately still advertises those addresses, and
  /// when that sibling later leaves ITS own item withdraws them.  Returning `None`
  /// here would (a) leave the item due forever — re-waking `poll_timeout` until its
  /// 2 s ceiling — and (b) stop the driver's `while let Some(..)` pump loop,
  /// starving any later same-time item that genuinely needs a TTL=0 goodbye.
  ///
  /// # An encode failure ADVANCES the item rather than blocking
  ///
  /// If the goodbye encoder returns an error for the chosen item (e.g. its
  /// goodbye does not fit `scratch`), this does NOT return
  /// `None` — that would leave the failing item first-due at this `now`
  /// and stop the driver pump loop before later due items are reached.
  /// Instead the failing item's `next_at` is pushed past `now`
  /// (`now + WITHDRAWAL_RETRY_BACKOFF`, its debt budget intact) and the scan
  /// CONTINUES, so another item that genuinely has an emittable goodbye is still
  /// served this pass.  The 2 s ceiling remains the backstop for an item
  /// whose goodbye can never be encoded.  The loop still terminates: every
  /// iteration either returns a datagram, completes an item, or pushes one
  /// past `now`.
  ///
  /// Returns `(multicast dst, datagram length, the item's [`WithdrawalToken`])`
  /// for the first due item that actually has records to emit, or `None` when no
  /// due item has anything to send (the empty/retained-only ones having been
  /// marked complete; the encode-failing ones having been pushed past `now`).
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub fn poll_withdrawal_transmit(
    &mut self,
    now: I,
    scratch: &mut [u8],
  ) -> Option<(SocketAddr, usize, WithdrawalToken)> {
    loop {
      // An item is selectable when it still owes a round (`owed != [0, 0]`) AND
      // either:
      //   * it is DUE within the normal window — `next_at <= now < ceiling_at`; or
      //   * it is PAST the ceiling but has not yet had its one FINAL ceiling
      //     attempt (`now >= ceiling_at && !final_attempt`).  This is the
      //     guarantee: if the last backoff overshot `ceiling_at`, the still-owed
      //     family would otherwise never be tried in the `[last_attempt, ceiling]`
      //     window and the route would be force-freed with debt owed.  The
      //     `!final_attempt` guard makes this branch fire AT MOST ONCE per item,
      //     so the loop always terminates (drain then force-completes it).  An
      //     item whose debt is `[0, 0]` no longer matches, so the scan advances
      //     past it on the next turn.
      let (idx, token, route, is_final) =
        self
          .withdrawals
          .iter()
          .enumerate()
          .find_map(|(i, (tok, w))| {
            if w.owed == [0, 0] {
              return None;
            }
            if w.next_at <= now && now < w.ceiling_at {
              Some((i, *tok, w.route, false))
            } else if now >= w.ceiling_at && !w.final_attempt {
              Some((i, *tok, w.route, true))
            } else {
              None
            }
          })?;

      // Sibling-retained host addresses, recomputed each round into an owned Vec
      // (releasing the `self.services` borrow before we read the item + write
      // `scratch`).  An address some OTHER same-host route still advertises must
      // NOT be withdrawn.  ONLY a route-attached item withdraws host addresses; a
      // detached item has empty host lists, so skip the (route-table) scan for it.
      let retained = match route {
        Some(handle) => self.sibling_retained_addrs(handle),
        None => std::vec::Vec::new(),
      };

      // Read the item under a SCOPED borrow dropped before any mutation.
      // (`.get(idx)` cannot be `None` — `idx` came from the scan above — but it
      // sidesteps the `indexing_slicing` lint with no panic path.)
      let (_, w) = self.withdrawals.get(idx)?;
      let owned = &w.owned;
      let has_something = owned.ptr()
        || owned.srv()
        || owned.txt()
        || owned.subtypes()
        || w
          .host_a
          .iter()
          .any(|ip| !retained.contains(&core::net::IpAddr::V4(*ip)))
        || w
          .host_aaaa
          .iter()
          .any(|ip| !retained.contains(&core::net::IpAddr::V6(*ip)));

      // Nothing left to withdraw (no owned instance records and every advertised
      // host address still retained by a sibling) → COMPLETE this item now
      // (`owed = [0, 0]`) and keep scanning; drain frees it. A final-ceiling
      // selection with nothing to emit is also handled here — zeroing the debt
      // lets drain free it without needing `final_attempt`.
      if !has_something {
        if let Some((_, w)) = self.withdrawals.get_mut(idx) {
          w.owed = [0, 0];
        }
        continue;
      }

      // Encode this name's single-name goodbye via the existing single-name
      // encoder: its emitted instance records + the sibling-filtered host
      // addresses. A detached item passes EMPTY host iterators (its lists are
      // empty), so `write_goodbye` produces an instance-only old-name goodbye —
      // no separate `write_rename_goodbye` path is needed.
      let encoded = crate::service::write_goodbye(
        &w.records,
        scratch,
        owned.ptr(),
        owned.srv(),
        owned.txt(),
        owned.subtypes(),
        w.host_a
          .iter()
          .copied()
          .filter(|ip| !retained.contains(&core::net::IpAddr::V4(*ip))),
        w.host_aaaa
          .iter()
          .copied()
          .filter(|ip| !retained.contains(&core::net::IpAddr::V6(*ip))),
      );
      match encoded {
        Ok(len) => {
          if is_final && let Some((_, w)) = self.withdrawals.get_mut(idx) {
            w.final_attempt = true;
          }
          return Some((crate::service::multicast_dst(), len, token));
        }
        Err(_) => {
          self.advance_after_encode_failure(idx, now, is_final);
          continue;
        }
      }
    }
  }

  /// Encode-failure scan-progress for one withdrawal item.
  ///
  /// An item whose goodbye does not fit `scratch` must NOT head-of-line block the
  /// pump at `now`. For a NORMAL (non-final) attempt this pushes `next_at`
  /// strictly past `now` (`now + WITHDRAWAL_RETRY_BACKOFF`, the item's debt budget
  /// intact) so the due scan won't re-select it this call; if the `Instant`
  /// saturated (the backoff cannot advance past `now`) the item's debt is zeroed
  /// so it can never be re-selected as due and re-fail forever (abandoning a
  /// goodbye we can neither encode nor reschedule is benign — the ceiling would
  /// force-complete it anyway). For the one FINAL ceiling attempt that could not
  /// be encoded, `final_attempt` is set so the past-ceiling scan branch cannot
  /// re-select this item forever; the next `drain_completed_withdrawals`
  /// force-completes it.
  #[cfg(any(feature = "alloc", feature = "std"))]
  fn advance_after_encode_failure(&mut self, idx: usize, now: I, is_final: bool) {
    let Some((_, w)) = self.withdrawals.get_mut(idx) else {
      return;
    };
    if is_final {
      // This WAS the final-ceiling attempt and it could not be encoded: burn it
      // so the past-ceiling scan branch cannot re-select this item forever (its
      // goodbye is unencodable). The next `drain_completed_withdrawals`
      // force-completes it — benign, as a permanently-unencodable goodbye is
      // abandoned anyway.
      w.final_attempt = true;
      return;
    }
    match now.checked_add_duration(WITHDRAWAL_RETRY_BACKOFF) {
      // Advanced strictly past `now`: the due scan won't re-select it this call,
      // so the loop makes progress.
      Some(t) if t > now => w.next_at = t,
      // The Instant saturated (backoff cannot advance past `now`): zero the
      // item's debt so it can never be re-selected as due — otherwise this same
      // item would be re-chosen and re-fail forever.
      _ => w.owed = [0, 0],
    }
  }

  /// Record the host addresses a service has CONFIRMED-ADVERTISED on the wire,
  /// overwriting the route's advertised set.  The driver calls this after a
  /// confirmed-delivered service announce with the Service's current
  /// [`Service::advertised_a_addrs`]/[`Service::advertised_aaaa_addrs`] sets
  /// (the confirmed-emitted / goodbye-owned host addresses).
  ///
  /// This is the set sibling host-address retention consults to decide which
  /// host addresses a withdrawing same-host sibling must RETAIN — distinct from
  /// the configured [`ServiceRoute::a_addrs`] captured at registration (which a
  /// never-announced service has, despite having advertised nothing).
  ///
  /// Idempotent overwrite (the advertised set only grows as the service
  /// announces), and a no-op for an unknown handle.
  ///
  /// [`Service::advertised_a_addrs`]: crate::service::Service::advertised_a_addrs
  /// [`Service::advertised_aaaa_addrs`]: crate::service::Service::advertised_aaaa_addrs
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub fn note_service_advertised(
    &mut self,
    handle: ServiceHandle,
    a: &[Ipv4Addr],
    aaaa: &[Ipv6Addr],
    advertised_instance: bool,
  ) {
    let name = {
      let Some((_, route)) = self.services.iter_mut().find(|(_, r)| r.handle() == handle) else {
        return;
      };
      route.advertised_a.clear();
      route.advertised_a.extend_from_slice(a);
      route.advertised_aaaa.clear();
      route.advertised_aaaa.extend_from_slice(aaaa);
      route.name().clone()
    };
    // CANCEL-ON-ANNOUNCE: a service that has CONFIRMED-ADVERTISED
    // its instance records under `name` supersedes any RECLAIMABLE detached
    // old-name goodbye for the same name — cancel it. This lives here, on a certain
    // live event, rather than in `try_register_service` (a registration is only
    // async-committed across the reactor's reply boundary; cancelling at register
    // time could lose the goodbye if the caller dropped the registration before
    // owning the service — ).
    //
    // The cancel is GATED on `advertised_instance`: this hook is called after EVERY
    // delivered service transmit, INCLUDING probes, so cancelling on a probe would
    // drop the goodbye before the reclaiming service ever announced — losing the
    // retraction if it then drops, conflicts, or renames away. The
    // address args cannot serve as the guard (an address-less service advertises no
    // host addresses), so `Service::advertises_instance` is the precise signal. If
    // the new service never announces, the goodbye is NEVER cancelled and completes
    // normally. A name-HOLDING collision goodbye is left intact.
    #[cfg(any(feature = "alloc", feature = "std"))]
    if advertised_instance {
      self.withdrawals.retain(|(_, item)| {
        !(item.route.is_none()
          && !item.holds_name
          && item.records.instance().as_str() == name.as_str())
      });
    }
  }

  /// Host addresses that a LIVE same-host SIBLING route (any non-withdrawing
  /// route other than `handle`'s) still ADVERTISES — these must be RETAINED (not
  /// withdrawn) by `handle`'s goodbye, since another live service still owns
  /// them in peer caches.  This is the per-driver `retained_host_addrs` scan,
  /// centralised here where the endpoint holds every route's advertised set.
  ///
  /// Two exclusions matter for correctness:
  ///   * `route.withdrawing` siblings are SKIPPED — a sibling that is itself
  ///     leaving owns nothing to retain (e.g. a simultaneous same-host shutdown:
  ///     neither service must pin the shared address for the other).
  ///   * the CONFIRMED-ADVERTISED set (`advertised_a`/`advertised_aaaa`) is used,
  ///     NOT the configured `a_addrs`/`aaaa_addrs` — a registered-but-never-
  ///     announced sibling has configured addresses but advertised none, so it
  ///     retains nothing.
  #[cfg(any(feature = "alloc", feature = "std"))]
  fn sibling_retained_addrs(&self, handle: ServiceHandle) -> std::vec::Vec<core::net::IpAddr> {
    let Some(host) = self
      .services
      .iter()
      .find_map(|(_, r)| (r.handle() == handle).then(|| r.host().clone()))
    else {
      return std::vec::Vec::new();
    };
    let mut retained = std::vec::Vec::new();
    for (_, route) in self.services.iter() {
      if route.handle() != handle && !route.withdrawing && route.host() == &host {
        retained.extend(
          route
            .advertised_a()
            .iter()
            .copied()
            .map(core::net::IpAddr::V4),
        );
        retained.extend(
          route
            .advertised_aaaa()
            .iter()
            .copied()
            .map(core::net::IpAddr::V6),
        );
      }
    }
    retained
  }

  /// Confirm the datagram most recently produced by
  /// [`Self::poll_withdrawal_transmit`] for `token`, reporting the outcome for
  /// EACH address family ([`WithdrawalSend`] for `v4` and `v6`) so withdrawal
  /// debt is tracked PER FAMILY. The token names exactly one
  /// `WithdrawalItem`, so no in-flight-part disambiguation is needed.
  ///
  /// Per family `f`:
  ///   * [`WithdrawalSend::Sent`] — the goodbye reached that family's wire, so
  ///     spend one of its owed rounds (`owed[f] = owed[f].saturating_sub(1)`).
  ///   * [`WithdrawalSend::Retry`] — transiently undeliverable (socket busy):
  ///     keep that family's debt for a later retry.
  ///   * [`WithdrawalSend::WriteOff`] — that family is permanently unavailable
  ///     (no socket / permanent send error): zero its debt (`owed[f] = 0`), since
  ///     it has no reachable peers to withdraw from.
  ///
  /// `next_at` re-arms at the full `WITHDRAWAL_INTERVAL` when a family made REAL
  /// progress this round — a `Sent` for a family that still OWED a goodbye
  /// (`owed[f] > 0` before this round). A `Sent` for an already-paid family
  /// (`owed[f] == 0`) is a redundant fan-out and is NOT progress: otherwise a
  /// paid v4 echoing `Sent` every round would keep re-arming at the full interval
  /// and starve a still-busy v6 of its short-backoff retry (risking a missed
  /// last-interval v6 recovery before the ceiling).  When no family made real
  /// progress (both `Retry`, or `Retry`+`WriteOff`, or only an already-paid family
  /// `Sent` while the other is busy) it re-arms at the short
  /// `WITHDRAWAL_RETRY_BACKOFF` so the still-owed family is retried soon rather
  /// than delayed a full interval.  Completion (every family's debt cleared, or the
  /// ceiling) is observed via `drain_completed_withdrawals`.
  ///
  /// An item therefore frees its route (route-attached) only once EVERY reachable
  /// family has withdrawn its records: v4-success while v6 stays busy does NOT
  /// complete it, so if v6 recovers before the 2 s ceiling its peers still receive
  /// the TTL=0 goodbye.
  ///
  /// No-op for an unknown token.
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub fn note_withdrawal_result(
    &mut self,
    token: WithdrawalToken,
    now: I,
    v4: WithdrawalSend,
    v6: WithdrawalSend,
  ) {
    let Some((_, w)) = self.withdrawals.iter_mut().find(|(t, _)| *t == token) else {
      return;
    };
    let mut progressed = false;
    // Zip each family's debt counter (by mutable reference) with its outcome to
    // avoid dynamic indexing (clippy::indexing_slicing) into `owed`.
    //
    // A `Sent` counts as progress ONLY when that family still OWED a goodbye
    // before this round (`*debt > 0`). Drivers fan every round's datagram to BOTH
    // families, so a family whose debt is already 0 keeps reporting `Sent`; if that
    // redundant send counted as progress it would re-arm at the FULL interval and
    // starve a still-busy family of its short-backoff retry, risking a missed
    // last-interval recovery before the ceiling. So a `Sent` on an already-paid
    // family changes nothing — neither the debt nor the schedule.
    let owed = &mut w.owed;
    for (debt, outcome) in owed.iter_mut().zip([v4, v6]) {
      match outcome {
        WithdrawalSend::Sent if *debt > 0 => {
          // `*debt > 0` here, so this is `-= 1`; `saturating_sub` keeps it free of
          // `clippy::arithmetic_side_effects` (denied workspace-wide).
          *debt = debt.saturating_sub(1);
          progressed = true;
        }
        // Redundant send on an already-paid family (`*debt == 0`): no progress.
        WithdrawalSend::Sent => {}
        WithdrawalSend::Retry => {}
        WithdrawalSend::WriteOff => *debt = 0,
      }
    }
    // Progress (>= 1 family sent) → full interval; otherwise the short backoff so
    // a transiently-busy family is retried soon. A pure write-off round (no Sent)
    // also takes the short backoff, but its `owed` is already cleared so it will
    // not be re-selected as due unless the OTHER family still owes.
    //
    // CLAMP the re-arm to `ceiling_at`: a backoff that overshot the
    // ceiling would skip the `[last_attempt, ceiling]` window entirely, so a
    // family recovering in that window would never be retried in the normal due
    // window — the route would be force-freed with debt owed. Clamping keeps the
    // last scheduled attempt at the ceiling, where `poll_withdrawal_transmit`'s
    // past-ceiling branch then emits exactly one final goodbye.
    let gap = if progressed {
      WITHDRAWAL_INTERVAL
    } else {
      WITHDRAWAL_RETRY_BACKOFF
    };
    w.next_at = now
      .checked_add_duration(gap)
      .unwrap_or(now)
      .min(w.ceiling_at);
  }

  /// Remove every withdrawal ITEM that has COMPLETED — either every family's
  /// resend budget is spent or written off (`owed == [0, 0]`), OR it has passed
  /// its anti-pin ceiling (`now >= ceiling_at`) AND its one final ceiling attempt
  /// has been made (`final_attempt`).
  ///
  /// For each completed item:
  ///   * a ROUTE-attached item (`route == Some(handle)`) frees its proto route —
  ///     releasing the name for re-registration and decrementing
  ///     `services_active` — and pushes `handle` into `out` so the driver can GC
  ///     its driver-side slot;
  ///   * a DETACHED item (`route == None`, a renamed-away old name) is simply
  ///     removed: it owns no route, holds no name, and is reported to NOBODY (push
  ///     nothing into `out`).
  ///
  /// Call once per pump, after draining withdrawal transmits.
  ///
  /// The ceiling guarantees that an item whose families are permanently
  /// unreachable still completes (and a route-attached one releases its name) — a
  /// down family has no reachable peers to evict, so force-completing it is
  /// benign.
  ///
  /// The `final_attempt` conjunct gives an owed family ONE last
  /// goodbye AT the ceiling before the item is removed: an item that is past
  /// `ceiling_at` but still owes a family AND has not yet been final-attempted is
  /// NOT completed here — it is left for the very next `poll_withdrawal_transmit`,
  /// whose past-ceiling branch emits that final goodbye and sets `final_attempt`,
  /// after which this method removes it. The drivers always pump
  /// `poll_withdrawal_transmit` (then `note_withdrawal_result`) before this call,
  /// so the final attempt and the free happen within the same pump cycle. An
  /// unencodable / nothing-to-emit goodbye sets `final_attempt` (or zeroes `owed`)
  /// in `poll_withdrawal_transmit` too, so a route can never be pinned past the
  /// ceiling waiting for a final attempt that can't be made.
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub fn drain_completed_withdrawals<E: Extend<ServiceHandle>>(&mut self, now: I, out: &mut E) {
    // Collect completed tokens first so the route/withdrawal removals below do
    // not fight the iteration borrow.
    let completed: std::vec::Vec<WithdrawalToken> = self
      .withdrawals
      .iter()
      .filter(|(_, w)| w.owed == [0, 0] || (now >= w.ceiling_at && w.final_attempt))
      .map(|(t, _)| *t)
      .collect();
    for token in completed {
      // Take the item out; a route-attached one frees its route + reports the
      // handle, a detached one just vanishes.
      let Some(pos) = self.withdrawals.iter().position(|(t, _)| *t == token) else {
        continue;
      };
      let (_, item) = self.withdrawals.remove(pos);
      let Some(handle) = item.route else {
        // Detached (renamed-away old name): no route, no name, report to nobody.
        continue;
      };
      // Free the proto route: releases the name and decrements services_active.
      let key = self
        .services
        .iter()
        .find(|(_, route)| route.handle() == handle)
        .map(|(k, _)| k);
      if let Some(k) = key {
        let removed = self.services.try_remove(k).is_some();
        #[cfg(feature = "stats")]
        if removed {
          self.stats.decr_services_active(1);
        }
        #[cfg(not(feature = "stats"))]
        let _ = removed;
      }
      out.extend(core::iter::once(handle));
    }
  }

  /// Test-only: the opaque token of the ROUTE-attached withdrawal item for
  /// `handle`, so a test can confirm/round-trip exactly that item's send. `None`
  /// if no route-attached item exists for `handle`.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  fn route_withdrawal_token(&self, handle: ServiceHandle) -> Option<WithdrawalToken> {
    self
      .withdrawals
      .iter()
      .find(|(_, w)| w.route == Some(handle))
      .map(|(t, _)| *t)
  }

  /// Test-only: confirm a send for the ROUTE-attached item of `handle` by looking
  /// up its token internally (a no-op if the item is gone). Lets handle-oriented
  /// tests spend a route withdrawal's debt without threading the token through.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  fn note_route_withdrawal_result(
    &mut self,
    handle: ServiceHandle,
    now: I,
    v4: WithdrawalSend,
    v6: WithdrawalSend,
  ) {
    if let Some(tok) = self.route_withdrawal_token(handle) {
      self.note_withdrawal_result(tok, now, v4, v6);
    }
  }

  /// Test-only: the PER-FAMILY resend budget (`[v4, v6]`) of the ROUTE-attached
  /// withdrawal item for `handle` (the current-name goodbye), or `None` if no
  /// such item exists.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  fn route_withdrawal_owed(&self, handle: ServiceHandle) -> Option<[u8; 2]> {
    self
      .withdrawals
      .iter()
      .find(|(_, w)| w.route == Some(handle))
      .map(|(_, w)| w.owed)
  }

  /// Test-only: the PER-FAMILY resend budget (`[v4, v6]`) of the DETACHED
  /// withdrawal item whose records name `instance` (the renamed-away old-name
  /// goodbye), or `None` if no such item exists.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  fn detached_withdrawal_owed_for(&self, instance: &Name) -> Option<[u8; 2]> {
    self
      .withdrawals
      .iter()
      .find(|(_, w)| {
        w.route.is_none()
          && w
            .records
            .instance()
            .as_str()
            .eq_ignore_ascii_case(instance.as_str())
      })
      .map(|(_, w)| w.owed)
  }

  /// Test-only: the next scheduled send time of the ROUTE-attached withdrawal
  /// item for `handle`.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  fn route_withdrawal_next_at(&self, handle: ServiceHandle) -> Option<I> {
    self
      .withdrawals
      .iter()
      .find(|(_, w)| w.route == Some(handle))
      .map(|(_, w)| w.next_at)
  }

  /// Start a new query.
  ///
  /// The [`Query`] state machine is owned by the endpoint and driven via
  /// the `*_query*` accessors (`poll_query`, `poll_query_timeout`,
  /// `poll_query_transmit`, `handle_query_timeout`, `cancel_query`,
  /// `collected_answers`).
  ///
  /// When the query reaches a terminal state (`Timeout` or `Done`),
  /// [`Self::poll_query`] returns the terminal update exactly once and
  /// the state machine becomes frozen: `collected_answers(h)` remains
  /// readable, but no further answers are applied and no further
  /// `QueryEvent::Answer` events fire for `h`.  The caller MUST
  /// eventually free the pool slot via [`Self::cancel_query`] (or use
  /// [`Self::sweep_terminated_queries`] for bulk cleanup) — terminated
  /// queries are NOT auto-pruned.
  ///
  /// # Errors
  ///
  /// Returns [`StartQueryError::StorageFull`] if the query pool cannot
  /// accept another entry.
  pub fn try_start_query(
    &mut self,
    spec: QuerySpec,
    now: I,
  ) -> Result<QueryHandle, StartQueryError> {
    let new_h = self.next_query_handle;
    self.next_query_handle = self.next_query_handle.saturating_add(1);
    let handle = QueryHandle::from_raw(new_h);

    let txid = self.next_txid;
    // next_txid wraps but skip 0.
    let next_raw = self.next_txid.wrapping_add(1);
    self.next_txid = if next_raw == 0 { 1 } else { next_raw };

    let timeout_deadline = spec.timeout().and_then(|dur| now.checked_add_duration(dur));
    let mut q = Query::try_new(
      handle,
      spec.qname().clone(),
      spec.qtype(),
      spec.qclass(),
      txid,
      spec.unicast_response(),
      timeout_deadline,
    );
    #[cfg(feature = "stats")]
    q.set_stats(self.stats.clone());
    if let Some(m) = spec.max_answers() {
      q.set_max_answers(m);
    }
    // q must be `mut` for set_max_answers above; allow for stats-only build.

    self
      .queries
      .insert(q)
      .map_err(|_| StartQueryError::StorageFull(StorageFullError))?;
    debug!(
      target: "mdns_proto::endpoint",
      handle = handle.raw(),
      qtype = ?spec.qtype(),
      txid,
      "try_start_query: query started"
    );
    #[cfg(feature = "stats")]
    {
      self.stats.queries_started(1);
      self.stats.incr_queries_active(1);
    }
    Ok(handle)
  }

  /// Is `addr` advertised by any registered service?  Used by `handle` to
  /// detect multicast-loopback datagrams whose source address matches an
  /// IP we are publishing.  Linear scan over routes;
  /// bounded by the number of registered services + their per-route
  /// address slice.
  ///
  /// `interface_index` is the receiving interface index (from PKTINFO),
  /// used for IPv6 link-local scope matching: without it, the
  /// same `fe80::*` advertised on a different interface would falsely
  /// classify a peer packet as self.  For IPv4 and for non-link-local
  /// IPv6 the scope check is bypassed.
  fn src_matches_advertised(&self, addr: IpAddr, interface_index: u32) -> bool {
    match addr {
      IpAddr::V4(v4) => self
        .services
        .iter()
        .any(|(_, route)| route.a_addrs().contains(&v4)),
      IpAddr::V6(v6) => {
        // Link-local IPv6 addresses (fe80::/10) are scoped per interface;
        // global / unique-local addresses are not.
        let is_link_local = matches!(v6.segments()[0], 0xfe80..=0xfebf);
        self.services.iter().any(|(_, route)| {
          let addrs = route.aaaa_addrs();
          let scopes = route.aaaa_scopes();
          // Defensive: `aaaa_scopes` is the parallel scope slice, but if a
          // future code path produces an unbalanced length we degrade to
          // the bare-address match rather than mismatch-and-panic.
          for (i, a) in addrs.iter().enumerate() {
            if *a != v6 {
              continue;
            }
            if !is_link_local {
              return true;
            }
            let scope = scopes.get(i).copied().unwrap_or(0);
            if scope == 0 || scope == interface_index {
              return true;
            }
          }
          false
        })
      }
    }
  }

  /// Process an incoming datagram. Returns an iterator over routing
  /// decisions; the iterator borrows from `data` and from `self`.
  ///
  /// `local_ip` is the address of the interface that received the datagram
  /// (as reported by IP_PKTINFO / IPV6_PKTINFO on Unix).  When the packet's
  /// source IP equals `local_ip` the datagram is treated as a self-originated
  /// multicast loopback: cache population and event routing are both
  /// suppressed so we do not interpret our own probes/announcements as peer
  /// conflicts, KAS hints, or query answers.
  ///
  /// `interface_index` is the receiving interface index (typically
  /// `if_nametoindex(3)` / PKTINFO `ipi_ifindex` / `ipi6_ifindex`).  It
  /// disambiguates IPv6 link-local self-loopback on multi-homed hosts:
  /// a peer reusing the same `fe80::*` on a different interface
  /// must NOT be classified as self.  Pass `0` if the receiving interface
  /// is unknown — link-local self-loopback detection then degrades
  /// gracefully (matches only AAAA entries registered with
  /// [`ServiceRecords::add_aaaa`] or [`add_aaaa_scoped`] with scope `0`).
  ///
  /// `caller_is_self` is the AUTHORITATIVE self-loopback signal:
  /// pass `true` when the I/O layer has determined — by content-matching
  /// the datagram against a recent outgoing packet, ordered by the kernel
  /// receive timestamp — that this is our OWN multicast loopback. When
  /// `true`, all side effects are suppressed (no peer-conflict, KAS, cache
  /// writes, or query answers). Callers that cannot make that
  /// determination (sync / single-process responders) pass `false` and may
  /// instead opt into the coarser advertised-source fallback via
  /// [`EndpointConfig::with_trust_advertised_src_as_self`].
  ///
  /// [`add_aaaa_scoped`]: crate::records::ServiceRecords::add_aaaa_scoped
  /// [`ServiceRecords::add_aaaa`]: crate::records::ServiceRecords::add_aaaa
  /// [`EndpointConfig::with_trust_advertised_src_as_self`]: crate::EndpointConfig::with_trust_advertised_src_as_self
  #[allow(clippy::type_complexity)]
  pub fn handle<'a, 'e>(
    &'e mut self,
    now: I,
    src: SocketAddr,
    local_ip: IpAddr,
    interface_index: u32,
    data: &'a [u8],
    caller_is_self: bool,
  ) -> Result<RouteEvents<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ>, HandleError> {
    #[cfg(feature = "tracing")]
    let _span = trace_span!("handle", src = %src, len = data.len()).entered();
    #[cfg(feature = "stats")]
    {
      self.stats.packets_rx(1);
      #[allow(clippy::cast_possible_truncation)]
      self.stats.bytes_rx(data.len() as u64);
    }

    let reader = MessageReader::try_parse(data).map_err(|e| {
      warn!(
        target: "mdns_proto::endpoint",
        src = %src,
        "handle: failed to parse incoming datagram"
      );
      #[cfg(feature = "stats")]
      self.stats.parse_errors(1);
      HandleError::Parse(e)
    })?;
    if !reader.header().flags().opcode().is_query() {
      #[cfg(feature = "stats")]
      self.stats.packets_dropped(1);
      return Err(HandleError::InvalidOpcode(reader.header().flags().opcode()));
    }
    if !reader.header().flags().response_code().is_no_error() {
      #[cfg(feature = "stats")]
      self.stats.packets_dropped(1);
      return Err(HandleError::InvalidResponseCode(
        reader.header().flags().response_code(),
      ));
    }
    let is_response = reader.header().flags().is_response();
    // Self-loopback detection. The AUTHORITATIVE per-Endpoint self
    // signal is provided by the CALLER via `caller_is_self`. The driver
    // computes it by content-matching the datagram against packets it
    // recently sent, ordered by the kernel receive timestamp — facilities
    // that live naturally in the std I/O layer, not in this `no_std`
    // protocol core. Routing our own multicast loopback as a peer packet
    // would cause false ProbeConflicts (self-rename), false HostConflicts,
    // spurious KAS suppression, and double cache writes, so we suppress all
    // side effects when the caller flags the datagram as self.
    //
    // we deliberately do NOT use `src == local_ip` as a self
    // signal. PKTINFO's local receive address is HOST/interface-level —
    // every same-host mDNS sender egresses from the same interface IP, so
    // `src == local_ip` would suppress legitimate co-resident peers and
    // hide same-host name conflicts. `local_ip` / `interface_index` remain
    // available for the opt-in advertised-source check below, which is
    // interface-scoped for IPv6 link-local.
    //
    // `src_matches_advertised` is an OPT-IN fallback
    // (`EndpointConfig::trust_advertised_src_as_self`, default off) for
    // single-process / sync callers that cannot supply `caller_is_self`.
    let _ = local_ip;
    let matched_advertised = self.config.trust_advertised_src_as_self()
      && self.src_matches_advertised(src.ip(), interface_index);
    let is_self_packet = caller_is_self || matched_advertised;
    // RFC 6762 — a Multicast DNS RESPONSE (QR=1) is only
    // trustworthy when it originates from UDP source port 5353. A response
    // from an ephemeral port is an off-path/legacy-unicast artifact that must
    // not be allowed to populate the cache, answer active queries, or drive
    // service conflicts. QUERIES (QR=0) are exempt — legacy unicast queriers
    // legitimately use ephemeral source ports (RFC 6762 §6.7) and we must
    // still respond to them. We fold the untrusted-response case into the
    // same all-side-effects suppression as a self packet.
    let untrusted_response = is_response && src.port() != crate::constants::MDNS_PORT;
    let suppress_side_effects = is_self_packet || untrusted_response;

    // ── Single eager section-validation latch ──────────────────────────────
    // Walk ALL FOUR sections (questions, answers, authority, additional) once
    // to detect whether any record in any section fails to parse.  If so,
    // bump `parse_errors(1)` exactly once per datagram.
    //
    // Precedence rule (exactly-one reject counter invariant):
    //   Suppression (`packets_dropped`) takes precedence over malformed-section
    //   `parse_errors`.  A suppressed datagram (self-loopback or untrusted
    //   QR=1 response from a non-5353 source) is dropped wholesale — we never
    //   process it — so `packets_dropped` is the sole meaningful reject counter
    //   and the malformation is moot.  Running the latch for a suppressed packet
    //   would bump BOTH `parse_errors` AND `packets_dropped`, violating the
    //   exactly-one-reject-per-packets_rx invariant.  Therefore the latch only
    //   runs when `!suppress_side_effects`.
    //
    // Counters per case:
    //   • suppressed (self-loopback or untrusted QR=1), malformed or not
    //       → `packets_dropped(1)` only (latch skipped)
    //   • not-suppressed, malformed section
    //       → `parse_errors(1)` only (latch fires)
    //   • not-suppressed, well-formed
    //       → 0 reject counters (latch fires, finds nothing)
    //   • header parse fail / invalid opcode / invalid rcode
    //       → their own single counter (unchanged, precede this point)
    //
    // The latch also catches errors in sections skipped by the routing iterator:
    //   • `answer_questions=false` → Questions arm skipped; latch still walks it
    //   • non-5353 source port → Authority conflict-routing skipped; latch walks
    //     authority regardless (port gate governs routing, not byte-validity)
    //
    // Protocol-behaviour contract: this validation ONLY adds accounting.
    // It does NOT introduce new drops or change which records get processed
    // by the routing iterator — lenient routing (process valid parts) is
    // preserved.
    //
    // NOTE on non-5353-source authority suppression: a well-formed
    // authority record from a non-5353 source is suppressed by the routing
    // iterator's Authority gate, but the DATAGRAM is still processed (its
    // question/answer/additional sections are still routed).  A section-level
    // suppression where the datagram's OTHER sections continue to be
    // processed is NOT a datagram drop, so no `packets_dropped` is bumped.
    // `packets_dropped` counts only whole-datagram rejects (invalid opcode,
    // invalid rcode, self-loopback, untrusted response).  A code comment
    // in the Authority arm documents this decision.
    #[cfg(feature = "stats")]
    if !suppress_side_effects {
      let mut section_parse_error = false;
      // Questions: walk regardless of `answer_questions` config —
      // a malformed question byte-stream is a datagram-level error.
      if !section_parse_error {
        for q in reader.questions() {
          if q.is_err() {
            section_parse_error = true;
            break;
          }
        }
      }
      // Answers + Additional: chained, matching the eager walk below.
      if !section_parse_error {
        for r in reader.answers().chain(reader.additional()) {
          if r.is_err() {
            section_parse_error = true;
            break;
          }
        }
      }
      // Authority: walk regardless of `src.port()` — the port gate only
      // governs conflict routing, not whether the bytes are well-formed.
      if !section_parse_error {
        for r in reader.authority() {
          if r.is_err() {
            section_parse_error = true;
            break;
          }
        }
      }
      if section_parse_error {
        self.stats.parse_errors(1);
      }
    }

    trace!(
      target: "mdns_proto::endpoint",
      src = %src,
      local_ip = %local_ip,
      interface_index,
      is_response,
      is_self_packet,
      data_len = data.len(),
      "handle: routing inbound packet"
    );
    if suppress_side_effects {
      debug!(
        target: "mdns_proto::endpoint",
        src = %src,
        is_self_packet,
        untrusted_response,
        "handle: suppressed self/untrusted packet"
      );
      #[cfg(feature = "stats")]
      self.stats.packets_dropped(1);
    }
    // + cache population: walk the answer section ONCE, eagerly
    // applying side effects so that dropping the returned `RouteEvents`
    // iterator early cannot lose state:
    //   1. populate the passive-observation cache (RFC 6762 §10);
    //   2. for response packets (QR=1), apply `QueryEvent::Answer` to
    //      every name/type-compatible owned `Query` state machine.
    //
    // Iterating answers a single time and dispatching both side effects
    // here keeps the receive path allocation-free w.r.t. fan-out
    // bookkeeping (no Vec of matching keys — `Pool::iter_mut` lets us
    // mutate matching queries in-place).
    if !suppress_side_effects {
      let populate_cache = self.config.populate_cache();
      // per-packet tracking of `(name, rtype)` pairs that have
      // already had their cache-flush eviction applied.  RFC 6762 §10.2
      // says that on cache-flush the receiver should consider all OTHER
      // cached records for the same `(name, rtype)` to be expired —
      // crucially, "other" excludes the records arriving in the same
      // datagram.  The previous implementation evicted on every
      // cache-flush record, so a multi-A announcement for one host
      // (all A records share `(name, rtype)` and the cache-flush bit)
      // saw the 2nd record evict the 1st, the 3rd evict the 2nd, etc.
      // — only the last A survived.
      //
      // Track which `(name, rtype)` pairs have been flushed in this
      // packet; for subsequent records of the same RRSet, insert with
      // cache_flush=false so they all land together.
      // per-packet flush marker keys on (name, rtype, rclass).
      // Class is part of the cache identity, so the dedup
      // tracker must include it too — otherwise a non-IN cache_flush
      // record in the same packet would consume the marker and the
      // subsequent IN cache_flush would be downgraded to non-flush,
      // leaving stale IN siblings alive past the §10.2 grace window.
      let mut flushed_in_packet: std::vec::Vec<(Name, ResourceType, ResourceClass)> =
        std::vec::Vec::new();
      // process the ANSWER section AND the ADDITIONAL section
      // together. Standard DNS-SD responders carry the SRV/TXT/A/AAAA that
      // accompany a PTR answer in the Additional section (RFC 6763 §12); a
      // querier must cache them and apply them to active queries, exactly like
      // answer records. They share the per-packet cache-flush tracker. (QR=0
      // additionals are skipped below by the same is_response gates as QR=0
      // answers — additionals are never known-answer hints.)
      for r in reader.answers().chain(reader.additional()) {
        let r = match r {
          Ok(r) => r,
          // Malformed record — the single upfront section-validation latch
          // (above, before routing) has already bumped `parse_errors(1)` for
          // this datagram.  Do NOT bump it again here — that would double-count.
          // Stop walking: a malformed record means subsequent cursors are
          // unreliable (the MessageReader's skip_records / skip_questions
          // helpers return None on failure, and the Records iterator latches
          // remaining=0 after the first error).
          Err(_) => {
            break;
          }
        };

        // eager query state update.  Apply this answer to every
        // matching owned Query in a single mutable pass.  iter_mut is
        // O(N_queries) per record, total O(N_answers × N_queries) —
        // identical to the previous lazy approach, but unconditional
        // (no longer depends on the caller draining the iterator).
        //
        // skip queries that have already delivered their
        // terminal `QueryUpdate` to the caller.  Such queries are
        // retained in the pool ONLY so the caller can drain
        // `collected_answers` — they MUST be frozen: late matching
        // responses that arrive between `poll_query` returning terminal
        // and the caller's eventual `cancel_query` must not mutate
        // collected_answers or trigger FIFO eviction of pre-terminal
        // results.
        if is_response {
          // answers_rx counts only actual QR=1 response records, not
          // QR=0 known-answer hints which should not inflate the counter.
          #[cfg(feature = "stats")]
          self.stats.answers_rx(1);
          for (_, q) in self.queries.iter_mut() {
            // skip on `is_done` AND `terminal_emitted`, not
            // just the latter.  `handle_query_timeout` flips
            // `done = true` BEFORE `poll_query` flips
            // `terminal_emitted` — without the `is_done` arm, an
            // answer arriving in that gap would still mutate
            // `collected_answers`.
            if q.is_done() || q.terminal_emitted() {
              continue;
            }
            if names_match_record(q.qname(), &r) && qry_query_accepts(q, &r) {
              q.handle_event(QueryEvent::Answer(r));
            }
          }
        }

        // gate passive cache population on QR=1.  RFC 6762
        // answer-section records in QUERY packets (QR=0) are
        // known-answer hints, NOT authoritative records — they
        // suppress redundant responses but must not feed the cache.
        // Without this gate a hostile querier could:
        //   * insert forged rdata into the cache (positive-TTL QR=0
        //     answer), or
        //   * delete cached records via TTL=0 QR=0 answers, or
        //   * clamp legitimate cached siblings via QR=0 cache_flush.
        if !populate_cache || !is_response {
          continue;
        }
        // Build an owned Name directly from the wire label sequence. Bails
        // (drops the record) on a malformed label, non-UTF-8 bytes — DNS-SD
        // names are UTF-8 (RFC 6763 §4.1) — or a length violation. Avoids the
        // throwaway presentation `String` the old loop assembled, and unlike a
        // `byte as char` join never Latin-1-mangles a multi-byte UTF-8 label.
        let name = match Name::from_wire_labels(r.name().labels()) {
          Some(n) => n,
          None => continue,
        };
        // cache rdata in canonical, case-FOLDED,
        // decompressed wire form. The cache's identity test (dedup, TTL=0
        // goodbye removal, cache-flush sibling clamp) compares raw rdata bytes,
        // so a PTR/SRV/NSEC stored with one compression pointer — or one case —
        // would never match the same logical record re-encoded differently in a
        // refresh or goodbye, leaving stale entries until TTL (and letting case
        // variants bloat the bounded cache). Canonicalizing + case-folding both
        // the stored and incoming bytes makes those comparisons encoding- and
        // case-independent (the cache never surfaces rdata for display). A
        // malformed / over-length name-bearing record is dropped, not cached.
        let rdata = match r.canonical_rdata_folded() {
          Ok(v) => v,
          Err(_) => continue,
        };
        let ttl = core::time::Duration::from_secs(u64::from(r.ttl()));

        // dedup cache-flush within this packet.  Only the FIRST
        // positive-TTL record per `(name, rtype)` with the cache-flush
        // bit triggers eviction of pre-existing entries; subsequent
        // records of the same RRSet insert with cache_flush=false so
        // they land alongside the first.
        //
        // TTL=0 records must NOT consume the per-packet flush
        // marker.  `Cache::try_insert` handles `ttl == 0` (goodbye /
        // deletion) BEFORE its cache-flush branch — it removes only
        // the exact rdata and performs no RRSet eviction.  If a TTL=0
        // record set `flushed_in_packet[(name, rtype)]`, a subsequent
        // positive-TTL cache_flush record for the same RRSet would be
        // downgraded to `cache_flush=false`, leaving older siblings
        // stale until expiry.  Gate on `ttl != 0`.
        let rtype = r.rtype();
        // thread the wire rclass into the cache so non-IN class
        // records don't collide with IN entries.  The cache-flush high
        // bit is already consumed via r.cache_flush(); r.rclass()
        // returns the remaining class value (typically IN).
        let rclass = r.rclass();
        // per-packet flush dedup keys on (name, rtype, rclass),
        // not just (name, rtype) — otherwise a class-A flush record in
        // the same packet would suppress a class-B flush record for
        // the same name/type.
        let do_flush = r.cache_flush()
          && r.ttl() != 0
          && !flushed_in_packet
            .iter()
            .any(|(n, t, c)| n.as_str() == name.as_str() && *t == rtype && *c == rclass);
        let _ = self
          .cache
          .try_insert(name.clone(), rtype, rclass, rdata, ttl, now, do_flush);
        if do_flush {
          flushed_in_packet.push((name, rtype, rclass));
        }
      }
    }

    // RFC 6762 §7.3 duplicate-question suppression (querier side). When another
    // host multicasts the SAME QM question this endpoint has an active query
    // for — and that query carries NO known answers (empty Answer section, TC
    // clear, so it cannot be suppressing records we still need) — treat our own
    // planned query as already sent and defer its next (re)transmit. The peer's
    // query elicits the same multicast answers, which we receive too, so we
    // avoid adding a redundant query to the link. Self / untrusted packets are
    // already excluded by `suppress_side_effects`.
    //
    // questions_rx is bumped for EVERY question in any QR=0 query from port 5353
    // (multicast querier), regardless of whether the answer section is empty.
    // Queries that carry a known-answer section (TC=0, answer_count>0) are still
    // genuine queries whose questions deserve to be counted; only the
    // duplicate-suppression side effect is gated on answer_count==0.
    if !suppress_side_effects && !is_response && src.port() == crate::constants::MDNS_PORT {
      #[cfg(feature = "stats")]
      for q in reader.questions() {
        match q {
          Ok(_) => self.stats.questions_rx(1),
          Err(_) => break,
        }
      }
    }

    // only a query from UDP source port 5353 counts. A query from an
    // ephemeral port is a legacy/one-shot resolver (RFC 6762 §6.7) whose request
    // may be answered by UNICAST straight to it — answers we would never see —
    // so suppressing our own multicast query on its behalf could silently lose
    // us the response.
    if !suppress_side_effects
      && !is_response
      && src.port() == crate::constants::MDNS_PORT
      && reader.header().answer_count() == 0
      && !reader.header().flags().is_truncated()
    {
      for q in reader.questions() {
        let q = match q {
          Ok(q) => q,
          Err(_) => break,
        };
        // A QU (unicast-response) question is answered unicast to the asker, so
        // it does NOT elicit the multicast answers our query needs — only a
        // shared QM question is a genuine duplicate of ours. Class-gate to IN.
        if q.unicast_response_requested() || !q.qclass().is_in() {
          continue;
        }
        for (_, query) in self.queries.iter_mut() {
          if query.is_done() {
            continue;
          }
          // Same question: identical qtype + qclass and a case-insensitive
          // qname match (an ANY query is only a duplicate of another ANY).
          if query.qtype() == q.qtype()
            && query.qclass() == q.qclass()
            && names_match(query.qname(), q.qname())
          {
            #[cfg(feature = "stats")]
            let suppressed = query.note_duplicate_question(now);
            #[cfg(not(feature = "stats"))]
            let _suppressed = query.note_duplicate_question(now);
            #[cfg(feature = "stats")]
            if suppressed {
              self.stats.duplicate_questions_suppressed(1);
            }
          }
        }
      }
    }

    Ok(RouteEvents {
      src,
      reader,
      is_response,
      question_idx: 0,
      service_cursor: 0,
      answer_idx: 0,
      authority_idx: 0,
      pending_query: None,
      pending_service_event: None,
      answer_query_cursor: None,
      answer_service_cursor: None,
      answer_service_done: false,
      authority_service_cursor: None,
      additional_idx: 0,
      additional_service_cursor: None,
      additional_service_done: false,
      additional_query_cursor: None,
      // a self-packet OR an untrusted response (QR=1
      // from a non-5353 source port) yields zero events. We still construct
      // a valid (but pre-drained) iterator so the caller's loop runs cleanly.
      section: if suppress_side_effects {
        Section::Done
      } else {
        Section::Questions
      },
      endpoint: self,
    })
  }

  /// Drain endpoint-level transmits. mDNS-side most transmits come from
  /// Service/Query — Endpoint rarely emits anything itself.
  pub fn poll_transmit(
    &mut self,
    _now: I,
    _buf: &mut [u8],
  ) -> Result<Option<Transmit>, TransmitError> {
    Ok(None)
  }

  /// Next deadline (next cache expiration), if any.
  pub fn poll_timeout(&self) -> Option<I> {
    let cache = self.cache.next_expiration();
    // Endpoint-owned withdrawals have no driver-side `Service` to report their
    // deadlines, so the endpoint surfaces the earliest time a withdrawal needs
    // to be pumped (`next_at`) or force-completed (`ceiling_at`) — otherwise the
    // driver could park past a due goodbye round.
    #[cfg(any(feature = "alloc", feature = "std"))]
    let withdrawal = self.next_withdrawal_deadline();
    #[cfg(not(any(feature = "alloc", feature = "std")))]
    let withdrawal: Option<I> = None;
    match (cache, withdrawal) {
      (Some(c), Some(w)) => Some(c.min(w)),
      (Some(c), None) => Some(c),
      (None, w) => w,
    }
  }

  /// The earliest time an in-flight withdrawal needs to be pumped (`next_at`) or
  /// force-completed (`ceiling_at`), or `None` when no withdrawal is pending.
  ///
  /// Unlike [`Self::poll_timeout`] this EXCLUDES cache and query deadlines, so a
  /// last-handle shutdown flush can sleep precisely on the next withdrawal action
  /// — and exit as soon as none remain — instead of parking on unrelated cache
  /// expiry (or the driver's wall-clock backstop) after every goodbye is sent.
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub fn next_withdrawal_deadline(&self) -> Option<I> {
    self
      .withdrawals
      .iter()
      .map(|(_, w)| w.next_at.min(w.ceiling_at))
      .min()
  }

  /// Whether any endpoint-owned withdrawal is still in flight (its TTL=0 goodbye
  /// not yet fully sent or force-completed). A shutdown flush loops until this is
  /// `false`, rather than on the aggregate driver deadline.
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub fn has_pending_withdrawals(&self) -> bool {
    !self.withdrawals.is_empty()
  }

  /// Drive timer-based work (cache TTL sweep).
  pub fn handle_timeout(&mut self, now: I) -> Result<(), HandleTimeoutError> {
    let n = self.cache.sweep_expired(now);
    if n > 0 {
      let _ = self
        .pending_events
        .insert(EndpointEventEntry(EndpointEvent::CacheExpired));
    }
    Ok(())
  }

  /// Drain a pending endpoint-level event.
  pub fn poll(&mut self) -> Option<EndpointEvent> {
    let key = self.pending_events.iter().next().map(|(k, _)| k)?;
    self.pending_events.try_remove(key).map(|e| e.0)
  }

  /// Update the routing table after a service auto-renamed itself due to a
  /// probe conflict.
  ///
  /// # Contract
  ///
  /// Callers **MUST** invoke this method after observing
  /// [`ServiceUpdate::Renamed`](crate::event::ServiceUpdate::Renamed) from
  /// [`Service::poll`](crate::service::Service::poll), and **BEFORE** routing
  /// any further datagrams via [`Endpoint::handle`].  Failing to do so means
  /// questions addressed to the new instance name will not be routed to the
  /// service.
  ///
  /// # Errors
  ///
  /// Returns [`HandleServiceRenamedError::ServiceNotFound`] if `handle` does
  /// not correspond to any registered service.
  ///
  /// Returns [`HandleServiceRenamedError::NameAlreadyRegistered`] if
  /// `new_name` is already used by a *different* registered service; the
  /// caller must retry with a different suffix.
  pub fn handle_service_renamed(
    &mut self,
    handle: ServiceHandle,
    new_name: Name,
  ) -> Result<(), HandleServiceRenamedError> {
    // Locate the key for the given handle.
    let mut existing_key: Option<usize> = None;
    for (key, route) in self.services.iter() {
      if route.handle() == handle {
        existing_key = Some(key);
        break;
      }
    }
    let key = match existing_key {
      Some(k) => k,
      None => return Err(HandleServiceRenamedError::ServiceNotFound(handle)),
    };

    // Reject if new_name collides with another route.
    for (other_key, route) in self.services.iter() {
      if other_key != key && route.name().as_str() == new_name.as_str() {
        return Err(HandleServiceRenamedError::NameAlreadyRegistered(new_name));
      }
    }
    // Also reject if new_name is HELD by a rename-COLLISION detached goodbye
    // (holds_name): that dead service's records must be retracted before the name is
    // reused, and a held item is intentionally NOT cancelled on
    // advertise — so letting a rename claim it would leave the held goodbye to later
    // flush the renamed service's records. Treat it like a live-route
    // collision (the driver retires the renamer, whose caller re-registers). This
    // mirrors the `try_register_service` holds_name guard.
    #[cfg(any(feature = "alloc", feature = "std"))]
    for (_, item) in self.withdrawals.iter() {
      if item.route.is_none()
        && item.holds_name
        && item.records.instance().as_str() == new_name.as_str()
      {
        return Err(HandleServiceRenamedError::NameAlreadyRegistered(new_name));
      }
    }
    // A rename onto a RECLAIMABLE (not held) renamed-away old name reclaims it — but
    // the reclaim-cancel of that name's in-flight DETACHED goodbye is NOT done here.
    // Like a registration, a rename only RESERVES the name; the renamed
    // service still probes (~750 ms, RFC 6762 §8.1) before it advertises, and may
    // conflict/rename away again before announcing. Cancelling now would lose the old
    // records' retraction if it never announces (the same premature-cancel class as
    //). The cancel instead fires on the certain live event —
    // `note_service_advertised` gated on `advertised_instance`, when the renamed
    // service confirms advertising this name. The rename is still NOT rejected for a
    // reclaimable name: a detached item holds no route, so the
    // duplicate-name scan above does not see it, and reuse proceeds.

    // Apply the rename.
    if let Some(route) = self.services.get_mut(key) {
      warn!(
        target: "mdns_proto::endpoint",
        handle = handle.raw(),
        old_name = route.name.as_str(),
        new_name = new_name.as_str(),
        "handle_service_renamed: service renamed due to conflict"
      );
      // NOTE: conflicts/renames counters are NOT bumped here.
      // They are bumped in Service::handle_timeout (service/mod.rs) at the
      // single canonical site — the Service state machine is the authority.
      // Bumping here too would double-count on the shared Arc.
      route.name = new_name;
    }
    Ok(())
  }

  /// Find the slab key for a registered query handle.  Returns `None` if
  /// the handle no longer corresponds to an active query (auto-pruned
  /// after terminal, explicitly cancelled, or never registered).
  fn query_key(&self, handle: QueryHandle) -> Option<usize> {
    for (key, q) in self.queries.iter() {
      if q.handle() == handle {
        return Some(key);
      }
    }
    None
  }

  /// Drain the next app-level update for a registered query.
  ///
  /// The terminal `QueryUpdate` ([`QueryUpdate::Done`] /
  /// [`QueryUpdate::Timeout`]) is returned at most ONCE per query —
  /// subsequent `poll_query(h)` calls on the same handle return `None`
  /// even though the underlying state machine is still in the pool.
  /// This lets the caller observe terminal, then read final results
  /// via [`Self::collected_answers`], then explicitly clean up via
  /// [`Self::cancel_query`].  Auto-prune was tried in an earlier
  /// design and rejected: pruning before the caller had a
  /// chance to read [`Self::collected_answers`] silently lost the
  /// query's results.
  ///
  /// Backstop for storage-pressure: if `Query::handle_timeout` could
  /// not push the terminal update into the internal `EV` pool
  /// (full / zero-capacity), this synthesises a
  /// `QueryUpdate::Timeout` from the internal `done` flag.  The
  /// `terminal_emitted` latch on `Query` ensures the synthesised value
  /// fires exactly once regardless of which path produced it.
  ///
  /// Returns `None` if the query has no pending updates, has already
  /// emitted its terminal, or the handle does not correspond to a
  /// registered query.
  ///
  /// # Cleanup contract
  ///
  /// After observing terminal, the caller MUST eventually call
  /// [`Self::cancel_query`] to free the pool entry — leaving terminated
  /// queries in the pool indefinitely will exhaust fixed-capacity
  /// storage just as the leak would have.  A convenience
  /// [`Self::sweep_terminated_queries`] is available for callers that
  /// want a single bulk-cleanup step.
  pub fn poll_query(&mut self, handle: QueryHandle) -> Option<QueryUpdate> {
    let key = self.query_key(handle)?;
    let q = self.queries.get_mut(key)?;
    if q.terminal_emitted() {
      // Terminal already delivered; do not re-emit or re-synthesise.
      return None;
    }
    // Drain a regular pending update.
    let update = q.poll();
    if let Some(u) = update {
      if matches!(u, QueryUpdate::Done | QueryUpdate::Timeout) {
        q.mark_terminal_emitted();
      }
      return Some(u);
    }
    // No pending update — backstop: if the query is internally done but
    // the terminal update was silently dropped under EV-pool pressure,
    // synthesise Timeout once.
    if q.is_done() {
      q.mark_terminal_emitted();
      return Some(QueryUpdate::Timeout);
    }
    None
  }

  /// Remove every registered query that has already delivered its
  /// terminal `QueryUpdate` via [`Self::poll_query`].  Returns the
  /// number of queries pruned.
  ///
  /// Convenience for callers that want a single bulk cleanup step
  /// instead of tracking handles individually with
  /// [`Self::cancel_query`].  Safe to call at any time — queries that
  /// have NOT yet emitted terminal are left untouched.
  pub fn sweep_terminated_queries(&mut self) -> usize {
    let mut to_remove: std::vec::Vec<usize> = std::vec::Vec::new();
    for (key, q) in self.queries.iter() {
      if q.terminal_emitted() {
        to_remove.push(key);
      }
    }
    let count = to_remove.len();
    for key in to_remove {
      self.queries.try_remove(key);
    }
    count
  }

  /// Next deadline for a registered query's `handle_query_timeout` /
  /// retry / absolute-timeout schedule.  Returns `None` if the query is
  /// idle (waiting on a response) or no longer registered.
  pub fn poll_query_timeout(&self, handle: QueryHandle) -> Option<I> {
    let key = self.query_key(handle)?;
    self.queries.get(key).and_then(Query::poll_timeout)
  }

  /// Produce the next outgoing datagram for a registered query, if any
  /// is due.  Writes into `buf` and returns the [`Transmit`] descriptor.
  ///
  /// Returns `Ok(None)` when no send is currently due, or when the
  /// handle does not correspond to an active query (use
  /// [`Self::poll_query`] to observe terminal updates separately).
  pub fn poll_query_transmit(
    &mut self,
    handle: QueryHandle,
    now: I,
    buf: &mut [u8],
  ) -> Result<Option<Transmit>, TransmitError> {
    let Some(key) = self.query_key(handle) else {
      return Ok(None);
    };
    match self.queries.get_mut(key) {
      Some(q) => q.poll_transmit(now, buf),
      None => Ok(None),
    }
  }

  /// Report the send result for the datagram most recently produced by
  /// [`Self::poll_query_transmit`] for `handle`. `delivered` is
  /// `true` when at least one socket send succeeded; the query advances its
  /// retry budget only on a confirmed-delivered send.
  pub fn note_query_transmit_result(&mut self, handle: QueryHandle, now: I, delivered: bool) {
    let Some(key) = self.query_key(handle) else {
      return;
    };
    if let Some(q) = self.queries.get_mut(key) {
      q.note_transmit_result(now, delivered);
    }
  }

  /// Drive timer-based transitions on a registered query.
  ///
  /// Callers wake from [`Self::poll_query_timeout`] and invoke this with
  /// the current instant; the underlying query state machine fires its
  /// retry backoff or absolute timeout.  Terminal events become
  /// observable via [`Self::poll_query`] on the next call.
  ///
  /// Returns `Ok(())` for unknown handles as well — there is nothing
  /// to drive.
  pub fn handle_query_timeout(
    &mut self,
    handle: QueryHandle,
    now: I,
  ) -> Result<(), HandleTimeoutError> {
    let Some(key) = self.query_key(handle) else {
      return Ok(());
    };
    match self.queries.get_mut(key) {
      Some(q) => q.handle_timeout(now),
      None => Ok(()),
    }
  }

  /// Retire a registered query at the DRIVER's request: force it to its terminal
  /// TIMEOUT state. Use this when the transport can never send the query's
  /// question (e.g. a permanently-too-large datagram on every reachable family),
  /// so the query would otherwise hang. The terminal `QueryUpdate::Timeout`
  /// becomes observable via [`Self::poll_query`], late answers are frozen (the
  /// query is now done), and [`Self::collected_answers`] stay readable until
  /// [`Self::cancel_query`]. No-op for an unknown handle or an already-done query.
  pub fn retire_query(&mut self, handle: QueryHandle) {
    if let Some(key) = self.query_key(handle)
      && let Some(q) = self.queries.get_mut(key)
    {
      q.retire();
    }
  }

  /// Cancel a registered query explicitly.  Removes the query state
  /// machine and its route immediately.  Use this for caller-initiated
  /// cancellation (e.g. the application no longer cares about the
  /// query); for natural termination (timeout / done) drive
  /// [`Self::poll_query`] and let auto-prune happen.
  ///
  /// # Errors
  ///
  /// Returns [`CancelQueryError::QueryNotFound`] if `handle` does not
  /// correspond to a currently registered query.
  pub fn cancel_query(&mut self, handle: QueryHandle) -> Result<(), CancelQueryError> {
    let key = self
      .query_key(handle)
      .ok_or(CancelQueryError::QueryNotFound(handle))?;
    // Apply terminal accounting for a live cancel.  If the query has NOT yet
    // reached a terminal state (done=false), this cancel IS the terminal
    // transition, so we must bump `queries_done` AND decrement `queries_active`
    // — exactly as `Query::terminate` would.  If the query is already done,
    // `Query::terminate` already performed both adjustments; do nothing here to
    // avoid double-counting.  This maintains the invariant:
    //   queries_started == queries_done + queries_timeout + queries_active
    #[cfg(feature = "stats")]
    if let Some(q) = self.queries.get(key)
      && !q.is_done()
    {
      self.stats.queries_done(1);
      self.stats.decr_queries_active(1);
    }
    self.queries.try_remove(key);
    Ok(())
  }

  /// Iterate the answers collected so far by a registered query.
  /// Returns an empty iterator if the handle does not correspond to an
  /// active query.
  pub fn collected_answers(
    &self,
    handle: QueryHandle,
  ) -> impl Iterator<Item = &CollectedAnswer> + '_ {
    let key = self.query_key(handle);
    key
      .and_then(|k| self.queries.get(k))
      .into_iter()
      .flat_map(Query::collected_answers)
  }

  /// Total answers ever accepted by a query (including ones the `max_answers`
  /// cap has since evicted). `None` if the handle is not an active query.
  ///
  /// A driver delivering answers by ascending `seq` compares this against the
  /// number it has observed to count answers evicted before delivery — loss
  /// the bounded [`Self::collected_answers`] snapshot would otherwise hide.
  pub fn query_accepted_count(&self, handle: QueryHandle) -> Option<u64> {
    self
      .query_key(handle)
      .and_then(|k| self.queries.get(k))
      .map(Query::accepted_count)
  }
}

/// Iterator over routing decisions for a single incoming datagram.
///
/// Borrows the endpoint mutably for the duration of iteration so that
/// `QueryEvent::Answer` events can be applied to the internal
/// [`Query`] state machines as they are yielded —
/// callers do not need to dispatch query events themselves.  Service
/// events still flow to the caller via the yielded [`RouteEvent`]s.
pub struct RouteEvents<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: Rng,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  src: SocketAddr,
  endpoint: &'e mut Endpoint<I, R, C, SR, QS, EV, AN, EvQ>,
  reader: MessageReader<'a>,
  /// `true` when the QR bit is set (this is a response, not a query).
  /// Used to gate KnownAnswer-suppression routing: KAS hints must only be
  /// extracted from QUERY packets (QR=0); response packets must not poison
  /// the KAS ring.
  is_response: bool,
  question_idx: u16,
  /// Per-question service cursor: the slab key from which to resume iterating
  /// services for the current question. Allows ALL matching services to receive
  /// a `ServiceEvent::Question` for a single question before advancing to the
  /// next question.
  service_cursor: usize,
  answer_idx: u16,
  authority_idx: u16,
  /// Stashed query event behind a higher-priority service event (e.g. a
  /// `ProbeConflict` or `KnownAnswer` returns first and the first matching
  /// `QueryEvent::Answer` for the same record drains on the next call).
  pending_query: Option<RouteEvent<'a>>,
  /// cursor for fanning out additional matching query routes for
  /// the current `answer_idx` across multiple `next()` calls without
  /// buffering events.  `None` means "have not started query fan-out for
  /// this record" — `next()` does the service-side pass plus finds the
  /// FIRST matching query.  `Some(k)` means "mid fan-out — resume scanning
  /// `self.queries` from slab key `k`."  Resets to `None` whenever
  /// `answer_idx` advances, so the cursor is always paired with the
  /// current answer record.
  ///
  /// Replaces the unbounded `std::Vec` buffering — that
  /// allocated on the inbound packet path with infallible `push`, which
  /// under allocator pressure aborts/panics instead of surfacing an
  /// error, and used `Vec::remove(0)` for drain (O(n²) on large
  /// fan-outs).  The cursor model is O(1) state per record, O(n) total
  /// work, and never allocates.
  answer_query_cursor: Option<usize>,
  /// cursor for fanning out KnownAnswer / ProbeConflict /
  /// HostConflict events across multiple registered services that all
  /// match the same answer record (e.g. several services sharing a
  /// `service_type` for a PTR known-answer hint, or multiple services
  /// sharing a host name).  Same shape as `answer_query_cursor`:
  /// `None` = haven't started service-side fan-out for this record;
  /// `Some(k)` = resume scan from slab key `k`.  Reset to `None` when
  /// `answer_idx` advances.
  ///
  /// Previously the service-side scan stopped at the first matching
  /// service, so the actual owning service of a PTR known-answer
  /// (which had the right rdata to suppress) never received the hint —
  /// the unrelated first-matching service got it instead and ignored
  /// it by rdata mismatch.
  answer_service_cursor: Option<usize>,
  /// whether the answer-record service-phase fan-out is COMPLETE for
  /// the current `answer_idx`. `answer_service_cursor` alone is ambiguous
  /// (`None` means both "not started" and "exhausted"), so after a query event
  /// returns mid-record, re-entry would re-scan services and replay conflict
  /// events. This flag gates the service phase; it is reset only when
  /// `answer_idx` advances.
  answer_service_done: bool,
  /// cursor for fanning out authority-section conflict events
  /// (ProbeConflict / HostConflict) across multiple services that
  /// share a host name.  `None` = haven't started fan-out for the
  /// current authority record; `Some(k)` = resume scan from slab key
  /// `k`.  Same shape as the other answer/question cursors.
  ///
  /// Previously the authority-section loop broke on the first
  /// matching service and advanced `authority_idx`, so a peer probe
  /// for a shared host name reached only one of the services
  /// sharing that host; the rest never received the HostConflict
  /// signal.
  authority_service_cursor: Option<usize>,
  /// When a QUERY-packet answer matches a registered service for both a
  /// ProbeConflict and a KnownAnswer event, we emit ProbeConflict first and
  /// stash the KnownAnswer here for the subsequent call.
  pending_service_event: Option<RouteEvent<'a>>,
  /// index into the ADDITIONAL section, plus the
  /// service-conflict and query fan-out cursors for the current additional
  /// record (same shape as the answer-section cursors). DNS-SD responders carry
  /// SRV/TXT/A/AAAA here, so QR=1 additionals run conflict detection (instance
  /// SRV/TXT → ProbeConflict, host A/AAAA → HostConflict) AND query fan-out —
  /// but never KAS (additionals are not known-answer hints).
  additional_idx: u16,
  additional_service_cursor: Option<usize>,
  /// like `answer_service_done`, marks the additional-record
  /// service-phase fan-out complete for the current `additional_idx` so a query
  /// event mid-record cannot cause the conflict events to replay on re-entry.
  additional_service_done: bool,
  additional_query_cursor: Option<usize>,
  section: Section,
}

#[derive(Copy, Clone)]
enum Section {
  Questions,
  Answers,
  Authority,
  Additional,
  Done,
}

impl<'a, I, R, C, SR, QS, EV, AN, EvQ> RouteEvents<'a, '_, I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: Rng,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  /// the ONE conflict-routing decision for a QR=1 record `r`,
  /// shared by the Answers, Authority, and Additional sections (previously
  /// triplicated). Scans registered services from slab key `start` and returns
  /// the next `(key, event)`:
  ///   * instance-name match + SRV/TXT → ProbeConflict (the instance's unique
  ///     RRset; service-type / shared names are never conflicts);
  ///   * host-name match + A/AAAA → HostConflict.
  ///
  /// conflicts are only routed for class-IN records — a record with
  /// class ANY or an unknown class is not the same-class RRset RFC 6762 §9
  /// requires, so it must not drive rename / host-conflict surfacing.
  fn next_service_conflict(
    &self,
    r: &crate::wire::Ref<'a>,
    start: usize,
  ) -> Option<(usize, RouteEvent<'a>)> {
    if r.rclass() != ResourceClass::In {
      return None;
    }
    for (key, route) in self.endpoint.services.iter() {
      if key < start {
        continue;
      }
      // A withdrawing route's service is being torn down (only its goodbye is still
      // draining) — never route a conflict to it. The route is retained for the
      // name guard, but dispatching ProbeConflict/HostConflict here would feed
      // terminal events into a proto the driver no longer drains (it skips
      // withdrawing/errored contexts), letting a peer flood the proto event slab of
      // a retiring service until GC — a bounded-time but unbounded-size growth path
      //. Mirrors the question-dispatch and known-answer skips.
      #[cfg(any(feature = "alloc", feature = "std"))]
      if route.withdrawing {
        continue;
      }
      if names_match_record(route.name(), r) && is_instance_conflict_rtype(r.rtype()) {
        return Some((
          key,
          RouteEvent::ToService(ToService::new(
            route.handle(),
            ServiceEvent::ProbeConflict(ProbeConflict::new(self.src, *r)),
          )),
        ));
      }
      if names_match_record(route.host(), r) && is_host_conflict_rtype(r.rtype()) {
        return Some((
          key,
          RouteEvent::ToService(ToService::new(
            route.handle(),
            ServiceEvent::HostConflict(HostConflict::new(*r)),
          )),
        ));
      }
    }
    None
  }
}

impl<'a, I, R, C, SR, QS, EV, AN, EvQ> Iterator
  for RouteEvents<'a, '_, I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: Rng,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  type Item = Result<RouteEvent<'a>, HandleError>;

  fn next(&mut self) -> Option<Self::Item> {
    // Flush pending stashed events in priority order before processing the
    // next record.  Order: ProbeConflict / KnownAnswer stash (service event)
    // first, then query Answer stash.
    if let Some(ev) = self.pending_service_event.take() {
      return Some(Ok(ev));
    }
    if let Some(ev) = self.pending_query.take() {
      return Some(Ok(ev));
    }

    loop {
      match self.section {
        Section::Questions => {
          // gate question→service routing on
          // `EndpointConfig::answer_questions`.  When disabled, no
          // `ServiceEvent::Question` events fire at all, so registered
          // services never schedule responses to inbound queries.
          // This is the "advertise but don't respond" / passive mode.
          if !self.endpoint.config.answer_questions() {
            self.section = Section::Answers;
            continue;
          }
          if self.question_idx >= self.reader.header().question_count() {
            self.section = Section::Answers;
            continue;
          }
          let mut qs = self.reader.questions();
          for _ in 0..self.question_idx {
            let _ = qs.next();
          }
          let q = match qs.next() {
            Some(Ok(q)) => q,
            Some(Err(e)) => {
              // skip the rest of the questions section after a
              // parse error so the iterator terminates instead of
              // looping on the same error indefinitely.
              // parse_errors was already bumped by the upfront section-
              // validation latch in Endpoint::handle — do NOT bump again.
              self.section = Section::Answers;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Answers;
              continue;
            }
          };
          // Walk services starting from the saved cursor, looking for the next
          // match. This allows ALL services sharing the same PTR name to each
          // receive a ServiceEvent::Question for this question before we move on.
          let cursor = self.service_cursor;
          let mut found: Option<(usize, RouteEvent<'a>)> = None;
          for (key, route) in self.endpoint.services.iter() {
            if key < cursor {
              continue;
            }
            // A withdrawing route's service is gone (only its goodbye is still
            // draining) — never route an incoming question to it, or it could
            // emit a positive-TTL answer contradicting its own TTL=0 goodbye.
            // The route is still present for the name guard, just not answered.
            #[cfg(any(feature = "alloc", feature = "std"))]
            if route.withdrawing {
              continue;
            }
            if names_match(route.name(), q.qname())
              || names_match(route.service_type(), q.qname())
              || names_match(route.host(), q.qname())
              || route
                .subtypes
                .iter()
                .any(|s| names_match(s, q.qname()))
              // RFC 6763 §9 service-type enumeration: route the meta-query to
              // EVERY service; each answerable (Established/Announcing) one emits
              // its own type PTR, and the cursor below delivers it to each in
              // turn. An earlier per-type dedup (route only the
              // lowest-keyed service of each type) is UNSAFE here — routing has
              // no visibility into Service lifecycle state, so it could pick a
              // probing/non-answering representative and mask an Established
              // same-type sibling, leaving a live type unanswered. Two instances
              // of one type emitting the identical meta-PTR is benign (receivers
              // dedup the identical RR); true per-type dedup would require
              // state-aware, cross-service handling at the driver layer.
              || is_meta_query_name(q.qname())
            {
              found = Some((
                key,
                RouteEvent::ToService(ToService::new(
                  route.handle(),
                  ServiceEvent::Question(
                    ServiceQuestion::new(q, self.src, self.reader.header().id())
                      // RFC 6762 §7.2: a TC-bit query spreads its known answers
                      // across multiple packets — the responder delays longer so
                      // the follow-up packets accumulate before it suppresses.
                      .with_truncated(self.reader.header().flags().is_truncated()),
                  ),
                )),
              ));
              break;
            }
          }
          if let Some((key, ev)) = found {
            // Advance the service cursor past this key so the next call picks up
            // where we left off within the same question.
            self.service_cursor = key.saturating_add(1);
            return Some(Ok(ev));
          }
          // No more matching services for this question: advance to the next
          // question and reset the per-question service cursor.
          self.question_idx = self.question_idx.saturating_add(1);
          self.service_cursor = 0;
          continue;
        }
        Section::Answers => {
          if self.answer_idx >= self.reader.header().answer_count() {
            self.section = Section::Authority;
            continue;
          }
          let mut ans = self.reader.answers();
          for _ in 0..self.answer_idx {
            let _ = ans.next();
          }
          let r = match ans.next() {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
              // skip the rest of the answers section after a
              // parse error so the iterator terminates instead of
              // looping on the same error indefinitely.
              // parse_errors was already bumped in the eager walk in
              // Endpoint::handle (which covers answers AND additionals);
              // do NOT bump it here to avoid double-counting.
              self.section = Section::Authority;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Authority;
              continue;
            }
          };

          // route-level TTL=0 guard.  Records with TTL=0 are
          // mDNS "goodbye" / deletion signals (RFC 6762 §10.1) — the
          // cache layer already processes them as removals during the
          // eager loop in `Endpoint::handle`, and `Query::handle_event`
          // rejects them at the eager-mutation step.  The
          // remaining hazard is the iterator: emitting service events
          // (ProbeConflict / HostConflict / KnownAnswer) for a goodbye
          // would let a peer withdrawing a record trigger our auto-
          // rename or HostConflict surfacing, and emitting ToQuery
          // for a goodbye would let callers receive ghost "answers"
          // from records being withdrawn.  Skip the whole fan-out for
          // TTL=0 — cache removal is the only correct side effect.
          if r.ttl() == 0 {
            self.answer_idx = self.answer_idx.saturating_add(1);
            self.answer_service_cursor = None;
            self.answer_service_done = false;
            self.answer_query_cursor = None;
            continue;
          }

          // Service-side fan-out for answer-section records.
          //
          // QR=0: records are KAS hints from another querier.
          //   Emit only KnownAnswer (for KAS suppression on probes).
          //   ProbeConflict / HostConflict are NEVER emitted here —
          //   letting a hostile querier trigger our auto-rename by
          //   mentioning our names in the answer section would be a
          //   trivial denial-of-service vector.
          //
          // QR=1: records are AUTHORITATIVE peer responses.
          //   Per RFC 6762 §8.1, a probing host MUST treat any
          //   response (solicited or unsolicited) claiming one of its
          //   tentative names as a conflict event.  Emit
          //   ProbeConflict for instance-name matches and HostConflict
          //   for host-name matches.  Service-type (shared) matches
          //   are NOT conflicts (multiple services share a type).
          //
          // Authority-section records (Section::Authority) fire
          // ProbeConflict / HostConflict regardless of QR — those are
          // tentative-probe records.
          if !self.answer_service_done {
            let start = self.answer_service_cursor.unwrap_or(0);
            let next_event = if self.is_response {
              // QR=1: ProbeConflict / HostConflict via the shared conflict
              // helper (name + rtype + class gates). Service-type (shared)
              // names are never conflicts.
              self.next_service_conflict(&r, start)
            } else {
              // QR=0: records are KAS hints. ANY name match (instance / host /
              // service-type) emits a KnownAnswer for suppression — conflicts
              // are NEVER routed for QR=0 (a hostile querier mentioning our
              // names must not trigger auto-rename).
              //
              // a QR=0 PTR owned by the DNS-SD service-type enumeration
              // meta name is a known-answer for the §9 meta reply. Its owner is
              // none of our RRset names, so fan it out to EVERY service (mirrors
              // how the meta QUESTION routes to all of them); each
              // service decides whether the PTR target matches its own type.
              let mut found: Option<(usize, RouteEvent<'a>)> = None;
              for (key, route) in self.endpoint.services.iter() {
                if key < start {
                  continue;
                }
                // A withdrawing route's service is being torn down — never route a
                // known-answer to it either, matching the question-dispatch and
                // conflict skips (no dispatch after retirement).
                #[cfg(any(feature = "alloc", feature = "std"))]
                if route.withdrawing {
                  continue;
                }
                if names_match_record(route.name(), &r)
                  || names_match_record(route.host(), &r)
                  || names_match_record(route.service_type(), &r)
                  || is_meta_query_name(r.name())
                {
                  found = Some((
                    key,
                    RouteEvent::ToService(ToService::new(
                      route.handle(),
                      ServiceEvent::KnownAnswer(KnownAnswer::new(self.src, r)),
                    )),
                  ));
                  break;
                }
              }
              found
            };
            if let Some((key, ev)) = next_event {
              self.answer_service_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
            }
            // service-side fan-out exhausted for THIS record. Mark
            // it done (not just reset the cursor to None, which is ambiguous
            // with "not started") so a later query event in the same record
            // can't re-enter and replay the conflict/KAS events.
            self.answer_service_done = true;
          }

          // Query-side fan-out (QR=1 only).  emit a
          // ToQuery for every name/type-compatible active query via
          // `answer_query_cursor`.  This already applied the answer
          // to the Query state eagerly in `Endpoint::handle`; the
          // events emitted here are informational only.
          if self.is_response {
            let start = self.answer_query_cursor.unwrap_or(0);
            let mut found: Option<(usize, RouteEvent<'a>)> = None;
            for (key, q) in self.endpoint.queries.iter() {
              if key < start {
                continue;
              }
              if q.is_done() || q.terminal_emitted() {
                continue;
              }
              if names_match_record(q.qname(), &r) && qry_query_accepts(q, &r) {
                found = Some((
                  key,
                  RouteEvent::ToQuery(ToQuery::new(q.handle(), QueryEvent::Answer(r))),
                ));
                break;
              }
            }
            if let Some((key, ev)) = found {
              self.answer_query_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
            }
            // Query-side fan-out exhausted for this record.
            self.answer_query_cursor = None;
          }

          // Both phases exhausted — record fully processed.  Advance to the
          // next answer record and reset the per-record fan-out state.
          self.answer_idx = self.answer_idx.saturating_add(1);
          self.answer_service_cursor = None;
          self.answer_service_done = false;
          self.answer_query_cursor = None;
          continue;
        }
        Section::Authority => {
          // authority-section records are tentative-probe claims
          // (RFC 6762 §8.2) — a peer asserting ownership of a name. Routing
          // them as ProbeConflict / HostConflict forces our service to rename
          // or surfaces a host conflict, so they MUST come from a trusted mDNS
          // peer. A genuine prober sends from UDP source port 5353; an
          // ephemeral-port packet carrying an authority RR for our name is an
          // off-path / forged artifact — a legacy §6.7 querier sends only
          // questions, never authority records. (QR=1 responses from non-5353
          // ports are already fully suppressed upstream; this closes the QR=0
          // query path, where the Question section has ALREADY been routed
          // above so legacy unicast repliers are unaffected.)
          //
          // accounting rule: suppressing conflict routing for a non-5353
          // source is a SECTION-LEVEL suppression — the datagram's other
          // sections (questions, answers, additional) are still processed.
          // This is NOT a whole-datagram reject, so `packets_dropped` is NOT
          // bumped here.  Parse errors in the authority section ARE still
          // counted by the upfront section-validation latch (which walks
          // authority regardless of source port), so malformed bytes are
          // always accounted even when conflict routing is suppressed.
          if self.src.port() != crate::constants::MDNS_PORT {
            self.section = Section::Additional;
            continue;
          }
          if self.authority_idx >= self.reader.header().authority_count() {
            self.section = Section::Additional;
            continue;
          }
          let mut auth = self.reader.authority();
          for _ in 0..self.authority_idx {
            let _ = auth.next();
          }
          let r = match auth.next() {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
              // skip the rest of the authority section after a
              // parse error so the iterator terminates instead of
              // looping on the same error indefinitely.
              // parse_errors was already bumped by the upfront section-
              // validation latch in Endpoint::handle — do NOT bump again.
              self.section = Section::Done;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Additional;
              continue;
            }
          };

          // route-level TTL=0 guard for the authority section.
          // covered Section::Answers; the same rationale applies
          // here.  A TTL=0 authority record is a goodbye/withdrawal,
          // not a peer claiming the name — emitting ProbeConflict or
          // HostConflict for it would let a withdrawing peer trigger
          // our auto-rename or HostConflict surfacing.
          if r.ttl() == 0 {
            self.authority_idx = self.authority_idx.saturating_add(1);
            self.authority_service_cursor = None;
            continue;
          }

          // Authority records in mDNS probe messages signal a peer claiming the
          // same name — route as ProbeConflict / HostConflict to EVERY matching
          // service (multiple services can share a host) via the shared
          // conflict helper (name + rtype + class gates centralized there).
          let start = self.authority_service_cursor.unwrap_or(0);
          if let Some((key, ev)) = self.next_service_conflict(&r, start) {
            self.authority_service_cursor = Some(key.saturating_add(1));
            return Some(Ok(ev));
          }
          // No more matching services for this authority record.
          // Advance to the next authority record.
          self.authority_idx = self.authority_idx.saturating_add(1);
          self.authority_service_cursor = None;
          continue;
        }
        Section::Additional => {
          // additional-section records are supplementary ANSWERS
          // (DNS-SD SRV/TXT/A/AAAA accompanying a PTR), NOT questions or probe
          // claims. They fan out to active queries ONLY (QR=1) — never service
          // conflicts/KAS. Cache population + eager query-state update already
          // happened in `Endpoint::handle`; these events are informational.
          if !self.is_response {
            self.section = Section::Done;
            continue;
          }
          if self.additional_idx >= self.reader.header().additional_count() {
            self.section = Section::Done;
            continue;
          }
          let mut add = self.reader.additional();
          for _ in 0..self.additional_idx {
            let _ = add.next();
          }
          let r = match add.next() {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
              // parse_errors was already bumped in the eager walk in
              // Endpoint::handle (which covers answers AND additionals);
              // do NOT bump it here to avoid double-counting.
              self.section = Section::Done;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Done;
              continue;
            }
          };
          // TTL=0 additionals are withdrawals — cache removal already handled
          // eagerly; do not surface a ghost conflict/answer.
          if r.ttl() == 0 {
            self.additional_idx = self.additional_idx.saturating_add(1);
            self.additional_service_cursor = None;
            self.additional_service_done = false;
            self.additional_query_cursor = None;
            continue;
          }
          // service-conflict fan-out FIRST. A QR=1 additional record
          // can carry a conflicting SRV/TXT (instance) or A/AAAA (host) for one
          // of our services — DNS-SD responders place these in the Additional
          // section, so missing them here would let duplicate names survive.
          // Same unique-record gates as the Answer/Authority sections;
          // service-type (shared) matches are never conflicts.
          if !self.additional_service_done {
            let start = self.additional_service_cursor.unwrap_or(0);
            if let Some((key, ev)) = self.next_service_conflict(&r, start) {
              self.additional_service_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
            }
            // mark the service phase done for this record so a later
            // query event can't re-enter and replay the conflict events.
            self.additional_service_done = true;
          }
          // Then query fan-out (informational; eager state update already done).
          let start = self.additional_query_cursor.unwrap_or(0);
          let mut found: Option<(usize, RouteEvent<'a>)> = None;
          for (key, q) in self.endpoint.queries.iter() {
            if key < start {
              continue;
            }
            if q.is_done() || q.terminal_emitted() {
              continue;
            }
            if names_match_record(q.qname(), &r) && qry_query_accepts(q, &r) {
              found = Some((
                key,
                RouteEvent::ToQuery(ToQuery::new(q.handle(), QueryEvent::Answer(r))),
              ));
              break;
            }
          }
          if let Some((key, ev)) = found {
            self.additional_query_cursor = Some(key.saturating_add(1));
            return Some(Ok(ev));
          }
          // Both fan-outs exhausted for this additional record; advance and
          // reset the per-record fan-out state.
          self.additional_idx = self.additional_idx.saturating_add(1);
          self.additional_service_cursor = None;
          self.additional_service_done = false;
          self.additional_query_cursor = None;
          continue;
        }
        Section::Done => return None,
      }
    }
  }
}

/// RFC 6763 §9 DNS-SD service-type enumeration (meta-query) name. A browser
/// queries this name (PTR) to discover which service TYPES exist on the link.
pub(crate) const DNS_SD_META_QUERY_NAME: &str = "_services._dns-sd._udp.local.";

/// True if `qname` is the RFC 6763 §9 meta-query name (case-insensitive). A
/// matching question is routed to every registered service so each can answer
/// with a shared PTR `_services._dns-sd._udp.local. -> <its service type>`.
pub(crate) fn is_meta_query_name(qname: &NameRef<'_>) -> bool {
  // Compare against the &'static meta-query name directly — no need to
  // allocate a `Name` (29 bytes, heap-backed) on every routed question.
  names_match_str(DNS_SD_META_QUERY_NAME, qname)
}

pub(crate) fn names_match(stored: &Name, incoming: &NameRef<'_>) -> bool {
  names_match_str(stored.as_str(), incoming)
}

pub(crate) fn names_match_str(stored_str: &str, incoming: &NameRef<'_>) -> bool {
  let stored_trim = match stored_str.strip_suffix('.') {
    Some(s) => s,
    None => stored_str,
  };
  let mut sit = stored_trim.split('.');
  let mut iit = incoming.labels();
  loop {
    match (sit.next(), iit.next()) {
      (None, None) => return true,
      (Some(s), Some(Ok(i))) => {
        if s.len() != i.len() {
          return false;
        }
        for (a, b) in s.bytes().zip(i.iter()) {
          if !a.eq_ignore_ascii_case(b) {
            return false;
          }
        }
      }
      _ => return false,
    }
  }
}

pub(crate) fn names_match_record(stored: &Name, r: &crate::wire::Ref<'_>) -> bool {
  names_match(stored, r.name())
}

/// the RR types a host name is authoritative for — the address
/// records (A / AAAA). Only these constitute a host-name conflict; a record of
/// any other type owned by the host name is not a claim on the host's unique
/// RRset and must not trigger a [`HostConflict`].
fn is_host_conflict_rtype(rt: ResourceType) -> bool {
  matches!(rt, ResourceType::A | ResourceType::AAAA)
}

/// the RR types a service INSTANCE name is authoritative for — SRV
/// and TXT (RFC 6763 §4). Only these constitute an instance-name conflict
/// (ProbeConflict / auto-rename); a record of any other type owned by the
/// instance name is not a claim on the instance's unique RRset. The PTR that
/// maps a service type to an instance is owned by the SHARED service-type name,
/// not the instance, and is excluded separately.
fn is_instance_conflict_rtype(rt: ResourceType) -> bool {
  matches!(rt, ResourceType::Srv | ResourceType::Txt)
}

/// Does `q`'s QTYPE/QCLASS accept the answer record `r`?
///
/// `ResourceType::Any` / `ResourceClass::Any` are wildcards.  Otherwise the
/// answer's rtype/rclass must match the query's exactly.  this
/// promotes type/class filtering from `Query::handle_event` up into the
/// demux so a single answer can fan out to every compatible query (not be
/// lost to the first-by-name match).
fn qry_query_accepts<I, AN, EvQ>(q: &Query<I, AN, EvQ>, r: &crate::wire::Ref<'_>) -> bool
where
  I: Instant,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  let qt = q.qtype();
  let qc = q.qclass();
  let rt_ok = qt == ResourceType::Any || qt == r.rtype();
  // ResourceClass::Any is the wildcard QCLASS value 255 used in mDNS QU
  // queries; accept any answer class against it.  Otherwise the answer's
  // class must equal the query's QCLASS exactly.
  let rc_ok = qc == ResourceClass::Any || qc == r.rclass();
  rt_ok && rc_ok
}

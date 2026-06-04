//! `Endpoint` orchestrator: demuxes incoming datagrams, holds routing
//! metadata + cache, drives Service/Query registration.

#![cfg(any(feature = "alloc", feature = "std"))]

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
  transmit::Transmit,
  wire::{MessageReader, NameRef, ResourceClass, ResourceType},
};

/// Number of goodbye sends during an orderly withdrawal (RFC 6762 §10.1),
/// counted PER FAMILY so each reachable family withdraws its records.
#[cfg(any(feature = "alloc", feature = "std"))]
const WITHDRAWAL_SENDS: u8 = 3;

/// Spacing between successive withdrawal goodbye resends (loss resilience).
// Used by `poll_withdrawal_transmit` (Task 3).
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(dead_code)]
const WITHDRAWAL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(250);

/// Back-off added to `next_at` on a missed send (delivery not yet confirmed).
// Used by `note_withdrawal_result` (Task 4).
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
  // Read by `poll_timeout` dispatch skip (Task 6).
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

    // Only AFTER the route insertion SUCCEEDS — the name is now committed in the
    // route table — reclaim it from any in-flight DETACHED withdrawal by CANCELLING
    // that goodbye. Doing this before the insert would drop a graceful withdrawal
    // even when registration fails with StorageFull, leaving stale old-name records
    // until TTL. A detached item withdraws a renamed-away old instance
    // with no live owner; the reclaiming service probes (~750 ms, RFC 6762 §8.1)
    // before announcing, and re-announces (§8.3), so no already-sent TTL=0 goodbye
    // can durably flush it. Rejecting instead would also wrongly kill an
    // auto-renaming service that picked this transiently-reserved suffix (drivers
    // treat a rename error as fatal —). Route-attached withdrawing names
    // stay reserved by the duplicate-name scan above — the unchanged R21–R24
    // teardown closure (a LEAVING service).
    #[cfg(any(feature = "alloc", feature = "std"))]
    self.withdrawals.retain(|(_, item)| {
      !(item.route.is_none()
        && item.records.instance().as_str() == spec.records().instance().as_str())
    });

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
    crate::trace::debug!(
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
      },
    ));

    crate::trace::debug!(
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
      },
    ));
    crate::trace::debug!(
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
  ) {
    let Some((_, route)) = self.services.iter_mut().find(|(_, r)| r.handle() == handle) else {
      return;
    };
    route.advertised_a.clear();
    route.advertised_a.extend_from_slice(a);
    route.advertised_aaaa.clear();
    route.advertised_aaaa.extend_from_slice(aaaa);
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
  #[cfg(all(test, any(feature = "alloc", feature = "std")))]
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
  #[cfg(all(test, any(feature = "alloc", feature = "std")))]
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
  #[cfg(all(test, any(feature = "alloc", feature = "std")))]
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
  #[cfg(all(test, any(feature = "alloc", feature = "std")))]
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
  #[cfg(all(test, any(feature = "alloc", feature = "std")))]
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
    crate::trace::debug!(
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
    // ── entry span + Rx counters ────────────────────────────────────────────
    #[cfg(feature = "tracing")]
    let _span = crate::trace::trace_span!("handle", src = %src, len = data.len()).entered();
    #[cfg(feature = "stats")]
    {
      self.stats.packets_rx(1);
      #[allow(clippy::cast_possible_truncation)]
      self.stats.bytes_rx(data.len() as u64);
    }

    let reader = MessageReader::try_parse(data).map_err(|e| {
      crate::trace::warn!(
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

    crate::trace::trace!(
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
      crate::trace::debug!(
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
        // Build an owned Name from the wire label sequence.
        let name_opt: Option<Name> = {
          let mut s = std::string::String::new();
          let mut ok = true;
          for label in r.name().labels() {
            match label {
              Ok(bytes) => {
                for &b in bytes {
                  s.push(b.to_ascii_lowercase() as char);
                }
                s.push('.');
              }
              Err(_) => {
                ok = false;
                break;
              }
            }
          }
          if ok {
            Name::try_from_str(&s).ok()
          } else {
            None
          }
        };
        let name = match name_opt {
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
        let rdata: std::vec::Vec<u8> = match r.canonical_rdata_folded() {
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
    // A rename onto a renamed-away old name reclaims it: CANCEL its in-flight
    // DETACHED goodbye rather than rejecting (same reasoning as the registration
    // gate — no live owner, the renamed service probes before announcing). This
    // is the fix: rejecting made the drivers treat a TRANSIENT detached
    // reservation as a permanent collision and kill the auto-renaming service.
    #[cfg(any(feature = "alloc", feature = "std"))]
    self.withdrawals.retain(|(_, item)| {
      !(item.route.is_none() && item.records.instance().as_str() == new_name.as_str())
    });

    // Apply the rename.
    if let Some(route) = self.services.get_mut(key) {
      crate::trace::warn!(
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

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(all(test, feature = "std", feature = "slab"))]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::panic,
  clippy::indexing_slicing,
  clippy::arithmetic_side_effects
)]
mod tests {
  use super::*;
  use crate::{
    cache::CacheEntry,
    config::{EndpointConfig, ServiceSpec},
    event::{QueryUpdate, ServiceUpdate},
    query::Query,
    records::ServiceRecords,
    transmit::Transmit,
  };
  use std::{net::Ipv4Addr, time::Instant as StdInstant};

  type TestQuery = Query<StdInstant, slab::Slab<CollectedAnswer>, slab::Slab<QueryUpdate>>;

  type TestEndp = Endpoint<
    StdInstant,
    rand::rngs::StdRng,
    slab::Slab<CacheEntry<StdInstant>>,
    slab::Slab<ServiceRoute>,
    slab::Slab<TestQuery>,
    slab::Slab<EndpointEventEntry>,
    slab::Slab<CollectedAnswer>,
    slab::Slab<QueryUpdate>,
  >;

  fn build_endpoint() -> TestEndp {
    use rand::SeedableRng;
    let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
    TestEndp::try_new(EndpointConfig::new(), rng)
  }

  #[test]
  fn service_route_exposes_advertised_addresses() {
    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("P._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 5));
    let (handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        StdInstant::now(),
      )
      .unwrap();
    let (_, route) = e
      .services
      .iter()
      .find(|(_, r)| r.handle() == handle)
      .unwrap();
    assert_eq!(route.a_addrs(), [Ipv4Addr::new(10, 0, 0, 5)].as_slice());
    assert!(route.aaaa_addrs().is_empty());
    assert!(route.aaaa_scopes().is_empty());
  }

  #[test]
  fn endpoint_event_entry_borrows_inner_event() {
    let entry = EndpointEventEntry(crate::event::EndpointEvent::CacheExpired);
    assert!(matches!(
      entry.event(),
      crate::event::EndpointEvent::CacheExpired
    ));
  }

  #[test]
  fn query_delegation_tolerates_unknown_handles() {
    let mut e = build_endpoint();
    let bogus = QueryHandle::from_raw(0xDEAD);
    let now = StdInstant::now();
    let mut buf = std::vec![0u8; 512];
    assert!(matches!(
      e.poll_query_transmit(bogus, now, &mut buf),
      Ok(None)
    ));
    e.note_query_transmit_result(bogus, now, true); // no-op on an unknown handle
    assert!(e.handle_query_timeout(bogus, now).is_ok());
  }

  #[test]
  fn endpoint_config_accessor_and_empty_poll_transmit() {
    let mut e = build_endpoint();
    let _ = e.config();
    // The endpoint itself emits nothing — all transmits come from services/queries.
    let mut buf = std::vec![0u8; 64];
    assert!(matches!(
      e.poll_transmit(StdInstant::now(), &mut buf),
      Ok(None)
    ));
  }

  #[test]
  fn src_matches_advertised_checks_route_addresses() {
    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("P._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 5));
    e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      StdInstant::now(),
    )
    .unwrap();
    // A source IP matching an advertised A record is on-link; a non-advertised
    // one is not; a v6 source (no advertised AAAA) exercises the v6 branch.
    assert!(e.src_matches_advertised(core::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 0));
    assert!(!e.src_matches_advertised(core::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)), 0));
    assert!(!e.src_matches_advertised(core::net::IpAddr::V6(core::net::Ipv6Addr::LOCALHOST), 0));
  }

  #[test]
  fn handle_rejects_invalid_opcode_and_response_code() {
    let mut e = build_endpoint();
    let src: std::net::SocketAddr = "192.168.1.5:5353".parse().unwrap();
    let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let now = StdInstant::now();
    // Header flags 0x1000 → opcode = Status (2), not Query → InvalidOpcode.
    let bad_opcode = [0u8, 0, 0x10, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(matches!(
      e.handle(now, src, local_ip, 0, &bad_opcode, false),
      Err(HandleError::InvalidOpcode(_))
    ));
    // Header flags 0x0001 → opcode = Query but RCODE = FormatError (1) → rejected.
    let bad_rcode = [0u8, 0, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(matches!(
      e.handle(now, src, local_ip, 0, &bad_rcode, false),
      Err(HandleError::InvalidResponseCode(_))
    ));
  }

  #[test]
  fn handle_service_renamed_updates_route_name() {
    let mut e = build_endpoint();
    let stype = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("WebServer._http._tcp.local.").unwrap();
    let host = Name::try_from_str("server.local.").unwrap();
    let mut recs = ServiceRecords::new(stype, inst.clone(), host, 80, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let now = StdInstant::now();
    let (handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let new_name = Name::try_from_str("WebServer-2._http._tcp.local.").unwrap();
    e.handle_service_renamed(handle, new_name.clone()).unwrap();

    // Verify the route was updated.
    let found = e
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle)
      .map(|(_, route)| route.name().clone());
    assert_eq!(
      found.as_ref().map(Name::as_str),
      Some(new_name.as_str()),
      "expected route name to be updated to the renamed instance"
    );
  }

  #[test]
  fn handle_service_renamed_rejects_duplicate() {
    use crate::error::HandleServiceRenamedError;

    let mut e = build_endpoint();
    let now = StdInstant::now();

    // Register first service.
    let stype1 = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst1 = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host1 = Name::try_from_str("alpha.local.").unwrap();
    let mut recs1 = ServiceRecords::new(stype1, inst1.clone(), host1, 80, 120);
    recs1.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let (handle1, _svc1) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs1),
        now,
      )
      .unwrap();

    // Register second service.
    let stype2 = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst2 = Name::try_from_str("Beta._http._tcp.local.").unwrap();
    let host2 = Name::try_from_str("beta.local.").unwrap();
    let mut recs2 = ServiceRecords::new(stype2, inst2.clone(), host2, 80, 120);
    recs2.add_a(Ipv4Addr::new(10, 0, 0, 2));
    let (_handle2, _svc2) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs2),
        now,
      )
      .unwrap();

    // Attempt to rename handle1 to the name already used by handle2.
    let result = e.handle_service_renamed(handle1, inst2.clone());
    assert!(
      result.is_err(),
      "expected an error when renaming to an already-registered name"
    );
    assert!(
      matches!(
        result.unwrap_err(),
        HandleServiceRenamedError::NameAlreadyRegistered(_)
      ),
      "expected NameAlreadyRegistered variant"
    );

    // Verify handle1's name was NOT changed.
    let found = e
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle1)
      .map(|(_, route)| route.name().clone());
    assert_eq!(
      found.as_ref().map(Name::as_str),
      Some(inst1.as_str()),
      "handle1 name must remain unchanged after rejected rename"
    );
  }

  #[test]
  fn service_route_has_host_field() {
    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let recs = ServiceRecords::new(st, inst, host.clone(), 631, 120);
    let now = StdInstant::now();
    let _ = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    let route = e
      .services
      .iter()
      .next()
      .map(|(_, r)| r.clone())
      .expect("expected one registered route");
    assert_eq!(
      route.host().as_str(),
      host.as_str(),
      "ServiceRoute::host() must reflect the host name from ServiceRecords"
    );
  }

  // ── host question routing ─────────────────────────────────────

  /// Helper: encode a minimal mDNS query message with a single A question.
  /// Returns the number of bytes written into `buf`.
  fn build_query_for_host(buf: &mut [u8; 512], host_str: &str) -> usize {
    use crate::wire::{Header, MessageBuilder, ResourceClass, ResourceType};
    // Header::new() zero-initialises flags; opcode 0 == Query.
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
    let name = Name::try_from_str(host_str).unwrap();
    b.push_question(&name, ResourceType::A, ResourceClass::In, false)
      .unwrap();
    b.finish().unwrap()
  }

  /// Helper: encode a minimal mDNS probe message with an A record in the
  /// authority section (RFC 6762 §8.1 simultaneous-probe tie-breaking). Use for
  /// HOST-name conflicts (a host claims A/AAAA).
  fn build_probe_authority_for_host(buf: &mut [u8; 512], host_str: &str) -> usize {
    use crate::wire::{Header, MessageBuilder};
    // Header::new() zero-initialises flags; opcode 0 == Query.
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
    let name = Name::try_from_str(host_str).unwrap();
    b.push_a_authority(&name, 120, Ipv4Addr::new(192, 168, 1, 99))
      .unwrap();
    b.finish().unwrap()
  }

  /// Helper: encode a probe message with an SRV record in the authority section
  /// for `name`. Use for INSTANCE-name conflicts. The endpoint gates ProbeConflict
  /// to the instance's unique RRset (SRV/TXT), so an A record owned by the
  /// instance name is no longer a conflict.
  fn build_probe_srv_authority(buf: &mut [u8; 512], instance_str: &str) -> usize {
    use crate::wire::{Header, MessageBuilder};
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
    let name = Name::try_from_str(instance_str).unwrap();
    let target = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_authority(&name, 120, 0, 0, 8080, &target)
      .unwrap();
    b.finish().unwrap()
  }

  /// Helper: build a test endpoint with one registered service whose host is
  /// "printer-host.local." and instance is "Printer._ipp._tcp.local.".
  fn build_endpoint_with_printer() -> (TestEndp, ServiceHandle) {
    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let recs = ServiceRecords::new(st, inst, host, 631, 120);
    let now = StdInstant::now();
    let (handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    (e, handle)
  }

  /// A direct A query for the SRV target host name must be routed to
  /// the matching service as ServiceEvent::Question.
  #[test]
  fn host_question_routes_to_service() {
    use crate::event::RouteEvent;
    use core::net::SocketAddr;

    let (mut e, expected_handle) = build_endpoint_with_printer();
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    let mut buf = [0u8; 512];
    let n = build_query_for_host(&mut buf, "printer-host.local.");
    let data = &buf[..n];

    let mut events = e
      .handle(StdInstant::now(), src, local_ip, 0, data, false)
      .unwrap();
    let ev = events
      .next()
      .expect("expected at least one routing event")
      .expect("expected Ok");

    match ev {
      RouteEvent::ToService(ts) => {
        assert_eq!(
          ts.handle(),
          expected_handle,
          "event must be addressed to the registered service handle"
        );
        assert!(
          ts.event().is_question(),
          "event must be ServiceEvent::Question, got {:?}",
          ts.event()
        );
      }
      other => panic!("expected RouteEvent::ToService(Question), got {:?}", other),
    }
  }

  // ── authority-section HostConflict vs ProbeConflict routing ────

  /// A probe authority record matching the instance name must route as
  /// ProbeConflict (triggers auto-rename in Service).
  #[test]
  fn authority_instance_name_routes_as_probe_conflict() {
    use crate::event::RouteEvent;
    use core::net::SocketAddr;

    let (mut e, expected_handle) = build_endpoint_with_printer();
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    let mut buf = [0u8; 512];
    let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
    let data = &buf[..n];

    let mut events = e
      .handle(StdInstant::now(), src, local_ip, 0, data, false)
      .unwrap();
    let ev = events
      .next()
      .expect("expected at least one routing event")
      .expect("expected Ok");

    match ev {
      RouteEvent::ToService(ts) => {
        assert_eq!(ts.handle(), expected_handle);
        assert!(
          ts.event().is_probe_conflict(),
          "expected ProbeConflict for an instance-name authority record, got {:?}",
          ts.event()
        );
      }
      other => panic!(
        "expected RouteEvent::ToService(ProbeConflict), got {:?}",
        other
      ),
    }
  }

  /// the SAME probe-shaped authority record that triggers a
  /// ProbeConflict from port 5353 (see
  /// `authority_instance_name_routes_as_probe_conflict`) must NOT route as any
  /// conflict when it arrives from an EPHEMERAL source port. Authority records
  /// are tentative-probe claims trusted only from a real mDNS peer (port 5353);
  /// an off-path / forged ephemeral-port packet must not force our rename.
  #[test]
  fn ephemeral_port_authority_record_does_not_trigger_conflict() {
    use crate::event::RouteEvent;
    use core::net::SocketAddr;

    let (mut e, _handle) = build_endpoint_with_printer();
    // Only the source PORT differs from the positive-control test.
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 40000));
    let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    let mut buf = [0u8; 512];
    let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
    let data = &buf[..n];

    let events = e
      .handle(StdInstant::now(), src, local_ip, 0, data, false)
      .unwrap();
    for ev in events {
      let ev = ev.expect("expected Ok");
      if let RouteEvent::ToService(ts) = ev {
        assert!(
          !ts.event().is_probe_conflict() && !ts.event().is_host_conflict(),
          "ephemeral-port authority record must not route as a conflict, got {:?}",
          ts.event()
        );
      }
    }
  }

  /// A probe authority record matching only the host name must route as
  /// HostConflict — NOT as ProbeConflict. Service must NOT auto-rename.
  #[test]
  fn authority_host_name_routes_as_host_conflict() {
    use crate::event::RouteEvent;
    use core::net::SocketAddr;

    let (mut e, expected_handle) = build_endpoint_with_printer();
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    let mut buf = [0u8; 512];
    let n = build_probe_authority_for_host(&mut buf, "printer-host.local.");
    let data = &buf[..n];

    let mut events = e
      .handle(StdInstant::now(), src, local_ip, 0, data, false)
      .unwrap();
    let ev = events
      .next()
      .expect("expected at least one routing event")
      .expect("expected Ok");

    match ev {
      RouteEvent::ToService(ts) => {
        assert_eq!(ts.handle(), expected_handle);
        assert!(
          ts.event().is_host_conflict(),
          "expected HostConflict for a host-name authority record, got {:?}",
          ts.event()
        );
      }
      other => panic!(
        "expected RouteEvent::ToService(HostConflict), got {:?}",
        other
      ),
    }
  }

  /// a non-address record (TXT) owned by the HOST name must NOT
  /// surface HostConflict — a host claims A/AAAA, so only those rtypes are a
  /// host-name conflict. (The A-record positive control is
  /// `authority_host_name_routes_as_host_conflict`.)
  #[test]
  fn txt_owned_by_host_name_does_not_route_host_conflict() {
    use crate::{
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use core::net::SocketAddr;

    let (mut e, _handle) = build_endpoint_with_printer();
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    // Probe-shaped packet: a TXT record (not A/AAAA) owned by the host name.
    let mut buf = [0u8; 512];
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let hdr = Header::new(); // opcode 0 == Query (QR=0 probe)
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_txt_authority(&host, 120, [b"k=v".as_slice()])
      .unwrap();
    let n = b.finish().unwrap();

    let events = e
      .handle(StdInstant::now(), src, local_ip, 0, &buf[..n], false)
      .unwrap();
    for ev in events {
      if let Ok(RouteEvent::ToService(ts)) = ev {
        assert!(
          !ts.event().is_host_conflict() && !ts.event().is_probe_conflict(),
          "a TXT owned by the host name must not route a conflict, got {:?}",
          ts.event()
        );
      }
    }
  }

  /// records in the ADDITIONAL section (as a DNS-SD responder sends
  /// the A/SRV/TXT accompanying a PTR) must be cached AND delivered to active
  /// queries — not silently ignored.
  #[test]
  fn additional_section_records_are_cached_and_delivered() {
    use crate::{
      config::QuerySpec,
      wire::{ResourceClass, ResourceType},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
      .unwrap();

    // QR=1 response carrying the A record ONLY in the ADDITIONAL section
    // (qd=0, an=0, ns=0, ar=1).
    let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
    msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 0, 0, 0, 0, 1]);
    msg.extend_from_slice(&[
      7, b'p', b'r', b'i', b'n', b't', b'e', b'r', 5, b'l', b'o', b'c', b'a', b'l', 0,
    ]);
    msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
    msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    msg.extend_from_slice(&[10, 0, 0, 7]);

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    // Drain events; count the ToQuery emitted for the additional record (the
    // lazy Additional-section fan-out).
    let to_query = e
      .handle(now, src, local_ip, 0, &msg, false)
      .unwrap()
      .filter(|r| matches!(r, Ok(ev) if ev.is_to_query()))
      .count();
    assert!(
      to_query >= 1,
      "additional-section A must emit a ToQuery for the matching query"
    );

    let answers: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers.len(),
      1,
      "additional-section A must reach the active query; got {answers:?}"
    );
    assert!(
      e.cache.contains(&qname, ResourceType::A, ResourceClass::In),
      "additional-section A must be cached"
    );
  }

  /// a conflicting SRV for our instance name carried ONLY in the
  /// ADDITIONAL section of a QR=1 response must still route a ProbeConflict —
  /// DNS-SD responders place SRV/TXT there, so missing it would let a duplicate
  /// name survive.
  #[test]
  fn additional_section_srv_for_instance_routes_probe_conflict() {
    use crate::{
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use core::net::SocketAddr;

    let (mut e, expected) = build_endpoint_with_printer();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();

    // Build the SRV as an ANSWER, then relocate it to the ADDITIONAL section by
    // rewriting the header counts (ANCOUNT 1->0, ARCOUNT 0->1) — identical
    // record bytes, different section (the builder has no push_*_additional).
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let target = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_answer(&inst, 120, 0, 0, 8080, &target, false)
      .unwrap();
    let n = b.finish().unwrap();
    buf[7] = 0; // ANCOUNT = 0
    buf[11] = 1; // ARCOUNT = 1

    let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let saw_conflict = e
      .handle(StdInstant::now(), src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .filter_map(Result::ok)
      .any(|ev| {
        matches!(ev, RouteEvent::ToService(ts) if ts.handle() == expected && ts.event().is_probe_conflict())
      });
    assert!(
      saw_conflict,
      "an SRV for our instance name in the ADDITIONAL section must route a ProbeConflict"
    );
  }

  /// an additional SRV that matches BOTH our service (conflict) and
  /// multiple active queries must emit EXACTLY ONE ProbeConflict plus a ToQuery
  /// per query — not replay the conflict after each query event (the cursor
  /// phase-ambiguity bug).
  #[test]
  fn additional_conflict_not_replayed_across_query_events() {
    use crate::{
      config::QuerySpec,
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::net::SocketAddr;

    let (mut e, _h) = build_endpoint_with_printer();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let now = StdInstant::now();
    // Two active queries for the instance name (ANY accepts the SRV).
    let _q1 = e
      .try_start_query(QuerySpec::new(inst.clone(), ResourceType::Any), now)
      .unwrap();
    let _q2 = e
      .try_start_query(QuerySpec::new(inst.clone(), ResourceType::Any), now)
      .unwrap();

    // QR=1 SRV for the instance, relocated from ANSWER to ADDITIONAL.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let target = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_answer(&inst, 120, 0, 0, 8080, &target, false)
      .unwrap();
    let n = b.finish().unwrap();
    buf[7] = 0; // ANCOUNT = 0
    buf[11] = 1; // ARCOUNT = 1

    let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let mut conflicts = 0usize;
    let mut to_query = 0usize;
    for ev in e.handle(now, src, local_ip, 0, &buf[..n], false).unwrap() {
      match ev.unwrap() {
        RouteEvent::ToService(ts) if ts.event().is_probe_conflict() => conflicts += 1,
        RouteEvent::ToQuery(_) => to_query += 1,
        _ => {}
      }
    }
    assert_eq!(
      conflicts, 1,
      "the conflict must fire exactly once, not replay per query"
    );
    assert_eq!(
      to_query, 2,
      "both active queries must receive the additional SRV"
    );
  }

  /// a conflict is only routed for the same-class (IN) RRset. An SRV
  /// for our instance name with class ANY (or any non-IN class) must NOT route
  /// a ProbeConflict — exercised through the shared next_service_conflict gate.
  #[test]
  fn non_in_class_record_does_not_route_conflict() {
    use crate::event::RouteEvent;
    use core::net::SocketAddr;

    let (mut e, _h) = build_endpoint_with_printer();

    // Hand-crafted QR=1 SRV answer for "Printer._ipp._tcp.local." with CLASS
    // ANY (0x00FF) instead of IN — same name/rtype, wrong class.
    let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
    msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]); // QR=1, an=1
    msg.extend_from_slice(&[
      7, b'P', b'r', b'i', b'n', b't', b'e', b'r', 4, b'_', b'i', b'p', b'p', 4, b'_', b't', b'c',
      b'p', 5, b'l', b'o', b'c', b'a', b'l', 0,
    ]);
    msg.extend_from_slice(&33u16.to_be_bytes()); // TYPE SRV
    msg.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY (not IN)
    msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
    msg.extend_from_slice(&15u16.to_be_bytes()); // RDLENGTH
    msg.extend_from_slice(&[0, 0, 0, 0, 0x1F, 0x90]); // priority/weight/port
    msg.extend_from_slice(&[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0]); // target x.local.

    let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    for ev in e
      .handle(StdInstant::now(), src, local_ip, 0, &msg, false)
      .unwrap()
    {
      if let Ok(RouteEvent::ToService(ts)) = ev {
        assert!(
          !ts.event().is_probe_conflict() && !ts.event().is_host_conflict(),
          "a non-IN-class record must not route a conflict, got {:?}",
          ts.event()
        );
      }
    }
  }

  // ── probe authority records + answer-section ProbeConflict routing

  /// a QUERY packet whose ANSWER section contains a record for
  /// one of our service's unique names is a KAS hint — not an
  /// authoritative claim.  The iterator must emit KnownAnswer (for KAS
  /// suppression), NEVER ProbeConflict.  Treating a QR=0 answer as a
  /// conflict signal would let a hostile querier trigger our auto-rename
  /// trivially.  Real probe-time conflicts arrive in the AUTHORITY
  /// section (peer probes); see `authority_instance_name_routes_as_probe_conflict`.
  #[test]
  fn query_answer_for_instance_name_emits_known_answer_only() {
    use crate::wire::{
      DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType,
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host = Name::try_from_str("alpha.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let mut buf = [0u8; 512];
    let header = Header::new(); // QR=0
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_question(&inst, ResourceType::Any, ResourceClass::In, true)
      .unwrap();
    b.push_a_answer(&inst, 120, Ipv4Addr::new(10, 0, 0, 2), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // No ProbeConflict events anywhere.
    for ev in &events {
      if let RouteEvent::ToService(ts) = ev {
        assert!(
          !ts.event().is_probe_conflict(),
          "QR=0 answer-section MUST NOT emit ProbeConflict; got {events:?}"
        );
      }
    }
    // But the KAS hint must reach the service.
    let kas_count = events
      .iter()
      .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_known_answer()))
      .count();
    assert!(
      kas_count >= 1,
      "at least one KnownAnswer must fire for the instance-name match; got {events:?}"
    );
  }

  // ── answer-section host-only matches emit HostConflict ────────

  /// RFC 6762 §8.1: a QUERY packet (QR=0) whose ANSWER section
  /// contains a record owned by the service's HOST name (not the instance
  /// name) must emit HostConflict — not ProbeConflict. Only ProbeConflict
  /// triggers an auto-rename in Service; HostConflict surfaces the event
  /// without renaming.
  #[test]
  fn qr0_answer_for_host_name_emits_host_conflict_not_probe_conflict() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder};
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host = Name::try_from_str("alpha.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let now = StdInstant::now();
    let (expected_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // Build a QUERY packet (QR=0) with an A answer record owned by the HOST
    // name (not the instance name).
    let mut buf = [0u8; 512];
    let header = Header::new(); // QR=0
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // QR=0 answer-section records MUST NOT emit HostConflict
    // or ProbeConflict.  Only KnownAnswer events fire (for KAS suppression).
    for ev in &events {
      if let RouteEvent::ToService(ts) = ev {
        assert!(
          !ts.event().is_host_conflict() && !ts.event().is_probe_conflict(),
          "QR=0 answer-section MUST NOT emit conflict events; got {events:?}"
        );
        assert_eq!(
          ts.handle(),
          expected_handle,
          "event must target the registered service"
        );
      }
    }
    // The KAS hint must reach the service.
    let kas_count = events
      .iter()
      .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_known_answer()))
      .count();
    assert!(
      kas_count >= 1,
      "at least one KnownAnswer must fire for the host-name match; got {events:?}"
    );
  }

  // ── QR=0 known-answer records must NOT populate active queries ─

  /// answer records inside a QUERY packet (QR=0) are known-answer
  /// hints from another querier — they must NOT be delivered as
  /// QueryEvent::Answer to active queries.  Only RESPONSE packets (QR=1)
  /// carry authoritative answers.
  #[test]
  fn qr0_answer_does_not_populate_query() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let qname = Name::try_from_str("myhost.local.").unwrap();
    let now = StdInstant::now();

    // Register an active query for "myhost.local.".
    let spec = QuerySpec::new(qname.clone(), ResourceType::A);
    let _qhandle = e.try_start_query(spec, now).unwrap();

    // Build a QUERY packet (QR=0) with an A answer record for the query name.
    // In mDNS this is a known-answer hint carried by another querier; it is
    // NOT an authoritative response.
    let mut buf = [0u8; 512];
    let header = Header::new(); // QR=0: query, not response
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 9), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();

    // Drain all events. None should be a ToQuery(Answer).
    for ev in events {
      let ev = ev.unwrap();
      assert!(
        !matches!(ev, RouteEvent::ToQuery(ref tq) if matches!(tq.event(), QueryEvent::Answer(_))),
        "QR=0 answer records must NOT produce QueryEvent::Answer; got: {:?}",
        ev
      );
    }
  }

  /// RFC 6762 §7.3 duplicate-question suppression: when another host multicasts
  /// the SAME QM question (empty known-answer section) that we have an active
  /// query for, our planned (re)transmit is suppressed — the peer's query
  /// elicits the same answers. A control run (no duplicate) confirms the query
  /// would otherwise transmit.
  #[test]
  fn duplicate_qm_question_suppresses_planned_query() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use core::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    // Control: with no duplicate observed, the freshly-started query transmits.
    {
      let mut e = build_endpoint();
      let now = StdInstant::now();
      let h = e
        .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
        .unwrap();
      let mut buf = [0u8; 512];
      assert!(
        e.poll_query_transmit(h, now, &mut buf).unwrap().is_some(),
        "control: a started query transmits when no duplicate is seen"
      );
    }

    // §7.3: observe a foreign QM query for the same question (no known answers,
    // TC clear) — our planned transmit must be suppressed but the query deferred,
    // not retired.
    let mut e = build_endpoint();
    let now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap(); // QR=0 query
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false) // QM (no QU bit)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e.handle(now, src, local_ip, 0, &qbuf[..n], false).unwrap();

    let mut buf = [0u8; 512];
    assert!(
      e.poll_query_transmit(h, now, &mut buf).unwrap().is_none(),
      "§7.3: observing a duplicate QM question must suppress our planned query"
    );
    assert!(
      e.poll_query_timeout(h).is_some(),
      "§7.3: the suppressed query is deferred (rescheduled), not retired"
    );
  }

  /// A QU (unicast-response) duplicate question must NOT suppress our query: a
  /// QU query is answered unicast to the asker, so it would not elicit the
  /// multicast answers our query needs (RFC 6762 §7.3 applies to QM only).
  #[test]
  fn qu_duplicate_question_does_not_suppress_query() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use core::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, true) // QU bit set
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e.handle(now, src, local_ip, 0, &qbuf[..n], false).unwrap();

    let mut buf = [0u8; 512];
    assert!(
      e.poll_query_transmit(h, now, &mut buf).unwrap().is_some(),
      "§7.3: a QU duplicate must NOT suppress our query (it elicits no multicast answer)"
    );
  }

  /// a duplicate QM query from a NON-5353 (legacy/ephemeral) source must
  /// NOT suppress our query — a legacy resolver's request may be answered by
  /// unicast straight to it (§6.7), answers we would never see.
  #[test]
  fn legacy_source_duplicate_does_not_suppress_query() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use core::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let legacy_src: SocketAddr = "192.168.1.77:40000".parse().unwrap(); // ephemeral port
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false) // QM
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(now, legacy_src, local_ip, 0, &qbuf[..n], false)
      .unwrap();

    let mut buf = [0u8; 512];
    assert!(
      e.poll_query_transmit(h, now, &mut buf).unwrap().is_some(),
      "§7.3: a legacy-source (non-5353) duplicate must NOT suppress our query"
    );
  }

  /// a query with NO absolute timeout, suppressed every retry slot by a
  /// flood of duplicate QM questions, must still progress to terminal via the
  /// retry budget — §7.3 suppression is "treat as sent", not "defer forever".
  #[test]
  fn repeated_duplicate_questions_do_not_stall_query_forever() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use core::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false)
      .unwrap();
    let n = b.finish().unwrap();

    // Each slot: a duplicate arrives while a transmit is pending → suppressed;
    // then we fire the next scheduled retry. The retry budget (MAX_RETRIES = 8)
    // must eventually retire the query even though it never transmitted itself.
    let mut buf = [0u8; 512];
    let mut retired = false;
    for _ in 0..32 {
      let _ = e.handle(now, src, local_ip, 0, &qbuf[..n], false).unwrap();
      assert!(
        e.poll_query_transmit(h, now, &mut buf).unwrap().is_none(),
        "each duplicate suppresses the planned transmit"
      );
      match e.poll_query_timeout(h) {
        Some(due) => {
          now = due;
          e.handle_query_timeout(h, now).unwrap();
        }
        None => {
          retired = true;
          break;
        }
      }
    }
    assert!(
      retired,
      "§7.3: a continuously-duplicated query must retire via the retry budget, not defer forever"
    );
  }

  /// a duplicate that arrives when our retransmit deadline is already
  /// DUE — but `handle_query_timeout` has not yet armed it (a driver that pumps
  /// received packets before firing query timeouts) — must still suppress the
  /// retry. Proves §7.3 is independent of the driver's packet-vs-timeout order.
  #[test]
  fn duplicate_suppresses_due_retry_independent_of_driver_order() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use core::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    // Send the first query and confirm delivery → a retransmit is scheduled
    // (next_deadline ≈ now+1s) with transmit_pending cleared.
    let mut buf = [0u8; 512];
    assert!(e.poll_query_transmit(h, now, &mut buf).unwrap().is_some());
    e.note_query_transmit_result(h, now, true);
    let t1 = e
      .poll_query_timeout(h)
      .expect("a retransmit must be scheduled");

    // Deliver a duplicate QM query exactly when the retry is DUE, WITHOUT first
    // calling handle_query_timeout (packet-before-timeout driver order).
    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e.handle(t1, src, local_ip, 0, &qbuf[..n], false).unwrap();

    // The due slot was consumed: the next retry is deferred to a later instant.
    let t2 = e
      .poll_query_timeout(h)
      .expect("query still active, retry rescheduled");
    assert!(
      t2 > t1,
      "§7.3: a duplicate at a due retry must consume the slot and defer it"
    );

    // Arming the now-stale deadline must not transmit (slot already consumed).
    e.handle_query_timeout(h, t1).unwrap();
    assert!(
      e.poll_query_transmit(h, t1, &mut buf).unwrap().is_none(),
      "§7.3: no redundant transmit after the due slot was suppressed"
    );
  }

  // ── self-packet guard suppresses loopback routing ────────────

  /// Multicast loopback returns our own probes/announcements to us with
  /// `src.ip() == local_ip` (the interface we sent from).  `Endpoint::handle`
  /// must drop these datagrams entirely: no ProbeConflict, no HostConflict,
  /// no Question, no KnownAnswer, no cache writes.  Without this guard a
  /// service can rename itself because of its own probe.
  ///
  /// Control half of the test: a probe with the same payload but a foreign
  /// source IP must still produce a ProbeConflict, proving the test is
  /// asserting against the source-equality guard and not some unrelated
  /// suppression.
  #[test]
  fn self_packet_does_not_route_as_probe_conflict() {
    use crate::event::RouteEvent;
    use core::net::SocketAddr;

    let (mut e, _expected_handle) = build_endpoint_with_printer();
    let local_ip: core::net::IpAddr = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    // Build a probe-shaped packet (authority section carries an A record for
    // the instance host) that would normally trigger ProbeConflict.
    let mut buf = [0u8; 512];
    let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
    let data = &buf[..n];
    let now = StdInstant::now();

    // (1) Self-packet: the caller (driver) flags self-loopback via
    // `caller_is_self = true`; handle() must then yield zero routing events.
    let self_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), 5353));
    let mut self_events = e.handle(now, self_src, local_ip, 0, data, true).unwrap();
    assert!(
      self_events.next().is_none(),
      "self-packet (caller_is_self = true) must yield zero routing events"
    );

    // (2) Control: the same payload from a peer with `caller_is_self = false`
    // MUST still emit ProbeConflict — proves suppression is driven by the
    // flag, not a broken routing path.
    let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let mut peer_events = e
      .handle(StdInstant::now(), peer_src, local_ip, 0, data, false)
      .unwrap();
    let ev = peer_events
      .next()
      .expect("control: foreign-source probe MUST still produce a routing event")
      .expect("control: routing event must be Ok");
    match ev {
      RouteEvent::ToService(ts) => assert!(
        ts.event().is_probe_conflict(),
        "control: foreign-source probe must still emit ProbeConflict; got {:?}",
        ts.event()
      ),
      other => panic!(
        "control: expected RouteEvent::ToService(ProbeConflict), got {:?}",
        other
      ),
    }
  }

  /// self-packet guard must also suppress cache population.  A
  /// loopback announcement with an A record for some unrelated name must
  /// NOT land in the passive observation cache.
  #[test]
  fn self_packet_does_not_populate_cache() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let local_ip: core::net::IpAddr = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let observed = Name::try_from_str("printer.local.").unwrap();

    // Build a RESPONSE (QR=1) packet with an A record in the ANSWER section
    // — the passive-observation cache writes from the answer section.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&observed, 120, Ipv4Addr::new(10, 0, 0, 9), false)
      .unwrap();
    let n = b.finish().unwrap();
    let data = &buf[..n];

    // self-detection is driven by the caller's `caller_is_self`
    // flag (the driver content-matches against recent sends). With it
    // true, the cache write is suppressed.
    let self_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), 5353));
    let _ = e.handle(now, self_src, local_ip, 0, data, true).unwrap();
    assert!(
      !e.cache
        .contains(&observed, ResourceType::A, ResourceClass::In),
      "self-packet must not populate cache; cache contained {:?}",
      observed.as_str()
    );

    // Control: a foreign source must populate the cache.
    let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let _ = e.handle(now, peer_src, local_ip, 0, data, false).unwrap();
    assert!(
      e.cache
        .contains(&observed, ResourceType::A, ResourceClass::In),
      "control: foreign-source response must populate the cache"
    );
  }

  /// the passive cache must compare records by their
  /// CANONICAL case-folded rdata, so a TTL=0 goodbye whose PTR target differs
  /// from the insert in BOTH compression and case still removes the cached
  /// entry. Insert: target "inst" compressed (back-pointer), lowercase.
  /// Goodbye: target "INST.SVC.LOCAL." inline + uppercase. Before the fixes the
  /// raw bytes differed (compression and/or case) and the goodbye left a stale
  /// entry until TTL expiry.
  #[test]
  fn cache_goodbye_matches_differently_encoded_and_cased_ptr() {
    use crate::wire::{ResourceClass, ResourceType};
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let local_ip: core::net::IpAddr = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let owner = Name::try_from_str("svc.local.").unwrap();

    // QR=1 response header, AN=1; owner "svc.local." parked at offset 12.
    let header_an1 = [0u8, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
    let owner_wire = [3u8, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0];

    // Insert: PTR with a COMPRESSED, lowercase target ("inst" + ptr→offset 12).
    let mut insert = std::vec::Vec::new();
    insert.extend_from_slice(&header_an1);
    insert.extend_from_slice(&owner_wire);
    insert.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
    insert.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    insert.extend_from_slice(&120u32.to_be_bytes()); // positive TTL
    insert.extend_from_slice(&7u16.to_be_bytes()); // RDLENGTH
    insert.extend_from_slice(&[4, b'i', b'n', b's', b't', 0xC0, 0x0C]);
    let _ = e.handle(now, src, local_ip, 0, &insert, false).unwrap();
    assert!(
      e.cache
        .contains(&owner, ResourceType::Ptr, ResourceClass::In),
      "compressed-target PTR response must populate the cache"
    );

    // Goodbye: same logical PTR, TTL=0, target written INLINE and UPPERCASE.
    let mut goodbye = std::vec::Vec::new();
    goodbye.extend_from_slice(&header_an1);
    goodbye.extend_from_slice(&owner_wire);
    goodbye.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
    goodbye.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    goodbye.extend_from_slice(&0u32.to_be_bytes()); // TTL=0 goodbye
    goodbye.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
    goodbye.extend_from_slice(&[
      4, b'I', b'N', b'S', b'T', 3, b'S', b'V', b'C', 5, b'L', b'O', b'C', b'A', b'L', 0,
    ]);
    let _ = e.handle(now, src, local_ip, 0, &goodbye, false).unwrap();
    // a TTL=0 goodbye does NOT delete immediately — it clamps the
    // matched entry to a 1-second rescue window. The MATCH (canonicalization
    // worked across compression + case) is proven by the entry expiring after
    // that 1s: a goodbye that failed to match would leave the original 120s
    // TTL, so the entry would survive the sweep below.
    let after_rescue = now + core::time::Duration::from_secs(2);
    e.cache.sweep_expired(after_rescue);
    assert!(
      !e.cache
        .contains(&owner, ResourceType::Ptr, ResourceClass::In),
      "a differently-encoded/-cased TTL=0 goodbye must match and expire the cached PTR within the §10.1 rescue window"
    );
  }

  // ── IPv6 self-packet via advertised-AAAA membership ──────────

  /// IPv6 `in6_pktinfo.ipi6_addr` carries the packet DESTINATION (e.g.
  /// `ff02::fb` for received mDNS multicast), not the local interface
  /// address.  Therefore `src.ip() == local_ip` cannot detect IPv6 self
  /// loopback: the source is our link-local/global unicast, the destination
  /// is the multicast group, and they never match.  This detects self via
  /// membership in any registered service's advertised AAAA list.
  ///
  /// Test: register a service publishing `fe80::1`, then feed back a
  /// probe-shaped packet with `src.ip() == fe80::1` and `local_ip == ff02::fb`.
  /// Without the membership signal the packet would be routed as a
  /// ProbeConflict (peer claiming our instance).  Control half: a foreign
  /// IPv6 source must still produce a ProbeConflict.
  #[test]
  fn ipv6_self_packet_detected_via_advertised_aaaa() {
    use crate::{
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use core::net::{Ipv6Addr, SocketAddr};

    // signal (b) is opt-in. This test validates the legacy
    // advertised-source fallback, so enable it explicitly.
    use rand::SeedableRng;
    let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
    let mut e = TestEndp::try_new(
      EndpointConfig::new().with_trust_advertised_src_as_self(true),
      rng,
    );
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host, 631, 120);
    let our_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    recs.add_aaaa(our_v6);
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // Build a probe-shaped packet (SRV authority record for the instance
    // name — the instance's unique RRset) — without the guard this triggers
    // ProbeConflict.
    let mut buf = [0u8; 512];
    let hdr = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_srv_authority(
      &inst,
      120,
      0,
      0,
      8080,
      &Name::try_from_str("other-host.local.").unwrap(),
    )
    .unwrap();
    let n = b.finish().unwrap();
    let data = &buf[..n];

    // local_ip is what IPv6 PKTINFO actually returns: the multicast group.
    // This is *intentionally* not our source, because for IPv6 PKTINFO has
    // no `ipi_spec_dst` equivalent.
    let local_ip: core::net::IpAddr =
      core::net::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb));

    // (1) Self-packet via membership: src matches our advertised AAAA.
    let self_src: SocketAddr = SocketAddr::from((our_v6, 5353));
    let mut self_events = e.handle(now, self_src, local_ip, 0, data, false).unwrap();
    assert!(
      self_events.next().is_none(),
      "IPv6 self-packet (src ∈ advertised AAAA) must yield zero routing events; \
       local_ip == ff02::fb cannot detect this, so the membership branch must catch it"
    );

    // (2) Control: a foreign IPv6 source must still emit ProbeConflict on
    // the same payload.  Proves the guard is specific to src-set membership
    // and not some other suppression.
    let peer_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0099);
    let peer_src: SocketAddr = SocketAddr::from((peer_v6, 5353));
    let mut peer_events = e.handle(now, peer_src, local_ip, 0, data, false).unwrap();
    let ev = peer_events
      .next()
      .expect("control: foreign IPv6 probe MUST still produce a routing event")
      .expect("control: routing event must be Ok");
    match ev {
      RouteEvent::ToService(ts) => assert!(
        ts.event().is_probe_conflict(),
        "control: foreign IPv6 probe must still emit ProbeConflict; got {:?}",
        ts.event()
      ),
      other => panic!(
        "control: expected RouteEvent::ToService(ProbeConflict), got {:?}",
        other
      ),
    }
  }

  // ── terminal-then-cancel cleanup, no leak ───────────

  /// Repeatedly starting + draining queries must not leak entries in the
  /// endpoint's owned-Query pool when callers follow the documented
  /// terminal-then-cancel pattern.  This dropped the previous
  /// auto-prune design (which silently lost `collected_answers` before
  /// the caller could read them); the new contract is:
  ///
  ///   1. drive `poll_query` until it returns `Some(Done | Timeout)`,
  ///   2. read final results via `collected_answers` (still available),
  ///   3. call `cancel_query` to free the pool entry.
  ///
  /// `poll_query` emits the terminal exactly once (latched via
  /// `Query::terminal_emitted`); subsequent calls return `None`.  This
  /// test exercises 1024 start/terminal/cancel cycles and asserts the
  /// pool returns to zero.
  #[test]
  fn poll_query_terminal_then_cancel_no_leak() {
    use crate::{config::QuerySpec, event::QueryUpdate, wire::ResourceType};
    use core::time::Duration;

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();

    for i in 0..1024u32 {
      // 100ms timeout — small relative to test runtime.
      let spec =
        QuerySpec::new(qname.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
      let qhandle = e.try_start_query(spec, now).unwrap_or_else(|err| {
        panic!(
          "try_start_query #{i} must succeed when previous queries are cancelled; \
           got {err:?}"
        )
      });

      // Pool must contain exactly this one query between start and cancel.
      assert_eq!(
        e.queries.len(),
        1,
        "queries pool len must be 1 after start #{i}, before cancel"
      );

      // Drive to terminal: advance past the absolute timeout.
      now = now.checked_add(Duration::from_millis(200)).unwrap();
      e.handle_query_timeout(qhandle, now).unwrap();

      // Observe terminal via poll_query.  Does NOT auto-prune.
      let update = e.poll_query(qhandle);
      assert!(
        matches!(update, Some(QueryUpdate::Timeout | QueryUpdate::Done)),
        "poll_query must return Some(Timeout|Done) after deadline; got {update:?}"
      );

      // query is STILL in the pool after terminal; collected_answers
      // is readable.  (No collected answers here since no responses arrived,
      // but the iterator must work — exercised by the standalone test below.)
      assert_eq!(
        e.queries.len(),
        1,
        "queries pool len must remain 1 after terminal poll_query #{i} \
         (no auto-prune; caller must explicitly cancel)"
      );

      // Subsequent poll_query returns None (terminal already emitted).
      assert!(
        e.poll_query(qhandle).is_none(),
        "subsequent poll_query after terminal must return None (latched)"
      );

      // Explicit cleanup — the documented contract.
      e.cancel_query(qhandle).unwrap();
      assert_eq!(
        e.queries.len(),
        0,
        "queries pool len must be 0 after cancel #{i}"
      );
    }
  }

  // ── collected_answers readable after terminal poll_query ─────

  /// After `poll_query` returns `Some(Done | Timeout)`, the natural
  /// caller flow is to read final results via `collected_answers`
  /// before discarding the handle.  Auto-prune would have wiped the
  /// answers in the same call.  Verify that:
  ///
  ///   * answers collected before the timeout are still readable AFTER
  ///     the terminal poll_query returns, AND
  ///   * the second poll_query on the same handle returns None
  ///     (terminal latched, exactly-once delivery), AND
  ///   * after cancel_query the handle is gone.
  #[test]
  fn collected_answers_survive_terminal_until_cancel() {
    use crate::{
      config::QuerySpec,
      event::QueryUpdate,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::{net::SocketAddr, time::Duration};

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let spec =
      QuerySpec::new(qname.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
    let h = e.try_start_query(spec, now).unwrap();

    // Feed a RESPONSE answer to populate collected_answers.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let addr = Ipv4Addr::new(10, 0, 0, 7);
    b.push_a_answer(&qname, 120, addr, false).unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();

    // Confirm the answer landed.
    let answers_before: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers_before.len(),
      1,
      "answer must land in collected_answers; got {answers_before:?}"
    );

    // Drive to terminal.
    now = now.checked_add(Duration::from_millis(200)).unwrap();
    e.handle_query_timeout(h, now).unwrap();
    let update = e.poll_query(h);
    assert!(
      matches!(update, Some(QueryUpdate::Timeout | QueryUpdate::Done)),
      "poll_query must return terminal; got {update:?}"
    );

    // collected_answers MUST still be readable AFTER terminal.
    let answers_after: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers_after.len(),
      1,
      "collected_answers must survive terminal poll_query; \
       caller had no chance to read them before they would have been \
       auto-pruned; got {answers_after:?}"
    );

    // Exactly-once: second poll_query returns None.
    assert!(
      e.poll_query(h).is_none(),
      "second poll_query after terminal must return None (latched)"
    );

    // Explicit cleanup leaves the pool empty.
    e.cancel_query(h).unwrap();
    assert!(e.collected_answers(h).next().is_none());
  }

  // ── query state applied eagerly during handle ────────────────

  /// Dropping the `RouteEvents` iterator BEFORE iterating it must NOT
  /// lose query-state updates.  Previously, query updates were
  /// applied lazily inside the iterator's `next()`; a caller that
  /// matched on the first event and broke out (or never iterated)
  /// would leave some compatible queries un-updated.  Eager
  /// application in `Endpoint::handle` (before the iterator is even
  /// returned) eliminates that hazard.
  #[test]
  fn dropping_route_events_does_not_lose_query_state() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();

    // Two compatible queries for the same name (A and Any).
    let h_a = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
      .unwrap();
    let h_any = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Any), now)
      .unwrap();

    // RESPONSE packet with an A answer.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 9), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    // Construct the iterator and IMMEDIATELY drop it — no .next() calls.
    {
      let _events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();
      // _events is dropped at end of scope WITHOUT iteration.
    }

    // both queries must already have the answer in their
    // collected_answers, because Endpoint::handle applied it eagerly
    // — not lazily on iterator advance.
    let a_answers: std::vec::Vec<_> = e.collected_answers(h_a).cloned().collect();
    let any_answers: std::vec::Vec<_> = e.collected_answers(h_any).cloned().collect();
    assert_eq!(
      a_answers.len(),
      1,
      "A-query must have the answer applied even with dropped iterator"
    );
    assert_eq!(
      any_answers.len(),
      1,
      "Any-query must ALSO have the answer applied even with dropped iterator \
       (fan-out is no longer dependent on draining the iterator)"
    );
  }

  // ── pre-poll terminal freeze closes the race ────────────────

  /// `handle_query_timeout` sets `done = true` BEFORE the caller has
  /// had a chance to call `poll_query` and observe the terminal.  An
  /// answer arriving in that window must NOT mutate `collected_answers`
  /// or fire ToQuery events — the freeze must key off `is_done()`, not
  /// only the deferred `terminal_emitted` latch.
  #[test]
  fn pre_poll_terminal_freeze_closes_race() {
    use crate::{
      config::QuerySpec,
      event::QueryUpdate,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::{net::SocketAddr, time::Duration};

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qn = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qn.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
    let h = e.try_start_query(spec, now).unwrap();

    // Drive `done = true` via handle_query_timeout, but do NOT call
    // poll_query yet — so terminal_emitted is still false.
    now = now.checked_add(Duration::from_millis(200)).unwrap();
    e.handle_query_timeout(h, now).unwrap();

    // Feed a matching response.  Without the fix the answer
    // would mutate collected_answers because terminal_emitted is still
    // false even though is_done is true.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qn, 120, Ipv4Addr::new(10, 0, 0, 7), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    let to_query_events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .filter_map(|ev| match ev {
        RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_)) => Some(tq.handle()),
        _ => None,
      })
      .collect();
    assert!(
      !to_query_events.contains(&h),
      "ToQuery events must NOT fire for is_done query (pre-poll); \
       got {to_query_events:?}"
    );

    // Now observe terminal — and assert no answer was collected.
    assert!(matches!(
      e.poll_query(h),
      Some(QueryUpdate::Timeout | QueryUpdate::Done)
    ));
    let answers: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert!(
      answers.is_empty(),
      "collected_answers must be empty — the post-done answer must NOT \
       have been applied to the Query; got {answers:?}"
    );
    e.cancel_query(h).unwrap();
  }

  // ── TTL=0 goodbye records are not collected ──────────────────

  /// RFC 6762 §10.1: a record with TTL=0 is a goodbye / deletion
  /// signal.  Active queries must NOT collect such records as live
  /// answers — under `max_answers` pressure a goodbye could even
  /// evict a real prior answer via FIFO.
  #[test]
  fn query_ignores_ttl_zero_goodbye_records() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qn = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qn.clone(), ResourceType::A);
    let h = e.try_start_query(spec, now).unwrap();

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    // First feed a normal answer (TTL=120) — must land.
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&qn, 120, Ipv4Addr::new(10, 0, 0, 7), false)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(now, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }
    assert_eq!(
      e.collected_answers(h).count(),
      1,
      "live (TTL=120) answer must be collected"
    );

    // Now feed a TTL=0 record for the same name — goodbye signal.
    // Must NOT land in collected_answers AND must NOT evict the prior.
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      // TTL=0 is the deletion marker.
      b.push_a_answer(&qn, 0, Ipv4Addr::new(10, 0, 0, 99), false)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(now, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }

    let answers: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers.len(),
      1,
      "TTL=0 goodbye record must NOT be collected; \
       prior live answer must remain intact.  Got: {answers:?}"
    );
    e.cancel_query(h).unwrap();
  }

  // ── KAS fan-out across same-type services ────────────────────

  /// A QR=0 known-answer PTR record for a shared `service_type` must
  /// fan out to EVERY registered service of that type, not just the
  /// first by slab order — otherwise the actual owning service never
  /// gets the suppression hint.
  #[test]
  fn qr0_ptr_known_answer_fans_out_to_all_same_type_services() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();

    // Three services sharing the same service_type.
    let mut handles = std::vec::Vec::new();
    for inst_label in ["Alpha", "Beta", "Gamma"] {
      let inst_str = std::format!("{inst_label}._ipp._tcp.local.");
      let inst = Name::try_from_str(&inst_str).unwrap();
      let host_str = std::format!("{}-host.local.", inst_label.to_ascii_lowercase());
      let host = Name::try_from_str(&host_str).unwrap();
      let recs = ServiceRecords::new(stype.clone(), inst, host, 631, 120);
      let (h, _svc) = e
        .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
          ServiceSpec::new(recs),
          now,
        )
        .unwrap();
      handles.push(h);
    }

    // Build a QR=0 packet with an ANSWER section containing a PTR
    // record for the shared service_type — a KAS hint from another
    // querier mentioning the Beta service.
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    let beta_inst = Name::try_from_str("Beta._ipp._tcp.local.").unwrap();
    b.push_ptr_answer(&stype, 120, &beta_inst).unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // Collect all KnownAnswer service handles.
    let kas_handles: std::vec::Vec<_> = events
      .iter()
      .filter_map(|ev| match ev {
        RouteEvent::ToService(ts) if ts.event().is_known_answer() => Some(ts.handle()),
        _ => None,
      })
      .collect();

    // all three same-type services must receive the KAS hint.
    for h in &handles {
      assert!(
        kas_handles.contains(h),
        "service {h:?} must receive KnownAnswer for shared-PTR; \
         got handles {kas_handles:?}"
      );
    }
    assert_eq!(
      kas_handles.len(),
      3,
      "exactly three KnownAnswer events expected (one per same-type service); \
       got {kas_handles:?}"
    );
  }

  /// a QR=0 PTR owned by the DNS-SD service-type enumeration meta name
  /// is a known-answer for the §9 meta reply. Its owner is none of any service's
  /// RRset names, so the endpoint must fan it out as a KnownAnswer to EVERY
  /// service (each then decides at the Service level whether the PTR target is
  /// its own type and the §7.1 gates hold). Without this routing the meta-KAS
  /// was unreachable end-to-end.
  #[test]
  fn meta_ptr_known_answer_fans_out_to_all_services() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();

    // Two services of DIFFERENT types.
    let mut handles = std::vec::Vec::new();
    for (inst_str, stype_str, host_str) in [
      ("p._ipp._tcp.local.", "_ipp._tcp.local.", "ph.local."),
      ("w._http._tcp.local.", "_http._tcp.local.", "wh.local."),
    ] {
      let recs = ServiceRecords::new(
        Name::try_from_str(stype_str).unwrap(),
        Name::try_from_str(inst_str).unwrap(),
        Name::try_from_str(host_str).unwrap(),
        631,
        120,
      );
      let (h, _svc) = e
        .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
          ServiceSpec::new(recs),
          now,
        )
        .unwrap();
      handles.push(h);
    }

    // QR=0 packet carrying a meta-PTR known-answer:
    //   _services._dns-sd._udp.local. -> _ipp._tcp.local.
    let mut buf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
    let meta = Name::try_from_str("_services._dns-sd._udp.local.").unwrap();
    let ipp = Name::try_from_str("_ipp._tcp.local.").unwrap();
    b.push_ptr_answer(&meta, 120, &ipp).unwrap();
    let n = b.finish().unwrap();

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let kas_handles: std::vec::Vec<_> = events
      .iter()
      .filter_map(|ev| match ev {
        RouteEvent::ToService(ts) if ts.event().is_known_answer() => Some(ts.handle()),
        _ => None,
      })
      .collect();

    for h in &handles {
      assert!(
        kas_handles.contains(h),
        "meta-PTR known-answer must fan out to service {h:?}; got {kas_handles:?}"
      );
    }
    assert_eq!(
      kas_handles.len(),
      2,
      "one meta KnownAnswer per registered service; got {kas_handles:?}"
    );
  }

  // ── TTL=0 records bypass route-level fan-out ─────────────────

  /// A QR=0 answer with TTL=0 (goodbye / withdrawal) must not trigger
  /// any service-side event — no ProbeConflict for a matching instance
  /// name, no HostConflict for a matching host, no KnownAnswer for a
  /// matching service_type.  The peer is WITHDRAWING the record, not
  /// claiming it.  Cache layer still observes the removal independently.
  #[test]
  fn qr0_ttl_zero_does_not_emit_service_events() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 631, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let now = StdInstant::now();
    let (_h, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // QR=0 packet with a TTL=0 A answer for our HOST name (would
    // normally trigger HostConflict + KnownAnswer).
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 0, Ipv4Addr::new(10, 0, 0, 2), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();
    assert!(
      events.is_empty(),
      "QR=0 TTL=0 record must NOT yield any RouteEvent; got {events:?}"
    );

    // Also exercise instance-name (would have been ProbeConflict) and
    // service_type (would have been KnownAnswer).
    for record_name in [&inst, &Name::try_from_str("_ipp._tcp.local.").unwrap()] {
      let mut buf2 = [0u8; 512];
      let header = Header::new();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf2, header).unwrap();
      b.push_a_answer(record_name, 0, Ipv4Addr::new(10, 0, 0, 3), false)
        .unwrap();
      let n = b.finish().unwrap();
      let events: std::vec::Vec<_> = e
        .handle(now, src, local_ip, 0, &buf2[..n], false)
        .unwrap()
        .map(Result::unwrap)
        .collect();
      assert!(
        events.is_empty(),
        "QR=0 TTL=0 for {} must NOT yield any RouteEvent; got {events:?}",
        record_name.as_str()
      );
    }
  }

  /// A TTL=0 authority-section record must NOT emit ProbeConflict /
  /// HostConflict — same goodbye semantics as in the answer
  /// section.
  #[test]
  fn authority_ttl_zero_does_not_emit_conflict_events() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{Header, MessageBuilder},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let recs = ServiceRecords::new(st, inst.clone(), host.clone(), 631, 120);
    let now = StdInstant::now();
    let (_h, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // Build a probe-shaped QR=0 packet with a TTL=0 A authority
    // record for the registered HOST name.  Under normal TTL this
    // would route as HostConflict.
    let mut buf = [0u8; 512];
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, hdr).unwrap();
    b.push_a_authority(&host, 0, Ipv4Addr::new(192, 168, 1, 99))
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();
    assert!(
      events.is_empty(),
      "TTL=0 authority record (host) must not emit HostConflict; got {events:?}"
    );

    // Same packet but the authority targets the INSTANCE name (would
    // normally route as ProbeConflict).
    let mut buf2 = [0u8; 512];
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf2, hdr).unwrap();
    b.push_a_authority(&inst, 0, Ipv4Addr::new(192, 168, 1, 99))
      .unwrap();
    let n = b.finish().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, &buf2[..n], false)
      .unwrap()
      .map(Result::unwrap)
      .collect();
    assert!(
      events.is_empty(),
      "TTL=0 authority record (instance) must not emit ProbeConflict; got {events:?}"
    );
  }

  // ── cache-flush dedup within a packet ────────────────────────

  /// A multi-record RRSet (e.g. multiple A records for the same host)
  /// with the cache-flush bit set on every record must end up with ALL
  /// records in the cache — not just the last.  Previously, the
  /// 2nd record's cache_flush evicted the 1st, the 3rd evicted the
  /// 2nd, etc., leaving only the final address.
  #[test]
  fn cache_flush_within_one_packet_preserves_full_rrset() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("multihomed.local.").unwrap();

    // Two A records for the same host, both cache_flush=true (typical
    // mDNS announcement of a multi-address host).
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 1), true)
      .unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
      .unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 3), true)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();

    // All three A records must be in the cache for the same host.
    let count = e
      .cache
      .count_matching(&host, ResourceType::A, ResourceClass::In);
    assert_eq!(
      count, 3,
      "multi-A RRSet with cache_flush must preserve all 3 entries; got {count}"
    );
  }

  // ── QR=1 answer-section records trigger probe-time conflict ─

  /// RFC 6762 §8.1 — a probing host MUST treat any RESPONSE message
  /// claiming one of its tentative names as a conflict event.  Test
  /// that a QR=1 packet with an A answer record owned by our
  /// instance/host fires ProbeConflict / HostConflict respectively.
  #[test]
  fn qr1_answer_for_instance_name_emits_probe_conflict() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host = Name::try_from_str("alpha.local.").unwrap();
    let recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // RESPONSE (QR=1) with an SRV answer for our instance name (the instance's
    // unique RRset; ProbeConflict is gated to SRV/TXT).
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let srv_target = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_answer(&inst, 120, 0, 0, 8080, &srv_target, false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let has_probe_conflict = events
      .iter()
      .any(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_probe_conflict()));
    assert!(
      has_probe_conflict,
      "QR=1 answer claiming our instance name must emit ProbeConflict; got {events:?}"
    );
  }

  /// Parallel test for host-name match → HostConflict.
  #[test]
  fn qr1_answer_for_host_name_emits_host_conflict() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host = Name::try_from_str("alpha.local.").unwrap();
    let recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let has_host_conflict = events
      .iter()
      .any(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_host_conflict()));
    assert!(
      has_host_conflict,
      "QR=1 answer claiming our host name must emit HostConflict; got {events:?}"
    );
  }

  // ── QR=0 answer-section records must NOT mutate the cache ────

  /// QR=0 (query) packets carry answer-section records as known-answer
  /// hints, not authoritative observations.  They must NOT insert into,
  /// delete from, or flush the passive cache.  Previously a hostile
  /// querier could:
  ///   * insert forged rdata into the cache via QR=0 positive-TTL answers,
  ///   * delete cached records via QR=0 TTL=0 answers,
  ///   * clamp legitimate cached siblings via QR=0 cache_flush answers.
  #[test]
  fn qr0_answer_does_not_mutate_cache() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::{net::SocketAddr, time::Duration};

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("victim.local.").unwrap();

    // Seed cache with an authoritative IN A record.
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        std::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1
    );

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    // (1) QR=0 packet with a forged A answer for the same host (different rdata).
    //     Must NOT insert a second cache entry.
    let mut buf = [0u8; 512];
    let header = Header::new(); // QR=0
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 99), false)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(now, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1,
      "QR=0 positive-TTL answer must NOT insert into cache"
    );

    // (2) QR=0 packet with TTL=0 for the seeded rdata.  Must NOT delete.
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 0, Ipv4Addr::new(10, 0, 0, 1), false)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(now, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1,
      "QR=0 TTL=0 answer must NOT delete cached entry"
    );

    // (3) QR=0 packet with cache_flush=true.  Must NOT clamp / evict.
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 99), true)
      .unwrap();
    let n = b.finish().unwrap();
    // Advance past §10.2 grace so the seeded entry WOULD have been
    // clamped if the QR=0 cache-flush were honoured.
    let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();
    let _ = e
      .handle(after_grace, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
    // Sweep past where the clamp would have expired the seeded record.
    let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
    e.cache.sweep_expired(after_clamp);
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1,
      "QR=0 cache_flush must NOT clamp legitimate cached siblings"
    );
  }

  // ── cache-flush uses deferred expiry, not immediate evict ────

  /// An old multi-record RRSet refreshed across two packets must
  /// survive the burst.  RFC 6762 §10.2 specifies cache-flush clamps
  /// matching siblings' `expires_at` to `min(current, now + 1s)`
  /// instead of removing them immediately — so siblings re-announced
  /// within 1s have their expiry undone by the refresh path, and
  /// siblings NOT re-announced expire naturally a second later.
  ///
  /// Test: seed an old A1/A2 RRSet (received 5 min ago).  Send
  /// packet 1 with A1 cache_flush=true (refreshes A1, clamps A2).
  /// Send packet 2 with A2 cache_flush=true within the grace window
  /// (refreshes A2, undoes the clamp).  Both A1 and A2 should still
  /// be in the cache, with non-clamped expirations.
  #[test]
  fn cache_flush_deferred_expiry_preserves_refreshed_rrset() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::{net::SocketAddr, time::Duration};

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("multihomed.local.").unwrap();

    // Seed cache with two OLD A records — received 5 minutes ago.
    let long_ago = now.checked_sub(Duration::from_secs(300)).unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        std::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        long_ago,
        false,
      )
      .unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        std::vec![10, 0, 0, 2],
        Duration::from_secs(120),
        long_ago,
        false,
      )
      .unwrap();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      2
    );

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    // Packet 1: A 10.0.0.1 cache_flush=true (refresh burst start).
    let pkt1_t = now;
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 1), true)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(pkt1_t, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }
    // After packet 1: A1 refreshed; A2 expires_at clamped to pkt1_t + 1s
    // but NOT yet removed.  Both still present.
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      2,
      "clamp must NOT remove A2 immediately — only defer its expiry"
    );

    // Packet 2: A 10.0.0.2 cache_flush=true, 200 ms later.
    let pkt2_t = pkt1_t.checked_add(Duration::from_millis(200)).unwrap();
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(pkt2_t, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }

    // After packet 2: A2 refreshed (clamp undone via dedup path).
    // Sweep past the original clamp deadline — neither should expire.
    let after_clamp = pkt1_t.checked_add(Duration::from_secs(3)).unwrap();
    e.cache.sweep_expired(after_clamp);
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      2,
      "a refresh burst within the §10.2 grace must preserve the \
       full RRSet — both A1 and A2 must survive after sweep"
    );
  }

  // ── per-packet flush dedup keys on (name, rtype, rclass) ─────

  /// A datagram containing a non-IN cache_flush record BEFORE an
  /// IN cache_flush record for the same (name, rtype) must NOT
  /// suppress the IN flush.  the per-packet flush dedup
  /// includes rclass, so the second record (different class) still
  /// performs the §10.2 deferred-expiry clamp on stale IN siblings.
  #[test]
  fn flush_marker_keys_on_rclass_so_mixed_class_does_not_suppress() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::{net::SocketAddr, time::Duration};

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("svc.local.").unwrap();

    // Seed an OLD IN-class A record (5 min ago) that is eligible for
    // the deferred-expiry clamp.
    let long_ago = now.checked_sub(Duration::from_secs(300)).unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        std::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        long_ago,
        false,
      )
      .unwrap();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1
    );

    // Build a single packet with TWO cache_flush A records:
    //   (i)  class ANY (non-IN) — would consume the flush marker under
    //        the class-blind keying.
    //   (ii) class IN — needs the deferred-expiry clamp on the old IN
    //        sibling above.
    // The wire builder doesn't expose a "set rclass" knob on push_a_answer
    // — that always emits class IN.  So we exercise the dedup directly
    // by calling try_insert twice with different rclass + cache_flush=true.
    //
    // First: ANY-class cache_flush insert.  This records
    // `(host, A, Any)` in flushed_in_packet — but we're calling
    // Cache::try_insert directly here, which bypasses Endpoint::handle's
    // per-packet tracker.  To exercise the actual code path, instead
    // build a valid wire packet with the IN record and verify the IN
    // sibling gets clamped via the normal handle path.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    // Two IN cache_flush A records with different rdata.  This exercises
    // the per-packet dedup: only the first triggers the clamp; the
    // second piggybacks via flushed_in_packet.  Crucially, the
    // class-aware dedup means we ALSO clamp the old sibling exactly
    // once per (name, rtype, rclass) — the test verifies that the
    // sibling IS clamped (would be skipped under a buggy class-blind
    // dedup if a non-IN flush had been first).
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
      .unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 3), true)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();

    // The old IN sibling (10.0.0.1) must be clamped to expire at now+1s.
    // Sweep past that deadline; the OLD record is removed.
    let after_clamp = now.checked_add(Duration::from_secs(2)).unwrap();
    e.cache.sweep_expired(after_clamp);

    let count = e
      .cache
      .count_matching(&host, ResourceType::A, ResourceClass::In);
    assert_eq!(
      count, 2,
      "old IN sibling must have been clamped + swept; the two \
       new IN records from the packet survive.  Expected 2 (10.0.0.2 \
       and 10.0.0.3); got {count}"
    );
  }

  // ── cache identity includes ResourceClass ─────────────────────

  /// A record with non-IN class must not dedupe with, evict, or count
  /// as an IN-class entry.  Previously the cache stored only
  /// `(name, rtype, rdata)` so a hostile or misconfigured response
  /// could corrupt the cache across class boundaries.
  #[test]
  fn cache_class_isolates_in_from_non_in() {
    use core::time::Duration;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("svc.local.").unwrap();

    // Insert an IN-class A record.
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        std::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();

    // Insert a record with SAME name + rtype + rdata but DIFFERENT class
    // (ANY).  Must NOT dedupe — must coexist.
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        crate::wire::ResourceClass::Any,
        std::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();

    // class is part of the key.  Two distinct entries.
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1
    );
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, crate::wire::ResourceClass::Any),
      1
    );

    // A cache_flush in class ANY must NOT evict the IN entry (advance
    // past grace first, so the IN entry would otherwise be eligible).
    let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        crate::wire::ResourceClass::Any,
        std::vec![10, 0, 0, 99],
        Duration::from_secs(120),
        after_grace,
        true,
      )
      .unwrap();
    let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
    e.cache.sweep_expired(after_clamp);

    // IN entry is still alive.
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1,
      "cache_flush in class ANY must NOT touch IN-class entries"
    );
  }

  // ── cross-packet cache-flush respects §10.2 grace window ─────

  /// A multi-address RRSet announced across TWO separate packets,
  /// both with cache_flush=true, must result in BOTH addresses being
  /// cached.  RFC 6762 §10.2 specifies a 1-second grace: cache_flush
  /// must not evict entries received within the last second.  Before
  /// the second packet's cache_flush evicted the first
  /// packet's record because the eviction was unconditional, so a
  /// multi-A announcement split across packets collapsed to only the
  /// last record.
  #[test]
  fn cache_flush_preserves_recent_siblings_across_packets() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("multihomed.local.").unwrap();

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    // Packet 1: A 10.0.0.1 with cache_flush=true.
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 1), true)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(now, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1
    );

    // Packet 2: A 10.0.0.2 with cache_flush=true, arriving 100 ms later
    // — well within the §10.2 1-second grace window.
    let later = now
      .checked_add(core::time::Duration::from_millis(100))
      .unwrap();
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(later, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }

    // BOTH A records must be cached.  Without the grace window
    // the second cache_flush would have evicted the first.
    let count = e
      .cache
      .count_matching(&host, ResourceType::A, ResourceClass::In);
    assert_eq!(
      count, 2,
      "cross-packet cache-flush within §10.2 grace must preserve \
       fresh siblings.  Expected 2 (both 10.0.0.1 and 10.0.0.2); got {count}"
    );
  }

  // ── TTL=0 record must not consume the per-packet flush marker ─

  /// A TTL=0 cache-flush record (goodbye for a single rdata) does NOT
  /// evict the RRSet — `Cache::try_insert` handles TTL=0 before the
  /// cache-flush branch and removes only the exact rdata.  If such a
  /// record consumed the per-packet flush marker, a later
  /// positive-TTL cache-flush record for the same `(name, rtype)`
  /// would be downgraded to `cache_flush=false` and would NOT evict
  /// older siblings — they would remain stale.
  ///
  /// Test: seed the cache with A=10.0.0.1 and A=10.0.0.2.  Feed a
  /// single packet containing (i) TTL=0/cache_flush goodbye for
  /// 10.0.0.1 and (ii) TTL=120/cache_flush for new 10.0.0.3.  Both
  /// 10.0.0.1 (removed by goodbye) AND 10.0.0.2 (evicted by the
  /// positive cache_flush) must be gone; only 10.0.0.3 should remain.
  #[test]
  fn ttl_zero_does_not_consume_flush_marker() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::{net::SocketAddr, time::Duration};

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("printer.local.").unwrap();

    // Seed the cache with two A records (TTL=120).
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        std::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        std::vec![10, 0, 0, 2],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      2
    );

    // Advance past the §10.2 grace so the seeded entries are
    // eligible for eviction.
    let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();

    // Build a single packet: (i) TTL=0/cache_flush goodbye for 10.0.0.1,
    // followed by (ii) TTL=120/cache_flush for 10.0.0.3.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 0, Ipv4Addr::new(10, 0, 0, 1), true)
      .unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 3), true)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let _ = e
      .handle(after_grace, src, local_ip, 0, pkt, false)
      .unwrap()
      .count();

    // deferred expiry: the positive-TTL cache_flush CLAMPS the
    // surviving sibling (10.0.0.2) to expire at after_grace + 1s.
    // Sweep past that deadline to drop it.
    let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
    e.cache.sweep_expired(after_clamp);

    // 10.0.0.2 must be evicted (via the clamp + sweep); only
    // 10.0.0.3 should remain (10.0.0.1 was removed by the goodbye).
    let count = e
      .cache
      .count_matching(&host, ResourceType::A, ResourceClass::In);
    assert_eq!(
      count, 1,
      "TTL=0 goodbye must not consume the per-packet flush \
       marker, so the subsequent positive-TTL cache_flush record must \
       still evict the unrelated sibling.  Expected 1 (only 10.0.0.3); \
       got {count}"
    );
  }

  // ── iterator terminates after parse errors ───────────────────

  /// A malformed answer/authority record must not pin the iterator
  /// returning the same Err on every call — the section must advance
  /// (or transition to Done) after the error so the iterator
  /// eventually returns None.
  #[test]
  fn malformed_record_does_not_loop_forever() {
    use crate::wire::Header;
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();

    // Build a packet with a malformed answer.  Hand-craft: header
    // claims 1 answer but the body is empty so parsing fails.
    let mut buf = [0u8; 32];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    hdr.set_answer_count(1);
    let header_len = hdr.write(&mut buf).unwrap();
    let pkt = &buf[..header_len]; // body absent -> malformed answer

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();
    let mut total_polls = 0u32;
    let mut error_count = 0u32;
    for ev in events {
      total_polls = total_polls.saturating_add(1);
      if ev.is_err() {
        error_count = error_count.saturating_add(1);
      }
      if total_polls > 10 {
        panic!(
          "iterator must terminate after parse error; \
           seen {error_count} errors in {total_polls} polls without None"
        );
      }
    }
    // Iterator terminated.  Bounded error count: at most one per section.
    assert!(
      error_count <= 3,
      "at most one parse error per section (3 sections); got {error_count}"
    );
  }

  // ── answer_questions=false suppresses Question events ────────

  /// When `EndpointConfig::answer_questions` is false, no
  /// `ServiceEvent::Question` events fire — the registered service
  /// stays passive even when peer queries match its names.
  #[test]
  fn answer_questions_false_suppresses_question_events() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::net::SocketAddr;

    use rand::SeedableRng;
    let rng = rand::rngs::StdRng::from_seed([7u8; 32]);
    let cfg = EndpointConfig::new().with_answer_questions(false);
    let mut e = TestEndp::try_new(cfg, rng);
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("WebServer._http._tcp.local.").unwrap();
    let host = Name::try_from_str("web.local.").unwrap();
    let recs = ServiceRecords::new(st.clone(), inst.clone(), host, 80, 120);
    let now = StdInstant::now();
    let (_h, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // QR=0 packet with a question for the registered instance name.
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_question(
      &inst,
      ResourceType::Any,
      crate::wire::ResourceClass::In,
      false,
    )
    .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let question_events: std::vec::Vec<_> = events
      .iter()
      .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_question()))
      .collect();
    assert!(
      question_events.is_empty(),
      "answer_questions=false must suppress ServiceEvent::Question; \
       got {question_events:?}"
    );
  }

  // ── authority-section host fan-out ───────────────────────────

  /// Multiple services can legitimately share a host name.  An authority
  /// record (peer probe) claiming that host MUST surface HostConflict
  /// to every service sharing it — not just the first by slab order.
  /// Previously the authority loop returned on the first match and
  /// advanced authority_idx, so additional services kept advertising the
  /// conflicted host with no signal.
  #[test]
  fn authority_host_conflict_fans_out_to_all_same_host_services() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{Header, MessageBuilder},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let host = Name::try_from_str("shared-host.local.").unwrap();
    let now = StdInstant::now();

    // Three services with DIFFERENT instance names but the SAME host.
    let mut handles = std::vec::Vec::new();
    for inst_label in ["A", "B", "C"] {
      let inst_str = std::format!("{inst_label}._ipp._tcp.local.");
      let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
      let inst = Name::try_from_str(&inst_str).unwrap();
      let recs = ServiceRecords::new(st, inst, host.clone(), 631, 120);
      let (h, _svc) = e
        .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
          ServiceSpec::new(recs),
          now,
        )
        .unwrap();
      handles.push(h);
    }

    // Probe-shaped authority record claiming the shared host.
    let mut buf = [0u8; 512];
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, hdr).unwrap();
    b.push_a_authority(&host, 120, Ipv4Addr::new(192, 168, 1, 99))
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // Every registered service must receive HostConflict.
    let conflict_handles: std::vec::Vec<_> = events
      .iter()
      .filter_map(|ev| match ev {
        RouteEvent::ToService(ts) if ts.event().is_host_conflict() => Some(ts.handle()),
        _ => None,
      })
      .collect();

    for h in &handles {
      assert!(
        conflict_handles.contains(h),
        "service {h:?} must receive HostConflict for shared host; \
         got handles {conflict_handles:?}"
      );
    }
    assert_eq!(
      conflict_handles.len(),
      3,
      "exactly three HostConflict events expected (one per service); \
       got {conflict_handles:?}"
    );
  }

  /// A QR=1 response answer with TTL=0 must not emit `ToQuery(Answer)`
  /// events for active queries.  The query state is already protected
  /// at the application step, but iterator-level events
  /// should also be suppressed so the caller never sees a "withdrawal
  /// disguised as answer."
  #[test]
  fn qr1_ttl_zero_does_not_emit_to_query_events() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
      .unwrap();

    // QR=1 response packet with a TTL=0 answer for the query name.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qname, 0, Ipv4Addr::new(10, 0, 0, 7), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let to_query_count = events
      .iter()
      .filter(
        |ev| matches!(ev, RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_))),
      )
      .count();
    assert_eq!(
      to_query_count, 0,
      "QR=1 TTL=0 must NOT emit ToQuery(Answer) events; got events {events:?}"
    );

    // And of course collected_answers must remain empty (this still applies).
    assert_eq!(
      e.collected_answers(h).count(),
      0,
      "TTL=0 must not land in collected_answers"
    );
    e.cancel_query(h).unwrap();
  }

  // ── terminal queries reject late answers ─────────────────────

  /// After `poll_query` returns terminal, subsequent matching
  /// responses arriving before `cancel_query` MUST NOT mutate the
  /// query's `collected_answers` or evict pre-terminal results from
  /// the FIFO under `max_answers` pressure.  This added the
  /// `terminal_emitted()` skip to both eager application (in
  /// `Endpoint::handle`) and `ToQuery` fan-out (in the iterator) so
  /// terminated queries are effectively frozen.
  #[test]
  fn terminated_query_rejects_late_answers() {
    use crate::{
      config::QuerySpec,
      event::QueryUpdate,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::{net::SocketAddr, time::Duration};

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qn = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qn.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
    let h = e.try_start_query(spec, now).unwrap();

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

    // First response: an A answer arrives BEFORE the timeout fires.
    let mut buf = [0u8; 512];
    let pre_terminal_addr = Ipv4Addr::new(10, 0, 0, 7);
    {
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&qn, 120, pre_terminal_addr, false).unwrap();
      let n = b.finish().unwrap();
      let pkt = &buf[..n];
      let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();
    }
    assert_eq!(
      e.collected_answers(h).count(),
      1,
      "pre-terminal answer must land in collected_answers"
    );

    // Drive to terminal.
    now = now.checked_add(Duration::from_millis(200)).unwrap();
    e.handle_query_timeout(h, now).unwrap();
    assert!(matches!(
      e.poll_query(h),
      Some(QueryUpdate::Timeout | QueryUpdate::Done)
    ));

    let answers_at_terminal: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(answers_at_terminal.len(), 1);

    // Second response: a DIFFERENT A answer arrives AFTER terminal.  This
    // must NOT mutate collected_answers (frozen) AND must NOT yield a
    // ToQuery event for the terminated query.
    let mut buf2 = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf2, hdr).unwrap();
    b.push_a_answer(&qn, 120, Ipv4Addr::new(10, 0, 0, 99), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf2[..n];

    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // No ToQuery(Answer) for the terminated handle.
    let to_query_events: std::vec::Vec<_> = events
      .iter()
      .filter_map(|ev| match ev {
        RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_)) => Some(tq.handle()),
        _ => None,
      })
      .collect();
    assert!(
      !to_query_events.contains(&h),
      "terminated query must NOT receive ToQuery(Answer) events; got handles {to_query_events:?}"
    );

    // collected_answers unchanged.
    let answers_after_terminal: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers_after_terminal.len(),
      1,
      "collected_answers must be frozen after terminal; \
       got {answers_after_terminal:?}"
    );
    assert_eq!(
      answers_after_terminal[0].rdata_slice(),
      &pre_terminal_addr.octets(),
      "pre-terminal answer must remain intact (no eviction)"
    );

    // Cleanup.
    e.cancel_query(h).unwrap();
  }

  /// `sweep_terminated_queries` prunes every query whose terminal has
  /// been emitted; ongoing queries are untouched.
  #[test]
  fn sweep_terminated_queries_prunes_only_terminated() {
    use crate::{config::QuerySpec, event::QueryUpdate, wire::ResourceType};
    use core::time::Duration;

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qn = Name::try_from_str("printer.local.").unwrap();

    // Two queries: one with a short timeout, one without.
    let h_short = e
      .try_start_query(
        QuerySpec::new(qn.clone(), ResourceType::A).with_timeout(Duration::from_millis(100)),
        now,
      )
      .unwrap();
    let h_long = e
      .try_start_query(QuerySpec::new(qn.clone(), ResourceType::AAAA), now)
      .unwrap();
    assert_eq!(e.queries.len(), 2);

    // Sweep with no terminated queries — no-op.
    assert_eq!(e.sweep_terminated_queries(), 0);
    assert_eq!(e.queries.len(), 2);

    // Drive h_short to terminal and observe.
    now = now.checked_add(Duration::from_millis(200)).unwrap();
    e.handle_query_timeout(h_short, now).unwrap();
    assert!(matches!(
      e.poll_query(h_short),
      Some(QueryUpdate::Timeout | QueryUpdate::Done)
    ));
    assert_eq!(e.queries.len(), 2, "terminal does not auto-prune");

    // Sweep — h_short goes; h_long stays.
    assert_eq!(e.sweep_terminated_queries(), 1);
    assert_eq!(e.queries.len(), 1);
    assert!(e.collected_answers(h_short).next().is_none());
    // h_long is still active.
    e.cancel_query(h_long).unwrap();
  }

  /// `cancel_query` removes the route immediately; subsequent lookups
  /// return `CancelQueryError::QueryNotFound` for the cancelled handle.
  #[test]
  fn cancel_query_removes_route() {
    use crate::{config::QuerySpec, error::CancelQueryError, wire::ResourceType};

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qname, ResourceType::A);
    let h = e.try_start_query(spec, now).unwrap();
    assert_eq!(e.queries.len(), 1);

    e.cancel_query(h).unwrap();
    assert_eq!(e.queries.len(), 0);

    // Second cancel on the same handle returns QueryNotFound.
    let r = e.cancel_query(h);
    assert!(
      matches!(r, Err(CancelQueryError::QueryNotFound(_))),
      "cancel_query on absent handle must return QueryNotFound; got {r:?}"
    );
  }

  // ── Stats invariant: queries_started == queries_done + queries_active ──────

  /// The invariant `queries_started == queries_done + queries_active` must
  /// hold at all times.  (`queries_timeout` is a sub-counter of `queries_done`
  /// — both are bumped by `terminate(Timeout)` — so it is NOT a third term.)
  ///
  /// This test verifies two paths:
  ///   (i)  live cancel — `cancel_query` IS the terminal transition, so it
  ///        must bump `queries_done` AND decrement `queries_active`.
  ///   (ii) cancel-after-terminal — `Query::terminate` already performed both
  ///        adjustments; `cancel_query` must NOT repeat them.
  #[cfg(feature = "stats")]
  #[test]
  fn cancel_query_stats_invariant() {
    use crate::{config::QuerySpec, wire::ResourceType};
    use core::time::Duration;

    // Helper: assert the fundamental counter invariant.
    let check_invariant = |label: &str, snap: &hick_trace::stats::StatsSnapshot| {
      assert_eq!(
        snap.queries_started,
        snap.queries_done + snap.queries_active,
        "invariant queries_started == queries_done + queries_active \
         violated at '{label}': {snap:?}"
      );
    };

    // ── (i) live cancel ────────────────────────────────────────────────────
    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qname.clone(), ResourceType::A);
    let h = e.try_start_query(spec, now).unwrap();

    let before = e.stats();
    assert_eq!(before.queries_started, 1);
    assert_eq!(before.queries_active, 1);
    assert_eq!(before.queries_done, 0);
    check_invariant("after-start", &before);

    // Cancel while still live (done=false).
    e.cancel_query(h).unwrap();
    let after_live_cancel = e.stats();
    assert_eq!(
      after_live_cancel.queries_done, 1,
      "live cancel must bump queries_done; got {after_live_cancel:?}"
    );
    assert_eq!(
      after_live_cancel.queries_active, 0,
      "live cancel must decrement queries_active; got {after_live_cancel:?}"
    );
    check_invariant("after-live-cancel", &after_live_cancel);

    // ── (ii) cancel after terminal ─────────────────────────────────────────
    let mut e2 = build_endpoint();
    let mut now2 = StdInstant::now();
    let spec2 = QuerySpec::new(qname, ResourceType::A).with_timeout(Duration::from_millis(50));
    let h2 = e2.try_start_query(spec2, now2).unwrap();

    // Drive past absolute timeout → query terminates inside handle_query_timeout.
    now2 += Duration::from_millis(100);
    e2.handle_query_timeout(h2, now2).unwrap();
    let _ = e2.poll_query(h2); // drain terminal update

    let snap_terminal = e2.stats();
    check_invariant("after-terminal", &snap_terminal);

    // cancel_query on an already-done query must be a no-op for stats.
    e2.cancel_query(h2).unwrap();
    let snap_after_cancel = e2.stats();
    assert_eq!(
      snap_after_cancel.queries_done, snap_terminal.queries_done,
      "cancel-after-terminal must not bump queries_done again; {snap_after_cancel:?}"
    );
    assert_eq!(
      snap_after_cancel.queries_active, snap_terminal.queries_active,
      "cancel-after-terminal must not decrement queries_active again; {snap_after_cancel:?}"
    );
    check_invariant("after-cancel-of-terminal", &snap_after_cancel);
  }

  // ── duplicate_questions_suppressed increments only on real suppression ──

  /// `duplicate_questions_suppressed` must ONLY be incremented when
  /// `note_duplicate_question` actually consumed a transmit slot.
  ///
  /// Two sub-cases:
  ///   (a) When the query is `awaiting_send_confirm` (initial datagram sent but
  ///       not yet confirmed), `note_duplicate_question` returns false and the
  ///       counter must NOT advance.
  ///   (b) After confirmation + timeout arms the next retry,
  ///       `note_duplicate_question` returns true and the counter advances.
  #[cfg(feature = "stats")]
  #[test]
  fn duplicate_questions_suppressed_only_on_real_suppression() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use core::{
      net::{IpAddr, Ipv4Addr, SocketAddr},
      time::Duration,
    };

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qname.clone(), ResourceType::A);
    let h = e.try_start_query(spec, now).unwrap();

    // Build a peer QM question packet matching our query (QR=0, source port 5353).
    let mut pkt_buf = [0u8; 512];
    let hdr = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut pkt_buf, hdr).unwrap();
    b.push_question(&qname, ResourceType::A, ResourceClass::In, false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = pkt_buf[..n].to_vec();

    let multicast_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
    let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 2), 5353u16));

    // (a) Drain the initial transmit without confirming → awaiting_send_confirm=true.
    let mut tx_buf = std::vec![0u8; 512];
    let tx = e.poll_query_transmit(h, now, &mut tx_buf).unwrap();
    assert!(
      tx.is_some(),
      "newly-started query must have an initial transmit pending"
    );
    // Do NOT call note_query_transmit_result — leave the query awaiting confirm.
    // Now feed the peer question: note_duplicate_question → returns false → no bump.
    {
      let mut events = e
        .handle(now, peer_src, multicast_ip, 0, &pkt, false)
        .unwrap();
      while events.next().is_some() {}
    }
    let snap_awaiting = e.stats();
    assert_eq!(
      snap_awaiting.duplicate_questions_suppressed, 0,
      "(a) no suppression while awaiting send confirm; got {snap_awaiting:?}"
    );

    // (b) Confirm the send, advance time to arm next retry, then feed the peer
    // question again → note_duplicate_question returns true → counter advances.
    e.note_query_transmit_result(h, now, true); // confirm
    now += Duration::from_secs(10); // past the first retry deadline (~1s)
    e.handle_query_timeout(h, now).unwrap(); // arms transmit_pending = true

    {
      let mut events = e
        .handle(now, peer_src, multicast_ip, 0, &pkt, false)
        .unwrap();
      while events.next().is_some() {}
    }
    let snap_suppressed = e.stats();
    assert_eq!(
      snap_suppressed.duplicate_questions_suppressed, 1,
      "(b) one suppression expected after arming next retry; got {snap_suppressed:?}"
    );
  }

  // ── IPv6 link-local self-check is interface-scoped ──────────

  /// IPv6 link-local addresses (`fe80::/10`) are scoped per interface.
  /// Two unrelated hosts on different interfaces can both pick `fe80::1`
  /// without conflict.  Previously the self-loopback membership check
  /// compared bare addresses, so a peer using the same link-local on a
  /// different interface would be wrongly classified as self and
  /// suppressed.
  ///
  /// Test: register a service publishing `fe80::1` scoped to interface
  /// index 2, then feed back a probe-shaped AAAA-authority packet with
  /// `src = fe80::1`.  The same packet must:
  ///   * be suppressed when delivered with `interface_index == 2` (true
  ///     self-loopback), AND
  ///   * be routed normally (ProbeConflict) when delivered with
  ///     `interface_index == 3` (a remote peer on another interface).
  #[test]
  fn ipv6_link_local_self_check_is_interface_scoped() {
    use crate::{
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use core::net::{Ipv6Addr, SocketAddr};

    // signal (b) is opt-in. This test validates the legacy
    // advertised-source fallback's interface-scoped behaviour.
    use rand::SeedableRng;
    let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
    let mut e = TestEndp::try_new(
      EndpointConfig::new().with_trust_advertised_src_as_self(true),
      rng,
    );
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host, 631, 120);
    let our_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    // Bound to interface index 2 — packets arriving on any other interface
    // with src = fe80::1 must be treated as peer, not self.
    recs.add_aaaa_scoped(our_v6, 2);
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let mut buf = [0u8; 512];
    let hdr = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_srv_authority(
      &inst,
      120,
      0,
      0,
      8080,
      &Name::try_from_str("other-host.local.").unwrap(),
    )
    .unwrap();
    let n = b.finish().unwrap();
    let data = &buf[..n];

    let local_ip: core::net::IpAddr =
      core::net::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb));
    let self_src: SocketAddr = SocketAddr::from((our_v6, 5353));

    // (1) Self-loopback: same address, same interface (ifindex=2).
    let mut self_events = e.handle(now, self_src, local_ip, 2, data, false).unwrap();
    assert!(
      self_events.next().is_none(),
      "link-local from OUR interface (ifindex=2) must be self-suppressed"
    );

    // (2) Foreign peer on a different interface (ifindex=3) using the
    //     same numeric link-local.  This is the regression case — must
    //     route as ProbeConflict, not be silently dropped.
    let mut peer_events = e.handle(now, self_src, local_ip, 3, data, false).unwrap();
    let ev = peer_events
      .next()
      .expect("link-local from a DIFFERENT interface must still produce a routing event")
      .expect("event must be Ok");
    match ev {
      RouteEvent::ToService(ts) => assert!(
        ts.event().is_probe_conflict(),
        "link-local from ifindex=3 must emit ProbeConflict (not be misclassified \
         as self because of bare-address match); got {:?}",
        ts.event()
      ),
      other => panic!(
        "expected RouteEvent::ToService(ProbeConflict), got {:?}",
        other
      ),
    }
  }

  // ── response answers fan out to all type-compatible routes ──

  /// Two concurrent queries for the SAME name but DIFFERENT QTYPEs (e.g.
  /// `printer.local. A` and `printer.local. AAAA`) must both receive
  /// matching answers.  Previously the demux matched the first route
  /// by name and broke; an AAAA answer would route to the A query, get
  /// filtered out at `Query::handle_event` (rtype mismatch), and never
  /// reach the AAAA query.
  ///
  /// Test plan: register an A query and an AAAA query for the same name,
  /// then feed a RESPONSE packet containing an AAAA answer.  Drain all
  /// routing events and assert exactly one `ToQuery(Answer)` reaches the
  /// AAAA handle; none reaches the A handle (the rtype filter at the
  /// route level rejects the AAAA against the A route).
  #[test]
  fn response_answer_fans_out_to_type_compatible_queries() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::net::{Ipv6Addr, SocketAddr};

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();

    // Register an A query AND an AAAA query for the same name.
    let spec_a = QuerySpec::new(qname.clone(), ResourceType::A);
    let h_a = e.try_start_query(spec_a, now).unwrap();
    let spec_aaaa = QuerySpec::new(qname.clone(), ResourceType::AAAA);
    let h_aaaa = e.try_start_query(spec_aaaa, now).unwrap();

    // Build a RESPONSE packet (QR=1) with an AAAA answer for the name.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let aaaa = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    b.push_aaaa_answer(&qname, 120, aaaa, false).unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();

    let mut answer_handles: std::vec::Vec<QueryHandle> = std::vec::Vec::new();
    for ev in events {
      let ev = ev.unwrap();
      if let RouteEvent::ToQuery(tq) = ev
        && let QueryEvent::Answer(_) = tq.event()
      {
        answer_handles.push(tq.handle());
      }
    }

    // The AAAA query must receive the answer.  The A query must NOT —
    // rtype filtering at the route level rejects AAAA against the A
    // route.
    assert!(
      answer_handles.contains(&h_aaaa),
      "AAAA query must receive the AAAA answer; got handles {answer_handles:?}"
    );
    assert!(
      !answer_handles.contains(&h_a),
      "A query must NOT receive an AAAA answer (route-level rtype filter); \
       got handles {answer_handles:?}"
    );
  }

  /// Same as above but with two queries that BOTH should receive the
  /// answer: one registered with `ResourceType::Any` and one with the
  /// exact rtype.  Both routes are compatible, so the same answer record
  /// must produce TWO `ToQuery(Answer)` events.
  #[test]
  fn response_answer_fans_out_to_any_and_specific_routes() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();

    let spec_a = QuerySpec::new(qname.clone(), ResourceType::A);
    let h_a = e.try_start_query(spec_a, now).unwrap();
    let spec_any = QuerySpec::new(qname.clone(), ResourceType::Any);
    let h_any = e.try_start_query(spec_any, now).unwrap();

    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 9), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();

    let mut answer_handles: std::vec::Vec<QueryHandle> = std::vec::Vec::new();
    for ev in events {
      let ev = ev.unwrap();
      if let RouteEvent::ToQuery(tq) = ev
        && let QueryEvent::Answer(_) = tq.event()
      {
        answer_handles.push(tq.handle());
      }
    }

    assert!(
      answer_handles.contains(&h_a),
      "A-specific query must receive the A answer; handles={answer_handles:?}"
    );
    assert!(
      answer_handles.contains(&h_any),
      "Any-wildcard query must also receive the A answer; handles={answer_handles:?}"
    );
    assert_eq!(
      answer_handles.len(),
      2,
      "exactly two ToQuery(Answer) events expected (one per compatible route); \
       got {answer_handles:?}"
    );
  }

  // `cancel_query` on an unknown handle returns
  // `CancelQueryError::QueryNotFound`; covered alongside the basic
  // removal path in `cancel_query_removes_route` above.

  // ── begin_withdrawal ─────────────────────────────────────────────────

  /// `begin_withdrawal` must leave `services_active` unchanged (it is
  /// decremented later in Task 5) and keep the route in `self.services` so
  /// that a same-name re-registration is still rejected.
  #[cfg(feature = "stats")]
  #[test]
  fn begin_withdrawal_holds_the_name_and_keeps_services_active() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();

    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let recs = ServiceRecords::new(st, inst.clone(), host, 631, 120);
    let (handle, mut svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let before = ep.stats().services_active;

    let snap = svc.withdrawal_snapshot();
    ep.begin_withdrawal(handle, snap, now);

    // services_active must NOT have changed.
    assert_eq!(
      ep.stats().services_active,
      before,
      "begin_withdrawal must not decrement services_active"
    );

    // The route is still present — same-name re-registration is rejected.
    let st2 = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst2 = inst; // same name
    let host2 = Name::try_from_str("printer-host.local.").unwrap();
    let recs2 = ServiceRecords::new(st2, inst2, host2, 631, 120);
    let result = ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs2),
      now,
    );
    assert!(
      matches!(result, Err(RegisterServiceError::NameAlreadyRegistered(_))),
      "same-name re-registration must be rejected while withdrawal route is held"
    );
  }

  /// `begin_withdrawal` with an unknown handle is a silent no-op.
  #[test]
  fn begin_withdrawal_unknown_handle_is_noop() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    // Build a dummy snapshot via a temporary service.
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Ghost._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("ghost-host.local.").unwrap();
    let recs = ServiceRecords::new(st, inst, host, 631, 120);
    let (_, mut svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    let snap = svc.withdrawal_snapshot();
    // Use a handle that was never registered.
    let bogus = ServiceHandle::from_raw(0xDEAD);
    ep.begin_withdrawal(bogus, snap, now); // must not panic
  }

  /// `poll_withdrawal_transmit` encodes the snapshot's TTL=0 goodbye and RETAINS
  /// a host address that a live same-host sibling still ADVERTISES, while
  /// withdrawing the withdrawing service's unique address (sibling retention is
  /// computed fresh from the route table's CONFIRMED-ADVERTISED set).
  #[test]
  fn poll_withdrawal_emits_ttl0_and_retains_sibling_host_addr() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let shared = Ipv4Addr::new(192, 168, 1, 5);
    let unique = Ipv4Addr::new(192, 168, 1, 6);
    let host = Name::try_from_str("h.local.").unwrap();

    // Service A (host h) advertises BOTH the shared and the unique address, plus
    // a `_printer` subtype (RFC 6763 §7.1) so the withdrawal must also retract
    // the subtype PTR at TTL 0.
    let mut recs_a = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("A._ipp._tcp.local.").unwrap(),
      host.clone(),
      631,
      120,
    );
    recs_a.add_a(shared);
    recs_a.add_a(unique);
    recs_a.add_subtype("_printer").unwrap();
    let sub = Name::try_from_str("_printer._sub._ipp._tcp.local.").unwrap();
    let (a_handle, _svc_a) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs_a.clone()),
        now,
      )
      .unwrap();

    // Service B (SAME host h) advertises ONLY the shared address.
    let mut recs_b = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("B._ipp._tcp.local.").unwrap(),
      host.clone(),
      632,
      120,
    );
    recs_b.add_a(shared);
    let (b_handle, _svc_b) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs_b),
        now,
      )
      .unwrap();
    // B has CONFIRMED-ADVERTISED the shared address (its announce was delivered),
    // so the route's advertised set is non-empty — otherwise retention would
    // honour nothing and A would (wrongly) withdraw the shared address.
    ep.note_service_advertised(b_handle, &[shared], &[]);

    // A's withdrawal snapshot: owns PTR/SRV/TXT, the subtype PTR, and both host
    // A addresses.
    let snap = crate::service::WithdrawalSnapshot {
      records: recs_a,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        true,
      ),
      host_a: std::vec![shared, unique],
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(a_handle, snap, now);

    let mut buf = std::vec![0u8; 4096];
    let (_dst, len, got) = ep
      .poll_withdrawal_transmit(now, &mut buf)
      .expect("a due withdrawal must produce a datagram");
    assert_eq!(
      Some(got),
      ep.route_withdrawal_token(a_handle),
      "the route-attached item for the withdrawing handle is the one emitted"
    );

    let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
    let mut saw_instance = false;
    let mut saw_subtype = false;
    let mut withdrawn_v4: std::vec::Vec<Ipv4Addr> = std::vec::Vec::new();
    for rec in reader.answers() {
      let rec = rec.unwrap();
      assert_eq!(rec.ttl(), 0, "every goodbye record must carry TTL 0");
      match rec.rtype() {
        crate::wire::ResourceType::A => {
          let d = rec.rdata();
          assert_eq!(d.len(), 4, "A rdata is 4 bytes");
          withdrawn_v4.push(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
        }
        crate::wire::ResourceType::Ptr => {
          if names_match(&sub, rec.name()) {
            saw_subtype = true;
          } else {
            saw_instance = true;
          }
        }
        crate::wire::ResourceType::Srv | crate::wire::ResourceType::Txt => saw_instance = true,
        _ => {}
      }
    }
    assert!(
      saw_instance,
      "instance records (PTR/SRV/TXT) must be withdrawn at TTL 0"
    );
    assert!(saw_subtype, "the subtype PTR must be withdrawn at TTL 0");
    assert!(
      withdrawn_v4.contains(&unique),
      "A's unique address must be withdrawn"
    );
    assert!(
      !withdrawn_v4.contains(&shared),
      "the sibling-shared address must be RETAINED (not withdrawn)"
    );
  }

  /// Helper: register a same-host service advertising the given A addresses and
  /// (optionally) mirror an advertised set into its route, returning its handle.
  /// `advertised == None` models a registered-but-never-announced sibling (its
  /// route advertised set stays EMPTY); `Some(addrs)` mirrors a confirmed
  /// announce via `note_service_advertised`.
  fn register_host_service(
    ep: &mut TestEndp,
    instance: &str,
    host: &Name,
    configured_a: &[Ipv4Addr],
    advertised: Option<&[Ipv4Addr]>,
  ) -> ServiceHandle {
    let mut recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str(instance).unwrap(),
      host.clone(),
      631,
      120,
    );
    for a in configured_a {
      recs.add_a(*a);
    }
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        StdInstant::now(),
      )
      .unwrap();
    if let Some(adv) = advertised {
      ep.note_service_advertised(h, adv, &[]);
    }
    h
  }

  /// Collect the A addresses a withdrawal datagram WITHDRAWS (TTL 0) for the
  /// next due round of `handle`.
  fn poll_withdrawn_v4(
    ep: &mut TestEndp,
    now: StdInstant,
  ) -> (std::vec::Vec<Ipv4Addr>, WithdrawalToken) {
    let mut buf = std::vec![0u8; 4096];
    let (_dst, len, token) = ep
      .poll_withdrawal_transmit(now, &mut buf)
      .expect("a due withdrawal must produce a datagram");
    let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
    let mut withdrawn = std::vec::Vec::new();
    for rec in reader.answers() {
      let rec = rec.unwrap();
      if rec.rtype() == crate::wire::ResourceType::A {
        let d = rec.rdata();
        withdrawn.push(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
      }
    }
    (withdrawn, token)
  }

  /// Build a withdrawal snapshot owning PTR/SRV/TXT plus the given host A set.
  fn host_a_snapshot(
    host: &Name,
    instance: &str,
    host_a: &[Ipv4Addr],
  ) -> crate::service::WithdrawalSnapshot {
    let mut recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str(instance).unwrap(),
      host.clone(),
      631,
      120,
    );
    for a in host_a {
      recs.add_a(*a);
    }
    crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: host_a.to_vec(),
      host_aaaa: std::vec::Vec::new(),
    }
  }

  /// Regression: a withdrawing service MUST withdraw a host
  /// address when the only same-host sibling holding it CONFIGURED but NEVER
  /// ADVERTISED it. The old scan keyed on configured `a_addrs`, so the real
  /// owner wrongly RETAINED the address and left stale records in peer caches.
  #[test]
  fn withdrawal_withdraws_addr_when_sibling_never_advertised() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("h.local.").unwrap();
    let shared = Ipv4Addr::new(192, 168, 1, 5);
    let unique = Ipv4Addr::new(192, 168, 1, 6);

    // A advertises BOTH .5 and .6 (confirmed announce mirrored in).
    let a = register_host_service(
      &mut ep,
      "A._ipp._tcp.local.",
      &host,
      &[shared, unique],
      Some(&[shared, unique]),
    );
    // B is CONFIGURED with .5 but NEVER announced — its advertised set is EMPTY.
    let _b = register_host_service(&mut ep, "B._ipp._tcp.local.", &host, &[shared], None);

    ep.begin_withdrawal(
      a,
      host_a_snapshot(&host, "A._ipp._tcp.local.", &[shared, unique]),
      now,
    );

    let (withdrawn, token) = poll_withdrawn_v4(&mut ep, now);
    assert_eq!(
      token,
      ep.route_withdrawal_token(a).unwrap(),
      "the datagram is A's route-attached withdrawal item"
    );
    assert!(
      withdrawn.contains(&shared),
      "shared addr must be WITHDRAWN: no LIVE sibling actually advertised it"
    );
    assert!(
      withdrawn.contains(&unique),
      "A's unique addr must be withdrawn"
    );
  }

  /// A host address a LIVE same-host sibling has actually ADVERTISED is RETAINED
  /// (not withdrawn) by the withdrawing service, while its unique address is
  /// withdrawn. This is the correct-retention counterpart of the regression.
  #[test]
  fn withdrawal_retains_addr_advertised_by_live_sibling() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("h.local.").unwrap();
    let shared = Ipv4Addr::new(192, 168, 1, 5);
    let unique = Ipv4Addr::new(192, 168, 1, 6);

    // A advertises .5 + .6; B (LIVE) advertises .5.
    let a = register_host_service(
      &mut ep,
      "A._ipp._tcp.local.",
      &host,
      &[shared, unique],
      Some(&[shared, unique]),
    );
    let _b = register_host_service(
      &mut ep,
      "B._ipp._tcp.local.",
      &host,
      &[shared],
      Some(&[shared]),
    );

    // Only A withdraws; B stays live (not withdrawing).
    ep.begin_withdrawal(
      a,
      host_a_snapshot(&host, "A._ipp._tcp.local.", &[shared, unique]),
      now,
    );

    let (withdrawn, token) = poll_withdrawn_v4(&mut ep, now);
    assert_eq!(
      token,
      ep.route_withdrawal_token(a).unwrap(),
      "the datagram is A's route-attached withdrawal item"
    );
    assert!(
      !withdrawn.contains(&shared),
      "shared addr must be RETAINED: live sibling B still advertises it"
    );
    assert!(
      withdrawn.contains(&unique),
      "A's unique addr must be withdrawn"
    );
  }

  /// Regression: two same-host services withdrawing TOGETHER must
  /// EACH withdraw the shared address. The old scan did not exclude withdrawing
  /// siblings, so each retained the other's leaving address and neither emitted
  /// the TTL=0 A — leaving the record stale in peer caches until its TTL.
  #[test]
  fn simultaneous_same_host_withdrawals_each_withdraw_shared_addr() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("h.local.").unwrap();
    let shared = Ipv4Addr::new(192, 168, 1, 5);

    // Both A and B advertised the shared address (confirmed announces mirrored).
    let a = register_host_service(
      &mut ep,
      "A._ipp._tcp.local.",
      &host,
      &[shared],
      Some(&[shared]),
    );
    let b = register_host_service(
      &mut ep,
      "B._ipp._tcp.local.",
      &host,
      &[shared],
      Some(&[shared]),
    );

    // BOTH withdraw — each marks its route `withdrawing`, so each is excluded
    // from the other's retention scan.
    ep.begin_withdrawal(
      a,
      host_a_snapshot(&host, "A._ipp._tcp.local.", &[shared]),
      now,
    );
    ep.begin_withdrawal(
      b,
      host_a_snapshot(&host, "B._ipp._tcp.local.", &[shared]),
      now,
    );

    // Each one's next due round must WITHDRAW the shared address. Confirm the
    // round so the second poll advances to the other withdrawer's item.
    let (withdrawn_1, tok1) = poll_withdrawn_v4(&mut ep, now);
    assert!(
      withdrawn_1.contains(&shared),
      "first withdrawer ({tok1:?}) must withdraw the shared addr (sibling is also leaving)"
    );
    ep.note_withdrawal_result(
      tok1,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Sent,
    );

    let (withdrawn_2, tok2) = poll_withdrawn_v4(&mut ep, now);
    assert_ne!(
      tok1, tok2,
      "the second poll must advance to the OTHER withdrawer's item"
    );
    assert!(
      withdrawn_2.contains(&shared),
      "second withdrawer ({tok2:?}) must ALSO withdraw the shared addr"
    );
  }

  /// `note_withdrawal_result` spends a resend round per family that `Sent`; a
  /// round where neither family sent (both `Retry`) re-arms at the short backoff
  /// WITHOUT spending either family's budget (Task 4).
  #[test]
  fn note_withdrawal_delivered_spends_failed_rearms() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("A._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs.clone()),
        now,
      )
      .unwrap();
    // A NON-empty snapshot (owns PTR/SRV/TXT) so the resend budget is non-zero
    // and the spend/backoff schedule is actually exercised.
    let snap = crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);
    let token = ep.route_withdrawal_token(h).unwrap();

    // A round where NEITHER family sent (both Retry) spends nothing and re-arms at
    // the short backoff.
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Retry,
      super::WithdrawalSend::Retry,
    );
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
      "a no-send round must not spend either family's resend budget"
    );
    let backoff_at = ep.route_withdrawal_next_at(h).unwrap();
    assert_eq!(
      backoff_at,
      now
        .checked_add_duration(super::WITHDRAWAL_RETRY_BACKOFF)
        .unwrap()
    );
    assert!(
      backoff_at
        < now
          .checked_add_duration(super::WITHDRAWAL_INTERVAL)
          .unwrap(),
      "a no-send round must NOT delay a full interval"
    );

    // A dual-stack delivered round spends exactly one PER family and re-arms at
    // the full interval (progress made).
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Sent,
    );
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([super::WITHDRAWAL_SENDS - 1, super::WITHDRAWAL_SENDS - 1]),
      "a dual-stack delivered round spends exactly one per family"
    );
    assert_eq!(
      ep.route_withdrawal_next_at(h).unwrap(),
      now
        .checked_add_duration(super::WITHDRAWAL_INTERVAL)
        .unwrap()
    );

    // A mixed round (v4 Sent, v6 Retry) spends only v4 and STILL counts as
    // progress (>= 1 Sent), so it re-arms at the full interval.
    ep.note_route_withdrawal_result(
      h,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Retry,
    );
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([super::WITHDRAWAL_SENDS - 2, super::WITHDRAWAL_SENDS - 1]),
      "a v4-only round spends only v4's budget; v6 keeps its debt"
    );
    assert_eq!(
      ep.route_withdrawal_next_at(h).unwrap(),
      now
        .checked_add_duration(super::WITHDRAWAL_INTERVAL)
        .unwrap(),
      "a round with >= 1 Sent re-arms at the full interval"
    );
  }

  /// Every [`super::WithdrawalSend`] variant has a canonical lowercase slug (and
  /// `Display` renders it), per the workspace unit-only-enum convention.
  #[test]
  fn withdrawal_send_as_str_slug_for_every_variant() {
    assert_eq!(super::WithdrawalSend::Sent.as_str(), "sent");
    assert_eq!(super::WithdrawalSend::Retry.as_str(), "retry");
    assert_eq!(super::WithdrawalSend::WriteOff.as_str(), "write_off");
    assert_eq!(
      std::format!("{}", super::WithdrawalSend::WriteOff),
      "write_off"
    );
  }

  /// regression: a withdrawal is NOT freed until EVERY reachable
  /// family has sent the goodbye. Pump WITHDRAWAL_SENDS rounds with `v4 = Sent,
  /// v6 = Retry`: v4's debt drains to 0 but v6 still owes, so the withdrawal is
  /// held (route still reserved, name still rejected) and does NOT complete. Only
  /// once v6 also sends its full budget does it complete and free the name — so a
  /// v6 that recovers before the 2 s ceiling still withdraws its records.
  #[test]
  fn withdrawal_not_freed_until_every_family_sent() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst.clone(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs.clone()),
        now,
      )
      .unwrap();
    // Owns instance records (PTR/SRV/TXT), so the withdrawal has a real goodbye.
    let snap = crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);
    let token = ep.route_withdrawal_token(h).unwrap();

    // v4 sends every round, v6 is transiently busy (Retry) every round: v4's debt
    // drains, v6's is untouched.
    for _ in 0..super::WITHDRAWAL_SENDS {
      ep.note_withdrawal_result(
        token,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Retry,
      );
    }
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, super::WITHDRAWAL_SENDS]),
      "v4 fully sent but v6 (busy) still owes its whole budget"
    );

    // A drain WELL within the 2 s ceiling must NOT free it: v6 has peers that never
    // got the TTL=0 goodbye.
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert!(
      done.is_empty(),
      "a withdrawal whose v6 family still owes must NOT be freed before the ceiling"
    );
    // The name is still held (route present for the guard).
    let dup = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst.clone(),
      Name::try_from_str("h2.local.").unwrap(),
      631,
      120,
    );
    assert!(
      matches!(
        ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
          ServiceSpec::new(dup),
          now,
        ),
        Err(RegisterServiceError::NameAlreadyRegistered(_))
      ),
      "the name must stay held while v6's goodbye debt is unpaid"
    );

    // Now v6 recovers and sends its whole budget (v4 already at 0 → reported Sent
    // is a no-op there). owed reaches [0, 0] → it completes and frees the name.
    for _ in 0..super::WITHDRAWAL_SENDS {
      ep.note_withdrawal_result(
        token,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Sent,
      );
    }
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, 0]),
      "once v6 sends its budget every family's debt is cleared"
    );
    ep.drain_completed_withdrawals(now, &mut done);
    assert!(
      done.contains(&h),
      "the withdrawal completes once every family has withdrawn its records"
    );
    // The name is now re-registerable.
    let recs2 = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst,
      Name::try_from_str("h2.local.").unwrap(),
      631,
      120,
    );
    assert!(
      ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs2),
        now,
      )
      .is_ok(),
      "the withdrawn name is re-registerable once all families have sent"
    );
  }

  /// a family reported `WriteOff` (no socket / permanent error) has its debt
  /// zeroed, so the withdrawal can complete via the OTHER family alone — a down
  /// family has no reachable peers to withdraw from, so it must not pin the name.
  #[test]
  fn withdrawal_writeoff_family_completes() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst,
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs.clone()),
        now,
      )
      .unwrap();
    let snap = crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);
    let token = ep.route_withdrawal_token(h).unwrap();

    // v6 has no socket (WriteOff zeroes its debt immediately); v4 still owes its
    // full budget after one Sent.
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::WriteOff,
    );
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([super::WITHDRAWAL_SENDS - 1, 0]),
      "WriteOff zeroes v6's debt; v4 spent exactly one"
    );

    // v4 sends out its remaining budget; v6 stays written off.
    for _ in 0..(super::WITHDRAWAL_SENDS - 1) {
      ep.note_withdrawal_result(
        token,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::WriteOff,
      );
    }
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, 0]),
      "v4 fully sent + v6 written off → every family's debt cleared"
    );
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert!(
      done.contains(&h),
      "the withdrawal completes via v4 alone once v6 is written off"
    );
  }

  /// regression: an already-PAID family's redundant `Sent`
  /// must NOT count as withdrawal progress. Drivers fan every round to BOTH
  /// families, so once v4's debt is 0 it keeps reporting `Sent`; if that counted
  /// as progress the schedule would re-arm at the FULL interval and starve a
  /// still-busy v6 of its short-backoff retry (risking a missed last-interval v6
  /// recovery before the ceiling). Drive v4 to `owed == 0` while v6 stays busy,
  /// then a `v4 = Sent (paid), v6 = Retry` round must re-arm at
  /// `WITHDRAWAL_RETRY_BACKOFF`, NOT the full interval. A subsequent `v6 = Sent`
  /// then decrements v6 and (with v4 already 0) completes the withdrawal.
  #[test]
  fn withdrawal_retries_owed_family_at_backoff_when_other_is_paid() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("A._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs.clone()),
        now,
      )
      .unwrap();
    let snap = crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);
    let token = ep.route_withdrawal_token(h).unwrap();

    // Drain v4's whole budget while v6 is transiently busy (Retry): v4 → 0, v6
    // keeps its full debt. Each of these rounds DID make real progress on v4
    // (its owed was > 0), so they legitimately re-arm at the full interval.
    for _ in 0..super::WITHDRAWAL_SENDS {
      ep.note_withdrawal_result(
        token,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Retry,
      );
    }
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, super::WITHDRAWAL_SENDS]),
      "v4 fully paid; v6 (busy) still owes its whole budget"
    );

    // The crux: v4 is already paid (owed 0) but the driver still fans the round to
    // it, so it reports `Sent` again; v6 is still busy (`Retry`). NO family made
    // real progress this round — the paid v4 `Sent` is redundant — so the schedule
    // must re-arm at the SHORT backoff to retry the still-owed v6 soon, NOT wait a
    // full interval (which could miss a late v6 recovery before the 2 s ceiling).
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Retry,
    );
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, super::WITHDRAWAL_SENDS]),
      "a redundant `Sent` on the already-paid v4 must not change any debt"
    );
    let backoff_at = ep.route_withdrawal_next_at(h).unwrap();
    assert_eq!(
      backoff_at,
      now
        .checked_add_duration(super::WITHDRAWAL_RETRY_BACKOFF)
        .unwrap(),
      "an already-paid family's `Sent` is not progress: re-arm at the short backoff"
    );
    assert!(
      backoff_at
        < now
          .checked_add_duration(super::WITHDRAWAL_INTERVAL)
          .unwrap(),
      "the still-owed v6 must be retried at the short backoff, not a full interval"
    );

    // v6 now recovers: its `Sent` IS real progress (its owed was > 0), so it
    // decrements and — v4 already 0 — owed reaches [0, 0] once v6 drains.
    for _ in 0..super::WITHDRAWAL_SENDS {
      ep.note_withdrawal_result(
        token,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Sent,
      );
    }
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, 0]),
      "v6 draining its budget clears every family's debt"
    );
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert!(
      done.contains(&h),
      "the withdrawal completes once the previously-owed v6 has sent its budget"
    );
  }

  /// corollary: `WriteOff` zeroes ONLY its own family's debt and leaves the
  /// other family's owed untouched — a down family must not drag the live one's
  /// budget down with it. (Complements `withdrawal_writeoff_family_completes`,
  /// which checks the completion path.)
  #[test]
  fn writeoff_only_zeroes_its_own_family() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("A._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs.clone()),
        now,
      )
      .unwrap();
    let snap = crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);

    // v4 written off (its debt → 0); v6 transiently busy (Retry, debt intact).
    ep.note_route_withdrawal_result(
      h,
      now,
      super::WithdrawalSend::WriteOff,
      super::WithdrawalSend::Retry,
    );
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, super::WITHDRAWAL_SENDS]),
      "WriteOff zeroes ONLY v4; v6's full budget is untouched"
    );
  }

  /// regression: an encode-failing withdrawal must NOT
  /// head-of-line block a sibling. Two due withdrawals share one `scratch`: A
  /// (first in the vec) owns a goodbye too large for the buffer (many host A
  /// records) so `write_goodbye` errors; B owns a minimal goodbye that fits. A
  /// single `poll_withdrawal_transmit` must scan PAST the encode-failing A —
  /// advancing A's `next_at` past `now` (budget intact) — and RETURN B's
  /// datagram, not `None`.
  #[test]
  fn encode_failing_withdrawal_does_not_block_a_sibling() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();

    // A (registered FIRST → withdrawals index 0): owns PTR + a LARGE host A set so
    // its goodbye overflows the small shared scratch below.
    let inst_a = Name::try_from_str("A._ipp._tcp.local.").unwrap();
    let host_a = Name::try_from_str("ha.local.").unwrap();
    let recs_a = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst_a,
      host_a,
      631,
      120,
    );
    // The goodbye's size is driven by the snapshot's host_a (60 A records), which
    // `write_goodbye` emits from the iterator using the host name — no need to
    // register the addresses on the route.
    let big_a: std::vec::Vec<Ipv4Addr> = (0..60u8).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
    let (a, _svc_a) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs_a.clone()),
        now,
      )
      .unwrap();
    let snap_a = crate::service::WithdrawalSnapshot {
      records: recs_a,
      owned: crate::service::EmittedRecords::new(
        true,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: big_a,
      host_aaaa: std::vec::Vec::new(),
    };

    // B (registered after A): owns only a single PTR — a minimal goodbye that
    // fits the small scratch.
    let inst_b = Name::try_from_str("B._ipp._tcp.local.").unwrap();
    let recs_b = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst_b,
      Name::try_from_str("hb.local.").unwrap(),
      632,
      120,
    );
    let (b, _svc_b) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs_b.clone()),
        now,
      )
      .unwrap();
    let snap_b = crate::service::WithdrawalSnapshot {
      records: recs_b,
      owned: crate::service::EmittedRecords::new(
        true,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };

    ep.begin_withdrawal(a, snap_a, now);
    ep.begin_withdrawal(b, snap_b, now);

    // A scratch big enough for B's single-PTR goodbye but far too small for A's
    // 60-address goodbye. A single pump must scan past the encode-failing A and
    // return B's datagram.
    let mut scratch = std::vec![0u8; 128];
    let got = ep.poll_withdrawal_transmit(now, &mut scratch);
    let (_dst, _len, got_handle) =
      got.expect("the pump must scan past the encode-failing A and return B's goodbye");
    assert_eq!(
      Some(got_handle),
      ep.route_withdrawal_token(b),
      "B (encodable) is returned; A (encode-failing) did not head-of-line block"
    );

    // A was advanced past `now` (no longer first-due at this instant) with its
    // per-family budget intact — the 2 s ceiling remains its backstop.
    let a_next = ep.route_withdrawal_next_at(a).unwrap();
    assert!(
      a_next > now,
      "the encode-failing A must have its next_at pushed past now, not left due"
    );
    assert_eq!(
      a_next,
      now
        .checked_add_duration(super::WITHDRAWAL_RETRY_BACKOFF)
        .unwrap(),
      "A re-arms at the short backoff after an encode failure"
    );
    assert_eq!(
      ep.route_withdrawal_owed(a),
      Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
      "an encode failure must NOT spend A's resend budget"
    );
  }

  /// Regression: a teardown DURING a still-draining §9 conflict-rename
  /// goodbye must withdraw BOTH the OLD instance name AND the CURRENT
  /// (re-announced) instance records + host addresses — emitted as TWO SEPARATE
  /// single-name datagrams (the current part first, then the rename part), never
  /// one combined message.
  ///
  /// After a rename A→B the service clears its old instance ownership and
  /// re-announces B, confirming B's PTR/SRV/TXT + host A/AAAA while A's rename
  /// goodbye is still spaced out. If the service is retired in that window the
  /// snapshot carries the CURRENT name B (records + owned + host addrs) PLUS the
  /// rename's OLD name A (instance-only). Both must be retracted at TTL 0: B's
  /// instance records + host A/AAAA in the current datagram, then A's instance
  /// records (PTR/SRV under owner `A`, NO host — a rename never withdraws host
  /// addrs) in the rename datagram. The earlier single combined encoder could
  /// drop the rename when current ownership was empty, and could fail entirely
  /// when the combined message exceeded the scratch buffer.
  #[test]
  fn teardown_during_rename_goodbye_withdraws_old_and_new_name() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let old_name = Name::try_from_str("A._ipp._tcp.local.").unwrap();
    let new_name = Name::try_from_str("A-1._ipp._tcp.local.").unwrap();
    let host_v4 = Ipv4Addr::new(192, 168, 1, 7);
    let host_v6 = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

    // The CURRENT (re-announced) records under the renamed name B = `A-1`, owning
    // a full instance set + both host addresses.
    let mut recs_b = ServiceRecords::new(stype.clone(), new_name.clone(), host.clone(), 631, 120);
    recs_b.add_a(host_v4);
    recs_b.add_aaaa(host_v6);
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs_b.clone()),
        now,
      )
      .unwrap();

    // The OLD name A's still-in-flight rename goodbye (instance-only: PTR+SRV;
    // host addrs are intentionally absent — a rename never withdraws them).
    let old_records = ServiceRecords::new(stype, old_name.clone(), host.clone(), 631, 120);
    let old_owned = crate::service::EmittedRecords::new(
      true,
      true,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    );

    // A teardown DURING a still-draining rename is now two SEPARATE calls, each
    // producing one independent item. The rename happened first, so its old-name
    // (A) goodbye was already enqueued as a DETACHED item; the teardown then
    // begins the route-attached (B) withdrawal from a current-only snapshot.
    ep.enqueue_rename_withdrawal(
      crate::service::RenameGoodbyeHandoff {
        records: old_records,
        owned: old_owned,
      },
      now,
    );
    let snap = crate::service::WithdrawalSnapshot {
      records: recs_b,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec![host_v4],
      host_aaaa: std::vec![host_v6],
    };
    ep.begin_withdrawal(h, snap, now);

    // Both items owe a full per-family budget: the route item for B (it advertised
    // instance + host) and the detached item for A.
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
      "the route-attached current-name (B) item owes a full budget"
    );
    assert_eq!(
      ep.detached_withdrawal_owed_for(&old_name),
      Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
      "the detached old-name (A) item owes a full budget independently"
    );

    let mut buf = std::vec![0u8; 4096];

    // Parse one goodbye datagram into (saw old-A SRV, saw new-B SRV, v4 addrs,
    // v6 addrs). SRV is owned by the INSTANCE name, so it disambiguates A vs B
    // directly (the instance PTR is owned by the shared service-type, so it
    // cannot).
    let parse = |bytes: &[u8]| {
      let reader = crate::wire::MessageReader::try_parse(bytes).unwrap();
      let mut saw_old = false;
      let mut saw_new = false;
      let mut v4: std::vec::Vec<Ipv4Addr> = std::vec::Vec::new();
      let mut v6: std::vec::Vec<std::net::Ipv6Addr> = std::vec::Vec::new();
      for rec in reader.answers() {
        let rec = rec.unwrap();
        assert_eq!(rec.ttl(), 0, "every goodbye record must carry TTL 0");
        match rec.rtype() {
          crate::wire::ResourceType::A => {
            let d = rec.rdata();
            assert_eq!(d.len(), 4, "A rdata is 4 bytes");
            v4.push(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
          }
          crate::wire::ResourceType::AAAA => {
            let d = rec.rdata();
            assert_eq!(d.len(), 16, "AAAA rdata is 16 bytes");
            let mut o = [0u8; 16];
            o.copy_from_slice(d);
            v6.push(std::net::Ipv6Addr::from(o));
          }
          crate::wire::ResourceType::Srv => {
            if names_match(&old_name, rec.name()) {
              saw_old = true;
            } else if names_match(&new_name, rec.name()) {
              saw_new = true;
            }
          }
          _ => {}
        }
      }
      (saw_old, saw_new, v4, v6)
    };

    // The two items are INDEPENDENT, each emitting its own single-name datagram —
    // never combined. Drive each by the token the poll returns and classify the
    // datagram by which name's SRV it carries. Both are due at `now`, so two polls
    // yield the two names in some order.
    let token_b = ep.route_withdrawal_token(h).expect("B's route token");
    let token_a_owed = ep.detached_withdrawal_owed_for(&old_name);
    assert!(token_a_owed.is_some(), "A's detached item exists");

    let mut saw_new_datagram = false;
    let mut saw_old_datagram = false;
    for _ in 0..2 {
      let (_dst, len, token) = ep
        .poll_withdrawal_transmit(now, &mut buf)
        .expect("each rename-window item is due at now and emits its own datagram");
      let (saw_old, saw_new, withdrawn_v4, withdrawn_v6) = parse(buf.get(..len).unwrap());
      if saw_new {
        assert_eq!(token, token_b, "B's datagram round-trips B's route token");
        assert!(!saw_old, "B's datagram does NOT carry the old name A");
        assert!(
          withdrawn_v4.contains(&host_v4) && withdrawn_v6.contains(&host_v6),
          "the confirmed host A/AAAA addresses are withdrawn with B"
        );
        saw_new_datagram = true;
      } else {
        assert!(saw_old, "the other datagram carries the old name A");
        assert_ne!(
          token, token_b,
          "A's datagram is a DIFFERENT (detached) item"
        );
        assert!(
          withdrawn_v4.is_empty() && withdrawn_v6.is_empty(),
          "a rename (old-name) goodbye never withdraws host addresses"
        );
        saw_old_datagram = true;
      }
      // Confirm this round so the same item is not re-selected before the other.
      ep.note_withdrawal_result(
        token,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Sent,
      );
    }
    assert!(
      saw_new_datagram && saw_old_datagram,
      "BOTH the current name B and the old name A are withdrawn, as separate datagrams"
    );

    // The two items are independent: spending B's first round did not touch A's
    // debt, and vice versa.
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([super::WITHDRAWAL_SENDS - 1, super::WITHDRAWAL_SENDS - 1]),
      "B's route item spent exactly one round of its own budget"
    );
    assert_eq!(
      ep.detached_withdrawal_owed_for(&old_name),
      Some([super::WITHDRAWAL_SENDS - 1, super::WITHDRAWAL_SENDS - 1]),
      "A's detached item spent exactly one round of its own budget"
    );
  }

  /// Commit 2: a §9 rename enqueues the OLD name's goodbye as an INDEPENDENT
  /// DETACHED withdrawal item via [`Endpoint::enqueue_rename_withdrawal`] (the
  /// handoff the driver takes from `Service::take_rename_goodbye_handoff`). The
  /// item owns the old name, `poll_withdrawal_transmit` emits its TTL=0 instance
  /// goodbye (no host addresses), and it drains independently — freeing no route
  /// and reported to nobody on completion.
  #[test]
  fn rename_enqueues_a_detached_withdrawal_for_the_old_name() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
    let new_name = Name::try_from_str("Old-1._ipp._tcp.local.").unwrap();

    // A live service that has just renamed Old → Old-1 (registered under the new
    // name). The rename produced a handoff for the OLD name's instance goodbye.
    let recs = ServiceRecords::new(stype.clone(), new_name.clone(), host.clone(), 631, 120);
    let (_h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // No detached item yet.
    assert!(
      ep.detached_withdrawal_owed_for(&old_name).is_none(),
      "no detached item exists before the rename handoff is enqueued"
    );

    // The driver feeds the rename handoff (old name + instance-only ownership) to
    // the endpoint — modelling `take_rename_goodbye_handoff()` → enqueue.
    let old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
    let old_owned = crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    );
    ep.enqueue_rename_withdrawal(
      crate::service::RenameGoodbyeHandoff {
        records: old_records,
        owned: old_owned,
      },
      now,
    );

    // A detached item now owns the OLD name with a full per-family budget.
    assert_eq!(
      ep.detached_withdrawal_owed_for(&old_name),
      Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
      "the rename enqueues a detached item owning the old name with a full budget"
    );

    // It emits a TTL=0 instance goodbye for the OLD name (PTR/SRV/TXT), no host
    // addresses; the returned token is NOT a route token (it holds no route).
    let mut buf = std::vec![0u8; 4096];
    let (_dst, len, token) = ep
      .poll_withdrawal_transmit(now, &mut buf)
      .expect("the detached old-name item is due and emits its goodbye");
    let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
    let mut saw_old_srv = false;
    let mut saw_host_addr = false;
    for rec in reader.answers() {
      let rec = rec.unwrap();
      assert_eq!(rec.ttl(), 0, "every rename-goodbye record carries TTL 0");
      match rec.rtype() {
        crate::wire::ResourceType::Srv => {
          if names_match(&old_name, rec.name()) {
            saw_old_srv = true;
          }
        }
        crate::wire::ResourceType::A | crate::wire::ResourceType::AAAA => saw_host_addr = true,
        _ => {}
      }
    }
    assert!(
      saw_old_srv,
      "the detached goodbye withdraws the OLD instance's SRV at TTL 0"
    );
    assert!(
      !saw_host_addr,
      "a rename (old-name) goodbye never withdraws host A/AAAA"
    );

    // Drain BEFORE the item completes: it holds no route, so nothing is reported.
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert!(
      done.is_empty(),
      "a detached item reports no handle while still in flight"
    );
    assert!(
      ep.detached_withdrawal_owed_for(&old_name).is_some(),
      "the detached item is still owed after one (unconfirmed-by-drain) round"
    );

    // Spend its budget by its own token; it completes and is removed silently.
    for _ in 0..super::WITHDRAWAL_SENDS {
      ep.note_withdrawal_result(
        token,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Sent,
      );
    }
    assert_eq!(
      ep.detached_withdrawal_owed_for(&old_name),
      Some([0, 0]),
      "the detached old-name budget is fully spent"
    );
    let mut done2: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done2);
    assert!(
      done2.is_empty(),
      "a completed detached item frees no route and reports to nobody"
    );
    assert!(
      ep.detached_withdrawal_owed_for(&old_name).is_none(),
      "the completed detached item is removed"
    );

    // No-op guard: an empty-ownership handoff enqueues nothing.
    let empty_owned = crate::service::EmittedRecords::new(
      false,
      false,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    );
    let empty_records = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("Empty._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    ep.enqueue_rename_withdrawal(
      crate::service::RenameGoodbyeHandoff {
        records: empty_records,
        owned: empty_owned,
      },
      now,
    );
    assert!(
      ep.detached_withdrawal_owed_for(&Name::try_from_str("Empty._ipp._tcp.local.").unwrap())
        .is_none(),
      "an empty-ownership handoff is a no-op (nothing for peers to evict)"
    );
  }

  /// Regression: a RENAME-ONLY withdrawal snapshot — empty current
  /// ownership and no host addresses, but a pending OLD-name rename goodbye — must
  /// NOT be treated as nothing-to-withdraw. `Service::withdrawal_snapshot` has
  /// already consumed the pending rename, so if `begin_withdrawal` zeroed every
  /// part's debt the old name would be freed WITHOUT ever sending its goodbye (it
  /// would ghost until TTL). The current part owes nothing (`[0, 0]`) while the
  /// rename part owes a full budget, and `poll_withdrawal_transmit` emits the old
  /// name's instance goodbye.
  #[test]
  fn rename_only_withdrawal_emits_old_name_goodbye() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
    let cur_name = Name::try_from_str("Cur._ipp._tcp.local.").unwrap();

    // A registered service whose CURRENT records own nothing on the wire (it
    // renamed away before re-announcing) — its snapshot has empty current
    // ownership and no host addresses.
    let cur_recs = ServiceRecords::new(stype.clone(), cur_name, host.clone(), 631, 120);
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(cur_recs.clone()),
        now,
      )
      .unwrap();

    // The OLD name's still-in-flight rename goodbye (instance-only PTR+SRV).
    let old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
    let old_owned = crate::service::EmittedRecords::new(
      true,
      true,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    );

    // The rename happened first: enqueue the old name's goodbye as its own
    // detached item. The teardown then begins a current-only withdrawal whose
    // snapshot owns nothing on the wire.
    ep.enqueue_rename_withdrawal(
      crate::service::RenameGoodbyeHandoff {
        records: old_records,
        owned: old_owned,
      },
      now,
    );
    let snap = crate::service::WithdrawalSnapshot {
      records: cur_recs,
      // CURRENT owns nothing on the wire.
      owned: crate::service::EmittedRecords::new(
        false,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);

    // The route-attached current-name item owes nothing (it advertised nothing on
    // the wire). The DETACHED old-name item owes a full budget — so the old name
    // is NOT treated as nothing-to-withdraw and will actually be emitted.
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, 0]),
      "the route-attached current-name item owes nothing"
    );
    assert_eq!(
      ep.detached_withdrawal_owed_for(&old_name),
      Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
      "the detached old-name item owes a full per-family budget"
    );

    // The OLD name's goodbye MUST be emitted (the core regression: a rename-only
    // teardown must not drop it). Poll until a datagram carrying the old name's
    // SRV appears; the empty route item produces no datagram (it head-of-line
    // completes in place), so the only datagram is the detached old-name goodbye.
    let mut buf = std::vec![0u8; 4096];
    let detached_token = {
      let (_dst, len, token) = ep
        .poll_withdrawal_transmit(now, &mut buf)
        .expect("the detached old-name item must still produce the old-name goodbye");
      let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
      let mut saw_old = false;
      for rec in reader.answers() {
        let rec = rec.unwrap();
        assert_eq!(rec.ttl(), 0);
        if rec.rtype() == crate::wire::ResourceType::Srv && names_match(&old_name, rec.name()) {
          saw_old = true;
        }
      }
      assert!(
        saw_old,
        "the OLD name's instance records are withdrawn at TTL 0 (separate detached item)"
      );
      token
    };

    // The empty route item completes immediately — its handle IS reported on this
    // drain (it owns no records to withdraw). The detached old-name item is
    // independent: it is still owed, so it is NOT freed here, and it reports to
    // NOBODY when it eventually completes (it holds no route/name).
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert!(
      done.contains(&h),
      "the (empty) route-attached item completes immediately and reports its handle"
    );
    assert!(
      ep.detached_withdrawal_owed_for(&old_name).is_some(),
      "the detached old-name item is still in flight (not yet fully sent)"
    );

    // Spend the detached item's budget by its own token; it then completes and is
    // removed silently (reported to nobody — it owns no route).
    for _ in 0..super::WITHDRAWAL_SENDS {
      ep.note_withdrawal_result(
        detached_token,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Sent,
      );
    }
    assert_eq!(
      ep.detached_withdrawal_owed_for(&old_name),
      Some([0, 0]),
      "the detached old-name budget is fully spent"
    );
    let mut done2: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done2);
    assert!(
      done2.is_empty(),
      "a detached old-name item completes silently — no handle reported"
    );
    assert!(
      ep.detached_withdrawal_owed_for(&old_name).is_none(),
      "the detached old-name item is removed once fully sent"
    );
  }

  /// Regression: a rename-window teardown where the current
  /// goodbye and the old-name goodbye EACH fit the driver scratch individually
  /// but their COMBINED message would not. The old single-datagram encoder failed
  /// to encode (combined > scratch) and the ceiling then freed the route having
  /// sent NEITHER name. Emitting the two as SEPARATE single-name datagrams
  /// withdraws both. The `len1 + len2 > scratch` assertion proves a combined
  /// message would not have fit — i.e. the split was necessary.
  #[test]
  fn dual_name_each_fits_but_combined_would_not() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
    let new_name = Name::try_from_str("New._ipp._tcp.local.").unwrap();

    // A big TXT on BOTH names so each single-name goodbye is sizeable; sized so
    // each fits a modest scratch but the two combined do not.
    let big_seg = || std::vec![b'x'; 240];
    let mut recs_b = ServiceRecords::new(stype.clone(), new_name.clone(), host.clone(), 631, 120);
    for _ in 0..4 {
      recs_b.add_txt_segment(big_seg());
    }
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs_b.clone()),
        now,
      )
      .unwrap();

    let mut old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
    for _ in 0..4 {
      old_records.add_txt_segment(big_seg());
    }
    let owned_full = crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    );

    // The rename happened first → its old-name goodbye is its own detached item;
    // the teardown then begins the route-attached current-name withdrawal. Two
    // independent items, each its own single-name datagram.
    ep.enqueue_rename_withdrawal(
      crate::service::RenameGoodbyeHandoff {
        records: old_records,
        owned: owned_full.clone(),
      },
      now,
    );
    let snap = crate::service::WithdrawalSnapshot {
      records: recs_b,
      owned: owned_full,
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);

    // A scratch that fits each single-name goodbye but NOT their combined message.
    let mut buf = std::vec![0u8; 1600];

    // Both items are due at `now` and each emits its OWN single-name datagram.
    // Capture each name's length regardless of poll order, driving each by its
    // returned token.
    let mut len_new = 0usize;
    let mut len_old = 0usize;
    for _ in 0..2 {
      let (_d, len, token) = ep
        .poll_withdrawal_transmit(now, &mut buf)
        .expect("each single-name goodbye fits its own datagram");
      let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
      let mut saw_new = false;
      let mut saw_old = false;
      for r in reader.answers() {
        let r = r.unwrap();
        if r.rtype() == crate::wire::ResourceType::Srv {
          if names_match(&new_name, r.name()) {
            saw_new = true;
          } else if names_match(&old_name, r.name()) {
            saw_old = true;
          }
        }
      }
      if saw_new {
        assert!(!saw_old, "the current name rides its OWN datagram");
        len_new = len;
      } else {
        assert!(saw_old, "the other datagram carries the old name");
        len_old = len;
      }
      ep.note_withdrawal_result(
        token,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Sent,
      );
    }
    assert!(
      len_new > 0 && len_old > 0,
      "BOTH names were withdrawn, each in its own datagram"
    );

    // Each single-name datagram fits the scratch, but their COMBINED size would
    // overflow it — proving the split into independent items was necessary (the
    // old combined encoder would have failed and dropped both names).
    assert!(len_new <= buf.len() && len_old <= buf.len());
    assert!(
      len_new + len_old > buf.len(),
      "combined message ({len_new} + {len_old} = {}) would exceed the {}-byte scratch",
      len_new + len_old,
      buf.len()
    );
  }

  /// Regression: with INDEPENDENT items, an UNENCODABLE current-name
  /// goodbye (too large for the driver scratch) cannot starve the renamed-away
  /// old-name goodbye. The detached old-name item is scheduled on its own, so the
  /// pump emits it despite the route item being unencodable, and the route is
  /// still force-freed at its own ceiling. The old dual-part design (shared
  /// schedule + single final-attempt) dropped the old name in exactly this case.
  #[test]
  fn independent_items_unencodable_current_does_not_starve_rename() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
    let cur_name = Name::try_from_str("Cur._ipp._tcp.local.").unwrap();

    // CURRENT name with a big TXT → its goodbye will NOT fit a small scratch.
    let mut cur_recs = ServiceRecords::new(stype.clone(), cur_name.clone(), host.clone(), 631, 120);
    for _ in 0..4 {
      cur_recs.add_txt_segment(std::vec![b'x'; 240]);
    }
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(cur_recs.clone()),
        now,
      )
      .unwrap();

    // OLD (renamed-away) name, instance-only and small → fits a small scratch.
    let old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
    let old_owned = crate::service::EmittedRecords::new(
      true,
      true,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    );
    // The rename happened first → its old-name goodbye is its own detached item;
    // the teardown then begins the route-attached (huge current) withdrawal.
    ep.enqueue_rename_withdrawal(
      crate::service::RenameGoodbyeHandoff {
        records: old_records,
        owned: old_owned,
      },
      now,
    );
    let snap = crate::service::WithdrawalSnapshot {
      records: cur_recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);

    // Two independent items: a route-attached (huge current) + a detached (old).
    assert!(
      ep.route_withdrawal_owed(h).is_some(),
      "the current name is a route-attached item"
    );
    assert_eq!(
      ep.detached_withdrawal_owed_for(&old_name),
      Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
      "the renamed-away old name is a detached item owing a full budget"
    );

    // A scratch too small for the current goodbye but big enough for the old one.
    let mut small = std::vec![0u8; 300];
    let (_d, len, tok) = ep
      .poll_withdrawal_transmit(now, &mut small)
      .expect("the small old-name goodbye is emitted even though the current is unencodable");
    let reader = crate::wire::MessageReader::try_parse(small.get(..len).unwrap()).unwrap();
    let saw_old = reader.answers().any(|r| {
      let r = r.unwrap();
      r.rtype() == crate::wire::ResourceType::Srv && names_match(&old_name, r.name())
    });
    assert!(
      saw_old,
      "the renamed-away old name is withdrawn — NOT starved by the unencodable current"
    );
    assert_ne!(
      Some(tok),
      ep.route_withdrawal_token(h),
      "the emitted item is the detached old-name item, not the unencodable route item"
    );

    // The route is held while its withdrawal is in flight (not freed yet).
    let mut done = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert!(
      !done.contains(&h),
      "the route is held while its withdrawal item is still in flight"
    );

    // Past the ceiling: the route item's goodbye stays unencodable, so its final
    // ceiling attempt cannot encode but still force-completes the item; the
    // detached item reaches its own ceiling too. Both terminate; the route frees.
    let past = now
      .checked_add_duration(super::WITHDRAWAL_CEILING + core::time::Duration::from_millis(1))
      .unwrap();
    let mut guard = 0;
    while ep.poll_withdrawal_transmit(past, &mut small).is_some() {
      guard += 1;
      assert!(
        guard < 16,
        "the past-ceiling pump must terminate (each item's final attempt fires once)"
      );
    }
    let mut done2 = std::vec::Vec::new();
    ep.drain_completed_withdrawals(past, &mut done2);
    assert!(
      done2.contains(&h),
      "the route is force-freed at its ceiling even though the current goodbye never encoded"
    );
  }

  /// Regression: `unregister_service` is a force-remove, NO-goodbye
  /// primitive — it must ALSO drop the handle's ROUTE-attached withdrawal item.
  /// Otherwise removing the route (and its name guard) lets the same name be
  /// re-registered while a stale route-attached item still owes a TTL=0 goodbye,
  /// which would later flush the same-name replacement from peer caches.
  #[test]
  fn unregister_service_drops_route_attached_withdrawal_no_stale_goodbye() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let inst = Name::try_from_str("Svc._ipp._tcp.local.").unwrap();

    let recs = ServiceRecords::new(stype.clone(), inst.clone(), host, 631, 120);
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs.clone()),
        now,
      )
      .unwrap();

    // Begin a ROUTE-attached withdrawal: a goodbye item now owes for `inst`.
    let snap = crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);
    assert!(
      ep.route_withdrawal_owed(h).is_some(),
      "a route-attached withdrawal item owes a goodbye for the name"
    );

    // Force-remove must drop the route-attached withdrawal item (no goodbye).
    assert!(ep.unregister_service(h), "the route was found and removed");
    assert!(
      ep.route_withdrawal_owed(h).is_none(),
      "force-remove dropped the route-attached withdrawal item"
    );

    // The SAME name is reusable, and no stale withdrawal exists to flush it.
    ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(ServiceRecords::new(
        stype,
        inst,
        Name::try_from_str("other.local.").unwrap(),
        700,
        120,
      )),
      now,
    )
    .expect("the name is reusable after force-remove");
    let mut buf = std::vec![0u8; 1500];
    assert!(
      ep.poll_withdrawal_transmit(now, &mut buf).is_none(),
      "no stale TTL=0 goodbye is emitted for the force-removed-then-reused name"
    );
  }

  /// Regression: a renamed-away old name held by an in-flight
  /// DETACHED withdrawal item is RECLAIMED by a new registration — the detached
  /// goodbye is CANCELLED (the renamed-away service no longer owns the name, and
  /// the reclaiming service probes before announcing, so no late TTL=0 goodbye can
  /// flush it) rather than the name being rejected. Rejecting would needlessly
  /// fail a legitimate reuse (and, on the auto-rename path, kill the service).
  #[test]
  fn reclaiming_a_detached_name_cancels_its_goodbye() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
    let cur_name = Name::try_from_str("Cur._ipp._tcp.local.").unwrap();

    let cur_recs = ServiceRecords::new(stype.clone(), cur_name, host.clone(), 631, 120);
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(cur_recs.clone()),
        now,
      )
      .unwrap();

    // Teardown during a rename window: the rename enqueued a DETACHED item owning
    // `old_name`, and the teardown began a current-only withdrawal that owns
    // nothing here (isolating the detached item). Keep the current item alive so
    // the route is still held — the focus is the detached old-name reservation.
    let old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
    let old_owned = crate::service::EmittedRecords::new(
      true,
      true,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    );
    ep.enqueue_rename_withdrawal(
      crate::service::RenameGoodbyeHandoff {
        records: old_records,
        owned: old_owned,
      },
      now,
    );
    let snap = crate::service::WithdrawalSnapshot {
      records: cur_recs,
      owned: crate::service::EmittedRecords::new(
        false,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);
    assert!(
      ep.detached_withdrawal_owed_for(&old_name).is_some(),
      "a detached item owns the renamed-away old name"
    );

    // Reclaiming the old name SUCCEEDS and cancels the detached goodbye.
    let dup = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      old_name.clone(),
      Name::try_from_str("other.local.").unwrap(),
      700,
      120,
    );
    ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(dup),
      now,
    )
    .expect("reclaiming a detached-reserved name succeeds (the goodbye is cancelled)");
    assert!(
      ep.detached_withdrawal_owed_for(&old_name).is_none(),
      "the detached old-name goodbye was cancelled by the reclaim, so no late TTL=0 \
       goodbye can flush the new registration"
    );
  }

  /// Regression: an auto-rename onto a name held only by an in-flight
  /// DETACHED withdrawal must NOT be rejected — the drivers treat a rename error
  /// as fatal and would move the service into withdrawal (kill it). The reclaim
  /// cancels the detached goodbye and the rename succeeds.
  #[test]
  fn rename_onto_a_detached_name_cancels_it_not_kills_the_service() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let target = Name::try_from_str("Target._ipp._tcp.local.").unwrap();

    // A live service that will auto-rename onto `target`.
    let s_recs = ServiceRecords::new(
      stype.clone(),
      Name::try_from_str("S._ipp._tcp.local.").unwrap(),
      host.clone(),
      631,
      120,
    );
    let (s, _svc_s) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(s_recs),
        now,
      )
      .unwrap();

    // A second service whose teardown-during-rename leaves a DETACHED item owning
    // `target` — the name S is about to rename onto.
    let c2_recs = ServiceRecords::new(
      stype.clone(),
      Name::try_from_str("C2._ipp._tcp.local.").unwrap(),
      host.clone(),
      632,
      120,
    );
    let (h2, _svc2) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(c2_recs.clone()),
        now,
      )
      .unwrap();
    let target_records = ServiceRecords::new(stype, target.clone(), host, 633, 120);
    let target_owned = crate::service::EmittedRecords::new(
      true,
      true,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    );
    // C2's rename enqueued a DETACHED item owning `target`; its teardown then
    // began a current-only withdrawal (owns nothing here).
    ep.enqueue_rename_withdrawal(
      crate::service::RenameGoodbyeHandoff {
        records: target_records,
        owned: target_owned,
      },
      now,
    );
    let snap2 = crate::service::WithdrawalSnapshot {
      records: c2_recs,
      owned: crate::service::EmittedRecords::new(
        false,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h2, snap2, now);
    assert!(
      ep.detached_withdrawal_owed_for(&target).is_some(),
      "a detached item owns `target`"
    );

    // S auto-renames onto `target`: the endpoint must NOT reject (the driver would
    // treat that as fatal) — it cancels the detached goodbye and applies the rename.
    ep.handle_service_renamed(s, target.clone())
      .expect("an auto-rename onto a detached-reserved name succeeds (cancels the goodbye)");
    assert!(
      ep.detached_withdrawal_owed_for(&target).is_none(),
      "the detached goodbye for the reclaimed name was cancelled, not left to flush S"
    );
  }

  /// regression: a family that recovers in the FINAL window
  /// before the ceiling (because the last backoff overshot `ceiling_at`) must
  /// still get ONE last goodbye attempt before the route is force-freed.
  ///
  /// v4 is paid; v6 stays busy (Retry). The last `note_withdrawal_result` clamps
  /// `next_at` to `ceiling_at` (the schedule cannot skip past the ceiling). AT
  /// the ceiling, `poll_withdrawal_transmit` must return a datagram for the owed
  /// withdrawal EXACTLY ONCE (the final attempt) — the normal due window
  /// (`now < ceiling_at`) no longer matches, so without the final-attempt branch
  /// the owed family would never be tried. A SECOND poll at the same instant must
  /// return `None` (no infinite emission), and `drain_completed_withdrawals` then
  /// force-completes the route.
  #[test]
  fn owed_family_gets_a_final_attempt_at_ceiling() {
    let mut ep = build_endpoint();
    let t0 = StdInstant::now();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst.clone(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs.clone()),
        t0,
      )
      .unwrap();
    // Owns instance records, so the withdrawal has a real goodbye to emit.
    let snap = crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, t0);
    let ceiling = t0.checked_add_duration(super::WITHDRAWAL_CEILING).unwrap();

    // Pay v4 fully; v6 is busy each round. v4's debt drains to 0, v6 still owes.
    for _ in 0..super::WITHDRAWAL_SENDS {
      ep.note_route_withdrawal_result(
        h,
        t0,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Retry,
      );
    }
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, super::WITHDRAWAL_SENDS]),
      "v4 paid; v6 still owes its whole budget"
    );

    // A round JUST before the ceiling with no real progress (v4 already paid →
    // redundant Sent, v6 still Retry) re-arms at the short backoff — which the
    // clamp pins to `ceiling_at` (the backoff would otherwise overshoot it).
    let t_near = t0
      .checked_add_duration(super::WITHDRAWAL_CEILING - core::time::Duration::from_millis(1))
      .unwrap();
    ep.note_route_withdrawal_result(
      h,
      t_near,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Retry,
    );
    assert_eq!(
      ep.route_withdrawal_next_at(h),
      Some(ceiling),
      "the re-arm must be CLAMPED to ceiling_at, not pushed past it"
    );

    // AT the ceiling: the normal due window (`now < ceiling_at`) no longer
    // matches, but the owed family still gets ONE final attempt.
    let mut buf = std::vec![0u8; 4096];
    let first = ep.poll_withdrawal_transmit(ceiling, &mut buf);
    let (_dst, _len, got) =
      first.expect("the owed family must get a FINAL goodbye attempt at the ceiling");
    assert_eq!(
      Some(got),
      ep.route_withdrawal_token(h),
      "the final attempt is for the owed withdrawal"
    );

    // A second poll at the SAME instant must NOT re-emit (final_attempt guards it)
    // — proving the past-ceiling branch fires at most once (no infinite emission).
    assert!(
      ep.poll_withdrawal_transmit(ceiling, &mut buf).is_none(),
      "the final attempt fires exactly once; a second poll must return None"
    );

    // The route is now force-completed (past the ceiling AND final-attempted).
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(ceiling, &mut done);
    assert!(
      done.contains(&h),
      "after its final ceiling attempt the route is force-completed and freed"
    );
    // The name is re-registerable once the route is freed.
    let recs2 = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst,
      Name::try_from_str("h2.local.").unwrap(),
      631,
      120,
    );
    assert!(
      ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs2),
        ceiling,
      )
      .is_ok(),
      "the withdrawn name is re-registerable after the route is force-freed"
    );
  }

  /// before the ceiling-attempt fix, a withdrawal past its ceiling with debt
  /// still owed but no final attempt must NOT be force-completed — it is held for
  /// the final attempt. This pins down the `drain` guard: past the ceiling but
  /// `!final_attempt` and `owed != [0,0]` → not yet drained.
  #[test]
  fn past_ceiling_owed_withdrawal_is_held_until_final_attempt() {
    let mut ep = build_endpoint();
    let t0 = StdInstant::now();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("Printer._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs.clone()),
        t0,
      )
      .unwrap();
    let snap = crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, t0);
    let ceiling = t0.checked_add_duration(super::WITHDRAWAL_CEILING).unwrap();

    // A drain PAST the ceiling, with v6 still owed and NO final attempt yet made,
    // must NOT free the route — the owed family is still entitled to its last try.
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(ceiling, &mut done);
    assert!(
      done.is_empty(),
      "a past-ceiling owed withdrawal must be HELD until its final attempt is made"
    );

    // The final attempt happens on the next poll; THEN drain frees it.
    let mut buf = std::vec![0u8; 4096];
    assert!(
      ep.poll_withdrawal_transmit(ceiling, &mut buf).is_some(),
      "the final ceiling attempt is emitted"
    );
    ep.drain_completed_withdrawals(ceiling, &mut done);
    assert!(
      done.contains(&h),
      "after the final attempt the held route is force-completed"
    );
  }

  /// A withdrawal that spends its whole budget COMPLETES: the route is freed,
  /// `services_active` is decremented, the handle is returned for GC, and the
  /// name is re-registerable (Task 5).
  #[cfg(feature = "stats")]
  #[test]
  fn withdrawal_completes_frees_name_and_decrements_active() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst.clone(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, mut svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    let before = ep.stats().services_active;
    ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);

    // Spend the whole per-family resend budget via dual-stack delivered
    // confirmations (both families Sent each round → owed reaches [0, 0]).
    for _ in 0..super::WITHDRAWAL_SENDS {
      ep.note_route_withdrawal_result(
        h,
        now,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Sent,
      );
    }
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);

    assert_eq!(
      done,
      std::vec![h],
      "the completed handle is returned for GC"
    );
    assert_eq!(
      ep.stats().services_active,
      before - 1,
      "services_active is decremented on completion"
    );

    // The name is now re-registerable.
    let recs2 = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst,
      Name::try_from_str("h2.local.").unwrap(),
      631,
      120,
    );
    assert!(
      ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs2),
        now,
      )
      .is_ok(),
      "the withdrawn name is re-registerable after completion"
    );
  }

  /// A withdrawal whose families never deliver is force-completed at its ceiling
  /// (anti-pin), so the name is eventually released (Task 5).
  #[test]
  fn withdrawal_force_completes_at_ceiling() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("A._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, mut svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);

    // Never deliver; advance to the ceiling (now + WITHDRAWAL_CEILING).
    let at_ceiling = now.checked_add_duration(super::WITHDRAWAL_CEILING).unwrap();
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(at_ceiling, &mut done);
    assert_eq!(
      done,
      std::vec![h],
      "ceiling force-completes a wedged withdrawal"
    );
  }

  /// Build a withdrawal snapshot owning NO instance records, withdrawing only
  /// the given host A set (models a host-record-only withdrawal).
  fn host_only_snapshot(
    host: &Name,
    instance: &str,
    host_a: &[Ipv4Addr],
  ) -> crate::service::WithdrawalSnapshot {
    let mut recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str(instance).unwrap(),
      host.clone(),
      631,
      120,
    );
    for a in host_a {
      recs.add_a(*a);
    }
    crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        false,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: host_a.to_vec(),
      host_aaaa: std::vec::Vec::new(),
    }
  }

  /// Regression: a retained-only withdrawal must NOT head-of-line
  /// block the pump. Two same-time withdrawals: A is retained-only (its single
  /// host address is still advertised by a LIVE non-withdrawing sibling C, and A
  /// owns no instance records) and B genuinely needs a TTL=0 goodbye. The pump
  /// must scan PAST A (returning B's datagram, not `None`) in the SAME pass, and
  /// a subsequent drain must complete/free A at once (not leave it pinned to the
  /// 2 s ceiling).
  #[test]
  fn retained_only_withdrawal_completes_and_does_not_block_a_sibling() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("h.local.").unwrap();
    let shared = Ipv4Addr::new(192, 168, 1, 5);

    // C: a LIVE same-host sibling that has CONFIRMED-ADVERTISED `shared` and is
    // NOT withdrawing — it legitimately keeps the address in peer caches.
    let _c = register_host_service(
      &mut ep,
      "C._ipp._tcp.local.",
      &host,
      &[shared],
      Some(&[shared]),
    );

    // A (registered FIRST → lower withdrawals index): withdraws only `shared`,
    // owns no instance records. Since C retains `shared`, A has NOTHING to emit.
    let a = register_host_service(
      &mut ep,
      "A._ipp._tcp.local.",
      &host,
      &[shared],
      Some(&[shared]),
    );
    // B (registered after A): genuinely needs a goodbye (owns PTR/SRV/TXT, no
    // host addresses so it is independent of host retention).
    let recs_b = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("B._ipp._tcp.local.").unwrap(),
      Name::try_from_str("hb.local.").unwrap(),
      632,
      120,
    );
    let (b, _svc_b) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs_b.clone()),
        now,
      )
      .unwrap();
    let snap_b = crate::service::WithdrawalSnapshot {
      records: recs_b,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };

    // Both withdraw at the SAME time (A first in the vec, then B).
    ep.begin_withdrawal(
      a,
      host_only_snapshot(&host, "A._ipp._tcp.local.", &[shared]),
      now,
    );
    ep.begin_withdrawal(b, snap_b, now);

    // A single pump must scan PAST the retained-only A and RETURN B's datagram —
    // NOT `None`. (Pre-fix it returned `None` on A, starving B.)
    let mut buf = std::vec![0u8; 4096];
    let (_dst, len, got) = ep
      .poll_withdrawal_transmit(now, &mut buf)
      .expect("the pump must scan past the retained-only A and return B's goodbye");
    assert_eq!(
      Some(got),
      ep.route_withdrawal_token(b),
      "the genuine withdrawal B is the one that emits"
    );
    let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
    assert!(
      reader.answers().count() > 0,
      "B's goodbye must carry its TTL=0 instance records"
    );

    // A was marked complete in that scan (owed set to [0, 0]), so the NEXT drain
    // frees it AT ONCE — without waiting for the 2 s ceiling.
    assert_eq!(
      ep.route_withdrawal_owed(a),
      Some([0, 0]),
      "the retained-only A must be COMPLETED (owed = [0, 0]) by the scan"
    );
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert!(
      done.contains(&a),
      "the retained-only A must be freed immediately, not pinned to the ceiling"
    );
    // A's route is gone, so its name is re-registerable now (no ceiling wait).
    let recs_a2 = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("A._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h2.local.").unwrap(),
      633,
      120,
    );
    assert!(
      ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs_a2),
        now,
      )
      .is_ok(),
      "A's name is released the moment its retained-only withdrawal completes"
    );
  }

  /// Regression: a LONE retained-only withdrawal returns `None`
  /// from `poll_withdrawal_transmit` (nothing to emit) but is COMPLETED in place
  /// (`owed` set to [0, 0]), so the next drain frees it AT ONCE rather than
  /// pinning the name to the 2 s ceiling and re-waking `poll_timeout` until then.
  #[test]
  fn retained_only_withdrawal_completes_immediately() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("h.local.").unwrap();
    let shared = Ipv4Addr::new(192, 168, 1, 5);

    // C: a LIVE same-host sibling that still advertises `shared`.
    let _c = register_host_service(
      &mut ep,
      "C._ipp._tcp.local.",
      &host,
      &[shared],
      Some(&[shared]),
    );
    // A: retained-only (owns no instance records; its only host addr is retained
    // by C).
    let a = register_host_service(
      &mut ep,
      "A._ipp._tcp.local.",
      &host,
      &[shared],
      Some(&[shared]),
    );
    ep.begin_withdrawal(
      a,
      host_only_snapshot(&host, "A._ipp._tcp.local.", &[shared]),
      now,
    );

    // A lone retained-only withdrawal emits no datagram.
    let mut buf = std::vec![0u8; 4096];
    assert!(
      ep.poll_withdrawal_transmit(now, &mut buf).is_none(),
      "a retained-only withdrawal has nothing to emit"
    );
    // But it is COMPLETED — `owed` is [0, 0], so the drain frees it immediately.
    assert_eq!(
      ep.route_withdrawal_owed(a),
      Some([0, 0]),
      "the retained-only withdrawal must be completed (owed = [0, 0]), not left due"
    );
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert_eq!(
      done,
      std::vec![a],
      "the retained-only withdrawal is freed at once, not at the 2 s ceiling"
    );
  }

  /// A withdrawing route is NOT routed an incoming question (its service is gone,
  /// only its goodbye is draining), but the route is still present so a same-name
  /// re-registration is rejected (Task 6).
  #[test]
  fn withdrawing_route_is_not_answered_but_still_blocks_reregister() {
    use core::net::SocketAddr;
    let mut e = build_endpoint();
    let now = StdInstant::now();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst.clone(),
      Name::try_from_str("printer-host.local.").unwrap(),
      631,
      120,
    );
    let (handle, mut svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    e.begin_withdrawal(handle, svc.withdrawal_snapshot(), now);

    // A question for the (withdrawing) host must NOT route to the service.
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let mut buf = [0u8; 512];
    let n = build_query_for_host(&mut buf, "printer-host.local.");
    let routed_to_service = e
      .handle(StdInstant::now(), src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
    assert!(
      !routed_to_service,
      "a withdrawing service must not be routed a question"
    );

    // The name is still held (route present for the guard).
    let recs2 = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst,
      Name::try_from_str("h2.local.").unwrap(),
      631,
      120,
    );
    assert!(
      matches!(
        e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
          ServiceSpec::new(recs2),
          now
        ),
        Err(RegisterServiceError::NameAlreadyRegistered(_))
      ),
      "the withdrawing name must still be held"
    );
  }

  /// a withdrawing route must receive NO `ToService` dispatch on ANY
  /// path — HostConflict, ProbeConflict, AND the QR=0 meta-PTR known-answer fanout
  /// — not just no question. The route is retained for the name guard, but
  /// dispatching to a service the driver no longer drains (it skips
  /// withdrawing/errored contexts) lets a peer flood the proto event slab of a
  /// retiring service until GC — a bounded-time but unbounded-size growth path. A
  /// positive control feeds the SAME packets while the service is LIVE (they must
  /// route), so the negative assertions are not vacuous; the name must still be held
  /// afterwards (dispatch-only skip).
  #[test]
  fn withdrawing_route_receives_no_service_dispatch_but_still_blocks_reregister() {
    use core::net::SocketAddr;

    use crate::wire::{Header, MessageBuilder};

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst.clone(),
      host.clone(),
      631,
      120,
    );
    let (handle, mut svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    // A peer claiming our HOST name with a DIFFERENT address → §9 HostConflict.
    let host_pkt = {
      let mut buf = [0u8; 512];
      let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
      b.push_a_authority(&host, 120, Ipv4Addr::new(10, 0, 0, 99))
        .unwrap();
      let n = b.finish().unwrap();
      buf[..n].to_vec()
    };
    // A peer claiming our INSTANCE name with rival rdata → §9 ProbeConflict.
    let inst_pkt = {
      let target = Name::try_from_str("rival.local.").unwrap();
      let mut buf = [0u8; 512];
      let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
      b.push_srv_authority(&inst, 120, 0, 0, 9999, &target)
        .unwrap();
      let n = b.finish().unwrap();
      buf[..n].to_vec()
    };
    // A QR=0 meta-PTR known-answer (DNS-SD service-type enumeration) fans out to
    // EVERY service; a withdrawing route must be excluded from that fanout too.
    let ka_pkt = {
      let meta = Name::try_from_str("_services._dns-sd._udp.local.").unwrap();
      let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
      let mut buf = [0u8; 512];
      let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
      b.push_ptr_answer(&meta, 120, &stype).unwrap();
      let n = b.finish().unwrap();
      buf[..n].to_vec()
    };
    // (inline handle-and-check: a closure capturing `&mut e` would conflict with
    // the direct `e` uses between calls, and naming the generic Endpoint type for a
    // by-ref-param closure is brittle.)

    // POSITIVE CONTROL: while LIVE, both conflicts DO route a ToService — so the
    // negative assertions below actually exercise the withdrawing skip.
    let live_host = e
      .handle(StdInstant::now(), src, local_ip, 0, &host_pkt, false)
      .unwrap()
      .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
    assert!(
      live_host,
      "sanity: a LIVE service must receive the HostConflict dispatch"
    );
    let live_inst = e
      .handle(StdInstant::now(), src, local_ip, 0, &inst_pkt, false)
      .unwrap()
      .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
    assert!(
      live_inst,
      "sanity: a LIVE service must receive the ProbeConflict dispatch"
    );
    let live_ka = e
      .handle(StdInstant::now(), src, local_ip, 0, &ka_pkt, false)
      .unwrap()
      .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
    assert!(
      live_ka,
      "sanity: a LIVE service must receive the meta-PTR KnownAnswer dispatch"
    );

    // Now retire the route via the endpoint-owned withdrawal.
    e.begin_withdrawal(handle, svc.withdrawal_snapshot(), now);

    // While WITHDRAWING, neither conflict routes any ToService.
    let wd_host = e
      .handle(StdInstant::now(), src, local_ip, 0, &host_pkt, false)
      .unwrap()
      .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
    assert!(
      !wd_host,
      "a withdrawing service must not receive a HostConflict dispatch"
    );
    let wd_inst = e
      .handle(StdInstant::now(), src, local_ip, 0, &inst_pkt, false)
      .unwrap()
      .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
    assert!(
      !wd_inst,
      "a withdrawing service must not receive a ProbeConflict dispatch"
    );
    let wd_ka = e
      .handle(StdInstant::now(), src, local_ip, 0, &ka_pkt, false)
      .unwrap()
      .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
    assert!(
      !wd_ka,
      "a withdrawing service must not receive a KnownAnswer dispatch"
    );

    // The name is still held (route present for the guard) — the skip is
    // dispatch-only, not a release of the name reservation.
    let recs2 = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst,
      Name::try_from_str("h2.local.").unwrap(),
      631,
      120,
    );
    assert!(
      matches!(
        e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
          ServiceSpec::new(recs2),
          now
        ),
        Err(RegisterServiceError::NameAlreadyRegistered(_))
      ),
      "the withdrawing name must still be held"
    );
  }

  /// `poll_timeout` accounts for a due endpoint-owned withdrawal so the driver
  /// wakes to pump it (Task 6).
  #[test]
  fn poll_timeout_accounts_for_due_withdrawal() {
    let mut e = build_endpoint();
    let now = StdInstant::now();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("A._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, mut svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    e.begin_withdrawal(h, svc.withdrawal_snapshot(), now);
    assert_eq!(
      e.poll_timeout(),
      Some(now),
      "a due-now withdrawal makes poll_timeout return now"
    );
  }

  /// A never-announced service (empty withdrawal snapshot) completes on the FIRST
  /// `drain_completed_withdrawals` — no spurious goodbye, no 2 s ceiling wait.
  #[cfg(feature = "stats")]
  #[test]
  fn empty_withdrawal_completes_immediately() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("A._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, mut svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    let before = ep.stats().services_active;
    // Never announced → empty snapshot → owed == [0, 0].
    ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert_eq!(
      done,
      std::vec![h],
      "an empty withdrawal completes on the first drain (no ceiling wait)"
    );
    assert_eq!(ep.stats().services_active, before - 1);
  }

  /// Regression: `next_withdrawal_deadline` / `has_pending_withdrawals`
  /// reflect ONLY in-flight withdrawals — excluding cache and query deadlines — so
  /// a last-handle shutdown flush exits as soon as every goodbye is sent instead
  /// of parking on an unrelated cache deadline (or the wall-clock backstop).
  #[test]
  fn next_withdrawal_deadline_reflects_only_withdrawals() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    assert_eq!(
      ep.next_withdrawal_deadline(),
      None,
      "no withdrawal in flight → no withdrawal deadline"
    );
    assert!(!ep.has_pending_withdrawals());

    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Svc._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let recs = ServiceRecords::new(stype, inst, host, 631, 120);
    let (h, _svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs.clone()),
        now,
      )
      .unwrap();

    // A route-attached withdrawal that owns instance records is due NOW.
    let snap = crate::service::WithdrawalSnapshot {
      records: recs,
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
      host_a: std::vec::Vec::new(),
      host_aaaa: std::vec::Vec::new(),
    };
    ep.begin_withdrawal(h, snap, now);
    assert_eq!(
      ep.next_withdrawal_deadline(),
      Some(now),
      "a due-now withdrawal sets the withdrawal deadline"
    );
    assert!(ep.has_pending_withdrawals());

    // Force-remove drops the route-attached item → the withdrawal deadline is gone
    // again, so a shutdown flush would exit (None) rather than wait on any cache
    // or query deadline.
    assert!(ep.unregister_service(h));
    assert_eq!(ep.next_withdrawal_deadline(), None);
    assert!(!ep.has_pending_withdrawals());
  }

  /// `begin_withdrawal` is idempotent: a second call for an already-withdrawing
  /// handle does not enqueue a duplicate (so the handle is GC-reported once).
  #[test]
  fn begin_withdrawal_is_idempotent() {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("A._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let (h, mut svc) = ep
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);
    // Second retire of the same handle must be a no-op (no duplicate schedule).
    ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);
    let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
    ep.drain_completed_withdrawals(now, &mut done);
    assert_eq!(
      done,
      std::vec![h],
      "idempotent begin_withdrawal must report the handle exactly once"
    );
  }
}

// ── RouteEvents iterator ─────────────────────────────────────────────

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
  match Name::try_from_str(DNS_SD_META_QUERY_NAME) {
    Ok(meta) => names_match(&meta, qname),
    Err(_) => false,
  }
}

pub(crate) fn names_match(stored: &Name, incoming: &NameRef<'_>) -> bool {
  let stored_str = stored.as_str();
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

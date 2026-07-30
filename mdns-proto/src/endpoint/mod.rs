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

mod matching;
pub(crate) use matching::*;
mod route;
pub use route::RouteEvents;
pub(crate) use route::Section;
mod query;
mod receive;
mod service;
mod withdrawal;

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
  service::{FullyAnnounced, Service},
  trace::*,
  transmit::{Transmit, TransmitOutcome},
  wire::{MessageReader, NameRef, ResourceClass, ResourceType},
};

cfg_heap! {
  /// Number of goodbye sends during an orderly withdrawal (RFC 6762 §10.1),
  /// counted PER FAMILY so each reachable family withdraws its records.
  const WITHDRAWAL_SENDS: u8 = 3;

  /// Spacing between successive withdrawal goodbye resends (loss resilience).
  // Used by `poll_withdrawal_transmit`.
  #[allow(dead_code)]
  const WITHDRAWAL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(250);

  /// Back-off added to `next_at` on a missed send (delivery not yet confirmed).
  // Used by `note_withdrawal_result`.
  #[allow(dead_code)]
  const WITHDRAWAL_RETRY_BACKOFF: core::time::Duration = core::time::Duration::from_millis(20);

  /// Hard deadline by which a withdrawal is force-completed regardless of
  /// pending sends, to prevent a stale withdrawing route from pinning the name
  /// slot indefinitely.
  const WITHDRAWAL_CEILING: core::time::Duration = core::time::Duration::from_secs(2);
}

cfg_heap! {
  /// Per-family result of sending one withdrawal (RFC 6762 §10.1 goodbye)
  /// datagram, reported to [`Endpoint::note_withdrawal_result`] for EACH address
  /// family so a withdrawal only completes once every reachable family has
  /// withdrawn its records.
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
    /// goodbye, leaving peers with stale PTR/SRV/TXT until TTL. A held name is
    /// rejected by BOTH reuse paths — `try_register_service` and
    /// `handle_service_renamed` — and is never cancelled by
    /// [`Endpoint::note_service_announced`], so the dead service's goodbye always
    /// drains before the name can be claimed again.
    #[allow(dead_code)]
    holds_name: bool,
  }
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
  /// [`Endpoint::note_service_announced`] after each confirmed announce.  This
  /// (NOT the configured `a_addrs`) is what `sibling_retained_addrs` honours so
  /// a withdrawing service only retains addresses a LIVE same-host sibling
  /// genuinely owns in peer caches.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  advertised_a: std::vec::Vec<Ipv4Addr>,
  /// IPv6 host addresses this service has actually CONFIRMED-ADVERTISED.  See
  /// `advertised_a`; this is the AAAA counterpart, also EMPTY at registration.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
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

  cfg_heap! {
    /// IPv4 host addresses this service has CONFIRMED-ADVERTISED on the wire.
    /// Distinct from [`Self::a_addrs`] (the configured set used for self-/
    /// loopback detection): this is the subset peers actually hold in cache, kept
    /// current by [`Endpoint::note_service_announced`] and consumed by
    /// sibling host-address retention during withdrawal.
    #[inline(always)]
    pub(crate) fn advertised_a(&self) -> &[Ipv4Addr] {
      &self.advertised_a
    }

    /// IPv6 host addresses this service has CONFIRMED-ADVERTISED on the wire (the
    /// AAAA counterpart of [`Self::advertised_a`]).
    #[inline(always)]
    pub(crate) fn advertised_aaaa(&self) -> &[Ipv6Addr] {
      &self.advertised_aaaa
    }
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
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  withdrawals: std::vec::Vec<(WithdrawalToken, WithdrawalItem<I>)>,
  /// Monotonic source of [`WithdrawalToken`] values. Incremented on every item
  /// insert and NEVER reused, so a token names exactly the item it was minted for
  /// (or nothing, once that item drained) — there is no ABA on the poll/note key.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
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
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      withdrawals: std::vec::Vec::new(),
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      next_withdrawal_token: 0,
      #[cfg(feature = "stats")]
      stats,
      _phantom: core::marker::PhantomData,
    }
  }

  cfg_stats! {
    /// Return a point-in-time snapshot of all counters and gauges.
    pub fn stats(&self) -> hick_trace::stats::StatsSnapshot {
      self.stats.snapshot()
    }

    /// Return a cloned handle to the shared [`hick_trace::stats::Stats`] so the I/O driver can
    /// bump transport-level counters (e.g. `bytes_tx`, `packets_tx`).
    pub fn stats_handle(&self) -> std::sync::Arc<hick_trace::stats::Stats> {
      self.stats.clone()
    }
  }

  /// Returns the configuration.
  #[inline(always)]
  pub const fn config(&self) -> &EndpointConfig {
    &self.config
  }
}

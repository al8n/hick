//! Driver state, the spawned `run()` loop, and the `LocalNotify` primitive.

// `LocalNotify` is consumed by the driver `run()` loop wired in by T7+; silence
// `dead_code` until those callers land in the same crate.
#![allow(dead_code)]

use std::rc::Rc;

use event_listener::Event;

/// Non-atomic notify for waking the driver from handle-side mutations.
/// Single-thread (`!Send`) by design — built on `event-listener`'s `Event`
/// primitive but never crosses threads.
#[derive(Clone)]
pub(crate) struct LocalNotify {
  inner: Rc<Event>,
}

impl LocalNotify {
  pub(crate) fn new() -> Self {
    Self {
      inner: Rc::new(Event::new()),
    }
  }

  pub(crate) fn notify(&self) {
    self.inner.notify(usize::MAX);
  }

  pub(crate) async fn listen(&self) {
    self.inner.listen().await;
  }
}

use std::{
  collections::{HashMap, VecDeque},
  time::{Duration, Instant as StdInstant, SystemTime},
};

use mdns_proto::{
  CacheEntry, CollectedAnswer, Endpoint as ProtoEp, EndpointConfig, EndpointEventEntry,
  QueryHandle, QueryUpdate, ServiceHandle, ServiceRoute, ServiceUpdate, query::Query as ProtoQuery,
  service::Service as ProtoSvc, transmit::Transmit,
};

/// RFC 6762 §10.1: a goodbye is multicast a few times for loss resilience.
/// Matches `hick-reactor::driver::GOODBYE_SENDS`.
pub(crate) const GOODBYE_SENDS: u8 = 3;

/// Spacing between successive goodbye resends. Matches
/// `hick-reactor::driver::GOODBYE_INTERVAL`.
pub(crate) const GOODBYE_INTERVAL: Duration = Duration::from_millis(250);

/// Per-iteration cap on the transmit pump.  Mirrors
/// `hick-reactor::driver::MAX_SEND_CREDITS_PER_DRAIN` (64) so a misbehaving
/// proto-state machine — or a transmit yielded for an unbound address family
/// where `note_*_transmit_result(delivered=false)` does not advance state —
/// cannot spin the driver in a tight unbounded loop.
pub(crate) const MAX_TRANSMIT_CREDITS_PER_PASS: usize = 64;

/// IPv4 mDNS multicast destination (224.0.0.251:5353). Used by the goodbye
/// pump (which doesn't go through `poll_one_transmit`).
pub(crate) const MDNS_V4_DST: core::net::SocketAddr = core::net::SocketAddr::V4(
  core::net::SocketAddrV4::new(core::net::Ipv4Addr::new(224, 0, 0, 251), 5353),
);

/// IPv6 mDNS multicast destination ([ff02::fb]:5353). Used by the goodbye
/// pump.
pub(crate) const MDNS_V6_DST: core::net::SocketAddr =
  core::net::SocketAddr::V6(core::net::SocketAddrV6::new(
    core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb),
    5353,
    0,
    0,
  ));

/// Whether `dst` is an mDNS multicast destination (multicast IP on port
/// 5353).  `mdns-proto`'s `multicast_dst()` ALWAYS returns the IPv4 group
/// `224.0.0.251:5353` — even for the IPv6 service group — so the transmit
/// pump cannot route multicast by the destination's address family. Instead
/// it detects an mDNS multicast destination here and fans the SAME payload
/// out to BOTH bound families' multicast groups (RFC 6762 §6: a dual-stack
/// host answers on each). Mirrors the reactor's `send_via` predicate.
pub(crate) fn is_mdns_multicast_dst(dst: core::net::SocketAddr) -> bool {
  use hick_udp::constants::MDNS_PORT;
  matches!(dst, core::net::SocketAddr::V4(a) if a.ip().is_multicast() && a.port() == MDNS_PORT)
    || matches!(dst, core::net::SocketAddr::V6(a) if a.ip().is_multicast() && a.port() == MDNS_PORT)
}

/// Concrete `mdns-proto::Endpoint` instantiation used by the compio driver.
/// All pool slots are `slab::Slab`-backed so the std-side state lives in heap-
/// growable storage rather than heapless fixed buffers.
pub(crate) type ProtoEndpoint = ProtoEp<
  StdInstant,
  rand::rngs::StdRng,
  slab::Slab<CacheEntry<StdInstant>>,
  slab::Slab<ServiceRoute>,
  slab::Slab<ProtoQuery<StdInstant, slab::Slab<CollectedAnswer>, slab::Slab<QueryUpdate>>>,
  slab::Slab<EndpointEventEntry>,
  slab::Slab<CollectedAnswer>,
  slab::Slab<QueryUpdate>,
>;

/// Concrete `mdns-proto::Service` instantiation used by the compio driver. The
/// state machine is owned per-`ServiceCtx`; the endpoint only tracks routing
/// metadata via `ServiceRoute`.
pub(crate) type ProtoService =
  ProtoSvc<StdInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>;

/// Origin tag for a pumped transmit. Carries the source handle so the driver
/// can route the post-send `note_transmit_result` (and similar) back to the
/// right per-handle context.
#[derive(Clone, Copy)]
pub(crate) enum TransmitOrigin {
  Service(ServiceHandle),
  Query(QueryHandle),
}

/// Whether `upd` is a known lifecycle kind that the coalescer collapses to its
/// latest occurrence (vs an unknown future `#[non_exhaustive]` variant, which
/// the bounded backstop in [`push_service_update_coalesced`] handles instead).
///
/// `ServiceUpdate` is `#[non_exhaustive]`, so a variant added upstream falls
/// through to `false` and is bounded by [`MAX_PENDING_SERVICE_UPDATES`] rather
/// than silently coalescing under semantics we can't know yet.
fn is_markable(upd: &ServiceUpdate) -> bool {
  matches!(
    upd,
    ServiceUpdate::Established
      | ServiceUpdate::Renamed(_)
      | ServiceUpdate::Conflict
      | ServiceUpdate::HostConflict
  )
}

/// Hard cap on a service's pending-update deque. Known lifecycle kinds coalesce
/// to ≤4 entries; this only bounds hypothetical future `#[non_exhaustive]`
/// `ServiceUpdate` variants that [`is_markable`] doesn't recognise.
const MAX_PENDING_SERVICE_UPDATES: usize = 16;

/// Maximum consecutive `Service::poll_transmit` errors before the driver gives
/// up on a registered service, surfaces [`ServiceUpdate::Conflict`] to the
/// caller, and marks the service permanently inert (`ServiceCtx::errored`).
/// Mirrors `hick-reactor::driver::MAX_CONSECUTIVE_ENCODE_ERRORS`.
///
/// The threshold is small because `mdns-proto` PRESERVES (does not pop) the
/// pending transmit on encode failure — it re-offers the identical oversized
/// datagram on the next `poll_transmit` — so three failures across consecutive
/// pump passes mean the payload simply cannot be encoded with the configured
/// `max_payload` (e.g. a `ServiceRecords` set whose probe/announce exceeds the
/// scratch buffer). Without escalation that oversized transmit stays
/// head-of-line forever: the service never advances past probing, never reaches
/// `Established`, never emits any `ServiceUpdate`, and the handle waits
/// indefinitely.
pub(crate) const MAX_CONSECUTIVE_ENCODE_ERRORS: u8 = 3;

/// Append `upd` to a service's update deque, coalescing so memory stays
/// bounded under churn while preserving the freshest lifecycle signal:
///
/// * markable kinds (`Established` / `Renamed` / `Conflict` / `HostConflict`)
///   keep only the LATEST update of their kind — drop any prior pending update
///   of the SAME kind (compared by enum discriminant, so a new `Renamed(b)`
///   supersedes a pending `Renamed(a)` and a fresh `Established` supersedes a
///   stale earlier one), then append the new event at the back.
/// * any future non-markable variant — append but stay bounded by dropping the
///   oldest entry past [`MAX_PENDING_SERVICE_UPDATES`] (defensive backstop,
///   unreachable with today's enum).
///
/// Dedup is by KIND, not by position, so a genuinely new event of a kind seen
/// earlier survives: the second `Established` in
/// `Established -> Renamed -> Established` (the §9 conflict-rename re-probe path,
/// `mdns_proto::service`) drops the STALE first `Established`, not the new one —
/// a by-kind-keep-first policy would wrongly discard the post-rename
/// confirmation that the renamed service is now advertised. The deque therefore
/// holds at most one entry per kind (≤ 4) regardless of how much an on-link peer
/// churns conflict-renames. Mirrors the latest-of-kind contract of
/// `hick-reactor::driver`'s service-update coalescing.
fn push_service_update_coalesced(updates: &mut VecDeque<ServiceUpdate>, upd: ServiceUpdate) {
  if is_markable(&upd) {
    // Known lifecycle event: keep only the latest of its kind.
    let kind = core::mem::discriminant(&upd);
    updates.retain(|u| core::mem::discriminant(u) != kind);
    updates.push_back(upd);
  } else {
    // Future non-markable variant: append, bounded by a hard cap (drop oldest
    // to preserve recency) — defensive backstop, unreachable with today's enum.
    if updates.len() >= MAX_PENDING_SERVICE_UPDATES {
      updates.pop_front();
    }
    updates.push_back(upd);
  }
}

/// Driver-side per-service context: the owned proto state machine, a bounded
/// and coalescing update queue, and a cancellation flag. Methods land in T8
/// and the driver loop consumes them in T9.
///
/// `updates` is bounded by coalescing in [`push_service_update_coalesced`]:
/// every known lifecycle kind (`Established` / `Renamed` / `Conflict` /
/// `HostConflict`) keeps only the LATEST entry of its kind (a new one drops the
/// prior of the same kind and re-appends at the back) — so the deque holds at
/// most one of each kind (≤ 4 entries) regardless of churn, with
/// [`MAX_PENDING_SERVICE_UPDATES`] as a hard-cap backstop for any future
/// `#[non_exhaustive]` variant that [`is_markable`] doesn't recognise. Keeping
/// the LATEST (not the first) preserves the post-rename `Established` across an
/// `Established -> Renamed -> Established` sequence. This stops a hostile on-link
/// peer from growing the deque without bound by spamming conflict-bearing
/// packets while the app isn't draining `Service::next`.
pub(crate) struct ServiceCtx {
  pub(crate) proto: ProtoService,
  pub(crate) updates: VecDeque<ServiceUpdate>,
  pub(crate) cancelled: bool,
  /// Count of consecutive `proto.poll_transmit` errors for this service. Reset
  /// to 0 on any `Ok` (a successful encode or an empty queue); incremented on
  /// each `Err`. Once it reaches [`MAX_CONSECUTIVE_ENCODE_ERRORS`] the service
  /// is escalated to [`ServiceUpdate::Conflict`] and marked [`Self::errored`].
  pub(crate) encode_failures: u8,
  /// Terminal "this service is structurally dead" flag. Set once a persistent
  /// encode failure escalated to `Conflict`. Unlike the reactor — which removes
  /// the `ServiceCtx` immediately after emitting `Conflict` because its updates
  /// live in an independently-buffered channel — the compio `ServiceUpdate`s
  /// live INSIDE `ServiceCtx.updates`, which `Service::next` drains directly.
  /// Removing the ctx here would destroy the `Conflict` before the handle could
  /// read it (the exact silent-failure this fix closes), so instead the ctx is
  /// kept but flagged `errored`: every proto-polling pump skips it (so a dead
  /// proto can't be re-polled into a busy-spin) while the already-queued
  /// `Conflict` stays readable. The slot is freed normally when the `Service`
  /// handle is dropped (the `flag_service_unregistered` → sweep path).
  pub(crate) errored: bool,
  /// One-shot "wake a parked `Service::next` for the escalation `Conflict`"
  /// flag. The escalation pushes `Conflict` into `updates` from inside the
  /// transmit pump, which is NOT the wake-bearing path: [`Self::errored`] makes
  /// every later pump skip this ctx, so `push_service_updates` no longer reports
  /// it as needing a wake. Set this once at escalation;
  /// [`State::push_service_updates`] consumes it to fire exactly one `notify`,
  /// so a handle parked on an otherwise-idle endpoint (no other service / query
  /// / goodbye deadline) still gets woken to read the `Conflict`. Cleared after
  /// that single wake so an undrained `Conflict` can't drive a notify busy-spin.
  pub(crate) conflict_wake_pending: bool,
}

/// Driver-side per-query context: last-delivered sequence number and a
/// cancellation flag.
pub(crate) struct QueryCtx {
  pub(crate) last_seq: u64,
  pub(crate) cancelled: bool,
  /// Terminal "this query is structurally dead" flag, set when its question
  /// persistently fails to encode into `max_payload` (the proto preserves the
  /// pending transmit on `Err`, so it would otherwise stay head-of-line
  /// forever). Unlike a service, a query has no `Conflict`-style update to
  /// surface and `QueryUpdate` is `#[non_exhaustive]` (so the driver cannot mint
  /// a terminal variant), so `Query::next` reports end-of-stream (`None`) —
  /// the same signal it already uses for the cancelled-drop path — rather than
  /// parking forever. A query with `QuerySpec` timeout `None` has no
  /// `timeout_deadline` and an un-encodable first send never schedules a
  /// `next_deadline`, so without this flag `poll_deadline` would have nothing to
  /// wake on and `Query::next` would hang indefinitely.
  pub(crate) errored: bool,
  /// One-shot: armed when `errored` is first set, consumed by the run loop to
  /// fire exactly one `notify` so a `Query::next` parked on an otherwise-idle
  /// endpoint wakes to observe the end-of-stream. Cleared after firing so an
  /// undrained terminal can't drive a notify busy-spin (mirrors
  /// `ServiceCtx::conflict_wake_pending`).
  pub(crate) terminal_wake_pending: bool,
}

/// A pending RFC 6762 §10.1 goodbye broadcast queued by service withdrawal.
/// The encoded datagram is self-contained; the proto `Service` is removed
/// immediately so withdrawal proceeds even after the state machine is gone.
pub(crate) struct PendingGoodbye {
  /// Fully encoded TTL=0 datagram (records of the withdrawn service).
  pub(crate) data: Vec<u8>,
  /// Remaining sends; the entry is dropped once this reaches zero.
  pub(crate) remaining: u8,
  /// Earliest wall-clock instant at which the next send may go out.
  pub(crate) next_at: StdInstant,
}

/// All state owned by the compio driver task. Held behind the `RefCell` in
/// `EndpointInner` (T9) — no `Arc` / `Mutex` / atomics: every borrower is on the
/// same `!Send` runtime thread.
pub(crate) struct State {
  pub(crate) endpoint: ProtoEndpoint,
  pub(crate) services: HashMap<ServiceHandle, ServiceCtx>,
  pub(crate) queries: HashMap<QueryHandle, QueryCtx>,
  /// Self-send tracker — `(content_hash, body_len, send_wall_time)` for every
  /// datagram we recently transmitted, used by T16's loopback-self detection.
  pub(crate) recent_sends: crate::selfsend::SelfSends,
  /// TTL=0 goodbye packets resent a few times before being dropped.
  pub(crate) goodbyes: Vec<PendingGoodbye>,
  /// Bound interface index (1-based) used for §11 link-local scoping.
  pub(crate) bound_interface: u32,
  /// Cached local subnets used for the §11 source-address fallback when the
  /// kernel didn't deliver an IPv4 TTL / IPv6 hop-limit cmsg.
  pub(crate) local_subnets: Vec<(core::net::IpAddr, u8)>,
  /// Max datagram size; used to size the scratch buffer for the encode/send
  /// path (T8/T9) and the goodbye-encoding path. Sourced from
  /// [`crate::ServerOptions::max_payload_size`].
  pub(crate) max_payload: usize,
  /// Max inbound-datagram size accepted without truncation. Sourced from
  /// [`crate::ServerOptions::max_recv_packet_size`] (RFC 6762 §17 requires
  /// implementations to accept up to 9000 bytes by default).
  pub(crate) max_recv: usize,
  /// Shared stats handle cloned from the proto endpoint. Present only when
  /// the `stats` Cargo feature is enabled. Stored here so the public
  /// `Endpoint::stats()` accessor can reach it without a command-channel
  /// round-trip.
  #[cfg(feature = "stats")]
  pub(crate) stats: std::sync::Arc<hick_trace::stats::Stats>,
}

impl State {
  /// Build a fresh driver state with no services, queries, or goodbye queue
  /// entries, seeded with an OS-derived [`rand::rngs::StdRng`]. Bound
  /// interface and local-subnet snapshot stay empty until T9 wires them in
  /// from the bound sockets / interface discovery.
  pub(crate) fn new(cfg: EndpointConfig, max_payload: usize, max_recv: usize) -> Self {
    use rand::SeedableRng;
    // rand 0.10 removed `from_entropy`; seed StdRng from the OS-seeded
    // thread RNG (same idiom as `hick-reactor::driver::DriverState::new`).
    let rng = rand::rngs::StdRng::from_rng(&mut rand::rng());
    let endpoint = ProtoEndpoint::try_new(cfg, rng);
    #[cfg(feature = "stats")]
    let stats = endpoint.stats_handle();
    Self {
      endpoint,
      services: HashMap::new(),
      queries: HashMap::new(),
      recent_sends: Vec::new(),
      goodbyes: Vec::new(),
      bound_interface: 0,
      local_subnets: Vec::new(),
      max_payload,
      max_recv,
      #[cfg(feature = "stats")]
      stats,
    }
  }

  /// Register a service spec with the endpoint and create an empty driver-side
  /// context for it. T11 wires the per-service update channel into [`ServiceCtx`].
  pub(crate) fn register_service(
    &mut self,
    spec: mdns_proto::ServiceSpec,
    now: StdInstant,
  ) -> Result<ServiceHandle, mdns_proto::error::RegisterServiceError> {
    let (handle, svc) = self
      .endpoint
      .try_register_service::<slab::Slab<_>, slab::Slab<_>>(spec, now)?;
    self.services.insert(
      handle,
      ServiceCtx {
        proto: svc,
        updates: VecDeque::new(),
        cancelled: false,
        encode_failures: 0,
        errored: false,
        conflict_wake_pending: false,
      },
    );
    Ok(handle)
  }

  /// Start a query against the endpoint and create an empty driver-side context
  /// for it. T13 wires per-query mailboxes / `last_seq` updates.
  pub(crate) fn start_query(
    &mut self,
    spec: mdns_proto::QuerySpec,
    now: StdInstant,
  ) -> Result<QueryHandle, mdns_proto::error::StartQueryError> {
    let h = self.endpoint.try_start_query(spec, now)?;
    self.queries.insert(
      h,
      QueryCtx {
        last_seq: 0,
        cancelled: false,
        errored: false,
        terminal_wake_pending: false,
      },
    );
    Ok(h)
  }

  /// Flag a query as cancelled.  The driver loop (T9) sweeps cancelled
  /// queries on the next poll cycle and calls `endpoint.cancel_query`.
  pub(crate) fn flag_query_cancelled(&mut self, h: QueryHandle) {
    if let Some(q) = self.queries.get_mut(&h) {
      q.cancelled = true;
    }
  }

  /// Flag a service as withdrawn (called from [`Service::drop`]). The actual
  /// proto-state removal + RFC 6762 §10.1 goodbye encoding is deferred to the
  /// driver loop's [`Self::sweep_cancelled_services`], which runs after the
  /// transmit pump so any in-flight send latches first. The `cancelled` flag is
  /// meanwhile honoured by [`Self::poll_one_transmit`] and [`Self::fire_timeouts`]
  /// so a withdrawn service emits no further probes/announces before the sweep.
  pub(crate) fn flag_service_unregistered(&mut self, h: ServiceHandle) {
    if let Some(s) = self.services.get_mut(&h) {
      s.cancelled = true;
    }
  }

  /// Remove a service: encode its RFC 6762 §10.1 goodbye (TTL=0) records
  /// while the proto state is still present, drop the proto state, and
  /// release the endpoint's route slot.
  ///
  /// Mirrors `hick-reactor::driver::DriverState::remove_service` (per-record
  /// goodbye ownership, sibling-host address retention, drained
  /// conflict-rename withdrawal). The encoded datagrams are pushed onto
  /// `self.goodbyes` — the driver loop's goodbye pump fans each one out to
  /// the bound multicast sockets [`GOODBYE_SENDS`] times spaced by
  /// [`GOODBYE_INTERVAL`]. A service that never reached the announced state
  /// yields `None` from `encode_goodbye`, so nothing is queued.
  pub(crate) fn remove_service(&mut self, handle: ServiceHandle, now: StdInstant) {
    let cap = self.max_payload.max(512);

    // Per-address sibling retention: another local service may still own a
    // subset of THIS service's host addresses. Collect each sibling's
    // confirmed-emitted (advertised) addresses; the goodbye encoder
    // withdraws only the addresses this service advertised that no sibling
    // is still keeping in peer caches.
    let retained_host_addrs: Vec<core::net::IpAddr> = if let Some(ctx) = self.services.get(&handle)
    {
      let host = ctx.proto.records().host().clone();
      let mut set: Vec<core::net::IpAddr> = Vec::new();
      for (h, other) in self.services.iter() {
        if *h != handle && other.proto.records().host() == &host {
          set.extend(
            other
              .proto
              .advertised_a_addrs()
              .iter()
              .map(|a| core::net::IpAddr::V4(*a)),
          );
          set.extend(
            other
              .proto
              .advertised_aaaa_addrs()
              .iter()
              .map(|a| core::net::IpAddr::V6(*a)),
          );
        }
      }
      set
    } else {
      Vec::new()
    };

    // Encode withdrawals while proto state is still present. Collect into a
    // local Vec first so the borrow of `self.services` is released before
    // pushing into `self.goodbyes`.
    let mut pending_datagrams: Vec<Vec<u8>> = Vec::new();
    if let Some(ctx) = self.services.get_mut(&handle) {
      let mut buf = vec![0u8; cap];
      if let Ok(Some(len)) = ctx.proto.encode_goodbye(&mut buf, &retained_host_addrs) {
        buf.truncate(len);
        pending_datagrams.push(buf);
      }
      // A conflict-rename may have queued an unsent withdrawal of the OLD
      // instance records inside the proto. Removal drops that proto state,
      // so drain those bytes here too — otherwise the old name lingers in
      // peer caches until TTL expiry.
      let mut rbuf = vec![0u8; cap];
      if let Ok(Some(rlen)) = ctx.proto.take_pending_rename_goodbye(&mut rbuf) {
        rbuf.truncate(rlen);
        pending_datagrams.push(rbuf);
      }
    }
    for data in pending_datagrams {
      self.goodbyes.push(PendingGoodbye {
        data,
        remaining: GOODBYE_SENDS,
        next_at: now,
      });
    }

    self.services.remove(&handle);
    let _ = self.endpoint.unregister_service(handle);
  }

  /// Drive endpoint + per-query timer-based work.  Per-service lifecycle
  /// timers fire via `ctx.proto.handle_timeout` from the driver loop (T9 / T11);
  /// at T8 only the endpoint cache sweep and query timeouts are exposed.
  pub(crate) fn fire_timeouts(&mut self, now: StdInstant) {
    let _ = self.endpoint.handle_timeout(now);
    let handles: Vec<QueryHandle> = self.queries.keys().copied().collect();
    for h in handles {
      // Don't tick a structurally-dead query's proto (see `QueryCtx::errored`).
      if self.queries.get(&h).is_some_and(|c| c.errored) {
        continue;
      }
      let _ = self.endpoint.handle_query_timeout(h, now);
    }
    let svc_handles: Vec<ServiceHandle> = self.services.keys().copied().collect();
    for h in svc_handles {
      if let Some(ctx) = self.services.get_mut(&h) {
        // Don't tick a withdrawn (cancelled) or structurally-dead (errored)
        // service's proto — a dead proto must not be driven (see
        // `ServiceCtx::errored`).
        if !ctx.cancelled && !ctx.errored {
          let _ = ctx.proto.handle_timeout(now);
        }
      }
    }
  }

  /// Remove every service flagged `cancelled` by [`Service::drop`], encoding
  /// each one's RFC 6762 §10.1 goodbye via [`Self::remove_service`]. Returns
  /// `true` if at least one service was swept.
  ///
  /// The driver calls this AFTER the transmit pump, never from `Service::drop`
  /// directly. The ordering is load-bearing: a service whose announce/response
  /// was in flight (mid-`send_to().await`) when its handle dropped only latches
  /// those records as advertised once the send completes and the pump calls
  /// [`Self::note_service_transmit_result`]. Sweeping after the pump guarantees
  /// `remove_service` sees the latched records and includes them in the
  /// goodbye. Encoding the goodbye synchronously in `Drop` — before the await
  /// completed — would miss the just-sent record and leak a positive-TTL entry
  /// into peer caches with no TTL=0 withdrawal (the §10.1 violation this fixes).
  pub(crate) fn sweep_cancelled_services(&mut self, now: StdInstant) -> bool {
    let cancelled: Vec<ServiceHandle> = self
      .services
      .iter()
      .filter(|(_, ctx)| ctx.cancelled)
      .map(|(h, _)| *h)
      .collect();
    let swept = !cancelled.is_empty();
    for h in cancelled {
      self.remove_service(h, now);
    }
    swept
  }

  /// Final withdrawal flush for driver shutdown. Sweeps any still-cancelled
  /// service (encoding its RFC 6762 §10.1 goodbye) and then DRAINS the entire
  /// goodbye queue into a flat list of datagrams — each pending entry expanded
  /// to its `remaining` burst copies — leaving `self.goodbyes` empty.
  ///
  /// The driver calls this on the last-handle-drop path INSTEAD of the normal
  /// timer-spaced goodbye pump. Once every external handle is gone the driver
  /// is about to exit and can't stay alive for the inter-burst
  /// [`GOODBYE_INTERVAL`] spacing, so it flushes all remaining bursts
  /// back-to-back to get the TTL=0 records on the wire before teardown. Without
  /// this, a service whose handle was the last `Rc` would be flagged cancelled
  /// but never swept — the loop's bottom-of-iteration shutdown check would exit
  /// before the next top-of-loop sweep ran — leaking a positive-TTL record into
  /// peer caches with no withdrawal (the §10.1 violation this closes).
  ///
  /// Returns owned datagrams so the caller sends them under no `RefCell` borrow.
  pub(crate) fn take_shutdown_goodbyes(&mut self, now: StdInstant) -> Vec<Vec<u8>> {
    self.sweep_cancelled_services(now);
    let mut out = Vec::new();
    for g in self.goodbyes.drain(..) {
      for _ in 0..g.remaining {
        out.push(g.data.clone());
      }
    }
    out
  }

  /// Drain pending `ServiceUpdate`s out of each per-service proto state machine
  /// into the driver-side `ctx.updates` deque so `Service::next` can pop them.
  /// Returns `true` if at least one update was pushed (so the caller knows to
  /// bump `notify` and wake any parked listener).
  pub(crate) fn push_service_updates(&mut self) -> bool {
    let mut pushed_any = false;
    // Iterate by handle (not `values_mut`) so each iteration can take DISJOINT
    // `&mut` access to `self.endpoint` (for `handle_service_renamed`) and
    // `self.services.get_mut(&h)` — a single `values_mut()` borrow would lock
    // `self.endpoint` out.
    let handles: Vec<ServiceHandle> = self.services.keys().copied().collect();
    for h in handles {
      // A structurally-dead proto (see `ServiceCtx::errored`) is never polled —
      // it can't produce more updates. Its escalation `Conflict` was already
      // queued into `ctx.updates` by the transmit pump and is drained directly
      // by `Service::next`, not through this pump. But the pump IS the
      // wake-bearing path, so consume the one-shot `conflict_wake_pending` here
      // to fire exactly one `notify` for that queued `Conflict` (so a handle
      // parked on an otherwise-idle endpoint still wakes), then skip the proto.
      if self.services.get(&h).is_some_and(|c| c.errored) {
        if let Some(ctx) = self.services.get_mut(&h)
          && ctx.conflict_wake_pending
        {
          ctx.conflict_wake_pending = false;
          pushed_any = true;
        }
        continue;
      }
      // Drain this service's proto events one at a time. A `Renamed` requires
      // routing the endpoint to the new instance name BEFORE the update is
      // surfaced; everything else is queued directly.
      // Each `proto.poll()` returns an owned `Option<ServiceUpdate>` and drops
      // its `&mut` borrow before the body runs, so the body can re-borrow
      // `self.services` / `self.endpoint` freely.
      while let Some(upd) = self.services.get_mut(&h).and_then(|c| c.proto.poll()) {
        // RFC 6762 §9 auto-rename: the proto picked a new instance name after a
        // probe conflict and has already mutated its own records to it. The
        // endpoint's route table still points at the OLD name, so datagrams for
        // the new name (and local rename-collision detection) won't route until
        // we call `handle_service_renamed`. Do it BEFORE surfacing the update,
        // mirroring `hick-reactor::driver`. If the proto rejects the new name
        // (already owned by another local service), the service has already
        // rebranded and can't be kept: surface `Conflict`, flag it errored so
        // every pump skips it, and stop draining it.
        if let ServiceUpdate::Renamed(ref renamed) = upd {
          let new_name = renamed.new_name().clone();
          match self.endpoint.handle_service_renamed(h, new_name) {
            Ok(()) => {}
            Err(_e) => {
              hick_trace::warn!(
                handle = ?h,
                error = ?_e,
                "auto-rename collided with another local service; emitting Conflict and marking errored"
              );
              if let Some(ctx) = self.services.get_mut(&h) {
                push_service_update_coalesced(&mut ctx.updates, ServiceUpdate::Conflict);
                ctx.errored = true;
                ctx.conflict_wake_pending = true;
              }
              pushed_any = true;
              break;
            }
          }
        }
        if let Some(ctx) = self.services.get_mut(&h) {
          push_service_update_coalesced(&mut ctx.updates, upd);
        }
        // Wake on every drained proto update regardless of whether coalescing
        // dropped it, so a parked `Service::next` still re-checks state. This
        // matches the pre-coalescing wake semantics.
        pushed_any = true;
      }
    }
    pushed_any
  }

  /// Extract one outgoing datagram into `scratch`. Returns
  /// `Some((dst, used, origin))` or `None`. Walks services first, then queries.
  /// The driver loop (T9) repeatedly calls this until `None`, sending each
  /// datagram via the matching socket. The `origin` carries the service handle
  /// that produced the datagram so the driver can call `note_transmit_result`
  /// after the send completes — the §8.1 probe sequence and §8.3 announce phase
  /// only advance once each pending datagram is acknowledged.
  pub(crate) fn poll_one_transmit(
    &mut self,
    now: StdInstant,
    scratch: &mut [u8],
  ) -> Option<(core::net::SocketAddr, usize, TransmitOrigin)> {
    let svc_handles: Vec<ServiceHandle> = self.services.keys().copied().collect();
    for h in svc_handles {
      let Some(ctx) = self.services.get_mut(&h) else {
        continue;
      };
      // Skip a cancelled (withdrawn, awaiting sweep) or errored (structurally
      // dead, see `ServiceCtx::errored`) service so neither is re-polled into a
      // busy-spin.
      if ctx.cancelled || ctx.errored {
        continue;
      }
      // distinguish `Ok(None)` ("nothing pending") from `Err`
      // ("can't encode the pending transmit"). `mdns-proto` PRESERVES the
      // pending transmit on encode failure, re-offering the identical oversized
      // datagram every call, so treating `Err` like `Ok(None)` (the prior
      // `if let Ok(Some(_))` bug) leaves it head-of-line forever and the service
      // silently stalls below `Established`. Count consecutive failures and
      // escalate to `ServiceUpdate::Conflict` once they cross the threshold.
      match ctx.proto.poll_transmit(now, scratch) {
        Ok(Some(t)) => {
          ctx.encode_failures = 0;
          return Some((t.dst(), t.size(), TransmitOrigin::Service(h)));
        }
        Ok(None) => {
          ctx.encode_failures = 0;
          // Nothing pending for this service — fall through to the next one.
        }
        Err(_e) => {
          ctx.encode_failures = ctx.encode_failures.saturating_add(1);
          if ctx.encode_failures >= MAX_CONSECUTIVE_ENCODE_ERRORS {
            // Persistent encode failure: the records can't fit `max_payload`.
            // Push `Conflict` into the in-ctx update deque (the handle drains it
            // directly via `Service::next`), flag the service `errored` so every
            // proto-polling pump skips it from here on, and arm the one-shot
            // `conflict_wake_pending` so the next `push_service_updates` fires a
            // single wake for the queued `Conflict`. Do NOT remove the ctx —
            // that would destroy the `Conflict` before the handle reads it. The
            // slot is freed normally when the `Service` handle drops.
            hick_trace::warn!(
              handle = ?h,
              error = ?_e,
              scratch_size = scratch.len(),
              consecutive_failures = ctx.encode_failures,
              "Service::poll_transmit failed; escalating to Conflict and marking the service errored"
            );
            push_service_update_coalesced(&mut ctx.updates, ServiceUpdate::Conflict);
            ctx.errored = true;
            ctx.conflict_wake_pending = true;
          }
          // Whether or not we escalated, do NOT return the un-encodable
          // transmit as a phantom send — fall through to the next service.
        }
      }
    }
    let q_handles: Vec<QueryHandle> = self.queries.keys().copied().collect();
    for h in q_handles {
      let Some(ctx) = self.queries.get_mut(&h) else {
        continue;
      };
      // Skip a cancelled (handle dropped) or errored (structurally dead, see
      // `QueryCtx::errored`) query so neither is re-polled into a busy-spin.
      if ctx.cancelled || ctx.errored {
        continue;
      }
      match self.endpoint.poll_query_transmit(h, now, scratch) {
        // A datagram is ready — hand it to the driver to send.
        Ok(Some(t)) => return Some((t.dst(), t.size(), TransmitOrigin::Query(h))),
        // Nothing due right now — try the next query.
        Ok(None) => {}
        // The question can't be encoded into `scratch` (e.g. `max_payload`
        // smaller than a DNS header + question). The proto PRESERVES the pending
        // transmit on `Err`, so it would be re-offered forever and the query
        // would never make progress. Crucially a `QuerySpec` with the default
        // `timeout` of `None` has no `timeout_deadline`, and an un-encodable
        // first send never schedules a `next_deadline`, so `poll_deadline` would
        // have nothing to wake on and a parked `Query::next` would hang
        // indefinitely. Mark the query errored so every proto-polling
        // pump skips it and `Query::next` surfaces end-of-stream (`None`) — we
        // can't mint a `QueryUpdate` terminal (the enum is `#[non_exhaustive]`),
        // and `None` is the same end signal the cancelled-drop path already uses.
        Err(_e) => {
          if let Some(ctx) = self.queries.get_mut(&h) {
            // Arm the one-shot terminal wake only on the transition into
            // `errored` (not on every re-poll, which can't happen anyway since
            // errored queries are skipped above — but guard it for clarity).
            if !ctx.errored {
              ctx.errored = true;
              ctx.terminal_wake_pending = true;
            }
          }
          hick_trace::warn!(
            handle = ?h,
            error = ?_e,
            scratch_size = scratch.len(),
            "Query::poll_query_transmit failed to encode; marking the query errored (Query::next will report end-of-stream)"
          );
        }
      }
    }
    None
  }

  /// Confirm a previously polled service transmit. Called by the driver loop
  /// after `send_to` returns, so the per-service state machine can advance the
  /// §8.1 probe sequence and §8.3 announce phase (which require the post-send
  /// `delivered` flag to clear `awaiting_confirm`). For query transmits the
  /// proto layer holds no equivalent commit token, so this is a no-op there.
  pub(crate) fn note_service_transmit_result(
    &mut self,
    h: ServiceHandle,
    now: StdInstant,
    delivered: bool,
  ) {
    if let Some(ctx) = self.services.get_mut(&h) {
      ctx.proto.note_transmit_result(now, delivered);
    }
  }

  /// Confirm a previously polled query transmit so the proto layer advances
  /// its §5.2 backoff and retry budget only on a confirmed-delivered send.
  /// Mirrors [`Self::note_service_transmit_result`] for the query side; called
  /// by the driver loop after `send_to` returns.
  pub(crate) fn note_query_transmit_result(
    &mut self,
    h: QueryHandle,
    now: StdInstant,
    delivered: bool,
  ) {
    self.endpoint.note_query_transmit_result(h, now, delivered);
  }

  /// Whether any service is flagged cancelled but not yet swept by
  /// [`Self::sweep_cancelled_services`]. The driver uses this to force an
  /// immediate (zero-duration) timer instead of parking. `Service::drop` flags
  /// the service and calls `notify()`, but the shared `LocalNotify` wake is lost
  /// when it lands while the driver is mid-`send_to` await with no listener
  /// armed, so the wake alone cannot be relied on to run the withdrawal sweep
  /// and its §10.1 goodbye — the forced timer is what guarantees it.
  pub(crate) fn has_pending_withdrawal(&self) -> bool {
    self.services.values().any(|ctx| ctx.cancelled)
  }

  /// Consume every armed [`QueryCtx::terminal_wake_pending`], returning `true`
  /// if at least one fired. The run loop calls this after the pumps: a query
  /// that just transitioned to `errored` (un-encodable question, see
  /// [`QueryCtx::errored`]) has no standing deadline, so the driver fires one
  /// `notify` here to wake a parked `Query::next` to observe end-of-stream. The
  /// flag is one-shot (cleared on consume) so an undrained terminal can't drive
  /// a notify busy-spin.
  pub(crate) fn take_query_terminal_wakes(&mut self) -> bool {
    let mut woke = false;
    for ctx in self.queries.values_mut() {
      if ctx.terminal_wake_pending {
        ctx.terminal_wake_pending = false;
        woke = true;
      }
    }
    woke
  }

  /// Earliest deadline across the endpoint, services, queries, and the
  /// pending-goodbye resend queue.
  pub(crate) fn poll_deadline(&self) -> Option<StdInstant> {
    let mut best = self.endpoint.poll_timeout();
    for ctx in self.services.values() {
      // A structurally-dead service (see `ServiceCtx::errored`) must not
      // contribute a deadline — otherwise its proto could report an immediate
      // (or no) timeout that pins the driver awake despite never being polled.
      if ctx.errored {
        continue;
      }
      if let Some(t) = ctx.proto.poll_timeout() {
        best = Some(best.map_or(t, |b| b.min(t)));
      }
    }
    for (h, ctx) in &self.queries {
      // A structurally-dead query (see `QueryCtx::errored`) must not contribute
      // a deadline — it is never polled again, and contributing an immediate/no
      // deadline would busy-spin (unlike a cancelled service it is not swept, so
      // it persists until its handle drops). Its end-of-stream terminal is
      // delivered to `Query::next` via a one-shot wake (`terminal_wake_pending`)
      // drained in the run loop, not via a standing deadline.
      if ctx.errored {
        continue;
      }
      if let Some(t) = self.endpoint.poll_query_timeout(*h) {
        best = Some(best.map_or(t, |b| b.min(t)));
      }
    }
    // Wake to resend any pending TTL=0 goodbye when it comes due so the
    // §10.1 burst completes even between recv / timer events.
    for g in &self.goodbyes {
      best = Some(best.map_or(g.next_at, |b| b.min(g.next_at)));
    }
    best
  }

  /// Apply §11 + self-send + `proto.handle` for one received datagram.
  ///
  /// The §11 on-link gate lives in [`crate::onlink`] and the FNV-1a self-send
  /// tracker (take-once classification with [`crate::selfsend::MatchMode`])
  /// lives in [`crate::selfsend`].
  pub(crate) fn handle_datagram(&mut self, meta: &crate::socket::RecvMeta, data: &[u8]) {
    // §11 on-link gate.  When the kernel delivered a TTL / hop-limit we trust
    // it (must be 255); otherwise we fall back to a source-address heuristic
    // anchored by the cached local-subnet snapshot.
    let on_link = if meta.hop_limit().is_some() {
      crate::onlink::is_on_link(meta.hop_limit())
    } else {
      crate::onlink::src_on_local_link(
        &self.local_subnets,
        self.bound_interface,
        meta.interface_index(),
        meta.peer().ip(),
      )
    };
    if !on_link {
      hick_trace::debug!(
        src = %meta.peer(),
        hop_limit = ?meta.hop_limit(),
        "dropping off-link packet (RFC 6762 §11 trust boundary)"
      );
      #[cfg(feature = "stats")]
      self.stats.packets_dropped(1);
      return;
    }

    // §11 source-port gate for responses before consuming a self-send credit.
    // A response (QR=1) from a non-5353 source can't be a legitimate mDNS
    // response (legacy queriers may use ephemeral ports for queries, not for
    // responses).  `endpoint.handle` enforces this again internally, but we
    // bail early so an off-path datagram never consumes a self-send credit.
    if data.get(2).is_some_and(|b| b & 0x80 != 0)
      && meta.peer().port() != hick_udp::constants::MDNS_PORT
    {
      hick_trace::debug!(
        src = %meta.peer(),
        "dropping untrusted response (source port != 5353) before self-send match"
      );
      #[cfg(feature = "stats")]
      self.stats.packets_dropped(1);
      return;
    }

    // Self-send classification (FNV-1a content-hash, take-once).
    let caller_is_self = match meta.kernel_rx_time() {
      Some(rx) => crate::selfsend::take_self_send(
        &mut self.recent_sends,
        data,
        rx,
        crate::selfsend::MatchMode::Ordered,
      ),
      None => crate::selfsend::take_self_send(
        &mut self.recent_sends,
        data,
        SystemTime::now(),
        crate::selfsend::MatchMode::Degraded,
      ),
    };

    // Use a process-monotonic `now` for proto scheduling; the SystemTime
    // reference above is what classified the self-send credit.
    let now = StdInstant::now();

    // Split-borrow: endpoint and services are disjoint fields, but
    // `endpoint.handle` borrows `self.endpoint` mutably while the route-event
    // iterator is alive, so the per-service `handle_event` calls can only read
    // from `services` through a second mutable borrow — keep them disjoint.
    let Self {
      endpoint, services, ..
    } = self;

    let route_events = match endpoint.handle(
      now,
      meta.peer(),
      meta.local_ip(),
      meta.interface_index(),
      data,
      caller_is_self,
    ) {
      Ok(it) => it,
      Err(_) => return,
    };

    for ev in route_events {
      match ev {
        Ok(mdns_proto::event::RouteEvent::ToService(ts)) => {
          if let Some(ctx) = services.get_mut(&ts.handle()) {
            ctx.proto.handle_event(ts.into_event(), now);
          }
        }
        // `ToQuery` answers are applied inside `endpoint.handle`;
        // `CacheUpdated` is a hint for future cache subscribers. Any
        // additional `RouteEvent` variants are ignored until wired by
        // T11/T13.
        Ok(_) => {}
        Err(_) => break,
      }
    }
  }
}

use core::cell::RefCell;

use crate::socket::{RecvMeta, Socket};

/// Shared driver-owned state held inside the `Endpoint`/`Service`/`Query`
/// handles **and** the spawned driver task. The handle clones bump
/// `Rc::strong_count`; the driver task uses `Rc::strong_count(&inner) == 1`
/// as the "last external handle dropped" signal to exit (see [`run`]).
pub(crate) struct EndpointInner {
  pub(crate) state: RefCell<State>,
  pub(crate) notify: LocalNotify,
  /// Level-triggered "the driver has unserviced handle work" flag — the
  /// driver-liveness invariant's single source of truth.
  ///
  /// WHY THIS EXISTS (do not replace it with bare `notify()`): the driver runs
  /// an event loop that registers its `notify` listener only while parked in
  /// `select!`. It spends most of each iteration `.await`ing socket sends, where
  /// NO listener is armed. `event_listener::Event::notify()` does not latch — a
  /// wake delivered with no listener registered is silently dropped. So a handle
  /// op (`start_query`, `register_service`, a drop) that lands during a send is
  /// invisible to the driver, which then parks: if that work contributed no
  /// timer deadline (e.g. a timeout-less query), it parks FOREVER.
  ///
  /// `dirty` makes handle work durable across that window. Every handle op that
  /// creates driver-actionable work calls [`Self::mark_dirty`], which sets this
  /// AND notifies. The driver clears it at the top of each iteration before
  /// pumping and forces an immediate re-settle (zero-duration timer) when it was
  /// set — so the lost `notify` becomes a latency optimisation, never the sole
  /// liveness guarantee. Work created during the pump re-sets `dirty` (caught
  /// next iteration); work created during the park is caught by the listener.
  ///
  /// This replaces the previously-enumerated `force_now` cases
  /// (`has_pending_withdrawal`, transmit-budget exhaustion, …) with one general
  /// invariant — closing the lost-wake class for all current and future handle
  /// operations by construction.
  pub(crate) dirty: core::cell::Cell<bool>,
}

impl EndpointInner {
  /// Build a fresh inner with empty proto state and a paired [`LocalNotify`].
  /// Returned as `Rc<Self>` so the handle layer (T10+) can clone it without
  /// re-wrapping. `dirty` starts `false`: no handle work exists until a handle
  /// op runs.
  pub(crate) fn new(cfg: EndpointConfig, max_payload: usize, max_recv: usize) -> Rc<Self> {
    Rc::new(Self {
      state: RefCell::new(State::new(cfg, max_payload, max_recv)),
      notify: LocalNotify::new(),
      dirty: core::cell::Cell::new(false),
    })
  }

  /// Mark the driver dirty and wake it. EVERY handle operation that creates
  /// driver-actionable work (start/register/cancel/withdraw) must call this
  /// rather than `notify()` directly: the `notify` alone can be lost across the
  /// driver's send-awaits (see [`Self::dirty`]); the flag is what guarantees the
  /// work is observed. The notify is the latency optimisation layered on top.
  #[inline]
  pub(crate) fn mark_dirty(&self) {
    self.dirty.set(true);
    self.notify.notify();
  }
}

/// Spawned driver future. Owns the compio sockets and runs until the last
/// external [`Endpoint`] / [`Service`] / [`Query`] clone is dropped — detected
/// by `Rc::strong_count(&inner) == 1`, meaning only this future's own Rc
/// remains.
///
/// Borrow discipline: every interaction with `inner.state` happens inside a
/// short `borrow()` / `borrow_mut()` scope that is dropped **before** any
/// `.await`. The only `.await` points are `send_to`, `Socket::recv`,
/// `compio::time::sleep`, and `LocalNotify::listen` — none of which run inside
/// an open borrow.
pub(crate) async fn run(
  inner: Rc<EndpointInner>,
  sock_v4: Option<Rc<Socket>>,
  sock_v6: Option<Rc<Socket>>,
) {
  use futures::{FutureExt, future::Either};

  // Scratch buffer reused across transmit-pump iterations. Sized from the
  // caller-configured [`crate::ServerOptions::max_payload_size`] (default
  // 1500, the Ethernet path MTU recommended by RFC 6762 §17 for outbound
  // datagrams); the driver only writes the actual encoded length each pass.
  //
  // The recv buffer is sized from
  // [`crate::ServerOptions::max_recv_packet_size`] (default 9000, the
  // ceiling RFC 6762 §17 requires receivers to accept without truncation).
  // Both are read off `state` once at startup — they are immutable for the
  // lifetime of the driver.
  let (mut scratch, max_recv) = {
    let s = inner.state.borrow();
    (vec![0u8; s.max_payload], s.max_recv)
  };

  loop {
    // 1. extract-then-await transmit pump.  Borrow only long enough to pull
    //    one datagram into `scratch`; drop the borrow before awaiting the
    //    socket send.  The self-send record runs inside a second short
    //    borrow after the send completes.
    //
    //    Bounded by [`MAX_TRANSMIT_CREDITS_PER_PASS`] (mirrors the reactor's
    //    `MAX_SEND_CREDITS_PER_DRAIN`): when `poll_one_transmit` yields a
    //    transmit for an address family WE never bound (e.g. v6 transmit
    //    requested but only v4 socket present), `note_*_transmit_result`
    //    is called with `delivered = false`, which re-arms the same transmit
    //    rather than advancing lifecycle. Without a cap proto could keep
    //    re-yielding it; the cap forces the loop to yield control to the
    //    select! so timers / recv can make progress, and the deadline-driven
    //    re-entry will retry.
    let mut credits = MAX_TRANSMIT_CREDITS_PER_PASS;
    loop {
      if credits == 0 {
        break;
      }
      credits -= 1;
      let pumped = {
        let mut s = inner.state.borrow_mut();
        let now = StdInstant::now();
        s.poll_one_transmit(now, &mut scratch)
      };
      let Some((dst, n, origin)) = pumped else {
        break;
      };
      // `mdns-proto` always hands back the IPv4 multicast group for BOTH the
      // v4 and v6 service groups (multicast_dst()), so we cannot route
      // multicast by the destination's address family. Detect an mDNS
      // multicast destination and fan the SAME body out to every bound
      // family's multicast group (RFC 6762 §6); a dual-stack endpoint then
      // reaches both `224.0.0.251` and `ff02::fb`, and a v6-only endpoint
      // actually transmits (instead of routing to an absent v4 socket and
      // marking the send undelivered).
      //
      // Self-send credit: record ONE tracker entry per ACTUAL successful
      // send. Take-once self-suppression consumes a single entry per matching
      // loopback, and dual-stack fan-out yields TWO loopback copies (one per
      // joined socket), so a successful v4+v6 send records two entries.
      //
      // Timestamp: capture `when` IMMEDIATELY BEFORE each `.await`. compio is
      // completion-based — the buffer moves into the op on `.await`, so we
      // can't stamp "at the syscall" the way the readiness-I/O reactor does
      // inside `poll_send_to`. Stamping before the await guarantees
      // `when <= kernel_send_time <= echo_rx_time`, keeping our own loopback
      // inside the 1 ms Ordered match window even when task-resume latency is
      // high. (Stamping AFTER the await — the previous bug — could push the
      // recorded time past the kernel's rx stamp and misclassify our own
      // announce/probe as a peer packet.)
      let delivered = if is_mdns_multicast_dst(dst) {
        let mut sent_any = false;
        if let Some(s4) = sock_v4.as_ref() {
          let when = SystemTime::now();
          let res = s4.send_to(&scratch[..n], MDNS_V4_DST, None).await;
          if res.is_ok() {
            hick_trace::trace!(dst = %MDNS_V4_DST, len = n, "send_to v4");
            let mut state = inner.state.borrow_mut();
            crate::selfsend::record_self_send(&mut state.recent_sends, &scratch[..n], when);
            #[cfg(feature = "stats")]
            {
              state.stats.packets_tx(1);
              state.stats.bytes_tx(n as u64);
            }
            sent_any = true;
          } else {
            hick_trace::debug!(dst = %MDNS_V4_DST, "send_to v4 failed");
            #[cfg(feature = "stats")]
            inner.state.borrow().stats.send_errors(1);
          }
        }
        if let Some(s6) = sock_v6.as_ref() {
          let when = SystemTime::now();
          let res = s6.send_to(&scratch[..n], MDNS_V6_DST, None).await;
          if res.is_ok() {
            hick_trace::trace!(dst = %MDNS_V6_DST, len = n, "send_to v6");
            let mut state = inner.state.borrow_mut();
            crate::selfsend::record_self_send(&mut state.recent_sends, &scratch[..n], when);
            #[cfg(feature = "stats")]
            {
              state.stats.packets_tx(1);
              state.stats.bytes_tx(n as u64);
            }
            sent_any = true;
          } else {
            hick_trace::debug!(dst = %MDNS_V6_DST, "send_to v6 failed");
            #[cfg(feature = "stats")]
            inner.state.borrow().stats.send_errors(1);
          }
        }
        // `delivered` ⇔ at least one family reached the wire.
        sent_any
      } else {
        // Unicast: pick the socket matching the destination family, single
        // send. No socket for this family → count as failed delivery so the
        // proto re-arms the probe / announce without advancing lifecycle
        // state (unchanged semantics).
        let sock = match dst {
          core::net::SocketAddr::V4(_) => sock_v4.as_ref(),
          core::net::SocketAddr::V6(_) => sock_v6.as_ref(),
        };
        if let Some(s) = sock {
          let when = SystemTime::now();
          let res = s.send_to(&scratch[..n], dst, None).await;
          // Record the self-send credit under a fresh short borrow so the next
          // inbound copy of this datagram (from the loopback / multicast echo)
          // is classified as our own.  Only record on a successful send.
          if res.is_ok() {
            hick_trace::trace!(dst = %dst, len = n, "send_to");
            let mut state = inner.state.borrow_mut();
            crate::selfsend::record_self_send(&mut state.recent_sends, &scratch[..n], when);
            #[cfg(feature = "stats")]
            {
              state.stats.packets_tx(1);
              state.stats.bytes_tx(n as u64);
            }
          } else {
            hick_trace::debug!(dst = %dst, "send_to failed");
            #[cfg(feature = "stats")]
            inner.state.borrow().stats.send_errors(1);
          }
          res.is_ok()
        } else {
          false
        }
      };
      // Confirm the pending transmit so the §8.1 probe sequence / §8.3 announce
      // phase advance (services), or so the §5.2 backoff + retry budget
      // advance only on a confirmed-delivered send (queries).  Anchored to
      // post-send time so the next deadline is relative to actual on-wire send.
      match origin {
        TransmitOrigin::Service(h) => {
          let mut state = inner.state.borrow_mut();
          state.note_service_transmit_result(h, StdInstant::now(), delivered);
        }
        TransmitOrigin::Query(h) => {
          let mut state = inner.state.borrow_mut();
          state.note_query_transmit_result(h, StdInstant::now(), delivered);
        }
      }
    }
    // Exhausted the per-pass send budget — more transmits may be ready, so the
    // driver must re-enter the pump rather than park until an unrelated event.
    //
    // Do NOT use `inner.notify.notify()` for this same-task re-entry: it is sent
    // HERE, before the loop arms its next `notify_fut`, and `event-listener`
    // does not latch a notification when no listener is active — so the wake
    // would be lost and the 65th+ ready transmit could stall until an unrelated
    // recv/timer/handle wake. Instead carry an explicit flag into the
    // pre-park timer decision below, which forces a zero-duration timer (the
    // same lost-wake-proof mechanism used for pending withdrawals).
    //
    // This cannot busy-spin now that multicast transmits reach a bound socket:
    // each successful send drives `note_*_transmit_result(delivered = true)`, so
    // the proto advances (§8.1 probe / §8.3 announce) and the queue drains.
    let pump_budget_exhausted = credits == 0;

    // 1a-pre. Sweep services whose handle was dropped. `Service::drop` only
    //     flags `cancelled`; the proto-state removal + §10.1 goodbye encoding
    //     happens HERE, after the transmit pump, so a send that was in flight
    //     when the handle dropped has already latched its records via
    //     `note_service_transmit_result` and is therefore captured in the
    //     goodbye. The freshly-queued goodbyes are sent by the 1a pump below in
    //     this same iteration (their `next_at` is `now`).
    {
      let now = StdInstant::now();
      inner.state.borrow_mut().sweep_cancelled_services(now);
    }

    // 1a. RFC 6762 §10.1 goodbye-burst pump. `sweep_cancelled_services` (and a
    //     conflict-rename withdrawal) encode the TTL=0 records and push them
    //     onto `state.goodbyes`; this loop fans each due entry out to BOTH
    //     multicast families' sockets [`GOODBYE_SENDS`] times, spaced by
    //     [`GOODBYE_INTERVAL`]. The borrow discipline matches the main pump:
    //     snapshot the bytes under a brief borrow, send under no borrow, and
    //     update remaining/next_at under another short borrow.
    loop {
      let now = StdInstant::now();
      let due_entry: Option<(usize, Vec<u8>)> = {
        let s = inner.state.borrow();
        s.goodbyes
          .iter()
          .enumerate()
          .find(|(_, g)| g.remaining > 0 && g.next_at <= now)
          .map(|(i, g)| (i, g.data.clone()))
      };
      let Some((idx, data)) = due_entry else {
        break;
      };
      // Fan out to every bound family on the mDNS multicast group.
      // Capture `when` BEFORE each `.await` (completion-I/O equivalent of
      // stamping at the syscall) so `when <= kernel_send_time <=
      // echo_rx_time` and the kernel-looped goodbye stays inside the 1 ms
      // Ordered self-send match window.
      let mut sent_any = false;
      if let Some(s4) = sock_v4.as_ref() {
        let when = SystemTime::now();
        let res = s4.send_to(&data, MDNS_V4_DST, None).await;
        if res.is_ok() {
          hick_trace::trace!(dst = %MDNS_V4_DST, len = data.len(), "goodbye send_to v4");
          let mut state = inner.state.borrow_mut();
          crate::selfsend::record_self_send(&mut state.recent_sends, &data, when);
          #[cfg(feature = "stats")]
          {
            state.stats.packets_tx(1);
            state.stats.bytes_tx(data.len() as u64);
          }
          sent_any = true;
        } else {
          hick_trace::debug!(dst = %MDNS_V4_DST, "goodbye send_to v4 failed");
          #[cfg(feature = "stats")]
          inner.state.borrow().stats.send_errors(1);
        }
      }
      if let Some(s6) = sock_v6.as_ref() {
        let when = SystemTime::now();
        let res = s6.send_to(&data, MDNS_V6_DST, None).await;
        if res.is_ok() {
          hick_trace::trace!(dst = %MDNS_V6_DST, len = data.len(), "goodbye send_to v6");
          let mut state = inner.state.borrow_mut();
          crate::selfsend::record_self_send(&mut state.recent_sends, &data, when);
          #[cfg(feature = "stats")]
          {
            state.stats.packets_tx(1);
            state.stats.bytes_tx(data.len() as u64);
          }
          sent_any = true;
        } else {
          hick_trace::debug!(dst = %MDNS_V6_DST, "goodbye send_to v6 failed");
          #[cfg(feature = "stats")]
          inner.state.borrow().stats.send_errors(1);
        }
      }
      let _ = sent_any; // Failure-to-send logged above.
      // Decrement remaining and re-arm next_at regardless of send outcome —
      // an entry that can't reach the wire still drains its budget so it
      // doesn't pin the goodbye queue forever.
      {
        let mut state = inner.state.borrow_mut();
        if let Some(g) = state.goodbyes.get_mut(idx) {
          g.remaining = g.remaining.saturating_sub(1);
          g.next_at = now + GOODBYE_INTERVAL;
        }
      }
    }
    // GC fully drained goodbye entries.
    {
      let mut state = inner.state.borrow_mut();
      state.goodbyes.retain(|g| g.remaining > 0);
    }

    // 1b. drain pending `ServiceUpdate`s out of each per-service proto state
    //     machine and into the driver-side `ctx.updates` deque so listeners
    //     parked on `Service::next` can pop them.  The borrow is brief and is
    //     dropped before any `.await`.
    {
      let pushed = inner.state.borrow_mut().push_service_updates();
      if pushed {
        inner.notify.notify();
      }
    }

    // 1b'. fire one-shot wakes for queries that just transitioned to `errored`
    //      (un-encodable question, see `QueryCtx::errored`). Such a query has no
    //      standing deadline, so this is the only wake that gets a parked
    //      `Query::next` to observe its end-of-stream terminal.
    {
      let woke = inner.state.borrow_mut().take_query_terminal_wakes();
      if woke {
        inner.notify.notify();
      }
    }

    // 1c. SHUTDOWN SETTLE (pre-park). All pending work for this iteration is now
    //     drained (transmits, goodbye burst, cancellation sweep, updates). If no
    //     external handle remains, exit — but FIRST flush every queued §10.1
    //     goodbye so a withdrawal is never lost at teardown.
    //
    //     This check lives HERE, before arming `select!`, not after the park.
    //     `Service::drop` / `Query::drop` only flag + `notify()`, and the shared
    //     `LocalNotify` wake is LOST if it lands while the driver is mid-`send_to`
    //     await with no listener armed. A bottom-of-loop, post-park shutdown
    //     check therefore raced last-handle drops: the loop could park forever
    //     (task + sockets leaked) or defer the goodbye to some unrelated later
    //     wake. Settling pre-park makes the last-handle exit deterministic and
    //     independent of whether that notify was delivered.
    if Rc::strong_count(&inner) == 1 {
      let datagrams = {
        let now = StdInstant::now();
        inner.state.borrow_mut().take_shutdown_goodbyes(now)
      };
      for data in datagrams {
        if let Some(s4) = sock_v4.as_ref() {
          let _ = s4.send_to(&data, MDNS_V4_DST, None).await;
        }
        if let Some(s6) = sock_v6.as_ref() {
          let _ = s6.send_to(&data, MDNS_V6_DST, None).await;
        }
      }
      break;
    }

    // 2. compute the next deadline, and decide whether to re-settle IMMEDIATELY
    //    (zero-duration timer) instead of parking. `force_now` is the
    //    driver-liveness guard, and both its sources are lost-wake-proof because
    //    they go through the TIMER, not `LocalNotify`:
    //
    //    * `dirty` — a handle op created work that hasn't been serviced. CRUCIAL:
    //      this is consumed HERE, at the pre-park boundary, AFTER every awaitable
    //      pump above — NOT at loop entry. A handle's `mark_dirty` can land during
    //      a LATE pump await (e.g. the §10.1 goodbye `send_to().await`), after a
    //      loop-entry sample would already have been taken; reading `dirty` here
    //      catches that. Everything from this `replace(false)` to arming the
    //      `select!` listener below is synchronous (no `.await`), so a `dirty` set
    //      before this read forces an immediate re-settle, and one set after is
    //      caught by the now-armed listener — no gap. This single level signal
    //      subsumes the previously-enumerated cases (pending withdrawal,
    //      newly-started timeout-less query, …): every work-creating handle op
    //      marks the endpoint dirty (see `EndpointInner::mark_dirty`), closing the
    //      "handle parks forever" lost-wake class by construction.
    //    * `pump_budget_exhausted` — the transmit pump hit its per-pass credit
    //      cap with work still queued; re-enter to drain the backlog.
    let deadline = { inner.state.borrow().poll_deadline() };
    let force_now = inner.dirty.replace(false) || pump_budget_exhausted;

    // 3. arm the timer future. `Either<sleep, pending>` keeps both arms with
    //    the same `Output = ()` so a single `pin_mut!` is enough for
    //    `select!` to accept either branch via the fused wrapper.
    let timer_fut = match (force_now, deadline) {
      (true, _) => Either::Left(compio::time::sleep(Duration::ZERO)),
      (false, Some(at)) => {
        let dur = at.saturating_duration_since(StdInstant::now());
        Either::Left(compio::time::sleep(dur))
      }
      (false, None) => Either::Right(core::future::pending::<()>()),
    }
    .fuse();
    futures::pin_mut!(timer_fut);

    // 4. arm the notify future. `LocalNotify::listen` is awaitable directly;
    //    fuse it so `select!` accepts it.
    let notify_fut = inner.notify.listen().fuse();
    futures::pin_mut!(notify_fut);

    // 5. arm one recv future per bound family. The recv future borrows from
    //    its socket and owns its data + control buffers across the
    //    completion; if `select!` picks another arm the recv future is
    //    dropped, taking the in-flight buffers with it.
    //
    // After a timer or recv arm fires the driver's own listener is consumed,
    // but user-side handles (`Service::next`, `Query::next`) may still be
    // parked on `inner.notify.listen()` — they need a wake to re-check the
    // proto state.  Bump notify whenever timer/recv may have advanced state.
    let mut woke_state = false;
    match (sock_v4.as_ref(), sock_v6.as_ref()) {
      (Some(s4), Some(s6)) => {
        let r4 = s4.recv(max_recv).fuse();
        let r6 = s6.recv(max_recv).fuse();
        futures::pin_mut!(r4, r6);
        futures::select! {
          r = r4 => { handle_recv(&inner, r); woke_state = true; }
          r = r6 => { handle_recv(&inner, r); woke_state = true; }
          _ = timer_fut => { inner.state.borrow_mut().fire_timeouts(StdInstant::now()); woke_state = true; }
          _ = notify_fut => {}
        }
      }
      (Some(s4), None) => {
        let r4 = s4.recv(max_recv).fuse();
        futures::pin_mut!(r4);
        futures::select! {
          r = r4 => { handle_recv(&inner, r); woke_state = true; }
          _ = timer_fut => { inner.state.borrow_mut().fire_timeouts(StdInstant::now()); woke_state = true; }
          _ = notify_fut => {}
        }
      }
      (None, Some(s6)) => {
        let r6 = s6.recv(max_recv).fuse();
        futures::pin_mut!(r6);
        futures::select! {
          r = r6 => { handle_recv(&inner, r); woke_state = true; }
          _ = timer_fut => { inner.state.borrow_mut().fire_timeouts(StdInstant::now()); woke_state = true; }
          _ = notify_fut => {}
        }
      }
      (None, None) => {
        // No sockets — just wait on timer/notify so the driver doesn't
        // busy-spin.
        futures::select! {
          _ = timer_fut => { inner.state.borrow_mut().fire_timeouts(StdInstant::now()); woke_state = true; }
          _ = notify_fut => {}
        }
      }
    }
    if woke_state {
      inner.notify.notify();
    }
  }
}

#[inline]
fn handle_recv(inner: &Rc<EndpointInner>, r: std::io::Result<(Vec<u8>, RecvMeta)>) {
  match r {
    Ok((data, meta)) => {
      hick_trace::trace!(src = %meta.peer(), len = data.len(), "recv datagram");
      #[cfg(feature = "stats")]
      {
        let s = inner.state.borrow();
        s.stats.packets_rx(1);
        s.stats.bytes_rx(data.len() as u64);
      }
      let mut s = inner.state.borrow_mut();
      s.handle_datagram(&meta, &data);
    }
    Err(_e) => {
      hick_trace::debug!(error = %_e, "socket recv failed; dropping datagram");
      #[cfg(feature = "stats")]
      inner.state.borrow().stats.packets_dropped(1);
    }
  }
}

#[cfg(test)]
mod tests {
  use core::cell::Cell;
  use std::rc::Rc;

  use super::*;

  #[compio::test]
  async fn local_notify_wakes_a_listener() {
    let n = LocalNotify::new();
    let woken = Rc::new(Cell::new(false));
    let woken_in = woken.clone();
    let n2 = n.clone();
    compio_runtime::spawn(async move {
      n2.listen().await;
      woken_in.set(true);
    })
    .detach();
    // give the listener a chance to register
    compio::time::sleep(std::time::Duration::from_millis(10)).await;
    n.notify();
    compio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(woken.get(), "listener woken by notify()");
  }

  /// `is_mdns_multicast_dst` must accept BOTH multicast service groups on
  /// port 5353 (so the transmit pump fans out to both families) and reject
  /// unicast destinations and the wrong port — proto's `multicast_dst()`
  /// always hands back the v4 group, so a false negative here would silence
  /// the v6 leg of every multicast send.
  #[test]
  fn is_mdns_multicast_dst_classifies_groups_and_ports() {
    use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    // v4 group on 5353 → true
    assert!(is_mdns_multicast_dst(SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::new(224, 0, 0, 251),
      5353
    ))));
    // v6 group on 5353 → true
    assert!(is_mdns_multicast_dst(SocketAddr::V6(SocketAddrV6::new(
      Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb),
      5353,
      0,
      0
    ))));
    // unicast on 5353 → false
    assert!(!is_mdns_multicast_dst(SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::new(192, 168, 1, 5),
      5353
    ))));
    // v4 group on the wrong port → false
    assert!(!is_mdns_multicast_dst(SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::new(224, 0, 0, 251),
      53
    ))));
  }

  #[test]
  fn state_construction_is_empty() {
    let s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    assert_eq!(s.services.len(), 0);
    assert_eq!(s.queries.len(), 0);
    assert!(s.goodbyes.is_empty());
  }

  #[test]
  fn fire_timeouts_runs_without_panic_on_empty_state() {
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    s.fire_timeouts(std::time::Instant::now());
  }

  #[compio::test]
  async fn endpoint_inner_can_be_constructed_and_dropped() {
    let cfg = mdns_proto::EndpointConfig::default();
    let inner = EndpointInner::new(cfg, 1500, 9000);
    // notify can be cloned and listened on without panicking
    let n = inner.notify.clone();
    // sanity: listening + notifying once doesn't deadlock
    let h = compio_runtime::spawn(async move {
      n.listen().await;
    });
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
    inner.notify.notify();
    h.await.ok();
    drop(inner);
  }

  /// Driver-liveness invariant: `mark_dirty` is the durable
  /// signal a handle op uses to guarantee the driver re-settles even if the
  /// paired `notify` is lost across a send-await. This pins the mechanics the run
  /// loop's PRE-PARK `inner.dirty.replace(false)` + `force_now` depend on:
  /// `dirty` starts clear, `mark_dirty` sets it, and the consume both reads the
  /// pending state AND clears it. Critically the consume happens at the PARK
  /// BOUNDARY (after every awaitable pump), not at loop entry — a
  /// loop-entry sample misses a `mark_dirty` landing during a late pump await
  /// (e.g. the goodbye send); reading at the boundary, with no `.await` between
  /// the read and arming the `select!` listener, closes that window with no gap.
  #[test]
  fn mark_dirty_sets_a_durable_level_flag_consumed_by_replace() {
    let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    // Fresh endpoint: no handle work yet.
    assert!(!inner.dirty.get(), "dirty must start clear");

    // A handle op marks the endpoint dirty (durably — independent of whether any
    // listener is armed, unlike a bare notify).
    inner.mark_dirty();
    assert!(inner.dirty.get(), "mark_dirty must set the level flag");

    // The driver's pre-park consume reads `true` (→ force_now re-settle) and
    // clears it in one step.
    let force_now = inner.dirty.replace(false);
    assert!(
      force_now,
      "the pre-park decision must observe the pending work"
    );
    assert!(
      !inner.dirty.get(),
      "consuming the flag clears it so a clean iteration can park"
    );

    // A second consume with no intervening mark sees nothing — no spurious
    // force_now / busy-spin once the work is serviced.
    assert!(
      !inner.dirty.replace(false),
      "no work created since last consume → not dirty → driver may park"
    );

    // Work created AFTER the consume (e.g. a handle op racing a late pump await)
    // re-sets the flag, so the NEXT pre-park consume observes it rather than
    // losing it.
    inner.mark_dirty();
    assert!(
      inner.dirty.replace(false),
      "work created after the previous consume must be observed at the next park boundary"
    );
  }

  /// §11 regression guard: a datagram whose TTL/hop-limit is < 255 and whose
  /// source address falls outside the cached local-subnet snapshot must be
  /// dropped by `handle_datagram` before it ever reaches `endpoint.handle`.
  /// We can't observe the proto-side call externally, so the assertion is
  /// "the call returns without panicking on a deliberately bogus 12-byte
  /// body" — which is only true if the §11 gate early-returns first.
  #[test]
  fn handle_datagram_drops_off_link_packet() {
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::socket::RecvMeta;
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
    s.bound_interface = 1;
    let meta = RecvMeta::new(
      SocketAddr::from(([8, 8, 8, 8], 5353)),
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      1,
      Some(64), // off-link: not 255
      None,
      12,
    );
    let data = vec![0u8; 12];
    // The §11 gate must drop this off-link datagram silently — no panic,
    // and crucially no unwind from `endpoint.handle` chewing on the bogus
    // 12-byte header (which would happen if the gate let it through).
    s.handle_datagram(&meta, &data);
  }

  /// `remove_service` MUST: (a) free the proto-layer route slot so re-
  /// registering the same instance name doesn't surface
  /// `NameAlreadyRegistered`, (b) evict the driver-side `ServiceCtx` from
  /// `state.services`, and (c) queue a TTL=0 goodbye burst for any
  /// confirmed-emitted records — the RFC 6762 §10.1 graceful-withdrawal
  /// contract.  Without (a) + (b) every dropped service permanently leaks a
  /// slot until endpoint shutdown.
  #[test]
  fn remove_service_queues_goodbye_and_frees_proto_slot() {
    use std::time::Duration;

    use mdns_proto::{Name, ServiceRecords, ServiceSpec};

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let mut t = std::time::Instant::now();

    let stype = Name::try_from_str("_gb._tcp.local.").unwrap();
    let inst = Name::try_from_str("G._gb._tcp.local.").unwrap();
    let host = Name::try_from_str("g.local.").unwrap();
    let mut recs = ServiceRecords::new(stype, inst.clone(), host, 1234, 120);
    recs.add_a([127, 0, 0, 1].into());
    let handle = s.register_service(ServiceSpec::new(recs), t).unwrap();

    // Drive the proto state machine through probe + announce so the goodbye
    // ownership latches are set — otherwise `encode_goodbye` returns
    // `Ok(None)` and nothing is queued.  Each `poll_transmit` stamps the
    // commit token; `note_transmit_delivered` advances the lifecycle.
    let mut buf = vec![0u8; 4096];
    for _ in 0..40 {
      t += Duration::from_millis(300);
      let ctx = s.services.get_mut(&handle).unwrap();
      let _ = ctx.proto.handle_timeout(t);
      while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
        ctx.proto.note_transmit_delivered(t);
      }
    }
    // Sanity: the service did reach a state that advertises records.
    assert!(
      s.services
        .get(&handle)
        .map(|c| c.proto.advertises_host())
        .unwrap_or(false),
      "service must have advertised at least one record before removal"
    );

    // Remove: the driver-side ctx must vanish AND a goodbye must be queued.
    s.remove_service(handle, t);
    assert!(
      !s.services.contains_key(&handle),
      "remove_service must evict the driver-side ServiceCtx"
    );
    assert!(
      !s.goodbyes.is_empty(),
      "remove_service must queue a TTL=0 goodbye for the confirmed-emitted records"
    );
    let g = &s.goodbyes[0];
    assert_eq!(
      g.remaining, GOODBYE_SENDS,
      "burst budget must be initialised"
    );
    // The proto-layer route slot must be released too: re-registering the
    // same instance name must succeed (otherwise we'd hit NameAlreadyRegistered).
    let mut recs2 = ServiceRecords::new(
      Name::try_from_str("_gb._tcp.local.").unwrap(),
      inst,
      Name::try_from_str("g.local.").unwrap(),
      1234,
      120,
    );
    recs2.add_a([127, 0, 0, 1].into());
    assert!(
      s.register_service(ServiceSpec::new(recs2), t).is_ok(),
      "the proto-layer route slot must be freed by remove_service"
    );
  }

  /// `Service::drop` must NOT remove the proto state or encode the goodbye
  /// synchronously — it only flags `cancelled` (via `flag_service_unregistered`).
  /// The driver's post-pump `sweep_cancelled_services` is what evicts the entry
  /// and queues the §10.1 goodbye. This split is load-bearing: it lets a send
  /// that was in flight when the handle dropped latch its records (via
  /// `note_service_transmit_result`) BEFORE the goodbye is encoded, so a service
  /// dropped mid-send still withdraws every record it actually put on the wire.
  #[compio::test]
  async fn drop_defers_goodbye_to_driver_sweep() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec};
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let mut t = std::time::Instant::now();
    let stype = Name::try_from_str("_sw._tcp.local.").unwrap();
    let inst = Name::try_from_str("s._sw._tcp.local.").unwrap();
    let host = Name::try_from_str("s.local.").unwrap();
    let mut recs = ServiceRecords::new(stype, inst, host, 1234, 120);
    recs.add_a([127, 0, 0, 1].into());
    let handle = s.register_service(ServiceSpec::new(recs), t).unwrap();

    // Drive probe + announce so the service has confirmed-emitted records.
    let mut buf = vec![0u8; 4096];
    for _ in 0..40 {
      t += Duration::from_millis(300);
      let ctx = s.services.get_mut(&handle).unwrap();
      let _ = ctx.proto.handle_timeout(t);
      while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
        ctx.proto.note_transmit_delivered(t);
      }
    }
    assert!(
      s.services
        .get(&handle)
        .map(|c| c.proto.advertises_host())
        .unwrap_or(false),
      "service must advertise before withdrawal"
    );

    // What `Service::drop` does — flag only, no removal, no goodbye encoding.
    s.flag_service_unregistered(handle);
    assert!(
      s.services.contains_key(&handle),
      "drop must NOT remove the service synchronously"
    );
    assert!(
      s.goodbyes.is_empty(),
      "drop must NOT encode the goodbye synchronously — the driver sweep does"
    );
    assert!(
      s.services
        .get(&handle)
        .map(|c| c.cancelled)
        .unwrap_or(false),
      "the service must be flagged cancelled"
    );

    // `has_pending_withdrawal` must report the cancelled-but-unswept service so
    // the driver forces an immediate wake instead of parking (the lost-notify
    // guard): a drop's `notify` can be lost mid-`send_to`, so the forced timer
    // is what guarantees the next iteration sweeps + sends the goodbye.
    assert!(
      s.has_pending_withdrawal(),
      "a cancelled-but-unswept service must report a pending withdrawal"
    );

    // What the driver's post-pump sweep does — evict + queue the §10.1 goodbye.
    let swept = s.sweep_cancelled_services(t);
    assert!(swept, "sweep must report it removed a cancelled service");
    assert!(
      !s.services.contains_key(&handle),
      "sweep must evict the cancelled service's ServiceCtx"
    );
    assert!(
      !s.goodbyes.is_empty(),
      "sweep must queue a TTL=0 goodbye for the confirmed-emitted records"
    );
    assert!(
      !s.has_pending_withdrawal(),
      "after the sweep there is no pending withdrawal left"
    );
  }

  /// On the last-handle-drop shutdown path the driver can't stay alive for the
  /// timer-spaced goodbye bursts, so it calls `take_shutdown_goodbyes`: this
  /// must (a) sweep a service that was flagged cancelled but never swept (the
  /// race where the shutdown check would otherwise exit before the
  /// next top-of-loop sweep) and (b) drain every queued burst into a flat
  /// datagram list so all TTL=0 copies reach the wire before exit, leaving the
  /// goodbye queue empty.
  #[compio::test]
  async fn shutdown_drain_sweeps_and_flushes_all_bursts() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec};
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let mut t = std::time::Instant::now();
    let stype = Name::try_from_str("_sd._tcp.local.").unwrap();
    let inst = Name::try_from_str("s._sd._tcp.local.").unwrap();
    let host = Name::try_from_str("s.local.").unwrap();
    let mut recs = ServiceRecords::new(stype, inst, host, 1234, 120);
    recs.add_a([127, 0, 0, 1].into());
    let handle = s.register_service(ServiceSpec::new(recs), t).unwrap();

    let mut buf = vec![0u8; 4096];
    for _ in 0..40 {
      t += Duration::from_millis(300);
      let ctx = s.services.get_mut(&handle).unwrap();
      let _ = ctx.proto.handle_timeout(t);
      while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
        ctx.proto.note_transmit_delivered(t);
      }
    }
    assert!(
      s.services
        .get(&handle)
        .map(|c| c.proto.advertises_host())
        .unwrap_or(false),
      "service must advertise before withdrawal"
    );

    // Service::drop on the last handle: flag only. The sweep never ran (the
    // driver is about to exit), so the shutdown drain must cover it.
    s.flag_service_unregistered(handle);

    let datagrams = s.take_shutdown_goodbyes(t);
    assert!(
      !s.services.contains_key(&handle),
      "shutdown drain must sweep the cancelled service"
    );
    assert!(
      s.goodbyes.is_empty(),
      "shutdown drain must leave the goodbye queue empty"
    );
    // One service worth of goodbye, expanded to its full burst count.
    assert_eq!(
      datagrams.len(),
      GOODBYE_SENDS as usize,
      "every remaining burst copy must be flushed back-to-back, got {}",
      datagrams.len()
    );
    assert!(
      datagrams.iter().all(|d| !d.is_empty()),
      "flushed goodbye datagrams must be non-empty"
    );
  }

  /// `poll_deadline` must include pending goodbyes' `next_at` so the driver
  /// wakes to fan out a queued §10.1 burst even when no other deadline is
  /// pending.  A regression here would let a goodbye burst silently stall
  /// after the first send.
  #[test]
  fn poll_deadline_sees_pending_goodbye() {
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let now = std::time::Instant::now();
    assert!(s.poll_deadline().is_none(), "empty state has no deadline");
    s.goodbyes.push(PendingGoodbye {
      data: vec![0xde, 0xad],
      remaining: GOODBYE_SENDS,
      next_at: now,
    });
    assert_eq!(
      s.poll_deadline(),
      Some(now),
      "a queued goodbye must surface its next_at on poll_deadline"
    );
  }

  /// Build a `ServiceUpdate::Renamed` carrying `name` (a `*.local.` instance
  /// name). `ServiceRenamed::new` is `#[doc(hidden)]` but public — the same
  /// constructor the reactor's tests use to synthesize renames.
  fn renamed(name: &str) -> ServiceUpdate {
    ServiceUpdate::Renamed(mdns_proto::ServiceRenamed::new(
      mdns_proto::Name::try_from_str(name).unwrap(),
    ))
  }

  /// One-time/idempotent kinds (`Established` / `Conflict` / `HostConflict`)
  /// must dedup by kind: repeated pushes of the same kind never grow the
  /// deque past one entry of that kind. This is the core memory-DoS guard —
  /// a peer spamming conflict-bearing packets can't inflate the queue.
  #[test]
  fn coalesce_dedups_one_time_kinds() {
    let mut d: VecDeque<ServiceUpdate> = VecDeque::new();

    for _ in 0..5 {
      push_service_update_coalesced(&mut d, ServiceUpdate::Established);
    }
    assert_eq!(d.len(), 1, "Established must dedup to a single entry");

    for _ in 0..3 {
      push_service_update_coalesced(&mut d, ServiceUpdate::Conflict);
    }
    assert_eq!(
      d.iter()
        .filter(|u| matches!(u, ServiceUpdate::Conflict))
        .count(),
      1,
      "Conflict must be present exactly once after 3 pushes"
    );

    push_service_update_coalesced(&mut d, ServiceUpdate::HostConflict);
    push_service_update_coalesced(&mut d, ServiceUpdate::HostConflict);
    assert_eq!(
      d.iter()
        .filter(|u| matches!(u, ServiceUpdate::HostConflict))
        .count(),
      1,
      "HostConflict must be present exactly once"
    );

    // Established + Conflict + HostConflict = 3 distinct kinds, one each.
    assert_eq!(d.len(), 3, "three distinct one-time kinds, one entry each");
  }

  /// A new `Renamed` must drop any prior pending `Renamed` and re-append at the
  /// back, so the deque keeps exactly one rename carrying the LATEST name —
  /// the only one the caller acts on.
  #[test]
  fn coalesce_keeps_latest_rename() {
    let mut d: VecDeque<ServiceUpdate> = VecDeque::new();
    push_service_update_coalesced(&mut d, renamed("a.local."));
    push_service_update_coalesced(&mut d, renamed("b.local."));

    assert_eq!(
      d.iter()
        .filter(|u| matches!(u, ServiceUpdate::Renamed(_)))
        .count(),
      1,
      "only the latest Renamed must remain"
    );
    match d.back() {
      Some(ServiceUpdate::Renamed(r)) => {
        assert_eq!(
          r.new_name().as_str(),
          "b.local.",
          "the surviving Renamed must carry the latest name"
        );
      }
      other => panic!("expected a Renamed at the back, got {other:?}"),
    }
  }

  /// RFC 6762 §9 conflict path: a service reaches `Established`, a peer
  /// conflict drives a `Renamed`, then the renamed service re-announces and the
  /// proto emits a SECOND `Established`. The coalescer must surface that final
  /// `Established` — dropping the STALE first one and keeping the new one. A
  /// by-kind-keep-first policy would wrongly discard the post-rename
  /// confirmation that the renamed service is now advertised.
  #[test]
  fn coalesce_keeps_post_rename_established() {
    let mut d: VecDeque<ServiceUpdate> = VecDeque::new();
    push_service_update_coalesced(&mut d, ServiceUpdate::Established);
    push_service_update_coalesced(&mut d, renamed("renamed.local."));
    push_service_update_coalesced(&mut d, ServiceUpdate::Established);

    assert!(
      d.iter().any(|u| matches!(u, ServiceUpdate::Established)),
      "post-rename Established must survive coalescing, got {d:?}"
    );
    assert!(
      d.iter().any(|u| matches!(u, ServiceUpdate::Renamed(_))),
      "the rename must also survive, got {d:?}"
    );
    assert_eq!(
      d.iter()
        .filter(|u| matches!(u, ServiceUpdate::Established))
        .count(),
      1,
      "exactly one Established retained (latest), got {d:?}"
    );
  }

  /// Under realistic churn — a peer interleaving every update kind many times —
  /// the deque must stay bounded to the ≤4-distinct-kinds invariant.
  #[test]
  fn coalesce_bounds_total() {
    let mut d: VecDeque<ServiceUpdate> = VecDeque::new();
    for i in 0..50 {
      push_service_update_coalesced(&mut d, ServiceUpdate::Established);
      push_service_update_coalesced(&mut d, ServiceUpdate::Conflict);
      push_service_update_coalesced(&mut d, ServiceUpdate::HostConflict);
      push_service_update_coalesced(&mut d, renamed(&format!("r-{i}.local.")));
    }
    assert!(
      d.len() <= 4,
      "coalesced deque must stay within the ≤4-kind bound, got {}",
      d.len()
    );
  }

  /// transmit-liveness regression: a service whose records cannot be
  /// encoded into the configured `max_payload` must NOT silently stall. The
  /// proto PRESERVES the un-encodable pending transmit (re-offering it every
  /// `poll_transmit`), so the prior `if let Ok(Some(_))` arm — which treated the
  /// `Err(TransmitError::BufferTooSmall)` like `Ok(None)` — left the service
  /// stuck below `Established` forever with no `ServiceUpdate` ever delivered.
  ///
  /// The fix counts consecutive encode failures per service and, at
  /// [`MAX_CONSECUTIVE_ENCODE_ERRORS`], escalates to `ServiceUpdate::Conflict`
  /// (queued in the in-ctx `updates` deque, NOT dropped) and flags the service
  /// `errored` so it is skipped by every later proto-polling pump. This test
  /// drives `poll_one_transmit` with a deliberately tiny scratch buffer and
  /// asserts: (a) the failure counter climbs one per call, (b) at the threshold
  /// a `Conflict` lands in `updates` and `errored` is set, and (c) a subsequent
  /// `poll_one_transmit` skips the errored service (returns `None` when it's the
  /// only one) rather than re-polling its dead proto.
  #[test]
  fn oversized_service_escalates_to_conflict_not_silent_stall() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec};

    // `max_payload` is irrelevant to `poll_one_transmit` (it takes `scratch`
    // explicitly); a real-record service is what matters.
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1, 9000);
    let now = std::time::Instant::now();

    // A realistic record set: PTR + SRV (implied by `new`) + TXT + A + AAAA.
    let stype = Name::try_from_str("_ovf._tcp.local.").unwrap();
    let inst = Name::try_from_str("Oversized._ovf._tcp.local.").unwrap();
    let host = Name::try_from_str("oversized.local.").unwrap();
    let mut recs = ServiceRecords::new(stype, inst, host, 8080, 120);
    recs.add_a([192, 168, 1, 42].into());
    recs.add_aaaa([0xfe80, 0, 0, 0, 0, 0, 0, 0x1234].into());
    recs.add_txt_segment(b"path=/health".to_vec());
    let handle = s.register_service(ServiceSpec::new(recs), now).unwrap();

    // A 1-byte scratch buffer guarantees `proto.poll_transmit` returns
    // `Err(BufferTooSmall)` once a probe is queued (a probe is many bytes).
    // Verified empirically: the proto needs the probe PENDING first — a fresh
    // service is in `Init` with no queued transmit, so the first few
    // `poll_one_transmit` calls would see `Ok(None)` (reset to 0). We therefore
    // PRIME the lifecycle: advance the clock and `fire_timeouts` until the proto
    // pushes its first probe (Init → Probing(0) → probe pending), detected by
    // the failure counter ticking to 1. Mirrors the time-advancing drive loop
    // the existing `remove_service` / shutdown tests use, but stops at the first
    // encode failure instead of delivering the transmit.
    let mut scratch = [0u8; 1];
    let mut t = now;
    let mut armed = false;
    for _ in 0..40 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      // A failing poll increments `encode_failures`; an `Ok(None)` (nothing
      // pending yet) resets it to 0. Once the probe is queued this sticks at 1.
      let pumped = s.poll_one_transmit(t, &mut scratch);
      assert!(
        pumped.is_none(),
        "an un-encodable transmit must never be returned as a phantom send"
      );
      if s.services.get(&handle).unwrap().encode_failures == 1 {
        armed = true;
        break;
      }
    }
    assert!(
      armed,
      "the proto must queue a probe that fails to encode into the 1-byte scratch"
    );

    // With the probe queued and `Err` preserving it (the proto does NOT pop an
    // un-encodable transmit), each further `poll_one_transmit` must fail again
    // and bump the counter by exactly one — no `fire_timeouts` needed between
    // them. Drive it the rest of the way to the escalation threshold.
    for expected in 2..=MAX_CONSECUTIVE_ENCODE_ERRORS {
      let pumped = s.poll_one_transmit(t, &mut scratch);
      assert!(
        pumped.is_none(),
        "an un-encodable transmit must never be returned as a phantom send \
         (failure #{expected})"
      );
      assert_eq!(
        s.services.get(&handle).unwrap().encode_failures,
        expected,
        "each failing poll must increment encode_failures by one"
      );
    }

    // At the threshold the service must be escalated: a `Conflict` queued in the
    // in-ctx deque, the terminal `errored` flag set, and the one-shot wake armed.
    {
      let ctx = s.services.get(&handle).unwrap();
      assert!(
        ctx.errored,
        "reaching MAX_CONSECUTIVE_ENCODE_ERRORS must mark the service errored"
      );
      assert!(
        ctx
          .updates
          .iter()
          .any(|u| matches!(u, ServiceUpdate::Conflict)),
        "the escalation must queue a ServiceUpdate::Conflict for Service::next, \
         got {:?}",
        ctx.updates
      );
      assert!(
        ctx.conflict_wake_pending,
        "the escalation must arm the one-shot wake so a parked handle is notified"
      );
    }

    // A subsequent pump must SKIP the errored service. With it the only
    // registered service (and no queries), the result is `None` — proving the
    // dead proto is no longer re-polled (no busy-spin) and the counter is frozen.
    assert!(
      s.poll_one_transmit(now, &mut scratch).is_none(),
      "an errored service must be skipped by poll_one_transmit"
    );
    assert_eq!(
      s.services.get(&handle).unwrap().encode_failures,
      MAX_CONSECUTIVE_ENCODE_ERRORS,
      "a skipped errored service must not have its failure counter advanced further"
    );

    // `push_service_updates` must consume the one-shot wake exactly once (so a
    // parked handle is woken), then report no further wake for the same queued
    // Conflict — i.e. an undrained Conflict cannot drive a notify busy-spin.
    assert!(
      s.push_service_updates(),
      "push_service_updates must report a wake for the freshly-escalated Conflict"
    );
    assert!(
      !s.services.get(&handle).unwrap().conflict_wake_pending,
      "the one-shot wake flag must be cleared after the single notify"
    );
    assert!(
      !s.push_service_updates(),
      "a second push must NOT re-wake for the same undrained Conflict (no spin)"
    );
    // The Conflict is still queued for the handle to drain.
    assert!(
      s.services
        .get(&handle)
        .unwrap()
        .updates
        .iter()
        .any(|u| matches!(u, ServiceUpdate::Conflict)),
      "the queued Conflict must remain readable by Service::next after the wake"
    );
  }

  /// a query whose question can't be encoded into `max_payload` (here
  /// a 1-byte scratch) must be flagged `errored` rather than re-offered forever.
  /// A fresh query has `transmit_pending = true`, so the first
  /// `poll_one_transmit` attempts the encode and fails. The driver must mark the
  /// query errored (so every pump skips it — no busy-spin), arm the one-shot
  /// terminal wake exactly once, and contribute no deadline. Without this, a
  /// `QuerySpec` with the default `timeout: None` has neither a `timeout_deadline`
  /// nor (post-failure) a `next_deadline`, so `poll_deadline` returns `None` and
  /// a parked `Query::next` would hang indefinitely.
  #[test]
  fn unencodable_query_is_errored_not_spun_or_hung() {
    use mdns_proto::{QuerySpec, wire::ResourceType};

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let now = std::time::Instant::now();
    let qname = mdns_proto::Name::try_from_str("printer.local.").unwrap();
    // Default QuerySpec: no timeout → no absolute deadline. This is the case
    // that hangs without the fix.
    let h = s
      .start_query(QuerySpec::new(qname, ResourceType::A), now)
      .unwrap();

    // A 1-byte scratch can't hold a DNS header + question → encode `Err`.
    let mut scratch = [0u8; 1];

    // First pump: the pending question fails to encode. The query must be
    // flagged errored and yield NO transmit (not a phantom send).
    let pumped = s.poll_one_transmit(now, &mut scratch);
    assert!(
      pumped.is_none(),
      "an un-encodable query must not yield a transmit"
    );
    assert!(
      s.queries.get(&h).map(|c| c.errored).unwrap_or(false),
      "the query must be flagged errored after the encode failure"
    );

    // No standing deadline from the errored query (would otherwise busy-spin).
    assert!(
      s.poll_deadline().is_none(),
      "an errored query must contribute no deadline"
    );

    // The one-shot terminal wake fires exactly once, then clears.
    assert!(
      s.take_query_terminal_wakes(),
      "the terminal wake must be armed once on the errored transition"
    );
    assert!(
      !s.take_query_terminal_wakes(),
      "the terminal wake is one-shot — a second drain must report nothing"
    );

    // A subsequent pump skips the errored query entirely (no re-poll busy-spin).
    assert!(
      s.poll_one_transmit(now, &mut scratch).is_none(),
      "an errored query must be skipped by later pumps, not re-polled"
    );
    assert!(
      !s.take_query_terminal_wakes(),
      "no further wake is armed once the query is already errored"
    );
  }

  /// Registering the same instance name twice (no intervening removal) must
  /// be rejected by the driver `State` with the proto
  /// `RegisterServiceError::NameAlreadyRegistered` — the duplicate-detection
  /// path the public `Endpoint` later maps onto `RegisterError`.
  #[test]
  fn duplicate_registration_is_rejected_as_name_already_registered() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec, error::RegisterServiceError};

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let t = std::time::Instant::now();

    let mk = || {
      let mut r = ServiceRecords::new(
        Name::try_from_str("_http._tcp.local.").unwrap(),
        Name::try_from_str("dup._http._tcp.local.").unwrap(),
        Name::try_from_str("dup.local.").unwrap(),
        80,
        120,
      );
      r.add_a([127, 0, 0, 1].into());
      ServiceSpec::new(r)
    };

    s.register_service(mk(), t).unwrap();
    let err = s.register_service(mk(), t).unwrap_err();
    assert!(
      matches!(err, RegisterServiceError::NameAlreadyRegistered(_)),
      "second registration of the same instance name must be rejected as NameAlreadyRegistered, got {err:?}"
    );
  }
}

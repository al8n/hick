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
  collections::HashMap,
  time::{Duration, Instant as StdInstant, SystemTime},
};

use mdns_proto::{
  CacheEntry, CollectedAnswer, Endpoint as ProtoEp, EndpointConfig, EndpointEventEntry,
  QueryHandle, QueryUpdate, ServiceHandle, ServiceRoute, ServiceUpdate, WithdrawalSend,
  WithdrawalToken, query::Query as ProtoQuery, service::Service as ProtoSvc, transmit::Transmit,
};

/// Per-iteration cap on the transmit pump.  Mirrors
/// `hick-reactor::driver::MAX_SEND_CREDITS_PER_DRAIN` (64) so a misbehaving
/// proto-state machine — or a transmit yielded for an unbound address family
/// where `note_*_transmit_result(delivered=false)` does not advance state —
/// cannot spin the driver in a tight unbounded loop.
pub(crate) const MAX_TRANSMIT_CREDITS_PER_PASS: usize = 64;

/// IPv4 mDNS multicast destination (224.0.0.251:5353). Used by the transmit
/// pump's dual-stack fan-out and the endpoint-owned withdrawal pump.
pub(crate) const MDNS_V4_DST: core::net::SocketAddr = core::net::SocketAddr::V4(
  core::net::SocketAddrV4::new(core::net::Ipv4Addr::new(224, 0, 0, 251), 5353),
);

/// IPv6 mDNS multicast destination ([ff02::fb]:5353). Used by the transmit
/// pump's dual-stack fan-out and the endpoint-owned withdrawal pump.
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

/// Driver-side per-service context: the owned proto state machine, the
/// handle-owned delivery mailbox, and a cancellation flag.
///
/// App-facing [`ServiceUpdate`]s are delivered through [`ServiceCtx::mailbox`], a
/// `Rc<RefCell<ServiceMailbox>>` shared with the [`crate::Service`] handle (the
/// `!Send` analogue of the reactor's `Arc<Mutex<_>>` mailbox). The mailbox bounds
/// and coalesces non-terminal updates by kind and reserves a slot for the
/// terminal retirement update, so a hostile on-link peer cannot grow it without
/// bound and the `Conflict`/`HostConflict` is never dropped. Because the mailbox
/// is owned by the HANDLE, the driver GCs this ctx UNCONDITIONALLY once its
/// withdrawal completes — a pending terminal is still delivered to a live reader.
pub(crate) struct ServiceCtx {
  pub(crate) proto: ProtoService,
  /// Handle-owned delivery buffer the driver fills with [`ServiceUpdate`]s and
  /// the [`crate::Service`] handle drains via [`crate::Service::next`]. Shared
  /// `Rc<RefCell<_>>`; outlives this ctx (held by the handle), so the reserved
  /// terminal survives an immediate ctx GC.
  pub(crate) mailbox: Rc<RefCell<crate::service::ServiceMailbox>>,
  pub(crate) cancelled: bool,
  /// Count of consecutive `proto.poll_transmit` errors for this service. Reset
  /// to 0 on any `Ok` (a successful encode or an empty queue); incremented on
  /// each `Err`. Once it reaches [`MAX_CONSECUTIVE_ENCODE_ERRORS`] the service
  /// is escalated to [`ServiceUpdate::Conflict`] and marked [`Self::errored`].
  pub(crate) encode_failures: u8,
  /// Terminal "this service is structurally dead" flag. Set once a persistent
  /// encode failure escalated to `Conflict` (or the service was retired into an
  /// endpoint-owned withdrawal). The escalation routes the `Conflict` into the
  /// handle-owned mailbox's reserved terminal slot — which outlives the ctx — so
  /// the driver GCs the ctx UNCONDITIONALLY on withdrawal completion without
  /// losing the `Conflict`. Meanwhile `errored` makes every proto-polling pump
  /// skip this ctx so a finished proto can't be re-polled into a busy-spin.
  pub(crate) errored: bool,
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
  /// undrained terminal can't drive a notify busy-spin. (A retiring SERVICE has
  /// no equivalent flag: its terminal lands in the handle-owned mailbox and the
  /// withdrawal it begins carries the wake — its deadline re-settles the driver
  /// and the completion GC notifies.)
  pub(crate) terminal_wake_pending: bool,
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
  /// Reusable scratch for the handles of endpoint-owned withdrawals that
  /// completed in a loop iteration, so [`ProtoEndpoint::drain_completed_withdrawals`]
  /// can push into it and the loop can GC each one's driver ctx. Kept on the
  /// state and `clear()`ed each iteration so the per-iteration GC allocates
  /// nothing in steady state.
  pub(crate) completed_withdrawals: Vec<ServiceHandle>,
  /// Reusable scratch for the service/query handle snapshots taken by the
  /// transmit pump (`poll_one_transmit`) and `push_service_updates`: those loops
  /// early-`return` and call `&mut self` withdrawal methods mid-iteration, so they
  /// can't hold a map borrow across the body — they reuse these buffers instead of
  /// allocating a fresh `Vec` per pump call. `clear()`ed at the start of each use.
  pub(crate) svc_handle_scratch: Vec<ServiceHandle>,
  pub(crate) query_handle_scratch: Vec<QueryHandle>,
  /// Bound interface index (1-based) used for §11 link-local scoping.
  pub(crate) bound_interface: u32,
  /// Cached local subnets used for the §11 source-address fallback when the
  /// kernel didn't deliver an IPv4 TTL / IPv6 hop-limit cmsg.
  pub(crate) local_subnets: Vec<(core::net::IpAddr, u8)>,
  /// Max datagram size; used to size the scratch buffer for the encode/send
  /// path (T8/T9). Sourced from [`crate::ServerOptions::max_payload_size`].
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
  /// Build a fresh driver state with no services or queries, seeded with an
  /// OS-derived [`rand::rngs::StdRng`]. Bound interface and local-subnet
  /// snapshot stay empty until T9 wires them in from the bound sockets /
  /// interface discovery.
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
      completed_withdrawals: Vec::new(),
      svc_handle_scratch: Vec::new(),
      query_handle_scratch: Vec::new(),
      bound_interface: 0,
      local_subnets: Vec::new(),
      max_payload,
      max_recv,
      #[cfg(feature = "stats")]
      stats,
    }
  }

  /// Register a service spec with the endpoint and create a driver-side context
  /// for it, holding the driver's clone of the handle-owned delivery `mailbox`
  /// (the [`crate::Service`] handle holds the other clone). The driver fills the
  /// mailbox in [`Self::push_service_updates`] / the escalation paths; the handle
  /// drains it via [`crate::Service::next`].
  pub(crate) fn register_service(
    &mut self,
    spec: mdns_proto::ServiceSpec,
    now: StdInstant,
    mailbox: Rc<RefCell<crate::service::ServiceMailbox>>,
  ) -> Result<ServiceHandle, mdns_proto::error::RegisterServiceError> {
    let (handle, svc) = self
      .endpoint
      .try_register_service::<slab::Slab<_>, slab::Slab<_>>(spec, now)?;
    self.services.insert(
      handle,
      ServiceCtx {
        proto: svc,
        mailbox,
        cancelled: false,
        encode_failures: 0,
        errored: false,
      },
    );
    Ok(handle)
  }

  /// Test-only: register a service with a freshly-created handle-owned mailbox.
  /// The mailbox is stashed in the resulting [`ServiceCtx`], so a test inspects
  /// what the driver delivered via `s.services.get(&h).unwrap().mailbox` (the
  /// `*_for_test` mailbox helpers). Lets the State-seam tests register without
  /// threading a mailbox through.
  #[cfg(test)]
  pub(crate) fn test_register_service(
    &mut self,
    spec: mdns_proto::ServiceSpec,
    now: StdInstant,
  ) -> Result<ServiceHandle, mdns_proto::error::RegisterServiceError> {
    let mailbox = crate::service::new_service_mailbox();
    self.register_service(spec, now, mailbox)
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

  /// Flag a service as withdrawn (called from [`crate::Service::drop`]). The
  /// actual retirement — beginning the endpoint-owned RFC 6762 §10.1 withdrawal —
  /// is deferred to the driver loop's [`Self::sweep_cancelled_services`], which
  /// runs after the transmit pump so any in-flight send latches first. The
  /// `cancelled` flag is meanwhile honoured by [`Self::poll_one_transmit`] and
  /// [`Self::fire_timeouts`] so a withdrawn service emits no further
  /// probes/announces before the sweep.
  ///
  /// A dropped handle is simply marked `cancelled`: its ctx is reclaimed
  /// UNCONDITIONALLY when the withdrawal completes
  /// ([`Self::drain_completed_withdrawals`]). Any pending terminal lives in the
  /// handle-owned mailbox, which outlives the ctx, so there is no GC-defer arm to
  /// keep here (the former `route_freed` special-case is gone — it existed only
  /// because updates used to live in the ctx).
  pub(crate) fn flag_service_unregistered(&mut self, h: ServiceHandle) {
    if let Some(s) = self.services.get_mut(&h) {
      s.cancelled = true;
    }
  }

  /// Begin the endpoint-owned RFC 6762 §10.1 withdrawal for `handle`: mark the
  /// ctx `errored` (so every subsequent pump skips it for transmits, deadlines,
  /// and ticks — its proto state machine is finished), snapshot what its CURRENT
  /// name's goodbye must retract
  /// ([`mdns_proto::service::Service::withdrawal_snapshot`]), and hand it to
  /// [`ProtoEndpoint::begin_withdrawal`]. The endpoint KEEPS the route (holding
  /// the name against a same-name re-registration) and drives the TTL=0 goodbye
  /// resend schedule; the run loop pumps each due goodbye datagram and, on
  /// completion, frees the route and GCs the driver ctx.
  ///
  /// This withdrawal covers the records the service confirmed-emitted under its
  /// CURRENT name (host A/AAAA filtered against same-host siblings by the
  /// endpoint). An in-flight conflict-rename old-name goodbye is a SEPARATE
  /// detached withdrawal item, enqueued the instant the rename happened via
  /// [`ProtoEndpoint::enqueue_rename_withdrawal`]. A never-announced service has an
  /// empty snapshot and completes on the next loop iteration with no datagram on
  /// the wire.
  ///
  /// The driver ctx is NOT removed here: it is kept (marked `errored`) so any
  /// already-queued `ServiceUpdate::Conflict` still reaches the host before the ctx
  /// is GC'd. `begin_withdrawal` is idempotent, so calling this for an
  /// already-withdrawing service is a no-op. A no-op for an unknown driver handle.
  pub(crate) fn begin_service_withdrawal(&mut self, handle: ServiceHandle, now: StdInstant) {
    // Scope the `ctx` borrow so it ends before `self.endpoint` is touched (the
    // snapshot is owned, so no borrow of `self.services` outlives this block).
    // ALSO take any pending §9 rename handoff here: a retirement that races a
    // queued `Renamed` update (closed receiver / explicit unregister) never
    // reaches the update-drain site that normally enqueues it, which would strand
    // the old-name goodbye in a proto being GC'd. `.take()` makes the handoff
    // exactly-once vs the update-drain path.
    let (snap, handoff) = match self.services.get_mut(&handle) {
      Some(ctx) => {
        ctx.errored = true;
        let handoff = ctx.proto.take_rename_goodbye_handoff();
        (ctx.proto.withdrawal_snapshot(), handoff)
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

  /// Pump every due endpoint-owned withdrawal datagram into `scratch`, returning
  /// `Some((dst, len, token))` for ONE due TTL=0 goodbye or `None` when none is
  /// due. Mirrors [`Self::poll_one_transmit`]: the run loop sends `scratch[..len]`
  /// (fanned to BOTH families — `dst` is always the IPv4 multicast marker) and
  /// then confirms via [`Self::note_withdrawal_result`], round-tripping the opaque
  /// [`WithdrawalToken`]. The endpoint encodes the goodbye with fresh sibling
  /// host-address retention computed internally.
  pub(crate) fn poll_one_withdrawal(
    &mut self,
    now: StdInstant,
    scratch: &mut [u8],
  ) -> Option<(core::net::SocketAddr, usize, WithdrawalToken)> {
    self.endpoint.poll_withdrawal_transmit(now, scratch)
  }

  /// Confirm a withdrawal goodbye round for `token`, reporting EACH family's
  /// [`WithdrawalSend`] outcome so the endpoint tracks per-family debt: an
  /// item frees only once every reachable family has withdrawn its records.
  /// A family that `Sent` spends one of its resend rounds; a busy family `Retry`s
  /// (keeps its debt); an absent-socket / permanent-error family is written off.
  /// No-op for an unknown token.
  pub(crate) fn note_withdrawal_result(
    &mut self,
    token: WithdrawalToken,
    now: StdInstant,
    v4: WithdrawalSend,
    v6: WithdrawalSend,
  ) {
    self.endpoint.note_withdrawal_result(token, now, v4, v6);
  }

  /// Free + GC every endpoint-owned withdrawal that COMPLETED (its resend budget
  /// is spent or it hit the 2 s anti-pin ceiling). The endpoint releases each
  /// route (decrementing `services_active`); the driver then GCs its driver ctx
  /// UNCONDITIONALLY.
  ///
  /// The GC is unconditional because app-facing updates no longer live in the ctx:
  /// any pending terminal (`Conflict`/`HostConflict`) sits in the handle-owned
  /// mailbox, which is owned by the [`crate::Service`] handle and OUTLIVES this
  /// ctx. Removing the ctx therefore cannot lose a terminal — a still-live reader
  /// drains it from the mailbox, and a dropped handle has no reader to lose it to.
  /// This is what closes the former leak class (a cancelled ctx with an
  /// undrained update used to be deferred via `route_freed` and leaked forever)
  /// AND the lost-terminal class (the `Conflict` survives a withdrawal completing
  /// in the SAME iteration that began it). Call once per loop iteration, after
  /// draining withdrawal transmits. Returns `true` if at least one ctx was GC'd
  /// (so the caller can wake any handle parked on an otherwise-idle endpoint to
  /// observe its end-of-stream).
  pub(crate) fn drain_completed_withdrawals(&mut self, now: StdInstant) -> bool {
    // `completed_withdrawals` and `endpoint` are disjoint fields; clear the
    // reused scratch and let the endpoint push the completed handles into it.
    self.completed_withdrawals.clear();
    self
      .endpoint
      .drain_completed_withdrawals(now, &mut self.completed_withdrawals);
    let mut gcd_any = false;
    while let Some(handle) = self.completed_withdrawals.pop() {
      // Unconditional GC: the handle-owned mailbox carries any pending terminal,
      // so reclaiming the ctx never loses an app-facing update.
      if self.services.remove(&handle).is_some() {
        gcd_any = true;
      }
    }
    gcd_any
  }

  /// Drive endpoint + per-query timer-based work.  Per-service lifecycle
  /// timers fire via `ctx.proto.handle_timeout` from the driver loop (T9 / T11);
  /// at T8 only the endpoint cache sweep and query timeouts are exposed.
  pub(crate) fn fire_timeouts(&mut self, now: StdInstant) {
    let _ = self.endpoint.handle_timeout(now);
    // Split-borrow so the query sweep reads `queries` in place and ticks via the
    // disjoint `endpoint` field — no per-tick Vec snapshot, and the `errored`
    // guard reuses the iterator's `ctx` instead of a second map lookup.
    let Self {
      endpoint, queries, ..
    } = &mut *self;
    for (&h, ctx) in queries.iter() {
      // Don't tick a structurally-dead query's proto (see `QueryCtx::errored`).
      if ctx.errored {
        continue;
      }
      let _ = endpoint.handle_query_timeout(h, now);
    }
    // The proto tick touches only the service's own ctx, so iterate
    // `values_mut()` in place rather than snapshotting handles into a Vec.
    for ctx in self.services.values_mut() {
      // Don't tick a withdrawn (cancelled) or structurally-dead (errored)
      // service's proto — a dead proto must not be driven (see
      // `ServiceCtx::errored`).
      if !ctx.cancelled && !ctx.errored {
        let _ = ctx.proto.handle_timeout(now);
      }
    }
  }

  /// Begin the endpoint-owned withdrawal for every service flagged `cancelled` by
  /// [`Service::drop`], via [`Self::begin_service_withdrawal`]. Returns `true` if
  /// at least one service was swept.
  ///
  /// The driver calls this AFTER the transmit pump, never from `Service::drop`
  /// directly. The ordering is load-bearing: a service whose announce/response was
  /// in flight (mid-`send_to().await`) when its handle dropped only latches those
  /// records as advertised once the send completes and the pump calls
  /// [`Self::note_service_transmit_result`]. Sweeping after the pump guarantees the
  /// withdrawal snapshot sees the latched records and includes them in the goodbye.
  /// Snapshotting synchronously in `Drop` — before the await completed — would miss
  /// the just-sent record and leak a positive-TTL entry into peer caches with no
  /// TTL=0 withdrawal (the §10.1 violation this fixes).
  pub(crate) fn sweep_cancelled_services(&mut self, now: StdInstant) -> bool {
    // Only sweep a cancelled service that is NOT already withdrawing (`errored`
    // is set by `begin_service_withdrawal`), so a second sweep pass before the
    // withdrawal completes is a no-op rather than a redundant idempotent call.
    let cancelled: Vec<ServiceHandle> = self
      .services
      .iter()
      .filter(|(_, ctx)| ctx.cancelled && !ctx.errored)
      .map(|(h, _)| *h)
      .collect();
    let swept = !cancelled.is_empty();
    for h in cancelled {
      self.begin_service_withdrawal(h, now);
    }
    swept
  }

  /// Drain pending `ServiceUpdate`s out of each per-service proto state machine
  /// into the handle-owned [`crate::service::ServiceMailbox`] so
  /// [`crate::Service::next`] can pop them: terminal kinds (`Conflict` /
  /// `HostConflict`) go to the reserved terminal slot, everything else to the
  /// coalescing non-terminal ring. Returns `true` if at least one update was
  /// pushed (so the caller knows to bump `notify` and wake any parked listener).
  pub(crate) fn push_service_updates(&mut self, now: StdInstant) -> bool {
    let mut pushed_any = false;
    // Iterate by handle (not `values_mut`) so each iteration can take DISJOINT
    // `&mut` access to `self.endpoint` (for `handle_service_renamed`) and
    // `self.services.get_mut(&h)` — a single `values_mut()` borrow would lock
    // `self.endpoint` out.
    self.svc_handle_scratch.clear();
    self
      .svc_handle_scratch
      .extend(self.services.keys().copied());
    let mut i = 0;
    while i < self.svc_handle_scratch.len() {
      let h = self.svc_handle_scratch[i];
      i += 1;
      // A structurally-dead proto (see `ServiceCtx::errored`) is never polled — it
      // can't produce more updates. Its escalation `Conflict` already sits in the
      // handle-owned mailbox's reserved terminal slot and is drained directly by
      // `Service::next`; the wake for it is carried by the withdrawal the
      // escalation began (its deadline re-settles the driver, and the completion
      // GC notifies), so there is nothing to do here but skip the proto.
      if self.services.get(&h).is_some_and(|c| c.errored) {
        continue;
      }
      // Drain this service's proto events one at a time. A `Renamed` requires
      // routing the endpoint to the new instance name BEFORE the update is
      // surfaced; everything else is queued directly.
      // Each `proto.poll()` returns an owned `Option<ServiceUpdate>` and drops its
      // `&mut` borrow before the body runs, so the body can re-borrow
      // `self.services` / `self.endpoint` freely.
      while let Some(upd) = self.services.get_mut(&h).and_then(|c| c.proto.poll()) {
        // RFC 6762 §9 auto-rename: the proto picked a new instance name after a
        // probe conflict and has already mutated its own records to it. The
        // endpoint's route table still points at the OLD name, so datagrams for the
        // new name (and local rename-collision detection) won't route until we call
        // `handle_service_renamed`. Do it BEFORE surfacing the update, mirroring
        // `hick-reactor::driver`. If the proto rejects the new name (already owned
        // by another local service), the service has already rebranded and can't be
        // kept: surface `Conflict`, flag it errored so every pump skips it, and stop
        // draining it.
        if let ServiceUpdate::Renamed(ref renamed) = upd {
          let new_name = renamed.new_name().clone();
          let rename_result = self.endpoint.handle_service_renamed(h, new_name);
          // The §9 rename of an announced service hands its OLD-name TTL=0 goodbye
          // off as an INDEPENDENT detached withdrawal item, both for a SURVIVING
          // rename and a COLLISION teardown. Take it from the proto the instant the
          // rename is observed (releasing the `self.services` borrow into a local
          // before re-borrowing `self.endpoint`) and enqueue it — the Service no
          // longer drains the old-name goodbye itself.
          let handoff = self
            .services
            .get_mut(&h)
            .and_then(|c| c.proto.take_rename_goodbye_handoff());
          if let Some(handoff) = handoff {
            // A rename COLLISION (rename_result Err) tears the service down: its old
            // name must HOLD until the goodbye completes so a quick re-register
            // cannot cancel the only retraction. A SURVIVING rename
            // stays reclaimable.
            self
              .endpoint
              .enqueue_rename_withdrawal(handoff, now, rename_result.is_err());
          }
          if let Err(_e) = rename_result {
            hick_trace::warn!(
              handle = ?h,
              error = ?_e,
              "auto-rename collided with another local service; emitting Conflict and beginning withdrawal"
            );
            // The new name collides with another LOCAL service; this service has
            // already rebranded and can't be kept. Record `Conflict` in the
            // handle-owned mailbox's reserved terminal slot (drained directly by
            // `Service::next`), then begin the endpoint-owned withdrawal for the
            // CURRENT name; the endpoint holds the route (keeping the name reserved)
            // while it resends, freeing the name on completion. The OLD name's
            // goodbye was already enqueued above as its own detached item. The ctx
            // is GC'd UNCONDITIONALLY by `drain_completed_withdrawals` once the
            // withdrawal completes — the mailbox outlives it, so the `Conflict`
            // survives.
            if let Some(ctx) = self.services.get(&h) {
              ctx
                .mailbox
                .borrow_mut()
                .set_terminal(ServiceUpdate::Conflict);
            }
            // The `ctx` borrow above ends at the closing `}`. Begin the
            // endpoint-owned withdrawal IN-ITERATION (non-bypassable — this
            // `while let` only borrows `self.services` transiently and there is no
            // transmit early-return here). `begin_service_withdrawal` sets `errored`
            // and holds the route; it touches `self.services`/`self.endpoint` only,
            // no iterator invalidation, and `begin_withdrawal` is idempotent.
            self.begin_service_withdrawal(h, now);
            pushed_any = true;
            break;
          }
        }
        // Route by kind: `push_update` forwards terminals to the reserved slot
        // and coalesces non-terminals into the bounded ring.
        let is_terminal = upd.is_conflict() || upd.is_host_conflict();
        if let Some(ctx) = self.services.get(&h) {
          ctx.mailbox.borrow_mut().push_update(upd);
        }
        // Wake on every drained proto update regardless of whether coalescing
        // dropped it, so a parked `Service::next` still re-checks state. This
        // matches the pre-coalescing wake semantics.
        pushed_any = true;
        // A terminal emitted DIRECTLY by the proto state machine (an unresolvable
        // §9 conflict, or the host name claimed during probing) RETIRES the
        // service, exactly like the rebrand-collision path above: begin the
        // endpoint-owned §10.1 withdrawal so the ctx/route are GC'd and the proto
        // stops serving, instead of leaving a zombie live — still answering
        // queries, with `Service::next` reporting end-of-stream — until the caller
        // drops the handle. The handle-owned mailbox outlives the ctx,
        // so the terminal still reaches the host after the completion GC.
        if is_terminal {
          self.begin_service_withdrawal(h, now);
          break;
        }
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
    self.svc_handle_scratch.clear();
    self
      .svc_handle_scratch
      .extend(self.services.keys().copied());
    let mut i = 0;
    while i < self.svc_handle_scratch.len() {
      let h = self.svc_handle_scratch[i];
      i += 1;
      // Skip a cancelled (withdrawn, awaiting sweep) or errored (structurally
      // dead, see `ServiceCtx::errored`) service so neither is re-polled into a
      // busy-spin.
      {
        let Some(ctx) = self.services.get_mut(&h) else {
          continue;
        };
        if ctx.cancelled || ctx.errored {
          continue;
        }
      }
      // distinguish `Ok(None)` ("nothing pending") from `Err`
      // ("can't encode the pending transmit"). `mdns-proto` PRESERVES the
      // pending transmit on encode failure, re-offering the identical oversized
      // datagram every call, so treating `Err` like `Ok(None)` (the prior
      // `if let Ok(Some(_))` bug) leaves it head-of-line forever and the service
      // silently stalls below `Established`. Count consecutive failures and
      // escalate to `ServiceUpdate::Conflict` once they cross the threshold.
      //
      // NLL note: `ctx` is scoped to the `match` block below so its borrow on
      // `self.services` ends before the post-match `begin_service_withdrawal` call.
      let escalated = {
        let ctx = self
          .services
          .get_mut(&h)
          .expect("handle present (just checked)");
        match ctx.proto.poll_transmit(now, scratch) {
          Ok(Some(t)) => {
            ctx.encode_failures = 0;
            return Some((t.dst(), t.size(), TransmitOrigin::Service(h)));
          }
          Ok(None) => {
            ctx.encode_failures = 0;
            // Nothing pending for this service — fall through to the next one.
            false
          }
          Err(_e) => {
            ctx.encode_failures = ctx.encode_failures.saturating_add(1);
            if ctx.encode_failures >= MAX_CONSECUTIVE_ENCODE_ERRORS {
              // Persistent encode failure: the records can't fit `max_payload`.
              // Record `Conflict` in the handle-owned mailbox's reserved terminal
              // slot (the handle drains it directly via `Service::next`). Do NOT
              // remove the ctx — but unlike before, the mailbox outlives the ctx, so
              // the `Conflict` survives the UNCONDITIONAL GC the post-match
              // `begin_service_withdrawal` → `drain_completed_withdrawals` performs
              // on completion. The withdrawal it begins also carries the wake (its
              // deadline re-settles the driver; the completion GC notifies).
              // `begin_service_withdrawal` marks the ctx `errored` so every
              // proto-polling pump skips it from here on.
              hick_trace::warn!(
                handle = ?h,
                error = ?_e,
                scratch_size = scratch.len(),
                consecutive_failures = ctx.encode_failures,
                "Service::poll_transmit failed; escalating to Conflict and beginning withdrawal"
              );
              ctx
                .mailbox
                .borrow_mut()
                .set_terminal(ServiceUpdate::Conflict);
              // `ctx` (and its borrow of `self.services`) ends here at the closing
              // brace of this block, before the post-match
              // `begin_service_withdrawal` call below.
              true
            } else {
              false
            }
            // Whether or not we escalated, do NOT return the un-encodable
            // transmit as a phantom send — fall through to the next service.
          }
        }
      };
      if escalated {
        // Begin the endpoint-owned withdrawal immediately — in-iteration and
        // non-bypassable — so an `Ok(Some)` early-return for a LATER service in
        // this same loop cannot skip it. A service that persistently fails to
        // ENCODE never reached Established, so its snapshot is empty and the
        // withdrawal completes on the next iteration with no datagram on the wire
        // (the records + scratch are fixed, so the failure is permanent). The
        // endpoint KEEPS the route (holding the name) and frees it on completion;
        // the ctx is kept (marked `errored` by `begin_service_withdrawal`) so the
        // queued `Conflict` still reaches the host. Touches only
        // `self.endpoint`/`self.services` (no iterator invalidation), and
        // `begin_withdrawal` is idempotent.
        self.begin_service_withdrawal(h, now);
      }
    }

    self.query_handle_scratch.clear();
    self
      .query_handle_scratch
      .extend(self.queries.keys().copied());
    let mut i = 0;
    while i < self.query_handle_scratch.len() {
      let h = self.query_handle_scratch[i];
      i += 1;
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
          // Retire the proto query so it records the terminal
          // (queries_done / queries_timeout bump + decr_queries_active), matching
          // the smoltcp driver's behaviour. After this, `Query::next` will
          // surface the `QueryUpdate::Timeout` terminal via `endpoint.poll_query`
          // before falling through to the errored-path end-of-stream `None`.
          self.endpoint.retire_query(h);
          hick_trace::warn!(
            handle = ?h,
            error = ?_e,
            scratch_size = scratch.len(),
            "Query::poll_query_transmit failed to encode; retiring proto query and marking errored (Query::next will surface terminal)"
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
      // Mirror the service's CONFIRMED-ADVERTISED host set into the endpoint
      // route so sibling host-address retention (during a same-host withdrawal)
      // honours what this service ACTUALLY announced, not its configured
      // addresses. Idempotent overwrite; only meaningful after a delivered send.
      // `self.services` (via `ctx`) and `self.endpoint` are disjoint fields, so
      // this borrow split is sound.
      if delivered {
        self.endpoint.note_service_advertised(
          h,
          ctx.proto.advertised_a_addrs(),
          ctx.proto.advertised_aaaa_addrs(),
          ctx.proto.advertises_instance(),
        );
      }
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
  /// [`Self::sweep_cancelled_services`] (i.e. `cancelled` but the withdrawal has
  /// not yet been begun — `!errored`). The driver uses this to force an immediate
  /// (zero-duration) timer instead of parking. `Service::drop` flags the service
  /// and calls `notify()`, but the shared `LocalNotify` wake is lost when it lands
  /// while the driver is mid-`send_to` await with no listener armed, so the wake
  /// alone cannot be relied on to run the withdrawal sweep — the forced timer is
  /// what guarantees it. Once the sweep has begun the withdrawal, its resend
  /// schedule lives in the endpoint and is folded into [`Self::poll_deadline`], so
  /// this no longer needs to report it.
  pub(crate) fn has_pending_withdrawal(&self) -> bool {
    self
      .services
      .values()
      .any(|ctx| ctx.cancelled && !ctx.errored)
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

  /// The earliest endpoint-owned WITHDRAWAL deadline (next due goodbye round or
  /// the 2 s anti-pin ceiling), or `None` when no withdrawal is in flight —
  /// EXCLUDING cache, query, and service deadlines. The last-handle shutdown flush
  /// uses this (not [`Self::poll_deadline`]) so it exits as soon as every goodbye
  /// is sent rather than parking on unrelated cache expiry or the wall-clock
  /// backstop.
  pub(crate) fn next_withdrawal_deadline(&self) -> Option<StdInstant> {
    self.endpoint.next_withdrawal_deadline()
  }

  /// Earliest deadline across the endpoint (which already folds in the
  /// endpoint-owned withdrawal deadlines — the next due goodbye round and the 2 s
  /// anti-pin ceiling — via [`ProtoEndpoint::poll_timeout`]), services, and
  /// queries.
  pub(crate) fn poll_deadline(&self) -> Option<StdInstant> {
    let mut best = self.endpoint.poll_timeout();
    for ctx in self.services.values() {
      // A structurally-dead / withdrawing service (see `ServiceCtx::errored`)
      // must not contribute a deadline — its proto state machine is finished and
      // its withdrawal schedule lives in the endpoint (folded into
      // `poll_timeout` above); contributing its proto's stale timeout would pin
      // the driver awake despite it never being polled.
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
      // The datagram WAS received off the socket — count it toward receive
      // volume exactly once (mirroring the proto path: packets_rx + bytes_rx at
      // entry, then one reject counter). proto's handle() is not called, so
      // proto cannot bump these; we do it here instead.
      #[cfg(feature = "stats")]
      {
        self.stats.packets_rx(1);
        self.stats.bytes_rx(data.len() as u64);
        self.stats.packets_dropped(1);
      }
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
      // Same as the off-link path above: the datagram was received, so count
      // receive volume once and the reject counter once. proto's handle() is
      // not reached, so this is the sole accounting point.
      #[cfg(feature = "stats")]
      {
        self.stats.packets_rx(1);
        self.stats.bytes_rx(data.len() as u64);
        self.stats.packets_dropped(1);
      }
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
          // Defense-in-depth for the no-dispatch-after-retirement invariant: the
          // endpoint already skips withdrawing routes in every ToService path
          // (question, conflict, known-answer), so this guards against a future
          // dispatch regression feeding events into a proto whose updates the
          // driver no longer drains — which would let a peer grow the proto event
          // slab of a retiring service until GC. `errored` is compio's
          // withdrawing marker (set by `begin_service_withdrawal`), matching the
          // update-drain skip.
          if let Some(ctx) = services.get_mut(&ts.handle())
            && !ctx.errored
          {
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
#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", skip_all))]
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
    //    The old free-name goodbye BARRIER (a pre-transmit gate that skipped this
    //    pump while an un-sent TTL=0 withdrawal was pending) is GONE: the §10.1
    //    ordering (a stale TTL=0 must precede a same-name replacement's fresh
    //    positive TTL) is now enforced by the ENDPOINT, which KEEPS the route
    //    while a withdrawal is in flight, so a same-name `register_service` is
    //    rejected (`NameAlreadyRegistered`) until the withdrawal frees the name.
    //    No replacement can announce ahead of the withdrawal, so this pump runs
    //    unconditionally.
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
    //     flags `cancelled`; beginning the endpoint-owned §10.1 withdrawal happens
    //     HERE, after the transmit pump, so a send that was in flight when the
    //     handle dropped has already latched its records via
    //     `note_service_transmit_result` and is therefore captured in the
    //     withdrawal snapshot. The endpoint holds the route + drives the goodbye
    //     schedule; the first round is due immediately and is pumped by
    //     `drain_withdrawals` (1a) later in this same iteration, after 1b has also
    //     had a chance to begin any rename-collision withdrawal.
    {
      let now = StdInstant::now();
      inner.state.borrow_mut().sweep_cancelled_services(now);
    }

    // 1b. drain pending `ServiceUpdate`s out of each per-service proto state
    //     machine and into the handle-owned `ServiceMailbox` so listeners parked
    //     on `Service::next` can pop them.  The borrow is brief and is dropped
    //     before any `.await`.
    //
    //     ORDERING NOTE: this runs before the withdrawal pump (1a) below so a
    //     rename-collision withdrawal begun HERE (`push_service_updates` calls
    //     `begin_service_withdrawal`, whose first goodbye round is due immediately)
    //     is pumped on-wire in this SAME iteration. The endpoint holds the OLD name
    //     for the whole withdrawal, so a same-name replacement cannot register (and
    //     evict the old name from peer caches) until the goodbye completes —
    //     structurally enforcing the stale-TTL0-before-replacement ordering the old
    //     pre-transmit barrier used to.
    {
      let now = StdInstant::now();
      let pushed = inner.state.borrow_mut().push_service_updates(now);
      if pushed {
        inner.notify.notify();
      }
    }

    // 1a. RFC 6762 §10.1 endpoint-owned withdrawal pump. `sweep_cancelled_services`
    //     (1a-pre), a conflict-rename teardown (1b above), and the transmit-pump /
    //     encode-failure escalations all begin endpoint-owned withdrawals; this
    //     pumps each due TTL=0 goodbye datagram (fanned to BOTH families) and, after
    //     draining, frees each completed route + GCs its driver ctx. Running AFTER
    //     `push_service_updates` (1b) ensures a rename-collision withdrawal begun
    //     this iteration flushes its first goodbye on-wire the same iteration.
    drain_withdrawals(&inner, &sock_v4, &sock_v6, &mut scratch).await;

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
    //     drained (transmits, withdrawal pump, cancellation sweep, updates). If no
    //     external handle remains, exit — but FIRST drive every in-flight §10.1
    //     withdrawal to completion so a withdrawal is never lost at teardown.
    //
    //     This check lives HERE, before arming `select!`, not after the park.
    //     `Service::drop` / `Query::drop` only flag + `notify()`, and the shared
    //     `LocalNotify` wake is LOST if it lands while the driver is mid-`send_to`
    //     await with no listener armed. A bottom-of-loop, post-park shutdown
    //     check therefore raced last-handle drops: the loop could park forever
    //     (task + sockets leaked) or defer the goodbye to some unrelated later
    //     wake. Settling pre-park makes the last-handle exit deterministic and
    //     independent of whether that notify was delivered.
    //
    //     The sweep (1a-pre) already began a withdrawal for every cancelled
    //     service; drive `drain_withdrawals` and sleep on the next withdrawal
    //     deadline (`poll_deadline`, which folds in the endpoint's withdrawal
    //     `next_at`/`ceiling_at` via `poll_timeout`) until none remains. Each
    //     withdrawal finishes when its resend budget is spent OR at its 2 s
    //     anti-pin ceiling, so this terminates; a wall-clock backstop guards
    //     against a clock anomaly so the task can never hang.
    if Rc::strong_count(&inner) == 1 {
      let shutdown_deadline = StdInstant::now() + Duration::from_secs(10);
      loop {
        drain_withdrawals(&inner, &sock_v4, &sock_v6, &mut scratch).await;
        // Sweep any service whose handle dropped since the last pass — INCLUDING
        // one that raced the awaited drain above — into a withdrawal BEFORE
        // deciding whether any remain. The 1a-pre sweep only ran for cancellations
        // seen up to the main-loop park; a last-handle drop during this shutdown
        // drain would otherwise be GC'd with no §10.1 goodbye, leaking a
        // positive-TTL record — the exact teardown this refactor protects. Idempotent: a service already withdrawing is skipped.
        inner
          .state
          .borrow_mut()
          .sweep_cancelled_services(StdInstant::now());
        let now = StdInstant::now();
        // Sleep on (and exit when there are no) WITHDRAWAL deadlines only — NOT
        // the aggregate `poll_deadline`, which folds in cache expiry and query
        // timers. Otherwise, once every goodbye is sent, a still-populated cache
        // would keep this flush parked until that unrelated deadline (or the 10 s
        // backstop) instead of exiting promptly.
        let Some(next) = ({ inner.state.borrow().next_withdrawal_deadline() }) else {
          break;
        };
        if now >= shutdown_deadline {
          hick_trace::debug!("shutdown withdrawal flush hit its wall-clock backstop; exiting");
          break;
        }
        let dur = next
          .saturating_duration_since(now)
          .min(shutdown_deadline.saturating_duration_since(now));
        if dur > Duration::ZERO {
          compio::time::sleep(dur).await;
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

/// Map a PRESENT (bound) family's `send_to` result to its per-family withdrawal
/// outcome: `Ok` → [`WithdrawalSend::Sent`] (spend one owed round); ANY
/// `Err` → [`WithdrawalSend::Retry`] (keep the debt, retry until success or the
/// 2 s ceiling).
///
/// The classification is deliberately NOT by `io::ErrorKind`: a BOUND UDP socket
/// can fail transiently with a kind other than `WouldBlock`/`Interrupted` (e.g.
/// `ENOBUFS` buffer pressure, transient route/interface churn). Writing such a
/// family off would zero its goodbye debt and free the route as soon as the OTHER
/// family drained, leaving this family's peers pinned to stale positive-TTL
/// records. [`WithdrawalSend::WriteOff`] is reserved for an ABSENT socket (handled
/// by the caller, which only invokes this for a present one); the ceiling is the
/// backstop for a genuinely-wedged bound socket.
fn present_socket_send_outcome<T>(res: &std::io::Result<T>) -> WithdrawalSend {
  match res {
    Ok(_) => WithdrawalSend::Sent,
    Err(_) => WithdrawalSend::Retry,
  }
}

/// Pump every DUE endpoint-owned RFC 6762 §10.1 withdrawal goodbye once, fanning
/// each out to both bound multicast families, then free + GC every completed
/// withdrawal.
///
/// Borrow discipline (mirrors the run loop's transmit pump): pull ONE due
/// `(dst, len, handle)` under a brief `borrow_mut` (`poll_one_withdrawal` encodes
/// the goodbye into `scratch`), send `scratch[..len]` to BOTH families under NO
/// borrow, then under another brief borrow report the result via
/// `note_withdrawal_result` and bump per-round stats. `dst` is always the IPv4
/// multicast marker; the driver fans to every bound family regardless. The
/// endpoint owns the resend schedule — a delivered round spends one resend; a
/// fully-failed round is re-armed (short backoff) WITHOUT spending — so this
/// drains at most one round per withdrawal per call and cannot busy-spin.
///
/// After the pump, `drain_completed_withdrawals` frees each completed route
/// (decrementing `services_active`) and GCs its driver ctx UNCONDITIONALLY. The
/// terminal `Conflict` lives in the handle-owned mailbox (which outlives the ctx),
/// so it survives a withdrawal completing in the same iteration that began it
/// without any GC-defer.
///
/// Per-family [`WithdrawalSend`] is mapped by socket PRESENCE, not error kind:
///   * present socket, `Ok` → [`WithdrawalSend::Sent`] (spend one owed round);
///   * present socket, ANY `Err` → [`WithdrawalSend::Retry`] (keep the debt and
///     retry until success or the 2 s ceiling). A BOUND UDP socket can fail
///     transiently (e.g. `ENOBUFS` buffer pressure, route/interface churn) with an
///     error kind other than `WouldBlock`/`Interrupted`; treating those as a
///     permanent write-off would free the route after the OTHER family drains and
///     leave this family's peers pinned to stale positive-TTL records. The ceiling
///     is the backstop for a genuinely-wedged bound socket;
///   * absent socket (family not bound) → [`WithdrawalSend::WriteOff`] (no reachable
///     peers on it), so its debt never pins the withdrawal past the other family.
async fn drain_withdrawals(
  inner: &Rc<EndpointInner>,
  sock_v4: &Option<Rc<Socket>>,
  sock_v6: &Option<Rc<Socket>>,
  scratch: &mut [u8],
) {
  loop {
    let due = {
      let mut s = inner.state.borrow_mut();
      let now = StdInstant::now();
      s.poll_one_withdrawal(now, scratch)
    };
    let Some((_dst, len, token)) = due else {
      break;
    };
    // Fan out to every bound family on the mDNS multicast group.
    // Capture `when` BEFORE each `.await` (completion-I/O equivalent of
    // stamping at the syscall) so `when <= kernel_send_time <= echo_rx_time`
    // and the kernel-looped goodbye stays inside the 1 ms Ordered self-send
    // match window.
    // Per-family outcome is load-bearing (not stats-only): the endpoint tracks
    // per-family debt, so a withdrawal frees only once EVERY reachable family
    // has withdrawn its records. A family with no bound socket is `WriteOff` (no
    // peers reachable on it to withdraw from) so its debt never pins the other.
    let mut v4_out = WithdrawalSend::WriteOff;
    let mut v6_out = WithdrawalSend::WriteOff;
    if let Some(s4) = sock_v4.as_ref() {
      let when = SystemTime::now();
      let res = s4.send_to(&scratch[..len], MDNS_V4_DST, None).await;
      // Present socket: Ok → Sent, ANY Err → Retry (never WriteOff). See
      // `present_socket_send_outcome`.
      v4_out = present_socket_send_outcome(&res);
      match res {
        Ok(_) => {
          hick_trace::trace!(dst = %MDNS_V4_DST, len, "withdrawal send_to v4");
          let mut state = inner.state.borrow_mut();
          crate::selfsend::record_self_send(&mut state.recent_sends, &scratch[..len], when);
          #[cfg(feature = "stats")]
          {
            state.stats.packets_tx(1);
            state.stats.bytes_tx(len as u64);
          }
        }
        Err(_e) => {
          hick_trace::debug!(error = %_e, dst = %MDNS_V4_DST, "withdrawal send_to v4 failed");
          #[cfg(feature = "stats")]
          inner.state.borrow().stats.send_errors(1);
        }
      }
    }
    if let Some(s6) = sock_v6.as_ref() {
      let when = SystemTime::now();
      let res = s6.send_to(&scratch[..len], MDNS_V6_DST, None).await;
      // Present socket: Ok → Sent, ANY Err → Retry (never WriteOff). See
      // `present_socket_send_outcome`.
      v6_out = present_socket_send_outcome(&res);
      match res {
        Ok(_) => {
          hick_trace::trace!(dst = %MDNS_V6_DST, len, "withdrawal send_to v6");
          let mut state = inner.state.borrow_mut();
          crate::selfsend::record_self_send(&mut state.recent_sends, &scratch[..len], when);
          #[cfg(feature = "stats")]
          {
            state.stats.packets_tx(1);
            state.stats.bytes_tx(len as u64);
          }
        }
        Err(_e) => {
          hick_trace::debug!(error = %_e, dst = %MDNS_V6_DST, "withdrawal send_to v6 failed");
          #[cfg(feature = "stats")]
          inner.state.borrow().stats.send_errors(1);
        }
      }
    }
    // Count the goodbye as a delivered round when at least one family Sent;
    // `send_to` already bumped packets_tx/bytes_tx/send_errors per family above.
    #[cfg(feature = "stats")]
    if matches!(v4_out, WithdrawalSend::Sent) || matches!(v6_out, WithdrawalSend::Sent) {
      inner.state.borrow().stats.goodbyes_tx(1);
    }
    // The endpoint spends a resend per Sent family + re-arms at WITHDRAWAL_INTERVAL
    // on a round with progress; a no-send round re-arms at the short backoff with
    // the family's budget intact (busy → Retry) or written off (permanent error).
    {
      let now = StdInstant::now();
      inner
        .state
        .borrow_mut()
        .note_withdrawal_result(token, now, v4_out, v6_out);
    }
  }
  // Free + GC every completed withdrawal (budget spent or 2 s ceiling reached).
  // GC'ing a ctx whose updates drained wakes any handle parked on an
  // otherwise-idle endpoint to observe its end-of-stream (the cancelled/errored
  // ctx is gone → `Service::next` returns `None`).
  let gcd_any = {
    let now = StdInstant::now();
    inner.state.borrow_mut().drain_completed_withdrawals(now)
  };
  if gcd_any {
    inner.notify.notify();
  }
}

#[inline]
fn handle_recv(inner: &Rc<EndpointInner>, r: std::io::Result<(Vec<u8>, RecvMeta)>) {
  match r {
    Ok((data, meta)) => {
      hick_trace::trace!(src = %meta.peer(), len = data.len(), truncated = meta.truncated(), "recv datagram");
      if meta.truncated() {
        // The datagram exceeded `max_recv_packet_size` (it overflowed the
        // one-byte sentinel the recv buffer is over-allocated by), so the
        // kernel silently truncated it. compio-net does not expose
        // `msg_flags`/`MSG_TRUNC` directly; the sentinel-overflow heuristic is
        // the best proxy available.
        //
        // Count as consumed (packets_rx + bytes_rx) but also dropped — feeding
        // the truncated prefix to proto could trigger protocol side effects from
        // an incomplete message. Do NOT call handle_datagram.
        hick_trace::debug!(
          src = %meta.peer(),
          len = data.len(),
          "dropping truncated (oversized) datagram before proto routing"
        );
        #[cfg(feature = "stats")]
        {
          let s = inner.state.borrow();
          s.stats.packets_rx(1);
          s.stats.bytes_rx(data.len() as u64);
          s.stats.packets_dropped(1);
        }
        return;
      }
      // NOTE: packets_rx / bytes_rx are bumped by ProtoEndpoint::handle()
      // on the shared Arc — do NOT bump them here too (double-count).
      let mut s = inner.state.borrow_mut();
      s.handle_datagram(&meta, &data);
    }
    Err(_e) => {
      // A generic recv error is a socket/driver failure — NOT a consumed-and-
      // dropped datagram — so do NOT count it as packets_dropped.  Only known
      // consumed-unusable datagrams (oversized/truncated/InvalidData) map to
      // packets_dropped, matching the reactor recv-error accounting.
      hick_trace::debug!(error = %_e, "socket recv failed");
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

  /// regression: a PRESENT (bound) family's `send_to` failure
  /// must map to `Retry` (keep the debt, retry until the 2 s ceiling), NOT
  /// `WriteOff`. A bound UDP socket can return transient errors whose kind is
  /// NOT `WouldBlock`/`Interrupted` (e.g. `ENOBUFS`, route/interface churn);
  /// writing that family off would free the route once the OTHER family drained
  /// and strand this family's peers on stale positive-TTL records. `WriteOff` is
  /// reserved for an ABSENT socket (the caller's `let mut … = WriteOff` default),
  /// never produced by this present-socket classifier.
  #[test]
  fn present_socket_send_error_is_retry_not_writeoff() {
    // Ok → Sent.
    assert_eq!(
      present_socket_send_outcome::<usize>(&Ok(42)),
      WithdrawalSend::Sent,
    );
    // Every non-WouldBlock/Interrupted error kind a bound socket might surface
    // must still be Retry (NEVER WriteOff).
    for kind in [
      std::io::ErrorKind::WouldBlock,
      std::io::ErrorKind::Interrupted,
      std::io::ErrorKind::OutOfMemory, // stands in for ENOBUFS buffer pressure
      std::io::ErrorKind::AddrNotAvailable, // transient interface/route churn
      std::io::ErrorKind::PermissionDenied,
      std::io::ErrorKind::Other,
    ] {
      let res: std::io::Result<usize> = Err(std::io::Error::from(kind));
      assert_eq!(
        present_socket_send_outcome(&res),
        WithdrawalSend::Retry,
        "a present (bound) socket error ({kind:?}) must be Retry, not WriteOff"
      );
    }
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
    assert!(s.completed_withdrawals.is_empty());
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

  /// A short datagram (3 bytes, QR=1 set) from a non-5353 source must hit the
  /// untrusted-response pre-drop path and count packets_rx +1, bytes_rx +len,
  /// packets_dropped +1 — with NO double-count (proto's handle() is never
  /// reached). Drives `State::handle_datagram` directly; no socket bind needed.
  #[cfg(feature = "stats")]
  #[test]
  fn pre_drop_short_qr1_counts_rx_and_dropped_exactly_once() {
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::socket::RecvMeta;
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    // Make the source address on-link (loopback subnet) so only the untrusted-
    // response gate fires, not the §11 off-link gate.
    s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
    s.bound_interface = 1;

    // 3-byte body: byte 2 = 0x80 → QR=1. Too short for a valid DNS message.
    let data: Vec<u8> = vec![0x00, 0x00, 0x80];
    let len = data.len() as u64;

    let meta = RecvMeta::new(
      SocketAddr::from(([127, 0, 0, 1], 40000)), // non-5353 source port → untrusted
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      1,
      Some(255), // on-link TTL
      None,
      len as usize,
    );
    s.handle_datagram(&meta, &data);

    let snap = s.stats.snapshot();
    assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
    assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
    assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
  }

  /// A well-formed 12-byte DNS response header (QR=1) from a non-5353 source
  /// must count packets_rx +1, bytes_rx +len, packets_dropped +1 exactly once.
  /// Self-send credit ring must remain untouched.
  #[cfg(feature = "stats")]
  #[test]
  fn pre_drop_untrusted_qr1_response_counts_rx_and_dropped_exactly_once() {
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::socket::RecvMeta;
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
    s.bound_interface = 1;

    // Minimal 12-byte DNS response header: QR=1 + AA (byte 2 = 0x84).
    let data: Vec<u8> = vec![
      0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let len = data.len() as u64;

    assert!(s.recent_sends.is_empty(), "no prior self-send credits");

    let meta = RecvMeta::new(
      SocketAddr::from(([127, 0, 0, 1], 54321)), // non-5353 → untrusted
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      1,
      Some(255), // on-link
      None,
      len as usize,
    );
    s.handle_datagram(&meta, &data);

    // Self-send tracker must be untouched (never reached).
    assert!(
      s.recent_sends.is_empty(),
      "self-send credit ring must be untouched"
    );

    let snap = s.stats.snapshot();
    assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
    assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
    assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
  }

  /// Off-link datagrams (TTL ≠ 255, source outside local subnets) must count
  /// packets_rx +1, bytes_rx +len, packets_dropped +1 exactly once.
  #[cfg(feature = "stats")]
  #[test]
  fn pre_drop_off_link_datagram_counts_rx_and_dropped_exactly_once() {
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::socket::RecvMeta;
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
    s.bound_interface = 1;

    // QR=0 query body — so only the §11 off-link gate fires, not the untrusted-
    // response gate.
    let data: Vec<u8> = vec![
      0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let len = data.len() as u64;

    let meta = RecvMeta::new(
      SocketAddr::from(([203, 0, 113, 5], 5353)),
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      1,
      Some(64), // off-link: TTL != 255
      None,
      len as usize,
    );
    s.handle_datagram(&meta, &data);

    let snap = s.stats.snapshot();
    assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
    assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
    assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
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

  /// Drive a service through probe + announce until it advertises its host
  /// record (goodbye ownership latched), so a withdrawal snapshot is non-empty.
  /// Shared by the State-seam withdrawal tests below.
  #[cfg(test)]
  fn establish_service(
    s: &mut State,
    handle: ServiceHandle,
    t0: std::time::Instant,
  ) -> std::time::Instant {
    let mut t = t0;
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
      "service must advertise at least one record before withdrawal"
    );
    t
  }

  /// `begin_service_withdrawal` MUST: (a) KEEP the driver-side `ServiceCtx`
  /// (marked `errored`) so a queued `Conflict` still reaches the host, (b) hold
  /// the proto-layer route (so a same-name re-register is rejected) while the
  /// withdrawal is in flight, and (c) on completion (`drain_completed_withdrawals`)
  /// free the route + GC the ctx so the same instance name is re-registerable —
  /// the RFC 6762 §10.1 graceful-withdrawal contract under the endpoint-owned
  /// lifecycle. (The TTL=0 goodbye bytes + sibling retention + resend schedule are
  /// covered by the proto-level withdrawal tests; this is the driver-State seam.)
  #[test]
  fn begin_service_withdrawal_holds_name_then_frees_on_completion() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec, error::RegisterServiceError};

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let t0 = std::time::Instant::now();

    let stype = Name::try_from_str("_gb._tcp.local.").unwrap();
    let inst = Name::try_from_str("G._gb._tcp.local.").unwrap();
    let host = Name::try_from_str("g.local.").unwrap();
    let mut recs = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 1234, 120);
    recs.add_a([127, 0, 0, 1].into());
    let handle = s.test_register_service(ServiceSpec::new(recs), t0).unwrap();
    let mut t = establish_service(&mut s, handle, t0);

    // Begin the withdrawal: the ctx is KEPT (errored) and the route is held.
    s.begin_service_withdrawal(handle, t);
    assert!(
      s.services.get(&handle).map(|c| c.errored).unwrap_or(false),
      "begin_service_withdrawal must keep the ctx and mark it errored"
    );

    // While the withdrawal holds the route, the same instance name is rejected.
    let mut dup = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 1234, 120);
    dup.add_a([127, 0, 0, 1].into());
    assert!(
      matches!(
        s.test_register_service(ServiceSpec::new(dup), t),
        Err(RegisterServiceError::NameAlreadyRegistered(_))
      ),
      "a same-name registration must be rejected while the withdrawal holds the name"
    );

    // Drive the withdrawal to completion. With no sockets every round fails to
    // deliver (`poll_one_withdrawal` writes the goodbye; we report not-delivered),
    // so the endpoint force-completes at its 2 s anti-pin ceiling; then
    // `drain_completed_withdrawals` frees the route + GCs the ctx.
    let mut scratch = vec![0u8; 4096];
    let mut completed = false;
    for _ in 0..64 {
      t += Duration::from_millis(250);
      while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
        // No sockets bound in this State-level test: model BOTH families as
        // transiently undeliverable (Retry) so the per-family budget stays intact
        // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
        // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
        // instead, defeating the ceiling assertion.)
        s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
      }
      s.drain_completed_withdrawals(t);
      if !s.services.contains_key(&handle) {
        completed = true;
        break;
      }
    }
    assert!(
      completed,
      "the withdrawal must complete (route freed + driver ctx GC'd) by its 2 s \
       anti-pin ceiling when no family can deliver"
    );

    // The proto-layer route slot must now be freed: re-registering the same
    // instance name must succeed.
    let mut recs2 = ServiceRecords::new(stype, inst, host, 1234, 120);
    recs2.add_a([127, 0, 0, 1].into());
    assert!(
      s.test_register_service(ServiceSpec::new(recs2), t).is_ok(),
      "the proto-layer route slot must be freed once the withdrawal completes"
    );
  }

  /// `Service::drop` must NOT retire the service synchronously — it only flags
  /// `cancelled` (via `flag_service_unregistered`). The driver's post-pump
  /// `sweep_cancelled_services` is what begins the endpoint-owned §10.1
  /// withdrawal. This split is load-bearing: it lets a send that was in flight
  /// when the handle dropped latch its records (via `note_service_transmit_result`)
  /// BEFORE the withdrawal snapshot is taken, so a service dropped mid-send still
  /// withdraws every record it actually put on the wire.
  #[compio::test]
  async fn drop_defers_withdrawal_to_driver_sweep() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec};
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let t0 = std::time::Instant::now();
    let stype = Name::try_from_str("_sw._tcp.local.").unwrap();
    let inst = Name::try_from_str("s._sw._tcp.local.").unwrap();
    let host = Name::try_from_str("s.local.").unwrap();
    let mut recs = ServiceRecords::new(stype, inst, host, 1234, 120);
    recs.add_a([127, 0, 0, 1].into());
    let handle = s.test_register_service(ServiceSpec::new(recs), t0).unwrap();
    let t = establish_service(&mut s, handle, t0);

    // What `Service::drop` does — flag only, no retirement.
    s.flag_service_unregistered(handle);
    assert!(
      s.services.contains_key(&handle),
      "drop must NOT remove the service synchronously"
    );
    assert!(
      !s.services.get(&handle).map(|c| c.errored).unwrap_or(true),
      "drop must NOT begin the withdrawal synchronously — the driver sweep does"
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
    // is what guarantees the next iteration sweeps + begins the withdrawal.
    assert!(
      s.has_pending_withdrawal(),
      "a cancelled-but-unswept service must report a pending withdrawal"
    );

    // What the driver's post-pump sweep does — begin the endpoint-owned
    // withdrawal: the ctx is KEPT (errored) and the route is held by the endpoint.
    let swept = s.sweep_cancelled_services(t);
    assert!(swept, "sweep must report it retired a cancelled service");
    assert!(
      s.services.get(&handle).map(|c| c.errored).unwrap_or(false),
      "sweep must begin the withdrawal (ctx kept, marked errored)"
    );
    assert!(
      !s.has_pending_withdrawal(),
      "after the sweep the cancelled service is already withdrawing (errored), so \
       it is no longer reported as an unswept pending withdrawal"
    );
  }

  /// Regression: a service handle dropped AFTER the normal
  /// cancellation sweep — racing the last-handle shutdown drain — must still be
  /// swept into a §10.1 withdrawal. The shutdown loop now sweeps each iteration
  /// (after the drain, before deciding whether any remain), so the raced drop is
  /// never GC'd without its TTL=0 goodbye.
  #[test]
  fn shutdown_loop_sweeps_a_drop_that_raced_the_prior_sweep() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec};
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let t = std::time::Instant::now();

    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("Svc._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let a = s.test_register_service(ServiceSpec::new(recs), t).unwrap();

    // A normal sweep finds nothing — A's handle is still held.
    assert!(
      !s.sweep_cancelled_services(t),
      "nothing is cancelled before the drop"
    );

    // A's handle drops AFTER that sweep — the exact race the shutdown loop closes.
    s.flag_service_unregistered(a);
    assert!(
      s.has_pending_withdrawal(),
      "the post-sweep drop is an unswept pending withdrawal"
    );

    // The shutdown loop's per-iteration sweep retires the raced drop into a
    // withdrawal BEFORE deciding whether any remain — without it the loop would
    // exit and GC the service with no goodbye.
    assert!(
      s.sweep_cancelled_services(t),
      "the shutdown-loop sweep retires the raced cancellation"
    );
    assert!(
      s.next_withdrawal_deadline().is_some(),
      "a withdrawal now exists for the raced drop — not GC'd goodbye-less"
    );
  }

  /// Regression: a service DROPPED with an undrained
  /// update (e.g. an `Established` the app never read) must still be GC'd when its
  /// withdrawal completes. The ctx GC is now UNCONDITIONAL — there is no
  /// pending-update defer arm to leak the slot — and the undrained update lives in
  /// the handle-owned mailbox, so discarding the (dropped) handle's mailbox loses
  /// nothing. This closes the original leak class at the root: the `services`
  /// map cannot grow without bound under register/establish/drop churn.
  #[test]
  fn dropped_ctx_with_undrained_update_is_gc_d_not_leaked() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec};
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let t = std::time::Instant::now();

    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("Svc._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let a = s.test_register_service(ServiceSpec::new(recs), t).unwrap();

    // An update the app never drained (it dropped the handle without reading). It
    // lives in the handle-owned mailbox now, not the ctx.
    s.services
      .get(&a)
      .unwrap()
      .mailbox
      .borrow_mut()
      .push_update(ServiceUpdate::Established);

    // Drop the handle (cancel) WITHOUT draining the update; the driver sweep then
    // begins the (empty, never-announced) withdrawal, which completes on the first
    // drain.
    s.flag_service_unregistered(a);
    s.sweep_cancelled_services(t);
    s.drain_completed_withdrawals(t);

    assert!(
      !s.services.contains_key(&a),
      "a cancelled ctx with an undrained update must be GC'd UNCONDITIONALLY on \
       withdrawal completion, never deferred and leaked"
    );
  }

  /// Regression: a ctx
  /// whose withdrawal already completed and is THEN dropped must be GC'd — and its
  /// terminal `Conflict`, recorded in the HANDLE-OWNED mailbox, must STILL be
  /// observable by a live reader. The mailbox outlives the ctx, so unconditional
  /// ctx GC at withdrawal completion cannot lose the terminal: a still-live
  /// `Service` handle drains it. This is the observable property the old
  /// `route_freed` drop-GC defer existed to protect, now structural.
  #[test]
  fn completed_ctx_gc_keeps_terminal_observable_by_live_reader() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec};
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let t = std::time::Instant::now();

    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("Svc._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let a = s.test_register_service(ServiceSpec::new(recs), t).unwrap();

    // The live reader's clone of the handle-owned mailbox (what the `Service`
    // handle holds). The internal retirement records the terminal `Conflict` here.
    let reader_mailbox = Rc::clone(&s.services.get(&a).unwrap().mailbox);

    // Simulate an internally-retired service: record the terminal `Conflict` in
    // the reserved slot and begin its (empty, never-announced) withdrawal, which
    // completes on the first drain.
    reader_mailbox
      .borrow_mut()
      .set_terminal(ServiceUpdate::Conflict);
    s.begin_service_withdrawal(a, t);
    s.drain_completed_withdrawals(t);

    // The ctx is GC'd UNCONDITIONALLY on completion (no defer) ...
    assert!(
      !s.services.contains_key(&a),
      "the completed ctx is GC'd unconditionally — no pending-terminal defer"
    );
    // ... yet the reserved `Conflict` is STILL observable by the live reader,
    // because the mailbox is handle-owned and outlives the ctx.
    assert!(
      matches!(
        reader_mailbox.borrow_mut().drain_for_test(),
        Some(ServiceUpdate::Conflict)
      ),
      "the terminal Conflict must survive the immediate ctx GC and be drainable \
       by a live reader (mailbox outlives the ctx)"
    );
  }

  /// Task-required: a FULL non-terminal ring plus a reserved terminal must both
  /// survive an immediate ctx GC and be fully drainable by a live reader. Fill the
  /// ring to the cap WITHOUT draining, `set_terminal(Conflict)`, complete the
  /// withdrawal so the ctx is GC'd immediately, then drain from the live handle —
  /// the `Conflict` IS observed and the ctx is gone from `services`.
  #[test]
  fn terminal_survives_full_mailbox_and_immediate_ctx_gc() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec};
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let t = std::time::Instant::now();

    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("Svc._ipp._tcp.local.").unwrap(),
      Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    let a = s.test_register_service(ServiceSpec::new(recs), t).unwrap();

    // The live reader's clone of the handle-owned mailbox.
    let reader_mailbox = Rc::clone(&s.services.get(&a).unwrap().mailbox);

    // Fill the non-terminal ring to the cap (no draining) and reserve the terminal.
    {
      let mut mb = reader_mailbox.borrow_mut();
      mb.fill_non_terminal_to_cap_for_test();
      mb.set_terminal(ServiceUpdate::Conflict);
      assert_eq!(
        mb.non_terminal_len(),
        crate::service::SERVICE_UPDATE_CAPACITY,
        "the non-terminal ring is full"
      );
      assert!(mb.has_terminal(), "the terminal slot is reserved");
    }

    // Complete the (empty, never-announced) withdrawal so the ctx is GC'd at once.
    s.begin_service_withdrawal(a, t);
    s.drain_completed_withdrawals(t);
    assert!(
      !s.services.contains_key(&a),
      "the ctx must be gone from `services` after the withdrawal completes"
    );

    // Drain from the LIVE handle: every non-terminal first, then the reserved
    // Conflict — none lost to the immediate ctx GC.
    let mut non_terminal = 0usize;
    let mut got_terminal = false;
    while let Some(upd) = reader_mailbox.borrow_mut().drain_for_test() {
      match upd {
        ServiceUpdate::Conflict => got_terminal = true,
        _ => non_terminal += 1,
      }
    }
    assert_eq!(
      non_terminal,
      crate::service::SERVICE_UPDATE_CAPACITY,
      "every buffered non-terminal update survives the ctx GC"
    );
    assert!(
      got_terminal,
      "the reserved Conflict IS observed by the live reader after the immediate \
       ctx GC (mailbox is handle-owned and outlives the ctx)"
    );
  }

  /// Endpoint-owned-withdrawal replacement survival (supersedes the old free-name
  /// goodbye BARRIER test). Under `with_probe_unique_names(false)` a same-name
  /// replacement would announce a positive TTL directly (no §8.1 probe) — exactly
  /// the configuration in which a stale TTL=0 goodbye could be overtaken. The old
  /// compio driver enforced ordering with a pre-transmit barrier; the endpoint now
  /// enforces it STRUCTURALLY — it KEEPS the route (holding the name) for the whole
  /// §10.1 withdrawal, so a same-name `register_service` is REJECTED until the
  /// goodbye completes and frees the name. No replacement can announce ahead of the
  /// withdrawal because no replacement can even be registered until it is done.
  ///
  /// Driven through `State` directly (no sockets — the compio run loop cannot be
  /// stepped deterministically). The full graceful path is exercised:
  /// `flag_service_unregistered` (what `Service::drop` does) → the driver's
  /// `sweep_cancelled_services` (begins the withdrawal) → `poll_one_withdrawal` /
  /// `note_withdrawal_result` / `drain_completed_withdrawals` (the run loop's
  /// `drain_withdrawals`). With no bound family every round fails to deliver, so the
  /// withdrawal force-completes at its 2 s anti-pin ceiling; the name-held →
  /// name-freed observation is identical either way.
  #[test]
  fn same_name_replacement_is_rejected_until_withdrawal_completes() {
    use mdns_proto::{Name, ServiceRecords, ServiceSpec, error::RegisterServiceError};

    let cfg = mdns_proto::EndpointConfig::new().with_probe_unique_names(false);
    let mut s = State::new(cfg, 1500, 9000);
    let t0 = std::time::Instant::now();

    let mk = || {
      let mut r = ServiceRecords::new(
        Name::try_from_str("_ipp._tcp.local.").unwrap(),
        Name::try_from_str("repl._ipp._tcp.local.").unwrap(),
        Name::try_from_str("repl.local.").unwrap(),
        631,
        120,
      );
      r.add_a([192, 168, 1, 10].into());
      ServiceSpec::new(r)
    };

    // 1. Register A and drive it to an announced state so its withdrawal snapshot
    //    is non-empty (records were confirmed-emitted).
    let a = s.test_register_service(mk(), t0).unwrap();
    let mut t = establish_service(&mut s, a, t0);

    // 2. Drop A: flag cancelled (what `Service::drop` does), then the driver's
    //    post-pump sweep begins the endpoint-owned withdrawal (name held).
    s.flag_service_unregistered(a);
    s.sweep_cancelled_services(t);
    assert!(
      s.services.get(&a).map(|c| c.errored).unwrap_or(false),
      "the sweep must begin the withdrawal and keep the ctx (errored)"
    );

    // 3. While the withdrawal is in flight the SAME name must be rejected.
    assert!(
      matches!(
        s.test_register_service(mk(), t),
        Err(RegisterServiceError::NameAlreadyRegistered(_))
      ),
      "a same-name registration must be rejected while the withdrawal holds the name"
    );

    // 4. Drive the withdrawal to completion (no family → force-finished at the 2 s
    //    anti-pin ceiling); `drain_completed_withdrawals` then frees the route + GCs
    //    the ctx.
    let mut scratch = vec![0u8; 4096];
    let mut completed = false;
    for _ in 0..64 {
      t += Duration::from_millis(250);
      while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
        // No sockets bound in this State-level test: model BOTH families as
        // transiently undeliverable (Retry) so the per-family budget stays intact
        // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
        // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
        // instead, defeating the ceiling assertion.)
        s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
      }
      s.drain_completed_withdrawals(t);
      if !s.services.contains_key(&a) {
        completed = true;
        break;
      }
    }
    assert!(
      completed,
      "the withdrawal must complete (route freed + driver ctx GC'd) by its 2 s \
       anti-pin ceiling when no family can deliver"
    );

    // 5. The name is freed → a same-name replacement now registers successfully.
    s.test_register_service(mk(), t)
      .expect("the same name must be re-registerable once the withdrawal completes");
  }

  // NOTE: the driver-goodbye-queue + barrier seam tests
  // (`remove_service_queues_goodbye_and_frees_proto_slot`,
  // `shutdown_drain_sweeps_and_flushes_all_bursts`, `poll_deadline_sees_pending_goodbye`,
  // `goodbye_round_with_no_send_keeps_budget_and_backs_off`,
  // `goodbye_round_with_a_send_spends_one_and_clears_barrier`, and
  // `gc_force_clears_expired_barrier_and_drops_sent_entries`) were REMOVED in the
  // endpoint-owned-withdrawal migration. They asserted against the deleted
  // driver-side `goodbyes` queue + `sent_once` transmit barrier (the `PendingGoodbye`
  // struct, `advance_goodbye_after_send` Part-A re-arm, the `gc_goodbyes` `expires_at`
  // anti-pin force-clear, `has_pending_barrier`, `take_shutdown_goodbyes`, and the
  // `poll_deadline` goodbye loop). The endpoint now owns the resend schedule, the
  // spend/re-arm bookkeeping, the 2 s anti-pin ceiling, and the goodbye-deadline
  // contribution to `poll_timeout` — covered by the proto-level withdrawal tests
  // (`note_withdrawal_result` spend/backoff, `drain_completed_withdrawals` ceiling,
  // `poll_withdrawal_transmit` sibling retention). The
  // `begin_service_withdrawal_holds_name_then_frees_on_completion` test above is the
  // driver-State-seam observation that a withdrawal HOLDS the name and frees it on
  // completion, and `drop_defers_withdrawal_to_driver_sweep` covers the deferred-
  // snapshot timing the old `drop_defers_goodbye_to_driver_sweep` test guarded.

  // The per-kind coalescing + drop-oldest backstop + reserved-terminal contract
  // now lives in `crate::service::ServiceMailbox`; its unit tests
  // (`mailbox_coalesces_established_and_renamed_by_kind`,
  // `mailbox_rename_churn_coalesces_within_cap`, `mailbox_hard_cap_drops_oldest`,
  // `mailbox_terminal_reserved_under_non_terminal_pressure`, …) own that surface.
  // The driver-side `push_service_update_coalesced` free function + its
  // `coalesce_*` tests were removed in the handle-owned-mailbox migration: the
  // driver now routes proto updates straight into the mailbox
  // (`push_update` for non-terminal kinds, `set_terminal` for Conflict/HostConflict),
  // so there is no driver-local deque to coalesce.

  /// transmit-liveness regression: a service whose records cannot be
  /// encoded into the configured `max_payload` must NOT silently stall. The
  /// proto PRESERVES the un-encodable pending transmit (re-offering it every
  /// `poll_transmit`), so the prior `if let Ok(Some(_))` arm — which treated the
  /// `Err(TransmitError::BufferTooSmall)` like `Ok(None)` — left the service
  /// stuck below `Established` forever with no `ServiceUpdate` ever delivered.
  ///
  /// The fix counts consecutive encode failures per service and, at
  /// [`MAX_CONSECUTIVE_ENCODE_ERRORS`], escalates to `ServiceUpdate::Conflict`
  /// (recorded in the handle-owned mailbox's reserved terminal slot, NOT dropped)
  /// and flags the service `errored` so it is skipped by every later proto-polling
  /// pump. This test drives `poll_one_transmit` with a deliberately tiny scratch
  /// buffer and asserts: (a) the failure counter climbs one per call, (b) at the
  /// threshold the reserved terminal `Conflict` is set and `errored` is set, and
  /// (c) a subsequent `poll_one_transmit` skips the errored service (returns `None`
  /// when it's the only one) rather than re-polling its dead proto.
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
    let handle = s
      .test_register_service(ServiceSpec::new(recs), now)
      .unwrap();

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

    // At the threshold the service must be escalated: the reserved terminal
    // `Conflict` set in the handle-owned mailbox, and the terminal `errored` flag
    // set on the ctx.
    {
      let ctx = s.services.get(&handle).unwrap();
      assert!(
        ctx.errored,
        "reaching MAX_CONSECUTIVE_ENCODE_ERRORS must mark the service errored"
      );
      assert!(
        ctx.mailbox.borrow().has_terminal(),
        "the escalation must record a reserved-slot Conflict for Service::next"
      );
    }

    // A subsequent pump must SKIP the errored service. With it the only registered
    // service (and no queries), the result is `None` — proving the dead proto is
    // no longer re-polled (no busy-spin) and the counter is frozen.
    assert!(
      s.poll_one_transmit(now, &mut scratch).is_none(),
      "an errored service must be skipped by poll_one_transmit"
    );
    assert_eq!(
      s.services.get(&handle).unwrap().encode_failures,
      MAX_CONSECUTIVE_ENCODE_ERRORS,
      "a skipped errored service must not have its failure counter advanced further"
    );

    // The reserved `Conflict` is still drainable by the handle, and draining it
    // (then end-of-stream) is exactly what `Service::next` does.
    let mailbox = Rc::clone(&s.services.get(&handle).unwrap().mailbox);
    assert!(
      matches!(
        mailbox.borrow_mut().drain_for_test(),
        Some(ServiceUpdate::Conflict)
      ),
      "the reserved Conflict must remain readable by Service::next"
    );
    assert!(
      mailbox.borrow_mut().drain_for_test().is_none(),
      "after the terminal Conflict the mailbox reports end-of-stream"
    );
  }

  /// regression: when a service is retired by encode-failure escalation,
  /// `endpoint.unregister_service` must be called so the proto route is freed
  /// (`services_active == 0`) and the same service name can be re-registered.
  ///
  /// This mirrors the smoltcp test but drives `State::poll_one_transmit`
  /// directly (compio's analogue of the engine's `poll_one_transmit`). The
  /// compio driver counts consecutive encode failures up to
  /// `MAX_CONSECUTIVE_ENCODE_ERRORS` before escalating, unlike smoltcp which
  /// retires on the first failure.
  #[cfg(feature = "stats")]
  #[test]
  fn encode_failure_escalation_frees_proto_route_and_decrements_services_active() {
    use std::time::Duration;

    use mdns_proto::{Name, ServiceRecords, ServiceSpec};

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1, 9000);
    let now = std::time::Instant::now();

    let stype = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("F2Test._http._tcp.local.").unwrap();
    let host = Name::try_from_str("f2test.local.").unwrap();
    let mut recs = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 80, 120);
    recs.add_a([10, 0, 0, 1].into());
    let handle = s
      .test_register_service(ServiceSpec::new(recs), now)
      .unwrap();

    // Confirm services_active == 1 after registration.
    assert_eq!(
      s.stats.snapshot().services_active,
      1,
      "services_active must be 1 after registration"
    );

    // Prime until the first encode failure, then push to the escalation threshold.
    let mut scratch = [0u8; 1];
    let mut t = now;
    let mut armed = false;
    for _ in 0..40 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      s.poll_one_transmit(t, &mut scratch);
      if s.services.get(&handle).unwrap().encode_failures == 1 {
        armed = true;
        break;
      }
    }
    assert!(armed, "must reach the first encode failure");

    // Drive to the escalation threshold.
    for _ in 2..=MAX_CONSECUTIVE_ENCODE_ERRORS {
      s.poll_one_transmit(t, &mut scratch);
    }

    // The service must now be errored.
    assert!(
      s.services.get(&handle).unwrap().errored,
      "service must be errored after escalation"
    );
    // The terminal Conflict must be set in the handle-owned mailbox. Grab the
    // reader's clone now (it outlives the ctx GC below).
    let mailbox = Rc::clone(&s.services.get(&handle).unwrap().mailbox);
    assert!(
      mailbox.borrow().has_terminal(),
      "the escalation must record a reserved-slot Conflict for Service::next"
    );

    // The escalation began an endpoint-owned withdrawal. A service that never
    // reached Established has an EMPTY snapshot, so the withdrawal completes
    // immediately (`remaining == 0`) and `drain_completed_withdrawals` frees the
    // route AND GCs the ctx UNCONDITIONALLY on the next call (with no datagram on
    // the wire).
    s.drain_completed_withdrawals(t);

    // Proto route freed — services_active must be 0.
    assert_eq!(
      s.stats.snapshot().services_active,
      0,
      "services_active must be 0 after the encode-failure withdrawal completes (route freed)"
    );
    // The ctx is GC'd unconditionally on completion — but the terminal Conflict
    // survives in the handle-owned mailbox and is still drainable by a live reader.
    assert!(
      !s.services.contains_key(&handle),
      "the ctx must be GC'd unconditionally once its withdrawal completes"
    );
    assert!(
      matches!(
        mailbox.borrow_mut().drain_for_test(),
        Some(ServiceUpdate::Conflict)
      ),
      "the reserved Conflict survives the ctx GC and is drainable by Service::next"
    );

    // The same service name must be re-registerable (route was released).
    let mut recs2 = ServiceRecords::new(stype, inst, host, 80, 120);
    recs2.add_a([10, 0, 0, 2].into());
    s.test_register_service(ServiceSpec::new(recs2), t)
      .expect("same service name must be re-registerable after encode-failure withdrawal");

    assert_eq!(
      s.stats.snapshot().services_active,
      1,
      "services_active must be 1 after re-registration"
    );
  }

  /// regression: when service A escalates (encode-failure threshold
  /// reached) in the SAME `poll_one_transmit` call that service B returns an
  /// `Ok(Some)` transmit (causing the early-return), the proto route for A must
  /// still be freed immediately — not deferred to a post-loop drain that the
  /// early-return bypasses.
  ///
  /// The bug: the old code pushed retiring handles into `proto_unregister: Vec`
  /// and drained it AFTER the service loop. An `Ok(Some)` early-return for B
  /// exits the loop before the drain, permanently leaking A's proto route.
  ///
  /// The fix: `unregister_service` is called IN-ITERATION the moment A
  /// escalates (before the loop continues to B), so the early-return cannot
  /// bypass it.
  ///
  /// Setup: Service A has a large TXT record (> 1500 bytes) that cannot be
  /// encoded into the 1500-byte scratch, while B has small records that fit.
  /// This means A will always fail encode while B succeeds — the exact
  /// in-call mix that triggers the bypass in the buggy code.
  ///
  /// Verification: after `MAX_CONSECUTIVE_ENCODE_ERRORS` pumps, A is retired
  /// (services_active == 1, A's name re-registerable) while B is unaffected
  /// (services_active rises to 2 after re-registering A).
  #[cfg(feature = "stats")]
  #[test]
  fn multi_service_encode_failure_frees_route_even_with_sibling_transmit() {
    use std::time::Duration;

    use mdns_proto::{Name, ServiceRecords, ServiceSpec};

    // Use a 1500-byte scratch — big enough for B's probe (small records) but
    // not for A's probe (A has a large TXT that pushes the probe past 1500
    // bytes). This ensures every `poll_one_transmit` call:
    //   - visits A → Err (too large) → A escalates toward threshold
    //   - visits B → Ok(Some(t)) → early-return (the bypass scenario)
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let now = std::time::Instant::now();

    // Service A: the one that will encode-fail. A large TXT segment fills the
    // probe past the 1500-byte scratch ceiling so every poll_transmit Errs.
    let stype_a = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst_a = Name::try_from_str("Retire._http._tcp.local.").unwrap();
    let host_a = Name::try_from_str("retire.local.").unwrap();
    let mut recs_a = ServiceRecords::new(stype_a.clone(), inst_a.clone(), host_a.clone(), 80, 120);
    recs_a.add_a([10, 0, 0, 1].into());
    // A 255-byte TXT segment pushes A's probe well past the 1500-byte ceiling.
    recs_a.add_txt_segment(vec![b'x'; 255]);
    recs_a.add_txt_segment(vec![b'y'; 255]);
    recs_a.add_txt_segment(vec![b'z'; 255]);
    recs_a.add_txt_segment(vec![b'w'; 255]);
    recs_a.add_txt_segment(vec![b'v'; 255]);
    recs_a.add_txt_segment(vec![b'u'; 255]);
    let handle_a = s
      .test_register_service(ServiceSpec::new(recs_a), now)
      .unwrap();

    // Service B: small records that fit in the 1500-byte scratch.
    let stype_b = Name::try_from_str("_grpc._tcp.local.").unwrap();
    let inst_b = Name::try_from_str("Active._grpc._tcp.local.").unwrap();
    let host_b = Name::try_from_str("active.local.").unwrap();
    let mut recs_b = ServiceRecords::new(stype_b, inst_b.clone(), host_b.clone(), 443, 120);
    recs_b.add_a([10, 0, 0, 2].into());
    let handle_b = s
      .test_register_service(ServiceSpec::new(recs_b), now)
      .unwrap();

    // Both services registered: services_active == 2.
    assert_eq!(
      s.stats.snapshot().services_active,
      2,
      "both services registered: services_active must be 2"
    );

    // Pump with the 1500-byte scratch. Each call:
    //   - If A is visited first: Err (records too large) → A's counter increments
    //   - If B is visited first: Ok(Some) → early-return (bypass scenario)
    // In the BUGGY code (deferred Vec): when B causes an early-return AFTER A
    // escalates in the same call, A's route stays leaked (services_active stays 2).
    // In the FIXED code (in-iteration): A's unregister runs BEFORE the loop
    // continues to B, so the early-return cannot bypass it.
    let mut scratch = [0u8; 1500];
    let mut t = now;
    let mut a_retired = false;

    for _ in 0..40 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      let result = s.poll_one_transmit(t, &mut scratch);

      // Note any Ok(Some) result (should always be B's transmit, never A's
      // since A's records can't be encoded).
      if let Some((_, _, TransmitOrigin::Service(h))) = result {
        // The returned transmit MUST belong to B (A's records are too large).
        assert_eq!(
          h, handle_b,
          "any returned transmit must be from B, never from A (A's records won't encode)"
        );
        // Confirm B's delivery so B advances its probe/announce lifecycle.
        s.note_service_transmit_result(h, t, true);
      }

      // Check if A just escalated.
      if s
        .services
        .get(&handle_a)
        .map(|c| c.errored)
        .unwrap_or(false)
      {
        // fix: A's withdrawal was BEGUN in-iteration (non-bypassable), even
        // though B may have returned Ok(Some) in the same call. The route is now
        // HELD by the withdrawal, so services_active stays 2 (A withdrawing + B
        // live) — the route frees on withdrawal completion, asserted below.
        assert_eq!(
          s.stats.snapshot().services_active,
          2,
          "services_active must be 2 when A escalates (A's route held by its \
           in-iteration-begun withdrawal + B live), even if B returned Ok(Some) in \
           the same poll_one_transmit call (regression: deferred-drain bypass)"
        );
        a_retired = true;
        break;
      }
    }

    assert!(
      a_retired,
      "A must be retired by encode-failure escalation within 40 pumps"
    );

    // A's terminal Conflict must be recorded in the handle-owned mailbox for
    // Service::next to drain. Grab the reader's clone now (it outlives the GC).
    let a_mailbox = Rc::clone(&s.services.get(&handle_a).unwrap().mailbox);
    assert!(
      a_mailbox.borrow().has_terminal(),
      "A's reserved-slot Conflict must be set for Service::next"
    );

    // A never reached Established → its withdrawal snapshot is empty and completes
    // immediately; `drain_completed_withdrawals` frees A's route AND GCs its ctx
    // unconditionally. If the bug were present (escalation marked A errored but
    // its withdrawal was never begun), the route would leak and services_active
    // would stay 2 here. A's terminal Conflict survives in `a_mailbox` regardless.
    s.drain_completed_withdrawals(t);
    assert!(
      matches!(
        a_mailbox.borrow_mut().drain_for_test(),
        Some(ServiceUpdate::Conflict)
      ),
      "A's reserved Conflict survives its ctx GC and is drainable by Service::next"
    );
    assert_eq!(
      s.stats.snapshot().services_active,
      1,
      "services_active must be 1 once A's (empty) withdrawal completes (B still live)"
    );

    // A's name must now be re-registerable (proto route was freed).
    let mut recs_a2 = ServiceRecords::new(stype_a, inst_a, host_a, 80, 120);
    recs_a2.add_a([10, 0, 0, 3].into());
    s.test_register_service(ServiceSpec::new(recs_a2), t)
      .expect("A's name must be re-registerable after its in-iteration-begun withdrawal completes");

    // B is still live: services_active == 2 after re-registering A.
    assert_eq!(
      s.stats.snapshot().services_active,
      2,
      "services_active must be 2 after re-registering A (B still live)"
    );

    // B must not have been errored (its records fit the scratch).
    assert!(
      !s.services.get(&handle_b).map(|c| c.errored).unwrap_or(true),
      "B must not be errored — its small records encode successfully"
    );
  }

  /// regression (endpoint-owned-withdrawal form): when a service's
  /// auto-rename (§9 conflict) collides with another LOCAL service that already
  /// owns the candidate name, `push_service_updates` retires the colliding service
  /// into an endpoint-owned withdrawal. The endpoint HOLDS the route (reserving the
  /// old name) until the withdrawal completes, THEN frees it — so `services_active`
  /// is decremented and the old name becomes re-registerable on COMPLETION, not at
  /// the collision instant. A's `Conflict` lands in the handle-owned mailbox
  /// regardless.
  ///
  /// The original bug: the compio `push_service_updates` break'd out of the rename
  /// loop without retiring the service, leaking the proto route for the colliding
  /// service. The migration replaces the immediate `unregister_service` with
  /// `begin_service_withdrawal` (route held → freed on completion).
  ///
  /// Verification: after the collision A is errored + `Conflict` is queued and the
  /// route is still HELD (services_active stays 2, old name rejected); after
  /// driving the withdrawal to completion, services_active drops to 1 and A's old
  /// name is re-registerable.
  #[cfg(feature = "stats")]
  #[test]
  fn rename_collision_with_local_service_frees_proto_route() {
    use std::time::Duration;

    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::socket::RecvMeta;
    use mdns_proto::{
      Name, ServiceRecords, ServiceSpec,
      wire::{Header, MessageBuilder},
    };

    // Build an mDNS authority-section packet that claims our instance name
    // with different SRV rdata — this is the §8.2 conflict signal that forces
    // the proto to revert to probing and eventually rename.
    fn conflict_for(instance: &str) -> Vec<u8> {
      let mut buf = [0u8; 512];
      let name = Name::try_from_str(instance).unwrap();
      let target = Name::try_from_str("rival.local.").unwrap();
      let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
      b.push_srv_authority(&name, 120, 0, 0, 9999, &target)
        .unwrap();
      let n = b.finish().unwrap();
      buf[..n].to_vec()
    }

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    // Enable §11 on-link so injected datagrams are accepted.
    s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
    s.bound_interface = 1;

    let now = std::time::Instant::now();

    // Service A: "First._ipp._tcp.local." — will be driven to rename to "First (2)".
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst_a = Name::try_from_str("First._ipp._tcp.local.").unwrap();
    let host_a = Name::try_from_str("first.local.").unwrap();
    let mut recs_a = ServiceRecords::new(stype.clone(), inst_a.clone(), host_a.clone(), 80, 120);
    recs_a.add_a([192, 168, 1, 1].into());
    let handle_a = s
      .test_register_service(ServiceSpec::new(recs_a), now)
      .unwrap();

    // Service B: pre-register "First-1._ipp._tcp.local." so the rename
    // collision fires when A tries to rename to it.
    // The proto uses a `-N` suffix (rename_with_suffix): "First._ipp._tcp.local."
    // with rename_attempt=1 → "First-1._ipp._tcp.local.".
    let inst_b = Name::try_from_str("First-1._ipp._tcp.local.").unwrap();
    let host_b = Name::try_from_str("second.local.").unwrap();
    let mut recs_b = ServiceRecords::new(stype, inst_b, host_b, 80, 120);
    recs_b.add_a([192, 168, 1, 2].into());
    s.test_register_service(ServiceSpec::new(recs_b), now)
      .unwrap();

    // Both registered: services_active == 2.
    assert_eq!(
      s.stats.snapshot().services_active,
      2,
      "both services registered: services_active must be 2"
    );

    // Helper: pump all pending transmits and confirm delivery (mimics the
    // async driver loop's send + note_service_transmit_result round-trip).
    fn pump_transmits(s: &mut State, t: StdInstant, buf: &mut [u8]) {
      loop {
        match s.poll_one_transmit(t, buf) {
          Some((_, _, TransmitOrigin::Service(h))) => {
            s.note_service_transmit_result(h, t, true);
          }
          Some(_) => {}
          None => break,
        }
      }
    }

    // Establish A (and advance B) by driving probe + announce with confirmed
    // delivery so the lifecycle states advance properly.
    let a_mailbox = Rc::clone(&s.services.get(&handle_a).unwrap().mailbox);
    let mut buf = [0u8; 1500];
    let mut t = now;
    let mut a_established = false;
    for _ in 0..60 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      pump_transmits(&mut s, t, &mut buf);
      s.push_service_updates(t);
      // Drain the handle-owned mailbox (what Service::next reads); detect the
      // Established and discard the rest so a fresh Conflict is detectable below.
      while let Some(u) = a_mailbox.borrow_mut().drain_for_test() {
        if matches!(u, ServiceUpdate::Established) {
          a_established = true;
        }
      }
      if a_established {
        break;
      }
    }
    let _ = a_established;

    // Inject a peer conflict for "First._ipp._tcp.local." repeatedly until
    // `push_service_updates` drives A to rename and collide with B, at which point
    // A's terminal Conflict is set in the mailbox and A is flagged errored.
    let conflict = conflict_for("First._ipp._tcp.local.");
    let peer = RecvMeta::new(
      SocketAddr::from(([192, 168, 1, 200], 5353)),
      IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
      1,
      Some(255),
      None,
      conflict.len(),
    );
    let mut conflicted = false;
    for _ in 0..80 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      s.handle_datagram(&peer, &conflict);
      pump_transmits(&mut s, t, &mut buf);
      s.push_service_updates(t);

      if s
        .services
        .get(&handle_a)
        .map(|c| c.errored)
        .unwrap_or(false)
      {
        conflicted = true;
        break;
      }
    }

    assert!(
      conflicted,
      "A must be driven to rename-collision-Conflict within 60 iterations"
    );

    // A's route is HELD by the in-flight withdrawal — services_active stays 2
    // (B live + A withdrawing), and A's terminal Conflict is set for Service::next.
    assert_eq!(
      s.stats.snapshot().services_active,
      2,
      "services_active must still be 2 while A's rename-collision withdrawal holds \
       the route (B live + A withdrawing)"
    );
    assert!(
      a_mailbox.borrow().has_terminal(),
      "A's reserved-slot Conflict must be set for Service::next"
    );
    // The GC is UNCONDITIONAL now, so the ctx need not be drained first — but the
    // terminal Conflict survives in `a_mailbox` regardless (asserted after).

    // Drive A's withdrawal to completion (no sockets → force-finished at the 2 s
    // ceiling), then GC the freed ctx.
    let mut scratch = vec![0u8; 4096];
    let mut completed = false;
    for _ in 0..64 {
      t += Duration::from_millis(250);
      while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
        // No sockets bound in this State-level test: model BOTH families as
        // transiently undeliverable (Retry) so the per-family budget stays intact
        // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
        // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
        // instead, defeating the ceiling assertion.)
        s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
      }
      s.drain_completed_withdrawals(t);
      if !s.services.contains_key(&handle_a) {
        completed = true;
        break;
      }
    }
    assert!(completed, "A's rename-collision withdrawal must complete");

    // On completion the route is freed: services_active drops to 1 (B only).
    assert_eq!(
      s.stats.snapshot().services_active,
      1,
      "services_active must be 1 once A's withdrawal completes (B still live)"
    );
    // A's terminal Conflict survived the unconditional ctx GC and is drainable by
    // a live reader.
    assert!(
      matches!(
        a_mailbox.borrow_mut().drain_for_test(),
        Some(ServiceUpdate::Conflict)
      ),
      "A's reserved Conflict survives the ctx GC and is drainable by Service::next"
    );

    // A's old name must now be re-registerable (route was freed on completion).
    let mut recs_a2 = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      inst_a,
      host_a,
      80,
      120,
    );
    recs_a2.add_a([192, 168, 1, 10].into());
    s.test_register_service(ServiceSpec::new(recs_a2), t)
      .expect(
        "A's old name must be re-registerable once the rename-collision withdrawal completes",
      );
  }

  /// regression (endpoint-owned-withdrawal form): when an ANNOUNCED service A
  /// is driven to auto-rename and its candidate new name collides with a local
  /// service B, the proto hands off A's OLD instance name goodbye (TTL=0). The OLD
  /// driver stole that goodbye into its own queue before freeing the old name,
  /// then guarded against replaying it on A's drop. The endpoint now enforces this
  /// STRUCTURALLY: the driver takes the handoff and enqueues it as an INDEPENDENT
  /// detached withdrawal item (`Endpoint::enqueue_rename_withdrawal`) that HOLDS
  /// the OLD name for the whole withdrawal — so a replacement R cannot register
  /// (and evict the old name from peer caches) until that goodbye completes. The
  /// rename-collision teardown additionally begins an endpoint-owned withdrawal
  /// for the CURRENT name. No steal, no replay-guard needed.
  ///
  /// (That the proto hands off the OLD name's records + ownership is covered at the
  /// proto level by `conflict_rename_hands_off_old_announced_name`, and that the
  /// handoff becomes a detached item by
  /// `rename_enqueues_a_detached_withdrawal_for_the_old_name`.)
  ///
  /// Asserts:
  /// 1. After collision retirement A is errored + the endpoint holds the OLD name,
  ///    so a same-name re-register is rejected (`NameAlreadyRegistered`).
  /// 2. Once the withdrawal completes (route freed + ctx GC'd), the OLD name is
  ///    re-registerable — and re-registering R THEN does not depend on any
  ///    driver-side replayed goodbye.
  #[cfg(feature = "stats")]
  #[test]
  fn rename_collision_drains_old_name_goodbye_before_name_reuse() {
    use std::time::Duration;

    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::socket::RecvMeta;
    use mdns_proto::{
      Name, ServiceRecords, ServiceSpec,
      wire::{Header, MessageBuilder},
    };

    fn conflict_for(instance: &str) -> Vec<u8> {
      let mut buf = [0u8; 512];
      let name = Name::try_from_str(instance).unwrap();
      let target = Name::try_from_str("rival.local.").unwrap();
      let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
      b.push_srv_authority(&name, 120, 0, 0, 9999, &target)
        .unwrap();
      let n = b.finish().unwrap();
      buf[..n].to_vec()
    }

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
    s.bound_interface = 1;

    let now = std::time::Instant::now();

    // Service A: will be announced then driven to rename-collision.
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst_a = Name::try_from_str("First._ipp._tcp.local.").unwrap();
    let host_a = Name::try_from_str("first.local.").unwrap();
    let mut recs_a = ServiceRecords::new(stype.clone(), inst_a.clone(), host_a.clone(), 80, 120);
    recs_a.add_a([192, 168, 1, 1].into());
    let handle_a = s
      .test_register_service(ServiceSpec::new(recs_a), now)
      .unwrap();

    // Service B: owns the name A will try to rename to.
    let inst_b = Name::try_from_str("First-1._ipp._tcp.local.").unwrap();
    let host_b = Name::try_from_str("second.local.").unwrap();
    let mut recs_b = ServiceRecords::new(stype.clone(), inst_b, host_b, 80, 120);
    recs_b.add_a([192, 168, 1, 2].into());
    s.test_register_service(ServiceSpec::new(recs_b), now)
      .unwrap();

    fn pump_transmits(s: &mut State, t: StdInstant, buf: &mut [u8]) {
      loop {
        match s.poll_one_transmit(t, buf) {
          Some((_, _, TransmitOrigin::Service(h))) => {
            s.note_service_transmit_result(h, t, true);
          }
          Some(_) => {}
          None => break,
        }
      }
    }

    // Advance A to Established so the proto hands off an old-name goodbye on
    // rename (only an ANNOUNCED service has one — that's the bug scenario).
    let a_mailbox = Rc::clone(&s.services.get(&handle_a).unwrap().mailbox);
    let mut buf = [0u8; 1500];
    let mut t = now;
    let mut a_established = false;
    for _ in 0..60 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      pump_transmits(&mut s, t, &mut buf);
      s.push_service_updates(t);
      // Drain the handle-owned mailbox; detect Established and discard the rest so
      // a fresh Conflict is detectable below.
      while let Some(u) = a_mailbox.borrow_mut().drain_for_test() {
        if matches!(u, ServiceUpdate::Established) {
          a_established = true;
        }
      }
      if a_established {
        break;
      }
    }
    assert!(
      a_established,
      "A must reach Established before the rename-collision test can verify the goodbye"
    );

    // Inject peer conflicts for A's original name until push_service_updates drives
    // the rename and detects the local collision.
    let conflict = conflict_for("First._ipp._tcp.local.");
    let peer = RecvMeta::new(
      SocketAddr::from(([192, 168, 1, 200], 5353)),
      IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
      1,
      Some(255),
      None,
      conflict.len(),
    );
    let mut conflicted = false;
    for _ in 0..80 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      s.handle_datagram(&peer, &conflict);
      pump_transmits(&mut s, t, &mut buf);
      s.push_service_updates(t);

      if s
        .services
        .get(&handle_a)
        .map(|c| c.errored)
        .unwrap_or(false)
      {
        conflicted = true;
        break;
      }
    }
    assert!(
      conflicted,
      "A must be driven to rename-collision-Conflict within 80 iterations"
    );

    // ASSERTION 1: the endpoint holds A's OLD name for the whole withdrawal, so a
    // same-name re-register is rejected — a replacement cannot announce a fresh
    // positive TTL ahead of the stale TTL=0 (and evict the old name from peer
    // caches). This is the structural ordering guarantee that replaces the old
    // steal-before-reuse dance.
    {
      let mut dup = ServiceRecords::new(stype.clone(), inst_a.clone(), host_a.clone(), 80, 120);
      dup.add_a([192, 168, 1, 1].into());
      assert!(
        matches!(
          s.test_register_service(ServiceSpec::new(dup), t),
          Err(mdns_proto::error::RegisterServiceError::NameAlreadyRegistered(_))
        ),
        "A's OLD name must be held by the in-flight withdrawal (NameAlreadyRegistered)"
      );
    }

    // The collision Conflict lives in the handle-owned mailbox; the ctx GC is now
    // UNCONDITIONAL, so it need not be drained first.

    // Drive A's withdrawal to completion (no sockets → force-finished at the 2 s
    // anti-pin ceiling), then GC the freed ctx.
    let mut scratch = vec![0u8; 4096];
    let mut completed = false;
    for _ in 0..64 {
      t += Duration::from_millis(250);
      while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
        // No sockets bound in this State-level test: model BOTH families as
        // transiently undeliverable (Retry) so the per-family budget stays intact
        // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
        // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
        // instead, defeating the ceiling assertion.)
        s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
      }
      s.drain_completed_withdrawals(t);
      if !s.services.contains_key(&handle_a) {
        completed = true;
        break;
      }
    }
    assert!(completed, "A's rename-collision withdrawal must complete");

    // ASSERTION 2: once the withdrawal completes, A's OLD name is freed → a
    // replacement R registers successfully under it.
    let host_r = Name::try_from_str("replacement.local.").unwrap();
    let mut recs_r = ServiceRecords::new(stype, inst_a, host_r, 80, 120);
    recs_r.add_a([192, 168, 1, 10].into());
    s.test_register_service(ServiceSpec::new(recs_r), t)
      .expect("replacement R must register under A's old name once the withdrawal completes");
  }

  /// a terminal emitted DIRECTLY by the proto state machine —
  /// here a `HostConflict` (a peer claimed our host name with a different address,
  /// RFC 6762 §9) — must RETIRE the service through the SAME path as a synthesized
  /// rename-collision Conflict: deliver the terminal into the handle-owned mailbox,
  /// begin the endpoint-owned §10.1 withdrawal (so the proto stops serving), and GC
  /// the ctx UNCONDITIONALLY once the withdrawal completes. Before the fix a
  /// proto-emitted terminal was only pushed into the mailbox: `errored` was never
  /// set and the withdrawal never began, so `Service::next` reported end-of-stream
  /// while the ctx/route stayed live (still answering queries) until the handle
  /// dropped.
  #[test]
  fn proto_emitted_host_conflict_retires_and_gcs_the_service() {
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use mdns_proto::{
      Name, ServiceRecords, ServiceSpec, WithdrawalSend,
      wire::{Header, MessageBuilder},
    };

    use crate::socket::RecvMeta;

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
    s.bound_interface = 1;
    let now = std::time::Instant::now();

    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer.local.").unwrap();
    let mut recs = ServiceRecords::new(stype, inst, host.clone(), 631, 120);
    recs.add_a([192, 168, 1, 10].into());
    let handle = s
      .test_register_service(ServiceSpec::new(recs), now)
      .unwrap();
    let mailbox = Rc::clone(&s.services.get(&handle).unwrap().mailbox);

    fn pump_transmits(s: &mut State, t: StdInstant, buf: &mut [u8]) {
      loop {
        match s.poll_one_transmit(t, buf) {
          Some((_, _, TransmitOrigin::Service(h))) => s.note_service_transmit_result(h, t, true),
          Some(_) => {}
          None => break,
        }
      }
    }

    // Drive the service to Established (advertising its host A record), so the
    // host conflict hits a SERVING service with a non-empty withdrawal snapshot.
    let mut buf = [0u8; 1500];
    let mut t = now;
    let mut established = false;
    for _ in 0..60 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      pump_transmits(&mut s, t, &mut buf);
      s.push_service_updates(t);
      while let Some(u) = mailbox.borrow_mut().drain_for_test() {
        if matches!(u, ServiceUpdate::Established) {
          established = true;
        }
      }
      if established {
        break;
      }
    }
    assert!(
      established,
      "service must reach Established before the host conflict"
    );

    // A peer claims our host name with a DIFFERENT address (10.0.0.99): a genuine
    // §9 host conflict. The proto does NOT auto-rename a host conflict — it emits
    // `ServiceUpdate::HostConflict` via `poll()`.
    let conflict = {
      let mut cbuf = [0u8; 512];
      let mut b = MessageBuilder::<'_, 32>::try_new(&mut cbuf, Header::new()).unwrap();
      b.push_a_authority(&host, 120, Ipv4Addr::new(10, 0, 0, 99))
        .unwrap();
      let n = b.finish().unwrap();
      cbuf[..n].to_vec()
    };
    let peer = RecvMeta::new(
      SocketAddr::from(([192, 168, 1, 200], 5353)),
      IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
      1,
      Some(255), // on-link
      None,
      conflict.len(),
    );

    // Feed the conflict; `push_service_updates` drains the proto's HostConflict and
    // (with the fix) begins the withdrawal — `errored` flips true.
    let mut retired = false;
    for _ in 0..40 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      s.handle_datagram(&peer, &conflict);
      pump_transmits(&mut s, t, &mut buf);
      s.push_service_updates(t);
      if s.services.get(&handle).map(|c| c.errored).unwrap_or(false) {
        retired = true;
        break;
      }
    }
    assert!(
      retired,
      "a proto-emitted HostConflict must begin the endpoint-owned withdrawal (errored)"
    );

    // The terminal HostConflict reached the handle-owned mailbox's reserved slot.
    let mut saw_host_conflict = false;
    while let Some(u) = mailbox.borrow_mut().drain_for_test() {
      if u.is_host_conflict() {
        saw_host_conflict = true;
      }
    }
    assert!(
      saw_host_conflict,
      "the HostConflict terminal must reach the handle-owned mailbox"
    );

    // Drive the withdrawal to completion (no bound family → both Retry → force-
    // complete at the 2 s anti-pin ceiling); the ctx must be GC'd UNCONDITIONALLY.
    let mut scratch = vec![0u8; 4096];
    let mut gced = false;
    for _ in 0..64 {
      t += Duration::from_millis(250);
      while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
        s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
      }
      s.drain_completed_withdrawals(t);
      if !s.services.contains_key(&handle) {
        gced = true;
        break;
      }
    }
    assert!(
      gced,
      "the withdrawn service ctx must be GC'd after the §10.1 goodbye completes"
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

    s.test_register_service(mk(), t).unwrap();
    let err = s.test_register_service(mk(), t).unwrap_err();
    assert!(
      matches!(err, RegisterServiceError::NameAlreadyRegistered(_)),
      "second registration of the same instance name must be rejected as NameAlreadyRegistered, got {err:?}"
    );
  }

  /// On encode failure (`poll_query_transmit` → `Err`) the driver must call
  /// `endpoint.retire_query` so the proto records the terminal transition:
  /// `queries_active` decrements to 0 and exactly one of `queries_done` /
  /// `queries_timeout` reaches 1. Without the fix `queries_active` leaks
  /// and `queries_done`/`queries_timeout` stay 0 forever.
  ///
  /// Also verifies: the errored flag is set (so subsequent pumps skip the
  /// handle), the one-shot wake is armed, and the terminal is available via
  /// `endpoint.poll_query` (so `Query::next` can surface it).
  #[cfg(feature = "stats")]
  #[test]
  fn unencodable_query_retire_records_terminal_stats() {
    use mdns_proto::{QuerySpec, wire::ResourceType};

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let now = std::time::Instant::now();
    let qname = mdns_proto::Name::try_from_str("printer.local.").unwrap();
    let h = s
      .start_query(QuerySpec::new(qname, ResourceType::A), now)
      .unwrap();

    // Confirm one active query was registered.
    let before = s.stats.snapshot();
    assert_eq!(
      before.queries_active, 1,
      "one active query before encode failure"
    );
    assert_eq!(before.queries_done, 0, "no terminal yet");

    // 1-byte scratch forces Err(BufferTooSmall).
    let mut scratch = [0u8; 1];
    let pumped = s.poll_one_transmit(now, &mut scratch);
    assert!(
      pumped.is_none(),
      "an un-encodable query must not yield a transmit"
    );

    // Stats invariant: queries_active == 0, (queries_done + queries_timeout) == 1.
    let after = s.stats.snapshot();
    assert_eq!(
      after.queries_active, 0,
      "queries_active must be 0 after retire_query (was leaking)"
    );
    let terminal_count = after.queries_done;
    assert_eq!(
      terminal_count, 1,
      "exactly one terminal (done/timeout) must be recorded; got queries_done={}, queries_timeout={}",
      after.queries_done, after.queries_timeout,
    );

    // The errored flag must be set so the handle is skipped on subsequent pumps.
    assert!(
      s.queries.get(&h).map(|c| c.errored).unwrap_or(false),
      "the query must be flagged errored after the encode failure"
    );
    // One-shot wake must be armed.
    assert!(
      s.take_query_terminal_wakes(),
      "the terminal wake must be armed once on the errored transition"
    );
  }

  /// regression: after an encode-failed query's terminal is observed via
  /// `Query::next`, the driver query map must no longer contain the handle and
  /// the proto query pool slot must be freed (cancel_query removes it).
  ///
  /// Verifies:
  ///  - `queries_active == 0` and one terminal counter after the encode failure.
  ///  - `Query::next` delivers exactly one `QueryEvent::Terminal`.
  ///  - After the terminal, `state.queries` no longer contains the handle
  ///    (driver map GC'd).
  ///  - The proto pool was freed: starting a new query reuses the pool (len
  ///    stays bounded / no phantom second active entry).
  ///  - A subsequent `Query::next` call returns `None` (no double terminal).
  #[cfg(feature = "stats")]
  #[compio::test]
  async fn encode_failed_query_slot_is_gc_after_terminal_observed() {
    use core::cell::Cell;

    use crate::query::{Query, QueryEvent};

    let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);

    // Register a query with no timeout so the encode failure would otherwise
    // hang Query::next indefinitely.
    let qname = mdns_proto::Name::try_from_str("printer.local.").unwrap();
    let spec = mdns_proto::QuerySpec::new(qname, mdns_proto::wire::ResourceType::A);
    let h = inner
      .state
      .borrow_mut()
      .start_query(spec, std::time::Instant::now())
      .unwrap();

    // Verify one active query registered.
    assert_eq!(
      inner.state.borrow().stats.snapshot().queries_active,
      1,
      "one active query before encode failure"
    );

    // Pump with a 1-byte scratch to force encode Err → retire + errored.
    let mut scratch = [0u8; 1];
    {
      let mut st = inner.state.borrow_mut();
      let _ = st.poll_one_transmit(std::time::Instant::now(), &mut scratch);
    }

    // queries_active must now be 0 (retire_query was called).
    let snap = inner.state.borrow().stats.snapshot();
    assert_eq!(
      snap.queries_active, 0,
      "queries_active must be 0 after retire"
    );
    assert_eq!(
      snap.queries_done, 1,
      "exactly one terminal counter must be recorded"
    );

    // Consume the one-shot terminal wake so it doesn't drive a notify busy-spin.
    let _ = inner.state.borrow_mut().take_query_terminal_wakes();

    // Build the Query handle.
    let query = Query {
      inner: Rc::clone(&inner),
      handle: h,
      terminal_delivered: Cell::new(false),
    };

    // Query::next must deliver exactly one Terminal event.
    let event = query.next().await;
    assert!(
      matches!(event, Some(QueryEvent::Terminal(_))),
      "Query::next must return Terminal after encode failure, got {event:?}"
    );

    // After the terminal is observed the driver query map must be empty.
    assert!(
      !inner.state.borrow().queries.contains_key(&h),
      "driver query map must not contain the handle after terminal is observed"
    );

    // Proto pool slot freed: a fresh query fits in the pool without leaking.
    let qname2 = mdns_proto::Name::try_from_str("scanner.local.").unwrap();
    let spec2 = mdns_proto::QuerySpec::new(qname2, mdns_proto::wire::ResourceType::A);
    let h2 = inner
      .state
      .borrow_mut()
      .start_query(spec2, std::time::Instant::now())
      .expect("new query must succeed after slot was freed");
    assert_ne!(h, h2, "new handle should differ from the retired one");
    // queries_active is back to 1 for the new query.
    assert_eq!(
      inner.state.borrow().stats.snapshot().queries_active,
      1,
      "new query must count as active"
    );

    // A subsequent next() on the original query returns None (no double terminal).
    let second = query.next().await;
    assert!(
      second.is_none(),
      "subsequent Query::next after terminal must return None, got {second:?}"
    );
  }

  /// regression: a generic `recv` error must NOT increment `packets_dropped`.
  /// `packets_dropped` is reserved for consumed-unusable datagrams (oversized /
  /// truncated / InvalidData); a socket/driver recv failure is not a datagram-
  /// level event and must not be counted.
  ///
  /// Contrast: the known consumed-unusable paths in `State::handle_datagram`
  /// (off-link, untrusted-response) DO bump `packets_dropped` — those tests
  /// already exist in this module.
  #[cfg(feature = "stats")]
  #[test]
  fn generic_recv_error_does_not_increment_packets_dropped() {
    let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);

    let before = inner.state.borrow().stats.snapshot();
    assert_eq!(before.packets_dropped, 0, "no drops before recv error");

    // Inject a generic I/O error (connection refused — not InvalidData).
    let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "injected recv error");
    handle_recv(&inner, Err(err));

    let after = inner.state.borrow().stats.snapshot();
    assert_eq!(
      after.packets_dropped, 0,
      "a generic recv error must NOT increment packets_dropped"
    );
    // Receive counters must also stay at zero — no datagram was consumed.
    assert_eq!(after.packets_rx, 0, "packets_rx must stay 0");
    assert_eq!(after.bytes_rx, 0, "bytes_rx must stay 0");
  }

  /// regression: a truncated (oversized) datagram surfaced by `Socket::recv`
  /// via the full-buffer heuristic must be counted as consumed (`packets_rx` +
  /// `bytes_rx`) AND as dropped (`packets_dropped`), but must NOT be routed to
  /// `handle_datagram` / proto (no partial-message side effects).
  ///
  /// The `RecvMeta::with_truncated()` helper marks the datagram the same way
  /// `Socket::recv` marks one that filled the buffer exactly (i.e. `data_len >=
  /// max_recv_packet_size`). No live socket is needed.
  #[cfg(feature = "stats")]
  #[test]
  fn truncated_datagram_counts_rx_and_dropped_not_delivered_to_proto() {
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::socket::RecvMeta;

    let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);

    // Craft an oversized-proxy datagram: `RecvMeta::with_truncated()` sets the
    // `truncated` flag as `Socket::recv` would when data_len >= max_recv.
    // The data is a synthetic blob (does not need to be a valid DNS message —
    // the test verifies the datagram is dropped BEFORE proto routing).
    let data: Vec<u8> = vec![0u8; 9000]; // 9000 bytes == max_recv_packet_size
    let len = data.len();

    let meta = RecvMeta::new(
      SocketAddr::from(([224, 0, 0, 251], 5353)),
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      0,
      Some(255),
      None,
      len,
    )
    .with_truncated();

    let before = inner.state.borrow().stats.snapshot();
    assert_eq!(before.packets_rx, 0);
    assert_eq!(before.bytes_rx, 0);
    assert_eq!(before.packets_dropped, 0);

    handle_recv(&inner, Ok((data, meta)));

    let after = inner.state.borrow().stats.snapshot();
    assert_eq!(
      after.packets_rx, 1,
      "truncated datagram was received — packets_rx must be +1"
    );
    assert_eq!(
      after.bytes_rx, len as u64,
      "bytes_rx must reflect the truncated bytes that landed"
    );
    assert_eq!(
      after.packets_dropped, 1,
      "truncated datagram must bump packets_dropped"
    );
    // Proto must not have been reached: no question/answer routing side effects.
    // A synthetic 9000-byte blob that bypassed proto leaves questions_rx == 0.
    assert_eq!(
      after.questions_rx, 0,
      "truncated datagram must NOT be routed to proto (no question side effect)"
    );
  }

  /// Complement to the truncated-datagram test: a normal sub-max datagram whose
  /// `truncated` flag is NOT set must still route to `handle_datagram` / proto
  /// (regression guard — the truncation gate must not block normal traffic).
  ///
  /// We use a well-formed 12-byte all-zero DNS query header (ID=0, QR=0, no
  /// sections) so proto's `handle()` succeeds (or fails gracefully) without
  /// producing a questions_rx bump that depends on implementation details.
  /// The key assertion is `packets_rx == 1` with `packets_dropped == 0`.
  #[cfg(feature = "stats")]
  #[test]
  fn normal_non_truncated_datagram_routes_to_proto() {
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::socket::RecvMeta;

    let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    // Put the loopback subnet in the local-subnets list so the §11 on-link
    // gate passes (otherwise the datagram is dropped at the off-link check
    // before proto — which would make packets_dropped > 0 and muddy the test).
    inner.state.borrow_mut().local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
    inner.state.borrow_mut().bound_interface = 1;

    // Minimal 12-byte DNS query header. QR=0, QDCOUNT=0 — proto accepts it as
    // an empty query and does nothing, producing no parse error.
    let data: Vec<u8> = vec![
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let len = data.len();

    // Not truncated (data_len < max_recv = 9000).
    let meta = RecvMeta::new(
      SocketAddr::from(([127, 0, 0, 1], 5353)),
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      1,
      Some(255),
      None,
      len,
    );
    // `truncated()` must be false — the normal routing path.
    assert!(
      !meta.truncated(),
      "sanity: RecvMeta::new must not set truncated"
    );

    handle_recv(&inner, Ok((data, meta)));

    let after = inner.state.borrow().stats.snapshot();
    assert_eq!(
      after.packets_dropped, 0,
      "a normal non-truncated datagram must NOT bump packets_dropped"
    );
    // packets_rx is bumped by proto's handle() for routed datagrams; the
    // datagram went through proto so this counter must be 1.
    assert_eq!(
      after.packets_rx, 1,
      "normal datagram must be counted by proto (packets_rx == 1)"
    );
  }

  /// Loop-ordering guard (endpoint-owned-withdrawal form): the withdrawal
  /// pump (`drain_withdrawals`) MUST run AFTER `push_service_updates`, not before.
  ///
  /// When a rename collision is detected inside `push_service_updates`, the
  /// teardown enqueues the old name's detached goodbye
  /// (`enqueue_rename_withdrawal`) AND begins an endpoint-owned withdrawal for the
  /// current name (`begin_service_withdrawal`), each due IMMEDIATELY
  /// (`next_at = now`).
  /// Under the wrong order —
  /// withdrawal pump first, then `push_service_updates` — the pump would run
  /// before the withdrawal exists, deferring its first goodbye to the NEXT
  /// iteration (whose Phase-1 transmit pump runs first). The endpoint holds the
  /// OLD name throughout, so a replacement still cannot overtake the goodbye, but
  /// running the pump after push keeps the stale TTL=0 promptly on the wire.
  ///
  /// This test proves the ordering at the State seam by stopping the drive loop
  /// on the decisive (collision) iteration and probing whether a withdrawal
  /// datagram is DUE before vs after `push_service_updates`. `poll_one_withdrawal`
  /// is non-destructive to the resend schedule (it only encodes into scratch;
  /// `next_at` advances only in `note_withdrawal_result`, which we do NOT call
  /// here), so before/after probes are side-effect-free:
  ///
  ///   before push: no withdrawal exists yet → `poll_one_withdrawal` == None.
  ///   after push: the collision withdrawal is queued, first round due now →
  ///                `poll_one_withdrawal` == Some (the pump would drain it this
  ///                iteration).
  #[cfg(feature = "stats")]
  #[test]
  fn withdrawal_pump_runs_after_push_service_updates_loop_order() {
    use std::time::Duration;

    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::socket::RecvMeta;
    use mdns_proto::{
      Name, ServiceRecords, ServiceSpec,
      wire::{Header, MessageBuilder},
    };

    fn conflict_for(instance: &str) -> Vec<u8> {
      let mut buf = [0u8; 512];
      let name = Name::try_from_str(instance).unwrap();
      let target = Name::try_from_str("rival.local.").unwrap();
      let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
      b.push_srv_authority(&name, 120, 0, 0, 9999, &target)
        .unwrap();
      let n = b.finish().unwrap();
      buf[..n].to_vec()
    }

    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
    s.bound_interface = 1;

    let now = std::time::Instant::now();

    // Service A: will be announced then driven to rename-collision.
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst_a = Name::try_from_str("Alpha._ipp._tcp.local.").unwrap();
    let host_a = Name::try_from_str("alpha.local.").unwrap();
    let mut recs_a = ServiceRecords::new(stype.clone(), inst_a.clone(), host_a, 80, 120);
    recs_a.add_a([192, 168, 1, 1].into());
    let handle_a = s
      .test_register_service(ServiceSpec::new(recs_a), now)
      .unwrap();

    // Service B: already owns the name A will try to rename into.
    let inst_b = Name::try_from_str("Alpha-1._ipp._tcp.local.").unwrap();
    let host_b = Name::try_from_str("beta.local.").unwrap();
    let mut recs_b = ServiceRecords::new(stype, inst_b, host_b, 80, 120);
    recs_b.add_a([192, 168, 1, 2].into());
    s.test_register_service(ServiceSpec::new(recs_b), now)
      .unwrap();

    fn pump_transmits(s: &mut State, t: StdInstant, buf: &mut [u8]) {
      loop {
        match s.poll_one_transmit(t, buf) {
          Some((_, _, TransmitOrigin::Service(h))) => {
            s.note_service_transmit_result(h, t, true);
          }
          Some(_) => {}
          None => break,
        }
      }
    }

    // Whether a withdrawal datagram is DUE (non-destructively to the schedule).
    fn withdrawal_due(s: &mut State, t: StdInstant, scratch: &mut [u8]) -> bool {
      s.poll_one_withdrawal(t, scratch).is_some()
    }

    // Advance A to Established so the proto hands off an old-name goodbye on
    // rename (only an ANNOUNCED service has one).
    let a_mailbox = Rc::clone(&s.services.get(&handle_a).unwrap().mailbox);
    let mut buf = [0u8; 1500];
    let mut t = now;
    let mut a_established = false;
    for _ in 0..60 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      pump_transmits(&mut s, t, &mut buf);
      s.push_service_updates(t);
      // Drain the handle-owned mailbox; detect Established and discard the rest.
      while let Some(u) = a_mailbox.borrow_mut().drain_for_test() {
        if matches!(u, ServiceUpdate::Established) {
          a_established = true;
        }
      }
      if a_established {
        break;
      }
    }
    assert!(
      a_established,
      "A must reach Established before the ordering test can verify the goodbye timing"
    );

    // Inject peer conflicts. On the decisive iteration (the one that WILL collide
    // A with B), probe withdrawal-due BEFORE and AFTER push_service_updates.
    let conflict = conflict_for("Alpha._ipp._tcp.local.");
    let peer = RecvMeta::new(
      SocketAddr::from(([192, 168, 1, 200], 5353)),
      IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
      1,
      Some(255),
      None,
      conflict.len(),
    );

    let mut scratch = [0u8; 1500];
    let mut decisive_before: Option<bool> = None;
    let mut decisive_after: Option<bool> = None;

    for _ in 0..80 {
      t += Duration::from_millis(300);
      s.fire_timeouts(t);
      s.handle_datagram(&peer, &conflict);
      pump_transmits(&mut s, t, &mut buf);

      // Probe BEFORE push_service_updates (wrong-order pump position).
      let before = withdrawal_due(&mut s, t, &mut scratch);
      s.push_service_updates(t);
      // Probe AFTER push_service_updates (correct-order pump position).
      let after = withdrawal_due(&mut s, t, &mut scratch);

      if s
        .services
        .get(&handle_a)
        .map(|c| c.errored)
        .unwrap_or(false)
      {
        decisive_before = Some(before);
        decisive_after = Some(after);
        break;
      }
    }

    let before = decisive_before
      .expect("A must be driven to rename-collision-Conflict within the iteration limit");
    let after = decisive_after.unwrap();

    // CORE ORDERING ASSERTION: the collision withdrawal is begun BY
    // push_service_updates. Before push no withdrawal is due (would have drained
    // nothing); after push its first goodbye round is due, so the pump (which runs
    // after push) flushes it this iteration.
    assert!(
      after,
      "a withdrawal datagram must be DUE after push_service_updates begins the \
       rename-collision withdrawal (so the post-push withdrawal pump drains it this \
       iteration)"
    );
    assert!(
      !before,
      "no withdrawal must be due BEFORE push_service_updates on the decisive \
       iteration (the collision withdrawal is begun by push, not by a prior sweep)"
    );
  }
}

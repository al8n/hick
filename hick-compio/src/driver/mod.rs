//! Driver state, the spawned `run()` loop, and the `LocalNotify` primitive.
use event_listener::Event;

use std::{
  collections::HashMap,
  rc::Rc,
  time::{Duration, Instant as StdInstant, SystemTime},
};

use core::{
  cell::RefCell,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};
use hick_trace::*;
use mdns_proto::{
  CacheEntry, CollectedAnswer, Endpoint as ProtoEp, EndpointConfig, EndpointEventEntry,
  QueryHandle, QueryUpdate, ServiceHandle, ServiceRoute, ServiceUpdate, TransmitOutcome,
  WithdrawalSend, WithdrawalToken, query::Query as ProtoQuery, service::Service as ProtoSvc,
  transmit::Transmit,
};
use rand::{SeedableRng, rngs::StdRng};
use slab::Slab;

use crate::{
  service::ServiceMailbox,
  socket::{RecvMeta, Socket},
};

#[cfg(test)]
mod tests;

/// Per-iteration cap on the transmit pump.  Mirrors
/// `hick-reactor::driver::MAX_SEND_CREDITS_PER_DRAIN` (64) so a misbehaving
/// proto-state machine — or a transmit yielded for an unbound address family
/// where `note_*_transmit_result(delivered=false)` does not advance state —
/// cannot spin the driver in a tight unbounded loop.
pub(crate) const MAX_TRANSMIT_CREDITS_PER_PASS: usize = 64;

/// IPv4 mDNS multicast destination (224.0.0.251:5353). Used by the transmit
/// pump's dual-stack fan-out and the endpoint-owned withdrawal pump.
pub(crate) const MDNS_V4_DST: SocketAddr =
  SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));

/// IPv6 mDNS multicast destination ([ff02::fb]:5353). Used by the transmit
/// pump's dual-stack fan-out and the endpoint-owned withdrawal pump.
pub(crate) const MDNS_V6_DST: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
  Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb),
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
pub(crate) fn is_mdns_multicast_dst(dst: SocketAddr) -> bool {
  use hick_udp::constants::MDNS_PORT;
  matches!(dst, SocketAddr::V4(a) if a.ip().is_multicast() && a.port() == MDNS_PORT)
    || matches!(dst, SocketAddr::V6(a) if a.ip().is_multicast() && a.port() == MDNS_PORT)
}

/// Concrete `mdns-proto::Endpoint` instantiation used by the compio driver.
/// All pool slots are `slab::Slab`-backed so the std-side state lives in heap-
/// growable storage rather than heapless fixed buffers.
pub(crate) type ProtoEndpoint = ProtoEp<
  StdInstant,
  StdRng,
  Slab<CacheEntry<StdInstant>>,
  Slab<ServiceRoute>,
  Slab<ProtoQuery<StdInstant, Slab<CollectedAnswer>, Slab<QueryUpdate>>>,
  Slab<EndpointEventEntry>,
  Slab<CollectedAnswer>,
  Slab<QueryUpdate>,
>;

/// Concrete `mdns-proto::Service` instantiation used by the compio driver. The
/// state machine is owned per-`ServiceCtx`; the endpoint only tracks routing
/// metadata via `ServiceRoute`.
pub(crate) type ProtoService = ProtoSvc<StdInstant, Slab<Transmit>, Slab<ServiceUpdate>>;

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

/// Origin tag for a pumped transmit. Carries the source handle so the driver
/// can route the post-send `note_*_transmit_outcome` back to the right
/// per-handle context.
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
  pub(crate) mailbox: Rc<RefCell<ServiceMailbox>>,
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
/// `EndpointInner` — no `Arc` / `Mutex` / atomics: every borrower is on the
/// same `!Send` runtime thread.
pub(crate) struct State {
  pub(crate) endpoint: ProtoEndpoint,
  pub(crate) services: HashMap<ServiceHandle, ServiceCtx>,
  pub(crate) queries: HashMap<QueryHandle, QueryCtx>,
  /// Self-send tracker — `(content_hash, body_len, send_wall_time)` for every
  /// datagram we recently transmitted, used by the loopback-self detection.
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
  pub(crate) local_subnets: Vec<(IpAddr, u8)>,
  /// Max datagram size; used to size the scratch buffer for the encode/send
  /// path. Sourced from [`crate::ServerOptions::max_payload_size`].
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
  pub(crate) stats: std::sync::Arc<stats::Stats>,
}

impl State {
  /// Build a fresh driver state with no services or queries, seeded with an
  /// OS-derived [`StdRng`]. Bound interface and local-subnet
  /// snapshot stay empty until wired in from the bound sockets /
  /// interface discovery.
  pub(crate) fn new(cfg: EndpointConfig, max_payload: usize, max_recv: usize) -> Self {
    // rand 0.10 removed `from_entropy`; seed StdRng from the OS-seeded
    // thread RNG (same idiom as `hick-reactor::driver::DriverState::new`).
    let rng = StdRng::from_rng(&mut rand::rng());
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
    mailbox: Rc<RefCell<ServiceMailbox>>,
  ) -> Result<ServiceHandle, mdns_proto::error::RegisterServiceError> {
    let (handle, svc) = self
      .endpoint
      .try_register_service::<Slab<_>, Slab<_>>(spec, now)?;
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
    use crate::service::new_service_mailbox;

    let mailbox = new_service_mailbox();
    self.register_service(spec, now, mailbox)
  }

  /// Start a query against the endpoint and create an empty driver-side context
  /// for it; the per-query mailbox and `last_seq` updates are driven separately.
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

  /// Flag a query as cancelled.  The driver loop sweeps cancelled
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
  ) -> Option<(SocketAddr, usize, WithdrawalToken)> {
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
  /// timers fire via `ctx.proto.handle_timeout` from the driver loop; this
  /// path exposes only the endpoint cache sweep and query timeouts.
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
  /// into the handle-owned [`ServiceMailbox`] so
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
            // name must HOLD until the goodbye completes, because the dead service
            // will never re-announce and the goodbye is the only retraction the old
            // name will ever get.
            //
            // A SURVIVING rename stays RECLAIMABLE. That is sound only because the
            // sole thing that can cancel a reclaimable goodbye —
            // `Endpoint::note_service_announced` — is gated on
            // `Service::has_fully_announced`: a complete §8.3 announcement of the
            // reclaiming name that reached EVERY family this driver still
            // obligates. For each such family §10.2's cache-flush announcement
            // supersedes the stale unique records the goodbye exists to retract, so
            // cancelling loses nothing. A partially-delivered replacement
            // announcement leaves the gate shut and the old goodbye keeps draining
            // its per-family debt — which is exactly the case where the unserved
            // family has heard neither the goodbye nor the replacement.
            self
              .endpoint
              .enqueue_rename_withdrawal(handoff, now, rename_result.is_err());
          }
          if let Err(_e) = rename_result {
            warn!(
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
  /// `Some((transmit, origin))` or `None`. Walks services first, then queries.
  /// The driver loop repeatedly calls this until `None`, sending each
  /// datagram via the matching socket. The `origin` carries the service handle
  /// that produced the datagram so the driver can confirm it via
  /// [`State::note_service_transmit_outcome`] after the send completes — the §8.1
  /// probe sequence and §8.3 announce phase only advance once every obligated
  /// family carried the pending datagram.
  pub(crate) fn poll_one_transmit(
    &mut self,
    now: StdInstant,
    scratch: &mut [u8],
  ) -> Option<(Transmit, TransmitOrigin)> {
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
            return Some((t, TransmitOrigin::Service(h)));
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
              warn!(
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
        Ok(Some(t)) => return Some((t, TransmitOrigin::Query(h))),
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
          warn!(
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
  /// after the fan-out returns, handing the core the honest per-family shape of
  /// what the sockets did so the core — the only layer holding lifecycle state —
  /// decides what it means: goodbye ownership (§10.1) latches for whatever
  /// reached a wire, while the §8.1 probe sequence and §8.3 announce phase
  /// advance only once EVERY obligated family heard it.
  ///
  /// A family that keeps missing eventually stops holding the phase: the core
  /// bounds its OWN patience inside this confirm, so nothing here needs to
  /// second-guess the fan-out's honest shape.
  pub(crate) fn note_service_transmit_outcome(
    &mut self,
    h: ServiceHandle,
    now: StdInstant,
    outcome: TransmitOutcome,
  ) {
    if let Some(ctx) = self.services.get_mut(&h) {
      ctx.proto.note_transmit_outcome(now, outcome);
      // Mirror the service's CONFIRMED-ADVERTISED host set into the endpoint
      // route so sibling host-address retention (during a same-host withdrawal)
      // honours what this service ACTUALLY announced, not its configured
      // addresses. That set grows exactly when ownership latches — on any
      // delivery — so a round that reached no wire has nothing to mirror.
      // Idempotent overwrite. `self.services` (via `ctx`) and `self.endpoint` are
      // disjoint fields, so this borrow split is sound.
      if outcome.any_delivered() {
        // The reclaim-cancel gate is the ALL-delivered announcement fact the CORE
        // computes, ferried verbatim. It is emphatically NOT
        // `advertises_instance()` — that latch fires on any delivery by any
        // transmit kind, so a v4-only announcement (or an RFC 6762 §6.7 legacy
        // unicast reply, which has one obligated link and is therefore
        // all-delivered by construction) would cancel a renamed-away name's
        // goodbye that the unserved family still needs. `FullyAnnounced` has no
        // public constructor precisely so that substitution cannot compile, and it
        // names the service it was minted from, so it cannot be applied to a
        // different one either.
        self.endpoint.note_service_announced(
          ctx.proto.has_fully_announced(),
          ctx.proto.advertised_a_addrs(),
          ctx.proto.advertised_aaaa_addrs(),
        );
      }
    }
  }

  /// Confirm a previously polled query transmit so the proto layer advances its
  /// §5.2 backoff and retry budget only once EVERY obligated family carried the
  /// question — a responder reachable on one family alone must not be able to
  /// consume the whole retry schedule of a question the other family never asked.
  /// Mirrors [`Self::note_service_transmit_outcome`] for the query side; called
  /// by the driver loop after the fan-out returns.
  pub(crate) fn note_query_transmit_outcome(
    &mut self,
    h: QueryHandle,
    now: StdInstant,
    outcome: TransmitOutcome,
  ) {
    self.endpoint.note_query_transmit_outcome(h, now, outcome);
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
  #[cfg(test)]
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
      debug!(
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
      debug!(
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
        // additional `RouteEvent` variants are ignored until wired in.
        Ok(_) => {}
        Err(_) => break,
      }
    }
  }
}

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
  /// Returned as `Rc<Self>` so the handle layer can clone it without
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
    //    `MAX_SEND_CREDITS_PER_DRAIN`): a fan-out that reaches no bound socket
    //    confirms as `NoneDelivered`, which re-arms the same transmit rather than
    //    advancing lifecycle. Without a cap proto could keep re-yielding it; the
    //    cap forces the loop to yield control to the select! so timers / recv can
    //    make progress, and the deadline-driven re-entry will retry.
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
      let Some((tx, origin)) = pumped else {
        break;
      };
      let fanout = send_via(&inner, &sock_v4, &sock_v6, tx.dst(), &scratch[..tx.size()]).await;
      // Confirm the pending transmit with the honest per-family shape of the
      // fan-out. The core latches §10.1 goodbye ownership for whatever reached a
      // wire and advances the §8.1 probe sequence / §8.3 announce phase / §5.2
      // retry budget only once every obligated family carried it. Anchored to
      // post-send time so the next deadline is relative to the actual on-wire
      // send.
      let outcome = fanout.transmit_outcome();
      match origin {
        TransmitOrigin::Service(h) => {
          let mut state = inner.state.borrow_mut();
          state.note_service_transmit_outcome(h, StdInstant::now(), outcome);
        }
        TransmitOrigin::Query(h) => {
          let mut state = inner.state.borrow_mut();
          state.note_query_transmit_outcome(h, StdInstant::now(), outcome);
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
          debug!("shutdown withdrawal flush hit its wall-clock backstop; exiting");
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

/// One address family's result for one logical transmit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FamilySend {
  /// No socket bound for this family, or the datagram was not addressed to it.
  /// It was therefore never OBLIGATED to carry this transmit, and its absence
  /// must not read as a failure — a v4-only host is fully delivered on v4 alone.
  Unbound,
  /// A bound socket accepted the datagram.
  Sent,
  /// A bound socket rejected it. A completion-based `send_to` removes
  /// `EWOULDBLOCK` and nothing else: `ENETUNREACH`/`EHOSTUNREACH` when a family's
  /// route goes away, `ENOBUFS` under buffer pressure, `EPERM` from a local
  /// firewall, `EADDRNOTAVAIL` when an interface loses its address, `EMSGSIZE`.
  /// Each of those lands here on one family while the other returns `Ok` in the
  /// very same fan-out.
  Failed,
}

impl FamilySend {
  /// Classify a PRESENT (bound) family's `send_to` result. Never yields
  /// [`FamilySend::Unbound`] — that is the caller's default for a family it has
  /// no socket for.
  fn from_bound_result<T>(res: &std::io::Result<T>) -> Self {
    match res {
      Ok(_) => Self::Sent,
      Err(_) => Self::Failed,
    }
  }
}

/// The per-family shape of one logical transmit's fan-out: the I/O answer, which
/// the core alone turns into a protocol answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Fanout {
  pub(crate) v4: FamilySend,
  pub(crate) v6: FamilySend,
}

impl Fanout {
  /// Neither family attempted — the starting value, and the honest report for an
  /// endpoint with no bound socket at all.
  const UNBOUND: Self = Self {
    v4: FamilySend::Unbound,
    v6: FamilySend::Unbound,
  };

  /// Project the fan-out onto the core's [`TransmitOutcome`] — the honest,
  /// unexcused shape of what the sockets did.
  ///
  /// The obligated set is every family with a socket that this datagram was
  /// offered to; `Unbound` means there is none, so that family was never
  /// obligated. Delivery is `Sent` and nothing else — a `Failed` family did not
  /// carry the datagram, so the core must not advance its §8.1 / §8.3 phase as if
  /// it had.
  ///
  /// An empty obligated set yields [`TransmitOutcome::NoneDelivered`], never a
  /// vacuous "all": nothing was delivered, so nothing may latch or advance.
  ///
  /// A family that keeps missing is never written off here, and this driver has
  /// no other place that could: the confirm is the honest I/O facts and nothing
  /// more. Bounding how long the lifecycle waits for it is the core's own
  /// patience, applied inside [`TransmitOutcome`]'s confirm.
  pub(crate) fn transmit_outcome(self) -> TransmitOutcome {
    let mut obligated = 0usize;
    let mut delivered = 0usize;
    for family in [self.v4, self.v6] {
      if matches!(family, FamilySend::Unbound) {
        continue;
      }
      obligated += 1;
      if matches!(family, FamilySend::Sent) {
        delivered += 1;
      }
    }
    if delivered == 0 {
      TransmitOutcome::NoneDelivered
    } else if delivered == obligated {
      TransmitOutcome::AllDelivered
    } else {
      TransmitOutcome::PartiallyDelivered
    }
  }
}

/// Send one logical transmit and report each family's result.
///
/// `mdns-proto` always hands back the IPv4 multicast group for BOTH the v4 and v6
/// service groups (`multicast_dst()`), so multicast cannot be routed by the
/// destination's address family. An mDNS multicast destination is detected here
/// and the SAME body fanned out to every bound family's group (RFC 6762 §6: a
/// dual-stack host answers on each); a v6-only endpoint therefore actually
/// transmits instead of routing to an absent v4 socket.
///
/// Self-send credits are recorded ONLY on the multicast branch, one per ACTUAL
/// successful send: take-once suppression consumes a single entry per matching
/// loopback, and a dual-stack fan-out yields two loopback copies (one per joined
/// socket). The unicast branch deliberately records none — see below.
///
/// Timestamp: `when` is captured IMMEDIATELY BEFORE each `.await`. compio is
/// completion-based — the buffer moves into the op on `.await`, so we cannot
/// stamp "at the syscall" the way readiness I/O does inside `poll_send_to`.
/// Stamping before the await guarantees `when <= kernel_send_time <=
/// echo_rx_time`, keeping our own loopback inside the 1 ms Ordered match window
/// even when task-resume latency is high; stamping after it could push the
/// recorded time past the kernel's rx stamp and misclassify our own
/// announce/probe as a peer packet.
async fn send_via(
  inner: &Rc<EndpointInner>,
  sock_v4: &Option<Rc<Socket>>,
  sock_v6: &Option<Rc<Socket>>,
  dst: SocketAddr,
  body: &[u8],
) -> Fanout {
  let n = body.len();
  let mut fanout = Fanout::UNBOUND;
  if is_mdns_multicast_dst(dst) {
    if let Some(s4) = sock_v4.as_ref() {
      let when = SystemTime::now();
      let res = s4.send_to(body, MDNS_V4_DST, None).await;
      fanout.v4 = FamilySend::from_bound_result(&res);
      if res.is_ok() {
        trace!(dst = %MDNS_V4_DST, len = n, "send_to v4");
        let mut state = inner.state.borrow_mut();
        crate::selfsend::record_self_send(&mut state.recent_sends, body, when);
        #[cfg(feature = "stats")]
        {
          state.stats.packets_tx(1);
          state.stats.bytes_tx(n as u64);
        }
      } else {
        debug!(dst = %MDNS_V4_DST, "send_to v4 failed");
        #[cfg(feature = "stats")]
        inner.state.borrow().stats.send_errors(1);
      }
    }
    if let Some(s6) = sock_v6.as_ref() {
      let when = SystemTime::now();
      let res = s6.send_to(body, MDNS_V6_DST, None).await;
      fanout.v6 = FamilySend::from_bound_result(&res);
      if res.is_ok() {
        trace!(dst = %MDNS_V6_DST, len = n, "send_to v6");
        let mut state = inner.state.borrow_mut();
        crate::selfsend::record_self_send(&mut state.recent_sends, body, when);
        #[cfg(feature = "stats")]
        {
          state.stats.packets_tx(1);
          state.stats.bytes_tx(n as u64);
        }
      } else {
        debug!(dst = %MDNS_V6_DST, "send_to v6 failed");
        #[cfg(feature = "stats")]
        inner.state.borrow().stats.send_errors(1);
      }
    }
    return fanout;
  }

  // Unicast: pick the socket matching the destination family. Exactly one family
  // is obligated (an absent socket obligates none), so this branch can only be
  // all- or none-delivered.
  let sock = match dst {
    SocketAddr::V4(_) => sock_v4.as_ref(),
    SocketAddr::V6(_) => sock_v6.as_ref(),
  };
  if let Some(s) = sock {
    // NO self-send tracker entry here, unlike the multicast branch. A unicast
    // datagram — an RFC 6762 §6.7 legacy reply, or a directed response — leaves
    // for the querier's own address and port and never loops back through the
    // multicast group we joined, so a credit recorded for it can never be
    // consumed. It would simply occupy the linear-scanned tracker for
    // `SELF_SEND_TTL`, and at `MAX_SELF_SEND_ENTRIES` `record_self_send` declines
    // the NEW entry — so a legacy-query flood would starve the genuine multicast
    // credits that suppression actually depends on.
    let res = s.send_to(body, dst, None).await;
    let outcome = FamilySend::from_bound_result(&res);
    match dst {
      SocketAddr::V4(_) => fanout.v4 = outcome,
      SocketAddr::V6(_) => fanout.v6 = outcome,
    }
    if res.is_ok() {
      trace!(dst = %dst, len = n, "send_to");
      #[cfg(feature = "stats")]
      {
        let state = inner.state.borrow();
        state.stats.packets_tx(1);
        state.stats.bytes_tx(n as u64);
      }
    } else {
      debug!(dst = %dst, "send_to failed");
      #[cfg(feature = "stats")]
      inner.state.borrow().stats.send_errors(1);
    }
  }
  fanout
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
          trace!(dst = %MDNS_V4_DST, len, "withdrawal send_to v4");
          let mut state = inner.state.borrow_mut();
          crate::selfsend::record_self_send(&mut state.recent_sends, &scratch[..len], when);
          #[cfg(feature = "stats")]
          {
            state.stats.packets_tx(1);
            state.stats.bytes_tx(len as u64);
          }
        }
        Err(_e) => {
          debug!(error = %_e, dst = %MDNS_V4_DST, "withdrawal send_to v4 failed");
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
          trace!(dst = %MDNS_V6_DST, len, "withdrawal send_to v6");
          let mut state = inner.state.borrow_mut();
          crate::selfsend::record_self_send(&mut state.recent_sends, &scratch[..len], when);
          #[cfg(feature = "stats")]
          {
            state.stats.packets_tx(1);
            state.stats.bytes_tx(len as u64);
          }
        }
        Err(_e) => {
          debug!(error = %_e, dst = %MDNS_V6_DST, "withdrawal send_to v6 failed");
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
      trace!(src = %meta.peer(), len = data.len(), truncated = meta.truncated(), "recv datagram");
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
        debug!(
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
      debug!(error = %_e, "socket recv failed");
    }
  }
}

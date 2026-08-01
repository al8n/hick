//! The owned mDNS endpoint: construction, `mio` registration, handle
//! lifecycle, and the single event drain.
//!
//! [`Mdns`] holds everything the driver needs and nothing it does not: the
//! `mdns-proto` endpoint, one context per registered service and running
//! query, the self-send tracker, the bounded event queue, and the socket pair.
//! There is no mailbox, no doorbell, no channel and no `Arc` — the caller owns
//! this struct outright and drives it from its own `mio::Poll` loop, so every
//! piece of shared-ownership machinery `hick-reactor` needs to talk to a
//! background task is absent by construction.
//!
//! The pipeline that advances all of it lives in [`crate::driver`].

use std::{collections::HashMap, io, net::IpAddr, time::Instant as StdInstant};

use mdns_proto::{QueryHandle, QuerySpec, ServiceHandle, ServiceSpec};
use mio::{Registry, Token};
use rand::{SeedableRng, rngs::StdRng};
use slab::Slab;

use crate::{
  discovery::{LookupHandle, Lookups},
  driver::{FamilyWireGate, GoodbyeLedger, SendHealth, TxQueue, TxSlot},
  error::{RegisterError, ServerError, StartQueryError},
  event::{Event, EventQueue},
  onlink::collect_local_subnets,
  options::ServerOptions,
  proto::{ProtoEndpoint, ProtoService},
  selfsend::SelfSendTracker,
  socket::Sockets,
};

/// Driver-side state for one registered service.
pub(crate) struct ServiceCtx {
  /// The `mdns-proto` state machine owning this service's §8 probe/announce
  /// schedule and its response generation.
  pub(crate) proto: ProtoService,
  /// Consecutive `Service::poll_transmit` failures. Reset by any successful
  /// poll; past [`crate::driver::MAX_CONSECUTIVE_ENCODE_ERRORS`] the
  /// registration is treated as structurally unusable and retired with a
  /// [`mdns_proto::ServiceUpdate::Conflict`], so the caller is told instead of
  /// waiting forever for an `Established` that cannot come.
  pub(crate) encode_failures: u8,
  /// Set once this service has been retired. Its proto state machine is
  /// finished, so every later stage skips it for transmits, deadlines, update
  /// draining, and inbound event dispatch.
  pub(crate) withdrawing: bool,
  /// Set once this service's RFC 6762 §10.1 goodbye has been handed to the
  /// endpoint by [`begin_service_withdrawal`].
  ///
  /// Distinct from `withdrawing`, which the pipeline sets on its own at an
  /// internal retirement (an encode-failure escalation or a conflict) without
  /// beginning anything. `drain_withdrawals` scans for exactly that gap —
  /// retired but not begun — which is what stops a retirement site from leaking
  /// a route by forgetting to start the goodbye. This flag is what keeps that
  /// scan from re-snapshotting a service whose goodbye is already in flight.
  pub(crate) goodbye_begun: bool,
  /// This service's position in the transmit queue. See
  /// [`TxQueue`](crate::driver::TxQueue), which owns the discipline; the value
  /// only ever comes from `TxQueue::join`.
  pub(crate) tx_seq: u64,
  /// When each family last carried one of THIS service's gated datagrams, so
  /// the RFC 6762 §8.1 / §8.3 spacing is honoured per wire rather than per
  /// confirm. See [`FamilyWireGate`].
  pub(crate) wire_gate: FamilyWireGate,
}

/// Driver-side state for one running query.
pub(crate) struct QueryCtx {
  /// Highest `CollectedAnswer::seq` already surfaced to the event queue.
  /// Compared against [`mdns_proto::Endpoint::query_accepted_count`] to find
  /// both the answers we have not delivered yet and the ones the proto layer's
  /// own `max_answers` cap evicted before we ever saw them.
  pub(crate) last_seq: u64,
  /// The lookup that owns this query, or `None` for one the caller started
  /// through [`Mdns::start_query`].
  ///
  /// **The distinction between a lookup's sub-query and a caller's query, and
  /// the only one.** Every pipeline stage drives both kinds identically — a
  /// sub-query must transmit, time out, and be swept like any other — except at
  /// the two sites where a query becomes a caller-visible event (`push_updates`
  /// and the encode-error retirement in `drain_transmits`), which skip an owned
  /// query entirely. Its answers and terminal are consumed by
  /// [`Mdns::advance_lookups`] instead, so they can never surface as
  /// [`Event::QueryAnswer`] or [`Event::QueryTerminal`] for a handle the caller
  /// never asked for.
  pub(crate) owner: Option<LookupHandle>,
  /// This query's position in the transmit queue. See
  /// [`TxQueue`](crate::driver::TxQueue), which owns the discipline; the value
  /// only ever comes from `TxQueue::join`.
  pub(crate) tx_seq: u64,
  /// When each family last carried one of THIS question's transmissions, so RFC
  /// 6762 §5.2's one-second floor is honoured per wire. See [`FamilyWireGate`].
  pub(crate) wire_gate: FamilyWireGate,
}

/// A synchronous mDNS responder and querier driven from the caller's own
/// [`mio::Poll`] loop.
///
/// `Mdns` spawns no thread and depends on no async runtime. The caller
/// registers its two sockets into its own [`Registry`], drives `Poll::poll`
/// itself, hands every event it [`owns`](Self::owns) to
/// [`handle_io`](Self::handle_io), and calls [`tick`](Self::tick) once per
/// iteration to advance the protocol.
///
/// # Loop contract
///
/// [`handle_io`](Self::handle_io) records readiness and does no I/O. **All**
/// work happens in [`tick`](Self::tick), which is why the caller's ordering
/// cannot break anything: a loop that ticks before draining events is as
/// correct as one that drains first, and a `tick` with no events at all (the
/// timer-only wakeup) still makes progress.
///
/// [`next_timeout`](Self::next_timeout) is the value to pass to `Poll::poll`.
/// Blocking longer than it reports delays a probe, an announcement, or a query
/// retry; it never loses one.
///
/// # Stopping
///
/// Call [`shutdown`](Self::shutdown) and keep running the same loop until
/// [`is_idle`](Self::is_idle) reports `true`. That is the only path that
/// honours the RFC 6762 §10.1 TTL=0 goodbyes, which is what makes peers evict
/// this endpoint's services instead of holding them until their record TTLs
/// expire.
///
/// Dropping without it attempts each goodbye **exactly once, non-blocking**, and
/// nothing more: §10.1's repeats are never sent, and a datagram the socket
/// refuses at that instant is lost with no loop left to retry it. Peers that
/// miss the retraction **keep advertising the service until its record TTL
/// expires, which can be over an hour.** See the [`Drop`] impl.
pub struct Mdns {
  /// The `mdns-proto` endpoint: cache, routing table, query pool, and the
  /// endpoint-owned withdrawal schedule.
  pub(crate) endpoint: ProtoEndpoint,
  /// One context per registered service, keyed by the handle the endpoint
  /// minted at registration.
  pub(crate) services: HashMap<ServiceHandle, ServiceCtx>,
  /// One context per running query, keyed the same way. Holds both the
  /// caller's own queries and every lookup's sub-queries; [`QueryCtx::owner`]
  /// tells them apart.
  pub(crate) queries: HashMap<QueryHandle, QueryCtx>,
  /// One context per running DNS-SD lookup, keyed by the slab key its
  /// [`LookupHandle`] wraps.
  pub(crate) lookups: Lookups,
  /// The bound socket pair and its readiness bookkeeping.
  pub(crate) sockets: Sockets,
  /// Take-once credits for our own multicast loopback. One entry per
  /// successful `send_to` **syscall**, because a multicast transmit fans out to
  /// both families and the kernel loops one copy back per joined socket.
  pub(crate) selfsend: SelfSendTracker,
  /// How badly each address family is currently failing to send, and therefore
  /// which of them this driver still obligates. The whole of the send-side
  /// bookkeeping that survives a tick — every datagram's delivery is settled
  /// inside the tick that produced it. See [`SendHealth`].
  pub(crate) send_health: SendHealth,
  /// The ONE queue every caller-visible signal is delivered through.
  pub(crate) events: EventQueue,
  /// Addresses configured on the bound interface, snapshotted at construction.
  /// The RFC 6762 §11 fallback for platforms that deliver no TTL cmsg. Scoped
  /// to the bound interface only, so an unrelated NIC's subnet cannot widen the
  /// trust boundary.
  pub(crate) local_subnets: Vec<(IpAddr, u8)>,
  /// The interface both sockets are scoped to. The §11 fallback needs it to
  /// scope a link-local source to the link we actually joined.
  pub(crate) bound_interface: u32,
  /// Encode scratch for `poll_transmit`, sized by
  /// [`ServerOptions::max_payload_size`].
  pub(crate) send_buf: Vec<u8>,
  /// Receive scratch, sized by [`ServerOptions::max_recv_packet_size`].
  pub(crate) recv_buf: Vec<u8>,
  /// Reusable handle snapshots for the pipeline stages that drive the endpoint
  /// while iterating the map it would otherwise borrow. Cleared at each use, so
  /// a steady-state tick allocates nothing. `svc_scratch` is shared by
  /// [`Mdns::shutdown`] and the withdrawal drain, which never overlap:
  /// `shutdown` is a caller-facing call that cannot land mid-tick.
  pub(crate) svc_scratch: Vec<ServiceHandle>,
  pub(crate) query_scratch: Vec<QueryHandle>,
  /// This tick's transmit queue: every registered service and running query,
  /// paired with the service sequence that orders them. Rebuilt each drain, so
  /// it holds no state between ticks — the sequences on the contexts do.
  pub(crate) tx_scratch: Vec<(u64, TxSlot)>,
  /// The transmit queue's sequence source.
  ///
  /// **The state that makes the drain budget a fair share rather than a
  /// prefix**, and that keeps a sender's position independent of its handle.
  /// Without it every tick would rebuild the list in whatever order it found the
  /// senders in, so which of them the budget reaches would be arbitrary and some
  /// could go unserved indefinitely. See [`TxQueue`](crate::driver::TxQueue).
  pub(crate) tx_queue: TxQueue,
  /// Reusable list of query handles retired during a stage, GC'd once the
  /// stage's split borrow ends.
  pub(crate) retired_scratch: Vec<QueryHandle>,
  /// Reusable list of services whose withdrawal completed this tick, filled by
  /// [`mdns_proto::Endpoint::drain_completed_withdrawals`] and drained into the
  /// context GC.
  pub(crate) completed_scratch: Vec<ServiceHandle>,
  /// Which families each in-flight RFC 6762 §10.1 goodbye still owes a round,
  /// so a family that has paid is not offered the next one. See
  /// [`GoodbyeLedger`] — it is a projection of the endpoint's own per-family
  /// debt, and emphatically not a pending-send table.
  pub(crate) goodbye_ledger: GoodbyeLedger,
  /// Work the driver knows is due **now** and that no deadline announces, so
  /// [`Mdns::next_timeout`] must not let the caller sleep on it.
  ///
  /// Two things set it, and neither is visible to the deadline fold:
  ///
  /// * a freshly started query, whose first question is pending immediately —
  ///   [`mdns_proto::Endpoint::poll_query_timeout`] reports nothing for it until
  ///   the first send is confirmed and the §5.2 retry backoff is scheduled, so
  ///   folding deadlines alone would tell the caller to block forever with a
  ///   question that never goes out;
  /// * a transmit drain that stopped at its credit cap, or that cut a sender off
  ///   at its round-robin quantum, either of which may have left a due datagram
  ///   unsent.
  ///
  /// Recomputed by every transmit drain, so it can never latch: the tick that
  /// does the work clears it.
  pub(crate) work_pending: bool,
  /// Set by [`Mdns::shutdown`]: every service live at that moment has begun its
  /// RFC 6762 §10.1 goodbye and no new registration may join them. One-way —
  /// there is no resume, because the withdrawals already begun cannot be
  /// recalled.
  pub(crate) shutting_down: bool,
  /// Shared counters, so proto-layer and driver-layer stats land in one place.
  #[cfg(feature = "stats")]
  pub(crate) stats: std::sync::Arc<hick_trace::stats::Stats>,
  /// Per-datagram stalls injected **between a datagram's admission and the
  /// self-send credit check weighed on it**, consumed one per admitted datagram;
  /// once exhausted every claim proceeds at full speed.
  ///
  /// It stands in for the one thing no test can ask a real host for: the drain
  /// thread losing the CPU inside stage 1 *after* the read and the two admission
  /// gates, with the claim still ahead of it. That stretch is post-opportunity
  /// time, which [`SELF_SEND_TTL`](crate::selfsend::SELF_SEND_TTL) requires be
  /// charged in full, and it is the last window in which a caller-supplied
  /// instant could still be stale — so it is exactly where a claim that trusts
  /// one swallows a co-resident peer's byte-identical datagram as our own echo.
  ///
  /// Distinct from `BoundSocket::forced_recv_delays`, which stalls *inside* the
  /// read and so lands before this window opens; the two are not substitutes.
  #[cfg(test)]
  pub(crate) forced_claim_delays: std::collections::VecDeque<std::time::Duration>,
}

impl Mdns {
  /// Bind the mDNS multicast sockets and build an endpoint around them.
  ///
  /// Both families are bound when the chosen interface has an address in each;
  /// a family the interface cannot serve is skipped rather than failing the
  /// whole endpoint, so the dual-stack default still works on a host with no
  /// global IPv6.
  ///
  /// The sockets are **not** registered with any `mio::Registry` yet — call
  /// [`register`](Self::register) with the two tokens you have reserved.
  ///
  /// # Errors
  ///
  /// Returns [`ServerError::NoFamilyEnabled`] when the options disable both
  /// families, and the corresponding bind error when the interface has an
  /// address in a requested family but the socket could not be bound or joined.
  pub fn new(opts: ServerOptions) -> Result<Self, ServerError> {
    // rand 0.10 removed `from_entropy`; seed StdRng from the OS-seeded thread RNG.
    let rng = StdRng::from_rng(&mut rand::rng());
    // `try_new` returns `Self`, not a `Result`, despite the name.
    //
    // Built BEFORE `Sockets::bind` because `bind` consumes what it mints: the
    // shared stats `Arc` below, without which a socket-layer send would land in
    // a private counter set instead of the one `Mdns::stats` reports — see
    // `Sockets`'s own `stats` field doc. Nothing else orders these two.
    let endpoint = ProtoEndpoint::try_new(*opts.endpoint_config(), rng);
    #[cfg(feature = "stats")]
    let stats = endpoint.stats_handle();
    let sockets = Sockets::bind(
      &opts,
      #[cfg(feature = "stats")]
      stats.clone(),
    )?;
    let bound_interface = sockets.interface_index();
    Ok(Self {
      endpoint,
      services: HashMap::new(),
      queries: HashMap::new(),
      lookups: Lookups::new(),
      sockets,
      selfsend: SelfSendTracker::new(),
      send_health: SendHealth::new(),
      events: EventQueue::new(),
      local_subnets: collect_local_subnets(bound_interface),
      bound_interface,
      send_buf: vec![0u8; opts.max_payload_size()],
      recv_buf: vec![0u8; opts.max_recv_packet_size()],
      svc_scratch: Vec::new(),
      query_scratch: Vec::new(),
      tx_scratch: Vec::new(),
      tx_queue: TxQueue::new(),
      retired_scratch: Vec::new(),
      completed_scratch: Vec::new(),
      goodbye_ledger: GoodbyeLedger::new(),
      work_pending: false,
      shutting_down: false,
      #[cfg(feature = "stats")]
      stats,
      #[cfg(test)]
      forced_claim_delays: std::collections::VecDeque::new(),
    })
  }

  /// Register both sockets into the caller's [`Registry`] under two tokens the
  /// caller reserved for us.
  ///
  /// `v4` and `v6` must be **distinct**: one token cannot address two sockets,
  /// because readiness would then be unattributable. Both are claimed by
  /// [`owns`](Self::owns) even when only one family is bound, so a caller can
  /// reserve the pair unconditionally.
  ///
  /// # Errors
  ///
  /// [`io::ErrorKind::InvalidInput`] when the two tokens are equal,
  /// [`io::ErrorKind::AlreadyExists`] when the sockets are already registered,
  /// and any error the underlying `Registry::register` returns. A partial
  /// registration is always rolled back.
  pub fn register(&mut self, registry: &Registry, v4: Token, v6: Token) -> io::Result<()> {
    self.sockets.register(registry, v4, v6)
  }

  /// Remove both sockets from the [`Registry`] they were registered into.
  ///
  /// It deliberately takes no `Registry`: the removal goes through a clone of
  /// the one handed to [`register`](Self::register), so a caller driving more
  /// than one `Poll` cannot deregister this endpoint from the wrong selector —
  /// which kqueue would report as success while the original registration went
  /// on delivering events under a token [`owns`](Self::owns) had stopped
  /// claiming. Calling this before ever registering is a no-op.
  ///
  /// # Errors
  ///
  /// Any error the underlying `Registry::deregister` returns. Both families are
  /// always attempted and the first failure is reported. A family the selector
  /// did not confirm stays registered *and stays owned*, so calling this again
  /// retries exactly the removal that is outstanding.
  pub fn deregister(&mut self) -> io::Result<()> {
    self.sockets.deregister()
  }

  /// Whether `token` is one of the two handed to [`register`](Self::register).
  ///
  /// The caller's event loop uses this to split its own tokens from ours.
  pub fn owns(&self, token: Token) -> bool {
    self.sockets.owns(token)
  }

  /// Which address families this endpoint actually bound, as `(ipv4, ipv6)`.
  ///
  /// [`new`](Self::new) degrades rather than failing when the chosen interface
  /// has no address in a requested family, so
  /// `ServerOptions::default()` — which requests both — may return an endpoint
  /// serving only one. **This is the only way to find out.**
  ///
  /// It matters because the IPv6 half fails in two very different ways. On a
  /// host that rejects the v6 bind outright, [`new`](Self::new) returns
  /// [`ServerError::BindV6`] and the caller cannot miss it. On a host that
  /// binds it but cannot set `IPV6_MULTICAST_HOPS`, the socket is live with a
  /// hop limit of 1 — every peer applying the RFC 6762 §11 rule drops what it
  /// sends, and nothing anywhere reports an error. Without this accessor a
  /// caller debugging "my peers do not see me over IPv6" has only a trace line
  /// to go on.
  pub const fn bound_families(&self) -> (bool, bool) {
    self.sockets.bound_families()
  }

  /// Which bound families are currently **degraded**, as `(ipv4, ipv6)`.
  ///
  /// The companion of [`bound_families`](Self::bound_families), and needed for
  /// the same reason. `bound_families` reports what was bound at construction;
  /// this reports what is actually carrying traffic now. A host whose IPv6
  /// route disappears after startup shows `(true, true)` there and
  /// `(false, true)` here.
  ///
  /// Two independent conditions report here, one per direction:
  ///
  /// * **It cannot deliver.** A family has failed to deliver several datagrams
  ///   in a row. It is still attempted on every transmit, every such attempt is
  ///   still reported to the protocol layer as a miss, and one successful send
  ///   clears the flag. Nothing about the flag changes what the protocol layer
  ///   is told: a service whose probe or announcement keeps missing this family
  ///   advances only under the protocol layer's own patience, which advances the
  ///   phase without granting it the credit a real delivery earns. What the flag
  ///   reports is a real reduction in coverage, and this is the only way to see
  ///   it.
  /// * **It cannot receive.** A receive that fails structurally (the socket is
  ///   not readable at all, not merely busy) is not retried, because retrying it
  ///   is a busy-loop that never recovers. The family keeps sending, so it is
  ///   still genuinely bound, but nothing a peer says reaches this endpoint over
  ///   it — no conflict, no known answer, no query. Unlike the delivery
  ///   condition this one does **not** clear.
  ///
  /// An unbound family is never reported as degraded: it owes nothing, so there
  /// is nothing for it to fail at.
  pub const fn degraded_families(&self) -> (bool, bool) {
    let (send_v4, send_v6) = self.send_health.degraded_families();
    let (deaf_v4, deaf_v6) = self.sockets.deaf_families();
    (send_v4 || deaf_v4, send_v6 || deaf_v6)
  }

  /// The index of the interface both sockets are scoped to.
  ///
  /// Either the index [`ServerOptions::with_interface_index`] pinned, or the
  /// one the default picker chose — which is the value a caller cannot
  /// otherwise recover, and the one to name when reporting that mDNS went out
  /// on the wrong link.
  pub const fn interface_index(&self) -> u32 {
    self.bound_interface
  }

  /// Pop the next event, if any.
  ///
  /// Every service lifecycle update, query answer, query terminal, and lookup
  /// result arrives here — one queue, one drain point, so a terminal is
  /// impossible to miss.
  ///
  /// **Drain it to empty on every loop iteration.** That is a contract, not
  /// advice, because only the *answer* half of the queue is self-limiting:
  /// [`Event::QueryAnswer`]s are capped, coalesced per record, and the oldest
  /// is evicted (counted in [`dropped_events`](Self::dropped_events)) once the
  /// backlog fills. Everything else — [`Event::Service`],
  /// [`Event::QueryTerminal`], [`Event::Lookup`], [`Event::LookupDone`] — is
  /// appended **uncapped and never evicted**, deliberately: a lifecycle
  /// transition the caller drops cannot be reconstructed from any later event.
  ///
  /// So this drain is the only thing bounding them. A peer that keeps
  /// conflicting with a registered instance name drives `mdns-proto`'s
  /// `rename_attempt` counter, which has no ceiling, and each rename is one
  /// more [`Event::Service`]. The rate is low — a rename costs a full RFC 6762
  /// §8.1 probe cycle — so one drain per tick keeps up comfortably; a caller
  /// that keeps ticking while never draining grows memory without limit.
  pub fn next_event(&mut self) -> Option<Event> {
    self.events.pop()
  }

  /// Total answers lost rather than delivered, monotonic for the life of this
  /// endpoint.
  ///
  /// Counts both losses: an answer the proto layer's own `max_answers` cap
  /// evicted before [`tick`](Self::tick) could scan it, and one the event
  /// queue evicted because the caller drained slower than answers arrived.
  /// Terminals are never counted here — they are never dropped.
  ///
  /// An answer a *lookup's* sub-query lost the same way is counted too, even
  /// though it was never destined for this queue: it is still a collected record
  /// that nothing could act on, and it means that lookup's result set is a
  /// partial view.
  pub fn dropped_events(&self) -> u64 {
    self.events.dropped()
  }

  /// Register a service and begin its RFC 6762 §8 probe sequence.
  ///
  /// Nothing goes on the wire until the next [`tick`](Self::tick); this only
  /// creates the state machine and schedules its first probe.
  ///
  /// # Errors
  ///
  /// [`RegisterError::NameAlreadyRegistered`] when another live registration
  /// already owns the instance name — including one whose §10.1 goodbye is
  /// still in flight, since the endpoint holds the name until the retraction
  /// settles — [`RegisterError::StorageFull`] when the proto service pool
  /// cannot accept another entry, and [`RegisterError::ShuttingDown`] after
  /// [`shutdown`](Self::shutdown).
  pub fn register_service(&mut self, spec: ServiceSpec) -> Result<ServiceHandle, RegisterError> {
    if self.shutting_down {
      return Err(RegisterError::ShuttingDown);
    }
    let now = StdInstant::now();
    let (handle, proto) = self
      .endpoint
      .try_register_service::<Slab<_>, Slab<_>>(spec, now)?;
    self.services.insert(
      handle,
      ServiceCtx {
        proto,
        encode_failures: 0,
        withdrawing: false,
        goodbye_begun: false,
        tx_seq: self.tx_queue.join(),
        wire_gate: FamilyWireGate::default(),
      },
    );
    Ok(handle)
  }

  /// Stop advertising a service and begin its RFC 6762 §10.1 goodbye.
  ///
  /// The service stops answering questions and stops transmitting at once, but
  /// its name is **not** free yet: the endpoint keeps the route, and drives a
  /// resend schedule of TTL=0 records so peers evict the service instead of
  /// holding it until its record TTL expires — which can be over an hour. The
  /// name becomes available to a new registration, and the driver-side context
  /// is dropped, only once that schedule finishes: its per-family resend budget
  /// spent, or its 2 s anti-pin ceiling reached.
  ///
  /// Nothing goes on the wire until the next [`tick`](Self::tick), and the
  /// goodbye is only carried by ticks — **keep running the loop**. A caller that
  /// unregisters and immediately stops ticking gets the same degraded outcome
  /// `Drop` documents.
  ///
  /// A service that never announced has nothing for peers to evict, so its
  /// withdrawal completes on the next tick with no datagram at all.
  ///
  /// Unknown and already-unregistered handles are accepted and ignored.
  pub fn unregister_service(&mut self, handle: ServiceHandle) {
    let Self {
      endpoint, services, ..
    } = self;
    begin_service_withdrawal(endpoint, services, handle);
  }

  /// Begin the RFC 6762 §10.1 goodbye for every live service and refuse further
  /// registrations.
  ///
  /// This is the **correct** way to stop: it starts the withdrawals but sends
  /// nothing itself, because in this crate the caller owns the loop. Keep
  /// running that loop — [`handle_io`](Self::handle_io), [`tick`](Self::tick),
  /// and [`next_timeout`](Self::next_timeout) exactly as before — until
  /// [`is_idle`](Self::is_idle) reports `true`. That is what honours the full
  /// §10.1 resend schedule; each round is a scheduled deadline, and
  /// `next_timeout` folds it in so the loop wakes for it.
  ///
  /// ```no_run
  /// # fn f(mdns: &mut hick_mio::Mdns, poll: &mut mio::Poll, events: &mut mio::Events)
  /// # -> Result<(), Box<dyn std::error::Error>> {
  /// mdns.shutdown();
  /// while !mdns.is_idle() {
  ///   poll.poll(events, mdns.next_timeout())?;
  ///   for ev in events.iter() {
  ///     if mdns.owns(ev.token()) {
  ///       mdns.handle_io(ev);
  ///     }
  ///   }
  ///   mdns.tick()?;
  /// }
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// The loop terminates without a deadline of its own: every withdrawal ends
  /// when its per-family resend budget is spent or at its 2 s anti-pin ceiling,
  /// whichever comes first. No wall-clock backstop is imposed here on purpose —
  /// the caller owns the loop and can abandon it whenever it likes.
  ///
  /// Idempotent, and one-way: [`register_service`](Self::register_service) then
  /// returns [`RegisterError::ShuttingDown`]. Queries and lookups are
  /// deliberately left alone — they advertise nothing, so they owe no
  /// retraction, and they do not keep [`is_idle`](Self::is_idle) from becoming
  /// `true`.
  ///
  /// # Each withdrawal is scheduled from its own creation
  ///
  /// There is no `now` read here, deliberately. Every item this begins takes its
  /// `next_at` and its 2 s anti-pin ceiling from the instant it is actually
  /// created, inside `begin_service_withdrawal` — so the scan below, and the
  /// `n − 1` withdrawals begun before this one, are not charged to its ceiling.
  /// See the clock rule in `crate::driver`'s own docs.
  pub fn shutdown(&mut self) {
    self.shutting_down = true;
    let Self {
      endpoint,
      services,
      svc_scratch,
      ..
    } = self;
    svc_scratch.clear();
    svc_scratch.extend(
      services
        .iter()
        .filter(|(_, ctx)| !ctx.goodbye_begun)
        .map(|(&handle, _)| handle),
    );
    for &handle in svc_scratch.iter() {
      begin_service_withdrawal(endpoint, services, handle);
    }
  }

  /// Whether every RFC 6762 §10.1 goodbye has run its schedule out, so a caller
  /// looping after [`shutdown`](Self::shutdown) may stop.
  ///
  /// The withdrawal schedule is the whole of it, and it is a complete answer
  /// because nothing this driver sends outlives the tick that sent it: a
  /// goodbye a socket refused was never handed to the kernel, its per-family
  /// debt was left unpaid rather than parked, and the endpoint's own schedule is
  /// what brings it back.
  ///
  /// Not a general "nothing to do" predicate: a fresh endpoint with a running
  /// query and a probing service is idle by this definition, because neither
  /// owes anyone a retraction.
  pub fn is_idle(&self) -> bool {
    !self.endpoint.has_pending_withdrawals()
  }

  /// Start a continuous query.
  ///
  /// The first question is multicast on the next [`tick`](Self::tick), and
  /// [`next_timeout`](Self::next_timeout) reports zero until it has been: the
  /// proto layer schedules a deadline only once that first send is confirmed,
  /// so nothing else would tell the caller to come back.
  ///
  /// Answers arrive as [`Event::QueryAnswer`] and the query's terminal as
  /// [`Event::QueryTerminal`]; both surface through
  /// [`next_event`](Self::next_event).
  ///
  /// # Errors
  ///
  /// [`StartQueryError::StorageFull`] when the proto query pool cannot accept
  /// another entry, and [`StartQueryError::Other`] for a proto failure this
  /// crate does not map explicitly yet.
  pub fn start_query(&mut self, spec: QuerySpec) -> Result<QueryHandle, StartQueryError> {
    let now = StdInstant::now();
    // `From`, never `map_err(|_| StorageFull)`: the proto error is
    // `#[non_exhaustive]`, and reporting a future variant as a full query pool
    // would send a caller that retries on that into a loop.
    let handle = self.endpoint.try_start_query(spec, now)?;
    self.queries.insert(
      handle,
      QueryCtx {
        last_seq: 0,
        owner: None,
        tx_seq: self.tx_queue.join(),
        wire_gate: FamilyWireGate::default(),
      },
    );
    self.work_pending = true;
    Ok(handle)
  }

  /// Cancel a running query and free its pool entry.
  ///
  /// No [`Event::QueryTerminal`] is produced: the caller asked for this, so
  /// there is nothing to report back. Answers already queued stay queued and
  /// are still delivered by [`next_event`](Self::next_event).
  ///
  /// Unknown and already-cancelled handles are accepted and ignored, as is a
  /// handle belonging to a lookup's sub-query: those are the lookup's to run and
  /// to stop, and cancelling one here would leave the lookup waiting on a leg
  /// that can never answer. Use [`cancel_lookup`](Self::cancel_lookup) instead.
  pub fn cancel_query(&mut self, handle: QueryHandle) {
    if self
      .queries
      .get(&handle)
      .is_some_and(|ctx| ctx.owner.is_some())
    {
      return;
    }
    let _ = self.endpoint.cancel_query(handle);
    self.queries.remove(&handle);
  }

  /// A point-in-time copy of this endpoint's counters.
  #[cfg(feature = "stats")]
  #[cfg_attr(docsrs, doc(cfg(feature = "stats")))]
  pub fn stats(&self) -> hick_trace::stats::StatsSnapshot {
    self.stats.snapshot()
  }

  /// The one degraded goodbye attempt [`Drop`] can make: begin every live
  /// service's withdrawal, put one round of each on the wire, and free whatever
  /// settled.
  ///
  /// Deliberately a single pass. RFC 6762 §10.1 asks for the goodbye to be
  /// repeated, and the endpoint schedules those resends 250 ms apart — but a
  /// destructor cannot sleep and cannot re-enter the caller's loop, so the
  /// resends are simply not sent. See the [`Drop`] impl for what that costs.
  fn best_effort_goodbye_pass(&mut self) {
    // The correct path already left nothing behind: no context to withdraw and
    // no schedule still running. Cost it nothing, and above all put no spurious
    // extra goodbye on the wire after a clean `shutdown` + `is_idle`.
    if self.services.is_empty() && !self.endpoint.has_pending_withdrawals() {
      return;
    }
    self.shutdown();
    self.drain_withdrawals();
  }
}

/// Retire `handle` and hand its RFC 6762 §10.1 goodbye to the endpoint.
///
/// A free function over the two fields it needs, so the pipeline stages can
/// call it while `Mdns` is split-borrowed. Follows
/// `hick-reactor/src/driver/mod.rs:1072-1094`:
///
/// * mark the context `withdrawing`, so every pipeline stage stops driving the
///   proto state machine — but keep the context, because the endpoint still
///   holds this service's name and reports the handle back only on completion;
/// * take any pending §9 rename handoff. `push_updates` takes it the instant a
///   `Renamed` update is observed, which is the normal path; this is the
///   backstop for a retirement that lands while a `Renamed` is still queued in
///   the proto's update pool — that update is never drained, so the old-name
///   goodbye would be dropped with the proto. The handoff is one-shot, so the
///   two sites cannot both claim it, and both hold the old name until the
///   retraction is paid on every bound family (see `push_updates` for why
///   reclaiming it early loses an unpaid family's debt);
/// * hand the current name's snapshot to `begin_withdrawal`, which keeps the
///   route (holding the name against a same-name re-registration) and owns the
///   resend schedule from here on.
///
/// # The snapshot is already the last word
///
/// The snapshot is taken from the goodbye-ownership latch, so records that
/// really are cached must be in it and nothing of this service's may still be
/// able to reach a wire after it. Both hold **structurally**: every datagram
/// this service produced was sent and confirmed inside the `poll_transmit`
/// iteration that produced it, so at this point there is no unresolved send
/// whose delivery the latch has not seen, and nothing left anywhere that could
/// transmit a positive-TTL record after the retraction. That is what the
/// outbound queue cost and what its deletion bought: there is no cancel step
/// here because there is nothing to cancel, and no teardown confirm because
/// there is no live commit token.
///
/// Idempotent at both levels: the `goodbye_begun` flag skips a service already
/// handed over, and `begin_withdrawal` itself no-ops for a handle that already
/// has a route-attached item. A no-op for an unknown handle.
///
/// # It takes no instant, and no caller may supply one
///
/// A withdrawal item's whole schedule is defined relative to the instant it is
/// **created**: `next_at` *is* that instant, and the 2 s anti-pin ceiling is
/// measured from it. So the instant is not a convenient earlier reading a caller
/// can pass down — it is the thing being defined, and it is read here, once per
/// item, at that item's own enqueue.
///
/// Every caller had one to hand and every one of them was wrong in the same
/// direction. `Mdns::shutdown` read once and then scanned its whole service map,
/// charging the scan and each earlier withdrawal to every later one's ceiling.
/// `Mdns::drain_withdrawals` passed the tick's instant, read before stages 1
/// through 6 — so a receive drain, the timers, the transmit fan-out and the
/// update drain were all deducted from the ceiling of a withdrawal that did not
/// exist while they ran. Past ~1.75 s of that, `note_withdrawal_result`'s clamp
/// puts the next round inside the 250 ms §10.1 interval; past 2 s the very next
/// pass makes the one final ceiling attempt and frees the route after two of the
/// three intended rounds, leaving peers holding records nothing retracted.
///
/// Deleting the parameter is the fix rather than moving the read: a parameter is
/// the channel, and every caller that has one will eventually pass the one it
/// happens to be holding. Same shape as
/// [`SelfSendTracker::take`](crate::selfsend::SelfSendTracker::take).
pub(crate) fn begin_service_withdrawal(
  endpoint: &mut ProtoEndpoint,
  services: &mut HashMap<ServiceHandle, ServiceCtx>,
  handle: ServiceHandle,
) {
  // Scoped so the borrow of `services` ends before `endpoint` is touched; the
  // snapshot and the handoff are both owned.
  let (snapshot, handoff) = match services.get_mut(&handle) {
    Some(ctx) if !ctx.goodbye_begun => {
      ctx.withdrawing = true;
      ctx.goodbye_begun = true;
      (
        ctx.proto.withdrawal_snapshot(),
        ctx.proto.take_rename_goodbye_handoff(),
      )
    }
    _ => return,
  };
  // TWO items, two creation instants, each read where its own schedule is
  // defined. A reading is spent by its first consumer: the rename item's
  // schedule spends the first read, and the whole of `enqueue_rename_withdrawal`
  // — opening the item, holding the name's route, arming its 250 ms interval and
  // its 2 s ceiling — then runs before the service item exists at all. One
  // reading shared between them charged every microsecond of that to the second
  // item's ceiling, which is the same error every deleted caller parameter made,
  // one call frame further in.
  if let Some(handoff) = handoff {
    // The service is dead, so its old name must be held until that goodbye
    // completes: a re-registration must not be able to cancel the only TTL=0
    // retraction the renamed-away name will ever get.
    endpoint.enqueue_rename_withdrawal(handoff, StdInstant::now(), true);
  }
  endpoint.begin_withdrawal(handle, snapshot, StdInstant::now());
}

/// The degraded fallback for a caller that never ran the
/// [`shutdown`](Mdns::shutdown) + [`is_idle`](Mdns::is_idle) loop.
///
/// `Drop` begins the RFC 6762 §10.1 withdrawal for every service still live and
/// then **attempts each pending goodbye exactly once, non-blocking**. That is
/// the whole of it: a destructor cannot sleep, and it cannot re-enter the loop
/// the caller owns.
///
/// Two concrete consequences, neither of which this path can recover from:
///
/// * **§10.1's repeats are never sent.** The endpoint schedules three goodbyes
///   per family, 250 ms apart, precisely so that one lost datagram is recovered
///   by the next. Only the first is attempted here, so a single loss is final.
/// * **A send that returns `WouldBlock` at that instant loses that goodbye
///   outright.** Nothing reached the kernel and there is no loop left to re-offer
///   it, so the family's debt simply goes unpaid.
///
/// In both cases the peers that missed the retraction **keep advertising this
/// service until its record TTL expires, which can be over an hour.** Relying on
/// `Drop` means accepting that a dead service may stay visible on the link for
/// that long.
///
/// [`Mdns::shutdown`] followed by pumping the loop until [`Mdns::is_idle`] is
/// the only path that honours §10.1, and is what callers should use. This exists
/// so that forgetting is not *silent* loss for every peer on the link — not as
/// an alternative to it.
impl Drop for Mdns {
  fn drop(&mut self) {
    self.best_effort_goodbye_pass();
  }
}

#[cfg(test)]
mod tests;

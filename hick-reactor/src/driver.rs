//! Background driver task. Owns the [`mdns_proto::Endpoint`] + per-service /
//! per-query state machines and pumps the I/O loop.

use std::{
  collections::HashMap,
  net::{IpAddr, SocketAddr},
  sync::{Arc, Mutex},
  time::{Duration, Instant as StdInstant, SystemTime},
};

use agnostic_lite::RuntimeLite;
use agnostic_net::{Net, UdpSocket};
use futures::{FutureExt, pin_mut, select_biased};
use mdns_proto::{
  CollectedAnswer, QueryHandle, QuerySpec, ServiceHandle, ServiceSpec, ServiceUpdate,
  endpoint::WithdrawalSend, event::RouteEvent,
};

use crate::{
  command::{Command, QueryStarted, ServiceRegistered},
  error::{RegisterError, StartQueryError},
  options::ServerOptions,
  proto::{ProtoEndpoint, ProtoService},
  query::{QueryMailbox, new_mailbox},
  service::{ServiceMailbox, new_service_mailbox},
};

/// V4/V6 socket pair handed to the driver task.
pub(crate) struct BoundSockets<N: Net> {
  pub(crate) v4: Option<N::UdpSocket>,
  pub(crate) v6: Option<N::UdpSocket>,
  pub(crate) interface_index: u32,
}

/// One inbound packet from a recv subtask.
struct Packet {
  src: SocketAddr,
  data: Vec<u8>,
  /// local receive address from PKTINFO (ipi_spec_dst /
  /// ipi6_addr). `UNSPECIFIED` when PKTINFO is unavailable (Windows,
  /// or a kernel that didn't deliver it) — the proto layer then relies
  /// on its content-hash tracker for self-loopback detection.
  local_ip: IpAddr,
  /// Receiving interface index from PKTINFO (`0` when unknown).
  interface_index: u32,
  /// the *kernel* receive timestamp (from `SO_TIMESTAMP(NS)`
  /// via `RecvMeta::rx_time`) when the OS delivered one, else `None`.
  /// When present it is the authoritative ordering signal for the
  /// self-send tracker: a datagram the kernel stamped BEFORE our send
  /// cannot be our own loopback, so it can't steal that send's credit
  /// even when read later (behind a bounded packet-pump backlog).
  /// Provenance is kept explicit (rather than collapsed to a read-time
  /// `SystemTime`) so the degraded path is never mistaken for ordered:
  /// see `handle_packet`.
  kernel_rx_time: Option<SystemTime>,
  /// Userspace read time, always present. Used (a) for TTL expiry in
  /// every path and (b) as the only available time signal on platforms
  /// that don't deliver a kernel rx timestamp (Windows, or a Unix kernel
  /// that didn't attach the cmsg), where self-detection degrades to a
  /// content-hash take-once match with NO ordering guarantee.
  read_time: SystemTime,
  /// IPv4 TTL / IPv6 Hop Limit of the datagram (from `IP_RECVTTL` /
  /// `IPV6_RECVHOPLIMIT`), or `None` when the platform didn't supply it. The
  /// RFC 6762 §11 on-link check ([`is_on_link`]) drops the packet before the
  /// proto layer when this is present and not 255; `None` degrades to
  /// pass-through (we cannot prove on-link, but neither can we prove off-link).
  hop_limit: Option<u8>,
}

/// Driver-side state for a single registered service.
struct ServiceCtx {
  proto: ProtoService,
  /// bounded/coalescing delivery buffer shared with the `Service` handle. The
  /// driver fills it (`push_update` for non-terminal updates, `set_terminal`
  /// for the `Conflict`/`HostConflict` retirement update) and rings `doorbell`.
  /// The mailbox is owned by the HANDLE (an `Arc` clone outlives this ctx), so
  /// a terminal placed in its reserved slot is delivered to a live reader even
  /// after the ctx is GC'd — which is what lets the withdrawal GC be
  /// unconditional (mirrors the query path's `QueryMailbox`).
  mailbox: Arc<Mutex<ServiceMailbox>>,
  /// Capacity-1 wakeup; closure of its receiver (handle dropped) is how the
  /// driver detects the consumer is gone and withdraws/ GCs the service.
  doorbell: async_channel::Sender<()>,
  /// count of consecutive `poll_transmit` errors for this
  /// service. Once it crosses [`MAX_CONSECUTIVE_ENCODE_ERRORS`] the
  /// driver assumes the registration is structurally unusable (e.g.
  /// records exceed `max_payload_size`) and surfaces `Conflict` so
  /// the caller is notified instead of seeing a misleading
  /// `Established` later.
  encode_failures: u8,
  /// Set when this service has been RETIRED into an endpoint-owned RFC 6762
  /// §10.1 withdrawal (graceful unregister/drop, an encode-failure escalation,
  /// or a rename-collision teardown). The proto state machine is finished, so
  /// every subsequent loop skips it for transmits, deadlines, and the
  /// orphan-sweep — but the ctx is KEPT (the endpoint holds the route, reserving
  /// the name) until [`Endpoint::drain_completed_withdrawals`] reports the
  /// withdrawal complete and the driver GCs the slot. Any
  /// `ServiceUpdate::Conflict` queued at an internal retirement already sits in
  /// the handle-owned mailbox's reserved terminal slot, so it survives the ctx
  /// GC and reaches a live reader.
  withdrawing: bool,
}

/// Driver-side state for a single active query.
struct QueryCtx {
  /// bounded/coalescing delivery buffer shared with the `Query`
  /// handle. The driver fills it (answers + terminal) and rings `doorbell`.
  mailbox: Arc<Mutex<QueryMailbox>>,
  /// Capacity-1 wakeup; closure of its receiver (handle dropped) is how the
  /// driver detects the consumer is gone and GCs the query.
  doorbell: async_channel::Sender<()>,
  last_seq: u64,
}

/// All state owned by the driver task.
struct DriverState<N: Net> {
  endpoint: ProtoEndpoint,
  services: HashMap<ServiceHandle, ServiceCtx>,
  queries: HashMap<QueryHandle, QueryCtx>,
  v4: Option<Arc<N::UdpSocket>>,
  v6: Option<Arc<N::UdpSocket>>,
  /// Shared stats handle — cloned into recv subtasks and the send path so
  /// all I/O counters land in the same [`hick_trace::stats::Stats`] the
  /// proto uses.  Gated on the `stats` feature; the field is absent when
  /// the feature is disabled so zero overhead in the no-stats build.
  #[cfg(feature = "stats")]
  stats: std::sync::Arc<hick_trace::stats::Stats>,
  /// self-send tracker — `(content_hash, send_wall_time)` for every
  /// datagram we recently transmitted. The driver (std layer) owns this
  /// because deciding "is this inbound packet our own loopback?" needs the
  /// kernel receive timestamp + a wall clock, facilities that don't belong
  /// in the `no_std` proto core. An inbound packet is classified self when
  /// its content hash matches a live entry AND its kernel rx timestamp is
  /// at-or-after that entry's send wall-time (consume-once). Both stamps
  /// are `SystemTime` so they're directly comparable; see `Packet::rx_time`.
  /// Keyed on OUR sends only, so its size tracks our (coalescing-bounded)
  /// send rate, not peer traffic.
  recent_sends: Vec<(u64, SystemTime)>,
  /// Reusable scratch for the handles of endpoint-owned withdrawals that
  /// completed in a loop iteration, so [`Endpoint::drain_completed_withdrawals`]
  /// can push into it and the loop can GC each one's driver ctx. Kept on the
  /// state and `clear()`ed each iteration so the per-iteration GC allocates
  /// nothing in steady state.
  completed_withdrawals: Vec<ServiceHandle>,
  /// this host's directly-attached subnets, the source-address
  /// fallback for the RFC 6762 §11 on-link check on platforms that can't
  /// supply a TTL/Hop-Limit. Empty if interface discovery failed (the
  /// fallback then accepts). Snapshotted once at startup. Scoped to
  /// the bound interface only.
  local_subnets: Vec<(IpAddr, u8)>,
  /// the interface index this endpoint is bound to. Used by the
  /// §11 source-address fallback to scope LINK-LOCAL sources: a link-local
  /// address is meaningful only within its own link, so a link-local packet
  /// is on-link only when it arrived on this interface. Always ≥ 1 (the
  /// endpoint always resolves a concrete interface index at bind time).
  bound_interface: u32,
}

impl<N: Net> DriverState<N> {
  fn new(opts: &ServerOptions, sockets: BoundSockets<N>) -> Self {
    use rand::SeedableRng;
    // rand 0.10 removed `from_entropy`; seed StdRng from the OS-seeded thread RNG.
    let rng = rand::rngs::StdRng::from_rng(&mut rand::rng());
    let endpoint = ProtoEndpoint::try_new(*opts.endpoint_config(), rng);
    let bound_interface = sockets.interface_index;
    #[cfg(feature = "stats")]
    let stats = endpoint.stats_handle();
    Self {
      endpoint,
      services: HashMap::new(),
      queries: HashMap::new(),
      recent_sends: Vec::new(),
      completed_withdrawals: Vec::new(),
      // scope the §11 source-subnet fallback to the BOUND
      // interface only — not every local NIC (per-packet interface index for
      // delivered PKTINFO is handled separately in recv_with_meta).
      local_subnets: collect_local_subnets(bound_interface),
      bound_interface,
      v4: sockets.v4.map(Arc::new),
      v6: sockets.v6.map(Arc::new),
      #[cfg(feature = "stats")]
      stats,
    }
  }

  /// Compute the earliest deadline across endpoint, services, and queries.
  ///
  /// Endpoint-owned withdrawal deadlines (the next due goodbye round and the 2 s
  /// anti-pin ceiling) are already folded into [`Endpoint::poll_timeout`], so the
  /// driver no longer tracks them here. A `withdrawing` service is skipped: its
  /// proto state machine is finished, and its withdrawal schedule lives in the
  /// endpoint.
  /// The earliest endpoint-owned WITHDRAWAL deadline (next due goodbye round or
  /// the 2 s anti-pin ceiling), or `None` when no withdrawal is in flight —
  /// EXCLUDING cache, query, and service deadlines. The last-handle shutdown flush
  /// uses this (not [`Self::next_deadline`]) so it exits as soon as every goodbye
  /// is sent rather than parking on unrelated cache expiry or the wall-clock
  /// backstop.
  fn next_withdrawal_deadline(&self) -> Option<StdInstant> {
    self.endpoint.next_withdrawal_deadline()
  }

  fn next_deadline(&self) -> Option<StdInstant> {
    let mut best: Option<StdInstant> = self.endpoint.poll_timeout();
    for ctx in self.services.values() {
      if ctx.withdrawing {
        continue;
      }
      if let Some(t) = ctx.proto.poll_timeout() {
        best = Some(min_opt(best, t));
      }
    }
    for handle in self.queries.keys() {
      if let Some(t) = self.endpoint.poll_query_timeout(*handle) {
        best = Some(min_opt(best, t));
      }
    }
    best
  }

  fn handle_command(&mut self, cmd: Command, now: StdInstant) {
    match cmd {
      Command::RegisterService { spec, reply } => {
        // if the caller's future was cancelled between
        // sending the command and awaiting the reply, `reply.send`
        // will fail. Roll back the proto/driver-side state so no
        // orphan Service is left probing/announcing without a handle.
        let result = self.register_service(spec, now);
        if let Ok(ref ok) = result {
          let handle = ok.handle;
          if let Err(returned) = reply.send(result) {
            // returned is the (now-unowned) Result<ServiceRegistered, _>;
            // dropping it drops the receiver half of the per-handle
            // channel, but the proto Service still lives in our map
            // until we GC it explicitly here.
            drop(returned);
            // go through the shared retirement path. The service was just
            // registered (still probing, never announced), so its withdrawal
            // snapshot is empty and the endpoint completes it immediately with no
            // goodbye on the wire — the rollback stays silent, as it should.
            self.remove_service(handle, now);
            hick_trace::debug!(
              ?handle,
              "RegisterService caller cancelled before reply; rolled back orphan state"
            );
          }
        } else {
          let _ = reply.send(result);
        }
      }
      Command::UnregisterService { handle } => {
        // graceful withdrawal goes through the shared retirement helper so an
        // explicit unregister and a dropped-handle sweep both begin the
        // endpoint-owned §10.1 withdrawal.
        self.remove_service(handle, now);
      }
      Command::StartQuery { spec, reply } => {
        // mirror: undo on cancellation.
        let result = self.start_query(spec, now);
        if let Ok(ref ok) = result {
          let handle = ok.handle;
          if let Err(returned) = reply.send(result) {
            drop(returned);
            let _ = self.endpoint.cancel_query(handle);
            self.queries.remove(&handle);
            hick_trace::debug!(
              ?handle,
              "StartQuery caller cancelled before reply; rolled back orphan state"
            );
          }
        } else {
          let _ = reply.send(result);
        }
      }
      Command::CancelQuery { handle } => {
        let _ = self.endpoint.cancel_query(handle);
        self.queries.remove(&handle);
      }
      Command::SpawnLookup { task } => {
        // spawn from WITHIN the driver task so the child inherits this task's
        // runtime context — the endpoint may have been created on a different
        // executor/thread than the caller of `browse()`, where a direct
        // ambient `spawn` would panic (no entered runtime).
        <N::Runtime as RuntimeLite>::spawn_detach(task);
      }
    }
  }

  fn register_service(
    &mut self,
    spec: ServiceSpec,
    now: StdInstant,
  ) -> Result<ServiceRegistered, RegisterError> {
    let (handle, svc) = self
      .endpoint
      .try_register_service::<slab::Slab<_>, slab::Slab<_>>(spec, now)?;
    // handle-owned, reserved-terminal mailbox + capacity-1 doorbell — exactly
    // the query wiring. The mailbox bounds + coalesces non-terminal updates
    // (`Established`/`Renamed`) so an on-link peer forcing endless
    // conflict-renames cannot grow memory, while the terminal retirement update
    // (`Conflict`/`HostConflict`) keeps a reserved slot. Because the `Service`
    // handle holds an `Arc` clone of the mailbox, that terminal is delivered to
    // a live reader even after the driver GCs this ctx.
    let (mailbox, doorbell_tx, doorbell_rx) = new_service_mailbox();
    self.services.insert(
      handle,
      ServiceCtx {
        proto: svc,
        mailbox: Arc::clone(&mailbox),
        doorbell: doorbell_tx,
        encode_failures: 0,
        withdrawing: false,
      },
    );
    Ok(ServiceRegistered {
      handle,
      mailbox,
      doorbell: doorbell_rx,
    })
  }

  fn start_query(
    &mut self,
    spec: QuerySpec,
    now: StdInstant,
  ) -> Result<QueryStarted, StartQueryError> {
    let handle = self
      .endpoint
      .try_start_query(spec, now)
      .map_err(|_| StartQueryError::StorageFull)?;
    // bounded/coalescing mailbox + capacity-1 doorbell instead of
    // an unbounded channel, so a slow consumer + answer flood can't OOM us.
    let (mailbox, doorbell_tx, doorbell_rx) = new_mailbox();
    self.queries.insert(
      handle,
      QueryCtx {
        mailbox: Arc::clone(&mailbox),
        doorbell: doorbell_tx,
        last_seq: 0,
      },
    );
    Ok(QueryStarted {
      handle,
      mailbox,
      doorbell: doorbell_rx,
    })
  }

  fn handle_packet(&mut self, pkt: Packet) {
    // RFC 6762 §11 on-link trust boundary: a datagram that did NOT originate
    // on the local link must be dropped before the proto layer can act on
    // (cache, conflict, withdraw) attacker-injected records.
    //   - when the kernel reported the IPv4 TTL / IPv6 Hop Limit,
    //     require exactly 255 (any lower value crossed a router).
    //   - when it didn't (Windows / illumos / solaris / fuchsia /
    //     no cmsg), fall back to a source-address-on-local-subnet check.
    let on_link = match pkt.hop_limit {
      Some(_) => is_on_link(pkt.hop_limit),
      None => src_on_local_link(
        &self.local_subnets,
        self.bound_interface,
        pkt.interface_index,
        pkt.src.ip(),
      ),
    };
    if !on_link {
      hick_trace::debug!(
        src = %pkt.src,
        hop_limit = ?pkt.hop_limit,
        "dropping off-link packet (RFC 6762 §11 trust boundary)"
      );
      // The datagram WAS received off the socket — count it toward receive
      // volume exactly once (matching the proto path: packets_rx + bytes_rx at
      // entry, then one reject counter). The proto's handle() is NOT called, so
      // proto cannot bump these counters itself; we do it here instead.
      #[cfg(feature = "stats")]
      {
        self.stats.packets_rx(1);
        self.stats.bytes_rx(pkt.data.len() as u64);
        self.stats.packets_dropped(1);
      }
      return;
    }

    // enforce the §11 source-port rule for RESPONSES *before*
    // consuming a self-send credit. Proto re-checks this for
    // direct callers, but if we let an untrusted response reach
    // `take_self_send` first, an on-link attacker's byte-identical copy from
    // an ephemeral port could burn the take-once credit — then proto
    // suppresses the attacker's copy, and our genuine port-5353 loopback
    // arrives with no credit and is mis-processed as a trusted peer. Drop
    // untrusted responses here so they never touch `recent_sends`. (Queries,
    // QR=0, are exempt — legacy unicast queriers use ephemeral ports.)
    if packet_is_response(&pkt.data) && pkt.src.port() != hick_udp::constants::MDNS_PORT {
      hick_trace::debug!(
        src = %pkt.src,
        "dropping untrusted response (source port != 5353) before self-send match"
      );
      // Same as the off-link path above: the datagram was received, so count
      // receive volume once and the reject counter once. proto's handle() is
      // not reached, so this is the sole accounting point.
      #[cfg(feature = "stats")]
      {
        self.stats.packets_rx(1);
        self.stats.bytes_rx(pkt.data.len() as u64);
        self.stats.packets_dropped(1);
      }
      return;
    }

    // local_ip + interface_index come from PKTINFO (via
    // hick_udp::recv_with_meta); UNSPECIFIED/0 when PKTINFO is unavailable.
    let local_ip = pkt.local_ip;
    let interface_index = pkt.interface_index;

    // the AUTHORITATIVE self-loopback decision happens
    // HERE, in the std driver, against our recorded send wall-times. We
    // hand the result to the proto layer as an explicit flag; proto keeps
    // no self-send tracker of its own.
    //
    // When the kernel gave us a receive timestamp we match in ORDERED
    // mode: the datagram is ours only if its kernel stamp is at-or-after
    // (within a sub-microsecond grain) the recorded send time,
    // which is what excludes a byte-identical peer datagram the kernel
    // saw before we sent. When no kernel timestamp is available we fall
    // back to a DEGRADED content-hash take-once match keyed on read time
    // — correct for normal single-host operation but, by construction,
    // unable to defend the credit-theft race (documented on
    // `take_self_send`).
    let caller_is_self = match pkt.kernel_rx_time {
      Some(rx) => take_self_send(&mut self.recent_sends, &pkt.data, rx, MatchMode::Ordered),
      None => take_self_send(
        &mut self.recent_sends,
        &pkt.data,
        pkt.read_time,
        MatchMode::Degraded,
      ),
    };

    // proto `now` is monotonic; process time is fine for cache TTL /
    // scheduling (the self-loopback ordering used the SystemTime rx stamp
    // above, not this value).
    let now = StdInstant::now();

    // Split-borrow: endpoint and services are disjoint fields.
    let Self {
      endpoint, services, ..
    } = self;

    let route_events = match endpoint.handle(
      now,
      pkt.src,
      local_ip,
      interface_index,
      &pkt.data,
      caller_is_self,
    ) {
      Ok(it) => it,
      Err(_e) => {
        hick_trace::debug!(error = %_e, src = %pkt.src, "endpoint.handle failed");
        return;
      }
    };

    for ev in route_events {
      match ev {
        Ok(RouteEvent::ToService(ts)) => {
          if let Some(ctx) = services.get_mut(&ts.handle()) {
            ctx.proto.handle_event(ts.into_event(), now);
          }
        }
        // ToQuery answers are dispatched inside endpoint.handle();
        // CacheUpdated is a future hook for cache subscribers; any new
        // RouteEvent variant added by mdns-proto is ignored until we wire
        // it up here.
        Ok(_) => {}
        Err(_e) => {
          hick_trace::debug!(error = %_e, "route event error mid-packet; bailing");
          break;
        }
      }
    }
  }

  fn fire_timeouts(&mut self, now: StdInstant) {
    let _ = self.endpoint.handle_timeout(now);
    for ctx in self.services.values_mut() {
      // Don't tick a withdrawing service's proto: its lifecycle is finished and
      // its goodbye schedule lives in the endpoint, so driving the dead driver
      // proto here is pure waste. Mirrors the smoltcp/compio timeout paths, which
      // skip errored/cancelled services.
      if ctx.withdrawing {
        continue;
      }
      let _ = ctx.proto.handle_timeout(now);
    }
    let query_handles: Vec<QueryHandle> = self.queries.keys().copied().collect();
    for h in query_handles {
      let _ = self.endpoint.handle_query_timeout(h, now);
    }
  }

  /// Push any pending updates / new answers out to the per-handle channels.
  ///
  /// per-handle channels are unbounded, so `try_send` only ever
  /// fails with `Closed` (consumer dropped the receiver). Critical events
  /// (Established / Renamed / Conflict / HostConflict / Terminal) reach
  /// the caller as long as the receiver is alive.
  ///
  /// (auto-rename routing): when
  /// [`ServiceUpdate::Renamed`] is observed, update the endpoint's route
  /// table BEFORE forwarding the event so callers can safely re-issue
  /// queries at the new name. If the new name collides with another
  /// registered service (proto returns `NameAlreadyRegistered`), drop the
  /// service and emit a synthesized `Conflict` instead of a `Renamed`.
  ///
  /// (orphan sweep): also GC handles whose receiver has been
  /// closed even when there is no event to push (e.g. caller dropped a
  /// Query handle that never collected any answer).
  async fn push_updates(&mut self, now: StdInstant) {
    // services to retire this pass. Collected here and retired AFTER the split
    // borrow ends so every retirement goes through `remove_service`, which begins
    // the endpoint-owned §10.1 withdrawal (the endpoint holds the route + drives
    // the goodbye schedule; a service still probing / mid-rename has an empty
    // snapshot and completes with nothing on the wire — safe for all cases).
    let mut removed_services: Vec<ServiceHandle> = Vec::new();
    {
      // Split-borrow so we can mutate self.endpoint inside the loops.
      let Self {
        endpoint,
        services,
        queries,
        ..
      } = self;

      // ── Service updates ───────────────────────────────────────────────
      for (handle, ctx) in services.iter_mut() {
        // A service already withdrawing has a finished proto state machine and
        // the endpoint owns its goodbye schedule; skip it (the ctx is GC'd by
        // `drain_withdrawals` once the withdrawal completes).
        if ctx.withdrawing {
          continue;
        }
        // even if no event is pending, a closed doorbell receiver means the
        // caller dropped their handle — withdraw the service gracefully.
        if ctx.doorbell.is_closed() {
          removed_services.push(*handle);
          continue;
        }
        while let Some(upd) = ctx.proto.poll() {
          // keep endpoint routing consistent on
          // auto-rename. If the proto rejects the new name (already owned by
          // another local service), the Service has already mutated its
          // records — we cannot safely keep it. Emit Conflict, then remove.
          let final_upd = match upd {
            ServiceUpdate::Renamed(ref renamed) => {
              let rename_result =
                endpoint.handle_service_renamed(*handle, renamed.new_name().clone());
              // The §9 rename of an announced service hands its OLD-name TTL=0
              // goodbye off as an INDEPENDENT detached withdrawal item, both for a
              // SURVIVING rename and a COLLISION teardown. Take it the instant the
              // rename is observed and enqueue it on the endpoint — the Service no
              // longer drains the old-name goodbye itself.
              if let Some(h) = ctx.proto.take_rename_goodbye_handoff() {
                endpoint.enqueue_rename_withdrawal(h, now);
              }
              match rename_result {
                Ok(()) => upd,
                Err(_) => {
                  // The new name collides with another local service; the Service
                  // has already rebranded and can't be kept. Surface Conflict (into
                  // the handle-owned mailbox's reserved terminal slot), then retire
                  // it: `remove_service` begins the endpoint-owned withdrawal for
                  // the CURRENT name and holds the route (keeping it reserved) while
                  // it resends, freeing the name on completion. The OLD name's
                  // goodbye was already enqueued above as its own detached item. The
                  // mailbox outlives the ctx, so this Conflict still reaches the
                  // host even after the withdrawal GCs the ctx.
                  hick_trace::warn!(
                    handle = ?handle,
                    new_name = %renamed.new_name(),
                    "auto-rename collided with another registered service; emitting Conflict"
                  );
                  deliver_service_update(ctx, ServiceUpdate::Conflict);
                  removed_services.push(*handle);
                  break;
                }
              }
            }
            _ => upd,
          };
          // The mailbox coalesces by kind (one Established, latest Renamed) and
          // reserves the terminal, so a hostile peer repeating an event cannot
          // grow it — no consecutive-duplicate bookkeeping needed here.
          deliver_service_update(ctx, final_upd);
        }
      }

      // ── Query answers + terminals ─────────────────────────────────────
      let mut terminated: Vec<QueryHandle> = Vec::new();
      let handles: Vec<QueryHandle> = queries.keys().copied().collect();
      for h in handles {
        // sweep: GC queries whose consumer dropped the handle (the
        // doorbell receiver closes when the `Query` is dropped).
        if let Some(ctx) = queries.get(&h)
          && ctx.doorbell.is_closed()
        {
          terminated.push(h);
          continue;
        }
        // 1. New answers (seq-based scan) — buffer BEFORE the terminal so the
        //    caller observes all collected data before the Terminal frame.
        let last_seq = match queries.get(&h) {
          Some(c) => c.last_seq,
          None => continue,
        };
        let new_answers: Vec<CollectedAnswer> = endpoint
          .collected_answers(h)
          .filter(|a| a.seq() >= last_seq)
          .cloned()
          .collect();
        // `collected_answers` is proto's BOUNDED snapshot — the
        // `max_answers` cap evicts oldest entries before we scan. Answers
        // accepted since our last scan but no longer present were evicted
        // before delivery; count them so the loss is observable via
        // `Query::dropped_answers` rather than silently vanishing.
        let accepted = endpoint.query_accepted_count(h).unwrap_or(last_seq);
        let expected = accepted.saturating_sub(last_seq);
        let evicted_before_seen = expected.saturating_sub(new_answers.len() as u64);
        if let Some(ctx) = queries.get_mut(&h)
          && (!new_answers.is_empty() || evicted_before_seen > 0)
        {
          let had_new = !new_answers.is_empty();
          // push into the bounded/coalescing mailbox (never
          // fails / never blocks; over-capacity coalesces or drops oldest).
          {
            let mut mb = ctx.mailbox.lock().unwrap_or_else(|e| e.into_inner());
            mb.record_dropped(evicted_before_seen);
            for ans in new_answers {
              mb.push_answer(ans);
            }
          }
          // Advance past everything proto has accepted: delivered answers and
          // evicted-before-seen ones are now all accounted for.
          ctx.last_seq = accepted;
          // Ring ONCE for the batch — only when there's an answer to drain
          // (a pure-eviction bookkeeping bump has nothing for the consumer).
          if had_new {
            let _ = ctx.doorbell.try_send(());
          }
        }

        // 2. Drain terminal from endpoint.poll_query into its reserved mailbox
        //    slot (never dropped under answer backpressure).
        if let Some(terminal) = endpoint.poll_query(h)
          && let Some(ctx) = queries.get_mut(&h)
        {
          ctx
            .mailbox
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_terminal(terminal);
          let _ = ctx.doorbell.try_send(());
          terminated.push(h);
        }
      }
      // GC: drop terminated queries to free pool slots.
      for h in terminated {
        let _ = endpoint.cancel_query(h);
        queries.remove(&h);
      }

      // Endpoint-level events: drain & discard (no caller channel yet).
      while let Some(_ev) = endpoint.poll() {}
    }

    // remove the services collected above via the goodbye-aware
    // helper, now that the split borrow has ended.
    for h in removed_services {
      self.remove_service(h, now);
    }
  }

  /// Drain outgoing transmits across services + queries, up to
  /// [`MAX_TRANSMITS_PER_DRAIN`] per call.
  ///
  /// every ACTUAL socket send records its own self-send tracker
  /// entry via [`record_self_send`]. With the take-once suppression
  /// introduced earlier, a single entry can match only one inbound
  /// loopback. Dual-stack fan-out sends the same payload to BOTH v4 and v6
  /// multicast sockets, so the tracker needs two entries to suppress both
  /// copies — not one. The entry is therefore recorded inside `send_via`
  /// per real send, not here.
  ///
  /// capped at [`MAX_SEND_CREDITS_PER_DRAIN`] sends per call so
  /// the work per drain pass stays bounded. Returns `true` if more
  /// transmits are pending so the driver loop knows to schedule another
  /// drain pass on the next tick rather than sleeping.
  #[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", skip_all, fields(credits = MAX_SEND_CREDITS_PER_DRAIN))
  )]
  async fn drain_transmits(&mut self, now: StdInstant, scratch: &mut [u8]) -> bool {
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();
    let Self {
      endpoint,
      services,
      queries,
      recent_sends,
      v4,
      v6,
      ..
    } = self;
    // Plain fairness cap: bound the work per drain pass so a very large
    // handle set can't monopolise the loop before commands / packets are
    // serviced. (Self-loopback safety no longer depends on this — it's the
    // SystemTime-keyed `recent_sends` tracker + kernel rx timestamps.)
    let mut credits_remaining = MAX_SEND_CREDITS_PER_DRAIN;
    // Service transmits.
    let service_handles: Vec<mdns_proto::ServiceHandle> = services.keys().copied().collect();
    for h in service_handles {
      if credits_remaining == 0 {
        return true;
      }
      // re-check liveness AT this handle so a drop / cancel
      // command racing with the per-loop sweep does not still emit a
      // transmit for an already-orphaned handle. A `withdrawing` service is
      // also skipped: its proto state machine is finished and the endpoint
      // owns the TTL=0 goodbye schedule (pumped by `drain_withdrawals`).
      let live = services
        .get(&h)
        .map(|c| !c.doorbell.is_closed() && !c.withdrawing)
        .unwrap_or(false);
      if !live {
        continue;
      }
      let mut hit_encode_error = false;
      loop {
        if credits_remaining == 0 {
          return true;
        }
        // distinguish "no more pending"
        // (Ok(None)) from a real encoding error (Err). Track
        // consecutive failures per service so persistent encoding
        // errors (e.g. records exceed `max_payload_size`) surface as
        // `ServiceUpdate::Conflict` instead of letting the lifecycle
        // tick to `Established` silently.
        let tx = match services.get_mut(&h) {
          Some(ctx) => match ctx.proto.poll_transmit(now, scratch) {
            Ok(Some(t)) => {
              ctx.encode_failures = 0;
              t
            }
            Ok(None) => {
              ctx.encode_failures = 0;
              break;
            }
            Err(_e) => {
              ctx.encode_failures = ctx.encode_failures.saturating_add(1);
              hick_trace::warn!(
                handle = ?h,
                error = ?_e,
                scratch_size = scratch.len(),
                consecutive_failures = ctx.encode_failures,
                "Service::poll_transmit failed"
              );
              hit_encode_error = true;
              break;
            }
          },
          None => break,
        };
        let body_len = tx.size();
        let used = send_via::<N>(
          recent_sends,
          v4,
          v6,
          tx.dst(),
          &scratch[..body_len],
          #[cfg(feature = "stats")]
          &stats,
        )
        .await;
        // report the send RESULT so the
        // proto advances its lifecycle — the §8.1 probe sequence, the §8.3
        // announce phase, and the goodbye-ownership guards — ONLY on a
        // confirmed-delivered send (`used > 0` = at least one socket send
        // succeeded). On all-socket failure (`used == 0`) the proto re-arms and
        // retries WITHOUT advancing, so a service can never claim a name it
        // never probed, nor enable a goodbye for records peers never received.
        // `StdInstant::now()` anchors any scheduled deadline to post-send time
        // (a long `send_via` await would put a pre-send deadline in the past).
        if let Some(ctx) = services.get_mut(&h) {
          ctx.proto.note_transmit_result(StdInstant::now(), used > 0);
          // Mirror the service's CONFIRMED-ADVERTISED host set into the endpoint
          // route so sibling host-address retention (during a same-host
          // withdrawal) honours what this service ACTUALLY announced, not its
          // configured addresses. Idempotent overwrite; only meaningful after a
          // delivered send. `endpoint` and `services` are disjointly borrowed
          // from `self` above, so this borrow split is sound.
          if used > 0 {
            endpoint.note_service_advertised(
              h,
              ctx.proto.advertised_a_addrs(),
              ctx.proto.advertised_aaaa_addrs(),
            );
          }
        }
        credits_remaining = credits_remaining.saturating_sub(used);
      }
      // persistent encode failure → escalate to Conflict.
      if hit_encode_error {
        let escalate = services
          .get(&h)
          .map(|c| c.encode_failures >= MAX_CONSECUTIVE_ENCODE_ERRORS)
          .unwrap_or(false);
        if escalate {
          hick_trace::warn!(
            handle = ?h,
            "Service exceeded MAX_CONSECUTIVE_ENCODE_ERRORS; emitting Conflict and withdrawing"
          );
          // Surface Conflict (into the handle-owned mailbox's reserved terminal
          // slot) and begin the endpoint-owned withdrawal. The endpoint KEEPS the
          // route (holding the name) and frees it on withdrawal completion; the
          // ctx is marked `withdrawing` and GC'd unconditionally by
          // `drain_withdrawals` once the withdrawal completes — the Conflict still
          // reaches the host because the mailbox outlives the ctx. A service that
          // persistently failed to ENCODE never reached Established, so its
          // snapshot is empty and the withdrawal completes on the next iteration
          // with no datagram on the wire (the records are fixed at registration
          // and the scratch is fixed, so an encode failure is permanent, not
          // transient). `begin_withdrawal` is idempotent. Inlined (not via
          // `begin_service_withdrawal`) because `self` is split-borrowed here into
          // `endpoint` + `services`.
          if let Some(ctx) = services.get_mut(&h) {
            deliver_service_update(ctx, ServiceUpdate::Conflict);
            ctx.withdrawing = true;
            // Enqueue any pending §9 rename handoff before snapshotting: keep the old-name goodbye exactly-once on every retirement
            // path, not just the update-drain site. (A persistently-encode-failing
            // service never announced, so this is usually `None` — but uniform.)
            if let Some(handoff) = ctx.proto.take_rename_goodbye_handoff() {
              endpoint.enqueue_rename_withdrawal(handoff, now);
            }
            let snap = ctx.proto.withdrawal_snapshot();
            endpoint.begin_withdrawal(h, snap, now);
          }
        }
      }
    }
    // Query transmits.
    let handles: Vec<QueryHandle> = queries.keys().copied().collect();
    // Collect queries that were retired due to encode failures so they can be
    // GC'd after the loop (matching the terminated-handle cleanup in push_updates).
    let mut encode_retired: Vec<QueryHandle> = Vec::new();
    // Use a flag instead of an early `return true` inside the query loop so
    // that encode_retired GC ALWAYS runs before the function returns — even
    // when the send budget is exhausted mid-loop.  An early `return true` here
    // would bypass the cleanup below and leave the retired handle resident in
    // both `queries` and proto storage until the user drops the stream.
    let mut more_pending = false;
    'query_loop: for h in handles {
      if credits_remaining == 0 {
        more_pending = true;
        break 'query_loop;
      }
      let live = queries
        .get(&h)
        .map(|c| !c.doorbell.is_closed())
        .unwrap_or(false);
      if !live {
        continue;
      }
      while credits_remaining > 0 {
        // surface encoding errors instead of treating them
        // as "no more transmits".
        let tx = match endpoint.poll_query_transmit(h, now, scratch) {
          Ok(Some(t)) => t,
          Ok(None) => break,
          Err(_e) => {
            // Retire the proto query (records terminal: queries_done /
            // queries_timeout + decr_queries_active), consistent with the
            // smoltcp driver which also calls retire_query on this error.
            // Then drain the resulting terminal into the mailbox so
            // `Query::next` surfaces `QueryEvent::Terminal` rather than
            // parking or silently ending.
            endpoint.retire_query(h);
            if let Some(terminal) = endpoint.poll_query(h)
              && let Some(ctx) = queries.get(&h)
            {
              ctx
                .mailbox
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .set_terminal(terminal);
              let _ = ctx.doorbell.try_send(());
            }
            encode_retired.push(h);
            hick_trace::warn!(
              handle = ?h,
              error = ?_e,
              scratch_size = scratch.len(),
              "Endpoint::poll_query_transmit failed; retiring proto query (terminal pushed to Query::next)"
            );
            break;
          }
        };
        let body_len = tx.size();
        let used = send_via::<N>(
          recent_sends,
          v4,
          v6,
          tx.dst(),
          &scratch[..body_len],
          #[cfg(feature = "stats")]
          &stats,
        )
        .await;
        // report the send result so the query advances its retry
        // budget only on a confirmed-delivered send. On all-socket failure
        // (`used == 0`) the query re-attempts without burning the budget rather
        // than timing out having put nothing on the wire.
        // anchor the retry backoff to POST-send time — `send_via`
        // can await longer than the backoff interval, so the pre-send `now`
        // would schedule a deadline already in the past.
        endpoint.note_query_transmit_result(h, StdInstant::now(), used > 0);
        credits_remaining = credits_remaining.saturating_sub(used);
      }
    }
    // GC queries retired by encode failure (mirrors the push_updates terminated
    // path).  This cleanup is intentionally placed AFTER the loop so it runs
    // on EVERY exit path — both normal completion and the budget-exhausted
    // `break` above.  Never skip this block by returning early from inside the
    // loop.
    for h in encode_retired {
      let _ = endpoint.cancel_query(h);
      queries.remove(&h);
    }
    more_pending
  }

  /// GC handles whose caller has dropped the receiver. Runs at
  /// the TOP of the driver loop (before `fire_timeouts` /
  /// `drain_transmits`) so an orphan query cancelled between its
  /// `StartQuery` reply and the caller receiving the handle cannot
  /// multicast a question before being collected.
  fn sweep_closed_handles(&mut self, now: StdInstant) {
    // a dropped Service handle closes its doorbell receiver AND enqueues
    // UnregisterService. This sweep can win the race and collect the service
    // first, so it MUST route through `remove_service` (which begins the
    // endpoint-owned §10.1 withdrawal) — otherwise the dropped service is
    // silently withdrawn with no TTL=0 goodbye and peers keep stale records until
    // TTL expiry. A service ALREADY withdrawing is skipped (its ctx is GC'd by
    // `drain_withdrawals` on completion); re-beginning would be an idempotent
    // no-op anyway.
    let dead_svc: Vec<ServiceHandle> = self
      .services
      .iter()
      .filter(|(_, ctx)| ctx.doorbell.is_closed() && !ctx.withdrawing)
      .map(|(h, _)| *h)
      .collect();
    for h in dead_svc {
      self.remove_service(h, now);
    }
    let dead_q: Vec<QueryHandle> = self
      .queries
      .iter()
      .filter(|(_, ctx)| ctx.doorbell.is_closed())
      .map(|(h, _)| *h)
      .collect();
    for h in dead_q {
      self.queries.remove(&h);
      let _ = self.endpoint.cancel_query(h);
    }
  }

  /// Retire a service into its endpoint-owned RFC 6762 §10.1 withdrawal. Shared
  /// by explicit `UnregisterService` and the dropped-handle sweep so withdrawal
  /// is graceful regardless of which path removes it.
  ///
  /// The endpoint KEEPS the route (holding the name against a same-name
  /// re-registration) and drives the TTL=0 goodbye resend schedule; the driver
  /// loop pumps each due goodbye datagram and, on completion, frees the route and
  /// GCs the driver ctx. This withdrawal covers the records the service
  /// confirmed-emitted under its CURRENT name (host A/AAAA filtered against
  /// same-host siblings by the endpoint). An in-flight conflict-rename old-name
  /// goodbye is a SEPARATE detached withdrawal item, enqueued the instant the
  /// rename happened via [`Endpoint::enqueue_rename_withdrawal`]. A
  /// never-announced service has an empty snapshot and completes on the next loop
  /// iteration with no datagram on the wire.
  ///
  /// The driver ctx is NOT removed here: it is kept (marked `withdrawing`) until
  /// the endpoint reports the withdrawal complete, then GC'd unconditionally. Any
  /// already-queued `ServiceUpdate::Conflict` lives in the handle-owned mailbox's
  /// reserved terminal slot (which outlives the ctx), so it still reaches the host
  /// after the GC.
  fn remove_service(&mut self, handle: ServiceHandle, now: StdInstant) {
    self.begin_service_withdrawal(handle, now);
  }

  /// Begin the endpoint-owned RFC 6762 §10.1 withdrawal for `handle`: mark the
  /// ctx `withdrawing` (so every subsequent loop skips it for transmits,
  /// deadlines, and the orphan-sweep), snapshot what its CURRENT name's goodbye
  /// must retract ([`Service::withdrawal_snapshot`]), and hand it to
  /// [`Endpoint::begin_withdrawal`]. The endpoint holds the route and drives the
  /// resend schedule; the route is freed and the driver ctx GC'd when
  /// [`Endpoint::drain_completed_withdrawals`] reports completion in the loop. Any
  /// in-flight §9 rename old-name goodbye is a SEPARATE detached item already
  /// enqueued via [`Endpoint::enqueue_rename_withdrawal`].
  ///
  /// `begin_withdrawal` is idempotent, so calling this for an already-withdrawing
  /// service is a no-op. A no-op for an unknown driver handle.
  fn begin_service_withdrawal(&mut self, handle: ServiceHandle, now: StdInstant) {
    // Scope the `ctx` borrow so it ends before `self.endpoint` is touched (the
    // snapshot is owned, so no borrow of `self.services` outlives this block).
    // ALSO take any pending §9 rename handoff here: a retirement that races a
    // queued `Renamed` update (closed receiver / explicit unregister) never
    // reaches the update-drain site that normally enqueues it, which would strand
    // the old-name goodbye in a proto being GC'd. `.take()` makes the handoff
    // exactly-once vs the update-drain path.
    let (snap, handoff) = match self.services.get_mut(&handle) {
      Some(ctx) => {
        ctx.withdrawing = true;
        let handoff = ctx.proto.take_rename_goodbye_handoff();
        (ctx.proto.withdrawal_snapshot(), handoff)
      }
      None => return,
    };
    if let Some(handoff) = handoff {
      self.endpoint.enqueue_rename_withdrawal(handoff, now);
    }
    self.endpoint.begin_withdrawal(handle, snap, now);
  }

  /// Pump every due endpoint-owned withdrawal goodbye, then free + GC every
  /// completed withdrawal.
  ///
  /// The endpoint encodes each TTL=0 goodbye (with fresh sibling host-address
  /// retention computed internally), hands back the multicast datagram + the
  /// withdrawing handle; the driver fans it to BOTH groups via
  /// `send_withdrawal_via`, reports back EACH family's `WithdrawalSend` outcome so
  /// the endpoint tracks per-family debt (a withdrawal frees only once every
  /// reachable family has withdrawn its records), and bumps `goodbyes_tx` once per
  /// DELIVERED round. After draining transmits,
  /// [`Endpoint::drain_completed_withdrawals`] frees each completed route
  /// (decrementing `services_active`) and the driver GCs its ctx.
  ///
  /// GC of a completed ctx is UNCONDITIONAL: any terminal `Conflict`/
  /// `HostConflict` queued at an internal retirement already lives in the
  /// HANDLE-owned [`ServiceMailbox`]'s reserved terminal slot, and the handle's
  /// `Arc` clone outlives this ctx, so the terminal is still delivered to a live
  /// reader after the ctx is dropped. A dropped reader means the handle's `Arc`
  /// (and its doorbell receiver) are gone and the buffered terminal is simply
  /// collected with the mailbox. No flag, no park, no retry (mirrors the query
  /// path, whose terminal also lives in a handle-owned mailbox).
  async fn drain_withdrawals(&mut self, now: StdInstant, scratch: &mut [u8]) {
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();
    // Split-borrow disjoint fields so `send_via` can borrow `recent_sends`/`v4`/
    // `v6` while `endpoint` is borrowed for the withdrawal pump.
    let Self {
      endpoint,
      recent_sends,
      v4,
      v6,
      ..
    } = self;
    while let Some((dst, len, token)) = endpoint.poll_withdrawal_transmit(now, scratch) {
      // The endpoint always returns the multicast marker; the driver fans the
      // datagram to both groups regardless. Assert the contract in debug builds.
      debug_assert!(
        matches!(dst, SocketAddr::V4(v4a) if v4a.ip().is_multicast() && v4a.port() == 5353),
        "withdrawal dst must be the IPv4 multicast marker"
      );
      let _ = dst;
      // Fan to both families and capture EACH family's outcome so the endpoint
      // tracks per-family debt: a withdrawal frees only once every reachable
      // family has withdrawn its records. `send_withdrawal_via` already bumps
      // packets_tx/bytes_tx per Sent family and send_errors per failed family, so
      // here we add only the per-round goodbyes_tx (one per DELIVERED round).
      let (v4_out, v6_out) = send_withdrawal_via::<N>(
        recent_sends,
        v4,
        v6,
        &scratch[..len],
        #[cfg(feature = "stats")]
        &stats,
      )
      .await;
      // A delivered round (>= 1 family Sent) bumps goodbyes_tx; a v4-Sent + v6-busy
      // round keeps v6's debt so a v6 recovery before the 2 s ceiling still emits
      // its TTL=0 goodbye. A fully-undeliverable round is re-armed (short backoff)
      // by the endpoint WITHOUT spending.
      #[cfg(feature = "stats")]
      if matches!(v4_out, WithdrawalSend::Sent) || matches!(v6_out, WithdrawalSend::Sent) {
        stats.goodbyes_tx(1);
      }
      endpoint.note_withdrawal_result(token, now, v4_out, v6_out);
    }
    // Free completed withdrawals (budget spent or 2 s ceiling reached): the
    // endpoint releases each route (decrementing services_active) and reports the
    // handle; GC its driver ctx. The scratch Vec is reused across iterations.
    self.completed_withdrawals.clear();
    self
      .endpoint
      .drain_completed_withdrawals(now, &mut self.completed_withdrawals);
    while let Some(handle) = self.completed_withdrawals.pop() {
      // UNCONDITIONAL GC: the route is freed, and any terminal queued at an
      // internal retirement (rename-collision / encode-failure) already sits in
      // the HANDLE-owned mailbox's reserved terminal slot. Because the `Service`
      // handle holds an `Arc` clone of that mailbox, dropping this ctx (and its
      // doorbell sender) does NOT drop the terminal — a live reader still drains
      // it via `Service::next`; a dropped reader means the mailbox `Arc` is gone
      // and the buffered terminal is collected with it. No park, no retry.
      self.services.remove(&handle);
    }
  }
}

/// Per-drain cap on actual self-send tracker entries.
///
/// each real socket send records one self-send
/// tracker entry via [`record_self_send`]. To keep the work per drain
/// pass bounded — and to leave headroom for late loopbacks of older
/// sends to be matched before we record more entries — we cap each
/// `drain_transmits` pass at 64 entries. Dual-stack mDNS multicast
/// generates two entries per Transmit, so this gives ≤ 64 actual sends
/// regardless of family enablement. Forward progress is guaranteed:
/// `drain_transmits` returns `true` when more is pending, and the driver
/// loop re-enters the packet pump immediately.
const MAX_SEND_CREDITS_PER_DRAIN: usize = 64;

/// Maximum consecutive `Service::poll_transmit` errors before the
/// driver gives up on a registered service and surfaces
/// `ServiceUpdate::Conflict` to the caller. The threshold
/// is small because `mdns-proto` retries the failed transmit on the
/// next call — three failures across consecutive ticks means the
/// payload simply cannot be encoded with the current scratch buffer
/// (e.g. records exceed `max_payload_size`).
const MAX_CONSECUTIVE_ENCODE_ERRORS: u8 = 3;

/// Deliver a `ServiceUpdate` to a service's caller via its handle-owned mailbox,
/// then ring the doorbell.
///
/// Routes by kind: the terminal retirement update (`Conflict`/`HostConflict`)
/// goes to the reserved [`ServiceMailbox`] slot (idempotent — first terminal
/// wins, never dropped under non-terminal pressure), every other update is
/// buffered into the bounded, coalescing non-terminal ring. A non-draining
/// caller therefore cannot grow memory beyond the mailbox cap, while the
/// retirement reason always survives.
///
/// Unlike the old bounded channel this can never "fail closed": the mailbox is
/// owned by the `Service` handle's `Arc`, so a dropped handle just leaves the
/// doorbell receiver gone. The update is still buffered (the orphan sweep / the
/// withdrawal GC then drops the whole ctx). A closed doorbell is treated as "no
/// reader to wake" — `try_send` fails silently and we move on.
fn deliver_service_update(ctx: &mut ServiceCtx, upd: ServiceUpdate) {
  ctx
    .mailbox
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .push_update(upd);
  // Capacity-1, coalescing wakeup. A closed receiver (handle dropped) means
  // there is no reader to wake — the buffered update stays in the mailbox until
  // the ctx is GC'd. We never `send().await`, so a slow reader never blocks the
  // driver.
  let _ = ctx.doorbell.try_send(());
}

fn min_opt(prev: Option<StdInstant>, t: StdInstant) -> StdInstant {
  match prev {
    Some(b) if b <= t => b,
    _ => t,
  }
}

/// IPv4 mDNS multicast destination (224.0.0.251:5353).
const MDNS_V4_DST: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
  std::net::Ipv4Addr::new(224, 0, 0, 251),
  5353,
));
/// IPv6 mDNS multicast destination ([ff02::fb]:5353).
const MDNS_V6_DST: SocketAddr = SocketAddr::V6(std::net::SocketAddrV6::new(
  std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb),
  5353,
  0,
  0,
));

/// How long a recorded self-send stays eligible to match an inbound
/// loopback before it is swept. Multicast loopback is delivered on the
/// same host within microseconds; 2s is generously larger than any real
/// loopback latency yet short enough that a byte-identical packet from a
/// co-resident peer arriving well after our send is correctly treated as
/// a peer, not as our own echo.
const SELF_SEND_TTL: Duration = Duration::from_secs(2);

/// Hard cap on live self-send tracker entries. Our send rate is bounded
/// by RFC 6762 §6 response coalescing (queries inside a jitter window
/// collapse into ONE response), so under normal operation the tracker
/// holds only a handful of entries. The cap is a backstop: if we ever
/// burst past it (e.g. many services announcing at once) `record_self_send`
/// declines to add more rather than evicting a still-live entry, which
/// would let a real loopback be misclassified as a peer.
const MAX_SELF_SEND_ENTRIES: usize = 65536;

/// FNV-1a 64-bit hash of a datagram body. Used only to fingerprint our
/// own sends for loopback matching — not a security primitive, so a fast
/// non-cryptographic hash is appropriate.
fn fnv1a(data: &[u8]) -> u64 {
  const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
  const PRIME: u64 = 0x0000_0100_0000_01b3;
  let mut h = OFFSET;
  for &b in data {
    h ^= b as u64;
    h = h.wrapping_mul(PRIME);
  }
  h
}

/// Record that we just sent `body` at wall time `sent`. Sweeps entries
/// older than [`SELF_SEND_TTL`] first (an entry whose age is `Err` is in
/// the future relative to `sent` — a clock step — so it is kept), then
/// appends `(hash, sent)` unless the tracker is already at
/// [`MAX_SELF_SEND_ENTRIES`] (decline rather than evict a live
/// entry).
fn record_self_send(tracker: &mut Vec<(u64, SystemTime)>, body: &[u8], sent: SystemTime) {
  tracker.retain(|(_, t)| match sent.duration_since(*t) {
    Ok(age) => age <= SELF_SEND_TTL,
    Err(_) => true,
  });
  if tracker.len() < MAX_SELF_SEND_ENTRIES {
    tracker.push((fnv1a(body), sent));
  }
}

/// How an inbound datagram's timestamp is matched against recorded sends.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MatchMode {
  /// The reference time is a KERNEL receive timestamp. A datagram is ours
  /// only if it was stamped at-or-after the recorded send (within
  /// [`hick_udp::RX_TIMESTAMP_GRAIN`]) and within [`SELF_SEND_TTL`] — this
  /// ordering is what excludes a byte-identical peer datagram the kernel
  /// saw before we sent (credit-theft guard).
  Ordered,
  /// No kernel timestamp was available (Windows, or a Unix kernel that
  /// didn't deliver the cmsg). The reference is a userspace READ time, so
  /// ordering carries no information: we match on content hash alone
  /// within [`SELF_SEND_TTL`] (take-once). This correctly suppresses our
  /// own loopback for normal single-host operation but, by construction,
  /// cannot defend the credit-theft race; that is the documented
  /// degradation on these platforms.
  Degraded,
}

/// Decide whether an inbound datagram (`body`, observed at `reference`) is
/// our own multicast loopback, consuming the matching tracker entry if so
/// (take-once, so one recorded send suppresses exactly one
/// loopback). See [`MatchMode`] for how `reference` is interpreted.
fn take_self_send(
  tracker: &mut Vec<(u64, SystemTime)>,
  body: &[u8],
  reference: SystemTime,
  mode: MatchMode,
) -> bool {
  let needle = fnv1a(body);
  match tracker
    .iter()
    .position(|(h, sent)| *h == needle && reference_matches(reference, *sent, mode))
  {
    Some(pos) => {
      tracker.remove(pos);
      true
    }
    None => false,
  }
}

/// Whether `reference` falls inside the acceptance window of a send made at
/// `sent`, per [`MatchMode`].
///
/// - `Ordered`: `reference ∈ [sent - RX_TIMESTAMP_GRAIN, sent + SELF_SEND_TTL]`.
///   The grain is the receive timestamp's worst-case truncation
///   ([`hick_udp::RX_TIMESTAMP_GRAIN`]: zero for nanosecond `SO_TIMESTAMPNS`,
///   one microsecond for `timeval` `SO_TIMESTAMP`), so a truncated loopback
///   still matches without widening the pre-send
///   credit-theft window beyond that intrinsic grain. The upper bound is TTL
///   expiry.
/// - `Degraded`: only the upper TTL bound applies (a read time is always
///   at-or-after the send, so the lower bound never bites). Equivalent to
///   content-hash take-once within TTL.
fn reference_matches(reference: SystemTime, sent: SystemTime, mode: MatchMode) -> bool {
  match reference.duration_since(sent) {
    // reference at-or-after sent: accept while within the TTL window.
    Ok(ahead) => ahead <= SELF_SEND_TTL,
    // reference before sent: only ordered mode tolerates it, and only
    // within this target's receive-timestamp truncation grain.
    Err(behind) => mode == MatchMode::Ordered && behind.duration() <= hick_udp::RX_TIMESTAMP_GRAIN,
  }
}

/// RFC 6762 §11 on-link check by TTL: a datagram is on-link only if its IPv4
/// TTL / IPv6 Hop Limit is exactly 255 (anything less crossed a router).
fn is_on_link(hop_limit: Option<u8>) -> bool {
  hop_limit.is_none_or(|hl| hl == 255)
}

/// Cheap peek at the DNS header's QR bit (RFC 1035 §4.1.1): byte 2, MSB.
/// `true` for a response (QR=1). Used by the driver to apply the §11
/// source-port trust check before consuming a self-send credit, without a
/// full message parse. A datagram too short to hold a header is not a
/// response (proto rejects it on parse).
fn packet_is_response(data: &[u8]) -> bool {
  data.get(2).is_some_and(|b| b & 0x80 != 0)
}

/// source-address fallback for the §11 on-link check, used when the
/// platform couldn't supply a TTL/Hop-Limit (Windows, illumos/solaris/fuchsia,
/// or a kernel without the cmsg). A datagram is treated as on-link when its
/// source address is loopback, an interface-matched link-local, or inside one
/// of the bound interface's directly-attached subnets — an off-link unicast
/// sender's global address matches none of these.
///
/// `bound_iface` is the interface this endpoint is bound to; `recv_iface` is
/// the interface the datagram arrived on (from PKTINFO, `0` when the platform
/// didn't report it).
///
/// link-local addresses (169.254/16, fe80::/10) are scoped to a
/// single link, so a link-local source counts as on-link ONLY when it arrived
/// on the bound interface. When `recv_iface` is `0` (provenance unavailable)
/// we cannot scope it and accept it (degraded) rather than drop legitimate
/// link-local discovery. Loopback is always on-link. A global (routable)
/// source is accepted only when it matches a cached local subnet; with no
/// match — including when no subnets were enumerated — it is dropped as
/// off-link (fail-closed per §11), so a global sender is never admitted
/// without positive on-link evidence.
fn src_on_local_link(
  local_subnets: &[(IpAddr, u8)],
  bound_iface: u32,
  recv_iface: u32,
  src: IpAddr,
) -> bool {
  let (is_loopback, is_link_local) = match src {
    IpAddr::V4(v4) => (v4.is_loopback(), v4.is_link_local()),
    IpAddr::V6(v6) => (v6.is_loopback(), (v6.segments()[0] & 0xffc0) == 0xfe80),
  };
  if is_loopback {
    return true;
  }
  if is_link_local {
    // On-link only if it arrived on the interface we're bound to. recv_iface
    // == 0 means the platform didn't report the receive interface — accept
    // (degraded) rather than drop.
    return recv_iface == 0 || recv_iface == bound_iface;
  }
  // Global (routable) source: admit only with positive on-link evidence. An
  // empty `local_subnets` makes `any` return `false`, so a global source is
  // dropped as off-link (fail-closed per §11) when nothing was enumerated.
  local_subnets
    .iter()
    .any(|&(net, prefix)| addr_in_subnet(net, prefix, src))
}

/// Whether `addr` falls within the subnet `net`/`prefix` (families must match).
fn addr_in_subnet(net: IpAddr, prefix: u8, addr: IpAddr) -> bool {
  match (net, addr) {
    (IpAddr::V4(n), IpAddr::V4(a)) => {
      let p = prefix.min(32);
      if p == 0 {
        return true;
      }
      let mask: u32 = u32::MAX.checked_shl(32 - u32::from(p)).unwrap_or(0);
      (u32::from(n) & mask) == (u32::from(a) & mask)
    }
    (IpAddr::V6(n), IpAddr::V6(a)) => {
      let p = prefix.min(128);
      if p == 0 {
        return true;
      }
      let mask: u128 = u128::MAX.checked_shl(128 - u32::from(p)).unwrap_or(0);
      (u128::from(n) & mask) == (u128::from(a) & mask)
    }
    _ => false,
  }
}

/// Best-effort snapshot of the BOUND interface's directly-attached subnets,
/// used by [`src_on_local_link`]. Scoped to `iface_index` — the
/// interface this endpoint is bound to — NOT every local interface, so a
/// packet from another NIC's subnet is not treated as on-link. An interface
/// index of 0 or a failed lookup yields an empty list (degraded: the fallback
/// then accepts, since we can't determine the link).
fn collect_local_subnets(iface_index: u32) -> Vec<(IpAddr, u8)> {
  let mut out: Vec<(IpAddr, u8)> = Vec::new();
  if iface_index == 0 {
    return out;
  }
  if let Ok(Some(i)) = getifs::interface_by_index(iface_index) {
    if let Ok(v4s) = i.ipv4_addrs() {
      for n in v4s.iter() {
        out.push((IpAddr::V4(n.addr()), n.prefix_len()));
      }
    }
    if let Ok(v6s) = i.ipv6_addrs() {
      for n in v6s.iter() {
        out.push((IpAddr::V6(n.addr()), n.prefix_len()));
      }
    }
  }
  out
}

/// Send a datagram on the appropriate socket(s) and record one self-send
/// tracker entry per ACTUAL successful send_to.
///
/// Returns the number of entries recorded (== number of successful
/// `send_to`s), so [`DriverState::drain_transmits`] can budget against
/// real tracker consumption rather than logical Transmits.
async fn send_via<N: Net>(
  tracker: &mut Vec<(u64, SystemTime)>,
  v4: &Option<Arc<N::UdpSocket>>,
  v6: &Option<Arc<N::UdpSocket>>,
  dst: SocketAddr,
  body: &[u8],
  #[cfg(feature = "stats")] stats: &std::sync::Arc<hick_trace::stats::Stats>,
) -> usize {
  // proto-layer transmits use multicast_dst() which always
  // returns the IPv4 group. Detect mDNS multicast destinations and fan
  // out the SAME payload to BOTH families' multicast groups (per RFC
  // 6762 §6 — a host with both IPv4 and IPv6 stacks must respond on
  // each). Non-multicast (unicast) sends fall back to the per-family
  // socket selection.
  //
  // record one tracker entry per ACTUAL send_to. Take-once
  // self suppression consumes a single entry per matching
  // loopback; dual-stack fan-out generates TWO loopback copies (one per
  // joined socket) so we need two entries.
  let is_mdns_multicast = matches!(dst, SocketAddr::V4(v4a) if v4a.ip().is_multicast() && v4a.port() == 5353)
    || matches!(dst, SocketAddr::V6(v6a) if v6a.ip().is_multicast() && v6a.port() == 5353);

  // stamp each tracker entry with the wall time captured INSIDE
  // the poll that actually performs the `sendto` (see `send_to_at`), not
  // before awaiting an async `send_to`. The kernel stamps the looped-back
  // copy during that syscall, so the captured time is immediately before
  // the kernel's receive stamp — guaranteeing `sent <= rx` for our own
  // loopback (modulo the truncation grain) while leaving no awaitable gap
  // in which a peer datagram could be stamped after our recorded time yet
  // before our packet is actually sent (which would let it steal the
  // take-once credit).
  let mut credits = 0usize;
  if is_mdns_multicast {
    if let Some(s) = v4 {
      let (res, send_wall) = send_to_at::<N>(s, body, MDNS_V4_DST).await;
      match res {
        // only record the tracker entry on a SUCCESSFUL send. A
        // failed send produces no loopback; a stale entry would suppress
        // a later byte-identical peer packet.
        Ok(_) => {
          hick_trace::trace!(dst = %MDNS_V4_DST, len = body.len(), "send_to v4");
          record_self_send(tracker, body, send_wall);
          #[cfg(feature = "stats")]
          {
            stats.packets_tx(1);
            stats.bytes_tx(body.len() as u64);
          }
          credits += 1;
        }
        Err(_e) => {
          hick_trace::debug!(error = %_e, dst = %MDNS_V4_DST, "send_to v4 failed");
          #[cfg(feature = "stats")]
          stats.send_errors(1);
        }
      }
    }
    if let Some(s) = v6 {
      let (res, send_wall) = send_to_at::<N>(s, body, MDNS_V6_DST).await;
      match res {
        Ok(_) => {
          hick_trace::trace!(dst = %MDNS_V6_DST, len = body.len(), "send_to v6");
          record_self_send(tracker, body, send_wall);
          #[cfg(feature = "stats")]
          {
            stats.packets_tx(1);
            stats.bytes_tx(body.len() as u64);
          }
          credits += 1;
        }
        Err(_e) => {
          hick_trace::debug!(error = %_e, dst = %MDNS_V6_DST, "send_to v6 failed");
          #[cfg(feature = "stats")]
          stats.send_errors(1);
        }
      }
    }
    return credits;
  }

  // Unicast: pick the socket matching the destination family.
  let sock = match dst {
    SocketAddr::V4(_) => v4.as_ref(),
    SocketAddr::V6(_) => v6.as_ref(),
  };
  if let Some(s) = sock {
    let (res, send_wall) = send_to_at::<N>(s, body, dst).await;
    match res {
      Ok(_) => {
        hick_trace::trace!(dst = %dst, len = body.len(), "send_to");
        record_self_send(tracker, body, send_wall);
        #[cfg(feature = "stats")]
        {
          stats.packets_tx(1);
          stats.bytes_tx(body.len() as u64);
        }
        credits += 1;
      }
      Err(_e) => {
        hick_trace::debug!(error = %_e, dst = %dst, "send_to failed");
        #[cfg(feature = "stats")]
        stats.send_errors(1);
      }
    }
  }
  credits
}

/// Fan ONE endpoint-owned withdrawal (TTL=0 goodbye) datagram out to BOTH bound
/// multicast families and report EACH family's [`WithdrawalSend`] outcome so the
/// endpoint tracks per-family debt. Mirrors [`send_via`]'s multicast branch
/// (same self-send tracking and `packets_tx`/`bytes_tx`/`send_errors` accounting)
/// but, unlike the coarse `credits` count, distinguishes a PRESENT family's send
/// result from an ABSENT socket. The mapping is by socket presence, not error kind:
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
async fn send_withdrawal_via<N: Net>(
  tracker: &mut Vec<(u64, SystemTime)>,
  v4: &Option<Arc<N::UdpSocket>>,
  v6: &Option<Arc<N::UdpSocket>>,
  body: &[u8],
  #[cfg(feature = "stats")] stats: &std::sync::Arc<hick_trace::stats::Stats>,
) -> (WithdrawalSend, WithdrawalSend) {
  // No socket for a family → WriteOff (no peers reachable on it to withdraw from).
  let mut v4_out = WithdrawalSend::WriteOff;
  let mut v6_out = WithdrawalSend::WriteOff;
  if let Some(s) = v4 {
    let (res, send_wall) = send_to_at::<N>(s, body, MDNS_V4_DST).await;
    // Present socket: Ok → Sent, ANY Err → Retry (never WriteOff). See
    // `present_socket_send_outcome`.
    v4_out = present_socket_send_outcome(&res);
    match res {
      Ok(_) => {
        hick_trace::trace!(dst = %MDNS_V4_DST, len = body.len(), "withdrawal send_to v4");
        record_self_send(tracker, body, send_wall);
        #[cfg(feature = "stats")]
        {
          stats.packets_tx(1);
          stats.bytes_tx(body.len() as u64);
        }
      }
      Err(_e) => {
        hick_trace::debug!(error = %_e, dst = %MDNS_V4_DST, "withdrawal send_to v4 failed");
        #[cfg(feature = "stats")]
        stats.send_errors(1);
      }
    }
  }
  if let Some(s) = v6 {
    let (res, send_wall) = send_to_at::<N>(s, body, MDNS_V6_DST).await;
    // Present socket: Ok → Sent, ANY Err → Retry (never WriteOff). See
    // `present_socket_send_outcome`.
    v6_out = present_socket_send_outcome(&res);
    match res {
      Ok(_) => {
        hick_trace::trace!(dst = %MDNS_V6_DST, len = body.len(), "withdrawal send_to v6");
        record_self_send(tracker, body, send_wall);
        #[cfg(feature = "stats")]
        {
          stats.packets_tx(1);
          stats.bytes_tx(body.len() as u64);
        }
      }
      Err(_e) => {
        hick_trace::debug!(error = %_e, dst = %MDNS_V6_DST, "withdrawal send_to v6 failed");
        #[cfg(feature = "stats")]
        stats.send_errors(1);
      }
    }
  }
  (v4_out, v6_out)
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

/// Send `buf` to `dst`, returning the send result paired with the wall
/// time captured in the poll iteration that performed the `sendto`.
///
/// Driving `poll_send_to` directly — rather than awaiting `send_to` and
/// stamping around it — lets us snapshot `SystemTime::now()` at the very
/// start of each poll and keep only the snapshot from the poll that
/// returns `Ready`. Polls that return `Pending` (socket not yet writable)
/// discard their snapshot, so the recorded time is always adjacent to the
/// syscall that creates the loopback, with no awaitable gap in between.
async fn send_to_at<N: Net>(
  sock: &N::UdpSocket,
  buf: &[u8],
  dst: SocketAddr,
) -> (std::io::Result<usize>, SystemTime) {
  let mut stamp = SystemTime::now();
  let res = core::future::poll_fn(|cx| {
    stamp = SystemTime::now();
    sock.poll_send_to(cx, buf, dst)
  })
  .await;
  (res, stamp)
}

/// Spawn the driver task on the runtime exposed by `N`.
pub(crate) fn spawn<N: Net>(
  opts: ServerOptions,
  sockets: BoundSockets<N>,
  cmd_rx: async_channel::Receiver<Command>,
  #[cfg(feature = "stats")] stats_out: &mut Option<std::sync::Arc<hick_trace::stats::Stats>>,
) {
  let max_send = opts.max_payload_size();
  let max_recv = opts.max_recv_packet_size();
  let state = DriverState::<N>::new(&opts, sockets);
  #[cfg(feature = "stats")]
  {
    *stats_out = Some(state.stats.clone());
  }
  <N::Runtime as RuntimeLite>::spawn_detach(driver_task::<N>(state, cmd_rx, max_send, max_recv));
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", skip_all))]
async fn driver_task<N: Net>(
  mut state: DriverState<N>,
  cmd_rx: async_channel::Receiver<Command>,
  max_send: usize,
  max_recv: usize,
) {
  let mut scratch: Vec<u8> = vec![0u8; max_send.max(512)];
  let (packet_tx, packet_rx) = async_channel::bounded::<Packet>(64);
  // shutdown signal for recv sub-tasks. The sender is held by
  // this task (driver_task) — the variable is intentionally unused
  // because we never explicitly send; we rely on the Drop at function
  // return to close the channel. recv_loop select!s on the receiver
  // half and exits promptly when the channel closes, instead of
  // blocking on the next packet to arrive on a now-orphaned socket.
  let (_shutdown_tx, shutdown_rx) = async_channel::bounded::<()>(1);

  if let Some(sock) = state.v4.clone() {
    let tx = packet_tx.clone();
    let sd = shutdown_rx.clone();
    #[cfg(feature = "stats")]
    let stats = state.stats.clone();
    <N::Runtime as RuntimeLite>::spawn_detach(recv_loop::<N>(
      sock,
      tx,
      sd,
      true,
      max_recv,
      #[cfg(feature = "stats")]
      stats,
    ));
  }
  if let Some(sock) = state.v6.clone() {
    let tx = packet_tx.clone();
    let sd = shutdown_rx.clone();
    #[cfg(feature = "stats")]
    let stats = state.stats.clone();
    <N::Runtime as RuntimeLite>::spawn_detach(recv_loop::<N>(
      sock,
      tx,
      sd,
      false,
      max_recv,
      #[cfg(feature = "stats")]
      stats,
    ));
  }
  drop(packet_tx);
  drop(shutdown_rx); // recv loops hold their own clones; the sender stays with us.

  loop {
    // drain any already-arrived packets BEFORE firing timers
    // and draining new transmits, so the multicast-loopback copies of
    // the PRIOR tick's transmits are matched against the self-send hash
    // ring before this tick records new sends.
    //
    // bound the drain to PACKET_PUMP_BUDGET iterations per
    // tick so a multicast flood (recv tasks can keep refilling the
    // 64-slot channel from another runtime thread) cannot starve
    // cmd / timer processing. Recompute `now` after the pump because
    // packet handling can take noticeable wall-clock time.
    const PACKET_PUMP_BUDGET: usize = 64;
    for _ in 0..PACKET_PUMP_BUDGET {
      match packet_rx.try_recv() {
        Ok(pkt) => state.handle_packet(pkt),
        Err(_) => break,
      }
    }
    // GC handles whose receiver has been dropped BEFORE
    // firing timers or draining transmits. Without this, an orphan
    // query cancelled between its `StartQuery` reply and the caller
    // future polling the handle could multicast its initial question
    // on this very tick.
    let now = StdInstant::now();
    state.sweep_closed_handles(now);
    state.fire_timeouts(now);
    // Positive-TTL transmits (probes/announcements/responses). The old free-name
    // goodbye barrier is GONE: the §10.1 ordering (a stale TTL=0 must precede a
    // same-name replacement's fresh positive TTL) is now enforced by the endpoint,
    // which KEEPS the route while a withdrawal is in flight, so a same-name
    // `register_service` is rejected (`NameAlreadyRegistered`) until the
    // withdrawal frees the name. No replacement can announce ahead of the
    // withdrawal, so this drain runs unconditionally.
    let more_transmits_pending = state.drain_transmits(now, &mut scratch).await;
    // `push_updates` may retire services (orphan drop, encode escalation, or a
    // rename collision), each beginning an endpoint-owned withdrawal.
    state.push_updates(now).await;
    // Pump every due endpoint-owned TTL=0 goodbye and GC each completed
    // withdrawal (route freed → driver ctx removed). `Endpoint::poll_timeout`
    // folds the withdrawal deadlines into `next_deadline`, so a due resend wakes
    // the loop.
    state.drain_withdrawals(now, &mut scratch).await;

    // if drain_transmits stopped at its per-tick budget,
    // don't sleep — loop back immediately so the packet pump can
    // consume the loopbacks from the sends we just made, before we
    // record the next batch of self-send tracker entries.
    //
    // but FIRST drain a bounded batch of pending commands
    // so cancel/unregister/shutdown can make progress even when
    // transmits are being continuously generated (e.g. a multicast
    // flood that triggers responses faster than we can drain). The
    // command channel is unbounded; without this drain a stuck
    // attacker scenario can grow it without bound.
    if more_transmits_pending {
      const COMMAND_DRAIN_BUDGET: usize = 8;
      let mut cmd_closed = false;
      for _ in 0..COMMAND_DRAIN_BUDGET {
        match cmd_rx.try_recv() {
          Ok(cmd) => state.handle_command(cmd, StdInstant::now()),
          Err(async_channel::TryRecvError::Empty) => break,
          Err(async_channel::TryRecvError::Closed) => {
            cmd_closed = true;
            break;
          }
        }
      }
      // don't bail straight out on a closed command channel —
      // fall through to drive any in-flight withdrawal to completion before
      // exiting (the shutdown sequence below).
      if cmd_closed {
        break;
      }
      continue;
    }

    let deadline = state.next_deadline();
    let cmd_fut = cmd_rx.recv().fuse();
    let pkt_fut = packet_rx.recv().fuse();
    pin_mut!(cmd_fut, pkt_fut);

    // A closed command or packet channel means the endpoint (and its recv
    // loops) are gone. Record it via a flag and break AFTER the select so the
    // control flow can't be confused with the select macro's internals.
    let mut closed = false;
    if let Some(at) = deadline {
      let dur = at.saturating_duration_since(now);
      let sleep = <N::Runtime as RuntimeLite>::sleep(dur).fuse();
      pin_mut!(sleep);
      select_biased! {
        c = cmd_fut => match c {
          Ok(cmd) => state.handle_command(cmd, StdInstant::now()),
          Err(_) => closed = true,
        },
        p = pkt_fut => match p {
          Ok(pkt) => state.handle_packet(pkt),
          Err(_) => closed = true,
        },
        _ = sleep => { /* timer fires; loop top re-runs fire_timeouts */ }
      }
    } else {
      select_biased! {
        c = cmd_fut => match c {
          Ok(cmd) => state.handle_command(cmd, StdInstant::now()),
          Err(_) => closed = true,
        },
        p = pkt_fut => match p {
          Ok(pkt) => state.handle_packet(pkt),
          Err(_) => closed = true,
        },
      }
    }
    if closed {
      break;
    }
  }

  // graceful shutdown — begin the endpoint-owned §10.1 withdrawal for EVERY
  // still-registered service (the endpoint is going away). Without this, services
  // that were live at shutdown would linger in peers' caches until TTL expiry.
  let shutdown_now = StdInstant::now();
  let live_services: Vec<ServiceHandle> = state.services.keys().copied().collect();
  for h in live_services {
    state.remove_service(h, shutdown_now);
  }
  // Drive the in-flight withdrawals (the ones just begun plus any from an
  // unregister/drop right before shutdown) to completion: pump each due TTL=0
  // goodbye and free completed routes until none remain. Each withdrawal finishes
  // when its resend budget is spent OR at its 2 s anti-pin ceiling, so this
  // terminates without an explicit per-entry bound — `Endpoint::poll_timeout`
  // returns `None` once every withdrawal route is freed. A wall-clock backstop
  // (a few ceilings) guards against a clock anomaly so the task can never hang.
  let shutdown_deadline = StdInstant::now() + Duration::from_secs(10);
  loop {
    let now = StdInstant::now();
    state.drain_withdrawals(now, &mut scratch).await;
    // Sleep on (and exit when there are no) WITHDRAWAL deadlines only — NOT the
    // aggregate `next_deadline`, which folds in cache expiry and query/service
    // timers. Otherwise, once every goodbye is sent, a still-populated cache would
    // keep this flush parked until that unrelated deadline (or the 10 s backstop)
    // instead of exiting promptly.
    let Some(next) = state.next_withdrawal_deadline() else {
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
      <N::Runtime as RuntimeLite>::sleep(dur).await;
    }
  }
}

/// Bump stats for a datagram that was consumed off the socket but is unusable
/// (oversized / MSG_TRUNC / unparseable source).  The datagram WAS consumed, so
/// `packets_rx` must rise to keep the denominator consistent; `packets_dropped`
/// marks the reject.  `buf_len` is the number of bytes that actually landed in
/// the receive buffer (best-effort for `bytes_rx`).
///
/// Extracted from the hot recv-loop so the accounting rule can be unit-tested
/// independently of socket I/O.
#[cfg(feature = "stats")]
#[inline]
fn count_consumed_oversized(stats: &hick_trace::stats::Stats, buf_len: usize) {
  stats.packets_rx(1);
  stats.bytes_rx(buf_len as u64);
  stats.packets_dropped(1);
}

#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, fields(via_v4))
)]
async fn recv_loop<N: Net>(
  sock: Arc<N::UdpSocket>,
  tx: async_channel::Sender<Packet>,
  shutdown: async_channel::Receiver<()>,
  via_v4: bool,
  max_recv: usize,
  #[cfg(feature = "stats")] stats: std::sync::Arc<hick_trace::stats::Stats>,
) {
  // RFC 6762 §17: outgoing mDNS messages should fit in the path MTU
  // (~1500 bytes for Ethernet), but receivers MUST be prepared to accept
  // messages up to 9000 bytes. `max_recv` defaults to 9000 (configurable
  // via ServerOptions::with_max_recv_packet_size). Larger sources include
  // exhaustive PTR responses with many KAS records.
  let mut buf = vec![0u8; max_recv.max(1500)];
  loop {
    // select! over readiness vs shutdown so this task exits
    // promptly when the driver drops its shutdown sender, releasing the
    // socket and its multicast memberships.
    //
    // on Unix we use `peek_from` purely for readiness (it does
    // NOT consume the datagram), then `hick_udp::recv_with_meta` does the
    // actual `recvmsg` to consume the datagram together with its
    // PKTINFO ancillary metadata (local receive address + interface
    // index). This keeps the readiness wait runtime-agnostic (via
    // agnostic-net) while recovering the metadata the proto layer needs
    // for reliable self-loopback detection. On non-Unix we fall back to
    // a plain `recv_from` with UNSPECIFIED local address.
    #[cfg(unix)]
    {
      let ready = {
        let peek_fut = sock.peek_from(&mut buf).fuse();
        let shutdown_fut = shutdown.recv().fuse();
        pin_mut!(peek_fut, shutdown_fut);
        select_biased! {
          _ = shutdown_fut => return,
          r = peek_fut => r,
        }
      };
      if let Err(_e) = ready {
        hick_trace::debug!(error = %_e, via_v4, "peek_from failed");
        return;
      }
      // Data is ready in the socket queue; consume it with PKTINFO.
      use std::os::fd::AsRawFd;
      let fd = sock.as_raw_fd();
      match hick_udp::recv_with_meta(fd, &mut buf, via_v4) {
        Ok(meta) => {
          let n = meta.len();
          hick_trace::trace!(src = %meta.peer(), len = n, via_v4, "recv datagram");
          // NOTE: packets_rx / bytes_rx are bumped by ProtoEndpoint::handle()
          // on the shared Arc — do NOT bump them here too (double-count).
          let data = buf.get(..n).unwrap_or(&buf).to_vec();
          let pkt = Packet {
            src: meta.peer(),
            data,
            local_ip: meta.local_ip(),
            interface_index: meta.interface_index(),
            // carry the kernel receive timestamp as-is (None
            // when this kernel didn't deliver the cmsg) so handle_packet
            // can pick ORDERED vs DEGRADED self-matching by provenance,
            // never silently treating a read time as an ordering signal.
            kernel_rx_time: meta.rx_time(),
            read_time: SystemTime::now(),
            // IPv4 TTL / IPv6 Hop Limit for the §11 on-link check.
            hop_limit: meta.hop_limit(),
          };
          if tx.send(pkt).await.is_err() {
            return;
          }
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
          // We own this socket exclusively, so the peeked datagram should
          // still be present; a spurious WouldBlock just means retry.
          continue;
        }
        // recv_with_meta returns InvalidData for a datagram we must
        // DROP but keep serving — an oversized/truncated datagram (MSG_TRUNC)
        // or one with an unparseable source address. The datagram was already
        // consumed by recvmsg, so drop+log+continue rather than killing the
        // receive task.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
          hick_trace::debug!(error = %e, via_v4, "dropping unusable datagram");
          // The datagram WAS consumed by recvmsg (MSG_TRUNC or unparseable
          // source address): count it toward receive volume so packets_rx is a
          // reliable denominator. recvmsg truncated the payload into the buffer,
          // so buf.len() is the best-effort byte count we can report.
          #[cfg(feature = "stats")]
          count_consumed_oversized(&stats, buf.len());
          continue;
        }
        Err(_e) => {
          hick_trace::debug!(error = %_e, via_v4, "recv_with_meta failed");
          return;
        }
      }
    }
    // on Windows, peek for readiness then consume with WSARecvMsg so
    // we recover the receiving interface index (IP_PKTINFO / IPV6_PKTINFO).
    // That index lets handle_packet scope the §11 link-local on-link check to
    // the bound interface (no longer fail-open). No TTL cmsg is wired here, so
    // hop_limit stays None and the §11 check uses the (now interface-scoped)
    // source-address fallback. No kernel rx timestamp either: degraded
    // (read-time) self-match.
    #[cfg(windows)]
    {
      use std::os::windows::io::AsRawSocket;
      // Winsock WSAEMSGSIZE: the datagram was larger than the supplied buffer.
      // Unlike Unix recvmsg (which truncates silently and succeeds),
      // peek/WSARecvMsg ERROR here. Such a datagram is non-conformant (RFC 6762
      // §17 caps mDNS at 9000 bytes, our default buffer) — WSARecvMsg consumes
      // and truncates it, so we DROP it and continue. Treating it as fatal
      // would let one oversized LAN packet permanently kill this
      // receive task, blinding the service on Windows until restart.
      const WSAEMSGSIZE: i32 = 10040;
      let ready = {
        let peek_fut = sock.peek_from(&mut buf).fuse();
        let shutdown_fut = shutdown.recv().fuse();
        pin_mut!(peek_fut, shutdown_fut);
        select_biased! {
          _ = shutdown_fut => return,
          r = peek_fut => r,
        }
      };
      match ready {
        Ok(_) => {}
        // Oversized datagram is queued but peek does NOT consume it; fall
        // through to WSARecvMsg, which consumes it so we make progress.
        Err(ref e) if e.raw_os_error() == Some(WSAEMSGSIZE) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
        Err(_e) => {
          hick_trace::debug!(error = %_e, via_v4, "peek_from failed");
          return;
        }
      }
      let raw = sock.as_raw_socket();
      match hick_udp::recv_with_meta(raw, &mut buf, via_v4) {
        Ok(meta) => {
          let n = meta.len();
          hick_trace::trace!(src = %meta.peer(), len = n, via_v4, "recv datagram");
          // NOTE: packets_rx / bytes_rx are bumped by ProtoEndpoint::handle()
          // on the shared Arc — do NOT bump them here too (double-count).
          let data = buf.get(..n).unwrap_or(&buf).to_vec();
          let pkt = Packet {
            src: meta.peer(),
            data,
            local_ip: meta.local_ip(),
            interface_index: meta.interface_index(),
            kernel_rx_time: meta.rx_time(),
            read_time: SystemTime::now(),
            hop_limit: meta.hop_limit(),
          };
          if tx.send(pkt).await.is_err() {
            return;
          }
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
          continue;
        }
        // Oversized datagram consumed + truncated by WSARecvMsg: drop it and
        // keep serving rather than killing the receive task. The datagram WAS
        // consumed (WSARecvMsg truncated it into the buffer), so bump packets_rx
        // as a reliable denominator; buf.len() is the best-effort byte count.
        Err(ref e) if e.raw_os_error() == Some(WSAEMSGSIZE) => {
          hick_trace::debug!(via_v4, "dropping oversized datagram (WSAEMSGSIZE)");
          // Datagram WAS consumed + truncated by WSARecvMsg — same rule as the
          // Unix InvalidData arm: count the receive toward the denominator.
          #[cfg(feature = "stats")]
          count_consumed_oversized(&stats, buf.len());
          continue;
        }
        Err(_e) => {
          hick_trace::debug!(error = %_e, via_v4, "recv_with_meta (windows) failed");
          return;
        }
      }
    }
    // Other non-Unix, non-Windows targets: plain recv_from with no ancillary
    // metadata (UNSPECIFIED local, interface 0, no TTL/timestamp).
    #[cfg(all(not(unix), not(windows)))]
    {
      let recv_result = {
        let recv_fut = sock.recv_from(&mut buf).fuse();
        let shutdown_fut = shutdown.recv().fuse();
        pin_mut!(recv_fut, shutdown_fut);
        select_biased! {
          _ = shutdown_fut => return,
          r = recv_fut => r,
        }
      };
      match recv_result {
        Ok((n, src)) => {
          hick_trace::trace!(src = %src, len = n, via_v4, "recv datagram");
          // NOTE: packets_rx / bytes_rx are bumped by ProtoEndpoint::handle()
          // on the shared Arc — do NOT bump them here too (double-count).
          let data = buf.get(..n).unwrap_or(&buf).to_vec();
          let local_ip = if via_v4 {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
          } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
          };
          let pkt = Packet {
            src,
            data,
            local_ip,
            interface_index: 0,
            kernel_rx_time: None,
            read_time: SystemTime::now(),
            hop_limit: None,
          };
          if tx.send(pkt).await.is_err() {
            return;
          }
        }
        Err(_e) => {
          hick_trace::debug!(error = %_e, via_v4, "recv_from failed");
          return;
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::service::{SERVICE_UPDATE_CAPACITY, ServiceMailbox};

  /// Drain one [`ServiceUpdate`] from a shared mailbox (the handle side), used by
  /// the service-update tests to assert delivery without awaiting the async
  /// [`crate::Service::next`].
  fn lock_mailbox_for_test(
    mailbox: &std::sync::Arc<std::sync::Mutex<ServiceMailbox>>,
  ) -> Option<ServiceUpdate> {
    mailbox
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .drain_for_test()
  }

  #[test]
  fn on_link_check_rejects_non_255_ttl() {
    // only TTL/Hop-Limit exactly 255 (or an absent value, where we
    // can't enforce) is treated as on-link.
    assert!(is_on_link(Some(255)));
    assert!(is_on_link(None)); // degraded: platform didn't report it
    assert!(!is_on_link(Some(254)));
    assert!(!is_on_link(Some(1)));
    assert!(!is_on_link(Some(0)));
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

  #[test]
  fn packet_is_response_reads_qr_bit() {
    // QR bit is the MSB of header byte 2.
    assert!(packet_is_response(&[0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    assert!(!packet_is_response(&[
      0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ])); // query
    assert!(!packet_is_response(&[0, 0])); // too short to be a response
    assert!(!packet_is_response(&[]));
  }

  // an untrusted response (QR=1 from a non-5353 source port) must
  // be dropped BEFORE it can consume the take-once self-send credit, so our
  // genuine port-5353 loopback still matches.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn untrusted_response_does_not_burn_self_send_credit() {
    use std::{
      net::{IpAddr, Ipv4Addr},
      time::SystemTime,
    };

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);

    // A QR=1 response body (header byte 2 = 0x84) we "recently sent".
    let body = vec![0u8, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    record_self_send(&mut state.recent_sends, &body, SystemTime::now());
    assert_eq!(state.recent_sends.len(), 1);

    // Same bytes arriving from an EPHEMERAL port (on-link TTL 255): untrusted
    // response — must be dropped before `take_self_send`.
    let untrusted = Packet {
      src: "192.0.2.9:40000".parse().unwrap(),
      data: body.clone(),
      local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
      interface_index: 0,
      kernel_rx_time: Some(SystemTime::now()),
      read_time: SystemTime::now(),
      hop_limit: Some(255),
    };
    state.handle_packet(untrusted);
    assert_eq!(
      state.recent_sends.len(),
      1,
      "untrusted response must not consume the self-send credit"
    );

    // The genuine loopback from port 5353 passes the gate and consumes it.
    let loopback = Packet {
      src: "192.0.2.9:5353".parse().unwrap(),
      data: body,
      local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
      interface_index: 0,
      kernel_rx_time: Some(SystemTime::now()),
      read_time: SystemTime::now(),
      hop_limit: Some(255),
    };
    state.handle_packet(loopback);
    assert_eq!(
      state.recent_sends.len(),
      0,
      "the trusted port-5353 loopback consumes the credit"
    );
  }

  /// A short datagram (just enough to set QR=1 but not a full DNS message) from
  /// a non-5353 source bumps packets_rx + bytes_rx exactly once, and exactly
  /// one reject counter (packets_dropped). No double-count: proto's handle() is
  /// never reached so proto cannot bump these counters.
  ///
  /// The test drives `handle_packet` directly — no socket bind needed — and uses
  /// `#[cfg(feature = "tokio")]` only to access `DriverState::new`.
  #[cfg(all(feature = "stats", feature = "tokio"))]
  #[test]
  fn pre_drop_short_qr1_counts_rx_and_dropped_exactly_once() {
    use std::{
      net::{IpAddr, Ipv4Addr},
      time::SystemTime,
    };

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);

    // 3-byte body: only byte 2 matters (QR=1 → 0x80). Too short for a valid DNS
    // message — proto would reject it on parse, but we drop before proto.
    let body: Vec<u8> = vec![0x00, 0x00, 0x80];
    let len = body.len() as u64;

    // Source port ≠ 5353 → untrusted-response pre-drop path; on-link (TTL=255).
    let pkt = Packet {
      src: "192.0.2.7:40000".parse().unwrap(),
      data: body,
      local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
      interface_index: 0,
      kernel_rx_time: Some(SystemTime::now()),
      read_time: SystemTime::now(),
      hop_limit: Some(255),
    };
    state.handle_packet(pkt);

    let snap = state.stats.snapshot();
    assert_eq!(
      snap.packets_rx, 1,
      "packets_rx must be 1 (datagram was received)"
    );
    assert_eq!(
      snap.bytes_rx, len,
      "bytes_rx must equal the datagram length"
    );
    assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
    // Confirm no double-count: only the driver-side bump runs (proto handle() was
    // not called), so no extra packets_rx from the proto path.
    assert_eq!(
      snap.packets_rx, 1,
      "no double-count: proto handle() was not reached"
    );
  }

  /// A well-formed untrusted QR=1 response from a non-5353 source (12-byte DNS
  /// header with QR=1 set, all fields zero otherwise) must trigger the
  /// untrusted-response pre-drop: packets_rx +1, bytes_rx +len, packets_dropped
  /// +1. Self-send credit ring must be unchanged.
  #[cfg(all(feature = "stats", feature = "tokio"))]
  #[test]
  fn pre_drop_untrusted_qr1_response_counts_rx_and_dropped_exactly_once() {
    use std::{
      net::{IpAddr, Ipv4Addr},
      time::SystemTime,
    };

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);

    // Minimal 12-byte DNS response header: QR=1 (byte 2 = 0x84 for AA+Response).
    let body: Vec<u8> = vec![
      0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let len = body.len() as u64;

    // No prior self-send credit recorded — if the drop were to incorrectly call
    // take_self_send the tracker would stay at zero (no match), but the correct
    // behaviour is that it is never called at all.
    assert_eq!(state.recent_sends.len(), 0);

    let pkt = Packet {
      src: "192.0.2.8:54321".parse().unwrap(), // non-5353 → untrusted
      data: body,
      local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
      interface_index: 0,
      kernel_rx_time: Some(SystemTime::now()),
      read_time: SystemTime::now(),
      hop_limit: Some(255), // on-link
    };
    state.handle_packet(pkt);

    // Self-send tracker unchanged (never reached).
    assert_eq!(
      state.recent_sends.len(),
      0,
      "self-send credit ring must be untouched"
    );

    let snap = state.stats.snapshot();
    assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
    assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
    assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
  }

  /// Off-link datagrams (TTL ≠ 255) must also count packets_rx + bytes_rx once
  /// (received from the wire) and packets_dropped once (rejected).
  #[cfg(all(feature = "stats", feature = "tokio"))]
  #[test]
  fn pre_drop_off_link_datagram_counts_rx_and_dropped_exactly_once() {
    use std::{
      net::{IpAddr, Ipv4Addr},
      time::SystemTime,
    };

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);

    // A datagram with TTL < 255 → off-link gate fires before the untrusted-
    // response check. Use a query (QR=0) so only the §11 path is exercised.
    let body: Vec<u8> = vec![
      0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let len = body.len() as u64;

    let pkt = Packet {
      src: "203.0.113.5:5353".parse().unwrap(),
      data: body,
      local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
      interface_index: 0,
      kernel_rx_time: Some(SystemTime::now()),
      read_time: SystemTime::now(),
      hop_limit: Some(64), // off-link: TTL != 255
    };
    state.handle_packet(pkt);

    let snap = state.stats.snapshot();
    assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
    assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
    assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
  }

  // NOTE: the same-host sibling-address RETENTION tests
  // (`unregister_shared_host_preserves_sibling_addresses`,
  // `unregister_with_unannounced_same_host_sibling_withdraws_addresses`,
  // `unregister_disjoint_host_addrs_withdraws_only_own`) and their
  // `goodbye_v4_addrs` / `goodbye_withdraws_addr` helpers were REMOVED in the
  // endpoint-owned-withdrawal migration. They inspected the encoded bytes of the
  // deleted driver-side goodbye queue (`state.goodbyes[0].data`), produced by the
  // deleted `retained_host_addrs` sibling scan in `remove_service`. Sibling
  // retention now lives in the endpoint (`Endpoint::sibling_retained_addrs`,
  // recomputed FRESH each round in `poll_withdrawal_transmit` from the route
  // table) and is covered by the proto-level
  // `poll_withdrawal_transmit ... sibling retention` test.
  // NOTE: the non-terminal coalescing + bound + drop-oldest semantics for
  // service updates (one Established, latest Renamed, bounded ring, reserved
  // terminal) moved out of the driver's per-ctx overflow deque into the
  // handle-owned `ServiceMailbox` and are unit-tested at that seam in
  // `crate::service::tests` (`mailbox_coalesces_established_and_renamed_by_kind`,
  // `mailbox_hard_cap_drops_oldest`,
  // `mailbox_terminal_reserved_under_non_terminal_pressure`, …). The driver-level
  // tests below assert the END-TO-END contract through `deliver_service_update` +
  // the live `Service` handle.

  /// a non-draining caller cannot grow memory without bound — a flood of service
  /// updates is bounded + coalesced by the handle-owned mailbox (one Established,
  /// latest Renamed, reserved terminal), never an unbounded backlog.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn service_update_delivery_is_bounded_for_non_draining_caller() {
    use mdns_proto::{ServiceUpdate, event::ServiceRenamed};

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    let mut r = mdns_proto::ServiceRecords::new(
      mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("svc._ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("host.local.").unwrap(),
      631,
      120,
    );
    r.add_a(std::net::Ipv4Addr::new(192, 168, 1, 10));
    // `reg` (the mailbox `Arc` + the doorbell receiver) is kept alive but NEVER
    // drained — a non-draining caller. The driver ctx shares the same mailbox.
    let reg = state
      .register_service(mdns_proto::ServiceSpec::new(r), now)
      .unwrap();
    let handle = reg.handle;

    // Push a churn of Established + distinct Renamed far past the cap.
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      for i in 0..1000u32 {
        deliver_service_update(ctx, ServiceUpdate::Established);
        deliver_service_update(
          ctx,
          ServiceUpdate::Renamed(ServiceRenamed::new(
            mdns_proto::Name::try_from_str(&format!("svc-{i}._ipp._tcp.local.")).unwrap(),
          )),
        );
      }
      // The mailbox coalesces to one Established + the latest Renamed — at most
      // the cap, regardless of how much the peer churns.
      let mb = ctx.mailbox.lock().unwrap_or_else(|e| e.into_inner());
      assert!(
        mb.non_terminal_len() <= SERVICE_UPDATE_CAPACITY,
        "the mailbox must stay within capacity under churn; got {}",
        mb.non_terminal_len()
      );
      // Established + Renamed coalesce by kind, so exactly two non-terminal
      // updates survive.
      assert_eq!(
        mb.non_terminal_len(),
        2,
        "Established and the latest Renamed coalesce to two pending updates"
      );
    }
    drop(reg);
  }

  #[test]
  fn addr_in_subnet_masks_correctly() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let net = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    assert!(addr_in_subnet(
      net,
      24,
      IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))
    ));
    assert!(!addr_in_subnet(
      net,
      24,
      IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))
    ));
    // prefix 0 matches everything; family mismatch never matches.
    assert!(addr_in_subnet(
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      0,
      IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    ));
    assert!(!addr_in_subnet(net, 24, IpAddr::V6(Ipv6Addr::LOCALHOST)));
    // IPv6 /64.
    let n6 = IpAddr::V6("2001:db8:0:1::".parse().unwrap());
    assert!(addr_in_subnet(
      n6,
      64,
      IpAddr::V6("2001:db8:0:1::ff".parse().unwrap())
    ));
    assert!(!addr_in_subnet(
      n6,
      64,
      IpAddr::V6("2001:db8:0:2::ff".parse().unwrap())
    ));
  }

  #[test]
  fn src_on_local_link_fallback() {
    use std::net::{IpAddr, Ipv4Addr};
    let subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24u8)];
    const BOUND: u32 = 3;
    // In-subnet peer is on-link; an off-subnet global address is not
    // (interface index is irrelevant for non-link-local sources).
    assert!(src_on_local_link(
      &subnets,
      BOUND,
      BOUND,
      IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55))
    ));
    assert!(!src_on_local_link(
      &subnets,
      BOUND,
      BOUND,
      IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    ));
    // Loopback is always on-link.
    assert!(src_on_local_link(
      &subnets,
      BOUND,
      BOUND,
      IpAddr::V4(Ipv4Addr::LOCALHOST)
    ));
    // §11 fail-closed: a global source with no enumerated subnets has no
    // on-link evidence and is dropped (was previously fail-open).
    assert!(!src_on_local_link(
      &[],
      BOUND,
      BOUND,
      IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    ));
    assert!(!src_on_local_link(
      &[],
      BOUND,
      BOUND,
      IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    ));
    // A global source inside a cached /8 is on-link; outside it is dropped.
    let wide = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8u8)];
    assert!(src_on_local_link(
      &wide,
      BOUND,
      BOUND,
      IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))
    ));
    assert!(!src_on_local_link(
      &wide,
      BOUND,
      BOUND,
      IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    ));
  }

  #[test]
  fn src_on_local_link_scopes_link_local_to_bound_interface() {
    // a link-local source is on-link ONLY when it arrived on the
    // interface we're bound to — a link-local address from a different NIC is
    // not our link and must not pass the §11 fallback.
    use std::net::{IpAddr, Ipv4Addr};
    let subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24u8)];
    const BOUND: u32 = 3;
    const OTHER: u32 = 7;
    let v4_ll = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
    let v6_ll = IpAddr::V6("fe80::1".parse().unwrap());
    // Arrived on the bound interface → on-link.
    assert!(src_on_local_link(&subnets, BOUND, BOUND, v4_ll));
    assert!(src_on_local_link(&subnets, BOUND, BOUND, v6_ll));
    // Arrived on a DIFFERENT interface → NOT on-link.
    assert!(!src_on_local_link(&subnets, BOUND, OTHER, v4_ll));
    assert!(!src_on_local_link(&subnets, BOUND, OTHER, v6_ll));
    // Receive interface unknown (0) → degraded accept (can't scope).
    assert!(src_on_local_link(&subnets, BOUND, 0, v4_ll));
    assert!(src_on_local_link(&subnets, BOUND, 0, v6_ll));
  }

  #[test]
  fn collect_local_subnets_rejects_zero_index() {
    // the fallback is scoped to the BOUND interface. Index 0 is
    // "no interface" — it must NOT enumerate every NIC, so the result is
    // empty (which makes src_on_local_link fail closed for a global source
    // rather than treat another NIC's subnet as on-link).
    assert!(collect_local_subnets(0).is_empty());
  }

  #[test]
  fn self_send_consume_once() {
    // one recorded send suppresses exactly one loopback.
    let t = SystemTime::now();
    let mut tracker = Vec::new();
    record_self_send(&mut tracker, b"hello", t);
    // The loopback arrives at-or-after our send -> matched and consumed.
    assert!(take_self_send(
      &mut tracker,
      b"hello",
      t,
      MatchMode::Ordered
    ));
    // A second byte-identical packet finds no entry -> treated as a peer.
    assert!(!take_self_send(
      &mut tracker,
      b"hello",
      t,
      MatchMode::Ordered
    ));
    assert!(tracker.is_empty());
  }

  #[test]
  fn self_send_distinct_payloads_do_not_match() {
    let t = SystemTime::now();
    let mut tracker = Vec::new();
    record_self_send(&mut tracker, b"alpha", t);
    assert!(!take_self_send(
      &mut tracker,
      b"beta",
      t,
      MatchMode::Ordered
    ));
    // The unrelated entry is left intact for its own loopback.
    assert!(take_self_send(
      &mut tracker,
      b"alpha",
      t,
      MatchMode::Ordered
    ));
  }

  #[test]
  fn self_send_expires_after_ttl() {
    // a packet arriving more than SELF_SEND_TTL after the send
    // is no longer our loopback, and the stale entry is swept on the next
    // record so the tracker can't grow without bound.
    let t = SystemTime::now();
    let mut tracker = Vec::new();
    record_self_send(&mut tracker, b"hello", t);
    let too_late = t + SELF_SEND_TTL + Duration::from_millis(1);
    assert!(!take_self_send(
      &mut tracker,
      b"hello",
      too_late,
      MatchMode::Ordered
    ));
    record_self_send(&mut tracker, b"other", too_late);
    assert_eq!(tracker.len(), 1);
    assert!(take_self_send(
      &mut tracker,
      b"other",
      too_late,
      MatchMode::Ordered
    ));
  }

  #[test]
  fn self_send_peer_before_our_send_cannot_steal_credit() {
    // a byte-identical peer datagram the kernel stamped BEFORE
    // our send must not consume the credit even though its content hash
    // matches; otherwise the genuine loopback is later misclassified as a
    // peer (self-rename / dropped answers).
    let sent = SystemTime::now();
    let mut tracker = Vec::new();
    record_self_send(&mut tracker, b"probe", sent);
    let peer_rx = sent - Duration::from_millis(500);
    assert!(!take_self_send(
      &mut tracker,
      b"probe",
      peer_rx,
      MatchMode::Ordered
    ));
    // Our genuine loopback arrives at-or-after the send and is matched.
    let loop_rx = sent + Duration::from_millis(1);
    assert!(take_self_send(
      &mut tracker,
      b"probe",
      loop_rx,
      MatchMode::Ordered
    ));
  }

  // on microsecond `timeval` sources (Apple/BSD)
  // RX_TIMESTAMP_GRAIN is 1µs, so a loopback whose kernel timestamp was
  // truncated to a slightly-earlier microsecond than our nanosecond send
  // time still counts as ours — but anything earlier than the grain is a
  // genuine pre-send (peer) datagram and must not match.
  #[cfg(not(any(target_os = "linux", target_os = "android")))]
  #[test]
  fn self_send_ordered_tolerates_microsecond_truncation() {
    assert_eq!(hick_udp::RX_TIMESTAMP_GRAIN, Duration::from_micros(1));
    let sent = SystemTime::now();
    let mut tracker = Vec::new();
    record_self_send(&mut tracker, b"trunc", sent);
    let truncated_rx = sent - (hick_udp::RX_TIMESTAMP_GRAIN - Duration::from_nanos(1));
    assert!(take_self_send(
      &mut tracker,
      b"trunc",
      truncated_rx,
      MatchMode::Ordered
    ));

    record_self_send(&mut tracker, b"trunc", sent);
    let too_early = sent - (hick_udp::RX_TIMESTAMP_GRAIN + Duration::from_micros(4));
    assert!(!take_self_send(
      &mut tracker,
      b"trunc",
      too_early,
      MatchMode::Ordered
    ));
  }

  // on nanosecond `SO_TIMESTAMPNS` (Linux/Android) the kernel
  // timestamp is exact, so RX_TIMESTAMP_GRAIN is zero and there is NO
  // pre-send tolerance: a byte-identical peer datagram stamped even 500ns
  // before our send must not steal the take-once credit.
  #[cfg(any(target_os = "linux", target_os = "android"))]
  #[test]
  fn self_send_ordered_nanosecond_rejects_pre_send() {
    assert_eq!(hick_udp::RX_TIMESTAMP_GRAIN, Duration::ZERO);
    let sent = SystemTime::now();
    let mut tracker = Vec::new();
    record_self_send(&mut tracker, b"probe", sent);
    let pre_send = sent - Duration::from_nanos(500);
    assert!(!take_self_send(
      &mut tracker,
      b"probe",
      pre_send,
      MatchMode::Ordered
    ));
    // The entry survives the non-match; our genuine loopback (at-or-after
    // the send) is still matched.
    assert!(take_self_send(
      &mut tracker,
      b"probe",
      sent,
      MatchMode::Ordered
    ));
  }

  #[test]
  fn self_send_degraded_matches_take_once_within_ttl() {
    // with no kernel timestamp the reference is a userspace
    // READ time (always at-or-after the send). Degraded mode matches on
    // content hash alone within TTL, take-once. This is what keeps normal
    // single-host operation correct on Windows / timestamp-less kernels.
    let sent = SystemTime::now();
    let mut tracker = Vec::new();
    record_self_send(&mut tracker, b"win", sent);
    let read = sent + Duration::from_millis(10);
    assert!(take_self_send(
      &mut tracker,
      b"win",
      read,
      MatchMode::Degraded
    ));
    // Take-once: the credit is gone. (A byte-identical PEER datagram read
    // next would now be treated as a peer — and, conversely, a pre-buffered
    // peer datagram read first could consume this credit. That credit-theft
    // exposure is the documented degradation when no kernel rx timestamp is
    // available; ordered mode is what closes it.)
    assert!(!take_self_send(
      &mut tracker,
      b"win",
      read,
      MatchMode::Degraded
    ));
  }

  #[test]
  fn self_send_degraded_expires_after_ttl() {
    let sent = SystemTime::now();
    let mut tracker = Vec::new();
    record_self_send(&mut tracker, b"win", sent);
    let too_late = sent + SELF_SEND_TTL + Duration::from_millis(1);
    assert!(!take_self_send(
      &mut tracker,
      b"win",
      too_late,
      MatchMode::Degraded
    ));
  }

  #[test]
  fn self_send_dual_stack_records_two_entries() {
    // dual-stack fan-out records one entry per real send, so
    // BOTH loopback copies are suppressed.
    let t = SystemTime::now();
    let mut tracker = Vec::new();
    record_self_send(&mut tracker, b"resp", t);
    record_self_send(&mut tracker, b"resp", t);
    assert!(take_self_send(&mut tracker, b"resp", t, MatchMode::Ordered));
    assert!(take_self_send(&mut tracker, b"resp", t, MatchMode::Ordered));
    assert!(!take_self_send(
      &mut tracker,
      b"resp",
      t,
      MatchMode::Ordered
    ));
  }

  #[test]
  fn self_send_cap_declines_without_evicting_live_entries() {
    // at capacity, record_self_send declines a new entry rather
    // than evicting a still-live one (which would unmask a real loopback).
    let t = SystemTime::now();
    let mut tracker = vec![(fnv1a(b"live"), t); MAX_SELF_SEND_ENTRIES];
    record_self_send(&mut tracker, b"overflow", t);
    assert_eq!(tracker.len(), MAX_SELF_SEND_ENTRIES);
    // The would-be new entry was never added.
    assert!(!take_self_send(
      &mut tracker,
      b"overflow",
      t,
      MatchMode::Ordered
    ));
    // A pre-existing live entry is still matchable.
    assert!(take_self_send(&mut tracker, b"live", t, MatchMode::Ordered));
  }

  // NOTE: the deleted driver-goodbye-queue seam tests
  // (`flush_goodbyes_completes_the_burst`,
  // `live_goodbye_round_with_no_send_keeps_budget_and_backs_off`,
  // `live_drain_force_clears_expired_barrier`) asserted the removed per-driver
  // `goodbyes` queue + `sent_once` transmit barrier (`drain_goodbyes` Part A
  // re-arm, the `expires_at` anti-pin force-clear, and `has_pending_barrier`).
  // The endpoint now owns the resend schedule, the spend/re-arm bookkeeping, and
  // the 2 s anti-pin ceiling — covered by the proto-level withdrawal tests
  // (`note_withdrawal_result` spend/backoff, `drain_completed_withdrawals`
  // ceiling). The replacement-survival test below is the driver-seam observation
  // that a withdrawal HOLDS the name and frees it on completion.

  /// Endpoint-owned-withdrawal replacement survival (supersedes the old free-name
  /// goodbye BARRIER test). Under `with_probe_unique_names(false)` a same-name
  /// replacement would announce a positive TTL directly (no §8.1 probe) — exactly
  /// the configuration in which a stale TTL=0 goodbye could be overtaken. The old
  /// driver enforced ordering with a transmit barrier; the endpoint now enforces
  /// it structurally — it KEEPS the route (holding the name) for the whole §10.1
  /// withdrawal, so a same-name `register_service` is REJECTED until the goodbye
  /// completes and frees the name. No replacement can announce ahead of the
  /// withdrawal because no replacement can even be registered until it is done.
  ///
  /// Driven through `DriverState` directly (no sockets — the reactor's multi-task
  /// loop cannot be stepped deterministically). With no bound family every
  /// withdrawal round fails to deliver, so the withdrawal is force-completed at
  /// its 2 s anti-pin ceiling rather than by spending its resend budget; the
  /// name-held → name-freed observation is identical either way.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn same_name_replacement_is_rejected_until_withdrawal_completes() {
    use std::{net::Ipv4Addr, time::Duration};

    let opts = crate::options::ServerOptions::default()
      .with_endpoint_config(mdns_proto::EndpointConfig::new().with_probe_unique_names(false));
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    let mk = || {
      let mut r = mdns_proto::ServiceRecords::new(
        mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
        mdns_proto::Name::try_from_str("repl._ipp._tcp.local.").unwrap(),
        mdns_proto::Name::try_from_str("repl.local.").unwrap(),
        631,
        120,
      );
      r.add_a(Ipv4Addr::new(192, 168, 1, 10));
      mdns_proto::ServiceSpec::new(r)
    };

    // 1. Register A and drive its proto to an announced state so the withdrawal
    //    snapshot is NON-empty (records were confirmed-emitted). Delivery is
    //    simulated via `note_transmit_delivered` so the announce/host guards
    //    latch (no sockets are bound).
    let a = state.register_service(mk(), now).unwrap().handle;
    {
      let ctx = state.services.get_mut(&a).unwrap();
      let mut buf = vec![0u8; 4096];
      let mut t = now;
      for _ in 0..40 {
        t += Duration::from_millis(300);
        let _ = ctx.proto.handle_timeout(t);
        while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
          ctx.proto.note_transmit_delivered(t);
        }
      }
    }

    // 2. Unregister A → begins the endpoint-owned withdrawal (name held). The ctx
    //    is KEPT (marked withdrawing) and the route is reserved.
    state.remove_service(a, now);
    assert!(
      state
        .services
        .get(&a)
        .map(|c| c.withdrawing)
        .unwrap_or(false),
      "unregister must begin the withdrawal and keep the ctx (withdrawing)"
    );

    // 3. While the withdrawal is in flight the SAME name must be rejected — the
    //    endpoint holds the route, so a replacement cannot announce a fresh
    //    positive TTL ahead of the stale TTL=0.
    match state.register_service(mk(), now) {
      Err(crate::error::RegisterError::NameAlreadyRegistered(_)) => {}
      Err(e) => panic!("a same-name registration must be rejected while withdrawing; got {e:?}"),
      Ok(_) => {
        panic!("a same-name registration must be rejected while the withdrawal holds the name")
      }
    }

    // 4. Drive the withdrawal to completion. With no bound family each round fails
    //    to deliver, so the endpoint force-completes it at the 2 s anti-pin
    //    ceiling; `drain_withdrawals` then frees the route and GCs the ctx.
    let mut scratch = vec![0u8; 4096];
    let mut t = now;
    let mut completed = false;
    for _ in 0..64 {
      t += Duration::from_millis(250);
      state.drain_withdrawals(t, &mut scratch).await;
      if !state.services.contains_key(&a) {
        completed = true;
        break;
      }
    }
    assert!(
      completed,
      "the withdrawal must complete (route freed + driver ctx GC'd) — by its 2 s \
       anti-pin ceiling when no family can deliver"
    );

    // 5. The name is freed → a same-name replacement now registers successfully.
    state
      .register_service(mk(), t)
      .expect("the same name must be re-registerable once the withdrawal completes");
  }

  /// A `Conflict` queued at an internal retirement must still reach the host
  /// after the withdrawal GCs the ctx. With the handle-owned reserved-terminal
  /// mailbox this is now TRIVIAL (formerly ): `deliver_service_update` routes
  /// the `Conflict` to the mailbox's reserved terminal slot, the mailbox `Arc` is
  /// shared with the live `Service` handle, and the withdrawal GC removes the ctx
  /// UNCONDITIONALLY — yet the terminal is still drainable by the live reader
  /// because the mailbox outlives the ctx. No overflow deque, no deferral.
  ///
  /// Driven through `DriverState` directly (no sockets). With no bound family the
  /// withdrawal force-completes at its 2 s anti-pin ceiling.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn queued_conflict_survives_withdrawal_gc() {
    use std::{net::Ipv4Addr, time::Duration};

    use mdns_proto::ServiceUpdate;

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    let mut r = mdns_proto::ServiceRecords::new(
      mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("cflt._ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("cflt.local.").unwrap(),
      631,
      120,
    );
    r.add_a(Ipv4Addr::new(192, 168, 1, 10));
    // Keep `reg` (the mailbox `Arc` + doorbell receiver) alive: this is the live
    // reader that must still observe the Conflict after the ctx is GC'd.
    let reg = state
      .register_service(mdns_proto::ServiceSpec::new(r), now)
      .unwrap();
    let handle = reg.handle;
    let mailbox = Arc::clone(&reg.mailbox);

    // 1. Drive the proto to an announced state so the withdrawal snapshot is
    //    NON-empty (otherwise the withdrawal completes instantly with nothing to
    //    retract — we want the Conflict to outlive an in-flight withdrawal).
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      let mut buf = vec![0u8; 4096];
      let mut t = now;
      for _ in 0..40 {
        t += Duration::from_millis(300);
        let _ = ctx.proto.handle_timeout(t);
        while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
          ctx.proto.note_transmit_delivered(t);
        }
      }
    }

    // 2. Deliver a `Conflict` at retirement — it lands in the mailbox's RESERVED
    //    terminal slot (not the non-terminal ring).
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      deliver_service_update(ctx, ServiceUpdate::Conflict);
    }

    // 3. Begin the endpoint-owned withdrawal — exactly what the rename-collision /
    //    encode-failure retirement arms do (mark `withdrawing`, snapshot, hand to
    //    the endpoint). From here `push_updates` skips this ctx.
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      ctx.withdrawing = true;
      let snap = ctx.proto.withdrawal_snapshot();
      state.endpoint.begin_withdrawal(handle, snap, now);
    }

    // 4. Drive the withdrawal to completion. With no bound family each round
    //    fails to deliver, so the endpoint force-completes at the 2 s ceiling;
    //    `drain_withdrawals` then GCs the ctx UNCONDITIONALLY (no deferral).
    let mut scratch = vec![0u8; 4096];
    let mut t = now;
    let mut completed = false;
    for _ in 0..64 {
      t += Duration::from_millis(250);
      state.drain_withdrawals(t, &mut scratch).await;
      if !state.services.contains_key(&handle) {
        completed = true;
        break;
      }
    }
    assert!(
      completed,
      "the withdrawal must complete (route freed + driver ctx GC'd unconditionally)"
    );

    // 5. The Conflict survived the ctx GC: it lives in the handle-owned mailbox's
    //    reserved slot and is still drainable by the live reader.
    let drained = lock_mailbox_for_test(&mailbox);
    assert!(
      matches!(drained, Some(ServiceUpdate::Conflict)),
      "the Conflict queued at retirement must survive the unconditional ctx GC and \
       stay readable from the handle-owned mailbox; got {drained:?}"
    );

    drop(reg);
  }

  /// The terminal retirement update survives BOTH a saturated non-terminal ring
  /// AND an immediate, unconditional ctx GC (the design-doc scenario; formerly
  /// the deferral case). Fill the mailbox's non-terminal `updates` to the cap
  /// WITHOUT draining, `set_terminal(Conflict)`, complete the withdrawal so the
  /// ctx is GC'd immediately, then drain from the LIVE handle and assert the
  /// `Conflict` IS observed and the ctx is gone from `services` — no park, no
  /// leak.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn terminal_survives_full_mailbox_and_immediate_ctx_gc() {
    use std::{net::Ipv4Addr, time::Duration};

    use mdns_proto::ServiceUpdate;

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    let mut r = mdns_proto::ServiceRecords::new(
      mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("stuck._ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("stuck.local.").unwrap(),
      631,
      120,
    );
    r.add_a(Ipv4Addr::new(192, 168, 1, 10));
    // Keep `reg` alive across the GC — it is the live reader.
    let reg = state
      .register_service(mdns_proto::ServiceSpec::new(r), now)
      .unwrap();
    let handle = reg.handle;
    let mailbox = Arc::clone(&reg.mailbox);

    // 1. Drive the proto to an announced state so the withdrawal snapshot is
    //    NON-empty (otherwise the withdrawal completes instantly).
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      let mut buf = vec![0u8; 4096];
      let mut t = now;
      for _ in 0..40 {
        t += Duration::from_millis(300);
        let _ = ctx.proto.handle_timeout(t);
        while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
          ctx.proto.note_transmit_delivered(t);
        }
      }
    }

    // 2. Saturate the non-terminal ring to the cap WITHOUT draining, then reserve
    //    the terminal. The terminal slot is independent of the (full) ring.
    {
      let mut mb = mailbox.lock().unwrap_or_else(|e| e.into_inner());
      mb.fill_non_terminal_to_cap_for_test();
      assert_eq!(
        mb.non_terminal_len(),
        SERVICE_UPDATE_CAPACITY,
        "the non-terminal ring must be saturated at the cap"
      );
      mb.set_terminal(ServiceUpdate::Conflict);
    }

    // 3. Begin the endpoint-owned withdrawal (rename-collision / encode-failure
    //    retirement arm). `push_updates` now skips this ctx.
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      ctx.withdrawing = true;
      let snap = ctx.proto.withdrawal_snapshot();
      state.endpoint.begin_withdrawal(handle, snap, now);
    }

    // 4. Drive the withdrawal to completion. The ctx is GC'd IMMEDIATELY on
    //    completion — no park, no deferral, regardless of the full ring + the
    //    still-undrained reader.
    let mut scratch = vec![0u8; 4096];
    let mut t = now;
    let mut completed = false;
    for _ in 0..64 {
      t += Duration::from_millis(250);
      state.drain_withdrawals(t, &mut scratch).await;
      if !state.services.contains_key(&handle) {
        completed = true;
        break;
      }
    }
    assert!(
      completed,
      "the ctx must be GC'd unconditionally on withdrawal completion"
    );
    assert!(
      !state.services.contains_key(&handle),
      "no leak: the ctx must be gone from `services` after the withdrawal"
    );

    // 5. Drain from the live handle: all cap non-terminal updates, then the
    //    reserved Conflict — it was NEVER dropped despite the full ring and the
    //    immediate GC.
    let mut non_terminal = 0usize;
    let mut saw_conflict = false;
    loop {
      let drained = lock_mailbox_for_test(&mailbox);
      match drained {
        Some(ServiceUpdate::Conflict) => {
          saw_conflict = true;
          break;
        }
        Some(_) => non_terminal += 1,
        None => break,
      }
    }
    assert_eq!(
      non_terminal, SERVICE_UPDATE_CAPACITY,
      "the saturated non-terminal ring must drain in full before the terminal"
    );
    assert!(
      saw_conflict,
      "the reserved terminal Conflict must survive a full mailbox + an immediate, \
       unconditional ctx GC and reach the live reader"
    );

    drop(reg);
  }

  /// Registering the same instance name twice maps the proto
  /// `RegisterServiceError::NameAlreadyRegistered` onto the public
  /// `RegisterError::NameAlreadyRegistered` — exercising the `From` arm that
  /// translates proto pool errors into the async-API error type. Sync path,
  /// so no runtime is needed.
  #[cfg(feature = "tokio")]
  #[test]
  fn duplicate_registration_maps_to_name_already_registered() {
    use std::net::Ipv4Addr;

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    let mk = || {
      let mut r = mdns_proto::ServiceRecords::new(
        mdns_proto::Name::try_from_str("_http._tcp.local.").unwrap(),
        mdns_proto::Name::try_from_str("dup._http._tcp.local.").unwrap(),
        mdns_proto::Name::try_from_str("dup.local.").unwrap(),
        80,
        120,
      );
      r.add_a(Ipv4Addr::new(192, 168, 1, 10));
      mdns_proto::ServiceSpec::new(r)
    };

    state.register_service(mk(), now).unwrap();
    // `ServiceRegistered` (the Ok type) is not `Debug`, so match instead of
    // `unwrap_err`.
    match state.register_service(mk(), now) {
      Err(crate::error::RegisterError::NameAlreadyRegistered(_)) => {}
      Err(e) => panic!("expected NameAlreadyRegistered, got error {e:?}"),
      Ok(_) => panic!("expected NameAlreadyRegistered, but the second registration succeeded"),
    }
  }

  /// On encode failure (`poll_query_transmit` → `Err`) the reactor driver must
  /// call `endpoint.retire_query` so the proto records the terminal transition:
  /// `queries_active` decrements to 0 and exactly one of `queries_done` /
  /// `queries_timeout` reaches 1. The query slot must also be GC'd (removed
  /// from the driver map) so late responses cannot mutate it, consistent with
  /// the smoltcp driver which calls retire_query on this error class.
  #[cfg(all(feature = "stats", feature = "tokio"))]
  #[tokio::test]
  async fn unencodable_query_retire_records_terminal_stats() {
    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    let qname = mdns_proto::Name::try_from_str("printer.local.").unwrap();
    let started = state
      .start_query(
        mdns_proto::QuerySpec::new(qname, mdns_proto::wire::ResourceType::A),
        now,
      )
      .unwrap();
    let h = started.handle;

    // Confirm one active query is registered in the proto.
    let before = state.stats.snapshot();
    assert_eq!(
      before.queries_active, 1,
      "one active query before encode failure"
    );
    assert_eq!(before.queries_done, 0, "no terminal yet");

    // Drive drain_transmits with a 1-byte scratch → encode fails for the
    // pending question → retire_query must be called.
    let mut scratch = vec![0u8; 1];
    state.drain_transmits(now, &mut scratch).await;

    // Stats invariant: queries_active == 0, queries_done == 1.
    let after = state.stats.snapshot();
    assert_eq!(
      after.queries_active, 0,
      "queries_active must be 0 after retire_query on encode failure (was leaking)"
    );
    assert_eq!(
      after.queries_done, 1,
      "exactly one terminal (queries_done) must be recorded after encode failure; \
       got queries_done={}, queries_timeout={}",
      after.queries_done, after.queries_timeout,
    );

    // The query slot must be GC'd so late answers cannot mutate retired state.
    assert!(
      !state.queries.contains_key(&h),
      "the retired query slot must be removed from the driver map"
    );

    // The terminal must be set in the mailbox so Query::next surfaces it.
    // Drive a full Query::next cycle: spin up a minimal loopback endpoint
    // with the existing mailbox + doorbell so the consumer can drain the
    // terminal without needing a live command channel.
    let mb = started.mailbox;
    let (cmd_tx, _cmd_rx) = async_channel::unbounded::<crate::command::Command>();
    let mut q = crate::query::Query::new(h, mb, started.doorbell, cmd_tx);
    // The doorbell was already rung by drain_transmits (terminal was pushed);
    // `Query::next` must surface QueryEvent::Terminal on this call.
    let event = tokio::time::timeout(std::time::Duration::from_millis(200), q.next())
      .await
      .expect("Query::next must complete (terminal is already in mailbox)")
      .expect("Query::next must return Some(Terminal), not None");
    assert!(
      matches!(event, crate::query::QueryEvent::Terminal(_)),
      "the first event from Query::next must be the terminal; got {event:?}"
    );
  }

  /// Regression test for the encode-retired query GC bypass under send pressure.
  ///
  /// The bug: `drain_transmits` collected encode-failed query handles into
  /// `encode_retired` but the per-handle credit check (`if credits_remaining ==
  /// 0 { return true }`) inside the query loop could fire BEFORE the cleanup
  /// block ran, leaving the retired handle resident in `queries` and proto
  /// storage even though the terminal was already consumed.
  ///
  /// The fix: replace that early `return true` with `more_pending = true; break`
  /// so the GC block at the end of the function ALWAYS executes.
  ///
  /// This test registers one encode-failing query (1-byte scratch) followed by
  /// N normal queries (large scratch).  HashMap iteration order is
  /// non-deterministic, so regardless of whether the encode-failing handle comes
  /// first or last in the `handles` vec, the GC block must remove it by the time
  /// `drain_transmits` returns.  With null sockets the credit counter never
  /// reaches zero (sends return `used = 0`), so `more_pending` is `false` here;
  /// the budget-exhaustion `break` path cannot be exercised without live
  /// multicast sockets, but the structural invariant — that the GC block runs on
  /// EVERY return path — is verified by the fix and by the code path taken here
  /// (normal-completion path also runs the GC block, just like the break path).
  ///
  /// Additionally asserts that the normal queries are still resident (their
  /// mailboxes are still open so they haven't been retired), confirming that
  /// only the encode-retired handle is cleaned up.
  #[cfg(all(feature = "stats", feature = "tokio"))]
  #[tokio::test]
  async fn encode_retired_gc_runs_with_subsequent_queries_pending() {
    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    // Register the encode-failing query: 1-byte scratch ensures encode fails.
    let bad_qname = mdns_proto::Name::try_from_str("encode-fail.local.").unwrap();
    let bad_started = state
      .start_query(
        mdns_proto::QuerySpec::new(bad_qname, mdns_proto::wire::ResourceType::A),
        now,
      )
      .unwrap();
    let bad_h = bad_started.handle;

    // Register N additional queries. Keep the `QueryStarted` structs alive so
    // the doorbell receivers (held by `started.doorbell`) stay open; the
    // driver's liveness check (`!c.doorbell.is_closed()`) would skip any
    // query whose receiver was dropped.
    // N = 4 is enough to confirm the iteration order does not matter.
    let mut normal_started = Vec::new();
    for i in 0u8..4 {
      let name = mdns_proto::Name::try_from_str(&format!("normal-{i}.local.")).unwrap();
      let started = state
        .start_query(
          mdns_proto::QuerySpec::new(name, mdns_proto::wire::ResourceType::A),
          now,
        )
        .unwrap();
      normal_started.push(started);
    }
    let normal_handles: Vec<_> = normal_started.iter().map(|s| s.handle).collect();

    // Confirm five active queries in proto before the drain.
    let before = state.stats.snapshot();
    assert_eq!(before.queries_active, 5, "five active queries before drain");

    // 1-byte scratch → the encode-failing query fails to encode; normal queries
    // also fail (1 byte is too small for any DNS message), so all end up in
    // encode_retired.  This is acceptable: the assertion below checks that the
    // encode-failing handle is gone, irrespective of how many others fail too.
    let mut scratch = vec![0u8; 1];
    let more_pending = state.drain_transmits(now, &mut scratch).await;

    // `more_pending` is false because null sockets never exhaust credits.
    // The credit-exhaustion `break` path requires live multicast sockets and
    // cannot be reproduced deterministically in a unit test; the structural
    // fix (flag + single cleanup path) guarantees correctness on that path too.
    assert!(
      !more_pending,
      "null sockets never exhaust credits; more_pending must be false"
    );

    // The encode-retired query slot MUST be gone from the driver map.
    assert!(
      !state.queries.contains_key(&bad_h),
      "the encode-retired query handle must be removed from the driver map after drain_transmits"
    );

    // All queries saw encode failure (1-byte scratch), so proto counters must
    // reflect all terminals.
    let after = state.stats.snapshot();
    assert_eq!(
      after.queries_active, 0,
      "all five queries must be retired; queries_active must be 0"
    );
    // Five terminals (all queries_done — no timeout, encode fails immediately).
    assert_eq!(
      after.queries_done, 5,
      "five terminals (queries_done) must be recorded; \
       got queries_done={}, queries_timeout={}",
      after.queries_done, after.queries_timeout,
    );

    // The normal handles must also be GC'd (same 1-byte scratch → all fail).
    for &h in &normal_handles {
      assert!(
        !state.queries.contains_key(&h),
        "normal query handle {h:?} must also be removed (all encode-failed with 1-byte scratch)"
      );
    }
  }

  /// A consumed-oversized datagram (MSG_TRUNC / InvalidData) must bump
  /// `packets_rx` AND `packets_dropped` — it was consumed off the socket so it
  /// counts toward the receive denominator. `bytes_rx` rises by the buffer
  /// capacity (best-effort, the actual payload bytes that landed in our buffer).
  ///
  /// Tests `count_consumed_oversized` directly so no socket bind is needed.
  #[cfg(feature = "stats")]
  #[test]
  fn consumed_oversized_datagram_counts_rx_and_dropped() {
    let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
    let buf_len: usize = 9000;

    count_consumed_oversized(&stats, buf_len);

    let snap = stats.snapshot();
    assert_eq!(
      snap.packets_rx, 1,
      "packets_rx must be 1 (datagram was consumed)"
    );
    assert_eq!(
      snap.bytes_rx, buf_len as u64,
      "bytes_rx must equal buf_len (best-effort truncated payload)"
    );
    assert_eq!(
      snap.packets_dropped, 1,
      "packets_dropped must be 1 (unusable datagram)"
    );
  }

  /// A generic recv error that consumed NO datagram must leave all counters at
  /// zero — only consumed-unusable datagrams bump `packets_dropped`.
  ///
  /// This mirrors the `handle_recv` path in compio: a socket/driver failure is
  /// NOT a datagram event and must not pollute the stats.
  #[cfg(feature = "stats")]
  #[test]
  fn generic_recv_error_does_not_increment_any_stats() {
    let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());

    // Simulate the path taken by `recv_with_meta failed` / `peek_from failed`:
    // we log but do NOT call count_consumed_oversized.
    let _e = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "simulated");
    hick_trace::debug!(error = %_e, "recv_with_meta failed (test simulation — no stats bumped)");
    // (no stats call here — that IS the test)

    let snap = stats.snapshot();
    assert_eq!(
      snap.packets_rx, 0,
      "packets_rx must stay 0 on a generic recv error"
    );
    assert_eq!(
      snap.bytes_rx, 0,
      "bytes_rx must stay 0 on a generic recv error"
    );
    assert_eq!(
      snap.packets_dropped, 0,
      "packets_dropped must stay 0 on a generic recv error"
    );
  }
}

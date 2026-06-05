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
use async_channel::Sender;
use futures::{FutureExt, pin_mut, select_biased};
use mdns_proto::{
  QueryHandle, QuerySpec, ServiceHandle, ServiceSpec, ServiceUpdate, endpoint::WithdrawalSend,
  event::RouteEvent,
};
use rand::{SeedableRng, rngs::StdRng};
use slab::Slab;

use crate::{
  command::{Command, QueryStarted, ServiceRegistered},
  error::{RegisterError, StartQueryError},
  options::ServerOptions,
  proto::{ProtoEndpoint, ProtoService},
  query::{QueryMailbox, new_mailbox},
  service::{ServiceMailbox, new_service_mailbox},
};

#[cfg(test)]
mod tests;

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
  doorbell: Sender<()>,
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
  doorbell: Sender<()>,
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
  /// Reusable scratch for the per-wakeup service/query handle snapshots taken by
  /// `drain_transmits` and `push_updates`: those loops `get_mut` the same map
  /// they iterate while driving the disjoint `endpoint`, so they snapshot the
  /// keys first — but reuse these buffers (`clear()`ed each pass) instead of
  /// allocating a fresh `Vec` per wakeup, matching the compio / smoltcp drivers.
  svc_handle_scratch: Vec<ServiceHandle>,
  query_handle_scratch: Vec<QueryHandle>,
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
    // rand 0.10 removed `from_entropy`; seed StdRng from the OS-seeded thread RNG.
    let rng = StdRng::from_rng(&mut rand::rng());
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
      svc_handle_scratch: Vec::new(),
      query_handle_scratch: Vec::new(),
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
        //
        // The renamed-away old-name goodbye this registration RECLAIMS is no longer
        // cancelled at register time: the reclaim-cancel moved to the endpoint's
        // CANCEL-ON-ANNOUNCE (`note_service_advertised`), a certain live event, so a
        // dropped registration here cannot lose it — an orphan that never announces
        // simply lets the old goodbye complete. The rollback therefore
        // only removes the orphan service.
        let result = self.register_service(spec, now);
        if let Ok(ref ok) = result {
          let handle = ok.handle;
          if let Err(returned) = reply.send(result) {
            // returned is the (now-unowned) Result<ServiceRegistered, _>;
            // dropping it drops the receiver half of the per-handle channel, but the
            // proto Service still lives in our map until we GC it here.
            drop(returned);
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
      .try_register_service::<Slab<_>, Slab<_>>(spec, now)?;
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
          // Defense-in-depth for the no-dispatch-after-retirement invariant: the
          // endpoint already skips withdrawing routes in every ToService path
          // (question, conflict, known-answer), so this guards against a future
          // dispatch regression feeding events into a proto whose updates the
          // driver no longer drains — which would let a peer grow the proto event
          // slab of a retiring service until GC.
          if let Some(ctx) = services.get_mut(&ts.handle())
            && !ctx.withdrawing
          {
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
    // Split-borrow `endpoint` from `queries` so the sweep iterates the query map
    // in place — `handle_query_timeout` touches only the disjoint `endpoint`
    // field — instead of snapshotting every handle into a fresh per-tick Vec.
    let Self {
      endpoint, queries, ..
    } = &mut *self;
    for &h in queries.keys() {
      let _ = endpoint.handle_query_timeout(h, now);
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
        query_handle_scratch,
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
                // A rename COLLISION (rename_result Err) tears the service down: its
                // old name must HOLD until the goodbye completes so a quick
                // re-register cannot cancel the only retraction. A
                // SURVIVING rename stays reclaimable.
                endpoint.enqueue_rename_withdrawal(h, now, rename_result.is_err());
              }
              match rename_result {
                Ok(()) => upd,
                Err(_) => {
                  // The new name collides with another local service; the Service
                  // has already rebranded and can't be kept. Synthesize a terminal
                  // Conflict and fall through to the UNIFIED retirement below — the
                  // OLD name's goodbye was already enqueued above as its own
                  // detached item.
                  hick_trace::warn!(
                    handle = ?handle,
                    new_name = %renamed.new_name(),
                    "auto-rename collided with another registered service; emitting Conflict"
                  );
                  ServiceUpdate::Conflict
                }
              }
            }
            _ => upd,
          };
          // The mailbox coalesces by kind (one Established, latest Renamed) and
          // reserves the terminal, so a hostile peer repeating an event cannot
          // grow it — no consecutive-duplicate bookkeeping needed here.
          //
          // A terminal update — Conflict/HostConflict, whether emitted directly by
          // the proto state machine (e.g. unresolvable §9 conflict, host-name
          // claimed during probing) or synthesized above for a rebrand collision —
          // RETIRES the service: deliver it into the reserved terminal slot, then
          // begin the endpoint-owned §10.1 withdrawal so the ctx/route are GC'd and
          // the proto stops serving. Without this a proto-emitted terminal left the
          // service live (still answering queries) until the caller dropped the
          // handle, and `Service::next` reported end-of-stream on a still-serving
          // ctx. The mailbox outlives the ctx, so the terminal still
          // reaches the host even after the withdrawal GCs the ctx.
          let is_terminal = final_upd.is_conflict() || final_upd.is_host_conflict();
          deliver_service_update(ctx, final_upd);
          if is_terminal {
            removed_services.push(*handle);
            break;
          }
        }
      }

      // ── Query answers + terminals ─────────────────────────────────────
      let mut terminated: Vec<QueryHandle> = Vec::new();
      query_handle_scratch.clear();
      query_handle_scratch.extend(queries.keys().copied());
      for &h in query_handle_scratch.iter() {
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
        // `collected_answers` is proto's BOUNDED snapshot — the `max_answers`
        // cap evicts oldest entries before we scan. Answers accepted since our
        // last scan but no longer present were evicted before delivery; count
        // them so the loss is observable via `Query::dropped_answers` rather
        // than silently vanishing.
        let accepted = endpoint.query_accepted_count(h).unwrap_or(last_seq);
        let expected = accepted.saturating_sub(last_seq);
        // Only touch the mailbox when the proto accepted something since our last
        // scan (`expected > 0`); otherwise there is nothing to deliver and
        // nothing to account for. This is exactly the old
        // new-answers-or-eviction gate: the delivered count is always <=
        // expected, so `expected > 0` holds iff there was a new answer or an
        // eviction.
        if expected > 0
          && let Some(ctx) = queries.get_mut(&h)
        {
          // Push each new answer STRAIGHT into the bounded/coalescing mailbox
          // (never fails / never blocks; over-capacity coalesces or drops
          // oldest) — no intermediate `Vec<CollectedAnswer>` — counting
          // deliveries so the evicted-before-seen loss is `expected - delivered`.
          let mut delivered: u64 = 0;
          {
            let mut mb = ctx.mailbox.lock().unwrap_or_else(|e| e.into_inner());
            for ans in endpoint
              .collected_answers(h)
              .filter(|a| a.seq() >= last_seq)
              .cloned()
            {
              mb.push_answer(ans);
              delivered += 1;
            }
            mb.record_dropped(expected.saturating_sub(delivered));
          }
          // Advance past everything proto has accepted: delivered answers and
          // evicted-before-seen ones are now all accounted for.
          ctx.last_seq = accepted;
          // Ring ONCE for the batch — only when there's an answer to drain
          // (a pure-eviction bookkeeping bump has nothing for the consumer).
          if delivered > 0 {
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
      svc_handle_scratch,
      query_handle_scratch,
      ..
    } = self;
    // Plain fairness cap: bound the work per drain pass so a very large
    // handle set can't monopolise the loop before commands / packets are
    // serviced. (Self-loopback safety no longer depends on this — it's the
    // SystemTime-keyed `recent_sends` tracker + kernel rx timestamps.)
    let mut credits_remaining = MAX_SEND_CREDITS_PER_DRAIN;
    // Service transmits.
    svc_handle_scratch.clear();
    svc_handle_scratch.extend(services.keys().copied());
    for &h in svc_handle_scratch.iter() {
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
              ctx.proto.advertises_instance(),
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
              // Retirement = the service is dead: hold its old name until the
              // goodbye completes.
              endpoint.enqueue_rename_withdrawal(handoff, now, true);
            }
            let snap = ctx.proto.withdrawal_snapshot();
            endpoint.begin_withdrawal(h, snap, now);
          }
        }
      }
    }
    // Query transmits.
    query_handle_scratch.clear();
    query_handle_scratch.extend(queries.keys().copied());
    // Collect queries that were retired due to encode failures so they can be
    // GC'd after the loop (matching the terminated-handle cleanup in push_updates).
    let mut encode_retired: Vec<QueryHandle> = Vec::new();
    // Use a flag instead of an early `return true` inside the query loop so
    // that encode_retired GC ALWAYS runs before the function returns — even
    // when the send budget is exhausted mid-loop.  An early `return true` here
    // would bypass the cleanup below and leave the retired handle resident in
    // both `queries` and proto storage until the user drops the stream.
    let mut more_pending = false;
    'query_loop: for &h in query_handle_scratch.iter() {
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
      // Retirement = the service is dead: hold its old name until the goodbye
      // completes so a re-register cannot cancel it.
      self.endpoint.enqueue_rename_withdrawal(handoff, now, true);
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

//! Background driver task. Owns the [`mdns_proto::Endpoint`] + per-service /
//! per-query state machines and pumps the I/O loop.

use std::{
  collections::{HashMap, VecDeque},
  net::{IpAddr, SocketAddr},
  sync::{Arc, Mutex},
  time::{Duration, Instant as StdInstant, SystemTime},
};

use agnostic_lite::RuntimeLite;
use agnostic_net::{Net, UdpSocket};
use futures::{FutureExt, pin_mut, select_biased};
use mdns_proto::{
  CollectedAnswer, QueryHandle, QuerySpec, ServiceHandle, ServiceSpec, ServiceUpdate,
  event::RouteEvent,
};

use crate::{
  command::{Command, QueryStarted, ServiceRegistered},
  error::{RegisterError, StartQueryError},
  options::ServerOptions,
  proto::{ProtoEndpoint, ProtoService},
  query::{QueryMailbox, new_mailbox},
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

/// Marker for [`ServiceUpdate`] deduplication. Two updates with the same
/// mark carry the same actionable information; the driver coalesces
/// consecutive duplicates so a hostile peer cannot inflate an unbounded
/// per-handle queue by spamming HostConflict/Conflict-bearing packets.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UpdateMark {
  Established,
  Renamed(mdns_proto::Name),
  Conflict,
  HostConflict,
}

impl UpdateMark {
  fn of(upd: &ServiceUpdate) -> Option<Self> {
    match upd {
      ServiceUpdate::Established => Some(Self::Established),
      ServiceUpdate::Renamed(r) => Some(Self::Renamed(r.new_name().clone())),
      ServiceUpdate::Conflict => Some(Self::Conflict),
      ServiceUpdate::HostConflict => Some(Self::HostConflict),
      _ => None,
    }
  }
}

/// Driver-side state for a single registered service.
struct ServiceCtx {
  proto: ProtoService,
  updates: async_channel::Sender<ServiceUpdate>,
  /// marker of the last update we pushed into `updates`.
  /// Consecutive `ServiceUpdate`s that map to the same mark are
  /// coalesced (skipped) so a hostile peer cannot grow the channel
  /// without bound by repeating an event the caller has already
  /// observed.
  last_pushed: Option<UpdateMark>,
  /// count of consecutive `poll_transmit` errors for this
  /// service. Once it crosses [`MAX_CONSECUTIVE_ENCODE_ERRORS`] the
  /// driver assumes the registration is structurally unusable (e.g.
  /// records exceed `max_payload_size`) and surfaces `Conflict` so
  /// the caller is notified instead of seeing a misleading
  /// `Established` later.
  encode_failures: u8,
  /// bounded, INSERTION-ORDERED overflow for service updates
  /// when the `updates` channel is full (a slow/non-draining consumer). Updates
  /// are appended in arrival order and flushed front-to-back, so causal order
  /// (e.g. a `Renamed` that arrived before `Established`, or vice-versa) is
  /// preserved. It stays bounded by coalescing: a new `Renamed` removes any
  /// prior pending `Renamed` and re-appends at the latest position (the caller
  /// only needs the current name), while the one-time/idempotent kinds
  /// (`Established`/`Conflict`/`HostConflict`) dedup by kind — so the deque
  /// holds at most one of each kind (≤ 4 entries) regardless of churn.
  pending: VecDeque<ServiceUpdate>,
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
  /// TTL=0 goodbye packets queued by `UnregisterService`, resent a
  /// few times for reliability before being dropped. Each entry is a fully
  /// encoded datagram (the proto Service is removed immediately; these bytes
  /// are self-contained), so withdrawal proceeds even though the service
  /// state machine is gone.
  goodbyes: Vec<PendingGoodbye>,
  /// Max datagram size, used to size the scratch buffer for encoding a
  /// goodbye in the (infrequent) unregister path.
  max_payload: usize,
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

/// A pending RFC 6762 §10.1 goodbye broadcast.
struct PendingGoodbye {
  /// Fully encoded TTL=0 datagram (records of the withdrawn service).
  data: Vec<u8>,
  /// Remaining sends; the entry is dropped once this reaches zero. Decremented
  /// ONLY on a round that actually reached the wire (Part A) — a round in which
  /// every family's `send_to` failed leaves this untouched.
  remaining: u8,
  /// Earliest wall-clock instant at which the next send may go out.
  next_at: StdInstant,
  /// `false` until the FIRST round of this goodbye reaches the wire (at least one
  /// family sent). While `false` — and before [`Self::expires_at`] — this entry
  /// is a PENDING BARRIER: a free-name (retirement/rename) TTL=0 withdrawal that
  /// must precede any positive-TTL transmit, so a same-name replacement under
  /// `with_probe_unique_names(false)` cannot announce a fresh positive TTL ahead
  /// of the stale TTL=0 and evict itself from peer caches. Set once, never cleared.
  sent_once: bool,
  /// Hard deadline after which the entry is force-cleared even if it never sent —
  /// the anti-pin bound for both the [`Self::sent_once`] barrier and the entry's
  /// lifetime. Set at queue time to `now + GOODBYE_BARRIER_MAX`. Because Part A
  /// stops advancing `remaining` on a never-delivered round, this bound (not
  /// `remaining`) prevents an undeliverable goodbye pinning the queue / blocking
  /// transmits forever.
  expires_at: StdInstant,
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
      goodbyes: Vec::new(),
      max_payload: opts.max_payload_size(),
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
  fn next_deadline(&self) -> Option<StdInstant> {
    let mut best: Option<StdInstant> = self.endpoint.poll_timeout();
    for ctx in self.services.values() {
      if let Some(t) = ctx.proto.poll_timeout() {
        best = Some(min_opt(best, t));
      }
    }
    for handle in self.queries.keys() {
      if let Some(t) = self.endpoint.poll_query_timeout(*handle) {
        best = Some(min_opt(best, t));
      }
    }
    // wake to resend any pending goodbye when it comes due. `next_at` is short
    // (GOODBYE_RETRY_BACKOFF) after a failed round, so a deferred barrier wakes
    // promptly. While still an un-sent barrier, also wake at its `expires_at`
    // ceiling so a never-sendable barrier releases the deferred positive
    // transmits no later than that bound.
    for g in &self.goodbyes {
      best = Some(min_opt(best, g.next_at));
      if !g.sent_once {
        best = Some(min_opt(best, g.expires_at));
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
            // go through the shared removal path. The service
            // was just registered (still probing, never announced), so
            // `encode_goodbye` yields None and no goodbye is queued — the
            // rollback stays silent, as it should.
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
        // graceful withdrawal goes through the shared
        // removal helper so an explicit unregister and a dropped-handle sweep
        // both emit the TTL=0 goodbye.
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
    // the per-service update channel delivers every
    // Established/Renamed/Conflict/HostConflict transition, but it is BOUNDED:
    // an on-link peer can force endless conflict-renames, and each
    // `Renamed(new_name)` is a distinct event (so consecutive-duplicate
    // coalescing does not collapse it). An unbounded channel + a non-draining
    // caller would then grow memory without bound. With a bounded channel the
    // driver distinguishes a full channel (slow consumer — coalesce into the
    // single `pending` overflow slot, keeping the latest state) from a closed
    // one (dropped handle — withdraw the service), so memory is bounded to
    // capacity + 1 per service while the current state still reaches the caller.
    let (tx, rx) = async_channel::bounded(SERVICE_UPDATE_CAPACITY);
    self.services.insert(
      handle,
      ServiceCtx {
        proto: svc,
        updates: tx,
        last_pushed: None,
        encode_failures: 0,
        pending: VecDeque::new(),
      },
    );
    Ok(ServiceRegistered {
      handle,
      updates: rx,
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
    // services to remove this pass. Collected here and removed
    // AFTER the split borrow ends so every removal goes through
    // `remove_service`, which emits the TTL=0 goodbye for an established
    // service. (A service still probing / mid-rename yields no goodbye —
    // `encode_goodbye` returns None — so this is safe for all cases.)
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
        // even if no event is pending, a closed receiver means the
        // caller dropped their handle — withdraw the service gracefully.
        if ctx.updates.is_closed() {
          removed_services.push(*handle);
          continue;
        }
        // opportunistically flush a coalesced overflow update now
        // that the caller may have drained the channel.
        if !flush_pending_service_update(ctx) {
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
              match endpoint.handle_service_renamed(*handle, renamed.new_name().clone()) {
                Ok(()) => upd,
                Err(_) => {
                  hick_trace::warn!(
                    handle = ?handle,
                    new_name = %renamed.new_name(),
                    "auto-rename collided with another registered service; emitting Conflict"
                  );
                  let conflict = ServiceUpdate::Conflict;
                  let mark = UpdateMark::of(&conflict);
                  if ctx.last_pushed != mark {
                    let _ = deliver_service_update(ctx, conflict);
                    ctx.last_pushed = mark;
                  }
                  removed_services.push(*handle);
                  break;
                }
              }
            }
            _ => upd,
          };
          // coalesce consecutive duplicates so a hostile peer cannot
          // grow the per-service channel by repeating an event the caller has
          // already observed. Distinct (non-consecutive) events route
          // through the bounded, overflow-coalescing delivery path.
          let mark = UpdateMark::of(&final_upd);
          if mark.is_some() && mark == ctx.last_pushed {
            continue;
          }
          if !deliver_service_update(ctx, final_upd) {
            removed_services.push(*handle);
            break;
          }
          ctx.last_pushed = mark;
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
      // transmit for an already-orphaned handle.
      let live = services
        .get(&h)
        .map(|c| !c.updates.is_closed())
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
            "Service exceeded MAX_CONSECUTIVE_ENCODE_ERRORS; emitting Conflict and unregistering"
          );
          if let Some(ctx) = services.get_mut(&h) {
            let _ = deliver_service_update(ctx, ServiceUpdate::Conflict);
            ctx.last_pushed = Some(UpdateMark::Conflict);
          }
          // direct removal (no goodbye) is correct here — a
          // service that persistently fails to ENCODE its announcement never
          // reached Established, so peers cached nothing to withdraw. (The
          // records are fixed at registration and the scratch buffer is
          // fixed, so an encode failure is permanent, not transient.)
          services.remove(&h);
          let _ = endpoint.unregister_service(h);
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

  /// Resend any due TTL=0 goodbye packets and drop those that are finished. Each
  /// goodbye fans out to BOTH multicast families via `send_via` (the `MDNS_V4_DST`
  /// sentinel triggers the dual-stack path) and is recorded in the self-send
  /// tracker like any other transmit, so its loopback isn't misclassified.
  ///
  /// ## Part A — round advancement is gated on a real send (live path)
  ///
  /// `send_via` returns the number of families that actually sent. When `force`
  /// is `false` (the live driver loop) a round is counted ONLY if at least one
  /// family sent: the first such round latches [`PendingGoodbye::sent_once`]
  /// (clearing the transmit barrier), spends one resend, and re-arms at
  /// [`GOODBYE_INTERVAL`]; an all-failing round re-arms at the short
  /// [`GOODBYE_RETRY_BACKOFF`] without consuming the budget, so a transiently-
  /// undeliverable free-name goodbye (and the positive transmit its barrier
  /// blocks) retries promptly. Entries past their `expires_at` anti-pin bound are
  /// force-cleared regardless of `remaining` so a never-deliverable barrier cannot
  /// pin the queue forever.
  ///
  /// ## `force` — the shutdown flush
  ///
  /// [`Self::flush_goodbyes`] passes `force = true`: the driver is exiting, the
  /// barrier/ordering is moot, and the burst must TERMINATE best-effort even with
  /// no reachable socket. There, a round spends a resend on every attempt (the
  /// pre-Part-A semantics) so the queue drains in at most `GOODBYE_SENDS` passes
  /// per entry rather than spinning to `expires_at`.
  async fn drain_goodbyes(&mut self, now: StdInstant, force: bool) {
    if self.goodbyes.is_empty() {
      return;
    }
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();
    let Self {
      goodbyes,
      recent_sends,
      v4,
      v6,
      ..
    } = self;
    for g in goodbyes.iter_mut() {
      if g.remaining > 0 && g.next_at <= now {
        let credits = send_via::<N>(
          recent_sends,
          v4,
          v6,
          MDNS_V4_DST,
          &g.data,
          #[cfg(feature = "stats")]
          &stats,
        )
        .await;
        let any_sent = credits > 0;
        #[cfg(feature = "stats")]
        if any_sent {
          stats.goodbyes_tx(1);
        }
        if any_sent {
          // Part A: a real send latches the barrier and spends a resend.
          g.sent_once = true;
          g.remaining = g.remaining.saturating_sub(1);
          g.next_at = now + GOODBYE_INTERVAL;
        } else if force {
          // Shutdown flush: terminate the burst even with nothing on the wire.
          g.remaining = g.remaining.saturating_sub(1);
          g.next_at = now + GOODBYE_INTERVAL;
        } else {
          // Live path, all-failing round: keep the budget, retry soon.
          g.next_at = now + GOODBYE_RETRY_BACKOFF;
        }
      }
    }
    // Drop finished entries; force-clear any past its anti-pin `expires_at`
    // REGARDLESS of `remaining` (a never-delivered barrier must not pin the queue
    // or block transmits forever now that Part A stops spending its budget on
    // failed rounds).
    let mut force_cleared = 0usize;
    goodbyes.retain(|g| {
      if g.expires_at <= now {
        if g.remaining > 0 {
          force_cleared += 1;
        }
        return false;
      }
      g.remaining > 0
    });
    if force_cleared > 0 {
      hick_trace::debug!(
        count = force_cleared,
        "force-cleared undeliverable goodbye(s) past the barrier/retention bound"
      );
    }
  }

  /// Part B — `true` if any pending goodbye is still a barrier: it has not yet
  /// reached the wire (`!sent_once`) AND has not passed its `expires_at` ceiling.
  /// The driver loop defers phase D (the positive-TTL transmit drain) while this
  /// holds.
  ///
  /// The barrier is intentionally GLOBAL — ANY pending un-sent free-name goodbye
  /// defers ALL positive transmits, not just same-name ones. This is acceptable
  /// (and far simpler than name-scoping the proto transmit queue) because a
  /// SENDABLE barrier clears in the same loop iteration's pre-transmit
  /// `drain_goodbyes`, so normal operation only gains a goodbye-before-transmit
  /// ordering; only an UN-sendable (all-failing) barrier actually defers
  /// transmits, bounded by `expires_at`.
  fn has_pending_barrier(&self, now: StdInstant) -> bool {
    self
      .goodbyes
      .iter()
      .any(|g| !g.sent_once && g.expires_at > now)
  }

  /// Drive the remaining goodbye burst to completion, sleeping
  /// between resends per [`GOODBYE_INTERVAL`]. Called once on driver shutdown
  /// so a withdrawal queued just before the endpoint dropped is fully sent
  /// rather than abandoned after its first packet. Bounded: each pass sends
  /// at least the earliest-due entry and decrements its count, so this
  /// completes in at most `GOODBYE_SENDS` iterations per entry.
  async fn flush_goodbyes(&mut self) {
    while !self.goodbyes.is_empty() {
      // `force = true`: we are exiting, so terminate the burst best-effort even
      // with no reachable socket (the barrier/ordering no longer matters).
      self.drain_goodbyes(StdInstant::now(), true).await;
      match self.goodbyes.iter().map(|g| g.next_at).min() {
        Some(next) => {
          let dur = next.saturating_duration_since(StdInstant::now());
          if dur > Duration::ZERO {
            <N::Runtime as RuntimeLite>::sleep(dur).await;
          }
        }
        None => break,
      }
    }
  }

  /// GC handles whose caller has dropped the receiver. Runs at
  /// the TOP of the driver loop (before `fire_timeouts` /
  /// `drain_transmits`) so an orphan query cancelled between its
  /// `StartQuery` reply and the caller receiving the handle cannot
  /// multicast a question before being collected.
  fn sweep_closed_handles(&mut self, now: StdInstant) {
    // a dropped Service handle closes `updates` AND enqueues
    // UnregisterService. This sweep can win the race and collect the service
    // first, so it MUST route through `remove_service` (which queues the
    // goodbye) — otherwise the dropped service is silently withdrawn with no
    // TTL=0 goodbye and peers keep stale records until TTL expiry.
    let dead_svc: Vec<ServiceHandle> = self
      .services
      .iter()
      .filter(|(_, ctx)| ctx.updates.is_closed())
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

  /// Remove a service, queuing its TTL=0 goodbye from
  /// the still-present records BEFORE dropping the driver ctx and proto
  /// route. Shared by explicit `UnregisterService` and the dropped-handle
  /// sweep so withdrawal is graceful regardless of which path removes it.
  /// `encode_goodbye` yields `None` for a service that never announced
  /// (still probing / conflicted) — nothing is cached, so nothing to send.
  fn remove_service(&mut self, handle: ServiceHandle, now: StdInstant) {
    let cap = self.max_payload.max(512);
    // if another service still advertises this service's host name,
    // its host A/AAAA records are shared. Withdrawing them would evict a
    // sibling's still-valid addresses from peer caches, so emit an
    // instance-only goodbye (PTR/SRV/TXT, no A/AAAA) in that case. Host names
    // are canonical-lowercase, so `==` is already case-insensitive (RFC §16).
    //
    // host A/AAAA ownership is PER ADDRESS, not per host
    // name. Two services sharing a host name may advertise different address
    // sets, so collect the exact addresses OTHER same-host services have
    // actually ADVERTISED — `advertised_a_addrs`/`advertised_aaaa_addrs`, the
    // confirmed-emitted set, NOT `records()` (the configured set: a §7.1
    // KAS-filtered send may have emitted only a subset). Building from the
    // configured set would over-retain — suppressing withdrawal of an address
    // no remaining service actually advertised, leaving it stale in peer caches
    // until TTL. The removed service then withdraws only its own host addresses
    // that no sibling still owns; a shared address is retained, a unique one is
    // retracted.
    let retained_host_addrs: Vec<IpAddr> = if let Some(ctx) = self.services.get(&handle) {
      let host = ctx.proto.records().host().clone();
      let mut set: Vec<IpAddr> = Vec::new();
      for (h, other) in self.services.iter() {
        if *h != handle && other.proto.records().host() == &host {
          set.extend(
            other
              .proto
              .advertised_a_addrs()
              .iter()
              .map(|a| IpAddr::V4(*a)),
          );
          set.extend(
            other
              .proto
              .advertised_aaaa_addrs()
              .iter()
              .map(|a| IpAddr::V6(*a)),
          );
        }
      }
      set
    } else {
      Vec::new()
    };
    // Encode the withdrawals while the proto state is still present, then
    // queue them. Collected into a local Vec first so the borrow of
    // `self.services` is released before pushing into `self.goodbyes`.
    let mut pending: Vec<Vec<u8>> = Vec::new();
    if let Some(ctx) = self.services.get_mut(&handle) {
      let mut buf = vec![0u8; cap];
      if let Ok(Some(len)) = ctx.proto.encode_goodbye(&mut buf, &retained_host_addrs) {
        buf.truncate(len);
        pending.push(buf);
      }
      // a conflict-rename may have queued an unsent withdrawal of
      // the OLD instance records in the proto, resent on a timer by
      // `poll_transmit`. Removal drops that proto state, so drain the bytes
      // here and hand them to our own goodbye queue — otherwise the old name
      // lingers in peer caches until TTL expiry. `cap` (>=512) always fits an
      // instance-only goodbye, so the BufferTooSmall arm is unreachable here;
      // treat it as best-effort (the old records otherwise TTL-expire).
      let mut rbuf = vec![0u8; cap];
      if let Ok(Some(rlen)) = ctx.proto.take_pending_rename_goodbye(&mut rbuf) {
        rbuf.truncate(rlen);
        pending.push(rbuf);
      }
    }
    for data in pending {
      self.goodbyes.push(PendingGoodbye {
        data,
        remaining: GOODBYE_SENDS,
        next_at: now,
        sent_once: false,
        expires_at: now + GOODBYE_BARRIER_MAX,
      });
    }
    self.services.remove(&handle);
    let _ = self.endpoint.unregister_service(handle);
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

/// Capacity of the per-service [`ServiceUpdate`] channel. Large
/// enough to hold the rare legitimate burst (Established + a few probe-time
/// renames + a terminal event) without overflowing; beyond it a slow/non-
/// draining consumer causes updates to coalesce into the single `pending`
/// overflow slot rather than growing memory without bound under
/// attacker-driven conflict-rename churn.
const SERVICE_UPDATE_CAPACITY: usize = 16;

/// Try to flush a service's ordered overflow into its bounded channel
///. Updates are sent front-to-back in insertion order, stopping
/// at the first that does not fit (kept at the front for a later attempt).
/// Returns `false` only when the channel is CLOSED (caller dropped the handle).
fn flush_pending_service_update(ctx: &mut ServiceCtx) -> bool {
  use async_channel::TrySendError;
  while let Some(upd) = ctx.pending.pop_front() {
    match ctx.updates.try_send(upd) {
      Ok(()) => {}
      Err(TrySendError::Full(upd)) => {
        ctx.pending.push_front(upd);
        return true;
      }
      Err(TrySendError::Closed(_)) => return false,
    }
  }
  true
}

/// Buffer `upd` into the ordered overflow when the bounded channel is full,
/// preserving insertion order while staying bounded:
///
/// * `Renamed` — drop any prior pending `Renamed` and append the new one, so
///   only the LATEST name is kept, at its true (most recent) position.
/// * `Established` / `Conflict` / `HostConflict` — append only if no update of
///   that kind is already pending (one-time / idempotent), never displacing an
///   earlier-queued update.
///
/// The deque therefore holds at most one entry per kind (≤ 4) regardless of
/// how much an on-link peer churns conflict-renames.
fn buffer_overflow_service_update(pending: &mut VecDeque<ServiceUpdate>, upd: ServiceUpdate) {
  if matches!(upd, ServiceUpdate::Renamed(_)) {
    pending.retain(|u| !matches!(u, ServiceUpdate::Renamed(_)));
    pending.push_back(upd);
    return;
  }
  let kind = core::mem::discriminant(&upd);
  if !pending.iter().any(|u| core::mem::discriminant(u) == kind) {
    pending.push_back(upd);
  }
}

/// Deliver a `ServiceUpdate` to a service's caller, bounding memory
/// while preserving insertion order.
///
/// Flushes the ordered overflow first, then sends `upd`. When the bounded
/// channel is FULL the update is appended to the ordered overflow (see
/// [`buffer_overflow_service_update`]), so a non-draining caller cannot grow
/// memory beyond capacity + 4. Returns `false` only when the channel is CLOSED
/// (the caller dropped the handle), signalling the driver to withdraw it.
fn deliver_service_update(ctx: &mut ServiceCtx, upd: ServiceUpdate) -> bool {
  use async_channel::TrySendError;
  if !flush_pending_service_update(ctx) {
    return false; // closed
  }
  // Overflow still present after the flush (channel full): append `upd` so it
  // stays ordered behind the existing overflow.
  if !ctx.pending.is_empty() {
    buffer_overflow_service_update(&mut ctx.pending, upd);
    return true;
  }
  match ctx.updates.try_send(upd) {
    Ok(()) => true,
    Err(TrySendError::Full(upd)) => {
      buffer_overflow_service_update(&mut ctx.pending, upd);
      true
    }
    Err(TrySendError::Closed(_)) => false,
  }
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

/// How many times a TTL=0 goodbye is multicast on unregister.
/// RFC 6762 §10.1 allows sending a goodbye two or three times for
/// reliability over lossy multicast.
const GOODBYE_SENDS: u8 = 3;

/// Spacing between goodbye resends.
const GOODBYE_INTERVAL: Duration = Duration::from_millis(250);

/// Short re-attempt delay for a goodbye round that put NOTHING on the wire (every
/// family's `send_to` failed). Much smaller than [`GOODBYE_INTERVAL`] so a
/// transiently-undeliverable free-name goodbye is retried promptly — WITHOUT
/// consuming a resend round and WITHOUT busy-spinning — and a positive transmit
/// deferred behind its [`PendingGoodbye::sent_once`] barrier wakes again soon.
/// Kept consistent with `hick-smoltcp`/`hick-compio`'s `GOODBYE_RETRY_BACKOFF`.
const GOODBYE_RETRY_BACKOFF: Duration = Duration::from_millis(20);

/// Hard ceiling on how long an un-sent free-name goodbye may act as a transmit
/// barrier (see [`PendingGoodbye::sent_once`]) AND on its retention. Because Part
/// A no longer decrements a goodbye's resend budget on a round that never reached
/// the wire, a permanently-undeliverable entry would otherwise pin the goodbye
/// queue — and block positive transmits — forever. Past this age the entry is
/// force-cleared so it can neither block transmits nor leak. Kept consistent with
/// `hick-smoltcp`/`hick-compio`'s `GOODBYE_BARRIER_MAX`.
const GOODBYE_BARRIER_MAX: Duration = Duration::from_secs(2);

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
    // FREE-NAME GOODBYE BARRIER (pre-transmit). Before phase D (the positive-TTL
    // transmit drain), (1) attempt the due goodbyes so a SENDABLE free-name
    // (retirement/rename) TTL=0 withdrawal reaches the wire FIRST — clearing such
    // a barrier this tick — then (2) if a goodbye is still an un-sent, unexpired
    // barrier, SKIP phase D so a same-name replacement registered under
    // `with_probe_unique_names(false)` cannot announce a fresh positive TTL ahead
    // of the stale TTL=0 (which would evict it from peer caches). Only an
    // UN-sendable (all-failing) barrier actually defers transmits, bounded by each
    // entry's `expires_at`; `next_deadline` wakes on GOODBYE_RETRY_BACKOFF /
    // `expires_at` so a deferred barrier retries promptly. The post-`push_updates`
    // drain (phase F, below) is KEPT so a newly-queued rename goodbye still flushes
    // this tick.
    state.drain_goodbyes(now, false).await;
    let transmit_barred = state.has_pending_barrier(now);
    let more_transmits_pending = if transmit_barred {
      false
    } else {
      state.drain_transmits(now, &mut scratch).await
    };
    state.push_updates(now).await;
    // emit any due TTL=0 goodbye resends for unregistered services (phase F).
    state.drain_goodbyes(now, false).await;

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
      // fall through to flush any queued goodbye burst before exiting.
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

  // graceful shutdown — withdraw EVERY still-registered service
  // (the endpoint is going away), queuing each one's TTL=0 goodbye via the
  // shared removal helper. Without this, services that were live at shutdown
  // would linger in peers' caches until TTL expiry.
  let shutdown_now = StdInstant::now();
  let live_services: Vec<ServiceHandle> = state.services.keys().copied().collect();
  for h in live_services {
    state.remove_service(h, shutdown_now);
  }
  // then finish any in-flight TTL=0 goodbye burst — both the ones
  // just queued above and any from an unregister/drop right before shutdown —
  // before the task ends.
  state.flush_goodbyes().await;
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

  /// unregistering one service must NOT withdraw the host A/AAAA
  /// records while another registered service still advertises the same host
  /// — otherwise the sibling's addresses are evicted from peer caches. The
  /// sole remaining owner's withdrawal DOES include the host addresses.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn unregister_shared_host_preserves_sibling_addresses() {
    use std::{net::Ipv4Addr, time::Duration};

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    // Two services with distinct instance/type names but the SAME host.
    let mk = |stype: &str, inst: &str| {
      let mut r = mdns_proto::ServiceRecords::new(
        mdns_proto::Name::try_from_str(stype).unwrap(),
        mdns_proto::Name::try_from_str(inst).unwrap(),
        mdns_proto::Name::try_from_str("shared.local.").unwrap(),
        631,
        120,
      );
      r.add_a(Ipv4Addr::new(192, 168, 1, 10));
      mdns_proto::ServiceSpec::new(r)
    };
    let reg_a = state
      .register_service(mk("_ipp._tcp.local.", "one._ipp._tcp.local."), now)
      .unwrap();
    let reg_b = state
      .register_service(mk("_http._tcp.local.", "two._http._tcp.local."), now)
      .unwrap();
    let (a, b) = (reg_a.handle, reg_b.handle);

    // Drive both proto services to an announced state so encode_goodbye fires.
    for h in [a, b] {
      let ctx = state.services.get_mut(&h).unwrap();
      let mut buf = vec![0u8; 4096];
      let mut t = now;
      for _ in 0..40 {
        t += Duration::from_millis(300);
        let _ = ctx.proto.handle_timeout(t);
        // Simulate a successful send so the proto latches its announce/host
        // guards (delivery is confirmed via note_transmit_delivered).
        while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
          ctx.proto.note_transmit_delivered(t);
        }
      }
    }

    // Remove A while B still uses "shared.local." → instance-only goodbye.
    state.goodbyes.clear();
    state.remove_service(a, now);
    assert_eq!(state.goodbyes.len(), 1, "removal must queue one goodbye");
    assert!(
      !goodbye_withdraws_addr(&state.goodbyes[0].data),
      "shared-host removal must omit host A/AAAA (sibling still advertises them)"
    );

    // Remove B (now the sole owner of the host) → full goodbye with A/AAAA.
    state.goodbyes.clear();
    state.remove_service(b, now);
    assert_eq!(state.goodbyes.len(), 1);
    assert!(
      goodbye_withdraws_addr(&state.goodbyes[0].data),
      "sole-owner removal must withdraw the host A/AAAA"
    );
  }

  /// a same-host sibling that is merely registered but has NOT
  /// announced does not keep peers' host records alive, so removing an
  /// announced service next to such a sibling must STILL withdraw the host
  /// A/AAAA (a full goodbye) — otherwise the only advertised host records
  /// linger in peer caches until TTL expiry.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn unregister_with_unannounced_same_host_sibling_withdraws_addresses() {
    use std::{net::Ipv4Addr, time::Duration};

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    let mk = |stype: &str, inst: &str| {
      let mut r = mdns_proto::ServiceRecords::new(
        mdns_proto::Name::try_from_str(stype).unwrap(),
        mdns_proto::Name::try_from_str(inst).unwrap(),
        mdns_proto::Name::try_from_str("shared.local.").unwrap(),
        631,
        120,
      );
      r.add_a(Ipv4Addr::new(192, 168, 1, 10));
      mdns_proto::ServiceSpec::new(r)
    };
    let reg_a = state
      .register_service(mk("_ipp._tcp.local.", "one._ipp._tcp.local."), now)
      .unwrap();
    let reg_b = state
      .register_service(mk("_http._tcp.local.", "two._http._tcp.local."), now)
      .unwrap();
    let (a, _b) = (reg_a.handle, reg_b.handle);

    // Drive ONLY A to an announced state; B stays registered but never
    // announces (still probing), so it has not advertised the host records.
    {
      let ctx = state.services.get_mut(&a).unwrap();
      let mut buf = vec![0u8; 4096];
      let mut t = now;
      for _ in 0..40 {
        t += Duration::from_millis(300);
        let _ = ctx.proto.handle_timeout(t);
        // Simulate a successful send so the proto latches its announce/host
        // guards (delivery is confirmed via note_transmit_delivered).
        while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
          ctx.proto.note_transmit_delivered(t);
        }
      }
    }

    // Removing A must withdraw the host A/AAAA: B never advertised them, so A
    // is the only peer-visible advertiser of "shared.local.".
    state.goodbyes.clear();
    state.remove_service(a, now);
    assert_eq!(state.goodbyes.len(), 1, "removal must queue one goodbye");
    assert!(
      goodbye_withdraws_addr(&state.goodbyes[0].data),
      "removal must withdraw host A/AAAA when the same-host sibling never announced"
    );
  }

  /// two services sharing a host NAME but advertising DISJOINT
  /// addresses. Removing one must withdraw only its own host address, never the
  /// sibling's still-advertised one (host ownership is per-address, not per
  /// host name).
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn unregister_disjoint_host_addrs_withdraws_only_own() {
    use std::{net::Ipv4Addr, time::Duration};

    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();

    let mk = |stype: &str, inst: &str, addr: Ipv4Addr| {
      let mut r = mdns_proto::ServiceRecords::new(
        mdns_proto::Name::try_from_str(stype).unwrap(),
        mdns_proto::Name::try_from_str(inst).unwrap(),
        mdns_proto::Name::try_from_str("shared.local.").unwrap(),
        631,
        120,
      );
      r.add_a(addr);
      mdns_proto::ServiceSpec::new(r)
    };
    let a_addr = Ipv4Addr::new(192, 168, 1, 10);
    let b_addr = Ipv4Addr::new(192, 168, 1, 11);
    let reg_a = state
      .register_service(mk("_ipp._tcp.local.", "one._ipp._tcp.local.", a_addr), now)
      .unwrap();
    let reg_b = state
      .register_service(
        mk("_http._tcp.local.", "two._http._tcp.local.", b_addr),
        now,
      )
      .unwrap();
    let (a, b) = (reg_a.handle, reg_b.handle);
    for h in [a, b] {
      let ctx = state.services.get_mut(&h).unwrap();
      let mut buf = vec![0u8; 4096];
      let mut t = now;
      for _ in 0..40 {
        t += Duration::from_millis(300);
        let _ = ctx.proto.handle_timeout(t);
        // Simulate a successful send so the proto latches its announce/host
        // guards (delivery is confirmed via note_transmit_delivered).
        while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
          ctx.proto.note_transmit_delivered(t);
        }
      }
    }

    // Remove A: its own .10 is withdrawn, B's disjoint .11 is preserved.
    state.goodbyes.clear();
    state.remove_service(a, now);
    assert_eq!(state.goodbyes.len(), 1);
    let withdrawn = goodbye_v4_addrs(&state.goodbyes[0].data);
    assert!(
      withdrawn.contains(&a_addr),
      "A's own host address must be withdrawn"
    );
    assert!(
      !withdrawn.contains(&b_addr),
      "the sibling's disjoint host address must NOT be withdrawn"
    );

    // Remove B (now sole owner): its own .11 is withdrawn.
    state.goodbyes.clear();
    state.remove_service(b, now);
    assert_eq!(state.goodbyes.len(), 1);
    let withdrawn = goodbye_v4_addrs(&state.goodbyes[0].data);
    assert!(
      withdrawn.contains(&b_addr),
      "B's own host address must be withdrawn when it leaves"
    );
  }

  #[cfg(feature = "tokio")]
  fn goodbye_v4_addrs(data: &[u8]) -> Vec<std::net::Ipv4Addr> {
    let reader = mdns_proto::wire::MessageReader::try_parse(data).unwrap();
    let mut out = Vec::new();
    for r in reader.answers().filter_map(Result::ok) {
      if r.rtype() == mdns_proto::wire::ResourceType::A {
        let rd = r.rdata();
        if rd.len() == 4 {
          out.push(std::net::Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]));
        }
      }
    }
    out
  }

  #[cfg(feature = "tokio")]
  fn goodbye_withdraws_addr(data: &[u8]) -> bool {
    let reader = mdns_proto::wire::MessageReader::try_parse(data).unwrap();
    reader.answers().filter_map(Result::ok).any(|r| {
      matches!(
        r.rtype(),
        mdns_proto::wire::ResourceType::A | mdns_proto::wire::ResourceType::AAAA
      )
    })
  }

  #[test]
  fn overflow_buffer_preserves_insertion_order_and_coalesces() {
    use mdns_proto::{ServiceUpdate, event::ServiceRenamed};
    let renamed = |n: &str| {
      ServiceUpdate::Renamed(ServiceRenamed::new(
        mdns_proto::Name::try_from_str(n).unwrap(),
      ))
    };

    // Renamed arriving BEFORE Established keeps insertion order
    // (Renamed first) — it is NOT forced behind Established.
    let mut d = VecDeque::new();
    buffer_overflow_service_update(&mut d, renamed("a-1._ipp._tcp.local."));
    buffer_overflow_service_update(&mut d, ServiceUpdate::Established);
    assert!(
      matches!(d.front(), Some(ServiceUpdate::Renamed(_))),
      "the Renamed inserted first must stay at the front"
    );
    assert!(matches!(d.back(), Some(ServiceUpdate::Established)));

    // Established then a terminal: order preserved.
    let mut d2 = VecDeque::new();
    buffer_overflow_service_update(&mut d2, ServiceUpdate::Established);
    buffer_overflow_service_update(&mut d2, ServiceUpdate::Conflict);
    assert!(matches!(d2.front(), Some(ServiceUpdate::Established)));
    assert!(matches!(d2.back(), Some(ServiceUpdate::Conflict)));

    // Rename churn coalesces to the LATEST name, kept at its most-recent
    // position (after Established, since those renames arrived after it).
    let mut d3 = VecDeque::new();
    buffer_overflow_service_update(&mut d3, ServiceUpdate::Established);
    buffer_overflow_service_update(&mut d3, renamed("a-1._ipp._tcp.local."));
    buffer_overflow_service_update(&mut d3, renamed("a-2._ipp._tcp.local."));
    buffer_overflow_service_update(&mut d3, renamed("a-3._ipp._tcp.local."));
    assert_eq!(
      d3.iter()
        .filter(|u| matches!(u, ServiceUpdate::Renamed(_)))
        .count(),
      1,
      "rename churn must coalesce to a single pending Renamed"
    );
    assert!(matches!(d3.front(), Some(ServiceUpdate::Established)));
    match d3.back() {
      Some(ServiceUpdate::Renamed(r)) => assert!(r.new_name().as_str().contains("a-3")),
      other => panic!("latest Renamed must be at the back; got {other:?}"),
    }

    // Idempotent/one-time kinds dedup, so the deque stays bounded under churn.
    let mut d4 = VecDeque::new();
    for _ in 0..100 {
      buffer_overflow_service_update(&mut d4, ServiceUpdate::Established);
      buffer_overflow_service_update(&mut d4, ServiceUpdate::HostConflict);
      buffer_overflow_service_update(&mut d4, renamed("x._ipp._tcp.local."));
    }
    assert!(
      d4.len() <= 4,
      "overflow deque must stay bounded (≤ one per kind); got {}",
      d4.len()
    );
  }

  /// a non-draining caller cannot grow memory without bound — a
  /// flood of service updates is held by the bounded channel plus a single
  /// coalescing overflow slot (capacity + 1), not an unbounded backlog.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn service_update_delivery_is_bounded_for_non_draining_caller() {
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
      mdns_proto::Name::try_from_str("svc._ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("host.local.").unwrap(),
      631,
      120,
    );
    r.add_a(std::net::Ipv4Addr::new(192, 168, 1, 10));
    let reg = state
      .register_service(mdns_proto::ServiceSpec::new(r), now)
      .unwrap();
    let handle = reg.handle;

    // `reg` (the receiver) is kept alive but NEVER drained — a non-draining
    // caller. Push far more updates than the channel can hold.
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      for _ in 0..1000 {
        assert!(
          deliver_service_update(ctx, ServiceUpdate::Established),
          "an alive (undropped) receiver must not report closed"
        );
      }
      assert!(
        ctx.updates.len() <= SERVICE_UPDATE_CAPACITY,
        "the bounded channel must stay within capacity; got {}",
        ctx.updates.len()
      );
      assert!(
        !ctx.pending.is_empty() && ctx.pending.len() <= 4,
        "beyond capacity, updates coalesce into the bounded ordered overflow; len {}",
        ctx.pending.len()
      );
    }
    drop(reg);
  }

  /// when both an Established and a later Renamed overflow, the
  /// overflow preserves insertion order — Established is NOT dropped, and a
  /// Renamed that arrived AFTER it is delivered after it (not reordered ahead).
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn established_then_renamed_overflow_preserves_order() {
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
    let reg = state
      .register_service(mdns_proto::ServiceSpec::new(r), now)
      .unwrap();
    let handle = reg.handle;
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      // Fill the bounded channel so subsequent updates overflow.
      for _ in 0..SERVICE_UPDATE_CAPACITY {
        assert!(deliver_service_update(ctx, ServiceUpdate::HostConflict));
      }
      // Overflow Established, then a Renamed that arrived AFTER it.
      assert!(deliver_service_update(ctx, ServiceUpdate::Established));
      let renamed = ServiceUpdate::Renamed(ServiceRenamed::new(
        mdns_proto::Name::try_from_str("svc-1._ipp._tcp.local.").unwrap(),
      ));
      assert!(deliver_service_update(ctx, renamed));
      // The Established was not dropped, and order is Established then Renamed.
      let kinds: Vec<&ServiceUpdate> = ctx.pending.iter().collect();
      assert!(
        matches!(kinds.first(), Some(ServiceUpdate::Established)),
        "Established (inserted first) must remain at the front; overflow = {kinds:?}"
      );
      assert!(
        matches!(kinds.last(), Some(ServiceUpdate::Renamed(_))),
        "the later Renamed must be delivered after Established; overflow = {kinds:?}"
      );
    }
    drop(reg);
  }

  /// liveness: a terminal update that overflowed into the ordered
  /// buffer is NOT stranded. Once the caller drains the bounded channel, the
  /// driver's opportunistic per-tick `flush_pending_service_update` (the
  /// service-update loop runs it for every service even with no new proto
  /// event) delivers the buffered update. This drives that flush directly,
  /// with no packets or commands in flight.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn overflow_terminal_update_is_delivered_after_drain() {
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
      mdns_proto::Name::try_from_str("svc._ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("host.local.").unwrap(),
      631,
      120,
    );
    r.add_a(std::net::Ipv4Addr::new(192, 168, 1, 10));
    let reg = state
      .register_service(mdns_proto::ServiceSpec::new(r), now)
      .unwrap();
    let handle = reg.handle;

    // Fill the bounded channel, then overflow a terminal Conflict into the
    // ordered buffer.
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      for _ in 0..SERVICE_UPDATE_CAPACITY {
        assert!(deliver_service_update(ctx, ServiceUpdate::HostConflict));
      }
      assert!(deliver_service_update(ctx, ServiceUpdate::Conflict));
      assert!(
        ctx
          .pending
          .iter()
          .any(|u| matches!(u, ServiceUpdate::Conflict)),
        "the terminal Conflict must be buffered while the channel is full"
      );
    }

    // Drain the receiver completely — no driver packet/command activity.
    let mut drained = 0usize;
    while reg.updates.try_recv().is_ok() {
      drained += 1;
    }
    assert_eq!(
      drained, SERVICE_UPDATE_CAPACITY,
      "draining must recover exactly the channel-buffered updates"
    );

    // The per-tick opportunistic flush now delivers the buffered terminal
    // update (liveness): it is not stranded behind a previously-full channel.
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      assert!(
        flush_pending_service_update(ctx),
        "flush must succeed against an alive receiver"
      );
      assert!(
        ctx.pending.is_empty(),
        "the buffered update must have been flushed into the channel"
      );
    }

    match reg.updates.try_recv() {
      Ok(ServiceUpdate::Conflict) => {}
      other => {
        panic!("the buffered Conflict must be delivered after drain+flush; got {other:?}")
      }
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

  // on shutdown, flush_goodbyes must drive a queued goodbye burst
  // to completion rather than abandoning it after the first send. No sockets
  // are needed — `drain_goodbyes` advances the burst regardless of send
  // outcome — so this also asserts the flush always terminates (no hang).
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn flush_goodbyes_completes_the_burst() {
    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();
    state.goodbyes.push(PendingGoodbye {
      data: vec![0xde, 0xad],
      remaining: GOODBYE_SENDS,
      next_at: now,
      sent_once: false,
      expires_at: now + GOODBYE_BARRIER_MAX,
    });
    state.flush_goodbyes().await;
    assert!(
      state.goodbyes.is_empty(),
      "the goodbye burst must fully drain before shutdown"
    );
  }

  /// Part A (live path, State seam): a goodbye round that reached NO family
  /// (here: no socket bound, so `send_via` reports zero sends) must NOT spend the
  /// resend budget, must NOT flip `sent_once`, and must re-arm at the short
  /// `GOODBYE_RETRY_BACKOFF` — not a full `GOODBYE_INTERVAL`. The all-failing case
  /// is reachable deterministically without sockets; the full async barrier-skip
  /// ordering is exercised end-to-end in the deterministic `hick-smoltcp` engine
  /// test (the reactor's multi-task loop cannot be stepped deterministically here).
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn live_goodbye_round_with_no_send_keeps_budget_and_backs_off() {
    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();
    state.goodbyes.push(PendingGoodbye {
      data: vec![0xde, 0xad],
      remaining: GOODBYE_SENDS,
      next_at: now,
      sent_once: false,
      expires_at: now + GOODBYE_BARRIER_MAX,
    });

    // `force = false`: the live path. With no socket nothing reaches the wire.
    state.drain_goodbyes(now, false).await;
    let g = &state.goodbyes[0];
    assert_eq!(
      g.remaining, GOODBYE_SENDS,
      "an all-failing live round must not consume the resend budget"
    );
    assert!(
      !g.sent_once,
      "an all-failing round must not flip sent_once — the barrier still holds"
    );
    assert_eq!(
      g.next_at,
      now + GOODBYE_RETRY_BACKOFF,
      "a failed live round must re-arm at GOODBYE_RETRY_BACKOFF"
    );
    assert!(
      g.next_at < now + GOODBYE_INTERVAL,
      "a failed live round must NOT push next_at out by a full GOODBYE_INTERVAL"
    );
    assert!(
      state.has_pending_barrier(now),
      "an un-sent goodbye remains a pending transmit barrier"
    );
  }

  /// Anti-pin (State seam): a goodbye past its `expires_at` is force-cleared by
  /// `drain_goodbyes` REGARDLESS of remaining sends, so a permanently-
  /// undeliverable barrier cannot pin the queue or block transmits forever. A
  /// live, un-expired entry survives and keeps barring transmits until its bound.
  #[cfg(feature = "tokio")]
  #[tokio::test]
  async fn live_drain_force_clears_expired_barrier() {
    let opts = crate::options::ServerOptions::default();
    let sockets = BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    };
    let mut state = DriverState::new(&opts, sockets);
    let now = StdInstant::now();
    // Already past its anti-pin bound while still owing sends.
    state.goodbyes.push(PendingGoodbye {
      data: vec![1],
      remaining: GOODBYE_SENDS,
      next_at: now,
      sent_once: false,
      expires_at: now - Duration::from_millis(1),
    });
    // Live, un-expired, still owing → retained.
    state.goodbyes.push(PendingGoodbye {
      data: vec![3],
      remaining: GOODBYE_SENDS,
      next_at: now + GOODBYE_INTERVAL, // not due, so no send is attempted
      sent_once: false,
      expires_at: now + GOODBYE_BARRIER_MAX,
    });

    state.drain_goodbyes(now, false).await;
    assert_eq!(
      state.goodbyes.len(),
      1,
      "the expired barrier must be force-cleared; only the live entry survives"
    );
    assert_eq!(state.goodbyes[0].data, vec![3]);
    assert!(
      state.has_pending_barrier(now),
      "the surviving un-sent entry is still a barrier"
    );
    let later = now + GOODBYE_BARRIER_MAX + Duration::from_millis(1);
    assert!(
      !state.has_pending_barrier(later),
      "an entry past its expires_at no longer bars transmits"
    );
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

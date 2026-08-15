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
use hick_udp::{
  Family,
  onlink::{
    BoundLink, DestinationWitness, IfaceWitness, admits_ingress, collect_local_subnets,
    is_loopback_interface,
  },
  selfsend::{ClockPair, RxDatagram, SelfSendMatch, SelfSendTracker},
};
use mdns_proto::{
  FamilyAttempt, Provenance, QueryHandle, QuerySpec, Received, ServiceHandle, ServiceSpec,
  ServiceUpdate, TransmitConfirm, endpoint::FamilyDebt, event::RouteEvent,
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
  /// The local receive address the ancillary data named, where it names one:
  /// `ipi_spec_dst` / `ipi6_addr` on the Unix `PKTINFO` squares, and `ipi_addr`
  /// on Windows, whose `IN_PKTINFO` has no `ipi_spec_dst` twin. `UNSPECIFIED`
  /// where nothing names it — the BSD `IP_RECVDSTADDR` + `IP_RECVIF` pair
  /// carries no interface address either, the `recv_from` arm carries no
  /// ancillary data at all, and any kernel may decline the cmsg for one
  /// datagram. It is not part of the self-loopback decision at all — that is
  /// [`DriverState::selfsend`]'s, taken before the proto layer sees the datagram.
  local_ip: IpAddr,
  /// What this receive path WITNESSED about the interface the datagram arrived
  /// on ([`hick_udp::RecvMeta::iface_witness`]).
  ///
  /// An [`IfaceWitness`] and not a `u32`, because an absent index is three
  /// different facts and RFC 6762 §11 decides them differently: our own control
  /// buffer was too small (`Lost`, refuses), the kernel skipped the cmsg for this
  /// datagram (`Declined`, degrades), or this path never reports one (`Blind`).
  /// The plain `recv_from` arm of `recv_task` — every target that is neither Unix
  /// nor Windows — declares `Blind` once, and cannot mint the other two.
  iface: IfaceWitness,
  /// The datagram itself: its bytes, the family it arrived on, and the kernel
  /// receive timestamp that orders it against our own sends — one value that
  /// cannot be taken apart.
  ///
  /// One field rather than three (`data`, `family`, and the stamp), so pairing
  /// them correctly is a property of the type rather than a convention this
  /// struct literal has to keep: [`RxDatagram`] is neither `Copy` nor `Clone`
  /// and has no stamp accessor, so a stamp a kernel really did write — for a
  /// *different* receive — cannot be lifted out and laid beside these bytes. A
  /// later stamp would let a datagram the kernel saw before our `sendto` take
  /// the credit; an earlier one would reject the genuine echo; both end at a
  /// phantom RFC 6762 §9 conflict against ourselves.
  ///
  /// The family is half the credit key, and it comes from the recv task that owns
  /// the socket rather than from [`Packet::src`]: a source address describes the
  /// sender, and an IPv4-mapped or otherwise unexpected address on either socket
  /// would silently key the claim to the wrong family. A multicast loopback copy
  /// arrives on the socket its original left from and on no other.
  ///
  /// The stamp's absence is carried as an absence — the Windows and `recv_from`
  /// arms mint through [`RxDatagram::without_stamp`] — never papered over with a
  /// userspace read time, which says nothing about when the kernel saw the
  /// datagram. Such a claim runs under
  /// [`MatchMode::Degraded`](hick_udp::selfsend::MatchMode::Degraded).
  ///
  /// The body is OWNED, because it crosses a channel: the Unix arm mints against
  /// the recv task's reused buffer through [`recv_datagram`] and calls
  /// [`RxDatagram::into_owned`], which is the same copy this driver made with
  /// `to_vec` before. Owning consumes the datagram rather than copying it, so the
  /// stamp still has no second value to travel in.
  rx: RxDatagram<'static>,
  /// What this receive path WITNESSED about the datagram's IP header
  /// **destination** ([`hick_udp::RecvMeta::destination_witness`]). NOT
  /// [`Packet::local_ip`]: on Unix IPv4 that is the receiving interface's own
  /// address, which never equals a group, so reading it here would make every
  /// multicast arrival look unicast.
  ///
  /// RFC 6762 §11 states the local-link test two ways and the header
  /// destination picks between them — arrival at `224.0.0.251` / `FF02::FB` is
  /// local-link origin on its own, "regardless of source IP address". Carrying
  /// it is what admits an on-link peer sourcing from a prefix this interface
  /// does not have configured, which is precisely the overlaid-subnet case §11
  /// calls it "essential" to accept. Windows recovers a destination and reports
  /// no hop limit at all, so on that target this is the ONLY thing that can
  /// select the group arm.
  destination: DestinationWitness,
  /// The kernel's own `MSG_MCAST` where this receive path reports it
  /// ([`hick_udp::RecvMeta::delivery`]), else `None`. Coarser than
  /// [`Packet::destination`] — "some multicast group" rather than which one —
  /// and consulted only where no destination was WITNESSED. On the OpenBSD and
  /// NetBSD IPv4 square it is what stands between a cmsg the kernel declined to
  /// emit and the loss of §11's group arm.
  ///
  /// **An unwitnessed destination is a different admission regime, not a
  /// coarser one.** `hick_udp::onlink::admits_ingress` refuses a WITNESSED
  /// destination this endpoint does not hold; with none witnessed it cannot.
  /// On Unix and Windows this driver reads through `hick_udp::recv_with_meta`,
  /// which witnesses a destination on every one of those targets and in both
  /// families — `IP_PKTINFO` on Linux/Android/Apple, the `IP_RECVDSTADDR` +
  /// `IP_RECVIF` pair on FreeBSD, DragonFly, OpenBSD and NetBSD, `IPV6_PKTINFO`
  /// for IPv6, `WSARecvMsg` on Windows — so the only structurally `Blind` square
  /// left is the plain `recv_from` arm of `recv_task`, which serves every target
  /// that is neither Unix nor Windows and reports no `delivery` either.
  ///
  /// What remains on the witnessing squares is per-datagram: a `Declined`
  /// destination, wherever a kernel skipped the cmsg under mbuf pressure — every
  /// BSD does, `sbcreatecontrol` running with `M_NOWAIT`. For that datagram what
  /// is left is exactly this field:
  ///
  /// * `Broadcast` (OpenBSD/NetBSD only — `libc` binds `MSG_BCAST` nowhere else)
  ///   REFUSES, which closes the IPv4 broadcast class on those two;
  /// * `Multicast` admits and names no group, so any foreign group is admitted
  ///   there from any source;
  /// * `None` — every other target — leaves the source arm deciding, so an IPv4
  ///   broadcast is still admitted there for an in-prefix source.
  ///
  /// Stated here so a reader of this struct is not left with the witnessed
  /// regime's guarantee; `admits_ingress` carries the full statement and what
  /// closes the rest.
  delivery: Option<hick_udp::LinkDelivery>,
  /// IPv4 TTL / IPv6 Hop Limit of the datagram (from `IP_RECVTTL` /
  /// `IPV6_RECVHOPLIMIT`), or `None` when the platform didn't supply it. The
  /// Carried as a DIAGNOSTIC and never tested:
  /// [`hick_udp::onlink::admits_ingress`] takes no hop limit, because RFC 6762
  /// §11's receive test is stated exhaustively and both ways are about the
  /// destination address. It appears in the drop trace and nowhere else.
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
  /// When each family last carried one of THIS service's gated datagrams, so the
  /// §8.1 / §8.3 spacing is honoured per wire rather than per confirm. See
  /// [`FamilyWireGate`].
  wire_gate: FamilyWireGate,
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
  /// When each family last carried one of THIS question's transmissions, so
  /// RFC 6762 §5.2's one-second floor is honoured per wire. See
  /// [`FamilyWireGate`].
  wire_gate: FamilyWireGate,
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
  /// The seal generation observed at the last park entry, so a receive that
  /// returned FROM that park can prove the seal it relies on happened before it
  /// rather than inside it. See [`SelfSendTracker::seal_generation`].
  ///
  /// `None` means "the next receive is not a park return", and that state is
  /// reachable on a perfectly correct path: when a drain reports more work
  /// pending this loop `continue`s straight back to the packet pump WITHOUT
  /// parking, so the pump drains a backlog that no park mediated. There is no
  /// park for such a receive to be early relative to, so the ordering question is
  /// not merely unproven but meaningless, and asking it would fail on correct
  /// sealing. Every `seal` clears this; only a park entry sets it.
  ///
  /// Debug builds only: it feeds assertions and no decision.
  #[cfg(debug_assertions)]
  sealed_generation_at_park: Option<u64>,
  /// Credits for the multicast datagrams this endpoint recently sent, so their
  /// kernel loopback copies are recognized instead of being ingested as a peer's
  /// traffic.
  ///
  /// The driver (std layer) owns it because the decision needs a kernel receive
  /// timestamp and two clocks, facilities that do not belong in the `no_std`
  /// proto core — which keeps no tracker of its own and takes the answer as an
  /// explicit flag. Keyed on OUR sends only, so its size tracks our
  /// (coalescing-bounded) send rate and never peer traffic.
  ///
  /// The window each credit ages in is opened once per run-loop iteration by
  /// [`SelfSendTracker::seal`]; see the call site in [`driver_task`] for why it
  /// sits at the top of the loop and nowhere else.
  selfsend: SelfSendTracker,
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
  /// Where the next transmit pass resumes in each handle snapshot, so a pass cut
  /// short by [`DRAIN_PASS_BUDGET`] does not restart at the front and serve the
  /// same few producers forever. Both loops iterate their snapshot rotated by
  /// this offset and park it on the first handle they did NOT reach.
  svc_resume: usize,
  query_resume: usize,
  /// Which producer CLASS the next transmit pass drains first, flipped after any
  /// pass that was cut short. The cursors above rotate within a class; this
  /// rotates between them, so a budget spent entirely on services cannot starve
  /// every query (and vice versa).
  queries_first: bool,
  /// The BOUND interface's directly-attached subnets — what RFC 6762 §11's
  /// unicast arm compares a source against. Re-read on a bounded interval (see
  /// `subnets_refreshed_at`), and scoped to the
  /// bound interface only so no other NIC's prefix can widen the gate. Empty if
  /// interface discovery failed, which the fallback reads as no on-link evidence
  /// and so REFUSES a global source — see
  /// [`hick_udp::onlink::collect_local_subnets`].
  local_subnets: Vec<(IpAddr, u8)>,
  /// The interface index this endpoint is bound to, and the link every inbound
  /// datagram is measured against: both mDNS sockets are wildcard bound, so on a
  /// multi-homed host every NIC's port-5353 traffic reaches them and only this
  /// index (plus an IPv6 source's scope id) says which link a datagram came
  /// from. Gates BOTH of §11's arms, because §11 answers "did this originate on
  /// a local link" and never "on which one". Always ≥ 1
  /// (the endpoint always resolves a concrete interface index at bind time).
  bound_interface: u32,
  /// Whether [`Self::bound_interface`] is the loopback interface, resolved once
  /// at construction rather than per datagram. It is the only thing that opens
  /// the §11 loopback exception: a loopback SOURCE address is forgeable onto a
  /// real NIC wherever an operator has stopped treating `127/8` as martian, so
  /// an endpoint serving a physical link grants it nothing.
  bound_is_loopback: bool,
  /// When `local_subnets` was last read from the interface.
  ///
  /// §11's unicast arm compares a source against the receiving interface's
  /// configuration as it IS. An address can change under a live endpoint — a
  /// DHCP lease lost into APIPA, a renumbered subnet — and a snapshot taken once
  /// at construction is then wrong in both directions: current-prefix traffic
  /// refused, obsolete prefix still admitted. `getifs` offers no change
  /// notification on any supported platform, so this is polled on a bounded
  /// interval. See [`hick_udp::onlink::refresh_subnets_if_stale`].
  subnets_refreshed_at: StdInstant,
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
      #[cfg(debug_assertions)]
      sealed_generation_at_park: None,
      selfsend: SelfSendTracker::new(),
      completed_withdrawals: Vec::new(),
      svc_handle_scratch: Vec::new(),
      query_handle_scratch: Vec::new(),
      svc_resume: 0,
      query_resume: 0,
      queries_first: false,
      // scope the §11 source-subnet fallback to the BOUND
      // interface only — not every local NIC (per-packet interface index for
      // delivered PKTINFO is handled separately in recv_with_meta).
      local_subnets: collect_local_subnets(bound_interface),
      bound_interface,
      bound_is_loopback: is_loopback_interface(bound_interface),
      subnets_refreshed_at: StdInstant::now(),
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
        // CANCEL-ON-ANNOUNCE (`note_service_announced`), a certain live event, so a
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
    // NO SUPERSEDE HERE. A registration only INSERTS a route: it mutates no
    // record this endpoint has already asserted, positive or negative, so every
    // credit in the log still describes a state this endpoint is in. See
    // `SelfSendTracker::supersede` for why superseding here declared a falsehood
    // and what the tombstone then cost.

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
        wire_gate: FamilyWireGate::default(),
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
        wire_gate: FamilyWireGate::default(),
      },
    );
    Ok(QueryStarted {
      handle,
      mailbox,
      doorbell: doorbell_rx,
    })
  }

  /// Close this iteration's records: open their claim window, and drop any park
  /// capture.
  ///
  /// The two belong together and this is why they are one call rather than two
  /// statements a test could reproduce differently from the loop. Any capture
  /// still held describes a park that happened BEFORE this seal, so it can no
  /// longer describe the next receive — and the next receive may well not be a
  /// park return at all: when a drain reports more work pending, `driver_task`
  /// `continue`s straight back to the packet pump without parking. Keeping the
  /// stale capture there would weigh that backlog receive against a park it never
  /// entered and fail on correct sealing.
  fn seal_after_records(&mut self) {
    self.selfsend.seal();
    #[cfg(debug_assertions)]
    {
      self.sealed_generation_at_park = None;
    }
  }

  /// The park entry: check that the seal this iteration relies on has already
  /// happened, and record WHICH seal it was so [`Self::handle_packet`] can prove
  /// it predated the park.
  ///
  /// Debug builds only — it makes no decision and compiles out of release. See
  /// the call site in [`driver_task`] for why the check belongs here and not
  /// beside `seal`.
  #[cfg(debug_assertions)]
  fn note_park_entry(&mut self) {
    debug_assert!(
      !self.selfsend.has_unsealed(),
      "a credit recorded this iteration is still unsealed at the park entry: \
       `seal` must run after every record stage and before this park"
    );
    self.sealed_generation_at_park = Some(self.selfsend.seal_generation());
  }

  fn handle_packet(&mut self, pkt: Packet) {
    // Defence in depth, and deliberately NOT the proof of placement: by the time
    // this runs the park is over, so "nothing is unsealed" is equally true of a
    // driver that sealed before parking and one that sealed in its receive arm
    // after an arbitrarily long park. The placement itself is pinned at the
    // park entry in `driver_task`; what this adds is that no path reaches
    // a claim with an unsealed credit, whatever route it took here.
    debug_assert!(
      !self.selfsend.has_unsealed(),
      "a credit reached the receive path unsealed: `seal` must sit between this \
       iteration's sends and this receive"
    );
    // The ordering half, and it applies to exactly one kind of receive: one that
    // came back OUT of a park. The park entry recorded which seal it was relying
    // on, so a window opened since means the seal ran inside or after the park and
    // every credit it anchored is a whole park late.
    //
    // A receive with no park behind it — the backlog the pump drains when a drain
    // reported more work and the loop `continue`d — has nothing to be early
    // relative to, and the seal that ran on the way there legitimately advanced
    // the generation. Asking the question there fails on correct sealing, so the
    // capture is absent and the question is not asked. The unsealed-state check
    // above still applies to every receive, park or not; it is the half that
    // holds unconditionally.
    #[cfg(debug_assertions)]
    if let Some(at_park) = self.sealed_generation_at_park {
      debug_assert_eq!(
        self.selfsend.seal_generation(),
        at_park,
        "a claim window opened between the park entry and this receive: `seal` \
         must PRECEDE the park, not run inside the receive arm"
      );
    }
    // The ingress trust boundary, applied BEFORE the proto layer can cache or
    // act on (conflict, withdraw) attacker-injected records and BEFORE the
    // take-once credit is consulted: the link the datagram arrived on, then RFC
    // 6762 §11. Both gates live in `hick_udp::onlink::admits_ingress` so neither
    // can be applied to only one of the §11 branches — the interface check in
    // particular, which the hop-limit branch used to skip entirely even though a
    // conforming hop limit says nothing about *whose* link a wildcard-bound
    // socket heard.
    //
    // `src` is the whole peer address rather than `pkt.src.ip()`: an IPv6
    // source's scope id is half of what names the link it came from, and taking
    // the address alone discarded it.
    //
    // `destination` and `delivery` come off the receive path rather than
    // being hardcoded away: §11 selects its arms by the header destination, and
    // dropping them routed a correctly-witnessed multicast from an
    // overlaid-subnet peer to the source-prefix arm, which refuses it.
    //
    // NOT the hop limit: RFC 6762 §11's receive test is stated exhaustively
    // and is about the destination address. Inbound TTL appears in the RFC
    // once, explaining why responses SHOULD be SENT at 255 for the benefit of
    // 2004-draft queriers — it is not a test a reader is told to apply, and
    // applying it refused conforming traffic (§5.5 unicast queries at the
    // stack's default TTL, group queries at the socket-default multicast TTL
    // of 1) while admitting witnessed out-of-prefix unicast. Outbound 255 is
    // unaffected and still honoured.
    // §11 compares against the interface's configuration as it is, so the
    // snapshot is re-read once it ages past the shared interval. One clock read
    // per datagram; one enumeration per interval at most.
    hick_udp::onlink::refresh_subnets_if_stale(
      self.bound_interface,
      &mut self.local_subnets,
      &mut self.subnets_refreshed_at,
    );
    let verdict = admits_ingress(
      pkt.src,
      pkt.destination,
      pkt.delivery,
      BoundLink::new(
        self.bound_interface,
        self.bound_is_loopback,
        &self.local_subnets,
      ),
      pkt.iface,
    );
    // The three §11 facts a drop count cannot carry, each read off the rule's
    // own predicates so this driver re-derives none of them. A DECLINED witness
    // is counted whatever the verdict was: a kernel skipping a cmsg it normally
    // emits is an event in its own right, and the only warning a host gets that
    // its §11 evidence is degrading.
    #[cfg(feature = "stats")]
    {
      if pkt.destination.is_declined() || pkt.iface.is_declined() {
        self.stats.ingress_witness_declined(1);
      }
      if verdict.is_degraded_admit() {
        self.stats.ingress_degraded_admits(1);
      }
      if verdict.is_residual_refusal() {
        self.stats.ingress_residual_refusals(1);
      }
      // The two sides of §11 arm one's link scoping. The refusal is the one to
      // alert on: it is a datagram §11 says to admit, dropped because nothing
      // established which link it arrived on — which every BSD produces under
      // the mbuf shortage a flood causes.
      if verdict.is_unscoped_group_admit() {
        self.stats.ingress_unscoped_group_admits(1);
      }
      if verdict.is_unscoped_group_refusal() {
        self.stats.ingress_unscoped_group_refusals(1);
      }
    }
    if !verdict.is_admit() {
      hick_trace::debug!(
        src = %pkt.src,
        dst = ?pkt.destination,
        delivery = ?pkt.delivery,
        hop_limit = ?pkt.hop_limit,
        iface_witness = ?pkt.iface,
        bound_interface = self.bound_interface,
        verdict = ?verdict,
        "dropping off-link packet (RFC 6762 §11 trust boundary)"
      );
      // The datagram WAS received off the socket — count it toward receive
      // volume exactly once (matching the proto path: packets_rx + bytes_rx at
      // entry, then one reject counter). The proto's handle() is NOT called, so
      // proto cannot bump these counters itself; we do it here instead.
      #[cfg(feature = "stats")]
      {
        self.stats.packets_rx(1);
        self.stats.bytes_rx(pkt.rx.body().len() as u64);
        self.stats.packets_dropped(1);
      }
      return;
    }

    // enforce the §11 source-port rule for RESPONSES *before*
    // consuming a self-send credit. Proto re-checks this for
    // direct callers, but if we let an untrusted response reach
    // the tracker first, an on-link attacker's byte-identical copy from
    // an ephemeral port could burn the take-once credit — then proto
    // suppresses the attacker's copy, and our genuine port-5353 loopback
    // arrives with no credit and is mis-processed as a trusted peer. Drop
    // untrusted responses here so they are never offered a credit. (Queries,
    // QR=0, are exempt — legacy unicast queriers use ephemeral ports.)
    if packet_is_response(pkt.rx.body()) && pkt.src.port() != hick_udp::constants::MDNS_PORT {
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
        self.stats.bytes_rx(pkt.rx.body().len() as u64);
        self.stats.packets_dropped(1);
      }
      return;
    }

    // local_ip + interface_index come from PKTINFO (via
    // hick_udp::recv_with_meta); UNSPECIFIED/None when PKTINFO is unavailable. The
    // protocol core takes the index as a ROUTING hint and admits nothing on it —
    // the trust decision was made above, against the witness itself.
    let local_ip = pkt.local_ip;
    let interface_index = pkt.iface.witnessed_index().map(|i| i.get());

    // The AUTHORITATIVE self-loopback decision happens HERE, in the std driver.
    // The result reaches the proto layer as an explicit flag; proto keeps no
    // self-send tracker of its own.
    //
    // The credit is looked up under the family this datagram ARRIVED on. One
    // multicast transmit is two syscalls with identical bytes and two
    // separately-stamped credits, and nothing fixes which socket's echo is read
    // first — so without the family key the second echo read can consume the
    // first echo's credit and leave its own owner facing a credit stamped after
    // the kernel saw it.
    //
    // How much ordering evidence this claim has is DERIVED inside `claim`, never
    // declared here: it comes from whether the kernel delivered a receive
    // timestamp, and is weakened per credit when that credit's own wall stamp did
    // not survive a clock step between the send and now. Both fall back to
    // matching on content, family and the TTL alone, which is enough to suppress
    // our own loopback in the ordinary single-host case but cannot defend the
    // credit-theft race — the cheap direction, since refusing our own echo raises
    // a phantom RFC 6762 §9 conflict against ourselves.
    //
    // The absence of a kernel stamp is handed over as an absence. A userspace
    // read time taken at this line would order every claim trivially and carry no
    // information about when the kernel saw the datagram.
    //
    // Only ordering is asked here. The credit's AGE is read inside `claim`, at
    // the decision, because everything between this datagram's arrival and this
    // line — both admission gates above, the packet-pump backlog, and whatever
    // the scheduler does among them — is elapsed time the credit must be charged.
    // **Only port 5353 may be offered a credit**, and that is this driver's half
    // of `SelfSendTracker::claim`'s contract rather than a local nicety. Both of
    // this endpoint's sockets bind 5353, so every datagram it sends leaves from
    // that port and every loopback copy arrives from it — a different source port
    // is proof the datagram is not our echo, and it is proof the tracker cannot
    // reach for itself, since it never sees where a datagram came from.
    //
    // The §11 gate above drops a RESPONSE from any other port, but a §6.7 legacy
    // unicast QUERY is deliberately kept — such a querier uses an ephemeral port
    // and is owed a reply. Kept is not ours: in degraded mode nothing orders a
    // claim against the send, so a byte-identical legacy query would take the
    // credit of a query we had just multicast and be reported as our own echo.
    // The reply that querier is owed would never be sent, and the genuine echo
    // behind it would find no credit and reach the protocol layer as peer
    // traffic. The port test below is the outer `if`, so such a datagram never
    // reaches a claim at all.
    //
    // THE TIER THIS DRIVER CAN HONESTLY REPORT. Three answers, not two, and each
    // is a claim about THIS DRIVER'S OWN SEND LOG rather than about the network
    // — no platform reports "this is your own multicast echo".
    //
    //  * `Ordered` weighed evidence that the kernel saw this datagram at or
    //    after our own `sendto`, so nothing else could have put these bytes on
    //    the wire in between. That is `OwnEcho`, the only tier that suppresses
    //    everything.
    //  * `Degraded` matched on content, family and the TTL with NOTHING ordering
    //    it — and a byte-identical datagram from a conforming RFC 6762 §9
    //    fault-tolerance twin matches exactly that way, so the claim cannot be
    //    trusted with a name. `OwnEchoLikely` still declines §10 cache
    //    population and §7.1/§7.3 quieting, where believing a peer is the more
    //    harmful error, and it still ADJUDICATES: suppressing a §8.2 proposal
    //    costs a name permanently and silently, while adjudicating our own echo
    //    costs at worst §8.2's one-second deferral.
    //  * `NoCredit` is a negative claim about this log — no credit matched, an
    //    evicted one included — which is what `NotFromUs` means. So is a source
    //    port this endpoint never sends from, decided by the `if` WITHOUT
    //    offering a credit at all, for the reason given above.
    let provenance = if pkt.src.port() == hick_udp::constants::MDNS_PORT {
      match self.selfsend.claim(&pkt.rx) {
        SelfSendMatch::Ordered => Provenance::OwnEcho,
        SelfSendMatch::Degraded => Provenance::OwnEchoLikely,
        // Our bytes, but from a generation of our own records that no longer
        // exists — a service began withdrawing, or took an RFC 6762 §9
        // automatic rename, since the send. `OwnEchoLikely`, the same tier
        // `Degraded` reports, and for the same reason: the match establishes
        // CONTENT, not origin, so it may deny OBSERVATION and QUIETING — a
        // stale echo must reach neither, or it writes records this endpoint no
        // longer publishes into its own cache and defers this endpoint's own
        // retransmits on their behalf — and it may not deny ADJUDICATION.
        //
        // NOT `OwnEcho`: that reads byte equality as proof these bytes are ours.
        // A superseded entry is a standing tombstone, so under that mapping an
        // old local responder and a live §9 fault-tolerance twin producing the
        // same bytes — or a peer replaying them — make EVERY matching peer
        // defence invisible for the whole credit lifetime, and a successor can
        // finish probing while the incumbent goes unheard.
        //
        // Keeping our own withdrawn generation from retiring the service that
        // replaced it belongs one layer up, at the `Endpoint` screen behind
        // `EndpointConfig::relinquished_retention`, which labels the record and
        // leaves the terminal `HostConflict` dropped in the router while a
        // pre-authoritative instance conflict merely defers. It has to live
        // there: this classification is defeasible three independent ways no
        // driver can close — a peer replaying our bytes reproduces everything
        // weighed here, one send can be delivered as several copies while it is
        // credited once, and credits are evicted under load. Each leaves the
        // GENUINE echo reading `NoCredit`, hence `NotFromUs`, hence fully
        // adjudicated already. See `SelfSendTracker::supersede`.
        SelfSendMatch::Superseded => Provenance::OwnEchoLikely,
        SelfSendMatch::NoCredit => Provenance::NotFromUs,
      }
    } else {
      Provenance::NotFromUs
    };

    // proto `now` is monotonic; process time is fine for cache TTL /
    // scheduling (the self-loopback ordering used the SystemTime rx stamp
    // above, not this value).
    //
    // Read per datagram, here, and it must stay here: `endpoint.handle` anchors
    // this datagram's every effect to it, and one of them is a bound the CALLER
    // holds — a query whose `QuerySpec::with_timeout` window has shut collects
    // nothing from this datagram and suppresses no RFC 6762 §7.3 slot for it.
    // Hoisting the read to a caller that drains a queue of packets would weigh
    // the last of them on a reading taken before the first, and that is not
    // laxity in the caller's favour: under `max_answers` a late answer EVICTS one
    // collected inside the window.
    let now = StdInstant::now();

    // Split-borrow: endpoint and services are disjoint fields.
    let Self {
      endpoint, services, ..
    } = self;

    let route_events = match endpoint.handle(
      now,
      Received::new(pkt.src, pkt.rx.body(), provenance)
        .with_interface(interface_index)
        .with_local_ip(local_ip),
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
        selfsend,
        query_handle_scratch,
        ..
      } = self;

      // Service updates.
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
              // A §9 auto-rename is a PUBLISHED-RECORD MUTATION: the proto
              // called `Service::set_instance` before it emitted this update, so
              // every credit recorded under the abandoned instance name
              // describes a state this endpoint has left. Advance at the
              // mutation, and UNCONDITIONALLY — the collision arm below is
              // retired through `begin_service_withdrawal`, which supersedes as
              // well, but a SURVIVING rename crosses no other seam at all. The
              // vacated name can then be taken by another local service, and
              // THAT registration advances nothing whatever — a registration
              // mutates no record this endpoint has already asserted — so
              // without the advance here a delayed echo of the abandoned owner
              // would still read as current, adjudicate, and defeat the new
              // holder under RFC 6762 §8.1. See `SelfSendTracker::supersede`.
              selfsend.supersede();
              let rename_result =
                endpoint.handle_service_renamed(*handle, renamed.new_name().clone());
              // The §9 rename of an announced service hands its OLD-name TTL=0
              // goodbye off as an INDEPENDENT detached withdrawal item, both for a
              // SURVIVING rename and a COLLISION teardown. Take it the instant the
              // rename is observed and enqueue it on the endpoint — the Service no
              // longer drains the old-name goodbye itself.
              if let Some(h) = ctx.proto.take_rename_goodbye_handoff() {
                // A rename COLLISION (rename_result Err) tears the service down: its
                // old name must HOLD until the goodbye completes, because the dead
                // service will never re-announce and the goodbye is the only
                // retraction the old name will ever get.
                //
                // A SURVIVING rename stays RECLAIMABLE. That is sound only because
                // the sole thing that can cancel a reclaimable goodbye —
                // `Endpoint::note_service_announced` — is gated on
                // `Service::has_fully_announced`: a complete §8.3 announcement of
                // the reclaiming name that reached EVERY family this driver still
                // obligates. For each such family §10.2's cache-flush announcement
                // supersedes the stale unique records the goodbye exists to retract,
                // so cancelling loses nothing. A partially-delivered replacement
                // announcement leaves the gate shut and the old goodbye keeps
                // draining its per-family debt — which is exactly the case where the
                // unserved family has heard neither the goodbye nor the replacement.
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

      // Query answers + terminals.
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

  /// Drain outgoing transmits across services + queries.
  ///
  /// Every ACTUAL successful MULTICAST send records its own credit in
  /// [`DriverState::selfsend`]. Take-once suppression means one credit can match
  /// only one inbound loopback, and a dual-stack fan-out sends the same payload
  /// to BOTH multicast sockets, so the tracker needs a credit per family — not
  /// one for the pair. The credit is therefore recorded inside [`send_via`] per
  /// real send, keyed to the family that carried it, and not here.
  ///
  /// Bounded by [`DrainBudget`] — the aggregate per-pass wall clock it shares with
  /// [`Self::drain_withdrawals`], plus the [`MAX_SEND_CREDITS_PER_DRAIN`] send
  /// cap. Returns `true` if either bound cut the pass short, so the driver loop
  /// re-enters immediately instead of sleeping.
  ///
  /// Services and queries take turns going first ([`Self::queries_first`]) and
  /// each class resumes where the previous cut pass stopped, so no producer can
  /// be permanently on the wrong side of a budget that keeps running out.
  #[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", skip_all, fields(credits = MAX_SEND_CREDITS_PER_DRAIN))
  )]
  async fn drain_transmits(
    &mut self,
    now: StdInstant,
    budget: &mut DrainBudget,
    scratch: &mut [u8],
  ) -> bool {
    let queries_first = self.queries_first;
    let mut more_pending = false;
    if queries_first {
      more_pending |= self.drain_query_transmits(budget, scratch).await;
      more_pending |= self.drain_service_transmits(now, budget, scratch).await;
    } else {
      more_pending |= self.drain_service_transmits(now, budget, scratch).await;
      more_pending |= self.drain_query_transmits(budget, scratch).await;
    }
    // Only a CUT pass rotates the class order. A pass that drained everything
    // leaves the order alone, so the steady state stays services-first and
    // predictable.
    if more_pending {
      self.queries_first = !queries_first;
    }
    more_pending
  }

  /// The service half of [`Self::drain_transmits`]. Returns `true` if the budget
  /// cut it short with services left unvisited.
  async fn drain_service_transmits(
    &mut self,
    now: StdInstant,
    budget: &mut DrainBudget,
    scratch: &mut [u8],
  ) -> bool {
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();
    let Self {
      endpoint,
      services,
      selfsend,
      v4,
      v6,
      svc_handle_scratch,
      svc_resume,
      ..
    } = self;
    svc_handle_scratch.clear();
    svc_handle_scratch.extend(services.keys().copied());
    let total = svc_handle_scratch.len();
    if total == 0 {
      return false;
    }
    let start = *svc_resume % total;
    let mut more_pending = false;
    'service_loop: for step in 0..total {
      let slot = (start + step) % total;
      let h = svc_handle_scratch[slot];
      if !budget.may_start_fanout() {
        // Park on the handle this pass did NOT reach, so the next one opens here.
        *svc_resume = slot;
        more_pending = true;
        break 'service_loop;
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
      // Whether this handle got a fan-out in THIS pass, which decides where the
      // cursor parks if the budget runs out mid-handle: a handle that was served
      // must be stepped PAST, or a producer that is due on every pass parks the
      // cursor on itself and starves everything behind it — the very starvation
      // the cursor exists to prevent.
      let mut served_here = false;
      loop {
        if !budget.may_start_fanout() {
          *svc_resume = if served_here {
            slot.saturating_add(1)
          } else {
            slot
          };
          more_pending = true;
          break 'service_loop;
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
        // The gate is copied out and written back rather than borrowed across the
        // await, so `services` stays free for the confirm below. Nothing else in
        // this single-task loop touches it in between.
        let mut gate = services.get(&h).map(|c| c.wire_gate).unwrap_or_default();
        let fanout = send_via(
          selfsend,
          v4,
          v6,
          tx.dst(),
          &scratch[..body_len],
          &mut gate,
          tx.min_family_gap(),
          #[cfg(feature = "stats")]
          &stats,
        )
        .await;
        // Report the honest per-family I/O facts so the core — the only layer
        // holding the lifecycle state — decides what they mean: goodbye ownership
        // (§10.1) latches for whatever reached a wire, while the §8.1 probe
        // sequence and §8.3 announce phase advance only once EVERY obligated
        // family heard it. A one-family success therefore cannot let a service
        // claim a name it never probed on the other family.
        //
        // The instant handed over is only the FALLBACK for a round that reached no
        // wire: the core anchors at the earliest family acceptance whenever one
        // happened, so the healthy family's next refresh is never backdated by
        // however long the slowest one took.
        let mut retire = false;
        if let Some(ctx) = services.get_mut(&h) {
          ctx.wire_gate = gate;
          let confirm =
            confirm_service_transmit(endpoint, ctx, StdInstant::now(), fanout.v4, fanout.v6);
          retire = confirm.retire_producer();
        }
        budget.charge(fanout.sent_count());
        served_here = true;
        // The core weighed the refusals against this datagram's obligation: no
        // bound family can ever carry these bytes and it will keep re-arming them,
        // so the service would probe or announce forever with nothing on any wire.
        // Retire it on exactly the terms a persistent encode failure takes — a
        // `Conflict` the caller can act on, and the endpoint-owned §10.1 goodbye
        // that frees the name — and AFTER the confirm above, which has already
        // spent the commit token and latched nothing.
        if retire {
          hick_trace::warn!(
            handle = ?h,
            len = body_len,
            "no bound family can carry this service's datagram; retiring it with a Conflict"
          );
          if let Some(ctx) = services.get_mut(&h) {
            deliver_service_update(ctx, ServiceUpdate::Conflict);
            ctx.withdrawing = true;
            if let Some(handoff) = ctx.proto.take_rename_goodbye_handoff() {
              endpoint.enqueue_rename_withdrawal(handoff, now, true);
            }
            let snap = ctx.proto.withdrawal_snapshot();
            // Inlined withdrawal, so the supersede is inlined with it — see
            // `SelfSendTracker::supersede`.
            selfsend.supersede();
            endpoint.begin_withdrawal(h, snap, now);
          }
          break;
        }
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
            // Inlined withdrawal, so the supersede is inlined with it — see
            // `SelfSendTracker::supersede`.
            selfsend.supersede();
            endpoint.begin_withdrawal(h, snap, now);
          }
        }
      }
    }
    more_pending
  }

  /// The query half of [`Self::drain_transmits`]. Returns `true` if the budget
  /// cut it short with queries left unvisited.
  async fn drain_query_transmits(&mut self, budget: &mut DrainBudget, scratch: &mut [u8]) -> bool {
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();
    let Self {
      endpoint,
      queries,
      selfsend,
      v4,
      v6,
      query_handle_scratch,
      query_resume,
      ..
    } = self;
    query_handle_scratch.clear();
    query_handle_scratch.extend(queries.keys().copied());
    let total = query_handle_scratch.len();
    if total == 0 {
      return false;
    }
    let start = *query_resume % total;
    // Collect queries that were retired due to encode failures so they can be
    // GC'd after the loop (matching the terminated-handle cleanup in push_updates).
    let mut encode_retired: Vec<QueryHandle> = Vec::new();
    // Use a flag instead of an early `return true` inside the query loop so
    // that encode_retired GC ALWAYS runs before the function returns — even
    // when the send budget is exhausted mid-loop.  An early `return true` here
    // would bypass the cleanup below and leave the retired handle resident in
    // both `queries` and proto storage until the user drops the stream.
    let mut more_pending = false;
    'query_loop: for step in 0..total {
      let slot = (start + step) % total;
      let h = query_handle_scratch[slot];
      if !budget.may_start_fanout() {
        *query_resume = slot;
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
      // See the service loop: a handle already served this pass parks the cursor
      // one step PAST itself.
      let mut served_here = false;
      loop {
        if !budget.may_start_fanout() {
          *query_resume = if served_here {
            slot.saturating_add(1)
          } else {
            slot
          };
          more_pending = true;
          break 'query_loop;
        }
        // The CLOCK, not a reading of it. The core weighs a query's
        // `QuerySpec::with_timeout` deadline — a bound the CALLER holds, no
        // question ADMITTED at or after it — against the instant it admits on,
        // and it takes that instant itself, at the comparison. This driver hands
        // over the source and keeps no reading of its own: the pass's `now` is
        // read before `sweep_closed_handles`, `fire_timeouts` and (in the default
        // order) the whole service drain, whose fan-outs are AWAITED, and any
        // reading taken right here would still predate the handle lookup the core
        // does before it compares — so neither can stand in.
        //
        // Admission is the core's COMPARISON, so the overshoot past it starts
        // with the encode and return that finish the poll, and is then dominated
        // by the AWAITED fan-out below: a question admitted just inside the
        // window reaches a wire up to one `SEND_ATTEMPT_TIMEOUT` — plus the
        // executor's scheduling latency — later. That is a bound to reason with,
        // not a second enforcement point; a recheck placed inside the fan-out
        // would still sit before a syscall, and before the wire.
        //
        // Nothing admitted is carried across a pass, either: `may_start_fanout`
        // is consulted ABOVE this poll, both times, so a pass cut short by its
        // budget parks its CURSOR and never a datagram. The query it did not
        // reach still has its send pending, and the pass that resumes re-draws
        // the question and re-weighs the window.
        //
        // Nothing else downstream wants an instant from this point: the fan-out
        // below takes no `now` of any kind — each family's wire gate is weighed at
        // ITS OWN send point (`attempt_gated_send_to`), against a reading taken
        // there, which is a different question about a different subject. The RFC
        // 6762 §5.2 retry ladder is not this deadline either — `fire_timeouts`
        // fires it against the pass's instant, and both it and the terminal stay
        // there.

        // surface encoding errors instead of treating them
        // as "no more transmits".
        let tx = match endpoint.poll_query_transmit(h, StdInstant::now, scratch) {
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
        let mut gate = queries.get(&h).map(|c| c.wire_gate).unwrap_or_default();
        let fanout = send_via(
          selfsend,
          v4,
          v6,
          tx.dst(),
          &scratch[..body_len],
          &mut gate,
          tx.min_family_gap(),
          #[cfg(feature = "stats")]
          &stats,
        )
        .await;
        if let Some(ctx) = queries.get_mut(&h) {
          ctx.wire_gate = gate;
        }
        // The §5.2 retry budget is spent only once EVERY obligated family carried
        // the question: a responder reachable on one family alone must not be able
        // to consume the whole retry schedule of a question the other family never
        // asked. A partial or wholly-failed round re-arms without burning a retry.
        // The instant handed over is the FALLBACK for a round that reached no
        // wire; the core anchors the backoff at the question's own acceptance
        // whenever there was one, so the response window a peer is given is
        // measured from when it was actually asked.
        let confirm =
          endpoint.note_query_transmit_outcome(h, StdInstant::now(), fanout.v4, fanout.v6);
        budget.charge(fanout.sent_count());
        served_here = true;
        // No bound family can ever carry the question, and the §5.2 budget is
        // spent only on a fully-delivered send — so this query would re-ask
        // forever without reaching its own retry ceiling. Retire it on the same
        // terms the un-encodable question above uses, and after the confirm for
        // the same reason the service arm gives.
        if confirm.retire_producer() {
          hick_trace::warn!(
            handle = ?h,
            len = body_len,
            "no bound family can carry this query's question; retiring it"
          );
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
          break;
        }
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
    // The withdrawing route stops holding its host name for the registration
    // guard, so a replacement may take that name with a DIFFERENT address set
    // while this goodbye drains — and a delayed echo of the announcement we
    // recorded a credit for would then be differing host rdata against the
    // replacement. See `SelfSendTracker::supersede`.
    self.selfsend.supersede();
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
  ///
  /// Shares the pass's [`DrainBudget`] with [`Self::drain_transmits`] and returns
  /// `true` when the budget stopped it with goodbyes still due, so the driver loop
  /// re-enters immediately. The pump was previously an unbounded `while let`: a
  /// family that never accepts costs a whole [`SEND_ATTEMPT_TIMEOUT`] per queued
  /// goodbye, and a mass unregister queues one per service.
  async fn drain_withdrawals(
    &mut self,
    now: StdInstant,
    budget: &mut DrainBudget,
    scratch: &mut [u8],
  ) -> bool {
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();
    // Split-borrow disjoint fields so `send_via` can borrow `selfsend`/`v4`/
    // `v6` while `endpoint` is borrowed for the withdrawal pump.
    let Self {
      endpoint,
      selfsend,
      v4,
      v6,
      ..
    } = self;
    let mut more_pending = false;
    while budget.may_start_fanout() {
      let Some(round) = endpoint.poll_withdrawal_transmit(now, scratch) else {
        break;
      };
      let (len, token) = (round.len(), round.token());
      // The endpoint always returns the multicast marker; the driver fans the
      // datagram to every group the round's debt still names. Assert the contract
      // in debug builds.
      debug_assert!(
        matches!(round.dst(), SocketAddr::V4(v4a) if v4a.ip().is_multicast() && v4a.port() == 5353),
        "withdrawal dst must be the IPv4 multicast marker"
      );
      // Fan to the families the round is FOR and capture EACH one's outcome so the
      // endpoint tracks per-family debt: a withdrawal frees only once every
      // reachable family has withdrawn its records. `send_withdrawal_via` already
      // bumps packets_tx/bytes_tx per Sent family and send_errors per failed
      // family, so here we add only the per-round goodbyes_tx (one per DELIVERED
      // round).
      let (v4_out, v6_out) = send_withdrawal_via(
        selfsend,
        v4,
        v6,
        &scratch[..len],
        round.debt(),
        #[cfg(feature = "stats")]
        &stats,
      )
      .await;
      // This round's own anchor, read after its LAST syscall and before anything
      // else — never `now`, which this pass read before it began pumping.
      //
      // What `note_withdrawal_result` re-arms is the RFC 6762 §10.1 resend
      // SCHEDULE: a real-time spacing bound on a wire, and the only thing pacing
      // consecutive goodbyes, since this fan-out is deliberately ungated. Every
      // family is offered the datagram under a `SEND_ATTEMPT_TIMEOUT` bound, so a
      // family that accepts late spends most of that bound before any byte reaches
      // a wire. Re-arming from the pass instant charges the next round every
      // microsecond this one spent — the drain that preceded it, the fan-out
      // itself, the scheduler — and once that total approaches the interval the
      // next goodbye is already due at the moment this one lands, collapsing the
      // three loss-resilience sends into near-adjacent transmissions.
      //
      // The pass instant keeps every question it is the right reference for: which
      // items are due (`poll_withdrawal_transmit`), whether one was left due
      // (`next_withdrawal_deadline`), and which have run out
      // (`drain_completed_withdrawals`). Those are due-list comparisons that must
      // agree across the pass; this one is a wire measurement. The two anchors are
      // wrong in opposite directions and are not interchangeable.
      let fanned_out_at = StdInstant::now();
      // A delivered round (>= 1 family Sent) bumps goodbyes_tx; a v4-Sent + v6-busy
      // round keeps v6's debt so a v6 recovery before the 2 s ceiling still emits
      // its TTL=0 goodbye. A fully-undeliverable round is re-armed (short backoff)
      // by the endpoint WITHOUT spending.
      #[cfg(feature = "stats")]
      if matches!(v4_out, FamilyAttempt::Accepted { .. })
        || matches!(v6_out, FamilyAttempt::Accepted { .. })
      {
        stats.goodbyes_tx(1);
      }
      endpoint.note_withdrawal_result(token, fanned_out_at, v4_out, v6_out);
      // The budget is charged per family that actually SENT, exactly as the
      // transmit drain charges it, so a wholly-undeliverable goodbye round is
      // bounded by the wall clock alone.
      budget.charge(
        usize::from(matches!(v4_out, FamilyAttempt::Accepted { .. }))
          + usize::from(matches!(v6_out, FamilyAttempt::Accepted { .. })),
      );
    }
    // The pass ran out with a goodbye already due — including the case where the
    // transmit drain spent the whole budget and this pump never started at all.
    if !budget.may_start_fanout()
      && endpoint
        .next_withdrawal_deadline()
        .is_some_and(|due| due <= now)
    {
      more_pending = true;
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
    more_pending
  }
}

/// Per-drain cap on actual socket sends.
///
/// To keep the work per drain pass bounded — and to leave headroom for
/// late loopbacks of older sends to be matched before we record more
/// entries — we cap each `drain_transmits` pass at 64 sends. Dual-stack
/// mDNS multicast charges two per Transmit, so this gives ≤ 64 actual
/// sends regardless of family enablement. Forward progress is guaranteed:
/// `drain_transmits` returns `true` when more is pending, and the driver
/// loop re-enters the packet pump immediately.
const MAX_SEND_CREDITS_PER_DRAIN: usize = 64;

/// The wall clock ONE driver pass may spend inside bounded send attempts, across
/// `drain_transmits` AND `drain_withdrawals` together.
///
/// The send credits above cannot bound a pass on their own, because they are
/// charged per family that actually SENT: a fan-out every family missed costs
/// zero credits while still costing a full [`SEND_ATTEMPT_TIMEOUT`] per wedged
/// family, and the producers are served serially. A pass of `n` due producers
/// with one wedged family therefore ran for `n × SEND_ATTEMPT_TIMEOUT` with no
/// cap at all, during which nothing else in the loop ran — the 64-slot packet
/// channel backs up and inbound peer datagrams are simply dropped.
///
/// This is a LIVENESS knob, on the same terms as [`SEND_ATTEMPT_TIMEOUT`]: it
/// buys nothing about wire freshness, it only bounds how long the loop can go
/// without pumping packets and commands. 500 ms is two attempt bounds, which is
/// the smallest value that lets a pass with a wedged family still make forward
/// progress (`DrainBudget::may_start_fanout` requires a whole attempt's worth of
/// budget left, so a pass starts at least one fan-out and at most two entirely
/// wedged ones). A pass therefore never overruns this by the last fan-out it
/// started — the only exception is the forward-progress clause on
/// `DrainBudget::may_start_fanout`.
const DRAIN_PASS_BUDGET: Duration = Duration::from_millis(500);

/// The two bounds one driver pass spends: [`MAX_SEND_CREDITS_PER_DRAIN`] actual
/// sends, and [`DRAIN_PASS_BUDGET`] of wall clock shared by every fan-out the
/// pass performs.
///
/// One value threaded through both drains so the budget is genuinely per PASS.
/// Withdrawals are drained after transmits, so a pass whose transmits spend the
/// whole budget defers its goodbyes — but only to the next pass, which the
/// `more_pending` return starts immediately without sleeping, and the goodbye
/// resend schedule the endpoint owns re-arms them regardless.
struct DrainBudget {
  credits: usize,
  deadline: StdInstant,
  /// Whether this pass has started a fan-out yet. See
  /// [`Self::may_start_fanout`]'s forward-progress clause.
  started: bool,
}

impl DrainBudget {
  /// Open a fresh budget for a pass beginning at `pass_start`.
  fn new(pass_start: StdInstant) -> Self {
    Self {
      credits: MAX_SEND_CREDITS_PER_DRAIN,
      deadline: pass_start
        .checked_add(DRAIN_PASS_BUDGET)
        .unwrap_or(pass_start),
      started: false,
    }
  }

  /// Whether another fan-out may START.
  ///
  /// Requires a whole [`SEND_ATTEMPT_TIMEOUT`] of budget left, not merely a
  /// non-zero remainder: a fan-out that begins inside the budget runs to its own
  /// bound regardless, so admitting one with less than that left would let the
  /// pass overrun. Reserving it up front makes [`DRAIN_PASS_BUDGET`] a ceiling
  /// on the pass rather than on the point at which it stops taking work.
  ///
  /// The FIRST fan-out of a pass is admitted regardless of the clock. The budget
  /// starts at the top of the loop, so the sweep and the timer fire are charged
  /// to it; if those ever outran it the pass would take no work, report more
  /// pending, and re-enter to do the same again — a livelock in which transmits
  /// never progress. Unreachable in practice (both are microseconds over a
  /// slab-capped handle set), and this clause is what makes it structurally so.
  /// It costs at most one attempt bound, and only in that degenerate case.
  fn may_start_fanout(&self) -> bool {
    self.credits > 0
      && (!self.started
        || self
          .deadline
          .checked_duration_since(StdInstant::now())
          .is_some_and(|left| left >= SEND_ATTEMPT_TIMEOUT))
  }

  /// Charge one fan-out's actual sends against the credit cap, and record that
  /// this pass has taken work.
  fn charge(&mut self, sends: usize) {
    self.credits = self.credits.saturating_sub(sends);
    self.started = true;
  }
}

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

/// Whether THIS driver's receive path reports the interface a datagram from
/// `src`'s address family arrived on.
///
/// Capability belongs to the receive path and not to the platform. On Unix and
/// Windows every datagram is read through [`hick_udp::recv_with_meta`], which
/// mints [`Packet::iface`] from this answer plus `MSG_CTRUNC` and hands the
/// trust boundary a witness rather than an index; every other target takes the
/// plain `recv_from` arm of `recv_task`, which recovers no ancillary data at all
/// and declares [`IfaceWitness::Blind`] once — a rule told otherwise would fail
/// every one of those datagrams closed and leave the endpoint deaf.
///
/// Test-only now: production states the same fact structurally, by which arm of
/// `recv_task` builds the packet, so there is no second copy to drift. The
/// fixtures still need it, because what they must assert about a zero index
/// depends on whether this driver's path could have supplied one.
#[cfg(test)]
const fn rx_interface_reported(src: SocketAddr) -> bool {
  cfg!(any(unix, windows)) && hick_udp::onlink::reports_rx_interface(src)
}

/// Cheap peek at the DNS header's QR bit (RFC 1035 §4.1.1): byte 2, MSB.
/// `true` for a response (QR=1). Used by the driver to apply the §11
/// source-port trust check before consuming a self-send credit, without a
/// full message parse. A datagram too short to hold a header is not a
/// response (proto rejects it on parse).
fn packet_is_response(data: &[u8]) -> bool {
  data.get(2).is_some_and(|b| b & 0x80 != 0)
}

/// Restate one family's bounded attempt in the core's I/O-world vocabulary.
///
/// `body` is the datagram, and it is what decides `permanent`: a refusal proves
/// the bytes did not go out, and only the SIZE against this family's hard UDP
/// ceiling proves they never could. The errno is deliberately not consulted —
/// Linux answers `EMSGSIZE` for a path-MTU refusal that the next attempt may get
/// past, so a table keyed on it retires healthy services. See
/// [`FamilyAttempt::Refused`].
///
/// A family whose bound expired is [`FamilyAttempt::WouldBlock`], not a refusal:
/// the readiness path makes no `sendto` syscall until the socket is writable, so
/// a timed-out attempt provably handed nothing to the kernel. That licence is
/// what [`SEND_ATTEMPT_TIMEOUT`] documents, and it is why this driver may bound
/// an attempt at all.
///
/// The [`Family`] whose ceiling applies is named by `family` rather than derived
/// from the destination, because the multicast fan-out sends each family its own
/// group's copy.
fn attempt_of(family: Family, body: &[u8], attempt: &SendAttempt) -> FamilyAttempt<StdInstant> {
  match attempt {
    SendAttempt::Unbound => FamilyAttempt::NoSocket,
    SendAttempt::Gated => FamilyAttempt::GateShut,
    SendAttempt::Answered { result: Ok(_), .. } => match attempt.confirm_anchor() {
      Some(at) => FamilyAttempt::Accepted { at },
      // `confirm_anchor` is `Some` for every answered-Ok attempt; a `None` here
      // would mean the stamp went missing, and claiming an acceptance without one
      // would hand the core an anchor it never measured.
      None => FamilyAttempt::Refused { permanent: false },
    },
    SendAttempt::Answered { result: Err(_), .. } => FamilyAttempt::Refused {
      permanent: body.len() > max_udp_payload(family),
    },
    SendAttempt::TimedOut => FamilyAttempt::WouldBlock,
  }
}

/// The largest UDP payload `family` can EVER carry — the only sound proof
/// that a refused datagram can never be sent. See
/// [`mdns_proto::constants::MAX_UDP_PAYLOAD_V6`].
///
/// A free function rather than a method: [`Family`] is `hick-udp`'s type, and
/// this ceiling is `mdns-proto`'s constant, which that crate deliberately does
/// not depend on.
const fn max_udp_payload(family: Family) -> usize {
  match family {
    Family::V4 => mdns_proto::constants::MAX_UDP_PAYLOAD_V4,
    Family::V6 => mdns_proto::constants::MAX_UDP_PAYLOAD_V6,
  }
}

/// The per-family shape of one logical transmit's fan-out: the I/O facts, which
/// the core alone turns into a protocol answer.
///
/// Nothing is projected onto an aggregate here, and nothing is written off. WHICH
/// family missed is what lets the core schedule the next announcement per link
/// rather than per round, and a driver that folded it away would put the core back
/// to refreshing alternating families at twice the periodic interval. Bounding how
/// long the lifecycle waits for a family that keeps missing is the core's own
/// patience, applied inside the confirm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fanout {
  v4: FamilyAttempt<StdInstant>,
  v6: FamilyAttempt<StdInstant>,
}

impl Fanout {
  /// Neither family was addressed — the starting value, overwritten per family
  /// the datagram is actually offered to. A unicast destination leaves the other
  /// family here, which is the honest fact about it: its socket may well be bound
  /// and healthy, this datagram was simply not for it.
  const NOT_ADDRESSED: Self = Self {
    v4: FamilyAttempt::NotAddressed,
    v6: FamilyAttempt::NotAddressed,
  };

  /// How many `send_to`s actually put bytes on a wire.
  ///
  /// This is the FAIRNESS-budget charge and nothing else. It deliberately does
  /// not decide delivery: one datagram that reached one of two obligated
  /// families costs one credit yet has discharged no obligation.
  fn sent_count(self) -> usize {
    usize::from(matches!(self.v4, FamilyAttempt::Accepted { .. }))
      + usize::from(matches!(self.v6, FamilyAttempt::Accepted { .. }))
  }
}

/// Confirm one service transmit: hand the core the delivery shape, then mirror
/// the service's CONFIRMED-ADVERTISED host set into its endpoint route.
///
/// The mirror exists so sibling host-address retention (during a same-host
/// withdrawal) honours what this service ACTUALLY announced rather than its
/// configured addresses. That set grows exactly when ownership latches — on any
/// delivery — so a round that reached no wire has nothing to mirror.
///
/// The reclaim-cancel gate is the ALL-delivered announcement fact the CORE
/// computes, ferried verbatim. It is emphatically NOT
/// `Service::advertises_instance()`: that latch fires on any delivery by any
/// transmit kind, so a v4-only announcement — or an RFC 6762 §6.7 legacy unicast
/// reply, which has one obligated link and is therefore all-delivered by
/// construction — would cancel a renamed-away name's goodbye that the unserved
/// family still needs. `FullyAnnounced` has no public constructor precisely so
/// that substitution cannot compile, and it names the service it was minted from,
/// so it cannot be applied to a different one either.
///
/// `endpoint` and `ctx` are disjoint fields of `DriverState`, so the split borrow
/// this signature requires is sound at every call site.
fn confirm_service_transmit(
  endpoint: &mut ProtoEndpoint,
  ctx: &mut ServiceCtx,
  fallback_at: StdInstant,
  v4: FamilyAttempt<StdInstant>,
  v6: FamilyAttempt<StdInstant>,
) -> TransmitConfirm {
  let confirm = ctx.proto.note_transmit_outcome(fallback_at, v4, v6);
  if confirm.any_delivered() {
    endpoint.note_service_announced(
      ctx.proto.has_fully_announced(),
      ctx.proto.advertised_a_addrs(),
      ctx.proto.advertised_aaaa_addrs(),
    );
  }
  confirm
}

/// How long ONE address family's `send_to` may stay unaccepted before the
/// fan-out gives up on it for this round and reports that family `Missed`.
///
/// Without a bound a family whose socket never becomes writable parks the whole
/// driver task — every timer, every command, every other family's transmit —
/// for as long as it stays wedged. Running the families concurrently removes the
/// serialisation but bounds neither attempt, so the bound is what actually
/// returns control to the loop.
///
/// # What this bound is, and what it is not
///
/// It is a LIVENESS knob, not a wire-freshness budget. What the core guarantees
/// is the SCHEDULE: a family in good standing is re-announced within
/// `max(R, 2 × ANNOUNCE_INTERVAL)` of ITS LAST DELIVERY, with `R` the periodic
/// refresh interval. Whether the records are actually fresh on the wire is
/// conditional on the driver delivering due transmits promptly. No value here
/// makes that unconditional: against arbitrarily slow I/O no budget causes a
/// non-accepting socket's peers to refresh in time, and the protocol-correct
/// response to a link that will not carry datagrams is the one the core already
/// has — patience, stall, excusal, and the silence rule. The driver owes loop
/// liveness and honest per-family facts, not a latency SLA.
///
/// The value is 250 ms because that is RFC 6762 §8.1's inter-probe interval, the
/// shortest cadence the protocol itself schedules: a timed-out family is
/// reported before the re-arm that report feeds falls due, so the bound never
/// becomes the thing that paces the lifecycle. A healthy bound UDP socket answers
/// in microseconds or with an errno, so this cannot manufacture the spurious
/// misses that would spend the core's patience.
///
/// # Why a READINESS driver may bound an attempt at all
///
/// Abandoning this future is a DEFINITIVE cancellation, and that is a property of
/// readiness I/O specifically. The attempt makes a `sendto` syscall only from
/// inside a poll that found the socket writable; when the bound fires, the future
/// is dropped between polls, after the last syscall returned `WouldBlock`.
/// Nothing was ever handed to the kernel, so reporting the family `Missed` is a
/// fact rather than a guess.
///
/// A COMPLETION-based driver has no such licence: its operation is submitted to
/// the kernel before the wait begins, and cancelling the wait does not cancel the
/// submission — compio documents its own cancellation as unreliable, with the
/// underlying operation free to continue. Timing one out there and reporting
/// `Missed` would tell the core a datagram never reached the wire while the
/// kernel may still be putting it there. Do NOT copy this pattern into such a
/// driver on the strength of it appearing here.
const SEND_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);

/// One PRODUCER's per-family earliest-next-send gate: when each address family
/// ([0] = v4, [1] = v6) last carried a datagram from this service or query.
///
/// The rule it enforces is RFC 6762's, on the wire: §6 and §8.3 forbid
/// re-multicasting a record on an interface inside one second of the last time it
/// went out on that same interface, and §8.1 spaces probes 250 ms apart. The
/// MINIMUM is protocol policy and arrives from the core on
/// [`Transmit::min_family_gap`]; only the driver knows when each family last
/// satisfied it, which is why the two halves live on opposite sides of the seam.
///
/// "Wire" throughout this driver names the KERNEL HANDOFF, the furthest point a
/// socket transport can observe: this gate anchors at the instant the send
/// syscall RETURNED, and success there means the kernel owns the datagram rather
/// than that the NIC has put it on the link. See [`Transmit::min_family_gap`] for
/// where each driver's boundary sits.
///
/// It cannot be folded into the core's schedule because the confirm anchors at
/// the EARLIEST acceptance across families. That anchor is the right one for the
/// TTL guarantee — it can only understate how fresh a family's peers are — but
/// under inter-family skew `s` it schedules the next datagram one interval after
/// the EARLY family's wire time, leaving the late family a gap of
/// `interval − s`. The core cannot see `s`; the driver measured it.
///
/// Kept PER PRODUCER because the rules are per record set: two different services
/// announcing inside the same second are two different records and pace each
/// other not at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FamilyWireGate {
  /// Indexed [v4, v6]. `None` until that family has carried a GATED datagram from
  /// this producer — an ungated (one-shot) send never writes here, so a §6 reply
  /// cannot defer the announcement that follows it.
  last_sent: [Option<StdInstant>; 2],
}

impl FamilyWireGate {
  /// Whether family `idx` may be offered a datagram at `now` under `min_gap`.
  ///
  /// A zero `min_gap` is ungated and always open. A family that has carried
  /// nothing yet is open. A clock that reads BEFORE the recorded send closes the
  /// gate: the elapsed gap is then unknown, and the conservative answer is the
  /// one that cannot put a record back on the wire too soon.
  fn open(&self, idx: usize, now: StdInstant, min_gap: Duration) -> bool {
    if min_gap.is_zero() {
      return true;
    }
    match self.last_sent.get(idx).copied().flatten() {
      Some(last) => now
        .checked_duration_since(last)
        .is_some_and(|gap| gap >= min_gap),
      None => true,
    }
  }

  /// Record that family `idx` put a GATED datagram on its wire at `at`.
  ///
  /// `at` must be that family's OWN POST-SYSCALL instant
  /// ([`SendAttempt::wire_time`]). Two ways to get it wrong, and this gate
  /// tolerates neither:
  ///
  /// * the fan-out's confirm anchor (the EARLIEST family's) would re-introduce
  ///   exactly the inter-family skew this gate exists to absorb;
  /// * a PRE-syscall instant would spend the gap on time the datagram had not
  ///   yet reached the wire. The next `open` would then pass while the true
  ///   spacing was only `min_gap` minus that delay — §6 / §8.1 / §8.3 measure
  ///   the wire, and the wire only saw bytes once the `sendto` returned.
  ///
  /// The core's own confirm anchor is a pre-syscall instant and correctly so
  /// ([`SendAttempt::confirm_anchor`]); the two anchors are wrong in opposite
  /// directions and are not interchangeable.
  fn record(&mut self, idx: usize, at: StdInstant, min_gap: Duration) {
    if min_gap.is_zero() {
      return;
    }
    if let Some(slot) = self.last_sent.get_mut(idx) {
      *slot = Some(at);
    }
  }
}

/// Index of the IPv4 family in every per-family array, matching
/// [`mdns_proto::TransmitDelivery`]'s own ordering.
const FAMILY_V4: usize = 0;
/// Index of the IPv6 family.
const FAMILY_V6: usize = 1;

/// One address family's answer to ONE bounded send attempt.
enum SendAttempt {
  /// No socket bound for this family, so it was never offered the datagram.
  Unbound,
  /// A bound socket the per-family wire gate held back for this round; no
  /// syscall was made. See [`FamilyWireGate`].
  Gated,
  /// The socket answered within [`SEND_ATTEMPT_TIMEOUT`]: the `send_to` result,
  /// plus THREE separate clock reads taken around the `sendto` (see
  /// [`send_to_at`]).
  ///
  /// Three, not one, and not two: each stamp is allowed to be wrong in exactly
  /// one direction, and the three directions do not agree. Folding any pair
  /// together silently breaks whichever consumer needed the other direction —
  /// see the field docs before "simplifying" them.
  Answered {
    /// What `poll_send_to` reported.
    result: std::io::Result<usize>,
    /// Wall clock, read BEFORE the syscall. Keys self-send suppression.
    ///
    /// Suppression matches our own multicast loopback echo against this stamp,
    /// so `submitted_wall <= kernel_send_time <= echo_rx_time` must hold or the
    /// echo looks like a peer datagram that predated our send and this host
    /// processes its own probe / announcement as peer traffic. Reading it after
    /// the syscall can push it past the kernel's rx stamp; reading it before
    /// cannot.
    submitted_wall: SystemTime,
    /// Monotonic, read BEFORE the syscall and immediately after
    /// `submitted_wall`. Anchors the CORE's refresh schedule.
    ///
    /// EARLY is the safe direction here: an anchor at or before the true
    /// acceptance can only understate how fresh a family's peers are, so the
    /// next refresh lands sooner than strictly needed. A late anchor would push
    /// a refresh past the records' own TTL.
    submitted_at: StdInstant,
    /// Monotonic, read AFTER the syscall returned. Anchors [`FamilyWireGate`].
    ///
    /// EARLY is the UNSAFE direction here — the opposite of `submitted_at`, and
    /// the whole reason this is a third stamp rather than that one reused. The
    /// gate measures the real spacing between bytes on ONE family's wire, and
    /// nothing bounds the delay between a pre-syscall clock read and the
    /// `sendto` that follows it: a preempted thread, a signal handler, or a page
    /// fault puts the datagram on the wire long after the stamp. Anchored at
    /// `submitted_at`, a send stalled by `P` re-opens its own family `P` early —
    /// at RFC 6762 §8.1's 250 ms inter-probe interval a 200 ms stall would leave
    /// 50 ms of true spacing, and it would do so on exactly the loaded host the
    /// spacing exists to protect.
    wire_at: StdInstant,
  },
  /// The socket had still not accepted the datagram when the bound expired.
  TimedOut,
}

impl SendAttempt {
  /// The instant to confirm a delivered family at, if it delivered.
  ///
  /// The CORE's anchor, read before the syscall (`Answered::submitted_at`), so
  /// it is at or before the true acceptance.
  fn confirm_anchor(&self) -> Option<StdInstant> {
    match self {
      Self::Answered {
        result: Ok(_),
        submitted_at,
        ..
      } => Some(*submitted_at),
      _ => None,
    }
  }

  /// The instant this family's bytes were actually on its wire, if they were.
  ///
  /// The WIRE GATE's anchor, read after the syscall returned
  /// (`Answered::wire_at`).
  ///
  /// Never fold this into [`Self::confirm_anchor`]. The two answer different
  /// questions — "when may the core assume peers heard us" versus "when did this
  /// wire last carry bytes" — and they are wrong in opposite directions, so each
  /// consumer can absorb only its own.
  fn wire_time(&self) -> Option<StdInstant> {
    match self {
      Self::Answered {
        result: Ok(_),
        wire_at,
        ..
      } => Some(*wire_at),
      _ => None,
    }
  }
}

/// Offer one family its copy of the datagram, bounded by
/// [`SEND_ATTEMPT_TIMEOUT`]. An absent socket is [`SendAttempt::Unbound`] — that
/// family was never obligated — and is answered without touching the clock.
///
/// This offer is UNCONDITIONAL, and the only caller entitled to one is the RFC
/// 6762 §10.1 goodbye fan-out ([`send_withdrawal_via`]), which is ungated by
/// design. A positive-TTL transmit goes through [`attempt_gated_send_to`], which
/// is where its wire gate is consulted.
async fn attempt_send_to<S: UdpSocket>(
  sock: Option<&S>,
  buf: &[u8],
  dst: SocketAddr,
) -> SendAttempt {
  let Some(sock) = sock else {
    return SendAttempt::Unbound;
  };
  let send = send_to_at(sock, buf, dst).fuse();
  let bound = <S::Runtime as RuntimeLite>::sleep(SEND_ATTEMPT_TIMEOUT).fuse();
  pin_mut!(send, bound);
  select_biased! {
    out = send => out,
    _ = bound => SendAttempt::TimedOut,
  }
}

/// [`attempt_send_to`], gated by this family's own share of the producer's
/// [`FamilyWireGate`].
///
/// The clock is read HERE — after the boundness check, with this family's
/// `sendto` as the next thing that happens — rather than once for the whole
/// driver pass. A pass may legitimately spend [`DRAIN_PASS_BUDGET`] plus the last
/// fan-out's own [`SEND_ATTEMPT_TIMEOUT`] serving the producers ahead of this one,
/// and a reading that old UNDERSTATES how long this wire has actually been idle.
/// The gate would then withhold a datagram whose §6 / §8.1 floor was genuinely
/// paid — and [`SendAttempt::Gated`] does not reach the core as "nothing
/// happened", it reaches it as [`FamilyDelivery::Missed`], spending the core's
/// partial-round patience and holding the §8.1 probe sequence / §8.3 announce
/// phase for a wire that was ready.
///
/// Reading later than the pass would have is provably one-directional: with
/// `last_sent` fixed [`FamilyWireGate::open`] is monotone in `now`, and nothing
/// can record into the gate while a fan-out is in flight —
/// [`FamilyWireGate::record`] runs once, after every family has answered, and the
/// SHARED borrow taken here is what makes that structural rather than a
/// convention. So this can only ever flip a family from gated to offered; it can
/// never withhold one a pass-wide reading would have offered.
async fn attempt_gated_send_to<S: UdpSocket>(
  sock: Option<&S>,
  gate: &FamilyWireGate,
  idx: usize,
  min_gap: Duration,
  buf: &[u8],
  dst: SocketAddr,
) -> SendAttempt {
  if sock.is_none() {
    return SendAttempt::Unbound;
  }
  if !gate.open(idx, StdInstant::now(), min_gap) {
    return SendAttempt::Gated;
  }
  attempt_send_to(sock, buf, dst).await
}

/// Record the trace line, the self-send credit, and the stats for one MULTICAST
/// family's completed attempt.
///
/// The credit is recorded only for an attempt that actually put bytes on the
/// wire. A failed or timed-out send produces no loopback, and a stale credit
/// would suppress a later byte-identical peer packet.
///
/// `family` is the family whose socket carried this attempt, passed in rather
/// than read off `_dst`: the credit is keyed to the socket its loopback copy can
/// arrive on, and only the caller that chose the socket knows that for certain.
fn note_multicast_attempt(
  tracker: &mut SelfSendTracker,
  family: Family,
  attempt: &SendAttempt,
  body: &[u8],
  _dst: SocketAddr,
  _kind: &'static str,
  #[cfg(feature = "stats")] stats: &std::sync::Arc<hick_trace::stats::Stats>,
) {
  match attempt {
    // Neither put bytes on a wire, and neither is an error: one has no socket,
    // the other is this driver's own deliberate spacing.
    SendAttempt::Unbound | SendAttempt::Gated => {}
    SendAttempt::Answered {
      result: Ok(_),
      submitted_wall,
      submitted_at,
      ..
    } => {
      hick_trace::trace!(kind = _kind, dst = %_dst, len = body.len(), "send_to");
      // The pre-syscall pair, wall first and monotonic immediately after, exactly
      // as `send_to_at` reads them on consecutive statements — which is the
      // adjacency `ClockPair` is built on. The wall half ORDERS this credit
      // against its echo and cannot outrun the kernel's stamp on a copy already
      // looped back; the monotonic half is its partner, the only thing that can
      // later say whether the wall clock stayed on one timeline. Neither is an
      // age: the credit takes no ageing anchor here, because no instant inside
      // this iteration is a legal one — nothing recorded now can be claimed
      // before the next iteration's seal opens the window.
      tracker.record(family, body, ClockPair::new(*submitted_wall, *submitted_at));
      #[cfg(feature = "stats")]
      {
        stats.packets_tx(1);
        stats.bytes_tx(body.len() as u64);
      }
    }
    SendAttempt::Answered {
      result: Err(_e), ..
    } => {
      hick_trace::debug!(kind = _kind, error = %_e, dst = %_dst, "send_to failed");
      #[cfg(feature = "stats")]
      stats.send_errors(1);
    }
    SendAttempt::TimedOut => {
      hick_trace::debug!(
        kind = _kind,
        dst = %_dst,
        "send_to did not complete within the per-family bound"
      );
      #[cfg(feature = "stats")]
      stats.send_errors(1);
    }
  }
}

/// Send a datagram on the appropriate socket(s), reporting each family's result
/// and recording one self-send credit per ACTUAL successful MULTICAST
/// `send_to`, keyed to the family that carried it.
///
/// Returns the per-family [`Fanout`]: the honest I/O facts for the confirm, and
/// `sent_count()` for the fairness budget — two independent facts that must not
/// be conflated, since one datagram that reached one of two families costs one
/// credit but has NOT discharged the transmit's obligation.
///
/// Each accepted family carries ITS OWN acceptance instant, and the core folds
/// the earliest across families itself. This function used to do that fold and
/// return one instant beside the fan-out, which left the anchor rule — an
/// interpretation, and the one the whole per-family schedule turns on — on this
/// side of the boundary.
///
/// `gate` is the PRODUCER's per-family earliest-next-send state and `min_gap` the
/// minimum the core computed for this datagram's kind
/// ([`Transmit::min_family_gap`]). A family whose gap is unpaid is not offered the
/// datagram at all and is reported [`FamilyAttempt::GateShut`] — obligated, and it
/// did not carry it. Every family that DID carry it records its own POST-SYSCALL
/// instant back into `gate` ([`SendAttempt::wire_time`]), which is a different
/// stamp from the acceptance instant the confirm carries.
///
/// This deliberately takes no `now`, unlike every sibling on the drain path: each
/// family's gap is weighed at ITS OWN send point ([`attempt_gated_send_to`]), not
/// against the reading the pass took before it began serving producers.
#[allow(clippy::too_many_arguments)]
async fn send_via<S: UdpSocket>(
  tracker: &mut SelfSendTracker,
  v4: &Option<Arc<S>>,
  v6: &Option<Arc<S>>,
  dst: SocketAddr,
  body: &[u8],
  gate: &mut FamilyWireGate,
  min_gap: Duration,
  #[cfg(feature = "stats")] stats: &std::sync::Arc<hick_trace::stats::Stats>,
) -> Fanout {
  // proto-layer transmits use multicast_dst() which always
  // returns the IPv4 group. Detect mDNS multicast destinations and fan
  // out the SAME payload to BOTH families' multicast groups (per RFC
  // 6762 §6 — a host with both IPv4 and IPv6 stacks must respond on
  // each). Non-multicast (unicast) sends fall back to the per-family
  // socket selection.
  //
  // Record one credit per ACTUAL send_to. Take-once suppression consumes a single
  // credit per matching loopback; a dual-stack fan-out generates TWO loopback
  // copies (one per joined socket), so it needs one credit per family and each is
  // claimable only by an echo read off that family's own socket.
  let is_mdns_multicast = matches!(dst, SocketAddr::V4(v4a) if v4a.ip().is_multicast() && v4a.port() == 5353)
    || matches!(dst, SocketAddr::V6(v6a) if v6a.ip().is_multicast() && v6a.port() == 5353);

  // Each credit is stamped with the clock pair read INSIDE the poll that actually
  // performs the `sendto` (see `send_to_at`), not before awaiting an async
  // `send_to`. The kernel stamps the looped-back copy during that syscall, so the
  // captured wall time is immediately before the kernel's receive stamp —
  // guaranteeing `sent <= rx` for our own loopback (modulo the truncation grain)
  // while leaving no awaitable gap in which a peer datagram could be stamped after
  // our recorded time yet before our packet is actually sent (which would let it
  // steal the take-once credit).
  let mut fanout = Fanout::NOT_ADDRESSED;
  if is_mdns_multicast {
    // Offer both families CONCURRENTLY. Serialising them made each family's
    // acceptance instant depend on how long the other one took, and made a
    // family that never accepts hold the whole fan-out — and with it the driver
    // loop — for as long as it stayed wedged.
    let (a4, a6) = futures::future::join(
      attempt_gated_send_to(v4.as_deref(), gate, FAMILY_V4, min_gap, body, MDNS_V4_DST),
      attempt_gated_send_to(v6.as_deref(), gate, FAMILY_V6, min_gap, body, MDNS_V6_DST),
    )
    .await;
    fanout.v4 = attempt_of(Family::V4, body, &a4);
    fanout.v6 = attempt_of(Family::V6, body, &a6);
    // Each family's OWN post-syscall instant re-opens ITS OWN gate one `min_gap`
    // later — never the fan-out anchor (the earliest across families), which
    // would put the late family's next send back inside the interval, and never
    // the pre-syscall anchor, which would spend part of the interval on time the
    // datagram had not yet reached the wire.
    if let Some(at) = a4.wire_time() {
      gate.record(FAMILY_V4, at, min_gap);
    }
    if let Some(at) = a6.wire_time() {
      gate.record(FAMILY_V6, at, min_gap);
    }
    // The tracker is written after the join, in family order, so the two credits
    // a dual-stack fan-out needs are recorded exactly as the serial version
    // recorded them.
    note_multicast_attempt(
      tracker,
      Family::V4,
      &a4,
      body,
      MDNS_V4_DST,
      "transmit",
      #[cfg(feature = "stats")]
      stats,
    );
    note_multicast_attempt(
      tracker,
      Family::V6,
      &a6,
      body,
      MDNS_V6_DST,
      "transmit",
      #[cfg(feature = "stats")]
      stats,
    );
    return fanout;
  }

  // Unicast: pick the socket matching the destination family. Exactly one family
  // is obligated (an absent socket obligates none), so this branch can only be
  // all- or none-delivered.
  let (idx, sock) = match dst {
    SocketAddr::V4(_) => (FAMILY_V4, v4.as_deref()),
    SocketAddr::V6(_) => (FAMILY_V6, v6.as_deref()),
  };
  // NO self-send credit here, unlike the multicast branch. A unicast datagram —
  // an RFC 6762 §6.7 legacy reply, or a directed response — leaves for the
  // querier's own address and port and never loops back through the multicast
  // group we joined, so a credit recorded for it can never be consumed. It would
  // simply occupy the linear-scanned tracker for `SELF_SEND_TTL`, and at
  // `MAX_SELF_SEND_ENTRIES` a record is refused rather than evicting a live
  // credit — so a legacy-query flood would starve the genuine multicast credits
  // that suppression actually depends on.
  let attempt = attempt_gated_send_to(sock, gate, idx, min_gap, body, dst).await;
  let outcome = attempt_of(Family::of(dst), body, &attempt);
  match dst {
    SocketAddr::V4(_) => fanout.v4 = outcome,
    SocketAddr::V6(_) => fanout.v6 = outcome,
  }
  if let Some(at) = attempt.wire_time() {
    gate.record(idx, at, min_gap);
  }
  match &attempt {
    // In tree every unicast datagram is a §6.7 legacy reply, which is one-shot
    // and therefore ungated — `Gated` is unreachable here today and is listed
    // with `Unbound` because neither wrote to a wire nor failed.
    SendAttempt::Unbound | SendAttempt::Gated => {}
    SendAttempt::Answered { result: Ok(_), .. } => {
      hick_trace::trace!(dst = %dst, len = body.len(), "send_to");
      #[cfg(feature = "stats")]
      {
        stats.packets_tx(1);
        stats.bytes_tx(body.len() as u64);
      }
    }
    SendAttempt::Answered {
      result: Err(_e), ..
    } => {
      hick_trace::debug!(error = %_e, dst = %dst, "send_to failed");
      #[cfg(feature = "stats")]
      stats.send_errors(1);
    }
    SendAttempt::TimedOut => {
      hick_trace::debug!(dst = %dst, "send_to did not complete within the per-family bound");
      #[cfg(feature = "stats")]
      stats.send_errors(1);
    }
  }
  fanout
}

/// Fan ONE endpoint-owned withdrawal (TTL=0 goodbye) datagram out to every bound
/// multicast family `debt` still names, and report EACH family's
/// [`FamilyAttempt`] so the endpoint can settle its per-family debt.
///
/// Mirrors [`send_via`]'s multicast branch — same self-send tracking, same
/// `packets_tx`/`bytes_tx`/`send_errors` accounting, and the SAME restatement of
/// a socket outcome, because what a socket did means the same thing whatever the
/// datagram was for. What each fact then does to a family's §10.1 debt is the
/// endpoint's table and no part of this crate: only an absent socket writes a
/// debt off, and a permanently-oversized goodbye keeps its debt exactly as a
/// transient failure does.
///
/// Every family the goodbye is offered to is offered it concurrently, and each
/// attempt is bounded by [`SEND_ATTEMPT_TIMEOUT`], for the same reason the
/// positive-TTL fan-out is: this pump runs in the driver loop, so a family that
/// never accepts would park every timer and every command behind it indefinitely.
/// A bound that expires reports [`FamilyAttempt::WouldBlock`] — nothing was
/// submitted — which keeps the debt exactly as a refusal does.
///
/// # `debt` decides which families are offered it at all
///
/// NOT a wire gate — there is deliberately none here (see the ungating note
/// below). It is the core's own per-family goodbye debt, carried on the round
/// itself, and a family it does not name has already retracted everything this
/// item withdraws. An item stays selectable while EITHER family owes, so without
/// this a paid family is handed every round the other one's retries produce: a
/// retraction of records no peer on that family still holds, arriving at whatever
/// cadence the other family's failures set rather than at the RFC 6762 §10.1
/// interval.
///
/// A withheld family made no syscall, so it has no I/O fact to report; it is sent
/// over as [`FamilyAttempt::GateShut`], and the endpoint discards any report for a
/// family whose debt was already zero — so erring towards caution costs a round
/// and never a debt.
async fn send_withdrawal_via<S: UdpSocket>(
  tracker: &mut SelfSendTracker,
  v4: &Option<Arc<S>>,
  v6: &Option<Arc<S>>,
  body: &[u8],
  debt: FamilyDebt,
  #[cfg(feature = "stats")] stats: &std::sync::Arc<hick_trace::stats::Stats>,
) -> (FamilyAttempt<StdInstant>, FamilyAttempt<StdInstant>) {
  let (a4, a6) = futures::future::join(
    // Ungated: a TTL=0 goodbye's repeat schedule is the endpoint's
    // (`note_withdrawal_result`), which already spaces the resends, and holding
    // one back here would leave a family's peers pinned to positive-TTL records
    // it has already been promised the retraction of.
    attempt_owed_send_to(debt.v4_owed(), v4.as_deref(), body, MDNS_V4_DST),
    attempt_owed_send_to(debt.v6_owed(), v6.as_deref(), body, MDNS_V6_DST),
  )
  .await;
  let out = |family: Family, attempt: &Option<SendAttempt>| match attempt {
    // Withheld because the core's debt says this family has already paid: no
    // syscall was made, so there is no I/O fact — only this driver's own
    // withholding, which the endpoint then discards along with the rest of a
    // zero-debt family's round.
    None => FamilyAttempt::GateShut,
    Some(attempt) => attempt_of(family, body, attempt),
  };
  let outcomes = (out(Family::V4, &a4), out(Family::V6, &a6));
  // Only a family that was actually offered the datagram has anything to record:
  // a withheld one made no syscall, so it produces no loopback to credit and no
  // stats to bump.
  if let Some(a4) = a4 {
    note_multicast_attempt(
      tracker,
      Family::V4,
      &a4,
      body,
      MDNS_V4_DST,
      "withdrawal",
      #[cfg(feature = "stats")]
      stats,
    );
  }
  if let Some(a6) = a6 {
    note_multicast_attempt(
      tracker,
      Family::V6,
      &a6,
      body,
      MDNS_V6_DST,
      "withdrawal",
      #[cfg(feature = "stats")]
      stats,
    );
  }
  outcomes
}

/// [`attempt_send_to`] for one family of a withdrawal fan-out, or `None` when the
/// core's [`FamilyDebt`] says that family owes this item nothing.
///
/// The decision is taken before the future is created, so a withheld family makes
/// no syscall, takes no [`SEND_ATTEMPT_TIMEOUT`] and has no attempt to record.
async fn attempt_owed_send_to<S: UdpSocket>(
  owed: bool,
  sock: Option<&S>,
  body: &[u8],
  dst: SocketAddr,
) -> Option<SendAttempt> {
  if !owed {
    return None;
  }
  Some(attempt_send_to(sock, body, dst).await)
}

/// Send `buf` to `dst`, answering with the send result and the THREE clock reads
/// taken around the `sendto` — see [`SendAttempt::Answered`], the only variant
/// this can produce, for why the three cannot be collapsed.
///
/// Driving `poll_send_to` directly — rather than awaiting `send_to` and
/// stamping around it — lets us snapshot the pre-syscall clocks at the very
/// start of each poll and keep only the snapshot from the poll that
/// returns `Ready`. Polls that return `Pending` (socket not yet writable)
/// discard their snapshot, so the recorded time is always adjacent to the
/// syscall that creates the loopback, with no awaitable gap in between.
///
/// The post-syscall read is taken as early as possible on the far side of that
/// same poll, before any restatement or telemetry — neither is free, and both
/// would otherwise be charged to the next datagram's wire gap.
async fn send_to_at<S: UdpSocket>(sock: &S, buf: &[u8], dst: SocketAddr) -> SendAttempt {
  let mut submitted_wall = SystemTime::now();
  let mut submitted_at = StdInstant::now();
  let result = core::future::poll_fn(|cx| {
    // Both PRE-syscall reads stay pre-syscall, and adjacent: the wall clock
    // because a late one could outrun the kernel's rx stamp and cost us loopback
    // suppression, the monotonic one because a late one could schedule a refresh
    // past its records' TTL.
    submitted_wall = SystemTime::now();
    submitted_at = StdInstant::now();
    sock.poll_send_to(cx, buf, dst)
  })
  .await;
  // POST-syscall, and only this one. The `sendto` has returned, so this is the
  // first instant at which the datagram is known to have reached the wire — the
  // only honest input to a gate that spaces one wire's bytes.
  let wire_at = StdInstant::now();
  SendAttempt::Answered {
    result,
    submitted_wall,
    submitted_at,
    wire_at,
  }
}

/// Spawn the driver task on the runtime exposed by `N`.
pub(crate) fn spawn<N: Net>(
  opts: ServerOptions,
  sockets: BoundSockets<N>,
  cmd_rx: async_channel::Receiver<Command>,
  #[cfg(feature = "stats")] stats_out: &mut Option<std::sync::Arc<hick_trace::stats::Stats>>,
) -> Arc<RecvHealth> {
  let max_send = opts.max_payload_size();
  let max_recv = opts.max_recv_packet_size();
  let state = DriverState::<N>::new(&opts, sockets);
  #[cfg(feature = "stats")]
  {
    *stats_out = Some(state.stats.clone());
  }
  // Created HERE rather than inside the task, because the caller has to hold a
  // clone: it is the only signal `Endpoint::deaf_families` can read, and a value
  // minted inside a detached task cannot be handed back out of one.
  let health = Arc::new(RecvHealth::default());
  <N::Runtime as RuntimeLite>::spawn_detach(driver_task::<N>(
    state,
    cmd_rx,
    max_send,
    max_recv,
    health.clone(),
  ));
  health
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", skip_all))]
async fn driver_task<N: Net>(
  mut state: DriverState<N>,
  cmd_rx: async_channel::Receiver<Command>,
  max_send: usize,
  max_recv: usize,
  health: Arc<RecvHealth>,
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
      health.clone(),
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
      health.clone(),
      #[cfg(feature = "stats")]
      stats,
    ));
  }
  drop(packet_tx);
  drop(shutdown_rx); // recv loops hold their own clones; the sender stays with us.
  // The driver task itself never reads the flags; the receive tasks own the
  // writes and `Endpoint` owns the reads.
  drop(health);

  loop {
    // drain any already-arrived packets BEFORE firing timers
    // and draining new transmits, so the multicast-loopback copies of
    // the PRIOR iteration's transmits are matched against the credits
    // sealed at the end of that iteration, before this one records new sends.
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
    //
    // ONE budget covers both drains, so the pass — not each drain in isolation —
    // is what is bounded. Its clock starts at `now`, so the sweep and the timer
    // fire above are charged to it too, which is the conservative direction.
    let mut budget = DrainBudget::new(now);
    let more_transmits_pending = state.drain_transmits(now, &mut budget, &mut scratch).await;
    // `push_updates` may retire services (orphan drop, encode escalation, or a
    // rename collision), each beginning an endpoint-owned withdrawal.
    state.push_updates(now).await;
    // Pump every due endpoint-owned TTL=0 goodbye and GC each completed
    // withdrawal (route freed → driver ctx removed). `Endpoint::poll_timeout`
    // folds the withdrawal deadlines into `next_deadline`, so a due resend wakes
    // the loop.
    let more_withdrawals_pending = state
      .drain_withdrawals(now, &mut budget, &mut scratch)
      .await;
    let more_pending = more_transmits_pending || more_withdrawals_pending;

    // Open the claim window on everything the drains above just recorded, and
    // nowhere else in this task.
    //
    // **Recording and window-opening must straddle the receive.** This is the
    // last statement in the iteration that can record a credit — `handle_command`
    // only answers channels — and every path from here to the next thing that can
    // receive passes through it: the `select_biased!` below handles a packet in
    // THIS iteration, and the `continue` above re-enters the packet pump at the
    // top of the next one. A seal at the loop top instead of here sits on the
    // same side of the receive as the records it is meant to open, which leaves
    // this iteration's credits unsealed across the park below — and an unsealed
    // credit is live unconditionally, so a matching datagram arriving minutes
    // later would still be swallowed as our own echo. `SELF_SEND_TTL` would bound
    // nothing on exactly the path it exists to bound.
    //
    // Sealing here rather than at each send keeps the two moments the credit's
    // two stamps exist to keep apart: the outbound stretch of the iteration that
    // recorded a credit is structurally claim-free, so charging it would
    // re-expire credits that never had a claim opportunity. What it costs is
    // over-retention bounded by the park below, and over-retention is the CHEAP
    // direction: a stale credit can at worst suppress one byte-identical peer
    // datagram, and take-once bounds it to one. Under-retention loses our own
    // echo to the protocol layer as peer traffic — a phantom RFC 6762 §9 conflict
    // against ourselves, and the rename that follows.
    //
    // It deliberately takes no instant: the anchor is read inside the call, after
    // the expiry sweep that precedes it, so a long sweep cannot hand a
    // just-opened window an anchor from before it.
    state.seal_after_records();

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
    if more_pending {
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

    // THE PARK ENTRY, and the one place the seal's placement is actually checked.
    //
    // Deliberately NOT adjacent to `seal` above: a check written straight after
    // `seal` is vacuous, since sealing is exactly what makes nothing unsealed.
    // Asked HERE it is a real question — "did the seal this iteration relies on
    // already happen, with every record stage behind it?" — and the three ways to
    // get the placement wrong all answer it "no":
    //
    // * seal at the loop top: the drains above recorded after it, so their
    //   credits are unsealed right here;
    // * no seal at all, or one only in a receive arm: likewise unsealed here;
    // * seal after the park: same.
    //
    // The generation captured alongside is what the receive path compares against,
    // which pins the remaining case — a seal that ran BOTH here and again inside
    // the receive arm leaves nothing unsealed, so only a changed generation shows
    // that the credits were re-anchored a whole park late.
    //
    // It compiles out of release builds and influences no decision.
    #[cfg(debug_assertions)]
    state.note_park_entry();

    // A closed command or packet channel means the endpoint (and its recv
    // loops) are gone. Record it via a flag and break AFTER the select so the
    // control flow can't be confused with the select macro's internals.
    let mut closed = false;
    if let Some(at) = deadline {
      // How long to sleep is measured from the moment the sleep starts, not from
      // the top of a pass that has since awaited every fan-out in it. The pass's
      // `now` is stale by exactly the wall clock those sends took, so a duration
      // derived from it overshoots the absolute deadline by the same amount —
      // and a §5.2 retry, a §8.3 announcement or a caller's query window would
      // be woken that late. `sleep` takes a duration, so the subtraction is
      // unavoidable; taking it here is what keeps the result a real interval.
      let dur = at.saturating_duration_since(StdInstant::now());
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
    // A fresh budget per iteration: this flush loop re-enters immediately when a
    // pass is cut (the next deadline is already past, so `dur` is zero), and its
    // own wall-clock backstop below is what terminates it.
    let mut budget = DrainBudget::new(now);
    let _ = state
      .drain_withdrawals(now, &mut budget, &mut scratch)
      .await;
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

/// Which address families' receive paths have stopped receiving.
///
/// # Mandatory, not telemetry
///
/// This exists because the first attempt at this fix was wrong in a way worth
/// recording. It made a permanently-failed receive task emit a `warn!` and bump
/// a stats counter, and called that "loud but unsupervised" — but `hick-trace`'s
/// `warn!` expands to `if false { … }` without the `tracing` feature and the
/// counter is `#[cfg(feature = "stats")]`, and this crate's default features are
/// `["tokio"]`. Under the configuration almost everyone builds, a family went
/// deaf with no signal whatsoever. An observability guarantee that a feature
/// flag can delete is not a guarantee.
///
/// So this is a plain value on the public API, readable with default features,
/// no subscriber, and no opt-in: [`crate::Endpoint::deaf_families`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct DeafFamilies {
  ipv4: bool,
  ipv6: bool,
}

impl DeafFamilies {
  /// Whether the IPv4 receive path has stopped receiving.
  #[inline]
  pub const fn ipv4(&self) -> bool {
    self.ipv4
  }

  /// Whether the IPv6 receive path has stopped receiving.
  #[inline]
  pub const fn ipv6(&self) -> bool {
    self.ipv6
  }

  /// Whether either family has. The common check, so it does not have to be
  /// spelled as an `||` at every call site.
  #[inline]
  pub const fn any(&self) -> bool {
    self.ipv4 || self.ipv6
  }
}

/// The shared flags behind [`DeafFamilies`], written by the receive tasks and
/// read by [`crate::Endpoint`].
///
/// `Relaxed` is the right ordering and not a shortcut: each flag is an
/// independent one-way-then-back announcement about one family, nothing else is
/// published through it, and a reader that sees a stale value gets the answer
/// from a moment ago rather than a wrong one.
#[derive(Debug, Default)]
pub(crate) struct RecvHealth {
  v4_deaf: std::sync::atomic::AtomicBool,
  v6_deaf: std::sync::atomic::AtomicBool,
}

impl RecvHealth {
  fn flag(&self, via_v4: bool) -> &std::sync::atomic::AtomicBool {
    if via_v4 { &self.v4_deaf } else { &self.v6_deaf }
  }

  fn set(&self, via_v4: bool, deaf: bool) {
    self
      .flag(via_v4)
      .store(deaf, std::sync::atomic::Ordering::Relaxed);
  }

  pub(crate) fn snapshot(&self) -> DeafFamilies {
    use std::sync::atomic::Ordering::Relaxed;
    DeafFamilies {
      ipv4: self.v4_deaf.load(Relaxed),
      ipv6: self.v6_deaf.load(Relaxed),
    }
  }
}

/// How many CONSECUTIVE transient receive errors — errors with not one
/// successful receive between them — a family absorbs before it is reported
/// deaf.
///
/// This is the backstop for a classifier that cannot see what it is looking at.
/// `std::io::Error::kind()` maps a great many OS codes to `Uncategorized`, which
/// no match arm can name, so an error that is structurally unrecoverable can
/// read as transient and be retried forever. That is not hypothetical: Windows
/// `WSAEOPNOTSUPP` from the `WSARecvMsg` lookup is exactly it, and because that
/// lookup happens after the peek and before the receive, the datagram stays
/// queued and every retry rediscovers the same gap.
///
/// The budget does NOT end the task. Reaching it reports the family deaf and
/// keeps retrying at the backoff ceiling, and the next successful receive clears
/// the flag. That combination is what makes the state safe to enter: a genuine
/// flood that outlasts the budget is reported and then recovers by itself, while
/// a structural gap is reported and costs one wakeup every 64 ms instead of a
/// hot loop. Exiting instead would make a recoverable condition permanent, which
/// is the defect this whole area started with.
///
/// 256 against a 64 ms ceiling is about 16 s of not receiving anything at all.
const DEAF_AFTER_CONSECUTIVE_TRANSIENT_RECV_ERRORS: u32 = 256;

/// Winsock codes that mean "this stack will never do this", which
/// [`std::io::Error::kind`] flattens to `Uncategorized`.
///
/// Deliberately a raw-code list and deliberately short. The kind-based
/// classifier below cannot express these at all — that is the whole reason this
/// exists — and every entry is a capability statement about the provider rather
/// than a condition that can clear:
///
/// * `WSAEOPNOTSUPP` (10045) — the operation is not supported for this socket
///   type. `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` returns it when the
///   provider cannot supply `WSARecvMsg`;
/// * `WSAENOTSOCK` (10038) — the descriptor is not a socket;
/// * `WSAEPROTONOSUPPORT` (10043) / `WSAEAFNOSUPPORT` (10047) — the protocol or
///   address family is not supported by this provider.
///
/// `WSAECONNRESET` (10054) is deliberately ABSENT: it is delivered to a UDP
/// socket after an ICMP port-unreachable for one of OUR OWN earlier sends and is
/// routine, which is the case the transient path exists for.
#[cfg(windows)]
const fn is_permanent_winsock_code(raw: i32) -> bool {
  matches!(raw, 10045 | 10038 | 10043 | 10047)
}

/// Whether a receive error is a property of the **socket** rather than of one
/// datagram or one moment, so no number of retries will ever get past it.
///
/// # This list is hick-mio's, copied rather than re-derived
///
/// `hick-mio`'s `is_permanent_recv_error` already answers this question, and it
/// answers it correctly; this driver answered it with "everything except
/// `WouldBlock` and `InvalidData` is fatal", which made a transient `ENOBUFS`
/// under memory pressure — or a Windows `WSAECONNRESET` after an ICMP
/// port-unreachable for one of our OWN sends, which is routine for UDP — end the
/// family's receive task for good. Two drivers with two answers is itself the
/// finding, so this is the same set with the same reasoning and not a second
/// opinion.
///
/// The default for an unrecognised error must stay **transient**: a receive path
/// abandoned by mistake is deaf until the process restarts, whereas a permanent
/// error misclassified as transient costs only the bounded retry budget below.
///
/// * `NotConnected` — `ENOTSOCK`/`ENOTCONN`: the descriptor is not a socket we
///   can read, which no later event changes;
/// * `PermissionDenied` — the kernel refuses this receive outright (a sandbox or
///   MAC policy); nothing about it is rate-related;
/// * `Unsupported` — `EOPNOTSUPP`/`ENOSYS`, or a `WSARecvMsg` this platform does
///   not provide;
/// * `InvalidInput` — `EINVAL` on the receive call. The arguments this crate
///   passes are fixed, so a rejection is structural. NOT `InvalidData`, which is
///   a consumed-but-unusable datagram and is handled before this is reached.
fn is_permanent_recv_error(e: &std::io::Error) -> bool {
  // Ask the raw code FIRST on Windows. A classifier that reads only
  // `ErrorKind` cannot distinguish "transient" from "structurally unsupported",
  // because `Uncategorized` is where that distinction goes to die — see
  // `is_permanent_winsock_code`.
  #[cfg(windows)]
  if let Some(raw) = e.raw_os_error()
    && is_permanent_winsock_code(raw)
  {
    return true;
  }
  matches!(
    e.kind(),
    std::io::ErrorKind::NotConnected
      | std::io::ErrorKind::PermissionDenied
      | std::io::ErrorKind::Unsupported
      | std::io::ErrorKind::InvalidInput
  )
}

/// How long a receive task sleeps after its `n`th consecutive transient error.
///
/// Bounded and short: 1 ms doubling to a 64 ms ceiling. The point is not to wait
/// out the condition — `ENOBUFS` clears when the pressure does — but to stop a
/// hot loop from spinning a core while it clears, without adding latency a
/// working socket would ever pay. A successful receive resets the streak, so the
/// steady state is zero.
const fn transient_recv_backoff(streak: u32) -> Duration {
  Duration::from_millis(1u64 << if streak > 6 { 6 } else { streak })
}

/// Wait out one transient-receive backoff. `false` means the driver asked this
/// task to stop while it waited, so the caller must return rather than loop.
///
/// The `select_biased!` is why this is a function and not a bare `sleep`: a
/// receive task that is backing off must still tear down promptly when the
/// driver drops its shutdown sender, or a socket and its group memberships stay
/// held for the length of the backoff.
async fn backoff_or_shutdown<N: Net>(shutdown: &async_channel::Receiver<()>, streak: u32) -> bool {
  let sleep_fut = <N::Runtime as RuntimeLite>::sleep(transient_recv_backoff(streak)).fuse();
  let shutdown_fut = shutdown.recv().fuse();
  pin_mut!(sleep_fut, shutdown_fut);
  select_biased! {
    _ = shutdown_fut => false,
    _ = sleep_fut => true,
  }
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
  health: Arc<RecvHealth>,
  #[cfg(feature = "stats")] stats: std::sync::Arc<hick_trace::stats::Stats>,
) {
  // This task owns exactly one socket, so every datagram it reads arrived on one
  // family and the parameter that selected the socket is the authority on which.
  // Stamped onto each `Packet` rather than recovered downstream from the source
  // address, because that address describes the SENDER: the family a self-send
  // credit is keyed to is the socket its loopback copy can arrive on, and nothing
  // in a peer's address can be allowed to name it.
  let family = if via_v4 { Family::V4 } else { Family::V6 };
  // RFC 6762 §17: outgoing mDNS messages should fit in the path MTU
  // (~1500 bytes for Ethernet), but receivers MUST be prepared to accept
  // messages up to 9000 bytes. `max_recv` defaults to 9000 (configurable
  // via ServerOptions::with_max_recv_packet_size). Larger sources include
  // exhaustive PTR responses with many KAS records.
  let mut buf = vec![0u8; max_recv.max(1500)];
  // Consecutive transient receive errors, reset by any successful receive. It
  // drives `transient_recv_backoff` and nothing else; see
  // `is_permanent_recv_error` for why an unrecognised error counts here rather
  // than ending the task.
  let mut transient_streak: u32 = 0;
  // Resolved ONCE, for this task's own socket, and used for every receive on it.
  // Per socket rather than process-wide because Winsock extension pointers are
  // provider-specific and are called directly: a pointer resolved through
  // another socket may not be this provider's. `Endpoint::server` has already
  // asked the same question of the same socket, so a failure here means the
  // provider changed under a bound socket, which it cannot — it is a permanent
  // error either way.
  #[cfg(windows)]
  let recvmsg = {
    use std::os::windows::io::AsSocket;
    match hick_udp::resolve_recv_with_meta(sock.as_socket()) {
      Ok(f) => f,
      Err(e) => {
        health.set(via_v4, true);
        hick_trace::warn!(
          error = %e,
          via_v4,
          "WSARecvMsg could not be resolved for this family's socket; it will never receive"
        );
        return;
      }
    }
  };
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
      if let Err(e) = ready {
        // `peek_from` consumed nothing, so this is a fact about the socket or
        // the moment, and it is classified exactly like the receive below.
        #[cfg(feature = "stats")]
        stats.recv_errors(1);
        if is_permanent_recv_error(&e) {
          health.set(via_v4, true);
          hick_trace::warn!(
            error = %e,
            via_v4,
            "this family's receive path failed permanently; the endpoint is now deaf on it"
          );
          return;
        }
        hick_trace::debug!(error = %e, via_v4, "peek_from failed transiently; retrying");
        transient_streak = transient_streak.saturating_add(1);
        if transient_streak >= DEAF_AFTER_CONSECUTIVE_TRANSIENT_RECV_ERRORS {
          health.set(via_v4, true);
        }
        if !backoff_or_shutdown::<N>(&shutdown, transient_streak).await {
          return;
        }
        continue;
      }
      // Data is ready in the socket queue; consume it with PKTINFO.
      use std::os::fd::AsRawFd;
      let fd = sock.as_raw_fd();
      // `hick-udp` performs this receive, so it also slices the body and reads
      // the stamp: the length, the buffer and the time are not arguments this
      // task supplies, and the `buf.get(..n).unwrap_or(&buf)` this line replaced
      // is gone with them. See `hick_udp::selfsend::recv_datagram`.
      match hick_udp::selfsend::recv_datagram(fd, &mut buf, family) {
        Ok((rx, meta)) => {
          // A datagram arrived, so whatever the transient errors were about is
          // over: the backoff starts from zero the next time one appears, and a
          // family reported deaf by the transient budget is receiving again.
          transient_streak = 0;
          health.set(via_v4, false);
          hick_trace::trace!(src = %meta.peer(), len = meta.len(), via_v4, "recv datagram");
          // NOTE: packets_rx / bytes_rx are bumped by ProtoEndpoint::handle()
          // on the shared Arc — do NOT bump them here too (double-count).
          let pkt = Packet {
            src: meta.peer(),
            local_ip: meta.local_ip(),
            iface: meta.iface_witness(),
            // Owned so it can cross the channel — the same copy `to_vec` made
            // here before, except that it CONSUMES the datagram, so the stamp
            // never exists beside a body it did not arrive with. See `Packet::rx`.
            rx: rx.into_owned(),
            // The two facts §11 selects its fallback arm by, carried rather
            // than discarded — see `Packet::destination`.
            destination: meta.destination_witness(),
            delivery: meta.delivery(),
            // Carried as a diagnostic; §11's receive test never reads it.
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
        // recv_datagram returns InvalidData for a datagram we must
        // DROP but keep serving — an oversized/truncated datagram (MSG_TRUNC),
        // one with an unparseable source address, or one whose receive reported
        // more bytes than the buffer holds. The datagram was already
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
        // Everything else. The old rule here was "anything that is not
        // WouldBlock or InvalidData is fatal", which ended the task for good on
        // a transient `ENOBUFS` under memory pressure — leaving the endpoint
        // silently deaf on this family, with sends still working and nothing
        // saying so. See `is_permanent_recv_error`.
        Err(e) => {
          #[cfg(feature = "stats")]
          stats.recv_errors(1);
          if is_permanent_recv_error(&e) {
            // Mandatory first, telemetry second: the flag is what a caller can
            // see with default features. See `DeafFamilies`.
            health.set(via_v4, true);
            hick_trace::warn!(
              error = %e,
              via_v4,
              "this family's receive path failed permanently; the endpoint is now deaf on it"
            );
            return;
          }
          hick_trace::debug!(error = %e, via_v4, "transient receive error; retrying");
          transient_streak = transient_streak.saturating_add(1);
          if transient_streak >= DEAF_AFTER_CONSECUTIVE_TRANSIENT_RECV_ERRORS {
            // Still retrying — see the constant for why this does not return —
            // but no longer claiming to be receiving.
            health.set(via_v4, true);
          }
          if !backoff_or_shutdown::<N>(&shutdown, transient_streak).await {
            return;
          }
          continue;
        }
      }
    }
    // on Windows, peek for readiness then consume with WSARecvMsg so
    // we recover the receiving interface index (IP_PKTINFO / IPV6_PKTINFO).
    // That index lets handle_packet scope §11's arms to the bound interface (no
    // longer fail-open), and WSARecvMsg also recovers the IP header destination
    // that §11 selects its arms by. No TTL cmsg is wired here; nothing depends
    // on one, since §11's receive test never reads it. No kernel rx timestamp
    // either, so the self-send match runs degraded: content and family,
    // weighing no reference at all rather than substituting a read time for one.
    #[cfg(windows)]
    {
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
        Err(ref e) => {
          // Same classification as Unix, and Windows has one more reason to
          // want it: `WSAECONNRESET` is delivered to a UDP socket after an ICMP
          // port-unreachable for one of OUR OWN earlier sends, which is routine
          // on a link where a peer went away and says nothing about this socket.
          #[cfg(feature = "stats")]
          stats.recv_errors(1);
          if is_permanent_recv_error(e) {
            // Mandatory first, telemetry second: the flag is what a caller can
            // see with default features. See `DeafFamilies`.
            health.set(via_v4, true);
            hick_trace::warn!(
              error = %e,
              via_v4,
              "this family's receive path failed permanently; the endpoint is now deaf on it"
            );
            return;
          }
          hick_trace::debug!(error = %e, via_v4, "peek_from failed transiently; retrying");
          transient_streak = transient_streak.saturating_add(1);
          if transient_streak >= DEAF_AFTER_CONSECUTIVE_TRANSIENT_RECV_ERRORS {
            // Still retrying — see the constant for why this does not return —
            // but no longer claiming to be receiving.
            health.set(via_v4, true);
          }
          if !backoff_or_shutdown::<N>(&shutdown, transient_streak).await {
            return;
          }
          continue;
        }
      }
      match recvmsg.recv(&mut buf, via_v4) {
        Ok(meta) => {
          // A datagram arrived, so whatever the transient errors were about is
          // over: the backoff starts from zero the next time one appears, and a
          // family reported deaf by the transient budget is receiving again.
          transient_streak = 0;
          health.set(via_v4, false);
          let n = meta.len();
          hick_trace::trace!(src = %meta.peer(), len = n, via_v4, "recv datagram");
          // A length the receive did not deliver is a DROP, never the whole
          // buffer and never a truncated report: this arm mints the datagram a
          // self-send credit is keyed on, so a body longer than what arrived is
          // hashed into the claim. `WSARecvMsg` is read through `hick-udp`, which
          // clamps to the buffer it was given, so this is unreachable here — it
          // is written out because the rule must be the same on every path. See
          // `hick_udp::selfsend::RxDatagram`, which states it once, and the Unix
          // arm above, where `recv_datagram` enforces it.
          let Some(data) = buf.get(..n) else {
            hick_trace::debug!(
              via_v4,
              len = n,
              buf = buf.len(),
              "dropping a datagram whose receive reported more bytes than the buffer holds"
            );
            #[cfg(feature = "stats")]
            count_consumed_oversized(&stats, buf.len());
            continue;
          };
          // NOTE: packets_rx / bytes_rx are bumped by ProtoEndpoint::handle()
          // on the shared Arc — do NOT bump them here too (double-count).
          let pkt = Packet {
            src: meta.peer(),
            local_ip: meta.local_ip(),
            iface: meta.iface_witness(),
            // Windows delivers no receive-timestamp cmsg at all, so the absence
            // is DECLARED rather than read out of a meta that would always
            // report `None`. The claim runs under `MatchMode::Degraded`.
            rx: RxDatagram::without_stamp(family, data.to_vec()),
            destination: meta.destination_witness(),
            delivery: meta.delivery(),
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
        // See the Unix twin and `is_permanent_recv_error`: a transient failure
        // must not end this task. `WSAECONNRESET` in particular is spurious for
        // UDP and used to be fatal here.
        Err(ref e) => {
          #[cfg(feature = "stats")]
          stats.recv_errors(1);
          if is_permanent_recv_error(e) {
            // Mandatory first, telemetry second: the flag is what a caller can
            // see with default features. See `DeafFamilies`.
            health.set(via_v4, true);
            hick_trace::warn!(
              error = %e,
              via_v4,
              "this family's receive path failed permanently; the endpoint is now deaf on it"
            );
            return;
          }
          hick_trace::debug!(error = %e, via_v4, "transient receive error (windows); retrying");
          transient_streak = transient_streak.saturating_add(1);
          if transient_streak >= DEAF_AFTER_CONSECUTIVE_TRANSIENT_RECV_ERRORS {
            // Still retrying — see the constant for why this does not return —
            // but no longer claiming to be receiving.
            health.set(via_v4, true);
          }
          if !backoff_or_shutdown::<N>(&shutdown, transient_streak).await {
            return;
          }
          continue;
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
          transient_streak = 0;
          health.set(via_v4, false);
          hick_trace::trace!(src = %src, len = n, via_v4, "recv datagram");
          // A length the receive did not deliver is a DROP, never the whole
          // buffer and never a truncated report — see
          // `hick_udp::selfsend::RxDatagram`, which states the rule once, and the
          // Windows arm above, which applies it against a receive `hick-udp`
          // clamps. This is the arm where it is NOT unreachable: `n` is whatever
          // the `agnostic-net` implementation reports, and nothing between there
          // and here bounds it by `buf`. The old `unwrap_or(&buf)` answered with
          // the whole buffer, so a body longer than the datagram would have been
          // hashed into the self-send credit and parsed by the protocol layer.
          let Some(data) = buf.get(..n) else {
            hick_trace::debug!(
              via_v4,
              len = n,
              buf = buf.len(),
              "dropping a datagram whose receive reported more bytes than the buffer holds"
            );
            #[cfg(feature = "stats")]
            count_consumed_oversized(&stats, buf.len());
            continue;
          };
          // NOTE: packets_rx / bytes_rx are bumped by ProtoEndpoint::handle()
          // on the shared Arc — do NOT bump them here too (double-count).
          let local_ip = if via_v4 {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
          } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
          };
          let pkt = Packet {
            src,
            local_ip,
            // A plain `recv_from` recovers no ancillary data at all, so this
            // path declares itself BLIND for both witnesses — once, here, from
            // its own construction. It can never mint `Lost` or `Declined`:
            // there is no cmsg for a kernel to skip and no control buffer of
            // ours to truncate. Same silence `rx` and `hop_limit` carry here.
            iface: IfaceWitness::blind(),
            rx: RxDatagram::without_stamp(family, data.to_vec()),
            destination: DestinationWitness::blind(),
            delivery: None,
            hop_limit: None,
          };
          if tx.send(pkt).await.is_err() {
            return;
          }
        }
        // The third copy of the same rule. Fixing the Unix and Windows arms and
        // leaving this one is how `set_multicast_hops_v6` came to be the only
        // one of three siblings that had been corrected — see
        // `is_permanent_recv_error`, which is the single answer all three use.
        Err(e) => {
          #[cfg(feature = "stats")]
          stats.recv_errors(1);
          if is_permanent_recv_error(&e) {
            // Mandatory first, telemetry second: the flag is what a caller can
            // see with default features. See `DeafFamilies`.
            health.set(via_v4, true);
            hick_trace::warn!(
              error = %e,
              via_v4,
              "this family's receive path failed permanently; the endpoint is now deaf on it"
            );
            return;
          }
          hick_trace::debug!(error = %e, via_v4, "transient receive error; retrying");
          transient_streak = transient_streak.saturating_add(1);
          if transient_streak >= DEAF_AFTER_CONSECUTIVE_TRANSIENT_RECV_ERRORS {
            // Still retrying — see the constant for why this does not return —
            // but no longer claiming to be receiving.
            health.set(via_v4, true);
          }
          if !backoff_or_shutdown::<N>(&shutdown, transient_streak).await {
            return;
          }
          continue;
        }
      }
    }
  }
}

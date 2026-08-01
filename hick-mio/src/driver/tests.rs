use std::{
  net::{Ipv4Addr, SocketAddr, SocketAddrV4},
  time::{Duration, Instant},
};

use mdns_proto::{
  CollectedAnswer, ServiceState,
  endpoint::WithdrawalSend,
  wire::{ResourceClass, ResourceType},
};
use mio::{Poll, Token};

use super::{
  EVENT_QUEUE_COMPACT_THRESHOLD, FamilyWireGate, MAX_SEND_CREDITS_PER_DRAIN,
  RETRY_INTEREST_BACKOFF, TxQueue, datagram_cost, packet_is_response, test_support,
};
use crate::{
  endpoint::Mdns,
  error::RegisterError,
  event::{Event, EventQueue},
  socket::{Family, MDNS_V4_DST},
};

/// A distinct synthetic answer keyed by `tag`, encoded into the rdata so
/// different tags do not coalesce. Same shape as `event/tests.rs`.
fn answer(tag: u32) -> CollectedAnswer {
  CollectedAnswer::from_parts(
    ResourceType::Ptr,
    ResourceClass::In,
    tag.to_be_bytes().to_vec(),
    u64::from(tag),
  )
}

#[test]
fn idle_endpoint_reports_no_deadline() {
  let Some(mdns) = test_support::loopback_mdns() else {
    return;
  };
  // Nothing registered, nothing queued, nothing readable -> the caller may
  // block indefinitely.
  assert_eq!(mdns.next_timeout(), None);
}

#[test]
fn leftover_readable_data_forces_a_zero_timeout() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  if !mdns.sockets.is_bound_for_test(Family::V4) {
    eprintln!("skipping: IPv4 is not bound on this host");
    return;
  }
  mdns.sockets.set_readable_for_test(Family::V4, true);
  // mio's readiness is edge-triggered: data already in the socket buffer will
  // never re-notify, so this is the ONE state that must not sleep.
  assert_eq!(mdns.next_timeout(), Some(Duration::ZERO));
}

/// A refused send needs no arm of `next_timeout` at all.
///
/// It is reported to the core inside the tick that made it, so the core's own
/// re-arm deadline — which the fold already sees — is what brings the caller
/// back. An arm of its own would either spin (zero) or duplicate a schedule the
/// core already keeps.
#[test]
fn a_refused_send_leaves_no_send_side_term_in_the_timeout() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let poll = Poll::new().expect("poll");
  mdns
    .register(poll.registry(), Token(20), Token(21))
    .expect("register");
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, true);
  let report = mdns.sockets.send_to(&[0u8; 12], MDNS_V4_DST, [true, true]);
  assert_eq!(
    report.v4,
    crate::socket::SendOutcome::Failed,
    "a `WouldBlock` send handed nothing to the kernel"
  );
  assert_eq!(
    mdns.next_timeout(),
    None,
    "nothing is parked, so nothing is waiting on an event that will not come"
  );
  assert!(
    !mdns.sockets.needs_interest_retry(),
    "the send path must not ask for a registration retry"
  );
  mdns.deregister(poll.registry()).expect("deregister");
}

/// The one thing that still needs a bounded backoff: a receive re-arm that
/// failed. `readable` has just been cleared and no edge is coming, so a caller
/// that blocked indefinitely would stay deaf on that family for good.
#[test]
fn a_stale_registration_yields_a_bounded_timeout() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let poll = Poll::new().expect("poll");
  mdns
    .register(poll.registry(), Token(20), Token(21))
    .expect("register");
  mdns.sockets.force_rearm_error_for_test(Family::V4, true);
  mdns.sockets.set_readable_for_test(Family::V4, true);
  mdns.sockets.stop_reading_for_test(Family::V4);
  assert!(mdns.sockets.needs_interest_retry());
  let t = mdns
    .next_timeout()
    .expect("a family with no edge coming must not block indefinitely");
  assert!(
    t > Duration::ZERO && t <= RETRY_INTEREST_BACKOFF,
    "expected a bounded backoff in (0, {RETRY_INTEREST_BACKOFF:?}], got {t:?}"
  );
  mdns.deregister(poll.registry()).expect("deregister");
}

#[test]
fn tick_without_registration_is_a_noop() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  mdns.tick().expect("tick");
  assert!(mdns.next_event().is_none());
  assert_eq!(mdns.dropped_events(), 0);
}

/// The close of every tick retries a registration a failed receive re-arm left
/// stale, and reports it while it keeps failing. On Windows that `reregister` is
/// the only thing that regenerates a readable edge, so a tick that skipped it
/// would leave the family deaf with nothing to say so.
#[test]
fn tick_retries_a_stale_registration_and_reports_a_failure() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let poll = Poll::new().expect("poll");
  mdns
    .register(poll.registry(), Token(20), Token(21))
    .expect("register");
  mdns.sockets.force_rearm_error_for_test(Family::V4, true);
  mdns.sockets.set_readable_for_test(Family::V4, true);
  mdns.sockets.stop_reading_for_test(Family::V4);

  let before = mdns.sockets.reregisters_for_test(Family::V4);
  mdns.sockets.force_rearm_error_for_test(Family::V4, false);
  mdns.tick().expect("tick");
  assert_eq!(
    mdns.sockets.reregisters_for_test(Family::V4),
    before.saturating_add(1),
    "the tick must issue a real reregister, which is the re-arm itself"
  );
  assert!(!mdns.sockets.needs_interest_retry());
  mdns.deregister(poll.registry()).expect("deregister");
}

#[test]
fn registering_a_service_schedules_a_deadline() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let spec = test_support::service_spec("_hick-mio-test._tcp.local.", 8080);
  let handle = mdns.register_service(spec).expect("register_service");
  let ctx = mdns.services.get(&handle).expect("the service context");
  // A freshly registered service carries its own §8.1 probe deadline, so the
  // fold alone is enough to bring the caller back — no zero-timeout override
  // is needed for it, unlike a freshly started query.
  assert!(
    ctx.proto.poll_timeout().is_some(),
    "a freshly registered service must be scheduled to probe"
  );
  // The tripwire for that rule: `work_pending` is queries-only. Without this,
  // both assertions above still pass if someone sets it in `register_service`,
  // and the real probe deadline would be silently replaced by a zero timeout.
  assert!(
    !mdns.work_pending,
    "register_service must rely on the probe deadline, not force a zero timeout"
  );
  assert!(mdns.next_timeout().is_some());
}

/// A freshly started query must yield `Some(ZERO)`, never `None`.
///
/// `Query::try_new` arms `transmit_pending` with `next_deadline = None`, so
/// `Endpoint::poll_query_timeout` reports nothing until the first send is
/// confirmed and the §5.2 backoff is scheduled. Folding only the state
/// machines' deadlines therefore yields `None` — telling the caller to block
/// indefinitely on a question that never goes out. This test pins the fold's
/// emptiness *and* the non-`None` result, so it fails on either half of that
/// reasoning breaking.
#[test]
fn a_fresh_query_forces_a_zero_timeout_not_none() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let spec = test_support::query_spec("_hick-mio-due._tcp.local.");
  let handle = mdns.start_query(spec).expect("start_query");

  // Every input the deadline fold has is empty, so the fold alone is `None`.
  assert_eq!(
    mdns.endpoint.poll_timeout(),
    None,
    "the endpoint has nothing scheduled"
  );
  assert_eq!(
    mdns.endpoint.poll_query_timeout(handle),
    None,
    "the proto layer reports no deadline before the first send"
  );
  assert!(mdns.services.is_empty(), "no service deadline is in play");

  let timeout = mdns.next_timeout();
  assert!(
    timeout.is_some(),
    "a fresh query must never yield None: the caller would block forever on a \
     question that never goes out"
  );
  assert_eq!(timeout, Some(Duration::ZERO));

  // One tick performs the work, which is what stops the flag latching into a
  // 100%-CPU spin: the send arms the retry backoff and the caller may sleep.
  mdns.tick().expect("tick");
  assert!(
    mdns.endpoint.poll_query_timeout(handle).is_some(),
    "the first send must arm the retry backoff"
  );
  assert!(
    mdns.next_timeout().is_some_and(|d| d > Duration::ZERO),
    "with the question sent, the caller may sleep until the retry"
  );
}

#[test]
fn cancelling_a_query_removes_its_deadline() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let spec = test_support::query_spec("_hick-mio-test._tcp.local.");
  let handle = mdns.start_query(spec).expect("start_query");
  assert!(mdns.next_timeout().is_some());
  mdns.tick().expect("tick");
  assert!(mdns.next_timeout().is_some());
  mdns.cancel_query(handle);
  assert!(mdns.queries.is_empty());
  assert_eq!(mdns.next_timeout(), None);
}

#[test]
fn sweep_drops_a_context_the_proto_layer_already_retired() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let handle = mdns
    .start_query(test_support::query_spec("_hick-mio-sweep._tcp.local."))
    .expect("start_query");
  // Retire the query behind the driver's back, exactly as a proto-side
  // cancellation would, and let the sweep collect the orphaned context.
  assert!(mdns.endpoint.cancel_query(handle).is_ok());
  assert!(mdns.queries.contains_key(&handle));
  mdns.sweep();
  assert!(
    mdns.queries.is_empty(),
    "sweep must drop a context whose proto query is gone"
  );
}

#[test]
fn tick_bounds_the_event_queues_physical_length() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  // Mint a real handle (there is no public `QueryHandle` constructor), then
  // cancel it so this test drives only the queue, never the transmit path.
  let handle = mdns
    .start_query(test_support::query_spec("_hick-mio-flood._tcp.local."))
    .expect("start_query");
  mdns.cancel_query(handle);

  // A flooding peer plus a caller that never drains: the LOGICAL queue is
  // capped by `ANSWER_CAPACITY`, but every evicted answer leaves a tombstone in
  // the physical backing store until `pop` reaches it — and nothing here ever
  // pops.
  let batch = EventQueue::ANSWER_CAPACITY;
  let mut tag = 0u32;
  for _ in 0..8 {
    for _ in 0..batch {
      mdns.events.push_answer(handle, answer(tag));
      tag += 1;
    }
    mdns.tick().expect("tick");
  }

  assert_eq!(mdns.events.len(), EventQueue::ANSWER_CAPACITY);
  assert!(
    mdns.events.physical_len() <= EVENT_QUEUE_COMPACT_THRESHOLD,
    "physical length {} grew past the compaction threshold {EVENT_QUEUE_COMPACT_THRESHOLD}",
    mdns.events.physical_len(),
  );
}

#[test]
fn next_timeout_never_overshoots_the_earliest_deadline() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-fold._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns
    .start_query(test_support::query_spec("_hick-mio-fold._tcp.local."))
    .expect("start_query");
  // Send the question so the query has a real deadline and the zero-timeout
  // override is no longer in play; the fold is what is under test here.
  mdns.tick().expect("tick");
  // Both zero-timeout overrides must be off, or `folded` is `ZERO` and the
  // comparison below passes without exercising the fold at all.
  assert!(
    !mdns.work_pending,
    "the fold, not the work-pending override"
  );
  assert!(
    !mdns.sockets.has_readable(),
    "the fold, not the readable override"
  );
  // Sampled BEFORE `next_timeout`, which takes its own (later) `now`: folding
  // against a later instant would make every comparison trivially pass.
  let now = Instant::now();
  let folded = mdns.next_timeout().expect("a folded deadline");
  let earliest = mdns
    .services
    .values()
    .filter_map(|ctx| ctx.proto.poll_timeout())
    .chain(
      mdns
        .queries
        .keys()
        .filter_map(|h| mdns.endpoint.poll_query_timeout(*h)),
    )
    .chain(mdns.endpoint.poll_timeout())
    .min()
    .expect("at least one deadline");
  assert!(
    folded <= earliest.saturating_duration_since(now),
    "next_timeout ({folded:?}) must not overshoot the earliest deadline"
  );
}

/// The IPv4-only fixture fixes the outcome on every platform: IPv4 is bound,
/// IPv6 is absent by construction rather than by accident of what this host
/// bound.
#[test]
fn a_multicast_send_takes_one_credit_per_family_that_reached_the_wire() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let now = Instant::now();
  let body = [0x5Au8; 20];
  let mut gate = FamilyWireGate::default();
  let Mdns {
    sockets,
    selfsend,
    send_health,
    ..
  } = &mut *mdns;
  let before = selfsend.len();
  let summary = super::send_and_credit(
    sockets,
    selfsend,
    send_health,
    &mut gate,
    &body,
    MDNS_V4_DST,
    Duration::ZERO,
    now,
  );
  assert_eq!(summary.sent, 1, "one bound family, one syscall");
  assert_eq!(
    selfsend.len() - before,
    1,
    "the credit is taken at the syscall that produced the loopback copy"
  );
  assert!(summary.accepted_at.is_some());
  assert!(summary.delivery.all_delivered());
  // Take it back with the body: the credit is keyed to the family that carried
  // it and to the fingerprint of what went out.
  assert!(selfsend.take(
    Family::V4,
    &body,
    std::time::SystemTime::now(),
    crate::selfsend::MatchMode::Degraded
  ));
}

/// A refused send takes no credit and reports the family `Missed`, inside the
/// same call. There is no later moment at which either could change: nothing
/// reached the kernel, so no loopback copy is coming and the core may re-arm
/// the datagram immediately.
#[test]
fn a_refused_send_takes_no_credit_and_reports_the_family_missed() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, true);
  let now = Instant::now();
  let mut gate = FamilyWireGate::default();
  let Mdns {
    sockets,
    selfsend,
    send_health,
    ..
  } = &mut *mdns;
  let summary = super::send_and_credit(
    sockets,
    selfsend,
    send_health,
    &mut gate,
    &[0x5Au8; 20],
    MDNS_V4_DST,
    Duration::ZERO,
    now,
  );
  assert_eq!(summary.sent, 0);
  assert_eq!(summary.accepted_at, None);
  assert_eq!(
    summary.delivery.v4(),
    mdns_proto::FamilyDelivery::Missed,
    "the family was obligated and did not carry it"
  );
  assert_eq!(
    mdns.selfsend.len(),
    0,
    "nothing reached the kernel, so no loopback copy will come back"
  );
}

/// The per-family wire gate, end to end through the socket layer: a producer's
/// second datagram inside the core's own minimum gap is not offered to the
/// family that has just carried one, and is reported `Missed` rather than
/// absent.
#[test]
fn a_families_wire_gate_withholds_a_second_datagram_inside_the_minimum_gap() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let now = Instant::now();
  let gap = Duration::from_secs(1);
  let mut gate = FamilyWireGate::default();
  let Mdns {
    sockets,
    selfsend,
    send_health,
    ..
  } = &mut *mdns;
  let first = super::send_and_credit(
    sockets,
    selfsend,
    send_health,
    &mut gate,
    &[0x5Au8; 20],
    MDNS_V4_DST,
    gap,
    now,
  );
  assert_eq!(first.sent, 1, "the first datagram owes no gap");

  let credits = selfsend.len();
  let second = super::send_and_credit(
    sockets,
    selfsend,
    send_health,
    &mut gate,
    &[0x5Au8; 20],
    MDNS_V4_DST,
    gap,
    now,
  );
  assert_eq!(second.sent, 0, "no syscall was made for the gated family");
  assert_eq!(
    second.delivery.v4(),
    mdns_proto::FamilyDelivery::Missed,
    "the socket is there and the datagram was meant for it; reporting it \
     absent would let the phase advance without the wire"
  );
  assert_eq!(
    selfsend.len(),
    credits,
    "a datagram that was never sent produces no loopback copy"
  );
  assert_eq!(
    send_health.degraded_families(),
    (false, false),
    "a deliberate deferral is no evidence at all about the link"
  );
}

/// A **unicast** reply takes no self-send credit.
///
/// It leaves for the querier's own address and never comes back through a group
/// we joined, so the credit could only ever expire unclaimed — and the tracker
/// declines a NEW entry at `MAX_SELF_SEND_ENTRIES` rather than evicting a live
/// one, so an on-link legacy-query flood would fill it with unclaimable credits
/// and then refuse the genuine multicast ones.
#[test]
fn a_unicast_reply_takes_no_self_send_credit() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let unicast = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353));
  let now = Instant::now();
  let mut gate = FamilyWireGate::default();
  let Mdns {
    sockets,
    selfsend,
    send_health,
    ..
  } = &mut *mdns;
  let summary = super::send_and_credit(
    sockets,
    selfsend,
    send_health,
    &mut gate,
    &[0x5Au8; 20],
    unicast,
    Duration::ZERO,
    now,
  );
  assert_eq!(summary.sent, 1, "the unicast reply really did go out");
  assert_eq!(selfsend.len(), 0, "and it will never come back");
  assert!(
    summary.delivery.all_delivered(),
    "exactly one family is obligated by a unicast destination"
  );
}

#[test]
fn a_fresh_endpoint_is_idle() {
  let Some(mdns) = test_support::loopback_mdns() else {
    return;
  };
  // Nothing registered, nothing withdrawing, nothing parked: a caller that
  // shuts an untouched endpoint down may stop looping at once.
  assert!(mdns.is_idle());
}

#[test]
fn shutdown_with_a_live_service_is_not_immediately_idle() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-bye._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns.shutdown();
  assert!(!mdns.is_idle(), "a withdrawal is in flight");
  // The withdrawal deadline must reach the fold, or the caller's `Poll::poll`
  // would park past the round that has to go out.
  assert!(mdns.next_timeout().is_some());
}

#[test]
fn shutdown_rejects_new_registrations() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  mdns.shutdown();
  assert!(
    mdns
      .register_service(test_support::service_spec(
        "_hick-mio-late._tcp.local.",
        8080
      ))
      .is_err(),
    "a registration accepted after shutdown would never be withdrawn"
  );
}

#[test]
fn shutdown_drives_to_idle_within_a_bounded_number_of_ticks() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-bye2._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns.shutdown();
  // Each withdrawal ends when its per-family resend budget is spent or at its
  // 2 s anti-pin ceiling, so ticking past that must reach idle. Five seconds is
  // two ceilings of slack, not a timing assertion.
  let deadline = Instant::now() + Duration::from_secs(5);
  while !mdns.is_idle() && Instant::now() < deadline {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(20));
  }
  assert!(mdns.is_idle(), "shutdown must terminate");
  assert!(
    mdns.services.is_empty(),
    "a completed withdrawal must GC its driver context"
  );
}

/// The per-family debt mapping, on its decisive case: an **absent** family is
/// written off so its debt cannot pin the withdrawal past the other family,
/// while a **present** one is never written off no matter how its send went.
///
/// Uses the IPv4-only fixture so "IPv6 is absent" is a property of the options,
/// not of whether this host happened to bind IPv6.
#[test]
fn an_absent_family_is_written_off_and_a_present_one_never_is() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let Mdns {
    sockets,
    selfsend,
    send_health,
    ..
  } = &mut *mdns;
  let (v4, v6) = super::withdrawal::send_withdrawal(sockets, selfsend, send_health, &[0x5Au8; 20]);
  assert_eq!(
    v6,
    WithdrawalSend::WriteOff,
    "an unbound family has no peers to withdraw from; its debt must not pin the route"
  );
  assert_ne!(
    v4,
    WithdrawalSend::WriteOff,
    "a bound family must keep its debt until it sends or the ceiling frees it"
  );
}

/// A bound family the socket refused still **owes** its goodbye. Mapping that
/// to a write-off would free the route while this family's peers stay pinned to
/// stale positive-TTL records.
#[test]
fn a_refused_family_keeps_its_goodbye_debt() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, true);
  let Mdns {
    sockets,
    selfsend,
    send_health,
    ..
  } = &mut *mdns;
  let (v4, _v6) = super::withdrawal::send_withdrawal(sockets, selfsend, send_health, &[0x5Au8; 20]);
  assert_eq!(
    v4,
    WithdrawalSend::Retry,
    "nothing reached this family's wire, so its debt must survive to the next \
     scheduled round"
  );
  assert_eq!(
    selfsend.len(),
    0,
    "a goodbye that was never sent produces no loopback copy"
  );
}

/// A withdrawal datagram loops back exactly like any other multicast transmit,
/// so every family that will hand a copy back needs exactly one take-once credit
/// — otherwise the responder ingests its own goodbye as a peer datagram and
/// raises a phantom conflict against itself.
///
/// Stated as `credits == sent` against a **computed** `sent`: a literal would
/// encode whether this host bound IPv6 and whether its multicast egress works,
/// both of which differ between macOS and Linux CI. This is the test that
/// covers the real-syscall arm; the refusing arm is
/// [`a_refused_family_keeps_its_goodbye_debt`].
#[test]
fn a_withdrawal_datagram_takes_one_self_send_credit_per_syscall() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let Mdns {
    sockets,
    selfsend,
    send_health,
    ..
  } = &mut *mdns;
  let before_credits = selfsend.len();
  let (v4, v6) = super::withdrawal::send_withdrawal(sockets, selfsend, send_health, &[0x5Au8; 20]);

  let credits = selfsend.len() - before_credits;
  let sent = [v4, v6]
    .into_iter()
    .filter(|o| *o == WithdrawalSend::Sent)
    .count();
  assert_eq!(
    credits, sent,
    "every family that put a copy on the wire needs exactly one credit, and no other family does"
  );
  if sent == 0 {
    eprintln!("note: no family put the goodbye on the wire here; the syscall arm is unexercised");
  }
}

/// Unregistering holds the name until the goodbye settles, then `tick` frees
/// both halves together: the proto route and the driver context that stayed
/// resident on purpose.
#[test]
fn drain_withdrawals_gcs_a_completed_services_context() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec("_hick-mio-gc._tcp.local.", 8080))
    .expect("register_service");
  mdns.unregister_service(handle);
  assert!(
    mdns.services.contains_key(&handle),
    "the context stays resident while the endpoint still holds the name"
  );
  assert!(mdns.endpoint.has_pending_withdrawals());
  // Never announced, so the goodbye owes nothing and settles on the first pass.
  mdns.tick().expect("tick");
  assert!(!mdns.endpoint.has_pending_withdrawals());
  assert!(
    mdns.services.is_empty(),
    "a completed withdrawal must GC its driver context"
  );
}

/// A service that actually put records on the wire owes a MULTI-round goodbye,
/// so one pass cannot finish it. This is what separates a real §10.1 schedule
/// from the never-announced shortcut every other test here takes.
#[test]
fn an_announced_service_owes_more_than_one_goodbye_round() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-owed._tcp.local.",
      8080,
    ))
    .expect("register_service");
  // Probing is real wall-clock work (RFC 6762 §8.1: three probes 250 ms apart),
  // so drive the loop until the service has confirmed-emitted its records.
  let deadline = Instant::now() + Duration::from_secs(5);
  let mut advertised = false;
  while Instant::now() < deadline {
    mdns.tick().expect("tick");
    if mdns
      .services
      .get(&handle)
      .is_some_and(|ctx| ctx.proto.advertises_instance())
    {
      advertised = true;
      break;
    }
    std::thread::sleep(Duration::from_millis(20));
  }
  if !advertised {
    eprintln!("skipping: the service never reached its announce within the budget");
    return;
  }

  mdns.shutdown();
  mdns.tick().expect("tick");
  // One delivered round spends ONE of the three owed sends, so the withdrawal
  // must still be live. A pass that finished here would mean the goodbye was
  // treated as fully paid after a single datagram.
  assert!(
    mdns.endpoint.has_pending_withdrawals(),
    "an announced service owes a multi-round goodbye, not a single datagram"
  );
  assert!(!mdns.is_idle());
}

/// A delivered §10.1 round (at least one bound family reported `Sent`) must
/// bump `goodbyes_tx` exactly once **per round**, at `drain_withdrawals`'s
/// level — not inside `send_withdrawal`, which already accounts for
/// `packets_tx` / `bytes_tx` / `send_errors` per family. The regression it
/// guards is a real one: `goodbyes_tx` was once bumped nowhere in the crate,
/// which no other test here can see.
///
/// Reuses `an_announced_service_owes_more_than_one_goodbye_round`'s "wait for
/// `advertises_instance`" gate: that proves a real `send_to` already
/// succeeded on this endpoint's own socket, so the withdrawal's sends
/// (same socket, same process, moments later) are expected to succeed too —
/// the same assumption `tests/loopback.rs`'s `advertise` helper relies on.
#[test]
#[cfg(feature = "stats")]
fn a_delivered_withdrawal_round_bumps_goodbyes_tx() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-goodbye-stats._tcp.local.",
      8080,
    ))
    .expect("register_service");
  let deadline = Instant::now() + Duration::from_secs(5);
  let mut advertised = false;
  while Instant::now() < deadline {
    mdns.tick().expect("tick");
    if mdns
      .services
      .get(&handle)
      .is_some_and(|ctx| ctx.proto.advertises_instance())
    {
      advertised = true;
      break;
    }
    std::thread::sleep(Duration::from_millis(20));
  }
  if !advertised {
    eprintln!("skipping: the service never reached its announce within the budget");
    return;
  }

  mdns.shutdown();
  let before = mdns.stats().goodbyes_tx;
  let deadline = Instant::now() + Duration::from_secs(5);
  while !mdns.is_idle() && Instant::now() < deadline {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(20));
  }
  assert!(mdns.is_idle(), "shutdown must terminate");
  assert!(
    mdns.stats().goodbyes_tx > before,
    "an announced service's withdrawal must deliver at least one round and bump goodbyes_tx"
  );
}

/// The untrusted-response guard drops a QR=1 datagram from a non-5353 source
/// port before it can burn a take-once self-send credit. `packet_is_response`
/// is the whole of its classification, and it is pure — no socket needed.
/// Ported from `hick-reactor/src/driver/tests.rs`'s
/// `packet_is_response_reads_qr_bit`.
#[test]
fn packet_is_response_reads_qr_bit() {
  // The QR bit is the MSB of header byte 2.
  assert!(packet_is_response(&[0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
  assert!(!packet_is_response(&[
    0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0
  ]));
  // Too short to hold a header: not a response, so the guard leaves it to the
  // proto layer's parser to reject rather than dropping it as untrusted.
  assert!(!packet_is_response(&[0, 0]));
  assert!(!packet_is_response(&[]));
}

// ── RFC 6762 §9 rename: the old name's TTL=0 goodbye ────────────────────────
//
// A rename leaves the OLD instance name in every peer's cache. The proto layer
// parks its retraction as a ONE-SHOT handoff at the moment it renames, so the
// driver has exactly one chance to take it: miss it and that name stays
// advertised for its whole positive TTL, and the next rename overwrites the
// parked handoff so the first name's retraction is lost outright.

/// Drive `mdns`, feeding `probe` on every iteration, until it reports a §9
/// rename. Returns the new instance name.
///
/// The probe is injected on every iteration rather than once because the
/// tiebreak that renames an *announced* service takes two rounds: the §9
/// conflict first reverts it to probing, and only a conflict observed while it
/// is probing loses the §8.2 comparison.
fn drive_to_rename(mdns: &mut Mdns, probe: &[u8]) -> Option<String> {
  let deadline = Instant::now() + Duration::from_secs(10);
  while Instant::now() < deadline {
    test_support::ingest(mdns, probe, Instant::now());
    mdns.tick().expect("tick");
    while let Some(ev) = mdns.next_event() {
      if let Event::Service {
        update: mdns_proto::ServiceUpdate::Renamed(renamed),
        ..
      } = ev
      {
        return Some(renamed.new_name().as_str().to_string());
      }
    }
    std::thread::sleep(Duration::from_millis(20));
  }
  None
}

/// Every goodbye the endpoint still owes, read far enough into the future that
/// the resend interval has elapsed.
///
/// `tick` has already pumped and confirmed this withdrawal's first round by the
/// time a rename is observed — stage 7 runs in the same tick as stage 5 — and a
/// confirmed round re-arms 250 ms out. Reading at `now` would therefore collect
/// nothing at all; the offset picks up the next round, which encodes the same
/// records.
fn goodbyes_now(mdns: &mut Mdns) -> Vec<Vec<u8>> {
  test_support::collect_goodbyes(mdns, Instant::now() + Duration::from_millis(400))
}

/// A rename the service **survives** still owes its old instance name a TTL=0
/// retraction. Nothing else will ever send one: the service is alive under a new
/// name, so no withdrawal is begun for it, and the one-shot handoff is gone the
/// moment the next rename overwrites it.
///
/// Also pins the retention: the old name is **held** until that retraction is
/// paid, and released the moment it is. Held is not permanent, and this is the
/// half a wrong fix in the other direction gets backwards.
#[test]
fn a_surviving_rename_holds_the_old_name_until_its_retraction_is_paid() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let ty = "_hick-mio-rn1._tcp.local.";
  let old = format!("survivor.{ty}");
  let handle = mdns
    .register_service(test_support::named_service_spec("survivor", ty, 8080))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }

  let probe = test_support::conflict_probe(&old);
  let Some(new_name) = drive_to_rename(&mut mdns, &probe) else {
    eprintln!("skipping: the service never renamed within the budget");
    return;
  };
  assert_ne!(new_name, old, "a rename must change the instance name");
  assert!(
    !mdns
      .services
      .get(&handle)
      .expect("a survived rename keeps its context")
      .withdrawing,
    "this must be the SURVIVING path; a collision teardown would prove nothing about it"
  );

  assert!(
    mdns.endpoint.has_pending_withdrawals(),
    "a surviving rename must leave the old name's goodbye owed"
  );
  // Read past the resend interval: this tick has already pumped and confirmed
  // the first round, and a confirmed round re-arms 250 ms out.
  let first_round = Instant::now() + Duration::from_millis(400);
  let goodbyes = test_support::collect_goodbyes(&mut mdns, first_round);
  assert!(
    goodbyes.iter().any(|d| test_support::retracts(d, &old)),
    "the renamed-away name must go out as a TTL=0 retraction; got {} datagram(s)",
    goodbyes.len()
  );

  assert!(
    matches!(
      mdns.register_service(test_support::named_service_spec("survivor", ty, 9090)),
      Err(RegisterError::NameAlreadyRegistered(_))
    ),
    "the vacated name must be held while its retraction is still owed"
  );

  // Released as soon as the debt is settled: the hold is the length of the
  // goodbye schedule, not of the endpoint.
  test_support::settle_goodbyes(&mut mdns, first_round);
  mdns
    .register_service(test_support::named_service_spec("survivor", ty, 9090))
    .expect("a paid-off retraction must release the old name");
}

/// **The per-family case.** A goodbye that reached IPv4 but not IPv6 has not
/// been paid, and the vacated name must stay held until it is.
///
/// Cancelling the retraction on the replacement's announcement instead cannot be
/// made safe: the cancellation is all-or-nothing while the debt is per family,
/// and "the replacement supersedes it" is false for any record the replacement
/// does not carry. This service advertises a subtype browse PTR and its
/// replacement does not, so that PTR is retracted by the goodbye or by nothing
/// at all — it would stay live in every IPv6 peer's cache for its whole positive
/// TTL.
///
/// The IPv6 failure is injected as a per-family withdrawal outcome rather than
/// staged on a socket: no socket can be made to fail on demand, and the debt is
/// the thing under test.
#[test]
fn an_unpaid_ipv6_retraction_holds_the_old_name_against_immediate_reuse() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let (v4, v6) = mdns.bound_families();
  if !v4 || !v6 {
    eprintln!("note: this host bound (v4={v4}, v6={v6}); the unpaid family is injected either way");
  }
  let ty = "_hick-mio-rn4._tcp.local.";
  let old = format!("reuse.{ty}");
  let subtype_browse = format!("_printer._sub.{ty}");
  let handle = mdns
    .register_service(test_support::subtyped_service_spec(
      "reuse", ty, "_printer", 8080,
    ))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }

  let probe = test_support::conflict_probe(&old);
  if drive_to_rename(&mut mdns, &probe).is_none() {
    eprintln!("skipping: the service never renamed within the budget");
    return;
  }

  // IPv4 pays, IPv6 fails, round after round: v4's debt runs out and v6's never
  // does, which is exactly the state a same-name reuse must not be able to
  // discard.
  let base = Instant::now();
  let mut last_round = base;
  let mut retracted_subtype = false;
  for round in 1..=4u32 {
    let at = base + Duration::from_millis(260 * u64::from(round));
    last_round = at;
    for datagram in
      test_support::collect_goodbyes_as(&mut mdns, at, WithdrawalSend::Sent, WithdrawalSend::Retry)
    {
      retracted_subtype |= test_support::retracts(&datagram, &subtype_browse);
    }
  }
  assert!(
    retracted_subtype,
    "the goodbye must retract the subtype browse PTR — nothing else ever will"
  );
  assert!(
    mdns.endpoint.has_pending_withdrawals(),
    "IPv6 never sent, so the retraction is still owed"
  );

  assert!(
    matches!(
      mdns.register_service(test_support::named_service_spec("reuse", ty, 9090)),
      Err(RegisterError::NameAlreadyRegistered(_))
    ),
    "a replacement must not be able to reclaim the name while IPv6 still owes its retraction"
  );

  // IPv6 recovers inside the ceiling and pays what it owed; only then is the
  // name free.
  test_support::settle_goodbyes(&mut mdns, last_round);
  mdns
    .register_service(test_support::named_service_spec("reuse", ty, 9090))
    .expect("once every family has retracted, the name is reclaimable");
}

/// Consecutive renames each owe their own retraction. The handoff is one-shot
/// and the proto overwrites it on the next rename, so a driver that takes it
/// late — or not at all — retracts the second name and silently strands the
/// first.
#[test]
fn consecutive_renames_each_retract_their_own_old_name() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let ty = "_hick-mio-rn2._tcp.local.";
  let first = format!("serial.{ty}");
  let handle = mdns
    .register_service(test_support::named_service_spec("serial", ty, 8080))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }

  let probe = test_support::conflict_probe(&first);
  let Some(second) = drive_to_rename(&mut mdns, &probe) else {
    eprintln!("skipping: the service never renamed within the budget");
    return;
  };
  let round_one = goodbyes_now(&mut mdns);
  assert!(
    round_one.iter().any(|d| test_support::retracts(d, &first)),
    "the first rename must retract the first name"
  );

  // The service re-probes and re-announces under its new name; only an
  // announced name has anything for peers to evict, so the second rename has a
  // handoff to lose only after this.
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }
  let probe = test_support::conflict_probe(&second);
  let Some(third) = drive_to_rename(&mut mdns, &probe) else {
    eprintln!("skipping: the service never renamed a second time within the budget");
    return;
  };
  assert_ne!(
    third, second,
    "the second rename must change the name again"
  );
  let round_two = goodbyes_now(&mut mdns);
  assert!(
    round_two.iter().any(|d| test_support::retracts(d, &second)),
    "the second rename must retract the second name, not lose it to the overwritten handoff"
  );
}

/// A rename whose new name collides with another local registration tears the
/// service down — and its old name must then be **held** until the retraction
/// completes, so a same-name re-registration cannot cancel the only TTL=0 that
/// name will ever get.
///
/// The mirror of the surviving case, and what stops the fix being "always pass
/// reclaimable": the retention flag is the rename's own outcome, not a constant.
#[test]
fn a_colliding_rename_holds_the_old_name_until_it_is_retracted() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let ty = "_hick-mio-rn3._tcp.local.";
  let old = format!("clash.{ty}");
  // Owns the name the rename will reach for, so the rebrand collides locally.
  mdns
    .register_service(test_support::named_service_spec("clash-1", ty, 9090))
    .expect("register the rival");
  let handle = mdns
    .register_service(test_support::named_service_spec("clash", ty, 8080))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }

  let probe = test_support::conflict_probe(&old);
  let deadline = Instant::now() + Duration::from_secs(10);
  let mut conflicted = false;
  while Instant::now() < deadline && !conflicted {
    test_support::ingest(&mut mdns, &probe, Instant::now());
    mdns.tick().expect("tick");
    while let Some(ev) = mdns.next_event() {
      if let Event::Service { handle: h, update } = ev
        && h == handle
        && update.is_conflict()
      {
        conflicted = true;
      }
    }
    std::thread::sleep(Duration::from_millis(20));
  }
  if !conflicted {
    eprintln!("skipping: the rename never collided within the budget");
    return;
  }

  assert!(
    matches!(
      mdns.register_service(test_support::named_service_spec("clash", ty, 7070)),
      Err(RegisterError::NameAlreadyRegistered(_))
    ),
    "a colliding rename must HOLD the old name until its retraction completes"
  );
  let goodbyes = goodbyes_now(&mut mdns);
  assert!(
    goodbyes.iter().any(|d| test_support::retracts(d, &old)),
    "the torn-down service's old name must still be retracted"
  );
}

// ── transmit fairness ───────────────────────────────────────────────────────
//
// A per-tick budget bounds the work inside one tick and says nothing about
// whose work it is, nor about the next tick. These pin the two mechanisms that
// do: the per-slot quantum, and the service sequence that makes a sender's
// queue position independent of its handle.
//
// Deliberately socket-free. Every one of them drives the production scheduler
// ([`TxQueue::serve`]) over a fake population that charges the budget through
// the production [`datagram_cost`], so a change to either shows up here rather
// than being modelled around.

/// One fake sender, shaped like a real one: a queue position it does not choose,
/// a backlog, and a family fan-out.
#[derive(Debug)]
struct FakeSender {
  /// Identity. Deliberately unrelated to queue position — that is the property
  /// under test.
  id: u32,
  /// Queue position, only ever assigned by [`TxQueue`].
  seq: u64,
  /// Datagrams still due. `usize::MAX` is a sender that never stops.
  due: usize,
  /// Bound families each of its multicast transmits fans out to.
  families: usize,
  /// Datagrams it has produced, over every tick.
  produced: usize,
}

/// A population of fake senders driven through the production scheduler.
#[derive(Debug)]
struct FakePopulation {
  senders: Vec<FakeSender>,
  queue: TxQueue,
  /// The ring `drain_transmits` rebuilds each tick, kept to mirror its reuse.
  ring: Vec<(u64, u32)>,
  /// `send_to` syscalls issued across every tick — datagrams times fan-out.
  syscalls: usize,
  /// Ids offered a turn during the most recent tick, in the order they were.
  visited: Vec<u32>,
}

impl FakePopulation {
  fn new() -> Self {
    Self {
      senders: Vec::new(),
      queue: TxQueue::new(),
      ring: Vec::new(),
      syscalls: 0,
      visited: Vec::new(),
    }
  }

  /// Register a sender, exactly as `register_service` / `start_query` do: it
  /// takes the queue's next sequence and so joins at the tail.
  fn add(&mut self, id: u32, due: usize, families: usize) {
    let seq = self.queue.join();
    self.senders.push(FakeSender {
      id,
      seq,
      due,
      families,
      produced: 0,
    });
  }

  fn cancel(&mut self, id: u32) {
    self.senders.retain(|s| s.id != id);
  }

  fn sender(&self, id: u32) -> &FakeSender {
    self
      .senders
      .iter()
      .find(|s| s.id == id)
      .expect("a live sender")
  }

  /// One `drain_transmits` worth of work. Returns what the drain would set
  /// `work_pending` to.
  ///
  /// The body of `visit` mirrors the per-sender loop in `drain_transmits`
  /// statement for statement — quantum guard, one datagram per iteration, one
  /// `send_to` per bound family, and the charge taken from the production
  /// [`datagram_cost`] — so a test here says something about the real drain and
  /// not about a model of it.
  fn tick(&mut self) -> bool {
    let Self {
      senders,
      queue,
      ring,
      syscalls,
      visited,
    } = self;
    ring.clear();
    ring.extend(senders.iter().map(|s| (s.seq, s.id)));
    visited.clear();
    queue.serve(
      ring.as_mut_slice(),
      MAX_SEND_CREDITS_PER_DRAIN,
      |id, quantum, next_seq| {
        visited.push(id);
        let Some(s) = senders.iter_mut().find(|s| s.id == id) else {
          return (0, false);
        };
        s.seq = next_seq;
        let mut spent = 0usize;
        loop {
          if spent >= quantum {
            return (spent, true);
          }
          if s.due == 0 {
            return (spent, false);
          }
          s.due = s.due.saturating_sub(1);
          s.produced = s.produced.saturating_add(1);
          let families_sent = s.families;
          *syscalls = syscalls.saturating_add(families_sent);
          spent = spent.saturating_add(datagram_cost(families_sent));
        }
      },
    )
  }
}

/// Every sender is offered a share of one budget, so a sender that never stops
/// producing cannot spend another's.
#[test]
fn a_firehose_sender_cannot_spend_another_senders_share() {
  let mut pop = FakePopulation::new();
  pop.add(0, usize::MAX, 1);
  pop.add(1, usize::MAX, 1);
  let left_behind = pop.tick();

  assert!(
    pop.sender(0).produced > 0 && pop.sender(1).produced > 0,
    "an insatiable first sender must not consume the whole budget"
  );
  assert_eq!(
    pop.sender(0).produced + pop.sender(1).produced,
    MAX_SEND_CREDITS_PER_DRAIN,
    "the two shares must add up to exactly one budget"
  );
  assert!(
    left_behind,
    "a sender cut off at its quantum may still owe a datagram"
  );
}

/// A single busy sender still gets the whole budget: the fair share is of what
/// is *left*, so fairness costs nothing when there is nothing to be unfair
/// about.
#[test]
fn one_sender_alone_still_gets_the_whole_budget() {
  let mut pop = FakePopulation::new();
  pop.add(0, MAX_SEND_CREDITS_PER_DRAIN, 1);
  assert!(pop.tick(), "it drained the budget exactly");
  assert_eq!(pop.sender(0).produced, MAX_SEND_CREDITS_PER_DRAIN);

  // Finishing inside the quantum leaves nothing behind, so the caller may sleep.
  let mut idle = FakePopulation::new();
  idle.add(0, 3, 1);
  assert!(!idle.tick(), "a sender that ran dry left no work behind");
  assert_eq!(idle.sender(0).produced, 3);
}

/// Idle senders leave their share to the ones behind them, so a queue of mostly
/// quiet senders does not throttle the one with work.
#[test]
fn an_idle_sender_leaves_its_share_to_the_rest() {
  let mut pop = FakePopulation::new();
  for id in 0..3 {
    pop.add(id, 0, 1);
  }
  pop.add(3, usize::MAX, 1);
  pop.tick();
  assert_eq!(
    pop.sender(3).produced,
    MAX_SEND_CREDITS_PER_DRAIN,
    "three idle senders must leave the whole budget to the fourth"
  );
}

/// A sender joining takes a sequence behind every sender already waiting. This
/// is the whole of why churn cannot starve anyone, so it is worth pinning on its
/// own rather than only through the queue that relies on it.
#[test]
fn a_newcomer_joins_behind_every_sender_already_waiting() {
  let mut queue = TxQueue::new();
  let waiting: Vec<u64> = (0..8).map(|_| queue.join()).collect();
  let newcomer = queue.join();
  assert!(
    waiting.iter().all(|&seq| seq < newcomer),
    "a newcomer must not land ahead of anything already queued: {waiting:?} vs {newcomer}"
  );
  // And the same for a sender being requeued after its turn: it goes to the
  // tail too, so taking a turn cannot buy another one.
  let requeued = queue.join();
  assert!(newcomer < requeued);
}

/// **The accounting property.** One logical datagram costs the budget the same
/// whether it fanned out to one family or two.
///
/// Charging per successful syscall instead makes a dual-stack transmit cost two,
/// so a busy dual-stack queue reaches only half as many senders per tick as a
/// single-stack one and the bound doubles with nothing in the code changing.
/// Both populations here are identical but for the fan-out.
#[test]
fn a_dual_stack_datagram_costs_the_same_as_a_single_stack_one() {
  let senders = MAX_SEND_CREDITS_PER_DRAIN * 2;
  let mut single = FakePopulation::new();
  let mut dual = FakePopulation::new();
  for id in 0..senders as u32 {
    single.add(id, usize::MAX, 1);
    dual.add(id, usize::MAX, 2);
  }
  single.tick();
  dual.tick();

  assert_eq!(
    dual.visited.len(),
    single.visited.len(),
    "the family fan-out must not change how many senders one tick reaches"
  );
  assert_eq!(
    dual.visited.len(),
    MAX_SEND_CREDITS_PER_DRAIN,
    "with every sender busy, one tick must reach exactly one budget's worth"
  );
  // The two runs really did differ: the dual-stack one issued twice the
  // syscalls for the same fairness cost, which is the whole distinction.
  assert_eq!(dual.syscalls, single.syscalls * 2);
  assert_eq!(single.syscalls, MAX_SEND_CREDITS_PER_DRAIN);
}

/// **The bound**, exercised under dual-stack charging: every sender is served
/// within `ceil(n / MAX_SEND_CREDITS_PER_DRAIN)` ticks, and 129 senders take
/// three ticks whether they fan out to one family or two.
///
/// 129 is chosen because it is the case that separates the two accountings: at
/// one credit per datagram it needs three ticks, at two it would need five.
#[test]
fn every_sender_is_served_within_the_stated_bound_under_dual_stack_charging() {
  let senders = MAX_SEND_CREDITS_PER_DRAIN * 2 + 1;
  let bound = senders.div_ceil(MAX_SEND_CREDITS_PER_DRAIN);
  assert_eq!(bound, 3, "the arithmetic this test is about");

  let mut pop = FakePopulation::new();
  for id in 0..senders as u32 {
    pop.add(id, usize::MAX, 2);
  }
  let mut served: Vec<u32> = Vec::new();
  for _ in 0..bound {
    pop.tick();
    served.extend(pop.visited.iter().copied());
  }
  served.sort_unstable();
  served.dedup();
  assert_eq!(
    served.len(),
    senders,
    "{senders} dual-stack senders must all be served within {bound} ticks, not {}",
    served.len()
  );
  assert_eq!(
    pop.syscalls,
    2 * MAX_SEND_CREDITS_PER_DRAIN * bound,
    "every one of those ticks really was dual-stack: two syscalls per datagram"
  );
}

/// **The starvation property.** Repeated cancel-and-reinsert cannot keep an
/// older due sender unserved.
///
/// This is the exact shape that defeats a queue whose position comes from handle
/// value: every tick, cancel the senders the last walk reached and start more
/// than a budget's worth of fresh ones. A cursor holding a handle then resumes
/// among the newcomers forever and never wraps back to the victim. Here the
/// newcomers take sequences behind the victim, so each tick moves it a whole
/// budget closer to the head no matter how many arrive.
///
/// The victim is placed at the very back of the initial queue — the worst
/// position there is, the one a sender is in immediately after taking its turn.
#[test]
fn cancel_and_reinsert_churn_cannot_keep_an_older_sender_unserved() {
  const VICTIM: u32 = 0;
  // More than one budget per tick, so the newcomers alone could consume every
  // credit if they were allowed ahead of the victim.
  let fresh_per_tick = MAX_SEND_CREDITS_PER_DRAIN + 1;
  let fillers = MAX_SEND_CREDITS_PER_DRAIN * 2;
  let ticks = 20;

  let mut pop = FakePopulation::new();
  let mut next_id = 1u32;
  for _ in 0..fillers {
    pop.add(next_id, usize::MAX, 2);
    next_id += 1;
  }
  pop.add(VICTIM, usize::MAX, 2);

  // The queue never exceeds this over the run — it starts at `fillers + 1` and
  // grows by one per tick — so `ceil(len / budget)` never exceeds `bound`.
  let max_len = fillers + 1 + ticks;
  let bound = max_len.div_ceil(MAX_SEND_CREDITS_PER_DRAIN);

  let mut served_on = Vec::new();
  for tick in 0..ticks {
    pop.tick();
    let reached: Vec<u32> = pop.visited.clone();
    if reached.contains(&VICTIM) {
      served_on.push(tick);
    }
    // The churn: retire everything this tick touched, then flood the queue with
    // newcomers. Only the victim survives every round.
    for id in reached {
      if id != VICTIM {
        pop.cancel(id);
      }
    }
    for _ in 0..fresh_per_tick {
      pop.add(next_id, usize::MAX, 2);
      next_id += 1;
    }
  }

  assert!(
    !served_on.is_empty(),
    "the victim was never served in {ticks} ticks of churn"
  );
  let first = *served_on.first().expect("a first visit");
  assert!(
    first < bound,
    "the victim waited {} ticks for its first turn, past the bound of {bound}",
    first + 1
  );
  // Not just once: it must keep its turn, so the gap between visits is bounded
  // too. A queue that served it once and then lost it again is still starving.
  for pair in served_on.windows(2) {
    let [prev, next] = *pair else { continue };
    assert!(
      next - prev <= bound,
      "the victim went {} ticks between turns, past the bound of {bound}: {served_on:?}",
      next - prev
    );
  }
  assert!(
    served_on.len() >= ticks / bound - 1,
    "the victim must take a turn roughly every {bound} ticks: {served_on:?}"
  );
}

/// The production drain really runs the queue: every sender gets a turn, and
/// taking it sends the sender to the tail with the queue order intact.
///
/// The pure scheduler tests above are the policy proof; this is what ties them
/// to `drain_transmits`, which is the only place the sequences are stored back.
#[test]
fn drain_transmits_gives_every_sender_a_turn_and_sends_it_to_the_tail() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let a = mdns
    .register_service(test_support::named_service_spec(
      "queue-a",
      "_hick-mio-queue._tcp.local.",
      8080,
    ))
    .expect("register a");
  let b = mdns
    .register_service(test_support::named_service_spec(
      "queue-b",
      "_hick-mio-queue._tcp.local.",
      8081,
    ))
    .expect("register b");
  let q = mdns
    .start_query(test_support::query_spec("_hick-mio-queue._tcp.local."))
    .expect("start_query");

  let seqs = |mdns: &Mdns| {
    [
      mdns.services.get(&a).expect("a").tx_seq,
      mdns.services.get(&b).expect("b").tx_seq,
      mdns.queries.get(&q).expect("q").tx_seq,
    ]
  };
  assert_eq!(
    seqs(&mdns),
    [0, 1, 2],
    "registration order is the initial queue order"
  );

  mdns.tick().expect("tick");
  let after = seqs(&mdns);
  assert!(
    after.iter().all(|&seq| seq >= 3),
    "one tick must offer all three a turn and requeue each of them: {after:?}"
  );
  assert!(
    after[0] < after[1] && after[1] < after[2],
    "a full pass must preserve the queue order, not reshuffle it: {after:?}"
  );

  // A sender starting now lands behind all three, however its handle compares.
  let late = mdns
    .start_query(test_support::query_spec("_hick-mio-late._tcp.local."))
    .expect("start_query");
  assert!(
    mdns.queries.get(&late).expect("late").tx_seq > after[2],
    "a newcomer joins the tail"
  );
}

// ── delivery is settled inside the tick that produced the datagram ─────────
//
// A `WouldBlock` send handed nothing to the kernel, so reporting the family
// `Missed` is a fact rather than a guess and the core may re-arm at once. What
// must NOT happen is the opposite: a refused datagram silently advancing the
// RFC 6762 §8.1 probe sequence, or a family that never carries anything pinning
// it forever.

/// Tick until the only bound family has been written off, or report why the
/// test is skipping.
///
/// Degradation takes `MAX_CONSECUTIVE_SEND_FAILURES` refused sends, so reaching
/// it is proof that the core really did re-arm and re-offer the probe that many
/// times. §8.1 spaces each retry 250 ms apart on top of the initial 0–250 ms
/// jitter, so the whole sequence is about a second; a slow host that has not got
/// there inside the budget is skipped rather than asserted against.
fn tick_until_the_family_is_written_off(mdns: &mut Mdns) -> bool {
  let deadline = Instant::now() + Duration::from_secs(3);
  while Instant::now() < deadline {
    mdns.tick().expect("tick");
    if mdns.degraded_families().0 {
      return true;
    }
    std::thread::sleep(Duration::from_millis(10));
  }
  eprintln!("skipping: the service produced no refused transmit within the budget");
  false
}

/// End to end: a probe the socket refused advances nothing, and the core
/// re-arms the SAME probe index rather than creeping forward.
#[test]
fn a_refused_probe_does_not_advance_the_probe_sequence() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-refused._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, true);
  if !tick_until_the_family_is_written_off(&mut mdns) {
    return;
  }

  let state = |mdns: &Mdns| {
    mdns
      .services
      .get(&handle)
      .map(|ctx| ctx.proto.state())
      .expect("the service is still registered")
  };
  assert_eq!(
    state(&mdns),
    ServiceState::Probing(0),
    "the probe reached no link, so §8.1 has not progressed"
  );
  // Nor does the write-off itself advance it. A family the driver has stopped
  // obligating reports `Unobligated`, and a round in which NO family delivered
  // is never a vacuous all-delivered — so the sequence stays put even once the
  // escape valve is open.
  for _ in 0..5 {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(60));
  }
  assert_eq!(state(&mdns), ServiceState::Probing(0));

  // Let the socket accept again. The next re-arm carries the SAME probe index,
  // and confirming it is what finally advances the sequence.
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, false);
  let deadline = Instant::now() + Duration::from_secs(2);
  while Instant::now() < deadline && state(&mdns) == ServiceState::Probing(0) {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(20));
  }
  assert_eq!(
    state(&mdns),
    ServiceState::Probing(1),
    "a delivered probe, and only a delivered one, advances the sequence"
  );
}

/// End to end: a socket that never accepts a byte does not pin RFC 6762 §8.1
/// probing.
///
/// The core re-arms the same probe on its own schedule, so the driver keeps
/// offering it; the family's failure streak is what eventually writes the family
/// off and lets the lifecycle continue with the links that do work. Nothing here
/// depends on a queue draining, which is the point.
#[test]
fn a_permanently_refusing_family_degrades_instead_of_pinning_the_lifecycle() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-pinned._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, true);

  if !tick_until_the_family_is_written_off(&mut mdns) {
    return;
  }
  assert_eq!(
    mdns.degraded_families(),
    (true, false),
    "the core re-armed the probe, the driver kept offering it, and the family's \
     failure streak is what finally writes it off"
  );
}

/// The public surface of a receive path this driver has given up on.
///
/// `bound_families` is a construction-time fact and stays `true` — the socket
/// exists and still sends — so this is the only thing that can tell a caller its
/// endpoint has gone deaf on that family.
#[test]
fn a_family_that_gave_up_on_receiving_is_reported_as_degraded() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  assert_eq!(mdns.degraded_families(), (false, false));
  mdns.sockets.set_readable_for_test(Family::V4, true);
  mdns.sockets.force_permanent_recv_error_for_test(Family::V4);
  mdns.tick().expect("tick");

  assert_eq!(
    mdns.degraded_families(),
    (true, false),
    "a family that can no longer be read is a real loss of coverage"
  );
  assert_eq!(
    mdns.bound_families(),
    (true, false),
    "it is still bound and still sending; only the receive path is gone"
  );
}

/// An RFC 6762 §9 rename leaves nothing of the old name able to confirm the
/// service, and it does so structurally.
///
/// A confirm arriving after the rename would be applied to whatever commit token
/// the *new* name holds — latching the old name's instance ownership onto a name
/// that has announced nothing, and opening the reclaim-cancel gate with it. That
/// is unreachable because every datagram is confirmed inside the `poll_transmit`
/// iteration that produced it, so the rename observed in stage 5 can never land
/// between a poll and its confirm.
///
/// Two things pin it. The core asserts the contract from its own side in debug
/// builds — `Service::handle_event` and `Service::handle_timeout` panic outright
/// if a commit token is live, and both run on **every** tick this test drives.
/// And the renamed service must go on to complete a fresh §8 lifecycle under its
/// new name, which a stuck token makes impossible: the core emits no further
/// datagram at all until its single token slot is spent.
#[test]
fn a_rename_leaves_no_transmit_still_awaiting_a_confirm() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let ty = "_hick-mio-rnreset._tcp.local.";
  let old = format!("resetme.{ty}");
  let handle = mdns
    .register_service(test_support::named_service_spec("resetme", ty, 8080))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }

  let probe = test_support::conflict_probe(&old);
  let Some(new_name) = drive_to_rename(&mut mdns, &probe) else {
    eprintln!("skipping: the service never renamed within the budget");
    return;
  };
  assert_ne!(new_name, old, "the rename must have chosen a fresh label");

  // A full §8.1 sequence is three probes 250 ms apart plus the first §8.3
  // announcement, so five seconds is several times over rather than a timing
  // assertion. Written out here instead of reusing `drive_to_advertised`
  // because a failure is a real defect, not an unsuitable host: the endpoint has
  // already proved it can advertise on this machine.
  let deadline = Instant::now() + Duration::from_secs(5);
  let mut advertised = false;
  while Instant::now() < deadline && !advertised {
    mdns.tick().expect("tick");
    advertised = mdns
      .services
      .get(&handle)
      .is_some_and(|ctx| ctx.proto.advertises_instance());
    std::thread::sleep(Duration::from_millis(20));
  }
  assert!(
    advertised,
    "a renamed service must re-probe and re-announce under its new name; a \
     commit token left live by the old name would stop it emitting anything"
  );
}

/// The receive-error backoff arm: a family whose readiness was retained across
/// a transient error must neither spin at zero nor be left with no wakeup at
/// all.
#[test]
fn a_family_backing_off_from_receive_errors_gets_a_bounded_timeout() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  mdns.sockets.set_readable_for_test(Family::V4, true);
  mdns
    .sockets
    .force_recv_errors_for_test(Family::V4, u32::MAX);
  mdns.tick().expect("tick");

  assert!(
    mdns.sockets.is_readable_for_test(Family::V4),
    "the flag survives, so the drain resumes next tick"
  );
  let timeout = mdns
    .next_timeout()
    .expect("a stranded family needs a wakeup");
  assert!(
    timeout > Duration::ZERO,
    "a family erroring on every read must not spin at a zero timeout"
  );
  assert!(
    timeout <= RETRY_INTEREST_BACKOFF,
    "the first failing round is still a prompt retry: {timeout:?}"
  );
}

#[test]
fn the_receive_error_backoff_escalates_and_is_capped() {
  assert_eq!(super::recv_error_backoff(1), RETRY_INTEREST_BACKOFF);
  assert_eq!(super::recv_error_backoff(2), RETRY_INTEREST_BACKOFF * 2);
  assert_eq!(super::recv_error_backoff(3), RETRY_INTEREST_BACKOFF * 4);
  let capped = RETRY_INTEREST_BACKOFF * (1 << super::MAX_RECV_BACKOFF_DOUBLINGS);
  assert_eq!(super::recv_error_backoff(5), capped);
  assert_eq!(
    super::recv_error_backoff(u32::MAX),
    capped,
    "a socket that never recovers costs a bounded trickle of wakeups"
  );
}

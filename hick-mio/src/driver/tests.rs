use std::{
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
  time::{Duration, Instant},
};

use mdns_proto::{
  CollectedAnswer, FamilyDelivery, ServiceState,
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
  selfsend::SELF_SEND_TTL,
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
  let report = mdns
    .sockets
    .send_to(&[0u8; 12], MDNS_V4_DST, &crate::socket::Ungated);
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
  mdns.deregister().expect("deregister");
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
  mdns.deregister().expect("deregister");
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
  mdns.deregister().expect("deregister");
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
  assert!(selfsend.take_at(
    Family::V4,
    &body,
    std::time::SystemTime::now(),
    Instant::now(),
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

// ── the wire gate's anchor ────────────────────────────────────────────
//
// The gate spaces one family's bytes on one wire, so what it must measure from
// is when the bytes GOT there — never when the driver was about to ask. Nothing
// bounds the window between a pre-syscall clock read and the syscall that
// follows it: a preemption, a signal handler or a page fault stretches it
// arbitrarily, and a gate anchored on the near side hands that whole stall back
// to the next datagram's spacing.
//
// The stall is what no test can ask a real host for, so it is injected — and the
// spacing is then measured from inside the send path, after the stall, so the
// assertion is the wire's own history rather than the driver's account of it.

/// What RFC 6762 gives each kind of datagram as its per-family minimum. Restated
/// here because the core's own copies are crate-private, and pinned by name so a
/// kind whose minimum changed would not silently reuse another's: §8.1 spaces
/// probes 250 ms apart.
const PROBE_MIN_FAMILY_GAP: Duration = Duration::from_millis(250);
/// §6 and §8.3: a record may not be re-multicast on an interface inside one
/// second of the last time it went out on that interface.
const ANNOUNCE_MIN_FAMILY_GAP: Duration = Duration::from_secs(1);
/// §5.2: "the interval between the first two queries MUST be at least one
/// second", and the backoff only widens from there.
const QUERY_MIN_FAMILY_GAP: Duration = Duration::from_secs(1);

/// How often a gated round is retried, standing in for the run loop's own
/// re-entry. Only granularity: a coarser value can delay a send but never let
/// one out early.
const GATED_RETRY_POLL: Duration = Duration::from_millis(5);

/// Put `stalls.len()` gated multicast datagrams from ONE producer onto ONE
/// family through the real [`send_and_credit`](super::send_and_credit), retrying
/// a gated round the way the run loop does, and return the instants the SOCKET
/// recorded for them.
///
/// The fixture is IPv4-only, so every wire time belongs to one family and the
/// gaps between them are that family's own wire spacing.
fn same_family_wire_times(mdns: &mut Mdns, min_gap: Duration, stalls: &[Duration]) -> Vec<Instant> {
  mdns.sockets.force_send_delays_for_test(Family::V4, stalls);
  let mut gate = FamilyWireGate::default();
  let Mdns {
    sockets,
    selfsend,
    send_health,
    ..
  } = &mut *mdns;
  for i in 0..stalls.len() {
    // A distinct body per round, so nothing about self-send bookkeeping can make
    // one round's datagram stand in for another's.
    let body = [b'g', b'a', b'p', i as u8];
    // A gated round is retried, but a REFUSED one never becomes a delivered one,
    // and looping on it forever would report a broken egress path as a hang.
    let deadline = Instant::now() + min_gap * 2 + Duration::from_secs(2);
    loop {
      let summary = super::send_and_credit(
        sockets,
        selfsend,
        send_health,
        &mut gate,
        &body,
        MDNS_V4_DST,
        min_gap,
      );
      if summary.sent == 1 {
        break;
      }
      assert!(
        Instant::now() < deadline,
        "round {i} never reached the wire; a send the socket refused cannot be \
         retried into a wire gap, so this is an egress failure and not a gate"
      );
      std::thread::sleep(GATED_RETRY_POLL);
    }
  }
  sockets.wire_times_for_test(Family::V4)
}

/// A send that had not reached the kernel when its pre-syscall stamps were read
/// must not buy back the wire gap it owes.
///
/// Anchored at the pre-syscall stamp instead, a send stalled by `P` re-opens its
/// own family `P` early. The stalls end at zero on purpose: with a CONSTANT
/// stall every wire time shifts by the same amount and the bug is invisible, so
/// it is the round that does NOT stall, following ones that did, that puts the
/// too-early datagram on the wire.
fn stalled_sends_keep_their_wire_gap(kind: &str, min_gap: Duration, stalls: &[Duration]) {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  if !mdns.sockets.is_bound_for_test(Family::V4) {
    eprintln!("skipping: IPv4 is not bound on this host");
    return;
  }
  let wire_times = same_family_wire_times(&mut mdns, min_gap, stalls);
  assert_eq!(
    wire_times.len(),
    stalls.len(),
    "{kind}: every round must have reached the wire exactly once"
  );
  for (i, pair) in wire_times.windows(2).enumerate() {
    let gap = pair[1].saturating_duration_since(pair[0]);
    assert!(
      gap >= min_gap,
      "{kind}: consecutive datagrams were {gap:?} apart on one family's wire, \
       inside the {min_gap:?} that kind owes it — the {:?} the send before it \
       spent between its pre-syscall stamp and the syscall was credited to the gap",
      stalls[i]
    );
  }
}

/// §8.1 probes: 250 ms apart on the wire, however long a probe was stalled. Two
/// stalled rounds in a row, so the anchor is exercised on a later send and not
/// just the first.
#[test]
fn a_stalled_probe_does_not_shorten_the_next_probes_wire_gap() {
  stalled_sends_keep_their_wire_gap(
    "probe",
    PROBE_MIN_FAMILY_GAP,
    &[
      Duration::from_millis(200),
      Duration::from_millis(200),
      Duration::ZERO,
    ],
  );
}

/// §6 / §8.3 unsolicited announcements: one second apart on the wire.
#[test]
fn a_stalled_announcement_does_not_shorten_the_next_ones_wire_gap() {
  stalled_sends_keep_their_wire_gap(
    "announcement",
    ANNOUNCE_MIN_FAMILY_GAP,
    &[
      Duration::from_millis(200),
      Duration::from_millis(200),
      Duration::ZERO,
    ],
  );
}

/// §5.2 queries: the same second, and the backoff only widens it.
#[test]
fn a_stalled_query_does_not_shorten_the_next_ones_wire_gap() {
  stalled_sends_keep_their_wire_gap(
    "query",
    QUERY_MIN_FAMILY_GAP,
    &[
      Duration::from_millis(200),
      Duration::from_millis(200),
      Duration::ZERO,
    ],
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
  let (v4, v6, _at) = super::withdrawal::send_withdrawal(
    sockets,
    selfsend,
    send_health,
    &[0x5Au8; 20],
    &crate::socket::Ungated,
  );
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
  let (v4, _v6, _at) = super::withdrawal::send_withdrawal(
    sockets,
    selfsend,
    send_health,
    &[0x5Au8; 20],
    &crate::socket::Ungated,
  );
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
  let (v4, v6, _at) = super::withdrawal::send_withdrawal(
    sockets,
    selfsend,
    send_health,
    &[0x5Au8; 20],
    &crate::socket::Ungated,
  );

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

// ── the §10.1 resend schedule's anchor ──────────────────────────────────────
//
// Stage 7 is ungated by design — the per-family wire gate paces a producer's own
// record set, and a goodbye answers to the endpoint's schedule instead — so that
// schedule is the ONLY thing pacing two consecutive goodbyes for one name on one
// family's wire. Re-arming it from the tick's `now`, read before the fan-out,
// hands the next round every microsecond this one spent inside the syscall: a
// stall past the 250 ms interval leaves the next round already due the moment the
// send returns, and the two goodbyes land back to back.
//
// Measured, like the wire gate's own anchor tests above, from
// `wire_times_for_test` — the socket's record of when the bytes reached the wire.
// Reading the endpoint's schedule instead would only ask the bug what it believed
// it had promised.

/// RFC 6762 §10.1's goodbye resend interval, restated because `mdns-proto`'s own
/// copy is crate-private.
const GOODBYE_MIN_FAMILY_GAP: Duration = Duration::from_millis(250);

/// §10.1's anti-pin ceiling: a withdrawal is force-completed this long after it
/// begins, whatever debt is left. The one thing allowed to shorten the interval
/// above, so it belongs to the property rather than being an exception carved out
/// of it.
const GOODBYE_CEILING: Duration = Duration::from_secs(2);

/// A first goodbye held inside its syscall for longer than the resend interval —
/// the whole of what the anchor has to survive. Short enough that the round it
/// delays is nowhere near the ceiling, so the full interval is what the next
/// round owes.
const GOODBYE_STALL_PAST_INTERVAL: Duration = Duration::from_millis(400);

/// A first goodbye held long enough that its send lands inside the LAST interval
/// before the ceiling: the re-arm then clamps to the ceiling and the goodbye after
/// it is the past-ceiling final attempt.
///
/// The value is bracketed on both sides and neither edge has slack to spare.
/// Below `GOODBYE_CEILING - GOODBYE_MIN_FAMILY_GAP` the re-arm does not clamp and
/// this is just the test above again; at or beyond `GOODBYE_CEILING` the stalled
/// send itself lands past the ceiling, where the final attempt fires on `now >=
/// ceiling_at` alone and no schedule — right or wrong — has any say.
const GOODBYE_STALL_INTO_CEILING: Duration = Duration::from_millis(1_850);

/// Stands in for the run loop's re-entry between two stage-7 drains. Only
/// granularity: a coarser poll can delay a round but never let one out early.
const GOODBYE_DRAIN_POLL: Duration = Duration::from_millis(5);

/// An IPv4-only [`Mdns`] whose one service has announced and is now withdrawing,
/// plus the two things the caller needs to read its goodbyes off the wire: a lower
/// bound on the withdrawal item's anti-pin ceiling, and how many datagrams the
/// probe and announce already put on IPv4's wire.
///
/// The service must have ANNOUNCED: a never-announced one owes `[0, 0]`, settles
/// on its first pass with nothing on the wire, and would make every gap assertion
/// below vacuous.
fn advertised_then_withdrawn(ty: &str) -> Option<(test_support::TestMdns, Instant, usize)> {
  let mut mdns = test_support::loopback_mdns_v4_only()?;
  if !mdns.sockets.is_bound_for_test(Family::V4) {
    eprintln!("skipping: IPv4 is not bound on this host");
    return None;
  }
  let handle = mdns
    .register_service(test_support::service_spec(ty, 8080))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return None;
  }
  let already_on_wire = mdns.sockets.wire_times_for_test(Family::V4).len();
  // `unregister_service` begins the withdrawal at its own `Instant::now()`, so the
  // item's ceiling is 2 s past an instant no EARLIER than this one. A lower bound
  // is exactly what the assertion wants: understating the ceiling can only weaken
  // the floor it computes, never move it somewhere the fix does not reach.
  let ceiling_floor = Instant::now() + GOODBYE_CEILING;
  mdns.unregister_service(handle);
  assert!(
    mdns.endpoint.has_pending_withdrawals(),
    "an announced service must owe a §10.1 goodbye once unregistered"
  );
  Some((mdns, ceiling_floor, already_on_wire))
}

/// Drive stage 7 the way the run loop does — one [`Mdns::drain_withdrawals`] per
/// re-entry, each at the live clock — until the withdrawal settles, and return the
/// instants IPv4's socket recorded for the goodbyes alone.
///
/// `drain_withdrawals` rather than `tick`, so that every datagram after
/// `already_on_wire` is a goodbye: no other stage gets to put bytes on this wire
/// or to eat the forced stall meant for the first round.
fn goodbye_wire_times(mdns: &mut Mdns, already_on_wire: usize) -> Vec<Instant> {
  // The ceiling force-completes every item, so a run that outlives it by a whole
  // second is a hang and must be reported as one rather than as a wire history
  // with a round missing from the end.
  let deadline = Instant::now() + GOODBYE_CEILING + Duration::from_secs(1);
  while mdns.endpoint.has_pending_withdrawals() && Instant::now() < deadline {
    mdns.drain_withdrawals();
    std::thread::sleep(GOODBYE_DRAIN_POLL);
  }
  assert!(
    !mdns.endpoint.has_pending_withdrawals(),
    "the withdrawal outlived its own anti-pin ceiling"
  );
  mdns
    .sockets
    .wire_times_for_test(Family::V4)
    .split_off(already_on_wire)
}

/// Two consecutive goodbyes for one name on one family's wire are `min(the §10.1
/// interval, whatever is left before the anti-pin ceiling)` apart — the endpoint's
/// own guarantee, restated against the wire instead of against its schedule.
///
/// The ceiling term is not a softened assertion: `note_withdrawal_result` clamps
/// every re-arm to `ceiling_at`, so a round taken inside the last interval before
/// the ceiling is followed by the final attempt, which is due AT the ceiling. What
/// the bug does is take that goodbye earlier still, from a schedule armed off an
/// instant that predates the stalled send.
fn assert_goodbye_wire_spacing(kind: &str, wire_times: &[Instant], ceiling_floor: Instant) {
  assert!(
    wire_times.len() >= 2,
    "{kind}: {} goodbyes reached IPv4's wire, so there is no consecutive pair to \
     weigh and this test asserts nothing",
    wire_times.len()
  );
  for pair in wire_times.windows(2) {
    let earliest = (pair[0] + GOODBYE_MIN_FAMILY_GAP).min(ceiling_floor);
    assert!(
      pair[1] >= earliest,
      "{kind}: a goodbye reached IPv4's wire {:?} after the one before it and \
       {:?} before its withdrawal's anti-pin ceiling, so it was {:?} early — the \
       §10.1 schedule was re-armed from an instant read BEFORE the fan-out, which \
       credits the stalled round's own time in the syscall to the next round's \
       spacing",
      pair[1].saturating_duration_since(pair[0]),
      ceiling_floor.saturating_duration_since(pair[1]),
      earliest.saturating_duration_since(pair[1]),
    );
  }
}

/// **The progress path.** A round that paid down real debt re-arms at the full
/// 250 ms interval, and that interval belongs to the wire: a first goodbye held
/// 400 ms inside its `send_to` must not have those 400 ms handed to the round
/// after it.
#[test]
fn a_stalled_goodbye_keeps_the_next_rounds_wire_gap() {
  let Some((mut mdns, ceiling_floor, already_on_wire)) =
    advertised_then_withdrawn("_hick-mio-goodbye-gap._tcp.local.")
  else {
    return;
  };
  // Only the FIRST round stalls. A constant stall shifts every wire time by the
  // same amount and hides the defect completely; it is the unstalled round
  // following a stalled one that goes out early.
  mdns
    .sockets
    .force_send_delays_for_test(Family::V4, &[GOODBYE_STALL_PAST_INTERVAL]);
  let wire_times = goodbye_wire_times(&mut mdns, already_on_wire);
  assert_goodbye_wire_spacing("a stalled progress round", &wire_times, ceiling_floor);
}

/// **The final-attempt path.** The same anchor, where the re-arm it produces is
/// clamped to the anti-pin ceiling and the goodbye that follows is the one final
/// attempt `poll_withdrawal_transmit` makes past it.
///
/// Anchored at the fan-out, the stalled round re-arms at the ceiling and the final
/// attempt is what pays the next goodbye. Anchored at the tick's `now` — read
/// 1.85 s earlier, before the stall — the schedule re-arms 250 ms after an instant
/// long past, so an ORDINARY round is already due when the stalled send returns
/// and goes out roughly 150 ms ahead of the ceiling. The ceiling is §10.1's only
/// licence to cut the interval short, and this takes the licence without the
/// ceiling.
#[test]
fn a_goodbye_stalled_into_its_ceiling_still_waits_for_the_final_attempt() {
  let Some((mut mdns, ceiling_floor, already_on_wire)) =
    advertised_then_withdrawn("_hick-mio-goodbye-ceiling._tcp.local.")
  else {
    return;
  };
  mdns
    .sockets
    .force_send_delays_for_test(Family::V4, &[GOODBYE_STALL_INTO_CEILING]);
  let wire_times = goodbye_wire_times(&mut mdns, already_on_wire);
  assert_goodbye_wire_spacing(
    "a round stalled into its ceiling",
    &wire_times,
    ceiling_floor,
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

/// Rename `handle` **without letting stage 5 see it**, so the one-shot §9
/// handoff is still parked on the service when the caller unregisters it.
///
/// `push_updates` takes the handoff on every rename it observes, which is
/// correct and is what production normally does. The window this reaches is the
/// other one: a caller that unregisters a service in the same breath as the
/// rename, so `begin_service_withdrawal` is the site holding both a handoff and
/// a snapshot to enqueue. Running the §8.1 probe machinery through stages 3 and
/// 4 alone — never `tick`, which would run stage 5 — is what holds that window
/// open for the length of a test rather than a scheduler quantum.
fn rename_leaving_the_handoff_parked(
  mdns: &mut Mdns,
  handle: mdns_proto::ServiceHandle,
  old: &str,
) -> bool {
  /// Drain this service's own updates, reporting whether a rename was among
  /// them. Draining is the point: an update stage 5 never sees is a handoff
  /// stage 5 never takes.
  fn took_the_rename(mdns: &mut Mdns, handle: mdns_proto::ServiceHandle) -> bool {
    let mut renamed = false;
    if let Some(ctx) = mdns.services.get_mut(&handle) {
      while let Some(update) = ctx.proto.poll() {
        renamed |= matches!(update, mdns_proto::ServiceUpdate::Renamed(_));
      }
    }
    renamed
  }

  let probe = test_support::conflict_probe(old);
  let deadline = Instant::now() + Duration::from_secs(10);
  while Instant::now() < deadline {
    test_support::ingest(mdns, &probe, Instant::now());
    if took_the_rename(mdns, handle) {
      return true;
    }
    let now = Instant::now();
    mdns.fire_timeouts(now);
    mdns.drain_transmits(now);
    if took_the_rename(mdns, handle) {
      return true;
    }
    std::thread::sleep(Duration::from_millis(20));
  }
  false
}

/// The rename item and the service item are **two** schedules, so they take two
/// creation instants.
///
/// A withdrawal item's `next_at` *is* the instant it was created, so an item is
/// due at exactly that instant and not before. Polling at the earlier of the two
/// therefore offers exactly one item — unless the two were created from one
/// reading, in which case both are due at it and both go out. That is the whole
/// observable difference, and this test is the whole of what is checkable from
/// outside.
///
/// **Weak, and worth saying so.** It pins the *direction* — the service item's
/// schedule begins after the rename item's, so the entire
/// `enqueue_rename_withdrawal` is not charged to the service item's 2 s
/// anti-pin ceiling — and nothing about the magnitude, which is one enqueue
/// wide. Nothing here would catch a future site that shared a reading between
/// two consumers a few instructions apart. The property that does is structural:
/// each enqueue reads its own clock, adjacent to its own use, and there is no
/// value in scope for a second consumer to reach for. This is the residual, and
/// it is accepted rather than argued away.
#[test]
fn two_withdrawal_items_take_two_creation_instants() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let ty = "_hick-mio-two-anchors._tcp.local.";
  let old = format!("anchors.{ty}");
  let handle = mdns
    .register_service(test_support::named_service_spec("anchors", ty, 8080))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }
  if !rename_leaving_the_handoff_parked(&mut mdns, handle, &old) {
    eprintln!("skipping: the service never renamed within the budget");
    return;
  }

  // Both items are created inside this one call: the rename handoff's, then the
  // service's own.
  mdns.unregister_service(handle);
  let Some(first) = mdns.endpoint.next_withdrawal_deadline() else {
    eprintln!("skipping: the unregister enqueued no withdrawal at all");
    return;
  };
  let due = test_support::collect_goodbyes_as(
    &mut mdns,
    first,
    WithdrawalSend::Retry,
    WithdrawalSend::Retry,
  );
  assert_eq!(
    due.len(),
    1,
    "at the EARLIER item's own creation instant only that item is due; a second \
     datagram here means both schedules were anchored at one reading, which \
     charges the whole of the first enqueue to the second item's 2 s ceiling"
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

/// Tick until the only bound family is reported degraded, or report why the test
/// is skipping.
///
/// Degradation takes `MAX_CONSECUTIVE_SEND_FAILURES` refused sends, so reaching
/// it is proof that the core really did re-arm and re-offer the probe that many
/// times. It is a health signal and changes nothing the core is told — which is
/// exactly what makes it a usable progress marker here. §8.1 spaces each retry
/// 250 ms apart on top of the initial 0–250 ms jitter, so the whole sequence is
/// about a second; a slow host that has not got there inside the budget is
/// skipped rather than asserted against.
fn tick_until_the_family_is_reported_degraded(mdns: &mut Mdns) -> bool {
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
  if !tick_until_the_family_is_reported_degraded(&mut mdns) {
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
  // Nor does the degradation itself advance it. A failing family stays `Missed`
  // however long it fails, the absent family is the only `Unobligated` one, and
  // a round in which NO family delivered is never a vacuous all-delivered — so
  // the sequence stays put no matter what the health table now says.
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

/// End to end: a socket that never accepts a byte is reported degraded, and that
/// is the whole of what the driver does about it.
///
/// The core re-arms the same probe on its own schedule and the driver keeps
/// offering it — every round reported honestly as a miss. The failure streak
/// surfaces on [`Mdns::degraded_families`] and nowhere else; deciding when a
/// family stops holding the lifecycle back is the core's own patience. Nothing
/// here depends on a queue draining, which is the point.
#[test]
fn a_permanently_refusing_family_is_reported_degraded_and_nothing_more() {
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

  if !tick_until_the_family_is_reported_degraded(&mut mdns) {
    return;
  }
  assert_eq!(
    mdns.degraded_families(),
    (true, false),
    "the core re-armed the probe, the driver kept offering it, and the family's \
     failure streak is what the caller gets to see"
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

// ── an encode failure is leftover work ──────────────────────────────────────
//
// `Service::poll_transmit` failing leaves the datagram armed inside the proto
// layer: the core retries the same one on the next call and schedules no
// deadline for something it has already armed. Nothing in `next_timeout`'s
// deadline fold speaks for it, and mio's readiness is edge-triggered, so no
// event can announce in-memory work either. If the drain reports the exit as
// "nothing left", the caller blocks in `Poll::poll` with a datagram sitting in
// memory — and the failure counter that retires a structurally unusable
// service only advances on ticks that reach the failing poll.

/// A payload buffer far too small for any DNS message, which is what makes
/// `poll_transmit` fail on demand. Twenty-four bytes leaves room for the
/// 12-byte header and nothing that follows it.
const UNENCODABLE_PAYLOAD_SIZE: usize = 24;

/// Tick until `handle`'s consecutive encode-failure count reaches `want`, or
/// report why the test is skipping.
///
/// The first probe is scheduled a random 0-250 ms out (RFC 6762 §8.1), so the
/// first few ticks legitimately poll nothing at all.
fn tick_to_encode_failures(mdns: &mut Mdns, handle: mdns_proto::ServiceHandle, want: u8) -> bool {
  let deadline = Instant::now() + Duration::from_secs(3);
  while Instant::now() < deadline {
    mdns.tick().expect("tick");
    match mdns.services.get(&handle) {
      Some(ctx) if ctx.encode_failures >= want => return true,
      Some(_) => {}
      None => {
        eprintln!("skipping: the service was retired before reaching {want} encode failures");
        return false;
      }
    }
    std::thread::sleep(Duration::from_millis(10));
  }
  eprintln!("skipping: the service never reached {want} encode failures within the budget");
  false
}

#[test]
fn a_non_terminal_encode_failure_reports_leftover_work() {
  let Some(mut mdns) = test_support::loopback_mdns_with(
    crate::options::ServerOptions::default()
      .with_ipv6(false)
      .with_max_payload_size(UNENCODABLE_PAYLOAD_SIZE),
  ) else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec("_encfail._tcp.local.", 4444))
    .expect("register_service");

  for want in 1..crate::driver::MAX_CONSECUTIVE_ENCODE_ERRORS {
    if !tick_to_encode_failures(&mut mdns, handle, want) {
      return;
    }
    // Nothing is readable — this fixture never received a datagram — so a zero
    // timeout can only come from `work_pending`.
    assert!(
      !mdns.sockets.has_readable(),
      "the zero timeout must be about the stranded datagram, not leftover \
       readable data"
    );
    assert_eq!(
      mdns.next_timeout(),
      Some(Duration::ZERO),
      "encode failure {want} left a datagram armed in the proto layer; the \
       caller must come straight back rather than sleep on a lifecycle deadline"
    );
  }
}

#[test]
fn consecutive_encode_failures_retire_the_service_with_a_conflict() {
  let Some(mut mdns) = test_support::loopback_mdns_with(
    crate::options::ServerOptions::default()
      .with_ipv6(false)
      .with_max_payload_size(UNENCODABLE_PAYLOAD_SIZE),
  ) else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec("_encfail._tcp.local.", 4445))
    .expect("register_service");

  let deadline = Instant::now() + Duration::from_secs(5);
  let mut conflict = None;
  while Instant::now() < deadline && conflict.is_none() {
    mdns.tick().expect("tick");
    while let Some(ev) = mdns.next_event() {
      if let Event::Service { handle: h, update } = ev
        && h == handle
      {
        conflict = Some(update);
      }
    }
    std::thread::sleep(Duration::from_millis(10));
  }
  let Some(update) = conflict else {
    eprintln!("skipping: the service never reported a terminal within the budget");
    return;
  };
  assert!(
    update.is_conflict(),
    "a payload that cannot be encoded retires the service rather than leaving \
     the caller waiting for an Established that can never arrive: {update:?}"
  );
  // Retired means retired: nothing keeps driving its proto state machine.
  assert!(
    mdns.services.get(&handle).is_none_or(|ctx| ctx.withdrawing),
    "the retirement must stop every stage from driving this service"
  );
}

// ── the ingress interface gate, wired ───────────────────────────────────────

/// The explicit loopback exception, through the real receive path.
///
/// The gate drops a datagram whose reported interface index is not the one this
/// endpoint bound. Our own multicast echo is the traffic loopback suppression
/// depends on, and a platform is free to report it as having arrived on the
/// loopback pseudo-interface rather than on the socket's egress interface — so
/// the exception is stated in `onlink::arrived_on_bound_interface` rather than
/// left to fall out of the index comparison. This forces exactly that
/// disagreement and pins that the echo still reaches the self-send match.
///
/// It cannot be inverted into a rejection test on this fixture: an endpoint
/// pinned to the loopback interface only ever receives loopback-sourced
/// datagrams, which is the very case the exception admits. The rejection matrix
/// lives in `onlink::tests`, against the same function this path calls.
#[test]
fn an_own_echo_survives_a_foreign_interface_index() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let poll = Poll::new().expect("poll");
  mdns
    .register(poll.registry(), Token(40), Token(41))
    .expect("register");

  let body = [0x3Cu8; 28];
  {
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
      &body,
      MDNS_V4_DST,
      Duration::ZERO,
    );
    if summary.sent == 0 {
      eprintln!("skipping: the datagram never reached a wire on this host");
      mdns.deregister().expect("deregister");
      return;
    }
  }
  // Every subsequent receive now reports an interface this endpoint did not
  // bind — the disagreement a loopback copy can genuinely show.
  let foreign = mdns.bound_interface.wrapping_add(1_000);
  mdns.sockets.force_rx_interface_for_test(Some(foreign));

  let mut events = mio::Events::with_capacity(8);
  let deadline = Instant::now() + Duration::from_secs(2);
  let mut poll = poll;
  while Instant::now() < deadline && mdns.selfsend.len() > 0 {
    poll
      .poll(&mut events, Some(Duration::from_millis(100)))
      .expect("poll");
    for ev in events.iter() {
      if mdns.owns(ev.token()) {
        mdns.handle_io(ev);
      }
    }
    mdns.tick().expect("tick");
  }
  let matched = mdns.selfsend.len() == 0;
  // The skip must gate on an observed counter, or a regression in the gate
  // itself would present as "the echo never arrived" and take this test green.
  // `packets_rx` counts every datagram that left the kernel queue, including one
  // the trust boundary then dropped, so it separates a host whose loopback
  // egress went nowhere from a gate that swallowed the echo.
  let arrived = saw_own_loopback(&mdns);
  mdns.deregister().expect("deregister");
  assert!(
    matched || !arrived,
    "our own multicast echo reached this endpoint and did not reach the \
     self-send match: the loopback exception in the ingress interface gate is \
     what keeps a foreign interface index from swallowing it"
  );
  if !matched {
    eprintln!("skipping: this endpoint's own multicast never looped back within the budget");
  }
}

/// The reported bypass, through the real receive path: a conforming hop limit
/// and a source address whose zone names another link.
///
/// The gate runs before the self-send credit and before `endpoint.handle`, so a
/// rejected datagram must reach neither. This drives the difference the wrong
/// way round from the test above: there the forced disagreement is one the
/// exception forgives, here it is one nothing forgives, and the observable is
/// that the take-once credit is still unclaimed afterwards. A claimed credit
/// would mean the datagram passed the gate and reached the self-send match —
/// which sits between the gate and `endpoint.handle`, so it is the earlier of
/// the two things the drop has to happen before.
///
/// Both witnesses are forced, in opposition: the receive path reports the
/// interface this endpoint bound (the loopback fixture's own), and the peer
/// reports a link-local address zoned to a different one. That is the case a
/// "some witness agrees" rule would admit, and it is exactly what a wildcard
/// socket on a multi-homed host is handed. Neither can be produced by a host
/// this test runs on: a loopback fixture only ever sees `127.0.0.1`/`::1`,
/// which the boundary admits by construction.
#[test]
fn a_conflicting_peer_scope_is_dropped_before_the_self_send_credit() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let poll = Poll::new().expect("poll");
  mdns
    .register(poll.registry(), Token(42), Token(43))
    .expect("register");

  let body = [0x5Au8; 32];
  {
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
      &body,
      MDNS_V4_DST,
      Duration::ZERO,
    );
    if summary.sent == 0 {
      eprintln!("skipping: the datagram never reached a wire on this host");
      mdns.deregister().expect("deregister");
      return;
    }
  }
  assert!(
    mdns.selfsend.len() > 0,
    "the send must have left a credit for the echo to claim, or this test \
     cannot tell a dropped echo from an unclaimable one"
  );
  // Port 5353 so the §11 source-port rule for responses cannot be what drops
  // this instead of the gate; the zone is the only thing wrong with it.
  let foreign = mdns.bound_interface.wrapping_add(1_000);
  mdns
    .sockets
    .force_rx_peer_for_test(Some(SocketAddr::V6(SocketAddrV6::new(
      Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
      5353,
      0,
      foreign,
    ))));

  let before = dropped_at_the_gate(&mdns);
  let mut events = mio::Events::with_capacity(8);
  // Well inside `SELF_SEND_TTL` (2 s), so an unclaimed credit below is one the
  // gate protected and never one the clock retired.
  let deadline = Instant::now() + Duration::from_millis(750);
  let mut poll = poll;
  while Instant::now() < deadline && dropped_at_the_gate(&mdns) == before {
    poll
      .poll(&mut events, Some(Duration::from_millis(50)))
      .expect("poll");
    for ev in events.iter() {
      if mdns.owns(ev.token()) {
        mdns.handle_io(ev);
      }
    }
    mdns.tick().expect("tick");
  }
  let unclaimed = mdns.selfsend.len() > 0;
  let dropped = dropped_at_the_gate(&mdns) > before;
  mdns.deregister().expect("deregister");
  assert!(
    unclaimed,
    "an echo whose source zone names another link reached the self-send match: \
     the ingress gate must reject it before the take-once credit is consulted, \
     and before `endpoint.handle` can cache anything it carries"
  );
  #[cfg(feature = "stats")]
  if !dropped {
    eprintln!("skipping: this endpoint's own multicast never looped back within the budget");
  }
  #[cfg(not(feature = "stats"))]
  let _ = dropped;
}

/// How many datagrams this endpoint has read and then thrown away, or `0` where
/// there is no counter to ask.
///
/// The ingress gate is the only stage before the self-send match that both
/// reads a datagram off the queue and drops it, so a rise here across the poll
/// loop above is the gate firing. Without the `stats` feature this is constant,
/// and the caller's loop simply runs out its budget.
fn dropped_at_the_gate(mdns: &Mdns) -> u64 {
  #[cfg(feature = "stats")]
  {
    mdns.stats().packets_dropped
  }
  #[cfg(not(feature = "stats"))]
  {
    let _ = mdns;
    0
  }
}

/// Whether this endpoint has read any datagram off its own sockets, dropped or
/// not.
///
/// The egress probe [`crate::Mdns::stats`] gives, under the same fallback the
/// loopback integration tests use: with no `stats` feature there is no counter
/// to consult, so it reports `true` and the caller asserts unconditionally.
fn saw_own_loopback(mdns: &Mdns) -> bool {
  #[cfg(feature = "stats")]
  {
    mdns.stats().packets_rx > 0
  }
  #[cfg(not(feature = "stats"))]
  {
    let _ = mdns;
    true
  }
}

// ── a self-send credit outlives its own recording tick ──────────────────────
//
// A credit recorded during a tick cannot be claimed during that tick: stage 1
// receives, and every stage that sends runs after it. So no instant inside the
// recording tick may start the credit's `SELF_SEND_TTL`, and each of these tests
// is one way the driver used to spend that unclaimable stretch — a stalled
// syscall, a stalled sibling family, a later send in the same tick, a stage-7
// goodbye after a stage-4 announcement — and thereby ingest its own datagram as
// peer traffic, raising a phantom conflict against itself and renaming under RFC
// 6762 §9. The last test is the other side: once the window HAS opened, elapsed
// time is charged in full.

/// Just past the TTL, so every stall injected below is unambiguously fatal to a
/// credit anchored anywhere inside its recording tick.
const STALL_PAST_TTL: Duration = SELF_SEND_TTL.saturating_add(Duration::from_millis(50));

/// Put `body` on the wire through stage 4's own credit path, or `None` when this
/// host's multicast egress went nowhere and the test has nothing to assert.
///
/// `min_gap` is zero, so the gate is open for both families and every test below
/// is about the credit rather than about the spacing.
fn credit_a_multicast_send(mdns: &mut Mdns, body: &[u8]) -> Option<()> {
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
    body,
    MDNS_V4_DST,
    Duration::ZERO,
  );
  if summary.sent == 0 {
    eprintln!("skipping: the datagram never reached a wire on this host");
    return None;
  }
  Some(())
}

/// Open the next tick's claim window and present the echo there, exactly where
/// [`Mdns::tick`] would.
///
/// The echo is presented rather than awaited: what is under test is *when* the
/// credit's window opens, and a real loopback copy would arrive with exactly
/// these — a kernel receive stamp taken after the syscall, read back against the
/// instant the following tick opened with.
fn echo_matched_at_next_tick_top(mdns: &mut Mdns, family: Family, body: &[u8]) -> bool {
  let top = Instant::now();
  mdns.selfsend.seal(top);
  mdns.selfsend.take_at(
    family,
    body,
    std::time::SystemTime::now(),
    top,
    crate::selfsend::MatchMode::Ordered,
  )
}

/// Send once through stage 4 and claim the echo at the next tick's top.
fn echo_is_matched(mdns: &mut Mdns, body: &[u8]) -> Option<bool> {
  credit_a_multicast_send(mdns, body)?;
  Some(echo_matched_at_next_tick_top(mdns, Family::V4, body))
}

#[test]
fn a_send_stalled_past_the_self_send_ttl_still_suppresses_its_own_echo() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  mdns
    .sockets
    .force_send_delays_for_test(Family::V4, &[STALL_PAST_TTL]);
  let body = [0x7Eu8; 32];
  let Some(matched) = echo_is_matched(&mut mdns, &body) else {
    return;
  };
  assert!(
    matched,
    "a stall longer than SELF_SEND_TTL between the pre-syscall stamp and the \
     kernel accepting the datagram must not expire the credit before its own \
     echo can claim it"
  );
}

#[test]
fn an_eintr_retry_past_the_self_send_ttl_still_suppresses_its_own_echo() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  // The first attempt stalls past the TTL and is then interrupted; the second
  // runs at full speed and carries the datagram. Only the second attempt's
  // stamps describe the syscall that actually happened.
  mdns.sockets.force_send_eintr_for_test(Family::V4, 1);
  mdns
    .sockets
    .force_send_delays_for_test(Family::V4, &[STALL_PAST_TTL, Duration::ZERO]);
  let body = [0x1Du8; 32];
  let Some(matched) = echo_is_matched(&mut mdns, &body) else {
    return;
  };
  assert!(
    matched,
    "an EINTR retry must not put a whole failed syscall, and whatever preempted \
     the thread around it, inside the credit's life"
  );
}

/// A dual-stack fixture with IPv6 actually bound, or `None` with a printed
/// reason.
///
/// `loopback_mdns` degrades to IPv4-only where `try_bind_v6` is refused (macOS
/// returns `EINVAL` on every interface), and these two tests are *about* the
/// second family, so an IPv4-only fixture would take them green while asserting
/// nothing.
fn dual_stack_mdns() -> Option<test_support::TestMdns> {
  let mdns = test_support::loopback_mdns()?;
  if !mdns.sockets.is_bound_for_test(Family::V6) {
    eprintln!("skipping: IPv6 is not bound on this host, so there is no second leg to stall");
    return None;
  }
  Some(mdns)
}

#[test]
fn an_ipv6_leg_stalling_past_the_ttl_does_not_expire_the_ipv4_credit() {
  let Some(mut mdns) = dual_stack_mdns() else {
    return;
  };
  // One multicast transmit is two syscalls. IPv4 goes first and takes its
  // credit; IPv6 then stalls past the whole TTL before its own syscall lands.
  // Nothing has drained a datagram in between — stage 1 is behind us — so the
  // IPv4 echo has not had one opportunity to claim its credit.
  mdns
    .sockets
    .force_send_delays_for_test(Family::V6, &[STALL_PAST_TTL]);
  let body = [0x4Au8; 32];
  if credit_a_multicast_send(&mut mdns, &body).is_none() {
    return;
  }
  assert!(
    echo_matched_at_next_tick_top(&mut mdns, Family::V4, &body),
    "the sibling family's stall is time in which no echo could be claimed; \
     charging it to the IPv4 credit expires it before its first opportunity"
  );
}

#[test]
fn an_ipv6_leg_that_stalls_and_then_fails_does_not_expire_the_ipv4_credit() {
  let Some(mut mdns) = dual_stack_mdns() else {
    return;
  };
  // Same stall, but IPv6 never reaches the kernel: interrupted on both attempts,
  // so it records no credit at all. This is the half a record-time sweep cannot
  // explain — with no second `record` there is no sweep, and the credit is lost
  // at claim time instead. Both TTL sites have to move, not just the sweep.
  mdns.sockets.force_send_eintr_for_test(Family::V6, 2);
  mdns
    .sockets
    .force_send_delays_for_test(Family::V6, &[STALL_PAST_TTL, Duration::ZERO]);
  let body = [0x4Bu8; 32];
  if credit_a_multicast_send(&mut mdns, &body).is_none() {
    return;
  }
  assert!(
    echo_matched_at_next_tick_top(&mut mdns, Family::V4, &body),
    "a sibling family that stalls and then fails records nothing, so only the \
     claim-time TTL can expire the IPv4 credit — and it must not"
  );
}

#[test]
fn a_later_same_tick_send_stalling_past_the_ttl_does_not_expire_an_earlier_credit() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  // Stage 4 drains a whole queue of transmits before stage 1 runs again. The
  // first send is clean; the second stalls past the TTL. The first datagram's
  // echo is sitting in the socket queue the entire time and cannot be read until
  // the next tick.
  mdns
    .sockets
    .force_send_delays_for_test(Family::V4, &[Duration::ZERO, STALL_PAST_TTL]);
  let first = [0x5Au8; 32];
  let second = [0x5Bu8; 32];
  if credit_a_multicast_send(&mut mdns, &first).is_none() {
    return;
  }
  if credit_a_multicast_send(&mut mdns, &second).is_none() {
    return;
  }
  assert!(
    echo_matched_at_next_tick_top(&mut mdns, Family::V4, &first),
    "a later datagram in the same tick must not age out an earlier one's \
     credit: receive does not resume until the tick ends, so the earlier echo \
     has had no opportunity at all"
  );
}

#[test]
fn a_stage_seven_goodbye_does_not_evict_an_unclaimed_stage_four_credit() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  // Stage 4 announces, then stage 7 pumps an RFC 6762 §10.1 goodbye in the SAME
  // tick — with stages 5 and 6 between them, and no receive anywhere. The
  // goodbye's own send stalls past the TTL, so a sweep anchored on the goodbye's
  // syscall would evict the announcement's credit.
  mdns
    .sockets
    .force_send_delays_for_test(Family::V4, &[Duration::ZERO, STALL_PAST_TTL]);
  let announcement = [0x6Au8; 32];
  let goodbye = [0x6Bu8; 32];
  if credit_a_multicast_send(&mut mdns, &announcement).is_none() {
    return;
  }
  {
    let Mdns {
      sockets,
      selfsend,
      send_health,
      ..
    } = &mut *mdns;
    super::withdrawal::send_withdrawal(
      sockets,
      selfsend,
      send_health,
      &goodbye,
      &crate::socket::Ungated,
    );
  }
  assert!(
    echo_matched_at_next_tick_top(&mut mdns, Family::V4, &announcement),
    "a stage-7 goodbye recorded a TTL after a stage-4 announcement must not \
     evict that announcement's credit: stage 1 has not run between them, so the \
     announcement's echo is still unclaimed"
  );
}

#[test]
fn a_caller_gap_after_the_claim_window_opened_still_expires_the_credit() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let body = [0x7Au8; 32];
  if credit_a_multicast_send(&mut mdns, &body).is_none() {
    return;
  }
  // The window opens, and then the caller goes away for longer than the TTL.
  // This half must NOT be forgiven: the TTL's other job is bounding false
  // suppression, and a co-resident peer's byte-identical datagram can arrive
  // during a caller stall exactly as it can during a tick. Ageing by tick count,
  // or re-anchoring on every seal, would make the suppression window a function
  // of the caller's loop rate instead of a bound.
  let top = Instant::now();
  mdns.selfsend.seal(top);
  let after_the_gap = top + STALL_PAST_TTL;
  assert!(
    !mdns.selfsend.take_at(
      Family::V4,
      &body,
      std::time::SystemTime::now(),
      after_the_gap,
      crate::selfsend::MatchMode::Ordered,
    ),
    "post-opportunity time is charged in full, caller stalls included, or the \
     false-suppression bound is not a bound"
  );
  mdns.selfsend.seal(after_the_gap);
  assert_eq!(
    mdns.selfsend.len(),
    0,
    "and the seal that observes the gap sweeps the credit rather than granting \
     it another whole TTL"
  );
}

// ── the receive stage's own runtime is charged to the credit ────────────────
//
// The upper half of the same invariant, through the real drain. Once a credit's
// window has opened, `SELF_SEND_TTL` charges elapsed time in full — and the
// receive stage's own runtime is elapsed time like any other. So stage 1 carries
// two monotonic clocks on purpose: the tick's instant, which stays the protocol
// `now` every deadline comparison below needs to be stable, and a live read per
// datagram, which is the only thing the credit is aged against. Weighing a claim
// against the tick's instant charges nothing for a drain that ran long or lost
// the CPU, and the bound on FALSE suppression stops being a bound — a
// co-resident peer's byte-identical datagram, read an unbounded time after the
// seal, still finds a live credit and is swallowed as our own echo.

/// A loopback IPv4-only fixture registered into its own `Poll`, so a send's
/// loopback copy can be waited for.
fn registered_v4_only() -> Option<(test_support::TestMdns, Poll)> {
  let mut mdns = test_support::loopback_mdns_v4_only()?;
  let poll = Poll::new().expect("poll");
  mdns
    .register(poll.registry(), Token(60), Token(61))
    .expect("register");
  Some((mdns, poll))
}

/// Put `body` on the multicast wire and wait until its loopback copy has made
/// the IPv4 socket readable, leaving the credit recorded and unclaimed.
///
/// `None`, with a printed reason, when this host's multicast egress or its
/// loopback delivered nothing — a silent skip is a test that passes while
/// asserting nothing. Readiness is what makes that skip stats-free: it is the
/// kernel's own word that a datagram is queued for the drain below to weigh.
fn queue_own_echo(mdns: &mut Mdns, poll: &mut Poll, body: &[u8]) -> Option<()> {
  credit_a_multicast_send(mdns, body)?;
  let mut events = mio::Events::with_capacity(8);
  let deadline = Instant::now() + Duration::from_secs(2);
  while Instant::now() < deadline {
    poll
      .poll(&mut events, Some(Duration::from_millis(50)))
      .expect("poll");
    for ev in events.iter() {
      if mdns.owns(ev.token()) {
        mdns.handle_io(ev);
      }
    }
    if mdns.sockets.is_readable_for_test(Family::V4) {
      return Some(());
    }
  }
  eprintln!("skipping: this endpoint's own multicast never looped back within the budget");
  None
}

/// Run one tick over a queued echo whose read stalls past the TTL, and report
/// how many credits survived it.
fn credits_after_a_stalled_drain(mdns: &mut Mdns, poll: &mut Poll, body: &[u8]) -> Option<usize> {
  queue_own_echo(mdns, poll, body)?;
  // The tick seals at its top and then loses the CPU inside stage 1, before the
  // read whose claim is weighed against that seal.
  mdns
    .sockets
    .force_recv_delays_for_test(Family::V4, &[STALL_PAST_TTL]);
  mdns.tick().expect("tick");
  Some(mdns.selfsend.len())
}

/// The defect the second clock exists for, on the ordered path.
///
/// The queued datagram is byte-identical to the one we sent, and bytes are all
/// the tracker has: our own echo and a co-resident peer's copy of it are the
/// same datagram here, which is the whole premise of the take-once design. So
/// the only question left is whether the credit's window is still open, and a
/// claim weighed a full `SELF_SEND_TTL` after the seal must be answered "peer".
/// Weighing it against the tick's own instant answers "ours" however long the
/// drain ran.
#[test]
fn an_ordered_claim_past_the_ttl_inside_one_receive_stage_is_rejected() {
  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  let body = [0x8Au8; 32];
  let survived = credits_after_a_stalled_drain(&mut mdns, &mut poll, &body);
  mdns.deregister().expect("deregister");
  let Some(survived) = survived else {
    return;
  };
  assert_eq!(
    survived, 1,
    "a claim evaluated a whole SELF_SEND_TTL after the seal must find the credit \
     expired: ageing it against the tick's own instant instead leaves the \
     false-suppression window a function of how long the drain happened to run"
  );
}

/// The same, on the path that has no arrival stamp at all.
///
/// `Degraded` is the whole self-send match on Windows and on any kernel that
/// delivers no timestamp cmsg, and it is content-hash matching bounded by
/// nothing but this TTL — so the TTL going unbounded there is not one guard of
/// two failing, it is the only guard failing. The forced absence of the stamp is
/// what makes that arm reachable from a host whose kernel does supply one.
#[test]
fn a_degraded_claim_past_the_ttl_inside_one_receive_stage_is_rejected() {
  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  mdns.sockets.force_no_rx_time_for_test();
  let body = [0x8Bu8; 32];
  let survived = credits_after_a_stalled_drain(&mut mdns, &mut poll, &body);
  mdns.deregister().expect("deregister");
  let Some(survived) = survived else {
    return;
  };
  assert_eq!(
    survived, 1,
    "with no arrival stamp the TTL is the entire bound on false suppression, so \
     a claim past it must be rejected on the degraded path too"
  );
}

/// The over-correction guard, and this section's positive control.
///
/// A live clock read must not turn into rejecting genuine loopback: a claim made
/// promptly inside the same receive stage still suppresses our own echo. It is
/// also the one test here that fails outright if this host's multicast never
/// loops back, so the two above cannot quietly pass by weighing a datagram that
/// was never delivered.
#[test]
fn a_prompt_claim_inside_the_receive_stage_still_suppresses_our_own_echo() {
  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  let body = [0x8Cu8; 32];
  let queued = queue_own_echo(&mut mdns, &mut poll, &body).is_some();
  if queued {
    mdns.tick().expect("tick");
  }
  let credits = mdns.selfsend.len();
  mdns.deregister().expect("deregister");
  if !queued {
    return;
  }
  assert_eq!(
    credits, 0,
    "our own loopback copy, read promptly after the seal, must still consume its \
     credit: the live clock bounds the window, it does not close it"
  );
}

// ── the claim's clock is read AT the claim, by the claim ────────────────────
//
// The defect class, closed at the signature rather than at another call site. A
// self-send credit's liveness was mis-evaluated six times, each in a different
// window between a caller's clock read and the comparison, and the read walked
// inward every round: the pre-syscall wall stamp, the recording tick, the tick's
// top, and finally the instant taken immediately after `recv`. That last one
// still left both admission gates — the ingress trust boundary and the §11
// source-port rule — plus whatever the scheduler does among them running on a
// frozen clock. A credit that expires in there is weighed as live, a
// byte-identical PEER datagram spends it, and the genuine loopback copy behind
// it reaches the protocol layer as peer traffic: a phantom conflict against
// ourselves and the RFC 6762 §9 rename that follows.
//
// So `SelfSendTracker::take` now takes no instant from anyone and reads the
// monotonic clock at its own liveness decision. No caller can supply a stale one
// because no caller can supply one at all.
//
// The two tests below stall exactly there — after the read, after both gates,
// with only the credit check left — in each match mode. The stalled-drain tests
// in the section above stall INSIDE `recv`, before that instant was even
// captured, so neither of them can reach this window.

/// Run one tick over a queued echo that is read and admitted at full speed and
/// then loses the CPU past the TTL with only the credit check ahead of it.
///
/// Reports the credits that survived, and whether the injected stall was
/// actually consumed — which is what makes the survivor count mean something. A
/// datagram dropped at either admission gate never reaches the claim, and would
/// leave the credit untouched for a reason that has nothing to do with the
/// clock.
fn credits_after_a_stalled_claim(
  mdns: &mut Mdns,
  poll: &mut Poll,
  body: &[u8],
) -> Option<(usize, bool)> {
  queue_own_echo(mdns, poll, body)?;
  mdns.force_claim_delays_for_test(&[STALL_PAST_TTL]);
  mdns.tick().expect("tick");
  Some((mdns.selfsend.len(), mdns.forced_claim_delays.is_empty()))
}

/// The seventh window, on the ordered path.
///
/// The queued datagram is byte-identical to the one we sent and its kernel stamp
/// is correctly ordered after the send, so ordering says nothing here — exactly
/// as it says nothing about a co-resident peer's copy of our own announcement.
/// The whole answer is whether the credit's window is still open when the claim
/// is made, and a claim made a full `SELF_SEND_TTL` after the seal must be
/// answered "peer" however early the driver happened to read a clock.
#[test]
fn an_ordered_claim_stalled_after_admission_is_rejected() {
  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  let body = [0x9Au8; 32];
  let outcome = credits_after_a_stalled_claim(&mut mdns, &mut poll, &body);
  mdns.deregister().expect("deregister");
  let Some((survived, stalled)) = outcome else {
    return;
  };
  assert!(
    stalled,
    "the stall is consumed at the claim itself, so an unconsumed one means the \
     echo never got past the admission gates and this test asserted nothing"
  );
  assert_eq!(
    survived, 1,
    "a claim evaluated a whole SELF_SEND_TTL after the seal must find the credit \
     expired even when every instant before the admission gates was fresh: the \
     age belongs to the claim, not to whatever the drain read on its way there"
  );
}

/// The same window on the path that has no arrival stamp at all.
///
/// `Degraded` is the whole self-send match on Windows and on any kernel that
/// delivers no timestamp cmsg: content hash bounded by this TTL and nothing
/// else. So a claim aged from before the gates is not one guard of two failing
/// there, it is the only guard failing. Forcing the stamp away is what makes the
/// arm reachable from a host whose kernel does supply one.
#[test]
fn a_degraded_claim_stalled_after_admission_is_rejected() {
  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  mdns.sockets.force_no_rx_time_for_test();
  let body = [0x9Bu8; 32];
  let outcome = credits_after_a_stalled_claim(&mut mdns, &mut poll, &body);
  mdns.deregister().expect("deregister");
  let Some((survived, stalled)) = outcome else {
    return;
  };
  assert!(
    stalled,
    "the stall is consumed at the claim itself, so an unconsumed one means the \
     echo never got past the admission gates and this test asserted nothing"
  );
  assert_eq!(
    survived, 1,
    "with no arrival stamp the TTL is the entire bound on false suppression, so \
     a claim stalled past it between admission and the credit check must be \
     rejected on the degraded path too"
  );
}

// ── the wire gate is weighed at the SEND, not at the top of the tick ─────────
//
// The gate is a real-time question about one family's wire — has it had its gap?
// — so the instant it is weighed against must be the one at which the datagram
// is offered. `tick`'s own instant is read before stages 1 through 3 and before
// every earlier datagram in stage 4's own walk, so on it a gap the wire has
// genuinely paid still reads as unpaid, the family is withheld, and it is
// reported `Missed` — which spends the core's partial-round patience for a wire
// that was ready.
//
// The window in which the tick's instant and the wire's disagree is normally one
// syscall wide. It is widened here the only way a test can: by stalling the send,
// which pushes the gate's own anchor (the WIRE instant) far past the core's
// confirm anchor (the PRE-syscall one) and opens a stretch in which a probe is
// genuinely due and the wire genuinely has its gap.

/// How long the first §8.1 probe is held inside its `send_to`. It sets the width
/// of that stretch: `GATE_ANCHOR_STALL - PROBE_MIN_FAMILY_GAP`.
const GATE_ANCHOR_STALL: Duration = Duration::from_millis(600);

/// Where in that stretch the stale tick instant is aimed, measured back from the
/// wire instant: past the core's own next-probe deadline (so a probe really is
/// due) and before the wire instant itself (so the gate, weighed there, cannot
/// even subtract a gap).
const GATE_STALE_TICK_OFFSET: Duration = Duration::from_millis(300);

#[test]
fn the_wire_gate_is_weighed_at_the_send_not_at_the_tick() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  if !mdns.sockets.is_bound_for_test(Family::V4) {
    eprintln!("skipping: IPv4 is not bound on this host");
    return;
  }
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-gate-anchor._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns
    .sockets
    .force_send_delays_for_test(Family::V4, &[GATE_ANCHOR_STALL]);
  // The service's first datagram is its first probe, and it is the one that
  // stalls. Nothing else can reach this wire: no query is running and no peer is
  // on loopback.
  let give_up = Instant::now() + Duration::from_secs(5);
  while mdns.sockets.wire_times_for_test(Family::V4).is_empty() {
    if Instant::now() >= give_up {
      eprintln!("skipping: no probe reached this host's wire within the budget");
      return;
    }
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(5));
  }
  let wire_times = mdns.sockets.wire_times_for_test(Family::V4);
  assert_eq!(
    wire_times.len(),
    1,
    "only the stalled first probe may have gone out, or the offsets below aim \
     at the wrong round"
  );
  let Some(&wire) = wire_times.first() else {
    return;
  };
  let Some(stale) = wire.checked_sub(GATE_STALE_TICK_OFFSET) else {
    eprintln!("skipping: this host's monotonic clock is too young to subtract from");
    return;
  };
  // Wait until the wire's own gap is genuinely paid, so the only thing that can
  // still withhold this family is an instant read before the wait.
  let open = wire + PROBE_MIN_FAMILY_GAP + Duration::from_millis(50);
  while Instant::now() < open {
    std::thread::sleep(Duration::from_millis(5));
  }
  // A tick instant from inside the stretch: the core says the next probe is due
  // at it, and the gate weighed at it reads a wire instant in its own future.
  // Stage 3 then stage 4, both on that instant, exactly as a tick runs them:
  // the timer is what arms the next probe, and the drain is what offers it.
  mdns.fire_timeouts(stale);
  mdns.drain_transmits(stale);
  assert!(
    mdns.sockets.wire_times_for_test(Family::V4).len() > 1,
    "the wire had paid its {PROBE_MIN_FAMILY_GAP:?} and the core had a probe \
     due, but the family was withheld — the gate was weighed against the tick's \
     instant instead of the instant the datagram was offered"
  );
}

// ── the SECOND family is admitted at its own offer ───────────────────────────
//
// A fan-out is SEQUENTIAL, so v4's `sendto` — and any preemption around it —
// runs between v6's admission being decided and v6 being offered anything. A
// mask computed once for the fan-out therefore answers v6's question at v4's
// instant, and is wrong in exactly one direction: a wire that has since paid its
// gap still reports `Gated`, which the projection maps to `Missed`, which spends
// the core's partial-round patience for a family that was ready.
//
// The window is normally one syscall wide. `forced_send_delays` widens it from
// inside v4's own send path, which is the seam that already exists — nothing new
// is needed to reach the cross-family case, only two bound families.

/// How long v4 is held inside its `sendto`. Must exceed
/// [`CROSS_FAMILY_MARGIN`], or v6's deadline does not fall inside the fan-out at
/// all and the test asserts nothing.
const CROSS_FAMILY_STALL: Duration = Duration::from_millis(300);

/// How far short of its own deadline v6 starts: small enough that the stall
/// crosses it with room, wide enough that a mask frozen at the top of the
/// fan-out cannot drift past it.
const CROSS_FAMILY_MARGIN: Duration = Duration::from_millis(100);

#[test]
fn the_second_family_is_admitted_at_its_own_offer_not_at_the_fan_outs() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  if !mdns.sockets.is_bound_for_test(Family::V6) {
    eprintln!("skipping: the cross-family window needs two bound families and this host bound one");
    return;
  }
  let gap = PROBE_MIN_FAMILY_GAP;
  let mut gate = FamilyWireGate::default();

  // Round one seeds v6's gate and leaves v4's untouched: the socket refuses v4,
  // so it puts nothing on a wire and the gate records nothing for it. That
  // asymmetry is what makes v4 open and v6 nearly-shut in round two — one
  // producer, one `min_gap`, two families at different points in it.
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, true);
  {
    let Mdns {
      sockets,
      selfsend,
      send_health,
      ..
    } = &mut *mdns;
    super::send_and_credit(
      sockets,
      selfsend,
      send_health,
      &mut gate,
      b"seed",
      MDNS_V4_DST,
      gap,
    );
  }
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, false);
  let Some(&v6_wire) = mdns.sockets.wire_times_for_test(Family::V6).first() else {
    eprintln!(
      "skipping: IPv6 is bound but its multicast egress failed, so its gate never moved and \
       there is no deadline for the fan-out to cross"
    );
    return;
  };

  // Wait until v6 is exactly `CROSS_FAMILY_MARGIN` short of its own deadline. A
  // decision taken now says v6 is gated; the truth at v6's own offer, after v4's
  // stall, is that it is not.
  let offer = v6_wire + gap - CROSS_FAMILY_MARGIN;
  while Instant::now() < offer {
    std::thread::sleep(Duration::from_millis(5));
  }
  if Instant::now() >= v6_wire + gap {
    eprintln!("skipping: this host overslept v6's own deadline, so the window never existed");
    return;
  }
  mdns
    .sockets
    .force_send_delays_for_test(Family::V4, &[CROSS_FAMILY_STALL]);
  let summary = {
    let Mdns {
      sockets,
      selfsend,
      send_health,
      ..
    } = &mut *mdns;
    super::send_and_credit(
      sockets,
      selfsend,
      send_health,
      &mut gate,
      b"offer",
      MDNS_V4_DST,
      gap,
    )
  };
  assert_eq!(
    summary.delivery.v6(),
    FamilyDelivery::Delivered,
    "v6's {gap:?} came due {CROSS_FAMILY_MARGIN:?} into v4's {CROSS_FAMILY_STALL:?} stall, \
     before v6 had been offered anything at all — reporting it missed weighs v6's admission \
     at v4's instant and spends the core's partial-round patience on a ready wire"
  );
}

// ── stage 7 reads its own clock ─────────────────────────────────────────────
//
// A withdrawal item's whole schedule is defined relative to the instant it is
// CREATED: `next_at` is that instant, and the 2 s anti-pin ceiling is measured
// from it. Stage 7 is where the pipeline creates one — for a service an earlier
// stage retired without beginning its goodbye — and on the tick's instant every
// microsecond of stages 1 through 6 is deducted from that ceiling for a schedule
// that did not exist while they ran. Past ~1.75 s of it the endpoint's own clamp
// puts the next round inside the 250 ms §10.1 interval, and the pass after that
// makes the one final ceiling attempt and frees the route with debt still owed.

/// A tick whose receive stage alone runs longer than the §10.1 interval the
/// schedule it is about to create owes. Past the 1.75 s at which the endpoint's
/// re-arm clamp starts cutting that interval short.
const SLOW_STAGE_ONE: Duration = Duration::from_millis(1_800);

/// Stands in for the run loop's re-entry while a goodbye drains.
const WITHDRAWAL_DRIVE_POLL: Duration = Duration::from_millis(5);

/// Tick until nothing is withdrawing, and return the instants IPv4's wire
/// recorded after `already_on_wire` — every one of which is a goodbye, since a
/// withdrawing service transmits in no other stage.
fn drive_withdrawal_to_settled(mdns: &mut Mdns, already_on_wire: usize) -> Vec<Instant> {
  let deadline = Instant::now() + GOODBYE_CEILING + Duration::from_secs(2);
  while mdns.endpoint.has_pending_withdrawals() && Instant::now() < deadline {
    mdns.tick().expect("tick");
    std::thread::sleep(WITHDRAWAL_DRIVE_POLL);
  }
  assert!(
    !mdns.endpoint.has_pending_withdrawals(),
    "the withdrawal outlived its own anti-pin ceiling"
  );
  let mut all = mdns.sockets.wire_times_for_test(Family::V4);
  all.split_off(already_on_wire)
}

/// An IPv4-only endpoint whose one service has announced, plus how many
/// datagrams that took, so everything after them is a goodbye.
fn advertised_service(
  ty: &str,
) -> Option<(test_support::TestMdns, mdns_proto::ServiceHandle, usize)> {
  let mut mdns = test_support::loopback_mdns_v4_only()?;
  if !mdns.sockets.is_bound_for_test(Family::V4) {
    eprintln!("skipping: IPv4 is not bound on this host");
    return None;
  }
  let handle = mdns
    .register_service(test_support::service_spec(ty, 8080))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return None;
  }
  let already_on_wire = mdns.sockets.wire_times_for_test(Family::V4).len();
  Some((mdns, handle, already_on_wire))
}

/// A goodbye begun by stage 7 is scheduled from stage 7, not from the top of the
/// tick that reached it.
///
/// The service is retired the way an internal retirement does it — `withdrawing`
/// set, the goodbye NOT begun — which is exactly the gap stage 7 scans for and
/// the only path that creates a withdrawal from inside a tick.
#[test]
fn a_goodbye_begun_in_stage_seven_is_scheduled_from_stage_seven() {
  let Some((mut mdns, handle, already_on_wire)) =
    advertised_service("_hick-mio-slow-tick._tcp.local.")
  else {
    return;
  };
  mdns
    .services
    .get_mut(&handle)
    .expect("the service context")
    .withdrawing = true;
  mdns.sockets.set_readable_for_test(Family::V4, true);
  mdns
    .sockets
    .force_recv_delays_for_test(Family::V4, &[SLOW_STAGE_ONE]);
  // The item is created after that stall, so its ceiling is at least this far
  // out. A LOWER bound is what the spacing assertion wants: understating it can
  // only weaken the floor it computes, never move it somewhere the fix does not
  // reach.
  let ceiling_floor = Instant::now() + SLOW_STAGE_ONE + GOODBYE_CEILING;
  mdns.tick().expect("tick");
  assert!(
    mdns.endpoint.has_pending_withdrawals(),
    "stage 7 must begin the goodbye of a service retired without one"
  );
  let wire_times = drive_withdrawal_to_settled(&mut mdns, already_on_wire);
  assert_eq!(
    wire_times.len(),
    usize::from(super::withdrawal::GOODBYE_ROUNDS_PER_FAMILY),
    "IPv4 owed a full §10.1 budget; a schedule anchored at the top of the slow \
     tick loses the last round to the anti-pin ceiling and frees the route with \
     the debt still owed"
  );
  assert_goodbye_wire_spacing("a goodbye begun by a slow tick", &wire_times, ceiling_floor);
}

// ── a paid family owes no further goodbye ───────────────────────────────────
//
// §10.1 debt is per family and the resend schedule is per item. Once one family
// has paid every round and the other is still failing, a `Sent` on the paid one
// is (correctly) not progress, so the endpoint re-arms the item on its 20 ms
// retry backoff for the sake of the family that still owes. A driver that fans
// every round to both families then puts a redundant TTL=0 goodbye on the paid
// family's wire every 20 ms until the ceiling — dozens of multicast datagrams
// per service, at a per-family spacing of 20 ms where §10.1 asks for 250 ms.

/// A family that has paid its whole §10.1 budget is not offered the rounds the
/// other family's retries keep producing.
#[test]
fn a_paid_family_carries_no_goodbye_while_the_blocked_one_retries() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  if mdns.bound_families() != (true, true) {
    eprintln!(
      "skipping: this host did not bind both families, so no family can be paid \
       while another still owes"
    );
    return;
  }
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-goodbye-debt._tcp.local.",
      8080,
    ))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }
  let already_on_wire = mdns.sockets.wire_times_for_test(Family::V4).len();
  // IPv6 refuses every datagram from here on, so it keeps its goodbye debt and
  // the item re-arms on the endpoint's short retry backoff for its sake.
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V6, true);
  mdns.unregister_service(handle);
  let wire_times = drive_withdrawal_to_settled(&mut mdns, already_on_wire);
  assert_eq!(
    wire_times.len(),
    usize::from(super::withdrawal::GOODBYE_ROUNDS_PER_FAMILY),
    "IPv4 owed exactly its §10.1 budget and paid it; every datagram after that \
     is a retraction of records nothing still advertises, emitted only because \
     IPv6 is retrying"
  );
  for pair in wire_times.windows(2) {
    let gap = pair[1].saturating_duration_since(pair[0]);
    assert!(
      gap >= GOODBYE_MIN_FAMILY_GAP,
      "two goodbyes for one name reached IPv4's wire {gap:?} apart, inside the \
       {GOODBYE_MIN_FAMILY_GAP:?} §10.1 gives one family's wire — the blocked \
       family's retry cadence was applied to the paid family's transmissions"
    );
  }
}

/// The endpoint's own per-family goodbye budget is what the driver projects.
///
/// Pinned against the ENDPOINT rather than against the driver: this pumps
/// `poll_withdrawal_transmit` directly, so it counts the rounds the endpoint
/// itself owes rather than the rounds the driver was willing to offer. A change
/// to `mdns-proto`'s budget therefore fails here, instead of leaving the driver
/// silently withholding a goodbye a family still owes.
#[test]
fn the_endpoints_goodbye_budget_is_what_the_driver_projects() {
  let Some((mut mdns, handle, _)) = advertised_service("_hick-mio-goodbye-budget._tcp.local.")
  else {
    return;
  };
  mdns.unregister_service(handle);
  let mut at = Instant::now();
  let mut rounds = 0usize;
  // One more turn than the projection expects, so an endpoint that owes MORE is
  // counted rather than truncated.
  for _ in 0..usize::from(super::withdrawal::GOODBYE_ROUNDS_PER_FAMILY).saturating_add(2) {
    let emitted = test_support::collect_goodbyes(&mut mdns, at);
    if emitted.is_empty() {
      break;
    }
    rounds = rounds.saturating_add(emitted.len());
    at += GOODBYE_MIN_FAMILY_GAP + Duration::from_millis(10);
  }
  assert_eq!(
    rounds,
    usize::from(super::withdrawal::GOODBYE_ROUNDS_PER_FAMILY),
    "`GOODBYE_ROUNDS_PER_FAMILY` restates a crate-private `mdns-proto` constant; \
     they have drifted, and the driver is now projecting a debt the endpoint \
     does not have"
  );
}

use std::{
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
  time::{Duration, Instant},
};

use mdns_proto::{
  CollectedAnswer, FamilyAttempt, ServiceState, ServiceUpdate,
  wire::{ResourceClass, ResourceType},
};
use mio::{Poll, Token};

use super::{
  EVENT_QUEUE_COMPACT_THRESHOLD, FamilyWireGate, MAX_SEND_CREDITS_PER_DRAIN,
  RETRY_INTEREST_BACKOFF, TxQueue, datagram_cost, packet_is_response, test_support,
};
use hick_udp::{
  onlink::{DestinationWitness, IfaceWitness},
  selfsend::{RxDatagram, SELF_SEND_TTL, SelfSendMatch},
};

use crate::{
  endpoint::Mdns,
  error::RegisterError,
  event::{Event, EventQueue},
  socket::{Family, MDNS_V4_DST},
};

/// Whether a claim consumed a credit at all, at either strength.
///
/// A test whose subject is the take-once bookkeeping — which credit was
/// consumed, which survived — says so through this, so the tier tests stay the
/// only place a strength is asserted and a change to one is not lost in the
/// other. It is deliberately NOT a method on `SelfSendMatch`: a driver mapping
/// an echo onto a trust tier must read the variant, and a public flattener is
/// exactly the collapse the tier exists to prevent.
fn consumed(m: SelfSendMatch) -> bool {
  !matches!(m, SelfSendMatch::NoCredit)
}

/// `idx` as the interface witness a receive path that DID name the link would
/// mint.
///
/// Spelled with a `match` rather than `unwrap`, and defaulting to
/// [`IfaceWitness::Lost`], because a zero would be a fixture bug and `Lost` is
/// the value that cannot silently widen the §11 gate if one ever appeared.
fn iface_witness(idx: u32) -> IfaceWitness {
  match core::num::NonZeroU32::new(idx) {
    Some(idx) => IfaceWitness::Witnessed(idx),
    None => IfaceWitness::Lost,
  }
}

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
  // A freshly registered service carries its own §8.1 probe deadline, so the
  // fold alone is enough to bring the caller back — no zero-timeout override
  // is needed for it, unlike a freshly started query.
  assert!(
    mdns.endpoint.poll_service_timeout(handle).is_some(),
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
    .keys()
    .filter_map(|h| mdns.endpoint.poll_service_timeout(*h))
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
  assert!(matches!(
    summary.attempts[Family::V4.index()],
    FamilyAttempt::Accepted { .. }
  ));
  // Take it back with the body: the credit is keyed to the family that carried
  // it and to the fingerprint of what went out. No receive stamp is offered, so
  // the claim runs on content and family alone.
  assert!(consumed(selfsend.claim_at(
    &RxDatagram::without_stamp(Family::V4, &body[..]),
    hick_udp::selfsend::ClockPair::now()
  )));
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
  assert_eq!(
    summary.attempts[Family::V4.index()],
    FamilyAttempt::Refused { permanent: false },
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
    second.attempts[Family::V4.index()],
    FamilyAttempt::GateShut,
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
    matches!(
      summary.attempts[Family::V4.index()],
      FamilyAttempt::Accepted { .. }
    ),
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
    FamilyAttempt::NoSocket,
    "an unbound family has no peers to withdraw from; its debt must not pin the route"
  );
  assert_ne!(
    v4,
    FamilyAttempt::NoSocket,
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
    FamilyAttempt::Refused { permanent: false },
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
    .filter(|o| matches!(o, FamilyAttempt::Accepted { .. }))
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
  if !test_support::drive_to_advertised(&mut mdns, handle) {
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
///
/// **`is_idle` is a termination guarantee, not a delivery one.**
/// `drain_withdrawals` exits its pump loop once every family's debt clears OR
/// the §10.1 anti-pin ceiling force-completes the item regardless of debt, and
/// `goodbyes_tx` is bumped only on the former path — so this binary racing
/// others against the same real multicast group (`BIND_LOCK` only serialises
/// binds within THIS process) can legitimately refuse every round for the
/// whole ceiling and reach `is_idle` with `goodbyes_tx` unmoved.
///
/// **`degraded_families` is not the discriminator, and must not become one.**
/// It is PER FAMILY, so on a dual-stack host it can be true for a family that
/// never sent anything while the OTHER family delivered every round fine — a
/// real `goodbyes_tx` regression would then still reach `is_idle` with
/// `goodbyes_tx` unmoved and one family degraded, and a bare
/// `v4_degraded || v6_degraded` would wrongly accept that. It is ALSO a
/// three-CONSECUTIVE-failure threshold (`MAX_CONSECUTIVE_SEND_FAILURES`), so
/// it can still read `false` after a real, total non-delivery if the
/// scheduler starved this test down to only one or two actual attempts before
/// the ceiling forced completion — a discriminator built from it would then
/// be unsound in the OTHER direction, flaking on exactly the contention this
/// test exists to tolerate.
///
/// `packets_tx` is the one signal that is both independent AND complete: it
/// is bumped inside `Sockets::send_one`, a code path `drain_withdrawals`'s own
/// `goodbyes_tx` bump never touches, so it moves if and only if a real send
/// reached the kernel — on however many attempts were actually made. If it
/// rose during this withdrawal, `goodbyes_tx` must have risen too,
/// unconditionally — see
/// `a_withdrawal_where_one_family_delivers_while_the_other_is_refused` for the
/// deterministic case this closes. If it did NOT rise, `goodbyes_tx` staying
/// put is not merely tolerated but PROVEN correct: `goodbyes_tx` cannot rise
/// without an antecedent `packets_tx` bump, so nothing further needs
/// corroborating.
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
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }

  mdns.shutdown();
  let goodbyes_before = mdns.stats().goodbyes_tx;
  let packets_before = mdns.stats().packets_tx;
  let deadline = Instant::now() + Duration::from_secs(5);
  while !mdns.is_idle() && Instant::now() < deadline {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(20));
  }
  assert!(mdns.is_idle(), "shutdown must terminate");

  let goodbyes_after = mdns.stats().goodbyes_tx;
  let packets_after = mdns.stats().packets_tx;
  if packets_after > packets_before {
    assert!(
      goodbyes_after > goodbyes_before,
      "a raw send reached the kernel during this withdrawal (packets_tx {packets_before} -> \
       {packets_after}), so goodbyes_tx must have bumped too; it stayed at {goodbyes_before}"
    );
    return;
  }
  assert_eq!(
    goodbyes_after, goodbyes_before,
    "no raw send reached the kernel this withdrawal (packets_tx stayed at {packets_before}), \
     so goodbyes_tx cannot have moved either — it went to {goodbyes_after}"
  );
  // Informational only, deliberately not asserted: `degraded_families` needs
  // three CONSECUTIVE non-`Accepted` outcomes, so a scheduler that starved
  // this test down to only one or two real attempts before the ceiling fired
  // can leave it `false` even though every attempt made genuinely failed.
  // `packets_tx` not moving, asserted above, is already the complete proof.
  let (v4_degraded, v6_degraded) = mdns.degraded_families();
  eprintln!(
    "note: the withdrawal completed via its anti-pin ceiling with neither packets_tx nor \
     goodbyes_tx moving this run (degraded v4={v4_degraded} v6={v6_degraded})"
  );
}

/// The exact gap a bare `v4_degraded || v6_degraded` leaves open: IPv4 pays
/// its whole §10.1 budget (real sends, real `Accepted`s) while IPv6 is
/// unconditionally refused and goes degraded. A dual-stack disjunction that
/// accepts "some family is degraded" as license for `goodbyes_tx` staying put
/// would pass here even if the `goodbyes_tx` bump were deleted outright —
/// IPv6's degradation says nothing about whether IPv4's real deliveries were
/// counted. `packets_tx` is what actually pins it: IPv4's sends bump it
/// (independently of `goodbyes_tx`), so this test requires `goodbyes_tx` to
/// have risen too, unconditionally, regardless of IPv6's health.
#[test]
#[cfg(feature = "stats")]
fn a_withdrawal_where_one_family_delivers_while_the_other_is_refused() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  if mdns.bound_families() != (true, true) {
    eprintln!(
      "skipping: this host did not bind both families, so IPv4 delivering while IPv6 is \
       refused cannot be exercised"
    );
    return;
  }
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-goodbye-mixed._tcp.local.",
      8080,
    ))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }

  // IPv6 refuses every datagram from here on; IPv4 is untouched and keeps
  // sending for real.
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V6, true);

  mdns.shutdown();
  let goodbyes_before = mdns.stats().goodbyes_tx;
  let packets_before = mdns.stats().packets_tx;
  let deadline = Instant::now() + Duration::from_secs(5);
  while !mdns.is_idle() && Instant::now() < deadline {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(20));
  }
  assert!(mdns.is_idle(), "shutdown must terminate");

  let (_, v6_degraded) = mdns.degraded_families();
  assert!(
    v6_degraded,
    "IPv6 was forced to refuse every send for the whole withdrawal; it must report degraded"
  );
  assert!(
    mdns.stats().packets_tx > packets_before,
    "IPv4 was never touched and owed a real §10.1 budget, so at least one of its sends must \
     have reached the kernel"
  );
  assert!(
    mdns.stats().goodbyes_tx > goodbyes_before,
    "IPv4 delivered real withdrawal rounds (packets_tx {packets_before} -> {}), so goodbyes_tx \
     must have bumped regardless of IPv6 being degraded — a bare v4_degraded || v6_degraded \
     disjunction would wrongly accept goodbyes_tx staying at {goodbyes_before} here",
    mdns.stats().packets_tx
  );
}

/// The disjunction `a_delivered_withdrawal_round_bumps_goodbyes_tx` and
/// `tests/loopback.rs`'s `shutdown_drives_goodbyes_to_idle_and_a_peer_observes_them`
/// both check when `goodbyes_tx` does NOT rise, forced here rather than left to
/// chance: every family is made to refuse every send (`WouldBlock`, exactly what
/// a busy wire under real cross-process contention reports — see
/// `Sockets::send_one`), so the withdrawal can only ever complete via the 2 s
/// anti-pin ceiling with zero rounds ever `Accepted`.
///
/// This is the deterministic sibling of the ALL-refused branch the two tests
/// above only reach by chance under contention: forced here every run,
/// `is_idle` still reaches true (the ceiling's job, and unconditional on
/// family health), `goodbyes_tx` never moves, and BOTH are asserted alongside
/// EVERY bound family reporting degraded — proving that branch of their
/// disjunction is not vacuous, i.e. that `degraded_families` really does
/// explain a zero count rather than merely happening not to contradict it in
/// whatever a real socket did this run. The OTHER branch — one family
/// delivering for real while the other is refused, which a degraded family
/// alone must NOT excuse — is
/// `a_withdrawal_where_one_family_delivers_while_the_other_is_refused`.
#[test]
#[cfg(feature = "stats")]
fn a_withdrawal_that_never_delivers_still_reaches_idle_with_degraded_families() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-goodbye-refused._tcp.local.",
      8080,
    ))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }
  let (v4, v6) = mdns.bound_families();
  assert!(v4, "the loopback fixture must bind IPv4");

  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, true);
  if v6 {
    mdns
      .sockets
      .force_send_wouldblock_for_test(Family::V6, true);
  }

  mdns.shutdown();
  let before = mdns.stats().goodbyes_tx;
  // Comfortably past the 2 s anti-pin ceiling: every round from here is a
  // refusal, so completion can only come from the ceiling forcing it, never
  // from debt clearing.
  let deadline = Instant::now() + Duration::from_secs(5);
  while !mdns.is_idle() && Instant::now() < deadline {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(20));
  }
  assert!(
    mdns.is_idle(),
    "the anti-pin ceiling must still force the withdrawal to completion when every family \
     refuses every round"
  );
  assert_eq!(
    mdns.stats().goodbyes_tx,
    before,
    "every round was forced to WouldBlock, so no round should ever have reached Accepted"
  );
  let (v4_bound, v6_bound) = mdns.bound_families();
  let (v4_degraded, v6_degraded) = mdns.degraded_families();
  assert!(
    (!v4_bound || v4_degraded) && (!v6_bound || v6_degraded),
    "every bound family refused every round for the whole ceiling, so EVERY bound family must \
     report degraded delivery (v4_bound={v4_bound} v4_degraded={v4_degraded}, \
     v6_bound={v6_bound} v6_degraded={v6_degraded}) — this is the all-refused branch the \
     goodbyes_tx tests' disjunction depends on, and it must not be vacuous"
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
///
/// Fewer than 2 wire times is not this property failing: the same anti-pin
/// ceiling that bounds the spacing above also force-completes the withdrawal
/// whatever a family answers, so a busy wire (this binary's own contention
/// with whatever else is bound to the shared multicast group) can legitimately
/// leave 0 or 1 round on IPv4's wire with the re-arm logic this helper checks
/// never having been exercised twice. The bug this guards against is a
/// too-small GAP between two rounds that did land, which a short count cannot
/// manufacture — dropping a round only ever widens the gap to whatever comes
/// after it — so skipping the comparison loses no coverage of it.
fn assert_goodbye_wire_spacing(kind: &str, wire_times: &[Instant], ceiling_floor: Instant) {
  if wire_times.len() < 2 {
    eprintln!(
      "skipping: {kind}: only {} goodbye(s) reached IPv4's wire before the withdrawal \
       completed, so there is no consecutive pair to weigh — consistent with the anti-pin \
       ceiling refusing every round on a busy wire, not with a spacing regression",
      wire_times.len()
    );
    return;
  }
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

/// Why a rename that does not happen is never excused as an unsuitable host.
///
/// The conflicting probe is handed straight to `Endpoint::handle` by
/// [`test_support::ingest`], so the §8.2 tiebreak that renames the service is
/// reached without a peer, without a link, and without a single byte leaving a
/// socket. The budget below is two orders of magnitude past the in-memory work
/// it bounds. Nothing about it is environmental, so a timeout is a defect in §9
/// conflict handling or in the `Renamed` update reaching the caller.
const RENAME_IS_NOT_ENVIRONMENTAL: &str = "an ingested §8.2 tiebreak loss must rename the service: the probe reaches the \
   core without touching a socket, so nothing here depends on this host";

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
/// Also pins the RECLAIMABILITY. A surviving rename VACATES its old name — the
/// service is alive under a different one — so the detached goodbye does not
/// hold that name against re-registration the way a dead service's does. A
/// replacement may take it while the retraction is still owed, and the
/// retraction still goes out. (A goodbye that HOLDS its name is the other case
/// entirely: the service went terminal under the name it already had, so
/// nothing is left to re-announce it and the retraction must land before the
/// name can be reused.)
#[test]
fn a_surviving_rename_vacates_the_old_name_and_still_retracts_it() {
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

  let conflict = test_support::conflict_response(&old);
  let new_name = drive_to_rename(&mut mdns, &conflict).expect(RENAME_IS_NOT_ENVIRONMENTAL);
  assert_ne!(new_name, old, "a rename must change the instance name");
  assert!(
    !mdns
      .services
      .get(&handle)
      .expect("a survived rename keeps its context")
      .withdrawing,
    "a rename must not retire the renamer; a retired service would prove \
     nothing about the surviving path"
  );

  assert!(
    mdns.endpoint.has_pending_withdrawals(),
    "a surviving rename must leave the old name's goodbye owed"
  );
  // Asserted while the retraction is STILL OWED, which is the whole point: a
  // name held against reuse would refuse this, and a test that registered after
  // the schedule drained would pass either way.
  let replacement = mdns
    .register_service(test_support::named_service_spec("survivor", ty, 9090))
    .expect("a vacated name is reclaimable while its retraction is still owed");
  assert_ne!(
    replacement, handle,
    "the replacement is a registration of its own, not the renamed service"
  );

  // And the reclaim costs the retraction nothing: it is still enqueued and still
  // goes out. Read past the resend interval — this tick has already pumped and
  // confirmed the first round, and a confirmed round re-arms 250 ms out.
  let first_round = Instant::now() + Duration::from_millis(400);
  let goodbyes = test_support::collect_goodbyes(&mut mdns, first_round);
  assert!(
    goodbyes.iter().any(|d| test_support::retracts(d, &old)),
    "the renamed-away name must go out as a TTL=0 retraction; got {} datagram(s)",
    goodbyes.len()
  );
}

/// A rename the service **survives** SUPERSEDES every self-send credit recorded
/// before it.
///
/// The proto calls `Service::set_instance` before it emits `Renamed`, so by the
/// time `push_updates` observes the update this service publishes a different
/// set of records — the rename is a published-record mutation, and
/// `SelfSendTracker::supersede` is owed at that site as much as at a withdrawal
/// — the only other seam there is, a registration having turned out not to be
/// one.
///
/// Left un-superseded, a credit older than the rename claims at the CURRENT
/// generation: `Provenance::OwnEchoLikely`, the tier that declines §10 caching
/// but still ADJUDICATES — and what it would adjudicate is an §8.2 proposal for
/// a name this endpoint no longer defends, carrying §9 rdata no live route
/// holds. The window runs from the rename to the next seam of either kind: the
/// tracker holds ONE generation for the whole log, so a later withdrawal or
/// rename demotes the stale credit too. A registration does NOT — it mutates no
/// record already asserted — so nothing else closes this window. The advance is
/// owed at the MUTATION rather than argued from where a stale credit can reach —
/// that argument has to be re-made after every change to the routing, and this
/// one does not.
///
/// The rename asserted here must SURVIVE, and the assertion below pins that:
/// a retirement supersedes for a reason of its own, so a test that drifted onto
/// a retired service would stay green with the mutation site deleted and prove
/// nothing about it.
///
/// # Accepted residual
///
/// This is the one of the three drivers' copies that runs on real sockets and a
/// real clock. The marker credit is sealed before [`drive_to_rename`], and every
/// `tick` inside it reclaims sealed credits past
/// [`SELF_SEND_TTL`](hick_udp::selfsend::SELF_SEND_TTL) — 2 s — so a host slow
/// enough to spend that long reaching the rename reports `NoCredit` rather than
/// `Superseded`. Measured at 288–512 ms here, a 4–7x margin, and the failure is
/// loud rather than a false green: the assertion below rejects `NoCredit` too.
/// `claim_at` would only move the claim-side half of that window; the reclaim
/// inside `seal` is on the real clock either way.
#[test]
fn a_surviving_rename_supersedes_the_credits_recorded_before_it() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let ty = "_hick-mio-rn5._tcp.local.";
  let old = format!("superseder.{ty}");
  let handle = mdns
    .register_service(test_support::named_service_spec("superseder", ty, 8080))
    .expect("register_service");
  // Only an ANNOUNCED service rewrites records a peer already holds when it
  // renames, which is what makes the credits older than it stale rather than
  // merely early.
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }

  // The credit under test: recorded and sealed while the old name is still this
  // service's, so the rename below is the only thing between it and the claim.
  const MARKER: &[u8] = b"pre-rename-self-send-credit";
  mdns
    .selfsend
    .record(Family::V4, MARKER, hick_udp::selfsend::ClockPair::now());
  mdns.selfsend.seal();

  // No LOCAL service owns the candidate name, so this rename SURVIVES.
  let conflict = test_support::conflict_response(&old);
  let new_name = drive_to_rename(&mut mdns, &conflict).expect(RENAME_IS_NOT_ENVIRONMENTAL);
  assert_ne!(new_name, old, "a rename must change the instance name");
  assert!(
    !mdns
      .services
      .get(&handle)
      .expect("a survived rename keeps its context")
      .withdrawing,
    "this must be the SURVIVING path: a retirement supersedes through \
     `begin_service_withdrawal` for its own reason and would prove nothing \
     about the rename"
  );

  assert_eq!(
    mdns
      .selfsend
      .claim(&RxDatagram::without_stamp(Family::V4, MARKER)),
    SelfSendMatch::Superseded,
    "a successful auto-rename mutates the records this service publishes, so a \
     credit recorded before it describes a state this endpoint has left. Both \
     tiers report `Provenance::OwnEchoLikely` — a content match claims no more \
     for naming an older generation — so what the seam buys is the STANDING \
     property: left un-superseded the credit is CURRENT and take-once, the first \
     delayed echo spends it, and every copy behind it reads `NoCredit`, hence \
     `NotFromUs`, hence full RFC 6762 §10 cache population and §7.1/§7.3 quieting \
     for records no live route of ours holds"
  );
}

/// **The per-family case.** A goodbye that reached IPv4 but not IPv6 has not
/// been paid, and the item stays alive owing exactly the family that missed.
///
/// The retraction is the only thing that will ever withdraw a record the
/// replacement does not carry. This service advertises a subtype browse PTR and
/// its replacement does not, so that PTR is retracted by the goodbye or by
/// nothing at all — it would stay live in every IPv6 peer's cache for its whole
/// positive TTL. So a v4 round that paid v4's debt must not be read as paying
/// the item off.
///
/// The vacated name is reclaimable throughout, because a SURVIVING rename
/// leaves a live service under a different name; the debt is what is per family
/// here, not the name hold.
///
/// The IPv6 failure is injected as a per-family withdrawal outcome rather than
/// staged on a socket: no socket can be made to fail on demand, and the debt is
/// the thing under test.
#[test]
fn an_unpaid_ipv6_retraction_keeps_owing_after_ipv4_has_paid() {
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

  let conflict = test_support::conflict_response(&old);
  drive_to_rename(&mut mdns, &conflict).expect(RENAME_IS_NOT_ENVIRONMENTAL);

  // IPv4 pays, IPv6 fails, round after round: v4's debt runs out and v6's never
  // does, which is exactly the state a per-family debt has to keep apart from
  // "the goodbye is done".
  let base = Instant::now();
  let mut last_round = base;
  let mut retracted_subtype = false;
  for round in 1..=4u32 {
    let at = base + Duration::from_millis(260 * u64::from(round));
    last_round = at;
    for datagram in test_support::collect_goodbyes_as(
      &mut mdns,
      at,
      FamilyAttempt::Accepted { at },
      FamilyAttempt::Refused { permanent: false },
    ) {
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

  // The name is the renamed service's to give up, and it gave it up: a
  // replacement takes it while IPv6 still owes, and the owed round still goes
  // out afterwards.
  mdns
    .register_service(test_support::named_service_spec("reuse", ty, 9090))
    .expect("a surviving rename vacates its old name; the goodbye does not hold it");

  // IPv6 recovers inside the ceiling and pays what it owed.
  test_support::settle_goodbyes(&mut mdns, last_round);
  assert!(
    !mdns.endpoint.has_pending_withdrawals(),
    "once every family has retracted, nothing is owed"
  );
}

/// Consecutive renames each owe their own retraction. The handoff is one-shot
/// and the next rename overwrites it, so an endpoint that drained it late — or
/// not at all — would retract the second name and silently strand the first.
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

  let conflict = test_support::conflict_response(&first);
  let second = drive_to_rename(&mut mdns, &conflict).expect(RENAME_IS_NOT_ENVIRONMENTAL);
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
  let conflict = test_support::conflict_response(&second);
  let third = drive_to_rename(&mut mdns, &conflict).expect(RENAME_IS_NOT_ENVIRONMENTAL);
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

/// A §9 auto-rename lands on a name **no local route holds**, and the route
/// table agrees with the state machine about it.
///
/// The endpoint collects its own route table's instance names on the tick a
/// rename is imminent, hands them to the state machine, and mirrors whatever
/// name comes back into the route in the same borrow. So a suffix another local
/// registration already owns is stepped over rather than claimed, the service
/// survives its rename, and there is no window in which routing and the state
/// machine disagree about which name is being probed. There is no collision for
/// this driver to reconcile, and no path by which a rename retires the renamer.
#[test]
fn a_rename_lands_on_a_free_name_and_the_route_table_agrees() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let ty = "_hick-mio-rn3._tcp.local.";
  let old = format!("clash.{ty}");
  // Owns the FIRST suffix the rename would otherwise reach for, so a rename
  // that did not consult the route table would claim a name already taken.
  let rival = mdns
    .register_service(test_support::named_service_spec("clash-1", ty, 9090))
    .expect("register the rival");
  let handle = mdns
    .register_service(test_support::named_service_spec("clash", ty, 8080))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }

  let conflict = test_support::conflict_response(&old);
  let new_name = drive_to_rename(&mut mdns, &conflict).expect(RENAME_IS_NOT_ENVIRONMENTAL);
  assert_ne!(
    new_name,
    format!("clash-1.{ty}"),
    "the rival already holds that name; a rename that claims it puts two live \
     routes on one instance name"
  );

  assert!(
    !mdns
      .services
      .get(&handle)
      .expect("a renamed service keeps its context")
      .withdrawing,
    "the rename is survivable: nothing may retire the renamer"
  );
  assert_eq!(
    mdns
      .endpoint
      .service(handle)
      .expect("the endpoint still owns the renamed service")
      .name()
      .as_str(),
    new_name,
    "the state machine's name is what the caller was told"
  );
  assert!(
    matches!(
      mdns.register_service(test_support::named_service_spec(
        new_name
          .split_once('.')
          .expect("an instance name has a label")
          .0,
        ty,
        7070
      )),
      Err(RegisterError::NameAlreadyRegistered(_))
    ),
    "the ROUTE holds the new name too: routing and the state machine were \
     updated in one borrow, so a question for the new name reaches this service"
  );
  assert!(
    mdns.endpoint.service(rival).is_some(),
    "the rival keeps the name it registered"
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

/// How long to wait for a refusal streak the socket has been forced to produce.
///
/// §8.1 spaces each retry 250 ms apart on top of the initial 0-250 ms jitter, so
/// `MAX_CONSECUTIVE_SEND_FAILURES` of them is about a second. Five times that is
/// slack for a loaded runner rather than a timing assertion.
const DEGRADATION_BUDGET: Duration = Duration::from_secs(5);

/// Tick until the only bound family is reported degraded.
///
/// Degradation takes `MAX_CONSECUTIVE_SEND_FAILURES` refused sends, so reaching
/// it is proof that the core really did re-arm and re-offer the probe that many
/// times. It is a health signal and changes nothing the core is told — which is
/// exactly what makes it a usable progress marker here.
///
/// Panics rather than skips. Every caller has already forced the family's sends
/// to fail through a test seam, so the refusals owe nothing to this host's
/// kernel, its link, or its multicast support: a streak that never forms means
/// the core stopped re-arming the probe or the driver stopped offering it.
fn tick_until_the_family_is_reported_degraded(mdns: &mut Mdns) {
  let deadline = Instant::now() + DEGRADATION_BUDGET;
  while Instant::now() < deadline {
    mdns.tick().expect("tick");
    if mdns.degraded_families().0 {
      return;
    }
    std::thread::sleep(Duration::from_millis(10));
  }
  let want = super::sends::MAX_CONSECUTIVE_SEND_FAILURES;
  panic!(
    "the socket was forced to refuse every send, so {want} consecutive failures \
     must accumulate within {DEGRADATION_BUDGET:?}: the core stopped re-arming \
     the probe, or the driver stopped offering it"
  );
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
  tick_until_the_family_is_reported_degraded(&mut mdns);

  let state = |mdns: &Mdns| {
    mdns
      .endpoint
      .service(handle)
      .map(|svc| svc.state())
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

/// The other half of the contract above: when ONE of two bound families keeps
/// refusing and the other carries the probe, RFC 6762 §8.1 advances anyway.
///
/// The two tests are the whole rule between them. A round that reached no wire
/// advances nothing, however long it repeats — that is what keeps a name from
/// being claimed out of silence. A round that reached one of two obligated
/// families is a different fact: the core spends its partial-round patience
/// re-arming the SAME probe, and then advances past the family that has not
/// answered, as `Excused`. A family that is bound but permanently unable to send
/// therefore costs the sequence a bounded delay and never pins it.
///
/// The driver's own part in that is to keep telling the truth: a
/// present-but-refusing socket is reported missed on its thousandth consecutive
/// failure exactly as on its first, and never `Unobligated`. It is the core, not
/// the health table, that decides when to stop waiting — so this asserts both
/// that the sequence moved and that the family is still being reported as
/// degraded while it moved.
///
/// # The host condition this pins
///
/// A dual-stack endpoint whose IPv6 family can never deliver is not a contrived
/// shape. A Linux host carrying `::1` on `lo` binds the socket, joins `ff02::fb`
/// on the loopback index, and then refuses every send with `ENETUNREACH`,
/// because `lo` has no IPv6 multicast route; every GitHub `ubuntu-latest` runner
/// is such a host. `force_send_wouldblock_for_test` reproduces that shape on any
/// host that binds the family at all, which is what makes the property testable
/// somewhere other than a runner.
///
/// Skipped where IPv6 does not bind, since there is then no second family to
/// hold anything back. The skip is decided from `bound_families`, a
/// construction-time fact settled before the behaviour under test runs, rather
/// than inferred from the sequence failing to advance.
#[test]
fn a_probe_one_of_two_families_carried_advances_the_sequence() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  if !mdns.bound_families().1 {
    eprintln!(
      "skipping: this host binds no IPv6 socket, so there is no second family to \
       hold back"
    );
    return;
  }
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-partial._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V6, true);

  let state = |mdns: &Mdns| {
    mdns
      .endpoint
      .service(handle)
      .map(|svc| svc.state())
      .expect("the service is still registered")
  };
  // `Init` is where a freshly registered service sits out §8.1's initial
  // 0-250 ms delay, and `Probing(0)` is where it lands once the first probe has
  // been sent and confirmed missed. Only leaving BOTH is the advance under test;
  // waiting merely to leave `Probing(0)` would be satisfied before the first
  // probe was ever armed.
  let waiting = |mdns: &Mdns| matches!(state(mdns), ServiceState::Init | ServiceState::Probing(0));
  // §8.1 spaces each re-arm 250 ms apart on top of the initial 0-250 ms jitter,
  // and the excusal lands on the round after the patience bound is spent, so the
  // advance is about a second away. This is slack for a loaded runner rather
  // than a timing assertion.
  let deadline = Instant::now() + Duration::from_secs(5);
  while Instant::now() < deadline && waiting(&mdns) {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(10));
  }
  assert!(
    !waiting(&mdns),
    "IPv4 carried every probe, so the core must spend its partial-round patience \
     on IPv6 and then advance without it: a bound family that can never deliver \
     may delay the §8.1 sequence and must not pin it, but the service is still \
     at {}",
    state(&mdns)
  );
  assert_eq!(
    mdns.degraded_families(),
    (false, true),
    "the sequence advanced because the CORE stopped waiting, not because the \
     driver wrote the family off: it is still bound, still offered every \
     datagram, and still reported failing"
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

  tick_until_the_family_is_reported_degraded(&mut mdns);
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
/// is unreachable because every datagram is confirmed inside the
/// `poll_service_transmit` iteration that produced it, so the rename can never
/// land between a poll and its confirm.
///
/// Two things pin it. The core asserts the contract from its own side in debug
/// builds — the inbound-event dispatch and the timeout tick panic outright if a
/// commit token is live, and both run on **every** tick this test drives.
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

  let conflict = test_support::conflict_response(&old);
  let new_name = drive_to_rename(&mut mdns, &conflict).expect(RENAME_IS_NOT_ENVIRONMENTAL);
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
      .endpoint
      .service(handle)
      .is_some_and(|svc| svc.advertises_instance());
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
// `Endpoint::poll_service_transmit` failing leaves the datagram armed inside the
// core: it retries the same one on the next call and schedules no
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

/// Tick until `handle`'s consecutive encode-failure count reaches `want`.
///
/// The first probe is scheduled a random 0-250 ms out (RFC 6762 §8.1), so the
/// first few ticks legitimately poll nothing at all. Everything after that is
/// in-memory: the encode scratch is sized [`UNENCODABLE_PAYLOAD_SIZE`] by the
/// fixture's own options, so `poll_transmit` fails before any socket is
/// consulted and the failures accumulate as fast as the caller ticks. No arm of
/// this owes anything to the host, so both exits panic.
fn tick_to_encode_failures(mdns: &mut Mdns, handle: mdns_proto::ServiceHandle, want: u8) {
  let deadline = Instant::now() + Duration::from_secs(3);
  while Instant::now() < deadline {
    mdns.tick().expect("tick");
    match mdns.services.get(&handle) {
      Some(ctx) if ctx.encode_failures >= want => return,
      Some(_) => {}
      None => panic!(
        "the service was retired before reaching {want} consecutive encode \
         failures, which is inside MAX_CONSECUTIVE_ENCODE_ERRORS ({max}): \
         retirement fired early",
        max = crate::driver::MAX_CONSECUTIVE_ENCODE_ERRORS
      ),
    }
    std::thread::sleep(Duration::from_millis(10));
  }
  panic!(
    "every `poll_transmit` on a {UNENCODABLE_PAYLOAD_SIZE}-byte scratch must fail, \
     so {want} consecutive failures must be counted within the budget: the failing \
     poll is not being reached, or its failure is not being counted"
  );
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
    tick_to_encode_failures(&mut mdns, handle, want);
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
  let update = conflict.expect(
    "the encode scratch is too small for any DNS message, so every poll fails \
     before a socket is consulted and MAX_CONSECUTIVE_ENCODE_ERRORS of them must \
     retire the service within the budget: no terminal at all means the counter \
     never reaches its own ceiling and the caller waits forever",
  );
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

// ── a datagram no reachable socket can ever carry ───────────────────────────
//
// A `Sustained` transmit is re-armed until every obligated link accepts it, and
// the core's own partial-round patience excuses a family that keeps MISSING —
// not a round that can never succeed on any family. So a datagram every
// reachable socket refuses on its SIZE is the one shape neither side bounds: the
// core re-arms it forever and the driver re-offers it forever, and the service
// stays pending and unestablished for the life of the process with nothing on
// any wire. It is reachable, not theoretical: `ServerOptions` admits any encode
// scratch up to `MAX_BUFFER_SIZE`, which is the IPv6 ceiling and 20 bytes above
// IPv4's, so a v4 family can be handed a message it can never carry.
//
// The fix is one asymmetry, and both halves are tested here. A `Sustained`
// producer is retired, because it can never make progress. A `OneShot` response
// is NOT, because it is never re-armed — losing it costs one unanswered
// question, and retiring on it would let any peer tear down a healthy service by
// asking it a question whose answer does not fit.
//
// Every "does not retire" test below is a guard against the OTHER failure mode:
// permanence is a property of the SIZE and of nothing else, so a transient
// failure — `WouldBlock`, or the `EMSGSIZE` Linux also raises for a write past
// the current path MTU — and a family with no socket are each no evidence at all.

/// Make every send on both families oversize, by lowering each family's hard UDP
/// payload ceiling to zero — or restore the real ceilings.
///
/// The ceiling, never a hook that answers `TooLarge` directly: an ordinary
/// datagram a live producer emits then reaches the driver's decision through the
/// same size comparison a 70 000-byte one does.
fn refuse_every_send_as_too_large(mdns: &mut Mdns, refuse: bool) {
  let ceiling = refuse.then_some(0);
  for family in [Family::V4, Family::V6] {
    mdns.sockets.force_payload_ceiling_for_test(family, ceiling);
  }
}

/// How many sends the hook above has actually refused, across both families.
///
/// A "the producer survived" assertion is vacuous unless the producer really was
/// offered a datagram nothing could carry; this is what proves it was.
fn too_large_refusals(mdns: &mut Mdns) -> u32 {
  mdns.sockets.forced_send_refusals_for_test(Family::V4)
    + mdns.sockets.forced_send_refusals_for_test(Family::V6)
}

/// Tick until some datagram has been refused as permanently too large.
///
/// `budget` is the caller's, because what a wait may safely span differs: a
/// service still probing has nothing else due, while one already announcing has
/// its next RFC 6762 §8.3 round a second out and must be asserted well inside it.
///
/// Panics rather than skips. The refusal is counted by
/// [`refuse_every_send_as_too_large`]'s forced payload ceiling, which is weighed
/// before the syscall, so it needs no link, no peer and no multicast support
/// whatever: reaching the budget means the producer was never offered a
/// datagram at all, and every assertion the caller goes on to make about how
/// that refusal was handled would be about a refusal that never happened.
fn tick_until_a_send_is_refused_as_too_large(mdns: &mut Mdns, budget: Duration) {
  let deadline = Instant::now() + budget;
  while Instant::now() < deadline {
    mdns.tick().expect("tick");
    if too_large_refusals(mdns) > 0 {
      return;
    }
    std::thread::sleep(Duration::from_millis(5));
  }
  panic!(
    "no datagram reached the socket within {budget:?}, so the size refusal this \
     fixture forces was never even offered one: the producer stopped emitting"
  );
}

/// Drain every service terminal the queue holds for `handle`.
fn service_terminals(mdns: &mut Mdns, handle: mdns_proto::ServiceHandle) -> Vec<ServiceUpdate> {
  let mut out = Vec::new();
  while let Some(ev) = mdns.next_event() {
    if let Event::Service { handle: h, update } = ev
      && h == handle
    {
      out.push(update);
    }
  }
  out
}

/// The defect itself: a `Sustained` probe no reachable socket can carry must
/// retire its producer rather than be re-armed forever.
///
/// The fixture is IPv4-only **by configuration**, so "every reachable family
/// refused it" is a property of the test rather than of the host: the absent
/// family reports `NoSocket`, which is no evidence either way, and the one family
/// this endpoint has refuses the size.
///
/// Retirement is asserted on the FIRST refusal, not merely "eventually". A
/// version that waited for a failure streak would look like this one on a green
/// run while still leaving the datagram re-armed for as long as the streak takes,
/// and a version that never retired would sit here until the budget expired.
#[test]
fn an_undeliverable_sustained_transmit_retires_the_service() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-toobig._tcp.local.",
      8080,
    ))
    .expect("register_service");
  refuse_every_send_as_too_large(&mut mdns, true);

  // §8.1 puts the first probe a random 0-250 ms out, so the first ticks
  // legitimately offer nothing at all.
  tick_until_a_send_is_refused_as_too_large(&mut mdns, Duration::from_secs(3));
  assert!(
    mdns.services.get(&handle).is_none_or(|ctx| ctx.withdrawing),
    "the probe reached no wire and no retry ever can, so the service must be \
     retired on that very round — not re-armed and re-offered forever"
  );
  let terminals = service_terminals(&mut mdns, handle);
  assert!(
    terminals.iter().any(ServiceUpdate::is_conflict),
    "the caller must be told, instead of waiting for an Established that can \
     never arrive: {terminals:?}"
  );

  // And retired means retired: no further tick revives the lifecycle.
  for _ in 0..5 {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(20));
  }
  assert!(
    mdns.services.get(&handle).is_none_or(|ctx| ctx.withdrawing),
    "nothing may drive a retired service's §8 lifecycle again"
  );
  assert!(
    mdns
      .endpoint
      .service(handle)
      .is_none_or(|svc| svc.state() == ServiceState::Probing(0)),
    "the §8.1 sequence never advanced: nothing reached a link"
  );
}

/// The over-eager direction, guarded end to end: a family that refuses every send
/// for a reason that MAY clear is never evidence that a datagram is impossible.
///
/// It ends by letting the socket accept again and watching the same service
/// complete its probe sequence — which is a much stronger statement than "no
/// terminal was queued". A retirement marks the context `withdrawing`, and every
/// stage skips such a context forever, so a service that goes on to reach
/// `Probing(1)` was demonstrably never retired.
#[test]
fn a_transient_all_family_failure_retries_and_never_retires() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-transient._tcp.local.",
      8081,
    ))
    .expect("register_service");
  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, true);
  // Reaching the degradation threshold is proof the core really did re-arm and
  // the driver really did re-offer the probe, several times over.
  //
  // The survival assertion is inside the loop, not after it, and that placement
  // is what keeps this test from going vacuous. A retirement stops the transmits
  // the degradation counter is made of, so an over-eager driver would never
  // reach the threshold at all — and a check that ran only after the loop would
  // see the timeout, print a skip and pass. Asserted every tick, the retirement
  // is caught on the tick it happens.
  let deadline = Instant::now() + DEGRADATION_BUDGET;
  let mut degraded = false;
  while Instant::now() < deadline && !degraded {
    mdns.tick().expect("tick");
    assert!(
      mdns
        .services
        .get(&handle)
        .is_some_and(|ctx| !ctx.withdrawing),
      "a full send buffer is a datagram that has not gone out YET; retiring a \
       healthy advertisement over it is the expensive way to be wrong"
    );
    degraded = mdns.degraded_families().0;
    std::thread::sleep(Duration::from_millis(10));
  }
  assert!(
    degraded,
    "the socket was forced to refuse every send, so the streak owes nothing to \
     this host: no degradation inside {DEGRADATION_BUDGET:?} means the probe \
     stopped being re-armed or stopped being offered, and the survival assertion \
     above never ran against a real retry"
  );
  let terminals = service_terminals(&mut mdns, handle);
  assert!(
    terminals.is_empty(),
    "nothing terminal has happened to this service: {terminals:?}"
  );

  mdns
    .sockets
    .force_send_wouldblock_for_test(Family::V4, false);
  let deadline = Instant::now() + Duration::from_secs(2);
  let state = |mdns: &Mdns| mdns.endpoint.service(handle).map(|svc| svc.state());
  while Instant::now() < deadline && state(&mdns) == Some(ServiceState::Probing(0)) {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(20));
  }
  assert_eq!(
    state(&mdns),
    Some(ServiceState::Probing(1)),
    "the service was never retired: the same registration picked its sequence \
     back up the moment the socket accepted a byte"
  );
}

/// The same over-eager direction, on the error that used to *define* permanence.
///
/// Linux reports `EMSGSIZE` for a write past the currently-known path MTU with
/// `DF` set as well as for one past the hard maximum (udp(7)), and an mDNS
/// datagram is three orders of magnitude inside that maximum when it happens. A
/// classification keyed on the errno therefore retires a healthy service over a
/// link whose next MTU probe would have carried it — which is why permanence is
/// proved by `socket::max_udp_payload` and by nothing else.
///
/// Ends the way its `WouldBlock` sibling does, by letting the socket accept
/// again and watching the same registration resume its §8.1 sequence: a retired
/// context is skipped by every stage forever, so reaching `Probing(1)` is proof
/// it was never retired.
#[test]
fn an_emsgsize_below_the_hard_limit_never_retires_a_sustained_producer() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-pathmtu._tcp.local.",
      8085,
    ))
    .expect("register_service");
  for family in [Family::V4, Family::V6] {
    mdns.sockets.force_send_emsgsize_for_test(family, true);
  }
  // Asserted every tick rather than once at the end, for the reason the
  // `WouldBlock` sibling gives: a retirement stops the transmits, so a check
  // that ran only afterwards could not tell a retirement from a slow start.
  let deadline = Instant::now() + Duration::from_secs(3);
  let mut refused = false;
  while Instant::now() < deadline && !refused {
    mdns.tick().expect("tick");
    assert!(
      mdns
        .services
        .get(&handle)
        .is_some_and(|ctx| !ctx.withdrawing),
      "the datagram is far inside every family's hard UDP limit, so this refusal \
       may clear on the very next attempt; retiring on it destroys a healthy \
       service over a transient path MTU"
    );
    refused = too_large_refusals(&mut mdns) > 0;
    std::thread::sleep(Duration::from_millis(5));
  }
  assert!(
    refused,
    "the forced `EMSGSIZE` is raised inside the send path, so it needs no link \
     and no peer: no refusal inside the budget means the probe was never offered \
     to the socket and the survival assertion above never ran against one"
  );
  let terminals = service_terminals(&mut mdns, handle);
  assert!(
    terminals.is_empty(),
    "nothing terminal has happened to this service: {terminals:?}"
  );

  for family in [Family::V4, Family::V6] {
    mdns.sockets.force_send_emsgsize_for_test(family, false);
  }
  let deadline = Instant::now() + Duration::from_secs(2);
  let state = |mdns: &Mdns| mdns.endpoint.service(handle).map(|svc| svc.state());
  while Instant::now() < deadline && state(&mdns) == Some(ServiceState::Probing(0)) {
    mdns.tick().expect("tick");
    std::thread::sleep(Duration::from_millis(20));
  }
  assert_eq!(
    state(&mdns),
    Some(ServiceState::Probing(1)),
    "the registration picked its §8.1 sequence back up once the refusal cleared, \
     which a retired one could never do"
  );
}

/// One family refusing the size while the other carries the datagram is a
/// PARTIAL round, and a partial round retires nothing.
///
/// Needs a real second family, so it skips loudly where IPv6 cannot be bound —
/// the aggregate itself is pinned on every host by
/// `undeliverable_is_every_reachable_family_refusing_the_size_and_nothing_less`.
#[test]
fn a_service_the_other_family_can_serve_is_never_retired() {
  let Some(mut mdns) = dual_stack_mdns() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-halfbig._tcp.local.",
      8082,
    ))
    .expect("register_service");
  // Only IPv6 refuses. IPv4 multicast on loopback works everywhere this suite
  // runs, so every round is `{v4: Sent, v6: TooLarge}` — a datagram that
  // manifestly CAN be carried.
  mdns
    .sockets
    .force_payload_ceiling_for_test(Family::V6, Some(0));

  let advertised = test_support::drive_to_advertised(&mut mdns, handle);
  assert!(
    mdns.sockets.forced_send_refusals_for_test(Family::V6) > 0,
    "IPv6 must actually have been offered — and have refused — a datagram"
  );
  assert!(
    mdns
      .services
      .get(&handle)
      .is_some_and(|ctx| !ctx.withdrawing),
    "one family put the records on a wire, so the datagram is deliverable and \
     nothing about the other family's refusal may retire the service"
  );
  let terminals = service_terminals(&mut mdns, handle);
  assert!(terminals.is_empty(), "{terminals:?}");
  assert!(
    advertised,
    "the service went on to announce over the family that works"
  );
}

/// The other half of the asymmetry: a `OneShot` reply that cannot be sent is a
/// lost reply, never a dead service.
///
/// The core never re-arms a §6 response, so nothing is stuck and nothing needs
/// bounding — while retiring on one would hand any peer on the link a way to
/// tear down an established service by asking it a question whose answer does
/// not fit.
///
/// The refusal is waited for well inside the next RFC 6762 §8.3 round: a §6
/// multicast reply is jittered 20-120 ms, and the announcement that follows the
/// one `drive_to_advertised` just watched land is a full second out. The budget
/// is bracketed on both sides and it is a panic on both, so it is aimed at the
/// middle of that window rather than at either edge: short of the jitter ceiling
/// the reply has not been offered yet and the wait fails for nothing, and past
/// the next announcement the refusal observed belongs to a `Sustained` datagram
/// that this driver is *supposed* to retire the service over.
#[test]
fn an_undeliverable_one_shot_reply_costs_the_reply_and_not_the_service() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let ty = "_hick-mio-bigreply._tcp.local.";
  let handle = mdns
    .register_service(test_support::service_spec(ty, 8083))
    .expect("register_service");
  if !test_support::drive_to_advertised(&mut mdns, handle) {
    return;
  }
  // Drop the lifecycle's own events; what this test reads is what comes AFTER.
  let _ = service_terminals(&mut mdns, handle);

  test_support::ingest(&mut mdns, &ptr_question(ty), Instant::now());
  refuse_every_send_as_too_large(&mut mdns, true);
  tick_until_a_send_is_refused_as_too_large(&mut mdns, Duration::from_millis(600));

  assert!(
    mdns
      .services
      .get(&handle)
      .is_some_and(|ctx| !ctx.withdrawing),
    "a response the core will never re-arm costs exactly one unanswered \
     question; the querier re-asks, and the service is untouched"
  );
  let terminals = service_terminals(&mut mdns, handle);
  assert!(
    terminals.is_empty(),
    "no peer may retire a healthy service by asking it a question whose answer \
     does not fit: {terminals:?}"
  );
  assert!(
    mdns
      .endpoint
      .service(handle)
      .is_some_and(|svc| svc.advertises_instance()),
    "the service still owns and advertises its instance name"
  );
}

/// A PTR browse for `ty`, from a peer that wants the multicast (§6) reply.
fn ptr_question(ty: &str) -> Vec<u8> {
  use mdns_proto::wire::{Header, MessageBuilder};

  let qname = mdns_proto::Name::try_from_str(ty).expect("query name");
  let mut buf = vec![0u8; 512];
  let mut b: MessageBuilder<'_> =
    MessageBuilder::try_new(&mut buf, Header::new()).expect("message builder");
  b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false)
    .expect("push_question");
  let n = b.finish().expect("finish");
  buf.truncate(n);
  buf
}

/// A query is always `Sustained` — RFC 6762 §5.2 has no one-shot form — so a
/// question no reachable socket can carry retires it for the same reason a probe
/// does, and for a sharper one: the §5.2 retry budget is spent only on an
/// all-delivered send, so this query would re-ask forever without ever reaching
/// its own ceiling.
#[test]
fn an_undeliverable_question_retires_the_query() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let handle = mdns
    .start_query(test_support::query_spec("_hick-mio-bigq._tcp.local."))
    .expect("start_query");
  refuse_every_send_as_too_large(&mut mdns, true);
  tick_until_a_send_is_refused_as_too_large(&mut mdns, Duration::from_secs(3));
  assert!(
    !mdns.queries.contains_key(&handle),
    "the question reached no wire and no retry ever can, so the query is \
     retired rather than left re-asking for the life of the process"
  );
  let mut terminal = None;
  while let Some(ev) = mdns.next_event() {
    if let Event::QueryTerminal { handle: h, update } = ev
      && h == handle
    {
      terminal = Some(update);
    }
  }
  assert!(
    terminal.is_some(),
    "the caller must be told, instead of waiting on a browse that can never ask"
  );
}

// ── the ingress interface gate, wired ───────────────────────────────────────

/// A REPORTED foreign interface refuses our own echo, through the real receive
/// path — and the loopback exception does not rescue it.
///
/// This inverts what this test used to assert. The old policy let a loopback
/// SOURCE override the interface the kernel reported, justified by "a platform
/// is free to report the echo as having arrived on the loopback
/// pseudo-interface rather than the socket's egress interface". That
/// justification was never checked against a live host —
/// `an_own_echo_is_reported_on_the_interface_this_endpoint_bound` now checks it
/// — and it is the wrong shape regardless: these sockets are wildcard bound, so
/// wherever an operator has stopped treating `127/8` as martian a
/// physical-interface unicast can carry a loopback source straight to port
/// 5353. A source address is a claim the sender wrote; a nonzero interface
/// index is evidence the kernel attached, and the evidence wins.
///
/// The observable is [`IngressRecord`] for THIS datagram, not a counter.
/// `packets_dropped` is all-cause and cumulative: on the forbidden path the
/// datagram reaches proto, proto rejects the deliberately invalid header, and
/// the same counter moves — so a counter-based assertion passes exactly when it
/// should fail.
#[test]
fn a_foreign_interface_index_refuses_our_own_echo() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let poll = Poll::new().expect("poll");
  mdns
    .register(poll.registry(), Token(40), Token(41))
    .expect("register");

  let body = [0x3Cu8; 28];
  let want = crate::driver::body_fingerprint(&body);
  if credit_a_multicast_send(&mut mdns, &body).is_none() {
    mdns.deregister().expect("deregister");
    eprintln!(
      "note: no multicast send reached the wire on this host, so this case \
       contributes no evidence"
    );
    return;
  }
  // Every subsequent receive now reports an interface this endpoint did not
  // bind. Baseline first: only records added after this line are ours.
  mdns.ingress_log.clear();
  let foreign = mdns.bound_interface.wrapping_add(1_000);
  mdns
    .sockets
    .force_rx_iface_for_test(Some(iface_witness(foreign)));

  let mut events = mio::Events::with_capacity(8);
  let deadline = Instant::now() + Duration::from_secs(2);
  let mut poll = poll;
  while Instant::now() < deadline && !mdns.ingress_log.iter().any(|r| r.body == want) {
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
  let ours: Vec<_> = mdns
    .ingress_log
    .iter()
    .filter(|r| r.body == want && r.family == Family::V4)
    .copied()
    .collect();
  mdns.deregister().expect("deregister");

  if ours.is_empty() {
    eprintln!(
      "note: this endpoint's own multicast never looped back, so no datagram \
       reached the gate and this host contributes no evidence"
    );
    return;
  }
  for rec in ours {
    assert!(
      !rec.admitted,
      "our own echo, forced to report interface {foreign}, was ADMITTED: a \
       loopback source must not override the interface the kernel attached"
    );
  }
}

/// A destination witness the KERNEL declined to emit is admitted where a LOST
/// one is refused — through the real receive path, on the same datagram.
///
/// The split matters because `Lost` and `Declined` are the same missing cmsg
/// told apart by one flag, and only one of them is the sender's doing. Every BSD
/// builds its ancillary mbufs with `M_NOWAIT` and, when `sbcreatecontrol`
/// returns `NULL`, skips the cmsg with no error, no counter and no `MSG_CTRUNC`
/// while still delivering the datagram (FreeBSD `kern/uipc_sockbuf.c`, NetBSD
/// `kern/uipc_socket2.c`; XNU checks the allocation and returns `ENOBUFS`
/// instead). Mbuf exhaustion is normally CAUSED by a flood, so refusing on it
/// makes the responder go silently deaf exactly while it is under attack.
/// `MSG_CTRUNC` is the opposite: our own control buffer was too small, which
/// this side controls and sizes against a worst case, so refusing on it is safe.
///
/// The observable is [`IngressRecord`] for THIS datagram — `packets_dropped` is
/// all-cause and cumulative, so a counter-based assertion passes exactly when it
/// should fail.
#[test]
fn a_declined_destination_witness_is_admitted_where_a_lost_one_is_refused() {
  for (witness, want_admitted, what) in [
    (
      DestinationWitness::Lost,
      false,
      "MSG_CTRUNC — our own control buffer",
    ),
    (
      DestinationWitness::Declined,
      true,
      "no cmsg, no MSG_CTRUNC — the kernel declined",
    ),
  ] {
    let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
      return;
    };
    let poll = Poll::new().expect("poll");
    mdns
      .register(poll.registry(), Token(60), Token(61))
      .expect("register");

    let body = [0x7Eu8; 28];
    let want = crate::driver::body_fingerprint(&body);
    if credit_a_multicast_send(&mut mdns, &body).is_none() {
      mdns.deregister().expect("deregister");
      eprintln!(
        "note: no multicast send reached the wire on this host, so this case \
         contributes no evidence"
      );
      return;
    }
    mdns.ingress_log.clear();
    mdns.sockets.force_rx_destination_for_test(Some(witness));

    let mut events = mio::Events::with_capacity(8);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut poll = poll;
    while Instant::now() < deadline && !mdns.ingress_log.iter().any(|r| r.body == want) {
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
    let ours: Vec<_> = mdns
      .ingress_log
      .iter()
      .filter(|r| r.body == want && r.family == Family::V4)
      .copied()
      .collect();
    mdns.deregister().expect("deregister");

    if ours.is_empty() {
      eprintln!(
        "note: this endpoint's own multicast never looped back, so no datagram \
         reached the gate and this host contributes no evidence"
      );
      continue;
    }
    for rec in ours {
      assert_eq!(
        rec.admitted,
        want_admitted,
        "a datagram whose destination witness was {witness:?} ({what}) must be \
         {}: refusing an mbuf shortage is deafness on demand, and admitting our \
         own truncation hides a bug on this side",
        if want_admitted { "admitted" } else { "refused" }
      );
    }
  }
}

/// Which interface does a REAL self-echo actually arrive on?
///
/// This is the premise the old loopback exception rested on, checked instead of
/// assumed. If a supported platform genuinely reported our own multicast echo on
/// some interface other than the socket's egress interface, the policy above
/// would break self-send suppression there and a different exception design
/// would be needed.
///
/// It matches on the fingerprint of the exact body it transmitted, so unrelated
/// mDNS traffic on the host — of which there is usually plenty on port 5353 —
/// cannot stand in for an echo that never looped back. Where no such datagram
/// arrives it says so and asserts nothing, because a host that does not loop its
/// own multicast back contributes no evidence either way.
#[test]
fn an_own_echo_is_reported_on_the_interface_this_endpoint_bound() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let poll = Poll::new().expect("poll");
  mdns
    .register(poll.registry(), Token(42), Token(43))
    .expect("register");

  let body = [0x5Au8; 28];
  let want = crate::driver::body_fingerprint(&body);
  if credit_a_multicast_send(&mut mdns, &body).is_none() {
    mdns.deregister().expect("deregister");
    eprintln!(
      "note: no multicast send reached the wire on this host, so this case \
       contributes no evidence"
    );
    return;
  }
  mdns.ingress_log.clear();

  let mut events = mio::Events::with_capacity(8);
  let deadline = Instant::now() + Duration::from_secs(2);
  let mut poll = poll;
  while Instant::now() < deadline && !mdns.ingress_log.iter().any(|r| r.body == want) {
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
  let bound = mdns.bound_interface;
  let ours: Vec<_> = mdns
    .ingress_log
    .iter()
    .filter(|r| r.body == want && r.family == Family::V4)
    .copied()
    .collect();
  mdns.deregister().expect("deregister");

  if ours.is_empty() {
    eprintln!(
      "note: this endpoint's own multicast never looped back on this host, so \
       it contributes no evidence about the reported echo interface"
    );
    return;
  }
  for rec in ours {
    assert_eq!(
      rec.reported_interface, bound,
      "this host reported our own loopback echo on interface {}, not the bound \
       interface {bound}: the ingress gate refuses a foreign index, so \
       self-send suppression would break here and the exception needs a design \
       that does not rest on the source address",
      rec.reported_interface
    );
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
  if credit_a_multicast_send(&mut mdns, &body).is_none() {
    mdns.deregister().expect("deregister");
    return;
  }
  assert!(
    !mdns.selfsend.is_empty(),
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

  // Baseline: only records added after this line belong to this case.
  mdns.ingress_log.clear();
  let want = crate::driver::body_fingerprint(&body);
  let mut events = mio::Events::with_capacity(8);
  // Well inside `SELF_SEND_TTL` (2 s), so an unclaimed credit below is one the
  // gate protected and never one the clock retired.
  let deadline = Instant::now() + Duration::from_millis(750);
  let mut poll = poll;
  while Instant::now() < deadline && !mdns.ingress_log.iter().any(|r| r.body == want) {
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
  let unclaimed = !mdns.selfsend.is_empty();
  let ours: Vec<_> = mdns
    .ingress_log
    .iter()
    .filter(|r| r.body == want)
    .copied()
    .collect();
  mdns.deregister().expect("deregister");
  assert!(
    unclaimed,
    "an echo whose source zone names another link reached the self-send match: \
     the ingress gate must reject it before the take-once credit is consulted, \
     and before `endpoint.handle` can cache anything it carries"
  );
  // The assertion above is vacuous on a host that delivered nothing, and an
  // unclaimed credit alone cannot say WHICH stage refused the datagram. The
  // per-datagram record can: it names this body and the gate's own verdict on
  // it, where a shared `packets_dropped` would also move if proto rejected the
  // same datagram after the gate let it through.
  if ours.is_empty() {
    eprintln!(
      "note: this endpoint's own multicast never looped back, so no datagram \
       reached the gate and the assertion above held vacuously"
    );
  }
  for rec in ours {
    assert!(
      !rec.admitted,
      "the ingress gate ADMITTED an echo whose source zone names another link: \
       an unclaimed credit afterwards would then be an expiry, not a refusal"
    );
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
/// host's kernel refused the datagram and there is nothing for the caller to
/// assert against.
///
/// `min_gap` is zero, so the gate is open for both families and every test below
/// is about the credit rather than about the spacing.
///
/// The `None` is a HOST verdict and is checked to be one. It is the setup this
/// endpoint needs before any behaviour under test runs, and the socket layer's
/// own wire history is what decides it: a fan-out that reported carrying nothing
/// while the socket recorded these bytes reaching a wire is the fan-out
/// miscounting its own send, which is a defect and panics here rather than
/// taking every caller below green.
fn credit_a_multicast_send(mdns: &mut Mdns, body: &[u8]) -> Option<()> {
  let before = [Family::V4, Family::V6].map(|f| mdns.sockets.wire_times_for_test(f).len());
  let summary = {
    let mut gate = FamilyWireGate::default();
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
      body,
      MDNS_V4_DST,
      Duration::ZERO,
    )
  };
  if summary.sent > 0 {
    return Some(());
  }
  let after = [Family::V4, Family::V6].map(|f| mdns.sockets.wire_times_for_test(f).len());
  assert_eq!(
    before, after,
    "the fan-out reported carrying nothing while the socket layer recorded these \
     bytes reaching a wire: a `sent` of zero is then the fan-out's own accounting, \
     not a host that cannot egress multicast"
  );
  eprintln!(
    "skipping: this host's kernel accepted no multicast datagram on the loopback \
     interface, so there is no send for an echo to be weighed against"
  );
  None
}

/// Open the next tick's claim window and present the echo there, exactly where
/// [`Mdns::tick`] would.
///
/// The echo is presented rather than awaited: what is under test is *when* the
/// credit's window opens, and a real loopback copy would arrive with exactly
/// these — a kernel receive stamp taken after the syscall, read back against the
/// instant the following tick opened with.
fn echo_matched_at_next_tick_top(mdns: &mut Mdns, family: Family, body: &[u8]) -> bool {
  let top = hick_udp::selfsend::ClockPair::now();
  mdns.selfsend.seal_at(top.mono);
  // Both readings are live, so the wall clock and the monotonic one agree about
  // how much time has passed since the send and the claim keeps full ordering
  // evidence — which is what makes this an `Ordered` claim rather than a
  // degraded one.
  consumed(mdns.selfsend.claim_at(
    &RxDatagram::from_stamp_for_test(family, body, top.wall),
    top,
  ))
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
  let top = hick_udp::selfsend::ClockPair::now();
  mdns.selfsend.seal_at(top.mono);
  // The gap is charged to BOTH clocks, so the claim below is refused by the TTL
  // and by nothing else: a gap that only the monotonic clock knew about would
  // read as a wall-clock step and give up the ordering evidence instead.
  let after_the_gap =
    hick_udp::selfsend::ClockPair::new(top.wall + STALL_PAST_TTL, top.mono + STALL_PAST_TTL);
  assert!(
    !consumed(mdns.selfsend.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, &body[..], after_the_gap.wall),
      after_the_gap
    )),
    "post-opportunity time is charged in full, caller stalls included, or the \
     false-suppression bound is not a bound"
  );
  mdns.selfsend.seal_at(after_the_gap.mono);
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
// receive stage's own runtime is elapsed time like any other. So the credit is
// aged against a live read inside `SelfSendTracker::claim` and against nothing
// else: the tick's instant stays the protocol `now` for the schedules the core
// owns, and the datagram's own processing instant — read per datagram for the
// caller-facing bounds `Endpoint::handle` weighs — is not an age either.
// Weighing a claim against the tick's instant charges nothing for a drain that
// ran long or lost the CPU, and the bound on FALSE suppression stops being a
// bound — a co-resident peer's byte-identical datagram, read an unbounded time
// after the seal, still finds a live credit and is swallowed as our own echo.

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
  await_queued_datagram(mdns, poll, "this endpoint's own multicast")
}

/// Poll until the IPv4 socket holds a datagram for the drain to weigh, or
/// `None` with a printed reason naming `what` never arrived.
///
/// Readiness is what makes that skip stats-free: it is the kernel's own word
/// that something is queued, so a test that goes on to assert is never asserting
/// over an empty receive stage.
fn await_queued_datagram(mdns: &mut Mdns, poll: &mut Poll, what: &str) -> Option<()> {
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
  eprintln!("skipping: {what} never reached this endpoint's socket within the budget");
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
// So `SelfSendTracker::claim` takes no instant from anyone and reads the
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

// ── only port 5353 may be offered a self-send credit ────────────────────────
//
// Both of this endpoint's sockets are bound to 5353, so that is the source port
// every datagram it sends leaves from and the only one a loopback copy can
// arrive from. RFC 6762 §11 already drops a RESPONSE from any other port, but a
// §6.7 legacy unicast QUERY is deliberately kept — such a querier uses an
// ephemeral port and is owed a unicast reply. Kept is not ours: under
// `MatchMode::Degraded` nothing orders a claim against the send, so a legacy
// query carrying the same bytes as one we just multicast would take that credit
// and be reported as our own echo. The reply the querier is owed would never be
// sent, and the genuine echo behind it would find no credit and reach the
// protocol layer as peer traffic.
//
// The two tests below are the same datagram, the same ordering and the same
// match mode, differing only in the source port it arrives from.

/// A UDP socket that can reach an endpoint joined on the loopback link, from an
/// EPHEMERAL source port.
///
/// Three options are load-bearing and `std::net::UdpSocket` exposes only two of
/// them, which is what `socket2` is a dev-dependency for:
///
/// * `IP_MULTICAST_IF` = 127.0.0.1, or the datagram egresses on the host's
///   default multicast interface and an endpoint joined only on loopback never
///   sees it;
/// * `IP_MULTICAST_TTL` = 255 — fixture normalisation, and load-bearing for
///   nothing. It is NOT needed for the ingress boundary, which reads no hop
///   limit; nor for delivery, since RFC 1112 requires the local loopback copy
///   regardless of TTL; nor by §11, whose 255 recommendation is about RESPONSES
///   and this fixture sends queries. An earlier version of this note claimed all
///   three, which was false evidence about the setup. It is set so the fixture
///   emits what a conforming responder would;
/// * `IP_MULTICAST_LOOP`, on by default but set explicitly, because same-host
///   delivery is the whole point.
///
/// Never bound to 5353: being a source port that is not ours is this socket's
/// entire job, and joining the endpoint's `SO_REUSEPORT` group would also let it
/// absorb deliveries meant for the endpoint under test.
fn ephemeral_loopback_sender() -> Option<socket2::Socket> {
  use socket2::{Domain, Protocol, Socket, Type};

  let build = || -> std::io::Result<Socket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    s.set_multicast_if_v4(&Ipv4Addr::LOCALHOST)?;
    s.set_multicast_ttl_v4(255)?;
    s.set_multicast_loop_v4(true)?;
    Ok(s)
  };
  match build() {
    Ok(s) => Some(s),
    Err(e) => {
      eprintln!("skipping: the ephemeral-port sender could not be set up ({e:?})");
      None
    }
  }
}

/// One PTR question, QR=0 — the shape of an RFC 6762 §6.7 legacy query.
///
/// A query rather than a response deliberately: a response from an ephemeral
/// port is dropped by the §11 source-port rule before the credit is weighed at
/// all, so it could never reach the gate these tests are about.
fn legacy_query_datagram(service_type: &str) -> Vec<u8> {
  use mdns_proto::wire::{Header, MessageBuilder};

  let mut buf = vec![0u8; 512];
  let mut builder: MessageBuilder<'_> =
    MessageBuilder::try_new(&mut buf, Header::new()).expect("message builder");
  builder
    .push_question(
      &mdns_proto::Name::try_from_str(service_type).expect("service type"),
      ResourceType::Ptr,
      ResourceClass::In,
      false,
    )
    .expect("push_question");
  let n = builder.finish().expect("finish");
  buf.truncate(n);
  buf
}

/// Record a credit for `body` — with the datagram that will be weighed against
/// it ALREADY queued — open its window, and report the credits that survived.
///
/// The credit is taken after the arrival on purpose: the kernel stamped the
/// datagram before the send it now faces, which is the ordering `Ordered`
/// matching exists to reject and `Degraded` matching cannot see. So the source
/// port is the only thing left that can tell the two callers apart.
fn credits_after_a_pre_send_arrival(mdns: &mut Mdns, body: &[u8]) -> usize {
  mdns
    .selfsend
    .record(Family::V4, body, hick_udp::selfsend::ClockPair::now());
  mdns.tick().expect("tick");
  mdns.selfsend.len()
}

/// [`credits_after_a_pre_send_arrival`] over a datagram delivered from an
/// ephemeral source port.
fn credits_after_an_ephemeral_arrival(
  mdns: &mut Mdns,
  poll: &mut Poll,
  body: &[u8],
) -> Option<usize> {
  let sender = ephemeral_loopback_sender()?;
  if sender.send_to(body, &MDNS_V4_DST.into()).is_err() {
    eprintln!("skipping: this host's multicast egress refused the ephemeral-port query");
    return None;
  }
  await_queued_datagram(mdns, poll, "the ephemeral-port query")?;
  Some(credits_after_a_pre_send_arrival(mdns, body))
}

/// [`credits_after_a_pre_send_arrival`] over this endpoint's own loopback copy.
///
/// Put on the wire through the socket layer alone rather than through
/// [`credit_a_multicast_send`], so the credit taken afterwards is the only one
/// and the arrival really does predate it.
fn credits_after_our_own_echo(mdns: &mut Mdns, poll: &mut Poll, body: &[u8]) -> Option<usize> {
  // The socket layer's own verdict on one ungated send, so the refusal it reports
  // is the kernel's and nothing in this crate stands between the two.
  let sent = mdns
    .sockets
    .send_one(Family::V4, body, MDNS_V4_DST, &crate::socket::Ungated);
  if !matches!(sent, crate::socket::SendOutcome::Sent { .. }) {
    eprintln!(
      "skipping: this host's kernel refused a multicast datagram on the loopback \
       interface ({sent:?}), so there is no echo to arrive from port 5353"
    );
    return None;
  }
  await_queued_datagram(mdns, poll, "this endpoint's own multicast")?;
  Some(credits_after_a_pre_send_arrival(mdns, body))
}

#[test]
fn a_degraded_claim_refuses_a_credit_to_an_ephemeral_port_query() {
  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  // The mode with no ordering evidence at all — the whole of the match on
  // Windows and on any kernel that delivers no timestamp cmsg. Forcing it is
  // what makes the arm reachable from a host whose kernel does supply a stamp.
  mdns.sockets.force_no_rx_time_for_test();
  let body = legacy_query_datagram("_hick-mio-legacy._tcp.local.");
  assert!(
    !packet_is_response(&body),
    "a response from an ephemeral port never reaches the credit check, so only a \
     query can exercise this gate"
  );

  let survived = credits_after_an_ephemeral_arrival(&mut mdns, &mut poll, &body);
  mdns.deregister().expect("deregister");
  let Some(survived) = survived else {
    return;
  };
  assert_eq!(
    survived, 1,
    "a query from an ephemeral port cannot be our own loopback — we send only \
     from 5353 — so it must not be offered the credit: swallowing it drops the \
     unicast reply RFC 6762 §6.7 owes that querier and leaves our own echo \
     facing no credit at all"
  );
}

#[test]
fn a_degraded_claim_still_admits_our_own_echo_that_predates_its_credit() {
  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  mdns.sockets.force_no_rx_time_for_test();
  let body = legacy_query_datagram("_hick-mio-legacy-echo._tcp.local.");
  let survived = credits_after_our_own_echo(&mut mdns, &mut poll, &body);
  mdns.deregister().expect("deregister");
  let Some(survived) = survived else {
    return;
  };
  assert_eq!(
    survived, 0,
    "the port gate must not become a second ordering check: our own echo arrives \
     from 5353 and still claims its credit, however the kernel happened to stamp \
     it against the send"
  );
}

// ── what a query may TAKE is weighed at the datagram, not at the tick ────────
//
// `QuerySpec::with_timeout` is a promise to whoever set it, and it bounds the
// receive side as well as the send: on and after the boundary the query collects
// no answer and spends no RFC 6762 §7.3 retry slot. The core weighs that promise
// against the instant `Endpoint::handle` is handed, so it is stage 1 that decides
// how much of the drain is charged to it. One reading for a whole drain charges
// none of it — the last of up to `RECV_BUDGET` datagrams, and the `recvmsg` calls
// before it, are weighed on a clock read at the top of the tick.
//
// Nor is the error in the caller's favour: under `max_answers` an answer admitted
// past the window EVICTS one collected inside it, and a duplicate question
// admitted past it spends a §5.2 slot on behalf of a query the window has already
// closed.
//
// Both tests below stall exactly there — after the tick has read its own instant,
// with the datagram already admitted and only `Endpoint::handle` ahead of it.

/// Long enough that the setup below finishes inside it on a loaded runner. The
/// stall that crosses it is sized from what is LEFT at the moment the tick is
/// about to run, so the crossing does not depend on how long the socket took.
const QUERY_WINDOW: Duration = Duration::from_millis(500);

/// Carries the stall past the boundary rather than onto it, so nothing turns on
/// the difference between `>=` and `>` here.
const PAST_THE_WINDOW: Duration = Duration::from_millis(50);

/// A QR=1 response carrying one A record for `qname`.
fn a_response(qname: &str, addr: Ipv4Addr) -> Vec<u8> {
  use mdns_proto::wire::{Header, MessageBuilder};

  let mut buf = vec![0u8; 512];
  let mut header = Header::new();
  header.flags_mut().set_response();
  let mut builder: MessageBuilder<'_> =
    MessageBuilder::try_new(&mut buf, header).expect("message builder");
  builder
    .push_a_answer(
      &mdns_proto::Name::try_from_str(qname).expect("query name"),
      120,
      addr,
      false,
    )
    .expect("push_a_answer");
  let n = builder.finish().expect("finish");
  buf.truncate(n);
  buf
}

/// Put `body` on the multicast wire through the socket layer alone — no credit
/// recorded, so the drain weighs the loopback copy as peer traffic — and wait
/// until it has made the IPv4 socket readable.
fn queue_peer_datagram(mdns: &mut Mdns, poll: &mut Poll, body: &[u8], what: &str) -> Option<()> {
  let sent = mdns
    .sockets
    .send_one(Family::V4, body, MDNS_V4_DST, &crate::socket::Ungated);
  if !matches!(sent, crate::socket::SendOutcome::Sent { .. }) {
    eprintln!(
      "skipping: this host's kernel refused a multicast datagram on the loopback \
       interface ({sent:?}), so {what} can never reach the drain"
    );
    return None;
  }
  await_queued_datagram(mdns, poll, what)
}

/// Run one tick whose stage 1 loses the CPU until the query's window has shut,
/// with the datagram already admitted and only `Endpoint::handle` left.
///
/// `started` is from just before the query was created, so the stall is what
/// remains of the window plus a margin: the tick's own instant is still inside
/// the window — which is what a stale reading would admit the datagram on — while
/// the datagram is processed outside it.
fn tick_across_the_window(mdns: &mut Mdns, started: Instant) {
  let left = QUERY_WINDOW.saturating_sub(started.elapsed());
  assert!(
    !left.is_zero(),
    "the window shut during setup, so the tick's own instant is past it too and \
     this test would assert nothing about which instant was weighed"
  );
  mdns.force_claim_delays_for_test(&[left.saturating_add(PAST_THE_WINDOW)]);
  mdns.tick().expect("tick");
  assert!(
    mdns.forced_claim_delays.is_empty(),
    "the stall is consumed at the claim, so an unconsumed one means the datagram \
     never got past the admission gates and this test asserted nothing"
  );
}

/// A response processed after the drain has crossed the window must not be
/// collected — and must not evict the answer that was collected inside it.
///
/// The cap is 1 because the late answer's real cost is not that it appears: it is
/// that FIFO eviction makes it take one away. That is what makes weighing the
/// refusal against a stale instant a loss rather than a laxity.
#[test]
fn a_response_processed_after_the_drain_crossed_the_window_is_not_collected() {
  const QNAME: &str = "hick-mio-late-answer.local.";

  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  let started = Instant::now();
  let handle = mdns
    .start_query(
      mdns_proto::QuerySpec::new(
        mdns_proto::Name::try_from_str(QNAME).expect("query name"),
        ResourceType::A,
      )
      .with_timeout(QUERY_WINDOW)
      .with_max_answers(1),
    )
    .expect("start_query");

  // The answer the caller is owed, taken while the window is open.
  test_support::ingest(
    &mut mdns,
    &a_response(QNAME, Ipv4Addr::new(10, 0, 0, 7)),
    Instant::now(),
  );
  assert_eq!(
    mdns.endpoint.collected_answers(handle).count(),
    1,
    "the in-window answer must be collected, or there is nothing for the late one \
     to evict"
  );

  let late = a_response(QNAME, Ipv4Addr::new(10, 0, 0, 8));
  let queued = queue_peer_datagram(&mut mdns, &mut poll, &late, "the late response");
  if queued.is_none() {
    mdns.deregister().expect("deregister");
    return;
  }
  tick_across_the_window(&mut mdns, started);
  // Read from the CALLER's queue rather than from the endpoint's collection.
  // The same drain that crossed the window raises the tick's protocol instant to
  // the instant it folded at, so stage 3 fires this query's deadline in the same
  // tick and stage 5 delivers what it collected on the way out. That is the
  // terminal the caller was promised, one tick earlier than a stale reading gave
  // it, and the answers still pass through stage 5 ahead of it.
  let mut answers: Vec<Vec<u8>> = Vec::new();
  let mut terminated = false;
  while let Some(ev) = mdns.next_event() {
    match ev {
      Event::QueryAnswer { handle: h, answer } if h == handle => {
        answers.push(answer.rdata_slice().to_vec());
      }
      Event::QueryTerminal { handle: h, .. } if h == handle => terminated = true,
      _ => {}
    }
  }
  mdns.deregister().expect("deregister");

  assert!(
    terminated,
    "the query's own deadline is the only thing that may end it, and the tick \
     that crossed it must deliver that terminal"
  );
  assert_eq!(
    answers.len(),
    1,
    "a response processed after the drain crossed the window must not be \
     collected; got {answers:?}"
  );
  assert_eq!(
    answers[0].as_slice(),
    &[10, 0, 0, 7],
    "and it must not have evicted the answer collected inside the window: the \
     tick's instant is what makes a late datagram look in-window, and under the \
     cap that costs the caller a result it was promised"
  );
}

/// A duplicate question processed after the drain has crossed the window must
/// spend no RFC 6762 §7.3 retry slot.
///
/// The query is deliberately never polled first, so its first transmit is still
/// pending — which is what makes a suppression reachable at all. Counted through
/// `duplicate_questions_suppressed`, which is bumped only where the endpoint
/// accepts the suppression.
#[test]
#[cfg(feature = "stats")]
fn a_duplicate_question_after_the_drain_crossed_the_window_spends_no_slot() {
  const QNAME: &str = "_hick-mio-late-dup._tcp.local.";

  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  let started = Instant::now();
  let handle = mdns
    .start_query(
      mdns_proto::QuerySpec::new(
        mdns_proto::Name::try_from_str(QNAME).expect("query name"),
        ResourceType::Ptr,
      )
      .with_timeout(QUERY_WINDOW),
    )
    .expect("start_query");

  let peer_question = legacy_query_datagram(QNAME);
  let queued = queue_peer_datagram(
    &mut mdns,
    &mut poll,
    &peer_question,
    "the peer's duplicate question",
  );
  if queued.is_none() {
    mdns.deregister().expect("deregister");
    return;
  }
  // The premise, stated BEFORE the tick: nothing inside it can retire this query
  // ahead of stage 1, so a query live here is a query live at the drain — and
  // that is what makes a zero count below mean the suppression was refused
  // rather than that there was nothing left to suppress. It is read here rather
  // than after because the same drain that crosses the window raises the tick's
  // protocol instant to it, so stage 3 fires this query's deadline in the same
  // tick and stage 5 retires it.
  let live_at_the_drain = mdns.endpoint.query_accepted_count(handle).is_some();
  tick_across_the_window(&mut mdns, started);
  let suppressed = mdns.stats().duplicate_questions_suppressed;
  mdns.deregister().expect("deregister");

  assert!(
    live_at_the_drain,
    "the query must exist when the drain runs for the count below to mean the \
     suppression was refused rather than that there was nothing left to suppress"
  );
  assert_eq!(
    suppressed, 0,
    "a duplicate question processed after the drain crossed the window must not \
     consume a §5.2 slot: the peer's query elicits answers this query's caller \
     was told it would no longer collect"
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
  // A probe that reaches no wire has two causes and they are not interchangeable:
  // a kernel that refuses multicast egress — which shows up as a send-failure
  // streak, since the driver goes on offering the probe and the socket goes on
  // refusing it — and a driver that stopped offering one, which leaves the family
  // healthy and this wire empty. Only the first is this host's doing.
  let give_up = Instant::now() + Duration::from_secs(8);
  while mdns.sockets.wire_times_for_test(Family::V4).is_empty() {
    if Instant::now() >= give_up {
      assert!(
        mdns.degraded_families().0,
        "nothing reached IPv4's wire and the family is not degraded either, so \
         the socket was never asked to carry a probe: the gate is withholding a \
         datagram the core had due"
      );
      eprintln!(
        "skipping: this host's kernel refused every multicast send, so no probe \
         could reach a wire for the gate to be weighed against"
      );
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
  assert!(
    matches!(
      summary.attempts[Family::V6.index()],
      FamilyAttempt::Accepted { .. }
    ),
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

// ── the tick's protocol instant is never older than what stage 1 folded ─────
//
// Stage 1 anchors every effect of a datagram to a reading of its own, taken per
// datagram and after however long the receive has already run. Among those
// effects is RFC 6762 §8.1's endpoint-wide conflict ring, whose fifteenth entry
// engages a five-second floor on the next probe sequence to start. Stages 3 and
// 4 then ask the core to weigh that floor — and the tick's entry reading is
// EARLIER than a conflict counted inside the receive, so the core is asked how
// long ago the burst was using an instant from before it was counted. That
// question has no answer, and this driver was asking it on ordinary traffic.
//
// The core now refuses it on the restrictive side, so the cost was a probe
// delayed rather than a MUST violated. This pins the driver's own half: the
// tick's instant is RAISED to whatever stage 1 folded at.

/// The instant stages 3 and 4 are handed is never older than one stage 1 handed
/// the core.
///
/// The stall is taken inside the drain — after the datagram has been read and
/// admitted, with only `Endpoint::handle` left — so the fold really does happen
/// at a reading the tick's entry precedes. A protocol instant still equal to the
/// entry one means every event that datagram produced is being judged from
/// before it happened.
#[test]
fn the_ticks_protocol_instant_is_never_older_than_what_the_receive_folded() {
  const STALL_INSIDE_THE_DRAIN: Duration = Duration::from_millis(400);

  let Some((mut mdns, mut poll)) = registered_v4_only() else {
    return;
  };
  let body = a_response("hick-mio-folded-late.local.", Ipv4Addr::new(10, 0, 0, 9));
  let queued = queue_peer_datagram(&mut mdns, &mut poll, &body, "the folded datagram");
  if queued.is_none() {
    mdns.deregister().expect("deregister");
    return;
  }
  mdns.force_claim_delays_for_test(&[STALL_INSIDE_THE_DRAIN]);
  mdns.tick().expect("tick");
  let consumed = mdns.forced_claim_delays.is_empty();
  let entered = mdns
    .last_tick_instant
    .expect("the tick records the instant it entered on");
  let protocol = mdns
    .last_protocol_instant
    .expect("the tick records the instant it handed stages 3 and 4");
  mdns.deregister().expect("deregister");

  assert!(
    consumed,
    "the stall is consumed at the claim, so an unconsumed one means the datagram \
     never reached `Endpoint::handle` and this test asserted nothing"
  );
  assert!(
    protocol.saturating_duration_since(entered) >= STALL_INSIDE_THE_DRAIN,
    "the tick handed its service and query paths an instant read {:?} after \
     entry, while stage 1 folded a datagram {STALL_INSIDE_THE_DRAIN:?} into it — \
     so an RFC 6762 §8.1 conflict counted inside the receive would be weighed \
     against a reading from before it was counted",
    protocol.saturating_duration_since(entered)
  );
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
  let budget = usize::from(super::withdrawal::GOODBYE_ROUNDS_PER_FAMILY);
  // The direction this test exists to catch is IPv6's retries leaking onto
  // IPv4's wire, which can only ever ADD datagrams past what IPv4 itself
  // owed — dropping a round never manufactures an extra one — so this half
  // is unconditional regardless of how much of IPv4's own budget a busy wire
  // let through.
  assert!(
    wire_times.len() <= budget,
    "IPv4 owed exactly its §10.1 budget; {} datagrams reached its wire after unregister, \
     more than that — the blocked IPv6 family's retries put a redundant goodbye on IPv4's \
     wire",
    wire_times.len()
  );
  // Whether IPv4 paid its FULL budget (not merely stopped short of it) does
  // depend on IPv4's own real sends succeeding, which this binary's own
  // contention with whatever else is bound to the shared multicast group can
  // legitimately prevent — the ceiling only guarantees IPv6's retries stop
  // riding a PAID IPv4, never that IPv4 gets through in the first place.
  // There is no discriminator this test can check for a partial shortfall
  // (unlike a total one, a family that delivered some but not all of its
  // budget need not have tripped `degraded_families`'s consecutive-failure
  // streak), so a shortfall here is a skip rather than a proven-safe case:
  // the over-fan half above still ran and still covers the regression this
  // test exists for.
  if wire_times.len() < budget {
    eprintln!(
      "skipping: the exact-budget and spacing checks below: IPv4 reached the wire only {} of \
       its {budget}-round §10.1 budget, which a busy wire can legitimately cause",
      wire_times.len()
    );
    return;
  }
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

/// The endpoint's own per-family goodbye budget is what this module's tests
/// restate.
///
/// Pinned against the ENDPOINT: this pumps `poll_withdrawal_transmit` directly,
/// so it counts the rounds the endpoint itself owes rather than the rounds any
/// fan-out was willing to offer. A change to `mdns-proto`'s budget therefore
/// fails here, instead of leaving the counts the other withdrawal tests assert
/// on quietly measuring against the wrong number.
#[test]
fn the_endpoints_goodbye_budget_is_what_the_tests_restate() {
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
     they have drifted, so every test here that counts goodbye rounds is now \
     measuring against a budget the endpoint does not have"
  );
}

// ── stage 4 weighs the caller's query window on its own clock ───────────────
//
// `QuerySpec::with_timeout` is a promise to whoever set it: no question is
// ADMITTED at or after the instant it makes absolute. The core keeps that
// promise inside `Query::poll_transmit`, weighed against the instant the driver
// hands in — so the promise is worth exactly what that reading is worth. The
// tick's reading is taken before stages 1 through 3, and stage 1 is bounded by a
// peer rather than by this host: a window that shuts while the receive is still
// running is invisible to it, and the question is admitted after the caller was
// told none would be.
//
// The §5.2 ladder underneath the same query is the opposite case and stays on
// the tick's instant — see this module's clock rule.

/// A receive stage that alone outlives the caller's whole window, so the
/// crossing is this stall's rather than a slow runner's.
const RECV_OUTLIVES_QUERY_WINDOW: Duration = Duration::from_millis(600);

/// The window the caller asks for. Short enough that the stall above clears it
/// several times over, long enough that reaching stage 4 inside it is not a race.
const CALLER_QUERY_WINDOW: Duration = Duration::from_millis(150);

/// A question drawn after the caller's window shut must not reach the wire — and
/// the query must still end where its deadline's owner ends it.
///
/// The window is a real 150 ms measured from `start_query`, and stage 1 is made
/// to lose the CPU for 600 ms of it. That stall lands *before* the read, so it is
/// charged whether or not a datagram is waiting, and it puts the deadline inside
/// the tick with stage 4 still to run — which no arrangement of the query's own
/// fields can do, since those fields are what the core reads.
///
/// What it catches: stage 4 handing the core the instant `tick` read at its top.
/// That reading is *before* the deadline here — asserted rather than assumed, so
/// a slow host fails the premise loudly instead of passing on the
/// already-expired path — so a stage 4 that trusts it draws a question the
/// caller's window has in fact already closed on, and multicasts it.
///
/// The wire count is the discriminator, and it is IPv4's own record rather than
/// the driver's account of it. The closing half asserts the withheld send left
/// the deadline standing: withholding defers the terminal to `handle_timeout`,
/// so a caller that would have been told `Timeout` must still be told it, on the
/// wakeup `next_timeout` already publishes.
#[test]
fn a_question_drawn_past_the_callers_window_never_reaches_the_wire() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  if !mdns.sockets.is_bound_for_test(Family::V4) {
    eprintln!("skipping: IPv4 is not bound on this host");
    return;
  }
  let handle = mdns
    .start_query(
      test_support::query_spec("_hick-mio-late-question._tcp.local.")
        .with_timeout(CALLER_QUERY_WINDOW),
    )
    .expect("start_query");
  let deadline = mdns
    .endpoint
    .poll_query_timeout(handle)
    .expect("a query given a window publishes its absolute deadline");
  let already_on_wire = mdns.sockets.wire_times_for_test(Family::V4).len();

  // Readable-but-empty: the stall is charged on the read attempt, and the real
  // `recv` behind it reports `WouldBlock` and ends stage 1 without needing a
  // peer to supply a datagram.
  mdns.sockets.set_readable_for_test(Family::V4, true);
  mdns
    .sockets
    .force_recv_delays_for_test(Family::V4, &[RECV_OUTLIVES_QUERY_WINDOW]);

  mdns.tick().expect("tick");

  // The premise, stated about the reading the tick itself took rather than one
  // taken beside the call: the tick began inside the window, so whatever
  // withheld this question can only be a reading taken later in the same tick.
  assert!(
    mdns
      .last_tick_instant
      .expect("the tick records the instant it read")
      < deadline,
    "the tick must begin inside the caller's window, or this asserts nothing"
  );
  assert!(
    Instant::now() >= deadline,
    "and the stall must have carried it out of the window"
  );

  assert_eq!(
    mdns.sockets.wire_times_for_test(Family::V4).len(),
    already_on_wire,
    "a question drawn after the caller's window shut reached IPv4's wire; stage \
     4 weighed a promise made to the caller against an instant read before \
     stage 1, which the peer — not this host — decides the length of"
  );

  // Withheld, not ended: the terminal belongs to the deadline's owner, and the
  // wakeup that reaches it must survive the withholding.
  assert_eq!(
    mdns.endpoint.poll_query_timeout(handle),
    Some(deadline),
    "the withheld question must leave the deadline standing — it is the wakeup \
     `next_timeout` folds, and the only thing left that can end this query"
  );
  assert_eq!(
    mdns.next_timeout(),
    Some(Duration::ZERO),
    "and that deadline is already past, so the caller is sent straight back"
  );

  mdns.tick().expect("tick");
  let mut terminal = None;
  while let Some(ev) = mdns.next_event() {
    if let Event::QueryTerminal { handle: h, update } = ev
      && h == handle
    {
      terminal = Some(update);
    }
  }
  assert!(
    matches!(terminal, Some(mdns_proto::QueryUpdate::Timeout)),
    "the query must still end, and with the terminal its deadline's owner \
     produces; got {terminal:?}"
  );
  assert!(
    !mdns.queries.contains_key(&handle),
    "and the ended query must not be left resident"
  );
}

/// A renumbering under a LIVE endpoint is picked up, through `drain_recv`, in
/// BOTH directions and on the interface actually asked for.
///
/// §11 compares a source against the receiving interface's configuration as it
/// IS. A snapshot taken once at bind is wrong in both directions the moment an
/// address changes, and it became load-bearing when the TTL arm was removed.
///
/// Three things this has to establish, and an earlier version established only
/// the first: that the obsolete prefix stops being admitted; that the CURRENT
/// one starts; and that the refresh asked about the interface this endpoint
/// bound. Without the last, production could refresh interface 0 or a foreign
/// one — or merely clear the snapshot — and the first two would still hold.
///
/// It drives the real receive stage: the datagram arrives on a real socket,
/// `drain_recv` refreshes and gates it, and the observable is the
/// [`IngressRecord`] that stage writes. The peer, receive interface and
/// destination are forced, because a loopback fixture only ever sees its own
/// multicast to the group — and the group arm admits regardless of source, which
/// would leave the prefix unobservable.
#[test]
fn a_renumbered_interface_is_picked_up_without_restarting_the_endpoint() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let poll = Poll::new().expect("poll");
  mdns
    .register(poll.registry(), Token(50), Token(51))
    .expect("register");

  // Each snapshot holds the interface's ASSIGNED address and that address's
  // mask, the way `collect_local_subnets` reports it. The address renumbers with
  // the interface, and the forced destination renumbers with it — a datagram
  // unicast to this host after a renumbering is addressed to the address it now
  // holds, and a destination the interface does not hold reaches no §11 arm at
  // all, which would make the prefix unobservable in the other direction.
  const OLD_OWN_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
  const NEW_OWN_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 0, 2));

  mdns.bound_is_loopback = false;
  mdns.local_subnets = vec![(OLD_OWN_ADDR, 24u8)];
  let bound = mdns.bound_interface;
  mdns
    .sockets
    .force_rx_iface_for_test(Some(iface_witness(bound)));
  // A UNICAST destination — one this interface holds — so §11's source-prefix
  // arm is what decides.
  mdns
    .sockets
    .force_rx_destination_for_test(Some(DestinationWitness::Witnessed(OLD_OWN_ADDR)));

  let old_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)), 5353);
  let new_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 3, 9)), 5353);

  let mut poll = poll;
  let verdict =
    |mdns: &mut Mdns, poll: &mut Poll, peer: SocketAddr, body: &[u8; 28]| -> Option<bool> {
      mdns.sockets.force_rx_peer_for_test(Some(peer));
      credit_a_multicast_send(mdns, body)?;
      let want = crate::driver::body_fingerprint(body);
      mdns.ingress_log.clear();
      let mut events = mio::Events::with_capacity(8);
      let deadline = Instant::now() + Duration::from_secs(2);
      while Instant::now() < deadline && !mdns.ingress_log.iter().any(|r| r.body == want) {
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
      mdns
        .ingress_log
        .iter()
        .find(|r| r.body == want)
        .map(|r| r.admitted)
    };

  let old_before = verdict(&mut mdns, &mut poll, old_peer, &[0x11u8; 28]);
  let new_before = verdict(&mut mdns, &mut poll, new_peer, &[0x22u8; 28]);

  // The interface renumbers 192.168.1.2/24 -> 169.254.0.2/16 under the live
  // endpoint. The forced answer is keyed to THIS interface: a refresh aimed at
  // any other index gets an empty list, so wrong-field wiring cannot pass.
  hick_udp::onlink::force_enumeration_for_test(Some((bound, vec![(NEW_OWN_ADDR, 16u8)])));
  // The address this host answers to renumbers with it, so both phases below
  // reach §11's second arm and the SOURCE prefix is the only thing that differs.
  mdns
    .sockets
    .force_rx_destination_for_test(Some(DestinationWitness::Witnessed(NEW_OWN_ADDR)));
  mdns.subnets_refreshed_at = Instant::now()
    .checked_sub(hick_udp::onlink::SUBNET_REFRESH_INTERVAL + Duration::from_millis(50))
    .expect("a monotonic instant that far back exists on this host");

  let old_after = verdict(&mut mdns, &mut poll, old_peer, &[0x33u8; 28]);
  let new_after = verdict(&mut mdns, &mut poll, new_peer, &[0x44u8; 28]);
  let asked = hick_udp::onlink::last_enumerated_interface_for_test();
  hick_udp::onlink::force_enumeration_for_test(None);
  mdns.deregister().expect("deregister");

  match (old_before, new_before, old_after, new_after) {
    (Some(ob), Some(nb), Some(oa), Some(na)) => {
      assert!(
        ob,
        "the configured prefix must admit before the renumbering"
      );
      assert!(
        !nb,
        "the future prefix must not admit before the renumbering"
      );
      assert!(
        !oa,
        "the obsolete prefix must stop being admissible once the interface \
         changed, and `drain_recv` is what has to notice"
      );
      assert!(
        na,
        "the current prefix must start being admitted without a restart"
      );
      assert_eq!(
        asked,
        Some(bound),
        "the refresh must enumerate the interface this endpoint BOUND; \
         refreshing index 0 or a foreign one would leave the four assertions \
         above green while isolating nothing"
      );
    }
    _ => eprintln!(
      "note: this endpoint's own multicast never looped back, so no datagram \
       reached the receive stage and this host contributes no evidence"
    ),
  }
}

/// A body the send log classifies as an ASSERTION — QR and AA set, the header
/// every response this endpoint sends carries — tagged so two of them are
/// distinct bytes.
///
/// Spelled out rather than left to an ASCII string, because
/// `a_registration_leaves_a_live_services_credits_observable` turns entirely on
/// the class: a QUESTION's credit is never superseded whatever the generation
/// reads, so a body that classified as one would make every assertion there pass
/// while testing nothing. `SendClass` is private to `hick-udp`, so the class is
/// proved by consequence instead —
/// `the_withdrawal_seam_supersedes_outstanding_credits` claims this exact shape
/// and gets `Superseded`, a tier only an ASSERTING credit can reach.
fn asserting_body(tag: u8) -> Vec<u8> {
  let mut body = vec![0u8; 12];
  // RFC 1035 §4.1.1 flags, high octet: QR | AA.
  body[2] = 0x84;
  body.push(tag);
  body
}

/// Beginning a withdrawal advances the self-send generation, so a credit
/// recorded before it is reported as `Superseded` — a STANDING tombstone that
/// keeps every copy of those bytes out of this endpoint's cache and quieting
/// rules, rather than a take-once credit whose second copy walks in as a peer's.
/// Both tiers still adjudicate: see `Provenance::OwnEchoLikely`.
///
/// The seam is what this pins, not the tracker's own rule (that lives in
/// `hick-udp`). `begin_service_withdrawal` is a free function taking only the
/// endpoint and the service map — it does NOT reach `Mdns` — so the tracker had
/// to be threaded into it, and a later refactor dropping that parameter would
/// silently reopen the whole finding. `unregister_service` is the caller that
/// proves the thread survives the split borrow it destructures through.
#[test]
fn the_withdrawal_seam_supersedes_outstanding_credits() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-generation._tcp.local.",
      8080,
    ))
    .expect("register_service");
  // A credit for a datagram sent while that registration was live.
  let announcement = asserting_body(1);
  let sent = hick_udp::selfsend::ClockPair::now();
  mdns.selfsend.record(Family::V4, &announcement, sent);
  mdns.selfsend.seal();
  // Retiring the service is the moment its route stops holding its host name
  // for the registration guard, so a replacement may take that name with a
  // different address set — which is exactly what the credit above must no
  // longer be allowed to adjudicate against.
  mdns.unregister_service(handle);
  assert_eq!(
    mdns
      .selfsend
      .claim(&RxDatagram::without_stamp(Family::V4, &announcement[..])),
    SelfSendMatch::Superseded,
    "beginning a withdrawal must supersede every outstanding credit"
  );
  mdns.deregister().expect("deregister");
}

/// A SERVICE REGISTRATION IS NOT A PUBLICATION CHANGE, SO IT SUPERSEDES NOTHING.
///
/// `SelfSendTracker::supersede` declares that what this endpoint publishes has
/// CHANGED, so every credit already recorded describes a state it has left. A
/// registration only INSERTS a route. It mutates no record this endpoint has
/// already asserted: there is no RFC 6762 §8.4 records mutator, a duplicate
/// instance name and a name a §10.1 goodbye still holds are both refused,
/// and a live-route host disagreement is refused by
/// `Endpoint::host_addresses_disagree`. The negative assertions are covered too
/// — the encoder emits exactly one §6.1 NSEC per service and it is owned by the
/// INSTANCE name, so no sibling registration can flip a host-name NSEC's truth.
/// No record this endpoint ever asserted, positive or negative, changes
/// truth-value here.
///
/// # What the spurious advance cost
///
/// A superseded credit is a STANDING tombstone: it answers EVERY byte-identical
/// copy for the rest of `SELF_SEND_TTL` and no claim spends it. So one unrelated
/// registration denied observation and quieting to every copy of a LIVE service's
/// own bytes for the whole window — to a conforming §9 fault-tolerance twin's
/// identical answers, and to a peer's TTL=0 §10.1 goodbye burst, which then
/// reaches no cache at all and leaves the very entry it exists to retract
/// standing for its full original TTL instead of §10.1's one-second clamp.
///
/// This is that finding's repro. The claims below are the burst: copy 1 is the
/// endpoint's own loopback echo and is spent by it, and every copy behind it must
/// read `NoCredit` — a peer's datagram, observed.
#[test]
fn a_registration_leaves_a_live_services_credits_observable() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let live = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-live._tcp.local.",
      8080,
    ))
    .expect("register_service");
  // A credit for a datagram this LIVE service sent. Nothing below retires it.
  let announcement = asserting_body(2);
  let sent = hick_udp::selfsend::ClockPair::now();
  mdns.selfsend.record(Family::V4, &announcement, sent);
  mdns.selfsend.seal();

  // An entirely unrelated service registers. Different instance name, different
  // service type, same host and same addresses — so it asserts nothing the live
  // route asserts, and contradicts nothing it asserts either.
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-unrelated._tcp.local.",
      8081,
    ))
    .expect("register_service");

  assert_eq!(
    mdns
      .selfsend
      .claim(&RxDatagram::without_stamp(Family::V4, &announcement[..])),
    SelfSendMatch::Degraded,
    "the registration published nothing this credit had left behind, so it must \
     still read at the CURRENT tier"
  );
  for copy in 2..=4u32 {
    assert_eq!(
      mdns
        .selfsend
        .claim(&RxDatagram::without_stamp(Family::V4, &announcement[..])),
      SelfSendMatch::NoCredit,
      "take-once must be intact across the registration: copy {copy} of these \
       bytes is a PEER's — a §9 twin's answer or a §10.1 goodbye — and a \
       tombstone standing here would deny it this endpoint's cache and quieting \
       for the whole recency window"
    );
  }
  assert!(
    mdns.services.contains_key(&live),
    "precondition: the credit's own service is still LIVE, so this is the \
     unrelated-registration case and not a withdrawal in disguise"
  );
  mdns.deregister().expect("deregister");
}

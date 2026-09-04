//! Socket-free tests for the per-family projection, the family-health policy,
//! and the wire gate.
//!
//! Every property here is arithmetic over per-family outcomes, so none of it
//! depends on whether this host bound IPv6 or on whether its multicast egress
//! works — the two things that differ between macOS and Linux CI and that a
//! socket-driven test would silently fold in.

use std::time::{Duration, Instant as StdInstant, SystemTime};

use mdns_proto::FamilyAttempt;

use super::{
  FAMILY_V4, FAMILY_V6, FamilyWireGate, MAX_CONSECUTIVE_SEND_FAILURES, SendHealth, summarize,
};
use crate::socket::{Family, SendOutcome, SendReport};

/// A stamped acceptance, `secs` after a fixed origin. All three clocks move
/// together so a test that reads any of them is talking about the same syscall.
///
/// The two monotonic stamps coincide here on purpose: an instantaneous syscall
/// is the case where the confirm anchor and the wire time agree, so a fixture
/// built on it cannot smuggle the difference between them into a property that
/// is not about it. [`stalled_send`] is the fixture that pulls them apart.
fn sent(base: StdInstant, secs: u64) -> SendOutcome {
  let at = base + Duration::from_secs(secs);
  SendOutcome::Sent {
    submitted_wall: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
    submitted_at: at,
    wire_at: at,
  }
}

/// An acceptance whose syscall did not run when its pre-syscall stamps were
/// read: submitted at `secs`, on the wire `stall` later.
///
/// Nothing bounds that window on a real host — a preemption, a signal handler or
/// a page fault between the clock read and `sendto` opens it — and it is the one
/// input that tells the core's anchor and the wire gate's apart.
fn stalled_send(base: StdInstant, secs: u64, stall: Duration) -> SendOutcome {
  let submitted_at = base + Duration::from_secs(secs);
  SendOutcome::Sent {
    submitted_wall: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
    submitted_at,
    wire_at: submitted_at + stall,
  }
}

/// A **multicast** report: the case that fans out to both families.
fn report(v4: SendOutcome, v6: SendOutcome) -> SendReport {
  SendReport {
    v4,
    v6,
    loops_back: true,
  }
}

/// Fold `rep` into `health` exactly as a real fan-out does, then project it.
///
/// The projection takes no `health`: that severance is the property most of the
/// tests below are about, so the fixture keeps both halves the way production
/// runs them rather than skipping the one that cannot matter.
fn settle(health: &mut SendHealth, rep: SendReport) -> super::SendSummary {
  health.note_fanout(rep);
  summarize(rep)
}

// ── the per-family projection ─────────────────────────────────────────

#[test]
fn a_dual_stack_send_both_families_took_is_all_delivered() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  let summary = settle(&mut health, report(sent(base, 1), sent(base, 2)));
  assert!(matches!(
    summary.attempts[FAMILY_V4],
    FamilyAttempt::Accepted { .. }
  ));
  assert!(matches!(
    summary.attempts[FAMILY_V6],
    FamilyAttempt::Accepted { .. }
  ));
  assert_eq!(summary.sent, 2, "two syscalls put bytes on a wire");
}

#[test]
fn a_round_that_reached_no_wire_has_no_anchor() {
  let mut health = SendHealth::new();
  let summary = settle(
    &mut health,
    report(SendOutcome::Failed, SendOutcome::Failed),
  );
  assert_eq!(
    summary.attempts,
    [
      FamilyAttempt::Refused { permanent: false },
      FamilyAttempt::Refused { permanent: false }
    ],
    "neither family accepted, so there is no acceptance to anchor a refresh on"
  );
  assert_eq!(summary.sent, 0);
}

#[test]
fn a_send_one_family_missed_latches_ownership_but_not_the_phase() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  let summary = settle(&mut health, report(sent(base, 1), SendOutcome::Failed));
  assert!(matches!(
    summary.attempts[FAMILY_V4],
    FamilyAttempt::Accepted { .. }
  ));
  assert_eq!(
    summary.attempts[FAMILY_V6],
    FamilyAttempt::Refused { permanent: false }
  );
  assert_eq!(summary.sent, 1);
}

#[test]
fn an_unbound_family_owes_nothing() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  let summary = settle(&mut health, report(sent(base, 1), SendOutcome::NoSocket));
  assert_eq!(summary.attempts[FAMILY_V6], FamilyAttempt::NoSocket);
}

#[test]
fn a_gated_family_is_missed_and_never_unobligated() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  let summary = settle(&mut health, report(sent(base, 1), SendOutcome::Gated));
  assert_eq!(
    summary.attempts[FAMILY_V6],
    FamilyAttempt::GateShut,
    "the socket is there and the datagram was meant for it; the driver owed \
     the wire a gap it had not paid, and that is never the same report as an \
     absent socket"
  );
}

#[test]
fn a_too_large_family_is_missed_exactly_like_a_refused_one() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  let summary = settle(&mut health, report(sent(base, 1), SendOutcome::TooLarge));
  assert_eq!(
    summary.attempts[FAMILY_V6],
    FamilyAttempt::Refused { permanent: true },
    "the socket is there and the datagram was meant for it, so it is a \
     refusal — never `NoSocket`, which would tell the core this family owes \
     nothing"
  );
}

#[test]
fn a_single_stack_host_refusing_the_size_has_refused_it_everywhere() {
  let mut health = SendHealth::new();
  let summary = settle(
    &mut health,
    report(SendOutcome::TooLarge, SendOutcome::NoSocket),
  );
  assert_eq!(
    summary.attempts,
    [
      FamilyAttempt::Refused { permanent: true },
      FamilyAttempt::NoSocket
    ],
    "the absent family was never offered the datagram, so only the bound one's \
     refusal is on record"
  );
}

// ── family health is observability, and nothing the core is told ──────

/// The laundering this driver must never do: a present family that keeps failing
/// is `Missed` forever, and never the `Unobligated` an ABSENT socket reports.
///
/// `Unobligated` tells the core the family owes nothing, so `classify_advance`
/// clears its missed count and marks it covered — and the round then satisfies
/// `all_delivered` on the strength of the one family that did deliver. Bounding
/// how long the lifecycle waits for a family that keeps missing is the core's
/// own patience, which advances the phase as `Excused` and takes none of the
/// credit a delivery earns.
#[test]
fn a_chronically_failing_family_is_missed_forever_never_unobligated() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  // Well past the degradation threshold: whatever the driver's health table
  // thinks of this link, the projection says the same thing every round.
  for round in 0..MAX_CONSECUTIVE_SEND_FAILURES * 4 {
    let summary = settle(&mut health, report(sent(base, 1), SendOutcome::Failed));
    assert_eq!(
      summary.attempts[FAMILY_V6],
      FamilyAttempt::Refused { permanent: false },
      "round {round}: the socket is there and the datagram was fanned onto it, \
       never `NoSocket`"
    );
  }
  assert_eq!(
    health.degraded_families(),
    (false, true),
    "the observability signal is preserved: a caller debugging \"my peers do \
     not see me over IPv6\" must still be able to see this"
  );
}

#[test]
fn a_gated_family_is_never_charged_to_health() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  for _ in 0..MAX_CONSECUTIVE_SEND_FAILURES * 4 {
    settle(&mut health, report(sent(base, 1), SendOutcome::Gated));
  }
  assert_eq!(
    health.degraded_families(),
    (false, false),
    "no syscall was made and the deferral is this driver's own, so it is no \
     evidence at all about the link"
  );
}

#[test]
fn a_family_refusing_the_size_is_charged_to_health_like_any_other_refusal() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  for _ in 0..MAX_CONSECUTIVE_SEND_FAILURES {
    settle(&mut health, report(sent(base, 1), SendOutcome::TooLarge));
  }
  assert_eq!(
    health.degraded_families(),
    (false, true),
    "a socket that refuses everything offered to it is a link a caller \
     debugging \"my peers do not see me over IPv6\" must be told about, \
     whatever the reason for the refusal"
  );
}

#[test]
fn an_unbound_family_is_never_charged_to_health() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  for _ in 0..MAX_CONSECUTIVE_SEND_FAILURES * 4 {
    settle(&mut health, report(sent(base, 1), SendOutcome::NoSocket));
  }
  assert_eq!(health.degraded_families(), (false, false));
}

#[test]
fn one_delivery_restores_a_degraded_family() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  for _ in 0..MAX_CONSECUTIVE_SEND_FAILURES {
    settle(&mut health, report(sent(base, 1), SendOutcome::Failed));
  }
  assert_eq!(health.degraded_families(), (false, true));
  let summary = settle(&mut health, report(sent(base, 1), sent(base, 1)));
  assert!(
    matches!(summary.attempts[FAMILY_V6], FamilyAttempt::Accepted { .. }),
    "a degraded family that put the records on a wire really did deliver them"
  );
  assert_eq!(
    health.degraded_families(),
    (false, false),
    "recovery is immediate and needs no separate edge"
  );
}

#[test]
fn a_delivery_by_a_degraded_family_still_latches_ownership() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  // Degrade v4 while v6 stays healthy.
  for _ in 0..MAX_CONSECUTIVE_SEND_FAILURES {
    settle(&mut health, report(SendOutcome::Failed, sent(base, 1)));
  }
  assert_eq!(health.degraded_families(), (true, false));
  let summary = settle(&mut health, report(sent(base, 2), SendOutcome::Failed));
  assert!(
    matches!(summary.attempts[FAMILY_V4], FamilyAttempt::Accepted { .. }),
    "peers reachable over the recovered family now hold these records"
  );
  assert_eq!(
    summary.attempts[FAMILY_V6],
    FamilyAttempt::Refused { permanent: false },
    "v6 is obligated and missed"
  );
}

#[test]
fn a_families_failure_streak_is_its_own() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  // Alternating single-family failures: each success resets that family, so
  // neither ever accumulates a streak.
  for _ in 0..MAX_CONSECUTIVE_SEND_FAILURES * 3 {
    settle(&mut health, report(sent(base, 1), SendOutcome::Failed));
    settle(&mut health, report(SendOutcome::Failed, sent(base, 1)));
  }
  assert_eq!(
    health.degraded_families(),
    (false, false),
    "a capacity-one transport is two working links taking turns, not a dead \
     one; bounding that is the core's patience, not this table's"
  );
}

// ── the reclaim-cancel gate belongs to the core alone ─────────────────

/// The hazard the severance exists to prevent, against a REAL `mdns-proto`
/// service rather than against the projection in isolation.
///
/// One family takes every datagram; the other is bound and refuses every one,
/// for far longer than [`MAX_CONSECUTIVE_SEND_FAILURES`]. `has_fully_announced`
/// is the reclaim-cancel gate, and its whole content is the assertion that EVERY
/// obligated link heard a complete announcement — so nothing the DRIVER does may
/// open it here. Only the core's own `Delivered` advance may, and a family that
/// heard nothing cannot produce one.
///
/// The service must still reach `Established`, and does so on the core's own
/// `Excused` patience: that advance moves the phase and takes none of the credit
/// a delivery earns, which is exactly the asymmetry a driver-side write-off
/// destroys.
///
/// Socket-free and on a virtual clock, so it asserts the same thing on every
/// host and in every CI configuration.
#[test]
fn a_chronically_failing_family_never_opens_the_fully_announced_gate() {
  use mdns_proto::ServiceState;
  use rand::{SeedableRng, rngs::StdRng};

  use crate::{driver::test_support, options::ServerOptions, proto::ProtoEndpoint};

  let opts = ServerOptions::default();
  let mut endpoint = ProtoEndpoint::try_new(*opts.endpoint_config(), StdRng::seed_from_u64(0x6a7c));
  let mut now = StdInstant::now();
  let handle = endpoint
    .try_register_service(
      test_support::service_spec("_hick-mio-gate._tcp.local.", 8080),
      now,
    )
    .expect("try_register_service");
  // Read-only observation of the endpoint-owned state machine, re-borrowed at
  // every use because every drive below mutates the endpoint.
  macro_rules! svc {
    () => {
      endpoint
        .service(handle)
        .expect("the endpoint owns the registered service")
    };
  }

  let mut health = SendHealth::new();
  let mut buf = vec![0u8; 1500];
  let mut confirms = 0usize;
  for _ in 0..400 {
    // Jump the virtual clock to whatever the service is next waiting for. The
    // extra millisecond is what makes a deadline of `now` due rather than
    // pending.
    match endpoint.poll_service_timeout(handle) {
      Some(due) => now = due.max(now) + Duration::from_millis(1),
      None => now += Duration::from_secs(1),
    }
    endpoint
      .handle_service_timeout(handle, now)
      .expect("handle_service_timeout");
    if endpoint
      .poll_service_transmit(handle, now, &mut buf)
      .expect("poll_service_transmit")
      .is_some()
    {
      let summary = settle(
        &mut health,
        report(
          SendOutcome::Sent {
            submitted_wall: SystemTime::UNIX_EPOCH,
            submitted_at: now,
            wire_at: now,
          },
          SendOutcome::Failed,
        ),
      );
      let _ = endpoint.note_service_transmit_outcome(
        handle,
        now,
        summary.attempts[FAMILY_V4],
        summary.attempts[FAMILY_V6],
      );
      confirms = confirms.saturating_add(1);
    }
    assert!(
      !svc!().has_fully_announced().get(),
      "the driver reported one family failing and nothing else; only a \
       complete announcement heard by EVERY obligated link may open the \
       reclaim-cancel gate, and IPv6 heard none of them"
    );
    if svc!().state() == ServiceState::Established {
      break;
    }
  }

  assert_eq!(
    svc!().state(),
    ServiceState::Established,
    "the core's own patience must still carry the lifecycle past a family that \
     never delivers; a test that never got here would assert nothing"
  );
  assert!(
    confirms > MAX_CONSECUTIVE_SEND_FAILURES as usize,
    "the run has to spend more rounds than the degradation threshold for the \
     property to mean anything: {confirms}"
  );
  assert_eq!(
    health.degraded_families(),
    (false, true),
    "and the caller can still see which family it was"
  );
}

// ── the per-family wire gate ──────────────────────────────────────────

#[test]
fn a_zero_gap_is_ungated_and_records_nothing() {
  let base = StdInstant::now();
  let mut gate = FamilyWireGate::default();
  assert_eq!(gate.allow_at(base, Duration::ZERO), [true, true]);
  gate.note(report(sent(base, 0), sent(base, 0)), Duration::ZERO);
  assert_eq!(
    gate.allow_at(base, Duration::ZERO),
    [true, true],
    "a one-shot §6 reply must not defer the announcement that follows it"
  );
}

#[test]
fn a_family_that_has_carried_nothing_is_open() {
  let base = StdInstant::now();
  let gate = FamilyWireGate::default();
  assert_eq!(gate.allow_at(base, Duration::from_secs(1)), [true, true]);
}

#[test]
fn each_family_reopens_on_its_own_acceptance_instant() {
  let base = StdInstant::now();
  let gap = Duration::from_secs(1);
  let mut gate = FamilyWireGate::default();
  // v4 accepted at +0, v6 at +3: the inter-family skew the core cannot see.
  gate.note(report(sent(base, 0), sent(base, 3)), gap);
  assert_eq!(
    gate.allow_at(base + Duration::from_millis(3500), gap),
    [true, false],
    "v4 has paid its second; v6's own second is not up until +4"
  );
  assert_eq!(
    gate.allow_at(base + Duration::from_secs(4), gap),
    [true, true]
  );
}

#[test]
fn a_family_that_missed_does_not_move_its_gate() {
  let base = StdInstant::now();
  let gap = Duration::from_secs(1);
  let mut gate = FamilyWireGate::default();
  gate.note(report(sent(base, 0), SendOutcome::Failed), gap);
  assert_eq!(
    gate.allow_at(base, gap),
    [false, true],
    "v6 carried nothing, so it owes no gap and must be offered the re-arm"
  );
}

#[test]
fn a_gated_family_does_not_move_its_own_gate() {
  let base = StdInstant::now();
  let gap = Duration::from_secs(1);
  let mut gate = FamilyWireGate::default();
  gate.note(report(sent(base, 0), sent(base, 0)), gap);
  // Half a second later both are shut; the shut round must not push them out.
  let mid = base + Duration::from_millis(500);
  assert_eq!(gate.allow_at(mid, gap), [false, false]);
  gate.note(report(SendOutcome::Gated, SendOutcome::Gated), gap);
  assert_eq!(
    gate.allow_at(base + Duration::from_secs(1), gap),
    [true, true],
    "the gate reopens one gap after the last ACCEPTANCE, not after the last attempt"
  );
}

#[test]
fn a_clock_that_reads_before_the_recorded_send_keeps_the_gate_shut() {
  let base = StdInstant::now() + Duration::from_secs(10);
  let gap = Duration::from_secs(1);
  let mut gate = FamilyWireGate::default();
  gate.note(report(sent(base, 0), sent(base, 0)), gap);
  assert_eq!(
    gate.allow_at(base - Duration::from_secs(5), gap),
    [false, false],
    "the elapsed gap is unknown, and the conservative answer is the one that \
     cannot put a record back on the wire too soon"
  );
}

/// The two monotonic stamps answer different questions, and a send that had not
/// reached the kernel when its pre-syscall stamps were read is what tells them
/// apart.
///
/// Collapsing them is the tempting simplification, and it is wrong in one
/// direction whichever one survives: the core's anchor must be at or before the
/// true acceptance, and the gate's must be at or after it.
#[test]
fn the_confirm_anchors_before_the_syscall_and_the_gate_after_it() {
  let base = StdInstant::now();
  let stall = Duration::from_millis(200);
  let gap = Duration::from_secs(1);
  let outcome = stalled_send(base, 0, stall);
  let rep = report(outcome, SendOutcome::NoSocket);

  let mut health = SendHealth::new();
  assert_eq!(
    settle(&mut health, rep).attempts[FAMILY_V4],
    FamilyAttempt::Accepted { at: base },
    "the core confirms at the PRE-syscall instant: early can only understate how \
     fresh this family's peers are, while a late one would schedule the refresh \
     past its records' TTL"
  );

  let mut gate = FamilyWireGate::default();
  gate.note(rep, gap);
  assert_eq!(
    gate.allow_at(base + gap, gap),
    [false, true],
    "the bytes reached the wire `stall` after the confirm anchor, so one gap \
     measured from that anchor has NOT paid this wire its second"
  );
  assert_eq!(
    gate.allow_at(base + gap + stall, gap),
    [true, true],
    "one gap after the bytes actually landed, and not before"
  );
}

#[test]
fn the_gate_indices_match_the_cores_family_order() {
  assert_eq!(FAMILY_V4, Family::V4.index());
  assert_eq!(FAMILY_V6, Family::V6.index());
  let base = StdInstant::now();
  let gap = Duration::from_secs(1);
  let mut gate = FamilyWireGate::default();
  gate.note(report(sent(base, 0), SendOutcome::Failed), gap);
  let allow = gate.allow_at(base, gap);
  assert!(
    !allow[FAMILY_V4] && allow[FAMILY_V6],
    "an index mismatch would gate the wrong wire"
  );
}

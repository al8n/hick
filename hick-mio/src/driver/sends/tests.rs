//! Socket-free tests for the per-family projection, the family-health policy,
//! and the wire gate.
//!
//! Every property here is arithmetic over per-family outcomes, so none of it
//! depends on whether this host bound IPv6 or on whether its multicast egress
//! works — the two things that differ between macOS and Linux CI and that a
//! socket-driven test would silently fold in.

use std::time::{Duration, Instant as StdInstant, SystemTime};

use mdns_proto::FamilyDelivery;

use super::{
  FAMILY_V4, FAMILY_V6, FamilyWireGate, MAX_CONSECUTIVE_SEND_FAILURES, SendHealth, summarize,
};
use crate::socket::{Family, SendOutcome, SendReport};

/// A stamped acceptance, `secs` after a fixed origin. Both clocks move together
/// so a test that reads the wall stamp and the monotonic one is talking about
/// the same syscall.
fn sent(base: StdInstant, secs: u64) -> SendOutcome {
  SendOutcome::Sent(
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
    base + Duration::from_secs(secs),
  )
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
fn settle(health: &mut SendHealth, rep: SendReport) -> super::SendSummary {
  health.note_fanout(rep);
  summarize(rep, health)
}

// ── the per-family projection ─────────────────────────────────────────

#[test]
fn a_dual_stack_send_both_families_took_is_all_delivered() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  let summary = settle(&mut health, report(sent(base, 1), sent(base, 2)));
  assert_eq!(summary.delivery.v4(), FamilyDelivery::Delivered);
  assert_eq!(summary.delivery.v6(), FamilyDelivery::Delivered);
  assert!(summary.delivery.all_delivered());
  assert_eq!(summary.sent, 2, "two syscalls put bytes on a wire");
}

#[test]
fn the_confirm_anchors_at_the_earliest_family_acceptance() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  // v6 accepted first. Anchoring at the later one would backdate v6's refresh
  // schedule by the whole inter-family skew.
  let summary = settle(&mut health, report(sent(base, 9), sent(base, 3)));
  assert_eq!(summary.accepted_at, Some(base + Duration::from_secs(3)));
}

#[test]
fn a_round_that_reached_no_wire_has_no_anchor() {
  let mut health = SendHealth::new();
  let summary = settle(
    &mut health,
    report(SendOutcome::Failed, SendOutcome::Failed),
  );
  assert_eq!(summary.accepted_at, None);
  assert_eq!(summary.sent, 0);
  assert!(!summary.delivery.any_delivered());
}

#[test]
fn a_send_one_family_missed_latches_ownership_but_not_the_phase() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  let summary = settle(&mut health, report(sent(base, 1), SendOutcome::Failed));
  assert_eq!(summary.delivery.v4(), FamilyDelivery::Delivered);
  assert_eq!(summary.delivery.v6(), FamilyDelivery::Missed);
  assert!(
    summary.delivery.any_delivered(),
    "IPv4 peers may hold these records, so §10.1 ownership latches"
  );
  assert!(
    !summary.delivery.all_delivered(),
    "IPv6 never saw it, so the §8.1/§8.3 phase must not advance"
  );
  assert_eq!(summary.sent, 1);
}

#[test]
fn an_unbound_family_owes_nothing() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  let summary = settle(&mut health, report(sent(base, 1), SendOutcome::NoSocket));
  assert_eq!(summary.delivery.v6(), FamilyDelivery::Unobligated);
  assert!(
    summary.delivery.all_delivered(),
    "a single-stack host is fully delivered on the one family it has"
  );
}

#[test]
fn a_gated_family_is_missed_and_never_unobligated() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  let summary = settle(&mut health, report(sent(base, 1), SendOutcome::Gated));
  assert_eq!(
    summary.delivery.v6(),
    FamilyDelivery::Missed,
    "the socket is there and the datagram was meant for it; the driver owed \
     the wire a gap it had not paid"
  );
  assert!(
    !summary.delivery.all_delivered(),
    "reporting the deferral absent would let the phase advance without it"
  );
}

#[test]
fn a_send_no_family_could_be_offered_delivers_nothing() {
  let mut health = SendHealth::new();
  let summary = settle(
    &mut health,
    report(SendOutcome::NoSocket, SendOutcome::NoSocket),
  );
  assert!(
    !summary.delivery.any_delivered() && !summary.delivery.all_delivered(),
    "an empty obligated set is never a vacuous all-delivered"
  );
}

// ── family health, and the obligated set it decides ───────────────────

#[test]
fn a_family_stops_holding_lifecycle_back_after_repeated_failures() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  for round in 0..MAX_CONSECUTIVE_SEND_FAILURES {
    let summary = settle(&mut health, report(sent(base, 1), SendOutcome::Failed));
    assert_eq!(
      summary.delivery.v6(),
      if round + 1 < MAX_CONSECUTIVE_SEND_FAILURES {
        FamilyDelivery::Missed
      } else {
        // Health is folded in BEFORE the projection, so the send that trips the
        // degradation is excused by it rather than being one more the core has
        // to wait on.
        FamilyDelivery::Unobligated
      },
      "round {round}"
    );
  }
  assert_eq!(health.degraded_families(), (false, true));
  let summary = settle(&mut health, report(sent(base, 1), SendOutcome::Failed));
  assert!(
    summary.delivery.all_delivered(),
    "a written-off family is one the core must stop waiting for"
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
  assert_eq!(
    summary.delivery.v6(),
    FamilyDelivery::Delivered,
    "a degraded family that put the records on a wire really did deliver them"
  );
  assert_eq!(
    health.degraded_families(),
    (false, false),
    "recovery is immediate and needs no separate edge"
  );
}

#[test]
fn a_delivery_by_a_written_off_family_still_latches_ownership() {
  let base = StdInstant::now();
  let mut health = SendHealth::new();
  // Degrade v4 while v6 stays healthy.
  for _ in 0..MAX_CONSECUTIVE_SEND_FAILURES {
    settle(&mut health, report(SendOutcome::Failed, sent(base, 1)));
  }
  assert_eq!(health.degraded_families(), (true, false));
  let summary = settle(&mut health, report(sent(base, 2), SendOutcome::Failed));
  assert!(
    summary.delivery.any_delivered(),
    "peers reachable over the recovered family now hold these records"
  );
  assert!(
    !summary.delivery.all_delivered(),
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

// ── the per-family wire gate ──────────────────────────────────────────

#[test]
fn a_zero_gap_is_ungated_and_records_nothing() {
  let base = StdInstant::now();
  let mut gate = FamilyWireGate::default();
  assert_eq!(gate.allow(base, Duration::ZERO), [true, true]);
  gate.note(report(sent(base, 0), sent(base, 0)), Duration::ZERO);
  assert_eq!(
    gate.allow(base, Duration::ZERO),
    [true, true],
    "a one-shot §6 reply must not defer the announcement that follows it"
  );
}

#[test]
fn a_family_that_has_carried_nothing_is_open() {
  let base = StdInstant::now();
  let gate = FamilyWireGate::default();
  assert_eq!(gate.allow(base, Duration::from_secs(1)), [true, true]);
}

#[test]
fn each_family_reopens_on_its_own_acceptance_instant() {
  let base = StdInstant::now();
  let gap = Duration::from_secs(1);
  let mut gate = FamilyWireGate::default();
  // v4 accepted at +0, v6 at +3: the inter-family skew the core cannot see.
  gate.note(report(sent(base, 0), sent(base, 3)), gap);
  assert_eq!(
    gate.allow(base + Duration::from_millis(3500), gap),
    [true, false],
    "v4 has paid its second; v6's own second is not up until +4"
  );
  assert_eq!(gate.allow(base + Duration::from_secs(4), gap), [true, true]);
}

#[test]
fn a_family_that_missed_does_not_move_its_gate() {
  let base = StdInstant::now();
  let gap = Duration::from_secs(1);
  let mut gate = FamilyWireGate::default();
  gate.note(report(sent(base, 0), SendOutcome::Failed), gap);
  assert_eq!(
    gate.allow(base, gap),
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
  assert_eq!(gate.allow(mid, gap), [false, false]);
  gate.note(report(SendOutcome::Gated, SendOutcome::Gated), gap);
  assert_eq!(
    gate.allow(base + Duration::from_secs(1), gap),
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
    gate.allow(base - Duration::from_secs(5), gap),
    [false, false],
    "the elapsed gap is unknown, and the conservative answer is the one that \
     cannot put a record back on the wire too soon"
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
  let allow = gate.allow(base, gap);
  assert!(
    !allow[FAMILY_V4] && allow[FAMILY_V6],
    "an index mismatch would gate the wrong wire"
  );
}

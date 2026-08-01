use std::time::{Duration, Instant as StdInstant, SystemTime};

use super::{Credit, MAX_SELF_SEND_ENTRIES, MatchMode, SELF_SEND_TTL, SelfSendTracker, fnv1a};
use crate::socket::Family;

/// A fixed wall instant to build ordering fixtures from. Ordering is all this
/// clock decides now, so every test that is not *about* ordering can leave it
/// alone.
fn wall() -> SystemTime {
  SystemTime::UNIX_EPOCH + Duration::from_secs(10)
}

/// A fixed monotonic instant to build ageing fixtures from.
///
/// `StdInstant` has no constructor and no epoch, so a test that needs one far
/// enough from the process start to subtract from has to take it from the clock
/// and add. Everything below adds; nothing subtracts.
fn mono() -> StdInstant {
  StdInstant::now()
}

/// Record `body` and open its claim window at `at`, which is what one turn of
/// the driver's loop does: the send stage records, and the **next** tick's top
/// seals. Every test whose subject is not the seal itself goes through this, so
/// none of them depends on the unsealed state by accident.
fn recorded_and_sealed(
  t: &mut SelfSendTracker,
  family: Family,
  body: &[u8],
  sent: SystemTime,
  at: StdInstant,
) {
  t.record(family, body, sent);
  t.seal(at);
}

#[test]
fn hash_is_content_addressed() {
  assert_eq!(fnv1a(b"abc"), fnv1a(b"abc"));
  assert_ne!(fnv1a(b"abc"), fnv1a(b"abd"));
}

#[test]
fn take_once_consumes_the_credit() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  let rx = sent + Duration::from_millis(1);
  assert!(t.take_at(Family::V4, b"payload", rx, at, MatchMode::Ordered));
  // Second identical datagram is a genuine peer packet: no credit left.
  assert!(!t.take_at(Family::V4, b"payload", rx, at, MatchMode::Ordered));
}

#[test]
fn ordered_mode_rejects_a_packet_stamped_before_our_send() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  // Kernel stamped this BEFORE we sent -> cannot be our loopback.
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!t.take_at(Family::V4, b"payload", earlier, at, MatchMode::Ordered));
  // The credit must survive for the real loopback copy.
  assert!(t.take_at(
    Family::V4,
    b"payload",
    sent + Duration::from_millis(1),
    at,
    MatchMode::Ordered
  ));
}

#[test]
fn degraded_mode_still_rejects_a_reference_before_the_send() {
  // Degraded does NOT blanket-accept. A read-time reference is always
  // at-or-after the send in practice, so a reference that predates it means the
  // clock moved backwards -- reject, matching hick-compio/hick-reactor.
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!t.take_at(Family::V4, b"payload", earlier, at, MatchMode::Degraded));
  // The credit must survive for the genuine loopback copy.
  assert!(t.take_at(Family::V4, b"payload", sent, at, MatchMode::Degraded));
}

#[test]
fn ordered_mode_tolerates_only_the_timestamp_grain() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  // One nanosecond past the grain is outside the truncation tolerance. This is
  // meaningful on both target classes without a `cfg`: on a nanosecond-grain
  // target (grain == ZERO) it is 1ns before `sent`, landing in the branch
  // Ordered shares with Degraded; on a microsecond-grain target it is 1ns
  // past the 1us tolerance. Either way it must not match, so this exercises
  // the grain comparison itself rather than only ever hitting the trivial
  // at-or-after-send case.
  let just_outside_grain = sent - super::RX_GRAIN_FOR_TEST - Duration::from_nanos(1);
  assert!(!t.take_at(
    Family::V4,
    b"payload",
    just_outside_grain,
    at,
    MatchMode::Ordered
  ));
  // Exactly one grain early is inside the truncation tolerance.
  let within = sent - super::RX_GRAIN_FOR_TEST;
  assert!(t.take_at(Family::V4, b"payload", within, at, MatchMode::Ordered));
  // A full second early is a peer packet the kernel saw before our sendto.
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  let way_early = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!t.take_at(Family::V4, b"payload", way_early, at, MatchMode::Ordered));
}

#[test]
fn a_credit_older_than_the_ttl_is_a_peer_not_our_echo() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  // Byte-identical and correctly ordered, but the credit has been waiting
  // longer than SELF_SEND_TTL -> a co-resident peer, not our echo.
  let late = at + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(!t.take_at(
    Family::V4,
    b"payload",
    sent + Duration::from_secs(3),
    late,
    MatchMode::Degraded
  ));
  // Exactly at the TTL it still matches.
  assert!(t.take_at(
    Family::V4,
    b"payload",
    sent + Duration::from_secs(2),
    at + SELF_SEND_TTL,
    MatchMode::Degraded
  ));
}

#[test]
fn the_ttl_upper_bound_applies_to_ordered_mode_too() {
  // Ordered's pre-send grain tolerance must not loosen the TTL upper bound:
  // every other Ordered-mode test in this file places the reference deep inside
  // the window, so a mutant that dropped the age check for Ordered would pass
  // all of them while swallowing a co-resident peer's byte-identical datagram,
  // hours later, as our own echo.
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  let expired = at + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(!t.take_at(
    Family::V4,
    b"payload",
    sent + Duration::from_secs(3),
    expired,
    MatchMode::Ordered
  ));
  // Inside the window it still matches.
  assert!(t.take_at(
    Family::V4,
    b"payload",
    sent + Duration::from_secs(2),
    at + SELF_SEND_TTL,
    MatchMode::Ordered
  ));
}

// ── where the window starts, and where it does not ──────────────────────────
//
// The invariant these four hold: a credit's ageing must not begin until the
// first instant its echo is claimable — the top of the tick after the recording
// tick — and from then on charges real monotonic elapsed time, including caller
// latency. The first three defend the lower end (nothing inside the recording
// tick may be charged), the fourth defends the upper end (everything after the
// seal must be).

/// The defect class this anchor exists for, in its purest form.
///
/// A credit is recorded and *nothing* about the driver's own tick can expire
/// it — not a syscall that stalled past the TTL before returning, not a later
/// send in the same tick, not the time the outbound stages took. The tracker is
/// handed no send instant at all, so there is no anchor available for that
/// stretch to be charged to. The window opens when the seal opens it.
#[test]
fn an_unsealed_credit_cannot_expire_however_long_the_recording_tick_ran() {
  let mut t = SelfSendTracker::new();
  let sent = wall();
  t.record(Family::V4, b"announcement", sent);
  // Whatever this tick then did — a stalled syscall, a fan-out to the other
  // family, a stage-7 goodbye — it ran well past the TTL.
  let much_later = mono() + SELF_SEND_TTL + Duration::from_secs(5);
  assert_eq!(
    t.len(),
    1,
    "an unsealed credit is live regardless of how much time the recording tick \
     went on to spend"
  );
  // Reached defensively, not by the driver: no send stage precedes the receive
  // stage today, so nothing unsealed is visible to a `take`. It must be live
  // anyway — a credit with no claim opportunity yet has nothing to have
  // outlived.
  assert!(t.take_at(
    Family::V4,
    b"announcement",
    sent + Duration::from_secs(7),
    much_later,
    MatchMode::Degraded
  ));
}

#[test]
fn the_seal_starts_an_unsealed_credit_at_age_zero() {
  let mut t = SelfSendTracker::new();
  let sent = wall();
  t.record(Family::V4, b"announcement", sent);
  // The recording tick ran long. The seal that follows is the credit's first
  // claim opportunity, so its age there is zero and the full TTL is ahead of it.
  let top = mono() + SELF_SEND_TTL + Duration::from_secs(5);
  t.seal(top);
  assert!(
    t.take_at(
      Family::V4,
      b"announcement",
      sent + Duration::from_secs(9),
      top + SELF_SEND_TTL,
      MatchMode::Degraded
    ),
    "a sealed credit gets the whole TTL measured from the seal, not a remainder \
     of it measured from the send"
  );
}

#[test]
fn recording_sweeps_nothing() {
  // The sweep moved to `seal` with the anchor, and this is why: a record-time
  // sweep ages every live credit against whatever instant THIS send reached, so
  // a second fan-out or a stage-7 goodbye later in the same tick could evict a
  // credit whose echo had not yet had one opportunity to claim it.
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"earlier", sent, at);
  t.record(Family::V4, b"later", sent);
  assert_eq!(t.len(), 2, "a record must never evict anything");
  assert!(
    t.take_at(Family::V4, b"earlier", sent, at, MatchMode::Degraded),
    "the earlier credit is untouched by the later record"
  );
}

#[test]
fn sealing_sweeps_entries_older_than_the_ttl() {
  // Eviction is by TTL relative to the tick that is opening a claim window, not
  // by ring position and not by the arrival of another send.
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"stale", sent, at);
  assert_eq!(t.len(), 1);
  t.record(Family::V4, b"fresh", sent);
  let much_later = at + SELF_SEND_TTL + Duration::from_secs(1);
  t.seal(much_later);
  // The stale entry was swept by the seal, not merely outvoted.
  assert_eq!(t.len(), 1);
  assert!(!t.take_at(Family::V4, b"stale", sent, much_later, MatchMode::Degraded));
  assert!(t.take_at(Family::V4, b"fresh", sent, much_later, MatchMode::Degraded));
}

/// The upper end of the invariant, and the reason the seal uses
/// `get_or_insert` rather than an unconditional assignment.
///
/// Post-opportunity time must be charged, caller stalls included: the TTL's
/// other job is bounding FALSE suppression, and a co-resident peer's
/// byte-identical datagram can arrive during a caller stall exactly as it can
/// during a tick. A seal that re-anchored on every tick, or an age counted in
/// ticks rather than in elapsed time, would couple the suppression window to
/// the caller's loop rate and never expire a credit on a slow caller.
///
/// This is also the accepted residual documented on `SELF_SEND_TTL`: a caller
/// that stalls a full TTL between two ticks loses a pending credit. That caller
/// has already broken the once-per-iteration contract, and a gap that size
/// mis-times RFC 6762 probing and §8.3 spacing regardless.
#[test]
fn a_caller_gap_after_the_seal_still_expires_the_credit() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  // The caller went away for longer than the TTL and came back. The credit's
  // window opened at `at` and has now run out.
  let after_the_gap = at + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(
    !t.take_at(
      Family::V4,
      b"payload",
      sent + Duration::from_secs(3),
      after_the_gap,
      MatchMode::Degraded
    ),
    "elapsed time after the first claim opportunity is charged in full, or the \
     false-suppression bound is not a bound at all"
  );
  t.seal(after_the_gap);
  assert_eq!(
    t.len(),
    0,
    "and the seal that observes the gap sweeps it, rather than re-anchoring it \
     forward for another whole TTL"
  );
}

#[test]
fn non_matching_body_is_never_taken() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  assert!(!t.take_at(Family::V4, b"other", sent, at, MatchMode::Degraded));
}

/// The dual-stack echo race, deterministically.
///
/// One multicast transmit is two syscalls with **identical bytes** and two
/// separately-stamped credits. The receive rotor does not fix which socket is
/// read first, so the later IPv6 echo can be read before the earlier IPv4 one.
/// Without the family key the IPv6 echo consumes the older IPv4 credit and the
/// IPv4 echo — stamped by the kernel *before* the surviving IPv6 credit — is
/// rejected by `Ordered` matching and ingested as peer traffic.
#[test]
fn an_ipv6_echo_read_first_cannot_steal_the_ipv4_credit() {
  let mut t = SelfSendTracker::new();
  let v4_sent = wall();
  // Ordered, distinct WALL stamps: the fan-out is two syscalls, IPv4 first, and
  // ordering is the only thing that still distinguishes them. Both credits are
  // recorded in one tick and share the next tick's seal, so neither ages ahead
  // of the other.
  let v6_sent = v4_sent + Duration::from_millis(5);
  t.record(Family::V4, b"announcement", v4_sent);
  t.record(Family::V6, b"announcement", v6_sent);
  let top = mono();
  t.seal(top);

  // The rotor reads IPv6 first. Its kernel stamp is at-or-after the IPv6 send
  // but AFTER the IPv4 send too, so both credits look eligible on content.
  let v6_rx = v6_sent + Duration::from_micros(50);
  assert!(t.take_at(Family::V6, b"announcement", v6_rx, top, MatchMode::Ordered));

  // The IPv4 echo now arrives, stamped between the two sends — before the IPv6
  // credit. It matches only because its own credit is still there.
  let v4_rx = v4_sent + Duration::from_micros(50);
  assert!(
    t.take_at(Family::V4, b"announcement", v4_rx, top, MatchMode::Ordered),
    "the IPv4 echo must find its own credit, not one already spent by IPv6"
  );
  assert_eq!(t.len(), 0, "both credits are spent exactly once");
}

/// The family key is a filter, not a tiebreak: a credit recorded for one family
/// is never available to the other, so a peer datagram arriving on the family
/// we did not send on is still seen as a peer.
#[test]
fn a_credit_is_not_visible_to_the_other_family() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent, at);
  let rx = sent + Duration::from_millis(1);
  assert!(!t.take_at(Family::V6, b"payload", rx, at, MatchMode::Ordered));
  assert!(t.take_at(Family::V4, b"payload", rx, at, MatchMode::Ordered));
}

#[test]
fn a_backwards_wall_clock_step_cannot_evict_or_expire_a_credit() {
  // Ageing is monotonic, so a wall clock that steps backwards between two sends
  // — an NTP correction, a manual `settimeofday` — can neither sweep a live
  // credit on `seal` nor expire one on `take`. The wall stamp still has a job
  // (ordering the echo against the send), which is why the step is visible at
  // all; it just no longer decides anyone's lifetime. Losing a credit is worse
  // than over-retaining one: it makes the responder treat its own loopback as a
  // peer and raise a phantom conflict against itself.
  let mut t = SelfSendTracker::new();
  let later = SystemTime::UNIX_EPOCH + Duration::from_secs(20);
  let first_at = mono();
  recorded_and_sealed(&mut t, Family::V4, b"already-recorded", later, first_at);
  // The clock stepped backwards: this send's WALL stamp predates the entry
  // above by ten seconds, while the seal that follows it is a millisecond after.
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  let second_at = first_at + Duration::from_millis(1);
  recorded_and_sealed(
    &mut t,
    Family::V4,
    b"clock-stepped-back",
    earlier,
    second_at,
  );
  assert_eq!(t.len(), 2, "a wall-clock step must not sweep a live credit");
  assert!(t.take_at(
    Family::V4,
    b"already-recorded",
    later,
    second_at,
    MatchMode::Degraded
  ));
}

/// A credit matches only the body it fingerprints: the tracker is a content
/// hash, so a byte-different datagram must not consume another's credit.
#[test]
fn a_credit_matches_only_the_body_it_fingerprints() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  recorded_and_sealed(&mut t, Family::V6, b"announcement", sent, at);
  assert!(!t.take_at(Family::V6, b"other", sent, at, MatchMode::Degraded));
  assert!(t.take_at(Family::V6, b"announcement", sent, at, MatchMode::Degraded));
}

/// A stall longer than [`SELF_SEND_TTL`], slept for real.
///
/// `record` reads the monotonic clock itself — that is the whole point of the
/// reclaim being live rather than anchored on anything the send carries — so the
/// two cap tests below cannot fake the elapsed time, and `StdInstant` offers no
/// constructor to fake it with. Same value and same reason as
/// `driver/tests.rs`'s `STALL_PAST_TTL`.
const STALL_PAST_TTL: Duration = SELF_SEND_TTL.saturating_add(Duration::from_millis(50));

/// Seed a FULL tracker directly, every entry anchored at `aged_from`.
///
/// Straight into the private `entries` field (visible here: `tests` is a child
/// module of `selfsend`) instead of looping `record()`
/// `MAX_SELF_SEND_ENTRIES` times, so each fixture states the shape it wants
/// rather than arriving at it, and only the single `record()` call under test
/// exercises the cap logic.
fn full_tracker(sent: SystemTime, aged_from: Option<StdInstant>) -> SelfSendTracker {
  SelfSendTracker {
    entries: (0..MAX_SELF_SEND_ENTRIES)
      .map(|i| Credit {
        family: Family::V4,
        hash: fnv1a(&(i as u64).to_be_bytes()),
        sent,
        aged_from,
      })
      .collect(),
  }
}

/// The cap counts credits that are still ALIVE, not corpses.
///
/// An expired sealed entry is removed by nothing but the next `seal`: `take`
/// refuses it and leaves it resident. So a tracker filled and sealed, whose tick
/// then stalls past the TTL, is `MAX_SELF_SEND_ENTRIES` dead credits — and a
/// send later in that same tick would be refused its credit by entries not one
/// of which could ever match anything again. Its genuine loopback then arrives
/// with nothing to claim, is ingested as peer traffic, and the responder raises
/// a phantom conflict against itself.
#[test]
fn the_cap_reclaims_dead_credits_rather_than_refusing_a_new_one() {
  let sent = wall();
  let mut t = full_tracker(sent, Some(mono()));
  // The tick ran on past the TTL after the seal that anchored every one of them.
  std::thread::sleep(STALL_PAST_TTL);
  t.record(Family::V4, b"later-in-the-same-tick", sent);
  assert_eq!(
    t.len(),
    1,
    "every entry was sealed and expired, so the cap had nothing live to protect"
  );
  // And the new credit behaves like any other: sealed at the next tick's top,
  // then claimed by its own echo.
  let top = StdInstant::now();
  t.seal(top);
  assert!(
    t.take_at(
      Family::V4,
      b"later-in-the-same-tick",
      sent,
      top,
      MatchMode::Degraded
    ),
    "a tracker full of dead credits must not crowd out a live send's echo \
     suppression"
  );
}

/// The half of the old record-time sweep that must never come back.
///
/// Every entry here is UNSEALED, so however long this tick has been running not
/// one of their echoes has had a single opportunity to claim them. The cap path
/// may not reclaim any of them — it drops the NEW entry instead, which is the
/// cheap direction: one datagram of ours ingested as a peer's, against
/// `MAX_SELF_SEND_ENTRIES` of them.
#[test]
fn the_cap_never_reclaims_an_unsealed_credit() {
  let sent = wall();
  let mut t = full_tracker(sent, None);
  // Long enough that ageing these against the live clock would evict every one.
  std::thread::sleep(STALL_PAST_TTL);
  t.record(Family::V4, b"one-too-many", sent);
  assert_eq!(
    t.len(),
    MAX_SELF_SEND_ENTRIES,
    "an unsealed credit has no window open and no age; elapsed time cannot \
     reclaim it, so the cap is still full and the NEW entry is what goes"
  );
  let now = StdInstant::now();
  assert!(!t.take_at(Family::V4, b"one-too-many", sent, now, MatchMode::Degraded));
  assert!(
    t.take_at(
      Family::V4,
      &0u64.to_be_bytes(),
      sent,
      now,
      MatchMode::Degraded
    ),
    "and the first-seeded credit is still there: the cap never evicts to make \
     room"
  );
}

#[test]
fn the_entry_cap_drops_the_new_entry_not_the_oldest() {
  let (sent, at) = (wall(), mono());
  // Full of credits that are sealed and still well inside their TTL: the
  // reclaim finds nothing to take, so this is the cap rule on its own.
  let mut t = full_tracker(sent, Some(at));
  assert_eq!(t.len(), MAX_SELF_SEND_ENTRIES);
  t.record(Family::V4, b"one-too-many", sent);
  // One more record() leaves len() at the cap: the new entry was dropped.
  assert_eq!(
    t.len(),
    MAX_SELF_SEND_ENTRIES,
    "the cap drops the NEW entry"
  );
  assert!(!t.take_at(Family::V4, b"one-too-many", sent, at, MatchMode::Degraded));
  // The first-seeded entry is still present — the oldest is NOT evicted.
  assert!(t.take_at(
    Family::V4,
    &0u64.to_be_bytes(),
    sent,
    at,
    MatchMode::Degraded
  ));
}

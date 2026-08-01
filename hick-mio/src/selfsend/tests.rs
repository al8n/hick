use std::time::{Duration, SystemTime};

use super::{Credit, MAX_SELF_SEND_ENTRIES, MatchMode, SELF_SEND_TTL, SelfSendTracker, fnv1a};
use crate::socket::Family;

#[test]
fn hash_is_content_addressed() {
  assert_eq!(fnv1a(b"abc"), fnv1a(b"abc"));
  assert_ne!(fnv1a(b"abc"), fnv1a(b"abd"));
}

#[test]
fn take_once_consumes_the_credit() {
  let mut t = SelfSendTracker::new();
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"payload", sent);
  let rx = sent + Duration::from_millis(1);
  assert!(t.take(Family::V4, b"payload", rx, MatchMode::Ordered));
  // Second identical datagram is a genuine peer packet: no credit left.
  assert!(!t.take(Family::V4, b"payload", rx, MatchMode::Ordered));
}

#[test]
fn ordered_mode_rejects_a_packet_stamped_before_our_send() {
  let mut t = SelfSendTracker::new();
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"payload", sent);
  // Kernel stamped this BEFORE we sent -> cannot be our loopback.
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!t.take(Family::V4, b"payload", earlier, MatchMode::Ordered));
  // The credit must survive for the real loopback copy.
  assert!(t.take(
    Family::V4,
    b"payload",
    sent + Duration::from_millis(1),
    MatchMode::Ordered
  ));
}

#[test]
fn degraded_mode_still_rejects_a_reference_before_the_send() {
  // Degraded does NOT blanket-accept. A read-time reference is always
  // at-or-after the send in practice, so a reference that predates it means the
  // clock moved backwards — reject, matching hick-compio/hick-reactor.
  let mut t = SelfSendTracker::new();
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"payload", sent);
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!t.take(Family::V4, b"payload", earlier, MatchMode::Degraded));
  // The credit must survive for the genuine loopback copy.
  assert!(t.take(Family::V4, b"payload", sent, MatchMode::Degraded));
}

#[test]
fn ordered_mode_tolerates_only_the_timestamp_grain() {
  let mut t = SelfSendTracker::new();
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"payload", sent);
  // One nanosecond past the grain is outside the truncation tolerance. This is
  // meaningful on both target classes without a `cfg`: on a nanosecond-grain
  // target (grain == ZERO) it is 1ns before `sent`, landing in the branch
  // Ordered shares with Degraded; on a microsecond-grain target it is 1ns
  // past the 1us tolerance. Either way it must not match, so this exercises
  // the grain comparison itself rather than only ever hitting the trivial
  // at-or-after-send case.
  let just_outside_grain = sent - super::RX_GRAIN_FOR_TEST - Duration::from_nanos(1);
  assert!(!t.take(
    Family::V4,
    b"payload",
    just_outside_grain,
    MatchMode::Ordered
  ));
  // Exactly one grain early is inside the truncation tolerance.
  let within = sent - super::RX_GRAIN_FOR_TEST;
  assert!(t.take(Family::V4, b"payload", within, MatchMode::Ordered));
  // A full second early is a peer packet the kernel saw before our sendto.
  t.record(Family::V4, b"payload", sent);
  let way_early = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!t.take(Family::V4, b"payload", way_early, MatchMode::Ordered));
}

#[test]
fn a_match_past_the_ttl_is_a_peer_not_our_echo() {
  let mut t = SelfSendTracker::new();
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"payload", sent);
  // Byte-identical, but well past SELF_SEND_TTL -> a co-resident peer.
  let late = sent + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(!t.take(Family::V4, b"payload", late, MatchMode::Degraded));
  // Inside the window it still matches.
  let inside = sent + SELF_SEND_TTL;
  assert!(t.take(Family::V4, b"payload", inside, MatchMode::Degraded));
}

#[test]
fn the_ttl_upper_bound_applies_to_ordered_mode_too() {
  // Ordered's pre-send grain tolerance must not loosen the TTL upper bound:
  // every other Ordered-mode test in this file only ever places the
  // reference deep inside the TTL window (e.g. 1ms after `sent`), so a
  // mutant that made the at-or-after-send arm unconditionally accept for
  // Ordered (`mode == MatchMode::Ordered || ahead <= SELF_SEND_TTL`) would
  // pass all of them while swallowing a co-resident peer's byte-identical
  // datagram, hours later, as our own echo.
  let mut t = SelfSendTracker::new();
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"payload", sent);
  let late = sent + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(!t.take(Family::V4, b"payload", late, MatchMode::Ordered));
  // Inside the window it still matches.
  assert!(t.take(
    Family::V4,
    b"payload",
    sent + SELF_SEND_TTL,
    MatchMode::Ordered
  ));
}

#[test]
fn non_matching_body_is_never_taken() {
  let mut t = SelfSendTracker::new();
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"payload", sent);
  assert!(!t.take(Family::V4, b"other", sent, MatchMode::Degraded));
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
  let v4_sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  // Ordered, distinct stamps: the fan-out is two syscalls, IPv4 first.
  let v6_sent = v4_sent + Duration::from_millis(5);
  t.record(Family::V4, b"announcement", v4_sent);
  t.record(Family::V6, b"announcement", v6_sent);

  // The rotor reads IPv6 first. Its kernel stamp is at-or-after the IPv6 send
  // but AFTER the IPv4 send too, so both credits look eligible on content.
  let v6_rx = v6_sent + Duration::from_micros(50);
  assert!(t.take(Family::V6, b"announcement", v6_rx, MatchMode::Ordered));

  // The IPv4 echo now arrives, stamped between the two sends — before the IPv6
  // credit. It matches only because its own credit is still there.
  let v4_rx = v4_sent + Duration::from_micros(50);
  assert!(
    t.take(Family::V4, b"announcement", v4_rx, MatchMode::Ordered),
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
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"payload", sent);
  let rx = sent + Duration::from_millis(1);
  assert!(!t.take(Family::V6, b"payload", rx, MatchMode::Ordered));
  assert!(t.take(Family::V4, b"payload", rx, MatchMode::Ordered));
}

#[test]
fn recording_sweeps_entries_older_than_the_ttl() {
  // Eviction is by TTL relative to the incoming send, not by ring position.
  let mut t = SelfSendTracker::new();
  let old = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"stale", old);
  assert_eq!(t.len(), 1);
  let much_later = old + SELF_SEND_TTL + Duration::from_secs(1);
  t.record(Family::V4, b"fresh", much_later);
  // The stale entry was swept by the second record, not merely outvoted.
  assert_eq!(t.len(), 1);
  assert!(!t.take(Family::V4, b"stale", much_later, MatchMode::Degraded));
  assert!(t.take(Family::V4, b"fresh", much_later, MatchMode::Degraded));
}

#[test]
fn a_backwards_clock_step_does_not_evict_the_newer_entry() {
  // record()'s sweep predicate keeps (rather than evicts) an existing entry
  // whose recorded time is AFTER the incoming `sent` -- that's the
  // `duration_since` `Err(_) => true` arm, which only executes when the
  // wall clock has stepped backwards between two sends. Every other fixture
  // in this file builds monotonically non-decreasing timestamps, so nothing
  // else would fail if this arm were flipped to evict instead (as
  // hick-compio's sibling implementation does). Pinned here because losing
  // the credit is worse than over-retaining one a clock jump made
  // unmatchable: it would make the responder treat its own loopback as a
  // peer and raise a phantom conflict against itself.
  let mut t = SelfSendTracker::new();
  let later = SystemTime::UNIX_EPOCH + Duration::from_secs(20);
  t.record(Family::V4, b"already-recorded", later);
  // The clock stepped backwards: this send predates the entry above, so its
  // sweep predicate hits the Err(_) => true arm for that entry.
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V4, b"clock-stepped-back", earlier);
  assert_eq!(t.len(), 2);
  assert!(t.take(Family::V4, b"already-recorded", later, MatchMode::Degraded));
}

/// A credit matches only the body it fingerprints: the tracker is a content
/// hash, so a byte-different datagram must not consume another's credit.
#[test]
fn a_credit_matches_only_the_body_it_fingerprints() {
  let mut t = SelfSendTracker::new();
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  t.record(Family::V6, b"announcement", sent);
  assert!(!t.take(Family::V6, b"other", sent, MatchMode::Degraded));
  assert!(t.take(Family::V6, b"announcement", sent, MatchMode::Degraded));
}

#[test]
fn the_entry_cap_drops_the_new_entry_not_the_oldest() {
  let sent = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  // Seed straight into the private `entries` field (visible here: `tests` is
  // a child module of `selfsend`) instead of looping `record()`
  // MAX_SELF_SEND_ENTRIES times. `record`'s per-call `retain` sweep is O(n),
  // so a loop of MAX_SELF_SEND_ENTRIES calls is O(n^2) and was ~31s of pure
  // fixture setup; direct seeding is O(n). It is behaviourally identical
  // here because every entry shares one `sent` instant, so `record`'s sweep
  // would never have evicted anything during the fill either way — only the
  // cap logic exercised by the single `record()` call below is under test.
  let mut t = SelfSendTracker {
    entries: (0..MAX_SELF_SEND_ENTRIES)
      .map(|i| Credit {
        family: Family::V4,
        hash: fnv1a(&(i as u64).to_be_bytes()),
        sent,
      })
      .collect(),
  };
  assert_eq!(t.len(), MAX_SELF_SEND_ENTRIES);
  t.record(Family::V4, b"one-too-many", sent);
  // One more record() leaves len() at the cap: the new entry was dropped.
  assert_eq!(
    t.len(),
    MAX_SELF_SEND_ENTRIES,
    "the cap drops the NEW entry"
  );
  assert!(!t.take(Family::V4, b"one-too-many", sent, MatchMode::Degraded));
  // The first-seeded entry is still present — the oldest is NOT evicted.
  assert!(t.take(Family::V4, &0u64.to_be_bytes(), sent, MatchMode::Degraded));
}

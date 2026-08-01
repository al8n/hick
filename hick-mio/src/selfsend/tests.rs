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

#[test]
fn hash_is_content_addressed() {
  assert_eq!(fnv1a(b"abc"), fnv1a(b"abc"));
  assert_ne!(fnv1a(b"abc"), fnv1a(b"abd"));
}

#[test]
fn take_once_consumes_the_credit() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  t.record(Family::V4, b"payload", sent, at);
  let rx = sent + Duration::from_millis(1);
  assert!(t.take(Family::V4, b"payload", rx, at, MatchMode::Ordered));
  // Second identical datagram is a genuine peer packet: no credit left.
  assert!(!t.take(Family::V4, b"payload", rx, at, MatchMode::Ordered));
}

#[test]
fn ordered_mode_rejects_a_packet_stamped_before_our_send() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  t.record(Family::V4, b"payload", sent, at);
  // Kernel stamped this BEFORE we sent -> cannot be our loopback.
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!t.take(Family::V4, b"payload", earlier, at, MatchMode::Ordered));
  // The credit must survive for the real loopback copy.
  assert!(t.take(
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
  t.record(Family::V4, b"payload", sent, at);
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!t.take(Family::V4, b"payload", earlier, at, MatchMode::Degraded));
  // The credit must survive for the genuine loopback copy.
  assert!(t.take(Family::V4, b"payload", sent, at, MatchMode::Degraded));
}

#[test]
fn ordered_mode_tolerates_only_the_timestamp_grain() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  t.record(Family::V4, b"payload", sent, at);
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
    at,
    MatchMode::Ordered
  ));
  // Exactly one grain early is inside the truncation tolerance.
  let within = sent - super::RX_GRAIN_FOR_TEST;
  assert!(t.take(Family::V4, b"payload", within, at, MatchMode::Ordered));
  // A full second early is a peer packet the kernel saw before our sendto.
  t.record(Family::V4, b"payload", sent, at);
  let way_early = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!t.take(Family::V4, b"payload", way_early, at, MatchMode::Ordered));
}

#[test]
fn a_credit_older_than_the_ttl_is_a_peer_not_our_echo() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  t.record(Family::V4, b"payload", sent, at);
  // Byte-identical and correctly ordered, but the credit has been waiting
  // longer than SELF_SEND_TTL -> a co-resident peer, not our echo.
  let late = at + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(!t.take(
    Family::V4,
    b"payload",
    sent + Duration::from_secs(3),
    late,
    MatchMode::Degraded
  ));
  // Exactly at the TTL it still matches.
  assert!(t.take(
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
  t.record(Family::V4, b"payload", sent, at);
  let expired = at + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(!t.take(
    Family::V4,
    b"payload",
    sent + Duration::from_secs(3),
    expired,
    MatchMode::Ordered
  ));
  // Inside the window it still matches.
  assert!(t.take(
    Family::V4,
    b"payload",
    sent + Duration::from_secs(2),
    at + SELF_SEND_TTL,
    MatchMode::Ordered
  ));
}

/// The defect this two-clock split exists for.
///
/// Nothing bounds the gap between a send's pre-syscall wall stamp and the
/// syscall that follows it: a preempted thread, a signal handler, or a page
/// fault can stretch it past `SELF_SEND_TTL`. When that stamp was also the
/// credit's age, the echo of a stalled send fell outside the window and the
/// endpoint ingested its own announcement as peer traffic -- a phantom conflict
/// against itself and the RFC 6762 §9 rename that follows.
///
/// Here the send is submitted at `sent`, stalls for well past the TTL, and only
/// then reaches the kernel. The echo comes back promptly afterwards. Ageing from
/// the post-syscall instant keeps the credit live; ageing from the wall stamp
/// would have expired it before the datagram was even on the wire.
#[test]
fn a_send_stalled_past_the_ttl_still_suppresses_its_own_echo() {
  let mut t = SelfSendTracker::new();
  let submitted_wall = wall();
  let stall = SELF_SEND_TTL + Duration::from_secs(1);
  // The syscall succeeded `stall` after the pre-syscall stamps were read.
  let accepted_at = mono() + stall;
  t.record(Family::V4, b"announcement", submitted_wall, accepted_at);

  // The kernel loops the copy back a millisecond later, stamping it with the
  // wall clock -- which by now reads `stall` past `submitted_wall`.
  let echo_rx = submitted_wall + stall + Duration::from_millis(1);
  let echo_at = accepted_at + Duration::from_millis(1);
  assert!(
    t.take(
      Family::V4,
      b"announcement",
      echo_rx,
      echo_at,
      MatchMode::Ordered
    ),
    "a credit must age from the syscall that succeeded, not from a pre-syscall \
     stamp an unbounded stall may precede"
  );
}

#[test]
fn non_matching_body_is_never_taken() {
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  t.record(Family::V4, b"payload", sent, at);
  assert!(!t.take(Family::V4, b"other", sent, at, MatchMode::Degraded));
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
  let v4_at = mono();
  // Ordered, distinct stamps: the fan-out is two syscalls, IPv4 first.
  let v6_sent = v4_sent + Duration::from_millis(5);
  let v6_at = v4_at + Duration::from_millis(5);
  t.record(Family::V4, b"announcement", v4_sent, v4_at);
  t.record(Family::V6, b"announcement", v6_sent, v6_at);

  // The rotor reads IPv6 first. Its kernel stamp is at-or-after the IPv6 send
  // but AFTER the IPv4 send too, so both credits look eligible on content.
  let v6_rx = v6_sent + Duration::from_micros(50);
  assert!(t.take(
    Family::V6,
    b"announcement",
    v6_rx,
    v6_at,
    MatchMode::Ordered
  ));

  // The IPv4 echo now arrives, stamped between the two sends — before the IPv6
  // credit. It matches only because its own credit is still there.
  let v4_rx = v4_sent + Duration::from_micros(50);
  assert!(
    t.take(
      Family::V4,
      b"announcement",
      v4_rx,
      v6_at,
      MatchMode::Ordered
    ),
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
  t.record(Family::V4, b"payload", sent, at);
  let rx = sent + Duration::from_millis(1);
  assert!(!t.take(Family::V6, b"payload", rx, at, MatchMode::Ordered));
  assert!(t.take(Family::V4, b"payload", rx, at, MatchMode::Ordered));
}

#[test]
fn recording_sweeps_entries_older_than_the_ttl() {
  // Eviction is by TTL relative to the incoming send, not by ring position.
  let mut t = SelfSendTracker::new();
  let (sent, at) = (wall(), mono());
  t.record(Family::V4, b"stale", sent, at);
  assert_eq!(t.len(), 1);
  let much_later = at + SELF_SEND_TTL + Duration::from_secs(1);
  t.record(Family::V4, b"fresh", sent, much_later);
  // The stale entry was swept by the second record, not merely outvoted.
  assert_eq!(t.len(), 1);
  assert!(!t.take(Family::V4, b"stale", sent, much_later, MatchMode::Degraded));
  assert!(t.take(Family::V4, b"fresh", sent, much_later, MatchMode::Degraded));
}

#[test]
fn a_backwards_wall_clock_step_cannot_evict_or_expire_a_credit() {
  // Ageing is monotonic, so a wall clock that steps backwards between two sends
  // — an NTP correction, a manual `settimeofday` — can neither sweep a live
  // credit on `record` nor expire one on `take`. The wall stamp still has a job
  // (ordering the echo against the send), which is why the step is visible at
  // all; it just no longer decides anyone's lifetime. Losing a credit is worse
  // than over-retaining one: it makes the responder treat its own loopback as a
  // peer and raise a phantom conflict against itself.
  let mut t = SelfSendTracker::new();
  let later = SystemTime::UNIX_EPOCH + Duration::from_secs(20);
  let first_at = mono();
  t.record(Family::V4, b"already-recorded", later, first_at);
  // The clock stepped backwards: this send's WALL stamp predates the entry
  // above by ten seconds, while its monotonic stamp is a millisecond after it.
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
  let second_at = first_at + Duration::from_millis(1);
  t.record(Family::V4, b"clock-stepped-back", earlier, second_at);
  assert_eq!(t.len(), 2, "a wall-clock step must not sweep a live credit");
  assert!(t.take(
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
  t.record(Family::V6, b"announcement", sent, at);
  assert!(!t.take(Family::V6, b"other", sent, at, MatchMode::Degraded));
  assert!(t.take(Family::V6, b"announcement", sent, at, MatchMode::Degraded));
}

#[test]
fn the_entry_cap_drops_the_new_entry_not_the_oldest() {
  let (sent, at) = (wall(), mono());
  // Seed straight into the private `entries` field (visible here: `tests` is
  // a child module of `selfsend`) instead of looping `record()`
  // MAX_SELF_SEND_ENTRIES times. `record`'s per-call `retain` sweep is O(n),
  // so a loop of MAX_SELF_SEND_ENTRIES calls is O(n^2) and was ~31s of pure
  // fixture setup; direct seeding is O(n). It is behaviourally identical
  // here because every entry shares one instant, so `record`'s sweep would
  // never have evicted anything during the fill either way — only the cap
  // logic exercised by the single `record()` call below is under test.
  let mut t = SelfSendTracker {
    entries: (0..MAX_SELF_SEND_ENTRIES)
      .map(|i| Credit {
        family: Family::V4,
        hash: fnv1a(&(i as u64).to_be_bytes()),
        sent,
        aged_from: at,
      })
      .collect(),
  };
  assert_eq!(t.len(), MAX_SELF_SEND_ENTRIES);
  t.record(Family::V4, b"one-too-many", sent, at);
  // One more record() leaves len() at the cap: the new entry was dropped.
  assert_eq!(
    t.len(),
    MAX_SELF_SEND_ENTRIES,
    "the cap drops the NEW entry"
  );
  assert!(!t.take(Family::V4, b"one-too-many", sent, at, MatchMode::Degraded));
  // The first-seeded entry is still present — the oldest is NOT evicted.
  assert!(t.take(
    Family::V4,
    &0u64.to_be_bytes(),
    sent,
    at,
    MatchMode::Degraded
  ));
}

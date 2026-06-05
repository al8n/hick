use super::*;

#[test]
fn record_then_take_in_degraded_mode_matches_once() {
  let mut t = Vec::new();
  let now = SystemTime::now();
  record_self_send(&mut t, b"hello", now);
  assert!(take_self_send(
    &mut t,
    b"hello",
    now + Duration::from_millis(1),
    MatchMode::Degraded
  ));
  assert!(!take_self_send(
    &mut t,
    b"hello",
    now + Duration::from_millis(2),
    MatchMode::Degraded
  ));
}

#[test]
fn ordered_pre_send_slack_admits_1ms_back() {
  let mut t = Vec::new();
  let now = SystemTime::now();
  record_self_send(&mut t, b"x", now);
  // reference 1ms BEFORE sent: Ordered mode admits (within 1ms slack)
  assert!(take_self_send(
    &mut t,
    b"x",
    now - Duration::from_millis(1),
    MatchMode::Ordered
  ));
}

#[test]
fn ordered_pre_send_slack_rejects_2ms_back() {
  let mut t = Vec::new();
  let now = SystemTime::now();
  record_self_send(&mut t, b"x", now);
  assert!(!take_self_send(
    &mut t,
    b"x",
    now - Duration::from_millis(2),
    MatchMode::Ordered
  ));
}

#[test]
fn degraded_mode_rejects_negative_skew() {
  let mut t = Vec::new();
  let now = SystemTime::now();
  record_self_send(&mut t, b"x", now);
  // Degraded mode does NOT allow reference < sent
  assert!(!take_self_send(
    &mut t,
    b"x",
    now - Duration::from_millis(1),
    MatchMode::Degraded
  ));
}

#[test]
fn ttl_sweeps_old_entries_on_record() {
  let mut t = Vec::new();
  let t0 = SystemTime::now();
  record_self_send(&mut t, b"old", t0);
  // record a fresh entry well past TTL — old entry should be swept
  let later = t0 + SELF_SEND_TTL + Duration::from_millis(1);
  record_self_send(&mut t, b"new", later);
  assert_eq!(t.len(), 1);
  assert!(!take_self_send(&mut t, b"old", later, MatchMode::Degraded));
  assert!(take_self_send(&mut t, b"new", later, MatchMode::Degraded));
}

#[test]
fn distinct_bodies_have_distinct_hashes() {
  let mut t = Vec::new();
  let now = SystemTime::now();
  record_self_send(&mut t, b"alpha", now);
  record_self_send(&mut t, b"beta", now);
  assert_eq!(t.len(), 2);
  assert!(take_self_send(&mut t, b"alpha", now, MatchMode::Degraded));
  assert!(take_self_send(&mut t, b"beta", now, MatchMode::Degraded));
}

#[test]
fn length_mismatch_blocks_hash_only_match() {
  let now = SystemTime::now();
  // A synthetic entry carrying body "hello"'s hash but a WRONG length:
  let mut t = vec![(fnv1a(b"hello"), 999u32, now)];
  // Same hash, but the real body length (5) != stored 999 → must NOT match.
  assert!(!take_self_send(&mut t, b"hello", now, MatchMode::Degraded));
  // Sanity: a correctly-recorded entry still matches.
  let mut t2 = Vec::new();
  record_self_send(&mut t2, b"hello", now);
  assert!(take_self_send(&mut t2, b"hello", now, MatchMode::Degraded));
}

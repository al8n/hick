//! FNV-1a self-send hash tracker (Ordered + Degraded match modes).
//!
//! Used by the driver to consume the loopback echo of multicast datagrams
//! the endpoint just sent — so the proto state machine doesn't ingest its
//! own announce/probe traffic as if it were an external peer.

use std::time::{Duration, SystemTime};

/// Self-send tracker storage: `(content_hash, body_len, send_wall_time)` for
/// every datagram the endpoint recently transmitted.  Keying on
/// `(hash, length)` rather than the FNV-1a hash alone means a hash collision
/// cannot, by itself, consume a self-send credit or misclassify a peer
/// datagram as our own loopback echo.
pub(crate) type SelfSends = Vec<(u64, u32, SystemTime)>;

/// Maximum age of a tracker entry before it is swept on the next
/// `record_self_send` call.
pub(crate) const SELF_SEND_TTL: Duration = Duration::from_secs(2);

/// Soft cap on the self-send tracker.  Mirrors `hick-reactor::driver`'s
/// constant; an oversized tracker silently drops new records rather than
/// growing without bound on a misbehaving loopback path.
pub(crate) const MAX_SELF_SEND_ENTRIES: usize = 65536;

/// Match mode for [`take_self_send`].
///
/// - `Ordered`: the reference timestamp may sit up to 1 ms *before* the
///   recorded send time — accounts for kernel timestamping that captures the
///   rx clock at a slightly earlier reading than the post-send wall clock.
/// - `Degraded`: no pre-send slack; the reference must be at or after the
///   recorded send time.  Used when the kernel did not deliver a rx
///   timestamp and the driver falls back to `SystemTime::now()`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MatchMode {
  Ordered,
  Degraded,
}

/// Record a freshly transmitted datagram in the self-send tracker.  Sweeps
/// any entries past [`SELF_SEND_TTL`] first, then pushes a new entry iff the
/// tracker is below [`MAX_SELF_SEND_ENTRIES`].  Each entry keys on both the
/// FNV-1a hash and the body length, so a hash collision alone can't consume a
/// credit.
pub(crate) fn record_self_send(tracker: &mut SelfSends, body: &[u8], sent: SystemTime) {
  tracker.retain(|(_, _, t)| {
    sent
      .duration_since(*t)
      .is_ok_and(|age| age <= SELF_SEND_TTL)
  });
  if tracker.len() < MAX_SELF_SEND_ENTRIES {
    tracker.push((fnv1a(body), body.len() as u32, sent));
  }
}

/// Consume one tracker entry whose FNV-1a hash *and* length of `body` match
/// and whose recorded send time falls inside the match window for `mode`.
/// Returns `true` when an entry was consumed (i.e. the datagram is our own
/// loopback echo and the caller should pass `caller_is_self = true` into
/// `endpoint.handle`).  Requiring the body length to match as well as the hash
/// means a lossy FNV-1a collision alone cannot misclassify a peer datagram as
/// self.
pub(crate) fn take_self_send(
  tracker: &mut SelfSends,
  body: &[u8],
  reference: SystemTime,
  mode: MatchMode,
) -> bool {
  let needle = fnv1a(body);
  let needle_len = body.len() as u32;
  if let Some(pos) = tracker.iter().position(|(h, len, sent)| {
    *h == needle && *len == needle_len && matches(reference, *sent, mode)
  }) {
    tracker.remove(pos);
    true
  } else {
    false
  }
}

/// Whether a reference timestamp falls inside the match window for `mode`
/// around a recorded `sent` time.
fn matches(reference: SystemTime, sent: SystemTime, mode: MatchMode) -> bool {
  match reference.duration_since(sent) {
    Ok(ahead) => ahead <= SELF_SEND_TTL,
    Err(behind) => mode == MatchMode::Ordered && behind.duration() <= Duration::from_millis(1),
  }
}

/// FNV-1a 64-bit content hash.
fn fnv1a(data: &[u8]) -> u64 {
  const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
  const PRIME: u64 = 0x0000_0100_0000_01b3;
  let mut h = OFFSET;
  for &b in data {
    h ^= u64::from(b);
    h = h.wrapping_mul(PRIME);
  }
  h
}

#[cfg(test)]
mod tests {
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
}

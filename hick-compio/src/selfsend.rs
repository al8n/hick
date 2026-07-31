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
  record_self_send_hashed(tracker, credit_of(body), sent);
}

/// The `(hash, length)` credit key for a datagram, computed up front so a send
/// whose completion is observed later does not have to keep the body alive to
/// record it. The tracker never stores the bytes themselves — only this key and
/// the send time — so nothing is lost by hashing early.
pub(crate) fn credit_of(body: &[u8]) -> (u64, u32) {
  (fnv1a(body), body.len() as u32)
}

/// [`record_self_send`] for a credit key already computed by [`credit_of`].
pub(crate) fn record_self_send_hashed(
  tracker: &mut SelfSends,
  credit: (u64, u32),
  sent: SystemTime,
) {
  tracker.retain(|(_, _, t)| {
    sent
      .duration_since(*t)
      .is_ok_and(|age| age <= SELF_SEND_TTL)
  });
  if tracker.len() < MAX_SELF_SEND_ENTRIES {
    tracker.push((credit.0, credit.1, sent));
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
mod tests;

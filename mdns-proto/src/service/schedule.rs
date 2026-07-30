//! Computes deadlines for the probe → announce → re-announce sequence.

use core::time::Duration;

use rand_core::Rng;

use crate::Instant;

/// Pre-computed timing constants from RFC 6762.
pub(crate) mod rfc {
  use super::Duration;
  /// Maximum initial-probe random wait (RFC §8.1).
  #[allow(dead_code)]
  pub const INITIAL_PROBE_WAIT_MAX_MS: u32 = 250;
  /// Inter-probe interval (RFC §8.1).
  #[allow(dead_code)]
  pub const PROBE_INTERVAL: Duration = Duration::from_millis(250);
  /// First announce delay after probing (RFC §8.3).
  #[allow(dead_code)]
  pub const FIRST_ANNOUNCE_DELAY: Duration = Duration::from_secs(0);
  /// Inter-announce interval (RFC §8.3 — at least 1 s).
  #[allow(dead_code)]
  pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(1);
}

/// Compute the next probe deadline given the current probe count (0..3).
/// Probe 0 uses a random offset ∈ [0, 250 ms]; probes 1 and 2 use `PROBE_INTERVAL`.
#[allow(clippy::arithmetic_side_effects, dead_code)]
pub(crate) fn probe_deadline<I: Instant, R: Rng>(
  now: I,
  probe_count: u8,
  rng: &mut R,
) -> Option<I> {
  let wait = if probe_count == 0 {
    let ms = rng.next_u32() % (rfc::INITIAL_PROBE_WAIT_MAX_MS.saturating_add(1));
    Duration::from_millis(ms as u64)
  } else {
    rfc::PROBE_INTERVAL
  };
  now.checked_add_duration(wait)
}

/// Compute the next announce deadline.
#[allow(dead_code)]
pub(crate) fn announce_deadline<I: Instant>(now: I, announce_count: u8) -> Option<I> {
  let wait = if announce_count == 0 {
    rfc::FIRST_ANNOUNCE_DELAY
  } else {
    rfc::ANNOUNCE_INTERVAL
  };
  now.checked_add_duration(wait)
}

/// Maximum doubling steps of the partial-announcement ladder. RFC §8.3 permits
/// "up to eight unsolicited responses", i.e. seven intervals, so the ladder
/// climbs 1, 2, 4, 8, 16, 32, 64 s and then holds at its top rung.
const MAX_PARTIAL_ANNOUNCE_SHIFT: u32 = 6;

/// Compute the re-announce deadline after a PARTIALLY-delivered announcement.
///
/// Unlike a fully-failed send, a partial one put a real datagram on the served
/// link's wire, so its repetition is governed by RFC §8.3: the interval between
/// unsolicited responses "increases by at least a factor of two with every
/// response sent". `streak` is the number of consecutive partial announcements
/// already confirmed BEFORE this one, so the first re-arms at the plain
/// [`rfc::ANNOUNCE_INTERVAL`] and each subsequent one doubles, holding at
/// [`MAX_PARTIAL_ANNOUNCE_SHIFT`] steps.
///
/// A fully-failed send is deliberately NOT on this ladder: it reached no wire, so
/// §8.3 counts no response and the flat `announce_deadline(now, 1)` retry stands.
#[allow(clippy::arithmetic_side_effects, dead_code)]
pub(crate) fn partial_announce_deadline<I: Instant>(now: I, streak: u8) -> Option<I> {
  let shift = u32::from(streak).min(MAX_PARTIAL_ANNOUNCE_SHIFT);
  let secs = rfc::ANNOUNCE_INTERVAL
    .as_secs()
    .saturating_mul(1u64 << shift);
  now.checked_add_duration(Duration::from_secs(secs))
}

/// Compute the next re-announce deadline once Established. Returns the time at which
/// records should be re-broadcast (~80% of TTL).
#[allow(clippy::integer_division, dead_code)]
pub(crate) fn re_announce_deadline<I: Instant>(now: I, ttl_secs: u32) -> Option<I> {
  let secs = (ttl_secs as u64).saturating_mul(80) / 100;
  now.checked_add_duration(Duration::from_secs(secs))
}

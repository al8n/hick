//! Query retry backoff (RFC 6762 §5.2).

use core::time::Duration;

use crate::Instant;

/// Initial interval between query retransmits (RFC §5.2).
const INITIAL_SECS: u64 = 1;
/// Maximum interval (RFC §5.2: hold at 60s).
const MAX_SECS: u64 = 60;

/// Compute the next retry deadline given the number of datagrams already sent
/// (`sends`, counting the initial query). The interval after the first send is
/// `INITIAL_SECS` (RFC §5.2: "at least one second"), doubling on each
/// subsequent send and capped at 60 seconds.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn next_deadline<I: Instant>(now: I, sends: u32) -> Option<I> {
  let shift = sends.saturating_sub(1).min(6);
  let secs = INITIAL_SECS.saturating_mul(1u64 << shift);
  let capped = Duration::from_secs(secs.min(MAX_SECS));
  now.checked_add_duration(capped)
}

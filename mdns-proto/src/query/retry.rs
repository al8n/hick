//! Query retry backoff (RFC 6762 §5.2).

use core::time::Duration;

use crate::Instant;

/// Initial interval between query retransmits (RFC §5.2).
const INITIAL_SECS: u64 = 1;

/// The tightest spacing RFC 6762 §5.2 permits between two transmissions of the
/// same question ON ONE INTERFACE: "the interval between the first two queries
/// MUST be at least one second". The backoff below only ever widens from there,
/// so this is the floor for the whole retry schedule and the value a question's
/// [`Transmit::min_family_gap`](crate::Transmit::min_family_gap) carries.
pub(crate) const MIN_QUERY_GAP: Duration = Duration::from_secs(INITIAL_SECS);
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

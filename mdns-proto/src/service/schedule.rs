//! Computes deadlines for the probe → announce → re-announce sequence, and the
//! bound on how long the core keeps waiting for a link that never accepts.

use core::time::Duration;

use rand_core::Rng;

use crate::{Instant, transmit::TransmitOutcome};

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

/// The periodic re-announce cadence: ~80 % of the record TTL.
///
/// Shared by [`re_announce_deadline`] and [`partial_announce_deadline`] so the
/// cadence and the ladder cap that must never exceed it cannot drift apart.
#[allow(clippy::integer_division, dead_code)]
pub(crate) fn periodic_refresh_secs(ttl_secs: u32) -> u64 {
  u64::from(ttl_secs).saturating_mul(80) / 100
}

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
///
/// # The invariant
///
/// > The served link's inter-refresh gap must be non-decreasing across an excuse
/// > and must never exceed the periodic refresh interval.
///
/// The doubling gives the first half; the CAP at
/// [`periodic_refresh_secs`] — floored at §8.3's one-second minimum so a
/// sub-second TTL cannot produce a zero interval — gives the second. Without the
/// cap the ladder starves the ONE link that is still being served: its rungs
/// reach 16 / 32 / 64 s while a short-TTL record expires from peer caches at
/// 0.8·TTL, so only TTL ≥ 80 s (where the cap never binds and behaviour is
/// therefore unchanged) was ever sound. At TTL = 10 s the uncapped post-excuse
/// cadence is 64, 64, 8, 64, 64, 8 … and the served link's records are absent for
/// most of it.
///
/// Capping rather than releasing the ladder is what keeps the two halves of the
/// invariant from contradicting each other: under persistent partial delivery the
/// served link converges on exactly the healthy periodic rate, which is both the
/// most §8.3 spacing that mechanism can justify and the least the TTL can afford.
///
/// The §8.3 doubling is read as governing the ANNOUNCEMENT BURST, not every
/// unsolicited response forever: a constant-interval periodic refresh is flatly
/// incompatible with the stronger reading — under it the periodic mechanism
/// itself would be illegal. In `Established` the ladder is a rate limiter, and a
/// rate limiter that outruns the TTL it protects has stopped limiting a rate and
/// started dropping the service.
#[allow(clippy::arithmetic_side_effects, dead_code)]
pub(crate) fn partial_announce_deadline<I: Instant>(
  now: I,
  streak: u8,
  ttl_secs: u32,
) -> Option<I> {
  let shift = u32::from(streak).min(MAX_PARTIAL_ANNOUNCE_SHIFT);
  let rung = rfc::ANNOUNCE_INTERVAL
    .as_secs()
    .saturating_mul(1u64 << shift);
  let cap = periodic_refresh_secs(ttl_secs).max(rfc::ANNOUNCE_INTERVAL.as_secs());
  now.checked_add_duration(Duration::from_secs(rung.min(cap)))
}

/// How many CONSECUTIVE partially-delivered confirms one producer (a service or
/// a query) re-arms for before the core stops waiting for the link that keeps
/// missing and advances the phase without it.
///
/// This bounds the CORE'S OWN PATIENCE. The core re-arms a
/// [`TransmitOutcome::PartiallyDelivered`] datagram losslessly and never advances
/// on one, so without a bound a link that is up enough to be obligated but never
/// carries anything holds every service in probing forever. The bound is
/// lifecycle policy, made of facts the core already owns — the confirm shape and
/// its own re-arm count — and needs nothing about sockets or link health. See
/// [`TransmitOutcome`] for why the DRIVER still owns the obligated set.
///
/// The bound counts ROUNDS on the confirm stream rather than wall-clock time,
/// because the re-offer cadence spans 250 ms while probing (RFC 6762 §8.1's own
/// interval) up to 64 s at the top of the §8.3 partial ladder, a factor of 256:
/// any single degrade window means ~120 attempts in one phase and one attempt in
/// the other. Rounds are the unit the re-arm schedule already speaks.
///
/// Two rounds is the smallest count that separates contention from failure. A
/// re-arm is lossless — the SAME probe index / announcement count is re-encoded —
/// so a link that missed round 1 because the transport had room for one datagram
/// gets that exact datagram again in round 2. It also caps the §8.3 doubling
/// ladder at its second rung, delaying an announcement step by at most 1 s + 2 s.
#[allow(dead_code)]
pub(crate) const MAX_PARTIAL_ROUNDS: u8 = 2;

/// What one confirm means for the producer's lifecycle phase, after the core's
/// patience bound ([`MAX_PARTIAL_ROUNDS`]) has been applied to the driver's
/// honest [`TransmitOutcome`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum PhaseAdvance {
  /// Every obligated link accepted the datagram. Advance the phase and take the
  /// full credit a delivery earns.
  Delivered,
  /// An obligated link still has not accepted it, but the producer has already
  /// re-armed [`MAX_PARTIAL_ROUNDS`] times waiting for it. Advance the phase —
  /// and NOTHING else. An excused advance is not a delivery: it earns no
  /// announcement proof, no ladder reset, and no delivered-datagram counter.
  Excused,
  /// An obligated link accepted the datagram, another did not, and the bound has
  /// not fired. Hold the phase and re-arm on the doubling ladder — this retry
  /// will put another real datagram on the served link's wire.
  Partial,
  /// Nothing reached any wire. Hold the phase and retry flat: no link was served,
  /// so no interval needs spacing out.
  Failed,
}

/// Apply the core's patience bound to one confirm, updating `rounds` in place.
///
/// `rounds` is the producer's own consecutive-partial counter. `NoneDelivered`
/// deliberately leaves it UNTOUCHED rather than resetting it: nothing reached a
/// wire, so no obligation was met and none may be written off — and resetting
/// would let an alternating partial/failed pattern evade the bound forever.
#[allow(dead_code)]
pub(crate) fn classify_advance(rounds: &mut u8, outcome: TransmitOutcome) -> PhaseAdvance {
  match outcome {
    TransmitOutcome::AllDelivered => {
      *rounds = 0;
      PhaseAdvance::Delivered
    }
    TransmitOutcome::PartiallyDelivered if *rounds >= MAX_PARTIAL_ROUNDS => {
      *rounds = 0;
      PhaseAdvance::Excused
    }
    TransmitOutcome::PartiallyDelivered => {
      *rounds = rounds.saturating_add(1);
      PhaseAdvance::Partial
    }
    TransmitOutcome::NoneDelivered => PhaseAdvance::Failed,
  }
}

/// The later of two deadlines, treating `None` (an unrepresentable instant) as
/// "no constraint" rather than as "immediately".
///
/// Used to floor an EXCUSED advance's re-arm at the rung the doubling ladder has
/// already earned, so the served link never observes a SHORTER interval across
/// the excuse point than it did before it.
#[allow(dead_code)]
pub(crate) fn later<I: Instant>(a: Option<I>, b: Option<I>) -> Option<I> {
  match (a, b) {
    (Some(x), Some(y)) => Some(x.max(y)),
    (Some(x), None) => Some(x),
    (None, b) => b,
  }
}

/// Compute the next re-announce deadline once Established. Returns the time at which
/// records should be re-broadcast (~80% of TTL).
///
/// Floored at RFC 6762 §8.3's one-second minimum, exactly as
/// [`partial_announce_deadline`] floors its cap. [`periodic_refresh_secs`]
/// truncates toward zero, so a TTL below 2 s yields a zero-second interval and
/// re-arms an `Established` service at `now` — a repump loop that emits an
/// unsolicited response every tick, which §8.3 forbids outright. Registration
/// rejects those TTLs ([`crate::constants::MIN_SERVICE_TTL_SECS`]); this floor is
/// what keeps a future TTL path from reintroducing the zero interval behind it.
#[allow(dead_code)]
pub(crate) fn re_announce_deadline<I: Instant>(now: I, ttl_secs: u32) -> Option<I> {
  let secs = periodic_refresh_secs(ttl_secs).max(rfc::ANNOUNCE_INTERVAL.as_secs());
  now.checked_add_duration(Duration::from_secs(secs))
}

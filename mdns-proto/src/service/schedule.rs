//! Computes deadlines for the probe → announce → re-announce sequence, and the
//! bound on how long the core keeps waiting for a link that never accepts.

use core::time::Duration;

use rand_core::Rng;

use crate::{
  Instant,
  transmit::{FamilyDelivery, TransmitDelivery},
};

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
/// > EVERY obligated family's own inter-refresh gap must be non-decreasing across
/// > an excuse and must never exceed the periodic refresh interval.
///
/// It is stated per FAMILY, not per round, because those differ under a
/// capacity-one transport: the families take turns, so every round carries a real
/// datagram while each family is served only every other one. A per-round reading
/// of this invariant holds there while each family's gap is twice the periodic
/// interval and its records expire from every peer cache. The rung below is
/// therefore only half the rule — [`stalest_refresh_due`] supplies the other half
/// by pulling the deadline in whenever some family's own gap would otherwise
/// exceed the refresh interval.
///
/// The doubling gives non-decreasing; the CAP at [`periodic_refresh_secs`] —
/// floored at §8.3's one-second minimum so a sub-second TTL cannot produce a zero
/// interval — bounds the gap. Without the cap the ladder starves the link that is
/// still being served: its rungs reach 16 / 32 / 64 s while a short-TTL record
/// expires from peer caches at 0.8·TTL, so only TTL ≥ 80 s (where the cap never
/// binds and behaviour is therefore unchanged) was ever sound. At TTL = 10 s the
/// uncapped post-excuse cadence is 64, 64, 8, 64, 64, 8 … and the served link's
/// records are absent for most of it.
///
/// Capping rather than releasing the ladder is what keeps the two halves of the
/// invariant from contradicting each other: under persistent partial delivery the
/// served link converges on exactly the healthy periodic rate, which is both the
/// most §8.3 spacing that mechanism can justify and the least the TTL can afford.
///
/// The §8.3 doubling is read as governing the ANNOUNCEMENT BURST, not every
/// unsolicited response forever: a constant-interval periodic refresh is flatly
/// incompatible with the stronger reading — under it the periodic mechanism
/// itself would be illegal. Once `Established` the burst is over: the ladder is
/// retired there entirely and the per-family refresh schedule governs alone, which
/// is the same rate limit the cap was imposing and enforces it per link instead of
/// per round.
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

/// How many CONSECUTIVE rounds ONE FAMILY may miss a datagram some other family
/// carried before the core stops waiting for it and advances the phase without it.
///
/// This bounds the CORE'S OWN PATIENCE. The core re-arms a partially-delivered
/// datagram losslessly and never advances on one, so without a bound a family that
/// is up enough to be obligated but never carries anything holds every service in
/// probing forever. The bound is lifecycle policy, made of facts the core already
/// owns — the confirm and its own re-arm count — and needs nothing about sockets or
/// link health. See [`TransmitDelivery`] for why the DRIVER still owns the
/// obligated set.
///
/// It is counted PER FAMILY. A shared counter cannot tell "v6 has missed twice"
/// from "v4 and v6 missed one round each while taking turns", and those need
/// opposite answers: the first is a family to stop waiting for, the second is two
/// families that are both being served.
///
/// The bound counts ROUNDS on the confirm stream rather than wall-clock time,
/// because the re-offer cadence spans 250 ms while probing (RFC 6762 §8.1's own
/// interval) up to 64 s at the top of the §8.3 partial ladder, a factor of 256:
/// any single degrade window means ~120 attempts in one phase and one attempt in
/// the other. Rounds are the unit the re-arm schedule already speaks.
///
/// Two rounds is the smallest count that separates contention from failure. A
/// re-arm is lossless — the SAME probe index / announcement count is re-encoded —
/// so a family that missed round 1 because the transport had room for one datagram
/// gets that exact datagram again in round 2. It also caps the §8.3 doubling
/// ladder at its second rung, delaying an announcement step by at most 1 s + 2 s.
#[allow(dead_code)]
pub(crate) const MAX_PARTIAL_ROUNDS: u8 = 2;

/// One address family's standing on the datagram the producer is currently
/// re-arming — the core's own per-family patience state.
///
/// Per family rather than per round because those disagree exactly where it
/// matters: two families alternating under a capacity-one transport look
/// identical to one chronically dead family through a shared counter, and they
/// need opposite answers. The alternating pair is being served in full, one
/// family per round; the dead one is not being served at all.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct FamilyPatience {
  /// Consecutive rounds in which this family was obligated, still owed the
  /// current datagram, and missed it — reset by its own delivery, by the phase
  /// advancing, and by the family ceasing to be obligated.
  pub(crate) missed: u8,
  /// Whether this family has carried the CURRENT datagram at all, at any point
  /// since the phase last advanced.
  ///
  /// A re-arm is LOSSLESS — the same probe index, the same announcement content
  /// is re-encoded — so a family that carried round 1's datagram has been asked
  /// (§8.1) and told (§8.3) even if round 2's copy went to the other family
  /// instead. Under a capacity-one transport that is the ONLY way the phase ever
  /// advances: the families alternate, so no single round reaches both and no
  /// family ever spends its patience, and without this the producer would sit in
  /// `Probing(0)` forever while both links were being served perfectly well.
  ///
  /// The bit is scoped to ONE continuous stretch of obligation. A family that
  /// ceases to be obligated and later returns is a NEW link that has carried
  /// nothing, so [`classify_advance`] drops this bit across the gap along with
  /// the rest of the family's state — otherwise pre-gap coverage would complete a
  /// round the returned family never received, and the phase would advance on
  /// evidence about a link that no longer exists.
  ///
  /// Unreachable in tree TODAY: every `Sustained` transmit is multicast, both
  /// families' obligation is fixed by socket presence, and every in-tree driver
  /// fixes its sockets at spawn, so no family ever leaves the obligated set
  /// mid-producer. The core is a public library and a driver that varies its
  /// obligated set at runtime is exactly what the trichotomy exists to support,
  /// so the gap is handled rather than assumed away.
  ///
  /// The harder limit is not fixable here at all: a gap that contains NO
  /// confirmed round is invisible to the core by construction. The core learns
  /// about obligation only through confirms, so a family that leaves and returns
  /// between two confirms is indistinguishable from one that never left, and its
  /// pre-gap coverage stands. No housekeeping inside this function can see that,
  /// and nothing short of the driver reporting the transition itself would.
  pub(crate) covered: bool,
  /// Whether this family was EXCUSED at the last advance and has not delivered
  /// since — i.e. the core has stopped waiting for it.
  ///
  /// It is still fanned onto every round; what it loses is the right to drive the
  /// per-family refresh schedule. This latch has to outlive the advance that set
  /// it: `missed` restarts there, so without it a chronically dead family would be
  /// back in good standing every third round, hold the next deadline permanently
  /// in the past, and have the HEALTHY family re-announced at the §8.3 one-second
  /// floor forever — one defect traded for another, and a per-link §8.3 violation
  /// on the link that works.
  pub(crate) stalled: bool,
}

impl FamilyPatience {
  /// Whether this family may still drive the per-family refresh schedule.
  #[allow(dead_code)]
  pub(crate) const fn in_good_standing(&self) -> bool {
    !self.stalled
  }
}

/// When the stalest obligated family in good standing is next owed an
/// announcement: the earliest `last delivery + periodic refresh interval` across
/// those families, or `None` when no family qualifies.
///
/// Families are skipped for exactly two reasons, and both are load-bearing:
///
/// * **Unanchored** (`None` last-delivery) — the family is not obligated at all.
///   A v4-only host, the common deployment, would otherwise read as infinitely
///   stale on v6 forever and re-arm every confirm at the §8.3 floor, flooding the
///   one link it has.
/// * **Out of good standing** — see [`FamilyPatience::stalled`].
///
/// The interval is [`re_announce_deadline`]'s, so the periodic cadence and the
/// per-family deadline that must not exceed it cannot drift apart.
#[allow(dead_code)]
pub(crate) fn stalest_refresh_due<I: Instant>(
  last_delivered: &[Option<I>; 2],
  patience: &[FamilyPatience; 2],
  ttl_secs: u32,
) -> Option<I> {
  last_delivered
    .iter()
    .zip(patience.iter())
    .filter(|&(_, p)| p.in_good_standing())
    .filter_map(|(at, _)| *at)
    .filter_map(|at| re_announce_deadline(at, ttl_secs))
    .min()
}

/// Compose the next announcement deadline out of the phase's own schedule
/// (`base`) and the per-family refresh schedule (`due`, from
/// [`stalest_refresh_due`]).
///
/// The composed rule is one line: **no later than either, and never sooner than
/// RFC 6762 §8.3's one-second minimum.**
///
/// `due` may only pull the deadline IN. The phase schedule already spaces
/// announcements out — the §8.3 doubling ladder while announcing, the periodic
/// refresh once `Established` — and that spacing is the §8.3 rate limit; taking the
/// later of the two would let a family's records expire while the ladder was off at
/// a higher rung. Taking the earlier bounds every family's own gap by the refresh
/// interval, which is exactly what the ladder's cap was already trying to do per
/// round.
///
/// The floor is what makes the rule total. `due` is derived from a PAST delivery,
/// so `stalest + R` is routinely already behind `now` — that is the signal that a
/// family is overdue, not a licence to re-announce continuously. Flooring at
/// `now + ANNOUNCE_INTERVAL` turns "overdue" into "next round, one second out" and
/// makes a permanently-past deadline unrepresentable.
#[allow(dead_code)]
pub(crate) fn compose_announce_deadline<I: Instant>(
  now: I,
  base: Option<I>,
  due: Option<I>,
) -> Option<I> {
  let base = base?;
  let capped = match due {
    Some(d) if d < base => d,
    _ => base,
  };
  match announce_deadline(now, 1) {
    Some(floor) if capped < floor => Some(floor),
    _ => Some(capped),
  }
}

/// What one confirm means for the producer's lifecycle phase, after the core's
/// per-family patience ([`FamilyPatience`]) has been applied to the driver's
/// honest [`TransmitDelivery`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum PhaseAdvance {
  /// Every obligated family accepted the datagram, in THIS round. Advance the
  /// phase and take the full credit a delivery earns.
  Delivered,
  /// No single round reached every obligated family, but between them the rounds
  /// since the last advance did: every obligated family has carried this exact
  /// datagram. Advance the phase — and NOTHING else, because no ONE datagram was
  /// confirmed by every family.
  Covered,
  /// An obligated family has still not accepted it, and EVERY such family has
  /// already spent [`MAX_PARTIAL_ROUNDS`] on this producer. Advance the phase —
  /// and NOTHING else. An excused advance is not a delivery: it earns no
  /// announcement proof, no ladder reset, and no delivered-datagram counter.
  Excused,
  /// An obligated family is still owed the datagram and its bound has not fired.
  /// Hold the phase and re-arm — this retry will put another real datagram on the
  /// served family's wire.
  Partial,
  /// Nothing reached any wire. Hold the phase and retry flat: no family was served,
  /// so no interval needs spacing out.
  Failed,
}

impl PhaseAdvance {
  /// Whether the phase moves on this confirm.
  #[allow(dead_code)]
  pub(crate) const fn advances(self) -> bool {
    matches!(self, Self::Delivered | Self::Covered | Self::Excused)
  }

  /// Whether the phase moves WITHOUT a single datagram having been confirmed by
  /// every obligated family — the shape that earns the advance and nothing else.
  #[allow(dead_code)]
  pub(crate) const fn advances_without_delivery(self) -> bool {
    matches!(self, Self::Covered | Self::Excused)
  }
}

/// Apply the core's per-family patience to one confirm, updating `patience`
/// (indexed [v4, v6]) in place.
///
/// A family's `missed` count advances in exactly one situation: some family
/// delivered, this family was obligated, and it was still owed the datagram. It is
/// reset by its own delivery, by ceasing to be obligated, and by the phase
/// advancing — the same three events that clear the aggregate counter this
/// replaced, so the excusal cadence is unchanged.
///
/// A round in which NOTHING was delivered leaves every MISSED family's counter
/// untouched rather than resetting it: nothing reached a wire, so no obligation
/// was met and none may be written off. It must not ADVANCE it either — that is
/// what keeps the excusal unreachable from silence, which §8.1 requires of
/// anything that lets a name be claimed. Resetting instead would let an
/// alternating partial/failed pattern evade the bound forever.
///
/// A family reported `Unobligated` is the one exception, and it is not about the
/// round at all: ceasing to be obligated is a TRANSITION, and everything it
/// leaves behind describes a family that no longer exists. Carrying the charge
/// across the gap would excuse the family the moment it comes back — it would
/// have spent the bound while unreachable and be written off after a single
/// offer, which is the §8.1 violation this bound exists to prevent. Carrying its
/// COVERAGE across the gap is the mirror image and just as wrong: coverage is a
/// claim that THIS family already carried the datagram still outstanding, and the
/// family that returns is a newly obligated link that has carried nothing. So the
/// whole of [`FamilyPatience`] is dropped here, not part of it. Clearing can only
/// make advancement harder, so it cannot reintroduce the silence hazard; a silent
/// round still SETS nothing, which is what keeps coverage — and therefore a phase
/// — unreachable from silence.
#[allow(dead_code)]
pub(crate) fn classify_advance(
  patience: &mut [FamilyPatience; 2],
  delivery: TransmitDelivery,
) -> PhaseAdvance {
  if !delivery.any_delivered() {
    for (p, family) in patience.iter_mut().zip(delivery.families().iter()) {
      if matches!(family, FamilyDelivery::Unobligated) {
        *p = FamilyPatience::default();
      }
    }
    return PhaseAdvance::Failed;
  }
  // Fold the round in. `excusable` tracks whether every family STILL OWED the
  // datagram has spent the bound, read from the count BEFORE this round so the
  // bound is spent on `MAX_PARTIAL_ROUNDS` genuine re-arms and the excusal lands
  // on the round after them.
  let mut excusable = true;
  for (p, family) in patience.iter_mut().zip(delivery.families().iter()) {
    match family {
      // An unobligated family owes nothing, so it can hold no phase and can be
      // behind on nothing.
      FamilyDelivery::Delivered | FamilyDelivery::Unobligated => {
        p.missed = 0;
        p.covered = true;
        p.stalled = false;
      }
      FamilyDelivery::Missed => {
        if !p.covered {
          if p.missed < MAX_PARTIAL_ROUNDS {
            excusable = false;
          }
          p.missed = p.missed.saturating_add(1);
        }
      }
    }
  }
  let advance = if !delivery.any_missed() {
    PhaseAdvance::Delivered
  } else if patience.iter().all(|p| p.covered) {
    PhaseAdvance::Covered
  } else if excusable {
    PhaseAdvance::Excused
  } else {
    return PhaseAdvance::Partial;
  };
  for p in patience.iter_mut() {
    // A family the phase is advancing PAST — one that never carried this
    // datagram — is what the core has stopped waiting for. Nothing is stalled by
    // a delivered or a covered advance.
    p.stalled |= !p.covered;
    p.missed = 0;
    p.covered = false;
  }
  advance
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

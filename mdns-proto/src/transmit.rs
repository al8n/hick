//! Outgoing-datagram descriptor and its delivery outcome.

use core::{
  net::{IpAddr, SocketAddr},
  time::Duration,
};

/// Whether the core will KEEP RE-ARMING a datagram until every obligated link
/// accepts it — i.e. whether missing this datagram pins the producer's progress.
///
/// The tag is a property of the DATAGRAM, not of the producing service's
/// lifecycle phase. The two diverge in both directions: the periodic
/// `Established` re-announce advances no phase yet is still re-armed on the RFC
/// 6762 §8.3 doubling ladder while a link keeps missing it, and
/// [`Query::poll_transmit`](crate::Query::poll_transmit) shares [`Transmit`]
/// while having no service phase at all.
///
/// A driver needs the distinction for any decision about what a FAILURE means.
/// The concrete one in tree: a datagram no reachable socket can ever carry (too
/// large for every one of them) retires a `Sustained` producer, because it would
/// otherwise re-offer that same datagram forever — while the same failure on a
/// `OneShot` reply is simply an unanswered question, and retiring on it would let
/// a remote peer tear down a healthy service by asking one.
///
/// Deliberately NOT `#[non_exhaustive]`: a future transmit kind must break every
/// driver's match and force it to choose a policy, rather than silently
/// inheriting a wildcard arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransmitObligation {
  /// The core re-arms this datagram until every obligated link accepts it, so a
  /// link that keeps missing pins the producer's progress — until the core's own
  /// patience bound excuses it (see [`TransmitDelivery`]).
  ///
  /// Carried by the RFC 6762 §8.1 probe, by every §8.3 announcement (including
  /// the periodic re-announce from `Established`), and by the §5.2 query
  /// retransmission.
  Sustained,
  /// Fire-and-forget: the core never re-arms this datagram, so missing it pins
  /// nothing and losing it costs nothing but one unanswered question. The core
  /// still reads [`TransmitDelivery::any_delivered`] from its confirm to latch
  /// §10.1 goodbye ownership for the records the datagram carried.
  ///
  /// Carried by every response: the jittered multicast reply (§6), the legacy
  /// unicast reply (§6.7), and the RFC 6763 §9 service-type enumeration reply.
  OneShot,
}

/// Outgoing datagram metadata produced by the proto state machines.
///
/// The proto writes the actual bytes into a caller-supplied `&mut [u8]`;
/// this struct describes where the bytes go, how many were written, and whether
/// the core will re-arm it until every obligated link accepts it
/// ([`TransmitObligation`]).
///
/// It deliberately carries NO caller deadline. A query's `QuerySpec::with_timeout`
/// bound is weighed once, at the poll that admits the datagram, and admission is
/// the boundary that bound names. Carrying it here would only invite a recheck
/// before each per-family syscall — the same comparison relocated, still ahead of
/// the syscall and the syscall still ahead of the wire — so it would narrow the
/// interval without ever closing it, while giving every driver a second place to
/// disagree about when the window shut.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Transmit {
  dst: SocketAddr,
  src_ip: Option<IpAddr>,
  size: usize,
  obligation: TransmitObligation,
  min_family_gap: Duration,
}

impl Transmit {
  /// Creates a new transmit descriptor.
  #[inline(always)]
  pub const fn new(
    dst: SocketAddr,
    src_ip: Option<IpAddr>,
    size: usize,
    obligation: TransmitObligation,
    min_family_gap: Duration,
  ) -> Self {
    Self {
      dst,
      src_ip,
      size,
      obligation,
      min_family_gap,
    }
  }

  /// Destination socket address (typically the mDNS multicast group).
  #[inline(always)]
  pub const fn dst(&self) -> SocketAddr {
    self.dst
  }

  /// Source local IP, if the proto needs the caller to bind a specific
  /// interface for this send.
  #[inline(always)]
  pub const fn src_ip(&self) -> Option<IpAddr> {
    self.src_ip
  }

  /// Number of bytes written into the caller-supplied buffer.
  #[inline(always)]
  pub const fn size(&self) -> usize {
    self.size
  }

  /// Whether the core will re-arm this datagram until every obligated link
  /// accepts it, and therefore what a permanent send failure means for the
  /// producer. See [`TransmitObligation`].
  #[inline(always)]
  pub const fn obligation(&self) -> TransmitObligation {
    self.obligation
  }

  /// The minimum time that must separate this datagram from the PRODUCER'S
  /// PREVIOUS one **on one address family's wire** — the earliest-next-send gate
  /// the driver owes each family it fans onto.
  ///
  /// # Why the core computes it and the driver enforces it
  ///
  /// The rule is about the WIRE, so only the driver knows when it was last
  /// satisfied: [`TransmitDelivery`]'s confirm anchors at the EARLIEST acceptance
  /// across families, which is the right anchor for the TTL guarantee but is not
  /// the late family's own wire time. With inter-family skew `s` the core
  /// schedules the next datagram one interval after the early family's
  /// acceptance, so the LATE family's own gap is `interval − s`: an announcement
  /// falls under RFC 6762 §6 / §8.3's one-second minimum at every TTL, and a
  /// probe gap can approach zero. Only the driver holds the per-family
  /// acceptance instants that make that visible.
  ///
  /// The VALUE, though, is protocol policy and is kind-dependent, which is why it
  /// is carried here rather than hardcoded in each driver. §8.1 spaces probes
  /// 250 ms apart and exempts them from the one-second rule; announcements and
  /// §5.2 query retransmissions are not exempt. A driver that picked the number
  /// itself would have taken protocol policy across the sans-I/O boundary, and
  /// would get the probe sequence wrong by a factor of four.
  ///
  /// # Zero
  ///
  /// [`Duration::ZERO`] means this datagram is UNGATED, and every
  /// [`TransmitObligation::OneShot`] datagram is. A one-shot is never re-armed,
  /// so a gate could only DROP it — trading a §6 spacing nicety for an
  /// unanswered question — and its spacing is already governed by the response
  /// jitter and coalescing schedule the core applies before emitting it.
  ///
  /// # What a driver does when the gate is shut
  ///
  /// It reports that family [`FamilyDelivery::Missed`] for this round: the family
  /// is obligated and did not carry the datagram, which is the honest fact. It
  /// must NOT report [`FamilyDelivery::Unobligated`] (that would launder a
  /// deferral into an absent link) and must not park the fan-out waiting for the
  /// gate to open. The core re-arms losslessly, and the gate is open by the time
  /// the re-armed datagram is due.
  #[inline(always)]
  pub const fn min_family_gap(&self) -> Duration {
    self.min_family_gap
  }
}

/// What ONE address family did with ONE logical datagram: the presence
/// trichotomy the core schedules on.
///
/// None of the three may be collapsed into another, and the interesting collapse
/// is `Unobligated` into `Missed`. A single-stack host has no IPv6 socket at all,
/// so folding the two makes it look permanently behind on a family it never had
/// — and a scheduler that chases the stalest family then re-arms that host at the
/// RFC 6762 §8.3 one-second floor forever, flooding the one link it does have.
///
/// Deliberately NOT `#[non_exhaustive]`: a future case must break every driver's
/// match and force it to choose, rather than silently inheriting a wildcard arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, derive_more::Display)]
#[display("{}", self.as_str())]
pub enum FamilyDelivery {
  /// No socket for this family, or the datagram was not addressed to it. The
  /// family was never OBLIGATED to carry this transmit, so its absence is not a
  /// failure and it owes nothing.
  Unobligated,
  /// Obligated, and the datagram was accepted.
  Delivered,
  /// Obligated, and the datagram was not accepted.
  Missed,
}

impl FamilyDelivery {
  /// Canonical lowercase slug for this result.
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Unobligated => "unobligated",
      Self::Delivered => "delivered",
      Self::Missed => "missed",
    }
  }
}

/// The PER-FAMILY delivery result of ONE logical datagram produced by a
/// `poll_transmit`.
///
/// A single logical mDNS multicast fans out to every link the driver serves — the
/// IPv4 and IPv6 groups — and those sends succeed or fail INDEPENDENTLY. The core
/// asks three different questions of a send, and under partial delivery their
/// answers differ:
///
/// * [`any_delivered`](Self::any_delivered) drives the goodbye-ownership latch
///   (RFC 6762 §10.1): peers reachable over a family that accepted the datagram
///   may now hold the records it carried, so a later withdrawal must retract them.
/// * [`all_delivered`](Self::all_delivered) drives lifecycle-phase advance (§8.1
///   probing, §8.3 announcing) and the §5.2 query retry budget: a family that
///   never saw the probe has not been asked, and one that never saw the
///   announcement has not been told.
/// * [`v4`](Self::v4) / [`v6`](Self::v6) drive per-family SCHEDULING: WHICH family
///   heard the announcement decides when the next one is due, because each family
///   races its own copy of the record TTL in its own peers' caches.
///
/// # Why the aggregate shape is not enough
///
/// An aggregate "all / partial / none" carries no family identity, so it cannot
/// distinguish "the same family keeps failing" (correctly excused) from "the
/// families are taking turns" (each one served, but only every other round). A
/// transport with room for one datagram per round produces exactly the second
/// pattern once the driver's fair-service obligation below rotates the slot: every
/// round is globally partial, the re-arm converges on the periodic refresh
/// interval `R`, and each family is refreshed every 2·`R` — beyond the TTL that
/// `R` is 80 % of. Records then expire cyclically on BOTH families while every
/// per-round invariant still holds. Per-family delivery is what makes that
/// observable at all.
///
/// # The obligated set
///
/// "Obligated" is DRIVER policy, not a core concept: a family is obligated for
/// this datagram when the driver fanned it onto that family's socket and has not
/// permanently written it off.
///
/// * An RFC 6762 §6.7 legacy unicast reply obligates exactly ONE family (the
///   destination's); the other is [`Unobligated`](FamilyDelivery::Unobligated).
/// * An EMPTY obligated set (no socket at all) is
///   [`any_delivered`](Self::any_delivered) `== false` and therefore
///   [`all_delivered`](Self::all_delivered) `== false` — never a vacuous "all".
///
/// # The split (normative)
///
/// The DRIVER owns the obligated set and link death: which families a datagram is
/// fanned onto, which have been permanently written off (no socket, a degraded
/// family), and when a socket is torn down. It reports the honest per-family facts
/// and nothing else — no confirm is ever laundered into a different one, and a
/// `OneShot` result in particular reaches the core verbatim, since the core reads
/// `any_delivered` from it to latch §10.1 goodbye ownership.
///
/// A driver MUST offer every obligated family on every round, and under a
/// constrained slot MUST prefer the longest-blocked family. This is what makes the
/// core's scheduling sufficient: the core says WHEN the stalest family is due and
/// the driver hands that family the next free slot, so neither side needs to know
/// anything new about the other. A driver that always filled the same family first
/// would starve the other one no matter what the core scheduled.
///
/// The CORE owns its own patience, per family. Repeated partial delivery re-arms
/// indefinitely, so the core bounds how many consecutive re-arms one producer
/// spends waiting for a family that never accepts; past that bound it advances the
/// phase without that family (`MAX_PARTIAL_ROUNDS`). That is a decision about the
/// core's own lifecycle, made of facts the core already holds — the confirm and its
/// own re-arm count — with no socket or link-health knowledge involved, so it
/// belongs where every other lifecycle rule lives. Its in-tree sibling is the
/// withdrawal ceiling, which force-completes per-family goodbye debt the driver
/// never paid.
///
/// The core does NOT thereby decide a family is dead: the excused family is fanned
/// onto on every later round and the first round it accepts is a delivery on its
/// own merit, so there is no degraded state to get stuck in and no recovery edge to
/// detect. Nor is the escape a delivery — it advances the phase and nothing else.
/// It earns no announcement proof
/// ([`Service::has_fully_announced`](crate::Service::has_fully_announced) stays
/// shut), no ladder reset, and no delivered-datagram counter. §8.1's requirement
/// that a name be probed before it is claimed is honoured by the bound being spent
/// on genuine re-arms of that probe, and by the excusal never being reachable from
/// a confirm that put nothing on a wire: an all-miss round leaves every per-family
/// count untouched, so an alternating partial/failed pattern cannot walk into it.
///
/// The core's other half of the contract: a re-arm is LOSSLESS (same probe index,
/// same announcement count — nothing restarts) and recovery is IMMEDIATE — the
/// first confirm after the lagging family starts accepting advances the phase from
/// exactly where it stood.
///
/// That same losslessness is what lets the phase advance through a second escape
/// that needs no patience bound at all: if every obligated family has carried the
/// CURRENT datagram at some point since the phase last advanced — each in its own
/// round, no round `all_delivered` on its own — the phase advances `Covered`, on
/// the same nothing-else terms as an excusal. A re-arm re-encodes the identical
/// probe index / announcement content, so the family served two rounds ago was
/// genuinely asked (§8.1) or told (§8.3) about the very datagram still
/// outstanding today. This is the capacity-one transport's own way out: its
/// families take turns by construction, so no single round is ever
/// `all_delivered`, yet each one is served in full every other round.
///
/// # What the per-family schedule guarantees
///
/// With `R` the periodic refresh interval (~80 % of the record TTL, floored at
/// §8.3's one second), every obligated family in good standing is re-announced
/// within `max(R, 2 × ANNOUNCE_INTERVAL)` of its last delivery. The second term is
/// arithmetic, not slack: at the minimum registrable TTL of 2 s
/// ([`MIN_SERVICE_TTL_SECS`](crate::constants::MIN_SERVICE_TTL_SECS)) `R` is 1 s,
/// so a capacity-one transport spends two §8.3-floored rounds to serve two
/// families and the per-family gap is the TTL exactly.
///
/// A family that has reached its own patience bound stops driving that schedule
/// until it delivers again — otherwise its frozen anchor would hold the deadline
/// permanently in the past and the HEALTHY family would be re-announced at the
/// one-second floor forever.
///
/// # Not modelled
///
/// * **Within-family aggregation.** Under a future multi-interface driver a
///   family spans several links, and [`Delivered`](FamilyDelivery::Delivered)
///   would have to mean "every obligated link of that family accepted"; the
///   fair-service obligation above would then apply per link inside the driver.
///   Today each family is one socket, so the two readings coincide.
/// * **Per-family goodbye ownership.** The §10.1 latch stays aggregate: any
///   delivery latches the records the datagram carried, for every family. That is
///   the conservative direction — it can only make a withdrawal retract more than
///   strictly necessary — and splitting it per family would risk the opposite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitDelivery {
  /// Indexed [v4, v6]. Private so the shape stays an implementation detail while
  /// the public surface names the families, matching
  /// [`Endpoint::note_withdrawal_result`](crate::Endpoint::note_withdrawal_result).
  families: [FamilyDelivery; 2],
}

impl TransmitDelivery {
  /// Report what each family did with this datagram.
  #[inline(always)]
  pub const fn new(v4: FamilyDelivery, v6: FamilyDelivery) -> Self {
    Self { families: [v4, v6] }
  }

  /// What the IPv4 family did with this datagram.
  #[inline(always)]
  pub const fn v4(&self) -> FamilyDelivery {
    self.families[0]
  }

  /// What the IPv6 family did with this datagram.
  #[inline(always)]
  pub const fn v6(&self) -> FamilyDelivery {
    self.families[1]
  }

  /// At least one obligated family accepted the datagram, so peers reachable over
  /// that family may now hold the records it carried.
  ///
  /// This is the goodbye-ownership fact (RFC 6762 §10.1): ownership latches iff
  /// this is `true`.
  #[inline(always)]
  pub const fn any_delivered(&self) -> bool {
    matches!(self.families[0], FamilyDelivery::Delivered)
      || matches!(self.families[1], FamilyDelivery::Delivered)
  }

  /// Every obligated family accepted the datagram — and at least one was
  /// obligated, so an empty obligated set is never a vacuous "all".
  ///
  /// This is the lifecycle fact: the §8.1 probe sequence, the §8.3 announcement
  /// phase, and the §5.2 query retry budget advance iff this is `true`, or iff
  /// every family that missed has already spent the core's patience.
  #[inline(always)]
  pub const fn all_delivered(&self) -> bool {
    self.any_delivered() && !self.any_missed()
  }

  /// At least one obligated family did NOT accept the datagram.
  #[inline(always)]
  pub(crate) const fn any_missed(&self) -> bool {
    matches!(self.families[0], FamilyDelivery::Missed)
      || matches!(self.families[1], FamilyDelivery::Missed)
  }

  /// The per-family results in index order, for the core's own per-family state.
  #[inline(always)]
  pub(crate) const fn families(&self) -> &[FamilyDelivery; 2] {
    &self.families
  }
}

/// Index of the IPv4 family in every per-family array, for the in-crate tests
/// that assert on the core's own per-family state.
#[cfg(test)]
#[cfg(all(any(feature = "alloc", feature = "std"), feature = "slab"))]
pub(crate) const V4: usize = 0;
/// Index of the IPv6 family. `V4_ONLY` misses on this one, so it is the family
/// the patience assertions are about.
#[cfg(test)]
#[cfg(all(any(feature = "alloc", feature = "std"), feature = "slab"))]
pub(crate) const V6: usize = 1;

/// Terse fixtures for the in-crate tests, which drive thousands of confirms and
/// mostly care about the delivery SHAPE rather than which family carried what.
#[cfg(test)]
impl TransmitDelivery {
  /// Both families obligated, both delivered.
  pub(crate) const ALL: Self = Self::new(FamilyDelivery::Delivered, FamilyDelivery::Delivered);
  /// Both families obligated, neither delivered.
  pub(crate) const NONE: Self = Self::new(FamilyDelivery::Missed, FamilyDelivery::Missed);
  /// Both obligated; v4 carried the datagram and v6 missed it. The canonical
  /// partial shape, so a REPEATED `V4_ONLY` is one chronically missing family —
  /// which is what the patience bound is about.
  pub(crate) const V4_ONLY: Self = Self::new(FamilyDelivery::Delivered, FamilyDelivery::Missed);
  /// The mirror image. Alternating `V4_ONLY` / `V6_ONLY` is the capacity-one
  /// transport, where every round is partial yet NEITHER family is failing.
  pub(crate) const V6_ONLY: Self = Self::new(FamilyDelivery::Missed, FamilyDelivery::Delivered);
}

#[cfg(test)]
mod tests;

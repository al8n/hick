//! Outgoing-datagram descriptor, the I/O-world vocabulary a driver reports it
//! in, and the core's own projection of that vocabulary onto protocol meaning.

use core::{
  net::{IpAddr, SocketAddr},
  time::Duration,
};

use crate::Instant;

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
  /// patience bound excuses it.
  ///
  /// Carried by the RFC 6762 §8.1 probe, by every §8.3 announcement (including
  /// the periodic re-announce from `Established`), and by the §5.2 query
  /// retransmission.
  Sustained,
  /// Fire-and-forget: the core never re-arms this datagram, so missing it pins
  /// nothing and losing it costs nothing but one unanswered question. The core
  /// still reads [`TransmitConfirm::any_delivered`] from its confirm to latch
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
/// bound is weighed once, by the comparison inside the poll that admits the
/// datagram, and that comparison is the boundary the bound names. Carrying the
/// deadline here would only invite a recheck before each per-family syscall — the
/// same comparison relocated, still ahead of the syscall and the syscall still
/// ahead of the wire — so it would narrow the interval without ever closing it,
/// while giving every driver a second place to disagree about when the window
/// shut.
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
  /// PREVIOUS one **on one address family's egress path** — the earliest-next-send
  /// gate the driver owes each family it fans onto, bounded at whatever egress
  /// boundary that driver's transport lets it observe: a socket driver
  /// (`hick-mio`, `hick-reactor`, `hick-compio`) spaces its KERNEL HANDOFFS, and a
  /// queued driver (`hick-smoltcp`, `hick-embassy`) spaces its ENQUEUES and
  /// nothing past them.
  ///
  /// No driver here bounds the WIRE, and this must not be cited as though one
  /// did: a `sendto` returning `Ok` means the kernel owns the datagram, not that
  /// it has left the NIC, and an accepted enqueue means only that some later
  /// interface poll will carry it.
  ///
  /// # Why the core computes it and the driver enforces it
  ///
  /// The rule is about the TRANSMISSION, so only the driver knows when it was
  /// last satisfied: the confirm anchors at the EARLIEST acceptance across
  /// families ([`FamilyAttempt::Accepted`]), which is the right anchor for the TTL
  /// guarantee but is not the late family's own egress instant. With inter-family
  /// skew `s` the core schedules the next datagram one interval after the early
  /// family's acceptance, so the LATE family's own gap is `interval − s`: an
  /// announcement falls under RFC 6762 §6 / §8.3's one-second minimum at every
  /// TTL, and a probe gap can approach zero. Only the driver holds the per-family
  /// acceptance instants that make that visible.
  ///
  /// # What each boundary does and does not bound
  ///
  /// A send call that hands the datagram to the kernel takes it out of this
  /// process, so a gate stamped there paces the handoffs and leaves only the
  /// kernel's own queueing between them and the link. A send call that merely
  /// ENQUEUES — a raw smoltcp UDP socket, embassy-net — leaves the datagram in
  /// this process: the device dispatch happens later, in the interface poll, and a
  /// gate stamped at the enqueue bounds ENQUEUE spacing. If that poll stalls for
  /// at least the gap, the gate opens, a second datagram is queued, and one poll
  /// can put both on the device back-to-back. Bounding the wire on such a
  /// transport would take a per-family egress ACKNOWLEDGEMENT from it, which is
  /// no part of this seam — so a queued driver bounds the enqueue, and owes its
  /// own readers that distinction rather than a claim about the wire.
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
  /// It reports that family [`FamilyAttempt::GateShut`], which the core reads as
  /// obligated-and-did-not-carry — the honest fact. It must not park the fan-out
  /// waiting for the gate to open, and it has no way to report the deferral as an
  /// absent link even if it wanted to. The core re-arms losslessly, and the gate
  /// is open by the time the re-armed datagram is due.
  #[inline(always)]
  pub const fn min_family_gap(&self) -> Duration {
    self.min_family_gap
  }
}

/// What ONE address family's transport did with ONE logical datagram — the
/// I/O-WORLD fact, before any protocol meaning is read into it.
///
/// This is the whole of what a driver reports about a send. The core owns every
/// interpretation of it: which families were obligated, whether the datagram was
/// delivered, missed or never owed, when the confirm is anchored, and whether the
/// producer can ever carry these bytes at all.
///
/// # This is a TRUST boundary, not a proof
///
/// Nothing here makes a delivery unforgeable, and nothing could. A driver can
/// report [`Accepted`](Self::Accepted) for a send it never made, and the core has
/// no way to tell: it performs no I/O, so it cannot witness a syscall, a shut
/// wire gate, or an absent socket. "This family owed nothing" in particular is
/// the value every withdrawal confirm starts from, so an "unconstructible
/// absence" is not even expressible.
///
/// What this vocabulary buys is narrower and worth more: the error-prone half —
/// the MAPPING from an I/O outcome onto a protocol verdict — has exactly one
/// implementation and one test suite. Every historical failing-versus-absent
/// defect lived in that mapping, duplicated across drivers, so each fix had to be
/// made once per driver and was in fact missed more than once. A driver that
/// reports honestly can no longer get the meaning wrong, because it no longer
/// states one.
///
/// # What stays on the driver's side, and why that is not interpretation
///
/// A driver reports I/O-world facts INCLUDING the static ones only it can know —
/// its transport's hard carry ceiling, and when each of its families last took
/// bytes for egress. Those are facts about the transport, not meanings read into
/// it:
///
/// * [`Refused { permanent }`](Self::Refused) — the refusal proves the bytes did
///   not go out; the SIZE proves whether any later attempt could. See the variant
///   for the normative rule every driver owes.
/// * [`GateShut`](Self::GateShut) — the minimum gap is protocol policy and
///   arrives from the core on [`Transmit::min_family_gap`], but only the driver
///   holds the per-family egress instants that say whether it has elapsed.
///
/// # The one thing a driver can observe and cannot say
///
/// "I withheld this family because you told me it owed nothing" — the RFC 6762
/// §10.1 goodbye case, where a driver fans a round only onto the families
/// [`FamilyDebt`](crate::endpoint::FamilyDebt) named. It is deliberately absent,
/// because it is not an I/O fact at all: no syscall was made, and the only thing
/// that happened is the driver honouring a decision the core already made and
/// already remembers. So the core discards whatever a driver reports for a family
/// whose debt was zero, which makes the choice unable to cost anything — rather
/// than adding a variant whose only content is a fact the core already holds.
///
/// # The fair-service obligation (normative)
///
/// A driver MUST offer every family it has a socket for on EVERY round, and under
/// a transport with room for fewer datagrams than it has families it MUST prefer
/// the longest-blocked one. This is what makes the core's per-family scheduling
/// sufficient: the core says WHEN the stalest family is due, and the driver hands
/// that family the next free slot, so neither side needs to know anything new
/// about the other. A driver that always filled the same family first would
/// starve the other one no matter what the core scheduled — and because every
/// round would then be partial, the core would refresh each family at twice the
/// periodic interval, past the TTL that interval is a fraction of, while every
/// per-round invariant still held.
///
/// A family that keeps refusing is never written off by the driver. Link health
/// is the driver's to observe and report to ITS OWN caller; it is no input to
/// what the core is told. Bounding how long the lifecycle waits for a chronically
/// missing family is the core's own patience, applied inside the confirm.
///
/// # Readiness and completion drivers
///
/// [`WouldBlock`](Self::WouldBlock) belongs to READINESS I/O, where nothing was
/// handed to the kernel and abandoning the send is a fact rather than a guess. A
/// COMPLETION driver submits its operation before it waits, so a cancelled wait
/// leaves a datagram whose fate is unknown, and it must await every send to
/// completion instead. That half of the asymmetry is a buffer-ownership rule the
/// core can neither observe nor enforce, so the variant is simply VACUOUS for a
/// completion driver rather than forbidden to it. There is deliberately no
/// "which kind am I" declaration: there is nowhere to make it and nothing the
/// core could do with it.
///
/// Deliberately NOT `#[non_exhaustive]`: a future outcome must break every
/// driver's match and force it to report the new fact, rather than silently
/// inheriting a wildcard arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FamilyAttempt<I> {
  /// This family's transport accepted the datagram, at `at`.
  ///
  /// `at` is that family's OWN instant, read BEFORE the syscall that accepted
  /// it. Pre-syscall is the required direction: the core anchors this family's
  /// refresh schedule here, and an anchor at or before the true acceptance can
  /// only ever UNDERSTATE how fresh that family's peers are, while a late one
  /// would push the next refresh past the records' own TTL.
  ///
  /// It is emphatically not the fan-out's post-send instant, and it is not the
  /// instant a driver's own send gate records (which must be POST-send-call,
  /// since that one measures spacing on the egress path and nothing bounds the
  /// delay between a pre-send clock read and the send). The two are wrong in
  /// opposite directions and are not interchangeable.
  ///
  /// How close that post-send reading is to the WIRE is a property of the
  /// transport rather than of the discipline: where the send call hands the
  /// datagram to the kernel it is the wire for every purpose here, while on a
  /// transport whose send call only ENQUEUES the closest observable point is the
  /// enqueue. See [`Transmit::min_family_gap`] for what such a driver's gate does
  /// and does not bound.
  ///
  /// The core folds the pair: a confirm is anchored at the EARLIEST acceptance
  /// across families. Handing over one already-folded instant is what used to
  /// leave that interpretation in the driver.
  Accepted {
    /// This family's own pre-syscall acceptance instant.
    at: I,
  },
  /// This family's transport had the datagram and refused it. The bytes
  /// provably did not go out on this family.
  ///
  /// # `permanent` is proved by the SIZE and never by the errno (normative)
  ///
  /// `permanent` says the identical bytes re-offered to the identical transport
  /// would be refused identically, forever. A driver may set it only from a
  /// comparison against its transport's own hard carry ceiling — for a UDP
  /// socket driver, `body.len()` against
  /// [`MAX_UDP_PAYLOAD_V4`](crate::constants::MAX_UDP_PAYLOAD_V4) /
  /// [`MAX_UDP_PAYLOAD_V6`](crate::constants::MAX_UDP_PAYLOAD_V6); for a driver
  /// whose binding ceiling is its socket buffer, that buffer. It must NEVER be
  /// set from an errno.
  ///
  /// An errno cannot prove permanence: Linux UDP answers `EMSGSIZE` both for a
  /// payload past the hard maximum, which is permanent, and for a write past the
  /// currently-known path MTU with `DF` set, which the next attempt may get past
  /// after an MTU probe or a route change (udp(7), ip(7) `IP_MTU_DISCOVER`). One
  /// errno, two meanings — and reading the transient one as permanent retires a
  /// healthy service over a link whose MTU just dropped. Nor can a table of
  /// errnos prove impossibility: a platform it lists wrongly answers "not
  /// permanent" for a datagram that is genuinely impossible, and the producer
  /// re-arms it until the process ends.
  ///
  /// The refusal is still required — it is what proves these bytes did not go
  /// out — but WHICH refusal it was decides nothing. Every refusal of a datagram
  /// within the ceiling is `permanent: false`, `EMSGSIZE` included, and that is
  /// the cheap direction: a retry costs one datagram per round, a wrong
  /// retirement costs the producer.
  ///
  /// The core cannot compute the ceiling universally — it differs per transport
  /// and is not a protocol quantity — which is why this one bit crosses the
  /// boundary rather than the datagram's size.
  Refused {
    /// Whether the refusal is proved permanent by the datagram's size against
    /// this transport's hard carry ceiling.
    permanent: bool,
  },
  /// The core's own minimum-gap gate declined this family for this round, so no
  /// syscall was made.
  ///
  /// The gate VALUE is protocol policy and arrives on
  /// [`Transmit::min_family_gap`]; only the driver holds the egress instants that
  /// say whether it has elapsed. Obligated and did not carry the datagram — the
  /// core re-arms losslessly, and the gate is open by the time the re-armed
  /// datagram is due.
  GateShut,
  /// This family has no bound socket, so it was never offered the datagram.
  NoSocket,
  /// The datagram was not addressed to this family — the family a unicast
  /// destination did not select, which on a dual-stack host is reported even
  /// though that socket is bound and healthy.
  ///
  /// Distinct from [`NoSocket`](Self::NoSocket) because the two differ in the
  /// I/O world even where the core reads them alike, and because a withdrawal's
  /// debt table must be able to tell "there is nobody on this family to retract
  /// from" apart from "this particular datagram was not for it".
  NotAddressed,
  /// A readiness transport was not writable, so NOTHING was submitted.
  ///
  /// Definitive rather than unknown, which is exactly why it is distinct from
  /// [`Refused`](Self::Refused): no error occurred and no kernel holds the
  /// datagram, so it is neither evidence about the link nor a candidate for a
  /// permanence claim. See the type-level note on completion drivers, for which
  /// this variant is vacuous.
  WouldBlock,
}

impl<I> FamilyAttempt<I> {
  /// Canonical lowercase slug, for a driver's own tracing.
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Accepted { .. } => "accepted",
      Self::Refused { permanent: true } => "refused_permanent",
      Self::Refused { permanent: false } => "refused",
      Self::GateShut => "gate_shut",
      Self::NoSocket => "no_socket",
      Self::NotAddressed => "not_addressed",
      Self::WouldBlock => "would_block",
    }
  }

  /// THE projection, and the whole of what the presence trichotomy means.
  ///
  /// * A family with no socket, or one this datagram was not addressed to, was
  ///   never OBLIGATED: its absence is not a failure and it owes nothing. This
  ///   is the collapse that must never happen in the other direction — a
  ///   single-stack host folded into `Missed` looks permanently behind on a
  ///   family it never had, and a scheduler chasing the stalest family then
  ///   re-announces at the RFC 6762 §8.3 one-second floor forever.
  /// * An acceptance is a delivery, and nothing else is. A refusal, a shut gate
  ///   and an unwritable socket are all `Missed`: the family had the datagram
  ///   and did not carry it. How long the lifecycle waits for such a family is
  ///   the core's own patience (`MAX_PARTIAL_ROUNDS`), spent on an excused
  ///   advance that takes none of the credit a delivery earns.
  ///
  /// A permanently-refused family is `Missed` like any other, and deliberately:
  /// "and there is no point re-arming it" is a different question, answered by
  /// [`Self::undeliverable`] and weighed against the datagram's
  /// [`TransmitObligation`].
  #[inline(always)]
  #[allow(dead_code)]
  pub(crate) const fn delivery(&self) -> FamilyDelivery {
    match self {
      Self::Accepted { .. } => FamilyDelivery::Delivered,
      Self::Refused { .. } | Self::GateShut | Self::WouldBlock => FamilyDelivery::Missed,
      Self::NoSocket | Self::NotAddressed => FamilyDelivery::Unobligated,
    }
  }
}

/// The core-side half: the projection, the anchor fold, and the retirement
/// predicate. `#[allow(dead_code)]` per item because the bare no-heap tier
/// compiles the VOCABULARY but no state machine to read it with — the same
/// reason `service::schedule` carries the attribute.
#[allow(dead_code)]
impl<I: Instant> FamilyAttempt<I> {
  /// This family's acceptance instant, if it accepted.
  #[inline(always)]
  const fn accepted_at(&self) -> Option<I> {
    match self {
      Self::Accepted { at } => Some(*at),
      _ => None,
    }
  }

  /// The core's per-family confirm, projected from one round's pair of attempts.
  #[inline(always)]
  pub(crate) const fn project(v4: Self, v6: Self) -> TransmitDelivery {
    TransmitDelivery::new(v4.delivery(), v6.delivery())
  }

  /// THE confirm anchor: the EARLIEST instant at which any family accepted this
  /// datagram, or `fallback` when none did.
  ///
  /// The min-fold lives here rather than in each driver because it IS an
  /// interpretation — it decides what "this datagram's peers are this fresh"
  /// means under partial delivery. Earliest is the only safe fold: it can only
  /// understate how fresh a family's peers are, so the next refresh lands sooner
  /// than strictly needed, whereas the latest (or a post-fan-out clock read)
  /// would backdate every family's freshness by however long the slowest one
  /// took and push a healthy family's refresh past its records' TTL.
  ///
  /// `fallback` is the driver's own instant for a round that reached no wire:
  /// there is no acceptance to anchor, so the re-arm is spaced from the attempt.
  /// The core reads no clock, so it cannot supply one itself.
  #[inline(always)]
  pub(crate) fn anchor(v4: Self, v6: Self, fallback: I) -> I {
    match (v4.accepted_at(), v6.accepted_at()) {
      (Some(a), Some(b)) => {
        if a <= b {
          a
        } else {
          b
        }
      }
      (Some(a), None) | (None, Some(a)) => a,
      (None, None) => fallback,
    }
  }

  /// Whether these attempts PROVE that no later offer of the identical bytes can
  /// ever reach a wire.
  ///
  /// "At least one family refused them permanently, and every other family was
  /// never offered them." A family with no socket, or one the datagram was not
  /// addressed to, is no evidence either way — a single-stack host that
  /// permanently refuses an oversized datagram on its one family has refused it
  /// on every family it has.
  ///
  /// # Which way each error direction cuts
  ///
  /// Too EAGER would read a transient refusal as permanent and destroy a healthy
  /// advertisement over a full send buffer, so every may-clear outcome vetoes it
  /// outright: [`Refused { permanent: false }`](Self::Refused),
  /// [`GateShut`](Self::GateShut) — whose next round carries the SAME datagram —
  /// and [`WouldBlock`](Self::WouldBlock). [`Accepted`](Self::Accepted) vetoes it
  /// trivially. A round mixing a permanent refusal with a transient one is
  /// therefore `false`, and the transient family is waited for.
  ///
  /// Too LAX would leave a [`TransmitObligation::Sustained`] producer re-arming a
  /// datagram no transport can ever carry, until the process ends. That is a
  /// liveness defect, not wire noise: no patience bound rescues it, because the
  /// core's patience excuses a MISSING family rather than a round that can
  /// succeed on none of them.
  ///
  /// It says nothing on its own about what to DO. Only
  /// [`TransmitObligation`] tells a lost one-shot reply — one unanswered
  /// question, and the querier re-asks — apart from a producer that can never
  /// make progress. The confirm weighs the two and answers with
  /// [`TransmitConfirm::retire_producer`].
  #[inline(always)]
  pub(crate) const fn undeliverable(v4: Self, v6: Self) -> bool {
    let mut any_permanent = false;
    // A `const fn` cannot iterate an array of a generic type here, so the pair is
    // matched explicitly. The two arms are identical by construction.
    match v4 {
      Self::Refused { permanent: true } => any_permanent = true,
      Self::NoSocket | Self::NotAddressed => {}
      _ => return false,
    }
    match v6 {
      Self::Refused { permanent: true } => any_permanent = true,
      Self::NoSocket | Self::NotAddressed => {}
      _ => return false,
    }
    any_permanent
  }
}

/// What the core made of one round of [`FamilyAttempt`]s — the two facts a
/// driver must act on after handing a confirm over.
///
/// Both are the CORE's conclusions, not the driver's own reading of what it just
/// reported. A driver that re-derived either from its attempts would be back to
/// keeping a second implementation of the projection.
///
/// [`Default`] is "nothing to act on" — neither delivered nor retiring — which is
/// what a confirm for a producer that no longer exists resolves to.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct TransmitConfirm {
  any_delivered: bool,
  retire_producer: bool,
}

impl TransmitConfirm {
  /// Neither delivered nor retiring: the confirm resolved no commit token (the
  /// producer had none pending, or is already finished).
  #[allow(dead_code)]
  pub(crate) const NOTHING: Self = Self::new(false, false);

  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(any_delivered: bool, retire_producer: bool) -> Self {
    Self {
      any_delivered,
      retire_producer,
    }
  }

  /// At least one obligated family accepted the datagram, so peers reachable
  /// over that family may now hold the records it carried.
  ///
  /// This is the RFC 6762 §10.1 goodbye-ownership fact, and a driver needs it to
  /// mirror a service's CONFIRMED-ADVERTISED host set back onto its endpoint
  /// route. It is emphatically NOT the all-delivered fact the reclaim-cancel gate
  /// turns on — that one is
  /// [`Service::has_fully_announced`](crate::Service::has_fully_announced), which
  /// has no public constructor precisely so the substitution cannot compile.
  #[inline(always)]
  pub const fn any_delivered(self) -> bool {
    self.any_delivered
  }

  /// No transport can ever carry this datagram AND the core will keep re-arming
  /// it: the producing service or query must be retired.
  ///
  /// The core owns this decision because it owns both halves of it — the proof
  /// that the bytes can never go out (every family that was offered them refused
  /// their SIZE) and the obligation that says whether they will be offered again
  /// ([`TransmitObligation`]). A [`TransmitObligation::OneShot`] reply that
  /// cannot be sent is never retired: it costs exactly one unanswered question,
  /// and retiring on one would let any peer tear down a healthy established
  /// service by asking it something whose answer does not fit.
  ///
  /// The confirm itself has already resolved the commit token and latched
  /// nothing, so the retirement a driver performs on this runs AFTER a settled
  /// confirm rather than instead of one — a §10.1 goodbye built from a service
  /// the core still considered mid-datagram would retract records no confirm had
  /// latched.
  ///
  /// What "retire" means is the driver's own: surface the terminal the caller
  /// can act on, stop driving the producer, and let the endpoint's withdrawal
  /// release the name.
  #[inline(always)]
  pub const fn retire_producer(self) -> bool {
    self.retire_producer
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
/// # Internal by construction
///
/// This is the CORE's reading of a round, reached only through
/// [`FamilyAttempt::delivery`]. It is deliberately unnameable from outside the
/// crate: a driver able to name a `FamilyDelivery` is a driver able to launder
/// one outcome into another, which is the whole class of defect the
/// [`FamilyAttempt`] vocabulary exists to make unrepresentable.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, derive_more::Display)]
#[display("{}", self.as_str())]
pub(crate) enum FamilyDelivery {
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
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn as_str(&self) -> &'static str {
    match self {
      Self::Unobligated => "unobligated",
      Self::Delivered => "delivered",
      Self::Missed => "missed",
    }
  }
}

cfg_heap! {
  /// WHICH address family — the index half of the crate's `[_; 2]` family pairs,
  /// named so a runtime choice between them never becomes a runtime index.
  ///
  /// Every per-family fact in this crate is a two-element array with `[0] = v4`
  /// and `[1] = v6` (`FamilyPatience`, `last_delivered`, a withdrawal item's
  /// `owed`, the goodbye-ownership masks). Reading one of those with a `usize`
  /// computed at runtime is both a `clippy::indexing_slicing` site and a place a
  /// v4/v6 mix-up cannot be caught, so the choice is a value with one accessor
  /// instead.
  ///
  /// Gated to the heap tier: every caller (`Endpoint`'s route/relinquished-screen
  /// code, and `Service`'s own family-scoped withdrawal helpers) lives inside
  /// `cfg_heap!` itself, so the bare tier never names this type.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) enum Family {
    /// IPv4 — slot `[0]`.
    V4,
    /// IPv6 — slot `[1]`.
    V6,
  }

  impl Family {
    /// The family a datagram arriving from `src` came in on.
    ///
    /// THE inbound family question. A multicast datagram travels back over a
    /// socket of its own family, so this is what says which of our transmissions
    /// could possibly be an echo of it.
    #[inline(always)]
    pub(crate) const fn of(src: core::net::SocketAddr) -> Self {
      match src {
        core::net::SocketAddr::V4(_) => Self::V4,
        core::net::SocketAddr::V6(_) => Self::V6,
      }
    }

    /// This family's half of a `[v4, v6]` pair.
    #[inline(always)]
    pub(crate) fn pick<T: Copy>(self, pair: [T; 2]) -> T {
      let [v4, v6] = pair;
      match self {
        Self::V4 => v4,
        Self::V6 => v6,
      }
    }

    /// This family's half of a `[v4, v6]` pair, by reference — for the pairs whose
    /// members are not `Copy`.
    #[inline(always)]
    pub(crate) fn pick_ref<T>(self, pair: &[T; 2]) -> &T {
      let [v4, v6] = pair;
      match self {
        Self::V4 => v4,
        Self::V6 => v6,
      }
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
pub(crate) struct TransmitDelivery {
  /// Indexed [v4, v6]. Private so the shape stays an implementation detail while
  /// the public surface names the families, matching
  /// [`Endpoint::note_withdrawal_result`](crate::Endpoint::note_withdrawal_result).
  families: [FamilyDelivery; 2],
}

#[allow(dead_code)]
impl TransmitDelivery {
  /// Report what each family did with this datagram.
  #[inline(always)]
  pub(crate) const fn new(v4: FamilyDelivery, v6: FamilyDelivery) -> Self {
    Self { families: [v4, v6] }
  }

  /// What the IPv4 family did with this datagram. `#[cfg(test)]`: the core
  /// reads the pair through [`Self::families`], and only the projection tests
  /// name one side of it.
  #[cfg(test)]
  #[inline(always)]
  pub(crate) const fn v4(&self) -> FamilyDelivery {
    self.families[0]
  }

  /// What the IPv6 family did with this datagram. `#[cfg(test)]`: the core
  /// reads the pair through [`Self::families`], and only the projection tests
  /// name one side of it.
  #[cfg(test)]
  #[inline(always)]
  pub(crate) const fn v6(&self) -> FamilyDelivery {
    self.families[1]
  }

  /// At least one obligated family accepted the datagram, so peers reachable over
  /// that family may now hold the records it carried.
  ///
  /// This is the goodbye-ownership fact (RFC 6762 §10.1): ownership latches iff
  /// this is `true`.
  #[inline(always)]
  pub(crate) const fn any_delivered(&self) -> bool {
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
  pub(crate) const fn all_delivered(&self) -> bool {
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

  /// WHICH families accepted the datagram, as a `[v4, v6]` mask.
  ///
  /// The finer form of [`Self::any_delivered`], and the one goodbye ownership
  /// latches with: a record reaches only the peers of the families that actually
  /// carried it, so "we advertised this record" is a per-family fact and
  /// collapsing it loses the only evidence that says an IPv6 arrival cannot be
  /// an echo of an IPv4-only transmission.
  #[inline(always)]
  pub(crate) const fn delivered_on(&self) -> [bool; 2] {
    [
      matches!(self.families[0], FamilyDelivery::Delivered),
      matches!(self.families[1], FamilyDelivery::Delivered),
    ]
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
#[allow(dead_code)]
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

  /// One pair of [`FamilyAttempt`]s that projects onto this delivery shape, so a
  /// lifecycle test can name the shape it is about rather than an I/O outcome it
  /// is not.
  ///
  /// The chosen preimage is the DULLEST one: a miss is a transient refusal and an
  /// absence is a missing socket, so no fixture can accidentally prove a datagram
  /// undeliverable or trip the retirement decision. Tests that are about the
  /// projection, the anchor fold, or retirement build their attempts explicitly.
  pub(crate) const fn as_attempts<I: Instant>(self, at: I) -> (FamilyAttempt<I>, FamilyAttempt<I>) {
    const fn one<I: Instant>(d: FamilyDelivery, at: I) -> FamilyAttempt<I> {
      match d {
        FamilyDelivery::Delivered => FamilyAttempt::Accepted { at },
        FamilyDelivery::Missed => FamilyAttempt::Refused { permanent: false },
        FamilyDelivery::Unobligated => FamilyAttempt::NoSocket,
      }
    }
    (one(self.families[0], at), one(self.families[1], at))
  }
}

#[cfg(test)]
mod tests;

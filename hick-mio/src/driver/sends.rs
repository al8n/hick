//! Per-family delivery reporting for every datagram this driver produces: the
//! self-send credit each fan-out earns, the per-family wire gate it must honour,
//! and the link-health signal the caller reads through
//! [`Mdns::degraded_families`](crate::Mdns::degraded_families).
//!
//! # Nothing is parked, so nothing is guessed
//!
//! Every send this driver makes resolves **within the call that made it**. A
//! `send_to` that returns `WouldBlock` handed nothing to the kernel, so
//! abandoning it is a fact rather than a guess: the family did not carry the
//! datagram, [`Sockets::send_one`] says so, and the core is told so at once.
//!
//! That licence is a property of *readiness* I/O. A completion-based driver
//! submits its operation before it waits, so a cancelled wait leaves a datagram
//! whose fate is unknown — which is why `hick-compio` awaits every send to
//! completion and this driver does not. The asymmetry is deliberate. Deferring a
//! confirm past its own tick is also what a parked-send table would reintroduce,
//! and with it an in-flight datagram racing an RFC 6762 §9 rename, a late
//! completion flushing a replacement service's name, and a self-send credit
//! stamped at queue time rather than at the syscall. There is no pending table
//! here, and there must not be one.
//!
//! # Self-send credit
//!
//! Taken per **family**, at the instant that family's syscall succeeded, and
//! only for a datagram sent to a multicast group this endpoint joined — see
//! [`SendReport::loops_back`]. A multicast transmit is two syscalls and two
//! loopback copies, so one credit per logical transmit would leave the second
//! copy uncredited and the responder would raise a phantom conflict against
//! itself.
//!
//! # The `mdns-proto` boundary
//!
//! This module reports the honest per-family shape of the fan-out and makes
//! **no** protocol decision. [`TransmitDelivery::any_delivered`] is the §10.1
//! goodbye-ownership fact and [`TransmitDelivery::all_delivered`] is the
//! lifecycle fact; the core owns both, and it owns its own patience for a family
//! that keeps missing. There is no driver-side partial-round bound here and
//! there must not be one: laundering a partial into an all-delivered confirm
//! would leave the core applying its patience to a fact that had already been
//! excused once.
//!
//! The **obligated set** the driver owns is a fact about SOCKETS, not about link
//! quality: a family is unobligated when there is no socket for it, or when this
//! datagram was not addressed to it. Nothing else may shrink it, and in
//! particular no amount of failing may — see
//! [`MAX_CONSECUTIVE_SEND_FAILURES`], which is a health signal for the caller
//! and no part of what the core is told.

use std::{
  net::SocketAddr,
  time::{Duration, Instant as StdInstant},
};

use mdns_proto::{FamilyDelivery, TransmitDelivery};

use crate::{
  selfsend::SelfSendTracker,
  socket::{Family, FamilyAdmission, SendOutcome, SendReport, Sockets},
};

/// Consecutive non-deliveries on one family before this driver calls that family
/// **degraded**.
///
/// Purely a health and observability signal. It reaches
/// [`Mdns::degraded_families`](crate::Mdns::degraded_families) and a warn line,
/// and it reaches **nothing the core is told**.
///
/// # The division, and why it is not negotiable
///
/// The driver reports honest per-family facts and owns LINK HEALTH. The core
/// owns PATIENCE and decides when a family stops holding a phase back. This
/// constant is the seam, and the seam is structural: [`summarize`] does not take
/// a [`SendHealth`], so no degradation can turn one [`FamilyDelivery`] into
/// another. A present-but-failing family is [`FamilyDelivery::Missed`] on its
/// thousandth consecutive failure exactly as on its first.
/// [`FamilyDelivery::Unobligated`] means what the core says it means — no socket
/// for this family, or a datagram not addressed to it — and a wire that keeps
/// refusing is neither.
///
/// **Do not reconnect them.** Reporting a failing family `Unobligated` reads to
/// the core as "this family owes nothing", which is what an ABSENT socket
/// reports. The core's `classify_advance` then clears that family's missed
/// count, marks it covered, and the round satisfies
/// [`TransmitDelivery::all_delivered`] on the strength of the one family that
/// did deliver. That is the `Delivered` advance, which sets
/// [`Service::has_fully_announced`](mdns_proto::Service::has_fully_announced),
/// counts a delivered datagram, and resets the RFC 6762 §8.3 ladder.
/// `has_fully_announced` is the reclaim-cancel gate and its entire content is
/// the assertion that EVERY obligated link heard a complete announcement — so a
/// driver able to shrink the obligated set on its own opens that gate for a
/// family that heard nothing. The opaque proof type exists to make precisely
/// that unrepresentable.
///
/// # The write-off would be redundant even if it were sound
///
/// A chronically-missing family does not pin the lifecycle. The core's own
/// `MAX_PARTIAL_ROUNDS` patience advances the phase past it as `Excused`, and
/// that escape is deliberately asymmetric with the one above: it advances the
/// phase and NOTHING else — no announcement proof, no delivered-datagram count,
/// no ladder reset. The core already solves this, and correctly. There is
/// nothing here for a driver-side bound to add.
///
/// # Choosing the threshold
///
/// Low on purpose, because the only cost of tripping it early is a caller told
/// sooner about a link that was briefly blipping. Three consecutive failures is
/// past any single blip — a probe sequence is 250 ms apart, so this is most of a
/// second of a family failing every time.
///
/// Only a resolution that reached no link counts, and only one that is evidence
/// about the link: a hard send error or a refused `send_to`. A family the wire
/// gate held back ([`SendOutcome::Gated`]) is **not** charged — no syscall was
/// made and the deferral is this driver's own — and neither is a family with no
/// socket, which owes nothing.
///
/// Recovery is immediate and needs no separate edge: one delivery clears the
/// streak and the degradation with it.
pub(crate) const MAX_CONSECUTIVE_SEND_FAILURES: u32 = 3;

/// Index of the IPv4 family in every per-family array, matching
/// [`TransmitDelivery`]'s own ordering.
pub(crate) const FAMILY_V4: usize = 0;
/// Index of the IPv6 family.
pub(crate) const FAMILY_V6: usize = 1;

/// One family's recent delivery record, and whether that record is currently bad
/// enough to report.
#[derive(Debug, Clone, Copy, Default)]
struct FamilyStanding {
  failures: u32,
  degraded: bool,
}

/// Each family's send-side standing: how badly it is currently failing.
///
/// **Observability only.** It feeds
/// [`Mdns::degraded_families`](crate::Mdns::degraded_families) and the warn
/// lines below, and it is deliberately not an input to [`summarize`] — see
/// [`MAX_CONSECUTIVE_SEND_FAILURES`] for why the two halves stay severed.
///
/// All that survives of the old send ledger. The pending table, the completion
/// tokens and the parked-send deadline went with the parking they existed to
/// account for; a send now resolves inside the call that made it.
#[derive(Debug, Default)]
pub(crate) struct SendHealth {
  v4: FamilyStanding,
  v6: FamilyStanding,
}

impl SendHealth {
  /// Both families in good standing, which is what a freshly bound pair is.
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// Which families have failed to deliver often enough in a row to report to
  /// the caller. It holds no family back from anything.
  pub(crate) const fn degraded_families(&self) -> (bool, bool) {
    (self.v4.degraded, self.v6.degraded)
  }

  const fn standing_mut(&mut self, family: Family) -> &mut FamilyStanding {
    match family {
      Family::V4 => &mut self.v4,
      Family::V6 => &mut self.v6,
    }
  }

  /// Fold one fan-out into every family's standing.
  ///
  /// Its order against [`summarize`] is immaterial, and that is the point:
  /// `summarize` cannot read what this leaves behind, so the same fan-out
  /// projects identically whether or not it tripped a degradation.
  ///
  /// `pub(crate)` because the RFC 6762 §10.1 withdrawal pump sends through
  /// [`Sockets::send_one`] directly (it always fans to both groups regardless of
  /// the destination the endpoint hands back) and its sends are evidence about
  /// the link like any other.
  pub(crate) fn note_fanout(&mut self, report: SendReport) {
    for (family, outcome) in report.per_family() {
      match outcome {
        SendOutcome::Sent { .. } => self.note_delivered(family),
        // A refusal is a refusal: an oversized datagram this socket will never
        // carry is as much a non-delivery on this link as a full send buffer.
        // What separates them is what the PRODUCER does about it, which is no
        // part of a health streak.
        SendOutcome::Failed | SendOutcome::TooLarge => self.note_failed(family),
        // Neither is evidence about the link: one has no socket, the other is
        // this driver's own deliberate spacing.
        SendOutcome::Gated | SendOutcome::NoSocket => {}
      }
    }
  }

  fn note_delivered(&mut self, family: Family) {
    let standing = self.standing_mut(family);
    let recovered = standing.degraded;
    standing.failures = 0;
    standing.degraded = false;
    if recovered {
      hick_trace::warn!(
        via_v4 = family.is_v4(),
        "a degraded family delivered again; it is no longer reported degraded"
      );
    }
  }

  fn note_failed(&mut self, family: Family) {
    let standing = self.standing_mut(family);
    standing.failures = standing.failures.saturating_add(1);
    if standing.degraded || standing.failures < MAX_CONSECUTIVE_SEND_FAILURES {
      return;
    }
    standing.degraded = true;
    hick_trace::warn!(
      via_v4 = family.is_v4(),
      failures = standing.failures,
      "a family has failed to deliver too many times in a row; it is still \
       offered every datagram and still reported missed, and `degraded_families` \
       now says so"
    );
  }
}

/// What one fan-out settled: the per-family confirm, the fairness charge, and
/// the instant to anchor the confirm at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SendSummary {
  /// Families that actually put bytes on a wire. Feeds
  /// [`datagram_cost`](crate::driver::datagram_cost) and nothing else — it is
  /// **not** the delivery verdict: one datagram that reached one of two
  /// obligated families costs one credit yet has discharged no obligation.
  pub(crate) sent: usize,
  /// The honest per-family result, to be handed to the core verbatim.
  pub(crate) delivery: TransmitDelivery,
  /// The **earliest** instant at which some family accepted the datagram, or
  /// `None` when none did.
  ///
  /// The core anchors each delivered family's refresh schedule at the confirm
  /// instant, so a clock read taken after the fan-out would record a family
  /// served at `t0` as having been served when the slower family finished, and
  /// its next refresh would land a whole fan-out later than its records' TTL
  /// allows. Taking the earliest can only ever understate how fresh a family's
  /// peers are, which is the safe direction.
  pub(crate) accepted_at: Option<StdInstant>,
  /// Every reachable family rejected this datagram as permanently too large, so
  /// re-offering these exact bytes can never put them on a wire. See
  /// [`SendReport::undeliverable`], which decides it, and
  /// [`Mdns::drain_transmits`](crate::Mdns::tick) — the one consumer — for the
  /// obligation it is weighed against.
  ///
  /// **Not a delivery verdict, and not an input to one.** `delivery` above is
  /// the same honest per-family shape either way: an undeliverable round is
  /// `Missed` on every family that has a socket, exactly as a refused one is.
  /// This rides alongside so the caller can ask a question the core's vocabulary
  /// has no room for — *is there any point re-arming this datagram* — without
  /// any of it reaching the confirm.
  pub(crate) undeliverable: bool,
}

/// One PRODUCER's per-family earliest-next-send gate: when each address family
/// (`[FAMILY_V4, FAMILY_V6]`) last carried a gated datagram from this service or
/// query.
///
/// The rule it enforces is RFC 6762's, on the wire: §6 and §8.3 forbid
/// re-multicasting a record on an interface inside one second of the last time
/// it went out on that same interface, and §8.1 spaces probes 250 ms apart. The
/// MINIMUM is protocol policy and arrives from the core on
/// [`Transmit::min_family_gap`](mdns_proto::Transmit::min_family_gap); only the
/// driver knows when each family last satisfied it, which is why the two halves
/// live on opposite sides of the sans-I/O seam. **Nothing here may hardcode the
/// value** — doing so would take protocol policy into the driver and get the
/// probe sequence wrong by a factor of four.
///
/// It cannot be folded into the core's schedule because the confirm anchors at
/// the EARLIEST acceptance across families. That anchor is the right one for the
/// TTL guarantee — it can only understate how fresh a family's peers are — but
/// under inter-family skew `s` it schedules the next datagram one interval after
/// the EARLY family's wire time, leaving the late family a gap of
/// `interval − s`. The core cannot see `s`; the driver measured it.
///
/// Kept PER PRODUCER because the rules are per record set: two different
/// services announcing inside the same second are two different records and pace
/// each other not at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FamilyWireGate {
  /// Indexed `[v4, v6]`. `None` until that family has carried a GATED datagram
  /// from this producer — an ungated (one-shot) send never writes here, so a §6
  /// reply cannot defer the announcement that follows it.
  last_sent: [Option<StdInstant>; 2],
}

impl FamilyWireGate {
  /// Whether family `idx` may be offered a datagram at `now` under `min_gap`.
  ///
  /// A zero `min_gap` is ungated and always open. A family that has carried
  /// nothing yet is open. A clock that reads BEFORE the recorded send closes the
  /// gate: the elapsed gap is then unknown, and the conservative answer is the
  /// one that cannot put a record back on the wire too soon.
  fn open(&self, idx: usize, now: StdInstant, min_gap: Duration) -> bool {
    if min_gap.is_zero() {
      return true;
    }
    match self.last_sent.get(idx).copied().flatten() {
      Some(last) => now
        .checked_duration_since(last)
        .is_some_and(|gap| gap >= min_gap),
      None => true,
    }
  }

  /// [`FamilyWireGate::open`] for both families at one instant, for the gate
  /// tests that are about the arithmetic rather than about when it is asked.
  ///
  /// `#[cfg(test)]` permanently, and this is the only composition of the two
  /// families that exists anywhere. Production asks each family at its own offer
  /// through [`WireGate`]; a value holding both answers is exactly what
  /// [`FamilyAdmission`] exists to keep out of a send path.
  #[cfg(test)]
  fn allow_at(&self, now: StdInstant, min_gap: Duration) -> [bool; 2] {
    [
      self.open(FAMILY_V4, now, min_gap),
      self.open(FAMILY_V6, now, min_gap),
    ]
  }

  /// Record that family `idx` put a GATED datagram on its wire at `at`.
  ///
  /// Two things `at` must be, and both are load-bearing:
  ///
  /// * that family's OWN instant, not the fan-out's confirm anchor — recording
  ///   the anchor would re-introduce exactly the skew this gate exists to
  ///   absorb;
  /// * its POST-syscall instant ([`SendOutcome::wire_time`]), not the
  ///   pre-syscall one the core confirms at. Nothing bounds the gap between a
  ///   pre-syscall clock read and the syscall itself, and a stamp taken on the
  ///   near side of a preemption hands that whole stall back to the next
  ///   datagram's spacing.
  ///
  /// The core's own confirm anchor is a pre-syscall instant and correctly so;
  /// the two are wrong in opposite directions and are not interchangeable.
  fn record(&mut self, idx: usize, at: StdInstant, min_gap: Duration) {
    if min_gap.is_zero() {
      return;
    }
    if let Some(slot) = self.last_sent.get_mut(idx) {
      *slot = Some(at);
    }
  }

  /// Fold one fan-out's WIRE instants back into the gate.
  fn note(&mut self, report: SendReport, min_gap: Duration) {
    for (family, outcome) in report.per_family() {
      if let Some(at) = outcome.wire_time() {
        self.record(family.index(), at, min_gap);
      }
    }
  }
}

/// One producer's [`FamilyWireGate`] as a per-family admission: the **only**
/// clock-reading [`FamilyAdmission`] in this crate.
///
/// The clock is read inside [`FamilyAdmission::admits`], so the gap each family
/// is weighed against is the one that wire has actually had at the moment the
/// datagram is offered to *it*. That is the whole difference from the `[bool;
/// 2]` this replaces, and it is one-directional: with `last_sent` fixed,
/// [`FamilyWireGate::open`] is monotone in `now`, and nothing records into the
/// gate during a fan-out — [`FamilyWireGate::note`] runs once, after both
/// families. So a per-family read taken later than a fan-out-wide one can only
/// ever flip Gated → open. It can never withhold a family the frozen mask would
/// have offered.
pub(crate) struct WireGate<'a> {
  gate: &'a FamilyWireGate,
  min_gap: Duration,
}

impl<'a> WireGate<'a> {
  /// `min_gap` is the core's own per-family minimum for this datagram's kind. A
  /// zero one is ungated; see [`FamilyWireGate::open`].
  pub(crate) const fn new(gate: &'a FamilyWireGate, min_gap: Duration) -> Self {
    Self { gate, min_gap }
  }
}

impl FamilyAdmission for WireGate<'_> {
  fn admits(&self, family: Family) -> bool {
    self
      .gate
      .open(family.index(), StdInstant::now(), self.min_gap)
  }
}

/// Send `body` to `dst` through `gate`, take the self-send credit of every
/// family that reached a wire, and report the per-family result.
///
/// One credit per **family**, never one per logical transmit: a multicast
/// destination fans out to both bound sockets, so one transmit is two syscalls
/// and two loopback copies. Recording a single credit would leave the second
/// copy uncredited — the tracker would ingest it as a peer datagram and the
/// responder would raise a phantom conflict against itself.
///
/// A **unicast** destination takes no credit at all: it does not go to a group
/// we joined, so no copy comes back and the credit could only ever expire
/// unclaimed. It is not merely wasted — the tracker is a linearly-scanned `Vec`
/// that at `MAX_SELF_SEND_ENTRIES` declines the NEW entry rather than evicting a
/// live one, so an on-link legacy-query flood would fill it with unclaimable
/// credits and then refuse the genuine multicast credits loopback suppression
/// depends on. The classification rides on the report `Sockets::send_to`
/// returns — the same test that decided the fan-out — so the credit and the
/// syscalls it accounts for can never disagree about what this datagram was.
///
/// `min_gap` is the core's own per-family minimum for this datagram's kind; a
/// family whose gap is unpaid is not offered the datagram and is reported
/// `Missed`. See [`FamilyWireGate`].
///
/// # It takes no instant, and the tick's is not a substitute for one
///
/// The gate is a **real-time** question — has this family's wire had its gap? —
/// so it is answered on a clock read at the offer, and the caller cannot supply
/// one. [`Mdns::tick`](crate::Mdns::tick)'s `now` is the tick's PROTOCOL instant
/// and is read before stages 1 through 3 and before every earlier datagram in
/// stage 4's own walk; handing it to the gate charges none of that elapsed time,
/// so a gap the wire has genuinely paid reads as unpaid and the family is
/// withheld. That is not a harmless conservatism: the family is reported
/// [`FamilyDelivery::Missed`], which spends the core's own partial-round
/// patience and delays the §8 phase for a wire that was ready.
///
/// # One read per family, and the older rule this overturns
///
/// This function used to read the clock **once** for the fan-out and hand
/// `send_to` a `[bool; 2]`, defended here in these terms: *"`allow` is one
/// decision about one datagram, and the two families must be weighed against the
/// same instant or the second would be offered a wider gap than the first for no
/// reason but syscall ordering."* That is withdrawn. It was the defect written
/// down, and it survived a round of review because it reads as a fairness
/// argument. Three things are wrong with it:
///
/// 1. **The gate was already per-family on its write side.**
///    [`FamilyWireGate::record`] insists `at` be that family's OWN instant and
///    refuses the fan-out's confirm anchor, because taking the anchor would
///    reintroduce the very skew this gate absorbs. A gate whose record side
///    refuses a fan-out-wide instant and whose decide side required one was
///    internally inconsistent, and the skew argument is the same argument on
///    both sides.
/// 2. **"A wider gap for no reason but syscall ordering" misnames the
///    quantity.** The second family's gap genuinely *is* wider when it is
///    offered, because time passed — the IPv4 syscall's time, plus any
///    preemption around it. Declining to charge elapsed time to a real-time
///    bound is this defect class stated in its own words.
/// 3. **The error was one-directional and landed on the expensive side.** A
///    frozen mask can only report a *ready* family gated, never a gated family
///    ready. `Gated` maps to [`FamilyDelivery::Missed`], which is no free
///    deferral: it spends the core's `MAX_PARTIAL_ROUNDS`, holds the §8 phase,
///    and on an announce round withholds the reclaim-cancel gate.
///
/// Each family is now asked at its own offer, inside [`Sockets::send_one`] and
/// immediately before that family's syscall — see [`WireGate`] and
/// [`FamilyAdmission`]. Nothing carries a decision from one family to the other.
pub(crate) fn send_and_credit(
  sockets: &mut Sockets,
  selfsend: &mut SelfSendTracker,
  health: &mut SendHealth,
  gate: &mut FamilyWireGate,
  body: &[u8],
  dst: SocketAddr,
  min_gap: Duration,
) -> SendSummary {
  let report = sockets.send_to(body, dst, &WireGate::new(gate, min_gap));
  if report.loops_back {
    for (family, outcome) in report.per_family() {
      // The wall stamp ORDERS the credit against its echo, and is pre-syscall so
      // it cannot outrun the kernel's receive stamp on a copy already looped
      // back. It is emphatically not an age: the credit takes no ageing anchor
      // here at all, because no anchor available inside this tick is a legal one
      // — stage 1 has already run, so nothing recorded now can be claimed before
      // the next tick opens the window. See `SelfSendTracker::seal`.
      if let Some(sent) = outcome.credit_stamp() {
        selfsend.record(family, body, sent);
      }
    }
  }
  gate.note(report, min_gap);
  // Health is a side channel to the caller, taken from the same report; it is
  // deliberately not an argument to `summarize`.
  health.note_fanout(report);
  summarize(report)
}

/// Project one fan-out onto the core's vocabulary.
///
/// It takes the [`SendReport`] and nothing else. No health table, no history,
/// nothing that could turn a link's CONDITION into a different protocol answer —
/// the signature is the guarantee, and [`MAX_CONSECUTIVE_SEND_FAILURES`] says
/// why it must stay that way. The mapping is one-to-one and nothing is
/// laundered:
///
/// * `NoSocket` is [`FamilyDelivery::Unobligated`], and is the ONLY thing that
///   is. It covers both of the core's cases — this driver has no socket for the
///   family, and the datagram was addressed to the other one — so the family was
///   never offered it and its absence is not a failure. A single-stack host is
///   fully delivered on the one family it has.
/// * `Sent` is [`FamilyDelivery::Delivered`], **including for a degraded
///   family**: a family that has quietly recovered really did put the records on
///   a wire, and peers reachable over it now hold them.
/// * `Gated`, `Failed` and `TooLarge` are [`FamilyDelivery::Missed`], however
///   long the family has been failing. Its socket is there and the datagram was
///   meant for it — the driver either owed the wire a gap it had not paid, or
///   the kernel refused it. Reporting any of them absent would hide it from the
///   core and let the phase advance without the family. How long the core waits
///   for such a family is the core's `MAX_PARTIAL_ROUNDS`, spent on an `Excused`
///   advance that takes none of the credit a delivery earns.
///
/// # `undeliverable` is carried, not projected
///
/// [`SendSummary::undeliverable`] leaves this mapping untouched: a datagram no
/// reachable socket can carry is still `Missed` on every family that has one.
/// The core's vocabulary has no way to say "and there is no point re-arming
/// it" — which is precisely why it must not be said in `delivery`, where the
/// only unused shape is `Unobligated` and that means an ABSENT socket. It rides
/// beside the confirm instead, and only [`Mdns::drain_transmits`](crate::Mdns::tick)
/// reads it, after the confirm has been spent.
fn summarize(report: SendReport) -> SendSummary {
  let mut sent = 0usize;
  let mut families = [FamilyDelivery::Unobligated; 2];
  let mut accepted_at: Option<StdInstant> = None;
  for (family, outcome) in report.per_family() {
    let delivery = match outcome {
      SendOutcome::Sent { .. } => {
        sent = sent.saturating_add(1);
        // `confirm_anchor`, never `wire_time`: the core's anchor is the
        // PRE-syscall instant, where early can only understate how fresh this
        // family's peers are, while a late one would schedule a refresh past its
        // records' TTL. The gate's anchor is the other one and reads the other
        // way round.
        if let Some(at) = outcome.confirm_anchor() {
          accepted_at = Some(accepted_at.map_or(at, |best: StdInstant| best.min(at)));
        }
        FamilyDelivery::Delivered
      }
      SendOutcome::Gated | SendOutcome::Failed | SendOutcome::TooLarge => FamilyDelivery::Missed,
      SendOutcome::NoSocket => FamilyDelivery::Unobligated,
    };
    if let Some(slot) = families.get_mut(family.index()) {
      *slot = delivery;
    }
  }
  SendSummary {
    sent,
    delivery: TransmitDelivery::new(families[FAMILY_V4], families[FAMILY_V6]),
    accepted_at,
    undeliverable: report.undeliverable(),
  }
}

#[cfg(test)]
mod tests;

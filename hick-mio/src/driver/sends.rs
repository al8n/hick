//! Per-family delivery reporting for every datagram this driver produces: the
//! self-send credit each fan-out earns, the per-family wire gate it must honour,
//! and the family-health policy that decides which families are still obligated.
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
//! What the driver *does* own is the **obligated set** — which families a
//! datagram was fanned onto, and which have been written off — and the core's
//! own documentation names a degraded family as one such write-off. That is
//! [`MAX_CONSECUTIVE_SEND_FAILURES`], reported through
//! [`Mdns::degraded_families`](crate::Mdns::degraded_families) because a caller
//! debugging "my peers do not see me over IPv6" must be able to see it.

use std::{
  net::SocketAddr,
  time::{Duration, Instant as StdInstant},
};

use mdns_proto::{FamilyDelivery, TransmitDelivery};

use crate::{
  selfsend::SelfSendTracker,
  socket::{Family, FamilyAllow, SendOutcome, SendReport, Sockets},
};

/// Consecutive non-deliveries on one family before it stops holding lifecycle
/// state back.
///
/// This is the driver's half of the [`TransmitDelivery`] contract — the
/// obligated set — and not a second patience bound: a family past this
/// threshold is reported [`FamilyDelivery::Unobligated`], the same thing an
/// absent socket reports, so the core is never told a family missed a round it
/// has stopped waiting for. The core's own `MAX_PARTIAL_ROUNDS` still governs
/// how long it waits for a family that *is* obligated.
///
/// Low on purpose. The cost of a threshold that is too high is a service stuck
/// in RFC 6762 §8.1 probing for as long as one family is broken; the cost of one
/// that is too low is a transmit confirmed while a briefly-blipping family
/// missed it. Three consecutive failures is past any single blip — a probe
/// sequence is 250 ms apart, so this is most of a second of a family failing
/// every time.
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

/// One family's recent delivery record and whether it is currently excused from
/// holding lifecycle state back.
#[derive(Debug, Clone, Copy, Default)]
struct FamilyStanding {
  failures: u32,
  degraded: bool,
}

/// Each family's send-side standing: how badly it is currently failing, and
/// whether it is still obligated to carry this driver's datagrams.
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

  /// Which families are currently excused from holding lifecycle state back.
  pub(crate) const fn degraded_families(&self) -> (bool, bool) {
    (self.v4.degraded, self.v6.degraded)
  }

  const fn standing(&self, family: Family) -> &FamilyStanding {
    match family {
      Family::V4 => &self.v4,
      Family::V6 => &self.v6,
    }
  }

  const fn standing_mut(&mut self, family: Family) -> &mut FamilyStanding {
    match family {
      Family::V4 => &mut self.v4,
      Family::V6 => &mut self.v6,
    }
  }

  /// Fold one fan-out into every family's standing.
  ///
  /// Health first, projection second — see [`summarize`], which reads the
  /// standing this leaves behind. A send that trips a family's degradation
  /// therefore excuses that same send, rather than being the one attempt that
  /// still has to be waited on before the escape valve opens.
  ///
  /// `pub(crate)` because the RFC 6762 §10.1 withdrawal pump sends through
  /// [`Sockets::send_one`] directly (it always fans to both groups regardless of
  /// the destination the endpoint hands back) and its sends are evidence about
  /// the link like any other.
  pub(crate) fn note_fanout(&mut self, report: SendReport) {
    for (family, outcome) in report.per_family() {
      match outcome {
        SendOutcome::Sent(_, _) => self.note_delivered(family),
        SendOutcome::Failed => self.note_failed(family),
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
        "a degraded family delivered again; it holds lifecycle state once more"
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
      "a family failed to deliver too many times; it no longer holds probing, \
       announcement ownership, or query retries back"
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

  /// Which families this gate permits at `now`, in the shape
  /// [`Sockets::send_to`] takes.
  fn allow(&self, now: StdInstant, min_gap: Duration) -> FamilyAllow {
    [
      self.open(FAMILY_V4, now, min_gap),
      self.open(FAMILY_V6, now, min_gap),
    ]
  }

  /// Record that family `idx` put a GATED datagram on its wire at `at`.
  ///
  /// `at` is that family's OWN acceptance instant, not the fan-out's confirm
  /// anchor — recording the anchor would re-introduce exactly the skew this gate
  /// exists to absorb.
  fn record(&mut self, idx: usize, at: StdInstant, min_gap: Duration) {
    if min_gap.is_zero() {
      return;
    }
    if let Some(slot) = self.last_sent.get_mut(idx) {
      *slot = Some(at);
    }
  }

  /// Fold one fan-out's accepted instants back into the gate.
  fn note(&mut self, report: SendReport, min_gap: Duration) {
    for (family, outcome) in report.per_family() {
      if let Some(at) = outcome.accepted_at() {
        self.record(family.index(), at, min_gap);
      }
    }
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_and_credit(
  sockets: &mut Sockets,
  selfsend: &mut SelfSendTracker,
  health: &mut SendHealth,
  gate: &mut FamilyWireGate,
  body: &[u8],
  dst: SocketAddr,
  min_gap: Duration,
  now: StdInstant,
) -> SendSummary {
  let report = sockets.send_to(body, dst, gate.allow(now, min_gap));
  if report.loops_back {
    for (family, outcome) in report.per_family() {
      if let SendOutcome::Sent(at, _) = outcome {
        selfsend.record(family, body, at);
      }
    }
  }
  gate.note(report, min_gap);
  health.note_fanout(report);
  summarize(report, health)
}

/// Project one fan-out onto the core's vocabulary, under the obligated set this
/// driver currently keeps.
///
/// The mapping is one-to-one and nothing is laundered:
///
/// * `NoSocket` is [`FamilyDelivery::Unobligated`] — the family was never
///   offered the datagram, so its absence is not a failure. A single-stack host
///   is fully delivered on the one family it has.
/// * `Sent` is [`FamilyDelivery::Delivered`], **including for a degraded
///   family**: a family that has quietly recovered really did put the records on
///   a wire, and peers reachable over it now hold them.
/// * `Gated` and `Failed` are [`FamilyDelivery::Missed`] for a family still
///   obligated. A gated family is emphatically not `Unobligated` — its socket is
///   there and the datagram was meant for it; the driver simply owed the wire a
///   gap it had not paid. Reporting it absent would hide the deferral from the
///   core and let the phase advance without it.
/// * `Gated` and `Failed` are [`FamilyDelivery::Unobligated`] for a **degraded**
///   family, and that is the one place the driver writes a family off. The
///   core's contract names it: "obligated" is driver policy, and a family the
///   driver has written off is one the core must stop waiting for. It is
///   transient — a single delivery restores it — and it is reported through
///   [`Mdns::degraded_families`](crate::Mdns::degraded_families) rather than
///   applied silently.
fn summarize(report: SendReport, health: &SendHealth) -> SendSummary {
  let mut sent = 0usize;
  let mut families = [FamilyDelivery::Unobligated; 2];
  let mut accepted_at: Option<StdInstant> = None;
  for (family, outcome) in report.per_family() {
    let delivery = match outcome {
      SendOutcome::Sent(_, at) => {
        sent = sent.saturating_add(1);
        accepted_at = Some(accepted_at.map_or(at, |best: StdInstant| best.min(at)));
        FamilyDelivery::Delivered
      }
      SendOutcome::Gated | SendOutcome::Failed => {
        if health.standing(family).degraded {
          FamilyDelivery::Unobligated
        } else {
          FamilyDelivery::Missed
        }
      }
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
  }
}

#[cfg(test)]
mod tests;

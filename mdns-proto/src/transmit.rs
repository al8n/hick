//! Outgoing-datagram descriptor and its delivery outcome.

use core::net::{IpAddr, SocketAddr};

/// Whether the core will KEEP RE-ARMING a datagram until every obligated link
/// accepts it — and therefore whether a driver's bounded obligation policy (see
/// [`TransmitOutcome`]) applies to that datagram's confirm.
///
/// The tag is a property of the DATAGRAM, not of the producing service's
/// lifecycle phase. The two diverge in both directions: the periodic
/// `Established` re-announce advances no phase yet is still re-armed on the RFC
/// 6762 §8.3 doubling ladder while a link keeps missing it, and
/// [`Query::poll_transmit`](crate::Query::poll_transmit) shares [`Transmit`]
/// while having no service phase at all.
///
/// A driver MUST route the two variants differently, because feeding a
/// [`OneShot`](Self::OneShot) confirm into a bounded obligation counter corrupts
/// that counter in both directions:
///
/// * An RFC 6762 §6.7 legacy unicast reply has exactly one obligated link, so it
///   is [`AllDelivered`](TransmitOutcome::AllDelivered) by construction and
///   RESETS the counter. A stream of replies interleaved with partial lifecycle
///   sends holds it at zero forever, and the bound never fires.
/// * A partially-delivered multicast response PRELOADS the counter, so the next
///   partial probe is excused and the §8.1 sequence advances although one family
///   never heard the probe.
///
/// Deliberately NOT `#[non_exhaustive]`: a future transmit kind must break every
/// driver's match and force it to choose a policy, rather than silently
/// inheriting a wildcard arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransmitObligation {
  /// The core re-arms this datagram until every obligated link accepts it, so a
  /// link that keeps missing pins the producer's progress. A driver's bounded
  /// obligation policy APPLIES.
  ///
  /// Carried by the RFC 6762 §8.1 probe, by every §8.3 announcement (including
  /// the periodic re-announce from `Established`), and by the §5.2 query
  /// retransmission.
  Sustained,
  /// Fire-and-forget: the core never re-arms this datagram, so missing it pins
  /// nothing. A driver's bounded obligation policy MUST NOT be applied — the
  /// outcome must reach the core VERBATIM, since the core still reads
  /// [`TransmitOutcome::any_delivered`] from it to latch §10.1 goodbye ownership
  /// for the records the datagram carried.
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
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Transmit {
  dst: SocketAddr,
  src_ip: Option<IpAddr>,
  size: usize,
  obligation: TransmitObligation,
}

impl Transmit {
  /// Creates a new transmit descriptor.
  #[inline(always)]
  pub const fn new(
    dst: SocketAddr,
    src_ip: Option<IpAddr>,
    size: usize,
    obligation: TransmitObligation,
  ) -> Self {
    Self {
      dst,
      src_ip,
      size,
      obligation,
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
  /// accepts it, and therefore whether the driver's bounded obligation policy
  /// applies to its confirm. See [`TransmitObligation`].
  #[inline(always)]
  pub const fn obligation(&self) -> TransmitObligation {
    self.obligation
  }
}

/// The delivery outcome of ONE logical datagram produced by a `poll_transmit`.
///
/// A single logical mDNS multicast fans out to every link the driver serves —
/// the IPv4 and IPv6 groups today, an arbitrary set under a future
/// multi-interface driver — and those sends succeed or fail INDEPENDENTLY. The
/// core asks two different questions of a send, and under partial delivery their
/// answers differ, so the driver reports the aggregate shape and the core alone
/// decides what each shape means:
///
/// * [`any_delivered`](Self::any_delivered) drives the goodbye-ownership latch
///   (RFC 6762 §10.1): peers reachable over a link that accepted the datagram may
///   now hold the records it carried, so a later withdrawal must retract them.
/// * [`all_delivered`](Self::all_delivered) drives lifecycle-phase advance (§8.1
///   probing, §8.3 announcing) and the §5.2 query retry budget: a link that never
///   saw the probe has not been asked, and one that never saw the announcement
///   has not been told.
///
/// # The obligated set
///
/// "Obligated" is DRIVER policy, not a core concept: the links this datagram is
/// fanned onto that the driver has not permanently written off (no socket, a
/// degraded family). The core never enumerates links, so this enum is
/// family-count-agnostic and unchanged by a driver that grows past two.
///
/// * An RFC 6762 §6.7 legacy unicast reply has exactly ONE obligated link (the
///   destination's family), so it reports `AllDelivered` or `NoneDelivered` by
///   construction and can never be `PartiallyDelivered`.
/// * An EMPTY obligated set (every link torn down mid-flight) reports
///   [`NoneDelivered`](Self::NoneDelivered) — never a vacuous "all".
///
/// # Driver obligation (normative)
///
/// A driver that can ever report [`PartiallyDelivered`](Self::PartiallyDelivered)
/// **MUST** implement a BOUNDED obligation policy — a consecutive-failure
/// write-off or family degradation that eventually drops a dead link from the
/// obligated set. Repeated `PartiallyDelivered` re-arms indefinitely, so without
/// such a policy a chronically-failing link holds every service in probing or
/// announcing forever.
///
/// That policy applies to [`TransmitObligation::Sustained`] datagrams and to
/// those ONLY. A [`OneShot`](TransmitObligation::OneShot) datagram is never
/// re-armed, so it has nothing to write off — and mixing its confirms into the
/// same counter both hides a chronically half-broken link and advances phases the
/// missing link never heard. Read [`Transmit::obligation`] and pass a `OneShot`
/// outcome to the core verbatim.
///
/// The bound cannot live in the core. Its only unilateral terminal action would
/// be to advance the phase anyway, and advancing on a link that never heard the
/// probe is precisely what §8.1 forbids ("it MUST send a Multicast DNS query …
/// to see if any of them are already in use") — the defect this type exists to
/// remove. Deciding that a lagging link no longer counts needs link-health
/// knowledge only the driver has.
///
/// The core's half of that contract: a re-arm is LOSSLESS (same probe index,
/// same announcement count — nothing restarts) and recovery is IMMEDIATE — the
/// first confirm after the driver stops obligating the dead link is
/// `AllDelivered`, and the phase advances from exactly where it stood.
#[derive(Clone, Copy, Debug, Eq, PartialEq, derive_more::Display)]
#[display("{}", self.as_str())]
pub enum TransmitOutcome {
  /// Every obligated link accepted the datagram.
  AllDelivered,
  /// At least one obligated link accepted the datagram and at least one did not.
  PartiallyDelivered,
  /// No link accepted the datagram, including the case of an empty obligated set.
  NoneDelivered,
}

impl TransmitOutcome {
  /// At least one obligated link accepted the datagram, so peers reachable over
  /// that link may now hold the records it carried.
  ///
  /// This is the goodbye-ownership fact (RFC 6762 §10.1): ownership latches iff
  /// this is `true`.
  #[inline(always)]
  pub const fn any_delivered(self) -> bool {
    matches!(self, Self::AllDelivered | Self::PartiallyDelivered)
  }

  /// Every obligated link accepted the datagram.
  ///
  /// This is the lifecycle fact: the §8.1 probe sequence, the §8.3 announcement
  /// phase, and the §5.2 query retry budget advance iff this is `true`.
  #[inline(always)]
  pub const fn all_delivered(self) -> bool {
    matches!(self, Self::AllDelivered)
  }

  /// Canonical lowercase slug for this outcome.
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::AllDelivered => "all_delivered",
      Self::PartiallyDelivered => "partially_delivered",
      Self::NoneDelivered => "none_delivered",
    }
  }
}

#[cfg(test)]
mod tests;

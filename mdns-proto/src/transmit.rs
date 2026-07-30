//! Outgoing-datagram descriptor and its delivery outcome.

use core::net::{IpAddr, SocketAddr};

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
  /// patience bound excuses it (see [`TransmitOutcome`]).
  ///
  /// Carried by the RFC 6762 §8.1 probe, by every §8.3 announcement (including
  /// the periodic re-announce from `Established`), and by the §5.2 query
  /// retransmission.
  Sustained,
  /// Fire-and-forget: the core never re-arms this datagram, so missing it pins
  /// nothing and losing it costs nothing but one unanswered question. The core
  /// still reads [`TransmitOutcome::any_delivered`] from its confirm to latch
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
  /// accepts it, and therefore what a permanent send failure means for the
  /// producer. See [`TransmitObligation`].
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
/// # The split (normative)
///
/// The DRIVER owns the obligated set and link death: which links a datagram is
/// fanned onto, which have been permanently written off (no socket, a degraded
/// family), and when a socket is torn down. It reports the honest aggregate shape
/// and nothing else — no confirm is ever laundered into a different one, and a
/// `OneShot` outcome in particular reaches the core verbatim, since the core
/// reads `any_delivered` from it to latch §10.1 goodbye ownership.
///
/// The CORE owns its own patience. Repeated `PartiallyDelivered` re-arms
/// indefinitely, so the core bounds how many consecutive re-arms one producer
/// spends waiting for a link that never accepts; past that bound it advances the
/// phase without that link (`MAX_PARTIAL_ROUNDS`). That is a decision about the
/// core's own lifecycle, made of facts the core already holds — the confirm shape
/// and its own re-arm count — with no socket or link-health knowledge involved,
/// so it belongs where every other lifecycle rule lives. Its in-tree sibling is
/// the withdrawal ceiling, which force-completes per-family goodbye debt the
/// driver never paid.
///
/// The core does NOT thereby decide a link is dead: the excused link is fanned
/// onto on every later round and the first round it accepts is `AllDelivered` on
/// its own merit, so there is no degraded state to get stuck in and no recovery
/// edge to detect. Nor is the escape a delivery — it advances the phase and
/// nothing else. It earns no announcement proof
/// ([`Service::has_fully_announced`](crate::Service::has_fully_announced) stays
/// shut), no ladder reset, and no delivered-datagram counter. §8.1's requirement
/// that a name be probed before it is claimed is honoured by the bound being
/// spent on genuine re-arms of that probe, and by the excusal never being
/// reachable from an outcome that put nothing on a wire
/// ([`NoneDelivered`](Self::NoneDelivered) leaves the count untouched, so an
/// alternating partial/failed pattern cannot walk into it).
///
/// The core's other half of the contract: a re-arm is LOSSLESS (same probe index,
/// same announcement count — nothing restarts) and recovery is IMMEDIATE — the
/// first confirm after the lagging link starts accepting is `AllDelivered`, and
/// the phase advances from exactly where it stood.
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

//! One inbound datagram, bundled with what the caller can say about it.

use core::net::{IpAddr, SocketAddr};

/// What the caller's OWN SEND LOG says about an inbound datagram.
///
/// Every variant is a claim about the caller's own records, never about the
/// network. No platform reports "this is your own multicast echo":
/// `IP_MULTICAST_LOOP` is a send-side knob, and PKTINFO's `ipi_spec_dst` names
/// the receiving interface — which every co-resident sender shares. So there is
/// deliberately no kernel-witnessed tier here: no driver could produce one.
///
/// # The two mistakes are not symmetric
///
/// A peer mis-flagged as self deletes an RFC 6762 §8.2 proposal, an §8.1 defeat
/// or a §9 conflict, and the result is permanent, silent duplicate ownership
/// between two conforming hosts. Our own echo mis-flagged as a peer costs at
/// worst §8.2's one-second deferral. **A tier that is unsure therefore routes to
/// the conflict path rather than suppressing it** — see [`Self::OwnEchoLikely`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Provenance {
  /// Our own bytes, ORDERED against our own `sendto`: the kernel stamped this
  /// arrival at or after the send, so nothing else could have put these bytes on
  /// the wire in between.
  ///
  /// **One route, and it is the ordering that earns it.** A content match with no
  /// ordering evidence is [`Self::OwnEchoLikely`] however stale the generation it
  /// matched — see that variant's obligation. A SUPERSEDED match does not belong
  /// here: that is the false axiom `relinquished_retention`'s screen is built to
  /// avoid, byte equality read as proof of origin. An old local responder and a
  /// live RFC 6762 §9 fault-tolerance twin can put the same bytes on the link,
  /// and a peer can replay them, so a stale-generation match says what the
  /// datagram CONTAINS and not who sent it — and a driver's superseded entry is
  /// typically non-consuming, so reporting it here makes every matching peer
  /// defence invisible for the credit's whole lifetime.
  ///
  /// The only tier that suppresses everything, which is why nothing but ordering
  /// may reach it.
  OwnEcho,
  /// Content match with NO ordering evidence.
  ///
  /// A byte-identical datagram from a conforming twin — the RFC 6762 §9
  /// fault-tolerance case, where two responders issue identical answers — matches
  /// exactly this way, so the claim cannot be trusted with a name.
  ///
  /// **Obligation.** Report this tier for an unordered content match whether the
  /// generation it matched is the one this endpoint still publishes or one it has
  /// left behind. A SUPERSEDED match belongs here and not at [`Self::OwnEcho`]:
  /// staleness is a fact about our records, not evidence about the sender, so it
  /// may buy the denials that protect US — observation and quieting — and may not
  /// buy the one that costs a PEER its name.
  ///
  /// A driver must still TRACK the generation, and still owes the advance at
  /// **every mutation of what this endpoint publishes**, at the site rather than
  /// once per loop: the `begin_withdrawal` that retires a route however that
  /// retirement was reached (caller unregister, shutdown, rename collision,
  /// internal retirement); and the RFC 6762 §9 automatic rename, taken at the
  /// driver's own `ServiceUpdate::Renamed` — a successful rename reaches the
  /// other seam not at all, and it has already mutated the service's records by
  /// the time the update is observed. What the tracking buys is that a stale
  /// credit is not mistaken for an ordered one; both stale and current unordered
  /// matches land here.
  ///
  /// **A service REGISTRATION is not a mutation**, despite falling inside that
  /// quantifier at a glance. A registration only inserts a route:
  /// [`Endpoint::try_register_service`](super::Endpoint::try_register_service)
  /// refuses a duplicate instance name, a name a collision goodbye still holds,
  /// and a host name a live route publishes with a different A or AAAA set, and
  /// there is no §8.4 records mutator for it to reach; the §6.1 NSEC an
  /// announcement carries is owned by the INSTANCE name, so a sibling
  /// registration cannot flip a host-name NSEC's truth either. Nothing this
  /// endpoint had asserted changes truth-value there, so a driver advancing the
  /// generation at a registration asserts something false about its own records
  /// — and since a driver's superseded credit is typically a standing tombstone,
  /// that falsehood then denies observation and quieting to EVERY byte-identical
  /// copy for the credit's whole life, a genuine peer's TTL=0 §10.1 goodbye
  /// burst included.
  ///
  /// **What that obligation is, and is not, worth.** It is DEFENCE IN DEPTH.
  /// What it buys is that a stale echo does not poison this endpoint's own cache
  /// with records it no longer publishes, and does not quiet its own traffic on
  /// their behalf. It is emphatically NOT what keeps our own withdrawn
  /// generation from retiring the service that replaced it: that is decided
  /// inside `Endpoint`, by screening every conflict candidate against the record
  /// sets this endpoint recently asserted and relinquished (see
  /// [`EndpointConfig::relinquished_retention`]).
  ///
  /// The distinction is load-bearing for a driver author. Getting the generation
  /// binding wrong — or losing the match entirely, which a replaying peer, a
  /// duplicated delivery, or an evicted credit can each cause without any bug at
  /// all — degrades cache hygiene. It does not cost a live service its name.
  ///
  /// [`EndpointConfig::relinquished_retention`]: crate::EndpointConfig::relinquished_retention
  OwnEchoLikely,
  /// The caller logs every datagram it sends and this datagram matched none it
  /// still holds.
  ///
  /// A negative claim about the caller's own log, so an evicted credit reads as
  /// this too. It suppresses nothing, and it also declines
  /// [`EndpointConfig::trust_advertised_src_as_self`]: a caller with a send log
  /// has better evidence than a source-address guess.
  ///
  /// [`EndpointConfig::trust_advertised_src_as_self`]: crate::EndpointConfig::trust_advertised_src_as_self
  NotFromUs,
  /// The caller keeps no send log and has nothing to say.
  ///
  /// The tier for sync / single-process responders, which may instead opt into
  /// the coarser advertised-source guess via
  /// [`EndpointConfig::with_trust_advertised_src_as_self`].
  ///
  /// [`EndpointConfig::with_trust_advertised_src_as_self`]: crate::EndpointConfig::with_trust_advertised_src_as_self
  Unknown,
}

/// One received datagram and everything the caller knows about it, handed to
/// [`Endpoint::handle`](super::Endpoint::handle) as a single value.
///
/// # Why a bundle
///
/// The payload and its [`Provenance`] are two halves of one fact, and passing
/// them as independent arguments is what lets a driver pair one datagram's
/// self-send verdict with another datagram's bytes. A shared lifetime would not
/// have closed that: `&'a [u8]` and a `Provenance<'a>` can be two different
/// subslices of one receive buffer, because Rust lifetimes bound validity and
/// never slice identity.
///
/// So the coupling here is **construction adjacency, not enforcement**: nothing
/// in this type can check that `provenance` was computed over `data`. What it
/// buys is distance — the obligation shrinks from spanning a receive, a struct
/// field and a call, to one statement with both values in scope. This crate is
/// `no_std` and cannot depend on the I/O layer that owns the send log, so
/// enforcement is not available to it at all.
///
/// # Private fields
///
/// Construct with [`Self::new`] and add what is known with the `with_*` builders.
/// The fields are private so a later addition — a receive-time witness, a
/// destination — is not a breaking change.
pub struct Received<'a> {
  pub(super) src: SocketAddr,
  pub(super) data: &'a [u8],
  pub(super) provenance: Provenance,
  pub(super) local_ip: Option<IpAddr>,
  pub(super) interface_index: Option<u32>,
}

impl<'a> Received<'a> {
  /// A datagram of `data` from `src`, with what the caller's send log says about
  /// it.
  ///
  /// Compute `provenance` here, next to the bytes it describes — see the type
  /// docs for why that adjacency is the whole guarantee.
  #[inline(always)]
  pub const fn new(src: SocketAddr, data: &'a [u8], provenance: Provenance) -> Self {
    Self {
      src,
      data,
      provenance,
      local_ip: None,
      interface_index: None,
    }
  }

  /// The receiving interface index (`if_nametoindex(3)` / PKTINFO `ipi_ifindex` /
  /// `ipi6_ifindex`).
  ///
  /// It disambiguates IPv6 link-local self-loopback on multi-homed hosts under
  /// [`EndpointConfig::trust_advertised_src_as_self`]: a peer reusing the same
  /// `fe80::*` on a different interface must not be classified as self.
  ///
  /// `None` — the default — says the caller does not know, and link-local
  /// self-loopback detection then degrades gracefully, matching only AAAA
  /// entries registered with scope `0` (see
  /// [`ServiceRecords::add_aaaa`](crate::records::ServiceRecords::add_aaaa) and
  /// [`add_aaaa_scoped`](crate::records::ServiceRecords::add_aaaa_scoped)). It is
  /// an `Option` rather than the `0` that also spells "any scope", so a driver
  /// that does not know says so.
  ///
  /// [`EndpointConfig::trust_advertised_src_as_self`]: crate::EndpointConfig::trust_advertised_src_as_self
  #[inline(always)]
  #[must_use]
  pub const fn with_interface(mut self, index: Option<u32>) -> Self {
    self.interface_index = index;
    self
  }

  /// The address of the interface that received the datagram, as reported by
  /// `IP_PKTINFO` / `IPV6_PKTINFO`.
  ///
  /// **Trace-only.** It is deliberately NOT a self-loopback signal: PKTINFO's
  /// local receive address is host/interface level, so every same-host mDNS
  /// sender egresses from the same interface IP and `src == local_ip` would
  /// suppress legitimate co-resident peers and hide same-host name conflicts.
  #[inline(always)]
  #[must_use]
  pub const fn with_local_ip(mut self, ip: IpAddr) -> Self {
    self.local_ip = Some(ip);
    self
  }

  /// Source address of the datagram.
  #[inline(always)]
  pub const fn src(&self) -> SocketAddr {
    self.src
  }

  /// The datagram's bytes.
  #[inline(always)]
  pub const fn data(&self) -> &'a [u8] {
    self.data
  }

  /// What the caller's send log says about these bytes.
  #[inline(always)]
  pub const fn provenance(&self) -> Provenance {
    self.provenance
  }

  /// The receiving interface index, if the caller knew it. See
  /// [`Self::with_interface`].
  #[inline(always)]
  pub const fn interface_index(&self) -> Option<u32> {
    self.interface_index
  }

  /// The receiving interface's own address, if the caller knew it. See
  /// [`Self::with_local_ip`].
  #[inline(always)]
  pub const fn local_ip(&self) -> Option<IpAddr> {
    self.local_ip
  }
}

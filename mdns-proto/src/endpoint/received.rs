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
  /// Content match AND evidence that ORDERS it: the kernel stamped this arrival
  /// at or after our own `sendto`, so nothing else could have put these bytes on
  /// the wire in between.
  ///
  /// The only tier that suppresses everything.
  OwnEcho,
  /// Content match with NO ordering evidence.
  ///
  /// A byte-identical datagram from a conforming twin — the RFC 6762 §9
  /// fault-tolerance case, where two responders issue identical answers — matches
  /// exactly this way, so the claim cannot be trusted with a name.
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

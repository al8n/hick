//! Error types for `hick-udp` operations.

use core::net::IpAddr;
use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// Detail for [`BindError::InterfaceNotFound`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("interface index {index} not found")]
pub struct InterfaceNotFoundDetail {
  index: u32,
}
impl InterfaceNotFoundDetail {
  /// Build a new detail payload.
  #[inline(always)]
  pub(crate) const fn new(index: u32) -> Self {
    Self { index }
  }
  /// The OS interface index that wasn't found.
  #[inline(always)]
  pub const fn index(&self) -> u32 {
    self.index
  }
}

/// Detail for [`BindError::AddressInUse`].
#[derive(Debug, Clone, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("address {addr} already in use on interface {iface}")]
pub struct AddressInUseDetail {
  addr: IpAddr,
  iface: u32,
}
impl AddressInUseDetail {
  /// Build a new detail payload.
  #[expect(dead_code, reason = "used by socket-bind helpers not yet wired in")]
  #[inline(always)]
  pub(crate) const fn new(addr: IpAddr, iface: u32) -> Self {
    Self { addr, iface }
  }
  /// The address that was already in use.
  #[inline(always)]
  pub const fn addr(&self) -> IpAddr {
    self.addr
  }
  /// The interface index involved.
  #[inline(always)]
  pub const fn iface(&self) -> u32 {
    self.iface
  }
}

/// Detail for [`BindError::MulticastHopsNotApplied`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("IPv6 multicast hop limit not applied: requested {requested}, observed {observed}")]
pub struct MulticastHopsNotAppliedDetail {
  requested: u8,
  observed: i32,
}
impl MulticastHopsNotAppliedDetail {
  /// Build a new detail payload.
  // Constructed only by the Unix `try_bind_v6` read-back path; on Windows
  // this option is set via `socket2` (no read-back), so suppress the
  // dead-code warning there.
  #[cfg_attr(not(unix), allow(dead_code))]
  #[inline(always)]
  pub(crate) const fn new(requested: u8, observed: i32) -> Self {
    Self {
      requested,
      observed,
    }
  }
  /// The IPv6 multicast hop limit that was requested via `setsockopt`.
  #[inline(always)]
  pub const fn requested(&self) -> u8 {
    self.requested
  }
  /// The hop limit `getsockopt` reports the kernel actually holds, read back
  /// immediately after the `setsockopt` call that was supposed to set
  /// `requested`. Kept as the raw signed kernel value rather than clamped to
  /// `u8`: this field exists only to describe a value that has already
  /// failed to be what was asked for, and truncating it could mask how wrong
  /// it is.
  #[inline(always)]
  pub const fn observed(&self) -> i32 {
    self.observed
  }
}

/// Detail for [`BindError::MulticastLoopNotApplied`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("IPv4 multicast loopback not applied: requested {requested}, observed {observed}")]
pub struct MulticastLoopNotAppliedDetail {
  requested: bool,
  observed: bool,
}
impl MulticastLoopNotAppliedDetail {
  /// Build a new detail payload.
  // Constructed only by the Unix `try_bind_v4` read-back path; Windows sets
  // this option through `socket2` at a fixed `DWORD` width, so there is no
  // width ambiguity to read back there.
  #[cfg_attr(not(unix), allow(dead_code))]
  #[inline(always)]
  pub(crate) const fn new(requested: bool, observed: bool) -> Self {
    Self {
      requested,
      observed,
    }
  }
  /// The `IP_MULTICAST_LOOP` state that was requested via `setsockopt`.
  #[inline(always)]
  pub const fn requested(&self) -> bool {
    self.requested
  }
  /// The state `getsockopt` reports the kernel actually holds, read back
  /// immediately after the `setsockopt` call that was supposed to set
  /// `requested`.
  #[inline(always)]
  pub const fn observed(&self) -> bool {
    self.observed
  }
}

/// Detail for [`BindError::MulticastTtlNotApplied`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("IPv4 multicast TTL not applied: requested {requested}, observed {observed}")]
pub struct MulticastTtlNotAppliedDetail {
  requested: u8,
  observed: u32,
}
impl MulticastTtlNotAppliedDetail {
  /// Build a new detail payload.
  // Constructed only by the Unix `try_bind_v4` read-back path; see the loop
  // twin above.
  #[cfg_attr(not(unix), allow(dead_code))]
  #[inline(always)]
  pub(crate) const fn new(requested: u8, observed: u32) -> Self {
    Self {
      requested,
      observed,
    }
  }
  /// The `IP_MULTICAST_TTL` value that was requested via `setsockopt`. A `u8`
  /// because a TTL is a byte on the wire and RFC 6762 §11 wants 255.
  #[inline(always)]
  pub const fn requested(&self) -> u8 {
    self.requested
  }
  /// The value `getsockopt` reports the kernel actually holds, read back
  /// immediately after the `setsockopt` call that was supposed to set
  /// `requested`. Kept at the width the read-back reports rather than narrowed
  /// to `u8`: this field exists only to describe a value that has already
  /// failed to be what was asked for, and truncating it could mask how wrong
  /// it is.
  #[inline(always)]
  pub const fn observed(&self) -> u32 {
    self.observed
  }
}

/// Detail for [`BindError::RxDestinationNotEnabled`].
///
/// Both fields are the raw values `getsockopt` reported for `IP_RECVDSTADDR`
/// and `IP_RECVIF` immediately after the `setsockopt` calls that were supposed
/// to enable them, so a report says WHICH of the pair the kernel did not take
/// rather than only that one of them did not.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display(
  "IPv4 receive-metadata options not enabled: IP_RECVDSTADDR reads {dstaddr}, IP_RECVIF reads \
   {recvif} (both must be non-zero)"
)]
pub struct RxDestinationNotEnabledDetail {
  dstaddr: i32,
  recvif: i32,
}
impl RxDestinationNotEnabledDetail {
  /// Build a new detail payload.
  // Constructed only where `has_ip_dstaddr_recvif` is set (the four BSDs);
  // every other target has no read-back to fail.
  #[cfg_attr(not(has_ip_dstaddr_recvif), allow(dead_code))]
  #[inline(always)]
  pub(crate) const fn new(dstaddr: i32, recvif: i32) -> Self {
    Self { dstaddr, recvif }
  }
  /// What `getsockopt(IPPROTO_IP, IP_RECVDSTADDR)` reported. Non-zero means the
  /// kernel holds the option; `0` means the enable did not take.
  #[inline(always)]
  pub const fn dstaddr(&self) -> i32 {
    self.dstaddr
  }
  /// What `getsockopt(IPPROTO_IP, IP_RECVIF)` reported, read the same way and
  /// meaning the same thing.
  #[inline(always)]
  pub const fn recvif(&self) -> i32 {
    self.recvif
  }
}

/// Detail for [`ParseRecvMetaError::BufferTooShort`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("cmsg buffer too short: needed {needed} bytes, had {have}")]
pub struct BufferTooShortDetail {
  needed: usize,
  have: usize,
}
impl BufferTooShortDetail {
  /// Build a new detail payload.
  // Constructed only by the Unix cmsg parsers; on Windows the receive path
  // does not produce this error, so suppress the dead-code warning there.
  #[cfg_attr(not(unix), allow(dead_code))]
  #[inline(always)]
  pub(crate) const fn new(needed: usize, have: usize) -> Self {
    Self { needed, have }
  }
  /// Bytes the parser needed.
  #[inline(always)]
  pub const fn needed(&self) -> usize {
    self.needed
  }
  /// Bytes that were available.
  #[inline(always)]
  pub const fn have(&self) -> usize {
    self.have
  }
}

/// Errors raised when binding an mDNS multicast UDP socket.
#[derive(Debug, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum BindError {
  /// The requested interface was not found.
  #[error(transparent)]
  InterfaceNotFound(InterfaceNotFoundDetail),

  /// The address was already in use on the chosen interface.
  #[error(transparent)]
  AddressInUse(AddressInUseDetail),

  /// The kernel accepted the `IPV6_MULTICAST_HOPS` `setsockopt` call, but a
  /// read-back shows it did not actually apply the requested value.
  #[error(transparent)]
  MulticastHopsNotApplied(MulticastHopsNotAppliedDetail),

  /// The kernel accepted the `IP_MULTICAST_LOOP` `setsockopt` call, but a
  /// read-back shows it did not actually apply the requested value.
  ///
  /// Unix only. The IPv4 sibling of [`BindError::MulticastHopsNotApplied`],
  /// raised per option rather than bundled with the TTL below so a report says
  /// WHICH scalar the kernel did not take. See
  /// `multicast::verify_multicast_loop_v4` for the two failures it guards: a
  /// wrong-width `setsockopt` on a big-endian host, and any future re-route of
  /// this setter onto a wrong level or a wrong constant, which is silent on
  /// every target.
  #[error(transparent)]
  MulticastLoopNotApplied(MulticastLoopNotAppliedDetail),

  /// The kernel accepted the `IP_MULTICAST_TTL` `setsockopt` call, but a
  /// read-back shows it did not actually apply the requested value.
  ///
  /// Unix only, and the twin of [`BindError::MulticastLoopNotApplied`] — see
  /// there. RFC 6762 §11 requires 255, and the value this failure leaves behind
  /// is typically the kernel default of 1 or a 0 that never leaves the host.
  #[error(transparent)]
  MulticastTtlNotApplied(MulticastTtlNotAppliedDetail),

  /// The kernel accepted the `IP_RECVDSTADDR` / `IP_RECVIF` `setsockopt` calls,
  /// but a read-back shows at least one of them is not actually enabled.
  ///
  /// Raised only on the four BSDs, where those two options are how
  /// `recv_with_meta` witnesses an IPv4 datagram's destination and receiving
  /// interface. Unlike `IP_PKTINFO`, they are TWO cmsgs the kernel allocates
  /// separately, and `multicast::parse_dstaddr_recvif_v4` reports each witness on
  /// its own — it fails only when NEITHER arrived. So a socket that holds one
  /// option and not the other is a real state, and it loses one isolation
  /// dimension while keeping the other:
  ///
  /// * `IP_RECVDSTADDR` not held — the destination is `Declined` on every
  ///   datagram, so the whole destination partition goes with it
  ///   ([`Refuse::ForeignGroup`](hick_onlink::Refuse::ForeignGroup),
  ///   [`BroadcastAddressed`](hick_onlink::Refuse::BroadcastAddressed),
  ///   [`DestinationNotHeld`](hick_onlink::Refuse::DestinationNotHeld) and the
  ///   rest). The interface is still `Witnessed`, so
  ///   [`ForeignLink`](hick_onlink::Refuse::ForeignLink) still refuses a
  ///   datagram from another link;
  /// * `IP_RECVIF` not held — the mirror image. The interface is `Declined`, so
  ///   `ForeignLink` is unreachable for IPv4, while the destination is still
  ///   `Witnessed` and every refusal in the destination partition still fires.
  ///
  /// Neither half is "isolating nothing", and neither is silent: the drivers count
  /// a degraded admission on `ingress_witness_declined`. What survives on the
  /// destination side once it is `Declined` is decided ENTIRELY by the kernel's
  /// coarse [`LinkDelivery`](hick_onlink::LinkDelivery), so it is enumerated
  /// rather than summarised:
  ///
  /// * `Some(Broadcast)` — refused,
  ///   [`BroadcastDelivery`](hick_onlink::Refuse::BroadcastDelivery). OpenBSD and
  ///   NetBSD only, the two targets `libc` binds `MSG_BCAST` for;
  /// * `Some(Multicast)` — **admitted**,
  ///   [`BlindMulticastDelivery`](hick_onlink::Admit::BlindMulticastDelivery). It
  ///   names no group and the source arm NEVER RUNS, so an out-of-prefix
  ///   multicast source is admitted and
  ///   [`SourceOffLink`](hick_onlink::Refuse::SourceOffLink) has no say. OpenBSD
  ///   and NetBSD only;
  /// * `Some(Unicast)` — the source arm runs, so `SourceOffLink` refuses an
  ///   out-of-prefix source. OpenBSD and NetBSD only;
  /// * `None` — every other supported target, which binds neither flag: the
  ///   source arm runs and `SourceOffLink` refuses an out-of-prefix source.
  ///
  /// What justifies failing the bind is narrower than any of that and still
  /// sufficient: losing EITHER witness dimension is a permanent, per-socket loss
  /// of half the trust boundary that no return code reported, and the read-back is
  /// the only thing that sees it.
  #[error(transparent)]
  RxDestinationNotEnabled(RxDestinationNotEnabledDetail),

  /// An I/O error occurred.
  #[error(transparent)]
  Io(#[from] std::io::Error),
}

/// Errors raised when joining/leaving a multicast group.
#[derive(Debug, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum JoinError {
  /// The requested interface was not found.
  #[error(transparent)]
  InterfaceNotFound(InterfaceNotFoundDetail),

  /// An I/O error occurred.
  #[error(transparent)]
  Io(#[from] std::io::Error),
}

/// Errors raised when parsing recvmsg cmsg ancillary data.
#[derive(Debug, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ParseRecvMetaError {
  /// The cmsg buffer was too short to contain the expected PKTINFO.
  #[error(transparent)]
  BufferTooShort(BufferTooShortDetail),

  /// No PKTINFO cmsg was found in the ancillary buffer.
  #[error("no pktinfo cmsg in ancillary buffer")]
  MissingPktinfo,
}

#[cfg(test)]
mod tests;

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

  /// The kernel accepted the `IP_RECVDSTADDR` / `IP_RECVIF` `setsockopt` calls,
  /// but a read-back shows at least one of them is not actually enabled.
  ///
  /// Raised only on the four BSDs, where those two options are how
  /// `recv_with_meta` witnesses an IPv4 datagram's destination and receiving
  /// interface. The bind fails rather than returning a socket that would report
  /// no witness for every datagram: on a target
  /// [`reports_rx_interface_v4`](crate::reports_rx_interface_v4) calls capable,
  /// a receiver is entitled to act on a missing witness, so continuing would be
  /// deafness dressed as degradation.
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

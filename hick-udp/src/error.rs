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
mod tests {
  use super::{
    BindError, BufferTooShortDetail, InterfaceNotFoundDetail, JoinError, ParseRecvMetaError,
  };

  #[test]
  fn detail_accessors_and_display() {
    let d = InterfaceNotFoundDetail::new(7);
    assert_eq!(d.index(), 7);
    assert_eq!(d.to_string(), "interface index 7 not found");

    let b = BufferTooShortDetail::new(20, 8);
    assert_eq!(b.needed(), 20);
    assert_eq!(b.have(), 8);
    assert_eq!(
      b.to_string(),
      "cmsg buffer too short: needed 20 bytes, had 8"
    );
  }

  #[test]
  fn error_enum_display_and_is_variant() {
    let bind = BindError::InterfaceNotFound(InterfaceNotFoundDetail::new(3));
    assert!(bind.is_interface_not_found());
    assert_eq!(bind.to_string(), "interface index 3 not found");

    let join = JoinError::InterfaceNotFound(InterfaceNotFoundDetail::new(4));
    assert!(join.is_interface_not_found());
    assert_eq!(join.to_string(), "interface index 4 not found");

    let parse = ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(16, 4));
    assert!(parse.is_buffer_too_short());
    assert_eq!(
      parse.to_string(),
      "cmsg buffer too short: needed 16 bytes, had 4"
    );

    let missing = ParseRecvMetaError::MissingPktinfo;
    assert!(missing.is_missing_pktinfo());
    assert_eq!(missing.to_string(), "no pktinfo cmsg in ancillary buffer");
  }
}

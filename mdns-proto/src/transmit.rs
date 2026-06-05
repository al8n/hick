//! Outgoing-datagram descriptor.

use core::net::{IpAddr, SocketAddr};

/// Outgoing datagram metadata produced by the proto state machines.
///
/// The proto writes the actual bytes into a caller-supplied `&mut [u8]`;
/// this struct describes where the bytes go and how many were written.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Transmit {
  dst: SocketAddr,
  src_ip: Option<IpAddr>,
  size: usize,
}

impl Transmit {
  /// Creates a new transmit descriptor.
  #[inline(always)]
  pub const fn new(dst: SocketAddr, src_ip: Option<IpAddr>, size: usize) -> Self {
    Self { dst, src_ip, size }
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
}

#[cfg(test)]
mod tests;

//! A record (IPv4 address, RFC 1035 §3.4.1).

use core::net::Ipv4Addr;

use crate::error::{BufferTooShortDetail, ParseError};

/// Parsed A record rdata.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct A {
  addr: Ipv4Addr,
}

impl A {
  /// Parses a 4-byte IPv4 address from rdata.
  ///
  /// `rdata` MUST be exactly 4 bytes (RFC 1035 §3.4.1).  A
  /// shorter slice yields `BufferTooShort`; an oversize slice would
  /// previously have been silently truncated, which is wire-level
  /// undefined behaviour and could mask a protocol error from the
  /// caller.
  pub fn try_from_rdata(rdata: &[u8]) -> Result<Self, ParseError> {
    if rdata.len() != 4 {
      return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
        4,
        0,
        rdata.len(),
      )));
    }
    let arr: &[u8; 4] = rdata
      .first_chunk::<4>()
      .ok_or_else(|| ParseError::BufferTooShort(BufferTooShortDetail::new(4, 0, rdata.len())))?;
    Ok(Self {
      addr: Ipv4Addr::from(*arr),
    })
  }

  /// Returns the parsed IPv4 address.
  #[inline(always)]
  pub const fn addr(&self) -> Ipv4Addr {
    self.addr
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

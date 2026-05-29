//! AAAA record (IPv6 address, RFC 3596).

use core::net::Ipv6Addr;

use crate::error::{BufferTooShortDetail, ParseError};

/// Parsed AAAA record rdata.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct AaaaRecord {
  addr: Ipv6Addr,
}

impl AaaaRecord {
  /// Parses a 16-byte IPv6 address from rdata.
  ///
  /// `rdata` MUST be exactly 16 bytes (RFC 3596 §2.2).  An
  /// oversize slice would previously have been silently truncated.
  pub fn try_from_rdata(rdata: &[u8]) -> Result<Self, ParseError> {
    if rdata.len() != 16 {
      return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
        16,
        0,
        rdata.len(),
      )));
    }
    let arr: &[u8; 16] = rdata
      .first_chunk::<16>()
      .ok_or_else(|| ParseError::BufferTooShort(BufferTooShortDetail::new(16, 0, rdata.len())))?;
    Ok(Self {
      addr: Ipv6Addr::from(*arr),
    })
  }

  /// Returns the parsed IPv6 address.
  #[inline(always)]
  pub const fn addr(&self) -> Ipv6Addr {
    self.addr
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::AaaaRecord;

  #[test]
  fn parses_16_bytes() {
    let r =
      AaaaRecord::try_from_rdata(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
    assert_eq!(r.addr().segments()[0], 0xfe80);
    assert_eq!(r.addr().segments()[7], 0x0001);
  }

  #[test]
  fn rejects_short() {
    let err = AaaaRecord::try_from_rdata(&[0u8; 10]).unwrap_err();
    assert!(err.is_buffer_too_short());
  }

  /// oversize rdata must also be rejected.
  #[test]
  fn rejects_oversize() {
    let err = AaaaRecord::try_from_rdata(&[0u8; 20]).unwrap_err();
    assert!(err.is_buffer_too_short());
  }
}

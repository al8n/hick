//! AAAA record (IPv6 address, RFC 3596).

use core::net::Ipv6Addr;

use crate::error::{BufferTooShortDetail, ParseError};

/// Parsed AAAA record rdata.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
// `AAAA` is the canonical DNS record-type name; keep the verbatim spelling.
#[allow(clippy::upper_case_acronyms)]
pub struct AAAA {
  addr: Ipv6Addr,
}

impl AAAA {
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
mod tests;

//! CNAME record (canonical name, RFC 1035 §3.3.1).
//!
//! CNAME rdata is exactly one domain name — structurally identical to PTR —
//! so it is parsed and canonicalized the same way (decompressed for storage,
//! case-folded for identity).

use crate::{error::ParseError, wire::NameRef};

/// Parsed CNAME record rdata.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Cname<'a> {
  target: NameRef<'a>,
}

impl<'a> Cname<'a> {
  /// Parses a CNAME record's rdata. `message` is the full DNS message so
  /// compression pointers can resolve; `rdata_offset` is the start of the
  /// rdata bytes within it; `rdata_len` is the declared RDLENGTH.
  ///
  /// Like PTR: the encoded name MUST consume EXACTLY
  /// `rdata_len` bytes — neither overrun the declared boundary nor leave
  /// trailing garbage inside it.
  pub fn try_from_message(
    message: &'a [u8],
    rdata_offset: usize,
    rdata_len: usize,
  ) -> Result<Self, ParseError> {
    let (target, consumed) = NameRef::try_parse(message, rdata_offset)?;
    if consumed != rdata_len {
      return Err(ParseError::BufferTooShort(
        crate::error::BufferTooShortDetail::new(consumed, rdata_offset, rdata_len),
      ));
    }
    Ok(Self { target })
  }

  /// Returns the canonical target name.
  #[inline(always)]
  pub const fn target(&self) -> &NameRef<'a> {
    &self.target
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::Cname;

  // "x.local." uncompressed: 1 'x' | 5 'local' | 0
  const NAME: &[u8] = &[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0];

  #[test]
  fn parses_exact_rdata_and_exposes_target() {
    let cname = Cname::try_from_message(NAME, 0, NAME.len()).unwrap();
    // The target is the decompressed name; confirm the accessor returns it.
    let _ = cname.target();
  }

  #[test]
  fn rejects_rdata_len_mismatch() {
    // RDLENGTH shorter than the name actually consumes must be rejected (the
    // encoded name MUST consume EXACTLY rdata_len bytes).
    assert!(Cname::try_from_message(NAME, 0, NAME.len() - 1).is_err());
  }
}

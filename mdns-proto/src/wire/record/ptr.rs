//! PTR record (domain name pointer, RFC 1035 §3.3.12).

use crate::{error::ParseError, wire::NameRef};

/// Parsed PTR record rdata.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Ptr<'a> {
  target: NameRef<'a>,
}

impl<'a> Ptr<'a> {
  /// Parses a PTR record's rdata. `message` is the full DNS message so
  /// compression pointers can resolve; `rdata_offset` is the start of the
  /// rdata bytes within it; `rdata_len` is the declared RDLENGTH.
  ///
  /// the inline portion of the encoded name (label bytes plus any
  /// initial compression pointer) MUST fit within the declared `rdata_len`.
  /// Without this check a record advertising a short `rdlength` could let
  /// inline labels run past the declared boundary and consume bytes from
  /// the next record, corrupting downstream conflict-routing,
  /// known-answer suppression, and cache decisions.
  pub fn try_from_message(
    message: &'a [u8],
    rdata_offset: usize,
    rdata_len: usize,
  ) -> Result<Self, ParseError> {
    // NameRef::try_parse returns (NameRef, consumed_bytes).
    // PTR rdata is EXACTLY one domain name — require the
    // consumed bytes to equal rdata_len.  Accepting `consumed <
    // rdata_len` would let a peer append trailing garbage inside the
    // declared rdlength and still see the record canonicalize as a
    // valid KAS hint, suppressing legitimate outgoing answers.
    let (target, consumed) = NameRef::try_parse(message, rdata_offset)?;
    if consumed != rdata_len {
      return Err(ParseError::BufferTooShort(
        crate::error::BufferTooShortDetail::new(consumed, rdata_offset, rdata_len),
      ));
    }
    Ok(Self { target })
  }

  /// Returns the target name.
  #[inline(always)]
  pub const fn target(&self) -> &NameRef<'a> {
    &self.target
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

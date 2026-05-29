//! PTR record (domain name pointer, RFC 1035 §3.3.12).

use crate::{error::ParseError, wire::NameRef};

/// Parsed PTR record rdata.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct PtrRecord<'a> {
  target: NameRef<'a>,
}

impl<'a> PtrRecord<'a> {
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
mod tests {
  use super::*;

  // ── PTR parser respects rdata_len boundary ───────────────────

  /// Inline name MUST fit within the declared RDLENGTH.  If a record
  /// claims `rdlen=5` but the inline target is 20 bytes, the parser
  /// MUST reject it — not silently consume bytes past the boundary
  /// into the next record.
  #[test]
  fn ptr_rejects_inline_name_past_rdlength() {
    // label "abcde" (1-byte length + 5-byte label + 1-byte root = 7 bytes)
    let msg: [u8; 7] = [5, b'a', b'b', b'c', b'd', b'e', 0];
    // Honest parse with full rdata_len: succeeds.
    assert!(PtrRecord::try_from_message(&msg, 0, msg.len()).is_ok());
    // Truncated rdata_len: name doesn't fit, must reject.
    let err = PtrRecord::try_from_message(&msg, 0, 3).unwrap_err();
    assert!(
      err.is_buffer_too_short(),
      "PTR with inline name past rdlength must return BufferTooShort; got {err:?}"
    );
  }

  /// PTR RDATA must be EXACTLY one domain name — declaring an
  /// `rdata_len` larger than the consumed name bytes (i.e. trailing
  /// garbage inside the rdlength) must reject.  Accepting trailing
  /// bytes would let a hostile peer canonicalize a malformed
  /// known-answer that suppresses a legitimate outgoing record.
  #[test]
  fn ptr_rejects_trailing_bytes_inside_rdlength() {
    // 7-byte name; declare rdlen = 9 (2 bytes of trailing garbage).
    let msg: [u8; 9] = [5, b'a', b'b', b'c', b'd', b'e', 0, 0xAA, 0xBB];
    let err = PtrRecord::try_from_message(&msg, 0, 9).unwrap_err();
    assert!(
      err.is_buffer_too_short(),
      "PTR with trailing garbage inside rdlength must reject; got {err:?}"
    );
  }
}

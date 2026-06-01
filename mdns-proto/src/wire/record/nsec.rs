//! NSEC record (negative-answer hint, RFC 4034 §4 + RFC 6762 §6.1).

use crate::{
  error::{BufferTooShortDetail, ParseError},
  wire::NameRef,
};

/// Parsed NSEC record rdata.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Nsec<'a> {
  next_name: NameRef<'a>,
  type_bitmap: &'a [u8],
}

impl<'a> Nsec<'a> {
  /// Parses an NSEC record from a message at the given rdata offset and length.
  pub fn try_from_message(
    message: &'a [u8],
    rdata_offset: usize,
    rdata_len: usize,
  ) -> Result<Self, ParseError> {
    let (next_name, name_bytes) = NameRef::try_parse(message, rdata_offset)?;
    let bitmap_start = rdata_offset.saturating_add(name_bytes);
    let rdata_end = rdata_offset.saturating_add(rdata_len);
    if bitmap_start > rdata_end {
      return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
        bitmap_start.saturating_sub(rdata_end),
        rdata_end,
        0,
      )));
    }
    let bitmap = message.get(bitmap_start..rdata_end).ok_or_else(|| {
      ParseError::BufferTooShort(BufferTooShortDetail::new(
        rdata_end.saturating_sub(bitmap_start),
        bitmap_start,
        message.len().saturating_sub(bitmap_start),
      ))
    })?;
    Ok(Self {
      next_name,
      type_bitmap: bitmap,
    })
  }

  #[inline(always)]
  pub const fn next_name(&self) -> &NameRef<'a> {
    &self.next_name
  }
  /// Raw type-bitmap bytes (RFC 4034 §4.1.2 encoding — parsing left to caller).
  #[inline(always)]
  pub const fn type_bitmap_slice(&self) -> &'a [u8] {
    self.type_bitmap
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::Nsec;
  use crate::error::ParseError;

  // "x.local." uncompressed (9 bytes).
  const NAME: &[u8] = &[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0];
  // NAME followed by a type bitmap [window 0, length 1, A-bit set] (12 bytes).
  const MSG: &[u8] = &[
    1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0, // next name
    0, 1, 0x40, // type bitmap: window 0, length 1, A (type 1) present
  ];

  #[test]
  fn parses_next_name_and_bitmap() {
    let nsec = Nsec::try_from_message(MSG, 0, MSG.len()).unwrap();
    let _ = nsec.next_name();
    assert_eq!(nsec.type_bitmap_slice(), [0u8, 1, 0x40].as_slice());
  }

  #[test]
  fn rejects_name_overrunning_rdata_len() {
    // rdata_len shorter than the encoded next-name actually consumes.
    assert!(matches!(
      Nsec::try_from_message(NAME, 0, 5),
      Err(ParseError::BufferTooShort(_))
    ));
  }

  #[test]
  fn rejects_rdata_len_past_message_end() {
    // rdata_len claims a type bitmap that runs off the end of the message.
    assert!(matches!(
      Nsec::try_from_message(NAME, 0, 20),
      Err(ParseError::BufferTooShort(_))
    ));
  }
}

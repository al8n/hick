//! NSEC record (negative-answer hint, RFC 4034 §4 + RFC 6762 §6.1).

use crate::{
  error::{BufferTooShortDetail, ParseError},
  wire::NameRef,
};

/// Parsed NSEC record rdata.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NsecRecord<'a> {
  next_name: NameRef<'a>,
  type_bitmap: &'a [u8],
}

impl<'a> NsecRecord<'a> {
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

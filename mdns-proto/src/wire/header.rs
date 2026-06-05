//! DNS header (RFC 1035 §4.1.1) — 12 bytes, fixed layout.

use super::Flags;
use crate::error::{BufferTooShortDetail, BufferTooSmallDetail, EncodeError, ParseError};

/// Size of the DNS header in bytes.
pub const HEADER_SIZE: usize = 12;

/// DNS message header.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub struct Header {
  id: u16,
  flags: Flags,
  question_count: u16,
  answer_count: u16,
  authority_count: u16,
  additional_count: u16,
}

impl Header {
  /// Constructs a zero-initialized header.
  #[inline(always)]
  pub const fn new() -> Self {
    Self {
      id: 0,
      flags: Flags::new(),
      question_count: 0,
      answer_count: 0,
      authority_count: 0,
      additional_count: 0,
    }
  }

  // Getters — projected, const where possible.

  /// Returns the transaction ID.
  #[inline(always)]
  pub const fn id(&self) -> u16 {
    self.id
  }
  /// Returns the flags.
  #[inline(always)]
  pub const fn flags(&self) -> Flags {
    self.flags
  }
  /// Returns a mutable reference to the flags for in-place modification.
  #[inline(always)]
  pub fn flags_mut(&mut self) -> &mut Flags {
    &mut self.flags
  }
  /// Returns the number of questions.
  #[inline(always)]
  pub const fn question_count(&self) -> u16 {
    self.question_count
  }
  /// Returns the number of answer records.
  #[inline(always)]
  pub const fn answer_count(&self) -> u16 {
    self.answer_count
  }
  /// Returns the number of authority records.
  #[inline(always)]
  pub const fn authority_count(&self) -> u16 {
    self.authority_count
  }
  /// Returns the number of additional records.
  #[inline(always)]
  pub const fn additional_count(&self) -> u16 {
    self.additional_count
  }

  // Setters (return &mut Self for chaining; no must_use).

  /// Sets the transaction ID.
  #[inline(always)]
  pub const fn set_id(&mut self, v: u16) -> &mut Self {
    self.id = v;
    self
  }
  /// Sets the flags.
  #[inline(always)]
  pub const fn set_flags(&mut self, v: Flags) -> &mut Self {
    self.flags = v;
    self
  }
  /// Sets the number of questions.
  #[inline(always)]
  pub const fn set_question_count(&mut self, v: u16) -> &mut Self {
    self.question_count = v;
    self
  }
  /// Sets the number of answer records.
  #[inline(always)]
  pub const fn set_answer_count(&mut self, v: u16) -> &mut Self {
    self.answer_count = v;
    self
  }
  /// Sets the number of authority records.
  #[inline(always)]
  pub const fn set_authority_count(&mut self, v: u16) -> &mut Self {
    self.authority_count = v;
    self
  }
  /// Sets the number of additional records.
  #[inline(always)]
  pub const fn set_additional_count(&mut self, v: u16) -> &mut Self {
    self.additional_count = v;
    self
  }

  // Builders (consuming, #[must_use]).

  /// Returns a header with the transaction ID set.
  #[must_use]
  #[inline(always)]
  pub const fn with_id(mut self, v: u16) -> Self {
    self.id = v;
    self
  }
  /// Returns a header with the flags set.
  #[must_use]
  #[inline(always)]
  pub const fn with_flags(mut self, v: Flags) -> Self {
    self.flags = v;
    self
  }
  /// Returns a header with the number of questions set.
  #[must_use]
  #[inline(always)]
  pub const fn with_question_count(mut self, v: u16) -> Self {
    self.question_count = v;
    self
  }
  /// Returns a header with the number of answer records set.
  #[must_use]
  #[inline(always)]
  pub const fn with_answer_count(mut self, v: u16) -> Self {
    self.answer_count = v;
    self
  }
  /// Returns a header with the number of authority records set.
  #[must_use]
  #[inline(always)]
  pub const fn with_authority_count(mut self, v: u16) -> Self {
    self.authority_count = v;
    self
  }
  /// Returns a header with the number of additional records set.
  #[must_use]
  #[inline(always)]
  pub const fn with_additional_count(mut self, v: u16) -> Self {
    self.additional_count = v;
    self
  }

  /// Parse a 12-byte DNS header from the start of `buf`. Returns the header
  /// and a slice of the bytes following it.
  pub fn try_parse(buf: &[u8]) -> Result<(Self, &[u8]), ParseError> {
    if buf.len() < HEADER_SIZE {
      return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
        HEADER_SIZE,
        0,
        buf.len(),
      )));
    }
    let (head, rest) = match buf.split_at_checked(HEADER_SIZE) {
      Some(parts) => parts,
      None => {
        return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
          HEADER_SIZE,
          0,
          buf.len(),
        )));
      }
    };

    let id_arr: &[u8; 2] = match head.first_chunk::<2>() {
      Some(a) => a,
      None => {
        return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          0,
          head.len(),
        )));
      }
    };
    let id = u16::from_be_bytes(*id_arr);

    let flags_arr: &[u8; 2] = match head.get(2..4).and_then(|s| s.first_chunk::<2>()) {
      Some(a) => a,
      None => {
        return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          2,
          head.len().saturating_sub(2),
        )));
      }
    };
    let flags = Flags::from_u16(u16::from_be_bytes(*flags_arr));

    let qd_arr: &[u8; 2] = match head.get(4..6).and_then(|s| s.first_chunk::<2>()) {
      Some(a) => a,
      None => {
        return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          4,
          head.len().saturating_sub(4),
        )));
      }
    };
    let an_arr: &[u8; 2] = match head.get(6..8).and_then(|s| s.first_chunk::<2>()) {
      Some(a) => a,
      None => {
        return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          6,
          head.len().saturating_sub(6),
        )));
      }
    };
    let ns_arr: &[u8; 2] = match head.get(8..10).and_then(|s| s.first_chunk::<2>()) {
      Some(a) => a,
      None => {
        return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          8,
          head.len().saturating_sub(8),
        )));
      }
    };
    let ar_arr: &[u8; 2] = match head.get(10..12).and_then(|s| s.first_chunk::<2>()) {
      Some(a) => a,
      None => {
        return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          10,
          head.len().saturating_sub(10),
        )));
      }
    };

    Ok((
      Self {
        id,
        flags,
        question_count: u16::from_be_bytes(*qd_arr),
        answer_count: u16::from_be_bytes(*an_arr),
        authority_count: u16::from_be_bytes(*ns_arr),
        additional_count: u16::from_be_bytes(*ar_arr),
      },
      rest,
    ))
  }

  /// Write a 12-byte DNS header into the start of `out`. Returns the number
  /// of bytes written (always [`HEADER_SIZE`] on success).
  pub fn write(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
    if out.len() < HEADER_SIZE {
      return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
        HEADER_SIZE,
        out.len(),
      )));
    }
    let head = match out.get_mut(..HEADER_SIZE) {
      Some(s) => s,
      None => {
        return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
          HEADER_SIZE,
          out.len(),
        )));
      }
    };

    let pairs: [u16; 6] = [
      self.id,
      self.flags.to_u16(),
      self.question_count,
      self.answer_count,
      self.authority_count,
      self.additional_count,
    ];
    let mut cursor = 0usize;
    for value in pairs {
      let bytes = value.to_be_bytes();
      let slot = match head.get_mut(cursor..cursor.saturating_add(2)) {
        Some(s) => s,
        None => {
          return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
            HEADER_SIZE,
            out.len(),
          )));
        }
      };
      slot.copy_from_slice(&bytes);
      cursor = cursor.saturating_add(2);
    }

    Ok(HEADER_SIZE)
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

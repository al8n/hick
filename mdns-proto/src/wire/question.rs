//! DNS question record (RFC 1035 §4.1.2).

use super::{NameRef, ResourceClass, ResourceType, resource_class::UNICAST_RESPONSE_BIT};
use crate::error::{BufferTooShortDetail, ParseError};

/// A parsed DNS question (zero-copy reference into a message buffer).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct QuestionRef<'a> {
  qname: NameRef<'a>,
  qtype: ResourceType,
  qclass: ResourceClass,
  unicast_response: bool,
}

impl<'a> QuestionRef<'a> {
  /// Parse a question starting at `offset` in `message`.
  /// Returns the question and the next offset to continue parsing from.
  pub fn try_parse(message: &'a [u8], offset: usize) -> Result<(Self, usize), ParseError> {
    let (qname, name_bytes) = NameRef::try_parse(message, offset)?;
    let after_name = offset.saturating_add(name_bytes);

    let qtype_slot = message
      .get(after_name..after_name.saturating_add(2))
      .and_then(|s| s.first_chunk::<2>())
      .ok_or_else(|| {
        ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          after_name,
          message.len().saturating_sub(after_name),
        ))
      })?;
    let qtype = ResourceType::from_u16(u16::from_be_bytes(*qtype_slot));

    let after_type = after_name.saturating_add(2);
    let qclass_slot = message
      .get(after_type..after_type.saturating_add(2))
      .and_then(|s| s.first_chunk::<2>())
      .ok_or_else(|| {
        ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          after_type,
          message.len().saturating_sub(after_type),
        ))
      })?;
    let raw = u16::from_be_bytes(*qclass_slot);
    let unicast_response = (raw & UNICAST_RESPONSE_BIT) != 0;
    let qclass = ResourceClass::from_u16(raw);

    let after_class = after_type.saturating_add(2);
    Ok((
      Self {
        qname,
        qtype,
        qclass,
        unicast_response,
      },
      after_class,
    ))
  }

  /// Returns the question's name.
  #[inline(always)]
  pub const fn qname(&self) -> &NameRef<'a> {
    &self.qname
  }

  /// Returns the question type.
  #[inline(always)]
  pub const fn qtype(&self) -> ResourceType {
    self.qtype
  }

  /// Returns the question class (with unicast-response bit stripped).
  #[inline(always)]
  pub const fn qclass(&self) -> ResourceClass {
    self.qclass
  }

  /// `true` if the unicast-response bit (RFC 6762 §5.4) was set on this
  /// question's class field.
  #[inline(always)]
  pub const fn unicast_response_requested(&self) -> bool {
    self.unicast_response
  }
}

#[cfg(test)]
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::QuestionRef;
  use crate::error::ParseError;

  #[test]
  fn parses_minimal_question() {
    // Name: "x" (1 byte 'x' + 0) = 3 bytes
    // Type 0x0001 (A) + Class 0x0001 (IN) = 4 bytes
    let buf: [u8; 7] = [0x01, b'x', 0x00, 0x00, 0x01, 0x00, 0x01];
    let (q, next) = QuestionRef::try_parse(&buf, 0).unwrap();
    assert_eq!(next, 7);
    assert!(q.qtype().is_a());
    assert!(q.qclass().is_in());
    assert!(!q.unicast_response_requested());
  }

  #[test]
  fn unicast_bit_is_recognised() {
    let buf: [u8; 7] = [0x01, b'x', 0x00, 0x00, 0x01, 0x80, 0x01];
    let (q, _) = QuestionRef::try_parse(&buf, 0).unwrap();
    assert!(q.unicast_response_requested());
    assert!(q.qclass().is_in());
  }

  #[test]
  fn rejects_truncated_qtype() {
    // The name parses, but no qtype bytes follow.
    let buf: [u8; 3] = [0x01, b'x', 0x00];
    assert!(matches!(
      QuestionRef::try_parse(&buf, 0),
      Err(ParseError::BufferTooShort(_))
    ));
  }

  #[test]
  fn rejects_truncated_qclass() {
    // Name + qtype present, but the qclass field is truncated.
    let buf: [u8; 5] = [0x01, b'x', 0x00, 0x00, 0x01];
    assert!(matches!(
      QuestionRef::try_parse(&buf, 0),
      Err(ParseError::BufferTooShort(_))
    ));
  }
}

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
mod tests;

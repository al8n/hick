//! SRV record (server location, RFC 2782).

use crate::{
  error::{BufferTooShortDetail, ParseError},
  wire::NameRef,
};

/// Parsed SRV record rdata: priority, weight, port, target.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Srv<'a> {
  priority: u16,
  weight: u16,
  port: u16,
  target: NameRef<'a>,
}

impl<'a> Srv<'a> {
  /// Parse an SRV record's rdata. `message` is the full message; `rdata_offset`
  /// is the start of the rdata bytes within it; `rdata_len` is the declared
  /// RDLENGTH.
  ///
  /// the 6-byte fixed header (priority+weight+port) AND the inline
  /// portion of the target name MUST fit within the declared `rdata_len`.
  /// A record advertising a short rdlength must not be allowed to consume
  /// bytes past its declared boundary.
  pub fn try_from_message(
    message: &'a [u8],
    rdata_offset: usize,
    rdata_len: usize,
  ) -> Result<Self, ParseError> {
    if rdata_len < 6 {
      return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
        6,
        rdata_offset,
        rdata_len,
      )));
    }
    let head = message
      .get(rdata_offset..rdata_offset.saturating_add(6))
      .and_then(|s| s.first_chunk::<6>())
      .ok_or_else(|| {
        ParseError::BufferTooShort(BufferTooShortDetail::new(
          6,
          rdata_offset,
          message.len().saturating_sub(rdata_offset),
        ))
      })?;

    let priority = u16::from_be_bytes([head[0], head[1]]);
    let weight = u16::from_be_bytes([head[2], head[3]]);
    let port = u16::from_be_bytes([head[4], head[5]]);

    let target_offset = rdata_offset.saturating_add(6);
    // SRV rdata is EXACTLY 6 bytes (priority + weight +
    // port) + one domain name.  Require `6 + consumed == rdata_len`.
    // Trailing bytes inside the declared rdlength would otherwise be
    // silently dropped — a hostile known-answer could append garbage
    // to a matching SRV and still suppress the legitimate outgoing
    // record.
    let (target, consumed) = NameRef::try_parse(message, target_offset)?;
    if consumed.saturating_add(6) != rdata_len {
      return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
        consumed.saturating_add(6),
        rdata_offset,
        rdata_len,
      )));
    }

    Ok(Self {
      priority,
      weight,
      port,
      target,
    })
  }

  /// Returns the priority field.
  #[inline(always)]
  pub const fn priority(&self) -> u16 {
    self.priority
  }
  /// Returns the weight field.
  #[inline(always)]
  pub const fn weight(&self) -> u16 {
    self.weight
  }
  /// Returns the port number.
  #[inline(always)]
  pub const fn port(&self) -> u16 {
    self.port
  }
  /// Returns the target host name.
  #[inline(always)]
  pub const fn target(&self) -> &NameRef<'a> {
    &self.target
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

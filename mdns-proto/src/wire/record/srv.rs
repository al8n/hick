//! SRV record (server location, RFC 2782).

use crate::{
  error::{BufferTooShortDetail, ParseError},
  wire::NameRef,
};

/// Parsed SRV record rdata: priority, weight, port, target.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct SrvRecord<'a> {
  priority: u16,
  weight: u16,
  port: u16,
  target: NameRef<'a>,
}

impl<'a> SrvRecord<'a> {
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
mod tests {
  use super::*;

  // ── SRV parser respects rdata_len boundary ───────────────────

  /// SRV header is 6 bytes (priority + weight + port).  rdata_len < 6
  /// must reject.
  #[test]
  fn srv_rejects_rdata_shorter_than_header() {
    let msg = [0u8; 16];
    let err = SrvRecord::try_from_message(&msg, 0, 4).unwrap_err();
    assert!(err.is_buffer_too_short());
  }

  /// Inline target name MUST fit within the declared `rdata_len`.  A
  /// truncated rdata_len that doesn't cover the encoded name must yield
  /// BufferTooShort.
  #[test]
  fn srv_rejects_inline_name_past_rdlength() {
    // 6-byte header (priority, weight, port) + 7-byte name = 13 bytes.
    let msg: [u8; 13] = [
      0, 0, 0, 0, 0, 80, // priority, weight, port
      5, b'a', b'b', b'c', b'd', b'e', 0, // name
    ];
    // Full rdata_len succeeds.
    assert!(SrvRecord::try_from_message(&msg, 0, msg.len()).is_ok());
    // Truncated rdata_len just covers the header + 2 bytes of name → reject.
    let err = SrvRecord::try_from_message(&msg, 0, 8).unwrap_err();
    assert!(
      err.is_buffer_too_short(),
      "SRV with inline name past rdlength must return BufferTooShort; got {err:?}"
    );
  }

  /// SRV RDATA is EXACTLY 6-byte header + one domain name.
  /// Trailing bytes inside the declared rdlength must reject.
  #[test]
  fn srv_rejects_trailing_bytes_inside_rdlength() {
    // 6-byte header + 7-byte name + 2 bytes garbage = 15 bytes.
    let msg: [u8; 15] = [
      0, 0, 0, 0, 0, 80, // priority, weight, port
      5, b'a', b'b', b'c', b'd', b'e', 0, // name
      0xAA, 0xBB, // trailing garbage
    ];
    let err = SrvRecord::try_from_message(&msg, 0, 15).unwrap_err();
    assert!(
      err.is_buffer_too_short(),
      "SRV with trailing garbage inside rdlength must reject; got {err:?}"
    );
  }
}

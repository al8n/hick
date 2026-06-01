//! Packed 16-bit DNS header flags field (RFC 1035 §4.1.1, RFC 6762 §18.6-18.12).

use super::{Opcode, ResponseCode};

const QR_BIT: u16 = 1 << 15;
const OPCODE_SHIFT: u32 = 11;
const OPCODE_MASK: u16 = 0b1111 << OPCODE_SHIFT;
const AA_BIT: u16 = 1 << 10;
const TC_BIT: u16 = 1 << 9;
const RD_BIT: u16 = 1 << 8;
const RA_BIT: u16 = 1 << 7;
const RCODE_MASK: u16 = 0b1111;

/// Packed 16-bit DNS header flags field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub struct Flags {
  bits: u16,
}

impl Flags {
  /// Empty flags (all zero — query, no error).
  #[inline(always)]
  pub const fn new() -> Self {
    Self { bits: 0 }
  }

  /// Constructs from raw wire bits.
  #[inline(always)]
  pub const fn from_u16(bits: u16) -> Self {
    Self { bits }
  }

  /// Returns the raw wire bits.
  #[inline(always)]
  pub const fn to_u16(&self) -> u16 {
    self.bits
  }

  /// `true` if this is a response (QR bit set).
  #[inline(always)]
  pub const fn is_response(&self) -> bool {
    self.bits & QR_BIT != 0
  }

  /// Opcode (4 bits).
  #[inline(always)]
  pub const fn opcode(&self) -> Opcode {
    Opcode::from_u8(((self.bits & OPCODE_MASK) >> OPCODE_SHIFT) as u8)
  }

  /// `true` if authoritative answer.
  #[inline(always)]
  pub const fn is_authoritative(&self) -> bool {
    self.bits & AA_BIT != 0
  }

  /// `true` if truncated (TC bit).
  #[inline(always)]
  pub const fn is_truncated(&self) -> bool {
    self.bits & TC_BIT != 0
  }

  /// `true` if recursion desired (RD bit).
  #[inline(always)]
  pub const fn is_recursion_desired(&self) -> bool {
    self.bits & RD_BIT != 0
  }

  /// `true` if recursion available (RA bit).
  #[inline(always)]
  pub const fn is_recursion_available(&self) -> bool {
    self.bits & RA_BIT != 0
  }

  /// Response code (4 bits).
  #[inline(always)]
  pub const fn response_code(&self) -> ResponseCode {
    ResponseCode::from_u8((self.bits & RCODE_MASK) as u8)
  }

  // ── Mutators (per §3 rust-type-conventions) ────────────────────

  /// Sets the QR bit (this is a response).
  #[inline(always)]
  pub const fn set_response(&mut self) -> &mut Self {
    self.bits |= QR_BIT;
    self
  }
  /// Same as [`Self::set_response`] but consuming.
  #[inline(always)]
  pub const fn with_response(mut self) -> Self {
    self.bits |= QR_BIT;
    self
  }
  /// Clears the QR bit (this is a query).
  #[inline(always)]
  pub const fn clear_response(&mut self) -> &mut Self {
    self.bits &= !QR_BIT;
    self
  }

  /// Sets the opcode.
  #[inline(always)]
  pub const fn set_opcode(&mut self, op: Opcode) -> &mut Self {
    self.bits &= !OPCODE_MASK;
    self.bits |= ((op.to_u8() as u16) << OPCODE_SHIFT) & OPCODE_MASK;
    self
  }
  /// Consuming version of [`Self::set_opcode`].
  #[inline(always)]
  pub const fn with_opcode(mut self, op: Opcode) -> Self {
    self.bits &= !OPCODE_MASK;
    self.bits |= ((op.to_u8() as u16) << OPCODE_SHIFT) & OPCODE_MASK;
    self
  }

  /// Sets the AA bit (authoritative answer).
  #[inline(always)]
  pub const fn set_authoritative(&mut self) -> &mut Self {
    self.bits |= AA_BIT;
    self
  }
  /// Consuming version.
  #[inline(always)]
  pub const fn with_authoritative(mut self) -> Self {
    self.bits |= AA_BIT;
    self
  }
  /// Clears the AA bit.
  #[inline(always)]
  pub const fn clear_authoritative(&mut self) -> &mut Self {
    self.bits &= !AA_BIT;
    self
  }

  /// Sets the TC bit.
  #[inline(always)]
  pub const fn set_truncated(&mut self) -> &mut Self {
    self.bits |= TC_BIT;
    self
  }
  /// Consuming version.
  #[inline(always)]
  pub const fn with_truncated(mut self) -> Self {
    self.bits |= TC_BIT;
    self
  }
  /// Clears the TC bit.
  #[inline(always)]
  pub const fn clear_truncated(&mut self) -> &mut Self {
    self.bits &= !TC_BIT;
    self
  }

  /// Sets the response code.
  #[inline(always)]
  pub const fn set_response_code(&mut self, rc: ResponseCode) -> &mut Self {
    self.bits &= !RCODE_MASK;
    self.bits |= (rc.to_u8() as u16) & RCODE_MASK;
    self
  }
  /// Consuming version.
  #[inline(always)]
  pub const fn with_response_code(mut self, rc: ResponseCode) -> Self {
    self.bits &= !RCODE_MASK;
    self.bits |= (rc.to_u8() as u16) & RCODE_MASK;
    self
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::{Flags, Opcode, ResponseCode};

  #[test]
  fn default_is_zero() {
    let f = Flags::new();
    assert_eq!(f.to_u16(), 0);
    assert!(!f.is_response());
    assert!(f.opcode().is_query());
    assert!(f.response_code().is_no_error());
  }

  #[test]
  fn with_response_sets_qr_bit() {
    let f = Flags::new().with_response();
    assert!(f.is_response());
    assert_eq!(f.to_u16() & 0x8000, 0x8000);
  }

  #[test]
  fn with_opcode_roundtrip() {
    let f = Flags::new().with_opcode(Opcode::Update);
    assert!(f.opcode().is_update());
  }

  #[test]
  fn with_response_code_roundtrip() {
    let f = Flags::new().with_response_code(ResponseCode::NameError);
    assert!(f.response_code().is_name_error());
  }

  #[test]
  fn flags_chaining() {
    let f = Flags::new()
      .with_response()
      .with_authoritative()
      .with_response_code(ResponseCode::NoError);
    assert!(f.is_response());
    assert!(f.is_authoritative());
    assert!(f.response_code().is_no_error());
  }

  #[test]
  fn recursion_bits() {
    assert!(Flags::from_u16(0x0100).is_recursion_desired()); // RD = 1 << 8
    assert!(!Flags::new().is_recursion_desired());
    assert!(Flags::from_u16(0x0080).is_recursion_available()); // RA = 1 << 7
    assert!(!Flags::new().is_recursion_available());
  }

  #[test]
  fn mut_setters_and_clears() {
    let mut f = Flags::new();
    f.set_response();
    assert!(f.is_response());
    f.clear_response();
    assert!(!f.is_response());

    f.set_opcode(Opcode::Update);
    assert!(f.opcode().is_update());

    f.set_authoritative();
    assert!(f.is_authoritative());
    f.clear_authoritative();
    assert!(!f.is_authoritative());

    f.set_truncated();
    assert!(f.is_truncated());
    f.clear_truncated();
    assert!(!f.is_truncated());

    f.set_response_code(ResponseCode::NameError);
    assert!(f.response_code().is_name_error());
  }

  #[test]
  fn with_truncated_consuming() {
    assert!(Flags::new().with_truncated().is_truncated());
  }
}

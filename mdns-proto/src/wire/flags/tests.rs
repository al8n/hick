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

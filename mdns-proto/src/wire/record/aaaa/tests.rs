use super::AAAA;

#[test]
fn parses_16_bytes() {
  let r = AAAA::try_from_rdata(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
  assert_eq!(r.addr().segments()[0], 0xfe80);
  assert_eq!(r.addr().segments()[7], 0x0001);
}

#[test]
fn rejects_short() {
  let err = AAAA::try_from_rdata(&[0u8; 10]).unwrap_err();
  assert!(err.is_buffer_too_short());
}

/// oversize rdata must also be rejected.
#[test]
fn rejects_oversize() {
  let err = AAAA::try_from_rdata(&[0u8; 20]).unwrap_err();
  assert!(err.is_buffer_too_short());
}

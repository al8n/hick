use super::A;

#[test]
fn parses_4_bytes() {
  let r = A::try_from_rdata(&[192, 168, 1, 1]).unwrap();
  assert_eq!(r.addr().octets(), [192, 168, 1, 1]);
}

#[test]
fn rejects_short() {
  let err = A::try_from_rdata(&[1, 2, 3]).unwrap_err();
  assert!(err.is_buffer_too_short());
}

/// oversize rdata must also be rejected — A record RDLENGTH is
/// always exactly 4 bytes per RFC 1035.  Silent truncation would
/// mask a wire-level protocol error.
#[test]
fn rejects_oversize() {
  let err = A::try_from_rdata(&[1, 2, 3, 4, 5]).unwrap_err();
  assert!(err.is_buffer_too_short());
}

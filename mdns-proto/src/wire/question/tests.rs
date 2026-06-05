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

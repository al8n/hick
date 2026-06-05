use super::{HEADER_SIZE, Header};
use crate::wire::Flags;

#[test]
fn parse_too_short_fails() {
  let buf = [0u8; 11];
  let err = Header::try_parse(&buf).unwrap_err();
  assert!(err.is_buffer_too_short());
}

#[test]
fn parse_minimal_zero_header() {
  let buf = [0u8; HEADER_SIZE];
  let (h, rest) = Header::try_parse(&buf).unwrap();
  assert_eq!(h.id(), 0);
  assert_eq!(h.flags().to_u16(), 0);
  assert_eq!(h.question_count(), 0);
  assert_eq!(rest.len(), 0);
}

#[test]
fn roundtrip_known_values() {
  let h = Header::new()
    .with_id(0xCAFE)
    .with_flags(Flags::from_u16(0x8400))
    .with_question_count(1)
    .with_answer_count(2)
    .with_authority_count(3)
    .with_additional_count(4);
  let mut out = [0u8; HEADER_SIZE];
  let n = h.write(&mut out).unwrap();
  assert_eq!(n, HEADER_SIZE);
  let (parsed, rest) = Header::try_parse(&out).unwrap();
  assert_eq!(parsed, h);
  assert!(rest.is_empty());
}

#[test]
fn write_too_small_fails() {
  let h = Header::new();
  let mut out = [0u8; 5];
  let err = h.write(&mut out).unwrap_err();
  assert!(err.is_buffer_too_small());
}

#[test]
fn setters_mutate_in_place() {
  let mut h = Header::new();
  h.set_id(0x1234)
    .set_flags(Flags::from_u16(0x8000))
    .set_question_count(1)
    .set_answer_count(2)
    .set_authority_count(3)
    .set_additional_count(4);
  assert_eq!(h.id(), 0x1234);
  assert_eq!(h.flags().to_u16(), 0x8000);
  assert_eq!(h.question_count(), 1);
  assert_eq!(h.answer_count(), 2);
  assert_eq!(h.authority_count(), 3);
  assert_eq!(h.additional_count(), 4);
  *h.flags_mut() = Flags::from_u16(0x0400);
  assert_eq!(h.flags().to_u16(), 0x0400);
}

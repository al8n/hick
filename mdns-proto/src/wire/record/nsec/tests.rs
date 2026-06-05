use super::Nsec;
use crate::error::ParseError;

// "x.local." uncompressed (9 bytes).
const NAME: &[u8] = &[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0];
// NAME followed by a type bitmap [window 0, length 1, A-bit set] (12 bytes).
const MSG: &[u8] = &[
  1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0, // next name
  0, 1, 0x40, // type bitmap: window 0, length 1, A (type 1) present
];

#[test]
fn parses_next_name_and_bitmap() {
  let nsec = Nsec::try_from_message(MSG, 0, MSG.len()).unwrap();
  let _ = nsec.next_name();
  assert_eq!(nsec.type_bitmap_slice(), [0u8, 1, 0x40].as_slice());
}

#[test]
fn rejects_name_overrunning_rdata_len() {
  // rdata_len shorter than the encoded next-name actually consumes.
  assert!(matches!(
    Nsec::try_from_message(NAME, 0, 5),
    Err(ParseError::BufferTooShort(_))
  ));
}

#[test]
fn rejects_rdata_len_past_message_end() {
  // rdata_len claims a type bitmap that runs off the end of the message.
  assert!(matches!(
    Nsec::try_from_message(NAME, 0, 20),
    Err(ParseError::BufferTooShort(_))
  ));
}

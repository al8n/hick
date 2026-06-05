use super::Txt;

#[test]
fn iterates_segments() {
  // "key=val" (7) + "x" (1) + "" (0)
  let rdata: [u8; 11] = [7, b'k', b'e', b'y', b'=', b'v', b'a', b'l', 1, b'x', 0];
  let txt = Txt::from_rdata(&rdata);
  let mut it = txt.segments();
  assert_eq!(it.next().unwrap().unwrap(), b"key=val".as_slice());
  assert_eq!(it.next().unwrap().unwrap(), b"x".as_slice());
  assert_eq!(it.next().unwrap().unwrap(), b"".as_slice());
  assert!(it.next().is_none());
}

#[test]
fn rejects_short_segment() {
  let rdata: [u8; 3] = [10, b'a', b'b']; // claims 10 bytes, only 2 follow
  let txt = Txt::from_rdata(&rdata);
  let err = txt.segments().next().unwrap().unwrap_err();
  assert!(err.is_buffer_too_short());
}

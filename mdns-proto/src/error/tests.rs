#[cfg(feature = "std")]
use super::ParseError;
use super::{BufferTooShortDetail, BufferTooSmallDetail};

#[test]
fn buffer_too_short_detail_accessors() {
  let d = BufferTooShortDetail::new(4, 12, 1);
  assert_eq!(d.needed(), 4);
  assert_eq!(d.at(), 12);
  assert_eq!(d.have(), 1);
}

#[test]
fn buffer_too_small_detail_accessors() {
  let d = BufferTooSmallDetail::new(100, 32);
  assert_eq!(d.needed(), 100);
  assert_eq!(d.have(), 32);
}

#[cfg(feature = "std")]
#[test]
fn parse_error_buffer_too_short_display() {
  let e = ParseError::BufferTooShort(BufferTooShortDetail::new(4, 12, 1));
  assert_eq!(
    std::format!("{e}"),
    "buffer too short: needed 4 bytes at offset 12, had 1"
  );
}

#[test]
fn is_empty_and_pointer_rdlength_accessors() {
  use super::{PointerForwardDetail, RdlengthOverrunDetail};
  assert!(!BufferTooShortDetail::new(4, 12, 1).is_empty());
  assert!(BufferTooShortDetail::new(4, 12, 0).is_empty());
  assert!(!BufferTooSmallDetail::new(100, 32).is_empty());
  assert!(BufferTooSmallDetail::new(100, 0).is_empty());

  let p = PointerForwardDetail::new(10, 5);
  assert_eq!(p.ptr(), 10);
  assert_eq!(p.at(), 5);

  let r = RdlengthOverrunDetail::new(20, 12, 4);
  assert_eq!(r.rdlen(), 20);
  assert_eq!(r.at(), 12);
  assert_eq!(r.rem(), 4);
}

use super::{
  BindError, BufferTooShortDetail, InterfaceNotFoundDetail, JoinError, ParseRecvMetaError,
};

#[test]
fn detail_accessors_and_display() {
  let d = InterfaceNotFoundDetail::new(7);
  assert_eq!(d.index(), 7);
  assert_eq!(d.to_string(), "interface index 7 not found");

  let b = BufferTooShortDetail::new(20, 8);
  assert_eq!(b.needed(), 20);
  assert_eq!(b.have(), 8);
  assert_eq!(
    b.to_string(),
    "cmsg buffer too short: needed 20 bytes, had 8"
  );
}

#[test]
fn error_enum_display_and_is_variant() {
  let bind = BindError::InterfaceNotFound(InterfaceNotFoundDetail::new(3));
  assert!(bind.is_interface_not_found());
  assert_eq!(bind.to_string(), "interface index 3 not found");

  let join = JoinError::InterfaceNotFound(InterfaceNotFoundDetail::new(4));
  assert!(join.is_interface_not_found());
  assert_eq!(join.to_string(), "interface index 4 not found");

  let parse = ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(16, 4));
  assert!(parse.is_buffer_too_short());
  assert_eq!(
    parse.to_string(),
    "cmsg buffer too short: needed 16 bytes, had 4"
  );

  let missing = ParseRecvMetaError::MissingPktinfo;
  assert!(missing.is_missing_pktinfo());
  assert_eq!(missing.to_string(), "no pktinfo cmsg in ancillary buffer");
}

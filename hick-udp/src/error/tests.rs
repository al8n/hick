use super::{
  BindError, BufferTooShortDetail, InterfaceNotFoundDetail, JoinError,
  MulticastLoopNotAppliedDetail, MulticastTtlNotAppliedDetail, ParseRecvMetaError,
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

  // The two IPv4 multicast scalar read-backs report per option, so each carries
  // its own requested/observed pair and names its own option in the message a
  // failed bind logs.
  let l = MulticastLoopNotAppliedDetail::new(true, false);
  assert!(l.requested());
  assert!(!l.observed());
  assert_eq!(
    l.to_string(),
    "IPv4 multicast loopback not applied: requested true, observed false"
  );

  let t = MulticastTtlNotAppliedDetail::new(255, 0);
  assert_eq!(t.requested(), 255);
  assert_eq!(t.observed(), 0);
  assert_eq!(
    t.to_string(),
    "IPv4 multicast TTL not applied: requested 255, observed 0"
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

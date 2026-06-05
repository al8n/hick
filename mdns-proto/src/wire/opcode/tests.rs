use super::Opcode;

#[test]
fn from_u8_to_u8_roundtrip_known() {
  for raw in [0u8, 1, 2, 4, 5] {
    assert_eq!(Opcode::from_u8(raw).to_u8(), raw);
  }
}

#[test]
fn from_u8_to_u8_roundtrip_unknown() {
  for raw in [3u8, 6, 7, 8, 15, 100, 200, 255] {
    let op = Opcode::from_u8(raw);
    assert!(op.is_unknown());
    assert_eq!(op.to_u8(), raw);
  }
}

#[test]
fn as_str_slug_for_every_variant() {
  assert_eq!(Opcode::Query.as_str(), "query");
  assert_eq!(Opcode::InverseQuery.as_str(), "inverse_query");
  assert_eq!(Opcode::Status.as_str(), "status");
  assert_eq!(Opcode::Notify.as_str(), "notify");
  assert_eq!(Opcode::Update.as_str(), "update");
  assert_eq!(Opcode::Unknown(9).as_str(), "unknown");
}

use super::ResponseCode;

#[test]
fn roundtrip_known() {
  for raw in 0u8..=5 {
    assert_eq!(ResponseCode::from_u8(raw).to_u8(), raw);
  }
}

#[test]
fn roundtrip_unknown() {
  for raw in [6u8, 10, 100, 255] {
    assert!(ResponseCode::from_u8(raw).is_unknown());
    assert_eq!(ResponseCode::from_u8(raw).to_u8(), raw);
  }
}

#[test]
fn as_str_slug_for_every_variant() {
  assert_eq!(ResponseCode::NoError.as_str(), "no_error");
  assert_eq!(ResponseCode::FormatError.as_str(), "format_error");
  assert_eq!(ResponseCode::ServerFailure.as_str(), "server_failure");
  assert_eq!(ResponseCode::NameError.as_str(), "name_error");
  assert_eq!(ResponseCode::NotImplemented.as_str(), "not_implemented");
  assert_eq!(ResponseCode::Refused.as_str(), "refused");
  assert_eq!(ResponseCode::Unknown(9).as_str(), "unknown");
}

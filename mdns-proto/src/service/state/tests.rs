use super::ServiceState;

#[test]
fn as_str_slug_for_every_variant() {
  assert_eq!(ServiceState::Init.as_str(), "init");
  assert_eq!(ServiceState::Probing(1).as_str(), "probing");
  assert_eq!(ServiceState::Announcing(0).as_str(), "announcing");
  assert_eq!(ServiceState::Established.as_str(), "established");
  assert_eq!(ServiceState::Conflicting.as_str(), "conflicting");
}

#[cfg(feature = "std")]
#[test]
fn display_uses_slug() {
  assert_eq!(std::format!("{}", ServiceState::Probing(2)), "probing");
}

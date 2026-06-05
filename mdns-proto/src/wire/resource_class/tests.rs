use super::{CACHE_FLUSH_BIT, ResourceClass};

#[test]
fn cache_flush_bit_stripped_by_default() {
  let raw = 0x8001;
  assert!(ResourceClass::from_u16(raw).is_in());
}

#[test]
fn cache_flush_bit_preserved_in_raw() {
  let raw = 0x8001;
  let parsed = ResourceClass::from_u16_raw(raw);
  assert!(parsed.is_unknown());
  assert_eq!(parsed.to_u16(), raw);
}

#[test]
fn cache_flush_constant() {
  assert_eq!(CACHE_FLUSH_BIT, 0x8000);
}

#[test]
fn as_str_slug_for_every_variant() {
  assert_eq!(ResourceClass::In.as_str(), "in");
  assert_eq!(ResourceClass::Any.as_str(), "any");
  assert_eq!(ResourceClass::Unknown(7).as_str(), "unknown");
}

#[test]
fn known_classes_roundtrip_through_wire_value() {
  assert_eq!(ResourceClass::In.to_u16(), 1);
  assert_eq!(ResourceClass::Any.to_u16(), 255);
  assert!(ResourceClass::from_u16(1).is_in());
  assert!(ResourceClass::from_u16(255).is_any());
  // The cache-flush/unicast top bit is stripped before matching.
  assert!(ResourceClass::from_u16(CACHE_FLUSH_BIT | 255).is_any());
}

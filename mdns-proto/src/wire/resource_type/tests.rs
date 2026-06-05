use super::ResourceType;

#[test]
fn roundtrip_known() {
  for raw in [1u16, 5, 12, 13, 16, 28, 33, 47, 255] {
    assert_eq!(ResourceType::from_u16(raw).to_u16(), raw);
  }
}

#[test]
fn roundtrip_unknown() {
  for raw in [0u16, 2, 100, 999, 65535] {
    assert!(ResourceType::from_u16(raw).is_unknown());
    assert_eq!(ResourceType::from_u16(raw).to_u16(), raw);
  }
}

#[test]
fn as_str_slug_for_every_variant() {
  assert_eq!(ResourceType::A.as_str(), "a");
  assert_eq!(ResourceType::AAAA.as_str(), "aaaa");
  assert_eq!(ResourceType::Ptr.as_str(), "ptr");
  assert_eq!(ResourceType::Srv.as_str(), "srv");
  assert_eq!(ResourceType::Txt.as_str(), "txt");
  assert_eq!(ResourceType::Nsec.as_str(), "nsec");
  assert_eq!(ResourceType::Hinfo.as_str(), "hinfo");
  assert_eq!(ResourceType::Cname.as_str(), "cname");
  assert_eq!(ResourceType::Any.as_str(), "any");
  assert_eq!(ResourceType::Unknown(999).as_str(), "unknown");
}

/// RFC 1035 §3.3 compression-eligible name-bearing types this stack does not
/// type-specifically parse must be flagged so callers drop (not cache) them;
/// the types we parse or that carry no compressible name must not be.
#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn unhandled_compressible_name_classification() {
  for v in [2u16, 3, 4, 6, 7, 8, 9, 14, 15, 39] {
    assert!(
      ResourceType::from_u16(v).is_unhandled_compressible_name(),
      "rtype {v} is a compression-eligible name-bearing type we don't parse"
    );
  }
  for t in [
    ResourceType::A,
    ResourceType::Cname,
    ResourceType::Ptr,
    ResourceType::Srv,
    ResourceType::Txt,
    ResourceType::Nsec,
    ResourceType::Any,
  ] {
    assert!(!t.is_unhandled_compressible_name());
  }
}

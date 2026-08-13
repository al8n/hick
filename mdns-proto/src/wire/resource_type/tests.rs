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

/// Whether rdata may be stored or compared as sent is asked of the BYTES, not of
/// a list of types — see `wire::record::rdata_is_position_independent`.
///
/// This replaces a test that pinned an enumeration of compression-eligible RR
/// types (NS, MD, MF, SOA, MB, MG, MR, MINFO, MX, DNAME). The enumeration was
/// incomplete — RP(17), AFSDB(18), RT(21), PX(26) and KX(36) are compression
/// eligible too — and pinning it only froze the omission in place. A list that
/// must track a spec is fail-OPEN when it falls behind; asking the bytes cannot
/// fall behind, because there is nothing to keep in sync.
#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn rdata_comparability_is_decided_by_the_bytes_not_a_type_list() {
  use crate::wire::rdata_is_position_independent;

  // A compression pointer is any octet >= 0xC0 (RFC 1035 §4.1.4), so rdata
  // holding one cannot be trusted to mean the same thing in another packet…
  assert!(!rdata_is_position_independent(&[0xC0, 0x0C]));
  assert!(!rdata_is_position_independent(&[0x00, 0x01, 0xC0, 0x0C]));
  assert!(!rdata_is_position_independent(&[0xFF]));
  // …including for the five types the old enumeration omitted, which is the
  // whole point: no type is named here, so none can be missed.
  for omitted_by_the_old_list in [17u16, 18, 21, 26, 36] {
    let _ = ResourceType::from_u16(omitted_by_the_old_list);
    assert!(!rdata_is_position_independent(&[0xC0, 0x0C]));
  }

  // Rdata with no such octet cannot contain a pointer whatever its type is, so
  // it is self-contained and comparable/storable verbatim.
  assert!(rdata_is_position_independent(&[]));
  assert!(rdata_is_position_independent(&[192 - 1]));
  assert!(rdata_is_position_independent(b"\x04mail\x05local\x00"));
}

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

/// Compression-eligibility is a per-TYPE property the spec defines, and this
/// pins the enumeration against RFC 6762 §18.14 / RFC 1035 §3.3.
///
/// It replaces a test that pinned a byte heuristic ("rdata holding an octet
/// `>= 0xC0` may be compressed"), which was wrong in both directions: pointer
/// syntax is meaningful ONLY inside a field a type defines as a domain name, so
/// an opaque RR may validly contain `0xC0` — and refusing it cost duplicate
/// ownership, because the peer compared that record correctly and won while we
/// abandoned.
///
/// An enumeration is normally a maintenance hazard, and here it is not: §18.14
/// closes its own list — "names that appear within the rdata of any type not
/// listed above MUST NOT be compressed" — so the set is finite by the spec's own
/// terms. If a future IETF Standards Action ever adds a type, add it here.
#[cfg(any(feature = "alloc", feature = "std"))]
#[test]
fn compression_eligibility_is_enumerated_per_type() {
  use crate::wire::RdataNames;

  // A single domain name: NS, CNAME, PTR, DNAME — and NSEC, which this crate
  // parses itself but which is on §18.14's list all the same.
  for v in [2u16, 5, 12, 39, 47] {
    assert_eq!(
      ResourceType::from_u16(v).rdata_names(),
      RdataNames::Compressible { lead: 0, names: 1 },
      "rtype {v} carries one compressible name"
    );
  }
  // Two names — RP, and SOA (whose 20 octets of timers are the name-free
  // remainder after them).
  for v in [6u16, 17] {
    assert_eq!(
      ResourceType::from_u16(v).rdata_names(),
      RdataNames::Compressible { lead: 0, names: 2 },
      "rtype {v} carries two compressible names"
    );
  }
  // A 16-bit preference then a name — MX, and the three R11 missed entirely.
  for v in [15u16, 18, 21, 36] {
    assert_eq!(
      ResourceType::from_u16(v).rdata_names(),
      RdataNames::Compressible { lead: 2, names: 1 },
      "rtype {v} is preference + name, and AFSDB/RT/KX are exactly the types an \
       earlier enumeration omitted"
    );
  }
  assert_eq!(
    ResourceType::from_u16(26).rdata_names(),
    RdataNames::Compressible { lead: 2, names: 2 },
    "PX is preference + two names, also omitted earlier"
  );
  assert_eq!(
    ResourceType::from_u16(33).rdata_names(),
    RdataNames::Compressible { lead: 6, names: 1 },
    "SRV is priority + weight + port, then a name"
  );

  // NOT on §18.14's list, so NOT eligible — SIG(24), NXT(30), NAPTR(35),
  // A6(38). RFC 3597 §4 is explicit that it UPDATES RFC 2535 to disallow the
  // compression SIG and NXT were once permitted, so these are opaque by the
  // spec's decision and not by our ignorance. A revision that read them as
  // "eligible with a layout we cannot locate" made this crate abandon
  // comparisons every conforming peer completes.
  for v in [24u16, 30, 35, 38] {
    assert_eq!(
      ResourceType::from_u16(v).rdata_names(),
      RdataNames::Opaque,
      "rtype {v} is absent from §18.14, so its rdata never compresses"
    );
  }

  // The RFC 1035 types §18.14 leaves off its list are opaque for the same
  // reason: MD(3), MF(4), MB(7), MG(8), MR(9), MINFO(14). "Well-known" in RFC
  // 3597's sense, but §18.14 governs Multicast DNS and does not list them.
  for v in [3u16, 4, 7, 8, 9, 14] {
    assert_eq!(
      ResourceType::from_u16(v).rdata_names(),
      RdataNames::Opaque,
      "rtype {v} is absent from §18.14, so its rdata never compresses"
    );
  }

  // Everything else is opaque — including the types we parse ourselves, and
  // genuinely unknown private types.
  for t in [
    ResourceType::A,
    ResourceType::AAAA,
    ResourceType::Txt,
    ResourceType::Hinfo,
    ResourceType::Any,
  ] {
    assert_eq!(t.rdata_names(), RdataNames::Opaque);
  }
  assert_eq!(
    ResourceType::from_u16(64000).rdata_names(),
    RdataNames::Opaque
  );
}

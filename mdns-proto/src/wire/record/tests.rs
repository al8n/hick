use super::*;

/// Assembles a message whose record owner name and rdata names are
/// compression pointers to "svc.local." parked at offset 12. Returns the
/// full message bytes; the record begins at offset 23.
///
/// Layout: [0..12] zero header · [12..23] "svc.local." · [23..25] owner
/// pointer→12 · [25..27] TYPE · [27..29] CLASS=IN · [29..33] TTL · [33..35]
/// RDLENGTH · [35..] rdata.
fn message_with_pointered_record(rtype: u16, rdata: &[u8]) -> std::vec::Vec<u8> {
  let mut m = std::vec::Vec::new();
  m.extend_from_slice(&[0u8; 12]); // dummy header region (pointer base 12)
  // "svc.local." at offset 12.
  m.extend_from_slice(&[3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0]);
  debug_assert_eq!(m.len(), 23);
  m.extend_from_slice(&[0xC0, 0x0C]); // owner name = pointer to offset 12
  m.extend_from_slice(&rtype.to_be_bytes());
  m.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  m.extend_from_slice(&120u32.to_be_bytes()); // TTL
  #[allow(clippy::cast_possible_truncation)]
  m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
  m.extend_from_slice(rdata);
  m
}

const SVC_LOCAL_WIRE: &[u8] = &[3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0];

#[test]
fn canonical_rdata_expands_srv_target() {
  // RDATA: priority=10 weight=20 port=8080 target=pointer→"svc.local.".
  let rdata = [0, 10, 0, 20, 0x1F, 0x90, 0xC0, 0x0C];
  let msg = message_with_pointered_record(33 /* SRV */, &rdata);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  let out = rec.canonical_rdata().unwrap();
  let mut expected = std::vec::Vec::from(&[0u8, 10, 0, 20, 0x1F, 0x90][..]);
  expected.extend_from_slice(SVC_LOCAL_WIRE);
  assert_eq!(out, expected, "SRV target must be decompressed in place");
}

#[test]
fn canonical_rdata_expands_cname_target() {
  // CNAME rdata is one domain name (like PTR) — target is a
  // pointer→"svc.local." and must be decompressed, not copied raw.
  let rdata = [0xC0, 0x0C];
  let msg = message_with_pointered_record(5 /* CNAME */, &rdata);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert_eq!(
    rec.canonical_rdata().unwrap(),
    std::vec::Vec::from(SVC_LOCAL_WIRE),
    "CNAME target must be decompressed in place"
  );
}

#[test]
fn canonical_rdata_expands_nsec_next_name() {
  // RDATA: next_name=pointer→"svc.local." then a 3-byte type bitmap.
  let rdata = [0xC0, 0x0C, 0x00, 0x01, 0x40];
  let msg = message_with_pointered_record(47 /* NSEC */, &rdata);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  let out = rec.canonical_rdata().unwrap();
  let mut expected = std::vec::Vec::from(SVC_LOCAL_WIRE);
  expected.extend_from_slice(&[0x00, 0x01, 0x40]); // bitmap preserved verbatim
  assert_eq!(
    out, expected,
    "NSEC next_name must be decompressed, bitmap preserved"
  );
}

#[test]
fn canonical_rdata_rejects_malformed_name() {
  // PTR whose rdata name is a pointer to an out-of-range offset (255) — the
  // label iterator errors, so canonical_rdata must Err (caller drops it)
  // rather than store undecodable bytes.
  let rdata = [0xC0, 0xFF];
  let msg = message_with_pointered_record(12 /* PTR */, &rdata);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert!(
    rec.canonical_rdata().is_err(),
    "a record with an undecodable name must be rejected"
  );
}

#[test]
fn canonical_rdata_validates_txt_segments() {
  // TXT canonicalization must walk the length-prefixed strings.
  // A length octet that overruns the (bounded) RDATA must make canonical_rdata
  // Err so the caller (query answer collection / cache insertion) DROPS it —
  // otherwise a single malformed TXT poisons the cache and query results.
  let malformed = [5u8, b'a', b'b']; // claims a 5-byte string, only 2 follow
  let msg = message_with_pointered_record(16 /* TXT */, &malformed);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert!(
    rec.canonical_rdata().is_err(),
    "a TXT record whose segment length overruns its RDATA must be rejected"
  );

  // A well-formed multi-segment TXT canonicalizes verbatim (segments rebuilt
  // length-prefixed, in order).
  let valid = [3u8, b'k', b'e', b'y', 1, b'x']; // "key" then "x"
  let msg = message_with_pointered_record(16, &valid);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert_eq!(
    rec.canonical_rdata().unwrap(),
    std::vec::Vec::from(&valid[..]),
    "a valid multi-segment TXT must canonicalize to its verbatim segments"
  );

  // An empty TXT (zero-length RDATA) normalizes to a single zero-length string
  // (RFC 6763 §6.1), matching respond::write_canonical_txt and a peer's
  // compliant empty TXT — so the two forms dedupe as one identity.
  let msg = message_with_pointered_record(16, &[]);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert_eq!(
    rec.canonical_rdata().unwrap(),
    std::vec![0u8],
    "an empty TXT must canonicalize to a single zero-length string (§6.1)"
  );
}

#[test]
fn canonical_rdata_folds_case_but_preserved_form_does_not() {
  // PTR target "InSt" (mixed case) + pointer→"svc.local.".
  let rdata = [4, b'I', b'n', b'S', b't', 0xC0, 0x0C];
  let msg = message_with_pointered_record(12 /* PTR */, &rdata);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();

  // Preserved form keeps the original instance-label case (for display).
  let mut preserved_expected = std::vec::Vec::from(&[4u8, b'I', b'n', b'S', b't'][..]);
  preserved_expected.extend_from_slice(SVC_LOCAL_WIRE);
  assert_eq!(rec.canonical_rdata().unwrap(), preserved_expected);

  // Folded form lowercases all labels (case-insensitive identity).
  let mut folded_expected = std::vec::Vec::from(&[4u8, b'i', b'n', b's', b't'][..]);
  folded_expected.extend_from_slice(SVC_LOCAL_WIRE);
  assert_eq!(rec.canonical_rdata_folded().unwrap(), folded_expected);
}

#[test]
fn canonical_rdata_rejects_unhandled_name_bearing_type() {
  // a well-known compressible name-bearing type we don't parse
  // (NS = 2) maps to Unknown; its rdata (a possibly-compressed name) can't be
  // canonicalized, so canonical_rdata must drop it rather than store
  // compression/case-sensitive bytes. Here the NS target is a pointer.
  let rdata = [0xC0, 0x0C];
  let msg = message_with_pointered_record(2 /* NS */, &rdata);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert!(
    matches!(
      rec.canonical_rdata(),
      Err(ParseError::UnsupportedNameBearingType(2))
    ),
    "NS must be dropped as an unsupported name-bearing type"
  );
  // A genuinely-unknown opaque type (e.g. 64) is stored verbatim (RFC 3597
  // §4: such types are never compressed).
  let opaque = [0x01, 0x02, 0x03];
  let msg2 = message_with_pointered_record(64, &opaque);
  let (rec2, _) = Ref::try_parse(&msg2, 23).unwrap();
  assert_eq!(
    rec2.canonical_rdata().unwrap(),
    std::vec::Vec::from(&opaque[..])
  );

  // MINFO (14) is another RFC 1035 compressible name-bearing type
  // we don't parse — it must be dropped too, not just NS/SOA/MX/DNAME.
  let msg3 = message_with_pointered_record(14 /* MINFO */, &[0xC0, 0x0C]);
  let (rec3, _) = Ref::try_parse(&msg3, 23).unwrap();
  assert!(matches!(
    rec3.canonical_rdata(),
    Err(ParseError::UnsupportedNameBearingType(14))
  ));
}

#[test]
fn canonical_rdata_rejects_overlong_encoded_name() {
  // 128 one-byte labels — summed content is 128 (≤ 255, so the
  // label iterator accepts it), but the ENCODED length (length octet + byte
  // per label, plus root terminator = 257) exceeds RFC 1035's 255-octet
  // limit. write_wire must reject it so an over-length name is never stored.
  let mut rdata = std::vec::Vec::new();
  for _ in 0..128 {
    rdata.push(1u8);
    rdata.push(b'a');
  }
  rdata.push(0); // root
  let msg = message_with_pointered_record(12 /* PTR */, &rdata);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert!(
    rec.canonical_rdata().is_err(),
    "an over-length encoded name must be rejected"
  );
}

#[test]
fn rdata_view_propagates_malformed_cname() {
  // CNAME rdata MUST consume EXACTLY RDLENGTH (cname.rs §3.3.1): a
  // self-contained name "svc.local." (11 bytes) plus one trailing garbage
  // octet, declared RDLENGTH = 12. `consumed (11) != rdata_len (12)` so
  // `Cname::try_from_message` returns Err and `rdata_view` propagates it
  // (the `?` on the CNAME arm). The existing CNAME test only hits the success
  // path, so this covers the error branch.
  let mut rdata = std::vec::Vec::from(SVC_LOCAL_WIRE);
  rdata.push(0xFF); // one trailing byte inside RDLENGTH
  let msg = message_with_pointered_record(5 /* CNAME */, &rdata);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert!(
    matches!(rec.rdata_view(), Err(ParseError::BufferTooShort(_))),
    "a CNAME whose name does not exactly fill RDLENGTH must be rejected"
  );
  // canonical_rdata routes through rdata_view, so it surfaces the same error.
  assert!(rec.canonical_rdata().is_err());
}

#[test]
fn rdata_view_propagates_malformed_nsec() {
  // NSEC next_name MUST NOT overrun the declared RDLENGTH (nsec.rs:
  // `bitmap_start > rdata_end`). Hand-build the record so RDLENGTH (1) is
  // smaller than the bytes the next_name consumes (a pointer = 2 bytes), which
  // the `message_with_pointered_record` helper cannot express (it forces
  // RDLENGTH == rdata.len()). The NSEC arm's `?` in `rdata_view` then fires.
  let mut m = std::vec::Vec::new();
  m.extend_from_slice(&[0u8; 12]); // header region (pointer base 12)
  m.extend_from_slice(SVC_LOCAL_WIRE); // "svc.local." at offset 12
  debug_assert_eq!(m.len(), 23);
  m.extend_from_slice(&[0xC0, 0x0C]); // owner name = pointer to offset 12
  m.extend_from_slice(&47u16.to_be_bytes()); // TYPE = NSEC
  m.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
  m.extend_from_slice(&120u32.to_be_bytes()); // TTL
  m.extend_from_slice(&1u16.to_be_bytes()); // RDLENGTH = 1 (too small)
  m.extend_from_slice(&[0xC0, 0x0C]); // next_name pointer (consumes 2 bytes)
  let (rec, _) = Ref::try_parse(&m, 23).unwrap();
  assert!(
    matches!(rec.rdata_view(), Err(ParseError::BufferTooShort(_))),
    "an NSEC whose next_name overruns RDLENGTH must be rejected"
  );
  assert!(rec.canonical_rdata().is_err());
}

#[test]
fn try_parse_rejects_message_too_short_for_fixed_header() {
  // "x.local." parses, but fewer than the 10 fixed type/class/ttl/rdlen
  // header bytes follow — the record header read must fail cleanly.
  let msg: [u8; 12] = [1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 1, 2];
  assert!(Ref::try_parse(&msg, 0).is_err());
}

#[test]
fn try_parse_rejects_rdlength_overrun() {
  // name(9) + TYPE=PTR + CLASS=IN + TTL + RDLENGTH=100, but no rdata follows,
  // so the declared rdata runs off the end of the message.
  let msg: [u8; 19] = [
    1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0, // owner name
    0, 12, // TYPE = 12 (PTR)
    0, 1, // CLASS = 1 (IN)
    0, 0, 0, 120, // TTL
    0, 100, // RDLENGTH = 100 (no rdata present)
  ];
  assert!(matches!(
    Ref::try_parse(&msg, 0),
    Err(ParseError::RdlengthOverrun(_))
  ));
}

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

/// RFC 6762 §18.14's list decides this, and BOTH answers are a "yes": a listed
/// type is decompressed, an unlisted one is copied verbatim. Neither is dropped.
///
/// A revision dropped both — every name-bearing type this crate does not parse,
/// on the reasoning that a raw copy of it "MAY arrive compressed". §18.14 says
/// otherwise for the unlisted ones ("names that appear within the rdata of any
/// type not listed above MUST NOT be compressed"), and for the LISTED ones the
/// answer is to decompress rather than to discard: RP, AFSDB, RT, PX and KX are
/// all on §18.14's list, all decodable by the one generic layout decoder, and
/// all were being thrown away by the query and cache paths.
#[test]
fn canonical_rdata_decompresses_listed_types_and_copies_unlisted_ones_verbatim() {
  // ── on §18.14's list: the embedded names are decompressed in place ──
  //
  // NS(2) is `(lead 0, names 1)` — the whole rdata is one name.
  let msg = message_with_pointered_record(2 /* NS */, &[0xC0, 0x0C]);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert_eq!(
    rec.canonical_rdata().unwrap(),
    std::vec::Vec::from(SVC_LOCAL_WIRE),
    "NS is on §18.14's list, so its name is decompressed — not dropped"
  );

  // `(lead 2, names 1)` — a 16-bit preference, then a name: MX, AFSDB, RT, KX.
  for rtype in [15u16, 18, 21, 36] {
    let msg = message_with_pointered_record(rtype, &[0x00, 0x0A, 0xC0, 0x0C]);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    let mut expected = std::vec::Vec::from(&[0x00u8, 0x0A][..]);
    expected.extend_from_slice(SVC_LOCAL_WIRE);
    assert_eq!(
      rec.canonical_rdata().unwrap(),
      expected,
      "rtype {rtype} is preference + one name, and every one of these was \
       dropped outright"
    );
  }

  // `(lead 0, names 2)` — RP. (SOA is the same shape with a name-free
  // remainder, covered by its own case below.)
  let msg = message_with_pointered_record(17 /* RP */, &[0xC0, 0x0C, 0xC0, 0x0C]);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  let mut expected = std::vec::Vec::from(SVC_LOCAL_WIRE);
  expected.extend_from_slice(SVC_LOCAL_WIRE);
  assert_eq!(rec.canonical_rdata().unwrap(), expected, "RP is two names");

  // SOA(6): two names, then 20 octets of timers that carry no name and are
  // therefore self-contained as sent.
  let mut soa = std::vec::Vec::from(&[0xC0u8, 0x0C, 0xC0, 0x0C][..]);
  soa.extend_from_slice(&[0xAB; 20]);
  let msg = message_with_pointered_record(6 /* SOA */, &soa);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  let mut expected = std::vec::Vec::from(SVC_LOCAL_WIRE);
  expected.extend_from_slice(SVC_LOCAL_WIRE);
  expected.extend_from_slice(&[0xAB; 20]);
  assert_eq!(
    rec.canonical_rdata().unwrap(),
    expected,
    "SOA's timers are the name-free remainder after its two names"
  );

  // `(lead 2, names 2)` — PX.
  let msg = message_with_pointered_record(26 /* PX */, &[0x00, 0x0A, 0xC0, 0x0C, 0xC0, 0x0C]);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  let mut expected = std::vec::Vec::from(&[0x00u8, 0x0A][..]);
  expected.extend_from_slice(SVC_LOCAL_WIRE);
  expected.extend_from_slice(SVC_LOCAL_WIRE);
  assert_eq!(
    rec.canonical_rdata().unwrap(),
    expected,
    "PX is pref + 2 names"
  );

  // ── absent from §18.14: copied verbatim, whatever the octets are ──
  //
  // A genuinely-unknown private type, including one holding pointer syntax as
  // ordinary data.
  let opaque = [0x01u8, 0x02, 0x03];
  let msg = message_with_pointered_record(64, &opaque);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert_eq!(
    rec.canonical_rdata().unwrap(),
    std::vec::Vec::from(&opaque[..])
  );

  // SIG(24), NXT(30), NAPTR(35), A6(38) — RFC 3597 §4 explicitly UPDATED RFC
  // 2535 to forbid the compression SIG and NXT once allowed, and §18.14 does not
  // list any of them. Their absence is a decision, not our ignorance, so their
  // bytes are self-contained and comparable. MD(3), MF(4), MB(7), MG(8), MR(9)
  // and MINFO(14) are unlisted for the same reason.
  for rtype in [24u16, 30, 35, 38, 3, 4, 7, 8, 9, 14] {
    let raw = [0xC0u8, 0x0C, 0x77];
    let msg = message_with_pointered_record(rtype, &raw);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    assert_eq!(
      rec.canonical_rdata().unwrap(),
      std::vec::Vec::from(&raw[..]),
      "rtype {rtype} is absent from §18.14, so its rdata is copied verbatim"
    );
  }

  // ── decompressing is not accepting anything ──
  //
  // A listed type whose name will not resolve still fails, so the caller drops
  // the record rather than storing bytes nobody could read. The record's rdata
  // begins at offset 35, so a pointer to 35 targets itself.
  let msg = message_with_pointered_record(2 /* NS */, &[0xC0, 35]);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert!(
    rec.canonical_rdata().is_err(),
    "a compressed name that cannot be resolved has no canonical form"
  );

  // A fixed prefix that does not fit inside RDLENGTH at all: AFSDB is
  // `(lead 2, names 1)` and this record declares one octet of rdata.
  let msg = message_with_pointered_record(18 /* AFSDB */, &[0x00]);
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert!(
    matches!(
      rec.canonical_rdata(),
      Err(ParseError::UnsupportedNameBearingType(18))
    ),
    "a fixed prefix longer than the whole rdata is malformed"
  );

  // And a name that PARSES but runs past the record's own RDLENGTH: an NS whose
  // RDLENGTH claims one octet while a full uncompressed name follows. The
  // remainder after such a name would be nonsense, so it fails rather than
  // comparing it.
  let mut msg = message_with_pointered_record(2 /* NS */, SVC_LOCAL_WIRE);
  // Rewrite RDLENGTH (offset 33..35) to 1, leaving the name bytes in place.
  msg[33] = 0;
  msg[34] = 1;
  let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
  assert!(
    matches!(
      rec.canonical_rdata(),
      Err(ParseError::UnsupportedNameBearingType(2))
    ),
    "a name overrunning its RDLENGTH is not decodable"
  );
}

/// THE property the one decoder exists for: the three [`RdataForm`]s differ in
/// NORMALISATION only. Whether a record decodes at all is not a per-consumer
/// answer.
///
/// It was one, and the divergence renamed services. The identity form raw-copied
/// unparsed rdata and dropped NSEC's `next_name`, so it never failed on either,
/// while the §8.2 form decompressed both and did. The same bytes therefore
/// answered "unreadable, decide nothing" on the §8.2 path and "differing rdata"
/// on the identity path — and differing rdata at a name a service is probing is
/// an RFC 6762 §8.1 defeat. One malformed IN/NS response, needing no knowledge of
/// the victim's records, was enough.
///
/// Note how many of these get past `rdata_view`. `NameRef::try_parse` accepts a
/// compression pointer without following it, so SRV and NSEC records whose
/// embedded name is a cycle PARSE, and only the decode below discovers them.
#[test]
fn every_form_agrees_about_which_records_decode() {
  // The rdata of a record built by `message_with_pointered_record` starts here,
  // so a pointer to this offset targets itself: forward, and unresolvable.
  const SELF: u8 = 35;

  let cases: &[(&str, u16, &[u8], bool)] = &[
    (
      "an opaque type holding pointer syntax as data",
      64000,
      &[0xC0, 0x0C, 0x01],
      true,
    ),
    (
      "NS whose name is a resolvable pointer",
      2,
      &[0xC0, 0x0C],
      true,
    ),
    (
      "NS whose name is an unresolvable pointer",
      2,
      &[0xC0, SELF],
      false,
    ),
    (
      "SRV whose target is an unresolvable pointer — `rdata_view` succeeds",
      33,
      &[0, 10, 0, 20, 0x1F, 0x90, 0xC0, SELF + 6],
      false,
    ),
    (
      "NSEC whose next_name is an unresolvable pointer — `rdata_view` succeeds",
      47,
      &[0xC0, SELF, 0, 1, 0x40],
      false,
    ),
    (
      "TXT whose length octet overruns its rdata",
      16,
      &[10, b'a', b'b'],
      false,
    ),
  ];

  for &(what, rtype, rdata, expected) in cases {
    let msg = message_with_pointered_record(rtype, rdata);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    let mut scratch = std::vec::Vec::new();
    let as_sent = rec
      .write_canonical_rdata(RdataForm::AS_SENT, &mut scratch)
      .is_ok();
    assert_eq!(as_sent, expected, "{what}: §8.2's form");
    assert_eq!(
      rec.canonical_rdata().is_ok(),
      expected,
      "{what}: the case-preserving form must agree with §8.2's"
    );
    assert_eq!(
      rec.canonical_rdata_folded().is_ok(),
      expected,
      "{what}: the identity form must agree with §8.2's — a record that is \
       undecodable for one consumer is undecodable for every consumer"
    );
  }
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

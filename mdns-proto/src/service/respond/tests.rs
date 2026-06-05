use super::canonical_rdata_for_hash;
use crate::wire::{A, AAAA, Ptr, Rdata, Srv, Txt};

#[test]
fn canonical_a_is_4_bytes() {
  let a = A::try_from_rdata(&[192, 168, 1, 10]).unwrap();
  let mut scratch = std::vec::Vec::new();
  let out = canonical_rdata_for_hash(&Rdata::A(a), &mut scratch).unwrap();
  assert_eq!(out, [192u8, 168, 1, 10].as_slice());
}

#[test]
fn write_announce_filtered_reports_emitted_groups() {
  // the encoder must report which owner groups it actually put on
  // the wire, so the caller latches goodbye ownership only for those — a
  // known-answer-suppressed response must NOT be treated as advertising
  // records it omitted.
  let mut r = crate::records::ServiceRecords::new(
    crate::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    crate::Name::try_from_str("p._ipp._tcp.local.").unwrap(),
    crate::Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  r.add_a(core::net::Ipv4Addr::new(192, 168, 1, 1));
  let mut buf = [0u8; 1500];

  // Nothing suppressed → every instance record + the host address emitted.
  let (_, e) = super::write_announce_filtered(&r, &mut buf, |_, _| false).unwrap();
  assert!(
    e.ptr && e.srv && e.txt && e.a == [core::net::Ipv4Addr::new(192, 168, 1, 1)],
    "all records: every record reported emitted"
  );

  // Suppress only A/AAAA → instance records emitted, no host address.
  let (_, e) = super::write_announce_filtered(&r, &mut buf, |rt, _| {
    matches!(
      rt,
      crate::wire::ResourceType::A | crate::wire::ResourceType::AAAA
    )
  })
  .unwrap();
  assert!(
    e.ptr && e.srv && e.txt && e.a.is_empty() && e.aaaa.is_empty(),
    "host suppressed: only instance records emitted"
  );

  // Suppress only SRV → PTR + TXT + A emitted, SRV NOT (per-record case).
  let (_, e) = super::write_announce_filtered(&r, &mut buf, |rt, _| {
    matches!(rt, crate::wire::ResourceType::Srv)
  })
  .unwrap();
  assert!(
    e.ptr && !e.srv && e.txt && e.a == [core::net::Ipv4Addr::new(192, 168, 1, 1)],
    "SRV suppressed: PTR/TXT/A emitted, SRV not"
  );

  // Suppress everything → nothing emitted (a header-only response).
  let (_, e) = super::write_announce_filtered(&r, &mut buf, |_, _| true).unwrap();
  assert!(
    e.is_empty(),
    "all suppressed: nothing emitted (header-only)"
  );
}

#[test]
fn canonical_aaaa_is_16_bytes() {
  use core::net::Ipv6Addr;
  let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
  let rdata = addr.octets();
  let rec = AAAA::try_from_rdata(&rdata).unwrap();
  let mut scratch = std::vec::Vec::new();
  let out = canonical_rdata_for_hash(&Rdata::AAAA(rec), &mut scratch).unwrap();
  assert_eq!(out.len(), 16);
  assert_eq!(out, &addr.octets());
}

#[test]
fn canonical_txt_roundtrips_wire_form() {
  // Wire form: 0x07 "key=val" 0x01 "x"
  let raw: &[u8] = &[7, b'k', b'e', b'y', b'=', b'v', b'a', b'l', 1, b'x'];
  let txt = Txt::from_rdata(raw);
  let mut scratch = std::vec::Vec::new();
  let out = canonical_rdata_for_hash(&Rdata::Txt(txt), &mut scratch).unwrap();
  assert_eq!(out, raw, "canonical TXT must match wire bytes verbatim");
}

#[test]
fn canonical_txt_malformed_segment_returns_err() {
  // Segment claims 10 bytes but only 2 follow — should return Err, not silently truncate.
  let raw: &[u8] = &[10, b'a', b'b'];
  let txt = Txt::from_rdata(raw);
  let mut scratch = std::vec::Vec::new();
  assert!(
    canonical_rdata_for_hash(&Rdata::Txt(txt), &mut scratch).is_err(),
    "malformed TXT segment must produce an Err"
  );
}

#[test]
fn canonical_ptr_is_lowercase_dotted_labels() {
  // Build a minimal DNS message containing the PTR rdata "MyPrinter._ipp._tcp.local."
  // as uncompressed length-prefixed labels so Ptr can parse it.
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in &[b"MyPrinter".as_slice(), b"_ipp", b"_tcp", b"local"] {
    msg.push(label.len() as u8);
    msg.extend_from_slice(label);
  }
  msg.push(0u8); // root label
  let rdata_len = msg.len();
  let ptr = Ptr::try_from_message(&msg, 0, rdata_len).unwrap();
  let mut scratch = std::vec::Vec::new();
  let out = canonical_rdata_for_hash(&Rdata::Ptr(ptr), &mut scratch).unwrap();
  // Expected: "myprinter._ipp._tcp.local" (lowercase, dot-separated, no trailing dot)
  assert_eq!(out, b"myprinter._ipp._tcp.local".as_slice());
}

#[test]
fn canonical_ptr_forward_pointer_returns_err() {
  // Build a message where the PTR rdata is a compression pointer that points
  // forward (to an offset >= itself). NameRef::try_parse accepts it (it only
  // checks that both pointer bytes exist), but NameLabels::next() rejects it
  // with ParseError::PointerForward. This is the canonical example of a
  // malformed peer-supplied name that the old `.flatten()` would silently
  // swallow, producing an empty hash.
  //
  // Layout: [ 0xC0, 0x00 ]  — a pointer at offset 0 that targets offset 0.
  // target (0) >= cursor (0) → PointerForward error during label iteration.
  let msg: std::vec::Vec<u8> = std::vec![0xC0u8, 0x00];
  let ptr = Ptr::try_from_message(&msg, 0, msg.len()).unwrap();
  let mut scratch = std::vec::Vec::new();
  assert!(
    canonical_rdata_for_hash(&Rdata::Ptr(ptr), &mut scratch).is_err(),
    "forward compression pointer in PTR target must produce an Err"
  );
}

#[test]
fn canonical_srv_starts_with_priority_weight_port() {
  // Build SRV rdata: priority=0, weight=0, port=631, target="printer.local."
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  msg.extend_from_slice(&0u16.to_be_bytes()); // priority
  msg.extend_from_slice(&0u16.to_be_bytes()); // weight
  msg.extend_from_slice(&631u16.to_be_bytes()); // port
  for label in &[b"printer".as_slice(), b"local"] {
    msg.push(label.len() as u8);
    msg.extend_from_slice(label);
  }
  msg.push(0u8); // root
  let rdata_len = msg.len();
  let srv = Srv::try_from_message(&msg, 0, rdata_len).unwrap();
  let mut scratch = std::vec::Vec::new();
  let out = canonical_rdata_for_hash(&Rdata::Srv(srv), &mut scratch).unwrap();
  // First 6 bytes: priority(0,0) weight(0,0) port(2,119 = 631 big-endian)
  assert_eq!(&out[..2], &0u16.to_be_bytes()); // priority
  assert_eq!(&out[2..4], &0u16.to_be_bytes()); // weight
  assert_eq!(&out[4..6], &631u16.to_be_bytes()); // port
  // Rest: wire-form target name "printer.local." →
  // \x07printer\x05local\x00  (length-prefixed labels, root terminator)
  let expected: &[u8] = &[
    7, b'p', b'r', b'i', b'n', b't', b'e', b'r', 5, b'l', b'o', b'c', b'a', b'l', 0,
  ];
  assert_eq!(
    &out[6..],
    expected,
    "SRV target must use wire-form label encoding"
  );
}

/// RFC 6762 §8.1: probe messages MUST carry the proposed unique records in
/// the authority section. Verify `write_probe` produces a packet with
/// question count=1, unicast-response bit set, and authority count>=3
/// (SRV + TXT + at least one A record).
#[test]
fn write_probe_includes_authority_records_and_unicast_bit() {
  use crate::{
    Name,
    records::ServiceRecords,
    wire::{MessageReader, ResourceType},
  };
  use core::net::Ipv4Addr;

  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 631, 120);
  recs.add_a(Ipv4Addr::new(192, 168, 1, 5));

  let mut buf = [0u8; 512];
  let n = super::write_probe(&recs, &mut buf).unwrap();
  let msg = MessageReader::try_parse(&buf[..n]).unwrap();

  assert_eq!(
    msg.header().question_count(),
    1,
    "probe must have exactly 1 question"
  );
  // SRV + TXT + A = 3 authority records minimum.
  assert!(
    msg.header().authority_count() >= 3,
    "probe with an A address must have >=3 authority records, got {}",
    msg.header().authority_count()
  );

  // Verify the question uses the unicast-response bit (RFC §5.4).
  let q = msg.questions().next().unwrap().unwrap();
  assert!(
    q.unicast_response_requested(),
    "probe question must have the unicast-response bit set"
  );

  // Verify authority contains at least one SRV record.
  let has_srv = msg.authority().any(|r| {
    r.map(|rec| rec.rtype() == ResourceType::Srv)
      .unwrap_or(false)
  });
  assert!(
    has_srv,
    "probe authority section must contain an SRV record"
  );
}

/// RFC 4034 §4.1.2 window-block-0 membership test for an NSEC type bitmap.
fn bitmap_has(slice: &[u8], t: u16) -> bool {
  if slice.len() < 2 || slice[0] != 0 {
    return false;
  }
  let len = slice[1] as usize;
  let bytes = &slice[2..(2 + len).min(slice.len())];
  let byte_idx = (t / 8) as usize;
  let mask = 0x80u8 >> (t % 8);
  bytes.get(byte_idx).is_some_and(|b| b & mask != 0)
}

fn dotted(nr: &crate::wire::NameRef<'_>) -> std::string::String {
  let mut s = std::string::String::new();
  for label in nr.labels() {
    let label = label.unwrap();
    if label.is_empty() {
      break;
    }
    if !s.is_empty() {
      s.push('.');
    }
    for &b in label {
      s.push(b.to_ascii_lowercase() as char);
    }
  }
  s
}

/// RFC 6762 §6.1: an announcement asserts the INSTANCE RRset via an NSEC
/// record (Additional section) — a querier asking the instance name for any
/// type other than SRV/TXT then gets an authoritative negative instead of
/// waiting out a retransmit. Verifies the single NSEC is the instance NSEC
/// ({SRV, TXT}, not A/AAAA), its next-name equals the owner, cache-flush is
/// set, and that NO host NSEC is emitted: the per-service encoder cannot prove
/// the shared host's complete address set, so it must not publish a host
/// negative a same-host sibling could contradict.
#[test]
fn write_announce_emits_instance_nsec_negative_response() {
  use crate::{
    Name,
    records::ServiceRecords,
    wire::{MessageReader, Rdata, ResourceType},
  };
  use core::net::Ipv4Addr;

  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
  recs.add_a(Ipv4Addr::new(192, 168, 1, 5)); // IPv4 only.

  let mut buf = [0u8; 1500];
  let n = super::write_announce(&recs, &mut buf).unwrap();
  let msg = MessageReader::try_parse(&buf[..n]).unwrap();

  assert_eq!(
    msg.header().additional_count(),
    1,
    "exactly one NSEC — instance only, no host NSEC"
  );

  let r = msg.additional().next().unwrap().unwrap();
  assert_eq!(r.rtype(), ResourceType::Nsec);
  assert_eq!(
    dotted(r.name()),
    "myprinter._ipp._tcp.local",
    "the sole NSEC is owned by the instance name, never the host"
  );
  let Rdata::Nsec(nsec) = r.rdata_view().unwrap() else {
    panic!("additional must parse as NSEC");
  };
  assert!(
    nsec.next_name().equals_ignoring_case(r.name()),
    "§6.1: NSEC next-name equals the owner"
  );
  assert!(
    r.cache_flush(),
    "instance SRV/TXT are unique → cache-flush set"
  );
  let bm = nsec.type_bitmap_slice();
  assert!(bitmap_has(bm, 33), "instance NSEC asserts SRV (33)");
  assert!(bitmap_has(bm, 16), "instance NSEC asserts TXT (16)");
  assert!(!bitmap_has(bm, 1), "instance NSEC must NOT assert A");
  assert!(!bitmap_has(bm, 28), "instance NSEC must NOT assert AAAA");

  // no NSEC may be owned by the (shared) host name.
  for add in msg.additional() {
    assert_ne!(
      dotted(add.unwrap().name()),
      "printer.local",
      "must not emit a host-name NSEC from partial per-service state"
    );
  }
}

/// The §6.1 instance NSEC also rides on the KAS-filtered response path, and
/// stays instance-only even for a dual-stack host (no host NSEC).
#[test]
fn write_announce_filtered_emits_instance_nsec_only() {
  use crate::{
    Name,
    records::ServiceRecords,
    wire::{MessageReader, Rdata},
  };
  use core::net::{Ipv4Addr, Ipv6Addr};

  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("p._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
  recs.add_a(Ipv4Addr::new(192, 168, 1, 5));
  recs.add_aaaa(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

  let mut buf = [0u8; 1500];
  let (n, _emitted) = super::write_announce_filtered(&recs, &mut buf, |_, _| false).unwrap();
  let msg = MessageReader::try_parse(&buf[..n]).unwrap();
  assert_eq!(msg.header().additional_count(), 1, "instance NSEC only");

  let r = msg.additional().next().unwrap().unwrap();
  assert_eq!(
    dotted(r.name()),
    "p._ipp._tcp.local",
    "owner is the instance"
  );
  let Rdata::Nsec(nsec) = r.rdata_view().unwrap() else {
    panic!("additional must be NSEC");
  };
  let bm = nsec.type_bitmap_slice();
  assert!(
    bitmap_has(bm, 33) && bitmap_has(bm, 16),
    "asserts SRV + TXT"
  );
  for add in msg.additional() {
    assert_ne!(
      dotted(add.unwrap().name()),
      "h.local",
      "no host NSEC even for a dual-stack host"
    );
  }
}

/// the §6.1 NSEC is an OPTIONAL Additional-section hint. When the
/// positive answers fit but the NSEC does not, the responder must still send
/// the answers (NSEC rolled back/omitted) — adding the hint must never turn a
/// deliverable response into a dropped one.
#[test]
fn nsec_omitted_when_it_does_not_fit_but_answers_still_send() {
  use crate::{
    Name,
    records::ServiceRecords,
    wire::{MessageReader, ResourceType},
  };
  use core::net::Ipv4Addr;

  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
  recs.add_a(Ipv4Addr::new(192, 168, 1, 5));

  // Baseline: full message including the instance NSEC.
  let mut big = [0u8; 1500];
  let n_full = super::write_announce(&recs, &mut big).unwrap();
  let full = MessageReader::try_parse(&big[..n_full]).unwrap();
  assert_eq!(full.header().additional_count(), 1, "baseline NSEC present");
  let answers = full.header().answer_count();

  // A buffer 8 bytes short of the full message: the answers fit, but the
  // ~20-byte NSEC cannot. (NSEC is well over 8 bytes, so this reliably keeps
  // every answer while excluding the hint.)
  let cut = n_full - 8;
  let mut small = std::vec![0u8; cut];
  let n = super::write_announce(&recs, &mut small).unwrap();
  let msg = MessageReader::try_parse(&small[..n]).unwrap();

  assert_eq!(
    msg.header().additional_count(),
    0,
    "NSEC omitted when it does not fit"
  );
  assert_eq!(
    msg.header().answer_count(),
    answers,
    "every positive answer must still be present"
  );
  assert!(
    msg
      .answers()
      .any(|r| r.map(|x| x.rtype() == ResourceType::Srv).unwrap_or(false)),
    "positive SRV answer must survive even when NSEC is dropped"
  );
}

use super::rdata_for_identity;
use crate::wire::{A, AAAA, Ptr, Rdata, Srv, Txt};

#[test]
fn canonical_a_is_4_bytes() {
  let a = A::try_from_rdata(&[192, 168, 1, 10]).unwrap();
  let mut scratch = std::vec::Vec::new();
  let out = rdata_for_identity(&Rdata::A(a), &mut scratch).unwrap();
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
  let out = rdata_for_identity(&Rdata::AAAA(rec), &mut scratch).unwrap();
  assert_eq!(out.len(), 16);
  assert_eq!(out, &addr.octets());
}

#[test]
fn canonical_txt_roundtrips_wire_form() {
  // Wire form: 0x07 "key=val" 0x01 "x"
  let raw: &[u8] = &[7, b'k', b'e', b'y', b'=', b'v', b'a', b'l', 1, b'x'];
  let txt = Txt::from_rdata(raw);
  let mut scratch = std::vec::Vec::new();
  let out = rdata_for_identity(&Rdata::Txt(txt), &mut scratch).unwrap();
  assert_eq!(out, raw, "canonical TXT must match wire bytes verbatim");
}

#[test]
fn canonical_txt_malformed_segment_returns_err() {
  // Segment claims 10 bytes but only 2 follow — should return Err, not silently truncate.
  let raw: &[u8] = &[10, b'a', b'b'];
  let txt = Txt::from_rdata(raw);
  let mut scratch = std::vec::Vec::new();
  assert!(
    rdata_for_identity(&Rdata::Txt(txt), &mut scratch).is_err(),
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
  let out = rdata_for_identity(&Rdata::Ptr(ptr), &mut scratch).unwrap();
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
    rdata_for_identity(&Rdata::Ptr(ptr), &mut scratch).is_err(),
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
  let out = rdata_for_identity(&Rdata::Srv(srv), &mut scratch).unwrap();
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

/// CNAME rdata is one domain name (RFC 1035 §3.3.1), structurally identical to
/// PTR — `rdata_for_identity` must case-fold it to dot-joined lowercase
/// labels with no length prefixes and no trailing dot, exactly like PTR. mDNS-SD
/// never emits CNAME, so the only way to obtain one is to parse it off the wire;
/// build a single CNAME resource record by hand and take its `rdata_view`.
#[test]
fn canonical_cname_is_lowercase_dotted_labels() {
  use crate::wire::{Rdata, Ref, ResourceClass, ResourceType};

  // Owner name "x.local." then type=CNAME(5), class=IN(1), ttl=120, RDLENGTH,
  // and the CNAME target "Target.Local." as uncompressed length-prefixed labels.
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in &[b"x".as_slice(), b"local"] {
    msg.push(label.len() as u8);
    msg.extend_from_slice(label);
  }
  msg.push(0u8); // owner root
  msg.extend_from_slice(&ResourceType::Cname.to_u16().to_be_bytes());
  msg.extend_from_slice(&ResourceClass::In.to_u16().to_be_bytes());
  msg.extend_from_slice(&120u32.to_be_bytes()); // ttl
  // Encode the rdata (the target name) into a scratch buffer to learn RDLENGTH.
  let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in &[b"Target".as_slice(), b"Local"] {
    rdata.push(label.len() as u8);
    rdata.extend_from_slice(label);
  }
  rdata.push(0u8); // target root
  msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
  msg.extend_from_slice(&rdata);

  let (rec, _next) = Ref::try_parse(&msg, 0).unwrap();
  assert_eq!(rec.rtype(), ResourceType::Cname);
  let Rdata::Cname(_) = rec.rdata_view().unwrap() else {
    panic!("record must parse as CNAME rdata");
  };
  let view = rec.rdata_view().unwrap();
  let mut scratch = std::vec::Vec::new();
  let out = rdata_for_identity(&view, &mut scratch).unwrap();
  // PTR-style canonical form: lowercase, dot-separated, no trailing dot.
  assert_eq!(out, b"target.local".as_slice());
}

/// A CNAME whose rdata target is a forward compression pointer must surface the
/// label-iteration error from `rdata_for_identity` (the CNAME arm hashes
/// the target via `write_canonical_name`, which propagates `ParseError`), never
/// a silent empty hash.
#[test]
fn canonical_cname_forward_pointer_returns_err() {
  use crate::wire::{Rdata, Ref, ResourceClass, ResourceType};

  // Owner "x." (single root-terminated label), CNAME header, then a 2-byte
  // rdata that is a compression pointer targeting offset 0 (forward → invalid).
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  msg.push(1u8);
  msg.push(b'x');
  msg.push(0u8); // owner root
  msg.extend_from_slice(&ResourceType::Cname.to_u16().to_be_bytes());
  msg.extend_from_slice(&ResourceClass::In.to_u16().to_be_bytes());
  msg.extend_from_slice(&120u32.to_be_bytes());
  msg.extend_from_slice(&2u16.to_be_bytes()); // RDLENGTH = 2 (a pointer)
  let rdata_start = msg.len();
  // A self-referential pointer: it targets its own offset, so target >= cursor
  // → `ParseError::PointerForward` on label iteration. NameRef::try_parse still
  // accepts it (both pointer bytes exist); the error only surfaces when
  // `write_canonical_name` walks the labels.
  assert!(
    rdata_start < 0x40,
    "pointer offset must fit a single high-bit byte"
  );
  msg.push(0xC0 | (rdata_start >> 8) as u8);
  msg.push((rdata_start & 0xFF) as u8);

  let (rec, _next) = Ref::try_parse(&msg, 0).unwrap();
  let Rdata::Cname(_) = rec.rdata_view().unwrap() else {
    panic!("record must parse as CNAME rdata");
  };
  let view = rec.rdata_view().unwrap();
  let mut scratch = std::vec::Vec::new();
  assert!(
    rdata_for_identity(&view, &mut scratch).is_err(),
    "forward compression pointer in CNAME target must produce an Err"
  );
}

/// Build a dual-stack `ServiceRecords` with a TXT segment, a subtype, an IPv4
/// and an IPv6 address — exercises every record-push branch in the encoders.
fn dual_stack_records() -> crate::records::ServiceRecords {
  use core::net::{Ipv4Addr, Ipv6Addr};
  let mut r = crate::records::ServiceRecords::new(
    crate::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    crate::Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap(),
    crate::Name::try_from_str("printer.local.").unwrap(),
    631,
    120,
  );
  r.add_a(Ipv4Addr::new(192, 168, 1, 5));
  r.add_aaaa(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
  r.add_txt_segment(b"path=/admin".to_vec());
  r.add_subtype("_printer").unwrap();
  r
}

/// Assert an encoder is buffer-safe at EVERY truncation boundary: for every
/// output length from the bare header up to one byte short of the full message,
/// calling `encode(size)` must either (a) fail with `EncodeError::BufferTooSmall`
/// or (b) succeed writing `n <= size` bytes into a still-parsable message — never
/// panic, never overrun, never emit a torn record. Sweeping every size drives the
/// `?` error branch of each record push in turn (the size range where the records
/// before push *k* fit but push *k* does not), which is the property under test.
fn assert_truncation_safe_at_every_boundary<F>(n_full: usize, mut encode: F)
where
  F: FnMut(&mut [u8]) -> Result<usize, crate::error::EncodeError>,
{
  use crate::wire::MessageReader;
  assert!(n_full >= 12, "full message must exceed the header");
  let mut saw_err = false;
  let mut saw_ok = false;
  for size in 12..n_full {
    let mut buf = std::vec![0u8; size];
    match encode(&mut buf) {
      Err(e) => {
        saw_err = true;
        assert!(
          e.is_buffer_too_small(),
          "truncated to {size}B must fail as BufferTooSmall, got {e:?}"
        );
      }
      Ok(n) => {
        saw_ok = true;
        assert!(n <= size, "encoder wrote {n}B into a {size}B buffer");
        // Whatever survived truncation must still be a well-formed message.
        MessageReader::try_parse(&buf[..n])
          .unwrap_or_else(|e| panic!("truncated {size}B encode produced a torn message: {e:?}"));
      }
    }
  }
  assert!(
    saw_err,
    "at least one truncation boundary must overflow a record push"
  );
  let _ = saw_ok; // some encoders (best-effort NSEC) start succeeding before n_full.
}

/// `write_probe` propagates `EncodeError` from the question push and from each
/// authority push (SRV/TXT/A/AAAA) when the buffer cannot hold that record —
/// covers the `?` error branches on the question and SRV-authority pushes.
#[test]
fn write_probe_propagates_encode_error_at_every_boundary() {
  let recs = dual_stack_records();
  let mut big = [0u8; 1500];
  let n_full = super::write_probe(&recs, &mut big).unwrap();
  // A 12-byte buffer holds the header but not even the question → error.
  let mut tiny = [0u8; 12];
  assert!(
    super::write_probe(&recs, &mut tiny)
      .unwrap_err()
      .is_buffer_too_small(),
    "header-only buffer must overflow the probe question"
  );
  assert_truncation_safe_at_every_boundary(n_full, |buf| super::write_probe(&recs, buf));
}

/// `write_announce` propagates `EncodeError` from the SRV and TXT answer pushes
/// (and the PTR/A/AAAA pushes) when truncated. The §6.1 NSEC is best-effort, so
/// once every positive answer fits the call succeeds with the NSEC dropped — the
/// sweep tolerates that while still driving each answer push's error branch.
#[test]
fn write_announce_propagates_encode_error_at_every_boundary() {
  let recs = dual_stack_records();
  let mut big = [0u8; 1500];
  let n_full = super::write_announce(&recs, &mut big).unwrap();
  assert_truncation_safe_at_every_boundary(n_full, |buf| super::write_announce(&recs, buf));
}

/// `write_legacy_response` propagates `EncodeError` from the SRV and AAAA answer
/// pushes (plus question/PTR/TXT/A) when truncated; it has NO best-effort tail,
/// so every short buffer strictly errors.
#[test]
fn write_legacy_response_propagates_encode_error_at_every_boundary() {
  use crate::wire::{ResourceClass, ResourceType};
  let recs = dual_stack_records();
  let qname = crate::Name::try_from_str("_ipp._tcp.local.").unwrap();
  let mut big = [0u8; 1500];
  let (n_full, emitted) = super::write_legacy_response(
    &recs,
    0x1234,
    &qname,
    ResourceType::Ptr,
    ResourceClass::In,
    &mut big,
  )
  .unwrap();
  // A §6.7 legacy reply echoes the full positive-TTL record set.
  assert!(
    emitted.ptr() && emitted.srv() && emitted.txt(),
    "legacy reply reports the full instance record set as emitted"
  );
  assert_eq!(
    emitted.a_slice(),
    &[core::net::Ipv4Addr::new(192, 168, 1, 5)]
  );
  assert_eq!(
    emitted.aaaa_slice(),
    &[core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)]
  );
  assert_truncation_safe_at_every_boundary(n_full, |buf| {
    super::write_legacy_response(
      &recs,
      0x1234,
      &qname,
      ResourceType::Ptr,
      ResourceClass::In,
      buf,
    )
    .map(|(n, _)| n)
  });
}

/// `write_goodbye` propagates `EncodeError` from the SRV goodbye push (and the
/// PTR/subtype/A/AAAA pushes) when truncated. Selecting every record group keeps
/// the SRV push reachable so its `?` error branch is exercised.
#[test]
fn write_goodbye_propagates_encode_error_at_every_boundary() {
  use core::net::{Ipv4Addr, Ipv6Addr};
  let recs = dual_stack_records();
  let a = [Ipv4Addr::new(192, 168, 1, 5)];
  let aaaa = [Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)];
  let mut big = [0u8; 1500];
  let n_full = super::write_goodbye(
    &recs,
    &mut big,
    true,
    true,
    true,
    true,
    a.iter().copied(),
    aaaa.iter().copied(),
  )
  .unwrap();
  assert_truncation_safe_at_every_boundary(n_full, |buf| {
    super::write_goodbye(
      &recs,
      buf,
      true,
      true,
      true,
      true,
      a.iter().copied(),
      aaaa.iter().copied(),
    )
  });
}

/// `write_announce_filtered` (nothing suppressed) propagates `EncodeError` from
/// the SRV, TXT and AAAA answer pushes (plus PTR/A) when truncated — covering
/// each answer push's `?` error branch on the KAS-filtered path. Like
/// `write_announce`, the trailing NSEC is best-effort.
#[test]
fn write_announce_filtered_propagates_encode_error_at_every_boundary() {
  let recs = dual_stack_records();
  let mut big = [0u8; 1500];
  let (n_full, _e) = super::write_announce_filtered(&recs, &mut big, |_, _| false).unwrap();
  assert_truncation_safe_at_every_boundary(n_full, |buf| {
    super::write_announce_filtered(&recs, buf, |_, _| false).map(|(n, _)| n)
  });
}

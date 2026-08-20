use crate::{
  error::ParseError,
  wire::{Ref, ResourceClass, ResourceType},
};

/// Where [`record_bytes`] places the RDATA: the owner name `x.local.` (9
/// octets) then type, class, TTL and RDLENGTH (10 more). Fixtures that need a
/// compression pointer INTO the rdata compute their target from this.
const RDATA_START: usize = 19;

/// One resource record, owner `x.local.`, ready for [`Ref::try_parse`] at
/// offset 0.
fn record_bytes(rtype: ResourceType, rdata: &[u8]) -> std::vec::Vec<u8> {
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in [b"x".as_slice(), b"local"] {
    msg.push(u8::try_from(label.len()).unwrap());
    msg.extend_from_slice(label);
  }
  msg.push(0u8); // owner root
  msg.extend_from_slice(&rtype.to_u16().to_be_bytes());
  msg.extend_from_slice(&ResourceClass::In.to_u16().to_be_bytes());
  msg.extend_from_slice(&120u32.to_be_bytes());
  msg.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
  assert_eq!(msg.len(), RDATA_START, "RDATA_START must track this layout");
  msg.extend_from_slice(rdata);
  msg
}

/// A record's IDENTITY bytes — `Ref::canonical_rdata_folded`, the ONE decoder
/// under `RdataForm::FOLDED`, which is what §7.1 known-answer suppression and
/// the §9 identical-rdata screen compare over.
///
/// Taken from a parsed `Ref` rather than from an `Rdata` view, because the view
/// is not where the failures are: `NameRef::try_parse` accepts a compression
/// pointer without following it, so `rdata_view` succeeds on a record whose
/// embedded name is a cycle and only the decode below discovers it.
fn identity_of(rtype: ResourceType, rdata: &[u8]) -> Result<std::vec::Vec<u8>, ParseError> {
  let msg = record_bytes(rtype, rdata);
  let (rec, _next) = Ref::try_parse(&msg, 0).unwrap();
  assert_eq!(rec.rtype(), rtype);
  rec.canonical_rdata_folded().map(|b| b.to_vec())
}

#[test]
fn canonical_a_is_4_bytes() {
  let out = identity_of(ResourceType::A, &[192, 168, 1, 10]).unwrap();
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
  let out = identity_of(ResourceType::AAAA, &addr.octets()).unwrap();
  assert_eq!(out.len(), 16);
  assert_eq!(out, &addr.octets());
}

#[test]
fn canonical_txt_roundtrips_wire_form() {
  // Wire form: 0x07 "key=val" 0x01 "x"
  let raw: &[u8] = &[7, b'k', b'e', b'y', b'=', b'v', b'a', b'l', 1, b'x'];
  let out = identity_of(ResourceType::Txt, raw).unwrap();
  assert_eq!(out, raw, "canonical TXT must match wire bytes verbatim");
}

#[test]
fn canonical_txt_malformed_segment_returns_err() {
  // Segment claims 10 bytes but only 2 follow — should return Err, not silently truncate.
  let raw: &[u8] = &[10, b'a', b'b'];
  assert!(
    identity_of(ResourceType::Txt, raw).is_err(),
    "malformed TXT segment must produce an Err"
  );
}

/// PTR identity is the target in case-folded WIRE form — length-octet, label
/// bytes, root terminator. It was dot-joined bytes with no length prefixes, a
/// form that is both unmatched by the one decoder and ambiguous: labels
/// `["a.b"]` and `["a", "b"]` join to the same string.
#[test]
fn canonical_ptr_is_lowercase_wire_form_labels() {
  let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in [b"MyPrinter".as_slice(), b"_ipp", b"_tcp", b"local"] {
    rdata.push(u8::try_from(label.len()).unwrap());
    rdata.extend_from_slice(label);
  }
  rdata.push(0u8); // root label
  let out = identity_of(ResourceType::Ptr, &rdata).unwrap();
  let expected: &[u8] = b"\x09myprinter\x04_ipp\x04_tcp\x05local\x00";
  assert_eq!(out, expected);
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
  // A pointer that targets its own offset: target >= cursor → PointerForward
  // during label iteration.
  let rdata = std::vec![
    0xC0u8 | u8::try_from(RDATA_START >> 8).unwrap(),
    u8::try_from(RDATA_START & 0xFF).unwrap(),
  ];
  assert!(
    identity_of(ResourceType::Ptr, &rdata).is_err(),
    "forward compression pointer in PTR target must produce an Err"
  );
}

#[test]
fn canonical_srv_starts_with_priority_weight_port() {
  // Build SRV rdata: priority=0, weight=0, port=631, target="printer.local."
  let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
  rdata.extend_from_slice(&0u16.to_be_bytes()); // priority
  rdata.extend_from_slice(&0u16.to_be_bytes()); // weight
  rdata.extend_from_slice(&631u16.to_be_bytes()); // port
  for label in [b"printer".as_slice(), b"local"] {
    rdata.push(u8::try_from(label.len()).unwrap());
    rdata.extend_from_slice(label);
  }
  rdata.push(0u8); // root
  let out = identity_of(ResourceType::Srv, &rdata).unwrap();
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
  let (n, nsec) = super::write_announce(&recs, &mut buf).unwrap();
  assert!(nsec, "an announcement that fits reports the NSEC it emitted");
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
  let (n_full, nsec_full) = super::write_announce(&recs, &mut big).unwrap();
  assert!(nsec_full, "baseline reports the NSEC it emitted");
  let full = MessageReader::try_parse(&big[..n_full]).unwrap();
  assert_eq!(full.header().additional_count(), 1, "baseline NSEC present");
  let answers = full.header().answer_count();

  // A buffer 8 bytes short of the full message: the answers fit, but the
  // ~20-byte NSEC cannot. (NSEC is well over 8 bytes, so this reliably keeps
  // every answer while excluding the hint.)
  let cut = n_full - 8;
  let mut small = std::vec![0u8; cut];
  let (n, nsec_small) = super::write_announce(&recs, &mut small).unwrap();
  assert!(
    !nsec_small,
    "a rolled-back NSEC must be reported as NOT emitted — exposure tracking \
     reads this answer, and a record that was rolled back never reached a wire"
  );
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
/// PTR — its identity form is the same case-folded wire-form name. mDNS-SD never
/// emits CNAME, so the only way to obtain one is to parse it off the wire.
#[test]
fn canonical_cname_is_lowercase_wire_form_labels() {
  let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in [b"Target".as_slice(), b"Local"] {
    rdata.push(u8::try_from(label.len()).unwrap());
    rdata.extend_from_slice(label);
  }
  rdata.push(0u8); // target root
  let out = identity_of(ResourceType::Cname, &rdata).unwrap();
  assert_eq!(out, b"\x06target\x05local\x00".as_slice());
}

/// A CNAME whose rdata target is a forward compression pointer must surface the
/// label-iteration error, never a silent empty hash.
///
/// `NameRef::try_parse` accepts the pointer — both its bytes exist — so
/// `rdata_view` succeeds and only writing the name out walks the labels and
/// fails. That is exactly why the decode, not the view, is what every consumer
/// of this record has to agree about.
#[test]
fn canonical_cname_forward_pointer_returns_err() {
  // A self-referential pointer: it targets its own offset, so target >= cursor
  // → `ParseError::PointerForward` on label iteration.
  let rdata = std::vec![
    0xC0u8 | u8::try_from(RDATA_START >> 8).unwrap(),
    u8::try_from(RDATA_START & 0xFF).unwrap(),
  ];
  assert!(
    identity_of(ResourceType::Cname, &rdata).is_err(),
    "forward compression pointer in CNAME target must produce an Err"
  );
}

/// `canonical_rdata_forms` says which types a record set CAN assert at its
/// INSTANCE name; `instance_rtype_exposed` says which of them one generation
/// DID. They are two spellings of one list, and this pins them to each other: a
/// type added to the first without a row in the second silently loses the
/// endpoint's relinquished-RRset screen for it, so a stale echo of that type
/// would adjudicate against whatever now holds the name.
#[test]
fn instance_rtype_exposure_mirrors_the_canonical_forms() {
  let recs = dual_stack_records();
  // Everything this record set could ever put on a wire.
  let everything = super::EmittedRecords::new(
    true,
    true,
    true,
    recs.a_addrs_slice().to_vec(),
    recs.aaaa_addrs_slice().to_vec(),
    true,
    true,
  );
  for rtype in [
    ResourceType::A,
    ResourceType::AAAA,
    ResourceType::Ptr,
    ResourceType::Srv,
    ResourceType::Txt,
    ResourceType::Nsec,
    ResourceType::Hinfo,
    ResourceType::Cname,
    ResourceType::Any,
    ResourceType::Unknown(0xBEEF),
  ] {
    assert_eq!(
      !super::canonical_rdata_forms(&recs, rtype).is_empty(),
      super::instance_rtype_exposed(&everything, rtype),
      "{rtype}: the two halves of the instance-rdata rule disagree about \
       whether this type can be ours"
    );
    assert_eq!(
      !super::canonical_rdata_forms(&recs, rtype).is_empty(),
      super::INSTANCE_CANONICAL_RTYPES.contains(&rtype),
      "{rtype}: the stated DOMAIN of `canonical_rdata_forms` disagrees with the \
       function itself — a type missing from the list is one the endpoint's \
       relinquished-RRset screen never decomposes an identity for"
    );
  }
}

/// `canonical_rdata_forms` is the LIVE classifier's list and
/// `transmitted_rdata_forms` is HISTORY's, and the relation between them is
/// one-directional: history may name fewer forms, never more, and never one the
/// live rule would not have accepted.
///
/// A widening here is not a bigger version of the same answer — it is the
/// endpoint's relinquished screen claiming a form no encoder wrote, which
/// disowns a genuine peer's record and withholds the RFC 6762 §8.1 / §9 conflict
/// it carried. Every type in the stated domain must also still HAVE a
/// transmitted form, or that type silently drops out of both retention tiers.
#[test]
fn transmitted_forms_never_widen_the_canonical_ones() {
  let rtypes = [
    ResourceType::A,
    ResourceType::AAAA,
    ResourceType::Ptr,
    ResourceType::Srv,
    ResourceType::Txt,
    ResourceType::Nsec,
    ResourceType::Hinfo,
    ResourceType::Cname,
    ResourceType::Any,
    ResourceType::Unknown(0xBEEF),
  ];
  for recs in [dual_stack_records(), same_name_records()] {
    for rtype in rtypes {
      let live = super::canonical_rdata_forms(&recs, rtype);
      let transmitted = super::transmitted_rdata_forms(&recs, rtype);
      assert!(
        transmitted.iter().all(|f| live.contains(f)),
        "{rtype}: history claims a form the live classifier does not even accept; \
         transmitted {transmitted:?}, live {live:?}"
      );
      assert_eq!(
        !transmitted.is_empty(),
        super::INSTANCE_CANONICAL_RTYPES.contains(&rtype),
        "{rtype}: the stated domain of the instance-rdata rule disagrees with \
         what history can name a transmitted form for"
      );
    }
  }
  // With a host name of its own there is no second spelling for any type, so the
  // two lists coincide.
  let separate_host = dual_stack_records();
  for rtype in rtypes {
    assert_eq!(
      super::transmitted_rdata_forms(&separate_host, rtype),
      super::canonical_rdata_forms(&separate_host, rtype),
      "{rtype}: with a host name of its own there is no conforming second \
       spelling, so the two lists coincide"
    );
  }
  // The point of the pair: at an instance name that is ALSO the host name the
  // two lists differ, and they differ for exactly one type. The live classifier
  // keeps accepting a §9 twin's bare `{SRV, TXT}` — a twin that spells the same
  // claim more narrowly is not a conflict — while history keeps the one bitmap
  // the encoder actually wrote there.
  let same_name = same_name_records();
  assert_eq!(
    super::canonical_rdata_forms(&same_name, ResourceType::Nsec).len(),
    2,
    "an instance name that is also the host name is where the twin's narrower \
     bitmap is a second accepted form"
  );
  assert_eq!(
    super::transmitted_rdata_forms(&same_name, ResourceType::Nsec),
    std::vec![super::emitted_nsec_identity(&same_name)],
    "history keeps the encoder's bitmap and nothing else"
  );
}

/// `emitted_nsec_identity` claims to be the bytes `push_service_nsec` writes, so
/// the encoder is run and the claim compared against what came off the wire. A
/// drift here makes the relinquished screen answer for a record this endpoint
/// never sent, or stop answering for one it did.
#[test]
fn the_emitted_nsec_identity_is_the_bitmap_the_encoder_writes() {
  for recs in [
    dual_stack_records(),
    same_name_records(),
    same_name_v4_only_records(),
  ] {
    let (wrote, on_the_wire) = encode_service_nsec(&recs);
    assert!(wrote, "the NSEC must fit a 512-byte buffer");
    assert_eq!(
      on_the_wire,
      std::vec![super::emitted_nsec_identity(&recs)],
      "the identity history retains must be byte-identical to what the encoder \
       put on the wire"
    );
  }
}

/// A record set whose INSTANCE name IS its HOST name, with both address
/// families — the configuration in which `our_nsec_identities` names a second,
/// narrower bitmap (a §9 twin's bare `{SRV, TXT}`) that this crate's encoder
/// does not write there.
fn same_name_records() -> crate::records::ServiceRecords {
  use core::net::{Ipv4Addr, Ipv6Addr};
  let name = crate::Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  let mut r = crate::records::ServiceRecords::new(
    crate::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    name.clone(),
    name,
    631,
    120,
  );
  r.add_a(Ipv4Addr::new(192, 168, 1, 5));
  r.add_aaaa(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
  r
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
  let (n_full, _) = super::write_announce(&recs, &mut big).unwrap();
  assert_truncation_safe_at_every_boundary(n_full, |buf| {
    super::write_announce(&recs, buf).map(|(n, _)| n)
  });
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

/// RFC 6762 §7.1 known-answer suppression compares HASHES of two byte strings
/// built by different code: `write_announce_filtered` derives one from our own
/// `ServiceRecords`, and `Service::handle_event` derives the other from the
/// querier's record with `Ref::canonical_rdata_folded`. A disagreement is
/// SILENT — the hint simply never matches and nothing is ever suppressed.
///
/// SRV was broken that way once (dot-joined bytes against wire form), and PTR
/// was broken the same way until its producer moved to wire form here. So the
/// pairing is pinned rather than commented: every record the filter offers must
/// be offered in exactly the bytes the decoder yields for that same record
/// coming back off the wire.
#[test]
fn the_kas_filter_offers_the_bytes_the_identity_decoder_yields() {
  use crate::{Name, records::ServiceRecords, wire::MessageReader};

  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap(),
    Name::try_from_str("Host.local.").unwrap(),
    631,
    120,
  );
  recs.add_a(core::net::Ipv4Addr::new(192, 168, 1, 1));
  recs.add_aaaa(core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

  // Suppress nothing, but record what each candidate was offered as.
  let mut offered: std::vec::Vec<(ResourceType, std::vec::Vec<u8>)> = std::vec::Vec::new();
  let mut buf = [0u8; 1500];
  let (n, _) = super::write_announce_filtered(&recs, &mut buf, |rtype, rdata| {
    offered.push((rtype, rdata.to_vec()));
    false
  })
  .unwrap();
  assert!(
    offered
      .iter()
      .any(|(rtype, _)| *rtype == ResourceType::Ptr),
    "precondition: the PTR candidate really is KAS-filtered"
  );

  let msg = MessageReader::try_parse(buf.get(..n).unwrap()).unwrap();
  let mut checked = 0usize;
  for rr in msg.answers().flatten() {
    let identity = rr.canonical_rdata_folded().unwrap();
    assert!(
      offered
        .iter()
        .any(|(rtype, bytes)| *rtype == rr.rtype() && bytes.as_slice() == &*identity),
      "a {:?} answer canonicalizes to {:?}, which is not among the byte strings \
       the filter was offered ({offered:?}) — a hint for this record could \
       never suppress it",
      rr.rtype(),
      &*identity
    );
    checked = checked.saturating_add(1);
  }
  assert!(checked >= 4, "PTR, SRV, TXT and the addresses must all be checked");
}

/// [`transmitted_envelope`] claims to describe the WIRE ENVELOPE this crate's
/// positive multicast encoders write — which section, and the RFC 6762 §10.2
/// cache-flush bit — so the encoders are run and every record they emit is put
/// to it at the section it actually landed in.
///
/// The endpoint's relinquished-history screen is what reads that description: it
/// disowns a peer's record as an echo of ours only where the envelope matches.
/// Drift in EITHER direction is a defect with a name. An encoder that starts
/// writing addresses in the ADDITIONAL section — the RFC 6763 §12 bundle a
/// conforming responder sends — while this function still says ANSWER makes the
/// screen stop recognising our own echo. A function widened past what the
/// encoders write makes it disown a GENUINE peer's record, which suppresses the
/// terminal `HostConflict` for the whole retention window.
///
/// `write_probe` is checked from the other side: it is the ONLY encoder here
/// that writes an authority section, and every record in it must be OUTSIDE the
/// envelope. That is what makes the screen's under-claim for probes harmless —
/// a probe latches no exposure, so no identity the screen answers for has ever
/// been in a QR=1 authority section.
#[test]
fn the_envelope_is_the_one_the_encoders_actually_write() {
  use crate::{
    service::{RecordSection, transmitted_envelope},
    wire::{MessageReader, ResourceType},
  };

  /// Every rrtype the relinquished screen can answer for: the instance
  /// identities plus the host addresses.
  const SCREENED: [ResourceType; 5] = [
    ResourceType::Srv,
    ResourceType::Txt,
    ResourceType::Nsec,
    ResourceType::A,
    ResourceType::AAAA,
  ];
  const SECTIONS: [RecordSection; 3] = [
    RecordSection::Answer,
    RecordSection::Authority,
    RecordSection::Additional,
  ];

  let recs = dual_stack_records();
  let mut buf = [0u8; 1500];

  // Both positive MULTICAST encoders, since either can latch the exposure the
  // screen reads: the unsolicited announcement and the §7.1-filtered response.
  let (announce, _) = super::write_announce(&recs, &mut buf).unwrap();
  let announce = buf[..announce].to_vec();
  let mut buf = [0u8; 1500];
  let (filtered, _) = super::write_announce_filtered(&recs, &mut buf, |_, _| false).unwrap();
  let filtered = buf[..filtered].to_vec();

  for pkt in [&announce, &filtered] {
    let msg = MessageReader::try_parse(pkt).unwrap();
    let mut seen = 0usize;
    let sections: [(RecordSection, std::vec::Vec<_>); 3] = [
      (RecordSection::Answer, msg.answers().flatten().collect()),
      (RecordSection::Authority, msg.authority().flatten().collect()),
      (
        RecordSection::Additional,
        msg.additional().flatten().collect(),
      ),
    ];
    for (section, records) in &sections {
      for rr in records {
        if !SCREENED.contains(&rr.rtype()) {
          // The shared service-type and §7.1 subtype PTRs, which go out without
          // the cache-flush bit and which the screen never answers for — no
          // owner it tests is a shared name.
          assert!(
            !rr.cache_flush(),
            "{:?} is outside the screen's rrtypes yet carries the cache-flush \
             bit, so it is a unique record the envelope does not describe",
            rr.rtype()
          );
          continue;
        }
        assert!(
          transmitted_envelope(rr.rtype(), *section, rr.cache_flush()),
          "the encoder put a {:?} in {section:?} with cache_flush={}, and \
           `transmitted_envelope` does not recognise it — the relinquished \
           screen would stop disowning this endpoint's own echo",
          rr.rtype(),
          rr.cache_flush()
        );
        // …and the envelope is not vacuously wide: the OTHER two sections must
        // be rejected for this rrtype, or the qualifier buys nothing.
        for other in SECTIONS {
          if other == *section {
            continue;
          }
          assert!(
            !transmitted_envelope(rr.rtype(), other, rr.cache_flush()),
            "a {:?} is accepted in {other:?} as well as {section:?}, but this \
             crate writes it in one section only",
            rr.rtype()
          );
        }
        // …nor blind to the bit: the same record without it is not ours.
        assert!(
          !transmitted_envelope(rr.rtype(), *section, false),
          "a {:?} is accepted without the §10.2 cache-flush bit, which no \
           positive multicast send of ours ever cleared",
          rr.rtype()
        );
        seen = seen.saturating_add(1);
      }
    }
    assert!(
      seen >= 5,
      "SRV, TXT, A, AAAA and the §6.1 NSEC must all have been weighed; saw {seen}"
    );
  }

  // The probe: QR=0, authority-section, and it latches NO exposure — so nothing
  // it writes may be inside the envelope.
  let mut buf = [0u8; 1500];
  let n = super::write_probe(&recs, &mut buf).unwrap();
  let msg = MessageReader::try_parse(&buf[..n]).unwrap();
  let mut proposed = 0usize;
  for rr in msg.authority().flatten() {
    assert!(
      !transmitted_envelope(rr.rtype(), RecordSection::Authority, rr.cache_flush()),
      "a probe's proposed {:?} is inside the envelope, but a probe latches no \
       exposure — the screen would answer for a record it was never told about",
      rr.rtype()
    );
    proposed = proposed.saturating_add(1);
  }
  assert!(
    proposed >= 4,
    "the probe proposes SRV, TXT and both addresses; saw {proposed}"
  );
}

// ── RFC 6762 §6.1: what we EMIT and what we RECOGNISE are one fact ──

/// A record set whose INSTANCE name IS its HOST name with only ONE address
/// family — the shape that shows the bitmap tracks what this record set
/// actually publishes, and the shape whose residual `respond::emitted_nsec_types`
/// states: a sibling may legally publish the OTHER family at that very name
/// (`Endpoint::host_addresses_disagree` compares per rrtype precisely so that
/// pair stays legal), and this bitmap cannot see it.
fn same_name_v4_only_records() -> crate::records::ServiceRecords {
  use core::net::Ipv4Addr;
  let name = crate::Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  let mut r = crate::records::ServiceRecords::new(
    crate::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    name.clone(),
    name,
    631,
    120,
  );
  r.add_a(Ipv4Addr::new(192, 168, 1, 5));
  r
}

/// A record's owner name, lowercased and dot-joined — an owner IDENTITY two
/// records of one message can be compared on without caring which of them the
/// compression table pointed at.
fn owner_key(rec: &Ref<'_>) -> std::string::String {
  let mut out = std::string::String::new();
  for label in rec.name().labels() {
    let label = label.unwrap();
    out.push_str(&std::string::String::from_utf8_lossy(label).to_lowercase());
    out.push('.');
  }
  out
}

/// The rrtypes an NSEC's RFC 4034 §4.1.2 bitmap says DO exist, read back off the
/// wire: `next_name` in wire form (length-prefixed labels, root 0x00), then the
/// single window block RFC 6762 §6.1 restricts mDNS to.
fn nsec_present_types(folded: &[u8]) -> std::vec::Vec<u16> {
  let mut i = 0usize;
  while let Some(&len) = folded.get(i) {
    i += 1;
    if len == 0 {
      break;
    }
    i += usize::from(len);
  }
  assert_eq!(
    folded.get(i),
    Some(&0u8),
    "RFC 6762 §6.1 restricts mDNS NSEC to type-bitmap window block 0"
  );
  let blen = usize::from(*folded.get(i + 1).expect("a block length byte"));
  let mut out = std::vec::Vec::new();
  for (byte_idx, byte) in folded[i + 2..i + 2 + blen].iter().enumerate() {
    for bit in 0..8u16 {
      if byte & (0x80u8 >> bit) != 0 {
        out.push(u16::try_from(byte_idx).unwrap() * 8 + bit);
      }
    }
  }
  out
}

/// Check every NSEC in `msg` against the message's own positive answers, and
/// return how many NSECs it carried.
///
/// The property: an NSEC may not deny an rrtype that the SAME message asserts at
/// the NSEC's own owner name. That is RFC 6762 §6.1's whole premise — the
/// responder "can legitimately assert that no record with that name, rrtype, and
/// rrclass exists" — read back off the datagram instead of off a constant.
fn nsec_count_after_checking_denials(msg: &[u8]) -> usize {
  let reader = crate::wire::MessageReader::try_parse(msg).unwrap();
  let asserted: std::vec::Vec<(std::string::String, u16)> = reader
    .answers()
    .flatten()
    .map(|rr| (owner_key(&rr), rr.rtype().to_u16()))
    .collect();
  let mut seen = 0usize;
  for rr in reader.additional().flatten() {
    if rr.rtype() != ResourceType::Nsec {
      continue;
    }
    seen += 1;
    let owner = owner_key(&rr);
    let folded = rr.canonical_rdata_folded().unwrap();
    let present = nsec_present_types(&folded);
    for (answer_owner, rtype) in &asserted {
      if *answer_owner != owner {
        continue;
      }
      assert!(
        present.contains(rtype),
        "the §6.1 NSEC at {owner} denies rrtype {rtype}, which this very message \
         asserts at that same owner; the bitmap lists {present:?}"
      );
    }
  }
  seen
}

/// The bytes `write_announce` produces for `records`.
fn announce_bytes(records: &crate::records::ServiceRecords) -> std::vec::Vec<u8> {
  let mut buf = std::vec![0u8; 1500];
  let (n, _) = super::write_announce(records, &mut buf).unwrap();
  buf.truncate(n);
  buf
}

/// The bytes `write_announce_filtered` produces for `records` with no §7.1 hint
/// suppressing anything — the other positive multicast encoder, which reaches
/// `push_service_nsec` through its own call site.
fn filtered_bytes(records: &crate::records::ServiceRecords) -> std::vec::Vec<u8> {
  let mut buf = std::vec![0u8; 1500];
  let (n, _) = super::write_announce_filtered(records, &mut buf, |_, _| false).unwrap();
  buf.truncate(n);
  buf
}

/// The §6.1 NSEC this crate emits must not deny records the same announcement
/// carries.
///
/// Both positive multicast encoders write the A and AAAA records at
/// `records.host()` and the NSEC at `records.instance()`. Where those two names
/// are ONE — a supported configuration — a `{SRV, TXT}` bitmap is a
/// cache-flushed authoritative denial of address records sitting in the very
/// same datagram, and a querier that believes it will not ask again for the
/// addresses it was just handed until the negative cache entry expires.
///
/// Asserted over the DATAGRAM, not over a bitmap constant: whatever this crate
/// decides to emit, no NSEC may deny a type its own message asserts at that
/// owner. The count is pinned in the same breath, because the other way to stop
/// denying a record is to stop answering at all.
#[test]
fn no_emitted_nsec_denies_a_type_the_same_message_carries() {
  // The first fixture is the CONTROL — a host name of its own, which is how this
  // crate is overwhelmingly deployed. The other two are the defect: the instance
  // name IS the host name, so the addresses land at the NSEC's own owner.
  for recs in [
    dual_stack_records(),
    same_name_records(),
    same_name_v4_only_records(),
  ] {
    for msg in [announce_bytes(&recs), filtered_bytes(&recs)] {
      assert_eq!(
        nsec_count_after_checking_denials(&msg),
        1,
        "every positive multicast response carries its §6.1 NSEC"
      );
    }
  }
}

/// Run `push_service_nsec` into a fresh message; hand back whether it reported
/// writing, and the identity bytes of every NSEC that actually reached the wire.
fn encode_service_nsec(
  records: &crate::records::ServiceRecords,
) -> (bool, std::vec::Vec<std::vec::Vec<u8>>) {
  let mut msg = [0u8; 512];
  let mut b =
    crate::wire::MessageBuilder::<'_, 32>::try_new(&mut msg, crate::wire::Header::new()).unwrap();
  let wrote = super::push_service_nsec(&mut b, records);
  let n = b.finish().unwrap();
  let reader = crate::wire::MessageReader::try_parse(&msg[..n]).unwrap();
  let forms = reader
    .additional()
    .flatten()
    .map(|rr| rr.canonical_rdata_folded().unwrap().to_vec())
    .collect();
  (wrote, forms)
}

/// The EMITTED identity and the LOCALLY RECOGNISED identities are two readings
/// of ONE fact, and the defect was that each kept its own copy of it. Pinned
/// against the FUNCTIONS rather than against a literal bitmap, so the two cannot
/// drift apart again.
///
/// They are not EQUAL, and must not be: recognition is lenient where emission is
/// exact, so `our_nsec_identities` also accepts a §9 twin's bare `{SRV, TXT}` at
/// a name that holds addresses. What has to hold is that whatever the encoder
/// puts on the wire is in that list — otherwise our own record comes back as
/// inconsistent rdata at a name we are probing.
#[test]
fn whatever_the_encoder_writes_is_recognised_as_ours() {
  for recs in [
    dual_stack_records(),
    same_name_records(),
    same_name_v4_only_records(),
  ] {
    let recognised = super::our_nsec_identities(&recs);
    let (wrote, on_the_wire) = encode_service_nsec(&recs);
    assert!(wrote, "the §6.1 NSEC is written at every instance name");
    assert_eq!(
      on_the_wire.len(),
      usize::from(wrote),
      "the reported answer must be the number of NSECs that reached the wire"
    );
    for form in &on_the_wire {
      assert!(
        recognised.contains(form),
        "the encoder wrote an NSEC the recogniser would not accept as ours: \
         {form:?} is not among {recognised:?}"
      );
    }
  }
}

/// The bitmap each shape of record set asserts, pinned by VALUE — what changed
/// on the wire and what did not.
#[test]
fn the_emitted_bitmap_names_the_address_families_this_record_set_publishes() {
  let srv = ResourceType::Srv.to_u16();
  let txt = ResourceType::Txt.to_u16();
  let a = ResourceType::A.to_u16();
  let aaaa = ResourceType::AAAA.to_u16();
  assert_eq!(
    super::emitted_nsec_types(&dual_stack_records()),
    std::vec![srv, txt],
    "a host name of its own puts no address record at the instance name, so \
     nothing changes on the wire there"
  );
  assert_eq!(
    super::emitted_nsec_types(&same_name_records()),
    std::vec![srv, txt, a, aaaa],
    "the addresses this record set publishes at that name are named, not denied"
  );
  assert_eq!(
    super::emitted_nsec_types(&same_name_v4_only_records()),
    std::vec![srv, txt, a],
    "and only the families it actually publishes — the bitmap describes this \
     record set, not the name"
  );
}

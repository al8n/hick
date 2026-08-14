//! Unit tests for the §8.2 fold and for the peer-side bytes it compares.
//!
//! They live here because nothing outside this module chooses an [`RdataForm`]
//! for §8.2 — that seal is the point of the module — so the `AS_SENT` rendering
//! of a peer record is only reachable from in here. The behaviour a caller CAN
//! reach is tested through `Service` in `service::tests`.

use super::*;

/// Build a one-record message and hand back the parsed record's tiebreak bytes.
fn tiebreak_bytes_of(msg: &[u8]) -> std::vec::Vec<u8> {
  let reader = crate::wire::MessageReader::try_parse(msg).unwrap();
  let rec = reader.additional().flatten().next().unwrap();
  let mut out = std::vec::Vec::new();
  rec.write_canonical_rdata(RdataForm::AS_SENT, &mut out).unwrap();
  out
}

fn nsec_message(owner: &str) -> std::vec::Vec<u8> {
  let mut msg = std::vec![0u8; 512];
  let name = crate::Name::try_from_str(owner).unwrap();
  let mut b =
    crate::wire::MessageBuilder::<'_, 32>::try_new(&mut msg, crate::wire::Header::new()).unwrap();
  b.push_nsec_additional(&name, 120, &respond::INSTANCE_NSEC_TYPES, true)
    .unwrap();
  let n = b.finish().unwrap();
  msg.truncate(n);
  msg
}

/// §8.2 compares NSEC's `next_name` along with its bitmap. Dropping the name made
/// two NSECs denying the same types at DIFFERENT names compare equal.
#[test]
fn an_nsecs_tiebreak_bytes_carry_its_next_name() {
  assert_ne!(
    tiebreak_bytes_of(&nsec_message("one._ipp._tcp.local.")),
    tiebreak_bytes_of(&nsec_message("two._ipp._tcp.local.")),
    "the next_name is part of what §8.2 compares"
  );
}

/// The peer's bytes are compared AS SENT — case included. That is the whole
/// difference between `RdataForm::AS_SENT` and `RdataForm::FOLDED`, and the
/// reason the §8.2 path may not reach for the identity form.
#[test]
fn a_peers_case_survives_into_the_tiebreak_bytes() {
  let build = |target: &str| {
    let mut msg = std::vec![0u8; 512];
    // Hand-built: `MessageBuilder::write_name` LOWERCASES on transmit, so it
    // cannot express a peer that sent mixed case at all.
    msg.clear();
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ARCOUNT=1
    for label in "x.local".split('.') {
      msg.push(u8::try_from(label.len()).unwrap());
      msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&33u16.to_be_bytes()); // SRV
    msg.extend_from_slice(&1u16.to_be_bytes()); // IN
    msg.extend_from_slice(&120u32.to_be_bytes());
    let mut rdata = std::vec::Vec::new();
    rdata.extend_from_slice(&0u16.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes());
    rdata.extend_from_slice(&631u16.to_be_bytes());
    for label in target.trim_end_matches('.').split('.') {
      rdata.push(u8::try_from(label.len()).unwrap());
      rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0);
    msg.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    msg.extend_from_slice(&rdata);
    msg
  };
  assert_ne!(
    tiebreak_bytes_of(&build("HOST.local.")),
    tiebreak_bytes_of(&build("host.local.")),
    "§8.2 mandates decompression and nothing else — case-folding the peer's \
     bytes makes the two sides compute different functions"
  );
}

/// Whether unparsed rdata has comparison bytes is a per-TYPE question, and the
/// answer is never inferred from the bytes.
///
/// R12 found the byte-sniffing predicate that briefly stood here wrong in both
/// directions, and the severe one is the first case below: pointer syntax is
/// meaningful only inside a field the type DEFINES as a name, so an opaque RR
/// may validly contain `0xC0`. Refusing it meant the peer compared that record
/// correctly and won while we abandoned and kept probing — BOTH then claimed
/// the name. The enumeration is the honest encoding, and RFC 3597 §4 closed it
/// in 2003, so it is a finite historical set rather than a moving target.
#[test]
fn comparability_of_unparsed_rdata_is_a_per_type_question() {
  /// A message whose single record sits after `extra_questions` + 1 questions.
  ///
  /// The first question's QNAME is always at offset 12, so a pointer to 12
  /// resolves to the same name in every variant while the RECORD's own offset
  /// moves — which is exactly the position-independence being asserted.
  fn message(rtype: u16, rdata: &[u8], extra_questions: usize) -> std::vec::Vec<u8> {
    let mut m = std::vec::Vec::new();
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&u16::try_from(1 + extra_questions).unwrap().to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1
    let question = |name: &[&str], m: &mut std::vec::Vec<u8>| {
      for label in name {
        m.push(u8::try_from(label.len()).unwrap());
        m.extend_from_slice(label.as_bytes());
      }
      m.push(0);
      m.extend_from_slice(&crate::wire::ResourceType::Any.to_u16().to_be_bytes());
      m.extend_from_slice(&1u16.to_be_bytes());
    };
    question(&["x", "local"], &mut m); // QNAME at offset 12, in every variant
    for _ in 0..extra_questions {
      question(&["filler", "local"], &mut m);
    }
    for label in ["rec", "local"] {
      m.push(u8::try_from(label.len()).unwrap());
      m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&rtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    m.extend_from_slice(&120u32.to_be_bytes());
    m.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    m.extend_from_slice(rdata);
    m
  }
  fn bytes_of(rtype: u16, rdata: &[u8], extra_questions: usize) -> Result<std::vec::Vec<u8>, ()> {
    let msg = message(rtype, rdata, extra_questions);
    let reader = crate::wire::MessageReader::try_parse(&msg).unwrap();
    let rec = reader.additional().flatten().next().ok_or(())?;
    let mut out = std::vec::Vec::new();
    rec
      .write_canonical_rdata(RdataForm::AS_SENT, &mut out)
      .map(|()| out)
      .map_err(|_| ())
  }

  // (1) THE DUPLICATE-OWNERSHIP CASE. An opaque private type may hold `0xC0` as
  // ordinary data. RFC 3597 §4 forbids compression in it, so those bytes are
  // self-contained and MUST compare — refusing them is what let a peer win a
  // round we then declined to lose.
  assert_eq!(
    bytes_of(64000, &[0xC0, 0x0C, 0x01], 0),
    Ok(std::vec![0xC0, 0x0C, 0x01]),
    "an opaque type is copied verbatim whatever octets it holds"
  );

  // (2) A compression-eligible type is DECOMPRESSED rather than refused, so it
  // takes part in the comparison instead of abandoning the whole proposal. MX is
  // `(lead 2, names 1)`: preference, then a name.
  let mut mx = std::vec::Vec::new();
  mx.extend_from_slice(&10u16.to_be_bytes());
  for label in ["mail", "local"] {
    mx.push(u8::try_from(label.len()).unwrap());
    mx.extend_from_slice(label.as_bytes());
  }
  mx.push(0);
  let uncompressed = bytes_of(15, &mx, 0).expect("an uncompressed MX compares");
  assert_eq!(
    uncompressed, mx,
    "an already-uncompressed name is its own comparison form"
  );

  // (3) …and the point of decompressing: the SAME record compressed, sitting at
  // two DIFFERENT offsets, yields the same bytes as the uncompressed form. That
  // is the position-independence §8.2 needs — achieved by decompressing, not by
  // refusing to look.
  let mut expected = std::vec::Vec::new();
  expected.extend_from_slice(&10u16.to_be_bytes());
  for label in ["x", "local"] {
    expected.push(u8::try_from(label.len()).unwrap());
    expected.extend_from_slice(label.as_bytes());
  }
  expected.push(0);
  let mut compressed = std::vec::Vec::new();
  compressed.extend_from_slice(&10u16.to_be_bytes());
  compressed.extend_from_slice(&(0xC000u16 | 12).to_be_bytes());
  for extra in [0usize, 1, 2] {
    assert_eq!(
      bytes_of(15, &compressed, extra),
      Ok(expected.clone()),
      "{extra} filler question(s): a compressed MX decompresses to the same \
       bytes wherever the record sat in the packet"
    );
  }

  // (4) A compression-eligible type whose name will NOT decode still abandons —
  // decompressing is not the same as accepting anything.
  {
    // The pointer targets its own position inside the rdata, so following it
    // loops. That position is `header + questions + owner(rec.local) + type +
    // class + ttl + rdlength + preference`.
    let rdata_at = 12 + (1 + 1 + 1 + 5 + 1 + 2 + 2) + (1 + 3 + 1 + 5 + 1) + 2 + 2 + 4 + 2;
    let mut cyclic = std::vec::Vec::new();
    cyclic.extend_from_slice(&10u16.to_be_bytes());
    cyclic.extend_from_slice(&(0xC000u16 | u16::try_from(rdata_at + 2).unwrap()).to_be_bytes());
    assert_eq!(
      bytes_of(15, &cyclic, 0),
      Err(()),
      "a compressed name that cannot be resolved has no comparison bytes"
    );
  }

  // (5) THE OTHER HALF OF (1), and the one an earlier revision got backwards.
  // SIG(24), NXT(30), NAPTR(35) and A6(38) are ABSENT from RFC 6762 §18.14, and
  // §18.14 closes its list: "names that appear within the rdata of any type not
  // listed above MUST NOT be compressed". Absence is therefore a positive fact —
  // these never carry a pointer, so their bytes are self-contained and compare
  // verbatim like any other unlisted type. Reading absence as "eligible with a
  // layout we cannot locate" made this crate abandon comparisons that every
  // conforming peer completes, which is (1)'s duplicate-ownership outcome
  // reached by declining instead of by refusing.
  for rtype in [24u16, 30, 35, 38] {
    assert_eq!(
      bytes_of(rtype, &[0x00, 0x0A, 0x00, 0x0A, 0x00], 0),
      Ok(std::vec![0x00, 0x0A, 0x00, 0x0A, 0x00]),
      "rtype {rtype} is absent from §18.14, so its rdata compares verbatim"
    );
  }
}

/// §8.2.1's length rule, at the level the fold implements it: equal on every
/// shared element, the longer list wins, and equal lengths are "no conflict".
#[test]
fn the_fold_gives_the_longer_list_the_win_and_ties_no_conflict() {
  let ours = std::vec![std::vec![1u8], std::vec![2u8]];
  let mut tie = ProposalFold::new(ours.len());
  tie.offer(std::vec![1u8]);
  tie.offer(std::vec![2u8]);
  assert!(!tie.peer_wins(&ours), "identical lists are not a conflict");

  let mut longer = ProposalFold::new(ours.len());
  longer.offer(std::vec![1u8]);
  longer.offer(std::vec![2u8]);
  longer.offer(std::vec![3u8]);
  assert!(
    longer.peer_wins(&ours),
    "\"the list with records remaining is deemed to have won\""
  );

  let mut shorter = ProposalFold::new(ours.len());
  shorter.offer(std::vec![1u8]);
  assert!(!shorter.peer_wins(&ours), "and ours is the longer one here");
}

/// A TTL-zero record in the peer's Authority Section is part of the list §8.2.1
/// sorts, exactly like every other record there.
///
/// §8.2 requires the Authority Section to hold "*all* the records and proposed
/// rdata being probed for uniqueness" and §8.2.1 orders by class, then type,
/// then rdata — the TTL is not compared. §10.1's goodbye encoding belongs to an
/// unsolicited RESPONSE, not to a QR=0 probe's proposal.
///
/// The fixture is built so the two dispositions give OPPOSITE verdicts. The
/// peer's SRV and TXT tie ours byte for byte, so the whole comparison turns on
/// its third record: counted, the peer's list has records remaining and §8.2.1
/// gives it the name; dropped, the lists tie and we keep the name. A screen that
/// shortens the peer's list can therefore only ever flatter us — which is the
/// defect, since the peer compares OUR complete list and reaches the other
/// answer, leaving two conforming hosts each holding the name.
#[test]
fn a_ttl_zero_record_is_still_part_of_the_peers_proposal() {
  const INSTANCE: &str = "myprinter._ipp._tcp.local.";

  fn labels(out: &mut std::vec::Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
      out.push(u8::try_from(label.len()).unwrap());
      out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
  }
  fn record(out: &mut std::vec::Vec<u8>, rtype: u16, ttl: u32, rdata: &[u8]) {
    labels(out, INSTANCE);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    out.extend_from_slice(rdata);
  }

  let records = ServiceRecords::new(
    crate::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    crate::Name::try_from_str(INSTANCE).unwrap(),
    crate::Name::try_from_str("host.local.").unwrap(),
    631,
    120,
  );

  let mut msg = std::vec::Vec::new();
  msg.extend_from_slice(&0u16.to_be_bytes());
  msg.extend_from_slice(&0u16.to_be_bytes()); // QR=0 — a probe is a query
  msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
  msg.extend_from_slice(&0u16.to_be_bytes());
  msg.extend_from_slice(&3u16.to_be_bytes()); // NSCOUNT
  msg.extend_from_slice(&0u16.to_be_bytes());
  labels(&mut msg, INSTANCE);
  msg.extend_from_slice(&crate::wire::ResourceType::Any.to_u16().to_be_bytes());
  msg.extend_from_slice(&(0x8000u16 | 1).to_be_bytes());
  // SRV(0, 0, 631, host.local.) and an empty TXT — byte-identical to ours.
  let mut srv = std::vec::Vec::new();
  srv.extend_from_slice(&0u16.to_be_bytes());
  srv.extend_from_slice(&0u16.to_be_bytes());
  srv.extend_from_slice(&631u16.to_be_bytes());
  labels(&mut srv, "host.local.");
  record(&mut msg, 33, 120, &srv);
  record(&mut msg, 16, 120, &[0x00]);
  // …and a third record carrying TTL 0. Its rtype (38) sorts after both of
  // ours, so it is exactly §8.2.1's record REMAINING once the tying pair is
  // exhausted — not an element that could win or lose on its own bytes. Type 38
  // is absent from §18.14, so its rdata compares verbatim; see
  // `comparability_of_unparsed_rdata_is_a_per_type_question`.
  record(&mut msg, 38, 0, &[0x2a]);

  let src: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let reader = crate::wire::MessageReader::try_parse(&msg).unwrap();
  let pp = crate::event::ProbeProposal::new(src, reader, crate::event::DatagramId::new(1));
  assert_eq!(
    adjudicate(&pp, &records),
    Verdict::PeerWins,
    "§8.2.1 compares class, type and rdata — never the TTL — so the peer's \
     TTL-zero record is one of the records remaining after the tying pair, and \
     dropping it would decide the tiebreak over a list the peer never sent"
  );
}

/// A record whose CLASS is not IN is not in the peer's proposal — the RECORD's
/// class, which is a different screen from the QUESTION's.
///
/// `a_question_asking_in_another_class_proposes_nothing_about_ours` pins the
/// question side: a query contending a name in another class proposes nothing
/// about our IN record. This pins the record side, and neither substitutes for
/// the other — a conforming IN probe may still carry a record of another class
/// in its Authority Section, and that record is not part of the RRset being
/// contended.
///
/// It is load-bearing rather than cosmetic because of how the fold keys its
/// elements. §8.2.1 orders "by class (then type, then rdata)", but
/// [`ProposalFold`] omits the class from the sort key entirely — precisely
/// BECAUSE only IN is admitted, so it is invariant. Admit a CH record and it is
/// compared as though it were IN, at a position its real class would never have
/// put it in.
///
/// Built so the two dispositions give OPPOSITE verdicts, like the TTL fixture
/// above: the peer's SRV and TXT tie ours byte for byte, so the round turns
/// entirely on the third record. Screened, the lists tie and §8.2.1's "no
/// conflict" leaves us the name; admitted, the peer has a record remaining and
/// takes it.
#[test]
fn a_record_of_another_class_is_not_in_the_peers_proposal() {
  const INSTANCE: &str = "myprinter._ipp._tcp.local.";

  fn labels(out: &mut std::vec::Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
      out.push(u8::try_from(label.len()).unwrap());
      out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
  }
  fn record(out: &mut std::vec::Vec<u8>, rtype: u16, rclass: u16, rdata: &[u8]) {
    labels(out, INSTANCE);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&rclass.to_be_bytes());
    out.extend_from_slice(&120u32.to_be_bytes());
    out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    out.extend_from_slice(rdata);
  }

  let records = ServiceRecords::new(
    crate::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    crate::Name::try_from_str(INSTANCE).unwrap(),
    crate::Name::try_from_str("host.local.").unwrap(),
    631,
    120,
  );

  let mut msg = std::vec::Vec::new();
  msg.extend_from_slice(&0u16.to_be_bytes());
  msg.extend_from_slice(&0u16.to_be_bytes()); // QR=0 — a probe is a query
  msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
  msg.extend_from_slice(&0u16.to_be_bytes());
  msg.extend_from_slice(&3u16.to_be_bytes()); // NSCOUNT
  msg.extend_from_slice(&0u16.to_be_bytes());
  labels(&mut msg, INSTANCE);
  msg.extend_from_slice(&crate::wire::ResourceType::Any.to_u16().to_be_bytes());
  msg.extend_from_slice(&(0x8000u16 | 1).to_be_bytes()); // QU | QCLASS IN
  // SRV(0, 0, 631, host.local.) and an empty TXT — byte-identical to ours, both
  // in class IN so the question and record classes both admit them.
  let mut srv = std::vec::Vec::new();
  srv.extend_from_slice(&0u16.to_be_bytes());
  srv.extend_from_slice(&0u16.to_be_bytes());
  srv.extend_from_slice(&631u16.to_be_bytes());
  labels(&mut srv, "host.local.");
  record(&mut msg, 33, 1, &srv);
  record(&mut msg, 16, 1, &[0x00]);
  // …and a third record in class CH(3). Its rtype (38) sorts after both of ours,
  // so if it were admitted it would be exactly §8.2.1's record REMAINING once
  // the tying pair is exhausted. Type 38 is absent from RFC 6762 §18.14, so its
  // rdata compares verbatim and the fixture turns on the class alone.
  record(&mut msg, 38, 3, &[0x2a]);

  let src: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let reader = crate::wire::MessageReader::try_parse(&msg).unwrap();
  let pp = crate::event::ProbeProposal::new(src, reader, crate::event::DatagramId::new(1));
  assert_eq!(
    adjudicate(&pp, &records),
    Verdict::WeHold,
    "a class-CH record is not in the IN RRset being contended, so it is not one \
     of the records §8.2.1 sorts — admitting it would compare it as though it \
     were IN, since the fold leaves class out of its sort key on the strength of \
     exactly this screen"
  );
}

/// THE property, asserted where it actually lives: on the [`Verdict`].
///
/// "No proposal containing anything undecodable produces a verdict" is a
/// statement about `adjudicate`'s RESULT, and a `Service`-level fixture cannot
/// see it — `Abandoned` and `WeHold` both leave `tiebreak_lost` false, so a
/// regression that silently SKIPPED the undecodable part instead of abandoning
/// would keep every service-level test green. Only the verdict tells them apart,
/// and the difference matters: skipping shortens the peer's list, and §8.2.1
/// gives the longer list the win, so a skip is systematically biased toward
/// deciding we won.
///
/// Every reason the fold can abandon for is driven from a real datagram here, so
/// each `?` in `fold` has a case behind it.
#[test]
fn anything_undecodable_yields_no_verdict() {
  const INSTANCE: &str = "myprinter._ipp._tcp.local.";

  fn records() -> ServiceRecords {
    ServiceRecords::new(
      crate::Name::try_from_str("_ipp._tcp.local.").unwrap(),
      crate::Name::try_from_str(INSTANCE).unwrap(),
      crate::Name::try_from_str("host.local.").unwrap(),
      631,
      120,
    )
  }
  fn labels(out: &mut std::vec::Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
      out.push(u8::try_from(label.len()).unwrap());
      out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
  }
  /// header + `qdcount` questions + `nscount` authority records.
  fn header(qd: u16, ns: u16) -> std::vec::Vec<u8> {
    let mut m = std::vec::Vec::new();
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes()); // QR=0, a probe is a query
    m.extend_from_slice(&qd.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&ns.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m
  }
  fn any_question(out: &mut std::vec::Vec<u8>, name: &str) {
    labels(out, name);
    out.extend_from_slice(&crate::wire::ResourceType::Any.to_u16().to_be_bytes());
    out.extend_from_slice(&(0x8000u16 | 1).to_be_bytes());
  }
  /// A record at INSTANCE with the given type and rdata.
  fn record(out: &mut std::vec::Vec<u8>, rtype: u16, ttl: u32, rdata: &[u8]) {
    labels(out, INSTANCE);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    out.extend_from_slice(rdata);
  }
  /// SRV(631, host.local.) + TXT(one empty string) — byte-identical to ours, so
  /// on their own they TIE and the verdict turns on whatever else is present.
  fn tying_pair(out: &mut std::vec::Vec<u8>) {
    let mut srv = std::vec::Vec::new();
    srv.extend_from_slice(&0u16.to_be_bytes());
    srv.extend_from_slice(&0u16.to_be_bytes());
    srv.extend_from_slice(&631u16.to_be_bytes());
    labels(&mut srv, "host.local.");
    record(out, 33, 120, &srv);
    record(out, 16, 120, &[0x00]);
  }

  // CONTROL: the tying pair alone reaches a real verdict, so every abandonment
  // below is the undecodable part and not the fixture failing to be adjudicated.
  let mut control = header(1, 2);
  any_question(&mut control, INSTANCE);
  tying_pair(&mut control);

  // An UNPARSEABLE authority record: NSCOUNT claims three, the third is truncated.
  let mut bad_authority = header(1, 3);
  any_question(&mut bad_authority, INSTANCE);
  tying_pair(&mut bad_authority);
  bad_authority.extend_from_slice(&[0x05, b'h', b'e', b'l', b'l']);

  // An UNDECODABLE OWNER NAME: a third record whose name points at itself.
  let mut bad_owner = header(1, 3);
  any_question(&mut bad_owner, INSTANCE);
  tying_pair(&mut bad_owner);
  let at = u16::try_from(bad_owner.len()).unwrap();
  bad_owner.extend_from_slice(&(0xC000u16 | at).to_be_bytes());
  bad_owner.extend_from_slice(&1u16.to_be_bytes()); // A
  bad_owner.extend_from_slice(&1u16.to_be_bytes());
  bad_owner.extend_from_slice(&120u32.to_be_bytes());
  bad_owner.extend_from_slice(&4u16.to_be_bytes());
  bad_owner.extend_from_slice(&[10, 0, 0, 1]);

  // UNCOMPARABLE RDATA: a KX (one of the types R11's enumeration missed) whose
  // compressed target points past the end of the datagram and cannot resolve.
  //
  // It has to be UNRESOLVABLE to abandon. A KX whose pointer resolves now
  // decompresses and takes part in the comparison — that is R12's fix, and
  // `comparability_of_unparsed_rdata_is_a_per_type_question` pins it. Abandoning
  // is for rdata that genuinely has no comparison bytes, not for a type.
  let mut bad_rdata = header(1, 3);
  any_question(&mut bad_rdata, INSTANCE);
  tying_pair(&mut bad_rdata);
  record(&mut bad_rdata, 36, 120, &[0x00, 0x0A, 0xFF, 0xFF]);

  // UNREADABLE QUESTIONS: a valid admitting question, then one whose QNAME is a
  // pointer that cannot be resolved.
  let mut bad_question = header(2, 2);
  any_question(&mut bad_question, INSTANCE);
  let q2 = u16::try_from(bad_question.len()).unwrap();
  bad_question.extend_from_slice(&(0xC000u16 | q2).to_be_bytes());
  bad_question.extend_from_slice(&crate::wire::ResourceType::Any.to_u16().to_be_bytes());
  bad_question.extend_from_slice(&(0x8000u16 | 1).to_be_bytes());
  tying_pair(&mut bad_question);

  let cases: [(&str, &std::vec::Vec<u8>, Verdict); 5] = [
    ("control: a readable tying proposal IS adjudicated", &control, Verdict::WeHold),
    (
      "an authority section that stops parsing partway",
      &bad_authority,
      Verdict::Abandoned(Abandon::UnparseableAuthority),
    ),
    (
      "a record whose owner name will not decode",
      &bad_owner,
      Verdict::Abandoned(Abandon::UndecodableOwnerName),
    ),
    (
      "rdata that may hold a compression pointer",
      &bad_rdata,
      Verdict::Abandoned(Abandon::UndecodableRdata),
    ),
    (
      "a question section holding a QNAME that will not decode",
      &bad_question,
      Verdict::Abandoned(Abandon::UnreadableQuestions),
    ),
  ];

  let src: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  for (what, bytes, expected) in cases {
    let reader = crate::wire::MessageReader::try_parse(bytes).unwrap();
    let pp = crate::event::ProbeProposal::new(src, reader, crate::event::DatagramId::new(1));
    assert_eq!(
      adjudicate(&pp, &records()),
      expected,
      "{what}: a proposal is adjudicated only when every part of it that had to \
       be read, read — and skipping the unreadable part instead would shorten \
       the peer's list, which only ever flatters us"
    );
  }
}

/// THE property §8.2 exists to provide: two differing proposals produce EXACTLY
/// ONE winner, whichever side is asked.
///
/// Run in BOTH directions on purpose. A one-directional fixture cannot see the
/// failure R12 found: when `instance == host`, `write_probe` emits the address
/// records under the contested owner, the peer's fold counted them and our list
/// did not, and with identical A records — which sort before TXT — each side saw
/// the other as sorting earlier. Both returned `WeHold`, both announced, and
/// nothing in a single-direction test was wrong.
///
/// So the assertion is on the PAIR: exactly one `PeerWins` for differing
/// records, and zero for identical ones (§8.2.1's "there is, in fact, no
/// conflict").
#[test]
fn two_differing_proposals_produce_exactly_one_winner() {
  fn records(instance: &str, host: &str, port: u16, addr: [u8; 4]) -> ServiceRecords {
    let mut r = ServiceRecords::new(
      crate::Name::try_from_str("_ipp._tcp.local.").unwrap(),
      crate::Name::try_from_str(instance).unwrap(),
      crate::Name::try_from_str(host).unwrap(),
      port,
      120,
    );
    r.add_a(core::net::Ipv4Addr::from(addr));
    r
  }
  /// What `other` decides when it adjudicates `probing`'s actual probe.
  fn verdict_of(other: &ServiceRecords, probing: &ServiceRecords) -> Verdict {
    let mut buf = std::vec![0u8; 4096];
    let n = respond::write_probe(probing, &mut buf).expect("probe encodes");
    let reader = crate::wire::MessageReader::try_parse(&buf[..n]).unwrap();
    let src: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
    let pp = crate::event::ProbeProposal::new(src, reader, crate::event::DatagramId::new(1));
    adjudicate(&pp, other)
  }

  const INST: &str = "myprinter._ipp._tcp.local.";
  let cases: [(&str, ServiceRecords, ServiceRecords, bool); 4] = [
    (
      "distinct host name, differing SRV port",
      records(INST, "host-a.local.", 631, [10, 0, 0, 1]),
      records(INST, "host-a.local.", 9999, [10, 0, 0, 1]),
      true,
    ),
    (
      // The R12 case: the address records land under the CONTESTED owner.
      "instance == host, differing SRV port, IDENTICAL addresses",
      records(INST, INST, 631, [10, 0, 0, 1]),
      records(INST, INST, 9999, [10, 0, 0, 1]),
      true,
    ),
    (
      "instance == host, same SRV, differing addresses",
      records(INST, INST, 631, [10, 0, 0, 1]),
      records(INST, INST, 631, [10, 0, 0, 2]),
      true,
    ),
    (
      "byte-identical: §8.2.1's \"there is, in fact, no conflict\"",
      records(INST, INST, 631, [10, 0, 0, 1]),
      records(INST, INST, 631, [10, 0, 0, 1]),
      false,
    ),
  ];

  for (what, a, b, differ) in cases {
    let a_says = verdict_of(&a, &b);
    let b_says = verdict_of(&b, &a);
    for (side, v) in [("a", a_says), ("b", b_says)] {
      assert!(
        !matches!(v, Verdict::Abandoned(_)),
        "{what}: side {side} must reach a verdict on a well-formed probe, got {v:?}"
      );
    }
    let winners = usize::from(a_says == Verdict::PeerWins) + usize::from(b_says == Verdict::PeerWins);
    if differ {
      assert_eq!(
        winners, 1,
        "{what}: differing proposals must resolve to exactly ONE loser — \
         a={a_says:?}, b={b_says:?}. Two `WeHold` means both hosts keep the \
         name and announce; two `PeerWins` means both defer and neither takes it"
      );
    } else {
      assert_eq!(
        winners, 0,
        "{what}: identical record sets are not a conflict at all — \
         a={a_says:?}, b={b_says:?}"
      );
    }
  }
}

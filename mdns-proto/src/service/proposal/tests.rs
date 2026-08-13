//! Unit tests for the §8.2 serializers that are private to this module.
//!
//! They live here because `rdata_for_tiebreak` and `write_wire_name_preserving_case`
//! are private — which is the point of the module — so nothing outside it can
//! test them directly. The behaviour a caller CAN reach is tested through
//! `Service` in `service::tests`.

use super::*;

/// Build a one-record message and hand back the parsed record's tiebreak bytes.
fn tiebreak_bytes_of(msg: &[u8]) -> std::vec::Vec<u8> {
  let reader = crate::wire::MessageReader::try_parse(msg).unwrap();
  let rec = reader.additional().flatten().next().unwrap();
  let view = rec.rdata_view().unwrap();
  let mut scratch = std::vec::Vec::new();
  rdata_for_tiebreak(rec.rtype(), &view, &mut scratch)
    .unwrap()
    .to_vec()
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

/// The peer's bytes are compared AS SENT — case included. This is the difference
/// from `respond::rdata_for_identity`, and the whole reason the two functions
/// exist separately.
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

/// Rdata this crate does not parse has comparison bytes exactly when those bytes
/// cannot move with the packet — decided by the BYTES, not by a list of types.
///
/// R11 found the list incomplete: it omitted RP(17), AFSDB(18), RT(21), PX(26)
/// and KX(36), all compression-eligible, so a KX with a cyclic or truncated
/// compressed target produced comparison bytes instead of an error. With
/// otherwise identical SRV and TXT the extra element made the peer's list
/// longer, §8.2.1 handed it the win, and repeating the packet could defer this
/// host indefinitely.
///
/// The replacement cannot be incomplete, because it names no types at all. It is
/// also strictly more accurate in BOTH directions, which the two halves below
/// pin: a compressed record of ANY unparsed type is refused, and an UNCOMPRESSED
/// one of a formerly-listed type now compares correctly where the list refused
/// it outright.
#[test]
fn comparability_of_unparsed_rdata_is_decided_by_the_bytes() {
  let mut scratch = std::vec::Vec::new();
  // Every type the old list named, every type it MISSED, and a genuinely unknown
  // one: rdata that could hold a compression pointer has no comparison bytes.
  let compressed = Rdata::Other(&[0xC0, 0x0C]);
  for raw in [2u16, 6, 15, 39, 17, 18, 21, 26, 36, 64000] {
    assert!(
      rdata_for_tiebreak(
        crate::wire::ResourceType::from_u16(raw),
        &compressed,
        &mut scratch
      )
      .is_err(),
      "type {raw}: rdata holding a 0xC0 octet may be a compression pointer, so \
       it has no position-independent comparison bytes"
    );
  }

  // …and the same types compare fine when the rdata provably holds no pointer.
  // The old list refused these outright on type alone, which was both incomplete
  // AND over-strict.
  let uncompressed = Rdata::Other(b"\x04mail\x05local\x00");
  for raw in [2u16, 15, 36, 64000] {
    assert!(
      rdata_for_tiebreak(
        crate::wire::ResourceType::from_u16(raw),
        &uncompressed,
        &mut scratch
      )
      .is_ok(),
      "type {raw}: an uncompressed name is already the form §8.2 compares, so \
       these bytes mean the same thing in any packet"
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

  // UNCOMPARABLE RDATA: a KX whose rdata may hold a compression pointer — the
  // type the old enumeration missed.
  let mut bad_rdata = header(1, 3);
  any_question(&mut bad_rdata, INSTANCE);
  tying_pair(&mut bad_rdata);
  record(&mut bad_rdata, 36, 120, &[0x00, 0x0A, 0xC0, 0x0C]);

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
      Verdict::Abandoned(Abandon::UncomparableRdata),
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

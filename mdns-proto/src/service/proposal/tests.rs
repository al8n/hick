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

/// A compression-eligible type this crate does not parse has no well-defined
/// comparison bytes: a raw copy of a compressed name depends on where in the
/// packet it sat.
#[test]
fn an_unparsed_compressible_type_has_no_tiebreak_bytes() {
  let view = Rdata::Other(&[0xC0, 0x0C]);
  let mut scratch = std::vec::Vec::new();
  for raw in [2u16, 6, 15, 39] {
    assert!(
      rdata_for_tiebreak(
        crate::wire::ResourceType::from_u16(raw),
        &view,
        &mut scratch
      )
      .is_err(),
      "type {raw} may arrive compressed, so it must not yield comparison bytes"
    );
  }
  // …while a genuinely unknown type is opaque per RFC 3597 §4 and comparable.
  assert!(
    rdata_for_tiebreak(
      crate::wire::ResourceType::from_u16(64000),
      &view,
      &mut scratch
    )
    .is_ok(),
    "RFC 3597 §4 forbids compression in unknown types, so their raw bytes are \
     position-independent"
  );
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

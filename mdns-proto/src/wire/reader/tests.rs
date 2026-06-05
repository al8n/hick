use super::*;

/// Build a 12-byte header with the given section counts.
fn header(qd: u16, an: u16, ns: u16, ar: u16) -> std::vec::Vec<u8> {
  let mut h = std::vec![0u8; HEADER_SIZE];
  h[4..6].copy_from_slice(&qd.to_be_bytes());
  h[6..8].copy_from_slice(&an.to_be_bytes());
  h[8..10].copy_from_slice(&ns.to_be_bytes());
  h[10..12].copy_from_slice(&ar.to_be_bytes());
  h
}

#[test]
fn malformed_question_surfaces_no_authority_or_additional() {
  // QDCOUNT=1 with a truncated question name, plus NSCOUNT=1 and
  // ARCOUNT=1. The question cannot be skipped, so the authority/additional
  // offsets are unknown — NO record may be surfaced from a misaligned cursor.
  let mut msg = header(1, 0, 1, 1);
  msg.push(0x05); // label length 5 with no following bytes => truncated name
  let reader = MessageReader::try_parse(&msg).unwrap();
  assert!(
    reader.authority().next().is_none(),
    "malformed question must surface no authority records"
  );
  assert!(
    reader.additional().next().is_none(),
    "malformed question must surface no additional records"
  );
}

#[test]
fn malformed_answer_surfaces_no_additional() {
  // a well-formed question but a malformed answer (ANCOUNT=1),
  // with ARCOUNT=1. The answer cannot be skipped, so additional iteration
  // must not surface records parsed from the misaligned offset — previously
  // `new_after_authority` ignored the answer-skip failure and walked from the
  // stale cursor.
  let mut msg = header(1, 1, 0, 1);
  // Valid question: root name (0x00) + QTYPE A (0x0001) + QCLASS IN (0x0001).
  msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
  // Malformed answer: label length 5 with no following bytes (truncated).
  msg.push(0x05);
  let reader = MessageReader::try_parse(&msg).unwrap();
  // The question itself is still well-formed and iterates.
  assert_eq!(
    reader
      .questions()
      .filter(core::result::Result::is_ok)
      .count(),
    1,
    "the well-formed question must still parse"
  );
  assert!(
    reader.additional().next().is_none(),
    "malformed answer must surface no additional records"
  );
}

#[test]
fn well_formed_additional_is_still_surfaced() {
  // Positive control: a message with a valid question + a valid additional A
  // record (ANCOUNT=0, NSCOUNT=0, ARCOUNT=1) must surface the additional.
  let mut msg = header(1, 0, 0, 1);
  // Question: root name + QTYPE A + QCLASS IN.
  msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
  // Additional A record: root name + TYPE A + CLASS IN + TTL + RDLEN 4 + addr.
  msg.extend_from_slice(&[0x00]); // owner name = root
  msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
  msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
  msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
  msg.extend_from_slice(&[192, 168, 1, 10]); // rdata
  let reader = MessageReader::try_parse(&msg).unwrap();
  let mut it = reader.additional();
  let first = it
    .next()
    .expect("a valid additional record must be surfaced");
  assert!(first.is_ok(), "the additional record must parse");
  assert!(it.next().is_none(), "exactly one additional record");
}

#[test]
fn questions_iterator_yields_error_then_stops_on_truncated_question() {
  // QDCOUNT=1 with a truncated question name (label length 5, no payload).
  let mut msg = header(1, 0, 0, 0);
  msg.push(0x05);
  let reader = MessageReader::try_parse(&msg).unwrap();
  let mut questions = reader.questions();
  assert!(
    matches!(questions.next(), Some(Err(_))),
    "a truncated question must surface a parse error"
  );
  // After the error the iterator latches done and yields nothing further.
  assert!(questions.next().is_none());
}

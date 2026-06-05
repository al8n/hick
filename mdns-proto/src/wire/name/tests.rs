use super::{NameRef, ParseError};

fn build_with_labels(labels: &[&[u8]]) -> std::vec::Vec<u8> {
  use std::vec::Vec;
  let mut v = Vec::new();
  for l in labels {
    v.push(l.len() as u8);
    v.extend_from_slice(l);
  }
  v.push(0);
  v
}

#[test]
fn parses_simple_name() {
  let buf = build_with_labels(&[b"foo", b"local"]);
  let (n, consumed) = NameRef::try_parse(&buf, 0).unwrap();
  assert_eq!(consumed, buf.len());
  let labels: std::vec::Vec<&[u8]> = n.labels().map(|r| r.unwrap()).collect();
  assert_eq!(labels, std::vec![b"foo".as_slice(), b"local".as_slice()]);
}

#[test]
fn rejects_label_over_63() {
  let buf = [64u8]; // length byte = 64 > 63
  let err = NameRef::try_parse(&buf, 0).unwrap_err();
  assert!(matches!(
    err,
    ParseError::InvalidLabelKind(_) | ParseError::LabelTooLong(_)
  ));
}

#[test]
fn labels_iteration_rejects_over_long_expanded_name() {
  // 128 one-byte labels = 257 expanded wire octets (each label is
  // 2 octets: a length byte + 1 payload byte, plus the root). Under the old
  // payload-only tally this summed to 128 and passed, but the EXPANDED wire
  // form exceeds the RFC 1035 §3.1 255-octet cap. try_parse is lazy (no total
  // cap), so the NameRef builds — but iterating labels() (as service
  // canonicalization does) MUST yield NameTooLong so an over-long peer name
  // cannot influence tiebreak / conflict handling.
  let labels: std::vec::Vec<&[u8]> = std::vec![b"a".as_slice(); 128];
  let buf = build_with_labels(&labels);
  assert_eq!(buf.len(), 257);
  let (n, _) = NameRef::try_parse(&buf, 0).unwrap();
  let mut saw_too_long = false;
  for r in n.labels() {
    if let Err(ParseError::NameTooLong(_)) = r {
      saw_too_long = true;
      break;
    }
  }
  assert!(
    saw_too_long,
    "labels() must reject a name whose expanded wire form exceeds 255 octets"
  );

  // A name at the boundary (wire form exactly 255 octets) iterates cleanly.
  // 126 one-byte labels + root = 126*2 + 1 = 253; add one 1-byte label = 255.
  let ok_labels: std::vec::Vec<&[u8]> = std::vec![b"a".as_slice(); 127];
  let ok_buf = build_with_labels(&ok_labels); // 127*2 + 1 = 255 octets
  assert_eq!(ok_buf.len(), 255);
  let (n2, _) = NameRef::try_parse(&ok_buf, 0).unwrap();
  assert!(
    n2.labels().all(|r| r.is_ok()),
    "a name whose expanded wire form is exactly 255 octets must iterate cleanly"
  );
}

#[test]
fn rejects_forward_pointer() {
  // Pointer at offset 0 -> target offset 0 (== current cursor): forward.
  let buf = [0xC0u8, 0x00, 0];
  let (n, _) = NameRef::try_parse(&buf, 0).unwrap();
  let first = n.labels().next().unwrap();
  assert!(matches!(first, Err(ParseError::PointerForward(_))));
}

#[test]
fn pointer_resolves_backwards() {
  // Layout:
  //   offset 0: "ab\0"   (3 bytes: 0x02 'a' 'b' 0x00, total 4)
  //   offset 4: pointer to 0
  let mut buf = std::vec::Vec::new();
  buf.push(2u8);
  buf.extend_from_slice(b"ab");
  buf.push(0);
  buf.push(0xC0);
  buf.push(0x00);
  let (n, _) = NameRef::try_parse(&buf, 4).unwrap();
  let labels: std::vec::Vec<&[u8]> = n.labels().map(|r| r.unwrap()).collect();
  assert_eq!(labels, std::vec![b"ab".as_slice()]);
}

#[test]
fn equality_ignoring_case() {
  let buf1 = build_with_labels(&[b"Foo", b"Local"]);
  let buf2 = build_with_labels(&[b"foo", b"LOCAL"]);
  let n1 = NameRef::try_parse(&buf1, 0).unwrap().0;
  let n2 = NameRef::try_parse(&buf2, 0).unwrap().0;
  assert!(n1.equals_ignoring_case(&n2));
}

#[test]
fn try_parse_rejects_truncated_pointer() {
  // A pointer tag byte with no second offset byte following.
  assert!(matches!(
    NameRef::try_parse(&[0xC0u8], 0),
    Err(ParseError::BufferTooShort(_))
  ));
}

#[test]
fn try_parse_rejects_truncated_label() {
  // Length octet declares 3 payload bytes but only 1 follows.
  assert!(matches!(
    NameRef::try_parse(&[3u8, b'a'], 0),
    Err(ParseError::BufferTooShort(_))
  ));
}

#[test]
fn equals_ignoring_case_detects_every_kind_of_difference() {
  let base_buf = build_with_labels(&[b"foo", b"local"]);
  let base = NameRef::try_parse(&base_buf, 0).unwrap().0;

  // Different label length.
  let longer = build_with_labels(&[b"fooo", b"local"]);
  assert!(!base.equals_ignoring_case(&NameRef::try_parse(&longer, 0).unwrap().0));
  // Same length, different bytes.
  let other = build_with_labels(&[b"bar", b"local"]);
  assert!(!base.equals_ignoring_case(&NameRef::try_parse(&other, 0).unwrap().0));
  // Different label count.
  let shorter = build_with_labels(&[b"foo"]);
  assert!(!base.equals_ignoring_case(&NameRef::try_parse(&shorter, 0).unwrap().0));
}

#[test]
fn labels_reject_invalid_kind_via_backward_pointer() {
  // offset 0: 0x80 (invalid label-kind byte); offset 1: root; offset 2..4:
  // backward pointer -> 0. Parsing at offset 2 builds a NameRef whose labels()
  // resolves the pointer to the bad 0x80 byte.
  let buf = [0x80u8, 0x00, 0xC0, 0x00];
  let (n, _) = NameRef::try_parse(&buf, 2).unwrap();
  assert!(matches!(
    n.labels().next(),
    Some(Err(ParseError::InvalidLabelKind(0x80)))
  ));
}

#[test]
fn labels_reject_truncated_label_via_backward_pointer() {
  // offset 0: length octet 5 with no payload; offset 1..3: backward ptr -> 0.
  let buf = [5u8, 0xC0, 0x00];
  let (n, _) = NameRef::try_parse(&buf, 1).unwrap();
  assert!(matches!(
    n.labels().next(),
    Some(Err(ParseError::BufferTooShort(_)))
  ));
}

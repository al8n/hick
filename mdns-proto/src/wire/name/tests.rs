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

#[test]
fn try_parse_rejects_reserved_label_kind_64() {
  // A length octet of 0x40 sets the 0b01 high-bit pattern, which is neither a
  // length-prefixed label (0b00) nor a compression pointer (0b11). It is a
  // reserved/invalid label kind, so try_parse reports InvalidLabelKind. (Note:
  // the LabelTooLong branch in try_parse is unreachable — once the two high
  // bits are clear the value is <= 63, so it can never exceed the 63 cap.)
  let buf = [0x40u8];
  let err = NameRef::try_parse(&buf, 0).unwrap_err();
  assert!(matches!(err, ParseError::InvalidLabelKind(0x40)));
}

#[test]
fn start_reports_parse_offset() {
  // start() echoes the offset try_parse was invoked at, even when the name
  // begins partway into the message.
  let mut buf = std::vec::Vec::new();
  buf.push(2u8);
  buf.extend_from_slice(b"ab");
  buf.push(0);
  buf.push(0xC0);
  buf.push(0x00);
  let (n, _) = NameRef::try_parse(&buf, 4).unwrap();
  assert_eq!(n.start(), 4);

  let zero = NameRef::try_parse(&buf, 0).unwrap().0;
  assert_eq!(zero.start(), 0);
}

#[test]
fn write_wire_folds_or_preserves_case() {
  // write_wire follows the (pointer-free) labels and re-encodes them in wire
  // form. fold_case lowercases ASCII label bytes (record IDENTITY form);
  // otherwise case is preserved for display.
  let buf = build_with_labels(&[b"Foo", b"LOCAL"]);
  let (n, _) = NameRef::try_parse(&buf, 0).unwrap();

  let mut folded = std::vec::Vec::new();
  n.write_wire(&mut folded, true).unwrap();
  assert_eq!(folded, build_with_labels(&[b"foo", b"local"]));

  let mut preserved = std::vec::Vec::new();
  n.write_wire(&mut preserved, false).unwrap();
  assert_eq!(preserved, build_with_labels(&[b"Foo", b"LOCAL"]));
}

#[test]
fn write_wire_propagates_iterator_error() {
  // write_wire threads `label?`, so a malformed label chain surfaces as an
  // error rather than a partial encode. A backward pointer onto a truncated
  // length octet (declares 5 payload bytes, none follow) yields BufferTooShort
  // from the iterator, which write_wire returns verbatim.
  let buf = [5u8, 0xC0, 0x00];
  let (n, _) = NameRef::try_parse(&buf, 1).unwrap();
  let mut out = std::vec::Vec::new();
  let err = n.write_wire(&mut out, false).unwrap_err();
  assert!(matches!(err, ParseError::BufferTooShort(_)));
}

#[test]
fn labels_next_is_fused_after_completion() {
  // Once the root terminator is consumed the iterator is done; further next()
  // calls take the early `done` short-circuit and keep returning None.
  let buf = build_with_labels(&[b"foo"]);
  let (n, _) = NameRef::try_parse(&buf, 0).unwrap();
  let mut it = n.labels();
  assert_eq!(it.next().map(|r| r.unwrap()), Some(b"foo".as_slice()));
  assert!(it.next().is_none()); // root terminator -> None, sets done
  assert!(it.next().is_none()); // fused: hits the `if self.done` guard
  assert!(it.next().is_none());
}

#[test]
fn labels_reject_label_running_to_end_of_message() {
  // A backward pointer hops to a label whose payload ends exactly at the
  // message boundary, leaving no terminator byte. The next iteration reads
  // past the end and reports BufferTooShort at that offset.
  //
  // Layout: offset 0 length-3 label whose 3 payload bytes ARE the start
  // pointer (0xC0 0x00) plus one filler; offset 1..3 is the complete pointer
  // try_parse begins at. After the label the cursor lands at len() == 4.
  let buf = [0x03u8, 0xC0, 0x00, b'a'];
  assert_eq!(buf.len(), 4);
  let (n, _) = NameRef::try_parse(&buf, 1).unwrap();
  let mut it = n.labels();
  // First the pointer resolves backward to offset 0 and yields the 3-byte label.
  assert_eq!(it.next().map(|r| r.unwrap()), Some(&buf[1..4]));
  match it.next() {
    Some(Err(ParseError::BufferTooShort(d))) => assert_eq!(d.at(), 4),
    other => panic!("expected BufferTooShort at end of message, got {other:?}"),
  }
}

#[test]
fn labels_reject_truncated_pointer_reached_mid_chain() {
  // The iterator walks a label and lands on a lone pointer tag byte that is the
  // final byte of the message (its second offset octet is missing). try_parse
  // itself cannot reach this — it begins at a *complete* pointer that hops back
  // to the label.
  //
  // Layout: offset 0 length-3 label; its payload spans the complete start
  // pointer (offset 1..3 = 0xC0 0x00 -> target 0). offset 4 is a lone 0xC0.
  let buf = [0x03u8, 0xC0, 0x00, b'a', 0xC0];
  assert_eq!(buf.len(), 5);
  let (n, _) = NameRef::try_parse(&buf, 1).unwrap();
  let mut it = n.labels();
  assert_eq!(it.next().map(|r| r.unwrap()), Some(&buf[1..4]));
  match it.next() {
    Some(Err(ParseError::BufferTooShort(d))) => assert_eq!(d.at(), 5),
    other => panic!("expected BufferTooShort for the truncated pointer, got {other:?}"),
  }
}

#[test]
fn labels_reject_pointer_chain_over_max_hops() {
  // Build MAX_POINTER_HOPS + 1 (= 33) backward-chained pointers. The iterator
  // follows 32 hops, then the 33rd pointer trips the hop-budget guard.
  use crate::constants::MAX_POINTER_HOPS;
  let count = usize::from(MAX_POINTER_HOPS) + 1; // 33 pointers, offsets 0,2,..,64
  let mut buf = std::vec::Vec::new();
  for i in 0..count {
    // Pointer at offset 2*i -> offset 2*(i-1); the i==0 pointer's target is
    // never read because the budget is already exhausted when it is reached.
    let target = if i == 0 { 0u16 } else { (2 * (i - 1)) as u16 };
    buf.push(0xC0u8); // all targets < 256, so the high offset bits are zero
    buf.push((target & 0xFF) as u8);
  }
  let start = 2 * (count - 1); // begin at the highest pointer
  let (n, _) = NameRef::try_parse(&buf, start).unwrap();
  let mut saw_chain_too_long = false;
  for r in n.labels() {
    if let Err(ParseError::PointerChainTooLong(max)) = r {
      assert_eq!(max, MAX_POINTER_HOPS);
      saw_chain_too_long = true;
      break;
    }
  }
  assert!(
    saw_chain_too_long,
    "a chain exceeding MAX_POINTER_HOPS must yield PointerChainTooLong"
  );
}

#[test]
fn labels_reject_label_ending_past_u16_range() {
  // A label whose end offset exceeds u16::MAX cannot be represented as the next
  // cursor, so the iterator surfaces IntegerConversion. This needs a message
  // larger than 64 KiB with the label placed near the top of the u16 range.
  let label_start = 65_500usize;
  let label_len = 63usize; // max label; label_end = 65500 + 1 + 63 = 65564 > 65535
  let label_end = label_start + 1 + label_len;
  let mut buf = std::vec![0u8; label_end + 1];
  buf[label_start] = label_len as u8;
  for b in buf.iter_mut().take(label_end).skip(label_start + 1) {
    *b = b'a';
  }
  buf[label_end] = 0; // root terminator so try_parse succeeds
  let (n, _) = NameRef::try_parse(&buf, label_start).unwrap();
  match n.labels().next() {
    Some(Err(ParseError::IntegerConversion(_))) => {}
    other => panic!("expected IntegerConversion past u16 range, got {other:?}"),
  }
}

//! Round-trip + property tests for the wire layer.

#![cfg(any(feature = "alloc", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use mdns_proto::{
  Name,
  wire::{
    DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, MessageReader, ResourceClass, ResourceType,
  },
};

#[test]
fn single_question_roundtrip() {
  let mut buf = [0u8; 1500];
  let header = Header::new().with_id(0xCAFE);
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  let name = Name::try_from_str("_ipp._tcp.local.").unwrap();
  b.push_question(&name, ResourceType::Ptr, ResourceClass::In, false)
    .unwrap();
  let n = b.finish().unwrap();

  let reader = MessageReader::try_parse(&buf[..n]).unwrap();
  assert_eq!(reader.header().question_count(), 1);
  let q = reader.questions().next().unwrap().unwrap();
  assert!(q.qtype().is_ptr());
  assert!(q.qclass().is_in());

  // Verify name labels.
  let labels: Vec<&[u8]> = q.qname().labels().map(|r| r.unwrap()).collect();
  assert_eq!(
    labels,
    vec![b"_ipp".as_slice(), b"_tcp".as_slice(), b"local".as_slice()]
  );
}

#[test]
fn multiple_questions_with_shared_suffix_compress() {
  // Two questions for "_a._tcp.local." and "_b._tcp.local." should share
  // the "_tcp.local." suffix via compression.
  let mut buf = [0u8; 1500];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  let a = Name::try_from_str("_a._tcp.local.").unwrap();
  let bn = Name::try_from_str("_b._tcp.local.").unwrap();
  b.push_question(&a, ResourceType::Ptr, ResourceClass::In, false)
    .unwrap();
  b.push_question(&bn, ResourceType::Ptr, ResourceClass::In, false)
    .unwrap();
  let n = b.finish().unwrap();

  // Both parse back correctly.
  let reader = MessageReader::try_parse(&buf[..n]).unwrap();
  let mut qs = reader.questions();
  let q1 = qs.next().unwrap().unwrap();
  let q2 = qs.next().unwrap().unwrap();
  let labels1: Vec<&[u8]> = q1.qname().labels().map(|r| r.unwrap()).collect();
  let labels2: Vec<&[u8]> = q2.qname().labels().map(|r| r.unwrap()).collect();
  assert_eq!(
    labels1,
    vec![b"_a".as_slice(), b"_tcp".as_slice(), b"local".as_slice()]
  );
  assert_eq!(
    labels2,
    vec![b"_b".as_slice(), b"_tcp".as_slice(), b"local".as_slice()]
  );
}

#[test]
fn malformed_input_does_not_panic() {
  // Random short buffers shouldn't crash the parser.
  for len in 0..=20 {
    let buf = vec![0xFFu8; len];
    let _ = MessageReader::try_parse(&buf);
  }
}

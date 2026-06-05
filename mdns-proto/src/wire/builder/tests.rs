use super::{DEFAULT_COMPRESSION_TABLE, MessageBuilder};
use crate::{
  Name,
  wire::{Header, MessageReader, ResourceClass, ResourceType},
};

#[test]
fn builds_minimal_query() {
  let mut buf = [0u8; 512];
  let name = Name::try_from_str("foo.local.").unwrap();
  let header = Header::new().with_id(0x1234);
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_question(&name, ResourceType::A, ResourceClass::In, false)
    .unwrap();
  let n = b.finish().unwrap();
  let msg = buf.get(..n).unwrap();

  let reader = MessageReader::try_parse(msg).unwrap();
  assert_eq!(reader.header().id(), 0x1234);
  assert_eq!(reader.header().question_count(), 1);
  let q = reader.questions().next().unwrap().unwrap();
  assert!(q.qtype().is_a());
  assert!(q.qclass().is_in());
}

#[test]
fn builds_ptr_txt_authority_and_nsec_additional() {
  let mut buf = [0u8; 512];
  let stype = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("Dev._http._tcp.local.").unwrap();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();

  b.push_ptr_authority(&stype, 120, &inst).unwrap();
  b.push_txt_authority(&inst, 120, [b"path=/".as_slice()])
    .unwrap();
  // A(1) + SRV(33) present; the 300 entry exercises the type >= 256 skip; the
  // cache-flush bit is set on the class field.
  b.push_nsec_additional(&inst, 120, &[1, 33, 300], true)
    .unwrap();

  let n = b.finish().unwrap();
  let reader = MessageReader::try_parse(buf.get(..n).unwrap()).unwrap();
  assert_eq!(reader.header().authority_count(), 2); // PTR + TXT
  assert_eq!(reader.header().additional_count(), 1); // NSEC
}

#[test]
fn push_txt_authority_rejects_oversized_segment() {
  let mut buf = [0u8; 512];
  let name = Name::try_from_str("x.local.").unwrap();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  // A single TXT segment longer than 255 bytes cannot be length-prefixed.
  let big = [b'a'; 256];
  assert!(b.push_txt_authority(&name, 120, [big.as_slice()]).is_err());
}

#[test]
fn push_txt_authority_empty_writes_single_zero_segment() {
  // RFC 6763 §6.1: no segments -> the "no information" single zero-length
  // string, not empty rdata.
  let mut buf = [0u8; 512];
  let name = Name::try_from_str("x.local.").unwrap();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  let empty: [&[u8]; 0] = [];
  b.push_txt_authority(&name, 120, empty).unwrap();
  let n = b.finish().unwrap();
  let reader = MessageReader::try_parse(buf.get(..n).unwrap()).unwrap();
  assert_eq!(reader.header().authority_count(), 1);
}

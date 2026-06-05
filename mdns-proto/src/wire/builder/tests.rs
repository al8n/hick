use super::{CompressionTable, DEFAULT_COMPRESSION_TABLE, MessageBuilder};
use crate::{
  Name,
  error::EncodeError,
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

#[test]
fn compression_table_default_equals_new() {
  // `Default::default()` must delegate to `new()` and yield an empty table
  // whose `lookup` finds nothing.
  let from_default: CompressionTable<DEFAULT_COMPRESSION_TABLE> = CompressionTable::default();
  assert_eq!(from_default.lookup(0), None);
  assert_eq!(from_default.lookup(0xdead_beef), None);
  // An inserted-then-looked-up entry confirms the defaulted table is usable,
  // not merely constructed.
  let mut t: CompressionTable<4> = CompressionTable::default();
  assert_eq!(t.lookup(42), None);
  t.insert(42, 12);
  assert_eq!(t.lookup(42), Some(12));
}

#[test]
fn write_name_without_trailing_dot_canonicalizes_like_dotted() {
  // `write_name` takes the `None => s` arm of `strip_suffix('.')` for a name
  // with no trailing dot; the encoded bytes must match the dotted form, since
  // a presentation trailing dot is not part of the wire encoding.
  let dotted = Name::try_from_str("foo.local.").unwrap();
  let bare = Name::try_from_str("foo.local").unwrap();
  assert_eq!(bare.as_str(), "foo.local"); // the no-dot arm is what we exercise

  let mut buf_dotted = [0u8; 64];
  let mut bd: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf_dotted, Header::new()).unwrap();
  bd.push_question(&dotted, ResourceType::A, ResourceClass::In, false)
    .unwrap();
  let nd = bd.finish().unwrap();

  let mut buf_bare = [0u8; 64];
  let mut bb: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf_bare, Header::new()).unwrap();
  bb.push_question(&bare, ResourceType::A, ResourceClass::In, false)
    .unwrap();
  let nb = bb.finish().unwrap();

  assert_eq!(buf_dotted.get(..nd), buf_bare.get(..nb));

  // And it still round-trips through the reader as a single question.
  let reader = MessageReader::try_parse(buf_bare.get(..nb).unwrap()).unwrap();
  assert_eq!(reader.header().question_count(), 1);
  let q = reader.questions().next().unwrap().unwrap();
  assert!(q.qtype().is_a());
}

#[test]
fn write_name_empty_emits_root_label() {
  // An empty `Name` (`""` is accepted by `validate_name`) drives the
  // `s.is_empty()` arm of `write_name`, which writes a single 0x00 root label.
  // Use it as a PTR target so the emitted root label lands in the rdata.
  let empty = Name::try_from_str("").unwrap();
  assert!(empty.as_str().is_empty());
  let owner = Name::try_from_str("_svc._tcp.local.").unwrap();

  let mut buf = [0u8; 128];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  b.push_ptr_answer(&owner, 120, &empty).unwrap();
  let n = b.finish().unwrap();

  let reader = MessageReader::try_parse(buf.get(..n).unwrap()).unwrap();
  assert_eq!(reader.header().answer_count(), 1);
  let rec = reader.answers().next().unwrap().unwrap();
  assert!(rec.rtype().is_ptr());
  // The PTR rdata is exactly the one-byte root label produced for the empty
  // target name.
  assert_eq!(rec.rdata(), &[0u8]);
}

#[test]
fn push_nsec_additional_without_cache_flush_sets_bitmap() {
  // Exercises the `cache_flush == false` arm (class field has no flush bit) and
  // the bitmap-emission path (a present type < 256 sets `max_byte`, so the
  // window block + bitmap bytes are written).
  let name = Name::try_from_str("host.local.").unwrap();
  let mut buf = [0u8; 256];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  // A=1 and AAAA=28 are present; 256 is skipped (>= 256, out of window 0).
  b.push_nsec_additional(&name, 120, &[1, 28, 256], false)
    .unwrap();
  let n = b.finish().unwrap();

  let reader = MessageReader::try_parse(buf.get(..n).unwrap()).unwrap();
  assert_eq!(reader.header().additional_count(), 1);
  let rec = reader.additional().next().unwrap().unwrap();
  assert!(rec.rtype().is_nsec());
  assert!(rec.rclass().is_in());
  // cache_flush == false must NOT set the flush bit on the parsed class.
  assert!(!rec.cache_flush());
  // rdata = owner name (root label here, "host.local." compressed to a pointer
  // back to the record owner) + window(0) + bitmap-len + bitmap bytes. AAAA=28
  // lives in byte 3 (28/8), so the bitmap length is 4 bytes; the rdata must be
  // longer than a bare name and the window/length header must be present.
  let rdata = rec.rdata();
  assert!(
    rdata.len() >= 2 + 4,
    "rdata too short for window+bitmap: {rdata:?}"
  );
}

#[test]
fn push_a_answer_into_undersized_buffer_errors() {
  // A buffer with room for only the 12-byte header cannot hold any record;
  // `write_name` (its first `write_byte`) overruns and surfaces
  // `EncodeError::BufferTooSmall`.
  let name = Name::try_from_str("a.local.").unwrap();
  let mut buf = [0u8; 12];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  let err = b
    .push_a_answer(&name, 120, core::net::Ipv4Addr::LOCALHOST, true)
    .unwrap_err();
  assert!(matches!(err, EncodeError::BufferTooSmall(_)));
  assert!(err.is_buffer_too_small());
}

#[test]
fn push_srv_answer_truncated_rdata_errors() {
  // Enough room for the name + type/class/ttl + rdlen placeholder, but not for
  // the SRV rdata body (priority/weight/port + target). The `write_u16` for the
  // priority overruns -> `BufferTooSmall`.
  let name = Name::try_from_str("s.local.").unwrap();
  let target = Name::try_from_str("t.local.").unwrap();
  // name "s.local." = 1+1 + 5+1 + 1 = 9 bytes; +2 type +2 class +4 ttl +2 rdlen
  // = 19 bytes used before the rdata body. Size the buffer to header + 19 so the
  // first rdata write fails.
  let mut buf = [0u8; 12 + 19];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  let err = b
    .push_srv_answer(&name, 120, 0, 0, 8080, &target, true)
    .unwrap_err();
  assert!(err.is_buffer_too_small());
}

#[test]
fn push_nsec_additional_into_undersized_buffer_errors() {
  // The NSEC writer must surface `BufferTooSmall` when the buffer cannot hold
  // the full record (here it overruns while writing the owner name).
  let name = Name::try_from_str("host.local.").unwrap();
  let mut buf = [0u8; 12];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  let err = b.push_nsec_additional(&name, 120, &[1], true).unwrap_err();
  assert!(err.is_buffer_too_small());
}

#[test]
fn finish_propagates_record_buffer_error_late() {
  // After a record fails to fit, `finish` still writes the header into the
  // reserved 12-byte slot and reports the bytes written so far; the record
  // error is what the caller observes from the failed `push_*`.
  let name = Name::try_from_str("a.local.").unwrap();
  let mut buf = [0u8; 14]; // header + 2 bytes: name's first label won't fit
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  assert!(
    b.push_a_answer(&name, 120, core::net::Ipv4Addr::LOCALHOST, false)
      .is_err()
  );
  // The header slot is still finishable.
  let n = b.finish().unwrap();
  assert_eq!(n, 14); // cursor advanced into the 2 spare bytes before failing
}

//! Clean-room mDNS / DNS-SD wire-conformance vectors, derived from RFC 6762 and
//! RFC 6763.
//!
//! The SCENARIOS covered here mirror the areas exercised by Avahi's
//! `avahi-core` test suite (DNS pack/unpack, domain names, TXT string-lists,
//! UTF-8) — but Avahi is LGPL and NONE of its code is used: every vector below
//! is constructed from the RFC text, with that test list serving only as a
//! "what to cover" checklist. Complements `golden_parity.rs` (real captured
//! reference bytes) and `wire_roundtrip.rs`.

#![cfg(any(feature = "alloc", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::net::{Ipv4Addr, Ipv6Addr};
use std::{vec, vec::Vec};

use mdns_proto::{
  Name,
  wire::{
    DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, MessageReader, NameRef, Rdata, ResourceType,
  },
};

/// Build a message by pushing records via `push`, finalize it, and return the
/// encoded bytes.
fn encode(push: impl FnOnce(&mut MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE>)) -> Vec<u8> {
  let mut buf = [0u8; 4096];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).expect("builder");
  push(&mut b);
  let n = b.finish().expect("finish");
  buf[..n].to_vec()
}

/// Render a name as a lowercase dotted string.
fn dotted(n: &NameRef<'_>) -> String {
  let mut parts = Vec::new();
  for label in n.labels() {
    let label = label.expect("label parses");
    if label.is_empty() {
      break;
    }
    parts.push(String::from_utf8_lossy(label).to_ascii_lowercase());
  }
  parts.join(".")
}

/// Collect a TXT record's raw segments from a single-answer message.
fn txt_segments(msg: &[u8]) -> Vec<Vec<u8>> {
  let r = MessageReader::try_parse(msg).expect("parse");
  let rec = r.answers().next().expect("answer").expect("record");
  match rec.rdata_view().expect("rdata") {
    Rdata::Txt(t) => t.segments().map(|s| s.expect("segment").to_vec()).collect(),
    other => panic!("expected TXT, got {other:?}"),
  }
}

// ─────────────────────────── per-record round-trips ───────────────────────────
// The dns-test.c analog: every record type must survive build -> parse intact.

#[test]
fn a_record_roundtrips() {
  let name = Name::try_from_str("host.local.").unwrap();
  let msg = encode(|b| {
    b.push_a_answer(&name, 120, Ipv4Addr::new(192, 0, 2, 7), true)
      .unwrap()
  });
  let r = MessageReader::try_parse(&msg).unwrap();
  let rec = r.answers().next().unwrap().unwrap();
  assert_eq!(dotted(rec.name()), "host.local");
  assert_eq!(rec.ttl(), 120);
  assert!(rec.cache_flush(), "A set cache_flush=true");
  let Rdata::A(a) = rec.rdata_view().unwrap() else {
    panic!("expected A")
  };
  assert_eq!(a.addr(), Ipv4Addr::new(192, 0, 2, 7));
}

#[test]
fn aaaa_record_roundtrips() {
  let name = Name::try_from_str("host.local.").unwrap();
  let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
  let msg = encode(|b| b.push_aaaa_answer(&name, 120, addr, true).unwrap());
  let r = MessageReader::try_parse(&msg).unwrap();
  let rec = r.answers().next().unwrap().unwrap();
  let Rdata::AAAA(a) = rec.rdata_view().unwrap() else {
    panic!("expected AAAA")
  };
  assert_eq!(a.addr(), addr);
}

#[test]
fn srv_record_roundtrips() {
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let target = Name::try_from_str("host.local.").unwrap();
  let msg = encode(|b| {
    b.push_srv_answer(&name, 120, 0, 0, 8080, &target, true)
      .unwrap()
  });
  let r = MessageReader::try_parse(&msg).unwrap();
  let rec = r.answers().next().unwrap().unwrap();
  let Rdata::Srv(s) = rec.rdata_view().unwrap() else {
    panic!("expected SRV")
  };
  assert_eq!(s.priority(), 0);
  assert_eq!(s.weight(), 0);
  assert_eq!(s.port(), 8080);
  assert_eq!(dotted(s.target()), "host.local");
}

#[test]
fn ptr_record_roundtrips() {
  let name = Name::try_from_str("_http._tcp.local.").unwrap();
  let target = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let msg = encode(|b| b.push_ptr_answer(&name, 4500, &target).unwrap());
  let r = MessageReader::try_parse(&msg).unwrap();
  let rec = r.answers().next().unwrap().unwrap();
  assert!(!rec.cache_flush(), "PTR is shared — no cache-flush bit");
  let Rdata::Ptr(p) = rec.rdata_view().unwrap() else {
    panic!("expected PTR")
  };
  assert_eq!(dotted(p.target()), "inst._http._tcp.local");
}

#[test]
fn txt_record_roundtrips() {
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let segs: [&[u8]; 2] = [b"path=/", b"txtvers=1"];
  let msg = encode(|b| b.push_txt_answer(&name, 4500, segs, true).unwrap());
  assert_eq!(
    txt_segments(&msg),
    vec![b"path=/".to_vec(), b"txtvers=1".to_vec()]
  );
}

#[test]
fn nsec_record_roundtrips() {
  // RFC 6762 §6.1 NSEC asserting the unique types A(1), TXT(16), AAAA(28),
  // SRV(33) exist while everything else does not.
  let name = Name::try_from_str("host.local.").unwrap();
  let msg = encode(|b| {
    b.push_nsec_additional(&name, 120, &[1, 16, 28, 33], true)
      .unwrap()
  });
  let r = MessageReader::try_parse(&msg).unwrap();
  let rec = r.additional().next().unwrap().unwrap();
  assert_eq!(rec.rtype(), ResourceType::Nsec);
  assert!(
    matches!(rec.rdata_view().unwrap(), Rdata::Nsec(_)),
    "NSEC rdata must decode"
  );
}

// ─────────────────────────── TXT conformance (RFC 6763 §6) ──────────────────────────

#[test]
fn txt_empty_encodes_as_single_zero_length_string() {
  // §6.1: the "no information" TXT is ONE zero-length string (a single 0x00),
  // NOT an empty (RDLENGTH 0) record.
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let msg = encode(|b| {
    b.push_txt_answer(&name, 120, core::iter::empty::<&[u8]>(), true)
      .unwrap()
  });
  let r = MessageReader::try_parse(&msg).unwrap();
  let rec = r.answers().next().unwrap().unwrap();
  assert_eq!(
    rec.rdata(),
    &[0u8],
    "empty TXT rdata must be a single 0x00 length byte"
  );
  assert_eq!(
    txt_segments(&msg),
    vec![Vec::<u8>::new()],
    "exactly one empty segment"
  );
}

#[test]
fn txt_boolean_key_has_no_equals() {
  // §6.4: a key with no value is a length-prefixed string with no '='.
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let msg = encode(|b| {
    b.push_txt_answer(&name, 120, [b"passreq".as_slice()], true)
      .unwrap()
  });
  assert_eq!(txt_segments(&msg), vec![b"passreq".to_vec()]);
}

#[test]
fn txt_empty_value_keeps_trailing_equals() {
  // §6.4: "key=" (empty value) is distinct from "key" (boolean) — the '=' is
  // preserved verbatim.
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let msg = encode(|b| {
    b.push_txt_answer(&name, 120, [b"key=".as_slice()], true)
      .unwrap()
  });
  assert_eq!(txt_segments(&msg), vec![b"key=".to_vec()]);
}

#[test]
fn txt_value_may_contain_equals() {
  // §6.4: only the FIRST '=' separates key from value; later '=' are data.
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let msg = encode(|b| {
    b.push_txt_answer(&name, 120, [b"k=a=b=c".as_slice()], true)
      .unwrap()
  });
  assert_eq!(txt_segments(&msg), vec![b"k=a=b=c".to_vec()]);
}

#[test]
fn txt_value_is_opaque_binary() {
  // §6.5: values are opaque binary, not text — NUL and high bytes survive.
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let raw: &[u8] = &[b'k', b'=', 0x00, 0xFF, 0x01, 0x80];
  let msg = encode(|b| b.push_txt_answer(&name, 120, [raw], true).unwrap());
  assert_eq!(txt_segments(&msg), vec![raw.to_vec()]);
}

#[test]
fn txt_segment_at_255_bytes_roundtrips() {
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let seg = [b'a'; 255];
  let msg = encode(|b| {
    b.push_txt_answer(&name, 120, [seg.as_slice()], true)
      .unwrap()
  });
  assert_eq!(txt_segments(&msg), vec![seg.to_vec()]);
}

#[test]
fn txt_segment_over_255_bytes_is_rejected() {
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let big = [b'a'; 256];
  let mut buf = [0u8; 1024];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  assert!(
    b.push_txt_answer(&name, 120, [big.as_slice()], true)
      .is_err(),
    "a TXT string longer than 255 bytes cannot be length-prefixed"
  );
}

#[test]
fn txt_multiple_segments_preserve_order() {
  let name = Name::try_from_str("inst._http._tcp.local.").unwrap();
  let segs: [&[u8]; 3] = [b"first=1", b"second=2", b"third=3"];
  let msg = encode(|b| b.push_txt_answer(&name, 120, segs, true).unwrap());
  assert_eq!(
    txt_segments(&msg),
    vec![
      b"first=1".to_vec(),
      b"second=2".to_vec(),
      b"third=3".to_vec()
    ]
  );
}

// ─────────────────────────── names (RFC 6762 §16, RFC 6763 §4.1) ──────────────────────

#[test]
fn wire_names_match_case_insensitively() {
  // §16: name comparison is case-insensitive. A peer may send mixed case on the
  // wire (hick lowercases its own, but MUST still match an upper-case peer).
  // Hand-craft two raw names so the case difference survives onto the wire.
  let mut buf = Vec::new();
  buf.extend_from_slice(&[3, b'F', b'O', b'O', 5, b'L', b'o', b'C', b'a', b'L', 0]); // FOO.LocaL.
  let off_b = buf.len();
  buf.extend_from_slice(&[3, b'f', b'o', b'o', 5, b'l', b'o', b'c', b'a', b'l', 0]); // foo.local.
  let (a, _) = NameRef::try_parse(&buf, 0).unwrap();
  let (b, _) = NameRef::try_parse(&buf, off_b).unwrap();
  assert!(
    a.equals_ignoring_case(&b),
    "mixed-case wire names must compare equal"
  );
}

#[test]
fn utf8_instance_name_roundtrips() {
  // RFC 6763 §4.1: instance names are arbitrary UTF-8. A non-ASCII label must
  // survive build -> parse byte-for-byte (only ASCII is case-folded).
  let instance = Name::try_from_str("Café._http._tcp.local.").unwrap();
  let service = Name::try_from_str("_http._tcp.local.").unwrap();
  let msg = encode(|b| b.push_ptr_answer(&service, 4500, &instance).unwrap());
  let r = MessageReader::try_parse(&msg).unwrap();
  let rec = r.answers().next().unwrap().unwrap();
  let Rdata::Ptr(p) = rec.rdata_view().unwrap() else {
    panic!("expected PTR")
  };
  // First label is the UTF-8 instance label, lowercased on the ASCII parts only.
  let first = p.target().labels().next().unwrap().unwrap();
  assert_eq!(
    first,
    "café".as_bytes(),
    "UTF-8 instance label must round-trip (ASCII case-folded, 'é' preserved)"
  );
}

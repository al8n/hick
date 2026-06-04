//! Golden parity: assert `mdns-proto` parses real reference-implementation
//! announcements byte-for-byte.
//!
//! Fixtures are captured from the actual daemons (see
//! `hick-udp/tests/golden_capture.rs`) via a proxy registration with a
//! controlled host name + RFC 5737 TEST-NET address, so they carry no real
//! machine identity and serve as frozen, deterministic parse oracles. Unlike
//! the live-daemon interop tests, this runs in normal CI with no network.

#![cfg(any(feature = "alloc", feature = "std"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::net::Ipv4Addr;

use mdns_proto::wire::{MessageReader, NameRef, Rdata, ResourceType};

/// A real Apple Bonjour (mDNSResponder) DNS-SD announcement for
/// `GoldenInst._hickgold._tcp.local.` — host `goldenhost.local.` @ `192.0.2.1`,
/// port 8080, TXT `txtvers=1` / `path=/golden`. Carries the instance PTR, the
/// `_services._dns-sd._udp` enumeration PTR, SRV, TXT, A, and two NSEC records,
/// with name-compression pointers and cache-flush bits set.
const BONJOUR_ANNOUNCE: &[u8] = include_bytes!("fixtures/golden/bonjour_dnssd_announcement.bin");

/// Render a (possibly compression-pointer-following) name as a lowercase dotted
/// string, e.g. `goldeninst._hickgold._tcp.local`.
fn dotted(name: &NameRef<'_>) -> String {
  let mut parts = std::vec::Vec::new();
  for label in name.labels() {
    let label = label.expect("label parses");
    if label.is_empty() {
      break;
    }
    parts.push(String::from_utf8_lossy(label).to_ascii_lowercase());
  }
  parts.join(".")
}

#[test]
fn parses_real_bonjour_dnssd_announcement() {
  let reader =
    MessageReader::try_parse(BONJOUR_ANNOUNCE).expect("must parse a real Bonjour announcement");

  // Header: an authoritative response with 5 answers + 2 additional records.
  let h = reader.header();
  assert!(h.flags().is_response(), "announcement is a response");
  assert!(
    h.flags().is_authoritative(),
    "announcements are authoritative"
  );
  assert_eq!(h.answer_count(), 5, "answer count");
  assert_eq!(h.additional_count(), 2, "additional count");

  // EVERY record in the real packet must decode — no ParseError on any rdata,
  // including the NSEC records and the compression-pointer SRV/PTR targets.
  // This is the core parity assertion: hick parses 100% of Bonjour's output.
  let mut srv_port = None;
  let mut srv_target = None;
  let mut a_addr = None;
  let mut txt: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
  let mut instance_ptr_target = None;
  let mut service_enum_target = None;
  let mut saw_nsec = false;

  for rec in reader.answers().chain(reader.additional()) {
    let rec = rec.expect("each record must parse");
    match rec.rdata_view().expect("each rdata must decode") {
      Rdata::Srv(s) => {
        srv_port = Some(s.port());
        srv_target = Some(dotted(s.target()));
      }
      Rdata::A(a) => a_addr = Some(a.addr()),
      Rdata::Txt(t) => {
        for seg in t.segments() {
          txt.push(seg.expect("TXT segment parses").to_vec());
        }
      }
      Rdata::Ptr(p) => match dotted(rec.name()).as_str() {
        "_hickgold._tcp.local" => instance_ptr_target = Some(dotted(p.target())),
        "_services._dns-sd._udp.local" => service_enum_target = Some(dotted(p.target())),
        _ => {}
      },
      Rdata::Nsec(_) => saw_nsec = true,
      _ => {}
    }
  }

  assert_eq!(srv_port, Some(8080), "SRV port");
  assert_eq!(
    srv_target.as_deref(),
    Some("goldenhost.local"),
    "SRV target"
  );
  assert_eq!(a_addr, Some(Ipv4Addr::new(192, 0, 2, 1)), "A address");
  assert!(
    txt.iter().any(|s| s == b"txtvers=1"),
    "TXT must carry txtvers=1; got {txt:?}"
  );
  assert!(
    txt.iter().any(|s| s == b"path=/golden"),
    "TXT must carry path=/golden"
  );
  assert_eq!(
    instance_ptr_target.as_deref(),
    Some("goldeninst._hickgold._tcp.local"),
    "instance PTR target (the DNS-SD instance)"
  );
  assert_eq!(
    service_enum_target.as_deref(),
    Some("_hickgold._tcp.local"),
    "_services._dns-sd._udp enumeration PTR target (the service type)"
  );
  assert!(saw_nsec, "hick must decode Bonjour's NSEC records");

  // Sanity: ResourceType is reachable + the message has the expected shape.
  assert_eq!(
    reader
      .answers()
      .filter_map(Result::ok)
      .filter(|r| r.rtype() == ResourceType::Ptr)
      .count(),
    2,
    "two PTR answers (instance + service enumeration)"
  );
}

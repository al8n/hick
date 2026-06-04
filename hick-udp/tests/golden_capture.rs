//! Golden-fixture CAPTURE tool (a generator, not an assertion): records a real
//! Apple Bonjour (mDNSResponder) DNS-SD announcement off the wire so it can be
//! committed as a deterministic parse fixture for `mdns-proto`.
//!
//! macOS-only + opt-in. Run it by hand to (re)generate fixtures:
//!
//! ```text
//! HICK_GOLDEN_CAPTURE=1 cargo test -p hick-udp --test golden_capture -- --nocapture
//! ```
//!
//! It proxy-registers (`dns-sd -P`) a service with a CONTROLLED host name and an
//! RFC 5737 TEST-NET-1 address (192.0.2.1), so the captured bytes carry no real
//! machine identity, then sniffs the group and writes each unique announcement
//! to `/tmp/golden_bonjour_NN.bin` (+ a hex dump) for review before committing.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
  io::Write,
  net::{Ipv4Addr, SocketAddrV4, UdpSocket},
  process::{Command, Stdio},
  time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

fn hex(b: &[u8]) -> String {
  b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn capture_bonjour_golden_fixtures() {
  if std::env::var("HICK_GOLDEN_CAPTURE").is_err() {
    eprintln!("HICK_GOLDEN_CAPTURE not set; skipping golden capture");
    return;
  }

  // Bonjour proxy-registers a service with a controlled host + TEST-NET IP.
  let mut child = Command::new("dns-sd")
    .args([
      "-P",
      "GoldenInst",
      "_hickgold._tcp",
      "local.",
      "8080",
      "goldenhost.local.",
      "192.0.2.1",
      "txtvers=1",
      "path=/golden",
    ])
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn dns-sd -P (is this macOS with Bonjour?)");

  // Sniffer: REUSEPORT-bind :5353 and join the group on the default interface.
  let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
  sock.set_reuse_address(true).unwrap();
  sock.set_reuse_port(true).unwrap();
  sock
    .bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into())
    .unwrap();
  sock
    .join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)
    .unwrap();
  sock
    .set_read_timeout(Some(Duration::from_millis(400)))
    .unwrap();
  let sock: UdpSocket = sock.into();

  let mut captured: Vec<Vec<u8>> = Vec::new();
  let mut buf = [0u8; 9000];
  let start = Instant::now();
  while start.elapsed() < Duration::from_secs(8) {
    let Ok((n, _src)) = sock.recv_from(&mut buf) else {
      continue; // read timeout tick
    };
    let pkt = &buf[..n];
    // Keep announcements that mention our unique service label, deduped.
    if pkt.windows(8).any(|w| w == b"hickgold") && !captured.iter().any(|c| c == pkt) {
      captured.push(pkt.to_vec());
    }
  }
  let _ = child.kill();
  let _ = child.wait();

  eprintln!("captured {} unique _hickgold packets", captured.len());
  for (i, pkt) in captured.iter().enumerate() {
    let path = format!("/tmp/golden_bonjour_{i:02}.bin");
    std::fs::File::create(&path)
      .unwrap()
      .write_all(pkt)
      .unwrap();
    eprintln!("wrote {path} ({} bytes)\n{}", pkt.len(), hex(pkt));
  }
  assert!(
    !captured.is_empty(),
    "expected at least one Bonjour announcement for _hickgold._tcp"
  );
}

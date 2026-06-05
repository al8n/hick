use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

/// Synthesize a Linux IP_PKTINFO cmsg buffer for testing.
#[cfg(has_ip_pktinfo)]
fn synth_cmsg_v4(local_ip: Ipv4Addr, iface: u32) -> Vec<u8> {
  let hdr_size = core::mem::size_of::<libc::cmsghdr>();
  let data_size = 12; // in_pktinfo
  let cmsg_len = hdr_size + data_size;
  let align = core::mem::align_of::<libc::cmsghdr>();
  let padded = (cmsg_len + align - 1) & !(align - 1);

  let mut buf = vec![0u8; padded];

  // Write cmsghdr at offset 0. Build via `zeroed` + field assignment so any
  // platform-specific padding (e.g. musl's `cmsghdr::__pad1`) is initialized.
  #[allow(unsafe_code)]
  let mut hdr: libc::cmsghdr = unsafe { core::mem::zeroed() };
  hdr.cmsg_len = cmsg_len as _;
  hdr.cmsg_level = libc::IPPROTO_IP;
  hdr.cmsg_type = libc::IP_PKTINFO;
  #[allow(unsafe_code)]
  unsafe {
    core::ptr::write_unaligned(buf.as_mut_ptr() as *mut libc::cmsghdr, hdr);
  }
  // Write in_pktinfo data: ifindex (i32 native), spec_dst (4 bytes), addr (4 bytes).
  let idx_bytes = iface.to_ne_bytes();
  buf[hdr_size..hdr_size + 4].copy_from_slice(&idx_bytes);
  // ipi_spec_dst = the local interface address the packet was received on
  // (this is what we want for self-packet detection); ipi_addr = the IP
  // header destination address.  For multicast the two differ: ipi_addr is
  // the group (224.0.0.251), ipi_spec_dst is the local interface IP.
  let spec_dst_bytes = local_ip.octets();
  let dst_bytes = Ipv4Addr::new(224, 0, 0, 251).octets();
  buf[hdr_size + 4..hdr_size + 8].copy_from_slice(&spec_dst_bytes);
  buf[hdr_size + 8..hdr_size + 12].copy_from_slice(&dst_bytes);
  buf
}

#[cfg(has_ip_pktinfo)]
#[test]
fn parses_ipv4_pktinfo() {
  // regression: ipi_spec_dst (local) and ipi_addr (multicast dst)
  // are distinct.  parse_pktinfo_v4 must return ipi_spec_dst as local_ip.
  let cmsgs = synth_cmsg_v4(Ipv4Addr::new(192, 168, 1, 100), 42);
  let peer: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5353).into();
  let meta = parse_pktinfo_v4(&cmsgs, 200, peer).unwrap();
  assert_eq!(
    meta.local_ip(),
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
    "local_ip must be ipi_spec_dst (interface), not ipi_addr (multicast group)"
  );
  assert_eq!(meta.interface_index(), 42);
  assert_eq!(meta.peer(), peer);
  assert_eq!(meta.len(), 200);
  // The PKTINFO parsers carry no timestamp; rx_time stays None until
  // recv_with_meta threads in a parsed SCM_TIMESTAMP* cmsg.
  assert_eq!(meta.rx_time(), None);
}

#[cfg(has_ip_pktinfo)]
#[test]
fn empty_cmsgs_returns_missing() {
  let peer: SocketAddr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353).into();
  let err = parse_pktinfo_v4(&[], 0, peer).unwrap_err();
  assert!(err.is_missing_pktinfo());
}

/// Build a single cmsg with the given level/type carrying `data`, padded to
/// the cmsghdr alignment, mirroring `synth_cmsg_v4`. Compiled wherever a
/// receive-timestamp or hop-limit parse test uses it (`has_recv_timestamp`
/// ⊇ `has_recv_hoplimit`).
#[cfg(has_recv_timestamp)]
fn synth_cmsg(level: libc::c_int, ty: libc::c_int, data: &[u8]) -> Vec<u8> {
  let hdr_size = core::mem::size_of::<libc::cmsghdr>();
  let cmsg_len = hdr_size + data.len();
  let align = core::mem::align_of::<libc::cmsghdr>();
  let padded = (cmsg_len + align - 1) & !(align - 1);

  let mut buf = vec![0u8; padded];
  // `zeroed` + field assignment initializes any platform-specific padding
  // (e.g. musl's `cmsghdr::__pad1`) that a struct literal would omit.
  #[allow(unsafe_code)]
  let mut hdr: libc::cmsghdr = unsafe { core::mem::zeroed() };
  hdr.cmsg_len = cmsg_len as _;
  hdr.cmsg_level = level;
  hdr.cmsg_type = ty;
  #[allow(unsafe_code)]
  unsafe {
    core::ptr::write_unaligned(buf.as_mut_ptr() as *mut libc::cmsghdr, hdr);
  }
  buf[hdr_size..hdr_size + data.len()].copy_from_slice(data);
  buf
}

// parse an IPv4 TTL cmsg (host-order int, as Linux delivers it).
#[cfg(has_recv_hoplimit)]
#[test]
fn parses_ipv4_ttl_cmsg() {
  let ttl: libc::c_int = 254;
  let buf = synth_cmsg(libc::IPPROTO_IP, libc::IP_TTL, &ttl.to_ne_bytes());
  assert_eq!(parse_hop_limit(&buf, true), Some(254));
  // 255 (on-link) parses cleanly too.
  let ttl255: libc::c_int = 255;
  let buf = synth_cmsg(libc::IPPROTO_IP, libc::IP_TTL, &ttl255.to_ne_bytes());
  assert_eq!(parse_hop_limit(&buf, true), Some(255));
}

// parse an IPv6 Hop-Limit cmsg (host-order int).
#[cfg(has_recv_hoplimit)]
#[test]
fn parses_ipv6_hoplimit_cmsg() {
  let hl: libc::c_int = 255;
  let buf = synth_cmsg(libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT, &hl.to_ne_bytes());
  assert_eq!(parse_hop_limit(&buf, false), Some(255));
}

#[test]
fn parse_hop_limit_empty_is_none() {
  assert_eq!(parse_hop_limit(&[], true), None);
  assert_eq!(parse_hop_limit(&[], false), None);
}

#[cfg(recv_timestamp_ns)]
#[test]
fn parses_scm_timestampns() {
  use std::time::{Duration, SystemTime};
  let ts = libc::timespec {
    tv_sec: 1_700_000_000,
    tv_nsec: 123_456_789,
  };
  #[allow(unsafe_code)]
  let bytes = unsafe {
    core::slice::from_raw_parts(
      core::ptr::addr_of!(ts).cast::<u8>(),
      core::mem::size_of::<libc::timespec>(),
    )
  };
  let buf = synth_cmsg(libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS, bytes);
  let got = parse_rx_time(&buf).expect("expected a parsed timestamp");
  let want = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
  assert_eq!(got, want);
}

#[cfg(all(has_recv_timestamp, not(recv_timestamp_ns)))]
#[test]
fn parses_scm_timestamp() {
  use std::time::{Duration, SystemTime};
  let tv = libc::timeval {
    tv_sec: 1_700_000_000,
    tv_usec: 654_321,
  };
  #[allow(unsafe_code)]
  let bytes = unsafe {
    core::slice::from_raw_parts(
      core::ptr::addr_of!(tv).cast::<u8>(),
      core::mem::size_of::<libc::timeval>(),
    )
  };
  let buf = synth_cmsg(libc::SOL_SOCKET, libc::SCM_TIMESTAMP, bytes);
  let got = parse_rx_time(&buf).expect("expected a parsed timestamp");
  let want = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 654_321 * 1000);
  assert_eq!(got, want);
}

/// A control buffer with no timestamp cmsg yields None on every Unix target.
#[test]
fn no_timestamp_cmsg_yields_none() {
  assert_eq!(parse_rx_time(&[]), None);
}

/// a datagram larger than the receive buffer (MSG_TRUNC) must be
/// rejected as `InvalidData`, NOT returned as a truncated prefix the driver
/// would route into the parser.
#[test]
fn recv_with_meta_rejects_oversized_datagram() {
  use std::{net::UdpSocket as StdUdp, os::fd::AsRawFd};

  let recv = StdUdp::bind("127.0.0.1:0").unwrap();
  recv.set_nonblocking(true).unwrap();
  let addr = recv.local_addr().unwrap();
  let send = StdUdp::bind("127.0.0.1:0").unwrap();
  // Datagram much larger than the 16-byte receive buffer below.
  let big = vec![0xABu8; 2048];
  send.send_to(&big, addr).unwrap();

  let mut small = [0u8; 16];
  let mut result = recv_with_meta(recv.as_raw_fd(), &mut small, true);
  // Tolerate a brief loopback-delivery race under non-blocking reads.
  for _ in 0..100 {
    match &result {
      Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
        std::thread::sleep(std::time::Duration::from_millis(1));
        result = recv_with_meta(recv.as_raw_fd(), &mut small, true);
      }
      _ => break,
    }
  }
  let err = result.expect_err("oversized datagram must be rejected, not returned as data");
  assert_eq!(
    err.kind(),
    std::io::ErrorKind::InvalidData,
    "oversized (MSG_TRUNC) datagram must surface as InvalidData; got {err:?}"
  );
}

/// Recovery half of issue #2 ("Weird log on `windows` and `macos`"): after an
/// oversized datagram is rejected, the socket must NOT be wedged — the very
/// next in-bounds datagram is received intact. The old monolith spun /
/// ERROR-spammed on the rejected read; the receive path must instead drop the
/// bad datagram and keep serving.
#[test]
fn recv_with_meta_recovers_after_oversized() {
  use std::{net::UdpSocket as StdUdp, os::fd::AsRawFd};

  // Retry a non-blocking read past a brief loopback-delivery race.
  fn recv_settled(fd: std::os::fd::RawFd, buf: &mut [u8]) -> std::io::Result<RecvMeta> {
    let mut result = recv_with_meta(fd, buf, true);
    for _ in 0..100 {
      match &result {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
          std::thread::sleep(std::time::Duration::from_millis(1));
          result = recv_with_meta(fd, buf, true);
        }
        _ => break,
      }
    }
    result
  }

  let recv = StdUdp::bind("127.0.0.1:0").unwrap();
  recv.set_nonblocking(true).unwrap();
  let addr = recv.local_addr().unwrap();
  let send = StdUdp::bind("127.0.0.1:0").unwrap();
  let mut buf = [0u8; 64];

  // 1) Oversized datagram (2048 > 64-byte buffer) → rejected as InvalidData.
  send.send_to(&vec![0xABu8; 2048], addr).unwrap();
  assert_eq!(
    recv_settled(recv.as_raw_fd(), &mut buf)
      .expect_err("oversized must be rejected")
      .kind(),
    std::io::ErrorKind::InvalidData,
  );

  // 2) The socket is NOT wedged: a subsequent in-bounds datagram is received
  //    intact, proving the receive path keeps serving after the drop.
  let normal = [0x42u8; 32];
  send.send_to(&normal, addr).unwrap();
  let meta = recv_settled(recv.as_raw_fd(), &mut buf)
    .expect("normal datagram must be received after an oversized drop");
  assert_eq!(meta.len(), normal.len(), "received length must match");
  assert_eq!(&buf[..meta.len()], &normal, "received bytes must match");
}

#[cfg(unix)]
#[test]
#[allow(unsafe_code)]
fn cmsg_iter_is_sound_on_crafted_and_unaligned_input() {
  // the public parse_pktinfo_* APIs accept arbitrary &[u8], so
  // CmsgIter must never read out of bounds or assume alignment (no
  // pointer-based CMSG_DATA/CMSG_NXTHDR over caller memory).
  let hdr_size = core::mem::size_of::<libc::cmsghdr>();

  // Too short for even a header → no items, no panic.
  assert_eq!(CmsgIter::new(&[0u8; 1]).count(), 0);

  // Copy a live cmsghdr's own bytes so we can craft cmsg_len portably.
  let bytes_of = |h: &libc::cmsghdr| -> std::vec::Vec<u8> {
    // SAFETY: read exactly `size_of::<cmsghdr>()` bytes of a live cmsghdr.
    unsafe {
      core::slice::from_raw_parts((h as *const libc::cmsghdr).cast::<u8>(), hdr_size).to_vec()
    }
  };

  // Zeroed header: cmsg_len = 0 (< hdr_size) → BufferTooShort, not OOB.
  let zeroed: libc::cmsghdr = unsafe { core::mem::zeroed() };
  assert!(matches!(
    CmsgIter::new(&bytes_of(&zeroed)).next(),
    Some(Err(_))
  ));

  // cmsg_len claims 4 KiB the slice doesn't hold → BufferTooShort, no OOB read.
  let mut big: libc::cmsghdr = unsafe { core::mem::zeroed() };
  big.cmsg_len = (hdr_size + 4096) as _;
  assert!(matches!(
    CmsgIter::new(&bytes_of(&big)).next(),
    Some(Err(_))
  ));

  // Unaligned backing store: a valid header-only cmsg placed at byte offset 1
  // must parse via read_unaligned, not trigger UB.
  let mut valid: libc::cmsghdr = unsafe { core::mem::zeroed() };
  valid.cmsg_len = hdr_size as _;
  let vb = bytes_of(&valid);
  let mut padded = std::vec![0u8; hdr_size + 1];
  padded[1..].copy_from_slice(&vb);
  let items: std::vec::Vec<_> = CmsgIter::new(&padded[1..]).collect();
  assert_eq!(
    items.len(),
    1,
    "one header-only cmsg parses from an odd offset"
  );
  assert!(items[0].is_ok());
}

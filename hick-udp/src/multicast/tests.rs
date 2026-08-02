use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

/// The Linux/Apple 12-byte `struct in_pktinfo`: `ipi_ifindex`, `ipi_spec_dst`,
/// `ipi_addr`. Also fed to the NetBSD parser, whose own `in_pktinfo` is a
/// different 8-byte layout, to pin that it refuses this one.
fn synth_linux_in_pktinfo(index: u32, spec_dst: Ipv4Addr, addr: Ipv4Addr) -> Vec<u8> {
  let mut v = Vec::with_capacity(12);
  v.extend_from_slice(&index.to_ne_bytes());
  v.extend_from_slice(&spec_dst.octets());
  v.extend_from_slice(&addr.octets());
  v
}

/// Synthesize a Linux/Apple `IP_PKTINFO` cmsg buffer for testing.
#[cfg(has_ip_pktinfo)]
fn synth_cmsg_v4(local_ip: Ipv4Addr, iface: u32) -> Vec<u8> {
  // ipi_spec_dst is the local interface address the datagram arrived on (what
  // self-packet detection wants); ipi_addr is the IP header destination. For a
  // multicast arrival the two differ — ipi_addr is the group, ipi_spec_dst the
  // interface's own IP — and the tests below pin that they never collapse onto
  // each other.
  synth_cmsg(
    libc::IPPROTO_IP,
    libc::IP_PKTINFO,
    &synth_linux_in_pktinfo(iface, local_ip, Ipv4Addr::new(224, 0, 0, 251)),
  )
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
fn destination_is_ipi_addr_while_local_ip_stays_ipi_spec_dst() {
  // Both readings, pinned on ONE buffer. The same in_pktinfo carries the
  // receiving interface's address in ipi_spec_dst and the address the sender
  // actually addressed in ipi_addr; `local_ip` and `destination` must keep
  // returning one each and never collapse onto either. Reading ipi_spec_dst as
  // the destination is what made a multicast arrival look unicast to the
  // RFC 6762 §11 fallback — ipi_spec_dst is a local unicast address, so it can
  // never equal a group.
  let cmsgs = synth_cmsg_v4(Ipv4Addr::new(192, 168, 1, 100), 42);
  let peer: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5353).into();
  let meta = parse_pktinfo_v4(&cmsgs, 200, peer).unwrap();
  assert_eq!(
    meta.destination(),
    Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
    "destination must be ipi_addr, the group the sender addressed"
  );
  assert_eq!(
    meta.local_ip(),
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
    "local_ip must stay ipi_spec_dst on the very same buffer"
  );
  assert_ne!(Some(meta.local_ip()), meta.destination());
  // Nothing sets the flag on this path: the PKTINFO parsers never see
  // `msg_flags`, and `None` is "no such flag here", not "unicast".
  assert_eq!(meta.multicast_flag(), None);
}

#[cfg(has_ip_pktinfo)]
#[test]
fn empty_cmsgs_returns_missing() {
  let peer: SocketAddr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353).into();
  let err = parse_pktinfo_v4(&[], 0, peer).unwrap_err();
  assert!(err.is_missing_pktinfo());
}

/// Where a kernel writes a cmsg's payload, and where `CmsgIter` reads it from:
/// `CMSG_LEN(0)` — the header size rounded up to the target's cmsg alignment.
///
/// NOT `size_of::<libc::cmsghdr>()`. The two coincide on Linux (16 == 16) and
/// Apple (12 == 12) and diverge on the BSDs, where `struct cmsghdr` is 12 bytes
/// (`socklen_t` plus two `int`s) but `_ALIGN` rounds to `_ALIGNBYTES` — 7 on
/// x86_64 FreeBSD, DragonFly, OpenBSD and NetBSD — making `CMSG_LEN(0)` 16.
/// A builder keyed to the struct size therefore writes every payload four bytes
/// early on exactly the targets these tests exist to cover, and the parser,
/// reading from `CMSG_LEN(0)`, sees a 4-byte `IP_RECVDSTADDR` as empty and an
/// 8-byte NetBSD `in_pktinfo` as four bytes. The alignment is not constant even
/// within one platform (NetBSD rounds to 4 on x86 and 16 on sparc64), which is
/// why this asks `libc` instead of deriving a constant.
fn cmsg_data_offset() -> usize {
  // SAFETY: `CMSG_LEN` is pure length arithmetic on an integer and dereferences
  // nothing; `libc` marks it `unsafe` by convention only. `CmsgIter` calls it
  // the same way, for the same reason, and that shared source is what makes
  // builder and parser agree on every target rather than only on this host.
  #[allow(unsafe_code)]
  unsafe {
    libc::CMSG_LEN(0) as usize
  }
}

/// How many bytes one cmsg occupies in an ancillary buffer, and so the offset
/// of the next header: `CMSG_SPACE(data_len)`, which pads the payload as well
/// as the header. This is the stride `CmsgIter` advances by, and therefore
/// exactly what a synthesized cmsg must be allocated — padding to
/// `align_of::<cmsghdr>()` is not the same quantity and is short on the BSDs,
/// where a 4-byte-aligned struct is walked with 8-byte alignment.
fn cmsg_stride(data_len: usize) -> usize {
  let data_len = u32::try_from(data_len).expect("test cmsg payloads are a few bytes");
  // SAFETY: as in `cmsg_data_offset` — `CMSG_SPACE` is integer arithmetic.
  #[allow(unsafe_code)]
  unsafe {
    libc::CMSG_SPACE(data_len) as usize
  }
}

/// Build one cmsg the way a kernel lays it out: header at offset 0, payload at
/// `CMSG_LEN(0)`, `cmsg_len` covering header-plus-payload, and the whole thing
/// occupying `CMSG_SPACE(data.len())` so the next header lands where the walker
/// looks for it.
///
/// The buffer is read back through `CmsgIter` before being returned. These
/// synthesized buffers are the only evidence the BSD parsers have — CI
/// cross-compiles those targets and executes nothing on them — so the builder
/// checks its own product instead of trusting its arithmetic: a target whose
/// header padding or stride differed from what was assumed here fails at the
/// build, in every test at once, rather than quietly handing the parsers
/// payloads they read short or headers they walk past. The round trip pins
/// builder against parser; what makes the parser itself right about a real
/// kernel is that both sides take their offsets from `libc`'s macros, which
/// are the ABI.
fn synth_cmsg(level: libc::c_int, ty: libc::c_int, data: &[u8]) -> Vec<u8> {
  let data_offset = cmsg_data_offset();
  let cmsg_len = data_offset + data.len();
  let mut buf = vec![0u8; cmsg_stride(data.len())];

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
  buf[data_offset..cmsg_len].copy_from_slice(data);

  let mut walk = CmsgIter::new(&buf);
  let parsed = walk
    .next()
    .expect("a synthesized cmsg must be visible to CmsgIter")
    .expect("a synthesized cmsg must parse");
  assert_eq!(
    parsed.level, level,
    "cmsg_level must survive the round trip"
  );
  assert_eq!(parsed.ty, ty, "cmsg_type must survive the round trip");
  assert_eq!(
    parsed.data, data,
    "the payload written at CMSG_LEN(0) must be the payload CmsgIter reads back"
  );
  assert!(
    walk.next().is_none(),
    "one cmsg must occupy exactly CMSG_SPACE(data.len()) bytes, no more and no less"
  );

  buf
}

/// The builder is evidence-bearing infrastructure — every parse test here reads
/// a buffer it produced — so its two derived quantities are pinned against
/// `libc`'s macros computed a different way, on whatever target is compiled.
///
/// The mismatch this guards was live in this file: deriving the payload offset
/// from `size_of::<cmsghdr>()` and the stride from `align_of::<cmsghdr>()` is
/// right on Linux and Apple and wrong on all four BSDs, so the tests below
/// proved the BSD parsers against a layout no BSD kernel emits.
#[test]
fn synth_cmsg_agrees_with_libc_on_payload_offset_and_stride() {
  let hdr_size = core::mem::size_of::<libc::cmsghdr>();
  let data_offset = cmsg_data_offset();
  assert!(
    data_offset >= hdr_size,
    "a payload at {data_offset} would overlap a {hdr_size}-byte cmsghdr"
  );

  for data_len in 0..=24usize {
    // `synth_cmsg` derives `cmsg_len` as CMSG_LEN(0) + data_len; `libc` derives
    // it as _ALIGN(sizeof cmsghdr) + data_len. Same ABI rule, different call.
    #[allow(unsafe_code)]
    let libc_len = unsafe { libc::CMSG_LEN(data_len as u32) } as usize;
    assert_eq!(
      data_offset + data_len,
      libc_len,
      "the builder's cmsg_len for a {data_len}-byte payload must be CMSG_LEN({data_len})"
    );

    let stride = cmsg_stride(data_len);
    assert!(
      stride >= libc_len,
      "CMSG_SPACE({data_len}) = {stride} must cover CMSG_LEN({data_len}) = {libc_len}"
    );

    // Every byte distinct, so a payload written at the wrong offset comes back
    // shifted rather than merely short: `synth_cmsg`'s own round trip compares
    // the bytes, not just the length.
    let data: Vec<u8> = (0..data_len).map(|i| 0xA5 ^ (i as u8)).collect();
    let one = synth_cmsg(libc::IPPROTO_IP, libc::IP_TTL, &data);
    assert_eq!(one.len(), stride, "one cmsg must be CMSG_SPACE bytes long");

    // Concatenated, the walker must still see both — true only if the stride
    // the builder allocates is the stride the walker advances by. The two
    // differ in level as well as type, so a second header found at the wrong
    // offset cannot pass by resembling the first. Both level/type pairs come
    // from constants every Unix target binds — this test is ungated, and
    // `IPV6_HOPLIMIT`, for one, does not exist on NetBSD.
    let pair = synth_cmsgs(&[
      (libc::IPPROTO_IP, libc::IP_TTL, &data),
      (libc::SOL_SOCKET, libc::SCM_RIGHTS, &data),
    ]);
    assert_eq!(pair.len(), 2 * stride);
    let items: Vec<_> = CmsgIter::new(&pair)
      .map(|c| c.expect("a synthesized pair must parse"))
      .collect();
    assert_eq!(
      items.len(),
      2,
      "a second cmsg placed at CMSG_SPACE({data_len}) must be walked to"
    );
    assert_eq!(
      (items[0].level, items[0].ty),
      (libc::IPPROTO_IP, libc::IP_TTL)
    );
    assert_eq!(
      (items[1].level, items[1].ty),
      (libc::SOL_SOCKET, libc::SCM_RIGHTS)
    );
    assert!(items.iter().all(|c| c.data == data.as_slice()));
  }
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

/// Regression test for the library-side `IPV6_MULTICAST_HOPS` read-back
/// verification's COMPARISON logic (`verify_multicast_hops_v6`, wired into
/// `try_bind_v6_inner` right after `platform::set_multicast_hops_v6`).
///
/// This test calls the private verifier directly, so it proves the
/// comparison itself is correct in isolation; it does NOT prove
/// `try_bind_v6_inner` still calls it — see
/// `try_bind_v6_rejects_a_mismatch_forced_through_production_wiring` below
/// for the test that exercises the real call sequence.
///
/// Uses `expect_bind_or_skip`, NOT a bare `Err(_) => skip`: this test's
/// initial bind previously matched every `BindError` as an environmental
/// skip, which would have silently absorbed an inverted verifier comparison
/// the moment `try_bind_v6`'s OWN internal check fired during the setup
/// bind — the test would report a skip, not a failure, for the exact
/// regression it exists to catch. `expect_bind_or_skip` panics
/// loudly on any `BindError` that is not a recognized environment refusal,
/// `MulticastHopsNotApplied` very much included.
///
/// The scenario reproduced below is honest, not fabricated: it uses the
/// crate's own (correct) setter to move the real hop limit to a second value
/// after binding, matching the historical bug's OBSERVABLE shape — a socket
/// whose real hop limit does not match what was asked for — rather than
/// lying about the `requested` argument. If `verify_multicast_hops_v6` is
/// deleted, or its comparison is weakened to always succeed, this test
/// fails.
#[test]
fn verify_multicast_hops_v6_rejects_a_kernel_value_that_drifted_from_the_request() {
  let opts = MulticastOptionsV6::new(0);
  let requested = opts.hops();
  let Some(sock) = expect_bind_or_skip(
    "verify_multicast_hops_v6_rejects_a_kernel_value_that_drifted_from_the_request",
    try_bind_v6(opts),
  ) else {
    return;
  };

  // Sanity: immediately after a successful bind, the real kernel state
  // already matches what was requested — try_bind_v6_inner's own call to
  // verify_multicast_hops_v6 already confirmed this before returning `sock`,
  // so this just re-derives the same fact through the same function the
  // mismatch check below relies on.
  verify_multicast_hops_v6(&sock, requested)
    .expect("a freshly bound socket must verify against the hop limit it was bound with");

  // Move the real kernel value away from `requested`, using the crate's own
  // (correct) setter. `wrapping_add(1)` on a `u8` always yields a different
  // value, so `drifted != requested` unconditionally.
  let drifted = requested.wrapping_add(1);
  platform::set_multicast_hops_v6(&sock, drifted)
    .expect("re-applying a different hop limit for this simulation must itself succeed");

  // The verifier must now reject `requested`: the kernel no longer holds it.
  let err = verify_multicast_hops_v6(&sock, requested).expect_err(
    "a socket whose real hop limit no longer matches `requested` must be rejected, not \
     silently accepted",
  );
  let detail = err
    .try_unwrap_multicast_hops_not_applied()
    .expect("expected BindError::MulticastHopsNotApplied");
  assert_eq!(detail.requested(), requested);
  assert_eq!(detail.observed(), i32::from(drifted));
}

/// Regression test proving `verify_multicast_hops_v6` is actually WIRED into
/// `try_bind_v6_inner`'s production call sequence: the test above calls the
/// verifier directly, so it would keep passing even if the call site at
/// `multicast.rs` (right after `platform::set_multicast_hops_v6`) were
/// deleted entirely, since the helper it calls would still exist and still
/// work correctly in isolation.
///
/// This test goes through the PUBLIC `try_bind_v6` entry point — the same
/// one every real caller uses — with the `FORCE_APPLIED_HOPS_V6` test-only
/// seam forcing the value actually applied to the kernel to differ from the
/// value the caller believes was requested. See that seam's doc in
/// `multicast.rs` for why a seam is unavoidable here: no input reachable
/// through `MulticastOptionsV6`/`try_bind_v6` alone can ever force this
/// disagreement on a correctly functioning kernel, so there is no seam-free
/// way to prove the WIRING (as opposed to the comparison) without
/// reintroducing a real bug.
///
/// Uses `expect_bind_or_skip`'s allowlist for the one expected-and-legitimate
/// non-regression outcome (the environment refuses IPv6 binding entirely),
/// but — critically — does NOT hand `try_bind_v6`'s result to that helper
/// directly: `expect_bind_or_skip` treats a `BindError::Io` matching
/// `is_environment_refusal` as a skip and panics on everything else,
/// including `MulticastHopsNotApplied` — the exact outcome this test expects
/// to see on success. So this test open-codes the same allowlist check for
/// the one “not the outcome under test but also not a bug” case (environment
/// refusal), and treats every other outcome — an unexpected `Ok`, or any
/// `BindError` variant other than `MulticastHopsNotApplied` — as the test's
/// own failure, not a skip.
///
/// If `verify_multicast_hops_v6`'s call is deleted from `try_bind_v6_inner`,
/// `try_bind_v6` returns `Ok` here (the forced-wrong value is never checked),
/// and this test fails. If the comparison is inverted or neutered, same
/// result: `Ok`, and this test fails.
#[test]
fn try_bind_v6_rejects_a_mismatch_forced_through_production_wiring() {
  let opts = MulticastOptionsV6::new(0);
  let requested = opts.hops();
  let forced = requested.wrapping_add(1);

  FORCE_APPLIED_HOPS_V6.with(|cell| cell.set(Some(forced)));
  let result = try_bind_v6(opts);
  // Reset before anything below can fail an assertion, so the override never
  // leaks into a later test on this thread even on an early failure here.
  FORCE_APPLIED_HOPS_V6.with(|cell| cell.set(None));

  let err = match result {
    Err(BindError::Io(e)) if is_environment_refusal(&e) => {
      eprintln!("skipping: environment refused the IPv6 bind needed to exercise this seam ({e})");
      return;
    }
    other => other.expect_err(
      "try_bind_v6 must reject a bind where the production wiring's own requested/observed \
       check disagrees — an Ok here means either the verifier call was removed from \
       try_bind_v6_inner or its comparison no longer detects a real disagreement",
    ),
  };
  let detail = err.try_unwrap_multicast_hops_not_applied().expect(
    "expected BindError::MulticastHopsNotApplied — a different BindError variant means \
     try_bind_v6 failed for a reason unrelated to the forced hops mismatch",
  );
  assert_eq!(detail.requested(), requested);
  assert_eq!(detail.observed(), i32::from(forced));
}

// ============================================================================
// BSD IPv4 receive metadata.
//
// These tests prove the PARSE and nothing else. They feed synthesized cmsg
// buffers to the decoders and walkers, so they run on any host — which is the
// only reason coverage exists for these targets at all, since CI cross-COMPILES
// FreeBSD/DragonFly/OpenBSD/NetBSD and runs nothing there. What they do NOT
// prove is the PLUMBING: that the enabling sockopt is accepted, that the kernel
// actually attaches these cmsgs to a real mDNS datagram, that the interface
// index it reports matches `if_nametoindex`, or that the 256-byte control
// buffer still escapes `MSG_CTRUNC` with them present. That evidence can only
// come from a real host of each target, and until it does the parsers stay
// unwired — see `build.rs` for the full list.
//
// Nor do they prove the parse ON a BSD. `synth_cmsg` now frames every buffer
// from the compiled target's own `CMSG_LEN`/`CMSG_SPACE`, so cross-compiling
// this test binary for a BSD type-checks the layout against that target's real
// ABI constants; but these assertions run on the host that runs `cargo test`,
// so what they execute is the host's cmsg ABI, with the per-target cmsg NUMBERS
// supplied as parameters. Read them as "the decoders and the walk are correct
// given the layout", not as "the layout is confirmed on FreeBSD". Only a run on
// each target turns this into activation evidence, which is the same bar
// `build.rs` sets for the flip.
//
// The cmsg type numbers are passed in rather than read from `libc` (see
// `scan_dstaddr_recvif`), so these are the real per-target values: 7 for
// `IP_RECVDSTADDR` everywhere, 20 for `IP_RECVIF` on FreeBSD/DragonFly/NetBSD
// against 30 on OpenBSD, and 25 for the `IP_PKTINFO` cmsg NetBSD delivers (the
// sockopt that enables it, `IP_RECVPKTINFO`, is a different number: 26).
// ============================================================================

const IP_RECVDSTADDR_TY: libc::c_int = 7;
const IP_RECVIF_TY: libc::c_int = 20;
const IP_RECVIF_TY_OPENBSD: libc::c_int = 30;
const IP_PKTINFO_TY_NETBSD: libc::c_int = 25;

/// Concatenate several cmsgs into one ancillary buffer. Each `synth_cmsg` is
/// already exactly `CMSG_SPACE(data.len())` long — the stride `CmsgIter`
/// advances by — so appending them places every header where the walker looks
/// for it. The multi-cmsg tests below assert the resulting item count, so a
/// disagreement surfaces as a failure rather than as a silently skipped cmsg.
fn synth_cmsgs(parts: &[(libc::c_int, libc::c_int, &[u8])]) -> Vec<u8> {
  let mut buf = Vec::new();
  for (level, ty, data) in parts {
    buf.extend_from_slice(&synth_cmsg(*level, *ty, data));
  }
  buf
}

/// A `struct sockaddr_dl` payload as the BSD kernels emit it for `IP_RECVIF`:
/// the 8-byte fixed prefix followed by `trailing` bytes of name/hardware
/// address, with `sdl_len` covering the whole thing. `trailing` empty is the
/// kernels' `makedummy` form.
fn synth_sockaddr_dl(index: u16, trailing: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(8 + trailing.len());
  v.push((8 + trailing.len()) as u8); // sdl_len
  v.push(18); // sdl_family = AF_LINK on every BSD
  v.extend_from_slice(&index.to_ne_bytes()); // sdl_index, host order
  v.push(6); // sdl_type
  v.push(trailing.len() as u8); // sdl_nlen
  v.push(0); // sdl_alen
  v.push(0); // sdl_slen
  v.extend_from_slice(trailing);
  v
}

/// NetBSD's 8-byte `struct in_pktinfo`: `ipi_addr` then `ipi_ifindex`.
fn synth_netbsd_in_pktinfo(addr: Ipv4Addr, index: u32) -> Vec<u8> {
  let mut v = Vec::with_capacity(8);
  v.extend_from_slice(&addr.octets());
  v.extend_from_slice(&index.to_ne_bytes());
  v
}

#[test]
fn decode_recvdstaddr_reads_a_network_order_in_addr() {
  let group = Ipv4Addr::new(224, 0, 0, 251);
  assert_eq!(decode_recvdstaddr(&group.octets()), Some(group));
  // A unicast destination must survive the same path: RFC 6762 §11 picks
  // between its two local-link tests by exactly this value, so the parser must
  // not be able to turn a unicast arrival into a group one or the reverse.
  let unicast = Ipv4Addr::new(192, 168, 1, 100);
  assert_eq!(decode_recvdstaddr(&unicast.octets()), Some(unicast));
}

#[test]
fn decode_recvdstaddr_rejects_a_truncated_in_addr() {
  assert_eq!(decode_recvdstaddr(&[224, 0, 0]), None);
  assert_eq!(decode_recvdstaddr(&[]), None);
}

#[test]
fn decode_recvif_index_reads_sdl_index_out_of_the_fixed_prefix() {
  // The kernels' shortest form: `sdl_len` == offsetof(sdl_data), no trailing
  // name or hardware address.
  assert_eq!(decode_recvif_index(&synth_sockaddr_dl(42, &[])), Some(42));

  // And the long form. `sockaddr_dl` is variable-length — the kernel copies
  // the interface's own link-layer address, whose length depends on the
  // interface name and hardware address — so the index must be read from the
  // fixed prefix and the tail ignored, never located relative to the end.
  let long = synth_sockaddr_dl(42, b"em0\x00\x11\x22\x33\x44\x55\x66");
  assert!(long.len() > 8, "the long form must actually be longer");
  assert_eq!(decode_recvif_index(&long), Some(42));

  // A wide index still round-trips: `sdl_index` is a `u_short`, so the top of
  // the 16-bit range has to survive the widening to u32 unchanged.
  assert_eq!(
    decode_recvif_index(&synth_sockaddr_dl(u16::MAX, &[])),
    Some(u32::from(u16::MAX))
  );
}

#[test]
fn decode_recvif_index_rejects_a_payload_shorter_than_the_fixed_prefix() {
  let full = synth_sockaddr_dl(42, &[]);
  for short in 0..full.len() {
    assert_eq!(
      decode_recvif_index(&full[..short]),
      None,
      "{short} bytes is not a sockaddr_dl and must not be decoded as one"
    );
  }
}

#[test]
fn decode_recvif_index_passes_through_the_kernel_dummy_zero() {
  // `sdl_index = 0` is what the BSD kernels' `makedummy` path emits when a
  // datagram has no receive interface. It is a decoded value, not a decode
  // failure, and it means exactly what the zero index a target without this
  // cmsg reports means: the platform is not naming an interface.
  assert_eq!(decode_recvif_index(&synth_sockaddr_dl(0, &[])), Some(0));
}

#[test]
fn scan_dstaddr_recvif_skips_unrelated_cmsgs_and_recovers_both() {
  let group = Ipv4Addr::new(224, 0, 0, 251);
  let sdl = synth_sockaddr_dl(7, b"em0");
  let ttl: libc::c_int = 255;
  let parts: &[(libc::c_int, libc::c_int, &[u8])] = &[
    // A different level entirely.
    (libc::SOL_SOCKET, libc::SCM_RIGHTS, &[0u8; 4]),
    (libc::IPPROTO_IP, IP_RECVDSTADDR_TY, &group.octets()),
    // Same level, unrelated type — including the number OpenBSD uses for
    // IP_RECVIF, which must NOT match while scanning with 20.
    (libc::IPPROTO_IP, libc::IP_TTL, &ttl.to_ne_bytes()),
    (libc::IPPROTO_IP, IP_RECVIF_TY_OPENBSD, &sdl),
    (libc::IPPROTO_IP, IP_RECVIF_TY, &sdl),
  ];
  let buf = synth_cmsgs(parts);
  assert_eq!(
    CmsgIter::new(&buf).count(),
    parts.len(),
    "the synthesized stride must match the one CmsgIter derives from CMSG_SPACE"
  );

  let (destination, iface) = scan_dstaddr_recvif(&buf, IP_RECVDSTADDR_TY, IP_RECVIF_TY);
  assert_eq!(destination, Some(group));
  assert_eq!(iface, Some(7));
}

#[test]
fn scan_dstaddr_recvif_honours_the_type_numbers_it_is_given() {
  // OpenBSD spells IP_RECVIF 30 where FreeBSD/DragonFly/NetBSD spell it 20.
  // The same buffer must therefore yield the interface under one number and
  // not under the other — proving the walk reads its parameters rather than a
  // hardcoded constant, which is what makes `libc`'s per-target numbers the
  // only thing this parse takes on trust.
  let sdl = synth_sockaddr_dl(9, &[]);
  let buf = synth_cmsgs(&[(libc::IPPROTO_IP, IP_RECVIF_TY_OPENBSD, &sdl)]);

  let (_, openbsd) = scan_dstaddr_recvif(&buf, IP_RECVDSTADDR_TY, IP_RECVIF_TY_OPENBSD);
  assert_eq!(openbsd, Some(9));

  let (_, freebsd) = scan_dstaddr_recvif(&buf, IP_RECVDSTADDR_TY, IP_RECVIF_TY);
  assert_eq!(freebsd, None);
}

#[test]
fn scan_dstaddr_recvif_reports_each_half_of_the_pair_independently() {
  let group = Ipv4Addr::new(224, 0, 0, 251);

  // Destination only: the two cmsgs are separately enabled and separately
  // delivered, so one arriving without the other is a real case.
  let dst_only = synth_cmsgs(&[(libc::IPPROTO_IP, IP_RECVDSTADDR_TY, &group.octets())]);
  assert_eq!(
    scan_dstaddr_recvif(&dst_only, IP_RECVDSTADDR_TY, IP_RECVIF_TY),
    (Some(group), None)
  );

  // Interface only.
  let sdl = synth_sockaddr_dl(3, &[]);
  let if_only = synth_cmsgs(&[(libc::IPPROTO_IP, IP_RECVIF_TY, &sdl)]);
  assert_eq!(
    scan_dstaddr_recvif(&if_only, IP_RECVDSTADDR_TY, IP_RECVIF_TY),
    (None, Some(3))
  );

  // Neither: an empty buffer, and a buffer holding only unrelated cmsgs.
  assert_eq!(
    scan_dstaddr_recvif(&[], IP_RECVDSTADDR_TY, IP_RECVIF_TY),
    (None, None)
  );
  let unrelated = synth_cmsgs(&[(libc::SOL_SOCKET, libc::SCM_RIGHTS, &[0u8; 4])]);
  assert_eq!(
    scan_dstaddr_recvif(&unrelated, IP_RECVDSTADDR_TY, IP_RECVIF_TY),
    (None, None)
  );

  // A truncated destination payload does not become a bogus address, and does
  // not cost us the interface sitting next to it.
  let truncated = synth_cmsgs(&[
    (libc::IPPROTO_IP, IP_RECVDSTADDR_TY, &[224, 0, 0]),
    (libc::IPPROTO_IP, IP_RECVIF_TY, &sdl),
  ]);
  assert_eq!(
    scan_dstaddr_recvif(&truncated, IP_RECVDSTADDR_TY, IP_RECVIF_TY),
    (None, Some(3))
  );
}

#[test]
fn decode_netbsd_pktinfo_reads_the_eight_byte_layout() {
  let group = Ipv4Addr::new(224, 0, 0, 251);
  assert_eq!(
    decode_netbsd_pktinfo(&synth_netbsd_in_pktinfo(group, 42)),
    Some((group, 42))
  );
  // ipi_ifindex is an `unsigned int`, not the `u_short` of sockaddr_dl.
  assert_eq!(
    decode_netbsd_pktinfo(&synth_netbsd_in_pktinfo(group, u32::from(u16::MAX) + 1)),
    Some((group, 65536))
  );
}

#[test]
fn decode_netbsd_pktinfo_rejects_a_truncated_payload() {
  let full = synth_netbsd_in_pktinfo(Ipv4Addr::new(224, 0, 0, 251), 42);
  for short in 0..full.len() {
    assert_eq!(
      decode_netbsd_pktinfo(&full[..short]),
      None,
      "{short} bytes is not a NetBSD in_pktinfo"
    );
  }
}

#[test]
fn decode_netbsd_pktinfo_rejects_the_twelve_byte_linux_layout() {
  // THE misread this parser exists to prevent. The Linux/Apple `in_pktinfo`
  // is 12 bytes ordered ipi_ifindex / ipi_spec_dst / ipi_addr; NetBSD's is 8
  // ordered ipi_addr / ipi_ifindex. Decoded as NetBSD's, the Linux struct
  // would hand back its interface index as the destination address and its
  // ipi_spec_dst as the index — both plausible-looking, neither out of range,
  // nothing to notice at runtime. The exact-length test is what stops it.
  let linux = synth_linux_in_pktinfo(
    42,
    Ipv4Addr::new(192, 168, 1, 100),
    Ipv4Addr::new(224, 0, 0, 251),
  );
  assert_eq!(linux.len(), 12);
  assert_eq!(decode_netbsd_pktinfo(&linux), None);

  // And through the walk, so a promotion that swapped the decoder for a
  // permissive one could not slip past on the cmsg type alone.
  let buf = synth_cmsgs(&[(libc::IPPROTO_IP, IP_PKTINFO_TY_NETBSD, &linux)]);
  assert_eq!(scan_netbsd_pktinfo(&buf, IP_PKTINFO_TY_NETBSD), None);
}

/// The other direction of the same confusion: the 12-byte parser must keep
/// refusing NetBSD's 8-byte struct rather than reading four bytes past its end
/// or accepting a short one. This is the behaviour `build.rs` cites as the
/// reason NetBSD is excluded from `has_ip_pktinfo`, pinned so it stays true.
#[cfg(has_ip_pktinfo)]
#[test]
fn parse_pktinfo_v4_rejects_the_netbsd_eight_byte_layout() {
  let netbsd = synth_netbsd_in_pktinfo(Ipv4Addr::new(224, 0, 0, 251), 42);
  assert_eq!(netbsd.len(), 8);
  let buf = synth_cmsg(libc::IPPROTO_IP, libc::IP_PKTINFO, &netbsd);
  let peer: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5353).into();
  let err = parse_pktinfo_v4(&buf, 200, peer).unwrap_err();
  let detail = err
    .try_unwrap_buffer_too_short()
    .expect("expected BufferTooShort, not a decoded meta");
  assert_eq!(detail.needed(), 12);
  assert_eq!(detail.have(), 8);
}

#[test]
fn scan_netbsd_pktinfo_skips_unrelated_cmsgs() {
  let group = Ipv4Addr::new(224, 0, 0, 251);
  let ttl: libc::c_int = 255;
  let sdl = synth_sockaddr_dl(9, &[]);
  let parts: &[(libc::c_int, libc::c_int, &[u8])] = &[
    (libc::SOL_SOCKET, libc::SCM_RIGHTS, &[0u8; 4]),
    (libc::IPPROTO_IP, libc::IP_TTL, &ttl.to_ne_bytes()),
    // NetBSD binds IP_RECVDSTADDR/IP_RECVIF too, so both can legitimately
    // share the buffer with IP_PKTINFO; neither may be mistaken for it.
    (libc::IPPROTO_IP, IP_RECVDSTADDR_TY, &group.octets()),
    (libc::IPPROTO_IP, IP_RECVIF_TY, &sdl),
    (
      libc::IPPROTO_IP,
      IP_PKTINFO_TY_NETBSD,
      &synth_netbsd_in_pktinfo(group, 42),
    ),
  ];
  let buf = synth_cmsgs(parts);
  assert_eq!(
    CmsgIter::new(&buf).count(),
    parts.len(),
    "the synthesized stride must match the one CmsgIter derives from CMSG_SPACE"
  );
  assert_eq!(
    scan_netbsd_pktinfo(&buf, IP_PKTINFO_TY_NETBSD),
    Some((group, 42))
  );
}

#[test]
fn scan_netbsd_pktinfo_is_none_without_its_own_cmsg() {
  assert_eq!(scan_netbsd_pktinfo(&[], IP_PKTINFO_TY_NETBSD), None);
  let ttl: libc::c_int = 255;
  let unrelated = synth_cmsgs(&[
    (libc::SOL_SOCKET, libc::SCM_RIGHTS, &[0u8; 4]),
    (libc::IPPROTO_IP, libc::IP_TTL, &ttl.to_ne_bytes()),
  ]);
  assert_eq!(scan_netbsd_pktinfo(&unrelated, IP_PKTINFO_TY_NETBSD), None);
}

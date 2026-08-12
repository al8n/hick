use super::*;
use std::net::Ipv4Addr;
// Only the `parse_pktinfo_v4` tests build a peer address or compare a
// `RecvMeta` address, and every one of them is `has_ip_pktinfo`-gated. Left
// unconditional, these three warn on each target without that cfg — all four
// BSDs — and so fail any job that compiles this file under `-D warnings`.
#[cfg(has_ip_pktinfo)]
use std::net::{IpAddr, SocketAddr, SocketAddrV4};

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
    meta.destination_witness(),
    crate::onlink::DestinationWitness::Witnessed(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
    "destination must be ipi_addr, the group the sender addressed"
  );
  assert_eq!(
    meta.local_ip(),
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
    "local_ip must stay ipi_spec_dst on the very same buffer"
  );
  assert_ne!(
    crate::onlink::DestinationWitness::Witnessed(meta.local_ip()),
    meta.destination_witness()
  );
  // Nothing sets the flag on this path: the PKTINFO parsers never see
  // `msg_flags`, and `None` is "no such flag here", not "unicast".
  assert_eq!(meta.delivery(), None);
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
/// synthesized buffers are the only layout evidence the BSD parsers have on
/// every target but FreeBSD, which CI now runs natively — so the builder
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
  let buf = synth_rx_timestamp_cmsg(1_700_000_000, 123_456_789);
  let got = parse_rx_time(&buf).expect("expected a parsed timestamp");
  let want = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
  assert_eq!(got, want);
}

#[cfg(all(has_recv_timestamp, not(recv_timestamp_ns)))]
#[test]
fn parses_scm_timestamp() {
  use std::time::{Duration, SystemTime};
  let buf = synth_rx_timestamp_cmsg(1_700_000_000, 654_321);
  let got = parse_rx_time(&buf).expect("expected a parsed timestamp");
  let want = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 654_321 * 1000);
  assert_eq!(got, want);
}

/// A control buffer with no timestamp cmsg yields None on every Unix target.
#[test]
fn no_timestamp_cmsg_yields_none() {
  assert_eq!(parse_rx_time(&[]), None);
}

/// `size` zeroed bytes with each `(offset, native-endian field bytes)` written
/// in — the byte image of a C struct, assembled field by field.
///
/// The point is that **every byte is initialized**, padding included. Building
/// the struct and then reading it as `&[u8]` (`slice::from_raw_parts` over
/// `addr_of!`) does not have that property: a struct literal leaves padding
/// uninitialized, and a `&[u8]` covering an uninitialized byte is undefined
/// behaviour whatever the struct is made of — "plain old data" is not the
/// question, padding is. Nor is it hypothetical here: `libc::timeval` is
/// `{ time_t, suseconds_t }`, which on Apple/aarch64 is 8 + 4 bytes inside a
/// 16-byte, 8-aligned struct, so bytes 12..16 are tail padding. `libc::timespec`
/// happens to have none on that target, which is luck rather than a rule — a
/// 32-bit target with a 64-bit `time_t` pads it too.
///
/// A kernel writes those padding bytes as whatever its stack held, and no parse
/// in this crate reads them, so zeroing is a faithful stand-in as well as a
/// sound one.
#[cfg(has_recv_timestamp)]
fn c_struct_bytes(size: usize, fields: &[(usize, &[u8])]) -> Vec<u8> {
  let mut buf = vec![0u8; size];
  for (offset, value) in fields {
    buf[*offset..*offset + value.len()].copy_from_slice(value);
  }
  buf
}

/// A synthesized kernel receive-timestamp cmsg: the `SCM_TIMESTAMPNS` /
/// `timespec` pair on Linux/Android, the `SCM_TIMESTAMP` / `timeval` pair on
/// every other target that delivers one. `secs` and `sub` are written into the
/// two fields verbatim, so a caller can put a value in either that no kernel
/// would produce.
///
/// Assembled through [`c_struct_bytes`] rather than transmuted from a struct
/// literal — see there for why that is a soundness requirement and not a style
/// choice. No `unsafe` is involved on either layout.
///
/// Each field is written at `offset_of!` in the width of the alias libc itself
/// declares that field with (`time_t`, `c_long`, `suseconds_t`). A target where
/// that stopped holding would not fail silently: `parses_scm_timestampns` /
/// `parses_scm_timestamp` round-trip a known value back through the real
/// `parse_rx_time`, which reads the genuine struct.
#[cfg(has_recv_timestamp)]
fn synth_rx_timestamp_cmsg(secs: i64, sub: i64) -> Vec<u8> {
  #[cfg(recv_timestamp_ns)]
  let (ty, payload) = (
    libc::SCM_TIMESTAMPNS,
    c_struct_bytes(
      core::mem::size_of::<libc::timespec>(),
      &[
        (
          core::mem::offset_of!(libc::timespec, tv_sec),
          &(secs as libc::time_t).to_ne_bytes()[..],
        ),
        (
          core::mem::offset_of!(libc::timespec, tv_nsec),
          &(sub as libc::c_long).to_ne_bytes()[..],
        ),
      ],
    ),
  );
  #[cfg(not(recv_timestamp_ns))]
  let (ty, payload) = (
    libc::SCM_TIMESTAMP,
    c_struct_bytes(
      core::mem::size_of::<libc::timeval>(),
      &[
        (
          core::mem::offset_of!(libc::timeval, tv_sec),
          &(secs as libc::time_t).to_ne_bytes()[..],
        ),
        (
          core::mem::offset_of!(libc::timeval, tv_usec),
          &(sub as libc::suseconds_t).to_ne_bytes()[..],
        ),
      ],
    ),
  );
  synth_cmsg(libc::SOL_SOCKET, ty, &payload)
}

/// The two doors onto a receive stamp must return the same evidence for the
/// same bytes.
///
/// [`RxEvidence::from_meta`] serves a driver that receives through this crate;
/// [`RxEvidence::from_cmsgs`] serves one that owns its own `recvmsg` and holds
/// only the control buffer. They exist so no driver has to decode
/// `SCM_TIMESTAMP`/`SCM_TIMESTAMPNS` for itself — which is worth nothing if the
/// second door drops the stamp or reads it differently, and neither failure is
/// visible from outside: `RxEvidence` is opaque, and a lost stamp only weakens a
/// claim to `Degraded` rather than breaking anything a test would notice.
///
/// Note what this test does to run at all: it **synthesizes** the buffer. That
/// is the plain demonstration that `from_cmsgs` cannot tell a kernel's control
/// buffer from an encoded one, and why its documentation states the origin of
/// the bytes as an obligation on the caller rather than as something checked
/// here.
#[cfg(has_recv_timestamp)]
#[test]
fn rx_evidence_from_cmsgs_carries_the_same_stamp_as_from_meta() {
  use crate::selfsend::RxEvidence;

  let buf = synth_rx_timestamp_cmsg(1_700_000_000, 123_456);
  let stamp = parse_rx_time(&buf).expect("a well-formed timestamp cmsg must parse");
  // The witnesses are BLIND rather than absent-for-a-reason, and that is the
  // honest filler: this `RecvMeta` exists only to carry the stamp to
  // `RxEvidence::from_meta`, and RFC 6762 §11 reads neither witness on this
  // path. A `Lost` or `Declined` here would assert something about a kernel that
  // never ran.
  let meta = RecvMeta::new(
    0,
    std::net::SocketAddr::from(([127, 0, 0, 1], 5353)),
    std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    crate::onlink::DestinationWitness::blind(),
    crate::onlink::IfaceWitness::blind(),
    Some(stamp),
  );
  assert_eq!(
    RxEvidence::from_cmsgs(&buf),
    RxEvidence::from_meta(&meta),
    "the control-buffer door must carry the stamp the RecvMeta door carries"
  );
  assert_ne!(
    RxEvidence::from_cmsgs(&buf),
    RxEvidence::none(),
    "a buffer that does carry a timestamp must not degrade to no evidence"
  );
}

/// A buffer with nothing in it — or nothing this crate can read — degrades
/// rather than inventing a stamp. `none()` is the safe answer: it costs only the
/// ordering arm of the match.
#[test]
fn rx_evidence_from_cmsgs_degrades_on_a_buffer_with_no_timestamp() {
  use crate::selfsend::RxEvidence;

  assert_eq!(RxEvidence::from_cmsgs(&[]), RxEvidence::none());
  assert_eq!(
    RxEvidence::from_cmsgs(&synth_cmsg(libc::SOL_SOCKET, libc::SCM_RIGHTS, &[0u8; 4])),
    RxEvidence::none(),
    "a cmsg that is not a receive timestamp must not be read as one"
  );
}

/// An absurd, malformed timestamp cmsg must not panic the parse. Two panic
/// vectors, and both are exercised: a sub-second field far past its modulus,
/// which `Duration::new`'s carry could overflow-panic on, and `tv_sec =
/// i64::MAX`, which a `UNIX_EPOCH + Duration` `Add` would overflow-panic on.
/// Reaching the assertion is the proof.
///
/// They need two buffers now, not one. The modulus gate declines an
/// out-of-range sub-second field before anything arithmetic runs, so the
/// all-`i64::MAX` buffer never reaches the seconds arithmetic at all; a
/// well-formed sub-second field beside the absurd `tv_sec` is what still puts
/// it there.
///
/// Neither result is required to be `None`, only well-defined — declined, or a
/// real [`SystemTime`]. `tv_sec`/`tv_nsec` are `time_t` / `c_long`, and on Linux
/// `UNIX_EPOCH.checked_add(Duration::new(i64::MAX as u64, _))` stays in range
/// and answers `Some`. The guarantee is "no panic", not a forced decline.
#[cfg(has_recv_timestamp)]
#[test]
fn absurd_timestamp_cmsg_does_not_panic() {
  use crate::selfsend::RxEvidence;

  for buf in [
    // Absurd in both fields; the sub-second gate is what declines it.
    synth_rx_timestamp_cmsg(i64::MAX, i64::MAX),
    // Absurd seconds, valid sub-second field — this one reaches
    // `Duration::new` and `checked_add`.
    synth_rx_timestamp_cmsg(i64::MAX, 0),
  ] {
    // Reaching the line after this call is the assertion.
    let stamp = parse_rx_time(&buf);
    if let Some(t) = stamp {
      // If a stamp came back it must be a real `SystemTime` — no panic in
      // `duration_since` either. The value is unspecified for garbage input;
      // only well-definedness is required.
      let _ = t.duration_since(std::time::UNIX_EPOCH);
    }
    // And the constructor a driver actually reaches must absorb it identically,
    // since that is the path a completion-based driver's buffer takes.
    let _ = RxEvidence::from_cmsgs(&buf);
  }
}

/// The sub-second field's modulus is a boundary, and the boundary value itself
/// is on the reject side.
///
/// `tv_nsec == 1_000_000_000` is not a nanosecond count; it is one second. The
/// gate used to be a sign test, so such a field passed and `Duration::new`
/// silently carried it — `parse_rx_time` returned `Some` for a malformed stamp,
/// one whole second later than the field reads, and the self-send match then ran
/// at [`crate::selfsend::MatchMode::Ordered`] strength on it. Two asserts, one
/// apart: `999_999_999` must still be admitted, or the fix would have cost the
/// last representable nanosecond.
#[cfg(recv_timestamp_ns)]
#[test]
fn nanoseconds_admit_below_the_modulus_and_reject_at_it() {
  use std::time::{Duration, SystemTime};

  assert_eq!(
    parse_rx_time(&synth_rx_timestamp_cmsg(1_700_000_000, 999_999_999)),
    Some(SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_999)),
    "the largest legal tv_nsec must still parse, and must not be rounded"
  );
  assert_eq!(
    parse_rx_time(&synth_rx_timestamp_cmsg(1_700_000_000, 1_000_000_000)),
    None,
    "tv_nsec at its modulus is malformed and must decline, not carry into the \
     next second"
  );
}

/// The `timeval` twin of the boundary above: `tv_usec == 1_000_000` is one
/// second, not a microsecond count, and multiplying it by 1000 hands
/// `Duration::new` a full 1e9 nanoseconds to carry. Same two asserts, one apart.
#[cfg(all(has_recv_timestamp, not(recv_timestamp_ns)))]
#[test]
fn microseconds_admit_below_the_modulus_and_reject_at_it() {
  use std::time::{Duration, SystemTime};

  assert_eq!(
    parse_rx_time(&synth_rx_timestamp_cmsg(1_700_000_000, 999_999)),
    Some(SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_000)),
    "the largest legal tv_usec must still parse, and must not be rounded"
  );
  assert_eq!(
    parse_rx_time(&synth_rx_timestamp_cmsg(1_700_000_000, 1_000_000)),
    None,
    "tv_usec at its modulus is malformed and must decline, not carry into the \
     next second"
  );
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

/// Regression test: a malformed header must fuse the iterator, not just
/// return an `Err` from the call that found it.
///
/// Every in-crate caller of `CmsgIter` bails on the first `Err` (via `?`,
/// `.ok()?`, or `let Ok(..) else { break }`), so this drives it through
/// `.collect()` instead — a consumer that does NOT stop at the first `Err`
/// and would have looped forever before `next()` cleared `rest` on both
/// error paths, since `cmsg_len` was the only way to find the next header
/// and the same unusable header was re-read on every call.
///
/// Covers the two length checks; the third non-progress path — a stride
/// computation that cannot advance past the header it was meant to skip —
/// is covered directly against `cmsg_advance` instead
/// (`cmsg_advance_rejects_a_u32_wrapped_stride` and
/// `cmsg_advance_holds_across_the_reachable_domain_below_64_bit`): reaching
/// it through `CmsgIter` itself needs a real multi-gigabyte buffer, which
/// `cmsg_advance` exists precisely to make unnecessary.
#[cfg(unix)]
#[test]
#[allow(unsafe_code)]
fn cmsg_iter_fuses_after_malformed_header() {
  let hdr_size = core::mem::size_of::<libc::cmsghdr>();
  let bytes_of = |h: &libc::cmsghdr| -> std::vec::Vec<u8> {
    // SAFETY: read exactly `size_of::<cmsghdr>()` bytes of a live cmsghdr.
    unsafe {
      core::slice::from_raw_parts((h as *const libc::cmsghdr).cast::<u8>(), hdr_size).to_vec()
    }
  };

  // Path 1: cmsg_len < hdr_size.
  let zeroed: libc::cmsghdr = unsafe { core::mem::zeroed() };
  let short = bytes_of(&zeroed);
  let items: std::vec::Vec<_> = CmsgIter::new(&short).collect();
  assert_eq!(
    items.len(),
    1,
    "a too-short cmsg_len must yield exactly one item, not hang"
  );
  assert!(items[0].is_err());

  // Path 2: cmsg_len > rest.len().
  let mut big: libc::cmsghdr = unsafe { core::mem::zeroed() };
  big.cmsg_len = (hdr_size + 4096) as _;
  let long = bytes_of(&big);
  let items: std::vec::Vec<_> = CmsgIter::new(&long).collect();
  assert_eq!(
    items.len(),
    1,
    "an oversized cmsg_len must yield exactly one item, not hang"
  );
  assert!(items[0].is_err());
}

/// `cmsg_advance` must advance by exactly `CMSG_SPACE(datalen)` for an
/// ordinary, small payload — same value the crate's own builder/parser
/// agreement above relies on. Portable: unlike the u32-boundary cases below,
/// nothing here depends on the target's pointer width.
#[cfg(unix)]
#[test]
fn cmsg_advance_matches_the_normal_stride() {
  let data_start = cmsg_data_offset();
  let normal_datalen = 4usize;
  assert_eq!(
    cmsg_advance(data_start + normal_datalen, data_start),
    Some(cmsg_stride(normal_datalen)),
    "a normal payload length must produce the libc-computed stride"
  );
}

/// Direct tests of `cmsg_advance`'s `u32`-overflow boundary — the arithmetic
/// `CmsgIter::next` relies on to know it may trust a computed stride,
/// checked here without allocating anything.
///
/// `libc::CMSG_SPACE` takes and returns a `c_uint` (32 bits) but aligns in
/// `usize` — 64 bits here — before truncating the sum back on return, so a
/// `datalen` near `u32::MAX` overflows only at that final truncation,
/// wrapping the returned stride to something smaller than the header it was
/// meant to skip, including exactly zero.
///
/// 64-bit only: reaching any of these `cmsg_len` values needs a real slice
/// at least that long (`cmsg_len <= rest.len()` is enforced by the caller),
/// and on a narrower target no slice can be long enough — see
/// `cmsg_advance_holds_across_the_reachable_domain_below_64_bit`. The
/// `usize` arithmetic these cases construct their inputs with (e.g.
/// `u32::MAX as usize + 1`) also overflows `usize` itself on a target where
/// `usize` is only 32 bits, which is the other reason this is 64-bit-only.
#[cfg(unix)]
#[cfg(target_pointer_width = "64")]
#[test]
fn cmsg_advance_rejects_a_u32_wrapped_stride() {
  let data_start = cmsg_data_offset();

  // datalen == u32::MAX: ALIGN(u32::MAX) rounds up to exactly 2**32 under
  // any power-of-two alignment (0xFFFF_FFFF is one less than any such
  // alignment), so CMSG_SPACE(u32::MAX) truncates to precisely `data_start`
  // — always < cmsg_len, so it must be rejected rather than read as a
  // `data_start`-sized advance.
  let at_u32_max = u32::MAX as usize;
  assert_eq!(
    cmsg_advance(data_start + at_u32_max, data_start),
    None,
    "datalen == u32::MAX must be rejected, not treated as a valid stride"
  );

  // datalen one past u32::MAX: does not fit the `c_uint` CMSG_SPACE takes at
  // all, so it must be rejected before any libc call.
  let past_u32_max = u32::MAX as usize + 1;
  assert_eq!(
    cmsg_advance(data_start + past_u32_max, data_start),
    None,
    "a datalen that overflows c_uint must be rejected"
  );

  // A datalen chosen so CMSG_SPACE's truncation lands on exactly zero:
  // ALIGN(datalen) == 2**32 - data_start (itself already ALIGN'd, since
  // data_start is), so + data_start truncates to 0 exactly. `advance == 0`
  // must be rejected, not read as "advance by nothing and try again" — the
  // caller has no other way to make progress.
  let wraps_to_zero = (u32::MAX - data_start as u32 + 1) as usize;
  assert_eq!(
    cmsg_advance(data_start + wraps_to_zero, data_start),
    None,
    "a datalen that wraps CMSG_SPACE to zero must be rejected"
  );
}

/// The `cmsg_advance` invariant (`advance >= cmsg_len`) holds across the
/// entire domain a target with a narrower-than-64-bit `usize` can actually
/// reach, checked at that domain's own upper edge.
///
/// No safe Rust slice can be longer than `isize::MAX` bytes — a
/// language-wide invariant, not specific to this crate — so `rest.len()`,
/// and therefore any `cmsg_len` a real `CmsgIter` could ever see, is bounded
/// by `isize::MAX`. On a 32-bit target that is roughly 2 GiB: far short of
/// the ~4 GiB `datalen` needs to reach the `u32` boundary in
/// `cmsg_advance_rejects_a_u32_wrapped_stride`, so `CMSG_SPACE` never
/// overflows for any `cmsg_len` reachable here. This is what makes the
/// production path safe on such a target without any extra guard: the
/// bound comes from what a slice can be, not from the arithmetic itself.
#[cfg(unix)]
#[cfg(not(target_pointer_width = "64"))]
#[test]
fn cmsg_advance_holds_across_the_reachable_domain_below_64_bit() {
  let data_start = cmsg_data_offset();
  let largest_reachable_cmsg_len = isize::MAX as usize;
  let advance = cmsg_advance(largest_reachable_cmsg_len, data_start).expect(
    "the largest cmsg_len any real slice could carry on this target must still be a valid stride",
  );
  assert!(
    advance >= largest_reachable_cmsg_len,
    "advance ({advance}) must reach at least as far as the largest reachable cmsg_len \
     ({largest_reachable_cmsg_len})"
  );
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
// buffers to the decoders and walkers, so they run on any host — which is what
// gives DragonFly, OpenBSD and NetBSD any coverage at all, since CI only
// cross-COMPILES those three and runs nothing on them. What they do NOT prove,
// on any host, is the PLUMBING: that the enabling sockopt is accepted, that the
// kernel actually attaches these cmsgs to a real mDNS datagram, that the
// interface index it reports matches `if_nametoindex`, or that the 256-byte
// control buffer still escapes `MSG_CTRUNC` with them present. That evidence
// can only come from a real host of each target, and until it does the parsers
// stay unwired — see `build.rs` for the full list.
//
// Where they run decides what the parse itself is worth. `synth_cmsg` frames
// every buffer from the compiled target's own `CMSG_LEN`/`CMSG_SPACE`, so
// cross-compiling this test binary for a BSD type-checks the layout against
// that target's real ABI constants — but the assertions execute on whatever
// host runs `cargo test`, with the per-target cmsg NUMBERS supplied as
// parameters. On FreeBSD they now execute on FreeBSD (ci.yml's `freebsd` job
// boots a VM), so there the layout is confirmed rather than assumed. On the
// other three, read them as "the decoders and the walk are correct given the
// layout", not as "the layout is confirmed on NetBSD". Neither reading is
// activation evidence: that bar is the four items at `build.rs`'s emit site,
// and it is about the kernel, not the bytes.
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

// ── The BSD IPv4 pair, as RFC 6762 §11 SEES it ──────────────────────────────
//
// Everything above asserts what the decoders recover. Nothing above asserts what
// the recovered pair DECIDES, and that gap is where the defect lived: a
// `DestinationWitness::Witnessed(224.0.0.251)` sitting beside an
// `IfaceWitness::Declined` reads as a perfectly reasonable pair, and a test that
// compares witness values calls it correct. It is not — that pair used to take
// §11's arm one, whose text is "regardless of source IP address", with nothing
// proving the datagram reached this endpoint on the link it bound.
//
// So the tests below drive `admits_ingress` and assert the VERDICT. The witness
// values are an intermediate, not the subject.
//
// This crate does not implement the rule they check. `hick_onlink::admits_ingress`
// withholds arm one's exemption from any datagram nothing scoped to the bound
// link, stated over the witness PAIR rather than over a cmsg shape — so it
// covers `IP_PKTINFO`'s zero-index square identically. What is checked HERE is
// that this crate's BSD receive path hands that rule an honest pair: both halves
// as the kernel produced them, with nothing pre-empted and nothing erased.

/// The bound interface index the §11 gate scopes to, and a different one for the
/// datagram that arrived on another NIC.
const BOUND_IFACE: u32 = 9;
const FOREIGN_IFACE: u32 = 11;

/// The receive-side sequence of `recv_with_meta` for the BSD IPv4 square,
/// without the syscall: `MSG_CTRUNC` short-circuits to the Lost/Lost pair before
/// any parse, and otherwise the parse runs and its result is taken as-is.
///
/// The `unwrap_or_else` arm spells the two absences with the same
/// `from_reporting_path` constructors `recv_with_meta`'s `witness_absent`
/// closure uses, since that closure is local to it.
fn bsd_v4_witnesses(cmsgs: &[u8], truncated: bool) -> (DestinationWitness, IfaceWitness) {
  if truncated {
    return (
      DestinationWitness::from_reporting_path(None, true),
      IfaceWitness::from_reporting_path(0, true),
    );
  }
  let peer: SocketAddr = ([203, 0, 113, 7], 5353).into();
  let meta =
    dstaddr_recvif_meta(cmsgs, IP_RECVDSTADDR_TY, IP_RECVIF_TY, 64, peer).unwrap_or_else(|_| {
      RecvMeta::new(
        64,
        peer,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        DestinationWitness::from_reporting_path(None, false),
        IfaceWitness::from_reporting_path(0, false),
        None,
      )
    });
  (meta.destination_witness(), meta.iface_witness())
}

/// Build the ancillary buffer for one square of the pair.
fn bsd_v4_cmsgs(destination: Option<Ipv4Addr>, iface: Option<u32>) -> Vec<u8> {
  let mut parts: Vec<(libc::c_int, libc::c_int, Vec<u8>)> = Vec::new();
  if let Some(dst) = destination {
    parts.push((libc::IPPROTO_IP, IP_RECVDSTADDR_TY, dst.octets().to_vec()));
  }
  if let Some(idx) = iface {
    parts.push((
      libc::IPPROTO_IP,
      IP_RECVIF_TY,
      synth_sockaddr_dl(u16::try_from(idx).unwrap(), b"em0"),
    ));
  }
  let borrowed: Vec<(libc::c_int, libc::c_int, &[u8])> = parts
    .iter()
    .map(|(l, t, d)| (*l, *t, d.as_slice()))
    .collect();
  synth_cmsgs(&borrowed)
}

/// The four-square table — both cmsgs, destination only, interface only,
/// neither — across both truncation states, decided by `admits_ingress` under
/// FreeBSD/DragonFly conditions: `libc` binds no `MSG_MCAST` there, so
/// `delivery` is `None` and a datagram with no witnessed destination reaches
/// §11's source-prefix rule.
///
/// # The square this test exists for
///
/// Destination only, not truncated. The parse reports
/// `Witnessed(224.0.0.251)` + `Declined`, and both halves reach the gate
/// untouched. What CHANGED is what the gate does with that pair: §11 arm one's
/// exemption is the one admission in the whole rule that weighs nothing about
/// where the datagram came from, so it is granted only to a datagram something
/// scoped to the bound link. Nothing scoped this one —
/// `arrived_on_bound_interface` PERMITS `Declined`, an availability invariant it
/// is tested for — so the source arm decides instead.
///
/// Every source below is OFF this interface's prefix. That is the point: an
/// off-prefix source is refused by every rule §11 has EXCEPT arm one, so it is
/// the probe that separates "arm one was taken" from "arm one was not".
#[test]
fn bsd_v4_partial_pair_does_not_buy_arm_one_without_link_proof() {
  use crate::onlink::{Admit, BoundLink, Refuse, Verdict, admits_ingress};

  // Named so the row shape does not read as a `clippy::type_complexity` blob.
  type Row = (bool, Option<Ipv4Addr>, Option<u32>, Verdict, &'static str);

  let group = Ipv4Addr::new(224, 0, 0, 251);
  // Off this interface's prefix, so only §11 arm one can admit it.
  let src: SocketAddr = ([203, 0, 113, 7], 5353).into();
  let addrs = [(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24u8)];
  let link = BoundLink::new(BOUND_IFACE, false, &addrs);

  // (truncated, destination cmsg, interface cmsg, expected verdict, what it is)
  let rows: [Row; 8] = [
    (
      false,
      Some(group),
      Some(BOUND_IFACE),
      // WIDER than the behaviour before the pair was decoded at all, and
      // CORRECT: §11 calls admitting a group datagram regardless of source
      // "essential ... in unusual configurations, such as multiple logical IP
      // subnets overlayed on a single link". Refusing it was the bug. It is safe
      // here and only here, because the interface half scoped it.
      Verdict::Admit(Admit::MdnsGroup),
      "both cmsgs, our interface: arm one, with the scoping that makes its \
       source exemption safe to grant",
    ),
    (
      false,
      Some(group),
      Some(FOREIGN_IFACE),
      // The scoping doing its job. A wildcard-bound socket on a multi-homed
      // host is handed every NIC's copy of the group traffic.
      Verdict::Refuse(Refuse::ForeignLink),
      "both cmsgs, another NIC: the interface check runs first and refuses \
       before arm one is reached",
    ),
    (
      false,
      Some(group),
      None,
      // THE FIX. On `main` this was `Admit(Admit::MdnsGroup)` — arm one taken on
      // a datagram that never proved it arrived on our link. The destination is
      // still WITNESSED here; what it no longer buys is the exemption.
      //
      // This refusal is the KNOWN availability residual, and FreeBSD/DragonFly
      // are where it lands: they bind no `MSG_MCAST`, so the unscoped group has
      // nothing but §11's source arm to fall back on. It is spelled apart from a
      // plain `SourceOffLink` so an operator can watch it — see
      // `mdns_ingress_unscoped_group_refusals`.
      Verdict::Refuse(Refuse::UnscopedGroupSourceOffLink),
      "destination only: nothing scoped this datagram, so arm one's exemption \
       is withheld and the source arm refuses an off-prefix sender",
    ),
    (
      false,
      None,
      Some(BOUND_IFACE),
      Verdict::Refuse(Refuse::SourceOffLink),
      "interface only, our interface: no destination, so the source rule \
       decides and an off-prefix sender is refused",
    ),
    (
      false,
      None,
      Some(FOREIGN_IFACE),
      Verdict::Refuse(Refuse::ForeignLink),
      "interface only, another NIC: the lone interface half still refuses",
    ),
    (
      false,
      None,
      None,
      Verdict::Refuse(Refuse::SourceOffLink),
      "neither cmsg: the kernel skipped both under mbuf pressure, the parse \
       degrades rather than erroring the datagram away, and the source rule \
       decides",
    ),
    // Both truncation rows below: `recv_with_meta` returns Lost/Lost on
    // `MSG_CTRUNC` WITHOUT parsing, so all four squares collapse onto one, and
    // `Lost` accuses our own control buffer rather than the sender. The
    // interface check refuses on it before the destination is looked at.
    (
      true,
      Some(group),
      Some(BOUND_IFACE),
      Verdict::Refuse(Refuse::LinkWitnessLost),
      "TRUNCATED, both cmsgs on the wire: our buffer overflowed, which is this \
       side's defect and refuses",
    ),
    (
      true,
      Some(group),
      None,
      Verdict::Refuse(Refuse::LinkWitnessLost),
      "TRUNCATED, destination only: same refusal, decided at the interface \
       stage before any destination arm",
    ),
  ];

  for (truncated, dst, iface, want, what) in rows {
    let cmsgs = bsd_v4_cmsgs(dst, iface);
    let (destination, iface_witness) = bsd_v4_witnesses(&cmsgs, truncated);
    assert_eq!(
      admits_ingress(src, destination, None, link, iface_witness),
      want,
      "{what} (destination={destination:?}, iface={iface_witness:?})"
    );
  }

  // Withholding is not refusing, and this is the row that says so: the SAME
  // unscoped group datagram from an ON-prefix sender is admitted, on the source
  // arm and named as such. A rule that refused here would be deafness rather
  // than scoping.
  let on_prefix: SocketAddr = ([192, 168, 1, 50], 5353).into();
  let (destination, iface_witness) = bsd_v4_witnesses(&bsd_v4_cmsgs(Some(group), None), false);
  assert_eq!(
    destination,
    DestinationWitness::Witnessed(IpAddr::V4(group)),
    "the destination reaches the gate WITNESSED — the privilege is withheld at \
     the gate, never by erasing the address"
  );
  assert_eq!(
    admits_ingress(on_prefix, destination, None, link, iface_witness),
    Verdict::Admit(Admit::UnscopedMdnsGroup),
    "an unscoped group from an on-prefix sender is admitted on the source arm, \
     under its own name"
  );
}

/// The same table under OpenBSD/NetBSD conditions, where `libc` binds
/// `MSG_MCAST` and `recv_with_meta` therefore hands §11 a
/// `LinkDelivery::Multicast` beside the witnesses.
///
/// Those two targets are where the availability residual does NOT land. An
/// unscoped mDNS-group destination takes the same coarse-delivery arm a datagram
/// with no destination witness takes, so `MSG_MCAST` admits it — as
/// `Admit::UnscopedMdnsGroup`, never as arm one, because the flag says only
/// "some group" and cannot buy an exemption the finer evidence failed to earn.
///
/// That is monotonicity rather than leniency: this square carries strictly more
/// evidence than the one below it and must not fare worse. FreeBSD and DragonFly
/// bind no `MSG_MCAST`, so the same datagram reaches §11's source arm there and
/// an off-prefix sender IS refused — the residual, named in `hick-onlink`'s
/// module header and counted as `Refuse::UnscopedGroupSourceOffLink`.
#[test]
fn bsd_v4_partial_pair_on_netbsdlike_is_admitted_by_the_coarse_multicast_flag() {
  use crate::onlink::{Admit, BoundLink, LinkDelivery, Refuse, Verdict, admits_ingress};

  type Row = (bool, Option<Ipv4Addr>, Option<u32>, Verdict, &'static str);

  let group = Ipv4Addr::new(224, 0, 0, 251);
  let src: SocketAddr = ([203, 0, 113, 7], 5353).into();
  let addrs = [(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24u8)];
  let link = BoundLink::new(BOUND_IFACE, false, &addrs);

  let rows: [Row; 5] = [
    (
      false,
      Some(group),
      Some(BOUND_IFACE),
      Verdict::Admit(Admit::MdnsGroup),
      "both cmsgs: the witnessed destination names WHICH group, so arm one is \
       taken by address rather than by flag",
    ),
    (
      false,
      Some(group),
      None,
      // ADMITTED, and NOT as arm one. The coarse flag is worth here exactly what
      // it is worth to the datagram beside this one that recovered no
      // destination at all — no more, so it never buys the exemption, and no
      // less, so this square cannot REFUSE what the strictly less-informed
      // square ADMITS. Refusing here punished partial evidence: an attacker who
      // can make one cmsg go missing can make both go missing and be admitted
      // through the blind square anyway, so it stopped nobody and taxed the
      // off-prefix peers §11 calls essential in full.
      Verdict::Admit(Admit::UnscopedMdnsGroup),
      "destination only: the coarse flag admits it, under its own name rather \
       than as arm one — so OpenBSD/NetBSD carry no availability residual",
    ),
    (
      false,
      Some(group),
      Some(FOREIGN_IFACE),
      Verdict::Refuse(Refuse::ForeignLink),
      "both cmsgs, another NIC: MSG_MCAST does not outrank the link scoping",
    ),
    (
      false,
      None,
      Some(BOUND_IFACE),
      // Where the flag DOES decide: no destination at all. This is the residual
      // `hick-onlink` names and does not close — a foreign group is admitted
      // here too, because "which group" is not a bit.
      Verdict::Admit(Admit::BlindMulticastDelivery),
      "interface only: with no destination the coarse flag is all there is, and \
       it admits any group",
    ),
    (
      true,
      Some(group),
      None,
      Verdict::Refuse(Refuse::LinkWitnessLost),
      "TRUNCATED: our own buffer failed, and the coarse flag is not evidence \
       about that",
    ),
  ];

  for (truncated, dst, iface, want, what) in rows {
    let cmsgs = bsd_v4_cmsgs(dst, iface);
    let (destination, iface_witness) = bsd_v4_witnesses(&cmsgs, truncated);
    assert_eq!(
      admits_ingress(
        src,
        destination,
        Some(LinkDelivery::Multicast),
        link,
        iface_witness
      ),
      want,
      "{what} (destination={destination:?}, iface={iface_witness:?})"
    );
  }
}

/// Withholding the privilege must NOT cost the classification, on the very
/// square where the privilege is withheld.
///
/// The first attempt at this fix enforced the rule in this crate by rewriting a
/// lone `Witnessed` destination to `Declined`. That withheld arm one — and threw
/// away the address, which is what every NEGATIVE class is decided by. A foreign
/// multicast group stopped being refused AS a foreign group and fell to the
/// coarse arms: admitted outright by `MSG_MCAST` on OpenBSD/NetBSD, and admitted
/// for any in-prefix sender on FreeBSD/DragonFly. Withholding a privilege by
/// destroying the evidence it rests on gives away everything else that evidence
/// was refusing.
///
/// So this asserts the opposite of what it once did: the address survives, and
/// every refusal it earns is still named — under both delivery regimes, from an
/// IN-prefix sender the source arm would otherwise have admitted, so the refusal
/// is attributable to the destination and cannot be the source's doing.
#[test]
fn bsd_v4_withholding_the_privilege_keeps_the_negative_classification() {
  use crate::onlink::{BoundLink, LinkDelivery, Refuse, Verdict, admits_ingress};

  // IN-prefix, so the source arm would admit and only the destination can refuse.
  let src: SocketAddr = ([192, 168, 1, 50], 5353).into();
  let addrs = [(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24u8)];
  let link = BoundLink::new(BOUND_IFACE, false, &addrs);

  for (dst, want, what) in [
    (
      Ipv4Addr::new(224, 0, 0, 252),
      Refuse::ForeignGroup,
      "LLMNR's group, not ours",
    ),
    (
      Ipv4Addr::BROADCAST,
      Refuse::BroadcastAddressed,
      "RFC 919's limited broadcast",
    ),
    (
      Ipv4Addr::new(192, 168, 1, 200),
      Refuse::DestinationNotHeld,
      "a neighbour's address on our own subnet",
    ),
  ] {
    let cmsgs = bsd_v4_cmsgs(Some(dst), None);
    let (destination, iface_witness) = bsd_v4_witnesses(&cmsgs, false);
    assert_eq!(
      destination,
      DestinationWitness::Witnessed(IpAddr::V4(dst)),
      "{what}: the lone destination reaches the gate as the kernel produced it"
    );
    // Both delivery regimes: a witnessed destination puts `admits_ingress` in
    // its first regime, where the coarse flag decides nothing, so all four BSDs
    // must name the same refusal.
    for delivery in [None, Some(LinkDelivery::Multicast)] {
      assert_eq!(
        admits_ingress(src, destination, delivery, link, iface_witness),
        Verdict::Refuse(want),
        "{what}: an unscoped datagram loses arm one and keeps every refusal its \
         destination earns ({delivery:?})"
      );
    }
  }
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

/// A kernel that emits `IP_PKTINFO` but names NO interface is a decline, not a
/// failed proof — and its destination is still witnessed.
///
/// Linux reaches this: `ipv4_pktinfo_prepare` (`net/ipv4/ip_sockglue.c`) sets
/// `pktinfo->ipi_ifindex = 0` and `ipi_spec_dst = 0` in its `else` branch, taken
/// when `skb_rtable(skb)` is `NULL`, while `ip_cmsg_recv_pktinfo` fills
/// `info.ipi_addr` from `ip_hdr(skb)->daddr` regardless. Apple's
/// `ip6_savecontrol_v4` has the same shape:
/// `pi6.ipi6_ifindex = (m && m->m_pkthdr.rcvif) ? m->m_pkthdr.rcvif->if_index : 0`.
///
/// It is the ONLY form of `Declined` reachable on those two platforms — an
/// absent cmsg is not a state either produces, because Linux's `put_cmsg` writes
/// into the caller's own buffer and flags `MSG_CTRUNC`, and Apple returns
/// `ENOBUFS` and drops the datagram. So this is where the RFC 6762 §11 widening
/// actually lands there, and it is much narrower than a blind square: the
/// destination partition still runs in full and only the link scoping is lost.
#[cfg(has_ip_pktinfo)]
#[test]
fn a_present_pktinfo_naming_no_interface_declines_rather_than_failing_a_proof() {
  let cmsgs = synth_cmsg_v4(Ipv4Addr::new(192, 168, 1, 100), 0);
  let peer: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5353).into();
  let meta = parse_pktinfo_v4(&cmsgs, 200, peer).expect("a present cmsg parses");

  assert_eq!(
    meta.iface_witness(),
    crate::onlink::IfaceWitness::Declined,
    "a zero ipi_ifindex inside a PRESENT cmsg is the kernel answering \"I do \
     not know which interface\" — nothing was lost on our side, and a bigger \
     control buffer would not change it"
  );
  assert_eq!(
    meta.destination_witness(),
    crate::onlink::DestinationWitness::Witnessed(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
    "and the DESTINATION off the same cmsg is untouched, so §11's destination \
     partition still decides in full"
  );
  // Not `Lost`: that is reserved for `MSG_CTRUNC`, which rides on the message
  // header and which a parser defined over a byte slice cannot even observe.
  assert_ne!(meta.iface_witness(), crate::onlink::IfaceWitness::Lost);
}

// ============================================================================
// EVIDENCE FOR `has_ip_dstaddr_recvif`, the capability flip in `build.rs`.
//
// Item 4 (`MSG_CTRUNC` stays clear) is measured below on EVERY host: it is
// arithmetic over `libc`'s own `CMSG_SPACE` and needs no BSD to be true. Items
// 1-3 need a kernel that actually delivers the cmsgs, so they are the two live
// tests after it — compiled only where the capability is set, and executed by
// ci.yml's `freebsd` job, which names all three in `REQUIRED_TESTS`.
// ============================================================================

/// `CMSG_SPACE` for one cmsg of `payload` bytes, asked of `libc` rather than
/// derived: `CMSG_ALIGN` is 4 on x86 NetBSD and 8 on x86_64, and the header it
/// pads is 12 bytes on the BSDs against 16 on Linux, so no constant written here
/// would be right on more than one target.
fn cmsg_space(payload: usize) -> usize {
  // SAFETY: `CMSG_SPACE` is pure length arithmetic on an integer and
  // dereferences nothing; `libc` marks it `unsafe` by convention only. This is
  // the same call `cmsg_advance` makes in the production walk, which is what
  // makes this measurement and the parser agree on every target.
  #[allow(unsafe_code)]
  unsafe {
    libc::CMSG_SPACE(payload as libc::c_uint) as usize
  }
}

/// EVIDENCE ITEM 4 for `has_ip_dstaddr_recvif`: our own control buffer is large
/// enough that the kernel never has to set `MSG_CTRUNC`.
///
/// This matters more than a sizing check normally would.
/// [`crate::onlink::DestinationWitness::Lost`] REFUSES, and `MSG_CTRUNC` is the
/// only thing that mints it — so a buffer we sized too small is a self-inflicted
/// outage wearing the shape of a security decision. Adding the
/// `IP_RECVDSTADDR`/`IP_RECVIF` pair is exactly the kind of change that could
/// cause one, and the standing rule at the `build.rs` emit site requires the
/// figure to be MEASURED rather than asserted.
///
/// The worst case is summed per-target from what `try_bind_v4`/`try_bind_v6`
/// actually enable, at the widest payload each cmsg can carry, with every term a
/// literal size taken from the kernel that emits it — not from a production
/// function, which would agree with itself whatever it did. One socket is one
/// family, so the two families are summed separately and the larger taken.
#[test]
fn control_buffer_holds_every_cmsg_this_target_enables() {
  // The IPv4 destination/interface shape. Exactly one of the two is enabled on
  // any target — see `try_bind_v4_inner` — so this is a choice, not a sum.
  let v4_destination = if cfg!(has_ip_pktinfo) {
    // `struct in_pktinfo`, 12 bytes on Linux/Apple: ipi_ifindex, ipi_spec_dst,
    // ipi_addr.
    cmsg_space(12)
  } else if cfg!(has_ip_dstaddr_recvif) {
    // Two separate cmsgs. `IP_RECVDSTADDR` is a bare `struct in_addr`.
    // `IP_RECVIF` is a `struct sockaddr_dl` of `sdl_len` bytes, and the kernels
    // copy the interface's own — so the widest payload is the full struct: 54
    // bytes on FreeBSD (46-byte `sdl_data`), 32 on OpenBSD, 24 on DragonFly and
    // 20 on NetBSD. FreeBSD's is the largest and is used for all four, so the
    // bound holds on every one of them whatever this host happens to be.
    cmsg_space(4) + cmsg_space(54)
  } else {
    0
  };
  // `IP_RECVTTL`: an `int` on Linux, a single `u_char` on the BSDs. The wider
  // reading is the safe one here.
  let v4_ttl = if cfg!(has_recv_hoplimit) {
    cmsg_space(4)
  } else {
    0
  };
  // `struct in6_pktinfo` is 20 bytes (ipi6_addr + ipi6_ifindex); `IPV6_HOPLIMIT`
  // is an `int`.
  let v6_destination = if cfg!(has_ipv6_pktinfo) {
    cmsg_space(20)
  } else {
    0
  };
  let v6_hoplimit = if cfg!(has_recv_hoplimit) {
    cmsg_space(4)
  } else {
    0
  };
  // Shared by both families: a `timespec` on Linux/Android, a `timeval`
  // elsewhere — 16 bytes either way.
  let timestamp = if cfg!(has_recv_timestamp) {
    cmsg_space(16)
  } else {
    0
  };

  let v4_worst = v4_destination + v4_ttl + timestamp;
  let v6_worst = v6_destination + v6_hoplimit + timestamp;
  let worst = v4_worst.max(v6_worst);

  // The buffer itself, read off the production type rather than restated.
  let capacity = core::mem::size_of::<CmsgBuf>();
  eprintln!("cmsg worst case: IPv4 {v4_worst}, IPv6 {v6_worst}, CmsgBuf {capacity}");
  assert!(
    worst <= capacity,
    "control buffer too small: this target's worst case is {worst} bytes (IPv4 \
     {v4_worst}, IPv6 {v6_worst}) against a {capacity}-byte CmsgBuf. MSG_CTRUNC \
     mints DestinationWitness::Lost, which REFUSES, so this would be a \
     self-inflicted outage and not a degradation — grow CmsgBuf and update its doc"
  );
  // Headroom for a cmsg this crate did not ask for. Not a second spelling of the
  // check above: this one fails while the buffer still technically fits, which
  // is the point at which the figure in `CmsgBuf`'s own doc has stopped holding.
  assert!(
    worst * 2 <= capacity,
    "this target's worst case is {worst} bytes against a {capacity}-byte \
     CmsgBuf — under 2x headroom for an unrequested cmsg. Re-derive the figure \
     in CmsgBuf's doc before relaxing this"
  );
  // The completion marker CI requires for evidence item 4. Spelled out rather
  // than routed through `evidence_complete`, which only exists where the BSD
  // capability is set; this test runs on every target.
  // Leading newline for the same reason as `evidence_complete`'s.
  eprintln!("\nhick-udp-evidence-complete: control_buffer_holds_every_cmsg_this_target_enables");
}

/// Emit the completion marker for one evidence test.
///
/// **Called only as the last statement, after every assertion.** CI requires
/// this line rather than libtest's `test <name> ... ok`, because those are
/// different claims: the status line says the test function RETURNED, and a
/// function that returned early because a precondition was unmet returns `ok`
/// just as loudly as one that asserted. This line says the test reached its
/// end, which is the only thing that makes the four evidence items behind
/// `has_ip_dstaddr_recvif` rest on execution rather than on a process starting.
///
/// It is not a defence against a hostile branch — that branch could print this
/// line directly, exactly as it could hollow out the assertions above it. It
/// closes the accidental case: an unmet precondition, a silently skipped body,
/// a test renamed out of the required list. See `ci.yml`'s `freebsd` job.
fn evidence_complete(test: &str) {
  // The LEADING NEWLINE is load-bearing. Under `--nocapture` libtest writes
  // `test <name> ... ` to stdout without a newline, runs the test, then writes
  // `ok`; a marker printed into that gap lands mid-line and no whole-line match
  // finds it. This was caught by simulating the CI check against a real harness
  // log rather than by reasoning about it. The newline closes libtest's partial
  // line so the marker always starts at column 0, which is what lets the check
  // stay an exact whole-line match — a substring match would find
  // `...-complete: foo` inside `...-complete: foo_v2` and re-open the rename
  // hole the whole-line matches exist to close.
  eprintln!("\nhick-udp-evidence-complete: {test}");
}

/// The index of an UP loopback interface.
///
/// FATAL rather than `Option`: every caller needs loopback to carry the group,
/// and a host without one cannot produce this evidence — which is a finding, not
/// a reason to report success.
#[cfg(has_ip_dstaddr_recvif)]
fn up_loopback_index() -> u32 {
  let ifaces = getifs::interfaces().expect(
    "interface enumeration must succeed: the BSD IPv4 evidence tests cannot run without it, \
     and returning early here would report success for a run that proved nothing",
  );
  ifaces
    .iter()
    .find(|i| i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP))
    .map(|i| i.index())
    .expect("no UP loopback interface: the BSD IPv4 evidence tests cannot be exercised here")
}

/// Send `payload` to `dst` from a socket pinned to `via` with `IP_MULTICAST_IF`,
/// on an EPHEMERAL port.
///
/// Ephemeral matters: the receiver below is on 5353 with `SO_REUSEPORT`, so a
/// sender sharing that port would join the same reuse group and the kernel could
/// hand it the unicast datagram the test is waiting for.
#[cfg(has_ip_dstaddr_recvif)]
fn send_from_interface(
  via: std::net::Ipv4Addr,
  dst: std::net::SocketAddrV4,
  payload: &[u8],
) -> std::io::Result<()> {
  let sock = socket2::Socket::new(
    socket2::Domain::IPV4,
    socket2::Type::DGRAM,
    Some(socket2::Protocol::UDP),
  )?;
  sock.bind(&std::net::SocketAddrV4::new(via, 0).into())?;
  sock.set_multicast_if_v4(&via)?;
  sock.set_multicast_loop_v4(true)?;
  sock.send_to(payload, &dst.into())?;
  Ok(())
}

/// Read from `fd` until the datagram carrying exactly `want` arrives, or give up.
///
/// Matching on the payload is what keeps these tests honest on a host with real
/// mDNS traffic: an assertion about "the destination of the datagram that came
/// back" is worth nothing if the datagram came from somebody else's responder.
/// Returns `None` on timeout, which each caller decides how to treat.
#[cfg(has_ip_dstaddr_recvif)]
fn recv_matching(fd: std::os::fd::RawFd, want: &[u8]) -> Option<RecvMeta> {
  let mut buf = [0u8; 2048];
  for _ in 0..400 {
    match recv_with_meta(fd, &mut buf, true) {
      Ok(meta) => {
        if buf.get(..meta.len()) == Some(want) {
          return Some(meta);
        }
      }
      Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
        std::thread::sleep(std::time::Duration::from_millis(5));
      }
      // Not a timeout and not something to report as "no datagram": the receive
      // path itself failed, which is the defect these tests exist to catch.
      Err(e) => panic!("recv_with_meta failed while waiting for the probe datagram: {e:?}"),
    }
  }
  None
}

/// EVIDENCE ITEM 1 for `has_ip_dstaddr_recvif`, verbatim: the enable returns 0
/// on a wildcard-bound `0.0.0.0:5353` socket joined to `224.0.0.251`.
///
/// `try_bind_v4` is the whole subject here. It calls
/// `platform::set_recv_dstaddr_recvif_v4` and then `verify_rx_dstaddr_recvif_v4`,
/// so a bind that returns `Ok` has ALREADY proven the kernel took both options —
/// a `setsockopt` failure would be `BindError::Io` and a kernel that accepted the
/// call without holding the flag would be `BindError::RxDestinationNotEnabled`.
/// The explicit read-back below is not a second copy of that check: it asserts
/// the values a caller can observe, so a `verify_` that had been silently
/// weakened to accept zero would fail HERE rather than passing quietly inside the
/// bind.
///
/// Nothing about this test can be lost to a delivery race — it sends no
/// datagram — which is why item 1 is separated from the destination evidence
/// below instead of being implied by it.
#[cfg(has_ip_dstaddr_recvif)]
#[test]
fn bsd_ipv4_bind_enables_the_receive_metadata_pair() {
  // NOT `expect_bind_or_skip`. That helper's whole job is to turn an
  // environment refusal into a silent success, which is right for a test that
  // merely happens to need a socket and wrong for the one that IS the evidence:
  // a run where the bind never happened has proven nothing about the enable, and
  // must not report `ok`. `try_bind_v4` sets SO_REUSEADDR/SO_REUSEPORT before
  // bind, so coexisting with another responder on 5353 is not a refusal here.
  let sock = try_bind_v4(MulticastOptionsV4::new(0)).expect(
    "try_bind_v4 on 0.0.0.0:5353 must succeed: this IS evidence item 1, so a bind that did \
     not happen is a failure and never a skip",
  );
  // The join half of item 1, on the interface that always exists. Fatal for the
  // same reason: item 1 is stated over a socket JOINED to 224.0.0.251.
  let lo = up_loopback_index();
  try_join_v4(&sock, lo).expect("joining 224.0.0.251 on loopback is part of evidence item 1");
  let (dstaddr, recvif) = crate::platform::get_recv_dstaddr_recvif_v4(&sock)
    .expect("getsockopt for IP_RECVDSTADDR/IP_RECVIF must succeed on this target");
  assert_ne!(
    dstaddr, 0,
    "IP_RECVDSTADDR must read back as enabled after try_bind_v4 — the whole \
     has_ip_dstaddr_recvif capability rests on this enable taking"
  );
  assert_ne!(
    recvif, 0,
    "IP_RECVIF must read back as enabled after try_bind_v4"
  );
  evidence_complete("bsd_ipv4_bind_enables_the_receive_metadata_pair");
}

/// A socket with the BSD receive-metadata pair enabled through the PRODUCTION
/// enabler and verifier, on an EPHEMERAL port.
///
/// Not `try_bind_v4`, and the reason is a real defect this harness caught rather
/// than a preference. `try_bind_v4` binds `0.0.0.0:5353` with `SO_REUSEPORT`, so
/// on any host already running an mDNS responder — every macOS, and any Linux or
/// BSD with Avahi — our socket joins that responder's reuse group and a UNICAST
/// datagram to port 5353 is delivered to exactly one member of it, chosen by the
/// kernel. The test would then fail, or worse pass, depending on which process
/// won. Multicast has no such lottery (every joined member gets a copy), which is
/// why only the unicast half was affected and why the port, not the send, is what
/// had to change. Item 1 is proven separately and deterministically by
/// `bsd_ipv4_bind_enables_the_receive_metadata_pair` above.
#[cfg(has_ip_dstaddr_recvif)]
fn bind_ephemeral_with_rx_metadata() -> std::net::UdpSocket {
  let sock = std::net::UdpSocket::bind("0.0.0.0:0")
    .expect("binding an ephemeral UDP socket must succeed; a host that cannot is not evidence");
  crate::platform::set_recv_dstaddr_recvif_v4(&sock)
    .expect("the IP_RECVDSTADDR/IP_RECVIF enable must succeed on this target");
  verify_rx_dstaddr_recvif_v4(&sock)
    .expect("the kernel must report both options enabled after the setsockopt calls");
  sock
    .set_nonblocking(true)
    .expect("setting O_NONBLOCK on our own socket must succeed");
  sock
}

/// EVIDENCE ITEMS 2 (address half) and 3 for `has_ip_dstaddr_recvif`, on a real
/// kernel: a group datagram yields the GROUP as its destination and a unicast
/// datagram yields the address it was sent to.
///
/// Both on ONE socket, because that is the pin that matters. RFC 6762 §11
/// partitions by destination: a parse that returned the group for a unicast
/// arrival would admit anything from anywhere, and one that returned a local
/// address for a group arrival would refuse the multicast §11 calls *essential*.
/// Two separate tests would not show that the two readings cannot collapse onto
/// each other.
///
/// # A datagram that does not come back is a FAILURE, not a skip
///
/// Everything environmental is checked before the sends and skips loudly: the
/// bind, the loopback interface, the join. Past that point the kernel has
/// accepted our membership and our send, the port is ours alone, and the BSD
/// `ip_output` loops a multicast datagram back whenever `IP_MULTICAST_LOOP` is
/// set. So a missing datagram is a real finding about this square and is reported
/// as one. Skipping instead is how this evidence would come to be "proven" by a
/// run that never asserted anything.
#[cfg(has_ip_dstaddr_recvif)]
#[test]
fn bsd_ipv4_recv_witnesses_the_group_and_a_unicast_destination() {
  use crate::onlink::DestinationWitness;
  use std::{
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    os::fd::AsRawFd,
  };

  let group = Ipv4Addr::new(224, 0, 0, 251);
  let sock = bind_ephemeral_with_rx_metadata();
  let port = sock
    .local_addr()
    .expect("our own socket must report its address")
    .port();

  let lo = up_loopback_index();
  try_join_v4(&sock, lo)
    .unwrap_or_else(|e| panic!("cannot join {group} on loopback index {lo}: {e:?}"));

  // 1) THE GROUP. Sent through loopback, so this needs no physical NIC.
  let group_payload = b"hick bsd ipv4 group probe";
  send_from_interface(
    Ipv4Addr::LOCALHOST,
    SocketAddrV4::new(group, port),
    group_payload,
  )
  .unwrap_or_else(|e| panic!("cannot send to {group} via 127.0.0.1: {e:?}"));
  let meta = recv_matching(sock.as_raw_fd(), group_payload).expect(
    "the group datagram never looped back, although the join and the send both \
     succeeded — see this test's doc for why that is a finding and not a skip",
  );
  assert_eq!(
    meta.destination_witness(),
    DestinationWitness::Witnessed(IpAddr::V4(group)),
    "IP_RECVDSTADDR must yield the GROUP the sender addressed. A local unicast \
     address here would send every multicast arrival to RFC 6762 §11's \
     source-prefix arm, which §11 says must not decide it"
  );
  // The refusal-minting flag, asserted directly rather than inferred: had
  // MSG_CTRUNC been set, `recv_with_meta` would have returned `Lost` for both
  // witnesses and never reached the parser at all.
  assert!(
    !meta.destination_witness().is_lost() && !meta.iface_witness().is_lost(),
    "MSG_CTRUNC must stay clear with the pair enabled — see \
     `control_buffer_holds_every_cmsg_this_target_enables` for the measured bound"
  );

  // 2) THE UNICAST, to one of this host's own addresses, on the very same
  //    socket. It must yield THAT address and not the group.
  let unicast_payload = b"hick bsd ipv4 unicast probe";
  send_from_interface(
    Ipv4Addr::LOCALHOST,
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
    unicast_payload,
  )
  .expect("sending to 127.0.0.1 from 127.0.0.1 cannot fail");
  let meta = recv_matching(sock.as_raw_fd(), unicast_payload)
    .expect("the unicast datagram to 127.0.0.1 never arrived");
  assert_eq!(
    meta.destination_witness(),
    DestinationWitness::Witnessed(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    "IP_RECVDSTADDR must yield the host address the sender addressed, so §11's \
     group arm is not taken for a unicast arrival"
  );
  assert_ne!(
    meta.destination_witness(),
    DestinationWitness::Witnessed(IpAddr::V4(group)),
    "and it must not be the group: §11's two arms would then be \
     indistinguishable on this square"
  );
  assert!(
    !meta.destination_witness().is_lost() && !meta.iface_witness().is_lost(),
    "MSG_CTRUNC must stay clear on the unicast arrival too"
  );
  evidence_complete("bsd_ipv4_recv_witnesses_the_group_and_a_unicast_destination");
}

/// EVIDENCE ITEM 2 (index half) for `has_ip_dstaddr_recvif`: `IP_RECVIF` names
/// the interface that actually carried the datagram.
///
/// Telling "arrived elsewhere" from "this platform never says" is the whole
/// value of the flip — `arrived_on_bound_interface` REFUSES on the first and
/// passes on the second — so an index that were merely non-zero would be
/// evidence of nothing. Each arrival is checked against `getifs`' own index for
/// the interface it was sent through, and where the host has a second
/// multicast-capable NIC the two indices are required to DIFFER.
///
/// A single-interface host cannot show that second half and SAYS SO rather than
/// passing it vacuously: the loop counts what it actually observed, the
/// assertions are on that count, and observing nothing at all is a failure.
#[cfg(has_ip_dstaddr_recvif)]
#[test]
fn bsd_ipv4_recv_witnesses_the_interface_that_carried_the_datagram() {
  use std::{
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::AsRawFd,
  };

  let group = Ipv4Addr::new(224, 0, 0, 251);
  let sock = bind_ephemeral_with_rx_metadata();
  let port = sock
    .local_addr()
    .expect("our own socket must report its address")
    .port();
  let loopback = up_loopback_index();

  // Every UP interface with an IPv4 address that can carry multicast, paired
  // with the index `getifs` reports — the value `IP_RECVIF` has to reproduce.
  let ifaces = getifs::interfaces().expect(
    "interface enumeration must succeed: without it there is no index for IP_RECVIF to be \
     checked against, and returning early would report success for a run that proved nothing",
  );
  let mut candidates: Vec<(u32, Ipv4Addr)> = Vec::new();
  for iface in ifaces.iter() {
    let flags = iface.flags();
    if !flags.contains(getifs::Flags::UP) {
      continue;
    }
    // Loopback carries the group without the MULTICAST flag on some BSDs.
    if !flags.contains(getifs::Flags::MULTICAST) && !flags.contains(getifs::Flags::LOOPBACK) {
      continue;
    }
    let Ok(addrs) = iface.ipv4_addrs() else {
      continue;
    };
    if let Some(addr) = addrs.first() {
      candidates.push((iface.index(), addr.addr()));
    }
  }
  // The per-interface `continue`s below are SELECTION, not preconditions: a NIC
  // that refuses the join or the send is simply not one this host can use, and
  // the assertions on `observed` are what stop that from emptying the test out.
  // These two are different — they are the test's own inputs.
  assert!(
    !candidates.is_empty(),
    "no UP interface with an IPv4 address: IP_RECVIF cannot be exercised at all here, so \
     this run is not evidence"
  );
  assert!(
    candidates.iter().any(|(idx, _)| *idx == loopback),
    "the UP loopback interface ({loopback}) is not among the candidates, so the one \
     interface guaranteed to carry the group would go unchecked"
  );

  let mut observed: Vec<u32> = Vec::new();
  for (index, addr) in &candidates {
    if try_join_v4(&sock, *index).is_err() {
      continue;
    }
    // The index goes IN THE PAYLOAD, so `recv_matching` returns this
    // iteration's datagram or nothing. Without that, a datagram from an earlier
    // interface still in the socket buffer would be asserted against the
    // current interface's index and the test would fail for the wrong reason —
    // or worse, pass for one.
    let payload = format!("hick recvif probe idx={index}").into_bytes();
    if send_from_interface(*addr, SocketAddrV4::new(group, port), &payload).is_err() {
      continue;
    }
    let Some(meta) = recv_matching(sock.as_raw_fd(), &payload) else {
      eprintln!("note: no loopback copy from interface {index} ({addr}); not counted");
      continue;
    };
    assert_eq!(
      meta.iface_witness().witnessed_index().map(|i| i.get()),
      Some(*index),
      "IP_RECVIF must report the index getifs gives for the interface that \
       carried the datagram (index {index}, address {addr}). A wrong or absent \
       index makes `arrived_on_bound_interface` refuse traffic that DID arrive \
       on the bound link"
    );
    observed.push(*index);
  }

  assert!(
    !observed.is_empty(),
    "no interface delivered a group datagram back to this socket, so IP_RECVIF \
     was never exercised — this test proved nothing and must not pass"
  );
  // Not implied by the line above. Without this, a host where the loopback
  // delivery silently stopped working would still pass on some other NIC, and
  // loopback is the one interface every runner has and every other evidence test
  // depends on.
  assert!(
    observed.contains(&loopback),
    "the loopback interface ({loopback}) delivered no group datagram, although it is UP and \
     was joined: IP_RECVIF was checked only on interfaces that happen to exist on this host"
  );
  observed.sort_unstable();
  observed.dedup();
  if observed.len() >= 2 {
    // The half a single-NIC runner cannot show: two interfaces, two DIFFERENT
    // indices, so the value is the interface's own and not a constant.
    eprintln!(
      "IP_RECVIF distinguished {} interfaces: {observed:?}",
      observed.len()
    );
  } else {
    eprintln!(
      "note: only interface {observed:?} delivered a datagram on this host, so \
       'distinguishes a NIC that is not the bound one' is NOT covered by this run"
    );
  }
  evidence_complete("bsd_ipv4_recv_witnesses_the_interface_that_carried_the_datagram");
}

/// The capability [`reports_rx_interface_v4`] publishes, spelled from TARGET
/// LITERALS rather than from the cfgs the function reads.
///
/// Asking the production answer to confirm itself would pass whatever `build.rs`
/// emitted — including the state this change is closing, where the four BSDs
/// answered `false`. The list below is the claim: every supported target
/// witnesses an IPv4 destination and receive interface through `recv_with_meta`,
/// by one of three routes, and nothing supported is left out of it.
#[test]
fn reports_rx_interface_v4_names_every_supported_target() {
  // `IP_PKTINFO` (Linux/Android/Apple), the `IP_RECVDSTADDR` + `IP_RECVIF` pair
  // (the four BSDs), or `WSARecvMsg` (Windows).
  let pktinfo = cfg!(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple"
  ));
  let bsd_pair = cfg!(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
  ));
  let wsarecvmsg = cfg!(windows);
  assert_eq!(
    reports_rx_interface_v4(),
    pktinfo || bsd_pair || wsarecvmsg,
    "reports_rx_interface_v4 must follow the enumerated capability routes, not \
     the other way round"
  );
  // This host is one of them, so a future target added without a route would
  // not be able to reach this assertion by making both sides `false`.
  assert!(
    reports_rx_interface_v4(),
    "every target this crate supports witnesses an IPv4 destination through \
     recv_with_meta; if this fails, a supported target lost its route"
  );
  // IPv6 was already uniform and stays so — asserted here so the two families
  // are pinned by one test and cannot drift into disagreeing about "supported".
  assert!(reports_rx_interface_v6());
}

/// A BSD square that recovers ONLY the destination reports the interface as
/// `Declined`, and KEEPS the destination — through the real parser, not through
/// the scan under it.
///
/// The scan's half of this is already covered by
/// `scan_dstaddr_recvif_reports_each_half_of_the_pair_independently`. What is
/// asserted here is what [`parse_dstaddr_recvif_v4`] builds out of a half-recovered
/// pair, because that is the decision `admits_ingress` actually reads and it is
/// the one a "require both cmsgs" simplification would silently change.
///
/// This state exists on no other square. `IP_RECVDSTADDR` and `IP_RECVIF` are two
/// cmsgs from two `sbcreatecontrol` calls, not two fields of one struct, so an
/// mbuf shortage can take either alone — and NetBSD's `ip_savecontrol` splits
/// them deterministically, emitting `IP_RECVDSTADDR` before its
/// `m_get_rcvif_psref() == NULL` early return and `IP_RECVIF` after it. A
/// detached receive interface on NetBSD produces exactly this buffer.
///
/// `Declined` and not `Lost`: nothing was lost on our side and a larger control
/// buffer would change nothing, so RFC 6762 §11's destination partition still
/// decides in full and only the link scoping goes. Refusing here would make a
/// NetBSD responder deaf on every datagram whose receive interface had detached.
#[cfg(has_ip_dstaddr_recvif)]
#[test]
fn a_dstaddr_without_recvif_declines_the_interface_and_keeps_the_destination() {
  use std::net::{IpAddr, SocketAddr, SocketAddrV4};

  let group = Ipv4Addr::new(224, 0, 0, 251);
  let peer: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5353).into();
  let cmsgs = synth_cmsgs(&[(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, &group.octets())]);

  let meta = parse_dstaddr_recvif_v4(&cmsgs, 200, peer)
    .expect("one half of the pair is still a parse, not a MissingPktinfo");
  assert_eq!(
    meta.destination_witness(),
    crate::onlink::DestinationWitness::Witnessed(IpAddr::V4(group)),
    "the destination survives its sibling's absence — §11's group arm still fires"
  );
  assert_eq!(
    meta.iface_witness(),
    crate::onlink::IfaceWitness::Declined,
    "a missing IP_RECVIF with MSG_CTRUNC clear is the kernel declining, which \
     DEGRADES; Lost would refuse a datagram nothing on our side mishandled"
  );
  assert_ne!(meta.iface_witness(), crate::onlink::IfaceWitness::Lost);

  // And the mirror: only the interface. It costs the destination partition for
  // this one datagram and must not cost the link scoping too.
  let sdl = synth_sockaddr_dl(7, b"em0");
  let cmsgs = synth_cmsgs(&[(libc::IPPROTO_IP, libc::IP_RECVIF, &sdl)]);
  let meta =
    parse_dstaddr_recvif_v4(&cmsgs, 200, peer).expect("the other half alone is also a parse");
  assert_eq!(
    meta.iface_witness().witnessed_index().map(|i| i.get()),
    Some(7),
    "the interface survives its sibling's absence"
  );
  assert_eq!(
    meta.destination_witness(),
    crate::onlink::DestinationWitness::Declined,
    "and the absent destination declines rather than being invented"
  );
}

/// The read-back is CALLED BY `try_bind_v4`, proven through the public API with
/// the `FORCE_RX_DSTADDR_READBACK_V4` seam forcing one option to read back as
/// disabled.
///
/// Without this, the two lines
/// `verify_rx_dstaddr_recvif_v4(&std_sock)?` in `try_bind_v4_inner` could be
/// deleted and every other test would stay green on a healthy kernel: the bind
/// test reads the options back independently, and the packet tests use an
/// ephemeral helper that calls the verifier directly. Those prove the
/// COMPARISON. Only this proves the CALL SITE — and the call site is the whole
/// of what DragonFly, OpenBSD and NetBSD have in place of a CI runner, since
/// none of them has one.
///
/// A seam is unavoidable, for the same reason `try_bind_v6`'s is: on a correctly
/// functioning kernel the enable always takes, so no value reachable through
/// `MulticastOptionsV4` or `try_bind_v4` can make the read-back return zero.
/// The alternative is to reintroduce a real bug.
///
/// Deleting the verifier call makes `try_bind_v4` return `Ok` here and this test
/// fails; neutering the `== 0` comparison does the same. The forced pair is
/// asymmetric — `(1, 0)` — so it also pins that the check is an `||` over BOTH
/// options and not a test of one of them.
#[cfg(has_ip_dstaddr_recvif)]
#[test]
fn try_bind_v4_rejects_a_half_enabled_socket_forced_through_production_wiring() {
  // dstaddr enabled, recvif not: the exact shape a half-applied enable takes,
  // and the one an `&&` comparison would wave through.
  FORCE_RX_DSTADDR_READBACK_V4.with(|cell| cell.set(Some((1, 0))));
  let result = try_bind_v4(MulticastOptionsV4::new(0));
  // Reset before anything below can fail an assertion, so the override never
  // leaks into a later test on this thread even on an early failure here. The
  // FreeBSD CI job runs `--test-threads=1`, so "a later test on this thread"
  // means every test that follows.
  FORCE_RX_DSTADDR_READBACK_V4.with(|cell| cell.set(None));

  let err = match result {
    // The one legitimate non-regression outcome: the environment refused the
    // bind outright, so the verifier was never reached. Open-coded rather than
    // routed through `expect_bind_or_skip`, which would treat the
    // `RxDestinationNotEnabled` this test EXPECTS as a failure.
    Err(BindError::Io(e)) if is_environment_refusal(&e) => {
      eprintln!("skipping: environment refused the IPv4 bind needed to exercise this seam ({e})");
      return;
    }
    other => other.expect_err(
      "try_bind_v4 must reject a bind whose IP_RECVDSTADDR/IP_RECVIF read-back reports one \
       option disabled — an Ok here means either the verify_rx_dstaddr_recvif_v4 call was \
       removed from try_bind_v4_inner or its comparison no longer detects a half-enabled socket",
    ),
  };
  let detail = err.try_unwrap_rx_destination_not_enabled().expect(
    "expected BindError::RxDestinationNotEnabled — a different variant means try_bind_v4 \
     failed for a reason unrelated to the forced read-back",
  );
  assert_eq!(
    detail.dstaddr(),
    1,
    "the detail must carry the value the read-back reported for IP_RECVDSTADDR"
  );
  assert_eq!(
    detail.recvif(),
    0,
    "the detail must carry the value the read-back reported for IP_RECVIF, which is the \
     option that was disabled"
  );
  evidence_complete("try_bind_v4_rejects_a_half_enabled_socket_forced_through_production_wiring");
}

/// `IP_MULTICAST_LOOP` is a one-byte `u_char` on this kernel and a four-byte
/// `c_int` on Linux, Apple and Windows, and the ONLY native BSD execution in
/// this workspace runs here — so this is where the setter's ABI is put in front
/// of a real BSD kernel rather than argued about.
///
/// # Why a test about `std` lives in this crate
///
/// The fact under test is neither crate's: it is whether
/// `std::net::UdpSocket::set_multicast_loop_v4` sizes the option the way THIS
/// kernel demands. `hick-reactor`'s loopback control depends on that answer —
/// its `std_sets_ip_multicast_loop_at_this_target_s_width` makes the same call —
/// but no BSD runs `hick-reactor`'s tests anywhere in CI, so its copy can only
/// establish the Linux/Apple/Windows half, where a wrong width is accepted and
/// proves nothing. `ci.yml`'s `freebsd` job names this test in
/// `REQUIRED_EVIDENCE`, so the BSD half is executed per run.
///
/// It is deliberately NOT a size assertion. `size_of::<c_uchar>() != size_of::<c_int>()`
/// is true on every target and would have passed while socket2 0.6.5 —
/// `loop_v4 as c_int`, unconditionally — was the setter in that control. Only
/// the syscall itself distinguishes them, and only on a kernel that cares.
///
/// An ephemeral port, not `:5353`: this establishes an option's ABI and needs no
/// particular port, and staying off 5353 keeps it clear of the reuse-group
/// lottery documented on `bind_ephemeral_with_rx_metadata`.
#[test]
fn std_set_multicast_loop_v4_is_accepted_by_this_kernel() {
  let sock = std::net::UdpSocket::bind("0.0.0.0:0").expect(
    "binding an ephemeral UDP socket must succeed: this IS the evidence, so a bind that did \
     not happen is a failure and never a skip",
  );
  sock.set_multicast_loop_v4(true).expect(
    "std::net::UdpSocket::set_multicast_loop_v4 must be accepted by this kernel. EINVAL here \
     is the four-byte-value defect: IP_MULTICAST_LOOP is a one-byte u_char on FreeBSD, \
     DragonFly, OpenBSD and NetBSD, and a setter that hardcodes c_int — socket2 0.6.5 does — \
     is rejected outright",
  );
  assert!(
    sock
      .multicast_loop_v4()
      .expect("reading IP_MULTICAST_LOOP back must succeed"),
    "the kernel accepted the enable and then reported the option off; a setsockopt that takes \
     the call without holding the value is the exact false success this crate's other \
     read-backs exist for"
  );
  evidence_complete("std_set_multicast_loop_v4_is_accepted_by_this_kernel");
}

/// The PRODUCTION IPv4 multicast setters, executed through the functions
/// `try_bind_v4_inner` actually calls, and read back.
///
/// # Why this is not the guard it looks like
///
/// Stated first so nobody reads more into it than it carries. The defect these
/// two setters had — rustix sending a four-byte value where the 4.4BSD API
/// defines a one-byte `u_char` — is INVISIBLE on FreeBSD, whose
/// `inp_setmoptions` deliberately accepts either width. So this test would have
/// passed with the defect in place on the only BSD this workspace can execute,
/// and it does not establish anything about OpenBSD, NetBSD or DragonFly, which
/// have no runner anywhere.
///
/// What it does do is pin the CALL SITE on a real kernel: it goes through
/// `platform::set_multicast_loop_v4` / `set_multicast_ttl_v4` rather than
/// alongside them, so a future change that makes either universally wrong —
/// a bad level, a bad optname, a width no kernel takes — fails here rather than
/// at a caller's bind. A test positioned next to the thing proves nothing about
/// the thing; this one is at least through it.
///
/// The read-backs are the point of doing it at all: a `setsockopt` that takes
/// the call and does not hold the value is the false success this crate already
/// met once on `IPV6_MULTICAST_HOPS`.
///
/// An ephemeral port, for the reuse-group reason `bind_ephemeral_with_rx_metadata`
/// documents.
#[test]
fn production_ipv4_multicast_setters_are_accepted_and_held_by_this_kernel() {
  let sock = std::net::UdpSocket::bind("0.0.0.0:0").expect(
    "binding an ephemeral UDP socket must succeed: this IS the evidence, so a bind that did \
     not happen is a failure and never a skip",
  );
  crate::platform::set_multicast_loop_v4(&sock, true).expect(
    "platform::set_multicast_loop_v4 must be accepted by this kernel. EINVAL here is a value \
     width no kernel takes — IP_MULTICAST_LOOP is a one-byte u_char on the BSD family and a \
     four-byte c_int elsewhere, and only std sizes it per target",
  );
  assert!(
    sock
      .multicast_loop_v4()
      .expect("reading IP_MULTICAST_LOOP back must succeed"),
    "the kernel accepted the enable and then reported the option off"
  );
  crate::platform::set_multicast_ttl_v4(&sock, 255).expect(
    "platform::set_multicast_ttl_v4 must be accepted by this kernel; see the loop option above \
     for the width this depends on",
  );
  assert_eq!(
    sock
      .multicast_ttl_v4()
      .expect("reading IP_MULTICAST_TTL back must succeed"),
    255,
    "RFC 6762 §11 wants 255 on the wire, and a setsockopt that takes the call without holding \
     the value would leave the kernel default of 1"
  );
  evidence_complete("production_ipv4_multicast_setters_are_accepted_and_held_by_this_kernel");
}

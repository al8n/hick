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

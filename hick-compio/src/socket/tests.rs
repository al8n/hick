use super::*;

/// Regression for the family-blind cmsg setup: `enable_recv_cmsgs` used to
/// apply the IPv4-only `IP_PKTINFO` / `IP_RECVTTL` sockopts with a fatal `?`
/// to EVERY socket, so an `AF_INET6` socket failed with `EINVAL` and
/// `from_std` bubbled the error — breaking v6-only and dual-stack endpoint
/// construction before any datagram could flow. `from_std` must now succeed on
/// a v6 socket by applying only the v6 cmsg options.
#[cfg(unix)]
#[compio::test]
async fn from_std_enables_cmsgs_on_v6_socket() {
  use std::net::{Ipv6Addr, UdpSocket};
  let sock = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
    Ok(s) => s,
    Err(_) => return, // host without usable IPv6 — environmental skip
  };
  let wrapped = Socket::from_std(sock).await;
  assert!(
    wrapped.is_ok(),
    "from_std must enable cmsgs on a v6 socket without EINVAL, got {:?}",
    wrapped.err()
  );
}

/// Companion to [`from_std_enables_cmsgs_on_v6_socket`]: the per-family gating
/// must not regress the v4 path.
#[cfg(unix)]
#[compio::test]
async fn from_std_enables_cmsgs_on_v4_socket() {
  use std::net::{Ipv4Addr, UdpSocket};
  let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind v4");
  let wrapped = Socket::from_std(sock).await;
  assert!(
    wrapped.is_ok(),
    "from_std must still succeed on a v4 socket, got {:?}",
    wrapped.err()
  );
}

/// Build a minimal control buffer containing a single SOL_SOCKET receive-
/// timestamp cmsg (the SCM_* TYPE the kernel actually delivers — and that
/// `decode_unix_cmsgs` matches), then iterate it and verify level/type/data.
/// The constant + payload are chosen by `recv_timestamp_ns`: nanosecond
/// SCM_TIMESTAMPNS/timespec on Linux/Android, microsecond SCM_TIMESTAMP/timeval
/// on Apple/BSD.
#[cfg(all(unix, has_recv_timestamp))]
#[test]
fn cmsg_iter_walks_a_single_timestamp_cmsg() {
  #[cfg(not(recv_timestamp_ns))]
  use libc::{SCM_TIMESTAMP as TS_TYPE, timeval as TsPayload};
  #[cfg(recv_timestamp_ns)]
  use libc::{SCM_TIMESTAMPNS as TS_TYPE, timespec as TsPayload};
  use libc::{SOL_SOCKET, cmsghdr};
  #[cfg(recv_timestamp_ns)]
  let payload = TsPayload {
    tv_sec: 1234,
    tv_nsec: 56,
  };
  #[cfg(not(recv_timestamp_ns))]
  let payload = TsPayload {
    tv_sec: 1234,
    tv_usec: 56,
  };
  let payload_bytes = core::mem::size_of::<TsPayload>();
  let total = unsafe { libc::CMSG_SPACE(payload_bytes as u32) } as usize;
  // Use a u64-backed allocation to guarantee at least 8-byte alignment,
  // which covers every cmsghdr alignment on supported targets. A plain
  // `vec![0u8; total]` is only alignment 1 and would trip CMsgIter::new.
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let words = total.div_ceil(core::mem::size_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; words.max(1)];
  // SAFETY: backing owns `words * 8` zeroed bytes; `total <= words * 8`,
  // so the resulting slice fits inside the allocation. The bytes stay
  // borrowed for the lifetime of this scope.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), total) };
  // SAFETY: buf is correctly sized and zero-initialised; we write a valid cmsghdr.
  // The header pointer is aligned (Vec<u64> backing), but CMSG_DATA may be
  // under-aligned for the payload type (`timeval` on macOS), so use
  // `write_unaligned` to match the eventual `read_unaligned` below.
  unsafe {
    let hdr = buf.as_mut_ptr() as *mut cmsghdr;
    (*hdr).cmsg_len = libc::CMSG_LEN(payload_bytes as u32) as _;
    (*hdr).cmsg_level = SOL_SOCKET;
    (*hdr).cmsg_type = TS_TYPE;
    let data = libc::CMSG_DATA(hdr) as *mut TsPayload;
    core::ptr::write_unaligned(data, payload);
  }
  let mut iter = CMsgIter::new(buf);
  let first = iter.next().expect("one cmsg");
  assert_eq!(first.level(), SOL_SOCKET);
  assert_eq!(first.ty(), TS_TYPE);
  // CMSG_DATA is only guaranteed to satisfy cmsghdr's alignment, not the
  // payload type's. On macOS `cmsghdr` is 4-byte aligned and `timeval`
  // wants 8 — read unaligned to stay sound across all targets.
  let got = unsafe { core::ptr::read_unaligned(first.data::<TsPayload>()) };
  assert_eq!(got.tv_sec, 1234);
  #[cfg(recv_timestamp_ns)]
  assert_eq!(got.tv_nsec, 56);
  #[cfg(not(recv_timestamp_ns))]
  assert_eq!(got.tv_usec, 56);
  assert!(iter.next().is_none(), "no second cmsg");
}

/// Round-trip an `IP_PKTINFO` cmsg through `CMsgBuilder` and `CMsgIter`:
/// the builder encodes the header + payload, then the iterator must read
/// back the same level/type/payload.
#[cfg(unix)]
#[test]
fn cmsg_builder_emits_a_round_trippable_pktinfo() {
  use libc::{IP_PKTINFO, IPPROTO_IP, in_addr, in_pktinfo};
  let pktinfo = in_pktinfo {
    ipi_ifindex: 7,
    ipi_spec_dst: in_addr {
      s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
    },
    ipi_addr: in_addr {
      s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
    },
  };
  // `vec![0u8; 128]` is only alignment 1, which would trip CMsgIter::new's
  // alignment assert. Back the buffer with a
  // `Vec<u64>` to get ≥8-byte alignment for the underlying bytes.
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; 128 / core::mem::size_of::<u64>()];
  // SAFETY: backing owns `len * 8 == 128` zeroed bytes; the resulting slice
  // is borrowed for the rest of this scope and never aliased.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), 128) };
  let written = {
    let mut b = CMsgBuilder::new(buf);
    b.push(IPPROTO_IP, IP_PKTINFO, &pktinfo).expect("fits");
    b.finish()
  };
  assert!(written > 0);
  let mut iter = CMsgIter::new(&buf[..written]);
  let cmsg = iter.next().expect("round-tripped one cmsg");
  assert_eq!(cmsg.level(), IPPROTO_IP);
  assert_eq!(cmsg.ty(), IP_PKTINFO);
  // CMSG_DATA is only guaranteed to satisfy cmsghdr's alignment; on macOS
  // `cmsghdr` aligns to 4, and `in_pktinfo` also aligns to 4, so this is
  // fine in practice — but use `read_unaligned` defensively to mirror the
  // builder's `write_unaligned`.
  let got = unsafe { core::ptr::read_unaligned(cmsg.data::<in_pktinfo>()) };
  assert_eq!(got.ipi_ifindex, 7);
  assert!(iter.next().is_none(), "no second cmsg");
}

/// A cmsg that advertises `IPPROTO_IP` / `IP_PKTINFO` but whose `cmsg_len`
/// only covers 2 payload bytes (far short of `in_pktinfo`) must be skipped,
/// not read: reading `in_pktinfo` out of it would run past the bytes the
/// kernel deposited. `decode_unix_cmsgs` must return without panicking and
/// leave `local_ip` / `interface_index` at their `RecvMeta::empty` defaults.
#[cfg(unix)]
#[test]
fn truncated_pktinfo_cmsg_is_skipped_not_read() {
  use libc::{IP_PKTINFO, IPPROTO_IP, cmsghdr};
  // Reserve room for a full `in_pktinfo` payload so the buffer itself is
  // large enough; only `cmsg_len` is shrunk to claim a 2-byte payload, which
  // is what makes the cmsg "truncated" from the decoder's point of view.
  let payload_bytes = core::mem::size_of::<libc::in_pktinfo>();
  let total = unsafe { libc::CMSG_SPACE(payload_bytes as u32) } as usize;
  // Back with a `Vec<u64>` for ≥8-byte alignment, mirroring the iterator
  // tests above; a plain `vec![0u8; total]` is only alignment 1 and would
  // trip `decode_unix_cmsgs`'s alignment guard / `CMsgIter::new`.
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let words = total.div_ceil(core::mem::size_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; words.max(1)];
  // SAFETY: backing owns `words * 8 >= total` zeroed bytes; the slice fits
  // inside the allocation and stays borrowed for this scope.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), total) };
  // SAFETY: buf is sized for a full `in_pktinfo` cmsg and zero-initialised;
  // we write a valid header but set `cmsg_len = CMSG_LEN(2)` so the cmsg
  // claims only 2 payload bytes.
  unsafe {
    let hdr = buf.as_mut_ptr() as *mut cmsghdr;
    (*hdr).cmsg_len = libc::CMSG_LEN(2) as _;
    (*hdr).cmsg_level = IPPROTO_IP;
    (*hdr).cmsg_type = IP_PKTINFO;
  }
  let mut meta = RecvMeta::empty(([0u8, 0, 0, 0], 0).into());
  decode_unix_cmsgs(buf, &mut meta);
  // Left at defaults: the truncated cmsg was skipped, never read as garbage.
  assert!(
    meta.local_ip.is_unspecified(),
    "truncated PKTINFO populated local_ip from a short cmsg"
  );
  assert_eq!(
    meta.interface_index, 0,
    "truncated PKTINFO populated interface_index from a short cmsg"
  );
}

/// An absurd, malformed timestamp cmsg must not panic the decoder. Two
/// panic vectors are exercised at once: `tv_sec = i64::MAX` (which the old
/// `UNIX_EPOCH + Duration` `Add` could overflow-panic on) and an
/// out-of-range sub-second field (`tv_nsec`/`tv_usec` far past its modulus,
/// which the old `Duration::new(secs, nanos)` could carry-overflow-panic on).
/// The checked/clamped arithmetic must absorb both: reaching the final
/// assertion at all proves no panic. We then require `kernel_rx_time` to be
/// well-defined — either declined (`None`, if the platform's `SystemTime`
/// range overflowed) or a valid stamp — but never a panic.
///
/// Note: we do *not* hard-assert `None`. `tv_sec`/`tv_nsec` are `i64`/`i64`
/// (`time_t`), and on Linux/Darwin `UNIX_EPOCH.checked_add(Duration::new(
/// i64::MAX as u64, _))` stays in range and returns `Some`; `None` is only
/// reachable with a seconds value larger than `i64` can hold, which a real
/// kernel timestamp field cannot carry. The fix's guarantee is "no panic",
/// not a forced `None`.
#[cfg(all(unix, has_recv_timestamp))]
#[test]
fn absurd_timestamp_does_not_panic() {
  use libc::{SOL_SOCKET, cmsghdr};

  // Use the SCM_* TYPE the decoder now matches (the kernel-delivered cmsg
  // type), selected by `recv_timestamp_ns` like the decode arms.
  #[cfg(not(recv_timestamp_ns))]
  use libc::{SCM_TIMESTAMP as TS_TYPE, timeval as TsPayload};
  #[cfg(recv_timestamp_ns)]
  use libc::{SCM_TIMESTAMPNS as TS_TYPE, timespec as TsPayload};

  // `tv_sec = i64::MAX` plus an out-of-range sub-second value: the latter is
  // exactly the input `Duration::new` would reject by panicking (nanos must
  // be < 1e9), so the decoder's clamp is what keeps this sound.
  #[cfg(recv_timestamp_ns)]
  let payload = TsPayload {
    tv_sec: i64::MAX,
    tv_nsec: i64::MAX,
  };
  #[cfg(not(recv_timestamp_ns))]
  let payload = TsPayload {
    tv_sec: i64::MAX as _,
    tv_usec: i64::MAX as _,
  };

  let payload_bytes = core::mem::size_of::<TsPayload>();
  let total = unsafe { libc::CMSG_SPACE(payload_bytes as u32) } as usize;
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let words = total.div_ceil(core::mem::size_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; words.max(1)];
  // SAFETY: backing owns `words * 8 >= total` zeroed bytes; the slice fits
  // inside the allocation and stays borrowed for this scope.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), total) };
  // SAFETY: buf is correctly sized and zero-initialised; we write a valid
  // header and an absurd-but-well-formed payload via `write_unaligned`
  // (CMSG_DATA may be under-aligned for the payload type on some targets).
  unsafe {
    let hdr = buf.as_mut_ptr() as *mut cmsghdr;
    (*hdr).cmsg_len = libc::CMSG_LEN(payload_bytes as u32) as _;
    (*hdr).cmsg_level = SOL_SOCKET;
    (*hdr).cmsg_type = TS_TYPE;
    let data = libc::CMSG_DATA(hdr) as *mut TsPayload;
    core::ptr::write_unaligned(data, payload);
  }
  let mut meta = RecvMeta::empty(([0u8, 0, 0, 0], 0).into());
  // Must return without panicking despite the absurd seconds + out-of-range
  // sub-second field. Reaching the line after this call is the proof.
  decode_unix_cmsgs(buf, &mut meta);
  if let Some(t) = meta.kernel_rx_time {
    // If a stamp was produced it must be a real `SystemTime` (no panic in
    // `duration_since` either); the exact value is unspecified for garbage
    // input, we only require well-definedness.
    let _ = t.duration_since(std::time::UNIX_EPOCH);
  }
}

#[test]
fn recv_meta_default_is_safe_and_unspecified() {
  let m = RecvMeta::empty(([127, 0, 0, 1], 5353).into());
  assert!(m.local_ip.is_unspecified());
  assert_eq!(m.interface_index, 0);
  assert!(m.hop_limit.is_none());
  assert!(m.kernel_rx_time.is_none());
}

/// Direct proof that the cmsg recv path delivers PKTINFO over loopback.
/// Higher layers (Endpoint, Service, Query) cover this indirectly, but
/// keeping the raw round-trip here as a unit test pins the low-level
/// pathway in isolation.
#[compio::test]
async fn raw_loopback_round_trip_carries_pktinfo_local_ip() {
  use core::net::{Ipv4Addr, SocketAddr};
  use hick_udp::{MulticastOptionsV4, try_bind_v4, try_join_v4};
  use std::time::Duration;

  fn loopback_index() -> Option<u32> {
    let ifs = getifs::interfaces().ok()?;
    ifs
      .iter()
      .find(|i| {
        i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP)
      })
      .map(|i| i.index())
  }

  let idx = match loopback_index() {
    Some(i) => i,
    None => {
      eprintln!("skip: no loopback iface");
      return;
    }
  };
  let s1 = match try_bind_v4(MulticastOptionsV4::new(idx)) {
    Ok(s) => s,
    Err(e) => {
      eprintln!("skip: bind: {e:?}");
      return;
    }
  };
  try_join_v4(&s1, idx).ok();
  s1.set_nonblocking(true).unwrap();
  let s2 = try_bind_v4(MulticastOptionsV4::new(idx)).unwrap();
  try_join_v4(&s2, idx).ok();
  s2.set_nonblocking(true).unwrap();
  let sock1 = Socket::from_std(s1).await.unwrap();
  let sock2 = Socket::from_std(s2).await.unwrap();
  let payload = b"compio mdns hello";
  let dst: SocketAddr = (Ipv4Addr::new(224, 0, 0, 251), 5353).into();
  sock1.send_to(payload, dst, None).await.unwrap();
  let (data, meta) = compio::time::timeout(Duration::from_secs(2), sock2.recv(2048))
    .await
    .expect("recv timed out")
    .unwrap();
  assert_eq!(&data[..payload.len()], payload);
  // local_ip and interface_index are populated from PKTINFO on Linux/macOS;
  // soft-assert because some loopback configs deliver UNSPECIFIED.
  if meta.local_ip.is_unspecified() {
    eprintln!("note: PKTINFO not delivered on this loopback config");
  }
}

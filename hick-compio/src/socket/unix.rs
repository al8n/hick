use libc::{cmsghdr, msghdr};

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::RecvMeta;

/// One ancillary control message inside a filled control buffer.
pub(crate) struct CMsgRef<'a> {
  inner: &'a cmsghdr,
}

impl CMsgRef<'_> {
  #[inline]
  pub(crate) fn level(&self) -> libc::c_int {
    self.inner.cmsg_level
  }

  #[inline]
  pub(crate) fn ty(&self) -> libc::c_int {
    self.inner.cmsg_type
  }

  /// Number of payload bytes this cmsg actually carries (`cmsg_len` minus the
  /// header/alignment offset). Saturating so a corrupt short cmsg yields 0.
  ///
  /// Callers must check `data_len() >= size_of::<T>()` before reading the
  /// payload as `T` via [`CMsgRef::data`]; otherwise the read would run past
  /// the bytes the kernel actually deposited for this cmsg.
  #[inline]
  // `cmsg_len` is `usize` on Linux but `socklen_t` (u32) on the BSDs/macOS, so
  // the `as usize` is platform-conditionally necessary.
  #[allow(clippy::unnecessary_cast)]
  pub(crate) fn data_len(&self) -> usize {
    // SAFETY: CMSG_LEN is a pure size macro (no pointer deref).
    let base = unsafe { libc::CMSG_LEN(0) } as usize;
    (self.inner.cmsg_len as usize).saturating_sub(base)
  }

  /// View the cmsg payload as `T`.
  ///
  /// # Safety
  ///
  /// - Caller must guarantee `T` matches the actual cmsg payload type/size,
  ///   and the underlying buffer must outlive any read through the returned
  ///   pointer.
  /// - **Alignment caveat:** `CMSG_DATA` is only guaranteed to be aligned
  ///   to `align_of::<libc::cmsghdr>()` (4 bytes on Darwin). When
  ///   `align_of::<T>() > align_of::<libc::cmsghdr>()` — for example
  ///   `libc::timeval` and `libc::timespec` on Darwin, which want 8-byte
  ///   alignment — callers MUST use `core::ptr::read_unaligned` on the
  ///   returned pointer instead of dereferencing it. Plain `*ptr` reads
  ///   are UB on misaligned data.
  #[inline]
  pub(crate) unsafe fn data<T>(&self) -> *const T {
    // SAFETY: caller asserts T matches; CMSG_DATA returns a pointer into
    // the same allocation as `inner`, which is borrowed for 'a. The caller
    // is responsible for honoring T's alignment (see method-level alignment
    // caveat above) — `*ptr` reads of misaligned data are UB, and they must
    // use `core::ptr::read_unaligned` in that case.
    unsafe { libc::CMSG_DATA(self.inner as *const cmsghdr) as *const T }
  }
}

/// Iterate ancillary control messages in a filled control buffer.
///
/// The buffer must be aligned to `align_of::<cmsghdr>()` — see
/// [`CMsgIter::new`]. In production this is satisfied by routing the kernel's
/// fill through a `cmsghdr`-aligned scratch buffer.
pub(crate) struct CMsgIter<'a> {
  msg: msghdr,
  next: *const cmsghdr,
  _lt: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> CMsgIter<'a> {
  /// Wrap a filled control buffer for iteration.
  ///
  /// # Panics
  ///
  /// Panics if `buf` is not aligned to `align_of::<cmsghdr>()`; reading a
  /// `cmsghdr` through a misaligned pointer is undefined behaviour, so we
  /// refuse rather than silently invoke UB.
  pub(crate) fn new(buf: &'a [u8]) -> Self {
    assert!(
      buf.as_ptr().cast::<cmsghdr>().is_aligned(),
      "control buffer is not aligned for cmsghdr"
    );
    // SAFETY: msghdr's all-zero pattern is a valid empty header. We then
    // patch the control pointer/len to point at the borrowed buffer.
    let mut msg: msghdr = unsafe { core::mem::zeroed() };
    msg.msg_control = buf.as_ptr() as *mut _;
    msg.msg_controllen = buf.len() as _;
    // SAFETY: msg has its control fields set to the borrowed buffer, which
    // outlives 'a; CMSG_FIRSTHDR reads only those fields.
    let next = unsafe { libc::CMSG_FIRSTHDR(&msg) } as *const cmsghdr;
    Self {
      msg,
      next,
      _lt: core::marker::PhantomData,
    }
  }
}

impl<'a> Iterator for CMsgIter<'a> {
  type Item = CMsgRef<'a>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.next.is_null() {
      return None;
    }
    // SAFETY: CMSG_FIRSTHDR / CMSG_NXTHDR returned a pointer inside the
    // control buffer that outlives 'a, or null when exhausted. Alignment
    // is ensured at `CMsgIter::new`.
    let cur = unsafe { &*self.next };
    // SAFETY: same as above; `next` is either a valid header pointer or
    // null at this point. CMSG_NXTHDR walks the control buffer.
    self.next = unsafe { libc::CMSG_NXTHDR(&self.msg, self.next) } as *const cmsghdr;
    Some(CMsgRef { inner: cur })
  }
}

// Windows iteration mirrors this shape over WSACMSGHDR / `WSA_CMSG_*` macros;
// added alongside the Windows recv path.

/// Encode outbound cmsgs into a caller-provided byte buffer.
///
/// The buffer must outlive any borrow of the builder; the builder writes
/// `cmsghdr` headers and payloads in place and tracks how many bytes have been
/// consumed. Call [`CMsgBuilder::finish`] to get the final `msg_controllen`.
pub(crate) struct CMsgBuilder<'a> {
  buf: &'a mut [u8],
  cursor: usize,
}

impl<'a> CMsgBuilder<'a> {
  /// Construct a builder over `buf`.
  ///
  /// # Panics
  ///
  /// Panics if `buf` is not aligned to `align_of::<cmsghdr>()`. Writing a
  /// `cmsghdr` through a misaligned pointer is undefined behaviour, so we
  /// refuse rather than silently invoke UB — mirrors [`CMsgIter::new`]'s
  /// precondition.
  pub(crate) fn new(buf: &'a mut [u8]) -> Self {
    assert!(
      buf.as_ptr().cast::<cmsghdr>().is_aligned(),
      "control buffer is not aligned for cmsghdr"
    );
    // recvmsg/sendmsg expect the inter-cmsg padding bytes to be zero; just
    // zero the whole buffer up front so subsequent CMSG_NXTHDR walks see
    // well-defined padding.
    for b in buf.iter_mut() {
      *b = 0;
    }
    Self { buf, cursor: 0 }
  }

  /// Append a cmsg with payload `value: T`.
  ///
  /// Returns `Err(())` if the buffer doesn't have `CMSG_SPACE(sizeof T)` bytes
  /// remaining (i.e. the cmsg wouldn't fit). On success, the cursor advances
  /// past the encoded cmsg + alignment padding.
  pub(crate) fn push<T: Copy>(
    &mut self,
    level: libc::c_int,
    ty: libc::c_int,
    value: &T,
  ) -> Result<(), ()> {
    let payload_bytes = core::mem::size_of::<T>();
    // SAFETY: CMSG_SPACE is a pure macro over its size argument; no pointers.
    let space = unsafe { libc::CMSG_SPACE(payload_bytes as u32) } as usize;
    let end = self.cursor.checked_add(space).ok_or(())?;
    if end > self.buf.len() {
      return Err(());
    }
    // SAFETY: we just bounds-checked `space`, and `new()` enforced that the
    // buffer is aligned to `align_of::<cmsghdr>()`, so the header store at
    // `buf + cursor` honours `cmsghdr`'s alignment. `CMSG_DATA(hdr)` only
    // guarantees `cmsghdr`-alignment for the payload — which may be looser
    // than `align_of::<T>()` (e.g. `timeval` on Darwin) — so the payload is
    // written via `write_unaligned`, matching the rule documented on
    // [`CMsgRef::data`].
    unsafe {
      let hdr = self.buf.as_mut_ptr().add(self.cursor) as *mut cmsghdr;
      (*hdr).cmsg_len = libc::CMSG_LEN(payload_bytes as u32) as _;
      (*hdr).cmsg_level = level;
      (*hdr).cmsg_type = ty;
      let data = libc::CMSG_DATA(hdr) as *mut T;
      core::ptr::write_unaligned(data, *value);
    }
    self.cursor = end;
    Ok(())
  }

  /// Consume the builder and return the number of bytes written, i.e. the
  /// `msg_controllen` value to hand to `sendmsg`.
  #[inline]
  pub(crate) fn finish(self) -> usize {
    self.cursor
  }
}

/// Boxed 256-byte ancillary buffer whose backing storage is ≥8-byte aligned,
/// which is what `compio-net`'s `recv_msg` / `send_msg` assert for the
/// control parameter and what [`CMsgIter::new`] requires for sound walking.
///
/// `Vec<u8>::with_capacity` does not guarantee anything beyond alignment 1
/// in the type system, so we own a `Box<AlignedStorage>` whose inner type is
/// a `#[repr(align(8))]` array. The wrapper implements `IoBuf` / `IoBufMut`
/// / `SetLen` over a manually tracked `init_len`; `SetLen::set_len` accepts
/// values up to `CMSG_CAP` and never resizes (the buffer is fixed-size).
pub(super) struct AlignedCtrlBuf {
  storage: Box<AlignedCtrlStorage>,
  init_len: usize,
}

const CMSG_CAP: usize = 256;

#[repr(align(8))]
struct AlignedCtrlStorage([u8; CMSG_CAP]);

impl AlignedCtrlBuf {
  pub fn new() -> Self {
    Self {
      storage: Box::new(AlignedCtrlStorage([0u8; CMSG_CAP])),
      init_len: 0,
    }
  }

  /// Build a control buffer pre-filled with `src` (used for `send_msg`).
  ///
  /// # Panics
  ///
  /// Panics if `src.len() > CMSG_CAP` — outbound mDNS cmsgs (PKTINFO,
  /// HOPLIMIT) are well under that, so the static cap is fine.
  pub fn from_slice(src: &[u8]) -> Self {
    assert!(
      src.len() <= CMSG_CAP,
      "outbound cmsg payload {} exceeds CMSG_CAP={CMSG_CAP}",
      src.len()
    );
    let mut buf = Self::new();
    buf.storage.0[..src.len()].copy_from_slice(src);
    buf.init_len = src.len();
    buf
  }

  /// Return the initialised portion as a `&[u8]`, clamped to the actual
  /// fill length reported by the kernel.
  pub fn filled(&self, kernel_len: usize) -> &[u8] {
    let n = kernel_len.min(CMSG_CAP);
    &self.storage.0[..n]
  }
}

impl compio_buf::IoBuf for AlignedCtrlBuf {
  fn as_init(&self) -> &[u8] {
    &self.storage.0[..self.init_len]
  }
}

impl compio_buf::IoBufMut for AlignedCtrlBuf {
  fn as_uninit(&mut self) -> &mut [core::mem::MaybeUninit<u8>] {
    let ptr = self.storage.0.as_mut_ptr() as *mut core::mem::MaybeUninit<u8>;
    // SAFETY: `storage` owns a fixed `[u8; CMSG_CAP]` (all zeroed at
    // construction), so the pointer is valid for `CMSG_CAP` bytes and the
    // bytes are initialised — treating them as `MaybeUninit<u8>` is sound.
    unsafe { core::slice::from_raw_parts_mut(ptr, CMSG_CAP) }
  }
}

impl compio_buf::SetLen for AlignedCtrlBuf {
  unsafe fn set_len(&mut self, len: usize) {
    debug_assert!(len <= CMSG_CAP);
    self.init_len = len.min(CMSG_CAP);
  }
}

pub(super) fn enable_recv_cmsgs(sock: &std::net::UdpSocket) -> std::io::Result<()> {
  use std::os::fd::AsRawFd;
  let fd = sock.as_raw_fd();
  let on: libc::c_int = 1;
  // Apply ONLY the cmsg options for this socket's address family. The IPv4
  // options (`IPPROTO_IP`/`IP_PKTINFO`/`IP_RECVTTL`) return `EINVAL` on an
  // `AF_INET6` socket and vice-versa, so a blanket apply made every v6-only /
  // dual-stack endpoint fail construction (the wrong-family `setsockopt`
  // bubbled up through `from_std` before any datagram could flow). mDNS binds
  // a separate single-family socket per family, so `local_addr` is the
  // authoritative family selector.
  //
  // The capability `cfg`s (emitted by `build.rs`) compose WITH this runtime
  // family check: a cfg gates "does this target define the constant at all"
  // (so an exotic Unix that lacks it still compiles), while `is_v6` gates "is
  // this socket that family" (so we never apply the wrong-family option). Both
  // are required. `fd`/`on`/`is_v6` are touched unconditionally below so they
  // never read as unused on a target where every option's cfg is off.
  let is_v6 = matches!(sock.local_addr()?, std::net::SocketAddr::V6(_));
  let _ = (fd, on, is_v6);
  if is_v6 {
    // IPV6_RECVPKTINFO — destination address + interface index. Only where
    // libc defines IPV6_PKTINFO (`has_ipv6_pktinfo`).
    #[cfg(has_ipv6_pktinfo)]
    set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, on)?;
    // IPV6_RECVHOPLIMIT — hop limit for the §11 on-link check. Only where libc
    // defines the hop-limit cmsg (`has_recv_hoplimit`; absent on OpenBSD/NetBSD).
    #[cfg(has_recv_hoplimit)]
    set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, on)?;
  } else {
    // IP_PKTINFO — destination address + interface index. Only where libc
    // defines the shared in_pktinfo layout (`has_ip_pktinfo`; BSDs excluded).
    #[cfg(has_ip_pktinfo)]
    set_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, on)?;
    // IP_RECVTTL — TTL for the §11 on-link check. Only where libc defines the
    // hop-limit cmsg (`has_recv_hoplimit`; absent on OpenBSD/NetBSD).
    #[cfg(has_recv_hoplimit)]
    set_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, on)?;
  }
  // SO_TIMESTAMP[NS] — kernel rx time for ordered self-send classification.
  // Family-agnostic (`SOL_SOCKET`); best-effort, the recv path degrades to
  // read-time when it is absent. We ENABLE via the SO_* sockopt (the kernel
  // then tags the received cmsg with the matching SCM_* type, which
  // `decode_unix_cmsgs` matches). `recv_timestamp_ns` selects the nanosecond
  // SO_TIMESTAMPNS (Linux/Android) over the microsecond SO_TIMESTAMP.
  #[cfg(all(has_recv_timestamp, recv_timestamp_ns))]
  set_int(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, on).ok();
  #[cfg(all(has_recv_timestamp, not(recv_timestamp_ns)))]
  set_int(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP, on).ok();
  Ok(())
}

fn set_int(
  fd: std::os::fd::RawFd,
  level: libc::c_int,
  optname: libc::c_int,
  val: libc::c_int,
) -> std::io::Result<()> {
  // SAFETY: `&val` is a valid pointer to a `c_int`, passed with the matching length.
  let rc = unsafe {
    libc::setsockopt(
      fd,
      level,
      optname,
      &val as *const _ as *const _,
      core::mem::size_of::<libc::c_int>() as libc::socklen_t,
    )
  };
  if rc != 0 {
    Err(std::io::Error::last_os_error())
  } else {
    Ok(())
  }
}

pub(super) fn decode_unix_cmsgs(ctrl: &[u8], meta: &mut RecvMeta) {
  // `ctrl` originates from `AlignedCtrlBuf::filled`, whose storage is the
  // start of a `#[repr(align(8))]` array — so the slice's first byte is
  // aligned for `cmsghdr`. Defensive bail for the rare future caller that
  // doesn't honour that invariant.
  if ctrl.is_empty() {
    return;
  }
  if !ctrl.as_ptr().cast::<libc::cmsghdr>().is_aligned() {
    return;
  }
  for c in CMsgIter::new(ctrl) {
    match (c.level(), c.ty()) {
      // IPv4 PKTINFO — only where libc defines the shared in_pktinfo layout
      // (`has_ip_pktinfo`; BSDs excluded — see build.rs).
      #[cfg(has_ip_pktinfo)]
      (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
        if c.data_len() < core::mem::size_of::<libc::in_pktinfo>() {
          continue;
        }
        // SAFETY: kernel writes `in_pktinfo` for the `IP_PKTINFO` cmsg, and the
        // length guard above ensures the cmsg carries at least
        // `size_of::<in_pktinfo>()` payload bytes before this read. CMSG_DATA
        // is only `cmsghdr`-aligned, so use `read_unaligned`.
        let pi = unsafe { core::ptr::read_unaligned(c.data::<libc::in_pktinfo>()) };
        meta.local_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(pi.ipi_spec_dst.s_addr)));
        meta.interface_index = pi.ipi_ifindex as u32;
      }
      // IPv6 PKTINFO — only where libc defines IPV6_PKTINFO (`has_ipv6_pktinfo`).
      #[cfg(has_ipv6_pktinfo)]
      (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
        if c.data_len() < core::mem::size_of::<libc::in6_pktinfo>() {
          continue;
        }
        // SAFETY: kernel writes `in6_pktinfo` for the `IPV6_PKTINFO` cmsg, and
        // the length guard above ensures the payload is at least
        // `size_of::<in6_pktinfo>()` bytes before this read.
        let pi = unsafe { core::ptr::read_unaligned(c.data::<libc::in6_pktinfo>()) };
        meta.local_ip = IpAddr::V6(Ipv6Addr::from(pi.ipi6_addr.s6_addr));
        meta.interface_index = pi.ipi6_ifindex as u32;
      }
      // IPv4 TTL — only where libc defines the hop-limit cmsg constants
      // (`has_recv_hoplimit`; absent on OpenBSD/NetBSD).
      #[cfg(has_recv_hoplimit)]
      (libc::IPPROTO_IP, libc::IP_TTL) | (libc::IPPROTO_IP, libc::IP_RECVTTL) => {
        if c.data_len() < core::mem::size_of::<libc::c_int>() {
          continue;
        }
        // SAFETY: kernel writes a `c_int` for `IP_TTL` / `IP_RECVTTL`, and the
        // length guard above ensures at least `size_of::<c_int>()` payload
        // bytes are present before this read.
        let v = unsafe { core::ptr::read_unaligned(c.data::<libc::c_int>()) };
        meta.hop_limit = Some(v as u8);
      }
      // IPv6 Hop Limit — same `has_recv_hoplimit` gate as the IPv4 TTL arm.
      #[cfg(has_recv_hoplimit)]
      (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => {
        if c.data_len() < core::mem::size_of::<libc::c_int>() {
          continue;
        }
        // SAFETY: kernel writes a `c_int` for `IPV6_HOPLIMIT`, and the length
        // guard above ensures at least `size_of::<c_int>()` payload bytes are
        // present before this read.
        let v = unsafe { core::ptr::read_unaligned(c.data::<libc::c_int>()) };
        meta.hop_limit = Some(v as u8);
      }
      // Kernel receive timestamp. The kernel tags the cmsg with the SCM_* TYPE,
      // which is NOT always equal to the SO_* sockopt used to enable it
      // (Linux happens to share values; on Darwin/BSD SCM_TIMESTAMP == 0x02 !=
      // SO_TIMESTAMP). Match the SCM_* type the kernel actually delivers.
      // `recv_timestamp_ns` selects the nanosecond SCM_TIMESTAMPNS (timespec,
      // Linux/Android) over the microsecond SCM_TIMESTAMP (timeval, Apple/BSD).
      #[cfg(all(has_recv_timestamp, recv_timestamp_ns))]
      (libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS) => {
        if c.data_len() < core::mem::size_of::<libc::timespec>() {
          continue;
        }
        // SAFETY: kernel writes a `timespec` for `SCM_TIMESTAMPNS`, and the
        // length guard above ensures at least `size_of::<timespec>()` payload
        // bytes are present before this read.
        let ts = unsafe { core::ptr::read_unaligned(c.data::<libc::timespec>()) };
        // Checked arithmetic so a garbage `tv_sec`/`tv_nsec` declines the stamp
        // (leaving `kernel_rx_time` untouched) instead of panicking the driver.
        let nanos = u32::try_from(ts.tv_nsec).unwrap_or(0).min(999_999_999);
        if let Ok(secs) = u64::try_from(ts.tv_sec) {
          meta.kernel_rx_time =
            std::time::UNIX_EPOCH.checked_add(std::time::Duration::new(secs, nanos));
        }
      }
      #[cfg(all(has_recv_timestamp, not(recv_timestamp_ns)))]
      (libc::SOL_SOCKET, libc::SCM_TIMESTAMP) => {
        if c.data_len() < core::mem::size_of::<libc::timeval>() {
          continue;
        }
        // SAFETY: kernel writes a `timeval` for `SCM_TIMESTAMP`, and the length
        // guard above ensures at least `size_of::<timeval>()` payload bytes are
        // present before this read.
        let tv = unsafe { core::ptr::read_unaligned(c.data::<libc::timeval>()) };
        // Checked arithmetic so a garbage `tv_sec`/`tv_usec` declines the stamp
        // (leaving `kernel_rx_time` untouched) instead of panicking the driver.
        let micros = u32::try_from(tv.tv_usec).unwrap_or(0).min(999_999);
        if let Ok(secs) = u64::try_from(tv.tv_sec) {
          meta.kernel_rx_time =
            std::time::UNIX_EPOCH.checked_add(std::time::Duration::new(secs, micros * 1000));
        }
      }
      _ => {}
    }
  }
}

/// Regression for the family-blind cmsg setup: `enable_recv_cmsgs` used to
/// apply the IPv4-only `IP_PKTINFO` / `IP_RECVTTL` sockopts with a fatal `?`
/// to EVERY socket, so an `AF_INET6` socket failed with `EINVAL` and
/// `from_std` bubbled the error — breaking v6-only and dual-stack endpoint
/// construction before any datagram could flow. `from_std` must now succeed on
/// a v6 socket by applying only the v6 cmsg options.
#[cfg(all(unix, test))]
#[compio::test]
async fn from_std_enables_cmsgs_on_v6_socket() {
  use crate::socket::Socket;
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
#[cfg(all(unix, test))]
#[compio::test]
async fn from_std_enables_cmsgs_on_v4_socket() {
  use crate::socket::Socket;
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
#[cfg(all(unix, has_recv_timestamp, test))]
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
#[cfg(all(unix, test))]
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
#[cfg(all(unix, test))]
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
#[cfg(all(unix, has_recv_timestamp, test))]
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

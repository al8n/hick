use libc::{cmsghdr, msghdr};

// Each address type is used only inside its matching capability-gated cmsg arm
// below (`IpAddr` in both); gate the imports the same way so platforms that lack
// a pktinfo layout (e.g. BSDs have no `in_pktinfo`) don't see an unused import.
#[cfg(any(has_ip_pktinfo, has_ipv6_pktinfo))]
use core::net::IpAddr;
#[cfg(has_ip_pktinfo)]
use core::net::Ipv4Addr;
#[cfg(has_ipv6_pktinfo)]
use core::net::Ipv6Addr;

#[cfg(any(has_ip_pktinfo, has_ipv6_pktinfo))]
use hick_udp::onlink::{DestinationWitness, IfaceWitness};

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

  /// Append a cmsg whose payload is already a **byte image**.
  ///
  /// # Why a second path rather than another `push::<T>` caller
  ///
  /// [`Self::push`] stores its payload with a *typed* `write_unaligned::<T>`,
  /// and a typed copy does not preserve padding initializedness: for a `T` that
  /// has padding — `libc::timeval` is `{ time_t, suseconds_t }`, 12 bytes of
  /// fields in a 16-byte type on Apple/aarch64 — the destination's padding bytes
  /// become UNINITIALIZED, and reading the encoded range back as `&[u8]` is then
  /// undefined behaviour.
  ///
  /// **Pre-zeroing the destination does not save it.** [`Self::new`] already
  /// zeroes the whole buffer, and the typed write de-initializes that padding
  /// again regardless of what the destination held. That is the trap in the
  /// obvious fix, which is why the answer is to keep a padded struct out of
  /// `push::<T>` entirely rather than to prepare the buffer for it.
  ///
  /// So a caller whose encoded bytes must stay readable as `[u8]` builds the
  /// payload field by field, at each `core::mem::offset_of!` position inside a
  /// zeroed buffer, and hands the result here. Copying `[u8]` to `[u8]`
  /// initializes every byte it writes and de-initializes nothing.
  ///
  /// The header setup mirrors [`Self::push`] line for line, `CMSG_DATA`
  /// included, so the two paths cannot drift on where a payload begins.
  #[cfg(test)]
  pub(crate) fn push_bytes(
    &mut self,
    level: libc::c_int,
    ty: libc::c_int,
    payload: &[u8],
  ) -> Result<(), ()> {
    // SAFETY: CMSG_SPACE is a pure macro over its size argument; no pointers.
    let space = unsafe { libc::CMSG_SPACE(payload.len() as u32) } as usize;
    let end = self.cursor.checked_add(space).ok_or(())?;
    if end > self.buf.len() {
      return Err(());
    }
    // SAFETY: `space` is bounds-checked above and `new()` enforced the buffer's
    // `cmsghdr` alignment, so the header store is aligned. The header fields are
    // assigned INDIVIDUALLY rather than by storing a whole `cmsghdr` value: a
    // whole-struct store would de-initialize `cmsghdr`'s own padding (musl's
    // `__pad1`) exactly the way `push`'s typed payload store does. The payload
    // is then a byte-to-byte `copy_nonoverlapping` out of an initialized slice,
    // which can neither require nor destroy initializedness anywhere.
    unsafe {
      let hdr = self.buf.as_mut_ptr().add(self.cursor) as *mut cmsghdr;
      (*hdr).cmsg_len = libc::CMSG_LEN(payload.len() as u32) as _;
      (*hdr).cmsg_level = level;
      (*hdr).cmsg_type = ty;
      let data = libc::CMSG_DATA(hdr);
      core::ptr::copy_nonoverlapping(payload.as_ptr(), data, payload.len());
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
    // IPV6_RECVHOPLIMIT — hop limit, carried as a diagnostic and read by no
    // admission decision. Only where libc
    // defines the hop-limit cmsg (`has_recv_hoplimit`; absent on OpenBSD/NetBSD).
    #[cfg(has_recv_hoplimit)]
    set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, on)?;
  } else {
    // IP_PKTINFO — destination address + interface index. Only where libc
    // defines the shared in_pktinfo layout (`has_ip_pktinfo`; BSDs excluded).
    #[cfg(has_ip_pktinfo)]
    set_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, on)?;
    // IP_RECVTTL — TTL, carried as a diagnostic and read by no admission
    // decision. Only where libc defines the
    // hop-limit cmsg (`has_recv_hoplimit`; absent on OpenBSD/NetBSD).
    #[cfg(has_recv_hoplimit)]
    set_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, on)?;
  }
  // SO_TIMESTAMP[NS] — kernel rx time for ordered self-send classification.
  // Family-agnostic (`SOL_SOCKET`); best-effort, and a socket without it simply
  // yields no evidence, degrading the self-send match rather than breaking it.
  // We ENABLE via the SO_* sockopt; the kernel then tags the received cmsg with
  // the matching SCM_* type, which `hick-udp` — not this crate — decodes out of
  // the control buffer (see `RxEvidence::from_cmsgs` in `Socket::recv`).
  // `recv_timestamp_ns` selects the nanosecond SO_TIMESTAMPNS (Linux/Android)
  // over the microsecond SO_TIMESTAMP; `hick-udp`'s matching cfg selects the
  // SCM_* type it looks for, and both crates emit that cfg from the same
  // build.rs matrix.
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

pub(super) fn decode_unix_cmsgs(ctrl: &[u8], meta: &mut RecvMeta, control_truncated: bool) {
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
        // `ipi_addr` is the IP header DESTINATION — the group, for a multicast
        // arrival — while `ipi_spec_dst` above is the receiving interface's own
        // unicast address. RFC 6762 §11 selects its local-link test by the
        // former; reading the latter made every multicast arrival look unicast
        // and sent it to the source-prefix arm, which refuses an on-link peer
        // sourcing from a prefix this interface does not carry.
        meta.destination = DestinationWitness::Witnessed(IpAddr::V4(Ipv4Addr::from(u32::from_be(
          pi.ipi_addr.s_addr,
        ))));
        // A zero `ipi_ifindex` INSIDE a present cmsg is a kernel that named no
        // interface, not a path that cannot name one — `from_reporting_path`
        // makes that `Declined`, or `Lost` where our own buffer truncated. The
        // C field is `int` (`c_int` in `libc` on Linux and Android, `c_uint` on
        // Apple), so it goes through the SIGNED constructor, where a negative
        // is that same absence and never an index near `u32::MAX`.
        meta.iface =
          IfaceWitness::from_reporting_path_signed(pi.ipi_ifindex as i32, control_truncated);
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
        // IPv6 PKTINFO carries only the header destination — there is no
        // `ipi_spec_dst` twin — so the one address serves as both.
        meta.local_ip = IpAddr::V6(Ipv6Addr::from(pi.ipi6_addr.s6_addr));
        meta.destination =
          DestinationWitness::Witnessed(IpAddr::V6(Ipv6Addr::from(pi.ipi6_addr.s6_addr)));
        // `libc` types `ipi6_ifindex` as `c_int` on Android and `c_uint` on
        // every other supported unix, though the Linux uapi header declares it
        // `int` there too. The `as i32` normalises both onto the signed
        // constructor, where a negative is an absence rather than an index near
        // `u32::MAX`.
        meta.iface =
          IfaceWitness::from_reporting_path_signed(pi.ipi6_ifindex as i32, control_truncated);
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
      // The kernel receive-timestamp cmsg is deliberately NOT decoded here.
      // `SCM_TIMESTAMP`/`SCM_TIMESTAMPNS` is one wire format, `hick-udp` already
      // reads it, and `Socket::recv` hands it this same buffer through
      // `RxEvidence::from_cmsgs`. Two readings of one kernel ABI drift silently
      // — a wrong stamp still type-checks — and that is the cost this crate
      // stopped paying. It does NOT make the resulting evidence checkable: that
      // is still a caller contract, discharged at the `from_cmsgs` call site.
      // An arm added back here would re-take the cost and buy nothing.
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

/// The kernel receive-timestamp payload as a **byte image**: `libc::timespec`
/// on Linux/Android, `libc::timeval` on Apple/BSD, with every byte initialized.
///
/// Assembled field by field at each `core::mem::offset_of!` position inside a
/// zeroed buffer; the struct never exists as a value at all. That is a
/// soundness requirement rather than a style choice. On Apple/aarch64
/// `libc::timeval` is `{ time_t, suseconds_t }` — 12 bytes of fields in a
/// 16-byte type — so a struct literal leaves four TAIL-PADDING bytes
/// uninitialized, and any *typed* store of such a value (`write_unaligned::<T>`,
/// which is what [`CMsgBuilder::push`] does) carries that uninitializedness into
/// the control buffer. Reading the encoded range back as `&[u8]` is then
/// undefined behaviour.
///
/// **Zeroing the destination first does not help.** A typed copy does not
/// preserve padding initializedness, so the padding is de-initialized again
/// whatever the destination held — which is exactly why the fix is to keep the
/// padded struct out of the typed path rather than to prepare the buffer for it.
///
/// # Which targets actually pad, measured rather than assumed
///
/// It is not an Apple quirk and it is not the whole `timeval` family either, so
/// neither "it is only Darwin" nor "it is only `timeval`" is a safe shortcut:
///
/// * `aarch64-apple-darwin` — `timeval` **pads**, 12 bytes of fields in 16
///   (`suseconds_t` is `i32` beside an `i64` `time_t`);
/// * `x86_64-unknown-netbsd` — `timeval` **pads**, for the same reason;
/// * `x86_64-unknown-freebsd` — `timeval` does NOT pad; `suseconds_t` is 8 bytes
///   there, so the fields tile the struct;
/// * `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-musl` — `timespec` does
///   NOT pad, two 8-byte fields in 16.
///
/// This construction does not consult that table — it is padding-correct either
/// way, which is the point of writing at `offset_of!` into zeroed bytes rather
/// than reasoning per target. The table is here so a future reader knows the
/// hazard is real on more than one supported target, and
/// `timestamp_payload_padding_is_measured_not_assumed` keeps the numbers honest
/// on whatever target actually runs.
#[cfg(all(unix, has_recv_timestamp, test))]
fn ts_payload_bytes(secs: i64, sub: i64) -> Vec<u8> {
  #[cfg(recv_timestamp_ns)]
  use libc::timespec as TsPayload;
  #[cfg(not(recv_timestamp_ns))]
  use libc::timeval as TsPayload;

  let mut buf = vec![0u8; core::mem::size_of::<TsPayload>()];
  {
    let mut put = |offset: usize, bytes: &[u8]| {
      buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    };
    put(
      core::mem::offset_of!(TsPayload, tv_sec),
      &(secs as libc::time_t).to_ne_bytes(),
    );
    #[cfg(recv_timestamp_ns)]
    put(
      core::mem::offset_of!(TsPayload, tv_nsec),
      &(sub as libc::c_long).to_ne_bytes(),
    );
    #[cfg(not(recv_timestamp_ns))]
    put(
      core::mem::offset_of!(TsPayload, tv_usec),
      &(sub as libc::suseconds_t).to_ne_bytes(),
    );
  }
  buf
}

/// Which of the two layouts this target uses, and whether it has tail padding —
/// measured rather than assumed, because the whole padding defect turns on it
/// and a target that quietly grew padding would otherwise re-open it silently.
///
/// This asserts nothing about *which* answer is right: [`ts_payload_bytes`] is
/// correct either way. It exists so the answer is on the record per target — on
/// Apple/aarch64 `timeval` is 16 bytes over 12 bytes of fields (4 padding) while
/// `timespec` is 16 over 16 (none).
#[cfg(all(unix, has_recv_timestamp, test))]
#[test]
fn timestamp_payload_padding_is_measured_not_assumed() {
  #[cfg(not(recv_timestamp_ns))]
  let (name, size, fields) = (
    "timeval",
    core::mem::size_of::<libc::timeval>(),
    core::mem::size_of::<libc::time_t>() + core::mem::size_of::<libc::suseconds_t>(),
  );
  #[cfg(recv_timestamp_ns)]
  let (name, size, fields) = (
    "timespec",
    core::mem::size_of::<libc::timespec>(),
    core::mem::size_of::<libc::time_t>() + core::mem::size_of::<libc::c_long>(),
  );
  assert!(
    fields <= size,
    "{name}: fields ({fields}) cannot exceed the struct ({size})"
  );
  // The byte image must cover the WHOLE struct, padding included, or the bytes
  // handed to `push_bytes` would be short of `CMSG_LEN`'s payload length.
  assert_eq!(
    ts_payload_bytes(1, 2).len(),
    size,
    "{name}: the byte image must span the struct, not just its fields"
  );
  println!(
    "{name}: size={size} fields={fields} padding={}",
    size - fields
  );
}

/// Build a minimal control buffer containing a single SOL_SOCKET receive-
/// timestamp cmsg (the SCM_* TYPE the kernel actually delivers — and that
/// `decode_unix_cmsgs` matches), then iterate it and verify level/type/data.
/// The constant + payload are chosen by `recv_timestamp_ns`: nanosecond
/// SCM_TIMESTAMPNS/timespec on Linux/Android, microsecond SCM_TIMESTAMP/timeval
/// on Apple/BSD.
///
/// The buffer is built by hand rather than through [`CMsgBuilder`] on purpose:
/// this is `CMsgIter`'s test, and routing it through the builder would make the
/// two halves of one round trip prove each other. What it does share is
/// [`ts_payload_bytes`] — the payload goes in as an initialized byte image and
/// is copied byte-to-byte, never stored as a padded struct value.
#[cfg(all(unix, has_recv_timestamp, test))]
#[test]
fn cmsg_iter_walks_a_single_timestamp_cmsg() {
  #[cfg(not(recv_timestamp_ns))]
  use libc::{SCM_TIMESTAMP as TS_TYPE, timeval as TsPayload};
  #[cfg(recv_timestamp_ns)]
  use libc::{SCM_TIMESTAMPNS as TS_TYPE, timespec as TsPayload};
  use libc::{SOL_SOCKET, cmsghdr};
  let payload = ts_payload_bytes(1234, 56);
  let payload_bytes = payload.len();
  assert_eq!(payload_bytes, core::mem::size_of::<TsPayload>());
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
  // SAFETY: buf is correctly sized and zero-initialised; we write a valid
  // cmsghdr. The header pointer is aligned (Vec<u64> backing). Its fields are
  // assigned INDIVIDUALLY, never by storing a whole `cmsghdr` value, so the
  // header's own padding (musl's `__pad1`) keeps the zeroes above. The payload
  // is a byte-to-byte `copy_nonoverlapping` out of an initialized slice, which
  // needs no alignment and — unlike the `write_unaligned::<TsPayload>` this
  // replaced — cannot de-initialize the struct's tail padding. See
  // `ts_payload_bytes`.
  unsafe {
    let hdr = buf.as_mut_ptr() as *mut cmsghdr;
    (*hdr).cmsg_len = libc::CMSG_LEN(payload_bytes as u32) as _;
    (*hdr).cmsg_level = SOL_SOCKET;
    (*hdr).cmsg_type = TS_TYPE;
    let data = libc::CMSG_DATA(hdr);
    core::ptr::copy_nonoverlapping(payload.as_ptr(), data, payload_bytes);
  }
  // Every encoded byte must be genuinely INITIALIZED, not merely zero. Only a
  // real per-byte read asserts that: the walk below reads the header fields and
  // then the payload as a typed `TsPayload`, and a typed read does not require
  // padding to be initialized — so without this loop the uninitialized-padding
  // regression is invisible here. Under Miri this is the regression test; in a
  // normal build it is a cheap checksum.
  let mut acc: u64 = 0;
  for b in buf.iter() {
    acc = acc.wrapping_add(u64::from(*b));
  }
  assert!(acc > 0, "the encoded cmsg must not be all-zero");
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
///
/// `has_ip_pktinfo`-gated: `IP_PKTINFO`/`in_pktinfo` are only bound where
/// `build.rs` sets that cfg (Linux/Android/Apple); the BSDs have no
/// `IP_PKTINFO` (NetBSD's `in_pktinfo` is a different, incompatible shape —
/// see `build.rs`), so a bare `#[cfg(all(unix, test))]` here fails to link
/// the import on FreeBSD/OpenBSD/DragonFly/NetBSD.
#[cfg(all(unix, has_ip_pktinfo, test))]
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
///
/// `has_ip_pktinfo`-gated: same reason as
/// [`cmsg_builder_emits_a_round_trippable_pktinfo`] — `IP_PKTINFO`/`in_pktinfo`
/// are unbound on the BSDs.
#[cfg(all(unix, has_ip_pktinfo, test))]
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
  decode_unix_cmsgs(buf, &mut meta, false);
  // Left at defaults: the truncated cmsg was skipped, never read as garbage.
  assert!(
    meta.local_ip.is_unspecified(),
    "truncated PKTINFO populated local_ip from a short cmsg"
  );
  assert_eq!(
    meta.iface.index_or_zero(),
    0,
    "truncated PKTINFO populated the interface witness from a short cmsg"
  );
}

/// The receive-timestamp cmsg is `hick-udp`'s to read, and this crate must not
/// grow a second reading of it.
///
/// Both halves are asserted over the SAME bytes: `decode_unix_cmsgs` walks a
/// buffer carrying a perfectly good timestamp cmsg and must leave
/// `RecvMeta::rx` exactly as `RecvMeta::empty` set it, while
/// `RxEvidence::from_cmsgs` — the constructor `Socket::recv` routes that buffer
/// through — must be what recovers the stamp. An arm added back to the decoder
/// fails the first assertion; a `Socket::recv` that stopped calling
/// `from_cmsgs` would leave the driver claiming self-sends on `Degraded`
/// evidence forever, which nothing louder than the second assertion detects.
///
/// Malformed and absurd payloads are not retried here. That parser has one
/// implementation now and `hick-udp` tests it against `i64::MAX` in both
/// fields; re-proving it from this side is the duplication this change removed.
#[cfg(all(unix, has_recv_timestamp, test))]
#[test]
fn timestamp_cmsg_is_decoded_by_hick_udp_and_not_by_this_crate() {
  use hick_udp::selfsend::RxEvidence;
  use libc::{SOL_SOCKET, cmsghdr};

  // The SCM_* TYPE the kernel delivers, selected by `recv_timestamp_ns` exactly
  // as `hick-udp`'s parser selects the type it looks for — both cfgs come from
  // the same build.rs matrix, which is what keeps the two crates in step.
  #[cfg(not(recv_timestamp_ns))]
  use libc::{SCM_TIMESTAMP as TS_TYPE, timeval as TsPayload};
  #[cfg(recv_timestamp_ns)]
  use libc::{SCM_TIMESTAMPNS as TS_TYPE, timespec as TsPayload};

  // The payload goes in as an initialized BYTE IMAGE and never exists as a
  // padded `TsPayload` value — see `ts_payload_bytes` for why that is a
  // soundness requirement rather than a style choice, and `push_bytes` for why
  // the builder needs a second path to accept it. Both assertions below read the
  // encoded range as `&[u8]`, which is undefined behaviour over an
  // uninitialized byte.
  let payload = ts_payload_bytes(1_700_000_000, 123_456);
  assert_eq!(payload.len(), core::mem::size_of::<TsPayload>());

  // `vec![0u8; _]` is only alignment 1, which `CMsgBuilder::new` refuses; back
  // the buffer with a `Vec<u64>` for ≥8-byte alignment as the tests above do.
  const TOTAL: usize = 128;
  assert!(core::mem::align_of::<cmsghdr>() <= core::mem::align_of::<u64>());
  let mut backing: Vec<u64> = vec![0u64; TOTAL / core::mem::size_of::<u64>()];
  // SAFETY: backing owns `TOTAL` zeroed bytes; the slice fits inside the
  // allocation and stays borrowed for this scope.
  let buf: &mut [u8] =
    unsafe { core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast::<u8>(), TOTAL) };
  let written = {
    let mut b = CMsgBuilder::new(buf);
    b.push_bytes(SOL_SOCKET, TS_TYPE, &payload).expect("fits");
    b.finish()
  };

  // Every byte of the encoded cmsg must be genuinely INITIALIZED, not merely
  // zero — the distinction the padding defect turns on, and one that only a
  // real per-byte read can assert. A `to_vec`/`copy_from_slice` would propagate
  // uninitializedness instead of tripping over it, and the two assertions below
  // would not catch it either: `decode_unix_cmsgs` skips this cmsg and
  // `parse_rx_time` reads it back as a typed `timeval`, neither of which needs
  // the padding initialized. Under Miri this loop is the whole regression test;
  // in a normal build it is a cheap checksum.
  let mut acc: u64 = 0;
  for b in &buf[..written] {
    acc = acc.wrapping_add(u64::from(*b));
  }
  assert!(acc > 0, "the encoded cmsg must not be all-zero");

  let mut meta = RecvMeta::empty(([0u8, 0, 0, 0], 0).into());
  decode_unix_cmsgs(&buf[..written], &mut meta, false);
  assert_eq!(
    meta.rx,
    RxEvidence::none(),
    "this crate's decoder must not read the timestamp cmsg for itself"
  );
  assert_ne!(
    RxEvidence::from_cmsgs(&buf[..written]),
    RxEvidence::none(),
    "hick-udp's parse, over the very same bytes, is what must recover it"
  );
}

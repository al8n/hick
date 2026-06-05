//! compio UdpSocket wrapper + in-crate cmsg codec (ported from compio-quic 0.7.2).

#![cfg(any(unix, windows))]
// CMsgIter/CMsgRef are wired in by their consumers (CMsgBuilder, RecvMeta, Socket); silence
// `dead_code` until the consumers land in the same crate.
#![allow(dead_code)]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;

#[cfg(unix)]
use libc::{cmsghdr, msghdr};

#[cfg(test)]
mod tests;

/// One ancillary control message inside a filled control buffer.
#[cfg(unix)]
pub(crate) struct CMsgRef<'a> {
  inner: &'a cmsghdr,
}

#[cfg(unix)]
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
#[cfg(unix)]
pub(crate) struct CMsgIter<'a> {
  msg: msghdr,
  next: *const cmsghdr,
  _lt: core::marker::PhantomData<&'a [u8]>,
}

#[cfg(unix)]
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

#[cfg(unix)]
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
#[cfg(unix)]
pub(crate) struct CMsgBuilder<'a> {
  buf: &'a mut [u8],
  cursor: usize,
}

#[cfg(unix)]
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

/// Decoded recv metadata pulled from cmsgs.
///
/// Reachable from `hick_compio::__test` for integration tests; the public
/// surface of the driver is wired up separately.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
  /// The peer that sent the datagram.
  peer: SocketAddr,
  /// The destination address recorded by the kernel (from PKTINFO).
  local_ip: IpAddr,
  /// Receiving interface index, taken from PKTINFO.
  interface_index: u32,
  /// IP TTL / IPv6 hop limit if the kernel exposed it.
  hop_limit: Option<u8>,
  /// Kernel-stamped rx time (SO_TIMESTAMP / SO_TIMESTAMPNS).
  kernel_rx_time: Option<SystemTime>,
  /// Bytes of payload received.
  len: usize,
  /// True when the datagram exceeded `max_recv_packet_size`, indicating it was
  /// truncated by the kernel (compio's `recv_msg` does not expose `msg_flags`,
  /// so a `data_len > max_recv_packet_size` overflow into the one-byte sentinel
  /// the buffer is over-allocated by is the proxy for `MSG_TRUNC`). The driver
  /// treats such datagrams as consumed-but-unusable (bumps `packets_rx` +
  /// `packets_dropped`) without routing them to proto.
  truncated: bool,
}

impl RecvMeta {
  pub(crate) fn empty(peer: SocketAddr) -> Self {
    let local_ip = match peer {
      SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    Self {
      peer,
      local_ip,
      interface_index: 0,
      hop_limit: None,
      kernel_rx_time: None,
      len: 0,
      truncated: false,
    }
  }

  /// The peer that sent the datagram.
  #[inline(always)]
  pub(crate) const fn peer(&self) -> SocketAddr {
    self.peer
  }

  /// The destination address the kernel recorded for the datagram (PKTINFO).
  #[inline(always)]
  pub(crate) const fn local_ip(&self) -> IpAddr {
    self.local_ip
  }

  /// The receiving interface index (PKTINFO).
  #[inline(always)]
  pub(crate) const fn interface_index(&self) -> u32 {
    self.interface_index
  }

  /// The IP TTL / IPv6 hop limit, if the kernel exposed it.
  #[inline(always)]
  pub(crate) const fn hop_limit(&self) -> Option<u8> {
    self.hop_limit
  }

  /// The kernel-stamped rx time, if available.
  #[inline(always)]
  pub(crate) const fn kernel_rx_time(&self) -> Option<SystemTime> {
    self.kernel_rx_time
  }

  /// True when the datagram exceeded the socket's configured
  /// `max_recv_packet_size` (overflowing into the one-byte over-allocation
  /// sentinel) and was therefore silently truncated by the kernel. A legal
  /// datagram of exactly `max_recv_packet_size` bytes is NOT flagged. The driver
  /// treats flagged datagrams as consumed-but-unusable (stats counted, not
  /// routed to proto).
  #[inline(always)]
  pub(crate) const fn truncated(&self) -> bool {
    self.truncated
  }

  /// Full constructor. Test-only: production code builds a `RecvMeta` via
  /// [`Self::empty`] plus in-module cmsg decoding.
  #[cfg(test)]
  pub(crate) const fn new(
    peer: SocketAddr,
    local_ip: IpAddr,
    interface_index: u32,
    hop_limit: Option<u8>,
    kernel_rx_time: Option<SystemTime>,
    len: usize,
  ) -> Self {
    Self {
      peer,
      local_ip,
      interface_index,
      hop_limit,
      kernel_rx_time,
      len,
      truncated: false,
    }
  }

  /// Mark the datagram as truncated. Test-only: production code sets this flag
  /// inside `Socket::recv` via the full-buffer heuristic.
  #[cfg(test)]
  pub(crate) const fn with_truncated(mut self) -> Self {
    self.truncated = true;
    self
  }
}

/// `compio` UDP socket wrapper + cmsg-aware recv/send.
///
/// The constructor enables the kernel ancillary-data options needed by the
/// driver (PKTINFO for the receiving interface, RECVTTL/HOPLIMIT for RFC 6762
/// §11 on-link checks, and `SO_TIMESTAMP`/`SO_TIMESTAMPNS` for ordered
/// self-send classification) and then wraps the file descriptor as a
/// `compio` socket.
///
/// Reachable from `hick_compio::__test` for integration tests; the public
/// surface of the driver is wired up separately.
pub struct Socket {
  inner: compio_net::UdpSocket,
}

impl Socket {
  /// Wrap an already-bound + joined `std::net::UdpSocket`, enabling cmsg recv
  /// options. Mirrors `compio-quic 0.7.2` socket construction.
  pub async fn from_std(sock: std::net::UdpSocket) -> std::io::Result<Self> {
    sock.set_nonblocking(true)?;
    #[cfg(unix)]
    {
      enable_recv_cmsgs(&sock)?;
    }
    let inner = compio_net::UdpSocket::from_std(sock)?;
    Ok(Self { inner })
  }

  /// One `recv_msg` with a 256-byte ancillary buffer; decode the metadata
  /// into [`RecvMeta`]. Owns its data + control buffers across the completion.
  ///
  /// Control buffer is backed by an `AlignedCtrlBuf` newtype that wraps a
  /// `[u8; 256]` inside a `#[repr(align(8))]` struct — guaranteeing the
  /// `cmsghdr` alignment that [`CMsgIter::new`] / `compio-net`'s `recv_msg`
  /// both require.
  pub async fn recv(&self, max: usize) -> std::io::Result<(Vec<u8>, RecvMeta)> {
    // Over-allocate by one sentinel byte beyond `max` (= max_recv_packet_size).
    // A legal datagram of up to and including `max` bytes then fits without
    // touching the sentinel (`data_len <= max`), while an oversized datagram
    // overflows into it (`data_len == max + 1`, the kernel having truncated the
    // tail). Testing `data_len > max` therefore distinguishes a truncated
    // datagram from a legal exactly-`max`-byte one — keeping
    // `max_recv_packet_size` a true *inclusive* ceiling rather than dropping a
    // perfectly-sized packet.
    let buf: Vec<u8> = Vec::with_capacity(max + 1);
    #[cfg(unix)]
    {
      let ctrl = AlignedCtrlBuf::new();
      let compio_buf::BufResult(res, (buf, ctrl)) = self.inner.recv_msg(buf, ctrl).await;
      // compio-net 0.12's `recv_msg` returns a 4-tuple
      // `(data_len, ctrl_len, peer, ReturnFlags)` — the trailing `ReturnFlags`
      // (recvmsg `msg_flags`) was added in #935. We deliberately keep using the
      // `data_len > max` sentinel proxy below rather than `flags.contains(TRUNC)`:
      // the sentinel is a true *inclusive* ceiling (a legal exactly-`max`-byte
      // datagram is preserved), whereas `MSG_TRUNC` would flag it. Bind the flags
      // to `_` to preserve the existing truncation semantics byte-for-byte.
      let (data_len, ctrl_len, peer, _recv_flags) = res?;
      let mut data = buf;
      // `compio-buf`'s `advance_vec_to` already set `data.len() = data_len`
      // through the `[Vec<u8>; 1]` SetLen impl, but truncate defensively.
      if data.len() > data_len {
        data.truncate(data_len);
      }
      let mut meta = RecvMeta::empty(peer);
      meta.len = data_len;
      // We do NOT read `msghdr::msg_flags` / `ReturnFlags::TRUNC` here (see the
      // note above). Use the buffer-sentinel proxy: the buffer is sized to
      // `max + 1`, so the kernel can only write more than `max` bytes when the
      // datagram exceeded `max_recv_packet_size` and was silently truncated. A
      // legal datagram of exactly `max` bytes lands as `data_len == max` and is
      // NOT flagged. The driver treats a flagged datagram as consumed-but-unusable.
      meta.truncated = data_len > max;
      let ctrl_bytes = ctrl.filled(ctrl_len);
      decode_unix_cmsgs(ctrl_bytes, &mut meta);
      Ok((data, meta))
    }
    #[cfg(not(unix))]
    {
      // Windows: no cmsg plumbing yet. Fall back to plain `recv_from` and
      // leave the per-packet PKTINFO / TTL fields empty. The driver still
      // works for loopback / single-interface scenarios; a proper Windows
      // port (WSARecvMsg + WSACMSG_FIRSTHDR) is a follow-up task.
      let compio_buf::BufResult(res, buf) = self.inner.recv_from(buf).await;
      let (data_len, peer) = res?;
      let mut data = buf;
      if data.len() > data_len {
        data.truncate(data_len);
      }
      let mut meta = RecvMeta::empty(peer);
      meta.len = data_len;
      // Same truncation proxy as the Unix path: `recv_from` doesn't expose
      // `WSAEMSGSIZE`/`MSG_TRUNC` as a flag, so the `max + 1` sentinel buffer +
      // `data_len > max` test stands in for it (a legal exactly-`max`-byte
      // datagram is preserved). The Windows WSARecvMsg port (follow-up task)
      // will use `dwFlags & MSG_TRUNC` once landed.
      meta.truncated = data_len > max;
      Ok((data, meta))
    }
  }

  /// Send `buf` to `dst`, optionally with caller-provided cmsg bytes
  /// already encoded via [`CMsgBuilder`]. The cmsg payload is copied into
  /// a stack-aligned [`AlignedCtrlBuf`] so callers may pass a borrowed
  /// slice that came from any allocator.
  pub async fn send_to(
    &self,
    buf: &[u8],
    dst: core::net::SocketAddr,
    ctrl: Option<&[u8]>,
  ) -> std::io::Result<usize> {
    let data = buf.to_vec();
    match ctrl {
      #[cfg(unix)]
      Some(c) if !c.is_empty() => {
        let ctrl_buf = AlignedCtrlBuf::from_slice(c);
        let compio_buf::BufResult(res, _) = self.inner.send_msg(data, ctrl_buf, dst).await;
        res
      }
      #[cfg(not(unix))]
      Some(_) => {
        // Windows: ignore caller-provided cmsg payload (PKTINFO/HOPLIMIT) and
        // fall back to plain send. The kernel picks the egress interface based
        // on the routing table; a proper Windows port (WSASendMsg) is a
        // follow-up task.
        let compio_buf::BufResult(res, _) = self.inner.send_to(data, dst).await;
        res
      }
      _ => {
        let compio_buf::BufResult(res, _) = self.inner.send_to(data, dst).await;
        res
      }
    }
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
#[cfg(unix)]
struct AlignedCtrlBuf {
  storage: Box<AlignedCtrlStorage>,
  init_len: usize,
}

#[cfg(unix)]
const CMSG_CAP: usize = 256;

#[cfg(unix)]
#[repr(align(8))]
struct AlignedCtrlStorage([u8; CMSG_CAP]);

#[cfg(unix)]
impl AlignedCtrlBuf {
  fn new() -> Self {
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
  fn from_slice(src: &[u8]) -> Self {
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
  fn filled(&self, kernel_len: usize) -> &[u8] {
    let n = kernel_len.min(CMSG_CAP);
    &self.storage.0[..n]
  }
}

#[cfg(unix)]
impl compio_buf::IoBuf for AlignedCtrlBuf {
  fn as_init(&self) -> &[u8] {
    &self.storage.0[..self.init_len]
  }
}

#[cfg(unix)]
impl compio_buf::IoBufMut for AlignedCtrlBuf {
  fn as_uninit(&mut self) -> &mut [core::mem::MaybeUninit<u8>] {
    let ptr = self.storage.0.as_mut_ptr() as *mut core::mem::MaybeUninit<u8>;
    // SAFETY: `storage` owns a fixed `[u8; CMSG_CAP]` (all zeroed at
    // construction), so the pointer is valid for `CMSG_CAP` bytes and the
    // bytes are initialised — treating them as `MaybeUninit<u8>` is sound.
    unsafe { core::slice::from_raw_parts_mut(ptr, CMSG_CAP) }
  }
}

#[cfg(unix)]
impl compio_buf::SetLen for AlignedCtrlBuf {
  unsafe fn set_len(&mut self, len: usize) {
    debug_assert!(len <= CMSG_CAP);
    self.init_len = len.min(CMSG_CAP);
  }
}

#[cfg(unix)]
fn enable_recv_cmsgs(sock: &std::net::UdpSocket) -> std::io::Result<()> {
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

#[cfg(unix)]
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

#[cfg(unix)]
fn decode_unix_cmsgs(ctrl: &[u8], meta: &mut RecvMeta) {
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

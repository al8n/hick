//! Windows socket option setters via socket2, plus a `WSARecvMsg`-based
//! receive path that recovers the datagram's receiving interface index and
//! local destination address (IP_PKTINFO / IPV6_PKTINFO).
//!
//! without the receiving interface index the driver cannot enforce
//! the RFC 6762 §11 bound-interface scoping for link-local sources on Windows
//! (a wildcard-bound socket receives from every interface). `recv_with_meta`
//! delivers that index so the §11 fallback is properly scoped here too.

use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
  os::windows::io::{AsRawSocket, BorrowedSocket},
};

use socket2::{Domain, Protocol, Socket, Type};
use windows_sys::Win32::Networking::WinSock::{
  AF_INET, AF_INET6, IP_PKTINFO, IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO, MSG_CTRUNC,
  SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKADDR, SOCKADDR_STORAGE, SOCKET, SOCKET_ERROR, WSABUF,
  WSAID_WSARECVMSG, WSAIoctl, WSAMSG, setsockopt,
};

use crate::{
  multicast::RecvMeta,
  onlink::{DestinationWitness, IfaceWitness},
};

fn as_socket(s: &UdpSocket) -> std::io::Result<Socket> {
  Ok(Socket::from(s.try_clone()?))
}

/// Create and bind an IPv4 mDNS UDP socket via socket2 (Windows mirror of
/// `crate::platform::unix::bind_v4`). `SO_REUSEADDR` precedes bind; the optional
/// `IP_MULTICAST_IF` and the `IP_TTL` (=255 for legacy unicast replies, RFC 6762
/// §11) follow. Windows has no `SO_REUSEPORT`.
pub(crate) fn bind_v4(
  local: SocketAddrV4,
  multicast_if: Option<Ipv4Addr>,
  unicast_ttl: u8,
) -> std::io::Result<UdpSocket> {
  let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
  sock.set_reuse_address(true)?;
  sock.bind(&SocketAddr::V4(local).into())?;
  if let Some(ip) = multicast_if {
    sock.set_multicast_if_v4(&ip)?;
  }
  sock.set_ttl_v4(unicast_ttl as u32)?;
  Ok(sock.into())
}

/// Create and bind an IPv6 mDNS UDP socket via socket2 (Windows mirror of
/// `crate::platform::unix::bind_v6`): `IPV6_V6ONLY` + `SO_REUSEADDR` before bind,
/// optional `IPV6_MULTICAST_IF`, then `IPV6_UNICAST_HOPS` (=255, RFC 6762 §11).
pub(crate) fn bind_v6(
  local: SocketAddrV6,
  multicast_if_index: u32,
  unicast_hops: u8,
) -> std::io::Result<UdpSocket> {
  let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
  sock.set_only_v6(true)?;
  sock.set_reuse_address(true)?;
  sock.bind(&SocketAddr::V6(local).into())?;
  if multicast_if_index != 0 {
    sock.set_multicast_if_v6(multicast_if_index)?;
  }
  sock.set_unicast_hops_v6(unicast_hops as u32)?;
  Ok(sock.into())
}

pub(crate) fn set_multicast_loop_v4(sock: &UdpSocket, on: bool) -> std::io::Result<()> {
  as_socket(sock)?.set_multicast_loop_v4(on)
}

pub(crate) fn set_multicast_ttl_v4(sock: &UdpSocket, ttl: u8) -> std::io::Result<()> {
  as_socket(sock)?.set_multicast_ttl_v4(ttl as u32)
}

pub(crate) fn set_multicast_hops_v6(sock: &UdpSocket, hops: u8) -> std::io::Result<()> {
  as_socket(sock)?.set_multicast_hops_v6(hops as u32)
}

pub(crate) fn set_multicast_loop_v6(sock: &UdpSocket, on: bool) -> std::io::Result<()> {
  as_socket(sock)?.set_multicast_loop_v6(on)
}

/// Enable `IP_PKTINFO` so `WSARecvMsg` reports the receiving interface index
/// and local destination address for each IPv4 datagram.
pub(crate) fn set_recv_pktinfo_v4(sock: &UdpSocket) -> std::io::Result<()> {
  set_bool_sockopt(sock, IPPROTO_IP, IP_PKTINFO)
}

/// No-op on Windows: `IP_RECVDSTADDR` / `IP_RECVIF` are the BSD spelling of the
/// two facts `IP_PKTINFO` above already delivers here, and Winsock defines
/// neither. See the unix twin for the `has_ip_dstaddr_recvif` capability they
/// gate; Windows reaches `reports_rx_interface_v4() == true` through
/// `cfg!(windows)` instead.
pub(crate) fn set_recv_dstaddr_recvif_v4(_sock: &UdpSocket) -> std::io::Result<()> {
  Ok(())
}

/// Enable `IPV6_PKTINFO` so `WSARecvMsg` reports the receiving interface index
/// and local destination address for each IPv6 datagram.
pub(crate) fn set_recv_pktinfo_v6(sock: &UdpSocket) -> std::io::Result<()> {
  set_bool_sockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO)
}

/// No-op on Windows: kernel receive-timestamp cmsgs are out of scope here, so
/// `RecvMeta::rx_time` is always `None`.
pub(crate) fn set_recv_timestamp(_sock: &UdpSocket) -> std::io::Result<()> {
  Ok(())
}

/// No-op on Windows: inbound TTL receipt is out of scope here, so
/// `RecvMeta::hop_limit` is always `None`. Nothing depends on it — RFC 6762
/// §11's receive test is about the destination address — and this path still
/// recovers the destination and the PKTINFO interface index, which are what the
/// boundary actually reads.
pub(crate) fn set_recv_ttl_v4(_sock: &UdpSocket) -> std::io::Result<()> {
  Ok(())
}

/// No-op on Windows: inbound Hop-Limit receipt is out of scope here.
pub(crate) fn set_recv_hoplimit_v6(_sock: &UdpSocket) -> std::io::Result<()> {
  Ok(())
}

/// `setsockopt(level, optname, 1)` for a BOOL-valued option.
fn set_bool_sockopt(sock: &UdpSocket, level: i32, optname: i32) -> std::io::Result<()> {
  use std::os::windows::io::AsRawSocket;
  let s = sock.as_raw_socket() as SOCKET;
  let one: i32 = 1;
  // SAFETY: `s` is a live socket (borrowed for the call). `optval` points to a
  // 4-byte `i32` living for the duration of the call, and `optlen` matches its
  // size. setsockopt only reads `optlen` bytes from `optval`.
  #[allow(unsafe_code)]
  let rc = unsafe {
    setsockopt(
      s,
      level,
      optname,
      core::ptr::addr_of!(one).cast::<u8>(),
      core::mem::size_of::<i32>() as i32,
    )
  };
  if rc == SOCKET_ERROR {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

/// The `WSARecvMsg` extension function pointer. windows-sys does not export the
/// `LPFN_WSARECVMSG` alias, so we declare the ABI here. The trailing overlapped
/// / completion-routine parameters are nullable pointers (we always pass null
/// for a synchronous receive), modelled as raw pointers.
type WsaRecvMsgFn = unsafe extern "system" fn(
  s: SOCKET,
  lpmsg: *mut WSAMSG,
  lpdwnumberofbytesrecvd: *mut u32,
  lpoverlapped: *mut core::ffi::c_void,
  lpcompletionroutine: *mut core::ffi::c_void,
) -> i32;

/// `WSARecvMsg`, resolved for ONE socket and **borrowing** that socket.
///
/// # Why a borrow, and not a number
///
/// This has now been wrong twice, one level apart, and the lifetime is what ends
/// both.
///
/// It began as a process-wide `OnceLock`: resolved for whichever socket asked
/// first and handed to every later caller. Winsock extension pointers are
/// provider-specific and are invoked directly, without Ws2_32 routing, so a
/// pointer obtained through one provider's socket is not valid for another's —
/// the cache was keyed by nothing and could certify a socket it had never
/// examined.
///
/// The first fix captured the socket, which fixed **identity** and said nothing
/// about **liveness**. It stored a bare numeric `SOCKET` and derived `Copy`
/// behind a safe constructor, so safe code could resolve socket A, copy the
/// token, close A, and invoke the pointer once Windows had reused that number
/// for socket B — the same cross-provider mismatch through a different door, and
/// unsound rather than merely unwise. A `SOCKET` is a number that names a socket
/// until it doesn't.
///
/// So the token borrows. [`BorrowedSocket<'a>`](std::os::windows::io::BorrowedSocket)
/// is the standard "this socket is open for `'a`" witness, and holding one makes
/// use-after-close a **compile error** rather than a documented rule. That is
/// the whole design: the unsound use is unrepresentable, so there is no `unsafe`
/// contract for a caller to read, believe, and get wrong.
///
/// Neither `Copy` nor `Clone`. The lifetime alone would make copying sound, but
/// every use here is through `&self`, so nothing needs it — and a token that
/// cannot be duplicated is one fewer way to end up holding it somewhere its
/// socket does not reach.
///
/// # Why it is not an owning receiver
///
/// The natural stronger shape — a type that owns the socket and receives through
/// itself — is not available to this crate: its consumers hold
/// `mio::net::UdpSocket` and `agnostic_net`'s socket, not `std::net::UdpSocket`,
/// and they need those for sending and readiness registration. Borrowing is the
/// strongest shape that fits.
pub struct RecvMsgFn<'a> {
  func: WsaRecvMsgFn,
  socket: BorrowedSocket<'a>,
}

impl core::fmt::Debug for RecvMsgFn<'_> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    // The pointer is not printed: it is an address inside a provider DLL and
    // says nothing a reader can act on. The socket it belongs to does.
    f.debug_struct("RecvMsgFn")
      .field("socket", &self.socket.as_raw_socket())
      .finish_non_exhaustive()
  }
}

/// Resolve `WSARecvMsg` **for this socket**, with a real `WSAIoctl` every time.
///
/// Both the capability check and the thing the receives use: call it once per
/// socket at bind and keep the result for that socket's receives, or call it per
/// receive where a borrow cannot be stored. A provider that cannot supply the
/// extension fails here rather than failing every receive afterwards — and
/// because the resolution would otherwise sit between peeking a datagram and
/// consuming one, "afterwards" means the datagram stays queued while every retry
/// rediscovers the same gap, forever.
///
/// `WSAEOPNOTSUPP` is what comes back in that case, and it is worse than it
/// looks from Rust: `std::io::Error::kind()` maps it to `Uncategorized`, which no
/// `ErrorKind` match can name, so a classifier written over kinds alone reads a
/// permanent capability gap as a transient hiccup.
///
/// Deliberately not cached anywhere — see [`RecvMsgFn`] for what caching cost,
/// twice.
pub fn resolve_recv_with_meta(socket: BorrowedSocket<'_>) -> std::io::Result<RecvMsgFn<'_>> {
  let s = socket.as_raw_socket() as SOCKET;
  let guid = WSAID_WSARECVMSG;
  let mut func: Option<WsaRecvMsgFn> = None;
  let mut returned: u32 = 0;
  // SAFETY: `socket` is a live socket for `'a` (that is what `BorrowedSocket`
  // witnesses). The in-buffer is the GUID (sized exactly); the out-buffer is
  // `func` (sized exactly). WSAIoctl writes at most
  // `size_of::<LPFN_WSARECVMSG>()` bytes into `func` and the byte count into
  // `returned`. A null overlapped/completion routine performs a blocking ioctl.
  #[allow(unsafe_code)]
  let rc = unsafe {
    WSAIoctl(
      s,
      SIO_GET_EXTENSION_FUNCTION_POINTER,
      core::ptr::addr_of!(guid).cast(),
      core::mem::size_of_val(&guid) as u32,
      core::ptr::addr_of_mut!(func).cast(),
      core::mem::size_of::<Option<WsaRecvMsgFn>>() as u32,
      core::ptr::addr_of_mut!(returned),
      core::ptr::null_mut(),
      None,
    )
  };
  if rc == SOCKET_ERROR {
    return Err(std::io::Error::last_os_error());
  }
  let func = func.ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "WSARecvMsg extension unavailable",
    )
  })?;
  Ok(RecvMsgFn { func, socket })
}

/// Receive one datagram together with its `IP_PKTINFO` / `IPV6_PKTINFO`
/// ancillary data via `WSARecvMsg`, returning the peer, byte count, local
/// destination address, and **receiving interface index**.
///
/// The caller must have signalled readiness (e.g. via `peek_from`) and own the
/// socket. A `WSAEWOULDBLOCK` surfaces as [`std::io::ErrorKind::WouldBlock`].
/// Missing/truncated PKTINFO degrades to an UNSPECIFIED local address and a
/// `0` interface index (never an error) so the datagram is not lost.
impl RecvMsgFn<'_> {
  /// Receive one datagram on the socket this token borrows, together with its
  /// `IP_PKTINFO` / `IPV6_PKTINFO` ancillary data.
  ///
  /// Takes no socket argument, deliberately: the pointer that was verified and
  /// the socket it is invoked on cannot disagree, because there is nothing to
  /// pass. See [`RecvMsgFn`] for the two revisions that reached that shape.
  ///
  /// The caller must have signalled readiness (e.g. via `peek_from`).
  /// `WSAEWOULDBLOCK` surfaces as [`std::io::ErrorKind::WouldBlock`]; missing or
  /// truncated `PKTINFO` degrades to an UNSPECIFIED local address and a `0`
  /// interface index rather than an error, so the datagram is not lost.
  pub fn recv(&self, buf: &mut [u8], is_v4: bool) -> std::io::Result<RecvMeta> {
    recv_with_meta_on(self, buf, is_v4)
  }
}

fn recv_with_meta_on(f: &RecvMsgFn<'_>, buf: &mut [u8], is_v4: bool) -> std::io::Result<RecvMeta> {
  let recvmsg = f.func;
  let s = f.socket.as_raw_socket() as SOCKET;

  let mut name: SOCKADDR_STORAGE = zeroed_sockaddr_storage();
  let mut wsabuf = WSABUF {
    len: u32::try_from(buf.len()).unwrap_or(u32::MAX),
    buf: buf.as_mut_ptr(),
  };
  // Control buffer for one PKTINFO cmsg. Sized like the Unix twin's `CmsgBuf`
  // and for the same reason: `MSG_CTRUNC` now REFUSES the datagram, so our own
  // sizing must not be able to provoke it.
  let mut control = [0u8; 512];
  let mut msg = WSAMSG {
    name: core::ptr::addr_of_mut!(name).cast::<SOCKADDR>(),
    namelen: core::mem::size_of::<SOCKADDR_STORAGE>() as i32,
    lpBuffers: core::ptr::addr_of_mut!(wsabuf),
    dwBufferCount: 1,
    Control: WSABUF {
      len: control.len() as u32,
      buf: control.as_mut_ptr(),
    },
    dwFlags: 0,
  };
  let mut received: u32 = 0;

  // SAFETY: `s` is a live socket (caller contract). `msg` points to live stack
  // buffers (`name`, `wsabuf`/`buf`, `control`) that outlive the call.
  // WSARecvMsg writes at most the lengths we supplied and updates
  // `received`, `msg.Control.len`, and `msg.dwFlags` in place. The
  // overlapped/completion pointers are null (synchronous receive).
  #[allow(unsafe_code)]
  let rc = unsafe {
    recvmsg(
      s,
      core::ptr::addr_of_mut!(msg),
      core::ptr::addr_of_mut!(received),
      core::ptr::null_mut(),
      core::ptr::null_mut(),
    )
  };
  if rc == SOCKET_ERROR {
    // Surfaces WouldBlock automatically when the socket is non-blocking.
    return Err(std::io::Error::last_os_error());
  }
  let n = core::cmp::min(received as usize, buf.len());

  let peer = sockaddr_storage_to_socketaddr(&name).ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "WSARecvMsg returned an unrecognized peer address family",
    )
  })?;

  let unspecified = if is_v4 {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
  } else {
    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
  };

  // MSG_CTRUNC means our control buffer was too small to hold all ancillary
  // data. The datagram is preserved — WSARecvMsg already consumed it — but the
  // witnesses are reported as LOST rather than absent, and the trust boundary
  // refuses on them: the kernel HAD the facts and this side could not take
  // them. On Windows this flag is 0x200 — use the platform constant.
  //
  // `WSARecvMsg` is enabled unconditionally on this path (`wsarecvmsg_fn`
  // returns an error rather than degrading), so Windows always WITNESSES both
  // facts and never declares itself blind — which is exactly what
  // `reports_rx_interface_v4`/`_v6` already report for this target.
  if msg.dwFlags & MSG_CTRUNC != 0 {
    return Ok(RecvMeta::new(
      n,
      peer,
      unspecified,
      DestinationWitness::from_reporting_path(None, true),
      IfaceWitness::from_reporting_path(0, true),
      None,
    ));
  }

  let ctrl_len = core::cmp::min(msg.Control.len as usize, control.len());
  let ctrl = control.get(..ctrl_len).unwrap_or(&control);
  let parsed = parse_pktinfo(ctrl, is_v4);
  let (local_ip, iface) = parsed.unwrap_or((unspecified, 0));
  // Windows' IN_PKTINFO carries `ipi_addr`, the IP header destination — there
  // is no `ipi_spec_dst` twin as on Unix IPv4 — so `local_ip` already IS the
  // destination and the two accessors agree here. It is `Witnessed` only when
  // the cmsg actually parsed: the UNSPECIFIED degradation is an absence of
  // evidence, not a destination of `0.0.0.0`.
  //
  // With `MSG_CTRUNC` clear an absent cmsg is the kernel emitting none of its
  // own accord, which DEGRADES rather than refusing — see `DestinationWitness::Declined`.
  Ok(RecvMeta::new(
    n,
    peer,
    local_ip,
    DestinationWitness::from_reporting_path(parsed.map(|(dst, _)| dst), false),
    IfaceWitness::from_reporting_path(iface, false),
    None,
  ))
}

/// Walk a `WSARecvMsg` control buffer for the IP_PKTINFO (v4) / IPV6_PKTINFO
/// (v6) cmsg and return `(local_ip, interface_index)`.
///
/// Reads are bounds-checked slice accesses (no unsafe). `WSACMSGHDR` is
/// `{ cmsg_len: usize, cmsg_level: i32, cmsg_type: i32 }`; cmsgs are aligned to
/// `size_of::<usize>()`, and data follows the (aligned) header.
fn parse_pktinfo(ctrl: &[u8], is_v4: bool) -> Option<(IpAddr, u32)> {
  const ALIGN: usize = core::mem::size_of::<usize>();
  const HDR: usize = ALIGN + 4 + 4; // cmsg_len(usize) + level(i32) + type(i32)
  let hdr_aligned = align_up(HDR, ALIGN);

  let (want_level, want_type) = if is_v4 {
    (IPPROTO_IP, IP_PKTINFO)
  } else {
    (IPPROTO_IPV6, IPV6_PKTINFO)
  };

  let mut off = 0usize;
  while off.saturating_add(HDR) <= ctrl.len() {
    let cmsg_len = usize_from_ne(ctrl.get(off..off.saturating_add(ALIGN))?);
    let level = i32_from_ne(ctrl.get(off.saturating_add(ALIGN)..off.saturating_add(ALIGN + 4))?);
    let ty = i32_from_ne(ctrl.get(off.saturating_add(ALIGN + 4)..off.saturating_add(ALIGN + 8))?);
    if cmsg_len < hdr_aligned {
      break; // malformed: a cmsg cannot be shorter than its header
    }
    let data_start = off.saturating_add(hdr_aligned);
    let data_end = off.saturating_add(cmsg_len);
    if let Some(data) = ctrl.get(data_start..core::cmp::min(data_end, ctrl.len()))
      && level == want_level
      && ty == want_type
    {
      if is_v4 {
        // IN_PKTINFO { IN_ADDR ipi_addr; u32 ipi_ifindex; }
        let addr = data.get(0..4)?;
        let ifindex = u32_from_ne(data.get(4..8)?);
        let mut octets = [0u8; 4];
        octets.copy_from_slice(addr);
        return Some((IpAddr::V4(Ipv4Addr::from(octets)), ifindex));
      }
      // IN6_PKTINFO { IN6_ADDR ipi6_addr; u32 ipi6_ifindex; }
      let addr = data.get(0..16)?;
      let ifindex = u32_from_ne(data.get(16..20)?);
      let mut octets = [0u8; 16];
      octets.copy_from_slice(addr);
      return Some((IpAddr::V6(Ipv6Addr::from(octets)), ifindex));
    }
    // Advance to the next aligned cmsg; stop if it would not progress.
    let next = off.saturating_add(align_up(cmsg_len, ALIGN));
    if next <= off {
      break;
    }
    off = next;
  }
  None
}

fn align_up(v: usize, align: usize) -> usize {
  v.saturating_add(align.saturating_sub(1)) & !(align.saturating_sub(1))
}

fn usize_from_ne(b: &[u8]) -> usize {
  let mut a = [0u8; core::mem::size_of::<usize>()];
  let take = core::cmp::min(b.len(), a.len());
  if let (Some(dst), Some(src)) = (a.get_mut(..take), b.get(..take)) {
    dst.copy_from_slice(src);
  }
  usize::from_ne_bytes(a)
}

fn i32_from_ne(b: &[u8]) -> i32 {
  let mut a = [0u8; 4];
  if let (Some(dst), Some(src)) = (a.get_mut(..), b.get(..4)) {
    dst.copy_from_slice(src);
  }
  i32::from_ne_bytes(a)
}

fn u32_from_ne(b: &[u8]) -> u32 {
  let mut a = [0u8; 4];
  if let (Some(dst), Some(src)) = (a.get_mut(..), b.get(..4)) {
    dst.copy_from_slice(src);
  }
  u32::from_ne_bytes(a)
}

fn zeroed_sockaddr_storage() -> SOCKADDR_STORAGE {
  // SAFETY: `SOCKADDR_STORAGE` is a plain-old-data struct whose all-zero bit
  // pattern is a valid (empty) value; WSARecvMsg overwrites the meaningful
  // bytes before we read them.
  #[allow(unsafe_code)]
  unsafe {
    core::mem::zeroed()
  }
}

/// Parse a filled `SOCKADDR_STORAGE` into a `SocketAddr`. Reads the family and
/// the family-specific fields via a byte view (network-order port/address).
fn sockaddr_storage_to_socketaddr(storage: &SOCKADDR_STORAGE) -> Option<SocketAddr> {
  // SAFETY: reinterpreting the POD storage as bytes for read-only,
  // bounds-checked field extraction. The slice borrows `storage` and does not
  // outlive it.
  #[allow(unsafe_code)]
  let bytes = unsafe {
    core::slice::from_raw_parts(
      core::ptr::addr_of!(*storage).cast::<u8>(),
      core::mem::size_of::<SOCKADDR_STORAGE>(),
    )
  };
  let family = u16::from_ne_bytes([*bytes.first()?, *bytes.get(1)?]);
  // Port is network (big-endian) order at offset 2 in both sockaddr_in/in6.
  let port = u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]);
  if family == AF_INET {
    // sockaddr_in: sin_addr at offset 4 (4 bytes, network order).
    let a = bytes.get(4..8)?;
    let mut octets = [0u8; 4];
    octets.copy_from_slice(a);
    Some(SocketAddr::V4(SocketAddrV4::new(
      Ipv4Addr::from(octets),
      port,
    )))
  } else if family == AF_INET6 {
    // sockaddr_in6: flowinfo at 4..8, sin6_addr at 8..24, scope_id at 24..28.
    let flowinfo = u32_from_ne(bytes.get(4..8)?);
    let a = bytes.get(8..24)?;
    let mut octets = [0u8; 16];
    octets.copy_from_slice(a);
    let scope_id = u32_from_ne(bytes.get(24..28)?);
    Some(SocketAddr::V6(SocketAddrV6::new(
      Ipv6Addr::from(octets),
      port,
      flowinfo,
      scope_id,
    )))
  } else {
    None
  }
}

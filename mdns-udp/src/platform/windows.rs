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
  os::windows::io::RawSocket,
  sync::OnceLock,
};

use socket2::Socket;
use windows_sys::Win32::Networking::WinSock::{
  AF_INET, AF_INET6, IP_PKTINFO, IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO, MSG_CTRUNC,
  SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKADDR, SOCKADDR_STORAGE, SOCKET, SOCKET_ERROR, WSABUF,
  WSAID_WSARECVMSG, WSAIoctl, WSAMSG, setsockopt,
};

use crate::multicast::RecvMeta;

fn as_socket(s: &UdpSocket) -> std::io::Result<Socket> {
  Ok(Socket::from(s.try_clone()?))
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
/// `RecvMeta::hop_limit` is always `None`. The §11 on-link check then relies on
/// the source-address fallback, now correctly scoped to the bound interface via
/// the PKTINFO interface index that `recv_with_meta` recovers.
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

/// Process-wide cache of the `WSARecvMsg` extension function pointer, stored as
/// a `usize`. The pointer is obtained once via `WSAIoctl`
/// (`SIO_GET_EXTENSION_FUNCTION_POINTER`) and is stable for the lifetime of the
/// Winsock provider.
static WSARECVMSG_PTR: OnceLock<usize> = OnceLock::new();

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

/// Resolve the `WSARecvMsg` extension function pointer for `s` (cached).
fn wsarecvmsg_fn(s: SOCKET) -> std::io::Result<WsaRecvMsgFn> {
  if let Some(&p) = WSARECVMSG_PTR.get() {
    // SAFETY: `p` was produced from a valid `WSARecvMsg` pointer below; the
    // transmute restores the same function-pointer type.
    #[allow(unsafe_code)]
    return Ok(unsafe { core::mem::transmute::<usize, WsaRecvMsgFn>(p) });
  }
  let guid = WSAID_WSARECVMSG;
  let mut func: Option<WsaRecvMsgFn> = None;
  let mut returned: u32 = 0;
  // SAFETY: `s` is a live socket. The in-buffer is the GUID (sized exactly);
  // the out-buffer is `func` (sized exactly). WSAIoctl writes at most
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
  let p = func as usize;
  let _ = WSARECVMSG_PTR.set(p);
  Ok(func)
}

/// Receive one datagram together with its `IP_PKTINFO` / `IPV6_PKTINFO`
/// ancillary data via `WSARecvMsg`, returning the peer, byte count, local
/// destination address, and **receiving interface index**.
///
/// The caller must have signalled readiness (e.g. via `peek_from`) and own the
/// socket. A `WSAEWOULDBLOCK` surfaces as [`std::io::ErrorKind::WouldBlock`].
/// Missing/truncated PKTINFO degrades to an UNSPECIFIED local address and a
/// `0` interface index (never an error) so the datagram is not lost.
pub fn recv_with_meta(socket: RawSocket, buf: &mut [u8], is_v4: bool) -> std::io::Result<RecvMeta> {
  let s = socket as SOCKET;
  let recvmsg = wsarecvmsg_fn(s)?;

  let mut name: SOCKADDR_STORAGE = zeroed_sockaddr_storage();
  let mut wsabuf = WSABUF {
    len: u32::try_from(buf.len()).unwrap_or(u32::MAX),
    buf: buf.as_mut_ptr(),
  };
  // Control buffer for one PKTINFO cmsg (256 bytes is plenty).
  let mut control = [0u8; 256];
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
  // data; treat as "no pktinfo" and fall back (the datagram is already
  // consumed). On Windows this flag is 0x200 — use the platform constant.
  if msg.dwFlags & MSG_CTRUNC != 0 {
    return Ok(RecvMeta::new(n, peer, unspecified, 0, None));
  }

  let ctrl_len = core::cmp::min(msg.Control.len as usize, control.len());
  let ctrl = control.get(..ctrl_len).unwrap_or(&control);
  let (local_ip, iface) = parse_pktinfo(ctrl, is_v4).unwrap_or((unspecified, 0));
  Ok(RecvMeta::new(n, peer, local_ip, iface, None))
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
    if let Some(data) = ctrl.get(data_start..core::cmp::min(data_end, ctrl.len())) {
      if level == want_level && ty == want_type {
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

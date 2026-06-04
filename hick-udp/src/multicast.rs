//! Multicast socket configuration helpers + RecvMeta + cmsg parsing (stubbed).

use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
  time::SystemTime,
};

use socket2::{Domain, Protocol, Socket, Type};

use crate::{
  constants::{MDNS_IPV4_GROUP, MDNS_IPV6_GROUP, MDNS_PORT},
  error::{BindError, JoinError},
};
// ParseRecvMetaError is produced only by the Unix cmsg parsers; on Windows the
// receive path returns Options, so gate the import to avoid an unused warning.
#[cfg(unix)]
use crate::error::ParseRecvMetaError;
use crate::platform;

/// Look up the first IPv4 address assigned to the interface with the given
/// OS index. Returns `None` if the interface cannot be found or carries no
/// IPv4 address (e.g. IPv6-only or the lookup failed).
///
/// Used by `try_bind_v4` to set `IP_MULTICAST_IF` to a single address; for
/// the multicast-join path that needs every IPv4 address of the interface,
/// see `try_join_v4`.
fn ipv4_addr_for_index(idx: u32) -> Option<Ipv4Addr> {
  let iface = getifs::interface_by_index(idx).ok().flatten()?;
  let v4s = iface.ipv4_addrs().ok()?;
  v4s.first().map(|a| a.addr())
}

/// Options for binding an IPv4 mDNS multicast socket.
#[derive(Debug, Clone)]
pub struct MulticastOptionsV4 {
  interface_index: u32,
  multicast_loop: bool,
  ttl: u8,
}
impl MulticastOptionsV4 {
  /// Build options targeting the interface with the given index.
  pub const fn new(interface_index: u32) -> Self {
    Self {
      interface_index,
      multicast_loop: true,
      ttl: 255,
    }
  }
  /// The interface index.
  #[inline(always)]
  pub const fn interface_index(&self) -> u32 {
    self.interface_index
  }
  /// Whether to receive our own multicast sends.
  #[inline(always)]
  pub const fn multicast_loop(&self) -> bool {
    self.multicast_loop
  }
  /// Multicast TTL.
  #[inline(always)]
  pub const fn ttl(&self) -> u8 {
    self.ttl
  }
  /// Override the multicast-loop flag.
  #[must_use]
  pub const fn with_multicast_loop(mut self, on: bool) -> Self {
    self.multicast_loop = on;
    self
  }
  /// Override the multicast TTL.
  #[must_use]
  pub const fn with_ttl(mut self, ttl: u8) -> Self {
    self.ttl = ttl;
    self
  }
}

/// Options for binding an IPv6 mDNS multicast socket.
#[derive(Debug, Clone)]
pub struct MulticastOptionsV6 {
  interface_index: u32,
  multicast_loop: bool,
  hops: u8,
}
impl MulticastOptionsV6 {
  /// Build options targeting the interface with the given index.
  pub const fn new(interface_index: u32) -> Self {
    Self {
      interface_index,
      multicast_loop: true,
      hops: 255,
    }
  }
  /// The interface index.
  #[inline(always)]
  pub const fn interface_index(&self) -> u32 {
    self.interface_index
  }
  /// Whether to receive our own multicast sends.
  #[inline(always)]
  pub const fn multicast_loop(&self) -> bool {
    self.multicast_loop
  }
  /// IPv6 hop limit for multicast.
  #[inline(always)]
  pub const fn hops(&self) -> u8 {
    self.hops
  }
  /// Override the multicast-loop flag.
  #[must_use]
  pub const fn with_multicast_loop(mut self, on: bool) -> Self {
    self.multicast_loop = on;
    self
  }
  /// Override the multicast hop limit.
  #[must_use]
  pub const fn with_hops(mut self, hops: u8) -> Self {
    self.hops = hops;
    self
  }
}

/// Metadata about a received datagram.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
  len: usize,
  peer: SocketAddr,
  local_ip: IpAddr,
  interface_index: u32,
  rx_time: Option<SystemTime>,
  hop_limit: Option<u8>,
}
impl RecvMeta {
  pub(crate) const fn new(
    len: usize,
    peer: SocketAddr,
    local_ip: IpAddr,
    iface: u32,
    rx_time: Option<SystemTime>,
  ) -> Self {
    Self {
      len,
      peer,
      local_ip,
      interface_index: iface,
      rx_time,
      hop_limit: None,
    }
  }
  /// Datagram length in bytes.
  #[inline(always)]
  pub const fn len(&self) -> usize {
    self.len
  }
  /// Whether the datagram was empty (defensive).
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }
  /// Peer socket address.
  #[inline(always)]
  pub const fn peer(&self) -> SocketAddr {
    self.peer
  }
  /// Local IP the datagram was received on.
  #[inline(always)]
  pub const fn local_ip(&self) -> IpAddr {
    self.local_ip
  }
  /// Interface index.
  #[inline(always)]
  pub const fn interface_index(&self) -> u32 {
    self.interface_index
  }
  /// Kernel receive timestamp for the datagram, if the OS delivered one via
  /// the `SCM_TIMESTAMPNS`/`SCM_TIMESTAMP` ancillary cmsg. `None` when the
  /// platform did not provide a timestamp (sockopt unavailable, cmsg absent or
  /// truncated, or a non-Unix target).
  #[inline(always)]
  pub const fn rx_time(&self) -> Option<SystemTime> {
    self.rx_time
  }
  /// Overwrite the kernel receive timestamp. Used by `recv_with_meta` to thread
  /// the timestamp parsed from the control buffer onto a meta produced by the
  /// PKTINFO parsers (which have no access to the timestamp cmsg).
  #[cfg(unix)]
  #[inline(always)]
  pub(crate) fn set_rx_time(&mut self, rx_time: Option<SystemTime>) {
    self.rx_time = rx_time;
  }

  /// IPv4 TTL / IPv6 Hop Limit of the received datagram, if the OS delivered
  /// it via the `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` ancillary cmsg. `None` when
  /// the platform did not provide it (sockopt unavailable, cmsg absent or
  /// truncated, or a non-Unix target).
  ///
  /// RFC 6762 §11: a Multicast DNS receiver should ignore packets whose
  /// TTL/Hop Limit is not 255, since a value below 255 proves the packet
  /// crossed a router and did not originate on the local link. The driver
  /// enforces this when the value is present.
  #[inline(always)]
  pub const fn hop_limit(&self) -> Option<u8> {
    self.hop_limit
  }

  /// Overwrite the TTL/Hop-Limit, threaded in by `recv_with_meta` from the
  /// `IP_TTL` / `IPV6_HOPLIMIT` cmsg.
  #[cfg(unix)]
  #[inline(always)]
  pub(crate) fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
    self.hop_limit = hop_limit;
  }
}

/// Bind an IPv4 mDNS multicast UDP socket with reuse options set BEFORE bind.
///
/// On Unix, `SO_REUSEADDR` and `SO_REUSEPORT` MUST be set before `bind` for
/// port-sharing to work when another mDNS responder already owns port 5353.
///
/// When `opts.interface_index()` is non-zero the socket's outbound multicast
/// interface is set via `IP_MULTICAST_IF` so that sends leave on the caller's
/// chosen interface rather than the OS default.
pub fn try_bind_v4(opts: MulticastOptionsV4) -> Result<UdpSocket, BindError> {
  try_bind_v4_inner(opts).inspect_err(|_e| {
    hick_trace::warn!(error = %_e, "try_bind_v4 failed");
  })
}

fn try_bind_v4_inner(opts: MulticastOptionsV4) -> Result<UdpSocket, BindError> {
  let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
  sock.set_reuse_address(true)?;
  #[cfg(unix)]
  sock.set_reuse_port(true)?;
  let addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into();
  sock.bind(&addr.into())?;

  // Set IP_MULTICAST_IF so outbound multicast uses the requested interface.
  let iface_index = opts.interface_index();
  if iface_index != 0 {
    let ip = match ipv4_addr_for_index(iface_index) {
      Some(ip) => ip,
      None => {
        return Err(BindError::InterfaceNotFound(
          crate::error::InterfaceNotFoundDetail::new(iface_index),
        ));
      }
    };
    sock.set_multicast_if_v4(&ip)?;
  }

  // unicast sends (legacy §6.7 responses) must ALSO egress with IP
  // TTL 255 per RFC 6762 §11 — the multicast TTL option does not affect them.
  // Without this a §11-enforcing receiver would drop our legacy replies.
  sock.set_ttl_v4(255)?;

  let std_sock: UdpSocket = sock.into();
  platform::set_multicast_loop_v4(&std_sock, opts.multicast_loop())?;
  platform::set_multicast_ttl_v4(&std_sock, opts.ttl())?;
  // Best-effort: enabling IP_PKTINFO must not fail the bind on platforms that
  // lack it. A missing PKTINFO just means the driver falls back to its
  // degraded self-loopback matching.
  let _ = platform::set_recv_pktinfo_v4(&std_sock);
  // Best-effort: enabling kernel receive timestamps must not fail the bind on
  // platforms that lack the sockopt. A missing timestamp just leaves
  // RecvMeta::rx_time as None.
  let _ = platform::set_recv_timestamp(&std_sock);
  // Best-effort: enabling IP_RECVTTL lets the driver enforce the RFC 6762 §11
  // on-link check. A missing value leaves RecvMeta::hop_limit as None.
  let _ = platform::set_recv_ttl_v4(&std_sock);
  Ok(std_sock)
}

/// Bind an IPv6 mDNS multicast UDP socket with reuse options set BEFORE bind.
///
/// On Unix, `SO_REUSEADDR` and `SO_REUSEPORT` MUST be set before `bind` for
/// port-sharing to work when another mDNS responder already owns port 5353.
///
/// When `opts.interface_index()` is non-zero the socket's outbound multicast
/// interface is set via `IPV6_MULTICAST_IF` so that sends leave on the caller's
/// chosen interface rather than the OS default.
pub fn try_bind_v6(opts: MulticastOptionsV6) -> Result<UdpSocket, BindError> {
  try_bind_v6_inner(opts).inspect_err(|_e| {
    hick_trace::warn!(error = %_e, "try_bind_v6 failed");
  })
}

fn try_bind_v6_inner(opts: MulticastOptionsV6) -> Result<UdpSocket, BindError> {
  let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
  // make this an IPv6-ONLY socket BEFORE bind. On dual-stack-default
  // systems (e.g. Linux `bindv6only=0`) a `[::]:5353` socket would otherwise
  // also accept IPv4 (as v4-mapped), colliding with the separate IPv4 socket
  // bound to `0.0.0.0:5353` (bind conflict / duplicate delivery). IPV6_V6ONLY
  // confines this socket to IPv6 so the two families stay on their own paths.
  sock.set_only_v6(true)?;
  sock.set_reuse_address(true)?;
  #[cfg(unix)]
  sock.set_reuse_port(true)?;
  let addr: SocketAddr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0).into();
  sock.bind(&addr.into())?;

  // Set IPV6_MULTICAST_IF so outbound multicast uses the requested interface.
  let iface_index = opts.interface_index();
  if iface_index != 0 {
    sock.set_multicast_if_v6(iface_index)?;
  }

  // unicast sends (legacy §6.7 responses) must ALSO egress with
  // Hop Limit 255 per RFC 6762 §11 — the multicast-hops option does not affect
  // them. Without this a §11-enforcing receiver would drop our legacy replies.
  sock.set_unicast_hops_v6(255)?;

  let std_sock: UdpSocket = sock.into();
  // honor with_multicast_loop(false) for IPv6 too (the IPv4 path
  // applies the analogous IP_MULTICAST_LOOP). Without this the option was
  // silently ignored and self-loopback could not be disabled on v6.
  platform::set_multicast_loop_v6(&std_sock, opts.multicast_loop())?;
  platform::set_multicast_hops_v6(&std_sock, opts.hops())?;
  // Best-effort: enabling IPV6_PKTINFO must not fail the bind on platforms that
  // lack it. A missing PKTINFO just means the driver falls back to its
  // hash-ring self-detection.
  let _ = platform::set_recv_pktinfo_v6(&std_sock);
  // Best-effort: enabling kernel receive timestamps must not fail the bind on
  // platforms that lack the sockopt. A missing timestamp just leaves
  // RecvMeta::rx_time as None.
  let _ = platform::set_recv_timestamp(&std_sock);
  // Best-effort: enabling IPV6_RECVHOPLIMIT lets the driver enforce the RFC
  // 6762 §11 on-link check. A missing value leaves RecvMeta::hop_limit as None.
  let _ = platform::set_recv_hoplimit_v6(&std_sock);
  Ok(std_sock)
}

/// Join the IPv4 mDNS multicast group on a specific interface.
///
/// Looks up the interface's IPv4 addresses via `getifs::interface_by_index`
/// and joins the multicast group on every one of them.  Returns
/// `JoinError::InterfaceNotFound` if the index does not resolve to an
/// interface or the interface carries no IPv4 addresses.
pub fn try_join_v4(sock: &UdpSocket, interface_index: u32) -> Result<(), JoinError> {
  try_join_v4_inner(sock, interface_index).inspect_err(|_e| {
    hick_trace::warn!(error = %_e, interface_index, "try_join_v4 failed");
  })
}

fn try_join_v4_inner(sock: &UdpSocket, interface_index: u32) -> Result<(), JoinError> {
  let iface = match getifs::interface_by_index(interface_index) {
    Ok(Some(i)) => i,
    _ => {
      return Err(JoinError::InterfaceNotFound(
        crate::error::InterfaceNotFoundDetail::new(interface_index),
      ));
    }
  };
  let v4_addrs = iface.ipv4_addrs().map_err(JoinError::Io)?;
  if v4_addrs.is_empty() {
    return Err(JoinError::InterfaceNotFound(
      crate::error::InterfaceNotFoundDetail::new(interface_index),
    ));
  }
  for ifv4 in v4_addrs.iter() {
    sock.join_multicast_v4(&MDNS_IPV4_GROUP, &ifv4.addr())?;
  }
  Ok(())
}

/// Join the IPv6 mDNS multicast group on a specific interface.
pub fn try_join_v6(sock: &UdpSocket, interface_index: u32) -> Result<(), JoinError> {
  try_join_v6_inner(sock, interface_index).inspect_err(|_e| {
    hick_trace::warn!(error = %_e, interface_index, "try_join_v6 failed");
  })
}

fn try_join_v6_inner(sock: &UdpSocket, interface_index: u32) -> Result<(), JoinError> {
  sock.join_multicast_v6(&MDNS_IPV6_GROUP, interface_index)?;
  Ok(())
}

/// Parse IP_PKTINFO cmsg ancillary data (Unix) to recover the local IP + interface
/// index for an incoming IPv4 datagram.
///
/// only compiled on targets that define `libc::IP_PKTINFO`. FreeBSD,
/// OpenBSD and DragonFly use `IP_RECVDSTADDR`/`IP_RECVIF` instead and are not
/// supported by this parser (the driver degrades to UNSPECIFIED local there).
#[cfg(has_ip_pktinfo)]
pub fn parse_pktinfo_v4(
  cmsgs: &[u8],
  len: usize,
  peer: SocketAddr,
) -> Result<RecvMeta, ParseRecvMetaError> {
  use crate::error::BufferTooShortDetail;
  use std::net::{IpAddr, Ipv4Addr};

  // Walk the cmsg buffer looking for an IP_PKTINFO message.
  for cmsg in CmsgIter::new(cmsgs) {
    let cmsg = cmsg?;
    if cmsg.level == libc::IPPROTO_IP && cmsg.ty == libc::IP_PKTINFO {
      // in_pktinfo: ipi_ifindex (i32) + ipi_spec_dst (4 bytes) + ipi_addr (4 bytes) = 12 bytes
      if cmsg.data.len() < 12 {
        return Err(ParseRecvMetaError::BufferTooShort(
          BufferTooShortDetail::new(12, cmsg.data.len()),
        ));
      }
      let idx_bytes: &[u8; 4] = cmsg.data.first_chunk::<4>().ok_or_else(|| {
        ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(4, cmsg.data.len()))
      })?;
      // ipi_ifindex is platform-endian; use from_ne_bytes for portability.
      let iface = u32::from_ne_bytes(*idx_bytes);
      // read ipi_spec_dst (bytes 4..8) — the local interface address
      // the packet was received on — NOT ipi_addr (bytes 8..12), which for
      // multicast carries the group destination (224.0.0.251) and is useless
      // for self-packet detection on multi-homed hosts.
      let addr_bytes: &[u8; 4] = cmsg
        .data
        .get(4..8)
        .and_then(|s| s.first_chunk::<4>())
        .ok_or_else(|| {
          ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(4, cmsg.data.len()))
        })?;
      let local_ip = IpAddr::V4(Ipv4Addr::from(*addr_bytes));
      // No timestamp available here; recv_with_meta overwrites rx_time after
      // parsing the SCM_TIMESTAMP* cmsg from the same control buffer.
      return Ok(RecvMeta::new(len, peer, local_ip, iface, None));
    }
  }
  Err(ParseRecvMetaError::MissingPktinfo)
}

/// Parse IPV6_PKTINFO cmsg ancillary data (Unix) to recover the local IP +
/// interface index for an incoming IPv6 datagram.
///
/// Gated on the `has_ipv6_pktinfo` capability cfg (see `build.rs`): every
/// supported Unix target defines `IPV6_PKTINFO`.
#[cfg(has_ipv6_pktinfo)]
pub fn parse_pktinfo_v6(
  cmsgs: &[u8],
  len: usize,
  peer: SocketAddr,
) -> Result<RecvMeta, ParseRecvMetaError> {
  use crate::error::BufferTooShortDetail;
  use std::net::{IpAddr, Ipv6Addr};

  for cmsg in CmsgIter::new(cmsgs) {
    let cmsg = cmsg?;
    if cmsg.level == libc::IPPROTO_IPV6 && cmsg.ty == libc::IPV6_PKTINFO {
      // in6_pktinfo: ipi6_addr (16 bytes) + ipi6_ifindex (i32) = 20 bytes
      if cmsg.data.len() < 20 {
        return Err(ParseRecvMetaError::BufferTooShort(
          BufferTooShortDetail::new(20, cmsg.data.len()),
        ));
      }
      let addr_bytes: &[u8; 16] = cmsg.data.first_chunk::<16>().ok_or_else(|| {
        ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(16, cmsg.data.len()))
      })?;
      let idx_bytes: &[u8; 4] = cmsg
        .data
        .get(16..20)
        .and_then(|s| s.first_chunk::<4>())
        .ok_or_else(|| {
          ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(4, cmsg.data.len()))
        })?;
      let local_ip = IpAddr::V6(Ipv6Addr::from(*addr_bytes));
      let iface = u32::from_ne_bytes(*idx_bytes);
      // No timestamp available here; recv_with_meta overwrites rx_time after
      // parsing the SCM_TIMESTAMP* cmsg from the same control buffer.
      return Ok(RecvMeta::new(len, peer, local_ip, iface, None));
    }
  }
  Err(ParseRecvMetaError::MissingPktinfo)
}

/// Control buffer for `recvmsg`: 256 bytes forced to 8-byte alignment via
/// `#[repr(align(8))]` so its base satisfies the kernel's `cmsghdr` alignment
/// requirement. 256 bytes is plenty for a single PKTINFO cmsg.
#[cfg(unix)]
#[repr(align(8))]
struct CmsgBuf([u8; 256]);

/// Receive one datagram from `fd` (must be non-blocking) together with its
/// PKTINFO ancillary metadata. `is_v4` selects the parser. Returns the
/// datagram bytes written into `buf` plus the recovered [`RecvMeta`].
///
/// Returns [`std::io::ErrorKind::WouldBlock`] if no datagram is ready.
/// Returns [`std::io::ErrorKind::Other`] if PKTINFO was missing (e.g. the
/// platform did not deliver it, or the control buffer was truncated), so the
/// caller can fall back to its own self-detection.
#[cfg(unix)]
pub fn recv_with_meta(
  fd: std::os::fd::RawFd,
  buf: &mut [u8],
  is_v4: bool,
) -> std::io::Result<RecvMeta> {
  // Why raw `libc::recvmsg` + manual `cmsghdr` parsing instead of rustix's
  // `recvmsg`: rustix's `RecvAncillaryMessage` only models `ScmRights` /
  // `ScmCredentials` and gives no access to the raw cmsg bytes, so the
  // IP_PKTINFO / IPV6_PKTINFO / SCM_TIMESTAMP(NS) / IP_TTL / IPV6_HOPLIMIT
  // control messages this function extracts cannot be read through it. See the
  // `crate::platform::unix` module docs for the full list of what rustix is
  // missing on the matching send/sockopt side.
  // Peer address storage, filled by recvmsg.
  let mut storage = socket2::SockAddrStorage::zeroed();
  let mut iov = libc::iovec {
    iov_base: buf.as_mut_ptr().cast(),
    iov_len: buf.len(),
  };
  // 8-aligned control buffer for one PKTINFO cmsg (256 bytes is plenty).
  let mut control = CmsgBuf([0u8; 256]);

  // Zero-initialize the msghdr, then fill the fields we own. We build it from
  // a zeroed value rather than a struct literal because msghdr has private
  // padding fields on some platforms.
  // SAFETY: `libc::msghdr` is a plain-old-data C struct whose all-zero bit
  // pattern is a valid (empty) header; we immediately overwrite every
  // meaningful field below.
  #[allow(unsafe_code)]
  let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
  // SAFETY: view the zeroed storage as the platform `sockaddr_storage` it wraps
  // to hand `recvmsg` a pointer to fill; recvmsg writes a valid sockaddr within
  // `msg_namelen` before we read it back via `SockAddr::new`.
  #[allow(unsafe_code)]
  let storage_ptr =
    unsafe { storage.view_as::<libc::sockaddr_storage>() } as *mut libc::sockaddr_storage;
  msg.msg_name = storage_ptr.cast();
  msg.msg_namelen = core::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
  msg.msg_iov = core::ptr::addr_of_mut!(iov);
  msg.msg_iovlen = 1;
  msg.msg_control = control.0.as_mut_ptr().cast();
  msg.msg_controllen = control.0.len() as _;

  // SAFETY: `fd` is a valid socket fd (caller contract). `msg` points to live,
  // correctly-sized stack buffers (`storage`, `iov`, `control`) that outlive
  // the call. recvmsg only writes within the lengths we supplied and updates
  // `msg_namelen`/`msg_controllen`/`msg_flags` in place.
  #[allow(unsafe_code)]
  let rc = unsafe { libc::recvmsg(fd, core::ptr::addr_of_mut!(msg), 0) };
  if rc < 0 {
    // Surfaces WouldBlock automatically when the socket is non-blocking.
    return Err(std::io::Error::last_os_error());
  }
  // MSG_TRUNC means the datagram was larger than our buffer — it is
  // oversized / non-conformant (RFC 6762 §17 caps mDNS at 9000 bytes, our
  // default buffer). recvmsg already consumed it, but only a truncated prefix
  // landed in `buf`; feeding that prefix to the parser could trigger side
  // effects from an incomplete message, so signal it for the caller to DROP
  // (parallels the Windows WSAEMSGSIZE path). InvalidData is the driver's
  // "unusable datagram — drop and keep serving" signal.
  if msg.msg_flags & libc::MSG_TRUNC != 0 {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "oversized datagram truncated (MSG_TRUNC)",
    ));
  }
  // Clamp the reported length to the buffer we provided (defensive against a
  // hostile/oversized return value).
  let n = core::cmp::min(rc as usize, buf.len());

  // Reconstruct the peer SocketAddr from the filled sockaddr_storage. This is
  // REQUIRED: it identifies the datagram source.
  // SAFETY: `recvmsg` filled `storage` with `msg.msg_namelen` valid bytes of a
  // sockaddr; socket2 only inspects bytes within that length.
  #[allow(unsafe_code)]
  let sockaddr = unsafe { socket2::SockAddr::new(storage, msg.msg_namelen) };
  let peer = sockaddr.as_socket().ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "recvmsg returned an unrecognized peer address family",
    )
  })?;

  // Helper: a RecvMeta carrying the real peer + length but an UNSPECIFIED
  // local address, used when PKTINFO is absent. The datagram itself was
  // already consumed by `recvmsg`, so we MUST NOT drop it just because the
  // ancillary metadata is missing — the caller falls back to its own
  // self-loopback detection (content-hash ring) when local_ip is
  // unspecified. This keeps a missing/failed PKTINFO sockopt from silently
  // black-holing all inbound traffic.
  let unspecified_meta = || {
    let local_ip = if is_v4 {
      std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
      std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    RecvMeta::new(n, peer, local_ip, 0, None)
  };

  // MSG_CTRUNC means our control buffer was too small to hold all ancillary
  // data; treat that as "no pktinfo" and fall back (data is preserved).
  if msg.msg_flags & libc::MSG_CTRUNC != 0 {
    return Ok(unspecified_meta());
  }

  // Parse the PKTINFO cmsg out of the (possibly shortened) control buffer.
  // A MissingPktinfo result degrades to an unspecified-local meta rather
  // than an error so the datagram is never lost.
  let controllen = msg.msg_controllen as usize;
  let control_slice = control.0.get(..controllen).unwrap_or(&control.0);
  let parsed = if is_v4 {
    // parse_pktinfo_v4 only exists where libc defines IP_PKTINFO
    // (`has_ip_pktinfo`); elsewhere the v4 path degrades to unspecified-local.
    #[cfg(has_ip_pktinfo)]
    {
      parse_pktinfo_v4(control_slice, n, peer)
    }
    #[cfg(not(has_ip_pktinfo))]
    {
      let _ = control_slice;
      Err(ParseRecvMetaError::MissingPktinfo)
    }
  } else {
    // parse_pktinfo_v6 only exists where libc defines IPV6_PKTINFO
    // (`has_ipv6_pktinfo`); elsewhere the v6 path degrades to unspecified-local.
    #[cfg(has_ipv6_pktinfo)]
    {
      parse_pktinfo_v6(control_slice, n, peer)
    }
    #[cfg(not(has_ipv6_pktinfo))]
    {
      let _ = control_slice;
      Err(ParseRecvMetaError::MissingPktinfo)
    }
  };
  let mut meta = parsed.unwrap_or_else(|_| unspecified_meta());
  // Walk the same control buffer for a kernel receive-timestamp cmsg and thread
  // it onto the meta. A missing/short timestamp leaves rx_time as None — never
  // an error, since the datagram has already been consumed.
  meta.set_rx_time(parse_rx_time(control_slice));
  // thread the IPv4 TTL / IPv6 Hop Limit so the driver can enforce
  // the RFC 6762 §11 on-link check (==255). Absent/short cmsg leaves it None
  // (degraded: the driver cannot enforce and passes the packet through).
  meta.set_hop_limit(parse_hop_limit(control_slice, is_v4));
  Ok(meta)
}

/// Walk an ancillary buffer for the inbound IPv4 TTL (`IP_TTL`) or IPv6 Hop
/// Limit (`IPV6_HOPLIMIT`) cmsg and return it as a `u8`.
///
/// Returns `None` when the cmsg is absent or its data is empty. The value is
/// delivered as a host-order `int` on Linux (and as a single byte on some
/// BSDs); reading the low byte of a native-endian `u32` handles both, and a
/// 1-byte payload is read directly.
#[cfg(all(unix, has_recv_hoplimit))]
fn parse_hop_limit(cmsgs: &[u8], is_v4: bool) -> Option<u8> {
  for cmsg in CmsgIter::new(cmsgs) {
    let cmsg = cmsg.ok()?;
    let matches = if is_v4 {
      cmsg.level == libc::IPPROTO_IP && (cmsg.ty == libc::IP_TTL || cmsg.ty == libc::IP_RECVTTL)
    } else {
      cmsg.level == libc::IPPROTO_IPV6 && cmsg.ty == libc::IPV6_HOPLIMIT
    };
    if matches {
      // Prefer a 4-byte host-order int (Linux/IPv6); fall back to a single
      // byte (some BSD IPv4 deliveries). `as u8` of the native-endian u32
      // yields the TTL byte on both endiannesses.
      if let Some(four) = cmsg.data.get(..4) {
        let mut b = [0u8; 4];
        b.copy_from_slice(four);
        return Some(u32::from_ne_bytes(b) as u8);
      }
      return cmsg.data.first().copied();
    }
  }
  None
}

/// Fallback for targets without the TTL/Hop-Limit cmsg wired up (OpenBSD/NetBSD):
/// always `None` (the driver then cannot enforce the §11 on-link check).
#[cfg(all(unix, not(has_recv_hoplimit)))]
fn parse_hop_limit(_cmsgs: &[u8], _is_v4: bool) -> Option<u8> {
  None
}

/// Worst-case truncation of this target's kernel receive timestamp, i.e. the
/// largest amount by which [`RecvMeta::rx_time`] may report a value EARLIER
/// than the true receive instant.
///
/// - Linux/Android deliver `SCM_TIMESTAMPNS` (a nanosecond `timespec`), so the
///   reported time is exact: the grain is [`core::time::Duration::ZERO`].
/// - Apple and the BSDs deliver `SCM_TIMESTAMP` (a microsecond `timeval`),
///   which truncates sub-microsecond precision: the grain is one microsecond.
/// - Targets with no receive-timestamp cmsg never produce an `rx_time`, so the
///   value is unused (the value here is an irrelevant default).
///
/// A consumer ordering an inbound datagram against a locally-recorded send
/// time should accept the datagram as "at-or-after" the send when its receive
/// timestamp is no more than this grain earlier, so a truncated loopback is
/// not misjudged as having arrived before the send.
#[cfg(recv_timestamp_ns)]
pub const RX_TIMESTAMP_GRAIN: core::time::Duration = core::time::Duration::ZERO;
/// See the nanosecond variant above; microsecond `timeval` sources (Apple/BSD)
/// and targets without a timestamp cmsg use a one-microsecond grain.
#[cfg(not(recv_timestamp_ns))]
pub const RX_TIMESTAMP_GRAIN: core::time::Duration = core::time::Duration::from_micros(1);

/// Walk an ancillary buffer for a kernel receive-timestamp cmsg and convert it
/// to a [`SystemTime`].
///
/// Linux/Android deliver `SCM_TIMESTAMPNS` (a `libc::timespec`); Apple and the
/// BSDs deliver `SCM_TIMESTAMP` (a `libc::timeval`), both at level
/// `SOL_SOCKET`. Returns `None` when no such cmsg is present, the data slice is
/// too short, or the seconds field is negative (pre-epoch / malformed). Other
/// Unix targets have no timestamp cmsg and always return `None`.
// Targets that deliver a `libc::timespec` via `SCM_TIMESTAMPNS` (Linux/Android).
#[cfg(recv_timestamp_ns)]
fn parse_rx_time(cmsgs: &[u8]) -> Option<SystemTime> {
  use std::time::Duration;

  for cmsg in CmsgIter::new(cmsgs) {
    // A malformed cmsg header aborts the walk; a missing timestamp is not an
    // error so we simply stop looking.
    let cmsg = cmsg.ok()?;
    if cmsg.level == libc::SOL_SOCKET && cmsg.ty == libc::SCM_TIMESTAMPNS {
      if cmsg.data.len() < core::mem::size_of::<libc::timespec>() {
        return None;
      }
      // SAFETY: the bounds check above guarantees `cmsg.data` holds at least a
      // full `timespec`; `read_unaligned` tolerates the slice's arbitrary
      // alignment and copies the POD struct out without retaining the pointer.
      #[allow(unsafe_code)]
      let ts: libc::timespec =
        unsafe { core::ptr::read_unaligned(cmsg.data.as_ptr().cast::<libc::timespec>()) };
      if ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return None;
      }
      // `checked_add` (not `+`) keeps the denied `arithmetic_side_effects` lint
      // satisfied and degrades a pathological overflow to None.
      return SystemTime::UNIX_EPOCH
        .checked_add(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32));
    }
  }
  None
}

// Apple + BSD targets that deliver a `libc::timeval` via `SCM_TIMESTAMP` (every
// supported timestamp target that is NOT the nanosecond Linux/Android variant).
#[cfg(all(has_recv_timestamp, not(recv_timestamp_ns)))]
fn parse_rx_time(cmsgs: &[u8]) -> Option<SystemTime> {
  use std::time::Duration;

  for cmsg in CmsgIter::new(cmsgs) {
    // A malformed cmsg header aborts the walk; a missing timestamp is not an
    // error so we simply stop looking.
    let cmsg = cmsg.ok()?;
    if cmsg.level == libc::SOL_SOCKET && cmsg.ty == libc::SCM_TIMESTAMP {
      if cmsg.data.len() < core::mem::size_of::<libc::timeval>() {
        return None;
      }
      // SAFETY: the bounds check above guarantees `cmsg.data` holds at least a
      // full `timeval`; `read_unaligned` tolerates the slice's arbitrary
      // alignment and copies the POD struct out without retaining the pointer.
      #[allow(unsafe_code)]
      let tv: libc::timeval =
        unsafe { core::ptr::read_unaligned(cmsg.data.as_ptr().cast::<libc::timeval>()) };
      if tv.tv_sec < 0 || tv.tv_usec < 0 {
        return None;
      }
      // microseconds -> nanoseconds; saturating_mul + checked_add keep the
      // denied `arithmetic_side_effects` lint satisfied (tv_usec is normally
      // < 1e6, so neither actually saturates/overflows in practice).
      let nanos = (tv.tv_usec as u32).saturating_mul(1000);
      return SystemTime::UNIX_EPOCH.checked_add(Duration::new(tv.tv_sec as u64, nanos));
    }
  }
  None
}

// Unix targets with no receive-timestamp cmsg wired up; the sockopt is a no-op,
// so always report None.
#[cfg(all(unix, not(has_recv_timestamp)))]
fn parse_rx_time(_cmsgs: &[u8]) -> Option<SystemTime> {
  None
}

/// One parsed cmsg header + data slice.
#[cfg(unix)]
struct ParsedCmsg<'a> {
  level: libc::c_int,
  ty: libc::c_int,
  data: &'a [u8],
}

/// Iterator over cmsg entries in an ancillary buffer.
///
/// Sound on ARBITRARY input: the public `parse_pktinfo_v4`/`parse_pktinfo_v6`
/// accept any `&[u8]`, so the header is read with `read_unaligned` and every
/// offset is slice-bounds-checked. The payload offset and the inter-cmsg stride
/// come from libc's own `CMSG_LEN(0)` / `CMSG_SPACE(datalen)` — pointer-free
/// length macros that encode each target/arch's exact `CMSG_ALIGN`. We do NOT
/// use `CMSG_DATA`/`CMSG_NXTHDR` (they dereference pointers off the caller's
/// slice — UB on a crafted/short buffer) nor a hand-rolled alignment
/// constant (the `apple?4:size_of::<usize>()` was wrong on BSD arches whose
/// `_ALIGNBYTES` differs from the pointer width, e.g. NetBSD/aarch64).
#[cfg(unix)]
struct CmsgIter<'a> {
  rest: &'a [u8],
}

#[cfg(unix)]
impl<'a> CmsgIter<'a> {
  fn new(buf: &'a [u8]) -> Self {
    Self { rest: buf }
  }
}

#[cfg(unix)]
impl<'a> Iterator for CmsgIter<'a> {
  type Item = Result<ParsedCmsg<'a>, ParseRecvMetaError>;

  fn next(&mut self) -> Option<Self::Item> {
    use crate::error::BufferTooShortDetail;

    let hdr_size = core::mem::size_of::<libc::cmsghdr>();
    if self.rest.len() < hdr_size {
      // Not even a full header remains — trailing pad or exhausted buffer.
      return None;
    }
    // Read the header UNALIGNED: the buffer may be any `&[u8]` (the public
    // parsers accept arbitrary input), so `cmsghdr` alignment is not assumed.
    // SAFETY: `rest.len() >= hdr_size` (checked) makes reading
    // `size_of::<cmsghdr>()` bytes from the start in-bounds; `read_unaligned`
    // imposes no alignment requirement and copies out a value.
    #[allow(unsafe_code)]
    let hdr: libc::cmsghdr =
      unsafe { core::ptr::read_unaligned(self.rest.as_ptr().cast::<libc::cmsghdr>()) };
    let cmsg_len = hdr.cmsg_len as usize;
    if cmsg_len < hdr_size {
      // cmsg_len must at least cover the header.
      return Some(Err(ParseRecvMetaError::BufferTooShort(
        BufferTooShortDetail::new(hdr_size, cmsg_len),
      )));
    }
    if cmsg_len > self.rest.len() {
      return Some(Err(ParseRecvMetaError::BufferTooShort(
        BufferTooShortDetail::new(cmsg_len, self.rest.len()),
      )));
    }
    // `CMSG_LEN(0)` is the platform-exact CMSG_ALIGN'd header size = the payload
    // offset; payload runs from there to `cmsg_len`. Pure length arithmetic (no
    // pointer), so it is sound on any slice and correct on every target/arch. A
    // header-only cmsg (cmsg_len below the aligned header) yields empty data.
    // SAFETY: CMSG_LEN/CMSG_SPACE are pure length arithmetic — they take an
    // integer and dereference no memory, so calling them is sound (libc marks
    // them `unsafe` only by convention).
    #[allow(unsafe_code)]
    let data_start = unsafe { libc::CMSG_LEN(0) } as usize;
    let data: &'a [u8] = self.rest.get(data_start..cmsg_len).unwrap_or(&[]);
    // The next header is `CMSG_SPACE(datalen)` bytes on — again libc's own
    // arithmetic. It is >= data_start >= hdr_size > 0, so iteration always
    // progresses; clamp to what remains.
    let datalen = cmsg_len.saturating_sub(data_start);
    #[allow(unsafe_code)]
    let advance = match u32::try_from(datalen) {
      Ok(dl) => (unsafe { libc::CMSG_SPACE(dl) } as usize).min(self.rest.len()),
      Err(_) => self.rest.len(),
    };
    self.rest = self.rest.get(advance..).unwrap_or(&[]);

    Some(Ok(ParsedCmsg {
      level: hdr.cmsg_level,
      ty: hdr.cmsg_type,
      data,
    }))
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod r4_f5_tests {
  use super::*;

  #[test]
  fn try_join_v4_errors_on_nonexistent_interface_index() {
    // Build a socket to pass to try_join_v4.  Use index=0 so that
    // try_bind_v4 does not attempt IP_MULTICAST_IF (which would require a
    // real indexed interface).
    let opts = MulticastOptionsV4::new(0);
    let sock = match try_bind_v4(opts) {
      Ok(s) => s,
      Err(_) => return, // env-specific (e.g. no IPv4 stack); skip gracefully
    };

    // u32::MAX is reserved / unassignable — getifs::interface_by_index
    // returns Ok(None), which try_join_v4 maps to InterfaceNotFound.
    let result = try_join_v4(&sock, u32::MAX);
    assert!(
      result.is_err(),
      "expected error for nonexistent interface index"
    );
    assert!(
      result.unwrap_err().is_interface_not_found(),
      "expected InterfaceNotFound variant"
    );
  }

  #[test]
  fn try_bind_v4_errors_on_nonzero_index_with_no_ipv4_interface() {
    // Use a fabricated index that cannot exist (u32::MAX).  ipv4_addr_for_index
    // will return None for it, triggering the new error path.
    let opts = MulticastOptionsV4::new(u32::MAX);
    let result = try_bind_v4(opts);
    assert!(result.is_err(), "expected error when interface has no IPv4");
    assert!(
      result.unwrap_err().is_interface_not_found(),
      "expected InterfaceNotFound variant"
    );
  }

  #[test]
  fn try_bind_v4_sets_unicast_and_multicast_ttl_255() {
    // a bound v4 socket must egress unicast (legacy §6.7) AND
    // multicast sends with TTL 255 (RFC 6762 §11). These are distinct socket
    // options; both must be 255. Best-effort: skip if the env can't bind.
    let sock = match try_bind_v4(MulticastOptionsV4::new(0)) {
      Ok(s) => s,
      Err(_) => return,
    };
    assert_eq!(sock.ttl().unwrap(), 255, "unicast IP_TTL must be 255");
    assert_eq!(
      sock.multicast_ttl_v4().unwrap(),
      255,
      "multicast IP_MULTICAST_TTL must be 255"
    );
  }

  #[test]
  fn try_bind_v6_applies_multicast_loop_option() {
    // with_multicast_loop(false) must actually disable IPv6
    // multicast loopback (it was previously ignored on v6). Best-effort: skip
    // if the env can't bind a v6 multicast socket.
    let off = match try_bind_v6(MulticastOptionsV6::new(0).with_multicast_loop(false)) {
      Ok(s) => s,
      Err(_) => return,
    };
    assert!(
      !off.multicast_loop_v6().unwrap(),
      "with_multicast_loop(false) must disable IPV6_MULTICAST_LOOP"
    );

    let on = match try_bind_v6(MulticastOptionsV6::new(0)) {
      Ok(s) => s,
      Err(_) => return,
    };
    assert!(
      on.multicast_loop_v6().unwrap(),
      "default multicast_loop must leave IPV6_MULTICAST_LOOP enabled"
    );
  }

  #[test]
  fn try_bind_v6_is_ipv6_only() {
    // the v6 mDNS socket must be IPV6_V6ONLY so it does not also
    // receive IPv4 (v4-mapped) and collide with the separate IPv4 socket on
    // dual-stack-default systems. Best-effort: skip if the env can't bind v6.
    let sock = match try_bind_v6(MulticastOptionsV6::new(0)) {
      Ok(s) => s,
      Err(_) => return,
    };
    let s2 = Socket::from(sock);
    assert!(
      s2.only_v6().unwrap(),
      "the IPv6 mDNS socket must be bound IPV6_V6ONLY"
    );
  }
}

#[cfg(test)]
#[cfg(unix)]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::arithmetic_side_effects,
  clippy::indexing_slicing
)]
mod tests {
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
}

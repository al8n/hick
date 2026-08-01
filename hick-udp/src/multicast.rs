//! Multicast socket configuration helpers + RecvMeta + cmsg parsing (stubbed).

use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
  time::SystemTime,
};

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

/// Whether this target can report the interface an **IPv4** datagram arrived
/// on, i.e. whether [`RecvMeta::interface_index`] carries evidence rather than
/// a placeholder.
///
/// `false` means every IPv4 [`RecvMeta`] reports index `0` whichever NIC
/// actually delivered the datagram. A caller that scopes a wildcard-bound
/// socket to one link — as RFC 6762 §11 requires — needs this to tell "this
/// arrived somewhere else" apart from "this platform never says": treating the
/// second as the first takes IPv4 off the air, and the reverse admits an
/// adjacent network. The capability is fixed at compile time, so the choice can
/// be made once per target rather than per datagram.
///
/// True on Linux/Android, Apple and Windows. **False on FreeBSD, DragonFly,
/// OpenBSD and NetBSD**: the first three define no `IP_PKTINFO` at all (they
/// use `IP_RECVDSTADDR`/`IP_RECVIF`), and NetBSD's `in_pktinfo` is a different,
/// 8-byte layout this crate's parser does not decode. See `build.rs` for the
/// capability matrix these track.
#[inline(always)]
pub const fn reports_rx_interface_v4() -> bool {
  cfg!(any(has_ip_pktinfo, windows))
}

/// Whether this target can report the interface an **IPv6** datagram arrived
/// on. The IPv6 twin of [`reports_rx_interface_v4`], and `true` on every
/// supported target.
///
/// Every supported Unix defines `IPV6_RECVPKTINFO`/`IPV6_PKTINFO`, and
/// `try_bind_v6` fails the bind rather than continuing if enabling it fails.
/// Windows sets `IPV6_PKTINFO` the same way, and its receive path reports an
/// error rather than degrading when the `WSARecvMsg` extension is unavailable.
#[inline(always)]
pub const fn reports_rx_interface_v6() -> bool {
  cfg!(any(has_ipv6_pktinfo, windows))
}

/// Metadata about a received datagram.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
  len: usize,
  peer: SocketAddr,
  local_ip: IpAddr,
  destination: Option<IpAddr>,
  interface_index: u32,
  rx_time: Option<SystemTime>,
  hop_limit: Option<u8>,
  multicast_flag: Option<bool>,
}
impl RecvMeta {
  /// `destination` is `Option<IpAddr>` rather than a second `IpAddr` so no call
  /// site can pass it positionally in place of `local_ip`: the two carry
  /// different addresses on Unix IPv4 and the compiler, not review, is what
  /// keeps them apart. See [`RecvMeta::destination`].
  pub(crate) const fn new(
    len: usize,
    peer: SocketAddr,
    local_ip: IpAddr,
    destination: Option<IpAddr>,
    iface: u32,
    rx_time: Option<SystemTime>,
  ) -> Self {
    Self {
      len,
      peer,
      local_ip,
      destination,
      interface_index: iface,
      rx_time,
      hop_limit: None,
      multicast_flag: None,
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
  ///
  /// On Unix IPv4 this is `in_pktinfo.ipi_spec_dst`, the receiving interface's
  /// own unicast address — deliberately, because self-send detection on a
  /// multi-homed host needs to know which of this host's addresses the datagram
  /// landed on. It is therefore NOT the address the sender wrote in the IP
  /// header; for that, and only for that, use [`RecvMeta::destination`].
  #[inline(always)]
  pub const fn local_ip(&self) -> IpAddr {
    self.local_ip
  }

  /// The IP header **destination** of the datagram, where this target recovers
  /// one.
  ///
  /// Distinct from [`RecvMeta::local_ip`] on exactly one square: Unix IPv4,
  /// where PKTINFO carries both `ipi_spec_dst` (the interface address, returned
  /// by `local_ip`) and `ipi_addr` (the header destination, returned here). For
  /// IPv6, and on Windows, PKTINFO carries only the header destination and the
  /// two accessors return the same address.
  ///
  /// `None` is "this receive recovered no destination", never "the destination
  /// was unicast": it is what Unix IPv4 without `IP_PKTINFO`
  /// (FreeBSD/DragonFly/OpenBSD/NetBSD) reports on every datagram, and what any
  /// receive whose PKTINFO cmsg was absent or truncated reports. RFC 6762 §11
  /// selects between its two local-link tests by destination, so a caller
  /// holding `None` has to decide on something else — see
  /// [`RecvMeta::multicast_flag`], which is that something on the netbsdlike
  /// half of the gap.
  #[inline(always)]
  pub const fn destination(&self) -> Option<IpAddr> {
    self.destination
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

  /// Whether the kernel flagged this datagram as delivered to a multicast
  /// group rather than to this host alone (`MSG_MCAST` in the `msg_flags`
  /// `recvmsg` returns), on targets that have that flag.
  ///
  /// `None` means the flag does not exist here — **not** that the datagram was
  /// unicast. Of the targets this crate supports, only OpenBSD and NetBSD bind
  /// `MSG_MCAST` in `libc`.
  ///
  /// `Some(true)` is coarse on purpose: it says the datagram was delivered as a
  /// multicast, not which group it was addressed to, and the flag follows the
  /// link-layer delivery. It exists because on OpenBSD/NetBSD IPv4 it is the
  /// only destination evidence available at all — [`RecvMeta::destination`] is
  /// `None` on every datagram there — and RFC 6762 §11 needs to tell a group
  /// destination from a unicast one to pick the right local-link test.
  #[inline(always)]
  pub const fn multicast_flag(&self) -> Option<bool> {
    self.multicast_flag
  }

  /// Overwrite the multicast-delivery flag, threaded in by `recv_with_meta`
  /// from `msghdr::msg_flags`. Unlike the cmsg-derived fields this one survives
  /// `MSG_CTRUNC`: it rides on the header, not on the control buffer.
  #[cfg(unix)]
  #[inline(always)]
  pub(crate) fn set_multicast_flag(&mut self, multicast_flag: Option<bool>) {
    self.multicast_flag = multicast_flag;
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
  // Resolve the requested egress interface (if any) to an IPv4 address for
  // IP_MULTICAST_IF; a non-zero index that doesn't resolve is a hard error.
  let multicast_if = if opts.interface_index() != 0 {
    match ipv4_addr_for_index(opts.interface_index()) {
      Some(ip) => Some(ip),
      None => {
        return Err(BindError::InterfaceNotFound(
          crate::error::InterfaceNotFoundDetail::new(opts.interface_index()),
        ));
      }
    }
  } else {
    None
  };

  // Create + bind the socket: SO_REUSEADDR/REUSEPORT before bind, IP_MULTICAST_IF
  // for the egress interface, and IP_TTL=255 for the legacy §6.7 unicast replies
  // (the multicast TTL option does not cover them — RFC 6762 §11). All applied
  // inside `platform::bind_v4`.
  let std_sock = platform::bind_v4(
    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT),
    multicast_if,
    255,
  )?;
  platform::set_multicast_loop_v4(&std_sock, opts.multicast_loop())?;
  platform::set_multicast_ttl_v4(&std_sock, opts.ttl())?;
  // NOT best-effort where the option exists. On a target `reports_rx_interface_v4`
  // calls capable, a receiver is entitled to read a zero interface index as "this
  // datagram was not delivered on my link" and drop it; if the enable silently
  // failed, every index would be zero and that receiver would be totally deaf
  // rather than degraded. On an incapable target the setter is a no-op returning
  // `Ok(())`, so this changes nothing there — the index stays zero and the
  // receiver knows from the constant that it means "unknown".
  platform::set_recv_pktinfo_v4(&std_sock)?;
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

/// Read `IPV6_MULTICAST_HOPS` back immediately after
/// `platform::set_multicast_hops_v6` and turn a mismatch into a distinct,
/// diagnosable [`BindError`] instead of letting the bind silently return a
/// socket configured differently than the caller asked for.
///
/// This is the ONLY sockopt `try_bind_v6`/`try_bind_v4` verify this way — see
/// `crate::platform::unix::set_multicast_hops_v6` for why: it is the one
/// option in this crate that has already failed silently in production (the
/// rustix wrong-protocol-level defect landed on Linux's unrelated
/// `IP_PASSSEC` boolean, reporting success while the real hop limit stayed at
/// its default of 1, violating the 255 RFC 6762 §11 requires). No other option
/// these two functions set has a comparable history: the PKTINFO enablers do
/// fail the bind now (see their call sites), but on a plain error return, which
/// no known defect turns into a false success; the timestamp and TTL enablers
/// degrade legitimately and stay best-effort. Re-reading any of them would add
/// a syscall without adding safety.
///
/// Unix-only: the read-back chokepoint (`get_int_sockopt`) only exists on
/// this platform. Windows sets this option through `socket2`, which passes
/// the correct protocol level — there is no known defect to detect there, so
/// no equivalent verification is added.
#[cfg(unix)]
fn verify_multicast_hops_v6(sock: &UdpSocket, requested: u8) -> Result<(), BindError> {
  let observed = platform::get_multicast_hops_v6(sock)?;
  if observed != i32::from(requested) {
    return Err(BindError::MulticastHopsNotApplied(
      crate::error::MulticastHopsNotAppliedDetail::new(requested, observed),
    ));
  }
  Ok(())
}

// Test-only seam for `try_bind_v6_inner`, below: when set with `.set(Some(v))`
// from inside a test (on that test's own thread), makes the function apply
// `v` to the kernel via `set_multicast_hops_v6` while still telling
// `verify_multicast_hops_v6` that `opts.hops()` was requested — forcing a
// genuine requested/observed disagreement through the REAL production call
// sequence. This is the only way to do that: on a correctly functioning
// kernel every value `MulticastOptionsV6::hops()` can hold (0..=255)
// round-trips faithfully, so no input reachable through the public API alone
// can ever make the setter and the verifier disagree — which is exactly why
// `crate::multicast::tests::try_bind_v6_rejects_a_mismatch_forced_through_production_wiring`
// needs this to exist at all, rather than only exercising
// `verify_multicast_hops_v6` directly (see that test's doc: calling the
// verifier directly proves the comparison works, but not that
// `try_bind_v6_inner` still calls it).
//
// `None` (the default) means "apply `opts.hops()` faithfully," identical to
// production behavior; this is the ONLY possible value outside `#[cfg(test)]`
// builds, since the item does not exist at all there. Thread-local, not a
// plain global `static`, so tests running concurrently on separate threads
// (the default `libtest` behavior) can never interfere with each other
// through it.
#[cfg(test)]
thread_local! {
  static FORCE_APPLIED_HOPS_V6: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) };
}

fn try_bind_v6_inner(opts: MulticastOptionsV6) -> Result<UdpSocket, BindError> {
  // Create + bind the socket. IPV6_V6ONLY is set before bind so a `[::]:5353`
  // socket doesn't also accept IPv4 (as v4-mapped) and collide with the separate
  // IPv4 socket bound to `0.0.0.0:5353` on dual-stack-default systems (e.g. Linux
  // `bindv6only=0`); SO_REUSEADDR/REUSEPORT likewise precede bind. The egress
  // interface (IPV6_MULTICAST_IF) and the legacy-reply hop limit 255
  // (IPV6_UNICAST_HOPS, RFC 6762 §11) are applied inside `platform::bind_v6`.
  let std_sock = platform::bind_v6(
    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0),
    opts.interface_index(),
    255,
  )?;
  // honor with_multicast_loop(false) for IPv6 too (the IPv4 path
  // applies the analogous IP_MULTICAST_LOOP). Without this the option was
  // silently ignored and self-loopback could not be disabled on v6.
  platform::set_multicast_loop_v6(&std_sock, opts.multicast_loop())?;

  // `hops_to_apply` is `opts.hops()` in every real build. See
  // `FORCE_APPLIED_HOPS_V6` for why the `#[cfg(test)]` override exists.
  let hops_to_apply = opts.hops();
  #[cfg(test)]
  let hops_to_apply = FORCE_APPLIED_HOPS_V6
    .with(|cell| cell.get())
    .unwrap_or(hops_to_apply);

  platform::set_multicast_hops_v6(&std_sock, hops_to_apply)?;
  // See `verify_multicast_hops_v6`'s doc for why this ONE option, and only
  // this one, gets a read-back: it already failed silently in production
  // despite `setsockopt` reporting success.
  #[cfg(unix)]
  verify_multicast_hops_v6(&std_sock, opts.hops())?;
  // NOT best-effort: `reports_rx_interface_v6` promises every supported target
  // reports the receiving interface, and a receiver that scopes itself to one
  // link is entitled to drop what arrived elsewhere. See the IPv4 twin in
  // `try_bind_v4_inner` for why a silent failure here would be deafness rather
  // than degradation.
  platform::set_recv_pktinfo_v6(&std_sock)?;
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
      // `local_ip` is ipi_spec_dst (bytes 4..8) — the local interface address
      // the packet was received on, which is what self-packet detection on a
      // multi-homed host needs and which for a multicast receive is NOT the
      // address the sender addressed.
      let addr_bytes: &[u8; 4] = cmsg
        .data
        .get(4..8)
        .and_then(|s| s.first_chunk::<4>())
        .ok_or_else(|| {
          ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(4, cmsg.data.len()))
        })?;
      let local_ip = IpAddr::V4(Ipv4Addr::from(*addr_bytes));
      // `destination` is ipi_addr (bytes 8..12) — the IP header destination,
      // the group (224.0.0.251) for a multicast receive. Both are kept: RFC 6762
      // §11 selects its local-link test by the header destination, and reading
      // ipi_spec_dst for that made every multicast arrival look unicast. The
      // 12-byte length check above already covers this slice.
      let dst_bytes: &[u8; 4] = cmsg
        .data
        .get(8..12)
        .and_then(|s| s.first_chunk::<4>())
        .ok_or_else(|| {
          ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(4, cmsg.data.len()))
        })?;
      let destination = IpAddr::V4(Ipv4Addr::from(*dst_bytes));
      // No timestamp available here; recv_with_meta overwrites rx_time after
      // parsing the SCM_TIMESTAMP* cmsg from the same control buffer.
      return Ok(RecvMeta::new(
        len,
        peer,
        local_ip,
        Some(destination),
        iface,
        None,
      ));
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
      // in6_pktinfo has no `ipi_spec_dst` twin: ipi6_addr IS the IP header
      // destination, so `local_ip` and `destination` are the same address here
      // and the v4 asymmetry does not reach IPv6.
      // No timestamp available here; recv_with_meta overwrites rx_time after
      // parsing the SCM_TIMESTAMP* cmsg from the same control buffer.
      return Ok(RecvMeta::new(
        len,
        peer,
        local_ip,
        Some(local_ip),
        iface,
        None,
      ));
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

/// Reconstruct a [`SocketAddr`] from a `sockaddr_storage` filled by `recvmsg`.
///
/// Returns `None` for a truncated address or a family other than `AF_INET` /
/// `AF_INET6` (mDNS handles only IPv4/IPv6 peers). Mirrors the prior
/// `socket2::SockAddr::as_socket` behavior: the v6 `flowinfo` / `scope_id` are
/// passed through verbatim (the latter carries the link-local zone the RFC 6762
/// §11 fallback relies on).
#[cfg(unix)]
fn sockaddr_storage_to_socketaddr(
  storage: &libc::sockaddr_storage,
  len: libc::socklen_t,
) -> Option<SocketAddr> {
  let len = len as usize;
  match storage.ss_family as libc::c_int {
    libc::AF_INET if len >= core::mem::size_of::<libc::sockaddr_in>() => {
      // SAFETY: ss_family is AF_INET and recvmsg wrote at least
      // size_of::<sockaddr_in>() bytes, so the sin_addr/sin_port reads stay
      // within the initialized storage; sockaddr_storage is suitably aligned.
      #[allow(unsafe_code)]
      let sin = unsafe { &*core::ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
      Some(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
        u16::from_be(sin.sin_port),
      )))
    }
    libc::AF_INET6 if len >= core::mem::size_of::<libc::sockaddr_in6>() => {
      // SAFETY: ss_family is AF_INET6 and recvmsg wrote at least
      // size_of::<sockaddr_in6>() bytes.
      #[allow(unsafe_code)]
      let sin6 = unsafe { &*core::ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
      Some(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(sin6.sin6_addr.s6_addr),
        u16::from_be(sin6.sin6_port),
        sin6.sin6_flowinfo,
        sin6.sin6_scope_id,
      )))
    }
    _ => None,
  }
}

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
  // SAFETY: `libc::sockaddr_storage` is plain-old-data; an all-zero bit pattern
  // is a valid (empty) storage that recvmsg overwrites before we read it.
  #[allow(unsafe_code)]
  let mut storage: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
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
  // `storage` is already a `sockaddr_storage`; hand recvmsg a pointer to it to
  // fill (it writes a valid sockaddr within `msg_namelen` before we read back).
  msg.msg_name = core::ptr::addr_of_mut!(storage).cast();
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
  let peer = sockaddr_storage_to_socketaddr(&storage, msg.msg_namelen).ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "recvmsg returned an unrecognized peer address family",
    )
  })?;

  // The kernel's own multicast-delivery flag, read from the header rather than
  // from a cmsg — so it survives MSG_CTRUNC, and it is available on the targets
  // that parse no IPv4 PKTINFO at all. `None` where libc binds no MSG_MCAST.
  let multicast_flag = msg_multicast_flag(msg.msg_flags);

  // Helper: a RecvMeta carrying the real peer + length but an UNSPECIFIED
  // local address and NO destination, used when PKTINFO is absent. The datagram
  // itself was already consumed by `recvmsg`, so we MUST NOT drop it just
  // because the ancillary metadata is missing — the caller falls back to its own
  // self-loopback detection (content-hash ring) when local_ip is
  // unspecified. This keeps a missing/failed PKTINFO sockopt from silently
  // black-holing all inbound traffic.
  //
  // `destination` is `None` rather than the UNSPECIFIED address: a caller must
  // be able to tell "no destination was recovered" from "the destination was
  // 0.0.0.0", because the two lead to opposite RFC 6762 §11 decisions.
  let unspecified_meta = || {
    let local_ip = if is_v4 {
      std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
      std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    RecvMeta::new(n, peer, local_ip, None, 0, None)
  };

  // MSG_CTRUNC means our control buffer was too small to hold all ancillary
  // data; treat that as "no pktinfo" and fall back (data is preserved).
  if msg.msg_flags & libc::MSG_CTRUNC != 0 {
    let mut meta = unspecified_meta();
    meta.set_multicast_flag(multicast_flag);
    return Ok(meta);
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
  meta.set_multicast_flag(multicast_flag);
  Ok(meta)
}

/// Read `MSG_MCAST` out of the `msg_flags` `recvmsg` returned: whether the
/// datagram was delivered as a multicast rather than addressed to this host
/// alone.
///
/// `None` where `libc` binds no `MSG_MCAST` — every supported target but
/// OpenBSD and NetBSD. See [`RecvMeta::multicast_flag`] for why a coarse
/// "some group" answer is worth carrying at all.
#[cfg(all(unix, has_msg_mcast))]
fn msg_multicast_flag(msg_flags: libc::c_int) -> Option<bool> {
  Some(msg_flags & libc::MSG_MCAST != 0)
}

/// Fallback for targets where `libc` binds no `MSG_MCAST`: always `None`,
/// meaning "this target has no such flag", never "the datagram was unicast".
#[cfg(all(unix, not(has_msg_mcast)))]
fn msg_multicast_flag(_msg_flags: libc::c_int) -> Option<bool> {
  None
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

// ============================================================================
// PAIRED CLASSIFIER — this function has a sibling copy, `is_environment_refusal`,
// in `hick-udp/tests/loopback.rs`. The two must classify identically. If you
// change the allowlist here (add/remove an `ErrorKind` or a raw-errno arm),
// make the SAME change there, and vice versa. This pairing previously caught
// a gap that existed in BOTH copies at once: neither recognized Windows'
// `WSAEAFNOSUPPORT`, because the omission was copied along with everything
// else. See the "why two copies, not one" note below before
// "solving" this by deleting one of them.
// ============================================================================
/// Whether `e` represents a legitimate environment refusal to bind (not a
/// hick-udp bug). Kept intentionally narrow: `PermissionDenied` /
/// `AddrInUse` / `AddrNotAvailable`, plus an errno-matched
/// "address family not supported" on the two platform families this crate
/// compiles for (`EAFNOSUPPORT` on Unix, `WSAEAFNOSUPPORT` on Windows). A
/// skip arm that accepts anything wider than this can absorb the exact
/// regressions these tests exist to catch — see `expect_bind_or_skip`'s doc
/// for the finding that made this explicit. `ErrorKind::Uncategorized` /
/// `InvalidInput` are deliberately NOT in this allowlist: broadening to
/// either would re-admit `EINVAL`, the exact errno the whole branch this
/// file belongs to exists to stop silently skipping.
///
/// Why two copies instead of one shared definition: the library's own unit
/// tests and `hick-udp/tests/loopback.rs` are separate compilation units — an
/// integration-test binary links against the COMPILED library as an external
/// crate, so it cannot see anything gated `#[cfg(test)]` inside the library
/// (that cfg only applies when the library itself is being tested). Sharing
/// for real would require either growing the library's real, public,
/// always-compiled API purely to expose test-classification logic (this
/// crate is otherwise disciplined about a tight public surface — see
/// `#![deny(missing_docs)]` and the `pub(crate)` sockopt chokepoints in
/// `platform/unix.rs`), or a new workspace member crate for ~20 lines of
/// logic. Both costs seemed to outweigh removing one small duplication, so
/// this stays two copies — kept honest by the pairing marker above, the
/// identical structure, and a matching set of classifier regression tests in
/// both files (see `is_environment_refusal_classifier_tests` below).
#[cfg(test)]
fn is_environment_refusal(e: &std::io::Error) -> bool {
  use std::io::ErrorKind;
  if matches!(
    e.kind(),
    ErrorKind::PermissionDenied | ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable
  ) {
    return true;
  }
  #[cfg(unix)]
  if e.raw_os_error() == Some(libc::EAFNOSUPPORT) {
    return true;
  }
  #[cfg(windows)]
  if e.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEAFNOSUPPORT) {
    return true;
  }
  false
}

/// Bind-or-skip helper for this crate's own unit tests, mirroring
/// `hick-udp/tests/loopback.rs`'s `expect_bind_or_skip` exactly (same shape,
/// same allowlist via `is_environment_refusal`).
///
/// Exists because an earlier version of the
/// `verify_multicast_hops_v6` regression test matched `Err(e) => skip`
/// on the INITIAL bind — every `BindError` variant, not just `Io` ones. Had
/// the verifier's comparison been inverted, `try_bind_v6` would have
/// returned `Err(BindError::MulticastHopsNotApplied(_))` right there, and
/// that bare `Err(e) => skip` would have absorbed it as if the environment
/// had merely refused the bind — the test would report a skip, not a
/// failure, for the exact regression it exists to catch. The same
/// overly-broad shape was already present, independently, in every test
/// below that pre-dates this file's `MulticastHopsNotApplied` variant: none
/// of them could have swallowed THAT specific error before it existed, but
/// all of them could swallow any other non-environmental `BindError` a
/// future regression might introduce, which is the general class this
/// helper exists to close in one pass, not just the one instance.
#[cfg(test)]
#[allow(clippy::panic)]
fn expect_bind_or_skip<T>(label: &str, result: Result<T, BindError>) -> Option<T> {
  match result {
    Ok(v) => Some(v),
    Err(BindError::Io(e)) if is_environment_refusal(&e) => {
      eprintln!("{label}: environment refused ({e}); skipping");
      None
    }
    Err(e) => panic!(
      "{label}: bind failed with an error that is not a recognized environment refusal — this \
       indicates a bug in our own binding/verification code, not an environment limitation: \
       {e:?}"
    ),
  }
}

// PAIRED CLASSIFIER TESTS — `hick-udp/tests/loopback.rs` has an identical
// `is_environment_refusal_classifier_tests` module for its own copy of
// `is_environment_refusal`. Extend both whenever a new platform/errno is
// added to either classifier.
#[cfg(test)]
mod is_environment_refusal_classifier_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod r4_f5_tests {
  use socket2::Socket;

  use super::*;

  #[test]
  fn try_join_v4_errors_on_nonexistent_interface_index() {
    // Build a socket to pass to try_join_v4.  Use index=0 so that
    // try_bind_v4 does not attempt IP_MULTICAST_IF (which would require a
    // real indexed interface).
    let opts = MulticastOptionsV4::new(0);
    let Some(sock) = expect_bind_or_skip(
      "try_join_v4_errors_on_nonexistent_interface_index",
      try_bind_v4(opts),
    ) else {
      return;
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
    let Some(sock) = expect_bind_or_skip(
      "try_bind_v4_sets_unicast_and_multicast_ttl_255",
      try_bind_v4(MulticastOptionsV4::new(0)),
    ) else {
      return;
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
    let Some(off) = expect_bind_or_skip(
      "try_bind_v6_applies_multicast_loop_option (loop=false)",
      try_bind_v6(MulticastOptionsV6::new(0).with_multicast_loop(false)),
    ) else {
      return;
    };
    assert!(
      !off.multicast_loop_v6().unwrap(),
      "with_multicast_loop(false) must disable IPV6_MULTICAST_LOOP"
    );

    let Some(on) = expect_bind_or_skip(
      "try_bind_v6_applies_multicast_loop_option (loop=true)",
      try_bind_v6(MulticastOptionsV6::new(0)),
    ) else {
      return;
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
    let Some(sock) = expect_bind_or_skip(
      "try_bind_v6_is_ipv6_only",
      try_bind_v6(MulticastOptionsV6::new(0)),
    ) else {
      return;
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
mod tests;

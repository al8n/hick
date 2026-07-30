//! Unix socket option setters.
//!
//! Multicast TX-side options mostly go through rustix (`rustix::net::sockopt`);
//! `set_multicast_hops_v6` is one deliberate exception — see the
//! `IPV6_MULTICAST_HOPS` paragraph below. The receive-side cmsg-enable options
//! below funnel through a SINGLE `libc::setsockopt` chokepoint
//! (`set_int_sockopt`) because rustix models sockopts as a curated, typed set
//! and — as of rustix 1.1.4 (the newest published) — exposes no setter for ANY
//! of them, and no generic/raw `setsockopt` escape hatch. A second, matching
//! chokepoint, `get_int_sockopt`, reads a `c_int`-valued sockopt back; it has
//! exactly one caller, `get_multicast_hops_v6` — see the `IPV6_MULTICAST_HOPS`
//! paragraph below for why that one option, and no other, is read back. What
//! rustix is missing here:
//!
//!   * `IP_PKTINFO` / `IP_RECVPKTINFO`  — no `sockopt::set_ip_(recv)pktinfo`
//!   * `IPV6_RECVPKTINFO`               — no `sockopt::set_ipv6_recvpktinfo`
//!   * `SO_TIMESTAMP` / `SO_TIMESTAMPNS`— no `sockopt::set_socket_timestamp[ns]`
//!   * `IP_RECVTTL`                     — no `sockopt::set_ip_recvttl`
//!   * `IPV6_RECVHOPLIMIT`              — no `sockopt::set_ipv6_recvhoplimit`
//!
//! (rustix DOES have the siblings `set_ip_recvtos` / `set_ipv6_recvtclass`, so
//! the gap is specific, not categorical.)
//!
//! `IPV6_MULTICAST_HOPS` is a DIFFERENT kind of defect, not a gap: rustix
//! 1.1.4's `sockopt::set_ipv6_multicast_hops` / `ipv6_multicast_hops` DO exist,
//! but both pass `IPPROTO_IP` instead of `IPPROTO_IPV6`
//! (`backend/libc/net/sockopt.rs:618-624`) and so fail every call with
//! `EINVAL` — the only `IPV6_*` sockopt in that file with the wrong level.
//! `set_multicast_hops_v6` below routes around it through the same
//! `set_int_sockopt` chokepoint instead of rustix; see that function for the
//! full citation and the on-host verification.
//!
//! The matching RECEIVE path in `crate::multicast` likewise uses
//! `libc::recvmsg` + manual `cmsghdr` parsing: rustix's `recvmsg` yields only
//! `RecvAncillaryMessage::{ScmRights, ScmCredentials}` and exposes no raw cmsg
//! bytes, so the `IP_PKTINFO` / `SCM_TIMESTAMP*` / `IP_TTL` / `IPV6_HOPLIMIT`
//! control messages mDNS needs cannot be read through it.
//!
//! If a future rustix adds these, the `libc` dependency can be dropped on Linux
//! (rustix's `linux_raw` backend is libc-free; on macOS/BSD rustix uses the
//! libc backend regardless, so the direct dep costs nothing extra there).

use std::{
  net::{Ipv4Addr, SocketAddrV4, SocketAddrV6, UdpSocket},
  os::fd::{AsFd, AsRawFd},
};

use rustix::net::{AddressFamily, SocketType, sockopt};

/// Map a rustix `Errno` to a `std::io::Error`, preserving the OS errno.
fn to_io(e: rustix::io::Errno) -> std::io::Error {
  std::io::Error::from_raw_os_error(e.raw_os_error())
}

/// Create and bind an IPv4 mDNS UDP socket via rustix.
///
/// `SO_REUSEADDR` + `SO_REUSEPORT` are set BEFORE bind so port 5353 can be
/// shared with another responder already on it. When `multicast_if` is `Some`,
/// outbound multicast egresses that interface address (`IP_MULTICAST_IF`).
/// `unicast_ttl` sets `IP_TTL` (255 for the legacy §6.7 unicast replies, which
/// the multicast TTL option does not cover — RFC 6762 §11). The returned
/// `UdpSocket` owns the fd.
pub(crate) fn bind_v4(
  local: SocketAddrV4,
  multicast_if: Option<Ipv4Addr>,
  unicast_ttl: u8,
) -> std::io::Result<UdpSocket> {
  // `None` protocol: the kernel selects UDP for an INET/INET6 DGRAM socket (the
  // explicit `IPPROTO_UDP` socket2 passed is the same value).
  let fd = rustix::net::socket(AddressFamily::INET, SocketType::DGRAM, None).map_err(to_io)?;
  sockopt::set_socket_reuseaddr(&fd, true).map_err(to_io)?;
  sockopt::set_socket_reuseport(&fd, true).map_err(to_io)?;
  rustix::net::bind(&fd, &local).map_err(to_io)?;
  if let Some(ip) = multicast_if {
    sockopt::set_ip_multicast_if(&fd, &ip).map_err(to_io)?;
  }
  sockopt::set_ip_ttl(&fd, unicast_ttl as u32).map_err(to_io)?;
  Ok(UdpSocket::from(fd))
}

/// Create and bind an IPv6 mDNS UDP socket via rustix.
///
/// `IPV6_V6ONLY` is set BEFORE bind so a `[::]:5353` socket does not also accept
/// v4-mapped traffic and collide with the separate IPv4 socket; `SO_REUSEADDR` +
/// `SO_REUSEPORT` likewise precede bind. A non-zero `multicast_if_index` pins the
/// outbound multicast interface (`IPV6_MULTICAST_IF`). `unicast_hops` sets
/// `IPV6_UNICAST_HOPS` (255 for legacy unicast replies — RFC 6762 §11).
pub(crate) fn bind_v6(
  local: SocketAddrV6,
  multicast_if_index: u32,
  unicast_hops: u8,
) -> std::io::Result<UdpSocket> {
  let fd = rustix::net::socket(AddressFamily::INET6, SocketType::DGRAM, None).map_err(to_io)?;
  sockopt::set_ipv6_v6only(&fd, true).map_err(to_io)?;
  sockopt::set_socket_reuseaddr(&fd, true).map_err(to_io)?;
  sockopt::set_socket_reuseport(&fd, true).map_err(to_io)?;
  rustix::net::bind(&fd, &local).map_err(to_io)?;
  if multicast_if_index != 0 {
    sockopt::set_ipv6_multicast_if(&fd, multicast_if_index).map_err(to_io)?;
  }
  sockopt::set_ipv6_unicast_hops(&fd, Some(unicast_hops)).map_err(to_io)?;
  Ok(UdpSocket::from(fd))
}

pub(crate) fn set_multicast_loop_v4(sock: &UdpSocket, on: bool) -> std::io::Result<()> {
  sockopt::set_ip_multicast_loop(sock.as_fd(), on)
    .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))
}

pub(crate) fn set_multicast_ttl_v4(sock: &UdpSocket, ttl: u8) -> std::io::Result<()> {
  sockopt::set_ip_multicast_ttl(sock.as_fd(), ttl as u32)
    .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))
}

/// Set the IPv6 multicast hop limit (`IPV6_MULTICAST_HOPS`, the v6 sibling of
/// `IP_MULTICAST_TTL`).
///
/// Deliberately bypasses rustix: as of rustix 1.1.4 (the newest published),
/// `sockopt::set_ipv6_multicast_hops` / `ipv6_multicast_hops`
/// (`backend/libc/net/sockopt.rs:618` / `:623`) both pass `IPPROTO_IP` instead
/// of `IPPROTO_IPV6` (the `setsockopt`/`getsockopt` calls at lines `:619` /
/// `:624`) — the ONLY `IPV6_*` sockopt in that file with the wrong level;
/// every sibling (`set_ipv6_unicast_hops`, `set_ipv6_multicast_loop`,
/// `set_ipv6_v6only`, …) correctly uses `IPPROTO_IPV6`. The wrong level makes
/// the kernel reject the call with `EINVAL` unconditionally — verified on
/// macOS across every interface (including loopback) and every hop value (0,
/// 1, 64, 255) — which fails `bind_v6` on every IPv6-capable host. Route
/// around it through the `set_int_sockopt` chokepoint instead of
/// `sockopt::set_ipv6_multicast_hops`. Do NOT "simplify" this back to the
/// rustix call without first confirming upstream has fixed the level.
///
/// The SAME wrong level is silent rather than loud on Linux: `IPPROTO_IP`/18
/// there is `IP_PASSSEC`, a real, settable, unrelated boolean, so the
/// wrong-level call would report success while the real hop limit stayed at
/// its kernel default of 1 instead of the 255 RFC 6762 §11 requires — this is
/// exactly the shape rustix's own bug had before this function routed around
/// it. Because a `setsockopt` return code alone cannot distinguish "applied"
/// from "silently hit the wrong option," `crate::multicast::try_bind_v6`
/// reads this ONE option back with `get_multicast_hops_v6` immediately after
/// calling this function, and fails the bind if the two disagree. No other
/// sockopt in this crate gets that treatment — see `get_multicast_hops_v6`.
pub(crate) fn set_multicast_hops_v6(sock: &UdpSocket, hops: u8) -> std::io::Result<()> {
  set_int_sockopt(
    sock,
    libc::IPPROTO_IPV6,
    libc::IPV6_MULTICAST_HOPS,
    hops as libc::c_int,
  )
}

pub(crate) fn set_multicast_loop_v6(sock: &UdpSocket, on: bool) -> std::io::Result<()> {
  sockopt::set_ipv6_multicast_loop(sock.as_fd(), on)
    .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))
}

/// Enable delivery of the `IP_PKTINFO` ancillary cmsg on an IPv4 socket so that
/// `recvmsg` reports the local receive address + interface index (the cmsg type
/// [`crate::parse_pktinfo_v4`] looks for is always `IP_PKTINFO`).
///
/// Gated on the `has_ip_pktinfo` capability cfg (see `build.rs`): Linux/Android,
/// Apple, and NetBSD. FreeBSD/OpenBSD/DragonFly use `IP_RECVDSTADDR`/`IP_RECVIF`
/// and are NOT supported by this parser, so this is a no-op there;
/// `recv_with_meta` then degrades to an UNSPECIFIED local address and the driver
/// falls back to its content-hash self-loopback matching.
///
/// rustix has no setter for this option (see the module docs), so it routes
/// through the single `libc::setsockopt` chokepoint. The *enable* optname
/// differs by platform: NetBSD spells it `IP_RECVPKTINFO`; the others use
/// `IP_PKTINFO`.
#[cfg(has_ip_pktinfo)]
pub(crate) fn set_recv_pktinfo_v4(sock: &UdpSocket) -> std::io::Result<()> {
  #[cfg(target_os = "netbsd")]
  let optname = libc::IP_RECVPKTINFO;
  #[cfg(not(target_os = "netbsd"))]
  let optname = libc::IP_PKTINFO;
  set_bool_sockopt(sock, libc::IPPROTO_IP, optname)
}

/// Fallback where IPv4 `IP_PKTINFO` isn't available (FreeBSD/OpenBSD/DragonFly):
/// no-op. See the supported-target variant above.
#[cfg(not(has_ip_pktinfo))]
pub(crate) fn set_recv_pktinfo_v4(_sock: &UdpSocket) -> std::io::Result<()> {
  Ok(())
}

/// Enable delivery of `IPV6_RECVPKTINFO` ancillary data on an IPv6 socket so
/// that `recvmsg` reports the local receive address + interface index.
///
/// rustix has no setter for this option (see the module docs), so it routes
/// through the single `libc::setsockopt` chokepoint. Unconditional on Unix:
/// every supported Unix target defines `IPV6_RECVPKTINFO` (the matching
/// `IPV6_PKTINFO` cmsg type, used by `multicast::parse_pktinfo_v6`, is gated on
/// `has_ipv6_pktinfo`). Keeping this unconditional also keeps the
/// `set_int_sockopt` chokepoint reachable on every Unix target.
pub(crate) fn set_recv_pktinfo_v6(sock: &UdpSocket) -> std::io::Result<()> {
  set_bool_sockopt(sock, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
}

/// Enable delivery of a kernel receive-timestamp ancillary cmsg on a socket so
/// that `recvmsg` reports when the datagram was timestamped by the OS.
///
/// The sockopt and resulting cmsg differ by platform:
/// - Linux/Android: `SO_TIMESTAMPNS` → an `SCM_TIMESTAMPNS` cmsg carrying a
///   `struct timespec` (nanosecond resolution).
/// - Apple (macos/ios/tvos/watchos) + the BSDs (freebsd/openbsd/netbsd/
///   dragonfly): `SO_TIMESTAMP` → an `SCM_TIMESTAMP` cmsg carrying a
///   `struct timeval` (microsecond resolution).
/// - Other Unix targets: no-op; `recv_with_meta` then reports `rx_time = None`.
///
/// rustix has no setter for these options (see the module docs), so it routes
/// through the single `libc::setsockopt` chokepoint. Both optnames live at
/// level `SOL_SOCKET`. Gated on the `has_recv_timestamp` capability cfg (all
/// supported Unix); `recv_timestamp_ns` selects the nanosecond variant.
#[cfg(has_recv_timestamp)]
pub(crate) fn set_recv_timestamp(sock: &UdpSocket) -> std::io::Result<()> {
  #[cfg(recv_timestamp_ns)]
  let optname = libc::SO_TIMESTAMPNS;
  #[cfg(not(recv_timestamp_ns))]
  let optname = libc::SO_TIMESTAMP;
  set_bool_sockopt(sock, libc::SOL_SOCKET, optname)
}

/// Fallback where no receive-timestamp cmsg is wired up: no-op. See the
/// supported-target variant above.
#[cfg(not(has_recv_timestamp))]
pub(crate) fn set_recv_timestamp(_sock: &UdpSocket) -> std::io::Result<()> {
  Ok(())
}

/// Enable delivery of the inbound IPv4 TTL (`IP_RECVTTL`) so `recvmsg` reports
/// it as an `IP_TTL` cmsg — needed for the RFC 6762 §11 on-link check.
/// Gated on the `has_recv_hoplimit` capability cfg (see `build.rs`):
/// Linux/Android, Apple, FreeBSD, DragonFly. `libc` does NOT define `IP_RECVTTL`
/// on the netbsdlike targets (OpenBSD/NetBSD), so they fall through to the no-op
/// below — `hop_limit` stays `None` and the §11 check degrades to pass-through.
#[cfg(has_recv_hoplimit)]
pub(crate) fn set_recv_ttl_v4(sock: &UdpSocket) -> std::io::Result<()> {
  set_bool_sockopt(sock, libc::IPPROTO_IP, libc::IP_RECVTTL)
}

/// Fallback where `IP_RECVTTL` isn't available (OpenBSD/NetBSD): no-op.
#[cfg(not(has_recv_hoplimit))]
pub(crate) fn set_recv_ttl_v4(_sock: &UdpSocket) -> std::io::Result<()> {
  Ok(())
}

/// Enable delivery of the inbound IPv6 Hop Limit (`IPV6_RECVHOPLIMIT`) so
/// `recvmsg` reports it as an `IPV6_HOPLIMIT` cmsg. Same
/// `has_recv_hoplimit` gate as `set_recv_ttl_v4`: `libc` lacks
/// `IPV6_RECVHOPLIMIT` on OpenBSD/NetBSD, so this is a no-op there.
#[cfg(has_recv_hoplimit)]
pub(crate) fn set_recv_hoplimit_v6(sock: &UdpSocket) -> std::io::Result<()> {
  set_bool_sockopt(sock, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
}

/// Fallback where `IPV6_RECVHOPLIMIT` isn't available (OpenBSD/NetBSD): no-op.
#[cfg(not(has_recv_hoplimit))]
pub(crate) fn set_recv_hoplimit_v6(_sock: &UdpSocket) -> std::io::Result<()> {
  Ok(())
}

/// The SINGLE `libc::setsockopt` call site in the crate: set an arbitrary
/// `c_int`-valued sockopt. Every non-rustix option in this module funnels
/// through here — the boolean receive-cmsg enablers via the `set_bool_sockopt`
/// wrapper just below (`set_recv_pktinfo_v4/v6`, `set_recv_timestamp`,
/// `set_recv_ttl_v4`, `set_recv_hoplimit_v6`), and the `IPV6_MULTICAST_HOPS`
/// rustix workaround in `set_multicast_hops_v6` directly — so all the
/// `unsafe` ffi for these options lives in one audited place. Always
/// compiled — `set_recv_pktinfo_v6` is unconditional, so this is reached on
/// every Unix target. Its read-back sibling is `get_int_sockopt`, further
/// down.
///
/// Valid ONLY for genuinely `int`-sized options: `optlen` below is hardcoded
/// to `size_of::<c_int>()`, so do not route an option through here without
/// first confirming it is `int`-sized on every target this crate supports —
/// classic BSD sockets documentation specifies `IP_MULTICAST_TTL` /
/// `IP_MULTICAST_LOOP` as `u_char`, and other BSDs are commonly strict about
/// rejecting anything but `sizeof(u_char)` for them. (Direct `setsockopt`
/// probing on one macOS host found it actually accepts either an
/// exactly-1-byte or an at-least-4-byte value for both, rejecting 2/3 bytes —
/// so a naive `c_int` would not silently corrupt anything there specifically,
/// but that is one host's observed leniency, not a portable guarantee across
/// every BSD this crate targets.) `set_multicast_ttl_v4`/`set_multicast_loop_v4`
/// stay on the rustix path for exactly this reason — don't move them here
/// without re-verifying the accepted width on every target.
fn set_int_sockopt(
  sock: &UdpSocket,
  level: libc::c_int,
  optname: libc::c_int,
  value: libc::c_int,
) -> std::io::Result<()> {
  // SAFETY: `sock` owns a valid UDP fd for the duration of the call; `value`
  // is a live `c_int` parameter, so a pointer to it paired with a matching
  // `optlen` is sound, and we read no memory back. setsockopt does not retain
  // the pointer past the call.
  #[allow(unsafe_code)]
  let rc = unsafe {
    libc::setsockopt(
      sock.as_raw_fd(),
      level,
      optname,
      core::ptr::addr_of!(value).cast(),
      core::mem::size_of::<libc::c_int>() as libc::socklen_t,
    )
  };
  if rc != 0 {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

/// `setsockopt(level, optname, 1)`: enable a boolean-valued receive-cmsg
/// option. Thin, `unsafe`-free wrapper around the `set_int_sockopt` chokepoint
/// above for the common "just turn this on" case; every receive-cmsg setter
/// (`set_recv_pktinfo_v4/v6`, `set_recv_timestamp`, `set_recv_ttl_v4`,
/// `set_recv_hoplimit_v6`) goes through this, not `set_int_sockopt` directly.
fn set_bool_sockopt(
  sock: &UdpSocket,
  level: libc::c_int,
  optname: libc::c_int,
) -> std::io::Result<()> {
  set_int_sockopt(sock, level, optname, 1)
}

/// The SINGLE `libc::getsockopt` call site in the crate: read back an
/// arbitrary `c_int`-valued sockopt. Its only caller is
/// `get_multicast_hops_v6` just below, which exists solely so
/// `crate::multicast::try_bind_v6` can confirm `set_multicast_hops_v6`
/// actually took — see that function's doc for the RFC 6762 §11
/// justification and the Linux wrong-level history that makes a read-back
/// necessary for this ONE option. No other sockopt in this module is read
/// back: every other rustix-covered setter has no comparable known defect,
/// and the other `set_int_sockopt` consumers (the receive-cmsg enablers) are
/// already deliberately best-effort, so confirming them would add a syscall
/// without adding safety.
///
/// Valid ONLY for genuinely `int`-sized options — the same caveat as
/// `set_int_sockopt` above applies to the read side. A `getsockopt` that
/// writes back fewer bytes than `size_of::<c_int>()` is treated as failure
/// (`Err`), never read as a partially valid value.
fn get_int_sockopt(
  sock: &UdpSocket,
  level: libc::c_int,
  optname: libc::c_int,
) -> std::io::Result<libc::c_int> {
  let mut value: libc::c_int = 0;
  let mut len: libc::socklen_t = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
  // SAFETY: `sock` owns a valid UDP fd for the duration of the call; `value`
  // and `len` are live locals sized exactly for a `c_int`, so pointers to
  // them are sound. `getsockopt` writes at most `len` bytes into `value` and
  // overwrites `len` with the size it actually wrote, both confined to the
  // buffer we handed it, and it retains neither pointer past the call.
  #[allow(unsafe_code)]
  let rc = unsafe {
    libc::getsockopt(
      sock.as_raw_fd(),
      level,
      optname,
      core::ptr::addr_of_mut!(value).cast(),
      core::ptr::addr_of_mut!(len),
    )
  };
  if rc != 0 {
    return Err(std::io::Error::last_os_error());
  }
  if len != core::mem::size_of::<libc::c_int>() as libc::socklen_t {
    // A short write is not a partially-valid c_int — reject it outright
    // rather than reading uninitialized/stale bytes out of `value`.
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "getsockopt returned a shorter value than a c_int",
    ));
  }
  Ok(value)
}

/// Read back the kernel's current `IPV6_MULTICAST_HOPS` value through the
/// `get_int_sockopt` chokepoint above. The ONLY caller is
/// `crate::multicast::try_bind_v6`, immediately after `set_multicast_hops_v6`,
/// to confirm the value it just asked for is the value the kernel now holds.
pub(crate) fn get_multicast_hops_v6(sock: &UdpSocket) -> std::io::Result<i32> {
  get_int_sockopt(sock, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS)
}

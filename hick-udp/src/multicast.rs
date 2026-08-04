//! Multicast socket configuration helpers + RecvMeta + cmsg parsing (stubbed).

use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
  time::SystemTime,
};

use crate::{
  constants::{MDNS_IPV4_GROUP, MDNS_IPV6_GROUP, MDNS_PORT},
  error::{BindError, JoinError},
  onlink::{DestinationWitness, IfaceWitness},
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

/// How the link layer delivered a datagram, where the receive path can tell.
///
/// This is the coarse stand-in for an IP header destination on the receive
/// squares that witness none — see [`RecvMeta::destination_witness`]. It names the
/// DELIVERY, never the address: [`Self::Multicast`] does not say which group,
/// which is why RFC 6762 §11's group arm can be over-approximated by it and its
/// unicast arm cannot be replaced by it.
///
/// Not `#[non_exhaustive]` on purpose. Every value is a decision in a trust
/// boundary, so a fourth class must break every `match` that admits or refuses
/// on this type rather than fall into a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkDelivery {
  /// Addressed to this host rather than to a group or a broadcast address.
  ///
  /// It does NOT say to which of this host's addresses; where the IP header
  /// destination itself was witnessed, use that instead.
  Unicast,
  /// Delivered to a multicast group — but not to WHICH group. A datagram
  /// addressed to `224.0.0.251` and one addressed to LLMNR's `224.0.0.252` are
  /// the same value here.
  Multicast,
  /// Delivered as a link-layer broadcast: `255.255.255.255`, a subnet-directed
  /// broadcast, or whatever address the interface was configured to answer
  /// broadcasts on.
  ///
  /// Definitive NEGATIVE evidence, which is what makes it worth carrying: the
  /// delivery was neither unicast to an address this host holds nor multicast to
  /// an mDNS group, so RFC 6762 §11 offers it no arm at all — without ever
  /// naming the address.
  Broadcast,
}

/// Metadata about a received datagram.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
  len: usize,
  peer: SocketAddr,
  local_ip: IpAddr,
  destination: DestinationWitness,
  iface: IfaceWitness,
  rx_time: Option<SystemTime>,
  hop_limit: Option<u8>,
  delivery: Option<LinkDelivery>,
}
impl RecvMeta {
  /// `destination` is a [`DestinationWitness`] rather than a second `IpAddr` so no call
  /// site can pass it positionally in place of `local_ip`: the two carry
  /// different addresses on Unix IPv4 and the compiler, not review, is what
  /// keeps them apart. See [`RecvMeta::destination_witness`].
  ///
  /// Both witnesses are TYPED because a receive path is the only thing that
  /// knows what an absence means: whether the platform never reports the fact,
  /// whether the kernel declined to emit it for this datagram, or whether our own
  /// control buffer was too small. See [`crate::onlink`] for what each one
  /// decides.
  pub(crate) const fn new(
    len: usize,
    peer: SocketAddr,
    local_ip: IpAddr,
    destination: DestinationWitness,
    iface: IfaceWitness,
    rx_time: Option<SystemTime>,
  ) -> Self {
    Self {
      len,
      peer,
      local_ip,
      destination,
      iface,
      rx_time,
      hop_limit: None,
      delivery: None,
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
  /// header; for that, and only for that, use
  /// [`RecvMeta::destination_witness`].
  #[inline(always)]
  pub const fn local_ip(&self) -> IpAddr {
    self.local_ip
  }

  /// What this receive WITNESSED about the datagram's IP header **destination**.
  ///
  /// Distinct from [`RecvMeta::local_ip`] on exactly one square: Unix IPv4,
  /// where PKTINFO carries both `ipi_spec_dst` (the interface address, returned
  /// by `local_ip`) and `ipi_addr` (the header destination, carried here). For
  /// IPv6, and on Windows, PKTINFO carries only the header destination and the
  /// two accessors agree.
  ///
  /// A [`DestinationWitness`] and not an `Option<IpAddr>`, because absence is three
  /// different facts that RFC 6762 §11 decides differently: a platform that
  /// never reports one ([`DestinationWitness::Blind`] — Unix IPv4 without `IP_PKTINFO`, on
  /// FreeBSD/DragonFly/OpenBSD/NetBSD), a kernel that declined to emit the cmsg
  /// for THIS datagram ([`DestinationWitness::Declined`]), and a control buffer of ours
  /// that was too small ([`DestinationWitness::Lost`]). Where none is witnessed the coarser
  /// [`RecvMeta::delivery`] is what is left to decide on.
  #[inline(always)]
  pub const fn destination_witness(&self) -> DestinationWitness {
    self.destination
  }

  /// What this receive WITNESSED about the interface the datagram arrived on.
  ///
  /// Hand this to [`admits_ingress`](crate::onlink::admits_ingress) rather than
  /// an index: [`IfaceWitness`] carries what a MISSING index means, which is the
  /// receive path's fact and not the platform's.
  #[inline(always)]
  pub const fn iface_witness(&self) -> IfaceWitness {
    self.iface
  }

  /// The receiving interface index, or `0` where none was witnessed.
  ///
  /// **A DIAGNOSTIC.** It flattens the three absences [`IfaceWitness`] keeps
  /// apart, so it is for traces, logs and test fixtures — never for an admission
  /// decision. [`RecvMeta::iface_witness`] is what the trust boundary reads, and
  /// [`admits_ingress`](crate::onlink::admits_ingress) will not accept this
  /// value in its place.
  #[inline(always)]
  pub const fn interface_index(&self) -> u32 {
    match self.iface.witnessed_index() {
      Some(idx) => idx.get(),
      None => 0,
    }
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
  /// This is a DIAGNOSTIC, not a test. RFC 6762 §11 states its receive test
  /// exhaustively and both ways are about the destination address; the RFC's one
  /// receive-side TTL sentence explains why responses SHOULD be SENT at 255, for
  /// the benefit of 2004-draft queriers, and describes those implementations in
  /// the past tense. Nothing in this workspace refuses or admits a datagram on
  /// this value — see [`crate::onlink`]. Outbound TTL 255 is unaffected.
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

  /// How the kernel says the link delivered this datagram — decoded from
  /// `MSG_MCAST`/`MSG_BCAST` in the `msg_flags` `recvmsg` returns, on targets
  /// that bind them.
  ///
  /// `None` means neither flag exists here — **not**
  /// [`LinkDelivery::Unicast`]. Of the targets this crate supports, only OpenBSD
  /// and NetBSD bind them (`libc`'s `src/unix/bsd/netbsdlike/mod.rs:576-577`).
  ///
  /// It is coarse on purpose and it exists because on OpenBSD/NetBSD IPv4 it is
  /// the only destination evidence available at all —
  /// [`RecvMeta::destination_witness`] is [`DestinationWitness::Blind`] on every datagram
  /// there — and RFC 6762 §11 picks its local-link test by destination.
  ///
  /// The three values are worth very different amounts to that test.
  /// [`LinkDelivery::Multicast`] over-approximates §11's group arm: it admits
  /// LLMNR's group as readily as ours, which is a real residual and one no flag
  /// can close, since "which group" is not a bit.
  /// [`LinkDelivery::Broadcast`] is the opposite — definitive NEGATIVE evidence,
  /// exact rather than approximate, because §11 offers a broadcast no arm at
  /// all. [`LinkDelivery::Unicast`] says only "neither of those", so the source
  /// arm still decides.
  #[inline(always)]
  pub const fn delivery(&self) -> Option<LinkDelivery> {
    self.delivery
  }

  /// Overwrite the multicast-delivery flag, threaded in by `recv_with_meta`
  /// from `msghdr::msg_flags`. Unlike the cmsg-derived fields this one survives
  /// `MSG_CTRUNC`: it rides on the header, not on the control buffer.
  #[cfg(unix)]
  #[inline(always)]
  pub(crate) fn set_delivery(&mut self, delivery: Option<LinkDelivery>) {
    self.delivery = delivery;
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
  // Best-effort: enabling IP_RECVTTL surfaces the inbound TTL as a diagnostic on
  // `RecvMeta::hop_limit`. No admission decision reads it — §11's receive test
  // is about the destination address — so a missing value costs nothing.
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
  // Best-effort: enabling IPV6_RECVHOPLIMIT surfaces the inbound hop limit as a
  // diagnostic on `RecvMeta::hop_limit`. No admission decision reads it — §11's
  // receive test is about the destination address — so a missing value costs
  // nothing.
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
      //
      // `control_truncated: false` is not an assumption about the caller's
      // buffer — it is what this function can honestly say. `MSG_CTRUNC` rides
      // on the message header and never on the bytes handed here, so a parser
      // defined over a byte slice cannot observe it; `recv_with_meta` reads the
      // flag and returns BEFORE calling this. An `ipi_ifindex` of `0` inside a
      // present cmsg is therefore a kernel that named no interface, which is
      // `Declined` and not `Lost`.
      return Ok(RecvMeta::new(
        len,
        peer,
        local_ip,
        DestinationWitness::Witnessed(destination),
        IfaceWitness::from_reporting_path(iface, false),
        None,
      ));
    }
  }
  Err(ParseRecvMetaError::MissingPktinfo)
}

// ============================================================================
// BSD IPv4 receive metadata — PARSED BUT NOT YET TRUSTED.
//
// The two shapes below recover for FreeBSD/DragonFly/OpenBSD/NetBSD what
// `parse_pktinfo_v4` recovers for Linux/Apple. Neither is reachable from
// `recv_with_meta`, neither has a matching `setsockopt` enabler, and neither
// changes `reports_rx_interface_v4()`, which still answers `false` on all four
// targets. They are landed inert on purpose: promoting them flips a receiver's
// ingress rule for a witness-less datagram from "admit" to "drop", so a parse
// that is quietly wrong would produce IPv4 deafness rather than a visible
// failure. `build.rs` lists, at the emit site for the two `ipv4_rx_*` cfgs,
// exactly what a real host of each target has to show before that flip.
//
// What is verifiable here, and is: the byte layouts, against `libc`'s own
// structs (the `const _` assertions below, checked by any cross-compile) and
// against synthesized cmsg buffers (the unit tests, which run on every host).
// What is not verifiable here: that a kernel delivers these cmsgs at all.
// ============================================================================

/// `offsetof(struct sockaddr_dl, sdl_index)`. Pinned against `libc` by the
/// assertion beside `parse_dstaddr_recvif_v4`.
#[cfg(all(unix, any(ipv4_rx_dstaddr_recvif, test)))]
const SDL_INDEX_OFFSET: usize = 2;

/// `offsetof(struct sockaddr_dl, sdl_data[0])` — the fixed prefix every
/// `sockaddr_dl` carries, and the shortest `IP_RECVIF` payload the BSD kernels
/// emit (their "no receive interface" dummy is exactly this long).
#[cfg(all(unix, any(ipv4_rx_dstaddr_recvif, test)))]
const SOCKADDR_DL_FIXED_LEN: usize = 8;

/// Decode an `IP_RECVDSTADDR` payload: a bare `struct in_addr`, which the
/// FreeBSD, DragonFly, OpenBSD and NetBSD kernels all fill with `ip->ip_dst` —
/// the IP header destination, i.e. the group for a multicast arrival. There is
/// no `ipi_spec_dst` twin in this cmsg, so it cannot report the receiving
/// interface's own address.
///
/// `s_addr` is in network byte order and `Ipv4Addr::from([u8; 4])` reads
/// big-endian octets, so the four bytes transfer verbatim. `None` for a payload
/// shorter than an `in_addr`.
#[cfg(all(unix, any(ipv4_rx_dstaddr_recvif, test)))]
fn decode_recvdstaddr(data: &[u8]) -> Option<Ipv4Addr> {
  data.first_chunk::<4>().map(|b| Ipv4Addr::from(*b))
}

/// Decode the receiving interface index out of an `IP_RECVIF` payload: a
/// `struct sockaddr_dl`, of which only `sdl_index` — a HOST-order `u_short` at
/// `SDL_INDEX_OFFSET` — is read.
///
/// The payload is variable-length. The kernels send `sdl_len` bytes, which is
/// the interface's own link-layer `sockaddr_dl` copied verbatim (FreeBSD's
/// `ip_savecontrol` does `bcopy(sdp, sdl2, sdp->sdl_len)`), so it runs from
/// `SOCKADDR_DL_FIXED_LEN` up to the full struct depending on how long that
/// interface's name and hardware address are. Requiring the full
/// `size_of::<sockaddr_dl>()` would therefore reject legitimate payloads, and
/// the three targets do not even agree on that size; only the fixed prefix may
/// be relied on. Anything shorter than the prefix is not a `sockaddr_dl` at
/// all: `None`.
///
/// `Some(0)` is a real answer, not an error — it is the kernels' own dummy for
/// "this datagram has no receive interface" (`sdl_index = 0` on the `makedummy`
/// path) and carries the same meaning as the zero index a target without this
/// cmsg reports. `sdl_family` is not checked: the cmsg level and type already
/// identify the producer as the kernel's `IP_RECVIF` writer, and `AF_LINK` is
/// the only family it ever sets.
#[cfg(all(unix, any(ipv4_rx_dstaddr_recvif, test)))]
fn decode_recvif_index(data: &[u8]) -> Option<u32> {
  if data.len() < SOCKADDR_DL_FIXED_LEN {
    return None;
  }
  let index_bytes = data
    .get(SDL_INDEX_OFFSET..)
    .and_then(|rest| rest.first_chunk::<2>())?;
  Some(u32::from(u16::from_ne_bytes(*index_bytes)))
}

/// Walk an ancillary buffer for the `IPPROTO_IP` destination-address and
/// receive-interface cmsgs, returning whichever of the two it recovers.
///
/// The two cmsg types are parameters rather than direct `libc::IP_RECVDSTADDR`
/// / `libc::IP_RECVIF` reads so that this walk — including the requirement to
/// skip unrelated cmsgs and to keep looking after one of the pair — is covered
/// by unit tests on every host, not only on a BSD nobody can run here. The one
/// thing the parameters hide is which numbers the target uses, and that is the
/// part `libc` answers: `IP_RECVIF` is 20 on FreeBSD/DragonFly/NetBSD but 30 on
/// OpenBSD.
///
/// A malformed cmsg header ends the walk with whatever was recovered before it,
/// mirroring the other parsers: the datagram has already been consumed, so a
/// bad control buffer must not cost the caller its data.
#[cfg(all(unix, any(ipv4_rx_dstaddr_recvif, test)))]
fn scan_dstaddr_recvif(
  cmsgs: &[u8],
  dstaddr_ty: libc::c_int,
  recvif_ty: libc::c_int,
) -> (Option<Ipv4Addr>, Option<u32>) {
  let mut destination = None;
  let mut iface = None;
  for cmsg in CmsgIter::new(cmsgs) {
    let Ok(cmsg) = cmsg else { break };
    if cmsg.level != libc::IPPROTO_IP {
      continue;
    }
    if cmsg.ty == dstaddr_ty && destination.is_none() {
      destination = decode_recvdstaddr(cmsg.data);
    } else if cmsg.ty == recvif_ty && iface.is_none() {
      iface = decode_recvif_index(cmsg.data);
    }
  }
  (destination, iface)
}

/// Parse the FreeBSD/DragonFly/OpenBSD IPv4 receive metadata — the
/// `IP_RECVDSTADDR` + `IP_RECVIF` cmsg pair — into a [`RecvMeta`].
///
/// The IPv4 counterpart of `parse_pktinfo_v4` on the targets that define no
/// `IP_PKTINFO`. **Not wired into [`recv_with_meta`]**, which still degrades on
/// these targets, and does not affect [`reports_rx_interface_v4`]; see the
/// comment block above this function and `build.rs` for the evidence a
/// promotion requires.
///
/// [`RecvMeta::local_ip`] is UNSPECIFIED, and that is the honest answer rather
/// than a placeholder: neither cmsg carries an `ipi_spec_dst` equivalent, so the
/// receiving interface's own unicast address is simply absent from the ancillary
/// data on these platforms. Callers already read an unspecified local address as
/// "fall back to content-hash self-detection".
///
/// Returns [`ParseRecvMetaError::MissingPktinfo`] only when NEITHER cmsg was
/// present. Recovering one without the other is reported, not discarded: the
/// destination and the interface answer different RFC 6762 §11 questions, and a
/// caller that got one of them is better off than a caller that got neither.
#[cfg(ipv4_rx_dstaddr_recvif)]
pub fn parse_dstaddr_recvif_v4(
  cmsgs: &[u8],
  len: usize,
  peer: SocketAddr,
) -> Result<RecvMeta, ParseRecvMetaError> {
  let (destination, iface) = scan_dstaddr_recvif(cmsgs, libc::IP_RECVDSTADDR, libc::IP_RECVIF);
  if destination.is_none() && iface.is_none() {
    return Err(ParseRecvMetaError::MissingPktinfo);
  }
  // No timestamp available here; `recv_with_meta` overwrites rx_time after
  // parsing the SCM_TIMESTAMP* cmsg from the same control buffer.
  Ok(RecvMeta::new(
    len,
    peer,
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    // The two cmsgs are allocated separately by `ip_savecontrol`, so one can be
    // present while the other is not — which is the whole reason the two
    // witnesses are separate values rather than one. See `parse_pktinfo_v4` for
    // why `control_truncated` is `false` here.
    DestinationWitness::from_reporting_path(destination.map(IpAddr::V4), false),
    IfaceWitness::from_reporting_path(iface.unwrap_or(0), false),
    None,
  ))
}

// The `sockaddr_dl` prefix `decode_recvif_index` reads, pinned against `libc`'s
// own struct for whichever BSD is being compiled. The three targets disagree on
// `size_of::<sockaddr_dl>()` — FreeBSD's trailing `sdl_data` is 46 bytes,
// OpenBSD's 24, and DragonFly follows a 12-byte `sdl_data` with `sdl_rcf` and
// `sdl_route` — so the OFFSET of the index, not the size of the struct, is what
// this parse may rely on. A cross-compile for any of the three checks it.
#[cfg(ipv4_rx_dstaddr_recvif)]
const _: () = assert!(core::mem::offset_of!(libc::sockaddr_dl, sdl_index) == SDL_INDEX_OFFSET);
#[cfg(ipv4_rx_dstaddr_recvif)]
const _: () = assert!(core::mem::offset_of!(libc::sockaddr_dl, sdl_data) == SOCKADDR_DL_FIXED_LEN);
#[cfg(ipv4_rx_dstaddr_recvif)]
const _: () = assert!(core::mem::size_of::<libc::in_addr>() == 4);

/// `sizeof(struct in_pktinfo)` on NetBSD, whose layout is `ipi_addr` (4) then
/// `ipi_ifindex` (4) — eight bytes, against the twelve of the Linux/Apple
/// struct. Pinned against `libc` by the assertion beside
/// `parse_netbsd_pktinfo_v4`.
#[cfg(all(unix, any(ipv4_rx_netbsd_pktinfo, test)))]
const NETBSD_IN_PKTINFO_LEN: usize = 8;

/// `offsetof(struct in_pktinfo, ipi_ifindex)` on NetBSD.
#[cfg(all(unix, any(ipv4_rx_netbsd_pktinfo, test)))]
const NETBSD_IPI_IFINDEX_OFFSET: usize = 4;

/// Decode NetBSD's `struct in_pktinfo`: `ipi_addr` (a network-order
/// `struct in_addr`, which `ip_savecontrol` fills with `ip->ip_dst` — the IP
/// header destination) followed by a host-order `unsigned int ipi_ifindex`.
///
/// The length test is EXACT, not a minimum, and that is the whole point of this
/// function existing separately from `parse_pktinfo_v4`. The Linux/Apple
/// `in_pktinfo` is twelve bytes in a different order (`ipi_ifindex`,
/// `ipi_spec_dst`, `ipi_addr`); accepting `>= 8` would decode ITS interface
/// index as this layout's destination address and its `ipi_spec_dst` as this
/// layout's index, silently, with no length or value out of range to give it
/// away. A cmsg payload is exactly `sizeof(struct in_pktinfo)` long — the
/// kernel passes that size to `sbcreatecontrol` and `CmsgIter` hands back
/// `cmsg_len` minus the aligned header — so nothing legitimate is rejected.
#[cfg(all(unix, any(ipv4_rx_netbsd_pktinfo, test)))]
fn decode_netbsd_pktinfo(data: &[u8]) -> Option<(Ipv4Addr, u32)> {
  if data.len() != NETBSD_IN_PKTINFO_LEN {
    return None;
  }
  let addr_bytes = data.first_chunk::<4>()?;
  let index_bytes = data
    .get(NETBSD_IPI_IFINDEX_OFFSET..)
    .and_then(|rest| rest.first_chunk::<4>())?;
  Some((
    Ipv4Addr::from(*addr_bytes),
    u32::from_ne_bytes(*index_bytes),
  ))
}

/// Walk an ancillary buffer for NetBSD's `IP_PKTINFO` cmsg.
///
/// The cmsg type is a parameter for the same reason as in
/// `scan_dstaddr_recvif`: it keeps the walk testable on every host. Note that
/// the type delivered is `IP_PKTINFO` (25) while the sockopt that ENABLES it is
/// `IP_RECVPKTINFO` (26) — two different numbers on NetBSD, unlike the single
/// `IP_PKTINFO` Linux uses for both.
#[cfg(all(unix, any(ipv4_rx_netbsd_pktinfo, test)))]
fn scan_netbsd_pktinfo(cmsgs: &[u8], pktinfo_ty: libc::c_int) -> Option<(Ipv4Addr, u32)> {
  for cmsg in CmsgIter::new(cmsgs) {
    let Ok(cmsg) = cmsg else { break };
    if cmsg.level == libc::IPPROTO_IP && cmsg.ty == pktinfo_ty {
      return decode_netbsd_pktinfo(cmsg.data);
    }
  }
  None
}

/// Parse NetBSD's IPv4 `IP_PKTINFO` cmsg into a [`RecvMeta`].
///
/// NetBSD is the one BSD here that does define `IP_PKTINFO`, but its
/// `in_pktinfo` is an 8-byte `ipi_addr`/`ipi_ifindex` pair rather than the
/// 12-byte Linux/Apple struct, so `parse_pktinfo_v4` cannot serve it — it
/// would reject the payload as truncated. **Not wired into [`recv_with_meta`]**
/// and does not affect [`reports_rx_interface_v4`]; see the comment block above
/// `parse_dstaddr_recvif_v4` and `build.rs`.
///
/// [`RecvMeta::local_ip`] is UNSPECIFIED for the same reason as in the
/// `IP_RECVDSTADDR` parser: NetBSD's `in_pktinfo` has no `ipi_spec_dst` field,
/// so the receiving interface's own address is not in the ancillary data.
#[cfg(ipv4_rx_netbsd_pktinfo)]
pub fn parse_netbsd_pktinfo_v4(
  cmsgs: &[u8],
  len: usize,
  peer: SocketAddr,
) -> Result<RecvMeta, ParseRecvMetaError> {
  let (destination, iface) =
    scan_netbsd_pktinfo(cmsgs, libc::IP_PKTINFO).ok_or(ParseRecvMetaError::MissingPktinfo)?;
  // No timestamp available here; `recv_with_meta` overwrites rx_time after
  // parsing the SCM_TIMESTAMP* cmsg from the same control buffer.
  Ok(RecvMeta::new(
    len,
    peer,
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    DestinationWitness::Witnessed(IpAddr::V4(destination)),
    IfaceWitness::from_reporting_path(iface, false),
    None,
  ))
}

// NetBSD's `in_pktinfo`, pinned against `libc`. If NetBSD ever grew the struct
// to match Linux's, the exact-length test in `decode_netbsd_pktinfo` would
// start rejecting every payload — these assertions turn that into a compile
// failure on the next cross-compile instead.
#[cfg(ipv4_rx_netbsd_pktinfo)]
const _: () = assert!(core::mem::size_of::<libc::in_pktinfo>() == NETBSD_IN_PKTINFO_LEN);
#[cfg(ipv4_rx_netbsd_pktinfo)]
const _: () = assert!(core::mem::offset_of!(libc::in_pktinfo, ipi_addr) == 0);
#[cfg(ipv4_rx_netbsd_pktinfo)]
const _: () =
  assert!(core::mem::offset_of!(libc::in_pktinfo, ipi_ifindex) == NETBSD_IPI_IFINDEX_OFFSET);

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
        DestinationWitness::Witnessed(local_ip),
        IfaceWitness::from_reporting_path(iface, false),
        None,
      ));
    }
  }
  Err(ParseRecvMetaError::MissingPktinfo)
}

/// Control buffer for `recvmsg`: 512 bytes forced to 8-byte alignment via
/// `#[repr(align(8))]` so its base satisfies the kernel's `cmsghdr` alignment
/// requirement.
///
/// # Why 512 and not 256
///
/// `MSG_CTRUNC` means the kernel had ancillary data this buffer could not hold,
/// which is a defect on THIS side of the boundary — and
/// [`DestinationWitness::Lost`](crate::onlink::DestinationWitness::Lost) refuses the datagram on it.
/// A refusal that our own sizing can provoke would be a self-inflicted outage,
/// so the buffer is sized to make the flag unreachable rather than merely
/// unlikely.
///
/// Every cmsg this crate enables, at the widest layout any supported target
/// uses, with `CMSG_SPACE`'s per-message header and padding: `IPV6_PKTINFO`
/// (20-byte payload), `IP_RECVDSTADDR` + `IP_RECVIF` (4 bytes and a padded
/// `sockaddr_dl`), `SCM_TIMESTAMPNS` (16), `IP_TTL`/`IPV6_HOPLIMIT` (4). The
/// worst case measures about 152 bytes. 512 leaves better than three times that
/// for a kernel that attaches something this crate did not ask for.
#[cfg(unix)]
#[repr(align(8))]
struct CmsgBuf([u8; 512]);

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
  // 8-aligned control buffer, sized so `MSG_CTRUNC` cannot be reached from the
  // wire — see `CmsgBuf`.
  let mut control = CmsgBuf([0u8; 512]);

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
  let delivery = msg_link_delivery(msg.msg_flags);

  // Whether THIS path witnesses a destination and a receive interface for this
  // family at all — a compile-time capability, read once here rather than
  // inferred per datagram from a missing cmsg. The two go together because both
  // ride on the same PKTINFO cmsg; the BSD `IP_RECVDSTADDR` + `IP_RECVIF` pair
  // that would separate them is not wired into this path.
  //
  // Read through the same two functions the crate publishes as its capability
  // answer, so a target can never be blind to a driver and witnessing to the
  // parser, or the reverse. (`cfg!(windows)` inside them is false here: this
  // whole function is `#[cfg(unix)]`.)
  let witnesses_pktinfo = if is_v4 {
    reports_rx_interface_v4()
  } else {
    reports_rx_interface_v6()
  };

  // Helper: a RecvMeta carrying the real peer + length but an UNSPECIFIED local
  // address and NO witnessed destination, used when PKTINFO is absent. The
  // datagram itself was already consumed by `recvmsg`, so we MUST NOT drop it
  // just because the ancillary metadata is missing — the caller falls back to
  // its own self-loopback detection (content-hash ring) when local_ip is
  // unspecified. This keeps a missing/failed PKTINFO sockopt from silently
  // black-holing all inbound traffic.
  //
  // `witness_absent` is what the two absences are spelled with, and the caller
  // supplies which one: `control_truncated` for `MSG_CTRUNC` — our buffer was
  // too small, which is this side's bug and REFUSES — and `false` for a kernel
  // that simply emitted nothing, which DEGRADES. A path that witnesses nothing
  // by construction reports `Blind` and never either of them, because a
  // capability is not a per-datagram failure.
  let witness_absent = |control_truncated: bool| {
    let local_ip = if is_v4 {
      std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
      std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    let (destination, iface) = if witnesses_pktinfo {
      (
        DestinationWitness::from_reporting_path(None, control_truncated),
        IfaceWitness::from_reporting_path(0, control_truncated),
      )
    } else {
      (DestinationWitness::blind(), IfaceWitness::blind())
    };
    RecvMeta::new(n, peer, local_ip, destination, iface, None)
  };

  // MSG_CTRUNC means our control buffer was too small to hold all ancillary
  // data. The datagram is preserved — it was already consumed — but the witness
  // is reported as LOST rather than absent, and the trust boundary refuses on
  // it. That is safe to do only because this side controls the buffer: see
  // `CmsgBuf`, which is sized so the flag cannot be provoked from the wire.
  if msg.msg_flags & libc::MSG_CTRUNC != 0 {
    let mut meta = witness_absent(true);
    meta.set_delivery(delivery);
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
  // A parse that recovered nothing degrades rather than refusing: with
  // `MSG_CTRUNC` clear the kernel emitted no usable cmsg of its own accord, and
  // every BSD does exactly that under mbuf pressure — `sbcreatecontrol` is
  // called with `M_NOWAIT` and its `NULL` return is skipped with no error, no
  // counter and no flag. Refusing there would make a responder go deaf during
  // the flood that caused the shortage.
  let mut meta = parsed.unwrap_or_else(|_| witness_absent(false));
  // Walk the same control buffer for a kernel receive-timestamp cmsg and thread
  // it onto the meta. A missing/short timestamp leaves rx_time as None — never
  // an error, since the datagram has already been consumed.
  meta.set_rx_time(parse_rx_time(control_slice));
  // Thread the IPv4 TTL / IPv6 Hop Limit onto the meta as a DIAGNOSTIC. RFC 6762
  // §11's receive test is stated exhaustively and both ways are about the
  // destination address, so nothing weighs this value; an absent or short cmsg
  // leaves it `None` and changes no admission decision.
  meta.set_hop_limit(parse_hop_limit(control_slice, is_v4));
  meta.set_delivery(delivery);
  Ok(meta)
}

/// Decode the link-layer delivery class out of the `msg_flags` a `recvmsg`
/// returned: whether the kernel delivered this datagram to a multicast group, as
/// a link-layer broadcast, or to this host alone.
///
/// `None` means "this target binds neither flag" — every supported target but
/// OpenBSD and NetBSD — and never [`LinkDelivery::Unicast`]. RFC 6762 §11 treats
/// the three completely differently, so the distinction has to survive into
/// [`RecvMeta::delivery`].
///
/// Exposed because a driver with its own receive path still has to decode the
/// same flags from the same field: `msg_flags` is the kernel's, this crate owns
/// what its bits mean, and a second hand-rolled reading of them is how a
/// capability gets quietly lost. Takes a plain `i32` so no caller has to name
/// `libc` to use it.
#[cfg(unix)]
#[inline]
pub fn link_delivery_from_msg_flags(msg_flags: i32) -> Option<LinkDelivery> {
  msg_link_delivery(msg_flags as libc::c_int)
}

/// Whether the kernel flagged the control buffer as TRUNCATED (`MSG_CTRUNC`) in
/// the `msg_flags` a `recvmsg` returned.
///
/// The one bit that separates the two ways a cmsg can be missing, and therefore
/// the one bit that separates [`DestinationWitness::Lost`] — our buffer was too small,
/// which refuses — from [`DestinationWitness::Declined`] — the kernel emitted nothing,
/// which degrades. Hand it straight to
/// [`DestinationWitness::from_reporting_path`] and
/// [`IfaceWitness::from_reporting_path`].
///
/// Exposed for the same reason [`link_delivery_from_msg_flags`] is: a driver
/// with its own receive path reads the same field, and what its bits mean is
/// this crate's business rather than each driver's. Takes a plain `i32` so no
/// caller has to name `libc` to use it.
#[cfg(unix)]
#[inline]
#[must_use]
pub fn control_truncated_from_msg_flags(msg_flags: i32) -> bool {
  msg_flags & libc::MSG_CTRUNC != 0
}

/// Read `MSG_MCAST`/`MSG_BCAST` out of the `msg_flags` `recvmsg` returned.
///
/// `None` where `libc` binds neither — every supported target but OpenBSD and
/// NetBSD, which bind both on adjacent lines
/// (`src/unix/bsd/netbsdlike/mod.rs:576-577`). See [`RecvMeta::delivery`] for
/// why a coarse answer is worth carrying at all.
///
/// # `MSG_MCAST` wins a contradiction, deliberately
///
/// The two bits are mutually exclusive in every stack that sets them: a datagram
/// is delivered to a group or as a broadcast, never both. If a kernel set both
/// anyway, reading it as a broadcast would REFUSE it, and the datagram most
/// likely to carry a multicast bit here is mDNS group traffic, which §11 calls
/// *essential* to admit. So the contradiction resolves toward the reading that
/// cannot make an endpoint silently deaf. Nothing an attacker chooses reaches
/// this: which bits the kernel sets follows from the destination they sent to,
/// and a sender cannot make one datagram both.
#[cfg(all(unix, any(has_msg_mcast, has_msg_bcast)))]
fn msg_link_delivery(msg_flags: libc::c_int) -> Option<LinkDelivery> {
  #[cfg(has_msg_mcast)]
  if msg_flags & libc::MSG_MCAST != 0 {
    return Some(LinkDelivery::Multicast);
  }
  #[cfg(has_msg_bcast)]
  if msg_flags & libc::MSG_BCAST != 0 {
    return Some(LinkDelivery::Broadcast);
  }
  let _ = msg_flags;
  Some(LinkDelivery::Unicast)
}

/// Fallback for targets where `libc` binds neither flag: always `None`, meaning
/// "this target cannot say", never [`LinkDelivery::Unicast`].
#[cfg(all(unix, not(any(has_msg_mcast, has_msg_bcast))))]
fn msg_link_delivery(_msg_flags: libc::c_int) -> Option<LinkDelivery> {
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

/// Fallback for targets without the TTL/Hop-Limit cmsg (OpenBSD/NetBSD):
/// always `None`. Costs nothing — the value is a diagnostic and no §11
/// admission decision reads it.
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
/// too short, the seconds field is negative (pre-epoch / malformed), or the
/// sub-second field is outside its own modulus. Other Unix targets have no
/// timestamp cmsg and always return `None`.
///
/// **The sub-second gate is a half-open range, not a sign test.** `tv_nsec`
/// must be in `0..1_000_000_000` and `tv_usec` in `0..1_000_000`, because
/// `Duration::new` would otherwise *normalize* an out-of-range field into the
/// next second instead of rejecting it — a malformed stamp would come back as
/// `Some`, one second later than it reads, and run the self-send match at
/// [`crate::selfsend::MatchMode::Ordered`] strength on it. Declining is the
/// documented answer for malformed input and it costs only the ordering arm.
///
/// **The workspace's only reading of that wire format.** It is reached two ways
/// and both land here: [`recv_with_meta`] threads the result onto a
/// [`RecvMeta`] for a driver that receives through this crate, and
/// [`crate::selfsend::RxEvidence::from_cmsgs`] is the door for a driver that
/// owns its own `recvmsg` and holds only the control buffer. A driver decoding
/// these cmsgs a second time for itself is how the two readings drift.
// Targets that deliver a `libc::timespec` via `SCM_TIMESTAMPNS` (Linux/Android).
#[cfg(recv_timestamp_ns)]
pub(crate) fn parse_rx_time(cmsgs: &[u8]) -> Option<SystemTime> {
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
      // Half-open range, not `< 0`: `tv_nsec == 1_000_000_000` is malformed,
      // and `Duration::new` would carry it into the next second rather than
      // reject it. See this function's docs.
      if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return None;
      }
      // `checked_add` (not `+`) keeps the denied `arithmetic_side_effects` lint
      // satisfied and degrades a pathological overflow to None. The gate above
      // leaves `tv_nsec` inside `u32` and below its modulus, so `Duration::new`
      // has no carry to make and cannot overflow on the sub-second field.
      return SystemTime::UNIX_EPOCH
        .checked_add(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32));
    }
  }
  None
}

// Apple + BSD targets that deliver a `libc::timeval` via `SCM_TIMESTAMP` (every
// supported timestamp target that is NOT the nanosecond Linux/Android variant).
#[cfg(all(has_recv_timestamp, not(recv_timestamp_ns)))]
pub(crate) fn parse_rx_time(cmsgs: &[u8]) -> Option<SystemTime> {
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
      // Half-open range, not `< 0`: `tv_usec == 1_000_000` is malformed, and
      // `Duration::new` would carry the resulting 1e9 nanoseconds into the next
      // second rather than reject it. See this function's docs.
      if tv.tv_sec < 0 || !(0..1_000_000).contains(&tv.tv_usec) {
        return None;
      }
      // microseconds -> nanoseconds; saturating_mul + checked_add keep the
      // denied `arithmetic_side_effects` lint satisfied (the gate above pins
      // tv_usec below 1e6, so neither actually saturates/overflows).
      let nanos = (tv.tv_usec as u32).saturating_mul(1000);
      return SystemTime::UNIX_EPOCH.checked_add(Duration::new(tv.tv_sec as u64, nanos));
    }
  }
  None
}

// Unix targets with no receive-timestamp cmsg wired up; the sockopt is a no-op,
// so always report None.
#[cfg(all(unix, not(has_recv_timestamp)))]
pub(crate) fn parse_rx_time(_cmsgs: &[u8]) -> Option<SystemTime> {
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
///
/// Terminates on malformed input: `cmsg_len` is the only way to locate the
/// next header, so once one is unusable — too short to cover even the header,
/// claiming more than the buffer holds, or (see `cmsg_advance`) producing a
/// computed stride that would not actually advance past it — the walk cannot
/// recover a position past it. Every error arm consumes the remainder before
/// returning, so a malformed header yields exactly one `Err` and every
/// following `next()` returns `None` — a caller that keeps polling past the
/// first `Err` (e.g. `.collect()`, `.count()`, an unconditional `for` loop)
/// still terminates instead of re-reading the same header forever.
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
      // cmsg_len must at least cover the header. cmsg_len is the only way to
      // locate the next header, so once it is unusable nothing past it is
      // parseable: fuse by dropping the rest of the buffer before returning,
      // rather than re-reading this same header forever.
      self.rest = &[];
      return Some(Err(ParseRecvMetaError::BufferTooShort(
        BufferTooShortDetail::new(hdr_size, cmsg_len),
      )));
    }
    if cmsg_len > self.rest.len() {
      // Same reasoning as above: an unusable cmsg_len ends the walk for good.
      // Build the error (which reports the pre-fuse remaining length) before
      // clearing `rest`.
      let err =
        ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(cmsg_len, self.rest.len()));
      self.rest = &[];
      return Some(Err(err));
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
    // The next header is `cmsg_advance(cmsg_len, data_start)` bytes on. That
    // helper is the only thing standing between this cmsg and the next, so an
    // `Err` from it gets the same fuse-then-yield-one-Err treatment as the two
    // length checks above rather than a silent zero-length advance.
    match cmsg_advance(cmsg_len, data_start) {
      Some(advance) => {
        // Clamp to what remains: `advance` is validated to be >= cmsg_len,
        // not to be <= self.rest.len().
        self.rest = self.rest.get(advance.min(self.rest.len())..).unwrap_or(&[]);
        Some(Ok(ParsedCmsg {
          level: hdr.cmsg_level,
          ty: hdr.cmsg_type,
          data,
        }))
      }
      None => {
        // No advance value can be trusted: fuse rather than loop on a stride
        // that cannot move past the header just read.
        let err = ParseRecvMetaError::BufferTooShort(BufferTooShortDetail::new(cmsg_len, 0));
        self.rest = &[];
        Some(Err(err))
      }
    }
  }
}

/// How far `CmsgIter::next` should advance past one cmsg entry (header at
/// offset 0, `cmsg_len` bytes long, payload starting at `data_start`), or
/// `None` if the platform's own stride arithmetic cannot be trusted to move
/// forward at all.
///
/// The one invariant `next()` needs from this: the result must be `>=
/// cmsg_len`, so the entry just read is fully behind the new `rest` and the
/// next call cannot read the same header again. `libc::CMSG_SPACE` takes and
/// returns `c_uint` (32 bits), but its `CMSG_ALIGN(len) +
/// CMSG_ALIGN(sizeof(cmsghdr))` body computes in `usize` — 64 bits on a
/// 64-bit host — and only truncates that sum back to `c_uint` on return. A
/// `datalen` near `u32::MAX` therefore overflows at the final truncation, not
/// the alignment itself: the returned stride wraps to something smaller than
/// the header it was meant to skip, including zero. A `cmsg_len` that large
/// needs a buffer of the same order (`cmsg_len <= rest.len()` is already
/// enforced by the caller), so on a 64-bit host this is reachable only
/// against a multi-gigabyte ancillary buffer; on a narrower host no real
/// slice can carry a `cmsg_len` that large in the first place (see the
/// pointer-width-specific tests). Either way, `parse_pktinfo_v4`/
/// `parse_pktinfo_v6` are public and documented as sound on arbitrary input,
/// so this is checked rather than assumed unreachable.
#[cfg(unix)]
fn cmsg_advance(cmsg_len: usize, data_start: usize) -> Option<usize> {
  let datalen = cmsg_len.saturating_sub(data_start);
  let dl = u32::try_from(datalen).ok()?;
  // SAFETY: CMSG_SPACE is pure length arithmetic — it takes an integer and
  // dereferences no memory, so calling it is sound (libc marks it `unsafe`
  // only by convention).
  #[allow(unsafe_code)]
  let advance = unsafe { libc::CMSG_SPACE(dl) } as usize;
  (advance >= cmsg_len).then_some(advance)
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

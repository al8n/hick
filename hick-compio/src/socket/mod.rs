//! compio UdpSocket wrapper + in-crate cmsg codec (ported from compio-quic 0.7.2).

#![cfg(any(unix, windows))]
// CMsgIter/CMsgRef are wired in by their consumers (CMsgBuilder, RecvMeta, Socket); silence
// `dead_code` until the consumers land in the same crate.
#![allow(dead_code)]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::SystemTime;

use hick_udp::selfsend::RxEvidence;

#[cfg(test)]
mod tests;

#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(unix)]
mod unix;

/// Whether THIS driver's receive path reports the interface a datagram from
/// `peer`'s address family arrived on, as the ingress trust boundary must be
/// told it.
///
/// Capability belongs to the receive path and not to the platform, which is why
/// [`hick_udp::onlink::admits_ingress`] takes it as a parameter rather than
/// reading a constant. This crate does NOT read its datagrams through
/// `hick-udp`: [`Socket::recv`] runs compio's own `recv_msg` plus
/// [`decode_unix_cmsgs`] on Unix — gated on the same `has_ip_pktinfo` /
/// `has_ipv6_pktinfo` cfgs `hick-udp` uses, so the answer there is identical —
/// and plain `recv_from` everywhere else, which recovers no ancillary data at
/// all.
///
/// # Windows recovers nothing, and says so
///
/// `hick-udp` reports IPv4 and IPv6 PKTINFO support on Windows because ITS
/// receive path calls `WSARecvMsg`. This crate's does not: the Windows arm of
/// [`Socket::recv`] is a plain `recv_from`, so every datagram arrives with
/// interface index `0` and no hop limit. Handing the rule `hick-udp`'s answer
/// there would make every zero index a failed proof and drop every non-loopback
/// datagram — a silently deaf responder on a physical Windows network. Saying
/// `false` instead leaves §11 deciding by the source-address rule exactly as it
/// did before the interface gate existed, which on Windows is the only rule
/// there has ever been anything to run: no hop limit is recovered there either.
/// The gate is not weakened so much as absent, because this path supplies
/// nothing for it to weigh. A `WSARecvMsg` port is what turns it on.
pub(crate) const fn rx_interface_reported(peer: core::net::SocketAddr) -> bool {
  cfg!(unix) && hick_udp::onlink::reports_rx_interface(peer)
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
  /// The IP header DESTINATION, where the cmsg carried one. Distinct from
  /// `local_ip`: on Unix IPv4 that field is `in_pktinfo.ipi_spec_dst`, the
  /// receiving interface's own unicast address, which never equals a multicast
  /// group — so reading it as a destination makes every multicast arrival look
  /// unicast. `ipi_addr` (IPv4) and `ipi6_addr` (IPv6) are the header
  /// destination and are what this carries.
  destination: Option<IpAddr>,
  /// Receiving interface index, taken from PKTINFO.
  interface_index: u32,
  /// IP TTL / IPv6 hop limit if the kernel exposed it.
  hop_limit: Option<u8>,
  /// Kernel-stamped rx time (SO_TIMESTAMP / SO_TIMESTAMPNS).
  kernel_rx_time: Option<SystemTime>,
  /// Bytes of payload received.
  len: usize,
  /// The kernel's `MSG_MCAST`, where this target binds one: whether the
  /// datagram was delivered as a multicast rather than addressed to this host
  /// alone. `None` means "this target has no such flag", never "it was
  /// unicast" — RFC 6762 §11's group arm treats those completely differently.
  delivery: Option<hick_udp::LinkDelivery>,
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
      destination: None,
      interface_index: 0,
      hop_limit: None,
      kernel_rx_time: None,
      delivery: None,
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

  /// The datagram's IP header destination, where this receive path recovered
  /// one. RFC 6762 §11 states its local-link test two ways and selects between
  /// them by this — arrival at `224.0.0.251` / `FF02::FB` is local-link origin
  /// on its own, regardless of source address — so it is emphatically NOT
  /// [`RecvMeta::local_ip`]. `None` means "this receive recovered none", never
  /// "the destination was unspecified".
  pub(crate) const fn destination(&self) -> Option<IpAddr> {
    self.destination
  }

  /// Whether the kernel delivered this datagram as a multicast, where this
  /// target reports it. Coarser than [`RecvMeta::destination`] — "some group"
  /// rather than which one — and consulted by §11's group arm only when no
  /// destination was recovered. `None` is "this target has no such flag".
  pub(crate) const fn delivery(&self) -> Option<hick_udp::LinkDelivery> {
    self.delivery
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

  /// This datagram's ordering evidence for the self-send match.
  ///
  /// # Why this driver asserts rather than proves it
  ///
  /// The strong form is [`RxEvidence::from_meta`], which reads the stamp out of a
  /// `hick_udp::RecvMeta` — a type `hick-udp` alone can mint, off its own
  /// `recvmsg`. This driver is completion-based: it submits its own `recv_msg`
  /// and walks the returned control buffer itself (see the cmsg decoder in
  /// `socket::unix`), so there is no `hick_udp::RecvMeta` anywhere on its receive
  /// path and nothing for that constructor to read.
  ///
  /// So the obligation is discharged HERE, at the single point where this crate's
  /// own cmsg decoding meets the tracker, and it is an obligation `hick-udp`
  /// cannot check: [`Self::kernel_rx_time`] must only ever hold a value the
  /// KERNEL wrote into `SCM_TIMESTAMP`/`SCM_TIMESTAMPNS`. It is populated in
  /// exactly one place, by that decoder, and is never defaulted to a userspace
  /// reading — a datagram whose cmsg carried no timestamp keeps `None` and
  /// degrades the match, which is the correct and safe answer.
  ///
  /// Substituting a read time here would not lose a byte: a read time is
  /// at-or-after our send in every case, so the ordering test could never reject
  /// on it and the claim would run at `Ordered` strength on `Degraded` evidence,
  /// re-opening the credit-theft window that ordering exists to close.
  pub(crate) const fn rx_evidence(&self) -> RxEvidence {
    match self.kernel_rx_time {
      Some(rx) => RxEvidence::from_caller_parsed_cmsg(rx),
      None => RxEvidence::none(),
    }
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
  /// `destination` is `Option<IpAddr>` rather than a second `IpAddr` so no
  /// call site can pass it positionally in place of `local_ip`: the two carry
  /// different addresses on Unix IPv4, and the compiler rather than review is
  /// what keeps them apart.
  pub(crate) const fn new(
    peer: SocketAddr,
    local_ip: IpAddr,
    destination: Option<IpAddr>,
    interface_index: u32,
    hop_limit: Option<u8>,
    kernel_rx_time: Option<SystemTime>,
    len: usize,
  ) -> Self {
    Self {
      peer,
      local_ip,
      destination,
      interface_index,
      hop_limit,
      kernel_rx_time,
      delivery: None,
      len,
      truncated: false,
    }
  }

  /// Set the kernel's multicast-delivery flag. Test-only; production sets it
  /// inside `Socket::recv` from the `recvmsg` return flags.
  #[cfg(test)]
  pub(crate) const fn with_delivery(mut self, delivery: Option<hick_udp::LinkDelivery>) -> Self {
    self.delivery = delivery;
    self
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
/// The constructor enables the kernel ancillary-data options the driver needs:
/// PKTINFO for the receiving interface and the IP header destination, which are
/// what RFC 6762 §11's arms actually read; RECVTTL/HOPLIMIT for the hop-limit
/// diagnostic, which no admission decision reads; and
/// `SO_TIMESTAMP`/`SO_TIMESTAMPNS` for ordered self-send classification. It then
/// wraps the file descriptor as a `compio` socket.
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
      let (data_len, ctrl_len, peer, recv_flags) = res?;
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
      // `recvmsg`'s own `msg_flags`, which compio hands back as `ReturnFlags`
      // and this code used to bind to `_` and throw away. rustix builds that
      // value with `from_bits_retain` and declares a catch-all bit, so a flag it
      // does not name — `MSG_MCAST` on OpenBSD/NetBSD — survives verbatim in
      // `bits()`. What those bits mean is `hick-udp`'s business, so the decode
      // lives there rather than being hand-rolled a second time here.
      //
      // Without it a valid mDNS-group datagram on those targets reached §11's
      // fallback with no destination AND no flag, fell to the source-prefix arm
      // and was refused whenever the sender's prefix was not one of ours —
      // traffic §11 requires be accepted.
      meta.delivery = hick_udp::link_delivery_from_msg_flags(recv_flags.bits() as i32);
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

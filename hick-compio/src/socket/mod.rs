//! compio UdpSocket wrapper + in-crate cmsg codec (ported from compio-quic 0.7.2).

#![cfg(any(unix, windows))]
// CMsgIter/CMsgRef are wired in by their consumers (CMsgBuilder, RecvMeta, Socket); silence
// `dead_code` until the consumers land in the same crate.
#![allow(dead_code)]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
  /// What this datagram's arrival says about its order against our own sends.
  ///
  /// An [`RxEvidence`] rather than an `Option<SystemTime>` so there is exactly
  /// one line that decides it — [`Socket::recv`]'s `RxEvidence::from_cmsgs`
  /// call, over the buffer that receive filled — instead of a plain timestamp
  /// field any later code could assign a clock reading to. That is a narrowed
  /// blast radius, not a proof: `hick-udp` cannot check that the bytes are a
  /// kernel's, so the obligation still rests on that one call site being fed
  /// the real control buffer.
  ///
  /// Living HERE, on the `RecvMeta` [`Socket::recv`] returns beside the very
  /// datagram it decoded, is what discharges the *other* half of that
  /// obligation: `hick-udp` cannot check which datagram a stamp belongs to
  /// either, and one struct carrying both is how this driver keeps them from
  /// being paired wrongly. See [`RxEvidence`] on origin versus association.
  rx: RxEvidence,
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
      rx: RxEvidence::none(),
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

  /// This datagram's ordering evidence for the self-send match.
  ///
  /// # This driver still asserts it. What changed is who decodes it
  ///
  /// [`RxEvidence::from_meta`] reads the stamp out of a `hick_udp::RecvMeta` — a
  /// type `hick-udp` alone can mint, off its own `recvmsg`, and the one form of
  /// this evidence whose ORIGIN `hick-udp` can actually check. That door is shut
  /// to this driver: it is completion-based, submits its own `recv_msg` and owns
  /// the control buffer that comes back, so there is no `hick_udp::RecvMeta`
  /// anywhere on its receive path, and there will not be one until `hick-udp`
  /// can own a completion-model receive.
  ///
  /// So this remains an obligation `hick-udp` cannot check, discharged HERE:
  /// [`Socket::recv`] must pass `RxEvidence::from_cmsgs` the control buffer its
  /// own `recv_msg` just filled, and nothing else. `hick-udp` parses those
  /// bytes but cannot tell them from bytes this crate encoded, so a buffer kept
  /// from an earlier receive, or one built by hand, would produce ordering
  /// evidence that orders nothing.
  ///
  /// What the change did buy is that the *decode* is no longer this crate's.
  /// The stamp comes out of the same parser every other driver here uses, so
  /// this crate can no longer disagree with them about what a
  /// `SCM_TIMESTAMP`/`SCM_TIMESTAMPNS` cmsg says — and the assertion above
  /// shrank from a whole cmsg decoder to one argument at one call site.
  ///
  /// Getting it wrong would not lose a byte: a stamp that does not order the
  /// datagram against our `sendto` is at-or-after our send in every case, so the
  /// ordering test could never reject on it and the claim would run at `Ordered`
  /// strength on evidence that carries no order, re-opening the credit-theft
  /// window that ordering exists to close.
  ///
  /// # The other unchecked half: which datagram the stamp belongs to
  ///
  /// `hick-udp` would not be able to check that even for a `hick_udp::RecvMeta`.
  /// `SelfSendTracker::take` takes the body and the evidence as separate
  /// arguments and `RxEvidence` is `Copy`, so a stamp a kernel really did write
  /// — for a *different* receive — is weighed at `Ordered` strength all the
  /// same. A later stamp lets a datagram the kernel saw before our `sendto` take
  /// the credit; an earlier one rejects the genuine echo. Both end at a phantom
  /// RFC 6762 §9 conflict against ourselves.
  ///
  /// This driver discharges it structurally rather than by care at the call: the
  /// stamp is a field of the `RecvMeta` that `Socket::recv` returns beside the
  /// datagram, and `DriverState`'s claim reads body and evidence out of that one
  /// value. See `hick_udp::selfsend::RxEvidence` for the full contract.
  pub(crate) const fn rx_evidence(&self) -> RxEvidence {
    self.rx
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
    rx: RxEvidence,
    len: usize,
  ) -> Self {
    Self {
      peer,
      local_ip,
      destination,
      interface_index,
      hop_limit,
      rx,
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
      // The kernel receive timestamp is read out of the SAME buffer by
      // `hick-udp`, not by the decoder above: `SCM_TIMESTAMP`/`SCM_TIMESTAMPNS`
      // is one wire format, and a driver-local copy of its decode is how two
      // readings of one kernel ABI drift.
      //
      // `ctrl_bytes` and nothing else. `hick-udp` parses these bytes but cannot
      // check where they came from, so this line IS the self-send ordering
      // contract for this driver: it must be the control buffer the `recv_msg`
      // directly above just filled. A retained buffer, or one assembled here,
      // would still produce `Ordered` evidence — and evidence that orders
      // nothing is what re-opens the credit-theft race. See
      // `RecvMeta::rx_evidence`.
      //
      // Assigning it onto THIS `meta`, which is returned with the very bytes
      // that receive produced, is equally load-bearing: `hick-udp` cannot check
      // which datagram a stamp belongs to either, so a stamp landing on some
      // other receive's meta would be weighed at `Ordered` strength against the
      // wrong payload. Keeping the two in one value is what rules that out.
      //
      // `None` — no cmsg, a short one, a target without the sockopt — is
      // `RxEvidence::none()` and correctly degrades the match.
      meta.rx = RxEvidence::from_cmsgs(ctrl_bytes);
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

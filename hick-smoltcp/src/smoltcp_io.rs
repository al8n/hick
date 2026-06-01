//! [`UdpIo`] over smoltcp UDP sockets, via the family-aware [`DualStack`].
//!
//! The engine fans every multicast to BOTH the v4 and v6 groups, so the transport
//! must be family-aware: a datagram of one family must reach a socket of THAT
//! family, and an absent family must report [`SendError::Unsupported`] so the
//! engine confirms on the family it has. A bare `udp::Socket` cannot express its
//! family — a port-only `bind(5353)` is family-ambiguous, and smoltcp's
//! `send_slice` does not reject a wrong-family destination (it enqueues, then
//! `iface.poll` panics on mixed IP versions or silently drops while the engine has
//! already confirmed the send). So this crate does NOT implement `UdpIo` for a raw
//! `udp::Socket`; use [`DualStack`], naming the v4 and/or v6 socket handle
//! explicitly (leave one `None` for a single-stack node). This is a bare poll loop
//! / RTIC transport; `hick-embassy` provides the embassy equivalent.

use core::net::SocketAddr;

use smoltcp::{
  iface::{SocketHandle, SocketSet},
  socket::udp,
  wire::IpEndpoint,
};

use crate::udpio::{RecvMeta, SendError, UdpIo};

/// Pull one datagram from `socket` into `buf`. `None` when the receive queue is
/// empty; a zero-length [`RecvMeta`] marks a datagram smoltcp dropped as oversized
/// (so the engine still counts it against the per-pump RX cap — see below).
fn recv_from(socket: &mut udp::Socket<'_>, buf: &mut [u8]) -> Option<RecvMeta> {
  match socket.recv_slice(buf) {
    Ok((len, meta)) => Some(RecvMeta {
      src: meta.endpoint.into(),
      local: meta.local_address.map(Into::into),
      // smoltcp's `udp::Socket` UDP metadata (`UdpMetadata`) exposes no received
      // hop-limit — verified against 0.13.1 (only `endpoint` / `local_address` /
      // `meta`) — so this is `None` and the engine's §11 RECEIVE gate falls back to
      // the source-subnet heuristic (`onlink::on_link`). The §11 TRANSMIT invariant
      // (TTL 255 out) is enforced separately in `send_from`, not here.
      hop_limit: None,
      len,
    }),
    Err(udp::RecvError::Exhausted) => None,
    // An oversized datagram was DROPPED (recv_slice already dequeued it). Surface a
    // zero-length marker rather than looping here to find the next fitting datagram:
    // the drop then counts against the engine's MAX_RX_PER_PUMP cap, so a flood
    // of oversized packets cannot drain the whole socket backlog in one uncapped pass.
    // A real mDNS datagram is never zero-length (>= 12-byte header), so the engine
    // treats len 0 as "nothing to deliver".
    Err(udp::RecvError::Truncated) => Some(RecvMeta {
      src: SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED), 0),
      local: None,
      hop_limit: None,
      len: 0,
    }),
  }
}

/// Enqueue one datagram on `socket` for `dst` — which [`DualStack`] has already
/// routed to this socket's family, so there is no wrong-family hazard here. Maps a
/// payload larger than the TX buffer to [`SendError::TooLarge`] (permanent, so the
/// engine retires the producer rather than retrying) versus a momentarily
/// full queue to [`SendError::Busy`] (transient).
fn send_from(socket: &mut udp::Socket<'_>, buf: &[u8], dst: SocketAddr) -> Result<(), SendError> {
  if buf.len() > socket.payload_send_capacity() {
    return Err(SendError::TooLarge);
  }
  // RFC 6762 §11: EVERY outgoing mDNS packet MUST leave with IP TTL / hop-limit 255,
  // and a conformant receiver rejects anything else (it is the multicast on-link
  // guard — the same gate `onlink::on_link` applies on RX). smoltcp dispatches a UDP
  // datagram with the socket's configured hop-limit and DEFAULTS it to 64 when unset,
  // so a probe/announcement/goodbye would otherwise egress at 64 and compliant peers
  // would silently drop it — the API would appear to transmit while no peer listens.
  // Force 255 here at the single send choke point (idempotent — a plain field set on
  // the value smoltcp reads at egress) rather than trusting every caller to have
  // configured both sockets; `hick-embassy`'s driver enforces the equivalent
  // `set_hop_limit(Some(255))` once at startup (it holds the sockets by `&mut` there),
  // and the smoltcp sockets are reached only through this transport, so enforce per-send.
  socket.set_hop_limit(Some(255));
  match socket.send_slice(buf, IpEndpoint::from(dst)) {
    Ok(()) => Ok(()),
    Err(udp::SendError::BufferFull) => Err(SendError::Busy),
    Err(udp::SendError::Unaddressable) => Err(SendError::Unsupported),
  }
}

/// A family-aware [`UdpIo`] over a v4 and/or v6 smoltcp UDP socket living in a
/// shared [`SocketSet`] — the smoltcp transport (single- OR dual-stack), mirroring
/// `hick-embassy`'s `DualUdp`.
///
/// The engine fans every multicast to BOTH groups, so each datagram must reach the
/// socket of ITS OWN family rather than be enqueued on a mismatched one (which
/// would panic or be silently dropped). `try_send` routes by the destination's
/// family and reports [`SendError::Unsupported`] for an absent family (the engine
/// then confirms on the family it has); `try_recv` alternates the two sockets
/// round-robin so a sustained backlog on one family cannot starve the other under
/// the engine's per-pump RX cap. For a SINGLE-stack node, leave the absent family's
/// handle `None` — the family-explicit replacement for naively pumping one raw socket.
///
/// `pump` borrows the [`SocketSet`] for the duration of one step; build a fresh
/// `DualStack` each step (it is a thin view) with [`DualStack::new`], e.g.
/// `engine.pump(now, &mut DualStack::new(sockets, Some(h4), Some(h6)), buf)`.
pub struct DualStack<'set, 'sockets> {
  sockets: &'set mut SocketSet<'sockets>,
  v4: Option<SocketHandle>,
  v6: Option<SocketHandle>,
  /// Which family to poll FIRST on the next `try_recv`, toggled each call so the two
  /// families are drained round-robin. Per-pump (a fresh `DualStack` resets it)
  /// is enough: the RX cap is per-pump, so alternating within each pump serves both.
  take_v6_first: bool,
}

impl<'set, 'sockets> DualStack<'set, 'sockets> {
  /// Build the transport view for one pump step over a v4 and/or v6 socket living in
  /// `sockets`. Pass `None` for an absent family on a single-stack node.
  pub fn new(
    sockets: &'set mut SocketSet<'sockets>,
    v4: Option<SocketHandle>,
    v6: Option<SocketHandle>,
  ) -> Self {
    Self {
      sockets,
      v4,
      v6,
      take_v6_first: false,
    }
  }
}

impl UdpIo for DualStack<'_, '_> {
  fn try_recv(&mut self, buf: &mut [u8]) -> Option<RecvMeta> {
    // Alternate which family is polled first so a sustained backlog on one cannot
    // monopolize the engine's per-pump RX cap and starve the other.
    let take_v6_first = self.take_v6_first;
    self.take_v6_first = !take_v6_first;
    let (first, second) = if take_v6_first {
      (self.v6, self.v4)
    } else {
      (self.v4, self.v6)
    };
    if let Some(handle) = first
      && let Some(meta) = recv_from(self.sockets.get_mut::<udp::Socket<'_>>(handle), buf)
    {
      return Some(meta);
    }
    if let Some(handle) = second {
      return recv_from(self.sockets.get_mut::<udp::Socket<'_>>(handle), buf);
    }
    None
  }

  fn try_send(&mut self, buf: &[u8], dst: SocketAddr) -> Result<(), SendError> {
    let handle = if dst.is_ipv4() { self.v4 } else { self.v6 };
    match handle {
      Some(handle) => send_from(self.sockets.get_mut::<udp::Socket<'_>>(handle), buf, dst),
      // No socket for this family — it will never queue here. Report unsupported so
      // the engine confirms on the family it has rather than retrying forever.
      None => Err(SendError::Unsupported),
    }
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Loopback, Medium, RxToken, TxToken},
    socket::udp,
    time::Instant as RawInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Packet},
  };

  use super::DualStack;
  use crate::udpio::{SendError, UdpIo};

  /// A phy device that CAPTURES every egressed frame (Medium::Ip → raw IP packets)
  /// so a test can inspect the on-wire IP header. Never delivers ingress.
  #[derive(Default)]
  struct CapturingDevice {
    sent: alloc::vec::Vec<alloc::vec::Vec<u8>>,
  }
  struct CapTxToken<'a> {
    sent: &'a mut alloc::vec::Vec<alloc::vec::Vec<u8>>,
  }
  impl TxToken for CapTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
      let mut buf = alloc::vec![0u8; len];
      let r = f(&mut buf);
      self.sent.push(buf);
      r
    }
  }
  struct CapRxToken;
  impl RxToken for CapRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, _f: F) -> R {
      unreachable!("the capturing device never receives")
    }
  }
  impl Device for CapturingDevice {
    type RxToken<'a> = CapRxToken;
    type TxToken<'a> = CapTxToken<'a>;
    fn receive(&mut self, _t: RawInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
      None
    }
    fn transmit(&mut self, _t: RawInstant) -> Option<Self::TxToken<'_>> {
      Some(CapTxToken {
        sent: &mut self.sent,
      })
    }
    fn capabilities(&self) -> DeviceCapabilities {
      let mut caps = DeviceCapabilities::default();
      caps.medium = Medium::Ip;
      caps.max_transmission_unit = 1500;
      caps
    }
  }

  /// Build a port-5353 UDP socket over caller-owned buffers.
  fn udp_socket<'a>(
    rx_meta: &'a mut [udp::PacketMetadata],
    rx_buf: &'a mut [u8],
    tx_meta: &'a mut [udp::PacketMetadata],
    tx_buf: &'a mut [u8],
  ) -> udp::Socket<'a> {
    udp::Socket::new(
      udp::PacketBuffer::new(rx_meta, rx_buf),
      udp::PacketBuffer::new(tx_meta, tx_buf),
    )
  }

  #[test]
  fn dual_stack_routes_by_family_and_reports_absent() {
    // DualStack routes each datagram to the socket of its OWN family and
    // reports Unsupported for an absent family (so the engine confirms on the one
    // it has). The socket here is port-only (`bind(5353)`, the common wildcard
    // case): the absent family is gated by the `None` handle, not by the
    // family-ambiguous socket, so a wrong-family datagram is NEVER enqueued (which
    // would crash iface.poll).
    let mut rx_meta = [udp::PacketMetadata::EMPTY; 1];
    let mut rx_buf = [0u8; 256];
    let mut tx_meta = [udp::PacketMetadata::EMPTY; 1];
    let mut tx_buf = [0u8; 256];
    let socket = udp_socket(&mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    let mut storage: [_; 1] = Default::default();
    let mut sockets = SocketSet::new(&mut storage[..]);
    let h4 = sockets.add(socket);
    sockets.get_mut::<udp::Socket<'_>>(h4).bind(5353).unwrap();
    let mut io = DualStack::new(&mut sockets, Some(h4), None);
    // No v6 socket → a v6 destination is reported absent (Unsupported), NOT
    // enqueued on the v4 socket.
    let v6 = SocketAddr::new(
      IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
      5353,
    );
    assert_eq!(io.try_send(&[0u8; 8], v6), Err(SendError::Unsupported));
    // A v4 destination is routed to the present v4 socket (not Unsupported).
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
    assert_ne!(io.try_send(&[0u8; 8], v4), Err(SendError::Unsupported));
  }

  #[test]
  fn oversized_datagram_maps_to_too_large_not_busy() {
    // a datagram larger than the socket's TX payload capacity can never be
    // enqueued. smoltcp reports it with the SAME BufferFull as a momentarily-full
    // queue, so DualStack's send size-checks first and surfaces TooLarge
    // (permanent) — otherwise the engine treats it as transient Busy and retries it
    // forever instead of retiring the producer.
    let mut rx_meta = [udp::PacketMetadata::EMPTY; 1];
    let mut rx_buf = [0u8; 64];
    let mut tx_meta = [udp::PacketMetadata::EMPTY; 1];
    let mut tx_buf = [0u8; 64]; // a TX buffer far smaller than a legal mDNS packet
    let socket = udp_socket(&mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    let mut storage: [_; 1] = Default::default();
    let mut sockets = SocketSet::new(&mut storage[..]);
    let h4 = sockets.add(socket);
    sockets.get_mut::<udp::Socket<'_>>(h4).bind(5353).unwrap();
    assert!(
      sockets
        .get_mut::<udp::Socket<'_>>(h4)
        .payload_send_capacity()
        < 128
    );
    let mut io = DualStack::new(&mut sockets, Some(h4), None);
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
    assert_eq!(
      io.try_send(&[0u8; 128], v4),
      Err(SendError::TooLarge),
      "a datagram exceeding the TX payload capacity must map to TooLarge, not Busy"
    );
    // A datagram within capacity is NOT mislabelled (queues, or transient Busy).
    assert_ne!(io.try_send(&[0u8; 8], v4), Err(SendError::TooLarge));
  }

  /// Round-trip a datagram through a smoltcp `Loopback` device to exercise the
  /// [`DualStack`] `UdpIo`: `try_send` queues it, the interface egresses it back to
  /// its own address, and `try_recv` yields it with correct source / destination
  /// metadata.
  #[test]
  fn loopback_udpio_roundtrip() {
    const PORT: u16 = 5353;
    let own_v4 = Ipv4Addr::new(127, 0, 0, 1);
    let dst = SocketAddr::new(IpAddr::V4(own_v4), PORT);

    // Pure-L3 loopback (no Ethernet/ARP) so a self-addressed datagram loops.
    let mut device = Loopback::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, RawInstant::ZERO);
    iface.update_ip_addrs(|addrs| {
      addrs
        .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
        .unwrap();
    });

    let mut rx_meta = [udp::PacketMetadata::EMPTY; 4];
    let mut rx_buf = [0u8; 1500];
    let mut tx_meta = [udp::PacketMetadata::EMPTY; 4];
    let mut tx_buf = [0u8; 1500];
    let socket = udp::Socket::new(
      udp::PacketBuffer::new(&mut rx_meta[..], &mut rx_buf[..]),
      udp::PacketBuffer::new(&mut tx_meta[..], &mut tx_buf[..]),
    );
    let mut sock_storage: [_; 2] = Default::default();
    let mut sockets = SocketSet::new(&mut sock_storage[..]);
    let handle = sockets.add(socket);
    sockets
      .get_mut::<udp::Socket<'_>>(handle)
      .bind(PORT)
      .unwrap();

    let payload = b"hick-mdns-loopback";
    // A fresh `DualStack` view per step (it borrows the SocketSet only for that
    // call), so `iface.poll` can take `&mut sockets` in between — mirroring how the
    // engine pumps one step at a time.
    DualStack::new(&mut sockets, Some(handle), None)
      .try_send(payload, dst)
      .expect("try_send should queue the datagram");

    // Drive egress -> loopback -> ingress.
    for _ in 0..8 {
      iface.poll(RawInstant::ZERO, &mut device, &mut sockets);
    }

    let mut buf = [0u8; 1500];
    let meta = DualStack::new(&mut sockets, Some(handle), None)
      .try_recv(&mut buf)
      .expect("the looped-back datagram should be received");

    assert_eq!(meta.len, payload.len());
    assert_eq!(&buf[..meta.len], payload);
    assert_eq!(meta.src, dst, "source is our own bound address:port");
    assert_eq!(
      meta.local,
      Some(IpAddr::V4(own_v4)),
      "local/destination address the datagram arrived on"
    );
    assert_eq!(
      meta.hop_limit, None,
      "smoltcp udp::Socket doesn't surface RX TTL"
    );
  }

  #[test]
  fn egress_packets_carry_hop_limit_255() {
    // RFC 6762 §11: every outgoing mDNS packet MUST leave with IP TTL /
    // hop-limit 255, and conformant peers reject anything else at their on-link gate.
    // smoltcp defaults a UDP socket's hop-limit to 64, so the DualStack send path must
    // force 255 — assert it on the ACTUAL egressed IPv4 header, not just socket state.
    let mut device = CapturingDevice::default();
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, RawInstant::ZERO);
    iface.update_ip_addrs(|addrs| {
      addrs
        .push(IpCidr::new(IpAddress::v4(192, 168, 1, 10), 24))
        .unwrap();
    });

    let mut rx_meta = [udp::PacketMetadata::EMPTY; 1];
    let mut rx_buf = [0u8; 256];
    let mut tx_meta = [udp::PacketMetadata::EMPTY; 1];
    let mut tx_buf = [0u8; 256];
    let socket = udp_socket(&mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    let mut storage: [_; 1] = Default::default();
    let mut sockets = SocketSet::new(&mut storage[..]);
    let h4 = sockets.add(socket);
    sockets.get_mut::<udp::Socket<'_>>(h4).bind(5353).unwrap();

    // Send to the IPv4 mDNS group through DualStack — the engine's real destination.
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
    DualStack::new(&mut sockets, Some(h4), None)
      .try_send(b"hick-mdns", dst)
      .expect("try_send should queue the datagram");

    // Drive egress into the capturing device.
    for _ in 0..4 {
      iface.poll(RawInstant::ZERO, &mut device, &mut sockets);
    }

    assert!(
      !device.sent.is_empty(),
      "the datagram must have egressed to the device"
    );
    let frame = &device.sent[0];
    let ip = Ipv4Packet::new_checked(&frame[..]).expect("a valid IPv4 packet egressed");
    assert_eq!(
      ip.hop_limit(),
      255,
      "RFC 6762 §11: every outgoing mDNS packet must leave with IP TTL 255, not the \
       smoltcp default 64"
    );
  }

  #[test]
  fn oversized_received_datagram_yields_a_drop_marker_not_a_loop() {
    // a received datagram larger than the engine's scratch is dropped by smoltcp
    // (RecvError::Truncated). recv_from must surface a zero-length MARKER so the engine
    // counts it against MAX_RX_PER_PUMP, instead of looping to find the next fitting
    // datagram (which would drain the whole oversized backlog in one uncapped pass).
    const PORT: u16 = 5353;
    let own = Ipv4Addr::new(127, 0, 0, 1);
    let dst = SocketAddr::new(IpAddr::V4(own), PORT);
    let mut device = Loopback::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, RawInstant::ZERO);
    iface.update_ip_addrs(|addrs| {
      addrs
        .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
        .unwrap();
    });
    let mut rx_meta = [udp::PacketMetadata::EMPTY; 4];
    let mut rx_buf = [0u8; 1500];
    let mut tx_meta = [udp::PacketMetadata::EMPTY; 4];
    let mut tx_buf = [0u8; 1500];
    let socket = udp::Socket::new(
      udp::PacketBuffer::new(&mut rx_meta[..], &mut rx_buf[..]),
      udp::PacketBuffer::new(&mut tx_meta[..], &mut tx_buf[..]),
    );
    let mut sock_storage: [_; 2] = Default::default();
    let mut sockets = SocketSet::new(&mut sock_storage[..]);
    let handle = sockets.add(socket);
    sockets
      .get_mut::<udp::Socket<'_>>(handle)
      .bind(PORT)
      .unwrap();

    // Send a 100-byte datagram to ourselves.
    DualStack::new(&mut sockets, Some(handle), None)
      .try_send(&[0xABu8; 100], dst)
      .expect("try_send should queue the datagram");
    for _ in 0..8 {
      iface.poll(RawInstant::ZERO, &mut device, &mut sockets);
    }

    // Receive with a buffer SMALLER than the datagram → smoltcp truncates/drops it.
    let mut small = [0u8; 50];
    let meta = DualStack::new(&mut sockets, Some(handle), None)
      .try_recv(&mut small)
      .expect("a drop marker (Some), not None");
    assert_eq!(
      meta.len, 0,
      "an oversized datagram must surface as a zero-length drop marker"
    );
    // The oversized datagram was consumed (no loop, no leftover).
    assert!(
      DualStack::new(&mut sockets, Some(handle), None)
        .try_recv(&mut small)
        .is_none(),
      "the dropped datagram must have been consumed"
    );
  }

  #[test]
  fn try_recv_round_robins_handles_so_one_backlog_cannot_starve_the_other() {
    // with the engine's per-pump RX cap, a strict first-family drain lets a
    // sustained backlog on one socket consume the whole cap every pump and starve the
    // other. `try_recv` must alternate the two handles. Two distinct loopback addresses
    // stand in for the v4/v6 handles (the round-robin alternates handles regardless of
    // family), avoiding a v6 loopback setup.
    let addr_a = Ipv4Addr::new(127, 0, 0, 1);
    let addr_b = Ipv4Addr::new(127, 0, 0, 2);
    let mut device = Loopback::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, RawInstant::ZERO);
    iface.update_ip_addrs(|addrs| {
      addrs
        .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
        .unwrap();
      addrs
        .push(IpCidr::new(IpAddress::v4(127, 0, 0, 2), 8))
        .unwrap();
    });
    let mut ra = [udp::PacketMetadata::EMPTY; 8];
    let mut rab = [0u8; 2048];
    let mut ta = [udp::PacketMetadata::EMPTY; 8];
    let mut tab = [0u8; 2048];
    let mut rb = [udp::PacketMetadata::EMPTY; 8];
    let mut rbb = [0u8; 2048];
    let mut tb = [udp::PacketMetadata::EMPTY; 8];
    let mut tbb = [0u8; 2048];
    let sa = udp::Socket::new(
      udp::PacketBuffer::new(&mut ra[..], &mut rab[..]),
      udp::PacketBuffer::new(&mut ta[..], &mut tab[..]),
    );
    let sb = udp::Socket::new(
      udp::PacketBuffer::new(&mut rb[..], &mut rbb[..]),
      udp::PacketBuffer::new(&mut tb[..], &mut tbb[..]),
    );
    let mut storage: [_; 4] = Default::default();
    let mut sockets = SocketSet::new(&mut storage[..]);
    let ha = sockets.add(sa);
    let hb = sockets.add(sb);
    sockets
      .get_mut::<udp::Socket<'_>>(ha)
      .bind(IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), 5353))
      .unwrap();
    sockets
      .get_mut::<udp::Socket<'_>>(hb)
      .bind(IpEndpoint::new(IpAddress::v4(127, 0, 0, 2), 5353))
      .unwrap();

    // Backlog: 4 datagrams to A, 2 to B. Sent directly (DualStack routing would send
    // both v4 destinations to the v4 handle).
    for _ in 0..4 {
      sockets
        .get_mut::<udp::Socket<'_>>(ha)
        .send_slice(b"a", IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), 5353))
        .unwrap();
    }
    for _ in 0..2 {
      sockets
        .get_mut::<udp::Socket<'_>>(hb)
        .send_slice(b"b", IpEndpoint::new(IpAddress::v4(127, 0, 0, 2), 5353))
        .unwrap();
    }
    for _ in 0..16 {
      iface.poll(RawInstant::ZERO, &mut device, &mut sockets);
    }

    // Drain via the round-robin `try_recv` and record which handle each came from.
    let mut io = DualStack::new(&mut sockets, Some(ha), Some(hb));
    let mut buf = [0u8; 64];
    let mut from_a = alloc::vec::Vec::new();
    while let Some(meta) = io.try_recv(&mut buf) {
      if meta.len > 0 {
        from_a.push(meta.src.ip() == IpAddr::V4(addr_a));
      }
    }
    let _ = addr_b;
    assert_eq!(
      from_a.iter().filter(|&&a| a).count(),
      4,
      "all 4 datagrams on handle A must arrive; order = {from_a:?}"
    );
    assert_eq!(
      from_a.iter().filter(|&&a| !a).count(),
      2,
      "both datagrams on handle B must arrive; order = {from_a:?}"
    );
    let first_b = from_a
      .iter()
      .position(|&a| !a)
      .expect("a handle-B datagram");
    assert!(
      first_b < 4,
      "handle B must interleave, not be starved behind A's backlog; order = {from_a:?}"
    );
  }
}

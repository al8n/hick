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

#[test]
fn a_present_but_unbound_socket_is_busy_not_unsupported() {
  // `SendError::Unsupported` means the family has NO socket, and the engine
  // therefore drops it from the obligated set entirely. smoltcp raises
  // `Unaddressable` when the socket's own local port is still zero — a socket
  // that plainly EXISTS — and also for an unspecified destination. Reporting
  // either as `Unsupported` would make a bound-v4 + present-but-unbound-v6
  // fan-out project to `AllDelivered`, advancing RFC 6762 §8.1 probing as though
  // IPv6 did not exist on a node that has it. It must be `Busy`: the family
  // stays obligated (so the fan-out is `PartiallyDelivered`) and is retried,
  // which is also right for a binding that may still complete.
  let mut rx4 = [udp::PacketMetadata::EMPTY; 1];
  let mut rb4 = [0u8; 256];
  let mut tx4 = [udp::PacketMetadata::EMPTY; 1];
  let mut tb4 = [0u8; 256];
  let mut rx6 = [udp::PacketMetadata::EMPTY; 1];
  let mut rb6 = [0u8; 256];
  let mut tx6 = [udp::PacketMetadata::EMPTY; 1];
  let mut tb6 = [0u8; 256];
  let s4 = udp_socket(&mut rx4, &mut rb4, &mut tx4, &mut tb4);
  let s6 = udp_socket(&mut rx6, &mut rb6, &mut tx6, &mut tb6);
  let mut storage: [_; 2] = Default::default();
  let mut sockets = SocketSet::new(&mut storage[..]);
  let h4 = sockets.add(s4);
  let h6 = sockets.add(s6);
  // v4 is bound; v6 is PRESENT but never bound (local port stays 0).
  sockets.get_mut::<udp::Socket<'_>>(h4).bind(5353).unwrap();
  assert!(
    !sockets.get_mut::<udp::Socket<'_>>(h6).is_open(),
    "the v6 socket must be present but unbound for this test to mean anything"
  );

  let mut io = DualStack::new(&mut sockets, Some(h4), Some(h6));
  let v6 = SocketAddr::new(
    IpAddr::V6(core::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
    5353,
  );
  assert_eq!(
    io.try_send(&[0u8; 8], v6),
    Err(SendError::Busy),
    "an unbound socket EXISTS, so its family stays obligated"
  );
  // The bound family still carries the same datagram, so the fan-out is a
  // genuine partial rather than a single-stack success.
  let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
  assert_eq!(io.try_send(&[0u8; 8], v4), Ok(()));
}

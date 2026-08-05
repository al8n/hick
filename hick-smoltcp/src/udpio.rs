//! The [`UdpIo`] transport seam between the engine and a concrete socket layer.

use core::net::{IpAddr, SocketAddr};

/// Normalized metadata for one received datagram.
///
/// Carries no interface identity — see [`UdpIo`]'s one-interface-per-implementation
/// contract, which is what makes the §11 ingress gate's use of [`Self::src`] sound.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
  /// Source endpoint (the sender).
  pub src: SocketAddr,
  /// The IP header DESTINATION the datagram was addressed to: the mDNS group for
  /// multicast, one of this device's own addresses for unicast.
  ///
  /// **RFC 6762 §11 picks its local-link test by this field**, so an
  /// implementation that leaves it `None` has its datagram DROPPED and counted
  /// rather than admitted on a weaker rule — a missing destination is not
  /// grounds for a wider arm. Both supplied transports always fill it: smoltcp
  /// sets `UdpMetadata::local_address` from the IP header on every receive, and
  /// its documentation says *"Incoming datagrams always have this set"*. The
  /// `Option` is a SEND-direction artifact of that type, kept here so the
  /// mapping is a plain `.map()`.
  pub local: Option<IpAddr>,
  /// The received IP TTL / IPv6 hop-limit, if the transport surfaces it.
  ///
  /// Diagnostic only — NOT a §11 input. RFC 6762 §11's receive-side test is
  /// exhaustive ("the test for whether a response originated on the local link
  /// is done in two ways"): mDNS-group destination, or source-subnet
  /// membership. The received hop-limit is neither; the RFC's only TTL
  /// provision is the outbound `SHOULD` (send at 255, a compatibility
  /// concession to 2004-draft queriers), not a receive check. The §11 ingress
  /// gate (`hick_onlink::admits_ingress`) does not take this field at all — it is
  /// carried here only so a caller/transport that has a hop-limit available can
  /// record or otherwise use it for its own purposes (logging, metrics, a
  /// stricter caller-side policy).
  pub hop_limit: Option<u8>,
  /// Number of payload bytes written into the receive buffer.
  pub len: usize,
}

/// Why [`UdpIo::try_send`] did not queue a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
  /// A socket for this family EXISTS but did not take the datagram this time, for
  /// a reason that may clear: a momentarily-full transmit queue, a socket not yet
  /// bound, or no route yet. The engine reports it
  /// [`FamilyAttempt::Refused`](mdns_proto::FamilyAttempt::Refused) with
  /// `permanent: false`, so the core keeps the family obligated — a fan-out where
  /// the other family succeeded is PARTIAL, not fully delivered — and retries it
  /// on the next pump.
  Busy,
  /// No socket for this datagram's address family — it will never be queued on
  /// this transport (e.g. an IPv6 group on a v4-only stack). The engine treats
  /// this as "this family is not applicable" and drops it from the obligated set
  /// entirely, so it must be reported ONLY for a family with no socket at all: an
  /// error raised BY an existing socket is [`Self::Busy`] or [`Self::TooLarge`],
  /// never this, or a half-broken dual-stack node would advertise as though it
  /// were single-stack.
  Unsupported,
  /// The datagram is larger than this socket's transmit buffer can ever hold — a
  /// PERMANENT failure for this packet (e.g. embassy-net's `PacketTooLarge`), not
  /// the momentary fullness of [`Self::Busy`]. The engine must NOT retry it
  /// forever; a service whose datagrams can never be sent is retired with an
  /// actionable update rather than left probing/announcing indefinitely.
  TooLarge,
}

/// A non-blocking UDP transport — the seam between the runtime-agnostic mDNS
/// engine and a concrete socket layer.
///
/// Implemented over a raw `smoltcp::socket::udp::Socket` in this crate, and
/// over embassy-net's `UdpSocket` in `hick-embassy`.
///
/// # Contract: exactly one interface per implementation
///
/// RFC 6762 §11's unicast on-link test is defined over "the interface
/// receiving the packet" (singular), but neither [`RecvMeta`] nor
/// [`Engine::set_local_addrs`](crate::Engine::set_local_addrs) carries or
/// is keyed by interface identity: an `Engine` holds one flat address list,
/// checked against every `RecvMeta::src` its `UdpIo` hands it, with no way to
/// tell which physical interface a datagram arrived on. An implementation
/// MUST therefore represent exactly one link: a `DualStack` / `DualUdp` over
/// one interface's v4 AND v6 sockets is fine (one link, two address
/// families); one that ALSO relays a second interface's socket(s) through the
/// same `UdpIo` is not — use two `Engine`s (each with its own `UdpIo` and
/// address list) instead, one per interface.
///
/// This is not runtime-checked, because there is nothing here to check it
/// against. Violating it is silent: a datagram received on interface A is
/// admitted because its source happens to fall inside interface B's
/// configured prefix, defeating the source comparison exactly where §11 relies
/// on it. See `crate::ingress`'s `aggregated_interfaces_defeat_the_source_arm`
/// for a pinned example.
pub trait UdpIo {
  /// Pull one queued datagram into `buf`, returning its metadata, or `None`
  /// when the receive queue is empty. Non-blocking.
  fn try_recv(&mut self, buf: &mut [u8]) -> Option<RecvMeta>;

  /// Enqueue one datagram for `dst`. Non-blocking; returns [`SendError::Busy`]
  /// when a socket for the family exists but did not take the datagram, or
  /// [`SendError::Unsupported`] when there is no socket for that family at all.
  ///
  /// # `Ok` means QUEUED, and the engine's spacing is measured from here
  ///
  /// Both transports behind this trait queue: smoltcp's `udp::Socket::send_slice`
  /// hands the datagram to a socket buffer that the caller's `Interface::poll`
  /// drains onto the device afterwards, and embassy-net's network task does the
  /// same. So the RFC 6762 spacing the engine enforces per family — §8.1 probes,
  /// §6 / §8.3 announcements, §5.2 query retransmissions, §10.1 goodbyes — is
  /// measured from THIS call and not from the device.
  ///
  /// Poll the interface promptly and the two coincide. Let it stall for longer
  /// than one of those floors and the engine, seeing only acceptances, can queue
  /// the next datagram while the previous one is still waiting; a single poll then
  /// puts both on the device back-to-back, inside the interval the RFC gives one
  /// interface. Bounding the device rather than the queue would take a per-family
  /// egress acknowledgement, which this seam deliberately does not have — an
  /// implementor owes only the honest `Ok`.
  fn try_send(&mut self, buf: &[u8], dst: SocketAddr) -> Result<(), SendError>;
}

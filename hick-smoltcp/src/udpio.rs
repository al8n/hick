//! The [`UdpIo`] transport seam between the engine and a concrete socket layer.

use core::net::{IpAddr, SocketAddr};

/// Normalized metadata for one received datagram.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
  /// Source endpoint (the sender).
  pub src: SocketAddr,
  /// The local/destination address the datagram arrived on, if the transport
  /// surfaces it: the mDNS group for multicast, our own address for unicast.
  pub local: Option<IpAddr>,
  /// The received IP TTL / IPv6 hop-limit, if the transport surfaces it.
  ///
  /// `Some(255)` is what RFC 6762 §11 requires of an on-link mDNS packet;
  /// `None` means the transport could not provide it and the §11 gate must
  /// fall back to a source-subnet heuristic.
  pub hop_limit: Option<u8>,
  /// Number of payload bytes written into the receive buffer.
  pub len: usize,
}

/// Why [`UdpIo::try_send`] did not queue a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
  /// A socket for this family EXISTS but did not take the datagram this time, for
  /// a reason that may clear: a momentarily-full transmit queue, a socket not yet
  /// bound, or no route yet. The engine keeps the family in the obligated set —
  /// so a fan-out where the other family succeeded projects to
  /// [`TransmitOutcome::PartiallyDelivered`](mdns_proto::TransmitOutcome::PartiallyDelivered),
  /// not `AllDelivered` — and retries on the next pump.
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
pub trait UdpIo {
  /// Pull one queued datagram into `buf`, returning its metadata, or `None`
  /// when the receive queue is empty. Non-blocking.
  fn try_recv(&mut self, buf: &mut [u8]) -> Option<RecvMeta>;

  /// Enqueue one datagram for `dst`. Non-blocking; returns [`SendError::Busy`]
  /// when a socket for the family exists but did not take the datagram, or
  /// [`SendError::Unsupported`] when there is no socket for that family at all.
  fn try_send(&mut self, buf: &[u8], dst: SocketAddr) -> Result<(), SendError>;
}

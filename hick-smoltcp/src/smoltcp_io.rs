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
    Ok((len, meta)) => {
      #[cfg(feature = "defmt")]
      defmt::trace!("smoltcp recv_from: {} bytes", len);
      Some(RecvMeta {
        src: meta.endpoint.into(),
        local: meta.local_address.map(Into::into),
        // smoltcp's `udp::Socket` UDP metadata (`UdpMetadata`) exposes no received
        // hop-limit — verified against 0.13.1 (only `endpoint` / `local_address` /
        // `meta`) — so this is diagnostic-only `None`; the engine's §11 RECEIVE
        // gate (`onlink::on_link`) does not take a hop-limit input at all. It
        // decides on destination and source alone: the mDNS group is admitted
        // outright (arrival at the group is its own §11 admission ground; a peer
        // outside your configured subnets is still on your link if its multicast
        // reached you); otherwise, for a non-group destination, subnet membership
        // decides; otherwise reject. The §11 TRANSMIT `SHOULD` (TTL 255 out) is
        // honoured separately in `send_from`, not here.
        hop_limit: None,
        len,
      })
    }
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
///
/// smoltcp's `Unaddressable` is ALSO [`SendError::Busy`], never
/// [`SendError::Unsupported`]. `Unsupported` means the family has no socket at
/// all and so was never obligated, which is why the engine excludes it from the
/// obligated set; but this socket demonstrably exists — smoltcp raises
/// `Unaddressable` when the socket's own local port is still zero (unbound) or
/// when the destination endpoint is unspecified. Reporting it as an absent family
/// would make a bound-v4 + present-but-unbound-v6 fan-out project to
/// `AllDelivered`, advancing RFC 6762 §8.1 probing as though IPv6 did not exist.
/// `Busy` keeps the family obligated and not-delivered, so the fan-out projects to
/// `PartiallyDelivered` and the phase waits — and it is retried, which is right
/// for a binding that may still complete. This matches `hick-embassy`, which maps
/// embassy-net's `SocketNotBound` / `NoRoute` the same way.
fn send_from(socket: &mut udp::Socket<'_>, buf: &[u8], dst: SocketAddr) -> Result<(), SendError> {
  if buf.len() > socket.payload_send_capacity() {
    return Err(SendError::TooLarge);
  }
  #[cfg(feature = "defmt")]
  defmt::trace!("smoltcp send_from: {} bytes", buf.len());
  // RFC 6762 §11: responses SHOULD leave with IP TTL / hop-limit 255 — a
  // recommendation for backwards-compatibility with OLDER queriers implementing
  // the February-2004 draft, which discard everything but 255 on reception. A
  // modern §11-conformant receiver's on-link test (the same gate
  // `onlink::on_link` applies on RX) never consults the received hop-limit at
  // all. smoltcp dispatches a UDP datagram with the socket's configured
  // hop-limit and DEFAULTS it to 64 when unset, so a probe/announcement/goodbye
  // would otherwise egress at 64 and those older queriers would silently drop
  // it — the API would appear to transmit while some listeners never see it.
  // Force 255 here at the single send choke point (idempotent — a plain field set on
  // the value smoltcp reads at egress) rather than trusting every caller to have
  // configured both sockets; `hick-embassy`'s driver honours the same `SHOULD` via
  // `set_hop_limit(Some(255))` once at startup (it holds the sockets by `&mut` there),
  // and the smoltcp sockets are reached only through this transport, so enforce per-send.
  socket.set_hop_limit(Some(255));
  match socket.send_slice(buf, IpEndpoint::from(dst)) {
    Ok(()) => Ok(()),
    Err(udp::SendError::BufferFull) => Err(SendError::Busy),
    Err(udp::SendError::Unaddressable) => Err(SendError::Busy),
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
/// `engine.pump(now, &mut DualStack::new(sockets, Some(h4), Some(h6)), buf)`,
/// where `now` is your clock ITSELF (a `FnMut() -> SmoltcpInstant`) rather than a
/// reading of it.
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
mod tests;

//! [`UdpIo`] over embassy-net UDP sockets, via the family-aware [`DualUdp`].
//!
//! The engine fans every multicast to BOTH the v4 and v6 groups, so the transport
//! must be family-aware: a datagram of one family must reach a socket of THAT
//! family, and an absent family must report [`SendError::Unsupported`]. A single
//! embassy-net `UdpSocket` is family-ambiguous (it accepts a port-only bind and
//! does not reject a wrong-family destination — the datagram is enqueued and later
//! dropped/panics while the engine has already confirmed it). So this crate does
//! NOT expose a raw single-socket `UdpIo`; use [`DualUdp`], giving the v4 and/or v6
//! socket explicitly (leave one `None` for a single-stack node).

use core::{
  net::{IpAddr, Ipv4Addr, SocketAddr},
  task::{Context, Poll, Waker},
};

use embassy_futures::select::select;
use embassy_net::{IpEndpoint, udp::UdpSocket};
use hick_smoltcp::{RecvMeta, SendError, UdpIo};

/// embassy-net 0.9 exposes only async + `poll_*` UDP methods (no `try_*`), so the
/// non-blocking [`UdpIo`] ops drive `poll_recv_from` / `poll_send_to` with a no-op
/// waker. The driver re-registers the real recv waker via `wait_recv_ready` after
/// every pump, so the transient no-op registration here is always overwritten
/// before the task parks.
fn recv_from(socket: &UdpSocket<'_>, buf: &mut [u8]) -> Option<RecvMeta> {
  let mut cx = Context::from_waker(Waker::noop());
  match socket.poll_recv_from(buf, &mut cx) {
    Poll::Ready(Ok((len, meta))) => Some(RecvMeta {
      src: meta.endpoint.into(),
      local: meta.local_address.map(Into::into),
      // embassy-net (like smoltcp) doesn't surface the received hop-limit yet, so
      // this is diagnostic-only `None`; the engine's §11 gate does not take a
      // hop-limit input at all. It decides on destination and source alone: the
      // mDNS group is admitted outright (arrival at the group is its own §11
      // admission ground; a peer outside your configured subnets is still on
      // your link if its multicast reached you); otherwise, for a non-group
      // destination, subnet membership decides; otherwise reject.
      hop_limit: None,
      len,
    }),
    // `RecvError::Truncated` (the only `Poll::Ready(Err)`): an oversized datagram was
    // DROPPED (already dequeued). Surface a zero-length marker — like the smoltcp
    // transport — so the drop counts against the engine's per-pump RX cap and
    // the drain continues instead of stopping early; the engine treats len 0 as
    // nothing to deliver.
    Poll::Ready(Err(_)) => Some(RecvMeta {
      src: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
      local: None,
      hop_limit: None,
      len: 0,
    }),
    // No datagram queued.
    Poll::Pending => None,
  }
}

/// Enqueue one datagram on `socket` for `dst` — which [`DualUdp`] has already routed
/// to this socket's family, so there is no wrong-family hazard here.
fn send_from(socket: &UdpSocket<'_>, buf: &[u8], dst: SocketAddr) -> Result<(), SendError> {
  use embassy_net::udp::SendError as EmbassySendError;
  let mut cx = Context::from_waker(Waker::noop());
  match socket.poll_send_to(buf, IpEndpoint::from(dst), &mut cx) {
    Poll::Ready(Ok(())) => Ok(()),
    // Transmit buffer full — transient; retry on the next pump.
    Poll::Pending => Err(SendError::Busy),
    // The send buffer is too small to EVER fit this datagram — permanent, not
    // momentary fullness. Surface it so the engine retires the service instead of
    // retrying a packet that can never be queued (a TX-buffer misconfig).
    Poll::Ready(Err(EmbassySendError::PacketTooLarge)) => Err(SendError::TooLarge),
    // NoRoute / SocketNotBound: the socket exists but the send failed for a reason
    // that may clear (route comes up, binding completes). Not an absent family, so
    // not `Unsupported`; treat as `Busy` and retry on the next pump.
    Poll::Ready(Err(_)) => Err(SendError::Busy),
  }
}

/// A family-aware [`UdpIo`] over an IPv4 and/or IPv6 embassy-net socket — the
/// embassy transport (single- OR dual-stack).
///
/// The engine fans every multicast to BOTH groups, so each datagram must reach the
/// socket of ITS OWN family. `try_send` routes by the destination's family and
/// reports [`SendError::Unsupported`] for an absent family (the engine then confirms
/// on the family it has); `try_recv` alternates the two sockets round-robin so a
/// sustained backlog on one family cannot starve the other under the engine's
/// per-pump RX cap. For a single-stack node, leave the absent family `None`.
///
/// The socket-buffer lifetime (`'sock`) and the borrow lifetime (`'b`) are distinct so
/// the driver can keep the sockets as `&mut` (to enforce the §11 egress hop-limit at
/// setup) and still hand this view a short per-pump shared reborrow of them.
pub struct DualUdp<'sock, 'b> {
  v4: Option<&'b UdpSocket<'sock>>,
  v6: Option<&'b UdpSocket<'sock>>,
  /// Which family to poll FIRST on the next `try_recv`, toggled each call so the two
  /// families are drained round-robin. Per-pump (a fresh `DualUdp` resets it)
  /// is enough: the RX cap is per-pump, so alternating within each pump serves both.
  take_v6_first: bool,
}

impl<'sock, 'b> DualUdp<'sock, 'b> {
  /// Build the transport view for one pump step over a v4 and/or v6 socket. Pass
  /// `None` for an absent family on a single-stack node.
  pub fn new(v4: Option<&'b UdpSocket<'sock>>, v6: Option<&'b UdpSocket<'sock>>) -> Self {
    Self {
      v4,
      v6,
      take_v6_first: false,
    }
  }
}

impl UdpIo for DualUdp<'_, '_> {
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
    if let Some(socket) = first
      && let Some(meta) = recv_from(socket, buf)
    {
      return Some(meta);
    }
    if let Some(socket) = second {
      return recv_from(socket, buf);
    }
    None
  }

  fn try_send(&mut self, buf: &[u8], dst: SocketAddr) -> Result<(), SendError> {
    let socket = if dst.is_ipv4() { self.v4 } else { self.v6 };
    match socket {
      Some(socket) => send_from(socket, buf, dst),
      // No socket for this address family: it will never queue here. Report
      // unsupported (not busy) so the engine confirms on the family it has, instead
      // of waiting to retry a family that can never send.
      None => Err(SendError::Unsupported),
    }
  }
}

/// Await recv-readiness on whichever of the v4 / v6 sockets are present (pending
/// forever if neither is — a degenerate no-transport config).
pub(crate) async fn wait_either_recv(v4: Option<&UdpSocket<'_>>, v6: Option<&UdpSocket<'_>>) {
  match (v4, v6) {
    (Some(a), Some(b)) => {
      let _ = select(a.wait_recv_ready(), b.wait_recv_ready()).await;
    }
    (Some(a), None) => a.wait_recv_ready().await,
    (None, Some(b)) => b.wait_recv_ready().await,
    (None, None) => core::future::pending::<()>().await,
  }
}

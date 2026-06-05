//! The async mDNS driver loop for embassy.

use embassy_futures::select::select;
use embassy_net::udp::UdpSocket;
use embassy_time::{Instant, Timer};
use hick_smoltcp::Engine;
use rand_core::Rng;

use crate::{
  io::{DualUdp, wait_either_recv},
  time::EmbassyInstant,
};

/// Run the mDNS driver loop over a bound IPv4 and/or IPv6 embassy-net
/// [`UdpSocket`] until the task is dropped. Never returns.
///
/// The engine fans every multicast to BOTH groups, so pass the v4 and/or v6 socket
/// separately (a [`DualUdp`] routes by family); leave a family `None` for a
/// single-stack node. Do NOT share one socket for both families — that re-creates
/// the wrong-family-enqueue hazard.
///
/// Takes the sockets by `&mut` so it can ENFORCE the RFC 6762 §11 transmit invariant
/// (hop-limit 255 on every outgoing mDNS packet) once at startup: embassy-net creates
/// UDP sockets with hop-limit `None`, which smoltcp egresses as 64, and a conformant
/// peer rejects anything but 255 — so a node would otherwise look established while
/// being invisible. The `DualUdp` send path holds only shared `&UdpSocket`, so this is
/// the point that still has the `&mut` needed to call `set_hop_limit`.
///
/// The caller must, before spawning this, for each socket present:
/// - `socket.bind(5353)`,
/// - join the matching mDNS group via `Stack::join_multicast_group`
///   (`224.0.0.251` for v4, `ff02::fb` for v6),
/// - register services / start queries on `engine`.
///
/// The loop pumps `engine` whenever a datagram arrives or the next protocol
/// deadline elapses, racing recv-readiness against the deadline timer.
pub async fn run<R: Rng>(
  mut v4: Option<&mut UdpSocket<'_>>,
  mut v6: Option<&mut UdpSocket<'_>>,
  mut engine: Engine<EmbassyInstant, R>,
  scratch: &mut [u8],
) -> ! {
  // RFC 6762 §11: force hop-limit 255 on egress while we still hold `&mut` (the pump's
  // `DualUdp` send path has only shared `&UdpSocket`, and `set_hop_limit` needs `&mut`).
  if let Some(s) = v4.as_deref_mut() {
    s.set_hop_limit(Some(255));
    #[cfg(feature = "defmt")]
    defmt::debug!("hick-embassy: v4 hop-limit set to 255 (RFC 6762 §11)");
  }
  if let Some(s) = v6.as_deref_mut() {
    s.set_hop_limit(Some(255));
    #[cfg(feature = "defmt")]
    defmt::debug!("hick-embassy: v6 hop-limit set to 255 (RFC 6762 §11)");
  }
  loop {
    let now = EmbassyInstant(Instant::now());
    let deadline = {
      let mut io = DualUdp::new(v4.as_deref(), v6.as_deref());
      engine.pump(now, &mut io, scratch)
    };
    match deadline {
      Some(d) => {
        #[cfg(feature = "defmt")]
        defmt::trace!("hick-embassy: waiting for recv or deadline timer");
        let _ = select(
          wait_either_recv(v4.as_deref(), v6.as_deref()),
          Timer::at(d.0),
        )
        .await;
      }
      // No scheduled work — wake only when a datagram arrives.
      None => {
        #[cfg(feature = "defmt")]
        defmt::trace!("hick-embassy: no deadline, waiting for recv");
        wait_either_recv(v4.as_deref(), v6.as_deref()).await;
      }
    }
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

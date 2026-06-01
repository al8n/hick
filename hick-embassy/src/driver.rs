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
  }
  if let Some(s) = v6.as_deref_mut() {
    s.set_hop_limit(Some(255));
  }
  loop {
    let now = EmbassyInstant(Instant::now());
    let deadline = {
      let mut io = DualUdp::new(v4.as_deref(), v6.as_deref());
      engine.pump(now, &mut io, scratch)
    };
    match deadline {
      Some(d) => {
        let _ = select(
          wait_either_recv(v4.as_deref(), v6.as_deref()),
          Timer::at(d.0),
        )
        .await;
      }
      // No scheduled work — wake only when a datagram arrives.
      None => wait_either_recv(v4.as_deref(), v6.as_deref()).await,
    }
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
  use core::task::Context;

  use embassy_net::{
    Config, Ipv4Address, Ipv4Cidr, StackResources, StaticConfigV4,
    driver::{Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken},
    udp::{PacketMetadata, UdpSocket},
  };
  use embassy_time::{Duration, Instant, Timer};
  use futures::executor::block_on;
  use hick_smoltcp::Engine;
  use mdns_proto::{EndpointConfig, Name, ServiceRecords, ServiceSpec};
  use rand::{SeedableRng, rngs::StdRng};

  use super::run;
  use crate::{MdnsState, time::EmbassyInstant};

  /// A do-nothing embassy-net device: link always up, transmit discards bytes,
  /// never receives. Enough to construct a `Stack` + `UdpSocket` so the run loop
  /// and the `DualUdp` transport execute end to end — `poll_send_to` buffers into
  /// the socket and returns `Ready(Ok)` without the device having to egress.
  struct NullDriver;
  struct NullRx;
  struct NullTx;

  impl RxToken for NullRx {
    fn consume<R, F>(self, f: F) -> R
    where
      F: FnOnce(&mut [u8]) -> R,
    {
      f(&mut [])
    }
  }

  impl TxToken for NullTx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
      F: FnOnce(&mut [u8]) -> R,
    {
      let mut buf = alloc::vec![0u8; len];
      f(&mut buf)
    }
  }

  impl Driver for NullDriver {
    type RxToken<'a> = NullRx;
    type TxToken<'a> = NullTx;

    fn receive(&mut self, _cx: &mut Context<'_>) -> Option<(NullRx, NullTx)> {
      None
    }
    fn transmit(&mut self, _cx: &mut Context<'_>) -> Option<NullTx> {
      Some(NullTx)
    }
    fn link_state(&mut self, _cx: &mut Context<'_>) -> LinkState {
      LinkState::Up
    }
    fn capabilities(&self) -> Capabilities {
      let mut caps = Capabilities::default();
      caps.max_transmission_unit = 1514;
      caps
    }
    fn hardware_address(&self) -> HardwareAddress {
      HardwareAddress::Ethernet([0x02, 0, 0, 0, 0, 1])
    }
  }

  fn http_service() -> ServiceSpec {
    let mut recs = ServiceRecords::new(
      Name::try_from_str("_http._tcp.local.").unwrap(),
      Name::try_from_str("Dev._http._tcp.local.").unwrap(),
      Name::try_from_str("dev.local.").unwrap(),
      80,
      120,
    );
    recs.add_a([169, 254, 1, 1].into());
    ServiceSpec::new(recs)
  }

  /// Drive the free `run` loop over a v4-only embassy-net socket for ~1.2s. A
  /// registered service makes the engine probe, so `pump` fans transmits to the
  /// v4 socket (`Ready(Ok)`) AND the absent v6 family (`Unsupported`) — covering
  /// both `DualUdp::try_send` arms — while `try_recv` stays `Pending` and the
  /// loop races recv-readiness against the protocol deadline timer.
  #[test]
  fn free_run_loop_pumps_over_a_v4_socket() {
    let mut resources = StackResources::<2>::new();
    let config = Config::ipv4_static(StaticConfigV4 {
      address: Ipv4Cidr::new(Ipv4Address::new(169, 254, 1, 1), 16),
      gateway: None,
      dns_servers: Default::default(),
    });
    let (stack, _runner) = embassy_net::new(NullDriver, config, &mut resources, 0x1234_5678);

    let mut rx_meta = [PacketMetadata::EMPTY; 8];
    let mut rx_buf = [0u8; 2048];
    let mut tx_meta = [PacketMetadata::EMPTY; 8];
    let mut tx_buf = [0u8; 2048];
    let mut sock = UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    sock.bind(5353).unwrap();

    let mut engine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(9));
    engine
      .register_service(http_service(), EmbassyInstant(Instant::now()))
      .unwrap();

    let mut scratch = [0u8; 1500];
    block_on(async {
      let _ = embassy_futures::select::select(
        run(Some(&mut sock), None, engine, &mut scratch),
        Timer::after(Duration::from_millis(1200)),
      )
      .await;
    });
  }

  /// Same, but through the `MdnsState` handle API: register via the shared state,
  /// then drive `MdnsState::run` (the `RefCell`-engine + wake-signal loop).
  #[test]
  fn mdns_state_run_loop_pumps_over_a_v4_socket() {
    let mut resources = StackResources::<2>::new();
    let config = Config::ipv4_static(StaticConfigV4 {
      address: Ipv4Cidr::new(Ipv4Address::new(169, 254, 1, 2), 16),
      gateway: None,
      dns_servers: Default::default(),
    });
    let (stack, _runner) = embassy_net::new(NullDriver, config, &mut resources, 0x9abc_def0);

    let mut rx_meta = [PacketMetadata::EMPTY; 8];
    let mut rx_buf = [0u8; 2048];
    let mut tx_meta = [PacketMetadata::EMPTY; 8];
    let mut tx_buf = [0u8; 2048];
    let mut sock = UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    sock.bind(5353).unwrap();

    let state = MdnsState::new(EndpointConfig::new(), StdRng::seed_from_u64(11));
    state.register_service(http_service()).unwrap();

    let mut scratch = [0u8; 1500];
    block_on(async {
      let _ = embassy_futures::select::select(
        state.run(Some(&mut sock), None, &mut scratch),
        Timer::after(Duration::from_millis(1200)),
      )
      .await;
    });
  }
}

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

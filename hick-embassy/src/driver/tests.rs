use alloc::vec::Vec;
use core::{net::SocketAddr, task::Context};

use embassy_net::{
  Config, Ipv4Address, Ipv4Cidr, StackResources, StaticConfigV4,
  driver::{Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken},
  udp::{PacketMetadata, UdpSocket},
};
use embassy_time::{Duration, Instant, Timer};
use futures::executor::block_on;
use hick_smoltcp::{
  Engine, RecvMeta, SendError, UdpIo,
  constants::{MDNS_SOCKET_V4, MDNS_SOCKET_V6},
};
use mdns_proto::{EndpointConfig, Name, ServiceRecords, ServiceSpec, event::ServiceUpdate};
use rand::{SeedableRng, rngs::StdRng};

use super::run;
use crate::{MdnsState, io::DualUdp, time::EmbassyInstant};

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

// ── Delivery-outcome behaviour over hick-embassy's own transport ────────────
//
// `hick-embassy` contributes exactly one input to the `TransmitDelivery` the
// engine reports: which per-family `SendError` each socket produces. That single
// mapping decides whether a family is in the obligated set at all — an absent
// family (`Unsupported`) is not obligated, so a single-stack node is
// all-delivered, whereas a present-but-failing one (`Busy`) is obligated and
// missing, which is what makes a fan-out partial. Everything downstream is the
// shared `hick-smoltcp` engine, so these tests drive the real `DualUdp` over
// real embassy-net sockets and observe the four delivery behaviours end to end.

/// Build a dual-stack `Stack` in the CALLER's frame — the resources and socket
/// buffers must outlive the sockets, so they cannot be returned from a function.
/// Declares `$v4` and `$v6` as unbound [`UdpSocket`]s; each test binds only the
/// families it wants reachable, since an UNBOUND socket is exactly embassy-net's
/// `SocketNotBound` → [`SendError::Busy`] (present, obligated, not delivering).
macro_rules! dual_stack_sockets {
  ($v4:ident, $v6:ident, $addr:expr, $seed:expr) => {
    let mut resources = StackResources::<4>::new();
    let (stack, _runner) = embassy_net::new(
      NullDriver,
      Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::new(169, 254, 1, $addr), 16),
        gateway: None,
        dns_servers: Default::default(),
      }),
      &mut resources,
      $seed,
    );
    // Sized for a whole probe + announce lifecycle: nothing drains these queues
    // (the stack runner is never polled here), so every datagram the engine
    // queues stays buffered for the duration of the test.
    let mut rx_meta4 = [PacketMetadata::EMPTY; 8];
    let mut rx_buf4 = [0u8; 2048];
    let mut tx_meta4 = [PacketMetadata::EMPTY; 64];
    let mut tx_buf4 = [0u8; 16384];
    #[allow(unused_mut)]
    let mut $v4 = UdpSocket::new(
      stack,
      &mut rx_meta4,
      &mut rx_buf4,
      &mut tx_meta4,
      &mut tx_buf4,
    );
    let mut rx_meta6 = [PacketMetadata::EMPTY; 8];
    let mut rx_buf6 = [0u8; 2048];
    let mut tx_meta6 = [PacketMetadata::EMPTY; 64];
    let mut tx_buf6 = [0u8; 16384];
    #[allow(unused_mut)]
    let mut $v6 = UdpSocket::new(
      stack,
      &mut rx_meta6,
      &mut rx_buf6,
      &mut tx_meta6,
      &mut tx_buf6,
    );
  };
}

/// A [`UdpIo`] that delegates every call to the real [`DualUdp`] and logs the
/// datagrams that were actually queued. The delivery facts still come from
/// hick-embassy's own family routing and embassy-net's own error mapping; this
/// only makes what the socket accepted visible to a test.
struct Recording<'sock, 'b> {
  inner: DualUdp<'sock, 'b>,
  sent: Vec<(SocketAddr, Vec<u8>)>,
}

impl<'sock, 'b> Recording<'sock, 'b> {
  fn new(v4: Option<&'b UdpSocket<'sock>>, v6: Option<&'b UdpSocket<'sock>>) -> Self {
    Self {
      inner: DualUdp::new(v4, v6),
      sent: Vec::new(),
    }
  }

  fn hit(&self, group: SocketAddr) -> usize {
    self.sent.iter().filter(|(dst, _)| *dst == group).count()
  }
}

impl UdpIo for Recording<'_, '_> {
  fn try_recv(&mut self, buf: &mut [u8]) -> Option<RecvMeta> {
    self.inner.try_recv(buf)
  }

  fn try_send(&mut self, buf: &[u8], dst: SocketAddr) -> Result<(), SendError> {
    let result = self.inner.try_send(buf, dst);
    if result.is_ok() {
      self.sent.push((dst, buf.to_vec()));
    }
    result
  }
}

/// A synthetic instant, so a lifecycle that spans seconds of protocol time runs
/// in microseconds of test time. `Engine` is generic over the clock and `pump`
/// is synchronous, so no executor or real timer is involved.
fn at(micros: u64) -> EmbassyInstant {
  EmbassyInstant(Instant::from_micros(micros))
}

/// `Some(true)` if the datagram carries at least one TTL=0 answer (an RFC 6762
/// §10.1 goodbye), `Some(false)` if it carries only positive-TTL answers, `None`
/// if it has no parseable answers (a probe or a query).
fn carries_goodbye(bytes: &[u8]) -> bool {
  use mdns_proto::wire::MessageReader;
  let Ok(reader) = MessageReader::try_parse(bytes) else {
    return false;
  };
  reader.answers().flatten().any(|rec| rec.ttl() == 0)
}

/// Pump the engine over `io` at a 250 ms cadence for `steps` rounds, draining
/// service updates like a real host loop. Returns `(established, next_micros)`.
fn pump_for(
  engine: &mut Engine<EmbassyInstant, StdRng>,
  io: &mut Recording<'_, '_>,
  handle: mdns_proto::ServiceHandle,
  from_micros: u64,
  steps: usize,
) -> (bool, u64) {
  let mut scratch = [0u8; 1500];
  let mut t = from_micros;
  let mut established = false;
  for _ in 0..steps {
    t += 250_000;
    engine.pump(|| at(t), io, &mut scratch);
    while let Some(update) = engine.poll_service_update(handle) {
      established |= matches!(update, ServiceUpdate::Established);
    }
  }
  (established, t)
}

/// Rounds that comfortably cover a §8.1 + §8.3 startup at this 250 ms cadence —
/// the budget every lifecycle case here is given.
///
/// A permanently-partial startup fits too: the core's patience is spent ONCE on a
/// family that never comes back, so such a run establishes a handful of rounds
/// after a fully-delivered one rather than an order of magnitude later. The two
/// are separated by comparing them ([`rounds_to_established`]) rather than by
/// tuning this budget to fall between them.
const HEALTHY_ROUNDS: usize = 24;

/// Pump one round at a time until the service reports `Established`. Returns the
/// round it arrived on — `None` if `limit` rounds pass without it — and the
/// instant the run ended at.
fn rounds_to_established(
  engine: &mut Engine<EmbassyInstant, StdRng>,
  io: &mut Recording<'_, '_>,
  handle: mdns_proto::ServiceHandle,
  limit: usize,
) -> (Option<usize>, u64) {
  let mut t = 0u64;
  for round in 1..=limit {
    let (established, next) = pump_for(engine, io, handle, t, 1);
    t = next;
    if established {
      return (Some(round), t);
    }
  }
  (None, t)
}

#[test]
fn dual_udp_separates_an_absent_family_from_a_failing_one() {
  // The one fact this crate contributes to the delivery outcome. An absent
  // family must NOT look like a failing one: `Unsupported` keeps it out of the
  // obligated set (so a single-stack node is all-delivered and advances at full
  // speed), while a present-but-unusable socket reports `Busy` and stays
  // obligated (so the fan-out is partial and the phase must wait).
  dual_stack_sockets!(v4, v6, 21, 0x1111_2222);
  v4.bind(5353).unwrap();
  // `v6` is deliberately left unbound: embassy-net answers `SocketNotBound`.

  let mut absent = DualUdp::new(Some(&v4), None);
  assert!(
    absent.try_send(b"datagram", MDNS_SOCKET_V4).is_ok(),
    "a bound socket must queue its own family's datagram"
  );
  assert_eq!(
    absent.try_send(b"datagram", MDNS_SOCKET_V6),
    Err(SendError::Unsupported),
    "no socket for a family means it was never obligated — not that it failed"
  );

  let mut failing = DualUdp::new(Some(&v4), Some(&v6));
  assert_eq!(
    failing.try_send(b"datagram", MDNS_SOCKET_V6),
    Err(SendError::Busy),
    "a socket that exists but cannot send is obligated and missing, so the \
     fan-out is partial rather than whole"
  );
}

#[test]
fn a_fully_delivered_fan_out_latches_ownership_and_advances_the_phase() {
  // Both families queue every datagram: no round is ever partial, so the phase
  // advances on every confirm and goodbye ownership latches for the records both
  // groups carried.
  dual_stack_sockets!(v4, v6, 22, 0x2222_3333);
  v4.bind(5353).unwrap();
  v6.bind(5353).unwrap();

  let mut engine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(41));
  let handle = engine.register_service(http_service(), at(0)).unwrap();
  let mut io = Recording::new(Some(&v4), Some(&v6));

  let (established, t) = pump_for(&mut engine, &mut io, handle, 0, HEALTHY_ROUNDS);
  assert!(
    established,
    "a dual-stack node whose every fan-out is whole must reach Established"
  );
  assert!(
    io.hit(MDNS_SOCKET_V4) > 0 && io.hit(MDNS_SOCKET_V6) > 0,
    "both groups must have carried datagrams; v4={} v6={}",
    io.hit(MDNS_SOCKET_V4),
    io.hit(MDNS_SOCKET_V6)
  );

  // Ownership latched → the unregister actually retracts, with a TTL=0 goodbye.
  engine.unregister_service(handle, at(t));
  io.sent.clear();
  let _ = pump_for(&mut engine, &mut io, handle, t, 4);
  assert!(
    io.sent.iter().any(|(_, d)| carries_goodbye(d)),
    "an announced service owns its records, so its withdrawal emits a §10.1 \
     TTL=0 goodbye"
  );
}

#[test]
fn a_partial_fan_out_latches_ownership_without_advancing_the_phase() {
  // v4 queues, v6 exists but cannot send. Ownership must latch for what v4 sent,
  // while the §8.1/§8.3 phase must NOT advance on the rounds the
  // core is still waiting for v6.
  //
  // The yardstick is the SAME schedule with nothing held back, run here under the
  // same seed, and the discriminator is the difference between the two rather than
  // a window tuned to fall between them. A driver that laundered the busy socket
  // into an all-delivered round would establish on the healthy round exactly;
  // holding the phase honestly costs the core's patience and nothing more, because
  // that patience is charged once for a family that never comes back. Re-charging
  // it at every phase would be paid in §8.3 ladder rungs on the link that works,
  // and stretched this run by an order of magnitude.
  let healthy = {
    dual_stack_sockets!(h4, h6, 26, 0x3333_4444);
    h4.bind(5353).unwrap();
    h6.bind(5353).unwrap();
    let mut engine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(42));
    let handle = engine.register_service(http_service(), at(0)).unwrap();
    let mut io = Recording::new(Some(&h4), Some(&h6));
    rounds_to_established(&mut engine, &mut io, handle, HEALTHY_ROUNDS)
      .0
      .expect("a whole fan-out establishes inside the budget")
  };

  dual_stack_sockets!(v4, v6, 23, 0x3333_4444);
  v4.bind(5353).unwrap();

  let mut engine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(42));
  let handle = engine.register_service(http_service(), at(0)).unwrap();
  let mut io = Recording::new(Some(&v4), Some(&v6));

  let (partial, t) = rounds_to_established(&mut engine, &mut io, handle, HEALTHY_ROUNDS);
  let partial = partial.expect(
    "the core's patience is spent once, so a permanently-partial fan-out must \
     still establish inside the budget a healthy one is given",
  );
  assert!(
    partial > healthy,
    "a partial fan-out must hold the phase while the core is still waiting for \
     the missing family; establishing on the healthy round {healthy} exactly \
     would mean the busy socket had been laundered into an all-delivered round"
  );
  assert!(
    io.hit(MDNS_SOCKET_V4) > 0,
    "the reachable family must still be carrying datagrams"
  );
  assert_eq!(
    io.hit(MDNS_SOCKET_V6),
    0,
    "the unusable family must never queue anything"
  );

  // …and yet the records v4 queued ARE owned: v4 peers may hold them,
  // so the withdrawal must retract them.
  engine.unregister_service(handle, at(t));
  io.sent.clear();
  let _ = pump_for(&mut engine, &mut io, handle, t, 4);
  assert!(
    io.sent.iter().any(|(_, d)| carries_goodbye(d)),
    "a partially-delivered advertisement still exposes its records to the \
     served family, so goodbye ownership must have latched"
  );
}

#[test]
fn a_wholly_failed_fan_out_neither_latches_nor_advances() {
  // Neither socket can send: nothing reaches a wire, so no peer holds anything
  // and no link has been asked or told. Nothing may latch and nothing may
  // advance — and the bounded policy must not launder this into an advance
  // either, since no family delivered for another to be excused against.
  dual_stack_sockets!(v4, v6, 24, 0x4444_5555);

  let mut engine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(43));
  let handle = engine.register_service(http_service(), at(0)).unwrap();
  let mut io = Recording::new(Some(&v4), Some(&v6));

  let (established, t) = pump_for(&mut engine, &mut io, handle, 0, HEALTHY_ROUNDS * 4);
  assert!(
    io.sent.is_empty(),
    "no datagram may reach a wire when neither socket can send"
  );
  assert!(
    !established,
    "a service whose datagrams never leave the host must not reach Established"
  );

  // Nothing was exposed, so the withdrawal has nothing to retract — it must not
  // TTL=0 records no peer ever saw. Bind v4 first so a goodbye COULD be sent.
  engine.unregister_service(handle, at(t));
  v4.bind(5353).unwrap();
  let mut io = Recording::new(Some(&v4), Some(&v6));
  let _ = pump_for(&mut engine, &mut io, handle, t, 8);
  assert!(
    !io.sent.iter().any(|(_, d)| carries_goodbye(d)),
    "an unexposed service owns nothing, so its withdrawal emits no goodbye"
  );
}

#[test]
fn the_bounded_partial_policy_fires_instead_of_pinning_the_phase() {
  // The core's patience bound, observed through this crate's transport: a family
  // that never accepts a datagram would otherwise hold the service in probing
  // forever, because a partial transmit re-arms losslessly and advances nothing.
  // Given enough rounds the core excuses the missing family and the service
  // establishes on the one it has.
  dual_stack_sockets!(v4, v6, 25, 0x5555_6666);
  v4.bind(5353).unwrap();

  let mut engine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(44));
  let handle = engine.register_service(http_service(), at(0)).unwrap();
  let mut io = Recording::new(Some(&v4), Some(&v6));

  let (established, _) = pump_for(&mut engine, &mut io, handle, 0, 400);
  assert!(
    established,
    "the core's patience bound must eventually excuse a family that never \
     delivers, instead of pinning the lifecycle forever"
  );
  assert_eq!(
    io.hit(MDNS_SOCKET_V6),
    0,
    "the excused family is still attempted every round but never queues a byte"
  );
}

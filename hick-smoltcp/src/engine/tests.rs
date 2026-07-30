use alloc::{collections::VecDeque, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use mdns_proto::{Name, ServiceRecords, ServiceSpec, ServiceState};
use rand::{SeedableRng, rngs::StdRng};
use smoltcp::time::Instant as RawInstant;

use super::*;
use crate::{
  SmoltcpInstant,
  constants::{MDNS_SOCKET_V4, MDNS_SOCKET_V6},
  udpio::{RecvMeta, SendError, UdpIo},
};

/// In-memory transport: a queue of inbound datagrams + a log of sent ones.
/// `v4_fail` / `v6_fail` make sends to that family return the given
/// [`SendError`] instead of being queued + logged (`None` = queued).
#[derive(Default)]
struct MockUdp {
  inbound: VecDeque<(Vec<u8>, RecvMeta)>,
  sent: Vec<(SocketAddr, Vec<u8>)>,
  v4_fail: Option<SendError>,
  v6_fail: Option<SendError>,
  /// Remaining TX slots for this poll cycle (`None` = unlimited). A test refills
  /// it before each pump to model a transport that fits only one datagram per
  /// cycle; the extra send in a fan-out then reports `Busy`.
  capacity: Option<usize>,
  /// Every `try_send` call, whether or not it queued. `sent` only records the
  /// ones that did, so a test that must observe a fan-out ROUND on a failing
  /// family has to count attempts instead.
  attempts: usize,
}

impl UdpIo for MockUdp {
  fn try_recv(&mut self, buf: &mut [u8]) -> Option<RecvMeta> {
    let (data, mut meta) = self.inbound.pop_front()?;
    let n = data.len().min(buf.len());
    buf[..n].copy_from_slice(&data[..n]);
    meta.len = n;
    Some(meta)
  }

  fn try_send(&mut self, buf: &[u8], dst: SocketAddr) -> Result<(), SendError> {
    self.attempts += 1;
    if let Some(err) = if dst.is_ipv4() {
      self.v4_fail
    } else {
      self.v6_fail
    } {
      return Err(err);
    }
    if let Some(slots) = self.capacity.as_mut() {
      if *slots == 0 {
        return Err(SendError::Busy);
      }
      *slots -= 1;
    }
    self.sent.push((dst, buf.to_vec()));
    Ok(())
  }
}

/// The engine shape every test in this module builds: the smoltcp clock and a
/// seeded RNG, over the crate's fixed slab-backed pools.
type TestEngine = Engine<SmoltcpInstant, StdRng>;
/// A log of `(destination, datagram)` pairs a [`MockUdp`] queued.
type SentLog = Vec<(SocketAddr, Vec<u8>)>;

fn at(micros: i64) -> SmoltcpInstant {
  SmoltcpInstant(RawInstant::from_micros(micros))
}

fn sample_spec() -> ServiceSpec {
  let service_type = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let instance = Name::try_from_str("Test._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("test.local.").unwrap();
  let mut records = ServiceRecords::new(service_type, instance, host, 631, 120);
  records.add_a(Ipv4Addr::new(192, 168, 1, 10));
  ServiceSpec::new(records)
}

/// A spec with explicit type / instance / host and one A address — for
/// same-host sibling tests.
fn spec_for(service_type: &str, instance: &str, host: &str, addr: Ipv4Addr) -> ServiceSpec {
  let mut records = ServiceRecords::new(
    Name::try_from_str(service_type).unwrap(),
    Name::try_from_str(instance).unwrap(),
    Name::try_from_str(host).unwrap(),
    631,
    120,
  );
  records.add_a(addr);
  ServiceSpec::new(records)
}

#[test]
fn registering_a_service_emits_a_probe_to_the_mdns_group() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(1));
  engine.register_service(sample_spec(), at(0)).unwrap();

  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  // Advance time past the §8.1 probe delay (0–250 ms) so the probe fires.
  for micros in [0, 250_000, 500_000, 1_000_000, 2_000_000] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }

  assert!(
    io.sent
      .iter()
      .any(|(dst, _)| *dst == MDNS_SOCKET_V4 || *dst == MDNS_SOCKET_V6),
    "expected at least one probe to an mDNS group; sent dsts = {:?}",
    io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
  );
}

#[test]
fn a_goodbye_with_no_socket_on_any_family_writes_off_without_error() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(101));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  // Announce so there are records to retract.
  for micros in [
    0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
  ] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  // Every family now reports "no socket": the goodbye burst must write each
  // family off as Unsupported — no error, no datagram, no infinite retry.
  io.v4_fail = Some(SendError::Unsupported);
  io.v6_fail = Some(SendError::Unsupported);
  io.sent.clear();
  engine.unregister_service(handle, at(5_000_000));
  for micros in [5_000_000, 5_250_001, 5_500_001, 5_750_001, 6_000_001] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  assert!(
    io.sent.is_empty(),
    "nothing can leave when every family is Unsupported; sent = {:?}",
    io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
  );
}

#[cfg(feature = "stats")]
#[test]
fn stats_handle_exposes_the_shared_counter() {
  let engine: Engine<SmoltcpInstant, StdRng> =
    Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(102));
  // The returned Arc aliases the engine's own counter (shared, not a copy).
  let s = engine.stats_handle();
  assert!(Arc::strong_count(&s) >= 2);
}

/// A browse (PTR) query for `qname`, as a legacy querier would send it.
fn build_ptr_query(qname: &Name) -> Vec<u8> {
  use mdns_proto::wire::{Header, MessageBuilder, ResourceClass, ResourceType};
  let mut buf = [0u8; 512];
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  b.push_question(qname, ResourceType::Ptr, ResourceClass::In, false)
    .unwrap();
  let n = b.finish().unwrap();
  buf[..n].to_vec()
}

/// Announce `sample_spec`, then feed a query from `querier`, pump, and return the
/// engine plus the sent log so a caller can assert how the (legacy → unicast)
/// reply fared — on the wire and in the engine's own accounting.
fn unicast_reply_scenario(seed: u64, v4_fail: Option<SendError>) -> (TestEngine, SentLog) {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(seed));
  engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in [
    0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
  ] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  io.sent.clear();
  io.v4_fail = v4_fail;
  // A browse query from a LEGACY source port (!= 5353), delivered to the mDNS
  // group so the §11 gate accepts it. §6.7: the reply must be UNICAST.
  let querier = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 50), 6000));
  io.inbound.push_back((
    build_ptr_query(&Name::try_from_str("_ipp._tcp.local.").unwrap()),
    RecvMeta {
      src: querier,
      local: Some(MDNS_SOCKET_V4.ip()),
      hop_limit: None,
      len: 0,
    },
  ));
  for micros in [5_000_000, 5_250_000, 5_500_000] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  (engine, io.sent)
}

#[test]
fn a_legacy_unicast_query_gets_a_unicast_reply() {
  let querier = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 50), 6000));
  let (_, sent) = unicast_reply_scenario(201, None);
  assert!(
    sent.iter().any(|(dst, _)| *dst == querier),
    "expected a unicast reply to the legacy querier; sent = {:?}",
    sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
  );
}

#[test]
fn a_unicast_reply_too_large_is_handled_without_panicking() {
  // A permanent TooLarge failure on the one-shot reply: the engine writes it
  // off (real send error) and stays healthy. Nothing reaches the wire.
  let querier = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 50), 6000));
  let (_, sent) = unicast_reply_scenario(202, Some(SendError::TooLarge));
  assert!(sent.iter().all(|(dst, _)| *dst != querier));
}

#[test]
fn a_unicast_reply_busy_is_best_effort_not_fatal() {
  // Busy is transient/not-an-error: the one-shot reply is dropped (the querier
  // re-asks) and the engine stays healthy.
  let querier = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 50), 6000));
  let (_, sent) = unicast_reply_scenario(203, Some(SendError::Busy));
  assert!(sent.iter().all(|(dst, _)| *dst != querier));
}

/// RFC 6762 §6.7: a legacy unicast reply is fanned to exactly ONE link — the
/// destination's family — so its obligated set has one member and the outcome is
/// all-delivered or none-delivered by construction, never partial. The core
/// counts a response iff it was delivered, which is what makes that mapping
/// observable from outside: a queued reply counts, a rejected one does not.
#[cfg(feature = "stats")]
#[test]
fn a_legacy_unicast_reply_is_confirmed_all_or_none_by_construction() {
  let (delivered, _) = unicast_reply_scenario(211, None);
  let (busy, _) = unicast_reply_scenario(212, Some(SendError::Busy));
  let (too_large, _) = unicast_reply_scenario(213, Some(SendError::TooLarge));

  assert!(
    delivered.stats().responses_tx > busy.stats().responses_tx,
    "a queued unicast reply is all-delivered, so it must be counted; \
     delivered={} busy={}",
    delivered.stats().responses_tx,
    busy.stats().responses_tx
  );
  assert_eq!(
    busy.stats().responses_tx,
    too_large.stats().responses_tx,
    "neither a busy nor a too-large unicast reply reached its one obligated \
     link, so both are none-delivered and neither may be counted"
  );
}

#[test]
fn a_legacy_unicast_reply_never_opens_the_reclaim_cancel_gate() {
  // RFC 6762 §6.7: a legacy unicast reply has exactly ONE obligated link, so it
  // is all-delivered by construction. That makes it the trap the reclaim-cancel
  // gate must not fall into — under the old `advertises_instance()` predicate a
  // single unicast reply, after a v4-only announcement, satisfied the gate and
  // cancelled a renamed-away name's goodbye that the v6 zone still needed.
  // The gate is now the core's own all-delivered ANNOUNCEMENT fact, which no
  // response of any kind can set.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(205));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp {
    v6_fail: Some(SendError::Busy),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];

  // Run to the first (partial) announcement: it exposes the instance records to
  // v4 — so ownership latches — while v6 has still been told nothing.
  let mut t = 0i64;
  for _ in 0..200 {
    t = pump_to_next_round(&mut engine, &mut io, &mut scratch, t);
    if engine.services[&handle].proto.advertises_instance() {
      break;
    }
  }
  assert!(
    engine.services[&handle].proto.advertises_instance(),
    "the v4-only announcement must have latched instance ownership"
  );
  assert!(
    !engine.services[&handle].proto.has_fully_announced().get(),
    "a partially-delivered announcement must NOT open the reclaim-cancel gate"
  );

  // A legacy querier (source port != 5353) gets a §6.7 UNICAST reply, which is
  // all-delivered by construction.
  let querier = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 50), 6000));
  io.inbound.push_back((
    build_ptr_query(&Name::try_from_str("_ipp._tcp.local.").unwrap()),
    RecvMeta {
      src: querier,
      local: Some(MDNS_SOCKET_V4.ip()),
      hop_limit: None,
      len: 0,
    },
  ));
  io.sent.clear();
  engine.pump(at(t + 1_000), &mut io, &mut scratch);
  assert!(
    io.sent.iter().any(|(dst, _)| *dst == querier),
    "the legacy querier must get its unicast reply; sent = {:?}",
    io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
  );
  assert!(
    !engine.services[&handle].proto.has_fully_announced().get(),
    "an all-delivered UNICAST reply must not open the reclaim-cancel gate — only \
     a complete announcement that reached every obligated family may"
  );
}

#[test]
fn unregistering_an_announced_service_emits_a_goodbye() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(2));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();

  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  // Drive through probing + announcing so the records become advertised.
  for micros in [
    0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
  ] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  io.sent.clear();

  // Unregister → begins the endpoint-owned §10.1 TTL=0 goodbye sequence. The
  // first round is due immediately; resends are WITHDRAWAL_INTERVAL (250 ms)
  // apart. Pump across the sequence so at least one goodbye reaches the wire.
  engine.unregister_service(handle, at(5_000_000));
  for micros in [5_000_000, 5_000_001, 5_250_001, 5_500_001, 5_750_001] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }

  assert!(
    !io.sent.is_empty(),
    "unregistering an announced service should emit a §10.1 goodbye burst"
  );
}

// NOTE: the same-host sibling-address RETENTION tests
// (`same_host_sibling_addresses_are_retained_on_unregister` and
// `unregister_retention_scales_to_many_same_host_siblings`) were REMOVED in the
// endpoint-owned-withdrawal migration. They asserted against the deleted
// driver-side `host_addr_retained` predicate; sibling retention now lives in the
// endpoint (`Endpoint::poll_withdrawal_transmit` recomputes it fresh each round
// from the route table) and is covered by the proto-level
// `poll_withdrawal_transmit ... sibling retention` test.

/// A generous probe-then-announce pump schedule that reaches `Established`.
fn pump_schedule() -> [i64; 10] {
  [
    0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000, 5_000_000,
  ]
}

#[test]
fn v6_only_node_advertises_via_multicast_fan_out() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(4));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp {
    v4_fail: Some(SendError::Unsupported),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];
  let mut established = false;
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
    while let Some(update) = engine.poll_service_update(handle) {
      established |= matches!(update, ServiceUpdate::Established);
    }
  }
  assert!(
    established,
    "a v6-only node must still reach Established via the v6 group"
  );
  assert!(!io.sent.is_empty(), "expected real sends to the v6 group");
  assert!(
    io.sent.iter().all(|(dst, _)| *dst == MDNS_SOCKET_V6),
    "v6-only: every queued send must target the v6 group; got {:?}",
    io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
  );
}

#[test]
fn no_reachable_group_does_not_falsely_advance() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(5));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  // No socket for either family: every send is unsupported, nothing is queued.
  let mut io = MockUdp {
    v4_fail: Some(SendError::Unsupported),
    v6_fail: Some(SendError::Unsupported),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];
  let mut established = false;
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
    while let Some(update) = engine.poll_service_update(handle) {
      established |= matches!(update, ServiceUpdate::Established);
    }
  }
  assert!(
    !established,
    "a service must NOT reach Established when no datagram is ever queued"
  );
  assert!(
    io.sent.is_empty(),
    "no send should be recorded when both families are blocked"
  );
}

/// A busy transport must not consume the endpoint-owned withdrawal's resend
/// budget: an all-`Busy` goodbye round is reported as not-delivered, so the
/// endpoint re-arms it (short backoff) WITHOUT spending — and once the transport
/// recovers the goodbye still reaches the wire. (The per-family `owed` budget is
/// now endpoint-owned; this is the black-box observation of that property
/// through the driver's `poll_withdrawal_transmit` → `note_withdrawal_result`
/// loop. The proto-level test exercises the spend/re-arm bookkeeping directly.)
#[test]
fn goodbye_budget_is_not_consumed_while_transport_is_busy() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(6));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in [
    0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
  ] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  engine.unregister_service(handle, at(5_000_000));

  // All-busy transport: nothing reaches the wire, and the withdrawal must NOT
  // complete (a fully-failed round is re-armed, not spent). Stay within the 2 s
  // anti-pin ceiling (begin at 5 s) so completion here would be a real spend,
  // not a forced finish.
  io.v4_fail = Some(SendError::Busy);
  io.v6_fail = Some(SendError::Busy);
  io.sent.clear();
  for micros in [5_000_000, 5_250_001, 5_500_001, 5_750_001, 6_000_001] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  assert!(
    io.sent.is_empty(),
    "no goodbye should be recorded while busy"
  );
  assert!(
    engine.services.contains_key(&handle),
    "an all-busy withdrawal must not complete (its budget is re-armed, not spent), \
       so the driver slot is still held"
  );

  // Transport recovers → the goodbye finally goes out (budget was preserved).
  io.v4_fail = None;
  io.v6_fail = None;
  engine.pump(at(6_250_001), &mut io, &mut scratch);
  assert!(
    io.sent.iter().any(|(_, d)| datagram_kind(d) == Some(true)),
    "the TTL=0 goodbye must go out once the transport frees"
  );
}

/// Classify a sent datagram by its answer-record TTLs:
/// `Some(true)`  — it carries at least one TTL=0 answer (a §10.1 goodbye),
/// `Some(false)` — it carries answers, all with TTL>0 (a positive announce),
/// `None`        — no parseable answer records (e.g. a probe/query).
fn datagram_kind(bytes: &[u8]) -> Option<bool> {
  use mdns_proto::wire::MessageReader;
  let reader = MessageReader::try_parse(bytes).ok()?;
  let mut saw_answer = false;
  let mut saw_zero_ttl = false;
  for rec in reader.answers().flatten() {
    saw_answer = true;
    if rec.ttl() == 0 {
      saw_zero_ttl = true;
    }
  }
  if !saw_answer {
    return None;
  }
  Some(saw_zero_ttl)
}

/// Endpoint-owned-withdrawal replacement survival (supersedes the old free-name
/// goodbye BARRIER test). Under `with_probe_unique_names(false)` a same-name
/// replacement announces a positive TTL directly (no §8.1 probe) — exactly the
/// configuration in which a stale TTL=0 goodbye could be overtaken. The old
/// driver enforced ordering with a transmit barrier; the endpoint now enforces
/// it structurally: it KEEPS the route (holding the name) for the whole §10.1
/// withdrawal, so a same-name `register_service` is REJECTED until the goodbye
/// completes and frees the name. No replacement can announce ahead of the
/// withdrawal because no replacement can even be registered until it is done.
#[test]
fn same_name_replacement_is_rejected_until_withdrawal_completes() {
  let cfg = EndpointConfig::new().with_probe_unique_names(false);
  let mut engine: TestEngine = Engine::new(cfg, StdRng::seed_from_u64(101));
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];

  // 1. Register service A and drive it to Established so its instance records
  //    are confirmed-advertised (the withdrawal will have records to retract).
  let a = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut established = false;
  let mut t = 0i64;
  for _ in 0..16 {
    engine.pump(at(t), &mut io, &mut scratch);
    while let Some(u) = engine.poll_service_update(a) {
      established |= matches!(u, ServiceUpdate::Established);
    }
    t += 250_000;
  }
  assert!(
    established,
    "service A must reach Established before withdrawal"
  );

  // 2. Unregister A → begins the endpoint-owned withdrawal (name held).
  engine.unregister_service(a, at(t));

  // 3. While the withdrawal is in flight the SAME name must be rejected — the
  //    endpoint holds the route, so a replacement cannot announce a fresh
  //    positive TTL ahead of the stale TTL=0.
  let rejected = engine.register_service(sample_spec(), at(t + 1));
  assert!(
    matches!(
      rejected,
      Err(RegisterServiceError::NameAlreadyRegistered(_))
    ),
    "a same-name registration must be rejected while the withdrawal holds the \
       name; got {rejected:?}"
  );

  // 4. Pump with a WORKING transport until the withdrawal completes (its budget
  //    is spent and `drain_completed_withdrawals` frees the route + GCs the
  //    slot). The first goodbye is due immediately; resends are 250 ms apart.
  io.sent.clear();
  let mut completed = false;
  for _ in 0..32 {
    t += 250_000;
    engine.pump(at(t), &mut io, &mut scratch);
    if !engine.services.contains_key(&a) {
      completed = true;
      break;
    }
  }
  assert!(
    completed,
    "the withdrawal must complete (route freed + driver slot GC'd) on a working \
       transport"
  );
  // The withdrawal put at least one TTL=0 goodbye on the wire.
  assert!(
    io.sent.iter().any(|(_, d)| datagram_kind(d) == Some(true)),
    "the withdrawal must emit a TTL=0 §10.1 goodbye; sent kinds = {:?}",
    io.sent
      .iter()
      .map(|(_, d)| datagram_kind(d))
      .collect::<Vec<_>>()
  );

  // 5. The name is freed → a same-name replacement now registers successfully.
  engine
    .register_service(sample_spec(), at(t))
    .expect("the same name must be re-registerable once the withdrawal completes");
}

/// Regression: a caller that `unregister_service`s and then discards
/// the handle WITHOUT polling a queued update (e.g. an unread `Established`) must
/// not leak the slot. `unregister_service` marks it `caller_gone`, so the
/// completed-withdrawal GC removes it regardless of pending updates — the
/// `route_freed` deferral (which waits for a reader that is now gone) would
/// otherwise grow `services` without bound under register/unregister churn.
#[test]
fn unregister_then_discard_with_unread_update_gc_s_the_slot() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(202));
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];

  let a = engine.register_service(sample_spec(), at(0)).unwrap();
  // An app-facing update the caller never polls.
  engine
    .services
    .get_mut(&a)
    .unwrap()
    .push_update(ServiceUpdate::Established);

  // Retire A and discard the handle WITHOUT polling the update; the (empty,
  // never-announced) withdrawal completes and the slot must be GC'd anyway.
  engine.unregister_service(a, at(1));
  let mut t = 1i64;
  let mut gcd = false;
  for _ in 0..4 {
    t += 250_000;
    engine.pump(at(t), &mut io, &mut scratch);
    if !engine.services.contains_key(&a) {
      gcd = true;
      break;
    }
  }
  assert!(
    gcd,
    "an unregistered service with an unread update must be GC'd (caller_gone), \
       not deferred forever and leaked"
  );
}

#[test]
fn flooded_conflict_updates_are_coalesced_and_bounded() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(7));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let slot = engine.services.get_mut(&handle).unwrap();
  // A peer flooding HostConflict must coalesce to a single queued update.
  for _ in 0..1000 {
    slot.push_update(ServiceUpdate::HostConflict);
  }
  assert_eq!(
    slot.updates.len(),
    1,
    "repeated HostConflict must coalesce to one queued update"
  );
  // Non-coalescible variety is still capped (drop-oldest backstop).
  for _ in 0..1000 {
    slot.push_update(ServiceUpdate::HostConflict);
    slot.push_update(ServiceUpdate::Conflict);
  }
  assert!(
    slot.updates.len() <= MAX_SERVICE_UPDATES,
    "the update backlog must stay capped; got {}",
    slot.updates.len()
  );
}

/// Drive `engine` at a fixed 250 ms cadence for `steps` pumps starting one step
/// after `from_micros`, draining service updates like a real host loop. Returns
/// `(established, next_micros)`.
fn pump_for(
  engine: &mut TestEngine,
  io: &mut MockUdp,
  scratch: &mut [u8],
  handle: ServiceHandle,
  from_micros: i64,
  steps: usize,
) -> (bool, i64) {
  let mut t = from_micros;
  let mut established = false;
  for _ in 0..steps {
    t += 250_000;
    engine.pump(at(t), io, scratch);
    while let Some(update) = engine.poll_service_update(handle) {
      established |= matches!(update, ServiceUpdate::Established);
    }
  }
  (established, t)
}

/// Pump at 250 ms from `from_micros` until ONE more fan-out round reaches the
/// transport, and return the time it landed. The first §8.1 probe carries a
/// randomised 0–250 ms delay, so a round is not reliably one pump away.
fn pump_to_next_round(
  engine: &mut TestEngine,
  io: &mut MockUdp,
  scratch: &mut [u8],
  from_micros: i64,
) -> i64 {
  let attempts_before = io.attempts;
  let mut t = from_micros;
  for _ in 0..400 {
    t += 250_000;
    engine.pump(at(t), io, scratch);
    if io.attempts > attempts_before {
      return t;
    }
  }
  panic!("no fan-out round happened within 100 s");
}

/// The current proto lifecycle state of a registered service, read through the
/// driver slot — the phase observable the invariant pair keys on.
fn service_state(engine: &TestEngine, handle: ServiceHandle) -> ServiceState {
  engine.services[&handle].proto.state()
}

#[test]
fn a_partial_fan_out_latches_ownership_without_advancing_the_phase() {
  // The invariant pair, at the driver seam. A partial multicast fan-out (v4
  // queues, v6 BUSY) reports `PartiallyDelivered`, which means two DIFFERENT
  // things to the core and must not be folded to one bit:
  //
  //   * goodbye ownership LATCHES — v4 peers may now cache the records v4 put on
  //     the wire, so a later unregister owes them a §10.1 TTL=0 withdrawal;
  //   * the §8.1/§8.3 phase does NOT advance — v6 has been neither asked nor
  //     told, and claiming a name on a link that never heard the probe is what
  //     §8.1 forbids.
  //
  // The old boolean confirm had no truthful value here: `true` advanced the
  // phase on v6's behalf, `false` dropped the ownership of records v4 peers
  // already hold.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(8));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp {
    v6_fail: Some(SendError::Busy),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];

  // Exactly one fan-out round: the first probe. v4 queues it, v6 is busy.
  let t = pump_to_next_round(&mut engine, &mut io, &mut scratch, 0);
  assert_eq!(io.sent.len(), 1, "one probe should have reached v4 only");
  assert_eq!(io.sent[0].0, MDNS_SOCKET_V4, "v4 must carry the probe");
  assert_eq!(
    service_state(&engine, handle),
    ServiceState::Probing(0),
    "a partial probe must re-arm the SAME probe index — v6 was never asked"
  );

  // Let it climb to the announcements. Every round stays partial, so the phase
  // only moves when the bounded policy excuses v6 (covered on its own below);
  // what matters here is that the FIRST partial announcement latches ownership
  // while the service is still short of Established.
  let (_, t) = pump_for(&mut engine, &mut io, &mut scratch, handle, t, 40);
  assert!(
    io.sent.iter().all(|(dst, _)| *dst == MDNS_SOCKET_V4),
    "only v4 should carry sends while v6 is busy; got {:?}",
    io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
  );
  assert!(
    engine.services[&handle].proto.advertises_instance(),
    "a v4-only announcement exposes the instance records to v4 peers, so \
     goodbye ownership must latch on the PARTIAL round"
  );

  // Ownership latched ⇒ a graceful unregister actually retracts: a TTL=0 §10.1
  // goodbye reaches v4 (the peers that cached them). Had the partial round
  // dropped ownership, the withdrawal snapshot would be empty and the wire
  // silent.
  engine.unregister_service(handle, at(t));
  io.sent.clear();
  engine.pump(at(t + 1), &mut io, &mut scratch);
  assert!(
    io.sent
      .iter()
      .any(|(dst, d)| *dst == MDNS_SOCKET_V4 && datagram_kind(d) == Some(true)),
    "a partially-delivered advertisement must still latch goodbye ownership, so \
     the withdrawal emits a TTL=0 goodbye to v4; sent = {:?}",
    io.sent
      .iter()
      .map(|(dst, d)| (*dst, datagram_kind(d)))
      .collect::<Vec<_>>()
  );
  // v6 recovers BEFORE the withdrawal's resend budget is spent → a later
  // goodbye round reaches v6 too (the busy family catches up). Resends are
  // 250 ms apart; recover v6 and pump the next due rounds.
  io.v6_fail = None;
  io.sent.clear();
  for micros in [t + 250_001, t + 500_001] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  assert!(
    io.sent.iter().any(|(dst, _)| *dst == MDNS_SOCKET_V6),
    "the goodbye must reach v6 once it recovers"
  );
}

#[test]
fn a_fully_delivered_fan_out_latches_ownership_and_advances_the_phase() {
  // The other half of the pair: when EVERY obligated family queues the datagram,
  // the same confirm both latches ownership and advances the phase. This is the
  // healthy dual-stack path, and it must not need the bounded policy to get
  // there — no family ever misses, so no round is ever partial.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(81));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];

  // One round: the first probe reaches BOTH groups, so the probe index advances.
  let t = pump_to_next_round(&mut engine, &mut io, &mut scratch, 0);
  assert_eq!(
    io.sent.len(),
    2,
    "a healthy dual-stack fan-out puts the probe on both groups; sent = {:?}",
    io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
  );
  assert_eq!(
    service_state(&engine, handle),
    ServiceState::Probing(1),
    "an all-delivered probe advances the §8.1 sequence"
  );

  // The full §8.1 + §8.3 startup completes with no round ever partial.
  let (established, _) = pump_for(&mut engine, &mut io, &mut scratch, handle, t, 20);
  assert!(
    established,
    "a fully-delivered dual-stack service must reach Established"
  );
  assert!(
    engine.services[&handle].proto.advertises_instance(),
    "a delivered announcement latches goodbye ownership"
  );
  assert!(
    engine.services[&handle].proto.has_fully_announced().get(),
    "an all-delivered announcement is what sets the reclaim-cancel gate"
  );
}

#[test]
fn a_wholly_failed_fan_out_neither_latches_nor_advances() {
  // Nothing reached any wire: no peer can hold these records and no link has
  // been asked or told, so a fully-failed round must latch NOTHING and advance
  // NOTHING — and must not be laundered into an all-delivered confirm by the
  // bounded policy either (that policy writes off a family that MISSED while
  // another delivered; here none did).
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(82));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp {
    v4_fail: Some(SendError::Busy),
    v6_fail: Some(SendError::Busy),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];

  // 20 s of all-busy rounds — far past the bounded policy's budget.
  let (established, t) = pump_for(&mut engine, &mut io, &mut scratch, handle, 0, 80);
  assert!(
    io.sent.is_empty(),
    "nothing may reach a wire while all-busy"
  );
  assert!(
    !established,
    "a service whose datagrams never leave the host must not reach Established"
  );
  assert_eq!(
    service_state(&engine, handle),
    ServiceState::Probing(0),
    "a fully-failed probe re-arms the same index forever — it is not a partial \
     round, so no obligation may be written off"
  );
  assert!(
    !engine.services[&handle].proto.advertises_instance(),
    "nothing was exposed, so goodbye ownership must not latch"
  );
  // The withdrawal therefore has nothing to retract: it completes with no
  // datagram on the wire rather than TTL=0-ing records no peer ever saw.
  engine.unregister_service(handle, at(t));
  io.v4_fail = None;
  io.v6_fail = None;
  io.sent.clear();
  engine.pump(at(t + 250_000), &mut io, &mut scratch);
  assert!(
    io.sent.iter().all(|(_, d)| datagram_kind(d) != Some(true)),
    "an unexposed service owns nothing, so its withdrawal emits no goodbye; \
     sent = {:?}",
    io.sent
      .iter()
      .map(|(dst, d)| (*dst, datagram_kind(d)))
      .collect::<Vec<_>>()
  );
}

#[test]
fn the_bounded_partial_policy_fires_instead_of_pinning_the_phase() {
  // The core's patience bound, observed end to end through THIS transport. A
  // partial transmit re-arms losslessly and advances nothing, so a family that
  // never accepts a datagram would hold this service in probing forever if the
  // core waited indefinitely. It does not: past its bound it advances without
  // that family, and the service completes its lifecycle on the family it has.
  // (Round-precision — how many partials are honest before one is excused, and
  // what the excused round must NOT credit — is asserted in `mdns-proto`, where
  // the bound lives.)
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(83));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp {
    v6_fail: Some(SendError::Busy),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];

  // Within the budget the phase must NOT advance: the first partial probe re-arms
  // the same probe index, because v6 has not been asked.
  let t = pump_to_next_round(&mut engine, &mut io, &mut scratch, 0);
  assert_eq!(
    service_state(&engine, handle),
    ServiceState::Probing(0),
    "the first partial round is within the budget, so the phase must not advance"
  );

  // End to end: the service reaches Established on v4 alone, and v6 — still
  // attempted on every round — never carries a byte.
  // The horizon is ~50 s because every round is partial: the served family's
  // announcements are spaced on the §8.3 doubling ladder (1, 2, 4, 8, 16 s), which
  // the excused advances carry across rather than reset.
  let (established, _) = pump_for(&mut engine, &mut io, &mut scratch, handle, t, 200);
  assert!(
    established,
    "the bound must let the healthy family finish the lifecycle"
  );
  assert!(
    !engine.services[&handle].proto.has_fully_announced().get(),
    "no announcement ever reached v6, so the excused advances must NOT have \
     opened the reclaim-cancel gate — an excused advance is not a delivery"
  );
  assert!(
    io.sent.iter().all(|(dst, _)| *dst == MDNS_SOCKET_V4),
    "the excused family must still send nothing; got {:?}",
    io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
  );
}

#[test]
fn a_recovered_family_resumes_the_obligated_set_on_its_next_send() {
  // Excusal is per-confirm and never sticky: a family is dropped from the
  // obligated set only for the round it missed, and the first round it accepts
  // is all-delivered on its own merit. This is the driver side of the core's
  // reciprocal guarantee (lossless re-arm, immediate recovery).
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(84));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp {
    v6_fail: Some(SendError::Busy),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];

  // Burn partial rounds while v6 is busy, then recover it.
  let (_, t) = pump_for(&mut engine, &mut io, &mut scratch, handle, 0, 2);
  assert_eq!(
    service_state(&engine, handle),
    ServiceState::Probing(0),
    "a partial probe re-arms the same index — v6 has not been asked"
  );
  io.v6_fail = None;
  io.sent.clear();
  let (_, t) = pump_for(&mut engine, &mut io, &mut scratch, handle, t, 2);
  assert!(
    io.sent.iter().any(|(dst, _)| *dst == MDNS_SOCKET_V6),
    "the recovered family must be attempted and must send"
  );
  let (established, _) = pump_for(&mut engine, &mut io, &mut scratch, handle, t, 20);
  assert!(
    established,
    "the lifecycle resumes from where it stood once every family delivers"
  );
  assert!(
    engine.services[&handle].proto.has_fully_announced().get(),
    "the recovered family carries the announcements on their own merit, so the \
     all-delivered credit an excused round never earns is earned here"
  );
}

/// Build a probe-shaped message carrying a CONFLICTING SRV authority record for
/// `instance_str` (different rdata than ours — port 9999, a rival target). From
/// an mDNS peer (source port 5353) this routes a §9 `ProbeConflict`, which
/// reverts an established service to probing and then loses the §8.2 tiebreak,
/// renaming and queuing the old-name goodbye.
fn build_conflict_srv_authority(instance_str: &str) -> Vec<u8> {
  use mdns_proto::wire::{Header, MessageBuilder};
  let mut buf = [0u8; 512];
  let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
  let name = Name::try_from_str(instance_str).unwrap();
  let target = Name::try_from_str("rival-host.local.").unwrap();
  b.push_srv_authority(&name, 120, 0, 0, 9999, &target)
    .unwrap();
  let n = b.finish().unwrap();
  buf[..n].to_vec()
}

/// Build a probe-shaped message carrying a CONFLICTING A authority record for
/// `host_str` (a peer claiming our host name with a DIFFERENT address). From an
/// mDNS peer this routes a §9 host conflict; the proto does NOT auto-rename a host
/// conflict — it queues a `ServiceUpdate::HostConflict`.
fn build_conflict_a_authority(host_str: &str, addr: [u8; 4]) -> Vec<u8> {
  use mdns_proto::wire::{Header, MessageBuilder};
  let mut buf = [0u8; 512];
  let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
  let name = Name::try_from_str(host_str).unwrap();
  b.push_a_authority(&name, 120, Ipv4Addr::from(addr))
    .unwrap();
  let n = b.finish().unwrap();
  buf[..n].to_vec()
}

// NOTE: the per-family rename-goodbye regressions
// (active_rename_goodbye_keeps_a_busy_family_owed_not_global_budget, its
// assert_rename_goodbye_keeps_busy_family_owed helper, and
// invalid_suffix_rename_goodbye_also_routes_through_per_family_queue) were
// REMOVED in the endpoint-owned-withdrawal migration. They asserted against the
// deleted driver-side goodbye queue (engine.goodbyes + per-family owed budget).
// A rename of a SURVIVING service now emits its old-name goodbye via the proto's
// own poll_transmit schedule (confirmed in the normal TX loop); a rename whose
// new name collides locally is torn down through the endpoint-owned withdrawal
// lifecycle, whose spend/re-arm bookkeeping is covered by the proto-level tests.

#[test]
fn a_constrained_transport_does_not_starve_either_family() {
  // With a TX buffer that fits ~one datagram per poll cycle, a
  // FIXED v4-first fan-out would let v4 win the only slot on every send and
  // starve v6 — the proto would reach Established with v6 having seen no
  // probes/announcements. The fan-out instead prioritises the family that has
  // been waiting longest (family_order), so both groups make progress and the
  // alternating success keeps either family from degrading.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(22));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  let mut established = false;
  let mut t = 0i64;
  // ~50 s: one slot per cycle makes EVERY fan-out partial, so the served family's
  // announcements walk the §8.3 doubling ladder (1, 2, 4, 8, 16 s) that the
  // core's excused advances carry across rather than reset.
  for _ in 0..200 {
    t += 250_000;
    // One datagram of TX room this cycle: the SECOND family in any fan-out is
    // busy, so only a fair order lets both groups eventually transmit.
    io.capacity = Some(1);
    engine.pump(at(t), &mut io, &mut scratch);
    while let Some(update) = engine.poll_service_update(handle) {
      established |= matches!(update, ServiceUpdate::Established);
    }
  }
  assert!(
    established,
    "the service must still reach Established on a one-slot transport"
  );
  let hit_v4 = io.sent.iter().any(|(dst, _)| *dst == MDNS_SOCKET_V4);
  let hit_v6 = io.sent.iter().any(|(dst, _)| *dst == MDNS_SOCKET_V6);
  assert!(
    hit_v4 && hit_v6,
    "both families must receive sends on a constrained transport, not just the \
       one that wins a fixed order; v4={hit_v4} v6={hit_v6}"
  );
}

/// A one-datagram-per-cycle (capacity-1) transport must still complete the
/// endpoint-owned withdrawal: each goodbye round fans out, and even though only
/// one family queues per pump the withdrawal is driven to completion across
/// pumps (each delivered round spends one of the endpoint resend budget). The
/// per-family burst BOOKKEEPING now lives in the endpoint (covered by the
/// proto-level tests); this is the driver black-box observation that the
/// withdrawal-transmit loop drains on a constrained transport. (The old
/// goodbye-queue capacity/byte-budget tests — drains_after_each_family,
/// the_goodbye_queue_stays_bounded_under_unregister_churn,
/// make_goodbye_room_evicts_to_fit_an_incoming_datagram,
/// a_large_main_goodbye_survives_when_no_rename_follows, and
/// goodbye_budget_holds_two_near_ceiling_withdrawals — were REMOVED: the driver
/// no longer owns a goodbye QUEUE, so its eviction/byte-budget machinery is
/// gone. The endpoint holds exactly one in-flight withdrawal per route.)
#[test]
fn a_constrained_transport_drains_a_withdrawal_after_each_family_gets_a_round() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(23));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  // Advertise (healthy) so there are records to withdraw.
  for micros in [
    0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
  ] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  engine.unregister_service(handle, at(5_000_000));
  io.sent.clear();
  // One datagram of TX room per cycle, pumps 250 ms apart (a WITHDRAWAL_INTERVAL),
  // all within the 2 s anti-pin ceiling so completion is a real budget spend.
  let mut t = 5_000_000i64;
  let mut completed = false;
  for _ in 0..16 {
    t += 250_000;
    io.capacity = Some(1);
    engine.pump(at(t), &mut io, &mut scratch);
    // Drain updates like a real host loop, so the slot is GC'd once its
    // withdrawal completes (a completed slot is reclaimed only after its
    // app-facing updates are read — see ServiceSlot::route_freed).
    while engine.poll_service_update(handle).is_some() {}
    if !engine.services.contains_key(&handle) {
      completed = true;
      break;
    }
  }
  assert!(
    completed,
    "the withdrawal must drain via the endpoint resend schedule on a one-slot \
       transport, not linger"
  );
  // Both families received at least one goodbye datagram across the rounds.
  let v4 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V4).count();
  let v6 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V6).count();
  assert!(
    v4 >= 1 && v6 >= 1,
    "each reachable family must receive at least one goodbye on a constrained \
       transport; v4={v4} v6={v6}"
  );
}

#[test]
fn default_setup_processes_rx_without_hop_limit_or_subnets() {
  // Both supplied transports report hop_limit: None (smoltcp's UdpMetadata
  // carries no RX TTL, and hick-embassy re-exports it), and Engine::new starts with
  // no local subnets. The §11 gate must NOT then drop every inbound datagram — a
  // default node could announce but never see a query, answer, or conflict. Feed a
  // conflict with the real supplied-transport metadata shape (hop_limit None) and NO
  // set_local_subnets; it must be PROCESSED (the service renames), not silently
  // dropped. The rename is the observable that the conflict reached the proto.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(47));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
    while engine.poll_service_update(handle).is_some() {}
  }

  // The default deaf scenario: no subnets configured, hop_limit None on every RX.
  let conflict = build_conflict_srv_authority("Test._ipp._tcp.local.");
  let mut t = 6_000_000i64;
  let mut reacted = false;
  for _ in 0..16 {
    io.inbound.push_back((
      conflict.clone(),
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
        // Arrived on the mDNS multicast group (link-scoped) — the §11 gate accepts
        // it even with no hop-limit and no subnets.
        local: Some(MDNS_SOCKET_V4.ip()),
        hop_limit: None,
        len: 0,
      },
    ));
    engine.pump(at(t), &mut io, &mut scratch);
    t += 250_000;
    while let Some(u) = engine.poll_service_update(handle) {
      reacted |= matches!(u, ServiceUpdate::Renamed(_) | ServiceUpdate::Conflict);
    }
    if reacted {
      break;
    }
  }
  assert!(
    reacted,
    "a default node (hop_limit None, no subnets) must PROCESS inbound mDNS — the §11 \
       gate dropping everything would leave it deaf to queries, answers, and conflicts"
  );
}

#[test]
fn default_setup_rejects_off_link_unicast() {
  // The default no-input gate must NOT accept UNICAST: a routed off-link host
  // could send unicast (or an ephemeral-port probe) to the device's :5353 and inject
  // conflict/answer data — link-scoped multicast does not protect a unicast path.
  // The SAME conflict that renames over multicast (above) must be ignored when its
  // destination is the device's own unicast address and no hop-limit/subnets vouch
  // for it.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(59));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
    while engine.poll_service_update(handle).is_some() {}
  }

  let conflict = build_conflict_srv_authority("Test._ipp._tcp.local.");
  let mut t = 6_000_000i64;
  let mut reacted = false;
  for _ in 0..16 {
    io.inbound.push_back((
      conflict.clone(),
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
        // Delivered to the device's OWN unicast address, not the mDNS group.
        local: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        hop_limit: None,
        len: 0,
      },
    ));
    engine.pump(at(t), &mut io, &mut scratch);
    t += 250_000;
    while let Some(u) = engine.poll_service_update(handle) {
      reacted |= matches!(u, ServiceUpdate::Renamed(_) | ServiceUpdate::Conflict);
    }
  }
  assert!(
    !reacted,
    "off-link unicast must NOT drive a conflict rename when no hop-limit or subnet \
       vouches for it — only link-scoped multicast is trusted by default"
  );
}

/// a terminal emitted DIRECTLY by the proto state machine — here a
/// HostConflict (a peer claims our host name with a different address, RFC 6762
/// §9) — must RETIRE the smoltcp service through the SAME path as a synthesized
/// rename-collision Conflict: queue the terminal, mark the slot errored, begin the
/// endpoint-owned §10.1 withdrawal (so the route stops being driven/answered), and
/// GC the slot once the goodbye completes and the caller has drained the terminal.
/// Before the fix a proto-emitted terminal was only queued (errored stayed false,
/// no withdrawal), leaving a zombie route that kept answering after the caller saw
/// the terminal.
#[test]
fn proto_emitted_host_conflict_retires_and_gcs_the_smoltcp_service() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(83));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];

  // Drive to Established (advertising test.local. -> 192.168.1.10), so the host
  // conflict hits a SERVING service with a non-empty withdrawal snapshot.
  let mut established = false;
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
    while let Some(u) = engine.poll_service_update(handle) {
      established |= matches!(u, ServiceUpdate::Established);
    }
  }
  assert!(
    established,
    "service must reach Established before the host conflict"
  );

  // A peer claims our HOST name with a DIFFERENT address: a genuine §9 host
  // conflict. The proto emits ServiceUpdate::HostConflict via poll(), which
  // drain_service_updates must now route through retirement.
  let conflict = build_conflict_a_authority("test.local.", [10, 0, 0, 99]);
  let mut t = 6_000_000i64;
  let mut retired = false;
  for _ in 0..16 {
    io.inbound.push_back((
      conflict.clone(),
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
        local: Some(MDNS_SOCKET_V4.ip()),
        hop_limit: None,
        len: 0,
      },
    ));
    engine.pump(at(t), &mut io, &mut scratch);
    t += 250_000;
    if engine
      .services
      .get(&handle)
      .map(|s| s.errored)
      .unwrap_or(false)
    {
      retired = true;
      break;
    }
  }
  assert!(
    retired,
    "a proto-emitted HostConflict must begin the endpoint-owned withdrawal (errored)"
  );

  // The HostConflict terminal is observable by the caller (queued in the slot
  // before GC); draining it lets the slot GC once the withdrawal completes.
  let mut saw_host_conflict = false;
  while let Some(u) = engine.poll_service_update(handle) {
    saw_host_conflict |= u.is_host_conflict();
  }
  assert!(
    saw_host_conflict,
    "the HostConflict terminal must reach the caller via poll_service_update"
  );

  // Drive the withdrawal to completion; the slot must be GC'd (route freed).
  let mut gced = false;
  for _ in 0..64 {
    t += 250_000;
    engine.pump(at(t), &mut io, &mut scratch);
    if !engine.services.contains_key(&handle) {
      gced = true;
      break;
    }
  }
  assert!(
    gced,
    "the withdrawn slot must be GC'd after the §10.1 goodbye completes"
  );
}

#[test]
fn rx_drain_is_capped_per_pump_with_immediate_repump() {
  // The per-pump RX drain is capped at MAX_RX_PER_PUMP so an on-link flood
  // cannot grow a service's proto update pool proportional to the whole RX backlog
  // before drain_service_updates coalesces/caps it. One pump processes at most the
  // cap and, because datagrams remain buffered, asks for an immediate re-pump
  // (deadline = now) so a genuine backlog still drains promptly.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(53));
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  let pkt = build_conflict_srv_authority("Whatever._ipp._tcp.local.");
  let flood = MAX_RX_PER_PUMP + 10;
  for _ in 0..flood {
    io.inbound.push_back((
      pkt.clone(),
      RecvMeta {
        src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 200), 5353)),
        // Arrived on the mDNS multicast group (link-scoped) — the §11 gate accepts
        // it even with no hop-limit and no subnets.
        local: Some(MDNS_SOCKET_V4.ip()),
        hop_limit: None,
        len: 0,
      },
    ));
  }
  let now = at(1_000_000);
  let deadline = engine.pump(now, &mut io, &mut scratch);
  assert_eq!(
    io.inbound.len(),
    flood - MAX_RX_PER_PUMP,
    "one pump must drain at most MAX_RX_PER_PUMP datagrams, leaving the rest buffered"
  );
  assert_eq!(
    deadline,
    Some(now),
    "a capped RX drain must request an immediate re-pump (deadline = now)"
  );
  // The remainder (< cap) drains in the next pump, which is no longer capped.
  engine.pump(at(1_000_001), &mut io, &mut scratch);
  assert!(
    io.inbound.is_empty(),
    "the follow-up pump drains the remaining buffered datagrams"
  );
}

// NOTE: `the_goodbye_scratch_is_a_fixed_preallocated_footprint` was REMOVED — the
// driver no longer keeps a goodbye encode scratch (`goodbye_scratch`); the
// endpoint encodes each withdrawal goodbye into the caller's `scratch`, capped to
// the §17 ceiling by `poll_one_transmit`'s `MAX_MDNS_MESSAGE` slice.

#[test]
fn an_oversized_service_is_not_advertised_so_it_is_never_unwithdrawable() {
  // the normal multicast path honors the §17 ceiling (MAX_MDNS_MESSAGE). A record
  // set that would encode above it must NOT be advertised — even when the caller's
  // pump scratch is larger — so the engine can never latch goodbye ownership for
  // records it could not later withdraw (which would leave peers caching them
  // until TTL).
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(30));
  let mut records = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Huge._ipp._tcp.local.").unwrap(),
    Name::try_from_str("huge.local.").unwrap(),
    631,
    120,
  );
  // ~400 AAAA records encode to well over the §17 ceiling (≈ 11 KiB).
  for i in 0..400u16 {
    records.add_aaaa(core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i));
  }
  let handle = engine
    .register_service(ServiceSpec::new(records), at(0))
    .unwrap();
  let mut io = MockUdp::default();
  // A caller scratch LARGER than the ceiling — the cap must still apply, so the
  // oversized probe/announce fails to encode and the service is retired.
  let mut scratch = [0u8; 12_000];
  let mut established = false;
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
    while let Some(u) = engine.poll_service_update(handle) {
      established |= matches!(u, ServiceUpdate::Established);
    }
  }
  assert!(
    !established,
    "an oversized service must not reach Established (it cannot be encoded \
       within the §17 ceiling, even with a larger caller scratch)"
  );
  // It never advertised, so the withdrawal snapshot is empty and the endpoint
  // completes it immediately with NO datagram on the wire — no unwithdrawable
  // records were ever advertised. Pump the withdrawal and assert no goodbye.
  io.sent.clear();
  engine.unregister_service(handle, at(6_000_000));
  for micros in [6_000_001, 6_250_001, 6_500_001] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  assert!(
    io.sent.iter().all(|(_, d)| datagram_kind(d) != Some(true)),
    "an oversized service that never advertised must not emit any TTL=0 goodbye; \
       sent kinds = {:?}",
    io.sent
      .iter()
      .map(|(_, d)| datagram_kind(d))
      .collect::<Vec<_>>()
  );
}

#[test]
fn permanently_failing_family_does_not_stall_the_healthy_one() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(15));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  // v6 is permanently busy (e.g. an unbound v6 socket mapped to Busy). It must
  // never block the healthy family: v4 confirms on its own (delivered = at least
  // one socket succeeded), so v4 advertisement reaches Established.
  let mut io = MockUdp {
    v6_fail: Some(SendError::Busy),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];
  let mut established = false;
  let mut t = 0;
  // ~50 s: every round is partial, so the healthy family's announcements walk the
  // §8.3 doubling ladder (1, 2, 4, 8, 16 s) that the core's excused advances carry
  // across rather than reset.
  for _ in 0..200 {
    t += 250_000;
    engine.pump(at(t), &mut io, &mut scratch);
    while let Some(update) = engine.poll_service_update(handle) {
      established |= matches!(update, ServiceUpdate::Established);
    }
  }
  assert!(
    established,
    "a healthy v4 family must reach Established despite a permanently-failing v6"
  );
  assert!(
    io.sent.iter().all(|(dst, _)| *dst == MDNS_SOCKET_V4),
    "only v4 should carry real sends; got {:?}",
    io.sent.iter().map(|(d, _)| *d).collect::<Vec<_>>()
  );
}

#[test]
fn own_multicast_loopback_is_not_treated_as_conflict() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(9));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  // Drive to advertised so an announcement (authoritative records) has gone out
  // and been fingerprinted.
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  // Loop our most recent multicast datagram back in, from a DIFFERENT source so
  // the proto's advertised-source fallback cannot catch it — only the self-send
  // fingerprint can. hop_limit 255 passes the §11 gate.
  let (_, datagram) = io.sent.last().cloned().expect("a datagram was sent");
  io.inbound.push_back((
    datagram,
    RecvMeta {
      src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 99), 5353)),
      local: None,
      hop_limit: Some(255),
      len: 0,
    },
  ));
  // Process the loopback promptly — within RECENT_SEND_TTL of the announcement.
  engine.pump(at(5_000_001), &mut io, &mut scratch);

  let mut conflict = false;
  while let Some(update) = engine.poll_service_update(handle) {
    conflict |= matches!(
      update,
      ServiceUpdate::Conflict | ServiceUpdate::HostConflict
    );
  }
  assert!(
    !conflict,
    "our own looped-back multicast must not be seen as a conflicting peer"
  );
}

#[test]
fn actionable_updates_survive_conflict_flood() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(10));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let slot = engine.services.get_mut(&handle).unwrap();
  // An actionable transition queued first...
  slot.push_update(ServiceUpdate::Established);
  // ...then a peer floods alternating conflict noise.
  for _ in 0..1000 {
    slot.push_update(ServiceUpdate::HostConflict);
    slot.push_update(ServiceUpdate::Conflict);
  }
  assert!(
    slot
      .updates
      .iter()
      .any(|u| matches!(u, ServiceUpdate::Established)),
    "the Established transition must not be evicted by conflict noise"
  );
  assert!(
    slot.updates.len() <= MAX_SERVICE_UPDATES,
    "the backlog must stay bounded; got {}",
    slot.updates.len()
  );
}

/// A permanently-busy withdrawal is held (route kept, name reserved) while it
/// keeps failing, then FORCE-completed at the endpoint's anti-pin ceiling
/// (`WITHDRAWAL_CEILING` = 2 s) so an undeliverable goodbye cannot pin the name
/// slot forever. (Supersedes the old 30 s `MAX_GOODBYE_AGE` driver-queue test;
/// the ceiling/age bookkeeping now lives in the endpoint.)
#[test]
fn busy_goodbye_is_held_then_force_completed_at_the_ceiling() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(11));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in [
    0, 250_000, 500_000, 750_000, 1_000_000, 1_500_000, 2_000_000, 3_000_000, 4_000_000,
  ] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  // Drain the announce-phase updates so the slot's only lifecycle left is the
  // withdrawal (a completed slot is GC'd only after its updates are read).
  while engine.poll_service_update(handle).is_some() {}
  engine.unregister_service(handle, at(5_000_000));
  // Permanently busy: nothing reaches the wire and no round is spent. WITHIN the
  // 2 s ceiling (begin at 5 s → ceiling 7 s) the withdrawal is HELD, so the route
  // is still reserved and the slot still present.
  io.v4_fail = Some(SendError::Busy);
  io.v6_fail = Some(SendError::Busy);
  for micros in [5_250_001, 5_500_001, 6_000_001, 6_500_001] {
    engine.pump(at(micros), &mut io, &mut scratch);
    while engine.poll_service_update(handle).is_some() {}
  }
  assert!(
    engine.services.contains_key(&handle),
    "a never-delivered withdrawal must be HELD (route reserved + slot present) \
       within the 2 s anti-pin ceiling"
  );
  // PAST the ceiling (7 s) `drain_completed_withdrawals` force-completes it — the
  // route is freed and the driver slot GC'd even though nothing ever sent.
  engine.pump(at(7_500_001), &mut io, &mut scratch);
  assert!(
    !engine.services.contains_key(&handle),
    "an undeliverable withdrawal must be force-completed at its anti-pin ceiling"
  );
}

#[test]
fn loopback_detected_across_a_large_send_burst() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(14));
  // Register many services so one pump emits a burst of probes far larger than
  // any small fixed ring would hold.
  let mut handles = Vec::new();
  for i in 0..8u8 {
    let instance = alloc::format!("Dev{i}._ipp._tcp.local.");
    let host = alloc::format!("dev{i}.local.");
    handles.push(
      engine
        .register_service(
          spec_for(
            "_ipp._tcp.local.",
            &instance,
            &host,
            Ipv4Addr::new(192, 168, 1, 10 + i),
          ),
          at(0),
        )
        .unwrap(),
    );
  }
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  // Pump until the probe burst has fired for every service.
  for micros in [0, 250_000, 500_000] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  assert!(
    io.sent.len() > 4,
    "expected a burst larger than any small fixed ring; got {}",
    io.sent.len()
  );
  // Loop the FIRST (oldest) probe back — it must still be recognised as self
  // despite the larger, more-recent burst that followed it.
  let first = io.sent.first().cloned().expect("a probe was sent");
  io.inbound.push_back((
    first.1,
    RecvMeta {
      src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 99), 5353)),
      local: None,
      hop_limit: Some(255),
      len: 0,
    },
  ));
  engine.pump(at(750_000), &mut io, &mut scratch);

  let mut conflict = false;
  for h in &handles {
    while let Some(u) = engine.poll_service_update(*h) {
      conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
    }
  }
  assert!(
    !conflict,
    "the oldest self-send in a large burst must still be loopback-detected"
  );
}

#[test]
fn send_multicast_projects_the_fan_out_onto_the_delivery_shape() {
  // Pin the projection every confirm downstream depends on: the obligated set is
  // the families that HAVE a socket, delivery is `Sent` and nothing else, and an
  // empty obligated set is none-delivered rather than a vacuous "all".
  let mut tx = Multicaster::<SmoltcpInstant>::new();

  // v4 queues, v6 transiently busy → PARTIAL. v6 has a socket, so it is
  // obligated and did not carry the datagram; folding this to "delivered" is
  // exactly what over-advanced the §8.1/§8.3 phase on a family that heard nothing.
  let mut partial = MockUdp {
    v6_fail: Some(SendError::Busy),
    ..Default::default()
  };
  let (outcome, fanout) = tx.send_multicast(&mut partial, b"a-multicast-datagram", at(0));
  assert!(
    matches!(
      outcome,
      MulticastOutcome::Confirm(TransmitOutcome::PartiallyDelivered)
    ),
    "v4 queued + v6 obligated-but-busy is a partial fan-out"
  );
  assert_eq!(
    fanout.sent_count(),
    1,
    "v4 queued, v6 busy: exactly 1 datagram on the wire"
  );
  assert!(
    matches!(fanout.v4, FamilySend::Sent(_)),
    "v4 must have sent"
  );
  assert!(matches!(fanout.v6, FamilySend::Busy), "v6 must be Busy");

  // v4 queues, v6 has NO socket → ALL delivered. An absent family was never
  // obligated, so a single-stack node advances its lifecycle at full speed.
  let mut single_stack = MockUdp {
    v6_fail: Some(SendError::Unsupported),
    ..Default::default()
  };
  let (outcome_single, _) = tx.send_multicast(&mut single_stack, b"a-multicast-datagram", at(0));
  assert!(
    matches!(
      outcome_single,
      MulticastOutcome::Confirm(TransmitOutcome::AllDelivered)
    ),
    "a family with no socket is not obligated, so a v4-only node is all-delivered"
  );

  // Both families busy: nothing reached a wire, so nothing may latch or advance —
  // the proto re-offers on its own schedule. A transiently-busy family is a
  // none-delivered confirm, never a retirement.
  let mut all_busy = MockUdp {
    v4_fail: Some(SendError::Busy),
    v6_fail: Some(SendError::Busy),
    ..Default::default()
  };
  let (outcome_busy, fanout_busy) =
    tx.send_multicast(&mut all_busy, b"a-multicast-datagram", at(0));
  assert!(
    matches!(
      outcome_busy,
      MulticastOutcome::Confirm(TransmitOutcome::NoneDelivered)
    ),
    "both families busy: nothing on the wire, so none-delivered rather than retire"
  );
  assert_eq!(
    fanout_busy.sent_count(),
    0,
    "both families busy: no datagrams on the wire"
  );

  // No socket on either family — an EMPTY obligated set. It must report
  // none-delivered, never a vacuous "all" that would advance a phase no link
  // ever heard.
  let mut no_transport = MockUdp {
    v4_fail: Some(SendError::Unsupported),
    v6_fail: Some(SendError::Unsupported),
    ..Default::default()
  };
  let (outcome_none, _) = tx.send_multicast(&mut no_transport, b"a-multicast-datagram", at(0));
  assert!(
    matches!(
      outcome_none,
      MulticastOutcome::Confirm(TransmitOutcome::NoneDelivered)
    ),
    "an empty obligated set is none-delivered, never a vacuous all-delivered"
  );
}

#[test]
fn a_permanently_too_large_send_retires_the_service() {
  // a datagram every reachable socket reports as permanently TooLarge (e.g.
  // embassy PacketTooLarge — a TX buffer too small for a legal ≤§17 packet) must
  // NOT be retried forever. The service is retired with an actionable Conflict
  // update instead of probing/announcing indefinitely with nothing on the wire.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(31));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp {
    v4_fail: Some(SendError::TooLarge),
    v6_fail: Some(SendError::TooLarge),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];
  let mut conflict = false;
  let mut established = false;
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
    while let Some(u) = engine.poll_service_update(handle) {
      conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
      established |= matches!(u, ServiceUpdate::Established);
    }
  }
  assert!(
    conflict,
    "a permanently-too-large send must retire the service with an actionable update"
  );
  assert!(
    !established,
    "a service whose datagrams can never be sent must not reach Established"
  );
  assert!(
    io.sent.is_empty(),
    "nothing is ever queued when every send is permanently too large"
  );
}

#[test]
fn a_too_large_family_does_not_retire_while_the_other_may_recover() {
  // a service is retired (Undeliverable) ONLY when nothing queued AND no
  // family is recoverable. A permanently-TooLarge family alongside a transiently
  // Busy one must NOT retire it — the busy family may yet recover and carry the
  // datagram (embassy maps NoRoute / SocketNotBound to Busy, and those clear).
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(33));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp {
    v4_fail: Some(SendError::TooLarge), // permanent on v4
    v6_fail: Some(SendError::Busy),     // transient on v6 — may recover
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];
  let mut conflict = false;
  let mut established = false;
  let mut t = 0i64;
  // Pump for 10 s — far longer than any prior degrade window — with v6 still
  // busy. The service must keep retrying, NOT be retired.
  for _ in 0..40 {
    t += 250_000;
    engine.pump(at(t), &mut io, &mut scratch);
    while let Some(u) = engine.poll_service_update(handle) {
      conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
      established |= matches!(u, ServiceUpdate::Established);
    }
  }
  assert!(
    !conflict,
    "a TooLarge family must not retire the service while the other (Busy) may \
       still recover"
  );
  assert!(
    !established,
    "cannot advertise while v6 is busy and v4 is permanently too large"
  );
  // v6 recovers → the service advertises on it and reaches Established, proving
  // it was never wrongly retired. Every round stays PARTIAL (v4 is permanently
  // TooLarge, so it is obligated and never delivers), so each phase step waits
  // out the core's patience bound plus its §8.3 partial ladder — hence the long
  // tail here.
  io.v6_fail = None;
  for ms in 41..=200i64 {
    engine.pump(at(ms * 250_000), &mut io, &mut scratch);
    while let Some(u) = engine.poll_service_update(handle) {
      established |= matches!(u, ServiceUpdate::Established);
    }
  }
  assert!(
    established,
    "once v6 recovers the service advertises on it — it was never retired"
  );
}

#[test]
fn established_is_observable_on_the_pump_that_confirms_it() {
  // the final announcement confirms INSIDE the pump's TX loop, after the
  // pre-loop drain. Without a post-TX drain, Established would sit in the proto
  // until the next pump — but the next deadline is the distant re-announce, so an
  // embassy driver would sleep and the app would not observe Established for ~80%
  // of a TTL. Assert it is surfaced on the SAME pump that confirms it: poll right
  // after each pump and break as soon as the lifecycle settles into the distant
  // re-announce deadline — at which point Established must already be visible.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(32));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  let mut established = false;
  let mut settled = false;
  let mut t = 0i64;
  for _ in 0..40 {
    t += 250_000;
    let deadline = engine.pump(at(t), &mut io, &mut scratch);
    while let Some(u) = engine.poll_service_update(handle) {
      established |= matches!(u, ServiceUpdate::Established);
    }
    // A deadline ≥ 30 s out means the §8.3 startup is done and only the distant
    // re-announce remains — the service is Established internally, so by now the
    // confirming pump must already have surfaced it (without an extra pump).
    if deadline.is_some_and(|d| d >= at(t + 30_000_000)) {
      settled = true;
      break;
    }
  }
  assert!(
    settled,
    "the service should have reached its re-announce deadline"
  );
  assert!(
    established,
    "Established must be surfaced on the pump that confirms the final \
       announcement, not stranded until the distant re-announce"
  );
}

#[test]
fn a_query_exposes_collected_answers_via_the_public_api() {
  // a bare-metal caller must be able to READ a query's collected answers,
  // not just its terminal update. Browse a service type, deliver a real response
  // (a responder engine's announcement of a matching service), and read it back
  // through the public collected_answers() / query_accepted_count() accessors.
  // Responder: advertise a service and capture its announcement datagram.
  let mut responder: Engine<SmoltcpInstant, StdRng> =
    Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(40));
  responder.register_service(sample_spec(), at(0)).unwrap();
  let mut rio = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in pump_schedule() {
    responder.pump(at(micros), &mut rio, &mut scratch);
  }
  let (_, announcement) = rio
    .sent
    .iter()
    .rev()
    .find(|(dst, _)| *dst == MDNS_SOCKET_V4)
    .cloned()
    .expect("the responder must have multicast an announcement");

  // Querier: browse the service type, then receive the announcement as a response.
  let mut querier: Engine<SmoltcpInstant, StdRng> =
    Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(41));
  let q = querier
    .start_query(
      QuerySpec::new(
        Name::try_from_str("_ipp._tcp.local.").unwrap(),
        mdns_proto::wire::ResourceType::Ptr,
      ),
      at(0),
    )
    .unwrap();
  let mut qio = MockUdp::default();
  qio.inbound.push_back((
    announcement,
    RecvMeta {
      src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 5353)),
      local: None,
      hop_limit: Some(255),
      len: 0,
    },
  ));
  for micros in pump_schedule() {
    querier.pump(at(micros), &mut qio, &mut scratch);
  }

  // The collected answer must be readable through the public API.
  let answers = querier.collected_answers(q).count();
  assert!(
    answers >= 1,
    "a query's collected answers must be readable via the public API; got {answers}"
  );
  assert!(
    querier.query_accepted_count(q).unwrap_or(0) >= 1,
    "query_accepted_count must reflect the accepted answer"
  );
}

#[test]
fn a_query_that_can_never_send_surfaces_a_terminal_update() {
  // a query whose question is permanently too large for every reachable
  // family is retired — and must surface a terminal QueryUpdate so the caller
  // learns it died, instead of waiting forever for a result it can never request.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(42));
  let q = engine
    .start_query(
      QuerySpec::new(
        Name::try_from_str("_ipp._tcp.local.").unwrap(),
        mdns_proto::wire::ResourceType::Ptr,
      ),
      at(0),
    )
    .unwrap();
  let mut io = MockUdp {
    v4_fail: Some(SendError::TooLarge),
    v6_fail: Some(SendError::TooLarge),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];
  let mut terminal = false;
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
    while let Some(u) = engine.poll_query_update(q) {
      terminal |= matches!(u, QueryUpdate::Timeout | QueryUpdate::Done);
    }
  }
  assert!(
    terminal,
    "a query that can never send must surface a terminal update, not hang silently"
  );
}

#[test]
fn a_retired_query_freezes_answers_and_emits_no_second_terminal() {
  // a retired query must be synchronized with the proto terminal state.
  // After its Timeout, a late MATCHING response must NOT mutate collected_answers
  // and no second terminal may appear — because the driver forces the proto
  // query's TIMEOUT terminal (is_done), so Endpoint::handle freezes late answers.
  // Responder: capture a matching announcement.
  let mut responder: Engine<SmoltcpInstant, StdRng> =
    Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(43));
  responder.register_service(sample_spec(), at(0)).unwrap();
  let mut rio = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in pump_schedule() {
    responder.pump(at(micros), &mut rio, &mut scratch);
  }
  let (_, announcement) = rio
    .sent
    .iter()
    .rev()
    .find(|(d, _)| *d == MDNS_SOCKET_V4)
    .cloned()
    .expect("the responder must have announced");

  // Querier with an all-TooLarge transport: the browse can never send → retired.
  let mut querier: Engine<SmoltcpInstant, StdRng> =
    Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(44));
  let q = querier
    .start_query(
      QuerySpec::new(
        Name::try_from_str("_ipp._tcp.local.").unwrap(),
        mdns_proto::wire::ResourceType::Ptr,
      ),
      at(0),
    )
    .unwrap();
  let mut qio = MockUdp {
    v4_fail: Some(SendError::TooLarge),
    v6_fail: Some(SendError::TooLarge),
    ..Default::default()
  };
  let mut terminals = 0;
  for micros in pump_schedule() {
    querier.pump(at(micros), &mut qio, &mut scratch);
    while let Some(u) = querier.poll_query_update(q) {
      if matches!(u, QueryUpdate::Timeout | QueryUpdate::Done) {
        terminals += 1;
      }
    }
  }
  assert_eq!(
    terminals, 1,
    "a retired query surfaces exactly one terminal"
  );
  assert_eq!(
    querier.collected_answers(q).count(),
    0,
    "a retired query collected nothing (it never sent)"
  );

  // A late MATCHING response after the terminal must be FROZEN (not collected)
  // and must NOT produce a second terminal.
  qio.inbound.push_back((
    announcement,
    RecvMeta {
      src: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 7), 5353)),
      local: None,
      hop_limit: Some(255),
      len: 0,
    },
  ));
  let mut t = 100_000_000i64;
  for _ in 0..10 {
    t += 250_000;
    querier.pump(at(t), &mut qio, &mut scratch);
    while let Some(u) = querier.poll_query_update(q) {
      if matches!(u, QueryUpdate::Timeout | QueryUpdate::Done) {
        terminals += 1;
      }
    }
  }
  assert_eq!(
    terminals, 1,
    "no SECOND terminal after a late response to a retired query"
  );
  assert_eq!(
    querier.collected_answers(q).count(),
    0,
    "a late response must be frozen — collected_answers unchanged after the terminal"
  );
}

// NOTE: the per-family goodbye-accounting stats tests
// (fan_out_tx_accounting_is_per_datagram_and_goodbye_rounds_are_logical,
// stats_goodbye_single_stack_unsupported_v6, stats_goodbye_v4_sent_v6_failed_per_round,
// and stats_goodbye_busy_until_expiry_no_overcount) were REMOVED in the
// endpoint-owned-withdrawal migration: they asserted the deleted drain_goodbyes
// per-family GOODBYE_SENDS bookkeeping (engine.goodbyes + owed). The endpoint now
// owns the resend schedule; the driver bumps goodbyes_tx once per DELIVERED round
// (>= 1 family on the wire), packets_tx/bytes_tx per Sent family, and send_errors
// per Failed family in the withdrawal send. The dual-stack happy path below pins
// that driver-side accounting; both-families-failed pins the no-send case.

/// Dual-stack withdrawal stats (replaces the old per-family goodbye-accounting
/// suite). With WITHDRAWAL_SENDS resend rounds and both families healthy, each
/// round fans to v4+v6, so across the completed withdrawal: goodbyes_tx rises by
/// the number of DELIVERED rounds, packets_tx by twice that (one Sent per family
/// per round), and send_errors stays 0.
#[cfg(feature = "stats")]
#[test]
fn stats_withdrawal_dual_stack_counts_rounds_and_per_family_datagrams() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(1005));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  engine.unregister_service(handle, at(5_000_000));
  let snap_before = engine.stats();
  io.sent.clear();

  // Unlimited capacity, pumps 250 ms apart (WITHDRAWAL_INTERVAL), within the 2 s
  // ceiling so completion is a real budget spend. Drive until the endpoint frees
  // the route (services_active drops to 0) — the authoritative completion signal.
  let mut t = 5_000_000i64;
  let mut completed = false;
  for _ in 0..16 {
    t += 250_000;
    engine.pump(at(t), &mut io, &mut scratch);
    if engine.stats().services_active == 0 {
      completed = true;
      break;
    }
  }
  assert!(completed, "the withdrawal must drain on dual-stack");

  let snap_after = engine.stats();
  let v4 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V4).count();
  let v6 = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V6).count();
  assert!(
    v4 >= 1 && v6 >= 1,
    "both families must carry goodbyes; v4={v4} v6={v6}"
  );
  assert_eq!(
    v4, v6,
    "dual-stack: each round fans to both families equally"
  );

  // goodbyes_tx == number of delivered rounds; on healthy dual-stack each round
  // delivers, so == v4 (one round per v4 datagram).
  let rounds = v4 as u64;
  assert_eq!(
    snap_after.goodbyes_tx - snap_before.goodbyes_tx,
    rounds,
    "goodbyes_tx must count one per delivered round (== {rounds})"
  );
  // packets_tx delta == per-family datagrams (v4 + v6).
  assert_eq!(
    snap_after.packets_tx - snap_before.packets_tx,
    (v4 + v6) as u64,
    "packets_tx delta must equal per-family goodbye datagrams"
  );
  assert_eq!(
    snap_after.send_errors - snap_before.send_errors,
    0,
    "dual-stack healthy: send_errors must be 0"
  );
}

/// regression: per-family withdrawal debt at the driver level.
/// With v4 healthy but v6 transiently BUSY, the withdrawal must NOT free before
/// v6 sends — v6 peers still hold the records. v4 drains its debt (and keeps
/// re-withdrawing harmlessly), yet the route stays held WITHIN the 2 s ceiling
/// until v6 recovers and emits its own TTL=0 goodbyes, at which point it
/// completes (well before the ceiling).
#[cfg(feature = "stats")]
#[test]
fn stats_withdrawal_v6_busy_until_recovery_not_freed_before_v6_sends() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(2006));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  // Drain announce-phase updates so the slot's only remaining lifecycle is the
  // withdrawal (a completed slot is GC'd only after its updates are read).
  while engine.poll_service_update(handle).is_some() {}
  engine.unregister_service(handle, at(5_000_000)); // ceiling at 7_000_000
  // Only count withdrawal-phase datagrams (the announce phase already put v4+v6
  // POSITIVE-TTL records on the wire).
  io.sent.clear();

  // v6 transiently busy, v4 healthy. Pump rounds 250 ms apart (WITHDRAWAL_INTERVAL,
  // since v4 keeps making progress) but WELL within the 2 s ceiling. v4 spends its
  // whole debt; v6's debt is untouched, so the withdrawal stays HELD.
  io.v6_fail = Some(SendError::Busy);
  for micros in [5_250_001, 5_500_001, 5_750_001, 6_000_001] {
    engine.pump(at(micros), &mut io, &mut scratch);
    while engine.poll_service_update(handle).is_some() {}
  }
  assert!(
    engine.services.contains_key(&handle),
    "a withdrawal whose v6 family is still busy must NOT be freed before the \
       2 s ceiling — v6 peers still hold the records"
  );
  let v6_before = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V6).count();
  assert_eq!(
    v6_before, 0,
    "no v6 goodbye can have reached the wire while v6 was busy; got {v6_before}"
  );
  // v4 DID withdraw (its debt drained), proving the route is held on v6 alone.
  assert!(
    io.sent.iter().any(|(d, _)| *d == MDNS_SOCKET_V4),
    "v4 must have emitted its TTL=0 goodbyes while v6 was busy"
  );

  // v6 recovers: pump until the withdrawal completes (route freed). Still inside
  // the 2 s ceiling, so completion is a real per-family budget spend, not the
  // anti-pin backstop.
  io.v6_fail = None;
  let mut completed = false;
  for micros in [6_250_001, 6_500_001, 6_750_001, 6_900_001] {
    engine.pump(at(micros), &mut io, &mut scratch);
    while engine.poll_service_update(handle).is_some() {}
    if !engine.services.contains_key(&handle) {
      completed = true;
      break;
    }
  }
  assert!(
    completed,
    "once v6 recovers and sends its goodbyes the withdrawal completes (before \
       the 2 s ceiling)"
  );
  let v6_after = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V6).count();
  assert!(
    v6_after >= 1,
    "v6 must have emitted at least one TTL=0 goodbye after recovery; got {v6_after}"
  );
}

/// Both families fail (TooLarge write-off): `send_errors` bumped per family,
/// `goodbyes_tx == 0` since nothing ever went on the wire.
#[cfg(feature = "stats")]
#[test]
fn stats_goodbye_both_families_failed_no_goodbyes_tx() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(1004));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  // Both families healthy during announce so records are owned (the withdrawal
  // snapshot is non-empty, so a goodbye send is attempted).
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];
  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  engine.unregister_service(handle, at(5_500_000));
  // NOW make both fail with TooLarge (the endpoint-owned withdrawal send path).
  io.v4_fail = Some(SendError::TooLarge);
  io.v6_fail = Some(SendError::TooLarge);
  let snap_before = engine.stats();
  io.sent.clear();

  // One pump (within the 2 s ceiling): both families are written off — nothing
  // reaches the wire, so the round is not delivered (re-armed, not spent).
  engine.pump(at(6_500_000), &mut io, &mut scratch);

  let snap_after = engine.stats();
  assert_eq!(
    io.sent.len(),
    0,
    "no datagrams should be sent when both families fail"
  );
  assert_eq!(
    snap_after.goodbyes_tx - snap_before.goodbyes_tx,
    0,
    "goodbyes_tx must be 0 when nothing ever goes on the wire; delta={}",
    snap_after.goodbyes_tx - snap_before.goodbyes_tx
  );
  let errors_delta = snap_after.send_errors - snap_before.send_errors;
  assert!(
    errors_delta >= 2,
    "both families TooLarge must bump send_errors at least once each; delta={errors_delta}"
  );
}

// NOTE: `stats_goodbye_dual_stack_happy_path` was REMOVED — it is superseded by
// `stats_withdrawal_dual_stack_counts_rounds_and_per_family_datagrams` above,
// which pins the same dual-stack accounting against the endpoint-owned
// withdrawal send (and no longer reads the deleted `engine.goodbyes` queue).

/// Normal multicast TX path (probes/announcements): per-family `packets_tx`
/// and `send_errors` correctness when one family fails permanently (TooLarge).
///
/// v4 sends (Sent), v6 returns TooLarge (Failed): the fan-out yields
/// MulticastOutcome::Delivered (because v4 sent), but `fanout.failed_count()` is
/// still 1. The fix counts send_errors unconditionally from `fanout.failed_count()`,
/// so the v6 failure is not dropped even though the coarse outcome is Delivered.
/// Each pump that fires a datagram increments send_errors by exactly 1 (the v6
/// failure). packets_tx reflects only v4 sends.
#[cfg(feature = "stats")]
#[test]
fn stats_multicast_tx_partial_failure_counted_per_family() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(1006));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  // v4 succeeds, v6 is permanently TooLarge (Failed in FamilySend terms).
  let mut io = MockUdp {
    v6_fail: Some(SendError::TooLarge),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];
  let snap_before = engine.stats();

  // Drive a few pumps so probes fire.
  for micros in [0, 250_000, 500_000, 750_000, 1_000_000] {
    engine.pump(at(micros), &mut io, &mut scratch);
  }
  let _ = handle;

  let snap_after = engine.stats();
  let v4_sent = io.sent.iter().filter(|(d, _)| *d == MDNS_SOCKET_V4).count();

  // packets_tx must reflect v4 sends only.
  assert!(
    snap_after.packets_tx > snap_before.packets_tx,
    "v4 probes must increment packets_tx"
  );
  assert_eq!(
    snap_after.packets_tx - snap_before.packets_tx,
    v4_sent as u64,
    "packets_tx delta must equal v4 sends only; delta={}, v4_sent={v4_sent}",
    snap_after.packets_tx - snap_before.packets_tx
  );
  // Tightened: v6 TooLarge must be counted in send_errors on EVERY fan-out
  // attempt, even when the overall outcome is Delivered (v4 succeeded). Each
  // multicast attempt contributes exactly 1 error (the v6 failure). The delta
  // must equal the number of v4 sends (one v6-Failed per fan-out that fired).
  assert_eq!(
    snap_after.send_errors - snap_before.send_errors,
    v4_sent as u64,
    "send_errors delta must equal v4_sent (one v6-TooLarge per fan-out); \
       errors_delta={}, v4_sent={v4_sent}",
    snap_after.send_errors - snap_before.send_errors
  );
}

// ── New mandatory tests: explicit send_errors delta assertions ──────────────

/// Multicast partial failure (v4 Sent + v6 TooLarge/Failed, overall Delivered):
/// send_errors must increment by exactly 1 (the v6 failure), packets_tx by 1.
/// This is the case the old outcome-gated code silently dropped.
#[cfg(feature = "stats")]
#[test]
fn stats_multicast_sent_plus_failed_send_errors_exact() {
  // Use a unit-level test via send_multicast directly so we get exactly one
  // fan-out and can assert the delta precisely.
  let mut tx: Multicaster<SmoltcpInstant> = Multicaster::new();
  let mut io = MockUdp {
    v6_fail: Some(SendError::TooLarge),
    ..Default::default()
  };
  let data = b"probe-datagram";
  let (outcome, fanout) = tx.send_multicast(&mut io, data, at(0));

  assert!(
    matches!(
      outcome,
      MulticastOutcome::Confirm(TransmitOutcome::PartiallyDelivered)
    ),
    "v4 Sent + v6 TooLarge: v6 has a socket and rejected the datagram, so it is \
     obligated-and-undelivered — a partial fan-out, not a whole one"
  );
  assert_eq!(
    fanout.failed_count(),
    1,
    "exactly one family (v6) must be Failed; failed_count={}",
    fanout.failed_count()
  );
  assert_eq!(
    fanout.sent_count(),
    1,
    "exactly one family (v4) must be Sent; sent_count={}",
    fanout.sent_count()
  );
  // This is the invariant the fix preserves: send_errors must equal failed_count()
  // regardless of the coarse outcome.
  assert_eq!(
    fanout.failed_count(),
    1,
    "send_errors delta must be 1 (v6 failure must not be dropped by Delivered arm)"
  );
}

/// Multicast partial failure (v4 Failed + v6 Busy):
/// send_errors must increment by exactly 1 (only the Failed), not 2 (not Busy).
#[cfg(feature = "stats")]
#[test]
fn stats_multicast_failed_plus_busy_send_errors_exact() {
  let mut tx: Multicaster<SmoltcpInstant> = Multicaster::new();
  let mut io = MockUdp {
    v4_fail: Some(SendError::TooLarge),
    v6_fail: Some(SendError::Busy),
    ..Default::default()
  };
  let data = b"probe-datagram";
  let (outcome, fanout) = tx.send_multicast(&mut io, data, at(0));

  // v4 Failed + v6 Busy: nothing reached a wire, and the busy family may yet
  // recover — so this confirms as none-delivered rather than retiring anything.
  assert!(
    matches!(
      outcome,
      MulticastOutcome::Confirm(TransmitOutcome::NoneDelivered)
    ),
    "v4 Failed + v6 Busy must confirm none-delivered (v6 Busy keeps things alive)"
  );
  assert_eq!(
    fanout.failed_count(),
    1,
    "only v4 is Failed; failed_count must be 1, got {}",
    fanout.failed_count()
  );
  // Busy must NOT be counted as an error.
  assert!(
    !matches!(fanout.v6, FamilySend::Failed),
    "v6 Busy must not be mapped to Failed"
  );
  // The pump will call stats.send_errors(fanout.failed_count()) = 1, not 2.
  assert_eq!(
    fanout.failed_count(),
    1,
    "send_errors delta must be 1 (Failed only), never 2 (Busy must not count)"
  );
}

/// Unicast Busy: send_errors must stay 0 (Busy is transient, not an error).
#[cfg(feature = "stats")]
#[test]
fn stats_unicast_busy_does_not_increment_send_errors() {
  // Inject a unicast reply by feeding a PTR query addressed to a specific
  // unicast source (non-multicast dst triggers the else branch).
  // We test the engine-level path by checking stats after a pump where the
  // only send is a unicast that returns Busy.
  //
  // Build an engine, register a service so it can respond, then inject a
  // unicast-expecting query and have the send return Busy.
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(2001));
  let _handle = engine.register_service(sample_spec(), at(0)).unwrap();

  // Use a MockUdp where every send returns Busy so ANY send path will fail.
  // We specifically need the unicast path. The easiest way is to set capacity=0
  // which causes try_send to return Busy regardless of destination.
  let mut io = MockUdp {
    capacity: Some(0),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];

  // Grab stats before any multicast fires (before any pumps so nothing has
  // happened yet).
  let snap_before = engine.stats();
  // Pump once at t=0. With capacity=0, any send returns Busy.
  engine.pump(at(0), &mut io, &mut scratch);
  let snap_after = engine.stats();

  // send_errors must be 0: Busy is not an error on any path.
  assert_eq!(
    snap_after.send_errors - snap_before.send_errors,
    0,
    "Busy (capacity=0) must not increment send_errors; delta={}",
    snap_after.send_errors - snap_before.send_errors
  );
}

/// Unicast Failed (TooLarge): send_errors must increment by exactly 1.
#[cfg(feature = "stats")]
#[test]
fn stats_unicast_too_large_increments_send_errors() {
  // Drive a service to established then make ALL sends return TooLarge.
  // The multicast pump will create Undeliverable (all families TooLarge →
  // send_errors via the unconditional fanout.failed_count() block). After that
  // we want to also confirm the unicast error path: set only unicast destination
  // to TooLarge while keeping multicast functional first.
  //
  // Simplest direct approach: test the `Fanout` / `FamilySend` API is consistent
  // for a direct try_send call on a MockUdp with TooLarge.
  let mut io = MockUdp {
    v4_fail: Some(SendError::TooLarge),
    ..Default::default()
  };
  // A unicast destination (not the mDNS multicast group).
  let unicast_dst: SocketAddr = "192.168.1.100:5353".parse().unwrap();
  let result = io.try_send(b"unicast-reply", unicast_dst);

  // The unicast arm must map TooLarge to send_errors(1), Busy/Unsupported to 0.
  assert!(
    matches!(result, Err(SendError::TooLarge)),
    "MockUdp with v4_fail=TooLarge must return TooLarge for IPv4 unicast"
  );
  // Verify the match arm logic: only TooLarge is an error.
  let errors: u64 = match result {
    Ok(()) => 0,
    Err(SendError::TooLarge) => 1,
    Err(SendError::Busy) | Err(SendError::Unsupported) => 0,
  };
  assert_eq!(
    errors, 1,
    "TooLarge unicast must count as send_errors=1; got {errors}"
  );
}

/// Unicast Unsupported: send_errors must stay 0.
#[cfg(feature = "stats")]
#[test]
fn stats_unicast_unsupported_does_not_increment_send_errors() {
  let mut io = MockUdp {
    v4_fail: Some(SendError::Unsupported),
    ..Default::default()
  };
  let unicast_dst: SocketAddr = "192.168.1.100:5353".parse().unwrap();
  let result = io.try_send(b"unicast-reply", unicast_dst);

  assert!(
    matches!(result, Err(SendError::Unsupported)),
    "MockUdp with v4_fail=Unsupported must return Unsupported for IPv4 unicast"
  );
  let errors: u64 = match result {
    Ok(()) => 0,
    Err(SendError::TooLarge) => 1,
    Err(SendError::Busy) | Err(SendError::Unsupported) => 0,
  };
  assert_eq!(
    errors, 0,
    "Unsupported unicast must not count as send_errors; got {errors}"
  );
}

/// RFC 6762 §11 off-link datagrams (hop-limit ≠ 255) are dropped before the
/// proto layer, but the datagram WAS received off the socket — so it must
/// increment `packets_rx`/`bytes_rx` AND `packets_dropped` exactly once each,
/// matching the reactor/compio pre-handle drop accounting (driver-consistent).
#[cfg(feature = "stats")]
#[test]
fn stats_off_link_datagram_counts_rx_bytes_and_dropped() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(9001));
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];

  // Well-formed mDNS packet so the only reject reason is the hop-limit.
  let pkt = build_conflict_srv_authority("Test._ipp._tcp.local.");
  let pkt_len = pkt.len();

  // Off-link: hop_limit = 1 (crossed a router → §11 reject). len > 0 so the
  // on-link gate is actually exercised, not the len==0 marker path.
  io.inbound.push_back((
    pkt,
    RecvMeta {
      src: SocketAddr::from((Ipv4Addr::new(192, 168, 2, 1), 5353)),
      local: Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
      hop_limit: Some(1),
      len: pkt_len,
    },
  ));

  let snap_before = engine.stats();
  engine.pump(at(0), &mut io, &mut scratch);
  let snap_after = engine.stats();

  assert_eq!(
    snap_after.packets_rx - snap_before.packets_rx,
    1,
    "an off-link datagram WAS received → packets_rx must rise by 1"
  );
  assert_eq!(
    snap_after.bytes_rx - snap_before.bytes_rx,
    pkt_len as u64,
    "off-link datagram bytes_rx must rise by the datagram length"
  );
  assert_eq!(
    snap_after.packets_dropped - snap_before.packets_dropped,
    1,
    "an off-link datagram must increment packets_dropped by 1"
  );
}

/// A zero-length receive (smoltcp oversized-datagram marker) must now bump
/// `packets_rx` AND `packets_dropped` — the datagram WAS consumed from the
/// transport queue so it must count toward the receive denominator.
///
/// `bytes_rx` is NOT expected to change: smoltcp discards the oversized
/// payload before handing control back to us, so the original length is lost.
#[cfg(feature = "stats")]
#[test]
fn stats_oversized_zero_len_marker_counts_rx_and_dropped() {
  use std::net::{IpAddr, Ipv4Addr, SocketAddr};

  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(42));
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];

  // An empty payload → MockUdp::try_recv sets meta.len = 0, which is the
  // zero-length oversized-datagram marker the engine checks.
  io.inbound.push_back((
    vec![],
    RecvMeta {
      src: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 5), 5353)),
      local: Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
      hop_limit: Some(255),
      len: 0,
    },
  ));

  let snap_before = engine.stats();
  engine.pump(at(0), &mut io, &mut scratch);
  let snap_after = engine.stats();

  assert_eq!(
    snap_after.packets_rx - snap_before.packets_rx,
    1,
    "a zero-length (oversized) marker WAS consumed → packets_rx must rise by 1"
  );
  assert_eq!(
    snap_after.packets_dropped - snap_before.packets_dropped,
    1,
    "a zero-length marker is an unusable datagram → packets_dropped must rise by 1"
  );
  // bytes_rx is not bumped: smoltcp discards the payload before we see it.
  assert_eq!(
    snap_after.bytes_rx, snap_before.bytes_rx,
    "bytes_rx must not change (oversized payload is lost before the zero-len marker)"
  );
}

/// regression: when `poll_one_transmit` retires a service due to a
/// permanently-unencodable datagram (scratch too small to encode any probe),
/// the proto route must be freed (`services_active == 0`) and the name must
/// be re-registerable. The service never advertised, so its withdrawal snapshot
/// is empty and completes on the same pump (freeing the route).
///
/// This covers the `Err(_)` arm in `Engine::poll_one_transmit` that now
/// calls `begin_service_withdrawal(handle, now)` in addition to setting
/// `slot.errored = true` (the endpoint frees the route on withdrawal completion).
#[cfg(feature = "stats")]
#[test]
fn encode_failure_retirement_frees_proto_route_and_decrements_services_active() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(99));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();

  // Verify services_active is 1 after registration.
  assert_eq!(
    engine.stats().services_active,
    1,
    "services_active must be 1 after registration"
  );

  // Use a 1-byte scratch to force `poll_one_transmit` → `Err(BufferTooSmall)`.
  // Drive with a normal (non-failing) io so the send path doesn't also retire
  // via `retire_origin` — we want to isolate the encode-failure branch.
  let mut io = MockUdp::default();
  let mut scratch_tiny = [0u8; 1];
  let mut got_conflict = false;

  // Pump until the service is retired. The probe fires after the §8.1 random
  // delay (≤250 ms), so pumping to 300 ms is sufficient. The encode Err path
  // retires immediately on the first failed encode (unlike compio which counts
  // to MAX_CONSECUTIVE_ENCODE_ERRORS — smoltcp retires on the first failure).
  for micros in [0i64, 100_000, 200_000, 300_000, 400_000] {
    engine.pump(at(micros), &mut io, &mut scratch_tiny);
    while let Some(u) = engine.poll_service_update(handle) {
      got_conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
    }
    if got_conflict {
      break;
    }
  }

  assert!(
    got_conflict,
    "encode failure must surface Conflict to the caller (poll_service_update)"
  );

  // Proto route freed — services_active must be 0.
  assert_eq!(
    engine.stats().services_active,
    0,
    "services_active must be 0 after encode-failure retirement (proto route freed)"
  );

  // The same service name must be re-registerable (route was released).
  engine
    .register_service(sample_spec(), at(500_000))
    .expect("same service name must be re-registerable after encode-failure retirement");

  assert_eq!(
    engine.stats().services_active,
    1,
    "services_active must be 1 again after re-registration"
  );
}

/// regression: when one of N registered services is retired by an
/// encode failure in `poll_one_transmit`, its proto route must be freed
/// IMMEDIATELY — in the same iteration that detects the failure — so an
/// `Ok(Some)` early-return from a LATER service in the same call cannot
/// bypass the `unregister_service` call.
///
/// The bug: the old code pushed retiring handles into `proto_unregister: Vec`
/// and drained it AFTER the service loop. An early-return from another
/// service exited the loop before the drain, permanently leaking the proto
/// route (`services_active` never decremented, old name not re-registerable).
///
/// The fix: `unregister_service` is called in-iteration (after the `slot`
/// borrow ends in the same loop body) so no early-return from a sibling
/// service can bypass it.
///
/// Verification: drive TWO services with a 1-byte scratch so both are retired
/// by encode failures. `services_active` must reach 0 (both routes freed),
/// and both names must be immediately re-registerable (no proto route leak).
/// The loop-ordering bypass would leave one (or both) routes leaked.
///
/// NOTE: With 1-byte scratch BOTH services fail to encode, so both get retired
/// in the same `poll_one_transmit` sweep. `services_active` must reach 0
/// (the fix ensures each retirement is unregistered immediately, regardless of
/// which service returned `Err` first). Without the fix, the deferred Vec
/// drain could be skipped by an intermediate state or exit path, leaving
/// `services_active > 0`.
#[cfg(feature = "stats")]
#[test]
fn multi_service_encode_failure_frees_route_even_with_sibling_transmit() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(200));

  // Register two services that will both encode-fail once we switch to the
  // 1-byte scratch (simulates the ordering bypass: both in the map, one
  // could short-circuit the other's post-loop drain in the buggy code).
  let handle_a = engine.register_service(sample_spec(), at(0)).unwrap();
  let handle_b = engine
    .register_service(
      spec_for(
        "_ipp._tcp.local.",
        "Sibling._ipp._tcp.local.",
        "sibling.local.",
        Ipv4Addr::new(192, 168, 1, 11),
      ),
      at(0),
    )
    .unwrap();

  assert_eq!(
    engine.stats().services_active,
    2,
    "both services registered: services_active must be 2"
  );

  // Pump with a tiny (1-byte) scratch. smoltcp retires on the FIRST encode
  // failure; both services have pending probes, so both begin an (empty,
  // never-announced) endpoint-owned withdrawal in the same `poll_one_transmit`
  // sweep. An empty withdrawal completes on the same pump, freeing both routes.
  // The key assertion (the fix) is that BOTH routes are freed —
  // services_active reaches 0 and both names re-registerable — not leaked by an
  // early-return for a sibling bypassing one service's in-iteration withdrawal.
  let mut io = MockUdp::default();
  let mut tiny = [0u8; 1];
  let mut got_conflict_a = false;
  let mut got_conflict_b = false;

  for i in 0..30i64 {
    let t = at(i * 100_000);
    engine.pump(t, &mut io, &mut tiny);
    // Draining the Conflict GCs the (route-already-freed) slot, so observe the
    // Conflict here rather than via a `slot.errored` peek (the slot may be gone).
    while let Some(u) = engine.poll_service_update(handle_a) {
      if matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict) {
        got_conflict_a = true;
      }
    }
    while let Some(u) = engine.poll_service_update(handle_b) {
      if matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict) {
        got_conflict_b = true;
      }
    }
    if got_conflict_a && got_conflict_b {
      break;
    }
  }

  // Conflicts surfaced for BOTH (each internal retirement still notifies the
  // host, even though it now begins a withdrawal instead of freeing immediately).
  assert!(
    got_conflict_a,
    "A's Conflict must be surfaced via poll_service_update"
  );
  assert!(
    got_conflict_b,
    "B's Conflict must be surfaced via poll_service_update"
  );

  // fix (endpoint-owned form): both routes freed → services_active == 0.
  // Each service's empty withdrawal completes (frees its route) in the pump that
  // began it; the in-iteration `begin_service_withdrawal` is non-bypassable, so
  // an early-return for a sibling cannot leak the other's route.
  assert_eq!(
    engine.stats().services_active,
    0,
    "services_active must be 0 after both services are retired by encode failure \
       (each begins + completes an empty withdrawal; no route leak)"
  );

  // Both names must be immediately re-registerable (routes were freed).
  engine
    .register_service(sample_spec(), at(3_000_000))
    .expect("A's name must be re-registerable after in-iteration unregister (fix)");
  engine
    .register_service(
      spec_for(
        "_ipp._tcp.local.",
        "Sibling._ipp._tcp.local.",
        "sibling.local.",
        Ipv4Addr::new(192, 168, 1, 11),
      ),
      at(3_000_000),
    )
    .expect("B's name must be re-registerable after in-iteration unregister (fix)");

  assert_eq!(
    engine.stats().services_active,
    2,
    "services_active must be 2 after re-registering both A and B"
  );
}

/// regression (send-too-large path): when `retire_origin` retires a service
/// because every send returned a permanent error (`SendError::TooLarge`), the
/// proto route must be freed (`services_active == 0`) and the name must be
/// re-registerable. The service never confirmed-emitted anything (all sends
/// failed), so its withdrawal snapshot is empty and completes immediately.
///
/// This covers the `Origin::Service` arm in `Engine::retire_origin` that now
/// calls `begin_service_withdrawal(handle, now)` (the endpoint frees the route
/// when the withdrawal completes — here on the same pump, an empty snapshot).
#[cfg(feature = "stats")]
#[test]
fn send_too_large_retirement_frees_proto_route_and_decrements_services_active() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(100));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();

  assert_eq!(
    engine.stats().services_active,
    1,
    "services_active must be 1 after registration"
  );

  // Both families permanently TooLarge → `retire_origin` path.
  let mut io = MockUdp {
    v4_fail: Some(SendError::TooLarge),
    v6_fail: Some(SendError::TooLarge),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];
  let mut got_conflict = false;

  for micros in pump_schedule() {
    engine.pump(at(micros), &mut io, &mut scratch);
    while let Some(u) = engine.poll_service_update(handle) {
      got_conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
    }
    if got_conflict {
      break;
    }
  }

  assert!(
    got_conflict,
    "permanently-too-large sends must surface Conflict (retire_origin path)"
  );

  assert_eq!(
    engine.stats().services_active,
    0,
    "services_active must be 0 after retire_origin (proto route freed)"
  );

  // Re-registration must succeed (route was released by retire_origin).
  engine
    .register_service(sample_spec(), at(10_000_000))
    .expect("same service name must be re-registerable after retire_origin");

  assert_eq!(
    engine.stats().services_active,
    1,
    "services_active must be 1 again after re-registration"
  );
}

// ── The obligation tag (`TransmitObligation`) at the driver seam ────────────

/// Deliver `data` to the engine as an on-link datagram from `src` addressed to
/// the IPv4 mDNS group.
fn inbound_from(src: SocketAddr, data: Vec<u8>) -> (Vec<u8>, RecvMeta) {
  (
    data,
    RecvMeta {
      src,
      local: Some(MDNS_SOCKET_V4.ip()),
      hop_limit: None,
      len: 0,
    },
  )
}

/// A datagram no reachable socket can carry retires its producer, so that a
/// service does not probe/announce forever with nothing on the wire. That
/// reasoning holds ONLY for a datagram the core RE-OFFERS.
///
/// A response is `TransmitObligation::OneShot`: the core emits it once for the
/// question that provoked it and never re-arms it, so an undeliverable one costs
/// exactly one unanswered question — the querier re-asks. Retiring on it would
/// hand any on-link peer a remote kill switch: ask an established service a
/// question whose answer does not fit the TX buffer and the service is marked
/// errored, surfaces `Conflict`, and begins withdrawing.
#[test]
fn an_undeliverable_one_shot_reply_must_not_retire_the_service() {
  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(91));
  let handle = engine.register_service(sample_spec(), at(0)).unwrap();
  let mut io = MockUdp::default();
  let mut scratch = [0u8; 1500];

  // Healthy startup: the service reaches Established on both families.
  let (established, mut t) = pump_for(&mut engine, &mut io, &mut scratch, handle, 0, 40);
  assert!(
    established,
    "the service must be established before the attack"
  );

  // Now every socket rejects every datagram as permanently too large, and a peer
  // asks a question. The only transmit due is the §6 multicast reply — the
  // periodic re-announce is ~80 % of a 120 s TTL away.
  io.v4_fail = Some(SendError::TooLarge);
  io.v6_fail = Some(SendError::TooLarge);
  let querier = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 50), 5353));
  let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
  t += 100_000;
  io.inbound
    .push_back(inbound_from(querier, build_ptr_query(&qname)));
  engine.pump(at(t), &mut io, &mut scratch); // arms the §6 20–120 ms jitter
  t += 200_000;
  engine.pump(at(t), &mut io, &mut scratch); // fires the reply — undeliverable

  let mut conflict = false;
  while let Some(u) = engine.poll_service_update(handle) {
    conflict |= matches!(u, ServiceUpdate::Conflict | ServiceUpdate::HostConflict);
  }
  assert!(
    !conflict,
    "an unanswerable question must not tear down a healthy service"
  );
  assert!(
    engine.services.contains_key(&handle),
    "the service must still be registered"
  );
  assert!(
    !engine.services[&handle].errored,
    "the service must still be pumped — a one-shot reply is best-effort"
  );
  assert_eq!(
    service_state(&engine, handle),
    ServiceState::Established,
    "the lifecycle is untouched: the undeliverable reply clears its commit token \
     with nothing latched and nothing advanced"
  );
}

/// The precision the previous test must not cost: an undeliverable SUSTAINED
/// datagram still retires its producer. A query is always `Sustained`, so a
/// question too large for every reachable socket must still terminate the query
/// rather than re-offer it forever.
#[test]
fn an_undeliverable_sustained_datagram_still_retires_its_producer() {
  use mdns_proto::{QuerySpec, wire::ResourceType};

  let mut engine: TestEngine = Engine::new(EndpointConfig::new(), StdRng::seed_from_u64(92));
  let mut io = MockUdp {
    v4_fail: Some(SendError::TooLarge),
    v6_fail: Some(SendError::TooLarge),
    ..Default::default()
  };
  let mut scratch = [0u8; 1500];
  let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let q = engine
    .start_query(QuerySpec::new(qname, ResourceType::Ptr), at(0))
    .unwrap();

  let mut terminal = false;
  let mut t = 0i64;
  for _ in 0..20 {
    engine.pump(at(t), &mut io, &mut scratch);
    while let Some(u) = engine.poll_query_update(q) {
      terminal |= matches!(u, QueryUpdate::Timeout | QueryUpdate::Done);
    }
    if terminal {
      break;
    }
    t += 250_000;
  }
  assert!(
    terminal,
    "a question that can never be sent must retire the query, not re-offer it \
     forever"
  );
  assert!(
    io.sent.is_empty(),
    "nothing may reach a wire when every send is permanently too large"
  );
}

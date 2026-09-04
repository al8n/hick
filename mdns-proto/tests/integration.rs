//! Sync in-process integration tests for the proto state machines.

#![cfg(all(feature = "std", feature = "slab"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::{net::Ipv4Addr, time::Instant as StdInstant};

use mdns_proto::{
  CollectedAnswer, FamilyAttempt, Name, Query, QueryHandle, ServiceHandle,
  cache::CacheEntry,
  config::{EndpointConfig, QuerySpec, ServiceSpec},
  endpoint::{Endpoint, EndpointEventEntry, Provenance, Received, ServiceRoute},
  event::{QueryUpdate, ServiceUpdate},
  records::ServiceRecords,
  transmit::Transmit,
  wire::ResourceType,
};

type TestQuery = Query<StdInstant, slab::Slab<CollectedAnswer>, slab::Slab<QueryUpdate>>;

type Endp = Endpoint<
  StdInstant,
  rand::rngs::StdRng,
  slab::Slab<CacheEntry<StdInstant>>,
  slab::Slab<ServiceRoute<StdInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>>,
  slab::Slab<TestQuery>,
  slab::Slab<EndpointEventEntry>,
  slab::Slab<CollectedAnswer>,
  slab::Slab<QueryUpdate>,
  slab::Slab<Transmit>,
  slab::Slab<ServiceUpdate>,
>;

fn build_responder() -> (Endp, ServiceHandle) {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([0u8; 32]);
  let mut e = Endp::try_new(EndpointConfig::new(), rng);
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 631, 120);
  recs.add_a(Ipv4Addr::new(192, 168, 1, 10));
  let now = StdInstant::now();
  let h = e.try_register_service(ServiceSpec::new(recs), now).unwrap();
  (e, h)
}

fn build_querier() -> (Endp, QueryHandle) {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([1u8; 32]);
  let mut e = Endp::try_new(EndpointConfig::new(), rng);
  let qn = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  let spec = QuerySpec::new(qn, ResourceType::Any);
  let now = StdInstant::now();
  let h = e.try_start_query(spec, now).unwrap();
  (e, h)
}

#[test]
fn responder_starts_in_init_state() {
  let (e, h) = build_responder();
  assert!(e.service(h).unwrap().state().is_init());
}

#[test]
fn querier_emits_question_on_first_poll() {
  let (mut e, h) = build_querier();
  let mut buf = [0u8; 1500];
  let now = StdInstant::now();
  let tx = e.poll_query_transmit(h, || now, &mut buf).unwrap();
  assert!(tx.is_some());
  let t = tx.unwrap();
  assert_eq!(t.dst().port(), 5353);
}

#[test]
fn responder_advances_through_states_with_time() {
  use std::time::Duration;
  let (mut e, h) = build_responder();
  // Push the clock forward in 300 ms increments to bypass the initial
  // 0–250 ms random wait and three subsequent 250 ms probe intervals.
  // probes (like announcements) advance only on a CONFIRMED send, so
  // drain each tick's transmits and report delivery — mirroring the driver.
  let mut now = StdInstant::now();
  let mut buf = [0u8; 1500];
  for _ in 0..10 {
    now += Duration::from_millis(300);
    let _ = e.handle_service_timeout(h, now);
    while e.poll_service_transmit(h, now, &mut buf).unwrap().is_some() {
      let _ = e.note_service_transmit_outcome(
        h,
        now,
        FamilyAttempt::Accepted { at: now },
        FamilyAttempt::Accepted { at: now },
      );
    }
  }
  // After enough probe + announce ticks, we expect the service to have
  // moved past Init/Probing.
  assert!(
    e.service(h).unwrap().state().is_announcing() || e.service(h).unwrap().state().is_established(),
    "state was {:?}",
    e.service(h).unwrap().state()
  );
}

#[test]
fn duplicate_service_registration_rejected() {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([2u8; 32]);
  let mut e = Endp::try_new(EndpointConfig::new(), rng);
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Dup._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let recs1 = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 631, 120);
  let now = StdInstant::now();
  let _r1 = e
    .try_register_service(ServiceSpec::new(recs1), now)
    .unwrap();
  let recs2 = ServiceRecords::new(stype, inst, host, 631, 120);
  let r2 = e.try_register_service(ServiceSpec::new(recs2), now);
  assert!(r2.is_err());
  let err = r2.err().expect("expected Err but got Ok");
  assert!(err.is_name_already_registered());
}

/// RFC 6762 §8.1 — a driver that drains `Service::poll_transmit` in a loop
/// must receive exactly ONE datagram per scheduled deadline tick.
#[test]
fn service_polls_one_transmit_per_deadline() {
  use std::time::Duration;

  let (mut e, h) = build_responder();
  let now = StdInstant::now();

  // First tick: Init -> Probing(0); schedules a probe delay (0-250 ms).
  // No transmit yet -- the probe fires when that delay elapses.
  let now1 = now + Duration::from_millis(300);
  e.handle_service_timeout(h, now1).unwrap();
  assert!(
    e.service(h).unwrap().state().is_probing(),
    "expected Probing state after first tick"
  );

  let mut buf = [0u8; 1500];
  // poll_transmit returns None because transmit_pending is still false.
  let before_probe = e.poll_service_transmit(h, now1, &mut buf).unwrap();
  assert!(
    before_probe.is_none(),
    "expected no transmit before probe delay fires"
  );

  // Second tick: advance past the probe delay to fire the Probing(0) deadline.
  let now2 = now1 + Duration::from_millis(300);
  e.handle_service_timeout(h, now2).unwrap();

  // First poll_transmit: transmit_pending was set by handle_timeout -> Some.
  let first = e.poll_service_transmit(h, now2, &mut buf).unwrap();
  assert!(first.is_some(), "expected first probe transmit");

  // Second poll_transmit at the same tick: transmit_pending is now false -> None.
  let second = e.poll_service_transmit(h, now2, &mut buf).unwrap();
  assert!(second.is_none(), "expected no second transmit at same tick");
}

/// RFC 6762 §8.1 — service must send exactly three probes before transitioning
/// to the Announcing state. The third probe must be a probe packet, not an
/// announcement, even though the state advances to Announcing after the final
/// probe deadline fires.
#[test]
fn service_emits_three_probes_before_announcement() {
  use std::time::Duration;
  let (mut e, h) = build_responder();
  let mut now = StdInstant::now();
  let mut buf = [0u8; 1500];
  let mut probes_emitted = 0u32;
  let mut announcements_emitted = 0u32;

  // Walk the clock in 100 ms increments for up to 3 seconds, counting
  // probe and announcement packets until we have seen all three probes.
  // a probe advances the §8.1 sequence only on a CONFIRMED send, so
  // report delivery for each emitted datagram (as the driver does).
  for _ in 0..30 {
    now += Duration::from_millis(100);
    e.handle_service_timeout(h, now).unwrap();
    while let Some(tx) = e.poll_service_transmit(h, now, &mut buf).unwrap() {
      let msg = &buf[..tx.size()];
      let reader = mdns_proto::wire::MessageReader::try_parse(msg).unwrap();
      let hdr = reader.header();
      if !hdr.flags().is_response() && hdr.question_count() >= 1 {
        probes_emitted = probes_emitted.saturating_add(1);
      } else if hdr.flags().is_response() && hdr.answer_count() >= 1 {
        announcements_emitted = announcements_emitted.saturating_add(1);
      }
      let _ = e.note_service_transmit_outcome(
        h,
        now,
        FamilyAttempt::Accepted { at: now },
        FamilyAttempt::Accepted { at: now },
      );
    }
    if probes_emitted >= 3 {
      break;
    }
  }
  assert_eq!(
    probes_emitted, 3,
    "expected exactly 3 probes before announcing"
  );
  assert_eq!(
    announcements_emitted, 0,
    "no announcements should precede the third probe"
  );

  // Continue for up to another 3 seconds and confirm at least one announcement.
  for _ in 0..30 {
    now += Duration::from_millis(100);
    e.handle_service_timeout(h, now).unwrap();
    while let Some(tx) = e.poll_service_transmit(h, now, &mut buf).unwrap() {
      let msg = &buf[..tx.size()];
      let reader = mdns_proto::wire::MessageReader::try_parse(msg).unwrap();
      let hdr = reader.header();
      if hdr.flags().is_response() && hdr.answer_count() >= 1 {
        announcements_emitted = announcements_emitted.saturating_add(1);
      }
      let _ = e.note_service_transmit_outcome(
        h,
        now,
        FamilyAttempt::Accepted { at: now },
        FamilyAttempt::Accepted { at: now },
      );
    }
    if announcements_emitted >= 1 {
      break;
    }
  }
  assert!(
    announcements_emitted >= 1,
    "expected at least one announcement after probing"
  );
}

/// RFC 6762 §5.2 — a driver that calls `poll_transmit` in a loop must receive
/// exactly ONE datagram per scheduled deadline tick, not a continuous stream.
#[test]
fn query_polls_one_transmit_per_deadline() {
  use std::time::Duration;

  let (mut e, h) = build_querier();
  let mut buf = [0u8; 1500];
  let now = StdInstant::now();

  // First call: transmit_pending starts true → yields a datagram.
  let tx1 = e.poll_query_transmit(h, || now, &mut buf).unwrap();
  assert!(tx1.is_some(), "expected first poll_transmit to return Some");
  // the retry is scheduled on a CONFIRMED delivery, not at encode
  // time. Confirm the send so the backoff deadline is armed.
  let _ = e.note_query_transmit_outcome(
    h,
    now,
    FamilyAttempt::Accepted { at: now },
    FamilyAttempt::Accepted { at: now },
  );

  // Second call immediately: transmit_pending is now false → None.
  let tx2 = e.poll_query_transmit(h, || now, &mut buf).unwrap();
  assert!(
    tx2.is_none(),
    "expected second poll_transmit (same tick) to return None"
  );

  // Advance clock past the first retry deadline (initial interval is 1 s).
  let later = now + Duration::from_secs(2);
  e.handle_query_timeout(h, later).unwrap();

  // After handle_query_timeout fires, transmit_pending is set again.
  let tx3 = e.poll_query_transmit(h, || later, &mut buf).unwrap();
  assert!(
    tx3.is_some(),
    "expected poll_transmit after handle_query_timeout to return Some"
  );

  // And again it is consumed: a second call still returns None.
  let tx4 = e.poll_query_transmit(h, || later, &mut buf).unwrap();
  assert!(
    tx4.is_none(),
    "expected poll_transmit to be None after consuming the retry send"
  );
}

// ── caller-supplied self-loopback flag ─────────────────────────

/// `Endpoint::handle` suppresses ALL side effects (cache writes, query
/// dispatch, service events) when the caller passes `caller_is_self = true`,
/// and processes the SAME bytes normally when it passes `false`. The
/// content-matching + arrival-ordering that decides the flag now lives in
/// the driver (std layer with kernel timestamps); this test pins the
/// proto-side mechanism the flag drives.
#[test]
fn r37r17_caller_is_self_suppresses_dispatch() {
  use mdns_proto::wire::{Flags, Header, MessageBuilder};
  use std::net::IpAddr;

  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([42u8; 32]);
  let mut e = Endp::try_new(EndpointConfig::new(), rng);
  let qname = Name::try_from_str("Demo._ipp._tcp.local.").unwrap();
  let now = StdInstant::now();

  let mut buf = [0u8; 512];
  let n = {
    let header = Header::new().with_flags(Flags::new().with_response());
    let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
    let target = Name::try_from_str("host.local.").unwrap();
    b.push_srv_answer(&qname, 120, 0, 0, 8080, &target, true)
      .unwrap();
    b.finish().unwrap()
  };
  let packet = buf[..n].to_vec();
  let src = "192.0.2.50:5353".parse().unwrap();
  let local_ip: IpAddr = "192.0.2.20".parse().unwrap();

  // caller_is_self = false → the SRV answer is dispatched to the query.
  let qh_peer = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Srv), now)
    .unwrap();
  for ev in e
    .handle(
      now,
      Received::new(src, &packet, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
  {
    let _ = ev;
  }
  assert_eq!(
    e.collected_answers(qh_peer).count(),
    1,
    "caller_is_self = false must dispatch the answer"
  );

  // caller_is_self = true → identical bytes are suppressed as self.
  let qh_self = e
    .try_start_query(QuerySpec::new(qname, ResourceType::Srv), now)
    .unwrap();
  for ev in e
    .handle(
      now,
      Received::new(src, &packet, Provenance::OwnEcho).with_local_ip(local_ip),
    )
    .unwrap()
  {
    let _ = ev;
  }
  assert_eq!(
    e.collected_answers(qh_self).count(),
    0,
    "caller_is_self = true must suppress the answer as self-loopback"
  );
}

/// a Multicast DNS RESPONSE (QR=1) is only trusted from UDP source
/// port 5353 (RFC 6762). A response from an ephemeral port must not populate
/// queries/cache. QR=0 queries are exempt (not exercised here — they carry no
/// answer side effects to observe).
#[test]
fn r37r27_response_from_non_5353_source_port_is_ignored() {
  use mdns_proto::wire::{Flags, Header, MessageBuilder};
  use std::net::IpAddr;

  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([7u8; 32]);
  let mut e = Endp::try_new(EndpointConfig::new(), rng);
  let qname = Name::try_from_str("Demo._ipp._tcp.local.").unwrap();
  let now = StdInstant::now();

  let mut buf = [0u8; 512];
  let n = {
    let header = Header::new().with_flags(Flags::new().with_response());
    let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
    let target = Name::try_from_str("host.local.").unwrap();
    b.push_srv_answer(&qname, 120, 0, 0, 8080, &target, true)
      .unwrap();
    b.finish().unwrap()
  };
  let packet = buf[..n].to_vec();
  let local_ip: IpAddr = "192.0.2.20".parse().unwrap();

  // Response from an ephemeral source port → ignored.
  let bad_src = "192.0.2.50:54321".parse().unwrap();
  let qh_bad = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Srv), now)
    .unwrap();
  for ev in e
    .handle(
      now,
      Received::new(bad_src, &packet, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
  {
    let _ = ev;
  }
  assert_eq!(
    e.collected_answers(qh_bad).count(),
    0,
    "a QR=1 response from a non-5353 source port must be ignored (RFC 6762 §11)"
  );

  // Control: the SAME response from port 5353 is accepted.
  let good_src = "192.0.2.50:5353".parse().unwrap();
  let qh_good = e
    .try_start_query(QuerySpec::new(qname, ResourceType::Srv), now)
    .unwrap();
  for ev in e
    .handle(
      now,
      Received::new(good_src, &packet, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
  {
    let _ = ev;
  }
  assert_eq!(
    e.collected_answers(qh_good).count(),
    1,
    "a response from port 5353 must be accepted"
  );
}

// ── unregister_service releases the route slot ──────────────

/// After `unregister_service`, the same instance name can be re-registered.
#[test]
fn r37_unregister_service_allows_reregister_same_name() {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([55u8; 32]);
  let mut e = Endp::try_new(EndpointConfig::new(), rng);
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Reg._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();

  let recs = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 631, 120);
  let now = StdInstant::now();
  let h = e.try_register_service(ServiceSpec::new(recs), now).unwrap();

  // Second register with same name is rejected.
  let recs2 = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 631, 120);
  let result2 = e.try_register_service(ServiceSpec::new(recs2), now);
  match result2 {
    Err(e) => assert!(e.is_name_already_registered()),
    Ok(_) => panic!("must reject duplicate name"),
  }

  // Unregister and re-register: this must succeed.
  let removed = e.force_remove_service(h, now);
  assert!(removed, "force-removal must report a removal");

  let recs3 = ServiceRecords::new(stype, inst, host, 631, 120);
  let h2 = match e.try_register_service(ServiceSpec::new(recs3), now) {
    Ok(ok) => ok,
    Err(_) => panic!("re-register after unregister must succeed"),
  };
  assert_ne!(h2, h, "re-registered service gets a fresh handle");
}

/// Double-unregister is idempotent: the second call returns `false`.
#[test]
fn r37_double_unregister_is_idempotent() {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([56u8; 32]);
  let mut e = Endp::try_new(EndpointConfig::new(), rng);
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Dbl._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let now = StdInstant::now();
  let h = e.try_register_service(ServiceSpec::new(recs), now).unwrap();
  assert!(
    e.force_remove_service(h, now),
    "the first force-removal removes the route"
  );
  assert!(
    !e.force_remove_service(h, now),
    "a second force-removal of the same handle is a no-op"
  );
}

// ── src==local_ip is NOT a self signal ────────────────────

/// A co-resident mDNS peer on the same real NIC sends from the same
/// interface address we receive on (`src == local_ip`), yet we did NOT
/// send that packet (no `observe_send`). It MUST be processed as peer
/// traffic, not suppressed — otherwise we'd hide same-host
/// mDNSResponder/avahi/other-Endpoint traffic and miss name conflicts.
#[test]
fn r37r13_src_equals_local_ip_is_not_self() {
  use mdns_proto::wire::{Flags, Header, MessageBuilder};

  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([88u8; 32]);
  let mut e = Endp::try_new(EndpointConfig::new(), rng);
  let qname = Name::try_from_str("CoResident._ipp._tcp.local.").unwrap();
  let now = StdInstant::now();
  let qh = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Srv), now)
    .unwrap();

  let mut buf = [0u8; 512];
  let n = {
    let header = Header::new().with_flags(Flags::new().with_response());
    let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
    let target = Name::try_from_str("host.local.").unwrap();
    b.push_srv_answer(&qname, 120, 0, 0, 8080, &target, true)
      .unwrap();
    b.finish().unwrap()
  };
  let packet = buf[..n].to_vec();

  // NOTE: no observe_send — this packet is a CO-RESIDENT PEER's, not ours.
  // Its source IP happens to equal the local receive address (every
  // same-host mDNS sender egresses from the host's interface IP).
  let local_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
  let peer_src = std::net::SocketAddr::new(local_ip, 5353);
  // caller_is_self = false: the driver determined this is NOT our own
  // loopback. src == local_ip must not, by itself, suppress it.
  for ev in e
    .handle(
      now,
      Received::new(peer_src, &packet, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
  {
    let _ = ev;
  }
  assert_eq!(
    e.collected_answers(qh).count(),
    1,
    "a co-resident peer packet (src == local_ip, caller_is_self = false) must \
     be processed, NOT suppressed as self"
  );
}

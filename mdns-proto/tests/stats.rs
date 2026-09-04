//! Stats counter integration test for `mdns-proto`.
//!
//! Exercises the `Endpoint::stats()` snapshot after a scripted exchange and
//! verifies that the atomic counters reflect the operations performed.

#![cfg(all(feature = "stats", feature = "std", feature = "slab"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{net::Ipv4Addr, time::Instant as StdInstant};

use std::time::Duration;

use mdns_proto::{
  CollectedAnswer, FamilyAttempt, Name, Query, ServiceHandle,
  cache::CacheEntry,
  config::{EndpointConfig, QuerySpec, ServiceSpec},
  endpoint::{Endpoint, EndpointEventEntry, Provenance, Received, ServiceRoute},
  event::{QueryUpdate, ServiceUpdate},
  records::ServiceRecords,
  transmit::Transmit,
  wire::{Flags, Header, MessageBuilder, ResourceType},
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

fn make_endpoint(seed: u8) -> Endp {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([seed; 32]);
  Endp::try_new(EndpointConfig::new(), rng)
}

/// Build an mDNS response datagram containing one SRV answer record.
fn build_srv_response(qname: &Name) -> Vec<u8> {
  let mut buf = [0u8; 512];
  let header = Header::new().with_flags(Flags::new().with_response());
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
  let target = Name::try_from_str("host.local.").unwrap();
  b.push_srv_answer(qname, 120, 0, 0, 8080, &target, true)
    .unwrap();
  let n = b.finish().unwrap();
  buf[..n].to_vec()
}

/// Build an mDNS query datagram containing one question.
fn build_query(qname: &Name) -> Vec<u8> {
  use mdns_proto::wire::ResourceClass;
  let mut buf = [0u8; 512];
  let header = Header::new();
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_question(qname, ResourceType::Srv, ResourceClass::In, false)
    .unwrap();
  let n = b.finish().unwrap();
  buf[..n].to_vec()
}

/// After registering a service the `services_registered` counter must be >= 1.
#[test]
fn stats_services_registered() {
  let mut e = make_endpoint(0);

  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("StatsTest._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("stats-host.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 631, 120);
  recs.add_a(Ipv4Addr::new(192, 168, 1, 42));
  let now = StdInstant::now();
  let _ = e.try_register_service(ServiceSpec::new(recs), now).unwrap();

  let snap = e.stats();
  assert!(
    snap.services_registered >= 1,
    "services_registered must be >= 1 after registering; got {}",
    snap.services_registered
  );
}

/// After calling `handle()` with an inbound response datagram the
/// `packets_rx` counter must be >= 1 and `answers_rx` must be >= 1
/// (the response carries one SRV answer record).
#[test]
fn stats_packets_rx_and_answers_rx() {
  let mut e = make_endpoint(1);
  let qname = Name::try_from_str("StatsProbe._ipp._tcp.local.").unwrap();
  let now = StdInstant::now();

  // Start a query so the response is actually dispatched.
  let _qh = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Srv), now)
    .unwrap();

  let packet = build_srv_response(&qname);
  let src = "192.0.2.100:5353".parse().unwrap();
  let local_ip = "192.0.2.20".parse().unwrap();

  // Consume the RouteEvents iterator so all side effects are applied.
  for ev in e
    .handle(
      now,
      Received::new(src, &packet, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
  {
    let _ = ev;
  }

  let snap = e.stats();
  assert!(
    snap.packets_rx >= 1,
    "packets_rx must be >= 1 after handle(); got {}",
    snap.packets_rx
  );
  assert!(
    snap.answers_rx >= 1,
    "answers_rx must be >= 1 after handling a response with one SRV record; got {}",
    snap.answers_rx
  );
}

/// After calling `handle()` with an inbound QUERY datagram (QR=0) the
/// `questions_rx` counter must be >= 1.
///
/// RFC 6762 §6: the endpoint processes incoming questions from peers to detect
/// duplicate questions and suppress its own retransmission.
#[test]
fn stats_questions_rx() {
  let mut e = make_endpoint(2);
  let qname = Name::try_from_str("StatsQRx._ipp._tcp.local.").unwrap();
  let now = StdInstant::now();

  // Register a service so the endpoint has context, then start a matching
  // query so the inbound peer question is seen as a duplicate-question.
  let _qh = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Srv), now)
    .unwrap();

  let packet = build_query(&qname);
  // Must arrive from port 5353 so the query path is taken.
  let src = "192.0.2.50:5353".parse().unwrap();
  let local_ip = "192.0.2.20".parse().unwrap();

  for ev in e
    .handle(
      now,
      Received::new(src, &packet, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
  {
    let _ = ev;
  }

  let snap = e.stats();
  assert!(
    snap.questions_rx >= 1,
    "questions_rx must be >= 1 after handling an inbound query; got {}",
    snap.questions_rx
  );
}

/// Combined: register a service, feed an answer, feed a query.
/// Assert all three key counters simultaneously.
#[test]
fn stats_combined_exchange() {
  let mut e = make_endpoint(3);
  let stype = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("StatsCombined._http._tcp.local.").unwrap();
  let host = Name::try_from_str("sc-host.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst.clone(), host, 80, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
  let now = StdInstant::now();

  let _ = e.try_register_service(ServiceSpec::new(recs), now).unwrap();

  // Feed an answer response.
  let _qh = e
    .try_start_query(QuerySpec::new(inst.clone(), ResourceType::Srv), now)
    .unwrap();
  let ans_pkt = build_srv_response(&inst);
  let src = "192.0.2.200:5353".parse().unwrap();
  let local_ip = "192.0.2.20".parse().unwrap();
  for ev in e
    .handle(
      now,
      Received::new(src, &ans_pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
  {
    let _ = ev;
  }

  let snap = e.stats();
  assert!(
    snap.services_registered >= 1,
    "services_registered: {}",
    snap.services_registered
  );
  assert!(snap.packets_rx >= 1, "packets_rx: {}", snap.packets_rx);
  assert!(snap.answers_rx >= 1, "answers_rx: {}", snap.answers_rx);
}

// ── regression: tx counters must reflect CONFIRMED delivery only ──────────

/// Helper: build a service that bypasses the probe sequence (starts directly
/// in `Announcing`), registered via an `Endpoint` so stats are attached.
fn make_no_probe_endpoint() -> (Endp, ServiceHandle) {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([7u8; 32]);
  let cfg = EndpointConfig::new().with_probe_unique_names(false);
  let mut e = Endp::try_new(cfg, rng);
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("TxTest._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("txtest-host.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 631, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 1, 1));
  let now = StdInstant::now();
  let h = e.try_register_service(ServiceSpec::new(recs), now).unwrap();
  (e, h)
}

/// Helper: advance `now` far enough that the service fires its next deadline,
/// call `handle_timeout`, then return `(ok_tx, now)` where `ok_tx` is whether
/// `poll_transmit` produced a datagram.
fn tick(e: &mut Endp, h: ServiceHandle, now: StdInstant) -> (bool, StdInstant) {
  let advanced = now + Duration::from_millis(1100);
  e.handle_service_timeout(h, advanced).unwrap();
  let mut buf = vec![0u8; 4096];
  let ok = e
    .poll_service_transmit(h, advanced, &mut buf)
    .unwrap()
    .is_some();
  (ok, advanced)
}

/// All-socket-failure: drive the service through probe, announce,
/// and response, confirming that no family carried them to every
/// `note_transmit_outcome`. After N ticks, NONE of the `*_tx` counters should
/// have advanced.
#[test]
fn tx_counters_stay_zero_on_all_socket_failure() {
  let (mut e, h) = make_no_probe_endpoint();

  // Drive two announce cycles (service starts in Announcing; the no-probe
  // config fires the first announce at delay=0, the second at +1 s).
  let mut now = StdInstant::now();
  for _ in 0..6 {
    let (ok, next) = tick(&mut e, h, now);
    now = next;
    if ok {
      let _ = e.note_service_transmit_outcome(
        h,
        now,
        FamilyAttempt::Refused { permanent: false },
        FamilyAttempt::Refused { permanent: false },
      ); // all-socket-failure
    }
  }

  let snap = e.stats();
  assert_eq!(
    snap.probes_tx, 0,
    "probes_tx must be 0 under all-socket-failure; got {}",
    snap.probes_tx
  );
  assert_eq!(
    snap.announcements_tx, 0,
    "announcements_tx must be 0 under all-socket-failure; got {}",
    snap.announcements_tx
  );
  assert_eq!(
    snap.responses_tx, 0,
    "responses_tx must be 0 under all-socket-failure; got {}",
    snap.responses_tx
  );
  assert_eq!(
    snap.goodbyes_tx, 0,
    "goodbyes_tx must be 0 under all-socket-failure; got {}",
    snap.goodbyes_tx
  );
}

/// Confirmed delivery: drive the service through probe and two
/// announce cycles with `delivered=true`. Each confirmed send must increment
/// the matching `*_tx` counter exactly once.
#[test]
fn tx_counters_advance_on_confirmed_delivery() {
  use rand::SeedableRng;

  // Use a probing-enabled endpoint so we can also exercise probes_tx.
  let rng = rand::rngs::StdRng::from_seed([8u8; 32]);
  let cfg = EndpointConfig::new(); // probe_unique_names = true (default)
  let mut e = Endp::try_new(cfg, rng);
  let stype = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("TxConfirm._http._tcp.local.").unwrap();
  let host = Name::try_from_str("txconfirm-host.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 80, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 2, 2));
  let start = StdInstant::now();
  let h = e
    .try_register_service(ServiceSpec::new(recs), start)
    .unwrap();

  // Pump until Established, confirming every send.
  let mut now = start;
  for _ in 0..20 {
    now += Duration::from_millis(1100);
    e.handle_service_timeout(h, now).unwrap();
    let mut buf = vec![0u8; 4096];
    if e.poll_service_transmit(h, now, &mut buf).unwrap().is_some() {
      let _ = e.note_service_transmit_outcome(
        h,
        now,
        FamilyAttempt::Accepted { at: now },
        FamilyAttempt::Accepted { at: now },
      );
    }
    if e.service(h).unwrap().state() == mdns_proto::ServiceState::Established {
      break;
    }
  }
  assert_eq!(
    e.service(h).unwrap().state(),
    mdns_proto::ServiceState::Established,
    "service must reach Established within 20 ticks"
  );

  let snap = e.stats();
  // RFC §8.1: exactly 3 probes; RFC §8.3: exactly 2 announcements.
  assert_eq!(
    snap.probes_tx, 3,
    "probes_tx must be exactly 3 after startup; got {}",
    snap.probes_tx
  );
  assert_eq!(
    snap.announcements_tx, 2,
    "announcements_tx must be exactly 2 after startup; got {}",
    snap.announcements_tx
  );
  // goodbyes_tx stays 0 — no service was unregistered.
  assert_eq!(
    snap.goodbyes_tx, 0,
    "goodbyes_tx must be 0 before any unregister; got {}",
    snap.goodbyes_tx
  );
}

/// `probes_tx` / `announcements_tx` mean "confirmed delivered to every obligated
/// link". The core's patience bound eventually EXCUSES a link that never accepts
/// and advances the phase without it — that advance is not a delivery, so it must
/// leave both counters alone. Otherwise a permanently half-broken host reports a
/// full, healthy startup while one whole family heard nothing.
#[test]
fn excused_rounds_do_not_count_as_delivered_transmits() {
  use rand::SeedableRng;

  let rng = rand::rngs::StdRng::from_seed([9u8; 32]);
  let mut e = Endp::try_new(EndpointConfig::new(), rng);
  let stype = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("Excused._http._tcp.local.").unwrap();
  let host = Name::try_from_str("excused-host.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 80, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 2, 3));
  let start = StdInstant::now();
  let h = e
    .try_register_service(ServiceSpec::new(recs), start)
    .unwrap();

  // Every round is partially delivered, so the lifecycle only ever moves on an
  // excused advance.
  let mut now = start;
  for _ in 0..200 {
    now += Duration::from_millis(1100);
    e.handle_service_timeout(h, now).unwrap();
    let mut buf = vec![0u8; 4096];
    if e.poll_service_transmit(h, now, &mut buf).unwrap().is_some() {
      let _ = e.note_service_transmit_outcome(
        h,
        now,
        FamilyAttempt::Accepted { at: now },
        FamilyAttempt::Refused { permanent: false },
      );
    }
    if e.service(h).unwrap().state() == mdns_proto::ServiceState::Established {
      break;
    }
  }
  assert_eq!(
    e.service(h).unwrap().state(),
    mdns_proto::ServiceState::Established,
    "the bound must carry a permanently half-delivered service to Established"
  );

  let snap = e.stats();
  assert_eq!(
    snap.probes_tx, 0,
    "no probe reached every obligated link, so probes_tx must stay 0; got {}",
    snap.probes_tx
  );
  assert_eq!(
    snap.announcements_tx, 0,
    "no announcement reached every obligated link, so announcements_tx must stay \
     0; got {}",
    snap.announcements_tx
  );
  assert!(
    !e.service(h).unwrap().has_fully_announced().get(),
    "and the reclaim-cancel gate stays shut for the same reason"
  );
}

// ── rejected datagrams must register a drop/error signal ────────────

/// An invalid-opcode packet (opcode != Query) must bump `packets_rx` AND
/// `packets_dropped`, and must NOT bump `parse_errors`.
#[test]
fn handle_invalid_opcode_bumps_packets_dropped() {
  let mut e = make_endpoint(9);
  let src = "192.0.2.5:5353".parse().unwrap();
  let local_ip = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();

  // DNS header with opcode = Status (2), not Query: flags byte 2 = 0x10
  // (opcode field is bits 14-11 of the 16-bit flags word → top nibble of
  // byte 2 in the wire header).
  let bad_opcode = [0u8, 0, 0x10, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
  let before = e.stats();
  let result = e.handle(
    now,
    Received::new(src, &bad_opcode, Provenance::Unknown).with_local_ip(local_ip),
  );
  assert!(
    matches!(result, Err(mdns_proto::HandleError::InvalidOpcode(_))),
    "expected Err(InvalidOpcode)"
  );
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "packets_rx must be bumped for an invalid-opcode packet"
  );
  assert_eq!(
    after.packets_dropped,
    before.packets_dropped + 1,
    "packets_dropped must be bumped for an invalid-opcode packet"
  );
  assert_eq!(
    after.parse_errors, before.parse_errors,
    "parse_errors must NOT be bumped for an invalid-opcode packet"
  );
}

/// An invalid-rcode packet (RCODE != NoError) must bump `packets_rx` AND
/// `packets_dropped`, and must NOT bump `parse_errors`.
#[test]
fn handle_invalid_rcode_bumps_packets_dropped() {
  let mut e = make_endpoint(10);
  let src = "192.0.2.6:5353".parse().unwrap();
  let local_ip = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();

  // DNS header with opcode = Query (0) and RCODE = FormatError (1):
  // flags bytes are 0x00 0x01.
  let bad_rcode = [0u8, 0, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
  let before = e.stats();
  let result = e.handle(
    now,
    Received::new(src, &bad_rcode, Provenance::Unknown).with_local_ip(local_ip),
  );
  assert!(
    matches!(result, Err(mdns_proto::HandleError::InvalidResponseCode(_))),
    "expected Err(InvalidResponseCode)"
  );
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "packets_rx must be bumped for an invalid-rcode packet"
  );
  assert_eq!(
    after.packets_dropped,
    before.packets_dropped + 1,
    "packets_dropped must be bumped for an invalid-rcode packet"
  );
  assert_eq!(
    after.parse_errors, before.parse_errors,
    "parse_errors must NOT be bumped for an invalid-rcode packet"
  );
}

/// Build an mDNS RESPONSE datagram that has a valid header but a truncated /
/// malformed answer record (rdlength claims more bytes than the packet
/// contains).  This forces a lazy parse error in the RouteEvents answer
/// section iterator.
fn build_response_with_malformed_answer() -> Vec<u8> {
  // Build a well-formed answer so we have the wire name in one shot, then
  // truncate the rdata so the parser hits a truncation error.
  let qname = Name::try_from_str("broken._ipp._tcp.local.").unwrap();
  let mut buf = [0u8; 512];
  let header = Header::new().with_flags(Flags::new().with_response());
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
  let target = Name::try_from_str("host.local.").unwrap();
  b.push_srv_answer(&qname, 120, 0, 0, 8080, &target, true)
    .unwrap();
  let n = b.finish().unwrap();
  let mut pkt = buf[..n].to_vec();
  // Corrupt the last 4 bytes of rdata so the rdata length still claims the
  // original size but the actual bytes are missing (truncate the packet).
  // The header's answer_count is still 1, so the iterator will try to parse
  // the record and fail.
  let truncated_len = n.saturating_sub(4);
  pkt.truncate(truncated_len);
  pkt
}

/// A packet with a valid header but a truncated answer record must bump
/// `packets_rx` AND `parse_errors`.  The lazy section-parse error surfaces
/// when the caller iterates `RouteEvents`; both counters must reflect it.
#[test]
fn handle_lazy_section_parse_error_bumps_parse_errors() {
  let mut e = make_endpoint(11);
  // Start a matching query so the endpoint processes the answer section.
  let qname = Name::try_from_str("broken._ipp._tcp.local.").unwrap();
  let _qh = e
    .try_start_query(
      QuerySpec::new(qname.clone(), ResourceType::Srv),
      StdInstant::now(),
    )
    .unwrap();

  let src = "192.0.2.7:5353".parse().unwrap();
  let local_ip = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let pkt = build_response_with_malformed_answer();

  let before = e.stats();
  // Iterate the RouteEvents so the lazy section parse fires.
  let route = e
    .handle(
      now,
      Received::new(src, &pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .expect("a well-formed header must not fail at handle() entry");
  let mut saw_parse_err = false;
  for ev in route {
    if ev.is_err() {
      saw_parse_err = true;
    }
  }
  assert!(
    saw_parse_err,
    "expected a lazy parse error from RouteEvents"
  );

  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "packets_rx must be bumped for a packet with a malformed record"
  );
  assert_eq!(
    after.parse_errors,
    before.parse_errors + 1,
    "parse_errors must be bumped when RouteEvents yields a lazy parse error"
  );
}

// ── regression: exactly-once parse_errors across ALL skip gates ──────────
//
// For every section (answer, authority, additional) and both QR values, a
// malformed record must bump `parse_errors` exactly once — never zero,
// never twice (double-count). The skip gates:
//   • Section::Additional    – skipped for QR=0 (!is_response)
//   • Section::Questions     – skipped when answer_questions=false
//   • Section::Authority     – only reached when src.port()==5353

/// Helper: build a truncated A record appended to a packet so the wire parser
/// sees a valid header but cannot read the full rdata.  Writes one complete
/// well-formed record then slices off the last `drop_bytes` bytes.
fn truncate_rdata(mut pkt: Vec<u8>, drop_bytes: usize) -> Vec<u8> {
  let new_len = pkt.len().saturating_sub(drop_bytes);
  pkt.truncate(new_len);
  pkt
}

/// Build a QR=0 query with a malformed ADDITIONAL record.
/// ANCOUNT=0, ARCOUNT=1, the additional record is truncated.
fn build_qr0_malformed_additional() -> Vec<u8> {
  // Build a well-formed QR=0 query with a single A answer, then move it to
  // the additional section by rewriting the header counts.
  let qname = Name::try_from_str("mal-add.local.").unwrap();
  let mut buf = [0u8; 512];
  let header = Header::new(); // QR=0
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 1), false)
    .unwrap();
  let n = b.finish().unwrap();
  let mut pkt = buf[..n].to_vec();
  // Move from answer to additional section: ANCOUNT 1→0 (byte 7), ARCOUNT 0→1 (byte 11).
  pkt[7] = 0;
  pkt[11] = 1;
  // Truncate rdata so the parser fails.
  truncate_rdata(pkt, 3)
}

/// Build a QR=1 response with a malformed ADDITIONAL record.
fn build_qr1_malformed_additional() -> Vec<u8> {
  let qname = Name::try_from_str("mal-add.local.").unwrap();
  let mut buf = [0u8; 512];
  let header = Header::new().with_flags(Flags::new().with_response()); // QR=1
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 2), false)
    .unwrap();
  let n = b.finish().unwrap();
  let mut pkt = buf[..n].to_vec();
  // Move from answer to additional section.
  pkt[7] = 0;
  pkt[11] = 1;
  truncate_rdata(pkt, 3)
}

/// Build a QR=1 response with a malformed ANSWER record.
fn build_qr1_malformed_answer() -> Vec<u8> {
  let qname = Name::try_from_str("mal-ans.local.").unwrap();
  let mut buf = [0u8; 512];
  let header = Header::new().with_flags(Flags::new().with_response());
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 3), false)
    .unwrap();
  let n = b.finish().unwrap();
  truncate_rdata(buf[..n].to_vec(), 3)
}

/// Build a QR=0 query with a malformed ANSWER (known-answer) record.
fn build_qr0_malformed_answer() -> Vec<u8> {
  let qname = Name::try_from_str("mal-ans.local.").unwrap();
  let mut buf = [0u8; 512];
  let header = Header::new(); // QR=0
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 4), false)
    .unwrap();
  let n = b.finish().unwrap();
  truncate_rdata(buf[..n].to_vec(), 3)
}

/// Build a QR=0 probe with a malformed AUTHORITY record (from port 5353).
fn build_qr0_malformed_authority() -> Vec<u8> {
  let qname = Name::try_from_str("mal-auth.local.").unwrap();
  let mut buf = [0u8; 512];
  let header = Header::new(); // QR=0 probe
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_authority(&qname, 120, Ipv4Addr::new(10, 0, 0, 5))
    .unwrap();
  let n = b.finish().unwrap();
  truncate_rdata(buf[..n].to_vec(), 3)
}

/// Helper: assert that handling a datagram bumps `packets_rx` exactly once,
/// bumps `parse_errors` exactly once, and does NOT bump `packets_dropped`.
/// The iterator is always fully drained so all lazy side effects fire.
fn assert_parse_error_exactly_once(e: &mut Endp, pkt: &[u8], src_port: u16, label: &str) {
  let src: std::net::SocketAddr = format!("192.0.2.99:{src_port}").parse().unwrap();
  let local_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let before = e.stats();
  let route = e
    .handle(
      now,
      Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .expect("valid header — handle() must not fail at entry");
  for ev in route {
    let _ = ev; // drain fully; lazy parse errors fire here
  }
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "{label}: packets_rx must be bumped exactly once"
  );
  assert_eq!(
    after.parse_errors,
    before.parse_errors + 1,
    "{label}: parse_errors must be bumped exactly once"
  );
  assert_eq!(
    after.packets_dropped, before.packets_dropped,
    "{label}: packets_dropped must NOT be bumped for a parse error"
  );
}

/// QR=0 query with a malformed ADDITIONAL record.
/// Previously: packets_rx bumped, parse_errors stayed zero (the Section::Additional
/// lazy arm was skipped by the !is_response gate, so the error was never counted).
#[test]
fn r10_qr0_malformed_additional_bumps_parse_errors_exactly_once() {
  let mut e = make_endpoint(20);
  let pkt = build_qr0_malformed_additional();
  assert_parse_error_exactly_once(&mut e, &pkt, 5353, "QR=0 malformed additional");
}

/// QR=1 response with a malformed ADDITIONAL record.
#[test]
fn r10_qr1_malformed_additional_bumps_parse_errors_exactly_once() {
  let mut e = make_endpoint(21);
  let pkt = build_qr1_malformed_additional();
  assert_parse_error_exactly_once(&mut e, &pkt, 5353, "QR=1 malformed additional");
}

/// QR=1 response with a malformed ANSWER record.
#[test]
fn r10_qr1_malformed_answer_bumps_parse_errors_exactly_once() {
  let mut e = make_endpoint(22);
  let pkt = build_qr1_malformed_answer();
  assert_parse_error_exactly_once(&mut e, &pkt, 5353, "QR=1 malformed answer");
}

/// QR=0 query with a malformed ANSWER (known-answer) record.
#[test]
fn r10_qr0_malformed_answer_bumps_parse_errors_exactly_once() {
  let mut e = make_endpoint(23);
  let pkt = build_qr0_malformed_answer();
  assert_parse_error_exactly_once(&mut e, &pkt, 5353, "QR=0 malformed answer");
}

/// QR=0 probe with a malformed AUTHORITY record (from port 5353).
#[test]
fn r10_qr0_malformed_authority_bumps_parse_errors_exactly_once() {
  let mut e = make_endpoint(24);
  let pkt = build_qr0_malformed_authority();
  assert_parse_error_exactly_once(&mut e, &pkt, 5353, "QR=0 malformed authority");
}

/// QR=0 query with answer_questions=false and a malformed ADDITIONAL
/// record.  The Questions section is skipped entirely; the additional-record
/// parse error must still bump parse_errors exactly once (via the eager walk).
#[test]
fn r10_answer_questions_false_malformed_additional_bumps_parse_errors() {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([25u8; 32]);
  let cfg = EndpointConfig::new().with_answer_questions(false);
  let mut e = Endp::try_new(cfg, rng);
  let pkt = build_qr0_malformed_additional();
  assert_parse_error_exactly_once(
    &mut e,
    &pkt,
    5353,
    "answer_questions=false malformed additional",
  );
}

// ── regression: malformed questions + non-5353 authority ─────────────────
//
// The upfront section-validation latch must catch parse errors in sections
// that the ROUTING iterator skips via its internal gates:
//   • Section::Questions — skipped when answer_questions=false
//   • Section::Authority — skipped when src.port() != 5353
//
// Each test below asserts parse_errors bumped exactly once and packets_dropped
// NOT bumped (a section-level gate suppresses routing, not the whole datagram).

/// Build a QR=0 query with a malformed QUESTION record (truncated name).
/// QDCOUNT=1, the question name is truncated (label len 5 with no bytes).
fn build_qr0_malformed_question() -> Vec<u8> {
  // Header: QR=0, QDCOUNT=1, all other counts 0.
  let mut msg = vec![0u8; 12];
  msg[5] = 1; // QDCOUNT = 1
  msg.push(0x05); // label length 5 with no payload → truncated
  msg
}

/// Build a QR=1 response with a malformed QUESTION record (truncated name).
/// RFC 6762 allows QR=1 packets to carry questions (§6); the endpoint must
/// still detect malformed bytes.
fn build_qr1_malformed_question() -> Vec<u8> {
  // Header: QR=1 (flags byte 2 bit 7 set), QDCOUNT=1, ANCOUNT=0.
  let mut msg = vec![0u8; 12];
  msg[2] = 0x84; // QR=1, AA=1 (standard mDNS response flags)
  msg[5] = 1; // QDCOUNT = 1
  msg.push(0x05); // label length 5 with no payload → truncated
  msg
}

/// Build a well-formed QR=0 authority packet from a non-5353 source.
/// Used to verify the no-false-positive case: well-formed bytes from an
/// ephemeral port must NOT bump parse_errors or packets_dropped.
fn build_qr0_well_formed_authority() -> Vec<u8> {
  let qname = Name::try_from_str("auth-host.local.").unwrap();
  let mut buf = [0u8; 512];
  let header = mdns_proto::wire::Header::new(); // QR=0 probe
  let mut b: mdns_proto::wire::MessageBuilder<'_, 0> =
    mdns_proto::wire::MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_authority(&qname, 120, Ipv4Addr::new(10, 0, 0, 9))
    .unwrap();
  let n = b.finish().unwrap();
  buf[..n].to_vec()
}

/// Build a QR=0 probe with a malformed AUTHORITY record from port 5353.
/// Already covered by `r10_qr0_malformed_authority_bumps_parse_errors_exactly_once`;
/// this builder is reused for the non-5353 variant below.
fn build_qr0_malformed_authority_for_r11() -> Vec<u8> {
  build_qr0_malformed_authority()
}

/// Helper: assert that handling a datagram bumps `packets_rx` exactly once,
/// bumps `parse_errors` exactly once, and does NOT bump `packets_dropped`.
/// Identical to `assert_parse_error_exactly_once` but accepts an explicit
/// source port parameter so we can exercise both 5353 and non-5353 paths.
fn assert_parse_error_exactly_once_port(e: &mut Endp, pkt: &[u8], src_port: u16, label: &str) {
  let src: std::net::SocketAddr = format!("192.0.2.99:{src_port}").parse().unwrap();
  let local_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let before = e.stats();
  let route = e
    .handle(
      now,
      Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .expect("valid header — handle() must not fail at entry");
  for ev in route {
    let _ = ev; // drain fully; lazy parse errors fire here
  }
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "{label}: packets_rx must be bumped exactly once"
  );
  assert_eq!(
    after.parse_errors,
    before.parse_errors + 1,
    "{label}: parse_errors must be bumped exactly once"
  );
  assert_eq!(
    after.packets_dropped, before.packets_dropped,
    "{label}: packets_dropped must NOT be bumped for a parse error"
  );
}

/// answer_questions=false + malformed QUESTION in a QR=0 packet.
/// Previously the Section::Questions arm was skipped entirely so the
/// malformed bytes were never detected by the routing iterator.  The upfront
/// section-validation latch must catch it regardless.
#[test]
fn r11_answer_questions_false_malformed_question_qr0_bumps_parse_errors() {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([30u8; 32]);
  let cfg = EndpointConfig::new().with_answer_questions(false);
  let mut e = Endp::try_new(cfg, rng);
  let pkt = build_qr0_malformed_question();
  assert_parse_error_exactly_once_port(
    &mut e,
    &pkt,
    5353,
    "answer_questions=false QR=0 malformed question",
  );
}

/// answer_questions=false + malformed QUESTION in a QR=1 packet.
#[test]
fn r11_answer_questions_false_malformed_question_qr1_bumps_parse_errors() {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([31u8; 32]);
  let cfg = EndpointConfig::new().with_answer_questions(false);
  let mut e = Endp::try_new(cfg, rng);
  let pkt = build_qr1_malformed_question();
  assert_parse_error_exactly_once_port(
    &mut e,
    &pkt,
    5353,
    "answer_questions=false QR=1 malformed question",
  );
}

/// answer_questions=true + malformed QUESTION in a QR=0 packet.
/// With answer_questions=true the routing iterator DOES enter the Questions
/// arm and would have returned Err from there — the latch must still count
/// exactly once (no double-count).
#[test]
fn r11_answer_questions_true_malformed_question_bumps_parse_errors_exactly_once() {
  let mut e = make_endpoint(32);
  let pkt = build_qr0_malformed_question();
  assert_parse_error_exactly_once_port(
    &mut e,
    &pkt,
    5353,
    "answer_questions=true QR=0 malformed question",
  );
}

/// non-5353 source + malformed AUTHORITY record (QR=0).
/// Previously the Section::Authority arm was skipped for non-5353 sources,
/// so the malformed bytes escaped accounting.  The upfront latch walks
/// authority regardless of source port.
#[test]
fn r11_non_5353_malformed_authority_bumps_parse_errors() {
  let mut e = make_endpoint(33);
  let pkt = build_qr0_malformed_authority_for_r11();
  assert_parse_error_exactly_once_port(
    &mut e,
    &pkt,
    40000, // ephemeral port — non-5353
    "non-5353 source QR=0 malformed authority",
  );
}

/// 5353 source + malformed AUTHORITY (keep existing test passing,
/// and verify no double-count now that the latch is the single bump point).
#[test]
fn r11_5353_malformed_authority_bumps_parse_errors_exactly_once() {
  let mut e = make_endpoint(34);
  let pkt = build_qr0_malformed_authority_for_r11();
  assert_parse_error_exactly_once_port(&mut e, &pkt, 5353, "5353 source QR=0 malformed authority");
}

/// No-false-positive: a well-formed packet through the non-5353 authority
/// gate must NOT bump parse_errors or packets_dropped.  The authority records
/// are well-formed bytes; only conflict ROUTING is suppressed, not accounting.
///
/// Documented rule: a well-formed authority record from a non-5353 source is
/// NOT counted as a drop — the datagram's question/answer/additional sections
/// are still processed.  `packets_dropped` is reserved for whole-datagram
/// rejects (invalid opcode, invalid rcode, self-loopback, untrusted QR=1
/// response).
#[test]
fn r11_well_formed_non_5353_authority_no_false_positive() {
  let mut e = make_endpoint(35);
  let pkt = build_qr0_well_formed_authority();
  let src: std::net::SocketAddr = "192.0.2.99:40000".parse().unwrap(); // non-5353
  let local_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let before = e.stats();
  let route = e
    .handle(
      now,
      Received::new(src, &pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .expect("valid header");
  for ev in route {
    let _ = ev;
  }
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "well-formed non-5353 authority: packets_rx must be bumped"
  );
  assert_eq!(
    after.parse_errors, before.parse_errors,
    "well-formed non-5353 authority: parse_errors must NOT be bumped"
  );
  assert_eq!(
    after.packets_dropped, before.packets_dropped,
    "well-formed non-5353 authority: packets_dropped must NOT be bumped \
     (section-level authority suppression is not a whole-datagram drop)"
  );
}

/// No-false-positive: a well-formed packet must NOT bump any reject
/// counter (parse_errors or packets_dropped).
#[test]
fn r11_well_formed_packet_does_not_bump_reject_counters() {
  let mut e = make_endpoint(36);
  let qname = Name::try_from_str("r11-well-formed.local.").unwrap();
  let pkt = build_srv_response(&qname);
  let src: std::net::SocketAddr = "192.0.2.99:5353".parse().unwrap();
  let local_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let before = e.stats();
  let route = e
    .handle(
      now,
      Received::new(src, &pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .expect("valid header");
  for ev in route {
    let _ = ev;
  }
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "well-formed: packets_rx must be bumped"
  );
  assert_eq!(
    after.parse_errors, before.parse_errors,
    "well-formed: parse_errors must NOT be bumped"
  );
  assert_eq!(
    after.packets_dropped, before.packets_dropped,
    "well-formed: packets_dropped must NOT be bumped"
  );
}

/// No-false-positive: a well-formed packet must NOT bump any reject
/// counter (parse_errors or packets_dropped).
#[test]
fn r10_well_formed_packet_does_not_bump_reject_counters() {
  let mut e = make_endpoint(26);
  let qname = Name::try_from_str("well-formed.local.").unwrap();
  let pkt = build_srv_response(&qname);
  let src: std::net::SocketAddr = "192.0.2.99:5353".parse().unwrap();
  let local_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let before = e.stats();
  let route = e
    .handle(
      now,
      Received::new(src, &pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .expect("valid header");
  for ev in route {
    let _ = ev;
  }
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "well-formed: packets_rx must be bumped"
  );
  assert_eq!(
    after.parse_errors, before.parse_errors,
    "well-formed: parse_errors must NOT be bumped"
  );
  assert_eq!(
    after.packets_dropped, before.packets_dropped,
    "well-formed: packets_dropped must NOT be bumped"
  );
}

// ── regression: suppression takes precedence over parse_errors ────────────
//
// Exactly-one-reject-counter invariant: for every (packets_rx += 1) event,
// at most ONE of {parse_errors, packets_dropped} may be incremented.
//
// A suppressed datagram (self-loopback or untrusted QR=1 from non-5353)
// must bump packets_dropped but NOT parse_errors — even if its sections are
// malformed. Running the section-validation latch for a suppressed packet
// would yield two reject counters for one packets_rx.

/// malformed datagram with caller_is_self=true (self-loopback).
/// Suppression takes precedence: packets_dropped +1, parse_errors +0.
#[test]
fn r12_malformed_self_loopback_bumps_dropped_not_parse_errors() {
  let mut e = make_endpoint(40);
  // Use a malformed QR=1 response (truncated answer rdata) as the datagram.
  let pkt = build_qr1_malformed_answer();
  let src: std::net::SocketAddr = "192.0.2.50:5353".parse().unwrap();
  let local_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let before = e.stats();
  // caller_is_self=true triggers self-loopback suppression.
  let route = e
    .handle(
      now,
      Received::new(src, &pkt, Provenance::OwnEcho).with_local_ip(local_ip),
    )
    .expect("valid header — suppression must not prevent handle() returning Ok");
  for ev in route {
    let _ = ev;
  }
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "r12 self-loopback malformed: packets_rx must be bumped exactly once"
  );
  assert_eq!(
    after.packets_dropped,
    before.packets_dropped + 1,
    "r12 self-loopback malformed: packets_dropped must be bumped (suppression)"
  );
  assert_eq!(
    after.parse_errors, before.parse_errors,
    "r12 self-loopback malformed: parse_errors must NOT be bumped \
     (suppression takes precedence over section malformation)"
  );
}

/// malformed QR=1 response from a non-5353 source (untrusted response).
/// Suppression takes precedence: packets_dropped +1, parse_errors +0.
#[test]
fn r12_malformed_untrusted_response_bumps_dropped_not_parse_errors() {
  let mut e = make_endpoint(41);
  // A malformed QR=1 response (truncated answer rdata) from an ephemeral port.
  let pkt = build_qr1_malformed_answer();
  // Non-5353 source port makes this an "untrusted response" (RFC 6762 §6).
  let src: std::net::SocketAddr = "192.0.2.51:40000".parse().unwrap();
  let local_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let before = e.stats();
  let route = e
    .handle(
      now,
      Received::new(src, &pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .expect("valid header");
  for ev in route {
    let _ = ev;
  }
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "r12 untrusted-response malformed: packets_rx must be bumped exactly once"
  );
  assert_eq!(
    after.packets_dropped,
    before.packets_dropped + 1,
    "r12 untrusted-response malformed: packets_dropped must be bumped (suppression)"
  );
  assert_eq!(
    after.parse_errors, before.parse_errors,
    "r12 untrusted-response malformed: parse_errors must NOT be bumped \
     (suppression takes precedence over section malformation)"
  );
}

/// regression-keep: malformed NOT-suppressed datagram must bump parse_errors,
/// not packets_dropped.  Verifies the fix did not over-suppress the latch.
#[test]
fn r12_malformed_not_suppressed_bumps_parse_errors_not_dropped() {
  let mut e = make_endpoint(42);
  // Malformed QR=1 answer, arriving from port 5353 (trusted), caller_is_self=false.
  let pkt = build_qr1_malformed_answer();
  let src: std::net::SocketAddr = "192.0.2.52:5353".parse().unwrap();
  let local_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let before = e.stats();
  let route = e
    .handle(
      now,
      Received::new(src, &pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .expect("valid header");
  for ev in route {
    let _ = ev;
  }
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "r12 not-suppressed malformed: packets_rx must be bumped exactly once"
  );
  assert_eq!(
    after.parse_errors,
    before.parse_errors + 1,
    "r12 not-suppressed malformed: parse_errors must be bumped"
  );
  assert_eq!(
    after.packets_dropped, before.packets_dropped,
    "r12 not-suppressed malformed: packets_dropped must NOT be bumped"
  );
}

/// regression-keep: well-formed suppressed datagram (self-loopback) must
/// bump packets_dropped only; parse_errors must stay zero.
#[test]
fn r12_well_formed_suppressed_bumps_dropped_not_parse_errors() {
  let mut e = make_endpoint(43);
  // Well-formed QR=1 response; self-loopback via caller_is_self=true.
  let qname = Name::try_from_str("r12-wellformed-self.local.").unwrap();
  let pkt = build_srv_response(&qname);
  let src: std::net::SocketAddr = "192.0.2.53:5353".parse().unwrap();
  let local_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
  let now = StdInstant::now();
  let before = e.stats();
  let route = e
    .handle(
      now,
      Received::new(src, &pkt, Provenance::OwnEcho).with_local_ip(local_ip),
    )
    .expect("valid header");
  for ev in route {
    let _ = ev;
  }
  let after = e.stats();
  assert_eq!(
    after.packets_rx,
    before.packets_rx + 1,
    "r12 well-formed suppressed: packets_rx must be bumped exactly once"
  );
  assert_eq!(
    after.packets_dropped,
    before.packets_dropped + 1,
    "r12 well-formed suppressed: packets_dropped must be bumped (suppression)"
  );
  assert_eq!(
    after.parse_errors, before.parse_errors,
    "r12 well-formed suppressed: parse_errors must NOT be bumped"
  );
}

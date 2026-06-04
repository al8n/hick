//! Stats counter integration test for `mdns-proto`.
//!
//! Exercises the `Endpoint::stats()` snapshot after a scripted exchange and
//! verifies that the atomic counters reflect the operations performed.

#![cfg(all(feature = "stats", feature = "std", feature = "slab"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{net::Ipv4Addr, time::Instant as StdInstant};

use mdns_proto::{
  CollectedAnswer, Name, Query,
  cache::CacheEntry,
  config::{EndpointConfig, QuerySpec, ServiceSpec},
  endpoint::{Endpoint, EndpointEventEntry, ServiceRoute},
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
  slab::Slab<ServiceRoute>,
  slab::Slab<TestQuery>,
  slab::Slab<EndpointEventEntry>,
  slab::Slab<CollectedAnswer>,
  slab::Slab<QueryUpdate>,
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
  let _ = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

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
  for ev in e.handle(now, src, local_ip, 0, &packet, false).unwrap() {
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

  for ev in e.handle(now, src, local_ip, 0, &packet, false).unwrap() {
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

  let _ = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // Feed an answer response.
  let _qh = e
    .try_start_query(QuerySpec::new(inst.clone(), ResourceType::Srv), now)
    .unwrap();
  let ans_pkt = build_srv_response(&inst);
  let src = "192.0.2.200:5353".parse().unwrap();
  let local_ip = "192.0.2.20".parse().unwrap();
  for ev in e.handle(now, src, local_ip, 0, &ans_pkt, false).unwrap() {
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

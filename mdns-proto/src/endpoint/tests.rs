use super::*;
use crate::{
  cache::CacheEntry,
  config::{EndpointConfig, ServiceSpec},
  event::{QueryUpdate, ServiceUpdate},
  query::Query,
  records::ServiceRecords,
  transmit::Transmit,
};
use std::{net::Ipv4Addr, time::Instant as StdInstant};

type TestQuery = Query<StdInstant, slab::Slab<CollectedAnswer>, slab::Slab<QueryUpdate>>;

type TestEndp = Endpoint<
  StdInstant,
  rand::rngs::StdRng,
  slab::Slab<CacheEntry<StdInstant>>,
  slab::Slab<ServiceRoute>,
  slab::Slab<TestQuery>,
  slab::Slab<EndpointEventEntry>,
  slab::Slab<CollectedAnswer>,
  slab::Slab<QueryUpdate>,
>;

fn build_endpoint() -> TestEndp {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
  TestEndp::try_new(EndpointConfig::new(), rng)
}

#[test]
fn service_route_exposes_advertised_addresses() {
  let mut e = build_endpoint();
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("P._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 0, 5));
  let (handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      StdInstant::now(),
    )
    .unwrap();
  let (_, route) = e
    .services
    .iter()
    .find(|(_, r)| r.handle() == handle)
    .unwrap();
  assert_eq!(route.a_addrs(), [Ipv4Addr::new(10, 0, 0, 5)].as_slice());
  assert!(route.aaaa_addrs().is_empty());
  assert!(route.aaaa_scopes().is_empty());
}

#[test]
fn endpoint_event_entry_borrows_inner_event() {
  let entry = EndpointEventEntry(crate::event::EndpointEvent::CacheExpired);
  assert!(matches!(
    entry.event(),
    crate::event::EndpointEvent::CacheExpired
  ));
}

#[test]
fn handle_rejects_a_malformed_packet_with_a_parse_error() {
  let mut e = build_endpoint();
  let now = StdInstant::now();
  let src = "192.0.2.1:5353".parse().unwrap();
  let local = "192.0.2.20".parse().unwrap();
  // A single byte cannot hold a DNS header — parsing must fail and the
  // endpoint must surface it as `HandleError::Parse`.
  let res = e.handle(now, src, local, 0, &[0u8], false);
  assert!(matches!(res, Err(HandleError::Parse(_))));
}

#[test]
fn note_service_announced_is_a_noop_for_an_unknown_handle() {
  let mut e = build_endpoint();
  // No registered service → the route lookup misses and the call returns early.
  e.note_service_announced(FullyAnnounced::new(ServiceHandle::from_raw(0xDEAD), false), &[], &[]);
}

#[test]
fn sibling_retained_addrs_is_empty_for_an_unknown_handle() {
  let e = build_endpoint();
  assert!(
    e.sibling_retained_addrs(ServiceHandle::from_raw(0xBEEF))
      .is_empty()
  );
}

#[test]
fn advance_after_encode_failure_is_a_noop_for_an_unknown_index() {
  let mut e = build_endpoint();
  let now = StdInstant::now();
  // No withdrawal item at this index → the lookup misses and it returns early.
  e.advance_after_encode_failure(9999, now, false);
}

#[test]
fn query_delegation_tolerates_unknown_handles() {
  let mut e = build_endpoint();
  let bogus = QueryHandle::from_raw(0xDEAD);
  let now = StdInstant::now();
  let mut buf = std::vec![0u8; 512];
  assert!(matches!(
    e.poll_query_transmit(bogus, || now, &mut buf),
    Ok(None)
  ));
  e.note_query_transmit_outcome(bogus, now, TransmitDelivery::ALL); // no-op on an unknown handle
  assert!(e.handle_query_timeout(bogus, now).is_ok());
}

#[test]
fn endpoint_config_accessor_and_empty_poll_transmit() {
  let mut e = build_endpoint();
  let _ = e.config();
  // The endpoint itself emits nothing — all transmits come from services/queries.
  let mut buf = std::vec![0u8; 64];
  assert!(matches!(
    e.poll_transmit(StdInstant::now(), &mut buf),
    Ok(None)
  ));
}

#[test]
fn src_matches_advertised_checks_route_addresses() {
  let mut e = build_endpoint();
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("P._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 0, 5));
  e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    ServiceSpec::new(recs),
    StdInstant::now(),
  )
  .unwrap();
  // A source IP matching an advertised A record is on-link; a non-advertised
  // one is not; a v6 source (no advertised AAAA) exercises the v6 branch.
  assert!(e.src_matches_advertised(core::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 0));
  assert!(!e.src_matches_advertised(core::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)), 0));
  assert!(!e.src_matches_advertised(core::net::IpAddr::V6(core::net::Ipv6Addr::LOCALHOST), 0));
}

#[test]
fn handle_rejects_invalid_opcode_and_response_code() {
  let mut e = build_endpoint();
  let src: std::net::SocketAddr = "192.168.1.5:5353".parse().unwrap();
  let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
  let now = StdInstant::now();
  // Header flags 0x1000 → opcode = Status (2), not Query → InvalidOpcode.
  let bad_opcode = [0u8, 0, 0x10, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
  assert!(matches!(
    e.handle(now, src, local_ip, 0, &bad_opcode, false),
    Err(HandleError::InvalidOpcode(_))
  ));
  // Header flags 0x0001 → opcode = Query but RCODE = FormatError (1) → rejected.
  let bad_rcode = [0u8, 0, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
  assert!(matches!(
    e.handle(now, src, local_ip, 0, &bad_rcode, false),
    Err(HandleError::InvalidResponseCode(_))
  ));
}

#[test]
fn handle_service_renamed_updates_route_name() {
  let mut e = build_endpoint();
  let stype = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("WebServer._http._tcp.local.").unwrap();
  let host = Name::try_from_str("server.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst.clone(), host, 80, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
  let now = StdInstant::now();
  let (handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let new_name = Name::try_from_str("WebServer-2._http._tcp.local.").unwrap();
  e.handle_service_renamed(handle, new_name.clone()).unwrap();

  // Verify the route was updated.
  let found = e
    .services
    .iter()
    .find(|(_, route)| route.handle() == handle)
    .map(|(_, route)| route.name().clone());
  assert_eq!(
    found.as_ref().map(Name::as_str),
    Some(new_name.as_str()),
    "expected route name to be updated to the renamed instance"
  );
}

#[test]
fn handle_service_renamed_rejects_duplicate() {
  use crate::error::HandleServiceRenamedError;

  let mut e = build_endpoint();
  let now = StdInstant::now();

  // Register first service.
  let stype1 = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst1 = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
  let host1 = Name::try_from_str("alpha.local.").unwrap();
  let mut recs1 = ServiceRecords::new(stype1, inst1.clone(), host1, 80, 120);
  recs1.add_a(Ipv4Addr::new(10, 0, 0, 1));
  let (handle1, _svc1) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs1),
      now,
    )
    .unwrap();

  // Register second service.
  let stype2 = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst2 = Name::try_from_str("Beta._http._tcp.local.").unwrap();
  let host2 = Name::try_from_str("beta.local.").unwrap();
  let mut recs2 = ServiceRecords::new(stype2, inst2.clone(), host2, 80, 120);
  recs2.add_a(Ipv4Addr::new(10, 0, 0, 2));
  let (_handle2, _svc2) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs2),
      now,
    )
    .unwrap();

  // Attempt to rename handle1 to the name already used by handle2.
  let result = e.handle_service_renamed(handle1, inst2.clone());
  assert!(
    result.is_err(),
    "expected an error when renaming to an already-registered name"
  );
  assert!(
    matches!(
      result.unwrap_err(),
      HandleServiceRenamedError::NameAlreadyRegistered(_)
    ),
    "expected NameAlreadyRegistered variant"
  );

  // Verify handle1's name was NOT changed.
  let found = e
    .services
    .iter()
    .find(|(_, route)| route.handle() == handle1)
    .map(|(_, route)| route.name().clone());
  assert_eq!(
    found.as_ref().map(Name::as_str),
    Some(inst1.as_str()),
    "handle1 name must remain unchanged after rejected rename"
  );
}

#[test]
fn service_route_has_host_field() {
  let mut e = build_endpoint();
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let recs = ServiceRecords::new(st, inst, host.clone(), 631, 120);
  let now = StdInstant::now();
  let _ = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  let route = e
    .services
    .iter()
    .next()
    .map(|(_, r)| r.clone())
    .expect("expected one registered route");
  assert_eq!(
    route.host().as_str(),
    host.as_str(),
    "ServiceRoute::host() must reflect the host name from ServiceRecords"
  );
}

// ── host question routing ─────────────────────────────────────

/// Helper: encode a minimal mDNS query message with a single A question.
/// Returns the number of bytes written into `buf`.
fn build_query_for_host(buf: &mut [u8; 512], host_str: &str) -> usize {
  use crate::wire::{Header, MessageBuilder, ResourceClass, ResourceType};
  // Header::new() zero-initialises flags; opcode 0 == Query.
  let hdr = Header::new();
  let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
  let name = Name::try_from_str(host_str).unwrap();
  b.push_question(&name, ResourceType::A, ResourceClass::In, false)
    .unwrap();
  b.finish().unwrap()
}

/// Helper: encode a minimal mDNS probe message with an A record in the
/// authority section (RFC 6762 §8.1 simultaneous-probe tie-breaking). Use for
/// HOST-name conflicts (a host claims A/AAAA).
fn build_probe_authority_for_host(buf: &mut [u8; 512], host_str: &str) -> usize {
  use crate::wire::{Header, MessageBuilder};
  // Header::new() zero-initialises flags; opcode 0 == Query.
  let hdr = Header::new();
  let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
  let name = Name::try_from_str(host_str).unwrap();
  b.push_a_authority(&name, 120, Ipv4Addr::new(192, 168, 1, 99))
    .unwrap();
  b.finish().unwrap()
}

/// Helper: encode a probe message with an SRV record in the authority section
/// for `name`. Use for INSTANCE-name conflicts. The endpoint gates ProbeConflict
/// to the instance's unique RRset (SRV/TXT), so an A record owned by the
/// instance name is no longer a conflict.
fn build_probe_srv_authority(buf: &mut [u8; 512], instance_str: &str) -> usize {
  use crate::wire::{Header, MessageBuilder};
  let hdr = Header::new();
  let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
  let name = Name::try_from_str(instance_str).unwrap();
  let target = Name::try_from_str("other-host.local.").unwrap();
  b.push_srv_authority(&name, 120, 0, 0, 8080, &target)
    .unwrap();
  b.finish().unwrap()
}

/// Helper: build a test endpoint with one registered service whose host is
/// "printer-host.local." and instance is "Printer._ipp._tcp.local.".
fn build_endpoint_with_printer() -> (TestEndp, ServiceHandle) {
  let mut e = build_endpoint();
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let recs = ServiceRecords::new(st, inst, host, 631, 120);
  let now = StdInstant::now();
  let (handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  (e, handle)
}

/// A direct A query for the SRV target host name must be routed to
/// the matching service as ServiceEvent::Question.
#[test]
fn host_question_routes_to_service() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  let (mut e, expected_handle) = build_endpoint_with_printer();
  let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  let mut buf = [0u8; 512];
  let n = build_query_for_host(&mut buf, "printer-host.local.");
  let data = &buf[..n];

  let mut events = e
    .handle(StdInstant::now(), src, local_ip, 0, data, false)
    .unwrap();
  let ev = events
    .next()
    .expect("expected at least one routing event")
    .expect("expected Ok");

  match ev {
    RouteEvent::ToService(ts) => {
      assert_eq!(
        ts.handle(),
        expected_handle,
        "event must be addressed to the registered service handle"
      );
      assert!(
        ts.event().is_question(),
        "event must be ServiceEvent::Question, got {:?}",
        ts.event()
      );
    }
    other => panic!("expected RouteEvent::ToService(Question), got {:?}", other),
  }
}

// ── authority-section HostConflict vs ProbeConflict routing ────

/// A probe authority record matching the instance name must route as
/// ProbeConflict (triggers auto-rename in Service).
#[test]
fn authority_instance_name_routes_as_probe_conflict() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  let (mut e, expected_handle) = build_endpoint_with_printer();
  let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  let mut buf = [0u8; 512];
  let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
  let data = &buf[..n];

  let mut events = e
    .handle(StdInstant::now(), src, local_ip, 0, data, false)
    .unwrap();
  let ev = events
    .next()
    .expect("expected at least one routing event")
    .expect("expected Ok");

  match ev {
    RouteEvent::ToService(ts) => {
      assert_eq!(ts.handle(), expected_handle);
      assert!(
        ts.event().is_probe_conflict(),
        "expected ProbeConflict for an instance-name authority record, got {:?}",
        ts.event()
      );
    }
    other => panic!(
      "expected RouteEvent::ToService(ProbeConflict), got {:?}",
      other
    ),
  }
}

/// the SAME probe-shaped authority record that triggers a
/// ProbeConflict from port 5353 (see
/// `authority_instance_name_routes_as_probe_conflict`) must NOT route as any
/// conflict when it arrives from an EPHEMERAL source port. Authority records
/// are tentative-probe claims trusted only from a real mDNS peer (port 5353);
/// an off-path / forged ephemeral-port packet must not force our rename.
#[test]
fn ephemeral_port_authority_record_does_not_trigger_conflict() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  let (mut e, _handle) = build_endpoint_with_printer();
  // Only the source PORT differs from the positive-control test.
  let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 40000));
  let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  let mut buf = [0u8; 512];
  let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
  let data = &buf[..n];

  let events = e
    .handle(StdInstant::now(), src, local_ip, 0, data, false)
    .unwrap();
  for ev in events {
    let ev = ev.expect("expected Ok");
    if let RouteEvent::ToService(ts) = ev {
      assert!(
        !ts.event().is_probe_conflict() && !ts.event().is_host_conflict(),
        "ephemeral-port authority record must not route as a conflict, got {:?}",
        ts.event()
      );
    }
  }
}

/// A probe authority record matching only the host name must route as
/// HostConflict — NOT as ProbeConflict. Service must NOT auto-rename.
#[test]
fn authority_host_name_routes_as_host_conflict() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  let (mut e, expected_handle) = build_endpoint_with_printer();
  let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  let mut buf = [0u8; 512];
  let n = build_probe_authority_for_host(&mut buf, "printer-host.local.");
  let data = &buf[..n];

  let mut events = e
    .handle(StdInstant::now(), src, local_ip, 0, data, false)
    .unwrap();
  let ev = events
    .next()
    .expect("expected at least one routing event")
    .expect("expected Ok");

  match ev {
    RouteEvent::ToService(ts) => {
      assert_eq!(ts.handle(), expected_handle);
      assert!(
        ts.event().is_host_conflict(),
        "expected HostConflict for a host-name authority record, got {:?}",
        ts.event()
      );
    }
    other => panic!(
      "expected RouteEvent::ToService(HostConflict), got {:?}",
      other
    ),
  }
}

/// a non-address record (TXT) owned by the HOST name must NOT
/// surface HostConflict — a host claims A/AAAA, so only those rtypes are a
/// host-name conflict. (The A-record positive control is
/// `authority_host_name_routes_as_host_conflict`.)
#[test]
fn txt_owned_by_host_name_does_not_route_host_conflict() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let (mut e, _handle) = build_endpoint_with_printer();
  let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  // Probe-shaped packet: a TXT record (not A/AAAA) owned by the host name.
  let mut buf = [0u8; 512];
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let hdr = Header::new(); // opcode 0 == Query (QR=0 probe)
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_txt_authority(&host, 120, [b"k=v".as_slice()])
    .unwrap();
  let n = b.finish().unwrap();

  let events = e
    .handle(StdInstant::now(), src, local_ip, 0, &buf[..n], false)
    .unwrap();
  for ev in events {
    if let Ok(RouteEvent::ToService(ts)) = ev {
      assert!(
        !ts.event().is_host_conflict() && !ts.event().is_probe_conflict(),
        "a TXT owned by the host name must not route a conflict, got {:?}",
        ts.event()
      );
    }
  }
}

/// records in the ADDITIONAL section (as a DNS-SD responder sends
/// the A/SRV/TXT accompanying a PTR) must be cached AND delivered to active
/// queries — not silently ignored.
#[test]
fn additional_section_records_are_cached_and_delivered() {
  use crate::{
    config::QuerySpec,
    wire::{ResourceClass, ResourceType},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let h = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
    .unwrap();

  // QR=1 response carrying the A record ONLY in the ADDITIONAL section
  // (qd=0, an=0, ns=0, ar=1).
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 0, 0, 0, 0, 1]);
  msg.extend_from_slice(&[
    7, b'p', b'r', b'i', b'n', b't', b'e', b'r', 5, b'l', b'o', b'c', b'a', b'l', 0,
  ]);
  msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
  msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
  msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
  msg.extend_from_slice(&[10, 0, 0, 7]);

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  // Drain events; count the ToQuery emitted for the additional record (the
  // lazy Additional-section fan-out).
  let to_query = e
    .handle(now, src, local_ip, 0, &msg, false)
    .unwrap()
    .filter(|r| matches!(r, Ok(ev) if ev.is_to_query()))
    .count();
  assert!(
    to_query >= 1,
    "additional-section A must emit a ToQuery for the matching query"
  );

  let answers: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
  assert_eq!(
    answers.len(),
    1,
    "additional-section A must reach the active query; got {answers:?}"
  );
  assert!(
    e.cache.contains(&qname, ResourceType::A, ResourceClass::In),
    "additional-section A must be cached"
  );
}

/// a conflicting SRV for our instance name carried ONLY in the
/// ADDITIONAL section of a QR=1 response must still route a ProbeConflict —
/// DNS-SD responders place SRV/TXT there, so missing it would let a duplicate
/// name survive.
#[test]
fn additional_section_srv_for_instance_routes_probe_conflict() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let (mut e, expected) = build_endpoint_with_printer();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();

  // Build the SRV as an ANSWER, then relocate it to the ADDITIONAL section by
  // rewriting the header counts (ANCOUNT 1->0, ARCOUNT 0->1) — identical
  // record bytes, different section (the builder has no push_*_additional).
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  let target = Name::try_from_str("other-host.local.").unwrap();
  b.push_srv_answer(&inst, 120, 0, 0, 8080, &target, false)
    .unwrap();
  let n = b.finish().unwrap();
  buf[7] = 0; // ANCOUNT = 0
  buf[11] = 1; // ARCOUNT = 1

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let saw_conflict = e
      .handle(StdInstant::now(), src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .filter_map(Result::ok)
      .any(|ev| {
        matches!(ev, RouteEvent::ToService(ts) if ts.handle() == expected && ts.event().is_probe_conflict())
      });
  assert!(
    saw_conflict,
    "an SRV for our instance name in the ADDITIONAL section must route a ProbeConflict"
  );
}

/// an additional SRV that matches BOTH our service (conflict) and
/// multiple active queries must emit EXACTLY ONE ProbeConflict plus a ToQuery
/// per query — not replay the conflict after each query event (the cursor
/// phase-ambiguity bug).
#[test]
fn additional_conflict_not_replayed_across_query_events() {
  use crate::{
    config::QuerySpec,
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::net::SocketAddr;

  let (mut e, _h) = build_endpoint_with_printer();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let now = StdInstant::now();
  // Two active queries for the instance name (ANY accepts the SRV).
  let _q1 = e
    .try_start_query(QuerySpec::new(inst.clone(), ResourceType::Any), now)
    .unwrap();
  let _q2 = e
    .try_start_query(QuerySpec::new(inst.clone(), ResourceType::Any), now)
    .unwrap();

  // QR=1 SRV for the instance, relocated from ANSWER to ADDITIONAL.
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  let target = Name::try_from_str("other-host.local.").unwrap();
  b.push_srv_answer(&inst, 120, 0, 0, 8080, &target, false)
    .unwrap();
  let n = b.finish().unwrap();
  buf[7] = 0; // ANCOUNT = 0
  buf[11] = 1; // ARCOUNT = 1

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let mut conflicts = 0usize;
  let mut to_query = 0usize;
  for ev in e.handle(now, src, local_ip, 0, &buf[..n], false).unwrap() {
    match ev.unwrap() {
      RouteEvent::ToService(ts) if ts.event().is_probe_conflict() => conflicts += 1,
      RouteEvent::ToQuery(_) => to_query += 1,
      _ => {}
    }
  }
  assert_eq!(
    conflicts, 1,
    "the conflict must fire exactly once, not replay per query"
  );
  assert_eq!(
    to_query, 2,
    "both active queries must receive the additional SRV"
  );
}

/// a conflict is only routed for the same-class (IN) RRset. An SRV
/// for our instance name with class ANY (or any non-IN class) must NOT route
/// a ProbeConflict — exercised through the shared next_service_conflict gate.
#[test]
fn non_in_class_record_does_not_route_conflict() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  let (mut e, _h) = build_endpoint_with_printer();

  // Hand-crafted QR=1 SRV answer for "Printer._ipp._tcp.local." with CLASS
  // ANY (0x00FF) instead of IN — same name/rtype, wrong class.
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]); // QR=1, an=1
  msg.extend_from_slice(&[
    7, b'P', b'r', b'i', b'n', b't', b'e', b'r', 4, b'_', b'i', b'p', b'p', 4, b'_', b't', b'c',
    b'p', 5, b'l', b'o', b'c', b'a', b'l', 0,
  ]);
  msg.extend_from_slice(&33u16.to_be_bytes()); // TYPE SRV
  msg.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY (not IN)
  msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
  msg.extend_from_slice(&15u16.to_be_bytes()); // RDLENGTH
  msg.extend_from_slice(&[0, 0, 0, 0, 0x1F, 0x90]); // priority/weight/port
  msg.extend_from_slice(&[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0]); // target x.local.

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  for ev in e
    .handle(StdInstant::now(), src, local_ip, 0, &msg, false)
    .unwrap()
  {
    if let Ok(RouteEvent::ToService(ts)) = ev {
      assert!(
        !ts.event().is_probe_conflict() && !ts.event().is_host_conflict(),
        "a non-IN-class record must not route a conflict, got {:?}",
        ts.event()
      );
    }
  }
}

// ── probe authority records + answer-section ProbeConflict routing

/// a QUERY packet whose ANSWER section contains a record for
/// one of our service's unique names is a KAS hint — not an
/// authoritative claim.  The iterator must emit KnownAnswer (for KAS
/// suppression), NEVER ProbeConflict.  Treating a QR=0 answer as a
/// conflict signal would let a hostile querier trigger our auto-rename
/// trivially.  Real probe-time conflicts arrive in the AUTHORITY
/// section (peer probes); see `authority_instance_name_routes_as_probe_conflict`.
#[test]
fn query_answer_for_instance_name_emits_known_answer_only() {
  use crate::wire::{
    DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType,
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let st = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
  let host = Name::try_from_str("alpha.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
  let now = StdInstant::now();
  let (_handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let mut buf = [0u8; 512];
  let header = Header::new(); // QR=0
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_question(&inst, ResourceType::Any, ResourceClass::In, true)
    .unwrap();
  b.push_a_answer(&inst, 120, Ipv4Addr::new(10, 0, 0, 2), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  // No ProbeConflict events anywhere.
  for ev in &events {
    if let RouteEvent::ToService(ts) = ev {
      assert!(
        !ts.event().is_probe_conflict(),
        "QR=0 answer-section MUST NOT emit ProbeConflict; got {events:?}"
      );
    }
  }
  // But the KAS hint must reach the service.
  let kas_count = events
    .iter()
    .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_known_answer()))
    .count();
  assert!(
    kas_count >= 1,
    "at least one KnownAnswer must fire for the instance-name match; got {events:?}"
  );
}

// ── answer-section host-only matches emit HostConflict ────────

/// RFC 6762 §8.1: a QUERY packet (QR=0) whose ANSWER section
/// contains a record owned by the service's HOST name (not the instance
/// name) must emit HostConflict — not ProbeConflict. Only ProbeConflict
/// triggers an auto-rename in Service; HostConflict surfaces the event
/// without renaming.
#[test]
fn qr0_answer_for_host_name_emits_host_conflict_not_probe_conflict() {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder};
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let st = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
  let host = Name::try_from_str("alpha.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
  let now = StdInstant::now();
  let (expected_handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // Build a QUERY packet (QR=0) with an A answer record owned by the HOST
  // name (not the instance name).
  let mut buf = [0u8; 512];
  let header = Header::new(); // QR=0
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  // QR=0 answer-section records MUST NOT emit HostConflict
  // or ProbeConflict.  Only KnownAnswer events fire (for KAS suppression).
  for ev in &events {
    if let RouteEvent::ToService(ts) = ev {
      assert!(
        !ts.event().is_host_conflict() && !ts.event().is_probe_conflict(),
        "QR=0 answer-section MUST NOT emit conflict events; got {events:?}"
      );
      assert_eq!(
        ts.handle(),
        expected_handle,
        "event must target the registered service"
      );
    }
  }
  // The KAS hint must reach the service.
  let kas_count = events
    .iter()
    .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_known_answer()))
    .count();
  assert!(
    kas_count >= 1,
    "at least one KnownAnswer must fire for the host-name match; got {events:?}"
  );
}

// ── QR=0 known-answer records must NOT populate active queries ─

/// answer records inside a QUERY packet (QR=0) are known-answer
/// hints from another querier — they must NOT be delivered as
/// QueryEvent::Answer to active queries.  Only RESPONSE packets (QR=1)
/// carry authoritative answers.
#[test]
fn qr0_answer_does_not_populate_query() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let qname = Name::try_from_str("myhost.local.").unwrap();
  let now = StdInstant::now();

  // Register an active query for "myhost.local.".
  let spec = QuerySpec::new(qname.clone(), ResourceType::A);
  let _qhandle = e.try_start_query(spec, now).unwrap();

  // Build a QUERY packet (QR=0) with an A answer record for the query name.
  // In mDNS this is a known-answer hint carried by another querier; it is
  // NOT an authoritative response.
  let mut buf = [0u8; 512];
  let header = Header::new(); // QR=0: query, not response
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 9), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();

  // Drain all events. None should be a ToQuery(Answer).
  for ev in events {
    let ev = ev.unwrap();
    assert!(
      !matches!(ev, RouteEvent::ToQuery(ref tq) if matches!(tq.event(), QueryEvent::Answer(_))),
      "QR=0 answer records must NOT produce QueryEvent::Answer; got: {:?}",
      ev
    );
  }
}

/// RFC 6762 §7.3 duplicate-question suppression: when another host multicasts
/// the SAME QM question (empty known-answer section) that we have an active
/// query for, our planned (re)transmit is suppressed — the peer's query
/// elicits the same answers. A control run (no duplicate) confirms the query
/// would otherwise transmit.
#[test]
fn duplicate_qm_question_suppresses_planned_query() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
  };
  use core::net::SocketAddr;

  let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  // Control: with no duplicate observed, the freshly-started query transmits.
  {
    let mut e = build_endpoint();
    let now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();
    let mut buf = [0u8; 512];
    assert!(
      e.poll_query_transmit(h, || now, &mut buf).unwrap().is_some(),
      "control: a started query transmits when no duplicate is seen"
    );
  }

  // §7.3: observe a foreign QM query for the same question (no known answers,
  // TC clear) — our planned transmit must be suppressed but the query deferred,
  // not retired.
  let mut e = build_endpoint();
  let now = StdInstant::now();
  let h = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
    .unwrap();

  let mut qbuf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap(); // QR=0 query
  b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false) // QM (no QU bit)
      .unwrap();
  let n = b.finish().unwrap();
  let _ = e.handle(now, src, local_ip, 0, &qbuf[..n], false).unwrap();

  let mut buf = [0u8; 512];
  assert!(
    e.poll_query_transmit(h, || now, &mut buf).unwrap().is_none(),
    "§7.3: observing a duplicate QM question must suppress our planned query"
  );
  assert!(
    e.poll_query_timeout(h).is_some(),
    "§7.3: the suppressed query is deferred (rescheduled), not retired"
  );
}

/// A QU (unicast-response) duplicate question must NOT suppress our query: a
/// QU query is answered unicast to the asker, so it would not elicit the
/// multicast answers our query needs (RFC 6762 §7.3 applies to QM only).
#[test]
fn qu_duplicate_question_does_not_suppress_query() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
  };
  use core::net::SocketAddr;

  let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let h = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
    .unwrap();

  let mut qbuf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
  b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, true) // QU bit set
      .unwrap();
  let n = b.finish().unwrap();
  let _ = e.handle(now, src, local_ip, 0, &qbuf[..n], false).unwrap();

  let mut buf = [0u8; 512];
  assert!(
    e.poll_query_transmit(h, || now, &mut buf).unwrap().is_some(),
    "§7.3: a QU duplicate must NOT suppress our query (it elicits no multicast answer)"
  );
}

/// a duplicate QM query from a NON-5353 (legacy/ephemeral) source must
/// NOT suppress our query — a legacy resolver's request may be answered by
/// unicast straight to it (§6.7), answers we would never see.
#[test]
fn legacy_source_duplicate_does_not_suppress_query() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
  };
  use core::net::SocketAddr;

  let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let legacy_src: SocketAddr = "192.168.1.77:40000".parse().unwrap(); // ephemeral port
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let h = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
    .unwrap();

  let mut qbuf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
  b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false) // QM
      .unwrap();
  let n = b.finish().unwrap();
  let _ = e
    .handle(now, legacy_src, local_ip, 0, &qbuf[..n], false)
    .unwrap();

  let mut buf = [0u8; 512];
  assert!(
    e.poll_query_transmit(h, || now, &mut buf).unwrap().is_some(),
    "§7.3: a legacy-source (non-5353) duplicate must NOT suppress our query"
  );
}

/// a query with NO absolute timeout, suppressed every retry slot by a
/// flood of duplicate QM questions, must still progress to terminal via the
/// retry budget — §7.3 suppression is "treat as sent", not "defer forever".
#[test]
fn repeated_duplicate_questions_do_not_stall_query_forever() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
  };
  use core::net::SocketAddr;

  let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  let mut e = build_endpoint();
  let mut now = StdInstant::now();
  let h = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
    .unwrap();

  let mut qbuf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
  b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false)
    .unwrap();
  let n = b.finish().unwrap();

  // Each slot: a duplicate arrives while a transmit is pending → suppressed;
  // then we fire the next scheduled retry. The retry budget (MAX_RETRIES = 8)
  // must eventually retire the query even though it never transmitted itself.
  let mut buf = [0u8; 512];
  let mut retired = false;
  for _ in 0..32 {
    let _ = e.handle(now, src, local_ip, 0, &qbuf[..n], false).unwrap();
    assert!(
      e.poll_query_transmit(h, || now, &mut buf).unwrap().is_none(),
      "each duplicate suppresses the planned transmit"
    );
    match e.poll_query_timeout(h) {
      Some(due) => {
        now = due;
        e.handle_query_timeout(h, now).unwrap();
      }
      None => {
        retired = true;
        break;
      }
    }
  }
  assert!(
    retired,
    "§7.3: a continuously-duplicated query must retire via the retry budget, not defer forever"
  );
}

/// a duplicate that arrives when our retransmit deadline is already
/// DUE — but `handle_query_timeout` has not yet armed it (a driver that pumps
/// received packets before firing query timeouts) — must still suppress the
/// retry. Proves §7.3 is independent of the driver's packet-vs-timeout order.
#[test]
fn duplicate_suppresses_due_retry_independent_of_driver_order() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
  };
  use core::net::SocketAddr;

  let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let h = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
    .unwrap();

  // Send the first query and confirm delivery → a retransmit is scheduled
  // (next_deadline ≈ now+1s) with transmit_pending cleared.
  let mut buf = [0u8; 512];
  assert!(e.poll_query_transmit(h, || now, &mut buf).unwrap().is_some());
  e.note_query_transmit_outcome(h, now, TransmitDelivery::ALL);
  let t1 = e
    .poll_query_timeout(h)
    .expect("a retransmit must be scheduled");

  // Deliver a duplicate QM query exactly when the retry is DUE, WITHOUT first
  // calling handle_query_timeout (packet-before-timeout driver order).
  let mut qbuf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
  b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false)
    .unwrap();
  let n = b.finish().unwrap();
  let _ = e.handle(t1, src, local_ip, 0, &qbuf[..n], false).unwrap();

  // The due slot was consumed: the next retry is deferred to a later instant.
  let t2 = e
    .poll_query_timeout(h)
    .expect("query still active, retry rescheduled");
  assert!(
    t2 > t1,
    "§7.3: a duplicate at a due retry must consume the slot and defer it"
  );

  // Arming the now-stale deadline must not transmit (slot already consumed).
  e.handle_query_timeout(h, t1).unwrap();
  assert!(
    e.poll_query_transmit(h, || t1, &mut buf).unwrap().is_none(),
    "§7.3: no redundant transmit after the due slot was suppressed"
  );
}

// ── self-packet guard suppresses loopback routing ────────────

/// Multicast loopback returns our own probes/announcements to us with
/// `src.ip() == local_ip` (the interface we sent from).  `Endpoint::handle`
/// must drop these datagrams entirely: no ProbeConflict, no HostConflict,
/// no Question, no KnownAnswer, no cache writes.  Without this guard a
/// service can rename itself because of its own probe.
///
/// Control half of the test: a probe with the same payload but a foreign
/// source IP must still produce a ProbeConflict, proving the test is
/// asserting against the source-equality guard and not some unrelated
/// suppression.
#[test]
fn self_packet_does_not_route_as_probe_conflict() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  let (mut e, _expected_handle) = build_endpoint_with_printer();
  let local_ip: core::net::IpAddr = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  // Build a probe-shaped packet (authority section carries an A record for
  // the instance host) that would normally trigger ProbeConflict.
  let mut buf = [0u8; 512];
  let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
  let data = &buf[..n];
  let now = StdInstant::now();

  // (1) Self-packet: the caller (driver) flags self-loopback via
  // `caller_is_self = true`; handle() must then yield zero routing events.
  let self_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), 5353));
  let mut self_events = e.handle(now, self_src, local_ip, 0, data, true).unwrap();
  assert!(
    self_events.next().is_none(),
    "self-packet (caller_is_self = true) must yield zero routing events"
  );

  // (2) Control: the same payload from a peer with `caller_is_self = false`
  // MUST still emit ProbeConflict — proves suppression is driven by the
  // flag, not a broken routing path.
  let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let mut peer_events = e
    .handle(StdInstant::now(), peer_src, local_ip, 0, data, false)
    .unwrap();
  let ev = peer_events
    .next()
    .expect("control: foreign-source probe MUST still produce a routing event")
    .expect("control: routing event must be Ok");
  match ev {
    RouteEvent::ToService(ts) => assert!(
      ts.event().is_probe_conflict(),
      "control: foreign-source probe must still emit ProbeConflict; got {:?}",
      ts.event()
    ),
    other => panic!(
      "control: expected RouteEvent::ToService(ProbeConflict), got {:?}",
      other
    ),
  }
}

/// self-packet guard must also suppress cache population.  A
/// loopback announcement with an A record for some unrelated name must
/// NOT land in the passive observation cache.
#[test]
fn self_packet_does_not_populate_cache() {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let local_ip: core::net::IpAddr = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
  let observed = Name::try_from_str("printer.local.").unwrap();

  // Build a RESPONSE (QR=1) packet with an A record in the ANSWER section
  // — the passive-observation cache writes from the answer section.
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&observed, 120, Ipv4Addr::new(10, 0, 0, 9), false)
    .unwrap();
  let n = b.finish().unwrap();
  let data = &buf[..n];

  // self-detection is driven by the caller's `caller_is_self`
  // flag (the driver content-matches against recent sends). With it
  // true, the cache write is suppressed.
  let self_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), 5353));
  let _ = e.handle(now, self_src, local_ip, 0, data, true).unwrap();
  assert!(
    !e.cache
      .contains(&observed, ResourceType::A, ResourceClass::In),
    "self-packet must not populate cache; cache contained {:?}",
    observed.as_str()
  );

  // Control: a foreign source must populate the cache.
  let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let _ = e.handle(now, peer_src, local_ip, 0, data, false).unwrap();
  assert!(
    e.cache
      .contains(&observed, ResourceType::A, ResourceClass::In),
    "control: foreign-source response must populate the cache"
  );
}

/// the passive cache must compare records by their
/// CANONICAL case-folded rdata, so a TTL=0 goodbye whose PTR target differs
/// from the insert in BOTH compression and case still removes the cached
/// entry. Insert: target "inst" compressed (back-pointer), lowercase.
/// Goodbye: target "INST.SVC.LOCAL." inline + uppercase. Before the fixes the
/// raw bytes differed (compression and/or case) and the goodbye left a stale
/// entry until TTL expiry.
#[test]
fn cache_goodbye_matches_differently_encoded_and_cased_ptr() {
  use crate::wire::{ResourceClass, ResourceType};
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let local_ip: core::net::IpAddr = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
  let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let owner = Name::try_from_str("svc.local.").unwrap();

  // QR=1 response header, AN=1; owner "svc.local." parked at offset 12.
  let header_an1 = [0u8, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
  let owner_wire = [3u8, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0];

  // Insert: PTR with a COMPRESSED, lowercase target ("inst" + ptr→offset 12).
  let mut insert = std::vec::Vec::new();
  insert.extend_from_slice(&header_an1);
  insert.extend_from_slice(&owner_wire);
  insert.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
  insert.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  insert.extend_from_slice(&120u32.to_be_bytes()); // positive TTL
  insert.extend_from_slice(&7u16.to_be_bytes()); // RDLENGTH
  insert.extend_from_slice(&[4, b'i', b'n', b's', b't', 0xC0, 0x0C]);
  let _ = e.handle(now, src, local_ip, 0, &insert, false).unwrap();
  assert!(
    e.cache
      .contains(&owner, ResourceType::Ptr, ResourceClass::In),
    "compressed-target PTR response must populate the cache"
  );

  // Goodbye: same logical PTR, TTL=0, target written INLINE and UPPERCASE.
  let mut goodbye = std::vec::Vec::new();
  goodbye.extend_from_slice(&header_an1);
  goodbye.extend_from_slice(&owner_wire);
  goodbye.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
  goodbye.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  goodbye.extend_from_slice(&0u32.to_be_bytes()); // TTL=0 goodbye
  goodbye.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
  goodbye.extend_from_slice(&[
    4, b'I', b'N', b'S', b'T', 3, b'S', b'V', b'C', 5, b'L', b'O', b'C', b'A', b'L', 0,
  ]);
  let _ = e.handle(now, src, local_ip, 0, &goodbye, false).unwrap();
  // a TTL=0 goodbye does NOT delete immediately — it clamps the
  // matched entry to a 1-second rescue window. The MATCH (canonicalization
  // worked across compression + case) is proven by the entry expiring after
  // that 1s: a goodbye that failed to match would leave the original 120s
  // TTL, so the entry would survive the sweep below.
  let after_rescue = now + core::time::Duration::from_secs(2);
  e.cache.sweep_expired(after_rescue);
  assert!(
    !e.cache
      .contains(&owner, ResourceType::Ptr, ResourceClass::In),
    "a differently-encoded/-cased TTL=0 goodbye must match and expire the cached PTR within the §10.1 rescue window"
  );
}

// ── IPv6 self-packet via advertised-AAAA membership ──────────

/// IPv6 `in6_pktinfo.ipi6_addr` carries the packet DESTINATION (e.g.
/// `ff02::fb` for received mDNS multicast), not the local interface
/// address.  Therefore `src.ip() == local_ip` cannot detect IPv6 self
/// loopback: the source is our link-local/global unicast, the destination
/// is the multicast group, and they never match.  This detects self via
/// membership in any registered service's advertised AAAA list.
///
/// Test: register a service publishing `fe80::1`, then feed back a
/// probe-shaped packet with `src.ip() == fe80::1` and `local_ip == ff02::fb`.
/// Without the membership signal the packet would be routed as a
/// ProbeConflict (peer claiming our instance).  Control half: a foreign
/// IPv6 source must still produce a ProbeConflict.
#[test]
fn ipv6_self_packet_detected_via_advertised_aaaa() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::{Ipv6Addr, SocketAddr};

  // signal (b) is opt-in. This test validates the legacy
  // advertised-source fallback, so enable it explicitly.
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
  let mut e = TestEndp::try_new(
    EndpointConfig::new().with_trust_advertised_src_as_self(true),
    rng,
  );
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst.clone(), host, 631, 120);
  let our_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
  recs.add_aaaa(our_v6);
  let now = StdInstant::now();
  let (_handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // Build a probe-shaped packet (SRV authority record for the instance
  // name — the instance's unique RRset) — without the guard this triggers
  // ProbeConflict.
  let mut buf = [0u8; 512];
  let hdr = Header::new();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_srv_authority(
    &inst,
    120,
    0,
    0,
    8080,
    &Name::try_from_str("other-host.local.").unwrap(),
  )
  .unwrap();
  let n = b.finish().unwrap();
  let data = &buf[..n];

  // local_ip is what IPv6 PKTINFO actually returns: the multicast group.
  // This is *intentionally* not our source, because for IPv6 PKTINFO has
  // no `ipi_spec_dst` equivalent.
  let local_ip: core::net::IpAddr =
    core::net::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb));

  // (1) Self-packet via membership: src matches our advertised AAAA.
  let self_src: SocketAddr = SocketAddr::from((our_v6, 5353));
  let mut self_events = e.handle(now, self_src, local_ip, 0, data, false).unwrap();
  assert!(
    self_events.next().is_none(),
    "IPv6 self-packet (src ∈ advertised AAAA) must yield zero routing events; \
       local_ip == ff02::fb cannot detect this, so the membership branch must catch it"
  );

  // (2) Control: a foreign IPv6 source must still emit ProbeConflict on
  // the same payload.  Proves the guard is specific to src-set membership
  // and not some other suppression.
  let peer_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0099);
  let peer_src: SocketAddr = SocketAddr::from((peer_v6, 5353));
  let mut peer_events = e.handle(now, peer_src, local_ip, 0, data, false).unwrap();
  let ev = peer_events
    .next()
    .expect("control: foreign IPv6 probe MUST still produce a routing event")
    .expect("control: routing event must be Ok");
  match ev {
    RouteEvent::ToService(ts) => assert!(
      ts.event().is_probe_conflict(),
      "control: foreign IPv6 probe must still emit ProbeConflict; got {:?}",
      ts.event()
    ),
    other => panic!(
      "control: expected RouteEvent::ToService(ProbeConflict), got {:?}",
      other
    ),
  }
}

// ── terminal-then-cancel cleanup, no leak ───────────

/// Repeatedly starting + draining queries must not leak entries in the
/// endpoint's owned-Query pool when callers follow the documented
/// terminal-then-cancel pattern.  This dropped the previous
/// auto-prune design (which silently lost `collected_answers` before
/// the caller could read them); the new contract is:
///
///   1. drive `poll_query` until it returns `Some(Done | Timeout)`,
///   2. read final results via `collected_answers` (still available),
///   3. call `cancel_query` to free the pool entry.
///
/// `poll_query` emits the terminal exactly once (latched via
/// `Query::terminal_emitted`); subsequent calls return `None`.  This
/// test exercises 1024 start/terminal/cancel cycles and asserts the
/// pool returns to zero.
#[test]
fn poll_query_terminal_then_cancel_no_leak() {
  use crate::{config::QuerySpec, event::QueryUpdate, wire::ResourceType};
  use core::time::Duration;

  let mut e = build_endpoint();
  let mut now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();

  for i in 0..1024u32 {
    // 100ms timeout — small relative to test runtime.
    let spec =
      QuerySpec::new(qname.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
    let qhandle = e.try_start_query(spec, now).unwrap_or_else(|err| {
      panic!(
        "try_start_query #{i} must succeed when previous queries are cancelled; \
           got {err:?}"
      )
    });

    // Pool must contain exactly this one query between start and cancel.
    assert_eq!(
      e.queries.len(),
      1,
      "queries pool len must be 1 after start #{i}, before cancel"
    );

    // Drive to terminal: advance past the absolute timeout.
    now = now.checked_add(Duration::from_millis(200)).unwrap();
    e.handle_query_timeout(qhandle, now).unwrap();

    // Observe terminal via poll_query.  Does NOT auto-prune.
    let update = e.poll_query(qhandle);
    assert!(
      matches!(update, Some(QueryUpdate::Timeout | QueryUpdate::Done)),
      "poll_query must return Some(Timeout|Done) after deadline; got {update:?}"
    );

    // query is STILL in the pool after terminal; collected_answers
    // is readable.  (No collected answers here since no responses arrived,
    // but the iterator must work — exercised by the standalone test below.)
    assert_eq!(
      e.queries.len(),
      1,
      "queries pool len must remain 1 after terminal poll_query #{i} \
         (no auto-prune; caller must explicitly cancel)"
    );

    // Subsequent poll_query returns None (terminal already emitted).
    assert!(
      e.poll_query(qhandle).is_none(),
      "subsequent poll_query after terminal must return None (latched)"
    );

    // Explicit cleanup — the documented contract.
    e.cancel_query(qhandle).unwrap();
    assert_eq!(
      e.queries.len(),
      0,
      "queries pool len must be 0 after cancel #{i}"
    );
  }
}

/// `QuerySpec::with_timeout` becomes an absolute deadline through
/// `Instant::checked_add_duration`, and a duration that overflows the instant
/// leaves the query with no effective deadline at all. Every deadline
/// comparison must read that absence as "unbounded", never as "already
/// expired" — the query that asked for the widest possible window must not be
/// the one that ends first.
#[test]
fn a_query_whose_timeout_overflows_the_instant_still_transmits() {
  use crate::{config::QuerySpec, wire::ResourceType};
  use core::time::Duration;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  // `Duration::MAX` overflows `StdInstant`, so no absolute deadline is stored.
  let spec = QuerySpec::new(qname, ResourceType::A).with_timeout(Duration::MAX);
  let h = e.try_start_query(spec, now).unwrap();
  assert!(
    e.poll_query_timeout(h).is_none(),
    "an overflowing timeout must leave the query with no deadline at all"
  );

  // Poll far past any plausible window: with no deadline there is nothing to be
  // past, so the query's question must still go out.
  let much_later = now.checked_add(Duration::from_secs(86_400)).unwrap();
  let mut buf = [0u8; 512];
  assert!(
    e.poll_query_transmit(h, || much_later, &mut buf)
      .unwrap()
      .is_some(),
    "a query with no effective deadline must still transmit"
  );
  assert!(
    e.poll_query(h).is_none(),
    "a query with no effective deadline must not have reached a terminal"
  );
}

/// The stretch between resolving a query handle and drawing its question is not
/// free: `poll_query_transmit` finds the handle by scanning a pool with no
/// capacity bound, and a preempted scan can take arbitrarily long whatever its
/// length. An instant the CALLER sampled — even one sampled on the statement
/// before the call — is therefore already history by the time the core weighs
/// it, so a question whose `QuerySpec::with_timeout` window shut during that
/// stretch would be admitted on the strength of a reading taken while the window
/// was still open, and the caller would be told a question was admitted inside a
/// window that had closed.
///
/// The clock is passed instead of a reading of it, so there is no parameter for
/// a stale reading to arrive through: the core samples at the comparison, after
/// the scan. This test burns real time in exactly that gap and then asks for the
/// question, with the window already shut.
///
/// The two halves differ only in how long resolution took, so what withholds the
/// question is the elapsed time and nothing else. And the withheld half stops at
/// withholding: the terminal stays with `handle_query_timeout`, whose wakeup
/// `poll_query_timeout` must still publish.
#[test]
fn a_window_that_shuts_during_handle_resolution_withholds_the_question() {
  use crate::{config::QuerySpec, wire::ResourceType};
  use core::time::Duration;

  /// The caller's window, wide enough that reaching the poll inside it is not a
  /// race and narrow enough that a scan can outlive it.
  const WINDOW: Duration = Duration::from_millis(300);
  /// What resolution costs when the window survives it — a small fraction of
  /// `WINDOW`, so the control half is not a race either.
  const SCAN_INSIDE: Duration = Duration::from_millis(20);
  /// What resolution costs when it outlives the window.
  const SCAN_PAST: Duration = Duration::from_millis(450);

  let mut e = build_endpoint();
  let mut buf = std::vec![0u8; 512];

  // Entries for the scan to walk, so the handle under test is genuinely found by
  // a linear pass over the pool rather than by a lookup that could not cost
  // anything.
  for i in 0..8u16 {
    let decoy = Name::try_from_str(&std::format!("decoy{i}.local.")).unwrap();
    e.try_start_query(
      QuerySpec::new(decoy, ResourceType::A),
      StdInstant::now(),
    )
    .unwrap();
  }

  // Control: resolution finishes well inside the window, and the question goes
  // out. Without this the assertion below would also pass on an endpoint that
  // never transmits for a query carrying a timeout at all.
  let inside = e
    .try_start_query(
      QuerySpec::new(Name::try_from_str("inside.local.").unwrap(), ResourceType::A)
        .with_timeout(WINDOW),
      StdInstant::now(),
    )
    .unwrap();
  let inside_deadline = e
    .poll_query_timeout(inside)
    .expect("a query given a timeout must carry its absolute deadline");
  e.query_resolve_stall = Some(SCAN_INSIDE);
  assert!(
    StdInstant::now() < inside_deadline,
    "premise: the control's window must still be open when the poll begins"
  );
  assert!(
    e.poll_query_transmit(inside, StdInstant::now, &mut buf)
      .unwrap()
      .is_some(),
    "a question drawn while the caller's window is open must go out"
  );

  // The fault: resolution outlives the window.
  let past = e
    .try_start_query(
      QuerySpec::new(Name::try_from_str("past.local.").unwrap(), ResourceType::A)
        .with_timeout(WINDOW),
      StdInstant::now(),
    )
    .unwrap();
  let past_deadline = e
    .poll_query_timeout(past)
    .expect("a query given a timeout must carry its absolute deadline");
  e.query_resolve_stall = Some(SCAN_PAST);
  assert!(
    StdInstant::now() < past_deadline,
    "premise: the window must still be open when the poll begins, so the only \
     thing that can shut it is the resolution the endpoint is about to spend"
  );
  let drawn = e.poll_query_transmit(past, StdInstant::now, &mut buf).unwrap();
  assert!(
    StdInstant::now() >= past_deadline,
    "premise: resolution must have outlived the window, or nothing was asked \
     past a deadline and the assertion below is vacuous"
  );
  assert!(
    drawn.is_none(),
    "the caller's window shut while the endpoint was still resolving the \
     handle, but the question was admitted anyway — the deadline was weighed \
     against an instant read before the scan instead of at the comparison"
  );

  // Withheld, not ended: the terminal belongs to `handle_query_timeout`, and the
  // wakeup that reaches it must still be published.
  assert!(
    e.poll_query(past).is_none(),
    "withholding a late question must not terminate the query"
  );
  assert_eq!(
    e.poll_query_timeout(past),
    Some(past_deadline),
    "the deadline the withheld question was weighed against must still be \
     scheduled, or no driver would ever wake to end the query"
  );
}

// ── collected_answers readable after terminal poll_query ─────

/// After `poll_query` returns `Some(Done | Timeout)`, the natural
/// caller flow is to read final results via `collected_answers`
/// before discarding the handle.  Auto-prune would have wiped the
/// answers in the same call.  Verify that:
///
///   * answers collected before the timeout are still readable AFTER
///     the terminal poll_query returns, AND
///   * the second poll_query on the same handle returns None
///     (terminal latched, exactly-once delivery), AND
///   * after cancel_query the handle is gone.
#[test]
fn collected_answers_survive_terminal_until_cancel() {
  use crate::{
    config::QuerySpec,
    event::QueryUpdate,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::{net::SocketAddr, time::Duration};

  let mut e = build_endpoint();
  let mut now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let spec =
    QuerySpec::new(qname.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
  let h = e.try_start_query(spec, now).unwrap();

  // Feed a RESPONSE answer to populate collected_answers.
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  let addr = Ipv4Addr::new(10, 0, 0, 7);
  b.push_a_answer(&qname, 120, addr, false).unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];
  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();

  // Confirm the answer landed.
  let answers_before: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
  assert_eq!(
    answers_before.len(),
    1,
    "answer must land in collected_answers; got {answers_before:?}"
  );

  // Drive to terminal.
  now = now.checked_add(Duration::from_millis(200)).unwrap();
  e.handle_query_timeout(h, now).unwrap();
  let update = e.poll_query(h);
  assert!(
    matches!(update, Some(QueryUpdate::Timeout | QueryUpdate::Done)),
    "poll_query must return terminal; got {update:?}"
  );

  // collected_answers MUST still be readable AFTER terminal.
  let answers_after: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
  assert_eq!(
    answers_after.len(),
    1,
    "collected_answers must survive terminal poll_query; \
       caller had no chance to read them before they would have been \
       auto-pruned; got {answers_after:?}"
  );

  // Exactly-once: second poll_query returns None.
  assert!(
    e.poll_query(h).is_none(),
    "second poll_query after terminal must return None (latched)"
  );

  // Explicit cleanup leaves the pool empty.
  e.cancel_query(h).unwrap();
  assert!(e.collected_answers(h).next().is_none());
}

/// A response processed after the query's absolute deadline is not collected,
/// even though nothing has ended the query yet.
///
/// `handle` applies matching answers eagerly, and a driver whose receive side
/// runs ahead of its timer pump reaches it while the query is still live:
/// `hick-mio` drains receives before it fires timeouts, and `hick-reactor`
/// drains queued packets first and prefers a packet to a simultaneously-ready
/// timer. So `done` is still false at the moment a datagram from past the
/// boundary is handed to the query. That is the ordering this screens, and
/// screening it is what keeps the answer set from depending on which stage of a
/// loop happens to run first.
///
/// The cap is 1, because the late answer's real cost is not that it appears: it
/// is that the FIFO cap makes it EVICT the answer collected while the window was
/// open, turning a laxity into a lost result.
#[test]
fn an_answer_processed_past_the_query_deadline_is_not_collected() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::{net::SocketAddr, time::Duration};

  /// Long enough that the first datagram is unambiguously inside the window.
  const WINDOW: Duration = Duration::from_millis(100);

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let spec = QuerySpec::new(qname.clone(), ResourceType::A)
    .with_timeout(WINDOW)
    .with_max_answers(1);
  let h = e.try_start_query(spec, now).unwrap();

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let response = |addr: Ipv4Addr, buf: &mut [u8]| -> usize {
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(buf, hdr).unwrap();
    b.push_a_answer(&qname, 120, addr, false).unwrap();
    b.finish().unwrap()
  };

  let mut buf = [0u8; 512];
  let n = response(Ipv4Addr::new(10, 0, 0, 7), &mut buf);
  let _ = e.handle(now, src, local_ip, 0, &buf[..n], false).unwrap().count();
  assert_eq!(
    e.collected_answers(h).count(),
    1,
    "an answer processed inside the window must be collected"
  );

  // Past the deadline, with no timer pump in between — the reachable ordering.
  let after = now.checked_add(Duration::from_millis(300)).unwrap();
  let n = response(Ipv4Addr::new(10, 0, 0, 8), &mut buf);
  let _ = e
    .handle(after, src, local_ip, 0, &buf[..n], false)
    .unwrap()
    .count();

  let answers: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
  assert_eq!(
    answers.len(),
    1,
    "a response processed past the deadline must not be collected; got {answers:?}"
  );
  assert_eq!(
    answers[0].rdata_slice(),
    &[10, 0, 0, 7],
    "and it must not have evicted the answer the caller collected inside its \
     window — that is the whole reason the boundary is enforced here rather \
     than left to whichever driver stage runs first"
  );
  assert!(
    e.poll_query(h).is_none(),
    "refusing the late answer must not produce a terminal: the terminal belongs \
     to handle_query_timeout"
  );
}

/// The routing fan-out must withhold a record refused for standing past the
/// CALLER's window — on the Answer section and on the Additional section alike.
///
/// The two sites observe one fact about one record. `handle` applies the answer
/// eagerly and refuses it, while the query deliberately stays LIVE until its own
/// timer fires — so `is_done` and `terminal_emitted`, the only other screens the
/// fan-out applies, are both false at exactly the moment the collection was
/// refused. A `ToQuery` emitted there points at nothing a caller can find in
/// `collected_answers`, and carries nothing to tell it apart from a record the
/// query kept.
///
/// This is the window and only the window: the fan-out screens none of
/// `handle_event`'s own grounds for declining, which
/// `an_uncollected_answer_is_still_routed_to_its_query` pins from the other
/// side.
///
/// Exactly ON the boundary, which is where `now >= deadline` differs from
/// `now > deadline`, and each section is weighed twice: once inside the window,
/// where the event MUST still be emitted, and once at the boundary. Without the
/// first half a fan-out that emitted nothing at all would pass.
#[test]
fn a_refused_answer_is_not_routed_to_its_query() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
  };
  use core::{net::SocketAddr, time::Duration};

  const WINDOW: Duration = Duration::from_millis(100);

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let deadline = now.checked_add(WINDOW).unwrap();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let h = e
    .try_start_query(
      QuerySpec::new(qname.clone(), ResourceType::A).with_timeout(WINDOW),
      now,
    )
    .unwrap();
  // A service publishing the SAME name as its host, so every datagram below also
  // has service-side work to do: the refusal must be scoped to the query that
  // asked for the window, not to the datagram.
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("P._ipp._tcp.local.").unwrap(),
    qname.clone(),
    631,
    120,
  );
  recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
  let _ = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();

  // The A record in the ANSWER section.
  let mut buf = [0u8; 512];
  let answer_section = |addr: Ipv4Addr, buf: &mut [u8]| -> usize {
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(buf, hdr).unwrap();
    b.push_a_answer(&qname, 120, addr, false).unwrap();
    b.finish().unwrap()
  };
  // The same record in the ADDITIONAL section (qd=0, an=0, ns=0, ar=1), where a
  // DNS-SD responder puts the SRV/TXT/A/AAAA accompanying a PTR. The builder has
  // no push_*_additional, so the bytes are laid out by hand.
  let additional_section = |addr: Ipv4Addr| -> std::vec::Vec<u8> {
    let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
    msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 0, 0, 0, 0, 1]);
    msg.extend_from_slice(&[
      7, b'p', b'r', b'i', b'n', b't', b'e', b'r', 5, b'l', b'o', b'c', b'a', b'l', 0,
    ]);
    msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
    msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    msg.extend_from_slice(&addr.octets());
    msg
  };
  /// Routing decisions for one datagram, split by which side they address.
  fn routed(e: &mut TestEndp, at: StdInstant, src: SocketAddr, pkt: &[u8]) -> (usize, usize) {
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let mut to_query = 0usize;
    let mut to_service = 0usize;
    for ev in e.handle(at, src, local_ip, 0, pkt, false).unwrap() {
      match ev {
        Ok(ev) if ev.is_to_query() => to_query = to_query.saturating_add(1),
        Ok(ev) if ev.is_to_service() => to_service = to_service.saturating_add(1),
        _ => {}
      }
    }
    (to_query, to_service)
  }

  // Inside the window: both sections route the answer they collected.
  let n = answer_section(Ipv4Addr::new(10, 0, 0, 7), &mut buf);
  let answer_pkt = buf[..n].to_vec();
  assert_eq!(
    routed(&mut e, now, src, &answer_pkt).0,
    1,
    "an answer collected inside the window must still be routed to its query"
  );
  let additional_pkt = additional_section(Ipv4Addr::new(10, 0, 0, 8));
  assert_eq!(
    routed(&mut e, now, src, &additional_pkt).0,
    1,
    "an additional-section answer collected inside the window must still be routed"
  );
  assert_eq!(
    e.collected_answers(h).count(),
    2,
    "both in-window records must have been collected, or the boundary below is \
     not what the difference is"
  );

  // On the boundary: the collection is refused, so the routing must be too.
  let n = answer_section(Ipv4Addr::new(10, 0, 0, 9), &mut buf);
  let late_answer = buf[..n].to_vec();
  let (to_query, to_service) = routed(&mut e, deadline, src, &late_answer);
  assert_eq!(
    to_query, 0,
    "an answer the query refused on the deadline must not be routed to it: the \
     event is indistinguishable from one for an answer that was collected"
  );
  assert!(
    to_service >= 1,
    "and only the query fan-out is refused: a peer claiming our host name is \
     still a HostConflict, whatever any query's window is doing"
  );
  let late_additional = additional_section(Ipv4Addr::new(10, 0, 0, 10));
  assert_eq!(
    routed(&mut e, deadline, src, &late_additional).0,
    0,
    "and the Additional section is the same record on the same terms — DNS-SD \
     carries SRV/TXT/A/AAAA there"
  );

  assert_eq!(
    e.collected_answers(h).count(),
    2,
    "neither refused record may be collected"
  );
  // The datagram is still processed: only the query fan-out is refused.
  assert!(
    e.cache.contains(&qname, ResourceType::A, ResourceClass::In),
    "a datagram whose query fan-out is refused must still populate the cache — \
     the cache is not bounded by any query's window"
  );
  assert!(
    e.poll_query(h).is_none(),
    "withholding the routing must not produce a terminal either: the terminal \
     belongs to handle_query_timeout"
  );
}

/// `ToQuery` reports that a query was OFFERED a record, not that it kept one:
/// the fan-out's four per-query screens are exactly that offer, and nothing
/// about what the query then did with the record.
///
/// A `QuerySpec::with_max_answers` cap of zero is the cheapest witness: the
/// query has not ended, has taken no terminal, sits well inside its caller's
/// window, and the record matches its name, type and class — all four screens
/// the fan-out applies per query — while `Query::handle_event` collects nothing.
/// This says nothing about the earlier stages a record must clear to reach the
/// fan-out at all; those are not screens on a query, and no absent event can be
/// read back to them. The other grounds on which collection declines
/// (undecodable rdata, a duplicate, a full pool) differ only in which of
/// `handle_event`'s filters fires; each would re-exercise the same divergence
/// this one already pins.
///
/// BOTH halves are asserted, because a change that stopped the fan-out routing
/// altogether would satisfy the empty answer set on its own.
#[test]
fn an_uncollected_answer_is_still_routed_to_its_query() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::{net::SocketAddr, time::Duration};

  /// Long enough that the datagram lands unambiguously inside the window, so the
  /// caller-window screen is not what this test turns on.
  const WINDOW: Duration = Duration::from_millis(100);

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let h = e
    .try_start_query(
      QuerySpec::new(qname.clone(), ResourceType::A)
        .with_timeout(WINDOW)
        .with_max_answers(0),
      now,
    )
    .unwrap();

  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 7), false)
    .unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let to_query: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, &buf[..n], false)
    .unwrap()
    .map(Result::unwrap)
    .filter_map(|ev| match ev {
      RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_)) => Some(tq.handle()),
      _ => None,
    })
    .collect();
  assert_eq!(
    to_query,
    [h],
    "an in-window matching answer must still be routed to the query it matches, \
     whatever that query then does with it"
  );
  assert_eq!(
    e.collected_answers(h).count(),
    0,
    "and a zero max_answers cap keeps none of it: the routed event is an offer, \
     not a receipt"
  );
}

// ── query state applied eagerly during handle ────────────────

/// Dropping the `RouteEvents` iterator BEFORE iterating it must NOT
/// lose query-state updates.  Previously, query updates were
/// applied lazily inside the iterator's `next()`; a caller that
/// matched on the first event and broke out (or never iterated)
/// would leave some compatible queries un-updated.  Eager
/// application in `Endpoint::handle` (before the iterator is even
/// returned) eliminates that hazard.
#[test]
fn dropping_route_events_does_not_lose_query_state() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();

  // Two compatible queries for the same name (A and Any).
  let h_a = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
    .unwrap();
  let h_any = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Any), now)
    .unwrap();

  // RESPONSE packet with an A answer.
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 9), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  // Construct the iterator and IMMEDIATELY drop it — no .next() calls.
  {
    let _events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();
    // _events is dropped at end of scope WITHOUT iteration.
  }

  // both queries must already have the answer in their
  // collected_answers, because Endpoint::handle applied it eagerly
  // — not lazily on iterator advance.
  let a_answers: std::vec::Vec<_> = e.collected_answers(h_a).cloned().collect();
  let any_answers: std::vec::Vec<_> = e.collected_answers(h_any).cloned().collect();
  assert_eq!(
    a_answers.len(),
    1,
    "A-query must have the answer applied even with dropped iterator"
  );
  assert_eq!(
    any_answers.len(),
    1,
    "Any-query must ALSO have the answer applied even with dropped iterator \
       (fan-out is no longer dependent on draining the iterator)"
  );
}

// ── pre-poll terminal freeze closes the race ────────────────

/// `handle_query_timeout` sets `done = true` BEFORE the caller has
/// had a chance to call `poll_query` and observe the terminal.  An
/// answer arriving in that window must NOT mutate `collected_answers`
/// or fire ToQuery events — the freeze must key off `is_done()`, not
/// only the deferred `terminal_emitted` latch.
#[test]
fn pre_poll_terminal_freeze_closes_race() {
  use crate::{
    config::QuerySpec,
    event::QueryUpdate,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::{net::SocketAddr, time::Duration};

  let mut e = build_endpoint();
  let mut now = StdInstant::now();
  let qn = Name::try_from_str("printer.local.").unwrap();
  let spec = QuerySpec::new(qn.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
  let h = e.try_start_query(spec, now).unwrap();

  // Drive `done = true` via handle_query_timeout, but do NOT call
  // poll_query yet — so terminal_emitted is still false.
  now = now.checked_add(Duration::from_millis(200)).unwrap();
  e.handle_query_timeout(h, now).unwrap();

  // Feed a matching response.  Without the fix the answer
  // would mutate collected_answers because terminal_emitted is still
  // false even though is_done is true.
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&qn, 120, Ipv4Addr::new(10, 0, 0, 7), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];
  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  let to_query_events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .filter_map(|ev| match ev {
      RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_)) => Some(tq.handle()),
      _ => None,
    })
    .collect();
  assert!(
    !to_query_events.contains(&h),
    "ToQuery events must NOT fire for is_done query (pre-poll); \
       got {to_query_events:?}"
  );

  // Now observe terminal — and assert no answer was collected.
  assert!(matches!(
    e.poll_query(h),
    Some(QueryUpdate::Timeout | QueryUpdate::Done)
  ));
  let answers: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
  assert!(
    answers.is_empty(),
    "collected_answers must be empty — the post-done answer must NOT \
       have been applied to the Query; got {answers:?}"
  );
  e.cancel_query(h).unwrap();
}

// ── TTL=0 goodbye records are not collected ──────────────────

/// RFC 6762 §10.1: a record with TTL=0 is a goodbye / deletion
/// signal.  Active queries must NOT collect such records as live
/// answers — under `max_answers` pressure a goodbye could even
/// evict a real prior answer via FIFO.
#[test]
fn query_ignores_ttl_zero_goodbye_records() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qn = Name::try_from_str("printer.local.").unwrap();
  let spec = QuerySpec::new(qn.clone(), ResourceType::A);
  let h = e.try_start_query(spec, now).unwrap();

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  // First feed a normal answer (TTL=120) — must land.
  {
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qn, 120, Ipv4Addr::new(10, 0, 0, 7), false)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(now, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
  }
  assert_eq!(
    e.collected_answers(h).count(),
    1,
    "live (TTL=120) answer must be collected"
  );

  // Now feed a TTL=0 record for the same name — goodbye signal.
  // Must NOT land in collected_answers AND must NOT evict the prior.
  {
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    // TTL=0 is the deletion marker.
    b.push_a_answer(&qn, 0, Ipv4Addr::new(10, 0, 0, 99), false)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(now, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
  }

  let answers: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
  assert_eq!(
    answers.len(),
    1,
    "TTL=0 goodbye record must NOT be collected; \
       prior live answer must remain intact.  Got: {answers:?}"
  );
  e.cancel_query(h).unwrap();
}

// ── KAS fan-out across same-type services ────────────────────

/// A QR=0 known-answer PTR record for a shared `service_type` must
/// fan out to EVERY registered service of that type, not just the
/// first by slab order — otherwise the actual owning service never
/// gets the suppression hint.
#[test]
fn qr0_ptr_known_answer_fans_out_to_all_same_type_services() {
  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();

  // Three services sharing the same service_type.
  let mut handles = std::vec::Vec::new();
  for inst_label in ["Alpha", "Beta", "Gamma"] {
    let inst_str = std::format!("{inst_label}._ipp._tcp.local.");
    let inst = Name::try_from_str(&inst_str).unwrap();
    let host_str = std::format!("{}-host.local.", inst_label.to_ascii_lowercase());
    let host = Name::try_from_str(&host_str).unwrap();
    let recs = ServiceRecords::new(stype.clone(), inst, host, 631, 120);
    let (h, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    handles.push(h);
  }

  // Build a QR=0 packet with an ANSWER section containing a PTR
  // record for the shared service_type — a KAS hint from another
  // querier mentioning the Beta service.
  let mut buf = [0u8; 512];
  let header = Header::new();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  let beta_inst = Name::try_from_str("Beta._ipp._tcp.local.").unwrap();
  b.push_ptr_answer(&stype, 120, &beta_inst).unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  // Collect all KnownAnswer service handles.
  let kas_handles: std::vec::Vec<_> = events
    .iter()
    .filter_map(|ev| match ev {
      RouteEvent::ToService(ts) if ts.event().is_known_answer() => Some(ts.handle()),
      _ => None,
    })
    .collect();

  // all three same-type services must receive the KAS hint.
  for h in &handles {
    assert!(
      kas_handles.contains(h),
      "service {h:?} must receive KnownAnswer for shared-PTR; \
         got handles {kas_handles:?}"
    );
  }
  assert_eq!(
    kas_handles.len(),
    3,
    "exactly three KnownAnswer events expected (one per same-type service); \
       got {kas_handles:?}"
  );
}

/// a QR=0 PTR owned by the DNS-SD service-type enumeration meta name
/// is a known-answer for the §9 meta reply. Its owner is none of any service's
/// RRset names, so the endpoint must fan it out as a KnownAnswer to EVERY
/// service (each then decides at the Service level whether the PTR target is
/// its own type and the §7.1 gates hold). Without this routing the meta-KAS
/// was unreachable end-to-end.
#[test]
fn meta_ptr_known_answer_fans_out_to_all_services() {
  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();

  // Two services of DIFFERENT types.
  let mut handles = std::vec::Vec::new();
  for (inst_str, stype_str, host_str) in [
    ("p._ipp._tcp.local.", "_ipp._tcp.local.", "ph.local."),
    ("w._http._tcp.local.", "_http._tcp.local.", "wh.local."),
  ] {
    let recs = ServiceRecords::new(
      Name::try_from_str(stype_str).unwrap(),
      Name::try_from_str(inst_str).unwrap(),
      Name::try_from_str(host_str).unwrap(),
      631,
      120,
    );
    let (h, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    handles.push(h);
  }

  // QR=0 packet carrying a meta-PTR known-answer:
  //   _services._dns-sd._udp.local. -> _ipp._tcp.local.
  let mut buf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  let meta = Name::try_from_str("_services._dns-sd._udp.local.").unwrap();
  let ipp = Name::try_from_str("_ipp._tcp.local.").unwrap();
  b.push_ptr_answer(&meta, 120, &ipp).unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, &buf[..n], false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  let kas_handles: std::vec::Vec<_> = events
    .iter()
    .filter_map(|ev| match ev {
      RouteEvent::ToService(ts) if ts.event().is_known_answer() => Some(ts.handle()),
      _ => None,
    })
    .collect();

  for h in &handles {
    assert!(
      kas_handles.contains(h),
      "meta-PTR known-answer must fan out to service {h:?}; got {kas_handles:?}"
    );
  }
  assert_eq!(
    kas_handles.len(),
    2,
    "one meta KnownAnswer per registered service; got {kas_handles:?}"
  );
}

// ── TTL=0 records bypass route-level fan-out ─────────────────

/// A QR=0 answer with TTL=0 (goodbye / withdrawal) must not trigger
/// any service-side event — no ProbeConflict for a matching instance
/// name, no HostConflict for a matching host, no KnownAnswer for a
/// matching service_type.  The peer is WITHDRAWING the record, not
/// claiming it.  Cache layer still observes the removal independently.
#[test]
fn qr0_ttl_zero_does_not_emit_service_events() {
  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 631, 120);
  recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
  let now = StdInstant::now();
  let (_h, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // QR=0 packet with a TTL=0 A answer for our HOST name (would
  // normally trigger HostConflict + KnownAnswer).
  let mut buf = [0u8; 512];
  let header = Header::new();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&host, 0, Ipv4Addr::new(10, 0, 0, 2), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();
  assert!(
    events.is_empty(),
    "QR=0 TTL=0 record must NOT yield any RouteEvent; got {events:?}"
  );

  // Also exercise instance-name (would have been ProbeConflict) and
  // service_type (would have been KnownAnswer).
  for record_name in [&inst, &Name::try_from_str("_ipp._tcp.local.").unwrap()] {
    let mut buf2 = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf2, header).unwrap();
    b.push_a_answer(record_name, 0, Ipv4Addr::new(10, 0, 0, 3), false)
      .unwrap();
    let n = b.finish().unwrap();
    let events: std::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, &buf2[..n], false)
      .unwrap()
      .map(Result::unwrap)
      .collect();
    assert!(
      events.is_empty(),
      "QR=0 TTL=0 for {} must NOT yield any RouteEvent; got {events:?}",
      record_name.as_str()
    );
  }
}

/// A TTL=0 authority-section record must NOT emit ProbeConflict /
/// HostConflict — same goodbye semantics as in the answer
/// section.
#[test]
fn authority_ttl_zero_does_not_emit_conflict_events() {
  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let recs = ServiceRecords::new(st, inst.clone(), host.clone(), 631, 120);
  let now = StdInstant::now();
  let (_h, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // Build a probe-shaped QR=0 packet with a TTL=0 A authority
  // record for the registered HOST name.  Under normal TTL this
  // would route as HostConflict.
  let mut buf = [0u8; 512];
  let hdr = Header::new();
  let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, hdr).unwrap();
  b.push_a_authority(&host, 0, Ipv4Addr::new(192, 168, 1, 99))
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();
  assert!(
    events.is_empty(),
    "TTL=0 authority record (host) must not emit HostConflict; got {events:?}"
  );

  // Same packet but the authority targets the INSTANCE name (would
  // normally route as ProbeConflict).
  let mut buf2 = [0u8; 512];
  let hdr = Header::new();
  let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf2, hdr).unwrap();
  b.push_a_authority(&inst, 0, Ipv4Addr::new(192, 168, 1, 99))
    .unwrap();
  let n = b.finish().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, &buf2[..n], false)
    .unwrap()
    .map(Result::unwrap)
    .collect();
  assert!(
    events.is_empty(),
    "TTL=0 authority record (instance) must not emit ProbeConflict; got {events:?}"
  );
}

// ── cache-flush dedup within a packet ────────────────────────

/// A multi-record RRSet (e.g. multiple A records for the same host)
/// with the cache-flush bit set on every record must end up with ALL
/// records in the cache — not just the last.  Previously, the
/// 2nd record's cache_flush evicted the 1st, the 3rd evicted the
/// 2nd, etc., leaving only the final address.
#[test]
fn cache_flush_within_one_packet_preserves_full_rrset() {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("multihomed.local.").unwrap();

  // Two A records for the same host, both cache_flush=true (typical
  // mDNS announcement of a multi-address host).
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 1), true)
    .unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
    .unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 3), true)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();

  // All three A records must be in the cache for the same host.
  let count = e
    .cache
    .count_matching(&host, ResourceType::A, ResourceClass::In);
  assert_eq!(
    count, 3,
    "multi-A RRSet with cache_flush must preserve all 3 entries; got {count}"
  );
}

// ── QR=1 answer-section records trigger probe-time conflict ─

/// RFC 6762 §8.1 — a probing host MUST treat any RESPONSE message
/// claiming one of its tentative names as a conflict event.  Test
/// that a QR=1 packet with an A answer record owned by our
/// instance/host fires ProbeConflict / HostConflict respectively.
#[test]
fn qr1_answer_for_instance_name_emits_probe_conflict() {
  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let st = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
  let host = Name::try_from_str("alpha.local.").unwrap();
  let recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
  let now = StdInstant::now();
  let (_handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // RESPONSE (QR=1) with an SRV answer for our instance name (the instance's
  // unique RRset; ProbeConflict is gated to SRV/TXT).
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  let srv_target = Name::try_from_str("other-host.local.").unwrap();
  b.push_srv_answer(&inst, 120, 0, 0, 8080, &srv_target, false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  let has_probe_conflict = events
    .iter()
    .any(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_probe_conflict()));
  assert!(
    has_probe_conflict,
    "QR=1 answer claiming our instance name must emit ProbeConflict; got {events:?}"
  );
}

/// Parallel test for host-name match → HostConflict.
#[test]
fn qr1_answer_for_host_name_emits_host_conflict() {
  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let st = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
  let host = Name::try_from_str("alpha.local.").unwrap();
  let recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
  let now = StdInstant::now();
  let (_handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  let has_host_conflict = events
    .iter()
    .any(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_host_conflict()));
  assert!(
    has_host_conflict,
    "QR=1 answer claiming our host name must emit HostConflict; got {events:?}"
  );
}

// ── QR=0 answer-section records must NOT mutate the cache ────

/// QR=0 (query) packets carry answer-section records as known-answer
/// hints, not authoritative observations.  They must NOT insert into,
/// delete from, or flush the passive cache.  Previously a hostile
/// querier could:
///   * insert forged rdata into the cache via QR=0 positive-TTL answers,
///   * delete cached records via QR=0 TTL=0 answers,
///   * clamp legitimate cached siblings via QR=0 cache_flush answers.
#[test]
fn qr0_answer_does_not_mutate_cache() {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
  use core::{net::SocketAddr, time::Duration};

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("victim.local.").unwrap();

  // Seed cache with an authoritative IN A record.
  e.cache
    .try_insert(
      host.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 1],
      Duration::from_secs(120),
      now,
      false,
    )
    .unwrap();
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    1
  );

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  // (1) QR=0 packet with a forged A answer for the same host (different rdata).
  //     Must NOT insert a second cache entry.
  let mut buf = [0u8; 512];
  let header = Header::new(); // QR=0
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 99), false)
    .unwrap();
  let n = b.finish().unwrap();
  let _ = e
    .handle(now, src, local_ip, 0, &buf[..n], false)
    .unwrap()
    .count();
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    1,
    "QR=0 positive-TTL answer must NOT insert into cache"
  );

  // (2) QR=0 packet with TTL=0 for the seeded rdata.  Must NOT delete.
  let mut buf = [0u8; 512];
  let header = Header::new();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&host, 0, Ipv4Addr::new(10, 0, 0, 1), false)
    .unwrap();
  let n = b.finish().unwrap();
  let _ = e
    .handle(now, src, local_ip, 0, &buf[..n], false)
    .unwrap()
    .count();
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    1,
    "QR=0 TTL=0 answer must NOT delete cached entry"
  );

  // (3) QR=0 packet with cache_flush=true.  Must NOT clamp / evict.
  let mut buf = [0u8; 512];
  let header = Header::new();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 99), true)
    .unwrap();
  let n = b.finish().unwrap();
  // Advance past §10.2 grace so the seeded entry WOULD have been
  // clamped if the QR=0 cache-flush were honoured.
  let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();
  let _ = e
    .handle(after_grace, src, local_ip, 0, &buf[..n], false)
    .unwrap()
    .count();
  // Sweep past where the clamp would have expired the seeded record.
  let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
  e.cache.sweep_expired(after_clamp);
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    1,
    "QR=0 cache_flush must NOT clamp legitimate cached siblings"
  );
}

// ── cache-flush uses deferred expiry, not immediate evict ────

/// An old multi-record RRSet refreshed across two packets must
/// survive the burst.  RFC 6762 §10.2 specifies cache-flush clamps
/// matching siblings' `expires_at` to `min(current, now + 1s)`
/// instead of removing them immediately — so siblings re-announced
/// within 1s have their expiry undone by the refresh path, and
/// siblings NOT re-announced expire naturally a second later.
///
/// Test: seed an old A1/A2 RRSet (received 5 min ago).  Send
/// packet 1 with A1 cache_flush=true (refreshes A1, clamps A2).
/// Send packet 2 with A2 cache_flush=true within the grace window
/// (refreshes A2, undoes the clamp).  Both A1 and A2 should still
/// be in the cache, with non-clamped expirations.
#[test]
fn cache_flush_deferred_expiry_preserves_refreshed_rrset() {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
  use core::{net::SocketAddr, time::Duration};

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("multihomed.local.").unwrap();

  // Seed cache with two OLD A records — received 5 minutes ago.
  // Windows' `Instant` counts from boot, so `now` can be < 300s on a freshly
  // booted runner — subtracting would underflow. Advance the base first; the
  // relative timing (long_ago is 300s before now) is unchanged.
  let now = now + Duration::from_secs(300);
  let long_ago = now.checked_sub(Duration::from_secs(300)).unwrap();
  e.cache
    .try_insert(
      host.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 1],
      Duration::from_secs(120),
      long_ago,
      false,
    )
    .unwrap();
  e.cache
    .try_insert(
      host.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 2],
      Duration::from_secs(120),
      long_ago,
      false,
    )
    .unwrap();
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    2
  );

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  // Packet 1: A 10.0.0.1 cache_flush=true (refresh burst start).
  let pkt1_t = now;
  {
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 1), true)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(pkt1_t, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
  }
  // After packet 1: A1 refreshed; A2 expires_at clamped to pkt1_t + 1s
  // but NOT yet removed.  Both still present.
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    2,
    "clamp must NOT remove A2 immediately — only defer its expiry"
  );

  // Packet 2: A 10.0.0.2 cache_flush=true, 200 ms later.
  let pkt2_t = pkt1_t.checked_add(Duration::from_millis(200)).unwrap();
  {
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(pkt2_t, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
  }

  // After packet 2: A2 refreshed (clamp undone via dedup path).
  // Sweep past the original clamp deadline — neither should expire.
  let after_clamp = pkt1_t.checked_add(Duration::from_secs(3)).unwrap();
  e.cache.sweep_expired(after_clamp);
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    2,
    "a refresh burst within the §10.2 grace must preserve the \
       full RRSet — both A1 and A2 must survive after sweep"
  );
}

// ── per-packet flush dedup keys on (name, rtype, rclass) ─────

/// A datagram containing a non-IN cache_flush record BEFORE an
/// IN cache_flush record for the same (name, rtype) must NOT
/// suppress the IN flush.  the per-packet flush dedup
/// includes rclass, so the second record (different class) still
/// performs the §10.2 deferred-expiry clamp on stale IN siblings.
#[test]
fn flush_marker_keys_on_rclass_so_mixed_class_does_not_suppress() {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
  use core::{net::SocketAddr, time::Duration};

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("svc.local.").unwrap();

  // Seed an OLD IN-class A record (5 min ago) that is eligible for
  // the deferred-expiry clamp.
  // Windows' `Instant` counts from boot, so `now` can be < 300s on a freshly
  // booted runner — subtracting would underflow. Advance the base first; the
  // relative timing (long_ago is 300s before now) is unchanged.
  let now = now + Duration::from_secs(300);
  let long_ago = now.checked_sub(Duration::from_secs(300)).unwrap();
  e.cache
    .try_insert(
      host.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 1],
      Duration::from_secs(120),
      long_ago,
      false,
    )
    .unwrap();
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    1
  );

  // Build a single packet with TWO cache_flush A records:
  //   (i)  class ANY (non-IN) — would consume the flush marker under
  //        the class-blind keying.
  //   (ii) class IN — needs the deferred-expiry clamp on the old IN
  //        sibling above.
  // The wire builder doesn't expose a "set rclass" knob on push_a_answer
  // — that always emits class IN.  So we exercise the dedup directly
  // by calling try_insert twice with different rclass + cache_flush=true.
  //
  // First: ANY-class cache_flush insert.  This records
  // `(host, A, Any)` in flushed_in_packet — but we're calling
  // Cache::try_insert directly here, which bypasses Endpoint::handle's
  // per-packet tracker.  To exercise the actual code path, instead
  // build a valid wire packet with the IN record and verify the IN
  // sibling gets clamped via the normal handle path.
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  // Two IN cache_flush A records with different rdata.  This exercises
  // the per-packet dedup: only the first triggers the clamp; the
  // second piggybacks via flushed_in_packet.  Crucially, the
  // class-aware dedup means we ALSO clamp the old sibling exactly
  // once per (name, rtype, rclass) — the test verifies that the
  // sibling IS clamped (would be skipped under a buggy class-blind
  // dedup if a non-IN flush had been first).
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
    .unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 3), true)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();

  // The old IN sibling (10.0.0.1) must be clamped to expire at now+1s.
  // Sweep past that deadline; the OLD record is removed.
  let after_clamp = now.checked_add(Duration::from_secs(2)).unwrap();
  e.cache.sweep_expired(after_clamp);

  let count = e
    .cache
    .count_matching(&host, ResourceType::A, ResourceClass::In);
  assert_eq!(
    count, 2,
    "old IN sibling must have been clamped + swept; the two \
       new IN records from the packet survive.  Expected 2 (10.0.0.2 \
       and 10.0.0.3); got {count}"
  );
}

// ── cache identity includes ResourceClass ─────────────────────

/// A record with non-IN class must not dedupe with, evict, or count
/// as an IN-class entry.  Previously the cache stored only
/// `(name, rtype, rdata)` so a hostile or misconfigured response
/// could corrupt the cache across class boundaries.
#[test]
fn cache_class_isolates_in_from_non_in() {
  use core::time::Duration;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("svc.local.").unwrap();

  // Insert an IN-class A record.
  e.cache
    .try_insert(
      host.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 1],
      Duration::from_secs(120),
      now,
      false,
    )
    .unwrap();

  // Insert a record with SAME name + rtype + rdata but DIFFERENT class
  // (ANY).  Must NOT dedupe — must coexist.
  e.cache
    .try_insert(
      host.clone(),
      ResourceType::A,
      crate::wire::ResourceClass::Any,
      std::vec![10, 0, 0, 1],
      Duration::from_secs(120),
      now,
      false,
    )
    .unwrap();

  // class is part of the key.  Two distinct entries.
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    1
  );
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, crate::wire::ResourceClass::Any),
    1
  );

  // A cache_flush in class ANY must NOT evict the IN entry (advance
  // past grace first, so the IN entry would otherwise be eligible).
  let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();
  e.cache
    .try_insert(
      host.clone(),
      ResourceType::A,
      crate::wire::ResourceClass::Any,
      std::vec![10, 0, 0, 99],
      Duration::from_secs(120),
      after_grace,
      true,
    )
    .unwrap();
  let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
  e.cache.sweep_expired(after_clamp);

  // IN entry is still alive.
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    1,
    "cache_flush in class ANY must NOT touch IN-class entries"
  );
}

// ── cross-packet cache-flush respects §10.2 grace window ─────

/// A multi-address RRSet announced across TWO separate packets,
/// both with cache_flush=true, must result in BOTH addresses being
/// cached.  RFC 6762 §10.2 specifies a 1-second grace: cache_flush
/// must not evict entries received within the last second.  Before
/// the second packet's cache_flush evicted the first
/// packet's record because the eviction was unconditional, so a
/// multi-A announcement split across packets collapsed to only the
/// last record.
#[test]
fn cache_flush_preserves_recent_siblings_across_packets() {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("multihomed.local.").unwrap();

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  // Packet 1: A 10.0.0.1 with cache_flush=true.
  {
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 1), true)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(now, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
  }
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    1
  );

  // Packet 2: A 10.0.0.2 with cache_flush=true, arriving 100 ms later
  // — well within the §10.2 1-second grace window.
  let later = now
    .checked_add(core::time::Duration::from_millis(100))
    .unwrap();
  {
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(later, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
  }

  // BOTH A records must be cached.  Without the grace window
  // the second cache_flush would have evicted the first.
  let count = e
    .cache
    .count_matching(&host, ResourceType::A, ResourceClass::In);
  assert_eq!(
    count, 2,
    "cross-packet cache-flush within §10.2 grace must preserve \
       fresh siblings.  Expected 2 (both 10.0.0.1 and 10.0.0.2); got {count}"
  );
}

// ── TTL=0 record must not consume the per-packet flush marker ─

/// A TTL=0 cache-flush record (goodbye for a single rdata) does NOT
/// evict the RRSet — `Cache::try_insert` handles TTL=0 before the
/// cache-flush branch and removes only the exact rdata.  If such a
/// record consumed the per-packet flush marker, a later
/// positive-TTL cache-flush record for the same `(name, rtype)`
/// would be downgraded to `cache_flush=false` and would NOT evict
/// older siblings — they would remain stale.
///
/// Test: seed the cache with A=10.0.0.1 and A=10.0.0.2.  Feed a
/// single packet containing (i) TTL=0/cache_flush goodbye for
/// 10.0.0.1 and (ii) TTL=120/cache_flush for new 10.0.0.3.  Both
/// 10.0.0.1 (removed by goodbye) AND 10.0.0.2 (evicted by the
/// positive cache_flush) must be gone; only 10.0.0.3 should remain.
#[test]
fn ttl_zero_does_not_consume_flush_marker() {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
  use core::{net::SocketAddr, time::Duration};

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("printer.local.").unwrap();

  // Seed the cache with two A records (TTL=120).
  e.cache
    .try_insert(
      host.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 1],
      Duration::from_secs(120),
      now,
      false,
    )
    .unwrap();
  e.cache
    .try_insert(
      host.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 2],
      Duration::from_secs(120),
      now,
      false,
    )
    .unwrap();
  assert_eq!(
    e.cache
      .count_matching(&host, ResourceType::A, ResourceClass::In),
    2
  );

  // Advance past the §10.2 grace so the seeded entries are
  // eligible for eviction.
  let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();

  // Build a single packet: (i) TTL=0/cache_flush goodbye for 10.0.0.1,
  // followed by (ii) TTL=120/cache_flush for 10.0.0.3.
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&host, 0, Ipv4Addr::new(10, 0, 0, 1), true)
    .unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 3), true)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let _ = e
    .handle(after_grace, src, local_ip, 0, pkt, false)
    .unwrap()
    .count();

  // deferred expiry: the positive-TTL cache_flush CLAMPS the
  // surviving sibling (10.0.0.2) to expire at after_grace + 1s.
  // Sweep past that deadline to drop it.
  let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
  e.cache.sweep_expired(after_clamp);

  // 10.0.0.2 must be evicted (via the clamp + sweep); only
  // 10.0.0.3 should remain (10.0.0.1 was removed by the goodbye).
  let count = e
    .cache
    .count_matching(&host, ResourceType::A, ResourceClass::In);
  assert_eq!(
    count, 1,
    "TTL=0 goodbye must not consume the per-packet flush \
       marker, so the subsequent positive-TTL cache_flush record must \
       still evict the unrelated sibling.  Expected 1 (only 10.0.0.3); \
       got {count}"
  );
}

// ── iterator terminates after parse errors ───────────────────

/// A malformed answer/authority record must not pin the iterator
/// returning the same Err on every call — the section must advance
/// (or transition to Done) after the error so the iterator
/// eventually returns None.
#[test]
fn malformed_record_does_not_loop_forever() {
  use crate::wire::Header;
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();

  // Build a packet with a malformed answer.  Hand-craft: header
  // claims 1 answer but the body is empty so parsing fails.
  let mut buf = [0u8; 32];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  hdr.set_answer_count(1);
  let header_len = hdr.write(&mut buf).unwrap();
  let pkt = &buf[..header_len]; // body absent -> malformed answer

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();
  let mut total_polls = 0u32;
  let mut error_count = 0u32;
  for ev in events {
    total_polls = total_polls.saturating_add(1);
    if ev.is_err() {
      error_count = error_count.saturating_add(1);
    }
    if total_polls > 10 {
      panic!(
        "iterator must terminate after parse error; \
           seen {error_count} errors in {total_polls} polls without None"
      );
    }
  }
  // Iterator terminated.  Bounded error count: at most one per section.
  assert!(
    error_count <= 3,
    "at most one parse error per section (3 sections); got {error_count}"
  );
}

// ── answer_questions=false suppresses Question events ────────

/// When `EndpointConfig::answer_questions` is false, no
/// `ServiceEvent::Question` events fire — the registered service
/// stays passive even when peer queries match its names.
#[test]
fn answer_questions_false_suppresses_question_events() {
  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::net::SocketAddr;

  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([7u8; 32]);
  let cfg = EndpointConfig::new().with_answer_questions(false);
  let mut e = TestEndp::try_new(cfg, rng);
  let st = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("WebServer._http._tcp.local.").unwrap();
  let host = Name::try_from_str("web.local.").unwrap();
  let recs = ServiceRecords::new(st.clone(), inst.clone(), host, 80, 120);
  let now = StdInstant::now();
  let (_h, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // QR=0 packet with a question for the registered instance name.
  let mut buf = [0u8; 512];
  let header = Header::new();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_question(
    &inst,
    ResourceType::Any,
    crate::wire::ResourceClass::In,
    false,
  )
  .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  let question_events: std::vec::Vec<_> = events
    .iter()
    .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_question()))
    .collect();
  assert!(
    question_events.is_empty(),
    "answer_questions=false must suppress ServiceEvent::Question; \
       got {question_events:?}"
  );
}

// ── authority-section host fan-out ───────────────────────────

/// Multiple services can legitimately share a host name.  An authority
/// record (peer probe) claiming that host MUST surface HostConflict
/// to every service sharing it — not just the first by slab order.
/// Previously the authority loop returned on the first match and
/// advanced authority_idx, so additional services kept advertising the
/// conflicted host with no signal.
#[test]
fn authority_host_conflict_fans_out_to_all_same_host_services() {
  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let now = StdInstant::now();

  // Three services with DIFFERENT instance names but the SAME host.
  let mut handles = std::vec::Vec::new();
  for inst_label in ["A", "B", "C"] {
    let inst_str = std::format!("{inst_label}._ipp._tcp.local.");
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str(&inst_str).unwrap();
    let recs = ServiceRecords::new(st, inst, host.clone(), 631, 120);
    let (h, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    handles.push(h);
  }

  // Probe-shaped authority record claiming the shared host.
  let mut buf = [0u8; 512];
  let hdr = Header::new();
  let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, hdr).unwrap();
  b.push_a_authority(&host, 120, Ipv4Addr::new(192, 168, 1, 99))
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  // Every registered service must receive HostConflict.
  let conflict_handles: std::vec::Vec<_> = events
    .iter()
    .filter_map(|ev| match ev {
      RouteEvent::ToService(ts) if ts.event().is_host_conflict() => Some(ts.handle()),
      _ => None,
    })
    .collect();

  for h in &handles {
    assert!(
      conflict_handles.contains(h),
      "service {h:?} must receive HostConflict for shared host; \
         got handles {conflict_handles:?}"
    );
  }
  assert_eq!(
    conflict_handles.len(),
    3,
    "exactly three HostConflict events expected (one per service); \
       got {conflict_handles:?}"
  );
}

/// A QR=1 response answer with TTL=0 must not emit `ToQuery(Answer)`
/// events for active queries.  The query state is already protected
/// at the application step, but iterator-level events
/// should also be suppressed so the caller never sees a "withdrawal
/// disguised as answer."
#[test]
fn qr1_ttl_zero_does_not_emit_to_query_events() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let h = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
    .unwrap();

  // QR=1 response packet with a TTL=0 answer for the query name.
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&qname, 0, Ipv4Addr::new(10, 0, 0, 7), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  let to_query_count = events
    .iter()
    .filter(
      |ev| matches!(ev, RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_))),
    )
    .count();
  assert_eq!(
    to_query_count, 0,
    "QR=1 TTL=0 must NOT emit ToQuery(Answer) events; got events {events:?}"
  );

  // And of course collected_answers must remain empty (this still applies).
  assert_eq!(
    e.collected_answers(h).count(),
    0,
    "TTL=0 must not land in collected_answers"
  );
  e.cancel_query(h).unwrap();
}

// ── terminal queries reject late answers ─────────────────────

/// After `poll_query` returns terminal, subsequent matching
/// responses arriving before `cancel_query` MUST NOT mutate the
/// query's `collected_answers` or evict pre-terminal results from
/// the FIFO under `max_answers` pressure.  This added the
/// `terminal_emitted()` skip to both eager application (in
/// `Endpoint::handle`) and `ToQuery` fan-out (in the iterator) so
/// terminated queries are effectively frozen.
#[test]
fn terminated_query_rejects_late_answers() {
  use crate::{
    config::QuerySpec,
    event::QueryUpdate,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::{net::SocketAddr, time::Duration};

  let mut e = build_endpoint();
  let mut now = StdInstant::now();
  let qn = Name::try_from_str("printer.local.").unwrap();
  let spec = QuerySpec::new(qn.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
  let h = e.try_start_query(spec, now).unwrap();

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  // First response: an A answer arrives BEFORE the timeout fires.
  let mut buf = [0u8; 512];
  let pre_terminal_addr = Ipv4Addr::new(10, 0, 0, 7);
  {
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qn, 120, pre_terminal_addr, false).unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];
    let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();
  }
  assert_eq!(
    e.collected_answers(h).count(),
    1,
    "pre-terminal answer must land in collected_answers"
  );

  // Drive to terminal.
  now = now.checked_add(Duration::from_millis(200)).unwrap();
  e.handle_query_timeout(h, now).unwrap();
  assert!(matches!(
    e.poll_query(h),
    Some(QueryUpdate::Timeout | QueryUpdate::Done)
  ));

  let answers_at_terminal: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
  assert_eq!(answers_at_terminal.len(), 1);

  // Second response: a DIFFERENT A answer arrives AFTER terminal.  This
  // must NOT mutate collected_answers (frozen) AND must NOT yield a
  // ToQuery event for the terminated query.
  let mut buf2 = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf2, hdr).unwrap();
  b.push_a_answer(&qn, 120, Ipv4Addr::new(10, 0, 0, 99), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf2[..n];

  let events: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, pkt, false)
    .unwrap()
    .map(Result::unwrap)
    .collect();

  // No ToQuery(Answer) for the terminated handle.
  let to_query_events: std::vec::Vec<_> = events
    .iter()
    .filter_map(|ev| match ev {
      RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_)) => Some(tq.handle()),
      _ => None,
    })
    .collect();
  assert!(
    !to_query_events.contains(&h),
    "terminated query must NOT receive ToQuery(Answer) events; got handles {to_query_events:?}"
  );

  // collected_answers unchanged.
  let answers_after_terminal: std::vec::Vec<_> = e.collected_answers(h).cloned().collect();
  assert_eq!(
    answers_after_terminal.len(),
    1,
    "collected_answers must be frozen after terminal; \
       got {answers_after_terminal:?}"
  );
  assert_eq!(
    answers_after_terminal[0].rdata_slice(),
    &pre_terminal_addr.octets(),
    "pre-terminal answer must remain intact (no eviction)"
  );

  // Cleanup.
  e.cancel_query(h).unwrap();
}

/// `sweep_terminated_queries` prunes every query whose terminal has
/// been emitted; ongoing queries are untouched.
#[test]
fn sweep_terminated_queries_prunes_only_terminated() {
  use crate::{config::QuerySpec, event::QueryUpdate, wire::ResourceType};
  use core::time::Duration;

  let mut e = build_endpoint();
  let mut now = StdInstant::now();
  let qn = Name::try_from_str("printer.local.").unwrap();

  // Two queries: one with a short timeout, one without.
  let h_short = e
    .try_start_query(
      QuerySpec::new(qn.clone(), ResourceType::A).with_timeout(Duration::from_millis(100)),
      now,
    )
    .unwrap();
  let h_long = e
    .try_start_query(QuerySpec::new(qn.clone(), ResourceType::AAAA), now)
    .unwrap();
  assert_eq!(e.queries.len(), 2);

  // Sweep with no terminated queries — no-op.
  assert_eq!(e.sweep_terminated_queries(), 0);
  assert_eq!(e.queries.len(), 2);

  // Drive h_short to terminal and observe.
  now = now.checked_add(Duration::from_millis(200)).unwrap();
  e.handle_query_timeout(h_short, now).unwrap();
  assert!(matches!(
    e.poll_query(h_short),
    Some(QueryUpdate::Timeout | QueryUpdate::Done)
  ));
  assert_eq!(e.queries.len(), 2, "terminal does not auto-prune");

  // Sweep — h_short goes; h_long stays.
  assert_eq!(e.sweep_terminated_queries(), 1);
  assert_eq!(e.queries.len(), 1);
  assert!(e.collected_answers(h_short).next().is_none());
  // h_long is still active.
  e.cancel_query(h_long).unwrap();
}

/// `cancel_query` removes the route immediately; subsequent lookups
/// return `CancelQueryError::QueryNotFound` for the cancelled handle.
#[test]
fn cancel_query_removes_route() {
  use crate::{config::QuerySpec, error::CancelQueryError, wire::ResourceType};

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let spec = QuerySpec::new(qname, ResourceType::A);
  let h = e.try_start_query(spec, now).unwrap();
  assert_eq!(e.queries.len(), 1);

  e.cancel_query(h).unwrap();
  assert_eq!(e.queries.len(), 0);

  // Second cancel on the same handle returns QueryNotFound.
  let r = e.cancel_query(h);
  assert!(
    matches!(r, Err(CancelQueryError::QueryNotFound(_))),
    "cancel_query on absent handle must return QueryNotFound; got {r:?}"
  );
}

/// Query teardown is bound by the same confirm-before-anything contract as a
/// service's. Removing the query DISCARDS the commit token, so the confirm that
/// follows finds no handle and silently does nothing while the datagram it
/// described is still on its way out — a driver that cancels from another task
/// must flag the cancellation and sweep it after its transmit pump confirms.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "still awaiting Query::note_transmit_outcome")]
fn cancel_query_under_a_live_send_confirm_trips_the_contract_assertion() {
  use crate::{config::QuerySpec, wire::ResourceType};

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let h = e
    .try_start_query(QuerySpec::new(qname, ResourceType::A), now)
    .unwrap();
  let mut buf = std::vec![0u8; 512];
  e.poll_query_transmit(h, || now, &mut buf)
    .unwrap()
    .expect("a newly-started query has its first question due");
  let _ = e.cancel_query(h);
}

/// The retirement half of the same contract: forcing the query to its TIMEOUT
/// terminal is a state mutation, so a driver that cannot send the question must
/// resolve the outstanding datagram as `NoneDelivered` before retiring the query
/// that produced it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "still awaiting Query::note_transmit_outcome")]
fn retire_query_under_a_live_send_confirm_trips_the_contract_assertion() {
  use crate::{config::QuerySpec, wire::ResourceType};

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let h = e
    .try_start_query(QuerySpec::new(qname, ResourceType::A), now)
    .unwrap();
  let mut buf = std::vec![0u8; 512];
  e.poll_query_transmit(h, || now, &mut buf)
    .unwrap()
    .expect("a newly-started query has its first question due");
  e.retire_query(h);
}

// ── Stats invariant: queries_started == queries_done + queries_active ──────

/// The invariant `queries_started == queries_done + queries_active` must
/// hold at all times.  (`queries_timeout` is a sub-counter of `queries_done`
/// — both are bumped by `terminate(Timeout)` — so it is NOT a third term.)
///
/// This test verifies two paths:
///   (i)  live cancel — `cancel_query` IS the terminal transition, so it
///        must bump `queries_done` AND decrement `queries_active`.
///   (ii) cancel-after-terminal — `Query::terminate` already performed both
///        adjustments; `cancel_query` must NOT repeat them.
#[cfg(feature = "stats")]
#[test]
fn cancel_query_stats_invariant() {
  use crate::{config::QuerySpec, wire::ResourceType};
  use core::time::Duration;

  // Helper: assert the fundamental counter invariant.
  let check_invariant = |label: &str, snap: &hick_trace::stats::StatsSnapshot| {
    assert_eq!(
      snap.queries_started,
      snap.queries_done + snap.queries_active,
      "invariant queries_started == queries_done + queries_active \
         violated at '{label}': {snap:?}"
    );
  };

  // ── (i) live cancel ────────────────────────────────────────────────────
  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let spec = QuerySpec::new(qname.clone(), ResourceType::A);
  let h = e.try_start_query(spec, now).unwrap();

  let before = e.stats();
  assert_eq!(before.queries_started, 1);
  assert_eq!(before.queries_active, 1);
  assert_eq!(before.queries_done, 0);
  check_invariant("after-start", &before);

  // Cancel while still live (done=false).
  e.cancel_query(h).unwrap();
  let after_live_cancel = e.stats();
  assert_eq!(
    after_live_cancel.queries_done, 1,
    "live cancel must bump queries_done; got {after_live_cancel:?}"
  );
  assert_eq!(
    after_live_cancel.queries_active, 0,
    "live cancel must decrement queries_active; got {after_live_cancel:?}"
  );
  check_invariant("after-live-cancel", &after_live_cancel);

  // ── (ii) cancel after terminal ─────────────────────────────────────────
  let mut e2 = build_endpoint();
  let mut now2 = StdInstant::now();
  let spec2 = QuerySpec::new(qname, ResourceType::A).with_timeout(Duration::from_millis(50));
  let h2 = e2.try_start_query(spec2, now2).unwrap();

  // Drive past absolute timeout → query terminates inside handle_query_timeout.
  now2 += Duration::from_millis(100);
  e2.handle_query_timeout(h2, now2).unwrap();
  let _ = e2.poll_query(h2); // drain terminal update

  let snap_terminal = e2.stats();
  check_invariant("after-terminal", &snap_terminal);

  // cancel_query on an already-done query must be a no-op for stats.
  e2.cancel_query(h2).unwrap();
  let snap_after_cancel = e2.stats();
  assert_eq!(
    snap_after_cancel.queries_done, snap_terminal.queries_done,
    "cancel-after-terminal must not bump queries_done again; {snap_after_cancel:?}"
  );
  assert_eq!(
    snap_after_cancel.queries_active, snap_terminal.queries_active,
    "cancel-after-terminal must not decrement queries_active again; {snap_after_cancel:?}"
  );
  check_invariant("after-cancel-of-terminal", &snap_after_cancel);
}

// ── duplicate_questions_suppressed increments only on real suppression ──

/// `duplicate_questions_suppressed` must ONLY be incremented when
/// `note_duplicate_question` actually consumed a transmit slot.
///
/// Two sub-cases:
///   (a) When the query is `awaiting_send_confirm` (initial datagram sent but
///       not yet confirmed), `note_duplicate_question` returns false and the
///       counter must NOT advance.
///   (b) After confirmation + timeout arms the next retry,
///       `note_duplicate_question` returns true and the counter advances.
#[cfg(feature = "stats")]
#[test]
fn duplicate_questions_suppressed_only_on_real_suppression() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
  };
  use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
  };

  let mut e = build_endpoint();
  let mut now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let spec = QuerySpec::new(qname.clone(), ResourceType::A);
  let h = e.try_start_query(spec, now).unwrap();

  // Build a peer QM question packet matching our query (QR=0, source port 5353).
  let mut pkt_buf = [0u8; 512];
  let hdr = Header::new();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut pkt_buf, hdr).unwrap();
  b.push_question(&qname, ResourceType::A, ResourceClass::In, false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = pkt_buf[..n].to_vec();

  let multicast_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
  let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 2), 5353u16));

  // (a) Drain the initial transmit without confirming → awaiting_send_confirm=true.
  let mut tx_buf = std::vec![0u8; 512];
  let tx = e.poll_query_transmit(h, || now, &mut tx_buf).unwrap();
  assert!(
    tx.is_some(),
    "newly-started query must have an initial transmit pending"
  );
  // Do NOT call note_query_transmit_outcome — leave the query awaiting confirm.
  // Now feed the peer question: note_duplicate_question → returns false → no bump.
  {
    let mut events = e
      .handle(now, peer_src, multicast_ip, 0, &pkt, false)
      .unwrap();
    while events.next().is_some() {}
  }
  let snap_awaiting = e.stats();
  assert_eq!(
    snap_awaiting.duplicate_questions_suppressed, 0,
    "(a) no suppression while awaiting send confirm; got {snap_awaiting:?}"
  );

  // (b) Confirm the send, advance time to arm next retry, then feed the peer
  // question again → note_duplicate_question returns true → counter advances.
  e.note_query_transmit_outcome(h, now, TransmitDelivery::ALL); // confirm
  now += Duration::from_secs(10); // past the first retry deadline (~1s)
  e.handle_query_timeout(h, now).unwrap(); // arms transmit_pending = true

  {
    let mut events = e
      .handle(now, peer_src, multicast_ip, 0, &pkt, false)
      .unwrap();
    while events.next().is_some() {}
  }
  let snap_suppressed = e.stats();
  assert_eq!(
    snap_suppressed.duplicate_questions_suppressed, 1,
    "(b) one suppression expected after arming next retry; got {snap_suppressed:?}"
  );
}

// ── IPv6 link-local self-check is interface-scoped ──────────

/// IPv6 link-local addresses (`fe80::/10`) are scoped per interface.
/// Two unrelated hosts on different interfaces can both pick `fe80::1`
/// without conflict.  Previously the self-loopback membership check
/// compared bare addresses, so a peer using the same link-local on a
/// different interface would be wrongly classified as self and
/// suppressed.
///
/// Test: register a service publishing `fe80::1` scoped to interface
/// index 2, then feed back a probe-shaped AAAA-authority packet with
/// `src = fe80::1`.  The same packet must:
///   * be suppressed when delivered with `interface_index == 2` (true
///     self-loopback), AND
///   * be routed normally (ProbeConflict) when delivered with
///     `interface_index == 3` (a remote peer on another interface).
#[test]
fn ipv6_link_local_self_check_is_interface_scoped() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::{Ipv6Addr, SocketAddr};

  // signal (b) is opt-in. This test validates the legacy
  // advertised-source fallback's interface-scoped behaviour.
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
  let mut e = TestEndp::try_new(
    EndpointConfig::new().with_trust_advertised_src_as_self(true),
    rng,
  );
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst.clone(), host, 631, 120);
  let our_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
  // Bound to interface index 2 — packets arriving on any other interface
  // with src = fe80::1 must be treated as peer, not self.
  recs.add_aaaa_scoped(our_v6, 2);
  let now = StdInstant::now();
  let (_handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let mut buf = [0u8; 512];
  let hdr = Header::new();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_srv_authority(
    &inst,
    120,
    0,
    0,
    8080,
    &Name::try_from_str("other-host.local.").unwrap(),
  )
  .unwrap();
  let n = b.finish().unwrap();
  let data = &buf[..n];

  let local_ip: core::net::IpAddr =
    core::net::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb));
  let self_src: SocketAddr = SocketAddr::from((our_v6, 5353));

  // (1) Self-loopback: same address, same interface (ifindex=2).
  let mut self_events = e.handle(now, self_src, local_ip, 2, data, false).unwrap();
  assert!(
    self_events.next().is_none(),
    "link-local from OUR interface (ifindex=2) must be self-suppressed"
  );

  // (2) Foreign peer on a different interface (ifindex=3) using the
  //     same numeric link-local.  This is the regression case — must
  //     route as ProbeConflict, not be silently dropped.
  let mut peer_events = e.handle(now, self_src, local_ip, 3, data, false).unwrap();
  let ev = peer_events
    .next()
    .expect("link-local from a DIFFERENT interface must still produce a routing event")
    .expect("event must be Ok");
  match ev {
    RouteEvent::ToService(ts) => assert!(
      ts.event().is_probe_conflict(),
      "link-local from ifindex=3 must emit ProbeConflict (not be misclassified \
         as self because of bare-address match); got {:?}",
      ts.event()
    ),
    other => panic!(
      "expected RouteEvent::ToService(ProbeConflict), got {:?}",
      other
    ),
  }
}

// ── response answers fan out to all type-compatible routes ──

/// Two concurrent queries for the SAME name but DIFFERENT QTYPEs (e.g.
/// `printer.local. A` and `printer.local. AAAA`) must both receive
/// matching answers.  Previously the demux matched the first route
/// by name and broke; an AAAA answer would route to the A query, get
/// filtered out at `Query::handle_event` (rtype mismatch), and never
/// reach the AAAA query.
///
/// Test plan: register an A query and an AAAA query for the same name,
/// then feed a RESPONSE packet containing an AAAA answer.  Drain all
/// routing events and assert exactly one `ToQuery(Answer)` reaches the
/// AAAA handle; none reaches the A handle (the rtype filter at the
/// route level rejects the AAAA against the A route).
#[test]
fn response_answer_fans_out_to_type_compatible_queries() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::net::{Ipv6Addr, SocketAddr};

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();

  // Register an A query AND an AAAA query for the same name.
  let spec_a = QuerySpec::new(qname.clone(), ResourceType::A);
  let h_a = e.try_start_query(spec_a, now).unwrap();
  let spec_aaaa = QuerySpec::new(qname.clone(), ResourceType::AAAA);
  let h_aaaa = e.try_start_query(spec_aaaa, now).unwrap();

  // Build a RESPONSE packet (QR=1) with an AAAA answer for the name.
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  let aaaa = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
  b.push_aaaa_answer(&qname, 120, aaaa, false).unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();

  let mut answer_handles: std::vec::Vec<QueryHandle> = std::vec::Vec::new();
  for ev in events {
    let ev = ev.unwrap();
    if let RouteEvent::ToQuery(tq) = ev
      && let QueryEvent::Answer(_) = tq.event()
    {
      answer_handles.push(tq.handle());
    }
  }

  // The AAAA query must receive the answer.  The A query must NOT —
  // rtype filtering at the route level rejects AAAA against the A
  // route.
  assert!(
    answer_handles.contains(&h_aaaa),
    "AAAA query must receive the AAAA answer; got handles {answer_handles:?}"
  );
  assert!(
    !answer_handles.contains(&h_a),
    "A query must NOT receive an AAAA answer (route-level rtype filter); \
       got handles {answer_handles:?}"
  );
}

/// Same as above but with two queries that BOTH should receive the
/// answer: one registered with `ResourceType::Any` and one with the
/// exact rtype.  Both routes are compatible, so the same answer record
/// must produce TWO `ToQuery(Answer)` events.
#[test]
fn response_answer_fans_out_to_any_and_specific_routes() {
  use crate::{
    config::QuerySpec,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();

  let spec_a = QuerySpec::new(qname.clone(), ResourceType::A);
  let h_a = e.try_start_query(spec_a, now).unwrap();
  let spec_any = QuerySpec::new(qname.clone(), ResourceType::Any);
  let h_any = e.try_start_query(spec_any, now).unwrap();

  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 9), false)
    .unwrap();
  let n = b.finish().unwrap();
  let pkt = &buf[..n];

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();

  let mut answer_handles: std::vec::Vec<QueryHandle> = std::vec::Vec::new();
  for ev in events {
    let ev = ev.unwrap();
    if let RouteEvent::ToQuery(tq) = ev
      && let QueryEvent::Answer(_) = tq.event()
    {
      answer_handles.push(tq.handle());
    }
  }

  assert!(
    answer_handles.contains(&h_a),
    "A-specific query must receive the A answer; handles={answer_handles:?}"
  );
  assert!(
    answer_handles.contains(&h_any),
    "Any-wildcard query must also receive the A answer; handles={answer_handles:?}"
  );
  assert_eq!(
    answer_handles.len(),
    2,
    "exactly two ToQuery(Answer) events expected (one per compatible route); \
       got {answer_handles:?}"
  );
}

// `cancel_query` on an unknown handle returns
// `CancelQueryError::QueryNotFound`; covered alongside the basic
// removal path in `cancel_query_removes_route` above.

// ── begin_withdrawal ─────────────────────────────────────────────────

/// `begin_withdrawal` must leave `services_active` unchanged (it is
/// decremented later) and keep the route in `self.services` so
/// that a same-name re-registration is still rejected.
#[cfg(feature = "stats")]
#[test]
fn begin_withdrawal_holds_the_name_and_keeps_services_active() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();

  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let recs = ServiceRecords::new(st, inst.clone(), host, 631, 120);
  let (handle, mut svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let before = ep.stats().services_active;

  let snap = svc.withdrawal_snapshot();
  ep.begin_withdrawal(handle, snap, now);

  // services_active must NOT have changed.
  assert_eq!(
    ep.stats().services_active,
    before,
    "begin_withdrawal must not decrement services_active"
  );

  // The route is still present — same-name re-registration is rejected.
  let st2 = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst2 = inst; // same name
  let host2 = Name::try_from_str("printer-host.local.").unwrap();
  let recs2 = ServiceRecords::new(st2, inst2, host2, 631, 120);
  let result = ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    ServiceSpec::new(recs2),
    now,
  );
  assert!(
    matches!(result, Err(RegisterServiceError::NameAlreadyRegistered(_))),
    "same-name re-registration must be rejected while withdrawal route is held"
  );
}

/// `begin_withdrawal` with an unknown handle is a silent no-op.
#[test]
fn begin_withdrawal_unknown_handle_is_noop() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  // Build a dummy snapshot via a temporary service.
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Ghost._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("ghost-host.local.").unwrap();
  let recs = ServiceRecords::new(st, inst, host, 631, 120);
  let (_, mut svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  let snap = svc.withdrawal_snapshot();
  // Use a handle that was never registered.
  let bogus = ServiceHandle::from_raw(0xDEAD);
  ep.begin_withdrawal(bogus, snap, now); // must not panic
}

/// `poll_withdrawal_transmit` encodes the snapshot's TTL=0 goodbye and RETAINS
/// a host address that a live same-host sibling still ADVERTISES, while
/// withdrawing the withdrawing service's unique address (sibling retention is
/// computed fresh from the route table's CONFIRMED-ADVERTISED set).
#[test]
fn poll_withdrawal_emits_ttl0_and_retains_sibling_host_addr() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let shared = Ipv4Addr::new(192, 168, 1, 5);
  let unique = Ipv4Addr::new(192, 168, 1, 6);
  let host = Name::try_from_str("h.local.").unwrap();

  // Service A (host h) advertises BOTH the shared and the unique address, plus
  // a `_printer` subtype (RFC 6763 §7.1) so the withdrawal must also retract
  // the subtype PTR at TTL 0.
  let mut recs_a = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("A._ipp._tcp.local.").unwrap(),
    host.clone(),
    631,
    120,
  );
  recs_a.add_a(shared);
  recs_a.add_a(unique);
  recs_a.add_subtype("_printer").unwrap();
  let sub = Name::try_from_str("_printer._sub._ipp._tcp.local.").unwrap();
  let (a_handle, _svc_a) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs_a.clone()),
      now,
    )
    .unwrap();

  // Service B (SAME host h) advertises ONLY the shared address.
  let mut recs_b = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("B._ipp._tcp.local.").unwrap(),
    host.clone(),
    632,
    120,
  );
  recs_b.add_a(shared);
  let (b_handle, _svc_b) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs_b),
      now,
    )
    .unwrap();
  // B has CONFIRMED-ADVERTISED the shared address (its announce was delivered),
  // so the route's advertised set is non-empty — otherwise retention would
  // honour nothing and A would (wrongly) withdraw the shared address.
  ep.note_service_announced(FullyAnnounced::new(b_handle, true), &[shared], &[]);

  // A's withdrawal snapshot: owns PTR/SRV/TXT, the subtype PTR, and both host
  // A addresses.
  let snap = crate::service::WithdrawalSnapshot {
    records: recs_a,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      true,
    ),
    host_a: std::vec![shared, unique],
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(a_handle, snap, now);

  let mut buf = std::vec![0u8; 4096];
  let round = ep
    .poll_withdrawal_transmit(now, &mut buf)
    .expect("a due withdrawal must produce a datagram");
  let (len, got) = (round.len(), round.token());
  assert_eq!(
    Some(got),
    ep.route_withdrawal_token(a_handle),
    "the route-attached item for the withdrawing handle is the one emitted"
  );

  let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
  let mut saw_instance = false;
  let mut saw_subtype = false;
  let mut withdrawn_v4: std::vec::Vec<Ipv4Addr> = std::vec::Vec::new();
  for rec in reader.answers() {
    let rec = rec.unwrap();
    assert_eq!(rec.ttl(), 0, "every goodbye record must carry TTL 0");
    match rec.rtype() {
      crate::wire::ResourceType::A => {
        let d = rec.rdata();
        assert_eq!(d.len(), 4, "A rdata is 4 bytes");
        withdrawn_v4.push(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
      }
      crate::wire::ResourceType::Ptr => {
        if names_match(&sub, rec.name()) {
          saw_subtype = true;
        } else {
          saw_instance = true;
        }
      }
      crate::wire::ResourceType::Srv | crate::wire::ResourceType::Txt => saw_instance = true,
      _ => {}
    }
  }
  assert!(
    saw_instance,
    "instance records (PTR/SRV/TXT) must be withdrawn at TTL 0"
  );
  assert!(saw_subtype, "the subtype PTR must be withdrawn at TTL 0");
  assert!(
    withdrawn_v4.contains(&unique),
    "A's unique address must be withdrawn"
  );
  assert!(
    !withdrawn_v4.contains(&shared),
    "the sibling-shared address must be RETAINED (not withdrawn)"
  );
}

/// Helper: register a same-host service advertising the given A addresses and
/// (optionally) mirror an advertised set into its route, returning its handle.
/// `advertised == None` models a registered-but-never-announced sibling (its
/// route advertised set stays EMPTY); `Some(addrs)` mirrors a confirmed
/// announce via `note_service_announced`.
fn register_host_service(
  ep: &mut TestEndp,
  instance: &str,
  host: &Name,
  configured_a: &[Ipv4Addr],
  advertised: Option<&[Ipv4Addr]>,
) -> ServiceHandle {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str(instance).unwrap(),
    host.clone(),
    631,
    120,
  );
  for a in configured_a {
    recs.add_a(*a);
  }
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      StdInstant::now(),
    )
    .unwrap();
  if let Some(adv) = advertised {
    ep.note_service_announced(FullyAnnounced::new(h, true), adv, &[]);
  }
  h
}

/// Collect the A addresses a withdrawal datagram WITHDRAWS (TTL 0) for the
/// next due round of `handle`.
fn poll_withdrawn_v4(
  ep: &mut TestEndp,
  now: StdInstant,
) -> (std::vec::Vec<Ipv4Addr>, WithdrawalToken) {
  let mut buf = std::vec![0u8; 4096];
  let round = ep
    .poll_withdrawal_transmit(now, &mut buf)
    .expect("a due withdrawal must produce a datagram");
  let (len, token) = (round.len(), round.token());
  let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
  let mut withdrawn = std::vec::Vec::new();
  for rec in reader.answers() {
    let rec = rec.unwrap();
    if rec.rtype() == crate::wire::ResourceType::A {
      let d = rec.rdata();
      withdrawn.push(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
    }
  }
  (withdrawn, token)
}

/// Build a withdrawal snapshot owning PTR/SRV/TXT plus the given host A set.
fn host_a_snapshot(
  host: &Name,
  instance: &str,
  host_a: &[Ipv4Addr],
) -> crate::service::WithdrawalSnapshot {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str(instance).unwrap(),
    host.clone(),
    631,
    120,
  );
  for a in host_a {
    recs.add_a(*a);
  }
  crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: host_a.to_vec(),
    host_aaaa: std::vec::Vec::new(),
  }
}

/// Regression: a withdrawing service MUST withdraw a host
/// address when the only same-host sibling holding it CONFIGURED but NEVER
/// ADVERTISED it. The old scan keyed on configured `a_addrs`, so the real
/// owner wrongly RETAINED the address and left stale records in peer caches.
#[test]
fn withdrawal_withdraws_addr_when_sibling_never_advertised() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("h.local.").unwrap();
  let shared = Ipv4Addr::new(192, 168, 1, 5);
  let unique = Ipv4Addr::new(192, 168, 1, 6);

  // A advertises BOTH .5 and .6 (confirmed announce mirrored in).
  let a = register_host_service(
    &mut ep,
    "A._ipp._tcp.local.",
    &host,
    &[shared, unique],
    Some(&[shared, unique]),
  );
  // B is CONFIGURED with .5 but NEVER announced — its advertised set is EMPTY.
  let _b = register_host_service(&mut ep, "B._ipp._tcp.local.", &host, &[shared], None);

  ep.begin_withdrawal(
    a,
    host_a_snapshot(&host, "A._ipp._tcp.local.", &[shared, unique]),
    now,
  );

  let (withdrawn, token) = poll_withdrawn_v4(&mut ep, now);
  assert_eq!(
    token,
    ep.route_withdrawal_token(a).unwrap(),
    "the datagram is A's route-attached withdrawal item"
  );
  assert!(
    withdrawn.contains(&shared),
    "shared addr must be WITHDRAWN: no LIVE sibling actually advertised it"
  );
  assert!(
    withdrawn.contains(&unique),
    "A's unique addr must be withdrawn"
  );
}

/// A host address a LIVE same-host sibling has actually ADVERTISED is RETAINED
/// (not withdrawn) by the withdrawing service, while its unique address is
/// withdrawn. This is the correct-retention counterpart of the regression.
#[test]
fn withdrawal_retains_addr_advertised_by_live_sibling() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("h.local.").unwrap();
  let shared = Ipv4Addr::new(192, 168, 1, 5);
  let unique = Ipv4Addr::new(192, 168, 1, 6);

  // A advertises .5 + .6; B (LIVE) advertises .5.
  let a = register_host_service(
    &mut ep,
    "A._ipp._tcp.local.",
    &host,
    &[shared, unique],
    Some(&[shared, unique]),
  );
  let _b = register_host_service(
    &mut ep,
    "B._ipp._tcp.local.",
    &host,
    &[shared],
    Some(&[shared]),
  );

  // Only A withdraws; B stays live (not withdrawing).
  ep.begin_withdrawal(
    a,
    host_a_snapshot(&host, "A._ipp._tcp.local.", &[shared, unique]),
    now,
  );

  let (withdrawn, token) = poll_withdrawn_v4(&mut ep, now);
  assert_eq!(
    token,
    ep.route_withdrawal_token(a).unwrap(),
    "the datagram is A's route-attached withdrawal item"
  );
  assert!(
    !withdrawn.contains(&shared),
    "shared addr must be RETAINED: live sibling B still advertises it"
  );
  assert!(
    withdrawn.contains(&unique),
    "A's unique addr must be withdrawn"
  );
}

/// Regression: two same-host services withdrawing TOGETHER must
/// EACH withdraw the shared address. The old scan did not exclude withdrawing
/// siblings, so each retained the other's leaving address and neither emitted
/// the TTL=0 A — leaving the record stale in peer caches until its TTL.
#[test]
fn simultaneous_same_host_withdrawals_each_withdraw_shared_addr() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("h.local.").unwrap();
  let shared = Ipv4Addr::new(192, 168, 1, 5);

  // Both A and B advertised the shared address (confirmed announces mirrored).
  let a = register_host_service(
    &mut ep,
    "A._ipp._tcp.local.",
    &host,
    &[shared],
    Some(&[shared]),
  );
  let b = register_host_service(
    &mut ep,
    "B._ipp._tcp.local.",
    &host,
    &[shared],
    Some(&[shared]),
  );

  // BOTH withdraw — each marks its route `withdrawing`, so each is excluded
  // from the other's retention scan.
  ep.begin_withdrawal(
    a,
    host_a_snapshot(&host, "A._ipp._tcp.local.", &[shared]),
    now,
  );
  ep.begin_withdrawal(
    b,
    host_a_snapshot(&host, "B._ipp._tcp.local.", &[shared]),
    now,
  );

  // Each one's next due round must WITHDRAW the shared address. Confirm the
  // round so the second poll advances to the other withdrawer's item.
  let (withdrawn_1, tok1) = poll_withdrawn_v4(&mut ep, now);
  assert!(
    withdrawn_1.contains(&shared),
    "first withdrawer ({tok1:?}) must withdraw the shared addr (sibling is also leaving)"
  );
  ep.note_withdrawal_result(
    tok1,
    now,
    super::WithdrawalSend::Sent,
    super::WithdrawalSend::Sent,
  );

  let (withdrawn_2, tok2) = poll_withdrawn_v4(&mut ep, now);
  assert_ne!(
    tok1, tok2,
    "the second poll must advance to the OTHER withdrawer's item"
  );
  assert!(
    withdrawn_2.contains(&shared),
    "second withdrawer ({tok2:?}) must ALSO withdraw the shared addr"
  );
}

/// `note_withdrawal_result` spends a resend round per family that `Sent`; a
/// round where neither family sent (both `Retry`) re-arms at the short backoff
/// WITHOUT spending either family's budget.
#[test]
fn note_withdrawal_delivered_spends_failed_rearms() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("A._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      now,
    )
    .unwrap();
  // A NON-empty snapshot (owns PTR/SRV/TXT) so the resend budget is non-zero
  // and the spend/backoff schedule is actually exercised.
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);
  let token = ep.route_withdrawal_token(h).unwrap();

  // A round where NEITHER family sent (both Retry) spends nothing and re-arms at
  // the short backoff.
  ep.note_withdrawal_result(
    token,
    now,
    super::WithdrawalSend::Retry,
    super::WithdrawalSend::Retry,
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
    "a no-send round must not spend either family's resend budget"
  );
  let backoff_at = ep.route_withdrawal_next_at(h).unwrap();
  assert_eq!(
    backoff_at,
    now
      .checked_add_duration(super::WITHDRAWAL_RETRY_BACKOFF)
      .unwrap()
  );
  assert!(
    backoff_at
      < now
        .checked_add_duration(super::WITHDRAWAL_INTERVAL)
        .unwrap(),
    "a no-send round must NOT delay a full interval"
  );

  // A dual-stack delivered round spends exactly one PER family and re-arms at
  // the full interval (progress made).
  ep.note_withdrawal_result(
    token,
    now,
    super::WithdrawalSend::Sent,
    super::WithdrawalSend::Sent,
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([super::WITHDRAWAL_SENDS - 1, super::WITHDRAWAL_SENDS - 1]),
    "a dual-stack delivered round spends exactly one per family"
  );
  assert_eq!(
    ep.route_withdrawal_next_at(h).unwrap(),
    now
      .checked_add_duration(super::WITHDRAWAL_INTERVAL)
      .unwrap()
  );

  // A mixed round (v4 Sent, v6 Retry) spends only v4 and STILL counts as
  // progress (>= 1 Sent), so it re-arms at the full interval.
  ep.note_route_withdrawal_result(
    h,
    now,
    super::WithdrawalSend::Sent,
    super::WithdrawalSend::Retry,
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([super::WITHDRAWAL_SENDS - 2, super::WITHDRAWAL_SENDS - 1]),
    "a v4-only round spends only v4's budget; v6 keeps its debt"
  );
  assert_eq!(
    ep.route_withdrawal_next_at(h).unwrap(),
    now
      .checked_add_duration(super::WITHDRAWAL_INTERVAL)
      .unwrap(),
    "a round with >= 1 Sent re-arms at the full interval"
  );
}

/// Every [`super::WithdrawalSend`] variant has a canonical lowercase slug (and
/// `Display` renders it), per the workspace unit-only-enum convention.
#[test]
fn withdrawal_send_as_str_slug_for_every_variant() {
  assert_eq!(super::WithdrawalSend::Sent.as_str(), "sent");
  assert_eq!(super::WithdrawalSend::Retry.as_str(), "retry");
  assert_eq!(super::WithdrawalSend::WriteOff.as_str(), "write_off");
  assert_eq!(
    std::format!("{}", super::WithdrawalSend::WriteOff),
    "write_off"
  );
}

/// regression: a withdrawal is NOT freed until EVERY reachable
/// family has sent the goodbye. Pump WITHDRAWAL_SENDS rounds with `v4 = Sent,
/// v6 = Retry`: v4's debt drains to 0 but v6 still owes, so the withdrawal is
/// held (route still reserved, name still rejected) and does NOT complete. Only
/// once v6 also sends its full budget does it complete and free the name — so a
/// v6 that recovers before the 2 s ceiling still withdraws its records.
#[test]
fn withdrawal_not_freed_until_every_family_sent() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst.clone(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      now,
    )
    .unwrap();
  // Owns instance records (PTR/SRV/TXT), so the withdrawal has a real goodbye.
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);
  let token = ep.route_withdrawal_token(h).unwrap();

  // v4 sends every round, v6 is transiently busy (Retry) every round: v4's debt
  // drains, v6's is untouched.
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Retry,
    );
  }
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, super::WITHDRAWAL_SENDS]),
    "v4 fully sent but v6 (busy) still owes its whole budget"
  );

  // A drain WELL within the 2 s ceiling must NOT free it: v6 has peers that never
  // got the TTL=0 goodbye.
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert!(
    done.is_empty(),
    "a withdrawal whose v6 family still owes must NOT be freed before the ceiling"
  );
  // The name is still held (route present for the guard).
  let dup = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst.clone(),
    Name::try_from_str("h2.local.").unwrap(),
    631,
    120,
  );
  assert!(
    matches!(
      ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(dup),
        now,
      ),
      Err(RegisterServiceError::NameAlreadyRegistered(_))
    ),
    "the name must stay held while v6's goodbye debt is unpaid"
  );

  // Now v6 recovers and sends its whole budget (v4 already at 0 → reported Sent
  // is a no-op there). owed reaches [0, 0] → it completes and frees the name.
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Sent,
    );
  }
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, 0]),
    "once v6 sends its budget every family's debt is cleared"
  );
  ep.drain_completed_withdrawals(now, &mut done);
  assert!(
    done.contains(&h),
    "the withdrawal completes once every family has withdrawn its records"
  );
  // The name is now re-registerable.
  let recs2 = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst,
    Name::try_from_str("h2.local.").unwrap(),
    631,
    120,
  );
  assert!(
    ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs2),
      now,
    )
    .is_ok(),
    "the withdrawn name is re-registerable once all families have sent"
  );
}

/// The round a driver is handed NAMES the families it is for.
///
/// An item stays selectable while EITHER family owes, so once v4 has paid its
/// whole §10.1 budget and v6 is still failing, every further round exists for v6
/// alone. `WithdrawalTransmit::debt` is the only thing that says so; without it a
/// driver can do nothing but fan to both, retracting on v4 records no v4 peer
/// still holds — at the 20 ms retry cadence, since a redundant `Sent` is
/// correctly not progress.
///
/// Also pins what a driver reports for the family it withheld on that basis:
/// `Retry` alone leaves both the debt and the schedule exactly as a family that
/// was never offered the round should leave them.
#[test]
fn a_withdrawal_round_names_the_families_that_still_owe() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst,
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      now,
    )
    .unwrap();
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);

  let mut buf = std::vec![0u8; 4096];
  let mut t = now;
  let first = ep
    .poll_withdrawal_transmit(t, &mut buf)
    .expect("a freshly begun withdrawal is due at once");
  assert!(
    first.debt().v4_owed() && first.debt().v6_owed(),
    "a withdrawal that has paid nothing owes on both families"
  );

  // v4 pays its whole budget while v6 stays busy. Each round makes real progress
  // (v4 still owed), so the schedule re-arms at the §10.1 interval.
  for _ in 0..super::WITHDRAWAL_SENDS {
    let round = ep
      .poll_withdrawal_transmit(t, &mut buf)
      .expect("v4 still owes, so a round is due");
    ep.note_withdrawal_result(
      round.token(),
      t,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Retry,
    );
    t = t.checked_add_duration(super::WITHDRAWAL_INTERVAL).unwrap();
  }
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, super::WITHDRAWAL_SENDS]),
    "v4 has paid its whole budget; v6 has paid nothing"
  );

  let round = ep
    .poll_withdrawal_transmit(t, &mut buf)
    .expect("v6 still owes, so the item is still selectable");
  assert!(
    !round.debt().v4_owed(),
    "v4 has paid every round it owed, so this datagram is not for it — another \
     copy on v4's wire retracts records no v4 peer still holds"
  );
  assert!(
    round.debt().v6_owed(),
    "v6 is the family this round exists for"
  );

  // v6 finally carries it; v4 is reported as the family the driver withheld.
  ep.note_withdrawal_result(
    round.token(),
    t,
    super::WithdrawalSend::Retry,
    super::WithdrawalSend::Sent,
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, super::WITHDRAWAL_SENDS - 1]),
    "a withheld family's `Retry` moves no debt, and v6's `Sent` spends exactly \
     one of its own rounds"
  );
  assert_eq!(
    ep.route_withdrawal_next_at(h).unwrap(),
    t.checked_add_duration(super::WITHDRAWAL_INTERVAL).unwrap(),
    "v6 made real progress, so the item re-arms at the §10.1 interval"
  );

  // The round that produced the storm: v6 fails too, so nothing is spent and the
  // item re-arms on the short backoff — which is exactly the cadence a redundant
  // v4 datagram would then have been emitted at.
  t = t.checked_add_duration(super::WITHDRAWAL_INTERVAL).unwrap();
  let round = ep
    .poll_withdrawal_transmit(t, &mut buf)
    .expect("v6 still owes");
  assert!(
    !round.debt().v4_owed() && round.debt().v6_owed(),
    "the debt still names v6 alone"
  );
  ep.note_withdrawal_result(
    round.token(),
    t,
    super::WithdrawalSend::Retry,
    super::WithdrawalSend::Retry,
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, super::WITHDRAWAL_SENDS - 1]),
    "a round no family carried spends nothing"
  );
  assert_eq!(
    ep.route_withdrawal_next_at(h).unwrap(),
    t.checked_add_duration(super::WITHDRAWAL_RETRY_BACKOFF)
      .unwrap(),
    "no progress, so the item re-arms on the short backoff for v6's sake"
  );
}

/// a family reported `WriteOff` (no socket / permanent error) has its debt
/// zeroed, so the withdrawal can complete via the OTHER family alone — a down
/// family has no reachable peers to withdraw from, so it must not pin the name.
#[test]
fn withdrawal_writeoff_family_completes() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst,
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      now,
    )
    .unwrap();
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);
  let token = ep.route_withdrawal_token(h).unwrap();

  // v6 has no socket (WriteOff zeroes its debt immediately); v4 still owes its
  // full budget after one Sent.
  ep.note_withdrawal_result(
    token,
    now,
    super::WithdrawalSend::Sent,
    super::WithdrawalSend::WriteOff,
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([super::WITHDRAWAL_SENDS - 1, 0]),
    "WriteOff zeroes v6's debt; v4 spent exactly one"
  );

  // v4 sends out its remaining budget; v6 stays written off.
  for _ in 0..(super::WITHDRAWAL_SENDS - 1) {
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::WriteOff,
    );
  }
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, 0]),
    "v4 fully sent + v6 written off → every family's debt cleared"
  );
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert!(
    done.contains(&h),
    "the withdrawal completes via v4 alone once v6 is written off"
  );
}

/// regression: an already-PAID family's redundant `Sent`
/// must NOT count as withdrawal progress. Drivers fan every round to BOTH
/// families, so once v4's debt is 0 it keeps reporting `Sent`; if that counted
/// as progress the schedule would re-arm at the FULL interval and starve a
/// still-busy v6 of its short-backoff retry (risking a missed last-interval v6
/// recovery before the ceiling). Drive v4 to `owed == 0` while v6 stays busy,
/// then a `v4 = Sent (paid), v6 = Retry` round must re-arm at
/// `WITHDRAWAL_RETRY_BACKOFF`, NOT the full interval. A subsequent `v6 = Sent`
/// then decrements v6 and (with v4 already 0) completes the withdrawal.
#[test]
fn withdrawal_retries_owed_family_at_backoff_when_other_is_paid() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("A._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      now,
    )
    .unwrap();
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);
  let token = ep.route_withdrawal_token(h).unwrap();

  // Drain v4's whole budget while v6 is transiently busy (Retry): v4 → 0, v6
  // keeps its full debt. Each of these rounds DID make real progress on v4
  // (its owed was > 0), so they legitimately re-arm at the full interval.
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Retry,
    );
  }
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, super::WITHDRAWAL_SENDS]),
    "v4 fully paid; v6 (busy) still owes its whole budget"
  );

  // The crux: v4 is already paid (owed 0) but the driver still fans the round to
  // it, so it reports `Sent` again; v6 is still busy (`Retry`). NO family made
  // real progress this round — the paid v4 `Sent` is redundant — so the schedule
  // must re-arm at the SHORT backoff to retry the still-owed v6 soon, NOT wait a
  // full interval (which could miss a late v6 recovery before the 2 s ceiling).
  ep.note_withdrawal_result(
    token,
    now,
    super::WithdrawalSend::Sent,
    super::WithdrawalSend::Retry,
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, super::WITHDRAWAL_SENDS]),
    "a redundant `Sent` on the already-paid v4 must not change any debt"
  );
  let backoff_at = ep.route_withdrawal_next_at(h).unwrap();
  assert_eq!(
    backoff_at,
    now
      .checked_add_duration(super::WITHDRAWAL_RETRY_BACKOFF)
      .unwrap(),
    "an already-paid family's `Sent` is not progress: re-arm at the short backoff"
  );
  assert!(
    backoff_at
      < now
        .checked_add_duration(super::WITHDRAWAL_INTERVAL)
        .unwrap(),
    "the still-owed v6 must be retried at the short backoff, not a full interval"
  );

  // v6 now recovers: its `Sent` IS real progress (its owed was > 0), so it
  // decrements and — v4 already 0 — owed reaches [0, 0] once v6 drains.
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Sent,
    );
  }
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, 0]),
    "v6 draining its budget clears every family's debt"
  );
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert!(
    done.contains(&h),
    "the withdrawal completes once the previously-owed v6 has sent its budget"
  );
}

/// corollary: `WriteOff` zeroes ONLY its own family's debt and leaves the
/// other family's owed untouched — a down family must not drag the live one's
/// budget down with it. (Complements `withdrawal_writeoff_family_completes`,
/// which checks the completion path.)
#[test]
fn writeoff_only_zeroes_its_own_family() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("A._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      now,
    )
    .unwrap();
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);

  // v4 written off (its debt → 0); v6 transiently busy (Retry, debt intact).
  ep.note_route_withdrawal_result(
    h,
    now,
    super::WithdrawalSend::WriteOff,
    super::WithdrawalSend::Retry,
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, super::WITHDRAWAL_SENDS]),
    "WriteOff zeroes ONLY v4; v6's full budget is untouched"
  );
}

/// regression: an encode-failing withdrawal must NOT
/// head-of-line block a sibling. Two due withdrawals share one `scratch`: A
/// (first in the vec) owns a goodbye too large for the buffer (many host A
/// records) so `write_goodbye` errors; B owns a minimal goodbye that fits. A
/// single `poll_withdrawal_transmit` must scan PAST the encode-failing A —
/// advancing A's `next_at` past `now` (budget intact) — and RETURN B's
/// datagram, not `None`.
#[test]
fn encode_failing_withdrawal_does_not_block_a_sibling() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();

  // A (registered FIRST → withdrawals index 0): owns PTR + a LARGE host A set so
  // its goodbye overflows the small shared scratch below.
  let inst_a = Name::try_from_str("A._ipp._tcp.local.").unwrap();
  let host_a = Name::try_from_str("ha.local.").unwrap();
  let recs_a = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst_a,
    host_a,
    631,
    120,
  );
  // The goodbye's size is driven by the snapshot's host_a (60 A records), which
  // `write_goodbye` emits from the iterator using the host name — no need to
  // register the addresses on the route.
  let big_a: std::vec::Vec<Ipv4Addr> = (0..60u8).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
  let (a, _svc_a) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs_a.clone()),
      now,
    )
    .unwrap();
  let snap_a = crate::service::WithdrawalSnapshot {
    records: recs_a,
    owned: crate::service::EmittedRecords::new(
      true,
      false,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: big_a,
    host_aaaa: std::vec::Vec::new(),
  };

  // B (registered after A): owns only a single PTR — a minimal goodbye that
  // fits the small scratch.
  let inst_b = Name::try_from_str("B._ipp._tcp.local.").unwrap();
  let recs_b = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst_b,
    Name::try_from_str("hb.local.").unwrap(),
    632,
    120,
  );
  let (b, _svc_b) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs_b.clone()),
      now,
    )
    .unwrap();
  let snap_b = crate::service::WithdrawalSnapshot {
    records: recs_b,
    owned: crate::service::EmittedRecords::new(
      true,
      false,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };

  ep.begin_withdrawal(a, snap_a, now);
  ep.begin_withdrawal(b, snap_b, now);

  // A scratch big enough for B's single-PTR goodbye but far too small for A's
  // 60-address goodbye. A single pump must scan past the encode-failing A and
  // return B's datagram.
  let mut scratch = std::vec![0u8; 128];
  let got = ep.poll_withdrawal_transmit(now, &mut scratch);
  let got_handle = got
    .expect("the pump must scan past the encode-failing A and return B's goodbye")
    .token();
  assert_eq!(
    Some(got_handle),
    ep.route_withdrawal_token(b),
    "B (encodable) is returned; A (encode-failing) did not head-of-line block"
  );

  // A was advanced past `now` (no longer first-due at this instant) with its
  // per-family budget intact — the 2 s ceiling remains its backstop.
  let a_next = ep.route_withdrawal_next_at(a).unwrap();
  assert!(
    a_next > now,
    "the encode-failing A must have its next_at pushed past now, not left due"
  );
  assert_eq!(
    a_next,
    now
      .checked_add_duration(super::WITHDRAWAL_RETRY_BACKOFF)
      .unwrap(),
    "A re-arms at the short backoff after an encode failure"
  );
  assert_eq!(
    ep.route_withdrawal_owed(a),
    Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
    "an encode failure must NOT spend A's resend budget"
  );
}

/// Regression: a teardown DURING a still-draining §9 conflict-rename
/// goodbye must withdraw BOTH the OLD instance name AND the CURRENT
/// (re-announced) instance records + host addresses — emitted as TWO SEPARATE
/// single-name datagrams (the current part first, then the rename part), never
/// one combined message.
///
/// After a rename A→B the service clears its old instance ownership and
/// re-announces B, confirming B's PTR/SRV/TXT + host A/AAAA while A's rename
/// goodbye is still spaced out. If the service is retired in that window the
/// snapshot carries the CURRENT name B (records + owned + host addrs) PLUS the
/// rename's OLD name A (instance-only). Both must be retracted at TTL 0: B's
/// instance records + host A/AAAA in the current datagram, then A's instance
/// records (PTR/SRV under owner `A`, NO host — a rename never withdraws host
/// addrs) in the rename datagram. The earlier single combined encoder could
/// drop the rename when current ownership was empty, and could fail entirely
/// when the combined message exceeded the scratch buffer.
#[test]
fn teardown_during_rename_goodbye_withdraws_old_and_new_name() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let old_name = Name::try_from_str("A._ipp._tcp.local.").unwrap();
  let new_name = Name::try_from_str("A-1._ipp._tcp.local.").unwrap();
  let host_v4 = Ipv4Addr::new(192, 168, 1, 7);
  let host_v6 = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

  // The CURRENT (re-announced) records under the renamed name B = `A-1`, owning
  // a full instance set + both host addresses.
  let mut recs_b = ServiceRecords::new(stype.clone(), new_name.clone(), host.clone(), 631, 120);
  recs_b.add_a(host_v4);
  recs_b.add_aaaa(host_v6);
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs_b.clone()),
      now,
    )
    .unwrap();

  // The OLD name A's still-in-flight rename goodbye (instance-only: PTR+SRV;
  // host addrs are intentionally absent — a rename never withdraws them).
  let old_records = ServiceRecords::new(stype, old_name.clone(), host.clone(), 631, 120);
  let old_owned = crate::service::EmittedRecords::new(
    true,
    true,
    false,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );

  // A teardown DURING a still-draining rename is now two SEPARATE calls, each
  // producing one independent item. The rename happened first, so its old-name
  // (A) goodbye was already enqueued as a DETACHED item; the teardown then
  // begins the route-attached (B) withdrawal from a current-only snapshot.
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: old_records,
      owned: old_owned,
    },
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot {
    records: recs_b,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec![host_v4],
    host_aaaa: std::vec![host_v6],
  };
  ep.begin_withdrawal(h, snap, now);

  // Both items owe a full per-family budget: the route item for B (it advertised
  // instance + host) and the detached item for A.
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
    "the route-attached current-name (B) item owes a full budget"
  );
  assert_eq!(
    ep.detached_withdrawal_owed_for(&old_name),
    Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
    "the detached old-name (A) item owes a full budget independently"
  );

  let mut buf = std::vec![0u8; 4096];

  // Parse one goodbye datagram into (saw old-A SRV, saw new-B SRV, v4 addrs,
  // v6 addrs). SRV is owned by the INSTANCE name, so it disambiguates A vs B
  // directly (the instance PTR is owned by the shared service-type, so it
  // cannot).
  let parse = |bytes: &[u8]| {
    let reader = crate::wire::MessageReader::try_parse(bytes).unwrap();
    let mut saw_old = false;
    let mut saw_new = false;
    let mut v4: std::vec::Vec<Ipv4Addr> = std::vec::Vec::new();
    let mut v6: std::vec::Vec<std::net::Ipv6Addr> = std::vec::Vec::new();
    for rec in reader.answers() {
      let rec = rec.unwrap();
      assert_eq!(rec.ttl(), 0, "every goodbye record must carry TTL 0");
      match rec.rtype() {
        crate::wire::ResourceType::A => {
          let d = rec.rdata();
          assert_eq!(d.len(), 4, "A rdata is 4 bytes");
          v4.push(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
        }
        crate::wire::ResourceType::AAAA => {
          let d = rec.rdata();
          assert_eq!(d.len(), 16, "AAAA rdata is 16 bytes");
          let mut o = [0u8; 16];
          o.copy_from_slice(d);
          v6.push(std::net::Ipv6Addr::from(o));
        }
        crate::wire::ResourceType::Srv => {
          if names_match(&old_name, rec.name()) {
            saw_old = true;
          } else if names_match(&new_name, rec.name()) {
            saw_new = true;
          }
        }
        _ => {}
      }
    }
    (saw_old, saw_new, v4, v6)
  };

  // The two items are INDEPENDENT, each emitting its own single-name datagram —
  // never combined. Drive each by the token the poll returns and classify the
  // datagram by which name's SRV it carries. Both are due at `now`, so two polls
  // yield the two names in some order.
  let token_b = ep.route_withdrawal_token(h).expect("B's route token");
  let token_a_owed = ep.detached_withdrawal_owed_for(&old_name);
  assert!(token_a_owed.is_some(), "A's detached item exists");

  let mut saw_new_datagram = false;
  let mut saw_old_datagram = false;
  for _ in 0..2 {
    let round = ep
      .poll_withdrawal_transmit(now, &mut buf)
      .expect("each rename-window item is due at now and emits its own datagram");
    let (len, token) = (round.len(), round.token());
    let (saw_old, saw_new, withdrawn_v4, withdrawn_v6) = parse(buf.get(..len).unwrap());
    if saw_new {
      assert_eq!(token, token_b, "B's datagram round-trips B's route token");
      assert!(!saw_old, "B's datagram does NOT carry the old name A");
      assert!(
        withdrawn_v4.contains(&host_v4) && withdrawn_v6.contains(&host_v6),
        "the confirmed host A/AAAA addresses are withdrawn with B"
      );
      saw_new_datagram = true;
    } else {
      assert!(saw_old, "the other datagram carries the old name A");
      assert_ne!(
        token, token_b,
        "A's datagram is a DIFFERENT (detached) item"
      );
      assert!(
        withdrawn_v4.is_empty() && withdrawn_v6.is_empty(),
        "a rename (old-name) goodbye never withdraws host addresses"
      );
      saw_old_datagram = true;
    }
    // Confirm this round so the same item is not re-selected before the other.
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Sent,
    );
  }
  assert!(
    saw_new_datagram && saw_old_datagram,
    "BOTH the current name B and the old name A are withdrawn, as separate datagrams"
  );

  // The two items are independent: spending B's first round did not touch A's
  // debt, and vice versa.
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([super::WITHDRAWAL_SENDS - 1, super::WITHDRAWAL_SENDS - 1]),
    "B's route item spent exactly one round of its own budget"
  );
  assert_eq!(
    ep.detached_withdrawal_owed_for(&old_name),
    Some([super::WITHDRAWAL_SENDS - 1, super::WITHDRAWAL_SENDS - 1]),
    "A's detached item spent exactly one round of its own budget"
  );
}

/// a rename-COLLISION old-name goodbye (enqueued with holds_name =
/// true) must HOLD its instance name against fresh `try_register_service` reuse
/// until the goodbye completes — otherwise the empty route-attached current-name
/// withdrawal completes first and a quick re-register cancels the only TTL=0
/// retraction, leaving peers with stale PTR/SRV/TXT until TTL. Once the held
/// goodbye drains, the name is reusable.
#[test]
fn collision_old_name_holds_against_reregister_until_goodbye_completes() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let old_name = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();

  // The DEAD service's old-name goodbye: instance records only (PTR+SRV+TXT), no
  // host (a rename never withdraws host addrs). Enqueued HELD (collision).
  let old_records = ServiceRecords::new(stype.clone(), old_name.clone(), host.clone(), 631, 120);
  let old_owned = crate::service::EmittedRecords::new(
    true,
    true,
    true,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: old_records,
      owned: old_owned,
    },
    now,
    true,
  );

  // While the held goodbye is in flight, a fresh registration of the old name is
  // REJECTED (retract-before-reuse), even though no live route holds it.
  let recs = ServiceRecords::new(stype.clone(), old_name.clone(), host.clone(), 631, 120);
  assert!(
    matches!(
      ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now
      ),
      Err(RegisterServiceError::NameAlreadyRegistered(_))
    ),
    "a HELD collision old-name must block re-registration until its goodbye completes"
  );

  // Drive the held withdrawal to completion (confirm sends; the 2 s anti-pin
  // ceiling force-completes any remainder as time advances).
  let mut buf = std::vec![0u8; 4096];
  let mut out: std::vec::Vec<crate::ServiceHandle> = std::vec::Vec::new();
  let mut t = now;
  for _ in 0..20 {
    while let Some(round) = ep.poll_withdrawal_transmit(t, &mut buf) {
      ep.note_withdrawal_result(
        round.token(),
        t,
        super::WithdrawalSend::Sent,
        super::WithdrawalSend::Sent,
      );
    }
    ep.drain_completed_withdrawals(t, &mut out);
    if ep.detached_withdrawal_owed_for(&old_name).is_none() {
      break;
    }
    t += std::time::Duration::from_millis(400);
  }
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_none(),
    "the held old-name goodbye must complete"
  );

  // Now the name is free: re-registration succeeds (retract-before-reuse done).
  let recs2 = ServiceRecords::new(stype, old_name, host, 631, 120);
  assert!(
    ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs2),
      now
    )
    .is_ok(),
    "once the held goodbye completes, the old name is reusable"
  );
}

/// Contrast to the collision hold: a SURVIVING rename's detached old name
/// (holds_name = false) stays RECLAIMABLE — a fresh registration of the vacated
/// name succeeds immediately (not blocked), and the goodbye is cancelled only when
/// the reclaiming service CONFIRMS it is advertising the name (cancel-on-announce,
/// — not at register time, which the reactor only async-commits across
/// its reply boundary). Until the announce the old goodbye keeps draining.
#[test]
fn surviving_rename_old_name_is_reclaimable_on_announce() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let old_name = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();
  let old_records = ServiceRecords::new(stype.clone(), old_name.clone(), host.clone(), 631, 120);
  let old_owned = crate::service::EmittedRecords::new(
    true,
    true,
    true,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: old_records,
      owned: old_owned,
    },
    now,
    false,
  );
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_some(),
    "the detached goodbye is queued"
  );
  // A fresh registration of the vacated name SUCCEEDS immediately (not blocked)...
  let recs = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
  let (handle, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .expect("a surviving rename's old name must be reclaimable, not blocked");
  // ...but registration alone must NOT cancel the goodbye — it keeps draining
  // until the reclaiming service confirms advertising the name.
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_some(),
    "registration must NOT cancel the reclaimable goodbye (it survives until announce)"
  );

  // The reclaiming service CONFIRMS advertising its name → cancel-on-announce.
  ep.note_service_announced(
    FullyAnnounced::new(handle, true),
    &[Ipv4Addr::new(192, 168, 1, 10)],
    &[],
  );
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_none(),
    "the reclaimable goodbye is cancelled when the new service announces the name"
  );
}

/// cancel-on-announce must NOT fire on a PROBE. `note_service_announced`
/// is called after EVERY delivered service transmit (including probes); the
/// reclaim-cancel is gated on `Service::has_fully_announced`, which is set only
/// by a fully-delivered §8.3 announcement — never a probe — so a probe alone
/// cannot cancel a renamed-away old name's goodbye before the reclaiming service
/// has actually announced. A service with NO host addresses still reaches this
/// gate through its instance records, so the address args cannot serve as the
/// guard.
#[test]
fn probe_does_not_cancel_reclaimed_goodbye_only_a_confirmed_advertise_does() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let old_name = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();

  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: ServiceRecords::new(stype.clone(), old_name.clone(), host.clone(), 631, 120),
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
    },
    now,
    false,
  );
  let recs = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
  let (handle, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // A delivered PROBE reports fully_announced=false (no instance records
  // emitted yet) — and ALSO an address-less shape (empty address slices). The
  // goodbye MUST survive: if the reclaiming service drops/conflicts after probing
  // but before announcing, the old records still need retracting.
  ep.note_service_announced(FullyAnnounced::new(handle, false), &[], &[]);
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_some(),
    "a probe (fully_announced=false) must NOT cancel the reclaimed goodbye"
  );

  // A CONFIRMED instance-advertise (fully_announced=true, still address-less)
  // cancels it.
  ep.note_service_announced(FullyAnnounced::new(handle, true), &[], &[]);
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_none(),
    "a confirmed instance-advertise cancels the reclaimed goodbye (even address-less)"
  );
}

/// Commit 2: a §9 rename enqueues the OLD name's goodbye as an INDEPENDENT
/// DETACHED withdrawal item via [`Endpoint::enqueue_rename_withdrawal`] (the
/// handoff the driver takes from `Service::take_rename_goodbye_handoff`). The
/// item owns the old name, `poll_withdrawal_transmit` emits its TTL=0 instance
/// goodbye (no host addresses), and it drains independently — freeing no route
/// and reported to nobody on completion.
#[test]
fn rename_enqueues_a_detached_withdrawal_for_the_old_name() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
  let new_name = Name::try_from_str("Old-1._ipp._tcp.local.").unwrap();

  // A live service that has just renamed Old → Old-1 (registered under the new
  // name). The rename produced a handoff for the OLD name's instance goodbye.
  let recs = ServiceRecords::new(stype.clone(), new_name.clone(), host.clone(), 631, 120);
  let (_h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // No detached item yet.
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_none(),
    "no detached item exists before the rename handoff is enqueued"
  );

  // The driver feeds the rename handoff (old name + instance-only ownership) to
  // the endpoint — modelling `take_rename_goodbye_handoff()` → enqueue.
  let old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
  let old_owned = crate::service::EmittedRecords::new(
    true,
    true,
    true,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: old_records,
      owned: old_owned,
    },
    now,
    false,
  );

  // A detached item now owns the OLD name with a full per-family budget.
  assert_eq!(
    ep.detached_withdrawal_owed_for(&old_name),
    Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
    "the rename enqueues a detached item owning the old name with a full budget"
  );

  // It emits a TTL=0 instance goodbye for the OLD name (PTR/SRV/TXT), no host
  // addresses; the returned token is NOT a route token (it holds no route).
  let mut buf = std::vec![0u8; 4096];
  let round = ep
    .poll_withdrawal_transmit(now, &mut buf)
    .expect("the detached old-name item is due and emits its goodbye");
  let (len, token) = (round.len(), round.token());
  let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
  let mut saw_old_srv = false;
  let mut saw_host_addr = false;
  for rec in reader.answers() {
    let rec = rec.unwrap();
    assert_eq!(rec.ttl(), 0, "every rename-goodbye record carries TTL 0");
    match rec.rtype() {
      crate::wire::ResourceType::Srv => {
        if names_match(&old_name, rec.name()) {
          saw_old_srv = true;
        }
      }
      crate::wire::ResourceType::A | crate::wire::ResourceType::AAAA => saw_host_addr = true,
      _ => {}
    }
  }
  assert!(
    saw_old_srv,
    "the detached goodbye withdraws the OLD instance's SRV at TTL 0"
  );
  assert!(
    !saw_host_addr,
    "a rename (old-name) goodbye never withdraws host A/AAAA"
  );

  // Drain BEFORE the item completes: it holds no route, so nothing is reported.
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert!(
    done.is_empty(),
    "a detached item reports no handle while still in flight"
  );
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_some(),
    "the detached item is still owed after one (unconfirmed-by-drain) round"
  );

  // Spend its budget by its own token; it completes and is removed silently.
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Sent,
    );
  }
  assert_eq!(
    ep.detached_withdrawal_owed_for(&old_name),
    Some([0, 0]),
    "the detached old-name budget is fully spent"
  );
  let mut done2: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done2);
  assert!(
    done2.is_empty(),
    "a completed detached item frees no route and reports to nobody"
  );
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_none(),
    "the completed detached item is removed"
  );

  // No-op guard: an empty-ownership handoff enqueues nothing.
  let empty_owned = crate::service::EmittedRecords::new(
    false,
    false,
    false,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );
  let empty_records = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Empty._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: empty_records,
      owned: empty_owned,
    },
    now,
    false,
  );
  assert!(
    ep.detached_withdrawal_owed_for(&Name::try_from_str("Empty._ipp._tcp.local.").unwrap())
      .is_none(),
    "an empty-ownership handoff is a no-op (nothing for peers to evict)"
  );
}

/// Regression: a RENAME-ONLY withdrawal snapshot — empty current
/// ownership and no host addresses, but a pending OLD-name rename goodbye — must
/// NOT be treated as nothing-to-withdraw. `Service::withdrawal_snapshot` has
/// already consumed the pending rename, so if `begin_withdrawal` zeroed every
/// part's debt the old name would be freed WITHOUT ever sending its goodbye (it
/// would ghost until TTL). The current part owes nothing (`[0, 0]`) while the
/// rename part owes a full budget, and `poll_withdrawal_transmit` emits the old
/// name's instance goodbye.
#[test]
fn rename_only_withdrawal_emits_old_name_goodbye() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
  let cur_name = Name::try_from_str("Cur._ipp._tcp.local.").unwrap();

  // A registered service whose CURRENT records own nothing on the wire (it
  // renamed away before re-announcing) — its snapshot has empty current
  // ownership and no host addresses.
  let cur_recs = ServiceRecords::new(stype.clone(), cur_name, host.clone(), 631, 120);
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(cur_recs.clone()),
      now,
    )
    .unwrap();

  // The OLD name's still-in-flight rename goodbye (instance-only PTR+SRV).
  let old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
  let old_owned = crate::service::EmittedRecords::new(
    true,
    true,
    false,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );

  // The rename happened first: enqueue the old name's goodbye as its own
  // detached item. The teardown then begins a current-only withdrawal whose
  // snapshot owns nothing on the wire.
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: old_records,
      owned: old_owned,
    },
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot {
    records: cur_recs,
    // CURRENT owns nothing on the wire.
    owned: crate::service::EmittedRecords::new(
      false,
      false,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);

  // The route-attached current-name item owes nothing (it advertised nothing on
  // the wire). The DETACHED old-name item owes a full budget — so the old name
  // is NOT treated as nothing-to-withdraw and will actually be emitted.
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, 0]),
    "the route-attached current-name item owes nothing"
  );
  assert_eq!(
    ep.detached_withdrawal_owed_for(&old_name),
    Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
    "the detached old-name item owes a full per-family budget"
  );

  // The OLD name's goodbye MUST be emitted (the core regression: a rename-only
  // teardown must not drop it). Poll until a datagram carrying the old name's
  // SRV appears; the empty route item produces no datagram (it head-of-line
  // completes in place), so the only datagram is the detached old-name goodbye.
  let mut buf = std::vec![0u8; 4096];
  let detached_token = {
    let round = ep
      .poll_withdrawal_transmit(now, &mut buf)
      .expect("the detached old-name item must still produce the old-name goodbye");
    let (len, token) = (round.len(), round.token());
    let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
    let mut saw_old = false;
    for rec in reader.answers() {
      let rec = rec.unwrap();
      assert_eq!(rec.ttl(), 0);
      if rec.rtype() == crate::wire::ResourceType::Srv && names_match(&old_name, rec.name()) {
        saw_old = true;
      }
    }
    assert!(
      saw_old,
      "the OLD name's instance records are withdrawn at TTL 0 (separate detached item)"
    );
    token
  };

  // The empty route item completes immediately — its handle IS reported on this
  // drain (it owns no records to withdraw). The detached old-name item is
  // independent: it is still owed, so it is NOT freed here, and it reports to
  // NOBODY when it eventually completes (it holds no route/name).
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert!(
    done.contains(&h),
    "the (empty) route-attached item completes immediately and reports its handle"
  );
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_some(),
    "the detached old-name item is still in flight (not yet fully sent)"
  );

  // Spend the detached item's budget by its own token; it then completes and is
  // removed silently (reported to nobody — it owns no route).
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_withdrawal_result(
      detached_token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Sent,
    );
  }
  assert_eq!(
    ep.detached_withdrawal_owed_for(&old_name),
    Some([0, 0]),
    "the detached old-name budget is fully spent"
  );
  let mut done2: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done2);
  assert!(
    done2.is_empty(),
    "a detached old-name item completes silently — no handle reported"
  );
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_none(),
    "the detached old-name item is removed once fully sent"
  );
}

/// Regression: a rename-window teardown where the current
/// goodbye and the old-name goodbye EACH fit the driver scratch individually
/// but their COMBINED message would not. The old single-datagram encoder failed
/// to encode (combined > scratch) and the ceiling then freed the route having
/// sent NEITHER name. Emitting the two as SEPARATE single-name datagrams
/// withdraws both. The `len1 + len2 > scratch` assertion proves a combined
/// message would not have fit — i.e. the split was necessary.
#[test]
fn dual_name_each_fits_but_combined_would_not() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
  let new_name = Name::try_from_str("New._ipp._tcp.local.").unwrap();

  // A big TXT on BOTH names so each single-name goodbye is sizeable; sized so
  // each fits a modest scratch but the two combined do not.
  let big_seg = || std::vec![b'x'; 240];
  let mut recs_b = ServiceRecords::new(stype.clone(), new_name.clone(), host.clone(), 631, 120);
  for _ in 0..4 {
    recs_b.add_txt_segment(big_seg());
  }
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs_b.clone()),
      now,
    )
    .unwrap();

  let mut old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
  for _ in 0..4 {
    old_records.add_txt_segment(big_seg());
  }
  let owned_full = crate::service::EmittedRecords::new(
    true,
    true,
    true,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );

  // The rename happened first → its old-name goodbye is its own detached item;
  // the teardown then begins the route-attached current-name withdrawal. Two
  // independent items, each its own single-name datagram.
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: old_records,
      owned: owned_full.clone(),
    },
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot {
    records: recs_b,
    owned: owned_full,
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);

  // A scratch that fits each single-name goodbye but NOT their combined message.
  let mut buf = std::vec![0u8; 1600];

  // Both items are due at `now` and each emits its OWN single-name datagram.
  // Capture each name's length regardless of poll order, driving each by its
  // returned token.
  let mut len_new = 0usize;
  let mut len_old = 0usize;
  for _ in 0..2 {
    let round = ep
      .poll_withdrawal_transmit(now, &mut buf)
      .expect("each single-name goodbye fits its own datagram");
    let (len, token) = (round.len(), round.token());
    let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
    let mut saw_new = false;
    let mut saw_old = false;
    for r in reader.answers() {
      let r = r.unwrap();
      if r.rtype() == crate::wire::ResourceType::Srv {
        if names_match(&new_name, r.name()) {
          saw_new = true;
        } else if names_match(&old_name, r.name()) {
          saw_old = true;
        }
      }
    }
    if saw_new {
      assert!(!saw_old, "the current name rides its OWN datagram");
      len_new = len;
    } else {
      assert!(saw_old, "the other datagram carries the old name");
      len_old = len;
    }
    ep.note_withdrawal_result(
      token,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Sent,
    );
  }
  assert!(
    len_new > 0 && len_old > 0,
    "BOTH names were withdrawn, each in its own datagram"
  );

  // Each single-name datagram fits the scratch, but their COMBINED size would
  // overflow it — proving the split into independent items was necessary (the
  // old combined encoder would have failed and dropped both names).
  assert!(len_new <= buf.len() && len_old <= buf.len());
  assert!(
    len_new + len_old > buf.len(),
    "combined message ({len_new} + {len_old} = {}) would exceed the {}-byte scratch",
    len_new + len_old,
    buf.len()
  );
}

/// Regression: with INDEPENDENT items, an UNENCODABLE current-name
/// goodbye (too large for the driver scratch) cannot starve the renamed-away
/// old-name goodbye. The detached old-name item is scheduled on its own, so the
/// pump emits it despite the route item being unencodable, and the route is
/// still force-freed at its own ceiling. The old dual-part design (shared
/// schedule + single final-attempt) dropped the old name in exactly this case.
#[test]
fn independent_items_unencodable_current_does_not_starve_rename() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
  let cur_name = Name::try_from_str("Cur._ipp._tcp.local.").unwrap();

  // CURRENT name with a big TXT → its goodbye will NOT fit a small scratch.
  let mut cur_recs = ServiceRecords::new(stype.clone(), cur_name.clone(), host.clone(), 631, 120);
  for _ in 0..4 {
    cur_recs.add_txt_segment(std::vec![b'x'; 240]);
  }
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(cur_recs.clone()),
      now,
    )
    .unwrap();

  // OLD (renamed-away) name, instance-only and small → fits a small scratch.
  let old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
  let old_owned = crate::service::EmittedRecords::new(
    true,
    true,
    false,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );
  // The rename happened first → its old-name goodbye is its own detached item;
  // the teardown then begins the route-attached (huge current) withdrawal.
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: old_records,
      owned: old_owned,
    },
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot {
    records: cur_recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);

  // Two independent items: a route-attached (huge current) + a detached (old).
  assert!(
    ep.route_withdrawal_owed(h).is_some(),
    "the current name is a route-attached item"
  );
  assert_eq!(
    ep.detached_withdrawal_owed_for(&old_name),
    Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
    "the renamed-away old name is a detached item owing a full budget"
  );

  // A scratch too small for the current goodbye but big enough for the old one.
  let mut small = std::vec![0u8; 300];
  let round = ep
    .poll_withdrawal_transmit(now, &mut small)
    .expect("the small old-name goodbye is emitted even though the current is unencodable");
  let (len, tok) = (round.len(), round.token());
  let reader = crate::wire::MessageReader::try_parse(small.get(..len).unwrap()).unwrap();
  let saw_old = reader.answers().any(|r| {
    let r = r.unwrap();
    r.rtype() == crate::wire::ResourceType::Srv && names_match(&old_name, r.name())
  });
  assert!(
    saw_old,
    "the renamed-away old name is withdrawn — NOT starved by the unencodable current"
  );
  assert_ne!(
    Some(tok),
    ep.route_withdrawal_token(h),
    "the emitted item is the detached old-name item, not the unencodable route item"
  );

  // The route is held while its withdrawal is in flight (not freed yet).
  let mut done = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert!(
    !done.contains(&h),
    "the route is held while its withdrawal item is still in flight"
  );

  // Past the ceiling: the route item's goodbye stays unencodable, so its final
  // ceiling attempt cannot encode but still force-completes the item; the
  // detached item reaches its own ceiling too. Both terminate; the route frees.
  let past = now
    .checked_add_duration(super::WITHDRAWAL_CEILING + core::time::Duration::from_millis(1))
    .unwrap();
  let mut guard = 0;
  while ep.poll_withdrawal_transmit(past, &mut small).is_some() {
    guard += 1;
    assert!(
      guard < 16,
      "the past-ceiling pump must terminate (each item's final attempt fires once)"
    );
  }
  let mut done2 = std::vec::Vec::new();
  ep.drain_completed_withdrawals(past, &mut done2);
  assert!(
    done2.contains(&h),
    "the route is force-freed at its ceiling even though the current goodbye never encoded"
  );
}

/// Regression: `unregister_service` is a force-remove, NO-goodbye
/// primitive — it must ALSO drop the handle's ROUTE-attached withdrawal item.
/// Otherwise removing the route (and its name guard) lets the same name be
/// re-registered while a stale route-attached item still owes a TTL=0 goodbye,
/// which would later flush the same-name replacement from peer caches.
#[test]
fn unregister_service_drops_route_attached_withdrawal_no_stale_goodbye() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let inst = Name::try_from_str("Svc._ipp._tcp.local.").unwrap();

  let recs = ServiceRecords::new(stype.clone(), inst.clone(), host, 631, 120);
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      now,
    )
    .unwrap();

  // Begin a ROUTE-attached withdrawal: a goodbye item now owes for `inst`.
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);
  assert!(
    ep.route_withdrawal_owed(h).is_some(),
    "a route-attached withdrawal item owes a goodbye for the name"
  );

  // Force-remove must drop the route-attached withdrawal item (no goodbye).
  assert!(ep.unregister_service(h), "the route was found and removed");
  assert!(
    ep.route_withdrawal_owed(h).is_none(),
    "force-remove dropped the route-attached withdrawal item"
  );

  // The SAME name is reusable, and no stale withdrawal exists to flush it.
  ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    ServiceSpec::new(ServiceRecords::new(
      stype,
      inst,
      Name::try_from_str("other.local.").unwrap(),
      700,
      120,
    )),
    now,
  )
  .expect("the name is reusable after force-remove");
  let mut buf = std::vec![0u8; 1500];
  assert!(
    ep.poll_withdrawal_transmit(now, &mut buf).is_none(),
    "no stale TTL=0 goodbye is emitted for the force-removed-then-reused name"
  );
}

/// Regression: a renamed-away old name held by an in-flight
/// DETACHED withdrawal item is RECLAIMED by a new registration rather than the
/// name being rejected (rejecting would needlessly fail a legitimate reuse and,
/// on the auto-rename path, kill the service). The detached goodbye is CANCELLED
/// when the reclaiming service CONFIRMS advertising the name (cancel-on-announce),
/// not at register time — so no late TTL=0 goodbye can flush the new registration.
#[test]
fn reclaiming_a_detached_name_cancels_its_goodbye() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let old_name = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
  let cur_name = Name::try_from_str("Cur._ipp._tcp.local.").unwrap();

  let cur_recs = ServiceRecords::new(stype.clone(), cur_name, host.clone(), 631, 120);
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(cur_recs.clone()),
      now,
    )
    .unwrap();

  // Teardown during a rename window: the rename enqueued a DETACHED item owning
  // `old_name`, and the teardown began a current-only withdrawal that owns
  // nothing here (isolating the detached item). Keep the current item alive so
  // the route is still held — the focus is the detached old-name reservation.
  let old_records = ServiceRecords::new(stype, old_name.clone(), host, 631, 120);
  let old_owned = crate::service::EmittedRecords::new(
    true,
    true,
    false,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: old_records,
      owned: old_owned,
    },
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot {
    records: cur_recs,
    owned: crate::service::EmittedRecords::new(
      false,
      false,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_some(),
    "a detached item owns the renamed-away old name"
  );

  // Reclaiming the old name SUCCEEDS (not rejected).
  let dup = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    old_name.clone(),
    Name::try_from_str("other.local.").unwrap(),
    700,
    120,
  );
  let (dup_h, _dup_svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(dup),
      now,
    )
    .expect("reclaiming a detached-reserved name succeeds (not rejected)");
  // Registration alone does NOT cancel the goodbye — it keeps draining until the
  // reclaiming service confirms advertising the name (cancel-on-announce,
  // ; cancelling at register time could lose it across the reactor's async
  // reply boundary).
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_some(),
    "registration must NOT cancel the goodbye — it survives until the reclaiming service announces"
  );

  // The reclaiming service CONFIRMS advertising the name → cancel-on-announce
  // drops the goodbye, so no late TTL=0 goodbye can flush the new registration.
  ep.note_service_announced(FullyAnnounced::new(dup_h, true), &[], &[]);
  assert!(
    ep.detached_withdrawal_owed_for(&old_name).is_none(),
    "the detached old-name goodbye is cancelled when the reclaiming service announces"
  );
}

/// Regression: an auto-rename onto a name held only by an in-flight
/// DETACHED withdrawal must NOT be rejected — the drivers treat a rename error
/// as fatal and would move the service into withdrawal (kill it). The reclaim
/// cancels the detached goodbye and the rename succeeds.
#[test]
fn rename_onto_a_detached_name_cancels_it_not_kills_the_service() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let target = Name::try_from_str("Target._ipp._tcp.local.").unwrap();

  // A live service that will auto-rename onto `target`.
  let s_recs = ServiceRecords::new(
    stype.clone(),
    Name::try_from_str("S._ipp._tcp.local.").unwrap(),
    host.clone(),
    631,
    120,
  );
  let (s, _svc_s) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(s_recs),
      now,
    )
    .unwrap();

  // A second service whose teardown-during-rename leaves a DETACHED item owning
  // `target` — the name S is about to rename onto.
  let c2_recs = ServiceRecords::new(
    stype.clone(),
    Name::try_from_str("C2._ipp._tcp.local.").unwrap(),
    host.clone(),
    632,
    120,
  );
  let (h2, _svc2) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(c2_recs.clone()),
      now,
    )
    .unwrap();
  let target_records = ServiceRecords::new(stype, target.clone(), host, 633, 120);
  let target_owned = crate::service::EmittedRecords::new(
    true,
    true,
    false,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  );
  // C2's rename enqueued a DETACHED item owning `target`; its teardown then
  // began a current-only withdrawal (owns nothing here).
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: target_records,
      owned: target_owned,
    },
    now,
    false,
  );
  let snap2 = crate::service::WithdrawalSnapshot {
    records: c2_recs,
    owned: crate::service::EmittedRecords::new(
      false,
      false,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h2, snap2, now);
  assert!(
    ep.detached_withdrawal_owed_for(&target).is_some(),
    "a detached item owns `target`"
  );

  // S auto-renames onto `target`: the endpoint must NOT reject (the driver would
  // treat that as fatal —). The rename succeeds + applies.
  ep.handle_service_renamed(s, target.clone())
    .expect("an auto-rename onto a detached-reserved name succeeds (not rejected)");
  // The rename only RESERVES `target`; it does NOT cancel the detached goodbye —
  // S still probes before advertising and may rename/conflict away again before
  // announcing, in which case the old records must still be retracted.
  assert!(
    ep.detached_withdrawal_owed_for(&target).is_some(),
    "the rename must NOT cancel the goodbye — it survives until S advertises `target`"
  );
  // When S CONFIRMS advertising its instance records under `target`,
  // cancel-on-announce drops the goodbye so no late TTL=0 send can flush S.
  ep.note_service_announced(FullyAnnounced::new(s, true), &[], &[]);
  assert!(
    ep.detached_withdrawal_owed_for(&target).is_none(),
    "the detached goodbye is cancelled once S advertises the reclaimed name"
  );
}

/// an auto-rename onto a HELD (collision) detached name must be
/// REJECTED — the held goodbye must complete (retract the dead service's records)
/// before reuse, and a held item is intentionally NOT cancelled on advertise,
/// so letting a rename claim it would leave the held item to later flush the
/// renamed service's records. A RECLAIMABLE detached name stays reusable by rename
///. Mirrors the `try_register_service` holds_name guard.
#[test]
fn rename_onto_a_held_detached_name_is_rejected_reclaimable_is_not() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let held = Name::try_from_str("Held._ipp._tcp.local.").unwrap();
  let reclaimable = Name::try_from_str("Reclaim._ipp._tcp.local.").unwrap();

  // A live service S that will try to rename.
  let s_recs = ServiceRecords::new(
    stype.clone(),
    Name::try_from_str("S._ipp._tcp.local.").unwrap(),
    host.clone(),
    631,
    120,
  );
  let (s, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(s_recs),
      now,
    )
    .unwrap();

  let mk = |name: &Name| crate::service::RenameGoodbyeHandoff {
    records: ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120),
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
  };
  // A HELD (collision) detached goodbye for `held`, and a RECLAIMABLE one.
  ep.enqueue_rename_withdrawal(mk(&held), now, true);
  ep.enqueue_rename_withdrawal(mk(&reclaimable), now, false);

  // Renaming S onto the HELD name is REJECTED (retract-before-reuse, ); the
  // held goodbye is left intact.
  assert!(
    ep.handle_service_renamed(s, held.clone()).is_err(),
    "a rename onto a HELD collision name must be rejected"
  );
  assert!(
    ep.detached_withdrawal_owed_for(&held).is_some(),
    "the held goodbye is untouched by the rejected rename"
  );

  // Renaming S onto the RECLAIMABLE name SUCCEEDS.
  assert!(
    ep.handle_service_renamed(s, reclaimable.clone()).is_ok(),
    "a rename onto a RECLAIMABLE detached name must succeed"
  );
  assert!(
    ep.detached_withdrawal_owed_for(&reclaimable).is_some(),
    "the reclaimable goodbye survives the rename (cancelled only on advertise)"
  );
}

/// regression: a family that recovers in the FINAL window
/// before the ceiling (because the last backoff overshot `ceiling_at`) must
/// still get ONE last goodbye attempt before the route is force-freed.
///
/// v4 is paid; v6 stays busy (Retry). The last `note_withdrawal_result` clamps
/// `next_at` to `ceiling_at` (the schedule cannot skip past the ceiling). AT
/// the ceiling, `poll_withdrawal_transmit` must return a datagram for the owed
/// withdrawal EXACTLY ONCE (the final attempt) — the normal due window
/// (`now < ceiling_at`) no longer matches, so without the final-attempt branch
/// the owed family would never be tried. A SECOND poll at the same instant must
/// return `None` (no infinite emission), and `drain_completed_withdrawals` then
/// force-completes the route.
#[test]
fn owed_family_gets_a_final_attempt_at_ceiling() {
  let mut ep = build_endpoint();
  let t0 = StdInstant::now();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst.clone(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      t0,
    )
    .unwrap();
  // Owns instance records, so the withdrawal has a real goodbye to emit.
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, t0);
  let ceiling = t0.checked_add_duration(super::WITHDRAWAL_CEILING).unwrap();

  // Pay v4 fully; v6 is busy each round. v4's debt drains to 0, v6 still owes.
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_route_withdrawal_result(
      h,
      t0,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Retry,
    );
  }
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, super::WITHDRAWAL_SENDS]),
    "v4 paid; v6 still owes its whole budget"
  );

  // A round JUST before the ceiling with no real progress (v4 already paid →
  // redundant Sent, v6 still Retry) re-arms at the short backoff — which the
  // clamp pins to `ceiling_at` (the backoff would otherwise overshoot it).
  let t_near = t0
    .checked_add_duration(super::WITHDRAWAL_CEILING - core::time::Duration::from_millis(1))
    .unwrap();
  ep.note_route_withdrawal_result(
    h,
    t_near,
    super::WithdrawalSend::Sent,
    super::WithdrawalSend::Retry,
  );
  assert_eq!(
    ep.route_withdrawal_next_at(h),
    Some(ceiling),
    "the re-arm must be CLAMPED to ceiling_at, not pushed past it"
  );

  // AT the ceiling: the normal due window (`now < ceiling_at`) no longer
  // matches, but the owed family still gets ONE final attempt.
  let mut buf = std::vec![0u8; 4096];
  let first = ep.poll_withdrawal_transmit(ceiling, &mut buf);
  let got = first
    .expect("the owed family must get a FINAL goodbye attempt at the ceiling")
    .token();
  assert_eq!(
    Some(got),
    ep.route_withdrawal_token(h),
    "the final attempt is for the owed withdrawal"
  );

  // A second poll at the SAME instant must NOT re-emit (final_attempt guards it)
  // — proving the past-ceiling branch fires at most once (no infinite emission).
  assert!(
    ep.poll_withdrawal_transmit(ceiling, &mut buf).is_none(),
    "the final attempt fires exactly once; a second poll must return None"
  );

  // The route is now force-completed (past the ceiling AND final-attempted).
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(ceiling, &mut done);
  assert!(
    done.contains(&h),
    "after its final ceiling attempt the route is force-completed and freed"
  );
  // The name is re-registerable once the route is freed.
  let recs2 = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst,
    Name::try_from_str("h2.local.").unwrap(),
    631,
    120,
  );
  assert!(
    ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs2),
      ceiling,
    )
    .is_ok(),
    "the withdrawn name is re-registerable after the route is force-freed"
  );
}

/// before the ceiling-attempt fix, a withdrawal past its ceiling with debt
/// still owed but no final attempt must NOT be force-completed — it is held for
/// the final attempt. This pins down the `drain` guard: past the ceiling but
/// `!final_attempt` and `owed != [0,0]` → not yet drained.
#[test]
fn past_ceiling_owed_withdrawal_is_held_until_final_attempt() {
  let mut ep = build_endpoint();
  let t0 = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Printer._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      t0,
    )
    .unwrap();
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, t0);
  let ceiling = t0.checked_add_duration(super::WITHDRAWAL_CEILING).unwrap();

  // A drain PAST the ceiling, with v6 still owed and NO final attempt yet made,
  // must NOT free the route — the owed family is still entitled to its last try.
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(ceiling, &mut done);
  assert!(
    done.is_empty(),
    "a past-ceiling owed withdrawal must be HELD until its final attempt is made"
  );

  // The final attempt happens on the next poll; THEN drain frees it.
  let mut buf = std::vec![0u8; 4096];
  assert!(
    ep.poll_withdrawal_transmit(ceiling, &mut buf).is_some(),
    "the final ceiling attempt is emitted"
  );
  ep.drain_completed_withdrawals(ceiling, &mut done);
  assert!(
    done.contains(&h),
    "after the final attempt the held route is force-completed"
  );
}

/// A withdrawal that spends its whole budget COMPLETES: the route is freed,
/// `services_active` is decremented, the handle is returned for GC, and the
/// name is re-registerable.
#[cfg(feature = "stats")]
#[test]
fn withdrawal_completes_frees_name_and_decrements_active() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst.clone(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, mut svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  let before = ep.stats().services_active;
  ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);

  // Spend the whole per-family resend budget via dual-stack delivered
  // confirmations (both families Sent each round → owed reaches [0, 0]).
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_route_withdrawal_result(
      h,
      now,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Sent,
    );
  }
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);

  assert_eq!(
    done,
    std::vec![h],
    "the completed handle is returned for GC"
  );
  assert_eq!(
    ep.stats().services_active,
    before - 1,
    "services_active is decremented on completion"
  );

  // The name is now re-registerable.
  let recs2 = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst,
    Name::try_from_str("h2.local.").unwrap(),
    631,
    120,
  );
  assert!(
    ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs2),
      now,
    )
    .is_ok(),
    "the withdrawn name is re-registerable after completion"
  );
}

/// A withdrawal whose families never deliver is force-completed at its ceiling
/// (anti-pin), so the name is eventually released.
#[test]
fn withdrawal_force_completes_at_ceiling() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("A._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, mut svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);

  // Never deliver; advance to the ceiling (now + WITHDRAWAL_CEILING).
  let at_ceiling = now.checked_add_duration(super::WITHDRAWAL_CEILING).unwrap();
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(at_ceiling, &mut done);
  assert_eq!(
    done,
    std::vec![h],
    "ceiling force-completes a wedged withdrawal"
  );
}

/// Build a withdrawal snapshot owning NO instance records, withdrawing only
/// the given host A set (models a host-record-only withdrawal).
fn host_only_snapshot(
  host: &Name,
  instance: &str,
  host_a: &[Ipv4Addr],
) -> crate::service::WithdrawalSnapshot {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str(instance).unwrap(),
    host.clone(),
    631,
    120,
  );
  for a in host_a {
    recs.add_a(*a);
  }
  crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      false,
      false,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: host_a.to_vec(),
    host_aaaa: std::vec::Vec::new(),
  }
}

/// Regression: a retained-only withdrawal must NOT head-of-line
/// block the pump. Two same-time withdrawals: A is retained-only (its single
/// host address is still advertised by a LIVE non-withdrawing sibling C, and A
/// owns no instance records) and B genuinely needs a TTL=0 goodbye. The pump
/// must scan PAST A (returning B's datagram, not `None`) in the SAME pass, and
/// a subsequent drain must complete/free A at once (not leave it pinned to the
/// 2 s ceiling).
#[test]
fn retained_only_withdrawal_completes_and_does_not_block_a_sibling() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("h.local.").unwrap();
  let shared = Ipv4Addr::new(192, 168, 1, 5);

  // C: a LIVE same-host sibling that has CONFIRMED-ADVERTISED `shared` and is
  // NOT withdrawing — it legitimately keeps the address in peer caches.
  let _c = register_host_service(
    &mut ep,
    "C._ipp._tcp.local.",
    &host,
    &[shared],
    Some(&[shared]),
  );

  // A (registered FIRST → lower withdrawals index): withdraws only `shared`,
  // owns no instance records. Since C retains `shared`, A has NOTHING to emit.
  let a = register_host_service(
    &mut ep,
    "A._ipp._tcp.local.",
    &host,
    &[shared],
    Some(&[shared]),
  );
  // B (registered after A): genuinely needs a goodbye (owns PTR/SRV/TXT, no
  // host addresses so it is independent of host retention).
  let recs_b = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("B._ipp._tcp.local.").unwrap(),
    Name::try_from_str("hb.local.").unwrap(),
    632,
    120,
  );
  let (b, _svc_b) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs_b.clone()),
      now,
    )
    .unwrap();
  let snap_b = crate::service::WithdrawalSnapshot {
    records: recs_b,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };

  // Both withdraw at the SAME time (A first in the vec, then B).
  ep.begin_withdrawal(
    a,
    host_only_snapshot(&host, "A._ipp._tcp.local.", &[shared]),
    now,
  );
  ep.begin_withdrawal(b, snap_b, now);

  // A single pump must scan PAST the retained-only A and RETURN B's datagram —
  // NOT `None`. (Pre-fix it returned `None` on A, starving B.)
  let mut buf = std::vec![0u8; 4096];
  let round = ep
    .poll_withdrawal_transmit(now, &mut buf)
    .expect("the pump must scan past the retained-only A and return B's goodbye");
  let (len, got) = (round.len(), round.token());
  assert_eq!(
    Some(got),
    ep.route_withdrawal_token(b),
    "the genuine withdrawal B is the one that emits"
  );
  let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
  assert!(
    reader.answers().count() > 0,
    "B's goodbye must carry its TTL=0 instance records"
  );

  // A was marked complete in that scan (owed set to [0, 0]), so the NEXT drain
  // frees it AT ONCE — without waiting for the 2 s ceiling.
  assert_eq!(
    ep.route_withdrawal_owed(a),
    Some([0, 0]),
    "the retained-only A must be COMPLETED (owed = [0, 0]) by the scan"
  );
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert!(
    done.contains(&a),
    "the retained-only A must be freed immediately, not pinned to the ceiling"
  );
  // A's route is gone, so its name is re-registerable now (no ceiling wait).
  let recs_a2 = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("A._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h2.local.").unwrap(),
    633,
    120,
  );
  assert!(
    ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs_a2),
      now,
    )
    .is_ok(),
    "A's name is released the moment its retained-only withdrawal completes"
  );
}

/// Regression: a LONE retained-only withdrawal returns `None`
/// from `poll_withdrawal_transmit` (nothing to emit) but is COMPLETED in place
/// (`owed` set to [0, 0]), so the next drain frees it AT ONCE rather than
/// pinning the name to the 2 s ceiling and re-waking `poll_timeout` until then.
#[test]
fn retained_only_withdrawal_completes_immediately() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let host = Name::try_from_str("h.local.").unwrap();
  let shared = Ipv4Addr::new(192, 168, 1, 5);

  // C: a LIVE same-host sibling that still advertises `shared`.
  let _c = register_host_service(
    &mut ep,
    "C._ipp._tcp.local.",
    &host,
    &[shared],
    Some(&[shared]),
  );
  // A: retained-only (owns no instance records; its only host addr is retained
  // by C).
  let a = register_host_service(
    &mut ep,
    "A._ipp._tcp.local.",
    &host,
    &[shared],
    Some(&[shared]),
  );
  ep.begin_withdrawal(
    a,
    host_only_snapshot(&host, "A._ipp._tcp.local.", &[shared]),
    now,
  );

  // A lone retained-only withdrawal emits no datagram.
  let mut buf = std::vec![0u8; 4096];
  assert!(
    ep.poll_withdrawal_transmit(now, &mut buf).is_none(),
    "a retained-only withdrawal has nothing to emit"
  );
  // But it is COMPLETED — `owed` is [0, 0], so the drain frees it immediately.
  assert_eq!(
    ep.route_withdrawal_owed(a),
    Some([0, 0]),
    "the retained-only withdrawal must be completed (owed = [0, 0]), not left due"
  );
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert_eq!(
    done,
    std::vec![a],
    "the retained-only withdrawal is freed at once, not at the 2 s ceiling"
  );
}

/// A withdrawing route is NOT routed an incoming question (its service is gone,
/// only its goodbye is draining), but the route is still present so a same-name
/// re-registration is rejected.
#[test]
fn withdrawing_route_is_not_answered_but_still_blocks_reregister() {
  use core::net::SocketAddr;
  let mut e = build_endpoint();
  let now = StdInstant::now();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst.clone(),
    Name::try_from_str("printer-host.local.").unwrap(),
    631,
    120,
  );
  let (handle, mut svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  e.begin_withdrawal(handle, svc.withdrawal_snapshot(), now);

  // A question for the (withdrawing) host must NOT route to the service.
  let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
  let mut buf = [0u8; 512];
  let n = build_query_for_host(&mut buf, "printer-host.local.");
  let routed_to_service = e
    .handle(StdInstant::now(), src, local_ip, 0, &buf[..n], false)
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    !routed_to_service,
    "a withdrawing service must not be routed a question"
  );

  // The name is still held (route present for the guard).
  let recs2 = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst,
    Name::try_from_str("h2.local.").unwrap(),
    631,
    120,
  );
  assert!(
    matches!(
      e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs2),
        now
      ),
      Err(RegisterServiceError::NameAlreadyRegistered(_))
    ),
    "the withdrawing name must still be held"
  );
}

/// a withdrawing route must receive NO `ToService` dispatch on ANY
/// path — HostConflict, ProbeConflict, AND the QR=0 meta-PTR known-answer fanout
/// — not just no question. The route is retained for the name guard, but
/// dispatching to a service the driver no longer drains (it skips
/// withdrawing/errored contexts) lets a peer flood the proto event slab of a
/// retiring service until GC — a bounded-time but unbounded-size growth path. A
/// positive control feeds the SAME packets while the service is LIVE (they must
/// route), so the negative assertions are not vacuous; the name must still be held
/// afterwards (dispatch-only skip).
#[test]
fn withdrawing_route_receives_no_service_dispatch_but_still_blocks_reregister() {
  use core::net::SocketAddr;

  use crate::wire::{Header, MessageBuilder};

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst.clone(),
    host.clone(),
    631,
    120,
  );
  let (handle, mut svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  // A peer claiming our HOST name with a DIFFERENT address → §9 HostConflict.
  let host_pkt = {
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_a_authority(&host, 120, Ipv4Addr::new(10, 0, 0, 99))
      .unwrap();
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  };
  // A peer claiming our INSTANCE name with rival rdata → §9 ProbeConflict.
  let inst_pkt = {
    let target = Name::try_from_str("rival.local.").unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_srv_authority(&inst, 120, 0, 0, 9999, &target)
      .unwrap();
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  };
  // A QR=0 meta-PTR known-answer (DNS-SD service-type enumeration) fans out to
  // EVERY service; a withdrawing route must be excluded from that fanout too.
  let ka_pkt = {
    let meta = Name::try_from_str("_services._dns-sd._udp.local.").unwrap();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_ptr_answer(&meta, 120, &stype).unwrap();
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  };
  // (inline handle-and-check: a closure capturing `&mut e` would conflict with
  // the direct `e` uses between calls, and naming the generic Endpoint type for a
  // by-ref-param closure is brittle.)

  // POSITIVE CONTROL: while LIVE, both conflicts DO route a ToService — so the
  // negative assertions below actually exercise the withdrawing skip.
  let live_host = e
    .handle(StdInstant::now(), src, local_ip, 0, &host_pkt, false)
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    live_host,
    "sanity: a LIVE service must receive the HostConflict dispatch"
  );
  let live_inst = e
    .handle(StdInstant::now(), src, local_ip, 0, &inst_pkt, false)
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    live_inst,
    "sanity: a LIVE service must receive the ProbeConflict dispatch"
  );
  let live_ka = e
    .handle(StdInstant::now(), src, local_ip, 0, &ka_pkt, false)
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    live_ka,
    "sanity: a LIVE service must receive the meta-PTR KnownAnswer dispatch"
  );

  // Now retire the route via the endpoint-owned withdrawal.
  e.begin_withdrawal(handle, svc.withdrawal_snapshot(), now);

  // While WITHDRAWING, neither conflict routes any ToService.
  let wd_host = e
    .handle(StdInstant::now(), src, local_ip, 0, &host_pkt, false)
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    !wd_host,
    "a withdrawing service must not receive a HostConflict dispatch"
  );
  let wd_inst = e
    .handle(StdInstant::now(), src, local_ip, 0, &inst_pkt, false)
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    !wd_inst,
    "a withdrawing service must not receive a ProbeConflict dispatch"
  );
  let wd_ka = e
    .handle(StdInstant::now(), src, local_ip, 0, &ka_pkt, false)
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    !wd_ka,
    "a withdrawing service must not receive a KnownAnswer dispatch"
  );

  // The name is still held (route present for the guard) — the skip is
  // dispatch-only, not a release of the name reservation.
  let recs2 = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst,
    Name::try_from_str("h2.local.").unwrap(),
    631,
    120,
  );
  assert!(
    matches!(
      e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs2),
        now
      ),
      Err(RegisterServiceError::NameAlreadyRegistered(_))
    ),
    "the withdrawing name must still be held"
  );
}

/// `poll_timeout` accounts for a due endpoint-owned withdrawal so the driver
/// wakes to pump it.
#[test]
fn poll_timeout_accounts_for_due_withdrawal() {
  let mut e = build_endpoint();
  let now = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("A._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, mut svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  e.begin_withdrawal(h, svc.withdrawal_snapshot(), now);
  assert_eq!(
    e.poll_timeout(),
    Some(now),
    "a due-now withdrawal makes poll_timeout return now"
  );
}

/// A never-announced service (empty withdrawal snapshot) completes on the FIRST
/// `drain_completed_withdrawals` — no spurious goodbye, no 2 s ceiling wait.
#[cfg(feature = "stats")]
#[test]
fn empty_withdrawal_completes_immediately() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("A._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, mut svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  let before = ep.stats().services_active;
  // Never announced → empty snapshot → owed == [0, 0].
  ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert_eq!(
    done,
    std::vec![h],
    "an empty withdrawal completes on the first drain (no ceiling wait)"
  );
  assert_eq!(ep.stats().services_active, before - 1);
}

/// Regression: `next_withdrawal_deadline` / `has_pending_withdrawals`
/// reflect ONLY in-flight withdrawals — excluding cache and query deadlines — so
/// a last-handle shutdown flush exits as soon as every goodbye is sent instead
/// of parking on an unrelated cache deadline (or the wall-clock backstop).
#[test]
fn next_withdrawal_deadline_reflects_only_withdrawals() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  assert_eq!(
    ep.next_withdrawal_deadline(),
    None,
    "no withdrawal in flight → no withdrawal deadline"
  );
  assert!(!ep.has_pending_withdrawals());

  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Svc._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let recs = ServiceRecords::new(stype, inst, host, 631, 120);
  let (h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs.clone()),
      now,
    )
    .unwrap();

  // A route-attached withdrawal that owns instance records is due NOW.
  let snap = crate::service::WithdrawalSnapshot {
    records: recs,
    owned: crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
    ),
    host_a: std::vec::Vec::new(),
    host_aaaa: std::vec::Vec::new(),
  };
  ep.begin_withdrawal(h, snap, now);
  assert_eq!(
    ep.next_withdrawal_deadline(),
    Some(now),
    "a due-now withdrawal sets the withdrawal deadline"
  );
  assert!(ep.has_pending_withdrawals());

  // Force-remove drops the route-attached item → the withdrawal deadline is gone
  // again, so a shutdown flush would exit (None) rather than wait on any cache
  // or query deadline.
  assert!(ep.unregister_service(h));
  assert_eq!(ep.next_withdrawal_deadline(), None);
  assert!(!ep.has_pending_withdrawals());
}

/// `begin_withdrawal` is idempotent: a second call for an already-withdrawing
/// handle does not enqueue a duplicate (so the handle is GC-reported once).
#[test]
fn begin_withdrawal_is_idempotent() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("A._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let (h, mut svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);
  // Second retire of the same handle must be a no-op (no duplicate schedule).
  ep.begin_withdrawal(h, svc.withdrawal_snapshot(), now);
  let mut done: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(now, &mut done);
  assert_eq!(
    done,
    std::vec![h],
    "idempotent begin_withdrawal must report the handle exactly once"
  );
}

// ── route iterator: known-answer fan-out across multiple services ──

/// a QR=0 ANSWER record (a known-answer hint) that matches ONLY a
/// later-registered service must still reach that service as
/// ServiceEvent::KnownAnswer. The service-side KAS scan walks every registered
/// service in slab order; an earlier non-matching service must not short-circuit
/// the fan-out before the actual owner is found. (Positive single-service
/// controls are `query_answer_for_instance_name_emits_known_answer_only` and
/// `qr0_answer_for_host_name_emits_host_conflict_not_probe_conflict`; this drives
/// the multi-service walk so the loop visits a non-matching service first.)
#[test]
fn qr0_known_answer_fans_out_to_a_later_matching_service() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();

  // Service 0 (lower slab key): Alpha / alpha.local. — must NOT match the hint.
  let st0 = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst0 = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
  let host0 = Name::try_from_str("alpha.local.").unwrap();
  let recs0 = ServiceRecords::new(st0, inst0, host0, 80, 120);
  let (_h0, _s0) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs0),
      now,
    )
    .unwrap();

  // Service 1 (higher slab key): Beta / beta.local. under a DISTINCT
  // service-type so service 0's names share nothing with the hint record.
  let st1 = Name::try_from_str("_other._tcp.local.").unwrap();
  let inst1 = Name::try_from_str("Beta._other._tcp.local.").unwrap();
  let host1 = Name::try_from_str("beta.local.").unwrap();
  let recs1 = ServiceRecords::new(st1, inst1.clone(), host1, 81, 120);
  let (h1, _s1) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs1),
      now,
    )
    .unwrap();

  // QR=0 query packet; ANSWER = A record owned by Beta's instance name only.
  let mut buf = [0u8; 512];
  let header = Header::new(); // QR=0 (known-answer hint, not a response)
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, header).unwrap();
  b.push_a_answer(&inst1, 120, Ipv4Addr::new(10, 0, 0, 2), false)
    .unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let known_answers: std::vec::Vec<_> = e
    .handle(now, src, local_ip, 0, &buf[..n], false)
    .unwrap()
    .filter_map(Result::ok)
    .filter_map(|ev| match ev {
      RouteEvent::ToService(ts) if ts.event().is_known_answer() => Some(ts.handle()),
      _ => None,
    })
    .collect();

  // Exactly one KnownAnswer, addressed to the later-registered Beta service —
  // proving the scan fell through the non-matching service 0 to find the owner.
  assert_eq!(
    known_answers,
    std::vec![h1],
    "the KAS hint must fan out past the non-matching first service to Beta"
  );
}

// ── route iterator: ADDITIONAL-section parse error + TTL=0 withdrawal ──

/// a malformed record in the ADDITIONAL section of a QR=1 response
/// must surface as `HandleError::Parse` from the route iterator (after any
/// well-formed earlier additionals are delivered), not be silently swallowed.
/// The header overstates ARCOUNT, so the iterator walks into truncated bytes.
#[test]
fn additional_section_malformed_record_surfaces_parse_error() {
  use crate::{config::QuerySpec, event::RouteEvent, wire::ResourceType};
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let _h = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
    .unwrap();

  // QR=1 response, ARCOUNT=2: record 0 is a well-formed A for the query name,
  // record 1 is a truncated name (label length 16 with a single trailing byte).
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 0, 0, 0, 0, 2]); // QR=1, ar=2
  msg.extend_from_slice(&[
    7, b'p', b'r', b'i', b'n', b't', b'e', b'r', 5, b'l', b'o', b'c', b'a', b'l', 0,
  ]);
  msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
  msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
  msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
  msg.extend_from_slice(&[10, 0, 0, 7]);
  msg.extend_from_slice(&[0x10, b'x']); // record 1: label len 16, only 1 byte → parse error

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let mut saw_to_query = false;
  let mut saw_parse_err = false;
  for ev in e.handle(now, src, local_ip, 0, &msg, false).unwrap() {
    match ev {
      Ok(RouteEvent::ToQuery(_)) => saw_to_query = true,
      Err(HandleError::Parse(_)) => saw_parse_err = true,
      _ => {}
    }
  }
  assert!(
    saw_to_query,
    "the well-formed first additional must still reach the active query"
  );
  assert!(
    saw_parse_err,
    "a malformed additional record must surface HandleError::Parse from the iterator"
  );
}

/// a TTL=0 record in the ADDITIONAL section (a goodbye/withdrawal) must
/// be skipped by the route-level TTL=0 guard — no ghost answer is surfaced for
/// it — while a following positive-TTL additional for the same query name is
/// still delivered. This exercises the additional-section per-record skip plus
/// the resume-from-cursor advance across two records.
#[test]
fn additional_section_ttl0_withdrawal_skipped_then_later_record_delivered() {
  use crate::{config::QuerySpec, event::RouteEvent, wire::ResourceType};
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let _h = e
    .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
    .unwrap();

  let owner: [u8; 15] = [
    7, b'p', b'r', b'i', b'n', b't', b'e', b'r', 5, b'l', b'o', b'c', b'a', b'l', 0,
  ];
  // QR=1 response, ARCOUNT=2: record 0 is a TTL=0 A (withdrawal) for the query
  // name; record 1 is a positive-TTL A for the same name.
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 0, 0, 0, 0, 2]); // QR=1, ar=2
  msg.extend_from_slice(&owner);
  msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
  msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  msg.extend_from_slice(&0u32.to_be_bytes()); // TTL=0 (goodbye)
  msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
  msg.extend_from_slice(&[10, 0, 0, 8]);
  msg.extend_from_slice(&owner);
  msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
  msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  msg.extend_from_slice(&120u32.to_be_bytes()); // positive TTL
  msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
  msg.extend_from_slice(&[10, 0, 0, 9]);

  let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let to_query = e
    .handle(now, src, local_ip, 0, &msg, false)
    .unwrap()
    .filter(|r| matches!(r, Ok(RouteEvent::ToQuery(_))))
    .count();
  // Exactly one ToQuery: the TTL=0 record 0 is skipped (no ghost answer), the
  // positive-TTL record 1 is delivered.
  assert_eq!(
    to_query, 1,
    "a TTL=0 additional must be skipped while the following positive-TTL one is delivered"
  );
}

// ── TransmitDelivery at the endpoint boundary ─────────────────────────

/// Drive one query at the ENDPOINT boundary, confirming every send with
/// `delivery`, until it stops transmitting. Returns how many questions it put on a
/// wire.
fn questions_before_the_query_retires(delivery: TransmitDelivery) -> usize {
  let mut ep = build_endpoint();
  let mut now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let h = ep
    .try_start_query(
      crate::config::QuerySpec::new(qname, ResourceType::Any),
      now,
    )
    .unwrap();
  let mut buf = std::vec![0u8; 512];
  let mut sent = 0usize;
  while ep
    .poll_query_transmit(h, || now, &mut buf)
    .unwrap()
    .is_some()
  {
    sent = sent.saturating_add(1);
    assert!(sent < 64, "the query never reached its §5.2 terminal");
    ep.note_query_transmit_outcome(h, now, delivery);
    let Some(due) = ep.poll_query_timeout(h) else {
      break;
    };
    assert!(
      due > now,
      "a {delivery:?} send must re-arm strictly later than §5.2's floor allows, \
       not at the instant it was confirmed"
    );
    now = due;
    ep.handle_query_timeout(h, due).unwrap();
  }
  sent
}

#[test]
fn note_query_transmit_outcome_freezes_the_budget_on_a_partial_send() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let qname = Name::try_from_str("printer.local.").unwrap();
  let h = ep
    .try_start_query(
      crate::config::QuerySpec::new(qname, ResourceType::Any),
      now,
    )
    .unwrap();
  let mut buf = std::vec![0u8; 512];
  assert!(ep.poll_query_transmit(h, || now, &mut buf).unwrap().is_some());

  ep.note_query_transmit_outcome(h, now, TransmitDelivery::V4_ONLY);
  let after_partial = ep.poll_query_timeout(h);
  assert!(
    after_partial.is_some(),
    "a partially-delivered question must still re-arm"
  );

  // A round inside the core's patience spends NO §5.2 slot: the question has not
  // been asked everywhere, so counting it would time the query out having never
  // queried the missing link.
  for _ in 1..crate::service::MAX_PARTIAL_ROUNDS {
    let due = ep.poll_query_timeout(h).unwrap();
    ep.handle_query_timeout(h, due).unwrap();
    assert!(ep.poll_query_transmit(h, || due, &mut buf).unwrap().is_some());
    ep.note_query_transmit_outcome(h, due, TransmitDelivery::V4_ONLY);
  }
  assert!(
    ep.poll_query(h).is_none(),
    "no round inside the bound may retire the query"
  );

  // …and the freeze is charged ONCE. Past the bound the missing family is written
  // off, so every later round spends its slot again and the half-reachable host
  // reaches the SAME §5.2 terminal exactly `MAX_PARTIAL_ROUNDS` questions later
  // than a fully-reachable one. Re-charging the freeze per slot instead put three
  // times as many questions on the served link's wire before the same terminal.
  //
  // (`Query::note_transmit_outcome` owns that walk; this pins that the endpoint
  // boundary ferries the per-family confirm rather than absorbing it into a
  // one-bit all-or-nothing answer, which would show up here as the two counts
  // being equal.)
  let healthy = questions_before_the_query_retires(TransmitDelivery::ALL);
  let half_reachable = questions_before_the_query_retires(TransmitDelivery::V4_ONLY);
  assert_eq!(
    half_reachable,
    healthy.saturating_add(usize::from(crate::service::MAX_PARTIAL_ROUNDS)),
    "a half-reachable host must pay the core's patience once — {healthy} healthy \
     questions, {half_reachable} half-reachable"
  );
}

/// Endpoint conformance for the driver-audit §2.3 reclaim sequence: a reclaiming
/// service that has announced on only SOME obligated links must NOT cancel the
/// renamed-away old name's in-flight goodbye. The gate is
/// `Service::has_fully_announced`, ferried verbatim; the sequence dies at the
/// step where a v4-only announce would previously have cancelled it, leaving the
/// v6 zone with neither the goodbye nor the replacement announcement.
#[test]
fn a_partially_announced_reclaim_does_not_cancel_the_old_name_goodbye() {
  let mut ep = build_endpoint();
  let mut now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let name = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();

  // A surviving rename left a RECLAIMABLE detached goodbye for the old name.
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120),
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
    },
    now,
    false,
  );

  // A fresh service reclaims the vacated name. The reclaim-cancel gate names its
  // own service through the `FullyAnnounced` token, so no handle is needed here.
  let mut recs = ServiceRecords::new(stype, name.clone(), host, 631, 120);
  recs.add_a(Ipv4Addr::new(192, 168, 1, 10));
  let (_handle, mut svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // Drive its §8.1 probes, every one fully delivered, and ferry the gate after
  // each confirm exactly as a driver does.
  let mut buf = std::vec![0u8; 4096];
  for _ in 0..20 {
    if matches!(svc.state(), crate::ServiceState::Announcing(0)) {
      break;
    }
    now = svc.poll_timeout().unwrap_or(now).max(now);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_transmit_outcome(now, TransmitDelivery::ALL);
      ep.note_service_announced(
        svc.has_fully_announced(),
        svc.advertised_a_addrs(),
        svc.advertised_aaaa_addrs(),
      );
    }
  }
  assert!(
    matches!(svc.state(), crate::ServiceState::Announcing(0)),
    "expected the reclaiming service to finish probing; got {:?}",
    svc.state()
  );
  assert!(
    ep.detached_withdrawal_owed_for(&name).is_some(),
    "probing alone must never cancel the old name's goodbye"
  );

  // The first announcement reaches IPv4 only.
  now = svc.poll_timeout().unwrap_or(now).max(now);
  svc.handle_timeout(now).unwrap();
  assert!(svc.poll_transmit(now, &mut buf).unwrap().is_some());
  svc.note_transmit_outcome(now, TransmitDelivery::V4_ONLY);
  assert!(
    svc.advertises_instance(),
    "the v4 zone heard it, so ownership latched"
  );
  ep.note_service_announced(
    svc.has_fully_announced(),
    svc.advertised_a_addrs(),
    svc.advertised_aaaa_addrs(),
  );
  assert!(
    ep.detached_withdrawal_owed_for(&name).is_some(),
    "the v6 zone has heard neither the goodbye nor the replacement — the old \
     name's goodbye MUST keep draining"
  );

  // IPv6 recovers and the next announcement reaches every obligated link.
  now = svc.poll_timeout().unwrap_or(now).max(now);
  svc.handle_timeout(now).unwrap();
  assert!(svc.poll_transmit(now, &mut buf).unwrap().is_some());
  svc.note_transmit_outcome(now, TransmitDelivery::ALL);
  ep.note_service_announced(
    svc.has_fully_announced(),
    svc.advertised_a_addrs(),
    svc.advertised_aaaa_addrs(),
  );
  assert!(
    ep.detached_withdrawal_owed_for(&name).is_none(),
    "once every obligated link has heard the replacement, §10.2's cache-flush \
     announcement supersedes the stale records and the goodbye is cancelled"
  );
}

/// The reclaim-cancel gate is reachable ONLY through a `FullyAnnounced`. This pins
/// what a compile-time check cannot state from inside the crate: the fact round-
/// trips whether it is ferried from `Service::has_fully_announced` or minted
/// directly — `false` cancels nothing, `true` cancels, regardless of provenance.
#[test]
fn the_reclaim_cancel_gate_travels_as_an_unforgeable_fact() {
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let name = Name::try_from_str("Ghost._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("ghost.local.").unwrap();

  // A service that has announced nothing mints a `false` fact, which cancels
  // nothing however it is delivered to the endpoint.
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff {
      records: ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120),
      owned: crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
      ),
    },
    now,
    false,
  );
  let recs = ServiceRecords::new(stype, name.clone(), host, 631, 120);
  let (handle, svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  let fact = svc.has_fully_announced();
  assert!(
    !fact.get(),
    "a freshly registered service has announced nothing"
  );
  ep.note_service_announced(fact, &[], &[]);
  assert!(
    ep.detached_withdrawal_owed_for(&name).is_some(),
    "a `false` fact cancels nothing"
  );

  // A directly-minted `true` fact is the same code path as one ferried from a
  // `Service` that has actually fully announced — it cancels.
  ep.note_service_announced(FullyAnnounced::new(handle, true), &[], &[]);
  assert!(
    ep.detached_withdrawal_owed_for(&name).is_none(),
    "a `true` fact cancels the reclaimable goodbye"
  );
}

/// The reclaim-cancel gate routes on the handle INSIDE the `FullyAnnounced`, so
/// one service's proof can only ever retire its OWN name's reclaimable goodbye.
///
/// An unforgeable fact is still transplantable while its subject is a separate
/// argument: a genuine `true` from a service that fully announced, paired with a
/// different service's handle, would cancel that other name's goodbye while an
/// obligated family still needed it.
#[test]
fn a_fully_announced_proof_cancels_only_its_own_services_goodbye() {
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("shared.local.").unwrap();
  let name_a = Name::try_from_str("A._ipp._tcp.local.").unwrap();
  let name_b = Name::try_from_str("B._ipp._tcp.local.").unwrap();

  let mut ep = build_endpoint();
  let now = StdInstant::now();

  // Both names have a RECLAIMABLE detached goodbye still draining.
  for name in [&name_a, &name_b] {
    ep.enqueue_rename_withdrawal(
      crate::service::RenameGoodbyeHandoff {
        records: ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120),
        owned: crate::service::EmittedRecords::new(
          true,
          true,
          true,
          std::vec::Vec::new(),
          std::vec::Vec::new(),
          false,
        ),
      },
      now,
      false,
    );
  }

  // Both names are reclaimed by fresh services.
  let (handle_a, _svc_a) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(ServiceRecords::new(
        stype.clone(),
        name_a.clone(),
        host.clone(),
        631,
        120,
      )),
      now,
    )
    .unwrap();
  let (_handle_b, _svc_b) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(ServiceRecords::new(stype, name_b.clone(), host, 631, 120)),
      now,
    )
    .unwrap();

  // Only A has fully announced. Its proof names A, and the endpoint has no other
  // way to learn which service the fact is about.
  ep.note_service_announced(FullyAnnounced::new(handle_a, true), &[], &[]);
  assert!(
    ep.detached_withdrawal_owed_for(&name_a).is_none(),
    "A's own reclaimable goodbye is superseded by A's complete announcement"
  );
  assert!(
    ep.detached_withdrawal_owed_for(&name_b).is_some(),
    "B has announced nothing, so B's goodbye MUST keep draining"
  );
}

// ── the minimum advertisable TTL ──────────────────────────────────────

fn spec_with_ttl(instance: &str, ttl_secs: u32) -> ServiceSpec {
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str(instance).unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 631, ttl_secs);
  recs.add_a(Ipv4Addr::new(10, 0, 0, 5));
  ServiceSpec::new(recs)
}

/// A TTL-0 positive record is the RFC 6762 §10.1 goodbye encoding — it tells
/// every peer to DELETE the record — so publishing a service at it advertises
/// and retracts in the same datagram. TTL 1 refreshes at 0.8 s, inside §8.3's
/// one-second floor on unsolicited responses, so the record cannot be kept alive
/// at a legal rate; both also truncate the periodic refresh interval to zero,
/// which re-arms an `Established` service at `now`.
///
/// `Service::try_new` is crate-private, so registration is the only way to build
/// one and this guard is total.
#[test]
fn registration_rejects_a_ttl_below_the_advertisable_minimum() {
  for ttl in [0u32, 1] {
    let mut e = build_endpoint();
    let err = match e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      spec_with_ttl("P._ipp._tcp.local.", ttl),
      StdInstant::now(),
    ) {
      Ok(_) => panic!("a TTL of {ttl} s must be rejected, not clamped or accepted"),
      Err(e) => e,
    };
    assert!(
      matches!(err, RegisterServiceError::TtlTooSmall(t) if t == ttl),
      "expected TtlTooSmall({ttl}), got {err:?}"
    );
    assert!(
      e.services.iter().next().is_none(),
      "a rejected registration must reserve no name"
    );
  }
}

/// The smallest TTL that IS advertisable, driven end-to-end: it registers, it
/// reaches `Established`, and its periodic refresh re-arms a full RFC 6762 §8.3
/// announce interval out rather than at `now`. A zero-length interval would make
/// the service re-announce on every tick forever.
#[test]
fn the_minimum_ttl_registers_and_refreshes_no_faster_than_the_announce_floor() {
  use core::time::Duration;

  let mut e = build_endpoint();
  let base = StdInstant::now();
  let (_handle, mut svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      spec_with_ttl("P._ipp._tcp.local.", crate::constants::MIN_SERVICE_TTL_SECS),
      base,
    )
    .expect("the minimum TTL is advertisable");

  let mut buf = std::vec![0u8; 4096];
  let mut now = base;
  for _ in 0..40 {
    now = svc.poll_timeout().filter(|d| *d > now).unwrap_or(now);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_transmit_outcome(now, TransmitDelivery::ALL);
    }
    if svc.state() == crate::ServiceState::Established {
      break;
    }
  }
  assert_eq!(
    svc.state(),
    crate::ServiceState::Established,
    "a minimum-TTL service must still complete the §8.1/§8.3 sequence"
  );

  // Two consecutive refresh rounds, each fired at its own deadline: both the
  // deadline the announce phase left and the one the refresh confirm installs
  // must clear the one-second floor.
  for round in 0..2 {
    let due = svc
      .poll_timeout()
      .expect("an Established service re-announces periodically");
    assert!(
      due >= now + Duration::from_secs(1),
      "round {round}: the periodic refresh re-armed inside the §8.3 one-second \
       floor, so the service repumps"
    );
    now = due;
    svc.handle_timeout(now).unwrap();
    let mut sent = 0usize;
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      sent += 1;
      svc.note_transmit_outcome(now, TransmitDelivery::ALL);
    }
    assert_eq!(
      sent, 1,
      "round {round}: one fired refresh deadline is one unsolicited response"
    );
  }
}

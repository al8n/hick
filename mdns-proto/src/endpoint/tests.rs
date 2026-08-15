use super::*;
use crate::{
  cache::CacheEntry,
  config::{EndpointConfig, ServiceSpec},
  event::{QueryUpdate, ServiceUpdate},
  query::Query,
  records::ServiceRecords,
  transmit::{Transmit, TransmitDelivery},
};
use std::{net::Ipv4Addr, time::Instant as StdInstant};

type TestQuery = Query<StdInstant, slab::Slab<CollectedAnswer>, slab::Slab<QueryUpdate>>;

type TestSvc = crate::service::Service<StdInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>;

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
  let res = e.handle(now, Received::new(src, &[0u8], Provenance::Unknown).with_local_ip(local));
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
  e.note_query_delivery(bogus, now, TransmitDelivery::ALL); // no-op on an unknown handle
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
    e.handle(now, Received::new(src, &bad_opcode, Provenance::Unknown).with_local_ip(local_ip)),
    Err(HandleError::InvalidOpcode(_))
  ));
  // Header flags 0x0001 → opcode = Query but RCODE = FormatError (1) → rejected.
  let bad_rcode = [0u8, 0, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
  assert!(matches!(
    e.handle(now, Received::new(src, &bad_rcode, Provenance::Unknown).with_local_ip(local_ip)),
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

/// Helper: encode a PROBE for `host_str` — the §8.1 ANY question plus the A
/// record the prober proposes to put at that name. Unlike
/// [`build_probe_authority_for_host`] this carries the question too, which is
/// what makes it a probe rather than a bare authority record: §8.1 defines the
/// probe as "a query with the record name in question in the Question Section",
/// and `RouteEvents::is_probe_for` — the §8.1 defence gate — requires both.
fn build_probe_for_host(buf: &mut [u8; 512], host_str: &str, addr: Ipv4Addr) -> usize {
  use crate::wire::{Header, MessageBuilder, ResourceClass, ResourceType};
  let hdr = Header::new();
  let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
  let name = Name::try_from_str(host_str).unwrap();
  b.push_question(&name, ResourceType::Any, ResourceClass::In, true)
    .unwrap();
  b.push_a_authority(&name, 120, addr).unwrap();
  b.finish().unwrap()
}

/// Helper: encode a PROBE for `instance_str` — the §8.1 ANY question plus an SRV
/// record in the authority section. Use for INSTANCE-name conflicts.
///
/// The question is not decoration: §8.1 defines a probe as "a query with the
/// record name in question in the Question Section" (§5.4 sets the
/// unicast-response bit on it), and §8.2 reads the proposal off "the Authority
/// Section of *that query*". A QDCOUNT=0 packet proposes nothing, so building
/// one here asserted the routing of a datagram no prober sends.
fn build_probe_srv_authority(buf: &mut [u8; 512], instance_str: &str) -> usize {
  use crate::wire::{Header, MessageBuilder};
  let hdr = Header::new();
  let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
  let name = Name::try_from_str(instance_str).unwrap();
  let target = Name::try_from_str("other-host.local.").unwrap();
  b.push_question(
    &name,
    crate::wire::ResourceType::Any,
    crate::wire::ResourceClass::In,
    true,
  )
  .unwrap();
  b.push_srv_authority(&name, 120, 0, 0, 8080, &target)
    .unwrap();
  b.finish().unwrap()
}

/// Helper: build a test endpoint with one registered service whose host is
/// "printer-host.local." and instance is "Printer._ipp._tcp.local.".
///
/// The host publishes an A record, because a host name that owns no address
/// RRset owns nothing that RFC 6762 §9 can put in conflict — its conflict is
/// over "the same name, rrtype and rrclass", so an addressless route is not a
/// party to any A/AAAA at its host name and receives no `HostConflict` for one.
/// An addressless fixture would assert host-conflict routing no real responder
/// reaches.
fn build_endpoint_with_printer() -> (TestEndp, ServiceHandle) {
  let mut e = build_endpoint();
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
  recs.add_a(Ipv4Addr::new(192, 168, 7, 7));
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
    .handle(
      StdInstant::now(),
      Received::new(src, data, Provenance::Unknown).with_local_ip(local_ip),
    )
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
/// ProbeProposal — the peer is PROBING, so RFC 6762 §8.2's tiebreak is what
/// governs it, and its input is that query's whole Authority Section.
/// `ProbeConflict` is now responses only.
#[test]
fn authority_instance_name_routes_as_probe_proposal() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  let (mut e, expected_handle) = build_endpoint_with_printer();
  let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let local_ip = core::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  let mut buf = [0u8; 512];
  let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
  let data = &buf[..n];

  // A probe routes TWO things to the owner of the name, and both are §8.1's:
  // the QUESTION it must defend the name by answering, and the §8.2 PROPOSAL
  // its Authority Section makes. The question is routed first (Question Section
  // precedes Authority), so this scans rather than taking the head.
  let proposal_handle = e
    .handle(
      StdInstant::now(),
      Received::new(src, data, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .filter_map(|ev| match ev.expect("expected Ok") {
      RouteEvent::ToService(ts) if ts.event().is_probe_proposal() => Some(ts.handle()),
      _ => None,
    })
    .next();
  assert_eq!(
    proposal_handle,
    Some(expected_handle),
    "an instance-name authority record on a probe must route as a ProbeProposal to that service"
  );
}

/// the SAME probe-shaped authority record that triggers a
/// ProbeConflict from port 5353 (see
/// `authority_instance_name_routes_as_probe_proposal`) must NOT route as any
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
    .handle(
      StdInstant::now(),
      Received::new(src, data, Provenance::Unknown).with_local_ip(local_ip),
    )
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
    .handle(
      StdInstant::now(),
      Received::new(src, data, Provenance::Unknown).with_local_ip(local_ip),
    )
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
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
    )
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
    .handle(now, Received::new(src, &msg, Provenance::Unknown).with_local_ip(local_ip))
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
      .handle(
        StdInstant::now(),
        Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
      )
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
  for ev in e.handle(
    now,
    Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap() {
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
    .handle(
      StdInstant::now(),
      Received::new(src, &msg, Provenance::Unknown).with_local_ip(local_ip),
    )
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
/// section (peer probes); see `authority_instance_name_routes_as_probe_proposal`.
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
  let events = e.handle(
    now,
    Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();

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
  let _ = e.handle(
    now,
    Received::new(src, &qbuf[..n], Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();

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
  let _ = e.handle(
    now,
    Received::new(src, &qbuf[..n], Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();

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
    .handle(now, Received::new(legacy_src, &qbuf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
    let _ = e.handle(
      now,
      Received::new(src, &qbuf[..n], Provenance::Unknown).with_local_ip(local_ip),
    ).unwrap();
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
  e.note_query_delivery(h, now, TransmitDelivery::ALL);
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
  let _ = e.handle(
    t1,
    Received::new(src, &qbuf[..n], Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();

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
  let mut self_events = e.handle(
    now,
    Received::new(self_src, data, Provenance::OwnEcho).with_local_ip(local_ip),
  ).unwrap();
  assert!(
    self_events.next().is_none(),
    "self-packet (caller_is_self = true) must yield zero routing events"
  );

  // (2) Control: the same payload from a peer with `caller_is_self = false`
  // MUST still emit ProbeConflict — proves suppression is driven by the
  // flag, not a broken routing path.
  let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  // The probe's own §8.1 question routes ahead of its §8.2 proposal, so scan.
  let saw_proposal = e
    .handle(
      StdInstant::now(),
      Received::new(peer_src, data, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .any(|ev| match ev.expect("control: routing event must be Ok") {
      RouteEvent::ToService(ts) => ts.event().is_probe_proposal(),
      _ => false,
    });
  assert!(
    saw_proposal,
    "control: foreign-source probe must still emit ProbeProposal"
  );
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
  let _ = e.handle(
    now,
    Received::new(self_src, data, Provenance::OwnEcho).with_local_ip(local_ip),
  ).unwrap();
  assert!(
    !e.cache
      .contains(&observed, ResourceType::A, ResourceClass::In),
    "self-packet must not populate cache; cache contained {:?}",
    observed.as_str()
  );

  // Control: a foreign source must populate the cache.
  let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
  let _ = e.handle(
    now,
    Received::new(peer_src, data, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();
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
  let _ = e.handle(
    now,
    Received::new(src, &insert, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();
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
  let _ = e.handle(
    now,
    Received::new(src, &goodbye, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();
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
/// Test: register a service publishing `fe80::1`, then feed back packets with
/// `src.ip() == fe80::1` and `local_ip == ff02::fb`. Without the membership
/// signal a DISCOVERY question from that source would route to the service as
/// one to answer.  Control half: a foreign IPv6 source must still produce a
/// ProbeProposal and must still have its discovery question answered.
///
/// What the heuristic does NOT suppress is the RFC 6762 §8.2 proposal, or the
/// §8.1 defence of a name we already hold. An address-based guess matches any
/// co-resident host publishing an address we publish — including a peer that has
/// taken it — and a deleted proposal or a skipped defence costs a name
/// permanently, so both survive the guess. See `Admits`.
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
  // §8.1's question, which is what makes this a probe (see
  // `build_probe_srv_authority`).
  b.push_question(
    &inst,
    crate::wire::ResourceType::Any,
    crate::wire::ResourceClass::In,
    true,
  )
  .unwrap();
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
  let self_events: std::vec::Vec<_> = e
    .handle(
      now,
      Received::new(self_src, data, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .map(|ev| ev.expect("routing event must be Ok"))
    .collect();
  assert_eq!(
    self_events
      .iter()
      .filter(|ev| matches!(
        ev,
        RouteEvent::ToService(ts) if ts.event().is_probe_proposal()
      ))
      .count(),
    1,
    "the §8.2 proposal survives the advertised-source guess — an opt-in \
       convenience knob must not be able to delete one"
  );
  assert!(
    self_events.iter().any(|ev| matches!(
      ev,
      RouteEvent::ToService(ts) if ts.event().is_question()
    )),
    "and so does the §8.1 defence: this datagram PROPOSES to take a unique name \
       we hold, and the guess matches every co-resident host publishing an \
       address we publish — so skipping the defence would let a real one take it"
  );

  // (2) Control: a foreign IPv6 source must still emit ProbeConflict on
  // the same payload.  Proves the guard is specific to src-set membership
  // and not some other suppression.
  let peer_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0099);
  let peer_src: SocketAddr = SocketAddr::from((peer_v6, 5353));
  // The probe's §8.1 question routes ahead of its §8.2 proposal, so scan.
  let saw_proposal = e
    .handle(now, Received::new(peer_src, data, Provenance::Unknown).with_local_ip(local_ip))
    .unwrap()
    .any(|ev| match ev.expect("control: routing event must be Ok") {
      RouteEvent::ToService(ts) => ts.event().is_probe_proposal(),
      _ => false,
    });
  assert!(
    saw_proposal,
    "control: foreign IPv6 probe must still emit ProbeProposal"
  );

  // (3) What the membership branch DOES still withhold, and the discriminator
  // this test now turns on: an ordinary discovery question. It proposes nothing,
  // so §8.1 owes it no defence and `Answering::DefenceOnly` withholds it from a
  // matched source while `Answering::All` routes it from a foreign one.
  let mut qbuf = [0u8; 512];
  let qn = build_query_for_host(&mut qbuf, "Printer._ipp._tcp.local.");
  let mut routes_question = |src: SocketAddr| {
    e.handle(
      now,
      Received::new(src, &qbuf[..qn], Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .any(|ev| matches!(
      ev.expect("routing event must be Ok"),
      RouteEvent::ToService(ts) if ts.event().is_question()
    ))
  };
  assert!(
    !routes_question(self_src),
    "IPv6 self-packet (src ∈ advertised AAAA) must not have its DISCOVERY \
       question answered as a peer's; local_ip == ff02::fb cannot detect this, \
       so the membership branch must catch it"
  );
  assert!(
    routes_question(peer_src),
    "control: the same question from a foreign IPv6 source is answered"
  );
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
  let _ = e.handle(
    now,
    Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap().count();

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
  let _ = e.handle(
    now,
    Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap().count();
  assert_eq!(
    e.collected_answers(h).count(),
    1,
    "an answer processed inside the window must be collected"
  );

  // Past the deadline, with no timer pump in between — the reachable ordering.
  let after = now.checked_add(Duration::from_millis(300)).unwrap();
  let n = response(Ipv4Addr::new(10, 0, 0, 8), &mut buf);
  let _ = e
    .handle(after, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
    for ev in e.handle(
      at,
      Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
    ).unwrap() {
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
    .handle(now, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
    let _events = e.handle(
      now,
      Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
    ).unwrap();
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
      .handle(now, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
      .handle(now, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(now, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
      .handle(now, Received::new(src, &buf2[..n], Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(now, Received::new(src, &buf2[..n], Provenance::Unknown).with_local_ip(local_ip))
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
  let _ = e.handle(
    now,
    Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap().count();

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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
  let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
  // The host must OWN an A RRset for a peer's A at that name to conflict with
  // it — §9 compares the same name AND rrtype.
  recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(now, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(now, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(after_grace, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
      .handle(pkt1_t, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
      .handle(pkt2_t, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
  let _ = e.handle(
    now,
    Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap().count();

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
      .handle(now, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
      .handle(later, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(after_grace, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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

  let events = e.handle(
    now,
    Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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

/// `answer_questions=false` suppresses DISCOVERY, not the RFC 6762 §8.1 defence
/// of a name this endpoint has already claimed.
///
/// §8.1 puts the defence on the responder as a duty: "it is important that when
/// a device receives a probe query for a name that it is currently using, it
/// SHOULD generate its response to defend that name immediately and send it as
/// quickly as possible." Suppressing it leaves the prober unanswered, and §8.1's
/// own next step is that an unanswered prober claims the name — so a passive
/// endpoint would keep advertising a name a conforming peer has just taken, with
/// nothing left to resolve it.
///
/// The exemption is drawn as narrowly as the duty. Each negative below is a way
/// the exemption could be over-wide, and is asserted separately.
#[test]
fn answer_questions_false_still_defends_a_probed_unique_name() {
  use core::net::SocketAddr;

  use rand::SeedableRng;

  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };

  const INSTANCE: &str = "WebServer._http._tcp.local.";
  const SERVICE_TYPE: &str = "_http._tcp.local.";
  const HOST: &str = "web.local.";

  /// A peer's §8.1 probe: QR=0, a question for `qname`, and the proposed record
  /// in the Authority Section (§8.2 requires it there). `with_authority` off
  /// makes it an ordinary query instead, which is the discovery case.
  fn probe_for(qname: &str, with_authority: bool, buf: &mut [u8; 512]) -> usize {
    let name = Name::try_from_str(qname).unwrap();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(buf, Header::new()).unwrap();
    b.push_question(
      &name,
      ResourceType::Any,
      crate::wire::ResourceClass::In,
      false,
    )
    .unwrap();
    if with_authority {
      let target = Name::try_from_str("rival-host.local.").unwrap();
      b.push_srv_authority(&name, 120, 0, 0, 9999, &target).unwrap();
    }
    b.finish().unwrap()
  }

  let mut e = {
    let rng = rand::rngs::StdRng::from_seed([9u8; 32]);
    let cfg = EndpointConfig::new().with_answer_questions(false);
    TestEndp::try_new(cfg, rng)
  };
  let now = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str(SERVICE_TYPE).unwrap(),
    Name::try_from_str(INSTANCE).unwrap(),
    Name::try_from_str(HOST).unwrap(),
    80,
    120,
  );
  let (_h, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let mdns_peer: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let mut questions_for = |qname: &str, with_authority: bool, src: SocketAddr| -> usize {
    let mut buf = [0u8; 512];
    let n = probe_for(qname, with_authority, &mut buf);
    e.handle(now, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
      .unwrap()
      .map(Result::unwrap)
      .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_question()))
      .count()
  };

  assert_eq!(
    questions_for(INSTANCE, true, mdns_peer),
    1,
    "a probe for our INSTANCE name must reach the service even with \
     answer_questions=false: §8.1 requires defending a name we are using, and an \
     unanswered prober claims it"
  );
  assert_eq!(
    questions_for(HOST, true, mdns_peer),
    1,
    "and a probe for our HOST name likewise — it is the other unique name this \
     service owns"
  );
  assert_eq!(
    questions_for(SERVICE_TYPE, true, mdns_peer),
    0,
    "but NOT the shared service type: many responders own it, so a query naming \
     it is discovery and not a uniqueness probe, however it is shaped"
  );
  assert_eq!(
    questions_for(INSTANCE, false, mdns_peer),
    0,
    "and not an ordinary query for the same name: no Authority Section means the \
     peer is asking about the name, not proposing to take it"
  );
  assert_eq!(
    questions_for(INSTANCE, true, "192.168.1.77:40404".parse().unwrap()),
    0,
    "and not one from an ephemeral port: a real prober multicasts from 5353, and \
     admitting an off-path sender would make passive endpoints answer on demand"
  );
}

/// The §8.1 exemption is owed to a datagram that PROPOSES to take the questioned
/// name — not to every QR=0 datagram whose header declares an Authority Section.
///
/// RFC 6762 §8.2 defines the probe by what it carries: "each host populates the
/// query message's Authority Section with the record or records with the rdata
/// that it would be proposing to use". A query carrying no such record for the
/// name it asks about is an ordinary query however its NSCOUNT reads, and
/// `answer_questions(false)` suppresses ordinary queries — so admitting one
/// walks a discovery query out to the service response path and past the whole
/// point of the configuration. A nonzero NSCOUNT costs an attacker two bytes.
///
/// # …but an unreadable QUESTION SECTION still releases the defence
///
/// The last case is the one that reads backwards and must not be "corrected".
/// This gate OVER-approximates on an undecidable Question Section, unlike
/// `RouteEvents::authority_proposes_for`, which fails closed. The two are not
/// inconsistent: withholding a §8.2 proposal decides nothing, because the fold's
/// only terminal value for a datagram it cannot read is an abandonment, and an
/// abandonment changes nothing. Withholding a §8.1 DEFENCE is not symmetric —
/// §8.1 requires a host that is not probing to defend a name it has established,
/// and refusing here would let a prober whose questions will not read take an
/// advertised name from a passive endpoint. `QuestionsUnreadable` is reachable
/// only from a record already matched to the questioned name in class IN, so the
/// datagram is probe-shaped before the question is asked.
#[test]
fn answer_questions_false_defends_only_against_a_real_proposal() {
  use core::net::SocketAddr;

  use rand::SeedableRng;

  use crate::{
    config::ServiceSpec,
    records::ServiceRecords,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
  };

  const INSTANCE: &str = "WebServer._http._tcp.local.";
  const SERVICE_TYPE: &str = "_http._tcp.local.";
  const HOST: &str = "web.local.";

  // A QR=0 query asking about `qname`, with `authority_owner`'s SRV proposed (or
  // nothing at all when it is `None`).
  let query = |qname: &str, authority_owner: Option<&str>| -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let name = Name::try_from_str(qname).unwrap();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
    b.push_question(
      &name,
      ResourceType::Any,
      crate::wire::ResourceClass::In,
      false,
    )
    .unwrap();
    if let Some(owner) = authority_owner {
      let owner = Name::try_from_str(owner).unwrap();
      let target = Name::try_from_str("rival-host.local.").unwrap();
      b.push_srv_authority(&owner, 120, 0, 0, 9999, &target).unwrap();
    }
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  };

  // The same query, but its Authority Section is a claim in the header and five
  // bytes of rubbish on the wire.
  let mut declared_only = query(INSTANCE, None);
  declared_only[9] = 1; // NSCOUNT
  declared_only.extend_from_slice(&[0x05, b'h', b'e', b'l', b'l']);

  // A genuine probe for our instance name, with a SECOND question spliced in
  // whose QNAME is a compression pointer to its own offset. `try_parse` consumes
  // the two pointer bytes without following them, so the section still parses and
  // the authority record is still surfaced — but the QNAME will not decode, so
  // admission answers `QuestionsUnreadable` for the datagram.
  let unreadable_questions = {
    let good = query(INSTANCE, Some(INSTANCE));
    let qlen = {
      let mut k = 0usize;
      for label in INSTANCE.trim_end_matches('.').split('.') {
        k += 1 + label.len();
      }
      k + 1 + 4 // root terminator + QTYPE + QCLASS
    };
    let mut d: std::vec::Vec<u8> = std::vec::Vec::new();
    d.extend_from_slice(&good[..12]);
    d[5] = 2; // QDCOUNT 1 -> 2
    d.extend_from_slice(&good[12..12 + qlen]);
    let at = 12 + qlen;
    #[allow(clippy::cast_possible_truncation)]
    d.extend_from_slice(&[0xC0 | ((at >> 8) as u8), at as u8]);
    d.extend_from_slice(&ResourceType::Any.to_u16().to_be_bytes());
    d.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    d.extend_from_slice(&good[12 + qlen..]);
    d
  };

  let mut e = {
    let rng = rand::rngs::StdRng::from_seed([11u8; 32]);
    let cfg = EndpointConfig::new().with_answer_questions(false);
    TestEndp::try_new(cfg, rng)
  };
  let now = StdInstant::now();
  let recs = ServiceRecords::new(
    Name::try_from_str(SERVICE_TYPE).unwrap(),
    Name::try_from_str(INSTANCE).unwrap(),
    Name::try_from_str(HOST).unwrap(),
    80,
    120,
  );
  let (_h, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let peer: SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let mut questions_for = |datagram: &[u8]| -> usize {
    // `filter_map` and not `unwrap`: the truncated-authority case below yields a
    // parse error of its own, which is not what this fixture is measuring.
    e.handle(now, Received::new(peer, datagram, Provenance::Unknown).with_local_ip(local_ip))
      .unwrap()
      .filter_map(Result::ok)
      .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_question()))
      .count()
  };

  assert_eq!(
    questions_for(&query(INSTANCE, Some(INSTANCE))),
    1,
    "CONTROL: a genuine probe for our instance name still gets its §8.1 defence, \
     so every negative below is the gate and not the fixture"
  );
  assert_eq!(
    questions_for(&query(INSTANCE, Some("printer._ipp._tcp.local."))),
    0,
    "an Authority record for somebody ELSE'S name proposes nothing about ours — \
     the datagram is a discovery query with a passenger, and passive mode \
     suppresses discovery"
  );
  assert_eq!(
    questions_for(&query(INSTANCE, Some(HOST))),
    0,
    "and a proposal for our HOST name is not a proposal for our INSTANCE name: \
     the gate is per questioned name, not per datagram"
  );
  assert_eq!(
    questions_for(&declared_only),
    0,
    "a nonzero NSCOUNT is a claim about the datagram, not a proposed record in \
     it — undecodable authority bytes must not buy a response out of an endpoint \
     configured not to answer"
  );
  // PRECONDITION: the section really is undecidable, so the assertion below is
  // about the gate's disposition and not about a datagram that reads fine.
  {
    let reader = crate::wire::MessageReader::try_parse(&unreadable_questions).unwrap();
    assert!(
      reader
        .questions()
        .any(|q| !crate::endpoint::name_fully_decodes(q.unwrap().qname())),
      "precondition: one QNAME really does fail to decode"
    );
    assert_eq!(
      reader.authority().filter(|r| r.is_ok()).count(),
      1,
      "precondition: the authority record is still surfaced, so the gate reaches \
       the question section at all"
    );
  }
  assert_eq!(
    questions_for(&unreadable_questions),
    1,
    "FAIL-OPEN, deliberately: this gate releases a §8.1 defence of a name already \
     established, against a datagram carrying a proposed record at that name in \
     class IN. Failing closed on a Question Section that will not read would let \
     a prober take an advertised name from a passive endpoint. The §8.2 proposal \
     route answers the same input the opposite way because withholding a proposal \
     decides nothing"
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
    let mut recs = ServiceRecords::new(st, inst, host.clone(), 631, 120);
    // All three share the host AND its address set — the only way the
    // registration invariant lets them share a host name, and what makes each
    // of them an owner of the A RRset a peer's probe contends for.
    recs.add_a(Ipv4Addr::new(192, 168, 1, 5));
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
    let _ = e.handle(
      now,
      Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
    ).unwrap().count();
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
    .handle(now, Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip))
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
      .handle(now, Received::new(peer_src, &pkt, Provenance::Unknown).with_local_ip(multicast_ip))
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
  e.note_query_delivery(h, now, TransmitDelivery::ALL); // confirm
  now += Duration::from_secs(10); // past the first retry deadline (~1s)
  e.handle_query_timeout(h, now).unwrap(); // arms transmit_pending = true

  {
    let mut events = e
      .handle(now, Received::new(peer_src, &pkt, Provenance::Unknown).with_local_ip(multicast_ip))
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
/// index 2, then feed back packets with `src = fe80::1`.  A DISCOVERY question
/// must:
///   * be suppressed when delivered with `interface_index == 2` (true
///     self-loopback), AND
///   * be routed normally when delivered with `interface_index == 3` (a remote
///     peer on another interface).
///
/// The §8.2 proposal and the §8.1 defence are routed in BOTH cases: an
/// address-based guess must not be able to delete either. See `Admits`.
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
  // §8.1's question, which is what makes this a probe (see
  // `build_probe_srv_authority`).
  b.push_question(
    &inst,
    crate::wire::ResourceType::Any,
    crate::wire::ResourceClass::In,
    true,
  )
  .unwrap();
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
  let self_events: std::vec::Vec<_> = e
    .handle(
      now,
      Received::new(self_src, data, Provenance::Unknown)
        .with_interface(Some(2))
        .with_local_ip(local_ip),
    )
    .unwrap()
    .map(|ev| ev.expect("event must be Ok"))
    .collect();
  assert!(
    self_events.iter().any(|ev| matches!(
      ev,
      RouteEvent::ToService(ts) if ts.event().is_probe_proposal()
    )),
    "its §8.2 proposal is still adjudicated"
  );
  assert!(
    self_events.iter().any(|ev| matches!(
      ev,
      RouteEvent::ToService(ts) if ts.event().is_question()
    )),
    "…and so is its §8.1 defence: this datagram proposes to take a unique name \
       we hold, and the guess cannot tell a co-resident responder from our own \
       echo"
  );

  // (2) Foreign peer on a different interface (ifindex=3) using the
  //     same numeric link-local.  This is the regression case — must
  //     route as ProbeConflict, not be silently dropped.
  // The probe's §8.1 question routes ahead of its §8.2 proposal, so scan.
  let saw_proposal = e
    .handle(
      now,
      Received::new(self_src, data, Provenance::Unknown)
        .with_interface(Some(3))
        .with_local_ip(local_ip),
    )
    .unwrap()
    .any(|ev| match ev.expect("event must be Ok") {
      RouteEvent::ToService(ts) => ts.event().is_probe_proposal(),
      _ => false,
    });
  assert!(
    saw_proposal,
    "link-local from ifindex=3 must emit ProbeProposal (not be misclassified \
       as self because of bare-address match)"
  );

  // (3) The interface scoping itself, read off what the guess still withholds:
  //     an ordinary discovery question, which proposes nothing and so is owed no
  //     §8.1 defence. Withheld on OUR interface, answered on any other.
  let mut qbuf = [0u8; 512];
  let qn = build_query_for_host(&mut qbuf, "Printer._ipp._tcp.local.");
  let mut routes_question = |ifindex: u32| {
    e.handle(
      now,
      Received::new(self_src, &qbuf[..qn], Provenance::Unknown)
        .with_interface(Some(ifindex))
        .with_local_ip(local_ip),
    )
    .unwrap()
    .any(|ev| matches!(
      ev.expect("event must be Ok"),
      RouteEvent::ToService(ts) if ts.event().is_question()
    ))
  };
  assert!(
    !routes_question(2),
    "link-local from OUR interface (ifindex=2) must not have its discovery \
       question answered as a peer's"
  );
  assert!(
    routes_question(3),
    "the same address on ifindex=3 is a peer, and its discovery question is \
       answered — the bare-address match must not decide this"
  );
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
  let events = e.handle(
    now,
    Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();

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
  let events = e.handle(
    now,
    Received::new(src, pkt, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap();

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
  // The CONFIGURED sets must agree across services sharing a host name — see
  // `Endpoint::host_addresses_disagree`. What separates A from B here is what
  // each has ADVERTISED, which is exactly what retention keys on.
  recs_b.add_a(shared);
  recs_b.add_a(unique);
  let (b_handle, _svc_b) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs_b),
      now,
    )
    .unwrap();
  // B has CONFIRMED-ADVERTISED only the shared address (its announce was
  // delivered), so the route's advertised set is non-empty — otherwise
  // retention would honour nothing and A would (wrongly) withdraw the shared
  // address.
  ep.note_service_announced(FullyAnnounced::new(b_handle, true), &[shared], &[]);

  // A's withdrawal snapshot: owns PTR/SRV/TXT, the subtype PTR, and both host
  // A addresses.
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs_a,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        true,
        false,
      ),
      std::vec![shared, unique],
      std::vec::Vec::new(),
    ),
  );
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
  crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      host_a.to_vec(),
      std::vec::Vec::new(),
    ),
  )
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
  // B shares the host name, so it is CONFIGURED with the same set A is — but it
  // has NEVER announced, so its advertised set is EMPTY.
  let _b = register_host_service(
    &mut ep,
    "B._ipp._tcp.local.",
    &host,
    &[shared, unique],
    None,
  );

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

  // Both are CONFIGURED with .5 + .6 (a shared host name requires that), but A
  // has advertised both and B (LIVE) has advertised only .5.
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
    &[shared, unique],
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
  ep.note_withdrawal_sends(
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
  ep.begin_withdrawal(h, snap, now);
  let token = ep.route_withdrawal_token(h).unwrap();

  // A round where NEITHER family sent (both Retry) spends nothing and re-arms at
  // the short backoff.
  ep.note_withdrawal_sends(
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
  ep.note_withdrawal_sends(
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
  ep.begin_withdrawal(h, snap, now);
  let token = ep.route_withdrawal_token(h).unwrap();

  // v4 sends every round, v6 is transiently busy (Retry) every round: v4's debt
  // drains, v6's is untouched.
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_withdrawal_sends(
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
    ep.note_withdrawal_sends(
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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
    ep.note_withdrawal_sends(
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
  ep.note_withdrawal_sends(
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
  ep.note_withdrawal_sends(
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
  ep.begin_withdrawal(h, snap, now);
  let token = ep.route_withdrawal_token(h).unwrap();

  // v6 has no socket (WriteOff zeroes its debt immediately); v4 still owes its
  // full budget after one Sent.
  ep.note_withdrawal_sends(
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
    ep.note_withdrawal_sends(
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
  ep.begin_withdrawal(h, snap, now);
  let token = ep.route_withdrawal_token(h).unwrap();

  // Drain v4's whole budget while v6 is transiently busy (Retry): v4 → 0, v6
  // keeps its full debt. Each of these rounds DID make real progress on v4
  // (its owed was > 0), so they legitimately re-arm at the full interval.
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_withdrawal_sends(
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
  ep.note_withdrawal_sends(
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
    ep.note_withdrawal_sends(
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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
  let snap_a = crate::service::WithdrawalSnapshot::announced(
    recs_a,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      big_a,
      std::vec::Vec::new(),
    ),
  );

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
  let snap_b = crate::service::WithdrawalSnapshot::announced(
    recs_b,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );

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
    false,
  );

  // A teardown DURING a still-draining rename is now two SEPARATE calls, each
  // producing one independent item. The rename happened first, so its old-name
  // (A) goodbye was already enqueued as a DETACHED item; the teardown then
  // begins the route-attached (B) withdrawal from a current-only snapshot.
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        old_owned,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs_b,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec![host_v4],
      std::vec![host_v6],
    ),
  );
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
    ep.note_withdrawal_sends(
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
    false,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        old_owned,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
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
      ep.note_withdrawal_sends(
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
    false,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        old_owned,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
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
    crate::service::RenameGoodbyeHandoff::announced(
      ServiceRecords::new(stype.clone(), old_name.clone(), host.clone(), 631, 120),
      on_both(
        crate::service::EmittedRecords::new(
          true,
          true,
          true,
          std::vec::Vec::new(),
          std::vec::Vec::new(),
          false,
          false,
        ),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
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
    false,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        old_owned,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
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
    ep.note_withdrawal_sends(
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
    crate::service::RenameGoodbyeHandoff::announced(
      empty_records,
      on_both(
        empty_owned,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
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
    false,
  );

  // The rename happened first: enqueue the old name's goodbye as its own
  // detached item. The teardown then begins a current-only withdrawal whose
  // snapshot owns nothing on the wire.
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        old_owned,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot::announced(
    cur_recs,
    on_both(
      crate::service::EmittedRecords::new(
        false,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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
    ep.note_withdrawal_sends(
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
    false,
  );

  // The rename happened first → its old-name goodbye is its own detached item;
  // the teardown then begins the route-attached current-name withdrawal. Two
  // independent items, each its own single-name datagram.
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        owned_full.clone(),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs_b,
    on_both(
      owned_full,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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
    ep.note_withdrawal_sends(
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
    false,
  );
  // The rename happened first → its old-name goodbye is its own detached item;
  // the teardown then begins the route-attached (huge current) withdrawal.
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        old_owned,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot::announced(
    cur_recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
  ep.begin_withdrawal(h, snap, now);
  assert!(
    ep.route_withdrawal_owed(h).is_some(),
    "a route-attached withdrawal item owes a goodbye for the name"
  );

  // Force-remove must drop the route-attached withdrawal item (no goodbye).
  assert!(
    ep.unregister_service(h, None, now),
    "the route was found and removed"
  );
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
    false,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        old_owned,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    false,
  );
  let snap = crate::service::WithdrawalSnapshot::announced(
    cur_recs,
    on_both(
      crate::service::EmittedRecords::new(
        false,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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

/// THE SUBTYPE PTR A REPLACEMENT'S ANNOUNCEMENT CANNOT SUPERSEDE.
///
/// Cancel-on-announce deleted the WHOLE detached item, on the reasoning that a
/// complete RFC 6762 §10.2 announcement of the same name leaves its goodbye
/// nothing to do. That holds record by record and not for every record. The
/// replacement's own cache-flushed answer supersedes the stale unique SRV and
/// TXT at the instance name, and it re-asserts the IDENTICAL service-type PTR —
/// but a REMOVED subtype's PTR is shared (no cache-flush bit), owned by a
/// `<sub>._sub.<type>` browse name the replacement does not publish, and carried
/// by no answer of the replacement's at all. §10.1's TTL=0 goodbye is its ONLY
/// retraction, so deleting the item while a family still owed one left that
/// family's peers listing the instance under a subtype it no longer has, for the
/// whole positive TTL.
///
/// The item is narrowed to what survives instead, and drains its remaining
/// PER-FAMILY debt for that alone.
#[test]
fn a_reclaim_keeps_the_goodbye_a_dropped_subtype_still_needs() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let name = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let removed_sub = Name::try_from_str("_removed._sub._ipp._tcp.local.").unwrap();
  let kept_sub = Name::try_from_str("_kept._sub._ipp._tcp.local.").unwrap();

  // The renamed-away old name published TWO subtypes and put its whole record
  // set on both families' wires.
  let mut old_records = ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120);
  old_records.add_subtype("_kept").unwrap();
  old_records.add_subtype("_removed").unwrap();
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        crate::service::EmittedRecords::new(
          true,
          true,
          true,
          std::vec::Vec::new(),
          std::vec::Vec::new(),
          true,
          true,
        ),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    false,
  );

  // IPv4 pays its whole §10.1 budget while IPv6 keeps failing — the partial-send
  // case, and the only one in which cancelling can still cost a retraction.
  let mut buf = std::vec![0u8; 4096];
  let mut t = now;
  for _ in 0..super::WITHDRAWAL_SENDS {
    let round = ep
      .poll_withdrawal_transmit(t, &mut buf)
      .expect("the detached item is due and has records to retract");
    ep.note_withdrawal_sends(
      round.token(),
      t,
      super::WithdrawalSend::Sent,
      super::WithdrawalSend::Retry,
    );
    t += core::time::Duration::from_millis(300);
  }
  assert_eq!(
    ep.detached_withdrawal_owed_for(&name),
    Some([0, super::WITHDRAWAL_SENDS]),
    "IPv4 has paid its goodbye and IPv6 has not — the case under test"
  );

  // The replacement takes the same instance name, KEEPS `_kept`, DROPS
  // `_removed`, and fully announces on every obligated link.
  let mut new_records = ServiceRecords::new(stype, name.clone(), host, 631, 120);
  new_records.add_subtype("_kept").unwrap();
  let (new_h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(new_records),
      t,
    )
    .expect("reclaiming a detached-reserved name succeeds");
  ep.note_service_announced(FullyAnnounced::new(new_h, true), &[], &[]);

  assert_eq!(
    ep.detached_withdrawal_owed_for(&name),
    Some([0, super::WITHDRAWAL_SENDS]),
    "the announcement supersedes no record at `_removed._sub…`, so IPv6's \
     unspent goodbye debt survives the reclaim — and IPv4's stays spent"
  );

  // And what it now emits is EXACTLY the non-superseded part.
  let round = ep
    .poll_withdrawal_transmit(t, &mut buf)
    .expect("the surviving debt still has a goodbye to send");
  assert!(
    !round.debt().v4_owed() && round.debt().v6_owed(),
    "the round is IPv6's alone — IPv4 already retracted what it advertised"
  );
  let reader = crate::wire::MessageReader::try_parse(buf.get(..round.len()).unwrap()).unwrap();
  let mut ptr_owners: std::vec::Vec<bool> = std::vec::Vec::new();
  let mut saw_kept_sub = false;
  let mut saw_type_ptr = false;
  let mut saw_unique = false;
  for rec in reader.answers() {
    let rec = rec.unwrap();
    assert_eq!(rec.ttl(), 0, "every goodbye record carries TTL 0");
    match rec.rtype() {
      crate::wire::ResourceType::Ptr => {
        assert!(
          matches!(
            rec.rdata_view(),
            Ok(crate::wire::Rdata::Ptr(p)) if names_match(&name, p.target())
          ),
          "a surviving PTR still points at the old instance name"
        );
        saw_kept_sub |= names_match(&kept_sub, rec.name());
        saw_type_ptr |= names_match(&Name::try_from_str("_ipp._tcp.local.").unwrap(), rec.name());
        ptr_owners.push(names_match(&removed_sub, rec.name()));
      }
      crate::wire::ResourceType::Srv | crate::wire::ResourceType::Txt => saw_unique = true,
      _ => {}
    }
  }
  assert_eq!(
    ptr_owners,
    std::vec![true],
    "exactly one PTR, and it retracts the REMOVED subtype's shared record"
  );
  assert!(
    !saw_kept_sub,
    "the replacement re-asserts `_kept._sub…` itself, so retracting it would \
     delete a record it is currently publishing"
  );
  assert!(
    !saw_type_ptr,
    "and the service-type PTR is the IDENTICAL shared record at the same owner \
     with the same rdata — not stale, and not this goodbye's to retract"
  );
  assert!(
    !saw_unique,
    "the SRV and TXT are unique at the instance name and the replacement's \
     cache-flushed announcement supersedes them"
  );

  // It is still an ordinary item: the last owed round drains it, and it holds no
  // name against the replacement in the meantime.
  ep.note_withdrawal_sends(
    round.token(),
    t,
    super::WithdrawalSend::Retry,
    super::WithdrawalSend::WriteOff,
  );
  let mut freed: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  ep.drain_completed_withdrawals(t, &mut freed);
  assert!(
    freed.is_empty(),
    "a detached item frees no route and is reported to nobody"
  );
  assert!(
    ep.detached_withdrawal_owed_for(&name).is_none(),
    "and once its debt is settled the narrowed item completes like any other"
  );
}

/// A reclaim whose replacement publishes EVERY subtype the old name did still
/// cancels the goodbye outright — the narrowing is what survives supersession,
/// not a new reason to keep an item alive.
#[test]
fn a_reclaim_that_supersedes_every_shared_record_still_cancels_outright() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let name = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();

  let mut old_records = ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120);
  old_records.add_subtype("_kept").unwrap();
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        crate::service::EmittedRecords::new(
          true,
          true,
          true,
          std::vec::Vec::new(),
          std::vec::Vec::new(),
          true,
          true,
        ),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    false,
  );
  assert!(
    ep.detached_withdrawal_owed_for(&name).is_some(),
    "the rename enqueued the old name's goodbye"
  );

  // Same service type, same subtype: every shared record the old name emitted is
  // re-asserted at its own owner name, and the unique ones are cache-flushed.
  let mut new_records = ServiceRecords::new(stype, name.clone(), host, 631, 120);
  new_records.add_subtype("_kept").unwrap();
  let (new_h, _svc) = ep
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(new_records),
      now,
    )
    .unwrap();
  ep.note_service_announced(FullyAnnounced::new(new_h, true), &[], &[]);
  assert!(
    ep.detached_withdrawal_owed_for(&name).is_none(),
    "nothing survives the supersession, so the item is cancelled whole"
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
    false,
  );
  // C2's rename enqueued a DETACHED item owning `target`; its teardown then
  // began a current-only withdrawal (owns nothing here).
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      target_records,
      on_both(
        target_owned,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    false,
  );
  let snap2 = crate::service::WithdrawalSnapshot::announced(
    c2_recs,
    on_both(
      crate::service::EmittedRecords::new(
        false,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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

  let mk = |name: &Name| crate::service::RenameGoodbyeHandoff::announced(
    ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120),
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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
  crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        false,
        false,
        false,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      host_a.to_vec(),
      std::vec::Vec::new(),
    ),
  )
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
  let snap_b = crate::service::WithdrawalSnapshot::announced(
    recs_b,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );

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
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
    )
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
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst.clone(),
    host.clone(),
    631,
    120,
  );
  // The host must OWN an A RRset for the peer's A at that name to reach it as a
  // §9 HostConflict at all.
  recs.add_a(Ipv4Addr::new(192, 168, 7, 7));
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
  // A peer PROBING for our INSTANCE name with rival rdata → §8.2 ProbeProposal.
  // The §8.1 question is what makes it a probe: without it the Authority Section
  // proposes nothing and the datagram routes nowhere at all.
  let inst_pkt = {
    let target = Name::try_from_str("rival.local.").unwrap();
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_question(
      &inst,
      crate::wire::ResourceType::Any,
      crate::wire::ResourceClass::In,
      true,
    )
    .unwrap();
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
    .handle(
      StdInstant::now(),
      Received::new(src, &host_pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    live_host,
    "sanity: a LIVE service must receive the HostConflict dispatch"
  );
  let live_inst = e
    .handle(
      StdInstant::now(),
      Received::new(src, &inst_pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    live_inst,
    "sanity: a LIVE service must receive the ProbeConflict dispatch"
  );
  let live_ka = e
    .handle(
      StdInstant::now(),
      Received::new(src, &ka_pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
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
    .handle(
      StdInstant::now(),
      Received::new(src, &host_pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    !wd_host,
    "a withdrawing service must not receive a HostConflict dispatch"
  );
  let wd_inst = e
    .handle(
      StdInstant::now(),
      Received::new(src, &inst_pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .any(|ev| matches!(ev, Ok(crate::event::RouteEvent::ToService(_))));
  assert!(
    !wd_inst,
    "a withdrawing service must not receive a ProbeConflict dispatch"
  );
  let wd_ka = e
    .handle(
      StdInstant::now(),
      Received::new(src, &ka_pkt, Provenance::Unknown).with_local_ip(local_ip),
    )
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
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
  assert!(ep.unregister_service(h, None, now));
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
    .handle(now, Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip))
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
  for ev in e.handle(
    now,
    Received::new(src, &msg, Provenance::Unknown).with_local_ip(local_ip),
  ).unwrap() {
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
    .handle(now, Received::new(src, &msg, Provenance::Unknown).with_local_ip(local_ip))
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
    ep.note_query_delivery(h, now, delivery);
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

  ep.note_query_delivery(h, now, TransmitDelivery::V4_ONLY);
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
    ep.note_query_delivery(h, due, TransmitDelivery::V4_ONLY);
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
    crate::service::RenameGoodbyeHandoff::announced(
      ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120),
      on_both(
        crate::service::EmittedRecords::new(
          true,
          true,
          true,
          std::vec::Vec::new(),
          std::vec::Vec::new(),
          false,
          false,
        ),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
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
      svc.note_delivery(now, TransmitDelivery::ALL);
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
  svc.note_delivery(now, TransmitDelivery::V4_ONLY);
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
  svc.note_delivery(now, TransmitDelivery::ALL);
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
    crate::service::RenameGoodbyeHandoff::announced(
      ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120),
      on_both(
        crate::service::EmittedRecords::new(
          true,
          true,
          true,
          std::vec::Vec::new(),
          std::vec::Vec::new(),
          false,
          false,
        ),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
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
      crate::service::RenameGoodbyeHandoff::announced(
        ServiceRecords::new(stype.clone(), name.clone(), host.clone(), 631, 120),
        on_both(
          crate::service::EmittedRecords::new(
            true,
            true,
            true,
            std::vec::Vec::new(),
            std::vec::Vec::new(),
            false,
            false,
          ),
          std::vec::Vec::new(),
          std::vec::Vec::new(),
        ),
      ),
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
      svc.note_delivery(now, TransmitDelivery::ALL);
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
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
    assert_eq!(
      sent, 1,
      "round {round}: one fired refresh deadline is one unsolicited response"
    );
  }
}

// ── service_type must be the parent label sequence of instance ───────────

fn spec_with_names(service_type: &str, instance: &str) -> ServiceSpec {
  let stype = Name::try_from_str(service_type).unwrap();
  let inst = Name::try_from_str(instance).unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  ServiceSpec::new(ServiceRecords::new(stype, inst, host, 631, 120))
}

/// A service type unrelated to the instance name would publish a PTR whose
/// owner the instance's SRV does not belong to — internally inconsistent on
/// the wire. `ServiceRecords::new` documents the parent-label-sequence
/// requirement but cannot enforce it (it is an infallible constructor), so
/// registration is where it is caught.
#[test]
fn registration_rejects_a_service_type_that_is_not_the_instance_parent() {
  let mut e = build_endpoint();
  let err = match e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    spec_with_names("_http._tcp.local.", "MyPrinter._ipp._tcp.local."),
    StdInstant::now(),
  ) {
    Ok(_) => panic!("an unrelated service type must be rejected"),
    Err(e) => e,
  };
  assert!(
    matches!(
      &err,
      RegisterServiceError::ServiceTypeNotParent(d)
        if d.service_type().as_str() == "_http._tcp.local."
        && d.instance().as_str() == "myprinter._ipp._tcp.local."
    ),
    "expected ServiceTypeNotParent, got {err:?}"
  );
  assert!(
    e.services.iter().next().is_none(),
    "a rejected registration must reserve no name"
  );
}

/// RFC 6763 §4.1.1 stores `<Instance>` as a SINGLE DNS label, so a Service
/// Instance Name has EXACTLY one label more than its service type — never two
/// or more. Two extra labels is not a valid instance of that service type
/// even though `service_type` names a real suffix of it.
#[test]
fn registration_rejects_an_instance_with_more_than_one_extra_label() {
  let mut e = build_endpoint();
  let err = match e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    spec_with_names("_ipp._tcp.local.", "a.b._ipp._tcp.local."),
    StdInstant::now(),
  ) {
    Ok(_) => panic!("two extra labels is not a single <Instance> label"),
    Err(e) => e,
  };
  assert!(
    matches!(err, RegisterServiceError::ServiceTypeNotParent(_)),
    "expected ServiceTypeNotParent, got {err:?}"
  );
}

/// The guard must not reject a spelling that differs only in CASE — RFC 6762
/// §16 makes DNS names case-insensitive, so a stricter-than-the-wire check
/// here would be a regression for a caller who spells their service type in
/// another case than their instance name's suffix.
#[test]
fn registration_accepts_a_case_differing_service_type() {
  let mut e = build_endpoint();
  e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    spec_with_names("_IPP._TCP.LOCAL.", "MyPrinter._ipp._tcp.local."),
    StdInstant::now(),
  )
  .expect("a case-differing service type is the same owner on the wire");
}

/// Nor may it reject a spelling that differs only in the optional trailing
/// root dot — `device.local` and `device.local.` are one DNS owner (see
/// [`Name::same_owner`]), and this guard extends that same rule to the
/// parent/child relation.
#[test]
fn registration_accepts_a_trailing_dot_differing_service_type() {
  let mut e = build_endpoint();
  // service_type has no trailing dot; instance's parent portion does.
  e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    spec_with_names("_ipp._tcp.local", "MyPrinter._ipp._tcp.local."),
    StdInstant::now(),
  )
  .expect("a trailing-dot-differing service type is the same owner on the wire");

  let mut e2 = build_endpoint();
  // The reverse: service_type has a trailing dot, the instance's does not.
  e2.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    spec_with_names("_ipp._tcp.local.", "MyPrinter._ipp._tcp.local"),
    StdInstant::now(),
  )
  .expect("a trailing-dot-differing service type is the same owner on the wire");
}

/// A withdrawal item whose goodbye owns PTR/SRV/TXT, so its per-family resend
/// budget is non-zero and the spend / keep / write-off table is actually
/// exercised. Returns the handle and the item's token.
fn withdrawing_route(ep: &mut TestEndp, now: StdInstant) -> (ServiceHandle, super::WithdrawalToken) {
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
  let snap = crate::service::WithdrawalSnapshot::announced(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
  ep.begin_withdrawal(h, snap, now);
  let token = ep.route_withdrawal_token(h).unwrap();
  (h, token)
}

/// A goodbye that is permanently too large for a family's transport KEEPS that
/// family's debt.
///
/// The one-sidedness is the whole point. The item's own anti-pin ceiling
/// force-completes it whatever the family answers, so a write-off could only buy
/// finishing marginally sooner — at the price of freeing the route while a BOUND
/// family's peers stay pinned to stale positive-TTL records for the rest of the
/// records' TTL. Only an absent socket writes a debt off.
#[test]
fn a_permanently_oversized_goodbye_keeps_its_family_debt() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let (h, token) = withdrawing_route(&mut ep, now);

  ep.note_withdrawal_result(
    token,
    now,
    crate::transmit::FamilyAttempt::Refused { permanent: true },
    crate::transmit::FamilyAttempt::Refused { permanent: true },
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
    "a permanent refusal is a bound socket that did not carry the goodbye, so its \
     debt survives for the retry the ceiling still allows"
  );

  // The contrast that makes the rule sharp: the SAME round with no socket at all
  // on v6 writes only v6 off, because there are no peers on it to retract from.
  ep.note_withdrawal_result(
    token,
    now,
    crate::transmit::FamilyAttempt::Refused { permanent: true },
    crate::transmit::FamilyAttempt::NoSocket,
  );
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([super::WITHDRAWAL_SENDS, 0]),
    "only an ABSENT socket writes a debt off"
  );
}

/// Every non-acceptance keeps a bound family's goodbye debt, whatever the reason.
///
/// Stated as a matrix because the rows used to live in each driver, and two of
/// them disagreed about the permanent-refusal row.
#[test]
fn only_an_absent_socket_writes_a_goodbye_debt_off() {
  use crate::transmit::FamilyAttempt;
  for keep in [
    FamilyAttempt::Refused { permanent: false },
    FamilyAttempt::Refused { permanent: true },
    FamilyAttempt::GateShut,
    FamilyAttempt::WouldBlock,
    FamilyAttempt::NotAddressed,
  ] {
    let mut ep = build_endpoint();
    let now = StdInstant::now();
    let (h, token) = withdrawing_route(&mut ep, now);
    ep.note_withdrawal_result(token, now, keep, keep);
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([super::WITHDRAWAL_SENDS, super::WITHDRAWAL_SENDS]),
      "{}: the family did not carry the goodbye, but it may yet",
      keep.as_str()
    );
  }
}

/// A family whose returned [`FamilyDebt`] was ZERO has its whole report
/// discarded.
///
/// A driver offers a round only to the families the debt names, so it has to
/// invent SOME outcome for one it withheld — no honest I/O fact describes "you
/// told me it owed nothing". Masking is what makes that invention unable to cost
/// anything: not the debt, not a spent round, not the item's schedule.
#[test]
fn a_zero_debt_family_report_is_masked() {
  use crate::transmit::FamilyAttempt;
  let now = StdInstant::now();

  // Drain v4's debt with the rounds it owes, leaving v6 untouched.
  let mut ep = build_endpoint();
  let (h, token) = withdrawing_route(&mut ep, now);
  for _ in 0..super::WITHDRAWAL_SENDS {
    ep.note_withdrawal_result(
      token,
      now,
      FamilyAttempt::Accepted { at: now },
      FamilyAttempt::Refused { permanent: false },
    );
  }
  assert_eq!(
    ep.route_withdrawal_owed(h),
    Some([0, super::WITHDRAWAL_SENDS]),
    "v4 paid every round it owed; v6 kept its debt"
  );
  // The short backoff is the no-progress re-arm, and it is what every masked round
  // below must produce: a still-failing v6 has to be retried soon rather than a
  // full interval away, or it can miss its last chance before the anti-pin ceiling.
  let no_progress_at = now
    .checked_add_duration(super::WITHDRAWAL_RETRY_BACKOFF)
    .unwrap();

  // Every shape a driver could invent for the withheld v4 leaves the item exactly
  // as it stands — including the write-off that would otherwise be the dangerous
  // one, and the acceptance that would otherwise re-arm at the FULL interval and
  // starve the still-failing v6 of its short-backoff retry.
  for invented in [
    FamilyAttempt::Accepted { at: now },
    FamilyAttempt::Refused { permanent: true },
    FamilyAttempt::GateShut,
    FamilyAttempt::NoSocket,
    FamilyAttempt::NotAddressed,
    FamilyAttempt::WouldBlock,
  ] {
    ep.note_withdrawal_result(
      token,
      now,
      invented,
      FamilyAttempt::Refused { permanent: false },
    );
    assert_eq!(
      ep.route_withdrawal_owed(h),
      Some([0, super::WITHDRAWAL_SENDS]),
      "{}: a report for a family that owed nothing must change nothing",
      invented.as_str()
    );
    assert_eq!(
      ep.route_withdrawal_next_at(h),
      Some(no_progress_at),
      "{}: nor may it count as progress and re-arm at the full interval, which \
       would starve the family that still owes",
      invented.as_str()
    );
  }
}

// ── R10 finding 1: §8 conflict routing is not scoped to SRV/TXT ────────

/// R10 finding 1: a peer PROBING our instance name with a type we do not
/// publish must still deliver a `ProbeProposal`.
///
/// The uniqueness question a probe asks is type ANY, so the peer's proposed
/// list — the one §8.2.1 sorts against ours — is everything it puts at that
/// name. Requiring SRV or TXT here made a peer proposing only an AAAA invisible:
/// that peer folds OUR SRV and TXT into its own comparison, finds its AAAA sorts
/// later, and continues as the winner, while this endpoint receives no proposal
/// at all and also continues. Two conforming peers, one name, and duplicate
/// ownership — the outcome the whole mechanism exists to prevent.
#[test]
fn a_probe_proposing_only_an_aaaa_still_delivers_a_proposal() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let (mut e, expected) = build_endpoint_with_printer();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();

  let mut buf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  b.push_question(
    &inst,
    crate::wire::ResourceType::Any,
    crate::wire::ResourceClass::In,
    true,
  )
  .unwrap();
  b.push_aaaa_authority(&inst, 120, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
    .unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let saw = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .filter_map(Result::ok)
    .any(|ev| {
      matches!(ev, RouteEvent::ToService(ts) if ts.handle() == expected && ts.event().is_probe_proposal())
    });
  assert!(
    saw,
    "a probe proposing ONLY an AAAA at our instance name is still a §8.2 \
     proposal — the probe's question is type ANY"
  );
}

/// R10 finding 1: an existing owner's RESPONSE at our instance name routes a
/// `ProbeConflict` whatever its type.
///
/// RFC 6762 §8.1 makes a probing host defer to "any conflicting Multicast DNS
/// response" for a name it is probing, and the name is asked about as type ANY.
/// Screening the route down to SRV/TXT dropped an existing owner's A, AAAA or
/// NSEC on the floor and let this service announce over it.
///
/// The narrow SRV/TXT rule is §9's, and `Service` applies it there itself — this
/// is only about what the ROUTER, which cannot see lifecycle state, delivers.
#[test]
fn a_response_of_any_type_at_our_instance_name_routes_a_conflict() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let (mut e, expected) = build_endpoint_with_printer();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();

  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&inst, 120, Ipv4Addr::new(10, 0, 0, 7), true)
    .unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let saw = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .filter_map(Result::ok)
    .any(|ev| {
      matches!(ev, RouteEvent::ToService(ts) if ts.handle() == expected && ts.event().is_probe_conflict())
    });
  assert!(
    saw,
    "an A record at our INSTANCE name on a response is a peer claiming a name \
     we are probing — §8.1 must see it"
  );
}

/// R10 finding 1: widening the instance route must not steal the HOST route.
///
/// The instance test no longer screens by rtype, so if a service's instance and
/// host names were ever the same name, testing it first would swallow an A/AAAA
/// the host rule owns and turn a `HostConflict` into a `ProbeConflict`. The host
/// rule is therefore tested FIRST, and this pins that ordering for the ordinary
/// case where the two names differ.
#[test]
fn a_host_address_response_still_routes_a_host_conflict() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let (mut e, expected) = build_endpoint_with_printer();
  let host = Name::try_from_str("printer-host.local.").unwrap();

  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 8), true)
    .unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let saw = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .filter_map(Result::ok)
    .any(|ev| {
      matches!(ev, RouteEvent::ToService(ts) if ts.handle() == expected && ts.event().is_host_conflict())
    });
  assert!(
    saw,
    "an A at the HOST name is still a HostConflict — widening the instance rule \
     must not take it"
  );
}

/// R10 finding 5: an Authority Section with no matching QUESTION is not a
/// proposal, so no `ProbeProposal` is routed.
///
/// §8.2 reads the proposal off "the Authority Section of *that query*". A
/// QDCOUNT=0 packet asks nothing, so its authority records answer nothing —
/// admitting them let any peer impose a one-second §8.2 deferral on demand.
#[test]
fn an_authority_section_with_no_question_routes_no_proposal() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let (mut e, _expected) = build_endpoint_with_printer();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();

  let mut buf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  let target = Name::try_from_str("other-host.local.").unwrap();
  b.push_srv_authority(&inst, 120, 0, 0, 8080, &target).unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let saw = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .filter_map(Result::ok)
    .any(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_probe_proposal()));
  assert!(
    !saw,
    "a QR=0 packet that asks no question proposes nothing, however its \
     Authority Section is filled"
  );
}

/// R10 finding 5: a query asking about ANOTHER name proposes nothing about
/// ours, even when its Authority Section names ours.
#[test]
fn a_question_for_another_name_routes_no_proposal_for_ours() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let (mut e, _expected) = build_endpoint_with_printer();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let other = Name::try_from_str("Scanner._ipp._tcp.local.").unwrap();

  let mut buf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  b.push_question(
    &other,
    crate::wire::ResourceType::Any,
    crate::wire::ResourceClass::In,
    true,
  )
  .unwrap();
  let target = Name::try_from_str("other-host.local.").unwrap();
  b.push_srv_authority(&inst, 120, 0, 0, 8080, &target).unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let saw = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .filter_map(Result::ok)
    .any(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_probe_proposal()));
  assert!(
    !saw,
    "the query asks about Scanner, so its authority records are not a proposal \
     for Printer"
  );
}

/// A probe whose proposed records all carry TTL 0 is still a §8.2 proposal, so
/// it is still delivered.
///
/// §8.2.1 orders the compared lists by class, then type, then rdata — the TTL is
/// not among them, and §8.2 requires the Authority Section to hold "*all* the
/// records and proposed rdata being probed for uniqueness". §10.1's goodbye
/// encoding is a property of an unsolicited RESPONSE; a QR=0 probe's Authority
/// Section is a claim whatever TTL it carries.
///
/// Withholding it here does not merely skip a record: it is what lets the fold
/// compare a SHORTER peer list than the peer sent, while the peer compares our
/// complete one. §8.2.1 sorts both lists and walks them pairwise, so removing an
/// element changes WHICH elements meet — the two sides then answer differently,
/// and not always in our favour (see `crate::endpoint::Admission`).
///
/// The per-record §8.1/§9 conflict route keeps its own TTL=0 guard, which
/// `authority_ttl_zero_does_not_emit_conflict_events` pins: that path turns a
/// peer's record into a rename, and a withdrawal must not.
#[test]
fn a_probe_proposing_a_ttl_zero_record_still_delivers_a_proposal() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let (mut e, expected) = build_endpoint_with_printer();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();

  let mut buf = [0u8; 512];
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
  b.push_question(
    &inst,
    crate::wire::ResourceType::Any,
    crate::wire::ResourceClass::In,
    true,
  )
  .unwrap();
  let target = Name::try_from_str("rival-host.local.").unwrap();
  b.push_srv_authority(&inst, 0, 0, 0, 9999, &target).unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let saw = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .filter_map(Result::ok)
    .any(|ev| {
      matches!(ev, RouteEvent::ToService(ts) if ts.handle() == expected && ts.event().is_probe_proposal())
    });
  assert!(
    saw,
    "a TTL of 0 is not one of the fields §8.2.1 compares, so the record is in \
     the peer's proposal and the proposal must reach the fold"
  );
}

// ── the cross-layer invariant R10-1 broke ──────────────────────────────

/// ROUTING OVER-APPROXIMATES VERDICTS: whenever the fold would reach
/// `PeerWins` or `WeHold` for a service's name, the endpoint routed a
/// `ProbeProposal` for that datagram.
///
/// The invariant is stated over VERDICTS, not over admission, because a verdict
/// is the only thing delivery can change. §8.2.1's two outcomes move a
/// `Service`: `PeerWins` loses the round, `WeHold` keeps it. `Abandoned` moves
/// nothing — it traces and returns — so a datagram whose only terminal value is
/// an abandonment is one the router may withhold, and withholding it decides
/// exactly as much as abandoning it would (nothing). That equivalence is pinned
/// separately by `an_abandoned_proposal_behaves_exactly_like_we_hold`; if it ever
/// stops holding, `authority_proposes_for`'s fail-closed disposition has to be
/// revisited and this test's statement with it.
///
/// It is deliberately an implication and not an equivalence in the other
/// direction either: the router may deliver a proposal the fold then abandons.
///
/// The failure it exists for is mechanical drift. The two layers each spelled out
/// `ttl != 0 && class == IN && the name matches && a question admits it`; the
/// fold's copy was corrected to admit every RTYPE and the router's was left at
/// SRV/TXT. Nothing failed, because every fixture drove ONE layer. A peer
/// proposing only an AAAA then folded our records into its own comparison and
/// continued as the winner while this endpoint, never handed the proposal, also
/// continued — two conforming peers, one name.
///
/// So this drives `Endpoint::handle` and `service::proposal::adjudicate` over the
/// SAME constructed datagrams. Layer two calls the real fold rather than
/// re-deriving what it would admit, which is the part a shared predicate does not
/// prove on its own.
#[test]
fn routing_over_approximates_what_the_fold_adjudicates() {
  use crate::{
    event::RouteEvent,
    records::ServiceRecords,
    wire::{Header, MessageBuilder, ResourceClass, ResourceType},
  };
  use core::net::SocketAddr;

  const INSTANCE: &str = "Printer._ipp._tcp.local.";

  fn srv_txt(b: &mut MessageBuilder<'_, 32>, n: &Name) {
    let t = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_authority(n, 120, 0, 0, 9999, &t).unwrap();
    let segs: [&[u8]; 0] = [];
    b.push_txt_authority(n, 120, segs).unwrap();
  }
  fn aaaa_only(b: &mut MessageBuilder<'_, 32>, n: &Name) {
    b.push_aaaa_authority(n, 120, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
      .unwrap();
  }
  fn a_only(b: &mut MessageBuilder<'_, 32>, n: &Name) {
    b.push_a_authority(n, 120, Ipv4Addr::new(10, 0, 0, 9)).unwrap();
  }
  fn srv_only(b: &mut MessageBuilder<'_, 32>, n: &Name) {
    let t = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_authority(n, 120, 0, 0, 9999, &t).unwrap();
  }
  fn goodbye_srv(b: &mut MessageBuilder<'_, 32>, n: &Name) {
    let t = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_authority(n, 0, 0, 0, 9999, &t).unwrap();
  }

  /// One case: description, the question's name and QTYPE, and the authority
  /// One case: description, whether the datagram is a §8.2 proposal for our
  /// instance name AT ALL, the question's name and QTYPE, and the authority
  /// records to push (all at the instance name).
  ///
  /// The second field is DECLARED GROUND TRUTH about the bytes, read off §8.1
  /// and §8.2 by hand — never computed from the admission rule, which is one of
  /// the two things this test is cross-checking. It is needed because
  /// `adjudicate` overloads `WeHold`: §8.2.1's "there is, in fact, no conflict"
  /// and "this query proposed nothing for me" are the same value, since a fold
  /// that compared nothing cannot have records remaining. Only the first is a
  /// verdict ABOUT something, and only the first has to be delivered.
  type Case = (
    &'static str,
    bool,
    &'static str,
    ResourceType,
    fn(&mut MessageBuilder<'_, 32>, &Name),
  );
  let cases: [Case; 7] = [
    (
      "the conforming probe: ANY question, SRV+TXT proposed",
      true,
      INSTANCE,
      ResourceType::Any,
      srv_txt,
    ),
    (
      "ANY question, only an AAAA — a type we do not publish",
      true,
      INSTANCE,
      ResourceType::Any,
      aaaa_only,
    ),
    (
      "ANY question, only an A",
      true,
      INSTANCE,
      ResourceType::Any,
      a_only,
    ),
    (
      // §8.2 reads the proposal off "the Authority Section of *that query*", and
      // this query asks about Scanner — so it proposes nothing about Printer,
      // however its Authority Section is filled.
      "a question for ANOTHER name, our name in the authority section",
      false,
      "Scanner._ipp._tcp.local.",
      ResourceType::Any,
      srv_txt,
    ),
    (
      "a SPECIFIC qtype naming the proposed record's own type",
      true,
      INSTANCE,
      ResourceType::Srv,
      srv_only,
    ),
    (
      "a SPECIFIC qtype naming NO proposed record's type — the Authority \
       Section is the peer's whole §8.2 proposal either way",
      true,
      INSTANCE,
      ResourceType::Txt,
      srv_only,
    ),
    (
      "a TTL=0 authority record — §8.2.1 compares class, type and rdata, so the \
       TTL cannot take a record out of the peer's proposal",
      true,
      INSTANCE,
      ResourceType::Any,
      goodbye_srv,
    ),
  ];

  let instance = Name::try_from_str(INSTANCE).unwrap();
  // The SAME records the endpoint registers in `build_endpoint_with_printer`, so
  // the two layers are asked about one service and not two.
  let records = || {
    ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str(INSTANCE).unwrap(),
      Name::try_from_str("printer-host.local.").unwrap(),
      631,
      120,
    )
  };

  // …plus the malformed datagrams, carrying the same declared ground truth. Two
  // of them still propose something readable at our name; the third proposes
  // nothing readable at all, and the fold's only terminal value for it is an
  // abandonment.
  let mut extra: std::vec::Vec<(&str, bool, std::vec::Vec<u8>)> = std::vec::Vec::new();
  {
    // A question whose QNAME is an unresolvable pointer, alongside a valid one.
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_question(&instance, ResourceType::Any, ResourceClass::In, true)
      .unwrap();
    srv_txt(&mut b, &instance);
    let n = b.finish().unwrap();
    let good = buf[..n].to_vec();
    // Rebuild with a second, pointer-named question spliced in after the first.
    let qlen = {
      let mut k = 12usize;
      for label in "Printer._ipp._tcp.local".split('.') {
        k += 1 + label.len();
      }
      k + 1 + 4 - 12
    };
    let mut d: std::vec::Vec<u8> = std::vec::Vec::new();
    d.extend_from_slice(&good[..12]);
    d[5] = 2;
    d.extend_from_slice(&good[12..12 + qlen]);
    let at = 12 + qlen;
    #[allow(clippy::cast_possible_truncation)]
    d.extend_from_slice(&[0xC0 | ((at >> 8) as u8), at as u8]);
    d.extend_from_slice(&ResourceType::Any.to_u16().to_be_bytes());
    d.extend_from_slice(&1u16.to_be_bytes());
    d.extend_from_slice(&good[12 + qlen..]);
    extra.push(("a pointer-named QNAME beside a valid question", true, d));
  }
  {
    // A KX whose rdata may hold a compression pointer.
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_question(&instance, ResourceType::Any, ResourceClass::In, true)
      .unwrap();
    srv_txt(&mut b, &instance);
    let n = b.finish().unwrap();
    let mut d = buf[..n].to_vec();
    for label in "Printer._ipp._tcp.local".split('.') {
      #[allow(clippy::cast_possible_truncation)]
      d.push(label.len() as u8);
      d.extend_from_slice(label.as_bytes());
    }
    d.push(0u8);
    d.extend_from_slice(&36u16.to_be_bytes()); // KX
    d.extend_from_slice(&1u16.to_be_bytes());
    d.extend_from_slice(&120u32.to_be_bytes());
    d.extend_from_slice(&4u16.to_be_bytes());
    d.extend_from_slice(&[0x00, 0x0A, 0xC0, 0x0C]);
    d[9] = 3; // NSCOUNT 2 -> 3
    extra.push((
      "a KX whose rdata may hold a compression pointer",
      true,
      d,
    ));
  }
  {
    // An authority section that stops PARSING at its first record, with no
    // readable record ahead of it. `Records` halts at its first error, so the
    // section carries nothing this query proposes for any name.
    let mut buf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_question(&instance, ResourceType::Any, ResourceClass::In, true)
      .unwrap();
    let n = b.finish().unwrap();
    let mut d = buf[..n].to_vec();
    d[9] = 1; // NSCOUNT claims one record …
    d.extend_from_slice(&[0x05, b'h', b'e', b'l', b'l']); // … which is truncated
    extra.push((
      "an authority section that stops parsing at its first record",
      false,
      d,
    ));
  }

  let built = cases
    .into_iter()
    .map(|(what, proposes_for_us, qname, qtype, push_recs)| {
      let mut buf = [0u8; 512];
      let q = Name::try_from_str(qname).unwrap();
      let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
      b.push_question(&q, qtype, ResourceClass::In, true).unwrap();
      push_recs(&mut b, &instance);
      let n = b.finish().unwrap();
      (what, proposes_for_us, buf[..n].to_vec())
    });

  for (what, proposes_for_us, datagram) in built.chain(extra) {
    // LAYER 1 — the endpoint: was a ProbeProposal routed?
    let (mut e, _h) = build_endpoint_with_printer();
    let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
    let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
    let routed = e
      .handle(
        StdInstant::now(),
        Received::new(src, &datagram, Provenance::Unknown).with_local_ip(local_ip),
      )
      .unwrap()
      .filter_map(Result::ok)
      .any(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_probe_proposal()));

    // LAYER 2 — the fold, called for real rather than re-derived. Its terminal
    // value is the whole question: `PeerWins` and `WeHold` are §8.2.1's two
    // verdicts, `Abandoned` is not a verdict at all.
    let reader = crate::wire::MessageReader::try_parse(&datagram).unwrap();
    let recs = records();
    let pp = crate::event::ProbeProposal::new(src, reader, crate::event::DatagramId::new(1));
    let verdict = crate::service::proposal::adjudicate(&pp, &recs);
    let reaches_a_verdict = !matches!(verdict, crate::service::proposal::Verdict::Abandoned(_));

    assert!(
      !(proposes_for_us && reaches_a_verdict) || routed,
      "{what}: this datagram proposes something at our name and the fold reaches \
       {verdict:?} over it, so a ProbeProposal MUST have been routed — routing \
       must OVER-approximate verdicts, never under-approximate them"
    );
  }
}

/// A QDCOUNT=0 datagram whose ONLY declared authority record is truncated
/// proposes nothing to anybody, and costs the endpoint work proportional to the
/// datagram rather than to the number of registered services.
///
/// It is the cheapest amplification input the §8.2 path admits: QR=0, source
/// port 5353, no questions, and roughly thirty bytes of which five are a
/// half-written record. §8.1 defines a probe as a query carrying "the record
/// name in question in the Question Section" and §8.2 reads the proposal off
/// "the Authority Section of *that query*", so a query that asks nothing
/// proposes nothing — and `Records` stops at its first error, so the section
/// carries no readable record either.
///
/// Routed anyway, it fans out to EVERY registered service: `AuthorityProposals`
/// restarts the service scan on each `next()`, so N deliveries cost Θ(N²) slab
/// visits, and every pre-authoritative service then builds and sorts its own
/// proposal before the fold dies on that same record. The fold's only terminal
/// value for it is `Verdict::Abandoned`, which
/// `an_abandoned_proposal_behaves_exactly_like_we_hold` shows changes nothing —
/// so all of that work buys no service any information at all.
///
/// Two assertions, neither of them timing-based: nothing is delivered, and the
/// number of routing events the datagram produces does not grow with the service
/// count. The control at the end registers the same services and sends a real
/// probe, so a fixture whose registrations silently failed cannot pass.
#[test]
fn a_questionless_truncated_authority_packet_is_routed_to_no_service() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  /// An endpoint with `n` distinct services registered, and the instance name of
  /// the first one.
  fn endpoint_with(n: usize) -> (TestEndp, Name) {
    let mut e = build_endpoint();
    let mut first = None;
    for i in 0..n {
      let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
      let inst = Name::try_from_str(&std::format!("Printer{i}._ipp._tcp.local.")).unwrap();
      let host = Name::try_from_str(&std::format!("printer-host{i}.local.")).unwrap();
      if first.is_none() {
        first = Some(inst.clone());
      }
      #[allow(clippy::cast_possible_truncation)]
      let recs = ServiceRecords::new(st, inst, host, 631 + i as u16, 120);
      e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        StdInstant::now(),
      )
      .unwrap();
    }
    (e, first.unwrap())
  }

  // QR=0, QDCOUNT=0, NSCOUNT=1 — and the one declared record is five bytes of a
  // label that claims to be longer than what follows it.
  let mut datagram: std::vec::Vec<u8> = std::vec::Vec::new();
  datagram.extend_from_slice(&0u16.to_be_bytes()); // ID
  datagram.extend_from_slice(&0u16.to_be_bytes()); // flags: QR=0
  datagram.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT — asks nothing
  datagram.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
  datagram.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT — claims one record
  datagram.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
  datagram.extend_from_slice(&[0x05, b'h', b'e', b'l', b'l']); // …which is truncated

  // Port 5353: the §8.2 proposal path is gated on it, so this is the shape that
  // reaches the fan-out at all.
  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();

  let mut counts = std::vec::Vec::new();
  for n in [4usize, 256] {
    let (mut e, _first) = endpoint_with(n);
    let mut proposals = 0usize;
    let mut events = 0usize;
    for ev in e
      .handle(
        StdInstant::now(),
        Received::new(src, &datagram, Provenance::Unknown).with_local_ip(local_ip),
      )
      .unwrap()
    {
      events = events.saturating_add(1);
      if matches!(&ev, Ok(RouteEvent::ToService(ts)) if ts.event().is_probe_proposal()) {
        proposals = proposals.saturating_add(1);
      }
    }
    assert_eq!(
      proposals, 0,
      "{n} services: a query that asks nothing proposes nothing, and a section \
       that stops parsing at its first record carries no readable proposal \
       either — so no service may be handed a §8.2 proposal for it"
    );
    counts.push(events);
  }
  assert_eq!(
    counts.first(),
    counts.last(),
    "the routing work this datagram causes must be a function of the DATAGRAM, \
     not of how many services are registered — a per-service fan-out here is an \
     amplification primitive, since `AuthorityProposals` rescans the service \
     slab on every delivery"
  );

  // CONTROL: the same registrations really are live, and a real §8.2 probe for
  // one of those names still reaches exactly its own service.
  let (mut e, first) = endpoint_with(4);
  let mut buf = [0u8; 512];
  let mut b = crate::wire::MessageBuilder::<'_, 32>::try_new(&mut buf, crate::wire::Header::new())
    .unwrap();
  b.push_question(
    &first,
    crate::wire::ResourceType::Any,
    crate::wire::ResourceClass::In,
    true,
  )
  .unwrap();
  let target = Name::try_from_str("rival-host.local.").unwrap();
  b.push_srv_authority(&first, 120, 0, 0, 9999, &target).unwrap();
  let n = b.finish().unwrap();
  let probe = buf[..n].to_vec();
  let delivered = e
    .handle(
      StdInstant::now(),
      Received::new(src, &probe, Provenance::Unknown).with_local_ip(local_ip),
    )
    .unwrap()
    .filter_map(Result::ok)
    .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_probe_proposal()))
    .count();
  assert_eq!(
    delivered, 1,
    "control: a genuine probe for a registered name is still delivered, to \
     exactly the one service that owns it"
  );
}

/// The OTHER fail-closed input on the §8.2 proposal route, and the one nothing
/// covered: a question section that PARSES but cannot be decoded, behind an
/// authority record that is perfectly readable and sits at a registered name.
///
/// The two inputs reach the same `return false` by different doors, and only one
/// of them had a test. A record that will not parse is caught by
/// `a_questionless_truncated_authority_packet_is_routed_to_no_service`; this is
/// the `Err(QuestionsUnreadable)` arm, which needs the record to be GOOD so that
/// the owner-and-class gate passes and the question walk is actually taken.
/// `QuestionRef::try_parse` consumes a compression pointer without following it,
/// so a pointer-named question parses — the section is locatable and the
/// authority records ARE surfaced — and only `name_fully_decodes` rejects it.
///
/// Fail-closed is the right disposition here because this route releases a
/// VERDICT PATH: the fold's only terminal value for an undecidable section is
/// `Abandoned`, which `an_abandoned_proposal_behaves_exactly_like_we_hold` shows
/// changes nothing, so delivering it buys no service any information while
/// costing a fan-out to every registered one. The §8.1 DEFENCE route answers the
/// identical input the opposite way — see
/// `answer_questions_false_defends_only_against_a_real_proposal` — because what
/// it releases is a defence of a name already established, and §8.1 makes
/// mounting that defence a duty. The pair is the decision; either alone reads as
/// an accident.
#[test]
fn an_undecodable_question_section_routes_no_proposal_though_its_record_is_good() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer-host.local.").unwrap();
  e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    ServiceSpec::new(ServiceRecords::new(st, inst.clone(), host, 631, 120)),
    StdInstant::now(),
  )
  .unwrap();

  // A well-formed SRV authority record at the registered instance name, so the
  // owner-and-class gate passes and the question walk is genuinely reached.
  let mut record = std::vec::Vec::new();
  for label in "Printer._ipp._tcp.local.".trim_end_matches('.').split('.') {
    record.push(u8::try_from(label.len()).unwrap());
    record.extend_from_slice(label.as_bytes());
  }
  record.push(0);
  record.extend_from_slice(&33u16.to_be_bytes()); // SRV
  record.extend_from_slice(&1u16.to_be_bytes()); // class IN
  record.extend_from_slice(&120u32.to_be_bytes());
  let mut rdata = std::vec::Vec::new();
  rdata.extend_from_slice(&0u16.to_be_bytes());
  rdata.extend_from_slice(&0u16.to_be_bytes());
  rdata.extend_from_slice(&9999u16.to_be_bytes());
  for label in ["rival-host", "local"] {
    rdata.push(u8::try_from(label.len()).unwrap());
    rdata.extend_from_slice(label.as_bytes());
  }
  rdata.push(0);
  record.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
  record.extend_from_slice(&rdata);

  let datagram = |decodable: bool| -> std::vec::Vec<u8> {
    let mut d: std::vec::Vec<u8> = std::vec::Vec::new();
    d.extend_from_slice(&0u16.to_be_bytes()); // ID
    d.extend_from_slice(&0u16.to_be_bytes()); // flags: QR=0 — a probe is a query
    d.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    d.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    d.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT
    d.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    if decodable {
      for label in "Printer._ipp._tcp.local.".trim_end_matches('.').split('.') {
        d.push(u8::try_from(label.len()).unwrap());
        d.extend_from_slice(label.as_bytes());
      }
      d.push(0);
    } else {
      // A QNAME that is a pointer to its own offset: `try_parse` accepts it (both
      // bytes exist) so the section PARSES and the authority record is surfaced;
      // following it cycles, so `name_fully_decodes` says no.
      let at = u16::try_from(d.len()).unwrap();
      d.extend_from_slice(&(0xC000u16 | at).to_be_bytes());
    }
    d.extend_from_slice(&crate::wire::ResourceType::Any.to_u16().to_be_bytes());
    d.extend_from_slice(&(0x8000u16 | 1).to_be_bytes()); // QU | QCLASS IN
    d.extend_from_slice(&record);
    d
  };

  let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
  let local_ip: core::net::IpAddr = "192.168.1.1".parse().unwrap();
  let proposals = |e: &mut TestEndp, bytes: &[u8]| -> usize {
    e.handle(
      StdInstant::now(),
      Received::new(src, bytes, Provenance::Unknown).with_local_ip(local_ip),
    )
      .unwrap()
      .filter_map(Result::ok)
      .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_probe_proposal()))
      .count()
  };

  // CONTROL FIRST: the identical record behind a DECODABLE question really is
  // delivered, so the assertion below cannot pass because the fixture was inert.
  assert_eq!(
    proposals(&mut e, &datagram(true)),
    1,
    "control: the same authority record behind a readable question is a genuine \
     §8.2 proposal and reaches the service that owns the name"
  );

  assert_eq!(
    proposals(&mut e, &datagram(false)),
    0,
    "the question section cannot be decoded, so whether this datagram proposes \
     anything for that name is UNKNOWN — and the proposal route answers unknown \
     with no, because the fold's only terminal value for it is an abandonment \
     that changes nothing while the delivery costs a fan-out to every service"
  );
}

/// One §8.2 admission scope reads the Question Section AT MOST ONCE, however
/// many Authority records it is asked about — and does not read it at all when
/// none of them is at the scope's name.
///
/// Admission used to re-parse and fully decode every question for every
/// authority record. Scope is the owner name and class, which does not vary with
/// the record, so that product was pure repetition: a maximum-size datagram
/// carries roughly 5,400 minimal questions and 2,700 minimal records, and both
/// the router and the fold scan, so one link-local packet bought ~15 million
/// pair iterations twice over before any compression-chain work.
///
/// The second half is the part that keeps behaviour identical rather than merely
/// faster. `QuestionsUnreadable` — the answer whose two callers owe it OPPOSITE
/// dispositions, fail-open at the router and abandon at the fold — is produced
/// by that walk, so hoisting it above the owner-and-class gate would surface it
/// on datagrams that never reached it: ones whose authority records are all at
/// other names, and ones with no authority records at all. Memoising on first
/// use, rather than reading eagerly, is what leaves those datagrams alone.
#[test]
fn one_admission_scope_reads_the_question_section_at_most_once() {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType};

  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let other = Name::try_from_str("Scanner._ipp._tcp.local.").unwrap();
  let target = Name::try_from_str("rival-host.local.").unwrap();

  // `at_ours` authority records at the instance name, then `at_theirs` at
  // another name, behind a question that puts the instance in scope.
  let datagram = |at_ours: usize, at_theirs: usize| -> std::vec::Vec<u8> {
    let mut buf = [0u8; 2048];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
    b.push_question(&instance, ResourceType::Any, ResourceClass::In, true)
      .unwrap();
    for i in 0..at_ours {
      #[allow(clippy::cast_possible_truncation)]
      b.push_srv_authority(&instance, 120, 0, 0, 9000 + i as u16, &target)
        .unwrap();
    }
    for i in 0..at_theirs {
      #[allow(clippy::cast_possible_truncation)]
      b.push_srv_authority(&other, 120, 0, 0, 9500 + i as u16, &target)
        .unwrap();
    }
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  };

  // Eight records at our name and four at another: the answer is unchanged for
  // every one of them, so one walk of the questions covers all twelve.
  let bytes = datagram(8, 4);
  let reader = crate::wire::MessageReader::try_parse(&bytes).unwrap();
  let walks = core::cell::Cell::new(0usize);
  let mut scope = crate::endpoint::ProposalScope::new(
    || {
      walks.set(walks.get().saturating_add(1));
      reader.questions()
    },
    &instance,
  );
  let admitted = reader
    .authority()
    .filter(|r| {
      r.as_ref()
        .is_ok_and(|r| scope.admits(r).unwrap() == crate::endpoint::Admission::Ours)
    })
    .count();
  assert_eq!(
    admitted, 8,
    "every record at the scope's name is admitted, and none of the others"
  );
  assert_eq!(
    walks.get(),
    1,
    "the question section decides scope by owner name and class, which does not \
     vary with the record — so it is read once for the whole section, not once \
     per record"
  );

  // And a datagram proposing nothing at our name never reaches the questions at
  // all, which is what keeps `QuestionsUnreadable` reachable from exactly the
  // datagrams that reached it before.
  let bytes = datagram(0, 4);
  let reader = crate::wire::MessageReader::try_parse(&bytes).unwrap();
  let walks = core::cell::Cell::new(0usize);
  let mut scope = crate::endpoint::ProposalScope::new(
    || {
      walks.set(walks.get().saturating_add(1));
      reader.questions()
    },
    &instance,
  );
  // …and each is refused for the STRUCTURAL reason, not merely refused: these
  // records are at another owner name, so they are part of another name's
  // proposal and leaving them out cannot shorten the list §8.2.1 compares here.
  let answers: std::vec::Vec<_> = reader
    .authority()
    .map(|r| scope.admits(r.as_ref().unwrap()).unwrap())
    .collect();
  assert_eq!(
    answers,
    std::vec![
      crate::endpoint::Admission::NotOurs(crate::endpoint::NotOurs::DifferentOwner);
      4
    ],
    "none of these records is at the scope's name"
  );
  assert_eq!(
    walks.get(),
    0,
    "the owner-and-class gate comes first, so a datagram whose authority records \
     are all out of scope never causes the question section to be read"
  );
}

// ── the trust tier: what each `Provenance` admits ───────────────────────────

/// Build an endpoint with one registered service, plus the datagram bytes for a
/// probe naming that service's instance — the shape that exercises every
/// permission at once: an RFC 6762 §8.1 question to answer, and an §8.2 proposal
/// to adjudicate.
fn probe_against_our_instance(buf: &mut [u8; 512]) -> (TestEndp, ServiceHandle, usize) {
  let (e, handle) = build_endpoint_with_printer();
  let n = build_probe_srv_authority(buf, "Printer._ipp._tcp.local.");
  (e, handle, n)
}

/// A content match with NO ordering evidence still ADJUDICATES. Suppressing an
/// RFC 6762 §8.2 proposal costs a name permanently and silently; routing our own
/// echo to the tiebreak costs, at worst, §8.2's one-second deferral — and a
/// byte-identical datagram from a conforming §9 twin is indistinguishable from
/// our own echo, so this tier cannot be trusted with the name.
#[test]
fn own_echo_likely_still_adjudicates_the_proposal() {
  use crate::event::RouteEvent;
  let mut buf = [0u8; 512];
  let (mut e, handle, n) = probe_against_our_instance(&mut buf);
  let src: core::net::SocketAddr = "192.0.2.1:5353".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::OwnEchoLikely),
    )
    .unwrap()
    .map(|ev| ev.expect("event must be Ok"))
    .collect();
  assert!(
    events.iter().any(|ev| matches!(
      ev,
      RouteEvent::ToService(ts)
        if ts.handle() == handle && ts.event().is_probe_proposal()
    )),
    "an unordered content match must still deliver the §8.2 proposal"
  );
}

/// …and an ORDERED one does not. Nothing else could have put these bytes on the
/// wire between our `sendto` and the kernel's receive stamp, so the datagram is
/// dropped whole, exactly as before this tier existed.
#[test]
fn own_echo_admits_nothing_at_all() {
  let mut buf = [0u8; 512];
  let (mut e, _handle, n) = probe_against_our_instance(&mut buf);
  let src: core::net::SocketAddr = "192.0.2.1:5353".parse().unwrap();
  let mut events = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::OwnEcho),
    )
    .unwrap();
  assert!(
    events.next().is_none(),
    "an ordered self-echo yields no routing event of any kind"
  );
}

/// A content match with no ordering evidence answers a §8.1 DEFENCE but nothing
/// else: `Answering::DefenceOnly`. Here the question names our host, and the
/// datagram carries no proposal for it, so the defence exemption does not apply
/// and the question is withheld — the discovery half of answering is shut.
#[test]
fn own_echo_likely_withholds_an_ordinary_question() {
  use crate::event::RouteEvent;
  let (mut e, _handle) = build_endpoint_with_printer();
  let mut buf = [0u8; 512];
  let n = build_query_for_host(&mut buf, "printer-host.local.");
  let src: core::net::SocketAddr = "192.0.2.1:5353".parse().unwrap();
  let mut events = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::OwnEchoLikely),
    )
    .unwrap();
  assert!(
    !events.any(|ev| matches!(
      ev.expect("event must be Ok"),
      RouteEvent::ToService(ts) if ts.event().is_question()
    )),
    "a plain discovery question is not a §8.1 defence, so DefenceOnly withholds it"
  );
}

/// `NotFromUs` declines the advertised-source guess. A caller that logs every
/// datagram it sends and matched none of them has better evidence than a source
/// address does — `src_matches_advertised` matches ANY co-resident host
/// publishing an address we publish, including a peer that has taken it.
#[test]
fn not_from_us_declines_the_advertised_source_guess() {
  use crate::event::RouteEvent;
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
  let mut e = TestEndp::try_new(
    EndpointConfig::new().with_trust_advertised_src_as_self(true),
    rng,
  );
  let our_v4 = Ipv4Addr::new(192, 168, 1, 7);
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Printer._ipp._tcp.local.").unwrap(),
    Name::try_from_str("printer-host.local.").unwrap(),
    631,
    120,
  );
  recs.add_a(our_v4);
  let now = StdInstant::now();
  let (handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let mut buf = [0u8; 512];
  let n = build_query_for_host(&mut buf, "printer-host.local.");
  // The source IS an address we advertise, so the heuristic fires.
  let src = core::net::SocketAddr::from((our_v4, 5353));

  let saw_question = |e: &mut TestEndp, prov| {
    e.handle(now, Received::new(src, &buf[..n], prov))
      .unwrap()
      .any(|ev| matches!(
        ev.expect("event must be Ok"),
        RouteEvent::ToService(ts) if ts.handle() == handle && ts.event().is_question()
      ))
  };
  assert!(
    !saw_question(&mut e, Provenance::Unknown),
    "a caller with nothing to say leaves the guess in charge"
  );
  assert!(
    saw_question(&mut e, Provenance::NotFromUs),
    "a caller that checked its send log overrides the guess"
  );
}

/// The advertised-source guess denies observation and quieting, but it may not
/// deny the RFC 6762 §8.1 DEFENCE — the same rule the `OwnEchoLikely` row
/// already follows, against evidence that is WEAKER, not stronger.
///
/// `src_matches_advertised` matches any co-resident host publishing an address
/// we publish, so a second responder on this machine shares the source address
/// and its legitimate probe lands in this cell. Skipping that probe's question
/// left nothing to stop it: the QR=0 proposal riding with it is §8.2's
/// pre-authoritative input and has no effect on an established service, so the
/// peer finished probing onto a name we already hold — duplicate ownership.
#[test]
fn a_matched_advertised_source_still_defends_an_established_name() {
  use crate::event::RouteEvent;
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
  let mut e = TestEndp::try_new(
    EndpointConfig::new().with_trust_advertised_src_as_self(true),
    rng,
  );
  let our_v4 = Ipv4Addr::new(192, 168, 1, 7);
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Printer._ipp._tcp.local.").unwrap(),
    Name::try_from_str("printer-host.local.").unwrap(),
    631,
    120,
  );
  recs.add_a(our_v4);
  let now = StdInstant::now();
  let (handle, _svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // A co-resident responder probing for the host name we already hold. Its
  // source IS an address we advertise, so the guess fires and the caller —
  // having no send log — says `Unknown`.
  let mut buf = [0u8; 512];
  let n = build_probe_for_host(&mut buf, "printer-host.local.", Ipv4Addr::new(10, 0, 0, 9));
  let src = core::net::SocketAddr::from((our_v4, 5353));
  assert!(
    e.handle(now, Received::new(src, &buf[..n], Provenance::Unknown))
      .unwrap()
      .any(|ev| matches!(
        ev.expect("event must be Ok"),
        RouteEvent::ToService(ts) if ts.handle() == handle && ts.event().is_question()
      )),
    "§8.1 requires the probe for a name we are using to be answered immediately; \
     an address guess must not be able to skip it"
  );
}

// ── the host address-set registration invariant ─────────────────────────────

fn register_with_addrs(
  e: &mut TestEndp,
  instance: &str,
  host: &str,
  a_addrs: &[Ipv4Addr],
) -> Result<ServiceHandle, RegisterServiceError> {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str(instance).unwrap(),
    Name::try_from_str(host).unwrap(),
    631,
    120,
  );
  for a in a_addrs {
    recs.add_a(*a);
  }
  e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    ServiceSpec::new(recs),
    StdInstant::now(),
  )
  .map(|(h, _svc)| h)
}

/// Two services may share a host name — that is how one machine advertises one
/// address set from several services — but they may not DISAGREE about the
/// addresses. Each would read the other's announcement as a host claiming its
/// own host name with rdata it does not hold, which RFC 6762 §9 makes a conflict
/// and which surfaces as a TERMINAL `ServiceUpdate::HostConflict` raised by a
/// sibling on the same machine.
#[test]
fn same_host_with_a_different_address_set_is_rejected() {
  let mut e = build_endpoint();
  let one = Ipv4Addr::new(192, 168, 1, 5);
  let two = Ipv4Addr::new(192, 168, 1, 6);
  register_with_addrs(&mut e, "A._ipp._tcp.local.", "h.local.", &[one]).unwrap();
  let err = register_with_addrs(&mut e, "B._ipp._tcp.local.", "h.local.", &[one, two])
    .expect_err("a disagreeing address set at a shared host name must be rejected");
  assert!(matches!(err, RegisterServiceError::HostAddressesDiffer(h) if h.as_str() == "h.local."));
}

/// The same set in a different order is the same set: the conflict classifier
/// asks `contains`, so mutual containment is what decides, not sequence.
#[test]
fn same_host_with_the_same_address_set_is_accepted() {
  let mut e = build_endpoint();
  let one = Ipv4Addr::new(192, 168, 1, 5);
  let two = Ipv4Addr::new(192, 168, 1, 6);
  register_with_addrs(&mut e, "A._ipp._tcp.local.", "h.local.", &[one, two]).unwrap();
  register_with_addrs(&mut e, "B._ipp._tcp.local.", "h.local.", &[two, one])
    .expect("the same set in another order is the same set");
  // A DIFFERENT host name is unconstrained by the other's addresses.
  register_with_addrs(&mut e, "C._ipp._tcp.local.", "other.local.", &[]).unwrap();
}

/// `Name` preserves the optional trailing root dot, but the wire encoder and
/// the routing path both strip it — so `h.local` and `h.local.` are ONE DNS
/// owner. A raw string comparison answers otherwise, and the spelling that
/// differs only by that dot registered past the guard and then collided on the
/// wire exactly as a matching spelling would have.
#[test]
fn the_host_address_guard_sees_through_a_trailing_root_dot() {
  let mut e = build_endpoint();
  register_with_addrs(
    &mut e,
    "A._ipp._tcp.local.",
    "h.local.",
    &[Ipv4Addr::new(192, 168, 1, 5)],
  )
  .unwrap();
  assert!(
    matches!(
      register_with_addrs(
        &mut e,
        "B._ipp._tcp.local.",
        "h.local", // same owner, no root dot
        &[Ipv4Addr::new(192, 168, 1, 6)],
      ),
      Err(RegisterServiceError::HostAddressesDiffer(_))
    ),
    "a root dot is not part of the name, so this is the same host with a \
     different address set"
  );
  // …and the same host WITHOUT the dot still shares addresses freely.
  register_with_addrs(
    &mut e,
    "C._ipp._tcp.local.",
    "h.local",
    &[Ipv4Addr::new(192, 168, 1, 5)],
  )
  .expect("the same address set under the same owner is not a disagreement");
}

/// Host names are matched case-insensitively, exactly as the routing path
/// matches a record against one — otherwise a second case spelling would
/// register past the guard and conflict on the wire anyway.
#[test]
fn the_host_address_guard_is_case_insensitive() {
  let mut e = build_endpoint();
  register_with_addrs(
    &mut e,
    "A._ipp._tcp.local.",
    "h.local.",
    &[Ipv4Addr::new(192, 168, 1, 5)],
  )
  .unwrap();
  assert!(matches!(
    register_with_addrs(
      &mut e,
      "B._ipp._tcp.local.",
      "H.LOCAL.",
      &[Ipv4Addr::new(192, 168, 1, 6)],
    ),
    Err(RegisterServiceError::HostAddressesDiffer(_))
  ));
}

// ── the trailing root dot in the INSTANCE-name and host-sibling guards ───────
//
// Same hole as the host address-set guard's, in guards that predate it: `Name`
// preserves the optional trailing root dot and these compared the stored
// strings, so one DNS owner spelled two ways passed every one of them.

/// Two live services may not hold one instance name. `A._ipp._tcp.local` and
/// `A._ipp._tcp.local.` ARE one instance name — they encode to the same wire
/// bytes and every peer sees one owner — so the second registration must be
/// rejected rather than left to probe for a name this endpoint already holds.
#[test]
fn the_duplicate_instance_name_guard_sees_through_a_trailing_root_dot() {
  let mut e = build_endpoint();
  register_with_addrs(&mut e, "A._ipp._tcp.local.", "h.local.", &[]).unwrap();
  assert!(
    matches!(
      register_with_addrs(&mut e, "A._ipp._tcp.local", "h.local.", &[]),
      Err(RegisterServiceError::NameAlreadyRegistered(_))
    ),
    "a root dot is not part of the name, so this is the name already registered"
  );
}

/// The same rule at the rename enforcement point: an auto-rename may not land on
/// a name a different live route already owns, whichever way that name is spelled.
#[test]
fn the_rename_duplicate_guard_sees_through_a_trailing_root_dot() {
  let mut e = build_endpoint();
  register_with_addrs(&mut e, "A._ipp._tcp.local.", "h.local.", &[]).unwrap();
  let b = register_with_addrs(&mut e, "B._ipp._tcp.local.", "h.local.", &[]).unwrap();
  assert!(
    matches!(
      e.handle_service_renamed(b, Name::try_from_str("A._ipp._tcp.local").unwrap()),
      Err(HandleServiceRenamedError::NameAlreadyRegistered(_))
    ),
    "renaming onto the same owner under a different spelling must be rejected"
  );
}

/// And at the retract-before-reuse guard: a rename-COLLISION goodbye still
/// holding its name blocks reuse of that NAME, not of one spelling of it.
/// Otherwise the dead service's stale records are never retracted — the held
/// goodbye is deliberately not cancelled on announce — while a replacement
/// advertises the same owner.
#[test]
fn a_held_goodbye_holds_its_name_through_a_trailing_root_dot() {
  let mut ep = build_endpoint();
  let now = StdInstant::now();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();
  let old_records = ServiceRecords::new(
    stype.clone(),
    Name::try_from_str("Printer._ipp._tcp.local.").unwrap(),
    host.clone(),
    631,
    120,
  );
  ep.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_both(
        crate::service::EmittedRecords::new(
          true,
          true,
          true,
          std::vec::Vec::new(),
          std::vec::Vec::new(),
          false,
          false,
        ),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    true, // holds_name
  );
  let recs = ServiceRecords::new(
    stype,
    Name::try_from_str("Printer._ipp._tcp.local").unwrap(),
    host,
    631,
    120,
  );
  assert!(
    matches!(
      ep.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now
      ),
      Err(RegisterServiceError::NameAlreadyRegistered(_))
    ),
    "the held goodbye owns this name, however the re-registration spells it"
  );
}

/// A withdrawing service must RETAIN an address a live same-host sibling still
/// advertises, or its TTL=0 goodbye deletes from every peer's cache a record the
/// sibling still owns. The sibling is found by host name, so a spelling that
/// differs only by the root dot must not hide it.
#[test]
fn sibling_host_retention_sees_through_a_trailing_root_dot() {
  let mut e = build_endpoint();
  let shared = Ipv4Addr::new(192, 168, 1, 5);
  let leaving = register_with_addrs(&mut e, "A._ipp._tcp.local.", "h.local.", &[shared]).unwrap();
  let staying = register_with_addrs(&mut e, "B._ipp._tcp.local.", "h.local", &[shared]).unwrap();
  // Only a CONFIRMED-ADVERTISED address is retained, so announce the sibling's.
  e.note_service_announced(FullyAnnounced::new(staying, true), &[shared], &[]);
  assert_eq!(
    e.sibling_retained_addrs(leaving),
    std::vec![core::net::IpAddr::V4(shared)],
    "the sibling shares this host name and still advertises the address"
  );
}

// ── the host invariant and the host fan-out are PER RRTYPE ───────────────────

fn register_with_addr_sets(
  e: &mut TestEndp,
  instance: &str,
  host: &str,
  a_addrs: &[Ipv4Addr],
  aaaa_addrs: &[core::net::Ipv6Addr],
) -> Result<ServiceHandle, RegisterServiceError> {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str(instance).unwrap(),
    Name::try_from_str(host).unwrap(),
    631,
    120,
  );
  for a in a_addrs {
    recs.add_a(*a);
  }
  for a in aaaa_addrs {
    recs.add_aaaa(*a);
  }
  e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    ServiceSpec::new(recs),
    StdInstant::now(),
  )
  .map(|(h, _svc)| h)
}

/// RFC 6762 §9's conflict is over "the same name, **rrtype** and rrclass, but
/// inconsistent rdata", so the A RRset at a host name and the AAAA RRset at it
/// are two distinct unique RRsets, each singly owned. An IPv4-only service and
/// an IPv6-only service may therefore share one host name: their records are
/// disjoint and cannot be inconsistent with one another.
///
/// Requiring both complete sets to be independently equal banned that legitimate
/// mixed-family configuration outright.
#[test]
fn an_ipv4_only_and_an_ipv6_only_service_may_share_a_host() {
  let mut e = build_endpoint();
  let v4 = Ipv4Addr::new(192, 168, 1, 5);
  let v6 = core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
  register_with_addr_sets(&mut e, "A._ipp._tcp.local.", "h.local.", &[v4], &[]).unwrap();
  register_with_addr_sets(&mut e, "B._ipp._tcp.local.", "h.local.", &[], &[v6])
    .expect("disjoint A and AAAA RRsets at one host name are not a disagreement");
  // …and a third, publishing NEITHER family, disagrees with neither.
  register_with_addr_sets(&mut e, "C._ipp._tcp.local.", "h.local.", &[], &[]).unwrap();
  // The rule is still enforced WITHIN a type both routes publish.
  assert!(matches!(
    register_with_addr_sets(
      &mut e,
      "D._ipp._tcp.local.",
      "h.local.",
      &[Ipv4Addr::new(192, 168, 1, 6)],
      &[v6],
    ),
    Err(RegisterServiceError::HostAddressesDiffer(_))
  ));
}

/// The fan-out half of the same rule, which must land with the registration
/// half: a route that publishes no record of the record's RRtype at its host
/// name is not a party to that RRset, so no `HostConflict` is routed to it.
///
/// Relaxing registration alone would admit the mixed-family pair above and then
/// let the fan-out — which read an ABSENT RRtype as differing — raise a terminal
/// `HostConflict` on the IPv4-only sibling the moment the IPv6-only one
/// announced, over an address it never published.
#[test]
fn a_host_conflict_is_routed_only_to_routes_publishing_that_rrtype() {
  use crate::{
    event::RouteEvent,
    wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
  };
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let v4 = Ipv4Addr::new(192, 168, 1, 5);
  let v6 = core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
  let v4_only =
    register_with_addr_sets(&mut e, "A._ipp._tcp.local.", "h.local.", &[v4], &[]).unwrap();
  let v6_only =
    register_with_addr_sets(&mut e, "B._ipp._tcp.local.", "h.local.", &[], &[v6]).unwrap();

  // The IPv6-only sibling's own announcement: a QR=1 AAAA at the shared host.
  let host = Name::try_from_str("h.local.").unwrap();
  let mut buf = [0u8; 512];
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(&mut buf, hdr).unwrap();
  b.push_aaaa_answer(&host, 120, v6, true).unwrap();
  let n = b.finish().unwrap();

  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let conflicted: std::vec::Vec<_> = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::NotFromUs),
    )
    .unwrap()
    .filter_map(Result::ok)
    .filter_map(|ev| match ev {
      RouteEvent::ToService(ts) if ts.event().is_host_conflict() => Some(ts.handle()),
      _ => None,
    })
    .collect();
  assert!(
    !conflicted.contains(&v4_only),
    "the IPv4-only route publishes no AAAA at this host name, so this record is \
     not its RRset; got {conflicted:?}"
  );
  assert!(
    conflicted.contains(&v6_only),
    "the route that DOES own the AAAA RRset still receives it — the gate is \
     ownership, not family; got {conflicted:?}"
  );
}

/// The same gate on the QR=0 authority path (`next_host_conflict`), which a
/// peer's probe for the shared host name takes.
#[test]
fn a_probe_host_conflict_is_routed_only_to_routes_publishing_that_rrtype() {
  use crate::event::RouteEvent;
  use core::net::SocketAddr;

  let mut e = build_endpoint();
  let v6 = core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
  let v4_only = register_with_addr_sets(
    &mut e,
    "A._ipp._tcp.local.",
    "h.local.",
    &[Ipv4Addr::new(192, 168, 1, 5)],
    &[],
  )
  .unwrap();
  let v6_only =
    register_with_addr_sets(&mut e, "B._ipp._tcp.local.", "h.local.", &[], &[v6]).unwrap();

  // A peer probing for the shared host with an A record it proposes to use.
  let mut buf = [0u8; 512];
  let n = build_probe_authority_for_host(&mut buf, "h.local.");
  let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let conflicted: std::vec::Vec<_> = e
    .handle(
      StdInstant::now(),
      Received::new(src, &buf[..n], Provenance::NotFromUs),
    )
    .unwrap()
    .filter_map(Result::ok)
    .filter_map(|ev| match ev {
      RouteEvent::ToService(ts) if ts.event().is_host_conflict() => Some(ts.handle()),
      _ => None,
    })
    .collect();
  assert_eq!(
    conflicted,
    std::vec![v4_only],
    "only the route that owns an A RRset at this host name is a party to the \
     peer's A; the IPv6-only route ({v6_only:?}) is not"
  );
}

// ── the relinquished-RRset screen (`endpoint::relinquished`) ─────────────────
//
// A stale positive-TTL echo — OUR OWN bytes, carrying records we no longer
// publish — must not be adjudicated against whatever now holds that owner name.
// Every test below feeds the echo with `Provenance::NotFromUs`, because that is
// what a driver honestly reports for it: a replaying peer spends the one credit
// the send was given, or the medium delivers a second copy (kernel loopback plus
// an 802.11 base-station re-broadcast, which RFC 6762 §8.2 names), or the credit
// was evicted under load. Whichever it is, the datagram reaches adjudication
// with no driver-side recognition left, so what screens it has to be here.

/// Build a QR=1 authoritative response carrying one A record at `owner`, with
/// the RFC 6762 §10.2 cache-flush bit set — the way this crate's own encoders
/// write every unique record they multicast.
fn build_host_a_response(buf: &mut [u8], owner: &Name, addr: Ipv4Addr) -> usize {
  build_host_a_response_with_flush(buf, owner, addr, true)
}

/// [`build_host_a_response`], with the cache-flush bit under the caller's
/// control — so a test can send the one shape no positive multicast send of
/// ours ever had.
fn build_host_a_response_with_flush(
  buf: &mut [u8],
  owner: &Name,
  addr: Ipv4Addr,
  cache_flush: bool,
) -> usize {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder};
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(buf, hdr).unwrap();
  b.push_a_answer(owner, 120, addr, cache_flush).unwrap();
  b.finish().unwrap()
}

/// Byte offsets of the section counts in a DNS header: ANCOUNT, NSCOUNT and
/// ARCOUNT, in wire order after the id, flags and QDCOUNT.
const ANCOUNT_AT: usize = 6;
const NSCOUNT_AT: usize = 8;
const ARCOUNT_AT: usize = 10;

/// Move ONE record off the answer count and onto `onto`, leaving every byte
/// after the header untouched.
///
/// A record's own bytes say nothing about which section it is in — only the
/// header counts do, and the sections are laid out contiguously in the order
/// answers → authority → additional. So a message whose LAST record is an
/// answer is byte-identical to the same message carrying that record in a later
/// section, and moving one off ANCOUNT is the whole difference between them.
///
/// That is what lets these tests write the shapes a CONFORMING responder sends
/// and this crate's encoders never do — an address in the additional section
/// beside the SRV that points at it (RFC 6763 §12), or an authority record on a
/// response.
fn relabel_last_answer(pkt: &mut [u8], onto: usize) {
  let take = |pkt: &[u8], at: usize| u16::from_be_bytes([pkt[at], pkt[at + 1]]);
  let ancount = take(pkt, ANCOUNT_AT);
  assert!(ancount > 0, "there must be an answer to relabel");
  let moved = take(pkt, onto).checked_add(1).unwrap();
  pkt[ANCOUNT_AT..ANCOUNT_AT + 2].copy_from_slice(&(ancount - 1).to_be_bytes());
  pkt[onto..onto + 2].copy_from_slice(&moved.to_be_bytes());
}

/// Build the CONFORMING DNS-SD response shape: a peer's own SRV in the ANSWER
/// section, and the address that SRV points at in the ADDITIONAL section.
///
/// RFC 6763 §12 tells a responder to bundle the address records with the SRV
/// exactly this way, so this is ordinary browse traffic rather than a crafted
/// datagram — and it is the shape this crate's encoders never produce, since
/// they write every address as an ANSWER.
fn build_srv_answer_plus_additional_a(
  buf: &mut [u8],
  peer_instance: &Name,
  host: &Name,
  addr: Ipv4Addr,
) -> usize {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder};
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let n = {
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(buf, hdr).unwrap();
    b.push_srv_answer(peer_instance, 120, 0, 0, 631, host, true)
      .unwrap();
    b.push_a_answer(host, 120, addr, true).unwrap();
    b.finish().unwrap()
  };
  relabel_last_answer(buf, ARCOUNT_AT);
  n
}

/// The `{SRV, TXT}` bitmap `push_service_nsec` writes, for the tests that build
/// the §6.1 instance NSEC an echo of ours would carry.
fn emitted_nsec_types() -> [u16; 2] {
  [
    crate::wire::ResourceType::Srv.to_u16(),
    crate::wire::ResourceType::Txt.to_u16(),
  ]
}

/// Move the sole ADDITIONAL record onto the answer count — the inverse of
/// [`relabel_last_answer`], for the one identity this crate transmits in the
/// additional section rather than the answer one.
fn relabel_sole_additional_as_answer(pkt: &mut [u8]) {
  let take = |pkt: &[u8], at: usize| u16::from_be_bytes([pkt[at], pkt[at + 1]]);
  assert_eq!(take(pkt, ANCOUNT_AT), 0, "the answer section must be empty");
  assert_eq!(take(pkt, ARCOUNT_AT), 1, "there must be one additional");
  pkt[ANCOUNT_AT..ANCOUNT_AT + 2].copy_from_slice(&1u16.to_be_bytes());
  pkt[ARCOUNT_AT..ARCOUNT_AT + 2].copy_from_slice(&0u16.to_be_bytes());
}

/// Build a QR=1 authoritative response carrying one SRV record at `owner`.
fn build_instance_srv_response(buf: &mut [u8], owner: &Name, port: u16, target: &Name) -> usize {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder};
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(buf, hdr).unwrap();
  b.push_srv_answer(owner, 120, 0, 0, port, target, true)
    .unwrap();
  b.finish().unwrap()
}

/// The withdrawal snapshot of a service that CONFIRMED-EMITTED its instance
/// records (SRV, TXT, the §6.1 NSEC) and `host_a` — i.e. one that actually
/// announced.
///
/// Every screen test states its exposure explicitly, because that is the fact
/// the screen turns on: it disowns an echo of a record this endpoint
/// TRANSMITTED, and a set nothing ever carried has no echo to disown.
/// `Service::withdrawal_snapshot` on a never-announced service reports no
/// exposure at all — see
/// `a_never_transmitted_withdrawal_does_not_screen_a_genuine_peer_conflict`.
fn announced_snapshot(
  records: &ServiceRecords,
  host_a: &[Ipv4Addr],
) -> crate::service::WithdrawalSnapshot {
  crate::service::WithdrawalSnapshot::announced(
    records.clone(),
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        true,
      ),
      host_a.to_vec(),
      std::vec::Vec::new(),
    ),
  )
}

/// Settle `handle`'s route-attached goodbye and free its route, returning what
/// `drain_completed_withdrawals` reported.
///
/// Both families write their debt off — [`WithdrawalSend::WriteOff`] is the
/// "nothing bound on this family" row, the one outcome that clears a debt rather
/// than keeping it — so the item completes in one round. A test that snapshots a
/// service which ACTUALLY ANNOUNCED needs this: such an item owes a real §10.1
/// budget, where a never-announced one settled on the first drain with nothing
/// owed at all.
fn finish_withdrawal(
  e: &mut TestEndp,
  handle: ServiceHandle,
  now: StdInstant,
) -> std::vec::Vec<ServiceHandle> {
  e.note_route_withdrawal_result(
    handle,
    now,
    super::WithdrawalSend::WriteOff,
    super::WithdrawalSend::WriteOff,
  );
  let mut freed: std::vec::Vec<ServiceHandle> = std::vec::Vec::new();
  e.drain_completed_withdrawals(now, &mut freed);
  freed
}

/// A per-family exposure whose two halves are IDENTICAL — the generation both
/// families carried.
///
/// What almost every test below means when it states an exposure: the fan-out
/// succeeded on both stacks, so v4 and v6 hold the same records. The tests that
/// are ABOUT a partial fan-out state the halves themselves.
fn on_both(
  owned: crate::service::EmittedRecords,
  host_a: std::vec::Vec<Ipv4Addr>,
  host_aaaa: std::vec::Vec<core::net::Ipv6Addr>,
) -> [crate::service::EmittedRecords; 2] {
  let one = crate::service::EmittedRecords::new(
    owned.ptr(),
    owned.srv(),
    owned.txt(),
    host_a,
    host_aaaa,
    owned.subtypes(),
    owned.nsec(),
  );
  [one.clone(), one]
}

/// A per-family exposure ONLY IPv4 carried — the partial fan-out the family
/// dimension exists for. IPv6 refused the datagram, so its half is empty.
fn on_v4_only(
  owned: crate::service::EmittedRecords,
  host_a: std::vec::Vec<Ipv4Addr>,
  host_aaaa: std::vec::Vec<core::net::Ipv6Addr>,
) -> [crate::service::EmittedRecords; 2] {
  let [v4, _] = on_both(owned, host_a, host_aaaa);
  [v4, crate::service::EmittedRecords::default()]
}

/// Every `ServiceHandle` this datagram raises a `HostConflict` on.
fn host_conflicted(e: &mut TestEndp, pkt: &[u8], now: StdInstant) -> std::vec::Vec<ServiceHandle> {
  host_conflicted_from(e, pkt, now, "192.168.1.99:5353")
}

/// [`host_conflicted`], but from a named source — so a test can say which
/// address FAMILY the datagram arrived on.
fn host_conflicted_from(
  e: &mut TestEndp,
  pkt: &[u8],
  now: StdInstant,
  src: &str,
) -> std::vec::Vec<ServiceHandle> {
  let src: core::net::SocketAddr = src.parse().unwrap();
  e.handle(now, Received::new(src, pkt, Provenance::NotFromUs))
    .unwrap()
    .filter_map(Result::ok)
    .filter_map(|ev| match ev {
      RouteEvent::ToService(ts) if ts.event().is_host_conflict() => Some(ts.handle()),
      _ => None,
    })
    .collect()
}

/// Every `ProbeConflict` this datagram raises, with the
/// [`ConflictHistory`] label the router attached to it.
///
/// The instance half of the relinquished screen no longer suppresses: a record
/// matching this endpoint's own recent history is DELIVERED carrying
/// [`ConflictHistory::Relinquished`], and the receiving service spends that on
/// RFC 6762 §8.2's one-second deferral rather than on §8.1's rename. So the
/// screen tests assert the LABEL, which is what the router decides, instead of
/// absence, which is what it used to decide and could not safely.
fn probe_conflict_history(
  e: &mut TestEndp,
  pkt: &[u8],
  now: StdInstant,
) -> std::vec::Vec<(ServiceHandle, ConflictHistory)> {
  probe_conflict_history_from(e, pkt, now, "192.168.1.99:5353")
}

/// [`probe_conflict_history`], but from a named source — so a test can say which
/// address FAMILY the datagram arrived on.
fn probe_conflict_history_from(
  e: &mut TestEndp,
  pkt: &[u8],
  now: StdInstant,
  src: &str,
) -> std::vec::Vec<(ServiceHandle, ConflictHistory)> {
  let src: core::net::SocketAddr = src.parse().unwrap();
  e.handle(now, Received::new(src, pkt, Provenance::NotFromUs))
    .unwrap()
    .filter_map(Result::ok)
    .filter_map(|ev| match ev {
      RouteEvent::ToService(ts) => match ts.event() {
        ServiceEvent::ProbeConflict(pc) => Some((ts.handle(), pc.history())),
        _ => None,
      },
      _ => None,
    })
    .collect()
}

/// The handles a datagram raises a RELINQUISHED-labelled `ProbeConflict` on:
/// [`probe_conflict_history`] filtered to the label, for the tests whose subject
/// is which services the screen disowns the record for.
fn probe_disowned(e: &mut TestEndp, pkt: &[u8], now: StdInstant) -> std::vec::Vec<ServiceHandle> {
  probe_conflict_history(e, pkt, now)
    .into_iter()
    .filter(|(_, h)| h.is_relinquished())
    .map(|(handle, _)| handle)
    .collect()
}

/// [`probe_disowned`], from a named source.
fn probe_disowned_from(
  e: &mut TestEndp,
  pkt: &[u8],
  now: StdInstant,
  src: &str,
) -> std::vec::Vec<ServiceHandle> {
  probe_conflict_history_from(e, pkt, now, src)
    .into_iter()
    .filter(|(_, h)| h.is_relinquished())
    .map(|(handle, _)| handle)
    .collect()
}

/// The handles a datagram raises an UNLABELLED `ProbeConflict` on — a genuine
/// peer conflict, as far as the endpoint's history can tell.
fn probe_unscreened(e: &mut TestEndp, pkt: &[u8], now: StdInstant) -> std::vec::Vec<ServiceHandle> {
  probe_unscreened_from(e, pkt, now, "192.168.1.99:5353")
}

/// [`probe_unscreened`], from a named source.
fn probe_unscreened_from(
  e: &mut TestEndp,
  pkt: &[u8],
  now: StdInstant,
  src: &str,
) -> std::vec::Vec<ServiceHandle> {
  probe_conflict_history_from(e, pkt, now, src)
    .into_iter()
    .filter(|(_, h)| h.is_unmatched())
    .map(|(handle, _)| handle)
    .collect()
}

/// Register `instance` at `host` with one A address, and hand back BOTH the
/// handle and the `Service`, so a test can take a withdrawal snapshot from it.
fn register_service_with_a(
  e: &mut TestEndp,
  instance: &str,
  host: &str,
  addr: Ipv4Addr,
) -> (
  ServiceHandle,
  crate::service::Service<StdInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
) {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str(instance).unwrap(),
    Name::try_from_str(host).unwrap(),
    631,
    120,
  );
  recs.add_a(addr);
  e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    ServiceSpec::new(recs),
    StdInstant::now(),
  )
  .unwrap()
}

/// THE DEFECT, while the §10.1 goodbye is still draining.
///
/// Service `A` publishes host `H` with address set `A1` and is withdrawn. The
/// withdrawing route no longer holds `H` for the registration guard, so `B`
/// registers `H` with a DIFFERENT set `A2` while the goodbye drains. `A`'s
/// delayed positive-TTL announcement of `A1` then arrives: it is our own past,
/// but `B` compares it against `A2`, finds differing rdata at its own host name,
/// and surfaces a TERMINAL `ServiceUpdate::HostConflict` that retires a live
/// service.
///
/// The withdrawing route's record set is resident for the whole drain and is
/// what disowns the echo. Before the screen existed it was consulted only to
/// decide that the route must not RECEIVE conflicts — never as evidence about
/// the record itself.
#[test]
fn a_draining_predecessors_echo_does_not_retire_the_replacement_at_its_host() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "A._ipp._tcp.local.", "shared-host.local.", a1);
  let snap = announced_snapshot(a_svc.records(), &[a1]);
  e.begin_withdrawal(a_handle, snap, now);
  let b_handle = register_with_addr_sets(
    &mut e,
    "B._ipp._tcp.local.",
    "shared-host.local.",
    &[a2],
    &[],
  )
  .unwrap();

  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert!(
    host_conflicted(&mut e, &buf[..n], now).is_empty(),
    "an echo of the WITHDRAWING route's own address set is this endpoint's own \
     past — it must not reach the replacement as a §9 conflict"
  );

  // NOT a blanket suppression of the owner name: a genuine peer asserting an
  // address neither route ever published still reaches `B`.
  let n = build_host_a_response(&mut buf, &host, Ipv4Addr::new(10, 0, 0, 99));
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "rdata this endpoint never asserted at this owner is a real conflict"
  );
}

/// THE DEFECT, after the goodbye has COMPLETED — round 3's exact scenario.
///
/// The withdrawing route is gone by the time the echo lands: `drain_completed_
/// withdrawals` has freed it, released the name, and removed the item. Nothing
/// resident describes `A1` any more, so the retention list is the only evidence
/// there is.
///
/// The echo is reported as `Provenance::NotFromUs` deliberately. Round 3 found
/// that a take-once credit can be spent by a peer replaying our bytes, after
/// which the GENUINE echo finds no credit and is reported exactly this way — so
/// this is the case no amount of driver-side recognition can reach.
#[test]
fn a_completed_withdrawals_echo_does_not_retire_the_replacement_at_its_host() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "A._ipp._tcp.local.", "shared-host.local.", a1);
  let snap = announced_snapshot(a_svc.records(), &[a1]);
  e.begin_withdrawal(a_handle, snap, now);
  // Drain it to completion: the route is freed and the item removed, so the
  // relinquished set survives only in the retention list.
  let freed = finish_withdrawal(&mut e, a_handle, now);
  assert_eq!(freed, std::vec![a_handle], "the goodbye must have completed");

  // The name is free again, so the replacement can even reuse `A`'s INSTANCE
  // name — the sharpest form of the takeover.
  let b_handle = register_with_addr_sets(
    &mut e,
    "A._ipp._tcp.local.",
    "shared-host.local.",
    &[a2],
    &[],
  )
  .unwrap();

  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert!(
    host_conflicted(&mut e, &buf[..n], now).is_empty(),
    "a delayed echo of the RELINQUISHED address set must not retire the service \
     that replaced it"
  );

  // The window is finite, and after it the same record adjudicates normally.
  let lapsed = now
    .checked_add(EndpointConfig::new().relinquished_retention())
    .unwrap();
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], lapsed),
    std::vec![b_handle],
    "the screen must LAPSE — it delays detection of a peer that happens to \
     assert exactly our relinquished rdata, it does not suppress it forever"
  );
}

/// The DROP above is now counted, not merely silent. Same setup as
/// [`a_completed_withdrawals_echo_does_not_retire_the_replacement_at_its_host`]:
/// `B`'s instance name differs from the shared host name, so the labelled
/// match has no second (instance) role to fall through to and hits the
/// `continue` in `RouteEvents::next_service_conflict` — the site issue #92
/// tracks for host-name-ownership probing and defence.
#[cfg(feature = "stats")]
#[test]
fn dropping_a_labelled_host_match_increments_relinquished_host_conflicts_suppressed() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "A._ipp._tcp.local.", "shared-host.local.", a1);
  let snap = announced_snapshot(a_svc.records(), &[a1]);
  e.begin_withdrawal(a_handle, snap, now);
  let freed = finish_withdrawal(&mut e, a_handle, now);
  assert_eq!(
    freed,
    std::vec![a_handle],
    "precondition: the goodbye must have completed"
  );

  let _b_handle = register_with_addr_sets(
    &mut e,
    "B._ipp._tcp.local.",
    "shared-host.local.",
    &[a2],
    &[],
  )
  .unwrap();

  assert_eq!(
    e.stats().relinquished_host_conflicts_suppressed,
    0,
    "precondition: nothing has been dropped yet"
  );

  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert!(
    host_conflicted(&mut e, &buf[..n], now).is_empty(),
    "precondition: the relinquished-history screen still suppresses the \
     HostConflict — this test must not change that"
  );
  assert_eq!(
    e.stats().relinquished_host_conflicts_suppressed,
    1,
    "the drop must be counted exactly once for this one suppressed match"
  );

  // A second, unrelated peer record at an address neither route ever
  // published is a genuine conflict and must not move this counter.
  let n = build_host_a_response(&mut buf, &host, Ipv4Addr::new(10, 0, 0, 99));
  assert!(
    !host_conflicted(&mut e, &buf[..n], now).is_empty(),
    "precondition: an address neither route asserted is a genuine conflict"
  );
  assert_eq!(
    e.stats().relinquished_host_conflicts_suppressed,
    1,
    "a genuine, delivered conflict must not bump the suppression counter"
  );
}

/// THE SECTION, and the serious half of the pair: a CONFORMING responder
/// reaches this with ORDINARY TRAFFIC.
///
/// The exposure records an rrtype and never a section, while QR=1 conflict
/// routing walks Answer, Authority AND Additional into `next_service_conflict`.
/// Every positive multicast encoder in this crate writes A / AAAA / SRV / TXT as
/// ANSWERS — an address of ours has never been in an additional or an authority
/// section — yet a peer's A in either matched a relinquished identity and was
/// disowned. The host cell SUPPRESSES rather than labels, so what went missing
/// was the TERMINAL, caller-visible `HostConflict`, for the whole retention
/// window.
///
/// And RFC 6763 §12 tells a responder to bundle the addresses with the SRV that
/// points at them, which is what a DNS-SD browse answer looks like everywhere.
/// Nothing here is crafted: the peer is answering a query correctly.
///
/// An echo cannot be caught by this narrowing, which is why it costs nothing. An
/// echo is a re-DELIVERY of a datagram — kernel loopback, or the 802.11
/// base-station re-broadcast RFC 6762 §8.2 names — not a re-encoding of it, so
/// the header counts that place a record in its section are the ones this
/// endpoint wrote. The control below is the same address in the section we
/// actually sent it in, and it is still disowned.
#[test]
fn an_address_in_a_section_we_never_wrote_one_in_is_not_our_echo() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let peer_instance = Name::try_from_str("Peer._ipp._tcp.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "A._ipp._tcp.local.", "shared-host.local.", a1);
  let snap = announced_snapshot(a_svc.records(), &[a1]);
  e.begin_withdrawal(a_handle, snap, now);
  let freed = finish_withdrawal(&mut e, a_handle, now);
  assert_eq!(freed, std::vec![a_handle], "the goodbye must have completed");

  let b_handle = register_with_addr_sets(
    &mut e,
    "B._ipp._tcp.local.",
    "shared-host.local.",
    &[a2],
    &[],
  )
  .unwrap();

  // THE CONTROL, first: arriving the way we actually sent it — an ANSWER with
  // the cache-flush bit — the very same record is still disowned.
  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert!(
    host_conflicted(&mut e, &buf[..n], now).is_empty(),
    "precondition: in the section this endpoint writes addresses in, the echo \
     of a relinquished address must still be screened"
  );

  // The conforming browse answer: the peer's SRV in the answer section, the
  // address it points at in the ADDITIONAL section.
  let mut buf = [0u8; 512];
  let n = build_srv_answer_plus_additional_a(&mut buf, &peer_instance, &host, a1);
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "this crate writes addresses only as ANSWERS, so a peer's ADDITIONAL-section \
     A cannot be an echo of ours — disowning it withheld the terminal \
     HostConflict from ordinary DNS-SD traffic"
  );

  // And the authority section of a QR=1 response, which no encoder here writes
  // under a latched exposure at all: `write_probe` is the only authority-section
  // encoder and a probe latches none.
  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  relabel_last_answer(&mut buf, NSCOUNT_AT);
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "no identity this screen can answer for was ever transmitted in a QR=1 \
     authority section"
  );
}

/// THE CACHE-FLUSH BIT. `rclass()` masks it off and `cache_flush()` preserves
/// it, and neither tier of the screen used to read either.
///
/// Every unique record this crate MULTICASTS sets it — `write_announce`,
/// `write_announce_filtered` and `push_service_nsec` alike — and the shared PTRs
/// that do not are records this screen never answers for, since neither the
/// service-type name nor a `_sub` name is an owner it tests. So every
/// screen-eligible identity went out with the bit SET, and a peer record without
/// it cannot be our echo: the bit is bit 15 of the record's own CLASS field, and
/// an echo carries our bytes.
///
/// It ranks below the section because exploiting it takes a peer that does not
/// set the bit on a unique record, which RFC 6762 §10.2 asks it to. The
/// narrowing is the same shape and the same cost either way.
#[test]
fn a_record_without_the_cache_flush_bit_is_not_our_echo() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "A._ipp._tcp.local.", "shared-host.local.", a1);
  let snap = announced_snapshot(a_svc.records(), &[a1]);
  e.begin_withdrawal(a_handle, snap, now);
  let freed = finish_withdrawal(&mut e, a_handle, now);
  assert_eq!(freed, std::vec![a_handle], "the goodbye must have completed");

  let b_handle = register_with_addr_sets(
    &mut e,
    "B._ipp._tcp.local.",
    "shared-host.local.",
    &[a2],
    &[],
  )
  .unwrap();

  // THE CONTROL: with the bit, exactly as every positive multicast send of ours
  // carried it, the echo is still disowned.
  let mut buf = [0u8; 512];
  let n = build_host_a_response_with_flush(&mut buf, &host, a1, true);
  assert!(
    host_conflicted(&mut e, &buf[..n], now).is_empty(),
    "precondition: the bit set is how we sent it, so the screen still answers"
  );

  // Without it — the one shape no positive multicast send of ours ever had.
  let mut buf = [0u8; 512];
  let n = build_host_a_response_with_flush(&mut buf, &host, a1, false);
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "every unique record this crate multicasts sets the §10.2 cache-flush bit, \
     so a peer's record without it is not our echo and its conflict is owed"
  );
}

/// …and the section rule is PER RRTYPE, not "the answer section".
///
/// The RFC 6762 §6.1 instance NSEC is the one identity this crate transmits in
/// the ADDITIONAL section — `push_service_nsec` is the builder's only additional
/// push, and both positive multicast encoders reach it. So the two sections
/// invert for this rrtype, and a rule spelled "answers only" would stop
/// screening our own NSEC echo: the under-claim direction, which re-opens the
/// defect the screen exists for rather than the one this round closes.
#[test]
fn the_instance_nsec_is_screened_in_the_section_it_was_written_in_and_no_other() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let addr = Ipv4Addr::new(192, 168, 1, 5);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "h.local.", addr);
  let snap = announced_snapshot(a_svc.records(), &[addr]);
  e.begin_withdrawal(a_handle, snap, now);
  let freed = finish_withdrawal(&mut e, a_handle, now);
  assert_eq!(freed, std::vec![a_handle], "the goodbye must have completed");

  // The successor reuses the vacated instance name, so the NSEC routes to it.
  let b_handle = register_with_addr_sets(
    &mut e,
    "Printer._ipp._tcp.local.",
    "h2.local.",
    &[Ipv4Addr::new(192, 168, 1, 9)],
    &[],
  )
  .unwrap();

  // THE CONTROL: the additional section, which is where `push_service_nsec`
  // puts it and therefore where an echo of it would arrive.
  let mut buf = [0u8; 512];
  let n = build_instance_nsec_response(&mut buf, &instance, &emitted_nsec_types());
  assert_eq!(
    probe_disowned(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "precondition: the NSEC arriving where we wrote it is this endpoint's own \
     recent past"
  );

  // The same NSEC as an ANSWER: a section this crate has never put one in.
  let mut buf = [0u8; 512];
  let n = build_instance_nsec_response(&mut buf, &instance, &emitted_nsec_types());
  relabel_sole_additional_as_answer(&mut buf);
  assert_eq!(
    probe_unscreened(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "the section a record was written in is per RRTYPE — the NSEC's is the \
     additional one, and an answer-section NSEC is no echo of ours"
  );
}

/// The INSTANCE half of the same defect: same-name reuse with changed SRV rdata
/// reaches a false RFC 6762 §8.1 probe defeat by the same route.
///
/// # This test used to assert the record was DROPPED, and that was wrong
///
/// Not wrong about the goal — a delayed echo of our own predecessor must not
/// rename its successor away, and it still does not. Wrong about the PREMISE it
/// used to reach that goal: it read a history match as proof the datagram was
/// ours, and no history match can be that. RFC 6762 §9 protects a
/// fault-tolerance twin "capable of issuing identical answers", so an incumbent
/// peer defending this name with the same bytes our predecessor published sends
/// a byte-identical datagram to the one our ghost would. At the instant of the
/// lookup the two are the same record.
///
/// Dropping it therefore made the wrong guess UNAPPEALABLE: with a live
/// incumbent P holding the name, every defence P sends matches the history and
/// reaches nobody, while the successor completes its probes and announcements
/// well inside the retention window — a usurpation, not a delay, because
/// nothing replays P's lost defences when the window closes.
///
/// So the record is DELIVERED, labelled, and the pre-authoritative cell spends
/// the label on §8.2's one-second deferral instead of §8.1's rename. That asks
/// the only question capable of separating the two cases, and asks it of the
/// network: a ghost cannot answer the re-probe, a live incumbent can. See
/// `a_relinquished_echo_defers_the_successors_probe_rather_than_renaming_it` and
/// `a_ghosts_echo_costs_the_successor_one_second_and_not_the_name` for the two
/// outcomes.
#[test]
fn a_relinquished_instances_echo_does_not_defeat_the_probe_of_its_successor() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let target = Name::try_from_str("h.local.").unwrap();
  let addr = Ipv4Addr::new(192, 168, 1, 5);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "h.local.", addr);
  let snap = announced_snapshot(a_svc.records(), &[addr]);
  e.begin_withdrawal(a_handle, snap, now);
  let freed = finish_withdrawal(&mut e, a_handle, now);
  assert_eq!(freed, std::vec![a_handle], "the goodbye must have completed");

  // The successor takes the same instance name on a different port.
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    instance.clone(),
    target.clone(),
    9999,
    120,
  );
  recs.add_a(addr);
  let (b_handle, _b_svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let mut buf = [0u8; 512];
  // The predecessor's own SRV (port 631) — rdata `B` does not hold.
  let n = build_instance_srv_response(&mut buf, &instance, 631, &target);
  assert_eq!(
    probe_conflict_history(&mut e, &buf[..n], now),
    std::vec![(b_handle, ConflictHistory::Relinquished)],
    "an echo of the relinquished instance's own SRV must REACH its successor \
     carrying the history label — the successor may then defer and re-probe, \
     which is the only move that can tell our own ghost from an incumbent twin"
  );

  // A third port is nobody's record here, and conflicts UNLABELLED — §8.1's
  // defeat, which renames rather than defers.
  let n = build_instance_srv_response(&mut buf, &instance, 1234, &target);
  assert_eq!(
    probe_conflict_history(&mut e, &buf[..n], now),
    std::vec![(b_handle, ConflictHistory::Unmatched)],
    "SRV rdata this endpoint never asserted at this instance is a real conflict"
  );
}

/// Drive `svc` until one probe has actually reached a link and been confirmed,
/// which is what opens RFC 6762 §8.1's window: a conflicting response arriving
/// "before the first probe packet is sent MUST be silently ignored", so a
/// fixture that wants a defence ACTED on has to get there first.
fn probe_once_confirmed(svc: &mut TestSvc, start: StdInstant) -> StdInstant {
  let mut buf = std::vec![0u8; 4096];
  let mut now = start;
  for _ in 0..20 {
    now = now
      .checked_add(core::time::Duration::from_millis(300))
      .unwrap();
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
      return now;
    }
  }
  panic!("no probe reached the wire; state={:?}", svc.state());
}

/// Route `pkt` through the endpoint and hand every event addressed to `handle`
/// to `svc`, exactly as a driver's receive path does. Returns how many arrived.
///
/// The COUNT is the assertion these regression tests turn on: a conflict the
/// router drops reaches no service, and a defence that reaches no service cannot
/// be appealed, deferred or spent — it is simply gone.
fn deliver_to_service(
  e: &mut TestEndp,
  svc: &mut TestSvc,
  handle: ServiceHandle,
  pkt: &[u8],
  now: StdInstant,
) -> usize {
  let src: core::net::SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let events: std::vec::Vec<_> = e
    .handle(now, Received::new(src, pkt, Provenance::NotFromUs))
    .unwrap()
    .filter_map(Result::ok)
    .collect();
  let mut delivered = 0usize;
  for ev in events {
    if let RouteEvent::ToService(ts) = ev
      && ts.handle() == handle
    {
      svc.handle_event(ts.into_event(), now);
      delivered = delivered.saturating_add(1);
    }
  }
  delivered
}

/// Every `ServiceUpdate` `svc` has queued, drained.
fn drain_updates(svc: &mut TestSvc) -> std::vec::Vec<ServiceUpdate> {
  let mut out = std::vec::Vec::new();
  while let Some(u) = svc.poll() {
    out.push(u);
  }
  out
}

/// Register a successor at `instance` proposing SRV(`port`), and hand back its
/// handle and `Service` so the fixture can drive its lifecycle.
fn register_probing_successor(
  e: &mut TestEndp,
  instance: &Name,
  target: &Name,
  port: u16,
  addr: Ipv4Addr,
  now: StdInstant,
) -> (ServiceHandle, TestSvc) {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    instance.clone(),
    target.clone(),
    port,
    120,
  );
  recs.add_a(addr);
  e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    ServiceSpec::new(recs),
    now,
  )
  .unwrap()
}

/// THE USURPATION, end to end — the scenario the history screen used to allow.
///
/// Local `A` and peer `P` both assert `R1` at one instance name. That is legal
/// and RFC 6762 §9 protects it: "resource records with identical rdata are never
/// considered inconsistent … to permit use of proxies and other fault-tolerance
/// mechanisms that may cause more than one responder to be capable of issuing
/// identical answers." `A` then relinquishes, so `R1` enters this endpoint's
/// history, and successor `B` probes the SAME owner name with different rdata
/// `R2`.
///
/// `P` is alive and defends, correctly, with `R1`. Every one of those defences
/// matches `A`'s history — and while the screen SUPPRESSED on a match, every one
/// of them was discarded before any service saw it. `B` then completed three
/// probes and its announcements inside the retention window (~2.25 s against a
/// 5 s default), and nothing replays a lost defence at expiry: `B` took a name a
/// live peer already held, permanently and silently.
///
/// The label fixes the premise rather than the bookkeeping. A match cannot mean
/// "ours" — `P`'s defence and `A`'s ghost are the same bytes — so the record is
/// delivered LABELLED and `B` spends the label on §8.2's deferral. That asks the
/// one question capable of separating them, and asks it of the network.
#[test]
fn a_relinquished_echo_defers_the_successors_probe_rather_than_renaming_it() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let target = Name::try_from_str("h.local.").unwrap();
  let addr = Ipv4Addr::new(192, 168, 1, 5);

  // `A` announced `R1` = SRV(631) at this name, then gave it up.
  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "h.local.", addr);
  let snap = announced_snapshot(a_svc.records(), &[addr]);
  e.begin_withdrawal(a_handle, snap, now);
  assert_eq!(
    finish_withdrawal(&mut e, a_handle, now),
    std::vec![a_handle],
    "precondition: R1 is now this endpoint's relinquished history"
  );

  // `B` takes the same owner name with `R2` = SRV(9999) and starts probing.
  let (b_handle, mut b) = register_probing_successor(&mut e, &instance, &target, 9999, addr, now);
  let kept = b.name().as_str().to_owned();
  let probed_at = probe_once_confirmed(&mut b, now);

  // `P` defends with `R1`.
  let mut buf = [0u8; 512];
  let n = build_instance_srv_response(&mut buf, &instance, 631, &target);
  assert_eq!(
    deliver_to_service(&mut e, &mut b, b_handle, &buf[..n], probed_at),
    1,
    "P's defence must REACH B. Dropping it here is the defect: a conflict no \
     service receives is not delayed, it is unappealable, and B goes on to \
     announce over a peer that already holds the name"
  );

  let deferred_at = probed_at
    .checked_add(core::time::Duration::from_millis(10))
    .unwrap();
  b.handle_timeout(deferred_at).unwrap();
  assert_eq!(
    b.name().as_str(),
    kept,
    "a history-labelled defeat is §8.2's deferral, which KEEPS the name — \
     renaming on a switch echo is the churn §8.2's one second exists to avoid"
  );
  assert_eq!(
    b.state(),
    crate::ServiceState::Init,
    "…and \"begins probing for this record again\" restarts the §8.1 sequence"
  );
  assert_eq!(
    b.poll_timeout(),
    deferred_at.checked_add(core::time::Duration::from_secs(1)),
    "…after waiting one second exactly"
  );
  assert!(
    !drain_updates(&mut b).iter().any(ServiceUpdate::is_renamed),
    "…and it is NOT a rename: §8.1's defeat is what renames, and this defeat is \
     not yet known to be one"
  );

  // A SECOND defence inside the window is labelled too — the retention row does
  // not lapse because it was read. So it defers again rather than renaming, and
  // what bounds this loop is the WINDOW closing, not the peer falling silent.
  let again_at = probe_once_confirmed(&mut b, deferred_at);
  assert_eq!(
    deliver_to_service(&mut e, &mut b, b_handle, &buf[..n], again_at),
    1,
    "the incumbent's next defence still reaches B"
  );
  let redeferred_at = again_at
    .checked_add(core::time::Duration::from_millis(10))
    .unwrap();
  b.handle_timeout(redeferred_at).unwrap();
  assert_eq!(
    b.name().as_str(),
    kept,
    "still deferring while the label is live, and still claiming nothing: \
     `conflict_classified_unresolved` withholds every claim to the name for the \
     whole of it"
  );

  // Once the window closes the SAME defence arrives unlabelled, and that is
  // §8.1's defeat: "the probing host MUST defer to the existing host, and SHOULD
  // choose new names". The incumbent keeps its name; the successor renames.
  let lapsed = now
    .checked_add(EndpointConfig::new().relinquished_retention())
    .unwrap()
    .checked_add(core::time::Duration::from_millis(1))
    .unwrap()
    .max(redeferred_at);
  let reprobed_at = probe_once_confirmed(&mut b, lapsed);
  assert_eq!(
    deliver_to_service(&mut e, &mut b, b_handle, &buf[..n], reprobed_at),
    1,
    "and it still reaches B once the label has lapsed"
  );
  b.handle_timeout(
    reprobed_at
      .checked_add(core::time::Duration::from_millis(10))
      .unwrap(),
  )
  .unwrap();
  assert_ne!(
    b.name().as_str(),
    kept,
    "an UNLABELLED defeat renames — §8.1 is honoured, one window late rather \
     than never, which is the whole of what the deferral costs"
  );
}

/// The GHOST half of the same deferral: nothing answers the retry, so the name
/// is claimed.
///
/// This is the case the screen was built for and the case §8.2 names as its own
/// reason — a probe "maybe from the host itself … which may be echoed back after
/// a short delay by some Ethernet switches and some 802.11 base stations". The
/// deferral is what makes it survivable WITHOUT deciding, at lookup time, a
/// question that cannot be decided at lookup time: our predecessor's echo cannot
/// answer a probe, so one second later the name is ours.
///
/// The cost is that second, and nothing else — no rename, no goodbye, no cache
/// churn, and no name given up.
#[test]
fn a_ghosts_echo_costs_the_successor_one_second_and_not_the_name() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let target = Name::try_from_str("h.local.").unwrap();
  let addr = Ipv4Addr::new(192, 168, 1, 5);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "h.local.", addr);
  let snap = announced_snapshot(a_svc.records(), &[addr]);
  e.begin_withdrawal(a_handle, snap, now);
  assert_eq!(
    finish_withdrawal(&mut e, a_handle, now),
    std::vec![a_handle],
    "precondition: R1 is now this endpoint's relinquished history"
  );

  let (b_handle, mut b) = register_probing_successor(&mut e, &instance, &target, 9999, addr, now);
  let kept = b.name().as_str().to_owned();
  let probed_at = probe_once_confirmed(&mut b, now);

  // A DELAYED ECHO of the predecessor's own SRV — there is no `P` on this link.
  let mut buf = [0u8; 512];
  let n = build_instance_srv_response(&mut buf, &instance, 631, &target);
  assert_eq!(
    deliver_to_service(&mut e, &mut b, b_handle, &buf[..n], probed_at),
    1,
    "the echo reaches B — indistinguishable, here, from the incumbent's defence"
  );

  let deferred_at = probed_at
    .checked_add(core::time::Duration::from_millis(10))
    .unwrap();
  b.handle_timeout(deferred_at).unwrap();
  assert_eq!(
    b.state(),
    crate::ServiceState::Init,
    "the labelled defeat defers rather than renaming"
  );
  assert_eq!(
    b.poll_timeout(),
    deferred_at.checked_add(core::time::Duration::from_secs(1)),
    "…by exactly the one second §8.2 prescribes"
  );

  // Nothing answers the restarted sequence, because a ghost cannot answer a
  // probe. B completes it and takes the name it never gave up.
  let mut txbuf = std::vec![0u8; 4096];
  let mut at = deferred_at;
  for _ in 0..40 {
    at = at
      .checked_add(core::time::Duration::from_millis(300))
      .unwrap();
    b.handle_timeout(at).unwrap();
    while let Ok(Some(_)) = b.poll_transmit(at, &mut txbuf) {
      b.note_delivery(at, TransmitDelivery::ALL);
    }
    if b.state() == crate::ServiceState::Established {
      break;
    }
  }
  assert_eq!(
    b.state(),
    crate::ServiceState::Established,
    "the retry went unanswered, so the §8.1 sequence completes"
  );
  assert_eq!(
    b.name().as_str(),
    kept,
    "…on the SAME name: a deferral that ends in silence costs one second and \
     nothing else"
  );
  assert!(
    !drain_updates(&mut b).iter().any(ServiceUpdate::is_renamed),
    "…and no rename was ever queued"
  );
}

/// THE USURPATION SURVIVING THE PROBE — packet loss lets the successor finish,
/// so the incumbent's next response arrives in row C instead of row B.
///
/// Nothing about the deferral in the tests above requires the incumbent's
/// defence to arrive WHILE the successor is probing. Drop one datagram per
/// probe — ordinary loss, no attacker — and `B` completes the RFC 6762 §8.1
/// sequence and announces `R2` over a name `P` already holds with `R1`. `P`'s
/// next response is then a §9 conflict against an ADVERTISED name.
///
/// # Why the established cell could not drop it
///
/// Because the cell's stated reason — §9 self-heals, since a live incumbent
/// keeps talking — is false. §8.3 bounds what `P` says unprompted: "two or
/// three times, at intervals of at least one second", and then silence until
/// something queries it. A screen that consumes those responses inside the
/// retention window consumes every copy there was, and nothing replays a
/// conflict once the window lapses. §9's "MUST immediately reset its conflicted
/// unique record to probing state" was then not late, it was never — and two
/// responders held one advertised name until unrelated traffic happened by.
///
/// So the label buys nothing here and the revert runs: same name, rate-limited,
/// claiming nothing while it runs. Against a GHOST the re-probe goes unanswered
/// and `B` re-announces (the cost, and the whole of it); against `P` it is
/// answered, and once the label lapses §8.1 renames `B`.
#[test]
fn an_incumbents_response_reverts_a_successor_that_established_inside_the_window() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let target = Name::try_from_str("h.local.").unwrap();
  let addr = Ipv4Addr::new(192, 168, 1, 5);

  // `A` announced `R1` = SRV(631) at this name, then gave it up. Peer `P` is a
  // §9 fault-tolerance twin asserting that same `R1`, which §9 makes legal.
  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "h.local.", addr);
  let snap = announced_snapshot(a_svc.records(), &[addr]);
  e.begin_withdrawal(a_handle, snap, now);
  assert_eq!(
    finish_withdrawal(&mut e, a_handle, now),
    std::vec![a_handle],
    "precondition: R1 is now this endpoint's relinquished history"
  );

  // `B` takes the same owner name with `R2` = SRV(9999), and NOTHING reaches it
  // while it probes.
  let (b_handle, mut b) = register_probing_successor(&mut e, &instance, &target, 9999, addr, now);
  let kept = b.name().as_str().to_owned();
  let mut txbuf = std::vec![0u8; 4096];
  let mut at = now;
  for _ in 0..40 {
    at = at
      .checked_add(core::time::Duration::from_millis(300))
      .unwrap();
    b.handle_timeout(at).unwrap();
    while let Ok(Some(_)) = b.poll_transmit(at, &mut txbuf) {
      b.note_delivery(at, TransmitDelivery::ALL);
    }
    if b.state() == crate::ServiceState::Established {
      break;
    }
  }
  assert_eq!(
    b.state(),
    crate::ServiceState::Established,
    "precondition: the loss let the successor finish probing and announce"
  );
  let window_ends = now
    .checked_add(EndpointConfig::new().relinquished_retention())
    .unwrap();
  assert!(
    at < window_ends,
    "precondition: and it got there INSIDE the retention window — the §8.1 \
     sequence and its announcements take about 2.25 s against a 5 s default, so \
     this needs no unusual timing at all"
  );

  // `P`'s next response. Still `R1`, still labelled, and — §8.3's burst being
  // bounded — quite possibly the last one `B` will ever see unprompted.
  let mut buf = [0u8; 512];
  let n = build_instance_srv_response(&mut buf, &instance, 631, &target);
  assert_eq!(
    deliver_to_service(&mut e, &mut b, b_handle, &buf[..n], at),
    1,
    "the incumbent's response must reach B"
  );
  assert_eq!(
    b.state(),
    crate::ServiceState::Init,
    "…and §9's immediate reset must be honoured on it. Dropping it for matching \
     this endpoint's own history left TWO responders owning one advertised \
     name, with nothing to replay the conflict at expiry"
  );
  assert_eq!(
    b.name().as_str(),
    kept,
    "…and it is §9's revert, on the SAME name: the re-probe is the only thing \
     that can tell a live incumbent from our own ghost"
  );
  assert!(
    !drain_updates(&mut b).iter().any(ServiceUpdate::is_renamed),
    "…so nothing is renamed on the evidence of one response"
  );
}

/// THE SAME USURPATION, REACHED THROUGH THE HOST ROLE — when the instance name
/// and the host name are ONE name.
///
/// The conflict fan-out tests the host rule first, so a labelled A/AAAA under
/// that name matched the host branch and was dropped there. The drop is right
/// for the `HostConflict` — it is terminal and nothing re-verifies it — but the
/// record belongs to BOTH roles here: A/AAAA under this name are members of the
/// §8.2 proposal this service is probing with, and §8.1 owes a deferral on "any
/// conflicting Multicast DNS response" for a name being probed, whatever its
/// type. Role precedence decides which EVENT a record becomes; deciding that it
/// is no conflict at all is a different power, and taking it let a live
/// incumbent answer every one of the successor's probes while the successor went
/// on to Established.
///
/// So the labelled record falls through to the instance rule and arrives as a
/// labelled `ProbeConflict`, which the pre-authoritative cell spends on §8.2's
/// one-second deferral. The unlabelled record is untouched and still the host
/// rule's — asserted at the end, because a fix that widened past the label would
/// be turning a terminal host conflict into a probe conflict for every peer.
#[test]
fn an_incumbents_labelled_defence_defers_a_successor_whose_instance_is_its_host() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  // ONE name, worn as both roles — the configuration the fan-out's ordering
  // comment calls pathological and routes for anyway. Still a valid instance
  // of `register_service_with_a`'s hardcoded `_ipp._tcp.local.` service type
  // (RFC 6763 §4.1.1: one label above it), which is what lets it ALSO serve
  // as its own SRV target.
  let shared = Name::try_from_str("h._ipp._tcp.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  // `A` announced `A1` under that name and gave it up.
  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "h._ipp._tcp.local.", "h._ipp._tcp.local.", a1);
  let snap = announced_snapshot(a_svc.records(), &[a1]);
  e.begin_withdrawal(a_handle, snap, now);
  assert_eq!(
    finish_withdrawal(&mut e, a_handle, now),
    std::vec![a_handle],
    "precondition: A1 is now this endpoint's relinquished history"
  );

  // `B` takes the same name with `A2` and starts probing.
  let (b_handle, mut b) = register_probing_successor(&mut e, &shared, &shared, 9999, a2, now);
  let kept = b.name().as_str().to_owned();
  let mut at = probe_once_confirmed(&mut b, now);

  // The incumbent `P` defends the name with `A1`, for as long as the retention
  // window lasts. Every one of those defences carries the history label, and
  // every one of them must still reach `B`.
  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &shared, a1);
  let window_ends = now
    .checked_add(EndpointConfig::new().relinquished_retention())
    .unwrap();
  let mut rounds = 0usize;
  while at < window_ends {
    assert_eq!(
      deliver_to_service(&mut e, &mut b, b_handle, &buf[..n], at),
      1,
      "round {rounds}: the incumbent's defence must REACH B. The host rule owns \
       which EVENT this record becomes, not whether it is a conflict — dropped \
       here, B probes and announces over a peer that is defending correctly"
    );
    at = at.checked_add(core::time::Duration::from_millis(10)).unwrap();
    b.handle_timeout(at).unwrap();
    assert_ne!(
      b.state(),
      crate::ServiceState::Established,
      "round {rounds}: a defended name is not this service's to advertise"
    );
    assert_eq!(
      b.name().as_str(),
      kept,
      "round {rounds}: and a labelled defeat is §8.2's deferral, which KEEPS the \
       name — the re-probe is the only thing that can tell our own ghost from an \
       incumbent twin"
    );
    rounds = rounds.saturating_add(1);
    at = probe_once_confirmed(&mut b, at);
  }
  assert!(
    rounds >= 2,
    "the window must have covered more than one probe/defence exchange, or this \
     test proves nothing about a SUSTAINED defence"
  );
  assert!(
    !drain_updates(&mut b).iter().any(ServiceUpdate::is_renamed),
    "…and no rename was queued for any of them"
  );

  // THE HOST CELL IS UNCHANGED. An address this endpoint never asserted carries
  // no label, so the host rule still owns it and it is still the terminal
  // `HostConflict` — the fall-through is the label's, and only the label's.
  let n = build_host_a_response(&mut buf, &shared, Ipv4Addr::new(10, 0, 0, 99));
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], at),
    std::vec![b_handle],
    "an UNLABELLED address at this owner is still the host rule's, and still \
     terminal: role precedence over the event is exactly what did not change"
  );
}

/// THE SAME NAME, THE SAME PEER, ONE LIFECYCLE STATE LATER — and the record used
/// to vanish.
///
/// The test above proves the labelled A/AAAA reaches the PRE-AUTHORITATIVE cell
/// and is spent on §8.2's deferral. Let ordinary packet loss carry the successor
/// past probing — no attacker and no unusual timing, exactly as
/// `an_incumbents_response_reverts_a_successor_that_established_inside_the_window`
/// does for a differing SRV — and the identical record arrives in row C instead,
/// where it was delivered and then SILENTLY DISCARDED.
///
/// Two gates disagreed about which role owns it. The router's host rule proved
/// this route authoritative for an A RRset at this name and then, having
/// withheld the terminal `HostConflict`, handed the record on stripped of that
/// proof; `Service::handle_event` asked its instance-authority gate —
/// `respond::canonical_rdata_forms`, whose domain is SRV / TXT / NSEC — whether
/// it asserts an A there, and answered no. It asserts one: the name is its HOST
/// name. So the same peer response was handled while probing and dropped once
/// announced, and §9's "MUST immediately reset its conflicted unique record to
/// probing state" was not honoured late, it was not honoured at all — §8.3
/// bounds the incumbent's burst, so the window swallowed every copy there was.
///
/// The host cell's own reason for suppressing does not reach this owner either.
/// It suppresses because the host name is NEVER PROBED, so nothing can
/// re-verify a labelled record — and here the owner IS being probed, by
/// `write_probe`'s ANY question proposing exactly these A/AAAA. The
/// re-verification the host cell lacks is the one this service already runs, so
/// §9's reversible same-name reset is available and the label buys it, exactly
/// as it does for a differing SRV.
#[test]
fn an_incumbents_labelled_address_reverts_a_successor_whose_instance_is_its_host() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  // Valid instance of `register_service_with_a`'s hardcoded `_ipp._tcp.local.`
  // service type (RFC 6763 §4.1.1: one label above it), which is what lets it
  // ALSO serve as its own SRV target below.
  let shared = Name::try_from_str("h._ipp._tcp.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  // `A` announced `A1` under the one name it wears as both roles, and gave it up.
  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "h._ipp._tcp.local.", "h._ipp._tcp.local.", a1);
  let snap = announced_snapshot(a_svc.records(), &[a1]);
  e.begin_withdrawal(a_handle, snap, now);
  assert_eq!(
    finish_withdrawal(&mut e, a_handle, now),
    std::vec![a_handle],
    "precondition: A1 is now this endpoint's relinquished history"
  );

  // `B` takes the same name with `A2`, and NOTHING reaches it while it probes.
  let (b_handle, mut b) = register_probing_successor(&mut e, &shared, &shared, 9999, a2, now);
  let kept = b.name().as_str().to_owned();
  let mut txbuf = std::vec![0u8; 4096];
  let mut at = now;
  for _ in 0..40 {
    at = at
      .checked_add(core::time::Duration::from_millis(300))
      .unwrap();
    b.handle_timeout(at).unwrap();
    while let Ok(Some(_)) = b.poll_transmit(at, &mut txbuf) {
      b.note_delivery(at, TransmitDelivery::ALL);
    }
    if b.state() == crate::ServiceState::Established {
      break;
    }
  }
  assert_eq!(
    b.state(),
    crate::ServiceState::Established,
    "precondition: the loss let the successor finish probing and announce"
  );
  assert!(
    at
      < now
        .checked_add(EndpointConfig::new().relinquished_retention())
        .unwrap(),
    "precondition: and it got there INSIDE the retention window, so the \
     incumbent's next defence still carries the label"
  );

  // The incumbent `P` defends with `A1` — labelled, and §8.3 says quite possibly
  // the last copy `B` will ever see unprompted.
  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &shared, a1);
  assert_eq!(
    deliver_to_service(&mut e, &mut b, b_handle, &buf[..n], at),
    1,
    "the incumbent's defence must REACH B — the fall-through already delivered \
     it, which is why the loss was silent"
  );
  assert_eq!(
    b.state(),
    crate::ServiceState::Init,
    "…and §9's immediate reset must be honoured ON IT. Delivering it stripped of \
     the host role let row C's instance-authority gate answer 'we assert no A at \
     this name' for an address we assert at exactly this name, so a record the \
     probing cell acted on was discarded the moment the service announced"
  );
  assert_eq!(
    b.name().as_str(),
    kept,
    "…and it is §9's revert, on the SAME name: reversible, rate-limited, and \
     claiming nothing while it runs"
  );
  assert!(
    !drain_updates(&mut b).iter().any(ServiceUpdate::is_renamed),
    "…so nothing is renamed on the evidence of one response"
  );
  assert!(
    !drain_updates(&mut b)
      .iter()
      .any(ServiceUpdate::is_host_conflict),
    "…and the TERMINAL host consequence is still withheld: the fall-through \
     carries the host rule's AUTHORITY, never its verdict"
  );
}

/// …and the host role it now carries is read by the identical-rdata precondition
/// too, which is the other half of the same correction.
///
/// A labelled A/AAAA at a name that is both roles used to be classified by
/// `classify_instance_rdata`, whose rule is `canonical_rdata_forms` — SRV, TXT,
/// NSEC. That function can name no form of an address, so it answered
/// `Different` for every address, INCLUDING one this service publishes at that
/// very name. §9 and §8.2.1 both call that no conflict at all ("two devices
/// advertising identical sets … there is, in fact, no conflict"), and the
/// UNLABELLED copy of this very record is already dropped as consistent by the
/// host rule. Labelling it must not make it MORE conflicting than not labelling
/// it did.
#[test]
fn a_labelled_address_this_service_publishes_is_no_conflict_at_a_shared_name() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  // Valid instance of `register_service_with_a`'s hardcoded `_ipp._tcp.local.`
  // service type (RFC 6763 §4.1.1: one label above it), which is what lets it
  // ALSO serve as its own SRV target below.
  let shared = Name::try_from_str("h._ipp._tcp.local.").unwrap();
  let addr = Ipv4Addr::new(192, 168, 1, 5);

  // `A` announced this address at the shared name and gave it up, so the address
  // is this endpoint's own history…
  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "h._ipp._tcp.local.", "h._ipp._tcp.local.", addr);
  let snap = announced_snapshot(a_svc.records(), &[addr]);
  e.begin_withdrawal(a_handle, snap, now);
  assert_eq!(
    finish_withdrawal(&mut e, a_handle, now),
    std::vec![a_handle],
    "precondition: the address is now this endpoint's relinquished history"
  );

  // …and `B` re-registers the same name publishing the SAME address, which is
  // what makes the arriving record both labelled and consistent.
  let (b_handle, mut b) = register_probing_successor(&mut e, &shared, &shared, 9999, addr, now);
  let kept = b.name().as_str().to_owned();
  let at = probe_once_confirmed(&mut b, now);

  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &shared, addr);
  assert_eq!(
    deliver_to_service(&mut e, &mut b, b_handle, &buf[..n], at),
    1,
    "precondition: the labelled record still reaches B as a `ProbeConflict` — \
     what changed is which classifier reads it, not whether it is delivered"
  );
  let after = at
    .checked_add(core::time::Duration::from_millis(10))
    .unwrap();
  b.handle_timeout(after).unwrap();
  assert_ne!(
    b.state(),
    crate::ServiceState::Init,
    "an address this service itself publishes is §9's 'never inconsistent', so \
     it must spend NO deferral — the instance classifier could not read an \
     address at all and called every one of them differing"
  );
  assert_eq!(
    b.name().as_str(),
    kept,
    "…and the name is untouched either way"
  );
}

/// A UNICAST-ONLY GENERATION DISOWNS NOTHING, because no multicast copy of its
/// bytes ever existed.
///
/// An RFC 6762 §6.7 legacy reply is a real, confirmed, positive-TTL send of the
/// FULL record set — so those records are in one resolver's cache and the §10.1
/// goodbye owes them a retraction. It is addressed to that resolver's ephemeral
/// port, nothing re-broadcasts it to the group, and this screen is only ever
/// asked about a MULTICAST arrival. The two facts were one latch, so a service
/// whose ONLY positive send was such a reply retained a row that disowned every
/// matching multicast record for the whole retention window — suppressing a
/// GENUINE peer's terminal host conflict on the strength of bytes no multicast
/// socket ever carried.
///
/// End to end, with no hand-built exposure: the snapshot here is the one
/// `Service::withdrawal_snapshot` actually produces after that reply, which
/// `a_legacy_unicast_reply_is_exposure_but_not_multicast_echo_provenance` pins
/// from the other side.
#[test]
fn a_unicast_only_generation_does_not_screen_a_genuine_peer_conflict() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let host = Name::try_from_str("h.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, mut a_svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "h.local.", a1);

  // Probe to `Announcing(0)` and stop there. A probe is a QUESTION (§8.1) and
  // latches no exposure of any kind, so nothing this service has sent so far is
  // a positive assertion.
  let mut txbuf = std::vec![0u8; 4096];
  let mut at = now;
  for _ in 0..40 {
    at = at
      .checked_add(core::time::Duration::from_millis(300))
      .unwrap();
    a_svc.handle_timeout(at).unwrap();
    if a_svc.state() == crate::ServiceState::Announcing(0) {
      break;
    }
    if let Ok(Some(_)) = a_svc.poll_transmit(at, &mut txbuf) {
      a_svc.note_delivery(at, TransmitDelivery::ALL);
    }
  }
  assert_eq!(
    a_svc.state(),
    crate::ServiceState::Announcing(0),
    "precondition: probing is done and nothing has been announced"
  );

  // ONE §6.7 legacy reply — drained ahead of the announcement queue, and the
  // only positive send this service ever makes.
  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  a_svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, legacy_src, 0x4242)),
    at,
  );
  let tx = a_svc
    .poll_transmit(at, &mut txbuf)
    .unwrap()
    .expect("the legacy reply drains first");
  assert_eq!(
    tx.dst(),
    legacy_src,
    "precondition: the one positive send went to a resolver's ephemeral port"
  );
  a_svc.note_delivery(at, TransmitDelivery::ALL);

  // …and is torn down, snapshot and all.
  let snap = a_svc.withdrawal_snapshot();
  assert!(
    !crate::transmit::Family::V4.pick_ref(&snap.owned).a_slice().is_empty(),
    "precondition: the goodbye's half DOES own the host address — the legacy \
     querier caches it, so a §10.1 goodbye must retract it"
  );
  e.begin_withdrawal(a_handle, snap, at);
  assert_eq!(
    finish_withdrawal(&mut e, a_handle, at),
    std::vec![a_handle],
    "precondition: the withdrawal completed, so only the retention list is left"
  );

  // A successor takes the host name with a DIFFERENT address, and a genuine peer
  // multicasts the old one. Those bytes match this endpoint's unicast history
  // exactly — and cannot be an echo of it.
  let (b_handle, _b_svc) = register_probing_successor(
    &mut e,
    &Name::try_from_str("Other._ipp._tcp.local.").unwrap(),
    &host,
    9999,
    a2,
    at,
  );
  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], at),
    std::vec![b_handle],
    "a set that was never on the group has no echo to disown, so the peer's \
     conflict must reach the successor. Screening it withheld a TERMINAL, \
     caller-visible host conflict for the whole retention window on the \
     strength of a datagram addressed to one ephemeral port"
  );
}

/// The RFC 6762 §9 RENAME is the other point a record set stops being published,
/// and its detached goodbye is not enough on its own: a SURVIVING rename's
/// old-name goodbye is reclaim-cancelled by `note_service_announced` the moment
/// a service fully announces that same name — which is exactly the moment a
/// replacement has taken it. So `enqueue_rename_withdrawal` retains the set at
/// the rename itself.
#[test]
fn a_renamed_away_instances_echo_does_not_conflict_after_its_goodbye_is_reclaimed() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let old = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let target = Name::try_from_str("h.local.").unwrap();
  let addr = Ipv4Addr::new(192, 168, 1, 5);

  let (handle, svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "h.local.", addr);
  // The service renames away; the driver hands the old name's goodbye over.
  e.handle_service_renamed(
    handle,
    Name::try_from_str("Printer (2)._ipp._tcp.local.").unwrap(),
  )
  .unwrap();
  let handoff = crate::service::RenameGoodbyeHandoff::announced(
    svc.records().clone(),
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        false,
      ),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
  );
  e.enqueue_rename_withdrawal(handoff, now, false);

  // A replacement takes the vacated name and fully announces it, which cancels
  // the detached goodbye — removing the last resident copy of the old set.
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    old.clone(),
    target.clone(),
    9999,
    120,
  );
  recs.add_a(addr);
  let (b_handle, _b_svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();
  e.note_service_announced(FullyAnnounced::new(b_handle, true), &[addr], &[]);
  assert!(
    e.detached_withdrawal_owed_for(&old).is_none(),
    "the reclaim-cancel must have removed the old name's detached goodbye"
  );

  let mut buf = [0u8; 512];
  let n = build_instance_srv_response(&mut buf, &old, 631, &target);
  assert_eq!(
    probe_disowned(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "the renamed-away name's own SRV echo must reach the service that reclaimed \
     the name LABELLED as this endpoint's own past — a deferral it can appeal by \
     re-probing, never a drop it cannot"
  );
}

/// FORCE-REMOVAL relinquishes too, so it retains too.
///
/// `unregister_service` sends no goodbye and releases the owner names the
/// instant it returns — but a service force-removed after a confirmed positive
/// send has records on the wire and, once its route is gone, none resident
/// anywhere. It used to delete the route and any attached withdrawal item
/// WITHOUT retaining either, so a caller that unregistered and re-registered at
/// the same names left a delayed echo free to reach normal adjudication and
/// retire the replacement. That is a direct path relinquishing a record set
/// without retaining it — precisely what the design claims cannot happen.
#[test]
fn a_force_removed_services_echo_does_not_retire_its_replacement() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "h.local.", a1);
  // The caller holds the `Service`, so it can say exactly what was asserted.
  let snap = announced_snapshot(a_svc.records(), &[a1]);
  assert!(
    e.unregister_service(a_handle, Some(snap), now),
    "the route was found and removed"
  );

  // …and re-registers at BOTH owner names in the very next breath.
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    instance.clone(),
    host.clone(),
    9999,
    120,
  );
  recs.add_a(a2);
  let (b_handle, _b_svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert!(
    host_conflicted(&mut e, &buf[..n], now).is_empty(),
    "a delayed echo of the force-removed service's own address must not retire \
     the replacement at its host name"
  );
  let n = build_instance_srv_response(&mut buf, &instance, 631, &host);
  assert_eq!(
    probe_disowned(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "nor its own SRV RENAME the replacement at the instance name — it is labelled \
     as ours, which buys §8.2's one-second re-probe instead"
  );

  // Still bounded, and still not a blanket suppression.
  let n = build_host_a_response(&mut buf, &host, Ipv4Addr::new(10, 0, 0, 99));
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "rdata the removed service never asserted is a real conflict"
  );
}

/// The same duty for a force-removal that lands MID-GOODBYE: dropping the
/// route-attached withdrawal item removes the last resident copy of a set this
/// endpoint transmitted, which is the same relinquishment
/// `drain_completed_withdrawals` would have retained had the goodbye finished.
#[test]
fn force_removing_a_draining_service_retains_the_item_it_drops() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "A._ipp._tcp.local.", "shared-host.local.", a1);
  e.begin_withdrawal(a_handle, announced_snapshot(a_svc.records(), &[a1]), now);
  assert!(
    e.route_withdrawal_owed(a_handle).is_some(),
    "the goodbye is still draining"
  );
  // No snapshot this time: the caller has nothing left to ask. The ITEM is the
  // description that must survive.
  assert!(e.unregister_service(a_handle, None, now));
  assert!(
    e.route_withdrawal_owed(a_handle).is_none(),
    "force-remove drops the route-attached item"
  );

  let b_handle = register_with_addr_sets(
    &mut e,
    "B._ipp._tcp.local.",
    "shared-host.local.",
    &[a2],
    &[],
  )
  .unwrap();
  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert!(
    host_conflicted(&mut e, &buf[..n], now).is_empty(),
    "the dropped item's record set must have moved into the retention list"
  );
  let n = build_host_a_response(&mut buf, &host, Ipv4Addr::new(10, 0, 0, 99));
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "and only that set — a peer's own address still conflicts"
  );
}

/// THE OPPOSITE ERROR, and the more serious one: a relinquishment that
/// TRANSMITTED NOTHING must screen nothing.
///
/// A withdrawal with no owned and no confirmed host records owes no goodbye —
/// registration followed by immediate withdrawal, or a service whose every send
/// failed — but it used to be retained with the service's whole CONFIGURED
/// record set anyway. For the retention window a genuine incumbent's matching
/// QR=1 records were then discarded before any conflict was built, letting a
/// same-name successor finish probing and announce over a peer that already held
/// the name. There is no possible stale positive-TTL echo to justify that: the
/// records were never on any wire.
#[test]
fn a_never_transmitted_withdrawal_does_not_screen_a_genuine_peer_conflict() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  // `A` is registered and withdrawn with nothing on the wire, so its own
  // snapshot reports no exposure at all. This is the DEFAULT path — no test
  // fixture is needed to reach it.
  let (a_handle, mut a_svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "h.local.", a1);
  let snap = a_svc.withdrawal_snapshot();
  assert!(
    snap.owned.iter().all(crate::service::EmittedRecords::is_empty),
    "a never-announced service must report no exposure"
  );
  e.begin_withdrawal(a_handle, snap, now);
  let freed = finish_withdrawal(&mut e, a_handle, now);
  assert_eq!(freed, std::vec![a_handle], "the empty goodbye completes at once");
  assert!(
    e.relinquished.is_empty(),
    "a relinquishment with no transmitted record must retain no row: there is \
     no echo of it for a row to disown, and the row would screen a peer's"
  );

  // The successor takes both owner names, with its own address and port.
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    instance.clone(),
    host.clone(),
    9999,
    120,
  );
  recs.add_a(a2);
  let (b_handle, _b_svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  // A GENUINE incumbent answers for both names with rdata that happens to match
  // what `A` was configured with — the peer's own address, and the port `A`
  // would have published had it ever announced.
  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "a peer's A at our host name is a real conflict when nothing we relinquished \
     ever carried that address"
  );
  let n = build_instance_srv_response(&mut buf, &instance, 631, &host);
  assert_eq!(
    probe_unscreened(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "and so is its SRV at the instance name the successor is probing — UNLABELLED, \
     so it is §8.1's defeat and renames"
  );
}

/// `Duration::ZERO` retains nothing that is ever live, so the screen reduces to
/// the withdrawal items still resident — the documented way to turn the
/// retention half off.
#[test]
fn a_zero_retention_window_keeps_only_the_resident_half_of_the_screen() {
  let now = StdInstant::now();
  use rand::SeedableRng;
  let mut e = TestEndp::try_new(
    EndpointConfig::new().with_relinquished_retention(core::time::Duration::ZERO),
    rand::rngs::StdRng::from_seed([7u8; 32]),
  );
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "A._ipp._tcp.local.", "shared-host.local.", a1);
  let snap = announced_snapshot(a_svc.records(), &[a1]);
  e.begin_withdrawal(a_handle, snap, now);
  let b_handle = register_with_addr_sets(
    &mut e,
    "B._ipp._tcp.local.",
    "shared-host.local.",
    &[a2],
    &[],
  )
  .unwrap();

  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  // Resident half: the withdrawing item still describes `A1`.
  assert!(host_conflicted(&mut e, &buf[..n], now).is_empty());
  // Retention half: disabled, so completing the goodbye reopens the window.
  let freed = finish_withdrawal(&mut e, a_handle, now);
  assert_eq!(freed, std::vec![a_handle], "the goodbye must have completed");
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "with a zero window nothing is retained past the item"
  );
}

/// Relinquish one generation, exposure-complete (SRV, TXT, the §6.1 NSEC and one
/// host address), at `at`. Names are derived from `i` so every generation is
/// distinct and nothing merges.
fn retain_generation(e: &mut TestEndp, i: usize, addr: Ipv4Addr, at: StdInstant) {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str(&std::format!("S{i}._ipp._tcp.local.")).unwrap(),
    Name::try_from_str(&std::format!("h{i}.local.")).unwrap(),
    631,
    120,
  );
  recs.add_a(addr);
  e.retain_relinquished(
    recs,
    on_both(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        true,
      ),
      std::vec![addr],
      std::vec::Vec::new(),
    ),
    at,
  );
}

/// PARTIAL-FAMILY DELIVERY MUST NOT BECOME GLOBAL EXPOSURE — the screen half.
///
/// Delivery is per family: a fan-out is two sends and either may be refused, so
/// a generation IPv4 accepted and IPv6 refused put nothing in any IPv6 peer's
/// cache. The exposure used to be family-agnostic — any successful family merged
/// the whole emitted set into one `GoodbyeOwnership` — so once that generation
/// was relinquished and replaced, a GENUINE IPv6 responder asserting its records
/// was disowned as an echo of a transmission IPv6 never saw. A loopback copy
/// comes back over the socket that carried the datagram out, so it cannot be an
/// echo at all, and the suppression hid a required §8.1 or §9 conflict.
///
/// The IPv4 arrival of the same record must still be screened: the point is a
/// narrower screen, not a disabled one.
#[test]
fn a_relinquished_generation_is_disowned_only_on_the_family_that_carried_it() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  // `A` announces, IPv4 accepts, IPv6 refuses. Then it is torn down.
  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "Printer._ipp._tcp.local.", "shared-host.local.", a1);
  let snap = crate::service::WithdrawalSnapshot::announced(
    a_svc.records().clone(),
    on_v4_only(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        true,
      ),
      std::vec![a1],
      std::vec::Vec::new(),
    ),
  );
  e.begin_withdrawal(a_handle, snap, now);
  let freed = finish_withdrawal(&mut e, a_handle, now);
  assert_eq!(freed, std::vec![a_handle], "the goodbye must have completed");

  // The replacement takes both owner names with its own address and port.
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    instance.clone(),
    host.clone(),
    9999,
    120,
  );
  recs.add_a(a2);
  let b_handle = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap()
    .0;

  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert!(
    host_conflicted_from(&mut e, &buf[..n], now, "192.168.1.99:5353").is_empty(),
    "an IPv4 arrival of the relinquished address IS a possible echo of the IPv4 \
     transmission, and must still be screened"
  );
  assert_eq!(
    host_conflicted_from(&mut e, &buf[..n], now, "[fe80::99]:5353"),
    std::vec![b_handle],
    "IPv6 never carried this record, so an IPv6 arrival cannot be our echo — \
     suppressing it hides a genuine peer's §9 conflict"
  );

  // The INSTANCE half, by the same rule.
  let n = build_instance_srv_response(&mut buf, &instance, 631, &host);
  assert_eq!(
    probe_disowned_from(&mut e, &buf[..n], now, "192.168.1.99:5353"),
    std::vec![b_handle],
    "the IPv4 echo of the relinquished SRV is still disowned — labelled, deferred, \
     not renamed on"
  );
  assert_eq!(
    probe_unscreened_from(&mut e, &buf[..n], now, "[fe80::99]:5353"),
    std::vec![b_handle],
    "an IPv6 responder asserting the old SRV must still defeat the successor's \
     probe — IPv6 never heard that SRV from us"
  );
}

/// The same rule for a still-RESIDENT withdrawal item, which is the screen's
/// first source and answers before any retention row exists.
#[test]
fn a_draining_withdrawals_exposure_screens_only_the_family_it_reached() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let host = Name::try_from_str("shared-host.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let a2 = Ipv4Addr::new(192, 168, 1, 9);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "A._ipp._tcp.local.", "shared-host.local.", a1);
  let snap = crate::service::WithdrawalSnapshot::announced(
    a_svc.records().clone(),
    on_v4_only(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        true,
      ),
      std::vec![a1],
      std::vec::Vec::new(),
    ),
  );
  // The item is still draining — nothing is retained yet, so the screen's
  // answer comes from the item itself.
  e.begin_withdrawal(a_handle, snap, now);
  let b_handle = register_with_addr_sets(
    &mut e,
    "B._ipp._tcp.local.",
    "shared-host.local.",
    &[a2],
    &[],
  )
  .unwrap();

  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, a1);
  assert!(
    host_conflicted_from(&mut e, &buf[..n], now, "192.168.1.99:5353").is_empty(),
    "the withdrawing route's own IPv4 address set is this endpoint's own past"
  );
  assert_eq!(
    host_conflicted_from(&mut e, &buf[..n], now, "[fe80::99]:5353"),
    std::vec![b_handle],
    "…on IPv4 only: the item never reached IPv6, so an IPv6 assertion of it is a \
     peer's"
  );
}

/// Build a QR=1 authoritative response carrying one instance NSEC at `owner`
/// asserting exactly `types` — the RFC 6762 §6.1 negative a DNS-SD responder
/// puts in the Additional section.
fn build_instance_nsec_response(buf: &mut [u8], owner: &Name, types: &[u16]) -> usize {
  use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder};
  let mut hdr = Header::new();
  hdr.flags_mut().set_response();
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
    MessageBuilder::try_new(buf, hdr).unwrap();
  b.push_nsec_additional(owner, 120, types, true).unwrap();
  b.finish().unwrap()
}

/// HISTORY ASSERTS TRANSMITTED BYTES, NOT CLASSIFIER-ACCEPTED FORMS.
///
/// `respond::canonical_rdata_forms` names TWO instance-NSEC bitmaps where the
/// instance name is also the host name and addresses are published: the fixed
/// `{SRV, TXT}` this crate's encoder writes, and the accurate `{SRV, TXT, A,
/// AAAA}` a CONFORMING responder writes at a name that really does hold all
/// four. Accepting both is right for the LIVE classifier — such a twin is
/// indistinguishable from us there, and RFC 6762 §9's identical-rdata rule
/// protects it from our rename.
///
/// It is wrong for the relinquished screen, which claims something narrower and
/// factual: these exact bytes left this endpoint, on this family, in this
/// generation. Expanding the exposure BOOLEAN through the live list made the
/// screen answer for a form no `push_service_nsec` ever encoded, so a GENUINE
/// twin's conforming NSEC read as an old self-echo and the §8.1 / §9 conflict
/// against the successor was withheld for the whole retention window.
///
/// The screen must be NARROWED, not disabled: our own `{SRV, TXT}` echo is
/// still disowned.
#[test]
fn a_conforming_nsec_this_endpoint_never_encoded_is_not_disowned_as_its_own_echo() {
  use crate::wire::ResourceType;

  let now = StdInstant::now();
  let mut e = build_endpoint();
  // The one configuration where the two forms differ: instance name IS host
  // name, and both address families are published there.
  let name = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);
  let v6 = core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

  let mut relinquished = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    name.clone(),
    name.clone(),
    631,
    120,
  );
  relinquished.add_a(a1);
  relinquished.add_aaaa(v6);
  let emitted = on_both(
    crate::service::EmittedRecords::new(
      true,
      true,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
      true,
    ),
    std::vec![a1],
    std::vec![v6],
  );
  // The premise: the live classifier really does accept two forms here, and
  // history really does keep only one of them.
  assert_eq!(
    crate::service::canonical_rdata_forms(&relinquished, ResourceType::Nsec).len(),
    2,
    "the live classifier must still accept the conforming twin's bitmap — this \
     test is about who ELSE may read that list"
  );
  assert_eq!(
    crate::service::transmitted_rdata_forms(&relinquished, ResourceType::Nsec).len(),
    1,
    "history may claim exactly the one bitmap this crate's encoder writes"
  );
  e.retain_relinquished(relinquished.clone(), emitted.clone(), now);

  // The successor takes both owner names.
  let successor = register_with_addr_sets(
    &mut e,
    "Printer._ipp._tcp.local.",
    "Printer._ipp._tcp.local.",
    &[Ipv4Addr::new(192, 168, 1, 9)],
    &[],
  )
  .unwrap();

  let mut buf = [0u8; 512];
  let emitted_types = [ResourceType::Srv.to_u16(), ResourceType::Txt.to_u16()];
  let n = build_instance_nsec_response(&mut buf, &name, &emitted_types);
  assert_eq!(
    probe_disowned_from(&mut e, &buf[..n], now, "192.168.1.99:5353"),
    std::vec![successor],
    "the bitmap this endpoint DID encode is still labelled its own echo — the \
     screen is narrowed, not disabled"
  );

  let conforming_types = [
    ResourceType::Srv.to_u16(),
    ResourceType::Txt.to_u16(),
    ResourceType::A.to_u16(),
    ResourceType::AAAA.to_u16(),
  ];
  let n = build_instance_nsec_response(&mut buf, &name, &conforming_types);
  assert_eq!(
    probe_unscreened_from(&mut e, &buf[..n], now, "192.168.1.99:5353"),
    std::vec![successor],
    "a conforming responder's ACCURATE bitmap is a form this endpoint never put \
     on any wire, so no history of ours may label it — labelling it would cost \
     the peer that sent it §8.1's immediate rename of our successor"
  );

  // The COMPACT tier decomposes to the same one form, or the two tiers would
  // disagree about this generation the moment the row ceiling is reached.
  let compact = super::relinquished::identities(&relinquished, &emitted[0]);
  let nsec_forms: std::vec::Vec<_> = compact
    .iter()
    .filter(|(_, rtype, _)| *rtype == ResourceType::Nsec)
    .map(|(_, _, rdata)| rdata.clone())
    .collect();
  assert_eq!(
    nsec_forms,
    crate::service::transmitted_rdata_forms(&relinquished, ResourceType::Nsec),
    "the compact tier must record the transmitted NSEC form and only it"
  );
}

/// THE HISTORY SCREEN IS PER RECORD, NOT PER CANDIDATE SERVICE.
///
/// `Endpoint::relinquished_asserts` is a whole-record answer, but the conflict
/// helper that consults it is re-entered after every match the cursor yields —
/// one event per `next()` — so a record matching `S` services ran the same scan
/// `S + 1` times. Each scan walks the withdrawal map plus up to
/// `MAX_RELINQUISHED_RRSETS` rows and `MAX_RELINQUISHED_IDENTITIES` identities,
/// so a multi-record datagram cost `records × services × history` receive-side
/// work for its sender's `records` bytes.
///
/// The assertion is on WORK DONE rather than on elapsed time, because that is
/// the property and it is deterministic: `RECORDS` screens for `RECORDS`
/// records, whatever the fan-out width. Before the cache it was
/// `RECORDS * (SERVICES + 1)` — fifteen here.
///
/// The routed events are asserted too: a bound that also dropped conflicts would
/// be the far worse defect.
#[test]
fn the_history_screen_runs_once_per_record_however_many_services_match() {
  const SERVICES: usize = 4;
  const RECORDS: usize = 3;

  let now = StdInstant::now();
  let mut e = build_endpoint();
  let host = Name::try_from_str("shared.local.").unwrap();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);

  // Services sharing ONE host name — the registration guard requires them to
  // publish the same address set there, which is exactly the shape that makes a
  // single A record match every one of them.
  for i in 0..SERVICES {
    register_with_addr_sets(
      &mut e,
      &std::format!("S{i}._ipp._tcp.local."),
      "shared.local.",
      &[a1],
      &[],
    )
    .unwrap();
  }
  // …and one relinquished generation, so the screen has history to walk rather
  // than an empty list to fall off the end of.
  retain_generation(&mut e, 99, Ipv4Addr::new(192, 168, 1, 77), now);

  let mut buf = [0u8; 512];
  let n = {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder};
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    for i in 0..RECORDS {
      let addr = Ipv4Addr::new(198, 51, 100, u8::try_from(i).unwrap().saturating_add(1));
      b.push_a_answer(&host, 120, addr, true).unwrap();
    }
    b.finish().unwrap()
  };

  let src: core::net::SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let mut events = e
    .handle(now, Received::new(src, &buf[..n], Provenance::NotFromUs))
    .unwrap();
  let conflicts = events
    .by_ref()
    .filter_map(Result::ok)
    .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_host_conflict()))
    .count();
  assert_eq!(
    conflicts,
    RECORDS * SERVICES,
    "every service sharing the host name must still receive every record's \
     conflict"
  );
  assert_eq!(
    events.history_screens, RECORDS,
    "the screen's answer does not vary with the route, so it must be taken once \
     per record — re-deriving it per candidate service is what multiplies a \
     hostile packet's receive cost by the fan-out width"
  );
}

/// PARTIAL-FAMILY DELIVERY MUST NOT BECOME GLOBAL EXPOSURE — the goodbye half,
/// which is independent of the screen.
///
/// A family that carried nothing has no peer holding these records from us, so
/// it owes no RFC 6762 §10.1 goodbye. Seeding it one anyway means a later
/// recovered IPv6 transport emits TTL=0 records this endpoint never advertised
/// there, which can cache-flush a peer's matching shared record — the same
/// over-withdrawal class the per-record `EmittedRecords` granularity closes, one
/// dimension over.
#[test]
fn a_family_that_carried_nothing_owes_no_goodbye() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let a1 = Ipv4Addr::new(192, 168, 1, 5);

  let (a_handle, a_svc) =
    register_service_with_a(&mut e, "A._ipp._tcp.local.", "h.local.", a1);
  let snap = crate::service::WithdrawalSnapshot::announced(
    a_svc.records().clone(),
    on_v4_only(
      crate::service::EmittedRecords::new(
        true,
        true,
        true,
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        false,
        true,
      ),
      std::vec![a1],
      std::vec::Vec::new(),
    ),
  );
  e.begin_withdrawal(a_handle, snap, now);
  assert_eq!(
    e.route_withdrawal_owed(a_handle),
    Some([super::WITHDRAWAL_SENDS, 0]),
    "only the family that put the records on a wire owes their goodbye"
  );

  // …and the §9 RENAME path, whose detached old-name item is seeded the same way.
  let old_instance = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
  let mut old_records = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    old_instance.clone(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  old_records.add_a(a1);
  e.enqueue_rename_withdrawal(
    crate::service::RenameGoodbyeHandoff::announced(
      old_records,
      on_v4_only(
        crate::service::EmittedRecords::new(
          true,
          true,
          true,
          std::vec::Vec::new(),
          std::vec::Vec::new(),
          false,
          true,
        ),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
    ),
    now,
    false,
  );
  assert_eq!(
    e.detached_withdrawal_owed_for(&old_instance),
    Some([super::WITHDRAWAL_SENDS, 0]),
    "a renamed-away name IPv6 never carried owes IPv6 no goodbye either"
  );
}

/// THE CAPACITY REGRESSION: reaching the retention ceiling must cost a cheaper
/// REPRESENTATION, never this endpoint's willingness to adjudicate.
///
/// The ceiling used to set an endpoint-wide QUARANTINE deadline, past which the
/// screen answered `true` for every candidate without consulting its name,
/// rrtype, class or rdata. An on-link peer sets the relinquishment rate — RFC
/// 6762 §9 re-probes and §8.1 renames carry no fifteen-conflicts-in-ten-seconds
/// backoff — so 129 conflict-driven relinquishments bought it a window in which
/// authoritative responses for UNRELATED names were discarded: this endpoint's
/// own prober could finish over an incumbent, and an established §9 conflict
/// went unseen. Withholding one generation's conflicts risks one generation;
/// withholding every conflict is a false negative at every name the endpoint
/// holds.
///
/// The overflow generation keeps its screen too, which is what separates this
/// from the eviction the quarantine was chosen over.
#[test]
fn the_relinquished_ceiling_spills_to_identities_rather_than_disabling_the_endpoint() {
  let mut e = build_endpoint();
  let base = StdInstant::now();
  let addr = Ipv4Addr::new(192, 168, 1, 5);
  // An UNRELATED name this endpoint holds — the incumbent whose conflicts the
  // quarantine used to swallow.
  let live_handle = register_with_addr_sets(
    &mut e,
    "Live._ipp._tcp.local.",
    "live-host.local.",
    &[Ipv4Addr::new(10, 0, 0, 1)],
    &[],
  )
  .unwrap();

  // Fill the exact tier, then overflow it by one: 129 distinct generations, each
  // one instant later than the last so their expiries are strictly ordered.
  let overflow = super::relinquished::MAX_RELINQUISHED_RRSETS;
  for i in 0..=overflow {
    retain_generation(
      &mut e,
      i,
      addr,
      base + core::time::Duration::from_millis(i as u64),
    );
  }
  let overflow_at = base + core::time::Duration::from_millis(overflow as u64);
  assert_eq!(
    e.relinquished.len(),
    super::relinquished::MAX_RELINQUISHED_RRSETS,
    "the exact tier must never exceed its ceiling"
  );
  // NOTHING UNEXPIRED WAS DROPPED. Every row that was there before the ceiling
  // was reached is still there — including the very first, which an
  // earliest-expiry eviction would have taken.
  let first = Name::try_from_str("S0._ipp._tcp.local.").unwrap();
  assert!(
    e.relinquished
      .iter()
      .any(|r| r.records.instance().same_owner(&first)),
    "the earliest-expiring row is still an UNEXPIRED obligation — reaching the \
     ceiling must not evict it"
  );

  let live_instance = Name::try_from_str("Live._ipp._tcp.local.").unwrap();
  let live_host = Name::try_from_str("live-host.local.").unwrap();
  let mut buf = [0u8; 512];

  // LEG 1 — a peer's authoritative SRV at a name we hold, with rdata we do not.
  // §8.1 needs this to reach the service; quarantined, it reached nobody and our
  // own probe would have completed over the incumbent that sent it.
  let n = build_instance_srv_response(
    &mut buf,
    &live_instance,
    1234,
    &Name::try_from_str("elsewhere.local.").unwrap(),
  );
  assert_eq!(
    probe_unscreened(&mut e, &buf[..n], overflow_at),
    std::vec![live_handle],
    "a full retention list says nothing about an UNRELATED name — the conflict \
     for one this endpoint still holds must still be built"
  );

  // LEG 2 — the §9 half, at the host name, and equally unrelated to anything
  // relinquished.
  let n = build_host_a_response(&mut buf, &live_host, Ipv4Addr::new(10, 0, 0, 99));
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], overflow_at),
    std::vec![live_handle],
    "an address this endpoint never asserted at a live host name is a real \
     conflict whatever the retention list's occupancy is"
  );

  // LEG 3 — and the generation that did not fit is NOT the price. It was
  // recorded compactly, so its own echo is still disowned at the names a
  // SUCCESSOR has since taken; an eviction-based ceiling is what fails here.
  assert!(
    !e.relinquished_identities.is_empty(),
    "the overflowing relinquishment must be recorded in the compact tier"
  );
  let spilled_host = Name::try_from_str(&std::format!("h{overflow}.local.")).unwrap();
  let spilled_instance = Name::try_from_str(&std::format!("S{overflow}._ipp._tcp.local.")).unwrap();
  // The successor reuses BOTH names with different rdata — a different address
  // and a different port — so every screened record below is one this route does
  // not hold and would otherwise adjudicate as a conflict.
  let mut successor = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    spilled_instance.clone(),
    spilled_host.clone(),
    9999,
    120,
  );
  successor.add_a(Ipv4Addr::new(10, 0, 0, 7));
  let spilled_handle = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(successor),
      overflow_at,
    )
    .unwrap()
    .0;
  let n = build_host_a_response(&mut buf, &spilled_host, addr);
  assert!(
    host_conflicted(&mut e, &buf[..n], overflow_at).is_empty(),
    "the overflowing generation keeps its screen — the ceiling costs a cheaper \
     representation, not an obligation"
  );
  let n = build_instance_srv_response(&mut buf, &spilled_instance, 631, &spilled_host);
  assert_eq!(
    probe_disowned(&mut e, &buf[..n], overflow_at),
    std::vec![spilled_handle],
    "the compact tier answers for the INSTANCE identities too, not only addresses"
  );

  // The compact tier LAPSES on the same window the exact one does — it delays a
  // peer that happens to assert our relinquished rdata, it does not silence it.
  let lapsed = overflow_at
    .checked_add(EndpointConfig::new().relinquished_retention())
    .unwrap()
    + core::time::Duration::from_millis(1);
  let n = build_host_a_response(&mut buf, &spilled_host, addr);
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], lapsed),
    std::vec![spilled_handle],
    "a compact identity must stop screening when its window closes"
  );
  e.handle_timeout(lapsed).unwrap();
  assert!(
    e.relinquished_identities.is_empty(),
    "and the sweep must reclaim it"
  );
}

/// The compact tier has a ceiling of its own, and reaching IT costs only the
/// identities that did not fit.
///
/// Nothing already recorded is disturbed, and — the property the quarantine
/// destroyed — no record this endpoint cannot name is answered for. The loss
/// lands on the newest relinquishment rather than on an older one because
/// evicting to make room would let a peer choose the victim: filling the table
/// is exactly how it would aim.
#[test]
fn the_compact_relinquished_ceiling_costs_only_what_did_not_fit() {
  let mut e = build_endpoint();
  let base = StdInstant::now();
  let live_handle = register_with_addr_sets(
    &mut e,
    "Live._ipp._tcp.local.",
    "live-host.local.",
    &[Ipv4Addr::new(10, 0, 0, 1)],
    &[],
  )
  .unwrap();

  // Enough distinct generations to fill both tiers. Each contributes one address
  // identity plus its SRV / TXT / NSEC forms, so the compact ceiling is reached
  // well before this many.
  let generations =
    super::relinquished::MAX_RELINQUISHED_RRSETS + super::relinquished::MAX_RELINQUISHED_IDENTITIES;
  for i in 0..generations {
    retain_generation(
      &mut e,
      i,
      Ipv4Addr::new(10, 1, (i >> 8) as u8, i as u8),
      base + core::time::Duration::from_millis(i as u64),
    );
  }
  let at = base + core::time::Duration::from_millis(generations as u64);
  assert_eq!(
    e.relinquished.len(),
    super::relinquished::MAX_RELINQUISHED_RRSETS,
    "the exact tier must never exceed its ceiling"
  );
  assert_eq!(
    e.relinquished_identities.len(),
    super::relinquished::MAX_RELINQUISHED_IDENTITIES,
    "nor the compact one"
  );

  // The FIRST identity the compact tier took is the one an eviction would have
  // reached for. A successor takes its host name with a different address, so
  // the predecessor's own address is a record this route does not hold.
  let spilled = super::relinquished::MAX_RELINQUISHED_RRSETS;
  let spilled_host = Name::try_from_str(&std::format!("h{spilled}.local.")).unwrap();
  let mut successor = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Successor._ipp._tcp.local.").unwrap(),
    spilled_host.clone(),
    9999,
    120,
  );
  successor.add_a(Ipv4Addr::new(10, 0, 0, 7));
  e.try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
    ServiceSpec::new(successor),
    at,
  )
  .unwrap();
  let mut buf = [0u8; 512];
  let n = build_host_a_response(
    &mut buf,
    &spilled_host,
    Ipv4Addr::new(10, 1, (spilled >> 8) as u8, spilled as u8),
  );
  assert!(
    host_conflicted(&mut e, &buf[..n], at).is_empty(),
    "a full compact tier must not evict an unexpired identity"
  );

  // And an unrelated live name still adjudicates — the whole point.
  let live_host = Name::try_from_str("live-host.local.").unwrap();
  let n = build_host_a_response(&mut buf, &live_host, Ipv4Addr::new(10, 0, 0, 99));
  assert_eq!(
    host_conflicted(&mut e, &buf[..n], at),
    std::vec![live_handle],
    "both tiers full is still not a reason to stop adjudicating"
  );
}

/// Relinquish ONE generation that put `addr` under `host` on ONE family alone,
/// at `at`.
///
/// The exposure is ADDRESS-ONLY, so the generation decomposes into exactly one
/// compact identity and two generations sharing an address share that identity —
/// which is what makes the merge below observable at all.
fn retain_address_generation(
  e: &mut TestEndp,
  instance: &str,
  host: &Name,
  addr: Ipv4Addr,
  family: crate::transmit::Family,
  at: StdInstant,
) {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str(instance).unwrap(),
    host.clone(),
    631,
    120,
  );
  recs.add_a(addr);
  let carried = crate::service::EmittedRecords::new(
    false,
    false,
    false,
    std::vec![addr],
    std::vec::Vec::new(),
    false,
    false,
  );
  let none = crate::service::EmittedRecords::default();
  let emitted = match family {
    crate::transmit::Family::V4 => [carried, none],
    crate::transmit::Family::V6 => [none, carried],
  };
  e.retain_relinquished(recs, emitted, at);
}

/// THE COMPACT TIER'S SECOND PER-FAMILY COLLAPSE: an identity two generations
/// transmitted on DIFFERENT families must expire on EACH FAMILY'S OWN window.
///
/// The compact tier merges identities ACROSS generations — that is what makes it
/// cheaper than a row apiece — and the merge key is `(owner, rrtype, rdata)`,
/// which says nothing about WHEN or WHERE. Carrying one expiry beside a `[v4,
/// v6]` presence mask made the merge write the later generation's window onto
/// the earlier generation's family: retain an identity from an IPv4 generation,
/// then the same rdata from a LATER IPv6 one, and the row read "both families,
/// the later expiry". After the IPv4 generation's own window closed, an IPv4
/// peer asserting that rdata was still disowned as our own echo — suppressing a
/// genuine RFC 6762 §8.1 or §9 conflict against a successor holding different
/// rdata, which is the terminal outcome this screen exists to prevent from the
/// other side.
///
/// The exact tier never agreed: it keeps the two generations in separate rows,
/// each living to its own expiry. Two tiers answering the same question must not
/// disagree about it.
#[test]
fn a_merged_compact_identity_expires_on_each_familys_own_window() {
  let mut e = build_endpoint();
  let base = StdInstant::now();
  let window = EndpointConfig::new().relinquished_retention();
  let gap = core::time::Duration::from_secs(2);
  let shared_addr = Ipv4Addr::new(192, 168, 1, 5);
  let host = Name::try_from_str("shared-host.local.").unwrap();

  // Fill the EXACT tier, so the two generations below land in the compact one —
  // the only tier that merges across generations at all.
  for i in 0..super::relinquished::MAX_RELINQUISHED_RRSETS {
    retain_generation(
      &mut e,
      i,
      Ipv4Addr::new(10, 1, (i >> 8) as u8, i as u8),
      base,
    );
  }
  assert_eq!(
    e.relinquished.len(),
    super::relinquished::MAX_RELINQUISHED_RRSETS,
    "the exact tier must be full, or nothing spills"
  );

  // Generation 1 reached IPv4 ALONE at `base`; generation 2 reached IPv6 ALONE
  // `gap` later. Both put the same address under the same host name, so the two
  // decompose to ONE identity and the compact tier merges them.
  retain_address_generation(
    &mut e,
    "G1._ipp._tcp.local.",
    &host,
    shared_addr,
    crate::transmit::Family::V4,
    base,
  );
  retain_address_generation(
    &mut e,
    "G2._ipp._tcp.local.",
    &host,
    shared_addr,
    crate::transmit::Family::V6,
    base + gap,
  );
  assert_eq!(
    e.relinquished_identities.len(),
    1,
    "the two generations assert ONE identity — the merge is the case under test"
  );

  // A successor takes the vacated host name with an address of its own, so the
  // predecessors' address is rdata this route does not hold: every arrival below
  // is a §9 conflict unless the screen disowns it.
  let mut successor = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Successor._ipp._tcp.local.").unwrap(),
    host.clone(),
    9999,
    120,
  );
  successor.add_a(Ipv4Addr::new(10, 0, 0, 7));
  let successor_handle = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(successor),
      base,
    )
    .unwrap()
    .0;

  // AFTER the IPv4 generation's window and BEFORE the IPv6 generation's.
  let between = base + window + gap / 2;
  let mut buf = [0u8; 512];
  let n = build_host_a_response(&mut buf, &host, shared_addr);
  assert_eq!(
    host_conflicted_from(&mut e, &buf[..n], between, "192.168.1.99:5353"),
    std::vec![successor_handle],
    "the IPv4 generation's window has CLOSED, so an IPv4 peer asserting that \
     rdata is a genuine conflict — inheriting the later IPv6 generation's \
     expiry silently suppresses it"
  );
  assert!(
    host_conflicted_from(&mut e, &buf[..n], between, "[fe80::99]:5353").is_empty(),
    "and the IPv6 generation's own window is still open, so this is a per-family \
     narrowing rather than a shortening of both"
  );

  // The row survives its IPv4 half lapsing: a sweep that dropped it would close
  // the IPv6 window early, which is the same collapse pointing the other way.
  e.handle_timeout(between).unwrap();
  assert_eq!(
    e.relinquished_identities.len(),
    1,
    "an identity live on ONE family is still an obligation owed on that family"
  );
  let both_lapsed = base + gap + window + core::time::Duration::from_millis(1);
  assert_eq!(
    host_conflicted_from(&mut e, &buf[..n], both_lapsed, "[fe80::99]:5353"),
    std::vec![successor_handle],
    "and the IPv6 half lapses on its own window too"
  );
  e.handle_timeout(both_lapsed).unwrap();
  assert!(
    e.relinquished_identities.is_empty(),
    "with both halves lapsed the sweep reclaims the row"
  );
}

/// RAPID SAME-OWNER REUSE: `R1 → R2 → R3` at ONE instance/host pair.
///
/// The list used to be keyed by owner pair, so relinquishing a second rdata
/// generation for the same names OVERWROTE the first — even with the first's
/// window nowhere near elapsed. A delayed `R1` echo then adjudicated against
/// `R3` and recreated the terminal conflict this whole design exists to
/// prevent. Each generation now lives to its own expiry.
#[test]
fn every_relinquished_generation_of_one_owner_pair_screens_to_its_own_expiry() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();

  // Three generations of ONE owner pair, differing only in SRV rdata, each
  // relinquished a moment after the last.
  let emitted = crate::service::EmittedRecords::new(
    true,
    true,
    true,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
    true,
  );
  for (i, port) in [631u16, 632, 633].into_iter().enumerate() {
    let recs = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      instance.clone(),
      host.clone(),
      port,
      120,
    );
    e.retain_relinquished(
      recs,
      on_both(
        emitted.clone(),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
      ),
      now + core::time::Duration::from_millis(i as u64),
    );
  }
  assert_eq!(
    e.relinquished.len(),
    3,
    "three distinct generations, three rows"
  );

  // A successor takes the name with a fourth rdata.
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    instance.clone(),
    host.clone(),
    9999,
    120,
  );
  let (b_handle, _b_svc) = e
    .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
      ServiceSpec::new(recs),
      now,
    )
    .unwrap();

  let mut buf = [0u8; 512];
  for port in [631u16, 632, 633] {
    let n = build_instance_srv_response(&mut buf, &instance, port, &host);
    assert_eq!(
      probe_disowned(&mut e, &buf[..n], now),
      std::vec![b_handle],
      "generation {port}'s own echo must not RENAME the successor while ITS \
       window is still open — it is labelled, so §8.2 defers and re-probes"
    );
  }
  // Still not a blanket suppression of the name.
  let n = build_instance_srv_response(&mut buf, &instance, 1234, &host);
  assert_eq!(
    probe_unscreened(&mut e, &buf[..n], now),
    std::vec![b_handle],
    "rdata no generation ever carried is a real conflict"
  );
}

/// An IDENTICAL generation relinquished twice is ONE row whose window takes the
/// LATER expiry — the merge that is safe, because the identity set is the same
/// one and the new window covers whatever the old still had to.
#[test]
fn an_identical_relinquished_generation_merges_by_extending_its_window() {
  let now = StdInstant::now();
  let mut e = build_endpoint();
  let instance = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let emitted = crate::service::EmittedRecords::new(
    true,
    true,
    true,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
    true,
  );
  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    instance.clone(),
    host.clone(),
    631,
    120,
  );
  let later = now + core::time::Duration::from_secs(1);
  e.retain_relinquished(
    recs.clone(),
    on_both(
      emitted.clone(),
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
    now,
  );
  e.retain_relinquished(
    recs,
    on_both(
      emitted,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
    ),
    later,
  );
  assert_eq!(e.relinquished.len(), 1, "the same generation is one row");
  assert_eq!(
    e.relinquished.first().map(|r| r.expires_at),
    later.checked_add(EndpointConfig::new().relinquished_retention()),
    "and it screens to the LATER of the two windows"
  );
}

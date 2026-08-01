use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
  time::{Duration, Instant},
};

use bytes::Bytes;
use mdns_proto::{
  CollectedAnswer, Name, QueryHandle,
  wire::{Header, MessageBuilder, ResourceClass, ResourceType},
};

use super::{LookupCtx, MAX_ADDRS_PER_HOST, PartialEntry, QueryParam, Step, fold, parse_name};
use crate::{Event, driver::test_support, endpoint::Mdns};

/// Encode a label sequence as a decompressed wire-form name.
fn wire_name(labels: &[&[u8]]) -> Vec<u8> {
  let mut out = Vec::new();
  for l in labels {
    out.push(u8::try_from(l.len()).expect("label fits in a byte"));
    out.extend_from_slice(l);
  }
  out.push(0);
  out
}

fn srv_rdata(port: u16, host: &[&[u8]]) -> Vec<u8> {
  let mut out = Vec::new();
  out.extend_from_slice(&0u16.to_be_bytes()); // priority
  out.extend_from_slice(&0u16.to_be_bytes()); // weight
  out.extend_from_slice(&port.to_be_bytes());
  out.extend_from_slice(&wire_name(host));
  out
}

fn answer(rtype: ResourceType, rdata: Vec<u8>) -> CollectedAnswer {
  CollectedAnswer::from_parts(rtype, ResourceClass::In, rdata, 0)
}

fn name(s: &str) -> Name {
  Name::try_from_str(s).expect("a valid name")
}

/// Feed a QR=1 mDNS response straight into the proto endpoint — the same inbound
/// path `drain_recv` uses, minus the socket, so a full browse chain can be driven
/// without a peer on the link.
///
/// The source port MUST be 5353: the proto layer suppresses every side effect of
/// a response from an ephemeral port (RFC 6762 §11), so the answers would never
/// reach the queries.
fn feed_response(mdns: &mut Mdns, records: &[Record<'_>]) {
  let mut buf = [0u8; 1024];
  let mut header = Header::new();
  header.flags_mut().set_response();
  let len = {
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, header).expect("a message builder");
    for record in records {
      match record {
        Record::Ptr { owner, target } => b.push_ptr_answer(owner, 120, target),
        Record::Srv {
          owner,
          port,
          target,
        } => b.push_srv_answer(owner, 120, 0, 0, *port, target, true),
        Record::Txt { owner, segments } => b.push_txt_answer(owner, 120, segments.iter(), true),
        Record::A { owner, addr } => b.push_a_answer(owner, 120, *addr, true),
      }
      .expect("the record encodes");
    }
    b.finish().expect("the message finishes")
  };
  let events = mdns
    .endpoint
    .handle(
      Instant::now(),
      SocketAddr::from(([192, 168, 1, 200], hick_udp::constants::MDNS_PORT)),
      IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
      0,
      &buf[..len],
      false,
    )
    .expect("the endpoint accepts the response");
  // Query answers are dispatched inside `handle`; the route events are for
  // services, of which this test has none.
  for _ in events {}
}

/// One answer record for [`feed_response`].
enum Record<'a> {
  Ptr {
    owner: &'a Name,
    target: &'a Name,
  },
  Srv {
    owner: &'a Name,
    port: u16,
    target: &'a Name,
  },
  Txt {
    owner: &'a Name,
    segments: Vec<&'a [u8]>,
  },
  A {
    owner: &'a Name,
    addr: Ipv4Addr,
  },
}

/// Drain every event the tick produced.
fn drain(mdns: &mut Mdns) -> Vec<Event> {
  std::iter::from_fn(|| mdns.next_event()).collect()
}

// ---------------------------------------------------------------------------
// PartialEntry: the completeness rule.
// ---------------------------------------------------------------------------

#[test]
fn partial_is_incomplete_until_srv_txt_and_an_address() {
  let mut p = PartialEntry::default();
  assert!(p.take_complete().is_none());
  p.set_srv(Name::try_from_str("host.local.").unwrap(), 8080);
  assert!(p.take_complete().is_none(), "needs TXT and an address");
  p.set_txt(vec![bytes::Bytes::from_static(b"k=v")]);
  assert!(p.take_complete().is_none(), "needs an address");
  p.add_v4("192.168.1.7".parse().unwrap());
  assert!(p.take_complete().is_some());
}

#[test]
fn a_completed_entry_is_emitted_once() {
  let mut p = PartialEntry::default();
  p.set_srv(Name::try_from_str("host.local.").unwrap(), 8080);
  p.set_txt(vec![bytes::Bytes::from_static(b"k=v")]);
  p.add_v4("192.168.1.7".parse().unwrap());
  assert!(p.take_complete().is_some());
  assert!(p.take_complete().is_none(), "no duplicate emission");
}

#[test]
fn both_families_are_collected() {
  let mut p = PartialEntry::default();
  p.set_srv(Name::try_from_str("host.local.").unwrap(), 8080);
  p.set_txt(vec![]);
  p.add_v4("192.168.1.7".parse().unwrap());
  p.add_v6("fe80::1".parse().unwrap());
  let e = p.take_complete().expect("complete");
  assert_eq!(e.ipv4_addresses().len(), 1);
  assert_eq!(e.ipv6_addresses().len(), 1);
  assert_eq!(e.addresses().count(), 2);
  assert_eq!(e.port(), 8080);
}

#[test]
fn duplicate_addresses_are_deduplicated() {
  let mut p = PartialEntry::default();
  p.set_srv(Name::try_from_str("host.local.").unwrap(), 8080);
  p.set_txt(vec![]);
  p.add_v4("192.168.1.7".parse().unwrap());
  p.add_v4("192.168.1.7".parse().unwrap());
  assert_eq!(
    p.take_complete().expect("complete").ipv4_addresses().len(),
    1
  );
}

#[test]
fn query_param_defaults_and_builders() {
  let p = QueryParam::new(Name::try_from_str("_http._tcp.local.").unwrap())
    .with_timeout(Duration::from_secs(3))
    .with_max_entries(7);
  assert_eq!(p.timeout(), Duration::from_secs(3));
  assert_eq!(p.max_entries(), 7);
}

#[test]
fn lookup_deadline_is_reported_for_the_timeout() {
  let p = QueryParam::new(Name::try_from_str("_http._tcp.local.").unwrap())
    .with_timeout(Duration::from_secs(3));
  let started = Instant::now();
  let ctx = super::LookupCtx::new(p, started);
  let deadline = ctx.deadline().expect("a timeout implies a deadline");
  assert!(deadline > started);
}

#[test]
fn a_bare_host_partial_uses_the_srv_target_as_its_identity() {
  // `resolve_host` has no PTR/SRV, so its partial carries no DNS-SD instance
  // name; the host it was asked about is the entry's identity.
  let mut p = PartialEntry::default();
  p.set_srv(name("printer.local."), 0);
  p.set_txt(vec![]);
  p.add_v4(Ipv4Addr::new(10, 0, 0, 3));
  let e = p.take_complete().expect("complete");
  assert_eq!(e.instance_name().as_str(), "printer.local.");
  assert_eq!(e.host().as_str(), "printer.local.");
  assert_eq!(e.port(), 0, "a bare host resolve reports no port");
  assert!(e.txt().is_empty(), "a bare host resolve reports no TXT");
}

#[test]
fn srv_port_zero_still_completes() {
  // `0` is a valid SRV port, so it cannot double as the "no SRV yet" sentinel.
  let mut p = PartialEntry::default();
  p.set_srv(name("h.local."), 0);
  p.set_txt(vec![]);
  p.add_v4(Ipv4Addr::LOCALHOST);
  assert!(p.take_complete().is_some());
}

#[test]
fn addresses_are_capped_per_family() {
  let mut p = PartialEntry::default();
  p.set_srv(name("h.local."), 1);
  p.set_txt(vec![]);
  for i in 0..(MAX_ADDRS_PER_HOST + 8) {
    p.add_v4(Ipv4Addr::new(10, 0, 0, u8::try_from(i).expect("fits")));
  }
  assert_eq!(
    p.take_complete().expect("complete").ipv4_addresses().len(),
    MAX_ADDRS_PER_HOST
  );
}

#[test]
fn srv_retarget_drops_the_old_hosts_addresses() {
  let mut p = PartialEntry::default();
  p.set_srv(name("old.local."), 1);
  p.add_v4(Ipv4Addr::new(10, 0, 0, 1));
  p.set_srv(name("new.local."), 1);
  p.set_txt(vec![]);
  assert!(
    p.take_complete().is_none(),
    "retargeting must invalidate the old host's addresses"
  );
  p.add_v4(Ipv4Addr::new(10, 0, 0, 2));
  let e = p
    .take_complete()
    .expect("complete on the new host's address");
  assert_eq!(e.host().as_str(), "new.local.");
  assert_eq!(e.ipv4_addresses(), [Ipv4Addr::new(10, 0, 0, 2)]);
}

// ---------------------------------------------------------------------------
// Name representability (RFC 6763 instance/host names through `Name`).
// ---------------------------------------------------------------------------

#[test]
fn unrepresentable_labels_are_skipped_not_corrupted() {
  // Plain ASCII labels round-trip (case-folded by `Name`).
  assert_eq!(
    parse_name(&wire_name(&[b"MyPrinter", b"_ipp", b"_tcp", b"local"]))
      .expect("representable")
      .as_str(),
    "myprinter._ipp._tcp.local."
  );
  // A label containing a literal '.' cannot be represented — skip it.
  assert!(parse_name(&wire_name(&[b"weird.name", b"_tcp", b"local"])).is_none());
  // A non-ASCII (UTF-8) label cannot round-trip through `Name` — skip it.
  assert!(parse_name(&wire_name(&[b"caf\xc3\xa9", b"local"])).is_none());
}

#[test]
fn a_ptr_answer_naming_an_unrepresentable_instance_starts_nothing() {
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")), Instant::now());
  ctx.feed(
    &Step::Ptr,
    &answer(
      ResourceType::Ptr,
      wire_name(&[b"weird.name", b"_x", b"_tcp", b"local"]),
    ),
  );
  assert!(ctx.partials.is_empty(), "the instance must be skipped");
  assert!(ctx.pending.is_empty(), "and no sub-query queued for it");
}

// ---------------------------------------------------------------------------
// LookupCtx: the browse -> resolve chain.
// ---------------------------------------------------------------------------

#[test]
fn a_ptr_answer_queues_srv_and_txt() {
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")), Instant::now());
  ctx.feed(
    &Step::Ptr,
    &answer(
      ResourceType::Ptr,
      wire_name(&[b"i", b"_x", b"_tcp", b"local"]),
    ),
  );
  assert_eq!(ctx.partials.len(), 1);
  assert_eq!(ctx.pending.len(), 2, "SRV + TXT");
  let qtypes: Vec<ResourceType> = ctx.pending.iter().map(|s| s.step.qtype()).collect();
  assert!(qtypes.contains(&ResourceType::Srv));
  assert!(qtypes.contains(&ResourceType::Txt));
}

#[test]
fn an_srv_answer_queues_a_and_aaaa_once_per_host() {
  let inst = name("i._x._tcp.local.");
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")), Instant::now());
  ctx.on_ptr(inst.clone());
  ctx.pending.clear();
  let key = fold(&inst);
  ctx.feed(
    &Step::Srv(key.clone()),
    &answer(ResourceType::Srv, srv_rdata(631, &[b"h", b"local"])),
  );
  let qtypes: Vec<ResourceType> = ctx.pending.iter().map(|s| s.step.qtype()).collect();
  assert!(qtypes.contains(&ResourceType::A));
  assert!(qtypes.contains(&ResourceType::AAAA));
  // A second SRV naming the same host must not re-query it.
  ctx.pending.clear();
  ctx.feed(
    &Step::Srv(key),
    &answer(ResourceType::Srv, srv_rdata(631, &[b"h", b"local"])),
  );
  assert!(ctx.pending.is_empty(), "the host is already being queried");
}

#[test]
fn a_ptr_flood_is_capped_at_max_entries() {
  let mut ctx = LookupCtx::new(
    QueryParam::new(name("_x._tcp.local.")).with_max_entries(2),
    Instant::now(),
  );
  ctx.on_ptr(name("a._x._tcp.local."));
  ctx.on_ptr(name("b._x._tcp.local."));
  ctx.on_ptr(name("c._x._tcp.local."));
  assert_eq!(ctx.partials.len(), 2, "the third instance is over the cap");
  // A duplicate of a tracked instance queues nothing new.
  ctx.pending.clear();
  ctx.on_ptr(name("a._x._tcp.local."));
  assert!(ctx.pending.is_empty());
}

#[test]
fn an_srv_target_flood_is_capped() {
  let mut ctx = LookupCtx::new(
    QueryParam::new(name("_x._tcp.local.")).with_max_entries(1),
    Instant::now(),
  );
  let inst = name("i._x._tcp.local.");
  ctx.on_ptr(inst.clone());
  let key = fold(&inst);
  ctx.on_srv(&key, name("h1.local."), 1);
  ctx.pending.clear();
  // A second, different SRV target would need a second host query; the cap
  // (equal to `max_entries`) refuses it.
  ctx.on_srv(&key, name("h2.local."), 1);
  assert!(ctx.pending.is_empty(), "the distinct-host cap must bite");
}

#[test]
fn a_shared_hosts_address_fans_out_to_every_instance_on_it() {
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")), Instant::now());
  let i1 = name("i1._x._tcp.local.");
  let i2 = name("i2._x._tcp.local.");
  let host = name("h.local.");
  ctx.on_ptr(i1.clone());
  ctx.on_ptr(i2.clone());
  ctx.on_srv(&fold(&i1), host.clone(), 8080);
  ctx.on_srv(&fold(&i2), host.clone(), 8081);
  ctx.on_txt(&fold(&i1), vec![Bytes::from_static(b"a=1")]);
  ctx.on_txt(&fold(&i2), vec![Bytes::from_static(b"b=2")]);
  ctx.on_addr(&fold(&host), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
  ctx.collect_ready();
  let mut ports: Vec<u16> = std::iter::from_fn(|| ctx.take_ready())
    .map(|e| e.port())
    .collect();
  ports.sort_unstable();
  assert_eq!(ports, [8080, 8081]);
}

#[test]
fn an_srv_arriving_after_its_hosts_address_still_resolves() {
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")), Instant::now());
  let i1 = name("i1._x._tcp.local.");
  let i2 = name("i2._x._tcp.local.");
  let host = name("h.local.");
  ctx.on_ptr(i1.clone());
  ctx.on_ptr(i2.clone());
  ctx.on_srv(&fold(&i1), host.clone(), 8080);
  ctx.on_txt(&fold(&i1), vec![]);
  ctx.on_addr(&fold(&host), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
  // i2's SRV lands only after the A answer has come and gone; the host cache
  // is what lets it complete anyway.
  ctx.on_srv(&fold(&i2), host, 8081);
  ctx.on_txt(&fold(&i2), vec![]);
  ctx.collect_ready();
  let mut found: Vec<(u16, Vec<Ipv4Addr>)> = std::iter::from_fn(|| ctx.take_ready())
    .map(|e| (e.port(), e.ipv4_addresses().to_vec()))
    .collect();
  found.sort_unstable();
  assert_eq!(
    found,
    [
      (8080, vec![Ipv4Addr::new(10, 0, 0, 1)]),
      (8081, vec![Ipv4Addr::new(10, 0, 0, 1)]),
    ]
  );
}

#[test]
fn an_ipv6_only_host_still_completes() {
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")), Instant::now());
  let inst = name("i._x._tcp.local.");
  let host = name("h.local.");
  ctx.on_ptr(inst.clone());
  ctx.on_srv(&fold(&inst), host.clone(), 5000);
  ctx.on_txt(&fold(&inst), vec![]);
  ctx.on_addr(
    &fold(&host),
    IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
  );
  ctx.collect_ready();
  let e = ctx
    .take_ready()
    .expect("one address of either family suffices");
  assert!(e.ipv4_addresses().is_empty());
  assert_eq!(e.ipv6_addresses().len(), 1);
}

#[test]
fn a_txt_only_answer_does_not_complete_an_instance() {
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")), Instant::now());
  let inst = name("i._x._tcp.local.");
  ctx.on_ptr(inst.clone());
  ctx.on_txt(&fold(&inst), vec![Bytes::from_static(b"k=v")]);
  ctx.collect_ready();
  assert!(ctx.take_ready().is_none());
}

// ---------------------------------------------------------------------------
// LookupCtx: termination.
// ---------------------------------------------------------------------------

#[test]
fn a_lookup_finishes_at_its_deadline() {
  let started = Instant::now();
  let ctx = LookupCtx::new(
    QueryParam::new(name("_x._tcp.local.")).with_timeout(Duration::from_secs(5)),
    started,
  );
  assert!(!ctx.is_finished(started), "not yet: no sub-query has ended");
  let deadline = ctx.deadline().expect("a deadline");
  assert!(ctx.is_finished(deadline), "due exactly at the deadline");
}

#[test]
fn a_lookup_finishes_once_max_entries_are_emitted() {
  let started = Instant::now();
  let mut ctx = LookupCtx::new(
    QueryParam::new(name("_x._tcp.local."))
      .with_timeout(Duration::from_secs(60))
      .with_max_entries(1),
    started,
  );
  let inst = name("i._x._tcp.local.");
  let host = name("h.local.");
  ctx.on_ptr(inst.clone());
  ctx.on_srv(&fold(&inst), host.clone(), 80);
  ctx.on_txt(&fold(&inst), vec![]);
  ctx.on_addr(&fold(&host), IpAddr::V4(Ipv4Addr::LOCALHOST));
  assert!(!ctx.is_finished(started), "nothing emitted yet");
  ctx.collect_ready();
  assert!(ctx.take_ready().is_some());
  assert!(ctx.is_finished(started), "the entry cap has been reached");
}

#[test]
fn a_lookup_with_a_zero_timeout_is_immediately_finished() {
  let started = Instant::now();
  let ctx = LookupCtx::new(
    QueryParam::new(name("_x._tcp.local.")).with_timeout(Duration::ZERO),
    started,
  );
  assert!(ctx.is_finished(started));
}

// ---------------------------------------------------------------------------
// Driver wiring: a lookup owns its sub-queries, start to finish.
// ---------------------------------------------------------------------------

#[test]
fn browse_starts_exactly_one_lookup_owned_subquery() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let handle = mdns
    .browse(
      QueryParam::new(name("_hick-mio-browse._tcp.local.")).with_timeout(Duration::from_secs(60)),
    )
    .expect("browse starts");
  assert_eq!(mdns.queries.len(), 1, "the PTR browse sub-query");
  assert!(
    mdns.queries.values().all(|c| c.owner == Some(handle)),
    "and it is owned by the lookup, not the caller"
  );
}

#[test]
fn cancel_lookup_cancels_its_subqueries() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let handle = mdns
    .browse(
      QueryParam::new(name("_hick-mio-cancel._tcp.local.")).with_timeout(Duration::from_secs(60)),
    )
    .expect("browse starts");
  assert_eq!(mdns.queries.len(), 1);
  mdns.cancel_lookup(handle);
  assert!(
    mdns.queries.is_empty(),
    "a cancelled lookup must leave no sub-query transmitting"
  );
  assert!(
    mdns.next_event().is_none(),
    "the caller asked for the cancel, so nothing is reported back"
  );
}

#[test]
fn a_finished_lookup_reports_done_and_leaves_no_subquery() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  // A zero timeout makes the whole lifecycle land inside one tick, with no
  // sleeping and nothing that depends on what is on the link.
  let handle = mdns
    .browse(QueryParam::new(name("_hick-mio-done._tcp.local.")).with_timeout(Duration::ZERO))
    .expect("browse starts");
  mdns.tick().expect("tick");
  let mut done = 0usize;
  while let Some(ev) = mdns.next_event() {
    match ev {
      Event::LookupDone { handle: h } => {
        assert_eq!(h, handle);
        done += 1;
      }
      Event::QueryAnswer { .. } | Event::QueryTerminal { .. } => {
        panic!("a lookup's sub-query must never surface as a caller-facing query event");
      }
      _ => {}
    }
  }
  assert_eq!(done, 1, "LookupDone is reported exactly once");
  assert!(
    mdns.queries.is_empty(),
    "a finished lookup must leave no sub-query transmitting"
  );
  assert!(mdns.lookups.is_empty(), "and no lookup state behind");
}

#[test]
fn a_full_browse_chain_surfaces_a_service_entry() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let service = name("_hick-mio-chain._tcp.local.");
  let instance = name("printer._hick-mio-chain._tcp.local.");
  let host = name("hick-mio-chain-host.local.");

  let lookup = mdns
    .browse(QueryParam::new(service.clone()).with_timeout(Duration::from_secs(60)))
    .expect("browse starts");

  // PTR -> the browse learns the instance and asks for its SRV + TXT.
  feed_response(
    &mut mdns,
    &[Record::Ptr {
      owner: &service,
      target: &instance,
    }],
  );
  mdns.tick().expect("tick");
  assert!(
    drain(&mut mdns).is_empty(),
    "nothing is resolvable from a PTR alone"
  );
  assert_eq!(mdns.queries.len(), 3, "PTR + the instance's SRV and TXT");

  // SRV + TXT -> host and port and metadata; the SRV target is address-queried.
  feed_response(
    &mut mdns,
    &[
      Record::Srv {
        owner: &instance,
        port: 8080,
        target: &host,
      },
      Record::Txt {
        owner: &instance,
        segments: vec![b"path=/x".as_slice()],
      },
    ],
  );
  mdns.tick().expect("tick");
  assert!(
    drain(&mut mdns).is_empty(),
    "still no address, so still not complete"
  );
  assert_eq!(mdns.queries.len(), 5, "plus the host's A and AAAA");

  // A -> the completeness rule is now satisfied and the entry surfaces.
  feed_response(
    &mut mdns,
    &[Record::A {
      owner: &host,
      addr: Ipv4Addr::new(10, 0, 0, 7),
    }],
  );
  mdns.tick().expect("tick");

  let entries: Vec<_> = drain(&mut mdns)
    .into_iter()
    .filter_map(|ev| match ev {
      Event::Lookup { handle, entry } => Some((handle, entry)),
      _ => None,
    })
    .collect();
  assert_eq!(entries.len(), 1, "exactly one resolved instance");
  let (handle, entry) = &entries[0];
  assert_eq!(*handle, lookup);
  assert_eq!(entry.instance_name().as_str(), instance.as_str());
  assert_eq!(entry.host().as_str(), host.as_str());
  assert_eq!(entry.port(), 8080);
  assert_eq!(
    entry.addresses().collect::<Vec<_>>(),
    [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))]
  );
  assert_eq!(entry.txt(), [Bytes::from_static(b"path=/x")]);

  // A fourth tick with no new answers must not re-emit: an instance is
  // reported once, however many times the aggregation is advanced.
  mdns.tick().expect("tick");
  assert!(
    drain(&mut mdns).is_empty(),
    "an already-reported instance must not surface again"
  );
  assert_eq!(mdns.dropped_events(), 0, "no answer was lost on the way");
}

#[test]
fn a_subquerys_answers_are_consumed_once_not_re_fed_every_tick() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let service = name("_hick-mio-seq._tcp.local.");
  mdns
    .browse(QueryParam::new(service.clone()).with_timeout(Duration::from_secs(60)))
    .expect("browse starts");
  let ptr = *mdns
    .queries
    .keys()
    .next()
    .expect("the browse's PTR sub-query");
  assert_eq!(
    mdns.queries[&ptr].last_seq, 0,
    "nothing has been consumed yet"
  );

  feed_response(
    &mut mdns,
    &[
      Record::Ptr {
        owner: &service,
        target: &name("a._hick-mio-seq._tcp.local."),
      },
      Record::Ptr {
        owner: &service,
        target: &name("b._hick-mio-seq._tcp.local."),
      },
    ],
  );
  mdns.tick().expect("tick");

  // The seq window must have advanced past both answers. Without this the
  // aggregation re-feeds the query's whole answer pool on every single tick
  // for the life of the lookup — invisible in the results, because the state
  // machine absorbs a repeat, but unbounded wasted work.
  let accepted = mdns
    .endpoint
    .query_accepted_count(ptr)
    .expect("the PTR query is live");
  assert_eq!(accepted, 2, "both PTR answers were collected");
  assert_eq!(
    mdns.queries[&ptr].last_seq, accepted,
    "the seq window must advance to the accepted count"
  );

  // A second tick with no new answers consumes nothing and starts nothing.
  let before = mdns.queries.len();
  mdns.tick().expect("tick");
  assert_eq!(
    mdns.queries[&ptr].last_seq, accepted,
    "and must not move again without a new answer"
  );
  assert_eq!(
    mdns.queries.len(),
    before,
    "a re-fed PTR answer would be a no-op here, so the sub-query count pins it"
  );
  assert_eq!(mdns.dropped_events(), 0);
}

#[test]
fn a_handle_retained_past_its_terminal_cannot_address_the_lookup_that_reused_its_slot() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  // A zero timeout runs the whole first lookup inside one tick, so the slot is
  // free again with no sleeping and nothing that depends on what is on the link.
  let first = mdns
    .browse(QueryParam::new(name("_hick-mio-aba-one._tcp.local.")).with_timeout(Duration::ZERO))
    .expect("the first browse starts");
  mdns.tick().expect("tick");
  assert!(
    std::iter::from_fn(|| mdns.next_event())
      .any(|ev| matches!(ev, Event::LookupDone { handle } if handle == first)),
    "the first lookup must have reached its terminal"
  );
  assert!(mdns.lookups.is_empty(), "so its slot is free for reuse");

  let second = mdns
    .browse(
      QueryParam::new(name("_hick-mio-aba-two._tcp.local.")).with_timeout(Duration::from_secs(60)),
    )
    .expect("the second browse starts");
  // Load-bearing: without slot reuse this test proves nothing at all.
  assert_eq!(
    first.key, second.key,
    "the slab must have handed the freed slot to the second lookup"
  );
  assert_ne!(
    first, second,
    "but a reused slot must still mint a distinct handle"
  );
  assert_eq!(mdns.queries.len(), 1, "the second lookup's PTR sub-query");

  // The stale handle must be INERT, not an alias for whatever took its slot.
  mdns.cancel_lookup(first);
  assert!(
    !mdns.lookups.is_empty(),
    "a stale handle must not free the live lookup's slot"
  );
  assert_eq!(
    mdns.queries.len(),
    1,
    "nor tear down the live lookup's sub-queries"
  );

  // And the live handle still works, so the check rejects only stale handles.
  mdns.cancel_lookup(second);
  assert!(mdns.lookups.is_empty());
  assert!(mdns.queries.is_empty());
}

#[test]
fn a_caller_owned_query_still_surfaces_its_own_terminal() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  // The mirror image of the test above: the lookup-owner guard must not
  // suppress an ordinary caller-started query's terminal.
  let handle = mdns
    .start_query(
      mdns_proto::QuerySpec::new(name("_hick-mio-plain._tcp.local."), ResourceType::Ptr)
        .with_timeout(Duration::ZERO),
    )
    .expect("query starts");
  mdns.tick().expect("tick");
  let saw_terminal = std::iter::from_fn(|| mdns.next_event())
    .any(|ev| matches!(ev, Event::QueryTerminal { handle: h, .. } if h == handle));
  assert!(saw_terminal, "a caller-owned query reports its terminal");
}

#[test]
fn a_lookup_deadline_wakes_the_loop_with_no_subquery_to_announce_it() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  assert_eq!(
    mdns.next_timeout(),
    None,
    "an endpoint with nothing scheduled blocks indefinitely"
  );
  mdns
    .browse(
      QueryParam::new(name("_hick-mio-timeout._tcp.local.")).with_timeout(Duration::from_secs(60)),
    )
    .expect("browse starts");
  // Strip everything else that could announce a deadline, leaving only the
  // lookup's own. Both removals model real driver states: `drain_transmits`
  // really does retire a sub-query whose question cannot be encoded, and
  // `work_pending` is cleared by the first transmit drain. Nothing was ever
  // sent, so no socket is readable either — if `next_timeout` still reports a
  // deadline, the fold is the only thing that could have produced it.
  let subs: Vec<QueryHandle> = mdns.queries.keys().copied().collect();
  for sub in subs {
    let _ = mdns.endpoint.cancel_query(sub);
    mdns.queries.remove(&sub);
  }
  mdns.work_pending = false;
  let t = mdns
    .next_timeout()
    .expect("a lookup with a pending deadline must wake the loop");
  assert!(
    t <= Duration::from_secs(60),
    "the fold must not report longer than the lookup's own deadline"
  );
}

#[test]
fn resolve_host_and_resolve_instance_start_their_own_sub_queries() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let host = mdns
    .resolve_host(name("hick-mio-host.local."), Duration::from_secs(60))
    .expect("resolve_host starts");
  assert_eq!(mdns.queries.len(), 2, "A + AAAA");
  let inst = mdns
    .resolve_instance(
      name("i._hick-mio-inst._tcp.local."),
      Duration::from_secs(60),
    )
    .expect("resolve_instance starts");
  assert_eq!(mdns.queries.len(), 4, "plus SRV + TXT");
  assert!(mdns.queries.values().all(|c| c.owner.is_some()));
  mdns.cancel_lookup(host);
  mdns.cancel_lookup(inst);
  assert!(mdns.queries.is_empty());
}

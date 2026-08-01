use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
  time::{Duration, Instant},
};

use bytes::Bytes;
use mdns_proto::{
  CollectedAnswer, Name, QueryHandle, QuerySpec,
  wire::{Header, MessageBuilder, ResourceClass, ResourceType},
};

use super::{
  LookupCtx, LookupHandle, MAX_ADDRS_PER_HOST, PartialEntry, QueryParam, Step, fold, parse_name,
};
use crate::{Event, driver::test_support, endpoint::Mdns, error::StartQueryError};

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
  let ctx = super::LookupCtx::new(p);
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
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")));
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
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")));
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
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")));
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
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")).with_max_entries(2));
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
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")).with_max_entries(1));
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
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")));
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
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")));
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
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")));
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
  let mut ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")));
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
  let ctx =
    LookupCtx::new(QueryParam::new(name("_x._tcp.local.")).with_timeout(Duration::from_secs(5)));
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
  let ctx = LookupCtx::new(QueryParam::new(name("_x._tcp.local.")).with_timeout(Duration::ZERO));
  // Asked *after* the lookup opened, because the lookup's window now opens
  // inside `new` rather than at an instant the caller read first: a zero-timeout
  // deadline is the creation instant itself, and an instant read before it is
  // genuinely earlier than the deadline.
  assert!(ctx.is_finished(Instant::now()));
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

// ---------------------------------------------------------------------------
// The clock rule: a sub-query's window is anchored to its lookup's, not to
// whatever instant happened to be in scope. See `driver`'s module docs.
// ---------------------------------------------------------------------------

/// The lookup's own deadline, read straight out of the slab.
fn lookup_deadline(mdns: &Mdns, handle: LookupHandle) -> Instant {
  mdns
    .lookups
    .slab
    .get(handle.key)
    .expect("the lookup is live")
    .deadline()
    .expect("a timeout implies a deadline")
}

#[test]
fn a_leg_opened_late_in_the_walk_still_lands_on_its_lookup_deadline() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let service = name("_hick-mio-anchor._tcp.local.");
  let instance = name("i._hick-mio-anchor._tcp.local.");
  let lookup = mdns
    .browse(QueryParam::new(service.clone()).with_timeout(Duration::from_secs(60)))
    .expect("browse starts");
  let deadline = lookup_deadline(&mdns, lookup);

  feed_response(
    &mut mdns,
    &[Record::Ptr {
      owner: &service,
      target: &instance,
    }],
  );
  let before: Vec<QueryHandle> = mdns.queries.keys().copied().collect();

  // Stage 6 driven with a THIRTY-MILLISECOND gap of real elapsed time between
  // the reading that admits this lookup's answers and the anchor each leg then
  // reads for itself. A real walk's gap is the answer loop — microseconds, which
  // no assertion could tell from zero; the stall stretches it until it cannot
  // hide, and it is elapsed time rather than a synthesised instant because there
  // is no parameter left to synthesise one through.
  //
  // The budget the SRV and TXT legs are given is `deadline - anchor` and the
  // proto layer's only use of the anchor is to add it back, so their absolute
  // deadlines must land on the lookup's EXACTLY however late the anchor is.
  // Split that one reading into two — a budget measured at one instant and an
  // anchor taken at another — and each leg overshoots by the gap.
  mdns.force_launch_delays_for_test(&[Duration::from_millis(30)]);
  mdns.advance_lookups();

  let started: Vec<QueryHandle> = mdns
    .queries
    .keys()
    .copied()
    .filter(|h| !before.contains(h))
    .collect();
  assert_eq!(started.len(), 2, "the instance's SRV and TXT legs");
  for sub in started {
    // Neither leg has transmitted, so the proto layer has scheduled no retry
    // yet and `poll_query_timeout` is the absolute deadline alone.
    assert_eq!(
      mdns.endpoint.poll_query_timeout(sub),
      Some(deadline),
      "a sub-query must expire with its lookup, not after it"
    );
  }
  assert_eq!(
    lookup_deadline(&mdns, lookup),
    deadline,
    "and starting a leg must not move the lookup's own deadline"
  );
}

#[test]
fn a_browses_first_leg_lands_on_the_lookup_deadline_it_was_opened_with() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  // The PTR leg is started by `browse` itself, one call after the lookup is
  // opened. It used to be given the FULL timeout and the lookup's own reading,
  // so it coincided only because the two shared that instant; it is measured
  // against the lookup now, so it coincides by construction.
  let lookup = mdns
    .browse(
      QueryParam::new(name("_hick-mio-first-leg._tcp.local."))
        .with_timeout(Duration::from_secs(60)),
    )
    .expect("browse starts");
  let deadline = lookup_deadline(&mdns, lookup);
  let ptr = *mdns.queries.keys().next().expect("the PTR leg");
  assert_eq!(
    mdns.endpoint.poll_query_timeout(ptr),
    Some(deadline),
    "the browse's own PTR leg must expire with its lookup"
  );

  // `resolve_host` and `resolve_instance` seed their legs before the lookup is
  // even in the slab, so they take the other path — `start_seeded`.
  let host = mdns
    .resolve_host(name("hick-mio-seeded.local."), Duration::from_secs(60))
    .expect("resolve_host starts");
  let host_deadline = lookup_deadline(&mdns, host);
  for sub in mdns
    .queries
    .iter()
    .filter(|(_, c)| c.owner == Some(host))
    .map(|(h, _)| *h)
    .collect::<Vec<_>>()
  {
    assert_eq!(
      mdns.endpoint.poll_query_timeout(sub),
      Some(host_deadline),
      "a seeded lookup's A/AAAA legs must expire with it too"
    );
  }
}

/// A leg may only be opened by an instant INSIDE its lookup's window.
///
/// A zero timeout puts the deadline on the very instant `LookupCtx::new` read,
/// so every reading taken afterwards — including the one `browse` takes a call
/// later for the PTR leg — is at or past it. Deterministic on any host: the
/// clock is monotonic, so no sleeping or backdating is needed to get there.
///
/// Clamping the remainder to zero rather than refusing hands the proto layer
/// `at + 0 == at`, an absolute deadline strictly LATER than the lookup's own —
/// a leg born outside the window it exists to be bounded by, alive until some
/// later tick reaps it.
#[test]
fn a_lookup_whose_window_has_already_closed_opens_no_leg() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let lookup = mdns
    .browse(QueryParam::new(name("_hick-mio-shut._tcp.local.")).with_timeout(Duration::ZERO))
    .expect("a lookup whose window is already shut is still a lookup, not an error");
  let deadline = lookup_deadline(&mdns, lookup);
  for &sub in mdns.queries.keys() {
    // Nothing has transmitted, so the proto layer has scheduled no retry yet and
    // `poll_query_timeout` is the absolute deadline alone. Checked before the
    // count below so a failure names WHERE the leg landed, not just that one
    // exists.
    assert!(
      mdns
        .endpoint
        .poll_query_timeout(sub)
        .is_none_or(|t| t <= deadline),
      "a leg was opened with a deadline past its lookup's"
    );
  }
  assert!(
    mdns.queries.is_empty(),
    "and on a shut window no leg may be opened at all"
  );

  // `resolve_host` seeds its legs before the lookup reaches the slab, so it
  // starts them through `start_seeded`/`launch_pending` rather than `browse`'s
  // path — and a refused start must not be mistaken there for the pool-full
  // failure those two unwind the whole lookup on.
  mdns
    .resolve_host(name("hick-mio-shut-host.local."), Duration::ZERO)
    .expect("a shut-window resolve_host is not an error either");
  assert!(
    mdns.queries.is_empty(),
    "the seeded path must open no leg on a shut window either"
  );

  // Opening none breaks nothing: both lookups still reach their terminal.
  mdns.tick().expect("tick");
  let done = drain(&mut mdns)
    .into_iter()
    .filter(|ev| matches!(ev, Event::LookupDone { .. }))
    .count();
  assert_eq!(done, 2, "each lookup still reports exactly one LookupDone");
}

/// Drive a browse of `service` to exactly one A answer short of completing
/// `instance`: PTR, SRV and TXT are in, `host`'s A/AAAA legs are running, and
/// nothing has surfaced yet.
///
/// Each caller then feeds the answer(s) it wants left unconsumed and chooses how
/// the expiry arrives.
fn browse_one_answer_short(
  mdns: &mut Mdns,
  service: &Name,
  instance: &Name,
  host: &Name,
  timeout: Duration,
) -> LookupHandle {
  // The window has to outlast this setup, or the caller's expiry is not the one
  // under test. A caller that stipulates the expiry afterwards passes a minute;
  // one that lets real time cross the boundary passes the shortest window its
  // own margin can carry.
  let lookup = mdns
    .browse(QueryParam::new(service.clone()).with_timeout(timeout))
    .expect("browse starts");
  feed_response(
    mdns,
    &[Record::Ptr {
      owner: service,
      target: instance,
    }],
  );
  mdns.tick().expect("tick");
  feed_response(
    mdns,
    &[
      Record::Srv {
        owner: instance,
        port: 8080,
        target: host,
      },
      Record::Txt {
        owner: instance,
        segments: vec![b"k=v".as_slice()],
      },
    ],
  );
  mdns.tick().expect("tick");
  assert!(
    drain(mdns).is_empty(),
    "an instance one address short of complete must not have surfaced yet"
  );
  lookup
}

/// Stipulate that `handle`'s window is already shut, without waiting for one.
///
/// The deadline is the only thing that says a lookup is over, so a test that
/// asserts what an *expired* lookup does states the expiry rather than racing
/// real time for it. Tests that assert *when* the boundary is observed must not
/// use this — they have to let a real clock cross a real window.
fn expire_now(mdns: &mut Mdns, handle: LookupHandle) {
  let expired = Instant::now()
    .checked_sub(Duration::from_secs(1))
    // A monotonic clock too young to backdate still satisfies the `now >= d`
    // boundary: every reading the walk takes is later than this one.
    .unwrap_or_else(Instant::now);
  mdns
    .lookups
    .slab
    .get_mut(handle.key)
    .expect("the lookup is live")
    .deadline = Some(expired);
}

#[test]
fn an_answer_consumed_after_the_deadline_surfaces_no_entry() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let service = name("_hick-mio-late._tcp.local.");
  let instance = name("i._hick-mio-late._tcp.local.");
  let host = name("hick-mio-late-host.local.");
  let lookup = browse_one_answer_short(
    &mut mdns,
    &service,
    &instance,
    &host,
    Duration::from_secs(60),
  );

  // The address that completes the instance: collected by the A leg, and
  // unconsumed because stage 6 has not run since.
  feed_response(
    &mut mdns,
    &[Record::A {
      owner: &host,
      addr: Ipv4Addr::new(10, 0, 0, 9),
    }],
  );

  // The lookup's window is put behind us rather than an instant ahead of it:
  // stage 6 reads its own clock at each decision, so "expired" is now a property
  // of the lookup and not of an argument. It must finish the lookup INSTEAD of
  // advancing it: emitting first and testing expiry afterwards puts a
  // caller-visible entry outside the window `QueryParam::with_timeout` bounds
  // the lookup to.
  expire_now(&mut mdns, lookup);
  mdns.advance_lookups();

  let events = drain(&mut mdns);
  assert!(
    !events.iter().any(|ev| matches!(ev, Event::Lookup { .. })),
    "an expired lookup must surface no entry: `with_timeout` is a hard boundary"
  );
  assert_eq!(
    events
      .iter()
      .filter(|ev| matches!(ev, Event::LookupDone { handle } if *handle == lookup))
      .count(),
    1,
    "it reports its terminal, and that is all it reports"
  );
  assert!(
    mdns.queries.is_empty(),
    "and it takes every leg it owned with it"
  );
}

/// Feed the crossing tests their two unconsumed answers: the address that
/// completes the first instance, and a second instance whose SRV/TXT resolves
/// the lookup would have to launch to pursue.
///
/// Both kinds of work at once, so a walk that runs when it must not is caught
/// whichever of them it does first.
fn feed_both_kinds_of_pending_work(mdns: &mut Mdns, service: &Name, host: &Name, second: &Name) {
  feed_response(
    mdns,
    &[
      Record::A {
        owner: host,
        addr: Ipv4Addr::new(10, 0, 0, 9),
      },
      Record::Ptr {
        owner: service,
        target: second,
      },
    ],
  );
}

/// The premise every crossing-tick test rests on: the tick **began** inside the
/// lookup's window and ended outside it.
///
/// The opening half is read from the instant `tick` took at its top rather than
/// from a reading taken beside the call, because those are different instants and
/// only one of them is the one under test. A tick that began past the deadline
/// would exercise the already-expired path instead, and would pass whatever stage
/// 6 does — a vacuous pass on a slow host, which is what this rules out.
fn assert_premise_of_a_mid_tick_crossing(mdns: &Mdns, deadline: Instant) {
  assert!(
    mdns
      .last_tick_instant
      .expect("the tick records the instant it read")
      < deadline,
    "the tick must begin inside the lookup's window, or this asserts nothing"
  );
  assert!(
    Instant::now() >= deadline,
    "and the stall must have carried it out of the window"
  );
}

/// A lookup already past its deadline when the tick begins does no work in it.
///
/// The expiry is stipulated, which is what makes this the *pre*-tick case: the
/// tick's own instant is already past the deadline, so it is caught by the first
/// test the walk makes. See the test below for the case where the tick itself
/// crosses the boundary, which this one cannot reach.
#[test]
fn a_tick_that_begins_past_the_deadline_does_no_lookup_work() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let service = name("_hick-mio-cross._tcp.local.");
  let instance = name("i._hick-mio-cross._tcp.local.");
  let host = name("hick-mio-cross-host.local.");
  let lookup = browse_one_answer_short(
    &mut mdns,
    &service,
    &instance,
    &host,
    Duration::from_secs(60),
  );
  feed_both_kinds_of_pending_work(
    &mut mdns,
    &service,
    &host,
    &name("j._hick-mio-cross._tcp.local."),
  );
  // The legs keep their own 60-second deadlines, so stage 3 does not reap them
  // and stage 6 is the only thing that can end this lookup.
  expire_now(&mut mdns, lookup);

  #[cfg(feature = "stats")]
  let started_before = mdns.stats().queries_started;
  mdns.tick().expect("tick");
  #[cfg(feature = "stats")]
  assert_eq!(
    mdns.stats().queries_started,
    started_before,
    "a lookup the tick has already crossed the deadline of must launch no leg"
  );

  let events = drain(&mut mdns);
  assert!(
    !events.iter().any(|ev| matches!(ev, Event::Lookup { .. })),
    "nor consume an answer into a caller-visible entry"
  );
  assert_eq!(
    events
      .iter()
      .filter(|ev| matches!(ev, Event::LookupDone { handle } if *handle == lookup))
      .count(),
    1,
    "the crossing tick reports the terminal exactly once"
  );
  assert!(mdns.queries.is_empty(), "and cancels every leg it owned");
}

/// The tick that crosses the boundary **itself**, with nothing backdated.
///
/// The window is a real 500 ms measured from `browse`, and stage 1 is made to
/// lose the CPU for 900 ms of it. That stall lands *before* the read, so it is
/// charged whether or not a datagram is waiting, and it puts the deadline inside
/// the tick with five stages still to run — which no arrangement of the lookup's
/// own fields can do, since the fields are what the tick reads.
///
/// What it catches: stage 6 weighing this caller-facing boundary against the
/// instant `tick` read at its top. That reading is *before* the deadline here —
/// asserted rather than assumed, so a slow host fails the premise loudly instead
/// of passing on the pre-tick path the test above already covers — so a stage 6
/// that trusts it walks a lookup whose window has in fact already shut, and must
/// be caught doing it.
///
/// Where it is caught, which bounds what it proves: this lookup reaches the
/// launch loop holding pending work, so a leg's own anchor reports the shut
/// window and the walk retires the lookup right there — **before** the emit
/// boundary is consulted at all. That makes this the launch boundary's test. The
/// variant below drains `pending` so the emit boundary is the only thing left
/// between a completed entry and the caller.
///
/// The leg assertion is a guard rather than a discriminator: a leg's window is
/// anchored by its own reading inside `start_subquery_in_window`, so a
/// post-deadline leg is already unopenable. It is asserted because that is the
/// property a future hoist of the anchor would silently take away.
#[test]
fn a_tick_that_crosses_the_deadline_mid_tick_does_no_lookup_work() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let service = name("_hick-mio-midtick._tcp.local.");
  let instance = name("i._hick-mio-midtick._tcp.local.");
  let host = name("hick-mio-midtick-host.local.");
  let lookup = browse_one_answer_short(
    &mut mdns,
    &service,
    &instance,
    &host,
    Duration::from_millis(500),
  );
  let deadline = lookup_deadline(&mdns, lookup);
  feed_both_kinds_of_pending_work(
    &mut mdns,
    &service,
    &host,
    &name("j._hick-mio-midtick._tcp.local."),
  );

  // Readable-but-empty: the stall is charged on the read attempt, and the real
  // `recv` behind it reports `WouldBlock` and ends stage 1 without needing a
  // peer to supply a datagram.
  mdns
    .sockets
    .set_readable_for_test(crate::socket::Family::V4, true);
  mdns
    .sockets
    .force_recv_delays_for_test(crate::socket::Family::V4, &[Duration::from_millis(900)]);

  #[cfg(feature = "stats")]
  let started_before = mdns.stats().queries_started;
  mdns.tick().expect("tick");
  // The premise, stated about the reading the tick itself took rather than one
  // taken beside the call: the tick began inside the window, so what ended this
  // lookup can only be a reading taken later in the same tick.
  assert_premise_of_a_mid_tick_crossing(&mdns, deadline);

  #[cfg(feature = "stats")]
  assert_eq!(
    mdns.stats().queries_started,
    started_before,
    "a tick that crossed the deadline mid-flight must launch no leg after it"
  );
  let events = drain(&mut mdns);
  assert!(
    !events.iter().any(|ev| matches!(ev, Event::Lookup { .. })),
    "nor surface an entry the caller was promised could not arrive"
  );
  assert_eq!(
    events
      .iter()
      .filter(|ev| matches!(ev, Event::LookupDone { handle } if *handle == lookup))
      .count(),
    1,
    "the crossing tick reports the terminal in that same tick"
  );
  assert!(mdns.queries.is_empty(), "and cancels every leg it owned");
}

/// The same real crossing with **nothing left to launch**, which is what makes
/// it discriminate the emit boundary.
///
/// The test above hands its lookup a second instance as well, so the walk always
/// reaches the launch loop with a non-empty `pending` list and is retired there
/// by the leg's own anchor. Every assertion it makes therefore still holds on an
/// implementation whose emit boundary weighs a stale tick-top reading: control
/// never gets that far. That test cannot see the difference.
///
/// This one feeds only the address that completes the first instance. There is
/// no second instance to pursue, `pending` is empty, the launch loop runs zero
/// iterations and produces no verdict — so the reading the emit takes for itself
/// is the ONLY thing standing between a completed entry and the caller. Weigh a
/// tick-top instant there and the queued A answer is consumed, collected, and
/// surfaced as an `Event::Lookup` well past a 500 ms window.
///
/// No leg assertion here, deliberately: with nothing pending there is nothing
/// that could open, so asserting it would assert nothing. The launch boundary is
/// the test above's to cover.
#[test]
fn a_tick_that_crosses_the_deadline_surfaces_no_entry_completed_in_it() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let service = name("_hick-mio-emit._tcp.local.");
  let instance = name("i._hick-mio-emit._tcp.local.");
  let host = name("hick-mio-emit-host.local.");
  let lookup = browse_one_answer_short(
    &mut mdns,
    &service,
    &instance,
    &host,
    Duration::from_millis(500),
  );
  let deadline = lookup_deadline(&mdns, lookup);

  // The completing answer and nothing else — no second instance — so the walk
  // arrives at the emit with an empty `pending` list and one entry ready to
  // surface. Feeding a second PTR here would mask the boundary under test.
  feed_response(
    &mut mdns,
    &[Record::A {
      owner: &host,
      addr: Ipv4Addr::new(10, 0, 0, 9),
    }],
  );

  // Readable-but-empty: the stall is charged on the read attempt, and the real
  // `recv` behind it reports `WouldBlock` and ends stage 1 without needing a
  // peer to supply a datagram.
  mdns
    .sockets
    .set_readable_for_test(crate::socket::Family::V4, true);
  mdns
    .sockets
    .force_recv_delays_for_test(crate::socket::Family::V4, &[Duration::from_millis(900)]);

  mdns.tick().expect("tick");
  assert_premise_of_a_mid_tick_crossing(&mdns, deadline);

  let events = drain(&mut mdns);
  assert!(
    !events.iter().any(|ev| matches!(ev, Event::Lookup { .. })),
    "an instance completed after the deadline must not be surfaced, however \
     early in the tick the deadline still looked open"
  );
  assert_eq!(
    events
      .iter()
      .filter(|ev| matches!(ev, Event::LookupDone { handle } if *handle == lookup))
      .count(),
    1,
    "the crossing tick reports the terminal in that same tick"
  );
  assert!(mdns.queries.is_empty(), "and cancels every leg it owned");
}

/// A window that shuts **during** the walk, between the reading that admitted
/// this lookup's answers and the launches that reading permitted.
///
/// `start_subquery_in_window` reads its own anchor, so it is the one thing in
/// the tick holding fresher evidence than the walk that called it: its
/// `Ok(None)` is a proof the window is shut. Discarding that proof — logging it
/// and continuing to result collection — surfaces an entry on the strength of a
/// reading already known to be stale.
///
/// What it catches: exactly that fall-through. Under the pre-fix shape, where
/// the walk weighs one hoisted reading, `Ok(None)` is the *only* evidence the
/// lookup is over, so a walk that logs it and carries on emits `Event::Lookup`
/// and leaves the lookup in the slab.
///
/// The gap is nanoseconds wide on a healthy host, so the stall is what makes it
/// reachable at all — there is no timeout a test could pick that lands inside
/// it, and no field to backdate that would not also move the reading above.
#[test]
fn a_window_that_shuts_mid_walk_retires_the_lookup_uncollected() {
  let Some(mut mdns) = test_support::loopback_mdns_v4_only() else {
    return;
  };
  let service = name("_hick-mio-midwalk._tcp.local.");
  let instance = name("i._hick-mio-midwalk._tcp.local.");
  let host = name("hick-mio-midwalk-host.local.");
  let lookup = browse_one_answer_short(
    &mut mdns,
    &service,
    &instance,
    &host,
    Duration::from_millis(500),
  );
  let deadline = lookup_deadline(&mdns, lookup);
  feed_both_kinds_of_pending_work(
    &mut mdns,
    &service,
    &host,
    &name("j._hick-mio-midwalk._tcp.local."),
  );

  #[cfg(feature = "stats")]
  let started_before = mdns.stats().queries_started;
  mdns.force_launch_delays_for_test(&[Duration::from_millis(900)]);
  assert!(
    Instant::now() < deadline,
    "the walk must begin inside the lookup's window, or this asserts nothing"
  );
  mdns.advance_lookups();
  assert!(
    Instant::now() >= deadline,
    "and the stall must have carried it out of the window"
  );

  #[cfg(feature = "stats")]
  assert_eq!(
    mdns.stats().queries_started,
    started_before,
    "the second instance's resolves are outside the window and must not open"
  );
  let events = drain(&mut mdns);
  assert!(
    !events.iter().any(|ev| matches!(ev, Event::Lookup { .. })),
    "the entry the answer walk completed must not be collected past the boundary"
  );
  assert_eq!(
    events
      .iter()
      .filter(|ev| matches!(ev, Event::LookupDone { handle } if *handle == lookup))
      .count(),
    1,
    "the walk that proved the window shut reports the terminal itself"
  );
  assert!(mdns.queries.is_empty(), "and cancels every leg it owned");
}

/// The parameters that carried an instant into a lookup's schedule-creating
/// entry points are gone, so a caller has nothing to hand one in through.
///
/// A signature assertion rather than a behavioural one, and deliberately so:
/// there is no behaviour left to assert. The reading those parameters carried
/// cancelled out of the result arithmetic, so removing them changed no deadline
/// anywhere — what changed is that the *split* reading, which does not cancel,
/// can no longer be expressed. A test that cannot fail is worse than none, so
/// this one pins the shape instead of pretending to measure a difference.
#[test]
fn a_lookups_schedule_creating_entry_points_take_no_instant() {
  let _: fn(QueryParam) -> LookupCtx = LookupCtx::new;
  let _: fn(&mut Mdns, LookupCtx) -> Result<LookupHandle, StartQueryError> = Mdns::start_seeded;
  let _: fn(&mut Mdns, LookupHandle) -> Result<(), StartQueryError> = Mdns::launch_pending;
  let _: fn(&mut Mdns, LookupHandle, QuerySpec, Step) -> Result<(), StartQueryError> =
    Mdns::start_subquery;
}

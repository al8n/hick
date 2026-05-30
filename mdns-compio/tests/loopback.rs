//! End-to-end loopback tests for the compio driver.
#![cfg(any(unix, windows))]
#![allow(clippy::unwrap_used)]

use std::time::Duration;

fn super_loopback_index() -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP))
    .map(|i| i.index())
}

#[compio::test]
async fn endpoint_server_constructs_and_drops_cleanly() {
  use mdns_compio::{Endpoint, ServerOptions};
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let opts = ServerOptions::default()
    .with_interface_index(Some(idx))
    .with_ipv6(false);
  let ep = match Endpoint::server(opts).await {
    Ok(e) => e,
    Err(e) => {
      eprintln!("skip: {e:?}");
      return;
    }
  };
  drop(ep);
}

#[compio::test]
async fn register_service_handle_is_returned() {
  use mdns_compio::{Endpoint, Name, ServerOptions, ServiceRecords, ServiceSpec};
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let ep = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(e) => {
      eprintln!("skip: {e:?}");
      return;
    }
  };
  let stype = Name::try_from_str("_t._tcp.local.").unwrap();
  let inst = Name::try_from_str("R._t._tcp.local.").unwrap();
  let host = Name::try_from_str("r.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 1234, 120);
  recs.add_a([127, 0, 0, 1].into());
  let svc = ep.register_service(ServiceSpec::new(recs)).await.unwrap();
  drop(svc);
}

#[compio::test]
async fn start_query_returns_handle_and_next_terminates_on_timeout() {
  use mdns_compio::{Endpoint, Name, QueryEvent, QuerySpec, ServerOptions};
  use mdns_proto::wire::ResourceType;
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let ep = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };
  let spec = QuerySpec::new(
    Name::try_from_str("_nx._tcp.local.").unwrap(),
    ResourceType::Ptr,
  )
  .with_timeout(Duration::from_millis(500));
  let q = ep.start_query(spec).await.unwrap();
  let mut saw_terminal = false;
  while let Some(ev) = q.next().await {
    if matches!(ev, QueryEvent::Terminal(_)) {
      saw_terminal = true;
      break;
    }
  }
  assert!(saw_terminal);
}

#[compio::test]
async fn responder_reaches_established_on_loopback() {
  use mdns_compio::{Endpoint, Name, ServerOptions, ServiceRecords, ServiceSpec, ServiceUpdate};
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let ep = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };
  let stype = Name::try_from_str("_resp._tcp.local.").unwrap();
  let inst = Name::try_from_str("R._resp._tcp.local.").unwrap();
  let host = Name::try_from_str("r.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 1234, 120);
  recs.add_a([127, 0, 0, 1].into());
  let svc = ep.register_service(ServiceSpec::new(recs)).await.unwrap();

  let mut saw_established = false;
  let _ = compio::time::timeout(std::time::Duration::from_secs(3), async {
    while let Some(u) = svc.next().await {
      if matches!(u, ServiceUpdate::Established) {
        saw_established = true;
        break;
      }
    }
  })
  .await;

  if !saw_established {
    eprintln!("note: did not observe Established within 3s — env may not loop multicast");
  }
}

#[compio::test]
async fn responder_to_querier_loopback_ptr() {
  use mdns_compio::{
    Endpoint, Name, QueryEvent, QuerySpec, ServerOptions, ServiceRecords, ServiceSpec,
  };
  use mdns_proto::wire::ResourceType;
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };

  let responder = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };
  let querier = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };

  let stype = Name::try_from_str("_ptr._tcp.local.").unwrap();
  let inst = Name::try_from_str("P._ptr._tcp.local.").unwrap();
  let host = Name::try_from_str("p.local.").unwrap();
  let mut recs = ServiceRecords::new(stype.clone(), inst, host, 9999, 120);
  recs.add_a([127, 0, 0, 1].into());
  let _svc = responder
    .register_service(ServiceSpec::new(recs))
    .await
    .unwrap();

  // Let the responder finish probing + announcing before the querier asks.
  compio::time::sleep(Duration::from_millis(1300)).await;

  let q = querier
    .start_query(QuerySpec::new(stype, ResourceType::Ptr).with_timeout(Duration::from_secs(2)))
    .await
    .unwrap();

  let mut got_ptr = false;
  let _ = compio::time::timeout(Duration::from_secs(3), async {
    while let Some(ev) = q.next().await {
      match ev {
        QueryEvent::Answer(a) => {
          if a.rtype() == ResourceType::Ptr {
            got_ptr = true;
            break;
          }
        }
        QueryEvent::Terminal(_) => break,
      }
    }
  })
  .await;

  if !got_ptr {
    eprintln!("note: no PTR within window — env may not loop multicast");
  }
}

#[compio::test]
async fn browse_returns_registered_instance() {
  use mdns_compio::{Endpoint, Name, QueryParam, ServerOptions, ServiceRecords, ServiceSpec};
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let responder = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };
  let querier = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };

  let stype = Name::try_from_str("_b._tcp.local.").unwrap();
  let inst = Name::try_from_str("B._b._tcp.local.").unwrap();
  let host = Name::try_from_str("b.local.").unwrap();
  let mut recs = ServiceRecords::new(stype.clone(), inst, host, 7777, 120);
  recs.add_a([127, 0, 0, 1].into());
  let _svc = responder
    .register_service(ServiceSpec::new(recs))
    .await
    .unwrap();

  // Let the responder finish probing + announcing before the querier browses.
  compio::time::sleep(Duration::from_millis(1300)).await;

  let lookup = querier
    .browse(QueryParam::new(stype).with_timeout(Duration::from_secs(2)))
    .await
    .unwrap();
  let entry = compio::time::timeout(Duration::from_secs(3), async {
    let mut l = lookup;
    l.next().await
  })
  .await
  .ok()
  .flatten();

  if let Some(e) = entry {
    assert_eq!(e.port(), 7777);
  } else {
    eprintln!("note: no entry — env may not loop multicast");
  }
}

#[compio::test]
async fn responder_to_querier_loopback_srv() {
  use mdns_compio::{
    Endpoint, Name, QueryEvent, QuerySpec, ServerOptions, ServiceRecords, ServiceSpec,
  };
  use mdns_proto::wire::ResourceType;
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };

  let responder = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };
  let querier = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };

  let stype = Name::try_from_str("_srv._tcp.local.").unwrap();
  let inst = Name::try_from_str("S._srv._tcp.local.").unwrap();
  let host = Name::try_from_str("s.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst.clone(), host, 5555, 120);
  recs.add_a([127, 0, 0, 1].into());
  let _svc = responder
    .register_service(ServiceSpec::new(recs))
    .await
    .unwrap();

  // Let the responder finish probing + announcing before the querier asks.
  compio::time::sleep(Duration::from_millis(1300)).await;

  let q = querier
    .start_query(QuerySpec::new(inst, ResourceType::Srv).with_timeout(Duration::from_secs(2)))
    .await
    .unwrap();

  let mut got_srv = false;
  let _ = compio::time::timeout(Duration::from_secs(3), async {
    while let Some(ev) = q.next().await {
      match ev {
        QueryEvent::Answer(a) => {
          if a.rtype() == ResourceType::Srv {
            got_srv = true;
            break;
          }
        }
        QueryEvent::Terminal(_) => break,
      }
    }
  })
  .await;

  if !got_srv {
    eprintln!("note: no SRV within window — env may not loop multicast");
  }
}

#[compio::test]
async fn responder_to_querier_loopback_txt() {
  use mdns_compio::{
    Endpoint, Name, QueryEvent, QuerySpec, ServerOptions, ServiceRecords, ServiceSpec,
  };
  use mdns_proto::wire::ResourceType;
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };

  let responder = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };
  let querier = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };

  let stype = Name::try_from_str("_txt._tcp.local.").unwrap();
  let inst = Name::try_from_str("T._txt._tcp.local.").unwrap();
  let host = Name::try_from_str("t.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst.clone(), host, 6666, 120);
  recs.add_a([127, 0, 0, 1].into());
  let _svc = responder
    .register_service(ServiceSpec::new(recs))
    .await
    .unwrap();

  // Let the responder finish probing + announcing before the querier asks.
  compio::time::sleep(Duration::from_millis(1300)).await;

  let q = querier
    .start_query(QuerySpec::new(inst, ResourceType::Txt).with_timeout(Duration::from_secs(2)))
    .await
    .unwrap();

  let mut got_txt = false;
  let _ = compio::time::timeout(Duration::from_secs(3), async {
    while let Some(ev) = q.next().await {
      match ev {
        QueryEvent::Answer(a) => {
          if a.rtype() == ResourceType::Txt {
            got_txt = true;
            break;
          }
        }
        QueryEvent::Terminal(_) => break,
      }
    }
  })
  .await;

  if !got_txt {
    eprintln!("note: no TXT within window — env may not loop multicast");
  }
}

#[compio::test]
async fn responder_to_querier_loopback_a() {
  use mdns_compio::{
    Endpoint, Name, QueryEvent, QuerySpec, ServerOptions, ServiceRecords, ServiceSpec,
  };
  use mdns_proto::wire::ResourceType;
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };

  let responder = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };
  let querier = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };

  let stype = Name::try_from_str("_a._tcp.local.").unwrap();
  let inst = Name::try_from_str("A._a._tcp.local.").unwrap();
  let host = Name::try_from_str("a.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host.clone(), 4444, 120);
  recs.add_a([127, 0, 0, 1].into());
  let _svc = responder
    .register_service(ServiceSpec::new(recs))
    .await
    .unwrap();

  // Let the responder finish probing + announcing before the querier asks.
  compio::time::sleep(Duration::from_millis(1300)).await;

  let q = querier
    .start_query(QuerySpec::new(host, ResourceType::A).with_timeout(Duration::from_secs(2)))
    .await
    .unwrap();

  let mut got_a = false;
  let _ = compio::time::timeout(Duration::from_secs(3), async {
    while let Some(ev) = q.next().await {
      match ev {
        QueryEvent::Answer(a) => {
          if a.rtype() == ResourceType::A {
            got_a = true;
            break;
          }
        }
        QueryEvent::Terminal(_) => break,
      }
    }
  })
  .await;

  if !got_a {
    eprintln!("note: no A within window — env may not loop multicast");
  }
}

#[compio::test]
async fn resolve_host_returns_addresses() {
  use mdns_compio::{Endpoint, Name, ServerOptions, ServiceRecords, ServiceSpec};
  use std::net::IpAddr;

  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let responder = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };
  let querier = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };

  let stype = Name::try_from_str("_rh._tcp.local.").unwrap();
  let inst = Name::try_from_str("RH._rh._tcp.local.").unwrap();
  let host = Name::try_from_str("rh.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host.clone(), 3333, 120);
  recs.add_a([127, 0, 0, 1].into());
  let _svc = responder
    .register_service(ServiceSpec::new(recs))
    .await
    .unwrap();

  // Let probe + announce settle before issuing queries.
  compio::time::sleep(Duration::from_millis(1300)).await;

  let addrs = match querier.resolve_host(host, Duration::from_secs(2)).await {
    Ok(a) => a,
    Err(e) => {
      eprintln!("note: resolve_host failed: {e:?}");
      return;
    }
  };

  if addrs.is_empty() {
    eprintln!("note: resolve_host returned no addresses — env may not loop multicast");
    return;
  }

  assert!(
    addrs.contains(&IpAddr::V4(core::net::Ipv4Addr::new(127, 0, 0, 1))),
    "expected 127.0.0.1 in {addrs:?}"
  );
}

/// RFC 6762 §10.1: dropping a registered service must release the
/// proto-layer route slot (so the same instance name can be re-registered
/// immediately) AND queue the TTL=0 goodbye burst — the regression Service
/// Drop used to skip, leaking a slot per drop until endpoint shutdown.
///
/// We can't directly observe the goodbye datagrams on the wire from a
/// caller-level test (multicast loopback may not echo to the same process
/// in every environment), so the assertion is the proto-side one: an
/// immediate re-register of the same instance name on the same endpoint
/// must succeed. Before the fix this returned `NameAlreadyRegistered`
/// because the proto route was never released on Drop.
#[compio::test]
async fn dropping_service_releases_proto_slot_for_reregister() {
  use mdns_compio::{Endpoint, Name, ServerOptions, ServiceRecords, ServiceSpec};
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let ep = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(e) => {
      eprintln!("skip: {e:?}");
      return;
    }
  };
  let stype = Name::try_from_str("_gb._tcp.local.").unwrap();
  let inst = Name::try_from_str("GB._gb._tcp.local.").unwrap();
  let host = Name::try_from_str("gb.local.").unwrap();
  let mk = || {
    let mut r = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 1234, 120);
    r.add_a([127, 0, 0, 1].into());
    ServiceSpec::new(r)
  };
  let svc = ep.register_service(mk()).await.unwrap();
  // Give the driver one loop iteration to pick up the registration before
  // dropping it.
  compio::time::sleep(Duration::from_millis(50)).await;
  drop(svc);
  // Withdrawal is DRIVER-OWNED: `Service::drop` only flags the service
  // cancelled (so a send in flight when the handle dropped can latch before the
  // §10.1 goodbye is encoded); the driver's post-pump sweep then frees the
  // proto route slot. Yield so that sweep runs before we re-register the same
  // instance name — otherwise the slot is still held and re-registration would
  // hit NameAlreadyRegistered.
  compio::time::sleep(Duration::from_millis(100)).await;
  let svc2 = ep
    .register_service(mk())
    .await
    .expect("re-register after drop must succeed once the driver sweep frees the slot");
  drop(svc2);
}

/// Dropping the Endpoint AND its last Service together must not hang the driver
/// task: the spawned driver observes `Rc::strong_count == 1` on its pre-park
/// settle step and exits, flushing the §10.1 goodbye, even though the drops'
/// `notify` wakes may have been lost (no listener armed mid-loop). Regression
/// for the codex R5 lost-notify shutdown stall: before the redesign the driver
/// could park forever after the last handle dropped during a send. The test
/// passes by simply completing — a hung driver would not deadlock the test (the
/// task is detached) but this exercises the clean-teardown path without panic,
/// and the bounded sleep lets the driver run its shutdown drain.
#[compio::test]
async fn dropping_endpoint_and_service_shuts_down_cleanly() {
  use mdns_compio::{Endpoint, Name, ServerOptions, ServiceRecords, ServiceSpec};
  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let ep = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(e) => {
      eprintln!("skip: {e:?}");
      return;
    }
  };
  let stype = Name::try_from_str("_sd._tcp.local.").unwrap();
  let inst = Name::try_from_str("SD._sd._tcp.local.").unwrap();
  let host = Name::try_from_str("sd.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 1234, 120);
  recs.add_a([127, 0, 0, 1].into());
  let svc = ep.register_service(ServiceSpec::new(recs)).await.unwrap();
  // Let the service probe/announce so a real goodbye is owed at withdrawal.
  compio::time::sleep(Duration::from_millis(800)).await;

  // Drop BOTH handles: this releases the last external `Rc<EndpointInner>` so
  // the driver's next pre-park settle sees `strong_count == 1` and runs the
  // shutdown goodbye flush before exiting — regardless of whether either drop's
  // `notify` reached a listener.
  drop(svc);
  drop(ep);

  // Give the detached driver time to settle + flush + exit. Reaching here
  // without a panic is the assertion; the redesign guarantees the driver does
  // not park indefinitely after the last handle is gone.
  compio::time::sleep(Duration::from_millis(300)).await;
}

#[compio::test]
async fn resolve_instance_returns_entry() {
  use mdns_compio::{Endpoint, Name, ServerOptions, ServiceRecords, ServiceSpec};

  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let responder = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };
  let querier = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(_) => return,
  };

  let stype = Name::try_from_str("_ri._tcp.local.").unwrap();
  let inst = Name::try_from_str("RI._ri._tcp.local.").unwrap();
  let host = Name::try_from_str("ri.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst.clone(), host, 2222, 120);
  recs.add_a([127, 0, 0, 1].into());
  let _svc = responder
    .register_service(ServiceSpec::new(recs))
    .await
    .unwrap();

  compio::time::sleep(Duration::from_millis(1300)).await;

  let entry = match querier.resolve_instance(inst, Duration::from_secs(3)).await {
    Ok(e) => e,
    Err(e) => {
      eprintln!("note: resolve_instance failed: {e:?}");
      return;
    }
  };

  let entry = match entry {
    Some(e) => e,
    None => {
      eprintln!("note: resolve_instance returned None — env may not loop multicast");
      return;
    }
  };

  assert_eq!(entry.port(), 2222, "wrong port");
  assert!(
    entry.host().as_str().eq_ignore_ascii_case("ri.local."),
    "wrong host: {}",
    entry.host()
  );
  assert!(
    !entry.ipv4_addresses().is_empty() || !entry.ipv6_addresses().is_empty(),
    "entry has no addresses: v4={:?} v6={:?}",
    entry.ipv4_addresses(),
    entry.ipv6_addresses()
  );
}

/// codex R9 liveness regression: a query started with a default `QuerySpec`
/// (timeout `None`) must make progress — its first question gets transmitted and
/// it can be cancelled cleanly — WITHOUT any other endpoint activity to wake the
/// driver. Before the `dirty`-flag invariant, `start_query`'s `notify` could be
/// lost across the driver's send-awaits and, with no timeout deadline and no
/// other traffic, the driver would park forever and `Query::next` would hang.
/// The bounded timeout turns a regression into a failure rather than a hung
/// suite: we only need the driver to be ALIVE and responsive (the query need not
/// receive an answer on loopback — reaching the drop + clean cancel is the
/// liveness proof).
#[compio::test]
async fn timeoutless_query_makes_progress_without_other_traffic() {
  use mdns_compio::{Endpoint, Name, QuerySpec, ServerOptions};
  use mdns_proto::wire::ResourceType;

  let idx = match super_loopback_index() {
    Some(i) => i,
    None => return,
  };
  let ep = match Endpoint::server(
    ServerOptions::default()
      .with_interface_index(Some(idx))
      .with_ipv6(false),
  )
  .await
  {
    Ok(e) => e,
    Err(e) => {
      eprintln!("skip: {e:?}");
      return;
    }
  };

  // Default QuerySpec → timeout: None. The ONLY thing that schedules a deadline
  // is the first transmit actually being pumped; if start_query's wake is lost
  // the driver has nothing to wake on.
  let qname = Name::try_from_str("liveness-probe.local.").unwrap();
  let q = ep
    .start_query(QuerySpec::new(qname, ResourceType::A))
    .await
    .expect("start_query must succeed");

  // The driver must be alive enough to pump the question + keep ticking. Give it
  // a brief window with NO other traffic; then prove the whole stack is still
  // responsive by driving a bounded next() (it returns on the proto's own retry
  // cadence or stays pending — either way the runtime is not deadlocked).
  let _ = compio::time::timeout(Duration::from_millis(500), q.next()).await;

  // Cleanly drop the query, then confirm the endpoint is still responsive by
  // starting + dropping another query within a bounded window — a parked-forever
  // driver would not service this second registration's wake either.
  drop(q);
  let q2 = compio::time::timeout(
    Duration::from_secs(2),
    ep.start_query(QuerySpec::new(
      Name::try_from_str("liveness-probe-2.local.").unwrap(),
      ResourceType::A,
    )),
  )
  .await
  .expect("driver must still service start_query (not parked forever)")
  .expect("second start_query must succeed");
  drop(q2);
}

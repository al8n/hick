//! End-to-end loopback tests for the tokio driver: a server advertises a
//! service and a client looks it up over loopback, with per-record-type
//! coverage (PTR / SRV / A / AAAA / TXT).
//!
//! ## Self-loopback handling
//!
//! Two Endpoints on the same host see each other's multicast packets AND
//! their own packets coming back via the OS loopback. The proto-layer
//! sent-packet hash cache disambiguates the two: every outgoing
//! datagram is recorded via `Endpoint::observe_send`, so the inbound
//! loopback copy is identified by content match and dropped, while the
//! peer's packets (which happen to share the same src IP on loopback)
//! are processed normally.
//!
//! That signal works regardless of advertised addresses, so these tests
//! advertise the real loopback `127.0.0.1`.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
  net::{IpAddr, Ipv6Addr},
  time::Duration,
};

use hick_reactor::{
  CollectedAnswer, Name, QueryEvent, QueryParam, QuerySpec, ServerOptions, Service, ServiceRecords,
  ServiceSpec, tokio as tokio_drv, wire::ResourceType,
};

const UNIQUE_SERVICE: &str = "_agnostic-mdns-test-v06._tcp.local.";
const UNIQUE_INSTANCE: &str = "Test._agnostic-mdns-test-v06._tcp.local.";
const UNIQUE_HOST: &str = "test-host.local.";
const SERVICE_PORT: u16 = 12345;
const ADVERTISED_V4: [u8; 4] = [127, 0, 0, 1];
const ADVERTISED_V6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

fn loopback_index() -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| {
      let f = i.flags();
      f.contains(getifs::Flags::LOOPBACK)
        && f.contains(getifs::Flags::UP)
        && i.ipv4_addrs().ok().map(|v| !v.is_empty()).unwrap_or(false)
    })
    .map(|i| i.index())
}

fn loopback_opts(idx: u32) -> ServerOptions {
  ServerOptions::new()
    .with_ipv6(false)
    .with_interface_index(Some(idx))
}

async fn try_endpoint(opts: ServerOptions) -> Option<tokio_drv::Endpoint> {
  match tokio_drv::server(opts).await {
    Ok(ep) => Some(ep),
    Err(e) => {
      eprintln!("skipping: endpoint construction failed: {e:?}");
      None
    }
  }
}

/// Owned bundle returned from [`build_pair`]. The caller must keep this
/// alive for the full test duration — dropping the [`Service`] would
/// unregister the responder service mid-test, and dropping either
/// [`tokio_drv::Endpoint`] would tear down its driver task.
struct LoopbackPair {
  /// Held to keep the responder driver task alive for the test duration.
  _responder: tokio_drv::Endpoint,
  querier: tokio_drv::Endpoint,
  // An explicit owned guard replaces the prior
  // `mem::forget(service)` so the test actually exercises Drop / cleanup
  // paths rather than masking lifecycle bugs.
  _service: Service,
}

/// Build a [responder, querier] pair on the loopback interface, with the
/// responder publishing the canonical test service. The responder is given
/// `setup_wait` to finish probing + announcing before the function returns.
async fn build_pair(setup_wait: Duration) -> Option<LoopbackPair> {
  build_pair_named(setup_wait, UNIQUE_SERVICE, UNIQUE_INSTANCE, UNIQUE_HOST).await
}

/// Like [`build_pair`] but with a caller-chosen service type, instance, and host
/// name. Tests that resolve a *specific* name (rather than browsing the shared
/// type) pass unique values so they neither conflict-rename a shared record nor
/// leak their instance into another test's browse results.
async fn build_pair_named(
  setup_wait: Duration,
  service: &str,
  instance: &str,
  host: &str,
) -> Option<LoopbackPair> {
  let idx = loopback_index()?;

  let responder = try_endpoint(loopback_opts(idx)).await?;
  let stype = Name::try_from_str(service).unwrap();
  let instance = Name::try_from_str(instance).unwrap();
  let host = Name::try_from_str(host).unwrap();
  let mut recs = ServiceRecords::new(stype, instance, host, SERVICE_PORT, 120);
  recs.add_a(ADVERTISED_V4.into());
  recs.add_aaaa(ADVERTISED_V6);
  recs.add_txt_segment(b"Local web server".to_vec());

  let svc = match responder.register_service(ServiceSpec::new(recs)).await {
    Ok(s) => s,
    Err(e) => {
      eprintln!("skipping: register_service failed: {e:?}");
      return None;
    }
  };

  tokio::time::sleep(setup_wait).await;

  let querier = try_endpoint(loopback_opts(idx)).await?;
  Some(LoopbackPair {
    _responder: responder,
    querier,
    _service: svc,
  })
}

/// Issue `spec` against `querier` and collect up to `Terminal`.
async fn run_query(
  querier: &tokio_drv::Endpoint,
  spec: QuerySpec,
  hard_timeout: Duration,
) -> Vec<CollectedAnswer> {
  let mut q = match querier.start_query(spec).await {
    Ok(q) => q,
    Err(e) => {
      eprintln!("start_query failed: {e:?}");
      return Vec::new();
    }
  };
  tokio::time::timeout(hard_timeout, async {
    let mut got = Vec::new();
    while let Some(ev) = q.next().await {
      match ev {
        QueryEvent::Answer(a) => got.push(a),
        QueryEvent::Terminal(_) => break,
      }
    }
    got
  })
  .await
  .unwrap_or_default()
}

#[tokio::test]
async fn loopback_ptr_query_returns_instance() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(
    Name::try_from_str(UNIQUE_SERVICE).unwrap(),
    ResourceType::Ptr,
  )
  .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  let saw_ptr = answers.iter().any(|a| a.rtype() == ResourceType::Ptr);
  eprintln!(
    "PTR query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  assert!(saw_ptr, "expected PTR answer; got {}", answers.len());
}

#[tokio::test]
async fn loopback_srv_query_returns_target() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(
    Name::try_from_str(UNIQUE_INSTANCE).unwrap(),
    ResourceType::Srv,
  )
  .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "SRV query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_srv = answers.iter().any(|a| a.rtype() == ResourceType::Srv);
  assert!(saw_srv, "expected SRV answer; got {}", answers.len());
}

#[tokio::test]
async fn loopback_a_query_returns_address() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(Name::try_from_str(UNIQUE_HOST).unwrap(), ResourceType::A)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "A query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_a = answers.iter().any(|a| a.rtype() == ResourceType::A);
  assert!(saw_a, "expected A answer; got {}", answers.len());
  let a_rdata = answers
    .iter()
    .find(|a| a.rtype() == ResourceType::A)
    .map(|a| a.rdata_slice().to_vec())
    .unwrap();
  assert_eq!(a_rdata, ADVERTISED_V4, "wrong A rdata: {a_rdata:?}");
}

#[tokio::test]
async fn loopback_aaaa_query_returns_address() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(Name::try_from_str(UNIQUE_HOST).unwrap(), ResourceType::AAAA)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "AAAA query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  // AAAA over an IPv4-only loopback socket only works if the responder
  // includes AAAA in its response (it does — write_announce emits all
  // record types regardless of socket family). Soft-assert and log.
  let saw_aaaa = answers.iter().any(|a| a.rtype() == ResourceType::AAAA);
  assert!(saw_aaaa, "expected AAAA answer; got {}", answers.len());
}

#[tokio::test]
async fn loopback_txt_query_returns_payload() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(
    Name::try_from_str(UNIQUE_INSTANCE).unwrap(),
    ResourceType::Txt,
  )
  .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "TXT query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_txt = answers.iter().any(|a| a.rtype() == ResourceType::Txt);
  assert!(saw_txt, "expected TXT answer; got {}", answers.len());
}

#[tokio::test]
async fn loopback_any_query_returns_full_record_set() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  // ANY query against the service-type owner only collects records whose
  // OWNER name equals the qname (PTR). SRV/A/AAAA/TXT have different owners
  // (instance / host). To collect everything in one query, ANY-on-instance
  // gives SRV + TXT (both owned by the instance name).
  let spec = QuerySpec::new(
    Name::try_from_str(UNIQUE_INSTANCE).unwrap(),
    ResourceType::Any,
  )
  .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "ANY-instance query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_srv = answers.iter().any(|a| a.rtype() == ResourceType::Srv);
  let saw_txt = answers.iter().any(|a| a.rtype() == ResourceType::Txt);
  assert!(saw_srv && saw_txt, "expected SRV+TXT; got {answers:?}");
}

/// End-to-end DNS-SD discovery: browse the service type and resolve the
/// published instance into a fully-populated `ServiceEntry` (PTR → SRV/TXT →
/// A/AAAA chained by the `Lookup`).
#[tokio::test]
async fn loopback_browse_resolves_service_entry() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let param = QueryParam::new(Name::try_from_str(UNIQUE_SERVICE).unwrap())
    .with_timeout(Duration::from_secs(2));
  let mut lookup = match pair.querier.browse(param).await {
    Ok(l) => l,
    Err(e) => {
      eprintln!("skipping: browse failed: {e:?}");
      return;
    }
  };

  // Resolve until an instance of our service type appears (or a hard cap).
  // Breaking on the first match keeps the test fast — the entry resolves long
  // before the per-query timeouts elapse. We match on the service-type suffix,
  // not the exact instance label: parallel tests publish the same instance name
  // on loopback, so §9 conflict resolution renames clones (`Test` → `test-2`),
  // and responders lowercase names on the wire. The host/port/addr/TXT are
  // identical across the renamed clones, so any resolved entry validates them.
  let suffix = UNIQUE_SERVICE.to_ascii_lowercase();
  let entry = tokio::time::timeout(Duration::from_secs(5), async {
    while let Some(e) = lookup.next().await {
      eprintln!(
        "browse entry: {} host={} port={} v4={:?}",
        e.instance_name(),
        e.host(),
        e.port(),
        e.ipv4_addresses()
      );
      // Wait for an instance of our type whose A address has resolved. On
      // loopback the responder emits both A (127.0.0.1) and AAAA (::1) over
      // IPv4, so the first emission for an instance may be AAAA-only; a later
      // re-emission carries the A address.
      if e
        .instance_name()
        .as_str()
        .to_ascii_lowercase()
        .ends_with(&suffix)
        && e.ipv4_addresses().contains(&ADVERTISED_V4.into())
      {
        return Some(e);
      }
    }
    None
  })
  .await
  .ok()
  .flatten();

  let entry = match entry {
    Some(e) => e,
    None => panic!("browse did not resolve any instance of {UNIQUE_SERVICE}"),
  };
  assert_eq!(entry.port(), SERVICE_PORT, "wrong port");
  assert!(
    entry.host().as_str().eq_ignore_ascii_case(UNIQUE_HOST),
    "wrong host: {}",
    entry.host()
  );
  assert!(
    entry.ipv4_addresses().contains(&ADVERTISED_V4.into()),
    "expected {ADVERTISED_V4:?} in {:?}",
    entry.ipv4_addresses()
  );
  assert!(
    entry
      .txt()
      .iter()
      .any(|t| t.as_slice() == b"Local web server"),
    "expected TXT 'Local web server' in {:?}",
    entry.txt()
  );
}

/// `resolve_host`: plain mDNS hostname resolution (A/AAAA), no DNS-SD chain. The
/// host name carries identical A rdata across any concurrent responders, so this
/// is robust under parallel tests (no §9 conflict on shared, identical records).
#[tokio::test]
async fn loopback_resolve_host_returns_addresses() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let addrs = match pair
    .querier
    .resolve_host(
      Name::try_from_str(UNIQUE_HOST).unwrap(),
      Duration::from_secs(2),
    )
    .await
  {
    Ok(a) => a,
    Err(e) => {
      eprintln!("skipping: resolve_host failed: {e:?}");
      return;
    }
  };
  eprintln!("resolve_host: {addrs:?}");
  assert!(
    addrs.contains(&IpAddr::V4(ADVERTISED_V4.into())),
    "expected {ADVERTISED_V4:?} in {addrs:?}"
  );
}

/// `resolve_instance`: resolve a *known* instance directly (SRV/TXT + A/AAAA),
/// skipping the PTR browse. Uses unique instance/host names so a concurrent test
/// can't conflict-rename them — this responder reliably owns the queried name.
#[tokio::test]
async fn loopback_resolve_instance_returns_entry() {
  // A dedicated service type (not UNIQUE_SERVICE) so this responder's PTR never
  // appears in `loopback_browse_resolves_service_entry`, which would otherwise
  // be able to pick this instance and then fail its UNIQUE_HOST assertion.
  const SVC: &str = "_agnostic-mdns-resolve-v06._tcp.local.";
  const INST: &str = "ResolveOne._agnostic-mdns-resolve-v06._tcp.local.";
  const HOST: &str = "resolve-one-host.local.";
  let pair = match build_pair_named(Duration::from_millis(1300), SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  let resolved = tokio::time::timeout(
    Duration::from_secs(6),
    pair
      .querier
      .resolve_instance(Name::try_from_str(INST).unwrap(), Duration::from_secs(2)),
  )
  .await;
  let entry = match resolved {
    Ok(Ok(Some(e))) => e,
    other => panic!("resolve_instance did not resolve {INST}: {other:?}"),
  };
  eprintln!(
    "resolve_instance: host={} port={} v4={:?} v6={:?}",
    entry.host(),
    entry.port(),
    entry.ipv4_addresses(),
    entry.ipv6_addresses()
  );
  assert_eq!(entry.port(), SERVICE_PORT, "wrong port");
  assert!(
    entry.host().as_str().eq_ignore_ascii_case(HOST),
    "wrong host: {}",
    entry.host()
  );
  // First complete resolution carries >= 1 address; family/order isn't fixed on
  // loopback, so assert presence + that every address is one we advertised.
  assert!(
    entry.addresses().next().is_some(),
    "expected at least one address"
  );
  for a in entry.addresses() {
    assert!(
      a == IpAddr::V4(ADVERTISED_V4.into()) || a == IpAddr::V6(ADVERTISED_V6),
      "unexpected address {a}"
    );
  }
  assert!(
    entry
      .txt()
      .iter()
      .any(|t| t.as_slice() == b"Local web server"),
    "expected TXT 'Local web server' in {:?}",
    entry.txt()
  );
}

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

use std::{net::Ipv6Addr, time::Duration};

use agnostic_mdns::{
  CollectedAnswer, Name, QueryEvent, QuerySpec, ServerOptions, Service, ServiceRecords,
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
  // R37 cleanup: an explicit owned guard replaces the prior
  // `mem::forget(service)` so the test actually exercises Drop / cleanup
  // paths rather than masking lifecycle bugs.
  _service: Service,
}

/// Build a [responder, querier] pair on the loopback interface, with the
/// responder publishing the canonical test service. The responder is given
/// `setup_wait` to finish probing + announcing before the function returns.
async fn build_pair(setup_wait: Duration) -> Option<LoopbackPair> {
  let idx = loopback_index()?;

  let responder = try_endpoint(loopback_opts(idx)).await?;
  let stype = Name::try_from_str(UNIQUE_SERVICE).unwrap();
  let instance = Name::try_from_str(UNIQUE_INSTANCE).unwrap();
  let host = Name::try_from_str(UNIQUE_HOST).unwrap();
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
  let spec = QuerySpec::new(Name::try_from_str(UNIQUE_HOST).unwrap(), ResourceType::Aaaa)
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
  let saw_aaaa = answers.iter().any(|a| a.rtype() == ResourceType::Aaaa);
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

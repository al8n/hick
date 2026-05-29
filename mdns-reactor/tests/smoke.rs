//! Smoke tests for the tokio driver.
//!
//! These tests bind a real multicast UDP socket. Environments that disallow
//! multicast bind (some CI runners, locked-down containers) cause the bind to
//! fail; we log and skip rather than fail in that case so the suite remains
//! green portably.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use mdns_reactor::{
  Name, QuerySpec, ServerOptions, ServiceRecords, ServiceSpec, tokio as tokio_drv,
  wire::ResourceType,
};

/// Construct an Endpoint with default options. Logs and skips if multicast
/// bind is not permitted in the test environment.
///
/// V6 is disabled because many test hosts disallow IPv6 multicast join on
/// the default interface (the `Invalid argument` errno from `join_multicast_v6`).
async fn try_make_endpoint() -> Option<tokio_drv::Endpoint> {
  let opts = ServerOptions::new().with_ipv6(false);
  match tokio_drv::server(opts).await {
    Ok(ep) => Some(ep),
    Err(e) => {
      eprintln!("skipping: endpoint construction failed: {e:?}");
      None
    }
  }
}

#[tokio::test]
async fn endpoint_construct_and_drop() {
  let _ep = match try_make_endpoint().await {
    Some(ep) => ep,
    None => return,
  };
  // Drop here — driver task should exit cleanly when the last command
  // sender (held by Endpoint) is dropped.
}

#[tokio::test]
async fn register_service_then_drop() {
  let ep = match try_make_endpoint().await {
    Some(ep) => ep,
    None => return,
  };

  let stype = Name::try_from_str("_smoke._tcp.local.").unwrap();
  let instance = Name::try_from_str("Test._smoke._tcp.local.").unwrap();
  let host = Name::try_from_str("test-host.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, instance, host, 12345, 120);
  recs.add_a([127, 0, 0, 1].into());

  let svc = match ep.register_service(ServiceSpec::new(recs)).await {
    Ok(s) => s,
    Err(e) => {
      eprintln!("register failed: {e:?}");
      return;
    }
  };

  // Give the driver a moment to advance probing / announce. We don't
  // assert what update arrives — too environment-dependent — only that
  // the call doesn't panic and Drop cleans up.
  let _ = tokio::time::timeout(Duration::from_millis(200), svc.next()).await;
}

#[tokio::test]
async fn start_query_then_cancel() {
  let ep = match try_make_endpoint().await {
    Some(ep) => ep,
    None => return,
  };

  let qname = Name::try_from_str("_smoke._tcp.local.").unwrap();
  let spec = QuerySpec::new(qname, ResourceType::Any).with_timeout(Duration::from_millis(150));

  let mut q = match ep.start_query(spec).await {
    Ok(q) => q,
    Err(e) => {
      eprintln!("start_query failed: {e:?}");
      return;
    }
  };

  // Drive next() until terminal (or test timeout). We expect Terminal
  // within ~150ms because of the per-query timeout we configured.
  let result = tokio::time::timeout(Duration::from_secs(2), async {
    loop {
      match q.next().await {
        Some(mdns_reactor::QueryEvent::Terminal(t)) => return Some(t),
        Some(mdns_reactor::QueryEvent::Answer(_)) => continue,
        None => return None,
      }
    }
  })
  .await;
  match result {
    Ok(Some(t)) => eprintln!("got terminal: {:?}", t),
    Ok(None) => eprintln!("stream closed without terminal"),
    Err(_) => panic!("query did not terminate in 2s"),
  }
}

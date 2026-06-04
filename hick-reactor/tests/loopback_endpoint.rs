//! End-to-end driver tests over a real loopback multicast socket.
//!
//! These bind actual UDP sockets on the loopback interface and spin the tokio
//! driver task, exercising the bind → spawn → select → send/recv → shutdown
//! paths that the in-process unit tests (which pass `v4: None, v6: None`)
//! cannot reach. Every test skips gracefully when the environment forbids a
//! multicast bind (some CI sandboxes), so they never produce a false failure.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{net::Ipv4Addr, time::Duration};

use hick_reactor::{
  Endpoint, Name, QueryEvent, QuerySpec, ServerOptions, ServiceRecords, ServiceSpec, ServiceUpdate,
  wire::ResourceType,
};

/// The loopback interface index, or `None` if it can't be resolved.
fn loopback_index() -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| i.flags().contains(getifs::Flags::LOOPBACK))
    .map(|i| i.index())
}

/// A `_http._tcp` service advertised on 127.0.0.1.
fn http_service(instance: &str) -> ServiceSpec {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_http._tcp.local.").unwrap(),
    Name::try_from_str(&format!("{instance}._http._tcp.local.")).unwrap(),
    Name::try_from_str(&format!("{instance}.local.")).unwrap(),
    80,
    120,
  );
  recs.add_a(Ipv4Addr::new(127, 0, 0, 1));
  ServiceSpec::new(recs)
}

/// Bind a v4-only endpoint pinned to loopback, or `None` to skip the test when
/// the environment refuses the multicast bind.
async fn loopback_v4_endpoint() -> Option<Endpoint> {
  let idx = loopback_index()?;
  let opts = ServerOptions::default()
    .with_interface_index(Some(idx))
    .with_ipv6(false);
  match hick_reactor::tokio::server(opts).await {
    Ok(ep) => Some(ep),
    Err(e) => {
      eprintln!("loopback multicast bind unavailable ({e}); skipping");
      None
    }
  }
}

/// A registered service must complete probing and reach `Established` (or, if
/// the looped-back probe is treated as a simultaneous-probe tiebreak, `Renamed`
/// — both mean the service finished probing and is now advertised). Probing is
/// timer-driven, so this resolves without depending on cross-socket delivery.
#[tokio::test]
async fn registered_service_reaches_advertised_state() {
  let Some(ep) = loopback_v4_endpoint().await else {
    return;
  };
  let svc = ep.register_service(http_service("alpha")).await.unwrap();

  match tokio::time::timeout(Duration::from_secs(10), svc.next()).await {
    Ok(Some(ServiceUpdate::Established)) => {}
    Ok(Some(ServiceUpdate::Renamed(_))) => {}
    Ok(Some(other)) => panic!("service failed to advertise: {other:?}"),
    Ok(None) => panic!("service update channel closed before the service advertised"),
    Err(_) => panic!("timed out waiting for the service to finish probing"),
  }
}

/// Two endpoints on the loopback group: one advertises a service, the other
/// browses for it. Cross-socket multicast delivery on loopback is environment
/// dependent, so a missed answer is tolerated — but the full send path on the
/// server and the full recv/parse path on the client are driven either way.
#[tokio::test]
async fn browse_drives_both_run_loops() {
  let Some(server) = loopback_v4_endpoint().await else {
    return;
  };
  let Some(client) = loopback_v4_endpoint().await else {
    return;
  };

  let _svc = server.register_service(http_service("beta")).await.unwrap();
  let mut query = client
    .start_query(QuerySpec::new(
      Name::try_from_str("_http._tcp.local.").unwrap(),
      ResourceType::Ptr,
    ))
    .await
    .unwrap();

  match tokio::time::timeout(Duration::from_secs(8), query.next()).await {
    Ok(Some(QueryEvent::Answer(a))) => {
      // If the datagram crossed, it must be a well-formed PTR answer.
      assert_eq!(a.rtype(), ResourceType::Ptr);
    }
    Ok(Some(QueryEvent::Terminal(_))) | Ok(None) | Err(_) => {
      eprintln!("no cross-socket loopback delivery here; run loops still exercised");
    }
  }
  // The browse query buffered no answers beyond the backlog cap.
  assert_eq!(query.dropped_answers(), 0);
}

/// Drive the explicit teardown paths: `Query::cancel` and `Service::unregister`
/// both round-trip a command to the live driver, and the trailing `Drop` impls
/// fire a second (tolerated) teardown command on scope exit.
#[tokio::test]
async fn cancel_query_and_unregister_service() {
  let Some(ep) = loopback_v4_endpoint().await else {
    return;
  };

  let query = ep
    .start_query(QuerySpec::new(
      Name::try_from_str("_absent._tcp.local.").unwrap(),
      ResourceType::Ptr,
    ))
    .await
    .unwrap();
  query.cancel().await.expect("driver still running");

  let svc = ep.register_service(http_service("gamma")).await.unwrap();
  svc.unregister().await.expect("driver still running");
}

/// `server` with neither family enabled must fail fast with `NoFamilyEnabled`,
/// before any socket bind is attempted.
#[tokio::test]
async fn server_rejects_no_family_enabled() {
  let opts = ServerOptions::default().with_ipv4(false).with_ipv6(false);
  match hick_reactor::tokio::server(opts).await {
    Err(hick_reactor::ServerError::NoFamilyEnabled) => {}
    Err(e) => panic!("expected NoFamilyEnabled, got {e:?}"),
    Ok(_) => panic!("expected NoFamilyEnabled, but server() succeeded"),
  }
}

/// A dual-stack endpoint pinned to loopback drives the IPv6 setup path: either
/// the dual bind succeeds, or v6 multicast on loopback is unsupported here and
/// the v6 leg surfaces a `BindV6` error (reactor folds join failures into it).
/// Either outcome exercises the v6 bind/join code the v4-only tests skip.
#[tokio::test]
async fn dual_stack_loopback_exercises_v6_setup() {
  let Some(idx) = loopback_index() else {
    return;
  };
  let opts = ServerOptions::default().with_interface_index(Some(idx));
  match hick_reactor::tokio::server(opts).await {
    Ok(_ep) => {}
    Err(hick_reactor::ServerError::BindV6(_)) => {}
    Err(e) => panic!("unexpected dual-stack setup error: {e:?}"),
  }
}

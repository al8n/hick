//! End-to-end driver tests over a real loopback multicast socket.
//!
//! These bind actual UDP sockets on the loopback interface and spin the compio
//! driver task, exercising the bind → spawn → poll → send/recv → shutdown paths
//! that the in-process unit tests (which drive the `State` directly) cannot
//! reach.
//!
//! Endpoint construction goes through [`common::loopback_v4_endpoint`] /
//! [`common::resolved_loopback_index`], which skip only when an independent
//! control socket was refused the exact same way — see `tests/common/mod.rs`
//! for why an uncorroborated skip here used to report a false "all tests
//! passed" under a forced `PermissionDenied` bind failure.

#![cfg(any(unix, windows))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use hick_compio::{
  Name, QueryEvent, QuerySpec, ServerOptions, ServiceRecords, ServiceSpec, ServiceUpdate,
  wire::ResourceType,
};

/// A `_http._tcp` service advertised on 127.0.0.1.
fn http_service(instance: &str) -> ServiceSpec {
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_http._tcp.local.").unwrap(),
    Name::try_from_str(&format!("{instance}._http._tcp.local.")).unwrap(),
    Name::try_from_str(&format!("{instance}.local.")).unwrap(),
    80,
    120,
  );
  recs.add_a(std::net::Ipv4Addr::new(127, 0, 0, 1));
  ServiceSpec::new(recs)
}

/// A registered service must complete probing and reach `Established` (or
/// `Renamed` if a looped-back probe triggers the simultaneous-probe tiebreak —
/// both mean probing finished and the service is advertised). Probing is
/// timer-driven, so this resolves without depending on cross-socket delivery.
#[compio::test]
async fn registered_service_reaches_advertised_state() {
  let Some(ep) = common::loopback_v4_endpoint().await else {
    return;
  };
  let svc = ep.register_service(http_service("alpha")).await.unwrap();

  match compio::time::timeout(Duration::from_secs(10), svc.next()).await {
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
#[compio::test]
async fn browse_drives_both_run_loops() {
  let Some(server) = common::loopback_v4_endpoint().await else {
    return;
  };
  let Some(client) = common::loopback_v4_endpoint().await else {
    return;
  };

  let _svc = server.register_service(http_service("beta")).await.unwrap();
  let query = client
    .start_query(QuerySpec::new(
      Name::try_from_str("_http._tcp.local.").unwrap(),
      ResourceType::Ptr,
    ))
    .await
    .unwrap();

  match compio::time::timeout(Duration::from_secs(8), query.next()).await {
    Ok(Some(QueryEvent::Answer(a))) => {
      assert_eq!(a.rtype(), ResourceType::Ptr);
    }
    Ok(Some(QueryEvent::Terminal(_))) | Ok(None) | Err(_) => {
      eprintln!("no cross-socket loopback delivery here; run loops still exercised");
    }
  }
  // The query handle stays valid for the life of the browse.
  let _ = query.handle();
}

/// Drive the teardown paths: dropping a `Query` / `Service` fires its `Drop`
/// impl, which sends the cancel / unregister command to the live driver. A
/// short tick lets the driver process them before the endpoint shuts down.
#[compio::test]
async fn dropping_handles_tears_down_via_driver() {
  let Some(ep) = common::loopback_v4_endpoint().await else {
    return;
  };

  let query = ep
    .start_query(QuerySpec::new(
      Name::try_from_str("_absent._tcp.local.").unwrap(),
      ResourceType::Ptr,
    ))
    .await
    .unwrap();
  let _ = query.handle();
  drop(query); // Drop -> CancelQuery command to the driver.

  let svc = ep.register_service(http_service("gamma")).await.unwrap();
  let _ = svc.handle();
  drop(svc); // Drop -> UnregisterService command to the driver.

  compio::time::sleep(Duration::from_millis(50)).await;
}

/// `server` with neither family enabled must fail fast with `NoFamilyEnabled`,
/// before any socket bind is attempted.
#[compio::test]
async fn server_rejects_no_family_enabled() {
  let opts = ServerOptions::default().with_ipv4(false).with_ipv6(false);
  match hick_compio::Endpoint::server(opts).await {
    Err(hick_compio::ServerError::NoFamilyEnabled) => {}
    Err(e) => panic!("expected NoFamilyEnabled, got {e:?}"),
    Ok(_) => panic!("expected NoFamilyEnabled, but server() succeeded"),
  }
}

/// A dual-stack endpoint pinned to loopback drives the IPv6 setup path: either
/// the dual bind succeeds, or v6 multicast on loopback is unsupported here and
/// the v6 leg surfaces a `BindV6` / `JoinV6` error. Either outcome exercises the
/// v6 bind/join code the v4-only tests skip.
#[compio::test]
async fn dual_stack_loopback_exercises_v6_setup() {
  let Some(idx) = common::resolved_loopback_index().await else {
    return;
  };
  let opts = ServerOptions::default().with_interface_index(Some(idx));
  match hick_compio::Endpoint::server(opts).await {
    Ok(_ep) => {}
    Err(hick_compio::ServerError::BindV6(_) | hick_compio::ServerError::JoinV6(_)) => {}
    Err(e) => panic!("unexpected dual-stack setup error: {e:?}"),
  }
}

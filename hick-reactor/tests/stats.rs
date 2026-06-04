//! Stats integration test for the `hick-reactor` driver.
//!
//! Binds a real loopback multicast socket, registers a service (which drives
//! probing transmits), and asserts that `Endpoint::stats()` shows
//! `packets_tx > 0` after the service has had time to send at least one probe
//! packet. The test self-skips gracefully when the multicast bind is
//! unavailable (some CI sandboxes prohibit it).

#![cfg(all(feature = "stats", feature = "tokio"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{net::Ipv4Addr, time::Duration};

use hick_reactor::{Name, ServerOptions, ServiceRecords, ServiceSpec};

/// Return the loopback interface index, or `None` if unavailable.
fn loopback_index() -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| i.flags().contains(getifs::Flags::LOOPBACK))
    .map(|i| i.index())
}

/// Construct a v4-only endpoint pinned to loopback, or `None` to skip.
async fn loopback_v4_endpoint() -> Option<hick_reactor::Endpoint> {
  let idx = loopback_index()?;
  let opts = ServerOptions::default()
    .with_interface_index(Some(idx))
    .with_ipv6(false);
  match hick_reactor::tokio::server(opts).await {
    Ok(ep) => Some(ep),
    Err(e) => {
      eprintln!("loopback multicast bind unavailable ({e}); skipping stats test");
      None
    }
  }
}

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

/// After registering a service and allowing the driver to run for a short
/// interval, the `packets_tx` counter (probe datagrams sent) must be > 0.
///
/// `services_registered` must also be >= 1 — this is set synchronously by
/// the proto layer during registration and does not depend on socket delivery.
#[tokio::test]
async fn stats_packets_tx_after_service_probing() {
  let Some(ep) = loopback_v4_endpoint().await else {
    return;
  };

  // Assert services_registered is 0 before we do anything.
  let snap_before = ep.stats();
  assert_eq!(
    snap_before.services_registered, 0,
    "fresh endpoint must have services_registered = 0"
  );

  let svc = ep
    .register_service(http_service("stats-probe"))
    .await
    .unwrap();

  // Give the driver enough time to advance through the 0–250 ms probe delay
  // and emit at least one probe datagram on the wire.
  let _ = tokio::time::timeout(Duration::from_secs(3), svc.next()).await;

  let snap = ep.stats();

  // The proto layer increments services_registered synchronously during
  // register_service, so this must be >= 1 regardless of socket state.
  assert!(
    snap.services_registered >= 1,
    "services_registered must be >= 1 after registering; got {}",
    snap.services_registered
  );

  // The driver increments packets_tx whenever it successfully sends a probe
  // or announcement via the multicast socket. Allow zero only when the
  // multicast socket is loopback-only and the delivery was suppressed — but
  // on a real loopback socket a probe IS sent, so we assert > 0 here.
  // (On the rare CI runner that refuses multicast delivery we'd have skipped
  // above in loopback_v4_endpoint, so this branch is intentional.)
  assert!(
    snap.packets_tx > 0,
    "packets_tx must be > 0 after probe send; got {} (services_registered={})",
    snap.packets_tx,
    snap.services_registered,
  );
}

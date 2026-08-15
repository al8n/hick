//! End-to-end driver tests over a real loopback multicast socket.
//!
//! These bind actual UDP sockets on the loopback interface and spin the tokio
//! driver task, exercising the bind → spawn → select → send/recv → shutdown
//! paths that the in-process unit tests (which pass `v4: None, v6: None`)
//! cannot reach.
//!
//! # Every skip is corroborated
//!
//! `loopback_index()` and `loopback_v4_endpoint()` used to fold every failure —
//! `getifs::interfaces()` refused, `hick_reactor::tokio::server()` refused —
//! into an uncorroborated `None`, and every caller returned successfully on
//! `None`. That shape reports a false "all tests passed" the moment either call
//! starts failing for a real reason: forcing `hick_udp::try_bind_v4` to return
//! `PermissionDenied` used to leave this whole file green.
//!
//! `hick-reactor/tests/loopback_lookup.rs` already worked out the fix for this
//! crate (see its `only_a_corroborated_environment_may_skip` / `is_environmental`
//! / `control_prerequisites`): a skip is legitimate only when an INDEPENDENT
//! control — a socket that shares none of `hick_reactor`'s own bind/join code —
//! was refused the exact same `io::ErrorKind`. Anything else is this crate's own
//! bug and must fail loudly. That shape is ported here rather than reinvented;
//! see the control block below for the reasoning in full. There is no shared
//! test-support crate for integration tests to pull this from, so the control
//! helpers are duplicated verbatim rather than imported — the same duplication
//! `loopback_lookup.rs`'s own doc comments call out.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{net::Ipv4Addr, time::Duration};

use hick_reactor::{
  Endpoint, Name, QueryEvent, QuerySpec, ServerError, ServerOptions, ServiceRecords, ServiceSpec,
  ServiceUpdate, wire::ResourceType,
};

/// The index of an UP loopback interface, or `Ok(None)` if this host genuinely
/// has none. `Err` is preserved with its real `io::ErrorKind` rather than
/// flattened into `None` — see [`only_an_absent_loopback_may_skip`] /
/// [`only_a_corroborated_environment_may_skip`] for why the distinction matters.
fn loopback_index() -> Result<Option<u32>, std::io::Error> {
  for i in getifs::interfaces()?.iter() {
    if i.flags().contains(getifs::Flags::LOOPBACK) {
      return Ok(Some(i.index()));
    }
  }
  Ok(None)
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

/// Resolve the loopback interface and hand the outcome to the corroboration
/// gates, or return `Some(idx)` to use.
async fn resolved_loopback_index() -> Option<u32> {
  match loopback_index() {
    Ok(Some(idx)) => Some(idx),
    Ok(None) => {
      only_an_absent_loopback_may_skip(
        "interface enumeration succeeded and found no UP loopback interface",
      );
      None
    }
    Err(e) => {
      let kind = e.kind();
      only_a_corroborated_environment_may_skip(
        &format!("interface enumeration failed: {e:?}"),
        is_environmental(kind).then_some(kind),
      );
      None
    }
  }
}

/// Bind a v4-only endpoint pinned to loopback, or `None` — after a corroborated
/// skip, or a panic if nothing corroborates it — when the environment refuses
/// the multicast bind.
async fn loopback_v4_endpoint() -> Option<Endpoint> {
  let idx = resolved_loopback_index().await?;
  let opts = ServerOptions::default()
    .with_interface_index(Some(idx))
    .with_ipv6(false);
  match hick_reactor::tokio::server(opts).await {
    Ok(ep) => Some(ep),
    Err(e) => {
      let kind = server_error_kind(&e);
      only_a_corroborated_environment_may_skip(
        &format!("loopback multicast bind unavailable: {e:?}"),
        kind,
      );
      None
    }
  }
}

/// A registered service must complete probing and reach `Established`, or
/// report `Renamed` if a looped-back probe is treated as a simultaneous-probe
/// tiebreak.
///
/// `Renamed` does NOT mean the service is advertised — it is emitted at the
/// rename DECISION, which sends the service back to `Init` to probe the new
/// label from scratch (`mdns-proto`'s
/// `renamed_update_means_probing_restarted_not_advertised` pins that). It is
/// accepted here only as evidence that the lifecycle ran, and nothing below
/// depends on the service actually being advertised. A caller that needs
/// "advertised" must wait for `Established`, the way
/// `hick-mio/tests/loopback.rs`'s `advertise` helper does.
///
/// Probing is timer-driven, so this resolves without depending on cross-socket
/// delivery.
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
  let Some(idx) = resolved_loopback_index().await else {
    return;
  };
  let opts = ServerOptions::default().with_interface_index(Some(idx));
  match hick_reactor::tokio::server(opts).await {
    Ok(_ep) => {}
    Err(hick_reactor::ServerError::BindV6(_)) => {}
    Err(e) => panic!("unexpected dual-stack setup error: {e:?}"),
  }
}

// ── the independent control ────────────────────────────────────────────────
//
// Ported from `hick-reactor/tests/loopback_lookup.rs` (not modified by this
// file) rather than reinvented. Duplicated, not shared, because there is no
// test-support crate for two integration-test BINARIES in the same crate to
// pull common code from.
//
// The rule: **a skip requires an independent control that failed the SAME way,
// and a control that SUCCEEDS turns any failure back into a regression.**
// Without the first half, a product defect reads as a hostile environment;
// without the second, a hostile environment reads as a product defect.

/// The mDNS multicast group. Restated here, deliberately, rather than imported
/// from hick — this control must not be able to inherit a defect in hick's own
/// constant.
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The mDNS port. Restated for the same reason as [`MDNS_GROUP`].
const MDNS_PORT: u16 = 5353;

/// Every [`std::io::ErrorKind`] this file reads as a fact about the HOST rather
/// than about hick. Closed and deliberately not a catch-all — see
/// `loopback_lookup.rs`'s own copy of this allowlist for the per-kind reasoning.
fn is_environmental(kind: std::io::ErrorKind) -> bool {
  matches!(
    kind,
    std::io::ErrorKind::PermissionDenied
      | std::io::ErrorKind::AddrInUse
      | std::io::ErrorKind::AddrNotAvailable
      | std::io::ErrorKind::Unsupported
      | std::io::ErrorKind::NetworkDown
      | std::io::ErrorKind::NetworkUnreachable
      | std::io::ErrorKind::HostUnreachable
  )
}

/// The `io::ErrorKind` behind a [`hick_udp::BindError`], where one exists and
/// the environment could have produced it. `None` means "not an environment
/// fact" — including the two read-back variants, which mean the kernel ACCEPTED
/// a `setsockopt` and then silently did not honour it, and which no environment
/// produces.
fn bind_error_kind(e: &hick_udp::BindError) -> Option<std::io::ErrorKind> {
  match e {
    hick_udp::BindError::Io(io) => Some(io.kind()),
    hick_udp::BindError::InterfaceNotFound(_) => Some(std::io::ErrorKind::AddrNotAvailable),
    _ => None,
  }
}

/// The `io::ErrorKind` behind a [`ServerError`], where one exists and the
/// environment could have produced it. `None` is a hard failure.
fn server_error_kind(e: &ServerError) -> Option<std::io::ErrorKind> {
  let kind = match e {
    ServerError::BindV4(b) | ServerError::BindV6(b) => bind_error_kind(b)?,
    ServerError::WrapSocket(io) | ServerError::Io(io) => io.kind(),
    // `NoFamilyEnabled` is a caller choosing both families off, which this file
    // never does when it wants an endpoint. Anything added to this
    // `#[non_exhaustive]` enum later must be classified deliberately rather than
    // inherited as "environment".
    _ => return None,
  };
  is_environmental(kind).then_some(kind)
}

/// What the control could establish about the host's willingness to let a
/// process do what an endpoint does.
#[derive(Debug)]
enum Prerequisites {
  /// Every call an endpoint needs succeeded on a socket that is not hick's.
  Available,
  /// The kernel refused the control with an environmental error kind.
  Refused(std::io::ErrorKind, String),
}

/// Attempt an endpoint's own prerequisites on an independent socket: a UDP
/// socket, `SO_REUSEADDR` (+ `SO_REUSEPORT` where it exists), a bind on
/// `0.0.0.0:5353`, and the mDNS group joined on the loopback interface.
///
/// A refusal whose kind is NOT in [`is_environmental`] panics rather than being
/// reported: it describes this control's own call, and a broken control must
/// never be readable as evidence about the host.
fn control_prerequisites() -> Prerequisites {
  use socket2::{Domain, Protocol, Socket, Type};

  let refused = |stage: &str, e: &std::io::Error| -> Prerequisites {
    let kind = e.kind();
    assert!(
      is_environmental(kind),
      "the independent control could not {stage} ({e}), and {kind:?} is not a kind this host \
       could have produced on its own — that is a bug in this test file, which must never be \
       readable as evidence about the environment"
    );
    Prerequisites::Refused(kind, format!("{stage}: {e}"))
  };

  let sock = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
    Ok(s) => s,
    Err(e) => return refused("open a UDP socket", &e),
  };
  if let Err(e) = sock.set_reuse_address(true) {
    return refused("set SO_REUSEADDR", &e);
  }
  #[cfg(unix)]
  if let Err(e) = sock.set_reuse_port(true) {
    return refused("set SO_REUSEPORT", &e);
  }
  let bind_addr: std::net::SocketAddr = (Ipv4Addr::UNSPECIFIED, MDNS_PORT).into();
  if let Err(e) = sock.bind(&bind_addr.into()) {
    return refused("bind 0.0.0.0:5353", &e);
  }
  if let Err(e) = sock.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::LOCALHOST) {
    return refused("join the mDNS group on loopback", &e);
  }
  Prerequisites::Available
}

/// A FAILED operation may be skipped over only when its error kind is one the
/// environment can produce AND an independent control was refused THE SAME WAY.
///
/// `what` names the operation. `kind` is `None` when nothing about the error
/// says "environment" — which panics unconditionally, since there is nothing
/// about the host to blame.
#[track_caller]
fn only_a_corroborated_environment_may_skip(what: &str, kind: Option<std::io::ErrorKind>) {
  let Some(kind) = kind else {
    panic!(
      "{what} — and that is not a failure any environment produces, so there is nothing about \
       this host to blame for it"
    );
  };
  match control_prerequisites() {
    Prerequisites::Available => panic!(
      "{what} — but an independent control socket opened, took the reuse options, bound \
       0.0.0.0:{MDNS_PORT} and joined the mDNS group on loopback without complaint. This host \
       permits exactly what the operation above failed at, so that failure is a regression, not \
       an environment."
    ),
    Prerequisites::Refused(control_kind, reason) if control_kind != kind => panic!(
      "{what} — the independent control was refused too, but with {control_kind:?} ({reason}) \
       rather than {kind:?}. A skip has to be corroborated by a control that failed the SAME \
       way; two different refusals are two different facts."
    ),
    Prerequisites::Refused(_, reason) => eprintln!(
      "skipping: {what}; an independent control socket was refused the same way ({reason})"
    ),
  }
}

/// Whether an independent socket can bind `127.0.0.1`, asked directly — the
/// same question `loopback_index()`'s enumeration was answering.
fn control_loopback_present() -> bool {
  match std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
    Ok(_) => true,
    Err(e) if is_environmental(e.kind()) => {
      eprintln!("note: an independent control could not bind 127.0.0.1 either ({e})");
      false
    }
    Err(e) => panic!(
      "the independent control could not bind 127.0.0.1 ({e}), and {:?} is not a kind this \
       host could have produced on its own — that is a bug in this test file, which must never \
       be readable as evidence about the environment",
      e.kind()
    ),
  }
}

/// A genuine "this host has no loopback interface" may be skipped over only
/// when an independent socket cannot bind `127.0.0.1` either.
#[track_caller]
fn only_an_absent_loopback_may_skip(what: &str) {
  assert!(
    !control_loopback_present(),
    "{what} — but an independent control socket bound 127.0.0.1 without complaint, so this \
     host does have a loopback interface with an IPv4 address. Enumeration missing it is a \
     regression, not an environment."
  );
  eprintln!("skipping: {what}; an independent control could not bind 127.0.0.1 either");
}

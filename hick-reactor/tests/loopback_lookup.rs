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

mod common;

use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  time::{Duration, Instant},
};

use hick_reactor::{
  CollectedAnswer, Name, QueryEvent, QueryParam, QuerySpec, ServerError, ServerOptions, Service,
  ServiceRecords, ServiceSpec, ServiceUpdate, tokio as tokio_drv, wire::ResourceType,
};

const SERVICE_PORT: u16 = 12345;
const ADVERTISED_V4: [u8; 4] = [127, 0, 0, 1];
const ADVERTISED_V6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

/// The index of an UP loopback interface that has an IPv4 address.
///
/// A `Result<Option<_>, _>` and not an `Option`, because those are three
/// outcomes and the gate below has to tell them apart:
///
/// * `Ok(Some(idx))` — found it;
/// * `Ok(None)` — enumeration WORKED and this host genuinely has no such
///   interface. There is no error kind here to compare against anything, and
///   inventing one is what this signature exists to stop;
/// * `Err(e)` — enumeration itself was refused, or querying a candidate's
///   addresses was. The kind is the caller's to weigh, so it is preserved
///   rather than flattened.
///
/// The old signature collapsed all three into `Option`, and the caller then
/// labelled every `None` as `AddrNotAvailable`. On a host whose interface
/// enumeration is refused with `PermissionDenied` that fabricated kind matched
/// nothing: a control refused with the REAL kind read as "failed differently",
/// and a control that succeeded read as a regression, so every test in this file
/// failed before an endpoint was ever constructed. Exact-kind corroboration
/// cannot work on an input the call site made up.
///
/// `ipv4_addrs()` is queried only for interfaces that already passed the
/// LOOPBACK|UP filter, so an error from it is an error about a candidate rather
/// than about some unrelated NIC, and propagating it loses nothing.
fn loopback_index() -> Result<Option<u32>, std::io::Error> {
  for i in getifs::interfaces()?.iter() {
    let f = i.flags();
    if !(f.contains(getifs::Flags::LOOPBACK) && f.contains(getifs::Flags::UP)) {
      continue;
    }
    if !i.ipv4_addrs()?.is_empty() {
      return Ok(Some(i.index()));
    }
  }
  Ok(None)
}

/// What a [`loopback_index`] outcome obliges of the caller.
///
/// Split out as a pure function over the outcome so the decision can be tested
/// without making `getifs` fail: see the tests directly below.
#[derive(Debug, PartialEq, Eq)]
enum LoopbackVerdict {
  /// Pin the endpoints to this index.
  Use(u32),
  /// Enumeration worked and found nothing. Corroborate the ABSENCE directly —
  /// there is no error kind in play.
  CorroborateAbsence,
  /// Enumeration failed with a kind the environment can produce. Corroborate by
  /// that kind.
  CorroborateKind(std::io::ErrorKind),
  /// Enumeration failed with a kind no environment produces. Nothing to
  /// corroborate; this is a failure.
  Fail(std::io::ErrorKind),
}

fn loopback_verdict(outcome: &Result<Option<u32>, std::io::Error>) -> LoopbackVerdict {
  match outcome {
    Ok(Some(idx)) => LoopbackVerdict::Use(*idx),
    Ok(None) => LoopbackVerdict::CorroborateAbsence,
    Err(e) if is_environmental(e.kind()) => LoopbackVerdict::CorroborateKind(e.kind()),
    Err(e) => LoopbackVerdict::Fail(e.kind()),
  }
}

/// Enumeration refused with a real kind must be corroborated by THAT kind, not
/// by a fabricated one. This is the case that false-failed every test in the
/// file when `loopback_index` returned a bare `Option`.
#[test]
fn an_enumeration_refused_with_permission_denied_corroborates_by_that_kind() {
  let outcome = Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
  assert_eq!(
    loopback_verdict(&outcome),
    LoopbackVerdict::CorroborateKind(std::io::ErrorKind::PermissionDenied)
  );
}

/// A host that enumerates fine and simply has no UP IPv4 loopback is NOT an
/// error, and must not be given one: it is corroborated by asking an independent
/// socket whether `127.0.0.1` is bindable, which is the same question directly.
#[test]
fn a_true_no_match_corroborates_absence_rather_than_a_kind() {
  let outcome: Result<Option<u32>, std::io::Error> = Ok(None);
  assert_eq!(
    loopback_verdict(&outcome),
    LoopbackVerdict::CorroborateAbsence
  );
}

/// An enumeration failure no environment produces is a failure, not a skip —
/// the same rule the endpoint errors follow.
#[test]
fn an_enumeration_failure_no_environment_produces_is_not_skippable() {
  let outcome: Result<Option<u32>, std::io::Error> =
    Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
  assert_eq!(
    loopback_verdict(&outcome),
    LoopbackVerdict::Fail(std::io::ErrorKind::InvalidInput)
  );
}

/// A found index is used, with nothing to corroborate.
#[test]
fn a_found_loopback_index_is_used() {
  assert_eq!(loopback_verdict(&Ok(Some(7))), LoopbackVerdict::Use(7));
}

fn loopback_opts(idx: u32) -> ServerOptions {
  ServerOptions::new()
    .with_ipv6(false)
    .with_interface_index(Some(idx))
}

/// Construct an endpoint, or hand the failure — with its own `io::ErrorKind`,
/// via [`server_error_kind`] — to
/// [`only_a_corroborated_environment_may_skip`], which fails the test unless an
/// independent control socket was refused the same way.
///
/// It used to fold every error into `None`, and every caller returned
/// successfully on `None`; then it read every error as an environment. See the
/// control block below for what each of those cost.
async fn try_endpoint(opts: ServerOptions) -> Option<tokio_drv::Endpoint> {
  match tokio_drv::server(opts).await {
    Ok(ep) => Some(ep),
    Err(e) => {
      let kind = server_error_kind(&e);
      only_a_corroborated_environment_may_skip(
        &format!("endpoint construction failed: {e:?}"),
        kind,
      );
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

/// Hard cap on the responder's RFC 6762 §8.1 probe sequence plus §8.3 startup
/// announcements, used by [`announcements_finished`].
///
/// Deliberately far above the sequence's own schedule — up to 250 ms of §8.1
/// initial jitter, two 250 ms probe intervals, then the two announcements at
/// least 1 s apart, so ~1.75 s — because it is a CAP and not a wait anything is
/// tuned to. Nine responders in this file probe and announce concurrently on one
/// loopback link, and a cap that a loaded runner could reach would turn this
/// file's own scheduling into test failures. Nothing waits it out on the happy
/// path: the wait ends on the `Established` update, whenever that arrives.
const ESTABLISH_BUDGET: Duration = Duration::from_secs(15);

/// Wait for `svc` to reach [`ServiceUpdate::Established`] — the proto layer's
/// own signal that RFC 6762 §8.3's two startup announcements have both been
/// confirmed (`mdns_proto::service` steps `Announcing(1)` → `Established`
/// there and nowhere else) — so the caller may open a querier that has heard
/// none of them.
///
/// `false` means the sequence did not finish inside [`ESTABLISH_BUDGET`], or the
/// update stream ended first (a `Conflict` / `HostConflict` retirement, or a
/// dead driver task). The caller must then treat it the way this file treats
/// every other absence: ask the independent witness whether this host's loopback
/// carries multicast at all, and skip only if it does not.
async fn announcements_finished(svc: &Service, instance: &str) -> bool {
  tokio::time::timeout(ESTABLISH_BUDGET, async {
    while let Some(update) = svc.next().await {
      // `Renamed` is a §9 conflict over a name this file hands to exactly one
      // responder, so it is a fact worth printing rather than skipping past:
      // `Established` still follows it, but the querier below would then be
      // looking up a name this responder no longer holds.
      eprintln!("{instance}: responder update {update:?}");
      if matches!(update, ServiceUpdate::Established) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false)
}

/// Build a [responder, querier] pair on the loopback interface, with the
/// responder publishing a service under the caller-chosen `service` type,
/// `instance`, and `host` names. The querier is opened LAST, only once the
/// responder has finished announcing.
///
/// # Why the querier is opened after `Established`, and not on a timer
///
/// A querier that already holds the answer never has to ask for it, and these
/// tests are named for the asking. A responder's §8.3 unsolicited announcements
/// are multicast to the whole group and carry the WHOLE record set — PTR, SRV,
/// TXT, A and AAAA, regardless of socket family — so any querier listening while
/// they go out caches all of it, and every per-record-type assertion below is
/// then satisfied from cache by traffic the test never sent.
///
/// A fixed sleep before opening the querier put it squarely in that window. §8.1
/// probing takes up to 750 ms and the two §8.3 announcements follow at ~750 ms
/// and ~1750 ms, so the 1300 ms this function used to sleep opened the querier
/// BETWEEN them and handed it the second one. Measured, not reasoned: with
/// `DriverState::drain_query_transmits` stubbed to return without sending — the
/// querier transmits nothing at all — a full workspace test run still left eight
/// of this file's nine query tests GREEN, and only
/// `loopback_browse_resolves_service_entry` (whose `Lookup` chains further
/// queries of its own) failed. A regression that stopped query transmission
/// outright was caught by exactly one test here.
///
/// Waiting for the responder's own `Service` handle to report
/// [`ServiceUpdate::Established`] is what closes that, and it closes it with a
/// fact rather than a longer sleep: the proto layer emits that update exactly
/// when the SECOND announcement is confirmed, and the next unsolicited response
/// after it is a periodic refresh at ~80 % of the record TTL — 96 s for the
/// 120 s TTL used here, past any budget in this file. So the querier is
/// constructed with a cache that is empty of this responder's records and stays
/// that way, and the only route from the responder's records to an assertion
/// below is this test's own query going out and being answered. That keeps the
/// coverage end-to-end: nothing here asserts on a transmit counter or any other
/// driver internal.
///
/// # Why the names are per-test
///
/// `service`/`instance`/`host` are mandatory, not defaulted, because cargo runs
/// every test in this file concurrently on the same loopback link, and a shared
/// name reopens the same hole from the side the wait above cannot reach — a
/// SIBLING test's announcements for the same name land in this test's querier
/// whenever that sibling happens to be announcing. It also makes two responders
/// probe the same name, which is a genuine §8.2 conflict, triggers a §9 rename,
/// and leaves the loser's own querier looking up a name it no longer holds.
///
/// Every call site must therefore pick a triple that is unique across this file,
/// so no two responders ever contend for the same probe and no test's records
/// can stand in for another's.
async fn build_pair(service: &str, instance: &str, host: &str) -> Option<LoopbackPair> {
  let outcome = loopback_index();
  let idx = match loopback_verdict(&outcome) {
    LoopbackVerdict::Use(idx) => idx,
    LoopbackVerdict::CorroborateAbsence => {
      only_an_absent_loopback_may_skip(
        "interface enumeration succeeded and found no UP loopback with an IPv4 address",
      );
      return None;
    }
    LoopbackVerdict::CorroborateKind(kind) => {
      only_a_corroborated_environment_may_skip(
        &format!("interface enumeration failed: {outcome:?}"),
        Some(kind),
      );
      return None;
    }
    LoopbackVerdict::Fail(kind) => panic!(
      "interface enumeration failed with {kind:?} ({outcome:?}), which is not a failure any \
       environment produces"
    ),
  };

  let responder = try_endpoint(loopback_opts(idx)).await?;
  let stype = Name::try_from_str(service).unwrap();
  let instance_name = Name::try_from_str(instance).unwrap();
  let host_name = Name::try_from_str(host).unwrap();
  let mut recs = ServiceRecords::new(stype, instance_name, host_name, SERVICE_PORT, 120);
  recs.add_a(ADVERTISED_V4.into());
  recs.add_aaaa(ADVERTISED_V6);
  recs.add_txt_segment(b"Local web server".to_vec());

  let svc = match responder.register_service(ServiceSpec::new(recs)).await {
    Ok(s) => s,
    Err(e) => {
      // `RegisterError` has no environmental variant — a full pool, a duplicate
      // name and a dead driver are all this crate's — so `None` makes every one
      // of them a hard failure.
      only_a_corroborated_environment_may_skip(
        &format!("register_service failed for {instance}: {e:?}"),
        None,
      );
      return None;
    }
  };

  if !announcements_finished(&svc, instance).await {
    only_an_unproven_link_may_skip(&format!(
      "the responder for {instance} never reached Established within {ESTABLISH_BUDGET:?}"
    ));
    return None;
  }

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
      // `StartQueryError` is `StorageFull` or `DriverGone`; neither is a host.
      only_a_corroborated_environment_may_skip(&format!("start_query failed: {e:?}"), None);
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

// ── the independent control ────────────────────────────────────────────────
//
// Nothing in this file may end a test early on its own say-so. Every skip has
// to be corroborated by a socket that is not hick's, and the two directions
// this control has been wrong in are both on record:
//
// * it once corroborated nothing at all. `try_endpoint` folded every
//   endpoint-construction error into `None` and every caller returned green, so
//   `BindV4(PermissionDenied)` reported ten passing tests with no query issued;
// * it then corroborated too little. The control classified an `EPERM` on its
//   OWN socket as a bug in this file and panicked, so a sandbox that forbids the
//   bind failed all nine query tests with nothing wrong in the product.
//
// The rule that sits between them: **a skip requires an independent control
// that failed the same way, and a control that SUCCEEDS turns any failure back
// into a regression.** Both halves are load-bearing. Without the first, a
// product defect reads as a hostile environment; without the second, a hostile
// environment reads as a product defect.
//
// `packets_rx`, hick's own receive counter, cannot play this part: a regression
// that stops query transmission, stops response generation, or stops receive
// processing yields `packets_rx == 0` exactly like a genuinely silent host, so a
// discriminator built from it would let every affected test skip instead of
// fail. `hick-reactor/tests/parity_bonjour.rs` (PR #59) solved the same problem
// for the harder case — hick against an external daemon on a real NIC — with a
// control socket outside hick's stack whose OWN observations decide environment
// from regression. This is that shape, for one host and the loopback interface.
//
// # Two stages, because there are two questions
//
// * [`control_prerequisites`] attempts what an endpoint attempts — a UDP socket,
//   the reuse options, a bind on `0.0.0.0:5353`, and the mDNS group joined on
//   loopback — and reports the `io::ErrorKind` if the kernel refuses. That is
//   what corroborates a FAILED operation.
// * [`control_delivery`] sends a throwaway datagram to the group from a socket
//   of its own and requires that same socket to receive it back. That is what
//   corroborates an operation that succeeded and produced nothing.
//
// The prerequisite stage MUST set the reuse options, and that is not a detail:
// a control that bound `:5353` without them would collide with any system mDNS
// daemon, report `AddrInUse`, and certify an environment as unavailable while
// hick — which does set them — works perfectly. That is the false-green door
// again, entered from the control side.
//
// # Built on socket2, on every platform
//
// Independence from THIS CRATE'S DRIVER is the property a control needs, not
// independence from every library, so a third-party socket wrapper qualifies
// exactly as `std::net` does. socket2 is what buys the two things `std::net`
// cannot express — `SO_REUSEADDR`/`SO_REUSEPORT` and `IP_MULTICAST_IF` — without
// a hand-rolled `setsockopt`, and it buys them on Windows too, which is why
// there is one control here rather than a Unix one and a hardcoded `true`
// everywhere else. A platform with no control cannot corroborate anything, so
// it could only ever skip on faith or never skip at all, and this file has now
// been wrong in both of those directions.
//
// It does NOT retire the width class, and assuming it did was this control's
// third defect in a row. Taking a dependency MOVES the correctness question, it
// does not settle it: socket2 0.6.5's `set_multicast_loop_v4` passes
// `loop_v4 as c_int` on every target, which is the same four-byte value FreeBSD,
// DragonFly, OpenBSD and NetBSD reject with `EINVAL` — the exact defect this
// file already had once with a hand-rolled `setsockopt`, reintroduced by the
// crate brought in to prevent it, and invisible here because no BSD runs these
// tests. So the options are split by who is demonstrably right about each:
//
// * socket2 sets `SO_REUSEADDR`/`SO_REUSEPORT` (`int` on every target),
//   `IP_MULTICAST_IF` (a `libc`-defined `in_addr` struct, sized per target by
//   construction), the bind and the group join — none of which has a width for
//   a caller to choose;
// * `std::net::UdpSocket` sets `IP_MULTICAST_LOOP`, which does. std resolves it
//   per target — `IpV4MultiCastType` is `c_uchar` on those four BSDs and
//   `c_int` everywhere else — and that is the ONLY reason this control converts
//   to a `std` socket partway through.
//
// `std_sets_ip_multicast_loop_at_this_target_s_width` below makes the real call
// rather than asserting a size, and hick-udp's
// `std_set_multicast_loop_v4_is_accepted_by_this_kernel` runs the same call on a
// real FreeBSD kernel in CI, which is the only native BSD execution this
// workspace has.

/// The mDNS multicast group. Restated here, deliberately, rather than imported
/// from hick — this control must not be able to inherit a defect in hick's own
/// constant.
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The mDNS port. Restated for the same reason as [`MDNS_GROUP`].
const MDNS_PORT: u16 = 5353;

/// Every [`std::io::ErrorKind`] this file reads as a fact about the HOST rather
/// than about hick.
///
/// Closed, short, and deliberately not a catch-all. Anything outside it — an
/// `InvalidInput` from a malformed call of ours, an `Unsupported` operation we
/// asked for wrongly, a read-back that says the kernel took a `setsockopt` and
/// did not honour it — describes this code or the product, and reading it as an
/// environment is how a real defect leaves a green suite behind.
///
/// * `PermissionDenied` — a sandbox, a MAC policy, or an unprivileged process
///   against a privileged port;
/// * `AddrInUse` — a port owner that will not share it even under the reuse
///   options;
/// * `AddrNotAvailable` — the address or interface is not on this host;
/// * `Unsupported` — `EAFNOSUPPORT` and friends: the address family is not
///   available in this environment (an IPv6-less container is the common one);
/// * `NetworkDown` / `NetworkUnreachable` / `HostUnreachable` — the kernel
///   refusing the LINK itself, which is the original narrow allowlist this file
///   carried as raw errnos and which `io::ErrorKind` now spells portably.
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
/// the environment could have produced it.
///
/// `None` means "not an environment fact", and the two read-back variants are
/// the reason this is a match rather than a downcast: `MulticastHopsNotApplied`
/// and `RxDestinationNotEnabled` are raised when a kernel ACCEPTED a
/// `setsockopt` and then did not honour it. No environment produces those; they
/// are exactly the silent-degradation cases those read-backs exist to make loud,
/// and letting one skip a test would undo the whole point of them.
fn bind_error_kind(e: &hick_udp::BindError) -> Option<std::io::ErrorKind> {
  match e {
    hick_udp::BindError::Io(io) => Some(io.kind()),
    hick_udp::BindError::AddressInUse(_) => Some(std::io::ErrorKind::AddrInUse),
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
    // `NoFamilyEnabled` is this file choosing both families off, which it never
    // does. Anything added to this `#[non_exhaustive]` enum later has to be
    // classified deliberately rather than inherited as "environment".
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
/// The socket is dropped on the way out. This answers "would the kernel let ANY
/// process do this here", not "is the port free right now", which is why the
/// reuse options are set before the bind exactly as `hick_udp::try_bind_v4`
/// sets them.
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
  // Windows has no `SO_REUSEPORT`; `hick_udp::platform::windows::bind_v4` does
  // not set one either, so the control matches the endpoint on both platforms.
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

/// The receive budget the delivery control gives one datagram, named once so the
/// helper below and its ABI test cannot take different ones.
const CONTROL_RECV_TIMEOUT: Duration = Duration::from_millis(200);

/// Apply the two socket options [`control_delivery`] needs, and THE ONLY PLACE
/// either is applied.
///
/// # Why this is a function
///
/// `IP_MULTICAST_LOOP` is a bare scalar whose C type a caller has to choose, and
/// the four BSDs choose a one-byte `u_char` where everyone else takes a
/// four-byte `c_int` and reject the wrong width with `EINVAL`. `std` resolves
/// that per target; socket2 0.6.5 does not — `loop_v4 as c_int`,
/// unconditionally — so this file has now had that defect twice, once
/// hand-rolled and once inherited from the crate brought in to prevent it.
///
/// The guard against a third time is NOT a test that makes a similar call. That
/// is what the previous attempt was, and it would have stayed green through a
/// revert to socket2: it exercised `std::net::UdpSocket::set_multicast_loop_v4`
/// directly rather than whatever [`control_delivery`] actually reaches for. A
/// check positioned NEXT TO the thing rather than THROUGH it proves nothing
/// about the thing — the same defect as a query test that passes with
/// transmission disabled.
///
/// So the option application lives here, `control_delivery` has no other route
/// to it, and both ABI tests below run this function or the caller that uses it.
/// Changing what `control_delivery` applies means changing what those tests
/// execute.
fn apply_control_multicast_options(
  sock: &std::net::UdpSocket,
) -> Result<(), (&'static str, std::io::Error)> {
  sock
    .set_multicast_loop_v4(true)
    .map_err(|e| ("enable multicast loopback", e))?;
  sock
    .set_read_timeout(Some(CONTROL_RECV_TIMEOUT))
    .map_err(|e| ("take a receive timeout", e))
}

/// Printed as the LAST statement of a test whose answer only a native BSD
/// kernel can give, so `ci.yml`'s `freebsd` job can require that the test
/// CONCLUDED rather than merely returned.
///
/// The leading newline is load-bearing, for the reason `hick-udp`'s twin
/// records: under `--nocapture` libtest writes `test <name> ... ` without a
/// newline, so a marker printed into that gap lands mid-line and no whole-line
/// match finds it.
fn evidence_complete(test: &str) {
  println!();
  println!("hick-reactor-evidence-complete: {test}");
}

/// Whether an independent socket can put a datagram on the mDNS group over
/// loopback and receive its own copy back.
///
/// Uses an EPHEMERAL port rather than `:5353`: this stage has to send a
/// throwaway payload, and sending it to the mDNS port would hand every hick
/// endpoint in the process — and any system mDNS daemon — a datagram to parse
/// and drop. [`control_prerequisites`] is where the real port is exercised.
///
/// `false` is "this host did not deliver it", which is the only thing an absence
/// with no error can be corroborated by. A refusal of the LINK itself counts as
/// `false` too; anything else panics, for [`control_prerequisites`]'s reason.
fn control_delivery() -> bool {
  use socket2::{Domain, Protocol, Socket, Type};

  let fatal = |stage: &str, e: &std::io::Error| -> bool {
    let kind = e.kind();
    assert!(
      is_environmental(kind),
      "the independent control could not {stage} ({e}), and {kind:?} is not a kind this host \
       could have produced on its own — that is a bug in this test file, which must never be \
       readable as evidence about the environment"
    );
    eprintln!("note: the independent control was refused the loopback link ({stage}: {e})");
    false
  };

  let sock = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
    Ok(s) => s,
    Err(e) => return fatal("open a UDP socket", &e),
  };
  let bind_addr: std::net::SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
  if let Err(e) = sock.bind(&bind_addr.into()) {
    return fatal("bind an ephemeral port", &e);
  }
  if let Err(e) = sock.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::LOCALHOST) {
    return fatal("join the mDNS group on loopback", &e);
  }
  // Membership and EGRESS are different options; the second is what puts the
  // datagram on loopback rather than on whatever the route table prefers.
  if let Err(e) = sock.set_multicast_if_v4(&Ipv4Addr::LOCALHOST) {
    return fatal("select loopback for multicast egress", &e);
  }
  // Everything that follows goes through `std::net::UdpSocket`, and
  // `IP_MULTICAST_LOOP` is why — see [`apply_control_multicast_options`], which
  // is the only place this stage's options are applied and the only thing its
  // ABI test executes.
  let sock: std::net::UdpSocket = sock.into();
  if let Err((stage, e)) = apply_control_multicast_options(&sock) {
    return fatal(stage, &e);
  }
  let port = match sock.local_addr() {
    Ok(a) => a.port(),
    Err(e) => return fatal("read its own bound address", &e),
  };
  let payload = format!("hick-loopback-control-{:x}", std::process::id()).into_bytes();
  if let Err(e) = sock.send_to(&payload, (MDNS_GROUP, port)) {
    return fatal("send to the mDNS group", &e);
  }

  let deadline = Instant::now() + Duration::from_secs(2);
  let mut buf = [0u8; 128];
  while Instant::now() < deadline {
    match sock.recv(&mut buf) {
      Ok(n) if buf.get(..n) == Some(&payload[..]) => return true,
      // Something else on the group — another test's traffic. Keep waiting.
      Ok(_) => continue,
      Err(e)
        if matches!(
          e.kind(),
          std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ) =>
      {
        continue;
      }
      Err(e) => return fatal("receive its own datagram", &e),
    }
  }
  eprintln!(
    "note: the independent control sent a datagram to the mDNS group and did not receive it \
     back within budget; treating multicast loopback as unavailable on this host"
  );
  false
}

/// The delivery control's own option application, executed on a real socket of
/// this kernel's.
///
/// It calls [`apply_control_multicast_options`] — the function
/// [`control_delivery`] calls and the only place those options are set — so a
/// width this kernel rejects fails HERE, and a change to what the control
/// applies is a change to what this test runs. That is the whole point: the
/// previous version of this test called `std::net::UdpSocket` directly and would
/// have stayed green through a revert to socket2's four-byte `c_int`.
///
/// The read-back is not redundant with the `Ok`: a `setsockopt` that takes the
/// call and does not hold the value is the false success this workspace has
/// already had once on `IPV6_MULTICAST_HOPS`.
///
/// Named with the `control_abi_` prefix because `ci.yml`'s `freebsd` job selects
/// both of these by that substring; the completion marker is what catches a
/// rename out of it.
#[test]
fn control_abi_applies_ip_multicast_loop_at_this_target_s_width() {
  let sock = match std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
    Ok(s) => s,
    Err(e) if is_environmental(e.kind()) => {
      eprintln!("skipping: this host would not open a UDP socket at all ({e})");
      return;
    }
    Err(e) => {
      panic!("binding an ephemeral UDP socket failed with {e:?}, which is this test's own bug")
    }
  };
  if let Err((stage, e)) = apply_control_multicast_options(&sock) {
    panic!(
      "the delivery control could not {stage} on this kernel ({e}). EINVAL here is the \
       four-byte-value defect: IP_MULTICAST_LOOP is a one-byte u_char on FreeBSD, DragonFly, \
       OpenBSD and NetBSD, so whatever applies it is not sizing it per target — check that it \
       is std and not socket2 or a hand-rolled setsockopt."
    );
  }
  assert!(
    sock
      .multicast_loop_v4()
      .expect("reading IP_MULTICAST_LOOP back must succeed"),
    "the kernel accepted the enable and then reported the option off"
  );
  evidence_complete("control_abi_applies_ip_multicast_loop_at_this_target_s_width");
}

/// [`control_delivery`] itself, run end to end on this kernel.
///
/// The stronger half of the pair: this executes the function rather than its
/// ingredients, so there is no arrangement of its internals — the helper above,
/// socket2, a hand-rolled `setsockopt` — that this test does not traverse. An
/// option this kernel rejects surfaces as `InvalidInput`, which
/// `control_delivery`'s own `fatal` refuses to read as an environment, so it
/// panics here.
///
/// The RESULT is deliberately not asserted. Whether the group carries a datagram
/// back is a fact about the host, and a VM that does not deliver multicast over
/// loopback is not a finding about this code; what is being established is that
/// every call the control makes is one this kernel accepts.
#[test]
fn control_abi_delivery_stage_runs_end_to_end_on_this_kernel() {
  let carried = control_delivery();
  eprintln!("control_delivery() -> {carried}");
  evidence_complete("control_abi_delivery_stage_runs_end_to_end_on_this_kernel");
}

/// A FAILED operation may be skipped over only when its error kind is one the
/// environment can produce AND an independent control was refused THE SAME WAY.
///
/// `what` names the operation. `kind` is its `io::ErrorKind` where the error
/// carries one the environment could have produced, and `None` otherwise.
///
/// Three ways to reach a panic, and each is a different finding:
///
/// * `kind` is `None` — no environment produces this error, so nothing about
///   the host explains it;
/// * the control found the prerequisites AVAILABLE — the kernel lets an
///   independent socket do exactly what the failing operation needed, so the
///   failure is hick's;
/// * the control was refused, but not the same way — a `PermissionDenied` from
///   the product against an `AddrInUse` from the control is two different facts,
///   and treating them as one is how a skip gets manufactured.
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

/// Whether an independent socket can bind `127.0.0.1`, asked directly.
///
/// This is the corroboration for a genuine no-match from [`loopback_index`], and
/// it asks the SAME question that enumeration answered rather than a proxy for
/// it: a UDP bind on `127.0.0.1:0` succeeds exactly when this host has a
/// loopback interface carrying that address, which is what the enumeration was
/// looking for. No error kind is synthesised and none is compared, because the
/// outcome being corroborated was not an error.
///
/// A refusal whose kind is not in [`is_environmental`] panics, for the reason
/// every other control call does: a broken control must not read as evidence.
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

/// A genuine "this host has no loopback interface" may be skipped over only when
/// an independent socket cannot bind `127.0.0.1` either.
///
/// Separate from [`only_a_corroborated_environment_may_skip`] because there is no
/// error to weigh: enumeration SUCCEEDED and reported nothing. Handing that case
/// an invented `AddrNotAvailable` is what made a real `PermissionDenied`
/// enumeration failure incomparable and false-failed the whole file.
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

/// An operation that SUCCEEDED and produced nothing may be skipped over only
/// when an independent control cannot get a datagram across loopback either.
///
/// There is no error kind to weigh here — nothing failed, the exchange was
/// simply silent — so [`control_delivery`] is the whole corroboration: if an
/// independent socket puts a datagram on the mDNS group and receives its own
/// copy back, this host carries multicast over loopback and a silent exchange is
/// a regression.
#[track_caller]
fn only_an_unproven_link_may_skip(what: &str) {
  assert!(
    !control_delivery(),
    "{what} — on a host where an independent control socket sent a datagram to the mDNS group \
     over loopback and received its own copy back. The link carries; this is a regression in \
     what this file tests, not an environment it may skip on."
  );
  eprintln!(
    "skipping: {what}; an independent control socket could not get a datagram across this host's own loopback either"
  );
}

#[tokio::test]
async fn loopback_ptr_query_returns_instance() {
  const SVC: &str = "_agnostic-mdns-test-ptr-v06._tcp.local.";
  const INST: &str = "TestPtr._agnostic-mdns-test-ptr-v06._tcp.local.";
  const HOST: &str = "test-ptr-host.local.";
  let pair = match build_pair(SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(Name::try_from_str(SVC).unwrap(), ResourceType::Ptr)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  let saw_ptr = answers.iter().any(|a| a.rtype() == ResourceType::Ptr);
  eprintln!(
    "PTR query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  if !saw_ptr {
    only_an_unproven_link_may_skip(&format!(
      "the querier's PTR query drew no PTR answer; {} answers arrived",
      answers.len()
    ));
    return;
  }
}

#[tokio::test]
async fn loopback_srv_query_returns_target() {
  const SVC: &str = "_agnostic-mdns-test-srv-v06._tcp.local.";
  const INST: &str = "TestSrv._agnostic-mdns-test-srv-v06._tcp.local.";
  const HOST: &str = "test-srv-host.local.";
  let pair = match build_pair(SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(Name::try_from_str(INST).unwrap(), ResourceType::Srv)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "SRV query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_srv = answers.iter().any(|a| a.rtype() == ResourceType::Srv);
  if !saw_srv {
    only_an_unproven_link_may_skip(&format!(
      "the querier's SRV query drew no SRV answer; {} answers arrived",
      answers.len()
    ));
    return;
  }
}

#[tokio::test]
async fn loopback_a_query_returns_address() {
  const SVC: &str = "_agnostic-mdns-test-a-v06._tcp.local.";
  const INST: &str = "TestA._agnostic-mdns-test-a-v06._tcp.local.";
  const HOST: &str = "test-a-host.local.";
  let pair = match build_pair(SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(Name::try_from_str(HOST).unwrap(), ResourceType::A)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "A query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_a = answers.iter().any(|a| a.rtype() == ResourceType::A);
  if !saw_a {
    only_an_unproven_link_may_skip(&format!(
      "the querier's A query drew no A answer; {} answers arrived",
      answers.len()
    ));
    return;
  }
  let a_rdata = answers
    .iter()
    .find(|a| a.rtype() == ResourceType::A)
    .map(|a| a.rdata_slice().to_vec())
    .unwrap();
  assert_eq!(a_rdata, ADVERTISED_V4, "wrong A rdata: {a_rdata:?}");
}

#[tokio::test]
async fn loopback_aaaa_query_returns_address() {
  const SVC: &str = "_agnostic-mdns-test-aaaa-v06._tcp.local.";
  const INST: &str = "TestAaaa._agnostic-mdns-test-aaaa-v06._tcp.local.";
  const HOST: &str = "test-aaaa-host.local.";
  let pair = match build_pair(SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(Name::try_from_str(HOST).unwrap(), ResourceType::AAAA)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "AAAA query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  // AAAA over an IPv4-only loopback socket only works if the responder answers
  // an AAAA question with the AAAA record it holds for the host, regardless of
  // which family carried the question. It does, and this test is now the thing
  // that proves it: the querier is opened after `Established` (see
  // `build_pair`), so the announcement that used to supply this record is long
  // gone and the only source left is the response to the query below.
  let saw_aaaa = answers.iter().any(|a| a.rtype() == ResourceType::AAAA);
  if !saw_aaaa {
    only_an_unproven_link_may_skip(&format!(
      "the querier's AAAA query drew no AAAA answer; {} answers arrived",
      answers.len()
    ));
    return;
  }
}

#[tokio::test]
async fn loopback_txt_query_returns_payload() {
  const SVC: &str = "_agnostic-mdns-test-txt-v06._tcp.local.";
  const INST: &str = "TestTxt._agnostic-mdns-test-txt-v06._tcp.local.";
  const HOST: &str = "test-txt-host.local.";
  let pair = match build_pair(SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(Name::try_from_str(INST).unwrap(), ResourceType::Txt)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "TXT query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_txt = answers.iter().any(|a| a.rtype() == ResourceType::Txt);
  if !saw_txt {
    only_an_unproven_link_may_skip(&format!(
      "the querier's TXT query drew no TXT answer; {} answers arrived",
      answers.len()
    ));
    return;
  }
}

#[tokio::test]
async fn loopback_any_query_returns_full_record_set() {
  const SVC: &str = "_agnostic-mdns-test-any-v06._tcp.local.";
  const INST: &str = "TestAny._agnostic-mdns-test-any-v06._tcp.local.";
  const HOST: &str = "test-any-host.local.";
  let pair = match build_pair(SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  // ANY query against the service-type owner only collects records whose
  // OWNER name equals the qname (PTR). SRV/A/AAAA/TXT have different owners
  // (instance / host). To collect everything in one query, ANY-on-instance
  // gives SRV + TXT (both owned by the instance name).
  let spec = QuerySpec::new(Name::try_from_str(INST).unwrap(), ResourceType::Any)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "ANY-instance query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_srv = answers.iter().any(|a| a.rtype() == ResourceType::Srv);
  let saw_txt = answers.iter().any(|a| a.rtype() == ResourceType::Txt);
  if !(saw_srv && saw_txt) {
    only_an_unproven_link_may_skip(&format!(
      "the querier's ANY query drew no SRV+TXT pair; got {answers:?}"
    ));
    return;
  }
}

/// End-to-end DNS-SD discovery: browse the service type and resolve the
/// published instance into a fully-populated `ServiceEntry` (PTR → SRV/TXT →
/// A/AAAA chained by the `Lookup`).
#[tokio::test]
async fn loopback_browse_resolves_service_entry() {
  const SVC: &str = "_agnostic-mdns-test-browse-v06._tcp.local.";
  const INST: &str = "TestBrowse._agnostic-mdns-test-browse-v06._tcp.local.";
  const HOST: &str = "test-browse-host.local.";
  let pair = match build_pair(SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  let param =
    QueryParam::new(Name::try_from_str(SVC).unwrap()).with_timeout(Duration::from_secs(2));
  let mut lookup = match pair.querier.browse(param).await {
    Ok(l) => l,
    Err(e) => {
      only_a_corroborated_environment_may_skip(&format!("browse failed: {e:?}"), None);
      return;
    }
  };

  // Resolve until our instance appears (or a hard cap). Breaking on the first
  // match keeps the test fast — the entry resolves long before the per-query
  // timeouts elapse. Every test in this file publishes under its own private
  // service/instance/host triple (see `build_pair`), so no concurrent test can
  // rename this responder or leak an entry into this browse; we still match on
  // the lowercased type suffix rather than full instance equality because
  // responders lowercase names on the wire.
  let suffix = SVC.to_ascii_lowercase();
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

  let Some(entry) = entry else {
    only_an_unproven_link_may_skip(&format!("browse did not resolve any instance of {SVC}"));
    return;
  };
  assert_eq!(entry.port(), SERVICE_PORT, "wrong port");
  assert!(
    entry.host().as_str().eq_ignore_ascii_case(HOST),
    "wrong host: {}",
    entry.host()
  );
  assert!(
    entry.ipv4_addresses().contains(&ADVERTISED_V4.into()),
    "expected {ADVERTISED_V4:?} in {:?}",
    entry.ipv4_addresses()
  );
  assert!(
    entry.txt().iter().any(|t| &t[..] == b"Local web server"),
    "expected TXT 'Local web server' in {:?}",
    entry.txt()
  );
}

/// `resolve_host`: plain mDNS hostname resolution (A/AAAA), no DNS-SD chain.
#[tokio::test]
async fn loopback_resolve_host_returns_addresses() {
  const SVC: &str = "_agnostic-mdns-test-resolvehost-v06._tcp.local.";
  const INST: &str = "TestResolveHost._agnostic-mdns-test-resolvehost-v06._tcp.local.";
  const HOST: &str = "test-resolvehost-host.local.";
  let pair = match build_pair(SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  let addrs = match pair
    .querier
    .resolve_host(Name::try_from_str(HOST).unwrap(), Duration::from_secs(2))
    .await
  {
    Ok(a) => a,
    Err(e) => {
      only_a_corroborated_environment_may_skip(&format!("resolve_host failed: {e:?}"), None);
      return;
    }
  };
  eprintln!("resolve_host: {addrs:?}");
  if !addrs.contains(&IpAddr::V4(ADVERTISED_V4.into())) {
    only_an_unproven_link_may_skip(&format!(
      "resolve_host did not return {ADVERTISED_V4:?}; got {addrs:?}"
    ));
    return;
  }
}

/// `resolve_instance`: resolve a *known* instance directly (SRV/TXT + A/AAAA),
/// skipping the PTR browse.
#[tokio::test]
async fn loopback_resolve_instance_returns_entry() {
  const SVC: &str = "_agnostic-mdns-resolve-v06._tcp.local.";
  const INST: &str = "ResolveOne._agnostic-mdns-resolve-v06._tcp.local.";
  const HOST: &str = "resolve-one-host.local.";
  let pair = match build_pair(SVC, INST, HOST).await {
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
    other => {
      only_an_unproven_link_may_skip(&format!(
        "resolve_instance did not resolve {INST}: {other:?}"
      ));
      return;
    }
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
    entry.txt().iter().any(|t| &t[..] == b"Local web server"),
    "expected TXT 'Local web server' in {:?}",
    entry.txt()
  );
}

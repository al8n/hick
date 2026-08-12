//! Shared integration-test support.
//!
//! Installs a minimal always-enabled subscriber as the process-wide default
//! before the test binary runs. The driver run loops are only exercised by
//! these loopback integration tests (real multicast I/O), and their
//! `trace!`/`debug!`/`warn!` call sites evaluate their field expressions only
//! when a subscriber reports them enabled — so without this the run-loop
//! instrumentation never earns coverage. The subscriber discards everything;
//! it exists purely so the fields are evaluated.
//!
//! # Endpoint construction, and why every skip here is corroborated
//!
//! [`loopback_v4_endpoint`] / [`try_endpoint`] are shared by both
//! `tests/loopback_endpoint.rs` and `tests/loopback.rs` — each of those files
//! used to hand-roll its own `match Endpoint::server(opts).await { Ok(e) => e,
//! Err(_) => return }`, over and over, which folded every construction failure
//! into an uncorroborated skip and let every caller return successfully. That
//! shape reports a false "all tests passed" the moment `Endpoint::server`
//! starts failing for a real reason: forcing `hick_udp::try_bind_v4` to return
//! `PermissionDenied` used to leave both files green.
//!
//! The fix, ported from `hick-reactor/tests/loopback_lookup.rs` rather than
//! reinvented (there is no shared test-support crate across `hick-reactor`,
//! `hick-mio` and `hick-compio` to pull it from, so the control logic below is
//! duplicated verbatim in each): a skip is legitimate only when an INDEPENDENT
//! control — a socket that shares none of `hick_compio`'s own bind/join code —
//! was refused the exact same `io::ErrorKind`. Anything else is this crate's
//! own bug and must fail loudly. See [`only_a_corroborated_environment_may_skip`]
//! and [`control_prerequisites`].

// Each test binary uses a subset of these helpers.
#![allow(dead_code)]

use std::net::Ipv4Addr;

use hick_compio::{Endpoint, ServerError, ServerOptions};
use tracing_core::{
  Dispatch, Event, LevelFilter, Metadata, Subscriber, dispatcher,
  span::{Attributes, Current, Id, Record},
};

struct AlwaysOn;

impl Subscriber for AlwaysOn {
  fn enabled(&self, _meta: &Metadata<'_>) -> bool {
    true
  }
  fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
    Id::from_u64(1)
  }
  fn record(&self, _span: &Id, _values: &Record<'_>) {}
  fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
  fn event(&self, _event: &Event<'_>) {}
  fn enter(&self, _span: &Id) {}
  fn exit(&self, _span: &Id) {}
  fn max_level_hint(&self) -> Option<LevelFilter> {
    Some(LevelFilter::TRACE)
  }
  fn current_span(&self) -> Current {
    Current::none()
  }
}

#[ctor::ctor(unsafe)]
fn install() {
  let _ = dispatcher::set_global_default(Dispatch::new(AlwaysOn));
}

/// The index of an UP loopback interface, or `Ok(None)` if this host genuinely
/// has none. `Err` is preserved with its real `io::ErrorKind` rather than
/// flattened into `None` — see [`only_an_absent_loopback_may_skip`] /
/// [`only_a_corroborated_environment_may_skip`] for why the distinction
/// matters: a caller that labels every enumeration failure with a fabricated
/// kind cannot corroborate a REAL one against an independent control.
pub fn loopback_index() -> Result<Option<u32>, std::io::Error> {
  for i in getifs::interfaces()?.iter() {
    if i.flags().contains(getifs::Flags::LOOPBACK) {
      return Ok(Some(i.index()));
    }
  }
  Ok(None)
}

/// Resolve the loopback interface and hand the outcome to the corroboration
/// gates, or return `Some(idx)` to use.
pub async fn resolved_loopback_index() -> Option<u32> {
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

/// Construct an endpoint, or hand the failure to
/// [`only_a_corroborated_environment_may_skip`], which fails the test unless an
/// independent control socket was refused the same way.
///
/// It used to fold every error into `None` uncorroborated, and every caller
/// returned successfully on `None` — see the module doc above for what that
/// cost.
pub async fn try_endpoint(opts: ServerOptions) -> Option<Endpoint> {
  match Endpoint::server(opts).await {
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

/// Bind a v4-only endpoint pinned to loopback, or `None` — after a corroborated
/// skip, or a panic if nothing corroborates it.
pub async fn loopback_v4_endpoint() -> Option<Endpoint> {
  let idx = resolved_loopback_index().await?;
  let opts = ServerOptions::default()
    .with_interface_index(Some(idx))
    .with_ipv6(false);
  try_endpoint(opts).await
}

// ── the independent control ────────────────────────────────────────────────
//
// Ported from `hick-reactor/tests/loopback_lookup.rs` rather than reinvented.
// Duplicated, not shared, because there is no test-support crate for
// `hick-reactor`, `hick-mio` and `hick-compio` to pull common code from.
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

/// Every [`std::io::ErrorKind`] this suite reads as a fact about the HOST
/// rather than about hick. Closed and deliberately not a catch-all — see
/// `hick-reactor/tests/loopback_lookup.rs`'s own copy of this allowlist for the
/// per-kind reasoning.
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
    hick_udp::BindError::AddressInUse(_) => Some(std::io::ErrorKind::AddrInUse),
    hick_udp::BindError::InterfaceNotFound(_) => Some(std::io::ErrorKind::AddrNotAvailable),
    _ => None,
  }
}

/// The `io::ErrorKind` behind a [`hick_udp::JoinError`] — the group-join
/// failure hick-compio's `ServerError::JoinV4`/`JoinV6` carry, which
/// hick-reactor and hick-mio instead fold into their `BindV4`/`BindV6`.
fn join_error_kind(e: &hick_udp::JoinError) -> Option<std::io::ErrorKind> {
  match e {
    hick_udp::JoinError::Io(io) => Some(io.kind()),
    hick_udp::JoinError::InterfaceNotFound(_) => Some(std::io::ErrorKind::AddrNotAvailable),
    _ => None,
  }
}

/// The `io::ErrorKind` behind a [`ServerError`], where one exists and the
/// environment could have produced it. `None` is a hard failure.
fn server_error_kind(e: &ServerError) -> Option<std::io::ErrorKind> {
  let kind = match e {
    ServerError::BindV4(b) | ServerError::BindV6(b) => bind_error_kind(b)?,
    ServerError::JoinV4(j) | ServerError::JoinV6(j) => join_error_kind(j)?,
    ServerError::WrapSocket(io) | ServerError::Io(io) => io.kind(),
    // `NoFamilyEnabled` is a caller choosing both families off, which this
    // fixture never does when it wants an endpoint. Anything added to this
    // `#[non_exhaustive]` enum later must be classified deliberately rather
    // than inherited as "environment".
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
pub fn only_a_corroborated_environment_may_skip(what: &str, kind: Option<std::io::ErrorKind>) {
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
pub fn only_an_absent_loopback_may_skip(what: &str) {
  assert!(
    !control_loopback_present(),
    "{what} — but an independent control socket bound 127.0.0.1 without complaint, so this \
     host does have a loopback interface with an IPv4 address. Enumeration missing it is a \
     regression, not an environment."
  );
  eprintln!("skipping: {what}; an independent control could not bind 127.0.0.1 either");
}

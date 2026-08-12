//! Fixtures shared by the loopback integration tests.
//!
//! `hick-reactor/tests/common/mod.rs` is a `tracing` subscriber installer and
//! not a spec-helper module; the spec constructors it uses live inline in
//! `hick-reactor/tests/loopback_endpoint.rs:30-41`. Those are mirrored here.
//!
//! # Why everything here funnels through [`bind_lock`]
//!
//! [`Mdns::new`] always lands on the fixed mDNS port and joins the same group,
//! so every live endpoint in this process shares one `SO_REUSEPORT` group.
//! macOS then delivers a group datagram to only **one** member, which is what
//! made a socket unit test fail about half the time under `cargo test`'s default
//! parallelism before `socket.rs` grew its crate-wide `BIND_LOCK`. That lock is
//! `#[cfg(test)] pub(crate)`, so it does not reach this binary — integration
//! tests are a separate crate — and this module carries its own.
//!
//! The guard is held for the endpoints' whole **lifetime**, not just across the
//! bind: two live endpoints in different tests is exactly the contention being
//! excluded. Because a test may need *two* endpoints at once, the guard is taken
//! once by the test and passed to [`endpoint`] by reference, rather than being
//! taken inside it — a second acquisition of a non-reentrant `Mutex` on the same
//! thread would deadlock.
//!
//! # Every skip is corroborated
//!
//! [`endpoint`] used to fold every failure — interface enumeration, `Mdns::new`
//! (even retried IPv4-only), `mio::Poll::new`, `Mdns::register` — into an
//! uncorroborated `None`, and every caller in `tests/loopback.rs` returned
//! successfully on `None`. That shape reports a false "all tests passed" the
//! moment any of those calls starts failing for a real reason: forcing
//! `hick_udp::try_bind_v4` to return `PermissionDenied` used to leave this
//! whole suite green.
//!
//! The fix, ported from `hick-reactor/tests/loopback_lookup.rs` rather than
//! reinvented (there is no shared test-support crate to pull it from, so it is
//! duplicated verbatim): a skip is legitimate only when an INDEPENDENT control —
//! a socket that shares none of `hick_mio`'s own bind/join code — was refused
//! the exact same `io::ErrorKind`. Anything else is this crate's own bug and
//! must fail loudly. See [`only_a_corroborated_environment_may_skip`] and
//! [`control_prerequisites`] below.

// Each test binary uses a subset of these helpers, and an unused one here is not
// dead code in any meaningful sense.
#![allow(dead_code)]

use std::{
  marker::PhantomData,
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
  sync::{Mutex, MutexGuard},
  time::{Duration, Instant},
};

use hick_mio::{
  Event, Mdns, Name, QueryParam, ServerOptions, ServiceRecords, ServiceSpec,
  wire::{Header, MessageBuilder, ResourceClass, ResourceType},
};
use mio::{Events, Poll, Token};

/// The token each endpoint's IPv4 socket is registered under.
pub const V4: Token = Token(0);
/// The token each endpoint's IPv6 socket is registered under.
pub const V6: Token = Token(1);

/// How long one [`Endpoint::step`] may block in `Poll::poll`.
///
/// Every wait in this file is bounded by a slice like this **and** by a
/// caller-supplied budget, so no helper here can hang: the worst case is that a
/// predicate never becomes true and the pump returns `false` at its deadline.
const SLICE: Duration = Duration::from_millis(20);

/// Serialises every test in this binary that binds a real mDNS socket.
static BIND_LOCK: Mutex<()> = Mutex::new(());

/// Proof that the caller holds the process-wide bind lock.
///
/// Every [`Endpoint`] borrows one of these for its whole life, so the compiler —
/// not a comment — is what stops a test releasing the lock while its sockets are
/// still in the multicast group.
pub struct BindGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

/// Take the process-wide bind lock.
///
/// Poisoning is ignored on purpose: a panic in one test must surface as that
/// test's own assertion failure, not as a poison error in every test after it.
pub fn bind_lock() -> BindGuard {
  BindGuard(BIND_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The index of an interface that is both `LOOPBACK` and `UP`, or `Ok(None)` if
/// this host genuinely has none. `Err` is preserved with its real
/// `io::ErrorKind` rather than flattened into `None` — see
/// [`only_an_absent_loopback_may_skip`] / [`only_a_corroborated_environment_may_skip`]
/// for why the distinction matters: a caller that labels every enumeration
/// failure with a fabricated kind cannot corroborate a REAL one against an
/// independent control, and every test in this suite used to false-pass on a
/// `PermissionDenied` enumeration failure as a result.
fn loopback_index() -> Result<Option<u32>, std::io::Error> {
  for i in getifs::interfaces()?.into_iter() {
    if i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP) {
      return Ok(Some(i.index()));
    }
  }
  Ok(None)
}

/// An [`Mdns`] plus the `mio` loop the test drives it from, and every event it
/// has produced so far.
///
/// The lifetime is the [`BindGuard`] it was built under: an endpoint cannot
/// outlive the lock that keeps its sockets the only ones in the group.
pub struct Endpoint<'lock> {
  /// The endpoint under test.
  pub mdns: Mdns,
  /// Every event [`Self::step`] has drained, in arrival order.
  pub seen: Vec<Event>,
  /// A human-readable name, used only in skip and diagnostic lines.
  pub label: &'static str,
  poll: Poll,
  events: Events,
  _lock: PhantomData<&'lock BindGuard>,
}

impl Endpoint<'_> {
  /// One event-loop iteration: block for at most `SLICE`, feed readiness, tick,
  /// and drain the event queue into [`Self::seen`].
  ///
  /// Mirrors the loop `Mdns::shutdown`'s rustdoc prescribes, except that the
  /// `Poll::poll` timeout is additionally capped at `SLICE` so a test that pumps
  /// two endpoints alternately never parks in one of them.
  ///
  /// That cap makes this **unusable for testing `next_timeout` itself**: a
  /// `next_timeout` that wrongly reported a distant deadline would still be
  /// re-entered `SLICE` later and would still make progress, so the defect would
  /// not show. Use [`Self::step_trusting_next_timeout`] for that.
  pub fn step(&mut self) {
    let timeout = self.mdns.next_timeout().map_or(SLICE, |t| t.min(SLICE));
    self.drive(timeout);
  }

  /// One event-loop iteration that takes `next_timeout()` at its word.
  ///
  /// `safety` is a backstop and nothing else: it bounds `None` (which means
  /// "block indefinitely") and any absurdly distant deadline, so a wrong answer
  /// **stalls** the loop instead of hanging it. Pick a `safety` far larger than
  /// the caller's own deadline, so that stalling once is already enough to fail
  /// the caller's assertion.
  pub fn step_trusting_next_timeout(&mut self, safety: Duration) {
    let timeout = self.mdns.next_timeout().map_or(safety, |t| t.min(safety));
    self.drive(timeout);
  }

  fn drive(&mut self, timeout: Duration) {
    self
      .poll
      .poll(&mut self.events, Some(timeout))
      .expect("poll");
    for ev in self.events.iter() {
      if self.mdns.owns(ev.token()) {
        self.mdns.handle_io(ev);
      }
    }
    self.mdns.tick().expect("tick");
    while let Some(e) = self.mdns.next_event() {
      self.seen.push(e);
    }
  }

  /// Whether this endpoint has parsed any answer record out of an inbound
  /// datagram.
  ///
  /// The delivery probe every environment-gated skip in this suite keys on: an
  /// endpoint that advertises nothing sends no answers of its own, so a non-zero
  /// count means a **peer's** response actually crossed the loopback group.
  /// `packets_rx` cannot serve here — it counts our own multicast loopback
  /// copies too, so it is non-zero the moment we send anything at all.
  ///
  /// Without the `stats` feature there is no counter to consult, so this reports
  /// `true` and the caller asserts unconditionally — the same contract
  /// `hick-reactor`'s loopback tests use, where a non-delivering environment is
  /// a failure rather than a skip. Build with `--features stats` to get the
  /// skip instead.
  pub fn saw_peer_answers(&self) -> bool {
    #[cfg(feature = "stats")]
    {
      self.mdns.stats().answers_rx > 0
    }
    #[cfg(not(feature = "stats"))]
    {
      true
    }
  }

  /// Whether this endpoint has ingested any datagram at all, its **own**
  /// multicast loopback copies included.
  ///
  /// The egress probe, and the counterpart to [`Self::saw_peer_answers`]: the
  /// kernel loops one copy of every multicast transmit back to each joined
  /// socket, so a responder that has put a probe on the wire receives that probe
  /// itself (the self-send tracker is what stops it being mistaken for a peer).
  /// A responder that has transmitted and still reads `packets_rx == 0`
  /// therefore had its egress swallowed by the environment; one that reads
  /// non-zero got its datagrams out and back, so anything it then fails to do is
  /// a defect in this crate rather than in the host.
  ///
  /// Exactly the counter [`Self::saw_peer_answers`] rejects, and for the
  /// opposite reason: counting our own loopback copies makes it useless as a
  /// *peer-delivery* probe and precisely right as an *egress* probe.
  ///
  /// Without the `stats` feature there is no counter to consult, so this reports
  /// `true` and the caller asserts unconditionally — the same fallback
  /// [`Self::saw_peer_answers`] uses.
  pub fn saw_own_loopback(&self) -> bool {
    #[cfg(feature = "stats")]
    {
      self.mdns.stats().packets_rx > 0
    }
    #[cfg(not(feature = "stats"))]
    {
      true
    }
  }
}

/// Whether interface `idx` can actually put an IPv6 multicast datagram on a
/// wire, decided by trying one **before** any endpoint is built.
///
/// # A successful bind is not the question
///
/// [`Mdns::new`] already degrades to IPv4-only when `hick_udp::try_bind_v6` is
/// *rejected*, and that covers the hosts which refuse the family outright. It
/// cannot cover the host that accepts it and then carries nothing: one with
/// `::1` on `lo` binds the socket, accepts `IPV6_MULTICAST_IF` for the loopback
/// index, joins `ff02::fb` there, and then refuses **every** `sendto` with
/// `ENETUNREACH`, because `lo` has no IPv6 multicast route. Every GitHub
/// `ubuntu-latest` runner is that host; a macOS box and a container that leaves
/// IPv6 disabled are not, which is why this was invisible outside CI. Nothing
/// short of the send distinguishes the two, so the send is the probe.
///
/// # Why such a family must be kept out rather than waited on
///
/// A bound family is an OBLIGATED family. `hick-mio` reports a
/// present-but-refusing socket as missed and never as unobligated — that rule is
/// load-bearing, since reporting it unobligated would tell the core the link
/// owes nothing and let an RFC 6762 §8.3 announcement count as delivered to a
/// link that heard none of it. The core then advances each §8 phase past the
/// dead family, but only after spending its partial-round patience on it, and
/// every one of those re-arms is a real unsolicited response on the IPv4 wire
/// that §8.3 requires the *next* one to be spaced at least twice as far behind.
/// The service does still reach `Established` — measured at ~34 s on such a
/// host, against ~2.5 s single-stack — which is the protocol behaving correctly
/// and is far outside any budget a test should sit through. So the family is
/// excluded here, from a fact about the host established up front, rather than
/// inferred afterwards from a lifecycle that failed to finish in time.
///
/// `hick-reactor`'s loopback fixture arrives at the same endpoint by
/// construction: its endpoints are `with_ipv6(false)` unconditionally, which is
/// why its suite is green on the runner this one failed on.
///
/// # The probe socket
///
/// Bound to an ephemeral port and never 5353: joining the endpoint's
/// `SO_REUSEPORT` group would let this socket absorb deliveries meant for the
/// endpoint under test. It joins no group either — only egress is in question,
/// and a joined socket would receive the group's traffic for no reason. The
/// destination is `hick-mio`'s own, scope id and all, so a route this probe
/// finds is the route the endpoint will use. The payload is empty: the datagram
/// exists to be routed, not to be read.
fn carries_ipv6_multicast(idx: u32) -> bool {
  use socket2::{Domain, Protocol, Socket, Type};

  let dst = SocketAddr::V6(SocketAddrV6::new(
    hick_udp::constants::MDNS_IPV6_GROUP,
    hick_udp::constants::MDNS_PORT,
    0,
    0,
  ));
  let probe = || -> std::io::Result<()> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(true)?;
    s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
    s.set_multicast_if_v6(idx)?;
    s.send_to(&[], &dst.into())?;
    Ok(())
  };
  match probe() {
    Ok(()) => true,
    Err(e) => {
      eprintln!("note: interface {idx} carries no IPv6 multicast egress ({e:?})");
      false
    }
  }
}

// ── the independent control ────────────────────────────────────────────────
//
// Ported from `hick-reactor/tests/loopback_lookup.rs` rather than reinvented.
// Duplicated, not shared, because there is no test-support crate for two
// crates' integration-test binaries to pull common code from.
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

/// The `io::ErrorKind` behind a [`hick_mio::ServerError`], where one exists and
/// the environment could have produced it. `None` is a hard failure.
fn server_error_kind(e: &hick_mio::ServerError) -> Option<std::io::ErrorKind> {
  let kind = match e {
    hick_mio::ServerError::BindV4(b) | hick_mio::ServerError::BindV6(b) => bind_error_kind(b)?,
    hick_mio::ServerError::Io(io) => io.kind(),
    // `NoFamilyEnabled` is a caller choosing both families off, which this
    // fixture never does. `BufferSizeUnsupported`/`BufferAllocation` are this
    // fixture's own construction request failing against `Mdns::new`'s
    // documented bounds/allocator, never an environment. Anything added to
    // this `#[non_exhaustive]` enum later must be classified deliberately
    // rather than inherited as "environment".
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

/// Build an endpoint pinned to the loopback interface, or print why the test is
/// skipping.
///
/// Which families end up bound is a property of the host, never of a test:
/// nothing in this suite asserts a family count, a credit count, or a `sent`
/// literal. Two host facts can each take IPv6 away, and they are established in
/// the order that a bind cannot answer the second of them:
///
/// * the loopback interface carries no IPv6 multicast egress — see
///   [`carries_ipv6_multicast`], which decides this by sending one datagram
///   before the endpoint exists;
/// * the dual-stack bind is rejected outright.
///
/// Both are printed, so a run that covers less than it looks like says so.
pub fn endpoint<'lock>(_lock: &'lock BindGuard, label: &'static str) -> Option<Endpoint<'lock>> {
  let idx = match loopback_index() {
    Ok(Some(idx)) => idx,
    Ok(None) => {
      only_an_absent_loopback_may_skip(&format!(
        "{label}: interface enumeration succeeded and found no UP loopback interface"
      ));
      return None;
    }
    Err(e) => {
      let kind = e.kind();
      only_a_corroborated_environment_may_skip(
        &format!("{label}: interface enumeration failed: {e:?}"),
        is_environmental(kind).then_some(kind),
      );
      return None;
    }
  };
  let want_v6 = carries_ipv6_multicast(idx);
  let opts = ServerOptions::default()
    .with_interface_index(Some(idx))
    .with_ipv6(want_v6);
  let mdns = match Mdns::new(opts.clone()) {
    Ok(m) => m,
    Err(e) if want_v6 => {
      eprintln!("note: {label}: dual-stack loopback bind failed ({e:?}); retrying IPv4-only");
      match Mdns::new(opts.with_ipv6(false)) {
        Ok(m) => m,
        Err(e) => {
          let kind = server_error_kind(&e);
          only_a_corroborated_environment_may_skip(
            &format!("{label}: loopback bind failed even IPv4-only: {e:?}"),
            kind,
          );
          return None;
        }
      }
    }
    Err(e) => {
      let kind = server_error_kind(&e);
      only_a_corroborated_environment_may_skip(
        &format!("{label}: loopback bind failed even IPv4-only: {e:?}"),
        kind,
      );
      return None;
    }
  };
  // The probe's answer must reach the endpoint, not merely be printed: an
  // endpoint that bound IPv6 anyway would be obligated on a family that can
  // never deliver, which is the whole condition this fixture exists to keep out.
  // Asserted rather than skipped — it is a statement about this crate honouring
  // `with_ipv6(false)`, and nothing about the host can make it false.
  assert!(
    !mdns.bound_families().1 || want_v6,
    "{label}: IPv6 egress is unavailable on interface {idx}, so the endpoint was built with \
     with_ipv6(false), yet it bound an IPv6 socket anyway"
  );
  let poll = match Poll::new() {
    Ok(p) => p,
    Err(e) => {
      let kind = e.kind();
      only_a_corroborated_environment_may_skip(
        &format!("{label}: mio::Poll::new failed: {e:?}"),
        is_environmental(kind).then_some(kind),
      );
      return None;
    }
  };
  let mut ep = Endpoint {
    mdns,
    seen: Vec::new(),
    label,
    poll,
    events: Events::with_capacity(64),
    _lock: PhantomData,
  };
  if let Err(e) = ep.mdns.register(ep.poll.registry(), V4, V6) {
    let kind = e.kind();
    only_a_corroborated_environment_may_skip(
      &format!("{label}: registering the sockets with mio failed: {e:?}"),
      is_environmental(kind).then_some(kind),
    );
    return None;
  }
  Some(ep)
}

/// Drive `ep` until `done` reports true or `budget` elapses. Returns whether it
/// hit.
///
/// `done` is evaluated once before the first `poll` too, so a condition already
/// satisfied costs no wall time.
pub fn pump<F>(ep: &mut Endpoint<'_>, budget: Duration, mut done: F) -> bool
where
  F: FnMut(&mut Endpoint<'_>) -> bool,
{
  let deadline = Instant::now() + budget;
  loop {
    if done(ep) {
      return true;
    }
    if Instant::now() >= deadline {
      return false;
    }
    ep.step();
  }
}

/// Drive `a` and `b` in lockstep until `done` reports true or `budget` elapses.
///
/// Both are stepped every iteration. Pumping one and then the other in separate
/// `pump` calls would let the idle endpoint's socket buffer absorb a burst it is
/// not draining, which on a small default `SO_RCVBUF` silently loses the very
/// packets the test is waiting for.
pub fn pump_pair<F>(
  a: &mut Endpoint<'_>,
  b: &mut Endpoint<'_>,
  budget: Duration,
  mut done: F,
) -> bool
where
  F: FnMut(&mut Endpoint<'_>, &mut Endpoint<'_>) -> bool,
{
  let deadline = Instant::now() + budget;
  loop {
    if done(a, b) {
      return true;
    }
    if Instant::now() >= deadline {
      return false;
    }
    a.step();
    b.step();
  }
}

/// A service advertised on 127.0.0.1, mirroring `hick-reactor`'s `http_service`.
///
/// `instance` and `host` are caller-chosen so each test owns names no other test
/// in this binary publishes: a shared instance name would be renamed by RFC 6762
/// §9 conflict resolution the moment two tests overlapped.
pub fn service_spec(service_type: &str, instance: &str, host: &str, port: u16) -> ServiceSpec {
  let mut recs = ServiceRecords::new(
    Name::try_from_str(service_type).expect("service type"),
    Name::try_from_str(instance).expect("instance name"),
    Name::try_from_str(host).expect("host name"),
    port,
    120,
  );
  recs.add_a(Ipv4Addr::LOCALHOST);
  ServiceSpec::new(recs)
}

/// A browse for `service_type` with an explicit timeout.
pub fn query_param(service_type: &str, timeout: Duration) -> QueryParam {
  QueryParam::new(Name::try_from_str(service_type).expect("service type")).with_timeout(timeout)
}

/// A UDP socket that can flood the mDNS IPv4 group *on the loopback link*, or
/// `None` with a printed reason.
///
/// Three socket options are all load-bearing, and `std::net::UdpSocket` exposes
/// only two of them — hence `socket2`:
///
/// * `IP_MULTICAST_IF` = 127.0.0.1. Without it the datagrams egress on the
///   host's **default** multicast interface, and an endpoint joined only on
///   loopback never sees them. Observed on macOS: 400 datagrams sent, zero
///   delivered.
/// * `IP_MULTICAST_TTL` = 255. Fixture normalisation, and load-bearing for
///   nothing: the ingress boundary reads no hop limit, RFC 1112 requires the
///   local loopback copy whatever the TTL, and §11's 255 recommendation is about
///   RESPONSES while this burst is queries. An earlier version of this note
///   claimed the default of 1 would prevent delivery — it does not, and saying
///   so was false evidence about the setup. It is set so the fixture emits what
///   a conforming responder would.
/// * `IP_MULTICAST_LOOP`. On by default, but set explicitly: the whole point is
///   that a same-host socket receives these.
///
/// Bound to an ephemeral port, never 5353: joining the endpoint's
/// `SO_REUSEPORT` group would let this socket absorb deliveries meant for the
/// endpoint under test.
pub fn loopback_flooder() -> Option<socket2::Socket> {
  use socket2::{Domain, Protocol, Socket, Type};

  let build = || -> std::io::Result<Socket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.bind(&std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    s.set_multicast_if_v4(&Ipv4Addr::LOCALHOST)?;
    s.set_multicast_ttl_v4(255)?;
    s.set_multicast_loop_v4(true)?;
    Ok(s)
  };
  match build() {
    Ok(s) => Some(s),
    Err(e) => {
      let kind = e.kind();
      only_a_corroborated_environment_may_skip(
        &format!("the flooding socket could not be set up: {e:?}"),
        is_environmental(kind).then_some(kind),
      );
      None
    }
  }
}

/// A wire-format PTR question for `service_type`, used to generate inbound load.
///
/// A **query** (QR=0), deliberately: RFC 6762 §11 makes this crate drop any
/// response whose source port is not 5353, and the flooding socket that sends
/// this is on an ephemeral port. A response body would be discarded before it
/// ever reached the drain under test.
pub fn minimal_query_datagram(service_type: &str) -> Vec<u8> {
  let mut buf = vec![0u8; 512];
  let mut b: MessageBuilder<'_> =
    MessageBuilder::try_new(&mut buf, Header::new()).expect("message builder");
  b.push_question(
    &Name::try_from_str(service_type).expect("service type"),
    ResourceType::Ptr,
    ResourceClass::In,
    false,
  )
  .expect("push_question");
  let n = b.finish().expect("finish");
  buf.truncate(n);
  buf
}

/// The first resolved entry in `seen` that is an instance of `service_type`
/// **and** satisfies `accept`.
///
/// Matched on the case-folded service-type **suffix**, never the exact instance
/// label: a responder lowercases names on the wire, and §9 conflict resolution
/// renames a clashing instance, so the label is not stable while the suffix is.
///
/// `accept` is part of the selection rather than a filter the caller applies
/// afterwards, and that is the point. A caller that waits on
/// `resolved_entry(..).is_some_and(accept)` and then re-fetches with
/// `resolved_entry(..)` alone is running two different searches: with more than
/// one instance of `service_type` on the link — a foreign responder advertising
/// the same custom type — the wait can be satisfied by the second entry while
/// the re-fetch returns the first. Folding `accept` in makes the two calls
/// select the same entry by construction.
pub fn resolved_entry<'a>(
  seen: &'a [Event],
  service_type: &str,
  mut accept: impl FnMut(&hick_mio::ServiceEntry) -> bool,
) -> Option<&'a hick_mio::ServiceEntry> {
  let suffix = service_type.to_ascii_lowercase();
  seen.iter().find_map(|e| match e {
    Event::Lookup { entry, .. }
      if entry
        .instance_name()
        .as_str()
        .to_ascii_lowercase()
        .ends_with(&suffix)
        && accept(entry) =>
    {
      Some(entry)
    }
    _ => None,
  })
}

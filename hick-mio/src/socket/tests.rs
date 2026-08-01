use std::{
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
  sync::MutexGuard,
  time::{Duration, Instant as StdInstant, SystemTime},
};

use mio::{Interest, Poll, Token};

use super::{
  ALLOW_BOTH, BIND_LOCK, Family, MAX_DISCARDED_PER_RECV, MAX_RECV_ERRORS_PER_ROUND, RecvRotor,
  SendOutcome, SendReport, Sockets,
};
use crate::options::ServerOptions;

/// The IPv4 mDNS group: the destination every proto-layer multicast transmit
/// carries, and therefore the one that triggers the dual-stack fan-out.
const MDNS_V4: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));

/// A bound socket pair plus the bind lock it holds.
///
/// Field order is load-bearing: struct fields drop in declaration order, so the
/// sockets close (leaving the multicast group) *before* the guard is released
/// and the next test is allowed to bind.
struct TestSockets {
  sockets: Sockets,
  /// The SAME `Arc` handed to [`Sockets::bind`], kept here so a test can read
  /// back what `send_one` / `recv` bumped without needing a
  /// `Mdns`-level fixture. A fresh, private `Stats` per test — never shared
  /// with another test's — so counts from one test can never leak into
  /// another's assertions.
  #[cfg(feature = "stats")]
  stats: std::sync::Arc<hick_trace::stats::Stats>,
  _guard: MutexGuard<'static, ()>,
}

impl core::ops::Deref for TestSockets {
  type Target = Sockets;

  fn deref(&self) -> &Sockets {
    &self.sockets
  }
}

impl core::ops::DerefMut for TestSockets {
  fn deref_mut(&mut self) -> &mut Sockets {
    &mut self.sockets
  }
}

fn loopback_index() -> Option<u32> {
  getifs::interfaces()
    .ok()?
    .into_iter()
    .find(|i| i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP))
    .map(|i| i.index())
}

/// Bind a loopback-scoped socket pair, or report why the test is skipping.
/// Every early return prints a reason: a silent skip is a test that passes
/// while asserting nothing.
///
/// Binding the IPv6 mDNS socket is rejected outright on some hosts (macOS
/// returns `EINVAL` from `hick_udp::try_bind_v6` on *every* interface), so a
/// dual-stack request degrades to IPv4-only rather than skipping the whole
/// test — the token, queue, and interest properties do not depend on IPv6. The
/// degradation is printed so a run that covers less than it looks like says so.
fn loopback_sockets(opts: ServerOptions) -> Option<TestSockets> {
  // Ignore poisoning: a panic in one test must surface as that test's own
  // assertion failure, not as a poison error in every test that follows it.
  let guard = BIND_LOCK.lock().unwrap_or_else(|e| e.into_inner());
  let Some(idx) = loopback_index() else {
    eprintln!("skipping: no UP loopback interface reported by getifs");
    return None;
  };
  let opts = opts.with_interface_index(Some(idx));
  let v6_wanted = opts.ipv6();
  #[cfg(feature = "stats")]
  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
  let sockets = match Sockets::bind(
    &opts,
    #[cfg(feature = "stats")]
    stats.clone(),
  ) {
    Ok(s) => s,
    Err(e) if v6_wanted => {
      eprintln!("note: dual-stack loopback bind failed ({e:?}); retrying IPv4-only");
      match Sockets::bind(
        &opts.with_ipv6(false),
        #[cfg(feature = "stats")]
        stats.clone(),
      ) {
        Ok(s) => s,
        Err(e) => {
          eprintln!("skipping: binding the loopback mDNS sockets failed: {e:?}");
          return None;
        }
      }
    }
    Err(e) => {
      eprintln!("skipping: binding the loopback mDNS sockets failed: {e:?}");
      return None;
    }
  };
  Some(TestSockets {
    sockets,
    #[cfg(feature = "stats")]
    stats,
    _guard: guard,
  })
}

#[test]
fn bind_register_and_deregister_on_loopback() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default()) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");
  assert!(socks.owns(Token(10)));
  assert!(socks.owns(Token(11)));
  assert!(!socks.owns(Token(12)));
  socks.deregister().expect("deregister");
}

// ── registration state ──────────────────────────────────────────────────────
//
// A registration lives in exactly one selector, and the state that names it —
// the cloned registry, the token pair, each family's own token — is the only
// handle this crate has on it. Forgetting any of that while the selector still
// holds the registration leaves a ghost: events still delivered under a token
// `owns` has stopped claiming, and no registry left to remove it with.

/// Deregistration goes to the selector that actually holds the registration.
///
/// A caller driving two `Poll`s could otherwise hand us the wrong one, and the
/// platforms do not even agree about what that means — kqueue ignores the absent
/// filter and reports success, epoll returns `ENOENT` — so honouring a
/// caller-supplied registry could only ever forget a registration that still
/// exists. There is deliberately no argument left to get wrong; what this pins is
/// that the removal really reached the first `Poll`.
#[test]
fn deregistration_reaches_the_selector_that_holds_the_registration() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  // `holder` takes the registration; `other` is a second selector the same
  // caller drives.
  let mut holder = Poll::new().expect("poll");
  let mut other = Poll::new().expect("poll");
  socks
    .register(holder.registry(), Token(10), Token(11))
    .expect("register");
  socks.deregister().expect("deregister");
  assert!(!socks.owns(Token(10)));

  // The registration really left `holder`, so `other` can take it — and then
  // `other` alone hears about a datagram. A ghost left behind would deliver the
  // same edge twice, the second time under a token nothing claims.
  socks
    .register(other.registry(), Token(10), Token(11))
    .expect("the second Poll must be able to take the registration");
  let report = socks.send_to(b"two-polls", MDNS_V4, ALLOW_BOTH);
  assert!(matches!(report.v4, SendOutcome::Sent { .. }), "{report:?}");

  let mut events = mio::Events::with_capacity(8);
  other
    .poll(&mut events, Some(std::time::Duration::from_millis(500)))
    .expect("poll");
  if !events.iter().any(|ev| socks.owns(ev.token())) {
    eprintln!("skipping the ghost assertion: no readiness arrived on the second Poll within 500ms");
    socks.deregister().expect("deregister");
    return;
  }
  let mut ghosts = mio::Events::with_capacity(8);
  holder
    .poll(&mut ghosts, Some(std::time::Duration::from_millis(100)))
    .expect("poll");
  assert!(
    !ghosts.iter().any(|ev| socks.owns(ev.token())),
    "the first Poll is still delivering readiness for a socket it was told to \
     release"
  );
  socks.deregister().expect("deregister");
}

/// A family the selector did not release keeps everything needed to retry.
///
/// Clearing the token, the readiness and the shared registration state on a
/// failure loses the ghost twice over: `owns` stops claiming a token the
/// selector still routes to us, and no registry is left to remove it with.
#[test]
fn a_family_the_selector_did_not_release_keeps_its_registration_state() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default()) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");
  socks.force_deregister_error_for_test(Family::V4, true);
  socks
    .deregister()
    .expect_err("a family the selector refused to release must be reported");

  assert!(
    socks.owns(Token(10)) && socks.owns(Token(11)),
    "IPv4 is still registered, so the pair the caller reserved is still ours to \
     route"
  );
  assert_eq!(
    socks.interest_for_test(Family::V4),
    Some(Interest::READABLE),
    "the family that was not released still holds the registration it was given"
  );
  assert_eq!(
    socks
      .register(poll.registry(), Token(12), Token(13))
      .expect_err("still registered")
      .kind(),
    std::io::ErrorKind::AlreadyExists,
    "the outstanding cleanup is exactly what the caller is told to do first"
  );

  // Retryable: the same call, once the selector cooperates, finishes it.
  socks.force_deregister_error_for_test(Family::V4, false);
  socks
    .deregister()
    .expect("the outstanding removal must still be retryable");
  assert!(!socks.owns(Token(10)));
  assert_eq!(socks.interest_for_test(Family::V4), None);
  socks
    .register(poll.registry(), Token(12), Token(13))
    .expect("re-register");
  socks.deregister().expect("deregister");
}

/// A partial registration whose rollback also failed stays owned and removable.
///
/// The rollback is the same hazard read backwards: IPv6 refuses the
/// registration, rolling IPv4 back out fails too, and IPv4 is left in the
/// caller's selector. Dropping the state that names it there would strand it for
/// the life of the process.
#[test]
fn a_registration_whose_rollback_failed_stays_owned_and_retryable() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks.force_v6_register_error_for_test(true);
  socks.force_deregister_error_for_test(Family::V4, true);
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect_err("the IPv6 half of the registration failed");

  assert!(
    socks.owns(Token(10)),
    "IPv4 is still in the caller's selector; `owns` must keep claiming the token \
     it will route on"
  );
  assert_eq!(
    socks.interest_for_test(Family::V4),
    Some(Interest::READABLE),
    "and the family still holds the registration the rollback could not remove"
  );

  socks.force_deregister_error_for_test(Family::V4, false);
  socks
    .deregister()
    .expect("the leftover registration must still be removable");
  assert!(!socks.owns(Token(10)));

  socks.force_v6_register_error_for_test(false);
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("a fully cleaned-up endpoint registers again");
  socks.deregister().expect("deregister");
}

#[test]
fn recv_with_nothing_pending_returns_none() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default()) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");
  let mut buf = vec![0u8; 2048];
  // No readiness recorded -> nothing to drain.
  assert!(socks.recv(&mut buf).is_none());
  socks.deregister().expect("deregister");
}

// ── readiness bookkeeping ───────────────────────────────────────────────────
//
// `has_readable` is what drives `Mdns::next_timeout`'s zero arm, so both
// of its edges matter: it must go true when mio reports data, and it must go
// false once `recv` has drained to `WouldBlock` and re-armed. If it stuck true
// the caller would spin; if it never went true the caller would block on an
// edge it had already consumed and go deaf.

#[test]
fn readiness_is_recorded_then_cleared_by_draining_to_wouldblock() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let mut poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");
  assert!(
    !socks.has_readable(),
    "a freshly registered socket has nothing to drain"
  );

  // Send to the group we joined, scoped to loopback. Multicast is delivered to
  // EVERY socket joined on that interface, so we get our own copy back —
  // unlike a unicast to our own port, which macOS `SO_REUSEPORT` hands to just
  // one of the sockets bound to 5353 (usually the system responder).
  let report = socks.send_to(b"ping", MDNS_V4, ALLOW_BOTH);
  assert!(matches!(report.v4, SendOutcome::Sent { .. }), "{report:?}");

  let mut events = mio::Events::with_capacity(8);
  poll
    .poll(&mut events, Some(std::time::Duration::from_millis(500)))
    .expect("poll");
  let mut saw_ours = false;
  for ev in &events {
    if socks.owns(ev.token()) {
      socks.note_readiness(ev);
      saw_ours = true;
    }
  }
  if !saw_ours {
    eprintln!("skipping the drain assertions: no readiness event arrived within 500ms");
    return;
  }
  assert!(
    socks.has_readable(),
    "note_readiness must record the readable edge"
  );

  // Drain everything queued and look for OUR datagram rather than assuming the
  // first one is it: another responder on this host may also be multicasting to
  // the group we joined.
  let mut buf = vec![0u8; 2048];
  let mut ours = None;
  let mut drained = 0usize;
  while let Some((meta, family)) = socks.recv(&mut buf) {
    drained += 1;
    assert_eq!(family, Family::V4, "only the v4 family is bound");
    // Still flagged: `recv` clears only once the kernel says WouldBlock.
    assert!(
      socks.has_readable(),
      "the flag must survive a successful recv"
    );
    if meta.len() == 4 && buf.get(..4) == Some(&b"ping"[..]) {
      ours = Some(meta);
    }
    assert!(drained < 64, "the socket never drained to WouldBlock");
  }
  let meta = ours.expect("our own multicast copy must come back on the joined socket");
  assert_eq!(meta.len(), 4);
  assert!(meta.peer().ip().is_loopback(), "peer: {}", meta.peer());
  assert!(
    !socks.has_readable(),
    "draining to WouldBlock must clear the flag and re-arm, or the caller spins"
  );
  socks.deregister().expect("deregister");
}

// ── liveness for pending output ─────────────────────────────────────────────
//
// `next_timeout` blocks on pending output whenever mio will wake us, so
// `needs_interest_retry` has to be exactly right about when it will not.

#[test]
fn a_healthy_socket_pair_needs_no_timer() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");
  assert!(
    !socks.needs_interest_retry(),
    "nothing is parked and no re-arm failed, so mio's own edges suffice"
  );
  socks.deregister().expect("deregister");
}

#[test]
fn a_registration_is_readable_only_for_the_life_of_the_socket() {
  // WRITABLE is never armed. A `WouldBlock` send is reported as a miss and
  // re-armed by the core, so there is nothing for a writable edge to wake — and
  // arming it would spin the caller's `Poll` on an always-writable UDP socket.
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");
  assert_eq!(
    socks.interest_for_test(Family::V4),
    Some(Interest::READABLE)
  );
  let report = socks.send_to(b"body", MDNS_V4, ALLOW_BOTH);
  assert!(matches!(report.v4, SendOutcome::Sent { .. }));
  assert_eq!(
    socks.interest_for_test(Family::V4),
    Some(Interest::READABLE),
    "a send must never change what the selector is watching for"
  );
  socks.deregister().expect("deregister");
}

#[test]
fn an_unknown_interface_index_is_not_reported_as_a_missing_address() {
  // A caller who passed a stale or invented index must be told the interface
  // does not exist, not that it exists and has no address in any requested
  // family — the latter sends them auditing addresses on an interface that is
  // not there. No socket is created on this path, so no bind lock is needed.
  let opts = ServerOptions::default().with_interface_index(Some(u32::MAX));
  let Err(err) = Sockets::bind(
    &opts,
    #[cfg(feature = "stats")]
    std::sync::Arc::new(hick_trace::stats::Stats::default()),
  ) else {
    panic!("u32::MAX cannot name a real interface");
  };
  let crate::error::ServerError::Io(io) = err else {
    panic!("an unknown interface index must surface as an I/O error, got {err:?}");
  };
  assert_ne!(
    io.kind(),
    std::io::ErrorKind::AddrNotAvailable,
    "AddrNotAvailable is the has-no-address error; an absent interface must not borrow it"
  );
  assert!(
    io.to_string().contains(&u32::MAX.to_string()),
    "the message must name the index the caller passed, got {io}"
  );
}

// ── self-send credit accounting ─────────────────────────────────────────────
//
// One logical multicast transmit is one syscall PER BOUND FAMILY, and each
// produces its own multicast loopback copy. The caller must take exactly one
// self-send credit per copy, so the per-family report has to carry one stamp
// per successful syscall — a single merged outcome would leave the second
// loopback uncredited, and the take-once tracker would then ingest it as a peer
// datagram and see a phantom conflict against itself.

/// A synthetic acceptance whose three stamps all describe one syscall: the wall
/// clock `wall`, and both monotonic reads at `mono`. Only the wall stamp matters
/// to the credit accounting below, and collapsing the other two keeps the
/// fixture from implying a stall it is not testing.
const fn sent_at(wall: SystemTime, mono: std::time::Instant) -> SendOutcome {
  SendOutcome::Sent {
    submitted_wall: wall,
    submitted_at: mono,
    wire_at: mono,
  }
}

/// The wall stamp of every family that actually transmitted, in family order.
/// The shape the driver reads out of [`SendReport::per_family`] to credit its
/// own loopback copies.
fn stamps(report: &SendReport) -> Vec<SystemTime> {
  report
    .per_family()
    .into_iter()
    .filter_map(|(_, outcome)| outcome.credit_stamp())
    .collect()
}

#[test]
fn stamps_yields_exactly_one_credit_per_successful_syscall() {
  // Pure arithmetic over `SendReport`, so the credit count is pinned on every
  // host — including the ones where no IPv6 socket can be bound and the real
  // dual-stack fan-out below cannot run.
  let t1 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1);
  let t2 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2);

  let mono = std::time::Instant::now();
  let both = SendReport {
    v4: sent_at(t1, mono),
    v6: sent_at(t2, mono),
    loops_back: true,
  };
  assert_eq!(
    stamps(&both),
    vec![t1, t2],
    "a dual-stack fan-out produces two loopback copies and must yield two credits"
  );

  let v4_only = SendReport {
    v4: sent_at(t1, mono),
    v6: SendOutcome::NoSocket,
    loops_back: true,
  };
  assert_eq!(stamps(&v4_only), vec![t1]);

  // None of these produced a loopback copy: one was never offered the datagram,
  // one was held back by the wire gate, and one was refused outright.
  for absent in [
    SendOutcome::Gated,
    SendOutcome::Failed,
    SendOutcome::NoSocket,
  ] {
    let r = SendReport {
      v4: absent,
      v6: absent,
      loops_back: true,
    };
    assert_eq!(stamps(&r).len(), 0, "{absent:?} must not yield a credit");
  }
}

#[test]
fn a_multicast_send_reports_one_outcome_per_bound_family() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default()) else {
    return;
  };
  let before = SystemTime::now();
  let report = socks.send_to(b"body", MDNS_V4, ALLOW_BOTH);
  let after = SystemTime::now();

  if socks.is_bound_for_test(Family::V6) {
    // Dual stack: two syscalls, two loopback copies — but a BOUND family is not
    // necessarily a SENDABLE one, so this deliberately does not assert `Sent`.
    //
    // On Linux, `sendto` to ff02::fb with `IPV6_MULTICAST_IF` pinned to the
    // loopback fails with `ENETUNREACH` (errno 101): the kernel has no route for
    // link-local multicast out of `lo`, even though the bind and the group join
    // both succeed. Reproduced outside this crate, so it is a kernel property,
    // not a container artifact — and it is invisible on macOS, where
    // `try_bind_v6` fails outright and this branch is never taken. Asserting
    // egress here made the suite green on macOS and red on `ubuntu-latest`.
    //
    // What survives is the distinction the §10.1 per-family goodbye debt
    // depends on: a bound family WAS attempted, so its outcome is never
    // `NoSocket`. An absent family is written off; a bound one that failed must
    // be retried, and conflating them strands that family's peers on stale
    // positive-TTL records.
    assert!(
      !matches!(report.v6, SendOutcome::NoSocket),
      "a bound family must be attempted, never reported absent: {report:?}"
    );
    if !matches!(report.v6, SendOutcome::Sent { .. }) {
      eprintln!(
        "note: IPv6 is bound but its multicast egress failed ({:?}); the two-credit fan-out is unexercised on this host",
        report.v6
      );
    }
  } else {
    eprintln!(
      "note: no IPv6 socket on this host; asserting the v4-only fan-out instead of the dual-stack one"
    );
    // The absent family must report NoSocket, NOT Failed: the §10.1 per-family
    // goodbye debt writes off an absent family but retries a failed one.
    assert_eq!(report.v6, SendOutcome::NoSocket);
  }
  // IPv4 multicast on loopback works on every supported platform, so this stays
  // strict.
  assert!(
    matches!(report.v4, SendOutcome::Sent { .. }),
    "v4: {report:?}"
  );
  // One credit per family that actually reached the kernel — whichever families
  // those turned out to be on this host.
  assert_eq!(
    stamps(&report).len(),
    [report.v4, report.v6]
      .iter()
      .filter(|o| matches!(o, SendOutcome::Sent { .. }))
      .count(),
    "credits must match the families that reached the kernel: {report:?}"
  );

  for at in stamps(&report) {
    // Each stamp must bracket its syscall, so the tracker entry it feeds can
    // never postdate the kernel's stamp on the loopback copy.
    assert!(at >= before, "send stamp predates the call");
    assert!(at <= after, "send stamp postdates the call");
  }
}

#[test]
fn a_unicast_send_reports_one_sent_and_one_no_socket() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5354));
  let report = socks.send_to(b"body", dst, ALLOW_BOTH);
  assert!(matches!(report.v4, SendOutcome::Sent { .. }), "{report:?}");
  assert_eq!(report.v6, SendOutcome::NoSocket);
  assert_eq!(
    stamps(&report).len(),
    1,
    "a unicast send is one syscall and must owe exactly one credit"
  );
}

#[test]
fn an_unbound_family_reports_no_socket_rather_than_failed() {
  // `NoSocket` must stay distinguishable from `Failed`: conflating them would
  // let the withdrawal pump free a route while a bound family still owes its
  // goodbye.
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5354, 0, 0));
  let report = socks.send_to(b"body", dst, ALLOW_BOTH);
  assert_eq!(report.v6, SendOutcome::NoSocket);
  assert_eq!(report.v4, SendOutcome::NoSocket);
  assert_eq!(stamps(&report).len(), 0);
}

#[test]
fn send_one_rejects_a_destination_from_another_family() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let v6_dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5354, 0, 0));
  // Failed, not NoSocket: the v4 family IS bound, the caller just passed a
  // destination it cannot carry.
  assert_eq!(
    socks.send_one(Family::V4, b"body", v6_dst, ALLOW_BOTH),
    SendOutcome::Failed
  );
}

#[test]
fn a_shut_gate_withholds_the_datagram_without_a_syscall() {
  // The gate is the caller's decision and this layer only reports it. `Gated`
  // must stay distinct from `NoSocket` — the socket is there and the datagram
  // was meant for it — and from `Sent`, since no syscall was made.
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let report = socks.send_to(b"body", MDNS_V4, [false, false]);
  assert_eq!(report.v4, SendOutcome::Gated);
  assert_eq!(
    report.v6,
    SendOutcome::NoSocket,
    "boundness is decided before the gate, so a shut gate cannot invent an \
     obligation for a link that does not exist"
  );
  assert_eq!(stamps(&report).len(), 0, "a gated family made no syscall");
  #[cfg(feature = "stats")]
  assert_eq!(
    socks.stats.snapshot().send_errors,
    0,
    "a deliberate deferral is not an I/O error"
  );
}

// ── interest state machine ──────────────────────────────────────────────────

#[test]
fn register_rejects_a_duplicate_token() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default()) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  // One token cannot address two sockets: readiness would be unattributable.
  let err = socks
    .register(poll.registry(), Token(7), Token(7))
    .expect_err("duplicate tokens must be rejected");
  assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
  assert!(!socks.owns(Token(7)));
}

// ── tx-side stats accounting ────────────────────────────────────────────────
//
// `packets_tx` / `bytes_tx` / `send_errors` are bumped inside `send_one`
// itself (see `Sockets`'s `stats` field doc for why there rather than in the
// driver), so these exercise `Sockets` directly rather than through a full
// `Mdns` fixture. The regression they guard is a real one: all three counters
// once stayed at zero no matter how much a `Sockets` actually sent, which is
// invisible to every other test here.

#[test]
#[cfg(feature = "stats")]
fn a_successful_send_bumps_packets_tx_and_bytes_tx() {
  // IPv4 multicast on loopback works on every supported platform (see
  // `a_multicast_send_reports_one_outcome_per_bound_family`), so this needs no
  // environment-gated skip beyond the bind itself.
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let before = socks.stats.snapshot();
  let body = b"ping";
  let report = socks.send_to(body, MDNS_V4, ALLOW_BOTH);
  assert!(matches!(report.v4, SendOutcome::Sent { .. }), "{report:?}");

  let after = socks.stats.snapshot();
  assert_eq!(
    after.packets_tx,
    before.packets_tx + 1,
    "one successful send_to syscall must bump packets_tx by exactly one"
  );
  assert_eq!(
    after.bytes_tx,
    before.bytes_tx + body.len() as u64,
    "bytes_tx must rise by exactly the payload length"
  );
}

#[test]
#[cfg(feature = "stats")]
fn a_send_the_kernel_rejects_bumps_send_errors() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  // A payload past the hard ceiling a UDP/IPv4 datagram can ever carry
  // (65535-byte max IP total length, minus a 20-byte IPv4 header and an
  // 8-byte UDP header = 65507) cannot be sent on ANY platform — a protocol
  // limit the kernel enforces before it even looks at routing, unlike the
  // multicast egress `a_multicast_send_reports_one_outcome_per_bound_family`
  // deliberately does NOT assert on because it genuinely varies by host. This
  // is the one deterministic way to force a real `send_to` failure.
  let oversized = vec![0u8; 70_000];
  let before = socks.stats.snapshot();
  let outcome = socks.send_one(Family::V4, &oversized, MDNS_V4, ALLOW_BOTH);
  assert_eq!(outcome, SendOutcome::Failed, "{outcome:?}");

  let after = socks.stats.snapshot();
  assert_eq!(
    after.send_errors,
    before.send_errors + 1,
    "a send_to the kernel rejects must bump send_errors by exactly one"
  );
  assert_eq!(
    after.packets_tx, before.packets_tx,
    "a failed send must never also be counted as a successful transmit"
  );
}

#[test]
#[cfg(feature = "stats")]
fn a_family_mismatch_is_not_counted_as_a_send_error() {
  // `send_one` rejects a destination from the wrong family before attempting
  // any syscall (`send_one_rejects_a_destination_from_another_family` above
  // covers the outcome); this is the companion stats assertion that the
  // caller-error guard is never credited as a network failure — only an
  // ATTEMPTED `send_to` that the kernel actually rejects is.
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let v6_dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5354, 0, 0));
  let before = socks.stats.snapshot();
  assert_eq!(
    socks.send_one(Family::V4, b"body", v6_dst, ALLOW_BOTH),
    SendOutcome::Failed
  );
  let after = socks.stats.snapshot();
  assert_eq!(
    after.send_errors, before.send_errors,
    "no syscall was attempted, so send_errors must not move"
  );
}

// ── rx-side accounting for a consumed-but-unusable datagram ─────────────────
//
// `packets_rx` / `bytes_rx` for a datagram `recv` hands back are bumped by
// `mdns-proto`'s `Endpoint::handle()` on the shared `Arc` (see `recv`'s doc),
// so `Sockets` must not double them — nothing here exercises that path. This
// covers the other one: a datagram the kernel truncated (`MSG_TRUNC`) never
// reaches `handle()` at all, so if `recv` drops it with no accounting — as it
// once did — packets_rx is silently undercounted for exactly the case
// `hick-reactor`'s `count_consumed_oversized` exists to keep reliable.

#[test]
#[cfg(feature = "stats")]
fn a_truncated_datagram_bumps_packets_rx_bytes_rx_and_packets_dropped() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let mut poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");

  // Larger than the buffer `recv` is given below, so the kernel truncates it
  // (MSG_TRUNC) rather than delivering it whole. IPv4 multicast loopback
  // delivery is relied on elsewhere in this file
  // (`readiness_is_recorded_then_cleared_by_draining_to_wouldblock`) as
  // reliable on every supported platform, so this needs no additional skip.
  let big = vec![0xABu8; 4096];
  let report = socks.send_to(&big, MDNS_V4, ALLOW_BOTH);
  assert!(matches!(report.v4, SendOutcome::Sent { .. }), "{report:?}");

  let mut events = mio::Events::with_capacity(8);
  poll
    .poll(&mut events, Some(std::time::Duration::from_millis(500)))
    .expect("poll");
  let mut saw_ours = false;
  for ev in &events {
    if socks.owns(ev.token()) {
      socks.note_readiness(ev);
      saw_ours = true;
    }
  }
  if !saw_ours {
    eprintln!("skipping: no readiness event arrived within 500ms");
    socks.deregister().expect("deregister");
    return;
  }

  let before = socks.stats.snapshot();
  // Far smaller than the 4096-byte send above, so the datagram cannot fit and
  // MSG_TRUNC fires — the one deterministic way to reach `recv`'s
  // consumed-but-unusable branch without depending on a peer's malformed
  // traffic.
  let mut small_buf = vec![0u8; 16];
  // `recv` loops internally past a truncated entry rather than returning it
  // (see its own doc comment) and may end up returning `None` here — what
  // matters is only that the counters moved, not this call's return value.
  let _ = socks.recv(&mut small_buf);

  let after = socks.stats.snapshot();
  assert!(
    after.packets_rx > before.packets_rx,
    "a truncated-but-consumed datagram must still count toward packets_rx"
  );
  assert!(
    after.bytes_rx > before.bytes_rx,
    "a truncated-but-consumed datagram must still count toward bytes_rx"
  );
  assert!(
    after.packets_dropped > before.packets_dropped,
    "a truncated datagram must be counted as a drop"
  );
  socks.deregister().expect("deregister");
}

// ── receive rotation ────────────────────────────────────────────────────────
//
// `readable` clears only on `WouldBlock`, so a family under a sustained on-link
// flood is readable at the top of every tick. A fixed preference then spends
// every tick's whole receive budget on it and the other family's questions,
// answers and conflict probes never reach the proto layer at all — a per-tick
// budget bounds the work inside one tick and decides nothing about the next.

/// With both families continuously readable, selection strictly alternates:
/// neither can hold the other off, however long the flood lasts.
#[test]
fn recv_rotation_alternates_between_two_readable_families() {
  let mut rotor = RecvRotor::new();
  let picks: Vec<Family> = (0..8).filter_map(|_| rotor.pick(true, true)).collect();
  assert_eq!(picks.len(), 8, "both readable: every call must pick one");
  for pair in picks.windows(2) {
    assert_ne!(
      pair[0], pair[1],
      "two consecutive reads from the same family let a flood starve the other: {picks:?}"
    );
  }
}

/// Preference is never idling: the family whose turn it is not still gets read
/// when it is the only readable one, so a single-family endpoint loses nothing.
#[test]
fn recv_rotation_never_idles_a_single_readable_family() {
  let mut rotor = RecvRotor::new();
  for _ in 0..6 {
    assert_eq!(rotor.pick(true, false), Some(Family::V4));
  }
  let mut rotor = RecvRotor::new();
  for _ in 0..6 {
    assert_eq!(rotor.pick(false, true), Some(Family::V6));
  }
}

/// Nothing readable selects nothing and moves nothing: the next readable family
/// must not have lost its turn to a call that read no datagram at all.
#[test]
fn recv_rotation_holds_its_place_when_nothing_is_readable() {
  let mut rotor = RecvRotor::new();
  assert_eq!(rotor.pick(true, true), Some(Family::V4));
  assert_eq!(rotor.pick(false, false), None);
  assert_eq!(rotor.pick(false, false), None);
  assert_eq!(
    rotor.pick(true, true),
    Some(Family::V6),
    "an empty poll must not hand v4 another turn"
  );
}

/// `recv` really consults and advances the rotor. Invisible from the outside on
/// a single-family endpoint — the same socket is read either way — so the
/// cursor itself is what the assertion reads.
#[test]
fn recv_consults_and_advances_the_family_rotor() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");
  assert_eq!(
    socks.recv_rotor_next_for_test(),
    Family::V4,
    "a fresh pair starts at v4"
  );
  socks.set_readable_for_test(Family::V4, true);
  let mut buf = vec![0u8; 2048];
  // Nothing is actually pending, so this drains straight to `WouldBlock` — but
  // it selected v4 on the way, and it is the selection that must rotate.
  assert!(socks.recv(&mut buf).is_none());
  assert_eq!(
    socks.recv_rotor_next_for_test(),
    Family::V6,
    "selecting a family must hand the next turn to the other one"
  );
  socks.deregister().expect("deregister");
}

// ── receive re-arm liveness ─────────────────────────────────────────────────

/// A failed receive re-arm must bring the caller back **with nothing queued**.
///
/// The raw `WSARecvMsg` bypasses mio's `do_io`, so on Windows that re-arm is the
/// only thing that regenerates a readable edge. A failure clears `readable` —
/// keeping it set would spin on a read that fails the same way — which leaves an
/// otherwise idle responder with no queued datagram, no deadline, and no edge:
/// permanently deaf unless the failure itself is what brings the caller back.
#[test]
fn a_failed_receive_rearm_brings_the_caller_back_with_nothing_queued() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");
  assert!(
    !socks.needs_interest_retry(),
    "a healthy pair needs nothing"
  );

  socks.force_rearm_error_for_test(Family::V4, true);
  socks.set_readable_for_test(Family::V4, true);
  let mut buf = vec![0u8; 2048];
  assert!(socks.recv(&mut buf).is_none());

  assert!(
    !socks.has_readable(),
    "readiness must be cleared: keeping it set spins on a read that fails identically"
  );
  assert!(
    socks.needs_interest_retry(),
    "a failed receive re-arm must bring the caller back on the bounded backoff"
  );

  // The recovery is the registration, not the flag: the close of the next tick
  // must actually reregister rather than short-circuit on an interest that
  // never changed.
  let before = socks.reregisters_for_test(Family::V4);
  socks.force_rearm_error_for_test(Family::V4, false);
  socks.end_tick().expect("end_tick");
  assert_eq!(
    socks.reregisters_for_test(Family::V4),
    before.saturating_add(1),
    "the retry must issue a real reregister, which is the re-arm itself"
  );
  assert!(
    !socks.needs_interest_retry(),
    "a re-arm that landed must stop asking to be retried"
  );
  socks.deregister().expect("deregister");
}

/// `WouldBlock` is the **only** thing that clears readiness, and when it does
/// it re-arms in the same operation rather than in two call sites that can
/// drift.
#[test]
fn stop_reading_clears_readiness_and_records_a_failed_rearm_together() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");
  socks.set_readable_for_test(Family::V4, true);
  // A re-arm that succeeds leaves nothing outstanding.
  socks.stop_reading_for_test(Family::V4);
  assert!(!socks.has_readable());
  assert!(!socks.needs_interest_retry());
  // A re-arm that fails clears readiness just the same, and records the retry.
  socks.set_readable_for_test(Family::V4, true);
  socks.force_rearm_error_for_test(Family::V4, true);
  socks.stop_reading_for_test(Family::V4);
  assert!(!socks.has_readable());
  assert!(socks.needs_interest_retry());
  socks.deregister().expect("deregister");
}

// ── transient receive errors ────────────────────────────────────────────────
//
// A non-consuming receive error says nothing about the kernel queue. Clearing
// readiness on one is the mirror of the Windows re-arm hazard, and worse: on
// Unix the re-arm is a no-op, so a family whose flag was cleared without
// draining to `WouldBlock` has nothing at all left to wake it, and whatever was
// queued behind the error sits there until unrelated traffic happens to arrive.

/// Put one datagram in this socket's own receive queue by multicasting to the
/// group it joined, and wait for mio to report the socket readable.
///
/// Returns `false` when this host does not loop multicast back on the interface
/// the fixture bound, which is the one environmental dependency of the test
/// below. Going through a real `Poll` rather than forcing the flag is what
/// makes that wait exist at all: the loopback copy is not necessarily in the
/// receive queue by the time `sendto` returns.
fn seed_one_datagram(socks: &mut Sockets, poll: &mut Poll, body: &[u8]) -> bool {
  let report = socks.send_to(body, MDNS_V4, ALLOW_BOTH);
  if !matches!(report.v4, SendOutcome::Sent { .. }) {
    eprintln!("skipping: the IPv4 multicast send did not reach the kernel ({report:?})");
    return false;
  }
  let mut events = mio::Events::with_capacity(8);
  poll
    .poll(&mut events, Some(std::time::Duration::from_millis(500)))
    .expect("poll");
  let mut saw_ours = false;
  for ev in &events {
    if socks.owns(ev.token()) {
      socks.note_readiness(ev);
      saw_ours = true;
    }
  }
  if !saw_ours {
    eprintln!("skipping: no readiness event arrived within 500ms");
  }
  saw_ours
}

/// Drain up to `MAX_DISCARDED_PER_RECV` datagrams looking for `body`.
fn drain_for(socks: &mut Sockets, body: &[u8]) -> bool {
  let mut buf = vec![0u8; 2048];
  for _ in 0..MAX_DISCARDED_PER_RECV {
    let Some((meta, _)) = socks.recv(&mut buf) else {
      return false;
    };
    if buf.get(..meta.len()) == Some(body) {
      return true;
    }
  }
  false
}

/// One transient error must not strand the datagram queued behind it.
///
/// The control phase is what makes the assertion mean something: it proves this
/// host loops our own multicast back at all, so a failure in the second phase is
/// the error handling and not the environment.
#[test]
fn a_transient_receive_error_still_reads_the_datagram_behind_it() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let mut poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");

  if !seed_one_datagram(&mut socks, &mut poll, b"control") {
    return;
  }
  if !drain_for(&mut socks, b"control") {
    eprintln!("skipping: this host did not loop our own multicast back");
    socks.deregister().expect("deregister");
    return;
  }

  if !seed_one_datagram(&mut socks, &mut poll, b"behind-the-error") {
    return;
  }
  // The next read fails without consuming anything — an `ENOBUFS`, or a Windows
  // `WSAECONNRESET` from an ICMP port-unreachable for one of our own sends.
  socks.force_recv_errors_for_test(Family::V4, 1);
  assert!(
    drain_for(&mut socks, b"behind-the-error"),
    "clearing readiness on an error that consumed nothing strands whatever is \
     queued behind it: edge-triggered readiness generates no second edge"
  );
  socks.deregister().expect("deregister");
}

/// A socket erroring on every read must neither spin nor go silent: readiness
/// stays set so the drain resumes, `has_readable` stops forcing a zero timeout,
/// and the backoff level brings the caller back and grows while it keeps
/// failing.
#[test]
fn repeated_receive_errors_retain_readiness_and_escalate_the_backoff() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");

  socks.set_readable_for_test(Family::V4, true);
  socks.force_recv_errors_for_test(Family::V4, u32::MAX);
  let mut buf = vec![0u8; 2048];

  socks.begin_recv_round();
  assert!(socks.recv(&mut buf).is_none());
  assert!(
    socks.is_readable_for_test(Family::V4),
    "the kernel queue was never proved empty, so the flag must survive"
  );
  assert_eq!(
    socks.recv_error_streak_for_test(Family::V4),
    MAX_RECV_ERRORS_PER_ROUND,
    "the retry inside one round is bounded"
  );
  assert!(
    !socks.has_readable(),
    "a family in error backoff must not force a zero timeout"
  );
  assert_eq!(
    socks.recv_error_backoff_level(),
    1,
    "the first failing round already needs a wakeup — nothing else has one"
  );

  // A new round hands the budget back, so the drain really is retried.
  socks.begin_recv_round();
  assert_eq!(socks.recv_error_streak_for_test(Family::V4), 0);
  assert!(
    socks.has_readable(),
    "the retry happens: the family is selectable again"
  );
  assert!(socks.recv(&mut buf).is_none());
  assert_eq!(
    socks.recv_error_backoff_level(),
    2,
    "a second consecutive failing round costs a longer wait, not a tighter one"
  );

  // Recovery: the socket is empty, so the very next read reaches `WouldBlock`
  // and everything resets.
  socks.begin_recv_round();
  socks.force_recv_errors_for_test(Family::V4, 0);
  assert!(socks.recv(&mut buf).is_none());
  assert!(
    !socks.is_readable_for_test(Family::V4),
    "WouldBlock is what clears readiness"
  );
  assert_eq!(socks.recv_error_backoff_level(), 0);
  socks.deregister().expect("deregister");
}

/// A receive error the socket will keep returning is not retried: the family is
/// abandoned, stops asking for the wakeups a transient backoff pays for, and
/// says so publicly.
///
/// The transient path is the twin
/// (`repeated_receive_errors_retain_readiness_and_escalate_the_backoff`), and
/// keeping both is the point: retrying a structural error leaves the family
/// silently deaf while every accessor still calls it bound, and abandoning a
/// transient one throws away a socket that would have recovered on its own.
#[test]
fn a_permanent_receive_error_gives_up_on_the_family() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  let poll = Poll::new().expect("poll");
  socks
    .register(poll.registry(), Token(10), Token(11))
    .expect("register");

  socks.set_readable_for_test(Family::V4, true);
  socks.force_permanent_recv_error_for_test(Family::V4);
  let mut buf = vec![0u8; 2048];

  socks.begin_recv_round();
  assert!(socks.recv(&mut buf).is_none());
  assert_eq!(
    socks.deaf_families(),
    (true, false),
    "the family must be reported as deaf, not left looking healthy"
  );
  assert!(
    !socks.has_readable(),
    "a family that will never be read again must not force a zero timeout"
  );
  assert_eq!(
    socks.recv_error_backoff_level(),
    0,
    "there is nothing to come back for: this is a give-up, not a backoff"
  );

  // A fresh round does not resurrect it, which is the whole difference from the
  // transient path.
  socks.begin_recv_round();
  assert!(socks.recv(&mut buf).is_none());
  assert_eq!(socks.deaf_families(), (true, false));
  assert_eq!(socks.recv_error_backoff_level(), 0);
  socks.deregister().expect("deregister");
}

/// A transient error must **not** reach the give-up path, or one `ENOBUFS`
/// would cost the family its receive path for good.
#[test]
fn a_transient_receive_error_never_marks_the_family_deaf() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  socks.set_readable_for_test(Family::V4, true);
  socks.force_recv_errors_for_test(Family::V4, u32::MAX);
  let mut buf = vec![0u8; 2048];
  socks.begin_recv_round();
  assert!(socks.recv(&mut buf).is_none());
  assert_eq!(socks.deaf_families(), (false, false));
}

// ── the EINTR retry's stamps ────────────────────────────────────────────────
//
// `send_to` retries once on `EINTR`, which makes one logical send read its
// pre-syscall clocks twice. Which reading survives into `SendOutcome::Sent`
// decides what every downstream consumer believes about the send: the
// interrupted attempt's stamps precede the successful syscall by a whole failed
// syscall plus whatever preempted the thread around it, so carrying them forward
// orders the self-send credit against an instant before the datagram existed and
// tells the core its peers were refreshed before they were.

/// Long enough that no scheduling noise could account for it, short enough to
/// keep the test fast. The stamps are read directly, so nothing here needs it to
/// exceed any TTL.
const EINTR_STALL: Duration = Duration::from_millis(200);

#[test]
fn an_eintr_retry_reports_the_successful_attempts_stamps() {
  let Some(mut socks) = loopback_sockets(ServerOptions::default().with_ipv6(false)) else {
    return;
  };
  if !socks.is_bound_for_test(Family::V4) {
    eprintln!("skipping: IPv4 is not bound on this host");
    return;
  }
  // Attempt one stalls, then reports `EINTR`; attempt two runs clean.
  socks.force_send_eintr_for_test(Family::V4, 1);
  socks.force_send_delays_for_test(Family::V4, &[EINTR_STALL, Duration::ZERO]);

  let before_wall = SystemTime::now();
  let before = StdInstant::now();
  let report = socks.send_to(b"eintr-retry", MDNS_V4, ALLOW_BOTH);
  let SendOutcome::Sent {
    submitted_wall,
    submitted_at,
    wire_at,
  } = report.v4
  else {
    panic!("the retry must carry the datagram: {report:?}");
  };

  assert!(
    submitted_at.saturating_duration_since(before) >= EINTR_STALL,
    "the monotonic pre-syscall stamp must belong to the attempt that succeeded, \
     which begins only after the interrupted one has stalled"
  );
  assert!(
    submitted_wall
      .duration_since(before_wall)
      .is_ok_and(|d| d >= EINTR_STALL),
    "the wall pre-syscall stamp keys self-send ordering; carrying the \
     interrupted attempt's forward would order the credit against an instant a \
     whole stall before the datagram existed"
  );
  assert!(
    wire_at >= submitted_at,
    "the post-syscall stamp still follows its own attempt's pre-syscall one"
  );
  assert_eq!(
    socks.wire_times_for_test(Family::V4).len(),
    1,
    "only the attempt the kernel accepted put bytes on the wire"
  );
}

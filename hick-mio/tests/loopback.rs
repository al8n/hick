//! End-to-end tests over real loopback multicast sockets.
//!
//! Everything else in this crate is unit-level and passes `Mdns` no peer at all.
//! These are the first tests that run two real endpoints against each other, and
//! the only place several paths are reachable: a lookup that resolves a peer's
//! service, an RFC 6762 §10.1 goodbye a peer actually observes, a burst larger
//! than the receive budget, and a lookup torn down while its sub-queries are
//! still in flight.
//!
//! # Every skip is loud, and every wait is bounded
//!
//! Two environment facts are load-bearing and neither is universal, so nothing
//! here is allowed to assume this host's behaviour:
//!
//! * **A family may not bind.** `hick_udp::try_bind_v6` is rejected outright on
//!   some hosts; on others it binds but link-local multicast egress over
//!   loopback fails. [`common::endpoint`] degrades to IPv4-only and prints why,
//!   and no assertion below mentions a family, a socket count, or a send count.
//! * **A host may bind and join fine yet carry nothing.** Every environment-
//!   dependent early return gates on an observed counter and prints a
//!   `skipping:` line naming the reason; none is unconditional, because a skip
//!   that fires on a regression is a test that passes while asserting nothing.
//!   Two probes, for two different failures:
//!   [`common::Endpoint::saw_peer_answers`] (`answers_rx > 0`) for
//!   cross-endpoint **delivery**, and [`common::Endpoint::saw_own_loopback`]
//!   (`packets_rx > 0`) for this endpoint's own multicast **egress**. Whatever
//!   the probe does not excuse is asserted.
//!
//! Every wait is bounded twice over — by the timeout handed to `Poll::poll` and
//! by a wall-clock deadline the loop re-checks each iteration — so no test here
//! can hang. Most go through [`common::pump`] / [`common::pump_pair`]; the
//! edge-trigger test runs its own loop, for the reason its doc comment gives.
//!
//! # Parallelism
//!
//! `--test-threads=1` is **not** required: [`common::bind_lock`] serialises the
//! whole lifetime of every endpoint this binary creates. See that module's docs
//! for why the `SO_REUSEPORT` group makes that necessary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use hick_mio::{Event, ServiceUpdate};

/// Long enough for RFC 6762 §8 probing (three probes 250 ms apart) plus the
/// first announcement, with generous slack for a loaded CI box.
const ADVERTISE_BUDGET: Duration = Duration::from_secs(10);

/// Long enough for a browse to complete the PTR → SRV/TXT → A/AAAA chain
/// against a responder that is already advertising.
const RESOLVE_BUDGET: Duration = Duration::from_secs(10);

/// Register `spec` on `ep` and pump it until the service is advertised.
///
/// `Renamed` counts: it means probing finished and the service is advertised
/// under a rebranded instance label, which every assertion here tolerates
/// because it matches on the service-type suffix rather than the label. This
/// wait is timer-driven, so it resolves without depending on cross-socket
/// **delivery** — but it does depend on the probes reaching the wire at all,
/// which is the one environmental cause of a failure here.
///
/// # Why the failure path is not simply a skip
///
/// Every other test in this file returns early when this returns `false`, so an
/// unconditional skip here would take four of the five green on a regression in
/// probing, announcing, or `ServiceUpdate` emission — including the
/// `assert!(idle, …)` that carries the brief's §10.1 coverage and needs no peer
/// at all. So the two causes are separated the same way every other skip in this
/// file is, by an observed counter: after a failed advertise,
/// [`common::Endpoint::saw_own_loopback`] false means the probes never got out
/// (the environment's fault — skip), and true means they went out, came back,
/// and the state machine still never reached `Established`/`Renamed` (this
/// crate's fault — panic).
fn advertise(ep: &mut common::Endpoint<'_>, spec: hick_mio::ServiceSpec) -> bool {
  ep.mdns.register_service(spec).expect("register_service");
  let advertised = common::pump(ep, ADVERTISE_BUDGET, |ep| {
    ep.seen.iter().any(|e| {
      matches!(
        e,
        Event::Service {
          update: ServiceUpdate::Established | ServiceUpdate::Renamed(_),
          ..
        }
      )
    })
  });
  if !advertised {
    assert!(
      !ep.saw_own_loopback(),
      "{}: the service never reached Established or Renamed in {ADVERTISE_BUDGET:?}, yet this \
       endpoint ingested its own multicast loopback copies — the probes did reach the wire, so \
       probing, announcing or ServiceUpdate emission has regressed",
      ep.label
    );
    eprintln!(
      "skipping: {}: the service never finished probing within {ADVERTISE_BUDGET:?} and this \
       endpoint ingested no datagram at all, not even its own multicast loopback copies: this \
       environment does not carry multicast egress on the loopback interface",
      ep.label
    );
  } else {
    // A relationship that holds on every host, unlike a family count or a
    // `sent` literal: reaching Established/Renamed means at least one real
    // `send_to` already succeeded on this endpoint's own socket (the probes
    // and the announcement), so packets_tx/bytes_tx must have risen. Shared by
    // every test in this file that calls `advertise`, so each one doubles as a
    // regression guard for the tx-side counters, which once stayed at zero no
    // matter how much a responder sent.
    #[cfg(feature = "stats")]
    {
      let s = ep.mdns.stats();
      assert!(
        s.packets_tx > 0,
        "{}: advertised successfully, so packets_tx must be > 0, not 0",
        ep.label
      );
      assert!(
        s.bytes_tx > 0,
        "{}: advertised successfully, so bytes_tx must be > 0, not 0",
        ep.label
      );
    }
  }
  advertised
}

/// The whole point of the crate: one endpoint advertises a service, another
/// browses for it and resolves a complete [`hick_mio::ServiceEntry`].
///
/// This is the only test that proves the register → probe → announce → browse →
/// resolve chain works over a real socket rather than in a state machine.
#[test]
fn two_endpoints_register_browse_and_resolve() {
  const SERVICE: &str = "_hick-mio-it._tcp.local.";
  const INSTANCE: &str = "resolve-me._hick-mio-it._tcp.local.";
  const HOST: &str = "hick-mio-it-host.local.";
  const PORT: u16 = 8080;

  // Every endpoint borrows this, so the compiler keeps it alive until both have
  // closed their sockets and left the multicast group.
  let lock = common::bind_lock();
  let Some(mut responder) = common::endpoint(&lock, "responder") else {
    return;
  };
  let Some(mut client) = common::endpoint(&lock, "client") else {
    return;
  };

  if !advertise(
    &mut responder,
    common::service_spec(SERVICE, INSTANCE, HOST, PORT),
  ) {
    return;
  }

  client
    .mdns
    .browse(common::query_param(SERVICE, Duration::from_secs(5)))
    .expect("browse");

  // ONE selection rule, used by both the wait below and the re-fetch after it.
  // Waiting on one predicate and re-fetching with a weaker one would let the two
  // pick different entries as soon as a second instance of SERVICE existed.
  let has_loopback_addr =
    |e: &hick_mio::ServiceEntry| e.ipv4_addresses().contains(&std::net::Ipv4Addr::LOCALHOST);

  let resolved = common::pump_pair(&mut responder, &mut client, RESOLVE_BUDGET, |_, client| {
    common::resolved_entry(&client.seen, SERVICE, has_loopback_addr).is_some()
  });

  if !resolved {
    if !client.saw_peer_answers() {
      eprintln!(
        "skipping: the client received no answer record at all in {RESOLVE_BUDGET:?}: this \
         environment binds and joins the loopback group but does not deliver across it"
      );
      return;
    }
    panic!("the client must resolve the responder's service");
  }

  let entry =
    common::resolved_entry(&client.seen, SERVICE, has_loopback_addr).expect("resolved entry");
  eprintln!(
    "resolved: instance={} host={} port={} v4={:?} v6={:?}",
    entry.instance_name(),
    entry.host(),
    entry.port(),
    entry.ipv4_addresses(),
    entry.ipv6_addresses()
  );
  // The loopback address is already guaranteed: `has_loopback_addr` is part of
  // the selection rule above, so asserting it again would test nothing. What
  // the selection does NOT pin is the SRV payload.
  assert_eq!(entry.port(), PORT, "wrong port");
  assert!(
    entry.host().as_str().eq_ignore_ascii_case(HOST),
    "wrong host: {}",
    entry.host()
  );
}

/// `shutdown()` drives every RFC 6762 §10.1 goodbye to completion on the wire,
/// and a peer that cached the service observes the retraction.
///
/// The first half is host-independent and always asserted: the withdrawal
/// schedule is timer-driven, so `is_idle()` must become true whether or not
/// anything is listening. The second half — the peer clamping its cached copies
/// to a one-second rescue window and then sweeping them — needs real delivery
/// and the `stats` counter that records it, so it is gated on both and prints
/// its reason when it cannot run.
#[test]
fn shutdown_drives_goodbyes_to_idle_and_a_peer_observes_them() {
  const SERVICE: &str = "_hick-mio-bye._tcp.local.";
  const INSTANCE: &str = "say-bye._hick-mio-bye._tcp.local.";
  const HOST: &str = "hick-mio-bye-host.local.";
  const PORT: u16 = 8081;

  let lock = common::bind_lock();
  let Some(mut responder) = common::endpoint(&lock, "responder") else {
    return;
  };
  let Some(mut observer) = common::endpoint(&lock, "observer") else {
    return;
  };

  if !advertise(
    &mut responder,
    common::service_spec(SERVICE, INSTANCE, HOST, PORT),
  ) {
    return;
  }

  // Give the observer a browse so its cache actually holds the responder's
  // records; a goodbye for a record nothing cached retracts nothing.
  observer
    .mdns
    .browse(common::query_param(SERVICE, Duration::from_secs(5)))
    .expect("browse");
  let observed = common::pump_pair(
    &mut responder,
    &mut observer,
    RESOLVE_BUDGET,
    |_, observer| common::resolved_entry(&observer.seen, SERVICE, |_| true).is_some(),
  );

  #[cfg(feature = "stats")]
  let expirations_before = observer.mdns.stats().cache_expirations;

  responder.mdns.shutdown();
  let idle = common::pump_pair(
    &mut responder,
    &mut observer,
    Duration::from_secs(10),
    |responder, _| responder.mdns.is_idle(),
  );
  assert!(
    idle,
    "shutdown must drive every §10.1 goodbye to completion and reach is_idle"
  );
  eprintln!("shutdown: reached is_idle; the observer resolved the service first: {observed}");

  #[cfg(feature = "stats")]
  {
    // Independent of whether the observer resolved anything: `advertise`
    // above already proved this responder's own sends work, so reaching
    // is_idle must mean at least one §10.1 round was actually delivered.
    // `goodbyes_tx` was once bumped nowhere in the crate; this is the
    // end-to-end guard for that.
    assert!(
      responder.mdns.stats().goodbyes_tx > 0,
      "shutdown reached is_idle, so at least one delivered withdrawal round must have bumped \
       goodbyes_tx"
    );
    if !observed {
      eprintln!(
        "skipping: the peer-side goodbye observation: the observer never resolved the service, \
         so it cached nothing for a TTL=0 record to retract (peer answers seen: {})",
        observer.saw_peer_answers()
      );
      return;
    }
    // A goodbye clamps the matching cache entry to expire one second out
    // (RFC 6762 §10.1 rescue window), so the eviction lands a beat after the
    // retraction itself. Keep both endpoints ticking until the sweep runs.
    let swept = common::pump_pair(
      &mut responder,
      &mut observer,
      Duration::from_secs(5),
      |_, observer| observer.mdns.stats().cache_expirations > expirations_before,
    );
    assert!(
      swept,
      "the peer must evict the withdrawn records after the TTL=0 goodbye: cache_expirations \
       stayed at {expirations_before}"
    );
    eprintln!(
      "goodbye observed: the peer's cache_expirations went {expirations_before} -> {}",
      observer.mdns.stats().cache_expirations
    );
  }
  #[cfg(not(feature = "stats"))]
  {
    let _ = observed;
    eprintln!(
      "note: the peer-side goodbye observation needs --features stats for cache_expirations; \
       only the shutdown-reaches-idle half ran"
    );
  }
}

/// Regression guard for mio's EDGE-TRIGGERED epoll. If `tick` stops at its recv
/// budget while the socket is still readable, `next_timeout` must report zero so
/// the caller's `Poll::poll` returns immediately. Were it to fold to the next
/// timer instead, the rest of the burst would sit unread until that timer fired.
///
/// # How this can actually fail
///
/// The whole burst is sent **before** the loop starts, so no further datagram
/// ever arrives and no further edge is ever produced: after the first drain
/// stops at its budget, `next_timeout` reporting zero is the *only* thing that
/// brings the caller back. The loop below therefore takes `next_timeout` at its
/// word ([`common::Endpoint::step_trusting_next_timeout`]) instead of the
/// `SLICE`-capped [`common::Endpoint::step`] the other tests use — a capped poll
/// would re-enter the drain on its own and mask the defect entirely.
///
/// The safety backstop is fifteen times the deadline, so a wrong `next_timeout`
/// costs one stalled poll and the assertion fails; it can never hang.
///
/// Needs `--features stats` for the `packets_rx` counter — there is no other way
/// to observe how much of the burst was actually ingested.
#[cfg(feature = "stats")]
#[test]
fn a_burst_larger_than_the_recv_budget_drains_past_one_budget() {
  use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
  };

  /// The driver's per-tick receive budget (`driver::RECV_BUDGET`). Consuming
  /// more than this is only reachable if the drain resumed after stopping.
  ///
  /// **Hand-copied, and the two directions of drift are not symmetric.** An
  /// integration test cannot read a private constant. If `driver::RECV_BUDGET`
  /// is ever *raised* above this, `assert_eq!(first, RECV_BUDGET)` below fails
  /// loudly and points straight here. If it is ever *lowered*, `first` comes in
  /// under this value and the test takes its "the kernel buffered fewer than one
  /// budget" skip instead — going green while testing nothing. Anyone changing
  /// `driver::RECV_BUDGET` must change this line with it; a lowered budget will
  /// not tell you.
  const RECV_BUDGET: u64 = 64;
  /// Several budgets' worth, so a single resumed drain is not enough either.
  const BURST: u64 = 400;
  /// How long the drain gets to get past its first budget. A correct zero
  /// timeout does the whole 400-datagram burst in single-digit milliseconds, so
  /// this is ~1000x headroom for a loaded CI box; a `next_timeout` that folded to
  /// a distant deadline instead spends `SAFETY` blocked in the poll that follows
  /// the capped drain, which is 15x this.
  const DRAIN_DEADLINE: Duration = Duration::from_secs(2);
  /// The backstop that stops a wrong `next_timeout` — including `None`, which
  /// means "block indefinitely" — from hanging the test.
  const SAFETY: Duration = Duration::from_secs(30);

  let lock = common::bind_lock();
  let Some(mut mdns) = common::endpoint(&lock, "flood target") else {
    return;
  };

  let Some(sender) = common::loopback_flooder() else {
    return;
  };
  let dst: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353).into();
  let payload = common::minimal_query_datagram("_hick-mio-flood._tcp.local.");
  let mut sent = 0u64;
  for _ in 0..BURST {
    match sender.send_to(&payload, &dst.into()) {
      Ok(_) => sent = sent.saturating_add(1),
      Err(e) => {
        eprintln!("note: the flooding socket stopped sending after {sent} datagrams ({e:?})");
        break;
      }
    }
  }
  if sent <= RECV_BUDGET {
    eprintln!(
      "skipping: only {sent} of {BURST} datagrams left the flooding socket, which cannot exceed \
       the {RECV_BUDGET}-datagram budget under test"
    );
    return;
  }

  // One iteration, which leaves the drain stopped at exactly its budget with the
  // socket still readable — the state the whole rule exists for. Multicast
  // loopback delivery completes inside the sender's `send_to`, so the data is
  // already queued and this poll returns at once; the short cap is here only so
  // an environment that delivered nothing reaches the skip below in two seconds
  // instead of parking on `SAFETY`. Nothing about the rule under test is
  // measured here — that starts at the *next* poll, once the budget is spent.
  mdns.step_trusting_next_timeout(Duration::from_secs(2));
  let first = mdns.mdns.stats().packets_rx;
  if first == 0 {
    eprintln!(
      "skipping: none of the {sent} multicast datagrams were delivered back to the endpoint: \
       this environment binds and joins the loopback group but does not deliver across it"
    );
    return;
  }
  if first < RECV_BUDGET {
    eprintln!(
      "skipping: the kernel buffered only {first} of the {sent} datagrams sent, fewer than the \
       {RECV_BUDGET}-datagram budget, so the drain was never capped and has nothing to resume from"
    );
    return;
  }
  assert_eq!(
    first, RECV_BUDGET,
    "one tick must ingest exactly the recv budget"
  );

  // The rule itself, asserted directly rather than inferred from a stopwatch:
  // with data still sitting in the socket buffer and no further edge coming,
  // zero is the only answer that brings the caller back.
  assert_eq!(
    mdns.mdns.next_timeout(),
    Some(Duration::ZERO),
    "a drain capped at its budget with the socket still readable must report a zero timeout; \
     mio is edge-triggered, so any other answer leaves the rest of the burst unread"
  );

  // And the consequence of that rule, end to end: a caller that trusts
  // `next_timeout` verbatim gets past the first budget promptly. `elapsed` is
  // the load-bearing half — a wrong `next_timeout` still eventually drains the
  // socket, because `tick` re-reads it regardless of what `poll` reported, so
  // the packet count alone does not distinguish the two. What it cannot do is
  // get there in time.
  let started = Instant::now();
  let deadline = started + DRAIN_DEADLINE;
  while mdns.mdns.stats().packets_rx <= RECV_BUDGET && Instant::now() < deadline {
    mdns.step_trusting_next_timeout(SAFETY);
  }
  let elapsed = started.elapsed();
  let rx = mdns.mdns.stats().packets_rx;
  eprintln!("burst: sent {sent}, ingested {rx} (first tick {first}), resumed in {elapsed:?}");
  // The kernel legitimately drops part of a large multicast burst under
  // socket-buffer pressure, so this does not demand all of them.
  assert!(
    rx > RECV_BUDGET && elapsed < DRAIN_DEADLINE,
    "the drain did not resume past its {RECV_BUDGET}-datagram budget within {DRAIN_DEADLINE:?}: \
     packets_rx = {rx} of {sent} sent, after {elapsed:?}"
  );
}

/// Cancelling a lookup whose sub-queries are still in flight must take those
/// sub-queries with it.
///
/// The teardown-with-live-legs path needs a real responder: without one a
/// browse only ever owns its PTR leg, and every deterministic finish has already
/// reaped it by the time the teardown runs. Here the responder's PTR answer
/// makes the lookup start SRV/TXT/A/AAAA resolves, so the cancel lands with
/// several legs running. A leaked leg would keep retransmitting its question
/// with nothing left to consume the answers.
#[cfg(feature = "stats")]
#[test]
fn cancel_lookup_tears_down_sub_queries_that_are_still_in_flight() {
  const SERVICE: &str = "_hick-mio-cancel._tcp.local.";
  const INSTANCE: &str = "cancel-me._hick-mio-cancel._tcp.local.";
  const HOST: &str = "hick-mio-cancel-host.local.";
  const PORT: u16 = 8082;

  let lock = common::bind_lock();
  let Some(mut responder) = common::endpoint(&lock, "responder") else {
    return;
  };
  let Some(mut client) = common::endpoint(&lock, "client") else {
    return;
  };

  if !advertise(
    &mut responder,
    common::service_spec(SERVICE, INSTANCE, HOST, PORT),
  ) {
    return;
  }

  // A long timeout so neither the lookup nor its legs can finish on their own
  // inside the window this test measures.
  let handle = client
    .mdns
    .browse(common::query_param(SERVICE, Duration::from_secs(60)))
    .expect("browse");

  // More than one active query means the PTR answer arrived and the aggregation
  // launched at least one resolve leg — the state the teardown needs.
  let in_flight = common::pump_pair(&mut responder, &mut client, RESOLVE_BUDGET, |_, client| {
    client.mdns.stats().queries_active > 1
  });
  if !in_flight {
    if !client.saw_peer_answers() {
      eprintln!(
        "skipping: the client received no answer record at all in {RESOLVE_BUDGET:?}, so no \
         resolve sub-query was ever launched: this environment does not deliver across the \
         loopback group"
      );
      return;
    }
    panic!("the browse must launch resolve sub-queries once the responder's PTR answer arrives");
  }
  let active_before = client.mdns.stats().queries_active;
  eprintln!("cancel: {active_before} sub-queries were in flight when the lookup was cancelled");

  client.mdns.cancel_lookup(handle);
  assert_eq!(
    client.mdns.stats().queries_active,
    0,
    "cancel_lookup must free every one of the {active_before} sub-queries it owned"
  );

  // And they must stay gone: a leg left in the proto pool would keep its §5.2
  // retry schedule and retransmit its question.
  let leaked = common::pump(&mut client, Duration::from_secs(2), |client| {
    client.mdns.stats().queries_active > 0
  });
  assert!(!leaked, "a cancelled lookup's sub-query came back to life");
  assert!(
    !client
      .seen
      .iter()
      .any(|e| matches!(e, Event::LookupDone { .. })),
    "cancel_lookup must not produce a LookupDone"
  );
}

/// A lookup that finishes by reaching its entry cap while other legs are still
/// running must cancel those legs.
///
/// This is stage 6's own teardown rather than [`Mdns::cancel_lookup`]'s
/// ([`cancel_subqueries`] is shared by both): with `max_entries = 1` the lookup
/// is finished the instant its first instance is emitted, which happens while
/// the PTR browse leg — and usually an address leg — is still live. Every
/// deterministic finish reachable without a responder has already reaped its
/// legs by the time that check runs, so this path needs a real peer.
///
/// [`Mdns::cancel_lookup`]: hick_mio::Mdns::cancel_lookup
/// [`cancel_subqueries`]: hick_mio::Mdns::cancel_lookup
#[cfg(feature = "stats")]
#[test]
fn a_lookup_that_hits_its_entry_cap_cancels_its_remaining_legs() {
  const SERVICE: &str = "_hick-mio-cap._tcp.local.";
  const INSTANCE: &str = "cap-me._hick-mio-cap._tcp.local.";
  const HOST: &str = "hick-mio-cap-host.local.";
  const PORT: u16 = 8083;

  let lock = common::bind_lock();
  let Some(mut responder) = common::endpoint(&lock, "responder") else {
    return;
  };
  let Some(mut client) = common::endpoint(&lock, "client") else {
    return;
  };

  if !advertise(
    &mut responder,
    common::service_spec(SERVICE, INSTANCE, HOST, PORT),
  ) {
    return;
  }

  // A long timeout so the finish can only come from the entry cap, never from
  // the deadline — the deadline path reaps every leg before the finish check.
  client
    .mdns
    .browse(common::query_param(SERVICE, Duration::from_secs(60)).with_max_entries(1))
    .expect("browse");

  // The count entering the tick that finished the lookup. Non-zero is what makes
  // this the teardown-with-LIVE-legs path rather than a teardown that found
  // nothing left to cancel.
  let mut active_at_finish = 0u64;
  let done = common::pump_pair(&mut responder, &mut client, RESOLVE_BUDGET, |_, client| {
    let finished = client
      .seen
      .iter()
      .any(|e| matches!(e, Event::LookupDone { .. }));
    if !finished {
      active_at_finish = client.mdns.stats().queries_active;
    }
    finished
  });
  if !done {
    if !client.saw_peer_answers() {
      eprintln!(
        "skipping: the client received no answer record at all in {RESOLVE_BUDGET:?}, so the \
         lookup never reached its entry cap: this environment does not deliver across the \
         loopback group"
      );
      return;
    }
    panic!("a lookup capped at one entry must finish once that entry resolves");
  }

  assert!(
    common::resolved_entry(&client.seen, SERVICE, |_| true).is_some(),
    "the lookup must have emitted the entry that took it to its cap"
  );
  eprintln!(
    "entry cap: {active_at_finish} sub-queries were still running when the lookup hit its cap"
  );
  // Strictly greater than ONE. The browse's own PTR leg is counted in
  // `queries_active` for the lookup's whole life, so `> 0` would be satisfied by
  // construction and could never detect the degradation this guard exists for:
  // resolve legs no longer being launched, leaving the teardown with only the
  // PTR leg to cancel. The sibling test establishes that same baseline of 1 by
  // gating on `> 1`. Observed here: 5.
  assert!(
    active_at_finish > 1,
    "the lookup finished with only its PTR leg running ({active_at_finish} active), so the \
     teardown had no resolve leg to cancel and this test did not exercise the path it exists for"
  );
  assert_eq!(
    client.mdns.stats().queries_active,
    0,
    "the stage-6 teardown must cancel every sub-query the finished lookup still owned"
  );
}

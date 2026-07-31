use core::cell::Cell;
use std::rc::Rc;

use super::*;

#[compio::test]
async fn local_notify_wakes_a_listener() {
  let n = LocalNotify::new();
  let woken = Rc::new(Cell::new(false));
  let woken_in = woken.clone();
  let n2 = n.clone();
  compio_runtime::spawn(async move {
    n2.listen().await;
    woken_in.set(true);
  })
  .detach();
  // give the listener a chance to register
  compio::time::sleep(std::time::Duration::from_millis(10)).await;
  n.notify();
  compio::time::sleep(std::time::Duration::from_millis(10)).await;
  assert!(woken.get(), "listener woken by notify()");
}

/// regression: a PRESENT (bound) family's `send_to` failure
/// must map to `Retry` (keep the debt, retry until the 2 s ceiling), NOT
/// `WriteOff`. A bound UDP socket can return transient errors whose kind is
/// NOT `WouldBlock`/`Interrupted` (e.g. `ENOBUFS`, route/interface churn);
/// writing that family off would free the route once the OTHER family drained
/// and strand this family's peers on stale positive-TTL records. `WriteOff` is
/// reserved for an ABSENT socket (the caller's `let mut … = WriteOff` default),
/// never produced by this present-socket classifier.
#[test]
fn present_socket_send_error_is_retry_not_writeoff() {
  // Ok → Sent.
  assert_eq!(
    present_socket_send_outcome::<usize>(&Ok(42)),
    WithdrawalSend::Sent,
  );
  // Every non-WouldBlock/Interrupted error kind a bound socket might surface
  // must still be Retry (NEVER WriteOff).
  for kind in [
    std::io::ErrorKind::WouldBlock,
    std::io::ErrorKind::Interrupted,
    std::io::ErrorKind::OutOfMemory, // stands in for ENOBUFS buffer pressure
    std::io::ErrorKind::AddrNotAvailable, // transient interface/route churn
    std::io::ErrorKind::PermissionDenied,
    std::io::ErrorKind::Other,
  ] {
    let res: std::io::Result<usize> = Err(std::io::Error::from(kind));
    assert_eq!(
      present_socket_send_outcome(&res),
      WithdrawalSend::Retry,
      "a present (bound) socket error ({kind:?}) must be Retry, not WriteOff"
    );
  }
}

/// `is_mdns_multicast_dst` must accept BOTH multicast service groups on
/// port 5353 (so the transmit pump fans out to both families) and reject
/// unicast destinations and the wrong port — proto's `multicast_dst()`
/// always hands back the v4 group, so a false negative here would silence
/// the v6 leg of every multicast send.
#[test]
fn is_mdns_multicast_dst_classifies_groups_and_ports() {
  use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

  // v4 group on 5353 → true
  assert!(is_mdns_multicast_dst(SocketAddr::V4(SocketAddrV4::new(
    Ipv4Addr::new(224, 0, 0, 251),
    5353
  ))));
  // v6 group on 5353 → true
  assert!(is_mdns_multicast_dst(SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb),
    5353,
    0,
    0
  ))));
  // unicast on 5353 → false
  assert!(!is_mdns_multicast_dst(SocketAddr::V4(SocketAddrV4::new(
    Ipv4Addr::new(192, 168, 1, 5),
    5353
  ))));
  // v4 group on the wrong port → false
  assert!(!is_mdns_multicast_dst(SocketAddr::V4(SocketAddrV4::new(
    Ipv4Addr::new(224, 0, 0, 251),
    53
  ))));
}

#[test]
fn state_construction_is_empty() {
  let s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  assert_eq!(s.services.len(), 0);
  assert_eq!(s.queries.len(), 0);
  assert!(s.completed_withdrawals.is_empty());
}

#[test]
fn fire_timeouts_runs_without_panic_on_empty_state() {
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.fire_timeouts(std::time::Instant::now());
}

#[compio::test]
async fn endpoint_inner_can_be_constructed_and_dropped() {
  let cfg = mdns_proto::EndpointConfig::default();
  let inner = EndpointInner::new(cfg, 1500, 9000);
  // notify can be cloned and listened on without panicking
  let n = inner.notify.clone();
  // sanity: listening + notifying once doesn't deadlock
  let h = compio_runtime::spawn(async move {
    n.listen().await;
  });
  compio::time::sleep(std::time::Duration::from_millis(5)).await;
  inner.notify.notify();
  h.await.ok();
  drop(inner);
}

/// Driver-liveness invariant: `mark_dirty` is the durable
/// signal a handle op uses to guarantee the driver re-settles even if the
/// paired `notify` is lost across a send-await. This pins the mechanics the run
/// loop's PRE-PARK `inner.dirty.replace(false)` + `force_now` depend on:
/// `dirty` starts clear, `mark_dirty` sets it, and the consume both reads the
/// pending state AND clears it. Critically the consume happens at the PARK
/// BOUNDARY (after every awaitable pump), not at loop entry — a
/// loop-entry sample misses a `mark_dirty` landing during a late pump await
/// (e.g. the goodbye send); reading at the boundary, with no `.await` between
/// the read and arming the `select!` listener, closes that window with no gap.
#[test]
fn mark_dirty_sets_a_durable_level_flag_consumed_by_replace() {
  let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  // Fresh endpoint: no handle work yet.
  assert!(!inner.dirty.get(), "dirty must start clear");

  // A handle op marks the endpoint dirty (durably — independent of whether any
  // listener is armed, unlike a bare notify).
  inner.mark_dirty();
  assert!(inner.dirty.get(), "mark_dirty must set the level flag");

  // The driver's pre-park consume reads `true` (→ force_now re-settle) and
  // clears it in one step.
  let force_now = inner.dirty.replace(false);
  assert!(
    force_now,
    "the pre-park decision must observe the pending work"
  );
  assert!(
    !inner.dirty.get(),
    "consuming the flag clears it so a clean iteration can park"
  );

  // A second consume with no intervening mark sees nothing — no spurious
  // force_now / busy-spin once the work is serviced.
  assert!(
    !inner.dirty.replace(false),
    "no work created since last consume → not dirty → driver may park"
  );

  // Work created AFTER the consume (e.g. a handle op racing a late pump await)
  // re-sets the flag, so the NEXT pre-park consume observes it rather than
  // losing it.
  inner.mark_dirty();
  assert!(
    inner.dirty.replace(false),
    "work created after the previous consume must be observed at the next park boundary"
  );
}

/// A short datagram (3 bytes, QR=1 set) from a non-5353 source must hit the
/// untrusted-response pre-drop path and count packets_rx +1, bytes_rx +len,
/// packets_dropped +1 — with NO double-count (proto's handle() is never
/// reached). Drives `State::handle_datagram` directly; no socket bind needed.
#[cfg(feature = "stats")]
#[test]
fn pre_drop_short_qr1_counts_rx_and_dropped_exactly_once() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  // Make the source address on-link (loopback subnet) so only the untrusted-
  // response gate fires, not the §11 off-link gate.
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
  s.bound_interface = 1;

  // 3-byte body: byte 2 = 0x80 → QR=1. Too short for a valid DNS message.
  let data: Vec<u8> = vec![0x00, 0x00, 0x80];
  let len = data.len() as u64;

  let meta = RecvMeta::new(
    SocketAddr::from(([127, 0, 0, 1], 40000)), // non-5353 source port → untrusted
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    1,
    Some(255), // on-link TTL
    None,
    len as usize,
  );
  s.handle_datagram(&meta, &data);

  let snap = s.stats.snapshot();
  assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
  assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
}

/// A well-formed 12-byte DNS response header (QR=1) from a non-5353 source
/// must count packets_rx +1, bytes_rx +len, packets_dropped +1 exactly once.
/// Self-send credit ring must remain untouched.
#[cfg(feature = "stats")]
#[test]
fn pre_drop_untrusted_qr1_response_counts_rx_and_dropped_exactly_once() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
  s.bound_interface = 1;

  // Minimal 12-byte DNS response header: QR=1 + AA (byte 2 = 0x84).
  let data: Vec<u8> = vec![
    0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  let len = data.len() as u64;

  assert!(s.recent_sends.is_empty(), "no prior self-send credits");

  let meta = RecvMeta::new(
    SocketAddr::from(([127, 0, 0, 1], 54321)), // non-5353 → untrusted
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    1,
    Some(255), // on-link
    None,
    len as usize,
  );
  s.handle_datagram(&meta, &data);

  // Self-send tracker must be untouched (never reached).
  assert!(
    s.recent_sends.is_empty(),
    "self-send credit ring must be untouched"
  );

  let snap = s.stats.snapshot();
  assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
  assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
}

/// Off-link datagrams (TTL ≠ 255, source outside local subnets) must count
/// packets_rx +1, bytes_rx +len, packets_dropped +1 exactly once.
#[cfg(feature = "stats")]
#[test]
fn pre_drop_off_link_datagram_counts_rx_and_dropped_exactly_once() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
  s.bound_interface = 1;

  // QR=0 query body — so only the §11 off-link gate fires, not the untrusted-
  // response gate.
  let data: Vec<u8> = vec![
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  let len = data.len() as u64;

  let meta = RecvMeta::new(
    SocketAddr::from(([203, 0, 113, 5], 5353)),
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    1,
    Some(64), // off-link: TTL != 255
    None,
    len as usize,
  );
  s.handle_datagram(&meta, &data);

  let snap = s.stats.snapshot();
  assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
  assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
}

/// §11 regression guard: a datagram whose TTL/hop-limit is < 255 and whose
/// source address falls outside the cached local-subnet snapshot must be
/// dropped by `handle_datagram` before it ever reaches `endpoint.handle`.
/// We can't observe the proto-side call externally, so the assertion is
/// "the call returns without panicking on a deliberately bogus 12-byte
/// body" — which is only true if the §11 gate early-returns first.
#[test]
fn handle_datagram_drops_off_link_packet() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
  s.bound_interface = 1;
  let meta = RecvMeta::new(
    SocketAddr::from(([8, 8, 8, 8], 5353)),
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    1,
    Some(64), // off-link: not 255
    None,
    12,
  );
  let data = vec![0u8; 12];
  // The §11 gate must drop this off-link datagram silently — no panic,
  // and crucially no unwind from `endpoint.handle` chewing on the bogus
  // 12-byte header (which would happen if the gate let it through).
  s.handle_datagram(&meta, &data);
}

/// Drive a service through probe + announce until it advertises its host
/// record (goodbye ownership latched), so a withdrawal snapshot is non-empty.
/// Shared by the State-seam withdrawal tests below.
#[cfg(test)]
fn establish_service(
  s: &mut State,
  handle: ServiceHandle,
  t0: std::time::Instant,
) -> std::time::Instant {
  let mut t = t0;
  let mut buf = vec![0u8; 4096];
  for _ in 0..40 {
    t += Duration::from_millis(300);
    let ctx = s.services.get_mut(&handle).unwrap();
    let _ = ctx.proto.handle_timeout(t);
    while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
      ctx.proto.note_transmit_outcome(
        t,
        mdns_proto::TransmitDelivery::new(
          mdns_proto::FamilyDelivery::Delivered,
          mdns_proto::FamilyDelivery::Delivered,
        ),
      );
    }
  }
  assert!(
    s.services
      .get(&handle)
      .map(|c| c.proto.advertises_host())
      .unwrap_or(false),
    "service must advertise at least one record before withdrawal"
  );
  t
}

/// `begin_service_withdrawal` MUST: (a) KEEP the driver-side `ServiceCtx`
/// (marked `errored`) so a queued `Conflict` still reaches the host, (b) hold
/// the proto-layer route (so a same-name re-register is rejected) while the
/// withdrawal is in flight, and (c) on completion (`drain_completed_withdrawals`)
/// free the route + GC the ctx so the same instance name is re-registerable —
/// the RFC 6762 §10.1 graceful-withdrawal contract under the endpoint-owned
/// lifecycle. (The TTL=0 goodbye bytes + sibling retention + resend schedule are
/// covered by the proto-level withdrawal tests; this is the driver-State seam.)
#[test]
fn begin_service_withdrawal_holds_name_then_frees_on_completion() {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec, error::RegisterServiceError};

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let t0 = std::time::Instant::now();

  let stype = Name::try_from_str("_gb._tcp.local.").unwrap();
  let inst = Name::try_from_str("G._gb._tcp.local.").unwrap();
  let host = Name::try_from_str("g.local.").unwrap();
  let mut recs = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 1234, 120);
  recs.add_a([127, 0, 0, 1].into());
  let handle = s.test_register_service(ServiceSpec::new(recs), t0).unwrap();
  let mut t = establish_service(&mut s, handle, t0);

  // Begin the withdrawal: the ctx is KEPT (errored) and the route is held.
  s.begin_service_withdrawal(handle, t);
  assert!(
    s.services.get(&handle).map(|c| c.errored).unwrap_or(false),
    "begin_service_withdrawal must keep the ctx and mark it errored"
  );

  // While the withdrawal holds the route, the same instance name is rejected.
  let mut dup = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 1234, 120);
  dup.add_a([127, 0, 0, 1].into());
  assert!(
    matches!(
      s.test_register_service(ServiceSpec::new(dup), t),
      Err(RegisterServiceError::NameAlreadyRegistered(_))
    ),
    "a same-name registration must be rejected while the withdrawal holds the name"
  );

  // Drive the withdrawal to completion. With no sockets every round fails to
  // deliver (`poll_one_withdrawal` writes the goodbye; we report not-delivered),
  // so the endpoint force-completes at its 2 s anti-pin ceiling; then
  // `drain_completed_withdrawals` frees the route + GCs the ctx.
  let mut scratch = vec![0u8; 4096];
  let mut completed = false;
  for _ in 0..64 {
    t += Duration::from_millis(250);
    while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
      // No sockets bound in this State-level test: model BOTH families as
      // transiently undeliverable (Retry) so the per-family budget stays intact
      // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
      // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
      // instead, defeating the ceiling assertion.)
      s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
    }
    s.drain_completed_withdrawals(t);
    if !s.services.contains_key(&handle) {
      completed = true;
      break;
    }
  }
  assert!(
    completed,
    "the withdrawal must complete (route freed + driver ctx GC'd) by its 2 s \
       anti-pin ceiling when no family can deliver"
  );

  // The proto-layer route slot must now be freed: re-registering the same
  // instance name must succeed.
  let mut recs2 = ServiceRecords::new(stype, inst, host, 1234, 120);
  recs2.add_a([127, 0, 0, 1].into());
  assert!(
    s.test_register_service(ServiceSpec::new(recs2), t).is_ok(),
    "the proto-layer route slot must be freed once the withdrawal completes"
  );
}

/// `Service::drop` must NOT retire the service synchronously — it only flags
/// `cancelled` (via `flag_service_unregistered`). The driver's post-pump
/// `sweep_cancelled_services` is what begins the endpoint-owned §10.1
/// withdrawal. This split is load-bearing: it lets a send that was in flight
/// when the handle dropped latch its records (via `note_service_transmit_outcome`)
/// BEFORE the withdrawal snapshot is taken, so a service dropped mid-send still
/// withdraws every record it actually put on the wire.
#[compio::test]
async fn drop_defers_withdrawal_to_driver_sweep() {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec};
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let t0 = std::time::Instant::now();
  let stype = Name::try_from_str("_sw._tcp.local.").unwrap();
  let inst = Name::try_from_str("s._sw._tcp.local.").unwrap();
  let host = Name::try_from_str("s.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 1234, 120);
  recs.add_a([127, 0, 0, 1].into());
  let handle = s.test_register_service(ServiceSpec::new(recs), t0).unwrap();
  let t = establish_service(&mut s, handle, t0);

  // What `Service::drop` does — flag only, no retirement.
  s.flag_service_unregistered(handle);
  assert!(
    s.services.contains_key(&handle),
    "drop must NOT remove the service synchronously"
  );
  assert!(
    !s.services.get(&handle).map(|c| c.errored).unwrap_or(true),
    "drop must NOT begin the withdrawal synchronously — the driver sweep does"
  );
  assert!(
    s.services
      .get(&handle)
      .map(|c| c.cancelled)
      .unwrap_or(false),
    "the service must be flagged cancelled"
  );

  // `has_pending_withdrawal` must report the cancelled-but-unswept service so
  // the driver forces an immediate wake instead of parking (the lost-notify
  // guard): a drop's `notify` can be lost mid-`send_to`, so the forced timer
  // is what guarantees the next iteration sweeps + begins the withdrawal.
  assert!(
    s.has_pending_withdrawal(),
    "a cancelled-but-unswept service must report a pending withdrawal"
  );

  // What the driver's post-pump sweep does — begin the endpoint-owned
  // withdrawal: the ctx is KEPT (errored) and the route is held by the endpoint.
  let swept = s.sweep_cancelled_services(t);
  assert!(swept, "sweep must report it retired a cancelled service");
  assert!(
    s.services.get(&handle).map(|c| c.errored).unwrap_or(false),
    "sweep must begin the withdrawal (ctx kept, marked errored)"
  );
  assert!(
    !s.has_pending_withdrawal(),
    "after the sweep the cancelled service is already withdrawing (errored), so \
       it is no longer reported as an unswept pending withdrawal"
  );
}

/// Regression: a service handle dropped AFTER the normal
/// cancellation sweep — racing the last-handle shutdown drain — must still be
/// swept into a §10.1 withdrawal. The shutdown loop now sweeps each iteration
/// (after the drain, before deciding whether any remain), so the raced drop is
/// never GC'd without its TTL=0 goodbye.
#[test]
fn shutdown_loop_sweeps_a_drop_that_raced_the_prior_sweep() {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec};
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let t = std::time::Instant::now();

  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Svc._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let a = s.test_register_service(ServiceSpec::new(recs), t).unwrap();

  // A normal sweep finds nothing — A's handle is still held.
  assert!(
    !s.sweep_cancelled_services(t),
    "nothing is cancelled before the drop"
  );

  // A's handle drops AFTER that sweep — the exact race the shutdown loop closes.
  s.flag_service_unregistered(a);
  assert!(
    s.has_pending_withdrawal(),
    "the post-sweep drop is an unswept pending withdrawal"
  );

  // The shutdown loop's per-iteration sweep retires the raced drop into a
  // withdrawal BEFORE deciding whether any remain — without it the loop would
  // exit and GC the service with no goodbye.
  assert!(
    s.sweep_cancelled_services(t),
    "the shutdown-loop sweep retires the raced cancellation"
  );
  assert!(
    s.next_withdrawal_deadline().is_some(),
    "a withdrawal now exists for the raced drop — not GC'd goodbye-less"
  );
}

/// Regression: a service DROPPED with an undrained
/// update (e.g. an `Established` the app never read) must still be GC'd when its
/// withdrawal completes. The ctx GC is now UNCONDITIONAL — there is no
/// pending-update defer arm to leak the slot — and the undrained update lives in
/// the handle-owned mailbox, so discarding the (dropped) handle's mailbox loses
/// nothing. This closes the original leak class at the root: the `services`
/// map cannot grow without bound under register/establish/drop churn.
#[test]
fn dropped_ctx_with_undrained_update_is_gc_d_not_leaked() {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec};
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let t = std::time::Instant::now();

  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Svc._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let a = s.test_register_service(ServiceSpec::new(recs), t).unwrap();

  // An update the app never drained (it dropped the handle without reading). It
  // lives in the handle-owned mailbox now, not the ctx.
  s.services
    .get(&a)
    .unwrap()
    .mailbox
    .borrow_mut()
    .push_update(ServiceUpdate::Established);

  // Drop the handle (cancel) WITHOUT draining the update; the driver sweep then
  // begins the (empty, never-announced) withdrawal, which completes on the first
  // drain.
  s.flag_service_unregistered(a);
  s.sweep_cancelled_services(t);
  s.drain_completed_withdrawals(t);

  assert!(
    !s.services.contains_key(&a),
    "a cancelled ctx with an undrained update must be GC'd UNCONDITIONALLY on \
       withdrawal completion, never deferred and leaked"
  );
}

/// Regression: a ctx
/// whose withdrawal already completed and is THEN dropped must be GC'd — and its
/// terminal `Conflict`, recorded in the HANDLE-OWNED mailbox, must STILL be
/// observable by a live reader. The mailbox outlives the ctx, so unconditional
/// ctx GC at withdrawal completion cannot lose the terminal: a still-live
/// `Service` handle drains it. This is the observable property the old
/// `route_freed` drop-GC defer existed to protect, now structural.
#[test]
fn completed_ctx_gc_keeps_terminal_observable_by_live_reader() {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec};
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let t = std::time::Instant::now();

  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Svc._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let a = s.test_register_service(ServiceSpec::new(recs), t).unwrap();

  // The live reader's clone of the handle-owned mailbox (what the `Service`
  // handle holds). The internal retirement records the terminal `Conflict` here.
  let reader_mailbox = Rc::clone(&s.services.get(&a).unwrap().mailbox);

  // Simulate an internally-retired service: record the terminal `Conflict` in
  // the reserved slot and begin its (empty, never-announced) withdrawal, which
  // completes on the first drain.
  reader_mailbox
    .borrow_mut()
    .set_terminal(ServiceUpdate::Conflict);
  s.begin_service_withdrawal(a, t);
  s.drain_completed_withdrawals(t);

  // The ctx is GC'd UNCONDITIONALLY on completion (no defer) ...
  assert!(
    !s.services.contains_key(&a),
    "the completed ctx is GC'd unconditionally — no pending-terminal defer"
  );
  // ... yet the reserved `Conflict` is STILL observable by the live reader,
  // because the mailbox is handle-owned and outlives the ctx.
  assert!(
    matches!(
      reader_mailbox.borrow_mut().drain_for_test(),
      Some(ServiceUpdate::Conflict)
    ),
    "the terminal Conflict must survive the immediate ctx GC and be drainable \
       by a live reader (mailbox outlives the ctx)"
  );
}

/// Task-required: a FULL non-terminal ring plus a reserved terminal must both
/// survive an immediate ctx GC and be fully drainable by a live reader. Fill the
/// ring to the cap WITHOUT draining, `set_terminal(Conflict)`, complete the
/// withdrawal so the ctx is GC'd immediately, then drain from the live handle —
/// the `Conflict` IS observed and the ctx is gone from `services`.
#[test]
fn terminal_survives_full_mailbox_and_immediate_ctx_gc() {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec};
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let t = std::time::Instant::now();

  let recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("Svc._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  let a = s.test_register_service(ServiceSpec::new(recs), t).unwrap();

  // The live reader's clone of the handle-owned mailbox.
  let reader_mailbox = Rc::clone(&s.services.get(&a).unwrap().mailbox);

  // Fill the non-terminal ring to the cap (no draining) and reserve the terminal.
  {
    let mut mb = reader_mailbox.borrow_mut();
    mb.fill_non_terminal_to_cap_for_test();
    mb.set_terminal(ServiceUpdate::Conflict);
    assert_eq!(
      mb.non_terminal_len(),
      crate::service::SERVICE_UPDATE_CAPACITY,
      "the non-terminal ring is full"
    );
    assert!(mb.has_terminal(), "the terminal slot is reserved");
  }

  // Complete the (empty, never-announced) withdrawal so the ctx is GC'd at once.
  s.begin_service_withdrawal(a, t);
  s.drain_completed_withdrawals(t);
  assert!(
    !s.services.contains_key(&a),
    "the ctx must be gone from `services` after the withdrawal completes"
  );

  // Drain from the LIVE handle: every non-terminal first, then the reserved
  // Conflict — none lost to the immediate ctx GC.
  let mut non_terminal = 0usize;
  let mut got_terminal = false;
  while let Some(upd) = reader_mailbox.borrow_mut().drain_for_test() {
    match upd {
      ServiceUpdate::Conflict => got_terminal = true,
      _ => non_terminal += 1,
    }
  }
  assert_eq!(
    non_terminal,
    crate::service::SERVICE_UPDATE_CAPACITY,
    "every buffered non-terminal update survives the ctx GC"
  );
  assert!(
    got_terminal,
    "the reserved Conflict IS observed by the live reader after the immediate \
       ctx GC (mailbox is handle-owned and outlives the ctx)"
  );
}

/// Endpoint-owned-withdrawal replacement survival (supersedes the old free-name
/// goodbye BARRIER test). Under `with_probe_unique_names(false)` a same-name
/// replacement would announce a positive TTL directly (no §8.1 probe) — exactly
/// the configuration in which a stale TTL=0 goodbye could be overtaken. The old
/// compio driver enforced ordering with a pre-transmit barrier; the endpoint now
/// enforces it STRUCTURALLY — it KEEPS the route (holding the name) for the whole
/// §10.1 withdrawal, so a same-name `register_service` is REJECTED until the
/// goodbye completes and frees the name. No replacement can announce ahead of the
/// withdrawal because no replacement can even be registered until it is done.
///
/// Driven through `State` directly (no sockets — the compio run loop cannot be
/// stepped deterministically). The full graceful path is exercised:
/// `flag_service_unregistered` (what `Service::drop` does) → the driver's
/// `sweep_cancelled_services` (begins the withdrawal) → `poll_one_withdrawal` /
/// `note_withdrawal_result` / `drain_completed_withdrawals` (the run loop's
/// `drain_withdrawals`). With no bound family every round fails to deliver, so the
/// withdrawal force-completes at its 2 s anti-pin ceiling; the name-held →
/// name-freed observation is identical either way.
#[test]
fn same_name_replacement_is_rejected_until_withdrawal_completes() {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec, error::RegisterServiceError};

  let cfg = mdns_proto::EndpointConfig::new().with_probe_unique_names(false);
  let mut s = State::new(cfg, 1500, 9000);
  let t0 = std::time::Instant::now();

  let mk = || {
    let mut r = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      Name::try_from_str("repl._ipp._tcp.local.").unwrap(),
      Name::try_from_str("repl.local.").unwrap(),
      631,
      120,
    );
    r.add_a([192, 168, 1, 10].into());
    ServiceSpec::new(r)
  };

  // 1. Register A and drive it to an announced state so its withdrawal snapshot
  //    is non-empty (records were confirmed-emitted).
  let a = s.test_register_service(mk(), t0).unwrap();
  let mut t = establish_service(&mut s, a, t0);

  // 2. Drop A: flag cancelled (what `Service::drop` does), then the driver's
  //    post-pump sweep begins the endpoint-owned withdrawal (name held).
  s.flag_service_unregistered(a);
  s.sweep_cancelled_services(t);
  assert!(
    s.services.get(&a).map(|c| c.errored).unwrap_or(false),
    "the sweep must begin the withdrawal and keep the ctx (errored)"
  );

  // 3. While the withdrawal is in flight the SAME name must be rejected.
  assert!(
    matches!(
      s.test_register_service(mk(), t),
      Err(RegisterServiceError::NameAlreadyRegistered(_))
    ),
    "a same-name registration must be rejected while the withdrawal holds the name"
  );

  // 4. Drive the withdrawal to completion (no family → force-finished at the 2 s
  //    anti-pin ceiling); `drain_completed_withdrawals` then frees the route + GCs
  //    the ctx.
  let mut scratch = vec![0u8; 4096];
  let mut completed = false;
  for _ in 0..64 {
    t += Duration::from_millis(250);
    while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
      // No sockets bound in this State-level test: model BOTH families as
      // transiently undeliverable (Retry) so the per-family budget stays intact
      // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
      // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
      // instead, defeating the ceiling assertion.)
      s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
    }
    s.drain_completed_withdrawals(t);
    if !s.services.contains_key(&a) {
      completed = true;
      break;
    }
  }
  assert!(
    completed,
    "the withdrawal must complete (route freed + driver ctx GC'd) by its 2 s \
       anti-pin ceiling when no family can deliver"
  );

  // 5. The name is freed → a same-name replacement now registers successfully.
  s.test_register_service(mk(), t)
    .expect("the same name must be re-registerable once the withdrawal completes");
}

// NOTE: the driver-goodbye-queue + barrier seam tests
// (`remove_service_queues_goodbye_and_frees_proto_slot`,
// `shutdown_drain_sweeps_and_flushes_all_bursts`, `poll_deadline_sees_pending_goodbye`,
// `goodbye_round_with_no_send_keeps_budget_and_backs_off`,
// `goodbye_round_with_a_send_spends_one_and_clears_barrier`, and
// `gc_force_clears_expired_barrier_and_drops_sent_entries`) were REMOVED in the
// endpoint-owned-withdrawal migration. They asserted against the deleted
// driver-side `goodbyes` queue + `sent_once` transmit barrier (the `PendingGoodbye`
// struct, `advance_goodbye_after_send` Part-A re-arm, the `gc_goodbyes` `expires_at`
// anti-pin force-clear, `has_pending_barrier`, `take_shutdown_goodbyes`, and the
// `poll_deadline` goodbye loop). The endpoint now owns the resend schedule, the
// spend/re-arm bookkeeping, the 2 s anti-pin ceiling, and the goodbye-deadline
// contribution to `poll_timeout` — covered by the proto-level withdrawal tests
// (`note_withdrawal_result` spend/backoff, `drain_completed_withdrawals` ceiling,
// `poll_withdrawal_transmit` sibling retention). The
// `begin_service_withdrawal_holds_name_then_frees_on_completion` test above is the
// driver-State-seam observation that a withdrawal HOLDS the name and frees it on
// completion, and `drop_defers_withdrawal_to_driver_sweep` covers the deferred-
// snapshot timing the old `drop_defers_goodbye_to_driver_sweep` test guarded.

// The per-kind coalescing + drop-oldest backstop + reserved-terminal contract
// now lives in `crate::service::ServiceMailbox`; its unit tests
// (`mailbox_coalesces_established_and_renamed_by_kind`,
// `mailbox_rename_churn_coalesces_within_cap`, `mailbox_hard_cap_drops_oldest`,
// `mailbox_terminal_reserved_under_non_terminal_pressure`, …) own that surface.
// The driver-side `push_service_update_coalesced` free function + its
// `coalesce_*` tests were removed in the handle-owned-mailbox migration: the
// driver now routes proto updates straight into the mailbox
// (`push_update` for non-terminal kinds, `set_terminal` for Conflict/HostConflict),
// so there is no driver-local deque to coalesce.

/// transmit-liveness regression: a service whose records cannot be
/// encoded into the configured `max_payload` must NOT silently stall. The
/// proto PRESERVES the un-encodable pending transmit (re-offering it every
/// `poll_transmit`), so the prior `if let Ok(Some(_))` arm — which treated the
/// `Err(TransmitError::BufferTooSmall)` like `Ok(None)` — left the service
/// stuck below `Established` forever with no `ServiceUpdate` ever delivered.
///
/// The fix counts consecutive encode failures per service and, at
/// [`MAX_CONSECUTIVE_ENCODE_ERRORS`], escalates to `ServiceUpdate::Conflict`
/// (recorded in the handle-owned mailbox's reserved terminal slot, NOT dropped)
/// and flags the service `errored` so it is skipped by every later proto-polling
/// pump. This test drives `poll_one_transmit` with a deliberately tiny scratch
/// buffer and asserts: (a) the failure counter climbs one per call, (b) at the
/// threshold the reserved terminal `Conflict` is set and `errored` is set, and
/// (c) a subsequent `poll_one_transmit` skips the errored service (returns `None`
/// when it's the only one) rather than re-polling its dead proto.
#[test]
fn oversized_service_escalates_to_conflict_not_silent_stall() {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec};

  // `max_payload` is irrelevant to `poll_one_transmit` (it takes `scratch`
  // explicitly); a real-record service is what matters.
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1, 9000);
  let now = std::time::Instant::now();

  // A realistic record set: PTR + SRV (implied by `new`) + TXT + A + AAAA.
  let stype = Name::try_from_str("_ovf._tcp.local.").unwrap();
  let inst = Name::try_from_str("Oversized._ovf._tcp.local.").unwrap();
  let host = Name::try_from_str("oversized.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 8080, 120);
  recs.add_a([192, 168, 1, 42].into());
  recs.add_aaaa([0xfe80, 0, 0, 0, 0, 0, 0, 0x1234].into());
  recs.add_txt_segment(b"path=/health".to_vec());
  let handle = s
    .test_register_service(ServiceSpec::new(recs), now)
    .unwrap();

  // A 1-byte scratch buffer guarantees `proto.poll_transmit` returns
  // `Err(BufferTooSmall)` once a probe is queued (a probe is many bytes).
  // Verified empirically: the proto needs the probe PENDING first — a fresh
  // service is in `Init` with no queued transmit, so the first few
  // `poll_one_transmit` calls would see `Ok(None)` (reset to 0). We therefore
  // PRIME the lifecycle: advance the clock and `fire_timeouts` until the proto
  // pushes its first probe (Init → Probing(0) → probe pending), detected by
  // the failure counter ticking to 1. Mirrors the time-advancing drive loop
  // the existing `remove_service` / shutdown tests use, but stops at the first
  // encode failure instead of delivering the transmit.
  let mut scratch = [0u8; 1];
  let mut t = now;
  let mut armed = false;
  for _ in 0..40 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    // A failing poll increments `encode_failures`; an `Ok(None)` (nothing
    // pending yet) resets it to 0. Once the probe is queued this sticks at 1.
    let pumped = s.poll_one_transmit(t, &mut scratch);
    assert!(
      pumped.is_none(),
      "an un-encodable transmit must never be returned as a phantom send"
    );
    if s.services.get(&handle).unwrap().encode_failures == 1 {
      armed = true;
      break;
    }
  }
  assert!(
    armed,
    "the proto must queue a probe that fails to encode into the 1-byte scratch"
  );

  // With the probe queued and `Err` preserving it (the proto does NOT pop an
  // un-encodable transmit), each further `poll_one_transmit` must fail again
  // and bump the counter by exactly one — no `fire_timeouts` needed between
  // them. Drive it the rest of the way to the escalation threshold.
  for expected in 2..=MAX_CONSECUTIVE_ENCODE_ERRORS {
    let pumped = s.poll_one_transmit(t, &mut scratch);
    assert!(
      pumped.is_none(),
      "an un-encodable transmit must never be returned as a phantom send \
         (failure #{expected})"
    );
    assert_eq!(
      s.services.get(&handle).unwrap().encode_failures,
      expected,
      "each failing poll must increment encode_failures by one"
    );
  }

  // At the threshold the service must be escalated: the reserved terminal
  // `Conflict` set in the handle-owned mailbox, and the terminal `errored` flag
  // set on the ctx.
  {
    let ctx = s.services.get(&handle).unwrap();
    assert!(
      ctx.errored,
      "reaching MAX_CONSECUTIVE_ENCODE_ERRORS must mark the service errored"
    );
    assert!(
      ctx.mailbox.borrow().has_terminal(),
      "the escalation must record a reserved-slot Conflict for Service::next"
    );
  }

  // A subsequent pump must SKIP the errored service. With it the only registered
  // service (and no queries), the result is `None` — proving the dead proto is
  // no longer re-polled (no busy-spin) and the counter is frozen.
  assert!(
    s.poll_one_transmit(now, &mut scratch).is_none(),
    "an errored service must be skipped by poll_one_transmit"
  );
  assert_eq!(
    s.services.get(&handle).unwrap().encode_failures,
    MAX_CONSECUTIVE_ENCODE_ERRORS,
    "a skipped errored service must not have its failure counter advanced further"
  );

  // The reserved `Conflict` is still drainable by the handle, and draining it
  // (then end-of-stream) is exactly what `Service::next` does.
  let mailbox = Rc::clone(&s.services.get(&handle).unwrap().mailbox);
  assert!(
    matches!(
      mailbox.borrow_mut().drain_for_test(),
      Some(ServiceUpdate::Conflict)
    ),
    "the reserved Conflict must remain readable by Service::next"
  );
  assert!(
    mailbox.borrow_mut().drain_for_test().is_none(),
    "after the terminal Conflict the mailbox reports end-of-stream"
  );
}

/// regression: when a service is retired by encode-failure escalation,
/// `endpoint.unregister_service` must be called so the proto route is freed
/// (`services_active == 0`) and the same service name can be re-registered.
///
/// This mirrors the smoltcp test but drives `State::poll_one_transmit`
/// directly (compio's analogue of the engine's `poll_one_transmit`). The
/// compio driver counts consecutive encode failures up to
/// `MAX_CONSECUTIVE_ENCODE_ERRORS` before escalating, unlike smoltcp which
/// retires on the first failure.
#[cfg(feature = "stats")]
#[test]
fn encode_failure_escalation_frees_proto_route_and_decrements_services_active() {
  use std::time::Duration;

  use mdns_proto::{Name, ServiceRecords, ServiceSpec};

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1, 9000);
  let now = std::time::Instant::now();

  let stype = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst = Name::try_from_str("F2Test._http._tcp.local.").unwrap();
  let host = Name::try_from_str("f2test.local.").unwrap();
  let mut recs = ServiceRecords::new(stype.clone(), inst.clone(), host.clone(), 80, 120);
  recs.add_a([10, 0, 0, 1].into());
  let handle = s
    .test_register_service(ServiceSpec::new(recs), now)
    .unwrap();

  // Confirm services_active == 1 after registration.
  assert_eq!(
    s.stats.snapshot().services_active,
    1,
    "services_active must be 1 after registration"
  );

  // Prime until the first encode failure, then push to the escalation threshold.
  let mut scratch = [0u8; 1];
  let mut t = now;
  let mut armed = false;
  for _ in 0..40 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    s.poll_one_transmit(t, &mut scratch);
    if s.services.get(&handle).unwrap().encode_failures == 1 {
      armed = true;
      break;
    }
  }
  assert!(armed, "must reach the first encode failure");

  // Drive to the escalation threshold.
  for _ in 2..=MAX_CONSECUTIVE_ENCODE_ERRORS {
    s.poll_one_transmit(t, &mut scratch);
  }

  // The service must now be errored.
  assert!(
    s.services.get(&handle).unwrap().errored,
    "service must be errored after escalation"
  );
  // The terminal Conflict must be set in the handle-owned mailbox. Grab the
  // reader's clone now (it outlives the ctx GC below).
  let mailbox = Rc::clone(&s.services.get(&handle).unwrap().mailbox);
  assert!(
    mailbox.borrow().has_terminal(),
    "the escalation must record a reserved-slot Conflict for Service::next"
  );

  // The escalation began an endpoint-owned withdrawal. A service that never
  // reached Established has an EMPTY snapshot, so the withdrawal completes
  // immediately (`remaining == 0`) and `drain_completed_withdrawals` frees the
  // route AND GCs the ctx UNCONDITIONALLY on the next call (with no datagram on
  // the wire).
  s.drain_completed_withdrawals(t);

  // Proto route freed — services_active must be 0.
  assert_eq!(
    s.stats.snapshot().services_active,
    0,
    "services_active must be 0 after the encode-failure withdrawal completes (route freed)"
  );
  // The ctx is GC'd unconditionally on completion — but the terminal Conflict
  // survives in the handle-owned mailbox and is still drainable by a live reader.
  assert!(
    !s.services.contains_key(&handle),
    "the ctx must be GC'd unconditionally once its withdrawal completes"
  );
  assert!(
    matches!(
      mailbox.borrow_mut().drain_for_test(),
      Some(ServiceUpdate::Conflict)
    ),
    "the reserved Conflict survives the ctx GC and is drainable by Service::next"
  );

  // The same service name must be re-registerable (route was released).
  let mut recs2 = ServiceRecords::new(stype, inst, host, 80, 120);
  recs2.add_a([10, 0, 0, 2].into());
  s.test_register_service(ServiceSpec::new(recs2), t)
    .expect("same service name must be re-registerable after encode-failure withdrawal");

  assert_eq!(
    s.stats.snapshot().services_active,
    1,
    "services_active must be 1 after re-registration"
  );
}

/// regression: when service A escalates (encode-failure threshold
/// reached) in the SAME `poll_one_transmit` call that service B returns an
/// `Ok(Some)` transmit (causing the early-return), the proto route for A must
/// still be freed immediately — not deferred to a post-loop drain that the
/// early-return bypasses.
///
/// The bug: the old code pushed retiring handles into `proto_unregister: Vec`
/// and drained it AFTER the service loop. An `Ok(Some)` early-return for B
/// exits the loop before the drain, permanently leaking A's proto route.
///
/// The fix: `unregister_service` is called IN-ITERATION the moment A
/// escalates (before the loop continues to B), so the early-return cannot
/// bypass it.
///
/// Setup: Service A has a large TXT record (> 1500 bytes) that cannot be
/// encoded into the 1500-byte scratch, while B has small records that fit.
/// This means A will always fail encode while B succeeds — the exact
/// in-call mix that triggers the bypass in the buggy code.
///
/// Verification: after `MAX_CONSECUTIVE_ENCODE_ERRORS` pumps, A is retired
/// (services_active == 1, A's name re-registerable) while B is unaffected
/// (services_active rises to 2 after re-registering A).
#[cfg(feature = "stats")]
#[test]
fn multi_service_encode_failure_frees_route_even_with_sibling_transmit() {
  use std::time::Duration;

  use mdns_proto::{Name, ServiceRecords, ServiceSpec};

  // Use a 1500-byte scratch — big enough for B's probe (small records) but
  // not for A's probe (A has a large TXT that pushes the probe past 1500
  // bytes). This ensures every `poll_one_transmit` call:
  //   - visits A → Err (too large) → A escalates toward threshold
  //   - visits B → Ok(Some(t)) → early-return (the bypass scenario)
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let now = std::time::Instant::now();

  // Service A: the one that will encode-fail. A large TXT segment fills the
  // probe past the 1500-byte scratch ceiling so every poll_transmit Errs.
  let stype_a = Name::try_from_str("_http._tcp.local.").unwrap();
  let inst_a = Name::try_from_str("Retire._http._tcp.local.").unwrap();
  let host_a = Name::try_from_str("retire.local.").unwrap();
  let mut recs_a = ServiceRecords::new(stype_a.clone(), inst_a.clone(), host_a.clone(), 80, 120);
  recs_a.add_a([10, 0, 0, 1].into());
  // A 255-byte TXT segment pushes A's probe well past the 1500-byte ceiling.
  recs_a.add_txt_segment(vec![b'x'; 255]);
  recs_a.add_txt_segment(vec![b'y'; 255]);
  recs_a.add_txt_segment(vec![b'z'; 255]);
  recs_a.add_txt_segment(vec![b'w'; 255]);
  recs_a.add_txt_segment(vec![b'v'; 255]);
  recs_a.add_txt_segment(vec![b'u'; 255]);
  let handle_a = s
    .test_register_service(ServiceSpec::new(recs_a), now)
    .unwrap();

  // Service B: small records that fit in the 1500-byte scratch.
  let stype_b = Name::try_from_str("_grpc._tcp.local.").unwrap();
  let inst_b = Name::try_from_str("Active._grpc._tcp.local.").unwrap();
  let host_b = Name::try_from_str("active.local.").unwrap();
  let mut recs_b = ServiceRecords::new(stype_b, inst_b.clone(), host_b.clone(), 443, 120);
  recs_b.add_a([10, 0, 0, 2].into());
  let handle_b = s
    .test_register_service(ServiceSpec::new(recs_b), now)
    .unwrap();

  // Both services registered: services_active == 2.
  assert_eq!(
    s.stats.snapshot().services_active,
    2,
    "both services registered: services_active must be 2"
  );

  // Pump with the 1500-byte scratch. Each call:
  //   - If A is visited first: Err (records too large) → A's counter increments
  //   - If B is visited first: Ok(Some) → early-return (bypass scenario)
  // In the BUGGY code (deferred Vec): when B causes an early-return AFTER A
  // escalates in the same call, A's route stays leaked (services_active stays 2).
  // In the FIXED code (in-iteration): A's unregister runs BEFORE the loop
  // continues to B, so the early-return cannot bypass it.
  let mut scratch = [0u8; 1500];
  let mut t = now;
  let mut a_retired = false;

  for _ in 0..40 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    let result = s.poll_one_transmit(t, &mut scratch);

    // Note any Ok(Some) result (should always be B's transmit, never A's
    // since A's records can't be encoded).
    if let Some((_tx, TransmitOrigin::Service(h))) = result {
      // The returned transmit MUST belong to B (A's records are too large).
      assert_eq!(
        h, handle_b,
        "any returned transmit must be from B, never from A (A's records won't encode)"
      );
      // Confirm B's delivery so B advances its probe/announce lifecycle.
      s.note_service_transmit_outcome(
        h,
        t,
        mdns_proto::TransmitDelivery::new(
          mdns_proto::FamilyDelivery::Delivered,
          mdns_proto::FamilyDelivery::Delivered,
        ),
      );
    }

    // Check if A just escalated.
    if s
      .services
      .get(&handle_a)
      .map(|c| c.errored)
      .unwrap_or(false)
    {
      // fix: A's withdrawal was BEGUN in-iteration (non-bypassable), even
      // though B may have returned Ok(Some) in the same call. The route is now
      // HELD by the withdrawal, so services_active stays 2 (A withdrawing + B
      // live) — the route frees on withdrawal completion, asserted below.
      assert_eq!(
        s.stats.snapshot().services_active,
        2,
        "services_active must be 2 when A escalates (A's route held by its \
           in-iteration-begun withdrawal + B live), even if B returned Ok(Some) in \
           the same poll_one_transmit call (regression: deferred-drain bypass)"
      );
      a_retired = true;
      break;
    }
  }

  assert!(
    a_retired,
    "A must be retired by encode-failure escalation within 40 pumps"
  );

  // A's terminal Conflict must be recorded in the handle-owned mailbox for
  // Service::next to drain. Grab the reader's clone now (it outlives the GC).
  let a_mailbox = Rc::clone(&s.services.get(&handle_a).unwrap().mailbox);
  assert!(
    a_mailbox.borrow().has_terminal(),
    "A's reserved-slot Conflict must be set for Service::next"
  );

  // A never reached Established → its withdrawal snapshot is empty and completes
  // immediately; `drain_completed_withdrawals` frees A's route AND GCs its ctx
  // unconditionally. If the bug were present (escalation marked A errored but
  // its withdrawal was never begun), the route would leak and services_active
  // would stay 2 here. A's terminal Conflict survives in `a_mailbox` regardless.
  s.drain_completed_withdrawals(t);
  assert!(
    matches!(
      a_mailbox.borrow_mut().drain_for_test(),
      Some(ServiceUpdate::Conflict)
    ),
    "A's reserved Conflict survives its ctx GC and is drainable by Service::next"
  );
  assert_eq!(
    s.stats.snapshot().services_active,
    1,
    "services_active must be 1 once A's (empty) withdrawal completes (B still live)"
  );

  // A's name must now be re-registerable (proto route was freed).
  let mut recs_a2 = ServiceRecords::new(stype_a, inst_a, host_a, 80, 120);
  recs_a2.add_a([10, 0, 0, 3].into());
  s.test_register_service(ServiceSpec::new(recs_a2), t)
    .expect("A's name must be re-registerable after its in-iteration-begun withdrawal completes");

  // B is still live: services_active == 2 after re-registering A.
  assert_eq!(
    s.stats.snapshot().services_active,
    2,
    "services_active must be 2 after re-registering A (B still live)"
  );

  // B must not have been errored (its records fit the scratch).
  assert!(
    !s.services.get(&handle_b).map(|c| c.errored).unwrap_or(true),
    "B must not be errored — its small records encode successfully"
  );
}

/// regression (endpoint-owned-withdrawal form): when a service's
/// auto-rename (§9 conflict) collides with another LOCAL service that already
/// owns the candidate name, `push_service_updates` retires the colliding service
/// into an endpoint-owned withdrawal. The endpoint HOLDS the route (reserving the
/// old name) until the withdrawal completes, THEN frees it — so `services_active`
/// is decremented and the old name becomes re-registerable on COMPLETION, not at
/// the collision instant. A's `Conflict` lands in the handle-owned mailbox
/// regardless.
///
/// The original bug: the compio `push_service_updates` break'd out of the rename
/// loop without retiring the service, leaking the proto route for the colliding
/// service. The migration replaces the immediate `unregister_service` with
/// `begin_service_withdrawal` (route held → freed on completion).
///
/// Verification: after the collision A is errored + `Conflict` is queued and the
/// route is still HELD (services_active stays 2, old name rejected); after
/// driving the withdrawal to completion, services_active drops to 1 and A's old
/// name is re-registerable.
#[cfg(feature = "stats")]
#[test]
fn rename_collision_with_local_service_frees_proto_route() {
  use std::time::Duration;

  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  use mdns_proto::{
    Name, ServiceRecords, ServiceSpec,
    wire::{Header, MessageBuilder},
  };

  // Build an mDNS authority-section packet that claims our instance name
  // with different SRV rdata — this is the §8.2 conflict signal that forces
  // the proto to revert to probing and eventually rename.
  fn conflict_for(instance: &str) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let name = Name::try_from_str(instance).unwrap();
    let target = Name::try_from_str("rival.local.").unwrap();
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_srv_authority(&name, 120, 0, 0, 9999, &target)
      .unwrap();
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  }

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  // Enable §11 on-link so injected datagrams are accepted.
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
  s.bound_interface = 1;

  let now = std::time::Instant::now();

  // Service A: "First._ipp._tcp.local." — will be driven to rename to "First (2)".
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst_a = Name::try_from_str("First._ipp._tcp.local.").unwrap();
  let host_a = Name::try_from_str("first.local.").unwrap();
  let mut recs_a = ServiceRecords::new(stype.clone(), inst_a.clone(), host_a.clone(), 80, 120);
  recs_a.add_a([192, 168, 1, 1].into());
  let handle_a = s
    .test_register_service(ServiceSpec::new(recs_a), now)
    .unwrap();

  // Service B: pre-register "First-1._ipp._tcp.local." so the rename
  // collision fires when A tries to rename to it.
  // The proto uses a `-N` suffix (rename_with_suffix): "First._ipp._tcp.local."
  // with rename_attempt=1 → "First-1._ipp._tcp.local.".
  let inst_b = Name::try_from_str("First-1._ipp._tcp.local.").unwrap();
  let host_b = Name::try_from_str("second.local.").unwrap();
  let mut recs_b = ServiceRecords::new(stype, inst_b, host_b, 80, 120);
  recs_b.add_a([192, 168, 1, 2].into());
  s.test_register_service(ServiceSpec::new(recs_b), now)
    .unwrap();

  // Both registered: services_active == 2.
  assert_eq!(
    s.stats.snapshot().services_active,
    2,
    "both services registered: services_active must be 2"
  );

  // Helper: pump all pending transmits and confirm delivery (mimics the
  // async driver loop's send + note_service_transmit_outcome round-trip).
  fn pump_transmits(s: &mut State, t: StdInstant, buf: &mut [u8]) {
    loop {
      match s.poll_one_transmit(t, buf) {
        Some((_tx, TransmitOrigin::Service(h))) => {
          s.note_service_transmit_outcome(
            h,
            t,
            mdns_proto::TransmitDelivery::new(
              mdns_proto::FamilyDelivery::Delivered,
              mdns_proto::FamilyDelivery::Delivered,
            ),
          );
        }
        Some(_) => {}
        None => break,
      }
    }
  }

  // Establish A (and advance B) by driving probe + announce with confirmed
  // delivery so the lifecycle states advance properly.
  let a_mailbox = Rc::clone(&s.services.get(&handle_a).unwrap().mailbox);
  let mut buf = [0u8; 1500];
  let mut t = now;
  let mut a_established = false;
  for _ in 0..60 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    pump_transmits(&mut s, t, &mut buf);
    s.push_service_updates(t);
    // Drain the handle-owned mailbox (what Service::next reads); detect the
    // Established and discard the rest so a fresh Conflict is detectable below.
    while let Some(u) = a_mailbox.borrow_mut().drain_for_test() {
      if matches!(u, ServiceUpdate::Established) {
        a_established = true;
      }
    }
    if a_established {
      break;
    }
  }
  let _ = a_established;

  // Inject a peer conflict for "First._ipp._tcp.local." repeatedly until
  // `push_service_updates` drives A to rename and collide with B, at which point
  // A's terminal Conflict is set in the mailbox and A is flagged errored.
  let conflict = conflict_for("First._ipp._tcp.local.");
  let peer = RecvMeta::new(
    SocketAddr::from(([192, 168, 1, 200], 5353)),
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
    1,
    Some(255),
    None,
    conflict.len(),
  );
  let mut conflicted = false;
  for _ in 0..80 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    s.handle_datagram(&peer, &conflict);
    pump_transmits(&mut s, t, &mut buf);
    s.push_service_updates(t);

    if s
      .services
      .get(&handle_a)
      .map(|c| c.errored)
      .unwrap_or(false)
    {
      conflicted = true;
      break;
    }
  }

  assert!(
    conflicted,
    "A must be driven to rename-collision-Conflict within 60 iterations"
  );

  // A's route is HELD by the in-flight withdrawal — services_active stays 2
  // (B live + A withdrawing), and A's terminal Conflict is set for Service::next.
  assert_eq!(
    s.stats.snapshot().services_active,
    2,
    "services_active must still be 2 while A's rename-collision withdrawal holds \
       the route (B live + A withdrawing)"
  );
  assert!(
    a_mailbox.borrow().has_terminal(),
    "A's reserved-slot Conflict must be set for Service::next"
  );
  // The GC is UNCONDITIONAL now, so the ctx need not be drained first — but the
  // terminal Conflict survives in `a_mailbox` regardless (asserted after).

  // Drive A's withdrawal to completion (no sockets → force-finished at the 2 s
  // ceiling), then GC the freed ctx.
  let mut scratch = vec![0u8; 4096];
  let mut completed = false;
  for _ in 0..64 {
    t += Duration::from_millis(250);
    while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
      // No sockets bound in this State-level test: model BOTH families as
      // transiently undeliverable (Retry) so the per-family budget stays intact
      // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
      // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
      // instead, defeating the ceiling assertion.)
      s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
    }
    s.drain_completed_withdrawals(t);
    if !s.services.contains_key(&handle_a) {
      completed = true;
      break;
    }
  }
  assert!(completed, "A's rename-collision withdrawal must complete");

  // On completion the route is freed: services_active drops to 1 (B only).
  assert_eq!(
    s.stats.snapshot().services_active,
    1,
    "services_active must be 1 once A's withdrawal completes (B still live)"
  );
  // A's terminal Conflict survived the unconditional ctx GC and is drainable by
  // a live reader.
  assert!(
    matches!(
      a_mailbox.borrow_mut().drain_for_test(),
      Some(ServiceUpdate::Conflict)
    ),
    "A's reserved Conflict survives the ctx GC and is drainable by Service::next"
  );

  // A's old name must now be re-registerable (route was freed on completion).
  let mut recs_a2 = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    inst_a,
    host_a,
    80,
    120,
  );
  recs_a2.add_a([192, 168, 1, 10].into());
  s.test_register_service(ServiceSpec::new(recs_a2), t)
    .expect("A's old name must be re-registerable once the rename-collision withdrawal completes");
}

/// regression (endpoint-owned-withdrawal form): when an ANNOUNCED service A
/// is driven to auto-rename and its candidate new name collides with a local
/// service B, the proto hands off A's OLD instance name goodbye (TTL=0). The OLD
/// driver stole that goodbye into its own queue before freeing the old name,
/// then guarded against replaying it on A's drop. The endpoint now enforces this
/// STRUCTURALLY: the driver takes the handoff and enqueues it as an INDEPENDENT
/// detached withdrawal item (`Endpoint::enqueue_rename_withdrawal`) that HOLDS
/// the OLD name for the whole withdrawal — so a replacement R cannot register
/// (and evict the old name from peer caches) until that goodbye completes. The
/// rename-collision teardown additionally begins an endpoint-owned withdrawal
/// for the CURRENT name. No steal, no replay-guard needed.
///
/// (That the proto hands off the OLD name's records + ownership is covered at the
/// proto level by `conflict_rename_hands_off_old_announced_name`, and that the
/// handoff becomes a detached item by
/// `rename_enqueues_a_detached_withdrawal_for_the_old_name`.)
///
/// Asserts:
/// 1. After collision retirement A is errored + the endpoint holds the OLD name,
///    so a same-name re-register is rejected (`NameAlreadyRegistered`).
/// 2. Once the withdrawal completes (route freed + ctx GC'd), the OLD name is
///    re-registerable — and re-registering R THEN does not depend on any
///    driver-side replayed goodbye.
#[cfg(feature = "stats")]
#[test]
fn rename_collision_drains_old_name_goodbye_before_name_reuse() {
  use std::time::Duration;

  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  use mdns_proto::{
    Name, ServiceRecords, ServiceSpec,
    wire::{Header, MessageBuilder},
  };

  fn conflict_for(instance: &str) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let name = Name::try_from_str(instance).unwrap();
    let target = Name::try_from_str("rival.local.").unwrap();
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_srv_authority(&name, 120, 0, 0, 9999, &target)
      .unwrap();
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  }

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
  s.bound_interface = 1;

  let now = std::time::Instant::now();

  // Service A: will be announced then driven to rename-collision.
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst_a = Name::try_from_str("First._ipp._tcp.local.").unwrap();
  let host_a = Name::try_from_str("first.local.").unwrap();
  let mut recs_a = ServiceRecords::new(stype.clone(), inst_a.clone(), host_a.clone(), 80, 120);
  recs_a.add_a([192, 168, 1, 1].into());
  let handle_a = s
    .test_register_service(ServiceSpec::new(recs_a), now)
    .unwrap();

  // Service B: owns the name A will try to rename to.
  let inst_b = Name::try_from_str("First-1._ipp._tcp.local.").unwrap();
  let host_b = Name::try_from_str("second.local.").unwrap();
  let mut recs_b = ServiceRecords::new(stype.clone(), inst_b, host_b, 80, 120);
  recs_b.add_a([192, 168, 1, 2].into());
  s.test_register_service(ServiceSpec::new(recs_b), now)
    .unwrap();

  fn pump_transmits(s: &mut State, t: StdInstant, buf: &mut [u8]) {
    loop {
      match s.poll_one_transmit(t, buf) {
        Some((_tx, TransmitOrigin::Service(h))) => {
          s.note_service_transmit_outcome(
            h,
            t,
            mdns_proto::TransmitDelivery::new(
              mdns_proto::FamilyDelivery::Delivered,
              mdns_proto::FamilyDelivery::Delivered,
            ),
          );
        }
        Some(_) => {}
        None => break,
      }
    }
  }

  // Advance A to Established so the proto hands off an old-name goodbye on
  // rename (only an ANNOUNCED service has one — that's the bug scenario).
  let a_mailbox = Rc::clone(&s.services.get(&handle_a).unwrap().mailbox);
  let mut buf = [0u8; 1500];
  let mut t = now;
  let mut a_established = false;
  for _ in 0..60 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    pump_transmits(&mut s, t, &mut buf);
    s.push_service_updates(t);
    // Drain the handle-owned mailbox; detect Established and discard the rest so
    // a fresh Conflict is detectable below.
    while let Some(u) = a_mailbox.borrow_mut().drain_for_test() {
      if matches!(u, ServiceUpdate::Established) {
        a_established = true;
      }
    }
    if a_established {
      break;
    }
  }
  assert!(
    a_established,
    "A must reach Established before the rename-collision test can verify the goodbye"
  );

  // Inject peer conflicts for A's original name until push_service_updates drives
  // the rename and detects the local collision.
  let conflict = conflict_for("First._ipp._tcp.local.");
  let peer = RecvMeta::new(
    SocketAddr::from(([192, 168, 1, 200], 5353)),
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
    1,
    Some(255),
    None,
    conflict.len(),
  );
  let mut conflicted = false;
  for _ in 0..80 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    s.handle_datagram(&peer, &conflict);
    pump_transmits(&mut s, t, &mut buf);
    s.push_service_updates(t);

    if s
      .services
      .get(&handle_a)
      .map(|c| c.errored)
      .unwrap_or(false)
    {
      conflicted = true;
      break;
    }
  }
  assert!(
    conflicted,
    "A must be driven to rename-collision-Conflict within 80 iterations"
  );

  // ASSERTION 1: the endpoint holds A's OLD name for the whole withdrawal, so a
  // same-name re-register is rejected — a replacement cannot announce a fresh
  // positive TTL ahead of the stale TTL=0 (and evict the old name from peer
  // caches). This is the structural ordering guarantee that replaces the old
  // steal-before-reuse dance.
  {
    let mut dup = ServiceRecords::new(stype.clone(), inst_a.clone(), host_a.clone(), 80, 120);
    dup.add_a([192, 168, 1, 1].into());
    assert!(
      matches!(
        s.test_register_service(ServiceSpec::new(dup), t),
        Err(mdns_proto::error::RegisterServiceError::NameAlreadyRegistered(_))
      ),
      "A's OLD name must be held by the in-flight withdrawal (NameAlreadyRegistered)"
    );
  }

  // The collision Conflict lives in the handle-owned mailbox; the ctx GC is now
  // UNCONDITIONAL, so it need not be drained first.

  // Drive A's withdrawal to completion (no sockets → force-finished at the 2 s
  // anti-pin ceiling), then GC the freed ctx.
  let mut scratch = vec![0u8; 4096];
  let mut completed = false;
  for _ in 0..64 {
    t += Duration::from_millis(250);
    while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
      // No sockets bound in this State-level test: model BOTH families as
      // transiently undeliverable (Retry) so the per-family budget stays intact
      // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
      // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
      // instead, defeating the ceiling assertion.)
      s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
    }
    s.drain_completed_withdrawals(t);
    if !s.services.contains_key(&handle_a) {
      completed = true;
      break;
    }
  }
  assert!(completed, "A's rename-collision withdrawal must complete");

  // ASSERTION 2: once the withdrawal completes, A's OLD name is freed → a
  // replacement R registers successfully under it.
  let host_r = Name::try_from_str("replacement.local.").unwrap();
  let mut recs_r = ServiceRecords::new(stype, inst_a, host_r, 80, 120);
  recs_r.add_a([192, 168, 1, 10].into());
  s.test_register_service(ServiceSpec::new(recs_r), t)
    .expect("replacement R must register under A's old name once the withdrawal completes");
}

/// a terminal emitted DIRECTLY by the proto state machine —
/// here a `HostConflict` (a peer claimed our host name with a different address,
/// RFC 6762 §9) — must RETIRE the service through the SAME path as a synthesized
/// rename-collision Conflict: deliver the terminal into the handle-owned mailbox,
/// begin the endpoint-owned §10.1 withdrawal (so the proto stops serving), and GC
/// the ctx UNCONDITIONALLY once the withdrawal completes. Before the fix a
/// proto-emitted terminal was only pushed into the mailbox: `errored` was never
/// set and the withdrawal never began, so `Service::next` reported end-of-stream
/// while the ctx/route stayed live (still answering queries) until the handle
/// dropped.
#[test]
fn proto_emitted_host_conflict_retires_and_gcs_the_service() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use mdns_proto::{
    Name, ServiceRecords, ServiceSpec, WithdrawalSend,
    wire::{Header, MessageBuilder},
  };

  use crate::socket::RecvMeta;

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
  s.bound_interface = 1;
  let now = std::time::Instant::now();

  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("printer.local.").unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host.clone(), 631, 120);
  recs.add_a([192, 168, 1, 10].into());
  let handle = s
    .test_register_service(ServiceSpec::new(recs), now)
    .unwrap();
  let mailbox = Rc::clone(&s.services.get(&handle).unwrap().mailbox);

  fn pump_transmits(s: &mut State, t: StdInstant, buf: &mut [u8]) {
    loop {
      match s.poll_one_transmit(t, buf) {
        Some((_tx, TransmitOrigin::Service(h))) => s.note_service_transmit_outcome(
          h,
          t,
          mdns_proto::TransmitDelivery::new(
            mdns_proto::FamilyDelivery::Delivered,
            mdns_proto::FamilyDelivery::Delivered,
          ),
        ),
        Some(_) => {}
        None => break,
      }
    }
  }

  // Drive the service to Established (advertising its host A record), so the
  // host conflict hits a SERVING service with a non-empty withdrawal snapshot.
  let mut buf = [0u8; 1500];
  let mut t = now;
  let mut established = false;
  for _ in 0..60 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    pump_transmits(&mut s, t, &mut buf);
    s.push_service_updates(t);
    while let Some(u) = mailbox.borrow_mut().drain_for_test() {
      if matches!(u, ServiceUpdate::Established) {
        established = true;
      }
    }
    if established {
      break;
    }
  }
  assert!(
    established,
    "service must reach Established before the host conflict"
  );

  // A peer claims our host name with a DIFFERENT address (10.0.0.99): a genuine
  // §9 host conflict. The proto does NOT auto-rename a host conflict — it emits
  // `ServiceUpdate::HostConflict` via `poll()`.
  let conflict = {
    let mut cbuf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut cbuf, Header::new()).unwrap();
    b.push_a_authority(&host, 120, Ipv4Addr::new(10, 0, 0, 99))
      .unwrap();
    let n = b.finish().unwrap();
    cbuf[..n].to_vec()
  };
  let peer = RecvMeta::new(
    SocketAddr::from(([192, 168, 1, 200], 5353)),
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
    1,
    Some(255), // on-link
    None,
    conflict.len(),
  );

  // Feed the conflict; `push_service_updates` drains the proto's HostConflict and
  // (with the fix) begins the withdrawal — `errored` flips true.
  let mut retired = false;
  for _ in 0..40 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    s.handle_datagram(&peer, &conflict);
    pump_transmits(&mut s, t, &mut buf);
    s.push_service_updates(t);
    if s.services.get(&handle).map(|c| c.errored).unwrap_or(false) {
      retired = true;
      break;
    }
  }
  assert!(
    retired,
    "a proto-emitted HostConflict must begin the endpoint-owned withdrawal (errored)"
  );

  // The terminal HostConflict reached the handle-owned mailbox's reserved slot.
  let mut saw_host_conflict = false;
  while let Some(u) = mailbox.borrow_mut().drain_for_test() {
    if u.is_host_conflict() {
      saw_host_conflict = true;
    }
  }
  assert!(
    saw_host_conflict,
    "the HostConflict terminal must reach the handle-owned mailbox"
  );

  // Drive the withdrawal to completion (no bound family → both Retry → force-
  // complete at the 2 s anti-pin ceiling); the ctx must be GC'd UNCONDITIONALLY.
  let mut scratch = vec![0u8; 4096];
  let mut gced = false;
  for _ in 0..64 {
    t += Duration::from_millis(250);
    while let Some((_, _, tok)) = s.poll_one_withdrawal(t, &mut scratch) {
      s.note_withdrawal_result(tok, t, WithdrawalSend::Retry, WithdrawalSend::Retry);
    }
    s.drain_completed_withdrawals(t);
    if !s.services.contains_key(&handle) {
      gced = true;
      break;
    }
  }
  assert!(
    gced,
    "the withdrawn service ctx must be GC'd after the §10.1 goodbye completes"
  );
}

/// a query whose question can't be encoded into `max_payload` (here
/// a 1-byte scratch) must be flagged `errored` rather than re-offered forever.
/// A fresh query has `transmit_pending = true`, so the first
/// `poll_one_transmit` attempts the encode and fails. The driver must mark the
/// query errored (so every pump skips it — no busy-spin), arm the one-shot
/// terminal wake exactly once, and contribute no deadline. Without this, a
/// `QuerySpec` with the default `timeout: None` has neither a `timeout_deadline`
/// nor (post-failure) a `next_deadline`, so `poll_deadline` returns `None` and
/// a parked `Query::next` would hang indefinitely.
#[test]
fn unencodable_query_is_errored_not_spun_or_hung() {
  use mdns_proto::{QuerySpec, wire::ResourceType};

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let now = std::time::Instant::now();
  let qname = mdns_proto::Name::try_from_str("printer.local.").unwrap();
  // Default QuerySpec: no timeout → no absolute deadline. This is the case
  // that hangs without the fix.
  let h = s
    .start_query(QuerySpec::new(qname, ResourceType::A), now)
    .unwrap();

  // A 1-byte scratch can't hold a DNS header + question → encode `Err`.
  let mut scratch = [0u8; 1];

  // First pump: the pending question fails to encode. The query must be
  // flagged errored and yield NO transmit (not a phantom send).
  let pumped = s.poll_one_transmit(now, &mut scratch);
  assert!(
    pumped.is_none(),
    "an un-encodable query must not yield a transmit"
  );
  assert!(
    s.queries.get(&h).map(|c| c.errored).unwrap_or(false),
    "the query must be flagged errored after the encode failure"
  );

  // No standing deadline from the errored query (would otherwise busy-spin).
  assert!(
    s.poll_deadline().is_none(),
    "an errored query must contribute no deadline"
  );

  // The one-shot terminal wake fires exactly once, then clears.
  assert!(
    s.take_query_terminal_wakes(),
    "the terminal wake must be armed once on the errored transition"
  );
  assert!(
    !s.take_query_terminal_wakes(),
    "the terminal wake is one-shot — a second drain must report nothing"
  );

  // A subsequent pump skips the errored query entirely (no re-poll busy-spin).
  assert!(
    s.poll_one_transmit(now, &mut scratch).is_none(),
    "an errored query must be skipped by later pumps, not re-polled"
  );
  assert!(
    !s.take_query_terminal_wakes(),
    "no further wake is armed once the query is already errored"
  );
}

/// A `Query::drop` that lands while the pump is inside `send_via().await` must
/// not cost the in-flight datagram its confirm.
///
/// The handle drops on the driver's own thread but from another task, so it can
/// run at exactly this point — for THIS query's own question. Cancelling the
/// proto query there DISCARDS the commit token, and the
/// `note_query_transmit_outcome` that follows lands on a handle the endpoint no
/// longer knows: a silent no-op, with the datagram still on its way out and the
/// §5.2 schedule left in the undecided state the confirm was supposed to resolve.
/// The drop therefore only FLAGS, and the removal waits for
/// `sweep_cancelled_queries`, which the run loop calls after the pump.
///
/// This drives the State seam directly because the interleaving IS the test: the
/// point between `poll_one_transmit` and `note_query_transmit_outcome` is exactly
/// where a real `send_via` await parks and where `Drop` can interpose.
#[test]
fn a_query_dropped_mid_send_still_gets_its_confirm() {
  use mdns_proto::{QuerySpec, wire::ResourceType};

  let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let now = std::time::Instant::now();
  let qname = mdns_proto::Name::try_from_str("printer.local.").unwrap();
  let h = inner
    .state
    .borrow_mut()
    .start_query(QuerySpec::new(qname, ResourceType::A), now)
    .unwrap();
  // The real app-facing handle, so this drives the real `Drop` impl.
  let query = crate::Query {
    inner: Rc::clone(&inner),
    handle: h,
    terminal_delivered: Cell::new(false),
  };

  let mut scratch = [0u8; 1500];
  // The pump extracts the question and stamps the commit token; from here the
  // driver is parked inside `send_via`, holding no borrow on the state.
  {
    let mut s = inner.state.borrow_mut();
    let (_tx, origin) = s
      .poll_one_transmit(now, &mut scratch)
      .expect("a newly-started query has its first question due");
    assert!(
      matches!(origin, TransmitOrigin::Query(qh) if qh == h),
      "the pending datagram must be attributed to the query that produced it"
    );
    assert!(
      s.endpoint.poll_query_timeout(h).is_none(),
      "the §5.2 retry is scheduled by the CONFIRM, not by the poll, so nothing \
       is armed while the token is live — this is what the confirm resolves"
    );
  }

  // `Query::drop` runs mid-send.
  drop(query);
  {
    let mut s = inner.state.borrow_mut();
    assert!(
      s.queries.contains_key(&h),
      "the drop must only FLAG — removing the query here would discard the \
       commit token the pump still owes a confirm for"
    );
    assert!(
      s.poll_one_transmit(now, &mut scratch).is_none(),
      "a cancelled query asks nothing further, flag or no flag"
    );

    // The send completes and the pump confirms.
    s.note_query_transmit_outcome(
      h,
      now,
      mdns_proto::TransmitDelivery::new(
        mdns_proto::FamilyDelivery::Delivered,
        mdns_proto::FamilyDelivery::Delivered,
      ),
    );
    assert!(
      s.endpoint.poll_query_timeout(h).is_some(),
      "the confirm must resolve the live token and advance the §5.2 schedule — \
       it silently no-ops if the drop already removed the handle"
    );

    // Only now is the query freed, driver ctx and proto pool entry together.
    assert!(
      s.sweep_cancelled_queries(),
      "the post-pump sweep is what removes a cancelled query"
    );
    assert!(
      !s.queries.contains_key(&h),
      "the driver ctx is gone after the sweep"
    );
    assert!(
      s.endpoint.poll_query_timeout(h).is_none(),
      "and so is the proto pool entry"
    );
    assert!(
      !s.sweep_cancelled_queries(),
      "a second sweep pass has nothing left to do"
    );
  }
}

/// Registering the same instance name twice (no intervening removal) must
/// be rejected by the driver `State` with the proto
/// `RegisterServiceError::NameAlreadyRegistered` — the duplicate-detection
/// path the public `Endpoint` later maps onto `RegisterError`.
#[test]
fn duplicate_registration_is_rejected_as_name_already_registered() {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec, error::RegisterServiceError};

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let t = std::time::Instant::now();

  let mk = || {
    let mut r = ServiceRecords::new(
      Name::try_from_str("_http._tcp.local.").unwrap(),
      Name::try_from_str("dup._http._tcp.local.").unwrap(),
      Name::try_from_str("dup.local.").unwrap(),
      80,
      120,
    );
    r.add_a([127, 0, 0, 1].into());
    ServiceSpec::new(r)
  };

  s.test_register_service(mk(), t).unwrap();
  let err = s.test_register_service(mk(), t).unwrap_err();
  assert!(
    matches!(err, RegisterServiceError::NameAlreadyRegistered(_)),
    "second registration of the same instance name must be rejected as NameAlreadyRegistered, got {err:?}"
  );
}

/// On encode failure (`poll_query_transmit` → `Err`) the driver must call
/// `endpoint.retire_query` so the proto records the terminal transition:
/// `queries_active` decrements to 0 and exactly one of `queries_done` /
/// `queries_timeout` reaches 1. Without the fix `queries_active` leaks
/// and `queries_done`/`queries_timeout` stay 0 forever.
///
/// Also verifies: the errored flag is set (so subsequent pumps skip the
/// handle), the one-shot wake is armed, and the terminal is available via
/// `endpoint.poll_query` (so `Query::next` can surface it).
#[cfg(feature = "stats")]
#[test]
fn unencodable_query_retire_records_terminal_stats() {
  use mdns_proto::{QuerySpec, wire::ResourceType};

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let now = std::time::Instant::now();
  let qname = mdns_proto::Name::try_from_str("printer.local.").unwrap();
  let h = s
    .start_query(QuerySpec::new(qname, ResourceType::A), now)
    .unwrap();

  // Confirm one active query was registered.
  let before = s.stats.snapshot();
  assert_eq!(
    before.queries_active, 1,
    "one active query before encode failure"
  );
  assert_eq!(before.queries_done, 0, "no terminal yet");

  // 1-byte scratch forces Err(BufferTooSmall).
  let mut scratch = [0u8; 1];
  let pumped = s.poll_one_transmit(now, &mut scratch);
  assert!(
    pumped.is_none(),
    "an un-encodable query must not yield a transmit"
  );

  // Stats invariant: queries_active == 0, (queries_done + queries_timeout) == 1.
  let after = s.stats.snapshot();
  assert_eq!(
    after.queries_active, 0,
    "queries_active must be 0 after retire_query (was leaking)"
  );
  let terminal_count = after.queries_done;
  assert_eq!(
    terminal_count, 1,
    "exactly one terminal (done/timeout) must be recorded; got queries_done={}, queries_timeout={}",
    after.queries_done, after.queries_timeout,
  );

  // The errored flag must be set so the handle is skipped on subsequent pumps.
  assert!(
    s.queries.get(&h).map(|c| c.errored).unwrap_or(false),
    "the query must be flagged errored after the encode failure"
  );
  // One-shot wake must be armed.
  assert!(
    s.take_query_terminal_wakes(),
    "the terminal wake must be armed once on the errored transition"
  );
}

/// regression: after an encode-failed query's terminal is observed via
/// `Query::next`, the driver query map must no longer contain the handle and
/// the proto query pool slot must be freed (cancel_query removes it).
///
/// Verifies:
///  - `queries_active == 0` and one terminal counter after the encode failure.
///  - `Query::next` delivers exactly one `QueryEvent::Terminal`.
///  - After the terminal, `state.queries` no longer contains the handle
///    (driver map GC'd).
///  - The proto pool was freed: starting a new query reuses the pool (len
///    stays bounded / no phantom second active entry).
///  - A subsequent `Query::next` call returns `None` (no double terminal).
#[cfg(feature = "stats")]
#[compio::test]
async fn encode_failed_query_slot_is_gc_after_terminal_observed() {
  use core::cell::Cell;

  use crate::query::{Query, QueryEvent};

  let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);

  // Register a query with no timeout so the encode failure would otherwise
  // hang Query::next indefinitely.
  let qname = mdns_proto::Name::try_from_str("printer.local.").unwrap();
  let spec = mdns_proto::QuerySpec::new(qname, mdns_proto::wire::ResourceType::A);
  let h = inner
    .state
    .borrow_mut()
    .start_query(spec, std::time::Instant::now())
    .unwrap();

  // Verify one active query registered.
  assert_eq!(
    inner.state.borrow().stats.snapshot().queries_active,
    1,
    "one active query before encode failure"
  );

  // Pump with a 1-byte scratch to force encode Err → retire + errored.
  let mut scratch = [0u8; 1];
  {
    let mut st = inner.state.borrow_mut();
    let _ = st.poll_one_transmit(std::time::Instant::now(), &mut scratch);
  }

  // queries_active must now be 0 (retire_query was called).
  let snap = inner.state.borrow().stats.snapshot();
  assert_eq!(
    snap.queries_active, 0,
    "queries_active must be 0 after retire"
  );
  assert_eq!(
    snap.queries_done, 1,
    "exactly one terminal counter must be recorded"
  );

  // Consume the one-shot terminal wake so it doesn't drive a notify busy-spin.
  let _ = inner.state.borrow_mut().take_query_terminal_wakes();

  // Build the Query handle.
  let query = Query {
    inner: Rc::clone(&inner),
    handle: h,
    terminal_delivered: Cell::new(false),
  };

  // Query::next must deliver exactly one Terminal event.
  let event = query.next().await;
  assert!(
    matches!(event, Some(QueryEvent::Terminal(_))),
    "Query::next must return Terminal after encode failure, got {event:?}"
  );

  // After the terminal is observed the driver query map must be empty.
  assert!(
    !inner.state.borrow().queries.contains_key(&h),
    "driver query map must not contain the handle after terminal is observed"
  );

  // Proto pool slot freed: a fresh query fits in the pool without leaking.
  let qname2 = mdns_proto::Name::try_from_str("scanner.local.").unwrap();
  let spec2 = mdns_proto::QuerySpec::new(qname2, mdns_proto::wire::ResourceType::A);
  let h2 = inner
    .state
    .borrow_mut()
    .start_query(spec2, std::time::Instant::now())
    .expect("new query must succeed after slot was freed");
  assert_ne!(h, h2, "new handle should differ from the retired one");
  // queries_active is back to 1 for the new query.
  assert_eq!(
    inner.state.borrow().stats.snapshot().queries_active,
    1,
    "new query must count as active"
  );

  // A subsequent next() on the original query returns None (no double terminal).
  let second = query.next().await;
  assert!(
    second.is_none(),
    "subsequent Query::next after terminal must return None, got {second:?}"
  );
}

/// regression: a generic `recv` error must NOT increment `packets_dropped`.
/// `packets_dropped` is reserved for consumed-unusable datagrams (oversized /
/// truncated / InvalidData); a socket/driver recv failure is not a datagram-
/// level event and must not be counted.
///
/// Contrast: the known consumed-unusable paths in `State::handle_datagram`
/// (off-link, untrusted-response) DO bump `packets_dropped` — those tests
/// already exist in this module.
#[cfg(feature = "stats")]
#[test]
fn generic_recv_error_does_not_increment_packets_dropped() {
  let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);

  let before = inner.state.borrow().stats.snapshot();
  assert_eq!(before.packets_dropped, 0, "no drops before recv error");

  // Inject a generic I/O error (connection refused — not InvalidData).
  let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "injected recv error");
  handle_recv(&inner, Err(err));

  let after = inner.state.borrow().stats.snapshot();
  assert_eq!(
    after.packets_dropped, 0,
    "a generic recv error must NOT increment packets_dropped"
  );
  // Receive counters must also stay at zero — no datagram was consumed.
  assert_eq!(after.packets_rx, 0, "packets_rx must stay 0");
  assert_eq!(after.bytes_rx, 0, "bytes_rx must stay 0");
}

/// regression: a truncated (oversized) datagram surfaced by `Socket::recv`
/// via the full-buffer heuristic must be counted as consumed (`packets_rx` +
/// `bytes_rx`) AND as dropped (`packets_dropped`), but must NOT be routed to
/// `handle_datagram` / proto (no partial-message side effects).
///
/// The `RecvMeta::with_truncated()` helper marks the datagram the same way
/// `Socket::recv` marks one that filled the buffer exactly (i.e. `data_len >=
/// max_recv_packet_size`). No live socket is needed.
#[cfg(feature = "stats")]
#[test]
fn truncated_datagram_counts_rx_and_dropped_not_delivered_to_proto() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;

  let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);

  // Craft an oversized-proxy datagram: `RecvMeta::with_truncated()` sets the
  // `truncated` flag as `Socket::recv` would when data_len >= max_recv.
  // The data is a synthetic blob (does not need to be a valid DNS message —
  // the test verifies the datagram is dropped BEFORE proto routing).
  let data: Vec<u8> = vec![0u8; 9000]; // 9000 bytes == max_recv_packet_size
  let len = data.len();

  let meta = RecvMeta::new(
    SocketAddr::from(([224, 0, 0, 251], 5353)),
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    0,
    Some(255),
    None,
    len,
  )
  .with_truncated();

  let before = inner.state.borrow().stats.snapshot();
  assert_eq!(before.packets_rx, 0);
  assert_eq!(before.bytes_rx, 0);
  assert_eq!(before.packets_dropped, 0);

  handle_recv(&inner, Ok((data, meta)));

  let after = inner.state.borrow().stats.snapshot();
  assert_eq!(
    after.packets_rx, 1,
    "truncated datagram was received — packets_rx must be +1"
  );
  assert_eq!(
    after.bytes_rx, len as u64,
    "bytes_rx must reflect the truncated bytes that landed"
  );
  assert_eq!(
    after.packets_dropped, 1,
    "truncated datagram must bump packets_dropped"
  );
  // Proto must not have been reached: no question/answer routing side effects.
  // A synthetic 9000-byte blob that bypassed proto leaves questions_rx == 0.
  assert_eq!(
    after.questions_rx, 0,
    "truncated datagram must NOT be routed to proto (no question side effect)"
  );
}

/// Complement to the truncated-datagram test: a normal sub-max datagram whose
/// `truncated` flag is NOT set must still route to `handle_datagram` / proto
/// (regression guard — the truncation gate must not block normal traffic).
///
/// We use a well-formed 12-byte all-zero DNS query header (ID=0, QR=0, no
/// sections) so proto's `handle()` succeeds (or fails gracefully) without
/// producing a questions_rx bump that depends on implementation details.
/// The key assertion is `packets_rx == 1` with `packets_dropped == 0`.
#[cfg(feature = "stats")]
#[test]
fn normal_non_truncated_datagram_routes_to_proto() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;

  let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  // Put the loopback subnet in the local-subnets list so the §11 on-link
  // gate passes (otherwise the datagram is dropped at the off-link check
  // before proto — which would make packets_dropped > 0 and muddy the test).
  inner.state.borrow_mut().local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
  inner.state.borrow_mut().bound_interface = 1;

  // Minimal 12-byte DNS query header. QR=0, QDCOUNT=0 — proto accepts it as
  // an empty query and does nothing, producing no parse error.
  let data: Vec<u8> = vec![
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  let len = data.len();

  // Not truncated (data_len < max_recv = 9000).
  let meta = RecvMeta::new(
    SocketAddr::from(([127, 0, 0, 1], 5353)),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    1,
    Some(255),
    None,
    len,
  );
  // `truncated()` must be false — the normal routing path.
  assert!(
    !meta.truncated(),
    "sanity: RecvMeta::new must not set truncated"
  );

  handle_recv(&inner, Ok((data, meta)));

  let after = inner.state.borrow().stats.snapshot();
  assert_eq!(
    after.packets_dropped, 0,
    "a normal non-truncated datagram must NOT bump packets_dropped"
  );
  // packets_rx is bumped by proto's handle() for routed datagrams; the
  // datagram went through proto so this counter must be 1.
  assert_eq!(
    after.packets_rx, 1,
    "normal datagram must be counted by proto (packets_rx == 1)"
  );
}

/// Loop-ordering guard (endpoint-owned-withdrawal form): the withdrawal
/// pump (`drain_withdrawals`) MUST run AFTER `push_service_updates`, not before.
///
/// When a rename collision is detected inside `push_service_updates`, the
/// teardown enqueues the old name's detached goodbye
/// (`enqueue_rename_withdrawal`) AND begins an endpoint-owned withdrawal for the
/// current name (`begin_service_withdrawal`), each due IMMEDIATELY
/// (`next_at = now`).
/// Under the wrong order —
/// withdrawal pump first, then `push_service_updates` — the pump would run
/// before the withdrawal exists, deferring its first goodbye to the NEXT
/// iteration (whose Phase-1 transmit pump runs first). The endpoint holds the
/// OLD name throughout, so a replacement still cannot overtake the goodbye, but
/// running the pump after push keeps the stale TTL=0 promptly on the wire.
///
/// This test proves the ordering at the State seam by stopping the drive loop
/// on the decisive (collision) iteration and probing whether a withdrawal
/// datagram is DUE before vs after `push_service_updates`. `poll_one_withdrawal`
/// is non-destructive to the resend schedule (it only encodes into scratch;
/// `next_at` advances only in `note_withdrawal_result`, which we do NOT call
/// here), so before/after probes are side-effect-free:
///
///   before push: no withdrawal exists yet → `poll_one_withdrawal` == None.
///   after push: the collision withdrawal is queued, first round due now →
///                `poll_one_withdrawal` == Some (the pump would drain it this
///                iteration).
#[cfg(feature = "stats")]
#[test]
fn withdrawal_pump_runs_after_push_service_updates_loop_order() {
  use std::time::Duration;

  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  use mdns_proto::{
    Name, ServiceRecords, ServiceSpec,
    wire::{Header, MessageBuilder},
  };

  fn conflict_for(instance: &str) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let name = Name::try_from_str(instance).unwrap();
    let target = Name::try_from_str("rival.local.").unwrap();
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
    b.push_srv_authority(&name, 120, 0, 0, 9999, &target)
      .unwrap();
    let n = b.finish().unwrap();
    buf[..n].to_vec()
  }

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
  s.bound_interface = 1;

  let now = std::time::Instant::now();

  // Service A: will be announced then driven to rename-collision.
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst_a = Name::try_from_str("Alpha._ipp._tcp.local.").unwrap();
  let host_a = Name::try_from_str("alpha.local.").unwrap();
  let mut recs_a = ServiceRecords::new(stype.clone(), inst_a.clone(), host_a, 80, 120);
  recs_a.add_a([192, 168, 1, 1].into());
  let handle_a = s
    .test_register_service(ServiceSpec::new(recs_a), now)
    .unwrap();

  // Service B: already owns the name A will try to rename into.
  let inst_b = Name::try_from_str("Alpha-1._ipp._tcp.local.").unwrap();
  let host_b = Name::try_from_str("beta.local.").unwrap();
  let mut recs_b = ServiceRecords::new(stype, inst_b, host_b, 80, 120);
  recs_b.add_a([192, 168, 1, 2].into());
  s.test_register_service(ServiceSpec::new(recs_b), now)
    .unwrap();

  fn pump_transmits(s: &mut State, t: StdInstant, buf: &mut [u8]) {
    loop {
      match s.poll_one_transmit(t, buf) {
        Some((_tx, TransmitOrigin::Service(h))) => {
          s.note_service_transmit_outcome(
            h,
            t,
            mdns_proto::TransmitDelivery::new(
              mdns_proto::FamilyDelivery::Delivered,
              mdns_proto::FamilyDelivery::Delivered,
            ),
          );
        }
        Some(_) => {}
        None => break,
      }
    }
  }

  // Whether a withdrawal datagram is DUE (non-destructively to the schedule).
  fn withdrawal_due(s: &mut State, t: StdInstant, scratch: &mut [u8]) -> bool {
    s.poll_one_withdrawal(t, scratch).is_some()
  }

  // Advance A to Established so the proto hands off an old-name goodbye on
  // rename (only an ANNOUNCED service has one).
  let a_mailbox = Rc::clone(&s.services.get(&handle_a).unwrap().mailbox);
  let mut buf = [0u8; 1500];
  let mut t = now;
  let mut a_established = false;
  for _ in 0..60 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    pump_transmits(&mut s, t, &mut buf);
    s.push_service_updates(t);
    // Drain the handle-owned mailbox; detect Established and discard the rest.
    while let Some(u) = a_mailbox.borrow_mut().drain_for_test() {
      if matches!(u, ServiceUpdate::Established) {
        a_established = true;
      }
    }
    if a_established {
      break;
    }
  }
  assert!(
    a_established,
    "A must reach Established before the ordering test can verify the goodbye timing"
  );

  // Inject peer conflicts. On the decisive iteration (the one that WILL collide
  // A with B), probe withdrawal-due BEFORE and AFTER push_service_updates.
  let conflict = conflict_for("Alpha._ipp._tcp.local.");
  let peer = RecvMeta::new(
    SocketAddr::from(([192, 168, 1, 200], 5353)),
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
    1,
    Some(255),
    None,
    conflict.len(),
  );

  let mut scratch = [0u8; 1500];
  let mut decisive_before: Option<bool> = None;
  let mut decisive_after: Option<bool> = None;

  for _ in 0..80 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    s.handle_datagram(&peer, &conflict);
    pump_transmits(&mut s, t, &mut buf);

    // Probe BEFORE push_service_updates (wrong-order pump position).
    let before = withdrawal_due(&mut s, t, &mut scratch);
    s.push_service_updates(t);
    // Probe AFTER push_service_updates (correct-order pump position).
    let after = withdrawal_due(&mut s, t, &mut scratch);

    if s
      .services
      .get(&handle_a)
      .map(|c| c.errored)
      .unwrap_or(false)
    {
      decisive_before = Some(before);
      decisive_after = Some(after);
      break;
    }
  }

  let before = decisive_before
    .expect("A must be driven to rename-collision-Conflict within the iteration limit");
  let after = decisive_after.unwrap();

  // CORE ORDERING ASSERTION: the collision withdrawal is begun BY
  // push_service_updates. Before push no withdrawal is due (would have drained
  // nothing); after push its first goodbye round is due, so the pump (which runs
  // after push) flushes it this iteration.
  assert!(
    after,
    "a withdrawal datagram must be DUE after push_service_updates begins the \
       rename-collision withdrawal (so the post-push withdrawal pump drains it this \
       iteration)"
  );
  assert!(
    !before,
    "no withdrawal must be due BEFORE push_service_updates on the decisive \
       iteration (the collision withdrawal is begun by push, not by a prior sweep)"
  );
}

// ── The dual-stack delivery boundary (`TransmitDelivery`) ───────────────────

/// A minimal registerable service spec for the delivery-shape tests.
fn delivery_test_spec(instance: &str) -> mdns_proto::ServiceSpec {
  use mdns_proto::{Name, ServiceRecords, ServiceSpec};
  let mut r = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str(&format!("{instance}._ipp._tcp.local.")).unwrap(),
    Name::try_from_str(&format!("{instance}.local.")).unwrap(),
    631,
    120,
  );
  r.add_a([192, 168, 1, 10].into());
  ServiceSpec::new(r)
}

/// Drain one service's due transmits at `t`, confirming each with `fanout`'s
/// per-family result through the SAME seam the run loop uses. Returns how many
/// were confirmed.
fn confirm_service_round(
  s: &mut State,
  h: ServiceHandle,
  t: StdInstant,
  buf: &mut [u8],
  fanout: Fanout,
) -> usize {
  s.fire_timeouts(t);
  let delivery = fanout.delivery();
  let mut rounds = 0;
  while let Some((_tx, origin)) = s.poll_one_transmit(t, buf) {
    match origin {
      TransmitOrigin::Service(origin_h) if origin_h == h => {
        s.note_service_transmit_outcome(h, t, delivery);
        rounds += 1;
      }
      TransmitOrigin::Service(other) => s.note_service_transmit_outcome(other, t, delivery),
      TransmitOrigin::Query(q) => s.note_query_transmit_outcome(q, t, delivery),
    }
  }
  rounds
}

/// A dual-stack fan-out in which v4 carried the datagram and a BOUND v6 socket
/// rejected it (`ENETUNREACH` and friends). Driving the behaviour tests from the
/// per-family facts rather than a hand-fed [`TransmitDelivery`] keeps the
/// mapping inside the tested path.
const PARTIAL_FANOUT: Fanout = Fanout {
  v4: FamilySend::Sent,
  v6: FamilySend::Failed,
};

/// Both bound families carried the datagram.
const WHOLE_FANOUT: Fanout = Fanout {
  v4: FamilySend::Sent,
  v6: FamilySend::Sent,
};

/// Both bound families rejected it — nothing reached any wire.
const FAILED_FANOUT: Fanout = Fanout {
  v4: FamilySend::Failed,
  v6: FamilySend::Failed,
};

/// The confirm is a pure, per-family function of the I/O facts, and the obligated
/// set is "every family that HAS a socket". The rows that matter: an absent family
/// is not obligated (a single-stack host advances at full speed), a
/// present-but-failing one is, and an empty obligated set delivers to nobody —
/// never a vacuous "all", which would let a torn-down endpoint advance its
/// lifecycle on nothing.
///
/// WHICH family missed survives to the core, so it can schedule the next
/// announcement per link. The two partial rows differ here; under the aggregate
/// confirm they were the same value.
#[test]
fn the_fan_out_reaches_the_core_per_family() {
  use FamilySend::{Failed, Sent, Unbound};
  use mdns_proto::FamilyDelivery::{Delivered, Missed, Unobligated};
  let cases = [
    (Sent, Sent, Delivered, Delivered),
    (Sent, Unbound, Delivered, Unobligated),
    (Unbound, Sent, Unobligated, Delivered),
    (Sent, Failed, Delivered, Missed),
    (Failed, Sent, Missed, Delivered),
    (Failed, Failed, Missed, Missed),
    (Failed, Unbound, Missed, Unobligated),
    (Unbound, Unbound, Unobligated, Unobligated),
  ];
  for (v4, v6, want_v4, want_v6) in cases {
    let delivery = Fanout { v4, v6 }.delivery();
    assert_eq!(
      (delivery.v4(), delivery.v6()),
      (want_v4, want_v6),
      "({v4:?}, {v6:?}) must reach the core as ({want_v4}, {want_v6})"
    );
  }
}

/// The invariant pair at the driver seam. A partial fan-out means two DIFFERENT
/// things to the core and must not be folded to one bit:
///
///   * goodbye ownership LATCHES — the served family's peers may now hold the
///     records that reached the wire, so a later unregister owes them a §10.1
///     TTL=0 withdrawal;
///   * the §8.3 phase does NOT advance, and the reclaim-cancel gate stays shut —
///     the unserved family was neither asked nor told.
///
/// The shipped `sent_any` boolean had no truthful value here: it advanced the
/// phase on the unserved family's behalf.
#[test]
fn a_partial_fan_out_latches_ownership_without_advancing_the_phase() {
  use mdns_proto::service::ServiceState;

  let mut s = State::new(
    mdns_proto::EndpointConfig::new().with_probe_unique_names(false),
    1500,
    9000,
  );
  let now = StdInstant::now();
  let h = s
    .test_register_service(delivery_test_spec("partial"), now)
    .unwrap();
  let mut buf = vec![0u8; 4096];

  // Exactly ONE confirm, so the bounded policy provably cannot have fired.
  assert_eq!(
    confirm_service_round(&mut s, h, now, &mut buf, PARTIAL_FANOUT),
    1,
    "one announcement should have been offered"
  );

  assert_eq!(
    s.services[&h].proto.state(),
    ServiceState::Announcing(0),
    "a partial announcement must re-arm the SAME announcement — the unserved \
     family never heard it"
  );
  assert!(
    s.services[&h].proto.advertises_instance(),
    "the served family's peers may now cache these records, so §10.1 goodbye \
     ownership must latch on the PARTIAL round"
  );
  assert!(
    !s.services[&h].proto.has_fully_announced().get(),
    "a partial announcement must NOT open the reclaim-cancel gate"
  );

  // The headline regression: ownership latched, so a graceful unregister really
  // does retract. Had the partial round dropped ownership the snapshot would be
  // empty and the wire silent.
  s.begin_service_withdrawal(h, now);
  assert!(
    s.poll_one_withdrawal(now, &mut buf).is_some(),
    "a partially-announced service must still emit a §10.1 TTL=0 goodbye for the \
     records the served family put into peer caches"
  );
}

/// The other half of the pair: when EVERY obligated family carried the datagram,
/// the same confirm both latches ownership and advances the phase — and only then
/// does the reclaim-cancel gate open.
#[test]
fn a_fully_delivered_fan_out_latches_ownership_and_advances_the_phase() {
  use mdns_proto::service::ServiceState;

  let mut s = State::new(
    mdns_proto::EndpointConfig::new().with_probe_unique_names(false),
    1500,
    9000,
  );
  let now = StdInstant::now();
  let h = s
    .test_register_service(delivery_test_spec("full"), now)
    .unwrap();
  let mut buf = vec![0u8; 4096];

  assert_eq!(
    confirm_service_round(&mut s, h, now, &mut buf, WHOLE_FANOUT),
    1,
    "one announcement should have been offered"
  );

  assert_eq!(
    s.services[&h].proto.state(),
    ServiceState::Announcing(1),
    "an all-delivered announcement advances the §8.3 sequence"
  );
  assert!(
    s.services[&h].proto.advertises_instance(),
    "a delivered announcement latches goodbye ownership"
  );
  assert!(
    s.services[&h].proto.has_fully_announced().get(),
    "a complete announcement is the ONLY thing that opens the reclaim-cancel gate"
  );
}

/// A fan-out that reached NO wire neither latches nor advances: nothing was
/// exposed to any peer, so there is nothing to retract, and no family heard the
/// announcement, so the phase must not move.
#[test]
fn a_wholly_failed_fan_out_neither_latches_nor_advances() {
  use mdns_proto::service::ServiceState;

  let mut s = State::new(
    mdns_proto::EndpointConfig::new().with_probe_unique_names(false),
    1500,
    9000,
  );
  let now = StdInstant::now();
  let h = s
    .test_register_service(delivery_test_spec("failed"), now)
    .unwrap();
  let mut buf = vec![0u8; 4096];

  assert_eq!(
    confirm_service_round(&mut s, h, now, &mut buf, FAILED_FANOUT),
    1,
    "one announcement should have been offered"
  );

  assert_eq!(
    s.services[&h].proto.state(),
    ServiceState::Announcing(0),
    "a wholly-failed announcement must re-arm without advancing"
  );
  assert!(
    !s.services[&h].proto.advertises_instance(),
    "nothing reached a wire, so no peer can hold these records and no goodbye \
     ownership may latch"
  );

  s.begin_service_withdrawal(h, now);
  assert!(
    s.poll_one_withdrawal(now, &mut buf).is_none(),
    "an unadvertised service has nothing to retract, so its withdrawal must put \
     no datagram on the wire"
  );
}

/// RFC 6762 §9 surviving rename: the renamed-away old name's detached goodbye is
/// enqueued RECLAIMABLE, so a replacement that takes the vacated name can cancel
/// it — but ONLY once that replacement has fully announced. A replacement that
/// reached one family alone must not cancel a goodbye the OTHER family still
/// needs; the shipped driver cancelled on the any-delivered exposure latch and
/// left every peer on the unserved family holding the old registration's records
/// until their positive TTL expired.
///
/// The old goodbye's per-family debt is what makes "both families" concrete: this
/// drives a v4-only goodbye round first, so the item still owes IPv6 when the
/// replacement announces.
#[test]
fn a_surviving_rename_retracts_its_old_name_on_both_families() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  use mdns_proto::{
    Name,
    service::ServiceState,
    wire::{Header, MessageBuilder},
  };

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24)];
  s.bound_interface = 1;
  let now = StdInstant::now();
  let old_inst = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
  let handle = s
    .test_register_service(delivery_test_spec("Old"), now)
    .unwrap();
  let mut buf = vec![0u8; 4096];

  // Drive "Old" to fully announced, so its rename hands off a NON-empty goodbye.
  let mut t = now;
  for _ in 0..40 {
    t += Duration::from_millis(300);
    confirm_service_round(&mut s, handle, t, &mut buf, WHOLE_FANOUT);
  }
  assert!(
    s.services[&handle].proto.advertises_instance(),
    "Old must announce before the rename (so the goodbye is non-empty)"
  );

  // A conflicting SRV authority for "Old" with rival rdata: we lose the §8.2
  // tiebreak and rename away. No LOCAL service owns the new name, so this is a
  // SURVIVING rename and its old-name goodbye is enqueued reclaimable.
  let conflict = {
    let target = Name::try_from_str("rival.local.").unwrap();
    let mut cbuf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut cbuf, Header::new()).unwrap();
    b.push_srv_authority(&old_inst, 120, 0, 0, 9999, &target)
      .unwrap();
    let n = b.finish().unwrap();
    cbuf[..n].to_vec()
  };
  let peer = RecvMeta::new(
    SocketAddr::from(([192, 168, 1, 200], 5353)),
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
    1,
    Some(255),
    None,
    conflict.len(),
  );
  let mut renamed = false;
  for _ in 0..80 {
    t += Duration::from_millis(250);
    s.handle_datagram(&peer, &conflict);
    confirm_service_round(&mut s, handle, t, &mut buf, WHOLE_FANOUT);
    s.push_service_updates(t);
    if s
      .services
      .get(&handle)
      .map(|c| c.proto.name().as_str() != old_inst.as_str())
      .unwrap_or(true)
    {
      renamed = true;
      break;
    }
  }
  assert!(
    renamed,
    "Old must rename away under sustained conflict (seeding the detached goodbye)"
  );

  // Goodbye round 1 reaches v4 only: IPv6's debt is still outstanding, which is
  // exactly what a premature cancel would throw away.
  let (_, _, token) = s
    .poll_one_withdrawal(t, &mut buf)
    .expect("the renamed-away old name must have a detached goodbye pending");
  s.note_withdrawal_result(token, t, WithdrawalSend::Sent, WithdrawalSend::Retry);

  // The application reclaims the vacated name.
  let rh = s
    .test_register_service(delivery_test_spec("Old"), t)
    .expect("the vacated name must be re-registerable while its goodbye drains");

  // Drive the replacement's §8.1 probes to completion (a probe is a question and
  // opens no gate) so the next round is its FIRST announcement.
  for _ in 0..12 {
    t += Duration::from_millis(300);
    confirm_service_round(&mut s, rh, t, &mut buf, WHOLE_FANOUT);
    if s.services[&rh].proto.state() == ServiceState::Announcing(0) {
      break;
    }
  }
  assert_eq!(
    s.services[&rh].proto.state(),
    ServiceState::Announcing(0),
    "the replacement must reach its first announcement"
  );

  // Exactly ONE partially-delivered announcement — the bounded policy provably
  // cannot have excused anything yet.
  t += Duration::from_millis(300);
  confirm_service_round(&mut s, rh, t, &mut buf, PARTIAL_FANOUT);
  assert!(
    !s.services[&rh].proto.has_fully_announced().get(),
    "a partial announcement must leave the reclaim-cancel gate shut"
  );
  assert!(
    s.poll_one_withdrawal(t, &mut buf).is_some(),
    "a partially-announced replacement must NOT cancel the old name's goodbye — \
     the unserved family has heard neither the goodbye nor the replacement, and \
     its share of the per-family debt is still owed"
  );

  // Once the replacement reaches every obligated family, §10.2's cache-flush
  // announcement supersedes the stale records and the goodbye may be cancelled.
  t += Duration::from_secs(2);
  confirm_service_round(&mut s, rh, t, &mut buf, WHOLE_FANOUT);
  assert!(
    s.services[&rh].proto.has_fully_announced().get(),
    "the replacement must have fully announced by now"
  );
  assert!(
    s.poll_one_withdrawal(t, &mut buf).is_none(),
    "a fully-announced replacement supersedes the old records on every obligated \
     family, so the reclaimable goodbye is cancelled"
  );
}

/// RFC 6762 §6.7 legacy unicast reply: no self-send credit.
///
/// A unicast datagram leaves for the querier's own address and ephemeral port and
/// never loops back through the multicast group we joined, so a credit recorded
/// for it can never be consumed. It would occupy the linear-scanned tracker for
/// `SELF_SEND_TTL`, and at `MAX_SELF_SEND_ENTRIES` `record_self_send` declines the
/// NEW entry — so a legacy-query flood would starve the genuine multicast credits
/// that loopback suppression depends on.
#[compio::test]
async fn a_legacy_unicast_reply_records_no_self_send_credit() {
  use crate::socket::Socket;

  let inner = Rc::new(EndpointInner::new(
    mdns_proto::EndpointConfig::default(),
    1500,
    9000,
  ));

  // A real bound socket, so this exercises the actual send path rather than the
  // absent-socket short circuit.
  let sender = Socket::from_std(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
    .await
    .expect("wrap a loopback sender");
  let querier = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
  let querier_addr = querier.local_addr().unwrap();

  let sock_v4 = Some(Rc::new(sender));
  let sock_v6: Option<Rc<Socket>> = None;

  let fanout = send_via(
    &inner,
    &sock_v4,
    &sock_v6,
    querier_addr,
    b"legacy-unicast-reply",
  )
  .await;

  assert_eq!(
    fanout.delivery(),
    mdns_proto::TransmitDelivery::new(
      mdns_proto::FamilyDelivery::Delivered,
      mdns_proto::FamilyDelivery::Unobligated,
    ),
    "a §6.7 reply obligates exactly the destination's family; the other one was \
     never offered the datagram and must not read as a miss"
  );
  assert!(
    inner.state.borrow().recent_sends.is_empty(),
    "a unicast reply never loops back, so it must record NO self-send credit"
  );
}

// ── The obligation tag (`TransmitObligation`) at the driver seam ────────────

/// A §6.7 legacy unicast reply reaches exactly ONE family, so its fan-out is
/// `AllDelivered` by construction.
const UNICAST_FANOUT: Fanout = Fanout {
  v4: FamilySend::Sent,
  v6: FamilySend::Unbound,
};

/// Drain one service's due transmits at `t` through the SAME seam the run loop
/// uses, choosing each datagram's fan-out the way `send_via` would: an mDNS
/// MULTICAST destination is fanned onto both families (and so can be partial),
/// while a §6.7 legacy UNICAST reply reaches the single family its destination
/// names. Returns how many datagrams were confirmed.
fn confirm_service_round_mixed(
  s: &mut State,
  h: ServiceHandle,
  t: StdInstant,
  buf: &mut [u8],
  multicast_fanout: Fanout,
) -> usize {
  s.fire_timeouts(t);
  let mut rounds = 0;
  while let Some((tx, origin)) = s.poll_one_transmit(t, buf) {
    let fanout = if tx.dst().ip().is_multicast() {
      multicast_fanout
    } else {
      UNICAST_FANOUT
    };
    let delivery = fanout.delivery();
    match origin {
      TransmitOrigin::Service(origin_h) => {
        s.note_service_transmit_outcome(origin_h, t, delivery);
        if origin_h == h {
          rounds += 1;
        }
      }
      TransmitOrigin::Query(q) => s.note_query_transmit_outcome(q, t, delivery),
    }
  }
  rounds
}

/// Feed a browse (PTR) query for the sample service type through the driver's
/// own receive path. A `src` port of 5353 elicits a jittered §6 MULTICAST
/// response; any other port elicits a §6.7 legacy UNICAST reply.
fn inject_ptr_query(s: &mut State, src: core::net::SocketAddr, t: StdInstant) {
  use core::net::{IpAddr, Ipv4Addr};

  use mdns_proto::{
    Name,
    wire::{Header, MessageBuilder, ResourceClass, ResourceType},
  };

  use crate::socket::RecvMeta;

  let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let mut qbuf = [0u8; 512];
  let n = {
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false)
      .unwrap();
    b.finish().unwrap()
  };
  let meta = RecvMeta::new(
    src,
    IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
    1,
    Some(255), // §11 on-link
    None,
    n,
  );
  let _ = t;
  s.handle_datagram(&meta, &qbuf[..n]);
}

/// Bypassing the bound for a one-shot datagram must not bypass the CORE confirm:
/// the outcome still reaches `Service::note_transmit_outcome` verbatim, so a
/// delivered response latches §10.1 goodbye ownership for the records it put on
/// the wire.
#[test]
fn a_one_shot_confirm_still_latches_goodbye_ownership() {
  let mut s = State::new(
    mdns_proto::EndpointConfig::new().with_probe_unique_names(false),
    1500,
    9000,
  );
  let now = StdInstant::now();
  let h = s
    .test_register_service(delivery_test_spec("oneshot"), now)
    .unwrap();
  let mut buf = vec![0u8; 4096];

  // The lifecycle reaches no wire at all, so nothing it sends can latch.
  confirm_service_round(&mut s, h, now, &mut buf, FAILED_FANOUT);
  assert!(
    !s.services[&h].proto.advertises_instance(),
    "a wholly-failed announcement exposes nothing"
  );

  // A §6.7 legacy querier is served over the one family its destination names.
  let legacy = core::net::SocketAddr::from(([192, 168, 1, 50], 6000));
  let t = now + Duration::from_millis(50);
  inject_ptr_query(&mut s, legacy, t);
  assert_eq!(
    confirm_service_round_mixed(&mut s, h, t, &mut buf, FAILED_FANOUT),
    1,
    "only the legacy reply is due this early"
  );
  assert!(
    s.services[&h].proto.advertises_instance(),
    "the reply put positive-TTL records on a wire, so §10.1 ownership latches — \
     the confirm reaches the core unchanged, it just skips the bound"
  );
  assert!(
    !s.services[&h].proto.has_fully_announced().get(),
    "an all-delivered UNICAST reply is still not a complete announcement"
  );
}

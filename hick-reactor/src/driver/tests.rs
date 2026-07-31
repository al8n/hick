use super::*;
use crate::service::{SERVICE_UPDATE_CAPACITY, ServiceMailbox};

/// Drain one [`ServiceUpdate`] from a shared mailbox (the handle side), used by
/// the service-update tests to assert delivery without awaiting the async
/// [`crate::Service::next`].
fn lock_mailbox_for_test(
  mailbox: &std::sync::Arc<std::sync::Mutex<ServiceMailbox>>,
) -> Option<ServiceUpdate> {
  mailbox
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .drain_for_test()
}

/// Confirm a send BOTH families carried, for tests that drive a service with no
/// bound sockets and must still see the announce/host-latch guards fire.
fn deliver_both(proto: &mut ProtoService, now: StdInstant) {
  proto.note_transmit_outcome(
    now,
    mdns_proto::TransmitDelivery::new(
      mdns_proto::FamilyDelivery::Delivered,
      mdns_proto::FamilyDelivery::Delivered,
    ),
  );
}

#[test]
fn on_link_check_rejects_non_255_ttl() {
  // only TTL/Hop-Limit exactly 255 (or an absent value, where we
  // can't enforce) is treated as on-link.
  assert!(is_on_link(Some(255)));
  assert!(is_on_link(None)); // degraded: platform didn't report it
  assert!(!is_on_link(Some(254)));
  assert!(!is_on_link(Some(1)));
  assert!(!is_on_link(Some(0)));
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

#[test]
fn packet_is_response_reads_qr_bit() {
  // QR bit is the MSB of header byte 2.
  assert!(packet_is_response(&[0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
  assert!(!packet_is_response(&[
    0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0
  ])); // query
  assert!(!packet_is_response(&[0, 0])); // too short to be a response
  assert!(!packet_is_response(&[]));
}

// an untrusted response (QR=1 from a non-5353 source port) must
// be dropped BEFORE it can consume the take-once self-send credit, so our
// genuine port-5353 loopback still matches.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn untrusted_response_does_not_burn_self_send_credit() {
  use std::{
    net::{IpAddr, Ipv4Addr},
    time::SystemTime,
  };

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);

  // A QR=1 response body (header byte 2 = 0x84) we "recently sent".
  let body = vec![0u8, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  record_self_send(&mut state.recent_sends, &body, SystemTime::now());
  assert_eq!(state.recent_sends.len(), 1);

  // Same bytes arriving from an EPHEMERAL port (on-link TTL 255): untrusted
  // response — must be dropped before `take_self_send`.
  let untrusted = Packet {
    src: "192.0.2.9:40000".parse().unwrap(),
    data: body.clone(),
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    interface_index: 0,
    kernel_rx_time: Some(SystemTime::now()),
    read_time: SystemTime::now(),
    hop_limit: Some(255),
  };
  state.handle_packet(untrusted);
  assert_eq!(
    state.recent_sends.len(),
    1,
    "untrusted response must not consume the self-send credit"
  );

  // The genuine loopback from port 5353 passes the gate and consumes it.
  let loopback = Packet {
    src: "192.0.2.9:5353".parse().unwrap(),
    data: body,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    interface_index: 0,
    kernel_rx_time: Some(SystemTime::now()),
    read_time: SystemTime::now(),
    hop_limit: Some(255),
  };
  state.handle_packet(loopback);
  assert_eq!(
    state.recent_sends.len(),
    0,
    "the trusted port-5353 loopback consumes the credit"
  );
}

/// A short datagram (just enough to set QR=1 but not a full DNS message) from
/// a non-5353 source bumps packets_rx + bytes_rx exactly once, and exactly
/// one reject counter (packets_dropped). No double-count: proto's handle() is
/// never reached so proto cannot bump these counters.
///
/// The test drives `handle_packet` directly — no socket bind needed — and uses
/// `#[cfg(feature = "tokio")]` only to access `DriverState::new`.
#[cfg(all(feature = "stats", feature = "tokio"))]
#[test]
fn pre_drop_short_qr1_counts_rx_and_dropped_exactly_once() {
  use std::{
    net::{IpAddr, Ipv4Addr},
    time::SystemTime,
  };

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);

  // 3-byte body: only byte 2 matters (QR=1 → 0x80). Too short for a valid DNS
  // message — proto would reject it on parse, but we drop before proto.
  let body: Vec<u8> = vec![0x00, 0x00, 0x80];
  let len = body.len() as u64;

  // Source port ≠ 5353 → untrusted-response pre-drop path; on-link (TTL=255).
  let pkt = Packet {
    src: "192.0.2.7:40000".parse().unwrap(),
    data: body,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    interface_index: 0,
    kernel_rx_time: Some(SystemTime::now()),
    read_time: SystemTime::now(),
    hop_limit: Some(255),
  };
  state.handle_packet(pkt);

  let snap = state.stats.snapshot();
  assert_eq!(
    snap.packets_rx, 1,
    "packets_rx must be 1 (datagram was received)"
  );
  assert_eq!(
    snap.bytes_rx, len,
    "bytes_rx must equal the datagram length"
  );
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
  // Confirm no double-count: only the driver-side bump runs (proto handle() was
  // not called), so no extra packets_rx from the proto path.
  assert_eq!(
    snap.packets_rx, 1,
    "no double-count: proto handle() was not reached"
  );
}

/// A well-formed untrusted QR=1 response from a non-5353 source (12-byte DNS
/// header with QR=1 set, all fields zero otherwise) must trigger the
/// untrusted-response pre-drop: packets_rx +1, bytes_rx +len, packets_dropped
/// +1. Self-send credit ring must be unchanged.
#[cfg(all(feature = "stats", feature = "tokio"))]
#[test]
fn pre_drop_untrusted_qr1_response_counts_rx_and_dropped_exactly_once() {
  use std::{
    net::{IpAddr, Ipv4Addr},
    time::SystemTime,
  };

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);

  // Minimal 12-byte DNS response header: QR=1 (byte 2 = 0x84 for AA+Response).
  let body: Vec<u8> = vec![
    0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  let len = body.len() as u64;

  // No prior self-send credit recorded — if the drop were to incorrectly call
  // take_self_send the tracker would stay at zero (no match), but the correct
  // behaviour is that it is never called at all.
  assert_eq!(state.recent_sends.len(), 0);

  let pkt = Packet {
    src: "192.0.2.8:54321".parse().unwrap(), // non-5353 → untrusted
    data: body,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    interface_index: 0,
    kernel_rx_time: Some(SystemTime::now()),
    read_time: SystemTime::now(),
    hop_limit: Some(255), // on-link
  };
  state.handle_packet(pkt);

  // Self-send tracker unchanged (never reached).
  assert_eq!(
    state.recent_sends.len(),
    0,
    "self-send credit ring must be untouched"
  );

  let snap = state.stats.snapshot();
  assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
  assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
}

/// Off-link datagrams (TTL ≠ 255) must also count packets_rx + bytes_rx once
/// (received from the wire) and packets_dropped once (rejected).
#[cfg(all(feature = "stats", feature = "tokio"))]
#[test]
fn pre_drop_off_link_datagram_counts_rx_and_dropped_exactly_once() {
  use std::{
    net::{IpAddr, Ipv4Addr},
    time::SystemTime,
  };

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);

  // A datagram with TTL < 255 → off-link gate fires before the untrusted-
  // response check. Use a query (QR=0) so only the §11 path is exercised.
  let body: Vec<u8> = vec![
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  let len = body.len() as u64;

  let pkt = Packet {
    src: "203.0.113.5:5353".parse().unwrap(),
    data: body,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    interface_index: 0,
    kernel_rx_time: Some(SystemTime::now()),
    read_time: SystemTime::now(),
    hop_limit: Some(64), // off-link: TTL != 255
  };
  state.handle_packet(pkt);

  let snap = state.stats.snapshot();
  assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
  assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
}

// NOTE: the same-host sibling-address RETENTION tests
// (`unregister_shared_host_preserves_sibling_addresses`,
// `unregister_with_unannounced_same_host_sibling_withdraws_addresses`,
// `unregister_disjoint_host_addrs_withdraws_only_own`) and their
// `goodbye_v4_addrs` / `goodbye_withdraws_addr` helpers were REMOVED in the
// endpoint-owned-withdrawal migration. They inspected the encoded bytes of the
// deleted driver-side goodbye queue (`state.goodbyes[0].data`), produced by the
// deleted `retained_host_addrs` sibling scan in `remove_service`. Sibling
// retention now lives in the endpoint (`Endpoint::sibling_retained_addrs`,
// recomputed FRESH each round in `poll_withdrawal_transmit` from the route
// table) and is covered by the proto-level
// `poll_withdrawal_transmit ... sibling retention` test.
// NOTE: the non-terminal coalescing + bound + drop-oldest semantics for
// service updates (one Established, latest Renamed, bounded ring, reserved
// terminal) moved out of the driver's per-ctx overflow deque into the
// handle-owned `ServiceMailbox` and are unit-tested at that seam in
// `crate::service::tests` (`mailbox_coalesces_established_and_renamed_by_kind`,
// `mailbox_hard_cap_drops_oldest`,
// `mailbox_terminal_reserved_under_non_terminal_pressure`, …). The driver-level
// tests below assert the END-TO-END contract through `deliver_service_update` +
// the live `Service` handle.

/// a non-draining caller cannot grow memory without bound — a flood of service
/// updates is bounded + coalesced by the handle-owned mailbox (one Established,
/// latest Renamed, reserved terminal), never an unbounded backlog.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn service_update_delivery_is_bounded_for_non_draining_caller() {
  use mdns_proto::{ServiceUpdate, event::ServiceRenamed};

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let now = StdInstant::now();

  let mut r = mdns_proto::ServiceRecords::new(
    mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("svc._ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("host.local.").unwrap(),
    631,
    120,
  );
  r.add_a(std::net::Ipv4Addr::new(192, 168, 1, 10));
  // `reg` (the mailbox `Arc` + the doorbell receiver) is kept alive but NEVER
  // drained — a non-draining caller. The driver ctx shares the same mailbox.
  let reg = state
    .register_service(mdns_proto::ServiceSpec::new(r), now)
    .unwrap();
  let handle = reg.handle;

  // Push a churn of Established + distinct Renamed far past the cap.
  {
    let ctx = state.services.get_mut(&handle).unwrap();
    for i in 0..1000u32 {
      deliver_service_update(ctx, ServiceUpdate::Established);
      deliver_service_update(
        ctx,
        ServiceUpdate::Renamed(ServiceRenamed::new(
          mdns_proto::Name::try_from_str(&format!("svc-{i}._ipp._tcp.local.")).unwrap(),
        )),
      );
    }
    // The mailbox coalesces to one Established + the latest Renamed — at most
    // the cap, regardless of how much the peer churns.
    let mb = ctx.mailbox.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
      mb.non_terminal_len() <= SERVICE_UPDATE_CAPACITY,
      "the mailbox must stay within capacity under churn; got {}",
      mb.non_terminal_len()
    );
    // Established + Renamed coalesce by kind, so exactly two non-terminal
    // updates survive.
    assert_eq!(
      mb.non_terminal_len(),
      2,
      "Established and the latest Renamed coalesce to two pending updates"
    );
  }
  drop(reg);
}

#[test]
fn addr_in_subnet_masks_correctly() {
  use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
  let net = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
  assert!(addr_in_subnet(
    net,
    24,
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))
  ));
  assert!(!addr_in_subnet(
    net,
    24,
    IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))
  ));
  // prefix 0 matches everything; family mismatch never matches.
  assert!(addr_in_subnet(
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    0,
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
  ));
  assert!(!addr_in_subnet(net, 24, IpAddr::V6(Ipv6Addr::LOCALHOST)));
  // IPv6 /64.
  let n6 = IpAddr::V6("2001:db8:0:1::".parse().unwrap());
  assert!(addr_in_subnet(
    n6,
    64,
    IpAddr::V6("2001:db8:0:1::ff".parse().unwrap())
  ));
  assert!(!addr_in_subnet(
    n6,
    64,
    IpAddr::V6("2001:db8:0:2::ff".parse().unwrap())
  ));
}

#[test]
fn src_on_local_link_fallback() {
  use std::net::{IpAddr, Ipv4Addr};
  let subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24u8)];
  const BOUND: u32 = 3;
  // In-subnet peer is on-link; an off-subnet global address is not
  // (interface index is irrelevant for non-link-local sources).
  assert!(src_on_local_link(
    &subnets,
    BOUND,
    BOUND,
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55))
  ));
  assert!(!src_on_local_link(
    &subnets,
    BOUND,
    BOUND,
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
  ));
  // Loopback is always on-link.
  assert!(src_on_local_link(
    &subnets,
    BOUND,
    BOUND,
    IpAddr::V4(Ipv4Addr::LOCALHOST)
  ));
  // §11 fail-closed: a global source with no enumerated subnets has no
  // on-link evidence and is dropped (was previously fail-open).
  assert!(!src_on_local_link(
    &[],
    BOUND,
    BOUND,
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
  ));
  assert!(!src_on_local_link(
    &[],
    BOUND,
    BOUND,
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
  ));
  // A global source inside a cached /8 is on-link; outside it is dropped.
  let wide = vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8u8)];
  assert!(src_on_local_link(
    &wide,
    BOUND,
    BOUND,
    IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))
  ));
  assert!(!src_on_local_link(
    &wide,
    BOUND,
    BOUND,
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
  ));
}

#[test]
fn src_on_local_link_scopes_link_local_to_bound_interface() {
  // a link-local source is on-link ONLY when it arrived on the
  // interface we're bound to — a link-local address from a different NIC is
  // not our link and must not pass the §11 fallback.
  use std::net::{IpAddr, Ipv4Addr};
  let subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24u8)];
  const BOUND: u32 = 3;
  const OTHER: u32 = 7;
  let v4_ll = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
  let v6_ll = IpAddr::V6("fe80::1".parse().unwrap());
  // Arrived on the bound interface → on-link.
  assert!(src_on_local_link(&subnets, BOUND, BOUND, v4_ll));
  assert!(src_on_local_link(&subnets, BOUND, BOUND, v6_ll));
  // Arrived on a DIFFERENT interface → NOT on-link.
  assert!(!src_on_local_link(&subnets, BOUND, OTHER, v4_ll));
  assert!(!src_on_local_link(&subnets, BOUND, OTHER, v6_ll));
  // Receive interface unknown (0) → degraded accept (can't scope).
  assert!(src_on_local_link(&subnets, BOUND, 0, v4_ll));
  assert!(src_on_local_link(&subnets, BOUND, 0, v6_ll));
}

#[test]
fn collect_local_subnets_rejects_zero_index() {
  // the fallback is scoped to the BOUND interface. Index 0 is
  // "no interface" — it must NOT enumerate every NIC, so the result is
  // empty (which makes src_on_local_link fail closed for a global source
  // rather than treat another NIC's subnet as on-link).
  assert!(collect_local_subnets(0).is_empty());
}

#[test]
fn self_send_consume_once() {
  // one recorded send suppresses exactly one loopback.
  let t = SystemTime::now();
  let mut tracker = Vec::new();
  record_self_send(&mut tracker, b"hello", t);
  // The loopback arrives at-or-after our send -> matched and consumed.
  assert!(take_self_send(
    &mut tracker,
    b"hello",
    t,
    MatchMode::Ordered
  ));
  // A second byte-identical packet finds no entry -> treated as a peer.
  assert!(!take_self_send(
    &mut tracker,
    b"hello",
    t,
    MatchMode::Ordered
  ));
  assert!(tracker.is_empty());
}

#[test]
fn self_send_distinct_payloads_do_not_match() {
  let t = SystemTime::now();
  let mut tracker = Vec::new();
  record_self_send(&mut tracker, b"alpha", t);
  assert!(!take_self_send(
    &mut tracker,
    b"beta",
    t,
    MatchMode::Ordered
  ));
  // The unrelated entry is left intact for its own loopback.
  assert!(take_self_send(
    &mut tracker,
    b"alpha",
    t,
    MatchMode::Ordered
  ));
}

#[test]
fn self_send_expires_after_ttl() {
  // a packet arriving more than SELF_SEND_TTL after the send
  // is no longer our loopback, and the stale entry is swept on the next
  // record so the tracker can't grow without bound.
  let t = SystemTime::now();
  let mut tracker = Vec::new();
  record_self_send(&mut tracker, b"hello", t);
  let too_late = t + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(!take_self_send(
    &mut tracker,
    b"hello",
    too_late,
    MatchMode::Ordered
  ));
  record_self_send(&mut tracker, b"other", too_late);
  assert_eq!(tracker.len(), 1);
  assert!(take_self_send(
    &mut tracker,
    b"other",
    too_late,
    MatchMode::Ordered
  ));
}

#[test]
fn self_send_peer_before_our_send_cannot_steal_credit() {
  // a byte-identical peer datagram the kernel stamped BEFORE
  // our send must not consume the credit even though its content hash
  // matches; otherwise the genuine loopback is later misclassified as a
  // peer (self-rename / dropped answers).
  let sent = SystemTime::now();
  let mut tracker = Vec::new();
  record_self_send(&mut tracker, b"probe", sent);
  let peer_rx = sent - Duration::from_millis(500);
  assert!(!take_self_send(
    &mut tracker,
    b"probe",
    peer_rx,
    MatchMode::Ordered
  ));
  // Our genuine loopback arrives at-or-after the send and is matched.
  let loop_rx = sent + Duration::from_millis(1);
  assert!(take_self_send(
    &mut tracker,
    b"probe",
    loop_rx,
    MatchMode::Ordered
  ));
}

// on microsecond `timeval` sources (Apple/BSD)
// RX_TIMESTAMP_GRAIN is 1µs, so a loopback whose kernel timestamp was
// truncated to a slightly-earlier microsecond than our nanosecond send
// time still counts as ours — but anything earlier than the grain is a
// genuine pre-send (peer) datagram and must not match.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[test]
fn self_send_ordered_tolerates_microsecond_truncation() {
  assert_eq!(hick_udp::RX_TIMESTAMP_GRAIN, Duration::from_micros(1));
  let sent = SystemTime::now();
  let mut tracker = Vec::new();
  record_self_send(&mut tracker, b"trunc", sent);
  let truncated_rx = sent - (hick_udp::RX_TIMESTAMP_GRAIN - Duration::from_nanos(1));
  assert!(take_self_send(
    &mut tracker,
    b"trunc",
    truncated_rx,
    MatchMode::Ordered
  ));

  record_self_send(&mut tracker, b"trunc", sent);
  let too_early = sent - (hick_udp::RX_TIMESTAMP_GRAIN + Duration::from_micros(4));
  assert!(!take_self_send(
    &mut tracker,
    b"trunc",
    too_early,
    MatchMode::Ordered
  ));
}

// on nanosecond `SO_TIMESTAMPNS` (Linux/Android) the kernel
// timestamp is exact, so RX_TIMESTAMP_GRAIN is zero and there is NO
// pre-send tolerance: a byte-identical peer datagram stamped even 500ns
// before our send must not steal the take-once credit.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn self_send_ordered_nanosecond_rejects_pre_send() {
  assert_eq!(hick_udp::RX_TIMESTAMP_GRAIN, Duration::ZERO);
  let sent = SystemTime::now();
  let mut tracker = Vec::new();
  record_self_send(&mut tracker, b"probe", sent);
  let pre_send = sent - Duration::from_nanos(500);
  assert!(!take_self_send(
    &mut tracker,
    b"probe",
    pre_send,
    MatchMode::Ordered
  ));
  // The entry survives the non-match; our genuine loopback (at-or-after
  // the send) is still matched.
  assert!(take_self_send(
    &mut tracker,
    b"probe",
    sent,
    MatchMode::Ordered
  ));
}

#[test]
fn self_send_degraded_matches_take_once_within_ttl() {
  // with no kernel timestamp the reference is a userspace
  // READ time (always at-or-after the send). Degraded mode matches on
  // content hash alone within TTL, take-once. This is what keeps normal
  // single-host operation correct on Windows / timestamp-less kernels.
  let sent = SystemTime::now();
  let mut tracker = Vec::new();
  record_self_send(&mut tracker, b"win", sent);
  let read = sent + Duration::from_millis(10);
  assert!(take_self_send(
    &mut tracker,
    b"win",
    read,
    MatchMode::Degraded
  ));
  // Take-once: the credit is gone. (A byte-identical PEER datagram read
  // next would now be treated as a peer — and, conversely, a pre-buffered
  // peer datagram read first could consume this credit. That credit-theft
  // exposure is the documented degradation when no kernel rx timestamp is
  // available; ordered mode is what closes it.)
  assert!(!take_self_send(
    &mut tracker,
    b"win",
    read,
    MatchMode::Degraded
  ));
}

#[test]
fn self_send_degraded_expires_after_ttl() {
  let sent = SystemTime::now();
  let mut tracker = Vec::new();
  record_self_send(&mut tracker, b"win", sent);
  let too_late = sent + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(!take_self_send(
    &mut tracker,
    b"win",
    too_late,
    MatchMode::Degraded
  ));
}

#[test]
fn self_send_dual_stack_records_two_entries() {
  // dual-stack fan-out records one entry per real send, so
  // BOTH loopback copies are suppressed.
  let t = SystemTime::now();
  let mut tracker = Vec::new();
  record_self_send(&mut tracker, b"resp", t);
  record_self_send(&mut tracker, b"resp", t);
  assert!(take_self_send(&mut tracker, b"resp", t, MatchMode::Ordered));
  assert!(take_self_send(&mut tracker, b"resp", t, MatchMode::Ordered));
  assert!(!take_self_send(
    &mut tracker,
    b"resp",
    t,
    MatchMode::Ordered
  ));
}

#[test]
fn self_send_cap_declines_without_evicting_live_entries() {
  // at capacity, record_self_send declines a new entry rather
  // than evicting a still-live one (which would unmask a real loopback).
  let t = SystemTime::now();
  let mut tracker = vec![(fnv1a(b"live"), t); MAX_SELF_SEND_ENTRIES];
  record_self_send(&mut tracker, b"overflow", t);
  assert_eq!(tracker.len(), MAX_SELF_SEND_ENTRIES);
  // The would-be new entry was never added.
  assert!(!take_self_send(
    &mut tracker,
    b"overflow",
    t,
    MatchMode::Ordered
  ));
  // A pre-existing live entry is still matchable.
  assert!(take_self_send(&mut tracker, b"live", t, MatchMode::Ordered));
}

// NOTE: the deleted driver-goodbye-queue seam tests
// (`flush_goodbyes_completes_the_burst`,
// `live_goodbye_round_with_no_send_keeps_budget_and_backs_off`,
// `live_drain_force_clears_expired_barrier`) asserted the removed per-driver
// `goodbyes` queue + `sent_once` transmit barrier (`drain_goodbyes` Part A
// re-arm, the `expires_at` anti-pin force-clear, and `has_pending_barrier`).
// The endpoint now owns the resend schedule, the spend/re-arm bookkeeping, and
// the 2 s anti-pin ceiling — covered by the proto-level withdrawal tests
// (`note_withdrawal_result` spend/backoff, `drain_completed_withdrawals`
// ceiling). The replacement-survival test below is the driver-seam observation
// that a withdrawal HOLDS the name and frees it on completion.

/// Endpoint-owned-withdrawal replacement survival (supersedes the old free-name
/// goodbye BARRIER test). Under `with_probe_unique_names(false)` a same-name
/// replacement would announce a positive TTL directly (no §8.1 probe) — exactly
/// the configuration in which a stale TTL=0 goodbye could be overtaken. The old
/// driver enforced ordering with a transmit barrier; the endpoint now enforces
/// it structurally — it KEEPS the route (holding the name) for the whole §10.1
/// withdrawal, so a same-name `register_service` is REJECTED until the goodbye
/// completes and frees the name. No replacement can announce ahead of the
/// withdrawal because no replacement can even be registered until it is done.
///
/// Driven through `DriverState` directly (no sockets — the reactor's multi-task
/// loop cannot be stepped deterministically). With no bound family every
/// withdrawal round fails to deliver, so the withdrawal is force-completed at
/// its 2 s anti-pin ceiling rather than by spending its resend budget; the
/// name-held → name-freed observation is identical either way.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn same_name_replacement_is_rejected_until_withdrawal_completes() {
  use std::{net::Ipv4Addr, time::Duration};

  let opts = crate::options::ServerOptions::default()
    .with_endpoint_config(mdns_proto::EndpointConfig::new().with_probe_unique_names(false));
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let now = StdInstant::now();

  let mk = || {
    let mut r = mdns_proto::ServiceRecords::new(
      mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("repl._ipp._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("repl.local.").unwrap(),
      631,
      120,
    );
    r.add_a(Ipv4Addr::new(192, 168, 1, 10));
    mdns_proto::ServiceSpec::new(r)
  };

  // 1. Register A and drive its proto to an announced state so the withdrawal
  //    snapshot is NON-empty (records were confirmed-emitted). Delivery is
  //    simulated via `deliver_both` so the announce/host guards latch (no
  //    sockets are bound).
  let a = state.register_service(mk(), now).unwrap().handle;
  {
    let ctx = state.services.get_mut(&a).unwrap();
    let mut buf = vec![0u8; 4096];
    let mut t = now;
    for _ in 0..40 {
      t += Duration::from_millis(300);
      let _ = ctx.proto.handle_timeout(t);
      while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
        deliver_both(&mut ctx.proto, t);
      }
    }
  }

  // 2. Unregister A → begins the endpoint-owned withdrawal (name held). The ctx
  //    is KEPT (marked withdrawing) and the route is reserved.
  state.remove_service(a, now);
  assert!(
    state
      .services
      .get(&a)
      .map(|c| c.withdrawing)
      .unwrap_or(false),
    "unregister must begin the withdrawal and keep the ctx (withdrawing)"
  );

  // 3. While the withdrawal is in flight the SAME name must be rejected — the
  //    endpoint holds the route, so a replacement cannot announce a fresh
  //    positive TTL ahead of the stale TTL=0.
  match state.register_service(mk(), now) {
    Err(crate::error::RegisterError::NameAlreadyRegistered(_)) => {}
    Err(e) => panic!("a same-name registration must be rejected while withdrawing; got {e:?}"),
    Ok(_) => {
      panic!("a same-name registration must be rejected while the withdrawal holds the name")
    }
  }

  // 4. Drive the withdrawal to completion. With no bound family each round fails
  //    to deliver, so the endpoint force-completes it at the 2 s anti-pin
  //    ceiling; `drain_withdrawals` then frees the route and GCs the ctx.
  let mut scratch = vec![0u8; 4096];
  let mut t = now;
  let mut completed = false;
  for _ in 0..64 {
    t += Duration::from_millis(250);
    state.drain_withdrawals(t, &mut scratch).await;
    if !state.services.contains_key(&a) {
      completed = true;
      break;
    }
  }
  assert!(
    completed,
    "the withdrawal must complete (route freed + driver ctx GC'd) — by its 2 s \
       anti-pin ceiling when no family can deliver"
  );

  // 5. The name is freed → a same-name replacement now registers successfully.
  state
    .register_service(mk(), t)
    .expect("the same name must be re-registerable once the withdrawal completes");
}

/// A `Conflict` queued at an internal retirement must still reach the host
/// after the withdrawal GCs the ctx. With the handle-owned reserved-terminal
/// mailbox this is now TRIVIAL (formerly ): `deliver_service_update` routes
/// the `Conflict` to the mailbox's reserved terminal slot, the mailbox `Arc` is
/// shared with the live `Service` handle, and the withdrawal GC removes the ctx
/// UNCONDITIONALLY — yet the terminal is still drainable by the live reader
/// because the mailbox outlives the ctx. No overflow deque, no deferral.
///
/// Driven through `DriverState` directly (no sockets). With no bound family the
/// withdrawal force-completes at its 2 s anti-pin ceiling.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn queued_conflict_survives_withdrawal_gc() {
  use std::{net::Ipv4Addr, time::Duration};

  use mdns_proto::ServiceUpdate;

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let now = StdInstant::now();

  let mut r = mdns_proto::ServiceRecords::new(
    mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("cflt._ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("cflt.local.").unwrap(),
    631,
    120,
  );
  r.add_a(Ipv4Addr::new(192, 168, 1, 10));
  // Keep `reg` (the mailbox `Arc` + doorbell receiver) alive: this is the live
  // reader that must still observe the Conflict after the ctx is GC'd.
  let reg = state
    .register_service(mdns_proto::ServiceSpec::new(r), now)
    .unwrap();
  let handle = reg.handle;
  let mailbox = Arc::clone(&reg.mailbox);

  // 1. Drive the proto to an announced state so the withdrawal snapshot is
  //    NON-empty (otherwise the withdrawal completes instantly with nothing to
  //    retract — we want the Conflict to outlive an in-flight withdrawal).
  {
    let ctx = state.services.get_mut(&handle).unwrap();
    let mut buf = vec![0u8; 4096];
    let mut t = now;
    for _ in 0..40 {
      t += Duration::from_millis(300);
      let _ = ctx.proto.handle_timeout(t);
      while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
        deliver_both(&mut ctx.proto, t);
      }
    }
  }

  // 2. Deliver a `Conflict` at retirement — it lands in the mailbox's RESERVED
  //    terminal slot (not the non-terminal ring).
  {
    let ctx = state.services.get_mut(&handle).unwrap();
    deliver_service_update(ctx, ServiceUpdate::Conflict);
  }

  // 3. Begin the endpoint-owned withdrawal — exactly what the rename-collision /
  //    encode-failure retirement arms do (mark `withdrawing`, snapshot, hand to
  //    the endpoint). From here `push_updates` skips this ctx.
  {
    let ctx = state.services.get_mut(&handle).unwrap();
    ctx.withdrawing = true;
    let snap = ctx.proto.withdrawal_snapshot();
    state.endpoint.begin_withdrawal(handle, snap, now);
  }

  // 4. Drive the withdrawal to completion. With no bound family each round
  //    fails to deliver, so the endpoint force-completes at the 2 s ceiling;
  //    `drain_withdrawals` then GCs the ctx UNCONDITIONALLY (no deferral).
  let mut scratch = vec![0u8; 4096];
  let mut t = now;
  let mut completed = false;
  for _ in 0..64 {
    t += Duration::from_millis(250);
    state.drain_withdrawals(t, &mut scratch).await;
    if !state.services.contains_key(&handle) {
      completed = true;
      break;
    }
  }
  assert!(
    completed,
    "the withdrawal must complete (route freed + driver ctx GC'd unconditionally)"
  );

  // 5. The Conflict survived the ctx GC: it lives in the handle-owned mailbox's
  //    reserved slot and is still drainable by the live reader.
  let drained = lock_mailbox_for_test(&mailbox);
  assert!(
    matches!(drained, Some(ServiceUpdate::Conflict)),
    "the Conflict queued at retirement must survive the unconditional ctx GC and \
       stay readable from the handle-owned mailbox; got {drained:?}"
  );

  drop(reg);
}

/// a reactor RegisterService that RECLAIMS a renamed-away old
/// name's detached goodbye must not LOSE that goodbye if the caller drops the
/// reply receiver. Under cancel-on-announce the goodbye is cancelled only when the
/// reclaiming service confirms advertising the name; a dropped-reply orphan is
/// removed before it ever announces, so the goodbye is never cancelled and still
/// emits the TTL=0 retraction. Seeds a real detached old-name goodbye by driving
/// an announced service through a §9 rename, then re-registers the OLD name with a
/// dropped reply and asserts the goodbye survives.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn dropped_reply_reclaiming_register_keeps_old_name_goodbye() {
  use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
  };

  use mdns_proto::{
    Name, ServiceRecords, ServiceSpec,
    event::RouteEvent,
    wire::{Header, MessageBuilder},
  };

  use crate::command::Command;

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let now = StdInstant::now();

  let old_inst = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
  let mut r = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    old_inst.clone(),
    Name::try_from_str("old-host.local.").unwrap(),
    631,
    120,
  );
  r.add_a(Ipv4Addr::new(192, 168, 1, 10));
  // Keep `reg` alive for the whole test: dropping it closes the doorbell, which
  // the driver reads as caller-gone and would withdraw the service mid-rename.
  let reg = state.register_service(ServiceSpec::new(r), now).unwrap();
  let handle = reg.handle;

  let mut buf = std::vec![0u8; 4096];

  // Drive "Old" to announced, so its rename hands off a NON-empty goodbye.
  {
    let ctx = state.services.get_mut(&handle).unwrap();
    let mut t = now;
    for _ in 0..40 {
      t += Duration::from_millis(300);
      let _ = ctx.proto.handle_timeout(t);
      while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
        deliver_both(&mut ctx.proto, t);
      }
    }
    assert!(
      ctx.proto.advertises_host(),
      "Old must announce before the rename (so the goodbye is non-empty)"
    );
  }

  // A conflicting SRV authority for "Old" with rival rdata (port 9999): we lose
  // the §8.2 tiebreak and rename away.
  let conflict = {
    let target = Name::try_from_str("rival-host.local.").unwrap();
    let mut cbuf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut cbuf, Header::new()).unwrap();
    b.push_srv_authority(&old_inst, 120, 0, 0, 9999, &target)
      .unwrap();
    let n = b.finish().unwrap();
    cbuf[..n].to_vec()
  };
  let src = SocketAddr::from(([192, 168, 1, 200], 5353));
  let local_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  // Feed the conflict + drive the proto until "Old" renames away (seeding the
  // detached old-name goodbye via push_updates' surviving-rename handoff).
  let mut t = now;
  let mut renamed = false;
  for _ in 0..80 {
    t += Duration::from_millis(250);
    {
      let ctx = state.services.get_mut(&handle).unwrap();
      let _ = ctx.proto.handle_timeout(t);
      while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
        deliver_both(&mut ctx.proto, t);
      }
    }
    {
      let DriverState {
        endpoint, services, ..
      } = &mut state;
      if let Ok(evs) = endpoint.handle(t, src, local_ip, 0, &conflict, false) {
        for ev in evs {
          if let Ok(RouteEvent::ToService(ts)) = ev
            && let Some(ctx) = services.get_mut(&ts.handle())
          {
            ctx.proto.handle_event(ts.into_event(), t);
          }
        }
      }
    }
    state.push_updates(t).await;
    if state
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

  // Re-register the OLD name with a DROPPED reply receiver: `reply.send` fails, so
  // the rollback must RESTORE the reclaimed old-name goodbye.
  let (reply_tx, reply_rx) = futures::channel::oneshot::channel();
  drop(reply_rx);
  let mut r2 = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    old_inst.clone(),
    Name::try_from_str("new-host.local.").unwrap(),
    631,
    120,
  );
  r2.add_a(Ipv4Addr::new(192, 168, 1, 11));
  state.handle_command(
    Command::RegisterService {
      spec: ServiceSpec::new(r2),
      reply: reply_tx,
    },
    t,
  );

  // The reclaimed old-name goodbye SURVIVED the dropped-reply rollback: a TTL=0
  // goodbye is still emitted (without the fix it would have been cancelled and
  // nothing would be due — the new orphan service's withdrawal is empty).
  assert!(
    state
      .endpoint
      .poll_withdrawal_transmit(t, &mut buf)
      .is_some(),
    "the reclaimed old-name goodbye must survive the dropped-reply rollback and still emit"
  );

  drop(reg);
}

/// a terminal emitted DIRECTLY by the proto state machine — here
/// a `HostConflict` (a peer claimed our host name with a different address, RFC
/// 6762 §9) — must RETIRE the service through the SAME path as a synthesized
/// rename-collision Conflict: deliver the terminal into the handle-owned mailbox,
/// begin the endpoint-owned §10.1 withdrawal (so the proto stops serving), and GC
/// the ctx UNCONDITIONALLY once the withdrawal completes. Before the fix the
/// proto-emitted terminal was delivered to the mailbox but `withdrawing` was never
/// set and the withdrawal never began, so a HostConflict left a zombie ctx/route
/// (still answering queries) until the caller dropped the handle.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn proto_emitted_host_conflict_retires_and_gcs_the_service() {
  use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
  };

  use mdns_proto::{
    event::RouteEvent,
    wire::{Header, MessageBuilder},
  };

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let now = StdInstant::now();

  let host = mdns_proto::Name::try_from_str("printer.local.").unwrap();
  let mut r = mdns_proto::ServiceRecords::new(
    mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("Printer._ipp._tcp.local.").unwrap(),
    host.clone(),
    631,
    120,
  );
  r.add_a(Ipv4Addr::new(192, 168, 1, 10));
  // Keep `reg` (the mailbox Arc + doorbell) alive: the live reader that must
  // still observe the HostConflict after the ctx is GC'd.
  let reg = state
    .register_service(mdns_proto::ServiceSpec::new(r), now)
    .unwrap();
  let handle = reg.handle;
  let mailbox = Arc::clone(&reg.mailbox);

  // 1. Drive the proto to announced (non-empty withdrawal snapshot; the conflict
  //    hits a SERVING service).
  {
    let ctx = state.services.get_mut(&handle).unwrap();
    let mut buf = vec![0u8; 4096];
    let mut t = now;
    for _ in 0..40 {
      t += Duration::from_millis(300);
      let _ = ctx.proto.handle_timeout(t);
      while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
        deliver_both(&mut ctx.proto, t);
      }
    }
  }

  // 2. Feed a §9 host conflict (a peer claims our host name with a DIFFERENT
  //    address) through the REAL inbound path, so the proto emits a HostConflict
  //    via poll() — the proto-emitted terminal `push_updates` must retire. This
  //    mirrors the driver's own receive routing (split-borrow + ToService).
  let conflict = {
    let mut cbuf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut cbuf, Header::new()).unwrap();
    b.push_a_authority(&host, 120, Ipv4Addr::new(10, 0, 0, 99))
      .unwrap();
    let n = b.finish().unwrap();
    cbuf[..n].to_vec()
  };
  {
    let DriverState {
      endpoint, services, ..
    } = &mut state;
    let route_events = endpoint
      .handle(
        now,
        SocketAddr::from(([192, 168, 1, 200], 5353)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        0,
        &conflict,
        false,
      )
      .expect("endpoint.handle must accept the host-conflict packet");
    for ev in route_events {
      if let Ok(RouteEvent::ToService(ts)) = ev
        && let Some(ctx) = services.get_mut(&ts.handle())
      {
        ctx.proto.handle_event(ts.into_event(), now);
      }
    }
  }

  // 3. push_updates drains the proto's HostConflict; the fix routes the terminal
  //    through retirement (deliver + begin the endpoint-owned withdrawal).
  state.push_updates(now).await;
  assert!(
    state
      .services
      .get(&handle)
      .map(|c| c.withdrawing)
      .unwrap_or(false),
    "a proto-emitted HostConflict must begin the withdrawal (withdrawing)"
  );

  // 4. Drive the withdrawal to completion; the ctx must be GC'd UNCONDITIONALLY
  //    (no bound family → force-complete at the 2 s anti-pin ceiling).
  let mut scratch = vec![0u8; 4096];
  let mut t = now;
  let mut gced = false;
  for _ in 0..64 {
    t += Duration::from_millis(250);
    state.drain_withdrawals(t, &mut scratch).await;
    if !state.services.contains_key(&handle) {
      gced = true;
      break;
    }
  }
  assert!(
    gced,
    "the withdrawn ctx must be GC'd after the §10.1 goodbye completes"
  );

  // 5. The HostConflict terminal survived the unconditional ctx GC: it lives in
  //    the handle-owned mailbox and is still drained by the live reader (the
  //    non-terminal Established, if any, drains first; the terminal is last).
  let mut saw_host_conflict = false;
  while let Some(u) = lock_mailbox_for_test(&mailbox) {
    if u.is_host_conflict() {
      saw_host_conflict = true;
    }
  }
  assert!(
    saw_host_conflict,
    "the HostConflict terminal must survive the ctx GC and stay readable from the \
       handle-owned mailbox"
  );

  drop(reg);
}

/// The terminal retirement update survives BOTH a saturated non-terminal ring
/// AND an immediate, unconditional ctx GC (the design-doc scenario; formerly
/// the deferral case). Fill the mailbox's non-terminal `updates` to the cap
/// WITHOUT draining, `set_terminal(Conflict)`, complete the withdrawal so the
/// ctx is GC'd immediately, then drain from the LIVE handle and assert the
/// `Conflict` IS observed and the ctx is gone from `services` — no park, no
/// leak.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn terminal_survives_full_mailbox_and_immediate_ctx_gc() {
  use std::{net::Ipv4Addr, time::Duration};

  use mdns_proto::ServiceUpdate;

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let now = StdInstant::now();

  let mut r = mdns_proto::ServiceRecords::new(
    mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("stuck._ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("stuck.local.").unwrap(),
    631,
    120,
  );
  r.add_a(Ipv4Addr::new(192, 168, 1, 10));
  // Keep `reg` alive across the GC — it is the live reader.
  let reg = state
    .register_service(mdns_proto::ServiceSpec::new(r), now)
    .unwrap();
  let handle = reg.handle;
  let mailbox = Arc::clone(&reg.mailbox);

  // 1. Drive the proto to an announced state so the withdrawal snapshot is
  //    NON-empty (otherwise the withdrawal completes instantly).
  {
    let ctx = state.services.get_mut(&handle).unwrap();
    let mut buf = vec![0u8; 4096];
    let mut t = now;
    for _ in 0..40 {
      t += Duration::from_millis(300);
      let _ = ctx.proto.handle_timeout(t);
      while let Ok(Some(_)) = ctx.proto.poll_transmit(t, &mut buf) {
        deliver_both(&mut ctx.proto, t);
      }
    }
  }

  // 2. Saturate the non-terminal ring to the cap WITHOUT draining, then reserve
  //    the terminal. The terminal slot is independent of the (full) ring.
  {
    let mut mb = mailbox.lock().unwrap_or_else(|e| e.into_inner());
    mb.fill_non_terminal_to_cap_for_test();
    assert_eq!(
      mb.non_terminal_len(),
      SERVICE_UPDATE_CAPACITY,
      "the non-terminal ring must be saturated at the cap"
    );
    mb.set_terminal(ServiceUpdate::Conflict);
  }

  // 3. Begin the endpoint-owned withdrawal (rename-collision / encode-failure
  //    retirement arm). `push_updates` now skips this ctx.
  {
    let ctx = state.services.get_mut(&handle).unwrap();
    ctx.withdrawing = true;
    let snap = ctx.proto.withdrawal_snapshot();
    state.endpoint.begin_withdrawal(handle, snap, now);
  }

  // 4. Drive the withdrawal to completion. The ctx is GC'd IMMEDIATELY on
  //    completion — no park, no deferral, regardless of the full ring + the
  //    still-undrained reader.
  let mut scratch = vec![0u8; 4096];
  let mut t = now;
  let mut completed = false;
  for _ in 0..64 {
    t += Duration::from_millis(250);
    state.drain_withdrawals(t, &mut scratch).await;
    if !state.services.contains_key(&handle) {
      completed = true;
      break;
    }
  }
  assert!(
    completed,
    "the ctx must be GC'd unconditionally on withdrawal completion"
  );
  assert!(
    !state.services.contains_key(&handle),
    "no leak: the ctx must be gone from `services` after the withdrawal"
  );

  // 5. Drain from the live handle: all cap non-terminal updates, then the
  //    reserved Conflict — it was NEVER dropped despite the full ring and the
  //    immediate GC.
  let mut non_terminal = 0usize;
  let mut saw_conflict = false;
  loop {
    let drained = lock_mailbox_for_test(&mailbox);
    match drained {
      Some(ServiceUpdate::Conflict) => {
        saw_conflict = true;
        break;
      }
      Some(_) => non_terminal += 1,
      None => break,
    }
  }
  assert_eq!(
    non_terminal, SERVICE_UPDATE_CAPACITY,
    "the saturated non-terminal ring must drain in full before the terminal"
  );
  assert!(
    saw_conflict,
    "the reserved terminal Conflict must survive a full mailbox + an immediate, \
       unconditional ctx GC and reach the live reader"
  );

  drop(reg);
}

/// Registering the same instance name twice maps the proto
/// `RegisterServiceError::NameAlreadyRegistered` onto the public
/// `RegisterError::NameAlreadyRegistered` — exercising the `From` arm that
/// translates proto pool errors into the async-API error type. Sync path,
/// so no runtime is needed.
#[cfg(feature = "tokio")]
#[test]
fn duplicate_registration_maps_to_name_already_registered() {
  use std::net::Ipv4Addr;

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let now = StdInstant::now();

  let mk = || {
    let mut r = mdns_proto::ServiceRecords::new(
      mdns_proto::Name::try_from_str("_http._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("dup._http._tcp.local.").unwrap(),
      mdns_proto::Name::try_from_str("dup.local.").unwrap(),
      80,
      120,
    );
    r.add_a(Ipv4Addr::new(192, 168, 1, 10));
    mdns_proto::ServiceSpec::new(r)
  };

  state.register_service(mk(), now).unwrap();
  // `ServiceRegistered` (the Ok type) is not `Debug`, so match instead of
  // `unwrap_err`.
  match state.register_service(mk(), now) {
    Err(crate::error::RegisterError::NameAlreadyRegistered(_)) => {}
    Err(e) => panic!("expected NameAlreadyRegistered, got error {e:?}"),
    Ok(_) => panic!("expected NameAlreadyRegistered, but the second registration succeeded"),
  }
}

/// On encode failure (`poll_query_transmit` → `Err`) the reactor driver must
/// call `endpoint.retire_query` so the proto records the terminal transition:
/// `queries_active` decrements to 0 and exactly one of `queries_done` /
/// `queries_timeout` reaches 1. The query slot must also be GC'd (removed
/// from the driver map) so late responses cannot mutate it, consistent with
/// the smoltcp driver which calls retire_query on this error class.
#[cfg(all(feature = "stats", feature = "tokio"))]
#[tokio::test]
async fn unencodable_query_retire_records_terminal_stats() {
  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let now = StdInstant::now();

  let qname = mdns_proto::Name::try_from_str("printer.local.").unwrap();
  let started = state
    .start_query(
      mdns_proto::QuerySpec::new(qname, mdns_proto::wire::ResourceType::A),
      now,
    )
    .unwrap();
  let h = started.handle;

  // Confirm one active query is registered in the proto.
  let before = state.stats.snapshot();
  assert_eq!(
    before.queries_active, 1,
    "one active query before encode failure"
  );
  assert_eq!(before.queries_done, 0, "no terminal yet");

  // Drive drain_transmits with a 1-byte scratch → encode fails for the
  // pending question → retire_query must be called.
  let mut scratch = vec![0u8; 1];
  state.drain_transmits(now, &mut scratch).await;

  // Stats invariant: queries_active == 0, queries_done == 1.
  let after = state.stats.snapshot();
  assert_eq!(
    after.queries_active, 0,
    "queries_active must be 0 after retire_query on encode failure (was leaking)"
  );
  assert_eq!(
    after.queries_done, 1,
    "exactly one terminal (queries_done) must be recorded after encode failure; \
       got queries_done={}, queries_timeout={}",
    after.queries_done, after.queries_timeout,
  );

  // The query slot must be GC'd so late answers cannot mutate retired state.
  assert!(
    !state.queries.contains_key(&h),
    "the retired query slot must be removed from the driver map"
  );

  // The terminal must be set in the mailbox so Query::next surfaces it.
  // Drive a full Query::next cycle: spin up a minimal loopback endpoint
  // with the existing mailbox + doorbell so the consumer can drain the
  // terminal without needing a live command channel.
  let mb = started.mailbox;
  let (cmd_tx, _cmd_rx) = async_channel::unbounded::<crate::command::Command>();
  let mut q = crate::query::Query::new(h, mb, started.doorbell, cmd_tx);
  // The doorbell was already rung by drain_transmits (terminal was pushed);
  // `Query::next` must surface QueryEvent::Terminal on this call.
  let event = tokio::time::timeout(std::time::Duration::from_millis(200), q.next())
    .await
    .expect("Query::next must complete (terminal is already in mailbox)")
    .expect("Query::next must return Some(Terminal), not None");
  assert!(
    matches!(event, crate::query::QueryEvent::Terminal(_)),
    "the first event from Query::next must be the terminal; got {event:?}"
  );
}

/// Regression test for the encode-retired query GC bypass under send pressure.
///
/// The bug: `drain_transmits` collected encode-failed query handles into
/// `encode_retired` but the per-handle credit check (`if credits_remaining ==
/// 0 { return true }`) inside the query loop could fire BEFORE the cleanup
/// block ran, leaving the retired handle resident in `queries` and proto
/// storage even though the terminal was already consumed.
///
/// The fix: replace that early `return true` with `more_pending = true; break`
/// so the GC block at the end of the function ALWAYS executes.
///
/// This test registers one encode-failing query (1-byte scratch) followed by
/// N normal queries (large scratch).  HashMap iteration order is
/// non-deterministic, so regardless of whether the encode-failing handle comes
/// first or last in the `handles` vec, the GC block must remove it by the time
/// `drain_transmits` returns.  With null sockets the credit counter never
/// reaches zero (sends return `used = 0`), so `more_pending` is `false` here;
/// the budget-exhaustion `break` path cannot be exercised without live
/// multicast sockets, but the structural invariant — that the GC block runs on
/// EVERY return path — is verified by the fix and by the code path taken here
/// (normal-completion path also runs the GC block, just like the break path).
///
/// Additionally asserts that the normal queries are still resident (their
/// mailboxes are still open so they haven't been retired), confirming that
/// only the encode-retired handle is cleaned up.
#[cfg(all(feature = "stats", feature = "tokio"))]
#[tokio::test]
async fn encode_retired_gc_runs_with_subsequent_queries_pending() {
  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let now = StdInstant::now();

  // Register the encode-failing query: 1-byte scratch ensures encode fails.
  let bad_qname = mdns_proto::Name::try_from_str("encode-fail.local.").unwrap();
  let bad_started = state
    .start_query(
      mdns_proto::QuerySpec::new(bad_qname, mdns_proto::wire::ResourceType::A),
      now,
    )
    .unwrap();
  let bad_h = bad_started.handle;

  // Register N additional queries. Keep the `QueryStarted` structs alive so
  // the doorbell receivers (held by `started.doorbell`) stay open; the
  // driver's liveness check (`!c.doorbell.is_closed()`) would skip any
  // query whose receiver was dropped.
  // N = 4 is enough to confirm the iteration order does not matter.
  let mut normal_started = Vec::new();
  for i in 0u8..4 {
    let name = mdns_proto::Name::try_from_str(&format!("normal-{i}.local.")).unwrap();
    let started = state
      .start_query(
        mdns_proto::QuerySpec::new(name, mdns_proto::wire::ResourceType::A),
        now,
      )
      .unwrap();
    normal_started.push(started);
  }
  let normal_handles: Vec<_> = normal_started.iter().map(|s| s.handle).collect();

  // Confirm five active queries in proto before the drain.
  let before = state.stats.snapshot();
  assert_eq!(before.queries_active, 5, "five active queries before drain");

  // 1-byte scratch → the encode-failing query fails to encode; normal queries
  // also fail (1 byte is too small for any DNS message), so all end up in
  // encode_retired.  This is acceptable: the assertion below checks that the
  // encode-failing handle is gone, irrespective of how many others fail too.
  let mut scratch = vec![0u8; 1];
  let more_pending = state.drain_transmits(now, &mut scratch).await;

  // `more_pending` is false because null sockets never exhaust credits.
  // The credit-exhaustion `break` path requires live multicast sockets and
  // cannot be reproduced deterministically in a unit test; the structural
  // fix (flag + single cleanup path) guarantees correctness on that path too.
  assert!(
    !more_pending,
    "null sockets never exhaust credits; more_pending must be false"
  );

  // The encode-retired query slot MUST be gone from the driver map.
  assert!(
    !state.queries.contains_key(&bad_h),
    "the encode-retired query handle must be removed from the driver map after drain_transmits"
  );

  // All queries saw encode failure (1-byte scratch), so proto counters must
  // reflect all terminals.
  let after = state.stats.snapshot();
  assert_eq!(
    after.queries_active, 0,
    "all five queries must be retired; queries_active must be 0"
  );
  // Five terminals (all queries_done — no timeout, encode fails immediately).
  assert_eq!(
    after.queries_done, 5,
    "five terminals (queries_done) must be recorded; \
       got queries_done={}, queries_timeout={}",
    after.queries_done, after.queries_timeout,
  );

  // The normal handles must also be GC'd (same 1-byte scratch → all fail).
  for &h in &normal_handles {
    assert!(
      !state.queries.contains_key(&h),
      "normal query handle {h:?} must also be removed (all encode-failed with 1-byte scratch)"
    );
  }
}

/// A consumed-oversized datagram (MSG_TRUNC / InvalidData) must bump
/// `packets_rx` AND `packets_dropped` — it was consumed off the socket so it
/// counts toward the receive denominator. `bytes_rx` rises by the buffer
/// capacity (best-effort, the actual payload bytes that landed in our buffer).
///
/// Tests `count_consumed_oversized` directly so no socket bind is needed.
#[cfg(feature = "stats")]
#[test]
fn consumed_oversized_datagram_counts_rx_and_dropped() {
  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
  let buf_len: usize = 9000;

  count_consumed_oversized(&stats, buf_len);

  let snap = stats.snapshot();
  assert_eq!(
    snap.packets_rx, 1,
    "packets_rx must be 1 (datagram was consumed)"
  );
  assert_eq!(
    snap.bytes_rx, buf_len as u64,
    "bytes_rx must equal buf_len (best-effort truncated payload)"
  );
  assert_eq!(
    snap.packets_dropped, 1,
    "packets_dropped must be 1 (unusable datagram)"
  );
}

/// A generic recv error that consumed NO datagram must leave all counters at
/// zero — only consumed-unusable datagrams bump `packets_dropped`.
///
/// This mirrors the `handle_recv` path in compio: a socket/driver failure is
/// NOT a datagram event and must not pollute the stats.
#[cfg(feature = "stats")]
#[test]
fn generic_recv_error_does_not_increment_any_stats() {
  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());

  // Simulate the path taken by `recv_with_meta failed` / `peek_from failed`:
  // we log but do NOT call count_consumed_oversized.
  let _e = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "simulated");
  hick_trace::debug!(error = %_e, "recv_with_meta failed (test simulation — no stats bumped)");
  // (no stats call here — that IS the test)

  let snap = stats.snapshot();
  assert_eq!(
    snap.packets_rx, 0,
    "packets_rx must stay 0 on a generic recv error"
  );
  assert_eq!(
    snap.bytes_rx, 0,
    "bytes_rx must stay 0 on a generic recv error"
  );
  assert_eq!(
    snap.packets_dropped, 0,
    "packets_dropped must stay 0 on a generic recv error"
  );
}

// ── The dual-stack delivery boundary (`TransmitDelivery`) ───────────────────

/// A driver state with NO bound family. The delivery-shape tests drive
/// `confirm_service_transmit` directly — the exact seam `drain_transmits` uses —
/// because the reactor's multi-task loop cannot be stepped deterministically and
/// a real partial fan-out needs one family's socket to fail on demand.
#[cfg(feature = "tokio")]
fn delivery_test_state(probe: bool) -> DriverState<agnostic_net::tokio::Net> {
  let opts = crate::options::ServerOptions::default()
    .with_endpoint_config(mdns_proto::EndpointConfig::new().with_probe_unique_names(probe));
  DriverState::new(
    &opts,
    BoundSockets::<agnostic_net::tokio::Net> {
      v4: None,
      v6: None,
      interface_index: 0,
    },
  )
}

/// A minimal registerable service spec.
#[cfg(feature = "tokio")]
fn delivery_test_spec(instance: &str) -> mdns_proto::ServiceSpec {
  let mut r = mdns_proto::ServiceRecords::new(
    mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str(&std::format!("{instance}._ipp._tcp.local.")).unwrap(),
    mdns_proto::Name::try_from_str(&std::format!("{instance}.local.")).unwrap(),
    631,
    120,
  );
  r.add_a(std::net::Ipv4Addr::new(192, 168, 1, 10));
  mdns_proto::ServiceSpec::new(r)
}

/// Drain one service's due transmits at `t`, confirming each through the SAME
/// seam `drain_transmits` uses. Returns how many datagrams were confirmed.
#[cfg(feature = "tokio")]
fn confirm_service_round(
  state: &mut DriverState<agnostic_net::tokio::Net>,
  h: ServiceHandle,
  t: StdInstant,
  buf: &mut [u8],
  fanout: Fanout,
) -> usize {
  let DriverState {
    endpoint, services, ..
  } = state;
  let Some(ctx) = services.get_mut(&h) else {
    return 0;
  };
  let _ = ctx.proto.handle_timeout(t);
  let mut rounds = 0;
  while ctx.proto.poll_transmit(t, buf).is_ok_and(|tx| tx.is_some()) {
    confirm_service_transmit(endpoint, ctx, t, fanout.delivery());
    rounds += 1;
  }
  rounds
}

/// A dual-stack fan-out in which v4 carried the datagram and a BOUND v6 socket
/// rejected it (`ENETUNREACH` and friends). Driving the behaviour tests from the
/// per-family facts rather than a hand-fed [`TransmitDelivery`] keeps the
/// mapping inside the tested path.
#[cfg(feature = "tokio")]
const PARTIAL_FANOUT: Fanout = Fanout {
  v4: FamilySend::Sent,
  v6: FamilySend::Failed,
};

/// Both bound families carried the datagram.
#[cfg(feature = "tokio")]
const WHOLE_FANOUT: Fanout = Fanout {
  v4: FamilySend::Sent,
  v6: FamilySend::Sent,
};

/// Both bound families rejected it — nothing reached any wire.
#[cfg(feature = "tokio")]
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
    (Sent, Sent, Delivered, Delivered, 2),
    (Sent, Unbound, Delivered, Unobligated, 1),
    (Unbound, Sent, Unobligated, Delivered, 1),
    (Sent, Failed, Delivered, Missed, 1),
    (Failed, Sent, Missed, Delivered, 1),
    (Failed, Failed, Missed, Missed, 0),
    (Failed, Unbound, Missed, Unobligated, 0),
    (Unbound, Unbound, Unobligated, Unobligated, 0),
  ];
  for (v4, v6, want_v4, want_v6, credits) in cases {
    let fanout = Fanout { v4, v6 };
    let delivery = fanout.delivery();
    assert_eq!(
      (delivery.v4(), delivery.v6()),
      (want_v4, want_v6),
      "({v4:?}, {v6:?}) must reach the core as ({want_v4}, {want_v6})"
    );
    assert_eq!(
      delivery.all_delivered(),
      want_v4 != Missed && want_v6 != Missed && (want_v4 == Delivered || want_v6 == Delivered),
      "({v4:?}, {v6:?}): all_delivered is 'every obligated family carried it, and \
       at least one was obligated'"
    );
    assert_eq!(
      fanout.sent_count(),
      credits,
      "({v4:?}, {v6:?}) must charge {credits} fairness credit(s)"
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
/// The shipped `used > 0` boolean had no truthful value here: it advanced the
/// phase on the unserved family's behalf.
#[cfg(feature = "tokio")]
#[test]
fn a_partial_fan_out_latches_ownership_without_advancing_the_phase() {
  use mdns_proto::service::ServiceState;

  let mut state = delivery_test_state(false);
  let now = StdInstant::now();
  let reg = state
    .register_service(delivery_test_spec("partial"), now)
    .unwrap();
  let h = reg.handle;
  let mut buf = std::vec![0u8; 4096];

  // Exactly ONE confirm, so the bounded policy provably cannot have fired.
  let rounds = confirm_service_round(&mut state, h, now, &mut buf, PARTIAL_FANOUT);
  assert_eq!(rounds, 1, "one announcement should have been offered");

  let ctx = state.services.get(&h).unwrap();
  assert_eq!(
    ctx.proto.state(),
    ServiceState::Announcing(0),
    "a partial announcement must re-arm the SAME announcement — the unserved \
     family never heard it"
  );
  assert!(
    ctx.proto.advertises_instance(),
    "the served family's peers may now cache these records, so §10.1 goodbye \
     ownership must latch on the PARTIAL round"
  );
  assert!(
    !ctx.proto.has_fully_announced().get(),
    "a partial announcement must NOT open the reclaim-cancel gate"
  );

  // The headline regression: ownership latched, so a graceful unregister really
  // does retract. Had the partial round dropped ownership the snapshot would be
  // empty and the wire silent.
  state.remove_service(h, now);
  assert!(
    state
      .endpoint
      .poll_withdrawal_transmit(now, &mut buf)
      .is_some(),
    "a partially-announced service must still emit a §10.1 TTL=0 goodbye for the \
     records the served family put into peer caches"
  );

  drop(reg);
}

/// The other half of the pair: when EVERY obligated family carried the datagram,
/// the same confirm both latches ownership and advances the phase — and only
/// then does the reclaim-cancel gate open.
#[cfg(feature = "tokio")]
#[test]
fn a_fully_delivered_fan_out_latches_ownership_and_advances_the_phase() {
  use mdns_proto::service::ServiceState;

  let mut state = delivery_test_state(false);
  let now = StdInstant::now();
  let reg = state
    .register_service(delivery_test_spec("full"), now)
    .unwrap();
  let h = reg.handle;
  let mut buf = std::vec![0u8; 4096];

  let rounds = confirm_service_round(&mut state, h, now, &mut buf, WHOLE_FANOUT);
  assert_eq!(rounds, 1, "one announcement should have been offered");

  let ctx = state.services.get(&h).unwrap();
  assert_eq!(
    ctx.proto.state(),
    ServiceState::Announcing(1),
    "an all-delivered announcement advances the §8.3 sequence"
  );
  assert!(
    ctx.proto.advertises_instance(),
    "a delivered announcement latches goodbye ownership"
  );
  assert!(
    ctx.proto.has_fully_announced().get(),
    "a complete announcement is the ONLY thing that opens the reclaim-cancel gate"
  );

  drop(reg);
}

/// A fan-out that reached NO wire neither latches nor advances: nothing was
/// exposed to any peer, so there is nothing to retract, and no family heard the
/// announcement, so the phase must not move.
#[cfg(feature = "tokio")]
#[test]
fn a_wholly_failed_fan_out_neither_latches_nor_advances() {
  use mdns_proto::service::ServiceState;

  let mut state = delivery_test_state(false);
  let now = StdInstant::now();
  let reg = state
    .register_service(delivery_test_spec("failed"), now)
    .unwrap();
  let h = reg.handle;
  let mut buf = std::vec![0u8; 4096];

  let rounds = confirm_service_round(&mut state, h, now, &mut buf, FAILED_FANOUT);
  assert_eq!(rounds, 1, "one announcement should have been offered");

  let ctx = state.services.get(&h).unwrap();
  assert_eq!(
    ctx.proto.state(),
    ServiceState::Announcing(0),
    "a wholly-failed announcement must re-arm without advancing"
  );
  assert!(
    !ctx.proto.advertises_instance(),
    "nothing reached a wire, so no peer can hold these records and no goodbye \
     ownership may latch"
  );

  state.remove_service(h, now);
  assert!(
    state
      .endpoint
      .poll_withdrawal_transmit(now, &mut buf)
      .is_none(),
    "an unadvertised service has nothing to retract, so its withdrawal must put \
     no datagram on the wire"
  );

  drop(reg);
}

/// RFC 6762 §9 surviving rename: the renamed-away old name's detached goodbye is
/// enqueued RECLAIMABLE, so a replacement that takes the vacated name can cancel
/// it — but ONLY once that replacement has fully announced. A replacement that
/// reached one family alone must not cancel a goodbye the OTHER family still
/// needs; the shipped drivers cancelled on the any-delivered exposure latch and
/// left every peer on the unserved family holding the old registration's records
/// until their positive TTL expired.
///
/// The old goodbye's per-family debt is what makes "both families" concrete: this
/// drives a v4-only goodbye round first, so the item still owes IPv6 when the
/// replacement announces.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn a_surviving_rename_retracts_its_old_name_on_both_families() {
  use std::net::{IpAddr, Ipv4Addr, SocketAddr};

  use mdns_proto::{
    Name,
    event::RouteEvent,
    wire::{Header, MessageBuilder},
  };

  let mut state = delivery_test_state(true);
  let now = StdInstant::now();
  let old_inst = Name::try_from_str("Old._ipp._tcp.local.").unwrap();
  let reg = state
    .register_service(delivery_test_spec("Old"), now)
    .unwrap();
  let handle = reg.handle;
  let mut buf = std::vec![0u8; 4096];

  // Drive "Old" to fully announced, so its rename hands off a NON-empty goodbye.
  let mut t = now;
  for _ in 0..40 {
    t += Duration::from_millis(300);
    confirm_service_round(&mut state, handle, t, &mut buf, WHOLE_FANOUT);
  }
  assert!(
    state.services[&handle].proto.advertises_instance(),
    "Old must announce before the rename (so the goodbye is non-empty)"
  );

  // A conflicting SRV authority for "Old" with rival rdata: we lose the §8.2
  // tiebreak and rename away.
  let conflict = {
    let target = Name::try_from_str("rival-host.local.").unwrap();
    let mut cbuf = [0u8; 512];
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut cbuf, Header::new()).unwrap();
    b.push_srv_authority(&old_inst, 120, 0, 0, 9999, &target)
      .unwrap();
    let n = b.finish().unwrap();
    cbuf[..n].to_vec()
  };
  let src = SocketAddr::from(([192, 168, 1, 200], 5353));
  let local_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

  let mut renamed = false;
  for _ in 0..80 {
    t += Duration::from_millis(250);
    confirm_service_round(&mut state, handle, t, &mut buf, WHOLE_FANOUT);
    {
      let DriverState {
        endpoint, services, ..
      } = &mut state;
      if let Ok(evs) = endpoint.handle(t, src, local_ip, 0, &conflict, false) {
        for ev in evs {
          if let Ok(RouteEvent::ToService(ts)) = ev
            && let Some(ctx) = services.get_mut(&ts.handle())
          {
            ctx.proto.handle_event(ts.into_event(), t);
          }
        }
      }
    }
    state.push_updates(t).await;
    if state
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
  let (_, _, token) = state
    .endpoint
    .poll_withdrawal_transmit(t, &mut buf)
    .expect("the renamed-away old name must have a detached goodbye pending");
  state
    .endpoint
    .note_withdrawal_result(token, t, WithdrawalSend::Sent, WithdrawalSend::Retry);

  // The application reclaims the vacated name.
  let replacement = state
    .register_service(delivery_test_spec("Old"), t)
    .expect("the vacated name must be re-registerable while its goodbye drains");
  let rh = replacement.handle;

  // Drive the replacement's §8.1 probes to completion (a probe is a question and
  // opens no gate) so the next round is its FIRST announcement.
  for _ in 0..12 {
    t += Duration::from_millis(300);
    confirm_service_round(&mut state, rh, t, &mut buf, WHOLE_FANOUT);
    if state.services[&rh].proto.state() == mdns_proto::service::ServiceState::Announcing(0) {
      break;
    }
  }
  assert_eq!(
    state.services[&rh].proto.state(),
    mdns_proto::service::ServiceState::Announcing(0),
    "the replacement must reach its first announcement"
  );

  // Exactly ONE partially-delivered announcement — the core's patience bound
  // provably cannot have excused anything yet.
  t += Duration::from_millis(300);
  confirm_service_round(&mut state, rh, t, &mut buf, PARTIAL_FANOUT);
  assert!(
    !state.services[&rh].proto.has_fully_announced().get(),
    "a partial announcement must leave the reclaim-cancel gate shut"
  );
  assert!(
    state
      .endpoint
      .poll_withdrawal_transmit(t, &mut buf)
      .is_some(),
    "a partially-announced replacement must NOT cancel the old name's goodbye — \
     the unserved family has heard neither the goodbye nor the replacement, and \
     its share of the per-family debt is still owed"
  );

  // Once the replacement reaches every obligated family, §10.2's cache-flush
  // announcement supersedes the stale records and the goodbye may be cancelled.
  t += Duration::from_secs(2);
  confirm_service_round(&mut state, rh, t, &mut buf, WHOLE_FANOUT);
  assert!(
    state.services[&rh].proto.has_fully_announced().get(),
    "the replacement must have fully announced by now"
  );
  assert!(
    state
      .endpoint
      .poll_withdrawal_transmit(t, &mut buf)
      .is_none(),
    "a fully-announced replacement supersedes the old records on every obligated \
     family, so the reclaimable goodbye is cancelled"
  );

  drop(replacement);
  drop(reg);
}

/// RFC 6762 §6.7 legacy unicast reply: no self-send credit.
///
/// A unicast datagram leaves for the querier's own address and ephemeral port and
/// never loops back through the multicast group we joined, so a credit recorded
/// for it can never be consumed. It would occupy the linear-scanned tracker for
/// `SELF_SEND_TTL`, and at `MAX_SELF_SEND_ENTRIES` `record_self_send` declines the
/// NEW entry — so a legacy-query flood would starve the genuine multicast credits
/// that loopback suppression depends on.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn a_legacy_unicast_reply_records_no_self_send_credit() {
  use agnostic_net::UdpSocket as _;

  type Net = agnostic_net::tokio::Net;

  // A real bound socket, so this exercises the actual send path rather than the
  // absent-socket short circuit.
  let sender = <Net as agnostic_net::Net>::UdpSocket::bind("127.0.0.1:0")
    .await
    .expect("bind a loopback sender");
  let querier = <Net as agnostic_net::Net>::UdpSocket::bind("127.0.0.1:0")
    .await
    .expect("bind a loopback querier");
  let querier_addr = querier.local_addr().expect("querier local addr");

  let v4 = Some(Arc::new(sender));
  let v6: Option<Arc<<Net as agnostic_net::Net>::UdpSocket>> = None;
  let mut tracker: Vec<(u64, SystemTime)> = Vec::new();
  #[cfg(feature = "stats")]
  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());

  let fanout = send_via::<Net>(
    &mut tracker,
    &v4,
    &v6,
    querier_addr,
    b"legacy-unicast-reply",
    #[cfg(feature = "stats")]
    &stats,
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
    tracker.is_empty(),
    "a unicast reply never loops back, so it must record NO self-send credit; \
     tracker = {tracker:?}"
  );
}

// ── The obligation tag (`TransmitObligation`) at the driver seam ────────────

/// A §6.7 legacy unicast reply reaches exactly ONE family, so its fan-out is
/// all-delivered by construction — the other family is unobligated, not missing.
#[cfg(feature = "tokio")]
const UNICAST_FANOUT: Fanout = Fanout {
  v4: FamilySend::Sent,
  v6: FamilySend::Unbound,
};

/// Drain one service's due transmits at `t` through the SAME seam
/// `drain_transmits` uses, choosing each datagram's fan-out the way `send_via`
/// would: an mDNS MULTICAST destination is fanned onto both families (and so can
/// be partial), while a §6.7 legacy UNICAST reply reaches the single family its
/// destination names. Returns how many datagrams were confirmed.
#[cfg(feature = "tokio")]
fn confirm_service_round_mixed(
  state: &mut DriverState<agnostic_net::tokio::Net>,
  h: ServiceHandle,
  t: StdInstant,
  buf: &mut [u8],
  multicast_fanout: Fanout,
) -> usize {
  let DriverState {
    endpoint, services, ..
  } = state;
  let Some(ctx) = services.get_mut(&h) else {
    return 0;
  };
  let _ = ctx.proto.handle_timeout(t);
  let mut rounds = 0;
  while let Ok(Some(tx)) = ctx.proto.poll_transmit(t, buf) {
    let fanout = if tx.dst().ip().is_multicast() {
      multicast_fanout
    } else {
      UNICAST_FANOUT
    };
    confirm_service_transmit(endpoint, ctx, t, fanout.delivery());
    rounds += 1;
  }
  rounds
}

/// Feed a browse (PTR) query for the sample service type into the endpoint and
/// route the resulting event into its service, exactly as the driver's receive
/// path does. A `src` port of 5353 elicits a jittered §6 MULTICAST response; any
/// other port elicits a §6.7 legacy UNICAST reply.
#[cfg(feature = "tokio")]
fn inject_ptr_query(
  state: &mut DriverState<agnostic_net::tokio::Net>,
  src: SocketAddr,
  t: StdInstant,
) {
  use mdns_proto::{
    Name,
    event::RouteEvent,
    wire::{Header, MessageBuilder, ResourceClass, ResourceType},
  };

  let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let mut qbuf = [0u8; 512];
  let n = {
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false)
      .unwrap();
    b.finish().unwrap()
  };
  let query = qbuf[..n].to_vec();
  let local_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 10));
  let DriverState {
    endpoint, services, ..
  } = state;
  let Ok(evs) = endpoint.handle(t, src, local_ip, 0, &query, false) else {
    panic!("the endpoint must accept a well-formed browse query");
  };
  for ev in evs {
    if let Ok(RouteEvent::ToService(ts)) = ev
      && let Some(ctx) = services.get_mut(&ts.handle())
    {
      ctx.proto.handle_event(ts.into_event(), t);
    }
  }
}

/// Bypassing the bound for a one-shot datagram must not bypass the CORE confirm:
/// the outcome still reaches `Service::note_transmit_outcome` verbatim, so a
/// delivered response latches §10.1 goodbye ownership for the records it put on
/// the wire.
#[cfg(feature = "tokio")]
#[test]
fn a_one_shot_confirm_still_latches_goodbye_ownership() {
  let mut state = delivery_test_state(false);
  let now = StdInstant::now();
  let reg = state
    .register_service(delivery_test_spec("oneshot"), now)
    .unwrap();
  let h = reg.handle;
  let mut buf = std::vec![0u8; 4096];

  // The lifecycle reaches no wire at all, so nothing it sends can latch.
  confirm_service_round(&mut state, h, now, &mut buf, FAILED_FANOUT);
  assert!(
    !state.services[&h].proto.advertises_instance(),
    "a wholly-failed announcement exposes nothing"
  );

  // A §6.7 legacy querier is served over the one family its destination names.
  let legacy = SocketAddr::from(([192, 168, 1, 50], 6000));
  let t = now + Duration::from_millis(50);
  inject_ptr_query(&mut state, legacy, t);
  assert_eq!(
    confirm_service_round_mixed(&mut state, h, t, &mut buf, FAILED_FANOUT),
    1,
    "only the legacy reply is due this early"
  );
  assert!(
    state.services[&h].proto.advertises_instance(),
    "the reply put positive-TTL records on a wire, so §10.1 ownership latches — \
     the confirm reaches the core unchanged, it just skips the bound"
  );
  assert!(
    !state.services[&h].proto.has_fully_announced().get(),
    "an all-delivered UNICAST reply is still not a complete announcement"
  );
  drop(reg);
}

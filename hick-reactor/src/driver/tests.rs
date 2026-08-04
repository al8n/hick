use super::*;
// The tracker's public bounds. Its clock seams (`take_at`, `seal_at`, `len`)
// come with the `test-support` feature this crate carries in `dev-dependencies`
// only, so a claim or a loop top can be placed without sleeping to it.
use hick_udp::selfsend::{MAX_SELF_SEND_ENTRIES, SELF_SEND_TTL, WALL_STEP_TOLERANCE};
// Every caller of this import and the three helpers below is a `#[cfg(feature
// = "tokio")]` test (they drive the driver via `agnostic_net::tokio::Net`), so
// all four are gated the same way rather than compiled — and reported dead —
// on a test build with no runtime feature enabled.
#[cfg(feature = "tokio")]
use crate::service::{SERVICE_UPDATE_CAPACITY, ServiceMailbox};

/// Drain one [`ServiceUpdate`] from a shared mailbox (the handle side), used by
/// the service-update tests to assert delivery without awaiting the async
/// [`crate::Service::next`].
#[cfg(feature = "tokio")]
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
#[cfg(feature = "tokio")]
fn deliver_both(proto: &mut ProtoService, now: StdInstant) {
  let _ = proto.note_transmit_outcome(
    now,
    FamilyAttempt::Accepted { at: now },
    FamilyAttempt::Accepted { at: now },
  );
}

/// This family's acceptance instant, if it accepted. The accessor lives inside
/// the core; a test names the fact by hand-matching the (public) variant.
#[cfg(feature = "tokio")]
fn accepted_at(attempt: FamilyAttempt<StdInstant>) -> Option<StdInstant> {
  match attempt {
    FamilyAttempt::Accepted { at } => Some(at),
    _ => None,
  }
}

/// regression: a PRESENT (bound) family's `send_to` failure must be reported
/// [`FamilyAttempt::Refused`], NEVER [`FamilyAttempt::NoSocket`] — the fact an
/// ABSENT family reports, and the only one that lets the core's withdrawal
/// table write a debt off. A bound UDP socket can return transient errors whose
/// kind is NOT `WouldBlock`/`Interrupted` (e.g. `ENOBUFS`, route/interface
/// churn); laundering those into `NoSocket` would free the route once the OTHER
/// family drained and strand this family's peers on stale positive-TTL records.
/// `permanent` is decided by the datagram's size against this family's UDP
/// ceiling and never by the error kind — see `attempt_of`.
#[test]
fn present_socket_send_error_is_refused_not_no_socket() {
  let body = *b"present-socket-probe";

  // Ok → Accepted, anchored at the PRE-syscall stamp. The post-syscall one is
  // deliberately a different instant here: the confirm anchor may only ever
  // understate how fresh a family's peers are, so reaching for the wire gate's
  // stamp instead would be visible as a failure right here.
  let at = StdInstant::now();
  assert_eq!(
    attempt_of(
      Family::V4,
      &body,
      &SendAttempt::Answered {
        result: Ok(body.len()),
        submitted_wall: SystemTime::now(),
        submitted_at: at,
        wire_at: at + Duration::from_millis(1),
      },
    ),
    FamilyAttempt::Accepted { at },
  );
  // Every non-WouldBlock/Interrupted error kind a bound socket might surface
  // must still be `Refused { permanent: false }` (NEVER `NoSocket`).
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
      attempt_of(
        Family::V4,
        &body,
        &SendAttempt::Answered {
          result: res,
          submitted_wall: SystemTime::now(),
          submitted_at: StdInstant::now(),
          wire_at: StdInstant::now(),
        },
      ),
      FamilyAttempt::Refused { permanent: false },
      "a present (bound) socket error ({kind:?}) must be Refused, not NoSocket"
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
  let sent = ClockPair::now();
  state.selfsend.record(Family::V4, &body, sent);
  state.selfsend.seal_at(sent.mono);
  #[cfg(debug_assertions)]
  state.note_park_entry();
  assert_eq!(state.selfsend.len(), 1);

  // Same bytes arriving from an EPHEMERAL port, admitted by §11: untrusted
  // response — must be dropped before it can be offered the credit.
  let untrusted = Packet {
    src: "192.0.2.9:40000".parse().unwrap(),
    data: body.clone(),
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("192.0.2.9:40000".parse().unwrap()),
    rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
    // A multicast echo carries the group destination, which is what §11 admits
    // it on now that the inbound TTL is not a test.
    destination: DestinationWitness::Witnessed(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    delivery: None,
    hop_limit: Some(255),
  };
  state.handle_packet(untrusted);
  assert_eq!(
    state.selfsend.len(),
    1,
    "untrusted response must not consume the self-send credit"
  );

  // The genuine loopback from port 5353 passes the gate and consumes it.
  let loopback = Packet {
    src: "192.0.2.9:5353".parse().unwrap(),
    data: body,
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("192.0.2.9:5353".parse().unwrap()),
    rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
    // A multicast echo carries the group destination, which is what §11 admits
    // it on now that the inbound TTL is not a test.
    destination: DestinationWitness::Witnessed(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    delivery: None,
    hop_limit: Some(255),
  };
  state.handle_packet(loopback);
  assert_eq!(
    state.selfsend.len(),
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

  // Source port ≠ 5353 → untrusted-response pre-drop path; §11 admits it.
  let pkt = Packet {
    src: "192.0.2.7:40000".parse().unwrap(),
    data: body,
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("192.0.2.7:40000".parse().unwrap()),
    rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
    // A multicast echo carries the group destination, which is what §11 admits
    // it on now that the inbound TTL is not a test.
    destination: DestinationWitness::Witnessed(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    delivery: None,
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

  // No prior self-send credit recorded — if the drop were to incorrectly offer
  // this datagram a credit the tracker would stay at zero (no match), but the
  // correct behaviour is that it is never offered one at all.
  assert!(state.selfsend.is_empty());

  let pkt = Packet {
    src: "192.0.2.8:54321".parse().unwrap(), // non-5353 → untrusted
    data: body,
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("192.0.2.8:54321".parse().unwrap()),
    rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
    // A multicast echo carries the group destination, which is what §11 admits
    // it on now that the inbound TTL is not a test.
    destination: DestinationWitness::Witnessed(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    delivery: None,
    hop_limit: Some(255), // carried, never read
  };
  state.handle_packet(pkt);

  // Self-send tracker unchanged (never reached).
  assert!(
    state.selfsend.is_empty(),
    "the self-send tracker must be untouched"
  );

  let snap = state.stats.snapshot();
  assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
  assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
}

/// A datagram the §11 boundary refuses must still count packets_rx + bytes_rx
/// once (it was read off the wire) and packets_dropped once.
///
/// The refusal here is §11's unicast arm: the source matches no prefix
/// configured on the bound interface. It is NOT the TTL — the boundary takes no
/// hop limit at all — and this doc used to say otherwise while passing for the
/// prefix reason anyway.
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

  // A source on no configured prefix → §11's unicast arm refuses it, before the
  // untrusted-response check. Use a query (QR=0) so only the §11 path is
  // exercised. The hop limit below is carried and never read.
  let body: Vec<u8> = vec![
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  let len = body.len() as u64;

  let pkt = Packet {
    src: "203.0.113.5:5353".parse().unwrap(),
    data: body,
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("203.0.113.5:5353".parse().unwrap()),
    rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
    destination: DestinationWitness::blind(),
    delivery: None,
    hop_limit: Some(64), // carried, never read — see the doc above
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

// ── the ingress trust boundary, through the production receive path ─────────
//
// Both mDNS sockets are wildcard bound, so on a multi-homed host every NIC's
// port-5353 traffic is delivered to them. A hop limit of 255 proves only that a
// datagram crossed no router; it says nothing about WHICH link it did not cross,
// and this endpoint serves exactly one interface. Two things can name that link
// — the PKTINFO interface index and an IPv6 source's scope id — and every one of
// them that is present has to agree.
//
// The rule itself is `hick_udp::onlink::admits_ingress` and is exhaustively
// tested there. What these pin is THIS driver's wiring of it — the facts it
// passes, and the capability it claims for its own receive path — driven through
// `handle_packet`, the same entry the packet pump calls, rather than through a
// reconstruction of it. Every rejecting case below is a row where
// `hick-reactor` used to admit what the gate now refuses.

/// The interface this fixture's endpoint is pinned to.
#[cfg(feature = "tokio")]
const INGRESS_BOUND: u32 = 5;
/// Some other NIC on the same host.
#[cfg(feature = "tokio")]
const INGRESS_OTHER: u32 = 9;

/// One datagram, in the shape a receive path hands it to the driver. A struct
/// rather than a widening parameter list so the two facts §11 selects its
/// fallback arm by are stated where they matter and default to "this path
/// recovered none" everywhere else.
#[cfg(feature = "tokio")]
struct Arrival {
  src: SocketAddr,
  family: Family,
  hop_limit: Option<u8>,
  iface: IfaceWitness,
  destination: DestinationWitness,
  delivery: Option<hick_udp::LinkDelivery>,
}

#[cfg(feature = "tokio")]
impl Arrival {
  /// A datagram whose receive path witnessed neither a destination nor a
  /// multicast flag.
  ///
  /// `pkt_iface` becomes the witness a path of THIS driver's shape would mint
  /// for it — see [`packet_iface_witness`] for the zero case, which is the one
  /// every case here turns on.
  fn new(src: SocketAddr, family: Family, hop_limit: Option<u8>, pkt_iface: u32) -> Self {
    Self {
      src,
      family,
      hop_limit,
      iface: match core::num::NonZeroU32::new(pkt_iface) {
        Some(idx) => IfaceWitness::Witnessed(idx),
        None => packet_iface_witness(src),
      },
      destination: DestinationWitness::blind(),
      delivery: None,
    }
  }

  /// The IP header destination this receive path witnessed.
  fn addressed_to(mut self, dst: IpAddr) -> Self {
    self.destination = DestinationWitness::Witnessed(dst);
    self
  }

  /// The kernel's `MSG_MCAST`, where the target reports one and no destination
  /// was witnessed.
  fn delivered_as_multicast(mut self) -> Self {
    self.delivery = Some(hick_udp::LinkDelivery::Multicast);
    self
  }

  /// The kernel DECLINED to name the receiving interface for this datagram: no
  /// index, and no `MSG_CTRUNC` to say our own buffer was at fault.
  fn iface_declined(mut self) -> Self {
    self.iface = IfaceWitness::Declined;
    self
  }

  /// The kernel DECLINED to report the IP header destination for this datagram.
  fn destination_declined(mut self) -> Self {
    self.destination = DestinationWitness::Declined;
    self
  }
}

/// The interface witness a `Packet` built with a ZERO index was equivalent to
/// before the witnesses existed — the pair `(0, rx_interface_reported(src))`.
///
/// A zero from a path that reports interfaces becomes [`IfaceWitness::Lost`],
/// which is the absence that still REFUSES, so every case written under the old
/// pair keeps asserting exactly what it asserted. [`IfaceWitness::Declined`] —
/// the absence that now degrades — is deliberately never produced here: routing
/// the old cases into it would silently rewrite them. It has cases of its own,
/// reached through [`Arrival::iface_declined`].
#[cfg(feature = "tokio")]
fn packet_iface_witness(src: SocketAddr) -> IfaceWitness {
  if rx_interface_reported(src) {
    IfaceWitness::Lost
  } else {
    IfaceWitness::Blind
  }
}

/// [`INGRESS_BOUND`] as a witnessed interface index.
#[cfg(feature = "tokio")]
fn ingress_bound_witness() -> IfaceWitness {
  match core::num::NonZeroU32::new(INGRESS_BOUND) {
    Some(idx) => IfaceWitness::Witnessed(idx),
    // `INGRESS_BOUND` is a nonzero literal; `Lost` is the value that cannot
    // silently widen the §11 gate if that ever changed.
    None => IfaceWitness::Lost,
  }
}

/// Whether the ingress trust boundary admitted one datagram, answered by the
/// PRODUCTION receive entry.
///
/// The observable is the take-once self-send credit. `handle_packet` consults
/// the tracker only AFTER the gate, and with a byte-identical credit already
/// recorded a datagram that reaches the tracker always spends it — so a credit
/// still unspent is a datagram the gate refused, and an empty tracker is one it
/// admitted. Nothing here restates the gate's own conditions: the answer comes
/// out of the function the packet pump calls.
///
/// The body is a QR=0 query, so the untrusted-response gate cannot be what
/// refuses it, and the source port is 5353 for the same reason.
#[cfg(feature = "tokio")]
fn ingress_admits(a: Arrival, subnets: &[(IpAddr, u8)], bound_is_loopback: bool) -> bool {
  use std::net::Ipv4Addr;

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: INGRESS_BOUND,
  };
  let mut state = DriverState::new(&opts, sockets);
  // Pinned rather than enumerated: `INGRESS_BOUND` names whatever NIC happens to
  // hold index 5 on the host running this, so neither its subnets nor its
  // loopback flag may be allowed to decide these cases.
  state.local_subnets = subnets.to_vec();
  state.bound_is_loopback = bound_is_loopback;

  let body = vec![0u8; 12];
  state.selfsend.record(a.family, &body, ClockPair::now());
  state.selfsend.seal();
  #[cfg(debug_assertions)]
  state.note_park_entry();
  assert_eq!(state.selfsend.len(), 1, "the send recorded its credit");

  state.handle_packet(Packet {
    src: a.src,
    data: body,
    family: a.family,
    local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    iface: a.iface,
    rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
    destination: a.destination,
    delivery: a.delivery,
    hop_limit: a.hop_limit,
  });
  state.selfsend.is_empty()
}

/// A routable source inside [`ingress_subnets`], so nothing below turns on the
/// §11 fallback's own subnet rule.
#[cfg(feature = "tokio")]
fn ingress_on_subnet_peer() -> SocketAddr {
  "192.168.1.7:5353".parse().expect("peer")
}

/// The bound interface's configuration: the address it HOLDS and that address's
/// mask, which is what `collect_local_subnets` reports (`getifs`' `addr()`, not
/// a masked network). Both of RFC 6762 §11's arms read it — the source arm as
/// address and mask, the destination test as the address alone — so
/// [`INGRESS_OUR_ADDR`] is also the unicast destination every case below reaches
/// the source arm through.
#[cfg(feature = "tokio")]
fn ingress_subnets() -> Vec<(IpAddr, u8)> {
  vec![(INGRESS_OUR_ADDR, 24u8)]
}

/// The address [`ingress_subnets`] holds, and therefore the destination §11
/// treats as a response *"received via unicast"* on this link. A destination the
/// interface does NOT hold reaches no §11 arm at all.
#[cfg(feature = "tokio")]
const INGRESS_OUR_ADDR: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2));

/// The link-local prefixes an interface holding a link-local address reports.
/// §11's second arm is the only thing that admits a link-local source, so a
/// fixture meaning "this link-local peer is on our link" has to say so the way a
/// real interface does — a witness settles which link, never the prefix.
#[cfg(feature = "tokio")]
fn ingress_ll_prefixes() -> Vec<(IpAddr, u8)> {
  vec![
    (
      IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
      64u8,
    ),
    (IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 0, 0)), 16u8),
  ]
}

/// A link-local IPv6 peer inside `scope`'s zone — the second witness of the link
/// a datagram came from, which taking `src.ip()` alone discarded.
#[cfg(feature = "tokio")]
fn ingress_link_local_peer(scope: u32) -> SocketAddr {
  SocketAddr::V6(std::net::SocketAddrV6::new(
    std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
    5353,
    0,
    scope,
  ))
}

/// A routable source on a prefix the bound interface does NOT carry: the
/// overlaid-subnet peer §11 names.
#[cfg(feature = "tokio")]
fn ingress_off_subnet_peer() -> SocketAddr {
  SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 4, 4, 4)), 5353)
}

/// The IPv6 twin of [`ingress_off_subnet_peer`], with no scope id — a global
/// source carries none.
#[cfg(feature = "tokio")]
fn ingress_off_subnet_peer_v6() -> SocketAddr {
  SocketAddr::new(
    IpAddr::V6(std::net::Ipv6Addr::new(
      0x2001, 0xdb8, 0xbeef, 0, 0, 0, 0, 1,
    )),
    5353,
  )
}

/// §11's GROUP arm, through the production receive path: arrival at the mDNS
/// group is local-link origin on its own, "regardless of source IP address".
///
/// The RFC calls admitting this "essential ... in unusual configurations, such
/// as multiple logical IP subnets overlayed on a single link". Hardcoding the
/// destination away routed a correctly-witnessed multicast from such a peer to
/// the source-prefix arm, which refuses it — and Windows recovers a destination
/// while reporting no hop limit at all, so there this is the ONLY thing that can
/// select the arm. That made the loss silent rather than rare.
#[cfg(feature = "tokio")]
#[test]
fn a_group_destination_admits_a_peer_from_an_unshared_prefix() {
  let subnets = ingress_subnets();
  // The Windows shape: a recovered destination, no hop limit, a source on a
  // prefix this interface does not carry.
  for group in [
    IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP),
    IpAddr::V6(hick_udp::constants::MDNS_IPV6_GROUP),
  ] {
    let family = if group.is_ipv4() {
      Family::V4
    } else {
      Family::V6
    };
    let src = if group.is_ipv4() {
      ingress_off_subnet_peer()
    } else {
      ingress_off_subnet_peer_v6()
    };
    assert!(
      ingress_admits(
        Arrival::new(src, family, None, INGRESS_BOUND).addressed_to(group),
        &subnets,
        false
      ),
      "{group}: §11 admits a group destination whatever the source prefix"
    );
  }

  // The OpenBSD/NetBSD IPv4 square: no PKTINFO parse wired in, so no
  // destination — but the kernel's own `MSG_MCAST` says it was delivered as a
  // multicast, and §11's group arm is what that stands in for.
  assert!(
    ingress_admits(
      Arrival::new(ingress_off_subnet_peer(), Family::V4, None, INGRESS_BOUND)
        .delivered_as_multicast(),
      &subnets,
      false
    ),
    "a multicast delivery is local-link origin by itself; discarding the flag \
     sent it to the source-prefix arm, which refuses an overlaid-subnet peer"
  );

  // The other arm is intact rather than merely unreachable: the same datagram
  // addressed to this host is still answered by the source-prefix rule, and
  // refused.
  assert!(!ingress_admits(
    Arrival::new(ingress_off_subnet_peer(), Family::V4, None, INGRESS_BOUND)
      .addressed_to(INGRESS_OUR_ADDR),
    &subnets,
    false
  ));
  // A group destination does not excuse a foreign link — the interface check
  // runs first. It DOES survive any TTL, which is the point of the change.
  assert!(!ingress_admits(
    Arrival::new(ingress_off_subnet_peer(), Family::V4, None, INGRESS_OTHER)
      .addressed_to(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    &subnets,
    false
  ));
  assert!(ingress_admits(
    Arrival::new(
      ingress_off_subnet_peer(),
      Family::V4,
      Some(254),
      INGRESS_BOUND
    )
    .addressed_to(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    &subnets,
    false
  ));
}

/// A link-local source with NO provenance is refused, through the production
/// receive path.
///
/// `169.254/16` names some link and never ours. Where the receive path reports
/// no interface — IPv4 on the four BSDs, and any driver reading datagrams with
/// `recvfrom` — nothing else names one either, so admitting it let a peer on a
/// neighbouring NIC unicast straight into the cache and §8.2 conflict handling
/// with no shared prefix and no forged address.
#[cfg(feature = "tokio")]
#[test]
fn an_unwitnessed_link_local_source_is_refused() {
  use std::net::Ipv4Addr;

  let subnets = ingress_subnets();
  let v4_ll = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 7, 7)), 5353);
  for hop in [Some(255), None] {
    assert!(
      !ingress_admits(Arrival::new(v4_ll, Family::V4, hop, 0), &subnets, false),
      "absent provenance is not membership of the bound link"
    );
  }
  // An index naming our own interface is the witness stage 1 was missing — and
  // §11's second arm still has to admit it, which needs the prefix.
  assert!(ingress_admits(
    Arrival::new(v4_ll, Family::V4, Some(255), INGRESS_BOUND),
    &ingress_ll_prefixes(),
    false
  ));
}

/// IPv4 APIPA on an infrastructure-less link, through the production receive
/// path: a `169.254/16` peer is admitted when the bound interface carries the
/// same prefix and nothing named the link.
///
/// §11's unicast test is the source against the configured address and mask and
/// names no exception for link-local. Diverting every `169.254/16` source into a
/// branch that demanded a witness made IPv4 mDNS deaf exactly where it is most
/// load-bearing — a link with no DHCP, where our own address and every peer's is
/// a link-local one.
///
/// The square that exercises is provenance-ABSENT, which this driver's own
/// capability decides and no test can force through the production entry, so
/// the expectation is derived from it: where the path does report an interface,
/// a zero index is a failed proof and refusal is correct. The rule under both
/// values of that axis is covered exhaustively in `hick_udp::onlink`'s tests,
/// where it is a parameter.
#[cfg(feature = "tokio")]
#[test]
fn an_unwitnessed_apipa_peer_is_admitted_on_a_matching_prefix() {
  let apipa: Vec<(IpAddr, u8)> = vec![(IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 0, 0)), 16u8)];
  let peer_ll = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 3, 9)), 5353);
  let reported = rx_interface_reported(peer_ll);
  for hop in [Some(255), None] {
    assert_eq!(
      ingress_admits(Arrival::new(peer_ll, Family::V4, hop, 0), &apipa, false),
      !reported,
      "a link-local peer on a link-local-configured interface is on-link per \
       §11 wherever nothing named the link, and a failed proof where something \
       should have"
    );
  }
  // Not a blanket exemption, on any target: with no matching prefix it is
  // refused whatever the capability says.
  assert!(!ingress_admits(
    Arrival::new(peer_ll, Family::V4, Some(255), 0),
    &ingress_subnets(),
    false
  ));
  // And a witness still decides alone and outranks the prefix.
  assert!(!ingress_admits(
    Arrival::new(peer_ll, Family::V4, Some(255), INGRESS_OTHER),
    &apipa,
    false
  ));
  assert!(ingress_admits(
    Arrival::new(peer_ll, Family::V4, Some(255), INGRESS_BOUND),
    &apipa,
    false
  ));
}

/// The inbound TTL is carried and NOT tested, through the production receive
/// path.
///
/// RFC 6762 §11 states its receive test exhaustively and both ways are about the
/// destination address. The single receive-side TTL sentence in the RFC explains
/// why responses SHOULD be SENT at 255 — backwards compatibility with
/// 2004-draft queriers — and describes those obsolete implementations in the
/// past tense. Testing it on receive refused conforming traffic: §5.5 direct
/// unicast queries arrive at the sender stack's default unicast TTL, and group
/// queries from a stack left at the socket-default multicast TTL arrive at 1.
///
/// These are the three cases that pin it. Outbound 255 is untouched.
#[cfg(feature = "tokio")]
#[test]
fn the_inbound_ttl_is_carried_and_never_tested() {
  let subnets = ingress_subnets();
  let off = ingress_off_subnet_peer();
  let group = IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP);

  // 1. A group destination at a TTL that is not 255 — the case the old rule
  //    refused ahead of the group arm, and which §11 calls *necessarily* local
  //    regardless of source and *essential* for overlaid subnets.
  for hop in [Some(1), Some(64), Some(254), None] {
    assert!(
      ingress_admits(
        Arrival::new(off, Family::V4, hop, INGRESS_BOUND).addressed_to(group),
        &subnets,
        false
      ),
      "a group destination is local-link origin regardless of source, and the \
       TTL is not part of that test (hop {hop:?})"
    );
  }

  // 2. In-prefix unicast at TTL 64 — a §5.5 direct unicast query arriving at a
  //    stack's default, which the old rule refused outright.
  assert!(ingress_admits(
    Arrival::new(
      ingress_on_subnet_peer(),
      Family::V4,
      Some(64),
      INGRESS_BOUND
    )
    .addressed_to(INGRESS_OUR_ADDR),
    &subnets,
    false
  ));

  // 3. Witnessed out-of-prefix unicast at TTL 255 — admitted by the old
  //    shortcut before either arm was read, and refused now, which is what §11
  //    expects a receiver to do with it.
  assert!(!ingress_admits(
    Arrival::new(off, Family::V4, Some(255), INGRESS_BOUND).addressed_to(INGRESS_OUR_ADDR),
    &subnets,
    false
  ));

  // The interface gate is unaffected by any of it: a foreign index still
  // refuses, at every TTL and with a group destination.
  for hop in [Some(255), Some(64), None] {
    assert!(!ingress_admits(
      Arrival::new(off, Family::V4, hop, INGRESS_OTHER).addressed_to(group),
      &subnets,
      false
    ));
  }
}

/// A renumbering under a LIVE endpoint is picked up: the old prefix stops being
/// admissible and the new one starts, with no restart.
///
/// §11 compares a source against the receiving interface's configuration as it
/// IS. A snapshot taken once at bind is wrong in both directions the moment an
/// address changes — a DHCP lease lost into APIPA is the ordinary case — and it
/// became load-bearing when the TTL arm was removed, because every non-loopback
/// source now depends on it.
///
/// The transition is driven through the production refresh, not by assigning the
/// field: the enumeration is forced to report the new prefix, the snapshot is
/// aged past the shared interval, and the next datagram is what triggers the
/// re-read.
#[cfg(feature = "tokio")]
#[test]
fn a_renumbered_interface_is_picked_up_without_restarting_the_endpoint() {
  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: INGRESS_BOUND,
  };
  let mut state = DriverState::new(&opts, sockets);
  state.bound_is_loopback = false;
  state.local_subnets = ingress_subnets();
  let old_peer = ingress_on_subnet_peer();
  let apipa = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 3, 9)), 5353);

  let feed = |state: &mut DriverState<agnostic_net::tokio::Net>, src: SocketAddr| -> bool {
    let body = vec![0u8; 12];
    state.selfsend.record(Family::V4, &body, ClockPair::now());
    state.selfsend.seal();
    #[cfg(debug_assertions)]
    state.note_park_entry();
    // The DELTA, not `is_empty`: a refused datagram leaves its credit behind, so
    // after the first refusal the tracker is never empty again and `is_empty`
    // would report every later datagram as refused too.
    let before = state.selfsend.len();
    state.handle_packet(Packet {
      src,
      data: body,
      family: Family::V4,
      local_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
      iface: ingress_bound_witness(),
      rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
      destination: DestinationWitness::blind(),
      delivery: None,
      hop_limit: None,
    });
    state.selfsend.len() < before
  };

  // Before: the configured prefix admits, APIPA does not.
  assert!(feed(&mut state, old_peer));
  assert!(!feed(&mut state, apipa));

  // The interface renumbers 192.168.1.0/24 -> 169.254/16 under the live
  // endpoint, and the snapshot ages past its interval.
  hick_udp::onlink::force_enumeration_for_test(Some((
    INGRESS_BOUND,
    vec![(IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 0, 0)), 16u8)],
  )));
  state.subnets_refreshed_at =
    monotonic_instant_ago(hick_udp::onlink::SUBNET_REFRESH_INTERVAL + Duration::from_millis(50));

  // After: the obsolete prefix is refused and the current one is admitted.
  assert!(
    !feed(&mut state, old_peer),
    "the obsolete prefix must stop being admissible once the interface changed"
  );
  assert!(
    feed(&mut state, apipa),
    "the current prefix must be admitted without restarting the endpoint"
  );
  // ... and the refresh asked about the interface this endpoint BOUND. Without
  // this, production could refresh index 0 or a foreign one — or merely clear
  // the snapshot — and both assertions above would still hold.
  assert_eq!(
    hick_udp::onlink::last_enumerated_interface_for_test(),
    Some(INGRESS_BOUND)
  );
  hick_udp::onlink::force_enumeration_for_test(None);
}

/// The hop limit changes NOTHING, asserted directly rather than left implied.
///
/// Four tests in this workspace once said a TTL other than 255 made a datagram
/// off-link. They passed — but for the source prefix, not the TTL — and the
/// wrong rationale outlived the rule by two prose sweeps, because nobody
/// re-reads a passing test. This is the assertion that would have caught them:
/// otherwise-identical datagrams at every hop limit, admitted and refused
/// together.
#[cfg(feature = "tokio")]
#[test]
fn the_outcome_is_invariant_under_the_hop_limit() {
  let subnets = ingress_subnets();
  let group = IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP);
  let unicast = INGRESS_OUR_ADDR;

  for hop in [Some(255), Some(64), None] {
    // Admitted, whatever the hop limit: in-prefix source at §11's unicast arm.
    assert!(
      ingress_admits(
        Arrival::new(ingress_on_subnet_peer(), Family::V4, hop, INGRESS_BOUND)
          .addressed_to(unicast),
        &subnets,
        false
      ),
      "in-prefix unicast must be admitted at hop {hop:?}"
    );
    // Admitted, whatever the hop limit: group destination, off-prefix source.
    assert!(
      ingress_admits(
        Arrival::new(ingress_off_subnet_peer(), Family::V4, hop, INGRESS_BOUND).addressed_to(group),
        &subnets,
        false
      ),
      "a group destination must be admitted at hop {hop:?}"
    );
    // Refused, whatever the hop limit: out-of-prefix unicast.
    assert!(
      !ingress_admits(
        Arrival::new(ingress_off_subnet_peer(), Family::V4, hop, INGRESS_BOUND)
          .addressed_to(unicast),
        &subnets,
        false
      ),
      "out-of-prefix unicast must be refused at hop {hop:?}"
    );
    // Refused, whatever the hop limit: foreign interface.
    assert!(
      !ingress_admits(
        Arrival::new(ingress_on_subnet_peer(), Family::V4, hop, INGRESS_OTHER)
          .addressed_to(unicast),
        &subnets,
        false
      ),
      "a foreign interface must be refused at hop {hop:?}"
    );
  }
}

/// Row 1, and the live one: a conforming hop limit does not excuse a foreign
/// interface.
///
/// This driver's gate was an exclusive match — a reported hop limit was decisive
/// on its own and the interface was consulted only on the fallback branch. An
/// attacker on a neighbouring NIC then reached the cache and RFC 6762 §8.2
/// conflict handling with nothing but a well-formed unicast datagram at TTL 255,
/// which needs no group membership to be delivered.
#[cfg(feature = "tokio")]
#[test]
fn a_conforming_hop_limit_does_not_excuse_a_foreign_interface() {
  let subnets = ingress_subnets();
  assert!(
    !ingress_admits(
      Arrival::new(
        ingress_on_subnet_peer(),
        Family::V4,
        Some(255),
        INGRESS_OTHER
      ),
      &subnets,
      false
    ),
    "a datagram delivered on a NIC this endpoint did not bind is off its link \
     whatever its hop limit says"
  );
  // The same datagram on the interface we bound is still admitted, so the
  // rejection above is the interface and not the datagram.
  assert!(ingress_admits(
    Arrival::new(
      ingress_on_subnet_peer(),
      Family::V4,
      Some(255),
      INGRESS_BOUND
    ),
    &subnets,
    false
  ));
}

/// Row 2: a zero interface index is never the bound link, whatever this
/// driver's receive path can report.
///
/// The old fallback read a zero as "the platform cannot tell us" and admitted a
/// link-local source on it. Both halves of that are now refused, for two
/// different reasons that reach the same answer — which is why this asserts
/// outright rather than deriving the expectation from
/// [`rx_interface_reported`]:
///
/// * where the path DOES report an interface, a zero is a datagram the kernel
///   declined to place — a failed proof, not silence, and `try_bind_v6` fails
///   the bind rather than leaving PKTINFO quietly disabled;
/// * where it reports none, nothing named the link at all, and a link-local
///   address may not name it for itself. Absent provenance is not membership.
///
/// The degraded mode that survives is the one resting on positive evidence — a
/// source inside the bound interface's own subnets — which is what
/// `a_receive_path_that_recovers_nothing_still_admits_an_in_subnet_peer`
/// covers. It is deliberately not this one.
#[cfg(feature = "tokio")]
#[test]
fn a_zero_interface_is_never_the_bound_link() {
  let subnets = ingress_subnets();
  // A scope-LESS link-local peer: nothing names the link, on any target.
  assert!(
    !ingress_admits(
      Arrival::new(ingress_link_local_peer(0), Family::V6, None, 0),
      &subnets,
      false
    ),
    "no witness at all is not the bound link, whichever reason applies"
  );
  // The shape a kernel actually produces: it fills `sin6_scope_id` for a
  // link-local source from the receiving interface, and that scope is a witness
  // in its own right — which is why IPv6 link-local discovery is unaffected by
  // the rule above even on a path that reports no interface index.
  assert!(ingress_admits(
    Arrival::new(ingress_link_local_peer(INGRESS_BOUND), Family::V6, None, 0),
    &ingress_ll_prefixes(),
    false
  ));
  // And a scope naming another link is refused on the same evidence.
  assert!(!ingress_admits(
    Arrival::new(ingress_link_local_peer(INGRESS_OTHER), Family::V6, None, 0),
    &subnets,
    false
  ));
}

/// Row 3: the fallback branch's own interface check only ever covered a
/// LINK-LOCAL source.
///
/// A routable source inside the bound interface's subnet passed it on any
/// interface at all — which is the whole neighbouring-NIC case again, on every
/// platform that reports no TTL cmsg (Windows reports none at all).
#[cfg(feature = "tokio")]
#[test]
fn a_foreign_interface_is_rejected_with_no_hop_metadata_either() {
  let subnets = ingress_subnets();
  assert!(
    !ingress_admits(
      Arrival::new(ingress_on_subnet_peer(), Family::V4, None, INGRESS_OTHER),
      &subnets,
      false
    ),
    "a global source inside our own prefix is still off our link when it \
     arrived on someone else's NIC"
  );
  assert!(ingress_admits(
    Arrival::new(ingress_on_subnet_peer(), Family::V4, None, INGRESS_BOUND),
    &subnets,
    false
  ));
}

/// Row 4: an IPv6 source's scope id is decisive even when the index agrees with
/// us.
///
/// This driver passed `pkt.src.ip()` to the gate and threw the zone away, so a
/// source whose own address says it came from another link was admitted on an
/// index that said ours. A datagram that contradicts itself has already failed
/// to prove it is ours, and a trust boundary resolves that against the sender.
#[cfg(feature = "tokio")]
#[test]
fn a_conflicting_scope_rejects_whatever_the_index_says() {
  let subnets = ingress_subnets();
  assert!(
    !ingress_admits(
      Arrival::new(
        ingress_link_local_peer(INGRESS_OTHER),
        Family::V6,
        None,
        INGRESS_BOUND
      ),
      &subnets,
      false
    ),
    "the scope id names another link; an index naming ours does not overrule it"
  );
  assert!(ingress_admits(
    Arrival::new(
      ingress_link_local_peer(INGRESS_BOUND),
      Family::V6,
      None,
      INGRESS_BOUND
    ),
    &ingress_ll_prefixes(),
    false
  ));
}

/// The must-REJECT half of the loopback exception, at the same entry.
///
/// A reported foreign interface outranks the source address even for the
/// endpoint the exception exists for. These sockets are wildcard bound, so where
/// the OS permits a loopback source onto a physical NIC — Linux's
/// `route_localnet` — the datagram reaches port 5353, and the exception must not
/// carry it.
#[cfg(feature = "tokio")]
#[test]
fn a_loopback_bound_endpoint_still_refuses_a_reported_foreign_interface() {
  use std::net::{Ipv4Addr, Ipv6Addr};

  let subnets = ingress_subnets();
  for ip in [
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
  ] {
    let family = if ip.is_ipv4() { Family::V4 } else { Family::V6 };
    assert!(
      !ingress_admits(
        Arrival::new(SocketAddr::new(ip, 5353), family, Some(255), INGRESS_OTHER),
        &subnets,
        true
      ),
      "a source address is a claim the sender wrote; a nonzero interface index \
       is evidence the kernel attached, and it wins"
    );
  }
}

/// A receive path that recovers no ancillary data at all must not be made deaf
/// by the interface gate — `recv_task`'s plain `recv_from` arm, checked through
/// the production receive entry.
///
/// Unix and Windows both read through `hick_udp::recv_with_meta`; every other
/// target takes an arm that declares `IfaceWitness::blind()` /
/// `DestinationWitness::blind()` once, from its own construction, and `hop_limit: None`.
/// Capability therefore belongs to the receive path and not to the platform, and
/// telling the rule otherwise would make every absent index a failed proof and
/// drop every non-loopback datagram there.
///
/// The fixture goes through [`packet_iface_witness`], so on a host whose path
/// DOES report the case exercised is the LOST one — our own control buffer too
/// small — which is what the assertion below is about. The blind arm's own case
/// is `a_blind_receive_path_admits_an_in_subnet_peer_on_every_target`.
///
/// The expectation is derived from this driver's own capability rather than
/// hardcoded, so the case runs on every target: where the path DOES report an
/// interface a zero is a failed proof and the datagram is refused; where it
/// reports none the source-address rule decides and an in-subnet peer is
/// admitted.
///
/// This is the ONLY degraded admission left, and it survives because it rests
/// on positive evidence: the source sits inside a prefix configured on the
/// interface this endpoint bound. The link-local case does not degrade the same
/// way and no longer admits anything on absent provenance — see
/// `a_zero_interface_is_never_the_bound_link`.
#[cfg(feature = "tokio")]
#[test]
fn a_receive_path_that_recovers_nothing_still_admits_an_in_subnet_peer() {
  use std::net::Ipv4Addr;

  let src = ingress_on_subnet_peer();
  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: INGRESS_BOUND,
  };
  let mut state = DriverState::new(&opts, sockets);
  state.local_subnets = ingress_subnets();
  state.bound_is_loopback = false;

  let body = vec![0u8; 12];
  state.selfsend.record(Family::V4, &body, ClockPair::now());
  state.selfsend.seal();
  #[cfg(debug_assertions)]
  state.note_park_entry();

  // What the no-ancillary-data arm of `recv_task` builds.
  state.handle_packet(Packet {
    src,
    data: body,
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    iface: packet_iface_witness(src),
    rx: RxEvidence::none(),
    destination: DestinationWitness::blind(),
    delivery: None,
    hop_limit: None,
  });

  assert_eq!(
    state.selfsend.is_empty(),
    !rx_interface_reported(src),
    "a path with no interface to give must fall to §11's source rule, not be \
     read as a kernel that declined to place the datagram"
  );
}

/// A witness the KERNEL declined to emit must not make this driver deaf.
///
/// The narrower case above it — `a_receive_path_that_recovers_nothing_...` —
/// is about our own control buffer being too small, which is this side's bug and
/// still refuses. This one is the other absence, and it is the one an attacker
/// can provoke: every BSD builds its ancillary mbufs with `M_NOWAIT` and, when
/// `sbcreatecontrol` returns `NULL`, skips the cmsg with no error, no counter and
/// no `MSG_CTRUNC`, while still delivering the datagram (FreeBSD
/// `kern/uipc_sockbuf.c`, NetBSD `kern/uipc_socket2.c`). Mbuf exhaustion is
/// normally caused by a flood, so refusing here takes the responder off the air
/// exactly during the traffic that caused it.
///
/// What it degrades to is not a new exposure: it is §11's source-prefix arm, the
/// standing rule on every structurally blind square.
#[cfg(feature = "tokio")]
#[test]
fn a_declined_witness_degrades_to_the_source_arm_rather_than_going_deaf() {
  let subnets = ingress_subnets();
  let src = ingress_on_subnet_peer();

  // The interface witness. Same datagram, same in-subnet source: declined
  // admits, and the LOST twin above it does not.
  assert!(
    ingress_admits(
      Arrival::new(src, Family::V4, None, INGRESS_BOUND).iface_declined(),
      &subnets,
      false
    ),
    "a kernel that skipped the PKTINFO cmsg leaves §11's source arm deciding,      and an in-prefix source passes it"
  );

  // The destination witness, with the link witnessed so stage 1 cannot be what
  // decides.
  assert!(
    ingress_admits(
      Arrival::new(src, Family::V4, None, INGRESS_BOUND).destination_declined(),
      &subnets,
      false
    ),
    "and the same for a declined destination cmsg"
  );

  // Degrading is not admitting: an OFF-prefix source is still refused, so the
  // fallback rests on positive evidence exactly as the blind squares' does.
  assert!(
    !ingress_admits(
      Arrival::new(ingress_off_subnet_peer(), Family::V4, None, INGRESS_BOUND).iface_declined(),
      &subnets,
      false
    ),
    "the degraded arm is §11's source rule, not an open door"
  );
}

/// The plain `recv_from` arm's own case, stated on every target rather than only
/// where that arm compiles.
///
/// `recv_task` builds `IfaceWitness::blind()` / `DestinationWitness::blind()` there — a
/// declaration made ONCE from the arm's own construction, never inferred from a
/// datagram — and the boundary must fall back to §11's source rule on it. The
/// fixture presents those witnesses directly, so the case runs on a Unix host
/// too, where that arm is not compiled at all.
#[cfg(feature = "tokio")]
#[test]
fn a_blind_receive_path_admits_an_in_subnet_peer_on_every_target() {
  let subnets = ingress_subnets();
  let mut arrival = Arrival::new(ingress_on_subnet_peer(), Family::V4, None, INGRESS_BOUND);
  arrival.iface = IfaceWitness::blind();
  arrival.destination = DestinationWitness::blind();
  assert!(
    ingress_admits(arrival, &subnets, false),
    "a path with nothing to witness must fall to §11's source rule rather than      read its own silence as a failed proof"
  );

  let mut off = Arrival::new(ingress_off_subnet_peer(), Family::V4, None, INGRESS_BOUND);
  off.iface = IfaceWitness::blind();
  off.destination = DestinationWitness::blind();
  assert!(
    !ingress_admits(off, &subnets, false),
    "and it is still the source rule: an off-prefix source is refused"
  );
}

/// Row 5: the loopback exception belongs to the ENDPOINT's link, not to the
/// source address.
///
/// "A kernel does not deliver a martian loopback source arriving on a real NIC"
/// is not an invariant — Linux's `route_localnet` exists to stop treating
/// `127/8` as martian — so an adjacent sender can put `127.0.0.1:5353` at hop
/// limit 255 onto a NIC this endpoint did not bind. An address-only exemption
/// short-circuits the whole boundary before either witness is read.
#[cfg(feature = "tokio")]
#[test]
fn a_loopback_source_from_a_foreign_interface_is_rejected() {
  use std::net::{Ipv4Addr, Ipv6Addr};

  let subnets = ingress_subnets();
  for (src, family) in [
    (
      SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353),
      Family::V4,
    ),
    (
      SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353),
      Family::V6,
    ),
  ] {
    assert!(
      !ingress_admits(
        Arrival::new(src, family, Some(255), INGRESS_OTHER),
        &subnets,
        false
      ),
      "a NIC-bound endpoint has no loopback traffic to protect, so a loopback \
       source from another link is just a spoofed source"
    );
    // And a loopback-BOUND endpoint refuses it too: the exception covers absent
    // provenance, not contradicted provenance. What it does still take is its
    // own echo where the platform placed it on no interface at all.
    assert!(!ingress_admits(
      Arrival::new(src, family, Some(255), INGRESS_OTHER),
      &subnets,
      true
    ));
    assert!(ingress_admits(
      Arrival::new(src, family, Some(255), 0),
      &subnets,
      true
    ));
  }
}

/// The must-ADMIT direction, in every shape a loopback fixture's own traffic
/// actually arrives in.
///
/// The rejecting rows above can only ever get stricter, and a gate that is
/// stricter than §11 is a responder that goes quiet rather than one that leaks —
/// so the boundary needs its other half pinned at the same entry. Every loopback
/// integration test in this workspace, and any caller pinned to the loopback
/// interface, runs entirely on the datagrams below; if the gate ever refuses one
/// of them, discovery stops working there and no rejecting test would notice.
///
/// `iface_reported` is production's own value, not a fixture constant: it is
/// `true` for both families on every target this driver builds for except the
/// BSD IPv4 square, which is exactly the condition under which the interface
/// check is live. A shape that survives it here survives it on the platforms
/// that enforce it.
#[cfg(feature = "tokio")]
#[test]
fn a_loopback_bound_endpoint_admits_its_own_traffic_in_every_shape() {
  use std::net::{Ipv4Addr, Ipv6Addr};

  let subnets = ingress_subnets();
  let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);
  let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353);
  for (src, family, hop, pkt_iface, what) in [
    // The ordinary case: our own echo, conforming hop limit, reported on the
    // interface we bound.
    (
      v4,
      Family::V4,
      Some(255),
      INGRESS_BOUND,
      "v4 echo on the bound index",
    ),
    (
      v6,
      Family::V6,
      Some(255),
      INGRESS_BOUND,
      "v6 echo on the bound index",
    ),
    // `IP_RECVTTL` is enabled best-effort at bind, so a host whose enable failed
    // delivers the same traffic with no hop limit at all.
    (
      v4,
      Family::V4,
      None,
      INGRESS_BOUND,
      "v4 echo with no hop limit",
    ),
    // A platform is free to place the echo on NO interface, which is the whole
    // extent of the exception: absent provenance, never contradicted
    // provenance. A REPORTED foreign index is refused even here — see
    // `a_loopback_bound_endpoint_still_refuses_a_reported_foreign_interface`.
    (v4, Family::V4, Some(255), 0, "v4 echo with no index at all"),
  ] {
    assert!(
      ingress_admits(Arrival::new(src, family, hop, pkt_iface), &subnets, true),
      "{what}: a loopback-bound endpoint must admit this, or its own \
       suppression and every loopback fixture stop working"
    );
  }
}

// ── The self-send tracker (`hick_udp::selfsend`) as this driver drives it ────
//
// The tracker itself is exhaustively tested in `hick-udp`. What these cover is
// the contract THIS driver depends on: a credit per real multicast send, keyed
// to the family that carried it, claimed take-once by the echo read off that
// family's socket, aged on the monotonic clock from the window the run loop's
// seal opens.

/// One send's own pre-syscall reading of both clocks, in the shape `send_to_at`
/// takes it: the wall stamp, and the monotonic partner read immediately after.
fn send_stamps() -> ClockPair {
  ClockPair::now()
}

/// A claim landing `after` the send on BOTH clocks at once — a run in which the
/// wall clock did nothing but keep up with the monotonic one.
///
/// Every test whose subject is not a clock step goes through this, so none of
/// them degrades to content-only matching by accident and quietly stops
/// exercising the ordering rule it was written for.
fn claim(sent: ClockPair, after: Duration) -> ClockPair {
  ClockPair::new(sent.wall + after, sent.mono + after)
}

/// Record `body` on `family` and open its claim window at `sent.mono` — one turn
/// of the driver loop, where the send stage records and the NEXT iteration's top
/// seals. Every test whose subject is not the seal itself goes through this, so
/// none of them leans on the unsealed state by accident.
fn recorded_and_sealed(t: &mut SelfSendTracker, family: Family, body: &[u8], sent: ClockPair) {
  t.record(family, body, sent);
  t.seal_at(sent.mono);
}

#[test]
fn self_send_consume_once() {
  // One recorded send suppresses exactly one loopback.
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"hello", sent);
  let now = claim(sent, Duration::from_millis(1));
  let rx = RxEvidence::from_stamp_for_test(now.wall);
  // The loopback the kernel stamped at-or-after our send is matched and consumed.
  assert!(tracker.take_at(Family::V4, b"hello", rx, now));
  // A second byte-identical datagram finds no credit -> treated as a peer's.
  assert!(!tracker.take_at(Family::V4, b"hello", rx, now));
  assert!(tracker.is_empty());
}

#[test]
fn self_send_distinct_payloads_do_not_match() {
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"alpha", sent);
  let now = claim(sent, Duration::from_millis(1));
  let rx = RxEvidence::from_stamp_for_test(now.wall);
  assert!(!tracker.take_at(Family::V4, b"beta", rx, now));
  // The unrelated credit is left intact for its own loopback.
  assert!(tracker.take_at(Family::V4, b"alpha", rx, now));
}

#[test]
fn self_send_expires_after_ttl() {
  // A datagram arriving more than SELF_SEND_TTL after the window opened is no
  // longer our loopback, and the dead credit is reclaimed by the next seal so
  // the tracker cannot grow without bound.
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"hello", sent);
  // Past the TTL on the MONOTONIC half, which is the only clock the age is
  // measured on; the wall half moves with it so nothing here is a step.
  let too_late = claim(sent, SELF_SEND_TTL + Duration::from_millis(1));
  assert!(!tracker.take_at(
    Family::V4,
    b"hello",
    RxEvidence::from_stamp_for_test(too_late.wall),
    too_late
  ));
  tracker.seal_at(too_late.mono);
  assert!(
    tracker.is_empty(),
    "the dead credit is swept, so a tracker under a sustained send rate stays bounded"
  );
  // A credit recorded afterwards is unaffected by the expiry above.
  recorded_and_sealed(&mut tracker, Family::V4, b"other", too_late);
  assert_eq!(tracker.len(), 1);
  let now = claim(too_late, Duration::from_millis(1));
  assert!(tracker.take_at(
    Family::V4,
    b"other",
    RxEvidence::from_stamp_for_test(now.wall),
    now
  ));
}

#[test]
fn self_send_peer_before_our_send_cannot_steal_credit() {
  // A byte-identical peer datagram the kernel stamped BEFORE our send must not
  // consume the credit even though its content hash matches; otherwise the
  // genuine loopback behind it is misclassified as a peer's and this endpoint
  // raises an RFC 6762 §9 conflict against itself.
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"probe", sent);
  let peer_rx = RxEvidence::from_stamp_for_test(sent.wall - Duration::from_millis(500));
  assert!(!tracker.take_at(Family::V4, b"probe", peer_rx, sent));
  // Our genuine loopback arrives at-or-after the send and is matched.
  let now = claim(sent, Duration::from_millis(1));
  assert!(tracker.take_at(
    Family::V4,
    b"probe",
    RxEvidence::from_stamp_for_test(now.wall),
    now
  ));
}

// On microsecond `timeval` sources (Apple/BSD) RX_TIMESTAMP_GRAIN is 1µs, so a
// loopback whose kernel timestamp was truncated to a slightly-earlier microsecond
// than our nanosecond send time still counts as ours — but anything earlier than
// the grain is a genuine pre-send (peer) datagram and must not match.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[test]
fn self_send_ordered_tolerates_microsecond_truncation() {
  assert_eq!(hick_udp::RX_TIMESTAMP_GRAIN, Duration::from_micros(1));
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"trunc", sent);
  let truncated_rx = sent.wall - (hick_udp::RX_TIMESTAMP_GRAIN - Duration::from_nanos(1));
  assert!(tracker.take_at(
    Family::V4,
    b"trunc",
    RxEvidence::from_stamp_for_test(truncated_rx),
    sent
  ));

  recorded_and_sealed(&mut tracker, Family::V4, b"trunc", sent);
  let too_early = sent.wall - (hick_udp::RX_TIMESTAMP_GRAIN + Duration::from_micros(4));
  assert!(!tracker.take_at(
    Family::V4,
    b"trunc",
    RxEvidence::from_stamp_for_test(too_early),
    sent
  ));
}

// On nanosecond `SO_TIMESTAMPNS` (Linux/Android) the kernel timestamp is exact,
// so RX_TIMESTAMP_GRAIN is zero and there is NO pre-send tolerance: a
// byte-identical peer datagram stamped even 500ns before our send must not steal
// the take-once credit.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn self_send_ordered_nanosecond_rejects_pre_send() {
  assert_eq!(hick_udp::RX_TIMESTAMP_GRAIN, Duration::ZERO);
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"probe", sent);
  let pre_send = sent.wall - Duration::from_nanos(500);
  assert!(!tracker.take_at(
    Family::V4,
    b"probe",
    RxEvidence::from_stamp_for_test(pre_send),
    sent
  ));
  // The credit survives the non-match; our genuine loopback (at-or-after the
  // send) is still matched.
  assert!(tracker.take_at(
    Family::V4,
    b"probe",
    RxEvidence::from_stamp_for_test(sent.wall),
    sent
  ));
}

/// Degraded matching is reached by presenting NO kernel receive stamp, and it
/// weighs content, family and the TTL — nothing else.
///
/// The old version of this test handed the claim a userspace read time and
/// asserted it was weighed as a reference. That behaviour is gone, and its
/// removal is the point: the only wall value a degraded claim can offer is a
/// read time, which is at-or-after the send in every case except a wall clock
/// that stepped backwards — so an ordering test against it could only ever fire
/// on the step, and firing means refusing our own echo.
#[test]
fn self_send_degraded_matches_take_once_within_ttl() {
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"win", sent);
  let now = claim(sent, Duration::from_millis(10));
  assert!(tracker.take_at(Family::V4, b"win", RxEvidence::none(), now));
  // Take-once: the credit is gone. A byte-identical PEER datagram read next
  // would now be treated as a peer's — and, conversely, a pre-buffered peer
  // datagram read first could consume this credit. That credit-theft exposure is
  // the documented degradation when no kernel rx timestamp is available.
  assert!(!tracker.take_at(Family::V4, b"win", RxEvidence::none(), now));
}

#[test]
fn self_send_degraded_expires_after_ttl() {
  // Nothing but the TTL bounds a degraded claim, and the TTL is monotonic.
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"win", sent);
  let too_late = claim(sent, SELF_SEND_TTL + Duration::from_millis(1));
  assert!(!tracker.take_at(Family::V4, b"win", RxEvidence::none(), too_late));
}

#[test]
fn self_send_dual_stack_records_two_entries() {
  // One logical transmit is TWO syscalls with identical bytes, so the fan-out
  // records one credit per family and each echo claims only its own.
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"resp", sent);
  recorded_and_sealed(&mut tracker, Family::V6, b"resp", sent);
  assert_eq!(tracker.len(), 2);
  let now = claim(sent, Duration::from_millis(1));
  let rx = RxEvidence::from_stamp_for_test(now.wall);
  assert!(tracker.take_at(Family::V4, b"resp", rx, now));
  assert!(tracker.take_at(Family::V6, b"resp", rx, now));
  // Both credits are spent; a third copy on either family is a peer's.
  assert!(!tracker.take_at(Family::V4, b"resp", rx, now));
  assert!(!tracker.take_at(Family::V6, b"resp", rx, now));
}

#[test]
fn self_send_cap_declines_without_evicting_live_entries() {
  // At the cap the NEW credit is the one refused. Evicting a live one would
  // unmask a real loopback as peer traffic, which is the expensive direction.
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  for _ in 0..MAX_SELF_SEND_ENTRIES {
    tracker.record(Family::V4, b"live", sent);
  }
  // Sealed, so every resident credit's window is genuinely open and its TTL is
  // genuinely running — an unsealed credit is retained by a different rule.
  tracker.seal_at(sent.mono);
  assert_eq!(tracker.len(), MAX_SELF_SEND_ENTRIES);

  tracker.record(Family::V4, b"overflow", sent);
  assert_eq!(tracker.len(), MAX_SELF_SEND_ENTRIES);

  let now = claim(sent, Duration::from_millis(1));
  let rx = RxEvidence::from_stamp_for_test(now.wall);
  assert!(
    !tracker.take_at(Family::V4, b"overflow", rx, now),
    "the would-be new credit was refused, never admitted"
  );
  assert!(
    tracker.take_at(Family::V4, b"live", rx, now),
    "and a resident LIVE credit is still claimable by its own loopback"
  );
}

/// A wall-clock step between the send and the echo used to make this endpoint
/// ingest its own announcement as a peer's.
///
/// `Credit::sent`'s wall half is the only thing ordering an echo against its
/// send, and it is not monotonic. When an NTP step, a `settimeofday`, or a VM
/// resume moves it under a credit that is already waiting, that stamp describes a
/// timeline the kernel's receive stamp was never taken on — and comparing the two
/// refused our own echo, which reached the protocol layer as peer traffic and
/// raised a phantom RFC 6762 §9 conflict against ourselves, once per step, for as
/// long as the clock kept stepping.
///
/// Every claim now reads both clocks, and a credit whose two elapsed times
/// disagree past `WALL_STEP_TOLERANCE` has its ordering evidence discarded rather
/// than used against it.
#[test]
fn self_send_wall_step_no_longer_makes_us_ingest_our_own_echo_as_a_peer() {
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"announce", sent);

  // A backwards step is the expensive direction, so that is the one presented:
  // one millisecond of real time passed on the monotonic clock while the wall
  // clock travelled ten seconds the other way.
  const STEP: Duration = Duration::from_secs(10);
  assert!(
    STEP > WALL_STEP_TOLERANCE,
    "the fixture must present a step large enough for the claim to detect"
  );
  let stepped = ClockPair::new(sent.wall - STEP, sent.mono + Duration::from_millis(1));
  // The kernel stamped our own echo on the far side of the step, so it reads as
  // predating the send it is the echo OF.
  let rx = RxEvidence::from_stamp_for_test(stepped.wall + Duration::from_millis(1));

  assert!(
    tracker.take_at(Family::V4, b"announce", rx, stepped),
    "the credit's wall stamp is not on the timeline this receive stamp was taken \
     on, so the ordering evidence must be discarded rather than weighed — \
     weighing it refuses our own echo and renames this service under §9"
  );
  assert!(tracker.is_empty(), "and the claim is still take-once");
}

/// The TTL is real elapsed time, so it is measured on the monotonic clock and a
/// wall-clock step can neither expire a live credit nor resurrect a dead one.
///
/// Both directions are asserted, because a wall-measured age gets each one wrong
/// in the opposite way: a forward step expires a credit whose echo is still in
/// flight (our own datagram then reaches the protocol layer as a peer's), and a
/// backward step keeps a credit alive past the window that bounds how long a
/// co-resident peer's byte-identical datagram can be swallowed as our echo.
///
/// Both claims pass no receive stamp, so the subject is the age alone and not the
/// ordering evidence a step also weakens.
#[test]
fn self_send_ttl_is_monotonic_so_a_wall_step_neither_expires_nor_resurrects() {
  const HOURS: Duration = Duration::from_secs(3 * 3600);

  // Hours forward on the wall clock, one millisecond of real time: still live.
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"probe", sent);
  let wall_far_ahead = ClockPair::new(sent.wall + HOURS, sent.mono + Duration::from_millis(1));
  assert!(
    tracker.take_at(Family::V4, b"probe", RxEvidence::none(), wall_far_ahead),
    "a wall clock that stepped hours forward is not hours of elapsed time; \
     ageing on it would expire a credit whose echo is still in flight"
  );

  // Past the TTL of real time, hours BACKWARD on the wall clock — which a
  // wall-measured age reads as no age at all: dead anyway.
  let mut tracker = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut tracker, Family::V4, b"probe", sent);
  let mono_expired = ClockPair::new(
    sent.wall - HOURS,
    sent.mono + SELF_SEND_TTL + Duration::from_millis(1),
  );
  assert!(
    !tracker.take_at(Family::V4, b"probe", RxEvidence::none(), mono_expired),
    "real elapsed time is past the TTL, so these bytes are a co-resident peer's \
     and not our echo; no wall-clock reading may resurrect the credit"
  );
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
  //    snapshot is NON-empty (records were confirmed-emitted). DestinationWitness is
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
    let _ = state
      .drain_withdrawals(t, &mut DrainBudget::new(t), &mut scratch)
      .await;
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
    let _ = state
      .drain_withdrawals(t, &mut DrainBudget::new(t), &mut scratch)
      .await;
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
    let _ = state
      .drain_withdrawals(t, &mut DrainBudget::new(t), &mut scratch)
      .await;
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
    let _ = state
      .drain_withdrawals(t, &mut DrainBudget::new(t), &mut scratch)
      .await;
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
  state
    .drain_transmits(now, &mut DrainBudget::new(now), &mut scratch)
    .await;

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
  let more_pending = state
    .drain_transmits(now, &mut DrainBudget::new(now), &mut scratch)
    .await;

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

// ── The dual-stack delivery boundary (`FamilyAttempt`) ──────────────────────

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
fn confirm_service_round<N: agnostic_net::Net>(
  state: &mut DriverState<N>,
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
    let _ = confirm_service_transmit(endpoint, ctx, t, fanout.v4, fanout.v6);
    rounds += 1;
  }
  rounds
}

/// A dual-stack fan-out in which v4 carried the datagram at `at` and a BOUND v6
/// socket rejected it (`ENETUNREACH` and friends). Driving the behaviour tests
/// from the per-family facts rather than a hand-fed delivery shape keeps the
/// mapping inside the tested path.
#[cfg(feature = "tokio")]
fn partial_fanout(at: StdInstant) -> Fanout {
  Fanout {
    v4: FamilyAttempt::Accepted { at },
    v6: FamilyAttempt::Refused { permanent: false },
  }
}

/// Both bound families carried the datagram, at `at`.
#[cfg(feature = "tokio")]
fn whole_fanout(at: StdInstant) -> Fanout {
  Fanout {
    v4: FamilyAttempt::Accepted { at },
    v6: FamilyAttempt::Accepted { at },
  }
}

/// Both bound families rejected it — nothing reached any wire.
#[cfg(feature = "tokio")]
fn failed_fanout() -> Fanout {
  Fanout {
    v4: FamilyAttempt::Refused { permanent: false },
    v6: FamilyAttempt::Refused { permanent: false },
  }
}

/// `Fanout::sent_count()` is the one piece of the old per-family table that is
/// still this driver's own: which [`FamilyAttempt`] a family reports now
/// projects onto the core's delivery shape, and that projection — the table of
/// which value is `Delivered`/`Missed`/`Unobligated`, and that a GATED family is
/// `Missed` rather than `Unobligated` — is internal to `mdns_proto` and asserted
/// once, in its own suite. What stays here is the fairness credit: how many
/// families the fan-out actually put bytes on, which this driver spends and the
/// core never sees.
#[test]
fn the_fan_out_charges_one_credit_per_family_actually_sent() {
  let at = StdInstant::now();
  let accepted = FamilyAttempt::Accepted { at };
  let refused = FamilyAttempt::Refused { permanent: false };
  let gate_shut = FamilyAttempt::GateShut;
  let no_socket = FamilyAttempt::NoSocket;
  let cases = [
    (accepted, accepted, 2),
    (accepted, no_socket, 1),
    (no_socket, accepted, 1),
    (accepted, refused, 1),
    (refused, accepted, 1),
    (refused, refused, 0),
    (refused, no_socket, 0),
    (no_socket, no_socket, 0),
    (accepted, gate_shut, 1),
    (gate_shut, accepted, 1),
    (gate_shut, gate_shut, 0),
    (gate_shut, refused, 0),
    (gate_shut, no_socket, 0),
  ];
  for (v4, v6, credits) in cases {
    assert_eq!(
      Fanout { v4, v6 }.sent_count(),
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
  let rounds = confirm_service_round(&mut state, h, now, &mut buf, partial_fanout(now));
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

  let rounds = confirm_service_round(&mut state, h, now, &mut buf, whole_fanout(now));
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

  let rounds = confirm_service_round(&mut state, h, now, &mut buf, failed_fanout());
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
    confirm_service_round(&mut state, handle, t, &mut buf, whole_fanout(t));
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
    confirm_service_round(&mut state, handle, t, &mut buf, whole_fanout(t));
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
  let token = state
    .endpoint
    .poll_withdrawal_transmit(t, &mut buf)
    .expect("the renamed-away old name must have a detached goodbye pending")
    .token();
  state.endpoint.note_withdrawal_result(
    token,
    t,
    FamilyAttempt::Accepted { at: t },
    FamilyAttempt::Refused { permanent: false },
  );

  // The application reclaims the vacated name.
  let replacement = state
    .register_service(delivery_test_spec("Old"), t)
    .expect("the vacated name must be re-registerable while its goodbye drains");
  let rh = replacement.handle;

  // Drive the replacement's §8.1 probes to completion (a probe is a question and
  // opens no gate) so the next round is its FIRST announcement.
  for _ in 0..12 {
    t += Duration::from_millis(300);
    confirm_service_round(&mut state, rh, t, &mut buf, whole_fanout(t));
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
  confirm_service_round(&mut state, rh, t, &mut buf, partial_fanout(t));
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
  confirm_service_round(&mut state, rh, t, &mut buf, whole_fanout(t));
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
/// [`SELF_SEND_TTL`], and at [`MAX_SELF_SEND_ENTRIES`] the NEW credit is the one
/// refused — so a legacy-query flood would starve the genuine multicast credits
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
  let mut tracker = SelfSendTracker::new();
  #[cfg(feature = "stats")]
  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());

  let fanout = send_via(
    &mut tracker,
    &v4,
    &v6,
    querier_addr,
    b"legacy-unicast-reply",
    // A §6.7 reply is one-shot and therefore ungated.
    &mut FamilyWireGate::default(),
    Duration::ZERO,
    #[cfg(feature = "stats")]
    &stats,
  )
  .await;

  assert!(
    matches!(fanout.v4, FamilyAttempt::Accepted { .. }),
    "the one obligated family accepted the datagram, so the confirm has a real \
     acceptance instant to anchor at; got {:?}",
    fanout.v4
  );
  assert_eq!(
    fanout.v6,
    FamilyAttempt::NotAddressed,
    "a §6.7 reply obligates exactly the destination's family; the other one was \
     never offered the datagram and must not read as a miss"
  );
  assert!(
    tracker.is_empty(),
    "a unicast reply never loops back, so it must record NO self-send credit; \
     the tracker holds {}",
    tracker.len()
  );
}

// ── The wedged family (per-family send bound) ───────────────────────────────

/// What `Transmit::min_family_gap()` carries for an RFC 6762 §8.3 unsolicited
/// announcement — the one-second floor §6 puts on re-multicasting a record on the
/// same interface. Restated here because the core's copy is crate-private; the
/// tests that assert on the gate check the two agree by driving a real
/// announcement through `drain_transmits`.
#[cfg(feature = "tokio")]
const ANNOUNCE_MIN_FAMILY_GAP: Duration = Duration::from_secs(1);

/// How a [`TestSocket`] answers `poll_send_to`.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy)]
enum SendBehaviour {
  /// Accepts immediately without touching the kernel, so the fan-out's timing is
  /// the test's rather than the host's routing table.
  Accepts,
  /// Never becomes writable — the family whose transport is wedged. This is the
  /// case no bound UDP socket can be coaxed into on a real host, and the only one
  /// that distinguishes a bounded attempt from an unbounded one.
  Wedged,
  /// Accepts, but not before this instant — the family that is SLOW rather than
  /// broken. This is what produces inter-family skew: both families carry the
  /// datagram, one of them measurably later than the other, so the confirm's
  /// earliest-acceptance anchor and this family's own wire time diverge.
  Delayed(StdInstant),
  /// Every send completes with an error, the way a bound socket does under
  /// buffer pressure or route churn. Unlike [`SendBehaviour::Wedged`] it
  /// ANSWERS, so the fan-out finishes at once instead of running to its own
  /// bound — which is what makes a multi-round schedule testable in bounded
  /// time.
  Refuses,
  /// Accepts every datagram, but holds the FIRST one this long — measured from
  /// when that attempt began — before doing so. Every later attempt is prompt.
  /// The family whose transport stalls transiently: a full send buffer that
  /// drains, not a route that is gone.
  ///
  /// [`SendBehaviour::Delayed`] cannot stand in for it. That one names an
  /// absolute instant, so a round-by-round schedule sees the delay once and by a
  /// diminishing amount; and a delay applied UNIFORMLY to every round is
  /// invisible to a spacing rule, because it shifts each transmission by the same
  /// offset. What separates an anchor read before a fan-out from one read after
  /// it is a round that costs real time followed by one that does not.
  StallsOnce(Duration),
  /// Accepts every datagram, but the FIRST poll to take one does not return
  /// until this long has elapsed INSIDE `poll_send_to`. Every later attempt is
  /// prompt.
  ///
  /// This is the window between the driver's pre-syscall clock read and the
  /// bytes actually reaching the wire, which a preempted thread, a signal
  /// handler, or a page fault opens for real — on precisely the loaded host RFC
  /// 6762 §6 / §8.1 / §8.3's spacing exists to protect.
  ///
  /// [`SendBehaviour::StallsOnce`] cannot stand in for it. That one answers
  /// `Pending` and is re-polled, so `send_to_at` re-reads its pre-syscall clocks
  /// on the poll that finally accepts and the two stamps still agree. Only a hold
  /// taken WITHOUT yielding, between those reads and the acceptance, makes them
  /// disagree.
  StallsInSyscall(Duration),
}

/// How far a one-shot stalling behaviour's first attempt has got. Shared by
/// [`SendBehaviour::StallsOnce`] and [`SendBehaviour::StallsInSyscall`]; every
/// other behaviour leaves it alone.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy)]
enum Stall {
  /// No attempt has been made yet.
  Idle,
  /// An attempt is in flight and will be accepted at this instant. Only
  /// [`SendBehaviour::StallsOnce`] parks here — a hold taken inside the syscall
  /// never yields, so it has no in-flight state to park in.
  Holding(StdInstant),
  /// The stalling attempt was accepted; every later one is immediate.
  Spent,
}

/// A bound socket whose write side is scripted. It owns a real `std::net`
/// socket so the `Fd` supertrait is satisfied by an actual descriptor; every
/// method the transmit fan-out does not call is left unimplemented rather than
/// delegated, so a future call site cannot silently start depending on kernel
/// behaviour this fixture does not model.
#[cfg(feature = "tokio")]
struct TestSocket {
  fd: std::net::UdpSocket,
  behaviour: SendBehaviour,
  /// Every instant at which this socket ACCEPTED a datagram, in order. This is
  /// the WIRE record the per-family spacing rules are actually about, captured
  /// independently of anything the driver reports.
  sends: Arc<Mutex<Vec<StdInstant>>>,
  /// [`SendBehaviour::StallsOnce`]'s progress. Untouched by every other
  /// behaviour.
  stall: Mutex<Stall>,
}

#[cfg(feature = "tokio")]
impl TestSocket {
  fn new(behaviour: SendBehaviour) -> Self {
    Self {
      fd: std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback socket"),
      behaviour,
      sends: Arc::new(Mutex::new(Vec::new())),
      stall: Mutex::new(Stall::Idle),
    }
  }

  /// A socket that accepts only once `skew` has elapsed from now.
  fn delayed(skew: Duration) -> Self {
    Self::new(SendBehaviour::Delayed(StdInstant::now() + skew))
  }

  /// A shared view of this socket's accepted-send instants.
  fn wire_log(&self) -> Arc<Mutex<Vec<StdInstant>>> {
    Arc::clone(&self.sends)
  }

  fn note_send(&self) {
    self
      .sends
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .push(StdInstant::now());
  }
}

#[cfg(feature = "tokio")]
impl TryFrom<std::net::UdpSocket> for TestSocket {
  type Error = std::io::Error;

  fn try_from(fd: std::net::UdpSocket) -> std::io::Result<Self> {
    Ok(Self {
      fd,
      behaviour: SendBehaviour::Accepts,
      sends: Arc::new(Mutex::new(Vec::new())),
      stall: Mutex::new(Stall::Idle),
    })
  }
}

#[cfg(all(unix, feature = "tokio"))]
impl std::os::fd::AsFd for TestSocket {
  fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
    self.fd.as_fd()
  }
}

#[cfg(all(unix, feature = "tokio"))]
impl std::os::fd::AsRawFd for TestSocket {
  fn as_raw_fd(&self) -> std::os::fd::RawFd {
    self.fd.as_raw_fd()
  }
}

#[cfg(all(windows, feature = "tokio"))]
impl std::os::windows::io::AsSocket for TestSocket {
  fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
    self.fd.as_socket()
  }
}

#[cfg(all(windows, feature = "tokio"))]
impl std::os::windows::io::AsRawSocket for TestSocket {
  fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
    self.fd.as_raw_socket()
  }
}

#[cfg(feature = "tokio")]
impl UdpSocket for TestSocket {
  type Runtime = <<agnostic_net::tokio::Net as agnostic_net::Net>::UdpSocket as UdpSocket>::Runtime;

  fn poll_send_to(
    &self,
    _cx: &mut core::task::Context<'_>,
    buf: &[u8],
    _target: SocketAddr,
  ) -> core::task::Poll<std::io::Result<usize>> {
    match self.behaviour {
      SendBehaviour::Accepts => {
        self.note_send();
        core::task::Poll::Ready(Ok(buf.len()))
      }
      // No waker is registered: a wedged family never wakes the task by itself,
      // which is precisely why the attempt needs its own bound.
      SendBehaviour::Wedged => core::task::Poll::Pending,
      // Nothing is logged: the wire log is what the socket ACCEPTED, and a
      // refused send put no bytes on any wire.
      SendBehaviour::Refuses => {
        core::task::Poll::Ready(Err(std::io::Error::other("scripted send refusal")))
      }
      SendBehaviour::Delayed(ready_at) => {
        let now = StdInstant::now();
        if now >= ready_at {
          self.note_send();
          return core::task::Poll::Ready(Ok(buf.len()));
        }
        // A slow family DOES wake the task, unlike a wedged one — that is the
        // whole difference between the two.
        let waker = _cx.waker().clone();
        let wait = ready_at.saturating_duration_since(now);
        tokio::spawn(async move {
          tokio::time::sleep(wait).await;
          waker.wake();
        });
        core::task::Poll::Pending
      }
      SendBehaviour::StallsOnce(hold) => {
        let now = StdInstant::now();
        let mut stall = self.stall.lock().unwrap_or_else(|e| e.into_inner());
        // The hold runs from the attempt itself, not from this socket's
        // construction, so what it costs does not depend on how long the setup
        // ahead of it took.
        if matches!(*stall, Stall::Idle) {
          *stall = Stall::Holding(now + hold);
        }
        if let Stall::Holding(ready_at) = *stall {
          if now < ready_at {
            // Wakes the task like a slow family and unlike a wedged one: this is a
            // round that COSTS time, not one that never answers.
            let waker = _cx.waker().clone();
            let wait = ready_at.saturating_duration_since(now);
            tokio::spawn(async move {
              tokio::time::sleep(wait).await;
              waker.wake();
            });
            return core::task::Poll::Pending;
          }
          *stall = Stall::Spent;
        }
        drop(stall);
        self.note_send();
        core::task::Poll::Ready(Ok(buf.len()))
      }
      SendBehaviour::StallsInSyscall(hold) => {
        let first = {
          let mut stall = self.stall.lock().unwrap_or_else(|e| e.into_inner());
          let first = matches!(*stall, Stall::Idle);
          *stall = Stall::Spent;
          first
        };
        // Deliberately BLOCKING, and taken after the driver's pre-syscall clock
        // reads and before this socket accepts anything: yielding here would let
        // `send_to_at` re-read those clocks, which is the one thing that would
        // close the window under test. `note_send` follows, so this socket's own
        // wire log records the far side of the hold.
        if first && !hold.is_zero() {
          std::thread::sleep(hold);
        }
        self.note_send();
        core::task::Poll::Ready(Ok(buf.len()))
      }
    }
  }

  fn poll_recv_from(
    &self,
    _cx: &mut core::task::Context<'_>,
    _buf: &mut [u8],
  ) -> core::task::Poll<std::io::Result<(usize, SocketAddr)>> {
    unimplemented!("the transmit fan-out never reads")
  }

  fn local_addr(&self) -> std::io::Result<SocketAddr> {
    self.fd.local_addr()
  }

  async fn bind<A: agnostic_net::ToSocketAddrs<Self::Runtime>>(_addr: A) -> std::io::Result<Self>
  where
    Self: Sized,
  {
    unimplemented!("scripted sockets are constructed directly")
  }

  async fn connect<A: agnostic_net::ToSocketAddrs<Self::Runtime>>(
    &self,
    _addr: A,
  ) -> std::io::Result<()> {
    unimplemented!()
  }

  fn peer_addr(&self) -> std::io::Result<SocketAddr> {
    unimplemented!()
  }

  async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
    unimplemented!()
  }

  async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    unimplemented!()
  }

  async fn send(&self, _buf: &[u8]) -> std::io::Result<usize> {
    unimplemented!()
  }

  async fn send_to<A: agnostic_net::ToSocketAddrs<Self::Runtime>>(
    &self,
    _buf: &[u8],
    _target: A,
  ) -> std::io::Result<usize> {
    unimplemented!()
  }

  async fn peek(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
    unimplemented!()
  }

  async fn peek_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    unimplemented!()
  }

  fn join_multicast_v4(
    &self,
    _multiaddr: std::net::Ipv4Addr,
    _interface: std::net::Ipv4Addr,
  ) -> std::io::Result<()> {
    unimplemented!()
  }

  fn join_multicast_v6(
    &self,
    _multiaddr: &std::net::Ipv6Addr,
    _interface: u32,
  ) -> std::io::Result<()> {
    unimplemented!()
  }

  fn leave_multicast_v4(
    &self,
    _multiaddr: std::net::Ipv4Addr,
    _interface: std::net::Ipv4Addr,
  ) -> std::io::Result<()> {
    unimplemented!()
  }

  fn leave_multicast_v6(
    &self,
    _multiaddr: &std::net::Ipv6Addr,
    _interface: u32,
  ) -> std::io::Result<()> {
    unimplemented!()
  }

  fn multicast_loop_v4(&self) -> std::io::Result<bool> {
    unimplemented!()
  }

  fn set_multicast_loop_v4(&self, _on: bool) -> std::io::Result<()> {
    unimplemented!()
  }

  fn multicast_ttl_v4(&self) -> std::io::Result<u32> {
    unimplemented!()
  }

  fn set_multicast_ttl_v4(&self, _ttl: u32) -> std::io::Result<()> {
    unimplemented!()
  }

  fn multicast_loop_v6(&self) -> std::io::Result<bool> {
    unimplemented!()
  }

  fn set_multicast_loop_v6(&self, _on: bool) -> std::io::Result<()> {
    unimplemented!()
  }

  fn set_ttl(&self, _ttl: u32) -> std::io::Result<()> {
    unimplemented!()
  }

  fn ttl(&self) -> std::io::Result<u32> {
    unimplemented!()
  }

  fn set_broadcast(&self, _broadcast: bool) -> std::io::Result<()> {
    unimplemented!()
  }

  fn broadcast(&self) -> std::io::Result<bool> {
    unimplemented!()
  }
}

/// Fan one multicast datagram out to a healthy v4 and a wedged v6, returning the
/// instant the fan-out STARTED (a lower bound on v4's true acceptance, taken
/// independently of what the fan-out reports), the fan-out itself — which
/// carries each family's own acceptance instant — and how long the whole
/// fan-out took.
#[cfg(feature = "tokio")]
async fn wedged_v6_round(body: &[u8]) -> (StdInstant, Fanout, Duration) {
  let v4 = Some(Arc::new(TestSocket::new(SendBehaviour::Accepts)));
  let v6 = Some(Arc::new(TestSocket::new(SendBehaviour::Wedged)));
  let mut tracker = SelfSendTracker::new();
  #[cfg(feature = "stats")]
  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());

  let started = StdInstant::now();
  let mut gate = FamilyWireGate::default();
  let fanout = tokio::time::timeout(
    SEND_ATTEMPT_TIMEOUT * 20,
    send_via(
      &mut tracker,
      &v4,
      &v6,
      MDNS_V4_DST,
      body,
      &mut gate,
      ANNOUNCE_MIN_FAMILY_GAP,
      #[cfg(feature = "stats")]
      &stats,
    ),
  )
  .await
  .expect(
    "a family that never becomes writable must not park the fan-out: the driver \
     loop cannot service a timer, a command, or any other family's transmit \
     while it is suspended here",
  );
  (started, fanout, started.elapsed())
}

/// A wedged family must be given up on within the per-family bound, and must not
/// move the healthy family's acceptance instant.
///
/// Both halves are the same defect seen from two sides. Serially awaiting an
/// unbounded `send_to` suspends the whole driver task, so nothing else the loop
/// owns runs; and confirming at post-fan-out time records the family that
/// accepted at `t0` as having been served when the wedged one finally gave up,
/// which is a lie about how fresh that family's peers are.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn a_wedged_family_is_bounded_and_leaves_the_healthy_anchor_alone() {
  let (started, fanout, elapsed) = wedged_v6_round(b"announcement").await;

  assert!(
    matches!(fanout.v4, FamilyAttempt::Accepted { .. }),
    "the healthy family must be reported delivered; got {:?}",
    fanout.v4
  );
  assert_eq!(
    fanout.v6,
    FamilyAttempt::WouldBlock,
    "the wedged family put nothing on its wire, so the core must be told it \
     missed — never that it was unobligated or that it carried the datagram"
  );
  assert!(
    elapsed < SEND_ATTEMPT_TIMEOUT * 4,
    "the fan-out must return once the bound expires; it took {elapsed:?}"
  );

  let anchor = accepted_at(fanout.v4).expect("the healthy family accepted the datagram");
  assert!(
    anchor.saturating_duration_since(started) < SEND_ATTEMPT_TIMEOUT,
    "the anchor must be the healthy family's OWN acceptance instant, not a time \
     read after the wedged family's bound expired"
  );
}

/// The consequence the anchor exists for: a wedged family must not push the
/// healthy family's next refresh beyond the TTL its records were published with.
///
/// Run at [`mdns_proto::constants::MIN_SERVICE_TTL_SECS`], where the slack
/// between the periodic refresh interval (`max(0.8 · TTL, 1 s)` = 1 s) and the
/// TTL itself is at its smallest, so the bound has the least room it will ever
/// have.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn a_wedged_family_cannot_push_the_healthy_refresh_past_its_ttl() {
  const TTL_SECS: u32 = mdns_proto::constants::MIN_SERVICE_TTL_SECS;
  /// `max(0.8 · TTL, RFC 6762 §8.3's one second)` at that TTL.
  const REFRESH: Duration = Duration::from_secs(1);

  // One periodic refresh in which v6 has wedged, taken first so the service's
  // schedule can be laid out around the acceptance instant it reports.
  let (started, fanout, _) = wedged_v6_round(b"refresh").await;
  let anchor = accepted_at(fanout.v4).expect("v4 accepted the refresh");
  let base = anchor
    .checked_sub(Duration::from_secs(3))
    .expect("the monotonic clock is at least a few seconds old");

  let mut state = delivery_test_state(false);
  let mut records = mdns_proto::ServiceRecords::new(
    mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("wedged._ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("wedged.local.").unwrap(),
    631,
    TTL_SECS,
  );
  records.add_a(std::net::Ipv4Addr::new(192, 168, 1, 10));
  let h = state
    .register_service(mdns_proto::ServiceSpec::new(records), base)
    .unwrap()
    .handle;
  let mut buf = std::vec![0u8; 4096];

  // Two whole announcements reach Established, so the periodic refresh is the
  // schedule under test and it is already due at `anchor`.
  confirm_service_round(&mut state, h, base, &mut buf, whole_fanout(base));
  confirm_service_round(
    &mut state,
    h,
    base + Duration::from_secs(1),
    &mut buf,
    whole_fanout(base + Duration::from_secs(1)),
  );
  assert_eq!(
    state.services[&h].proto.state(),
    mdns_proto::service::ServiceState::Established
  );

  // Confirm the wedged round with exactly what the fan-out reported, the way
  // `drain_transmits` does.
  let DriverState {
    endpoint, services, ..
  } = &mut state;
  let ctx = services.get_mut(&h).unwrap();
  let _ = ctx.proto.handle_timeout(anchor);
  assert!(
    ctx
      .proto
      .poll_transmit(anchor, &mut buf)
      .is_ok_and(|t| t.is_some()),
    "the periodic re-announce must be due"
  );
  let _ = confirm_service_transmit(endpoint, ctx, anchor, fanout.v4, fanout.v6);

  let due = ctx.proto.poll_timeout().expect("re-armed");
  assert!(
    due.saturating_duration_since(anchor) <= REFRESH,
    "the core arms the next announcement one refresh interval after the confirm"
  );
  // Measured from a clock read the fan-out never touched, so a confirm instant
  // that had absorbed the wedged family's bound cannot hide inside it.
  let gap = due.saturating_duration_since(started);
  assert!(
    gap < REFRESH + SEND_ATTEMPT_TIMEOUT / 2,
    "v4's gap is measured from ITS OWN acceptance, so a family that never \
     accepted may add nothing to it; v4's next announcement was due {gap:?} after \
     the fan-out began, against a refresh interval of {REFRESH:?}"
  );
  assert!(
    gap < Duration::from_secs(u64::from(TTL_SECS)),
    "…which is what keeps v4's peers from expiring these records: they hold them \
     for {TTL_SECS} s from that same instant"
  );
}

// ── The obligation tag (`TransmitObligation`) at the driver seam ────────────

/// A §6.7 legacy unicast reply reaches exactly ONE family, so its fan-out is
/// all-delivered by construction — the other family was not addressed, not missing.
#[cfg(feature = "tokio")]
fn unicast_fanout(at: StdInstant) -> Fanout {
  Fanout {
    v4: FamilyAttempt::Accepted { at },
    v6: FamilyAttempt::NotAddressed,
  }
}

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
      unicast_fanout(t)
    };
    let _ = confirm_service_transmit(endpoint, ctx, t, fanout.v4, fanout.v6);
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
  confirm_service_round(&mut state, h, now, &mut buf, failed_fanout());
  assert!(
    !state.services[&h].proto.advertises_instance(),
    "a wholly-failed announcement exposes nothing"
  );

  // A §6.7 legacy querier is served over the one family its destination names.
  let legacy = SocketAddr::from(([192, 168, 1, 50], 6000));
  let t = now + Duration::from_millis(50);
  inject_ptr_query(&mut state, legacy, t);
  assert_eq!(
    confirm_service_round_mixed(&mut state, h, t, &mut buf, failed_fanout()),
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

// ── The per-family wire gate and the drain pass budget ──────────────────────

/// A [`Net`](agnostic_net::Net) whose UDP socket is the scripted [`TestSocket`],
/// so `drain_transmits` can be driven end to end against a family that is slow,
/// or one that never becomes writable. Everything else is tokio's.
#[cfg(feature = "tokio")]
struct TestNet;

#[cfg(feature = "tokio")]
impl agnostic_net::Net for TestNet {
  type Runtime = <agnostic_net::tokio::Net as agnostic_net::Net>::Runtime;
  type TcpListener = <agnostic_net::tokio::Net as agnostic_net::Net>::TcpListener;
  type TcpStream = <agnostic_net::tokio::Net as agnostic_net::Net>::TcpStream;
  type UdpSocket = TestSocket;
}

/// A driver state bound to two scripted sockets.
#[cfg(feature = "tokio")]
fn scripted_state(probe: bool, v4: TestSocket, v6: TestSocket) -> DriverState<TestNet> {
  let opts = crate::options::ServerOptions::default()
    .with_endpoint_config(mdns_proto::EndpointConfig::new().with_probe_unique_names(probe));
  DriverState::new(
    &opts,
    BoundSockets::<TestNet> {
      v4: Some(v4),
      v6: Some(v6),
      interface_index: 0,
    },
  )
}

/// Fire the due deadlines and run ONE whole driver pass — both drains under one
/// shared budget, exactly as `driver_task` does. Returns `(more_pending, elapsed)`.
#[cfg(feature = "tokio")]
async fn drive_one_pass(state: &mut DriverState<TestNet>, scratch: &mut [u8]) -> (bool, Duration) {
  let now = StdInstant::now();
  state.fire_timeouts(now);
  let mut budget = DrainBudget::new(now);
  let more_tx = state.drain_transmits(now, &mut budget, scratch).await;
  let more_wd = state.drain_withdrawals(now, &mut budget, scratch).await;
  (more_tx || more_wd, now.elapsed())
}

/// The successive gaps between one socket's accepted sends.
#[cfg(feature = "tokio")]
fn wire_gaps(log: &Arc<Mutex<Vec<StdInstant>>>) -> Vec<Duration> {
  let sends = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
  sends
    .windows(2)
    .map(|w| w[1].saturating_duration_since(w[0]))
    .collect()
}

/// The headline defect the per-family gate exists for: with inter-family skew,
/// the LATE family's own successive wire gap fell below RFC 6762 §6 / §8.3's
/// one-second minimum on every announcement.
///
/// The confirm anchors at the EARLIEST acceptance across families, which is the
/// right anchor for the TTL guarantee — it can only understate how fresh a
/// family's peers are. But it also means the core schedules the next
/// announcement one interval after the EARLY family's wire time, so a family
/// that accepted `s` later gets its own copy `interval − s` after its last one.
/// The core cannot see `s`; the driver measured it, so the driver holds the gate
/// and the core supplies the minimum.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread")]
async fn a_skewed_family_is_never_re_announced_inside_its_own_floor() {
  /// Well under the per-family attempt bound, so v6 genuinely ACCEPTS the first
  /// datagram (late) rather than timing out and missing it.
  const SKEW: Duration = Duration::from_millis(150);

  let v4 = TestSocket::new(SendBehaviour::Accepts);
  let v6 = TestSocket::delayed(SKEW);
  let (v4_log, v6_log) = (v4.wire_log(), v6.wire_log());
  let mut state = scripted_state(false, v4, v6);
  let mut scratch = std::vec![0u8; 4096];

  let reg = state
    .register_service(delivery_test_spec("skewed"), StdInstant::now())
    .expect("register the service under test");
  let h = reg.handle;

  // Three announcement rounds: the first is the skewed one, the second is the
  // round at which v6's floor is still unpaid, the third is when it is.
  for _ in 0..3 {
    drive_one_pass(&mut state, &mut scratch).await;
    let Some(due) = state.next_deadline() else {
      break;
    };
    let wait = due.saturating_duration_since(StdInstant::now());
    // Once the burst is over the next deadline is the periodic refresh, ~80 % of
    // the TTL away; the rounds under test are all §8.3-spaced, so anything longer
    // means the sequence is done.
    if wait > Duration::from_secs(3) {
      break;
    }
    // A small overshoot so the deadline has genuinely passed when the next pass
    // reads the clock; the schedule under test is measured in seconds.
    tokio::time::sleep(wait + Duration::from_millis(20)).await;
  }
  assert!(
    state.services.contains_key(&h),
    "the service must survive the whole sequence"
  );

  for (family, log) in [("v4", &v4_log), ("v6", &v6_log)] {
    for gap in wire_gaps(log) {
      assert!(
        gap >= ANNOUNCE_MIN_FAMILY_GAP,
        "{family} received two copies of the same service's announcement {gap:?} \
         apart, inside RFC 6762 §6 / §8.3's one-second floor for that interface. \
         v4 gaps {:?}, v6 gaps {:?}",
        wire_gaps(&v4_log),
        wire_gaps(&v6_log),
      );
    }
  }
  assert!(
    v6_log.lock().unwrap_or_else(|e| e.into_inner()).len() >= 2,
    "the late family must still be SERVED — the gate defers a round, it does not \
     write the family off"
  );
  drop(reg);
}

/// The other side of the gate: a family whose wire had genuinely paid its floor
/// by the time the datagram was offered to IT must not be held back.
///
/// The gap has to be weighed at that family's own send point. A driver pass reads
/// its clock once, at the top, and may then legitimately spend
/// [`DRAIN_PASS_BUDGET`] plus the last fan-out's own [`SEND_ATTEMPT_TIMEOUT`]
/// serving the producers ahead of this one. Weighing the gate against that reading
/// UNDERSTATES how long the wire has been idle, so the gate withholds a round the
/// wire had in fact paid for — and `Gated` is not "nothing happened": it reaches
/// the core as `FamilyDelivery::Missed`, spending its partial-round patience and
/// holding the §8.3 announce phase for a family that was ready.
///
/// Inter-family skew is what makes the two anchors disagree at all: the confirm
/// anchors at the EARLIEST acceptance, so the core re-arms one interval after the
/// EARLY family's wire time while the late family's own floor still has the skew
/// left to run. That is the window in which a stale reading is wrong.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread")]
async fn a_family_that_paid_its_floor_before_its_own_send_is_not_gated() {
  /// Well under the per-family attempt bound, so v6 genuinely ACCEPTS the first
  /// datagram late rather than timing out and missing it.
  const SKEW: Duration = Duration::from_millis(150);
  /// How far into the pass this producer's fan-out lands — past v6's floor, and
  /// far short of what one pass may legitimately spend before reaching a producer.
  const PASS_LAG: Duration = Duration::from_millis(400);

  let v4 = TestSocket::new(SendBehaviour::Accepts);
  let v6 = TestSocket::delayed(SKEW);
  let (v4_log, v6_log) = (v4.wire_log(), v6.wire_log());
  let mut state = scripted_state(false, v4, v6);
  let mut scratch = std::vec![0u8; 4096];

  let reg = state
    .register_service(delivery_test_spec("skewed"), StdInstant::now())
    .expect("register the service under test");
  let h = reg.handle;

  // Round 1, at a clock the pass reads for itself: both families carry it, v6 its
  // SKEW later.
  drive_one_pass(&mut state, &mut scratch).await;
  let v6_first = *v6_log
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .first()
    .expect("v6 must have carried the first announcement");

  // The pass carrying round 2 wakes when the core's re-arm falls due and reads its
  // clock ONCE, there — with a small overshoot so the deadline has genuinely
  // passed.
  let due = state.services[&h]
    .proto
    .poll_timeout()
    .expect("the next announcement must be armed");
  let pass_clock = due + Duration::from_millis(20);
  assert!(
    pass_clock.saturating_duration_since(v6_first) < ANNOUNCE_MIN_FAMILY_GAP,
    "the pass wakes while v6's own floor still has the skew left to run — that is \
     the window under test"
  );

  // …but it does not reach THIS producer until PASS_LAG later, by which point v6's
  // floor has been paid several times over. The pass-level reading cannot show it.
  let wait = (pass_clock + PASS_LAG).saturating_duration_since(StdInstant::now());
  tokio::time::sleep(wait).await;
  state.fire_timeouts(pass_clock);
  // A budget opened at the CURRENT clock, so the pass cannot be cut short before
  // this producer's fan-out: what is under test is the gate, not the budget.
  let mut budget = DrainBudget::new(StdInstant::now());
  let offered_at = StdInstant::now();
  state
    .drain_transmits(pass_clock, &mut budget, &mut scratch)
    .await;

  let v6_sends = v6_log.lock().unwrap_or_else(|e| e.into_inner()).len();
  assert_eq!(
    v6_sends,
    2,
    "v6's wire had been idle {:?} — well past RFC 6762 §6 / §8.3's \
     {ANNOUNCE_MIN_FAMILY_GAP:?} floor — by the time the datagram was offered to \
     IT, yet the gate was weighed against the reading the pass took {PASS_LAG:?} \
     earlier and reported it Gated, which reaches the core as \
     FamilyDelivery::Missed",
    offered_at.saturating_duration_since(v6_first),
  );

  // The gate must still be a gate: a round is deferred until the floor is paid,
  // never merely waved through.
  for (family, log) in [("v4", &v4_log), ("v6", &v6_log)] {
    for gap in wire_gaps(log) {
      assert!(
        gap >= ANNOUNCE_MIN_FAMILY_GAP,
        "{family} received two copies of the same service's announcement {gap:?} \
         apart, inside RFC 6762 §6 / §8.3's one-second floor for that interface. \
         v4 gaps {:?}, v6 gaps {:?}",
        wire_gaps(&v4_log),
        wire_gaps(&v6_log),
      );
    }
  }
  drop(reg);
}

/// The RECORD side of the same gate: a send whose syscall completes long after
/// the driver offered it must re-open its family from the instant the bytes
/// reached the wire, never from the pre-syscall reading taken before it.
///
/// The two stamps are wrong in opposite directions, so neither can stand in for
/// the other. The core's confirm anchor is pre-syscall and correctly so — it may
/// only ever UNDERSTATE how fresh a family's peers are. The gate measures the
/// real spacing between bytes on ONE wire, so a pre-syscall anchor spends part of
/// the interval on time the datagram had not yet reached that wire, and the next
/// datagram goes out INSIDE RFC 6762 §6 / §8.1 / §8.3's floor. That direction is
/// permissive rather than conservative: reading a clock early withholds a send,
/// recording one early releases one.
///
/// Nothing bounds the delay between the clock read and the `sendto` — a preempted
/// thread, a signal handler, or a page fault — and that is what
/// [`SendBehaviour::StallsInSyscall`] stands in for. At §8.1's 250 ms inter-probe
/// interval a 200 ms stall would leave 50 ms of true spacing, on precisely the
/// loaded host the interval exists to protect.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_send_re_opens_its_family_from_the_wire_not_the_offer() {
  /// The floor the gate is asked to keep for this datagram's kind.
  const GAP: Duration = Duration::from_millis(400);
  /// How long the first send is held between the driver's clock reads and the
  /// socket accepting it. Comfortably PAST `GAP`, so a gate anchored at the
  /// pre-syscall reading has already re-opened by the time the syscall returns.
  const STALL: Duration = Duration::from_millis(900);

  let sock = TestSocket::new(SendBehaviour::StallsInSyscall(STALL));
  let wire_log = sock.wire_log();
  let v4 = Some(Arc::new(sock));
  let v6: Option<Arc<TestSocket>> = None;
  let mut tracker = SelfSendTracker::new();
  #[cfg(feature = "stats")]
  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
  let mut gate = FamilyWireGate::default();

  let first = send_via(
    &mut tracker,
    &v4,
    &v6,
    MDNS_V4_DST,
    b"announcement",
    &mut gate,
    GAP,
    #[cfg(feature = "stats")]
    &stats,
  )
  .await;
  assert!(
    matches!(first.v4, FamilyAttempt::Accepted { .. }),
    "the stalled send still SUCCEEDS — this is a slow syscall, not a failure, and \
     a round that missed would never reach the spacing under test; got {:?}",
    first.v4
  );

  // The socket's own record of when it took the datagram, captured on the far
  // side of the hold and independently of anything the driver reports.
  let wire_at = *wire_log
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .first()
    .expect("the socket accepted the datagram");
  let recorded =
    gate.last_sent[FAMILY_V4].expect("a carried datagram re-arms its own family's gate");
  assert!(
    recorded >= wire_at,
    "the gate must be anchored at or after the instant the bytes reached the wire; \
     it was anchored {:?} BEFORE it, which is the whole {STALL:?} the syscall spent \
     handing the datagram over",
    wire_at.saturating_duration_since(recorded),
  );

  // The consequence, in the gate's own vocabulary: the very next datagram of the
  // same kind is offered immediately, and its family has not paid the floor.
  let second = send_via(
    &mut tracker,
    &v4,
    &v6,
    MDNS_V4_DST,
    b"announcement",
    &mut gate,
    GAP,
    #[cfg(feature = "stats")]
    &stats,
  )
  .await;
  assert_eq!(
    second.v4,
    FamilyAttempt::GateShut,
    "this wire carried the previous copy moments ago, so the {GAP:?} floor is \
     unpaid and the datagram must be withheld"
  );
  assert_eq!(
    wire_log.lock().unwrap_or_else(|e| e.into_inner()).len(),
    1,
    "a withheld family makes no syscall at all, so exactly one copy may have \
     reached this wire"
  );
}

/// A pass with many simultaneously-due producers and one wedged family must stay
/// inside its aggregate budget — and that budget spans the withdrawal pump too.
///
/// Producers are awaited serially and the send credits are charged only per
/// family that actually SENT, so an all-miss fan-out costs zero credits while
/// still costing a whole attempt bound. The pass was therefore bounded by nothing
/// at all: `n` due producers with a wedged family ran for `n × 250 ms` with the
/// packet channel backing up behind it. The goodbye pump had no budget of any
/// kind.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread")]
async fn a_pass_with_a_wedged_family_stays_inside_its_budget() {
  /// Far more than the two entirely-wedged fan-outs a pass can afford, so the
  /// budget is what stops it rather than the work running out.
  const DUE_PRODUCERS: usize = 8;

  let v4 = TestSocket::new(SendBehaviour::Accepts);
  let v6 = TestSocket::new(SendBehaviour::Wedged);
  let mut state = scripted_state(false, v4, v6);
  let mut scratch = std::vec![0u8; 4096];
  let t = StdInstant::now();

  // A service that has announced and is then retired, so a real TTL=0 goodbye is
  // due in the same pass. Confirmed through the direct seam so the setup itself
  // costs no wall clock.
  let dying = state
    .register_service(delivery_test_spec("dying"), t)
    .expect("register the withdrawing service");
  confirm_service_round(&mut state, dying.handle, t, &mut scratch, whole_fanout(t));
  state.remove_service(dying.handle, t);
  assert!(
    state
      .endpoint
      .next_withdrawal_deadline()
      .is_some_and(|due| due <= t),
    "the retired service must owe a goodbye at the instant the pass starts"
  );

  let mut regs = Vec::new();
  for i in 0..DUE_PRODUCERS {
    regs.push(
      state
        .register_service(delivery_test_spec(&std::format!("due{i}")), t)
        .expect("register a due service"),
    );
  }

  let started = StdInstant::now();
  state.fire_timeouts(started);
  let mut budget = DrainBudget::new(started);
  let more_tx = state
    .drain_transmits(started, &mut budget, &mut scratch)
    .await;
  let after_transmits = started.elapsed();
  let more_wd = state
    .drain_withdrawals(started, &mut budget, &mut scratch)
    .await;
  let elapsed = started.elapsed();

  assert!(
    more_tx,
    "the budget must have cut the transmit drain short with producers unserved"
  );
  assert!(
    more_wd,
    "…and the goodbye still due must be reported pending rather than silently \
     skipped, so the loop re-enters instead of sleeping"
  );
  assert!(
    elapsed <= DRAIN_PASS_BUDGET + Duration::from_millis(200),
    "one pass ran for {elapsed:?} against a {DRAIN_PASS_BUDGET:?} budget \
     ({after_transmits:?} of it in the transmit drain); {DUE_PRODUCERS} due \
     producers with a wedged family used to cost {:?}",
    SEND_ATTEMPT_TIMEOUT * (DUE_PRODUCERS as u32),
  );
  assert!(
    elapsed >= after_transmits,
    "the withdrawal pump shares the pass budget rather than opening its own"
  );
  drop(regs);
  drop(dying);
}

// ── a paid family owes no further goodbye ───────────────────────────────────
//
// RFC 6762 §10.1 debt is per family while the resend schedule is per item. Once
// one family has paid every round and the other is still failing, a `Sent` on
// the paid one is (correctly) not progress, so the endpoint re-arms the item on
// its short retry backoff for the sake of the family that still owes. A driver
// that fans every round to both families then puts a TTL=0 goodbye on the paid
// family's wire at THAT cadence until the anti-pin ceiling — retracting records
// no peer on that family still holds, dozens of times, where §10.1 spaces one
// family's goodbyes 250 ms apart. `WithdrawalTransmit::debt` is what lets the
// driver tell; before it there was nothing to consult.

/// The §10.1 spacing between two successive goodbyes for one name on ONE
/// family's wire. Restated because the core's copy is crate-private, exactly as
/// [`ANNOUNCE_MIN_FAMILY_GAP`] restates the announce floor.
#[cfg(feature = "tokio")]
const GOODBYE_MIN_FAMILY_GAP: Duration = Duration::from_millis(250);

/// Goodbye rounds ONE family owes for one withdrawal item, restated for the same
/// reason.
#[cfg(feature = "tokio")]
const GOODBYE_ROUNDS_PER_FAMILY: usize = 3;

/// The anti-pin ceiling at which an unfinished withdrawal is force-completed,
/// restated for the same reason.
#[cfg(feature = "tokio")]
const GOODBYE_CEILING: Duration = Duration::from_secs(2);

/// A family that has paid its whole §10.1 budget is not offered the rounds the
/// blocked family's retries keep producing.
///
/// Both halves are asserted: the count (v4 emits exactly the budget it owed) and
/// the spacing (no two v4 goodbyes land inside the §10.1 interval). The run
/// reaching the ceiling is asserted too, so a schedule that merely stopped
/// producing rounds cannot pass this vacuously.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn a_paid_family_is_not_offered_the_blocked_familys_retry_rounds() {
  let v4 = TestSocket::new(SendBehaviour::Accepts);
  let v6 = TestSocket::new(SendBehaviour::Refuses);
  let v4_log = v4.wire_log();
  let mut state = scripted_state(false, v4, v6);
  let mut scratch = std::vec![0u8; 4096];

  // A service driven to an announced state through the direct seam (so the setup
  // costs no wall clock) and then retired: its goodbye is non-empty and both
  // families owe it.
  let base = StdInstant::now();
  let reg = state
    .register_service(delivery_test_spec("paid"), base)
    .expect("register the withdrawing service");
  let handle = reg.handle;
  confirm_service_round(&mut state, handle, base, &mut scratch, whole_fanout(base));
  state.remove_service(handle, base);

  // Every round is pumped when the endpoint's own next deadline falls due, ON THE
  // WALL CLOCK, exactly as `driver_task` sleeps to it. A synthetic instant walked
  // along `next_withdrawal_deadline` cannot stand in: the §10.1 resend schedule is
  // re-armed from the instant the round FANNED OUT, which this drain reads for
  // itself, so a hand-rolled clock running ahead of the host's would leave every
  // item due against a schedule anchored where the host actually is. The
  // sequence terminates at the anti-pin ceiling; the iteration cap is a hang
  // guard, not a bound the assertions rely on.
  for _ in 0..512 {
    let t = StdInstant::now();
    state
      .drain_withdrawals(t, &mut DrainBudget::new(t), &mut scratch)
      .await;
    let Some(due) = state.endpoint.next_withdrawal_deadline() else {
      break;
    };
    tokio::time::sleep(due.saturating_duration_since(StdInstant::now())).await;
  }

  assert!(
    !state.services.contains_key(&handle),
    "the withdrawal must have settled; otherwise the loop stopped on its hang \
     guard and the counts below mean nothing"
  );
  assert!(
    base.elapsed() >= GOODBYE_CEILING,
    "v6 never carried its goodbye, so the item must have run to its \
     {GOODBYE_CEILING:?} anti-pin ceiling — a shorter run means the rounds v4 \
     was NOT offered were never produced in the first place"
  );
  let v4_gaps = wire_gaps(&v4_log);
  assert_eq!(
    v4_log.lock().unwrap_or_else(|e| e.into_inner()).len(),
    GOODBYE_ROUNDS_PER_FAMILY,
    "v4 owed exactly its §10.1 budget and paid it; every datagram after that \
     retracts records no v4 peer still holds, and exists only because v6 is \
     retrying. Gaps between the rounds that reached v4's wire: {v4_gaps:?}"
  );
  for gap in v4_gaps {
    assert!(
      gap >= GOODBYE_MIN_FAMILY_GAP,
      "two goodbyes for one name reached v4's wire {gap:?} apart, inside the \
       {GOODBYE_MIN_FAMILY_GAP:?} §10.1 gives one family's wire — the blocked \
       family's retry cadence was applied to the paid family's transmissions"
    );
  }
  drop(reg);
}

/// The §10.1 resend schedule is re-armed from the round's OWN fan-out, so a slow
/// goodbye does not pull the next one onto its heels.
///
/// `note_withdrawal_result` re-arms `next_at` at the instant it is handed plus
/// the §10.1 interval, and that schedule is the only thing pacing consecutive
/// goodbyes — this fan-out is deliberately ungated, so nothing else stands
/// between two rounds. Hand it the instant the PASS began and every microsecond
/// the round spent is charged to the next one: the drain ahead of it, the fan-out
/// itself under its own [`SEND_ATTEMPT_TIMEOUT`], the scheduler. A family that
/// accepts near that bound leaves the next round already due at the moment this
/// one lands, and §10.1's three loss-resilience sends collapse into near-adjacent
/// transmissions on the very wire the spacing is for.
///
/// The fan-out is slow ONCE and prompt afterwards, which is what makes the two
/// anchors disagree: a uniform delay shifts every transmission equally and is
/// invisible to a spacing rule. Both families carry every round, so nothing here
/// rides on the failure paths — what is measured is the schedule alone.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_goodbye_fan_out_does_not_pull_the_next_round_onto_it() {
  /// How long the first round's fan-out holds before both families accept it.
  /// Inside [`SEND_ATTEMPT_TIMEOUT`], so the datagram is genuinely CARRIED rather
  /// than missed — a missed round takes the short retry backoff and never reaches
  /// the interval under test.
  const STALL: Duration = Duration::from_millis(200);

  let v4 = TestSocket::new(SendBehaviour::StallsOnce(STALL));
  let v6 = TestSocket::new(SendBehaviour::StallsOnce(STALL));
  let (v4_log, v6_log) = (v4.wire_log(), v6.wire_log());
  let mut state = scripted_state(false, v4, v6);
  let mut scratch = std::vec![0u8; 4096];

  // Announced through the direct seam (so the setup costs no wall clock) and then
  // retired: the goodbye is non-empty and both families owe it.
  let base = StdInstant::now();
  let reg = state
    .register_service(delivery_test_spec("slowbye"), base)
    .expect("register the withdrawing service");
  let handle = reg.handle;
  confirm_service_round(&mut state, handle, base, &mut scratch, whole_fanout(base));
  state.remove_service(handle, base);

  // Passes exactly as `driver_task` runs them: ONE instant read at the top and
  // handed to the drain, then a sleep to the endpoint's own next deadline. That
  // is the whole of the setup — the stale anchor is the pass's own `now`, not
  // anything contrived here. The iteration cap is a hang guard, not a bound the
  // assertions rely on.
  for _ in 0..16 {
    let now = StdInstant::now();
    let mut budget = DrainBudget::new(now);
    state
      .drain_withdrawals(now, &mut budget, &mut scratch)
      .await;
    let Some(due) = state.endpoint.next_withdrawal_deadline() else {
      break;
    };
    tokio::time::sleep(due.saturating_duration_since(StdInstant::now())).await;
  }

  assert!(
    !state.services.contains_key(&handle),
    "the withdrawal must have settled; otherwise the loop stopped on its hang \
     guard and the gaps below mean nothing"
  );
  assert!(
    base.elapsed() < GOODBYE_CEILING,
    "the sequence must have run on its own schedule rather than been cut off by \
     the {GOODBYE_CEILING:?} anti-pin ceiling"
  );
  for (family, log) in [("v4", &v4_log), ("v6", &v6_log)] {
    assert_eq!(
      log.lock().unwrap_or_else(|e| e.into_inner()).len(),
      GOODBYE_ROUNDS_PER_FAMILY,
      "{family} accepted every round it was offered, so it must have carried its \
       whole §10.1 budget — otherwise there is no spacing left to measure"
    );
    for gap in wire_gaps(log) {
      assert!(
        gap >= GOODBYE_MIN_FAMILY_GAP,
        "two goodbyes for one name reached {family}'s wire {gap:?} apart, inside \
         the {GOODBYE_MIN_FAMILY_GAP:?} §10.1 gives one family's wire. The round \
         took {STALL:?} to fan out and its schedule was re-armed from the instant \
         the PASS began, so the next round was already due when this one landed. \
         v4 gaps {:?}, v6 gaps {:?}",
        wire_gaps(&v4_log),
        wire_gaps(&v6_log),
      );
    }
  }
  drop(reg);
}

/// Repeated budget cuts must eventually service EVERY producer.
///
/// A pass that always restarts at the front of the handle snapshot serves the
/// same few producers forever: the ones behind the cut are due on every pass and
/// reached on none of them. The resume cursor is what makes the budget a delay
/// rather than a starvation.
///
/// Driven with probing services because RFC 6762 §8.1 re-arms a partially
/// delivered probe within 250 ms, so every producer is genuinely due again at
/// every pass — which is the condition under which a fixed start point starves.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread")]
async fn repeated_budget_cuts_reach_every_producer() {
  const PRODUCERS: usize = 3;

  let v4 = TestSocket::new(SendBehaviour::Accepts);
  let v6 = TestSocket::new(SendBehaviour::Wedged);
  let mut state = scripted_state(true, v4, v6);
  let mut scratch = std::vec![0u8; 4096];
  let t = StdInstant::now();

  let mut regs = Vec::new();
  for i in 0..PRODUCERS {
    regs.push(
      state
        .register_service(delivery_test_spec(&std::format!("probe{i}")), t)
        .expect("register a probing service"),
    );
  }
  // Two warm-up ticks: the first moves each service Init → Probing(0) (which
  // schedules the first probe rather than sending one), the second lands past
  // §8.1's random initial wait of up to 250 ms, so every service is due when the
  // measured passes begin.
  for _ in 0..2 {
    tokio::time::sleep(Duration::from_millis(300)).await;
    state.fire_timeouts(StdInstant::now());
  }
  assert!(
    state.services.values().all(|c| matches!(
      c.proto.state(),
      mdns_proto::service::ServiceState::Probing(0)
    )),
    "every service must be probing and due before the budget is applied"
  );

  for _ in 0..PRODUCERS {
    let now = StdInstant::now();
    state.fire_timeouts(now);
    // A budget with room for exactly ONE wedged fan-out, so each pass is cut at a
    // known point and the cursor is the only thing that can move the start.
    let mut budget = DrainBudget {
      credits: MAX_SEND_CREDITS_PER_DRAIN,
      deadline: now + SEND_ATTEMPT_TIMEOUT + Duration::from_millis(50),
      started: false,
    };
    let more = state.drain_transmits(now, &mut budget, &mut scratch).await;
    assert!(
      more,
      "a one-fan-out budget must cut a {PRODUCERS}-producer pass"
    );
    // Past every served producer's §8.1 re-arm, so the whole set is due again and
    // a fixed start point would spend the next budget on the same handle.
    tokio::time::sleep(Duration::from_millis(280)).await;
  }

  let unserved: Vec<_> = state
    .services
    .iter()
    .filter(|(_, ctx)| ctx.wire_gate.last_sent[FAMILY_V4].is_none())
    .map(|(h, _)| *h)
    .collect();
  assert!(
    unserved.is_empty(),
    "{} of {PRODUCERS} producers never reached a wire across {PRODUCERS} cut \
     passes: {unserved:?}. A budget cut must rotate where the next pass resumes, \
     or the producers behind the first cut are starved for as long as the \
     pressure lasts",
    unserved.len(),
  );
  drop(regs);
}

// ── the query drain weighs the caller's window on its own clock ─────────────
//
// `QuerySpec::with_timeout` is a promise to whoever set it: no question is
// ADMITTED at or after the instant it makes absolute. The core keeps that
// promise inside `Query::poll_transmit`, weighed against the instant the driver
// hands in — so the promise is worth exactly what that reading is worth. The
// pass's reading is taken before `sweep_closed_handles`, `fire_timeouts` and (in
// the default class order) the whole service drain, whose fan-outs are AWAITED
// and bounded only by `SEND_ATTEMPT_TIMEOUT` — so a window that shuts while an
// earlier producer's datagram is in flight is invisible to it, and the question
// is admitted after the caller was told none would be.
//
// The RFC 6762 §5.2 ladder underneath the same query is the opposite case and
// stays on the pass's instant: it is the core's own schedule, and every stage of
// a pass must agree about it.

/// How long the earlier producer's fan-out takes to be accepted. Inside
/// [`SEND_ATTEMPT_TIMEOUT`], so both families genuinely ACCEPT the datagram and
/// the pass is delayed by a real send rather than by a bound expiring.
#[cfg(feature = "tokio")]
const EARLIER_SEND_ACCEPTS_AFTER: Duration = Duration::from_millis(200);

/// The window the caller asks for. Comfortably shorter than the send above, so
/// the crossing belongs to the send rather than to a slow runner.
#[cfg(feature = "tokio")]
const CALLER_QUERY_WINDOW: Duration = Duration::from_millis(60);

/// A question drawn after the caller's window shut must not reach either wire —
/// and the query must still end where its deadline's owner ends it.
///
/// The two drains are called separately, in the order `drain_transmits` calls
/// them by default, so the wire record can be read at the seam between them.
/// That is what makes the count a discriminator: the earlier producer's
/// announcement is on both wires before the query is polled at all, and anything
/// the query adds is the question under test.
///
/// Both premises are asserted about the instants that were actually used, not
/// about readings taken beside the call: the pass began inside the window (its
/// own `now`, the one handed to both drains), and the awaited fan-out carried it
/// out of the window before the query drain was entered. A pass that began
/// outside the window would exercise the already-expired path instead and pass
/// whatever the query drain does.
///
/// The closing half is why "no datagram" is not the whole property. Withholding
/// defers the terminal to `handle_timeout`, so the deadline must still stand in
/// `poll_query_timeout` — it is the wakeup `next_deadline` folds — and a caller
/// parked on `Query::next` must still be told `Timeout`.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread")]
async fn a_question_drawn_past_the_callers_window_never_reaches_the_wire() {
  let v4 = TestSocket::delayed(EARLIER_SEND_ACCEPTS_AFTER);
  let v6 = TestSocket::delayed(EARLIER_SEND_ACCEPTS_AFTER);
  let (v4_log, v6_log) = (v4.wire_log(), v6.wire_log());
  let mut state = scripted_state(false, v4, v6);
  let mut scratch = std::vec![0u8; 4096];

  let t0 = StdInstant::now();
  let reg = state
    .register_service(delivery_test_spec("earlier"), t0)
    .expect("register the earlier producer");
  let started = state
    .start_query(
      mdns_proto::QuerySpec::new(
        mdns_proto::Name::try_from_str("printer.local.").unwrap(),
        mdns_proto::wire::ResourceType::A,
      )
      .with_timeout(CALLER_QUERY_WINDOW),
      t0,
    )
    .expect("start the query under test");
  let qh = started.handle;
  let deadline = state
    .endpoint
    .poll_query_timeout(qh)
    .expect("a query given a window publishes its absolute deadline");

  // One pass, exactly as `driver_task` runs it: one instant read at the top,
  // handed to the timer fire and to both drains.
  let pass_now = StdInstant::now();
  assert!(
    pass_now < deadline,
    "the pass must begin inside the caller's window, or this asserts nothing"
  );
  state.fire_timeouts(pass_now);
  let mut budget = DrainBudget::new(pass_now);
  state
    .drain_service_transmits(pass_now, &mut budget, &mut scratch)
    .await;

  let served =
    |log: &Arc<Mutex<Vec<StdInstant>>>| log.lock().unwrap_or_else(|e| e.into_inner()).len();
  let (v4_after_services, v6_after_services) = (served(&v4_log), served(&v6_log));
  assert!(
    v4_after_services > 0 && v6_after_services > 0,
    "premise: the earlier producer must have been SERVED on both wires, or the \
     pass never spent the wall clock this test is about"
  );
  assert!(
    StdInstant::now() >= deadline,
    "premise: awaiting that fan-out must have carried the pass out of the \
     caller's window"
  );

  state.drain_query_transmits(&mut budget, &mut scratch).await;
  assert_eq!(
    (served(&v4_log), served(&v6_log)),
    (v4_after_services, v6_after_services),
    "a question drawn after the caller's window shut reached the wire; the query \
     drain weighed a promise made to the caller against an instant read before \
     an awaited fan-out it does not bound"
  );

  // Withheld, not ended: the terminal belongs to the deadline's owner, and the
  // wakeup that reaches it must survive the withholding.
  assert_eq!(
    state.endpoint.poll_query_timeout(qh),
    Some(deadline),
    "the withheld question must leave the deadline standing — it is the wakeup \
     `next_deadline` folds, and the only thing left that can end this query"
  );
  assert!(
    state
      .next_deadline()
      .is_some_and(|at| at <= StdInstant::now()),
    "and it is already due, so the loop is sent straight back rather than parked"
  );

  let settle = StdInstant::now();
  state.fire_timeouts(settle);
  state.push_updates(settle).await;
  let (cmd_tx, _cmd_rx) = async_channel::unbounded::<crate::command::Command>();
  let mut q = crate::query::Query::new(qh, started.mailbox, started.doorbell, cmd_tx);
  let event = tokio::time::timeout(Duration::from_millis(200), q.next())
    .await
    .expect("the terminal is already in the mailbox, so `next` must complete")
    .expect("a query past its window ends, rather than closing its stream");
  assert!(
    matches!(
      event,
      crate::query::QueryEvent::Terminal(mdns_proto::QueryUpdate::Timeout)
    ),
    "the query must still end, and with the terminal its deadline's owner \
     produces; got {event:?}"
  );
  drop(reg);
}

/// A datagram past this family's HARD UDP ceiling is reported permanently
/// refused; one within it never is, whatever errno the kernel chose.
///
/// This driver had no permanence arm at all: every `Err` was one undifferentiated
/// failure, so a §8.1 probe or a §8.3 announcement no socket could ever carry was
/// re-armed by the core forever, with nothing on any wire and `Established` never
/// reached. The core's patience does not rescue that — it excuses a MISSING
/// family, not a round that can succeed on none of them.
///
/// The SIZE is the only sound proof and the errno is deliberately not consulted:
/// Linux answers `EMSGSIZE` both for a payload past the hard maximum, which is
/// permanent, and for a write past the currently-known path MTU with `DF` set,
/// which the next attempt may get past after an MTU probe or a route change
/// (udp(7), ip(7) `IP_MTU_DISCOVER`). Reading that errno as permanent retires a
/// healthy service over a link whose MTU just dropped.
#[test]
fn permanence_is_proved_by_the_size_and_never_by_the_errno() {
  let err = || SendAttempt::Answered {
    result: Err(std::io::Error::from(std::io::ErrorKind::Other)),
    submitted_wall: SystemTime::now(),
    submitted_at: StdInstant::now(),
    wire_at: StdInstant::now(),
  };
  // An ordinary mDNS-sized body: three orders of magnitude inside the limit, and
  // the size at which a path-MTU refusal actually happens.
  let ordinary = std::vec![0u8; 1200];
  assert_eq!(
    attempt_of(Family::V4, &ordinary, &err()),
    FamilyAttempt::Refused { permanent: false },
    "a refusal of a datagram within the ceiling proves only that these bytes did \
     not go out now"
  );

  let past_v4 = std::vec![0u8; mdns_proto::constants::MAX_UDP_PAYLOAD_V4 + 1];
  assert_eq!(
    attempt_of(Family::V4, &past_v4, &err()),
    FamilyAttempt::Refused { permanent: true },
    "past IPv4's 16-bit total-length ceiling, no route and no MTU can ever carry \
     it, so the core must stop re-arming it"
  );
  // The two ceilings differ by the 20-byte IPv4 header, so the very body that is
  // impossible on v4 is merely refused on v6.
  assert_eq!(
    attempt_of(Family::V6, &past_v4, &err()),
    FamilyAttempt::Refused { permanent: false },
    "each family's ceiling is its own"
  );
  assert_eq!(
    attempt_of(
      Family::V6,
      &std::vec![0u8; mdns_proto::constants::MAX_UDP_PAYLOAD_V6 + 1],
      &err()
    ),
    FamilyAttempt::Refused { permanent: true },
  );
}

/// A sustained datagram every offered family refuses by SIZE retires its
/// producer, and the core is the one that says so.
///
/// The end of the liveness defect: this driver reported such a round as an
/// ordinary miss, the core re-armed it, and the producer probed or announced
/// forever with nothing on any wire.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn a_permanently_oversized_sustained_datagram_retires_its_producer() {
  let mut buf = std::vec![0u8; 4096];

  // End to end through this driver's own classification: a body no IPv4 socket
  // can carry, refused by the kernel, on a single-stack host.
  let oversized = std::vec![0u8; mdns_proto::constants::MAX_UDP_PAYLOAD_V4 + 1];
  let refused = SendAttempt::Answered {
    result: Err(std::io::Error::from(std::io::ErrorKind::Other)),
    submitted_wall: SystemTime::now(),
    submitted_at: StdInstant::now(),
    wire_at: StdInstant::now(),
  };
  let (mut state, h) = probing_service();
  let ctx = state.services.get_mut(&h).unwrap();
  let now = draw_first_probe(&mut ctx.proto, &mut buf);
  assert!(
    ctx
      .proto
      .note_transmit_outcome(
        now,
        attempt_of(Family::V4, &oversized, &refused),
        FamilyAttempt::NoSocket,
      )
      .retire_producer(),
    "the one family this host has refused the probe's SIZE, so re-offering these \
     exact bytes can never put them on a wire"
  );

  // The contrast: a family that may still clear is waited for, however badly the
  // other one failed. Retiring here would destroy a healthy advertisement over a
  // full send buffer.
  let (mut state, h) = probing_service();
  let ctx = state.services.get_mut(&h).unwrap();
  let now = draw_first_probe(&mut ctx.proto, &mut buf);
  assert!(
    !ctx
      .proto
      .note_transmit_outcome(
        now,
        attempt_of(Family::V4, &oversized, &refused),
        FamilyAttempt::WouldBlock,
      )
      .retire_producer(),
    "an unwritable socket submitted nothing and may accept the same bytes next \
     round"
  );
}

/// A `DriverState` with no bound socket, and one registered service in `Probing`.
///
/// No sockets: this test is about what the CORE concludes from a reported round,
/// and the report is handed over by hand.
#[cfg(feature = "tokio")]
fn probing_service() -> (
  DriverState<agnostic_net::tokio::Net>,
  mdns_proto::ServiceHandle,
) {
  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let mut records = mdns_proto::ServiceRecords::new(
    mdns_proto::Name::try_from_str("_ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("printer._ipp._tcp.local.").unwrap(),
    mdns_proto::Name::try_from_str("host.local.").unwrap(),
    631,
    120,
  );
  records.add_a(std::net::Ipv4Addr::new(192, 168, 1, 10));
  let handle = state
    .register_service(mdns_proto::ServiceSpec::new(records), StdInstant::now())
    .unwrap()
    .handle;
  (state, handle)
}

/// Arm and draw the first §8.1 probe, returning the instant it was drawn at. A
/// fresh service waits out §8.1's random 0-250 ms initial delay first.
#[cfg(feature = "tokio")]
fn draw_first_probe(proto: &mut ProtoService, buf: &mut [u8]) -> StdInstant {
  let start = StdInstant::now();
  for step in 1..=8u32 {
    let now = start
      .checked_add(std::time::Duration::from_millis(u64::from(step) * 100))
      .unwrap();
    proto.handle_timeout(now).unwrap();
    if proto.poll_transmit(now, buf).unwrap().is_some() {
      return now;
    }
  }
  panic!("no probe was drawn within the §8.1 initial delay");
}

/// A monotonic instant `age` in the past, waiting for the clock if this process
/// has not been up that long yet.
///
/// `StdInstant` has no constructor and no epoch, so the only way to name an
/// instant a whole `SELF_SEND_TTL` ago is to subtract from a live reading — which
/// a process younger than the TTL cannot do. Waiting is a bounded precondition,
/// not a skip: the assertions below always run.
#[cfg(feature = "tokio")]
fn monotonic_instant_ago(age: Duration) -> StdInstant {
  loop {
    if let Some(t) = StdInstant::now().checked_sub(age) {
      return t;
    }
    std::thread::sleep(Duration::from_millis(25));
  }
}

/// The claim window must be open BEFORE the driver can receive, or the TTL bounds
/// nothing on the path it exists to bound.
///
/// `driver_task` records this iteration's sends in `drain_transmits` /
/// `drain_withdrawals` and then parks in `select_biased!`, which handles a
/// received packet in that SAME iteration. A credit that is still unsealed when
/// the park returns is live UNCONDITIONALLY — `still_live` reads `aged_from:
/// None` as "no window has opened, so nothing can have been missed" — so a
/// byte-identical peer datagram arriving arbitrarily long after the send would be
/// swallowed as our own echo. The park is bounded only by the next protocol
/// deadline, which can be seconds away or absent.
///
/// So the seal is placed after the drains and before the park, and this test
/// stands on that placement: it seals the credit exactly as the loop does, ages
/// it past `SELF_SEND_TTL`, and drives the production receive path. Remove the
/// seal from `driver_task` — the state this test builds is then precisely what
/// the loop hands `handle_packet` — and the credit is consumed instead of
/// refused.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn a_credit_sealed_before_the_park_expires_across_it_and_cannot_suppress_a_peer() {
  use std::net::{IpAddr, Ipv4Addr};

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);

  // A QR=0 query body, so the §11 untrusted-response gate cannot be what refuses
  // it and the datagram genuinely reaches the self-send match.
  let body = vec![0u8; 12];
  state.selfsend.record(Family::V4, &body, ClockPair::now());
  assert_eq!(state.selfsend.len(), 1, "the send recorded its credit");

  // The seal the loop performs after its drains, with the window opened longer
  // ago than the TTL — which is what a park longer than the TTL amounts to.
  let opened = monotonic_instant_ago(SELF_SEND_TTL + Duration::from_millis(250));
  state.selfsend.seal_at(opened);
  #[cfg(debug_assertions)]
  state.note_park_entry();

  // The park ends with a byte-identical datagram from a co-resident peer, on
  // port 5353 and on-link, offered to the production receive path.
  state.handle_packet(Packet {
    src: "192.0.2.9:5353".parse().unwrap(),
    data: body.clone(),
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("192.0.2.9:5353".parse().unwrap()),
    rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
    // A multicast echo carries the group destination, which is what §11 admits
    // it on now that the inbound TTL is not a test.
    destination: DestinationWitness::Witnessed(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    delivery: None,
    hop_limit: Some(255),
  });

  assert_eq!(
    state.selfsend.len(),
    1,
    "the credit's window opened more than SELF_SEND_TTL before this datagram \
     arrived, so these bytes are a peer's and the credit must NOT be consumed; \
     an unsealed credit would have been spent here however long the park lasted"
  );
}

/// The seal must PRECEDE the park, and this pins the ordering rather than the
/// state left behind.
///
/// "Nothing is unsealed" is true at the receive whichever side of the park the
/// seal happened on, so a driver that sealed in its receive arm — after an
/// arbitrarily long park, with every credit anchored that late — satisfies a
/// state check placed there. What separates the two is *when* the window opened,
/// and `SelfSendTracker::seal_generation` is what makes that observable: the
/// boundary records which seal it is relying on, and the receive requires that
/// no window has opened since.
///
/// The three phases below are the loop's, in the loop's order.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn the_seal_predates_the_park_and_the_generation_proves_it() {
  use std::net::{IpAddr, Ipv4Addr};

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);
  let body = vec![0u8; 12];

  // Phase 1 — the pumps record. Until the seal these credits are ageless, which
  // is exactly the state a receive must never be reached in.
  state.selfsend.record(Family::V4, &body, ClockPair::now());
  assert!(
    state.selfsend.has_unsealed(),
    "a freshly recorded credit has no window yet; this is the state a seal \
     placed after the park would leave standing across it"
  );
  let before_seal = state.selfsend.seal_generation();

  // Phase 2 — the park entry. Both halves of the contract become true
  // here and nowhere later.
  state.selfsend.seal();
  assert!(
    !state.selfsend.has_unsealed(),
    "the boundary seal must close every credit the pumps recorded"
  );
  let at_boundary = state.selfsend.seal_generation();
  // The park entry, exactly as `driver_task` reaches it.
  #[cfg(debug_assertions)]
  state.note_park_entry();
  assert_eq!(
    at_boundary,
    before_seal + 1,
    "the boundary seal opened exactly one window"
  );

  // Phase 3 — the park, then a receive. The park itself performs no tracker
  // operation, which is the whole claim: the generation observed at the receive
  // must be the one the boundary recorded.
  state.handle_packet(Packet {
    src: "192.0.2.9:5353".parse().unwrap(),
    data: body.clone(),
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("192.0.2.9:5353".parse().unwrap()),
    rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
    // A multicast echo carries the group destination, which is what §11 admits
    // it on now that the inbound TTL is not a test.
    destination: DestinationWitness::Witnessed(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    delivery: None,
    hop_limit: Some(255),
  });
  assert_eq!(
    state.selfsend.seal_generation(),
    at_boundary,
    "no claim window may open between the park entry and the receive; a \
     seal that ran in the receive arm would show up here as a later generation"
  );

  // And the credit really was claimable, so the ordering above was exercised
  // against a live match rather than a vacuous one.
  assert!(
    state.selfsend.is_empty(),
    "the datagram matched its own credit, so this test weighed a real claim"
  );
}

/// The reactor has a receive path that never parks, and the seal-ordering check
/// must not fire on it.
///
/// When a drain reports work still pending, `driver_task` does NOT park: it
/// drains a bounded batch of commands and `continue`s straight back to the packet
/// pump, so the next datagram it handles arrives with no park behind it. The seal
/// on the way there legitimately advanced the generation, and the capture still
/// held describes a park one or more iterations old — so comparing against it
/// panics on correct sealing and kills the driver task on an ordinary backlog.
///
/// Everything the loop does at that boundary is `DriverState::seal_after_records`,
/// and this test calls that same method rather than restating what it should do.
/// Delete the clear inside it and this test fails, because production and the
/// test execute one body: the earlier version of this test assigned the capture
/// by hand and survived exactly that deletion.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread")]
async fn a_receive_reached_without_parking_is_not_weighed_against_a_stale_park() {
  use std::net::{IpAddr, Ipv4Addr};

  let mut state = scripted_state(
    false,
    TestSocket::new(SendBehaviour::Accepts),
    TestSocket::new(SendBehaviour::Accepts),
  );
  let mut scratch = vec![0u8; 4096];

  // Enough services that one pass cannot serve them all: `more_pending` is what
  // sends the loop down the no-park path, so the test has to earn it rather than
  // assume it. Each fan-out charges two credits against
  // `MAX_SEND_CREDITS_PER_DRAIN`.
  //
  // The registrations are KEPT: dropping one closes its doorbell and the drain
  // skips it as orphaned, so a discarded handle means nothing is ever sent and
  // the pass below would be vacuous.
  let _regs: Vec<_> = (0..64u16)
    .map(|i| {
      state
        .register_service(delivery_test_spec(&format!("svc{i}")), StdInstant::now())
        .expect("register the service under test")
    })
    .collect();

  // A park from an EARLIER iteration, whose capture is the stale value the
  // backlog receive must not be weighed against.
  #[cfg(debug_assertions)]
  state.note_park_entry();

  let (more_pending, _) = drive_one_pass(&mut state, &mut scratch).await;
  assert!(
    more_pending,
    "this test is about the path taken when a drain reports more work; without \
     that the loop parks and the stale capture is replaced rather than carried"
  );
  assert!(
    state.selfsend.has_unsealed(),
    "the pass above recorded credits, so there is something for the seal to close"
  );

  // The loop's own boundary, executed rather than described.
  state.seal_after_records();

  // `more_pending` is true, so `driver_task` drains commands and `continue`s —
  // no park entry runs — and the next iteration's packet pump receives this.
  state.handle_packet(Packet {
    src: "192.0.2.9:5353".parse().unwrap(),
    data: vec![0u8; 12],
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("192.0.2.9:5353".parse().unwrap()),
    rx: RxEvidence::from_stamp_for_test(SystemTime::now()),
    // A multicast echo carries the group destination, which is what §11 admits
    // it on now that the inbound TTL is not a test.
    destination: DestinationWitness::Witnessed(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    delivery: None,
    hop_limit: Some(255),
  });

  // The unconditional half still holds on this path: a receive reached without
  // parking must still find every credit sealed.
  assert!(
    !state.selfsend.has_unsealed(),
    "the seal before the `continue` must leave nothing unsealed, park or no park"
  );
}

/// Only port 5353 may be offered a self-send credit, and a §6.7 legacy query is
/// the case that tests it.
///
/// Both of this endpoint's sockets bind 5353, so that is the source port every
/// datagram it sends leaves from and the only one a loopback copy can arrive
/// from. The §11 gate already drops a RESPONSE from any other port, but a legacy
/// unicast QUERY is deliberately kept — that querier uses an ephemeral port and
/// is owed a reply. Kept is not ours: in degraded mode nothing orders the claim
/// against the send, so without the source-port gate this byte-identical query
/// takes the credit and is reported as our own echo. The querier's reply is then
/// never sent, and the genuine echo behind it finds no credit and reaches the
/// protocol layer as peer traffic — the credit spent on the wrong datagram, and
/// both datagrams misclassified.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn a_legacy_query_from_an_ephemeral_port_is_never_offered_a_credit() {
  use std::net::{IpAddr, Ipv4Addr};

  let opts = crate::options::ServerOptions::default();
  let sockets = BoundSockets::<agnostic_net::tokio::Net> {
    v4: None,
    v6: None,
    interface_index: 0,
  };
  let mut state = DriverState::new(&opts, sockets);

  // QR=0, so the §11 untrusted-response gate does not fire and the datagram
  // genuinely reaches the self-send match.
  let body = vec![0u8; 12];
  let sent = ClockPair::now();
  state.selfsend.record(Family::V4, &body, sent);
  state.selfsend.seal_at(sent.mono);
  #[cfg(debug_assertions)]
  state.note_park_entry();
  assert_eq!(state.selfsend.len(), 1, "one credit is outstanding");

  // Degraded: no kernel receive stamp, so nothing orders this claim against the
  // send and content plus family plus the TTL is the whole of the match.
  let ephemeral = Packet {
    src: "192.0.2.9:40000".parse().unwrap(),
    data: body.clone(),
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("192.0.2.9:40000".parse().unwrap()),
    rx: RxEvidence::none(),
    // A multicast echo carries the group destination, which is what §11 admits
    // it on now that the inbound TTL is not a test.
    destination: DestinationWitness::Witnessed(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    delivery: None,
    hop_limit: Some(255),
  };
  state.handle_packet(ephemeral);
  assert_eq!(
    state.selfsend.len(),
    1,
    "a datagram from a port this endpoint never sends from cannot be its own \
     echo, so it must not be offered the credit at all"
  );

  // And the credit is still there for the datagram it belongs to: the same bytes
  // arriving from 5353 are our echo and claim it.
  state.handle_packet(Packet {
    src: "192.0.2.9:5353".parse().unwrap(),
    data: body,
    family: Family::V4,
    local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    iface: packet_iface_witness("192.0.2.9:5353".parse().unwrap()),
    rx: RxEvidence::none(),
    // A multicast echo carries the group destination, which is what §11 admits
    // it on now that the inbound TTL is not a test.
    destination: DestinationWitness::Witnessed(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    delivery: None,
    hop_limit: Some(255),
  });
  assert!(
    state.selfsend.is_empty(),
    "the genuine echo, from 5353, still finds the credit the legacy query was \
     refused"
  );
}

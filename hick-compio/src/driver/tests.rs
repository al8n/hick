use core::cell::Cell;

use hick_udp::selfsend::RxEvidence;
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
  let now = StdInstant::now();

  // Ok → Accepted.
  assert_eq!(
    attempt_of(
      Family::V4,
      &body,
      &SendAttempt::Answered {
        result: Ok(body.len()),
        submitted_wall: SystemTime::now(),
        submitted_at: now,
        completed_at: now,
      },
    ),
    FamilyAttempt::Accepted { at: now },
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
          completed_at: StdInstant::now(),
        },
      ),
      FamilyAttempt::Refused { permanent: false },
      "a present (bound) socket error ({kind:?}) must be Refused, not NoSocket"
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
  // response gate fires, not §11's arms.
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
  s.bound_interface = 1;

  // 3-byte body: byte 2 = 0x80 → QR=1. Too short for a valid DNS message.
  let data: Vec<u8> = vec![0x00, 0x00, 0x80];
  let len = data.len() as u64;

  let meta = RecvMeta::new(
    SocketAddr::from(([127, 0, 0, 1], 40000)), // non-5353 source port → untrusted
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    1,
    Some(255), // carried, never read
    RxEvidence::none(),
    len as usize,
  );
  s.handle_datagram(Family::V4, &meta, &data);

  let snap = s.stats.snapshot();
  assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
  assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
}

/// A well-formed 12-byte DNS response header (QR=1) from a non-5353 source
/// must count packets_rx +1, bytes_rx +len, packets_dropped +1 exactly once.
/// The self-send tracker must remain untouched.
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

  assert!(s.selfsend.is_empty(), "no prior self-send credits");

  let meta = RecvMeta::new(
    SocketAddr::from(([127, 0, 0, 1], 54321)), // non-5353 → untrusted
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    1,
    Some(255), // on-link
    RxEvidence::none(),
    len as usize,
  );
  s.handle_datagram(Family::V4, &meta, &data);

  // Self-send tracker must be untouched (never reached).
  assert!(
    s.selfsend.is_empty(),
    "the untrusted-response gate returns before the tracker is consulted"
  );

  let snap = s.stats.snapshot();
  assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
  assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
}

/// A datagram the §11 boundary refuses must count packets_rx +1, bytes_rx +len,
/// packets_dropped +1 exactly once.
///
/// The refusal is §11's unicast arm — the source matches no prefix configured on
/// the bound interface. It is NOT the TTL, which the boundary never reads.
#[cfg(feature = "stats")]
#[test]
fn pre_drop_off_link_datagram_counts_rx_and_dropped_exactly_once() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
  s.bound_interface = 1;

  // QR=0 query body, so only §11's arms decide and not the untrusted-response
  // gate. The source matches no configured prefix, which is the refusal.
  let data: Vec<u8> = vec![
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  let len = data.len() as u64;

  let meta = RecvMeta::new(
    SocketAddr::from(([203, 0, 113, 5], 5353)),
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    None,
    1,
    Some(64), // carried, never read — see the doc above
    RxEvidence::none(),
    len as usize,
  );
  s.handle_datagram(Family::V4, &meta, &data);

  let snap = s.stats.snapshot();
  assert_eq!(snap.packets_rx, 1, "packets_rx +1 (datagram was received)");
  assert_eq!(snap.bytes_rx, len, "bytes_rx == datagram length");
  assert_eq!(snap.packets_dropped, 1, "exactly one reject counter");
}

/// §11 regression guard: a datagram whose source address falls outside every
/// prefix configured on the bound interface must be refused by
/// `handle_datagram` before it reaches the self-send match or `endpoint.handle`.
///
/// The observable is the take-once self-send credit, which `handle_datagram`
/// consults only AFTER the gate. The previous version of this asserted "no
/// panic" on a 12-byte all-zero body — which is a valid empty DNS header the
/// proto layer handles gracefully, as `a_zero_length_answer_section_is_not_an_
/// error` shows independently. So it stayed green with the ingress rejection
/// removed: it proved nothing.
///
/// The hop limit is carried and never read; the refusal is the prefix.
#[test]
fn handle_datagram_refuses_a_source_outside_every_configured_prefix() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(INGRESS_OUR_ADDR, 24u8)];
  s.bound_interface = 1;
  s.bound_is_loopback = false;

  let admits = |s: &mut State, peer: SocketAddr| -> bool {
    let body = vec![0u8; 12];
    s.selfsend.record(Family::V4, &body, ClockPair::now());
    s.selfsend.seal();
    #[cfg(debug_assertions)]
    s.note_park_entry();
    let before = s.selfsend.len();
    let meta = RecvMeta::new(
      peer,
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      // A unicast destination, so §11's source-prefix arm is what decides.
      Some(INGRESS_OUR_ADDR),
      1,
      Some(64),
      RxEvidence::from_stamp_for_test(SystemTime::now()),
      body.len(),
    );
    s.handle_datagram(Family::V4, &meta, &body);
    // The DELTA: a refused datagram leaves its credit behind, so `is_empty`
    // stops discriminating after the first refusal.
    s.selfsend.len() < before
  };

  assert!(
    !admits(&mut s, SocketAddr::from(([203, 0, 113, 5], 5353))),
    "a source in no configured prefix must be refused before the self-send match"
  );
  // The same datagram from inside the prefix IS admitted, so the refusal above
  // is the source and not the body, the port or the interface.
  assert!(admits(&mut s, SocketAddr::from(([192, 168, 1, 7], 5353))));
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
// passes, and the capability it claims for its own receive path, which is NOT
// `hick-udp`'s — driven through `handle_datagram`, the same entry the `select!`
// recv arms call, rather than through a reconstruction of it. Every rejecting
// case below is a row where `hick-compio` used to admit what the gate now
// refuses.

/// The interface this fixture's endpoint is pinned to.
const INGRESS_BOUND: u32 = 5;
/// Some other NIC on the same host.
const INGRESS_OTHER: u32 = 9;

/// The bound interface's configuration: the address it HOLDS and that address's
/// mask, which is what `collect_local_subnets` reports (`getifs`' `addr()`, not
/// a masked network). Both of RFC 6762 §11's arms read it — the source arm as
/// address and mask, the destination test as the address alone — so
/// [`INGRESS_OUR_ADDR`] is also the unicast destination every case below reaches
/// the source arm through.
fn ingress_subnets() -> Vec<(IpAddr, u8)> {
  vec![(INGRESS_OUR_ADDR, 24u8)]
}

/// The address [`ingress_subnets`] holds, and therefore the destination §11
/// treats as a response *"received via unicast"* on this link. A destination the
/// interface does NOT hold reaches no §11 arm at all.
const INGRESS_OUR_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

/// A routable source inside [`ingress_subnets`], so nothing below turns on the
/// §11 fallback's own subnet rule.
fn ingress_on_subnet_peer() -> SocketAddr {
  SocketAddr::from(([192, 168, 1, 7], 5353))
}

/// The link-local prefixes an interface holding a link-local address reports.
/// §11's second arm is the only thing that admits a link-local source, so a
/// fixture meaning "this link-local peer is on our link" has to say so the way a
/// real interface does — a witness settles which link, never the prefix.
fn ingress_ll_prefixes() -> Vec<(IpAddr, u8)> {
  vec![
    (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 64u8),
    (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16u8),
  ]
}

/// A link-local IPv6 peer inside `scope`'s zone — the second witness of the link
/// a datagram came from, which taking `peer().ip()` alone discarded.
fn ingress_link_local_peer(scope: u32) -> SocketAddr {
  SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
    5353,
    0,
    scope,
  ))
}

/// One datagram, in the shape a receive path hands it to the driver. A struct
/// rather than a widening parameter list so the two facts §11 selects its
/// fallback arm by are stated where they matter and default to "this path
/// recovered none" everywhere else.
struct Arrival {
  src: SocketAddr,
  family: Family,
  hop_limit: Option<u8>,
  pkt_iface: u32,
  destination: Option<IpAddr>,
  delivery: Option<hick_udp::LinkDelivery>,
}

impl Arrival {
  /// A datagram whose receive path recovered neither a destination nor a
  /// multicast flag.
  fn new(src: SocketAddr, family: Family, hop_limit: Option<u8>, pkt_iface: u32) -> Self {
    Self {
      src,
      family,
      hop_limit,
      pkt_iface,
      destination: None,
      delivery: None,
    }
  }

  /// The IP header destination this receive path recovered.
  fn addressed_to(mut self, dst: IpAddr) -> Self {
    self.destination = Some(dst);
    self
  }

  /// The kernel's `MSG_MCAST`, where the target reports one and no destination
  /// was recovered.
  fn delivered_as_multicast(mut self) -> Self {
    self.delivery = Some(hick_udp::LinkDelivery::Multicast);
    self
  }
}

/// Whether the ingress trust boundary admitted one datagram, answered by the
/// PRODUCTION receive entry.
///
/// The observable is the take-once self-send credit. `handle_datagram` consults
/// the tracker only AFTER the gate, and with a byte-identical credit already
/// recorded a datagram that reaches the tracker always spends it — so a credit
/// still unspent is a datagram the gate refused, and an empty tracker is one it
/// admitted. Nothing here restates the gate's own conditions: the answer comes
/// out of the function the `select!` recv arms call.
///
/// The body is a QR=0 query, so the untrusted-response gate cannot be what
/// refuses it, and the source port is 5353 for the same reason.
fn ingress_admits(a: Arrival, subnets: &[(IpAddr, u8)], bound_is_loopback: bool) -> bool {
  use crate::socket::RecvMeta;

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.bound_interface = INGRESS_BOUND;
  // Pinned rather than enumerated: `INGRESS_BOUND` names whatever NIC happens to
  // hold index 5 on the host running this, so neither its subnets nor its
  // loopback flag may be allowed to decide these cases.
  s.local_subnets = subnets.to_vec();
  s.bound_is_loopback = bound_is_loopback;

  let body = vec![0u8; 12];
  s.selfsend.record(a.family, &body, ClockPair::now());
  s.selfsend.seal();
  #[cfg(debug_assertions)]
  s.note_park_entry();
  assert_eq!(s.selfsend.len(), 1, "the send recorded its credit");

  let local = match a.src {
    SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
  };
  let meta = RecvMeta::new(
    a.src,
    local,
    a.destination,
    a.pkt_iface,
    a.hop_limit,
    RxEvidence::from_stamp_for_test(SystemTime::now()),
    body.len(),
  )
  .with_delivery(a.delivery);
  s.handle_datagram(a.family, &meta, &body);
  s.selfsend.is_empty()
}

/// A routable source on a prefix the bound interface does NOT carry: the
/// overlaid-subnet peer §11 names.
fn ingress_off_subnet_peer() -> SocketAddr {
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 4, 4, 4)), 5353)
}

/// The IPv6 twin of [`ingress_off_subnet_peer`], with no scope id — a global
/// source carries none.
fn ingress_off_subnet_peer_v6() -> SocketAddr {
  SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xbeef, 0, 0, 0, 0, 1)),
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
  // destination — but `recvmsg`'s own `msg_flags` carries `MSG_MCAST`, which
  // this driver reads off compio's `ReturnFlags` instead of discarding, and
  // §11's group arm is what that stands in for.
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
#[test]
fn an_unwitnessed_link_local_source_is_refused() {
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
#[test]
fn an_unwitnessed_apipa_peer_is_admitted_on_a_matching_prefix() {
  let apipa: Vec<(IpAddr, u8)> = vec![(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16u8)];
  let peer_ll = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 3, 9)), 5353);
  let reported = crate::socket::rx_interface_reported(peer_ll);
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
#[test]
fn a_renumbered_interface_is_picked_up_without_restarting_the_endpoint() {
  let mut state = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  state.bound_interface = INGRESS_BOUND;
  state.bound_is_loopback = false;
  state.local_subnets = ingress_subnets();
  let old_peer = ingress_on_subnet_peer();
  let apipa = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 3, 9)), 5353);

  let feed = |state: &mut State, src: SocketAddr| -> bool {
    use crate::socket::RecvMeta;
    let body = vec![0u8; 12];
    state.selfsend.record(Family::V4, &body, ClockPair::now());
    state.selfsend.seal();
    #[cfg(debug_assertions)]
    state.note_park_entry();
    // The DELTA, not `is_empty`: a refused datagram leaves its credit behind, so
    // after the first refusal the tracker is never empty again and `is_empty`
    // would report every later datagram as refused too.
    let before = state.selfsend.len();
    let meta = RecvMeta::new(
      src,
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      None,
      INGRESS_BOUND,
      None,
      RxEvidence::from_stamp_for_test(SystemTime::now()),
      body.len(),
    );
    state.handle_datagram(Family::V4, &meta, &body);
    state.selfsend.len() < before
  };

  // Before: the configured prefix admits, APIPA does not.
  assert!(feed(&mut state, old_peer));
  assert!(!feed(&mut state, apipa));

  // The interface renumbers 192.168.1.0/24 -> 169.254/16 under the live
  // endpoint, and the snapshot ages past its interval.
  hick_udp::onlink::force_enumeration_for_test(Some((
    INGRESS_BOUND,
    vec![(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16u8)],
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
/// This driver's gate was an exclusive `if`/`else` — a reported hop limit was
/// decisive on its own and the interface was consulted only on the fallback
/// branch. An attacker on a neighbouring NIC then reached the cache and RFC 6762
/// §8.2 conflict handling with nothing but a well-formed unicast datagram at TTL
/// 255, which needs no group membership to be delivered.
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
/// [`crate::socket::rx_interface_reported`]:
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
/// This driver passed `meta.peer().ip()` to the gate and threw the zone away, so
/// a source whose own address says it came from another link was admitted on an
/// index that said ours. A datagram that contradicts itself has already failed
/// to prove it is ours, and a trust boundary resolves that against the sender.
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
#[test]
fn a_loopback_bound_endpoint_still_refuses_a_reported_foreign_interface() {
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
/// by the interface gate — the Windows arm of [`crate::socket::Socket::recv`],
/// checked through the production receive entry.
///
/// That arm is a plain `recv_from`: it hands the driver exactly
/// `RecvMeta::empty(peer)`, so every datagram arrives with interface index `0`
/// and no hop limit. `hick-udp` reports IPv4 and IPv6 PKTINFO support on Windows
/// because ITS path calls `WSARecvMsg` — passing that answer here would make
/// every zero index a failed proof and drop every non-loopback datagram, a
/// silently deaf responder on a physical network.
///
/// The meta below is production's own constructor rather than a synthesised
/// index, and the expectation is derived from this driver's own capability
/// rather than hardcoded, so the case runs on every target: where the path DOES
/// report an interface a zero is a failed proof and the datagram is refused;
/// where it reports none the source-address rule decides and an in-subnet peer
/// is admitted. On Windows this is the whole §11 rule there has ever been
/// anything to run — no hop limit is recovered there either.
///
/// This is the ONLY degraded admission left, and it survives because it rests
/// on positive evidence: the source sits inside a prefix configured on the
/// interface this endpoint bound. The link-local case does not degrade the same
/// way and no longer admits anything on absent provenance — see
/// `a_zero_interface_is_never_the_bound_link`.
#[test]
fn a_receive_path_that_recovers_nothing_still_admits_an_in_subnet_peer() {
  use crate::socket::{RecvMeta, rx_interface_reported};

  let peer = ingress_on_subnet_peer();
  let subnets = ingress_subnets();
  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.bound_interface = INGRESS_BOUND;
  s.local_subnets = subnets.clone();
  s.bound_is_loopback = false;

  let body = vec![0u8; 12];
  s.selfsend.record(Family::V4, &body, ClockPair::now());
  s.selfsend.seal();
  #[cfg(debug_assertions)]
  s.note_park_entry();

  // Byte-for-byte what the Windows arm builds.
  let meta = RecvMeta::empty(peer);
  s.handle_datagram(Family::V4, &meta, &body);

  assert_eq!(
    s.selfsend.is_empty(),
    !rx_interface_reported(peer),
    "a path with no interface to give must fall to §11's source rule, not be \
     read as a kernel that declined to place the datagram"
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
#[test]
fn a_loopback_source_from_a_foreign_interface_is_rejected() {
  let subnets = ingress_subnets();
  for (peer, family) in [
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
        Arrival::new(peer, family, Some(255), INGRESS_OTHER),
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
      Arrival::new(peer, family, Some(255), INGRESS_OTHER),
      &subnets,
      true
    ));
    assert!(ingress_admits(
      Arrival::new(peer, family, Some(255), 0),
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
#[test]
fn a_loopback_bound_endpoint_admits_its_own_traffic_in_every_shape() {
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
      let _ = ctx.proto.note_transmit_outcome(
        t,
        FamilyAttempt::Accepted { at: t },
        FamilyAttempt::Accepted { at: t },
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
    while let Some(round) = s.poll_one_withdrawal(t, &mut scratch) {
      // No sockets bound in this State-level test: model BOTH families as
      // transiently undeliverable (Retry) so the per-family budget stays intact
      // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
      // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
      // instead, defeating the ceiling assertion.)
      s.note_withdrawal_result(
        round.token(),
        t,
        FamilyAttempt::Refused { permanent: false },
        FamilyAttempt::Refused { permanent: false },
      );
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
    while let Some(round) = s.poll_one_withdrawal(t, &mut scratch) {
      // No sockets bound in this State-level test: model BOTH families as
      // transiently undeliverable (Retry) so the per-family budget stays intact
      // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
      // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
      // instead, defeating the ceiling assertion.)
      s.note_withdrawal_result(
        round.token(),
        t,
        FamilyAttempt::Refused { permanent: false },
        FamilyAttempt::Refused { permanent: false },
      );
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
      let _ = s.note_service_transmit_outcome(
        h,
        t,
        FamilyAttempt::Accepted { at: t },
        FamilyAttempt::Accepted { at: t },
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
          let _ = s.note_service_transmit_outcome(
            h,
            t,
            FamilyAttempt::Accepted { at: t },
            FamilyAttempt::Accepted { at: t },
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
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    1,
    Some(255),
    RxEvidence::none(),
    conflict.len(),
  );
  let mut conflicted = false;
  for _ in 0..80 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    s.handle_datagram(Family::V4, &peer, &conflict);
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
    while let Some(round) = s.poll_one_withdrawal(t, &mut scratch) {
      // No sockets bound in this State-level test: model BOTH families as
      // transiently undeliverable (Retry) so the per-family budget stays intact
      // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
      // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
      // instead, defeating the ceiling assertion.)
      s.note_withdrawal_result(
        round.token(),
        t,
        FamilyAttempt::Refused { permanent: false },
        FamilyAttempt::Refused { permanent: false },
      );
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
          let _ = s.note_service_transmit_outcome(
            h,
            t,
            FamilyAttempt::Accepted { at: t },
            FamilyAttempt::Accepted { at: t },
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
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    1,
    Some(255),
    RxEvidence::none(),
    conflict.len(),
  );
  let mut conflicted = false;
  for _ in 0..80 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    s.handle_datagram(Family::V4, &peer, &conflict);
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
    while let Some(round) = s.poll_one_withdrawal(t, &mut scratch) {
      // No sockets bound in this State-level test: model BOTH families as
      // transiently undeliverable (Retry) so the per-family budget stays intact
      // and the withdrawal force-completes at its 2 s anti-pin ceiling — exactly
      // the pre-fix "not delivered" behaviour. (WriteOff would complete it at once
      // instead, defeating the ceiling assertion.)
      s.note_withdrawal_result(
        round.token(),
        t,
        FamilyAttempt::Refused { permanent: false },
        FamilyAttempt::Refused { permanent: false },
      );
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
    Name, ServiceRecords, ServiceSpec,
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
        Some((_tx, TransmitOrigin::Service(h))) => {
          let _ = s.note_service_transmit_outcome(
            h,
            t,
            FamilyAttempt::Accepted { at: t },
            FamilyAttempt::Accepted { at: t },
          );
        }
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
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    1,
    Some(255), // on-link
    RxEvidence::none(),
    conflict.len(),
  );

  // Feed the conflict; `push_service_updates` drains the proto's HostConflict and
  // (with the fix) begins the withdrawal — `errored` flips true.
  let mut retired = false;
  for _ in 0..40 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    s.handle_datagram(Family::V4, &peer, &conflict);
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
    while let Some(round) = s.poll_one_withdrawal(t, &mut scratch) {
      s.note_withdrawal_result(
        round.token(),
        t,
        FamilyAttempt::Refused { permanent: false },
        FamilyAttempt::Refused { permanent: false },
      );
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
    let _ = s.note_query_transmit_outcome(
      h,
      now,
      FamilyAttempt::Accepted { at: now },
      FamilyAttempt::Accepted { at: now },
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

/// A query that ends while the driver is looking away strands the caller that
/// asked for it: the terminal is delivered by a WAKE, and the driver can only
/// arm a wake for a transition it can see.
///
/// Every step below is a seam the run loop really runs, in the order it runs
/// them:
///
/// 1. a §5.2 retry falls due INSIDE the query's absolute window, so the timer arm
///    arms its transmit and bumps `notify` (`woke_state`);
/// 2. the `Query::next` parked on that `notify` consumes the wake, finds the
///    query merely armed with nothing to report, and re-parks — the wake is
///    spent;
/// 3. the transmit pump reaches an EARLIER producer first (services are pumped
///    before queries) and the driver sits in that send's `.await` while the
///    absolute deadline passes. The query walk reads its own instant at the poll
///    that would draw the question, so the query is finally polled past its own
///    deadline;
/// 4. nothing else the driver holds is due — asserted, not assumed.
///
/// A `Query::poll_transmit` that took the query's terminal there and reported it
/// as the `Ok(None)` an idle poll returns would leave this driver nothing to act
/// on: the one-shot terminal wake belongs to the encode-error path and is not
/// armed here, and the terminal itself clears the query's deadline, so
/// `poll_deadline` has nothing left to fold for it. The driver parks, and the
/// waiter from step 2 is never woken by anything it was owed — its terminal sits
/// undelivered and the query's storage stays pinned for as long as the handle
/// lives.
///
/// The future is driven by hand with a counting waker instead of being spawned
/// because the fault IS the missing wake: polled by hand its absence is an
/// assertion, spawned it would only be a test that hangs.
#[test]
fn a_query_ended_past_its_deadline_wakes_the_next_parked_on_it() {
  use core::{
    future::Future,
    task::{Context, Poll, Waker},
  };
  use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  };

  use mdns_proto::{Name, QuerySpec, QueryUpdate, wire::ResourceType};

  /// Counts wakes instead of resuming a task, so "was the parked waiter woken?"
  /// is answerable without a runtime, a timer, or a spawn.
  #[derive(Default)]
  struct WakeCount(AtomicUsize);

  impl WakeCount {
    fn count(&self) -> usize {
      self.0.load(Ordering::Relaxed)
    }

    fn reset(&self) {
      self.0.store(0, Ordering::Relaxed);
    }
  }

  impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::Relaxed);
    }
  }

  let inner = EndpointInner::new(
    mdns_proto::EndpointConfig::new().with_probe_unique_names(false),
    1500,
    9000,
  );
  // `establish_service`'s ladder: 40 rounds 300 ms apart.
  const ESTABLISH_LADDER: Duration = Duration::from_secs(12);
  // How much of the caller's window is still open, in REAL time, when the pump
  // first draws the question. Wide enough that reaching that draw inside it is
  // not a race.
  const WINDOW_STILL_OPEN: Duration = Duration::from_millis(500);
  // What the fan-out the driver awaits actually costs — past the slack above, so
  // the window shuts while the driver is inside it.
  const AWAITED_FANOUT: Duration = Duration::from_millis(700);

  // The window the caller asks for, wide enough to hold the §5.2 retry armed
  // inside it.
  let window = Duration::from_millis(2500);

  // Protocol time and real time have to agree about the caller's window here,
  // because the query walk weighs it on an instant it reads itself while every
  // other instant below is one this test chooses. The schedule is therefore
  // anchored in the real past by the protocol time it spends before that window
  // shuts, less the slack that must still be open at the first draw. Neither
  // half is assumed: the slack is asserted before that draw and the crossing is
  // asserted after the fan-out.
  //
  // How far back the monotonic clock reaches is a property of the HOST, decided
  // before any of the behaviour below runs: a machine booted moments ago has no
  // instant this far in its past to anchor at. That is a setup this host cannot
  // provide, not an outcome, so it skips rather than fails.
  let Some(t0) = StdInstant::now().checked_sub(ESTABLISH_LADDER + window - WINDOW_STILL_OPEN)
  else {
    eprintln!("skipping: this host's monotonic clock is too young to subtract from");
    return;
  };
  let mut buf = vec![0u8; 4096];

  // The earlier producer: an established service, drained of its lifecycle
  // updates. Draining is load-bearing — an undrained `Established` would make
  // the post-pump `push_service_updates` bump `notify` and supply the very wake
  // this schedule must not have.
  let svc = {
    let mut s = inner.state.borrow_mut();
    s.test_register_service(delivery_test_spec("earlier"), t0)
      .unwrap()
  };
  let t_est = {
    let mut s = inner.state.borrow_mut();
    let t = establish_service(&mut s, svc, t0);
    let _ = s.push_service_updates(t);
    assert!(
      !s.push_service_updates(t),
      "premise: the established service must have nothing left to report"
    );
    assert!(
      s.endpoint.poll_timeout().is_none(),
      "premise: the endpoint itself must have nothing scheduled, so every \
       deadline in play below belongs to a producer this test controls"
    );
    t
  };

  // The query, and the caller parked on it.
  let deadline = t_est + window;
  let qh = {
    let mut s = inner.state.borrow_mut();
    let h = s
      .start_query(
        QuerySpec::new(
          Name::try_from_str("printer.local.").unwrap(),
          ResourceType::A,
        )
        .with_timeout(window),
        t_est,
      )
      .unwrap();
    assert!(
      StdInstant::now() < deadline,
      "premise: the caller's window must still be open on the clock the query \
       walk reads, or the first question would be withheld here instead of drawn"
    );
    let (_tx, origin) = s
      .poll_one_transmit(t_est, &mut buf)
      .expect("a newly-started query has its first question due");
    assert!(
      matches!(origin, TransmitOrigin::Query(h2) if h2 == h),
      "the idle service has nothing due, so the first datagram is the query's"
    );
    // Delivered everywhere, so the §5.2 ladder advances and the retry is armed
    // one second out — comfortably inside the caller's window.
    let fanout = whole_fanout(t_est);
    let _ = s.note_query_transmit_outcome(h, t_est, fanout.v4, fanout.v6);
    h
  };
  let query = crate::Query {
    inner: Rc::clone(&inner),
    handle: qh,
    terminal_delivered: Cell::new(false),
  };

  let wakes = Arc::new(WakeCount::default());
  let waker = Waker::from(Arc::clone(&wakes));
  let mut cx = Context::from_waker(&waker);
  let next = query.next();
  futures::pin_mut!(next);
  assert!(
    next.as_mut().poll(&mut cx).is_pending(),
    "the caller parks: no answer has arrived and the query is still running"
  );

  // ── The iteration that arms the retry ────────────────────────────────────
  let t1 = t_est + Duration::from_secs(1);
  let legacy_querier = core::net::SocketAddr::from(([192, 168, 1, 50], 6000));
  {
    let mut s = inner.state.borrow_mut();
    // A §6.7 legacy querier: exactly one unicast reply, due immediately, and
    // once it is confirmed the service is back to nothing due in this window.
    inject_ptr_query(&mut s, legacy_querier, t1);
    s.fire_timeouts(t1);
    assert_eq!(
      s.endpoint.poll_query_timeout(qh),
      Some(deadline),
      "the retry is ARMED, not scheduled, so the absolute deadline is now the \
       query's whole schedule"
    );
  }
  inner.notify.notify(); // the run loop's post-timer `woke_state` bump
  assert!(
    wakes.count() > 0,
    "the timer wake must reach the parked waiter"
  );
  assert!(
    next.as_mut().poll(&mut cx).is_pending(),
    "the query is merely armed — nothing to report, so the waiter re-parks and \
     that wake is spent"
  );
  wakes.reset();

  // ── The iteration whose pump crosses the deadline ────────────────────────
  let t_past = deadline + Duration::from_millis(10);
  {
    let mut s = inner.state.borrow_mut();
    // Pump pass 1: services before queries, so the earlier producer's datagram
    // is the one this iteration awaits.
    let (tx, origin) = s
      .poll_one_transmit(t1, &mut buf)
      .expect("the legacy reply is due");
    assert!(
      matches!(origin, TransmitOrigin::Service(h) if h == svc),
      "the earlier producer must be the one the pump serves first"
    );
    assert!(
      !tx.dst().ip().is_multicast(),
      "a §6.7 legacy reply is unicast back to its querier"
    );
    // The driver is inside `send_via().await` for it, and the caller's window
    // closes while it is there — in real time as much as in protocol time, since
    // the query walk below weighs that window on the clock it reads itself.
    std::thread::sleep(AWAITED_FANOUT);
    let fanout = unicast_fanout(t_past);
    let _ = s.note_service_transmit_outcome(svc, t_past, fanout.v4, fanout.v6);
    assert!(
      StdInstant::now() >= deadline,
      "the awaited fan-out must have carried the real clock out of the caller's \
       window too, or the withholding below would be this test's own clock alone"
    );

    // Pump pass 2: the query walk reads its own instant, and the question is
    // drawn past the caller's deadline.
    assert!(
      s.poll_one_transmit(t_past, &mut buf).is_none(),
      "no question may go out at or after the caller's absolute deadline"
    );
    assert_eq!(
      s.endpoint.poll_query_timeout(qh),
      Some(deadline),
      "and the query must still publish the deadline that ENDS it: this is the \
       wake the driver folds into its park, and a terminal taken inside that \
       `Ok(None)` would have cleared it — the driver would then be parking on a \
       query it has no reason left to come back to"
    );
  }

  // ── The post-pump settle, in the run loop's order ────────────────────────
  //
  // No I/O, no clock advance, no invented timer: whatever wakes the caller now
  // has to be work this driver can see.
  let fired_due_deadline = {
    let mut s = inner.state.borrow_mut();
    s.sweep_cancelled_services(t_past);
    s.sweep_cancelled_queries();
    if s.push_service_updates(t_past) {
      inner.notify.notify();
    }
    if s.take_query_terminal_wakes() {
      inner.notify.notify();
    }
    assert!(
      s.services[&svc]
        .proto
        .poll_timeout()
        .is_some_and(|at| at > t_past),
      "premise: the earlier producer's own next tick is its §8.3 re-announcement, \
       far beyond this window — it cannot stand in for the wake the query owes"
    );
    match s.poll_deadline() {
      // Already due: the run loop's zero-duration timer arm, which fires the
      // timeouts in this same iteration and bumps `notify` (`woke_state`).
      Some(at) if at <= t_past => {
        s.fire_timeouts(t_past);
        true
      }
      // Anything else is a timer the driver parks on. This schedule has none,
      // and the test will not invent one to rescue the waiter.
      _ => false,
    }
  };
  if fired_due_deadline {
    inner.notify.notify();
  }

  assert!(
    wakes.count() > 0,
    "the driver settled with nothing it could act on, so the `Query::next` \
     parked on this query is never woken again — its terminal was taken behind \
     an `Ok(None)` indistinguishable from an idle poll, and taking it cleared \
     the very deadline that would have woken the caller"
  );
  match next.as_mut().poll(&mut cx) {
    Poll::Ready(Some(crate::QueryEvent::Terminal(QueryUpdate::Timeout))) => {}
    other => panic!("the woken caller must observe the timeout terminal, got {other:?}"),
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
  handle_recv(&inner, Family::V4, Err(err));

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
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    0,
    Some(255),
    RxEvidence::none(),
    len,
  )
  .with_truncated();

  let before = inner.state.borrow().stats.snapshot();
  assert_eq!(before.packets_rx, 0);
  assert_eq!(before.bytes_rx, 0);
  assert_eq!(before.packets_dropped, 0);

  handle_recv(&inner, Family::V4, Ok((data, meta)));

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
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    1,
    Some(255),
    RxEvidence::none(),
    len,
  );
  // `truncated()` must be false — the normal routing path.
  assert!(
    !meta.truncated(),
    "sanity: RecvMeta::new must not set truncated"
  );

  handle_recv(&inner, Family::V4, Ok((data, meta)));

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
          let _ = s.note_service_transmit_outcome(
            h,
            t,
            FamilyAttempt::Accepted { at: t },
            FamilyAttempt::Accepted { at: t },
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
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    1,
    Some(255),
    RxEvidence::none(),
    conflict.len(),
  );

  let mut scratch = [0u8; 1500];
  let mut decisive_before: Option<bool> = None;
  let mut decisive_after: Option<bool> = None;

  for _ in 0..80 {
    t += Duration::from_millis(300);
    s.fire_timeouts(t);
    s.handle_datagram(Family::V4, &peer, &conflict);
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

// ── The dual-stack delivery boundary (`FamilyAttempt`) ──────────────────────

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
  let mut rounds = 0;
  while let Some((_tx, origin)) = s.poll_one_transmit(t, buf) {
    match origin {
      TransmitOrigin::Service(origin_h) if origin_h == h => {
        let _ = s.note_service_transmit_outcome(h, t, fanout.v4, fanout.v6);
        rounds += 1;
      }
      TransmitOrigin::Service(other) => {
        let _ = s.note_service_transmit_outcome(other, t, fanout.v4, fanout.v6);
      }
      TransmitOrigin::Query(q) => {
        let _ = s.note_query_transmit_outcome(q, t, fanout.v4, fanout.v6);
      }
    }
  }
  rounds
}

/// A dual-stack fan-out in which v4 carried the datagram at `at` and a BOUND v6
/// socket rejected it (`ENETUNREACH` and friends). Driving the behaviour tests
/// from the per-family facts rather than a hand-fed delivery shape keeps the
/// mapping inside the tested path.
fn partial_fanout(at: StdInstant) -> Fanout {
  Fanout {
    v4: FamilyAttempt::Accepted { at },
    v6: FamilyAttempt::Refused { permanent: false },
  }
}

/// Both bound families carried the datagram, at `at`.
fn whole_fanout(at: StdInstant) -> Fanout {
  Fanout {
    v4: FamilyAttempt::Accepted { at },
    v6: FamilyAttempt::Accepted { at },
  }
}

/// Both bound families rejected it — nothing reached any wire.
fn failed_fanout() -> Fanout {
  Fanout {
    v4: FamilyAttempt::Refused { permanent: false },
    v6: FamilyAttempt::Refused { permanent: false },
  }
}

/// The classification each completed attempt gets — raw [`SendAttempt`] to
/// [`FamilyAttempt`] — is the only piece of the old per-family table still this
/// driver's own: what a family's answer becomes IS the whole of what this
/// driver tells the core now that [`Fanout`] carries the two families'
/// [`FamilyAttempt`]s with no projection of its own. The core's projection of
/// that onto `Delivered`/`Missed`/`Unobligated`, and how a pair of them combine,
/// is internal to `mdns_proto` and asserted once, in its own suite.
#[test]
fn a_completed_attempt_classifies_into_exactly_one_family_attempt() {
  let body = *b"classification-probe";
  let at = StdInstant::now();
  let cases: [(&str, SendAttempt, FamilyAttempt<StdInstant>); 4] = [
    (
      "no socket bound",
      SendAttempt::Unbound,
      FamilyAttempt::NoSocket,
    ),
    (
      "withheld by the wire gate",
      SendAttempt::Gated,
      FamilyAttempt::GateShut,
    ),
    (
      "the socket accepted it",
      SendAttempt::Answered {
        result: Ok(body.len()),
        submitted_wall: SystemTime::now(),
        submitted_at: at,
        completed_at: at,
      },
      FamilyAttempt::Accepted { at },
    ),
    (
      "the socket refused it",
      SendAttempt::Answered {
        result: Err(std::io::Error::from(std::io::ErrorKind::Other)),
        submitted_wall: SystemTime::now(),
        submitted_at: at,
        completed_at: at,
      },
      FamilyAttempt::Refused { permanent: false },
    ),
  ];
  for (label, attempt, want) in cases {
    assert_eq!(
      attempt_of(Family::V4, &body, &attempt),
      want,
      "{label} must classify as {want:?}"
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
    confirm_service_round(&mut s, h, now, &mut buf, partial_fanout(now)),
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
    confirm_service_round(&mut s, h, now, &mut buf, whole_fanout(now)),
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
    confirm_service_round(&mut s, h, now, &mut buf, failed_fanout()),
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
    confirm_service_round(&mut s, handle, t, &mut buf, whole_fanout(t));
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
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    1,
    Some(255),
    RxEvidence::none(),
    conflict.len(),
  );
  let mut renamed = false;
  for _ in 0..80 {
    t += Duration::from_millis(250);
    s.handle_datagram(Family::V4, &peer, &conflict);
    confirm_service_round(&mut s, handle, t, &mut buf, whole_fanout(t));
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
  let token = s
    .poll_one_withdrawal(t, &mut buf)
    .expect("the renamed-away old name must have a detached goodbye pending")
    .token();
  s.note_withdrawal_result(
    token,
    t,
    FamilyAttempt::Accepted { at: t },
    FamilyAttempt::Refused { permanent: false },
  );

  // The application reclaims the vacated name.
  let rh = s
    .test_register_service(delivery_test_spec("Old"), t)
    .expect("the vacated name must be re-registerable while its goodbye drains");

  // Drive the replacement's §8.1 probes to completion (a probe is a question and
  // opens no gate) so the next round is its FIRST announcement.
  for _ in 0..12 {
    t += Duration::from_millis(300);
    confirm_service_round(&mut s, rh, t, &mut buf, whole_fanout(t));
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
  confirm_service_round(&mut s, rh, t, &mut buf, partial_fanout(t));
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
  confirm_service_round(&mut s, rh, t, &mut buf, whole_fanout(t));
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
/// `SELF_SEND_TTL`, and at `MAX_SELF_SEND_ENTRIES` a record declines the NEW entry
/// — so a legacy-query flood would starve the genuine multicast credits that
/// loopback suppression depends on.
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
    // A §6.7 reply is one-shot and therefore ungated.
    &mut FamilyWireGate::default(),
    Duration::ZERO,
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
    inner.state.borrow().selfsend.is_empty(),
    "a unicast reply never loops back, so it must record NO self-send credit"
  );
}

// ── The two clocks a self-send credit carries ───────────────────────────────
//
// A credit holds a wall stamp and a monotonic one, they answer different
// questions, and this driver's own copy of the tracker folded them together
// until it was deleted for the shared `hick_udp::selfsend`. The two below pin
// each half at the seam this crate owns: the ordering stamp, weighed at
// `handle_datagram`, and the ageing stamp, which nothing but the monotonic clock
// may decide.

/// A wall clock that stepped backwards after the send must not make this
/// endpoint ingest its own announcement as a peer's.
///
/// The credit's wall stamp is read before the `sendto`, the kernel stamps the
/// loopback copy on whatever timeline the clock holds when it arrives, and an NTP
/// correction, a `settimeofday` or a VM resume in between leaves the two on
/// different timelines. Weighed as ordering evidence the echo then looks like a
/// peer datagram the kernel saw BEFORE our own send, and the credit is refused:
/// the endpoint ingests its own announcement as peer traffic and raises a phantom
/// RFC 6762 §9 conflict against itself — repeatedly, for as long as the clock
/// keeps stepping. The step is detected instead, the unusable ordering evidence
/// is discarded, and the claim falls back to content-plus-family inside the TTL.
///
/// Expressed as a credit whose wall stamp is an hour AHEAD of every later
/// reading, which is what an hour-backwards step looks like from the far side of
/// it. The monotonic halves are real, so the two elapsed times disagree by the
/// whole step.
#[test]
fn a_backwards_wall_step_must_not_turn_our_own_echo_into_a_phantom_self_conflict() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use hick_udp::selfsend::WALL_STEP_TOLERANCE;

  use crate::socket::RecvMeta;

  const STEP: Duration = Duration::from_secs(3600);
  assert!(
    STEP > WALL_STEP_TOLERANCE,
    "the fixture must present a step, not the slew a disciplined clock shows"
  );

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
  s.bound_interface = 1;

  // A minimal empty query header: QR=0, so the §11 untrusted-response gate does
  // not fire and the datagram reaches the self-send match.
  let body: Vec<u8> = vec![0u8; 12];
  let on_link = |rx: SystemTime| {
    RecvMeta::new(
      SocketAddr::from(([127, 0, 0, 1], 5353)),
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
      1,
      Some(255), // §11 on-link
      RxEvidence::from_stamp_for_test(rx),
      body.len(),
    )
  };

  // The multicast send, with the pre-submit pair `note_multicast_attempt` hands
  // over, and the pre-park seal opening its claim window.
  let stepped = ClockPair::new(SystemTime::now() + STEP, StdInstant::now());
  s.selfsend.record(Family::V4, &body, stepped);
  s.selfsend.seal();
  #[cfg(debug_assertions)]
  s.note_park_entry();
  assert_eq!(s.selfsend.len(), 1, "one credit is outstanding");

  // Our own echo, stamped by the kernel on the post-step timeline and therefore
  // an hour before the credit it belongs to.
  s.handle_datagram(Family::V4, &on_link(SystemTime::now()), &body);
  assert!(
    s.selfsend.is_empty(),
    "the credit's two elapsed times disagree by an hour, so its wall stamp is not \
     on the timeline the receive stamp was taken on and orders nothing — refusing \
     the credit here is a phantom conflict against ourselves"
  );

  // The control, and it is what keeps the assertion above about the STEP rather
  // than about ordering having been dropped altogether: with both stamps on one
  // timeline the ordering rule is intact, and a datagram the kernel saw before
  // our send is a peer's.
  let unstepped = ClockPair::now();
  s.selfsend.record(Family::V4, &body, unstepped);
  s.selfsend.seal();
  #[cfg(debug_assertions)]
  s.note_park_entry();
  s.handle_datagram(
    Family::V4,
    &on_link(unstepped.wall - Duration::from_secs(1)),
    &body,
  );
  assert_eq!(
    s.selfsend.len(),
    1,
    "nothing stepped inside this credit's window, so a datagram the kernel \
     stamped a second before our sendto must not steal it"
  );
}

/// `SELF_SEND_TTL` is measured on the monotonic clock, and a wall-clock step must
/// neither expire a live credit nor resurrect a dead one.
///
/// Ageing is a duration question, and the wall clock answers it wrongly twice
/// over: it steps, and the only wall stamp a send has is read BEFORE its syscall,
/// so every microsecond between that read and the kernel accepting the datagram
/// would be charged to the credit's life. Both directions are asserted because a
/// one-sided implementation — say one that clamped a backwards step — would pass
/// either half alone.
///
/// Every claim here presents no kernel receive stamp, so no ordering evidence is
/// weighed and the TTL is the only thing that can decide the outcome.
#[test]
fn the_self_send_ttl_is_measured_monotonically_not_on_the_wall_clock() {
  use hick_udp::selfsend::SELF_SEND_TTL;

  let mut t = SelfSendTracker::new();
  let sent = ClockPair::new(
    SystemTime::UNIX_EPOCH + Duration::from_secs(10_000),
    StdInstant::now(),
  );

  // A wall clock hours ahead of the send, five milliseconds of real time later.
  // Aged on the wall clock this credit is hours past a two-second TTL and its own
  // echo reaches the protocol layer as a peer's.
  t.record(Family::V6, b"announcement", sent);
  t.seal_at(sent.mono);
  let wall_ran_ahead = ClockPair::new(
    sent.wall + Duration::from_secs(3 * 3600),
    sent.mono + Duration::from_millis(5),
  );
  assert!(
    t.take_at(
      Family::V6,
      b"announcement",
      RxEvidence::none(),
      wall_ran_ahead
    ),
    "five milliseconds of real time elapsed, so the credit is live however far \
     the wall clock jumped"
  );

  // The other direction: real time ran past the TTL while the wall clock stood
  // still. Aged on the wall clock this credit reads as newborn and would swallow
  // a co-resident peer's byte-identical datagram indefinitely.
  t.record(Family::V6, b"announcement", sent);
  t.seal_at(sent.mono);
  let expired = sent.mono + SELF_SEND_TTL + Duration::from_millis(1);
  assert!(
    !t.take_at(
      Family::V6,
      b"announcement",
      RxEvidence::none(),
      ClockPair::new(sent.wall, expired)
    ),
    "the monotonic clock is past the TTL, so the credit is dead however the wall \
     clock reads"
  );
  assert_eq!(
    t.len(),
    1,
    "and it was refused rather than matched — a dead credit is not consumed"
  );
  // Nor does a wall clock that stepped BACKWARDS revive it.
  assert!(
    !t.take_at(
      Family::V6,
      b"announcement",
      RxEvidence::none(),
      ClockPair::new(sent.wall - Duration::from_secs(900), expired)
    ),
    "a backwards step cannot buy a dead credit more window than the monotonic \
     clock allows"
  );
}

// ── The per-family wire gate ────────────────────────────────────────────────

/// What `Transmit::min_family_gap()` carries for an RFC 6762 §8.3 unsolicited
/// announcement — the one-second floor §6 puts on re-multicasting a record on the
/// same interface. Restated here because the core's copy is crate-private.
const ANNOUNCE_MIN_FAMILY_GAP: Duration = Duration::from_secs(1);

/// What it carries for a §8.1 probe, which is explicitly EXEMPT from that
/// one-second rule and spaced by its own inter-probe interval instead.
const PROBE_MIN_FAMILY_GAP: Duration = Duration::from_millis(250);

/// The gate is kind-dependent, which is precisely why the driver may not pick the
/// number: a driver that hardcoded §6's one second would stretch the §8.1 probe
/// sequence fourfold, and one that hardcoded 250 ms would breach §6 on every
/// announcement. The value arrives on the `Transmit`; only the WHEN is the
/// driver's.
#[test]
fn the_wire_gate_holds_each_kind_to_its_own_minimum() {
  let mut gate = FamilyWireGate::default();
  let t0 = StdInstant::now();

  assert!(
    gate.open(FAMILY_V6, t0, ANNOUNCE_MIN_FAMILY_GAP),
    "a family that has carried nothing owes no gap"
  );
  gate.record(FAMILY_V6, t0, ANNOUNCE_MIN_FAMILY_GAP);

  let skewed = t0 + Duration::from_millis(850);
  assert!(
    !gate.open(FAMILY_V6, skewed, ANNOUNCE_MIN_FAMILY_GAP),
    "an announcement 850 ms after this family's own last one is inside §6 /      §8.3's floor for that interface, however the confirm anchored"
  );
  assert!(
    gate.open(FAMILY_V6, skewed, PROBE_MIN_FAMILY_GAP),
    "…yet a §8.1 probe at the same instant is fine: probes are exempt from the      one-second rule and carry their own 250 ms minimum"
  );
  assert!(
    gate.open(FAMILY_V6, skewed, Duration::ZERO),
    "…and a one-shot reply is ungated entirely — a gate could only drop it"
  );
  assert!(
    gate.open(FAMILY_V4, skewed, ANNOUNCE_MIN_FAMILY_GAP),
    "the gate is per family: v4's wire owes nothing because of what v6 carried"
  );
  assert!(
    gate.open(
      FAMILY_V6,
      t0 + ANNOUNCE_MIN_FAMILY_GAP,
      ANNOUNCE_MIN_FAMILY_GAP
    ),
    "exactly one interval later the floor is paid"
  );

  // An ungated send must leave no trace, or a §6 reply would defer the
  // announcement that follows it.
  let mut ungated = FamilyWireGate::default();
  ungated.record(FAMILY_V4, t0, Duration::ZERO);
  assert!(
    ungated.open(FAMILY_V4, t0, ANNOUNCE_MIN_FAMILY_GAP),
    "a one-shot send does not start the clock on the next announcement"
  );
}

/// What a §5.2 question carries: "the interval between the first two queries
/// MUST be at least one second", and the backoff only widens from there.
/// Restated here for the same reason the other two are — the core's copy is
/// crate-private.
const QUERY_MIN_FAMILY_GAP: Duration = Duration::from_secs(1);

/// A socket whose sends SUCCEED but only after sitting pending, recording the
/// instant each one actually reached the wire.
///
/// The pending time is what no real host lets a test choose, and it is exactly
/// the variable the wire gate must not be allowed to spend: a gate anchored
/// before submission gives back every millisecond a send spent in flight.
struct DelayedSender {
  /// Which family's socket this stands in for. Every event it logs carries it, so
  /// the fan-out's event order can be read per family.
  family: usize,
  /// Per-call pending durations, consumed in order; exhausted calls complete
  /// immediately.
  pending: RefCell<std::collections::VecDeque<Duration>>,
  /// When each successful send actually put bytes on the wire — read INSIDE the
  /// socket, so it owes nothing to how the driver stamps anything.
  wire_times: RefCell<Vec<StdInstant>>,
}

impl DelayedSender {
  fn new(family: usize, pending: &[Duration]) -> Self {
    Self {
      family,
      pending: RefCell::new(pending.iter().copied().collect()),
      wire_times: RefCell::new(Vec::new()),
    }
  }
}

impl SendDatagram for DelayedSender {
  async fn send_to(&self, buf: &[u8], _dst: SocketAddr) -> std::io::Result<usize> {
    // Logged on ENTRY, ahead of any pending time: the event marks the point this
    // family's socket was handed the datagram, which is what its admission
    // reading is supposed to sit immediately before. Logging it at completion
    // instead would make the order depend on how long each socket took.
    note_fanout_event(FanoutEvent::Send(self.family));
    let pending = self
      .pending
      .borrow_mut()
      .pop_front()
      .unwrap_or(Duration::ZERO);
    if !pending.is_zero() {
      compio::time::sleep(pending).await;
    }
    self.wire_times.borrow_mut().push(StdInstant::now());
    Ok(buf.len())
  }
}

/// How often a gated round is retried, standing in for the run loop's own
/// re-entry. Only granularity: a coarser value can delay a send but never let
/// one out early.
const GATED_RETRY_POLL: Duration = Duration::from_millis(5);

/// Put `pending.len()` gated multicast datagrams from ONE producer onto ONE
/// family through the real [`send_via`], retrying a gated round the way the run
/// loop does, and return the instants the SOCKET recorded for them.
///
/// Only v4 is bound, so every wire time belongs to one family and the gaps
/// between them are that family's own wire spacing.
async fn same_family_wire_times(min_gap: Duration, pending: &[Duration]) -> Vec<StdInstant> {
  let inner = Rc::new(EndpointInner::new(
    mdns_proto::EndpointConfig::default(),
    1500,
    9000,
  ));
  let sender = Rc::new(DelayedSender::new(FAMILY_V4, pending));
  let sock_v4 = Some(sender.clone());
  let sock_v6: Option<Rc<DelayedSender>> = None;
  let mut gate = FamilyWireGate::default();

  for i in 0..pending.len() {
    // A distinct body per round, so nothing about self-send bookkeeping can
    // make one round's datagram stand in for another's.
    let body = [b'g', b'a', b'p', i as u8];
    loop {
      let fanout = send_via(
        &inner,
        &sock_v4,
        &sock_v6,
        MDNS_V4_DST,
        &body,
        &mut gate,
        min_gap,
      )
      .await;
      match fanout.v4 {
        FamilyAttempt::Accepted { .. } => break,
        FamilyAttempt::GateShut => compio::time::sleep(GATED_RETRY_POLL).await,
        other => {
          panic!("a delayed-but-successful send must be Accepted or GateShut, got {other:?}")
        }
      }
    }
  }
  sender.wire_times.take()
}

/// A send that stays PENDING must not buy back the wire gap it owes.
///
/// The gate exists to space one family's bytes on one wire, so its anchor has to
/// be when the operation COMPLETED. Anchored before submission instead, a send
/// pending `P` re-opens its own family `P` early: at §8.1's 250 ms inter-probe
/// interval a 200 ms-pending probe leaves 50 ms of real spacing, and it does so
/// on exactly the slow-socket path the spacing protects. Measured from inside
/// the socket, so the assertion is the wire's own history and not the driver's
/// account of it.
async fn delayed_sends_keep_their_wire_gap(kind: &str, min_gap: Duration, pending: &[Duration]) {
  let wire_times = same_family_wire_times(min_gap, pending).await;
  assert_eq!(
    wire_times.len(),
    pending.len(),
    "{kind}: every round must have reached the wire exactly once"
  );
  for (i, pair) in wire_times.windows(2).enumerate() {
    let gap = pair[1].saturating_duration_since(pair[0]);
    assert!(
      gap >= min_gap,
      "{kind}: consecutive datagrams were {gap:?} apart on one family's wire, \
       inside the {min_gap:?} that kind owes it — the send pending {:?} before it \
       succeeded was credited to the gap",
      pending[i]
    );
  }
}

/// §8.1 probes: 250 ms apart on the wire, however long a probe sat pending. Two
/// pending rounds in a row, so the anchor is exercised on a later send and not
/// just the first.
#[compio::test]
async fn a_pending_probe_does_not_shorten_the_next_probes_wire_gap() {
  delayed_sends_keep_their_wire_gap(
    "probe",
    PROBE_MIN_FAMILY_GAP,
    &[
      Duration::from_millis(200),
      Duration::from_millis(200),
      Duration::ZERO,
    ],
  )
  .await;
}

/// §6 / §8.3 unsolicited announcements: one second apart on the wire.
#[compio::test]
async fn a_pending_announcement_does_not_shorten_the_next_ones_wire_gap() {
  delayed_sends_keep_their_wire_gap(
    "announcement",
    ANNOUNCE_MIN_FAMILY_GAP,
    &[Duration::from_millis(500), Duration::ZERO],
  )
  .await;
}

/// §5.2 questions: at least one second between the first two transmissions of
/// the same question on one interface.
#[compio::test]
async fn a_pending_query_does_not_shorten_the_next_ones_wire_gap() {
  delayed_sends_keep_their_wire_gap(
    "query",
    QUERY_MIN_FAMILY_GAP,
    &[Duration::from_millis(500), Duration::ZERO],
  )
  .await;
}

/// One thing a fan-out did, as it did it.
///
/// The two kinds share one timeline, which is what makes the reading's PLACEMENT
/// observable. Counting readings cannot: two taken back to back before either
/// send are still two, and are still one stale verdict for whichever family goes
/// second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FanoutEvent {
  /// Admission read the clock for this family.
  Admit(usize),
  /// This family's socket was handed the datagram.
  Send(usize),
}

thread_local! {
  /// What the fan-out did, oldest first. Written by the admission seam and by
  /// [`DelayedSender`], which is what puts both kinds of event on one timeline.
  static FANOUT_LOG: RefCell<Vec<FanoutEvent>> = const { RefCell::new(Vec::new()) };

  /// The instants admission will read, in call order, once armed.
  ///
  /// `None` — the state every other test in this file runs in — is the real
  /// clock. Per thread, and `#[compio::test]` polls the whole fan-out on the
  /// test's own.
  static SCRIPTED_ADMISSION: RefCell<Option<std::collections::VecDeque<StdInstant>>> =
    const { RefCell::new(None) };
}

fn note_fanout_event(event: FanoutEvent) {
  FANOUT_LOG.with(|log| log.borrow_mut().push(event));
}

/// The seam `admission_now` reads under `cfg(test)`.
///
/// Every read is logged, armed or not, so the log records what the code did
/// rather than what a script expected of it. An ARMED script that runs out is a
/// failure and not a fallback: quietly returning the real clock would hand the
/// decision to the host's timing in a test that exists to be decided by
/// arithmetic.
pub(super) fn scripted_admission_now(family: usize) -> StdInstant {
  note_fanout_event(FanoutEvent::Admit(family));
  SCRIPTED_ADMISSION.with(|script| match script.borrow_mut().as_mut() {
    None => StdInstant::now(),
    Some(readings) => readings.pop_front().unwrap_or_else(|| {
      panic!(
        "admission asked for more readings than were scripted for it (family \
         {family} found the script exhausted)"
      )
    }),
  })
}

/// Arms the admission script and clears the event log, and on drop requires that
/// admission took every reading it was given.
///
/// On drop, so a test that ends before its own assertions still reports a fan-out
/// that weighed fewer gaps than it had families rather than passing quietly.
struct ScriptedAdmission;

impl ScriptedAdmission {
  fn arm(readings: &[StdInstant]) -> Self {
    FANOUT_LOG.with(|log| log.borrow_mut().clear());
    SCRIPTED_ADMISSION.with(|script| {
      *script.borrow_mut() = Some(readings.iter().copied().collect());
    });
    Self
  }

  /// What the fan-out did since it was armed, oldest first.
  fn events(&self) -> Vec<FanoutEvent> {
    FANOUT_LOG.with(|log| log.borrow().clone())
  }
}

impl Drop for ScriptedAdmission {
  fn drop(&mut self) {
    let unread =
      SCRIPTED_ADMISSION.with(|script| script.borrow_mut().take().map_or(0, |r| r.len()));
    FANOUT_LOG.with(|log| log.borrow_mut().clear());
    // A test already unwinding carries its own report, and a second panic here
    // would abort the process and take that report with it.
    assert!(
      unread == 0 || std::thread::panicking(),
      "admission left {unread} of its scripted readings unread: it weighed fewer \
       gaps than the fan-out had families, which is one verdict shared across them"
    );
  }
}

/// Each family reads the clock at ITS OWN send point, with that family's
/// `send_to` as the next thing that happens.
///
/// That placement is the invariant, and it is not a count. Two readings taken
/// back to back before either send are still two readings, and are still one
/// stale verdict for whichever family goes second: everything between them and
/// that family's send — a scheduler pause, the first family's submission work —
/// is time the second family's gap was credited with but had not paid. So the
/// admission seam and the sockets write onto one timeline, and the SHAPE of it is
/// what is asserted.
///
/// Both families are given a reading that pays their floor, so both are admitted
/// and both send: the log then shows the interleaving rather than a verdict.
/// Neither socket has anything pending, so each completes inside the poll that
/// handed it the datagram and the fan-out's whole history is these four events.
/// Which family goes first is the fan-out's business and the assertion does not
/// care; that a family's reading is followed by ITS OWN send, with nothing in
/// between, is not.
#[compio::test]
async fn each_family_reads_the_clock_at_its_own_send_point() {
  /// The floor both families owe, and what the reading each is given pays.
  const GAP: Duration = ANNOUNCE_MIN_FAMILY_GAP;

  let inner = Rc::new(EndpointInner::new(
    mdns_proto::EndpointConfig::default(),
    1500,
    9000,
  ));
  let v4 = Rc::new(DelayedSender::new(FAMILY_V4, &[]));
  let v6 = Rc::new(DelayedSender::new(FAMILY_V6, &[]));
  let sock_v4 = Some(v4.clone());
  let sock_v6 = Some(v6.clone());

  // An origin, not a measurement.
  let t0 = StdInstant::now();
  let mut gate = FamilyWireGate::default();
  gate.record(FAMILY_V4, t0, GAP);
  gate.record(FAMILY_V6, t0, GAP);

  let script = ScriptedAdmission::arm(&[t0 + GAP, t0 + GAP]);
  let fanout = send_via(
    &inner,
    &sock_v4,
    &sock_v6,
    MDNS_V4_DST,
    b"announce",
    &mut gate,
    GAP,
  )
  .await;
  let events = script.events();

  assert!(
    matches!(fanout.v4, FamilyAttempt::Accepted { .. })
      && matches!(fanout.v6, FamilyAttempt::Accepted { .. }),
    "both families were given a reading that pays their floor, so both must carry \
     the datagram — a withheld family sends nothing and would leave nothing to \
     order. Got v4 {:?}, v6 {:?}",
    fanout.v4,
    fanout.v6
  );

  match events.as_slice() {
    [
      FanoutEvent::Admit(first),
      FanoutEvent::Send(first_sent),
      FanoutEvent::Admit(second),
      FanoutEvent::Send(second_sent),
    ] if first == first_sent && second == second_sent && first != second => {}
    other => panic!(
      "each family must read the clock at its own send point, so the fan-out's \
       history is one family's reading, that family's send, then the other \
       family's pair. A reading that sits before ANOTHER family's send is a \
       reading taken before this family's — the pass-wide reading under a shorter \
       name — however many of them there are. Got {other:?}"
    ),
  }
}

/// Every family weighs its gap against ITS OWN reading: the fan-out does not take
/// one reading and hand the same verdict to both.
///
/// The companion to the ordering above, in the gate's own vocabulary. The pump
/// reads its instant before `poll_one_transmit` walks every producer, and may
/// then spend up to [`DRAIN_PASS_BUDGET`] serving the ones ahead of this fan-out,
/// so a reading taken before a family's own send point can understate how long
/// that family's wire has been idle and withhold a round it had already paid for.
/// A withheld family is not "nothing happened": it reaches the core as
/// [`FamilyAttempt::GateShut`], spending its partial-round patience and holding
/// the §8.1 probe sequence / §8.3 announce phase for a wire that was ready.
///
/// Both families start owing the same floor, and admission is scripted two
/// readings, only the later of which pays it. Weighed at their own send points
/// that is one family admitted and one withheld, whichever order the fan-out
/// polls them in. Weighed against a SINGLE reading — taken at the top of the
/// fan-out, or by the caller before the walk — both families get the stale
/// verdict and no family carries the datagram at all. Every instant here is
/// arithmetic on one origin, so nothing depends on what the host managed to
/// execute inside a given second.
#[compio::test]
async fn admission_is_weighed_per_family_not_once_per_fan_out() {
  /// The floor both families owe, and the distance between the two readings.
  const GAP: Duration = ANNOUNCE_MIN_FAMILY_GAP;
  /// How far into that floor the earlier reading falls. Anything short of `GAP`
  /// does; this is nowhere near it.
  const STALE: Duration = Duration::from_millis(10);

  let inner = Rc::new(EndpointInner::new(
    mdns_proto::EndpointConfig::default(),
    1500,
    9000,
  ));
  // Nothing pending on either socket: what is under test is when the gap is
  // WEIGHED, not what a completed send anchors it at.
  let v4 = Rc::new(DelayedSender::new(FAMILY_V4, &[]));
  let v6 = Rc::new(DelayedSender::new(FAMILY_V6, &[]));
  let sock_v4 = Some(v4.clone());
  let sock_v6 = Some(v6.clone());

  // An origin, not a measurement.
  let t0 = StdInstant::now();
  let mut gate = FamilyWireGate::default();
  gate.record(FAMILY_V4, t0, GAP);
  gate.record(FAMILY_V6, t0, GAP);

  // Two readings for two families, and the guard requires both be taken: a
  // fan-out that read once leaves one behind and fails on the way out.
  let _script = ScriptedAdmission::arm(&[t0 + STALE, t0 + GAP]);
  let fanout = send_via(
    &inner,
    &sock_v4,
    &sock_v6,
    MDNS_V4_DST,
    b"announce",
    &mut gate,
    GAP,
  )
  .await;

  let outcomes = [fanout.v4, fanout.v6];
  let admitted = outcomes
    .iter()
    .filter(|o| matches!(o, FamilyAttempt::Accepted { .. }))
    .count();
  let withheld = outcomes
    .iter()
    .filter(|o| matches!(o, FamilyAttempt::GateShut))
    .count();
  assert_eq!(
    (admitted, withheld),
    (1, 1),
    "the two readings sit either side of the floor, so exactly one family had paid \
     it when the datagram was offered to IT and exactly one had not. One reading \
     shared across the fan-out is the stale one: it gives both families the same \
     verdict and withholds the round entirely. Got v4 {:?}, v6 {:?}",
    fanout.v4,
    fanout.v6
  );

  assert_eq!(
    v4.wire_times.borrow().len() + v6.wire_times.borrow().len(),
    1,
    "a withheld family submits no send at all, so exactly one copy may have \
     reached a wire"
  );
}

// ── The obligation tag (`TransmitObligation`) at the driver seam ────────────

/// A §6.7 legacy unicast reply reaches exactly ONE family, so its fan-out is
/// all-delivered by construction — the other family was not addressed, not missing.
fn unicast_fanout(at: StdInstant) -> Fanout {
  Fanout {
    v4: FamilyAttempt::Accepted { at },
    v6: FamilyAttempt::NotAddressed,
  }
}

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
      unicast_fanout(t)
    };
    match origin {
      TransmitOrigin::Service(origin_h) => {
        let _ = s.note_service_transmit_outcome(origin_h, t, fanout.v4, fanout.v6);
        if origin_h == h {
          rounds += 1;
        }
      }
      TransmitOrigin::Query(q) => {
        let _ = s.note_query_transmit_outcome(q, t, fanout.v4, fanout.v6);
      }
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
    Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
    1,
    Some(255), // §11 on-link
    RxEvidence::none(),
    n,
  );
  let _ = t;
  s.handle_datagram(Family::V4, &meta, &qbuf[..n]);
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
  confirm_service_round(&mut s, h, now, &mut buf, failed_fanout());
  assert!(
    !s.services[&h].proto.advertises_instance(),
    "a wholly-failed announcement exposes nothing"
  );

  // A §6.7 legacy querier is served over the one family its destination names.
  let legacy = core::net::SocketAddr::from(([192, 168, 1, 50], 6000));
  let t = now + Duration::from_millis(50);
  inject_ptr_query(&mut s, legacy, t);
  assert_eq!(
    confirm_service_round_mixed(&mut s, h, t, &mut buf, failed_fanout()),
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

// ── the pump weighs the caller's query window on its own clock ──────────────
//
// `QuerySpec::with_timeout` is a promise to whoever set it: no question is
// ADMITTED at or after the instant it makes absolute. The core keeps that
// promise inside `Query::poll_transmit`, weighed against the instant the driver
// hands in — so the promise is worth exactly what that reading is worth. The run
// loop re-reads once per pump iteration, but it hands that reading to
// `poll_one_transmit`, which snapshots and walks every service — and every
// preceding query — before a query poll can use it. Both maps are uncapped and
// nothing in that stretch awaits, so a re-read outside the call cannot stand in
// for one inside it.
//
// The §5.2 ladder underneath the same query is the opposite case and keeps the
// instant the call was given — see `poll_one_transmit`.

/// A walk that alone outlives the caller's whole window, so the crossing is this
/// stall's rather than a slow runner's.
const WALK_OUTLIVES_QUERY_WINDOW: Duration = Duration::from_millis(600);

/// The window the caller asks for. Short enough that the stall above clears it
/// several times over, long enough that entering the pump inside it is not a
/// race.
const CALLER_QUERY_WINDOW: Duration = Duration::from_millis(150);

/// A question drawn after the caller's window shut must not be handed back for
/// the run loop to send — and the query must still end where its deadline's
/// owner ends it.
///
/// The window is a real 150 ms measured from `start_query`, and the pump is made
/// to lose the CPU for 600 ms of it *inside* `poll_one_transmit`: after the run
/// loop's own per-iteration reading was taken, after the service walk, and with
/// the query poll still ahead. No `await` divides that stretch, so no
/// arrangement of the run loop outside the call can re-read across it — which is
/// what separates this from the awaited-send schedule
/// `a_query_ended_past_its_deadline_wakes_the_next_parked_on_it` covers.
///
/// What it catches: the query poll trusting the `now` the pump was handed. That
/// reading is *before* the deadline here — asserted rather than assumed, so a
/// slow host fails the premise loudly instead of passing on the already-expired
/// path — so a poll that trusts it draws a question the caller's window has in
/// fact already closed on, and returns it to be sent.
///
/// The closing half asserts the withheld question left the deadline standing:
/// withholding defers the terminal to `handle_timeout`, so a caller that would
/// have been told `Timeout` must still be told it, on the wakeup `poll_deadline`
/// already publishes.
#[test]
fn a_question_drawn_past_the_callers_window_is_withheld_inside_the_pump() {
  use mdns_proto::{Name, QuerySpec, QueryUpdate, wire::ResourceType};

  let mut s = State::new(
    mdns_proto::EndpointConfig::new().with_probe_unique_names(false),
    1500,
    9000,
  );
  let mut buf = vec![0u8; 4096];
  let t0 = StdInstant::now();

  // An earlier producer, so the walk this stall stands in for is one the pump
  // really performs. Driven to its own steady state at `t0` — fire what is due,
  // confirm what that yields, repeat — so its §8.3 successor is a full second
  // out and the pump reaches the query walk instead of returning ITS datagram.
  let svc = s
    .test_register_service(delivery_test_spec("earlier"), t0)
    .unwrap();
  for _ in 0..8 {
    let ctx = s.services.get_mut(&svc).unwrap();
    if ctx.proto.poll_timeout().is_none_or(|at| at > t0) {
      break;
    }
    let _ = ctx.proto.handle_timeout(t0);
    while let Ok(Some(_)) = ctx.proto.poll_transmit(t0, &mut buf) {
      let _ = ctx.proto.note_transmit_outcome(
        t0,
        FamilyAttempt::Accepted { at: t0 },
        FamilyAttempt::Accepted { at: t0 },
      );
    }
  }

  let qh = s
    .start_query(
      QuerySpec::new(
        Name::try_from_str("printer.local.").unwrap(),
        ResourceType::A,
      )
      .with_timeout(CALLER_QUERY_WINDOW),
      t0,
    )
    .unwrap();
  let deadline = s
    .endpoint
    .poll_query_timeout(qh)
    .expect("a query given a window publishes its absolute deadline");
  assert!(
    s.services[&svc]
      .proto
      .poll_timeout()
      .is_some_and(|at| at > deadline),
    "premise: the earlier producer must have nothing due inside the caller's \
     window, or the pump would return ITS datagram and never reach the query"
  );

  s.force_query_poll_delays_for_test(&[WALK_OUTLIVES_QUERY_WINDOW]);

  // Exactly what the run loop hands in: read immediately before the call, so
  // nothing outside `poll_one_transmit` can be blamed for its staleness.
  let now = StdInstant::now();
  assert!(
    now < deadline,
    "the pump must be entered inside the caller's window, or this asserts nothing"
  );
  let pumped = s.poll_one_transmit(now, &mut buf);
  assert!(
    StdInstant::now() >= deadline,
    "and the walk must have carried it out of the window"
  );

  assert!(
    pumped.is_none(),
    "a question drawn after the caller's window shut was handed back to be sent; \
     the query poll weighed a promise made to the caller against a reading taken \
     before a walk over two uncapped maps in this same call"
  );

  // Withheld, not ended: the terminal belongs to the deadline's owner, and the
  // wakeup that reaches it must survive the withholding.
  assert_eq!(
    s.endpoint.poll_query_timeout(qh),
    Some(deadline),
    "the withheld question must leave the deadline standing — it is the wakeup \
     `poll_deadline` folds, and the only thing left that can end this query"
  );
  assert!(
    s.poll_deadline().is_some_and(|at| at <= StdInstant::now()),
    "and that deadline is already past, so the driver is sent straight back"
  );

  s.fire_timeouts(deadline + Duration::from_millis(1));
  let mut terminal = None;
  while let Some(update) = s.endpoint.poll_query(qh) {
    terminal = Some(update);
  }
  assert!(
    matches!(terminal, Some(QueryUpdate::Timeout)),
    "the query must still end, and with the terminal its deadline's owner \
     produces; got {terminal:?}"
  );
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
/// `EMSGSIZE` is equally what a write past the currently-known path MTU with `DF`
/// set reports, and the next attempt may get past that after an MTU probe or a
/// route change.
#[test]
fn permanence_is_proved_by_the_size_and_never_by_the_errno() {
  let at = StdInstant::now();
  let err = || SendAttempt::Answered {
    result: Err(std::io::Error::from(std::io::ErrorKind::Other)),
    submitted_wall: SystemTime::now(),
    submitted_at: at,
    completed_at: at,
  };
  // An ordinary mDNS-sized body: three orders of magnitude inside the limit, and
  // the size at which a path-MTU refusal actually happens.
  let ordinary = vec![0u8; 1200];
  assert_eq!(
    attempt_of(Family::V4, &ordinary, &err()),
    FamilyAttempt::Refused { permanent: false },
    "a refusal of a datagram within the ceiling proves only that these bytes did \
     not go out now"
  );

  let past_v4 = vec![0u8; mdns_proto::constants::MAX_UDP_PAYLOAD_V4 + 1];
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
      &vec![0u8; mdns_proto::constants::MAX_UDP_PAYLOAD_V6 + 1],
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
#[test]
fn a_permanently_oversized_sustained_datagram_retires_its_producer() {
  use mdns_proto::{Name, ServiceSpec, records::ServiceRecords};

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let t0 = std::time::Instant::now();
  let mut recs = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("printer._ipp._tcp.local.").unwrap(),
    Name::try_from_str("host.local.").unwrap(),
    631,
    120,
  );
  recs.add_a([127, 0, 0, 1].into());
  let h = s.test_register_service(ServiceSpec::new(recs), t0).unwrap();

  // Draw the first §8.1 probe: a fresh service waits out §8.1's random 0-250 ms
  // initial delay first.
  let mut buf = vec![0u8; 4096];
  let mut now = t0;
  let mut drawn = false;
  for step in 1..=8u32 {
    now = t0
      .checked_add(Duration::from_millis(u64::from(step) * 100))
      .unwrap();
    let ctx = s.services.get_mut(&h).unwrap();
    ctx.proto.handle_timeout(now).unwrap();
    if ctx.proto.poll_transmit(now, &mut buf).unwrap().is_some() {
      drawn = true;
      break;
    }
  }
  assert!(drawn, "no probe was drawn within the §8.1 initial delay");

  // End to end through this driver's own classification: a body no IPv4 socket
  // can carry, refused by the kernel, on a single-stack host.
  let oversized = vec![0u8; mdns_proto::constants::MAX_UDP_PAYLOAD_V4 + 1];
  let refused = SendAttempt::Answered {
    result: Err(std::io::Error::from(std::io::ErrorKind::Other)),
    submitted_wall: SystemTime::now(),
    submitted_at: now,
    completed_at: now,
  };
  assert!(
    s.note_service_transmit_outcome(
      h,
      now,
      attempt_of(Family::V4, &oversized, &refused),
      FamilyAttempt::NoSocket,
    )
    .retire_producer(),
    "the one family this host has refused the probe's SIZE, so re-offering these \
     exact bytes can never put them on a wire"
  );
}

/// A monotonic instant `age` in the past, waiting for the clock if this process
/// has not been up that long yet.
///
/// `StdInstant` has no constructor and no epoch, so the only way to name an
/// instant a whole `SELF_SEND_TTL` ago is to subtract from a live reading — which
/// a process younger than the TTL cannot do. Waiting is a bounded precondition,
/// not a skip: the assertions below always run.
fn monotonic_instant_ago(age: Duration) -> StdInstant {
  loop {
    if let Some(t) = StdInstant::now().checked_sub(age) {
      return t;
    }
    std::thread::sleep(Duration::from_millis(25));
  }
}

/// The claim window must be open BEFORE the park, or the TTL bounds nothing on
/// the path it exists to bound.
///
/// `run` records this iteration's sends in its transmit and withdrawal pumps and
/// then parks in `select!`, whose recv arms hand a datagram to `handle_recv` in
/// that SAME iteration. A credit still unsealed when the park returns is live
/// UNCONDITIONALLY — `still_live` reads `aged_from: None` as "no window has
/// opened, so nothing can have been missed" — so a byte-identical peer datagram
/// arriving arbitrarily long after the send would be swallowed as our own echo.
/// This driver's park is bounded only by the next protocol deadline, and with no
/// deadline armed there is no bound at all.
///
/// So the seal is placed after the pumps and immediately before the recv arms are
/// armed, and this test stands on that placement: it seals the credit exactly as
/// the loop does, ages it past `SELF_SEND_TTL`, and drives the production receive
/// path. Remove the seal from `run` — the state this test builds is then
/// precisely what the loop hands `handle_datagram` — and the credit is consumed
/// instead of refused.
///
/// Both families are exercised because the four `select!` arms supply both: the
/// dual-stack branch arms `r4` and `r6` together, and each single-family branch
/// arms one. Whichever arm wins, the family it passes must find its own credit
/// already aged.
#[test]
fn a_credit_sealed_before_the_park_expires_across_it_and_cannot_suppress_a_peer() {
  use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

  use hick_udp::selfsend::SELF_SEND_TTL;

  use crate::socket::RecvMeta;

  for (family, peer, local) in [
    (
      Family::V4,
      SocketAddr::from(([192, 0, 2, 9], 5353)),
      IpAddr::V4(Ipv4Addr::LOCALHOST),
    ),
    (
      Family::V6,
      SocketAddr::from(([0xfe80, 0, 0, 0, 0, 0, 0, 9], 5353)),
      IpAddr::V6(Ipv6Addr::LOCALHOST),
    ),
  ] {
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);

    // A QR=0 query body, so the §11 untrusted-response gate cannot be what
    // refuses it and the datagram genuinely reaches the self-send match.
    let body = vec![0u8; 12];
    s.selfsend.record(family, &body, ClockPair::now());
    assert_eq!(s.selfsend.len(), 1, "the send recorded its credit");

    // The seal the loop performs after its pumps, with the window opened longer
    // ago than the TTL — which is what a park longer than the TTL amounts to.
    s.selfsend.seal_at(monotonic_instant_ago(
      SELF_SEND_TTL + Duration::from_millis(250),
    ));
    #[cfg(debug_assertions)]
    s.note_park_entry();

    // The park ends with a byte-identical datagram from a co-resident peer, on
    // port 5353 and on-link, offered to the production receive path.
    let meta = RecvMeta::new(
      peer,
      local,
      Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
      1,
      Some(255),
      RxEvidence::from_stamp_for_test(SystemTime::now()),
      body.len(),
    );
    s.handle_datagram(family, &meta, &body);

    assert_eq!(
      s.selfsend.len(),
      1,
      "{family:?}: the credit's window opened more than SELF_SEND_TTL before \
       this datagram arrived, so these bytes are a peer's and the credit must \
       NOT be consumed; an unsealed credit would have been spent here however \
       long the park lasted"
    );
  }
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
/// The three phases below are the loop's, in the loop's order, for both families
/// the `select!` arms can deliver.
#[test]
fn the_seal_predates_the_park_and_the_generation_proves_it() {
  use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

  use crate::socket::RecvMeta;

  for (family, peer, local) in [
    (
      Family::V4,
      SocketAddr::from(([192, 0, 2, 9], 5353)),
      IpAddr::V4(Ipv4Addr::LOCALHOST),
    ),
    (
      Family::V6,
      SocketAddr::from(([0xfe80, 0, 0, 0, 0, 0, 0, 9], 5353)),
      IpAddr::V6(Ipv6Addr::LOCALHOST),
    ),
  ] {
    let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let body = vec![0u8; 12];

    // Phase 1 — the pumps record. Until the seal these credits are ageless,
    // which is exactly the state a receive must never be reached in.
    s.selfsend.record(family, &body, ClockPair::now());
    assert!(
      s.selfsend.has_unsealed(),
      "{family:?}: a freshly recorded credit has no window yet; this is the \
       state a seal placed after the park would leave standing across it"
    );
    let before_seal = s.selfsend.seal_generation();

    // Phase 2 — the park entry, exactly as `run` reaches it: seal, then
    // capture the generation the receive will be checked against.
    s.selfsend.seal();
    assert!(
      !s.selfsend.has_unsealed(),
      "{family:?}: the boundary seal must close every credit the pumps recorded"
    );
    let at_boundary = s.selfsend.seal_generation();
    assert_eq!(
      at_boundary,
      before_seal + 1,
      "{family:?}: the boundary seal opened exactly one window"
    );
    // The park entry, exactly as `run` reaches it.
    #[cfg(debug_assertions)]
    s.note_park_entry();

    // Phase 3 — the park, then a receive. The park performs no tracker
    // operation, which is the whole claim: the generation observed at the
    // receive must be the one the boundary recorded.
    let meta = RecvMeta::new(
      peer,
      local,
      Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
      1,
      Some(255),
      RxEvidence::from_stamp_for_test(SystemTime::now()),
      body.len(),
    );
    s.handle_datagram(family, &meta, &body);
    assert_eq!(
      s.selfsend.seal_generation(),
      at_boundary,
      "{family:?}: no claim window may open between the park entry and \
       the receive; a seal that ran in the receive arm would show up here as a \
       later generation"
    );
    assert!(
      s.selfsend.is_empty(),
      "{family:?}: the datagram matched its own credit, so this test weighed a \
       real claim"
    );
  }
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
#[test]
fn a_legacy_query_from_an_ephemeral_port_is_never_offered_a_credit() {
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

  use crate::socket::RecvMeta;

  let mut s = State::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  s.local_subnets = vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)];
  s.bound_interface = 1;

  // QR=0, so the §11 untrusted-response gate does not fire and the datagram
  // genuinely reaches the self-send match.
  let body = vec![0u8; 12];
  let sent = ClockPair::now();
  s.selfsend.record(Family::V4, &body, sent);
  s.selfsend.seal_at(sent.mono);
  #[cfg(debug_assertions)]
  s.note_park_entry();
  assert_eq!(s.selfsend.len(), 1, "one credit is outstanding");

  // Degraded: no kernel receive stamp, so nothing orders this claim against the
  // send and content plus family plus the TTL is the whole of the match.
  let from = |port: u16| {
    RecvMeta::new(
      SocketAddr::from(([127, 0, 0, 1], port)),
      IpAddr::V4(Ipv4Addr::UNSPECIFIED),
      Some(IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP)),
      1,
      Some(255),
      RxEvidence::none(),
      body.len(),
    )
  };
  s.handle_datagram(Family::V4, &from(40000), &body);
  assert_eq!(
    s.selfsend.len(),
    1,
    "a datagram from a port this endpoint never sends from cannot be its own \
     echo, so it must not be offered the credit at all"
  );

  // And the credit is still there for the datagram it belongs to: the same bytes
  // arriving from 5353 are our echo and claim it.
  s.handle_datagram(Family::V4, &from(5353), &body);
  assert!(
    s.selfsend.is_empty(),
    "the genuine echo, from 5353, still finds the credit the legacy query was \
     refused"
  );
}

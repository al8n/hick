use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::{
  addr_in_subnet, addressed_to_group, admits_ingress, arrived_on_bound_interface, is_mdns_group,
  is_on_link, reports_rx_interface, src_on_local_link,
};

/// The interface this fixture's endpoint is pinned to.
const BOUND: u32 = 5;
/// Some other NIC on the same host.
const OTHER: u32 = 9;
/// A routable source inside [`SUBNETS`], so nothing below turns on the §11
/// fallback's own subnet rule.
const ON_SUBNET_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7));
/// The bound interface's configured subnets.
const SUBNETS: [(IpAddr, u8); 1] = [(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24u8)];

/// A **unicast** destination, per family: the arm of §11 that does consult the
/// source prefix. Every pre-existing case below passes one of these, because a
/// unicast destination is the condition they were all implicitly written under.
const UNICAST_V4_DST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
const UNICAST_V6_DST: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));

/// The two mDNS groups, the destinations §11 says establish local-link origin
/// on their own.
const V4_GROUP: IpAddr = IpAddr::V4(hick_udp::constants::MDNS_IPV4_GROUP);
const V6_GROUP: IpAddr = IpAddr::V6(hick_udp::constants::MDNS_IPV6_GROUP);

/// Routable sources on prefixes the bound interface does NOT have configured:
/// the overlaid-subnet host §11 names, which the source-prefix arm cannot admit
/// and must not be asked to.
const OFF_SUBNET_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 4, 4, 4));
const OFF_SUBNET_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xbeef, 0, 0, 0, 0, 1));

/// [`ON_SUBNET_IP`] as the peer the receive path actually hands the boundary.
fn on_subnet() -> SocketAddr {
  peer(ON_SUBNET_IP)
}

/// `ip` as a port-5353 peer. IPv6 peers built this way carry scope id `0`, the
/// "no zone" a global source has.
fn peer(ip: IpAddr) -> SocketAddr {
  SocketAddr::new(ip, 5353)
}

/// An IPv6 peer inside its zone: the address plus the scope id the kernel
/// attaches to a link-local source, which is the second witness of the link a
/// datagram came from.
fn scoped(ip: Ipv6Addr, scope: u32) -> SocketAddr {
  SocketAddr::V6(SocketAddrV6::new(ip, 5353, 0, scope))
}

/// A link-local IPv6 source, the family of address a scope id is really about.
const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

#[test]
fn ttl_255_is_on_link_and_lower_is_not() {
  assert!(is_on_link(Some(255)));
  assert!(!is_on_link(Some(254)));
  assert!(!is_on_link(Some(1)));
}

#[test]
fn missing_ttl_fails_open() {
  // We cannot prove on-link, but neither can we prove off-link.
  assert!(is_on_link(None));
}

#[test]
fn addr_in_subnet_v4_boundaries() {
  let net = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));
  assert!(addr_in_subnet(
    net,
    24,
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
  ));
  assert!(addr_in_subnet(
    net,
    24,
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))
  ));
  assert!(!addr_in_subnet(
    net,
    24,
    IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))
  ));
}

#[test]
fn prefix_zero_matches_everything_and_full_prefix_matches_exactly() {
  let net = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
  assert!(addr_in_subnet(
    net,
    0,
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
  ));
  assert!(addr_in_subnet(
    net,
    32,
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
  ));
  assert!(!addr_in_subnet(
    net,
    32,
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
  ));
}

#[test]
fn mismatched_families_never_match() {
  let net = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));
  assert!(!addr_in_subnet(net, 24, IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn addr_in_subnet_v6_byte_aligned_prefix() {
  let net = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0));
  // Same upper 64 bits, arbitrary lower 64 bits -> on-link at /64.
  assert!(addr_in_subnet(
    net,
    64,
    IpAddr::V6(Ipv6Addr::new(
      0x2001, 0x0db8, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0
    ))
  ));
  // Upper 64 bits differ -> off-link.
  assert!(!addr_in_subnet(
    net,
    64,
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, 0))
  ));
}

#[test]
fn addr_in_subnet_v6_partial_byte_prefix() {
  // /60 lands mid-byte (full = 7, rem = 4): the first 7 bytes must match
  // exactly, and only the top nibble of the 8th byte is significant.
  let net = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0x00a0, 0, 0, 0, 0));
  // Top nibble of the 8th byte matches (0xa_); the bottom nibble is free.
  assert!(addr_in_subnet(
    net,
    60,
    IpAddr::V6(Ipv6Addr::new(
      0x2001, 0x0db8, 0, 0x00af, 0x1234, 0x5678, 0x9abc, 0xdef0
    ))
  ));
  // Top nibble of the 8th byte differs (0x5_ vs 0xa_) -> off-link.
  assert!(!addr_in_subnet(
    net,
    60,
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0x0050, 0, 0, 0, 0))
  ));
}

#[test]
fn addr_in_subnet_v4_partial_byte_prefix_rem4() {
  // /20 lands mid-byte (full = 2, rem = 4): the first 2 bytes must match
  // exactly, and only the top nibble of the 3rd byte (0x50 -> 0x5_) is
  // significant.
  let net = IpAddr::V4(Ipv4Addr::new(10, 1, 0x50, 0));
  assert!(addr_in_subnet(
    net,
    20,
    IpAddr::V4(Ipv4Addr::new(10, 1, 0x5f, 222))
  ));
  assert!(!addr_in_subnet(
    net,
    20,
    IpAddr::V4(Ipv4Addr::new(10, 1, 0x60, 0))
  ));
}

#[test]
fn addr_in_subnet_v4_partial_byte_prefix_rem7() {
  // /31 lands mid-byte (full = 3, rem = 7): a classic point-to-point pair
  // where only the least-significant bit of the last byte is free.
  let net = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));
  assert!(addr_in_subnet(
    net,
    31,
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))
  ));
  assert!(!addr_in_subnet(
    net,
    31,
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6))
  ));
}

#[test]
fn prefix_beyond_address_width_is_rejected_not_clamped() {
  // A prefix wider than the address (33 on IPv4) is rejected outright rather
  // than clamped to 32 the way hick-reactor's `.min(32)`/`.min(128)` does.
  // This is a deliberate fail-closed choice for a trust boundary: an
  // out-of-range prefix here can only come from a corrupt or hostile
  // `local_subnets` entry, never from a well-formed OS-reported interface
  // prefix, so refusing to match anything is safer than silently widening
  // the match via clamping. `addr == net` here on purpose: even an
  // identical address is rejected, which shows the rejection is driven by
  // the prefix, not by an address mismatch.
  let net = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
  assert!(!addr_in_subnet(net, 33, net));
}

#[test]
fn link_local_v6_requires_matching_interface() {
  let src = peer(IpAddr::V6(LINK_LOCAL));
  // Packet arrived on the bound interface -> trusted.
  assert!(src_on_local_link(src, &[], BOUND, BOUND, true));
  // Packet arrived on a different interface -> not trusted.
  assert!(!src_on_local_link(src, &[], BOUND, OTHER, true));
  // Interface unknown (0) on a platform that never reports one -> absent
  // evidence, admitted degraded.
  assert!(src_on_local_link(src, &[], BOUND, 0, false));
  // The same zero from a platform that DOES report one is a failed proof, not
  // an absent one.
  assert!(!src_on_local_link(src, &[], BOUND, 0, true));
}

#[test]
fn a_link_local_source_must_also_match_on_its_scope_id() {
  // The link-local arm's own interface check used to be a bare `pkt_iface`
  // comparison, so a source whose zone said "another link" walked straight
  // through it on any platform that reports no index. The arm now runs the
  // whole rule, scope witness included.
  let foreign_zone = scoped(LINK_LOCAL, OTHER);
  assert!(!src_on_local_link(foreign_zone, &[], BOUND, 0, false));
  assert!(!src_on_local_link(foreign_zone, &[], BOUND, BOUND, true));
  // And our own zone still passes, whether or not an index backs it up.
  assert!(src_on_local_link(
    scoped(LINK_LOCAL, BOUND),
    &[],
    BOUND,
    0,
    false
  ));
  assert!(src_on_local_link(
    scoped(LINK_LOCAL, BOUND),
    &[],
    BOUND,
    BOUND,
    true
  ));
}

#[test]
fn loopback_is_on_link_regardless_of_interface() {
  // Loopback must short-circuit BEFORE the interface check — the loopback
  // integration tests depend on this.
  assert!(src_on_local_link(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    &[],
    BOUND,
    OTHER,
    true
  ));
  assert!(src_on_local_link(
    peer(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    &[],
    BOUND,
    OTHER,
    true
  ));
}

#[test]
fn a_global_source_with_no_known_subnets_fails_closed() {
  // §11: no positive on-link evidence for a routable source -> drop.
  assert!(!src_on_local_link(
    peer(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    &[],
    BOUND,
    BOUND,
    true
  ));
}

#[test]
fn global_src_matches_only_a_local_subnet() {
  assert!(src_on_local_link(on_subnet(), &SUBNETS, BOUND, BOUND, true));
  assert!(!src_on_local_link(
    peer(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 7))),
    &SUBNETS,
    BOUND,
    BOUND,
    true
  ));
}

// ── the ingress interface gate ──────────────────────────────────────────────
//
// Both mDNS sockets are wildcard bound, so on a multi-homed host every NIC's
// port-5353 traffic is delivered to them. A hop limit of 255 proves only that a
// datagram crossed no router; it says nothing about WHICH link it did not cross,
// and this endpoint serves exactly one interface. Two things can name that link
// — the PKTINFO interface index and an IPv6 source's scope id — and every one of
// them that is present has to agree.

#[test]
fn a_conforming_hop_limit_does_not_excuse_a_foreign_interface() {
  // The defect this gate closes: hop limit 255 used to be decisive on its own,
  // and the interface index was consulted only on the fallback branch. A
  // neighbouring network's unicast port-5353 traffic then reached the cache and
  // the RFC 6762 §8.2 conflict handling.
  assert!(!admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    Some(255),
    &SUBNETS,
    BOUND,
    OTHER
  ));
  // And the same datagram on the interface we bound is still admitted.
  assert!(admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    Some(255),
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn a_conforming_hop_limit_does_not_excuse_a_conflicting_scope() {
  // The reported bypass, in one assertion. A wildcard-bound socket on a
  // multi-homed host is handed the neighbouring link's port-5353 traffic with a
  // perfectly conforming hop limit of 255; the source address's own zone says
  // it came from somewhere else, and the driver used to throw that zone away by
  // passing only `peer().ip()`. Hop limit 255 answered "did this cross a
  // router", nothing answered "whose link is this", and the datagram was
  // admitted.
  let foreign_zone = scoped(LINK_LOCAL, OTHER);
  assert!(!admits_ingress(
    foreign_zone,
    Some(UNICAST_V6_DST),
    None,
    Some(255),
    &SUBNETS,
    BOUND,
    0
  ));
  assert!(!admits_ingress(
    foreign_zone,
    Some(UNICAST_V6_DST),
    None,
    Some(255),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // Our own zone, same hop limit: still admitted, so the rejection above is the
  // scope and not the address family.
  assert!(admits_ingress(
    scoped(LINK_LOCAL, BOUND),
    Some(UNICAST_V6_DST),
    None,
    Some(255),
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn a_foreign_interface_is_rejected_with_no_hop_metadata_either() {
  // The fallback branch, on a platform that delivers no TTL cmsg. Its own
  // interface check only ever covered a LINK-LOCAL source; a routable source
  // inside the bound interface's subnet passed it on any interface at all.
  assert!(!admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    None,
    &SUBNETS,
    BOUND,
    OTHER
  ));
  assert!(admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // And the scope witness reaches the fallback branch too.
  assert!(!admits_ingress(
    scoped(LINK_LOCAL, OTHER),
    Some(UNICAST_V6_DST),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn a_matching_scope_is_a_witness_in_its_own_right() {
  // The scope id alone is enough to place a datagram on our link, which is what
  // makes IPv6 provable on the targets that report no IPv4 interface index. It
  // holds whether or not an index corroborates it.
  for pkt_iface in [0, BOUND] {
    assert!(arrived_on_bound_interface(
      scoped(LINK_LOCAL, BOUND),
      BOUND,
      pkt_iface,
      true
    ));
  }
}

#[test]
fn a_conflicting_scope_rejects_whatever_the_index_says() {
  // Every nonzero witness must match, so a foreign zone is decisive on its own
  // (index 0), against a corroborating foreign index, and — the case a
  // "majority wins" rule would get wrong — against an index that says our own
  // interface. A datagram that contradicts itself has already failed to prove
  // it is ours.
  for pkt_iface in [0, BOUND, OTHER] {
    assert!(!arrived_on_bound_interface(
      scoped(LINK_LOCAL, OTHER),
      BOUND,
      pkt_iface,
      true
    ));
    // The platform's capability cannot rescue it either: a present witness is
    // decisive whether or not absent ones would have failed open.
    assert!(!arrived_on_bound_interface(
      scoped(LINK_LOCAL, OTHER),
      BOUND,
      pkt_iface,
      false
    ));
  }
}

#[test]
fn an_unreported_interface_is_absent_evidence_and_a_reported_zero_is_a_failed_proof() {
  // With no witness at all, the answer is entirely the platform's capability.
  // On a target that never reports a receive interface — IPv4 on the BSDs —
  // rejecting the zero would take IPv4 mDNS off the air there, so it degrades
  // exactly as the §11 hop-limit rule does.
  assert!(arrived_on_bound_interface(on_subnet(), BOUND, 0, false));
  // On a target that does report one, that same zero is not silence: the kernel
  // was asked and did not place the datagram, and `try_bind_v4`/`try_bind_v6`
  // fail the bind rather than leave PKTINFO quietly disabled. Fail closed.
  assert!(!arrived_on_bound_interface(on_subnet(), BOUND, 0, true));
  // A scopeless IPv6 peer — a global source, no zone — has exactly the same two
  // outcomes: the scope contributes no witness rather than a zero one.
  let global_v6 = peer(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
  assert!(arrived_on_bound_interface(global_v6, BOUND, 0, false));
  assert!(!arrived_on_bound_interface(global_v6, BOUND, 0, true));
}

#[test]
fn admits_ingress_reads_the_capability_of_the_peers_own_family() {
  // `admits_ingress` resolves `iface_reported` itself, per family, so the
  // no-witness outcome it produces is whatever this target can actually prove.
  // Pinned against the same constants rather than a hardcoded expectation: the
  // point is that the two track each other, on every platform this runs on.
  assert_eq!(
    admits_ingress(
      on_subnet(),
      Some(UNICAST_V4_DST),
      None,
      Some(255),
      &SUBNETS,
      BOUND,
      0
    ),
    !hick_udp::reports_rx_interface_v4(),
    "an IPv4 zero index must be admitted exactly where the platform reports no interface"
  );
  assert_eq!(
    reports_rx_interface(on_subnet()),
    hick_udp::reports_rx_interface_v4()
  );
  let global_v6 = peer(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
  assert_eq!(
    reports_rx_interface(global_v6),
    hick_udp::reports_rx_interface_v6()
  );
  // IPv6 is provable on every supported target, so a zero index there is always
  // a failed proof and never silence.
  assert!(hick_udp::reports_rx_interface_v6());
  assert!(!admits_ingress(
    global_v6,
    Some(UNICAST_V6_DST),
    None,
    Some(255),
    &SUBNETS,
    BOUND,
    0
  ));
}

#[test]
fn a_bound_interface_of_zero_proves_nothing_and_so_forbids_nothing() {
  // An endpoint that does not know its own link cannot prove anything about a
  // datagram's. Production never reaches this: `Sockets::bind` resolves an
  // index and fails the bind if it names no interface, so a live endpoint
  // always has a real one. Kept, and tested, because the alternative is a
  // silent total-deafness mode if that ever changes.
  assert!(arrived_on_bound_interface(on_subnet(), 0, OTHER, true));
  assert!(arrived_on_bound_interface(
    scoped(LINK_LOCAL, OTHER),
    0,
    OTHER,
    true
  ));
  assert!(admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    Some(255),
    &SUBNETS,
    0,
    OTHER
  ));
}

#[test]
fn a_loopback_source_is_admitted_from_any_interface() {
  // Explicit, not incidental: this crate's own loopback suppression depends on
  // receiving its own multicast back, and every test here and any caller pinned
  // to the loopback interface runs on traffic sourced from 127.0.0.1 / ::1. A
  // datagram from a loopback address crossed no link, so there is no link for it
  // to be off — and a kernel does not deliver a martian loopback source arriving
  // on a real NIC, so a remote attacker cannot reach this arm.
  assert!(arrived_on_bound_interface(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    BOUND,
    OTHER,
    true
  ));
  assert!(arrived_on_bound_interface(
    peer(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    BOUND,
    OTHER,
    true
  ));
  // Precedence, stated: loopback is checked BEFORE the witnesses, so even a
  // scope id naming another link does not override it. `::1` with a foreign
  // zone is not traffic a kernel delivers, and the loopback fixtures this crate
  // tests on must not be at the mercy of what one reports.
  assert!(arrived_on_bound_interface(
    scoped(Ipv6Addr::LOCALHOST, OTHER),
    BOUND,
    OTHER,
    true
  ));
  assert!(admits_ingress(
    scoped(Ipv6Addr::LOCALHOST, OTHER),
    Some(UNICAST_V6_DST),
    None,
    Some(255),
    &[],
    BOUND,
    OTHER
  ));
  assert!(admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    Some(UNICAST_V4_DST),
    None,
    Some(255),
    &[],
    BOUND,
    OTHER
  ));
  // The loopback exception is the SOURCE's, not the destination's: it still
  // holds on the unicast arm, with no group destination to carry it.
  assert!(admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    Some(UNICAST_V4_DST),
    None,
    None,
    &[],
    BOUND,
    OTHER
  ));
}

#[test]
fn the_interface_gate_does_not_replace_the_hop_limit_rule() {
  // Right interface, routed hop limit: still §11-off-link. The new gate is an
  // additional condition, never a substitute.
  assert!(!admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    Some(254),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(!admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    Some(1),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // Right interface, no hop metadata, and a global source with no matching
  // subnet: the unicast fallback still fails closed.
  assert!(!admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    Some(UNICAST_V4_DST),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

// ── §11's two arms, selected by DESTINATION ─────────────────────────────────
//
// §11 gives the local-link test two forms and the IP header's destination picks
// between them: a datagram addressed to 224.0.0.251 or FF02::FB is "necessarily
// deemed to have originated on the local link, regardless of source IP address",
// and only a UNICAST destination puts the source address to the subnet check.
// This crate had the unicast form alone and applied it to both.

#[test]
fn a_group_destination_establishes_local_link_origin_with_no_hop_limit() {
  // The defect, in the shape Windows actually produces: `set_recv_ttl_v4` and
  // `set_recv_hoplimit_v6` are no-ops there, so every datagram reaches the
  // fallback with no hop limit at all — and a host on an overlaid subnet, or one
  // simply misconfigured onto an unrelated prefix, sources from outside
  // `SUBNETS`. §11 calls admitting it "essential ... in unusual configurations,
  // such as multiple logical IP subnets overlayed on a single link". It was
  // silently dropped.
  assert!(admits_ingress(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(admits_ingress(
    peer(OFF_SUBNET_V6),
    Some(V6_GROUP),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // An empty subnet list is the same case with the evidence gone entirely: the
  // group destination is the whole proof, so it must not depend on `subnets`.
  assert!(admits_ingress(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
    None,
    None,
    &[],
    BOUND,
    BOUND
  ));
}

#[test]
fn a_unicast_destination_still_answers_to_the_source_prefix_rule() {
  // §11's other arm, reserved rather than deleted. Same source, same missing hop
  // limit, same interface as the case above — only the destination differs, and
  // with a unicast one the source address is the only evidence there is.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    Some(UNICAST_V4_DST),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V6),
    Some(UNICAST_V6_DST),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // And it still ADMITS on a matching prefix, so the arm is intact in both
  // directions rather than merely unreachable.
  assert!(admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn a_group_destination_does_not_excuse_a_foreign_interface_or_scope() {
  // The interface check runs FIRST and gates both arms. A group destination
  // proves a datagram was link-local to SOME link, never that it was ours, and a
  // wildcard-bound socket on a multi-homed host is handed every NIC's copy.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
    None,
    None,
    &SUBNETS,
    BOUND,
    OTHER
  ));
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V6),
    Some(V6_GROUP),
    None,
    None,
    &SUBNETS,
    BOUND,
    OTHER
  ));
  // The scope witness too: an index naming our own interface does not rescue a
  // source whose zone names another link, group destination or not.
  assert!(!admits_ingress(
    scoped(LINK_LOCAL, OTHER),
    Some(V6_GROUP),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn a_group_destination_does_not_excuse_a_routed_hop_limit() {
  // The group arm sits INSIDE the no-hop-limit branch: it replaces the
  // source-prefix guess, which is the only thing §11 ever offered it as an
  // alternative to. A hop limit below 255 crossed a router and stays decisive
  // whatever the destination says.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
    None,
    Some(254),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V6),
    Some(V6_GROUP),
    None,
    Some(1),
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

// ── The fallback's third reading: no destination at all ─────────────────────
//
// `RecvMeta::destination` is `None` wherever this crate recovers no IP header
// destination — every IPv4 datagram on FreeBSD/DragonFly/OpenBSD/NetBSD, and
// any receive whose PKTINFO cmsg was absent or truncated. §11 selects its arm by
// destination, so `None` needs an answer of its own, and on OpenBSD/NetBSD the
// kernel's `MSG_MCAST` is the one signal there is.

#[test]
fn no_destination_but_a_kernel_multicast_flag_takes_the_group_arm() {
  // The netbsdlike square, whole: no IPv4 PKTINFO parse (so no destination), no
  // IP_RECVTTL binding (so no hop limit), and a source on a prefix the bound
  // interface does not have configured — the overlaid subnet §11 calls it
  // "essential" to admit. Before the flag was consulted, the source-prefix arm
  // decided this and dropped it.
  assert!(admits_ingress(
    peer(OFF_SUBNET_V4),
    None,
    Some(true),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // Not a subnet question at all: an empty list changes nothing, because the
  // multicast delivery is the whole proof.
  assert!(admits_ingress(
    peer(OFF_SUBNET_V4),
    None,
    Some(true),
    None,
    &[],
    BOUND,
    BOUND
  ));
  assert!(admits_ingress(
    peer(OFF_SUBNET_V6),
    None,
    Some(true),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn no_destination_and_no_flag_still_answers_to_the_source_prefix_rule() {
  // `None` flag is "this target has no such flag", which is every target but
  // OpenBSD/NetBSD. The rule there is exactly what it was before: the source
  // address is the only evidence, so an off-prefix source is dropped and an
  // on-prefix one is admitted.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    None,
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(admits_ingress(
    on_subnet(),
    None,
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // A flag that is present and says "not multicast" is the same answer by a
  // different route: the datagram was addressed to this host, which is the arm
  // the source prefix is for.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    None,
    Some(false),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(admits_ingress(
    on_subnet(),
    None,
    Some(false),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn a_recovered_destination_outranks_the_multicast_flag() {
  // The flag is the coarser signal and never overrules the finer one. A target
  // that reports both — OpenBSD/NetBSD IPv6 — must decide on the address the
  // sender actually wrote, whichever way the link-layer flag went.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V6),
    Some(UNICAST_V6_DST),
    Some(true),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(admits_ingress(
    peer(OFF_SUBNET_V6),
    Some(V6_GROUP),
    Some(false),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn the_multicast_flag_excuses_neither_a_foreign_link_nor_a_routed_hop_limit() {
  // Same order of gates as the group destination gets: the interface check runs
  // first and a reported hop limit below 255 stays decisive. A multicast
  // delivery proves the datagram was addressed to SOME group, never that it was
  // on our link or that it did not cross a router.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    None,
    Some(true),
    None,
    &SUBNETS,
    BOUND,
    OTHER
  ));
  assert!(!admits_ingress(
    scoped(LINK_LOCAL, OTHER),
    None,
    Some(true),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    None,
    Some(true),
    Some(254),
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn the_group_arm_reads_a_destination_when_there_is_one_and_the_flag_otherwise() {
  // The selection itself, isolated from the rest of the boundary. A recovered
  // destination is matched against exactly the two groups; only its absence
  // hands the question to the kernel's flag, and a target with no flag answers
  // "not a group" so the source-prefix arm keeps deciding as before.
  assert!(addressed_to_group(Some(V4_GROUP), None));
  assert!(addressed_to_group(Some(V6_GROUP), Some(false)));
  assert!(!addressed_to_group(Some(UNICAST_V4_DST), Some(true)));
  // UNSPECIFIED is a real address here, not a stand-in for absence: `None` is
  // how "no destination was recovered" is spelled, and the two must not merge.
  assert!(!addressed_to_group(
    Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    Some(true)
  ));
  assert!(addressed_to_group(None, Some(true)));
  assert!(!addressed_to_group(None, Some(false)));
  assert!(!addressed_to_group(None, None));
}

#[test]
fn only_the_two_mdns_groups_establish_local_link_origin() {
  assert!(is_mdns_group(V4_GROUP));
  assert!(is_mdns_group(V6_GROUP));
  // The nearest neighbours in the same link-local blocks are LLMNR's groups,
  // not ours; this is a trust boundary, not a link-local scope test.
  assert!(!is_mdns_group(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 252))));
  assert!(!is_mdns_group(IpAddr::V6(Ipv6Addr::new(
    0xff02, 0, 0, 0, 0, 0, 1, 3
  ))));
  assert!(!is_mdns_group(UNICAST_V4_DST));
  assert!(!is_mdns_group(UNICAST_V6_DST));
  // What a target with no PKTINFO parser degrades to. It must read as unicast,
  // so the source-prefix rule keeps deciding exactly as it did before.
  assert!(!is_mdns_group(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
  assert!(!is_mdns_group(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
  // The families do not cross: a group compared against the other family's
  // address is not a match by accident of octets.
  assert!(!is_mdns_group(IpAddr::V6(Ipv6Addr::new(
    0, 0, 0, 0, 0, 0xffff, 0xe000, 0x00fb
  ))));
}

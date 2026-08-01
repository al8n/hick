use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::{
  addr_in_subnet, admits_ingress, arrived_on_bound_interface, is_on_link, reports_rx_interface,
  src_on_local_link,
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
    Some(255),
    &SUBNETS,
    BOUND,
    OTHER
  ));
  // And the same datagram on the interface we bound is still admitted.
  assert!(admits_ingress(
    on_subnet(),
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
  assert!(!admits_ingress(foreign_zone, Some(255), &SUBNETS, BOUND, 0));
  assert!(!admits_ingress(
    foreign_zone,
    Some(255),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // Our own zone, same hop limit: still admitted, so the rejection above is the
  // scope and not the address family.
  assert!(admits_ingress(
    scoped(LINK_LOCAL, BOUND),
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
  assert!(!admits_ingress(on_subnet(), None, &SUBNETS, BOUND, OTHER));
  assert!(admits_ingress(on_subnet(), None, &SUBNETS, BOUND, BOUND));
  // And the scope witness reaches the fallback branch too.
  assert!(!admits_ingress(
    scoped(LINK_LOCAL, OTHER),
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
    admits_ingress(on_subnet(), Some(255), &SUBNETS, BOUND, 0),
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
  assert!(!admits_ingress(global_v6, Some(255), &SUBNETS, BOUND, 0));
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
  assert!(admits_ingress(on_subnet(), Some(255), &SUBNETS, 0, OTHER));
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
    Some(255),
    &[],
    BOUND,
    OTHER
  ));
  assert!(admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    Some(255),
    &[],
    BOUND,
    OTHER
  ));
  assert!(admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
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
    Some(254),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(!admits_ingress(
    on_subnet(),
    Some(1),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // Right interface, no hop metadata, and a global source with no matching
  // subnet: the fallback still fails closed.
  assert!(!admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

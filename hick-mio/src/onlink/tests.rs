use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{
  addr_in_subnet, admits_ingress, arrived_on_bound_interface, is_on_link, src_on_local_link,
};

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
  let src = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
  // Packet arrived on the bound interface -> trusted.
  assert!(src_on_local_link(src, &[], 5, 5));
  // Packet arrived on a different interface -> not trusted.
  assert!(!src_on_local_link(src, &[], 5, 9));
  // Interface unknown (0) -> fall back to trusting, matching hick-reactor.
  assert!(src_on_local_link(src, &[], 5, 0));
}

#[test]
fn loopback_is_on_link_regardless_of_interface() {
  // Loopback must short-circuit BEFORE the interface check — the loopback
  // integration tests depend on this.
  assert!(src_on_local_link(
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    &[],
    5,
    9
  ));
  assert!(src_on_local_link(
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    &[],
    5,
    9
  ));
}

#[test]
fn a_global_source_with_no_known_subnets_fails_closed() {
  // §11: no positive on-link evidence for a routable source -> drop.
  assert!(!src_on_local_link(
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    &[],
    5,
    5
  ));
}

#[test]
fn global_src_matches_only_a_local_subnet() {
  let subnets = [(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24u8)];
  assert!(src_on_local_link(
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)),
    &subnets,
    5,
    5
  ));
  assert!(!src_on_local_link(
    IpAddr::V4(Ipv4Addr::new(10, 1, 1, 7)),
    &subnets,
    5,
    5
  ));
}

// ── the ingress interface gate ──────────────────────────────────────────────
//
// Both mDNS sockets are wildcard bound, so on a multi-homed host every NIC's
// port-5353 traffic is delivered to them. A hop limit of 255 proves only that a
// datagram crossed no router; it says nothing about WHICH link it did not cross,
// and this endpoint serves exactly one interface.

/// The interface this fixture's endpoint is pinned to.
const BOUND: u32 = 5;
/// Some other NIC on the same host.
const OTHER: u32 = 9;
/// A routable source inside `SUBNETS`, so nothing below turns on the §11
/// fallback's own subnet rule.
const ON_SUBNET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7));
/// The bound interface's configured subnets.
const SUBNETS: [(IpAddr, u8); 1] = [(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24u8)];

#[test]
fn a_conforming_hop_limit_does_not_excuse_a_foreign_interface() {
  // The defect this gate closes: hop limit 255 used to be decisive on its own,
  // and the interface index was consulted only on the fallback branch. A
  // neighbouring network's unicast port-5353 traffic then reached the cache and
  // the RFC 6762 §8.2 conflict handling.
  assert!(!admits_ingress(
    ON_SUBNET,
    Some(255),
    &SUBNETS,
    BOUND,
    OTHER
  ));
  // And the same datagram on the interface we bound is still admitted.
  assert!(admits_ingress(ON_SUBNET, Some(255), &SUBNETS, BOUND, BOUND));
}

#[test]
fn a_foreign_interface_is_rejected_with_no_hop_metadata_either() {
  // The fallback branch, on a platform that delivers no TTL cmsg. Its own
  // interface check only ever covered a LINK-LOCAL source; a routable source
  // inside the bound interface's subnet passed it on any interface at all.
  assert!(!admits_ingress(ON_SUBNET, None, &SUBNETS, BOUND, OTHER));
  assert!(admits_ingress(ON_SUBNET, None, &SUBNETS, BOUND, BOUND));
}

#[test]
fn an_unknown_interface_index_is_not_a_mismatch() {
  // Zero is what a platform that delivers no PKTINFO/RECVIF cmsg reports.
  // Treating "unknown" as "different" would take the responder off the air on
  // every such host, so absent evidence fails open exactly as the §11
  // hop-limit rule does.
  assert!(arrived_on_bound_interface(ON_SUBNET, BOUND, 0));
  assert!(admits_ingress(ON_SUBNET, Some(255), &SUBNETS, BOUND, 0));
  // The same both ways round: an endpoint that does not know its own link
  // cannot prove anything about a datagram's.
  assert!(arrived_on_bound_interface(ON_SUBNET, 0, OTHER));
  assert!(admits_ingress(ON_SUBNET, Some(255), &SUBNETS, 0, OTHER));
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
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    BOUND,
    OTHER
  ));
  assert!(arrived_on_bound_interface(
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    BOUND,
    OTHER
  ));
  assert!(admits_ingress(
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    Some(255),
    &[],
    BOUND,
    OTHER
  ));
  assert!(admits_ingress(
    IpAddr::V4(Ipv4Addr::LOCALHOST),
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
    ON_SUBNET,
    Some(254),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(!admits_ingress(ON_SUBNET, Some(1), &SUBNETS, BOUND, BOUND));
  // Right interface, no hop metadata, and a global source with no matching
  // subnet: the fallback still fails closed.
  assert!(!admits_ingress(
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

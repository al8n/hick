use core::net::{IpAddr, Ipv4Addr};

use smoltcp::wire::{IpAddress, IpCidr};

use super::on_link;
use crate::constants::{MDNS_IPV4, MDNS_IPV6};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
  IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn ttl_255_is_on_link() {
  // The authoritative §11 test: TTL 255 is decisive regardless of destination.
  assert!(on_link(Some(255), v4(8, 8, 8, 8), None, &[]));
}

#[test]
fn ttl_other_than_255_is_off_link() {
  // §11: a received TTL/hop-limit != 255 is not from the local link — drop it.
  assert!(!on_link(Some(64), v4(192, 168, 1, 5), None, &[]));
}

#[test]
fn no_ttl_falls_back_to_subnet_membership() {
  let subnet = IpCidr::new(IpAddress::v4(192, 168, 1, 0), 24);
  assert!(on_link(None, v4(192, 168, 1, 5), None, &[subnet]));
  assert!(!on_link(None, v4(10, 0, 0, 1), None, &[subnet]));
}

#[test]
fn no_ttl_no_subnets_accepts_multicast_rejects_unicast() {
  // with no hop-limit and no subnets the gate has no on-link evidence. It
  // accepts a datagram sent TO the mDNS group (link-scoped multicast routers don't
  // forward — on-link by IP design) so a default node isn't deaf, but REJECTS
  // unicast: a routed off-link host could otherwise inject conflict/answer data via
  // unicast to :5353, which the multicast scope does not protect.
  assert!(on_link(
    None,
    v4(8, 8, 8, 8),
    Some(IpAddr::V4(MDNS_IPV4)),
    &[]
  ));
  assert!(on_link(
    None,
    v4(8, 8, 8, 8),
    Some(IpAddr::V6(MDNS_IPV6)),
    &[]
  ));
  // Unicast destination (the device's own address) → rejected without TTL/subnets.
  assert!(!on_link(
    None,
    v4(8, 8, 8, 8),
    Some(v4(192, 168, 1, 10)),
    &[]
  ));
  // Unknown destination → rejected.
  assert!(!on_link(None, v4(8, 8, 8, 8), None, &[]));
}

use core::net::{IpAddr, Ipv4Addr};

use smoltcp::wire::{IpAddress, IpCidr};

use super::on_link;
use crate::constants::{MDNS_IPV4, MDNS_IPV6};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
  IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn subnet_membership_admits_in_subnet_rejects_out_of_subnet() {
  let subnet = IpCidr::new(IpAddress::v4(192, 168, 1, 0), 24);
  assert!(on_link(v4(192, 168, 1, 5), None, &[subnet]));
  assert!(!on_link(v4(10, 0, 0, 1), None, &[subnet]));
}

#[test]
fn no_subnets_accepts_multicast_rejects_unicast() {
  // with no subnets configured the gate has only the destination to go on. It
  // accepts a datagram sent TO the mDNS group (link-scoped multicast routers don't
  // forward — on-link by IP design) so a default node isn't deaf, but REJECTS
  // unicast: a routed off-link host could otherwise inject conflict/answer data via
  // unicast to :5353, which the multicast scope does not protect.
  assert!(on_link(v4(8, 8, 8, 8), Some(IpAddr::V4(MDNS_IPV4)), &[]));
  assert!(on_link(v4(8, 8, 8, 8), Some(IpAddr::V6(MDNS_IPV6)), &[]));
  // Unicast destination (the device's own address) → rejected without subnets.
  assert!(!on_link(v4(8, 8, 8, 8), Some(v4(192, 168, 1, 10)), &[]));
  // Unknown destination → rejected.
  assert!(!on_link(v4(8, 8, 8, 8), None, &[]));
}

/// `on_link`'s subnet arm has no interface identity to scope the check
/// with — it treats `subnets` as one flat list belonging to whichever single
/// interface the caller's `UdpIo` represents (see the `UdpIo` trait doc's
/// one-interface-per-implementation contract). A `UdpIo` that ignores that
/// contract and aggregates sockets from TWO physical interfaces behind one
/// `Engine` gets exactly this: a datagram received on interface A, carrying a
/// source address from interface B's configured prefix, is admitted — §11
/// scopes the unicast test to "the interface receiving the packet", and this
/// is not that. This is the documented consequence of violating the
/// contract, not a supported configuration; a conforming caller runs one
/// `Engine` (and one `UdpIo`, with that interface's own subnet list) per
/// interface instead.
#[test]
fn aggregated_interfaces_defeat_the_subnet_check() {
  let iface_a = IpCidr::new(IpAddress::v4(192, 168, 1, 0), 24);
  let iface_b = IpCidr::new(IpAddress::v4(10, 0, 0, 0), 24);
  // A source that belongs only to interface B's prefix, checked against the
  // union an aggregating caller would have configured for both interfaces.
  let src_only_on_b = v4(10, 0, 0, 42);
  assert!(
    on_link(
      src_only_on_b,
      Some(v4(192, 168, 1, 10)),
      &[iface_a, iface_b]
    ),
    "an aggregating UdpIo's shared subnet list admits a cross-interface \
     source — the out-of-contract behavior the UdpIo trait doc warns about"
  );
}

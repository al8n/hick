use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hick_onlink::{Admit, Refuse, Verdict};

use super::verdict;
use crate::constants::{MDNS_IPV4, MDNS_IPV6};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
  IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn peer(ip: IpAddr) -> SocketAddr {
  SocketAddr::new(ip, 5353)
}

/// The device's own address on a `/24`, as
/// [`Engine::set_local_addrs`](crate::Engine::set_local_addrs) stores it: the
/// ASSIGNED address next to its prefix length.
const OURS: (IpAddr, u8) = (IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24);

#[test]
fn a_group_destination_is_admitted_regardless_of_source() {
  // §11 arm one, verbatim: `224.0.0.251` / `ff02::fb` are "necessarily deemed to
  // have originated on the local link, regardless of source IP address". The RFC
  // calls this essential for overlaid subnets, so a source outside every address
  // the device holds must still be admitted — and must still be admitted once
  // addresses ARE configured, since the source comparison is an ALTERNATIVE §11
  // offers, never a veto.
  for addrs in [&[][..], &[OURS][..]] {
    assert_eq!(
      verdict(peer(v4(8, 8, 8, 8)), IpAddr::V4(MDNS_IPV4), addrs),
      Verdict::Admit(Admit::MdnsGroup)
    );
    assert_eq!(
      verdict(peer(v4(8, 8, 8, 8)), IpAddr::V6(MDNS_IPV6), addrs),
      Verdict::Admit(Admit::MdnsGroup)
    );
  }
}

#[test]
fn unicast_to_an_address_the_device_holds_answers_to_the_source_arm() {
  // §11 arm two: a datagram "received via unicast" is one addressed to an
  // address of ours, and only then is the SOURCE put to the on-link comparison.
  assert_eq!(
    verdict(peer(v4(192, 168, 1, 5)), OURS.0, &[OURS]),
    Verdict::Admit(Admit::HeldDestination)
  );
  assert_eq!(
    verdict(peer(v4(10, 0, 0, 1)), OURS.0, &[OURS]),
    Verdict::Refuse(Refuse::SourceOffLink)
  );
}

#[test]
fn with_no_addresses_configured_only_the_group_arm_is_left() {
  // A device that cannot say which addresses it holds proves nothing about a
  // unicast destination, and the source arm has no prefix to match, so it admits
  // nothing. The group arm above keeps such a node from being deaf; unicast to
  // `:5353` is NOT accepted, because a routed off-link host could otherwise
  // inject conflict/answer data on a path the multicast scope does not protect.
  assert_eq!(
    verdict(peer(v4(8, 8, 8, 8)), OURS.0, &[]),
    Verdict::Refuse(Refuse::SourceOffLink)
  );
  assert_eq!(
    verdict(peer(v4(192, 168, 1, 5)), OURS.0, &[]),
    Verdict::Refuse(Refuse::SourceOffLink)
  );
}

/// The two classes the hand-copied gate this file replaced admitted, and the
/// reason it had to go.
///
/// That copy asked "is the destination one of the two mDNS groups; if not, is
/// the SOURCE in a configured subnet" — so every destination §11 gives no arm
/// to was handed to a comparison §11 never offers for it. An in-prefix source
/// therefore carried LLMNR's group and an IPv4 broadcast straight through.
/// `hick-onlink` sorts a witnessed destination by what it IS, so both are named
/// and refused, and the source is never consulted.
#[test]
fn a_foreign_group_and_a_broadcast_have_no_arm_and_are_refused() {
  // An in-prefix source, so the deleted copy's subnet arm would have said yes to
  // every one of these.
  let src = peer(v4(192, 168, 1, 5));
  assert_eq!(
    verdict(src, v4(224, 0, 0, 252), &[OURS]),
    Verdict::Refuse(Refuse::ForeignGroup),
    "LLMNR's IPv4 group is not one of the two §11 names"
  );
  assert_eq!(
    verdict(
      src,
      IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 3)),
      &[OURS]
    ),
    Verdict::Refuse(Refuse::ForeignGroup),
    "LLMNR's IPv6 group likewise"
  );
  assert_eq!(
    verdict(src, IpAddr::V4(Ipv4Addr::BROADCAST), &[OURS]),
    Verdict::Refuse(Refuse::BroadcastAddressed),
    "RFC 919's limited broadcast: §11 offers a broadcast no arm at all"
  );
  assert_eq!(
    verdict(src, v4(192, 168, 1, 255), &[OURS]),
    Verdict::Refuse(Refuse::DestinationNotHeld),
    "the subnet-directed broadcast is refused as an address we do not hold, \
     with no prefix arithmetic to get wrong"
  );
  assert_eq!(
    verdict(src, v4(192, 168, 1, 11), &[OURS]),
    Verdict::Refuse(Refuse::DestinationNotHeld),
    "a neighbour's address on our own subnet was addressed to somebody else"
  );
}

/// A loopback destination is refused because the seam is never loopback-BOUND.
///
/// `BoundLink::new(0, false, …)` is what this square passes, and the §11
/// loopback exception turns on the BINDING rather than on the address — Linux's
/// `route_localnet` is why. A bare-metal device runs a network interface, so the
/// exception stays shut and `127/8` is a martian here.
#[test]
fn the_loopback_block_is_a_martian_on_a_device_bound_seam() {
  assert_eq!(
    verdict(peer(v4(192, 168, 1, 5)), v4(127, 0, 0, 1), &[OURS]),
    Verdict::Refuse(Refuse::LoopbackDestinationOffLoopbackBinding)
  );
  assert_eq!(
    verdict(peer(v4(127, 0, 0, 1)), OURS.0, &[OURS]),
    Verdict::Refuse(Refuse::SourceOffLink),
    "and a loopback SOURCE is not evidence of anything on this seam either"
  );
}

/// This seam mints [`IfaceWitness::Blind`] and binds interface `0`, so §11's
/// link stage forbids nothing — there is no interface identity to scope with.
///
/// [`UdpIo`](crate::UdpIo)'s one-interface-per-implementation contract is what
/// makes that sound. An implementation that ignores it and aggregates sockets
/// from TWO physical interfaces behind one [`Engine`](crate::Engine) gets
/// exactly this: a datagram addressed to interface A's own address, carrying a
/// source from interface B's prefix, is admitted — §11 scopes its source
/// comparison to "the interface receiving the packet", and this is not that.
/// The documented consequence of violating the contract, not a supported
/// configuration; a conforming caller runs one `Engine` per interface.
///
/// [`IfaceWitness::Blind`]: hick_onlink::IfaceWitness::Blind
#[test]
fn aggregated_interfaces_defeat_the_source_arm() {
  let iface_b = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 24);
  assert_eq!(
    verdict(peer(v4(10, 0, 0, 42)), OURS.0, &[OURS, iface_b]),
    Verdict::Admit(Admit::HeldDestination),
    "an aggregating UdpIo's shared address list admits a cross-interface \
     source — the out-of-contract behaviour the UdpIo trait doc warns about"
  );
}

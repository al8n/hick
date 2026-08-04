use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::{
  BoundLink, LinkDelivery, addr_in_subnet, admits_ingress, arrived_on_bound_interface,
  collect_local_subnets, is_loopback_interface, is_mdns_group, reports_rx_interface,
  src_on_local_link,
};

/// The interface this fixture's endpoint is pinned to.
const BOUND: u32 = 5;
/// Some other NIC on the same host.
const OTHER: u32 = 9;
/// A routable source inside [`SUBNETS`], so nothing below turns on the §11
/// fallback's own subnet rule.
const ON_SUBNET_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7));

/// The addresses the bound interface HOLDS, one per family.
///
/// `collect_local_subnets` stores `getifs`' `n.addr()` — the assigned address —
/// next to `n.prefix_len()`, so an entry is an ADDRESS and a mask, never a
/// masked network. Both of §11's arms read this one fixture: the source arm as
/// address+mask, and the destination test as the address alone.
const OUR_V4_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
const OUR_V6_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2));
/// The bound interface's configuration: the two addresses above and their masks.
static SUBNETS: [(IpAddr, u8); 2] = [(OUR_V4_ADDR, 24u8), (OUR_V6_ADDR, 64u8)];

/// The addresses an interface holding only link-local ones reports — `fe80::/64`
/// for IPv6, `169.254/16` for IPv4 APIPA. §11's second arm is the only thing
/// that admits a link-local source, so a fixture that means "this link-local
/// peer is on our link" has to say so the way a real interface does.
const OUR_V6_LL_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
const OUR_V4_LL_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 0, 2));
static LL_PREFIXES: [(IpAddr, u8); 2] = [(OUR_V6_LL_ADDR, 64u8), (OUR_V4_LL_ADDR, 16u8)];

/// An interface with IPv4 APIPA and nothing else — the infrastructure-less link
/// where mDNS matters most, and where §11's second arm is the whole rule.
static APIPA: [(IpAddr, u8); 1] = [(OUR_V4_LL_ADDR, 16u8)];

/// An interface holding a global IPv6 address and nothing else.
const V6_PREFIX_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xbeef, 0, 0, 0, 0, 2));
static V6_PREFIX: [(IpAddr, u8); 1] = [(V6_PREFIX_ADDR, 64u8)];

/// A **unicast** destination, per family: the arm of §11 that does consult the
/// source prefix. Every pre-existing case below passes one of these, because a
/// unicast destination is the condition they were all implicitly written under.
///
/// It is one of [`SUBNETS`]' own addresses, because that is what §11 means by a
/// response *"received via unicast"* — addressed to this host. A destination
/// this interface does NOT hold reaches no §11 arm at all, so passing one here
/// would refuse at the destination test and leave the source arm unprobed. The
/// [`LL_PREFIXES`] link holds different addresses and so has its own pair.
const UNICAST_V4_DST: IpAddr = OUR_V4_ADDR;
const UNICAST_V6_DST: IpAddr = OUR_V6_ADDR;
const LL_UNICAST_V4_DST: IpAddr = OUR_V4_LL_ADDR;
const LL_UNICAST_V6_DST: IpAddr = OUR_V6_LL_ADDR;

/// Multicast groups that are NOT ours: LLMNR's, in each family. §11 has no arm
/// for them, and they are the nearest neighbours in the same link-local blocks —
/// so if anything is going to fall through to the unicast arm by accident, it is
/// these.
const FOREIGN_V4_GROUP: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 252));
const FOREIGN_V6_GROUP: IpAddr = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 3));

/// The IPv4 broadcast destinations, which are neither multicast nor an address
/// this interface holds and so have no §11 arm either.
///
/// All three are LITERALS, and [`NON_DEFAULT_BROADCAST`] is why that matters.
/// `192.168.1.255` is the all-ones host address of [`SUBNETS`]' `/24` — the one
/// a computation finds. `192.168.1.200` is the one an operator can configure
/// instead (`ip addr add 192.168.1.5/24 broadcast 192.168.1.200` is legal), and
/// no arithmetic over `addr/prefix` finds it. Neither is an address the
/// interface holds, which is the only fact any assertion below uses: nothing
/// here knows what a broadcast IS.
const LIMITED_BROADCAST: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
const DIRECTED_BROADCAST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255));
const NON_DEFAULT_BROADCAST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));

/// An interface configured the way RFC 6762 §11's destination test must survive:
/// a `/24` whose broadcast address is NOT its all-ones host address. The address
/// it holds is `192.168.1.5`; [`NON_DEFAULT_BROADCAST`] is the broadcast an
/// operator gave it, and [`DIRECTED_BROADCAST`] is the one arithmetic would have
/// derived. Every host on the link receives both.
const NON_DEFAULT_BROADCAST_HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
static NON_DEFAULT_BROADCAST_LINK: [(IpAddr, u8); 1] = [(NON_DEFAULT_BROADCAST_HOST, 24u8)];

/// A host address on our own subnet that is NOT ours, and its IPv6 twin. A
/// datagram addressed to a neighbour is not one §11 calls *"received via
/// unicast"* — not by us — and it looks exactly like a legitimate destination to
/// any test that only asks "is this a unicast address".
const NEIGHBOUR_V4_DST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9));
const NEIGHBOUR_V6_DST: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 9));

/// A martian: reserved by RFC 1112 §4 and deliverable to nothing. It is neither
/// multicast nor broadcast nor unspecified, so every partition this file has
/// carried before this one sent it to the source-prefix arm.
const MARTIAN_V4_DST: IpAddr = IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1));

/// A loopback-bound endpoint's own configuration, and three addresses RFC 1122
/// §3.2.1.3 makes this host's own that `getifs` does not report.
///
/// The interface is configured with `127.0.0.1` and `::1`, which is what an
/// enumeration returns. `127.0.0.2` and `127.255.255.255` are equally inside the
/// `127.0.0.0/8` block that section assigns to internal host loopback, so a
/// locally looped datagram may legitimately carry either as its destination —
/// and neither is a broadcast, a martian or a neighbour's address.
///
/// [`LOOPBACK_BLOCK`] is the literal list of enumerated destinations inside the
/// block. The invariants read THAT and never `IpAddr::is_loopback`, so the
/// oracle states which addresses the rule must cover rather than asking
/// production the same question production answers.
const LOOPBACK_V4_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const LOOPBACK_V6_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
const LOOPBACK_ALT_V4_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
const LOOPBACK_BROADCAST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255));
static LOOPBACK_LINK: [(IpAddr, u8); 2] = [(LOOPBACK_V4_ADDR, 8u8), (LOOPBACK_V6_ADDR, 128u8)];
const LOOPBACK_BLOCK: [IpAddr; 4] = [
  LOOPBACK_V4_ADDR,
  LOOPBACK_V6_ADDR,
  LOOPBACK_ALT_V4_ADDR,
  LOOPBACK_BROADCAST,
];

/// The unspecified address, per family: never a destination a datagram was
/// delivered to, and so no §11 arm for it either.
///
/// It is NOT what a target with no PKTINFO parser degrades to — that is
/// `destination == None`, kept distinct precisely because the two lead to
/// opposite §11 decisions (see [`crate::RecvMeta::destination`]). So refusing it
/// takes nothing off the air; it closes a value only a corrupt cmsg or a
/// hand-rolled receive path can produce.
const UNSPECIFIED_V4_DST: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const UNSPECIFIED_V6_DST: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// The two mDNS groups, the destinations §11 says establish local-link origin
/// on their own.
const V4_GROUP: IpAddr = IpAddr::V4(crate::constants::MDNS_IPV4_GROUP);
const V6_GROUP: IpAddr = IpAddr::V6(crate::constants::MDNS_IPV6_GROUP);

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

/// A NIC-bound endpoint on `bound` carrying `subnets`: the shape every case
/// below was written under, and never the loopback interface.
fn nic(bound: u32, subnets: &[(IpAddr, u8)]) -> BoundLink<'_> {
  BoundLink::new(bound, false, subnets)
}

/// An endpoint pinned to the loopback interface, the only configuration that
/// opens the §11 loopback exception.
fn lo(bound: u32, subnets: &[(IpAddr, u8)]) -> BoundLink<'_> {
  BoundLink::new(bound, true, subnets)
}

/// [`admits_ingress`] for a NIC-bound endpoint whose receive path DOES report an
/// interface — the capability every supported target has for IPv6 and every
/// non-BSD one has for IPv4, and the condition each case below is written under.
///
/// The two axes this pins are exercised on their own, against
/// [`admits_ingress`] directly: see
/// `admits_ingress_uses_the_capability_its_caller_states`,
/// `a_conforming_hop_limit_does_not_decide_an_unwitnessed_link` and
/// `a_loopback_source_is_admitted_only_by_a_loopback_bound_endpoint`.
fn admits(
  src: SocketAddr,
  destination: Option<IpAddr>,
  delivery: Option<LinkDelivery>,
  subnets: &[(IpAddr, u8)],
  bound: u32,
  pkt_iface: u32,
) -> bool {
  admits_ingress(
    src,
    destination,
    delivery,
    nic(bound, subnets),
    pkt_iface,
    true,
  )
}

/// [`arrived_on_bound_interface`] for a NIC-bound endpoint.
fn arrived(src: SocketAddr, bound: u32, pkt_iface: u32, iface_reported: bool) -> bool {
  arrived_on_bound_interface(src, nic(bound, &[]), pkt_iface, iface_reported)
}

/// [`src_on_local_link`] for a NIC-bound endpoint.
fn on_local_link(
  src: SocketAddr,
  subnets: &[(IpAddr, u8)],
  bound: u32,
  pkt_iface: u32,
  iface_reported: bool,
) -> bool {
  src_on_local_link(src, nic(bound, subnets), pkt_iface, iface_reported)
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
  // Arrived on the bound interface AND inside a prefix that interface carries:
  // §11's second arm admits it. Both halves are required — a witness alone is
  // not a third arm.
  assert!(on_local_link(src, &LL_PREFIXES, BOUND, BOUND, true));
  // The witness agrees but the interface carries no matching prefix: refused.
  assert!(!on_local_link(src, &SUBNETS, BOUND, BOUND, true));
  // A foreign witness is stage 1's refusal, not this arm's — §11's second arm
  // asks only about the prefix. Asserted where the question is decided, and
  // with a destination this interface HOLDS, so nothing but stage 1 can refuse.
  assert!(!admits_ingress(
    src,
    Some(LL_UNICAST_V6_DST),
    None,
    nic(BOUND, &LL_PREFIXES),
    OTHER,
    true
  ));
  // No witness at all -> REFUSED, whatever the platform can report. A
  // link-local address names some link and never ours, so absent provenance is
  // absent membership: nothing hands a source the link it is claiming.
  assert!(!on_local_link(src, &[], BOUND, 0, false));
  assert!(!on_local_link(src, &[], BOUND, 0, true));
}

#[test]
fn an_unwitnessed_ipv4_link_local_source_is_refused() {
  // The bypass this closes: with no interface to give, `169.254/16` from a
  // neighbouring NIC used to reach the cache and §8.2 conflict handling on the
  // strength of its own address — no shared prefix, no spoofing, hop limit 255
  // or none at all. That is every IPv4 receive on the four BSDs, and any driver
  // reading its datagrams with `recvfrom`.
  let v4_ll = peer(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)));
  for reported in [true, false] {
    assert!(!on_local_link(v4_ll, &[], BOUND, 0, reported));
    assert!(
      !admits_ingress(v4_ll, None, None, nic(BOUND, &SUBNETS), 0, reported),
      "an unwitnessed link-local source outside every configured prefix has \
       nothing left to be admitted on"
    );
  }
  // An index that names our own interface is the witness it was missing, so the
  // arm is intact rather than merely unreachable.
  assert!(on_local_link(v4_ll, &LL_PREFIXES, BOUND, BOUND, true));
  // IPv6 needs no special case: an interface holding a link-local address
  // carries `fe80::/64`, which is one of the "on-link IPv6 prefixes" §11 points
  // at, so the same arm admits a link-local peer there.
  assert!(on_local_link(
    scoped(LINK_LOCAL, BOUND),
    &LL_PREFIXES,
    BOUND,
    0,
    false
  ));
  // A contradicting scope refuses at stage 1, prefix or not.
  assert!(!admits_ingress(
    scoped(LINK_LOCAL, OTHER),
    None,
    None,
    nic(BOUND, &LL_PREFIXES),
    0,
    false
  ));
}

#[test]
fn a_link_local_source_must_also_match_on_its_scope_id() {
  // The scope id is a witness, and a witness is stage 1's business: it settles
  // which LINK a datagram arrived on. It is deliberately NOT asserted through
  // §11's second arm, which asks only whether the source sits in a prefix this
  // interface carries — a witnessed link-local source used to return true there
  // on the witness alone, which was a third arm the RFC does not have.
  let foreign_zone = scoped(LINK_LOCAL, OTHER);
  for reported in [true, false] {
    for pkt_iface in [0, BOUND] {
      assert!(!admits_ingress(
        foreign_zone,
        Some(LL_UNICAST_V6_DST),
        None,
        nic(BOUND, &LL_PREFIXES),
        pkt_iface,
        reported
      ));
    }
  }
  // Our own zone passes stage 1 whether or not an index backs it up, and the
  // prefix then admits.
  for pkt_iface in [0, BOUND] {
    assert!(admits_ingress(
      scoped(LINK_LOCAL, BOUND),
      Some(LL_UNICAST_V6_DST),
      None,
      nic(BOUND, &LL_PREFIXES),
      pkt_iface,
      true
    ));
  }
  // ... and with no matching prefix it is refused even so, because the witness
  // was never an admission ground of its own. The destination is one this
  // interface DOES hold, so the destination test cannot be what refuses.
  assert!(!admits_ingress(
    scoped(LINK_LOCAL, BOUND),
    Some(UNICAST_V6_DST),
    None,
    nic(BOUND, &SUBNETS),
    BOUND,
    true
  ));
}

#[test]
fn loopback_is_on_link_for_a_loopback_bound_endpoint_and_nobody_else() {
  // Loopback short-circuits BEFORE the interface check — the loopback
  // integration tests depend on this — but only for the endpoint whose link it
  // actually is. A source address is not a link.
  for ip in [
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
  ] {
    // Matching witness, loopback-bound: our own traffic.
    assert!(src_on_local_link(peer(ip), lo(BOUND, &[]), BOUND, true));
    // No witness at all, loopback-bound: the exception, and its whole extent.
    assert!(src_on_local_link(peer(ip), lo(BOUND, &[]), 0, true));
    // A REPORTED foreign interface outranks the source address, even for the
    // endpoint the exception exists for.
    assert!(!src_on_local_link(peer(ip), lo(BOUND, &[]), OTHER, true));
    // And a NIC-bound endpoint has no loopback traffic to protect at all.
    assert!(!src_on_local_link(peer(ip), nic(BOUND, &[]), BOUND, true));
    assert!(!src_on_local_link(peer(ip), nic(BOUND, &[]), 0, false));
  }
}

#[test]
fn a_global_source_with_no_known_subnets_fails_closed() {
  // §11: no positive on-link evidence for a routable source -> drop.
  assert!(!on_local_link(
    peer(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    &[],
    BOUND,
    BOUND,
    true
  ));
}

#[test]
fn global_src_matches_only_a_local_subnet() {
  assert!(on_local_link(on_subnet(), &SUBNETS, BOUND, BOUND, true));
  assert!(!on_local_link(
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
  assert!(!admits(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    &SUBNETS,
    BOUND,
    OTHER
  ));
  // And the same datagram on the interface we bound is still admitted.
  assert!(admits(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
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
  assert!(!admits(
    foreign_zone,
    Some(UNICAST_V6_DST),
    None,
    &SUBNETS,
    BOUND,
    0
  ));
  assert!(!admits(
    foreign_zone,
    Some(UNICAST_V6_DST),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // Our own zone, with the interface carrying the matching prefix: admitted, so
  // the rejection above is the scope and not the address family. The prefix is
  // required as well — a witness is not an admission ground of its own.
  assert!(admits(
    scoped(LINK_LOCAL, BOUND),
    Some(LL_UNICAST_V6_DST),
    None,
    &LL_PREFIXES,
    BOUND,
    BOUND
  ));
}

#[test]
fn a_foreign_interface_is_rejected_with_no_hop_metadata_either() {
  // The fallback branch, on a platform that delivers no TTL cmsg. Its own
  // interface check only ever covered a LINK-LOCAL source; a routable source
  // inside the bound interface's subnet passed it on any interface at all.
  assert!(!admits(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    &SUBNETS,
    BOUND,
    OTHER
  ));
  assert!(admits(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // And the scope witness reaches the fallback branch too.
  assert!(!admits(
    scoped(LINK_LOCAL, OTHER),
    Some(UNICAST_V6_DST),
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
    assert!(arrived(scoped(LINK_LOCAL, BOUND), BOUND, pkt_iface, true));
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
    assert!(!arrived(scoped(LINK_LOCAL, OTHER), BOUND, pkt_iface, true));
    // The platform's capability cannot rescue it either: a present witness is
    // decisive whether or not absent ones would have failed open.
    assert!(!arrived(scoped(LINK_LOCAL, OTHER), BOUND, pkt_iface, false));
  }
}

#[test]
fn an_unreported_interface_is_absent_evidence_and_a_reported_zero_is_a_failed_proof() {
  // With no witness at all, the answer is entirely the platform's capability.
  // On a target that never reports a receive interface — IPv4 on the BSDs —
  // rejecting the zero would take IPv4 mDNS off the air there, so it degrades
  // rather than take mDNS off the air on a path that cannot answer.
  assert!(arrived(on_subnet(), BOUND, 0, false));
  // On a target that does report one, that same zero is not silence: the kernel
  // was asked and did not place the datagram, and `try_bind_v4`/`try_bind_v6`
  // fail the bind rather than leave PKTINFO quietly disabled. Fail closed.
  assert!(!arrived(on_subnet(), BOUND, 0, true));
  // A scopeless IPv6 peer — a global source, no zone — has exactly the same two
  // outcomes: the scope contributes no witness rather than a zero one.
  let global_v6 = peer(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
  assert!(arrived(global_v6, BOUND, 0, false));
  assert!(!arrived(global_v6, BOUND, 0, true));
}

#[test]
fn admits_ingress_uses_the_capability_its_caller_states() {
  // Capability is a parameter, not a constant read inside the rule, because it
  // belongs to the RECEIVE PATH and not to the platform: a driver reading its
  // datagrams with `recvfrom` recovers no interface on a target whose `recvmsg`
  // would have supplied one, and resolving it here would fail every one of that
  // driver's datagrams closed and leave it silently deaf.
  //
  // Same datagram, same target, both answers — decided entirely by what the
  // caller said its own path can report.
  assert!(
    !admits_ingress(
      on_subnet(),
      Some(UNICAST_V4_DST),
      None,
      nic(BOUND, &SUBNETS),
      0,
      true
    ),
    "a path that DOES report an interface handed us a zero: a failed proof"
  );
  assert!(
    admits_ingress(
      on_subnet(),
      Some(UNICAST_V4_DST),
      None,
      nic(BOUND, &SUBNETS),
      0,
      false
    ),
    "a path with no interface to give is silent, not contradicted — and the \
     source is inside the bound interface's own subnet"
  );
  assert_eq!(
    reports_rx_interface(on_subnet()),
    crate::reports_rx_interface_v4()
  );
  let global_v6 = peer(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
  assert_eq!(
    reports_rx_interface(global_v6),
    crate::reports_rx_interface_v6()
  );
  // IPv6 is provable on every supported target through that path, so a zero
  // index there is always a failed proof and never silence.
  assert!(crate::reports_rx_interface_v6());
  assert!(!admits(
    global_v6,
    Some(UNICAST_V6_DST),
    None,
    &SUBNETS,
    BOUND,
    0
  ));
}

#[test]
fn a_bound_interface_of_zero_proves_nothing_and_so_forbids_nothing() {
  // An endpoint that does not know its own link cannot prove anything about a
  // datagram's. Production never reaches this: a driver's bind resolves an index
  // and fails if it names no interface. Kept, and tested, because the
  // alternative is a silent total-deafness mode if that ever changes.
  //
  // It forbids nothing AT STAGE 1. §11's own arms still decide after it — an
  // unbound endpoint is not an open door.
  assert!(arrived_on_bound_interface(
    on_subnet(),
    nic(0, &[]),
    OTHER,
    true
  ));
  assert!(arrived_on_bound_interface(
    scoped(LINK_LOCAL, OTHER),
    nic(0, &[]),
    OTHER,
    true
  ));
  assert!(admits(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    &SUBNETS,
    0,
    OTHER
  ));
  // Off-prefix unicast is still refused there, by the unicast arm.
  assert!(!admits(
    peer(OFF_SUBNET_V4),
    Some(UNICAST_V4_DST),
    None,
    &SUBNETS,
    0,
    OTHER
  ));
  // And a group destination is admitted, as §11 requires.
  assert!(admits(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
    None,
    &[],
    0,
    OTHER
  ));
}

#[test]
fn a_loopback_source_is_admitted_only_by_a_loopback_bound_endpoint() {
  // Explicit, not incidental: a loopback-pinned endpoint's own suppression
  // depends on receiving its own multicast back, and every loopback fixture in
  // this workspace — and any caller pinned to that interface — runs on traffic
  // sourced from 127.0.0.1 / ::1. The exception is stated rather than left to
  // fall out of the index comparison, so a platform that places the echo on NO
  // interface still delivers it.
  //
  // Its extent is exactly that: absent provenance. It never overrules a witness
  // — see `a_reported_foreign_interface_outranks_a_loopback_source`.
  for src in [
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    peer(IpAddr::V6(Ipv6Addr::LOCALHOST)),
  ] {
    assert!(arrived_on_bound_interface(src, lo(BOUND, &[]), 0, true));
    assert!(arrived_on_bound_interface(src, lo(BOUND, &[]), BOUND, true));
  }
  assert!(admits_ingress(
    peer(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    Some(UNICAST_V6_DST),
    None,
    lo(BOUND, &[]),
    0,
    true
  ));
  // The exception is the SOURCE's, not the destination's: it still holds on the
  // unicast arm, with no group destination and no hop limit to carry it.
  assert!(admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    Some(UNICAST_V4_DST),
    None,
    lo(BOUND, &[]),
    0,
    true
  ));
}

#[test]
fn a_reported_foreign_interface_outranks_a_loopback_source() {
  // The witnesses are read FIRST and no exception may override them. A source
  // ADDRESS is a claim the sender wrote; a nonzero interface index is evidence
  // the kernel attached. These sockets are wildcard bound, so wherever an
  // operator has stopped treating `127/8` as martian — Linux's `route_localnet`
  // — a physical-interface unicast can carry a loopback source right to
  // port 5353, and a loopback-bound endpoint must still refuse it.
  for src in [
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    peer(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    scoped(Ipv6Addr::LOCALHOST, OTHER),
  ] {
    assert!(!arrived_on_bound_interface(
      src,
      lo(BOUND, &[]),
      OTHER,
      true
    ));
    assert!(!admits_ingress(
      src,
      Some(UNICAST_V6_DST),
      None,
      lo(BOUND, &[]),
      OTHER,
      true
    ));
  }
  // A contradicting SCOPE is a witness too, with no index to back it up.
  assert!(!arrived_on_bound_interface(
    scoped(Ipv6Addr::LOCALHOST, OTHER),
    lo(BOUND, &[]),
    0,
    true
  ));
}

#[test]
fn a_spoofed_loopback_source_is_rejected_on_a_foreign_interface() {
  // The exception must not be granted by the source ADDRESS. "A kernel does not
  // deliver a martian loopback source arriving on a real NIC" is not an
  // invariant: Linux's `route_localnet` exists precisely to stop treating 127/8
  // as martian, and with suitable routing an adjacent sender can put
  // 127.0.0.1:5353 at hop limit 255 onto a NIC this endpoint did not bind. An
  // address-only exemption would hand it the whole boundary, hop-limit branch
  // and all.
  for src in [
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    peer(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    scoped(Ipv6Addr::LOCALHOST, OTHER),
  ] {
    assert!(!arrived_on_bound_interface(
      src,
      nic(BOUND, &SUBNETS),
      OTHER,
      true
    ));
    assert!(
      !admits_ingress(
        src,
        Some(UNICAST_V4_DST),
        None,
        nic(BOUND, &SUBNETS),
        OTHER,
        true
      ),
      "a NIC-bound endpoint has no loopback traffic to protect, so a loopback \
       source from another link is just a spoofed source"
    );
  }
  // Nor at stage 1 with NO witness at all. The three cases above all carry a
  // contradicting index, which refuses on the witness before the exception is
  // ever reached — so they cannot tell whether the exception is scoped to a
  // loopback-BOUND endpoint or granted to any loopback source. This one can:
  // the path could have named the link and did not, which is a failed proof,
  // and a NIC-bound endpoint has no loopback traffic the exception exists for.
  assert!(
    !arrived_on_bound_interface(
      peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
      nic(BOUND, &SUBNETS),
      0,
      true
    ),
    "the loopback exception is the loopback-BOUND endpoint's; a loopback \
     SOURCE must not open it at stage 1"
  );
  // Nor by way of the source arm, where the same short-circuit used to sit: a
  // loopback source now answers to exactly the link evidence every other source
  // does, so a reported zero is a failed proof there too.
  assert!(!src_on_local_link(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    nic(BOUND, &SUBNETS),
    0,
    true
  ));
  // And it does NOT degrade open on a path with no interface to give: a
  // loopback source is this endpoint's own traffic or it is nothing, and a
  // NIC-bound endpoint has none. Absent provenance is not membership.
  assert!(!src_on_local_link(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    nic(BOUND, &SUBNETS),
    0,
    false
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
  assert!(admits(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(admits(
    peer(OFF_SUBNET_V6),
    Some(V6_GROUP),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // An empty subnet list is the same case with the evidence gone entirely: the
  // group destination is the whole proof, so it must not depend on `subnets`.
  assert!(admits(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
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
  assert!(!admits(
    peer(OFF_SUBNET_V4),
    Some(UNICAST_V4_DST),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(!admits(
    peer(OFF_SUBNET_V6),
    Some(UNICAST_V6_DST),
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // And it still ADMITS on a matching prefix, so the arm is intact in both
  // directions rather than merely unreachable.
  assert!(admits(
    on_subnet(),
    Some(UNICAST_V4_DST),
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
  assert!(!admits(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
    None,
    &SUBNETS,
    BOUND,
    OTHER
  ));
  assert!(!admits(
    peer(OFF_SUBNET_V6),
    Some(V6_GROUP),
    None,
    &SUBNETS,
    BOUND,
    OTHER
  ));
  // The scope witness too: an index naming our own interface does not rescue a
  // source whose zone names another link, group destination or not.
  assert!(!admits(
    scoped(LINK_LOCAL, OTHER),
    Some(V6_GROUP),
    None,
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
  assert!(admits(
    peer(OFF_SUBNET_V4),
    None,
    Some(LinkDelivery::Multicast),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  // Not a subnet question at all: an empty list changes nothing, because the
  // multicast delivery is the whole proof.
  assert!(admits(
    peer(OFF_SUBNET_V4),
    None,
    Some(LinkDelivery::Multicast),
    &[],
    BOUND,
    BOUND
  ));
  assert!(admits(
    peer(OFF_SUBNET_V6),
    None,
    Some(LinkDelivery::Multicast),
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
  assert!(!admits(
    peer(OFF_SUBNET_V4),
    None,
    None,
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(admits(on_subnet(), None, None, &SUBNETS, BOUND, BOUND));
  // A flag that is present and says "not multicast" is the same answer by a
  // different route: the datagram was addressed to this host, which is the arm
  // the source prefix is for.
  assert!(!admits(
    peer(OFF_SUBNET_V4),
    None,
    Some(LinkDelivery::Unicast),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(admits(
    on_subnet(),
    None,
    Some(LinkDelivery::Unicast),
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
  assert!(!admits(
    peer(OFF_SUBNET_V6),
    Some(UNICAST_V6_DST),
    Some(LinkDelivery::Multicast),
    &SUBNETS,
    BOUND,
    BOUND
  ));
  assert!(admits(
    peer(OFF_SUBNET_V6),
    Some(V6_GROUP),
    Some(LinkDelivery::Unicast),
    &SUBNETS,
    BOUND,
    BOUND
  ));
}

#[test]
fn the_multicast_flag_does_not_excuse_a_foreign_link() {
  // Same order of gates as the group destination gets: the interface check runs
  // first. A multicast delivery proves the datagram was addressed to SOME
  // group, never that it arrived on our link.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    None,
    Some(LinkDelivery::Multicast),
    nic(BOUND, &SUBNETS),
    OTHER,
    true
  ));
  assert!(!admits_ingress(
    scoped(LINK_LOCAL, OTHER),
    None,
    Some(LinkDelivery::Multicast),
    nic(BOUND, &SUBNETS),
    BOUND,
    true
  ));
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
  // Neither is the unspecified address, which is not a group and is not a host
  // address either — `the_destination_classes_with_no_section_11_arm_are_refused`
  // is where its refusal is pinned. Note this is NOT what a target with no
  // PKTINFO parser degrades to: that is `destination == None`.
  assert!(!is_mdns_group(UNSPECIFIED_V4_DST));
  assert!(!is_mdns_group(UNSPECIFIED_V6_DST));
  // A broadcast is not a group either, in the one form std can recognise. §11's
  // first arm names two addresses and this is not a link-scope test.
  assert!(!is_mdns_group(LIMITED_BROADCAST));
  assert!(!is_mdns_group(DIRECTED_BROADCAST));
  // The families do not cross: a group compared against the other family's
  // address is not a match by accident of octets.
  assert!(!is_mdns_group(IpAddr::V6(Ipv6Addr::new(
    0, 0, 0, 0, 0, 0xffff, 0xe000, 0x00fb
  ))));
}

#[test]
fn collect_local_subnets_enumerates_nothing_for_a_zero_index() {
  // Index 0 names no interface. The §11 fallback is scoped to the BOUND
  // interface, so a zero must NOT collapse into "every NIC on this host" —
  // which would let another link's prefix admit a global source. An empty list
  // is a refusal, and a refusal is the right answer here.
  assert!(collect_local_subnets(0).is_empty());
}

// ── a conforming hop limit decides only for a WITNESSED link ────────────────
//
// `arrived_on_bound_interface` admits an unwitnessed datagram wherever the
// caller's receive path had no witness to give. That is the absence of evidence,
// not proof, and a hop limit of 255 does not supply what is missing: it answers
// "did this cross a router", never "whose link is this". Left decisive on top of
// an unwitnessed admission it reopens the whole cross-NIC attack on exactly the
// targets that cannot see it coming.

#[test]
fn is_loopback_interface_refuses_what_it_cannot_prove() {
  // Index 0 names no interface, and an index nothing can resolve is not evidence
  // of anything. The loopback exception is a widening, so both must answer
  // "no" — the flag is only ever granted on a positive read.
  assert!(!is_loopback_interface(0));
  assert!(!is_loopback_interface(u32::MAX));
}

/// §11's unicast test is the source against the interface's configured address
/// and mask, and it names no exception for IPv4 link-local.
///
/// An infrastructure-less link is where mDNS matters most and where every
/// address — ours and every peer's — is a `169.254/16` one. Diverting all of
/// them into a branch that demands a receive witness made IPv4 mDNS deaf there
/// on exactly the squares that have no witness to give.
#[test]
fn an_unwitnessed_apipa_source_answers_to_the_configured_prefix() {
  let peer_ll = peer(IpAddr::V4(Ipv4Addr::new(169, 254, 3, 9)));

  for reported in [true, false] {
    // The bound interface carries the same link-local prefix: admitted, on the
    // same evidence any other in-prefix source is admitted on.
    assert!(
      src_on_local_link(peer_ll, nic(BOUND, &APIPA), 0, reported),
      "a link-local peer on a link-local-configured interface is on-link per §11"
    );
    // And with no matching prefix it is still refused, so the arm did not turn
    // into a blanket link-local exemption.
    assert!(!src_on_local_link(
      peer_ll,
      nic(BOUND, &SUBNETS),
      0,
      reported
    ));
  }

  // Through the whole boundary, on the square this is actually for: a receive
  // path with no interface to give. With `iface_reported` true a zero index is
  // a failed proof and never reaches the source arm at all — see
  // `an_unreported_interface_is_absent_evidence_and_a_reported_zero_is_a_failed_proof`.
  assert!(admits_ingress(
    peer_ll,
    None,
    None,
    nic(BOUND, &APIPA),
    0,
    false
  ));

  // A contradicting witness still refuses — at stage 1, which is where that
  // question belongs. §11's second arm asks only about the prefix.
  assert!(!admits_ingress(
    peer_ll,
    None,
    None,
    nic(BOUND, &APIPA),
    OTHER,
    true
  ));
  assert!(src_on_local_link(peer_ll, nic(BOUND, &APIPA), BOUND, true));
  // The IPv6 twin, through the boundary: a foreign scope refuses at stage 1, and
  // a matching one is admitted only because the interface also carries
  // `fe80::/64`.
  assert!(!admits_ingress(
    scoped(LINK_LOCAL, OTHER),
    None,
    None,
    nic(BOUND, &LL_PREFIXES),
    0,
    true
  ));
  assert!(admits_ingress(
    scoped(LINK_LOCAL, BOUND),
    None,
    None,
    nic(BOUND, &LL_PREFIXES),
    0,
    true
  ));
}

/// The staged contract, checked exhaustively over every combination of its
/// inputs rather than at points chosen to make a claim come out.
///
/// Two dimensions collapsed when the TTL stages went: there is no `hop_limit`
/// input any more, and no stage that returns before the destination is read. The
/// space is sources x links x bound configs x receive indices x capability x
/// destinations x flags, which is small enough to enumerate whole rather than
/// sample.
///
/// What is asserted is the STAGES, each stated in terms of the raw inputs — not
/// a second implementation of the decision, which would only mirror whatever the
/// first one does. In particular **no invariant asks production what a
/// destination is**: every link below is enumerated alongside a hand-written
/// list of the addresses it HOLDS, both written from the same named literals,
/// and that list is the only thing the destination invariants consult.
///
/// # Counters are keyed by the family the invariant is ABOUT
///
/// Every invariant carries a per-family firing count and the test fails if the
/// families it needs never fired. The key is the SOURCE's family for a
/// source-or-link invariant and the DESTINATION's for a destination-class one,
/// and the distinction is load-bearing rather than tidy: this is a Cartesian
/// product, so cross-family pairs are in it. Keying a destination-class counter
/// off the source recorded an IPv6 firing for an IPv4-only class every time an
/// IPv6 source was paired with it, and a "fired for both families" check then
/// passed with the IPv4-destination coverage it existed to guarantee gone
/// entirely.
///
/// So an IPv4-only class asserts `v4 > 0 && v6 == 0`. The second half is the one
/// that catches the mis-keying, and it is worth as much as the first.
///
/// # Each destination class is counted only against an ADMITTING source
///
/// A refusal is evidence about the destination only if nothing else in the case
/// could have produced it. Every destination-class counter therefore requires
/// `source_arm_admits` — stage 1 passed AND §11's source arm would have taken
/// this source on this link — so the destination is the only thing left that can
/// refuse. Without that control the counters could be satisfied entirely by
/// pairs the source arm refuses anyway, which is the vacuity a Cartesian product
/// invites.
#[test]
fn the_staged_contract_holds_over_every_combination_of_its_inputs() {
  // Sources covering every shape stages 1 and 3 distinguish, in both families:
  // loopback, link-local with each scope value, routable in and out of prefix.
  let sources: [SocketAddr; 10] = [
    on_subnet(),
    peer(OFF_SUBNET_V4),
    peer(IpAddr::V4(Ipv4Addr::new(169, 254, 3, 9))),
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    peer(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    peer(OFF_SUBNET_V6),
    peer(IpAddr::V6(Ipv6Addr::new(
      0x2001, 0xdb8, 0xbeef, 0, 0, 0, 0, 7,
    ))),
    peer(IpAddr::V6(LINK_LOCAL)),
    scoped(LINK_LOCAL, BOUND),
    scoped(LINK_LOCAL, OTHER),
  ];
  // Each enumerated link, paired with the addresses it HOLDS. Both sides name
  // the same constants, so the pairing cannot drift from the fixture — and the
  // right-hand list, never `subnets` and never a production helper, is what the
  // destination invariants below read.
  //
  // `NON_DEFAULT_BROADCAST_LINK` is the one an operator configured a broadcast
  // address for by hand, and `LOOPBACK_LINK` is the one with no broadcast
  // capability at all. Both are links whose broadcast a computation over
  // `addr/prefix` gets wrong; neither needs one here.
  let links: [EnumeratedLink; 6] = [
    (&[], &[]),
    (&SUBNETS, &[OUR_V4_ADDR, OUR_V6_ADDR]),
    (&APIPA, &[OUR_V4_LL_ADDR]),
    (&V6_PREFIX, &[V6_PREFIX_ADDR]),
    (&NON_DEFAULT_BROADCAST_LINK, &[NON_DEFAULT_BROADCAST_HOST]),
    (&LOOPBACK_LINK, &[LOOPBACK_V4_ADDR, LOOPBACK_V6_ADDR]),
  ];
  // Every destination the partition must tell apart. The first group is §11's
  // two arms: the two groups, and the addresses the links above hold. The rest
  // have no arm at all — and the list is not a taxonomy production shares, it is
  // the set of concrete addresses a wrong rule has admitted or would admit.
  //
  // Each of the last nine reached §11's source arm under some previous version
  // of this partition: a foreign group under "group or not"; the limited and
  // directed broadcasts under "multicast or not"; the operator-configured
  // broadcast, the martian and a neighbour's address under "computes to a
  // broadcast of one of our prefixes, or not".
  let dests = [
    None,
    Some(V4_GROUP),
    Some(V6_GROUP),
    Some(OUR_V4_ADDR),
    Some(OUR_V6_ADDR),
    Some(OUR_V4_LL_ADDR),
    Some(V6_PREFIX_ADDR),
    Some(NON_DEFAULT_BROADCAST_HOST),
    Some(LOOPBACK_V4_ADDR),
    Some(LOOPBACK_V6_ADDR),
    Some(LOOPBACK_ALT_V4_ADDR),
    Some(FOREIGN_V4_GROUP),
    Some(FOREIGN_V6_GROUP),
    Some(LIMITED_BROADCAST),
    Some(DIRECTED_BROADCAST),
    Some(NON_DEFAULT_BROADCAST),
    Some(LOOPBACK_BROADCAST),
    Some(UNSPECIFIED_V4_DST),
    Some(UNSPECIFIED_V6_DST),
    Some(MARTIAN_V4_DST),
    Some(NEIGHBOUR_V4_DST),
    Some(NEIGHBOUR_V6_DST),
  ];
  // The three delivery classes plus "this target reports none". `Broadcast`
  // is new: it is the only value that REFUSES on its own, and only where no
  // destination was recovered.
  let flags = [
    None,
    Some(LinkDelivery::Multicast),
    Some(LinkDelivery::Unicast),
    Some(LinkDelivery::Broadcast),
  ];
  let pkt_ifaces = [0u32, BOUND, OTHER];
  let bounds = [(BOUND, false), (BOUND, true), (0, false)];

  // Per-family firing counts, so neither family can go unprobed. Named rather
  // than indexed: this crate denies `indexing_slicing`, and a trust boundary's
  // tests should not be the place that argues for an exception.
  //
  // The first group is keyed by the SOURCE's family, the second by the
  // DESTINATION's. Which one a counter takes is stated at each `hit`.
  let mut contradicted_fired = Fired::default();
  let mut absent_iface_fired = Fired::default();
  let mut in_prefix_fired = Fired::default();
  let mut nothing_left_fired = Fired::default();
  let mut unbound_fired = Fired::default();
  let mut coarse_flag_fired = Fired::default();
  let mut broadcast_delivery_fired = Fired::default();
  let mut group_arm_fired = Fired::default();
  let mut arm_two_fired = Fired::default();
  let mut loopback_block_fired = Fired::default();
  let mut no_arm_fired = Fired::default();
  let mut empty_snapshot_fired = Fired::default();
  let mut foreign_group_fired = Fired::default();
  let mut unspecified_dst_fired = Fired::default();
  let mut neighbour_dst_fired = Fired::default();
  let mut limited_broadcast_fired = Fired::default();
  let mut directed_broadcast_fired = Fired::default();
  let mut non_default_broadcast_fired = Fired::default();
  let mut loopback_broadcast_fired = Fired::default();
  let mut martian_fired = Fired::default();
  let mut cases = 0u32;

  for &src in &sources {
    let src_v6 = src.is_ipv6();
    for &(subnets, assigned) in &links {
      for &(bound_iface, is_lo) in &bounds {
        let link = BoundLink::new(bound_iface, is_lo, subnets);
        for &pkt_iface in &pkt_ifaces {
          for &reported in &[false, true] {
            for &dst in &dests {
              for &flag in &flags {
                cases = cases.saturating_add(1);
                let got = admits_ingress(src, dst, flag, link, pkt_iface, reported);
                let scope = match src {
                  SocketAddr::V6(a) => a.scope_id(),
                  SocketAddr::V4(_) => 0,
                };
                let witnesses = [pkt_iface, scope];
                let contradicted =
                  bound_iface != 0 && witnesses.iter().any(|&w| w != 0 && w != bound_iface);
                let witnessed = witnesses.iter().any(|&w| w != 0);
                let loopback_own = is_lo && src.ip().is_loopback();
                let in_prefix = subnets
                  .iter()
                  .any(|&(n, pfx)| addr_in_subnet(n, pfx, src.ip()));
                let stage1 = arrived_on_bound_interface(src, link, pkt_iface, reported);
                // Whether §11's SOURCE arm would take this source on this link:
                // a loopback source belongs to a loopback-BOUND endpoint and
                // nobody else, and every other source answers to the prefix.
                // The control every destination-class counter below requires, so
                // that a refusal there is attributable to the destination.
                let source_arm_admits = stage1
                  && if src.ip().is_loopback() {
                    is_lo
                  } else {
                    in_prefix
                  };

                // 1. A nonzero witness that disagrees refuses, and no later
                //    stage overturns it — not even a group destination.
                if contradicted {
                  contradicted_fired.hit(src_v6);
                  assert!(!got, "stage 1: {src} vs bound {bound_iface} on {pkt_iface}");
                }
                // 2. No witness at all on a path that COULD name the link is a
                //    failed proof, except a loopback-bound endpoint's own.
                if bound_iface != 0 && !witnessed && reported && !loopback_own {
                  absent_iface_fired.hit(src_v6);
                  assert!(
                    !got,
                    "stage 1: an expected-but-absent interface fails closed"
                  );
                }

                // The destination partition, stated where the enumeration can
                // see it, and stated POSITIVELY: `ours_group` and
                // `assigned_here` are the two things §11 gives an arm to, and
                // everything else is the third line of the rule rather than a
                // list to keep current. `assigned` is the literal table above,
                // so nothing here can agree with production by construction.
                //
                // Four rounds of review found a class that a residual defined as
                // "none of the above" had absorbed. There is no such residual to
                // write here any more, and that is the whole of what changed.
                let ours_group = dst == Some(V4_GROUP) || dst == Some(V6_GROUP);
                let assigned_here = matches!(dst, Some(d) if assigned.contains(&d));
                let dst_v6 = matches!(dst, Some(d) if d.is_ipv6());
                // RFC 1122 §3.2.1.3 makes the whole `127.0.0.0/8` block (and
                // `::1`) this host's own, so a loopback-BOUND endpoint holds
                // every address in it whether or not the enumeration named it.
                // `LOOPBACK_BLOCK` is the literal list of the enumerated
                // destinations that fall inside; the oracle reads it rather than
                // calling `is_loopback()`, which is the question production
                // asks and so cannot be the question that checks production.
                let in_loopback_block = matches!(dst, Some(d) if LOOPBACK_BLOCK.contains(&d));
                let held_by_block = is_lo && in_loopback_block;
                let held_here = assigned_here || held_by_block;
                // The one exception, and it is about the SNAPSHOT rather than
                // about any destination: an empty list is a failed enumeration,
                // not a verdict, so it defers to the source arm. Invariant 7
                // pins exactly how far that can go.
                let empty_snapshot = subnets.is_empty();
                let no_arm = dst.is_some() && !ours_group && !held_here && !empty_snapshot;
                // With NO destination recovered, a broadcast DELIVERY refuses
                // on its own. It is the only value of the coarse signal that
                // does, and it is exact rather than approximate: §11 gives a
                // broadcast no arm, so no address is needed to decide it.
                let no_dst_broadcast = dst.is_none() && flag == Some(LinkDelivery::Broadcast);
                // What reaches §11's second arm: a destination this endpoint
                // holds, a destination on a link that enumerated nothing, or no
                // destination at all with the coarse signal saying neither
                // multicast nor broadcast.
                let host_address_arm = (dst.is_some() && !ours_group && !no_arm)
                  || (dst.is_none() && flag != Some(LinkDelivery::Multicast) && !no_dst_broadcast);

                // 3. Past stage 1, OUR group admits regardless of source —
                //    §11's "regardless of source IP address". Keyed by the
                //    DESTINATION's family: it is the destination that selects
                //    this arm.
                if stage1 && ours_group {
                  group_arm_fired.hit(dst_v6);
                  assert!(got, "stage 2: the group arm must admit {src}");
                }
                // 3b. The coarse flag stands in where no destination was
                //     recovered. Keyed by the SOURCE's family — there is no
                //     destination here to key on, which is the whole point of
                //     this square.
                if stage1 && dst.is_none() && flag == Some(LinkDelivery::Multicast) {
                  coarse_flag_fired.hit(src_v6);
                  assert!(got, "stage 2: a multicast delivery must admit {src}");
                }
                // 3c. A broadcast delivery with no destination is REFUSED,
                //     whatever the source, the witnesses or the prefixes say.
                //     Counted only against a source the source arm WOULD have
                //     admitted, so the refusal is attributable to the delivery
                //     class and cannot be the source's doing. Keyed by the
                //     SOURCE's family: there is no destination here to key on.
                if no_dst_broadcast {
                  assert!(
                    !got,
                    "a broadcast delivery has no §11 arm and needs no address \
                     to be refused: {src}"
                  );
                  if source_arm_admits {
                    broadcast_delivery_fired.hit(src_v6);
                  }
                }
                // 4. A destination this endpoint HOLDS is what §11 means by
                //    "received via unicast", so stage 1 and the source arm are
                //    the WHOLE decision. An equality, so it pins the arm in both
                //    directions rather than only where it refuses.
                if held_here {
                  arm_two_fired.hit(dst_v6);
                  assert_eq!(
                    got, source_arm_admits,
                    "stage 2: a destination this endpoint holds decides on the \
                     source and nothing else: {src} -> {dst:?}"
                  );
                }
                // 4b. ... and the loopback BLOCK is one of the two ways to hold
                //     one. Counted separately where the block is the ONLY thing
                //     that holds it — the enumeration named `127.0.0.1` and
                //     `::1` and never `127.0.0.2` or `127.255.255.255` — so this
                //     cannot be satisfied by an address that was enumerated
                //     anyway.
                if held_by_block && !assigned_here {
                  loopback_block_fired.hit(dst_v6);
                  assert_eq!(
                    got, source_arm_admits,
                    "RFC 1122 §3.2.1.3: a loopback-bound endpoint holds the \
                     whole 127.0.0.0/8 block, not the one address enumerated: \
                     {src} -> {dst:?}"
                  );
                }
                // 4c. The same address on a NIC-bound endpoint is a martian
                //     destination and stays refused. The block widens exactly
                //     one configuration and this is where that scoping is
                //     checked, rather than left to the `no_arm` aggregate.
                if in_loopback_block && !is_lo && !assigned_here && !empty_snapshot {
                  assert!(
                    !got,
                    "the loopback block is a loopback-BOUND endpoint's; on a \
                     NIC a 127/8 destination is a martian: {src} -> {dst:?}"
                  );
                }
                // 5. Every other destination, on a link that DID enumerate, has
                //    no §11 arm and is refused — whatever the source, the
                //    witnesses or the flag say.
                if no_arm {
                  no_arm_fired.hit(dst_v6);
                  assert!(
                    !got,
                    "a destination this link does not hold has no §11 arm: \
                     {src} -> {dst:?}"
                  );
                }
                // 5a-5h. The same refusal, per class, each counted only where
                //        the source arm WOULD have admitted — so the refusal is
                //        the destination and cannot be the source, the prefix or
                //        the interface. Guarded by `no_arm` itself, so a
                //        destination the endpoint turns out to HOLD (the
                //        loopback block) leaves its class counter alone instead
                //        of asserting a refusal that is no longer correct.
                if source_arm_admits && no_arm {
                  if matches!(dst, Some(FOREIGN_V4_GROUP) | Some(FOREIGN_V6_GROUP)) {
                    foreign_group_fired.hit(dst_v6);
                    assert!(!got, "a foreign multicast group has no §11 arm: {src}");
                  }
                  if matches!(dst, Some(UNSPECIFIED_V4_DST) | Some(UNSPECIFIED_V6_DST)) {
                    unspecified_dst_fired.hit(dst_v6);
                    assert!(!got, "an unspecified destination has no §11 arm: {src}");
                  }
                  if matches!(dst, Some(NEIGHBOUR_V4_DST) | Some(NEIGHBOUR_V6_DST)) {
                    neighbour_dst_fired.hit(dst_v6);
                    assert!(
                      !got,
                      "a neighbour's address on our own subnet was not addressed \
                       to us: {src} -> {dst:?}"
                    );
                  }
                  if dst == Some(LIMITED_BROADCAST) {
                    limited_broadcast_fired.hit(dst_v6);
                    assert!(!got, "255.255.255.255 has no §11 arm: {src}");
                  }
                  if dst == Some(DIRECTED_BROADCAST) {
                    directed_broadcast_fired.hit(dst_v6);
                    assert!(!got, "192.168.1.255 has no §11 arm: {src}");
                  }
                  if dst == Some(NON_DEFAULT_BROADCAST) {
                    non_default_broadcast_fired.hit(dst_v6);
                    assert!(
                      !got,
                      "192.168.1.200 is a broadcast no arithmetic over \
                       192.168.1.5/24 finds, and has no §11 arm: {src}"
                    );
                  }
                  if dst == Some(LOOPBACK_BROADCAST) {
                    loopback_broadcast_fired.hit(dst_v6);
                    assert!(!got, "127.255.255.255 has no §11 arm: {src}");
                  }
                  if dst == Some(MARTIAN_V4_DST) {
                    martian_fired.hit(dst_v6);
                    assert!(!got, "240.0.0.1 has no §11 arm: {src}");
                  }
                }
                // 6. Past stage 1 and on the host-address arm, an in-prefix
                //    source is admitted.
                if stage1 && host_address_arm && in_prefix && !src.ip().is_loopback() {
                  in_prefix_fired.hit(src_v6);
                  assert!(got, "stage 3: an in-prefix source must be admitted: {src}");
                }
                // 6b. ... and one with no prefix, no group and no loopback claim
                //     is refused. Nothing admits on arrival alone.
                // NO carve-out for a witnessed link-local source. There used
                // to be one, and it was what let a third §11 arm survive
                // unnoticed: the invariant exempted exactly the branch that
                // deviated, so the enumeration ratified the deviation instead
                // of detecting it. The only exemption left is loopback, which
                // is a documented arm of its own rather than a shortcut around
                // this one.
                if stage1 && host_address_arm && !in_prefix && !loopback_own {
                  nothing_left_fired.hit(src_v6);
                  assert!(!got, "stage 3: nothing left to admit on: {src}");
                }
                // 7. The empty-snapshot decision, and its EXACT bound. With
                //    nothing enumerated, "not one of our addresses" is not a
                //    fact this endpoint established, so the destination test
                //    defers to the source arm — and the source arm with no
                //    prefixes to match admits a loopback-BOUND endpoint's own
                //    traffic and nothing whatsoever else. Written as an
                //    equality, because the claim this decision rests on is that
                //    the fallback is bounded, not merely that it is not open.
                if empty_snapshot && dst.is_some() && !ours_group {
                  empty_snapshot_fired.hit(dst_v6);
                  assert_eq!(
                    got,
                    stage1 && is_lo && src.ip().is_loopback(),
                    "an empty snapshot runs the source arm, which then admits \
                     only a loopback-bound endpoint's own traffic: {src} -> \
                     {dst:?}"
                  );
                }
                // 8. An endpoint that knows no link of its own forbids nothing
                //    at stage 1.
                if bound_iface == 0 {
                  unbound_fired.hit(src_v6);
                  assert!(stage1, "an unbound endpoint must forbid nothing");
                }
              }
            }
          }
        }
      }
    }
  }

  // Invariants whose subject exists in both families: each must have fired for
  // both, or half the rule went unprobed.
  for (fired, what) in [
    (contradicted_fired, "contradicted witness"),
    (absent_iface_fired, "expected-but-absent interface"),
    (in_prefix_fired, "in-prefix source at the host-address arm"),
    (nothing_left_fired, "nothing left to admit on"),
    (unbound_fired, "unbound endpoint"),
    (coarse_flag_fired, "no destination, coarse multicast flag"),
    (
      broadcast_delivery_fired,
      "no destination, broadcast delivery, against an admitting source",
    ),
    (group_arm_fired, "our group destination"),
    (arm_two_fired, "a destination this endpoint holds"),
    (
      loopback_block_fired,
      "the RFC 1122 loopback block, where the enumeration did not name it",
    ),
    (no_arm_fired, "a destination this endpoint does not hold"),
    (empty_snapshot_fired, "empty-snapshot fallback"),
    (foreign_group_fired, "foreign multicast destination"),
    (unspecified_dst_fired, "unspecified destination"),
    (neighbour_dst_fired, "a neighbour's address"),
  ] {
    assert!(
      fired.both(),
      "invariant did not fire for both families over {cases} cases \
       (v4 {}, v6 {}): {what}",
      fired.v4,
      fired.v6
    );
  }
  // Classes that exist only in IPv4. `v6 == 0` is asserted as hard as `v4 > 0`:
  // a counter keyed off the SOURCE's family records a phantom IPv6 firing here
  // for every IPv6 source paired with an IPv4-only destination, and `both()`
  // then passes with no IPv4-destination coverage left at all. That is the
  // mis-keying this half exists to catch.
  for (fired, what) in [
    (limited_broadcast_fired, "255.255.255.255"),
    (directed_broadcast_fired, "192.168.1.255"),
    (non_default_broadcast_fired, "192.168.1.200"),
    (loopback_broadcast_fired, "127.255.255.255"),
    (martian_fired, "240.0.0.1"),
  ] {
    assert!(
      fired.only_v4(),
      "an IPv4-only destination class must fire for IPv4 and NEVER for IPv6 \
       over {cases} cases (v4 {}, v6 {}): {what}",
      fired.v4,
      fired.v6
    );
  }
}

/// One link of the enumeration above: the snapshot a driver would hand
/// [`BoundLink::new`], paired with the addresses that snapshot HOLDS.
///
/// The pair is the point. The right-hand list is written from the same named
/// constants as the left, and it — never `subnets`, never `is_bound_address` —
/// is what every destination invariant reads, so an invariant cannot come to
/// agree with production by computing what production computes.
type EnumeratedLink = (&'static [(IpAddr, u8)], &'static [IpAddr]);

/// Per-family firing count for one invariant of the enumeration above.
#[derive(Default, Clone, Copy)]
struct Fired {
  v4: u32,
  v6: u32,
}

impl Fired {
  fn hit(&mut self, is_v6: bool) {
    // Saturating because this crate forbids panicking arithmetic; the counts are
    // only ever compared against zero, so a saturated value says what it needs
    // to.
    if is_v6 {
      self.v6 = self.v6.saturating_add(1);
    } else {
      self.v4 = self.v4.saturating_add(1);
    }
  }

  /// Whether the invariant's precondition was reached for BOTH families. One
  /// family alone leaves the other half of the rule unprobed, which a
  /// whole-space counter cannot tell you.
  fn both(&self) -> bool {
    self.v4 > 0 && self.v6 > 0
  }

  /// Whether an IPv4-ONLY class fired for IPv4 and for nothing else. The second
  /// half is not pedantry: a firing recorded against IPv6 for a destination that
  /// has no IPv6 form means the counter is keyed off something other than the
  /// destination, and every guarantee it was carrying is void.
  fn only_v4(&self) -> bool {
    self.v4 > 0 && self.v6 == 0
  }
}

// ── three counterexamples to a staged decision described as a table ─────────
//
// A table over "provenance" and "destination evidence" reads as though those
// two facts select a behaviour. They do not: this is a staged decision, and
// several stages return before the destination is ever examined. Each case
// below is a combination the table gets wrong, kept as a test so the prose
// cannot drift back into one.

#[test]
fn a_witnessed_datagram_still_answers_to_the_destination_and_the_prefix() {
  // What the removed hop-limit shortcut used to skip. A witnessed datagram at a
  // conforming TTL was admitted before either §11 arm was read, so a witnessed
  // OUT-OF-PREFIX unicast was admitted where §11 expects a receiver to ignore
  // it. There is no TTL input any more, and the arms decide.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    Some(UNICAST_V4_DST),
    None,
    nic(BOUND, &[]),
    BOUND,
    true
  ));
  // The same witnessed datagram addressed to the group is admitted, because §11
  // says a group destination is local-link origin regardless of source.
  assert!(admits_ingress(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
    None,
    nic(BOUND, &[]),
    BOUND,
    true
  ));
  // And in-prefix unicast is admitted by the unicast arm.
  assert!(admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    nic(BOUND, &SUBNETS),
    BOUND,
    true
  ));
}

#[test]
fn an_expected_but_missing_interface_refuses_before_the_group_arm() {
  // The case a two-valued "provenance absent" hides: absence is not one
  // condition. A path that CAN report an interface and returned zero — a
  // missing or truncated PKTINFO cmsg — is a failed proof, and the boundary
  // returns at the interface stage. So a perfectly valid group response is
  // refused before §11's group arm is consulted at all.
  for dst in [Some(V4_GROUP), Some(V6_GROUP), None] {
    for flag in [None, Some(LinkDelivery::Multicast)] {
      assert!(
        !admits_ingress(
          peer(OFF_SUBNET_V4),
          dst,
          flag,
          nic(BOUND, &SUBNETS),
          0,
          true
        ),
        "a capable path reporting index 0 must fail closed at the interface \
         stage, whatever the destination says"
      );
    }
  }
  // The SAME datagram on a path that reports no interface reaches the group arm
  // and is admitted. Identical provenance value, opposite outcome — decided by
  // the capability, which the table did not carry.
  assert!(admits_ingress(
    peer(OFF_SUBNET_V4),
    Some(V4_GROUP),
    None,
    nic(BOUND, &SUBNETS),
    0,
    false
  ));
}

#[test]
fn a_scope_id_is_provenance_even_where_no_interface_index_is() {
  // The completion-path square, corrected. A driver whose receive path is a
  // plain `recvfrom` recovers no interface index and no destination — but the
  // peer `sockaddr_in6` it does recover carries `sin6_scope_id`, which every
  // supported platform fills from the receiving interface for a link-local
  // source, Windows included. This module counts a nonzero scope as provenance,
  // so such a path is NOT uniformly provenance-less: link-local IPv6 is
  // witnessed there and everything else is not.
  for reported in [false, true] {
    // Scope names our link: stage 1 passes on it alone, and §11's second arm
    // then admits because the interface carries the matching prefix.
    assert!(admits_ingress(
      scoped(LINK_LOCAL, BOUND),
      None,
      None,
      nic(BOUND, &LL_PREFIXES),
      0,
      reported
    ));
    // Scope names another: refused at the interface stage, prefix or not.
    assert!(!admits_ingress(
      scoped(LINK_LOCAL, OTHER),
      None,
      None,
      nic(BOUND, &LL_PREFIXES),
      0,
      reported
    ));
  }
  // A scopeless IPv6 source on the same path has no witness at all, so it lands
  // in the genuinely provenance-less case and answers to the source prefix.
  let global_v6 = peer(OFF_SUBNET_V6);
  assert!(!admits_ingress(
    global_v6,
    None,
    None,
    nic(BOUND, &SUBNETS),
    0,
    false
  ));
}

#[test]
fn a_matching_witness_does_not_admit_a_link_local_source_without_a_prefix() {
  // §11 has two arms and a witness is not one of them. A witness settles which
  // LINK a datagram arrived on — stage 1's question — and says nothing about
  // whether the source belongs to a prefix this interface carries.
  //
  // This is the branch that used to return true here, in both families: an
  // interface configured only for `192.168.1.0/24` admitted unicast from
  // `169.254.7.7` and from `fe80::…` purely because the receive index or scope
  // agreed.
  let v4_ll = peer(IpAddr::V4(Ipv4Addr::new(169, 254, 7, 7)));
  let v6_ll = scoped(LINK_LOCAL, BOUND);
  // Each source is paired with the address of ITS OWN family that each link
  // holds, so every assertion below reaches §11's second arm and the prefix is
  // the only thing left to decide it.
  for (src, ours, theirs, what) in [
    (v4_ll, UNICAST_V4_DST, LL_UNICAST_V4_DST, "169.254/16"),
    (v6_ll, UNICAST_V6_DST, LL_UNICAST_V6_DST, "fe80::/10"),
  ] {
    assert!(
      !src_on_local_link(src, nic(BOUND, &SUBNETS), BOUND, true),
      "{what}: a matching witness must not stand in for §11's prefix test"
    );
    assert!(
      !admits_ingress(src, Some(ours), None, nic(BOUND, &SUBNETS), BOUND, true),
      "{what}: and the whole boundary must refuse it too"
    );
    // The interface carrying the matching prefix is what admits it — §11's own
    // second arm, and the APIPA case that arm exists to serve.
    assert!(admits_ingress(
      src,
      Some(theirs),
      None,
      nic(BOUND, &LL_PREFIXES),
      BOUND,
      true
    ));
    // A group destination still admits regardless of prefix, as §11 requires.
    assert!(admits_ingress(
      src,
      Some(V6_GROUP),
      None,
      nic(BOUND, &SUBNETS),
      BOUND,
      true
    ));
  }
}

#[test]
fn a_multicast_destination_that_is_not_ours_has_no_arm_and_is_refused() {
  // §11 partitions by destination and offers an arm for exactly two of the
  // three kinds. Letting the third fall through to the second admitted an
  // in-prefix packet addressed to LLMNR's group on a comparison §11 scopes to
  // UNICAST destinations — and on Linux that is reachable, because
  // `IP_MULTICAST_ALL` defaults to delivering every globally-joined group to a
  // matching socket, so another process joining it is enough.
  for foreign in [FOREIGN_V4_GROUP, FOREIGN_V6_GROUP] {
    // The source is in-prefix and the witness agrees: everything the unicast
    // arm would have admitted on.
    assert!(
      !admits_ingress(
        on_subnet(),
        Some(foreign),
        None,
        nic(BOUND, &SUBNETS),
        BOUND,
        true
      ),
      "{foreign} is not an mDNS group, so §11 has no arm that admits it"
    );
    // Not rescued by the coarse flag either, which is a weaker signal than the
    // destination it would be overruling.
    assert!(!admits_ingress(
      on_subnet(),
      Some(foreign),
      Some(LinkDelivery::Multicast),
      nic(BOUND, &SUBNETS),
      BOUND,
      true
    ));
  }
  // Ours, same everything else: admitted. So the rejection above is the group
  // and not the source or the interface.
  for ours in [V4_GROUP, V6_GROUP] {
    assert!(admits_ingress(
      on_subnet(),
      Some(ours),
      None,
      nic(BOUND, &SUBNETS),
      BOUND,
      true
    ));
  }
  // And a unicast destination with the same source still reaches the prefix
  // arm, so the partition did not swallow arm two.
  assert!(admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    nic(BOUND, &SUBNETS),
    BOUND,
    true
  ));
}

#[test]
fn a_destination_this_interface_does_not_hold_has_no_section_11_arm() {
  // The whole of the partition's third line, checked against every class that
  // has ever reached §11's source arm by being left out of a list.
  //
  // Each destination is paired with a source the source arm WOULD admit —
  // `on_subnet()`, inside the bound interface's own prefix, or a loopback source
  // on the endpoint whose link the loopback interface IS — and every witness
  // agrees. So the destination is the only thing left that can refuse any of
  // them.
  //
  // Nothing in this test knows what a broadcast, a martian or a group IS. Each
  // address below is a literal, and the only fact any assertion uses is that
  // `SUBNETS` does not contain it.
  for (dst, what) in [
    (LIMITED_BROADCAST, "255.255.255.255, the limited broadcast"),
    (
      DIRECTED_BROADCAST,
      "192.168.1.255, the all-ones host address of 192.168.1.2/24",
    ),
    (
      NON_DEFAULT_BROADCAST,
      "192.168.1.200, a broadcast address only an operator can name",
    ),
    (FOREIGN_V4_GROUP, "224.0.0.252, LLMNR's IPv4 group"),
    (FOREIGN_V6_GROUP, "ff02::1:3, LLMNR's IPv6 group"),
    (UNSPECIFIED_V4_DST, "0.0.0.0"),
    (UNSPECIFIED_V6_DST, "::"),
    (MARTIAN_V4_DST, "240.0.0.1, a martian"),
    (
      NEIGHBOUR_V4_DST,
      "192.168.1.9, a neighbour on our own subnet",
    ),
    (
      NEIGHBOUR_V6_DST,
      "2001:db8:1::9, a neighbour on our own IPv6 prefix",
    ),
  ] {
    assert!(
      !admits_ingress(
        on_subnet(),
        Some(dst),
        None,
        nic(BOUND, &SUBNETS),
        BOUND,
        true
      ),
      "{what} is not an address this interface holds, so §11 gives it no arm"
    );
    // Not rescued by the coarse flag either, in either direction: a recovered
    // destination outranks it, in all three directions — including
    // `Broadcast`, which is the one value that refuses on its own where no
    // destination was recovered and must not start deciding where one was.
    for flag in [
      Some(LinkDelivery::Multicast),
      Some(LinkDelivery::Unicast),
      Some(LinkDelivery::Broadcast),
    ] {
      assert!(
        !admits_ingress(
          on_subnet(),
          Some(dst),
          flag,
          nic(BOUND, &SUBNETS),
          BOUND,
          true
        ),
        "{what} is refused whatever the coarse flag says"
      );
    }
    // Nor by the loopback exception, which is the SOURCE's: a destination with
    // no arm is refused before the source is consulted at all.
    assert!(
      !admits_ingress(
        peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Some(dst),
        None,
        lo(BOUND, &SUBNETS),
        BOUND,
        true
      ),
      "{what} is refused for a loopback-bound endpoint's own traffic too"
    );
  }
  // The loopback block is the ONE class whose answer depends on which interface
  // this endpoint bound, so it is asserted here rather than in the list above:
  // on a NIC, `127/8` and `::1` are martian destinations and refused, with the
  // same admitting source and the same witnesses. The loopback-BOUND half is
  // `a_loopback_bound_endpoint_holds_the_whole_rfc_1122_block`.
  for dst in LOOPBACK_BLOCK {
    assert!(
      !admits_ingress(
        on_subnet(),
        Some(dst),
        None,
        nic(BOUND, &SUBNETS),
        BOUND,
        true
      ),
      "{dst} is a martian destination on an interface that is not the loopback \
       one, and this endpoint does not hold it"
    );
  }
  // The controls, same everything else: the addresses this interface DOES hold
  // reach the source arm and are admitted, in both families, and so is the
  // group. So the refusals above are the destination and not the source, the
  // subnet or the interface.
  for ours in [UNICAST_V4_DST, UNICAST_V6_DST, V4_GROUP] {
    assert!(
      admits_ingress(
        on_subnet(),
        Some(ours),
        None,
        nic(BOUND, &SUBNETS),
        BOUND,
        true
      ),
      "{ours} must still be admitted, or the refusals above prove nothing"
    );
  }
}

/// R12's live leak, and the reason this partition is positive rather than
/// subtractive.
///
/// `ip addr add 192.168.1.5/24 broadcast 192.168.1.200` is legal, and the link
/// then delivers `192.168.1.200` to every host on it. A partition that DERIVES a
/// broadcast from `addr/prefix` computes `192.168.1.255`, does not recognise
/// `192.168.1.200`, and hands it to §11's source arm — which admits it, because
/// the source is genuinely inside the prefix. Every in-prefix neighbour could
/// then reach the cache and §8.2 conflict handling with one broadcast datagram.
///
/// The refusal here is provable without knowing what a broadcast is: the
/// interface holds `192.168.1.5` and nothing else, so `192.168.1.200` was not
/// addressed to it.
#[test]
fn an_operator_configured_broadcast_address_is_refused_with_no_arithmetic() {
  let src = on_subnet();
  assert!(
    !admits_ingress(
      src,
      Some(NON_DEFAULT_BROADCAST),
      None,
      nic(BOUND, &NON_DEFAULT_BROADCAST_LINK),
      BOUND,
      true
    ),
    "192.168.1.200 is not an address 192.168.1.5/24 holds, whatever a \
     computation over that prefix would have derived"
  );
  // The derived one is refused for the SAME reason rather than by arithmetic,
  // so closing the leak did not open the case that used to be closed.
  assert!(!admits_ingress(
    src,
    Some(DIRECTED_BROADCAST),
    None,
    nic(BOUND, &NON_DEFAULT_BROADCAST_LINK),
    BOUND,
    true
  ));
  // The control: the one address this interface does hold, same source, same
  // witnesses — admitted. So the two refusals are the destination and not the
  // source or the link.
  assert!(
    admits_ingress(
      src,
      Some(NON_DEFAULT_BROADCAST_HOST),
      None,
      nic(BOUND, &NON_DEFAULT_BROADCAST_LINK),
      BOUND,
      true
    ),
    "192.168.1.5 IS this interface's address, so §11's second arm decides it"
  );
  // ... and the source arm really is what decides it there: an off-prefix source
  // to the same held address is refused.
  assert!(!admits_ingress(
    peer(OFF_SUBNET_V4),
    Some(NON_DEFAULT_BROADCAST_HOST),
    None,
    nic(BOUND, &NON_DEFAULT_BROADCAST_LINK),
    BOUND,
    true
  ));
}

/// A directed broadcast is refused on EVERY link now, not only on the one it
/// belongs to.
///
/// The residual this replaces was real: a directed broadcast was recognised only
/// for a subnet the bound interface carried, because that snapshot was the only
/// thing there was to compute one from, so `192.168.1.255` was a broadcast on a
/// `192.168.1.0/24` link and an ordinary host address everywhere else. A router
/// forwarding some other subnet's directed broadcast onto this link landed in
/// the second case.
///
/// Under the positive rule there is nothing to compute and so nothing that
/// depends on which subnet the link carries: `192.168.1.255` is refused on the
/// APIPA link for exactly the reason it is refused on the `192.168.1.2/24` one.
#[test]
fn a_directed_broadcast_is_refused_whatever_subnet_this_link_carries() {
  let apipa_src = peer(IpAddr::V4(Ipv4Addr::new(169, 254, 3, 9)));
  assert!(
    !admits_ingress(
      on_subnet(),
      Some(DIRECTED_BROADCAST),
      None,
      nic(BOUND, &SUBNETS),
      BOUND,
      true
    ),
    "on a 192.168.1.2/24 link, 192.168.1.255 is not the address we hold"
  );
  assert!(
    !admits_ingress(
      apipa_src,
      Some(DIRECTED_BROADCAST),
      None,
      nic(BOUND, &APIPA),
      BOUND,
      true
    ),
    "and on a 169.254.0.2/16 link it is not the address we hold either — the \
     old rule admitted this one, because it could not compute a broadcast for a \
     subnet the link does not carry"
  );
  // The control for the second case: the APIPA link's own address, same source,
  // is admitted. So the refusal above is the destination and not the source.
  assert!(admits_ingress(
    apipa_src,
    Some(LL_UNICAST_V4_DST),
    None,
    nic(BOUND, &APIPA),
    BOUND,
    true
  ));
  // The limited broadcast needs no subnet to be recognised and never did, so it
  // is refused on both links as it always was.
  for subnets in [&SUBNETS[..], &APIPA[..]] {
    assert!(!admits_ingress(
      apipa_src,
      Some(LIMITED_BROADCAST),
      None,
      nic(BOUND, subnets),
      BOUND,
      true
    ));
  }
}

/// The `/31` and `/32` hazard is gone, because the arithmetic it was a hazard in
/// is gone.
///
/// Deriving a broadcast from `addr/prefix` needed `prefix >= 31` excluded, and
/// that exclusion was load-bearing: a `/32`'s all-ones host address IS the
/// interface's own unicast address, and a `/31` is RFC 3021 point-to-point with
/// no broadcast address at all. Get it wrong and a `/32`-configured interface
/// goes deaf to every unicast addressed to it.
///
/// Nothing below consults a prefix length. A `/32` and a `/31` interface admit
/// unicast to the address they hold for the same reason a `/24` one does, and
/// the `/30` case shows the derived broadcast is still refused — as one of the
/// many addresses this interface does not hold, rather than as a broadcast.
#[test]
fn a_short_prefix_needs_no_broadcast_arithmetic() {
  static HOST_32: [(IpAddr, u8); 1] = [(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 32u8)];
  static P2P_31: [(IpAddr, u8); 1] = [(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)), 31u8)];
  static NET_30: [(IpAddr, u8); 1] = [(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)), 30u8)];

  // The /32's own address: the case a naive broadcast computation would have
  // refused outright, leaving the interface deaf.
  let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
  assert!(
    admits_ingress(
      peer(host),
      Some(host),
      None,
      nic(BOUND, &HOST_32),
      BOUND,
      true
    ),
    "a /32-configured interface must still hear unicast addressed to it"
  );

  // RFC 3021: .4 and .5 are both usable hosts of 198.51.100.4/31, and this
  // interface holds .4. Its peer holds .5, so a datagram addressed to .5 was
  // addressed to the peer — refused here, where the old arithmetic admitted it
  // for want of a broadcast to call it.
  assert!(
    admits_ingress(
      peer(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))),
      Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))),
      None,
      nic(BOUND, &P2P_31),
      BOUND,
      true
    ),
    "198.51.100.4 is the address this /31 holds, so §11's second arm decides it"
  );
  assert!(
    !admits_ingress(
      peer(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))),
      Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))),
      None,
      nic(BOUND, &P2P_31),
      BOUND,
      true
    ),
    "198.51.100.5 is the PEER's address on this /31, not ours"
  );

  // The same base address at /30. `.7` is what the old code computed as the
  // broadcast and `.6` is the /30's other host; both are refused now, and for
  // one reason rather than two — neither is an address this interface holds.
  for other in [6u8, 7u8] {
    assert!(
      !admits_ingress(
        peer(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))),
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, other))),
        None,
        nic(BOUND, &NET_30),
        BOUND,
        true
      ),
      "198.51.100.{other} is not the address 198.51.100.4/30 holds"
    );
  }
  // ... and the address it does hold is admitted, so the /30 refusals are the
  // destination and not the prefix length.
  assert!(admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))),
    Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))),
    None,
    nic(BOUND, &NET_30),
    BOUND,
    true
  ));
}

/// RFC 1122 §3.2.1.3: a loopback-bound endpoint holds the whole `127.0.0.0/8`
/// block, not the one address the enumeration named.
///
/// The interface is configured with `127.0.0.1`, so that is all `getifs`
/// reports — but that section assigns the entire block as "the internal host
/// loopback address", and a stack looping a datagram back may legitimately
/// carry any of it as the destination. Exact equality refused `127.0.0.2`, which
/// is a real unicast destination for this host and not a broadcast, a martian or
/// a neighbour's address.
///
/// This is also what finally settles `127.255.255.255`, which three review
/// rounds argued over. It is an ordinary member of the block: held, and decided
/// by the source arm like every other loopback destination. The two earlier
/// answers were both wrong — deriving a broadcast from `127.0.0.1/8` invents a
/// capability a loopback interface does not have, and refusing it as "not the
/// one address enumerated" is the reading RFC 1122 rules out.
#[test]
fn a_loopback_bound_endpoint_holds_the_whole_rfc_1122_block() {
  // Every address in the block reaches §11's second arm and is admitted for
  // this endpoint's own loopback traffic — including the two the enumeration
  // never named.
  for dst in LOOPBACK_BLOCK {
    assert!(
      admits_ingress(
        peer(LOOPBACK_V4_ADDR),
        Some(dst),
        None,
        lo(BOUND, &LOOPBACK_LINK),
        BOUND,
        true
      ),
      "{dst} is inside 127.0.0.0/8 (or is ::1), so a loopback-bound endpoint \
       holds it whether or not `getifs` reported it"
    );
  }
  // The block holds even when the enumeration named NOTHING of the sort: the
  // rule is the endpoint's binding, not the snapshot's contents.
  assert!(admits_ingress(
    peer(LOOPBACK_V4_ADDR),
    Some(LOOPBACK_ALT_V4_ADDR),
    None,
    lo(BOUND, &SUBNETS),
    BOUND,
    true
  ));
  // Reaching the second arm is NOT admission. The block decides the
  // destination; the source still has to be this endpoint's own traffic or
  // inside a configured prefix, so an off-prefix source to the same
  // block address is refused.
  for dst in LOOPBACK_BLOCK {
    assert!(
      !admits_ingress(
        peer(OFF_SUBNET_V4),
        Some(dst),
        None,
        lo(BOUND, &LOOPBACK_LINK),
        BOUND,
        true
      ),
      "{dst}: the block holds the destination, and the SOURCE arm still decides"
    );
  }
  // And the whole widening is scoped to a loopback-BOUND endpoint. On a real
  // NIC every one of these is a martian destination and stays refused, with an
  // admitting source and agreeing witnesses — so nothing an off-link sender can
  // reach gained an arm.
  for dst in LOOPBACK_BLOCK {
    assert!(
      !admits_ingress(
        on_subnet(),
        Some(dst),
        None,
        nic(BOUND, &SUBNETS),
        BOUND,
        true
      ),
      "{dst} on a NIC-bound endpoint is a martian destination"
    );
    // Not even when the NIC-bound endpoint's snapshot literally contains the
    // loopback addresses: `is_loopback()` is the endpoint's binding and the
    // enumeration is not a substitute for it. `127.0.0.1` and `::1` ARE in this
    // snapshot and so are held on their own; the two the block would have added
    // are not.
    if dst != LOOPBACK_V4_ADDR && dst != LOOPBACK_V6_ADDR {
      assert!(
        !admits_ingress(
          peer(LOOPBACK_V4_ADDR),
          Some(dst),
          None,
          nic(BOUND, &LOOPBACK_LINK),
          BOUND,
          true
        ),
        "{dst}: the block is opened by the BINDING, never by the snapshot"
      );
    }
  }
}

/// A loopback destination is decided by the BINDING, and a snapshot that happens
/// to contain one does not open it.
///
/// The fence was `link.is_loopback() && dst.is_loopback()` followed by a
/// fall-through to snapshot equality — which is not "only a loopback binding
/// holds 127/8", it is that OR "the snapshot lists it". A NIC-bound endpoint
/// whose interface carries both `192.168.1.2/24` and `127.0.0.1/8` — one
/// `ifconfig` away, and the ordinary shape of a snapshot read off a host rather
/// than written in a fixture — then held `127.0.0.1` after all, and an in-prefix
/// source reached §11's source arm with a loopback destination on a real NIC.
///
/// Every earlier loopback fixture was loopback-ONLY, so the destination test
/// never got the chance to be wrong: the source-prefix arm refused those cases
/// for its own reasons and the counters passed for the wrong reason. The
/// snapshots below are MIXED for exactly that reason.
#[test]
fn a_mixed_snapshot_does_not_let_a_nic_bound_endpoint_hold_the_loopback_block() {
  // A real dual-stack NIC that also lists the loopback addresses.
  static MIXED: [(IpAddr, u8); 4] = [
    (OUR_V4_ADDR, 24u8),
    (OUR_V6_ADDR, 64u8),
    (LOOPBACK_V4_ADDR, 8u8),
    (LOOPBACK_V6_ADDR, 128u8),
  ];
  // The source is in-prefix and every witness agrees, so the source arm would
  // admit and only the destination test can refuse. `127.0.0.1` and `::1` are
  // EXACT entries of this snapshot, which is what makes this the bypass rather
  // than a repeat of the block test.
  for dst in [LOOPBACK_V4_ADDR, LOOPBACK_V6_ADDR] {
    assert!(
      !admits_ingress(
        on_subnet(),
        Some(dst),
        None,
        nic(BOUND, &MIXED),
        BOUND,
        true
      ),
      "{dst} is in this NIC's snapshot verbatim, and a NIC-bound endpoint must \
       still not hold a loopback destination"
    );
  }
  // The rest of the block, which is not in the snapshot, is refused too — so the
  // rule is the same one for every address in it.
  for dst in [LOOPBACK_ALT_V4_ADDR, LOOPBACK_BROADCAST] {
    assert!(!admits_ingress(
      on_subnet(),
      Some(dst),
      None,
      nic(BOUND, &MIXED),
      BOUND,
      true
    ));
  }
  // The controls: the same snapshot's NON-loopback addresses are held and reach
  // the source arm, so the four refusals are the loopback class and not the
  // snapshot, the source or the interface.
  for dst in [OUR_V4_ADDR, OUR_V6_ADDR] {
    assert!(admits_ingress(
      on_subnet(),
      Some(dst),
      None,
      nic(BOUND, &MIXED),
      BOUND,
      true
    ));
  }
  // ... and the SAME mixed snapshot on a loopback-BOUND endpoint holds the whole
  // block, so the fence swings both ways on the binding alone.
  for dst in LOOPBACK_BLOCK {
    assert!(
      admits_ingress(
        peer(LOOPBACK_V4_ADDR),
        Some(dst),
        None,
        lo(BOUND, &MIXED),
        BOUND,
        true
      ),
      "{dst}: a loopback-bound endpoint holds the block whatever else the \
       snapshot lists"
    );
  }
}

/// A broadcast DELIVERY is refused where no destination was recovered — the
/// OpenBSD/NetBSD square, and the only exact destination fact it has.
///
/// `MSG_BCAST` says the delivery was neither unicast to an address this host
/// holds nor multicast to a group, which is precisely the class RFC 6762 §11
/// gives no arm to. It needs no address, which is why it can decide here at all.
///
/// The source is in-prefix and every witness agrees in every case below, so the
/// delivery class is the only thing that can refuse.
#[test]
fn a_broadcast_delivery_is_refused_where_no_destination_was_recovered() {
  assert!(
    !admits_ingress(
      on_subnet(),
      None,
      Some(LinkDelivery::Broadcast),
      nic(BOUND, &SUBNETS),
      BOUND,
      true
    ),
    "a datagram the kernel delivered as a broadcast has no §11 arm, and the \
     source prefix must not decide it"
  );
  // The three controls that make the refusal attributable. Same source, same
  // link, same witnesses; only the delivery class differs.
  assert!(
    admits_ingress(
      on_subnet(),
      None,
      Some(LinkDelivery::Unicast),
      nic(BOUND, &SUBNETS),
      BOUND,
      true
    ),
    "a unicast delivery still takes the source arm, which admits an in-prefix \
     source"
  );
  assert!(
    admits_ingress(
      on_subnet(),
      None,
      Some(LinkDelivery::Multicast),
      nic(BOUND, &SUBNETS),
      BOUND,
      true
    ),
    "a multicast delivery still takes the group arm"
  );
  assert!(
    admits_ingress(on_subnet(), None, None, nic(BOUND, &SUBNETS), BOUND, true),
    "and a target that reports no delivery class at all is unchanged — this is \
     the FreeBSD/DragonFly and compio-Windows residual, still open"
  );
  // It refuses regardless of the source, so it is not a source test wearing a
  // different name: a loopback-bound endpoint's own traffic is refused too.
  assert!(!admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    None,
    Some(LinkDelivery::Broadcast),
    lo(BOUND, &LOOPBACK_LINK),
    BOUND,
    true
  ));
  // And a RECOVERED destination outranks it in both directions: the delivery
  // class only decides where there is no address to decide from.
  assert!(
    admits_ingress(
      on_subnet(),
      Some(V4_GROUP),
      Some(LinkDelivery::Broadcast),
      nic(BOUND, &SUBNETS),
      BOUND,
      true
    ),
    "a recovered group destination is §11's first arm whatever the coarse \
     delivery class says"
  );
  assert!(admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    Some(LinkDelivery::Broadcast),
    nic(BOUND, &SUBNETS),
    BOUND,
    true
  ));
}

/// §11's source arm treats every assigned IPv6 prefix as on-link, and assignment
/// and on-link status are INDEPENDENT.
///
/// A router advertising a prefix with **A=1, L=0** tells a host to autoconfigure
/// an address from it and explicitly does NOT put the prefix on-link: reaching
/// any other address in that /64 goes through the router. `collect_local_subnets`
/// records the assigned address with its /64, [`BoundLink::new`] hands that list
/// to the source arm as if it were the interface's on-link prefix list, and a
/// ROUTED source inside the nominal /64 then passes §11's unicast arm.
///
/// This test pins the CURRENT behaviour, which is wrong in the permissive
/// direction, so that the fix has a place to land and cannot be made silently.
/// The removed inbound-TTL check used to mask it on metadata-capable paths,
/// which is why this diff exposes it.
///
/// The other direction — an **L=1, A=0** prefix, on-link but never assigned, so
/// a genuinely on-link peer is refused — is the same root cause and is tracked
/// alongside it. [`BoundLink::with_onlink_prefixes`] is the constructor both
/// fixes use; nothing populates it yet.
#[test]
fn an_assigned_ipv6_prefix_is_treated_as_on_link_which_it_need_not_be() {
  // The shape an A=1, L=0 advertisement leaves behind: one address, and a /64
  // the host may NOT assume is on-link.
  const AUTOCONF_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xa1c, 0, 0, 0, 0, 2));
  static AUTOCONF: [(IpAddr, u8); 1] = [(AUTOCONF_ADDR, 64u8)];
  // A source elsewhere in that /64. With L=0 it is reachable only through the
  // router, so it is NOT on-link and §11's unicast arm should not admit it.
  let routed_peer = peer(IpAddr::V6(Ipv6Addr::new(
    0x2001, 0xdb8, 0xa1c, 0, 0, 0, 0, 99,
  )));
  assert!(
    admits_ingress(
      routed_peer,
      Some(AUTOCONF_ADDR),
      None,
      nic(BOUND, &AUTOCONF),
      BOUND,
      true
    ),
    "KNOWN WRONG, pinned deliberately: assignment is being read as on-link \
     evidence. Fixing it means populating `BoundLink::with_onlink_prefixes` \
     from a real on-link source and flipping this assertion to `!`"
  );
  // What the fix changes, and what it must NOT change: with the two lists
  // supplied separately, the same source is refused while the destination test
  // is untouched — the destination is still held, so this is the source arm
  // moving and nothing else.
  static NO_ONLINK_PREFIX: [(IpAddr, u8); 0] = [];
  assert!(
    !admits_ingress(
      routed_peer,
      Some(AUTOCONF_ADDR),
      None,
      BoundLink::with_onlink_prefixes(BOUND, false, &AUTOCONF, &NO_ONLINK_PREFIX),
      BOUND,
      true
    ),
    "with the on-link list supplied separately and empty, the routed source is \
     refused — so the split is what the fix needs and the destination side is \
     unaffected"
  );
  // The destination side really is unaffected: an address NOT in `local_addrs`
  // is still refused no matter what the on-link list says, so the two roles
  // cannot be confused by the new constructor either.
  assert!(!admits_ingress(
    routed_peer,
    Some(NEIGHBOUR_V6_DST),
    None,
    BoundLink::with_onlink_prefixes(BOUND, false, &AUTOCONF, &AUTOCONF),
    BOUND,
    true
  ));
}

/// Each of [`BoundLink`]'s two lists is read by exactly one consumer, and this
/// is the case that can tell.
///
/// Splitting the field is worth nothing if both roles still read the same one,
/// and with [`BoundLink::new`] aliasing them no ordinary fixture can detect a
/// swap: every entry is in both lists at once. So this fixture makes them
/// DISJOINT and picks a source and a destination that each match only one:
///
/// * `local_addrs` holds `192.168.1.2/24` and the destination is `192.168.1.2`;
/// * `onlink_prefixes` holds `10.9.0.1/16` and the source is `10.9.0.5`.
///
/// A correct boundary admits: the destination is one of ours, and the source is
/// inside a prefix the interface treats as on-link. Reading `onlink_prefixes`
/// for the destination refuses it, and so does reading `local_addrs` for the
/// source — so this single admit assertion pins both reads at once.
#[test]
fn each_bound_link_list_is_read_by_exactly_one_arm() {
  const ONLINK_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1));
  static LOCAL_ONLY: [(IpAddr, u8); 1] = [(OUR_V4_ADDR, 24u8)];
  static ONLINK_ONLY: [(IpAddr, u8); 1] = [(ONLINK_ADDR, 16u8)];
  let onlink_src = peer(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 5)));
  let link = BoundLink::with_onlink_prefixes(BOUND, false, &LOCAL_ONLY, &ONLINK_ONLY);

  assert!(
    admits_ingress(onlink_src, Some(OUR_V4_ADDR), None, link, BOUND, true),
    "the destination test must read `local_addrs` (which holds 192.168.1.2) \
     and the source arm must read `onlink_prefixes` (which holds 10.9.0.0/16); \
     either read taken from the other list refuses this"
  );
  // The two halves, separately, so a failure above says which read is wrong.
  // A destination in the ON-LINK list but not in `local_addrs` is not ours.
  assert!(
    !admits_ingress(onlink_src, Some(ONLINK_ADDR), None, link, BOUND, true),
    "10.9.0.1 is an on-link prefix's address, not an address we hold"
  );
  // A source in `local_addrs`' prefix but not in the on-link list is not on-link.
  assert!(
    !admits_ingress(on_subnet(), Some(OUR_V4_ADDR), None, link, BOUND, true),
    "192.168.1.7 is inside an address we hold, which is not the same fact as \
     being inside a prefix this interface treats as on-link"
  );
}

/// A destination the host holds but the enumeration did not report is refused,
/// and the concrete case is anycast.
///
/// Linux carries anycast under `IFA_ANYCAST`, separate from
/// `IFA_ADDRESS`/`IFA_LOCAL`; `getifs` 0.6.1 reads only the latter two, and its
/// Windows backend leaves `FirstAnycastAddress` commented out. So there is no
/// way to put such an address into the snapshot at the pinned version, and a
/// datagram locally delivered to it takes no §11 arm.
///
/// Pinned as a test rather than left in prose because it is a REFUSAL of
/// legitimate traffic: it should fail the day `getifs` grows the accessor and
/// this fixture stops modelling reality, and the assertion says which change
/// that would be.
#[test]
fn a_locally_delivered_address_absent_from_the_snapshot_is_refused() {
  // The shape of the gap: the host answers for this address, the kernel
  // delivered the datagram to us, and the enumeration never mentioned it.
  const ANYCAST_DST: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 250));
  assert!(
    !admits_ingress(
      on_subnet(),
      Some(ANYCAST_DST),
      None,
      nic(BOUND, &SUBNETS),
      BOUND,
      true
    ),
    "an address the host holds but `getifs` 0.6.1 cannot report takes no §11 \
     arm; closing this needs the dependency to surface IFA_ANYCAST, after which \
     it joins `collect_local_subnets` and nothing here changes"
  );
  // ... and the moment it IS in the snapshot, the same datagram is admitted.
  // That is the whole of what the fix requires, asserted so the claim above is
  // not merely an explanation.
  static WITH_ANYCAST: [(IpAddr, u8); 3] = [
    (OUR_V4_ADDR, 24u8),
    (OUR_V6_ADDR, 64u8),
    (ANYCAST_DST, 32u8),
  ];
  assert!(admits_ingress(
    on_subnet(),
    Some(ANYCAST_DST),
    None,
    nic(BOUND, &WITH_ANYCAST),
    BOUND,
    true
  ));
}

/// A snapshot that enumerated one family and not the other refuses that family's
/// unicast destinations — the second residual, as a test rather than prose.
///
/// `collect_local_subnets` reads each family independently and collapses a
/// failed read to nothing collected, so a snapshot can be non-empty and still
/// have no entry for one family. That is not the EMPTY case: non-empty means an
/// enumeration succeeded, so the fallback does not apply and the missing
/// family's destinations are refused at both arms.
#[test]
fn a_snapshot_missing_one_family_fails_closed_for_that_family_only() {
  // IPv6 read succeeded, IPv4 read did not. The IPv4 destination this endpoint
  // really holds is refused ...
  static V6_ONLY: [(IpAddr, u8); 1] = [(OUR_V6_ADDR, 64u8)];
  assert!(
    !admits_ingress(
      on_subnet(),
      Some(UNICAST_V4_DST),
      None,
      nic(BOUND, &V6_ONLY),
      BOUND,
      true
    ),
    "a non-empty snapshot is a successful enumeration, so an IPv4 destination \
     missing from it is refused rather than deferred to the source arm"
  );
  // ... and the family that WAS enumerated is unaffected, so this fails closed
  // for one family rather than for the endpoint.
  assert!(admits_ingress(
    peer(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 7))),
    Some(UNICAST_V6_DST),
    None,
    nic(BOUND, &V6_ONLY),
    BOUND,
    true
  ));
  // The mirror, so neither family is the special one.
  static V4_ONLY: [(IpAddr, u8); 1] = [(OUR_V4_ADDR, 24u8)];
  assert!(!admits_ingress(
    peer(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 7))),
    Some(UNICAST_V6_DST),
    None,
    nic(BOUND, &V4_ONLY),
    BOUND,
    true
  ));
  assert!(admits_ingress(
    on_subnet(),
    Some(UNICAST_V4_DST),
    None,
    nic(BOUND, &V4_ONLY),
    BOUND,
    true
  ));
  // And it is NOT the empty-snapshot fallback: an empty snapshot for a
  // loopback-bound endpoint admits its own traffic, a half-empty one does not
  // change what the enumerated family answers. Same endpoint, same destination,
  // opposite verdicts — decided by whether anything was enumerated at all.
  assert!(admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    Some(NEIGHBOUR_V4_DST),
    None,
    lo(BOUND, &[]),
    BOUND,
    true
  ));
  assert!(!admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    Some(NEIGHBOUR_V4_DST),
    None,
    lo(BOUND, &V6_ONLY),
    BOUND,
    true
  ));
}

/// The empty-snapshot decision, and the bound that makes it safe.
///
/// Under the positive rule an empty `subnets()` would otherwise refuse every
/// non-group destination, so a driver whose interface enumeration failed would
/// go silently deaf to all unicast. An empty list is "we could not enumerate",
/// which is not the same fact as "we enumerated and this is not one of ours", so
/// it defers to the source arm — the same reading `arrived_on_bound_interface`
/// gives a bound interface of `0`.
///
/// It is a fallback and not a fail-open, and this is the proof: with no prefixes
/// to match, §11's source arm admits a loopback-BOUND endpoint's own traffic and
/// refuses everything else, so the fallback cannot admit anything the source arm
/// would not have. A STALE snapshot gets no such treatment — non-empty means the
/// enumeration succeeded — and fails closed for at most `SUBNET_REFRESH_INTERVAL`.
#[test]
fn an_empty_snapshot_defers_to_the_source_arm_which_still_fails_closed() {
  // The whole of what the fallback admits: a loopback-bound endpoint's own
  // traffic, to a destination nothing could have vouched for.
  for dst in [UNICAST_V4_DST, UNICAST_V6_DST, NEIGHBOUR_V4_DST] {
    assert!(
      admits_ingress(
        peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Some(dst),
        None,
        lo(BOUND, &[]),
        0,
        true
      ),
      "an endpoint that could not enumerate its loopback interface must still \
       hear its own traffic ({dst})"
    );
  }
  // And the whole of what it refuses. Every one of these is a source the source
  // arm has nothing to admit on once the prefixes are gone — including the
  // in-prefix source that a populated snapshot admits, which is what shows the
  // fallback is running the source arm rather than skipping it.
  for src in [
    on_subnet(),
    peer(OFF_SUBNET_V4),
    peer(OFF_SUBNET_V6),
    scoped(LINK_LOCAL, BOUND),
  ] {
    assert!(
      !admits_ingress(
        src,
        Some(UNICAST_V4_DST),
        None,
        nic(BOUND, &[]),
        BOUND,
        true
      ),
      "{src}: an empty snapshot admits nothing for a NIC-bound endpoint"
    );
  }
  // A loopback SOURCE does not open it either, for an endpoint the loopback
  // interface is not the link of.
  assert!(!admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    Some(UNICAST_V4_DST),
    None,
    nic(BOUND, &[]),
    BOUND,
    true
  ));
  // Nor does it survive stage 1: the fallback runs the source arm, and the
  // source arm asks `arrived_on_bound_interface` about a loopback source too.
  assert!(!admits_ingress(
    peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    Some(UNICAST_V4_DST),
    None,
    lo(BOUND, &[]),
    OTHER,
    true
  ));
  // The contrast that makes "empty" the operative fact rather than "small": the
  // SAME destination on a link that DID enumerate — and does not hold it — is
  // refused for the loopback-bound endpoint's own traffic.
  assert!(
    !admits_ingress(
      peer(IpAddr::V4(Ipv4Addr::LOCALHOST)),
      Some(NEIGHBOUR_V4_DST),
      None,
      lo(BOUND, &LOOPBACK_LINK),
      0,
      true
    ),
    "a non-empty snapshot that does not hold the destination is a verdict, not \
     a failed enumeration"
  );
}

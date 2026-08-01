//! RFC 6762 §11 on-link trust boundary.

use std::net::{IpAddr, SocketAddr};

use hick_udp::constants::{MDNS_IPV4_GROUP, MDNS_IPV6_GROUP};

/// §11: a conforming mDNS datagram arrives with IPv4 TTL / IPv6 hop limit 255.
/// Anything lower crossed a router. `None` means the platform did not report it,
/// which fails open — we can prove neither on-link nor off-link.
#[inline]
pub(crate) fn is_on_link(hop_limit: Option<u8>) -> bool {
  hop_limit.is_none_or(|t| t == 255)
}

/// Whether a datagram from `src`, delivered on interface `pkt_iface`, belongs to
/// the link this endpoint bound.
///
/// `iface_reported` says whether this platform reports a receive interface for
/// `src`'s address family at all — [`hick_udp::reports_rx_interface_v4`] /
/// [`hick_udp::reports_rx_interface_v6`]. It is a parameter rather than a
/// direct call so the decision is testable on every host, not only on one whose
/// capabilities happen to match the case under test.
///
/// # Why this is a separate gate from §11
///
/// A hop limit of 255 proves a datagram did not cross a router. It says nothing
/// at all about **which** link it did not cross. Both mDNS sockets are wildcard
/// bound — they have to be, to receive multicast addressed to a group rather
/// than to an address — so on a multi-homed host every NIC's port-5353 traffic
/// is delivered to them, each copy with a perfectly conforming hop limit of 255.
/// Admitting those puts an adjacent network inside this endpoint's trust
/// boundary: it can seed the cache, provoke RFC 6762 §8.2 conflict handling and
/// the §9 rename that follows, and elicit our records onto a network the caller
/// never asked to advertise on. This endpoint serves exactly one interface — see
/// [`ServerOptions::with_interface_index`](crate::ServerOptions::with_interface_index)
/// — so anything else is off its link by construction, whatever its hop limit
/// says. Applied to BOTH §11 branches, and before the self-send match, because a
/// foreign-link datagram must not even be offered a take-once credit.
///
/// # Two witnesses, not one
///
/// The receive interface is not the only thing that names the link a datagram
/// came from: an IPv6 source address carries a **scope id**, and the platforms
/// this crate supports all preserve it into the peer address (`hick-udp`'s
/// `sockaddr_storage_to_socketaddr` and its Windows twin). So both are consulted,
/// and **every nonzero witness must equal `bound_iface`** — including when they
/// disagree with each other. A datagram whose PKTINFO says our own interface and
/// whose scope id says another has already contradicted itself; a trust boundary
/// resolves that against the sender, not for it.
///
/// # The three exceptions, all deliberate
///
/// **A loopback source is admitted whatever interface it arrived on**, and
/// whatever scope it carries. It is stated here rather than left to fall out of
/// the index comparison because this crate's own loopback suppression depends on
/// receiving its own multicast back: the tests in this crate, and any caller
/// pinned to the loopback interface, run entirely on traffic whose source is
/// `127.0.0.1`/`::1`. A datagram from a loopback address crossed no link at all,
/// so there is no link for it to be off — and a remote attacker cannot
/// manufacture one, because a kernel does not deliver a martian loopback source
/// arriving on a real NIC. The same short-circuit, for the same reason, opens
/// [`src_on_local_link`].
///
/// **`bound_iface == 0` is permissive**, meaning this endpoint does not know its
/// own link and so can prove nothing about anyone else's. Production never
/// reaches it: [`Sockets::bind`](crate::socket::Sockets::bind) either takes the
/// caller's index or picks a default, then fails the bind outright if that index
/// names no interface, so a live endpoint always has a real one.
///
/// **No witness at all is admitted only where the platform never had one to
/// give.** With `iface_reported == false` a zero index is the platform's silence
/// — IPv4 on FreeBSD/DragonFly/OpenBSD/NetBSD, which define no usable
/// `IP_PKTINFO` — and rejecting silence would take IPv4 off the air there
/// entirely, so it degrades as the §11 hop-limit rule does. With
/// `iface_reported == true` the platform does answer this question, so a zero
/// index is a datagram the kernel declined to place: no longer absent evidence
/// but a failed proof, and this fails closed on it. That asymmetry is the
/// residual attack surface, and it is exactly one square of the matrix: IPv4 on
/// the four BSDs, known at compile time and documented in `hick-udp`'s README.
pub(crate) fn arrived_on_bound_interface(
  src: SocketAddr,
  bound_iface: u32,
  pkt_iface: u32,
  iface_reported: bool,
) -> bool {
  if src.ip().is_loopback() {
    return true;
  }
  if bound_iface == 0 {
    return true;
  }
  // An IPv4 peer carries no scope, so its only witness is the cmsg index.
  let scope = match src {
    SocketAddr::V6(a) => a.scope_id(),
    SocketAddr::V4(_) => 0,
  };
  let mut witnessed = false;
  for witness in [pkt_iface, scope] {
    if witness == 0 {
      continue;
    }
    witnessed = true;
    if witness != bound_iface {
      return false;
    }
  }
  witnessed || !iface_reported
}

/// Whether this platform reports the interface a datagram from `src`'s address
/// family arrived on. The family is the peer's because the sockets are
/// `IPV6_V6ONLY`, so a peer's family is always the receiving socket's.
const fn reports_rx_interface(src: SocketAddr) -> bool {
  match src {
    SocketAddr::V4(_) => hick_udp::reports_rx_interface_v4(),
    SocketAddr::V6(_) => hick_udp::reports_rx_interface_v6(),
  }
}

/// Whether `dst` is one of the two mDNS link-local multicast groups, the
/// destination RFC 6762 §11 says establishes local-link origin on its own.
///
/// Exactly these two and nothing else. The nearest neighbours in the same
/// link-local blocks — `224.0.0.252` and `ff02::1:3` — are LLMNR's groups, not
/// ours, and this is a trust boundary rather than a link-local scope test: §11
/// names these two addresses, so widening it to "any link-local multicast"
/// would hand the exemption to every other protocol sharing the link.
fn is_mdns_group(dst: IpAddr) -> bool {
  match dst {
    IpAddr::V4(a) => a == MDNS_IPV4_GROUP,
    IpAddr::V6(a) => a == MDNS_IPV6_GROUP,
  }
}

/// The whole ingress trust boundary for one datagram: the link it arrived on,
/// then RFC 6762 §11.
///
/// One function so the two gates cannot drift apart or be applied to only one
/// of the §11 branches. The interface check runs **first** and applies to both:
/// a reported hop limit answers "did this cross a router", never "whose link is
/// this", and only the fallback branch ever looked at an interface index at all.
///
/// `src` is the whole peer [`SocketAddr`], not its [`IpAddr`]: for an IPv6 peer
/// the scope id is half of what names the link it came from, and taking the
/// address alone silently discarded it.
///
/// # §11 selects the fallback's arm by DESTINATION, not by source
///
/// §11 states the local-link test two ways, and the IP header's destination
/// picks between them. A datagram addressed to `224.0.0.251` or `FF02::FB` is
/// *"necessarily deemed to have originated on the local link, regardless of
/// source IP address"* — which the RFC calls *"essential to allow devices to
/// work correctly and reliably in unusual configurations, such as multiple
/// logical IP subnets overlayed on a single link, or in cases of severe
/// misconfiguration"*. Only a **unicast** destination sends the source address
/// to the subnet check.
///
/// This crate had the unicast arm alone and applied it to both, so an on-link
/// host sourcing from a prefix we do not share was dropped exactly where §11
/// says it must not be. That is not a hypothetical square: Windows reports no
/// TTL/hop limit at all — `hick-udp`'s `set_recv_ttl_v4` and
/// `set_recv_hoplimit_v6` are no-ops there — so every Windows datagram takes
/// this branch, which made the loss silent rather than rare.
///
/// The group arm sits INSIDE the no-hop-limit branch rather than ahead of it.
/// It replaces the source-prefix *guess*, the only thing §11 ever offered it as
/// an alternative to; a reported hop limit below 255 crossed a router and stays
/// decisive whatever the destination says. And the interface check still runs
/// first and still gates both arms: a group destination proves a datagram was
/// link-local to SOME link, never that it was ours, and a wildcard-bound socket
/// on a multi-homed host is handed every NIC's copy.
///
/// # What `dst` actually carries
///
/// The caller passes `RecvMeta::local_ip`, whose meaning is per-platform: the
/// IP header destination on Windows (`IN_PKTINFO.ipi_addr` /
/// `IN6_PKTINFO.ipi6_addr`) and on every Unix IPv6 receive
/// (`in6_pktinfo.ipi6_addr`), but the receiving interface's own address on Unix
/// IPv4, where `hick-udp` reads `ipi_spec_dst` deliberately and asserts it.
/// That asymmetry cannot admit anything it should not: `ipi_spec_dst` is a
/// local unicast address and so never equals a group, and the targets that read
/// it (Linux/Android/Apple) all report a hop limit and never reach this branch.
/// A `dst` that is not the destination — including the UNSPECIFIED a target
/// with no PKTINFO parser degrades to — therefore reads as "unicast" and falls
/// through to the source-prefix rule, which is what was there before.
pub(crate) fn admits_ingress(
  src: SocketAddr,
  dst: IpAddr,
  hop_limit: Option<u8>,
  subnets: &[(IpAddr, u8)],
  bound_iface: u32,
  pkt_iface: u32,
) -> bool {
  let iface_reported = reports_rx_interface(src);
  if !arrived_on_bound_interface(src, bound_iface, pkt_iface, iface_reported) {
    return false;
  }
  // A reported TTL/hop limit is decisive. Without one, §11's own two arms: a
  // group destination is local-link origin by itself, and only a unicast one
  // falls back to the source address on the bound interface's own links.
  if hop_limit.is_some() {
    is_on_link(hop_limit)
  } else if is_mdns_group(dst) {
    true
  } else {
    src_on_local_link(src, subnets, bound_iface, pkt_iface, iface_reported)
  }
}

/// Whether `addr` falls inside `net/prefix`. Mismatched families never match.
pub(crate) fn addr_in_subnet(net: IpAddr, prefix: u8, addr: IpAddr) -> bool {
  match (net, addr) {
    (IpAddr::V4(n), IpAddr::V4(a)) => prefix_match(&n.octets(), &a.octets(), prefix, 32),
    (IpAddr::V6(n), IpAddr::V6(a)) => prefix_match(&n.octets(), &a.octets(), prefix, 128),
    _ => false,
  }
}

fn prefix_match(net: &[u8], addr: &[u8], prefix: u8, max: u8) -> bool {
  if prefix > max {
    return false;
  }
  let full = (prefix / 8) as usize;
  let rem = prefix % 8;
  if net.get(..full) != addr.get(..full) {
    return false;
  }
  if rem == 0 {
    return true;
  }
  let mask = 0xffu8 << (8 - rem);
  match (net.get(full), addr.get(full)) {
    (Some(n), Some(a)) => (n & mask) == (a & mask),
    // Unreachable with this module's callers: both slices are whole
    // `Ipv4Addr`/`Ipv6Addr` octet arrays and `prefix <= max` was checked above,
    // so a non-zero `rem` always leaves `full` in range. `false` regardless,
    // because this file is the RFC 6762 §11 trust boundary and a partial byte
    // it cannot compare is not evidence of a match. Failing open here would
    // admit an off-link source on a slice this function never proved anything
    // about.
    _ => false,
  }
}

/// Addresses + prefix lengths configured on the bound interface. Scoped to the
/// BOUND interface only — not every local NIC — so the §11 fallback cannot be
/// widened by an unrelated interface's subnet.
pub(crate) fn collect_local_subnets(iface_index: u32) -> Vec<(IpAddr, u8)> {
  let mut out = Vec::new();
  let Ok(Some(iface)) = getifs::interface_by_index(iface_index) else {
    return out;
  };
  if let Ok(v4) = iface.ipv4_addrs() {
    out.extend(v4.iter().map(|n| (IpAddr::V4(n.addr()), n.prefix_len())));
  }
  if let Ok(v6) = iface.ipv6_addrs() {
    out.extend(v6.iter().map(|n| (IpAddr::V6(n.addr()), n.prefix_len())));
  }
  out
}

/// §11's **unicast** arm, used when no TTL cmsg is available: trust a source
/// that is link-local on the receiving interface, or that falls inside a subnet
/// configured on the bound interface.
///
/// Reached only through [`admits_ingress`], which has already required the
/// datagram to have arrived on the bound interface AND to have been addressed
/// to this host rather than to an mDNS group: §11 scopes this source check to
/// unicast destinations, because a group destination settles the question by
/// itself and a source prefix could only overrule it wrongly.
///
/// The link-local arm below keeps its own copy of the interface check anyway:
/// this is the trust boundary, it costs
/// one integer comparison, and a caller that reaches this function by some other
/// route must not silently lose it. It delegates to
/// [`arrived_on_bound_interface`] rather than restating the rule, so the copy
/// cannot become a weaker copy — it was previously a bare `pkt_iface` test that
/// admitted a link-local source with a foreign scope id.
pub(crate) fn src_on_local_link(
  src: SocketAddr,
  subnets: &[(IpAddr, u8)],
  bound_iface: u32,
  pkt_iface: u32,
  iface_reported: bool,
) -> bool {
  let ip = src.ip();
  let (is_loopback, is_link_local) = match ip {
    IpAddr::V4(a) => (a.is_loopback(), a.is_link_local()),
    // `Ipv6Addr::is_unicast_link_local` is still UNSTABLE in std, so test the
    // fe80::/10 prefix directly — same expression as hick-reactor
    // (driver/mod.rs:1406) and hick-compio (onlink.rs:31).
    IpAddr::V6(a) => (a.is_loopback(), (a.segments()[0] & 0xffc0) == 0xfe80),
  };
  // Loopback short-circuits BEFORE the interface check: our own loopback
  // traffic is on-link by definition, and gating it on the receive interface
  // would drop the traffic the loopback integration tests depend on.
  if is_loopback {
    return true;
  }
  if is_link_local {
    // A link-local source is only meaningful within its own link: require the
    // datagram to have arrived on the interface we bound, by whichever witnesses
    // this platform and this address family can supply.
    return arrived_on_bound_interface(src, bound_iface, pkt_iface, iface_reported);
  }
  // Global (routable) source: admit only on positive on-link evidence. An empty
  // `subnets` makes this `false`, so a global source is dropped as off-link —
  // fail-CLOSED per §11, unlike the missing-TTL case which fails open.
  subnets
    .iter()
    .any(|&(net, pfx)| addr_in_subnet(net, pfx, ip))
}

#[cfg(test)]
mod tests;

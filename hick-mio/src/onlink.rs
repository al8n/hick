//! RFC 6762 §11 on-link trust boundary.

use std::net::IpAddr;

/// §11: a conforming mDNS datagram arrives with IPv4 TTL / IPv6 hop limit 255.
/// Anything lower crossed a router. `None` means the platform did not report it,
/// which fails open — we can prove neither on-link nor off-link.
#[inline]
pub(crate) fn is_on_link(hop_limit: Option<u8>) -> bool {
  hop_limit.is_none_or(|t| t == 255)
}

/// Whether a datagram that arrived on interface `pkt_iface` belongs to the link
/// this endpoint bound.
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
/// # The two exceptions, both deliberate
///
/// **An unknown index is not a mismatch.** `pkt_iface == 0` is what a platform
/// that delivers no `PKTINFO`/`RECVIF` cmsg reports — the same platforms that
/// deliver no TTL cmsg — and `bound_iface == 0` would mean this endpoint does
/// not know its own link either. Treating "unknown" as "different" would drop
/// every datagram on those hosts and take the responder off the air entirely, so
/// it degrades exactly as the §11 hop-limit rule does: absent evidence fails
/// open, present evidence is decisive.
///
/// **A loopback source is admitted whatever interface it arrived on.** It is
/// stated here rather than left to fall out of the index comparison because this
/// crate's own loopback suppression depends on receiving its own multicast back:
/// the tests in this crate, and any caller pinned to the loopback interface, run
/// entirely on traffic whose source is `127.0.0.1`/`::1`. A datagram from a
/// loopback address crossed no link at all, so there is no link for it to be off
/// — and a remote attacker cannot manufacture one, because a kernel does not
/// deliver a martian loopback source arriving on a real NIC. The same
/// short-circuit, for the same reason, opens [`src_on_local_link`].
pub(crate) fn arrived_on_bound_interface(src: IpAddr, bound_iface: u32, pkt_iface: u32) -> bool {
  if src.is_loopback() {
    return true;
  }
  if pkt_iface == 0 || bound_iface == 0 {
    return true;
  }
  pkt_iface == bound_iface
}

/// The whole ingress trust boundary for one datagram: the link it arrived on,
/// then RFC 6762 §11.
///
/// One function so the two gates cannot drift apart or be applied to only one
/// of the §11 branches. The interface check runs **first** and applies to both:
/// a reported hop limit answers "did this cross a router", never "whose link is
/// this", and only the fallback branch ever looked at an interface index at all.
pub(crate) fn admits_ingress(
  src: IpAddr,
  hop_limit: Option<u8>,
  subnets: &[(IpAddr, u8)],
  bound_iface: u32,
  pkt_iface: u32,
) -> bool {
  if !arrived_on_bound_interface(src, bound_iface, pkt_iface) {
    return false;
  }
  // A reported TTL/hop limit is decisive; without one, fall back to the source
  // address on the bound interface's own links.
  if hop_limit.is_some() {
    is_on_link(hop_limit)
  } else {
    src_on_local_link(src, subnets, bound_iface, pkt_iface)
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

/// §11 fallback used when no TTL cmsg is available: trust a source that is
/// link-local on the receiving interface, or that falls inside a subnet
/// configured on the bound interface.
///
/// Reached only through [`admits_ingress`], which has already required the
/// datagram to have arrived on the bound interface. The link-local arm below
/// keeps its own copy of that check anyway: this is the trust boundary, it costs
/// one integer comparison, and a caller that reaches this function by some other
/// route must not silently lose it.
pub(crate) fn src_on_local_link(
  src: IpAddr,
  subnets: &[(IpAddr, u8)],
  bound_iface: u32,
  pkt_iface: u32,
) -> bool {
  let (is_loopback, is_link_local) = match src {
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
    // datagram to have arrived on the interface we bound. `0` means the platform
    // did not report an interface, which fails open (degraded, not dropped).
    return pkt_iface == 0 || pkt_iface == bound_iface;
  }
  // Global (routable) source: admit only on positive on-link evidence. An empty
  // `subnets` makes this `false`, so a global source is dropped as off-link —
  // fail-CLOSED per §11, unlike the missing-TTL case which fails open.
  subnets
    .iter()
    .any(|&(net, pfx)| addr_in_subnet(net, pfx, src))
}

#[cfg(test)]
mod tests;

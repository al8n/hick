//! RFC 6762 §11 on-link trust boundary.

use std::net::IpAddr;

/// §11: a conforming mDNS datagram arrives with IPv4 TTL / IPv6 hop limit 255.
/// Anything lower crossed a router. `None` means the platform did not report it,
/// which fails open — we can prove neither on-link nor off-link.
#[inline]
pub(crate) fn is_on_link(hop_limit: Option<u8>) -> bool {
  hop_limit.is_none_or(|t| t == 255)
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

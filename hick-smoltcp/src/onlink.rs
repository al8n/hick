//! RFC 6762 §11 on-link gate.

use core::net::IpAddr;

use smoltcp::wire::{IpAddress, IpCidr};

use crate::constants::{MDNS_IPV4, MDNS_IPV6};

/// The §11 decision for an inbound datagram.
///
/// The authoritative test is the received hop-limit: an on-link mDNS packet
/// arrives with TTL / hop-limit 255. When the transport surfaces it
/// (`Some(ttl)`), that is decisive. Neither supplied transport does — smoltcp's
/// `udp::Socket` `UdpMetadata` carries no received hop-limit, and `hick-embassy`
/// re-exports the same type — so in practice this always takes the `None` arm:
///
/// * `None` with `local` the mDNS multicast group → accept, regardless of source
///   or configured subnets. RFC 6762 §11 deems a datagram addressed to
///   `224.0.0.251` / `ff02::fb` on-link "regardless of source IP address" — those
///   are link-scoped multicast groups routers do not forward — so this is checked
///   BEFORE the source-subnet heuristic below, the only thing §11 ever offers it
///   as an alternative to.
/// * `None` with local subnets configured (and `local` not the group) → a
///   best-effort source-subnet heuristic (weaker: a same-subnet host can spoof
///   it).
/// * `None` with neither of the above → reject. Dropping everything would make
///   the node deaf — it could announce but never receive a query, answer, or
///   conflict, the common default-setup failure — which is why the group arm
///   above exists; but UNICAST is NOT accepted here: a routed off-link host
///   could otherwise send ordinary unicast (or an ephemeral-port probe) to the
///   device's `:5353` and inject conflict/answer data — the multicast scope does
///   not protect that path. Configure local subnets (`Engine::set_local_subnets`)
///   to accept on-subnet unicast too (and to reject spoofed same-link sources).
#[inline]
pub fn on_link(
  hop_limit: Option<u8>,
  src: IpAddr,
  local: Option<IpAddr>,
  subnets: &[IpCidr],
) -> bool {
  match hop_limit {
    Some(ttl) => ttl == 255,
    // §11: a datagram addressed to the mDNS group is on-link by destination
    // alone. Checked ahead of the source-subnet guess so a peer on an overlaid
    // or misconfigured subnet — on-link, but outside the configured subnets — is
    // not dropped exactly where §11 says it must not be.
    None if local_is_mdns_group(local) => true,
    None if !subnets.is_empty() => src_in_local_subnets(src, subnets),
    None => false,
  }
}

/// Whether `local` (the datagram's destination address) is an mDNS multicast group —
/// trusted as on-link by IP design whenever no hop-limit was reported, regardless of
/// whether local subnets are configured.
fn local_is_mdns_group(local: Option<IpAddr>) -> bool {
  match local {
    Some(IpAddr::V4(a)) => a == MDNS_IPV4,
    Some(IpAddr::V6(a)) => a == MDNS_IPV6,
    None => false,
  }
}

/// Whether `src` falls within one of the device's configured local subnets.
fn src_in_local_subnets(src: IpAddr, subnets: &[IpCidr]) -> bool {
  let addr = IpAddress::from(src);
  subnets.iter().any(|cidr| cidr.contains_addr(&addr))
}

#[cfg(test)]
mod tests;

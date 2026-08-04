//! RFC 6762 §11 on-link gate.

use core::net::IpAddr;

use smoltcp::wire::{IpAddress, IpCidr};

use crate::constants::{MDNS_IPV4, MDNS_IPV6};

/// The §11 decision for an inbound datagram.
///
/// RFC 6762 §11's receive-side test is exhaustive — "the test for whether a
/// response originated on the local link is done in two ways" — and the
/// received hop-limit / TTL is neither of them. §11's only TTL provision is an
/// outbound `SHOULD` (send at 255, for compatibility with 2004-draft
/// queriers); there is no inbound TTL test to implement, so this function does
/// not take a hop-limit parameter at all:
///
/// * `local` is the mDNS multicast group → accept, regardless of source or
///   configured subnets. RFC 6762 §11 deems a datagram addressed to
///   `224.0.0.251` / `ff02::fb` on-link "regardless of source IP address" — those
///   are link-scoped multicast groups routers do not forward — so this is checked
///   BEFORE the source-subnet heuristic below, the only thing §11 ever offers it
///   as an alternative to.
/// * local subnets are configured (and `local` is not the group) → a
///   best-effort source-subnet heuristic (weaker: a same-subnet host can spoof
///   it).
/// * neither of the above → reject. Dropping everything would make the node
///   deaf — it could announce but never receive a query, answer, or conflict,
///   the common default-setup failure — which is why the group arm above
///   exists; but UNICAST is NOT accepted here: a routed off-link host could
///   otherwise send ordinary unicast (or an ephemeral-port probe) to the
///   device's `:5353` and inject conflict/answer data — the multicast scope does
///   not protect that path. Configure local subnets (`Engine::set_local_subnets`)
///   to accept on-subnet unicast too (and to reject spoofed same-link sources).
///
/// The subnet arm has no interface identity to scope `subnets` with — it is
/// sound only under the `UdpIo` trait's one-interface-per-implementation
/// contract (`crate::udpio::UdpIo`), which is what makes "the device's
/// configured subnets" mean the ONE interface this gate is being run for. A
/// caller whose `UdpIo` aggregates more than one physical interface gets a
/// cross-interface source silently admitted here — see this module's tests.
#[inline]
pub fn on_link(src: IpAddr, local: Option<IpAddr>, subnets: &[IpCidr]) -> bool {
  if local_is_mdns_group(local) {
    // §11: a datagram addressed to the mDNS group is on-link by destination
    // alone, regardless of source. Checked ahead of the source-subnet guess so
    // a peer on an overlaid or misconfigured subnet — on-link, but outside the
    // configured subnets — is not dropped exactly where §11 says it must not be.
    true
  } else if !subnets.is_empty() {
    src_in_local_subnets(src, subnets)
  } else {
    false
  }
}

/// Whether `local` (the datagram's destination address) is an mDNS multicast group —
/// trusted as on-link by IP design regardless of whether local subnets are
/// configured.
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

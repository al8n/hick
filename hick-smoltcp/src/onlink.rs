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
/// * `None` with local subnets configured → a best-effort source-subnet heuristic
///   (weaker: a same-subnet host can spoof it).
/// * `None` with NO subnets → accept ONLY a datagram whose destination (`local`) is
///   the mDNS multicast group. Dropping everything would make the node deaf — it
///   could announce but never receive a query, answer, or conflict, the common
///   default-setup failure — and a datagram sent TO `224.0.0.251` / `ff02::fb` is
///   on-link by IP design: those are link-scoped multicast groups routers do not
///   forward. UNICAST is NOT accepted here: a routed off-link host could otherwise
///   send ordinary unicast (or an ephemeral-port probe) to the device's `:5353` and
///   inject conflict/answer data — the multicast scope does not protect that path.
///   Configure local subnets (`Engine::set_local_subnets`) to accept on-subnet
///   unicast too (and to reject spoofed same-link sources).
#[inline]
pub fn on_link(
  hop_limit: Option<u8>,
  src: IpAddr,
  local: Option<IpAddr>,
  subnets: &[IpCidr],
) -> bool {
  match hop_limit {
    Some(ttl) => ttl == 255,
    None if !subnets.is_empty() => src_in_local_subnets(src, subnets),
    // No hop-limit AND no subnets: accept only genuine link-scoped multicast (see
    // above); a unicast or unknown destination has no on-link evidence here.
    None => local_is_mdns_group(local),
  }
}

/// Whether `local` (the datagram's destination address) is an mDNS multicast group —
/// the only no-hop-limit, no-subnet destination trusted as on-link by IP design.
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
mod tests {
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
}

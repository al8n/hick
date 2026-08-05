use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{collect_local_subnets, is_loopback_interface, reports_rx_interface};

/// `ip` as a port-5353 peer. IPv6 peers built this way carry scope id `0`, the
/// "no zone" a global source has.
fn peer(ip: IpAddr) -> SocketAddr {
  SocketAddr::new(ip, 5353)
}

#[test]
fn collect_local_subnets_enumerates_nothing_for_a_zero_index() {
  // Index 0 names no interface. The §11 fallback is scoped to the BOUND
  // interface, so a zero must NOT collapse into "every NIC on this host" —
  // which would let another link's prefix admit a global source. An empty list
  // is a refusal, and a refusal is the right answer here.
  assert!(collect_local_subnets(0).is_empty());
}

#[test]
fn is_loopback_interface_refuses_what_it_cannot_prove() {
  // Index 0 names no interface, and an index nothing can resolve is not evidence
  // of anything. The loopback exception is a widening, so both must answer
  // "no" — the flag is only ever granted on a positive read.
  assert!(!is_loopback_interface(0));
  assert!(!is_loopback_interface(u32::MAX));
}

/// Capability belongs to the RECEIVE PATH, not to the platform, so this crate
/// answers only for its OWN `recv_with_meta` — and answers per family, because
/// the sockets are `IPV6_V6ONLY` and a peer's family is always the receiving
/// socket's.
///
/// That the RULE takes the answer as a parameter rather than reading a cfg is
/// asserted in `hick-onlink`, by
/// `admits_ingress_uses_the_capability_its_caller_states`. This is the other
/// half: that the answer handed to it is this path's own.
#[test]
fn reports_rx_interface_answers_for_this_crates_own_receive_path() {
  assert_eq!(
    reports_rx_interface(peer(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)))),
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
}

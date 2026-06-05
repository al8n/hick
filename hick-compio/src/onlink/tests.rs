use core::net::{IpAddr, Ipv4Addr};

use super::*;

#[test]
fn ttl_255_is_on_link() {
  assert!(is_on_link(Some(255)));
}

#[test]
fn ttl_less_than_255_is_off_link() {
  assert!(!is_on_link(Some(254)));
}

#[test]
fn missing_ttl_is_on_link() {
  assert!(is_on_link(None));
}

#[test]
fn addr_in_loopback_8() {
  let net = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0));
  assert!(addr_in_subnet(
    net,
    8,
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
  ));
  assert!(!addr_in_subnet(
    net,
    8,
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
  ));
}

#[test]
fn link_local_must_match_iface() {
  let subnets: &[(IpAddr, u8)] = &[];
  let src = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2));
  assert!(src_on_local_link(subnets, 5, 5, src));
  assert!(!src_on_local_link(subnets, 5, 6, src));
  assert!(src_on_local_link(subnets, 5, 0, src));
}

#[test]
fn loopback_is_always_on_link() {
  let subnets: &[(IpAddr, u8)] = &[];
  let src = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
  assert!(src_on_local_link(subnets, 5, 5, src));
  assert!(src_on_local_link(subnets, 5, 99, src));
}

#[test]
fn global_source_dropped_without_subnet_evidence() {
  // §11 fail-closed: a routable source with no enumerated subnets has no
  // on-link evidence and must be dropped (loopback/link-local early-return
  // before this point, so this exercises the global path on an empty list).
  let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
  assert!(!src_on_local_link(&[], 5, 5, src));
}

#[test]
fn global_source_admitted_when_in_subnet() {
  // A global source inside a cached local subnet is on-link; one outside
  // every cached subnet is dropped.
  let subnets: &[(IpAddr, u8)] = &[(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)];
  assert!(src_on_local_link(
    subnets,
    5,
    5,
    IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))
  ));
  assert!(!src_on_local_link(
    subnets,
    5,
    5,
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
  ));
}

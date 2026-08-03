use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::Family;

#[test]
fn of_reads_the_family_off_the_destination() {
  let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
  let v6 = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb),
    5353,
    0,
    0,
  ));
  assert_eq!(Family::of(v4), Family::V4);
  assert_eq!(Family::of(v6), Family::V6);
}

/// The index order is IPv4-first, and it is the whole reason this method exists
/// rather than each caller writing its own `match`.
#[test]
fn index_is_v4_first_and_the_two_are_distinct() {
  assert_eq!(Family::V4.index(), 0);
  assert_eq!(Family::V6.index(), 1);
}

#[test]
fn is_v4_and_other_are_consistent() {
  assert!(Family::V4.is_v4());
  assert!(!Family::V6.is_v4());
  assert_eq!(Family::V4.other(), Family::V6);
  assert_eq!(Family::V6.other(), Family::V4);
  assert_eq!(Family::V4.other().other(), Family::V4);
}

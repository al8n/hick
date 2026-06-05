use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use super::Transmit;

#[test]
fn accessors_return_constructed_fields() {
  let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
  let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
  let t = Transmit::new(dst, Some(src), 42);
  assert_eq!(t.dst(), dst);
  assert_eq!(t.src_ip(), Some(src));
  assert_eq!(t.size(), 42);
}

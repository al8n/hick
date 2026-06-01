//! mDNS multicast endpoints (RFC 6762 §3).

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The mDNS UDP port, `5353` (RFC 6762 §3).
pub const MDNS_PORT: u16 = 5353;

/// The mDNS IPv4 link-local multicast group, `224.0.0.251`.
pub const MDNS_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The mDNS IPv6 link-local multicast group, `ff02::fb`.
pub const MDNS_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// The IPv4 mDNS destination, `224.0.0.251:5353`.
pub const MDNS_SOCKET_V4: SocketAddr = SocketAddr::new(IpAddr::V4(MDNS_IPV4), MDNS_PORT);

/// The IPv6 mDNS destination, `[ff02::fb]:5353`.
pub const MDNS_SOCKET_V6: SocketAddr = SocketAddr::new(IpAddr::V6(MDNS_IPV6), MDNS_PORT);

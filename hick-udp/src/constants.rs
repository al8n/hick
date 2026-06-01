//! mDNS-specific constants (RFC 6762 §3).

use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv4 mDNS multicast group (`224.0.0.251`).
pub const MDNS_IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// IPv6 mDNS multicast group (`ff02::fb`).
pub const MDNS_IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// mDNS UDP port (`5353`).
pub const MDNS_PORT: u16 = 5353;

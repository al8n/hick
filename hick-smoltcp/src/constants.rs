//! mDNS multicast endpoints (RFC 6762 §3).

use core::net::{IpAddr, SocketAddr};

/// The mDNS UDP port, `5353` (RFC 6762 §3).
pub const MDNS_PORT: u16 = 5353;

/// The mDNS IPv4 link-local multicast group, `224.0.0.251`.
///
/// Re-exported from [`hick_onlink`], the crate that decides on it: RFC 6762 §11
/// deems a datagram addressed here on-link regardless of source, so the address
/// the gate compares and the address this crate transmits to must be one
/// literal.
pub use hick_onlink::MDNS_IPV4_GROUP as MDNS_IPV4;

/// The mDNS IPv6 link-local multicast group, `ff02::fb`.
pub use hick_onlink::MDNS_IPV6_GROUP as MDNS_IPV6;

/// The IPv4 mDNS destination, `224.0.0.251:5353`.
pub const MDNS_SOCKET_V4: SocketAddr = SocketAddr::new(IpAddr::V4(MDNS_IPV4), MDNS_PORT);

/// The IPv6 mDNS destination, `[ff02::fb]:5353`.
pub const MDNS_SOCKET_V6: SocketAddr = SocketAddr::new(IpAddr::V6(MDNS_IPV6), MDNS_PORT);

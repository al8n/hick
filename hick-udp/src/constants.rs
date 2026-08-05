//! mDNS-specific constants (RFC 6762 §3).

/// IPv4 mDNS multicast group (`224.0.0.251`).
///
/// Re-exported from [`hick_onlink`], the crate that decides on it: RFC 6762 §11
/// deems a datagram addressed here on-link regardless of source, so the address
/// the gate compares and the address a driver joins must be one literal.
pub use hick_onlink::MDNS_IPV4_GROUP;

/// IPv6 mDNS multicast group (`ff02::fb`).
pub use hick_onlink::MDNS_IPV6_GROUP;

/// mDNS UDP port (`5353`).
pub const MDNS_PORT: u16 = 5353;

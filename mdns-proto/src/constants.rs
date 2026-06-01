//! Constants defined by RFC 1035 (DNS), RFC 6762 (mDNS), and our internal limits.

use core::net::{Ipv4Addr, Ipv6Addr};

/// Maximum bytes in a single DNS label (RFC 1035 §2.3.4).
pub const MAX_LABEL_BYTES: u8 = 63;

/// Maximum bytes in a fully-encoded DNS name (RFC 1035 §2.3.4).
pub const MAX_NAME_BYTES: usize = 255;

/// Maximum logical labels per DNS name (defensive — DNS practical limit).
pub const MAX_LABELS: usize = 128;

/// Maximum compression-pointer hops we will follow when resolving a name.
/// Defends against pathological pointer chains and cycles.
pub const MAX_POINTER_HOPS: u8 = 32;

/// IPv4 mDNS multicast group (RFC 6762 §3).
pub const MDNS_IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// IPv6 mDNS multicast group (RFC 6762 §3).
pub const MDNS_IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// mDNS UDP port (RFC 6762 §3).
pub const MDNS_PORT: u16 = 5353;

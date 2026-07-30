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

/// Smallest record TTL a service may be registered with.
///
/// Two seconds is the smallest TTL whose ~80 % periodic refresh (`ttl * 80 /
/// 100`, integer division) still clears RFC 6762 §8.3's one-second floor on the
/// interval between unsolicited responses. Below it:
///
/// * **TTL 0** is not an advertisement at all — a TTL-0 resource record is the
///   §10.1 goodbye that DELETES the record from every peer cache, so publishing
///   one as a positive record advertises a service that peers are told to forget
///   in the same datagram.
/// * **TTL 1** refreshes at 0.8 s, inside the §8.3 floor, so the responder
///   cannot re-announce often enough to keep the record alive without violating
///   the rate limit.
pub const MIN_SERVICE_TTL_SECS: u32 = 2;

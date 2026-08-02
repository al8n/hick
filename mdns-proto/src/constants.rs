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

/// The largest UDP payload IPv4 can **ever** carry: **65 507** bytes.
///
/// A 16-bit total-length field caps the whole datagram at 65 535, of which a
/// minimal IPv4 header takes 20 and the UDP header 8. Options make the real
/// ceiling lower, never higher.
///
/// See [`MAX_UDP_PAYLOAD_V6`] for what this is for and why it, rather than an
/// errno, is the only sound proof that a refused datagram can never be sent.
pub const MAX_UDP_PAYLOAD_V4: usize = 65_507;

/// The largest UDP payload IPv6 can **ever** carry: **65 527** bytes.
///
/// The 16-bit payload-length field caps everything after the fixed header at
/// 65 535, of which the UDP header takes 8. Extension headers count against that
/// payload length, so the real ceiling is again only ever lower. RFC 2675
/// jumbograms are deliberately not modelled: they need a hop-by-hop option and a
/// jumbo-capable path end to end, an mDNS message is orders of magnitude smaller
/// than the threshold, and reading the bound too low is the expensive direction.
///
/// # These prove permanence; an errno does not
///
/// A driver reporting a refused send must say whether the identical bytes could
/// ever leave on the identical socket
/// ([`FamilyAttempt::Refused`](crate::transmit::FamilyAttempt::Refused)), and
/// `body.len() > MAX_UDP_PAYLOAD_*` is the only sound test: exact,
/// platform-independent, and a property of the datagram rather than of the
/// moment. `EMSGSIZE` is not — Linux answers it both for a payload past the hard
/// maximum, which is permanent, and for a write past the currently-known path MTU
/// with `DF` set, which the next attempt may get past after an MTU probe or a
/// route change (udp(7), ip(7) `IP_MTU_DISCOVER`).
///
/// Both numbers are upper bounds a host may fail to reach and can never exceed,
/// which is the direction that matters: a datagram BELOW the bound may still be
/// refused for a reason that clears, while one above it is impossible on any
/// route, at any MTU, forever.
///
/// They live in the core because the rule they serve is the core's, and because
/// every driver that needs them must be able to reach them: the bare-metal
/// drivers share no other crate with the socket drivers.
pub const MAX_UDP_PAYLOAD_V6: usize = 65_527;

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

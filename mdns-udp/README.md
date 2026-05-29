# mdns-udp

Sync multicast UDP helpers for mDNS. Cross-platform (Linux, macOS, BSD, Windows). std-only, no async.

This crate provides:
- Socket configuration helpers — bind a multicast UDP socket on a specific interface, join/leave the mDNS group, set multicast options.
- Interface enumeration — find suitable interfaces for mDNS.
- Ancillary data parsing — recover the local IP an incoming datagram arrived on via `IP_PKTINFO` / `IPV6_PKTINFO`.
- Optional sync convenience wrappers (`sync::MulticastSocketV4` / `V6`) for callers who don't need an async runtime.

Used by `agnostic-mdns`, `mdns-compio`, and `mdns-monoio` as a shared platform layer. Each async crate creates a `std::net::UdpSocket` via this crate's helpers, then wraps it in its own runtime-native UDP type.

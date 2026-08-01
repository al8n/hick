#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::panic,
  clippy::panic_in_result_fn,
  clippy::indexing_slicing,
  clippy::arithmetic_side_effects,
  clippy::unreachable,
  clippy::todo,
  clippy::unimplemented
)]

/// mDNS-specific constants (multicast addresses, port).
pub mod constants;

/// Error types.
pub mod error;

pub use error::{
  AddressInUseDetail, BindError, BufferTooShortDetail, InterfaceNotFoundDetail, JoinError,
  MulticastHopsNotAppliedDetail, ParseRecvMetaError,
};

/// Multicast socket configuration + cmsg parsing.
pub mod multicast;
mod platform;
/// Sync convenience wrappers.
pub mod sync;

#[cfg(unix)]
pub use multicast::recv_with_meta;
pub use multicast::{
  MulticastOptionsV4, MulticastOptionsV6, RX_TIMESTAMP_GRAIN, RecvMeta, reports_rx_interface_v4,
  reports_rx_interface_v6, try_bind_v4, try_bind_v6, try_join_v4, try_join_v6,
};
// `parse_pktinfo_v6` exists only where libc defines `IPV6_PKTINFO`
// (`has_ipv6_pktinfo`, see build.rs); gate the re-export identically.
#[cfg(has_ipv6_pktinfo)]
pub use multicast::parse_pktinfo_v6;
// Windows recovers the receiving interface index via WSARecvMsg
// (IP_PKTINFO / IPV6_PKTINFO) so the driver's RFC 6762 §11 bound-interface
// link-local scoping works there too. Mirrors the Unix `recv_with_meta`.
#[cfg(windows)]
pub use platform::recv_with_meta;
// `parse_pktinfo_v4` only exists on Unix targets that define `libc::IP_PKTINFO`
// (`has_ip_pktinfo`, see build.rs); gate the re-export identically so it doesn't
// dangle on FreeBSD/OpenBSD/DragonFly (which use IP_RECVDSTADDR/IP_RECVIF).
#[cfg(has_ip_pktinfo)]
pub use multicast::parse_pktinfo_v4;
pub use sync::{MulticastSocketV4, MulticastSocketV6};

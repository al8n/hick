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

mod family;

pub use error::{
  AddressInUseDetail, BindError, BufferTooShortDetail, InterfaceNotFoundDetail, JoinError,
  MulticastHopsNotAppliedDetail, ParseRecvMetaError, RxDestinationNotEnabledDetail,
};
pub use family::Family;

/// Multicast socket configuration + cmsg parsing.
pub mod multicast;
pub mod onlink;
mod platform;
pub mod selfsend;
/// Sync convenience wrappers.
pub mod sync;

#[cfg(unix)]
pub use multicast::recv_with_meta;
pub use multicast::{
  LinkDelivery, MulticastOptionsV4, MulticastOptionsV6, RX_TIMESTAMP_GRAIN, RecvMeta,
  reports_rx_interface_v4, reports_rx_interface_v6, try_bind_v4, try_bind_v6, try_join_v4,
  try_join_v6,
};
// A driver with its own `recvmsg` still has to read the kernel's `msg_flags`,
// and what its bits mean is this crate's business rather than each driver's.
#[cfg(unix)]
pub use multicast::{control_truncated_from_msg_flags, link_delivery_from_msg_flags};
// `parse_pktinfo_v6` exists only where libc defines `IPV6_PKTINFO`
// (`has_ipv6_pktinfo`, see build.rs); gate the re-export identically.
#[cfg(has_ipv6_pktinfo)]
pub use multicast::parse_pktinfo_v6;
// Windows recovers the receiving interface index via WSARecvMsg
// (IP_PKTINFO / IPV6_PKTINFO) so the driver's RFC 6762 §11 bound-interface
// link-local scoping works there too. Mirrors the Unix `recv_with_meta`.
// Windows receives through a per-socket handle rather than a free function, so
// the `WSARecvMsg` pointer that was verified for a socket is the pointer that
// socket's receives use. Winsock extension pointers are provider-specific and
// are called directly, so a process-wide cache — which this was — could certify
// a socket it had never examined. See `RecvMsgFn`.
#[cfg(windows)]
pub use platform::{RecvMsgFn, resolve_recv_with_meta};
// `parse_pktinfo_v4` only exists on Unix targets that define `libc::IP_PKTINFO`
// (`has_ip_pktinfo`, see build.rs); gate the re-export identically so it doesn't
// dangle on FreeBSD/OpenBSD/DragonFly (which use IP_RECVDSTADDR/IP_RECVIF).
#[cfg(has_ip_pktinfo)]
pub use multicast::parse_pktinfo_v4;
// The BSD IPv4 ancillary parser: `IP_RECVDSTADDR` + `IP_RECVIF`, and what
// `recv_with_meta` calls on FreeBSD, DragonFly, OpenBSD and NetBSD — the IPv4
// counterpart of `parse_pktinfo_v4`, gated on the capability that says the
// bind enables the pair (`has_ip_dstaddr_recvif`, see build.rs). Public for the
// same reason `parse_pktinfo_v4` is: a driver with its own `recvmsg` decodes
// the same cmsgs and should not hand-roll a second reading of them.
#[cfg(has_ip_dstaddr_recvif)]
pub use multicast::parse_dstaddr_recvif_v4;
// NetBSD's own `IP_PKTINFO` shape. Compiled but NOT wired: NetBSD takes the
// `IP_RECVDSTADDR` pair above instead, because its `ip_savecontrol` emits
// IP_RECVDSTADDR before the `m_get_rcvif_psref() == NULL` early return and
// IP_PKTINFO after it, so a detached receive interface loses the destination
// here and keeps it there. See `build.rs` at the `ipv4_rx_netbsd_pktinfo` emit
// site. Exported so a caller on a real NetBSD can drive it against live
// ancillary data.
#[cfg(ipv4_rx_netbsd_pktinfo)]
pub use multicast::parse_netbsd_pktinfo_v4;
pub use sync::{MulticastSocketV4, MulticastSocketV6};

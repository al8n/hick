//! Platform-specific socket option setters.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use unix::*;
#[cfg(windows)]
pub(crate) use windows::*;
// the Windows WSARecvMsg-based receive path, re-exported publicly so
// the crate root can surface it as `hick_udp::recv_with_meta` (mirroring the
// Unix `recv_with_meta`).
#[cfg(windows)]
pub use windows::{RecvMsgFn, resolve_recv_with_meta};

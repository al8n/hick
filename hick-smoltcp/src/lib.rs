//! `hick-smoltcp` — runtime-agnostic mDNS / DNS-SD engine over smoltcp.
//!
//! This crate wires the Sans-I/O protocol core ([`mdns_proto`]) to smoltcp's
//! UDP sockets without assuming an async runtime: it exposes a synchronous
//! *pump* over a small [`UdpIo`] transport seam. `hick-embassy` builds on it
//! for the embassy async runtime; a bare poll loop or RTIC can drive it
//! directly.
//!
//! `no_std` + `alloc` — the [`mdns_proto`] `Endpoint` requires a heap.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

extern crate alloc;

pub mod constants;
pub mod engine;
mod onlink;
mod smoltcp_io;
pub mod time;
pub mod udpio;

pub use engine::Engine;
pub use smoltcp_io::DualStack;
pub use time::SmoltcpInstant;
pub use udpio::{RecvMeta, SendError, UdpIo};

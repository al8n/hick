#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

extern crate alloc;

// At least one storage tier must be active. `atomic` (default) and `no-atomic`
// select different mdns-proto Name/rdata backends; if both are enabled (e.g.
// `--all-features`) `atomic` wins via mdns-proto's backend precedence, so the
// no-atomic build must use `--no-default-features --features no-atomic`.
#[cfg(not(any(feature = "atomic", feature = "no-atomic")))]
compile_error!("hick-smoltcp: enable one storage tier — `atomic` (default) or `no-atomic`");

pub mod constants;
pub mod engine;
mod ingress;
mod smoltcp_io;
pub mod time;
pub mod udpio;

pub use engine::Engine;
pub use smoltcp_io::DualStack;
pub use time::SmoltcpInstant;
pub use udpio::{RecvMeta, SendError, UdpIo};

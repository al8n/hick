#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

// At least one storage tier must be active (propagated to `hick-smoltcp` /
// `mdns-proto`). `atomic` (default) and `no-atomic` select different backends; if
// both are on (e.g. `--all-features`) `atomic` wins, so the no-atomic build needs
// `--no-default-features --features no-atomic`.
#[cfg(not(any(feature = "atomic", feature = "no-atomic")))]
compile_error!("hick-embassy: enable one storage tier — `atomic` (default) or `no-atomic`");

mod driver;
mod io;
mod mdns;
pub mod time;

pub use driver::run;
pub use io::DualUdp;
pub use mdns::MdnsState;
pub use time::EmbassyInstant;

#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

/// The Sans-I/O mDNS protocol core ([`mdns_proto`]).
///
/// Re-exported in full for direct access to the wire codec, the record cache,
/// and the protocol state machines. The types most callers need are already
/// surfaced at the crate root (re-exported from the driver); reach here for the
/// rest.
pub use mdns_proto as proto;

/// Common, runtime-agnostic protocol types — re-exported from [`mdns_proto`] for
/// ergonomics. Service / query specs, records, names, update events, and the wire
/// codec are identical for every driver, so they live at the crate root; the
/// runtime-specific entry points (the endpoint constructor and its handle types)
/// live in the per-runtime driver modules ([`tokio`], [`smol`]) or driver crates
/// ([`compio`], [`smoltcp`], [`embassy`]).
pub use mdns_proto::{
  CollectedAnswer, Name, QuerySpec, ServiceRecords, ServiceSpec, ServiceUpdate, wire,
};

/// `tokio`-pinned mDNS driver: the endpoint constructor ([`server`](tokio::server))
/// plus the driver handle types (themselves runtime-agnostic).
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio {
  pub use hick_reactor::{
    CancelError, Lookup, Query, QueryEvent, QueryParam, RegisterError, ServerError, ServerOptions,
    Service, ServiceEntry, StartQueryError,
    tokio::{Endpoint, server},
  };
}

/// `smol`-pinned mDNS driver — same shape as [`tokio`].
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub mod smol {
  pub use hick_reactor::{
    CancelError, Lookup, Query, QueryEvent, QueryParam, RegisterError, ServerError, ServerOptions,
    Service, ServiceEntry, StartQueryError,
    smol::{Endpoint, server},
  };
}

#[cfg(feature = "compio")]
#[cfg_attr(docsrs, doc(cfg(feature = "compio")))]
pub use hick_compio as compio;

/// The runtime-agnostic bare-metal mDNS engine ([`hick_smoltcp`]) over smoltcp
/// UDP (`no_std` + `alloc`). Enable the `smoltcp` feature.
#[cfg(feature = "smoltcp")]
#[cfg_attr(docsrs, doc(cfg(feature = "smoltcp")))]
pub use hick_smoltcp as smoltcp;

/// The embassy async mDNS driver ([`hick_embassy`]) built on the [`smoltcp`]
/// engine (`no_std` + `alloc`). Enable the `embassy` feature.
#[cfg(feature = "embassy")]
#[cfg_attr(docsrs, doc(cfg(feature = "embassy")))]
pub use hick_embassy as embassy;

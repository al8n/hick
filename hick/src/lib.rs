#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

// `hick` is a batteries-included facade: it needs at least one runtime or
// bare-metal driver. The proto core is pulled with only `slab` (no storage tier),
// so a featureless build has neither a driver nor the storage tier the
// crate-root proto types require — fail fast with guidance instead of emitting
// cryptic unresolved-import errors.
#[cfg(not(any(
  feature = "tokio",
  feature = "smol",
  feature = "compio",
  feature = "mio",
  feature = "smoltcp",
  feature = "smoltcp-no-atomic",
  feature = "embassy",
  feature = "embassy-no-atomic"
)))]
compile_error!(
  "hick: enable a runtime (`tokio`, `smol`, or `compio`), the synchronous `mio` \
   driver, or a bare-metal driver (`smoltcp` / `embassy`, or their `-no-atomic` \
   variants for cores without native atomic CAS)"
);

/// The Sans-I/O mDNS protocol core ([`mdns_proto`]).
///
/// Re-exported in full for direct access to the wire codec, the record cache,
/// and the protocol state machines. The types most callers need are already
/// surfaced at the crate root (re-exported from the driver); reach here for the
/// rest.
pub use mdns_proto as proto;

/// The wire codec ([`mdns_proto::wire`]) — parser and encoder. Available in every
/// build tier (no storage tier required), so it is always re-exported.
pub use mdns_proto::wire;

/// Common, runtime-agnostic protocol types — re-exported from [`mdns_proto`] for
/// ergonomics. Service / query specs, records, names, and update events are
/// identical for every driver, so they live at the crate root; the runtime-specific
/// entry points (the endpoint constructor and its handle types) live in the
/// per-runtime driver modules (`tokio`, `smol`) or driver crates (`compio`,
/// `mio`, `smoltcp`, `embassy`). These require a proto storage tier, which
/// every runtime / driver feature enables, so the re-export is gated on having one.
///
/// Named as plain code rather than intra-doc links: each is only compiled in
/// under its own feature, so a doc build enabling just one (rather than
/// `--all-features`, which is what docs.rs and this workspace's CI use) would
/// otherwise report the others as broken links.
#[cfg(any(
  feature = "tokio",
  feature = "smol",
  feature = "compio",
  feature = "mio",
  feature = "smoltcp",
  feature = "smoltcp-no-atomic",
  feature = "embassy",
  feature = "embassy-no-atomic"
))]
pub use mdns_proto::{
  CollectedAnswer, Name, QuerySpec, ServiceRecords, ServiceSpec, ServiceUpdate,
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

/// The `mio` mDNS driver ([`hick_mio`]) — a synchronous endpoint driven from the
/// caller's own `mio::Poll` loop. No async runtime and no extra thread.
#[cfg(feature = "mio")]
#[cfg_attr(docsrs, doc(cfg(feature = "mio")))]
pub use hick_mio as mio;

/// The runtime-agnostic bare-metal mDNS engine ([`hick_smoltcp`]) over smoltcp
/// UDP (`no_std` + `alloc`). Enable `smoltcp` (atomic tier) or `smoltcp-no-atomic`
/// (portable-atomic tier, for cores without native atomic CAS).
#[cfg(any(feature = "smoltcp", feature = "smoltcp-no-atomic"))]
#[cfg_attr(
  docsrs,
  doc(cfg(any(feature = "smoltcp", feature = "smoltcp-no-atomic")))
)]
pub use hick_smoltcp as smoltcp;

/// The embassy async mDNS driver ([`hick_embassy`]) built on the [`smoltcp`]
/// engine (`no_std` + `alloc`). Enable `embassy` (atomic tier) or
/// `embassy-no-atomic` (portable-atomic tier, for cores without native atomic CAS).
#[cfg(any(feature = "embassy", feature = "embassy-no-atomic"))]
#[cfg_attr(
  docsrs,
  doc(cfg(any(feature = "embassy", feature = "embassy-no-atomic")))
)]
pub use hick_embassy as embassy;

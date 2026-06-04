//! Tracing shim. Delegates to `hick_trace` which resolves to real `tracing`
//! calls when the `tracing` Cargo feature is enabled, and to token-discarding
//! no-ops otherwise.
//!
//! The re-exports are only compiled when at least one of `std` or `alloc` is
//! active — those are the only build tiers that have call sites.

#[cfg(any(feature = "std", feature = "alloc"))]
pub(crate) use hick_trace::{debug, trace, warn};

#[cfg(all(any(feature = "std", feature = "alloc"), feature = "tracing"))]
pub(crate) use hick_trace::trace_span;

//! Tracing-feature shim. Exposes a small set of macros (`trace!`, `debug!`,
//! `info!`, `warn!`) that compile to actual `tracing` calls when the
//! `tracing` Cargo feature is enabled and to no-ops otherwise.
//!
//! Using this shim keeps `tracing` truly optional — no transitive `tracing`
//! dep is pulled in on default builds — while letting trace sites read
//! naturally at the call site.

#[cfg(feature = "tracing")]
#[allow(unused_imports)]
pub(crate) use tracing::{debug, info, trace, warn};

#[cfg(not(feature = "tracing"))]
#[allow(unused_macros)]
macro_rules! trace_noop {
  ($($tt:tt)*) => {{}};
}

#[cfg(not(feature = "tracing"))]
#[allow(unused_imports)]
pub(crate) use trace_noop as trace;
#[cfg(not(feature = "tracing"))]
#[allow(unused_imports)]
pub(crate) use trace_noop as debug;
#[cfg(not(feature = "tracing"))]
#[allow(unused_imports)]
pub(crate) use trace_noop as info;
#[cfg(not(feature = "tracing"))]
#[allow(unused_imports)]
pub(crate) use trace_noop as warn;

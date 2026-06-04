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

/// Test-only coverage support for the tracing instrumentation.
///
/// A `trace!`/`debug!`/`warn!` macro only evaluates its field expressions when a
/// subscriber reports the call site as enabled; with the default no-op
/// subscriber `enabled()` is false, so every instrumented field (`handle =
/// self.handle.raw()`, …) is skipped and shows as uncovered. The unit-test
/// suite already exercises every code path, so installing an always-enabled
/// subscriber as the process-wide default *before* the tests run gives those
/// call sites coverage credit without duplicating a single behavioural test.
///
/// Excluded under miri: `ctor`'s static-initializer mechanism is not supported
/// by the interpreter, and coverage is irrelevant to a UB check anyway.
#[cfg(all(test, feature = "tracing", not(miri)))]
mod cov {
  use tracing_core::{
    Event, LevelFilter, Metadata, Subscriber,
    span::{Attributes, Current, Id, Record},
  };

  /// Reports every call site as enabled and discards everything it receives.
  struct AlwaysOn;

  impl Subscriber for AlwaysOn {
    fn enabled(&self, _meta: &Metadata<'_>) -> bool {
      true
    }
    fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
      // tracing requires a non-zero span id.
      Id::from_u64(1)
    }
    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn event(&self, _event: &Event<'_>) {}
    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
    fn max_level_hint(&self) -> Option<LevelFilter> {
      Some(LevelFilter::TRACE)
    }
    fn current_span(&self) -> Current {
      Current::none()
    }
  }

  #[ctor::ctor]
  fn install() {
    // Runs once at test-binary load, before libtest spawns any test thread.
    // Ignore the error: another global default would only mean coverage is
    // already being collected.
    let _ = tracing::subscriber::set_global_default(AlwaysOn);
  }
}

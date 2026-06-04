//! Test-only coverage support for the tracing instrumentation.
//!
//! A `trace!`/`debug!`/`warn!` macro only evaluates its field expressions when
//! a subscriber reports the call site as enabled; under the default no-op
//! subscriber `enabled()` is false, so every instrumented field is skipped and
//! shows as uncovered. The unit-test suite already drives the run loop, so
//! installing an always-enabled subscriber as the process-wide default *before*
//! the tests run gives those call sites coverage credit without duplicating a
//! single behavioural test.

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

#[ctor::ctor(unsafe)]
fn install() {
  // Runs once at test-binary load, before libtest spawns any test thread.
  let _ = tracing::subscriber::set_global_default(AlwaysOn);
}

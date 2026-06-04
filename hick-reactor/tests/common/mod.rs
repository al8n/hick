//! Shared integration-test support.
//!
//! Installs a minimal always-enabled subscriber as the process-wide default
//! before the test binary runs. The driver run loops are only exercised by
//! these loopback integration tests (real multicast I/O), and their
//! `trace!`/`debug!`/`warn!` call sites evaluate their field expressions only
//! when a subscriber reports them enabled — so without this the run-loop
//! instrumentation never earns coverage. The subscriber discards everything;
//! it exists purely so the fields are evaluated.

use tracing_core::{
  Dispatch, Event, LevelFilter, Metadata, Subscriber, dispatcher,
  span::{Attributes, Current, Id, Record},
};

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
  let _ = dispatcher::set_global_default(Dispatch::new(AlwaysOn));
}

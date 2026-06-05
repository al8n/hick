//! Bridge smoltcp's monotonic clock to the [`mdns_proto::Instant`] trait.

use core::time::Duration;

use mdns_proto::Instant as ProtoInstant;
use smoltcp::time::Instant as RawInstant;

/// A [`smoltcp::time::Instant`] that implements [`mdns_proto::Instant`].
///
/// smoltcp's `Instant` and the `mdns_proto::Instant` trait are both foreign to
/// this crate, so the orphan rule requires a newtype to bridge them. The driver
/// wraps each clock reading (`SmoltcpInstant(iface_now)`); the engine is generic
/// over the trait, so this is the `I` type for the standalone smoltcp path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SmoltcpInstant(pub RawInstant);

impl From<RawInstant> for SmoltcpInstant {
  #[inline(always)]
  fn from(raw: RawInstant) -> Self {
    Self(raw)
  }
}

impl From<SmoltcpInstant> for RawInstant {
  #[inline(always)]
  fn from(wrapped: SmoltcpInstant) -> Self {
    wrapped.0
  }
}

impl ProtoInstant for SmoltcpInstant {
  #[inline]
  fn checked_add_duration(self, dur: Duration) -> Option<Self> {
    let add_us = i64::try_from(dur.as_micros()).ok()?;
    let total = self.0.total_micros().checked_add(add_us)?;
    Some(Self(RawInstant::from_micros(total)))
  }

  #[inline]
  fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
    // `None` when `earlier > self` (negative delta fails the u64 conversion).
    let delta = self
      .0
      .total_micros()
      .checked_sub(earlier.0.total_micros())?;
    let micros = u64::try_from(delta).ok()?;
    Some(Duration::from_micros(micros))
  }
}

#[cfg(test)]
mod tests;

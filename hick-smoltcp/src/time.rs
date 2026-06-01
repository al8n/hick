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
mod tests {
  use super::*;

  #[test]
  fn add_then_since_roundtrips() {
    let t0 = SmoltcpInstant(RawInstant::from_micros(10_000_000_i64));
    let t1 = t0.checked_add_duration(Duration::from_millis(500)).unwrap();
    assert!(t1 > t0);
    assert_eq!(
      t1.checked_duration_since(t0),
      Some(Duration::from_millis(500))
    );
  }

  #[test]
  fn since_is_none_when_earlier_is_later() {
    let t0 = SmoltcpInstant(RawInstant::from_micros(0_i64));
    let t1 = SmoltcpInstant(RawInstant::from_micros(1_000_i64));
    assert_eq!(t0.checked_duration_since(t1), None);
  }
}

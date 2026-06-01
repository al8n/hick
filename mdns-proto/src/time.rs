//! Monotonic time abstraction for protocol state machines.
//!
//! `mdns-proto` is generic over a custom [`Instant`] trait so it works on
//! `std` (default `Instant = std::time::Instant`), on `no_std` with an
//! ecosystem timekeeping crate (Embassy, fugit, embedded-time), or on bare
//! metal with a user-defined hardware-clock wrapper.
//!
//! The trait surface is intentionally minimal: two checked operations,
//! `Copy + Ord`. No system-clock access, no allocation, no `Display` —
//! the protocol never needs to inspect or format wall-clock times.

use core::time::Duration;

/// Monotonic point-in-time. Protocol state machines schedule and compare
/// deadlines against this type.
///
/// Implementations must be **monotonic** with respect to the same time
/// source. Mixing instants from different sources is undefined behaviour
/// at the protocol level (deadlines may fire spuriously or never).
///
/// All arithmetic is checked: implementations return `None` on overflow
/// or when subtracting a later instant from an earlier one, rather than
/// panicking. The proto crate is `#![deny(clippy::arithmetic_side_effects)]`
/// and relies on this contract.
pub trait Instant: Copy + Ord + Sized {
  /// Returns `self + dur`, or `None` if the operation would overflow.
  fn checked_add_duration(self, dur: Duration) -> Option<Self>;

  /// Returns `self - earlier`, or `None` if `earlier > self` or the
  /// operation would overflow.
  fn checked_duration_since(self, earlier: Self) -> Option<Duration>;
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl Instant for std::time::Instant {
  #[inline]
  fn checked_add_duration(self, dur: Duration) -> Option<Self> {
    std::time::Instant::checked_add(&self, dur)
  }

  #[inline]
  fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
    std::time::Instant::checked_duration_since(&self, earlier)
  }
}

#[cfg(all(test, feature = "std"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests_std {
  use super::Instant;
  use core::time::Duration;

  #[test]
  fn std_instant_checked_add_works() {
    let now = std::time::Instant::now();
    let later = now.checked_add_duration(Duration::from_secs(1)).unwrap();
    assert!(later > now);
  }

  #[test]
  fn std_instant_checked_duration_since_handles_reverse() {
    let earlier = std::time::Instant::now();
    let later = earlier
      .checked_add_duration(Duration::from_millis(50))
      .unwrap();
    assert!(later.checked_duration_since(earlier).is_some());
    assert!(earlier.checked_duration_since(later).is_none());
  }

  #[test]
  fn std_instant_checked_add_overflow_returns_none() {
    let now = std::time::Instant::now();
    let overflow = now.checked_add_duration(Duration::MAX);
    assert!(overflow.is_none());
  }
}

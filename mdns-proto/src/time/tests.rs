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

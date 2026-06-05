use core::time::Duration;

use embassy_time::Instant as RawInstant;
use mdns_proto::Instant as ProtoInstant;

use super::EmbassyInstant;

#[test]
fn conversions_and_proto_instant_arithmetic() {
  let raw = RawInstant::from_ticks(1_000);
  let t: EmbassyInstant = raw.into(); // From<RawInstant>
  let back: RawInstant = t.into(); // From<EmbassyInstant>
  assert_eq!(back, raw);

  let later = t.checked_add_duration(Duration::from_secs(2)).unwrap();
  assert!(later > t);
  // Tolerant bound — robust to the embassy-time tick rate's rounding.
  let delta = later.checked_duration_since(t).unwrap();
  assert!(delta >= Duration::from_millis(1900) && delta <= Duration::from_millis(2100));

  // Going backwards yields no (negative) duration.
  assert!(t.checked_duration_since(later).is_none());
}

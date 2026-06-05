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

use super::{QueryHandle, ServiceHandle};

#[test]
fn service_handle_roundtrip() {
  let h = ServiceHandle::from_raw(42);
  assert_eq!(h.raw(), 42);
  assert_eq!(h, ServiceHandle::from_raw(42));
  assert_ne!(h, ServiceHandle::from_raw(43));
}

#[test]
fn query_handle_roundtrip() {
  let h = QueryHandle::from_raw(7);
  assert_eq!(h.raw(), 7);
  assert_eq!(h, QueryHandle::from_raw(7));
  assert_ne!(h, QueryHandle::from_raw(0));
}

#[cfg(feature = "std")]
#[test]
fn service_handle_display() {
  let h = ServiceHandle::from_raw(99);
  let s = std::format!("{h}");
  assert_eq!(s, "ServiceHandle(99)");
}

#[cfg(feature = "std")]
#[test]
fn query_handle_display() {
  let h = QueryHandle::from_raw(7);
  assert_eq!(std::format!("{h}"), "QueryHandle(7)");
}

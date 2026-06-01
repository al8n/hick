//! Opaque identifiers for registered services and in-flight queries.
//!
//! Handles are returned from `try_register_service` / `try_start_query` and
//! are used to route incoming events back to the matching `Service` / `Query`
//! state machine.
//!
//! The wrapped `u32` representation is an internal detail; do not depend on
//! its numeric value beyond comparison and hashing.

use derive_more::Display;

/// Opaque identifier for a registered service.
#[derive(Debug, Display, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[display("ServiceHandle({_0})")]
pub struct ServiceHandle(u32);

impl ServiceHandle {
  /// Constructs a handle from a raw `u32`. Intended for internal crate use
  /// (e.g. rebuilding a handle from persisted state).
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn from_raw(raw: u32) -> Self {
    Self(raw)
  }

  /// Returns the raw `u32` representation. Stable across releases for the
  /// purpose of equality / hashing only.
  #[inline(always)]
  pub const fn raw(self) -> u32 {
    self.0
  }
}

/// Opaque identifier for an in-flight query.
#[derive(Debug, Display, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[display("QueryHandle({_0})")]
pub struct QueryHandle(u32);

impl QueryHandle {
  /// Constructs a handle from a raw `u32`. Crate-internal.
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn from_raw(raw: u32) -> Self {
    Self(raw)
  }

  /// Returns the raw `u32` representation.
  #[inline(always)]
  pub const fn raw(self) -> u32 {
    self.0
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
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
}

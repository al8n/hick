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
mod tests;

//! Service lifecycle states (RFC 6762 §8).

use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// Lifecycle state of a registered service.
///
/// Transitions:
///   `Init` → `Probing(0..3)` → `Announcing(0..2)` → `Established`
///   `Probing(_)` -\[conflict\]→ `Conflicting` (caller decides next step)
#[derive(Debug, Display, Copy, Clone, Eq, PartialEq, Hash, IsVariant, Unwrap, TryUnwrap)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum ServiceState {
  /// Just registered; waiting on initial 0–250 ms randomized delay.
  Init,
  /// Probing: probes sent so far (0, 1, or 2 — third probe ends probing).
  Probing(u8),
  /// Announcing: announcements sent so far (0 or 1).
  Announcing(u8),
  /// Established and serving questions; periodically re-announces.
  Established,
  /// Detected a conflict while probing; caller must rename and restart.
  Conflicting,
}

impl ServiceState {
  /// Canonical lowercase slug for this state.
  pub fn as_str(&self) -> &str {
    match self {
      Self::Init => "init",
      Self::Probing(_) => "probing",
      Self::Announcing(_) => "announcing",
      Self::Established => "established",
      Self::Conflicting => "conflicting",
    }
  }
}

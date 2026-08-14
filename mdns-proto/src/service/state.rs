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
  /// Probing: probes sent so far (0, 1, 2), or `3` for RFC 6762 §8.1's
  /// settling window.
  ///
  /// `Probing(3)` is not a fourth probe — §8.1 permits exactly three. It is the
  /// 250 ms that §8.1 keeps the conflict window open past the last one: "If, by
  /// 250 ms after the third probe, no conflicting Multicast DNS responses have
  /// been received, the host may move to the next step, announcing." Conflict
  /// handling matches `Probing(_)`, so both a peer's tentative probe and a
  /// conflicting response are still resolved by §8.2/§8.1 rather than by the
  /// post-establishment rules.
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

#[cfg(test)]
mod tests;

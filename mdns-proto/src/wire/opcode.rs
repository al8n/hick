//! DNS opcodes (RFC 1035 §4.1.1).

use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// DNS message opcode. mDNS requires `Opcode::Query` (0); other values are
/// kept for round-trip correctness against non-conforming traffic.
#[derive(
  Debug, Display, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, IsVariant, Unwrap, TryUnwrap,
)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum Opcode {
  /// Standard query (`0`).
  Query,
  /// Inverse query (`1`, obsoleted by RFC 3425).
  InverseQuery,
  /// Server status request (`2`).
  Status,
  /// Notify (`4`, RFC 1996).
  Notify,
  /// Dynamic update (`5`, RFC 2136).
  Update,
  /// Lossless escape for unknown opcodes encountered on the wire.
  Unknown(u8),
}

impl Opcode {
  /// Canonical lowercase slug for this opcode.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Query => "query",
      Self::InverseQuery => "inverse_query",
      Self::Status => "status",
      Self::Notify => "notify",
      Self::Update => "update",
      Self::Unknown(_) => "unknown",
    }
  }

  /// Returns the wire-format `u8` value (only the low 4 bits are significant
  /// in the actual flags field, but the conversion is total for `u8`).
  #[inline(always)]
  pub const fn to_u8(self) -> u8 {
    match self {
      Self::Query => 0,
      Self::InverseQuery => 1,
      Self::Status => 2,
      Self::Notify => 4,
      Self::Update => 5,
      Self::Unknown(v) => v,
    }
  }

  /// Reconstructs an `Opcode` from a wire-format `u8`. Always succeeds —
  /// unknown values land in `Unknown(v)`.
  #[inline(always)]
  pub const fn from_u8(v: u8) -> Self {
    match v {
      0 => Self::Query,
      1 => Self::InverseQuery,
      2 => Self::Status,
      4 => Self::Notify,
      5 => Self::Update,
      other => Self::Unknown(other),
    }
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::Opcode;

  #[test]
  fn from_u8_to_u8_roundtrip_known() {
    for raw in [0u8, 1, 2, 4, 5] {
      assert_eq!(Opcode::from_u8(raw).to_u8(), raw);
    }
  }

  #[test]
  fn from_u8_to_u8_roundtrip_unknown() {
    for raw in [3u8, 6, 7, 8, 15, 100, 200, 255] {
      let op = Opcode::from_u8(raw);
      assert!(op.is_unknown());
      assert_eq!(op.to_u8(), raw);
    }
  }

  #[test]
  fn as_str_query() {
    assert_eq!(Opcode::Query.as_str(), "query");
  }
}

//! DNS response codes (RFC 1035 §4.1.1 / RFC 6762 §18.11).

use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// DNS response code. mDNS requires `ResponseCode::NoError` in both queries
/// and responses; other values are kept for round-trip correctness.
#[derive(
  Debug, Display, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, IsVariant, Unwrap, TryUnwrap,
)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum ResponseCode {
  /// No error (`0`).
  NoError,
  /// Format error (`1`).
  FormatError,
  /// Server failure (`2`).
  ServerFailure,
  /// Name error (`3`, "NXDOMAIN").
  NameError,
  /// Not implemented (`4`).
  NotImplemented,
  /// Refused (`5`).
  Refused,
  /// Lossless escape for unknown response codes.
  Unknown(u8),
}

impl ResponseCode {
  /// Canonical lowercase slug for this response code.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::NoError => "no_error",
      Self::FormatError => "format_error",
      Self::ServerFailure => "server_failure",
      Self::NameError => "name_error",
      Self::NotImplemented => "not_implemented",
      Self::Refused => "refused",
      Self::Unknown(_) => "unknown",
    }
  }

  /// Returns the wire-format `u8` value.
  #[inline(always)]
  pub const fn to_u8(self) -> u8 {
    match self {
      Self::NoError => 0,
      Self::FormatError => 1,
      Self::ServerFailure => 2,
      Self::NameError => 3,
      Self::NotImplemented => 4,
      Self::Refused => 5,
      Self::Unknown(v) => v,
    }
  }

  /// Reconstructs a `ResponseCode` from a wire-format `u8`. Always succeeds —
  /// unknown values land in `Unknown(v)`.
  #[inline(always)]
  pub const fn from_u8(v: u8) -> Self {
    match v {
      0 => Self::NoError,
      1 => Self::FormatError,
      2 => Self::ServerFailure,
      3 => Self::NameError,
      4 => Self::NotImplemented,
      5 => Self::Refused,
      other => Self::Unknown(other),
    }
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::ResponseCode;

  #[test]
  fn roundtrip_known() {
    for raw in 0u8..=5 {
      assert_eq!(ResponseCode::from_u8(raw).to_u8(), raw);
    }
  }

  #[test]
  fn roundtrip_unknown() {
    for raw in [6u8, 10, 100, 255] {
      assert!(ResponseCode::from_u8(raw).is_unknown());
      assert_eq!(ResponseCode::from_u8(raw).to_u8(), raw);
    }
  }
}

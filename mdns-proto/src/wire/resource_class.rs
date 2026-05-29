//! DNS resource record classes with mDNS-specific cache-flush bit.

use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// Mask for the mDNS cache-flush bit (top bit of the 16-bit class field).
/// RFC 6762 §10.2 — set on response records to indicate "any prior record(s)
/// of this name/type/class are now invalid".
pub const CACHE_FLUSH_BIT: u16 = 0x8000;

/// Mask for the mDNS unicast-response bit (top bit of the 16-bit class field
/// in a question). RFC 6762 §5.4.
pub const UNICAST_RESPONSE_BIT: u16 = 0x8000;

/// DNS class. mDNS uses `In` (1) almost exclusively; the top bit is repurposed
/// per RFC 6762.
#[derive(
  Debug, Display, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, IsVariant, Unwrap, TryUnwrap,
)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum ResourceClass {
  /// Internet (`1`).
  In,
  /// Wildcard (`255`).
  Any,
  /// Lossless escape for unknown classes.
  Unknown(u16),
}

impl ResourceClass {
  /// Canonical lowercase slug for this resource class.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::In => "in",
      Self::Any => "any",
      Self::Unknown(_) => "unknown",
    }
  }

  /// Returns the wire-format `u16` value.
  #[inline(always)]
  pub const fn to_u16(self) -> u16 {
    match self {
      Self::In => 1,
      Self::Any => 255,
      Self::Unknown(v) => v,
    }
  }

  /// Reconstructs from a wire-format 16-bit class field, **stripping** the
  /// top bit (cache-flush / unicast-response). Use [`Self::from_u16_raw`]
  /// if you need to preserve the bit.
  #[inline(always)]
  pub const fn from_u16(v: u16) -> Self {
    Self::from_u16_raw(v & !CACHE_FLUSH_BIT)
  }

  /// Reconstructs from a wire-format 16-bit class field without masking.
  #[inline(always)]
  pub const fn from_u16_raw(v: u16) -> Self {
    match v {
      1 => Self::In,
      255 => Self::Any,
      other => Self::Unknown(other),
    }
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::{CACHE_FLUSH_BIT, ResourceClass};

  #[test]
  fn cache_flush_bit_stripped_by_default() {
    let raw = 0x8001;
    assert!(ResourceClass::from_u16(raw).is_in());
  }

  #[test]
  fn cache_flush_bit_preserved_in_raw() {
    let raw = 0x8001;
    let parsed = ResourceClass::from_u16_raw(raw);
    assert!(parsed.is_unknown());
    assert_eq!(parsed.to_u16(), raw);
  }

  #[test]
  fn cache_flush_constant() {
    assert_eq!(CACHE_FLUSH_BIT, 0x8000);
  }
}

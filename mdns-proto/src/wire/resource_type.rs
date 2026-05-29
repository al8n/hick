//! DNS resource record types relevant to mDNS (RFC 1035 §3.2.2 + RFC 6762).

use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// Resource record type code.
#[derive(
  Debug, Display, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, IsVariant, Unwrap, TryUnwrap,
)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum ResourceType {
  /// IPv4 address (`1`).
  A,
  /// IPv6 address (`28`).
  Aaaa,
  /// Domain name pointer (`12`).
  Ptr,
  /// Server location (`33`).
  Srv,
  /// Text record (`16`).
  Txt,
  /// Next secure (`47`, used for negative responses in RFC 6762 §6.1).
  Nsec,
  /// Host info (`13`, rarely used).
  Hinfo,
  /// Canonical name alias (`5`).
  Cname,
  /// Wildcard query type (`255`).
  Any,
  /// Lossless escape for unknown rtypes.
  Unknown(u16),
}

impl ResourceType {
  /// Canonical lowercase slug for this resource type.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::A => "a",
      Self::Aaaa => "aaaa",
      Self::Ptr => "ptr",
      Self::Srv => "srv",
      Self::Txt => "txt",
      Self::Nsec => "nsec",
      Self::Hinfo => "hinfo",
      Self::Cname => "cname",
      Self::Any => "any",
      Self::Unknown(_) => "unknown",
    }
  }

  /// Returns the wire-format `u16` value.
  #[inline(always)]
  pub const fn to_u16(self) -> u16 {
    match self {
      Self::A => 1,
      Self::Aaaa => 28,
      Self::Ptr => 12,
      Self::Srv => 33,
      Self::Txt => 16,
      Self::Nsec => 47,
      Self::Hinfo => 13,
      Self::Cname => 5,
      Self::Any => 255,
      Self::Unknown(v) => v,
    }
  }

  /// Whether this is a standardized RR type whose RDATA contains a (potentially
  /// compressed) domain name but which this stack does NOT type-specifically
  /// parse. Per RFC 1035 §3.3 the compression-eligible
  /// name-bearing types are NS(2), MD(3), MF(4), CNAME(5), SOA(6), MB(7),
  /// MG(8), MR(9), PTR(12), MINFO(14), MX(15) — plus DNAME(39). We parse CNAME
  /// and PTR; the rest map to `Unknown` and a sender that knows them MAY
  /// compress / case-vary their embedded names, so storing raw bytes would be
  /// compression/case-sensitive and break cache dedup / TTL=0 removal. They are
  /// not mDNS/DNS-SD record types, so callers DROP them rather than cache a
  /// non-canonical entry. (RFC 3597 §4: types defined after RFC 1035 are sent
  /// uncompressed, so genuinely-unknown opaque RDATA is safe to store verbatim.)
  #[inline(always)]
  pub(crate) const fn is_unhandled_compressible_name(self) -> bool {
    matches!(self.to_u16(), 2 | 3 | 4 | 6 | 7 | 8 | 9 | 14 | 15 | 39)
  }

  /// Reconstructs a `ResourceType` from a wire-format `u16`. Always succeeds —
  /// unknown values land in `Unknown(v)`.
  #[inline(always)]
  pub const fn from_u16(v: u16) -> Self {
    match v {
      1 => Self::A,
      28 => Self::Aaaa,
      12 => Self::Ptr,
      33 => Self::Srv,
      16 => Self::Txt,
      47 => Self::Nsec,
      13 => Self::Hinfo,
      5 => Self::Cname,
      255 => Self::Any,
      other => Self::Unknown(other),
    }
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::ResourceType;

  #[test]
  fn roundtrip_known() {
    for raw in [1u16, 5, 12, 13, 16, 28, 33, 47, 255] {
      assert_eq!(ResourceType::from_u16(raw).to_u16(), raw);
    }
  }

  #[test]
  fn roundtrip_unknown() {
    for raw in [0u16, 2, 100, 999, 65535] {
      assert!(ResourceType::from_u16(raw).is_unknown());
      assert_eq!(ResourceType::from_u16(raw).to_u16(), raw);
    }
  }
}

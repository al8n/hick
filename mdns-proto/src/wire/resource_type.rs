//! DNS resource record types relevant to mDNS (RFC 1035 §3.2.2 + RFC 6762).

use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// Resource record type code.
#[derive(
  Debug, Display, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, IsVariant, Unwrap, TryUnwrap,
)]
#[display("{}", self.as_str())]
#[non_exhaustive]
// The `AAAA` variant keeps the canonical DNS record-type spelling.
#[allow(clippy::upper_case_acronyms)]
pub enum ResourceType {
  /// IPv4 address (`1`).
  A,
  /// IPv6 address (`28`).
  AAAA,
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
      Self::AAAA => "aaaa",
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
      Self::AAAA => 28,
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

  cfg_heap! {
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
  ///
  /// Gated to the heap tiers: the sole caller is `Rdata::canonical_rdata_inner`
  /// (`wire::record`, gated on `alloc` / `std` / `no-atomic`), so without a
  /// matching gate this is dead code in the core-only (no-storage) tiers and
  /// trips `#[deny(dead_code)]`.
    #[inline(always)]
    pub(crate) const fn is_unhandled_compressible_name(self) -> bool {
      matches!(self.to_u16(), 2 | 3 | 4 | 6 | 7 | 8 | 9 | 14 | 15 | 39)
    }
  }

  /// Reconstructs a `ResourceType` from a wire-format `u16`. Always succeeds —
  /// unknown values land in `Unknown(v)`.
  #[inline(always)]
  pub const fn from_u16(v: u16) -> Self {
    match v {
      1 => Self::A,
      28 => Self::AAAA,
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
mod tests;

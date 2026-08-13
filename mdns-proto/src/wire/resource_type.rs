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

  /// How this RR type's RDATA carries domain names, which is what decides
  /// whether its bytes may be compared or stored as they arrived.
  ///
  /// # This is a per-TYPE property, and it has to be
  ///
  /// Compression pointer syntax is meaningful ONLY inside a field the type
  /// defines as a domain name. The same octets elsewhere are ordinary data, so
  /// no inspection of the bytes can answer this — a previous attempt refused any
  /// rdata containing an octet `>= 0xC0`, which is wrong in both directions: an
  /// opaque private RR may validly contain `0xC0` and was refused (the peer
  /// compared it correctly, won, and we abandoned — both then claimed the name),
  /// while a name-bearing type whose name happens to be low-octet slipped
  /// through with no structural validation at all.
  ///
  /// # The list is closed, and it is §18.14's list EXACTLY
  ///
  /// §18.14 enumerates the types whose rdata names may be compressed in
  /// Multicast DNS, and then closes the set in the next sentence: "names that
  /// appear within the rdata of any type not listed above MUST NOT be
  /// compressed". RFC 3597 §4 closed the unicast set the same way in 2003.
  ///
  /// So ABSENCE FROM THE LIST IS A POSITIVE FACT, not an unknown: a type not
  /// listed never carries a compression pointer, its rdata therefore means the
  /// same thing in any packet, and it is trivially comparable verbatim. An
  /// earlier revision read absence as ignorance and invented a third category
  /// for SIG(24), NXT(30), NAPTR(35) and A6(38) — the four types RFC 3597 §4
  /// explicitly moved OUT of the compressible set — which made this crate refuse
  /// to compare records that any conforming peer compares fine. Abandoning where
  /// the peer decides is the two-owner outcome §8.2 exists to prevent, reached
  /// by declining rather than by getting the answer wrong.
  ///
  /// Every eligible type has the same shape: `lead` fixed octets, then `names`
  /// domain names, then a remainder that carries no name (SOA's 20 octets of
  /// timers are exactly that remainder), so one decoder serves all of them.
  ///
  /// If a future IETF Standards Action adds a type to §18.14 — which §18.14
  /// anticipates and no action has yet taken — add it here with its layout.
  #[allow(dead_code)]
  pub(crate) const fn rdata_names(self) -> RdataNames {
    // §18.14's list, verbatim: NS, CNAME, PTR, DNAME, SOA, MX, AFSDB, RT, KX,
    // RP, PX, SRV, NSEC.
    match self.to_u16() {
      // A single domain name: NS(2), CNAME(5), PTR(12), DNAME(39).
      2 | 5 | 12 | 39 => RdataNames::Compressible { lead: 0, names: 1 },
      // Two domain names: RP(17) — and SOA(6), whose 20 octets of timers follow
      // the two names and contain no name of their own.
      6 | 17 => RdataNames::Compressible { lead: 0, names: 2 },
      // A 16-bit preference, then one name: MX(15), AFSDB(18), RT(21), KX(36).
      15 | 18 | 21 | 36 => RdataNames::Compressible { lead: 2, names: 1 },
      // A 16-bit preference, then two names: PX(26).
      26 => RdataNames::Compressible { lead: 2, names: 2 },
      // SRV(33) and NSEC(47) are on §18.14's list AND are parsed by this crate,
      // so they never reach the generic decoder. They are enumerated anyway so
      // that this table is §18.14 rather than "§18.14 minus whatever we happen
      // to parse today" — a subset is a table a reader cannot check against the
      // spec.
      33 => RdataNames::Compressible { lead: 6, names: 1 },
      47 => RdataNames::Compressible { lead: 0, names: 1 },
      // Everything else is opaque, BECAUSE §18.14 says its names MUST NOT be
      // compressed. Its bytes mean the same thing in any packet WHATEVER they
      // are — including octets that would be pointer syntax inside a name field.
      _ => RdataNames::Opaque,
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

/// How an RR type's RDATA carries domain names. See
/// [`ResourceType::rdata_names`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum RdataNames {
  /// Not on RFC 6762 §18.14's list, so its names — if it has any — MUST NOT be
  /// compressed: the bytes are self-contained as sent, whatever octets they
  /// hold.
  Opaque,
  /// `lead` fixed octets, then `names` domain names, then a name-free
  /// remainder. Any of the names may be compressed.
  Compressible { lead: usize, names: u8 },
}

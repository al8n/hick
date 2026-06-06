//! Resource records — type-specific parsers + the generic `Ref`
//! wrapper that pairs them with their owner name, type, class, and TTL.

mod a;
mod aaaa;
mod cname;
mod nsec;
mod ptr;
mod srv;
mod txt;

pub use a::A;
pub use aaaa::AAAA;
pub use cname::Cname;
pub use nsec::Nsec;
pub use ptr::Ptr;
pub use srv::Srv;
#[allow(unused_imports)]
pub use txt::{Txt, TxtSegments};

cfg_heap! {
  use crate::backend::{RdataBuf, rdata_from_vec};
}

use super::{NameRef, ResourceClass, ResourceType};
use crate::error::{BufferTooShortDetail, ParseError, RdlengthOverrunDetail};

/// Parsed resource record (zero-copy view into a message). Stores the full
/// message reference so type-specific rdata parsers can resolve compression
/// pointers inside record data.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Ref<'a> {
  message: &'a [u8],
  name: NameRef<'a>,
  rtype: ResourceType,
  rclass: ResourceClass,
  cache_flush: bool,
  ttl: u32,
  rdata_start: usize,
  rdata_len: usize,
}

impl<'a> Ref<'a> {
  /// Parses a single resource record from `message` at `offset`.
  /// Returns the record and the next offset to parse from.
  pub fn try_parse(message: &'a [u8], offset: usize) -> Result<(Self, usize), ParseError> {
    use super::resource_class::CACHE_FLUSH_BIT;
    let (name, name_bytes) = NameRef::try_parse(message, offset)?;
    let after_name = offset.saturating_add(name_bytes);

    // type (2) + class (2) + ttl (4) + rdlength (2) = 10 bytes
    let hdr = message
      .get(after_name..after_name.saturating_add(10))
      .ok_or_else(|| {
        ParseError::BufferTooShort(BufferTooShortDetail::new(
          10,
          after_name,
          message.len().saturating_sub(after_name),
        ))
      })?;

    let rtype_arr: &[u8; 2] = hdr.first_chunk::<2>().ok_or_else(|| {
      ParseError::BufferTooShort(BufferTooShortDetail::new(2, after_name, hdr.len()))
    })?;
    let rtype = ResourceType::from_u16(u16::from_be_bytes(*rtype_arr));

    let rclass_raw_arr: &[u8; 2] = hdr
      .get(2..4)
      .and_then(|s| s.first_chunk::<2>())
      .ok_or_else(|| {
        ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          after_name.saturating_add(2),
          hdr.len(),
        ))
      })?;
    let rclass_raw = u16::from_be_bytes(*rclass_raw_arr);
    let cache_flush = (rclass_raw & CACHE_FLUSH_BIT) != 0;
    let rclass = ResourceClass::from_u16(rclass_raw);

    let ttl_arr: &[u8; 4] = hdr
      .get(4..8)
      .and_then(|s| s.first_chunk::<4>())
      .ok_or_else(|| {
        ParseError::BufferTooShort(BufferTooShortDetail::new(
          4,
          after_name.saturating_add(4),
          hdr.len(),
        ))
      })?;
    let ttl = u32::from_be_bytes(*ttl_arr);

    let rdlen_arr: &[u8; 2] = hdr
      .get(8..10)
      .and_then(|s| s.first_chunk::<2>())
      .ok_or_else(|| {
        ParseError::BufferTooShort(BufferTooShortDetail::new(
          2,
          after_name.saturating_add(8),
          hdr.len(),
        ))
      })?;
    let rdlen = u16::from_be_bytes(*rdlen_arr);

    let rdata_start = after_name.saturating_add(10);
    let rdata_end = rdata_start.saturating_add(rdlen as usize);
    if rdata_end > message.len() {
      let remaining = message.len().saturating_sub(rdata_start);
      return Err(ParseError::RdlengthOverrun(RdlengthOverrunDetail::new(
        rdlen,
        rdata_start,
        remaining,
      )));
    }

    Ok((
      Self {
        message,
        name,
        rtype,
        rclass,
        cache_flush,
        ttl,
        rdata_start,
        rdata_len: rdlen as usize,
      },
      rdata_end,
    ))
  }

  /// Returns the owner name of this record.
  #[inline(always)]
  pub const fn name(&self) -> &NameRef<'a> {
    &self.name
  }

  /// Returns the resource record type.
  #[inline(always)]
  pub const fn rtype(&self) -> ResourceType {
    self.rtype
  }

  /// Returns the resource record class.
  #[inline(always)]
  pub const fn rclass(&self) -> ResourceClass {
    self.rclass
  }

  /// Returns `true` if the mDNS cache-flush bit was set on this record.
  #[inline(always)]
  pub const fn cache_flush(&self) -> bool {
    self.cache_flush
  }

  /// Returns the time-to-live value in seconds.
  #[inline(always)]
  pub const fn ttl(&self) -> u32 {
    self.ttl
  }

  /// Raw rdata slice borrowed from the message.
  pub fn rdata(&self) -> &'a [u8] {
    self
      .message
      .get(self.rdata_start..self.rdata_start.saturating_add(self.rdata_len))
      .unwrap_or(&[])
  }

  /// Interpret this record's rdata, dispatching by [`Self::rtype`].
  /// typed parsers now respect `rdata_len` so a malformed RDLENGTH cannot
  /// let a name (PTR/SRV) consume bytes past its declared boundary, and
  /// oversize A/AAAA rdata is rejected explicitly.
  pub fn rdata_view(&self) -> Result<Rdata<'a>, ParseError> {
    match self.rtype {
      ResourceType::A => Ok(Rdata::A(A::try_from_rdata(self.rdata())?)),
      ResourceType::AAAA => Ok(Rdata::AAAA(AAAA::try_from_rdata(self.rdata())?)),
      ResourceType::Ptr => Ok(Rdata::Ptr(Ptr::try_from_message(
        self.message,
        self.rdata_start,
        self.rdata_len,
      )?)),
      ResourceType::Cname => Ok(Rdata::Cname(Cname::try_from_message(
        self.message,
        self.rdata_start,
        self.rdata_len,
      )?)),
      ResourceType::Srv => Ok(Rdata::Srv(Srv::try_from_message(
        self.message,
        self.rdata_start,
        self.rdata_len,
      )?)),
      ResourceType::Txt => Ok(Rdata::Txt(Txt::from_rdata(self.rdata()))),
      ResourceType::Nsec => Ok(Rdata::Nsec(Nsec::try_from_message(
        self.message,
        self.rdata_start,
        self.rdata_len,
      )?)),
      _ => Ok(Rdata::Other(self.rdata())),
    }
  }

  cfg_heap! {
  /// Copies this record's rdata with internal DNS compression pointers
  /// EXPANDED to self-contained wire form, PRESERVING name case. PTR/SRV/NSEC
  /// rdata carries a domain name that responders — and this crate's own builder
  /// — may compress with a back-pointer into the packet; a raw copy would
  /// dangle once the source datagram is gone. Case is preserved so a query
  /// caller can surface the name for display (RFC 6762 §16). A/AAAA/TXT/Other
  /// carry no name we expand and are copied verbatim. Malformed typed rdata
  /// (bad RDLENGTH, an over-length name, or a name with a pointer cycle /
  /// forward pointer) yields `Err` so the caller can drop the record instead of
  /// storing undecodable bytes.
  ///
  /// For record IDENTITY comparison use [`Self::canonical_rdata_folded`], which
  /// additionally case-folds so two encodings differing only in name case (or
  /// compression) compare equal.
  pub(crate) fn canonical_rdata(&self) -> Result<RdataBuf, ParseError> {
    self.canonical_rdata_inner(false)
  }

  /// Like [`Self::canonical_rdata`] but case-FOLDS names (ASCII lowercase) —
  /// the canonical case-insensitive identity form (RFC 6762 §16). Used for the
  /// passive cache, whose `(name, rtype, rclass, rdata)` dedup / TTL=0 goodbye
  /// removal / cache-flush sibling matching compare rdata bytewise: without
  /// folding, a peer announcing then withdrawing the same record with differing
  /// case would leave a stale entry (and case variants could bloat the bounded
  /// cache). The cache never surfaces rdata for display, so folding is safe
  /// there.
  pub(crate) fn canonical_rdata_folded(&self) -> Result<RdataBuf, ParseError> {
    self.canonical_rdata_inner(true)
  }

  fn canonical_rdata_inner(&self, fold_case: bool) -> Result<RdataBuf, ParseError> {
    match self.rdata_view()? {
      Rdata::Ptr(p) => {
        let mut out = std::vec::Vec::new();
        p.target().write_wire(&mut out, fold_case)?;
        Ok(rdata_from_vec(out))
      }
      Rdata::Cname(c) => {
        let mut out = std::vec::Vec::new();
        c.target().write_wire(&mut out, fold_case)?;
        Ok(rdata_from_vec(out))
      }
      Rdata::Srv(s) => {
        let mut out = std::vec::Vec::new();
        out.extend_from_slice(&s.priority().to_be_bytes());
        out.extend_from_slice(&s.weight().to_be_bytes());
        out.extend_from_slice(&s.port().to_be_bytes());
        s.target().write_wire(&mut out, fold_case)?;
        Ok(rdata_from_vec(out))
      }
      Rdata::Nsec(n) => {
        let mut out = std::vec::Vec::new();
        n.next_name().write_wire(&mut out, fold_case)?;
        out.extend_from_slice(n.type_bitmap_slice());
        Ok(rdata_from_vec(out))
      }
      // Truly-unknown types are opaque (RFC 3597 §4 forbids name compression in
      // them) so raw bytes are a stable identity — EXCEPT a well-known
      // compressible name-bearing type we don't parse (NS/SOA/MX/DNAME), which
      // MAY arrive compressed/case-varied and can't be canonicalized; it's not
      // an mDNS/DNS-SD type, so drop it.
      Rdata::Other(bytes) => {
        if self.rtype.is_unhandled_compressible_name() {
          return Err(ParseError::UnsupportedNameBearingType(self.rtype.to_u16()));
        }
        Ok(rdata_from_vec(bytes.to_vec()))
      }
      Rdata::Txt(t) => {
        // TXT rdata is a sequence of length-prefixed strings (RFC 6763
        // §6), NOT opaque bytes. Walk the segments to VALIDATE: a length octet
        // that overruns the rdata makes `segments()` yield Err, which propagates
        // so the caller DROPS the record. Without this a malformed TXT (e.g. a
        // length byte of 5 followed by 2 bytes) passed this canonical-rdata
        // validity gate and was admitted to the cache / query results. Rebuild
        // the canonical bytes from the validated segments; an empty TXT
        // normalizes to a single zero-length string (§6.1) so it matches both
        // `respond::write_canonical_txt` and a peer's compliant empty TXT.
        let mut out = std::vec::Vec::new();
        let mut wrote_any = false;
        for seg in t.segments() {
          let seg = seg?;
          // A parsed segment's length came from a single octet, so it is <= 255.
          #[allow(clippy::cast_possible_truncation)]
          out.push(seg.len() as u8);
          out.extend_from_slice(seg);
          wrote_any = true;
        }
        if !wrote_any {
          out.push(0);
        }
        Ok(rdata_from_vec(out))
      }
      // A / AAAA carry no domain name and no internal structure — copy verbatim.
      // (`_` also satisfies the `#[non_exhaustive]` enum.)
      _ => Ok(rdata_from_vec(self.rdata().to_vec())),
    }
  }
  }
}

/// Dispatched rdata view — interprets `rdata` per `rtype`.
#[derive(
  Debug, Copy, Clone, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
// The `AAAA` variant keeps the canonical DNS record-type spelling.
#[allow(clippy::upper_case_acronyms)]
pub enum Rdata<'a> {
  /// Parsed A record (IPv4 address).
  A(A),
  /// Parsed AAAA record (IPv6 address).
  AAAA(AAAA),
  /// Parsed PTR record (domain name pointer).
  Ptr(Ptr<'a>),
  /// Parsed CNAME record (canonical name alias).
  Cname(Cname<'a>),
  /// Parsed SRV record (server location).
  Srv(Srv<'a>),
  /// Parsed TXT record (key=value text segments).
  Txt(Txt<'a>),
  /// Parsed NSEC record (negative-answer hint).
  Nsec(Nsec<'a>),
  /// Catch-all for record types this crate does not type-specifically parse
  /// (or for `Unknown` rtypes).
  Other(&'a [u8]),
}

#[cfg(all(test, any(feature = "alloc", feature = "std")))]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::panic,
  clippy::indexing_slicing,
  clippy::arithmetic_side_effects
)]
mod tests;

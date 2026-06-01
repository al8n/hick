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
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub(crate) fn canonical_rdata(&self) -> Result<std::vec::Vec<u8>, ParseError> {
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
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub(crate) fn canonical_rdata_folded(&self) -> Result<std::vec::Vec<u8>, ParseError> {
    self.canonical_rdata_inner(true)
  }

  #[cfg(any(feature = "alloc", feature = "std"))]
  fn canonical_rdata_inner(&self, fold_case: bool) -> Result<std::vec::Vec<u8>, ParseError> {
    match self.rdata_view()? {
      Rdata::Ptr(p) => {
        let mut out = std::vec::Vec::new();
        p.target().write_wire(&mut out, fold_case)?;
        Ok(out)
      }
      Rdata::Cname(c) => {
        let mut out = std::vec::Vec::new();
        c.target().write_wire(&mut out, fold_case)?;
        Ok(out)
      }
      Rdata::Srv(s) => {
        let mut out = std::vec::Vec::new();
        out.extend_from_slice(&s.priority().to_be_bytes());
        out.extend_from_slice(&s.weight().to_be_bytes());
        out.extend_from_slice(&s.port().to_be_bytes());
        s.target().write_wire(&mut out, fold_case)?;
        Ok(out)
      }
      Rdata::Nsec(n) => {
        let mut out = std::vec::Vec::new();
        n.next_name().write_wire(&mut out, fold_case)?;
        out.extend_from_slice(n.type_bitmap_slice());
        Ok(out)
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
        Ok(bytes.to_vec())
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
        Ok(out)
      }
      // A / AAAA carry no domain name and no internal structure — copy verbatim.
      // (`_` also satisfies the `#[non_exhaustive]` enum.)
      _ => Ok(self.rdata().to_vec()),
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
mod tests {
  use super::*;

  /// Assembles a message whose record owner name and rdata names are
  /// compression pointers to "svc.local." parked at offset 12. Returns the
  /// full message bytes; the record begins at offset 23.
  ///
  /// Layout: [0..12] zero header · [12..23] "svc.local." · [23..25] owner
  /// pointer→12 · [25..27] TYPE · [27..29] CLASS=IN · [29..33] TTL · [33..35]
  /// RDLENGTH · [35..] rdata.
  fn message_with_pointered_record(rtype: u16, rdata: &[u8]) -> std::vec::Vec<u8> {
    let mut m = std::vec::Vec::new();
    m.extend_from_slice(&[0u8; 12]); // dummy header region (pointer base 12)
    // "svc.local." at offset 12.
    m.extend_from_slice(&[3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0]);
    debug_assert_eq!(m.len(), 23);
    m.extend_from_slice(&[0xC0, 0x0C]); // owner name = pointer to offset 12
    m.extend_from_slice(&rtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    m.extend_from_slice(&120u32.to_be_bytes()); // TTL
    #[allow(clippy::cast_possible_truncation)]
    m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    m.extend_from_slice(rdata);
    m
  }

  const SVC_LOCAL_WIRE: &[u8] = &[3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0];

  #[test]
  fn canonical_rdata_expands_srv_target() {
    // RDATA: priority=10 weight=20 port=8080 target=pointer→"svc.local.".
    let rdata = [0, 10, 0, 20, 0x1F, 0x90, 0xC0, 0x0C];
    let msg = message_with_pointered_record(33 /* SRV */, &rdata);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    let out = rec.canonical_rdata().unwrap();
    let mut expected = std::vec::Vec::from(&[0u8, 10, 0, 20, 0x1F, 0x90][..]);
    expected.extend_from_slice(SVC_LOCAL_WIRE);
    assert_eq!(out, expected, "SRV target must be decompressed in place");
  }

  #[test]
  fn canonical_rdata_expands_cname_target() {
    // CNAME rdata is one domain name (like PTR) — target is a
    // pointer→"svc.local." and must be decompressed, not copied raw.
    let rdata = [0xC0, 0x0C];
    let msg = message_with_pointered_record(5 /* CNAME */, &rdata);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    assert_eq!(
      rec.canonical_rdata().unwrap(),
      std::vec::Vec::from(SVC_LOCAL_WIRE),
      "CNAME target must be decompressed in place"
    );
  }

  #[test]
  fn canonical_rdata_expands_nsec_next_name() {
    // RDATA: next_name=pointer→"svc.local." then a 3-byte type bitmap.
    let rdata = [0xC0, 0x0C, 0x00, 0x01, 0x40];
    let msg = message_with_pointered_record(47 /* NSEC */, &rdata);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    let out = rec.canonical_rdata().unwrap();
    let mut expected = std::vec::Vec::from(SVC_LOCAL_WIRE);
    expected.extend_from_slice(&[0x00, 0x01, 0x40]); // bitmap preserved verbatim
    assert_eq!(
      out, expected,
      "NSEC next_name must be decompressed, bitmap preserved"
    );
  }

  #[test]
  fn canonical_rdata_rejects_malformed_name() {
    // PTR whose rdata name is a pointer to an out-of-range offset (255) — the
    // label iterator errors, so canonical_rdata must Err (caller drops it)
    // rather than store undecodable bytes.
    let rdata = [0xC0, 0xFF];
    let msg = message_with_pointered_record(12 /* PTR */, &rdata);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    assert!(
      rec.canonical_rdata().is_err(),
      "a record with an undecodable name must be rejected"
    );
  }

  #[test]
  fn canonical_rdata_validates_txt_segments() {
    // TXT canonicalization must walk the length-prefixed strings.
    // A length octet that overruns the (bounded) RDATA must make canonical_rdata
    // Err so the caller (query answer collection / cache insertion) DROPS it —
    // otherwise a single malformed TXT poisons the cache and query results.
    let malformed = [5u8, b'a', b'b']; // claims a 5-byte string, only 2 follow
    let msg = message_with_pointered_record(16 /* TXT */, &malformed);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    assert!(
      rec.canonical_rdata().is_err(),
      "a TXT record whose segment length overruns its RDATA must be rejected"
    );

    // A well-formed multi-segment TXT canonicalizes verbatim (segments rebuilt
    // length-prefixed, in order).
    let valid = [3u8, b'k', b'e', b'y', 1, b'x']; // "key" then "x"
    let msg = message_with_pointered_record(16, &valid);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    assert_eq!(
      rec.canonical_rdata().unwrap(),
      std::vec::Vec::from(&valid[..]),
      "a valid multi-segment TXT must canonicalize to its verbatim segments"
    );

    // An empty TXT (zero-length RDATA) normalizes to a single zero-length string
    // (RFC 6763 §6.1), matching respond::write_canonical_txt and a peer's
    // compliant empty TXT — so the two forms dedupe as one identity.
    let msg = message_with_pointered_record(16, &[]);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    assert_eq!(
      rec.canonical_rdata().unwrap(),
      std::vec![0u8],
      "an empty TXT must canonicalize to a single zero-length string (§6.1)"
    );
  }

  #[test]
  fn canonical_rdata_folds_case_but_preserved_form_does_not() {
    // PTR target "InSt" (mixed case) + pointer→"svc.local.".
    let rdata = [4, b'I', b'n', b'S', b't', 0xC0, 0x0C];
    let msg = message_with_pointered_record(12 /* PTR */, &rdata);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();

    // Preserved form keeps the original instance-label case (for display).
    let mut preserved_expected = std::vec::Vec::from(&[4u8, b'I', b'n', b'S', b't'][..]);
    preserved_expected.extend_from_slice(SVC_LOCAL_WIRE);
    assert_eq!(rec.canonical_rdata().unwrap(), preserved_expected);

    // Folded form lowercases all labels (case-insensitive identity).
    let mut folded_expected = std::vec::Vec::from(&[4u8, b'i', b'n', b's', b't'][..]);
    folded_expected.extend_from_slice(SVC_LOCAL_WIRE);
    assert_eq!(rec.canonical_rdata_folded().unwrap(), folded_expected);
  }

  #[test]
  fn canonical_rdata_rejects_unhandled_name_bearing_type() {
    // a well-known compressible name-bearing type we don't parse
    // (NS = 2) maps to Unknown; its rdata (a possibly-compressed name) can't be
    // canonicalized, so canonical_rdata must drop it rather than store
    // compression/case-sensitive bytes. Here the NS target is a pointer.
    let rdata = [0xC0, 0x0C];
    let msg = message_with_pointered_record(2 /* NS */, &rdata);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    assert!(
      matches!(
        rec.canonical_rdata(),
        Err(ParseError::UnsupportedNameBearingType(2))
      ),
      "NS must be dropped as an unsupported name-bearing type"
    );
    // A genuinely-unknown opaque type (e.g. 64) is stored verbatim (RFC 3597
    // §4: such types are never compressed).
    let opaque = [0x01, 0x02, 0x03];
    let msg2 = message_with_pointered_record(64, &opaque);
    let (rec2, _) = Ref::try_parse(&msg2, 23).unwrap();
    assert_eq!(
      rec2.canonical_rdata().unwrap(),
      std::vec::Vec::from(&opaque[..])
    );

    // MINFO (14) is another RFC 1035 compressible name-bearing type
    // we don't parse — it must be dropped too, not just NS/SOA/MX/DNAME.
    let msg3 = message_with_pointered_record(14 /* MINFO */, &[0xC0, 0x0C]);
    let (rec3, _) = Ref::try_parse(&msg3, 23).unwrap();
    assert!(matches!(
      rec3.canonical_rdata(),
      Err(ParseError::UnsupportedNameBearingType(14))
    ));
  }

  #[test]
  fn canonical_rdata_rejects_overlong_encoded_name() {
    // 128 one-byte labels — summed content is 128 (≤ 255, so the
    // label iterator accepts it), but the ENCODED length (length octet + byte
    // per label, plus root terminator = 257) exceeds RFC 1035's 255-octet
    // limit. write_wire must reject it so an over-length name is never stored.
    let mut rdata = std::vec::Vec::new();
    for _ in 0..128 {
      rdata.push(1u8);
      rdata.push(b'a');
    }
    rdata.push(0); // root
    let msg = message_with_pointered_record(12 /* PTR */, &rdata);
    let (rec, _) = Ref::try_parse(&msg, 23).unwrap();
    assert!(
      rec.canonical_rdata().is_err(),
      "an over-length encoded name must be rejected"
    );
  }

  #[test]
  fn try_parse_rejects_message_too_short_for_fixed_header() {
    // "x.local." parses, but fewer than the 10 fixed type/class/ttl/rdlen
    // header bytes follow — the record header read must fail cleanly.
    let msg: [u8; 12] = [1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 1, 2];
    assert!(Ref::try_parse(&msg, 0).is_err());
  }

  #[test]
  fn try_parse_rejects_rdlength_overrun() {
    // name(9) + TYPE=PTR + CLASS=IN + TTL + RDLENGTH=100, but no rdata follows,
    // so the declared rdata runs off the end of the message.
    let msg: [u8; 19] = [
      1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0, // owner name
      0, 12, // TYPE = 12 (PTR)
      0, 1, // CLASS = 1 (IN)
      0, 0, 0, 120, // TTL
      0, 100, // RDLENGTH = 100 (no rdata present)
    ];
    assert!(matches!(
      Ref::try_parse(&msg, 0),
      Err(ParseError::RdlengthOverrun(_))
    ));
  }
}

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

// `RdataNames` is only consumed by `write_canonical_rdata` below, which is
// itself `cfg_heap!`-gated — without a matching cfg here the import is dead
// (and denied by `-D warnings`) on every tier without a heap.
cfg_heap! {
  use super::RdataNames;
}

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

  /// The whole message this record came from, plus where its RDATA starts and
  /// how long it is.
  ///
  /// A compression pointer inside RDATA is an offset into the WHOLE message, so
  /// a decoder holding only the rdata slice cannot follow one. That is why
  /// [`Rdata::Other`] is not enough to decompress a name-bearing type this crate
  /// has no parser for — see `ResourceType::rdata_names`.
  #[allow(dead_code)]
  pub(crate) const fn rdata_location(&self) -> (&'a [u8], usize, usize) {
    (self.message, self.rdata_start, self.rdata_len)
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
  /// EXPANDED to self-contained wire form, PRESERVING name case. Case is
  /// preserved so a query caller can surface the name for display (RFC 6762
  /// §16).
  ///
  /// For record IDENTITY comparison use [`Self::canonical_rdata_folded`], which
  /// additionally case-folds so two encodings differing only in name case (or
  /// compression) compare equal.
  pub(crate) fn canonical_rdata(&self) -> Result<RdataBuf, ParseError> {
    self.canonical_rdata_inner(RdataForm::PRESERVING_CASE)
  }

  /// Like [`Self::canonical_rdata`] but case-FOLDS names (ASCII lowercase) —
  /// the canonical case-insensitive identity form (RFC 6762 §16). Used for the
  /// passive cache, whose `(name, rtype, rclass, rdata)` dedup / TTL=0 goodbye
  /// removal / cache-flush sibling matching compare rdata bytewise: without
  /// folding, a peer announcing then withdrawing the same record with differing
  /// case would leave a stale entry (and case variants could bloat the bounded
  /// cache). The cache never surfaces rdata for display, so folding is safe
  /// there. It is also the form the service layer's §7.1 known-answer
  /// suppression and §9 identical-rdata screen compare over.
  pub(crate) fn canonical_rdata_folded(&self) -> Result<RdataBuf, ParseError> {
    self.canonical_rdata_inner(RdataForm::FOLDED)
  }

  fn canonical_rdata_inner(&self, form: RdataForm) -> Result<RdataBuf, ParseError> {
    let mut out = std::vec::Vec::new();
    self.write_canonical_rdata(form, &mut out)?;
    Ok(rdata_from_vec(out))
  }

  /// THE structural decode of this record's rdata, appended to `out`.
  ///
  /// # One decoder, because the failures have to agree
  ///
  /// Three questions are asked of a peer's rdata in this crate — "which of two
  /// §8.2 proposals sorts later", "are these two records the same record", and
  /// "what do I store for this record" — and they differ ONLY in the two knobs
  /// [`RdataForm`] carries. Everything else is one job: FIND THE NAMES THE TYPE
  /// DEFINES, DECOMPRESS THEM, AND FAIL WHEN THEY DO NOT DECODE.
  ///
  /// They were three separate serializers, and the divergence was not cosmetic.
  /// The identity form raw-copied [`Rdata::Other`] and dropped NSEC's
  /// `next_name`, so it never failed on either; the §8.2 form decompressed both
  /// and did. The same bytes therefore answered "unreadable, decide nothing" on
  /// one path and "differing rdata" on the other — and "differing rdata" at a
  /// name we are probing IS an RFC 6762 §8.1 defeat. One malformed IN/NS
  /// response, needing no knowledge of our records at all, renamed a probing
  /// service.
  ///
  /// With one decoder that is unrepresentable rather than fixed: a type cannot
  /// be safe for one consumer and fatal for another, because there is only one
  /// answer to be had. A knob may change the BYTES; none can change whether
  /// there are bytes.
  ///
  /// Note what the laziness of the typed parsers means here. `Srv`, `Nsec`,
  /// `Ptr` and `Cname` all obtain their name through `NameRef::try_parse`,
  /// which accepts a compression pointer WITHOUT following it — so
  /// [`Self::rdata_view`] succeeds on a record whose embedded name is a pointer
  /// cycle, and only writing the name out discovers it. The validation this
  /// function performs is therefore not a duplicate of `rdata_view`'s; it is
  /// the only place those names are decoded at all.
  pub(crate) fn write_canonical_rdata(
    &self,
    form: RdataForm,
    out: &mut std::vec::Vec<u8>,
  ) -> Result<(), ParseError> {
    match self.rdata_view()? {
      Rdata::Ptr(p) => p.target().write_wire(out, form.fold_case)?,
      Rdata::Cname(c) => c.target().write_wire(out, form.fold_case)?,
      Rdata::Srv(s) => {
        out.extend_from_slice(&s.priority().to_be_bytes());
        out.extend_from_slice(&s.weight().to_be_bytes());
        out.extend_from_slice(&s.port().to_be_bytes());
        s.target().write_wire(out, form.fold_case)?;
      }
      // NSEC rdata is `next_name` THEN the type bitmap (RFC 4034 §4.1), and the
      // name is on §18.14's compressible list. Dropping it — which the identity
      // form used to do — discarded both a difference the comparison must see
      // (two NSECs denying the same types at different names compared equal) and
      // the decode that fails closed on an unreadable name.
      Rdata::Nsec(n) => {
        n.next_name().write_wire(out, form.fold_case)?;
        out.extend_from_slice(n.type_bitmap_slice());
      }
      Rdata::Other(bytes) => match self.rtype.rdata_names() {
        // Absent from RFC 6762 §18.14, so §18.14's own closing sentence says its
        // names MUST NOT be compressed: the bytes mean the same thing in any
        // packet WHATEVER octets they hold, and they are copied verbatim.
        // Deliberately WITHOUT sniffing for `0xC0` — pointer syntax is
        // meaningful only inside a field a type defines as a name, so a `0xC0`
        // here is ordinary data. A byte-sniffing predicate briefly refused such
        // a record, and because the peer compared it correctly and won while we
        // abandoned, both hosts went on to claim the name.
        RdataNames::Opaque => out.extend_from_slice(bytes),
        // On §18.14's list: decompress the names in place. A raw copy would be
        // message-OFFSET-dependent, so the same record at a different position
        // in the packet would yield different bytes.
        RdataNames::Compressible { lead, names } => {
          self.write_decompressed_rdata(lead, names, form.fold_case, out)?;
        }
      },
      Rdata::Txt(t) => {
        // TXT rdata is a sequence of length-prefixed strings (RFC 6763 §6), NOT
        // opaque bytes. Walking the segments VALIDATES: a length octet that
        // overruns the rdata makes `segments()` yield Err, which propagates so
        // the caller drops the record. Without this a malformed TXT (a length
        // byte of 5 followed by 2 bytes) passed the validity gate and was
        // admitted to the cache / query results.
        let mut wrote_any = false;
        for seg in t.segments() {
          let seg = seg?;
          // A parsed segment's length came from a single octet, so it is <= 255.
          #[allow(clippy::cast_possible_truncation)]
          out.push(seg.len() as u8);
          out.extend_from_slice(seg);
          wrote_any = true;
        }
        // RFC 6763 §6.1: a TXT record MUST contain at least one string, so the
        // identity of an empty one is a single zero-length string — which is
        // what this crate's builder emits and what a compliant peer sends.
        // §8.2 does NOT normalise: a peer that sent zero-length rdata proposed
        // zero-length rdata, and that is the byte string it will compare.
        if !wrote_any && form.normalise_empty_txt {
          out.push(0);
        }
      }
      // A / AAAA carry no domain name and no internal structure — copy verbatim.
      // (`_` also satisfies the `#[non_exhaustive]` enum.) `rdata_view` above
      // already rejected an oversize A/AAAA, so these bytes are the address.
      _ => out.extend_from_slice(self.rdata()),
    }
    Ok(())
  }

  /// Rewrite a §18.14-compressible RDATA into self-contained form: `lead` fixed
  /// octets verbatim, then `names` domain names UNCOMPRESSED, then whatever
  /// remains verbatim.
  ///
  /// ONE decoder for every eligible type, because they all share that shape —
  /// `(0,1)` for NS/CNAME/PTR/DNAME, `(0,2)` for RP and for SOA (whose 20 octets
  /// of timers are simply the remainder), `(2,1)` for MX/AFSDB/RT/KX, `(2,2)`
  /// for PX. The alternative was a parser per type, which is far more code for
  /// types that cannot legitimately appear at a DNS-SD instance name.
  ///
  /// Needs the whole message, not the rdata slice: a compression pointer is an
  /// offset into the message, which is why [`Rdata::Other`] alone cannot do this.
  fn write_decompressed_rdata(
    &self,
    lead: usize,
    names: u8,
    fold_case: bool,
    out: &mut std::vec::Vec<u8>,
  ) -> Result<(), ParseError> {
    let (message, rdata_start, rdata_len) = self.rdata_location();
    let rdata_end = rdata_start.saturating_add(rdata_len);
    let mut cursor = rdata_start.saturating_add(lead);
    if cursor > rdata_end {
      return Err(ParseError::UnsupportedNameBearingType(self.rtype.to_u16()));
    }
    // The fixed prefix carries no name, so it is already self-contained.
    out.extend_from_slice(message.get(rdata_start..cursor).unwrap_or(&[]));
    for _ in 0..names {
      let (name, consumed) = NameRef::try_parse(message, cursor)?;
      name.write_wire(out, fold_case)?;
      cursor = cursor.saturating_add(consumed);
      // A name that ran past the record's own RDLENGTH is malformed, and the
      // remainder below would be nonsense; fail rather than compare it.
      if cursor > rdata_end {
        return Err(ParseError::UnsupportedNameBearingType(self.rtype.to_u16()));
      }
    }
    // Everything after the names is fixed data of the type (SOA's timers) and
    // carries no name, so it too is self-contained as sent.
    out.extend_from_slice(message.get(cursor..rdata_end).unwrap_or(&[]));
    Ok(())
  }
  }
}

cfg_heap! {
/// The two knobs that separate this crate's three canonical-rdata consumers.
///
/// They are knobs rather than three functions because the STRUCTURAL decode
/// — see [`Ref::write_canonical_rdata`] — must be identical for all three: a
/// record that cannot be decoded has to be undecodable for every consumer, or
/// one of them reads malformed data as an ordinary answer. Only the
/// normalisation may differ, and only in these two ways.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct RdataForm {
  /// Lowercase the ASCII bytes of every embedded name (RFC 6762 §16's
  /// case-insensitive canonical form).
  fold_case: bool,
  /// Render a TXT with no strings as one zero-length string (RFC 6763 §6.1).
  normalise_empty_txt: bool,
}

impl RdataForm {
  /// RFC 6762 §8.2's form: EXACTLY what the sender put on the wire, with names
  /// decompressed and nothing else touched.
  ///
  /// §8.2 mandates one transformation and no others — "the names MUST be
  /// uncompressed before comparison" — over a "raw comparison of the binary
  /// content of the rdata without regard for meaning or structure". Normalising
  /// here breaks the tiebreak's symmetry, because the peer compares OUR bytes
  /// unnormalised: with our SRV target `m.local` and the peer's `Z.local`, the
  /// peer sees `Z`(0x5A) before `m`(0x6D) and loses, while a normalising us
  /// sees `m`(0x6D) before `z`(0x7A) and also loses. Both abdicate, and the
  /// mirror case gives two owners.
  pub(crate) const AS_SENT: Self = Self {
    fold_case: false,
    normalise_empty_txt: false,
  };

  /// Self-contained bytes with name case PRESERVED, for a caller that may
  /// surface the name for display (RFC 6762 §16).
  pub(crate) const PRESERVING_CASE: Self = Self {
    fold_case: false,
    normalise_empty_txt: true,
  };

  /// The IDENTITY form — "are these two records the same record". Names are
  /// case-folded and an empty TXT is normalised, so two encodings of one record
  /// compare equal however the sender spelled them.
  pub(crate) const FOLDED: Self = Self {
    fold_case: true,
    normalise_empty_txt: true,
  };
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

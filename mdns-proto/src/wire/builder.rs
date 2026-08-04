//! Incremental mDNS message encoder with bounded compression table.
//!
//! The builder writes into a caller-supplied `&mut [u8]` and tracks the
//! number of bytes used. A const-generic `CompressionTable<COMP_N>` records
//! up to `COMP_N` name-offset entries for back-references; names beyond
//! capacity are simply written uncompressed (legal — slightly larger output).
//!
//! Requires the `Name` type, so the `MessageBuilder` and `CompressionTable`
//! are only available when one of `alloc` / `std` / `no-atomic` features is
//! enabled.

#![cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]

use super::{HEADER_SIZE, Header, ResourceClass, ResourceType};
use crate::{
  Name,
  constants::{MAX_LABEL_BYTES, MAX_NAME_BYTES},
  error::{BufferTooSmallDetail, EncodeError},
};

/// Default compression-table size used by [`MessageBuilder`] when the user
/// doesn't override.
pub const DEFAULT_COMPRESSION_TABLE: usize = 32;

/// Bounded compression table — stores (name-bytes-hash, offset-in-message)
/// pairs as back-references. Hashes (instead of names) so we can run no_alloc.
#[derive(Debug, Copy, Clone)]
pub struct CompressionTable<const COMP_N: usize> {
  entries: [(u64, u16); COMP_N],
  used: usize,
}

impl<const COMP_N: usize> CompressionTable<COMP_N> {
  /// Empty compression table.
  pub const fn new() -> Self {
    Self {
      entries: [(0, 0); COMP_N],
      used: 0,
    }
  }

  /// Looks up an offset for a name hash, if known.
  pub fn lookup(&self, hash: u64) -> Option<u16> {
    let mut i = 0usize;
    while i < self.used {
      let entry = self.entries.get(i)?;
      if entry.0 == hash {
        return Some(entry.1);
      }
      i = i.saturating_add(1);
    }
    None
  }

  /// Records a (hash, offset) pair. Silently drops the entry if the table
  /// is full (legal — yields a larger but valid message).
  pub fn insert(&mut self, hash: u64, offset: u16) {
    if self.used < COMP_N
      && let Some(slot) = self.entries.get_mut(self.used)
    {
      *slot = (hash, offset);
      self.used = self.used.saturating_add(1);
    }
  }
}

impl<const COMP_N: usize> Default for CompressionTable<COMP_N> {
  fn default() -> Self {
    Self::new()
  }
}

/// Deterministic FNV-1a hash of a DNS suffix (the remaining labels at a
/// given position), case-insensitive. Used by the compression table.
#[allow(clippy::arithmetic_side_effects)]
fn hash_suffix(labels: &[&[u8]]) -> u64 {
  const FNV_BASIS: u64 = 0xcbf29ce484222325;
  const FNV_PRIME: u64 = 0x100000001b3;
  let mut h: u64 = FNV_BASIS;
  for label in labels {
    for &b in *label {
      h ^= b.to_ascii_lowercase() as u64;
      h = h.wrapping_mul(FNV_PRIME);
    }
    h ^= b'.' as u64;
    h = h.wrapping_mul(FNV_PRIME);
  }
  h
}

/// An opaque snapshot of a [`MessageBuilder`]'s full encode state — write
/// cursor, header counts, and compression-table size. Used to speculatively
/// append an OPTIONAL record group (e.g. an RFC 6762 §6.1 NSEC) and roll back
/// cleanly if it does not fit, without discarding records already written.
#[derive(Copy, Clone)]
pub struct BuilderCheckpoint {
  cursor: usize,
  header: Header,
  compression_used: usize,
}

/// Incremental mDNS message encoder.
pub struct MessageBuilder<'a, const COMP_N: usize = DEFAULT_COMPRESSION_TABLE> {
  out: &'a mut [u8],
  cursor: usize,
  header: Header,
  compression: CompressionTable<COMP_N>,
}

impl<'a, const COMP_N: usize> MessageBuilder<'a, COMP_N> {
  /// Begin building. Reserves the 12-byte header slot and finalises it on
  /// [`Self::finish`].
  pub fn try_new(out: &'a mut [u8], header: Header) -> Result<Self, EncodeError> {
    if out.len() < HEADER_SIZE {
      return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
        HEADER_SIZE,
        out.len(),
      )));
    }
    Ok(Self {
      out,
      cursor: HEADER_SIZE,
      header,
      compression: CompressionTable::new(),
    })
  }

  /// Snapshot the full encode state — cursor, header counts, and
  /// compression-table size (see [`BuilderCheckpoint`]).
  pub fn checkpoint(&self) -> BuilderCheckpoint {
    BuilderCheckpoint {
      cursor: self.cursor,
      header: self.header,
      compression_used: self.compression.used,
    }
  }

  /// Roll back to a [`Self::checkpoint`], fully restoring the encode state: the
  /// write cursor, the header counts, AND the compression table — entries
  /// recorded after the snapshot are dropped. Without truncating the
  /// table, a later `write_name` could emit a back-reference pointer into the
  /// rolled-back (now-overwritten) region and corrupt the message; restoring
  /// `used` makes those stale entries invisible to `lookup`, so appending after
  /// a restore is safe.
  pub fn restore(&mut self, cp: BuilderCheckpoint) {
    self.cursor = cp.cursor;
    self.header = cp.header;
    self.compression.used = cp.compression_used;
  }

  /// Append a question to the message.
  pub fn push_question(
    &mut self,
    name: &Name,
    qtype: ResourceType,
    qclass: ResourceClass,
    unicast_response: bool,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(qtype.to_u16())?;
    let class_raw = qclass.to_u16()
      | if unicast_response {
        super::resource_class::UNICAST_RESPONSE_BIT
      } else {
        0
      };
    self.write_u16(class_raw)?;
    self
      .header
      .set_question_count(self.header.question_count().saturating_add(1));
    Ok(())
  }

  /// Append an A record answer.
  ///
  /// `cache_flush` — when `true`, the cache-flush bit (RFC 6762 §10.2, bit 15
  /// of the class field) is set.  Set this for unique records (A/AAAA/SRV/TXT
  /// owned by a single host); leave clear for shared records such as PTR.
  pub fn push_a_answer(
    &mut self,
    name: &Name,
    ttl: u32,
    addr: core::net::Ipv4Addr,
    cache_flush: bool,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(ResourceType::A.to_u16())?;
    let class_raw = ResourceClass::In.to_u16()
      | if cache_flush {
        super::resource_class::CACHE_FLUSH_BIT
      } else {
        0
      };
    self.write_u16(class_raw)?;
    self.write_u32(ttl)?;
    self.write_u16(4)?;
    for &b in &addr.octets() {
      self.write_byte(b)?;
    }
    self
      .header
      .set_answer_count(self.header.answer_count().saturating_add(1));
    Ok(())
  }

  /// Append an AAAA record answer.
  ///
  /// `cache_flush` — when `true`, the cache-flush bit (RFC 6762 §10.2) is set.
  /// Unique records such as AAAA should always set this.
  pub fn push_aaaa_answer(
    &mut self,
    name: &Name,
    ttl: u32,
    addr: core::net::Ipv6Addr,
    cache_flush: bool,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(ResourceType::AAAA.to_u16())?;
    let class_raw = ResourceClass::In.to_u16()
      | if cache_flush {
        super::resource_class::CACHE_FLUSH_BIT
      } else {
        0
      };
    self.write_u16(class_raw)?;
    self.write_u32(ttl)?;
    self.write_u16(16)?;
    for &b in &addr.octets() {
      self.write_byte(b)?;
    }
    self
      .header
      .set_answer_count(self.header.answer_count().saturating_add(1));
    Ok(())
  }

  /// Append an SRV record answer.
  ///
  /// `cache_flush` — when `true`, the cache-flush bit (RFC 6762 §10.2) is set.
  /// SRV records are unique and should always set this.
  #[allow(clippy::too_many_arguments)]
  pub fn push_srv_answer(
    &mut self,
    name: &Name,
    ttl: u32,
    priority: u16,
    weight: u16,
    port: u16,
    target: &Name,
    cache_flush: bool,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(ResourceType::Srv.to_u16())?;
    let class_raw = ResourceClass::In.to_u16()
      | if cache_flush {
        super::resource_class::CACHE_FLUSH_BIT
      } else {
        0
      };
    self.write_u16(class_raw)?;
    self.write_u32(ttl)?;
    let len_offset = self.cursor;
    self.write_u16(0)?;
    let rdata_start = self.cursor;
    self.write_u16(priority)?;
    self.write_u16(weight)?;
    self.write_u16(port)?;
    self.write_name(target)?;
    let rdata_end = self.cursor;
    let rdlen = u16::try_from(rdata_end.saturating_sub(rdata_start)).map_err(EncodeError::from)?;
    let slot = self
      .out
      .get_mut(len_offset..len_offset.saturating_add(2))
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(2, 0)))?;
    slot.copy_from_slice(&rdlen.to_be_bytes());
    self
      .header
      .set_answer_count(self.header.answer_count().saturating_add(1));
    Ok(())
  }

  /// Append a TXT record answer.
  ///
  /// `cache_flush` — when `true`, the cache-flush bit (RFC 6762 §10.2) is set.
  /// TXT records are unique and should always set this.
  pub fn push_txt_answer<I, S>(
    &mut self,
    name: &Name,
    ttl: u32,
    segments: I,
    cache_flush: bool,
  ) -> Result<(), EncodeError>
  where
    I: IntoIterator<Item = S>,
    S: AsRef<[u8]>,
  {
    self.write_name(name)?;
    self.write_u16(ResourceType::Txt.to_u16())?;
    let class_raw = ResourceClass::In.to_u16()
      | if cache_flush {
        super::resource_class::CACHE_FLUSH_BIT
      } else {
        0
      };
    self.write_u16(class_raw)?;
    self.write_u32(ttl)?;
    let len_offset = self.cursor;
    self.write_u16(0)?;
    let rdata_start = self.cursor;
    let mut wrote_any = false;
    for seg in segments {
      let s = seg.as_ref();
      if s.len() > 255 {
        return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
          s.len(),
          255,
        )));
      }
      #[allow(clippy::cast_possible_truncation)]
      self.write_byte(s.len() as u8)?;
      for &b in s {
        self.write_byte(b)?;
      }
      wrote_any = true;
    }
    // RFC 6763 §6.1: a TXT record MUST contain at least one string. The "no
    // information" representation is a single zero-length string (one 0x00
    // length byte), NOT empty rdata — an empty TXT RR (RDLENGTH 0) is invalid.
    if !wrote_any {
      self.write_byte(0)?;
    }
    let rdata_end = self.cursor;
    let rdlen = u16::try_from(rdata_end.saturating_sub(rdata_start)).map_err(EncodeError::from)?;
    let slot = self
      .out
      .get_mut(len_offset..len_offset.saturating_add(2))
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(2, 0)))?;
    slot.copy_from_slice(&rdlen.to_be_bytes());
    self
      .header
      .set_answer_count(self.header.answer_count().saturating_add(1));
    Ok(())
  }

  /// Append a PTR record answer.
  pub fn push_ptr_answer(
    &mut self,
    name: &Name,
    ttl: u32,
    target: &Name,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(ResourceType::Ptr.to_u16())?;
    self.write_u16(ResourceClass::In.to_u16())?;
    self.write_u32(ttl)?;
    let len_offset = self.cursor;
    self.write_u16(0)?;
    let rdata_start = self.cursor;
    self.write_name(target)?;
    let rdata_end = self.cursor;
    let rdlen = u16::try_from(rdata_end.saturating_sub(rdata_start)).map_err(EncodeError::from)?;
    let slot = self
      .out
      .get_mut(len_offset..len_offset.saturating_add(2))
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(2, 0)))?;
    slot.copy_from_slice(&rdlen.to_be_bytes());
    self
      .header
      .set_answer_count(self.header.answer_count().saturating_add(1));
    Ok(())
  }

  // ── Authority-section record writers ────────────────────────────────
  // These are structurally identical to the answer-section variants except
  // they increment `authority_count` in the header.

  /// Append an A record to the authority section.
  pub fn push_a_authority(
    &mut self,
    name: &Name,
    ttl: u32,
    addr: core::net::Ipv4Addr,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(ResourceType::A.to_u16())?;
    self.write_u16(ResourceClass::In.to_u16())?;
    self.write_u32(ttl)?;
    self.write_u16(4)?;
    for &b in &addr.octets() {
      self.write_byte(b)?;
    }
    self
      .header
      .set_authority_count(self.header.authority_count().saturating_add(1));
    Ok(())
  }

  /// Append an AAAA record to the authority section.
  pub fn push_aaaa_authority(
    &mut self,
    name: &Name,
    ttl: u32,
    addr: core::net::Ipv6Addr,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(ResourceType::AAAA.to_u16())?;
    self.write_u16(ResourceClass::In.to_u16())?;
    self.write_u32(ttl)?;
    self.write_u16(16)?;
    for &b in &addr.octets() {
      self.write_byte(b)?;
    }
    self
      .header
      .set_authority_count(self.header.authority_count().saturating_add(1));
    Ok(())
  }

  /// Append an SRV record to the authority section.
  pub fn push_srv_authority(
    &mut self,
    name: &Name,
    ttl: u32,
    priority: u16,
    weight: u16,
    port: u16,
    target: &Name,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(ResourceType::Srv.to_u16())?;
    self.write_u16(ResourceClass::In.to_u16())?;
    self.write_u32(ttl)?;
    let len_offset = self.cursor;
    self.write_u16(0)?;
    let rdata_start = self.cursor;
    self.write_u16(priority)?;
    self.write_u16(weight)?;
    self.write_u16(port)?;
    self.write_name(target)?;
    let rdata_end = self.cursor;
    let rdlen = u16::try_from(rdata_end.saturating_sub(rdata_start)).map_err(EncodeError::from)?;
    let slot = self
      .out
      .get_mut(len_offset..len_offset.saturating_add(2))
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(2, 0)))?;
    slot.copy_from_slice(&rdlen.to_be_bytes());
    self
      .header
      .set_authority_count(self.header.authority_count().saturating_add(1));
    Ok(())
  }

  /// Append a TXT record to the authority section.
  pub fn push_txt_authority<I, S>(
    &mut self,
    name: &Name,
    ttl: u32,
    segments: I,
  ) -> Result<(), EncodeError>
  where
    I: IntoIterator<Item = S>,
    S: AsRef<[u8]>,
  {
    self.write_name(name)?;
    self.write_u16(ResourceType::Txt.to_u16())?;
    self.write_u16(ResourceClass::In.to_u16())?;
    self.write_u32(ttl)?;
    let len_offset = self.cursor;
    self.write_u16(0)?;
    let rdata_start = self.cursor;
    let mut wrote_any = false;
    for seg in segments {
      let s = seg.as_ref();
      if s.len() > 255 {
        return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
          s.len(),
          255,
        )));
      }
      #[allow(clippy::cast_possible_truncation)]
      self.write_byte(s.len() as u8)?;
      for &b in s {
        self.write_byte(b)?;
      }
      wrote_any = true;
    }
    // RFC 6763 §6.1: a TXT record MUST contain at least one string. The "no
    // information" representation is a single zero-length string (one 0x00
    // length byte), NOT empty rdata — an empty TXT RR (RDLENGTH 0) is invalid.
    if !wrote_any {
      self.write_byte(0)?;
    }
    let rdata_end = self.cursor;
    let rdlen = u16::try_from(rdata_end.saturating_sub(rdata_start)).map_err(EncodeError::from)?;
    let slot = self
      .out
      .get_mut(len_offset..len_offset.saturating_add(2))
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(2, 0)))?;
    slot.copy_from_slice(&rdlen.to_be_bytes());
    self
      .header
      .set_authority_count(self.header.authority_count().saturating_add(1));
    Ok(())
  }

  /// Append a PTR record to the authority section.
  pub fn push_ptr_authority(
    &mut self,
    name: &Name,
    ttl: u32,
    target: &Name,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(ResourceType::Ptr.to_u16())?;
    self.write_u16(ResourceClass::In.to_u16())?;
    self.write_u32(ttl)?;
    let len_offset = self.cursor;
    self.write_u16(0)?;
    let rdata_start = self.cursor;
    self.write_name(target)?;
    let rdata_end = self.cursor;
    let rdlen = u16::try_from(rdata_end.saturating_sub(rdata_start)).map_err(EncodeError::from)?;
    let slot = self
      .out
      .get_mut(len_offset..len_offset.saturating_add(2))
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(2, 0)))?;
    slot.copy_from_slice(&rdlen.to_be_bytes());
    self
      .header
      .set_authority_count(self.header.authority_count().saturating_add(1));
    Ok(())
  }

  /// Append an NSEC record to the **additional** section (RFC 6762 §6.1,
  /// "negative responses"). `present_types` lists the resource-record types
  /// that DO exist at `name` — e.g. `[A]` for an IPv4-only host, or
  /// `[SRV, TXT]` for a service instance. A querier asking for any type NOT in
  /// the bitmap thereby learns authoritatively that no such record exists,
  /// instead of waiting out a retransmission timeout. The NSEC "Next Domain
  /// Name" field is the owner name itself (§6.1; legacy DNSSEC chaining does
  /// not apply to mDNS). Every type must be `< 256` so it maps into RFC 4034
  /// §4.1.2 window block 0 — the only block mDNS service types need; any
  /// `>= 256` entry is ignored.
  ///
  /// `cache_flush` — set for the unique RRset this NSEC asserts (RFC 6762
  /// §10.2), as the host/instance records it describes are themselves unique.
  pub fn push_nsec_additional(
    &mut self,
    name: &Name,
    ttl: u32,
    present_types: &[u16],
    cache_flush: bool,
  ) -> Result<(), EncodeError> {
    self.write_name(name)?;
    self.write_u16(ResourceType::Nsec.to_u16())?;
    let class_raw = ResourceClass::In.to_u16()
      | if cache_flush {
        super::resource_class::CACHE_FLUSH_BIT
      } else {
        0
      };
    self.write_u16(class_raw)?;
    self.write_u32(ttl)?;
    let len_offset = self.cursor;
    self.write_u16(0)?;
    let rdata_start = self.cursor;
    // RFC 6762 §6.1: the NSEC "Next Domain Name" is the owner name itself.
    self.write_name(name)?;
    // Type bitmap (RFC 4034 §4.1.2). Every mDNS type we assert (A=1, TXT=16,
    // AAAA=28, SRV=33) lives in window block 0 (types 0..=255), so a single
    // window suffices. Bit for type T = byte (T/8), mask 0x80 >> (T%8).
    let mut bitmap = [0u8; 32];
    let mut max_byte: Option<usize> = None;
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    for &t in present_types {
      if t >= 256 {
        continue;
      }
      let byte_idx = (t >> 3) as usize; // t / 8
      let mask = 0x80u8 >> (t & 0x07); // 0x80 >> (t % 8)
      if let Some(slot) = bitmap.get_mut(byte_idx) {
        *slot |= mask;
        max_byte = Some(max_byte.map_or(byte_idx, |m| m.max(byte_idx)));
      }
    }
    if let Some(max_byte) = max_byte {
      let blen = max_byte.saturating_add(1);
      self.write_byte(0)?; // window block number 0
      #[allow(clippy::cast_possible_truncation)]
      self.write_byte(blen as u8)?; // bitmap length (1..=32)
      let mut i = 0usize;
      while i < blen {
        self.write_byte(bitmap.get(i).copied().unwrap_or(0))?;
        i = i.saturating_add(1);
      }
    }
    let rdata_end = self.cursor;
    let rdlen = u16::try_from(rdata_end.saturating_sub(rdata_start)).map_err(EncodeError::from)?;
    let slot = self
      .out
      .get_mut(len_offset..len_offset.saturating_add(2))
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(2, 0)))?;
    slot.copy_from_slice(&rdlen.to_be_bytes());
    self
      .header
      .set_additional_count(self.header.additional_count().saturating_add(1));
    Ok(())
  }

  /// Writes a Name into the message, using compression where the suffix
  /// has been seen before.
  fn write_name(&mut self, name: &Name) -> Result<(), EncodeError> {
    let s = name.as_str();
    if s.is_empty() {
      return self.write_byte(0);
    }
    let trimmed = match s.strip_suffix('.') {
      Some(r) => r,
      None => s,
    };
    // Collect labels into a stack-allocated array; max 128 labels per name.
    let mut labels: [&[u8]; 128] = [&[]; 128];
    let mut nlabels = 0usize;
    for label in trimmed.split('.') {
      if nlabels >= labels.len() {
        return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
          MAX_NAME_BYTES,
          self.out.len(),
        )));
      }
      if let Some(slot) = labels.get_mut(nlabels) {
        *slot = label.as_bytes();
        nlabels = nlabels.saturating_add(1);
      }
    }

    // Find longest known suffix in the compression table.
    let mut suffix_start = nlabels;
    let mut pointer_target: Option<u16> = None;
    let mut i = 0usize;
    while i < nlabels {
      let suffix = match labels.get(i..nlabels) {
        Some(s) => s,
        None => break,
      };
      let h = hash_suffix(suffix);
      if let Some(off) = self.compression.lookup(h) {
        suffix_start = i;
        pointer_target = Some(off);
        break;
      }
      i = i.saturating_add(1);
    }

    // Emit labels [0..suffix_start) inline, then a pointer (if any).
    let mut j = 0usize;
    while j < suffix_start {
      let label = match labels.get(j) {
        Some(l) => *l,
        None => break,
      };
      if label.len() > MAX_LABEL_BYTES as usize {
        return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
          label.len(),
          self.out.len(),
        )));
      }
      // Record an entry for the suffix starting at this label.
      let suffix_slice = match labels.get(j..nlabels) {
        Some(s) => s,
        None => break,
      };
      let h = hash_suffix(suffix_slice);
      let offset = u16::try_from(self.cursor).map_err(EncodeError::from)?;
      self.compression.insert(h, offset);
      #[allow(clippy::cast_possible_truncation)]
      self.write_byte(label.len() as u8)?;
      // LOAD-BEARING BEYOND THIS FILE: the RFC 6762 §8.2 tiebreak compares raw
      // rdata bytes, and it only resolves a name if both hosts compare the same
      // pair of lists. `Service::our_proposal` therefore lowercases OUR side to
      // match what this emits, while `respond::rdata_for_tiebreak` leaves a PEER's
      // bytes exactly as received. If this stops lowercasing, `our_proposal`
      // must stop in the same change, or our comparison bytes stop being the
      // bytes we transmit and every tiebreak against a byte-comparing peer can
      // disagree.
      for &b in label {
        self.write_byte(b.to_ascii_lowercase())?;
      }
      j = j.saturating_add(1);
    }
    match pointer_target {
      Some(off) => {
        #[allow(clippy::arithmetic_side_effects)]
        let hi = ((off >> 8) as u8) | 0b1100_0000;
        #[allow(clippy::cast_possible_truncation)]
        let lo = (off & 0x00ff) as u8;
        self.write_byte(hi)?;
        self.write_byte(lo)?;
      }
      None => {
        self.write_byte(0)?;
      }
    }
    Ok(())
  }

  fn write_byte(&mut self, b: u8) -> Result<(), EncodeError> {
    let slot = self
      .out
      .get_mut(self.cursor)
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(1, 0)))?;
    *slot = b;
    self.cursor = self.cursor.saturating_add(1);
    Ok(())
  }

  fn write_u16(&mut self, v: u16) -> Result<(), EncodeError> {
    let bytes = v.to_be_bytes();
    let dest = self
      .out
      .get_mut(self.cursor..self.cursor.saturating_add(2))
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(2, 0)))?;
    dest.copy_from_slice(&bytes);
    self.cursor = self.cursor.saturating_add(2);
    Ok(())
  }

  fn write_u32(&mut self, v: u32) -> Result<(), EncodeError> {
    let bytes = v.to_be_bytes();
    let dest = self
      .out
      .get_mut(self.cursor..self.cursor.saturating_add(4))
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(4, 0)))?;
    dest.copy_from_slice(&bytes);
    self.cursor = self.cursor.saturating_add(4);
    Ok(())
  }

  /// Finalise: write the header into the reserved 12-byte slot and return
  /// the total number of bytes written.
  pub fn finish(self) -> Result<usize, EncodeError> {
    let head_slot = self
      .out
      .get_mut(..HEADER_SIZE)
      .ok_or_else(|| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(HEADER_SIZE, 0)))?;
    self.header.write(head_slot)?;
    Ok(self.cursor)
  }
}

#[cfg(test)]
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(clippy::unwrap_used)]
mod tests;

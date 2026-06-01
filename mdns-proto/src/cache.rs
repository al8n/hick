//! Passive record cache observed from incoming traffic.

#[cfg(any(feature = "alloc", feature = "std"))]
use core::time::Duration;

#[cfg(any(feature = "alloc", feature = "std"))]
use crate::Instant;
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::Name;
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::Pool;
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::wire::{ResourceClass, ResourceType};

/// One cached resource record.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
#[derive(Debug, Clone)]
pub struct CacheEntry<I: Instant> {
  name: Name,
  rtype: ResourceType,
  /// cache key includes ResourceClass so a non-IN-class record
  /// cannot dedupe with, evict, or count as an IN-class record.  Without
  /// this, a malformed or hostile response with the same `(name, rtype)`
  /// but class != IN could corrupt the cache across protocol identity
  /// boundaries.
  rclass: ResourceClass,
  rdata: std::vec::Vec<u8>,
  expires_at: I,
  /// When this record was last received / refreshed.  used to
  /// implement the RFC 6762 §10.2 "1-second grace" on cache-flush —
  /// an incoming cache-flush only affects siblings whose
  /// `now - received_at >= 1 second`, so a multi-address RRSet
  /// announced across two back-to-back packets is not collapsed.
  received_at: I,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<I: Instant> CacheEntry<I> {
  /// Build a new cache entry.  `received_at` is the wall instant at
  /// which this record arrived; `expires_at` is the TTL-derived
  /// future deadline.
  pub(crate) fn new(
    name: Name,
    rtype: ResourceType,
    rclass: ResourceClass,
    rdata: std::vec::Vec<u8>,
    expires_at: I,
    received_at: I,
  ) -> Self {
    Self {
      name,
      rtype,
      rclass,
      rdata,
      expires_at,
      received_at,
    }
  }

  /// The record's name.
  #[inline(always)]
  pub fn name(&self) -> &Name {
    &self.name
  }

  /// The record's type.
  #[inline(always)]
  pub const fn rtype(&self) -> ResourceType {
    self.rtype
  }

  /// The record's class.
  #[inline(always)]
  pub const fn rclass(&self) -> ResourceClass {
    self.rclass
  }

  /// The record's raw rdata bytes.
  #[inline(always)]
  pub fn rdata_slice(&self) -> &[u8] {
    &self.rdata
  }

  /// Absolute expiration deadline.
  #[inline(always)]
  pub fn expires_at(&self) -> I {
    self.expires_at
  }

  /// Wall instant at which this record was last received / refreshed.
  #[inline(always)]
  pub fn received_at(&self) -> I {
    self.received_at
  }
}

/// Default maximum number of cache entries before eviction kicks in.
#[cfg(any(feature = "alloc", feature = "std"))]
const DEFAULT_MAX_ENTRIES: usize = 1024;

/// Passive record cache.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub struct Cache<I, P> {
  entries: P,
  max_entries: usize,
  _phantom: core::marker::PhantomData<I>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<I, P> Cache<I, P>
where
  I: Instant,
  P: Pool<CacheEntry<I>>,
{
  /// Empty cache with the default maximum entry cap (1024).
  pub fn new() -> Self {
    Self {
      entries: P::new(),
      max_entries: DEFAULT_MAX_ENTRIES,
      _phantom: core::marker::PhantomData,
    }
  }

  /// Empty cache with a custom maximum entry cap.
  ///
  /// When `try_insert` is called and the number of stored entries has reached
  /// `max`, the soonest-expiring entry is evicted proactively before the new
  /// entry is inserted. This bounds memory usage even when the backing
  /// [`Pool`] grows without error (e.g. `slab::Slab`).
  pub fn with_max_entries(max: usize) -> Self {
    Self {
      entries: P::new(),
      max_entries: max,
      _phantom: core::marker::PhantomData,
    }
  }

  /// The configured maximum number of entries.
  #[inline(always)]
  pub const fn max_entries(&self) -> usize {
    self.max_entries
  }

  /// Insert (or update / remove) a record observation.
  ///
  /// Semantics:
  /// - If `ttl == 0`, treat as "record going away" (RFC 6762 §10.1): clamp the
  ///   matching `(name, rtype, rclass, rdata)` entry's `expires_at` to one
  ///   second out (rescue window, never extending a sooner expiry) and return
  ///   `Ok(None)` — NOT an immediate delete.
  /// - If `cache_flush == true` (RFC 6762 §10.2), DEFER eviction by 1 second:
  ///   clamp the `expires_at` of every existing sibling matching
  ///   `(name, rtype, rclass)` (and not the new rdata) to `min(current,
  ///   now + 1s)`.  This gives a refresh burst time to re-announce
  ///   missing siblings before they disappear from the cache.
  /// - If a matching `(name, rtype, rclass, rdata)` entry already exists,
  ///   refresh its expiration in place and return `Ok(Some(key))`
  ///   (deduplication).
  /// - Otherwise insert a new entry.  If the pool is full, evict the
  ///   soonest-expiring entry first (best-effort) then retry.  If the
  ///   retry still fails the error is propagated.
  ///
  /// cache identity is `(name, rtype, rclass, rdata)`.  A non-IN
  /// class record cannot dedupe with, evict, or count as an IN record.
  #[allow(clippy::too_many_arguments)]
  pub fn try_insert(
    &mut self,
    name: Name,
    rtype: ResourceType,
    rclass: ResourceClass,
    rdata: std::vec::Vec<u8>,
    ttl: Duration,
    now: I,
    cache_flush: bool,
  ) -> Result<Option<usize>, P::Error> {
    // max_entries == 0 means caching is disabled.  Honour it on every
    // insert path (including cache_flush, which would otherwise insert a fresh
    // entry after evicting matching ones).  Returning Ok(None) keeps the
    // existing "no entry was inserted" semantic (same as the TTL=0 branch).
    if self.max_entries == 0 {
      // Still honour TTL=0 removals so a zero-cap cache stays consistent if a
      // caller is shrinking max_entries dynamically — but no entry to remove
      // here (the cache is empty by construction), so just bail.
      return Ok(None);
    }
    // TTL=0 → goodbye (RFC 6762 §10.1). Do NOT delete immediately: shorten the
    // matching entry to expire in ONE SECOND. This gives any responder still
    // using the record a window to rescue it (a positive-TTL re-announce before
    // then refreshes it via the dedup path below), and bounds the disruption of
    // an accidental or malicious on-link goodbye to a brief disappearance window
    // rather than instant deletion. Only ever SHORTENS — never extends a sooner
    // natural expiry. (mirrors the cache-flush deferred-expiry below.)
    if ttl == Duration::ZERO {
      if let Some(deadline) = now.checked_add_duration(Duration::from_secs(1)) {
        let mut victim: Option<usize> = None;
        for (key, entry) in self.entries.iter() {
          if entry.rtype() == rtype
            && entry.rclass() == rclass
            && entry.name().as_str() == name.as_str()
            && entry.rdata_slice() == rdata.as_slice()
          {
            victim = Some(key);
            break;
          }
        }
        if let Some(key) = victim
          && let Some(entry) = self.entries.get_mut(key)
          && entry.expires_at() > deadline
        {
          entry.expires_at = deadline;
        }
      }
      return Ok(None);
    }

    // cache_flush=true → RFC 6762 §10.2: the sender is authoritative for
    // records of this (name, rtype, rclass).  This implements the
    // RFC-specified DEFERRED expiry: instead of immediately removing
    // matching siblings, clamp their `expires_at` to `min(current,
    // now + 1s)`.  Behaviour:
    //   * Refresh bursts that re-announce missing siblings within 1s
    //     update those siblings' received_at/expires_at via the dedup
    //     path below — the clamp is undone.
    //   * Siblings that are NOT re-announced expire naturally one
    //     second later via the normal TTL sweep — callers have a 1s
    //     window to observe them before they vanish.
    //
    // the "skip recent siblings" semantics still apply: entries
    // received within the last second are left untouched (no clamp).
    if cache_flush {
      let one_sec_from_now = now.checked_add_duration(Duration::from_secs(1));
      if let Some(deadline) = one_sec_from_now {
        // Collect first to avoid mutable-while-iterating problems.
        let mut to_clamp: std::vec::Vec<usize> = std::vec::Vec::new();
        for (key, entry) in self.entries.iter() {
          if entry.rtype() != rtype
            || entry.rclass() != rclass
            || entry.name().as_str() != name.as_str()
          {
            continue;
          }
          // grace: do not touch entries received within the last second.
          let age = now.checked_duration_since(entry.received_at());
          let recent = match age {
            Some(d) => d < Duration::from_secs(1),
            None => true, // received_at in the future — treat as recent
          };
          if recent || entry.rdata_slice() == rdata.as_slice() {
            continue;
          }
          // Only clamp if it would shorten the deadline.
          if entry.expires_at() > deadline {
            to_clamp.push(key);
          }
        }
        for key in to_clamp {
          if let Some(entry) = self.entries.get_mut(key) {
            entry.expires_at = deadline;
          }
        }
      }
      // Fall through to the dedup/insert path: the new record either
      // refreshes an existing copy of itself or inserts fresh.
    }

    let expires_at = now.checked_add_duration(ttl).unwrap_or(now);

    // Deduplicate: refresh the expiration of an existing matching entry.
    let mut update_key: Option<usize> = None;
    for (key, entry) in self.entries.iter() {
      if entry.rtype() == rtype
        && entry.rclass() == rclass
        && entry.name().as_str() == name.as_str()
        && entry.rdata_slice() == rdata.as_slice()
      {
        update_key = Some(key);
        break;
      }
    }
    if let Some(key) = update_key {
      if let Some(entry) = self.entries.get_mut(key) {
        entry.expires_at = expires_at;
        entry.received_at = now;
      }
      return Ok(Some(key));
    }

    // Insert through the bounded helper (proactive cap eviction + reactive retry).
    self
      .bounded_insert(CacheEntry::new(name, rtype, rclass, rdata, expires_at, now))
      .map(Some)
  }

  /// Insert `entry` into the backing pool while respecting `max_entries`.
  ///
  /// Algorithm:
  /// 1. Proactive eviction: if the pool is at or above `max_entries`, evict the
  ///    soonest-expiring entry BEFORE attempting the insert.  This bounds memory
  ///    usage even when the backing pool is infallible (e.g. `slab::Slab`).
  /// 2. Attempt the insert.
  /// 3. Reactive eviction + retry: if the pool returns a capacity error (e.g.
  ///    `heapless` fixed-size collections), evict the soonest-expiring entry
  ///    and retry once.
  fn bounded_insert(&mut self, entry: CacheEntry<I>) -> Result<usize, P::Error> {
    // Step 1: proactive eviction when at or above the cap.
    if self.entries.len() >= self.max_entries {
      let mut victim: Option<(usize, I)> = None;
      for (key, e) in self.entries.iter() {
        let exp = e.expires_at();
        if !matches!(victim, Some((_, prev_exp)) if prev_exp <= exp) {
          victim = Some((key, exp));
        }
      }
      if let Some((vk, _)) = victim {
        self.entries.try_remove(vk);
      }
    }

    // Step 2: attempt insert.
    match self.entries.insert(entry.clone()) {
      Ok(k) => Ok(k),
      Err(_) => {
        // Step 3: reactive eviction + single retry.
        let mut victim: Option<(usize, I)> = None;
        for (key, e) in self.entries.iter() {
          let exp = e.expires_at();
          if !matches!(victim, Some((_, prev_exp)) if prev_exp <= exp) {
            victim = Some((key, exp));
          }
        }
        if let Some((vk, _)) = victim {
          self.entries.try_remove(vk);
        }
        self.entries.insert(entry)
      }
    }
  }

  /// Sweep expired entries, returning how many were removed.
  pub fn sweep_expired(&mut self, now: I) -> usize {
    let mut to_remove: std::vec::Vec<usize> = std::vec::Vec::new();
    for (key, entry) in self.entries.iter() {
      if entry.expires_at() <= now {
        to_remove.push(key);
      }
    }
    let mut removed = 0usize;
    for key in to_remove {
      if self.entries.try_remove(key).is_some() {
        removed = removed.saturating_add(1);
      }
    }
    removed
  }

  /// Next deadline (soonest expiration), if any.
  pub fn next_expiration(&self) -> Option<I> {
    let mut best: Option<I> = None;
    for (_, entry) in self.entries.iter() {
      let exp = entry.expires_at();
      best = Some(match best {
        Some(prev) if prev < exp => prev,
        _ => exp,
      });
    }
    best
  }

  /// Look up whether the cache contains a record matching
  /// `(name, rtype, rclass)`.  class is part of the cache key.
  pub fn contains(&self, name: &Name, rtype: ResourceType, rclass: ResourceClass) -> bool {
    self.entries.iter().any(|(_, e)| {
      e.rtype() == rtype && e.rclass() == rclass && e.name().as_str() == name.as_str()
    })
  }

  /// Count the number of cached entries matching `(name, rtype, rclass)`.
  ///
  /// Multiple distinct records can share `(name, rtype, rclass)` (e.g. a
  /// multi-homed host with several A records), so a single `contains`
  /// check cannot tell you whether the full RRSet landed.  Use this for
  /// RRSet-coherency checks.
  pub fn count_matching(&self, name: &Name, rtype: ResourceType, rclass: ResourceClass) -> usize {
    self
      .entries
      .iter()
      .filter(|(_, e)| {
        e.rtype() == rtype && e.rclass() == rclass && e.name().as_str() == name.as_str()
      })
      .count()
  }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<I, P> Default for Cache<I, P>
where
  I: Instant,
  P: Pool<CacheEntry<I>>,
{
  fn default() -> Self {
    Self::new()
  }
}

// Gated to `std` (not `any(alloc, std)`): these tests drive the cache against
// the REAL `std::time::Instant` clock (`Instant::now()`), which is std-only
// (no-std golden rule §4). The cache logic is generic over `I: Instant` and is
// type-checked in the alloc tier by the library build; only this clock-backed
// coverage needs `std`. `Duration` stays `core::time::Duration` (core-first).
#[cfg(all(test, feature = "std", feature = "slab"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
  use super::*;
  use core::time::Duration;
  use std::time::Instant;

  fn make_entry(
    name: &str,
    rtype: ResourceType,
    rdata: u8,
    ttl_secs: u64,
  ) -> (Name, ResourceType, std::vec::Vec<u8>, Duration) {
    (
      Name::try_from_str(name).unwrap(),
      rtype,
      std::vec![rdata],
      Duration::from_secs(ttl_secs),
    )
  }

  #[test]
  fn cache_evicts_on_max_entries() {
    let mut cache: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::with_max_entries(4);

    let now = Instant::now();
    // Insert 5 entries; each has a distinct name, rtype, and rdata.
    for i in 0u8..5 {
      let name = std::format!("entry{}.local.", i);
      let (n, rt, rd, ttl) = make_entry(&name, ResourceType::A, i, 30);
      cache
        .try_insert(n, rt, ResourceClass::In, rd, ttl, now, false)
        .unwrap();
    }

    assert!(
      cache.entries.len() <= 4,
      "expected at most 4 entries after 5 inserts with max_entries=4, got {}",
      cache.entries.len()
    );
  }

  #[test]
  fn max_entries_accessor_and_default_cap() {
    let custom: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::with_max_entries(9);
    assert_eq!(custom.max_entries(), 9);
    let default: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::default();
    assert_eq!(default.max_entries(), DEFAULT_MAX_ENTRIES);
  }

  #[test]
  fn cache_flush_insert_walks_siblings_and_inserts_fresh() {
    let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::new();
    let now = Instant::now();
    let name = "host.local.";
    // An existing A record for the name.
    let (n, rt, rd, ttl) = make_entry(name, ResourceType::A, 1, 120);
    c.try_insert(n, rt, ResourceClass::In, rd, ttl, now, false)
      .unwrap();
    // A cache-flush insert of a DIFFERENT rdata for the same (name, rtype,
    // rclass) walks the just-inserted sibling (recent -> not clamped) then
    // inserts itself fresh, so both records coexist for the grace window.
    let (n2, rt2, rd2, ttl2) = make_entry(name, ResourceType::A, 2, 120);
    c.try_insert(n2, rt2, ResourceClass::In, rd2, ttl2, now, true)
      .unwrap();
    assert_eq!(
      c.count_matching(
        &Name::try_from_str(name).unwrap(),
        ResourceType::A,
        ResourceClass::In
      ),
      2
    );
  }

  /// a TTL=0 goodbye (RFC 6762 §10.1) must NOT delete immediately —
  /// it clamps the entry to a 1-second rescue window.
  #[test]
  fn ttl_zero_goodbye_clamps_to_one_second_not_immediate_delete() {
    let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::new();
    let (n, rt, rd, ttl) = make_entry("host.local.", ResourceType::A, 7, 120);
    let now = Instant::now();
    c.try_insert(
      n.clone(),
      rt,
      ResourceClass::In,
      rd.clone(),
      ttl,
      now,
      false,
    )
    .unwrap();
    assert!(c.contains(&n, rt, ResourceClass::In));

    // Goodbye: clamps, does not delete.
    c.try_insert(
      n.clone(),
      rt,
      ResourceClass::In,
      rd.clone(),
      Duration::ZERO,
      now,
      false,
    )
    .unwrap();
    c.sweep_expired(now);
    assert!(
      c.contains(&n, rt, ResourceClass::In),
      "TTL=0 must NOT delete immediately (§10.1 rescue window)"
    );
    // After the ~1s window it expires.
    c.sweep_expired(now + Duration::from_secs(2));
    assert!(
      !c.contains(&n, rt, ResourceClass::In),
      "the clamped entry must expire ~1s after the goodbye"
    );
  }

  /// a positive re-announce within the rescue window restores the
  /// record's normal TTL (another responder still using it rescues it).
  #[test]
  fn ttl_zero_goodbye_can_be_rescued_by_reannounce() {
    let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::new();
    let (n, rt, rd, ttl) = make_entry("host.local.", ResourceType::A, 7, 120);
    let now = Instant::now();
    c.try_insert(
      n.clone(),
      rt,
      ResourceClass::In,
      rd.clone(),
      ttl,
      now,
      false,
    )
    .unwrap();
    // Goodbye clamps to ~1s.
    c.try_insert(
      n.clone(),
      rt,
      ResourceClass::In,
      rd.clone(),
      Duration::ZERO,
      now,
      false,
    )
    .unwrap();
    // A positive re-announce within the window refreshes the full TTL.
    c.try_insert(
      n.clone(),
      rt,
      ResourceClass::In,
      rd.clone(),
      ttl,
      now,
      false,
    )
    .unwrap();
    c.sweep_expired(now + Duration::from_secs(5));
    assert!(
      c.contains(&n, rt, ResourceClass::In),
      "a re-announce within the rescue window must restore the record"
    );
  }

  // ── cache-flush eviction ────────────────────────────────────

  /// RFC 6762 §10.2: when a record is received with the cache-flush bit set,
  /// existing cache entries for the same (name, rtype) MORE THAN 1 SECOND
  /// OLD must be evicted before inserting the new record.  Records received
  /// within the last second are protected by the §10.2 grace window.
  /// Only the flush record and very-recent siblings survive.
  #[test]
  fn cache_flush_evicts_existing_entries_for_same_name_rtype() {
    let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::new();
    let name = Name::try_from_str("host.local.").unwrap();
    let now = Instant::now();
    let ttl = Duration::from_secs(120);

    // Insert two non-flush A records with distinct rdata.
    c.try_insert(
      name.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 1],
      ttl,
      now,
      false,
    )
    .unwrap();
    c.try_insert(
      name.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 2],
      ttl,
      now,
      false,
    )
    .unwrap();
    assert_eq!(c.entries.len(), 2, "expected 2 entries before flush");

    // Advance the clock past the §10.2 grace window so the prior entries
    // are eligible for the deferred-expiry clamp.
    let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();

    // Insert with cache_flush=true — prior entries' expires_at is
    // CLAMPED to `after_grace + 1s`.  New record inserted.
    c.try_insert(
      name.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 99],
      ttl,
      after_grace,
      true,
    )
    .unwrap();

    // Sweep at `after_grace + 2s` (past the clamped expiry) to drop the
    // clamped siblings.  Only the flushed record survives.
    let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
    c.sweep_expired(after_clamp);

    assert_eq!(
      c.entries.len(),
      1,
      "cache_flush=true after §10.2 grace + sweep must leave exactly 1 entry"
    );
    // The surviving entry must be the newly inserted rdata.
    let surviving = c
      .entries
      .iter()
      .next()
      .map(|(_, e)| e.rdata_slice().to_vec());
    assert_eq!(
      surviving,
      Some(std::vec![10, 0, 0, 99]),
      "surviving rdata must be the cache-flush record"
    );
  }

  /// cache_flush=true must NOT evict entries for a different rtype,
  /// even when the name matches.
  #[test]
  fn cache_flush_does_not_evict_different_rtype() {
    let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::new();
    let name = Name::try_from_str("host.local.").unwrap();
    let now = Instant::now();
    let ttl = Duration::from_secs(120);

    // An AAAA record and an A record share the same name.
    c.try_insert(
      name.clone(),
      ResourceType::AAAA,
      ResourceClass::In,
      std::vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
      ttl,
      now,
      false,
    )
    .unwrap();

    // Flush only the A records.
    c.try_insert(
      name.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 1],
      ttl,
      now,
      true,
    )
    .unwrap();

    // AAAA must still be present; A is the only entry for that rtype.
    assert_eq!(
      c.entries.len(),
      2,
      "cache_flush for A must not evict the AAAA entry"
    );
    assert!(
      c.contains(&name, ResourceType::AAAA, ResourceClass::In),
      "AAAA entry must survive a cache_flush targeting A"
    );
    assert!(
      c.contains(&name, ResourceType::A, ResourceClass::In),
      "A entry (flush record) must be present"
    );
  }

  // ── cache_flush insert respects max_entries ──────────────────

  /// A cache_flush insert into a full cache must NOT grow past `max_entries`.
  ///
  /// Previously the cache_flush path called `self.entries.insert(...)` directly,
  /// bypassing the proactive eviction that the non-flush path performed.  This meant
  /// a cache_flush record with a new `(name, rtype)` could silently expand the
  /// cache beyond the configured cap.
  #[test]
  fn cache_flush_respects_max_entries() {
    let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::with_max_entries(3);
    let now = Instant::now();
    let ttl = Duration::from_secs(120);

    // Fill the cache to max_entries (3 entries, each distinct (name, rtype)).
    c.try_insert(
      Name::try_from_str("a.local.").unwrap(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![1],
      ttl,
      now,
      false,
    )
    .unwrap();
    c.try_insert(
      Name::try_from_str("b.local.").unwrap(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![2],
      ttl,
      now,
      false,
    )
    .unwrap();
    c.try_insert(
      Name::try_from_str("c.local.").unwrap(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![3],
      ttl,
      now,
      false,
    )
    .unwrap();
    assert_eq!(c.entries.len(), 3, "cache must be full before flush test");

    // A cache_flush insert with a NEW name must NOT grow past max_entries.
    c.try_insert(
      Name::try_from_str("d.local.").unwrap(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![4],
      ttl,
      now,
      true, // cache_flush=true
    )
    .unwrap();

    let count = c.entries.len();
    assert!(
      count <= 3,
      "cache must not grow past max_entries=3 after cache_flush insert; got {count}"
    );
  }

  // ── max_entries == 0 short-circuits insertion ────────────────

  /// A cache built with `max_entries == 0` must never accept inserts via either
  /// the regular path or the cache_flush path.  Both must return `Ok(None)`
  /// and leave the cache empty.
  #[test]
  fn zero_cap_cache_rejects_inserts() {
    let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::with_max_entries(0);
    let now = Instant::now();
    let ttl = Duration::from_secs(120);

    // Non-flush insert into a zero-cap cache.
    let key = c
      .try_insert(
        Name::try_from_str("a.local.").unwrap(),
        ResourceType::A,
        ResourceClass::In,
        std::vec![1],
        ttl,
        now,
        false,
      )
      .unwrap();
    assert!(
      key.is_none(),
      "zero-cap cache must return Ok(None) on regular insert"
    );
    assert_eq!(c.entries.len(), 0);

    // cache_flush insert into a zero-cap cache (RFC 6762 §10.2).
    let key = c
      .try_insert(
        Name::try_from_str("b.local.").unwrap(),
        ResourceType::A,
        ResourceClass::In,
        std::vec![2],
        ttl,
        now,
        true,
      )
      .unwrap();
    assert!(
      key.is_none(),
      "zero-cap cache must return Ok(None) on cache_flush insert"
    );
    assert_eq!(
      c.entries.len(),
      0,
      "zero-cap cache must remain empty after cache_flush insert"
    );
  }
}

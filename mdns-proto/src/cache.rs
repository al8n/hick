//! Passive record cache observed from incoming traffic.

use core::time::Duration;

use crate::{
  Instant, Name, Pool,
  backend::RdataBuf,
  trace::*,
  wire::{ResourceClass, ResourceType},
};

/// One cached resource record.

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
  rdata: RdataBuf,
  expires_at: I,
  /// When this record was last received / refreshed.  used to
  /// implement the RFC 6762 §10.2 "1-second grace" on cache-flush —
  /// an incoming cache-flush only affects siblings whose
  /// `now - received_at >= 1 second`, so a multi-address RRSet
  /// announced across two back-to-back packets is not collapsed.
  received_at: I,
}

impl<I: Instant> CacheEntry<I> {
  /// Build a new cache entry.  `received_at` is the wall instant at
  /// which this record arrived; `expires_at` is the TTL-derived
  /// future deadline.
  pub(crate) fn new(
    name: Name,
    rtype: ResourceType,
    rclass: ResourceClass,
    rdata: RdataBuf,
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
    self.rdata.as_ref()
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
const DEFAULT_MAX_ENTRIES: usize = 1024;

/// Passive record cache.
pub struct Cache<I, P> {
  entries: P,
  max_entries: usize,
  _phantom: core::marker::PhantomData<I>,
  #[cfg(feature = "stats")]
  stats: Option<std::sync::Arc<hick_trace::stats::Stats>>,
}

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
      #[cfg(feature = "stats")]
      stats: None,
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
      #[cfg(feature = "stats")]
      stats: None,
    }
  }

  /// Attach the shared [`hick_trace::stats::Stats`] handle from the owning
  /// [`crate::endpoint::Endpoint`]. No allocation — the Arc is cloned from the
  /// endpoint's existing single Arc. Called immediately after construction by
  /// the `Endpoint` so that all per-cache counters accumulate into the
  /// endpoint-level stats. Before this is called, stats bumps are no-ops
  /// (the field is `None`).
  #[cfg(feature = "stats")]
  pub(crate) fn set_stats(&mut self, stats: std::sync::Arc<hick_trace::stats::Stats>) {
    self.stats = Some(stats);
  }

  /// Borrow the stats handle if one has been attached.
  #[cfg(feature = "stats")]
  #[inline]
  fn stat(&self) -> Option<&hick_trace::stats::Stats> {
    self.stats.as_deref()
  }

  /// The configured maximum number of entries.
  #[inline(always)]
  pub const fn max_entries(&self) -> usize {
    self.max_entries
  }

  /// The current number of cached entries.
  #[inline(always)]
  pub fn len(&self) -> usize {
    self.entries.len()
  }

  /// Whether the cache is empty.
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.entries.len() == 0
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
    rdata: impl Into<RdataBuf>,
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
    let rdata: RdataBuf = rdata.into();
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
            && entry.rdata_slice() == rdata.as_ref()
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
          if recent || entry.rdata_slice() == rdata.as_ref() {
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
        && entry.rdata_slice() == rdata.as_ref()
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
      trace!(
        target: "mdns_proto::cache",
        rtype = ?rtype,
        "cache: refreshed existing entry (dedup)"
      );
      #[cfg(feature = "stats")]
      if let Some(s) = self.stat() {
        s.cache_refreshes(1);
        s.set_cache_size(self.entries.len() as u64);
      }
      return Ok(Some(key));
    }

    // Insert through the bounded helper (proactive cap eviction + reactive retry).
    let result = self
      .bounded_insert(CacheEntry::new(name, rtype, rclass, rdata, expires_at, now))
      .map(Some);
    if result.is_ok() {
      trace!(
        target: "mdns_proto::cache",
        rtype = ?rtype,
        "cache: inserted new entry"
      );
      #[cfg(feature = "stats")]
      if let Some(s) = self.stat() {
        s.cache_inserts(1);
        s.set_cache_size(self.entries.len() as u64);
      }
    }
    result
  }

  /// Insert `entry` into the backing pool while respecting `max_entries`.
  ///
  /// Algorithm:
  /// 1. Proactive eviction: if the pool is at or above `max_entries`, evict the
  ///    soonest-expiring entry BEFORE attempting the insert.  This bounds memory
  ///    usage even when the backing pool is infallible (e.g. `slab::Slab`).
  /// 2. Attempt the insert.
  /// 3. Reactive eviction + retry: if the pool returns a capacity error (e.g.
  ///    a fixed-capacity fallible pool), evict the soonest-expiring entry
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
        trace!(
          target: "mdns_proto::cache",
          "cache: proactive eviction (cap reached)"
        );
        #[cfg(feature = "stats")]
        if let Some(s) = self.stat() {
          s.cache_evictions(1);
        }
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
          trace!(
            target: "mdns_proto::cache",
            "cache: reactive eviction (pool capacity error)"
          );
          #[cfg(feature = "stats")]
          if let Some(s) = self.stat() {
            s.cache_evictions(1);
          }
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
    if removed > 0 {
      trace!(
        target: "mdns_proto::cache",
        removed,
        "cache: swept expired entries"
      );
      #[cfg(feature = "stats")]
      if let Some(s) = self.stat() {
        #[allow(clippy::cast_possible_truncation)]
        s.cache_expirations(removed as u64);
        s.set_cache_size(self.entries.len() as u64);
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

impl<I, P> Default for Cache<I, P>
where
  I: Instant,
  P: Pool<CacheEntry<I>>,
{
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(all(test, feature = "std", feature = "slab"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

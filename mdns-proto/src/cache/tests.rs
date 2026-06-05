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
fn len_and_is_empty_track_entry_count() {
  let mut cache: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::new();
  assert!(cache.is_empty());
  assert_eq!(cache.len(), 0);

  let now = Instant::now();
  let (n, rt, rd, ttl) = make_entry("len.local.", ResourceType::A, 1, 30);
  cache
    .try_insert(n, rt, ResourceClass::In, rd, ttl, now, false)
    .unwrap();

  assert!(!cache.is_empty());
  assert_eq!(cache.len(), 1);
}

#[cfg(feature = "stats")]
#[test]
fn cache_insert_and_eviction_bump_stats() {
  use std::sync::Arc;
  let mut cache: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::with_max_entries(2);
  cache.set_stats(Arc::new(hick_trace::stats::Stats::default()));

  let now = Instant::now();
  // Insert past the cap: every insert updates the cache-size gauge, and the
  // over-cap inserts force a proactive eviction (both stats paths).
  for i in 0u8..4 {
    let (n, rt, rd, ttl) = make_entry(&std::format!("e{}.local.", i), ResourceType::A, i, 30);
    cache
      .try_insert(n, rt, ResourceClass::In, rd, ttl, now, false)
      .unwrap();
  }
  assert!(cache.len() <= 2);
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

// ── TTL=0 goodbye: no matching entry / sooner-expiry no-op ────

/// A TTL=0 goodbye (RFC 6762 §10.1) for a record that is NOT in the cache
/// must be a harmless no-op: the goodbye walks the entries, finds no
/// matching `(name, rtype, rclass, rdata)` victim, and returns `Ok(None)`
/// without inserting or mutating anything.  This drives the
/// "victim stays `None`" path of the goodbye-clamp guard.
#[test]
fn ttl_zero_goodbye_for_absent_record_is_noop() {
  let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::new();
  let now = Instant::now();

  // Cache holds an unrelated record.
  let (n, rt, rd, ttl) = make_entry("present.local.", ResourceType::A, 1, 120);
  c.try_insert(n, rt, ResourceClass::In, rd, ttl, now, false)
    .unwrap();
  assert_eq!(c.entries.len(), 1);

  // Goodbye for a DIFFERENT name that the cache has never seen.
  let absent = Name::try_from_str("absent.local.").unwrap();
  let key = c
    .try_insert(
      absent.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![9],
      Duration::ZERO,
      now,
      false,
    )
    .unwrap();
  assert!(key.is_none(), "TTL=0 goodbye must return Ok(None)");
  assert_eq!(
    c.entries.len(),
    1,
    "a goodbye for an absent record must not insert or remove anything"
  );
  assert!(
    !c.contains(&absent, ResourceType::A, ResourceClass::In),
    "the absent record must remain absent after its goodbye"
  );
}

/// A TTL=0 goodbye must only ever SHORTEN an entry's deadline, never push it
/// out.  When the matching entry already expires at or before the 1-second
/// rescue deadline (`now + 1s`), the `expires_at() > deadline` guard is false
/// and the entry is left exactly as-is.  This drives the guard's false branch
/// and asserts the no-extension invariant.
#[test]
fn ttl_zero_goodbye_does_not_extend_a_sooner_expiry() {
  let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::new();
  let now = Instant::now();

  // Insert with a 1-second TTL: expires_at == now + 1s, exactly the goodbye
  // rescue deadline, so `expires_at() > deadline` is false.
  let (n, rt, rd, ttl) = make_entry("brief.local.", ResourceType::A, 1, 1);
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
  let before = c
    .entries
    .iter()
    .next()
    .map(|(_, e)| e.expires_at())
    .unwrap();

  // Goodbye for the same record. The clamp would set expires_at to now + 1s,
  // but the existing deadline is already now + 1s, so nothing changes.
  c.try_insert(n, rt, ResourceClass::In, rd, Duration::ZERO, now, false)
    .unwrap();
  let after = c
    .entries
    .iter()
    .next()
    .map(|(_, e)| e.expires_at())
    .unwrap();
  assert_eq!(
    before, after,
    "a goodbye must never push a sooner-or-equal expiry further out"
  );
}

// ── cache-flush §10.2 grace: future received_at counts as recent ──

/// RFC 6762 §10.2 grace skips siblings received within the last second.  A
/// sibling whose `received_at` is in the FUTURE relative to the flush's `now`
/// (e.g. clock instants arriving out of order) yields `None` from
/// `checked_duration_since` and must be treated as "recent" — i.e. left
/// untouched, not clamped.  This drives the `None => true` grace arm.
#[test]
fn cache_flush_grace_treats_future_received_at_as_recent() {
  let mut c: Cache<Instant, slab::Slab<CacheEntry<Instant>>> = Cache::new();
  let base = Instant::now();
  let ttl = Duration::from_secs(120);
  let name = Name::try_from_str("host.local.").unwrap();

  // Sibling A record received at a FUTURE instant relative to the flush below.
  let future = base.checked_add(Duration::from_secs(10)).unwrap();
  c.try_insert(
    name.clone(),
    ResourceType::A,
    ResourceClass::In,
    std::vec![10, 0, 0, 1],
    ttl,
    future,
    false,
  )
  .unwrap();

  // Cache-flush a DIFFERENT rdata at the earlier `base` instant. The existing
  // sibling's received_at (future) is newer than `base`, so the grace check
  // sees it as recent and does NOT clamp it.
  c.try_insert(
    name.clone(),
    ResourceType::A,
    ResourceClass::In,
    std::vec![10, 0, 0, 2],
    ttl,
    base,
    true,
  )
  .unwrap();

  // The future-received sibling keeps its full TTL: a sweep at base + 5s (well
  // past a hypothetical base + 1s clamp) must NOT drop it.
  c.sweep_expired(base.checked_add(Duration::from_secs(5)).unwrap());
  assert_eq!(
    c.count_matching(&name, ResourceType::A, ResourceClass::In),
    2,
    "a future-received sibling must be treated as recent (no §10.2 clamp)"
  );
}

// ── reactive eviction: fallible pool capacity error + retry ──

/// When the backing [`Pool`] is fixed-capacity and FALLIBLE (here a
/// `heapless::Vec`, whose `insert` returns `Err` once full), an insert that
/// overflows the pool must trigger `bounded_insert`'s reactive eviction:
/// evict the soonest-expiring entry, then retry the insert once (which now
/// succeeds).
///
/// `max_entries` is set ABOVE the pool's fixed capacity so the proactive
/// `len >= max_entries` eviction (Step 1) never fires — the only thing that
/// can make room is the reactive Step 3 driven by the pool's capacity error.
#[cfg(feature = "heapless")]
#[test]
fn fallible_pool_capacity_error_triggers_reactive_eviction() {
  // Fixed capacity 2; cap deliberately higher so proactive eviction is inert.
  let mut c: Cache<Instant, heapless::Vec<Option<CacheEntry<Instant>>, 2>> =
    Cache::with_max_entries(100);
  // Attach stats so the reactive-eviction counter bump is exercised too.
  #[cfg(feature = "stats")]
  c.set_stats(std::sync::Arc::new(hick_trace::stats::Stats::default()));
  let now = Instant::now();
  let name = Name::try_from_str("host.local.").unwrap();

  // Entry A: soonest expiry (10s) — this is the reactive-eviction victim.
  c.try_insert(
    name.clone(),
    ResourceType::A,
    ResourceClass::In,
    std::vec![10, 0, 0, 1],
    Duration::from_secs(10),
    now,
    false,
  )
  .unwrap();
  // Entry B: later expiry (300s) — must survive.
  c.try_insert(
    name.clone(),
    ResourceType::A,
    ResourceClass::In,
    std::vec![10, 0, 0, 2],
    Duration::from_secs(300),
    now,
    false,
  )
  .unwrap();
  assert_eq!(c.len(), 2, "pool is now at its fixed capacity of 2");

  // Entry C: a third distinct record. The pool is full, so the underlying
  // `insert` returns Err and reactive eviction kicks in: the soonest-expiring
  // entry (A) is evicted, then C is inserted on retry.
  let key = c
    .try_insert(
      name.clone(),
      ResourceType::A,
      ResourceClass::In,
      std::vec![10, 0, 0, 3],
      Duration::from_secs(300),
      now,
      false,
    )
    .unwrap();
  assert!(
    key.is_some(),
    "reactive eviction + retry must insert the new entry successfully"
  );
  assert_eq!(c.len(), 2, "cache must stay at the pool's fixed capacity");

  // A (the soonest-expiring victim) was evicted; B and C remain.
  let surviving: std::vec::Vec<std::vec::Vec<u8>> = c
    .entries
    .iter()
    .map(|(_, e)| e.rdata_slice().to_vec())
    .collect();
  assert!(
    !surviving.contains(&std::vec![10, 0, 0, 1]),
    "the soonest-expiring entry must be the reactive-eviction victim"
  );
  assert!(
    surviving.contains(&std::vec![10, 0, 0, 2]),
    "the later-expiring sibling must survive reactive eviction"
  );
  assert!(
    surviving.contains(&std::vec![10, 0, 0, 3]),
    "the newly inserted entry must be present after the retry"
  );
}

//! The single event queue every driver-produced signal surfaces through.
//!
//! `hick-mio` has no async, no channels, and no per-handle mailboxes — unlike
//! `hick-reactor`. Every service lifecycle update, query answer, and query
//! terminal — and every lookup result — is delivered through the ONE
//! [`EventQueue`] backing `Mdns::next_event()`. A single drain point is what
//! makes terminals impossible to miss: they arrive whether or not the caller
//! is still tracking the handle they belong to.
//!
//! The delivery contract is deliberately asymmetric: answers are lossy and
//! coalesced under backpressure, but terminals are never dropped. A flooding
//! peer can grow only the bounded, coalescing answer set — it can never push
//! a `Conflict` or `Timeout` out of the queue.

use std::collections::{HashMap, VecDeque};

use mdns_proto::{
  CollectedAnswer, QueryHandle, QueryUpdate, ServiceHandle, ServiceUpdate,
  wire::{ResourceClass, ResourceType},
};

use crate::discovery::{LookupHandle, ServiceEntry};

/// Something the driver has produced for the caller to observe.
///
/// Delivered one at a time from `EventQueue::pop`, which backs
/// `Mdns::next_event()` — the single queue shared by every registered
/// service, running query, and active lookup.
///
/// `#[non_exhaustive]`: a match must include a wildcard arm, so a later variant
/// is not a breaking change for code written against this one.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
  /// A registered service's lifecycle advanced — established, renamed during
  /// conflict resolution, or a conflict the caller must resolve.
  ///
  /// Delivered via `EventQueue::push_terminal`: never dropped or coalesced.
  /// A single service can produce more than one of these over its lifetime
  /// (e.g. `Established` and later `Conflict`), so unlike
  /// [`Self::QueryTerminal`] this is not necessarily the last event for its
  /// handle.
  Service {
    /// The service this update is about.
    handle: ServiceHandle,
    /// What changed.
    update: ServiceUpdate,
  },
  /// A running query collected a new answer record.
  ///
  /// **Lossy under sustained backpressure.** If the caller drains events
  /// slower than matching answers arrive, the oldest queued answer sharing
  /// the same query, resource type/class, and case-folded rdata identity is
  /// evicted once the shared answer backlog fills (see
  /// `EventQueue::dropped`). mDNS discovery is eventually consistent —
  /// responders re-advertise — so a dropped answer is normally re-collected,
  /// but a caller must not assume this stream is gap-free.
  QueryAnswer {
    /// The query this answer belongs to.
    handle: QueryHandle,
    /// The collected answer record.
    answer: CollectedAnswer,
  },
  /// A running query reached a terminal state (timed out, or done).
  ///
  /// Delivered via `EventQueue::push_terminal`: always appended and never
  /// dropped, even when the answer backlog is completely full — unlike
  /// [`Self::QueryAnswer`], a flooding peer can never push this out of the
  /// queue. Delivered at most once per query.
  ///
  /// Only ever reported for a query the caller started through
  /// [`Mdns::start_query`](crate::Mdns::start_query). A lookup's sub-queries are
  /// consumed by the lookup itself and never surface here.
  QueryTerminal {
    /// The query that terminated.
    handle: QueryHandle,
    /// How it terminated.
    update: QueryUpdate,
  },
  /// A lookup resolved a service instance.
  ///
  /// Delivered via `EventQueue::push_terminal`: never dropped or coalesced,
  /// because it is the *product* of a lookup's sub-query answers rather than an
  /// answer itself. An instance is reported at most once per lookup, and every
  /// [`Self::Lookup`] for a handle precedes that handle's
  /// [`Self::LookupDone`].
  Lookup {
    /// The lookup that resolved it.
    handle: LookupHandle,
    /// The resolved instance.
    entry: ServiceEntry,
  },
  /// A lookup finished: its deadline came due, its entry cap was reached, or
  /// every sub-query it started has terminated.
  ///
  /// Delivered via `EventQueue::push_terminal`, exactly once per lookup, and
  /// always last for its handle. Not produced for a lookup the caller stopped
  /// with [`Mdns::cancel_lookup`](crate::Mdns::cancel_lookup).
  LookupDone {
    /// The lookup that finished.
    handle: LookupHandle,
  },
}

/// The identity `EventQueue::push_answer` coalesces on: `(handle, rtype,
/// rclass, rdata_key)` — the CASE-FOLDED identity of the rdata
/// ([`CollectedAnswer::rdata_key`]), not its display-case bytes, so two
/// announcements of the same PTR/SRV/CNAME record differing only in DNS-name
/// case still coalesce instead of counting as distinct keys — mirroring
/// `hick-reactor`'s `QueryMailbox::push_answer` (`hick-reactor/src/query.rs:92`).
/// Keying on the handle — not just the record — is what lets two independent
/// queries that each collect the identical record surface it twice instead of
/// one silently absorbing the other's answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AnswerKey {
  handle: QueryHandle,
  rtype: ResourceType,
  rclass: ResourceClass,
  rdata_key: Vec<u8>,
}

/// One physically-queued item, in the order [`EventQueue::pop`] delivers it.
///
/// An `Answer` slot is a lightweight `(key, generation)` pair into
/// `EventQueue::live`: the actual [`CollectedAnswer`] payload lives in that
/// map so a coalescing update (same key, new content) can replace it in O(1)
/// without moving this slot — coalescing must not change an answer's
/// position in delivery order, and leaves its `generation` unchanged too.
///
/// `generation` is what makes a key's occurrences across time
/// distinguishable: if `key` is evicted and later genuinely re-collected
/// before THIS slot is reached, `EventQueue::live` comes to hold a NEWER
/// generation for the same key (the re-collection's own, later slot). Without
/// the generation tag, [`EventQueue::pop`] would have no way to tell this
/// stale slot apart from the live one — mistaking it for the current
/// occurrence, which is exactly the bug this tag exists to rule out (see
/// [`EventQueue`]'s `# Invariant` section). A `Terminal` slot carries its
/// event inline and is never coalesced, evicted, or made stale.
#[derive(Debug)]
enum Slot {
  /// A coalescing-eligible answer at a specific generation; the payload
  /// lives in `EventQueue::live`.
  Answer(AnswerKey, u64),
  /// Any other event, queued verbatim by `EventQueue::push_terminal`.
  Terminal(Event),
}

/// The current payload for a live answer key, tagged with the generation its
/// owning [`Slot::Answer`] was queued under.
///
/// The generation is how [`EventQueue::pop`] recognises that a queued
/// `Slot::Answer(key, generation)` is still the authoritative occurrence of
/// `key`, as opposed to a stale duplicate left behind by an earlier eviction
/// that a later, genuine re-collection has since superseded.
#[derive(Debug)]
struct LiveAnswer {
  generation: u64,
  answer: CollectedAnswer,
}

/// Bounded, coalescing FIFO backing `Mdns::next_event()` — the ONE queue
/// shared by every registered service, running query, and active lookup.
///
/// Answers are bounded by [`Self::ANSWER_CAPACITY`] and coalesced by
/// `(handle, rtype, rclass, rdata_key)` (see [`AnswerKey`]): the same logical
/// record re-collected by the SAME query replaces its queued copy in place
/// instead of accumulating, so a peer that keeps re-advertising cannot grow
/// the queue. Once the live answer count is at capacity, a genuinely new
/// record evicts the OLDEST live answer (never a terminal) and increments
/// [`Self::dropped`]. Every other event — [`Event::Service`],
/// [`Event::QueryTerminal`], [`Event::Lookup`] and [`Event::LookupDone`] — is
/// queued via [`Self::push_terminal`], which always appends and is
/// never coalesced or evicted.
///
/// # Invariant
///
/// `live` and `order` always hold EXACTLY the same set of keys, and each key
/// appears in `order` at most once. Every mutation maintains this together,
/// never touching one side alone:
/// * a coalescing push (key already in `live`) touches neither `live`'s
///   membership nor `order` — only the stored [`CollectedAnswer`] changes,
///   in place, under the SAME generation;
/// * a capacity eviction removes the SAME key from both: `order.pop_front()`
///   names it, `live.remove` drops it, together, in the same call;
/// * a new-key push (first time, or after an earlier eviction) inserts the
///   SAME key into both, under a freshly minted [`Slot::Answer`] generation
///   ([`Self::next_generation`]);
/// * [`Self::pop`] removes the SAME key from both, but ONLY when the popped
///   slot's generation matches `live`'s CURRENT generation for that key — a
///   mismatched generation (the key was evicted and later genuinely
///   re-collected under this exact key before this stale slot was reached)
///   or an absent one (evicted, never re-collected) means the slot is
///   stale, and neither structure is touched.
///
/// Because `order`'s membership always equals `live`'s, a capacity eviction
/// can never find `order` unexpectedly empty while `live` is not (so `live`
/// can never grow past [`Self::ANSWER_CAPACITY`], and eviction can never
/// permanently stop working). Because [`Self::pop`] only ever resolves a key
/// under its CURRENT generation, `order`'s front is always exactly the key
/// the next successful match in `queue` belongs to — so a re-collection
/// racing its own eviction is delivered at the position it actually arrived,
/// never at the position of the stale occurrence it superseded. This holds
/// under any interleaving of `push_answer`/`push_terminal`/`pop`, not only
/// the full-drain-between-bursts usage the original tests happened to cover.
pub(crate) struct EventQueue {
  /// Every queued item, in true arrival order. `Slot::Answer` entries may be
  /// stale duplicates (see [`Slot`]); `pop` skips those transparently.
  queue: VecDeque<Slot>,
  /// Current payload (and generation) for each still-live (not yet delivered
  /// or evicted) answer key. The source of truth for "is this key still
  /// queued, and under which generation".
  live: HashMap<AnswerKey, LiveAnswer>,
  /// Live answer keys in FIFO order. See the type-level `# Invariant`: kept
  /// in lockstep with `live` (identical membership, at all times) by
  /// construction, which is what makes eviction O(1) —
  /// `order.pop_front()` always names the oldest still-live answer —
  /// without scanning `queue`.
  order: VecDeque<AnswerKey>,
  /// Count of answers evicted (never coalesced, never a terminal) because
  /// the live set was at [`Self::ANSWER_CAPACITY`] when a genuinely new
  /// record arrived.
  dropped: u64,
  /// Number of events currently queued for delivery: live answers plus
  /// terminals not yet popped. Tracked directly at each mutation point rather
  /// than derived from `queue.len()`, which also counts stale slots still
  /// awaiting their lazy skip in `pop`.
  len: usize,
  /// Source of the generation tag minted for each NEW (non-coalescing)
  /// [`Slot::Answer`], so any two occurrences of the same key are
  /// distinguishable — see [`Slot`]'s doc and this type's `# Invariant`.
  ///
  /// Advanced with `wrapping_add`, matching `Lookups::next_generation`
  /// (`crate::discovery`) and for the same reason: saturating would give every
  /// answer minted after the counter tops out one shared generation, so a
  /// key's stale slot would match its own later re-collection and be delivered
  /// as the live one — reinstating exactly the aliasing this tag rules out.
  /// Wrapping instead needs the same key re-collected 2^64 generations later
  /// while its original slot is still physically queued, and at most
  /// [`Self::ANSWER_CAPACITY`] answers are ever live at once.
  next_generation: u64,
}

impl EventQueue {
  /// Upper bound on live (queued, undelivered) answers across every query,
  /// service, and lookup sharing this ONE queue.
  ///
  /// The same value as `hick-reactor`'s `MAX_QUERY_EVENT_BACKLOG`
  /// (`hick-reactor/src/query.rs:23`), but bounding a DIFFERENT thing:
  /// `hick-reactor` gives each query its own 1024-slot mailbox, whereas every
  /// query/service/lookup here shares this one queue and one cap. Coalescing
  /// keeps distinct records the only occupants, and the caller is expected to
  /// drain every tick, so one shared cap is adequate — though it does mean a
  /// flooding query can crowd out another's answers. That is the accepted
  /// cost of the single-drain-point design; terminals are exempt, so no
  /// lifecycle event is ever lost to it.
  pub(crate) const ANSWER_CAPACITY: usize = 1024;

  /// An empty queue.
  pub(crate) fn new() -> Self {
    Self {
      queue: VecDeque::new(),
      live: HashMap::new(),
      order: VecDeque::new(),
      dropped: 0,
      len: 0,
      next_generation: 0,
    }
  }

  /// Queue a newly collected answer for `handle`.
  ///
  /// Coalesces onto a queued answer with the same `(handle, rtype, rclass,
  /// rdata_key)` key ([`AnswerKey`]) in place — the position in delivery
  /// order and the occupying [`Slot::Answer`]'s generation are unchanged, and
  /// [`Self::dropped`] is not incremented; this is a refresh, not a loss.
  /// Otherwise, once [`Self::ANSWER_CAPACITY`] live answers are already
  /// queued, evicts the oldest live answer (never a terminal) before queuing
  /// the new one under a fresh generation and increments [`Self::dropped`].
  pub(crate) fn push_answer(&mut self, handle: QueryHandle, answer: CollectedAnswer) {
    let key = AnswerKey {
      handle,
      rtype: answer.rtype(),
      rclass: answer.rclass(),
      rdata_key: answer.rdata_key().to_vec(),
    };
    if let Some(existing) = self.live.get_mut(&key) {
      existing.answer = answer;
      return;
    }
    if self.live.len() >= Self::ANSWER_CAPACITY {
      // `order` and `live` share membership at all times (see the
      // type-level `# Invariant`): whenever `live` is at capacity it is
      // non-empty, so `order` — always the SAME membership — is too. The
      // `if let` is a defensive guard, not an expected `None` path.
      if let Some(victim) = self.order.pop_front() {
        self.live.remove(&victim);
        self.dropped = self.dropped.saturating_add(1);
        self.len = self.len.saturating_sub(1);
      }
    }
    let generation = self.next_generation;
    // `wrapping`, never `saturating`: see the field's doc.
    self.next_generation = self.next_generation.wrapping_add(1);
    self.order.push_back(key.clone());
    self.queue.push_back(Slot::Answer(key.clone(), generation));
    self.live.insert(key, LiveAnswer { generation, answer });
    self.len = self.len.saturating_add(1);
  }

  /// Queue any event that is **never an answer** — [`Event::Service`],
  /// [`Event::QueryTerminal`], [`Event::Lookup`] and [`Event::LookupDone`] —
  /// verbatim.
  ///
  /// Always appends: unlike [`Self::push_answer`] this is never coalesced,
  /// never evicted, and does not count against [`Self::ANSWER_CAPACITY`].
  ///
  /// # Panics
  ///
  /// Debug builds assert the event is not an [`Event::QueryAnswer`]. `Event` is
  /// one enum for both paths, so nothing in the type system stops an answer
  /// being routed through here — where it would bypass both the cap and the
  /// coalescing, letting a flooding peer grow the queue without bound. Answers
  /// go through [`Self::push_answer`], always.
  pub(crate) fn push_terminal(&mut self, event: Event) {
    debug_assert!(
      !matches!(event, Event::QueryAnswer { .. }),
      "an answer must go through push_answer: push_terminal is uncapped and non-coalescing"
    );
    self.queue.push_back(Slot::Terminal(event));
    self.len = self.len.saturating_add(1);
  }

  /// Pop the next event, if any, in arrival order.
  ///
  /// A `Slot::Answer(key, generation)` is only ever delivered when
  /// `generation` matches `live`'s CURRENT generation for `key` — seeing the
  /// current, authoritative occurrence of that key, by the type-level
  /// `# Invariant`, always at `order`'s current front. A mismatch means a
  /// NEWER generation of the same key is still live (this slot is a stale
  /// duplicate the newer occurrence's own, later slot will resolve instead);
  /// the entry is put back untouched and scanning continues. An absent entry
  /// means the key was evicted and never re-collected since — already
  /// accounted in [`Self::dropped`] and [`Self::len`] at eviction time, so
  /// skipping it here changes neither counter.
  pub(crate) fn pop(&mut self) -> Option<Event> {
    loop {
      match self.queue.pop_front()? {
        Slot::Answer(key, generation) => match self.live.remove(&key) {
          Some(live) if live.generation == generation => {
            self.order.pop_front();
            self.len = self.len.saturating_sub(1);
            return Some(Event::QueryAnswer {
              handle: key.handle,
              answer: live.answer,
            });
          }
          Some(live) => {
            // A newer generation of `key` is still live; put it back and
            // keep scanning for that generation's own slot.
            self.live.insert(key, live);
          }
          None => {
            // Evicted, and never re-collected since. Keep scanning.
          }
        },
        Slot::Terminal(event) => {
          self.len = self.len.saturating_sub(1);
          return Some(event);
        }
      }
    }
  }

  /// Total number of answers lost rather than delivered. Monotonic for the
  /// life of the queue.
  ///
  /// Counts [`Self::push_answer`]'s capacity evictions plus every loss the
  /// producer reports through [`Self::record_dropped`].
  pub(crate) fn dropped(&self) -> u64 {
    self.dropped
  }

  /// Account for answers lost BEFORE they reached this queue — the proto
  /// layer's own `max_answers` cap evicting a record between two scans.
  ///
  /// Folded into the same counter as this queue's own evictions: from the
  /// caller's side both are one thing, an answer that was collected and never
  /// delivered. Keeping them apart would leave the proto-side loss invisible.
  pub(crate) fn record_dropped(&mut self, n: u64) {
    self.dropped = self.dropped.saturating_add(n);
  }

  /// Number of events currently queued for delivery (live answers plus
  /// terminals not yet popped).
  ///
  /// Test-only, permanently: the driver never consults the depth — capacity is
  /// enforced inside [`Self::push_answer`] and the physical footprint by
  /// [`Self::compact`] — so this stays `#[cfg(test)]` rather than carrying a
  /// dead-code allow that a later cleanup could mistake for stale.
  #[cfg(test)]
  pub(crate) fn len(&self) -> usize {
    self.len
  }

  /// Number of slots physically held in the backing store, including the stale
  /// ones [`Self::pop`] has not yet skipped past.
  ///
  /// Always at least [`Self::len`]. The gap is what [`Self::compact`] reclaims.
  pub(crate) fn physical_len(&self) -> usize {
    self.queue.len()
  }

  /// Discard every stale [`Slot::Answer`] still occupying the backing store.
  ///
  /// [`Self::pop`] skips stale slots lazily, which is free for a caller that
  /// drains every tick but unbounded for one that does not: an evicted answer's
  /// slot survives until a `pop` walks past it, so a flooding peer plus a
  /// non-draining caller grows `queue` without limit even though `live` stays
  /// capped. This reclaims those slots eagerly.
  ///
  /// The type-level `# Invariant` is preserved exactly: only slots that
  /// [`Self::pop`] would have skipped are removed, `live` and `order` are not
  /// touched, relative order is unchanged, and neither [`Self::len`] nor
  /// [`Self::dropped`] moves — a stale slot was already accounted for when it
  /// was evicted.
  pub(crate) fn compact(&mut self) {
    let live = &self.live;
    self.queue.retain(|slot| match slot {
      Slot::Answer(key, generation) => live
        .get(key)
        .is_some_and(|current| current.generation == *generation),
      // Terminals are queued verbatim and are never stale.
      Slot::Terminal(_) => true,
    });
  }
}

#[cfg(test)]
mod tests;

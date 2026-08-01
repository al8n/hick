use std::time::Instant;

use mdns_proto::{
  CollectedAnswer, EndpointConfig, Name, QueryHandle, QuerySpec, QueryUpdate,
  wire::{ResourceClass, ResourceType},
};
use rand::{SeedableRng, rngs::StdRng};

use super::{Event, EventQueue};
use crate::proto::ProtoEndpoint;

/// Two real `QueryHandle`s. They cannot be fabricated — `QueryHandle::from_raw`
/// is `pub(crate)` to `mdns-proto` — so mint them from a throwaway endpoint via
/// the public `try_start_query`. The endpoint is returned so it outlives them.
fn two_handles() -> (ProtoEndpoint, QueryHandle, QueryHandle) {
  let rng = StdRng::from_rng(&mut rand::rng());
  let mut ep = ProtoEndpoint::try_new(EndpointConfig::new(), rng);
  let now = Instant::now();
  let spec = |n: &str| QuerySpec::new(Name::try_from_str(n).unwrap(), ResourceType::Ptr);
  let a = ep.try_start_query(spec("_a._tcp.local."), now).unwrap();
  let b = ep.try_start_query(spec("_b._tcp.local."), now).unwrap();
  (ep, a, b)
}

/// A distinct synthetic answer keyed by `tag` (encoded into the rdata so
/// different tags do not coalesce). Mirrors `hick-reactor/src/query/tests.rs:9`.
fn answer(tag: u32) -> CollectedAnswer {
  CollectedAnswer::from_parts(
    ResourceType::Ptr,
    ResourceClass::In,
    tag.to_be_bytes().to_vec(),
    u64::from(tag),
  )
}

#[test]
fn pop_returns_events_in_order() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  q.push_answer(h, answer(1));
  q.push_answer(h, answer(2));
  assert!(matches!(q.pop(), Some(Event::QueryAnswer { .. })));
  assert!(matches!(q.pop(), Some(Event::QueryAnswer { .. })));
  assert!(q.pop().is_none());
}

#[test]
fn identical_answers_coalesce() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  q.push_answer(h, answer(7));
  q.push_answer(h, answer(7));
  assert_eq!(q.len(), 1);
  assert_eq!(q.dropped(), 0, "coalescing is not a drop");
}

#[test]
fn the_same_record_for_different_queries_does_not_coalesce() {
  // Coalescing is keyed by (handle, record) — two queries that independently
  // collect the same record must each surface it.
  let (_ep, a, b) = two_handles();
  let mut q = EventQueue::new();
  q.push_answer(a, answer(7));
  q.push_answer(b, answer(7));
  assert_eq!(q.len(), 2);
}

#[test]
fn answers_drop_oldest_past_capacity_and_count() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  let overflow = 10u32;
  for i in 0..(EventQueue::ANSWER_CAPACITY as u32 + overflow) {
    q.push_answer(h, answer(i));
  }
  assert_eq!(q.len(), EventQueue::ANSWER_CAPACITY);
  assert_eq!(q.dropped(), u64::from(overflow));
  // The oldest were evicted, so the head is now `overflow`.
  match q.pop() {
    Some(Event::QueryAnswer { answer: a, .. }) => {
      assert_eq!(a.rdata_slice(), &overflow.to_be_bytes()[..]);
    }
    other => panic!("expected an answer at the head, got {other:?}"),
  }
}

#[test]
fn a_terminal_survives_a_full_queue() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  for i in 0..(EventQueue::ANSWER_CAPACITY as u32 + 10) {
    q.push_answer(h, answer(i));
  }
  q.push_terminal(Event::QueryTerminal {
    handle: h,
    update: QueryUpdate::Timeout,
  });
  let mut saw_terminal = false;
  while let Some(ev) = q.pop() {
    if matches!(ev, Event::QueryTerminal { .. }) {
      saw_terminal = true;
    }
  }
  assert!(saw_terminal, "a terminal must never be dropped");
}

#[test]
fn eviction_never_removes_a_terminal_to_make_room() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  q.push_terminal(Event::QueryTerminal {
    handle: h,
    update: QueryUpdate::Timeout,
  });
  // Overflow the queue with answers; the terminal queued FIRST must survive.
  for i in 0..(EventQueue::ANSWER_CAPACITY as u32 + 50) {
    q.push_answer(h, answer(i));
  }
  let terminals = std::iter::from_fn(|| q.pop())
    .filter(|e| matches!(e, Event::QueryTerminal { .. }))
    .count();
  assert_eq!(terminals, 1, "the terminal was evicted to make room");
}

// --- Evicted, then genuinely re-collected --------------------------------
//
// A key that is evicted and later GENUINELY re-collected -- before its
// now-stale `Slot::Answer` is popped -- once broke the `live`/`order` lockstep
// invariant `push_answer`/`pop` rely on. The tests below drive that exact
// interleaving through the public `push_answer`/`pop` surface only.

// A capacity breach is not directly observable as `len() > ANSWER_CAPACITY`:
// the buggy implementation's eviction path increments `dropped` and
// decrements `len` whenever `order.pop_front()` returns *a* key, without
// checking whether that key was still actually present in `live` --  so a
// "ghost" eviction (the popped key already gone from `live` via the
// `live`/`order` desync below) silently cancels its own `len -= 1` against
// the following insert's `len += 1`, hiding the breach from `len()` alone.
// The robust, implementation-independent check is conservation: every
// pushed, non-coalescing answer must be EITHER delivered exactly once OR
// dropped exactly once, never both and never neither. A ghost eviction
// double-charges -- the phantom drop is counted, and the real entry that
// should have been removed is still delivered independently later -- so
// `delivered + dropped` exceeds `pushed` exactly when a breach occurred.

/// Fill to `ANSWER_CAPACITY`, evict key `0` with a new push, then genuinely
/// re-collect key `0` (same query, same record) before its original,
/// now-stale slot is popped, then do exactly one partial drain -- the pop
/// that, on the buggy implementation, matches key 0's re-collected value
/// against its STALE, original slot instead of skipping it. Returns the
/// number of `push_answer` calls made and of answers delivered by the one
/// partial drain, so callers can fold them into their own conservation
/// check.
fn corrupt_then_partially_drain(q: &mut EventQueue, h: QueryHandle, cap: u32) -> (u64, u64) {
  for i in 0..cap {
    q.push_answer(h, answer(i));
  }
  // Evict key 0.
  q.push_answer(h, answer(cap));
  // Re-collect key 0 before its original slot is popped -- evicts key 1.
  q.push_answer(h, answer(0));
  let delivered = u64::from(q.pop().is_some());
  (u64::from(cap) + 2, delivered)
}

#[test]
fn evicted_then_recollected_key_cannot_breach_capacity() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  let cap = EventQueue::ANSWER_CAPACITY as u32;
  let (mut pushed, mut delivered) = corrupt_then_partially_drain(&mut q, h, cap);

  // Keep pushing fresh distinct keys well past capacity -- enough for
  // `order` to cycle all the way around to the stale key-0 entry the
  // corruption above leaves behind, on the buggy implementation.
  for i in 0..(cap * 2) {
    q.push_answer(h, answer(cap + 1 + i));
    pushed += 1;
  }
  while q.pop().is_some() {
    delivered += 1;
  }

  assert_eq!(
    delivered + q.dropped(),
    pushed,
    "delivered ({delivered}) + dropped ({}) != pushed ({pushed}): a live answer \
     was evicted more than once (phantom drop), which is only possible if \
     `live` silently grew past ANSWER_CAPACITY at some point",
    q.dropped()
  );
}

#[test]
fn evicted_then_recollected_key_does_not_permanently_disable_eviction() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  let cap = EventQueue::ANSWER_CAPACITY as u32;
  let mut pushed = 0u64;
  let mut delivered = 0u64;
  let mut next_fresh = 0u32;

  for _ in 0..cap {
    q.push_answer(h, answer(next_fresh));
    next_fresh += 1;
    pushed += 1;
  }

  // Three separate evict/re-collect/partial-drain rounds, each followed by
  // a full-capacity batch of fresh pushes. If the FIRST round's corruption
  // permanently disabled eviction (rather than being a one-off eviction
  // recovers from), later rounds keep compounding it instead of the queue
  // self-healing -- demonstrating "permanently", not just "once".
  for _round in 0..3 {
    q.push_answer(h, answer(next_fresh)); // evicts the current oldest live key
    next_fresh += 1;
    pushed += 1;
    q.push_answer(h, answer(0)); // re-collect key 0 again
    pushed += 1;
    if q.pop().is_some() {
      delivered += 1;
    }
    for _ in 0..cap {
      q.push_answer(h, answer(next_fresh));
      next_fresh += 1;
      pushed += 1;
    }
  }
  while q.pop().is_some() {
    delivered += 1;
  }

  assert_eq!(
    delivered + q.dropped(),
    pushed,
    "delivered ({delivered}) + dropped ({}) != pushed ({pushed}) after repeated \
     evict/re-collect rounds -- eviction did not keep reclaiming capacity \
     correctly, indefinitely",
    q.dropped()
  );
}

#[test]
fn a_recollected_answer_is_not_delivered_before_an_earlier_unrelated_one() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  let cap = EventQueue::ANSWER_CAPACITY as u32;

  // Fill to capacity with distinct keys 0..cap; key 0 is the oldest.
  for i in 0..cap {
    q.push_answer(h, answer(i));
  }
  // Evict key 0.
  q.push_answer(h, answer(cap));
  // An "unrelated" key, queued strictly BEFORE key 0's re-collection below.
  q.push_answer(h, answer(cap + 1));
  // Re-collect key 0 (same rtype/rclass/rdata, so the same AnswerKey) with a
  // distinguishable `seq` so it can be told apart from its first occurrence
  // once popped; queued strictly AFTER the unrelated key above.
  q.push_answer(
    h,
    CollectedAnswer::from_parts(
      ResourceType::Ptr,
      ResourceClass::In,
      0u32.to_be_bytes().to_vec(),
      999,
    ),
  );

  let mut unrelated_index = None;
  let mut recollected_index = None;
  for (i, ev) in std::iter::from_fn(|| q.pop()).enumerate() {
    if let Event::QueryAnswer { answer, .. } = &ev {
      if answer.rdata_slice() == (cap + 1).to_be_bytes() {
        unrelated_index = Some(i);
      }
      if answer.rdata_slice() == 0u32.to_be_bytes() && answer.seq() == 999 {
        recollected_index = Some(i);
      }
    }
  }

  let unrelated_index = unrelated_index.expect("unrelated answer must be delivered");
  let recollected_index = recollected_index.expect("re-collected answer must be delivered");
  assert!(
    unrelated_index < recollected_index,
    "the unrelated answer, queued first, must be delivered before the re-collected one \
     (got unrelated at {unrelated_index}, re-collected at {recollected_index})"
  );
}

/// The generation counter WRAPS rather than saturating, so a slot minted at the
/// very top of the range is still told apart from a later re-collection of the
/// same key.
///
/// Saturating would hand every answer minted after the top-out one shared
/// generation, and `pop` would then match an evicted key's STALE slot against
/// its own live re-collection — delivering the re-collected answer at the stale
/// slot's position and popping `order`'s front for a key that is not there.
/// That is exactly the aliasing the tag exists to rule out, and only this
/// fixture reaches it: every other test here starts the counter at `0`.
#[test]
fn a_generation_at_the_top_of_the_range_does_not_alias_a_later_one() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  // The next mint is `u64::MAX` itself, so a saturating counter would never
  // advance past it again and every slot below would share that one value.
  q.next_generation = u64::MAX;
  let cap = EventQueue::ANSWER_CAPACITY as u32;

  for i in 0..cap {
    q.push_answer(h, answer(i));
  }
  // Evict key 0, then genuinely re-collect it before its now-stale slot is
  // reached; that second push evicts key 1 in turn.
  q.push_answer(h, answer(cap));
  q.push_answer(h, answer(0));

  // Keys 0 and 1 are both gone from `live`, so the first two slots are stale
  // and the first answer delivered must be key 2's.
  match q.pop() {
    Some(Event::QueryAnswer { answer: a, .. }) => assert_eq!(
      a.rdata_slice(),
      &2u32.to_be_bytes()[..],
      "a stale slot was delivered: its generation aliased the live one"
    ),
    other => panic!("expected an answer at the head, got {other:?}"),
  }
}

// --- Physical-footprint compaction ---------------------------------------
//
// `pop` skips stale slots lazily, which is free for a caller that drains every
// tick and unbounded for one that does not. `compact` reclaims them eagerly;
// these tests pin down that it reclaims exactly the slots `pop` would have
// skipped and nothing else.

#[test]
fn compaction_reclaims_every_stale_slot() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  let cap = EventQueue::ANSWER_CAPACITY as u32;
  // Four capacities of distinct keys with no pop in between: three quarters of
  // the physical store is now tombstones.
  for i in 0..(cap * 4) {
    q.push_answer(h, answer(i));
  }
  assert_eq!(q.physical_len(), (cap * 4) as usize);
  q.compact();
  assert_eq!(
    q.physical_len(),
    EventQueue::ANSWER_CAPACITY,
    "compaction must leave exactly the live answers"
  );
  assert_eq!(q.len(), EventQueue::ANSWER_CAPACITY, "len is unchanged");
}

#[test]
fn compaction_changes_neither_delivery_order_nor_content() {
  let (_ep, h, _) = two_handles();
  let cap = EventQueue::ANSWER_CAPACITY as u32;

  let drain = |compact: bool| -> (Vec<Vec<u8>>, u64) {
    let mut q = EventQueue::new();
    for i in 0..cap {
      q.push_answer(h, answer(i));
    }
    // Evict key 0, re-collect it, and interleave a terminal so the compaction
    // has a stale slot, a superseded key, and a never-stale slot to handle.
    q.push_answer(h, answer(cap));
    q.push_terminal(Event::QueryTerminal {
      handle: h,
      update: QueryUpdate::Timeout,
    });
    q.push_answer(h, answer(0));
    for i in 0..cap {
      q.push_answer(h, answer(cap + 1 + i));
    }
    if compact {
      q.compact();
    }
    let mut out = Vec::new();
    while let Some(ev) = q.pop() {
      match ev {
        Event::QueryAnswer { answer, .. } => out.push(answer.rdata_slice().to_vec()),
        _ => out.push(Vec::new()),
      }
    }
    (out, q.dropped())
  };

  let (plain, plain_dropped) = drain(false);
  let (compacted, compacted_dropped) = drain(true);
  assert_eq!(
    plain, compacted,
    "compaction must not change what is delivered, or in what order"
  );
  assert_eq!(
    plain_dropped, compacted_dropped,
    "a stale slot was already accounted for at eviction; compaction must not re-count it"
  );
}

#[test]
fn record_dropped_folds_proto_side_loss_into_the_same_counter() {
  let (_ep, h, _) = two_handles();
  let mut q = EventQueue::new();
  q.push_answer(h, answer(1));
  assert_eq!(q.dropped(), 0);
  // Answers the proto layer's own cap evicted before this queue ever saw them.
  q.record_dropped(3);
  assert_eq!(q.dropped(), 3);
  q.record_dropped(0);
  assert_eq!(
    q.dropped(),
    3,
    "reporting no loss must not move the counter"
  );
  assert_eq!(q.len(), 1, "accounting for a loss queues nothing");
}

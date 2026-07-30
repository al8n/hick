#![allow(warnings)]

use std::time::Instant as StdInstant;

use super::*;
use crate::{
  Name, QueryHandle,
  event::QueryEvent,
  service::MAX_PARTIAL_ROUNDS,
  wire::{MessageReader, ResourceClass, ResourceType},
};

type TestQuery = Query<StdInstant, slab::Slab<CollectedAnswer>, slab::Slab<QueryUpdate>>;

/// Build a minimal mDNS response containing a single A record for `name`.
///
/// Layout:
///   Header (12 bytes) — QR=1, ancount=1
///   Answer: <name> A IN ttl=120 rdata=<ip_bytes>
///
/// We use fully-qualified single-label names to avoid compression complexity.
fn make_a_response(name: &[u8], ip: [u8; 4]) -> std::vec::Vec<u8> {
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  // Header: id=0, flags=0x8400 (QR=1,AA=1), qdcount=0, ancount=1, nscount=0, arcount=0
  msg.extend_from_slice(&[
    0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  ]);
  // Name: length-prefixed label then \0
  msg.push(name.len() as u8);
  msg.extend_from_slice(name);
  msg.push(0x00); // root label
  // rtype = A (1)
  msg.extend_from_slice(&[0x00, 0x01]);
  // rclass = IN (1)
  msg.extend_from_slice(&[0x00, 0x01]);
  // ttl = 120
  msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]);
  // rdlength = 4
  msg.extend_from_slice(&[0x00, 0x04]);
  // rdata
  msg.extend_from_slice(&ip);
  msg
}

fn make_query(qtype: ResourceType, qclass: ResourceClass) -> TestQuery {
  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("printer.local.").unwrap();
  TestQuery::try_new(handle, qname, qtype, qclass, 1, false, None)
}

fn inject_a_record(q: &mut TestQuery, msg: &[u8]) {
  let reader = MessageReader::try_parse(msg).unwrap();
  let record = reader.answers().next().unwrap().unwrap();
  q.handle_event(QueryEvent::Answer(record));
}

// ── dedupe ───────────────────────────────────────────────────────────

#[test]
fn identical_answers_are_deduped() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let msg = make_a_response(b"printer", [192, 168, 1, 10]);
  inject_a_record(&mut q, &msg);
  inject_a_record(&mut q, &msg);
  inject_a_record(&mut q, &msg);
  assert_eq!(q.answers.len(), 1, "duplicate answers must be deduped");
}

#[test]
fn non_name_answer_stores_no_separate_identity_key() {
  // A/AAAA/TXT/unknown rdata has no DNS name to fold, so the
  // folded identity equals the display rdata — we must store ONLY one buffer
  // (rdata_key is None), not double per-answer memory under a flood.
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let msg = make_a_response(b"printer", [192, 168, 1, 10]);
  inject_a_record(&mut q, &msg);
  let ans = q.collected_answers().next().unwrap();
  assert!(
    ans.rdata_key.is_none(),
    "non-name rdata must not allocate a separate folded key buffer"
  );
  assert_eq!(ans.rdata_key(), ans.rdata_slice());
}

#[test]
fn different_rdata_not_deduped() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let msg1 = make_a_response(b"printer", [192, 168, 1, 10]);
  let msg2 = make_a_response(b"printer", [192, 168, 1, 11]);
  inject_a_record(&mut q, &msg1);
  inject_a_record(&mut q, &msg2);
  assert_eq!(q.answers.len(), 2, "different rdata must not be deduped");
}

#[test]
fn ptr_answer_with_compressed_target_is_decompressed() {
  // a PTR whose RDATA target is a compression pointer must be
  // stored DECOMPRESSED, so a caller can decode the instance name without
  // the original packet.
  let mut q = make_query(ResourceType::Ptr, ResourceClass::In);
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  // Header: id=0, flags=0x8400 (QR+AA), qd=0 an=1 ns=0 ar=0.
  msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
  // Owner name "svc.local." starting at offset 12.
  msg.extend_from_slice(&[3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0]);
  msg.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
  msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
  // RDATA = "inst" + pointer (0xC00C) to "svc.local." at offset 12.
  msg.extend_from_slice(&7u16.to_be_bytes()); // RDLENGTH
  msg.extend_from_slice(&[4, b'i', b'n', b's', b't', 0xC0, 0x0C]);

  inject_a_record(&mut q, &msg);
  assert_eq!(q.answers.len(), 1);
  let ans = q.collected_answers().next().unwrap();
  // Full decompressed wire name: inst.svc.local.
  let expected: &[u8] = &[
    4, b'i', b'n', b's', b't', 3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0,
  ];
  assert_eq!(
    ans.rdata_slice(),
    expected,
    "PTR target must be stored as a decompressed self-contained wire name"
  );
}

#[test]
fn ptr_answers_differing_only_in_case_are_deduped() {
  // two PTR answers whose targets differ only in DNS name case
  // are the SAME logical record (case-insensitive matching), so they must
  // collapse to ONE collected answer — a responder can't flood the bounded
  // set with case permutations. The stored rdata keeps the FIRST seen case
  // for display; the folded identity key is lowercased.
  let mut q = make_query(ResourceType::Ptr, ResourceClass::In);
  let ptr_with_target = |first_label: &[u8]| -> std::vec::Vec<u8> {
    let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
    msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
    msg.extend_from_slice(&[3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0]);
    msg.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
    msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
    // RDATA = <first_label> + "svc.local." written INLINE (uncompressed).
    let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
    rdata.push(first_label.len() as u8);
    rdata.extend_from_slice(first_label);
    rdata.extend_from_slice(&[3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0]);
    msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    msg.extend_from_slice(&rdata);
    msg
  };
  inject_a_record(&mut q, &ptr_with_target(b"INST"));
  inject_a_record(&mut q, &ptr_with_target(b"inst"));
  assert_eq!(
    q.answers.len(),
    1,
    "case-only PTR variants must collapse to a single collected answer"
  );
  let ans = q.collected_answers().next().unwrap();
  assert_eq!(
    ans.rdata_slice(),
    &[
      4, b'I', b'N', b'S', b'T', 3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0
    ][..],
    "the first-seen display case must be preserved"
  );
  assert_eq!(
    ans.rdata_key(),
    &[
      4, b'i', b'n', b's', b't', 3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0
    ][..],
    "the identity key must be case-folded"
  );
}

#[test]
fn qtype_filter_drops_non_matching_records() {
  // Query is for AAAA; inject an A record — should be dropped.
  let mut q = make_query(ResourceType::AAAA, ResourceClass::Any);
  let msg = make_a_response(b"printer", [192, 168, 1, 10]);
  inject_a_record(&mut q, &msg);
  assert_eq!(
    q.answers.len(),
    0,
    "A record should be dropped for AAAA query"
  );
}

#[test]
fn qtype_any_accepts_all_rtypes() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let msg = make_a_response(b"printer", [192, 168, 1, 10]);
  inject_a_record(&mut q, &msg);
  assert_eq!(q.answers.len(), 1, "Any qtype should accept A records");
}

#[test]
fn qtype_exact_match_accepted() {
  let mut q = make_query(ResourceType::A, ResourceClass::Any);
  let msg = make_a_response(b"printer", [192, 168, 1, 10]);
  inject_a_record(&mut q, &msg);
  assert_eq!(q.answers.len(), 1, "exact rtype match should be accepted");
}

// ── max_answers cap ──────────────────────────────────────────────────

#[test]
fn answers_capped_at_max_answers() {
  let mut q = make_query(ResourceType::A, ResourceClass::Any).with_max_answers(3);
  // Inject 5 distinct A records (different IPs).
  for i in 0u8..5 {
    let msg = make_a_response(b"printer", [10, 0, 0, i]);
    inject_a_record(&mut q, &msg);
  }
  assert_eq!(
    q.answers.len(),
    3,
    "answers must be capped at max_answers=3"
  );
}

#[test]
fn max_answers_zero_disables_collection() {
  let mut q = make_query(ResourceType::A, ResourceClass::Any).with_max_answers(0);
  let msg = make_a_response(b"printer", [10, 0, 0, 1]);
  inject_a_record(&mut q, &msg);
  assert_eq!(q.answers.len(), 0, "max_answers=0 must disable collection");
}

#[test]
fn accepted_count_tracks_evictions_beyond_the_cap() {
  // accepted_count counts EVERY accepted answer, even those the
  // cap has since evicted, so a consumer can compute how many were lost.
  let mut q = make_query(ResourceType::A, ResourceClass::Any).with_max_answers(1);
  for i in 0u8..5 {
    let msg = make_a_response(b"printer", [10, 0, 0, i]);
    inject_a_record(&mut q, &msg);
  }
  assert_eq!(q.collected_answers().count(), 1, "snapshot capped at 1");
  assert_eq!(q.accepted_count(), 5, "but all 5 were accepted");
  // The gap a driver would count as dropped-before-seen.
  assert_eq!(q.accepted_count() - q.collected_answers().count() as u64, 4);
}

#[test]
fn cap_evicts_oldest_on_overflow() {
  // max_answers = 2; inject 4 distinct answers A, B, C, D in order.
  // After all insertions the pool must hold exactly C and D (the two newest),
  // not A or B.  This verifies *true* FIFO: the eviction victim is always the
  // entry with the lowest insertion-sequence, not the one with the lowest slab
  // slot index (which would be wrong after the first eviction reuses a slot).
  let mut q = make_query(ResourceType::A, ResourceClass::Any).with_max_answers(2);
  let msg_a = make_a_response(b"printer", [10, 0, 0, 0]); // seq 0
  let msg_b = make_a_response(b"printer", [10, 0, 0, 1]); // seq 1
  let msg_c = make_a_response(b"printer", [10, 0, 0, 2]); // seq 2 — evicts seq 0
  let msg_d = make_a_response(b"printer", [10, 0, 0, 3]); // seq 3 — evicts seq 1
  inject_a_record(&mut q, &msg_a);
  inject_a_record(&mut q, &msg_b);
  inject_a_record(&mut q, &msg_c);
  inject_a_record(&mut q, &msg_d);
  assert_eq!(q.answers.len(), 2, "pool must stay at cap after evictions");
  // C and D must be present; A and B must be gone.
  let retained: std::vec::Vec<[u8; 4]> = q
    .answers
    .iter()
    .filter_map(|(_, a)| {
      let s = a.rdata_slice();
      s.get(..4).and_then(|b| b.try_into().ok())
    })
    .collect();
  assert!(
    retained.contains(&[10, 0, 0, 2]),
    "C (10.0.0.2) must be retained; got {:?}",
    retained
  );
  assert!(
    retained.contains(&[10, 0, 0, 3]),
    "D (10.0.0.3) must be retained; got {:?}",
    retained
  );
  assert!(
    !retained.contains(&[10, 0, 0, 0]),
    "A (10.0.0.0) must have been evicted; got {:?}",
    retained
  );
  assert!(
    !retained.contains(&[10, 0, 0, 1]),
    "B (10.0.0.1) must have been evicted; got {:?}",
    retained
  );
}

// ── fixed-capacity pool smaller than max_answers ──────────

/// Error raised by [`CappedPool`] when its fixed capacity is exhausted.
#[derive(Debug)]
struct CappedPoolFull;
impl core::fmt::Display for CappedPoolFull {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str("capped pool full")
  }
}
impl core::error::Error for CappedPoolFull {}

/// A test-only [`Pool`] with a hard capacity of `N`, independent of the
/// `Query`'s logical `max_answers`. Models a fixed-capacity fallible pool
/// whose `insert`/`vacant_key` fail once full — the
/// scenario the `max_answers`-only eviction check cannot see.
struct CappedPool<const N: usize> {
  slots: std::vec::Vec<Option<CollectedAnswer>>,
}

impl<const N: usize> Pool<CollectedAnswer> for CappedPool<N> {
  type Error = CappedPoolFull;
  type Iter<'a> = std::boxed::Box<dyn Iterator<Item = (usize, &'a CollectedAnswer)> + 'a>;
  type IterMut<'a> = std::boxed::Box<dyn Iterator<Item = (usize, &'a mut CollectedAnswer)> + 'a>;

  fn new() -> Self {
    Self {
      slots: std::vec::Vec::new(),
    }
  }

  fn with_capacity(_capacity: usize) -> Result<Self, Self::Error> {
    Ok(Self::new())
  }

  fn vacant_key(&self) -> Result<usize, Self::Error> {
    if let Some(i) = self.slots.iter().position(|s| s.is_none()) {
      Ok(i)
    } else if self.slots.len() < N {
      Ok(self.slots.len())
    } else {
      Err(CappedPoolFull)
    }
  }

  fn is_empty(&self) -> bool {
    self.slots.iter().all(|s| s.is_none())
  }

  fn len(&self) -> usize {
    self.slots.iter().filter(|s| s.is_some()).count()
  }

  fn get(&self, key: usize) -> Option<&CollectedAnswer> {
    self.slots.get(key).and_then(|s| s.as_ref())
  }

  fn get_mut(&mut self, key: usize) -> Option<&mut CollectedAnswer> {
    self.slots.get_mut(key).and_then(|s| s.as_mut())
  }

  fn insert(&mut self, value: CollectedAnswer) -> Result<usize, Self::Error> {
    if let Some(i) = self.slots.iter().position(|s| s.is_none()) {
      self.slots[i] = Some(value);
      Ok(i)
    } else if self.slots.len() < N {
      self.slots.push(Some(value));
      Ok(self.slots.len() - 1)
    } else {
      Err(CappedPoolFull)
    }
  }

  fn try_remove(&mut self, key: usize) -> Option<CollectedAnswer> {
    self.slots.get_mut(key).and_then(|s| s.take())
  }

  fn iter(&self) -> Self::Iter<'_> {
    std::boxed::Box::new(
      self
        .slots
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.as_ref().map(|v| (i, v))),
    )
  }

  fn iter_mut(&mut self) -> Self::IterMut<'_> {
    std::boxed::Box::new(
      self
        .slots
        .iter_mut()
        .enumerate()
        .filter_map(|(i, s)| s.as_mut().map(|v| (i, v))),
    )
  }
}

/// when the underlying pool's hard capacity is *below*
/// `max_answers`, a full pool must not silently reject new answers — the
/// oldest entry is evicted (drop-oldest) so the newest survive, and
/// `next_seq` advances only on a successful insert.
///
/// Under the pre-fix code the `len >= max_answers` eviction check never
/// fired (the pool tops out at 2, well under `max_answers = 10`), so the
/// 3rd+ inserts failed silently while `next_seq` still advanced — leaving
/// the *oldest* two answers stuck in the pool and three phantom seq gaps.
#[test]
fn fixed_capacity_pool_below_max_answers_evicts_and_advances_seq() {
  type CappedQuery = Query<StdInstant, CappedPool<2>, slab::Slab<QueryUpdate>>;
  let mut q: CappedQuery = CappedQuery::try_new(
    QueryHandle::from_raw(0),
    Name::try_from_str("printer.local.").unwrap(),
    ResourceType::A,
    ResourceClass::Any,
    1,
    false,
    None,
  )
  .with_max_answers(10); // logical cap (10) >> pool capacity (2)

  for i in 0u8..5 {
    let msg = make_a_response(b"printer", [10, 0, 0, i]);
    let reader = MessageReader::try_parse(&msg).unwrap();
    let record = reader.answers().next().unwrap().unwrap();
    q.handle_event(QueryEvent::Answer(record));
  }

  // The pool stays at its own hard capacity (2), NOT max_answers (10).
  assert_eq!(
    q.answers.len(),
    2,
    "answers must be bounded by the pool's hard capacity, not max_answers"
  );
  // Five answers each inserted successfully (after evicting the oldest), so
  // next_seq advanced exactly five times — no phantom advance on a drop.
  assert_eq!(
    q.accepted_count(),
    5,
    "next_seq must advance once per successful insert"
  );
  // Drop-oldest keeps the NEWEST two answers (10.0.0.3 and 10.0.0.4); the
  // buggy path would have left the oldest two (10.0.0.0/.1) stuck.
  let retained: std::vec::Vec<u8> = q
    .answers
    .iter()
    .filter_map(|(_, a)| a.rdata_slice().get(3).copied())
    .collect();
  assert!(
    retained.contains(&3) && retained.contains(&4),
    "drop-oldest must retain the newest answers; got {:?}",
    retained
  );
  assert!(
    !retained.contains(&0) && !retained.contains(&1),
    "the oldest answers must have been evicted; got {:?}",
    retained
  );
}

// ── unicast_response QU bit ─────────────────────────────────

/// When `unicast_response=true`, `poll_transmit` must emit a question
/// with the QU bit (bit 15 of qclass) set.
#[test]
fn query_emits_unicast_response_bit_when_spec_set() {
  use crate::wire::{MessageReader, QuestionRef};

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let now = StdInstant::now();
  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    42,
    true, // unicast_response = true
    None,
  );

  let mut buf = [0u8; 512];
  let result = q.poll_transmit(now, &mut buf).unwrap();
  let n = result.expect("expected a transmit to be produced").size();

  // Parse the datagram and inspect the question's QU bit.
  let reader = MessageReader::try_parse(&buf[..n]).expect("datagram must parse");
  let question: QuestionRef<'_> = reader
    .questions()
    .next()
    .expect("expected one question")
    .expect("question must parse");
  assert!(
    question.unicast_response_requested(),
    "QU bit must be set when unicast_response=true"
  );
}

/// When `unicast_response=false` (the default), the QU bit must be clear.
#[test]
fn query_omits_unicast_response_bit_by_default() {
  use crate::wire::{MessageReader, QuestionRef};

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let now = StdInstant::now();
  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    43,
    false, // unicast_response = false
    None,
  );

  let mut buf = [0u8; 512];
  let result = q.poll_transmit(now, &mut buf).unwrap();
  let n = result.expect("expected a transmit to be produced").size();

  let reader = MessageReader::try_parse(&buf[..n]).expect("datagram must parse");
  let question: QuestionRef<'_> = reader
    .questions()
    .next()
    .expect("expected one question")
    .expect("question must parse");
  assert!(
    !question.unicast_response_requested(),
    "QU bit must NOT be set when unicast_response=false"
  );
}

// ── absolute timeout deadline ───────────────────────────────

/// A query with an absolute timeout must remain active before the deadline
/// and transition to done (emitting QueryUpdate::Timeout) at or after it.
#[test]
fn query_times_out_at_absolute_deadline() {
  use core::time::Duration;

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let now = StdInstant::now();

  // deadline is 100 ms from now.
  let deadline = now.checked_add(Duration::from_millis(100)).unwrap();

  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    44,
    false,
    Some(deadline),
  );

  // 50 ms before deadline — not yet timed out.
  let before = now.checked_add(Duration::from_millis(50)).unwrap();
  q.handle_timeout(before).unwrap();
  assert!(
    q.poll().is_none() || !matches!(q.poll(), Some(QueryUpdate::Timeout)),
    "query must not time out before the absolute deadline"
  );
  // Reset any consumed update (poll is destructive; just check done flag).
  assert!(
    !q.done,
    "query must not be done before the absolute deadline"
  );

  // 200 ms — after deadline — must time out.
  let after = now.checked_add(Duration::from_millis(200)).unwrap();
  q.handle_timeout(after).unwrap();
  assert!(q.done, "query must be done after the absolute deadline");
  assert!(
    matches!(q.poll(), Some(QueryUpdate::Timeout)),
    "query must emit QueryUpdate::Timeout at the absolute deadline"
  );
}

/// When no timeout_deadline is set, the query must not auto-cancel until
/// its retry budget runs out (existing behaviour is preserved).
#[test]
fn query_without_timeout_deadline_does_not_cancel_early() {
  use core::time::Duration;

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let now = StdInstant::now();

  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    45,
    false,
    None, // no absolute deadline
  );

  // A modest future time that does not exhaust the retry budget.
  let soon = now.checked_add(Duration::from_secs(1)).unwrap();
  q.handle_timeout(soon).unwrap();
  assert!(
    !q.done,
    "query without a timeout_deadline must not auto-cancel at 1s"
  );
}

// ── poll_timeout includes timeout_deadline ───────────────────

/// `poll_timeout` must return the EARLIER of `next_deadline` (retry backoff)
/// and `timeout_deadline` (absolute cancellation).
///
/// After the first send, `next_deadline` is the first retry (+1 s). When a
/// 100 ms `timeout_deadline` is set, `poll_timeout` must return the timeout
/// instant so that a driver sleeping until `poll_timeout()` wakes at the
/// right time to fire the absolute timeout.
#[test]
fn poll_timeout_reflects_absolute_timeout() {
  use core::time::Duration;

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let now = StdInstant::now();

  // Absolute timeout 100 ms from now.
  let timeout_dl = now.checked_add(Duration::from_millis(100)).unwrap();

  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    46,
    false,
    Some(timeout_dl),
  );

  // On construction, no retry is scheduled yet (next_deadline == None), so
  // poll_timeout reflects the only known deadline: timeout_dl.
  let pt0 = q
    .poll_timeout()
    .expect("poll_timeout must be Some on construction");
  assert!(
    pt0 <= timeout_dl,
    "initial poll_timeout must be <= timeout_deadline"
  );

  // The first transmit schedules the first retry at now + ~1s (well past the
  // 100 ms timeout). handle_timeout(now) is then a no-op: the retry is not
  // yet due.
  let mut buf = [0u8; 512];
  let _ = q.poll_transmit(now, &mut buf).unwrap();
  q.handle_timeout(now).unwrap();
  assert!(!q.done, "query must not be done immediately");

  // next_deadline is now ~1 s out; timeout_deadline is 100 ms out.
  // poll_timeout must return timeout_deadline (the smaller value).
  let pt1 = q
    .poll_timeout()
    .expect("poll_timeout must be Some after first retry");
  assert!(
    pt1 <= timeout_dl,
    "poll_timeout must return <= timeout_deadline (got instant past the timeout)"
  );

  // Advance to timeout_deadline — query must become done with Timeout.
  let at_timeout = now.checked_add(Duration::from_millis(150)).unwrap();
  q.handle_timeout(at_timeout).unwrap();
  assert!(q.done, "query must be done after timeout_deadline");
  assert!(
    matches!(q.poll(), Some(crate::event::QueryUpdate::Timeout)),
    "query must emit Timeout after absolute deadline fires"
  );

  // After done, poll_timeout must return None.
  assert!(
    q.poll_timeout().is_none(),
    "poll_timeout must be None after query is done"
  );
}

// ── first-retry timing / no same-tick duplicate ──────────────

/// After the initial transmit at `now`, the first retry must be scheduled
/// at `now + 1s` (RFC 6762 §5.2), and a driver that drains `poll_transmit`
/// then sleeps to `poll_timeout` must NOT be told to wake at `now` (which
/// would re-fire `handle_timeout` and emit a duplicate query at `now`,
/// pushing the real first retry out to ~2s).
#[test]
fn first_retry_is_one_second_and_no_same_tick_duplicate() {
  use core::time::Duration;

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let now = StdInstant::now();

  // No absolute timeout: isolate the retry-backoff behaviour.
  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    48,
    false,
    None,
  );

  let mut buf = [0u8; 512];

  // First send (the initial query) is immediately due.
  assert!(
    q.poll_transmit(now, &mut buf).unwrap().is_some(),
    "initial query must be sent at now"
  );
  // the retry is scheduled on a CONFIRMED delivery, not at encode
  // time. Confirm the send.
  q.note_transmit_outcome(now, TransmitOutcome::AllDelivered);

  // The driver now sleeps until poll_timeout. It must be exactly now + 1s —
  // not now — so the loop does not immediately re-fire at now.
  let one_sec = now.checked_add(Duration::from_secs(1)).unwrap();
  assert_eq!(
    q.poll_timeout(),
    Some(one_sec),
    "first retry must be scheduled at now + 1s, not now"
  );

  // A driver that nonetheless ticks/polls again at `now` must produce no
  // second datagram (no duplicate at now).
  q.handle_timeout(now).unwrap();
  assert!(
    q.poll_transmit(now, &mut buf).unwrap().is_none(),
    "no duplicate query may be emitted at now"
  );
  assert_eq!(
    q.poll_timeout(),
    Some(one_sec),
    "next wake must remain now + 1s after a no-op tick at now"
  );

  // At now + 1s the retry fires: exactly one datagram, and once confirmed the
  // following retry is scheduled 2s later (now + 3s), honouring the ≥2x backoff.
  q.handle_timeout(one_sec).unwrap();
  assert!(
    q.poll_transmit(one_sec, &mut buf).unwrap().is_some(),
    "first retry must be sent at now + 1s"
  );
  q.note_transmit_outcome(one_sec, TransmitOutcome::AllDelivered);
  let three_sec = now.checked_add(Duration::from_secs(3)).unwrap();
  assert_eq!(
    q.poll_timeout(),
    Some(three_sec),
    "second retry must be scheduled at now + 3s (interval doubles to 2s)"
  );
}

/// a send that fails on every socket must NOT advance the retry
/// budget — the query re-attempts (with backoff) instead of marching toward a
/// premature Timeout having put no datagram on the wire.
#[test]
fn failed_send_does_not_consume_retry_budget() {
  use core::time::Duration;

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let now = StdInstant::now();
  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    49,
    false,
    None,
  );

  let mut buf = [0u8; 512];

  // Drive many tick/send cycles where EVERY send fails (delivered = false).
  // With the budget gated on confirmed delivery, the query must never time
  // out, and must keep re-attempting (transmit due again after the backoff).
  let mut t = now;
  for _ in 0..50 {
    let sent = q.poll_transmit(t, &mut buf).unwrap().is_some();
    assert!(sent, "query must keep attempting to send while undelivered");
    q.note_transmit_outcome(t, TransmitOutcome::NoneDelivered); // all sockets failed
    assert!(!q.is_done(), "an undelivered query must NOT time out");
    // Advance to the re-attempt deadline and fire it.
    let due = q.poll_timeout().expect("a re-attempt must be scheduled");
    t = due;
    q.handle_timeout(t).unwrap();
  }
  assert!(
    !q.is_done(),
    "after 50 failed sends the query must still be live (budget untouched)"
  );

  // Now let a send succeed: the budget finally advances and normal backoff
  // resumes (first confirmed retry at +1s).
  assert!(q.poll_transmit(t, &mut buf).unwrap().is_some());
  q.note_transmit_outcome(t, TransmitOutcome::AllDelivered);
  let plus_1s = t.checked_add(Duration::from_secs(1)).unwrap();
  assert_eq!(
    q.poll_timeout(),
    Some(plus_1s),
    "after the first delivered send the retry is scheduled +1s out"
  );
}

/// the retry backoff is anchored to the time passed to
/// `note_transmit_outcome` (post-send), not the `poll_transmit` time — a send
/// that takes longer than the backoff interval must not yield a past deadline.
#[test]
fn query_retry_anchored_to_confirmation_time() {
  use core::time::Duration;

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let t0 = StdInstant::now();
  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    50,
    false,
    None,
  );
  let mut buf = [0u8; 512];
  assert!(q.poll_transmit(t0, &mut buf).unwrap().is_some());

  // The send completes 5 s later — longer than the 1 s first backoff.
  let send_done = t0.checked_add(Duration::from_secs(5)).unwrap();
  q.note_transmit_outcome(send_done, TransmitOutcome::AllDelivered);

  // The next retry is 1 s AFTER the confirmed-send time, not after t0.
  assert_eq!(
    q.poll_timeout(),
    send_done.checked_add(Duration::from_secs(1)),
    "retry backoff must be anchored to the confirmed-send time, not poll_transmit time"
  );
}

// ── is_done() exposes terminal state independent of poll() ───

/// `is_done()` must reflect terminal state even after `poll()` has
/// drained the `QueryUpdate::Timeout`.  Callers that drive cleanup off
/// `is_done()` must therefore still see `true` after they have
/// consumed the corresponding update — the accessor is a level signal,
/// not an edge signal.
///
/// This also guards against a case: under a
/// fixed-capacity / full `pending_updates` pool, `handle_timeout`
/// silently drops the terminal update.  `is_done()` is still `true`
/// because the internal flag is set regardless, so the route-cleanup
/// caller has a robust signal to invoke
/// `Endpoint::handle_query_completed`.
#[test]
fn is_done_is_a_level_signal_independent_of_poll() {
  use core::time::Duration;

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let now = StdInstant::now();
  let timeout_dl = now.checked_add(Duration::from_millis(100)).unwrap();

  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    47,
    false,
    Some(timeout_dl),
  );

  // Before any timer fires, the query is not done.
  assert!(!q.is_done(), "fresh query must not be done");

  // Fire the absolute timeout.
  let at_timeout = now.checked_add(Duration::from_millis(150)).unwrap();
  q.handle_timeout(at_timeout).unwrap();
  assert!(q.is_done(), "is_done() must be true after timeout");

  // Drain the QueryUpdate.  is_done() must stay true (level signal).
  let update = q.poll();
  assert!(
    matches!(update, Some(crate::event::QueryUpdate::Timeout)),
    "expected QueryUpdate::Timeout from poll(); got {update:?}"
  );
  assert!(
    q.is_done(),
    "is_done() must remain true after poll() drained the terminal update; \
       this is the contract that lets cleanup work under a full pending_updates pool"
  );

  // poll() after drain returns None.
  assert!(q.poll().is_none(), "no further updates after drain");
  // But is_done() still reports terminal.
  assert!(
    q.is_done(),
    "is_done() must remain true indefinitely after termination"
  );
}

// ── handle_event / handle_timeout / note_* edge arms ──────────────────

#[test]
fn txid_accessor_returns_transaction_id() {
  let q = make_query(ResourceType::Any, ResourceClass::In);
  assert_eq!(q.txid(), 1, "make_query builds the query with txid 1");
}

#[test]
fn truncated_event_collects_nothing() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  q.handle_event(QueryEvent::Truncated);
  assert_eq!(q.answers.len(), 0, "a Truncated event collects no answer");
}

#[test]
fn answer_in_non_matching_class_is_dropped() {
  let mut q = make_query(ResourceType::A, ResourceClass::In);
  let mut msg = make_a_response(b"printer", [192, 168, 1, 10]);
  // The CLASS field sits at header(12) + name(9) + rtype(2) = bytes 23..25.
  msg[23] = 0x00;
  msg[24] = 0xFF; // CLASS = 255 (ANY), not IN
  inject_a_record(&mut q, &msg);
  assert_eq!(
    q.answers.len(),
    0,
    "an answer whose class doesn't match the query (and isn't ANY) is dropped"
  );
}

#[test]
fn answer_with_undecodable_rdata_is_dropped() {
  let mut q = make_query(ResourceType::Ptr, ResourceClass::In);
  // A PTR whose RDATA target is truncated (label length 5, no payload), so
  // canonical_rdata() fails and the answer is dropped rather than stored.
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]); // header, an=1
  msg.extend_from_slice(&[6, b'p', b'r', b'i', b'n', b't', b'r', 0]); // name "printr"
  msg.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
  msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
  msg.extend_from_slice(&1u16.to_be_bytes()); // RDLENGTH = 1
  msg.push(5); // truncated target
  inject_a_record(&mut q, &msg);
  assert_eq!(
    q.answers.len(),
    0,
    "an answer with undecodable rdata is dropped"
  );
}

#[test]
fn handle_timeout_is_noop_when_done() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  q.retire();
  assert!(q.handle_timeout(StdInstant::now()).is_ok());
}

#[test]
fn retire_is_idempotent() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  q.retire();
  q.retire(); // second retire is a no-op
  let mut timeouts = 0;
  while let Some(u) = q.poll() {
    if matches!(u, QueryUpdate::Timeout) {
      timeouts += 1;
    }
  }
  assert_eq!(
    timeouts, 1,
    "retire must queue exactly one Timeout terminal"
  );
}

#[test]
fn note_transmit_outcome_without_a_pending_send_is_noop() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  // No poll_transmit happened → awaiting_send_confirm is false → no-op.
  q.note_transmit_outcome(StdInstant::now(), TransmitOutcome::AllDelivered);
  assert_eq!(
    q.retry_count, 0,
    "a result with no in-flight send must not advance the retry budget"
  );
}

#[test]
fn note_duplicate_question_is_noop_when_done() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  q.retire();
  q.note_duplicate_question(StdInstant::now());
  assert!(q.is_done());
}

#[test]
fn retry_budget_exhaustion_retires_the_query() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let mut buf = std::vec![0u8; 512];
  let mut now = StdInstant::now();
  let mut retired = false;
  for _ in 0..(MAX_RETRIES as usize + 5) {
    now += std::time::Duration::from_secs(120); // past the 60s backoff cap
    q.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = q.poll_transmit(now, &mut buf) {
      q.note_transmit_outcome(now, TransmitOutcome::AllDelivered); // confirmed send burns one retry slot
    }
    if q.is_done() {
      retired = true;
      break;
    }
  }
  assert!(
    retired,
    "a query must retire once its MAX_RETRIES budget is exhausted"
  );
  let mut saw_timeout = false;
  while let Some(u) = q.poll() {
    if matches!(u, QueryUpdate::Timeout) {
      saw_timeout = true;
    }
  }
  assert!(saw_timeout, "budget exhaustion queues a Timeout terminal");
}

/// regression test: a query terminated via the duplicate-question path
/// (MAX_RETRIES suppressed slots exhausted) must
///   1. emit exactly one QueryUpdate::Timeout, and
///   2. leave queries_active == 0 and bump queries_timeout once
///      (verified via the Stats snapshot when the `stats` feature is on).
#[test]
fn duplicate_question_exhaustion_produces_timeout_and_correct_stats() {
  #[cfg(feature = "stats")]
  use std::sync::Arc;

  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("host.local.").unwrap();
  let now = StdInstant::now();
  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::A,
    ResourceClass::In,
    1,
    false,
    None,
  );

  // Wire up a Stats instance so we can inspect the gauges/counters.
  #[cfg(feature = "stats")]
  let stats: Arc<hick_trace::stats::Stats> = Arc::default();
  #[cfg(feature = "stats")]
  {
    // Simulate what Endpoint::try_start_query does: bump active, attach stats.
    stats.queries_started(1);
    stats.incr_queries_active(1);
    q.set_stats(stats.clone());
  }

  // Drive `note_duplicate_question` until the budget is exhausted.
  // Each call that finds an imminent transmit consumes one retry slot.
  let mut advanced_now = now;
  for _ in 0..(MAX_RETRIES as usize + 2) {
    if q.is_done() {
      break;
    }
    // Arm the next deadline so the "imminent" check fires.
    // After the first call transmit_pending is false; subsequent calls
    // need the deadline to be due.
    advanced_now += std::time::Duration::from_secs(120);
    q.note_duplicate_question(advanced_now);
  }

  assert!(
    q.is_done(),
    "duplicate-question exhaustion must set done=true"
  );

  // Exactly one Timeout terminal must be queued.
  let mut timeout_count = 0u32;
  while let Some(u) = q.poll() {
    if matches!(u, QueryUpdate::Timeout) {
      timeout_count += 1;
    }
  }
  assert_eq!(
    timeout_count, 1,
    "duplicate-question exhaustion must queue exactly one Timeout"
  );

  // Verify stats are consistent (queries_active back to 0, queries_timeout = 1).
  #[cfg(feature = "stats")]
  {
    let snap = stats.snapshot();
    assert_eq!(
      snap.queries_active, 0,
      "queries_active must be 0 after duplicate-question termination"
    );
    assert_eq!(
      snap.queries_timeout, 1,
      "queries_timeout must be 1 after duplicate-question termination"
    );
  }
}

// ── TransmitOutcome: the §5.2 retry budget and its ladder ─────────────

/// Emit the query's pending datagram, leaving its confirm outstanding.
fn emit_question(q: &mut TestQuery, now: StdInstant) {
  let mut buf = std::vec![0u8; 512];
  q.poll_transmit(now, &mut buf)
    .unwrap()
    .expect("a due query must produce a datagram");
}

#[test]
fn partially_delivered_question_does_not_burn_the_retry_budget() {
  // A question that reached only some of the links the driver fans it onto has
  // not been asked everywhere. Burning a §5.2 retry slot for it would march the
  // query to its retry-budget timeout having never queried the missing link —
  // the same over-advance the §8.1/§8.3 phases suffer under `used > 0`.
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let now = StdInstant::now();

  emit_question(&mut q, now);
  q.note_transmit_outcome(now, TransmitOutcome::PartiallyDelivered);
  assert_eq!(
    q.retry_count, 0,
    "a partially-delivered question must NOT consume a retry slot"
  );
  assert!(
    q.next_deadline.is_some(),
    "it must still re-arm, so the query keeps trying"
  );
  assert!(!q.is_done(), "and it must not be retired");
}

#[test]
fn fully_delivered_question_burns_the_retry_budget() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let now = StdInstant::now();

  emit_question(&mut q, now);
  q.note_transmit_outcome(now, TransmitOutcome::AllDelivered);
  assert_eq!(
    q.retry_count, 1,
    "a fully-delivered question advances the §5.2 budget"
  );
}

#[test]
fn undelivered_question_neither_burns_the_budget_nor_grows_the_interval() {
  // Nothing reached any wire, so §5.2 counts no query to space out. This is the
  // bit-for-bit parity row for the old `delivered = false`.
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let mut now = StdInstant::now();

  let mut previous = None;
  for _ in 0..3 {
    emit_question(&mut q, now);
    q.note_transmit_outcome(now, TransmitOutcome::NoneDelivered);
    assert_eq!(
      q.retry_count, 0,
      "an undelivered question must not consume a retry slot"
    );
    let gap = q.next_deadline.unwrap().duration_since(now);
    if let Some(prev) = previous {
      assert_eq!(
        gap, prev,
        "a fully-failed send does not climb the §5.2 ladder"
      );
    }
    previous = Some(gap);
    now = q.next_deadline.unwrap();
    q.handle_timeout(now).unwrap();
  }
  assert_eq!(
    previous,
    Some(core::time::Duration::from_secs(1)),
    "the undelivered retry stays at the initial §5.2 interval"
  );
}

#[test]
fn repeated_partial_questions_climb_the_rfc_5_2_doubling_ladder() {
  // RFC 6762 §5.2: "the intervals between successive queries MUST increase by at
  // least a factor of two". A partial send puts a real question on the served
  // link's wire every round, so a flat-interval partial resend would violate that
  // for the link that IS being served — while the budget stays frozen, because no
  // slot was spent.
  //
  // The budget cannot stay frozen forever, or a half-reachable link would keep
  // the query alive past every terminal. After `MAX_PARTIAL_ROUNDS` honest
  // partials the next is EXCUSED and spends a slot — carrying the ladder across
  // rather than resetting it, so the served link never sees a shorter interval.
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let mut now = StdInstant::now();

  let mut previous = 0u64;
  let mut spent = 0u32;
  let mut excused = 0u32;
  for round in 0..8 {
    emit_question(&mut q, now);
    let before = q.retry_count;
    q.note_transmit_outcome(now, TransmitOutcome::PartiallyDelivered);
    let deadline = q.next_deadline.expect("a partial send always re-arms");
    let gap = deadline.duration_since(now).as_secs();
    if q.retry_count == before {
      assert!(
        round % 3 != 2,
        "round {round} is the budget-exhausting one and must have been excused"
      );
    } else {
      assert_eq!(
        q.retry_count,
        before + 1,
        "an excused round spends exactly one slot"
      );
      spent += 1;
      excused += 1;
    }
    // §5.2 holds the interval at 60 s, so the doubling requirement only binds
    // below that cap.
    if round > 0 && gap < 60 {
      assert!(
        gap >= previous.saturating_mul(2),
        "§5.2 requires each interval to be at least double the previous one \
         ({gap} s after {previous} s) — round {round}"
      );
    }
    previous = gap;
    now = deadline;
    q.handle_timeout(now).unwrap();
  }
  assert_eq!(
    (spent, excused),
    (2, 2),
    "two of eight partial rounds exhausted the bound and advanced the budget"
  );

  // Recovery is immediate: the first fully-delivered question spends its slot and
  // the ladder resets to the bottom rung.
  emit_question(&mut q, now);
  let before = q.retry_count;
  q.note_transmit_outcome(now, TransmitOutcome::AllDelivered);
  assert_eq!(q.retry_count, before + 1, "recovery spends exactly one slot");
  assert_eq!(
    q.partial_send_streak, 0,
    "a genuine delivery resets the partial ladder — an excused one does not"
  );
  assert_eq!(
    q.next_deadline.unwrap().duration_since(now),
    core::time::Duration::from_secs(4),
    "and the schedule returns to the plain §5.2 walk for the slots now spent"
  );
}

#[test]
fn the_first_partial_rungs_are_the_plain_5_2_intervals() {
  // The head of the ladder, exactly: 1 s, then 2 s while the budget is frozen,
  // then the EXCUSED round at 4 s — never back at the flat 1 s the freshly-spent
  // budget slot would otherwise index.
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let mut now = StdInstant::now();
  for want in [1u64, 2, 4] {
    emit_question(&mut q, now);
    q.note_transmit_outcome(now, TransmitOutcome::PartiallyDelivered);
    let deadline = q.next_deadline.expect("a partial send always re-arms");
    assert_eq!(
      deadline.duration_since(now).as_secs(),
      want,
      "expected a {want} s rung"
    );
    now = deadline;
    q.handle_timeout(now).unwrap();
  }
  assert_eq!(
    q.retry_count, 1,
    "only the excused third round may have spent a slot"
  );
}

#[test]
fn a_permanently_partial_question_still_reaches_its_terminal_timeout() {
  // Without the bound the §5.2 budget never advances on a partial send, so a
  // half-reachable link keeps a query re-asking on the growing partial interval
  // forever and the caller's `QueryUpdate::Timeout` never arrives.
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let mut now = StdInstant::now();
  for _ in 0..64 {
    if q.is_done() {
      break;
    }
    emit_question(&mut q, now);
    q.note_transmit_outcome(now, TransmitOutcome::PartiallyDelivered);
    now = q.next_deadline.expect("a partial send always re-arms");
    q.handle_timeout(now).unwrap();
  }
  assert!(
    q.is_done(),
    "a permanently half-delivered question must still retire, not hang"
  );
}

/// RFC 6762 §7.3 treats a peer's identical question as OUR send, so the slot it
/// consumes must clear exactly what an all-delivered send clears — the core's
/// patience counter included.
///
/// Leaving `partial_rounds` charged carries the previous slot's unmet obligation
/// into a slot that met its own, so the NEXT genuine partial is EXCUSED early:
/// a §5.2 retry slot spent on behalf of a link that was never asked.
#[test]
fn duplicate_suppression_clears_the_partial_bound_like_a_delivered_send() {
  let mut q = make_query(ResourceType::Any, ResourceClass::Any);
  let mut now = StdInstant::now();

  // Charge the bound to exactly one round short of the excusal.
  for _ in 0..MAX_PARTIAL_ROUNDS {
    emit_question(&mut q, now);
    q.note_transmit_outcome(now, TransmitOutcome::PartiallyDelivered);
    now = q.next_deadline.expect("a partial send always re-arms");
    q.handle_timeout(now).unwrap();
  }
  assert_eq!(q.partial_rounds, MAX_PARTIAL_ROUNDS);

  // A peer multicasts the same question just as ours becomes due.
  assert!(
    q.note_duplicate_question(now),
    "a suppressed retransmit must actually consume the slot"
  );
  assert_eq!(
    q.partial_rounds, 0,
    "the peer's query was asked on every link, so nothing is left outstanding"
  );
  assert_eq!(
    q.partial_send_streak, 0,
    "…which is the same reason the §5.2 ladder resets here"
  );

  // The next honestly-partial round is therefore held, not excused.
  now = q.next_deadline.expect("suppression arms the next slot");
  q.handle_timeout(now).unwrap();
  emit_question(&mut q, now);
  let before = q.retry_count;
  q.note_transmit_outcome(now, TransmitOutcome::PartiallyDelivered);
  assert_eq!(
    q.retry_count, before,
    "the first partial after a full slot must not be excused — the bound was \
     cleared, so this round is held honestly"
  );
  assert_eq!(q.partial_rounds, 1);
}

/// The absolute `timeout_deadline` can terminate a query while a question is
/// still awaiting its confirm. `terminate` clears both deadlines, so a late
/// confirm that re-armed `next_deadline` would hand the driver a wakeup for a
/// query that will never transmit again — `poll_timeout` does not screen `done`.
#[test]
fn a_late_confirm_on_a_terminated_query_arms_no_wakeup() {
  let handle = QueryHandle::from_raw(0);
  let qname = Name::try_from_str("printer.local.").unwrap();
  let start = StdInstant::now();
  let deadline = start + core::time::Duration::from_millis(500);
  let mut q: TestQuery = TestQuery::try_new(
    handle,
    qname,
    ResourceType::Any,
    ResourceClass::Any,
    1,
    false,
    Some(deadline),
  );

  emit_question(&mut q, start);
  assert!(q.awaiting_send_confirm);

  // The absolute deadline fires first: the query is terminal and quiescent.
  let late = start + core::time::Duration::from_secs(1);
  q.handle_timeout(late).unwrap();
  assert!(q.is_done());
  assert!(q.poll_timeout().is_none());

  // The parked datagram's confirm finally lands.
  q.note_transmit_outcome(late, TransmitOutcome::AllDelivered);
  assert!(
    !q.awaiting_send_confirm,
    "the token is still resolved — a terminal query must not stay awaiting"
  );
  assert!(
    q.poll_timeout().is_none(),
    "a finished query must not re-arm a deadline the driver would wake for"
  );
}

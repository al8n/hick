use mdns_proto::{
  CollectedAnswer,
  wire::{ResourceClass, ResourceType},
};

use super::next_answer_by_seq;

/// A distinct synthetic answer carrying `seq` (encoded into rdata so answers
/// don't coalesce). Mirrors `hick-reactor`'s test answer helper.
fn answer(seq: u64) -> CollectedAnswer {
  CollectedAnswer::from_parts(
    ResourceType::Ptr,
    ResourceClass::In,
    seq.to_be_bytes().to_vec(),
    seq,
  )
}

/// The selection must follow `seq`, NOT the iterator's (slab-key) order. This
/// reproduces the post-eviction slab-key reuse layout: a higher-seq answer
/// occupies a lower slab key and is therefore yielded FIRST by the snapshot
/// iterator, ahead of an older retained lower-seq answer. `next_answer_by_seq`
/// must still pick the lower seq.
#[test]
fn picks_min_seq_not_first_iterated() {
  // Iterator order [5, 2]: seq 5 sits at the reused low slab key, seq 2 after.
  let snapshot = [answer(5), answer(2)];
  let picked = next_answer_by_seq(snapshot.iter(), 0).expect("an answer is pending");
  assert_eq!(
    picked.seq(),
    2,
    "must surface the minimum seq >= last, not the first iterated (5)"
  );
}

/// Walking `last` forward across an out-of-order snapshot must deliver EVERY
/// retained answer exactly once, in strict seq order — the old first-match
/// logic would jump `last` past the lower-seq entries and strand them.
#[test]
fn walks_every_retained_answer_in_seq_order() {
  // Out-of-slab-order snapshot with a FIFO gap (seq 0/1 were evicted): the
  // lowest retained seq is 2. Keys deliberately scrambled.
  let snapshot = [answer(4), answer(2), answer(6), answer(3), answer(5)];
  let mut last = 0u64;
  let mut delivered = Vec::new();
  while let Some(a) = next_answer_by_seq(snapshot.iter(), last) {
    delivered.push(a.seq());
    last = a.seq().saturating_add(1);
  }
  assert_eq!(
    delivered,
    vec![2, 3, 4, 5, 6],
    "every retained answer delivered once, in seq order, none skipped"
  );
}

/// Nothing newer than `last` → no answer (terminal/park path).
#[test]
fn none_when_all_already_delivered() {
  let snapshot = [answer(2), answer(3)];
  assert!(
    next_answer_by_seq(snapshot.iter(), 4).is_none(),
    "no answer with seq >= 4 is present"
  );
  assert!(
    next_answer_by_seq([].iter(), 0).is_none(),
    "empty snapshot yields nothing"
  );
}

use super::*;
use mdns_proto::{
  QueryUpdate,
  wire::{ResourceClass, ResourceType},
};

/// A distinct synthetic answer keyed by `tag` (encoded into the rdata so
/// different tags don't coalesce).
fn answer(tag: u16) -> CollectedAnswer {
  CollectedAnswer::from_parts(
    ResourceType::Ptr,
    ResourceClass::In,
    tag.to_be_bytes().to_vec(),
    tag as u64,
  )
}

#[test]
fn mailbox_coalesces_duplicate_answers() {
  // A re-collected record (same rtype/rclass/rdata) must not accumulate.
  let mut mb = QueryMailbox::new();
  mb.push_answer(answer(7));
  mb.push_answer(answer(7));
  assert_eq!(mb.answers.len(), 1);
  assert!(matches!(mb.drain(), Drained::Event(QueryEvent::Answer(_))));
  assert!(matches!(mb.drain(), Drained::Empty));
}

#[test]
fn mailbox_bounds_backlog_dropping_oldest() {
  // a flood of distinct answers cannot grow the queue past the
  // cap; the oldest are dropped.
  let mut mb = QueryMailbox::new();
  let overflow: u16 = 64;
  for i in 0..(MAX_QUERY_EVENT_BACKLOG as u16 + overflow) {
    mb.push_answer(answer(i));
  }
  assert_eq!(mb.answers.len(), MAX_QUERY_EVENT_BACKLOG);
  // The drops are counted so the loss is observable.
  assert_eq!(mb.dropped, u64::from(overflow));
  // The first `overflow` answers were evicted, so the oldest survivor is
  // `tag == overflow`.
  match mb.drain() {
    Drained::Event(QueryEvent::Answer(a)) => {
      assert_eq!(a.rdata_slice(), &overflow.to_be_bytes()[..]);
    }
    _ => panic!("expected an answer at the head of the queue"),
  }
}

#[test]
fn mailbox_record_dropped_accumulates_with_drop_oldest() {
  // upstream (proto-cap) evictions fold into the same counter as
  // the mailbox's own drop-oldest.
  let mut mb = QueryMailbox::new();
  mb.record_dropped(3); // e.g. proto evicted 3 before the driver saw them
  for i in 0..(MAX_QUERY_EVENT_BACKLOG as u16 + 2) {
    mb.push_answer(answer(i));
  }
  // 3 upstream + 2 mailbox drop-oldest.
  assert_eq!(mb.dropped, 5);
}

#[test]
fn mailbox_terminal_reserved_under_answer_pressure() {
  // The terminal slot is separate from the bounded answer ring, so a flood
  // never drops it.
  let mut mb = QueryMailbox::new();
  for i in 0..(MAX_QUERY_EVENT_BACKLOG as u16 + 64) {
    mb.push_answer(answer(i));
  }
  mb.set_terminal(QueryUpdate::Done);
  let mut answers = 0usize;
  let mut got_terminal = false;
  loop {
    match mb.drain() {
      Drained::Event(QueryEvent::Answer(_)) => answers += 1,
      Drained::Event(QueryEvent::Terminal(_)) => got_terminal = true,
      Drained::Ended | Drained::Empty => break,
    }
  }
  assert_eq!(answers, MAX_QUERY_EVENT_BACKLOG);
  assert!(got_terminal, "terminal must survive answer backpressure");
}

#[test]
fn mailbox_drains_answers_then_terminal_then_ends() {
  let mut mb = QueryMailbox::new();
  mb.push_answer(answer(1));
  mb.push_answer(answer(2));
  mb.set_terminal(QueryUpdate::Done);
  assert!(matches!(mb.drain(), Drained::Event(QueryEvent::Answer(_))));
  assert!(matches!(mb.drain(), Drained::Event(QueryEvent::Answer(_))));
  assert!(matches!(
    mb.drain(),
    Drained::Event(QueryEvent::Terminal(_))
  ));
  // Terminal is the last event; subsequent drains report end-of-stream.
  assert!(matches!(mb.drain(), Drained::Ended));
  assert!(matches!(mb.drain(), Drained::Ended));
}

// regression: a single consumer parked on the doorbell must
// receive an ENTIRE batch that the driver delivered with one ring — no
// events stranded. (Concurrent waiters are ruled out at compile time by
// `Query::next(&mut self)`, so the single-waiter wakeup is all we test.)
#[tokio::test]
async fn doorbell_wakes_parked_consumer_for_full_batch() {
  let (mailbox, doorbell_tx, doorbell_rx) = new_mailbox();
  let mb_consumer = Arc::clone(&mailbox);

  let consumer = tokio::spawn(async move {
    let mut answers = 0usize;
    let mut got_terminal = false;
    loop {
      let drained = lock(&mb_consumer).drain();
      match drained {
        Drained::Event(QueryEvent::Answer(_)) => answers += 1,
        Drained::Event(QueryEvent::Terminal(_)) => got_terminal = true,
        Drained::Ended => break,
        Drained::Empty => {
          if doorbell_rx.recv().await.is_err() {
            break;
          }
        }
      }
    }
    (answers, got_terminal)
  });

  // Let the consumer reach the empty-mailbox park before we deliver.
  tokio::time::sleep(std::time::Duration::from_millis(20)).await;

  {
    let mut mb = lock(&mailbox);
    for i in 0..5u16 {
      mb.push_answer(answer(i));
    }
    mb.set_terminal(QueryUpdate::Done);
  }
  // A single ring for the whole batch — the parked consumer must still
  // drain all five answers and the terminal.
  let _ = doorbell_tx.try_send(());

  let (answers, got_terminal) = consumer.await.expect("consumer task panicked");
  assert_eq!(answers, 5);
  assert!(got_terminal);
}

#[test]
fn dropped_handle_tracks_mailbox_drops() {
  // The handle shares the mailbox, so it keeps reflecting drops after the
  // `Query` it came from has been moved away (e.g. into a stream adapter).
  let (mailbox, _tx, _rx) = new_mailbox();
  let handle = DroppedHandle {
    mailbox: Arc::clone(&mailbox),
  };
  assert_eq!(handle.get(), 0);
  // Upstream (proto-cap) evictions.
  lock(&mailbox).record_dropped(4);
  assert_eq!(handle.get(), 4);
  // Mailbox drop-oldest under a flood folds into the same counter.
  for i in 0..(MAX_QUERY_EVENT_BACKLOG as u16 + 3) {
    lock(&mailbox).push_answer(answer(i));
  }
  assert_eq!(handle.get(), 4 + 3);
}

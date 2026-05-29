//! Caller-side handle for a running query.

use std::{
  collections::VecDeque,
  sync::{Arc, Mutex, MutexGuard},
};

use mdns_proto::{CollectedAnswer, QueryHandle, QueryUpdate};

use crate::{command::Command, error::CancelError};

/// Upper bound on undelivered answers buffered per query.
///
/// The proto layer's `max_answers` bounds the *collected* answer set; this is
/// an independent backstop on the *undelivered event* backlog so a peer that
/// streams matching answers faster than the application drains
/// [`Query::next`] cannot grow the queue without bound. In normal operation
/// the consumer keeps up and the backlog stays near zero; the cap only
/// engages under a pathological slow-consumer + flood, where
/// [`QueryMailbox::push_answer`] coalesces duplicates and drops the oldest
/// pending answer. The terminal event has its own reserved slot and is never
/// dropped.
const MAX_QUERY_EVENT_BACKLOG: usize = 1024;

/// Per-answer event surfaced on the [`Query`] stream.
#[derive(Debug, Clone)]
pub enum QueryEvent {
  /// A new answer collected by the underlying state machine.
  ///
  /// The answer stream is **lossy under sustained backpressure**: if the
  /// application drains [`Query::next`] slower than answers arrive, the
  /// oldest buffered answers are dropped once the per-query backlog fills
  /// (see [`Query::dropped_answers`] to observe how many). Discovery is
  /// eventually-consistent — mDNS responders re-advertise — so a dropped
  /// answer is normally re-collected, but a caller must not assume the
  /// stream is gap-free.
  Answer(CollectedAnswer),
  /// The query reached a terminal state. Always the last event delivered,
  /// and never dropped under backpressure.
  Terminal(QueryUpdate),
}

/// Bounded, coalescing delivery buffer shared between the driver task (which
/// fills it) and the [`Query`] handle (which drains it via [`Query::next`]).
///
/// answers are bounded ([`MAX_QUERY_EVENT_BACKLOG`]) and coalesced
/// by `(rtype, rclass, rdata)` so a flooding peer cannot grow the queue, while
/// the terminal event keeps a dedicated slot so it is delivered even under
/// answer backpressure.
pub(crate) struct QueryMailbox {
  answers: VecDeque<CollectedAnswer>,
  terminal: Option<QueryUpdate>,
  /// Set once the terminal has been handed to the consumer, so subsequent
  /// drains report end-of-stream rather than waiting forever.
  terminal_delivered: bool,
  /// running count of answers dropped by the backlog cap, so the
  /// otherwise-silent loss is observable via [`Query::dropped_answers`].
  dropped: u64,
}

/// Result of draining one event from a [`QueryMailbox`].
enum Drained {
  /// An event is ready for the consumer.
  Event(QueryEvent),
  /// No more events will ever arrive (terminal already delivered).
  Ended,
  /// Nothing ready right now; the consumer should wait for a wakeup.
  Empty,
}

impl QueryMailbox {
  fn new() -> Self {
    Self {
      answers: VecDeque::new(),
      terminal: None,
      terminal_delivered: false,
      dropped: 0,
    }
  }

  /// Buffer a newly collected answer. Coalesces a re-collected record (same
  /// `rtype`/`rclass` and case-folded rdata identity) onto the pending copy
  /// instead of accumulating, and drops the oldest pending answer (incrementing
  /// the dropped counter) once the backlog cap is reached.
  ///
  /// coalescing compares the case-FOLDED `rdata_key` (DNS names are
  /// case-insensitive), so case-only variants of one logical record collapse to
  /// a single delivered answer rather than reaching the caller as duplicates.
  /// The newer copy replaces the slot, keeping its (display-case) rdata.
  pub(crate) fn push_answer(&mut self, ans: CollectedAnswer) {
    if let Some(slot) = self.answers.iter_mut().find(|a| {
      a.rtype() == ans.rtype() && a.rclass() == ans.rclass() && a.rdata_key() == ans.rdata_key()
    }) {
      *slot = ans;
      return;
    }
    if self.answers.len() >= MAX_QUERY_EVENT_BACKLOG && self.answers.pop_front().is_some() {
      self.dropped = self.dropped.saturating_add(1);
    }
    self.answers.push_back(ans);
  }

  /// Account for answers lost UPSTREAM of the mailbox — i.e. evicted by the
  /// proto `max_answers` cap before the driver could scan them.
  /// Folded into the same public [`Query::dropped_answers`] counter as the
  /// mailbox's own drop-oldest, so every loss path is observable through one
  /// number.
  pub(crate) fn record_dropped(&mut self, n: u64) {
    self.dropped = self.dropped.saturating_add(n);
  }

  /// Record the terminal event in its reserved slot (idempotent).
  pub(crate) fn set_terminal(&mut self, terminal: QueryUpdate) {
    if self.terminal.is_none() && !self.terminal_delivered {
      self.terminal = Some(terminal);
    }
  }

  /// Pull the next event for the consumer: answers first (FIFO), then the
  /// reserved terminal, then end-of-stream.
  fn drain(&mut self) -> Drained {
    if let Some(ans) = self.answers.pop_front() {
      Drained::Event(QueryEvent::Answer(ans))
    } else if let Some(terminal) = self.terminal.take() {
      self.terminal_delivered = true;
      Drained::Event(QueryEvent::Terminal(terminal))
    } else if self.terminal_delivered {
      Drained::Ended
    } else {
      Drained::Empty
    }
  }
}

/// Lock the mailbox, recovering the inner guard if a previous holder panicked
/// (we never hold the lock across a fallible operation, so the data is sound).
fn lock(mailbox: &Mutex<QueryMailbox>) -> MutexGuard<'_, QueryMailbox> {
  mailbox
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Handle to an in-flight query.
///
/// Dropping the handle implicitly cancels the query.
pub struct Query {
  handle: QueryHandle,
  mailbox: Arc<Mutex<QueryMailbox>>,
  /// Capacity-1 wakeup signal: the driver rings it after filling the mailbox.
  /// Closure of the sender (driver dropped our `QueryCtx`) means no further
  /// events will arrive.
  doorbell: async_channel::Receiver<()>,
  cmd: async_channel::Sender<Command>,
}

impl Query {
  pub(crate) fn new(
    handle: QueryHandle,
    mailbox: Arc<Mutex<QueryMailbox>>,
    doorbell: async_channel::Receiver<()>,
    cmd: async_channel::Sender<Command>,
  ) -> Self {
    Self {
      handle,
      mailbox,
      doorbell,
      cmd,
    }
  }

  /// The underlying proto-layer query handle.
  #[inline]
  pub const fn handle(&self) -> QueryHandle {
    self.handle
  }

  /// Number of answers dropped so far because the per-query backlog filled.
  /// Monotonic for the life of the query. A non-zero, growing
  /// value means the consumer is not keeping up with a burst of answers and
  /// some [`QueryEvent::Answer`] values were discarded; see that variant for
  /// the lossy-stream contract.
  pub fn dropped_answers(&self) -> u64 {
    lock(&self.mailbox).dropped
  }

  /// A cheap, cloneable view of this query's dropped-answer counter that stays
  /// valid after the `Query` is moved (e.g. into a stream adapter). Shares the
  /// mailbox, so it reports the same count as [`Self::dropped_answers`]. Used by
  /// the discovery layer to fold the browse query's drops into
  /// [`crate::Lookup::dropped`].
  pub(crate) fn dropped_handle(&self) -> DroppedHandle {
    DroppedHandle {
      mailbox: Arc::clone(&self.mailbox),
    }
  }

  /// Wait for the next answer or terminal. Returns `None` once the query has
  /// ended (terminal delivered) or the driver task has exited.
  ///
  /// Single-consumer: this takes `&mut self`, so there is at most one
  /// in-flight `next()` future per `Query`. That is deliberate — the wakeup
  /// path assumes one waiter, and it makes the lossy-stream contract on
  /// [`QueryEvent::Answer`] the only source of gaps.
  pub async fn next(&mut self) -> Option<QueryEvent> {
    loop {
      match lock(&self.mailbox).drain() {
        Drained::Event(ev) => return Some(ev),
        Drained::Ended => return None,
        Drained::Empty => {}
      }
      // Nothing buffered: wait for the driver to ring the doorbell. A closed
      // doorbell means the driver dropped our context — do one final drain
      // (a terminal it set just before exiting is still in the mailbox).
      if self.doorbell.recv().await.is_err() {
        return match lock(&self.mailbox).drain() {
          Drained::Event(ev) => Some(ev),
          _ => None,
        };
      }
    }
  }

  /// Explicitly cancel the query. Equivalent to dropping the handle but
  /// returns an error if the driver task has already exited.
  pub async fn cancel(self) -> Result<(), CancelError> {
    // Use the channel send through Drop. We can't reasonably do an .await
    // send because Drop is sync; the Drop impl below uses try_send. To
    // surface a deterministic error here, we send before dropping.
    self
      .cmd
      .send(Command::CancelQuery {
        handle: self.handle,
      })
      .await
      .map_err(|_| CancelError::DriverGone)?;
    // The Drop impl will also try_send a CancelQuery; the driver tolerates
    // a second cancel (no-op since the handle is already gone).
    Ok(())
  }
}

impl Drop for Query {
  fn drop(&mut self) {
    let _ = self.cmd.try_send(Command::CancelQuery {
      handle: self.handle,
    });
  }
}

/// A cloneable view of a query's dropped-answer counter, decoupled from the
/// [`Query`] handle's lifetime (see [`Query::dropped_handle`]).
pub(crate) struct DroppedHandle {
  mailbox: Arc<Mutex<QueryMailbox>>,
}

impl DroppedHandle {
  /// The query's current dropped-answer count.
  pub(crate) fn get(&self) -> u64 {
    lock(&self.mailbox).dropped
  }
}

/// Construct a fresh mailbox plus its capacity-1 doorbell channel. Returns the
/// shared mailbox, the driver-side doorbell sender, and the consumer-side
/// doorbell receiver.
pub(crate) fn new_mailbox() -> (
  Arc<Mutex<QueryMailbox>>,
  async_channel::Sender<()>,
  async_channel::Receiver<()>,
) {
  let mailbox = Arc::new(Mutex::new(QueryMailbox::new()));
  let (doorbell_tx, doorbell_rx) = async_channel::bounded(1);
  (mailbox, doorbell_tx, doorbell_rx)
}

#[cfg(test)]
mod tests {
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
}

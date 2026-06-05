//! `Query` handle returned by [`Endpoint::start_query`].
//!
//! Holds an [`Rc<EndpointInner>`] + the proto-layer [`QueryHandle`]. The driver
//! task owns the proto `Query` state machine inside `State.queries`; this handle
//! reads collected answers and terminal updates directly off the proto state
//! under a brief borrow, then parks on the shared driver notifier when nothing
//! is ready.
//!
//! Dropping a [`Query`] flags the registration as cancelled and removes it from
//! the proto endpoint, then wakes the driver so any pending transmits queued for
//! the handle stop firing.
//!
//! [`Endpoint::start_query`]: crate::Endpoint::start_query

use core::cell::Cell;
use std::rc::Rc;

use mdns_proto::{CollectedAnswer, QueryHandle, QueryUpdate};

use crate::driver::EndpointInner;

/// One event surfaced by [`Query::next`]: either an answer collected by the
/// underlying state machine, or the terminal update signalling the query has
/// ended (timeout / done).  Answers are delivered in monotonically-increasing
/// `seq()` order; the terminal is always the last event surfaced.
#[derive(Debug, Clone)]
pub enum QueryEvent {
  /// A new answer collected by the underlying state machine.
  Answer(CollectedAnswer),
  /// The query reached a terminal state. Always the last event delivered.
  Terminal(QueryUpdate),
}

/// Handle to an in-flight query.
///
/// Dropping the handle implicitly cancels the query: the driver task removes
/// the proto state machine on its next loop iteration so no further transmits
/// fire against it.
pub struct Query {
  pub(crate) inner: Rc<EndpointInner>,
  pub(crate) handle: QueryHandle,
  /// Latches once the terminal `QueryEvent` has been surfaced via
  /// [`Self::next`], so subsequent calls report end-of-stream rather than
  /// re-polling the proto layer.  `Cell<bool>` interior mutability is sound
  /// because the type is `!Send` (held via [`Rc`]) and [`Self::next`] is the
  /// single consumer.
  pub(crate) terminal_delivered: Cell<bool>,
}

impl Query {
  /// The underlying proto-layer [`QueryHandle`] for this query.
  #[inline]
  pub const fn handle(&self) -> QueryHandle {
    self.handle
  }

  /// Wait for the next answer or terminal.  Returns `None` once the terminal
  /// has been delivered (single-consumer; subsequent calls report
  /// end-of-stream) or the driver has dropped the query entry.
  ///
  /// Borrow discipline: every interaction with `inner.state` is confined to a
  /// short synchronous scope; the only `.await` (`notify.listen()`) runs after
  /// the borrow is dropped at the closing `}` of the scope.
  pub async fn next(&self) -> Option<QueryEvent> {
    loop {
      if self.terminal_delivered.get() {
        return None;
      }
      // Brief synchronous borrow — read one event off the proto state, else
      // fall through to park.  The borrow is dropped at the closing `}` of
      // this block, well before any `.await`.
      {
        let mut st = self.inner.state.borrow_mut();
        // The driver removes our entry on cancellation / endpoint teardown.
        let ctx = st.queries.get(&self.handle)?;
        let last = ctx.last_seq;
        let cancelled = ctx.cancelled;
        // The driver flags a query `errored` when its question can't be encoded
        // into `max_payload` (see `QueryCtx::errored`): it has no standing
        // deadline and can never make progress, so surface end-of-stream rather
        // than park forever. We still drain any already-collected answers below
        // first, then fall through to the terminal.
        let errored = ctx.errored;
        // Surface the next undelivered answer in `seq` order (see
        // [`next_answer_by_seq`] for why min-by-seq, not first-iterated),
        // advancing `last_seq` past it so we don't re-deliver on the next pass.
        let next_answer = next_answer_by_seq(st.endpoint.collected_answers(self.handle), last);
        if let Some(a) = next_answer {
          let new_last = a.seq().saturating_add(1);
          if let Some(ctx) = st.queries.get_mut(&self.handle) {
            ctx.last_seq = new_last;
          }
          return Some(QueryEvent::Answer(a));
        }
        // No pending answer; the proto layer surfaces the terminal once via
        // `poll_query`, then None forever.
        if let Some(t) = st.endpoint.poll_query(self.handle) {
          self.terminal_delivered.set(true);
          // GC: free the driver query slot and the proto pool entry now that
          // the terminal has been observed.  The Drop impl is safe to run
          // afterward: `cancel_query` is idempotent (returns QueryNotFound and
          // is ignored), and `queries.remove` on a missing key is a no-op.
          st.queries.remove(&self.handle);
          let _ = st.endpoint.cancel_query(self.handle);
          return Some(QueryEvent::Terminal(t));
        }
        // Driver flagged us cancelled (drop path) or errored (un-encodable
        // question) and no answer/terminal was pending — surface end-of-stream.
        if cancelled || errored {
          self.terminal_delivered.set(true);
          // GC: same cleanup as the Terminal branch above.
          st.queries.remove(&self.handle);
          let _ = st.endpoint.cancel_query(self.handle);
          return None;
        }
      }
      // Nothing buffered: park on the driver's notify. The borrow above is
      // already dropped, so this await never holds a RefCell borrow.
      self.inner.notify.listen().await;
    }
  }
}

/// Pick the next answer to surface from a query's collected-answer snapshot:
/// the one with the SMALLEST `seq` that is `>= last` (the smallest not-yet-
/// delivered sequence number), cloned out.
///
/// Selecting the minimum — rather than the first item the iterator yields — is
/// load-bearing. `collected_answers` is proto's BOUNDED snapshot backed by a
/// `slab::Slab`, so it iterates in SLAB-KEY order, not `seq` order: once
/// `max_answers` is reached the proto FIFO-evicts the lowest-`seq` entry and the
/// freed low slab key is reused by the next insert, so a higher-`seq` answer can
/// sit at a lower key ahead of older retained lower-`seq` answers. Taking the
/// first item with `seq >= last` (the previous behaviour) would deliver that
/// higher-`seq` answer, jump `last_seq` past it, and PERMANENTLY skip the still-
/// retained lower-`seq` answers — so a peer flooding more than `max_answers`
/// distinct records before the app drains could make browse/lookup/resolve
/// silently miss valid records. Min-by-`seq` keeps delivery strictly ordered
/// regardless of slab layout.
// `'a` reads as single-use, but it cannot be elided at our 1.91 MSRV:
// anonymous lifetimes in `impl Trait` are unstable there (rustc E0658).
#[allow(single_use_lifetimes)]
fn next_answer_by_seq<'a>(
  answers: impl Iterator<Item = &'a CollectedAnswer>,
  last: u64,
) -> Option<CollectedAnswer> {
  answers
    .filter(|a| a.seq() >= last)
    .min_by_key(|a| a.seq())
    .cloned()
}

impl Drop for Query {
  fn drop(&mut self) {
    // Flag cancellation, then remove the proto-layer query immediately so any
    // pending transmits stop firing.  Wake the driver so it observes the
    // change on its next loop iteration.
    {
      let mut st = self.inner.state.borrow_mut();
      st.flag_query_cancelled(self.handle);
      let _ = st.endpoint.cancel_query(self.handle);
      st.queries.remove(&self.handle);
    }
    // Durable wake (see `EndpointInner::dirty`): removing the query may free the
    // last handle, and the driver must re-settle to observe the change even if a
    // bare notify would be lost across its send-awaits.
    self.inner.mark_dirty();
  }
}

#[cfg(test)]
mod tests;

//! Query state machine — retry backoff + answer collection + KAS hints.

mod retry;

use crate::{
  Instant, Name, Pool, QueryHandle,
  backend::RdataBuf,
  error::{HandleTimeoutError, TransmitError},
  event::{QueryEvent, QueryUpdate},
  service::{FamilyPatience, PhaseAdvance, classify_advance},
  transmit::{Transmit, TransmitObligation, TransmitDelivery},
  wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
};

#[cfg(all(test, feature = "std", feature = "slab"))]
mod tests;

/// Maximum retries before giving up.
const MAX_RETRIES: u32 = 8;

/// Default maximum number of collected answers per query.
const DEFAULT_MAX_ANSWERS: usize = 256;

/// One collected answer record for a Query.
///
/// Stores the resource type, class, and raw rdata bytes so that
/// deduplication, qtype/qclass filtering, and the answer cap can all
/// be applied before inserting into the pool.
#[derive(Debug, Clone)]
pub struct CollectedAnswer {
  rtype: ResourceType,
  rclass: ResourceClass,
  rdata: RdataBuf,
  /// the case-FOLDED identity form of `rdata` (PTR/SRV/NSEC/CNAME
  /// names lowercased) used for dedup, cap accounting, and mailbox coalescing —
  /// while `rdata` keeps the original case for display. Two answers that are
  /// the same logical record differing only in DNS name case share this key,
  /// so a responder cannot evict/flood the bounded answer set with case
  /// permutations.
  ///
  /// `None` means the folded form is byte-identical to `rdata` (the
  /// common case: A/AAAA/TXT/unknown rdata, or a name already lowercase), so we
  /// store ONLY one buffer — folding a large TXT/unknown flood does not double
  /// per-answer memory. [`Self::rdata_key`] resolves `None` to `rdata`.
  rdata_key: Option<RdataBuf>,
  /// Monotonically increasing insertion sequence number within a single Query.
  /// Used to identify the oldest entry for FIFO eviction.
  seq: u64,
}

impl CollectedAnswer {
  /// Construct an answer from its parts.
  ///
  /// Hidden from the documented surface: the `Query` state machine builds
  /// these internally, but downstream crates need a way to synthesize them
  /// for tests and synthetic answer feeds. Synthetic answers carry opaque
  /// rdata with no DNS-name semantics, so the dedup key is the rdata itself
  /// (`rdata_key` is `None`, i.e. identical to `rdata`).
  #[doc(hidden)]
  pub fn from_parts(
    rtype: ResourceType,
    rclass: ResourceClass,
    rdata: impl Into<RdataBuf>,
    seq: u64,
  ) -> Self {
    Self {
      rtype,
      rclass,
      rdata: rdata.into(),
      rdata_key: None,
      seq,
    }
  }

  /// The resource type of this answer.
  #[inline(always)]
  pub fn rtype(&self) -> ResourceType {
    self.rtype
  }

  /// The resource class of this answer.
  #[inline(always)]
  pub fn rclass(&self) -> ResourceClass {
    self.rclass
  }

  /// The raw rdata bytes of this answer, with DNS name case PRESERVED (for
  /// display). For identity/dedup comparisons use [`Self::rdata_key`].
  #[inline(always)]
  pub fn rdata_slice(&self) -> &[u8] {
    self.rdata.as_ref()
  }

  /// The case-FOLDED identity form of the rdata. Equal for two
  /// answers that are the same logical record differing only in DNS name case;
  /// callers coalescing/deduping answers should compare this, not
  /// [`Self::rdata_slice`] (which preserves display case). resolves
  /// to `rdata` when the folded form is identical (no separate buffer stored).
  #[inline(always)]
  pub fn rdata_key(&self) -> &[u8] {
    self.rdata_key.as_deref().unwrap_or(self.rdata.as_ref())
  }

  /// Insertion sequence number (monotonically increasing per-Query).
  ///
  /// Used for FIFO eviction: the entry with the lowest `seq` is the oldest.
  #[inline(always)]
  pub fn seq(&self) -> u64 {
    self.seq
  }
}

/// Query state machine. One per outstanding query.
///
/// Driving one means confirming each datagram [`Query::poll_transmit`] hands out
/// — via [`Query::note_transmit_outcome`] — before invoking any other
/// state-mutating entry point on this query. [`Query::poll_transmit`] documents
/// that contract in full.
pub struct Query<I, AN, EV> {
  handle: QueryHandle,
  #[cfg(feature = "stats")]
  stats: Option<std::sync::Arc<hick_trace::stats::Stats>>,
  qname: Name,
  qtype: ResourceType,
  qclass: ResourceClass,
  txid: u16,
  /// Number of datagrams sent so far (including the initial query).
  /// Incremented by `poll_transmit`; drives both the §5.2 backoff interval
  /// and the retry budget (`MAX_RETRIES`).
  retry_count: u32,
  next_deadline: Option<I>,
  answers: AN,
  pending_updates: EV,
  done: bool,
  /// latch tracking whether the terminal `QueryUpdate` has
  /// already been returned to the caller via `Endpoint::poll_query`.
  /// Used so the terminal is emitted exactly once even when both
  /// `pending_updates` push and the `is_done` backstop would fire — and
  /// to short-circuit subsequent `poll_query` calls on a terminated
  /// query to `None`.
  terminal_emitted: bool,
  /// Maximum number of answers to collect before evicting the oldest (FIFO).
  max_answers: usize,
  /// Monotonic counter incremented on every successful answer insertion.
  /// Each `CollectedAnswer` records the value at the time of its insertion;
  /// eviction picks the entry with the lowest `next_seq` (i.e. the oldest).
  next_seq: u64,
  /// True when a datagram is ready to be built and sent.
  /// Set on construction (first send is immediately due) and on each
  /// `handle_timeout` tick that fires a retry; cleared after `poll_transmit`
  /// consumes it. This prevents a driver looping on `poll_transmit` from
  /// sending the same query continuously instead of honoring the backoff.
  transmit_pending: bool,
  /// set by `poll_transmit` for the datagram it just produced, and
  /// cleared by `note_transmit_outcome` once the driver reports the send result.
  /// The retry budget (`retry_count`) and the next-retry deadline are advanced
  /// ONLY on a confirmed-delivered send — a datagram that fails on every socket
  /// is re-attempted without consuming the budget, so a transient send failure
  /// can never time out a query that never actually put a question on the wire.
  awaiting_send_confirm: bool,
  /// Consecutive `PartiallyDelivered` sends since the last budget advance — the
  /// extra doubling steps applied to the §5.2 backoff while the budget is frozen.
  /// A partial send puts a real question on the served link's wire every re-arm,
  /// and §5.2 requires "the intervals between successive queries MUST increase by
  /// at least a factor of two"; a fully-failed send reaches no wire and so
  /// neither uses nor advances this.
  partial_send_streak: u32,
  /// Per family ([0] = v4, [1] = v6): consecutive sends in which THAT family was
  /// obligated and missed a question some other family carried — the core's own
  /// patience, bounded by `MAX_PARTIAL_ROUNDS`. A partial send freezes the §5.2
  /// budget, so without the bound a half-reachable family would keep a question
  /// re-asking on the growing partial interval and the query would never reach its
  /// terminal timeout. Once EVERY missing family has spent the bound the send is
  /// excused and the budget advances. Reset by that family's own delivery and by it
  /// ceasing to be obligated; left ALONE by a wholly-failed round (see
  /// [`classify_advance`]).
  ///
  /// A query takes per-family PATIENCE and nothing else from the per-family
  /// confirm. It has no §5.2 requery scheduler and races no record TTL — the cache
  /// refreshes on receive — so there is no per-family staleness for it to anchor
  /// on, and its backoff stays measured from confirm time.
  partial_rounds: [FamilyPatience; 2],
  /// When `true`, questions are emitted with the QU bit set (RFC 6762 §5.4):
  /// the sender prefers a unicast response rather than a multicast one.
  unicast_response: bool,
  /// Absolute instant at which this query should auto-cancel regardless of
  /// the retry budget (`None` means no hard deadline beyond the retry budget).
  timeout_deadline: Option<I>,
  /// Test-only: silence [`Query::assert_no_live_send_confirm`] so a test can
  /// drive the entry points the way a NON-COMPLIANT driver would and pin what a
  /// release build actually does. `cfg(test)`: it does not exist in a shipped
  /// build and no public API sets it.
  #[cfg(test)]
  contract_assertions_off: bool,
}

impl<I, AN, EV> Query<I, AN, EV>
where
  I: Instant,
  AN: Pool<CollectedAnswer>,
  EV: Pool<QueryUpdate>,
{
  /// Construct a new Query. Its first transmission is immediately due (the
  /// next `poll_transmit` emits it); the retry schedule is then driven off
  /// that send's instant, not construction time.
  ///
  /// * `unicast_response` — when `true`, questions carry the QU bit (RFC 6762 §5.4).
  /// * `timeout_deadline` — optional absolute instant at which the query auto-cancels.
  #[allow(dead_code, clippy::too_many_arguments)]
  pub(crate) fn try_new(
    handle: QueryHandle,
    qname: Name,
    qtype: ResourceType,
    qclass: ResourceClass,
    txid: u16,
    unicast_response: bool,
    timeout_deadline: Option<I>,
  ) -> Self {
    Self {
      handle,
      #[cfg(feature = "stats")]
      stats: None,
      qname,
      qtype,
      qclass,
      txid,
      retry_count: 0,
      // No retry is scheduled yet: the first send is driven by
      // `transmit_pending`, and `poll_transmit` schedules the first retry
      // (+INITIAL_SECS) only after that send actually goes out. This keeps
      // `poll_timeout` from returning `now` right after the first transmit,
      // which would otherwise make a driver re-fire `handle_timeout` at `now`
      // and collapse the first retry interval to zero / push it to 2s.
      next_deadline: None,
      answers: AN::new(),
      pending_updates: EV::new(),
      done: false,
      terminal_emitted: false,
      max_answers: DEFAULT_MAX_ANSWERS,
      next_seq: 0,
      transmit_pending: true,
      awaiting_send_confirm: false,
      partial_send_streak: 0,
      partial_rounds: [FamilyPatience::default(); 2],
      unicast_response,
      timeout_deadline,
      #[cfg(test)]
      contract_assertions_off: false,
    }
  }

  /// Test-only: opt this query out of the debug-build contract assertions.
  ///
  /// The only callers are tests that must reproduce a non-compliant driver to
  /// observe what release builds do when the contract is broken.
  #[cfg(test)]
  pub(crate) fn disable_contract_assertions(&mut self) {
    self.contract_assertions_off = true;
  }

  /// Fail loudly, in debug builds, when a state-mutating entry point runs while
  /// the datagram [`Self::poll_transmit`] produced is still awaiting its
  /// [`Self::note_transmit_outcome`].
  ///
  /// See [`Self::poll_transmit`] for the contract this enforces. It compiles out
  /// of release builds, where `awaiting_send_confirm` alone absorbs the
  /// violation: it makes at most one confirm resolve one datagram, but it cannot
  /// undo state a mid-flight `handle_event` / `handle_timeout` already moved.
  ///
  /// `pub(crate)` so the endpoint's teardown entry points ([`Endpoint::cancel_query`],
  /// [`Endpoint::sweep_terminated_queries`]) can assert it for a query they are
  /// about to drop, which is the case the query's own methods can no longer see.
  ///
  /// [`Endpoint::cancel_query`]: crate::Endpoint::cancel_query
  /// [`Endpoint::sweep_terminated_queries`]: crate::Endpoint::sweep_terminated_queries
  #[inline]
  pub(crate) fn assert_no_live_send_confirm(&self, entry_point: &str) {
    #[cfg(test)]
    if self.contract_assertions_off {
      return;
    }
    debug_assert!(
      !self.awaiting_send_confirm,
      "{entry_point} was called while a datagram from Query::poll_transmit is \
       still awaiting Query::note_transmit_outcome",
    );
  }

  /// Attach the shared [`hick_trace::stats::Stats`] handle from the owning
  /// [`crate::endpoint::Endpoint`]. No allocation — the Arc is cloned from the
  /// endpoint's existing single Arc. Called immediately after construction by
  /// `Endpoint::try_start_query` so that all per-query counters accumulate into
  /// the endpoint-level stats. Before this is called, stats bumps are no-ops
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

  /// Override the maximum number of collected answers (default 256).
  ///
  /// When the pool reaches this limit the oldest entry (FIFO) is evicted to
  /// make room for the incoming answer. Setting `max` to 0 disables collection
  /// entirely.
  #[must_use]
  pub fn with_max_answers(mut self, max: usize) -> Self {
    self.max_answers = max;
    self
  }

  /// Set the maximum number of collected answers in place.  Same semantics
  /// as [`Self::with_max_answers`] but for use after construction (e.g. by
  /// `Endpoint::try_start_query` when threading a `QuerySpec::max_answers`).
  #[inline(always)]
  pub fn set_max_answers(&mut self, max: usize) {
    self.max_answers = max;
  }

  /// Returns the handle assigned at start.
  #[inline(always)]
  pub const fn handle(&self) -> QueryHandle {
    self.handle
  }
  /// Returns the queried name.
  #[inline(always)]
  pub fn qname(&self) -> &Name {
    &self.qname
  }
  /// Returns the queried record type.
  #[inline(always)]
  pub const fn qtype(&self) -> ResourceType {
    self.qtype
  }
  /// Returns the queried class.
  #[inline(always)]
  pub const fn qclass(&self) -> ResourceClass {
    self.qclass
  }
  /// Returns the transaction id used on outgoing queries.
  #[inline(always)]
  pub const fn txid(&self) -> u16 {
    self.txid
  }

  /// Process an event routed to this query by the Endpoint.
  ///
  /// # Contract
  ///
  /// Must NOT be called while a datagram from [`Self::poll_transmit`] is still
  /// awaiting its [`Self::note_transmit_outcome`]; see [`Self::poll_transmit`].
  pub fn handle_event(&mut self, event: QueryEvent<'_>) {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("query", handle = self.handle.raw()).entered();
    self.assert_no_live_send_confirm("Query::handle_event");
    crate::trace::trace!(
      target: "mdns_proto::query",
      handle = self.handle.raw(),
      event = ?core::mem::discriminant(&event),
      "query: handle_event"
    );
    match event {
      QueryEvent::Answer(record) => {
        // TTL=0 records are mDNS "goodbye" / deletion records
        // (RFC 6762 §10.1).  Treating them as live answers would let a
        // peer withdrawing a service inject a ghost entry into
        // `collected_answers`, and under `max_answers` pressure could
        // evict a real answer via FIFO.  The cache layer already
        // handles TTL=0 as removal; for active queries we simply
        // ignore the record.  Callers observe withdrawal indirectly
        // via the cache.
        if record.ttl() == 0 {
          return;
        }
        // qtype filter: drop if rtype doesn't match (unless query is Any).
        let qtype = self.qtype;
        if !qtype.is_any() && record.rtype() != qtype {
          return;
        }
        // qclass filter: drop if rclass doesn't match (unless query is Any).
        let qclass = self.qclass;
        if !qclass.is_any() && record.rclass() != qclass {
          return;
        }

        // store the rdata in canonical (decompressed)
        // wire form. PTR/SRV/NSEC rdata carries a domain name that responders
        // (and this crate's own builder) may compress with a back-pointer into
        // the packet; copying the raw slice would leave a dangling pointer the
        // caller cannot decode once the datagram is gone, and two encodings of
        // the same logical record would not dedupe. A malformed name drops the
        // answer rather than storing undecodable bytes.
        let owned = match record.canonical_rdata() {
          Ok(v) => v,
          Err(_) => return,
        };
        // the case-FOLDED identity key. Dedup/cap/coalescing compare
        // this (DNS names are case-insensitive) so a responder can't flood the
        // bounded answer set with case permutations of one record; `owned`
        // keeps the original case for display.
        let folded = match record.canonical_rdata_folded() {
          Ok(v) => v,
          Err(_) => return,
        };
        // only keep a SEPARATE key buffer when folding actually
        // changed the bytes (a mixed-case name). For A/AAAA/TXT/unknown rdata —
        // and names already lowercase — the folded form equals `owned`, so we
        // store None and avoid doubling memory under a large-rdata flood.
        let rdata_key = if folded == owned { None } else { Some(folded) };
        let key: &[u8] = rdata_key.as_deref().unwrap_or(owned.as_ref());

        // Dedupe: skip if a matching (rtype, rclass, folded-rdata) already in.
        for (_, existing) in self.answers.iter() {
          if existing.rtype() == record.rtype()
            && existing.rclass() == record.rclass()
            && existing.rdata_key() == key
          {
            crate::trace::trace!(
              target: "mdns_proto::query",
              handle = self.handle.raw(),
              rtype = ?record.rtype(),
              "query: answer deduped (already collected)"
            );
            return;
          }
        }

        // A zero cap collects nothing.
        if self.max_answers == 0 {
          return;
        }
        // Make room before inserting. Evict the oldest (lowest-seq, true FIFO)
        // entry when at the logical `max_answers` cap OR when the
        // underlying pool has no vacant slot (a fixed-capacity pool
        // smaller than `max_answers` would otherwise reject every new answer
        // once full, since the `len >= max_answers` check never fires). One
        // eviction frees room for exactly one insert.
        if self.answers.len() >= self.max_answers || self.answers.vacant_key().is_err() {
          let mut victim: Option<(usize, u64)> = None;
          for (key, entry) in self.answers.iter() {
            let s = entry.seq();
            victim = Some(match victim {
              // Existing candidate has a lower (older) seq — keep it.
              Some(prev) if prev.1 <= s => prev,
              _ => (key, s),
            });
          }
          if let Some((victim_key, _)) = victim {
            crate::trace::trace!(
              target: "mdns_proto::query",
              handle = self.handle.raw(),
              "query: evicting oldest answer (cap reached)"
            );
            self.answers.try_remove(victim_key);
          }
        }

        // Insert; advance `next_seq` ONLY on a successful insert so
        // a dropped answer (a degenerate pool that cannot hold it even after
        // eviction) is never accounted as collected — which would otherwise
        // leave a gap in the FIFO seq ordering.
        let new_seq = self.next_seq;
        if self
          .answers
          .insert(CollectedAnswer {
            rtype: record.rtype(),
            rclass: record.rclass(),
            rdata: owned,
            rdata_key,
            seq: new_seq,
          })
          .is_ok()
        {
          self.next_seq = self.next_seq.saturating_add(1);
          crate::trace::trace!(
            target: "mdns_proto::query",
            handle = self.handle.raw(),
            rtype = ?record.rtype(),
            seq = new_seq,
            "query: answer collected"
          );
          #[cfg(feature = "stats")]
          if let Some(s) = self.stat() {
            s.answers_collected(1);
          }
        }
      }
      QueryEvent::Truncated => {
        // Hold off retry — more answers coming.
      }
    }
  }

  /// Next deadline for `handle_timeout`.
  ///
  /// Returns the earlier of `next_deadline` (next retry) and `timeout_deadline`
  /// (absolute query cancellation). A driver that sleeps until this instant is
  /// guaranteed to wake in time to fire the absolute timeout even when the next
  /// retry is scheduled far in the future.
  pub fn poll_timeout(&self) -> Option<I> {
    match (self.next_deadline, self.timeout_deadline) {
      (Some(n), Some(t)) => Some(if n < t { n } else { t }),
      (Some(n), None) => Some(n),
      (None, Some(t)) => Some(t),
      (None, None) => None,
    }
  }

  /// Route EVERY terminal transition through here. Idempotent: a no-op if
  /// the query is already `done`. Sets `done = true`, queues the terminal
  /// `QueryUpdate`, and under `#[cfg(feature="stats")]` bumps the correct
  /// counter (`queries_timeout` or `queries_done`) and decrements
  /// `queries_active` exactly once.
  ///
  /// Callers must pass the appropriate `update`:
  /// * [`QueryUpdate::Timeout`] for timeout/retry-exhaustion/duplicate-question paths.
  /// * [`QueryUpdate::Done`] for voluntary "done" paths (if/when added).
  fn terminate(&mut self, update: QueryUpdate) {
    if self.done {
      return;
    }
    self.done = true;
    self.transmit_pending = false;
    let _ = self.pending_updates.insert(update);
    self.next_deadline = None;
    self.timeout_deadline = None;
    #[cfg(feature = "stats")]
    if let Some(s) = self.stat() {
      match update {
        QueryUpdate::Timeout => s.queries_timeout(1),
        QueryUpdate::Done => {}
      }
      s.queries_done(1);
      s.decr_queries_active(1);
    }
  }

  /// Drive timer-based transitions.
  ///
  /// # Contract
  ///
  /// Must NOT be called while a datagram from [`Self::poll_transmit`] is still
  /// awaiting its [`Self::note_transmit_outcome`]; see [`Self::poll_transmit`].
  pub fn handle_timeout(&mut self, now: I) -> Result<(), HandleTimeoutError> {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("query", handle = self.handle.raw()).entered();
    self.assert_no_live_send_confirm("Query::handle_timeout");
    if self.done {
      return Ok(());
    }

    // Check the absolute deadline before the per-retry deadline. A caller-
    // supplied timeout takes priority over the built-in retry budget.
    if let Some(td) = self.timeout_deadline
      && now >= td
    {
      crate::trace::trace!(
        target: "mdns_proto::query",
        handle = self.handle.raw(),
        "query: absolute timeout deadline reached"
      );
      self.terminate(QueryUpdate::Timeout);
      return Ok(());
    }

    let due = match self.next_deadline {
      Some(d) => d,
      None => return Ok(()),
    };
    if now < due {
      return Ok(());
    }
    // The scheduled retry is due. The retry budget is measured in datagrams
    // actually sent (`retry_count`, incremented by `poll_transmit`); once the
    // full budget is spent, retire the query instead of scheduling more.
    if self.retry_count > MAX_RETRIES {
      crate::trace::trace!(
        target: "mdns_proto::query",
        handle = self.handle.raw(),
        retry_count = self.retry_count,
        "query: retry budget exhausted — timeout"
      );
      self.terminate(QueryUpdate::Timeout);
    } else {
      // Mark a transmit due now and clear the deadline; `poll_transmit` emits
      // the datagram and schedules the following retry. Clearing the deadline
      // makes repeated `handle_timeout` calls before the drain no-ops, so a
      // single fired tick yields exactly one retransmit.
      crate::trace::trace!(
        target: "mdns_proto::query",
        handle = self.handle.raw(),
        retry_count = self.retry_count,
        "query: retry due — arming transmit"
      );
      self.transmit_pending = true;
      self.next_deadline = None;
    }
    Ok(())
  }

  /// Force the query to its terminal TIMEOUT state at the DRIVER's request — used
  /// when the transport can never send the question (e.g. a permanently-too-large
  /// datagram on every reachable family), so the query would otherwise hang. This
  /// is exactly the terminal a timer-driven timeout produces: it marks the query
  /// `done` (so [`Self::is_done`] is true and `Endpoint::handle` freezes any late
  /// answers) and queues a terminal [`QueryUpdate::Timeout`]. The collected answers
  /// stay readable until the caller cancels. No-op if already done.
  ///
  /// A terminal transition is a state mutation like any other, so it is bound by
  /// the same confirm-before-anything contract (see [`Self::poll_transmit`]): the
  /// driver must resolve an outstanding datagram's commit token — a datagram it
  /// cannot send is a confirm no family delivered
  /// — before retiring the query that produced it.
  pub(crate) fn retire(&mut self) {
    self.assert_no_live_send_confirm("Endpoint::retire_query");
    self.terminate(QueryUpdate::Timeout);
  }

  /// Produce the next outgoing datagram, if any. Writes into `buf`.
  ///
  /// Returns `Ok(None)` when the query is done or when no send is currently
  /// due (i.e. `transmit_pending` is false). A single call per scheduled
  /// deadline tick is guaranteed: the pending flag is cleared after the
  /// datagram is built, so a driver looping on this method will not
  /// re-send the query until the next `handle_timeout` fires.
  ///
  /// # The confirm-before-anything contract
  ///
  /// > Once this method returns a datagram, NO other state-mutating entry point
  /// > for this query — [`Self::handle_event`], [`Self::handle_timeout`] — may be
  /// > invoked until that datagram's [`Self::note_transmit_outcome`].
  /// > `poll_transmit` itself is excepted: `transmit_pending` is already cleared,
  /// > so it produces nothing further.
  ///
  /// A driver therefore does `poll_transmit` → send → `note_transmit_outcome` as
  /// one indivisible step, and a send the transport cannot accept right now is
  /// dropped and confirmed as delivered by no family
  /// rather than parked — nothing is lost, because a re-armed question is
  /// re-encoded from live state on the next poll.
  ///
  /// The reason is the same as for a service: "delivered" here already means only
  /// *the kernel accepted the datagram synchronously*, so deferring the confirm
  /// buys no extra fidelity, while the §5.2 retry budget and backoff — which
  /// [`Self::note_transmit_outcome`] alone advances — sit in an undecided state
  /// for the whole interim. An absolute [`Self::poll_timeout`] deadline firing in
  /// that window terminates the query with a question outstanding, and RFC 6762
  /// §7.3 duplicate-question suppression arriving in it re-times a retransmission
  /// the pending confirm is about to reschedule. Debug builds assert the ordering.
  pub fn poll_transmit(
    &mut self,
    _now: I,
    buf: &mut [u8],
  ) -> Result<Option<Transmit>, TransmitError> {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("query", handle = self.handle.raw()).entered();
    if self.done || !self.transmit_pending {
      return Ok(None);
    }
    let buf_len = buf.len();
    let header = Header::new().with_id(self.txid);
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> = MessageBuilder::try_new(buf, header)
      .map_err(|_| {
        TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(
          crate::wire::HEADER_SIZE,
          buf_len,
        ))
      })?;
    b.push_question(&self.qname, self.qtype, self.qclass, self.unicast_response)
      .map_err(|_| TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(0, 0)))?;
    let n = b
      .finish()
      .map_err(|_| TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(0, 0)))?;
    self.transmit_pending = false;
    // do NOT advance the retry budget or schedule the next retry
    // here — the datagram has only been ENCODED. Await the driver's delivery
    // result (`note_transmit_outcome`), which schedules the backoff on a
    // confirmed send and re-attempts (without burning the budget) on failure.
    self.awaiting_send_confirm = true;
    crate::trace::debug!(
      target: "mdns_proto::query",
      handle = self.handle.raw(),
      qname = self.qname.as_str(),
      qtype = ?self.qtype,
      bytes = n,
      "query: poll_transmit emitting question"
    );
    // Sustained: a question that did not reach every obligated link re-arms
    // WITHOUT spending a §5.2 retry slot (see `note_transmit_outcome`), until the
    // core's patience bound (`MAX_PARTIAL_ROUNDS`) excuses the link that keeps
    // missing and the budget resumes.
    //
    // The per-family gate carries §5.2's own floor: the re-arm that follows a
    // partial round is anchored at the EARLIEST family acceptance, so without it
    // the family that accepted late would be re-asked the same question inside
    // one second on its own interface.
    Ok(Some(Transmit::new(
      crate::service::multicast_dst(),
      None,
      n,
      TransmitObligation::Sustained,
      retry::MIN_QUERY_GAP,
    )))
  }

  /// Report the delivery outcome of the datagram most recently produced by
  /// [`Self::poll_transmit`].
  ///
  /// Must be called before ANY other state-mutating entry point for this query —
  /// see [`Self::poll_transmit`] for the ordering contract.
  ///
  /// The §5.2 retry BUDGET advances iff [`TransmitDelivery::all_delivered`] — a
  /// question that reached only some of the links the driver fans it onto has
  /// not been asked everywhere, so spending a retry slot for it would time the
  /// query out having never queried the missing link.
  ///
  /// * **All delivered** — count the transmission against the budget and
  ///   schedule the next retransmit on the §5.2 backoff (+1 s, doubling, capped
  ///   at 60 s).
  /// * **Partially delivered** — the budget is NOT consumed, but the served
  ///   link's wire did carry a real question, so the re-arm climbs the §5.2
  ///   ladder: each consecutive partial doubles the interval, without ever
  ///   burning a retry slot.
  /// * **None delivered** — the budget is NOT consumed and the interval does not
  ///   grow; the query re-attempts after the current backoff, so a transient or
  ///   total send failure retries without a tight spin and can never reach the
  ///   retry-budget timeout having put nothing on the wire.
  ///
  /// A frozen budget cannot stay frozen forever, or a chronically half-reachable
  /// link would keep the query re-asking without ever reaching its terminal
  /// timeout. After `MAX_PARTIAL_ROUNDS` consecutive partials the next one is
  /// EXCUSED and spends a slot — but takes none of the credit a delivery earns:
  /// the §5.2 ladder is carried across the excuse point rather than reset, so the
  /// served link never sees a shorter interval than the one before it.
  pub fn note_transmit_outcome(&mut self, now: I, delivery: TransmitDelivery) {
    if !self.awaiting_send_confirm {
      return;
    }
    self.awaiting_send_confirm = false;
    // The absolute `timeout_deadline` can terminate the query while a send is
    // still awaiting its confirm, and `terminate` clears both deadlines. Re-arming
    // `next_deadline` on a finished query would hand the driver one wakeup for a
    // query that will never transmit again — `poll_timeout` does not screen `done`
    // — so a terminal query resolves the token and stops there.
    if self.done {
      return;
    }
    match classify_advance(&mut self.partial_rounds, delivery) {
      PhaseAdvance::Delivered => {
        self.retry_count = self.retry_count.saturating_add(1);
        self.partial_send_streak = 0;
        self.next_deadline = retry::next_deadline(now, self.retry_count);
      }
      PhaseAdvance::Covered | PhaseAdvance::Excused => {
        // The slot is spent so the query can progress to its terminal, but the
        // send was NOT delivered everywhere: the ladder keeps climbing from where
        // it stood rather than resetting to the bottom rung. Indexing the backoff
        // by budget + streak is the same walk the honest-partial arm below does,
        // so the served link's intervals stay monotonically doubling across the
        // excuse point.
        self.retry_count = self.retry_count.saturating_add(1);
        let index = self.retry_count.saturating_add(self.partial_send_streak);
        self.next_deadline = retry::next_deadline(now, index);
        self.partial_send_streak = self.partial_send_streak.saturating_add(1);
      }
      PhaseAdvance::Partial => {
        // §5.2 ladder: the served link heard this question, so the NEXT one must
        // be at least twice as far out. `retry::next_deadline` derives the
        // interval from a send index, so adding the partial streak to the
        // (unspent) budget index walks the same doubling schedule — 1 s, 2 s,
        // 4 s … — while `retry_count` itself stays frozen.
        let index = self
          .retry_count
          .saturating_add(1)
          .saturating_add(self.partial_send_streak);
        self.next_deadline = retry::next_deadline(now, index);
        self.partial_send_streak = self.partial_send_streak.saturating_add(1);
      }
      PhaseAdvance::Failed => {
        // Nothing reached any wire: §5.2 counts no query to space out. Re-attempt
        // after the current backoff interval without advancing `retry_count` or
        // the ladder. `transmit_pending` stays false until the deadline fires, so
        // the driver's drain loop does not spin.
        self.next_deadline = retry::next_deadline(now, self.retry_count.saturating_add(1));
      }
    }
  }

  /// RFC 6762 §7.3 duplicate-question suppression. Another host has multicast
  /// the SAME question that this query is ABOUT TO (re)transmit. Treat the
  /// peer's query as our own ("treat its own query as having been sent"):
  /// consume this retry slot and arm the next retransmit on the normal backoff,
  /// without putting a redundant query on the wire — the peer's query elicits
  /// the multicast answers we want.
  ///
  /// A retransmit is "imminent" either when it is already armed
  /// (`transmit_pending`, the window between `handle_timeout` firing and
  /// `poll_transmit` draining) OR when its `next_deadline` is already due but
  /// not yet armed — the latter covers drivers that pump received packets BEFORE
  /// firing query timeouts, so suppression does not depend on that ordering.
  /// Either way it consumes exactly one retry slot: `transmit_pending`
  /// is cleared and the due deadline is pushed forward, so a second duplicate in
  /// the same slot is a no-op — suppression is idempotent per slot.
  ///
  /// The retry budget advances exactly as a real send would (and the query
  /// retires via `MAX_RETRIES` here too), so a continuously-duplicated query
  /// still progresses to its terminal timeout instead of being
  /// deferred forever. An in-flight (awaiting-confirm) send is left alone.
  ///
  /// Returns `true` if a transmit slot was actually consumed (i.e. real
  /// suppression happened) and `false` if the call was a no-op (query is
  /// done, awaiting send confirmation, or no send was imminent). Callers use
  /// the return value to decide whether to bump the
  /// `duplicate_questions_suppressed` counter.
  pub fn note_duplicate_question(&mut self, now: I) -> bool {
    if self.done || self.awaiting_send_confirm {
      return false;
    }
    let imminent = self.transmit_pending || self.next_deadline.is_some_and(|d| now >= d);
    if !imminent {
      return false;
    }
    self.transmit_pending = false;
    self.retry_count = self.retry_count.saturating_add(1);
    // The peer's query counts as ours, so this IS a budget advance: the §5.2
    // partial ladder resets exactly as it does on an all-delivered send — and so
    // does the core's patience counter, for the same reason. Leaving
    // `partial_rounds` charged would carry the previous slot's unmet obligations
    // into a slot that met its own, so the next genuine partial could be EXCUSED
    // early — spending a retry slot for a link that was never asked.
    self.partial_send_streak = 0;
    self.partial_rounds = [FamilyPatience::default(); 2];
    if self.retry_count > MAX_RETRIES {
      // Budget spent (counting suppressed slots as our sends) — retire exactly
      // as `handle_timeout` would after the final retransmit. Route through
      // `terminate` so stats (queries_timeout, queries_done, decr_queries_active)
      // are bumped exactly once on this path too.
      self.terminate(QueryUpdate::Timeout);
      // The slot was consumed even though the query is now terminal.
      return true;
    }
    self.next_deadline = retry::next_deadline(now, self.retry_count);
    true
  }

  /// Drain a pending app-level update.
  pub fn poll(&mut self) -> Option<QueryUpdate> {
    let key = self.pending_updates.iter().next().map(|(k, _)| k)?;
    self.pending_updates.try_remove(key)
  }

  /// Has the query reached a terminal state?  Backstop for
  /// [`Endpoint::poll_query`](crate::endpoint::Endpoint::poll_query) under
  /// EV-pool pressure: if `handle_timeout` cannot push the terminal
  /// `QueryUpdate::Timeout`, `Endpoint::poll_query` falls back to this
  /// flag and synthesises `Timeout`.  External callers normally do NOT
  /// need to consult this directly — drive `Endpoint::poll_query` and
  /// react to its terminal return value.
  #[inline(always)]
  pub const fn is_done(&self) -> bool {
    self.done
  }

  /// Has the terminal `QueryUpdate` already been delivered to the
  /// caller via `Endpoint::poll_query`?  Internal latch — set
  /// the first time `poll_query` returns `Done`/`Timeout` so subsequent
  /// calls return `None` instead of re-emitting (or worse, double-emitting
  /// from both the `pending_updates` push AND the `is_done` backstop).
  #[inline(always)]
  pub(crate) const fn terminal_emitted(&self) -> bool {
    self.terminal_emitted
  }

  /// Mark the terminal as delivered.  Intended for
  /// `Endpoint::poll_query` to call after returning `Done`/`Timeout`.
  #[inline(always)]
  pub(crate) fn mark_terminal_emitted(&mut self) {
    self.terminal_emitted = true;
  }

  /// Iterate the answers collected so far by this query.
  pub fn collected_answers(&self) -> impl Iterator<Item = &CollectedAnswer> + '_ {
    self.answers.iter().map(|(_, a)| a)
  }

  /// Total number of answers ever accepted by this query, including ones
  /// already evicted by the `max_answers` cap.
  ///
  /// Equal to the next sequence number to be assigned, so it is monotonic and
  /// `>=` the highest `seq` currently in [`Self::collected_answers`]. A
  /// consumer that delivers answers by ascending `seq` can compare this
  /// against the count it has observed to detect (and count) answers the cap
  /// evicted before they were read.
  pub fn accepted_count(&self) -> u64 {
    self.next_seq
  }
}

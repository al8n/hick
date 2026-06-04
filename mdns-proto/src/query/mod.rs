//! Query state machine — retry backoff + answer collection + KAS hints.

mod retry;

#[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
use crate::Name;
use crate::{
  Instant, Pool, QueryHandle,
  error::{HandleTimeoutError, TransmitError},
  event::{QueryEvent, QueryUpdate},
  transmit::Transmit,
  wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
};

/// Maximum retries before giving up.
const MAX_RETRIES: u32 = 8;

/// Default maximum number of collected answers per query.
const DEFAULT_MAX_ANSWERS: usize = 256;

/// One collected answer record for a Query.
///
/// Stores the resource type, class, and raw rdata bytes so that
/// deduplication, qtype/qclass filtering, and the answer cap can all
/// be applied before inserting into the pool.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
#[derive(Debug, Clone)]
pub struct CollectedAnswer {
  rtype: ResourceType,
  rclass: ResourceClass,
  rdata: std::vec::Vec<u8>,
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
  rdata_key: Option<std::vec::Vec<u8>>,
  /// Monotonically increasing insertion sequence number within a single Query.
  /// Used to identify the oldest entry for FIFO eviction.
  seq: u64,
}

#[cfg(any(feature = "alloc", feature = "std"))]
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
    rdata: std::vec::Vec<u8>,
    seq: u64,
  ) -> Self {
    Self {
      rtype,
      rclass,
      rdata,
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
    &self.rdata
  }

  /// The case-FOLDED identity form of the rdata. Equal for two
  /// answers that are the same logical record differing only in DNS name case;
  /// callers coalescing/deduping answers should compare this, not
  /// [`Self::rdata_slice`] (which preserves display case). resolves
  /// to `rdata` when the folded form is identical (no separate buffer stored).
  #[inline(always)]
  pub fn rdata_key(&self) -> &[u8] {
    self.rdata_key.as_deref().unwrap_or(&self.rdata)
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
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub struct Query<I, AN, EV> {
  handle: QueryHandle,
  #[cfg(feature = "stats")]
  stats: std::sync::Arc<hick_trace::stats::Stats>,
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
  /// cleared by `note_transmit_result` once the driver reports the send result.
  /// The retry budget (`retry_count`) and the next-retry deadline are advanced
  /// ONLY on a confirmed-delivered send — a datagram that fails on every socket
  /// is re-attempted without consuming the budget, so a transient send failure
  /// can never time out a query that never actually put a question on the wire.
  awaiting_send_confirm: bool,
  /// When `true`, questions are emitted with the QU bit set (RFC 6762 §5.4):
  /// the sender prefers a unicast response rather than a multicast one.
  unicast_response: bool,
  /// Absolute instant at which this query should auto-cancel regardless of
  /// the retry budget (`None` means no hard deadline beyond the retry budget).
  timeout_deadline: Option<I>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
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
      stats: std::sync::Arc::new(hick_trace::stats::Stats::default()),
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
      unicast_response,
      timeout_deadline,
    }
  }

  /// Replace the shared [`Stats`] handle with one from the owning [`Endpoint`].
  ///
  /// Called immediately after construction by `Endpoint::try_start_query`
  /// so that all per-query counters accumulate into the endpoint-level stats.
  #[cfg(feature = "stats")]
  pub(crate) fn set_stats(&mut self, stats: std::sync::Arc<hick_trace::stats::Stats>) {
    self.stats = stats;
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
  pub fn handle_event(&mut self, event: QueryEvent<'_>) {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("query", handle = self.handle.raw()).entered();
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
        let key: &[u8] = rdata_key.as_deref().unwrap_or(&owned);

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
          self.stats.answers_collected(1);
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

  /// Drive timer-based transitions.
  pub fn handle_timeout(&mut self, now: I) -> Result<(), HandleTimeoutError> {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("query", handle = self.handle.raw()).entered();
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
      self.done = true;
      self.transmit_pending = false;
      let _ = self.pending_updates.insert(QueryUpdate::Timeout);
      self.next_deadline = None;
      self.timeout_deadline = None;
      #[cfg(feature = "stats")]
      {
        self.stats.queries_timeout(1);
        self.stats.queries_done(1);
      }
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
      self.done = true;
      self.transmit_pending = false;
      let _ = self.pending_updates.insert(QueryUpdate::Timeout);
      self.next_deadline = None;
      self.timeout_deadline = None;
      #[cfg(feature = "stats")]
      {
        self.stats.queries_timeout(1);
        self.stats.queries_done(1);
      }
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
  pub(crate) fn retire(&mut self) {
    if self.done {
      return;
    }
    self.done = true;
    self.transmit_pending = false;
    let _ = self.pending_updates.insert(QueryUpdate::Timeout);
    self.next_deadline = None;
    self.timeout_deadline = None;
    #[cfg(feature = "stats")]
    {
      self.stats.queries_timeout(1);
      self.stats.queries_done(1);
    }
  }

  /// Produce the next outgoing datagram, if any. Writes into `buf`.
  ///
  /// Returns `Ok(None)` when the query is done or when no send is currently
  /// due (i.e. `transmit_pending` is false). A single call per scheduled
  /// deadline tick is guaranteed: the pending flag is cleared after the
  /// datagram is built, so a driver looping on this method will not
  /// re-send the query until the next `handle_timeout` fires.
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
    // result (`note_transmit_result`), which schedules the backoff on a
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
    Ok(Some(Transmit::new(
      crate::service::multicast_dst(),
      None,
      n,
    )))
  }

  /// Report the result of sending the datagram most recently produced by
  /// [`Self::poll_transmit`]. The driver calls this after a send,
  /// with `delivered = true` when at least one socket send succeeded.
  ///
  /// On a delivered send this counts the transmission against the §5.2 retry
  /// budget and schedules the next retransmit (backoff: +1s, doubling, capped
  /// at 60s). On a failed send the budget is NOT consumed and the query is
  /// re-armed to re-attempt at the same interval — so a transient or total send
  /// failure retries with backoff (no tight spin) and a query can never reach
  /// its retry-budget timeout having put nothing on the wire.
  pub fn note_transmit_result(&mut self, now: I, delivered: bool) {
    if !self.awaiting_send_confirm {
      return;
    }
    self.awaiting_send_confirm = false;
    if delivered {
      self.retry_count = self.retry_count.saturating_add(1);
      self.next_deadline = retry::next_deadline(now, self.retry_count);
    } else {
      // Re-attempt this (undelivered) send after its backoff interval without
      // advancing `retry_count`. `transmit_pending` stays false until the
      // deadline fires, so the driver's drain loop does not spin.
      self.next_deadline = retry::next_deadline(now, self.retry_count.saturating_add(1));
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
  pub fn note_duplicate_question(&mut self, now: I) {
    if self.done || self.awaiting_send_confirm {
      return;
    }
    let imminent = self.transmit_pending || self.next_deadline.is_some_and(|d| now >= d);
    if !imminent {
      return;
    }
    self.transmit_pending = false;
    self.retry_count = self.retry_count.saturating_add(1);
    if self.retry_count > MAX_RETRIES {
      // Budget spent (counting suppressed slots as our sends) — retire exactly
      // as `handle_timeout` would after the final retransmit.
      self.done = true;
      self.next_deadline = None;
      self.timeout_deadline = None;
      let _ = self.pending_updates.insert(QueryUpdate::Timeout);
      return;
    }
    self.next_deadline = retry::next_deadline(now, self.retry_count);
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

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "std", feature = "slab"))]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::indexing_slicing,
  clippy::panic,
  clippy::arithmetic_side_effects
)]
mod tests {
  use std::time::Instant as StdInstant;

  use super::*;
  use crate::{
    Name, QueryHandle,
    event::QueryEvent,
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

  // ── qtype filter ─────────────────────────────────────────────────────

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
  /// `Query`'s logical `max_answers`. Models a fixed-capacity backing (e.g.
  /// `heapless::Vec<_, N>`) whose `insert`/`vacant_key` fail once full — the
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
    q.note_transmit_result(now, true);

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
    q.note_transmit_result(one_sec, true);
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
      q.note_transmit_result(t, false); // all sockets failed
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
    q.note_transmit_result(t, true);
    let plus_1s = t.checked_add(Duration::from_secs(1)).unwrap();
    assert_eq!(
      q.poll_timeout(),
      Some(plus_1s),
      "after the first delivered send the retry is scheduled +1s out"
    );
  }

  /// the retry backoff is anchored to the time passed to
  /// `note_transmit_result` (post-send), not the `poll_transmit` time — a send
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
    q.note_transmit_result(send_done, true);

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
  fn note_transmit_result_without_a_pending_send_is_noop() {
    let mut q = make_query(ResourceType::Any, ResourceClass::Any);
    // No poll_transmit happened → awaiting_send_confirm is false → no-op.
    q.note_transmit_result(StdInstant::now(), true);
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
        q.note_transmit_result(now, true); // confirmed send burns one retry slot
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
}

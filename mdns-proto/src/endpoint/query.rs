//! Query lifecycle: start, poll, transmit, timeout, cancel.

use super::*;

impl<I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS> Endpoint<I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS>
where
  I: Instant,
  R: Rng,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute<I, TQ, EvS>>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
  TQ: Pool<Transmit>,
  EvS: Pool<ServiceUpdate>,
{
  /// Start a new query.
  ///
  /// The [`Query`] state machine is owned by the endpoint and driven via
  /// the `*_query*` accessors (`poll_query`, `poll_query_timeout`,
  /// `poll_query_transmit`, `handle_query_timeout`, `cancel_query`,
  /// `collected_answers`).
  ///
  /// When the query reaches a terminal state (`Timeout` or `Done`),
  /// [`Self::poll_query`] returns the terminal update exactly once and
  /// the state machine becomes frozen: `collected_answers(h)` remains
  /// readable, but no further answers are applied and no further
  /// `QueryEvent::Answer` events fire for `h`.  The caller MUST
  /// eventually free the pool slot via [`Self::cancel_query`] (or use
  /// [`Self::sweep_terminated_queries`] for bulk cleanup) — terminated
  /// queries are NOT auto-pruned.
  ///
  /// # Errors
  ///
  /// Returns [`StartQueryError::StorageFull`] if the query pool cannot
  /// accept another entry.
  pub fn try_start_query(
    &mut self,
    spec: QuerySpec,
    now: I,
  ) -> Result<QueryHandle, StartQueryError> {
    let new_h = self.next_query_handle;
    self.next_query_handle = self.next_query_handle.saturating_add(1);
    let handle = QueryHandle::from_raw(new_h);

    let txid = self.next_txid;
    // next_txid wraps but skip 0.
    let next_raw = self.next_txid.wrapping_add(1);
    self.next_txid = if next_raw == 0 { 1 } else { next_raw };

    let timeout_deadline = spec.timeout().and_then(|dur| now.checked_add_duration(dur));
    let mut q = Query::try_new(
      handle,
      spec.qname().clone(),
      spec.qtype(),
      spec.qclass(),
      txid,
      spec.unicast_response(),
      timeout_deadline,
    );
    #[cfg(feature = "stats")]
    q.set_stats(self.stats.clone());
    if let Some(m) = spec.max_answers() {
      q.set_max_answers(m);
    }
    // q must be `mut` for set_max_answers above; allow for stats-only build.

    self
      .queries
      .insert(q)
      .map_err(|_| StartQueryError::StorageFull(StorageFullError))?;
    debug!(
      target: "mdns_proto::endpoint",
      handle = handle.raw(),
      qtype = ?spec.qtype(),
      txid,
      "try_start_query: query started"
    );
    #[cfg(feature = "stats")]
    {
      self.stats.queries_started(1);
      self.stats.incr_queries_active(1);
    }
    Ok(handle)
  }

  /// Find the slab key for a registered query handle.  Returns `None` if
  /// the handle no longer corresponds to an active query (auto-pruned
  /// after terminal, explicitly cancelled, or never registered).
  pub(crate) fn query_key(&self, handle: QueryHandle) -> Option<usize> {
    for (key, q) in self.queries.iter() {
      if q.handle() == handle {
        return Some(key);
      }
    }
    None
  }

  /// Drain the next app-level update for a registered query.
  ///
  /// The terminal `QueryUpdate` ([`QueryUpdate::Done`] /
  /// [`QueryUpdate::Timeout`]) is returned at most ONCE per query —
  /// subsequent `poll_query(h)` calls on the same handle return `None`
  /// even though the underlying state machine is still in the pool.
  /// This lets the caller observe terminal, then read final results
  /// via [`Self::collected_answers`], then explicitly clean up via
  /// [`Self::cancel_query`].  Auto-prune was tried in an earlier
  /// design and rejected: pruning before the caller had a
  /// chance to read [`Self::collected_answers`] silently lost the
  /// query's results.
  ///
  /// Backstop for storage-pressure: if `Query::handle_timeout` could
  /// not push the terminal update into the internal `EV` pool
  /// (full / zero-capacity), this synthesises a
  /// `QueryUpdate::Timeout` from the internal `done` flag.  The
  /// `terminal_emitted` latch on `Query` ensures the synthesised value
  /// fires exactly once regardless of which path produced it.
  ///
  /// Returns `None` if the query has no pending updates, has already
  /// emitted its terminal, or the handle does not correspond to a
  /// registered query.
  ///
  /// # Cleanup contract
  ///
  /// After observing terminal, the caller MUST eventually call
  /// [`Self::cancel_query`] to free the pool entry — leaving terminated
  /// queries in the pool indefinitely will exhaust fixed-capacity
  /// storage just as the leak would have.  A convenience
  /// [`Self::sweep_terminated_queries`] is available for callers that
  /// want a single bulk-cleanup step.
  pub fn poll_query(&mut self, handle: QueryHandle) -> Option<QueryUpdate> {
    let key = self.query_key(handle)?;
    let q = self.queries.get_mut(key)?;
    if q.terminal_emitted() {
      // Terminal already delivered; do not re-emit or re-synthesise.
      return None;
    }
    // Drain a regular pending update.
    let update = q.poll();
    if let Some(u) = update {
      if matches!(u, QueryUpdate::Done | QueryUpdate::Timeout) {
        q.mark_terminal_emitted();
      }
      return Some(u);
    }
    // No pending update — backstop: if the query is internally done but
    // the terminal update was silently dropped under EV-pool pressure,
    // synthesise Timeout once.
    if q.is_done() {
      q.mark_terminal_emitted();
      return Some(QueryUpdate::Timeout);
    }
    None
  }

  /// Remove every registered query that has already delivered its
  /// terminal `QueryUpdate` via [`Self::poll_query`].  Returns the
  /// number of queries pruned.
  ///
  /// Convenience for callers that want a single bulk cleanup step
  /// instead of tracking handles individually with
  /// [`Self::cancel_query`].  Safe to call at any time — queries that
  /// have NOT yet emitted terminal are left untouched.
  ///
  /// Carries the same confirm-before-anything obligation as
  /// [`Self::cancel_query`] for each query it removes. A query that has emitted
  /// its terminal has stopped producing datagrams, so a compliant driver cannot
  /// reach this with one outstanding; debug builds assert it per removed query
  /// rather than assuming.
  pub fn sweep_terminated_queries(&mut self) -> usize {
    let mut to_remove: std::vec::Vec<usize> = std::vec::Vec::new();
    for (key, q) in self.queries.iter() {
      if q.terminal_emitted() {
        q.assert_no_live_send_confirm("Endpoint::sweep_terminated_queries");
        to_remove.push(key);
      }
    }
    let count = to_remove.len();
    for key in to_remove {
      self.queries.try_remove(key);
    }
    count
  }

  /// Next deadline for a registered query's `handle_query_timeout` /
  /// retry / absolute-timeout schedule.  Returns `None` if the query is
  /// idle (waiting on a response) or no longer registered.
  pub fn poll_query_timeout(&self, handle: QueryHandle) -> Option<I> {
    let key = self.query_key(handle)?;
    self.queries.get(key).and_then(Query::poll_timeout)
  }

  /// Produce the next outgoing datagram for a registered query, if any
  /// is due.  Writes into `buf` and returns the [`Transmit`] descriptor.
  ///
  /// Returns `Ok(None)` when no send is currently due, or when the
  /// handle does not correspond to an active query (use
  /// [`Self::poll_query`] to observe terminal updates separately).
  ///
  /// # Why a clock, not an instant
  ///
  /// `clock` is the caller's monotonic source, and it is read INSIDE this call —
  /// after the handle is resolved, immediately before [`Query::poll_transmit`]
  /// weighs it against the `QuerySpec::with_timeout` deadline. That deadline
  /// bounds ADMISSION, and admission is that comparison rather than this call's
  /// return: the reading has to be taken where the decision is, because
  /// everything before it — the handle resolution here most of all — is time a
  /// reading taken earlier would not know about. What the datagram then costs on
  /// the way to a wire is the driver's, and is what `QuerySpec::with_timeout`
  /// bounds instead of pretending to eliminate.
  ///
  /// An instant parameter could not be: resolving `handle` walks the query pool,
  /// whose length is the caller's choice and which this crate puts no ceiling on,
  /// so a value sampled before this call can be stale before the comparison it
  /// was sampled for — and on a preemptible host so can one sampled a single
  /// statement earlier. Taking the clock instead of
  /// its reading leaves no parameter through which a stale reading can arrive.
  /// It is invoked at most once, and only when a datagram is otherwise due.
  pub fn poll_query_transmit(
    &mut self,
    handle: QueryHandle,
    clock: impl FnOnce() -> I,
    buf: &mut [u8],
  ) -> Result<Option<Transmit>, TransmitError> {
    let Some(key) = self.query_key(handle) else {
      return Ok(None);
    };
    #[cfg(all(test, feature = "std"))]
    {
      // The scan above, made observable: see `query_resolve_stall`.
      if let Some(stall) = self.query_resolve_stall.take()
        && !stall.is_zero()
      {
        std::thread::sleep(stall);
      }
    }
    match self.queries.get_mut(key) {
      Some(q) => q.poll_transmit(clock, buf),
      None => Ok(None),
    }
  }

  /// Report what each address family's transport did with the datagram most
  /// recently produced by [`Self::poll_query_transmit`] for `handle`.
  ///
  /// The query advances its RFC 6762 §5.2 retry budget only once EVERY obligated
  /// family accepted the question; a partially-delivered one climbs the §5.2
  /// doubling ladder without spending a slot. See
  /// [`Query::note_transmit_outcome`] for the full contract, including what
  /// [`TransmitConfirm::retire_producer`] obliges the caller to do. No-op for an
  /// unknown handle.
  pub fn note_query_transmit_outcome(
    &mut self,
    handle: QueryHandle,
    now: I,
    v4: FamilyAttempt<I>,
    v6: FamilyAttempt<I>,
  ) -> TransmitConfirm {
    let Some(key) = self.query_key(handle) else {
      return TransmitConfirm::NOTHING;
    };
    match self.queries.get_mut(key) {
      Some(q) => q.note_transmit_outcome(now, v4, v6),
      None => TransmitConfirm::NOTHING,
    }
  }

  /// Test-only: confirm from a projected delivery SHAPE. See
  /// [`Service::note_delivery`](crate::Service::note_delivery).
  #[cfg(test)]
  #[allow(dead_code)]
  pub(crate) fn note_query_delivery(
    &mut self,
    handle: QueryHandle,
    now: I,
    delivery: crate::transmit::TransmitDelivery,
  ) {
    let (v4, v6) = delivery.as_attempts(now);
    let _ = self.note_query_transmit_outcome(handle, now, v4, v6);
  }

  /// Drive timer-based transitions on a registered query.
  ///
  /// Callers wake from [`Self::poll_query_timeout`] and invoke this with
  /// the current instant; the underlying query state machine fires its
  /// retry backoff or absolute timeout.  Terminal events become
  /// observable via [`Self::poll_query`] on the next call.
  ///
  /// Returns `Ok(())` for unknown handles as well — there is nothing
  /// to drive.
  pub fn handle_query_timeout(
    &mut self,
    handle: QueryHandle,
    now: I,
  ) -> Result<(), HandleTimeoutError> {
    let Some(key) = self.query_key(handle) else {
      return Ok(());
    };
    match self.queries.get_mut(key) {
      Some(q) => q.handle_timeout(now),
      None => Ok(()),
    }
  }

  /// Retire a registered query at the DRIVER's request: force it to its terminal
  /// TIMEOUT state. Use this when the transport can never send the query's
  /// question (e.g. a permanently-too-large datagram on every reachable family),
  /// so the query would otherwise hang. The terminal `QueryUpdate::Timeout`
  /// becomes observable via [`Self::poll_query`], late answers are frozen (the
  /// query is now done), and [`Self::collected_answers`] stay readable until
  /// [`Self::cancel_query`]. No-op for an unknown handle or an already-done query.
  pub fn retire_query(&mut self, handle: QueryHandle) {
    if let Some(key) = self.query_key(handle)
      && let Some(q) = self.queries.get_mut(key)
    {
      q.retire();
    }
  }

  /// Cancel a registered query explicitly.  Removes the query state
  /// machine and its route immediately.  Use this for caller-initiated
  /// cancellation (e.g. the application no longer cares about the
  /// query); for natural termination (timeout / done) drive
  /// [`Self::poll_query`] and let auto-prune happen.
  ///
  /// # Errors
  ///
  /// Returns [`CancelQueryError::QueryNotFound`] if `handle` does not
  /// correspond to a currently registered query.
  ///
  /// # Contract
  ///
  /// Must NOT be called while a datagram from [`Self::poll_query_transmit`] is
  /// still awaiting its [`Self::note_query_transmit_outcome`]. Removing the query
  /// discards the commit token, so the confirm that follows lands on a handle the
  /// endpoint no longer knows and silently does nothing — while the datagram it
  /// described may still be on its way out. A driver that cancels from another
  /// task must FLAG the cancellation and sweep it once the transmit pump has
  /// confirmed. Debug builds assert this; see [`Query::poll_transmit`] for the
  /// full contract.
  ///
  /// [`Query::poll_transmit`]: crate::query::Query::poll_transmit
  pub fn cancel_query(&mut self, handle: QueryHandle) -> Result<(), CancelQueryError> {
    let key = self
      .query_key(handle)
      .ok_or(CancelQueryError::QueryNotFound(handle))?;
    if let Some(q) = self.queries.get(key) {
      q.assert_no_live_send_confirm("Endpoint::cancel_query");
    }
    // Apply terminal accounting for a live cancel.  If the query has NOT yet
    // reached a terminal state (done=false), this cancel IS the terminal
    // transition, so we must bump `queries_done` AND decrement `queries_active`
    // — exactly as `Query::terminate` would.  If the query is already done,
    // `Query::terminate` already performed both adjustments; do nothing here to
    // avoid double-counting.  This maintains the invariant:
    //   queries_started == queries_done + queries_timeout + queries_active
    #[cfg(feature = "stats")]
    if let Some(q) = self.queries.get(key)
      && !q.is_done()
    {
      self.stats.queries_done(1);
      self.stats.decr_queries_active(1);
    }
    self.queries.try_remove(key);
    Ok(())
  }

  /// Iterate the answers collected so far by a registered query.
  /// Returns an empty iterator if the handle does not correspond to an
  /// active query.
  pub fn collected_answers(
    &self,
    handle: QueryHandle,
  ) -> impl Iterator<Item = &CollectedAnswer> + '_ {
    let key = self.query_key(handle);
    key
      .and_then(|k| self.queries.get(k))
      .into_iter()
      .flat_map(Query::collected_answers)
  }

  /// Total answers ever accepted by a query (including ones the `max_answers`
  /// cap has since evicted). `None` if the handle is not an active query.
  ///
  /// A driver delivering answers by ascending `seq` compares this against the
  /// number it has observed to count answers evicted before delivery — loss
  /// the bounded [`Self::collected_answers`] snapshot would otherwise hide.
  pub fn query_accepted_count(&self, handle: QueryHandle) -> Option<u64> {
    self
      .query_key(handle)
      .and_then(|k| self.queries.get(k))
      .map(Query::accepted_count)
  }
}

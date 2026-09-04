//! Service withdrawal (TTL=0 goodbye) lifecycle.

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
  cfg_heap! {
    /// Mint the next monotonic [`WithdrawalToken`]. Never reused.
    pub(crate) fn mint_withdrawal_token(&mut self) -> WithdrawalToken {
      let t = WithdrawalToken(self.next_withdrawal_token);
      self.next_withdrawal_token = self.next_withdrawal_token.saturating_add(1);
      t
    }

    /// Begin terminal withdrawal for `handle`.
    ///
    /// Enqueues ONE route-attached withdrawal item for the current (live /
    /// re-announced) name. The OLD instance name of an in-flight §9 rename is NOT
    /// handled here — a rename hands its old-name goodbye off the instant it
    /// happens (the driver calls [`Self::enqueue_rename_withdrawal`] after
    /// the tick that renamed), so it is already its own INDEPENDENT
    /// detached item. A teardown DURING the rename window is therefore simply two
    /// independent single-name items — that earlier detached old-name one plus this
    /// route-attached current-name one: the two never share a
    /// schedule or a datagram, so the old-name goodbye can never be starved by the
    /// current one nor dropped because their combined message overflowed `scratch`.
    ///
    /// # Route retention
    ///
    /// The route is **kept** in `self.services`: the name guard continues to
    /// reject a same-name re-registration while the route-attached item is in
    /// flight.  `services_active` is **not** decremented here — that happens in
    /// [`Self::drain_completed_withdrawals`] when that item completes.
    ///
    /// # Timing
    ///
    /// The item's `next_at` is set to `now` so its first goodbye fires
    /// immediately. `ceiling_at` is `now + WITHDRAWAL_CEILING` (2 s) — if a
    /// sequence has not completed by then it is force-finished to avoid pinning the
    /// name slot indefinitely.
    ///
    /// # Idempotency
    ///
    /// If a route-attached item already exists for `handle` (`route ==
    /// Some(handle)`) the call is a no-op: a driver may retire the same service
    /// more than once (e.g. an encode-failure escalation on an already-cancelled
    /// service) and must not enqueue a duplicate. If `handle` has no registered
    /// route the call is likewise a silent no-op.
    ///
    /// # Contract
    ///
    /// `snapshot` must be taken with no datagram outstanding — i.e. after the
    /// service's last [`Self::poll_service_transmit`] was confirmed. A snapshot
    /// taken mid-flight omits the records that datagram is about to place in
    /// peer caches, and this goodbye can only withdraw what the snapshot names.
    pub(crate) fn begin_withdrawal(
      &mut self,
      handle: ServiceHandle,
      snapshot: crate::service::WithdrawalSnapshot,
      now: I,
    ) {
      // Locate the route.
      let route_key = self
        .services
        .iter()
        .find(|(_, route)| route.handle() == handle)
        .map(|(k, _)| k);
      let Some(key) = route_key else { return };

      // Idempotency: a route-attached item already exists for this handle → do not
      // enqueue a second (a driver may retire the same service more than once).
      if self
        .withdrawals
        .iter()
        .any(|(_, w)| w.route == Some(handle))
      {
        return;
      }

      let Some(route) = self.services.get_mut(key) else {
        return;
      };
      route.withdrawing = true;
      // Positive-TTL work still queued on the state machine is DISCARDED, not
      // merely left unreachable. The snapshot taken a moment ago names what
      // peers hold, so anything emitted after it — a queued first announcement,
      // a §6.7 legacy reply, a periodic re-announce — would put records in peer
      // caches that this goodbye cannot mention and nothing else will retract.
      // See `Endpoint::unregister_service` for the whole rule and the accessors
      // it closes.
      route.proto.quiesce_for_withdrawal();

      // next_at = now (first send fires immediately); ceiling_at = now +
      // WITHDRAWAL_CEILING (hard anti-pin deadline).
      let ceiling_at = now.checked_add_duration(WITHDRAWAL_CEILING).unwrap_or(now);

      // Route-attached item: the CURRENT (live / re-announced) name.
      // A family owes a goodbye iff IT actually advertised an instance record or
      // a host address; otherwise `0`, so the next `drain_completed_withdrawals`
      // frees the name at once with no spurious goodbye and no 2 s ceiling wait.
      //
      // PER FAMILY, not per item. A fan-out is two sends and either may be
      // refused, so an announcement IPv6 never carried put nothing in an IPv6
      // peer's cache — and a TTL=0 goodbye sent there would retract records this
      // endpoint never advertised on that family, which can cache-flush a peer's
      // matching shared record. That is the same over-withdrawal class the
      // per-record `EmittedRecords` granularity closes, one dimension over.
      let current_owed = owed_per_family(&snapshot.owned);

      let crate::service::WithdrawalSnapshot {
        records,
        owned,
        multicast,
      } = snapshot;

      let token = self.mint_withdrawal_token();
      self.withdrawals.push((
        token,
        WithdrawalItem {
          records,
          owned,
          multicast,
          owed: current_owed,
          next_at: now,
          ceiling_at,
          final_attempt: false,
          route: Some(handle),
          // Route-attached: already holds its name via the route table (the
          // duplicate-name scan in `try_register_service`), so the detached-only
          // name hold does not apply.
          holds_name: false,
        },
      ));

      debug!(
        target: "mdns_proto::endpoint",
        handle = handle.raw(),
        "begin_withdrawal: route held, goodbye schedule queued"
      );
    }

    /// Enqueue a DETACHED withdrawal item for the OLD instance name of a §9
    /// conflict rename (the renamed-away old name's TTL=0 goodbye).
    ///
    /// Called from [`Self::handle_service_timeout`] and
    /// [`Self::unregister_service`] with the handoff the renaming `Service` left
    /// behind (the old name's records + the per-record ownership of what it
    /// advertised).
    /// This models the old-name goodbye as an INDEPENDENT single-name withdrawal
    /// item — its own per-family debt, schedule, ceiling, and loss-resilience
    /// resends — exactly like a teardown's detached item. A teardown DURING the
    /// rename window is therefore simply two independent items (this detached
    /// old-name one, plus the route-attached current-name one from
    /// [`Self::begin_withdrawal`]); neither can starve the other nor be dropped
    /// because their combined message overflowed `scratch`.
    ///
    /// The item holds NO route (it frees nothing and is reported to nobody on
    /// completion) and NO host addresses (a rename never withdraws host A/AAAA —
    /// the host name is invariant across an instance rename). It is a **no-op when
    /// the handoff owned nothing** (the old name never advertised an instance
    /// record, so there is nothing for peers to evict).
    ///
    /// # It also RELINQUISHES the old name's record set
    ///
    /// A §9 rename is one of the two points at which this endpoint stops
    /// publishing a set it recently put on the wire, so the old name's records
    /// are retained here — at the rename, not when this
    /// item finishes — for
    /// [`EndpointConfig::relinquished_retention`](crate::EndpointConfig::relinquished_retention),
    /// so a delayed echo of them cannot be adjudicated against whatever takes
    /// the vacated name. The item's own residency is not enough on its own: a
    /// SURVIVING rename's detached goodbye is reclaim-cancelled by
    /// [`Self::note_service_transmit_outcome`] the moment a service fully announces
    /// that same name, which is precisely the moment a replacement has taken it
    /// and the evidence is most needed.
    pub(crate) fn enqueue_rename_withdrawal(
      &mut self,
      handoff: crate::service::RenameGoodbyeHandoff,
      now: I,
      holds_name: bool,
    ) {
      let crate::service::RenameGoodbyeHandoff {
        records,
        owned,
        multicast,
      } = handoff;
      // RETAIN FIRST, and independently of whether an item is owed. The two
      // questions differ: a goodbye retracts what peers CACHE, the screen
      // disowns what we TRANSMITTED, and the §6.1 instance NSEC is transmitted
      // without being retractable. A §7.1-filtered response that emitted only
      // host addresses put the old name's NSEC on the wire and nothing this
      // goodbye can withdraw, so keying the retention on `owned.is_empty()`
      // would drop exactly that echo's evidence.
      //
      // NO HOST ADDRESSES: a rename replaces the INSTANCE name and the host name
      // is invariant, so the live service still publishes its addresses and
      // `Service::classify_host_rdata` recognises their echoes itself. Retaining
      // them here would screen a GENUINE peer's A/AAAA conflict at a host name
      // this endpoint still holds. The handoff carries none, so the exposure
      // pair goes across whole.
      //
      // THE SCREEN'S HALF, not the goodbye's. `owned` says which records a peer
      // may hold from us and therefore what this goodbye must retract; only
      // `multicast` says which bytes could still be echoing back, and only that
      // question is the retention list's.
      self.retain_relinquished(records.clone(), multicast.clone(), now);
      // Nothing for peers to evict on either family → no item.
      let owed = owed_per_family(&owned);
      if owed == [0, 0] {
        return;
      }
      let ceiling_at = now.checked_add_duration(WITHDRAWAL_CEILING).unwrap_or(now);
      let token = self.mint_withdrawal_token();
      self.withdrawals.push((
        token,
        WithdrawalItem {
          records,
          owned,
          multicast,
          owed,
          next_at: now,
          ceiling_at,
          final_attempt: false,
          route: None,
          // A rename-COLLISION teardown's old name must be retracted before reuse
          // (the dead service has no live re-announcer); a SURVIVING rename's old
          // name stays reclaimable.
          holds_name,
        },
      ));
      debug!(
        target: "mdns_proto::endpoint",
        "enqueue_rename_withdrawal: detached old-name goodbye queued"
      );
    }

    /// Pump one due withdrawal datagram.  Mirrors [`Self::poll_query_transmit`]:
    /// the driver sends the returned datagram (fanned to every bound family) and
    /// then confirms it via [`Self::note_withdrawal_result`].
    ///
    /// Encodes a SINGLE `WithdrawalItem`'s TTL=0 goodbye per call. For a
    /// route-attached item (`route == Some`) a host address is withdrawn ONLY if no
    /// OTHER live route still advertises it — same-host sibling retention is
    /// recomputed FRESH each call from the route table, so siblings joining or
    /// leaving during the multi-round window are always honoured. A detached item
    /// (`route == None`) holds no host addresses, so retention does not apply and
    /// its goodbye is purely instance-only (the renamed-away old name).
    ///
    /// # Independent single-name items
    ///
    /// A teardown DURING a still-draining §9 rename owes goodbyes for TWO names —
    /// but each is its OWN item with its OWN per-family debt and schedule, so they
    /// are emitted as SEPARATE datagrams chosen independently by this scan. That
    /// fixes two bugs at the root:
    ///   * a rename-ONLY teardown still emits the old name (it is a separate
    ///     detached item that owes a full budget, never folded into an empty
    ///     current item); and
    ///   * neither datagram can be "combined too large" — each carries one name, so
    ///     two names that each fit `scratch` individually are BOTH emitted even when
    ///     their combined message would not, and an unencodable item never starves
    ///     the other.
    ///
    /// # Retained-only / empty items do not head-of-line block
    ///
    /// A route-attached item can have NOTHING left to put on the wire — it owns no
    /// instance records and every host address it advertised is still retained by
    /// a LIVE same-host sibling.  Such an item is COMPLETED in place
    /// (`owed = [0, 0]`, freed by the next [`Self::drain_completed_withdrawals`])
    /// and the scan CONTINUES, rather than returning `None`.  Completing it at once
    /// is correct: a live sibling legitimately still advertises those addresses, and
    /// when that sibling later leaves ITS own item withdraws them.  Returning `None`
    /// here would (a) leave the item due forever — re-waking `poll_timeout` until its
    /// 2 s ceiling — and (b) stop the driver's `while let Some(..)` pump loop,
    /// starving any later same-time item that genuinely needs a TTL=0 goodbye.
    ///
    /// # An encode failure ADVANCES the item rather than blocking
    ///
    /// If the goodbye encoder returns an error for the chosen item (e.g. its
    /// goodbye does not fit `scratch`), this does NOT return
    /// `None` — that would leave the failing item first-due at this `now`
    /// and stop the driver pump loop before later due items are reached.
    /// Instead the failing item's `next_at` is pushed past `now`
    /// (`now + WITHDRAWAL_RETRY_BACKOFF`, its debt budget intact) and the scan
    /// CONTINUES, so another item that genuinely has an emittable goodbye is still
    /// served this pass.  The 2 s ceiling remains the backstop for an item
    /// whose goodbye can never be encoded.  The loop still terminates: every
    /// iteration either returns a datagram, completes an item, or pushes one
    /// past `now`.
    ///
    /// # The round names the families it is FOR
    ///
    /// An item stays selectable while EITHER family still owes, so a round chosen
    /// for one family's sake is not a round the other one needs.
    /// [`WithdrawalTransmit::debt`] is what says which is which, and a driver must
    /// offer the datagram only to the families it names: a paid family's peers
    /// have already dropped the records, so another copy retracts nothing. §10.1
    /// permits the repeats, but with one family paid and the other retrying on the
    /// short backoff they arrive at that backoff's cadence rather than the §10.1
    /// interval, for as long as the item lives.
    ///
    /// Whatever a driver reports for a family this names as owing nothing is
    /// discarded — see [`Self::note_withdrawal_result`].
    ///
    /// Returns the [`WithdrawalTransmit`] describing the first due item that
    /// actually has records to emit, or `None` when no due item has anything to
    /// send (the empty/retained-only ones having been marked complete; the
    /// encode-failing ones having been pushed past `now`).
    pub fn poll_withdrawal_transmit(
      &mut self,
      now: I,
      scratch: &mut [u8],
    ) -> Option<WithdrawalTransmit> {
      loop {
        // An item is selectable when it still owes a round (`owed != [0, 0]`) AND
        // either:
        //   * it is DUE within the normal window — `next_at <= now < ceiling_at`; or
        //   * it is PAST the ceiling but has not yet had its one FINAL ceiling
        //     attempt (`now >= ceiling_at && !final_attempt`).  This is the
        //     guarantee: if the last backoff overshot `ceiling_at`, the still-owed
        //     family would otherwise never be tried in the `[last_attempt, ceiling]`
        //     window and the route would be force-freed with debt owed.  The
        //     `!final_attempt` guard makes this branch fire AT MOST ONCE per item,
        //     so the loop always terminates (drain then force-completes it).  An
        //     item whose debt is `[0, 0]` no longer matches, so the scan advances
        //     past it on the next turn.
        let (idx, token, route, is_final) =
          self
            .withdrawals
            .iter()
            .enumerate()
            .find_map(|(i, (tok, w))| {
              if w.owed == [0, 0] {
                return None;
              }
              if w.next_at <= now && now < w.ceiling_at {
                Some((i, *tok, w.route, false))
              } else if now >= w.ceiling_at && !w.final_attempt {
                Some((i, *tok, w.route, true))
              } else {
                None
              }
            })?;

        // Sibling-retained host addresses, recomputed each round into an owned Vec
        // (releasing the `self.services` borrow before we read the item + write
        // `scratch`).  An address some OTHER same-host route still advertises must
        // NOT be withdrawn.  ONLY a route-attached item withdraws host addresses; a
        // detached item has empty host lists, so skip the (route-table) scan for it.
        let retained = match route {
          Some(handle) => self.sibling_retained_addrs(handle),
          None => std::vec::Vec::new(),
        };

        // Read the item under a SCOPED borrow dropped before any mutation.
        // (`.get(idx)` cannot be `None` — `idx` came from the scan above — but it
        // sidesteps the `indexing_slicing` lint with no panic path.)
        let (_, w) = self.withdrawals.get(idx)?;
        // The families this round is FOR, captured with the same scoped borrow
        // that reads the records it encodes, so the debt handed out can only ever
        // be the debt the emitted datagram was chosen for.
        let debt = FamilyDebt::new(w.owed);
        // WHAT THE OWING FAMILIES ACTUALLY PUT ON THE WIRE — the union over the
        // families this round is FOR, not over both halves of the exposure. A
        // family whose debt is spent or was never owed contributes nothing, so a
        // generation IPv6 never carried is never named in a goodbye IPv6
        // receives: `owed[v6]` is `0` from the start (see `owed_per_family`), so
        // the round is v4's alone and so is its content.
        //
        // KNOWN RESIDUAL: while BOTH families still owe and their exposures
        // DIFFER — reachable when one confirmed send was partial and a later,
        // §7.1-trimmed one was not — the union names records the lesser family
        // did not carry. One item emits one datagram and the round's
        // `FamilyDebt` is what a driver fans it by, so separating the content
        // would mean handing out one round per family and teaching
        // `note_withdrawal_result` the difference between "owes" and "owes THIS
        // round" — a change to `WithdrawalTransmit`'s contract with every
        // driver. The narrowing above removes the case the exposure was designed
        // around (a family that carried NOTHING); what is left is a pre-existing,
        // strictly smaller instance of it.
        let owned = union_owed(&w.owned, w.owed);
        let has_something = owned.ptr()
          || owned.srv()
          || owned.txt()
          || owned.subtypes()
          || owned
            .a_slice()
            .iter()
            .any(|ip| !retained.contains(&core::net::IpAddr::V4(*ip)))
          || owned
            .aaaa_slice()
            .iter()
            .any(|ip| !retained.contains(&core::net::IpAddr::V6(*ip)));

        // Nothing left to withdraw (no owned instance records and every advertised
        // host address still retained by a sibling) → COMPLETE this item now
        // (`owed = [0, 0]`) and keep scanning; drain frees it. A final-ceiling
        // selection with nothing to emit is also handled here — zeroing the debt
        // lets drain free it without needing `final_attempt`.
        if !has_something {
          if let Some((_, w)) = self.withdrawals.get_mut(idx) {
            w.owed = [0, 0];
          }
          continue;
        }

        // Encode this name's single-name goodbye via the existing single-name
        // encoder: its emitted instance records + the sibling-filtered host
        // addresses. A detached item passes EMPTY host iterators (its lists are
        // empty), so `write_goodbye` produces an instance-only old-name goodbye —
        // no separate `write_rename_goodbye` path is needed.
        let encoded = crate::service::write_goodbye(
          &w.records,
          scratch,
          owned.ptr(),
          owned.srv(),
          owned.txt(),
          owned.subtypes(),
          owned
            .a_slice()
            .iter()
            .copied()
            .filter(|ip| !retained.contains(&core::net::IpAddr::V4(*ip))),
          owned
            .aaaa_slice()
            .iter()
            .copied()
            .filter(|ip| !retained.contains(&core::net::IpAddr::V6(*ip))),
        );
        match encoded {
          Ok(len) => {
            if is_final && let Some((_, w)) = self.withdrawals.get_mut(idx) {
              w.final_attempt = true;
            }
            return Some(WithdrawalTransmit::new(
              crate::service::multicast_dst(),
              len,
              token,
              debt,
            ));
          }
          Err(_) => {
            self.advance_after_encode_failure(idx, now, is_final);
            continue;
          }
        }
      }
    }

    /// Encode-failure scan-progress for one withdrawal item.
    ///
    /// An item whose goodbye does not fit `scratch` must NOT head-of-line block the
    /// pump at `now`. For a NORMAL (non-final) attempt this pushes `next_at`
    /// strictly past `now` (`now + WITHDRAWAL_RETRY_BACKOFF`, the item's debt budget
    /// intact) so the due scan won't re-select it this call; if the `Instant`
    /// saturated (the backoff cannot advance past `now`) the item's debt is zeroed
    /// so it can never be re-selected as due and re-fail forever (abandoning a
    /// goodbye we can neither encode nor reschedule is benign — the ceiling would
    /// force-complete it anyway). For the one FINAL ceiling attempt that could not
    /// be encoded, `final_attempt` is set so the past-ceiling scan branch cannot
    /// re-select this item forever; the next `drain_completed_withdrawals`
    /// force-completes it.
    pub(crate) fn advance_after_encode_failure(&mut self, idx: usize, now: I, is_final: bool) {
      let Some((_, w)) = self.withdrawals.get_mut(idx) else {
        return;
      };
      if is_final {
        // This WAS the final-ceiling attempt and it could not be encoded: burn it
        // so the past-ceiling scan branch cannot re-select this item forever (its
        // goodbye is unencodable). The next `drain_completed_withdrawals`
        // force-completes it — benign, as a permanently-unencodable goodbye is
        // abandoned anyway.
        w.final_attempt = true;
        return;
      }
      match now.checked_add_duration(WITHDRAWAL_RETRY_BACKOFF) {
        // Advanced strictly past `now`: the due scan won't re-select it this call,
        // so the loop makes progress.
        Some(t) if t > now => w.next_at = t,
        // The Instant saturated (backoff cannot advance past `now`): zero the
        // item's debt so it can never be re-selected as due — otherwise this same
        // item would be re-chosen and re-fail forever.
        _ => w.owed = [0, 0],
      }
    }


    /// Test-only: install what a confirmed service transmit would have mirrored
    /// into the route, without driving a real send.
    ///
    /// [`Self::note_service_transmit_outcome`] does this from a live confirm, and
    /// is where the shipped path is exercised. The rules these fixtures are about
    /// — sibling host-address retention, and the reclaim-cancel of a superseded
    /// detached goodbye — turn on the route state, not on how it got there, and
    /// reaching it through a real confirm would mean driving a whole §8.3
    /// announcement just to set two vectors and a flag.
    ///
    /// `fully_announced` is the ALL-delivered fact, exactly as
    /// [`Service::has_fully_announced`](crate::service::Service::has_fully_announced)
    /// reports it: only that gates the reclaim, because only for a link the
    /// announcement actually reached does §10.2's cache-flush supersede the stale
    /// records the goodbye exists to retract.
    #[cfg(test)]
    pub(crate) fn note_service_announced_for_test(
      &mut self,
      handle: ServiceHandle,
      fully_announced: bool,
      a: &[Ipv4Addr],
      aaaa: &[Ipv6Addr],
    ) {
      let name = {
        let Some((_, route)) = self.services.iter_mut().find(|(_, r)| r.handle() == handle) else {
          return;
        };
        route.advertised_a.clear();
        route.advertised_a.extend_from_slice(a);
        route.advertised_aaaa.clear();
        route.advertised_aaaa.extend_from_slice(aaaa);
        route.name().clone()
      };
      if fully_announced {
        self.reclaim_detached_goodbyes(handle, &name);
      }
    }

    /// Retire everything a fully-announced replacement at `name` SUPERSEDES of
    /// the reclaimable detached goodbyes still draining for that name — and keep
    /// what it does not.
    ///
    /// # An announcement retracts nothing it does not itself carry
    ///
    /// Deleting the whole item would rest on the reasoning that a complete
    /// §10.2 announcement of the same name leaves the old goodbye nothing to do.
    /// That holds for some of its records and not others:
    ///
    /// * the SRV and the TXT are UNIQUE at the instance name and the replacement
    ///   announces them with the cache-flush bit, so its own answer supersedes
    ///   the stale one — nothing left to retract;
    /// * the service-type PTR is SHARED, but the replacement asserts the
    ///   IDENTICAL record (same browse owner, and rdata is the instance name the
    ///   two share), so the cached entry is not stale at all — retracting it
    ///   would delete a record the replacement is currently publishing;
    /// * a REMOVED SUBTYPE PTR is neither. It is shared, so it carries no
    ///   cache-flush bit and nothing supersedes it implicitly; it is owned by a
    ///   `<sub>._sub.<type>` browse name the replacement does not publish, so no
    ///   answer of the replacement's carries it at all. RFC 6762 §10.1's TTL=0
    ///   goodbye is the ONLY way it is ever retracted. Deleting the item while it
    ///   still owes a family leaves that family's peers listing the instance
    ///   under a subtype it no longer has, for the full positive TTL.
    ///
    /// So the item is NARROWED to the shared PTRs the replacement's own record
    /// set does not assert, and drains its remaining per-family debt for those
    /// alone. When nothing survives the narrowing — the ordinary case, since
    /// most renames keep their subtypes and most services have none — the item is
    /// removed outright.
    ///
    /// # What the narrowing costs the relinquished screen: nothing
    ///
    /// A narrowed item stops answering [`Self::relinquished_asserts`] for the
    /// SRV / TXT / NSEC identities, since those are read out of the same
    /// exposure. That is not a loss:
    /// [`Self::enqueue_rename_withdrawal`] retains the old name's whole record
    /// set at the RENAME — up front, unconditionally, and for the full
    /// [`EndpointConfig::relinquished_retention`](crate::EndpointConfig::relinquished_retention)
    /// — precisely because a surviving rename's goodbye can be reclaimed long
    /// before that. The alternative, deleting the item, answers for nothing at
    /// all, so this direction cannot be the worse one.
    ///
    /// A no-op unless something is actually draining for `name`: the common
    /// announce confirm never reads the replacement's record set.
    pub(crate) fn reclaim_detached_goodbyes(&mut self, handle: ServiceHandle, name: &Name) {
      if !self
        .withdrawals
        .iter()
        .any(|(_, item)| reclaimable_for(item, name))
      {
        return;
      }
      // WHAT THE REPLACEMENT ITSELF ASSERTS at a shared owner name — its service
      // type and its subtype browse names, as registered. The route was resolved
      // a moment ago by the only caller, so this cannot miss; if it ever did,
      // cancelling nothing is the safe answer, because "superseded" is a claim
      // about the replacement's records and there would be none to read.
      let Some((_, route)) = self.services.iter().find(|(_, r)| r.handle() == handle) else {
        return;
      };
      let (service_type, subtypes) = (route.service_type().clone(), route.subtypes.clone());
      self.withdrawals.retain_mut(|(_, item)| {
        if !reclaimable_for(item, name) {
          return true;
        }
        // A shared PTR survives iff the replacement publishes no record at its
        // owner name. Their rdata needs no comparison: both PTRs point at the
        // instance name, and that the two names are the same is what put this
        // item in scope.
        let type_ptr = !item.records.service_type().same_owner(&service_type);
        item
          .records
          .retain_subtypes(|sub| !subtypes.iter().any(|kept| kept.same_owner(sub)));
        let subtypes_left = !item.records.subtype_names().is_empty();
        for (half, debt) in item.owned.iter_mut().zip(item.owed.iter_mut()) {
          half.keep_only_shared_ptrs(type_ptr, subtypes_left);
          // A family left with nothing to retract owes no further round, and
          // must not be sent one: it would carry the OTHER family's surviving
          // PTR as a TTL=0 record this family never advertised, which is the
          // over-withdrawal `owed_per_family` closes at the item's birth.
          if half.is_empty() {
            *debt = 0;
          }
        }
        // …and the SCREEN's half narrows in lockstep, so it never answers for
        // more than the goodbye half does. `multicast` is a subset of `owned` by
        // construction and this keeps it one; what either stops answering for,
        // the row `enqueue_rename_withdrawal` retained at the RENAME still holds.
        for half in item.multicast.iter_mut() {
          half.keep_only_shared_ptrs(type_ptr, subtypes_left);
        }
        // Kept only while some family still owes a record the announcement
        // cannot supersede. Otherwise this IS the whole-item cancel.
        item.owed != [0, 0]
      });
    }

    /// Host addresses that a LIVE same-host SIBLING route (any non-withdrawing
    /// route other than `handle`'s) still ADVERTISES — these must be RETAINED (not
    /// withdrawn) by `handle`'s goodbye, since another live service still owns
    /// them in peer caches.  This is the per-driver `retained_host_addrs` scan,
    /// centralised here where the endpoint holds every route's advertised set.
    ///
    /// Two exclusions matter for correctness:
    ///   * `route.withdrawing` siblings are SKIPPED — a sibling that is itself
    ///     leaving owns nothing to retain (e.g. a simultaneous same-host shutdown:
    ///     neither service must pin the shared address for the other).
    ///   * the CONFIRMED-ADVERTISED set (`advertised_a`/`advertised_aaaa`) is used,
    ///     NOT the configured `a_addrs`/`aaaa_addrs` — a registered-but-never-
    ///     announced sibling has configured addresses but advertised none, so it
    ///     retains nothing.
    pub(crate) fn sibling_retained_addrs(
      &self,
      handle: ServiceHandle,
    ) -> std::vec::Vec<core::net::IpAddr> {
      let Some(host) = self
        .services
        .iter()
        .find_map(|(_, r)| (r.handle() == handle).then(|| r.host().clone()))
      else {
        return std::vec::Vec::new();
      };
      let mut retained = std::vec::Vec::new();
      for (_, route) in self.services.iter() {
        if route.handle() != handle && !route.withdrawing && route.host().same_owner(&host) {
          retained.extend(
            route
              .advertised_a()
              .iter()
              .copied()
              .map(core::net::IpAddr::V4),
          );
          retained.extend(
            route
              .advertised_aaaa()
              .iter()
              .copied()
              .map(core::net::IpAddr::V6),
          );
        }
      }
      retained
    }

    /// Confirm the datagram most recently produced by
    /// [`Self::poll_withdrawal_transmit`] for `token`, reporting what EACH address
    /// family's transport did with it ([`FamilyAttempt`]) so withdrawal debt is
    /// tracked PER FAMILY. The token names exactly one `WithdrawalItem`, so no
    /// in-flight-part disambiguation is needed.
    ///
    /// The driver reports I/O-world facts; the core owns the spend / keep /
    /// write-off table they project onto — see `WithdrawalSend::project`, and note
    /// in particular that a PERMANENTLY-refused goodbye KEEPS its debt. Only an
    /// absent socket writes one off.
    ///
    /// `now` is the driver's own instant for this round, and unlike a positive-TTL
    /// confirm it is not folded from the attempts: what it re-arms is a §10.1
    /// resend SCHEDULE, a real-time spacing bound on one family's egress path, so
    /// it must be at or
    /// AFTER the round's last syscall rather than at the earliest acceptance. The
    /// two anchors are wrong in opposite directions and are not interchangeable.
    ///
    /// # A family that owed nothing is MASKED
    ///
    /// A driver offers the round only to the families
    /// [`WithdrawalTransmit::debt`] named, so it must invent SOME report for a
    /// family it withheld — no honest I/O fact describes "you told me it owed
    /// nothing". Whatever it invents is discarded here: a family whose debt was
    /// already zero when the round was handed out has its outcome ignored
    /// outright, so no laundering can cost a debt, spend a round, or count as
    /// progress. The mask is one-sided by construction — a driver that withholds a
    /// family which DID still owe loses that family one round, which the next
    /// schedule offers again.
    ///
    /// `next_at` re-arms at the full `WITHDRAWAL_INTERVAL` when a family made REAL
    /// progress this round — a `Sent` for a family that still OWED a goodbye
    /// (`owed[f] > 0` before this round). A `Sent` for an already-paid family
    /// (`owed[f] == 0`) is a redundant fan-out and is NOT progress: otherwise a
    /// paid v4 echoing `Sent` every round would keep re-arming at the full interval
    /// and starve a still-busy v6 of its short-backoff retry (risking a missed
    /// last-interval v6 recovery before the ceiling).  When no family made real
    /// progress (both `Retry`, or `Retry`+`WriteOff`, or only an already-paid family
    /// `Sent` while the other is busy) it re-arms at the short
    /// `WITHDRAWAL_RETRY_BACKOFF` so the still-owed family is retried soon rather
    /// than delayed a full interval.  Completion (every family's debt cleared, or the
    /// ceiling) is observed via `drain_completed_withdrawals`.
    ///
    /// An item therefore frees its route (route-attached) only once EVERY reachable
    /// family has withdrawn its records: v4-success while v6 stays busy does NOT
    /// complete it, so if v6 recovers before the 2 s ceiling its peers still receive
    /// the TTL=0 goodbye.
    ///
    /// No-op for an unknown token.
    pub fn note_withdrawal_result(
      &mut self,
      token: WithdrawalToken,
      now: I,
      v4: FamilyAttempt<I>,
      v6: FamilyAttempt<I>,
    ) {
      let Some((_, w)) = self.withdrawals.iter_mut().find(|(t, _)| *t == token) else {
        return;
      };
      let mut progressed = false;
      // Zip each family's debt counter (by mutable reference) with its outcome to
      // avoid dynamic indexing (clippy::indexing_slicing) into `owed`.
      //
      // The ZERO-DEBT MASK is the `*debt == 0` guard, and it is the whole of it: a
      // family that owed nothing when the round was handed out cannot have its
      // outcome change anything, whatever the driver reported. `Sent` on such a
      // family is a redundant fan-out rather than progress — were it counted, a
      // paid family echoing `Sent` every round would keep re-arming at the FULL
      // interval and starve a still-failing family of its short-backoff retry,
      // risking a missed last-interval recovery before the ceiling — and a
      // `WriteOff` cannot zero a debt that is already zero.
      let owed = &mut w.owed;
      for (debt, attempt) in owed.iter_mut().zip([v4, v6]) {
        if *debt == 0 {
          continue;
        }
        match WithdrawalSend::project(attempt) {
          WithdrawalSend::Sent => {
            // `*debt > 0` here, so this is `-= 1`; `saturating_sub` keeps it free of
            // `clippy::arithmetic_side_effects` (denied workspace-wide).
            *debt = debt.saturating_sub(1);
            progressed = true;
          }
          WithdrawalSend::Retry => {}
          WithdrawalSend::WriteOff => *debt = 0,
        }
      }
      // Progress (>= 1 family sent) → full interval; otherwise the short backoff so
      // a transiently-busy family is retried soon. A pure write-off round (no Sent)
      // also takes the short backoff, but its `owed` is already cleared so it will
      // not be re-selected as due unless the OTHER family still owes.
      //
      // CLAMP the re-arm to `ceiling_at`: a backoff that overshot the
      // ceiling would skip the `[last_attempt, ceiling]` window entirely, so a
      // family recovering in that window would never be retried in the normal due
      // window — the route would be force-freed with debt owed. Clamping keeps the
      // last scheduled attempt at the ceiling, where `poll_withdrawal_transmit`'s
      // past-ceiling branch then emits exactly one final goodbye.
      let gap = if progressed {
        WITHDRAWAL_INTERVAL
      } else {
        WITHDRAWAL_RETRY_BACKOFF
      };
      w.next_at = now
        .checked_add_duration(gap)
        .unwrap_or(now)
        .min(w.ceiling_at);
    }

    /// Remove every withdrawal ITEM that has COMPLETED — either every family's
    /// resend budget is spent or written off (`owed == [0, 0]`), OR it has passed
    /// its anti-pin ceiling (`now >= ceiling_at`) AND its one final ceiling attempt
    /// has been made (`final_attempt`).
    ///
    /// For each completed item:
    ///   * a ROUTE-attached item (`route == Some(handle)`) frees its proto route —
    ///     releasing the name for re-registration and decrementing
    ///     `services_active` — and pushes `handle` into `out` so the driver can GC
    ///     its driver-side slot;
    ///   * a DETACHED item (`route == None`, a renamed-away old name) is simply
    ///     removed: it owns no route, holds no name, and is reported to NOBODY (push
    ///     nothing into `out`).
    ///
    /// Either way the item's record set is RETAINED as relinquished for
    /// [`EndpointConfig::relinquished_retention`](crate::EndpointConfig::relinquished_retention)
    /// first. This item was the last resident description of a set this endpoint
    /// put on the wire, and a route-attached one is about to release its owner
    /// names for re-registration — so without that hand-off a delayed
    /// positive-TTL echo of it would be adjudicated against its own successor.
    ///
    /// Call once per pump, after draining withdrawal transmits.
    ///
    /// The ceiling guarantees that an item whose families are permanently
    /// unreachable still completes (and a route-attached one releases its name) — a
    /// down family has no reachable peers to evict, so force-completing it is
    /// benign.
    ///
    /// The `final_attempt` conjunct gives an owed family ONE last
    /// goodbye AT the ceiling before the item is removed: an item that is past
    /// `ceiling_at` but still owes a family AND has not yet been final-attempted is
    /// NOT completed here — it is left for the very next `poll_withdrawal_transmit`,
    /// whose past-ceiling branch emits that final goodbye and sets `final_attempt`,
    /// after which this method removes it. The drivers always pump
    /// `poll_withdrawal_transmit` (then `note_withdrawal_result`) before this call,
    /// so the final attempt and the free happen within the same pump cycle. An
    /// unencodable / nothing-to-emit goodbye sets `final_attempt` (or zeroes `owed`)
    /// in `poll_withdrawal_transmit` too, so a route can never be pinned past the
    /// ceiling waiting for a final attempt that can't be made.
    pub fn drain_completed_withdrawals<E: Extend<ServiceHandle>>(&mut self, now: I, out: &mut E) {
      // Collect completed tokens first so the route/withdrawal removals below do
      // not fight the iteration borrow.
      let completed: std::vec::Vec<WithdrawalToken> = self
        .withdrawals
        .iter()
        .filter(|(_, w)| w.owed == [0, 0] || (now >= w.ceiling_at && w.final_attempt))
        .map(|(t, _)| *t)
        .collect();
      for token in completed {
        // Take the item out; a route-attached one frees its route + reports the
        // handle, a detached one just vanishes.
        let Some(pos) = self.withdrawals.iter().position(|(t, _)| *t == token) else {
          continue;
        };
        let (_, item) = self.withdrawals.remove(pos);
        let route = item.route;
        // This item was the last resident copy of a record set this endpoint
        // asserted, and a route-attached one is about to release its owner names
        // for re-registration. Move the set into the relinquished list so a
        // delayed positive-TTL echo of it is still recognised as OURS by the
        // conflict fan-out — the successor at those names cannot recognise it.
        //
        // The item's own EXPOSURE goes with it, and the whole of it: these are
        // the sets `Service::withdrawal_snapshot` reported as confirmed-emitted,
        // so the row disowns exactly the records that were transmitted. A
        // never-announced service's item carries none, and `retain_relinquished`
        // then retains nothing at all rather than screening its whole configured
        // record set.
        self.retain_relinquished(item.records, item.multicast, now);
        let Some(handle) = route else {
          // Detached (renamed-away old name): no route, no name, report to nobody.
          continue;
        };
        // Free the proto route: releases the name and decrements services_active.
        let key = self
          .services
          .iter()
          .find(|(_, route)| route.handle() == handle)
          .map(|(k, _)| k);
        if let Some(k) = key {
          let removed = self.services.try_remove(k).is_some();
          #[cfg(feature = "stats")]
          if removed {
            self.stats.decr_services_active(1);
          }
          #[cfg(not(feature = "stats"))]
          let _ = removed;
        }
        out.extend(core::iter::once(handle));
      }
    }
  }

  /// Test-only: the opaque token of the ROUTE-attached withdrawal item for
  /// `handle`, so a test can confirm/round-trip exactly that item's send. `None`
  /// if no route-attached item exists for `handle`.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  pub(crate) fn route_withdrawal_token(&self, handle: ServiceHandle) -> Option<WithdrawalToken> {
    self
      .withdrawals
      .iter()
      .find(|(_, w)| w.route == Some(handle))
      .map(|(t, _)| *t)
  }

  /// Test-only: confirm a round by the DEBT EFFECT it should have, rather than by
  /// the I/O outcome that projects onto it. The debt tests are about spend / keep
  /// / write-off; the projection has its own tests, which build attempts
  /// explicitly.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  pub(crate) fn note_withdrawal_sends(
    &mut self,
    token: WithdrawalToken,
    now: I,
    v4: WithdrawalSend,
    v6: WithdrawalSend,
  ) {
    self.note_withdrawal_result(token, now, v4.as_attempt(now), v6.as_attempt(now));
  }

  /// Test-only: confirm a send for the ROUTE-attached item of `handle` by looking
  /// up its token internally (a no-op if the item is gone). Lets handle-oriented
  /// tests spend a route withdrawal's debt without threading the token through.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  pub(crate) fn note_route_withdrawal_result(
    &mut self,
    handle: ServiceHandle,
    now: I,
    v4: WithdrawalSend,
    v6: WithdrawalSend,
  ) {
    if let Some(tok) = self.route_withdrawal_token(handle) {
      self.note_withdrawal_sends(tok, now, v4, v6);
    }
  }

  /// Test-only: the PER-FAMILY resend budget (`[v4, v6]`) of the ROUTE-attached
  /// withdrawal item for `handle` (the current-name goodbye), or `None` if no
  /// such item exists.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  pub(crate) fn route_withdrawal_owed(&self, handle: ServiceHandle) -> Option<[u8; 2]> {
    self
      .withdrawals
      .iter()
      .find(|(_, w)| w.route == Some(handle))
      .map(|(_, w)| w.owed)
  }

  /// Test-only: the PER-FAMILY resend budget (`[v4, v6]`) of the DETACHED
  /// withdrawal item whose records name `instance` (the renamed-away old-name
  /// goodbye), or `None` if no such item exists.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  pub(crate) fn detached_withdrawal_owed_for(&self, instance: &Name) -> Option<[u8; 2]> {
    self
      .withdrawals
      .iter()
      .find(|(_, w)| {
        w.route.is_none()
          && w
            .records
            .instance()
            .as_str()
            .eq_ignore_ascii_case(instance.as_str())
      })
      .map(|(_, w)| w.owed)
  }

  /// Test-only: the next scheduled send time of the ROUTE-attached withdrawal
  /// item for `handle`.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  pub(crate) fn route_withdrawal_next_at(&self, handle: ServiceHandle) -> Option<I> {
    self
      .withdrawals
      .iter()
      .find(|(_, w)| w.route == Some(handle))
      .map(|(_, w)| w.next_at)
  }
}

cfg_heap! {
  /// Is `item` a RECLAIMABLE detached goodbye for `name` — a SURVIVING §9
  /// rename's renamed-away old name, which a replacement at that name may
  /// reclaim?
  ///
  /// The three conjuncts are the whole of the reclaim scope. A route-attached
  /// item belongs to a live route and is freed by its own drain; a `holds_name`
  /// item is a rename-COLLISION teardown's, whose dead service's records must be
  /// retracted BEFORE the name is reused and which is therefore never cancelled;
  /// and the name is matched by DNS-name equality, not string equality, since a
  /// spelling differing only in the trailing root dot is the same owner on the
  /// wire.
  fn reclaimable_for<I>(item: &WithdrawalItem<I>, name: &Name) -> bool {
    item.route.is_none() && !item.holds_name && item.records.instance().same_owner(name)
  }

  /// What the families that STILL OWE a goodbye round put on the wire, as one
  /// report.
  ///
  /// A family whose debt is `0` — spent, written off, or never owed because it
  /// carried nothing — contributes nothing, so its records are never named in a
  /// datagram the remaining families receive. See the residual noted at the call
  /// site for the case this does not reach.
  pub(crate) fn union_owed(
    owned: &[crate::service::EmittedRecords; 2],
    owed: [u8; 2],
  ) -> crate::service::EmittedRecords {
    let mut out = crate::service::EmittedRecords::default();
    for (e, debt) in owned.iter().zip(owed) {
      if debt == 0 {
        continue;
      }
      out.merge_instance(e);
      out.merge_addrs(e);
    }
    out
  }

  /// The RFC 6762 §10.1 goodbye budget each family owes for `owned`.
  ///
  /// `WITHDRAWAL_SENDS` for a family that actually put a retractable record in
  /// its peers' caches, `0` for one that did not. A family with nothing cached
  /// from us has nothing to retract, and a TTL=0 goodbye it never earned can
  /// cache-flush a peer's matching shared record — the same over-withdrawal
  /// class `EmittedRecords`' per-record granularity closes, one dimension over.
  ///
  /// [`EmittedRecords::is_empty`](crate::service::EmittedRecords::is_empty) is
  /// the right test and the §6.1 NSEC's absence from it is deliberate: a goodbye
  /// emits no NSEC, so an exposure that is nothing BUT an NSEC owes no rounds.
  /// The relinquished-RRset screen still sees it — that is a different question,
  /// asked of what we TRANSMITTED rather than of what peers can be told to drop.
  pub(crate) fn owed_per_family(owned: &[crate::service::EmittedRecords; 2]) -> [u8; 2] {
    let [v4, v6] = owned;
    let budget = |e: &crate::service::EmittedRecords| {
      if e.is_empty() { 0 } else { WITHDRAWAL_SENDS }
    };
    [budget(v4), budget(v6)]
  }
}

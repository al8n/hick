//! Service withdrawal (TTL=0 goodbye) lifecycle.

use super::*;

impl<I, R, C, SR, QS, EV, AN, EvQ> Endpoint<I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: Rng,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
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
    /// [`Self::handle_service_renamed`]), so it is already its own INDEPENDENT
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
    /// `snapshot` must come from a
    /// [`Service::withdrawal_snapshot`](crate::service::Service::withdrawal_snapshot)
    /// taken with no datagram outstanding — i.e. after the service's last
    /// `poll_transmit` was confirmed. A snapshot taken mid-flight omits the
    /// records that datagram is about to place in peer caches, and this goodbye
    /// can only withdraw what the snapshot names. See
    /// [`Service::poll_transmit`](crate::service::Service::poll_transmit).
    pub fn begin_withdrawal(
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

      // next_at = now (first send fires immediately); ceiling_at = now +
      // WITHDRAWAL_CEILING (hard anti-pin deadline).
      let ceiling_at = now.checked_add_duration(WITHDRAWAL_CEILING).unwrap_or(now);

      // ── route-attached item: the CURRENT (live / re-announced) name ──────────
      // Owes a goodbye iff it actually advertised an instance record OR a host
      // address; otherwise `[0, 0]` so the next `drain_completed_withdrawals` frees
      // the name at once with no spurious goodbye and no 2 s ceiling wait.
      let current_has_something =
        !snapshot.owned.is_empty() || !snapshot.host_a.is_empty() || !snapshot.host_aaaa.is_empty();
      let current_owed = if current_has_something {
        [WITHDRAWAL_SENDS, WITHDRAWAL_SENDS]
      } else {
        [0, 0]
      };

      let crate::service::WithdrawalSnapshot {
        records,
        owned,
        host_a,
        host_aaaa,
      } = snapshot;

      let token = self.mint_withdrawal_token();
      self.withdrawals.push((
        token,
        WithdrawalItem {
          records,
          owned,
          host_a,
          host_aaaa,
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
    /// The driver calls this immediately after [`Self::handle_service_renamed`],
    /// passing the
    /// [`RenameGoodbyeHandoff`](crate::service::RenameGoodbyeHandoff) it took from
    /// [`Service::take_rename_goodbye_handoff`](crate::service::Service::take_rename_goodbye_handoff)
    /// (the old name's records + the per-record ownership of what it advertised).
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
    pub fn enqueue_rename_withdrawal(
      &mut self,
      handoff: crate::service::RenameGoodbyeHandoff,
      now: I,
      holds_name: bool,
    ) {
      let crate::service::RenameGoodbyeHandoff { records, owned } = handoff;
      // Nothing for peers to evict → no item.
      if owned.is_empty() {
        return;
      }
      let ceiling_at = now.checked_add_duration(WITHDRAWAL_CEILING).unwrap_or(now);
      let token = self.mint_withdrawal_token();
      self.withdrawals.push((
        token,
        WithdrawalItem {
          records,
          owned,
          host_a: std::vec::Vec::new(),
          host_aaaa: std::vec::Vec::new(),
          owed: [WITHDRAWAL_SENDS, WITHDRAWAL_SENDS],
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
    /// Returns `(multicast dst, datagram length, the item's [`WithdrawalToken`])`
    /// for the first due item that actually has records to emit, or `None` when no
    /// due item has anything to send (the empty/retained-only ones having been
    /// marked complete; the encode-failing ones having been pushed past `now`).
    pub fn poll_withdrawal_transmit(
      &mut self,
      now: I,
      scratch: &mut [u8],
    ) -> Option<(SocketAddr, usize, WithdrawalToken)> {
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
        let owned = &w.owned;
        let has_something = owned.ptr()
          || owned.srv()
          || owned.txt()
          || owned.subtypes()
          || w
            .host_a
            .iter()
            .any(|ip| !retained.contains(&core::net::IpAddr::V4(*ip)))
          || w
            .host_aaaa
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
          w.host_a
            .iter()
            .copied()
            .filter(|ip| !retained.contains(&core::net::IpAddr::V4(*ip))),
          w.host_aaaa
            .iter()
            .copied()
            .filter(|ip| !retained.contains(&core::net::IpAddr::V6(*ip))),
        );
        match encoded {
          Ok(len) => {
            if is_final && let Some((_, w)) = self.withdrawals.get_mut(idx) {
              w.final_attempt = true;
            }
            return Some((crate::service::multicast_dst(), len, token));
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

    /// Record the host addresses a service has CONFIRMED-ADVERTISED on the wire,
    /// overwriting the route's advertised set.  The driver calls this after a
    /// confirmed-delivered service announce with the Service's current
    /// [`Service::advertised_a_addrs`]/[`Service::advertised_aaaa_addrs`] sets
    /// (the confirmed-emitted / goodbye-owned host addresses).
    ///
    /// This is the set sibling host-address retention consults to decide which
    /// host addresses a withdrawing same-host sibling must RETAIN — distinct from
    /// the configured [`ServiceRoute::a_addrs`] captured at registration (which a
    /// never-announced service has, despite having advertised nothing).
    ///
    /// Idempotent overwrite (the advertised set only grows as the service
    /// announces), and a no-op for a handle the endpoint does not route.
    ///
    /// # `announced`
    ///
    /// The RECLAIM-CANCEL gate, and the only place the target service is named.
    /// A [`FullyAnnounced`] that reads `true` retires any reclaimable detached
    /// goodbye still draining for that service's instance name (see below).
    ///
    /// The parameter is the opaque token rather than a `bool` because no
    /// driver-side formula is admissible here: it must be
    /// [`Service::has_fully_announced`] and nothing else. In particular it is NOT
    /// [`Service::advertises_instance`] — that latch fires on ANY delivery, so a
    /// v4-only announcement, or an RFC 6762 §6.7 legacy unicast reply (one
    /// obligated link, hence fully delivered by construction), would cancel a
    /// goodbye the unserved family still needs. Since [`FullyAnnounced`] has no
    /// public constructor, that substitution does not compile.
    ///
    /// The route is looked up through the token's own
    /// [`ServiceHandle`] rather than a separate argument, so a genuine token from
    /// one service cannot be applied to another. A caller CAN still pass `a` /
    /// `aaaa` slices read from a different service; that mis-records an advertised
    /// address set (a sibling-retention input) and is a strictly smaller fault
    /// than cancelling the wrong service's goodbye.
    ///
    /// # Examples
    ///
    /// The token names its own service, so the confirm takes no separate handle:
    ///
    // This doctest and its `compile_fail` twin below share a preamble that needs
    // BOTH `std` (the `StdInstant` alias only implements `mdns_proto::Instant`
    // under `std`, see `time.rs`) AND `slab` (`slab::Slab` only implements
    // `mdns_proto::Pool` under `slab`, see `pool.rs`) to compile at all. Gate
    // both fences on `all(std, slab)` — they are a deliberate pair: the twin
    // below proves the handle mismatch fails to compile for the RIGHT reason,
    // and this one proves the shared preamble compiles when both features are
    // present. Gating or deleting only one lets the other pass vacuously
    // elsewhere: a preamble that fails to *build* (missing `std` or `slab`,
    // e.g. the `alloc`-only tier, or the `std`-without-`slab` tiers such as
    // plain `std` or `metrics`) is not the same as the API *rejecting* the
    // mismatch it documents. Keep them gated together.
    #[cfg_attr(all(feature = "std", feature = "slab"), doc = "```")]
    #[cfg_attr(not(all(feature = "std", feature = "slab")), doc = "```ignore")]
    /// # use core::net::{Ipv4Addr, Ipv6Addr};
    /// # use std::time::Instant as StdInstant;
    /// # use mdns_proto::{
    /// #   CollectedAnswer, FullyAnnounced,
    /// #   cache::CacheEntry,
    /// #   endpoint::{Endpoint, EndpointEventEntry, ServiceRoute},
    /// #   event::QueryUpdate,
    /// #   query::Query,
    /// # };
    /// # use slab::Slab;
    /// # type Q = Query<StdInstant, Slab<CollectedAnswer>, Slab<QueryUpdate>>;
    /// # type Ep = Endpoint<
    /// #   StdInstant,
    /// #   rand::rngs::StdRng,
    /// #   Slab<CacheEntry<StdInstant>>,
    /// #   Slab<ServiceRoute>,
    /// #   Slab<Q>,
    /// #   Slab<EndpointEventEntry>,
    /// #   Slab<CollectedAnswer>,
    /// #   Slab<QueryUpdate>,
    /// # >;
    /// fn confirm(ep: &mut Ep, announced: FullyAnnounced, a: &[Ipv4Addr], aaaa: &[Ipv6Addr]) {
    ///   ep.note_service_announced(announced, a, aaaa);
    /// }
    /// ```
    ///
    /// Pairing one service's proof with ANOTHER service's handle — the transplant
    /// this signature exists to rule out — does not compile:
    ///
    // Paired with the positive doctest above over the same preamble that needs
    // BOTH `std` and `slab` (see the comment there for why). Gated identically
    // so this can't start passing vacuously — for the wrong reason — on a tier
    // missing either feature.
    #[cfg_attr(all(feature = "std", feature = "slab"), doc = "```compile_fail")]
    #[cfg_attr(not(all(feature = "std", feature = "slab")), doc = "```ignore")]
    /// # use core::net::{Ipv4Addr, Ipv6Addr};
    /// # use std::time::Instant as StdInstant;
    /// # use mdns_proto::{
    /// #   CollectedAnswer, FullyAnnounced, ServiceHandle,
    /// #   cache::CacheEntry,
    /// #   endpoint::{Endpoint, EndpointEventEntry, ServiceRoute},
    /// #   event::QueryUpdate,
    /// #   query::Query,
    /// # };
    /// # use slab::Slab;
    /// # type Q = Query<StdInstant, Slab<CollectedAnswer>, Slab<QueryUpdate>>;
    /// # type Ep = Endpoint<
    /// #   StdInstant,
    /// #   rand::rngs::StdRng,
    /// #   Slab<CacheEntry<StdInstant>>,
    /// #   Slab<ServiceRoute>,
    /// #   Slab<Q>,
    /// #   Slab<EndpointEventEntry>,
    /// #   Slab<CollectedAnswer>,
    /// #   Slab<QueryUpdate>,
    /// # >;
    /// fn transplant(
    ///   ep: &mut Ep,
    ///   other: ServiceHandle,
    ///   announced_by_someone_else: FullyAnnounced,
    ///   a: &[Ipv4Addr],
    ///   aaaa: &[Ipv6Addr],
    /// ) {
    ///   ep.note_service_announced(other, a, aaaa, announced_by_someone_else);
    /// }
    /// ```
    ///
    /// [`Service::advertised_a_addrs`]: crate::service::Service::advertised_a_addrs
    /// [`Service::advertised_aaaa_addrs`]: crate::service::Service::advertised_aaaa_addrs
    /// [`Service::has_fully_announced`]: crate::service::Service::has_fully_announced
    /// [`Service::advertises_instance`]: crate::service::Service::advertises_instance
    pub fn note_service_announced(
      &mut self,
      announced: FullyAnnounced,
      a: &[Ipv4Addr],
      aaaa: &[Ipv6Addr],
    ) {
      let handle = announced.handle();
      let fully_announced = announced.get();
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
      // CANCEL-ON-ANNOUNCE: a service that has CONFIRMED-ADVERTISED
      // its instance records under `name` supersedes any RECLAIMABLE detached
      // old-name goodbye for the same name — cancel it. This lives here, on a certain
      // live event, rather than in `try_register_service` (a registration is only
      // async-committed across the reactor's reply boundary; cancelling at register
      // time could lose the goodbye if the caller dropped the registration before
      // owning the service — ).
      //
      // The cancel is GATED on `fully_announced`: this hook is called after EVERY
      // delivered service transmit, INCLUDING probes and responses, so cancelling on
      // one of those would drop the goodbye before the reclaiming service ever
      // announced — losing the retraction if it then drops, conflicts, or renames
      // away. The address args cannot serve as the guard (an address-less service
      // advertises no host addresses).
      //
      // The gate must be the ALL-delivered fact, not the any-delivered exposure
      // latch: it may fire only once a complete announcement of this name has
      // reached every link the driver still obligates, because only for such a link
      // does §10.2's cache-flush announcement supersede the stale unique records the
      // goodbye exists to retract. A partially-delivered announcement therefore
      // leaves the old goodbye draining its per-family debt, which is exactly the
      // case where the unserved family has heard neither the goodbye nor the
      // replacement.
      //
      // If the new service never fully announces, the goodbye is NEVER cancelled and
      // completes normally. A name-HOLDING collision goodbye is left intact.
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      if fully_announced {
        self.withdrawals.retain(|(_, item)| {
          !(item.route.is_none()
            && !item.holds_name
            && item.records.instance().as_str() == name.as_str())
        });
      }
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
        if route.handle() != handle && !route.withdrawing && route.host() == &host {
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
    /// [`Self::poll_withdrawal_transmit`] for `token`, reporting the outcome for
    /// EACH address family ([`WithdrawalSend`] for `v4` and `v6`) so withdrawal
    /// debt is tracked PER FAMILY. The token names exactly one
    /// `WithdrawalItem`, so no in-flight-part disambiguation is needed.
    ///
    /// Per family `f`:
    ///   * [`WithdrawalSend::Sent`] — the goodbye reached that family's wire, so
    ///     spend one of its owed rounds (`owed[f] = owed[f].saturating_sub(1)`).
    ///   * [`WithdrawalSend::Retry`] — transiently undeliverable (socket busy):
    ///     keep that family's debt for a later retry.
    ///   * [`WithdrawalSend::WriteOff`] — that family is permanently unavailable
    ///     (no socket / permanent send error): zero its debt (`owed[f] = 0`), since
    ///     it has no reachable peers to withdraw from.
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
      v4: WithdrawalSend,
      v6: WithdrawalSend,
    ) {
      let Some((_, w)) = self.withdrawals.iter_mut().find(|(t, _)| *t == token) else {
        return;
      };
      let mut progressed = false;
      // Zip each family's debt counter (by mutable reference) with its outcome to
      // avoid dynamic indexing (clippy::indexing_slicing) into `owed`.
      //
      // A `Sent` counts as progress ONLY when that family still OWED a goodbye
      // before this round (`*debt > 0`). Drivers fan every round's datagram to BOTH
      // families, so a family whose debt is already 0 keeps reporting `Sent`; if that
      // redundant send counted as progress it would re-arm at the FULL interval and
      // starve a still-busy family of its short-backoff retry, risking a missed
      // last-interval recovery before the ceiling. So a `Sent` on an already-paid
      // family changes nothing — neither the debt nor the schedule.
      let owed = &mut w.owed;
      for (debt, outcome) in owed.iter_mut().zip([v4, v6]) {
        match outcome {
          WithdrawalSend::Sent if *debt > 0 => {
            // `*debt > 0` here, so this is `-= 1`; `saturating_sub` keeps it free of
            // `clippy::arithmetic_side_effects` (denied workspace-wide).
            *debt = debt.saturating_sub(1);
            progressed = true;
          }
          // Redundant send on an already-paid family (`*debt == 0`): no progress.
          WithdrawalSend::Sent => {}
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
        let Some(handle) = item.route else {
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
      self.note_withdrawal_result(tok, now, v4, v6);
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

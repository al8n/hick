//! Service registration, unregistration, and conflict-driven rename.

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
  /// Does any LIVE route publish `host` with an A or AAAA set that CONTRADICTS
  /// the one given? `exclude` skips one route key, for a check that re-examines a
  /// route already in the table.
  ///
  /// # The invariant, and what it protects
  ///
  /// Two services may share a host name — that is how several services on one
  /// machine advertise one set of addresses, and it is supported. What must not
  /// differ is the ADDRESSES WITHIN AN RRTYPE BOTH PUBLISH: RFC 6762 §9's
  /// conflict test compares a record against the RECEIVING service's own records,
  /// so a sibling's A/AAAA at a shared host name with rdata this service holds a
  /// contradicting set for is, by that test, a genuine conflict — and `Endpoint`
  /// has no auto-rename for a host name, so it surfaces as a TERMINAL
  /// `ServiceUpdate::HostConflict`, raised by a sibling on the same machine
  /// rather than by any peer.
  ///
  /// Nothing upstream blocks that path: a content match with no ordering
  /// evidence adjudicates rather than being suppressed (see
  /// [`Provenance::OwnEchoLikely`](crate::Provenance::OwnEchoLikely)), which is
  /// what makes this guard the FOURTH invariant that cell's safety rests on.
  ///
  /// # PER RRTYPE, and only where both routes publish that type
  ///
  /// §9 makes a conflict "the same name, **rrtype** and rrclass, but
  /// inconsistent rdata", so the A RRset at a host name and the AAAA RRset at it
  /// are two DISTINCT unique RRsets, each singly owned. An IPv4-only service and
  /// an IPv6-only service sharing one host name publish disjoint RRsets that
  /// cannot be inconsistent with each other — a legitimate configuration this
  /// crate documents as supported, and one an all-or-nothing comparison bans.
  ///
  /// A route that publishes no record of a type asserts nothing at that name for
  /// the other to disagree with, so that type is simply not compared. This is
  /// the same rule the conflict fan-out applies — see
  /// [`route_publishes_host_rtype`](crate::endpoint::route_publishes_host_rtype)
  /// and `Service::classify_host_rdata` — and the two halves must stay together:
  /// relaxing only this one would admit the split-family pair and then let a
  /// fan-out that reads an ABSENT RRtype as differing raise a terminal
  /// `HostConflict` on the sibling's first announcement.
  ///
  /// # Set equality, and only of what is configured
  ///
  /// Where both DO publish a type, the two sets are compared as SETS in both
  /// directions, because the conflict classifier asks `contains`, and mutual
  /// containment is exactly what makes it answer "identical" for every address
  /// either side can put on the wire. Order and repetition are therefore
  /// irrelevant, and a re-registration that lists the same addresses differently
  /// is not rejected.
  ///
  /// The CONFIGURED sets are compared, not the confirmed-advertised ones: what a
  /// service has advertised so far is a subset of what it may advertise next, so
  /// only the configured sets bound every datagram a sibling can send.
  ///
  /// Interface SCOPES are not compared. The host-conflict classifier reads bare
  /// A/AAAA rdata and has no scope to compare against, so scope cannot turn an
  /// identical address into a conflict.
  ///
  /// # Withdrawing routes are skipped
  ///
  /// A withdrawing route is skipped by every conflict fan-out in
  /// [`RouteEvents`](super::RouteEvents), so it can neither raise nor receive the
  /// event this guards against, and `withdrawing` is set once and never cleared.
  /// Counting one would block a replacement service from taking over a host name
  /// with a new address set until the outgoing goodbye drained.
  ///
  /// Skipped as a PARTY to the conflict, that is — its record set is still read
  /// as EVIDENCE. Letting the replacement in is precisely what puts a delayed
  /// echo of the outgoing route's own addresses in front of a service that holds
  /// different ones, so `Endpoint::relinquished_asserts` screens every conflict
  /// candidate against the withdrawing route's set before the fan-out builds an
  /// event from it. The two halves belong together: relaxing this guard without
  /// that screen is what makes our own past retire our own present.
  fn host_addresses_disagree(
    &self,
    host: &Name,
    a_addrs: &[Ipv4Addr],
    aaaa_addrs: &[Ipv6Addr],
    exclude: Option<usize>,
  ) -> bool {
    /// Do these two routes DISAGREE about one RRtype at the shared host name?
    ///
    /// Only when both publish it: an empty side is a route that asserts no
    /// record of that type there, which §9 leaves out of the conflict entirely.
    fn rrset_disagrees<T: PartialEq>(theirs: &[T], ours: &[T]) -> bool {
      if theirs.is_empty() || ours.is_empty() {
        return false;
      }
      !(theirs.iter().all(|x| ours.contains(x)) && ours.iter().all(|x| theirs.contains(x)))
    }
    self.services.iter().any(|(key, route)| {
      if Some(key) == exclude {
        return false;
      }
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      if route.withdrawing {
        return false;
      }
      // Semantic DNS-name equality, because that is how the routing path
      // matches a record against a host name — a string test here lets a
      // spelling that differs only in case or in the optional trailing root dot
      // register past the guard and conflict on the wire anyway. See
      // [`Name::same_owner`], which is where the rule lives.
      if !route.host().same_owner(host) {
        return false;
      }
      rrset_disagrees(route.a_addrs(), a_addrs) || rrset_disagrees(route.aaaa_addrs(), aaaa_addrs)
    })
  }

  /// Register a new service. Returns the handle and a `Service` state-machine.
  ///
  /// # Errors
  ///
  /// Returns [`RegisterServiceError::NameAlreadyRegistered`] if the instance name
  /// belongs to another registered service, or is still held by an unfinished
  /// RFC 6762 §10.1 goodbye that must retract it before the name is reused.
  ///
  /// Returns [`RegisterServiceError::TtlTooSmall`] if the records' TTL is below
  /// [`MIN_SERVICE_TTL_SECS`](crate::constants::MIN_SERVICE_TTL_SECS): a TTL of 0
  /// is the §10.1 goodbye encoding rather than an advertisement, and a TTL of 1
  /// refreshes inside §8.3's one-second floor. The TTL is rejected rather than
  /// clamped — silently publishing a service at a lifetime the caller did not ask
  /// for is the kind of surprise a registration API should not hand back.
  ///
  /// Returns [`RegisterServiceError::ServiceTypeIsRoot`] if `service_type` is
  /// the DNS root (the empty [`Name`]). RFC 6763 §4.1.2 defines `<Service>` as
  /// exactly two labels, so the root can never be valid — checked before, and
  /// independently of, the parent-label-sequence test below, because the root
  /// genuinely IS the immediate parent of any single-label `instance` and so
  /// would otherwise pass it.
  ///
  /// Returns [`RegisterServiceError::ServiceTypeNotParent`] if `service_type`
  /// is not the parent label sequence of `instance` — i.e. `instance` is not
  /// exactly one label longer than `service_type` (case-insensitively, and
  /// blind to the optional trailing root dot on either name). RFC 6763 §4.1: a
  /// Service Instance Name is `<Instance> . <Service> . <Domain>`, and §4.1.1
  /// stores `<Instance>` as a single DNS label, so this can only ever be
  /// EXACTLY one label — never zero, never several.
  ///
  /// Returns [`RegisterServiceError::HostAddressesDiffer`] if a live route
  /// already publishes this host name with a different A or AAAA set. **Two live
  /// services may share a host name, but where both publish an RRtype they must
  /// publish the same addresses under it.** RFC 6762 §9 classifies a conflict
  /// against the RECEIVING service's own records, so a sibling advertising that
  /// host with a different set is a genuine conflict by that test — and a host
  /// name has no auto-rename, so it surfaces as a terminal update rather than
  /// resolving itself.
  ///
  /// The comparison is PER RRTYPE, because §9's conflict is "the same name,
  /// rrtype and rrclass, but inconsistent rdata": an IPv4-only service and an
  /// IPv6-only service may share a host name, since disjoint A and AAAA RRsets
  /// cannot be inconsistent with one another. Where both routes do publish a
  /// type, its two sets are compared as SETS, so order and repeats do not matter
  /// and an IPv6 scope id does. The host name is matched by DNS-name equality
  /// ([`Name::same_owner`] — case-insensitive, and blind to the optional
  /// trailing root dot), the way the routing path matches a record against it. A
  /// route already withdrawing under §10.1 no longer holds its host name for
  /// this test.
  ///
  /// Returns [`RegisterServiceError::StorageFull`] if the routing pool is at
  /// capacity.
  pub fn try_register_service<TQ, EvS>(
    &mut self,
    spec: ServiceSpec,
    now: I,
  ) -> Result<(ServiceHandle, Service<I, TQ, EvS>), RegisterServiceError>
  where
    TQ: Pool<Transmit>,
    EvS: Pool<crate::event::ServiceUpdate>,
  {
    // A TTL the periodic refresh cannot legally sustain is rejected before the
    // name is reserved: `periodic_refresh_secs` truncates a sub-2 s TTL to a
    // zero-second re-announce interval, so an Established service would re-arm at
    // `now` and repump every tick.
    let ttl_secs = spec.records().ttl_secs();
    if ttl_secs < crate::constants::MIN_SERVICE_TTL_SECS {
      return Err(RegisterServiceError::TtlTooSmall(ttl_secs));
    }
    // `service_type` must not be the DNS root: RFC 6763 §4.1.2 defines
    // `<Service>` as exactly two labels, so the root is structurally invalid
    // regardless of what the parent-label-sequence check below says — and
    // that check's `is_parent_of` correctly treats the root as the immediate
    // parent of any single-label `instance`, so without this guard a root
    // `service_type` would pass it. Checked before that call, same reason the
    // TTL is checked before either: reject before the name is reserved.
    if spec.records().service_type().is_empty() {
      return Err(RegisterServiceError::ServiceTypeIsRoot(
        spec.records().instance().clone(),
      ));
    }
    // `service_type` must be the parent label sequence of `instance`
    // (`ServiceRecords::new` documents this but is an infallible constructor
    // and cannot enforce it itself) — rejected before the name is reserved,
    // same as the TTL above. Otherwise the PTR this service answers for
    // points into a service type its own SRV owner does not belong to: a
    // registration that is internally inconsistent on the wire.
    if !spec
      .records()
      .service_type()
      .is_parent_of(spec.records().instance())
    {
      return Err(RegisterServiceError::ServiceTypeNotParent(
        ServiceTypeNotParentDetail::new(
          spec.records().service_type().clone(),
          spec.records().instance().clone(),
        ),
      ));
    }
    // Reject duplicate names. DNS-name equality, not string equality: a name
    // differing only in the optional trailing root dot is the SAME owner on the
    // wire, so a string test lets both spellings register and probe for one
    // name. See [`Name::same_owner`].
    for (_, route) in self.services.iter() {
      if route.name().same_owner(spec.records().instance()) {
        return Err(RegisterServiceError::NameAlreadyRegistered(
          spec.records().instance().clone(),
        ));
      }
    }
    // Also reject if a rename-COLLISION teardown's detached goodbye is still
    // HOLDING this name: the dead service's stale records must be retracted before
    // the name is reused, or a quick re-register would cancel the only TTL=0
    // goodbye and leave peers with stale PTR/SRV/TXT until TTL. A
    // SURVIVING rename's detached old name does NOT hold — it is reclaimed/
    // cancelled by the retain below.
    #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
    for (_, item) in self.withdrawals.iter() {
      if item.route.is_none()
        && item.holds_name
        && item.records.instance().same_owner(spec.records().instance())
      {
        return Err(RegisterServiceError::NameAlreadyRegistered(
          spec.records().instance().clone(),
        ));
      }
    }
    // Reject a host name shared with a live route that publishes DIFFERENT
    // addresses. See `host_addresses_disagree` for what this buys and why it is
    // checked here rather than left to the conflict path.
    if self.host_addresses_disagree(
      spec.records().host(),
      spec.records().a_addrs_slice(),
      spec.records().aaaa_addrs_slice(),
      None,
    ) {
      return Err(RegisterServiceError::HostAddressesDiffer(
        spec.records().host().clone(),
      ));
    }
    let new_h = self.next_service_handle;
    self.next_service_handle = self.next_service_handle.saturating_add(1);
    let handle = ServiceHandle::from_raw(new_h);

    self
      .services
      .insert(ServiceRoute {
        service_type: spec.records().service_type().clone(),
        name: spec.records().instance().clone(),
        host: spec.records().host().clone(),
        handle,
        a_addrs: spec.records().a_addrs_slice().to_vec(),
        aaaa_addrs: spec.records().aaaa_addrs_slice().to_vec(),
        aaaa_scopes: spec.records().aaaa_scopes_slice().to_vec(),
        subtypes: spec.records().subtype_names().to_vec(),
        // EMPTY at registration: a service has CONFIRMED-ADVERTISED nothing
        // until its first announce is delivered (then mirrored in here via
        // `note_service_announced`).
        #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
        advertised_a: std::vec::Vec::new(),
        #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
        advertised_aaaa: std::vec::Vec::new(),
        withdrawing: false,
      })
      .map_err(|_| RegisterServiceError::StorageFull(StorageFullError))?;

    // NOTE: a reclaimable detached old-name goodbye for this instance name is NOT
    // cancelled here. Registration only RESERVES the name; the reclaiming service
    // probes (~750 ms, RFC 6762 §8.1) before it advertises. The reclaim-cancel now
    // fires on the CERTAIN live event — `note_service_announced`, when this service
    // confirms it is announcing the name — not at register time, because the
    // reactor only async-commits a registration across its reply boundary and
    // cancelling here could lose the goodbye when the caller drops the registration
    // before owning the service. Until then the old goodbye keeps
    // draining; if this registration is orphaned or renames away before announcing,
    // the goodbye completes normally and retracts the old records. A name-HOLDING
    // collision goodbye still blocks reuse via the duplicate-name + holds_name scans
    // above. Auto-rename onto a reclaimable detached name is still
    // reclaimed synchronously in `handle_service_renamed`.

    let mut seed = [0u8; 32];
    self.rng.fill_bytes(&mut seed);
    // honor EndpointConfig::probe_unique_names — when disabled the
    // service skips the §8.1 probe sequence and announces immediately.
    // EndpointConfig::announce(false) additionally switches the service to a
    // non-announcing responder (established, no announcements at all).
    let svc = {
      #[allow(unused_mut)]
      let mut s = Service::try_new(
        handle,
        spec.into_records(),
        now,
        seed,
        self.config.probe_unique_names(),
        self.config.announce(),
      );
      #[cfg(feature = "stats")]
      s.set_stats(self.stats.clone());
      s
    };
    debug!(
      target: "mdns_proto::endpoint",
      handle = handle.raw(),
      "try_register_service: service registered"
    );
    #[cfg(feature = "stats")]
    {
      self.stats.services_registered(1);
      self.stats.incr_services_active(1);
    }
    Ok((handle, svc))
  }

  /// **Force-remove** the registered service for `handle` IMMEDIATELY, with NO
  /// RFC 6762 §10.1 goodbye.
  ///
  /// This drops the route and decrements `services_active` at once: it does NOT
  /// send a TTL=0 goodbye, so peers keep the service in their caches until the
  /// records' own TTLs expire, AND the instance name is released for re-use the
  /// moment this returns. It is intended ONLY for forced / non-graceful removal
  /// (e.g. an abort path, or after a confirmed goodbye has already drained).
  ///
  /// # Prefer the graceful withdrawal lifecycle
  ///
  /// For normal teardown use the withdrawal lifecycle, which announces a §10.1
  /// goodbye AND holds the name until that goodbye is confirmed-sent — closing
  /// the same-name-reuse race this primitive deliberately does not guard:
  ///
  /// 1. [`Service::withdrawal_snapshot`](crate::service::Service::withdrawal_snapshot)
  ///    — capture the goodbye-owned records.
  /// 2. [`Self::begin_withdrawal`] — mark the route withdrawing and queue the
  ///    goodbye schedule (the route, and thus the name guard, is KEPT).
  /// 3. Pump [`Self::poll_withdrawal_transmit`] / confirm each round via
  ///    [`Self::note_withdrawal_result`] until the budget is spent.
  /// 4. [`Self::drain_completed_withdrawals`] — frees the route (releasing the
  ///    name and decrementing `services_active`) only AFTER the goodbye is
  ///    confirmed-sent, and returns the handle for driver-side GC.
  ///
  /// The drivers retire services via that lifecycle, NOT this method.
  ///
  /// # It still RELINQUISHES, so it still has to say what it asserted
  ///
  /// Sending no goodbye does not make this path quiet. A service force-removed
  /// straight after a confirmed positive send has records on the wire and none
  /// resident anywhere, and the caller may register a replacement at the same
  /// owner names in the very next statement. A delayed echo of the removed
  /// service's own records then reaches normal conflict adjudication and retires
  /// the replacement.
  ///
  /// This call therefore RETAINS what it gives up. The records the removed
  /// service actually put on a wire are kept for
  /// [`EndpointConfig::relinquished_retention`](crate::EndpointConfig::relinquished_retention)
  /// and screened out of conflict adjudication — on the family that carried
  /// them, which is the only family an echo of them can arrive on — so a late
  /// echo is read as this endpoint's own past rather than as a peer contesting
  /// the replacement's name. Force-removal sends no goodbye, which does not make
  /// it quiet — the retention is owed here exactly as at the other two
  /// relinquishing paths.
  ///
  /// So `asserted` is the removed service's
  /// [`Service::withdrawal_snapshot`](crate::service::Service::withdrawal_snapshot)
  /// — the same value [`Self::begin_withdrawal`] takes, reporting what a
  /// confirmed send actually emitted. Pass `Some(..)` whenever the `Service`
  /// still exists; only its exposure is retained, so a never-announced service's
  /// snapshot retains nothing at all.
  ///
  /// `None` is for a caller that genuinely has no `Service` to ask: the state
  /// machine was already dropped, or its goodbye already drained (in which case
  /// [`Self::drain_completed_withdrawals`] retained the set when it completed).
  /// Passing `None` while holding a live, announced `Service` re-opens the class
  /// above.
  ///
  /// A still-draining ROUTE-ATTACHED withdrawal item is retained here too,
  /// whatever `asserted` says: dropping the item removes the last resident
  /// description of that set, which is the same relinquishment
  /// `drain_completed_withdrawals` would have retained had the goodbye been
  /// allowed to finish.
  ///
  /// # Behaviour
  ///
  /// Returns `true` if a route was found and removed, `false` if the handle
  /// was already unknown (idempotent). When this returns, re-registering the
  /// same instance name via [`Self::try_register_service`] succeeds immediately
  /// (no [`RegisterServiceError::NameAlreadyRegistered`] guard remains), and
  /// inbound packets no longer match the removed route.
  pub fn unregister_service(
    &mut self,
    handle: ServiceHandle,
    asserted: Option<crate::service::WithdrawalSnapshot>,
    now: I,
  ) -> bool {
    let key = self
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle)
      .map(|(k, _)| k);
    if let Some(k) = key {
      // BEFORE the route goes: what this service put on the wire outlives it,
      // and once the name is released there is nothing left to say it was ours.
      if let Some(snapshot) = asserted {
        // The MULTICAST half: the screen asks what could still be echoing, and
        // a §6.7 legacy reply left no copy on the group to echo.
        self.retain_relinquished(snapshot.records, snapshot.multicast, now);
      }
      let removed = self.services.try_remove(k).is_some();
      // Force-remove is a NO-goodbye primitive: also drop any ROUTE-attached
      // withdrawal item for this handle. Otherwise removing the route (and thus
      // the name guard) would let the same name be re-registered while a stale
      // route-attached item still owes a TTL=0 goodbye — a late goodbye would
      // then flush the same-name replacement, contradicting "no goodbye". Detached items (renamed-away OLD names) are independent of this
      // handle's route and are left to drain / be cancelled on reclaim.
      //
      // Each dropped item's record set is RELINQUISHED on the way out, exactly
      // as `drain_completed_withdrawals` would have relinquished it: the item
      // was the last resident copy of a set this endpoint transmitted, and this
      // is the moment it stops being consultable.
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      {
        let mut dropped = std::vec::Vec::new();
        self.withdrawals.retain(|(_, item)| {
          let keep = item.route != Some(handle);
          if !keep {
            dropped.push((item.records.clone(), item.multicast.clone()));
          }
          keep
        });
        for (records, multicast) in dropped {
          self.retain_relinquished(records, multicast, now);
        }
      }
      #[cfg(feature = "stats")]
      if removed {
        self.stats.decr_services_active(1);
      }
      removed
    } else {
      false
    }
  }

  /// Update the routing table after a service auto-renamed itself due to a
  /// probe conflict.
  ///
  /// # Contract
  ///
  /// Callers **MUST** invoke this method after observing
  /// [`ServiceUpdate::Renamed`](crate::event::ServiceUpdate::Renamed) from
  /// [`Service::poll`](crate::service::Service::poll), and **BEFORE** routing
  /// any further datagrams via [`Endpoint::handle`].  Failing to do so means
  /// questions addressed to the new instance name will not be routed to the
  /// service.
  ///
  /// # Errors
  ///
  /// Returns [`HandleServiceRenamedError::ServiceNotFound`] if `handle` does
  /// not correspond to any registered service.
  ///
  /// Returns [`HandleServiceRenamedError::NameAlreadyRegistered`] if
  /// `new_name` is already used by a *different* registered service; the
  /// caller must retry with a different suffix.
  pub fn handle_service_renamed(
    &mut self,
    handle: ServiceHandle,
    new_name: Name,
  ) -> Result<(), HandleServiceRenamedError> {
    // Locate the key for the given handle.
    let mut existing_key: Option<usize> = None;
    for (key, route) in self.services.iter() {
      if route.handle() == handle {
        existing_key = Some(key);
        break;
      }
    }
    let key = match existing_key {
      Some(k) => k,
      None => return Err(HandleServiceRenamedError::ServiceNotFound(handle)),
    };

    // Reject if new_name collides with another route.
    for (other_key, route) in self.services.iter() {
      if other_key != key && route.name().same_owner(&new_name) {
        return Err(HandleServiceRenamedError::NameAlreadyRegistered(new_name));
      }
    }
    // Also reject if new_name is HELD by a rename-COLLISION detached goodbye
    // (holds_name): that dead service's records must be retracted before the name is
    // reused, and a held item is intentionally NOT cancelled on
    // advertise — so letting a rename claim it would leave the held goodbye to later
    // flush the renamed service's records. Treat it like a live-route
    // collision (the driver retires the renamer, whose caller re-registers). This
    // mirrors the `try_register_service` holds_name guard.
    #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
    for (_, item) in self.withdrawals.iter() {
      if item.route.is_none()
        && item.holds_name
        && item.records.instance().same_owner(&new_name)
      {
        return Err(HandleServiceRenamedError::NameAlreadyRegistered(new_name));
      }
    }
    // A rename onto a RECLAIMABLE (not held) renamed-away old name reclaims it — but
    // the reclaim-cancel of that name's in-flight DETACHED goodbye is NOT done here.
    // Like a registration, a rename only RESERVES the name; the renamed
    // service still probes (~750 ms, RFC 6762 §8.1) before it advertises, and may
    // conflict/rename away again before announcing. Cancelling now would lose the old
    // records' retraction if it never announces (the same premature-cancel class as
    //). The cancel instead fires on the certain live event —
    // `note_service_announced` gated on `Service::has_fully_announced`, when the
    // renamed service has announced this name on every obligated link. The rename is
    // still NOT rejected for a reclaimable name: a detached item holds no route, so
    // the duplicate-name scan above does not see it, and reuse proceeds.

    // The host address-set invariant's second enforcement point. It cannot fail
    // today — a rename replaces the INSTANCE name and touches neither the host
    // name nor the addresses, so a route that satisfied the guard at
    // registration still satisfies it here — and it is kept because the day a
    // rename is allowed to carry new records is the day the terminal
    // `HostConflict`-on-every-sibling-echo path reopens, silently, with no other
    // site to catch it. `exclude` is this route's own key: it is already in the
    // table, and a route never disagrees with itself.
    let renaming_host = self.services.get(key).map(|route| {
      (
        route.host().clone(),
        route.a_addrs().to_vec(),
        route.aaaa_addrs().to_vec(),
      )
    });
    if let Some((host, a_addrs, aaaa_addrs)) = renaming_host
      && self.host_addresses_disagree(&host, &a_addrs, &aaaa_addrs, Some(key))
    {
      return Err(HandleServiceRenamedError::HostAddressesDiffer(host));
    }

    // Apply the rename.
    if let Some(route) = self.services.get_mut(key) {
      warn!(
        target: "mdns_proto::endpoint",
        handle = handle.raw(),
        old_name = route.name.as_str(),
        new_name = new_name.as_str(),
        "handle_service_renamed: service renamed due to conflict"
      );
      // NOTE: conflicts/renames counters are NOT bumped here.
      // They are bumped in Service::handle_timeout (service/mod.rs) at the
      // single canonical site — the Service state machine is the authority.
      // Bumping here too would double-count on the shared Arc.
      route.name = new_name;
    }
    Ok(())
  }
}

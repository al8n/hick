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
  /// Does any LIVE route publish `host` with an A/AAAA set other than the one
  /// given? `exclude` skips one route key, for a check that re-examines a route
  /// already in the table.
  ///
  /// # The invariant, and what it protects
  ///
  /// Two services may share a host name — that is how several services on one
  /// machine advertise one set of addresses, and it is supported. What must not
  /// differ is the ADDRESSES: RFC 6762 §9's conflict test compares a record
  /// against the RECEIVING service's own records, so a sibling's A/AAAA at a
  /// shared host name with rdata this service does not hold is, by that test, a
  /// genuine conflict — and `Endpoint` has no auto-rename for a host name, so it
  /// surfaces as a TERMINAL `ServiceUpdate::HostConflict`, raised by a sibling
  /// on the same machine rather than by any peer.
  ///
  /// That path was previously unreachable only because self-detection suppressed
  /// every effect of an echoed announcement. It is not suppressed any more: a
  /// content match with no ordering evidence now adjudicates (see
  /// [`Provenance::OwnEchoLikely`](crate::Provenance::OwnEchoLikely)), which is
  /// what makes this guard the FOURTH invariant that cell's safety rests on.
  ///
  /// # Set equality, and only of what is configured
  ///
  /// Compared as SETS in both directions, because the conflict classifier asks
  /// `contains`, and mutual containment is exactly what makes it answer
  /// "identical" for every address either side can put on the wire. Order and
  /// repetition are therefore irrelevant, and a re-registration that lists the
  /// same addresses differently is not rejected.
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
  fn host_addresses_disagree(
    &self,
    host: &Name,
    a_addrs: &[Ipv4Addr],
    aaaa_addrs: &[Ipv6Addr],
    exclude: Option<usize>,
  ) -> bool {
    fn same_set<T: PartialEq>(a: &[T], b: &[T]) -> bool {
      a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
    }
    self.services.iter().any(|(key, route)| {
      if Some(key) == exclude {
        return false;
      }
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      if route.withdrawing {
        return false;
      }
      // Case-insensitive, because that is how the routing path matches a record
      // against a host name — an equality test here would let one case spelling
      // register past the guard and conflict on the wire anyway.
      if !route.host().as_str().eq_ignore_ascii_case(host.as_str()) {
        return false;
      }
      !same_set(route.a_addrs(), a_addrs) || !same_set(route.aaaa_addrs(), aaaa_addrs)
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
  /// Returns [`RegisterServiceError::HostAddressesDiffer`] if a live route
  /// already publishes this host name with a different A/AAAA set. **Two live
  /// services may share a host name, but only by publishing the same addresses
  /// under it.** RFC 6762 §9 classifies a conflict against the RECEIVING
  /// service's own records, so a sibling advertising that host with a different
  /// set is a genuine conflict by that test — and a host name has no auto-rename,
  /// so it surfaces as a terminal update rather than resolving itself. The two
  /// address sets are compared as SETS, so order and repeats do not matter and an
  /// IPv6 scope id does; the host name is matched case-insensitively, the way the
  /// routing path matches a record against it. A route already withdrawing under
  /// §10.1 no longer holds its host name for this test.
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
    // Reject duplicate names.
    for (_, route) in self.services.iter() {
      if route.name().as_str() == spec.records().instance().as_str() {
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
        && item.records.instance().as_str() == spec.records().instance().as_str()
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
    let svc = {
      #[allow(unused_mut)]
      let mut s = Service::try_new(
        handle,
        spec.into_records(),
        now,
        seed,
        self.config.probe_unique_names(),
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
  /// # Behaviour
  ///
  /// Returns `true` if a route was found and removed, `false` if the handle
  /// was already unknown (idempotent). When this returns, re-registering the
  /// same instance name via [`Self::try_register_service`] succeeds immediately
  /// (no [`RegisterServiceError::NameAlreadyRegistered`] guard remains), and
  /// inbound packets no longer match the removed route.
  pub fn unregister_service(&mut self, handle: ServiceHandle) -> bool {
    let key = self
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle)
      .map(|(k, _)| k);
    if let Some(k) = key {
      let removed = self.services.try_remove(k).is_some();
      // Force-remove is a NO-goodbye primitive: also drop any ROUTE-attached
      // withdrawal item for this handle. Otherwise removing the route (and thus
      // the name guard) would let the same name be re-registered while a stale
      // route-attached item still owes a TTL=0 goodbye — a late goodbye would
      // then flush the same-name replacement, contradicting "no goodbye". Detached items (renamed-away OLD names) are independent of this
      // handle's route and are left to drain / be cancelled on reclaim.
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      self
        .withdrawals
        .retain(|(_, item)| item.route != Some(handle));
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
      if other_key != key && route.name().as_str() == new_name.as_str() {
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
        && item.records.instance().as_str() == new_name.as_str()
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

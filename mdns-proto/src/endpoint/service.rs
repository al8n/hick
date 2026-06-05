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
  /// Register a new service. Returns the handle and a `Service` state-machine.
  pub fn try_register_service<TQ, EvS>(
    &mut self,
    spec: ServiceSpec,
    now: I,
  ) -> Result<(ServiceHandle, Service<I, TQ, EvS>), RegisterServiceError>
  where
    TQ: Pool<Transmit>,
    EvS: Pool<crate::event::ServiceUpdate>,
  {
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
    #[cfg(any(feature = "alloc", feature = "std"))]
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
        // `note_service_advertised`).
        #[cfg(any(feature = "alloc", feature = "std"))]
        advertised_a: std::vec::Vec::new(),
        #[cfg(any(feature = "alloc", feature = "std"))]
        advertised_aaaa: std::vec::Vec::new(),
        withdrawing: false,
      })
      .map_err(|_| RegisterServiceError::StorageFull(StorageFullError))?;

    // NOTE: a reclaimable detached old-name goodbye for this instance name is NOT
    // cancelled here. Registration only RESERVES the name; the reclaiming service
    // probes (~750 ms, RFC 6762 §8.1) before it advertises. The reclaim-cancel now
    // fires on the CERTAIN live event — `note_service_advertised`, when this service
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
      #[cfg(any(feature = "alloc", feature = "std"))]
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
    #[cfg(any(feature = "alloc", feature = "std"))]
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
    // `note_service_advertised` gated on `advertised_instance`, when the renamed
    // service confirms advertising this name. The rename is still NOT rejected for a
    // reclaimable name: a detached item holds no route, so the
    // duplicate-name scan above does not see it, and reuse proceeds.

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

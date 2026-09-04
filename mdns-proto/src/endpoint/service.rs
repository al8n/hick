//! Service registration, unregistration, and conflict-driven rename.

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

  /// Register a new service. Returns its [`ServiceHandle`].
  ///
  /// The [`Service`] state machine is owned by the endpoint and driven via the
  /// `*_service*` accessors ([`Self::poll_service`],
  /// [`Self::poll_service_timeout`], [`Self::handle_service_timeout`],
  /// [`Self::poll_service_transmit`], [`Self::note_service_transmit_outcome`],
  /// [`Self::unregister_service`]), exactly as a query is driven through the
  /// `*_query*` ones. [`Self::service`] hands out a read-only view.
  ///
  /// # RFC 6762 §8.1's flood floor applies to this registration's first probe
  ///
  /// §8.1 obliges the HOST to "wait at least five seconds before each successive
  /// additional probe attempt" once fifteen conflicts have occurred inside ten
  /// seconds, and a record set registered while that limit is in force is making
  /// one of those attempts. So the first probe deadline is floored here, not
  /// merely on conflict-driven restarts — otherwise unregistering and
  /// re-registering, which is the ordinary response to a terminal conflict,
  /// would hand the replacement §8.1's ordinary 0-250 ms delay and walk straight
  /// past the limit.
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
  pub fn try_register_service(
    &mut self,
    spec: ServiceSpec,
    now: I,
  ) -> Result<ServiceHandle, RegisterServiceError> {
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

    let mut seed = [0u8; 32];
    self.rng.fill_bytes(&mut seed);
    // honor EndpointConfig::probe_unique_names — when disabled the
    // service skips the §8.1 probe sequence and announces immediately.
    // EndpointConfig::re_announce(false) switches the service to a
    // non-announcing responder: the §8.3 startup burst still runs, but the
    // periodic re-announce is suppressed, so nothing unsolicited is sent
    // afterwards.
    //
    // `self.flood` is what makes this registration's FIRST probe subject to
    // §8.1's floor. "Each successive additional probe attempt" is the host's
    // obligation, and a record set registered into an active flood is making
    // one — which is precisely the bypass a per-record-set counter could not
    // close, since every fresh `Service` started with an empty history.
    // The routing metadata is read off the spec BEFORE the records move into the
    // state machine, so neither is cloned for the other's sake.
    let service_type = spec.records().service_type().clone();
    let name = spec.records().instance().clone();
    let host = spec.records().host().clone();
    let a_addrs = spec.records().a_addrs_slice().to_vec();
    let aaaa_addrs = spec.records().aaaa_addrs_slice().to_vec();
    let aaaa_scopes = spec.records().aaaa_scopes_slice().to_vec();
    let subtypes = spec.records().subtype_names().to_vec();

    let proto = {
      #[allow(unused_mut)]
      let mut s = Service::try_new(
        handle,
        spec.into_records(),
        now,
        seed,
        self.config.probe_unique_names(),
        self.config.re_announce(),
        &self.flood,
      );
      #[cfg(feature = "stats")]
      s.set_stats(self.stats.clone());
      s
    };

    self
      .services
      .insert(ServiceRoute {
        proto,
        service_type,
        name,
        host,
        handle,
        a_addrs,
        aaaa_addrs,
        aaaa_scopes,
        subtypes,
        // EMPTY at registration: a service has CONFIRMED-ADVERTISED nothing
        // until its first announce is delivered (then mirrored in here by
        // `note_service_transmit_outcome`).
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
    // fires on the CERTAIN live event — `note_service_transmit_outcome`, when this service
    // confirms it is announcing the name — not at register time, because the
    // reactor only async-commits a registration across its reply boundary and
    // cancelling here could lose the goodbye when the caller drops the registration
    // before owning the service. Until then the old goodbye keeps
    // draining; if this registration is orphaned or renames away before announcing,
    // the goodbye completes normally and retracts the old records. A name-HOLDING
    // goodbye — one left by a rename that could not move off its own name — still
    // blocks reuse via the duplicate-name + holds_name scans above, and a rename
    // sees the same two lists through `collect_names_in_use`.

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
    Ok(handle)
  }


  /// Find the pool key for a registered service handle. `None` once the route
  /// has been freed (a completed withdrawal, or a force-removal).
  pub(crate) fn service_key(&self, handle: ServiceHandle) -> Option<usize> {
    self
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle)
      .map(|(k, _)| k)
  }

  /// A READ-ONLY view of a registered service's state machine.
  ///
  /// Everything a caller needs to observe — [`Service::name`],
  /// [`Service::state`], [`Service::has_fully_announced`],
  /// [`Service::advertised_a_addrs`], [`Service::advertised_aaaa_addrs`] — and
  /// nothing that mutates. Every state-mutating entry point is a `*_service*`
  /// method on `Endpoint`, because each of them has to be paired with something
  /// the endpoint owns: the flood history, the route table's names, or the
  /// withdrawal lifecycle.
  ///
  /// `None` for a handle whose route has been freed.
  #[inline]
  pub fn service(&self, handle: ServiceHandle) -> Option<&Service<I, TQ, EvS>> {
    self
      .service_key(handle)
      .and_then(|key| self.services.get(key))
      .map(|route| &route.proto)
  }

  /// Drain the next app-level update for a registered service
  /// ([`ServiceUpdate::Renamed`], [`ServiceUpdate::Conflict`],
  /// [`ServiceUpdate::HostConflict`], …).
  ///
  /// A `Renamed` here is a NOTIFICATION, never an instruction. The route table
  /// already carries the new name — it was mirrored in the same borrow that
  /// chose it, from a set of names the route table itself supplied — so there is
  /// nothing for a caller to apply and no way for a caller to disagree.
  ///
  /// Returns `None` when the service has no pending update, or the handle no
  /// longer names a registered service.
  ///
  /// # Still open while the service is WITHDRAWING
  ///
  /// Every other `*_service*` entry point goes inert the moment
  /// [`Self::unregister_service`] begins a §10.1 goodbye; this one does not.
  /// It drains an update QUEUE and can put nothing on a link — a `Conflict` or
  /// `HostConflict` raised just before the teardown is news the caller still has
  /// to hear, and dropping it on the floor would be the only way it could be
  /// lost.
  pub fn poll_service(&mut self, handle: ServiceHandle) -> Option<ServiceUpdate> {
    let key = self.service_key(handle)?;
    self.services.get_mut(key)?.proto.poll()
  }

  /// Next deadline at which [`Self::handle_service_timeout`] must be called for
  /// this service. `None` if it is idle, WITHDRAWING, or no longer registered.
  ///
  /// A service whose RFC 6762 §8 startup sequence is PARKED — nothing armed
  /// because this clock cannot represent a wait the protocol mandates — is
  /// reported as due IMMEDIATELY. It is not idle: it owes a probe it may not
  /// schedule, and [`Self::handle_service_timeout`] is where that is reported as
  /// [`HandleTimeoutError::Overflow`]. Reporting no deadline would let the caller
  /// sleep on a service that will never move again.
  ///
  /// A withdrawing service is reported as having no deadline because it has
  /// nothing left to do: its lifecycle is finished, and the RFC 6762 §10.1
  /// goodbye that outlives it is the endpoint's own withdrawal item, scheduled
  /// through [`Self::poll_withdrawal_transmit`] and reported by
  /// [`Self::poll_timeout`]. Reporting the retired state machine's stale
  /// deadline here is what kept a caller ticking it. See
  /// [`Self::unregister_service`].
  pub fn poll_service_timeout(&self, handle: ServiceHandle) -> Option<I> {
    let key = self.service_key(handle)?;
    let route = self.services.get(key)?;
    if route.withdrawing {
      return None;
    }
    route.proto.poll_timeout()
  }

  /// Drive timer-based transitions on a registered service — RFC 6762 §8.1's
  /// probe sequence, §8.3's announcements, the periodic re-announce, and the one
  /// site where a conflicted name is given up.
  ///
  /// # A rename is COMPLETE when this returns
  ///
  /// A §8.1 defeat renames the service here, and it picks a name this endpoint
  /// does not already hold: the route table's instance names are collected on
  /// exactly the ticks a rename is imminent and handed to the state machine, so
  /// the name it settles on is one the route table accepts, and the route's own
  /// `name` is updated in the same borrow. There is no second call to make, no
  /// error to handle, and no window in which the service and the router disagree
  /// about which name is being probed.
  ///
  /// That window used to be a caller's to close, and closing it took a hundred
  /// lines in every driver: offer the new name, handle a refusal by retiring the
  /// renamer and synthesizing a conflict, take the old name's goodbye handoff,
  /// and enqueue it as a name-HOLDING item so the dead service's records were
  /// retracted before the name could be reused. None of that is reachable now —
  /// the collision it reconciled cannot occur.
  ///
  /// The old name's §10.1 goodbye is enqueued here too, as an independent
  /// detached withdrawal item with its own per-family debt and schedule.
  ///
  /// # Errors
  ///
  /// [`HandleTimeoutError::Overflow`] when a deadline could not be computed, or
  /// when RFC 6762 §8.1's flood limit is in force and this clock cannot
  /// represent the five-second wait it mandates — in which case the service is
  /// PARKED with nothing armed, which is what failing closed looks like, and
  /// this reports it rather than leaving it indistinguishable from an idle tick.
  /// [`Self::poll_service_timeout`] reports a parked service as due immediately,
  /// so the error repeats until the wait can be armed rather than arriving once
  /// and then never again.
  ///
  /// `Ok(())` for an unknown handle, and for one already WITHDRAWING: there is
  /// nothing to drive. A retired state machine driven on has nothing legitimate
  /// left to do and one illegitimate thing it can still do — a §8.1 defeat would
  /// rename the route mid-teardown, moving the very name whose goodbye is in
  /// flight. See [`Self::unregister_service`].
  pub fn handle_service_timeout(
    &mut self,
    handle: ServiceHandle,
    now: I,
  ) -> Result<(), HandleTimeoutError> {
    let Some(key) = self.service_key(handle) else {
      return Ok(());
    };
    if self.services.get(key).is_some_and(|route| route.withdrawing) {
      return Ok(());
    }
    // The names a rename must avoid — collected ONLY on a tick where one is
    // actually imminent, since it costs a clone per live route, and collected
    // BEFORE the route holding this service is mutably borrowed.
    self.rename_scratch.clear();
    if self
      .services
      .get(key)
      .is_some_and(|route| route.proto.rename_imminent())
    {
      self.collect_names_in_use(key);
    }

    let outcome = {
      let Self {
        services,
        flood,
        rename_scratch,
        ..
      } = self;
      let Some(route) = services.get_mut(key) else {
        return Ok(());
      };
      let outcome = route
        .proto
        .handle_timeout(now, flood, &NamesInUse::new(rename_scratch));
      // THE MIRROR, in the same borrow that chose the name. Routing and the
      // state machine cannot disagree about this service's instance name for
      // even one statement, let alone for the span of a driver's reply.
      if !route.name.same_owner(route.proto.name()) {
        warn!(
          target: "mdns_proto::endpoint",
          handle = handle.raw(),
          old_name = route.name.as_str(),
          new_name = route.proto.name().as_str(),
          "handle_service_timeout: service renamed due to conflict"
        );
        route.name = route.proto.name().clone();
      }
      outcome
    };

    // The renamed-away name's TTL=0 goodbye, modelled as its own detached item.
    self.drain_rename_goodbye(key, now);
    outcome
  }

  /// Fill [`Self::rename_scratch`] with every instance name this endpoint holds
  /// except the one at route `except`.
  ///
  /// TWO kinds of holder, and both must be here or a rename can take a name that
  /// is not free:
  ///
  /// * every other live route's instance name;
  /// * every rename-failure teardown's detached goodbye that still HOLDS its
  ///   name. The dead service's stale records must be retracted before that name
  ///   is claimed again, which is the same guard [`Self::try_register_service`]
  ///   applies to the same items.
  ///
  /// A route never collides with itself, which is what `except` is for.
  fn collect_names_in_use(&mut self, except: usize) {
    let Self {
      services,
      rename_scratch,
      ..
    } = self;
    for (other, route) in services.iter() {
      if other != except {
        rename_scratch.push(route.name().clone());
      }
    }
    let Self {
      withdrawals,
      rename_scratch,
      ..
    } = self;
    for (_, item) in withdrawals.iter() {
      if item.route.is_none() && item.holds_name {
        rename_scratch.push(item.records.instance().clone());
      }
    }
  }

  /// Test-only: move a registered service onto `new_name`, refusing exactly what
  /// a real rename refuses. Returns whether the name was free.
  ///
  /// It runs the SAME screen [`Self::handle_service_timeout`] hands to the state
  /// machine — [`Self::collect_names_in_use`] — so a fixture that asserts which
  /// names a rename may take is asserting the shipped rule rather than a
  /// restatement of it. What it skips is only the conflict that would normally
  /// cause the rename.
  #[cfg(test)]
  #[allow(dead_code)]
  pub(crate) fn rename_service_for_test(&mut self, handle: ServiceHandle, new_name: Name) -> bool {
    let Some(key) = self.service_key(handle) else {
      return false;
    };
    self.rename_scratch.clear();
    self.collect_names_in_use(key);
    if NamesInUse::new(&self.rename_scratch).holds(&new_name) {
      return false;
    }
    let Some(route) = self.services.get_mut(key) else {
      return false;
    };
    route.proto.rename_for_test(new_name.clone());
    route.name = new_name;
    true
  }

  /// Take whatever RFC 6762 §10.1 goodbye a rename left behind for the OLD name
  /// and enqueue it as a detached withdrawal item.
  ///
  /// It HOLDS the name exactly when the service did not actually move off it —
  /// the suffixed candidate was not a valid DNS name, so the service went
  /// terminal under the name it already had. Its records must then be retracted
  /// before that name is reused: the route-attached teardown that follows owns
  /// no instance records (the handoff took them), so it completes at once and
  /// frees the name, and a quick re-registration would otherwise cancel the only
  /// real goodbye and leave peers with stale PTR/SRV/TXT until TTL.
  ///
  /// A SURVIVING rename's old name is reclaimable instead: the service is alive
  /// under a new name, and a fresh registration of the vacated one supersedes
  /// the goodbye rather than being blocked by it.
  fn drain_rename_goodbye(&mut self, key: usize, now: I) {
    let Some(handoff) = self
      .services
      .get_mut(key)
      .and_then(|route| route.proto.take_rename_goodbye_handoff())
    else {
      return;
    };
    let holds_name = self
      .services
      .get(key)
      .is_some_and(|route| route.name().same_owner(handoff.records.instance()));
    self.enqueue_rename_withdrawal(handoff, now, holds_name);
  }

  /// Produce the next outgoing datagram for a registered service, if one is due.
  /// Writes into `buf` and returns the [`Transmit`] descriptor.
  ///
  /// # The confirm-before-anything contract
  ///
  /// > Once this returns a datagram, NO other state-mutating entry point for
  /// > this service — [`Self::handle_service_timeout`], [`Self::handle`],
  /// > [`Self::unregister_service`] — may be invoked until that datagram's
  /// > [`Self::note_service_transmit_outcome`].
  ///
  /// The core cannot type-check the ordering, so it is enforced by cheap
  /// backstops rather than assumed: a `debug_assert!` at each entry point fails a
  /// non-compliant driver loudly in its own test suite, and in release the single
  /// commit-token slot keeps the damage defined.
  ///
  /// # This is the WIRE COMMIT BOUNDARY
  ///
  /// Probes leave this host only through this method, so RFC 6762 §8.1's
  /// five-second floor is re-read HERE and not only where a probe was enqueued.
  /// The fifteenth conflict of a burst can land between the two — it is counted
  /// endpoint-wide, so it need not even concern this service — and a probe
  /// queued before that latch engaged has never been tested against it. There is
  /// no point after this one, which is why the check lives here — see
  /// `Service::defer_first_probe_under_flood`, which states the rule.
  ///
  /// A service that is WITHDRAWING transmits nothing at all. Its §10.1 goodbye
  /// is the endpoint's own withdrawal item, drained through
  /// [`Self::poll_withdrawal_transmit`]; anything still queued on the service is
  /// a POSITIVE-TTL claim to a name whose goodbye snapshot has already been
  /// taken, so no goodbye could ever retract it. See
  /// [`Self::unregister_service`].
  ///
  /// `Ok(None)` when nothing is due, the service is withdrawing, or the handle
  /// is not registered.
  pub fn poll_service_transmit(
    &mut self,
    handle: ServiceHandle,
    now: I,
    buf: &mut [u8],
  ) -> Result<Option<Transmit>, TransmitError> {
    let Some(key) = self.service_key(handle) else {
      return Ok(None);
    };
    let Self {
      services, flood, ..
    } = self;
    let Some(route) = services.get_mut(key) else {
      return Ok(None);
    };
    if route.withdrawing {
      return Ok(None);
    }
    route.proto.defer_first_probe_under_flood(now, flood);
    route.proto.poll_transmit(now, buf)
  }

  /// Report what each address family's transport did with the datagram most
  /// recently produced by [`Self::poll_service_transmit`] for `handle`.
  ///
  /// ALL lifecycle progression happens here rather than at the poll, so a send
  /// that reached no link advances nothing — neither the goodbye-ownership
  /// latches for an announcement nor the RFC 6762 §8.1 probe sequence. See
  /// [`Self::poll_service_transmit`] for the full contract, including what
  /// [`TransmitConfirm::retire_producer`] obliges the caller to do.
  ///
  /// It also mirrors what the confirm latched into the route: the host addresses
  /// this service has now CONFIRMED-ADVERTISED (which is what a sibling's
  /// withdrawal retention honours), and — once a COMPLETE announcement of this
  /// name has reached every obligated link — the reclaim of any detached
  /// old-name goodbye the announcement supersedes.
  ///
  /// An empty confirm for an unknown handle.
  ///
  /// # It also drains the §9 rename goodbye handoff
  ///
  /// A confirm that resolves a datagram PARKED across a conflict rename installs
  /// a fresh handoff for the old name — its records really are in peer caches —
  /// and it lands after the rename that would otherwise have drained it. Draining
  /// here is what anchors the old name's detached goodbye, and its two-second
  /// anti-pin ceiling, at the confirm rather than at whenever the next service
  /// timeout happens to fall. A confirm that installed nothing drains a `None`,
  /// which is every confirm from a transport that cannot park.
  ///
  /// # The ONE mutating accessor a withdrawal does not close
  ///
  /// [`Self::unregister_service`] makes every other `*_service*` entry point
  /// inert, and this one deliberately stays open: it is the COMPLETION half of a
  /// poll → confirm pair, and the commit token is a single slot. A datagram
  /// handed out before the withdrawal began still owes its outcome, and refusing
  /// it would leave that slot occupied for as long as the route lives while
  /// stranding the route's confirmed-advertised mirror — which is what a
  /// sibling's §10.1 retention screen reads. It advances a lifecycle that is
  /// already retired and enqueues nothing: the transmit queue was emptied when
  /// the withdrawal began and [`Self::poll_service_transmit`] can no longer fill
  /// it.
  ///
  /// A conforming caller never reaches that state — the contract on
  /// [`Self::unregister_service`] forbids retiring a service with a datagram
  /// outstanding — so this is a backstop, not a path.
  pub fn note_service_transmit_outcome(
    &mut self,
    handle: ServiceHandle,
    now: I,
    v4: FamilyAttempt<I>,
    v6: FamilyAttempt<I>,
  ) -> TransmitConfirm {
    let Some(key) = self.service_key(handle) else {
      return TransmitConfirm::NOTHING;
    };
    let (confirm, announced_name) = {
      let Some(route) = self.services.get_mut(key) else {
        return TransmitConfirm::NOTHING;
      };
      let confirm = route.proto.note_transmit_outcome(now, v4, v6);
      // The CONFIRMED-ADVERTISED host addresses, mirrored into the route so
      // sibling retention reads what peers actually hold rather than what was
      // configured. Disjoint fields of one route, so no clone is needed.
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      {
        route.advertised_a.clear();
        route
          .advertised_a
          .extend_from_slice(route.proto.advertised_a_addrs());
        route.advertised_aaaa.clear();
        route
          .advertised_aaaa
          .extend_from_slice(route.proto.advertised_aaaa_addrs());
      }
      // Cloned only when a reclaim is actually owed, which is the rare case: the
      // gate is the ALL-delivered fact, and this hook runs after every confirm.
      let announced_name = route
        .proto
        .has_fully_announced()
        .get()
        .then(|| route.name().clone());
      (confirm, announced_name)
    };
    #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
    if let Some(name) = announced_name {
      self.reclaim_detached_goodbyes(handle, &name);
    }
    #[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
    let _ = announced_name;
    // A confirm can INSTALL a rename handoff (a datagram parked across the
    // rename), and it lands after the rename's own drain, so the old name's
    // goodbye is enqueued here rather than at the next service timeout.
    self.drain_rename_goodbye(key, now);
    confirm
  }

  /// Test-only: RFC 6762 §8.1's conflict history, for the tests that are about
  /// the history itself rather than about what it does to a schedule.
  #[cfg(test)]
  #[allow(dead_code)]
  pub(crate) fn flood_for_test(&self) -> &ConflictFlood<I> {
    &self.flood
  }

  /// Test-only: route one [`ServiceEvent`] to a registered service without
  /// building a datagram for it.
  ///
  /// The shipped path is `RouteEvents::next`, which is where every real event
  /// comes from; this is for fixtures that need one specific event delivered at
  /// one specific instant and have no reason to encode a message to get it. The
  /// flood history is the endpoint's own, so what the event counts, it counts.
  #[cfg(test)]
  #[allow(dead_code)]
  pub(crate) fn dispatch_service_event_for_test(
    &mut self,
    handle: ServiceHandle,
    event: ServiceEvent<'_>,
    now: I,
  ) {
    let Some(key) = self.service_key(handle) else {
      return;
    };
    let Self {
      services, flood, ..
    } = self;
    if let Some(route) = services.get_mut(key) {
      route.proto.handle_event(event, now, flood);
    }
  }

  /// Test-only: what a registered service says a §10.1 goodbye must retract.
  ///
  /// [`Self::unregister_service`] takes this itself; a fixture reads it directly
  /// when the SNAPSHOT is the thing under test rather than the withdrawal.
  #[cfg(test)]
  #[allow(dead_code)]
  pub(crate) fn service_withdrawal_snapshot_for_test(
    &mut self,
    handle: ServiceHandle,
  ) -> crate::service::WithdrawalSnapshot {
    let key = self
      .service_key(handle)
      .expect("service must be registered");
    self
      .services
      .get_mut(key)
      .expect("route must resolve")
      .proto
      .withdrawal_snapshot()
  }

  /// Test-only: confirm from a projected delivery SHAPE rather than a pair of
  /// per-family attempts.
  #[cfg(test)]
  #[allow(dead_code)]
  pub(crate) fn note_service_delivery(
    &mut self,
    handle: ServiceHandle,
    now: I,
    delivery: crate::transmit::TransmitDelivery,
  ) {
    let (v4, v6) = delivery.as_attempts(now);
    let _ = self.note_service_transmit_outcome(handle, now, v4, v6);
  }

  /// Retire a registered service GRACEFULLY: capture what it put on the wire and
  /// begin its RFC 6762 §10.1 TTL=0 goodbye.
  ///
  /// The route is KEPT — so the instance name stays blocked against
  /// re-registration — until the goodbye drains. The caller then pumps
  /// [`Self::poll_withdrawal_transmit`] / [`Self::note_withdrawal_result`] and
  /// learns the route was freed from
  /// [`Self::drain_completed_withdrawals`], which is also what drops the
  /// `Service` itself.
  ///
  /// Two goodbyes can be owed at once and each becomes its own item: a rename
  /// still draining its old name's handoff is enqueued here before the current
  /// name's, so neither can starve the other nor be dropped because their
  /// combined message overflowed a scratch buffer.
  ///
  /// Idempotent, and a no-op for an unknown handle: a driver may retire the same
  /// service more than once (an encode-failure escalation on an already-retiring
  /// service, say) and must not enqueue a duplicate.
  ///
  /// # The service goes INERT here, not when the caller stops calling it
  ///
  /// The route survives the call, so a caller holding its handle can still reach
  /// every `*_service*` accessor. All of them are closed from this point, and
  /// the endpoint closes them rather than trusting a caller to stop:
  ///
  /// * [`Self::poll_service_timeout`] reports no deadline;
  /// * [`Self::handle_service_timeout`] drives nothing — in particular it cannot
  ///   rename the route out from under the goodbye that is already in flight;
  /// * [`Self::poll_service_transmit`] emits nothing, and the queued transmits
  ///   and response deadlines are DISCARDED here rather than left unreachable;
  /// * [`Self::note_service_transmit_outcome`] is the single exception, and its
  ///   own documentation says why.
  ///
  /// The snapshot above names exactly what peers hold, so a positive-TTL
  /// datagram emitted after it — a queued first announcement, a §6.7 legacy
  /// reply, a periodic re-announce — would put records in peer caches that this
  /// goodbye cannot mention and nothing else will ever retract. They would stand
  /// until their own TTL expired. Each bundled driver used to hold a flag of its
  /// own to prevent that; the flag belongs where the state machine now lives.
  ///
  /// # Contract
  ///
  /// Must NOT be called while a datagram from [`Self::poll_service_transmit`] is
  /// still awaiting its [`Self::note_service_transmit_outcome`]: the snapshot
  /// taken here cannot know about records that datagram is about to place in
  /// peer caches, so the goodbye would never withdraw them.
  pub fn unregister_service(&mut self, handle: ServiceHandle, now: I) {
    let Some(key) = self.service_key(handle) else {
      return;
    };
    // A still-undrained rename handoff first: it is a DIFFERENT name, and its
    // goodbye is independent of this teardown's.
    self.drain_rename_goodbye(key, now);
    let Some(snapshot) = self
      .services
      .get_mut(key)
      .map(|route| route.proto.withdrawal_snapshot())
    else {
      return;
    };
    self.begin_withdrawal(handle, snapshot, now);
  }

  /// **Force-remove** the registered service for `handle` IMMEDIATELY, with NO
  /// RFC 6762 §10.1 goodbye.
  ///
  /// This drops the route — and with it the `Service` — and decrements
  /// `services_active` at once: it does NOT send a TTL=0 goodbye, so peers keep
  /// the service in their caches until the records' own TTLs expire, AND the
  /// instance name is released for re-use the moment this returns. It is
  /// intended ONLY for forced / non-graceful removal (an abort path, or after a
  /// confirmed goodbye has already drained).
  ///
  /// # Prefer [`Self::unregister_service`]
  ///
  /// The graceful lifecycle announces a §10.1 goodbye AND holds the name until
  /// that goodbye is confirmed-sent, closing the same-name-reuse race this
  /// primitive deliberately does not guard. The bundled drivers retire services
  /// that way.
  ///
  /// # It still RELINQUISHES, so it still has to say what it asserted
  ///
  /// Sending no goodbye does not make this path quiet. A service force-removed
  /// straight after a confirmed positive send has records on the wire and none
  /// resident anywhere, and the caller may register a replacement at the same
  /// owner names in the very next statement. A delayed echo of the removed
  /// service's own records would then reach normal conflict adjudication and
  /// retire the replacement.
  ///
  /// So this RETAINS what it gives up, taking the removed service's own
  /// withdrawal snapshot on the way out — the same value the graceful path takes
  /// — and keeping it for
  /// [`EndpointConfig::relinquished_retention`](crate::EndpointConfig::relinquished_retention)
  /// on the family that carried it. A never-announced service's snapshot retains
  /// nothing at all, which is correct: it put nothing on any wire.
  ///
  /// A still-draining ROUTE-ATTACHED withdrawal item is retained here too:
  /// dropping the item removes the last resident description of that set, which
  /// is the same relinquishment [`Self::drain_completed_withdrawals`] would have
  /// retained had the goodbye been allowed to finish.
  ///
  /// # Behaviour
  ///
  /// Returns `true` if a route was found and removed, `false` if the handle was
  /// already unknown (idempotent). When this returns, re-registering the same
  /// instance name via [`Self::try_register_service`] succeeds immediately, and
  /// inbound packets no longer match the removed route.
  pub fn force_remove_service(&mut self, handle: ServiceHandle, now: I) -> bool {
    let Some(key) = self.service_key(handle) else {
      return false;
    };
    // BEFORE the route goes: what this service put on the wire outlives it, and
    // once the name is released there is nothing left to say it was ours. The
    // MULTICAST half is the screen's, because it asks what could still be
    // echoing and a §6.7 legacy reply left no copy on the group to echo.
    let snapshot = self
      .services
      .get_mut(key)
      .map(|route| route.proto.withdrawal_snapshot());
    if let Some(snapshot) = snapshot {
      self.retain_relinquished(snapshot.records, snapshot.multicast, now);
    }
    let removed = self.services.try_remove(key).is_some();
    // Force-remove is a NO-goodbye primitive: also drop any ROUTE-attached
    // withdrawal item for this handle. Otherwise removing the route (and thus
    // the name guard) would let the same name be re-registered while a stale
    // route-attached item still owed a TTL=0 goodbye — a late goodbye would then
    // flush the same-name replacement, contradicting "no goodbye". Detached
    // items (renamed-away OLD names) are independent of this handle's route and
    // are left to drain / be cancelled on reclaim.
    //
    // Each dropped item's record set is RELINQUISHED on the way out, exactly as
    // `drain_completed_withdrawals` would have relinquished it: the item was the
    // last resident copy of a set this endpoint transmitted, and this is the
    // moment it stops being consultable.
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
  }
}

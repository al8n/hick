//! RFC 6762 §9's "identical rdata is never a conflict", asked of the record sets
//! this endpoint has RELINQUISHED as well as of the ones it still publishes.
//!
//! # Why the endpoint, and not the service
//!
//! `Service::handle_event` applies the identical-rdata precondition against the
//! RECEIVING service's own records. That is the whole rule while the asserting
//! set and the receiving set are the same set — but a service that has just
//! taken over an owner name is structurally incapable of recognising its
//! PREDECESSOR'S rdata. A withdrawing route stops holding its host name for the
//! registration guard, so a replacement may take host `H` with address set `A2`
//! while the route that held `H` with `A1` is still draining its §10.1 goodbye;
//! a delayed positive-TTL echo of `A1` then reaches the replacement, compares
//! against `A2`, and retires it with a TERMINAL `ServiceUpdate::HostConflict`.
//! Same-instance reuse with changed SRV/TXT reaches a false §8.1 probe defeat
//! the same way.
//!
//! Only the endpoint holds both sides of that, so the screen lives here — in the
//! fan-out that BUILDS the conflict events, before any of them reaches a service.
//!
//! # Why not on the driver side
//!
//! Because every driver-side recognition of such an echo is defeasible, and each
//! of the three reasons is independent:
//!
//! * **Replay-equivalence.** What a self-send log weighs — family, exact bytes,
//!   source port 5353, age — is entirely reproducible by an on-link peer
//!   replaying bytes it captured. There is no fifth signal, and a kernel receive
//!   stamp does not add one: it rejects a datagram the kernel saw BEFORE our
//!   send, and a replay arrives after.
//! * **"No credit" is not "not from us".** Every driver maps an unmatched
//!   datagram to [`Provenance::NotFromUs`](crate::Provenance::NotFromUs), which
//!   adjudicates in full. A send is credited once per family, but the medium may
//!   deliver more than one copy — kernel loopback plus an 802.11 base-station
//!   re-broadcast, which RFC 6762 §8.2 names as an echo source — so whichever
//!   copy loses the race is adjudicated. No attacker is required.
//! * **Recognition state is traffic-scaled and bounded; the obligation is per
//!   copy and unbounded.** A driver evicts credits under a byte budget or
//!   refuses new ones at a cap, and either way the copy it dropped adjudicates.
//!
//! This screen's soundness turns on none of that. Its state scales with LOCAL
//! LIFECYCLE EVENTS rather than with traffic, so it cannot be evicted under
//! load, and it is uniform across every driver.
//!
//! # What a row covers, and why not more
//!
//! A row disowns the record IDENTITIES its set actually TRANSMITTED in positive
//! authoritative responses — never the configured ones. Both errors here are
//! real and they point in opposite directions:
//!
//! * retaining too LITTLE re-opens the stale echo for the identities dropped;
//! * retaining too MUCH suppresses a GENUINE peer's conflict for the whole
//!   window, which is the same terminal outcome from the other side: a
//!   same-name successor finishes probing and announces over an incumbent that
//!   already holds the name.
//!
//! So the retained set is the exposure `Service`'s `GoodbyeOwnership` latch
//! records — per instance record and per host address, latched only by a
//! confirmed send that emitted THAT record — and a relinquishment with no
//! exposure retains nothing at all.
//!
//! # RFC 6762 §8.4
//!
//! In-place record updating is unimplemented. It is a SECOND route to a
//! self-echo carrying rdata we no longer hold — one that stays inside a single
//! service rather than crossing a lifecycle seam — so whoever implements it owes
//! [`Endpoint::retain_relinquished`] a call with the superseded record set, not
//! merely the mutator.

use super::*;

cfg_heap! {
  /// Hard ceiling on retained relinquished record sets — a MEMORY bound, and
  /// nothing else. Reaching it never drops an obligation; see
  /// [`Endpoint::retain_relinquished`] for what it does instead.
  ///
  /// The list is fed by lifecycle events, not by traffic, and every entry
  /// expires on its own window — so in steady state it holds one row per record
  /// GENERATION that recently left with something on the wire, which is bounded
  /// by the relinquishment rate times the window. The ceiling is for the sources
  /// that rate is not itself bounded by: RFC 6762 §9 automatic renaming, where
  /// one service can relinquish a fresh instance name per probe cycle, and an
  /// application that churns registrations.
  ///
  /// It is a real bound rather than a guess because a row costs a whole
  /// `ServiceRecords`; 128 of them is the memory this screen is allowed to hold
  /// on a heap-less-adjacent target, and every one of them lapses within
  /// `EndpointConfig::relinquished_retention` of its insert.
  pub(crate) const MAX_RELINQUISHED_RRSETS: usize = 128;

  /// One record set this endpoint asserted and has since given up, kept until
  /// `expires_at` so its own delayed echoes cannot be adjudicated against
  /// whatever now holds its owner names.
  ///
  /// The whole [`ServiceRecords`](crate::records::ServiceRecords) rather than a
  /// digest of it, because the screen must answer for the INSTANCE name as well
  /// as the host name, and the instance half compares canonical SRV / TXT / NSEC
  /// rdata that only the record bundle can regenerate — PLUS the EXPOSURE that
  /// says which of those identities actually reached the wire. See
  /// [`asserts`] for why the second half is not optional.
  pub(crate) struct Relinquished<I> {
    pub(crate) records: crate::records::ServiceRecords,
    /// Which INSTANCE-owned identities this set confirmed-emitted. Its address
    /// lists are unused — the host halves are `host_a` / `host_aaaa` below,
    /// matching how a `WithdrawalItem` carries them.
    pub(crate) emitted: crate::service::EmittedRecords,
    /// Host A addresses this set confirmed-emitted under `records.host()`.
    pub(crate) host_a: std::vec::Vec<Ipv4Addr>,
    /// Host AAAA addresses this set confirmed-emitted under `records.host()`.
    pub(crate) host_aaaa: std::vec::Vec<Ipv6Addr>,
    /// The instant this row stops screening. A row is skipped, never trusted,
    /// once `now` has reached it; the list is compacted on the next insert.
    pub(crate) expires_at: I,
  }

  /// Does this relinquished set ASSERT `r` — the same owner name, the same
  /// rrtype, rdata byte-identical to a form the set puts on the wire, AND a
  /// record it actually TRANSMITTED?
  ///
  /// The first three are exactly `Service::handle_event`'s precondition, against
  /// the same inputs, so a relinquished set screens no more widely than a live
  /// one would:
  ///
  /// * the HOST half compares ADDRESSES, as `Service::classify_host_rdata` does;
  /// * the INSTANCE half compares CANONICAL rdata through
  ///   [`canonical_rdata_forms`](crate::service::canonical_rdata_forms), which is
  ///   the same function `Service::classify_instance_rdata` reaches — one rule
  ///   with one home, since a second spelling of "which types can be ours" is
  ///   exactly what went stale when conflict routing widened past SRV/TXT.
  ///
  /// Both halves are tested, because a service whose instance name IS its host
  /// name asserts its addresses under both owners.
  ///
  /// # …and the fourth condition, which is this screen's alone
  ///
  /// A live `Service` compares against what it MAY yet advertise, because it may
  /// still advertise it. A relinquished set never will, so its bound is what it
  /// DID advertise — the confirmed-emitted sets, not the configured ones, and
  /// per identity:
  ///
  /// * addresses through `host_a` / `host_aaaa`, the `GoodbyeOwnership` latch's
  ///   per-address record of what a confirmed send actually emitted;
  /// * instance identities through
  ///   [`instance_rtype_exposed`](crate::service::instance_rtype_exposed), the
  ///   exposure mirror of `canonical_rdata_forms`.
  ///
  /// Widening it back to the configured set is not the conservative choice, it
  /// is the OPPOSITE ERROR. A record no transport ever accepted has no echo of
  /// ours to disown, so screening for it can only discard a GENUINE incumbent's
  /// records — letting a same-name successor finish probing and announce over a
  /// peer that already holds the name. That is what a withdrawal with no
  /// exposure at all used to do to every matching QR=1 record for the whole
  /// retention window.
  ///
  /// Rdata that will not decode answers `false`. This screen only ever
  /// WITHHOLDS a conflict, so failing closed here costs nothing the classifier
  /// does not already refund: `Service` drops an undecodable record as
  /// `PeerRdata::Invalid` before every conflict arm.
  pub(crate) fn asserts(
    records: &crate::records::ServiceRecords,
    emitted: &crate::service::EmittedRecords,
    host_a: &[Ipv4Addr],
    host_aaaa: &[Ipv6Addr],
    r: &crate::wire::Ref<'_>,
  ) -> bool {
    // §9's conflict is over "the same name, rrtype and RRCLASS", so a record of
    // another class is not this set's record whatever its rdata says. The
    // callers gate on class IN already; stating it here keeps the predicate
    // true on its own terms.
    if r.rclass() != ResourceClass::In {
      return false;
    }
    if names_match_record(records.host(), r) {
      let asserted_here = match r.rdata_view() {
        Ok(crate::wire::Rdata::A(a)) => host_a.contains(&a.addr()),
        Ok(crate::wire::Rdata::AAAA(a)) => host_aaaa.contains(&a.addr()),
        // Not an address type at all, or rdata that will not decode. Neither is
        // this set's host RRset; the instance half below may still claim it.
        _ => false,
      };
      if asserted_here {
        return true;
      }
    }
    if names_match_record(records.instance(), r)
      && crate::service::instance_rtype_exposed(emitted, r.rtype())
      && let Ok(peer) = r.canonical_rdata_folded()
    {
      return crate::service::canonical_rdata_forms(records, r.rtype())
        .iter()
        .any(|form| form.as_slice() == &*peer);
    }
    false
  }

  /// Is there any identity in this exposure that [`asserts`] could answer for?
  ///
  /// The insert guard: a relinquishment with nothing on the wire has no echo to
  /// disown, so retaining it would screen a genuine peer's matching records for
  /// the whole window and buy nothing. It is deliberately NOT
  /// `EmittedRecords::is_empty`, which counts the SHARED service-type and
  /// subtype PTRs — records this screen never answers for, since neither the
  /// service-type name nor a `_sub` name is an owner it tests.
  pub(crate) fn screens_something(
    emitted: &crate::service::EmittedRecords,
    host_a: &[Ipv4Addr],
    host_aaaa: &[Ipv6Addr],
  ) -> bool {
    emitted.srv() || emitted.txt() || emitted.nsec() || !host_a.is_empty() || !host_aaaa.is_empty()
  }
}

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
    /// Is `r` a record THIS endpoint recently asserted and has since given up?
    ///
    /// Two sources, and they are consecutive rather than alternative — together
    /// they cover the whole life of a relinquishment, from the moment it stops
    /// being published to the end of its retention window:
    ///
    ///  1. **Every in-flight withdrawal item.** A route-attached one is the
    ///     withdrawing route's own set, resident for the whole RFC 6762 §10.1
    ///     drain; a detached one is a §9 rename's abandoned instance name. Both
    ///     are already skipped as conflict RECIPIENTS; this is where they are
    ///     finally read as exculpatory EVIDENCE, which is the half that was
    ///     missing.
    ///  2. **The retention list**, from the moment the item above is gone. See
    ///     [`Self::retain_relinquished`].
    ///
    /// It is a WHOLE-RECORD answer — it depends on the record and on this
    /// endpoint's own history, never on which route the fan-out is currently
    /// visiting — so the conflict helpers take it once per record rather than
    /// per candidate service.
    ///
    /// Both sources are asked with their own EXPOSURE, never with their
    /// configured record set: a withdrawal item's `owned` / `host_a` /
    /// `host_aaaa` came from `Service::withdrawal_snapshot`, which reports only
    /// what a confirmed send actually emitted. See [`relinquished::asserts`].
    ///
    /// A third answer sits above both, and it is the whole of the capacity
    /// story: while a QUARANTINE is live this answers `true` for every
    /// candidate. See [`Self::retain_relinquished`].
    pub(crate) fn relinquished_asserts(&self, r: &crate::wire::Ref<'_>, now: I) -> bool {
      if self.relinquished_quarantined(now) {
        return true;
      }
      self.withdrawals.iter().any(|(_, w)| {
        relinquished::asserts(&w.records, &w.owned, &w.host_a, &w.host_aaaa, r)
      }) || self.relinquished.iter().any(|e| {
        now < e.expires_at
          && relinquished::asserts(&e.records, &e.emitted, &e.host_a, &e.host_aaaa, r)
      })
    }

    /// Is this endpoint holding relinquishments it could not record?
    ///
    /// See [`Self::retain_relinquished`]'s capacity section. `None` — the only
    /// state a normally-operating endpoint is ever in — is `false`.
    pub(crate) fn relinquished_quarantined(&self, now: I) -> bool {
      matches!(self.relinquished_quarantine_until, Some(until) if now < until)
    }

    /// Retain `records` as a relinquished set for
    /// [`EndpointConfig::relinquished_retention`](crate::EndpointConfig::relinquished_retention),
    /// measured from `now`.
    ///
    /// `emitted` / `host_a` / `host_aaaa` are that set's EXPOSURE — the
    /// per-identity record of what a confirmed send actually put on the wire,
    /// exactly as `Service::withdrawal_snapshot` reports it. A relinquishment
    /// with no exposure at all retains NOTHING: it has no echo of its own to
    /// disown, and a row for it would screen a genuine peer's matching records
    /// for the whole window. See [`relinquished::asserts`].
    ///
    /// # Where this is owed
    ///
    /// At every point a record set this endpoint asserted stops being
    /// consultable through anything else:
    ///
    /// * [`Self::drain_completed_withdrawals`], when a goodbye finishes and its
    ///   item — the last resident copy of that set — is removed;
    /// * [`Self::enqueue_rename_withdrawal`], at the §9 rename itself, so the
    ///   abandoned instance name is covered for the full window even though its
    ///   detached goodbye can be reclaim-cancelled long before that;
    /// * [`Self::unregister_service`], the force-remove primitive, which
    ///   releases the owner names the instant it returns. Sending no goodbye
    ///   does not make it quiet: it relinquishes a set that may still be on the
    ///   wire with nothing resident left to describe it, so it retains both the
    ///   caller's snapshot and any route-attached withdrawal item it drops.
    ///
    /// # Generations, not owners
    ///
    /// Each relinquishment is its own row, living to its own expiry. Keying the
    /// list by owner pair and letting a later relinquishment REFRESH the row was
    /// a silent loss: a rapid `R1 → R2 → R3` reuse of one instance/host pair
    /// destroyed `R1`'s protection while `R1`'s echoes were still in flight, so
    /// a delayed `R1` adjudicated against `R3` and recreated the exact terminal
    /// conflict this screen exists to prevent. Only an IDENTICAL generation —
    /// the same records and the same exposure — merges, and it merges by taking
    /// the LATER expiry, which drops nothing because the identity set is the
    /// same one.
    ///
    /// # Capacity
    ///
    /// Expired rows are compacted first, so [`MAX_RELINQUISHED_RRSETS`] bounds
    /// LIVE rows only. Reaching it does NOT evict: an unexpired row is an
    /// unexpired obligation, and dropping the earliest-expiring one is still
    /// dropping one.
    ///
    /// Instead the endpoint QUARANTINES ITS OWN ADJUDICATION until the
    /// relinquishment it could not record would have lapsed:
    /// [`Self::relinquished_asserts`] answers `true` for every candidate, so the
    /// conflict fan-out builds nothing, for at most one retention window past
    /// the last unrecordable relinquishment.
    ///
    /// Three properties make that the right degradation:
    ///
    /// * it is O(1) — one deadline, so the quarantine cannot itself overflow.
    ///   A quarantine LIST of the affected owner names would need its own bound
    ///   and the regress has no fixed point;
    /// * its cost is RECOVERABLE while the alternative's is not. Withholding
    ///   conflicts delays detection of a duplicate name by at most the window,
    ///   and mDNS re-raises it — §8.3 announcements repeat, §9 fires on any
    ///   later response, a prober re-probes. Dropping a relinquishment's
    ///   protection is one-shot and terminal: the delayed echo arrives once and
    ///   retires a live service permanently;
    /// * it is not a name-reuse embargo. `try_register_service` and
    ///   `handle_service_renamed` are untouched, so a vacated host or instance
    ///   name may still be taken immediately — which is what §8.4 wants of a
    ///   same-name record change, and what §8.2's defer-and-re-verify already
    ///   handles for a stale self-packet. What pauses is this endpoint's own
    ///   willingness to RAISE a conflict, not anything visible on the wire.
    ///
    /// §8.2 proposals and the §8.1 defence are unaffected either way: neither
    /// consults this screen, so a probing peer is still tiebroken against and a
    /// name this endpoint holds is still defended during a quarantine.
    ///
    /// Reaching it at all takes more than [`MAX_RELINQUISHED_RRSETS`]
    /// relinquishments of DISTINCT generations that each put a record on the
    /// wire, inside one retention window.
    ///
    /// A window of `Duration::ZERO` — or one the clock cannot represent the end
    /// of — retains nothing, which reduces the screen to source 1 above.
    pub(crate) fn retain_relinquished(
      &mut self,
      records: crate::records::ServiceRecords,
      emitted: crate::service::EmittedRecords,
      host_a: std::vec::Vec<Ipv4Addr>,
      host_aaaa: std::vec::Vec<Ipv6Addr>,
      now: I,
    ) {
      if !relinquished::screens_something(&emitted, &host_a, &host_aaaa) {
        // Nothing of this set ever reached a wire, so no echo of it exists and a
        // row would only withhold a genuine peer's conflicts. The default
        // never-announced withdrawal lands here.
        return;
      }
      let Some(expires_at) = now.checked_add_duration(self.config.relinquished_retention()) else {
        // The clock cannot represent the end of this window, so no row it holds
        // could ever read as live. Nothing to retain.
        return;
      };
      // Compact first: the list is meant to be as large as the live
      // relinquishments and no larger, so history never occupies the ceiling.
      self.relinquished.retain(|e| now < e.expires_at);
      if let Some(existing) = self.relinquished.iter_mut().find(|e| {
        e.records == records
          && e.emitted == emitted
          && e.host_a == host_a
          && e.host_aaaa == host_aaaa
      }) {
        // The IDENTICAL generation relinquished again — a service registered,
        // announced and torn down twice over with nothing changed. It screens
        // exactly the same identities, so taking the later expiry adds a row's
        // worth of nothing and drops nothing either: whatever the old window
        // still had to cover, the new one covers too. `max`, never assignment,
        // so a clock that went backwards cannot shorten a live obligation.
        if existing.expires_at < expires_at {
          existing.expires_at = expires_at;
        }
        return;
      }
      if self.relinquished.len() >= MAX_RELINQUISHED_RRSETS {
        // AT THE CEILING, QUARANTINE — never evict. Every row here is unexpired,
        // so every row is an obligation still owed, and the earliest-expiring
        // one is no more droppable than any other. What this endpoint can no
        // longer say is "that record was not ours", so it stops saying the
        // opposite: `relinquished_asserts` withholds EVERY conflict until this
        // relinquishment would have lapsed. One deadline, so the quarantine
        // cannot itself overflow. See the capacity section above.
        let until = match self.relinquished_quarantine_until {
          Some(t) if t >= expires_at => t,
          _ => expires_at,
        };
        self.relinquished_quarantine_until = Some(until);
        warn!(
          target: "mdns_proto::endpoint",
          live_rows = MAX_RELINQUISHED_RRSETS,
          "retain_relinquished: at the relinquished-RRset ceiling with every row \
           still live — quarantining conflict adjudication for one retention window \
           rather than dropping an unexpired relinquishment"
        );
        return;
      }
      self.relinquished.push(Relinquished {
        records,
        emitted,
        host_a,
        host_aaaa,
        expires_at,
      });
    }

    /// Drop every relinquished row whose window has closed, and lift the
    /// capacity quarantine once its own deadline has passed.
    ///
    /// Hygiene for the rows: [`Self::relinquished_asserts`] already skips an
    /// expired row, and [`Self::retain_relinquished`] compacts before it inserts.
    /// This is what reclaims the memory when the relinquishments STOP — a host
    /// that tears down its services and then goes quiet inserts nothing more.
    ///
    /// Clearing the quarantine latch is likewise hygiene — the read compares
    /// against `now` — but it keeps a stale deadline from outliving the
    /// condition that set it.
    pub(crate) fn sweep_relinquished(&mut self, now: I) {
      self.relinquished.retain(|e| now < e.expires_at);
      if !self.relinquished_quarantined(now) {
        self.relinquished_quarantine_until = None;
      }
    }
  }
}

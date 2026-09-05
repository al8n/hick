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
//! # …and only the MULTICAST half of it, in the ENVELOPE the encoders wrote
//!
//! `GoodbyeOwnership` answers two questions and this screen may read only the
//! narrower one. "A peer may hold this FROM US" counts an RFC 6762 §6.7 legacy
//! reply, so the §10.1 goodbye owes those records a retraction; "a copy may
//! still be ECHOING" does not, because that reply went to one ephemeral port and
//! nothing re-broadcasts it to the group.
//!
//! The same narrowing continues into the wire envelope — which SECTION, and the
//! §10.2 cache-flush bit — asked through
//! [`transmitted_envelope`](crate::service::transmitted_envelope), the one
//! description of what this crate's positive multicast encoders write. Neither
//! qualifier can reject a real echo, and both reject a conforming peer's
//! ordinary browse answer.
//!
//! [`asserts`] states each qualifier and the traffic it turns on.
//!
//! # Two tiers, one question
//!
//! A row keeps the whole `ServiceRecords` and regenerates the comparison forms
//! per candidate record; a [`RelinquishedIdentity`] keeps the forms themselves,
//! `(owner name, rrtype, canonical rdata)` plus the window EACH FAMILY's
//! transmission of them earned, decomposed once at the
//! relinquishment. They answer the same question by construction —
//! [`identities`] is built from the same two functions [`asserts`] calls — and
//! the second exists so that reaching the row ceiling costs a cheaper
//! REPRESENTATION rather than costing adjudication. Capacity exhaustion may
//! narrow what this endpoint can say; it may never make it say more. See
//! [`Endpoint::retain_relinquished`].
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
  /// nothing else. Reaching it drops no obligation and disables no adjudication;
  /// see [`Endpoint::retain_relinquished`] for the compact tier it spills into.
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

  /// Hard ceiling on the COMPACT tier — the identity rows a relinquishment
  /// spills into once [`MAX_RELINQUISHED_RRSETS`] is reached.
  ///
  /// Sized so the compact tier costs about what the exact one does: a
  /// [`RelinquishedIdentity`] is a fraction of a [`Relinquished`], and one
  /// generation decomposes into `SRV + TXT + NSEC` instance identities plus one
  /// per confirmed-emitted address — three for the RFC 6762 §9 rename that is
  /// the only unbounded source of relinquishments, since a rename retains no
  /// addresses. So this covers at least another 128 rename generations beyond
  /// the exact tier's 128, and identical identities MERGE across generations,
  /// which the exact tier cannot do.
  ///
  /// It is a second ceiling rather than a bigger first one because the two tiers
  /// are not interchangeable: the exact tier answers from the record set itself
  /// and cannot be wrong, and everything that fits in it stays there.
  pub(crate) const MAX_RELINQUISHED_IDENTITIES: usize = 512;

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
    /// What this set confirmed-emitted BY MULTICAST ON EACH FAMILY — `[v4, v6]`,
    /// instance identities and host addresses together, exactly as a
    /// `WithdrawalItem`'s own `multicast` half carries them. [`asserts`] reads
    /// only the half belonging to the family the candidate record ARRIVED on.
    ///
    /// MULTICAST, not every confirmed send. A §6.7 legacy unicast reply is a
    /// positive-TTL send of these very records and it is deliberately absent
    /// here: it went to one resolver's ephemeral port, so no copy of it was ever
    /// on the group and no multicast arrival can be its echo. The goodbye's own
    /// accounting still counts it — see `WithdrawalSnapshot::multicast` for the
    /// split.
    pub(crate) emitted: [crate::service::EmittedRecords; 2],
    /// The instant this row stops screening. A row is skipped, never trusted,
    /// once `now` has reached it; the list is compacted on the next insert.
    ///
    /// ONE instant for both families, and that is NOT the aggregate the compact
    /// tier's [`RelinquishedIdentity::expires_at`] has to avoid: a row is ONE
    /// GENERATION, relinquished at one moment, so its two exposure halves were
    /// given up together and lapse together. The only merge that touches it
    /// requires an IDENTICAL generation — the same records AND the same `[v4,
    /// v6]` pair — so extending it extends both halves by the same amount and
    /// each half still screens exactly what it did. A compact identity is the
    /// opposite case: it merges ACROSS generations on a PARTIAL key, where the
    /// two may have reached different families at different times.
    pub(crate) expires_at: I,
  }

  /// ONE record identity a relinquished set transmitted — the COMPACT tier, and
  /// the whole of what this screen has ever needed.
  ///
  /// [`asserts`] only ever answers a per-record question: same owner name, same
  /// rrtype, rdata byte-identical to a form the set puts on the wire, and
  /// actually transmitted. A [`Relinquished`] row answers it by regenerating
  /// the forms from a whole `ServiceRecords`; this answers the same question by
  /// having done that once, at the relinquishment, and keeping only the answer.
  ///
  /// The rdata is kept VERBATIM rather than digested. A digest would be smaller
  /// still, but a collision here is not a smaller version of the same error — it
  /// SUPPRESSES A GENUINE PEER'S CONFLICT, letting a same-name successor
  /// announce over an incumbent, which is the terminal outcome from the other
  /// side. Nothing about this tier needs the extra compaction badly enough to
  /// buy a defect class that no test can observe, and the bytes are bounded by
  /// what the exact tier already stores for the same generation.
  pub(crate) struct RelinquishedIdentity<I> {
    /// The owner name this identity is asserted at — the set's host name for an
    /// address, its instance name otherwise.
    pub(crate) owner: crate::Name,
    /// The rrtype, compared exactly as §9's "the same name, rrtype and RRCLASS"
    /// requires. Class IN is not stored: [`identity_asserts`] rejects every
    /// other class outright, as [`asserts`] does.
    pub(crate) rtype: ResourceType,
    /// The canonical FOLDED rdata bytes, in the form
    /// [`crate::wire::Ref::canonical_rdata_folded`] produces for a peer record —
    /// so the comparison is the byte equality [`asserts`] performs, not a
    /// re-derivation of it.
    pub(crate) rdata: std::vec::Vec<u8>,
    /// WHEN THIS IDENTITY STOPS SCREENING ON EACH FAMILY — `[v4, v6]`, `None`
    /// for a family that never transmitted it.
    ///
    /// Both halves of one fact, because both are per family and neither
    /// survives being reduced to the other's aggregate:
    ///
    /// * WHICH families transmitted it. An arrival on a family that did not
    ///   cannot be an echo of ours — a loopback copy comes back over a socket
    ///   that carried the datagram out — so the screen must not disown it. The
    ///   exact tier answers this by reading its own family's `emitted` half.
    /// * HOW LONG each family's claim lasts. This tier MERGES identities across
    ///   generations, and two generations that reached different families
    ///   relinquished at different instants. A single expiry with a `[v4, v6]`
    ///   presence mask beside it collapses exactly that: retain an identity from
    ///   an IPv4 generation, then the same rdata from a LATER IPv6 one, and the
    ///   merged row said "both families, the later expiry" — so after the IPv4
    ///   generation's window closed an IPv4 peer asserting that rdata was still
    ///   disowned, suppressing a genuine RFC 6762 §8.1 or §9 conflict against a
    ///   successor holding different rdata. The exact tier keeps the two
    ///   generations in separate rows and never agreed with that answer.
    ///
    /// So the presence mask IS the expiry: `None` is "this family never carried
    /// it", `Some(t)` is "this family carried it and screens until `t`", and a
    /// merge may only ever extend the half its generation actually reached.
    pub(crate) expires_at: [Option<I>; 2],
  }

  /// Decompose what a relinquished set TRANSMITTED into the identities
  /// [`asserts`] would have answered for.
  ///
  /// It is the same two rules, evaluated once instead of per candidate record:
  /// the confirmed-emitted addresses under the HOST name, and every
  /// [`transmitted_rdata_forms`](crate::service::transmitted_rdata_forms) form
  /// of every rrtype this generation
  /// [`instance_rtype_exposed`](crate::service::instance_rtype_exposed) reports
  /// under the INSTANCE name. Both halves are produced, because a service whose
  /// instance name IS its host name asserts its addresses under both owners.
  ///
  /// TRANSMITTED forms, not the live classifier's — [`asserts`] and this must
  /// answer for the same identities or the two tiers disagree about the same
  /// generation, and the transmitted list is the one history is entitled to.
  /// See [`asserts`]'s fourth condition.
  ///
  /// The rrtypes come from
  /// [`INSTANCE_CANONICAL_RTYPES`](crate::service::INSTANCE_CANONICAL_RTYPES),
  /// which is `canonical_rdata_forms`'s own stated domain and therefore
  /// `transmitted_rdata_forms`'s too. Writing the list out here instead would be
  /// the third spelling of "which types can be ours", and the second one is what
  /// went stale when conflict routing widened past SRV/TXT.
  pub(crate) fn identities(
    records: &crate::records::ServiceRecords,
    emitted: &crate::service::EmittedRecords,
  ) -> std::vec::Vec<(crate::Name, ResourceType, std::vec::Vec<u8>)> {
    let mut out = std::vec::Vec::new();
    for ip in emitted.a_slice() {
      out.push((records.host().clone(), ResourceType::A, ip.octets().to_vec()));
    }
    for ip in emitted.aaaa_slice() {
      out.push((records.host().clone(), ResourceType::AAAA, ip.octets().to_vec()));
    }
    for rtype in crate::service::INSTANCE_CANONICAL_RTYPES {
      if !crate::service::instance_rtype_exposed(emitted, rtype) {
        continue;
      }
      for form in crate::service::transmitted_rdata_forms(records, rtype) {
        out.push((records.instance().clone(), rtype, form));
      }
    }
    out
  }

  /// Does the identity `(owner, rtype, rdata)` assert `r`?
  ///
  /// The compact tier's half of [`asserts`], and deliberately the same three
  /// comparisons in the same order: class IN, the owner name, the rrtype, then
  /// canonical FOLDED rdata equality. An address identity holds the four or
  /// sixteen octets `write_canonical_rdata` copies verbatim for A / AAAA, so the
  /// one comparison covers both halves that [`asserts`] spells separately.
  ///
  /// The WIRE ENVELOPE — `section` and the cache-flush bit — is asked through
  /// the same [`transmitted_envelope`](crate::service::transmitted_envelope) the
  /// exact tier asks, which is what keeps the two tiers answering for one set of
  /// identities. See [`asserts`]'s own section on it.
  ///
  /// THE WINDOW IS PART OF THE ANSWER HERE, and per family, which is why this
  /// takes `now` where the exact tier's caller tests the row's one expiry
  /// itself: an identity may be live on the family a later generation reached
  /// and lapsed on the family an earlier one did. See
  /// [`RelinquishedIdentity::expires_at`].
  ///
  /// `peer` is `r`'s canonical FOLDED rdata, decoded ONCE by the caller and
  /// `None` when it will not decode — which answers `false`, for the reason
  /// [`asserts`] gives: this screen only ever WITHHOLDS a conflict, and
  /// `Service` drops an undecodable record as `PeerRdata::Invalid` before every
  /// conflict arm anyway. It is the caller's because the answer does not vary
  /// with the identity, and this runs once per row of a list bounded by
  /// [`MAX_RELINQUISHED_IDENTITIES`].
  pub(crate) fn identity_asserts<I: Instant>(
    identity: &RelinquishedIdentity<I>,
    r: &crate::wire::Ref<'_>,
    peer: Option<&[u8]>,
    now: I,
    family: crate::transmit::Family,
    section: crate::service::RecordSection,
  ) -> bool {
    matches!(family.pick(identity.expires_at), Some(expires_at) if now < expires_at)
      && r.rclass() == ResourceClass::In
      && crate::service::transmitted_envelope(r.rtype(), section, r.cache_flush())
      && r.rtype() == identity.rtype
      && names_match_record(&identity.owner, r)
      && peer == Some(identity.rdata.as_slice())
  }

  /// Is this identity still screening on EITHER family?
  ///
  /// The compaction and sweep predicate, and it must be the OR: a row whose
  /// IPv4 half has lapsed while its IPv6 half is live is still an obligation
  /// owed on IPv6, and dropping it would re-open that family's window early.
  /// A lapsed half needs no clearing — [`identity_asserts`] reads the arriving
  /// family's own expiry and a lapsed one never answers `true` — and keeping it
  /// is what lets a later generation on that family extend it forward.
  pub(crate) fn identity_live<I: Instant>(identity: &RelinquishedIdentity<I>, now: I) -> bool {
    identity
      .expires_at
      .iter()
      .any(|e| matches!(e, Some(expires_at) if now < *expires_at))
  }

  /// Does this relinquished set ASSERT `r` — the same owner name, the same
  /// rrtype, rdata byte-identical to a form the set PUT on the wire, AND a
  /// record it actually TRANSMITTED?
  ///
  /// The first three are `Service::handle_event`'s precondition NARROWED, over
  /// the same inputs, so a relinquished set screens no more widely than a live
  /// one would — and for the instance half, strictly less widely:
  ///
  /// * the HOST half compares ADDRESSES, as `Service::classify_host_rdata` does;
  /// * the INSTANCE half compares CANONICAL rdata through
  ///   [`transmitted_rdata_forms`](crate::service::transmitted_rdata_forms), the
  ///   HISTORY half of the one function `Service::classify_instance_rdata`
  ///   reaches — one rule with one home, since a second spelling of "which types
  ///   can be ours" is exactly what went stale when conflict routing widened
  ///   past SRV/TXT.
  ///
  /// Both halves are tested, because a service whose instance name IS its host
  /// name asserts its addresses under both owners.
  ///
  /// # …and the fourth condition, which is this screen's alone
  ///
  /// A live `Service` compares against what it MAY yet advertise, because it may
  /// still advertise it. A relinquished set never will, so its bound is what it
  /// DID advertise BY MULTICAST — the confirmed-emitted sets, not the configured
  /// ones, and the multicast half of those, not every send. An RFC 6762 §6.7
  /// legacy reply put these very records in one resolver's cache and put no copy
  /// of them on the group, so it owes a §10.1 retraction and can produce no echo
  /// this screen would ever be asked about. Per identity:
  ///
  /// * addresses through the exposure's own address lists, the
  ///   `GoodbyeOwnership` latch's per-address record of what a confirmed send
  ///   actually emitted;
  /// * instance identities through
  ///   [`instance_rtype_exposed`](crate::service::instance_rtype_exposed), the
  ///   exposure mirror of `canonical_rdata_forms`.
  ///
  /// Widening it back to the configured set is not the conservative choice, it
  /// is the OPPOSITE ERROR. A record no transport ever accepted has no echo of
  /// ours to disown, so screening for it can only discard a GENUINE incumbent's
  /// records — letting a same-name successor finish probing and announce over a
  /// peer that already holds the name, for the whole retention window.
  ///
  /// # …and the RDATA FORM, which is the same condition one dimension further in
  ///
  /// The exposure says WHICH rrtypes went out; it does not say which SPELLING of
  /// one. For SRV and TXT there is only one and the question does not arise, but
  /// `canonical_rdata_forms` deliberately accepts a SECOND instance-NSEC bitmap
  /// — the accurate `{SRV, TXT, A, AAAA}` one a CONFORMING responder publishes
  /// where the instance name is also the host name, which this crate's encoder
  /// does not write (it always writes `{SRV, TXT}`).
  ///
  /// Accepting it is right for the LIVE classifier: such a twin is
  /// indistinguishable from us at that name and §9's identical-rdata rule
  /// protects it from our rename. It is wrong here, because this screen makes a
  /// FACTUAL claim about the wire — these exact bytes left this endpoint, on
  /// this family, in this generation — and a form we never encoded did not. A
  /// genuine twin's conforming NSEC read as an old self-echo of ours withholds
  /// the decisive §8.1 / §9 conflict against a successor for the whole retention
  /// window, which is the terminal outcome this screen exists to prevent, from
  /// the other side.
  ///
  /// # …and the FAMILY, which is the same condition one dimension over
  ///
  /// `emitted` is the `[v4, v6]` pair and `family` is the family the candidate
  /// ARRIVED on, so this reads only the half that family transmitted. A datagram
  /// travels back over a socket that carried it out, so a record IPv6 never sent
  /// can hold no IPv6 echo, and a set that says otherwise is disowning a GENUINE
  /// peer's §8.1 or §9 conflict purely for agreeing with a transmission that
  /// family never saw. A fan-out is two sends and either may be refused, so a
  /// generation reaching one family and not the other is an ordinary partial
  /// round rather than an exotic case.
  ///
  /// # …and the WIRE ENVELOPE: the SECTION, and the CACHE-FLUSH BIT
  ///
  /// The same condition two dimensions further over, and asked of
  /// [`transmitted_envelope`](crate::service::transmitted_envelope) — the one
  /// description of what this crate's positive multicast encoders write, kept
  /// beside `transmitted_rdata_forms` so the screen cannot drift from them. A
  /// record is this set's only if it arrives in the section that set's rrtype
  /// was WRITTEN in (the answer section for SRV / TXT / A / AAAA, the additional
  /// section for the §6.1 instance NSEC, never the authority section) and
  /// carries the RFC 6762 §10.2 cache-flush bit those encoders set.
  ///
  /// Neither can reject a real echo. An echo is a re-DELIVERY of a datagram, not
  /// a re-encoding of it, so the header counts that place a record in its
  /// section and the bit in its class field are the ones this endpoint wrote.
  ///
  /// Without them a peer's ordinary browse response was disowned. A conforming
  /// responder answers a PTR query with its SRV in the answer section and the
  /// ADDRESS it points at in the additional section — RFC 6763 §12's own advice
  /// — and this crate writes addresses only as answers, so such a record cannot
  /// be an echo of ours; disowning it SUPPRESSED THE TERMINAL `HostConflict`
  /// with ordinary traffic and no crafted case. The bit ranks below the section
  /// only because exploiting it needs a non-conforming peer: every unique record
  /// this crate multicasts sets it, so a peer record without it cannot be our
  /// echo either.
  ///
  /// `peer` is `r`'s canonical FOLDED rdata, decoded ONCE by the caller. Rdata
  /// that will not decode is `None` and answers `false`: this screen only ever
  /// WITHHOLDS a conflict, so failing closed here costs nothing the classifier
  /// does not already refund — `Service` drops an undecodable record as
  /// `PeerRdata::Invalid` before every conflict arm. It is a parameter because
  /// the decode does not vary with the record SET, while this runs once per
  /// resident withdrawal item and once per row of a list bounded by
  /// [`MAX_RELINQUISHED_RRSETS`].
  pub(crate) fn asserts(
    records: &crate::records::ServiceRecords,
    emitted: &[crate::service::EmittedRecords; 2],
    r: &crate::wire::Ref<'_>,
    peer: Option<&[u8]>,
    family: crate::transmit::Family,
    section: crate::service::RecordSection,
  ) -> bool {
    // §9's conflict is over "the same name, rrtype and RRCLASS", so a record of
    // another class is not this set's record whatever its rdata says. The
    // callers gate on class IN already; stating it here keeps the predicate
    // true on its own terms.
    if r.rclass() != ResourceClass::In {
      return false;
    }
    // THE WIRE ENVELOPE, before either half: an rrtype this crate does not write
    // in THIS section, or one written with the §10.2 cache-flush bit and
    // arriving without it, is not an echo of anything this endpoint multicast —
    // whatever its owner name and rdata say. Ahead of the family narrowing
    // because it is a fact about the encoders rather than about this generation.
    if !crate::service::transmitted_envelope(r.rtype(), section, r.cache_flush()) {
      return false;
    }
    // ONLY the arriving family's half. See the section above.
    let emitted = family.pick_ref(emitted);
    if names_match_record(records.host(), r) {
      let asserted_here = match r.rdata_view() {
        Ok(crate::wire::Rdata::A(a)) => emitted.a_slice().contains(&a.addr()),
        Ok(crate::wire::Rdata::AAAA(a)) => emitted.aaaa_slice().contains(&a.addr()),
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
      && let Some(peer) = peer
    {
      return crate::service::transmitted_rdata_forms(records, r.rtype())
        .iter()
        .any(|form| form.as_slice() == peer);
    }
    false
  }

  /// Is there any identity in this exposure that [`asserts`] could answer for,
  /// on EITHER family?
  ///
  /// The insert guard: a relinquishment with nothing on any wire has no echo to
  /// disown, so retaining it would screen a genuine peer's matching records for
  /// the whole window and buy nothing. It is deliberately NOT
  /// `EmittedRecords::is_empty`, which counts the SHARED service-type and
  /// subtype PTRs — records this screen never answers for, since neither the
  /// service-type name nor a `_sub` name is an owner it tests.
  ///
  /// EITHER family, because a row that screens only IPv4 is still a row worth
  /// keeping: `asserts` narrows to the arriving family itself, so the guard only
  /// has to reject a set that screens nothing anywhere.
  pub(crate) fn screens_something(emitted: &[crate::service::EmittedRecords; 2]) -> bool {
    emitted.iter().any(|e| {
      e.srv() || e.txt() || e.nsec() || !e.a_slice().is_empty() || !e.aaaa_slice().is_empty()
    })
  }
}

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
    /// Is `r` a record THIS endpoint recently asserted and has since given up?
    ///
    /// Three sources, and they are consecutive rather than alternative —
    /// together they cover the whole life of a relinquishment, from the moment
    /// it stops being published to the end of its retention window:
    ///
    ///  1. **Every in-flight withdrawal item.** A route-attached one is the
    ///     withdrawing route's own set, resident for the whole RFC 6762 §10.1
    ///     drain; a detached one is a §9 rename's abandoned instance name. Both
    ///     are also skipped as conflict RECIPIENTS; this is where they are read
    ///     as exculpatory EVIDENCE.
    ///  2. **The retention list**, from the moment the item above is gone. See
    ///     [`Self::retain_relinquished`].
    ///  3. **The compact identity list**, which holds what a relinquishment
    ///     transmitted when the retention list was already at its ceiling. Same
    ///     answer, decomposed once at the relinquishment instead of regenerated
    ///     per record. See [`Self::retain_relinquished`].
    ///
    /// It is a WHOLE-RECORD answer — it depends on the record and on this
    /// endpoint's own history, never on which route the fan-out is currently
    /// visiting — so the conflict helpers take it once per record rather than
    /// per candidate service.
    ///
    /// Every source is asked with its own MULTICAST EXPOSURE, never with a
    /// configured record set and never with the goodbye's wider one: a
    /// withdrawal item's `multicast` came from `Service::withdrawal_snapshot`,
    /// which reports what a confirmed send actually emitted, on which family,
    /// and TO WHAT DESTINATION CLASS. A §6.7 legacy reply is a positive
    /// authoritative send that reached no group, so it is in `owned` — the
    /// goodbye must still retract it — and not here. See
    /// [`relinquished::asserts`].
    /// A reclaim can NARROW an item to what a replacement's announcement did not
    /// supersede, which makes source 1 answer for LESS and never for more; the
    /// retention row taken at the relinquishment itself — source 2 — is what
    /// holds the rest, which is why that retain is unconditional and up front.
    ///
    /// `family` is the family `r` ARRIVED on, and every source is narrowed to
    /// what IT transmitted there. A multicast datagram comes back over a socket
    /// that carried it out, so a record only IPv4 ever sent can hold no IPv6
    /// echo — and an exposure that answered for both would be disowning a
    /// GENUINE peer's §8.1 or §9 conflict on the family it never reached.
    ///
    /// `section` is the section `r` ARRIVED in, and it is weighed the same way
    /// against the section this crate's encoders WRITE that rrtype in — together
    /// with the RFC 6762 §10.2 cache-flush bit they set. Both are envelope facts
    /// about the datagram rather than about any one source, so every source is
    /// asked with them; see [`relinquished::asserts`]. A conforming responder's
    /// Additional-section address is the case that matters: this crate writes
    /// addresses only as ANSWERS, so such a record can be no echo of ours, and
    /// disowning it withheld the terminal `HostConflict` from ordinary traffic.
    ///
    /// NO SOURCE ANSWERS FOR A RECORD IT CANNOT NAME. There is no capacity
    /// fallback that answers `true` unconditionally, and there must not be: an
    /// endpoint that cannot say "that record was not ours" has learned nothing
    /// about the records it CAN still name, and saying `true` for those is a
    /// false negative at every name it holds. See [`Self::retain_relinquished`]
    /// for what reaching a ceiling costs instead.
    ///
    /// # The canonical rdata is decoded ONCE, here
    ///
    /// All three sources compare the same bytes — `r`'s canonical FOLDED rdata
    /// — against their own stored form, and every one of them is a LIST: the
    /// resident withdrawal items, up to [`MAX_RELINQUISHED_RRSETS`] rows and up
    /// to [`MAX_RELINQUISHED_IDENTITIES`] identities. Decoding per row would
    /// cost one screen hundreds of canonicalizations of the same record. It is
    /// decoded before the first source and handed down; `None` — rdata that will
    /// not decode — is `false` at every source.
    ///
    /// The other half of the same bound is that the SCREEN itself runs once per
    /// section record rather than once per candidate service; that lives in
    /// `RouteEvents::relinquished_screen`, because only the iterator knows when
    /// the record advances.
    pub(crate) fn relinquished_asserts(
      &self,
      r: &crate::wire::Ref<'_>,
      now: I,
      family: crate::transmit::Family,
      section: crate::service::RecordSection,
    ) -> bool {
      let folded = r.canonical_rdata_folded().ok();
      let peer = folded.as_deref();
      self
        .withdrawals
        .iter()
        .any(|(_, w)| relinquished::asserts(&w.records, &w.multicast, r, peer, family, section))
        || self.relinquished.iter().any(|e| {
          now < e.expires_at
            && relinquished::asserts(&e.records, &e.emitted, r, peer, family, section)
        })
        || self
          .relinquished_identities
          .iter()
          .any(|e| relinquished::identity_asserts(e, r, peer, now, family, section))
    }

    /// Retain `records` as a relinquished set for
    /// [`EndpointConfig::relinquished_retention`](crate::EndpointConfig::relinquished_retention),
    /// measured from `now`.
    ///
    /// `emitted` is that set's MULTICAST EXPOSURE — `[v4, v6]`, the
    /// per-identity and per-family record of what a confirmed send actually put
    /// on the GROUP, exactly as `Service::withdrawal_snapshot` reports it in its
    /// `multicast` half. A relinquishment with no such exposure on either family
    /// retains NOTHING: it has no echo of its own to disown, and a row for it
    /// would screen a genuine peer's matching records for the whole window. That
    /// now includes a set whose only positive send was a §6.7 legacy reply —
    /// real, confirmed, and incapable of producing a multicast echo. See
    /// [`relinquished::asserts`].
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
    /// list by owner pair and letting a later relinquishment REFRESH the row is
    /// a silent loss: a rapid `R1 → R2 → R3` reuse of one instance/host pair
    /// destroys `R1`'s protection while `R1`'s echoes are still in flight, so a
    /// delayed `R1` adjudicates against `R3` and recreates the exact terminal
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
    /// Instead the relinquishment is recorded COMPACTLY — decomposed into the
    /// record identities it transmitted ([`relinquished::identities`]) and kept
    /// as [`RelinquishedIdentity`] rows to the same expiry. The screen answers
    /// exactly the same question from them, so nothing is lost but the ability
    /// to regenerate the forms; identical identities MERGE across generations,
    /// which the exact tier cannot do, so a rename storm that reuses rdata costs
    /// far less here than a row apiece.
    ///
    /// CAPACITY EXHAUSTION MUST NEVER BECOME A GLOBAL "THIS WAS OURS". An
    /// endpoint-wide fallback — a quarantine deadline past which
    /// [`Self::relinquished_asserts`] answers `true` for every candidate — is
    /// wrong in SCALE even where it is right in kind. Withholding one
    /// generation's conflicts risks that generation; withholding every
    /// conflict guarantees false negatives at every name the endpoint holds,
    /// for names it could still perfectly well have adjudicated. On-link peers
    /// choose the relinquishment rate, through §9 re-probes and §8.1 renames
    /// that carry no fifteen-in-ten-seconds backoff, so the reachable state was:
    /// fill the table, then probe over an incumbent or hide an established §9
    /// conflict while it drained.
    ///
    /// So the degradation is bounded to the identity that could not be recorded,
    /// and to nothing else. When [`MAX_RELINQUISHED_IDENTITIES`] is reached too,
    /// the identities that do not fit are simply not recorded: the endpoint
    /// loses THIS relinquishment's screen and keeps every other one it holds.
    /// The loss lands on the newest relinquishment rather than on an older one
    /// because evicting to make room would let a peer choose the victim —
    /// filling the table is how it would aim.
    ///
    /// §8.2 proposals and the §8.1 defence are unaffected throughout: neither
    /// consults this screen, so a probing peer is still tiebroken against and a
    /// name this endpoint holds is still defended.
    ///
    /// Reaching the first ceiling takes more than [`MAX_RELINQUISHED_RRSETS`]
    /// relinquishments of DISTINCT generations that each put a record on the
    /// wire, inside one retention window; reaching the second takes
    /// [`MAX_RELINQUISHED_IDENTITIES`] DISTINCT identities beyond that.
    ///
    /// A window of `Duration::ZERO` — or one the clock cannot represent the end
    /// of — retains nothing, which reduces the screen to source 1 above.
    pub(crate) fn retain_relinquished(
      &mut self,
      records: crate::records::ServiceRecords,
      emitted: [crate::service::EmittedRecords; 2],
      now: I,
    ) {
      if !relinquished::screens_something(&emitted) {
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
      if let Some(existing) = self
        .relinquished
        .iter_mut()
        .find(|e| e.records == records && e.emitted == emitted)
      {
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
        // AT THE CEILING, SPILL — never evict, and never quarantine. Every row
        // here is unexpired, so every row is an obligation still owed and the
        // earliest-expiring one is no more droppable than any other; and an
        // endpoint that cannot record THIS set has learned nothing about the
        // ones it already holds, so it must not stop adjudicating for them. What
        // it records instead is exactly what this set transmitted, identity by
        // identity. See the capacity section above.
        self.retain_relinquished_identities(&records, &emitted, now, expires_at);
        return;
      }
      self.relinquished.push(Relinquished {
        records,
        emitted,
        expires_at,
      });
    }

    /// Record one relinquishment in the COMPACT tier: every identity it
    /// transmitted, each to `expires_at` ON THE FAMILY THAT TRANSMITTED IT.
    ///
    /// An identity already held merges by taking the LATER expiry — `max`, never
    /// assignment, so a clock that went backwards cannot shorten a live
    /// obligation — and PER FAMILY, only on the half this generation reached.
    /// Merging is sound for the same reason the exact tier's
    /// identical-generation merge is, but only under that narrowing: the two
    /// generations answer for the same record ON A GIVEN FAMILY, so one half
    /// covering the longer window covers both. Merging the windows THEMSELVES
    /// does not follow and is not sound — see
    /// [`RelinquishedIdentity::expires_at`] for what an IPv4 generation
    /// inheriting a later IPv6 one's expiry suppresses.
    ///
    /// At [`MAX_RELINQUISHED_IDENTITIES`] the identities that do not fit are NOT
    /// recorded, and nothing already recorded is disturbed. That is the whole
    /// degradation: this relinquishment loses its screen, every other one keeps
    /// it, and no record anywhere is answered for that this endpoint cannot
    /// name.
    fn retain_relinquished_identities(
      &mut self,
      records: &crate::records::ServiceRecords,
      emitted: &[crate::service::EmittedRecords; 2],
      now: I,
      expires_at: I,
    ) {
      // Compact first, exactly as the exact tier does: the ceiling is meant to
      // bound the LIVE identities, so a lapsed one must never occupy it. LIVE ON
      // EITHER FAMILY — see `relinquished::identity_live`.
      self
        .relinquished_identities
        .retain(|e| relinquished::identity_live(e, now));
      let mut dropped = 0usize;
      // Decomposed PER FAMILY and merged into one row per identity, so an
      // identity IPv4 alone transmitted keeps a window on IPv4 ALONE. What each
      // half carries is this generation's own expiry, never a blanket `[Some,
      // Some]` — the collapse this tier must not reintroduce, in either of its
      // two spellings (a family that never carried the identity, or one whose
      // own window has closed).
      let [v4, v6] = emitted;
      let decomposed = [
        (
          relinquished::identities(records, v4),
          [Some(expires_at), None],
        ),
        (
          relinquished::identities(records, v6),
          [None, Some(expires_at)],
        ),
      ];
      for (identities, on) in decomposed {
        for (owner, rtype, rdata) in identities {
          if let Some(existing) = self
            .relinquished_identities
            .iter_mut()
            .find(|e| e.rtype == rtype && e.rdata == rdata && e.owner.same_owner(&owner))
          {
            // PER FAMILY, and forward only. `None` sorts below every `Some`, so
            // `max` is exactly the two rules at once: the half this generation
            // did NOT carry is left untouched whatever it holds, and the half it
            // did carry takes the later of the two windows — never a shortening,
            // so a clock that went backwards cannot cut a live obligation, and
            // never a cross-family write.
            for (slot, carried) in existing.expires_at.iter_mut().zip(on) {
              *slot = (*slot).max(carried);
            }
            continue;
          }
          if self.relinquished_identities.len() >= MAX_RELINQUISHED_IDENTITIES {
            dropped = dropped.saturating_add(1);
            continue;
          }
          self.relinquished_identities.push(RelinquishedIdentity {
            owner,
            rtype,
            rdata,
            expires_at: on,
          });
        }
      }
      if dropped > 0 {
        warn!(
          target: "mdns_proto::endpoint",
          dropped,
          live_rows = MAX_RELINQUISHED_RRSETS,
          live_identities = MAX_RELINQUISHED_IDENTITIES,
          "retain_relinquished: both relinquished tiers are full of live entries — \
           this relinquishment's identities go unscreened, and no other \
           relinquishment's screen is affected"
        );
      }
    }

    /// Drop every relinquished row and identity whose window has closed — for an
    /// identity, on BOTH families.
    ///
    /// Hygiene: [`Self::relinquished_asserts`] already skips an expired entry,
    /// and [`Self::retain_relinquished`] compacts before it inserts. This is
    /// what reclaims the memory when the relinquishments STOP — a host that
    /// tears down its services and then goes quiet inserts nothing more.
    pub(crate) fn sweep_relinquished(&mut self, now: I) {
      self.relinquished.retain(|e| now < e.expires_at);
      self
        .relinquished_identities
        .retain(|e| relinquished::identity_live(e, now));
    }
  }
}

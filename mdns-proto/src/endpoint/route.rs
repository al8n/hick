//! The `RouteEvents` iterator: demuxes one inbound message into routing events.

use super::*;

/// Iterator over routing decisions for a single incoming datagram.
///
/// Borrows the endpoint mutably for the duration of iteration, and DISPATCHES —
/// it does not merely describe. A [`ServiceEvent`] is applied to the addressed
/// [`Service`] inside this borrow, at the `now` [`Endpoint::handle`] was called
/// with, before any event is yielded; `QueryEvent::Answer` was already applied
/// eagerly in `handle`, and [`RouteEvent::ToQuery`] reports it.
///
/// So a caller dispatches nothing. That is what makes the datagram's receipt
/// instant the instant its conflicts are classified and counted at — RFC 6762
/// §8.1's flood history is folded here, synchronously — rather than whenever a
/// caller got round to forwarding an event it had been handed.
pub struct RouteEvents<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS>
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
  pub(crate) src: SocketAddr,
  pub(crate) endpoint: &'e mut Endpoint<I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS>,
  pub(crate) reader: MessageReader<'a>,
  /// The instant [`Endpoint::handle`] processed this datagram at, carried in so
  /// the query fan-out weighs the caller's `QuerySpec::with_timeout` window
  /// against the SAME reading that decided whether the answer was collected.
  ///
  /// Without it the two sites disagree about one datagram: `handle` applies and
  /// refuses a late answer eagerly, while the query intentionally stays live
  /// until its own timer fires — so the fan-out below, which screens only
  /// `is_done` / `terminal_emitted`, would announce a record refused for
  /// standing past a boundary the CALLER set. These events are informational, so
  /// that is a report of an answer no caller can find in `collected_answers`
  /// rather than a state change; the remedy is the same either way, because a
  /// consumer cannot tell such a report apart from an accepted one.
  ///
  /// This aligns the two sites on the caller's window and on nothing else.
  /// `Query::handle_event` also declines records on its own terms — a zero
  /// `max_answers` cap, a duplicate, undecodable rdata, a full answer pool — and
  /// the fan-out screens none of those, which is why [`RouteEvent::ToQuery`]
  /// states an offer rather than a receipt. Those refusals stay deliberately
  /// unreported, and a consumer cannot in general reconstruct them: a duplicate
  /// the query already held and an equal record it has just kept leave
  /// `collected_answers` looking the same, and a pool refusal turns on occupancy
  /// no event carries. The window is mirrored because it is the one refusal that
  /// is otherwise INVISIBLE — it turns on a reading taken inside `handle`, so
  /// leaving it unmirrored would let a driver's tick order decide what the
  /// consumer is told.
  ///
  /// It is not re-read per record. The datagram is one event with one processing
  /// instant, which is what keeps its cache writes, its collections and this
  /// fan-out in one epoch instead of splitting a single message across two.
  pub(crate) now: I,
  /// `true` when the QR bit is set (this is a response, not a query).
  /// Used to gate KnownAnswer-suppression routing: KAS hints must only be
  /// extracted from QUERY packets (QR=0); response packets must not poison
  /// the KAS ring.
  pub(crate) is_response: bool,
  /// Identifies THIS datagram, stamped on every conflict it raises so a
  /// service keeps one query's proposal separate from the next. See
  /// [`DatagramId`].
  pub(crate) datagram: crate::event::DatagramId,
  /// Cursor for the one-proposal-per-service fan-out of `AuthorityProposals`.
  pub(crate) proposal_service_cursor: Option<usize>,
  pub(crate) question_idx: u16,
  /// Per-question service cursor: the slab key from which to resume iterating
  /// services for the current question. Allows ALL matching services to receive
  /// a `ServiceEvent::Question` for a single question before advancing to the
  /// next question.
  pub(crate) service_cursor: usize,
  pub(crate) answer_idx: u16,
  pub(crate) authority_idx: u16,
  /// Stashed query event behind a higher-priority service event (e.g. a
  /// `ProbeConflict` or `KnownAnswer` is dispatched first and the first matching
  /// `QueryEvent::Answer` for the same record drains on the next call).
  pub(crate) pending_query: Option<RouteEvent<'a>>,
  /// cursor for fanning out additional matching query routes for
  /// the current `answer_idx` across multiple `next()` calls without
  /// buffering events.  `None` means "have not started query fan-out for
  /// this record" — `next()` does the service-side pass plus finds the
  /// FIRST matching query.  `Some(k)` means "mid fan-out — resume scanning
  /// `self.queries` from slab key `k`."  Resets to `None` whenever
  /// `answer_idx` advances, so the cursor is always paired with the
  /// current answer record.
  ///
  /// A cursor rather than a buffer because the inbound packet path may not
  /// allocate: `Vec::push` is infallible, so under allocator pressure it aborts
  /// instead of surfacing an error, and draining a buffer with `Vec::remove(0)`
  /// is O(n²) on large fan-outs. This is O(1) state per record, O(n) total work,
  /// and never allocates.
  pub(crate) answer_query_cursor: Option<usize>,
  /// cursor for fanning out KnownAnswer / ProbeConflict /
  /// HostConflict events across multiple registered services that all
  /// match the same answer record (e.g. several services sharing a
  /// `service_type` for a PTR known-answer hint, or multiple services
  /// sharing a host name).  Same shape as `answer_query_cursor`:
  /// `None` = haven't started service-side fan-out for this record;
  /// `Some(k)` = resume scan from slab key `k`.  Reset to `None` when
  /// `answer_idx` advances.
  ///
  /// The scan may not stop at the first matching service: the one that owns a
  /// PTR known-answer — and so holds the rdata that would suppress — need not be
  /// the first to match, and an unrelated first match ignores the hint on rdata
  /// mismatch, losing it.
  pub(crate) answer_service_cursor: Option<usize>,
  /// whether the answer-record service-phase fan-out is COMPLETE for
  /// the current `answer_idx`. `answer_service_cursor` alone is ambiguous
  /// (`None` means both "not started" and "exhausted"), so after a query event
  /// returns mid-record, re-entry would re-scan services and replay conflict
  /// events. This flag gates the service phase; it is reset only when
  /// `answer_idx` advances.
  pub(crate) answer_service_done: bool,
  /// cursor for fanning out authority-section conflict events
  /// (ProbeConflict / HostConflict) across multiple services that
  /// share a host name.  `None` = haven't started fan-out for the
  /// current authority record; `Some(k)` = resume scan from slab key
  /// `k`.  Same shape as the other answer/question cursors.
  ///
  /// Breaking on the first match and advancing `authority_idx` would deliver a
  /// peer probe for a shared host name to only one of the services sharing that
  /// host; the rest would never see the HostConflict.
  pub(crate) authority_service_cursor: Option<usize>,
  /// index into the ADDITIONAL section, plus the
  /// service-conflict and query fan-out cursors for the current additional
  /// record (same shape as the answer-section cursors). DNS-SD responders carry
  /// SRV/TXT/A/AAAA — and the §6.1 instance NSEC — here, so QR=1 additionals run
  /// conflict detection (any type at the instance name → ProbeConflict, host
  /// A/AAAA → HostConflict) AND query fan-out — but never KAS (additionals are
  /// not known-answer hints).
  pub(crate) additional_idx: u16,
  pub(crate) additional_service_cursor: Option<usize>,
  /// like `answer_service_done`, marks the additional-record
  /// service-phase fan-out complete for the current `additional_idx` so a query
  /// event mid-record cannot cause the conflict events to replay on re-entry.
  pub(crate) additional_service_done: bool,
  pub(crate) additional_query_cursor: Option<usize>,
  /// What this datagram is permitted to do, decided once in `Endpoint::handle`
  /// and consulted per ARM below rather than at the iterator's mouth.
  ///
  /// A whole-iterator gate can only answer all-or-nothing, and that is what made
  /// a datagram this endpoint half-believed it had sent itself delete an RFC 6762
  /// §8.2 proposal along with everything else. Gating each arm is what lets one
  /// permission be denied while another stands — but it is also the shape that
  /// resurrects the replay bugs the cursors and `*_service_done` latches above
  /// exist for, so every gate below takes one of exactly two shapes already
  /// present in this iterator:
  ///
  /// * a WHOLE-SECTION skip that advances `section` and touches no cursor —
  ///   the same shape as the source-port gates on Authority and
  ///   AuthorityProposals; or
  /// * a gate INSIDE one phase of a record, which lets that phase reach its
  ///   own "exhausted" exit, so a denied phase latches `*_service_done` exactly
  ///   as an empty one does and the per-record advance stays the single place
  ///   the cursors are reset.
  ///
  /// No gate skips a record, and none leaves a cursor in a state re-entry can
  /// read differently from the pass that set it.
  pub(crate) admits: Admits,
  pub(crate) section: Section,
  /// The relinquished-history screen's answer for ONE section record, kept so
  /// the service fan-out cannot re-derive it per candidate service.
  ///
  /// # Why it has to be cached rather than merely cheap
  ///
  /// `Endpoint::relinquished_asserts` is a WHOLE-RECORD answer — it depends on
  /// the record, this endpoint's own history, the arriving family and the
  /// SECTION the record arrived in, never on which route the fan-out is
  /// visiting — but the helper that consults it is
  /// re-entered after EVERY yielded match, because the cursor model returns one
  /// event per `next()`. So a record matching `S` services ran the same scan
  /// `S + 1` times, and each scan walks the withdrawal map plus up to
  /// `MAX_RELINQUISHED_RRSETS` exact rows and `MAX_RELINQUISHED_IDENTITIES`
  /// compact identities. Multiplied by the records in one datagram, a hostile
  /// packet bought `records × services × history` receive-side work for its
  /// sender's `records` bytes.
  ///
  /// # The key IS the invalidation
  ///
  /// A [`RecordSlot`] names the section and the index within it, so a read for
  /// any other record — the next one, one in a later section, or one reached
  /// again after a parse error changed `section` — misses and recomputes. There
  /// is no reset to forget at a record-advance site, and no cursor path that can
  /// leave a stale answer readable.
  ///
  /// The key having a SECTION in it is now load-bearing twice over: the screen's
  /// answer depends on the arriving section, and it is read off this same slot
  /// (see [`RecordSlot::section`]), so the cached answer and the input that
  /// produced it cannot describe different sections.
  ///
  /// Nothing can mutate the history UNDER the cache while the iterator lives:
  /// [`RouteEvents`] holds the endpoint mutably for the whole iteration, and
  /// `next` only ever READS `endpoint.services`, `endpoint.queries` and the
  /// screen. The three lists the screen consults are written by
  /// `retain_relinquished`, `sweep_relinquished` and the withdrawal lifecycle,
  /// none of which this iterator can reach. `now` is likewise fixed for the
  /// datagram — see the field.
  pub(crate) relinquished_screen: Option<(RecordSlot, ConflictHistory)>,
}

/// Which section record the conflict fan-out is currently visiting.
///
/// The cache key for [`RouteEvents::relinquished_screen`], and stated as a value
/// rather than derived from `self.section` so a call site that is wrong about
/// which record it holds cannot silently share another record's answer.
#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum RecordSlot {
  Answer(u16),
  Authority(u16),
  Additional(u16),
}

impl RecordSlot {
  /// The SECTION half of this slot, stripped of the index — what the
  /// relinquished-history screen weighs against the section this crate's
  /// encoders actually wrote that rrtype in.
  ///
  /// It is read off the slot rather than off `self.section` for the reason the
  /// slot exists at all: `section` is the ITERATOR's phase and moves ahead of
  /// the record being fanned out, while a slot is the caller's statement about
  /// the record in hand. The cache key and the screen's input are then the same
  /// value, so a record can never be answered for under another's section.
  const fn section(self) -> crate::service::RecordSection {
    match self {
      Self::Answer(_) => crate::service::RecordSection::Answer,
      Self::Authority(_) => crate::service::RecordSection::Authority,
      Self::Additional(_) => crate::service::RecordSection::Additional,
    }
  }
}

#[derive(Copy, Clone)]
pub(crate) enum Section {
  Questions,
  Answers,
  /// QR=0 only: one whole §8.2 proposal per matching service, before the
  /// per-record authority fan-out below.
  AuthorityProposals,
  Authority,
  Additional,
  Done,
}

impl<'a, I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS>
  RouteEvents<'a, '_, I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS>
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
  /// Does this datagram's Authority Section carry at least one record proposing
  /// something about `name`? A §8.2 proposal is only worth delivering if it
  /// proposes something about a name we own.
  ///
  /// # Every type, because the probe asks ANY
  ///
  /// EVERY positive-TTL IN record at the name counts, not just SRV/TXT. The
  /// uniqueness question a probe asks is type ANY, so the peer's proposed list —
  /// the one §8.2.1 sorts against ours — is everything it puts at that name.
  /// Filtering to SRV/TXT here makes a peer proposing only an AAAA invisible:
  /// that peer folds our SRV/TXT into its own comparison, finds its AAAA sorts
  /// later, and continues as the winner, while this endpoint receives no
  /// `ProbeProposal` at all and also continues. Two conforming peers, one name,
  /// and duplicate ownership — the outcome the whole mechanism exists to
  /// prevent, invisible unless the peer proposes a type we do not.
  ///
  /// A narrowing survives only where it is actually the rule: RFC 6762 §9's
  /// post-establishment conflict, which `Service` applies to exactly the records
  /// it is authoritative for at that name — asked of its own canonical rdata
  /// forms rather than of a list of rrtypes.
  ///
  /// # …but only what the query ASKS about
  ///
  /// §8.1 defines a probe as a query "with the record name in question in the
  /// Question Section", and §8.2 reads the proposal off "the Authority Section
  /// of *that query*". An Authority Section read without its questions is not a
  /// proposal at all: a QDCOUNT=0 packet, or one asking about an unrelated name,
  /// would trigger §8.2 on any authority record that happens to mention a name
  /// of ours — records it never proposed, and a free one-second deferral on
  /// demand.
  ///
  /// "Asks about" is the QUESTION'S NAME and class, never its QTYPE. §8.2
  /// requires the Authority Section to carry "*all* the records and proposed
  /// rdata being probed for uniqueness", so it is the sender's complete
  /// proposal, and narrowing it by the sender's own QTYPE compares a list that
  /// host never made — see [`question_is_about`].
  ///
  /// # One predicate, one home
  ///
  /// Both halves above are [`ProposalScope`], USED rather than restated —
  /// `service::proposal::adjudicate` scopes the fold with the same type over the
  /// same records, so the two layers cannot answer differently. A second
  /// spelling of the rule is what produces the SRV/TXT defect above: correct one
  /// copy, leave the other, and a peer proposing a type we do not publish goes
  /// unseen by a whole endpoint while it considers itself the winner.
  ///
  /// The invariant that buys — ROUTING OVER-APPROXIMATES VERDICTS: if the fold
  /// would reach `PeerWins` or `WeHold` for a datagram, a `ProbeProposal` was
  /// routed for it. Non-verdicts need not be delivered. Pinned by
  /// `routing_over_approximates_what_the_fold_adjudicates`, which drives
  /// `Endpoint::handle` and `service::proposal::adjudicate` over the SAME
  /// constructed datagrams rather than trusting two spellings to agree.
  ///
  /// # …and it fails CLOSED, unlike [`Self::is_probe_for`]
  ///
  /// Undecodable bytes answer NO here. Nothing is lost by that, because the only
  /// terminal value the fold has for such a datagram is `Verdict::Abandoned`,
  /// and an abandonment is behaviourally identical to `WeHold` — it traces and
  /// changes nothing. So not delivering and delivering-then-abandoning are
  /// indistinguishable to the `Service`, and withholding a whole proposal decides
  /// no more than abandoning it does.
  ///
  /// What it avoids is an amplification primitive. A QR=0, port-5353, QDCOUNT=0
  /// packet carrying one truncated declared authority record would otherwise be
  /// routed as a proposal to EVERY registered service: `AuthorityProposals`
  /// restarts the service iterator on each `next()`, so the fan-out costs Θ(N²)
  /// slab visits, and every pre-authoritative service then allocates and sorts
  /// its own proposal before the fold dies on that same record. Roughly thirty
  /// bytes of spoofable link-local traffic buys all of it.
  ///
  /// `Verdict::Abandoned` being a non-yield is what makes this equivalence hold,
  /// and it is pinned by `an_abandoned_proposal_behaves_exactly_like_we_hold`. If
  /// abandonment ever becomes a yield, this disposition must be revisited.
  fn authority_proposes_for(&self, name: &crate::Name) -> bool {
    // ONE scope for the whole section: the question section decides scope by
    // owner name and class, which does not vary with the record, so it is read
    // at most once here instead of once per authority record.
    let mut scope = ProposalScope::new(|| self.reader.questions(), name);
    for r in self.reader.authority() {
      // A record that will not parse is not a readable proposal for `name`, and
      // `Records` STOPS at its first error — so every record before it has
      // already been tested and nothing readable follows. The section is decided.
      let Ok(r) = r else {
        return false;
      };
      // Exhaustive on purpose: `Admission` has no arm meaning "ours, but skip",
      // so a record admitted here is one the fold folds.
      match scope.admits(&r) {
        Ok(Admission::Ours) => return true,
        Ok(Admission::NotOurs(_)) => continue,
        // Scope is undecidable for the whole datagram, so no later record can
        // answer differently; the fold's only terminal value here is an
        // abandonment, which changes nothing.
        Err(QuestionsUnreadable) => return false,
      }
    }
    false
  }

  /// Is this datagram a probe for `name` — a query actually PROPOSING to take
  /// it, rather than one merely asking about it?
  ///
  /// The RFC 6762 §8.1 defence gate under `answer_questions(false)`. §8.2
  /// defines the probe by what it carries: "each host populates the query
  /// message's Authority Section with the record or records with the rdata that
  /// it would be proposing to use". So the exemption a passive endpoint grants
  /// is owed to a datagram that carries such a record FOR THE QUESTIONED NAME —
  /// not to any datagram that merely declares a nonzero NSCOUNT, and not to a
  /// discovery query that happens to carry an unrelated Authority record. Either
  /// of those would walk a normal query past the suppression boundary that
  /// configuration exists to draw, and out to the service response path.
  ///
  /// [`ProposalScope`] again, so the record this asks for is exactly the record
  /// §8.2 adjudication would fold: owner name and class IN, in the scope of a
  /// question this query asked. The scope's name is the one the question matched,
  /// which is why the gate is per question and service rather than per datagram —
  /// a peer probing our host name proposes nothing about our instance name.
  ///
  /// # …and it OVER-approximates, unlike [`Self::authority_proposes_for`]
  ///
  /// The two gates answer an unreadable Question Section oppositely because what
  /// they release is opposite, and this is the one that must say YES.
  ///
  /// It is not on the verdict path at all. What it releases is a §8.1 DEFENCE of
  /// a name this endpoint has already established — "a host that is not currently
  /// probing … MUST … defend" — against a datagram that is already probe-shaped
  /// at that name in class IN, since `QuestionsUnreadable` is only reachable
  /// after a record has matched `name` in class IN. Failing closed here would let
  /// a prober whose Question Section will not read take an advertised name from a
  /// passive endpoint, purely because the endpoint could not read the section.
  /// §8.1 makes defending a name in use a duty this configuration has not opted
  /// out of.
  ///
  /// The other direction has no such cost: withholding a whole `ProbeProposal`
  /// decides nothing, exactly as abandoning one decides nothing, so the proposal
  /// gate is free to fail closed. A RECORD that will not parse is still NO here —
  /// the exemption is owed to a record that reads, not to a nonzero NSCOUNT.
  fn is_probe_for(&self, name: &crate::Name) -> bool {
    let mut scope = ProposalScope::new(|| self.reader.questions(), name);
    for r in self.reader.authority() {
      // A record that will not parse is not a proposed record. `Records` stops
      // at its first error, so nothing follows it either.
      let Ok(r) = r else {
        return false;
      };
      // `names_match_record` is already false for an owner name that will not
      // decode, but the requirement is stated where it is required: the
      // exemption is owed to a record that is fully readable, not to one whose
      // owner merely might have been ours.
      if !name_fully_decodes(r.name()) {
        continue;
      }
      match scope.admits(&r) {
        // FAIL-OPEN, and deliberately: see above. An undecidable Question
        // Section must not cost an established name its §8.1 defence.
        Ok(Admission::Ours) | Err(QuestionsUnreadable) => return true,
        Ok(Admission::NotOurs(_)) => continue,
      }
    }
    false
  }

  /// The relinquished-history screen for the record at `slot`, run at most ONCE
  /// per section record however many services the fan-out then visits.
  ///
  /// See [`Self::relinquished_screen`] for why the caching is load-bearing
  /// rather than an optimisation, and why the key alone is the invalidation.
  ///
  /// The answer is a [`ConflictHistory`] rather than a decision because the two
  /// consumers spend it differently and only one of them may suppress: see the
  /// note in [`Self::next_service_conflict`].
  fn relinquished_screens(
    &mut self,
    r: &crate::wire::Ref<'_>,
    slot: RecordSlot,
  ) -> ConflictHistory {
    if let Some((cached, answer)) = self.relinquished_screen
      && cached == slot
    {
      return answer;
    }
    let answer = if self.endpoint.relinquished_asserts(
      r,
      self.now,
      crate::transmit::Family::of(self.src),
      slot.section(),
    ) {
      ConflictHistory::Relinquished
    } else {
      ConflictHistory::Unmatched
    };
    self.relinquished_screen = Some((slot, answer));
    #[cfg(test)]
    {
      self.endpoint.history_screens = self.endpoint.history_screens.saturating_add(1);
    }
    answer
  }

  /// Apply one routed [`ServiceEvent`] to the service at route key `key`.
  ///
  /// This is the whole of what replaced `RouteEvent::ToService`. Two properties
  /// follow from doing it HERE rather than handing the event out:
  ///
  /// * `now` is [`Endpoint::handle`]'s own `now` — the datagram's RECEIPT
  ///   instant. RFC 6762 §8.1 counts conflicts by when they occur, and a
  ///   caller-dispatched event occurred whenever the caller got round to it;
  /// * the [`ConflictFlood`] is mutable in the same borrow as the service that
  ///   classifies the conflict, so the count and the classification are one
  ///   step. No acknowledgement can be dropped and no verdict can be stale.
  ///
  /// Every event this datagram raises is folded before the iterator yields
  /// anything, so a timeout that runs afterwards — in either driver order —
  /// reads a history that already includes it.
  fn dispatch(&mut self, key: usize, event: ServiceEvent<'_>) {
    let now = self.now;
    #[cfg(test)]
    if let Some(route) = self.endpoint.services.get(key) {
      let record = super::Dispatched::new(route.handle(), &event);
      self.endpoint.dispatched.push(record);
    }
    // A split borrow: the route holding the `Service` and the endpoint-wide
    // flood history are disjoint fields, so both are live at once without a
    // handoff between them.
    let Endpoint {
      services, flood, ..
    } = &mut *self.endpoint;
    if let Some(route) = services.get_mut(key) {
      route.proto.handle_event(event, now, flood);
    }
  }

  /// The HOST half of the conflict fan-out, for the QR=0 authority path whose
  /// INSTANCE half is delivered whole as a [`ProbeProposal`] instead.
  fn next_host_conflict(
    &mut self,
    r: &crate::wire::Ref<'a>,
    start: usize,
    origin: ConflictOrigin,
    slot: RecordSlot,
  ) -> Option<(usize, ServiceEvent<'a>)> {
    if r.rclass() != ResourceClass::In {
      return None;
    }
    // THE RELINQUISHED-RRSET SCREEN, and this helper builds only `HostConflict`
    // — the one consequence that still SUPPRESSES on a history match rather than
    // being delivered labelled. See the note on the same call in
    // `next_service_conflict` for why the two consequences part company here,
    // and why this call is asked of the family the datagram ARRIVED on.
    if self.relinquished_screens(r, slot).is_relinquished() {
      return None;
    }
    for (key, route) in self.endpoint.services.iter() {
      if key < start {
        continue;
      }
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      if route.withdrawing {
        continue;
      }
      if names_match_record(route.host(), r)
        && is_host_conflict_rtype(r.rtype())
        && route_publishes_host_rtype(route, r.rtype())
      {
        return Some((
          key,
          ServiceEvent::HostConflict(HostConflict::new(*r, origin, self.datagram)),
        ));
      }
    }
    None
  }

  /// The ONE conflict-routing decision for a record `r`, shared by the Answers,
  /// Authority and Additional sections. Scans registered services from slab key
  /// `start` and returns the next `(key, event)`:
  ///   * instance-name match, ANY rrtype → ProbeConflict. §8.1's input is every
  ///     type at a name being probed, so the router routes every type and the
  ///     narrower §9 rule is applied by `Service` on the established side.
  ///     Service-type / shared names are never conflicts;
  ///   * host-name match + A/AAAA → HostConflict.
  ///
  /// Conflicts are only routed for class-IN records — a record with class ANY or
  /// an unknown class is not the same-class RRset RFC 6762 §9 requires, so it
  /// must not drive rename / host-conflict surfacing.
  ///
  /// `origin` is the caller's witness for HOW `r` arrived, and it is a parameter
  /// rather than something inferred here because only the caller knows: this
  /// helper sees one record and cannot tell an Authority-section proposal from
  /// an Answer-section assertion. It rides on the `ProbeConflict` so `Service`
  /// can apply §8.2's tiebreak to a peer's tentative probe and §8.1/§9 to a
  /// peer's response — different rules over different inputs. See
  /// [`ConflictOrigin`].
  fn next_service_conflict(
    &mut self,
    r: &crate::wire::Ref<'a>,
    start: usize,
    origin: ConflictOrigin,
    slot: RecordSlot,
  ) -> Option<(usize, ServiceEvent<'a>)> {
    if r.rclass() != ResourceClass::In {
      return None;
    }
    // THE RELINQUISHED-RRSET SCREEN.
    //
    // RFC 6762 §9's "identical rdata is never a conflict", asked of what this
    // ENDPOINT recently asserted rather than only of what the receiving service
    // still publishes. It is a whole-record answer, so it is taken once here
    // rather than per candidate route.
    //
    // A LABEL FOR THE INSTANCE HALF, A SUPPRESSION FOR THE HOST HALF. A match
    // cannot mean "this was ours" — a §9 fault-tolerance twin publishing
    // identical rdata is indistinguishable from our own ghost at the instant of
    // the lookup, and §9 exists to protect exactly that twin. What a match
    // licenses therefore depends on what the receiver would DO with it:
    //
    //   * A pre-authoritative `ProbeConflict` costs, at most, §8.2's one-second
    //     deferral — and §8.2's own script separates the two cases for us,
    //     because a ghost cannot answer the re-probe and a live incumbent can.
    //     So it is DELIVERED carrying [`ConflictHistory::Relinquished`] and the
    //     service defers instead of renaming. Dropping it here instead lets a
    //     successor probe and announce clean over an incumbent inside the
    //     retention window: a defence that never reaches a service is not merely
    //     delayed, it is unappealable.
    //   * A `HostConflict` is TERMINAL and caller-visible, and nothing in this
    //     crate re-verifies it — the HOST NAME is never probed, so there is no
    //     re-probe whose silence could convict a ghost. It stays suppressed.
    //     Suppressing the EVENT is all that buys, though: where the owner is
    //     also the route's instance name the record is still delivered as a
    //     labelled `ProbeConflict` carrying [`ConflictRole::InstanceAndHost`],
    //     because the instance role is the one being probed and it owes §8.1 an
    //     answer for every type at that name — and because that premise, "the
    //     name is never probed", is FALSE for this owner: `write_probe` asks ANY
    //     for it and proposes exactly these A/AAAA, so §9's reversible same-name
    //     reset has the re-verification the host cell lacks. The role is what
    //     carries the host rule's proven AUTHORITY across the fall-through, so
    //     the established cell can spend it.
    //
    // The router still cannot see lifecycle state and does not need to: it
    // states the fact, and `Service::handle_event` — which knows the phase —
    // decides. NEITHER instance cell drops a labelled record. An ESTABLISHED
    // service spends the label on nothing at all: §9's revert-to-probing runs as it
    // would unlabelled, because dropping it there risked consuming a conforming
    // peer's whole BOUNDED §8.3 announcement burst — at least two responses one
    // second apart, MAY continue to eight with the interval at least doubling each
    // time, then silence until queried — inside the window, and nothing replays a
    // conflict once the window lapses.
    //
    // THE DOUBLING FLOOR BOUNDS HOW MUCH OF THAT BURST THE WINDOW CAN EVER COVER
    // WHOLE. By the fourth response, elapsed time since the first is at least 1 +
    // 2 + 4 = 7 seconds, and no 5-second window that holds the first response can
    // also hold one 7 seconds later — so only a MINIMUM-CONFORMANT burst (two or
    // three responses, near the one-second floor) is ever wholly swallowed. A peer
    // that sends four or more always leaves a later response outside the window.
    //
    // The gap it closes: a withdrawing route stops holding its host name for the
    // registration guard, so a replacement may take host `H` with address set
    // `A2` while the route that held `H` with `A1` is still draining its §10.1
    // goodbye. A delayed positive-TTL echo of `A1` — OUR OWN BYTES — is then
    // adjudicated against `A2` and retires a live service with a TERMINAL
    // `ServiceUpdate::HostConflict`. Service B structurally cannot recognise
    // `A1`; only the endpoint can, which is why the screen is here and not in
    // `Service::handle_event` beside the rule it extends.
    //
    // It is NOT an attempt at RECOGNISING the datagram as our own echo, and no
    // such attempt can be sound — the three independent reasons are in
    // `endpoint::relinquished`: a replaying peer reproduces every signal a
    // driver's send log weighs, one send can be delivered as several copies
    // while a credit is spent once, and recognition state is evicted under
    // traffic while the obligation is per copy. This screen turns on none of
    // that — it reads what this endpoint published and gave up.
    //
    // ASKED OF THIS DATAGRAM'S OWN FAMILY. A multicast datagram travels back
    // over a socket that carried it out, so a record only IPv4 ever transmitted
    // can hold no IPv6 echo — and disowning one would be silencing a GENUINE
    // peer's conflict purely for agreeing with a transmission that family never
    // saw.
    //
    // AND ONCE PER RECORD, not once per candidate service. The answer does not
    // vary with the route, but this helper is re-entered after every match the
    // cursor yields, so an uncached record matching S services would scan the
    // whole history S + 1 times. See `RouteEvents::relinquished_screen`.
    let history = self.relinquished_screens(r, slot);
    for (key, route) in self.endpoint.services.iter() {
      if key < start {
        continue;
      }
      // A withdrawing route's service is being torn down (only its goodbye is still
      // draining) — never route a conflict to it. The route is retained for the
      // name guard, but dispatching ProbeConflict/HostConflict here would feed
      // terminal events into a proto the driver no longer drains (it skips
      // withdrawing/errored contexts), letting a peer flood the proto event slab
      // of a retiring service until GC — a bounded-time but unbounded-size
      // growth path. Mirrors the question-dispatch and known-answer skips.
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      if route.withdrawing {
        continue;
      }
      // HOST first, INSTANCE second, which is only observable when one service's
      // instance and host names are the SAME name. The instance test below does
      // not screen by rtype, so leading with it would swallow an A/AAAA that the
      // host test owns and turn a `HostConflict` into a `ProbeConflict`. Testing
      // the narrower rule first
      // keeps every A/AAAA-at-the-host-name decision the host rule's, and
      // confines the widening to records only the instance test claims.
      //
      // Precedence over the EVENT, never over the CONFLICT. The one case where
      // the host rule matches and still does not consume the record is a
      // history-labelled record at a name that is this route's instance name
      // too — see below.
      //
      // `route_publishes_host_rtype` is the RRSET-OWNERSHIP half of the host
      // rule, and a route that fails it FALLS THROUGH to the instance test
      // rather than being skipped. That is deliberate: the two rules are
      // independent predicates over different names, and when one service's
      // instance name IS its host name a record we hold no host RRset for is
      // still a peer asserting something at a UNIQUE INSTANCE name — §8.1's
      // "any conflicting Multicast DNS response" while probing, and once
      // advertised, screened by the established arm against the records this
      // service is actually authoritative for there. Declining the host rule
      // must not also delete the instance rule's input.
      //
      // WHICH ROLE the record reaches the instance rule UNDER is a separate
      // question from whether it reaches it, and the two fall-throughs answer it
      // oppositely — see [`ConflictRole`]. Declining the host rule leaves the
      // instance role alone to be authoritative; falling through a MATCHED host
      // rule does not.
      let mut role = ConflictRole::Instance;
      if names_match_record(route.host(), r)
        && is_host_conflict_rtype(r.rtype())
        && route_publishes_host_rtype(route, r.rtype())
      {
        if !history.is_relinquished() {
          return Some((
            key,
            ServiceEvent::HostConflict(HostConflict::new(*r, origin, self.datagram)),
          ));
        }
        // THE LABELLED RECORD RAISES NO `HostConflict`: the terminal
        // consequence is the one a history match still suppresses outright.
        //
        // WHAT THE DROP MAY NOT ALSO DO is answer for the INSTANCE role. When
        // this route's instance name IS its host name the record belongs to BOTH
        // roles: A/AAAA under that name are members of the §8.2 proposal this
        // service is probing with, and §8.1's "any conflicting Multicast DNS
        // response" covers every type at a name being probed. Role precedence
        // decides which EVENT a record becomes; it may not decide that the
        // record is no conflict at all. An unconditional `continue` here — the
        // obvious way to stop a suppressed `HostConflict` sliding into the
        // instance arm — discards a live incumbent's defence of a name we are
        // actively probing, and the successor then completes probing and
        // announcing over it: precisely the usurpation the pre-authoritative
        // cell prevents, reached through the other role.
        //
        // So a route wearing both roles for this owner FALLS THROUGH to the
        // instance rule below and takes the labelled `ProbeConflict`. A route
        // with no second role to fall through to is skipped.
        if !names_match_record(route.name(), r) {
          // The suppression stands here, but observably rather than silently.
          // Standing obligation, filed as issue #92 — once host-name ownership
          // gets its own probing and defence, this becomes delivery-labelled,
          // exactly as the instance cells already are.
          warn!(
            target: "mdns_proto::endpoint",
            handle = route.handle().raw(),
            rtype = ?r.rtype(),
            "next_service_conflict: relinquished-history host match dropped — no \
             instance role to fall through to"
          );
          #[cfg(feature = "stats")]
          self.endpoint.stats.relinquished_host_conflicts_suppressed(1);
          continue;
        }
        // AND IT FALLS THROUGH WEARING BOTH ROLES. Suppressing the host
        // CONSEQUENCE does not unprove the host AUTHORITY: this route publishes
        // an RRset of this rrtype at this name, which is §9's "a unique record
        // for which it is currently authoritative" in as many words. Delivering
        // the record as a bare instance-role conflict throws that away, and the
        // ESTABLISHED cell then drops it — `canonical_rdata_forms` names SRV,
        // TXT and NSEC and never an address, so its instance-authority gate
        // answers "we assert no record of this type at this name" for an A/AAAA
        // that we do in fact assert there. The same peer response would then be
        // handled while probing and silently discarded once announced.
        //
        // The host cell's own reason for suppressing does not reach this case.
        // It suppresses because a `HostConflict` is terminal AND the host name
        // is never probed, so nothing can re-verify a labelled record. Here the
        // owner IS being probed — `write_probe` asks ANY for it and proposes
        // exactly these A/AAAA — so the re-verification the host cell lacks
        // already exists, and §9's reversible same-name reset can spend it.
        role = ConflictRole::InstanceAndHost;
      }
      // EVERY type at the instance name, not just SRV/TXT. A probing host owes
      // §8.1 a deferral on "any conflicting Multicast DNS response" for a name
      // it is probing, and the name it is probing is asked about as type ANY —
      // so an existing owner's A, AAAA or NSEC at that name is a response
      // claiming our tentative name just as much as its SRV is. Screening
      // those out here let this service finish probing and announce over a peer
      // that already holds the name.
      //
      // Widening is safe because the narrowing lives where the narrow rule is
      // true: §9's post-establishment arm in `Service::handle_event` asks its
      // OWN canonical rdata forms whether it is authoritative for this type at
      // this name before reverting an ESTABLISHED service to probing, so a type
      // it asserts nothing of — a shared PTR, say — is dropped there. A record
      // it does assert (SRV, TXT, and the §6.1 instance NSEC) is §9's conflict
      // and is adjudicated. What reaches a PRE-authoritative service is §8.1's
      // input, which is every type.
      if names_match_record(route.name(), r) {
        return Some((
          key,
          ServiceEvent::ProbeConflict(ProbeConflict::new(
            self.src,
            *r,
            self.datagram,
            history,
            role,
          )),
        ));
      }
    }
    None
  }
}

impl<'a, I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS> Iterator
  for RouteEvents<'a, '_, I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS>
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
  type Item = Result<RouteEvent<'a>, HandleError>;

  fn next(&mut self) -> Option<Self::Item> {
    // Flush a stashed query event before processing the next record. Service
    // events are never stashed: they are dispatched where they are found, so
    // nothing has to be held back for a later `next()`.
    if let Some(ev) = self.pending_query.take() {
      return Some(Ok(ev));
    }

    loop {
      match self.section {
        Section::Questions => {
          // gate question→service routing on
          // `EndpointConfig::answer_questions`.  When disabled, no
          // `ServiceEvent::Question` events fire at all, so registered
          // services never schedule responses to inbound queries.
          // This is the "advertise but don't respond" / passive mode.
          //
          // ONE exception, and it is not discovery: defending a unique name this
          // endpoint has already claimed. RFC 6762 §8.1 puts that on the
          // responder as a duty — "it is important that when a device receives a
          // probe query for a name that it is currently using, it SHOULD
          // generate its response to defend that name immediately" — and it is
          // the only thing that stops a conforming prober taking an advertised
          // name. Passive mode opts out of ANSWERING QUERIES, not out of owning
          // the names it advertises; without this a peer's probe went unanswered
          // and the peer completed probing and claimed the name.
          //
          // The exemption is drawn as narrowly as the duty: a probe is a QUERY
          // (QR=0) carrying its proposed records in the Authority Section (§8.2
          // requires them there), from a real Multicast DNS peer on port 5353 —
          // an ephemeral-port sender is an off-path artifact, and admitting one
          // would make passive endpoints answer on demand. Only the UNIQUE names
          // are defended below; a probe naming the shared service type is not a
          // uniqueness probe and stays suppressed.
          //
          // What the header says is only the CHEAP half of that, and on its own
          // it is not the rule: a nonzero NSCOUNT is a claim about the datagram,
          // not a proposed record in it. The half that decides is
          // `Self::is_probe_for`, applied per question and service below,
          // against the name the question actually matched. It is split this way
          // so an ordinary datagram — every datagram, on an endpoint that
          // answers nothing — leaves at the header test without either section
          // being walked.
          //
          // TWO independent things reduce a datagram to defence — this
          // endpoint's `answer_questions` configuration, and a datagram whose
          // provenance it half-believes — and they are already folded into ONE
          // value by `Admits`, so this arm reads a single local rather than
          // combining two conditions that could be combined wrongly.
          let defence_only = match self.admits.answering() {
            Answering::All => false,
            Answering::DefenceOnly => true,
            Answering::None => {
              self.section = Section::Answers;
              continue;
            }
          };
          let could_be_a_probe = !self.is_response
            && self.reader.header().authority_count() > 0
            && self.src.port() == crate::constants::MDNS_PORT;
          if defence_only && !could_be_a_probe {
            self.section = Section::Answers;
            continue;
          }
          if self.question_idx >= self.reader.header().question_count() {
            self.section = Section::Answers;
            continue;
          }
          let mut qs = self.reader.questions();
          for _ in 0..self.question_idx {
            let _ = qs.next();
          }
          let q = match qs.next() {
            Some(Ok(q)) => q,
            Some(Err(e)) => {
              // skip the rest of the questions section after a
              // parse error so the iterator terminates instead of
              // looping on the same error indefinitely.
              // parse_errors was already bumped by the upfront section-
              // validation latch in Endpoint::handle — do NOT bump again.
              self.section = Section::Answers;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Answers;
              continue;
            }
          };
          // Walk services starting from the saved cursor, looking for the next
          // match. This allows ALL services sharing the same PTR name to each
          // receive a ServiceEvent::Question for this question before we move on.
          let cursor = self.service_cursor;
          let mut found: Option<(usize, ServiceEvent<'a>)> = None;
          // The §8.1 defence gate's answer for THIS question, taken at most once.
          // Every route reached below matched on a name equal to this question's
          // own QNAME, so the Authority Section proposes for one of them exactly
          // when it proposes for all of them.
          let mut is_a_probe: Option<bool> = None;
          for (key, route) in self.endpoint.services.iter() {
            if key < cursor {
              continue;
            }
            // A withdrawing route's service is gone (only its goodbye is still
            // draining) — never route an incoming question to it, or it could
            // emit a positive-TTL answer contradicting its own TTL=0 goodbye.
            // The route is still present for the name guard, just not answered.
            #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
            if route.withdrawing {
              continue;
            }
            // The UNIQUE names this route owns, and the only ones a §8.1
            // defence covers — which is all `defence_only` mode routes.
            let questioned_unique_name = if names_match(route.name(), q.qname()) {
              Some(route.name())
            } else if names_match(route.host(), q.qname()) {
              Some(route.host())
            } else {
              None
            };
            let unique_name_match = match questioned_unique_name {
              None => false,
              // Answering is enabled, so the question routes on the name alone.
              Some(_) if !defence_only => true,
              // Passive: only a datagram that actually PROPOSES to take this
              // name gets the §8.1 exemption. A discovery query carrying an
              // unrelated Authority record, or one that only declares a nonzero
              // NSCOUNT, is an ordinary query and stays suppressed.
              Some(name) => match is_a_probe {
                Some(known) => known,
                None => {
                  let probe = self.is_probe_for(name);
                  is_a_probe = Some(probe);
                  probe
                }
              },
            };
            if unique_name_match
              || (!defence_only
                && (names_match(route.service_type(), q.qname())
              || route
                .subtypes
                .iter()
                .any(|s| names_match(s, q.qname()))
              // RFC 6763 §9 service-type enumeration: route the meta-query to
              // EVERY service; each answerable (Established/Announcing) one emits
              // its own type PTR, and the cursor below delivers it to each in
              // turn. An earlier per-type dedup (route only the
              // lowest-keyed service of each type) is UNSAFE here — routing has
              // no visibility into Service lifecycle state, so it could pick a
              // probing/non-answering representative and mask an Established
              // same-type sibling, leaving a live type unanswered. Two instances
              // of one type emitting the identical meta-PTR is benign (receivers
              // dedup the identical RR); true per-type dedup would require
              // state-aware, cross-service handling at the driver layer.
              || is_meta_query_name(q.qname())))
            {
              found = Some((
                key,
                ServiceEvent::Question(
                  ServiceQuestion::new(q, self.src, self.reader.header().id())
                    // RFC 6762 §7.2: a TC-bit query spreads its known answers
                    // across multiple packets — the responder delays longer so
                    // the follow-up packets accumulate before it suppresses.
                    .with_truncated(self.reader.header().flags().is_truncated()),
                ),
              ));
              break;
            }
          }
          if let Some((key, ev)) = found {
            // Advance the service cursor past this key so the next call picks up
            // where we left off within the same question.
            self.service_cursor = key.saturating_add(1);
            self.dispatch(key, ev);
            continue;
          }
          // No more matching services for this question: advance to the next
          // question and reset the per-question service cursor.
          self.question_idx = self.question_idx.saturating_add(1);
          self.service_cursor = 0;
          continue;
        }
        Section::Answers => {
          if self.answer_idx >= self.reader.header().answer_count() {
            self.section = Section::AuthorityProposals;
            continue;
          }
          let mut ans = self.reader.answers();
          for _ in 0..self.answer_idx {
            let _ = ans.next();
          }
          let r = match ans.next() {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
              // skip the rest of the answers section after a
              // parse error so the iterator terminates instead of
              // looping on the same error indefinitely.
              // parse_errors was already bumped in the eager walk in
              // Endpoint::handle (which covers answers AND additionals);
              // do NOT bump it here to avoid double-counting.
              self.section = Section::AuthorityProposals;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::AuthorityProposals;
              continue;
            }
          };

          // route-level TTL=0 guard.  Records with TTL=0 are
          // mDNS "goodbye" / deletion signals (RFC 6762 §10.1) — the eager loop
          // in `Endpoint::handle` has already offered them to the cache, and
          // `Query::handle_event` rejects them at the eager-mutation step.  What
          // the cache made of it is conditional (population enabled, name and
          // rdata canonicalizable, a matching entry whose expiry is later than
          // the one-second rescue window), so nothing here may be read as proof
          // that a withdrawal was recorded.  The remaining hazard is the
          // iterator: emitting service events
          // (ProbeConflict / HostConflict / KnownAnswer) for a goodbye
          // would let a peer withdrawing a record trigger our auto-
          // rename or HostConflict surfacing, and emitting ToQuery
          // for a goodbye would let callers receive ghost "answers"
          // from records being withdrawn.  Skip the whole fan-out for
          // TTL=0 — whatever the cache did with it is the only correct
          // side effect.
          if r.ttl() == 0 {
            self.answer_idx = self.answer_idx.saturating_add(1);
            self.answer_service_cursor = None;
            self.answer_service_done = false;
            self.answer_query_cursor = None;
            continue;
          }

          // Service-side fan-out for answer-section records.
          //
          // QR=0: records are KAS hints from another querier.
          //   Emit only KnownAnswer (for KAS suppression on probes).
          //   ProbeConflict / HostConflict are NEVER emitted here —
          //   letting a hostile querier trigger our auto-rename by
          //   mentioning our names in the answer section would be a
          //   trivial denial-of-service vector.
          //
          // QR=1: records are AUTHORITATIVE peer responses.
          //   Per RFC 6762 §8.1, a probing host MUST treat any
          //   response (solicited or unsolicited) claiming one of its
          //   tentative names as a conflict event.  Emit
          //   ProbeConflict for instance-name matches and HostConflict
          //   for host-name matches.  Service-type (shared) matches
          //   are NOT conflicts (multiple services share a type).
          //
          // Authority-section records (Section::Authority) fire
          // ProbeConflict / HostConflict regardless of QR — those are
          // tentative-probe records.
          if !self.answer_service_done {
            let start = self.answer_service_cursor.unwrap_or(0);
            let next_event = if self.is_response {
              // QR=1: ProbeConflict / HostConflict via the shared conflict
              // helper (name + rtype + class gates). Service-type (shared)
              // names are never conflicts. An ANSWER-section record of a
              // response is a peer asserting a name it owns, so it carries
              // `AuthoritativeResponse` — §8.1 and §9's input, never §8.2's.
              if self.admits.adjudication() {
                self.next_service_conflict(
                  &r,
                  start,
                  ConflictOrigin::AuthoritativeResponse,
                  RecordSlot::Answer(self.answer_idx),
                )
              } else {
                None
              }
            } else if !self.admits.quieting() {
              // A known answer is §7.1 QUIETING — it exists to stop this
              // endpoint saying something. Denied, the hint is simply not
              // delivered and the response it would have suppressed still goes
              // out; nothing is lost but a redundant-answer optimisation.
              None
            } else {
              // QR=0: records are KAS hints. ANY name match (instance / host /
              // service-type) emits a KnownAnswer for suppression — conflicts
              // are NEVER routed for QR=0 (a hostile querier mentioning our
              // names must not trigger auto-rename).
              //
              // a QR=0 PTR owned by the DNS-SD service-type enumeration
              // meta name is a known-answer for the §9 meta reply. Its owner is
              // none of our RRset names, so fan it out to EVERY service (mirrors
              // how the meta QUESTION routes to all of them); each
              // service decides whether the PTR target matches its own type.
              let mut found: Option<(usize, ServiceEvent<'a>)> = None;
              for (key, route) in self.endpoint.services.iter() {
                if key < start {
                  continue;
                }
                // A withdrawing route's service is being torn down — never route a
                // known-answer to it either, matching the question-dispatch and
                // conflict skips (no dispatch after retirement).
                #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
                if route.withdrawing {
                  continue;
                }
                if names_match_record(route.name(), &r)
                  || names_match_record(route.host(), &r)
                  || names_match_record(route.service_type(), &r)
                  || is_meta_query_name(r.name())
                {
                  found = Some((key, ServiceEvent::KnownAnswer(KnownAnswer::new(self.src, r))));
                  break;
                }
              }
              found
            };
            if let Some((key, ev)) = next_event {
              self.answer_service_cursor = Some(key.saturating_add(1));
              self.dispatch(key, ev);
              continue;
            }
            // service-side fan-out exhausted for THIS record. Mark
            // it done (not just reset the cursor to None, which is ambiguous
            // with "not started") so a later query event in the same record
            // can't re-enter and replay the conflict/KAS events.
            self.answer_service_done = true;
          }

          // Query-side fan-out (QR=1 only).  emit a
          // ToQuery for every name/type-compatible active query via
          // `answer_query_cursor`.  This already applied the answer
          // to the Query state eagerly in `Endpoint::handle`; the
          // events emitted here are informational only.
          //
          // Informational is exactly why the caller's window is weighed here
          // too: a query past it collected nothing from this record, so
          // announcing it would describe a result the caller cannot find. See
          // the `now` field. The OBSERVATION permission is weighed for the same
          // reason: when it is denied the eager pass in `Endpoint::handle` never
          // ran, so a `ToQuery` here would report a collection that did not
          // happen.
          if self.is_response && self.admits.observation() {
            let now = self.now;
            let start = self.answer_query_cursor.unwrap_or(0);
            let mut found: Option<(usize, RouteEvent<'a>)> = None;
            for (key, q) in self.endpoint.queries.iter() {
              if key < start {
                continue;
              }
              if q.is_done() || q.terminal_emitted() || q.caller_window_shut(now) {
                continue;
              }
              if names_match_record(q.qname(), &r) && qry_query_accepts(q, &r) {
                found = Some((
                  key,
                  RouteEvent::ToQuery(ToQuery::new(q.handle(), QueryEvent::Answer(r))),
                ));
                break;
              }
            }
            if let Some((key, ev)) = found {
              self.answer_query_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
            }
            // Query-side fan-out exhausted for this record.
            self.answer_query_cursor = None;
          }

          // Both phases exhausted — record fully processed.  Advance to the
          // next answer record and reset the per-record fan-out state.
          self.answer_idx = self.answer_idx.saturating_add(1);
          self.answer_service_cursor = None;
          self.answer_service_done = false;
          self.answer_query_cursor = None;
          continue;
        }
        Section::AuthorityProposals => {
          // RFC 6762 §8.2's tiebreak input is a whole query: "it consults the
          // Authority Section of that query", which §8.2 requires to "contain
          // *all* the records and proposed rdata being probed for uniqueness".
          // So the proposal is delivered ONCE per (datagram, service), whole —
          // never record by record, which would make a partial list
          // representable and let a service adjudicate a proposal the peer has
          // not finished making.
          //
          // QR=0 only: an authority record on a QR=1 response is not a
          // proposal, and falls through to the per-record arm below as a
          // response. The source-port gate is the same trust boundary that arm
          // documents — a genuine prober multicasts from 5353.
          if self.is_response || self.src.port() != crate::constants::MDNS_PORT {
            self.section = Section::Authority;
            continue;
          }
          // §8.2's tiebreak is ADJUDICATION, the permission a tier that is
          // unsure keeps: withholding a proposal is what silently leaves two
          // conforming hosts owning one name.
          if !self.admits.adjudication() {
            self.section = Section::Authority;
            continue;
          }
          let start = self.proposal_service_cursor.unwrap_or(0);
          let mut found: Option<(usize, ServiceEvent<'a>)> = None;
          for (key, route) in self.endpoint.services.iter() {
            if key < start {
              continue;
            }
            #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
            if route.withdrawing {
              continue;
            }
            if self.authority_proposes_for(route.name()) {
              found = Some((
                key,
                ServiceEvent::ProbeProposal(ProbeProposal::new(
                  self.src,
                  self.reader,
                  self.datagram,
                )),
              ));
              break;
            }
          }
          if let Some((key, ev)) = found {
            self.proposal_service_cursor = Some(key.saturating_add(1));
            self.dispatch(key, ev);
            continue;
          }
          self.section = Section::Authority;
          continue;
        }
        Section::Authority => {
          // authority-section records are tentative-probe claims
          // (RFC 6762 §8.2) — a peer asserting ownership of a name. Routing
          // them as ProbeConflict / HostConflict forces our service to rename
          // or surfaces a host conflict, so they MUST come from a trusted mDNS
          // peer. A genuine prober sends from UDP source port 5353; an
          // ephemeral-port packet carrying an authority RR for our name is an
          // off-path / forged artifact — a legacy §6.7 querier sends only
          // questions, never authority records. (QR=1 responses from non-5353
          // ports are already fully suppressed upstream; this closes the QR=0
          // query path, where the Question section has ALREADY been routed
          // above so legacy unicast repliers are unaffected.)
          //
          // accounting rule: suppressing conflict routing for a non-5353
          // source is a SECTION-LEVEL suppression — the datagram's other
          // sections (questions, answers, additional) are still processed.
          // This is NOT a whole-datagram reject, so `packets_dropped` is NOT
          // bumped here.  Parse errors in the authority section ARE still
          // counted by the upfront section-validation latch (which walks
          // authority regardless of source port), so malformed bytes are
          // always accounted even when conflict routing is suppressed.
          if self.src.port() != crate::constants::MDNS_PORT {
            self.section = Section::Additional;
            continue;
          }
          // Every event this arm can raise is a conflict, so the whole section is
          // ADJUDICATION. Same accounting as the port gate above: a section-level
          // suppression, not a datagram drop.
          if !self.admits.adjudication() {
            self.section = Section::Additional;
            continue;
          }
          if self.authority_idx >= self.reader.header().authority_count() {
            self.section = Section::Additional;
            continue;
          }
          let mut auth = self.reader.authority();
          for _ in 0..self.authority_idx {
            let _ = auth.next();
          }
          let r = match auth.next() {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
              // skip the rest of the authority section after a
              // parse error so the iterator terminates instead of
              // looping on the same error indefinitely.
              // parse_errors was already bumped by the upfront section-
              // validation latch in Endpoint::handle — do NOT bump again.
              self.section = Section::Done;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Additional;
              continue;
            }
          };

          // route-level TTL=0 guard for the authority section.
          // covered Section::Answers; the same rationale applies
          // here.  A TTL=0 authority record is a goodbye/withdrawal,
          // not a peer claiming the name — emitting ProbeConflict or
          // HostConflict for it would let a withdrawing peer trigger
          // our auto-rename or HostConflict surfacing.
          if r.ttl() == 0 {
            self.authority_idx = self.authority_idx.saturating_add(1);
            self.authority_service_cursor = None;
            continue;
          }

          // Authority records in mDNS probe messages signal a peer claiming the
          // same name — route as ProbeConflict / HostConflict to EVERY matching
          // service (multiple services can share a host) via the shared
          // conflict helper (name + rtype + class gates centralized there).
          //
          // The QR bit is what makes it §8.2's input or not. §8.2 consults "the
          // Authority Section of that QUERY", so only QR=0 carries a tentative
          // proposal. An authority record riding on a QR=1 response is not a
          // proposal at all — it comes from a host that is answering, not
          // probing — so it is classed with the responses.
          //
          // The INSTANCE half of a QR=0 section was already delivered whole by
          // `AuthorityProposals` above, so this fan-out is host-only there. A
          // QR=1 authority record is a response and keeps the full per-record
          // treatment.
          let start = self.authority_service_cursor.unwrap_or(0);
          let slot = RecordSlot::Authority(self.authority_idx);
          let next = if self.is_response {
            self.next_service_conflict(&r, start, ConflictOrigin::AuthoritativeResponse, slot)
          } else {
            self.next_host_conflict(&r, start, ConflictOrigin::TentativeProbe, slot)
          };
          if let Some((key, ev)) = next {
            self.authority_service_cursor = Some(key.saturating_add(1));
            self.dispatch(key, ev);
            continue;
          }
          // No more matching services for this authority record.
          // Advance to the next authority record.
          self.authority_idx = self.authority_idx.saturating_add(1);
          self.authority_service_cursor = None;
          continue;
        }
        Section::Additional => {
          // additional-section records are supplementary ANSWERS
          // (DNS-SD SRV/TXT/A/AAAA accompanying a PTR), NOT questions or probe
          // claims. They fan out to active queries ONLY (QR=1) — never service
          // conflicts/KAS. Cache population + eager query-state update already
          // happened in `Endpoint::handle`; these events are informational.
          if !self.is_response {
            self.section = Section::Done;
            continue;
          }
          if self.additional_idx >= self.reader.header().additional_count() {
            self.section = Section::Done;
            continue;
          }
          let mut add = self.reader.additional();
          for _ in 0..self.additional_idx {
            let _ = add.next();
          }
          let r = match add.next() {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
              // parse_errors was already bumped in the eager walk in
              // Endpoint::handle (which covers answers AND additionals);
              // do NOT bump it here to avoid double-counting.
              self.section = Section::Done;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Done;
              continue;
            }
          };
          // TTL=0 additionals are withdrawals — already offered to the cache
          // eagerly, on the conditional terms noted in the Answer arm; do not
          // surface a ghost conflict/answer.
          if r.ttl() == 0 {
            self.additional_idx = self.additional_idx.saturating_add(1);
            self.additional_service_cursor = None;
            self.additional_service_done = false;
            self.additional_query_cursor = None;
            continue;
          }
          // service-conflict fan-out FIRST. A QR=1 additional record
          // can carry a conflicting SRV/TXT (instance) or A/AAAA (host) for one
          // of our services — DNS-SD responders place these in the Additional
          // section, so missing them here would let duplicate names survive.
          // Same unique-record gates as the Answer/Authority sections;
          // service-type (shared) matches are never conflicts.
          if !self.additional_service_done {
            let start = self.additional_service_cursor.unwrap_or(0);
            // This arm is QR=1 only (the `!self.is_response` guard above
            // returns), so an additional here is a supplementary ANSWER — a
            // peer asserting a name it owns, never a §8.2 proposal.
            let next_event = if self.admits.adjudication() {
              self.next_service_conflict(
                &r,
                start,
                ConflictOrigin::AuthoritativeResponse,
                RecordSlot::Additional(self.additional_idx),
              )
            } else {
              None
            };
            if let Some((key, ev)) = next_event {
              self.additional_service_cursor = Some(key.saturating_add(1));
              self.dispatch(key, ev);
              continue;
            }
            // mark the service phase done for this record so a later
            // query event can't re-enter and replay the conflict events.
            self.additional_service_done = true;
          }
          // Then query fan-out (informational; eager state update already done),
          // on the same terms as the Answer section: DNS-SD carries SRV/TXT/A/AAAA
          // here, so a query past the caller's window would otherwise be told
          // about additionals it refused to collect. Denied OBSERVATION says the
          // same thing more strongly — the eager pass never ran at all.
          if self.admits.observation() {
            let now = self.now;
            let start = self.additional_query_cursor.unwrap_or(0);
            let mut found: Option<(usize, RouteEvent<'a>)> = None;
            for (key, q) in self.endpoint.queries.iter() {
              if key < start {
                continue;
              }
              if q.is_done() || q.terminal_emitted() || q.caller_window_shut(now) {
                continue;
              }
              if names_match_record(q.qname(), &r) && qry_query_accepts(q, &r) {
                found = Some((
                  key,
                  RouteEvent::ToQuery(ToQuery::new(q.handle(), QueryEvent::Answer(r))),
                ));
                break;
              }
            }
            if let Some((key, ev)) = found {
              self.additional_query_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
            }
          }
          // Both fan-outs exhausted for this additional record; advance and
          // reset the per-record fan-out state.
          self.additional_idx = self.additional_idx.saturating_add(1);
          self.additional_service_cursor = None;
          self.additional_service_done = false;
          self.additional_query_cursor = None;
          continue;
        }
        Section::Done => return None,
      }
    }
  }
}

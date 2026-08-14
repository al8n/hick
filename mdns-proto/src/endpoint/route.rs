//! The `RouteEvents` iterator: demuxes one inbound message into routing events.

use super::*;

/// Iterator over routing decisions for a single incoming datagram.
///
/// Borrows the endpoint mutably for the duration of iteration so that
/// `QueryEvent::Answer` events can be applied to the internal
/// [`Query`] state machines as they are yielded —
/// callers do not need to dispatch query events themselves.  Service
/// events still flow to the caller via the yielded [`RouteEvent`]s.
pub struct RouteEvents<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ>
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
  pub(crate) src: SocketAddr,
  pub(crate) endpoint: &'e mut Endpoint<I, R, C, SR, QS, EV, AN, EvQ>,
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
  /// `ProbeConflict` or `KnownAnswer` returns first and the first matching
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
  /// Replaces the unbounded `std::Vec` buffering — that
  /// allocated on the inbound packet path with infallible `push`, which
  /// under allocator pressure aborts/panics instead of surfacing an
  /// error, and used `Vec::remove(0)` for drain (O(n²) on large
  /// fan-outs).  The cursor model is O(1) state per record, O(n) total
  /// work, and never allocates.
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
  /// Previously the service-side scan stopped at the first matching
  /// service, so the actual owning service of a PTR known-answer
  /// (which had the right rdata to suppress) never received the hint —
  /// the unrelated first-matching service got it instead and ignored
  /// it by rdata mismatch.
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
  /// Previously the authority-section loop broke on the first
  /// matching service and advanced `authority_idx`, so a peer probe
  /// for a shared host name reached only one of the services
  /// sharing that host; the rest never received the HostConflict
  /// signal.
  pub(crate) authority_service_cursor: Option<usize>,
  /// When a QUERY-packet answer matches a registered service for both a
  /// ProbeConflict and a KnownAnswer event, we emit ProbeConflict first and
  /// stash the KnownAnswer here for the subsequent call.
  pub(crate) pending_service_event: Option<RouteEvent<'a>>,
  /// index into the ADDITIONAL section, plus the
  /// service-conflict and query fan-out cursors for the current additional
  /// record (same shape as the answer-section cursors). DNS-SD responders carry
  /// SRV/TXT/A/AAAA here, so QR=1 additionals run conflict detection (instance
  /// SRV/TXT → ProbeConflict, host A/AAAA → HostConflict) AND query fan-out —
  /// but never KAS (additionals are not known-answer hints).
  pub(crate) additional_idx: u16,
  pub(crate) additional_service_cursor: Option<usize>,
  /// like `answer_service_done`, marks the additional-record
  /// service-phase fan-out complete for the current `additional_idx` so a query
  /// event mid-record cannot cause the conflict events to replay on re-entry.
  pub(crate) additional_service_done: bool,
  pub(crate) additional_query_cursor: Option<usize>,
  pub(crate) section: Section,
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

impl<'a, I, R, C, SR, QS, EV, AN, EvQ> RouteEvents<'a, '_, I, R, C, SR, QS, EV, AN, EvQ>
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
  /// the ONE conflict-routing decision for a record `r`,
  /// shared by the Answers, Authority, and Additional sections (previously
  /// triplicated). Scans registered services from slab key `start` and returns
  /// the next `(key, event)`:
  ///   * instance-name match + SRV/TXT → ProbeConflict (the instance's unique
  ///     RRset; service-type / shared names are never conflicts);
  ///   * host-name match + A/AAAA → HostConflict.
  ///
  /// `origin` is the caller's witness for HOW `r` arrived, and it is a
  /// parameter rather than something inferred here because only the caller
  /// knows: this helper sees one record and cannot tell an Authority-section
  /// proposal from an Answer-section assertion. It rides on the `ProbeConflict`
  /// so `Service` can apply §8.2's tiebreak to a peer's tentative probe and
  /// §8.1/§9 to a peer's response — different rules over different inputs. See
  /// [`ConflictOrigin`].
  ///
  /// conflicts are only routed for class-IN records — a record with
  /// class ANY or an unknown class is not the same-class RRset RFC 6762 §9
  /// requires, so it must not drive rename / host-conflict surfacing.
  /// Does this datagram's Authority Section carry at least one record proposing
  /// something about `name`? A §8.2 proposal is only worth delivering if it
  /// proposes something about a name we own.
  ///
  /// # Every type, because the probe asks ANY
  ///
  /// EVERY positive-TTL IN record at the name counts, not just SRV/TXT. The
  /// uniqueness question a probe asks is type ANY, so the peer's proposed list —
  /// the one §8.2.1 sorts against ours — is everything it puts at that name.
  /// Filtering to SRV/TXT here made a peer proposing only an AAAA invisible:
  /// that peer folds our SRV/TXT into its own comparison, finds its AAAA sorts
  /// later, and continues as the winner, while this endpoint receives no
  /// `ProbeProposal` at all and also continues. Two conforming peers, one name,
  /// and duplicate ownership — the outcome the whole mechanism exists to
  /// prevent, invisible unless the peer proposes a type we do not.
  ///
  /// The SRV/TXT restriction survives only where it is actually the rule: RFC
  /// 6762 §9's post-establishment conflict, which `Service` applies to the
  /// unique RRset it is authoritative for.
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
  /// same records, so the two layers cannot answer differently. Spelling the rule
  /// out twice is exactly what produced the SRV/TXT defect: the fold's copy was
  /// corrected and this one was left, and a peer proposing a type we do not
  /// publish went unseen by a whole endpoint while it considered itself the
  /// winner.
  ///
  /// The invariant that buys — ROUTING OVER-APPROXIMATES ADMISSION: if the fold
  /// would reach a verdict or an abandonment for a datagram, a `ProbeProposal`
  /// was routed for it. Pinned by
  /// `routing_over_approximates_what_the_fold_adjudicates`, which drives
  /// `Endpoint::handle` and `Service::handle_event` over the SAME constructed
  /// datagrams rather than trusting two spellings to agree.
  fn authority_proposes_for(&self, name: &crate::Name) -> bool {
    // ONE scope for the whole section: the question section decides scope by
    // owner name and class, which does not vary with the record, so it is read
    // at most once here instead of once per authority record.
    let mut scope = ProposalScope::new(|| self.reader.questions(), name);
    for r in self.reader.authority() {
      // Every undecidable answer is YES here, and that is the whole job of this
      // layer. A record that will not parse, or a question section that will not
      // read, means this datagram MIGHT be a proposal for `name` — and the fold
      // is where a proposal that cannot be read is abandoned. Withholding it
      // would not be caution, it would be deciding the question in the one place
      // that must not decide it.
      //
      // `.flatten()` used to drop an unparseable record silently, and `Records`
      // STOPS at its first error, so a single malformed record hid every record
      // after it — including the one the fold needed to see to abandon on.
      let Ok(r) = r else {
        return true;
      };
      if scope.admits(&r).unwrap_or(true) {
        return true;
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
  /// # …and it fails CLOSED, unlike [`Self::authority_proposes_for`]
  ///
  /// The two gates answer malformed input oppositely because what they release
  /// is opposite. Delivering a `ProbeProposal` that cannot be read costs
  /// nothing — the fold ABANDONS it, reaching no verdict — so that gate must
  /// over-approximate. Releasing a question here produces a RESPONSE from an
  /// endpoint configured not to answer, so undecodable bytes must not buy one.
  ///
  /// A `QuestionsUnreadable` is still answered YES, and only that. It is
  /// reachable only from a record already matched to `name` in class IN, so the
  /// datagram is probe-shaped already, and §8.1 makes defending a name in use a
  /// duty this endpoint has not opted out of.
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
      if scope.admits(&r).unwrap_or(true) {
        return true;
      }
    }
    false
  }

  /// The HOST half of the conflict fan-out, for the QR=0 authority path whose
  /// INSTANCE half is delivered whole as a [`ProbeProposal`] instead.
  fn next_host_conflict(
    &self,
    r: &crate::wire::Ref<'a>,
    start: usize,
    origin: ConflictOrigin,
  ) -> Option<(usize, RouteEvent<'a>)> {
    if r.rclass() != ResourceClass::In {
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
      if names_match_record(route.host(), r) && is_host_conflict_rtype(r.rtype()) {
        return Some((
          key,
          RouteEvent::ToService(ToService::new(
            route.handle(),
            ServiceEvent::HostConflict(HostConflict::new(*r, origin)),
          )),
        ));
      }
    }
    None
  }

  fn next_service_conflict(
    &self,
    r: &crate::wire::Ref<'a>,
    start: usize,
    origin: ConflictOrigin,
  ) -> Option<(usize, RouteEvent<'a>)> {
    if r.rclass() != ResourceClass::In {
      return None;
    }
    for (key, route) in self.endpoint.services.iter() {
      if key < start {
        continue;
      }
      // A withdrawing route's service is being torn down (only its goodbye is still
      // draining) — never route a conflict to it. The route is retained for the
      // name guard, but dispatching ProbeConflict/HostConflict here would feed
      // terminal events into a proto the driver no longer drains (it skips
      // withdrawing/errored contexts), letting a peer flood the proto event slab of
      // a retiring service until GC — a bounded-time but unbounded-size growth path
      //. Mirrors the question-dispatch and known-answer skips.
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      if route.withdrawing {
        continue;
      }
      // HOST first, INSTANCE second — the reverse of the old order, and only
      // observable when one service's instance and host names are the SAME
      // name. The instance test below no longer screens by rtype, so leading
      // with it would swallow an A/AAAA that the host test owns and turn a
      // `HostConflict` into a `ProbeConflict`. Testing the narrower rule first
      // keeps every A/AAAA-at-the-host-name decision byte-identical to before
      // and confines the widening to records only the instance test claims.
      if names_match_record(route.host(), r) && is_host_conflict_rtype(r.rtype()) {
        return Some((
          key,
          RouteEvent::ToService(ToService::new(
            route.handle(),
            ServiceEvent::HostConflict(HostConflict::new(*r, origin)),
          )),
        ));
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
      // true: §9's post-establishment arm in `Service::handle_event` tests
      // SRV/TXT itself before reverting an ESTABLISHED service to probing, so
      // an extra type reaching an established service is dropped there. What
      // reaches a PRE-authoritative one is §8.1's input, which is every type.
      if names_match_record(route.name(), r) {
        return Some((
          key,
          RouteEvent::ToService(ToService::new(
            route.handle(),
            ServiceEvent::ProbeConflict(ProbeConflict::new(self.src, *r, self.datagram)),
          )),
        ));
      }
    }
    None
  }
}

impl<'a, I, R, C, SR, QS, EV, AN, EvQ> Iterator
  for RouteEvents<'a, '_, I, R, C, SR, QS, EV, AN, EvQ>
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
  type Item = Result<RouteEvent<'a>, HandleError>;

  fn next(&mut self) -> Option<Self::Item> {
    // Flush pending stashed events in priority order before processing the
    // next record.  Order: ProbeConflict / KnownAnswer stash (service event)
    // first, then query Answer stash.
    if let Some(ev) = self.pending_service_event.take() {
      return Some(Ok(ev));
    }
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
          let defence_only = !self.endpoint.config.answer_questions();
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
          let mut found: Option<(usize, RouteEvent<'a>)> = None;
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
                RouteEvent::ToService(ToService::new(
                  route.handle(),
                  ServiceEvent::Question(
                    ServiceQuestion::new(q, self.src, self.reader.header().id())
                      // RFC 6762 §7.2: a TC-bit query spreads its known answers
                      // across multiple packets — the responder delays longer so
                      // the follow-up packets accumulate before it suppresses.
                      .with_truncated(self.reader.header().flags().is_truncated()),
                  ),
                )),
              ));
              break;
            }
          }
          if let Some((key, ev)) = found {
            // Advance the service cursor past this key so the next call picks up
            // where we left off within the same question.
            self.service_cursor = key.saturating_add(1);
            return Some(Ok(ev));
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
              self.next_service_conflict(&r, start, ConflictOrigin::AuthoritativeResponse)
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
              let mut found: Option<(usize, RouteEvent<'a>)> = None;
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
                  found = Some((
                    key,
                    RouteEvent::ToService(ToService::new(
                      route.handle(),
                      ServiceEvent::KnownAnswer(KnownAnswer::new(self.src, r)),
                    )),
                  ));
                  break;
                }
              }
              found
            };
            if let Some((key, ev)) = next_event {
              self.answer_service_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
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
          // the `now` field.
          if self.is_response {
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
          let start = self.proposal_service_cursor.unwrap_or(0);
          let mut found: Option<(usize, RouteEvent<'a>)> = None;
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
                RouteEvent::ToService(ToService::new(
                  route.handle(),
                  ServiceEvent::ProbeProposal(ProbeProposal::new(
                    self.src,
                    self.reader,
                    self.datagram,
                  )),
                )),
              ));
              break;
            }
          }
          if let Some((key, ev)) = found {
            self.proposal_service_cursor = Some(key.saturating_add(1));
            return Some(Ok(ev));
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
          let next = if self.is_response {
            self.next_service_conflict(&r, start, ConflictOrigin::AuthoritativeResponse)
          } else {
            self.next_host_conflict(&r, start, ConflictOrigin::TentativeProbe)
          };
          if let Some((key, ev)) = next {
            self.authority_service_cursor = Some(key.saturating_add(1));
            return Some(Ok(ev));
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
            if let Some((key, ev)) =
              self.next_service_conflict(&r, start, ConflictOrigin::AuthoritativeResponse)
            {
              self.additional_service_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
            }
            // mark the service phase done for this record so a later
            // query event can't re-enter and replay the conflict events.
            self.additional_service_done = true;
          }
          // Then query fan-out (informational; eager state update already done),
          // on the same terms as the Answer section: DNS-SD carries SRV/TXT/A/AAAA
          // here, so a query past the caller's window would otherwise be told
          // about additionals it refused to collect.
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

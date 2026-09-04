//! Name-matching + record-type helpers for the endpoint demux.

use super::*;

/// RFC 6763 §9 DNS-SD service-type enumeration (meta-query) name. A browser
/// queries this name (PTR) to discover which service TYPES exist on the link.
pub(crate) const DNS_SD_META_QUERY_NAME: &str = "_services._dns-sd._udp.local.";

/// True if `qname` is the RFC 6763 §9 meta-query name (case-insensitive). A
/// matching question is routed to every registered service so each can answer
/// with a shared PTR `_services._dns-sd._udp.local. -> <its service type>`.
pub(crate) fn is_meta_query_name(qname: &NameRef<'_>) -> bool {
  // Compare against the &'static meta-query name directly — no need to
  // allocate a `Name` (29 bytes, heap-backed) on every routed question.
  names_match_str(DNS_SD_META_QUERY_NAME, qname)
}

pub(crate) fn names_match(stored: &Name, incoming: &NameRef<'_>) -> bool {
  names_match_str(stored.as_str(), incoming)
}

pub(crate) fn names_match_str(stored_str: &str, incoming: &NameRef<'_>) -> bool {
  let stored_trim = match stored_str.strip_suffix('.') {
    Some(s) => s,
    None => stored_str,
  };
  let mut sit = stored_trim.split('.');
  let mut iit = incoming.labels();
  loop {
    match (sit.next(), iit.next()) {
      (None, None) => return true,
      (Some(s), Some(Ok(i))) => {
        if s.len() != i.len() {
          return false;
        }
        for (a, b) in s.bytes().zip(i.iter()) {
          if !a.eq_ignore_ascii_case(b) {
            return false;
          }
        }
      }
      _ => return false,
    }
  }
}

pub(crate) fn names_match_record(stored: &Name, r: &crate::wire::Ref<'_>) -> bool {
  names_match(stored, r.name())
}

/// Does every label of `name` decode?
///
/// [`names_match`] answers `false` for two different facts — "a different name"
/// and "a name I could not read" — because a lazy [`NameRef`] carries an
/// unresolved compression pointer and only reports the cycle, the forward
/// pointer or the truncation when its labels are walked. Anywhere the
/// difference matters (RFC 6762 §8.2, where an out-of-scope record is skipped
/// and an unreadable one must abandon the whole proposal) the caller asks this
/// FIRST and treats `false` as undecodable rather than as out of scope.
pub(crate) fn name_fully_decodes(name: &NameRef<'_>) -> bool {
  name.labels().all(|label| label.is_ok())
}

/// Is question `q` about `name`, in class IN?
///
/// The RFC 6762 §8.2 scoping rule, in ONE place because two layers apply it: the
/// endpoint decides whether a datagram's Authority Section is a proposal for a
/// registered name at all, and `Service` decides which of that section's records
/// are in the proposal it folds. The two ran as independent copies of the
/// SRV/TXT rule once, one was fixed and the other left, and the gap was
/// duplicate ownership between two conforming peers.
///
/// QCLASS is `In`, or the wildcard `Any` (255). The RFC 6762 §5.4
/// unicast-response bit is already stripped by [`QuestionRef::qclass`], so a QU
/// probe — which is what `respond::write_probe` sends — reads as `In` here.
///
/// # QTYPE is deliberately NOT considered
///
/// §8.2: "each host populates the query message's Authority Section with the
/// record or records with the rdata that it would be proposing to use, should
/// its probing be successful", and "for tiebreaking to work correctly in all
/// cases, the Authority Section must contain *all* the records and proposed
/// rdata being probed for uniqueness". The Authority Section is therefore the
/// SENDER'S COMPLETE PROPOSAL — fixed by what that host intends to claim, not by
/// what its Question Section narrows to. §8.2's other phrasing, about records
/// that answer the query, sits inside the section's own stated assumption that
/// the probe asks QTYPE ANY (§8.1); the work it really does is partitioning a
/// MULTI-QUESTION probe's Authority Section per contested name, which the
/// name-and-class match here already does completely.
///
/// A QTYPE gate did not merely over-restrict; it broke the symmetry §8.2 rests
/// on. Our own proposal — `service::proposal::our_proposal` — is not
/// question-scoped: it always lists SRV and TXT, plus A/AAAA when the instance
/// name IS the host name. So against a peer that narrowed its QTYPE the two
/// hosts sorted DIFFERENT PAIRS of lists and both concluded they had won. A peer
/// probing QTYPE=TXT with an Authority Section of `[TXT identical to ours, SRV
/// port 9999]` had only its TXT folded here: element 0 tied, our SRV was the
/// record remaining, and §8.2.1 left us the name. That peer folded our whole
/// type-ANY probe, tied on TXT, and its SRV port 9999 sorted after our 631 — so
/// it kept the name too. Two conforming peers, one name.
pub(crate) fn question_is_about(q: &QuestionRef<'_>, name: &Name) -> bool {
  (q.qclass() == ResourceClass::In || q.qclass() == ResourceClass::Any)
    && names_match(name, q.qname())
}

/// The admission rule's answer for ONE record of a §8.2 Authority Section.
///
/// There is deliberately no arm meaning "ours, but skip" and no arm meaning
/// "ours, but abandon": a readable in-scope record has exactly ONE lawful
/// consumption, the fold. §8.2 makes the Authority Section the sender's COMPLETE
/// proposal — "the Authority Section must contain *all* the records and proposed
/// rdata being probed for uniqueness" — and §8.2.1 adjudicates by comparing that
/// list against ours. A predicate that quietly removes a record from the peer's
/// list therefore does not filter noise; it fabricates a different proposal and
/// decides the name over it.
///
/// # Why removal is a CORRECTNESS failure, not merely an unfair one
///
/// §8.2.1 sorts both lists and compares them pairwise "until a difference is
/// found", awarding the name to "the list with records remaining". Removing an
/// element does not only change the lengths: it changes WHICH elements occupy
/// the compared prefix, so it can flip the verdict in EITHER direction.
///
/// Peer `[a, z]` against our `[b, c]`, with `a < b < c < z`. Compared in full,
/// the first pair is `(a, b)`, `a` sorts earlier, and we hold the name. Drop `a`
/// and the first pair becomes `(z, b)`: `z` sorts later, the peer wins, and we
/// defer a round we lawfully won — then re-probe into the now-established peer's
/// §8.1 defence, which renames us off our own name.
///
/// So "a shorter peer list flatters us" is not the rule. The rule is that a
/// shortened list is a list nobody sent, and adjudicating it is wrong in both
/// directions — which is why every failure abandons the whole proposal (a
/// non-verdict, deciding nothing) instead of skipping the offending record.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Admission {
  /// Structurally part of a DIFFERENT proposal or a different RRset, so leaving
  /// it out cannot shorten the list §8.2.1 compares for this name. Every variant
  /// must name that structural reason; a predicate that cannot claim one does
  /// not belong here.
  NotOurs(NotOurs),
  /// In the peer's proposal for this name. Fold it — there is nothing else to do
  /// with it.
  Ours,
}

/// WHY a record is not in this proposal, as a closed and greppable enum.
///
/// Each variant names a fact about which RRset or which proposal the record
/// belongs to — never a judgement about whether it is worth comparing. That
/// distinction is the whole contract:
///
/// * a record in another CLASS is in another namespace, and §8.2.1's ordering
///   begins with the class;
/// * a record at another OWNER name is a proposal about another name;
/// * a record at our name in a datagram that asks about no such name is not part
///   of a proposal at all, because §8.1 defines the probe as a query carrying
///   "the record name in question in the Question Section" and §8.2 reads the
///   proposal off "the Authority Section of *that query*".
///
/// # Adding a conjunct
///
/// A new screen means a new variant here, and the variant's documentation must
/// defend that the records it excludes belong to SOMEONE ELSE'S proposal. That
/// bar is deliberately hard to clear, and three screens that look reasonable
/// each fail it visibly:
///
/// * a QTYPE screen — the sender's own QTYPE says what it wants ANSWERED; §8.2
///   makes its Authority Section what it CLAIMS, and the two are different
///   sections saying different things. The excluded records are the peer's own.
/// * an RTYPE carve-out (compare only the types we publish) — a probe asks type
///   ANY (§8.1), so every type the peer puts at the contested name is part of
///   its proposal. The excluded records are the peer's own.
/// * a TTL screen — §8.2.1 orders "by class (then type, then rdata)"; the TTL is
///   not compared, and §10.1's TTL-zero goodbye is an encoding for an
///   unsolicited RESPONSE, a different message in a different section. The
///   excluded records are the peer's own.
///
/// Each shortens the peer's list, and by [`Admission`]'s reasoning each could
/// decide the name in either direction over a list the peer never sent.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum NotOurs {
  /// The record's CLASS is not IN. §8.2.1 orders by class first, so a record of
  /// another class is not in the RRset being contended.
  DifferentClass,
  /// The record's OWNER name is not the name being adjudicated.
  DifferentOwner,
  /// No question in this query puts the scope's name in contention, so the
  /// datagram's Authority Section is not a proposal for it — however that
  /// section is filled, and including when QDCOUNT is zero.
  NameOutOfQuestionScope,
}

/// The RFC 6762 §8.2 admission rule for ONE (query, name) pair: which of a
/// query's Authority Section records are in the proposal it makes for `name`.
///
/// THE admission rule, and the only copy of it. Two layers ask this question —
/// `RouteEvents::authority_proposes_for` decides whether a datagram is a
/// proposal for a registered name at all, and `service::proposal::adjudicate`
/// decides which of that section's records are in the list it folds — and each
/// once spelled it out itself. That is not a hypothetical drift channel: the
/// two copies once disagreed about which RTYPES count, the fold was fixed and
/// the router was left, and the result was that a peer proposing a type we do
/// not publish was invisible to a whole endpoint while it considered itself the
/// winner. Duplicate ownership between two conforming peers.
///
/// # Why it is a value and not a function
///
/// Scope is decided by the QUESTION Section, and the question section says the
/// same thing for every record in the datagram: after the QTYPE gate came out,
/// what admission reads off the questions is "does this query ask about `name`,
/// in class IN", which does not vary with the record being tested. Asking it per
/// record re-parsed and fully decoded every question for every authority record.
/// A maximum-size UDP datagram carries roughly 5,400 minimal questions and 2,700
/// minimal records, so a peer could buy ~15 million pair iterations — before any
/// compression-chain work — with one link-local packet, twice over, since the
/// router scans as well as the fold.
///
/// So the walk is hoisted to the pair, not to the caller. A per-caller summary
/// would be the second copy of the rule this type exists to prevent — the exact
/// drift that produced the SRV/TXT defect — whereas binding `questions` and
/// `name` together here keeps one rule with one home and reads the Question
/// Section AT MOST ONCE per (query, name).
///
/// It is memoised rather than computed eagerly in [`Self::new`] so the walk
/// still happens at exactly the moment it happened before: on the first record
/// that passes the owner-and-class gate, and never on a datagram whose authority
/// records are all out of scope. That keeps [`QuestionsUnreadable`] — and both
/// callers' dispositions of it — reachable on precisely the datagrams that
/// reached it before, so the fail-open/fail-closed split below is not widened.
///
/// The conjuncts, each with its own reason:
///
/// * **class IN** — §8.2.1 orders by class, then type, then rdata; a record of
///   another class is not in the same RRset being contended.
/// * **owned by `name`** — the proposal is about the name being adjudicated.
/// * **in the scope of a question this query asked** — §8.2 reads the proposal
///   off "the Authority Section of *that query*" and §8.1 defines the query as
///   one carrying "the record name in question in the Question Section", so a
///   QDCOUNT=0 packet proposes nothing however its Authority Section is filled,
///   and neither does a query asking only about somebody else's name. That scope
///   is NAME AND CLASS, never QTYPE — see [`question_is_about`], which is where
///   the reason lives, since a §8.2 Authority Section is the sender's whole
///   proposal rather than an answer to its own question.
///
/// `questions` is a CLOSURE returning a fresh iterator rather than an iterator,
/// because [`crate::wire::Questions`] is single-pass and the walk must start
/// from the top of the section whenever it is taken.
///
/// # TTL is deliberately NOT considered
///
/// §8.2.1 orders the two lists "by class (then type, then rdata)" — the TTL is
/// not one of the fields compared, and §8.2 requires the Authority Section to
/// carry "*all* the records and proposed rdata being probed for uniqueness". A
/// TTL of zero is §10.1's goodbye encoding for an unsolicited RESPONSE (QR=1),
/// which is a different message in a different section; it says nothing about a
/// QR=0 probe's Authority Section, and this predicate only ever runs on that.
///
/// So a TTL screen here is one more way to SHORTEN the peer's list, and a
/// shortened list is a list the peer never sent — which §8.2.1 can resolve in
/// EITHER direction, never merely in ours (see [`Admission`]). A peer whose
/// proposal held a TTL-zero record sorting after ours compared our complete list
/// and kept the name, while we compared a truncated copy of its list and kept
/// the name too: two conforming peers, one name. Reorder the same fixture so the
/// screened record sorts FIRST and the loss lands on us instead, over a round we
/// had won. That is the same defect a QTYPE screen produced — see
/// [`question_is_about`] — and it has the same shape whatever the screening
/// field is.
///
/// The positive-TTL rule is correct where it governs a record ASSERTED rather
/// than proposed: the §9 post-establishment conflict and the goodbye handling
/// on the QR=1 answer/authority paths keep it, in `RouteEvents::next`.
///
/// # What this does NOT do
///
/// It does not validate the owner NAME's decodability, because its two callers
/// need different things from a failure. `names_match_record` answers `false`
/// both for "a different name" and for "a name I could not read", so the fold
/// checks `name_fully_decodes` FIRST and abandons the whole proposal; the router
/// simply does not deliver. Both reach a NON-VERDICT, and a non-verdict decides
/// nothing either way — which is why the asymmetry is sound. Pinned by
/// `routing_over_approximates_what_the_fold_adjudicates`.
///
/// # The Err case is the answer "I cannot tell"
///
/// It is NOT "no", and it is not per record: a Question Section that will not
/// read leaves admission undecidable for the whole DATAGRAM, which is the honest
/// scope for the fact and the reason it lives in the `Err` channel rather than
/// as an [`Admission`] arm. There is no representable "this record is ours, but
/// skip it".
///
/// The three callers dispose of it differently, because what each RELEASES is
/// different:
///
/// * the FOLD abandons the whole proposal, because a list it could not finish
///   reading is not a list §8.2.1 can sort;
/// * `RouteEvents::authority_proposes_for` treats it as NON-ADMISSION. The fold's
///   terminal value for such a datagram is an abandonment, and abandonment is
///   behaviourally identical to holding the name — so not delivering and
///   delivering-then-abandoning are indistinguishable to a `Service`, while
///   delivering costs a whole-endpoint fan-out per malformed packet;
/// * `RouteEvents::is_probe_for` treats it as YES, and is the ONE fail-open of
///   the three. It sits on no verdict path: it releases a §8.1 DEFENCE of a name
///   already established, from an endpoint configured not to answer, against a
///   datagram already probe-shaped at that name in class IN. Failing closed there
///   would let a prober with an unreadable Question Section take an advertised
///   name.
///
/// Folding all three into a plain "no" — which is what `.flatten()` did here —
/// would also silently make the FOLD adjudicate a datagram carrying a valid
/// admitting question alongside a cyclic one. `.flatten()` over a fallible wire
/// iterator is a fail-OPEN default and this branch has paid for it twice.
pub(crate) struct ProposalScope<'n, F> {
  questions: F,
  name: &'n Name,
  /// The question section's answer, taken at most once: `None` until some record
  /// passes the owner-and-class gate and makes it matter.
  scoped: Option<Result<bool, QuestionsUnreadable>>,
}

impl<'a, 'n, F> ProposalScope<'n, F>
where
  F: Fn() -> crate::wire::Questions<'a>,
{
  pub(crate) const fn new(questions: F, name: &'n Name) -> Self {
    Self {
      questions,
      name,
      scoped: None,
    }
  }

  /// Is `r` in the proposal this query makes for the scope's name?
  ///
  /// Every `Ok` answer is one of [`Admission`]'s two arms, and the negative arm
  /// carries the structural reason it is not this proposal's record. There is no
  /// third answer: a record that is [`Admission::Ours`] is folded.
  pub(crate) fn admits(
    &mut self,
    r: &crate::wire::Ref<'_>,
  ) -> Result<Admission, QuestionsUnreadable> {
    if r.rclass() != ResourceClass::In {
      return Ok(Admission::NotOurs(NotOurs::DifferentClass));
    }
    if !names_match_record(self.name, r) {
      return Ok(Admission::NotOurs(NotOurs::DifferentOwner));
    }
    let scoped = match self.scoped {
      Some(scoped) => scoped,
      None => {
        let scoped = self.read_questions();
        self.scoped = Some(scoped);
        scoped
      }
    };
    Ok(if scoped? {
      Admission::Ours
    } else {
      Admission::NotOurs(NotOurs::NameOutOfQuestionScope)
    })
  }

  /// Does this query ask a question that puts `name` in scope? Read once; every
  /// later record reuses the answer, because nothing about it depends on the
  /// record.
  fn read_questions(&self) -> Result<bool, QuestionsUnreadable> {
    let mut admitted = false;
    // The WHOLE section, never short-circuited on the first admitting question: a
    // malformed question sitting AFTER one that admits still makes the proposal
    // unreadable, and `.any()` would have returned before reaching it.
    for q in (self.questions)() {
      let q = q.map_err(|_| QuestionsUnreadable)?;
      if !name_fully_decodes(q.qname()) {
        return Err(QuestionsUnreadable);
      }
      if question_is_about(&q, self.name) {
        admitted = true;
      }
    }
    Ok(admitted)
  }
}

/// The datagram's Question Section could not be read to the end, so whether it
/// admits a record is UNKNOWN — see [`ProposalScope`] for why that is not the
/// same as "no", and why its callers answer it differently.
///
/// Its scope is the DATAGRAM, not one record, which is why it is an `Err` rather
/// than a [`NotOurs`] variant: nothing about it claims the record belongs to
/// someone else's proposal.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct QuestionsUnreadable;

/// the RR types a host name is authoritative for — the address
/// records (A / AAAA). Only these constitute a host-name conflict; a record of
/// any other type owned by the host name is not a claim on the host's unique
/// RRset and must not trigger a [`HostConflict`].
pub(crate) fn is_host_conflict_rtype(rt: ResourceType) -> bool {
  matches!(rt, ResourceType::A | ResourceType::AAAA)
}

/// Does `route` publish any record of `rt` at its HOST name?
///
/// [`is_host_conflict_rtype`] is the half of the host rule that turns on the
/// RECORD; this is the half that turns on US. RFC 6762 §9's conflict is over "a
/// unique record for which it is currently authoritative … with the same name,
/// **rrtype** and rrclass, but inconsistent rdata", so a route publishing no
/// record of that type at that name is not a party to this record's RRset at
/// all — there is nothing of ours for the peer's rdata to be inconsistent with.
/// It is IRRELEVANT, which is not the same answer as "differing".
///
/// Reading an absent RRtype as differing is what retired a service over an
/// address it never published: an IPv6-only responder received a same-host
/// sibling's A announcement, held no A to compare it against, and surfaced a
/// TERMINAL `ServiceUpdate::HostConflict`. `Service::classify_host_rdata`
/// applies the same rule on the receiving side, and
/// `Endpoint::host_addresses_disagree` applies it at registration; all three are
/// one rule about RRset ownership and must answer alike.
///
/// The CONFIGURED sets are read, not the confirmed-advertised ones — the same
/// choice `host_addresses_disagree` makes, and for the same reason: what a
/// service has advertised so far is a subset of what it may advertise next, and
/// the classifier this gate feeds compares against the configured set too.
pub(crate) fn route_publishes_host_rtype<I, TQ, EvS>(
  route: &ServiceRoute<I, TQ, EvS>,
  rt: ResourceType,
) -> bool {
  match rt {
    ResourceType::A => !route.a_addrs().is_empty(),
    ResourceType::AAAA => !route.aaaa_addrs().is_empty(),
    // Not a host RRtype at all — `is_host_conflict_rtype` is that gate, and this
    // one never decides for a type it does not cover.
    _ => false,
  }
}

// A SECOND SPELLING OF "which types can be ours at the instance name" USED TO
// LIVE HERE, as `is_instance_conflict_rtype` — `matches!(rt, Srv | Txt)`, the
// established-state gate in `Service::handle_event`. It went stale in exactly
// the way a second spelling does: `respond::canonical_rdata_forms` gained an
// NSEC arm when conflict routing widened past SRV/TXT, this list did not, and a
// peer's authoritative cache-flushed NSEC at our instance name with DIFFERENT
// rdata was routed, classified as conflicting, and then discarded solely for
// being an NSEC. An NSEC-only response or additional record left duplicate
// instance-name ownership undetected until unrelated SRV/TXT traffic arrived.
//
// The gate now asks `Service::our_canonical_records_for` — the same function the
// classifier reaches — whether this service asserts ANY form of that type at its
// instance name. Shared PTRs are still excluded, because `canonical_rdata_forms`
// yields no form for them: they are owned by the service-type name.

/// Does `q`'s QTYPE/QCLASS accept the answer record `r`?
///
/// `ResourceType::Any` / `ResourceClass::Any` are wildcards.  Otherwise the
/// answer's rtype/rclass must match the query's exactly.  this
/// promotes type/class filtering from `Query::handle_event` up into the
/// demux so a single answer can fan out to every compatible query (not be
/// lost to the first-by-name match).
pub(crate) fn qry_query_accepts<I, AN, EvQ>(q: &Query<I, AN, EvQ>, r: &crate::wire::Ref<'_>) -> bool
where
  I: Instant,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  let qt = q.qtype();
  let qc = q.qclass();
  let rt_ok = qt == ResourceType::Any || qt == r.rtype();
  // ResourceClass::Any is the wildcard QCLASS value 255 used in mDNS QU
  // queries; accept any answer class against it.  Otherwise the answer's
  // class must equal the query's QCLASS exactly.
  let rc_ok = qc == ResourceClass::Any || qc == r.rclass();
  rt_ok && rc_ok
}

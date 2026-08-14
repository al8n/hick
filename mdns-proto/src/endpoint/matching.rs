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
/// QCLASS is `In`, or the wildcard `Any` (255). The RFC 6762 §5.4
/// unicast-response bit is already stripped by [`QuestionRef::qclass`], so a QU
/// probe — which is what `respond::write_probe` sends — reads as `In` here.
///
/// The QTYPE is deliberately NOT considered: this answers "is this query about
/// our name at all", which is what a caller with no record in hand can ask. See
/// [`question_admits_record`] for the per-record question.
pub(crate) fn question_is_about(q: &QuestionRef<'_>, name: &Name) -> bool {
  (q.qclass() == ResourceClass::In || q.qclass() == ResourceClass::Any)
    && names_match(name, q.qname())
}

/// Does question `q` ask about `name` in a way that admits a record of `rtype`
/// as an answer?
///
/// The RFC 6762 §8.2 scoping rule, in ONE place because two layers apply it: the
/// endpoint decides whether a datagram's Authority Section is a proposal for a
/// registered name at all, and `Service` decides which of that section's records
/// are in the proposal it folds. The two ran as independent copies of the
/// SRV/TXT rule once, one was fixed and the other left, and the gap was
/// duplicate ownership between two conforming peers.
///
/// QTYPE is `Any` — which a conforming probe asks (§8.1), and which puts every
/// type at the name in the proposal — or exactly `rtype`. A query asking a
/// specific type proposes only that type; folding its other authority records
/// would compare a list the peer never made.
///
/// CNAME IS THE ONE TYPE A NARROW QTYPE STILL ADMITS. RFC 1034 §3.6.2 makes a
/// CNAME the answer to a query of ANY type at its owner name — "if a CNAME RR is
/// present at a node, no other data should be present" — so a peer's CNAME
/// answers whatever its probe asked, and §8.2.1's "tiebreaker records answering
/// a given probe question in the Question Section" therefore covers it however
/// narrow that question is.
///
/// The direction of the error is why this is not a nicety. Dropping a record
/// SHORTENS the peer's list, and §8.2.1 gives "the list with records remaining"
/// the win, so every omission decides in our favour. A peer whose proposal is a
/// CNAME went unadmitted here while its own fold — of the type-ANY probe §8.1
/// tells us to send — counted every record we proposed and put its type-5 record
/// after our type-1 A. Both sides then held the name.
pub(crate) fn question_admits_record(
  q: &QuestionRef<'_>,
  name: &Name,
  rtype: ResourceType,
) -> bool {
  question_is_about(q, name)
    && (q.qtype() == ResourceType::Any || q.qtype() == rtype || rtype == ResourceType::Cname)
}

/// Is `r` part of the RFC 6762 §8.2 proposal that this query's Authority Section
/// makes for `name`?
///
/// THE admission rule, and the only copy of it. Two layers ask this question —
/// `RouteEvents::authority_proposes_for` decides whether a datagram is a
/// proposal for a registered name at all, and `service::proposal::adjudicate`
/// decides which of that section's records are in the list it folds — and until
/// now each spelled it out itself. That is not a hypothetical drift channel: the
/// two copies once disagreed about which RTYPES count, the fold was fixed and
/// the router was left, and the result was that a peer proposing a type we do
/// not publish was invisible to a whole endpoint while it considered itself the
/// winner. Duplicate ownership between two conforming peers.
///
/// The conjuncts, each with its own reason:
///
/// * **positive TTL** — a TTL=0 record is a §10.1 goodbye, a withdrawal rather
///   than a claim, so it is not in the proposal at all.
/// * **class IN** — §8.2.1 orders by class, then type, then rdata; a record of
///   another class is not in the same RRset being contended.
/// * **owned by `name`** — the proposal is about the name being adjudicated.
/// * **answers a question this query asked** — §8.2 reads the proposal off "the
///   Authority Section of *that query*" and §8.1 defines the query as one
///   carrying "the record name in question in the Question Section", so a
///   QDCOUNT=0 packet proposes nothing however its Authority Section is filled.
///   Type is honoured too: a conforming probe asks ANY (§8.1) and then every
///   type at the name is proposed, while a query asking a SPECIFIC type proposes
///   only that — plus any CNAME, which answers every QTYPE at its owner name
///   (RFC 1034 §3.6.2). See [`question_admits_record`].
///
/// `questions` is a CLOSURE returning a fresh iterator, not an iterator: this is
/// called once per authority record and the question section must be re-walked
/// for each. The scan is nested rather than reduced to a summary first, which is
/// `O(questions x records)` and deliberately so — a summary of admitted QTYPEs
/// is a SET of `u16`, and any bounded set would make capacity a possible answer
/// to "did the peer propose this", which is the class of defect this path exists
/// to make unrepresentable. Both sections come from ONE link-local datagram
/// whose sections `Endpoint::handle` has already walked, so the product is
/// bounded by that datagram's size, and the inner scan only runs for a record
/// already matched to `name`.
///
/// # What this does NOT do
///
/// It does not validate the owner NAME's decodability, because its two callers
/// need different things from a failure. `names_match_record` answers `false`
/// both for "a different name" and for "a name I could not read", so the fold
/// checks `name_fully_decodes` FIRST and abandons the whole proposal; the router
/// simply does not deliver. Both reach a non-verdict, which is why the
/// asymmetry is sound — see the `routing over-approximates admission` test.
///
/// # The Err case is the answer "I cannot tell"
///
/// It is NOT "no". A question section that will not read leaves admission
/// undecidable, and the two callers owe that fact opposite dispositions, which
/// is precisely why it is returned rather than folded into the `bool`:
///
/// * the ROUTER treats it as YES (`unwrap_or(true)`), because a proposal that
///   might concern us must still reach the fold — that is what lets the fold
///   ABANDON it, and routing must over-approximate admission;
/// * the FOLD treats it as ABANDON, because a list it could not finish reading
///   is not a list §8.2.1 can sort.
///
/// Returning `false` for both — which is what `.flatten()` did here — reads
/// "undecodable" as "not for us" at BOTH layers: the router does not deliver,
/// so the fold never gets to abandon, and a datagram carrying a valid admitting
/// question alongside a cyclic one is simply adjudicated. `.flatten()` over a
/// fallible wire iterator is a fail-OPEN default and this branch has now paid
/// for it twice.
pub(crate) fn proposal_admits<'a, F>(
  r: &crate::wire::Ref<'a>,
  questions: F,
  name: &Name,
) -> Result<bool, QuestionsUnreadable>
where
  F: Fn() -> crate::wire::Questions<'a>,
{
  if r.ttl() == 0 || r.rclass() != ResourceClass::In || !names_match_record(name, r) {
    return Ok(false);
  }
  let mut admitted = false;
  // The WHOLE section, never short-circuited on the first admitting question: a
  // malformed question sitting AFTER one that admits still makes the proposal
  // unreadable, and `.any()` would have returned before reaching it.
  for q in questions() {
    let q = q.map_err(|_| QuestionsUnreadable)?;
    if !name_fully_decodes(q.qname()) {
      return Err(QuestionsUnreadable);
    }
    if question_admits_record(&q, name, r.rtype()) {
      admitted = true;
    }
  }
  Ok(admitted)
}

/// The datagram's Question Section could not be read to the end, so whether it
/// admits a record is UNKNOWN — see [`proposal_admits`] for why that is not the
/// same as "no", and why its two callers answer it differently.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct QuestionsUnreadable;

/// the RR types a host name is authoritative for — the address
/// records (A / AAAA). Only these constitute a host-name conflict; a record of
/// any other type owned by the host name is not a claim on the host's unique
/// RRset and must not trigger a [`HostConflict`].
pub(crate) fn is_host_conflict_rtype(rt: ResourceType) -> bool {
  matches!(rt, ResourceType::A | ResourceType::AAAA)
}

/// the RR types a service INSTANCE name is authoritative for — SRV and TXT (RFC
/// 6763 §4) — and so the scope of RFC 6762 §9's post-establishment conflict:
/// "a Multicast DNS responder has a unique record for which it is currently
/// authoritative, and it receives a ... response ... with the same name, rrtype
/// and rrclass, but inconsistent rdata". SRV and TXT are the records an
/// established instance is authoritative FOR; a record of another type at that
/// name is not one of them, so it cannot make §9's conflict. The PTR that maps a
/// service type to an instance is owned by the SHARED service-type name, not the
/// instance, and is excluded separately.
///
/// §9 ONLY. It is emphatically NOT the scope of §8's PROBING rules: a probe asks
/// type ANY, so every type at the name is part of the proposal §8.2.1 compares
/// and part of the "any conflicting response" §8.1 defers to. Applying this
/// filter to the probing path made a peer proposing a type we do not publish
/// invisible, and two conforming peers both kept the name. See
/// `RouteEvents::authority_proposes_for`.
pub(crate) fn is_instance_conflict_rtype(rt: ResourceType) -> bool {
  matches!(rt, ResourceType::Srv | ResourceType::Txt)
}

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

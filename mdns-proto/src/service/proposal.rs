//! RFC 6762 §8.2 simultaneous-probe tiebreaking: both proposals, the bytes each
//! side is compared over, and the fold that reaches §8.2.1's verdict.
//!
//! # Why this is one module
//!
//! §8.2's comparison only resolves a name if BOTH hosts compute the same
//! function over the same two lists. That makes the two serializers a matched
//! PAIR — [`our_proposal`] for the bytes we transmit, and
//! [`RdataForm::AS_SENT`](crate::wire::RdataForm::AS_SENT) applied to the peer's
//! record for the bytes the peer transmitted — and a pair is only correct
//! together.
//!
//! The peer's side is no longer a serializer of this module's own. There is ONE
//! rdata decoder in this crate — `wire::Ref::write_canonical_rdata` — and the
//! §8.2 form is one of its three [`RdataForm`](crate::wire::RdataForm) settings.
//! That is deliberate: the identity form ("are these two records the same
//! record", used by §7.1 known-answer suppression and the §9 screen) normalises
//! where §8.2 must not, and when the two were separate functions they also
//! disagreed about which records DECODE AT ALL — which is how a malformed record
//! became a §8.1 defeat. A knob may change the bytes; it cannot change whether
//! there are bytes.
//!
//! What stays sealed is the direction that actually went wrong twice: nothing
//! outside this module serializes a record for §8.2, because the only thing this
//! module exports is a finished [`Verdict`]. A caller cannot reach past the
//! verdict and pick a form.

use crate::{records::ServiceRecords, service::respond, wire::RdataForm};

// Under the `alloc` / `no-atomic` tiers (no `std`) this module is `no_std` and
// `std` is `extern crate alloc as std` (see `lib.rs`) — `ToOwned` is not in the
// `core` prelude the way it is in `std`'s, so `&str::to_owned()` below fails to
// resolve without it. `feature = "std"` already has it via the prelude.
#[cfg(all(not(feature = "std"), any(feature = "alloc", feature = "no-atomic")))]
use crate::std::borrow::ToOwned as _;

/// RFC 6762 §8.2.1's answer for ONE peer proposal.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Verdict {
  /// The peer's proposed list sorts later: "the host with the lexicographically
  /// later record set" wins, and this round is lost.
  PeerWins,
  /// Ours sorts later, or the two lists are identical — §8.2.1's "there is, in
  /// fact, no conflict". Either way the probe sequence continues unchanged.
  WeHold,
  /// The Authority Section is not a list §8.2.1 can sort, so it yields NO
  /// verdict at all. Never a silent skip of the offending record: dropping one
  /// shortens the peer's list, and §8.2.1 resolves a shortened list in EITHER
  /// direction — see [`adjudicate`].
  Abandoned(Abandon),
}

/// Why a proposal could not be adjudicated. Carried out to the caller rather
/// than logged here so the trace keeps the service's handle and source address.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Abandon {
  /// The Authority Section stopped parsing partway. §8.2 requires it to "contain
  /// *all* the records and proposed rdata being probed for uniqueness", and a
  /// list we could read only part of is not that list.
  UnparseableAuthority,
  /// A record's OWNER name would not decode. Name matching answers `false` both
  /// for "a different name" and for "a name I could not read", so this is
  /// checked before scope: the unreadable record may have been the one at our
  /// name.
  UndecodableOwnerName,
  /// An in-scope record's rdata would not decode — a bad RDLENGTH, a TXT length
  /// octet that overruns, or an embedded name that will not decompress. ONE
  /// reason, because there is one decoder: `wire::Ref::write_canonical_rdata`
  /// parses and decompresses in a single pass, so "would not parse" and "has no
  /// comparison bytes" are no longer separable answers — which is the point,
  /// since a record that is undecodable here must be undecodable everywhere.
  UndecodableRdata,
  /// The Question Section did not read to the end, so what the query ASKS — and
  /// therefore what its Authority Section proposes — is unknown.
  UnreadableQuestions,
}

/// Adjudicate ONE peer's complete §8.2 proposal against our own.
///
/// The proposal arrives whole — see [`ProbeProposal`](crate::event::ProbeProposal)
/// — so it is compared the moment it arrives and never retained. That is what
/// makes two failures unrepresentable rather than checked for: a partial list
/// cannot be adjudicated because no partial list exists, and a capacity bound
/// cannot become a lexicographic verdict because there is no buffer to bound.
///
/// # The one property
///
/// NO PROPOSAL CONTAINING ANYTHING UNDECODABLE PRODUCES A VERDICT — it abandons.
///
/// That is a single property rather than a list of guards, and it is the TYPE
/// that enforces it: every fallible step of [`fold`] is a `?`, so the only way
/// to reach a `PeerWins` or `WeHold` is for every part of the proposal that had
/// to be read to have read. There is no arm that can quietly `continue` past an
/// error, because a `Result` cannot be ignored.
///
/// It matters which way that fails, and the failure is worse than unfair.
/// Skipping an unreadable record SHORTENS the peer's list, and §8.2.1 does not
/// merely count: it sorts both lists and compares them pairwise "until a
/// difference is found", awarding the name to "the list with records remaining".
/// Removing an element changes WHICH elements meet in that comparison, so it can
/// flip the verdict in EITHER direction.
///
/// [`ProposalFold`] shows it directly: it keeps the peer's `keep` SMALLEST
/// elements and zips them against ours, returning on the first non-`Equal` pair.
/// With the peer proposing `[a, z]` against our `[b, c]`, `a < b < c < z`, the
/// full lists meet as `(a, b)` — `Less`, so we hold. Drop `a` and the surviving
/// `z` is promoted into the compared prefix: `(z, b)` is `Greater`, the peer
/// wins, and we defer a round that was lawfully ours, re-probe into the
/// now-established peer's §8.1 defence, and get renamed off our own name.
///
/// So a skip is not a thumb on the scale in our favour; it is a verdict computed
/// over a list nobody sent, which can hand us a name we did not win and can
/// equally lose us one we did. Every failure therefore abandons the whole
/// proposal, which decides nothing at all.
pub(crate) fn adjudicate(
  pp: &crate::event::ProbeProposal<'_>,
  ours_records: &ServiceRecords,
) -> Verdict {
  match fold(pp, ours_records) {
    Ok(verdict) => verdict,
    Err(why) => Verdict::Abandoned(why),
  }
}

/// The fold proper. Every step that can fail returns through `?`, which is what
/// makes [`adjudicate`]'s property structural rather than reviewed.
fn fold(
  pp: &crate::event::ProbeProposal<'_>,
  ours_records: &ServiceRecords,
) -> Result<Verdict, Abandon> {
  let ours = our_proposal(ours_records);
  let mut fold = ProposalFold::new(ours.len());
  // ONE scope for the whole proposal. What the Question Section decides — is
  // this name in scope, in class IN — is the same for every record of the
  // datagram, so it is read at most once instead of once per authority record.
  let mut scope = crate::endpoint::ProposalScope::new(|| pp.questions(), ours_records.instance());
  for r in pp.authority() {
    let r = r.map_err(|_| Abandon::UnparseableAuthority)?;
    // OWNER NAME FIRST, before any filter that could read a decode failure as an
    // answer. `names_match_record` returns false BOTH for "a different name" and
    // for "a name that would not decode" — and `Ref` parsing accepts a
    // compression pointer without ever resolving it, so a cyclic or truncated
    // owner name reaches here looking exactly like an out-of-scope record.
    // Adjudicating the readable subset is adjudicating a list the peer did not
    // make: the unreadable record may have been the one at OUR name. So the name
    // is fully decoded first and any error abandons the whole proposal —
    // including on records owned by names that are not ours, because whose name
    // it is, is exactly what could not be read.
    if !crate::endpoint::name_fully_decodes(r.name()) {
      return Err(Abandon::UndecodableOwnerName);
    }
    // Scope: EXACTLY the endpoint's admission rule, used rather than restated.
    // See [`crate::endpoint::Admission`] — the two layers held independent copies
    // of this once and one of them went stale, which is how a peer proposing a
    // type we do not publish became invisible to a whole endpoint.
    //
    // Its `Err` is "I cannot tell whether this is admitted", and here that
    // abandons. `Admission` has no arm meaning "ours, but skip", which is why the
    // match below has only the two arms it has: an in-scope readable record is
    // folded, and everything unreadable leaves through a `?`.
    //
    // TWO DIFFERENT MALFORMED-QUESTION CASES, and they fail closed by different
    // routes. A question section that will not PARSE leaves the authority section
    // unlocatable — locating it means skipping the questions — so `pp.authority()`
    // yields nothing and this loop never runs; that is pinned by
    // `an_unparseable_question_section_surfaces_no_authority_records`. A question
    // whose QNAME is an unresolvable POINTER does not do that: `try_parse`
    // consumes the two pointer bytes without following them, so the section
    // parses and the records ARE surfaced. That case is caught here, by
    // admission decoding every QNAME in full.
    match scope.admits(&r).map_err(|_| Abandon::UnreadableQuestions)? {
      // Structurally another proposal's record or another RRset's, so leaving it
      // out cannot shorten the list §8.2.1 compares for our name.
      crate::endpoint::Admission::NotOurs(_) => continue,
      crate::endpoint::Admission::Ours => {
        // §8.2's ordering key: class, then type, then rdata. Class is invariant
        // (only IN is admitted above), so type then the peer's own bytes.
        //
        // In scope but not decodable: same abandonment, same reason. Skipping it
        // would silently shorten the very list being compared.
        let mut elem = std::vec::Vec::new();
        elem.extend_from_slice(&r.rtype().to_u16().to_be_bytes());
        r.write_canonical_rdata(RdataForm::AS_SENT, &mut elem)
          .map_err(|_| Abandon::UndecodableRdata)?;
        fold.offer(elem);
      }
    }
  }
  Ok(if fold.peer_wins(&ours) {
    Verdict::PeerWins
  } else {
    Verdict::WeHold
  })
}

/// Our own RFC 6762 §8.2 proposal, sorted: the records this service would claim
/// for its instance name.
///
/// SRV and TXT, because those are exactly what `write_probe` puts in the
/// Authority Section under the instance name. A/AAAA belong to the HOST name, so
/// they are normally neither proposed here nor compared — see the branch below
/// for the configuration where they are. The peer's side is not limited this
/// way: §8.2 makes ITS Authority Section its complete proposal, so every record
/// it puts at the contested name counts for it; see [`adjudicate`].
///
/// # These bytes must be the bytes we TRANSMIT
///
/// §8.2's comparison only resolves a name if both hosts compute the same
/// function over the same two lists, and the peer compares against what we
/// actually sent. So this side deliberately LOWERCASES the SRV target and
/// renders an empty TXT as a single zero-length string — not because §8.2 wants
/// normalisation (it does not — see
/// [`RdataForm::AS_SENT`](crate::wire::RdataForm::AS_SENT), the peer side, which
/// normalises nothing) but because that is precisely what
/// [`crate::wire::MessageBuilder`] emits for us: `write_name` lowercases, and
/// `push_txt_authority` writes one zero-length string for an empty TXT.
///
/// LOAD-BEARING COUPLING, and it is not local: the correctness of this function
/// depends on `MessageBuilder::write_name` lowercasing on transmit. That is
/// otherwise an unrelated builder detail. If transmission stops lowercasing,
/// THIS must stop lowercasing in the same change, or our comparison bytes and
/// our wire bytes diverge and the tiebreak stops being symmetric with every peer.
fn our_proposal(our: &ServiceRecords) -> std::vec::Vec<std::vec::Vec<u8>> {
  let mut set: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
  // SRV — priority(2 BE) + weight(2 BE) + port(2 BE) + wire-form target name.
  {
    let mut buf = std::vec::Vec::new();
    buf.extend_from_slice(&crate::wire::ResourceType::Srv.to_u16().to_be_bytes());
    buf.extend_from_slice(&our.priority().to_be_bytes());
    buf.extend_from_slice(&our.weight().to_be_bytes());
    buf.extend_from_slice(&our.port().to_be_bytes());
    write_canonical_wire_name(our.host().as_str(), &mut buf);
    set.push(buf);
  }
  // TXT — always, because `write_probe` emits one unconditionally. Omitting an
  // empty TXT here would compare a list we never proposed; an empty TXT
  // canonicalizes to the rtype prefix plus one zero-length string, so both sides
  // agree byte-for-byte.
  {
    let mut buf = std::vec::Vec::new();
    buf.extend_from_slice(&crate::wire::ResourceType::Txt.to_u16().to_be_bytes());
    respond::write_canonical_txt(our.txt_segments(), &mut buf);
    set.push(buf);
  }
  // A/AAAA — but ONLY when the host name IS the instance name, because then
  // `write_probe`'s address records are emitted under the contested owner too.
  //
  // THE SHARED CONDITION, and it is not spelled the same way on both sides:
  // `respond::write_probe` pushes its A and AAAA records under
  // `records.host()`, unconditionally — they land under the name being probed
  // exactly when `instance == host`, which is the condition this branch tests
  // directly. The two are one fact written twice, so a change to either side
  // alone (a probe that stops emitting addresses, or emits them under the
  // instance name always) silently desymmetrises §8.2: our comparison list would
  // stop matching the records a peer folds off our wire bytes, and neither side
  // would fail loudly. Change them together.
  //
  // Normally the host is a separate name, its addresses answer a different
  // question, and they are neither proposed nor compared. `instance == host` is
  // a supported configuration, though, and there the two sides were computing
  // different functions: the peer fold admits EVERY record answering the
  // instance's ANY question, so it counted our addresses, while this list held
  // only SRV and TXT. With identical A records — which sort before TXT — two
  // peers whose SRV differ each saw the other's list as sorting earlier, BOTH
  // returned `WeHold`, and both announced.
  //
  // §8.2's comparison only resolves a name if both hosts compute the same
  // function over the same two lists, so what goes in this list is decided by
  // what `write_probe` puts on the wire under this owner — not by a fixed
  // "SRV and TXT" that was only ever true of the common configuration.
  if names_equal_ignoring_case(our.instance().as_str(), our.host().as_str()) {
    for a in our.a_addrs_slice() {
      let mut buf = std::vec::Vec::new();
      buf.extend_from_slice(&crate::wire::ResourceType::A.to_u16().to_be_bytes());
      buf.extend_from_slice(&a.octets());
      set.push(buf);
    }
    for a in our.aaaa_addrs_slice() {
      let mut buf = std::vec::Vec::new();
      buf.extend_from_slice(&crate::wire::ResourceType::AAAA.to_u16().to_be_bytes());
      buf.extend_from_slice(&a.octets());
      set.push(buf);
    }
  }
  set.sort();
  set
}

/// Are these two owner names the same name? DNS names are case-insensitive
/// (RFC 6762 §16) and a trailing root dot is not part of the name.
pub(crate) fn names_equal_ignoring_case(a: &str, b: &str) -> bool {
  let trim = |s: &str| s.strip_suffix('.').unwrap_or(s).to_owned();
  trim(a).eq_ignore_ascii_case(&trim(b))
}

/// Write a DNS name in canonical wire form (length-prefixed labels, root
/// terminator), lowercased — OUR side's encoding, matching what
/// `MessageBuilder::write_name` puts on the wire.
pub(crate) fn write_canonical_wire_name(name_str: &str, out: &mut std::vec::Vec<u8>) {
  let trimmed = match name_str.strip_suffix('.') {
    Some(t) => t,
    None => name_str,
  };
  if trimmed.is_empty() {
    out.push(0);
    return;
  }
  for label in trimmed.split('.') {
    if label.is_empty() {
      continue;
    }
    let len = label.len().min(63);
    #[allow(clippy::cast_possible_truncation)]
    out.push(len as u8);
    for &b in label.as_bytes().iter().take(63) {
      out.push(b.to_ascii_lowercase());
    }
  }
  out.push(0); // root terminator
}

/// Folds ONE peer proposal into an RFC 6762 §8.2.1 verdict without ever holding
/// the proposal.
///
/// §8.2.1 sorts both lists and compares them pairwise "until a difference is
/// found"; if one runs out first "the list with records remaining is deemed to
/// have won", and if both run out together there is no conflict. Against a local
/// list of `keep` records that needs only the peer's `keep` SMALLEST elements and
/// its TOTAL count — everything past the local list's length can only matter as
/// "the peer has more", which the count already says.
///
/// So the peer's proposal is streamed, never buffered. There is no per-round
/// proposal cap and no per-proposal record cap to exhaust, which is what makes
/// "capacity exhaustion read as a lexicographic loss" unrepresentable rather than
/// guarded against: a bound on our memory is a fact about us, and it can no
/// longer become a claim about the wire.
///
/// `keep` is taken from THE LOCAL LIST, never from a constant. It bounds only
/// what we retain of the peer's list; the peer's list itself is unbounded,
/// because §8.2 makes its Authority Section the peer's COMPLETE proposal and
/// that may carry any number of records at the contested name.
/// That asymmetry is the point: `keep` smallest plus a total `count` is
/// everything §8.2.1 needs however long the peer's proposal is, since anything
/// sorting past the local list's length can only matter as "the peer has more",
/// which `count` already answers.
///
/// DUPLICATES ARE NOT REMOVED. §8.2.1 says sort and compare; it does not say
/// deduplicate, and the comparison only resolves a name if BOTH hosts compute the
/// same function over the same two lists. A peer that repeats a record and a
/// responder that silently drops the repeat reach different verdicts about the
/// same pair of lists, and "both sides think they won" is the one outcome §8.2
/// exists to prevent. Comparing what the peer actually sent is what keeps the two
/// sides symmetric.
struct ProposalFold {
  /// The `keep` smallest peer elements seen so far, ascending.
  smallest: std::vec::Vec<std::vec::Vec<u8>>,
  /// Every element seen, including any beyond `keep` and any repeated.
  count: usize,
  keep: usize,
}

impl ProposalFold {
  fn new(keep: usize) -> Self {
    Self {
      smallest: std::vec::Vec::new(),
      count: 0,
      keep,
    }
  }

  /// Offer one canonical element (`rtype` big-endian, then canonical rdata).
  fn offer(&mut self, elem: std::vec::Vec<u8>) {
    self.count = self.count.saturating_add(1);
    let at = self.smallest.partition_point(|e| e <= &elem);
    // Only the `keep` smallest can matter: anything sorting past them lies
    // beyond the local list's length, where §8.2.1 asks only whether the peer
    // has MORE records — which `count` already answers. `at <= len`, so when the
    // buffer is short of `keep` this branch always takes it.
    if at < self.keep {
      self.smallest.insert(at, elem);
      self.smallest.truncate(self.keep);
    }
  }

  /// §8.2.1's verdict: did this peer's proposal beat `our` sorted list?
  fn peer_wins(&self, our: &[std::vec::Vec<u8>]) -> bool {
    debug_assert_eq!(
      self.keep,
      our.len(),
      "the fold retains exactly as many elements as the local list it will be \
       compared against; a mismatch silently truncates the comparison"
    );
    for (peer_elem, our_elem) in self.smallest.iter().zip(our.iter()) {
      match peer_elem.cmp(our_elem) {
        core::cmp::Ordering::Equal => {}
        other => return other == core::cmp::Ordering::Greater,
      }
    }
    // Equal on every record both lists have: the longer list wins, and equal
    // lengths are §8.2.1's "there is, in fact, no conflict".
    self.count > our.len()
  }
}

/// TEST-ONLY window onto the §8.2 form, for fixtures that pin the compared
/// bytes against enumerated literals.
///
/// The seal this module exists for is against PRODUCTION code: outside here,
/// nothing chooses an [`RdataForm`] for §8.2, so nothing can pick the
/// normalising one by mistake — the failure that silently broke the tiebreak
/// twice. A `#[cfg(test)]` accessor does not weaken that; it is unreachable from
/// any shipped path. It exists because the byte-level fixtures in
/// `service::tests` assert what a peer's records COMPARE AS, and a fixture that
/// re-derived those bytes itself would be asserting its own arithmetic rather
/// than the decoder's.
// The only consumer is `service::tests`, which is gated on `std` + `slab`; under
// a `cargo hack --each-feature` leg such as `--no-default-features --features
// alloc` this module still compiles for test but that consumer does not exist.
#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn tiebreak_bytes_for_fixture(
  record: &crate::wire::Ref<'_>,
  out: &mut std::vec::Vec<u8>,
) -> Result<(), crate::error::ParseError> {
  out.clear();
  record.write_canonical_rdata(RdataForm::AS_SENT, out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests;

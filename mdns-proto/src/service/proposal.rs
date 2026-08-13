//! RFC 6762 §8.2 simultaneous-probe tiebreaking: both proposals, the bytes each
//! side is compared over, and the fold that reaches §8.2.1's verdict.
//!
//! # Why this is one module
//!
//! §8.2's comparison only resolves a name if BOTH hosts compute the same
//! function over the same two lists. That makes the two serializers a matched
//! PAIR — [`our_proposal`] for the bytes we transmit, [`rdata_for_tiebreak`] for
//! the bytes the peer transmitted — and a pair is only correct together.
//!
//! There is a second serializer in this crate that answers a DIFFERENT question:
//! `respond::rdata_for_identity`, "are these two records the same record", which
//! normalises (lowercased SRV target, empty TXT rewritten). It agrees with the
//! tiebreak form on every all-lowercase name and every non-empty TXT, so calling
//! it here compiles, passes most fixtures, and is wrong exactly where a tiebreak
//! has to be right. Two fixtures had already done it.
//!
//! Documenting that hazard was not enough, so the shape now forbids it:
//! [`rdata_for_tiebreak`] and its name writer are PRIVATE to this module,
//! `rdata_for_identity` lives with its own consumers, and the only thing this
//! module exports is a finished [`Verdict`]. A caller cannot reach past the
//! verdict to serialize a record itself, which is the only way the wrong
//! canonicalizer got used.

use crate::{records::ServiceRecords, service::respond, wire::Rdata};

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
  /// shortens the peer's list, and a shorter peer list only ever flatters us.
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
  /// An in-scope record's rdata would not parse.
  UnreadableRdata,
  /// An in-scope record's rdata has no well-defined comparison bytes — an
  /// undecompressable embedded name, or a compression-eligible type this crate
  /// does not parse.
  UncomparableRdata,
}

/// Adjudicate ONE peer's complete §8.2 proposal against our own.
///
/// The proposal arrives whole — see [`ProbeProposal`](crate::event::ProbeProposal)
/// — so it is compared the moment it arrives and never retained. That is what
/// makes two failures unrepresentable rather than checked for: a partial list
/// cannot be adjudicated because no partial list exists, and a capacity bound
/// cannot become a lexicographic verdict because there is no buffer to bound.
pub(crate) fn adjudicate(
  pp: &crate::event::ProbeProposal<'_>,
  ours_records: &ServiceRecords,
) -> Verdict {
  let ours = our_proposal(ours_records);
  let mut fold = ProposalFold::new(ours.len());
  let mut scratch = std::vec::Vec::new();
  for r in pp.authority() {
    let Ok(r) = r else {
      return Verdict::Abandoned(Abandon::UnparseableAuthority);
    };
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
      return Verdict::Abandoned(Abandon::UndecodableOwnerName);
    }
    // Scope: EXACTLY the endpoint's admission rule, called rather than restated.
    // See [`crate::endpoint::proposal_admits`] — the two layers held independent
    // copies of this once and one of them went stale, which is how a peer
    // proposing a type we do not publish became invisible to a whole endpoint.
    //
    // There is no separate arm for an unreadable QUESTION section, and that is a
    // verified property of the reader rather than an oversight: locating the
    // authority section requires skipping the questions, so a question section
    // that will not parse leaves it unlocatable and `pp.authority()` yields
    // NOTHING — there is no partial list to abandon. Pinned by
    // `an_unparseable_question_section_surfaces_no_authority_records`, because a
    // comment asserting it would be exactly the kind of claim that silently
    // stops being true.
    //
    // A question whose NAME is an unresolvable compression pointer is a
    // different case and is fail-closed here: `try_parse` consumes the pointer
    // without following it, so the section still parses, and the admission test
    // then walks the labels, errors, and admits nothing on that question.
    if !crate::endpoint::proposal_admits(&r, || pp.questions(), ours_records.instance()) {
      continue;
    }
    // In scope but not representable: same abandonment, same reason. Skipping it
    // would silently shorten the very list being compared.
    let Ok(view) = r.rdata_view() else {
      return Verdict::Abandoned(Abandon::UnreadableRdata);
    };
    let Ok(raw) = rdata_for_tiebreak(r.rtype(), &view, &mut scratch) else {
      return Verdict::Abandoned(Abandon::UncomparableRdata);
    };
    // §8.2's ordering key: class, then type, then rdata. Class is invariant
    // (only IN is admitted above), so type then the peer's own bytes.
    let mut elem = std::vec::Vec::new();
    elem.extend_from_slice(&r.rtype().to_u16().to_be_bytes());
    elem.extend_from_slice(raw);
    fold.offer(elem);
  }
  if fold.peer_wins(&ours) {
    Verdict::PeerWins
  } else {
    Verdict::WeHold
  }
}

/// Our own RFC 6762 §8.2 proposal, sorted: the records this service would claim
/// for its instance name.
///
/// SRV and TXT, because those are exactly what `write_probe` puts in the
/// Authority Section under the instance name. A/AAAA belong to the HOST name, so
/// they are neither proposed here nor compared. The peer's side is not limited
/// this way — a probe asks type ANY, so anything at that name counts for them;
/// see [`adjudicate`].
///
/// # These bytes must be the bytes we TRANSMIT
///
/// §8.2's comparison only resolves a name if both hosts compute the same
/// function over the same two lists, and the peer compares against what we
/// actually sent. So this side deliberately LOWERCASES the SRV target and
/// renders an empty TXT as a single zero-length string — not because §8.2 wants
/// normalisation (it does not; see [`rdata_for_tiebreak`] for the peer side,
/// which normalises nothing) but because that is precisely what
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
  set.sort();
  set
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

/// A PEER record's rdata as RFC 6762 §8.2 compares it: the bytes that peer put
/// on the wire, with embedded names decompressed and nothing else changed.
///
/// §8.2 compares "raw comparison of the binary content of the rdata without
/// regard for meaning or structure", and the ONLY transformation it mandates is
/// decompression: "In the case of resource records containing rdata that is
/// subject to name compression, the names MUST be uncompressed before
/// comparison."
///
/// # Why this is not `rdata_for_identity`
///
/// That one answers "are these two records the same record" and so lowercases
/// SRV targets and rewrites an empty TXT to a single zero-length string. Both
/// are right for identity and wrong for the tiebreak, because the tiebreak only
/// resolves a name if BOTH hosts compute the same function over the same two
/// lists. Normalising the peer's bytes while a byte-comparing peer does not
/// normalise ours makes the two sides disagree:
///
/// | our target `m.local`, peer's `Z.local` | compares | verdict |
/// |---|---|---|
/// | peer, raw | `Z`(0x5A) vs `m`(0x6D), theirs earlier | peer loses |
/// | us, normalising | `m`(0x6D) vs `z`(0x7A), ours earlier | we lose |
///
/// Both abdicate; the mirror case gives two owners.
///
/// # The rule is per SIDE, not "raw everywhere"
///
/// EACH SIDE COMPARES THE BYTES THAT SIDE PUT ON THE WIRE. This function is the
/// peer's side. OUR side keeps lowercasing — see [`our_proposal`] — and that is
/// not an inconsistency: [`crate::wire::MessageBuilder`]'s `write_name`
/// lowercases on transmit, so lowercased bytes ARE what we send, and a peer
/// comparing against us compares those. Making our side "raw" too would make our
/// comparison bytes differ from our own wire bytes and open a second asymmetry
/// while looking like a fix.
///
/// LOAD-BEARING COUPLING: this correctness argument depends on
/// `MessageBuilder::write_name` lowercasing. If transmission ever stops
/// lowercasing, [`our_proposal`] must stop lowercasing with it, or the two sides
/// diverge again.
///
/// # Every name-bearing type, or none
///
/// `rtype` is a parameter because [`Rdata::Other`] has already thrown the type
/// away, and the type is what says whether the bytes may contain a compression
/// pointer. Two omissions made the comparison bytes wrong in the two ways §8.2
/// cannot tolerate:
///
/// * NSEC's `next_name` was DROPPED, leaving only the bitmap. Two NSECs denying
///   the same types at different names then compared equal, and — worse — an
///   NSEC whose `next_name` is a pointer cycle produced bytes at all, so a
///   proposal of "our SRV, our TXT, and one unreadable NSEC" was scored as three
///   records and won §8.2.1 on list length against our two.
/// * `Other` was raw-copied, including the compression-eligible types this crate
///   does not parse (NS/SOA/MX/DNAME). A raw copy of a compressed name is
///   message-OFFSET-dependent: the same record at a different position in the
///   packet yields different comparison bytes, so the two sides do not compute
///   the same function and the tiebreak stops resolving.
///
/// Both now return `Err`, and [`adjudicate`] ABANDONS the proposal on `Err`
/// rather than skipping the record — skipping shortens the list being compared,
/// and shortening only ever flatters us.
fn rdata_for_tiebreak<'s>(
  rtype: crate::wire::ResourceType,
  view: &Rdata<'_>,
  scratch: &'s mut std::vec::Vec<u8>,
) -> Result<&'s [u8], crate::error::ParseError> {
  scratch.clear();
  match view {
    Rdata::A(a) => scratch.extend_from_slice(&a.addr().octets()),
    Rdata::AAAA(a) => scratch.extend_from_slice(&a.addr().octets()),
    // Names subject to compression: decompressed, case untouched.
    Rdata::Ptr(p) => write_wire_name_preserving_case(p.target(), scratch)?,
    Rdata::Cname(c) => write_wire_name_preserving_case(c.target(), scratch)?,
    Rdata::Srv(s) => {
      scratch.extend_from_slice(&s.priority().to_be_bytes());
      scratch.extend_from_slice(&s.weight().to_be_bytes());
      scratch.extend_from_slice(&s.port().to_be_bytes());
      write_wire_name_preserving_case(s.target(), scratch)?;
    }
    Rdata::Txt(t) => {
      // Exactly as sent. No empty-TXT rewriting: a peer that sent zero-length
      // rdata proposed zero-length rdata, and that is what it will compare.
      for seg in t.segments() {
        let seg = seg?;
        #[allow(clippy::cast_possible_truncation)]
        scratch.push(seg.len() as u8);
        scratch.extend_from_slice(seg);
      }
    }
    // NSEC rdata is `next_name` THEN the type bitmap (RFC 4034 §4.1). The name
    // is compression-subject, so it decompresses like every other one here, and
    // it is part of what the peer proposed — dropping it discarded both a
    // difference §8.2 must see and the parse that fails closed on a bad name.
    Rdata::Nsec(n) => {
      write_wire_name_preserving_case(n.next_name(), scratch)?;
      scratch.extend_from_slice(n.type_bitmap_slice());
    }
    Rdata::Other(bytes) => {
      // RFC 3597 §4 forbids compression in truly-unknown types, so their raw
      // bytes are position-independent and comparable as sent. A WELL-KNOWN
      // compressible type this crate does not parse is the opposite: it may
      // arrive compressed, and no comparison over it is well defined.
      if rtype.is_unhandled_compressible_name() {
        return Err(crate::error::ParseError::UnsupportedNameBearingType(
          rtype.to_u16(),
        ));
      }
      scratch.extend_from_slice(bytes);
    }
  }
  Ok(scratch.as_slice())
}

/// Write `name` into `out` in uncompressed wire form, PRESERVING CASE.
///
/// The §8.2 tiebreak's counterpart to [`write_canonical_wire_name`], which
/// lowercases. See [`rdata_for_tiebreak`] for why the two must differ.
fn write_wire_name_preserving_case(
  name: &crate::wire::NameRef<'_>,
  out: &mut std::vec::Vec<u8>,
) -> Result<(), crate::error::ParseError> {
  for label in name.labels() {
    let label = label?;
    if label.is_empty() {
      break;
    }
    let len = label.len().min(63);
    #[allow(clippy::cast_possible_truncation)]
    out.push(len as u8);
    // `.iter().take(len)` rather than `&label[..len]`: the crate denies
    // `clippy::indexing_slicing`, and this is the same truncation-by-iterator
    // `write_canonical_wire_name` uses — the two must stay byte-for-byte
    // parallel apart from the case fold.
    out.extend(label.iter().take(len));
  }
  out.push(0); // root terminator
  Ok(())
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
/// because a probe asks type ANY and may carry any number of records at the name.
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

/// TEST-ONLY window onto [`rdata_for_tiebreak`], for fixtures that pin the
/// compared bytes against enumerated literals.
///
/// The seal this module exists for is against PRODUCTION code: outside here,
/// nothing can serialize a record for §8.2, so nothing can reach for
/// `respond::rdata_for_identity` by mistake — the failure that silently broke
/// the tiebreak twice. A `#[cfg(test)]` accessor does not weaken that; it is
/// unreachable from any shipped path. It exists because the byte-level fixtures
/// in `service::tests` assert what a peer's records COMPARE AS, and a fixture
/// that re-derived those bytes itself would be asserting its own arithmetic
/// rather than this function's.
// The only consumer is `service::tests`, which is gated on `std` + `slab`; under
// a `cargo hack --each-feature` leg such as `--no-default-features --features
// alloc` this module still compiles for test but that consumer does not exist.
#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn tiebreak_bytes_for_fixture<'s>(
  rtype: crate::wire::ResourceType,
  view: &Rdata<'_>,
  scratch: &'s mut std::vec::Vec<u8>,
) -> Result<&'s [u8], crate::error::ParseError> {
  rdata_for_tiebreak(rtype, view, scratch)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests;

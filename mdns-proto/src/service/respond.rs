//! Assemble outgoing probes, announcements, and responses.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{
  constants::{MDNS_IPV4_GROUP, MDNS_PORT},
  error::EncodeError,
  records::ServiceRecords,
  wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
};

/// Append the canonical wire form of a TXT record's rdata to `out`: each
/// segment as a length-octet followed by its bytes, in order.
///
/// RFC 6763 §6.1: a TXT record MUST contain at least one string, so when there
/// are NO segments the canonical form is a single zero-length string (one 0x00
/// byte). This MUST match the wire encoding produced by
/// `MessageBuilder::push_txt_answer` / `push_txt_authority`, so the local TXT
/// canonical used for §8.2 tiebreak, §9 conflict comparison, and KAS-hint
/// matching stays byte-symmetric with what a peer actually receives (a peer's
/// compliant empty TXT — a single 0x00 — canonicalizes to the same bytes under
/// [`RdataForm::FOLDED`](crate::wire::RdataForm::FOLDED)).
// `'a` reads as single-use, but it cannot be elided at our 1.91 MSRV:
// anonymous lifetimes in `impl Trait` are unstable before they stabilized
// (rustc E0658), so the lifetime must stay named.
#[allow(single_use_lifetimes)]
pub(crate) fn write_canonical_txt<'a>(
  segments: impl Iterator<Item = &'a [u8]>,
  out: &mut std::vec::Vec<u8>,
) {
  let mut wrote_any = false;
  for seg in segments {
    if seg.len() <= u8::MAX as usize {
      #[allow(clippy::cast_possible_truncation)]
      out.push(seg.len() as u8);
      out.extend_from_slice(seg);
      wrote_any = true;
    }
  }
  if !wrote_any {
    out.push(0);
  }
}

/// The DOMAIN of [`canonical_rdata_forms`] — every rrtype it can name a form
/// for at the INSTANCE name.
///
/// A caller that must ENUMERATE the instance identities of a record set (rather
/// than ask about one rtype it already holds) has no other way to reach them,
/// and the endpoint's relinquished-RRset screen is such a caller: it decomposes
/// a set it has given up into the identities that set transmitted. Stating the
/// domain here keeps it in the same file as the rule, and
/// `instance_rtype_exposure_mirrors_the_canonical_forms` walks EVERY rtype and
/// pins all three spellings — this list, `canonical_rdata_forms`'s arms, and
/// [`instance_rtype_exposed`]'s — to each other, so a type added to one without
/// the others fails a test rather than silently losing the screen.
pub(crate) const INSTANCE_CANONICAL_RTYPES: [ResourceType; 3] = [
  ResourceType::Srv,
  ResourceType::Txt,
  ResourceType::Nsec,
];

/// The canonical rdata forms `records` puts at its INSTANCE name for `rtype`, in
/// the SAME byte format [`RdataForm::FOLDED`](crate::wire::RdataForm::FOLDED)
/// produces for a peer record — so a §9 conflict check can tell identical
/// (consistent) rdata from a real conflict. SRV → priority+weight+port (BE) +
/// lowercased wire-form host; TXT → length-prefixed segments; NSEC → see
/// [`our_nsec_identities`].
///
/// The arms are EXACTLY the record types a service emits under its instance
/// name, because that is what "identical to these records" can be true of. A
/// type not emitted yields NO forms, and no peer record equals none of them: a
/// peer record canonicalizes to at least one byte for every type, so an empty
/// answer is "this set asserts no record of this type at this name" rather than
/// "it asserts a zero-length one".
///
/// A LIST, because one rtype can have more than one indistinguishable spelling:
/// §9's rule is about proxies and fault-tolerance twins, which are required to
/// be correct rather than to be this crate, and NSEC is a type where the two
/// currently differ. See [`our_nsec_identities`].
///
/// # It takes the RECORDS, not a `Service`
///
/// Two screens ask this question of two different record sets, and both must get
/// the same answer or the second is a second copy of the rule. `Service` asks it
/// of the set it still publishes ([`Service::classify_instance_rdata`]);
/// `Endpoint` asks it of a set it has RELINQUISHED — a withdrawing route's, or
/// one in its retention list — which no live `Service` holds at all. Keeping one
/// function over `&ServiceRecords` is what stops the endpoint's copy going stale
/// the way the pre-screen list did when conflict routing widened past SRV/TXT.
///
/// [`Service::classify_instance_rdata`]: crate::service::Service
pub(crate) fn canonical_rdata_forms(
  records: &ServiceRecords,
  rtype: ResourceType,
) -> std::vec::Vec<std::vec::Vec<u8>> {
  let mut out = std::vec::Vec::new();
  match rtype {
    ResourceType::Srv => {
      let mut srv = std::vec::Vec::new();
      srv.extend_from_slice(&records.priority().to_be_bytes());
      srv.extend_from_slice(&records.weight().to_be_bytes());
      srv.extend_from_slice(&records.port().to_be_bytes());
      super::proposal::write_canonical_wire_name(records.host().as_str(), &mut srv);
      out.push(srv);
    }
    ResourceType::Txt => {
      // empty TXT → single zero-length string (one 0x00), matching both our wire
      // form and a peer's compliant empty TXT canonicalization.
      let mut txt = std::vec::Vec::new();
      write_canonical_txt(records.txt_segments(), &mut txt);
      out.push(txt);
    }
    ResourceType::Nsec => out = our_nsec_identities(records),
    _ => {}
  }
  out
}

/// Did `emitted` put a record of `rtype` on the wire under the INSTANCE name?
///
/// The exposure half of [`canonical_rdata_forms`], and its arms MIRROR that
/// function's — one says which types a record set CAN assert at its instance
/// name, this says which of them a given generation actually did assert. The
/// endpoint's relinquished-RRset screen needs both: a set it retains only
/// disowns an echo of a record that was genuinely transmitted, since a record
/// never transmitted has no echo to disown and screening for it would suppress a
/// GENUINE peer conflict instead.
///
/// A type this record set asserts no form of answers `false` here too, which is
/// why the `_` arm is safe: the two functions are read together and a type
/// absent from one is absent from the other. `instance_rtype_forms_are_tracked`
/// in the tests pins them to each other, because a type added to
/// `canonical_rdata_forms` without a row here would silently lose its screen.
pub(crate) fn instance_rtype_exposed(emitted: &EmittedRecords, rtype: ResourceType) -> bool {
  match rtype {
    ResourceType::Srv => emitted.srv(),
    ResourceType::Txt => emitted.txt(),
    ResourceType::Nsec => emitted.nsec(),
    _ => false,
  }
}

/// Write a probe message per RFC 6762 §8.1: an ANY question for the instance
/// name (with unicast-response bit set) and the proposed unique records in the
/// authority section.
///
/// * Question section: `instance` ANY IN, unicast-response bit set (§5.4).
/// * Authority section: SRV + TXT + A records + AAAA records — the "I propose
///   to own these" claims that allow simultaneous probers to detect conflicts
///   and run the tiebreak algorithm.
pub(crate) fn write_probe(records: &ServiceRecords, out: &mut [u8]) -> Result<usize, EncodeError> {
  let header = Header::new(); // QR=0, opcode=Query
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> = MessageBuilder::try_new(out, header)?;
  // Question: ANY for instance name, unicast-response bit set (RFC §5.4).
  b.push_question(
    records.instance(),
    ResourceType::Any,
    ResourceClass::In,
    true,
  )?;
  // Authority section: proposed unique RR set.
  b.push_srv_authority(
    records.instance(),
    records.ttl_secs(),
    records.priority(),
    records.weight(),
    records.port(),
    records.host(),
  )?;
  b.push_txt_authority(
    records.instance(),
    records.ttl_secs(),
    records.txt_segments(),
  )?;
  for a in records.a_addrs_slice() {
    b.push_a_authority(records.host(), records.ttl_secs(), *a)?;
  }
  for a in records.aaaa_addrs_slice() {
    b.push_aaaa_authority(records.host(), records.ttl_secs(), *a)?;
  }
  b.finish()
}

/// RFC 6762 §6.1 ("negative responses"): append an NSEC record for the service
/// INSTANCE name to the Additional section, asserting the record types this
/// record set publishes there. A querier asking that name for another type then
/// receives a "no such record" answer instead of waiting out a retransmission
/// timeout. The NSEC "Next Domain Name" is the owner name itself
/// (§6.1), and the cache-flush bit is set (the records it describes are unique,
/// §10.2).
///
/// WHAT it asserts is [`emitted_nsec_types`], the one home of that rule. This
/// function only encodes the answer, so it cannot disagree with the recognition
/// side about what our own NSEC says.
///
/// Only the instance NSEC is ever emitted, never a host NSEC: `write_probe`
/// claims the instance name with an rrtype-ANY probe and §9 renames a duplicate,
/// whereas a host name is never probed and may legitimately be shared. Where the
/// two names COINCIDE the instance NSEC IS a host NSEC, and its bitmap names the
/// address records this record set puts at that name — read
/// [`emitted_nsec_types`] for what that bitmap can and cannot vouch for.
///
/// Best-effort: it rides the Additional section, so if it does not fit the
/// remaining buffer the builder is rolled back to before it and the positive
/// answers already written are sent unchanged — adding the record must never
/// turn a deliverable response into a dropped one.
///
/// Returns whether the NSEC actually made it into the message. The rollback is
/// why that answer must be REPORTED rather than assumed: exposure tracking asks
/// "did this record reach the wire", and a rolled-back record did not. See
/// [`EmittedRecords::nsec`].
fn push_service_nsec<const COMP_N: usize>(
  b: &mut MessageBuilder<'_, COMP_N>,
  records: &ServiceRecords,
) -> bool {
  let types = emitted_nsec_types(records);
  let checkpoint = b.checkpoint();
  if b
    .push_nsec_additional(records.instance(), records.ttl_secs(), &types, true)
    .is_err()
  {
    b.restore(checkpoint);
    return false;
  }
  true
}

/// The types a service instance name owns IN ITS OWN RIGHT: `{SRV, TXT}`
/// (RFC 6763 §4).
///
/// The SEED of [`instance_rrset_types`], and only that. An instance name does
/// not always hold just these two, so nothing may treat this constant as the
/// answer to "what is at that name" — ask [`instance_rrset_types`] for what this
/// record set puts there, and [`emitted_nsec_types`] for how far that may be
/// asserted.
pub(crate) const INSTANCE_NSEC_TYPES: [u16; 2] =
  [ResourceType::Srv.to_u16(), ResourceType::Txt.to_u16()];

/// Every RRTYPE THIS RECORD SET puts at its INSTANCE name — this record set's
/// view of that name, which is not the same thing as the name's contents; see
/// [`emitted_nsec_types`] for the limits of what it may be used to assert.
///
/// [`INSTANCE_NSEC_TYPES`] — plus A and/or AAAA when the HOST name IS the
/// instance name and the corresponding address slice is non-empty, because then
/// [`write_announce`] emits those address records at this very name (it writes
/// them at `records.host()`, and the two names are one).
///
/// ONE home for that union, because two sides read it and they used to keep a
/// copy each: emission reaches it through [`emitted_nsec_types`] and recognition
/// through [`our_nsec_identities`]. While they were separate, the emitted NSEC
/// asserted `{SRV, TXT}` at a name the same datagram was putting addresses at —
/// a §6.1 negative answer denying records its own announcement carried.
fn instance_rrset_types(records: &ServiceRecords) -> std::vec::Vec<u16> {
  let mut types: std::vec::Vec<u16> = INSTANCE_NSEC_TYPES.to_vec();
  if records.instance().same_owner(records.host()) {
    if !records.a_addrs_slice().is_empty() {
      types.push(ResourceType::A.to_u16());
    }
    if !records.aaaa_addrs_slice().is_empty() {
      types.push(ResourceType::AAAA.to_u16());
    }
  }
  types
}

/// The RFC 6762 §6.1 type bitmap this crate asserts at `records`' instance name:
/// [`instance_rrset_types`], every time.
///
/// # What one record set can vouch for, and what it cannot
///
/// The bitmap is what THIS RECORD SET publishes at that name, and that is the
/// whole of its warrant. It is NOT a statement that the name holds nothing else
/// on the link, because a `ServiceRecords` cannot see another route's records
/// and the endpoint admits routes that can publish at this very name:
///
/// * a sibling sharing the HOST name, which `Endpoint::host_addresses_disagree`
///   admits whenever the two publish disjoint address families — where that host
///   name is also this instance name, the sibling's family is denied here
///   (#147);
/// * a route whose HOST name is this INSTANCE name: registration compares
///   instance names to instance names and host names to host names, and never
///   across the two roles (#147);
/// * a PTR record at an instance name, which this bitmap never names — the
///   DNS-SD meta PTR, or another route's service-type or subtype name (#145);
/// * an NSEC outliving the owner that emitted it (#146).
///
/// What this bitmap DOES buy is the filed defect and only it: the §6.1 negative
/// answer no longer denies records the SAME record set publishes at that name. A
/// fixed `{SRV, TXT}` denied the A and AAAA records sitting in its own datagram
/// every time the host name was the instance name — cache-flush bit set, so a
/// querier stopped asking for addresses it had just been handed. The cross-route
/// cases above are left to the endpoint-wide owner state the proto layer is not
/// handed; #144 through #147 all wait on it. A reader must not take this bitmap
/// as authoritative for the whole link.
///
/// # Why the answer is not to withhold the record
///
/// Because withholding removes a real negative response rather than a
/// decoration. `endpoint::route` matches a question against a route's own unique
/// names and, with answering enabled, routes it on THE NAME ALONE — there is no
/// qtype filter. A query for an ABSENT type at an owned name therefore reaches
/// the service, [`write_announce_filtered`] answers it with the record set, and
/// the NSEC riding along is the only thing that tells the querier the type it
/// asked for is not there. §6.1 asks a responder to *"respond asserting the
/// nonexistence of that record using a DNS NSEC record"* and says nothing about
/// which section carries it.
///
/// Withholding does not reach the residuals it would be traded for, either. They
/// turn on what a SECOND route publishes, and
/// `records.instance().same_owner(records.host())` — the only test one record
/// set can run — cannot see one: the route whose HOST name is our INSTANCE name
/// is invisible to that test, at a name this encoder writes at either way. So
/// withholding suppresses accurate negatives where nothing is shared, and leaves
/// the cross-route false negatives standing.
///
/// Of the two bitmaps available at a shared name, this is also the narrower
/// denial: `{SRV, TXT, A}` denies one address family where `{SRV, TXT}` denied
/// both.
pub(crate) fn emitted_nsec_types(records: &ServiceRecords) -> std::vec::Vec<u16> {
  instance_rrset_types(records)
}

/// The RFC 4034 §4.1.2 type-bitmap bytes for `present_types`, appended to `out`.
///
/// MIRRORS [`crate::wire::MessageBuilder::push_nsec_additional`], which cannot
/// be reused: it writes through a fixed-size cursor with no allocator, because
/// it must work on the bare-metal targets. The duplication is pinned by a test
/// that builds a real NSEC with the builder, parses it back, and requires the
/// two encodings to be byte-identical — so a change to either side that is not
/// made to both fails rather than silently un-recognising our own record.
fn write_nsec_type_bitmap(present_types: &[u16], out: &mut std::vec::Vec<u8>) {
  let mut bitmap = [0u8; 32];
  let mut max_byte: Option<usize> = None;
  for &t in present_types {
    if t >= 256 {
      continue;
    }
    let byte_idx = usize::from(t >> 3);
    #[allow(clippy::cast_possible_truncation)]
    let mask = 0x80u8 >> (t & 0x07);
    if let Some(slot) = bitmap.get_mut(byte_idx) {
      *slot |= mask;
      max_byte = Some(max_byte.map_or(byte_idx, |m| m.max(byte_idx)));
    }
  }
  let Some(max_byte) = max_byte else {
    return;
  };
  let blen = max_byte.saturating_add(1);
  out.push(0); // window block number 0
  #[allow(clippy::cast_possible_truncation)]
  out.push(blen as u8);
  out.extend(bitmap.iter().take(blen));
}

/// Every instance-NSEC rdata that is INDISTINGUISHABLE FROM OURS, in the
/// identity form [`RdataForm::FOLDED`](crate::wire::RdataForm::FOLDED) yields
/// for a peer's record: `next_name` — the owner name itself (§6.1) — in
/// case-folded wire form, then the RFC 4034 §4.1.2 type bitmap.
///
/// # Why a SET, when we emit at most one
///
/// RFC 6762 §9's "resource records with identical rdata are never considered
/// inconsistent" exists for "proxies and other fault-tolerance mechanisms",
/// which means the twin at the other end is not required to be this crate. It is
/// required to be CORRECT — and where the two differ, both spellings have to be
/// recognised as ours or the twin renames us.
///
/// They differ in exactly one configuration. When the host name IS the instance
/// name, this service publishes its A/AAAA records at the instance name too (see
/// `write_probe` and `proposal::our_proposal`, which counts them for the same
/// reason), so [`instance_rrset_types`] is wider than `{SRV, TXT}` there — and
/// the wider set is the one [`push_service_nsec`] writes.
///
/// RECOGNITION MAY NOT FOLLOW EMISSION. An NSEC arriving at a name we are
/// probing is adjudicated whether or not we would have written that exact
/// bitmap, so both spellings must read as identical rdata — otherwise a twin's
/// record is inconsistent rdata at a name we are probing, which is an RFC 6762
/// §8.1 defeat. Both are kept for that reason: the bare `{SRV, TXT}` is what a
/// twin treating the name as an ordinary instance name sends, the wider set is
/// what one that notices the addresses sends, and neither is a conflict. The two
/// coincide — one entry — in every configuration where the host is a separate
/// name.
///
/// LENIENCE IS THE SAFE DIRECTION HERE, and the opposite of what HISTORY may
/// claim about the same rrtype: see [`transmitted_rdata_forms`].
pub(crate) fn our_nsec_identities(records: &ServiceRecords) -> std::vec::Vec<std::vec::Vec<u8>> {
  let mut forms = std::vec::Vec::new();
  forms.push(nsec_identity(records, &INSTANCE_NSEC_TYPES));
  let published = nsec_identity(records, &instance_rrset_types(records));
  if !forms.contains(&published) {
    forms.push(published);
  }
  forms
}

/// The instance-NSEC identity for one type bitmap: `next_name` — the owner name
/// itself (§6.1) — in case-folded wire form, then the RFC 4034 §4.1.2 bitmap.
fn nsec_identity(records: &ServiceRecords, types: &[u16]) -> std::vec::Vec<u8> {
  let mut out = std::vec::Vec::new();
  super::proposal::write_canonical_wire_name(records.instance().as_str(), &mut out);
  write_nsec_type_bitmap(types, &mut out);
  out
}

/// The instance-NSEC rdata THIS ENCODER PUTS ON THE WIRE for `records` — the one
/// form [`push_service_nsec`] writes, and the only NSEC bytes any echo of ours
/// can carry.
///
/// It agrees with the encoder BY CONSTRUCTION rather than by coincidence, which
/// is the whole point of naming it: both read [`emitted_nsec_types`], so neither
/// can drift from the bitmap the other means. It is also an entry of
/// [`our_nsec_identities`] — the two callers want opposite things from that list
/// and only one of them may have the whole of it. See
/// [`transmitted_rdata_forms`].
pub(crate) fn emitted_nsec_identity(records: &ServiceRecords) -> std::vec::Vec<u8> {
  nsec_identity(records, &emitted_nsec_types(records))
}

/// The canonical rdata forms `records` ACTUALLY TRANSMITS at its instance name
/// for `rtype` — the HISTORY half of [`canonical_rdata_forms`], and never wider
/// than it.
///
/// # Why history may not use the classifier's list
///
/// [`canonical_rdata_forms`] answers *"could a record set indistinguishable from
/// ours have sent this?"*. That leniency is correct where it is asked: a
/// conforming RFC 6762 §9 fault-tolerance twin publishing the ACCURATE NSEC
/// bitmap at a name that really does hold all four types is a legitimate twin,
/// and §9's identical-rdata rule protects it from our rename.
///
/// The endpoint's relinquished-RRset screen asks something narrower and purely
/// factual: *"did these exact bytes leave this endpoint, on this family, in this
/// generation?"* — and a form this crate never encodes did not. Answering that
/// one from the classifier's list converts semantic compatibility into false
/// wire provenance: a GENUINE peer's conforming NSEC reads as an old self-echo,
/// and the decisive §8.1 / §9 conflict against a successor is withheld for the
/// whole retention window. See [`crate::endpoint::relinquished::asserts`].
///
/// # The arms
///
/// SRV and TXT DELEGATE, because each yields exactly one form there and that
/// form IS the encoded one — `push_srv_answer` and `push_txt_answer` write the
/// same bytes [`canonical_rdata_forms`] builds, which is what makes the §8.2
/// byte-symmetry invariant hold. NSEC is the one rtype whose classifier list can
/// be WIDER than what the encoder emits: where the instance name is also the
/// host name it also accepts a twin's bare `{SRV, TXT}` spelling, which this
/// crate does not write there, so history keeps the emitted bitmap alone.
///
/// A type absent from every arm yields NOTHING, and that is the direction to
/// fail in: retaining too little re-opens a stale echo for the identities
/// dropped, while retaining too much suppresses a genuine peer's conflict — the
/// terminal outcome from the other side. `transmitted_forms_never_widen_the_
/// canonical_ones` walks [`INSTANCE_CANONICAL_RTYPES`] and pins both halves.
pub(crate) fn transmitted_rdata_forms(
  records: &ServiceRecords,
  rtype: ResourceType,
) -> std::vec::Vec<std::vec::Vec<u8>> {
  match rtype {
    ResourceType::Srv | ResourceType::Txt => canonical_rdata_forms(records, rtype),
    ResourceType::Nsec => std::vec![emitted_nsec_identity(records)],
    _ => std::vec::Vec::new(),
  }
}

/// WHICH SECTION of a message a record sits in — the arriving half of the
/// qualifier [`transmitted_envelope`] states the transmitted half of.
///
/// Three variants because the QR=1 conflict fan-out walks three sections. The
/// question section carries no records at all, and the iterator's
/// `AuthorityProposals` phase is a second pass over the SAME authority records
/// rather than a fourth section, so it needs no variant of its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecordSection {
  /// The answer section — where every positive multicast record this crate
  /// encodes goes EXCEPT the RFC 6762 §6.1 instance NSEC.
  Answer,
  /// The authority section. QR=0 it carries a peer's §8.2 proposal; QR=1 it is
  /// classed with the responses. [`write_probe`] is the only encoder here that
  /// writes one, and a probe latches no exposure — see [`transmitted_envelope`].
  Authority,
  /// The additional section — where [`push_service_nsec`] puts the §6.1
  /// instance NSEC, and where a CONFORMING responder routinely puts the
  /// addresses this crate keeps in the answer section.
  Additional,
}

/// Could a record of `rtype` arriving in `section` with this `cache_flush` bit
/// be an ECHO of something this crate put on the MULTICAST group?
///
/// The WIRE ENVELOPE half of the same question [`transmitted_rdata_forms`]
/// answers for rdata, and it lives beside that function for the same reason:
/// "what this endpoint transmitted" gets ONE description, so the endpoint's
/// relinquished-history screen cannot drift from the encoders it is describing.
/// Both of this crate's positive multicast encoders — [`write_announce`] and
/// [`write_announce_filtered`] — write:
///
/// * the unique instance SRV / TXT and the host A / AAAA in the ANSWER section,
///   each with the RFC 6762 §10.2 cache-flush bit SET;
/// * the §6.1 instance NSEC in the ADDITIONAL section, through the single
///   [`push_service_nsec`] call site, also cache-flushed;
/// * nothing whatever in the AUTHORITY section. [`write_probe`] writes one, but
///   a probe is QR=0 and latches no exposure (`AwaitingConfirm::Probe` records
///   none), so no identity this screen can answer for has ever been in a QR=1
///   authority section.
///
/// # Why both qualifiers are exact for a real echo, and what a mismatch means
///
/// An echo is a RE-DELIVERY of a datagram — kernel loopback, or the 802.11
/// base-station re-broadcast RFC 6762 §8.2 names — not a re-encoding of it.
/// The UDP payload is the same bytes, so the header counts that place a record
/// in its section are ours, and the cache-flush bit, which is bit 15 of the
/// record's own CLASS field, is ours. A genuine echo therefore arrives in the
/// section we wrote it in with the bit we set, and NEITHER qualifier can reject
/// one.
///
/// So a mismatch says the datagram is not our echo, and the two readings of
/// that agree: either a conforming peer put an address in ADDITIONAL beside its
/// SRV (RFC 6763 §12's own advice, and an ordinary browse response), or
/// something re-encoded our bytes — which is a §9 fault-tolerance twin or a
/// replaying peer, and this cell's whole premise is that neither may be
/// disowned. Both point the same way: deliver the conflict.
///
/// # The direction it fails in
///
/// `false` for anything it does not recognise, exactly as
/// [`transmitted_rdata_forms`] yields no form for a type it does not encode.
/// Claiming an envelope this crate never wrote would suppress a GENUINE peer's
/// terminal `HostConflict` — a conforming responder's Additional-section
/// address is reachable with ordinary traffic, no crafted case required — while
/// failing to claim one it did write can only re-open a stale self-echo, which
/// the §8.2 deferral and §9's reversible same-name reset already bound.
///
/// # The cache-flush bit is per rrtype, not a flat conjunct
///
/// Because it would be WRONG for a shared record. The service-type and RFC 6763
/// §7.1 subtype PTRs go out with the bit clear, and they are outside every arm
/// here for the same reason [`instance_rtype_exposed`] has no PTR row: their
/// owner is neither the instance name nor the host name, so the screen never
/// answers for them. A PTR arm added here would need its own `!cache_flush`
/// rule, not this one.
pub(crate) const fn transmitted_envelope(
  rtype: ResourceType,
  section: RecordSection,
  cache_flush: bool,
) -> bool {
  match rtype {
    // The unique instance and host records, every one of them an answer.
    ResourceType::Srv | ResourceType::Txt | ResourceType::A | ResourceType::AAAA => {
      matches!(section, RecordSection::Answer) && cache_flush
    }
    // The §6.1 negative response, and the only thing this crate ever writes
    // into the additional section.
    ResourceType::Nsec => matches!(section, RecordSection::Additional) && cache_flush,
    _ => false,
  }
}

/// WHICH OF OUR OWNER NAMES a record of `rtype` sits at, or `None` for a type
/// these encoders never write.
///
/// The ONE statement of the record-to-owner rule, and it lives beside the
/// encoders because they are what make it true: [`write_announce`] and
/// [`write_announce_filtered`] push the service-type PTR at
/// `records.service_type()`, the SRV and TXT at `records.instance()`, every
/// A / AAAA at `records.host()`, and [`push_service_nsec`] the §6.1 NSEC at
/// `records.instance()`. `the_owner_name_rule_is_the_one_the_encoders_write_at`
/// walks a real message and puts every record it emits to this answer, so an
/// encoder that moves a record to another owner fails a test rather than
/// silently splitting the rule in two.
///
/// # Both halves of §7.1 known-answer suppression read it
///
/// RFC 6762 §7.1 identifies an RRset by (name, type, class, rdata), so a
/// known-answer may suppress one of our records only when it names the very
/// owner that record sits at. A same-rtype, same-rdata answer under a DIFFERENT
/// owner name is a DIFFERENT RRset and must not silence us — otherwise a
/// querier could quiet our `host.local A x` by sending `_svc._tcp.local A x`.
///
/// Ingest binds a hint by asking this for the ARRIVING record's rtype and
/// requiring that record's name to match; the emit-side filter then needs no
/// owner test of its own, because a stored hint of the same rtype is by
/// construction a hint at the same owner name. The two used to answer the
/// question separately — ingest by walking our names in a precedence order,
/// emission by matching on rtype — and where a service's instance name IS its
/// host name they disagreed: an inbound A known-answer took the instance arm
/// because that name matched first, while the A candidate was owned by the host,
/// so `hint.owner == owner` could never hold and §7.1 suppression for host
/// addresses silently never fired.
///
/// # What is deliberately outside it
///
/// The RFC 6763 §7.1 SUBTYPE PTRs, which [`write_announce_filtered`] does not
/// KAS-filter: no candidate is ever offered under a `_sub` name, so a
/// known-answer at one has nothing to suppress and this answers for the
/// service-type PTR alone. And a type these encoders do not write at all, which
/// gets `None` — the direction that can only fail to suppress.
pub(crate) fn emitted_owner_name(
  records: &ServiceRecords,
  rtype: ResourceType,
) -> Option<&crate::Name> {
  match rtype {
    ResourceType::Ptr => Some(records.service_type()),
    ResourceType::Srv | ResourceType::Txt | ResourceType::Nsec => Some(records.instance()),
    ResourceType::A | ResourceType::AAAA => Some(records.host()),
    _ => None,
  }
}

/// Write an unsolicited announcement: SRV, TXT, A, AAAA records.
///
/// Returns the encoded length and whether the RFC 6762 §6.1 instance NSEC rode
/// with it — best-effort, so it can be rolled back when the buffer is full, and
/// the caller latches exposure for what actually went out.
pub(crate) fn write_announce(
  records: &ServiceRecords,
  out: &mut [u8],
) -> Result<(usize, bool), EncodeError> {
  let header = Header::new().with_flags(
    crate::wire::Flags::new()
      .with_response()
      .with_authoritative(),
  );
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> = MessageBuilder::try_new(out, header)?;
  // PTR: service-type → instance (RFC 6763 §4.1, required for DNS-SD browsers)
  b.push_ptr_answer(
    records.service_type(),
    records.ttl_secs(),
    records.instance(),
  )?;
  // RFC 6763 §7.1 subtype PTRs: <sub>._sub.<type> → instance. Shared records
  // (like the main service-type PTR), so NO cache-flush bit.
  for sub in records.subtype_names() {
    b.push_ptr_answer(sub, records.ttl_secs(), records.instance())?;
  }
  // SRV — unique record: set cache-flush bit (RFC 6762 §10.2).
  b.push_srv_answer(
    records.instance(),
    records.ttl_secs(),
    records.priority(),
    records.weight(),
    records.port(),
    records.host(),
    true,
  )?;
  // TXT — unique record: set cache-flush bit.
  b.push_txt_answer(
    records.instance(),
    records.ttl_secs(),
    records.txt_segments(),
    true,
  )?;
  // A records (one per address) — unique: set cache-flush bit.
  for a in records.a_addrs_slice() {
    b.push_a_answer(records.host(), records.ttl_secs(), *a, true)?;
  }
  // AAAA records — unique: set cache-flush bit.
  for a in records.aaaa_addrs_slice() {
    b.push_aaaa_answer(records.host(), records.ttl_secs(), *a, true)?;
  }
  // RFC 6762 §6.1 negative responses (Additional section).
  let nsec = push_service_nsec(&mut b, records);
  Ok((b.finish()?, nsec))
}

/// Write an RFC 6763 §9 meta-query answer: a single shared PTR
/// `_services._dns-sd._udp.<domain>. -> <service_type>`. Shared (many responders
/// on the link advertise the same type), so NO cache-flush bit. `meta_name` is
/// the meta-query owner name the caller has validated.
pub(crate) fn write_meta_response(
  records: &ServiceRecords,
  meta_name: &crate::Name,
  out: &mut [u8],
) -> Result<usize, EncodeError> {
  let header = Header::new().with_flags(
    crate::wire::Flags::new()
      .with_response()
      .with_authoritative(),
  );
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> = MessageBuilder::try_new(out, header)?;
  b.push_ptr_answer(meta_name, records.ttl_secs(), records.service_type())?;
  b.finish()
}

/// Write a legacy unicast RFC 6763 §9 meta reply: echoes the query ID +
/// meta question, then the single shared meta-PTR `<meta> -> service_type` at
/// the §6.7-capped TTL with the cache-flush bit cleared. A non-mDNS resolver is
/// not on the multicast group, so its service-type enumeration must be answered
/// by a unicast echo — this is the §9 analogue of [`write_legacy_response`].
pub(crate) fn write_legacy_meta_response(
  records: &ServiceRecords,
  query_id: u16,
  meta_name: &crate::Name,
  qtype: ResourceType,
  qclass: ResourceClass,
  out: &mut [u8],
) -> Result<usize, EncodeError> {
  let header = Header::new().with_id(query_id).with_flags(
    crate::wire::Flags::new()
      .with_response()
      .with_authoritative(),
  );
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> = MessageBuilder::try_new(out, header)?;
  b.push_question(meta_name, qtype, qclass, false)?;
  let ttl = records.ttl_secs().min(LEGACY_UNICAST_MAX_TTL_SECS);
  b.push_ptr_answer(meta_name, ttl, records.service_type())?;
  b.finish()
}

/// RFC 6762 §6.7: cap on the TTL of records in a legacy unicast response, so a
/// non-mDNS resolver (which doesn't run mDNS cache maintenance) doesn't hold
/// our records longer than a few seconds.
pub(crate) const LEGACY_UNICAST_MAX_TTL_SECS: u32 = 10;

/// Write a legacy unicast response (RFC 6762 §6.7) for a querier that is not
/// an mDNS participant (it sent a one-shot query from an ephemeral port).
///
/// Unlike a multicast response it: (a) echoes the original query ID, (b) repeats
/// the question (so a conventional DNS resolver can match the reply), (c) caps
/// record TTLs at [`LEGACY_UNICAST_MAX_TTL_SECS`], and (d) clears the cache-flush
/// bit (the resolver doesn't implement §10.2 semantics). The full record set is
/// included; the resolver selects the records matching its question and ignores
/// the rest.
pub(crate) fn write_legacy_response(
  records: &ServiceRecords,
  query_id: u16,
  qname: &crate::Name,
  qtype: ResourceType,
  qclass: ResourceClass,
  out: &mut [u8],
) -> Result<(usize, EmittedRecords), EncodeError> {
  let header = Header::new().with_id(query_id).with_flags(
    crate::wire::Flags::new()
      .with_response()
      .with_authoritative(),
  );
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> = MessageBuilder::try_new(out, header)?;
  // Echo the question (no QU bit in a response).
  b.push_question(qname, qtype, qclass, false)?;
  let ttl = records.ttl_secs().min(LEGACY_UNICAST_MAX_TTL_SECS);
  b.push_ptr_answer(records.service_type(), ttl, records.instance())?;
  // RFC 6763 §7.1 subtype PTRs (shared) — part of the full echoed record set.
  for sub in records.subtype_names() {
    b.push_ptr_answer(sub, ttl, records.instance())?;
  }
  b.push_srv_answer(
    records.instance(),
    ttl,
    records.priority(),
    records.weight(),
    records.port(),
    records.host(),
    false,
  )?;
  b.push_txt_answer(records.instance(), ttl, records.txt_segments(), false)?;
  for a in records.a_addrs_slice() {
    b.push_a_answer(records.host(), ttl, *a, false)?;
  }
  for a in records.aaaa_addrs_slice() {
    b.push_aaaa_answer(records.host(), ttl, *a, false)?;
  }
  // A §6.7 legacy reply is NOT KAS-filtered — it echoes the full positive-TTL
  // record set, so it advertises every instance record and every host address.
  // Report exactly that so the caller latches goodbye ownership matching what
  // went on the wire. Deriving it from the echoed QUESTION name instead splits
  // the set into instance-XOR-host and under- or over-withdraws on a later
  // goodbye.
  let emitted = EmittedRecords {
    ptr: true,
    srv: true,
    txt: true,
    a: records.a_addrs_slice().to_vec(),
    aaaa: records.aaaa_addrs_slice().to_vec(),
    subtypes: !records.subtype_names().is_empty(),
    // A legacy reply carries no §6.1 NSEC: it is answered to one off-group
    // resolver that asked a specific question, not multicast to the group.
    nsec: false,
  };
  Ok((b.finish()?, emitted))
}

/// Write a goodbye (RFC 6762 §10.1): TTL-0 copies of the announced records,
/// telling receivers the service is withdrawn. The instance records and the
/// host A/AAAA are selected independently — they are owned by DIFFERENT names
/// and have independent lifecycles:
///
/// * `include_ptr` / `include_srv` / `include_txt` — the instance-owned records
///   (owned by the service instance name), withdrawn independently. Withdraw
///   each only if the current instance actually emitted it (§7.1 KAS can have
///   suppressed a subset).
/// * `a_addrs` / `aaaa_addrs` — the host A/AAAA to withdraw (owned by the host
///   name, which is invariant across instance renames). The caller passes the
///   exact addresses to retract — per-address, since same-host services may
///   advertise different address sets, withdrawing an address another local
///   service still advertises would wrongly evict it from peer caches.
///   All A/AAAA use `records.host()` as the owner name.
///
/// The unique records keep the cache-flush bit, so per §10.2 a TTL of zero
/// schedules deletion one second out rather than instantly — robust against a
/// stale re-announce that races the goodbye.
// Per-record include flags + the host-address withdraw lists are all distinct
// inputs an unregister/rename goodbye must select independently;
// grouping them would just shuffle the same data into a one-use struct.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_goodbye(
  records: &ServiceRecords,
  out: &mut [u8],
  include_ptr: bool,
  include_srv: bool,
  include_txt: bool,
  include_subtypes: bool,
  a_addrs: impl Iterator<Item = Ipv4Addr>,
  aaaa_addrs: impl Iterator<Item = Ipv6Addr>,
) -> Result<usize, EncodeError> {
  let header = Header::new().with_flags(
    crate::wire::Flags::new()
      .with_response()
      .with_authoritative(),
  );
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> = MessageBuilder::try_new(out, header)?;
  push_goodbye_records(
    &mut b,
    records,
    include_ptr,
    include_srv,
    include_txt,
    include_subtypes,
    a_addrs,
    aaaa_addrs,
  )?;
  b.finish()
}

/// Append one service's TTL=0 goodbye records (selected per-record) into an
/// EXISTING [`MessageBuilder`]. Factored out of [`write_goodbye`] so the
/// per-record goodbye selection (PTR/SRV/TXT/subtypes + host A/AAAA) lives in
/// one place.
#[allow(clippy::too_many_arguments)]
fn push_goodbye_records<const COMP_N: usize>(
  b: &mut MessageBuilder<'_, COMP_N>,
  records: &ServiceRecords,
  include_ptr: bool,
  include_srv: bool,
  include_txt: bool,
  include_subtypes: bool,
  a_addrs: impl Iterator<Item = Ipv4Addr>,
  aaaa_addrs: impl Iterator<Item = Ipv6Addr>,
) -> Result<(), EncodeError> {
  // the instance-owned PTR/SRV/TXT are withdrawn INDEPENDENTLY — §7.1
  // known-answer suppression can put only a subset of them on the wire, and a
  // goodbye must retract exactly the records this responder transmitted.
  if include_ptr {
    b.push_ptr_answer(records.service_type(), 0, records.instance())?;
  }
  if include_srv {
    b.push_srv_answer(
      records.instance(),
      0,
      records.priority(),
      records.weight(),
      records.port(),
      records.host(),
      true,
    )?;
  }
  if include_txt {
    // Pass the TXT segments straight through: push_txt_answer takes an iterator of
    // `AsRef<[u8]>`, so no per-segment `Vec` clone is needed on this path.
    b.push_txt_answer(records.instance(), 0, records.txt_segments(), true)?;
  }
  // RFC 6763 §7.1 subtype PTRs are instance-associated (target = instance), so
  // they are withdrawn with the instance records (TTL 0, shared → no flush bit).
  if include_subtypes {
    for sub in records.subtype_names() {
      b.push_ptr_answer(sub, 0, records.instance())?;
    }
  }
  for a in a_addrs {
    b.push_a_answer(records.host(), 0, a, true)?;
  }
  for a in aaaa_addrs {
    b.push_aaaa_answer(records.host(), 0, a, true)?;
  }
  Ok(())
}

/// Which CONCRETE records a filtered/legacy response actually put on the wire
///. Known-answer suppression (§7.1) can omit ANY subset
/// — individual PTR/SRV/TXT and individual A/AAAA addresses — so the caller must
/// NOT assume a delivered response advertised a whole owner group. Goodbye
/// ownership latches per record reported here, so a later TTL=0 goodbye
/// withdraws ONLY records this responder truly transmitted (withdrawing one it
/// never sent could cache-flush a peer's matching shared record).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EmittedRecords {
  /// The instance PTR (service-type → instance) was emitted.
  ptr: bool,
  /// The instance SRV was emitted.
  srv: bool,
  /// The instance TXT was emitted.
  txt: bool,
  /// The host A addresses actually emitted (KAS may suppress a subset).
  a: std::vec::Vec<Ipv4Addr>,
  /// The host AAAA addresses actually emitted.
  aaaa: std::vec::Vec<Ipv6Addr>,
  /// The RFC 6763 §7.1 subtype PTRs were emitted. These are shared, not
  /// KAS-filtered, so they are emitted all-or-nothing together with the
  /// instance — a single bit suffices (no per-subtype tracking).
  subtypes: bool,
  /// The RFC 6762 §6.1 instance NSEC rode in the Additional section.
  ///
  /// Tracked rather than derived, because the three encoders differ: an
  /// announcement always carries it, a §7.1-filtered response carries it only
  /// when some positive answer survived, a §6.7 legacy unicast reply never
  /// carries it — and [`push_service_nsec`] rolls it back when the buffer is
  /// full. It is not a goodbye-able record (a §10.1 goodbye emits no NSEC), so
  /// it is deliberately outside [`Self::is_empty`] and
  /// `GoodbyeOwnership::any_instance`; what reads it is the endpoint's
  /// relinquished-RRset screen, which must know which record IDENTITIES this
  /// endpoint actually put on the wire.
  nsec: bool,
}

impl EmittedRecords {
  /// True when nothing positive-TTL reached the wire (every record was §7.1
  /// suppressed → a header-only response): the caller must not send it and
  /// latches no goodbye ownership.
  ///
  /// [`Self::nsec`] is NOT a term here, and cannot be: the NSEC is an
  /// Additional-section hint that only ever rides a message some positive answer
  /// already survived into, so it can never be the sole emitted record. Counting
  /// it would make this predicate — which is the SEND decision — circular.
  pub fn is_empty(&self) -> bool {
    !self.ptr
      && !self.srv
      && !self.txt
      && !self.subtypes
      && self.a.is_empty()
      && self.aaaa.is_empty()
  }

  /// True when this send put a record the INSTANCE NAME uniquely owns on the
  /// wire — the SRV or the TXT (RFC 6763 §4).
  ///
  /// This is what "this generation has claimed the name" means, and it is a
  /// narrower fact than "something was emitted". The PTRs are the difference:
  /// the service-type PTR and the RFC 6763 §7.1 subtype PTRs are owned by SHARED
  /// names that any number of responders answer for, so emitting one asserts
  /// nothing about who owns this instance. A §7.1 known-answer-filtered response
  /// can emit exactly those and nothing else — reachable in `Announcing(0)`,
  /// after a failed announcement, from a querier that already holds our SRV and
  /// TXT — and counting it closed `Service::is_preauthoritative`'s window with no
  /// instance-owned record anywhere on the link. A winning `ProbeProposal`
  /// arriving after that was then silently not adjudicated.
  ///
  /// Goodbye ownership is a DIFFERENT question and keeps counting the PTRs: a
  /// shared PTR we emitted is one a peer now caches from us, and it has to be
  /// withdrawn whether or not it claimed anything. See
  /// `Service::generation_advertised`.
  pub(crate) const fn claims_instance_name(&self) -> bool {
    self.srv || self.txt
  }

  /// Construct from an explicit record set (used by callers in other modules
  /// that latch goodbye ownership without going through the encoders).
  pub(crate) fn new(
    ptr: bool,
    srv: bool,
    txt: bool,
    a: std::vec::Vec<Ipv4Addr>,
    aaaa: std::vec::Vec<Ipv6Addr>,
    subtypes: bool,
    nsec: bool,
  ) -> Self {
    Self {
      ptr,
      srv,
      txt,
      a,
      aaaa,
      subtypes,
      nsec,
    }
  }

  /// OR another report's INSTANCE records (PTR/SRV/TXT/subtypes, and the
  /// instance NSEC) into this one.
  ///
  /// Ownership is a union of what reached the wire, so merging two reports for
  /// the SAME name is the same operation the goodbye latch performs. Host
  /// addresses are deliberately not merged: the only caller is the RFC 6763 §9
  /// rename handoff, which withdraws instance records exclusively (the host name
  /// is invariant across an instance rename). The NSEC is an INSTANCE-owned
  /// identity, so it merges with them.
  pub(crate) fn merge_instance(&mut self, other: &Self) {
    self.ptr |= other.ptr;
    self.srv |= other.srv;
    self.txt |= other.txt;
    self.subtypes |= other.subtypes;
    self.nsec |= other.nsec;
  }

  /// OR another report's HOST ADDRESSES into this one.
  ///
  /// The companion of [`Self::merge_instance`], split from it because the one
  /// caller that merges instance records — the RFC 6763 §9 rename handoff — must
  /// NOT merge addresses (the host name is invariant across an instance rename).
  /// The endpoint's goodbye encoder merges both: it is folding the two halves of
  /// a per-family exposure back into the one datagram a round emits.
  pub(crate) fn merge_addrs(&mut self, other: &Self) {
    for ip in &other.a {
      if !self.a.contains(ip) {
        self.a.push(*ip);
      }
    }
    for ip in &other.aaaa {
      if !self.aaaa.contains(ip) {
        self.aaaa.push(*ip);
      }
    }
  }

  /// Narrow this report to the SHARED PTRs a caller says are still owed a
  /// retraction, dropping everything else it recorded.
  ///
  /// The one caller is the reclaim-cancel in
  /// [`Endpoint::note_service_transmit_outcome`](crate::Endpoint::note_service_transmit_outcome),
  /// and the asymmetry it needs is RFC 6762's own. A same-name replacement's
  /// §10.2 announcement carries the SRV and TXT with the cache-flush bit, so it
  /// SUPERSEDES the stale unique records at that instance name and the goodbye
  /// for them has nothing left to do. It supersedes no SHARED record it does not
  /// itself carry: a PTR is owned by a browse name, arrives with no cache-flush
  /// bit, and is retracted only by its own §10.1 TTL=0 goodbye. So which shared
  /// PTRs survive is a question about the REPLACEMENT'S record set, which only
  /// the endpoint can answer — hence the two flags rather than a rule here.
  ///
  /// The §6.1 NSEC goes with the superseded records: a goodbye never emits one,
  /// so keeping it could only ever hold an item open with nothing to send.
  pub(crate) fn keep_only_shared_ptrs(&mut self, type_ptr: bool, subtypes: bool) {
    *self = Self {
      ptr: self.ptr && type_ptr,
      subtypes: self.subtypes && subtypes,
      ..Self::default()
    };
  }

  /// Whether the instance PTR was emitted.
  #[inline(always)]
  pub(crate) const fn ptr(&self) -> bool {
    self.ptr
  }

  /// Whether the instance SRV was emitted.
  #[inline(always)]
  pub(crate) const fn srv(&self) -> bool {
    self.srv
  }

  /// Whether the instance TXT was emitted.
  #[inline(always)]
  pub(crate) const fn txt(&self) -> bool {
    self.txt
  }

  /// Whether the RFC 6763 §7.1 subtype PTRs were emitted.
  #[inline(always)]
  pub(crate) const fn subtypes(&self) -> bool {
    self.subtypes
  }

  /// Whether the RFC 6762 §6.1 instance NSEC was emitted. See the field.
  #[inline(always)]
  pub(crate) const fn nsec(&self) -> bool {
    self.nsec
  }

  /// The host A addresses actually emitted.
  #[inline(always)]
  pub(crate) const fn a_slice(&self) -> &[Ipv4Addr] {
    self.a.as_slice()
  }

  /// The host AAAA addresses actually emitted.
  #[inline(always)]
  pub(crate) const fn aaaa_slice(&self) -> &[Ipv6Addr] {
    self.aaaa.as_slice()
  }
}

/// Write an announcement, suppressing records matching fresh KAS hints.
///
/// `hint_matches(rtype, rdata)` is called for each candidate record; return
/// `true` to suppress that record from the outgoing message. Returns the encoded
/// length and which owner groups were actually emitted — KAS may
/// suppress any subset, including all of them (a header-only response).
pub(crate) fn write_announce_filtered<F>(
  records: &ServiceRecords,
  out: &mut [u8],
  mut hint_matches: F,
) -> Result<(usize, EmittedRecords), EncodeError>
where
  F: FnMut(ResourceType, &[u8]) -> bool,
{
  let header = crate::wire::Header::new().with_flags(
    crate::wire::Flags::new()
      .with_response()
      .with_authoritative(),
  );
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> = MessageBuilder::try_new(out, header)?;

  let mut emitted = EmittedRecords::default();
  let mut scratch: std::vec::Vec<u8> = std::vec::Vec::new();

  // PTR — canonical: the target name in case-folded WIRE form (length-octet +
  // label bytes …, root 0x00), which is what the one decoder yields for an
  // inbound PTR under `RdataForm::FOLDED`. Dot-joined bytes with no length
  // prefixes would not match the decoder, and are ambiguous besides: labels
  // `["a.b"]` and `["a", "b"]` join to the same string.
  {
    scratch.clear();
    super::proposal::write_canonical_wire_name(records.instance().as_str(), &mut scratch);
    if !hint_matches(ResourceType::Ptr, &scratch) {
      b.push_ptr_answer(
        records.service_type(),
        records.ttl_secs(),
        records.instance(),
      )?;
      emitted.ptr = true;
    }
  }

  // RFC 6763 §7.1 subtype PTRs: <sub>._sub.<type> → instance. Shared records,
  // NOT KAS-filtered (a small fixed set; the simplicity of all-or-nothing
  // ownership outweighs suppressing the occasional already-held subtype PTR).
  for sub in records.subtype_names() {
    b.push_ptr_answer(sub, records.ttl_secs(), records.instance())?;
    emitted.subtypes = true;
  }

  // SRV — canonical: priority (2 BE) + weight (2 BE) + port (2 BE) +
  // wire-form target name (length-octet + label bytes, root 0x00 terminator).
  // MUST use the same wire-form encoding the one decoder yields for an inbound
  // SRV under `RdataForm::FOLDED`. Using dot-joined plain bytes here while the
  // decoder uses wire-form means SRV KAS hints never match — the hashes diverge.
  {
    scratch.clear();
    scratch.extend_from_slice(&records.priority().to_be_bytes());
    scratch.extend_from_slice(&records.weight().to_be_bytes());
    scratch.extend_from_slice(&records.port().to_be_bytes());
    super::proposal::write_canonical_wire_name(records.host().as_str(), &mut scratch);
    if !hint_matches(ResourceType::Srv, &scratch) {
      // SRV — unique record: set cache-flush bit (RFC 6762 §10.2).
      b.push_srv_answer(
        records.instance(),
        records.ttl_secs(),
        records.priority(),
        records.weight(),
        records.port(),
        records.host(),
        true,
      )?;
      emitted.srv = true;
    }
  }

  // TXT — canonical: length-prefixed segments verbatim (matches wire form,
  // including the §6.1 single-empty-string form when there are no segments).
  {
    scratch.clear();
    write_canonical_txt(records.txt_segments(), &mut scratch);
    if !hint_matches(ResourceType::Txt, &scratch) {
      // TXT — unique record: set cache-flush bit.
      b.push_txt_answer(
        records.instance(),
        records.ttl_secs(),
        records.txt_segments(),
        true,
      )?;
      emitted.txt = true;
    }
  }

  // A records (one per address) — canonical: 4 raw octets.
  for a in records.a_addrs_slice() {
    let rdata = a.octets();
    if !hint_matches(ResourceType::A, &rdata) {
      // A — unique record: set cache-flush bit.
      b.push_a_answer(records.host(), records.ttl_secs(), *a, true)?;
      emitted.a.push(*a);
    }
  }

  // AAAA records — canonical: 16 raw octets.
  for a in records.aaaa_addrs_slice() {
    let rdata = a.octets();
    if !hint_matches(ResourceType::AAAA, &rdata) {
      // AAAA — unique record: set cache-flush bit.
      b.push_aaaa_answer(records.host(), records.ttl_secs(), *a, true)?;
      emitted.aaaa.push(*a);
    }
  }

  // RFC 6762 §6.1 negative responses (Additional section). Only ride along when
  // at least one positive answer survived §7.1 suppression: an all-suppressed
  // response is header-only and the caller drops it (it keys the send decision on
  // `emitted.is_empty()`), so a lone NSEC there would never reach the wire — and
  // a querier that already holds every record we own does not need it.
  //
  // It is not a goodbye-able owned record, so it changes neither `is_empty` nor
  // what a §10.1 goodbye withdraws — but it IS a record identity this endpoint
  // put on its instance name, so it is reported, and reported only when the
  // best-effort push actually kept it.
  if !emitted.is_empty() {
    emitted.nsec = push_service_nsec(&mut b, records);
  }

  let n = b.finish()?;
  Ok((n, emitted))
}

/// Multicast destination for outgoing service traffic (IPv4 group + port 5353).
pub(crate) fn multicast_dst() -> SocketAddr {
  SocketAddr::new(IpAddr::V4(MDNS_IPV4_GROUP), MDNS_PORT)
}

#[cfg(test)]
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(
  clippy::unwrap_used,
  clippy::indexing_slicing,
  clippy::panic,
  clippy::arithmetic_side_effects,
  clippy::integer_division
)]
mod tests;

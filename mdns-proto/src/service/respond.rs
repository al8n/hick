//! Assemble outgoing probes, announcements, and responses.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{
  constants::{MDNS_IPV4_GROUP, MDNS_PORT},
  error::EncodeError,
  records::ServiceRecords,
  wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, Rdata, ResourceClass, ResourceType},
};

/// A record's rdata reduced to its IDENTITY — the bytes that answer "are these
/// two records the same record", for §7.1 known-answer suppression and the §9
/// identical-rdata screen.
///
/// The canonical form is the same regardless of whether the rdata was read from
/// a compressed wire message or assembled locally, so that storage (from an
/// incoming `KnownAnswer`) and filtering (of outgoing records) always hash
/// identically. Getting there NORMALISES: SRV targets are lowercased, an empty
/// TXT is rewritten to a single zero-length string.
///
/// # The other one
///
/// [`rdata_for_tiebreak`] has the same signature and answers a different
/// question — which of two proposals sorts later (RFC 6762 §8.2), over the bytes
/// a side actually put on the wire. It decompresses and normalises nothing.
///
/// Picking the wrong one of the pair FAILS SILENTLY on ordinary inputs: the two
/// agree on every all-lowercase name and every non-empty TXT, which covers most
/// fixtures and most real records, and they diverge exactly where a tiebreak has
/// to be right. Choose by the question being asked, never by which one is
/// already imported.
///
/// The result is appended into `scratch`; the returned slice references `scratch`.
///
/// Returns `Err` on any label-iteration error (pointer cycle, forward pointer,
/// truncated name, etc.). Callers should drop the hint/record on error rather
/// than storing a potentially incorrect partial hash.
pub(crate) fn rdata_for_identity<'s>(
  view: &Rdata<'_>,
  scratch: &'s mut std::vec::Vec<u8>,
) -> Result<&'s [u8], crate::error::ParseError> {
  scratch.clear();
  match view {
    Rdata::A(a) => {
      scratch.extend_from_slice(&a.addr().octets());
    }
    Rdata::AAAA(a) => {
      scratch.extend_from_slice(&a.addr().octets());
    }
    Rdata::Ptr(p) => {
      // Lowercase label bytes joined by '.', no length prefixes, no null terminator.
      write_canonical_name(p.target(), scratch)?;
    }
    Rdata::Cname(c) => {
      // CNAME rdata is one domain name — hash it like PTR.
      write_canonical_name(c.target(), scratch)?;
    }
    Rdata::Srv(s) => {
      // priority (2 BE) + weight (2 BE) + port (2 BE) + wire-form target name.
      // Wire form: length-octet + label bytes, repeated, terminated by 0x00.
      // This matches the encoding used in compare_rr_sets_we_lose for our own
      // SRV records, ensuring bytewise symmetry between our side and peer side.
      scratch.extend_from_slice(&s.priority().to_be_bytes());
      scratch.extend_from_slice(&s.weight().to_be_bytes());
      scratch.extend_from_slice(&s.port().to_be_bytes());
      write_canonical_wire_name(s.target(), scratch)?;
    }
    Rdata::Txt(t) => {
      // Raw wire bytes (length-prefixed segments); no compression in TXT rdata.
      let mut wrote_any = false;
      for seg in t.segments() {
        let seg = seg?;
        #[allow(clippy::cast_possible_truncation)]
        scratch.push(seg.len() as u8);
        scratch.extend_from_slice(seg);
        wrote_any = true;
      }
      // normalize an empty TXT to a single zero-length string (one
      // 0x00), so a peer's empty TXT — whether sent compliantly as a single
      // empty string or (non-compliantly) as empty rdata — canonicalizes to the
      // same bytes as our own empty TXT. Keeps tiebreak / §9 conflict / KAS
      // comparisons symmetric (RFC 6763 §6.1).
      if !wrote_any {
        scratch.push(0);
      }
    }
    Rdata::Nsec(n) => {
      // For NSEC we use the raw type-bitmap bytes (next_name is compression-
      // sensitive so we skip it, similar to "Other" fallback).
      scratch.extend_from_slice(n.type_bitmap_slice());
    }
    Rdata::Other(bytes) => {
      scratch.extend_from_slice(bytes);
    }
  }
  Ok(scratch.as_slice())
}

/// Append the canonical wire form of a TXT record's rdata to `out`: each
/// segment as a length-octet followed by its bytes, in order.
///
/// RFC 6763 §6.1: a TXT record MUST contain at least one string, so when there
/// are NO segments the canonical form is a single zero-length string (one 0x00
/// byte). This MUST match the wire encoding produced by
/// `MessageBuilder::push_txt_answer` / `push_txt_authority`, so the local TXT
/// canonical used for §8.2 tiebreak, §9 conflict comparison, and KAS-hint
/// matching stays byte-symmetric with what a peer actually receives (a peer's
/// compliant empty TXT — a single 0x00 — canonicalizes to the same bytes via
/// `rdata_for_identity`).
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

/// Write the labels of `name` into `out` in DNS wire form:
/// `length_byte label_bytes ... 0x00`. Each label byte is lowercased.
/// Propagates any [`crate::error::ParseError`] from the label iterator
/// (pointer cycle, forward pointer, truncation, etc.).
///
/// This is used for SRV target encoding in `rdata_for_identity` so that
/// the peer-side canonical bytes are byte-identical to what
/// `write_canonical_wire_name` in `mod.rs` produces for our own SRV records.
fn write_canonical_wire_name(
  name: &crate::wire::NameRef<'_>,
  out: &mut std::vec::Vec<u8>,
) -> Result<(), crate::error::ParseError> {
  for label in name.labels() {
    let label = label?;
    if label.is_empty() {
      // Empty label = root; stop (root terminator added below)
      break;
    }
    let len = label.len().min(63);
    #[allow(clippy::cast_possible_truncation)]
    out.push(len as u8);
    for &b in label.iter().take(63) {
      out.push(b.to_ascii_lowercase());
    }
  }
  out.push(0); // root terminator
  Ok(())
}

/// Write `name` into `out` in uncompressed wire form, PRESERVING CASE.
///
/// The RFC 6762 §8.2 tiebreak's counterpart to [`write_canonical_wire_name`],
/// which lowercases. See [`rdata_for_tiebreak`] for why the two must differ.
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

/// A PEER record's rdata as RFC 6762 §8.2 compares it: the bytes that peer put
/// on the wire, with embedded names decompressed and nothing else changed.
///
/// # Why this is not [`rdata_for_identity`]
///
/// §8.2 compares "raw comparison of the binary content of the rdata without
/// regard for meaning or structure", and the ONLY transformation it mandates is
/// decompression: "In the case of resource records containing rdata that is
/// subject to name compression, the names MUST be uncompressed before
/// comparison."
///
/// The identity canonicalizer answers a different question — "are these two
/// records the same record" — and so lowercases SRV targets and rewrites an
/// empty TXT to a single zero-length string. Both are right for identity and
/// wrong for the tiebreak, because the tiebreak only resolves a name if BOTH
/// hosts compute the same function over the same two lists. Normalising the
/// peer's bytes while a byte-comparing peer does not normalise ours makes the
/// two sides disagree:
///
/// | our target `m.local`, peer's `Z.local` | compares | verdict |
/// |---|---|---|
/// | peer, raw | `Z`(0x5A) vs `m`(0x6D), theirs earlier | peer loses |
/// | us, normalising | `m`(0x6D) vs `z`(0x7A), ours earlier | we lose |
///
/// Both abdicate; the mirror case gives two owners.
///
/// The two have the SAME SIGNATURE and agree on every all-lowercase name and
/// every non-empty TXT, so calling the wrong one compiles, passes, and stays
/// wrong until a mixed-case target or an empty TXT turns up. Two fixtures had
/// already done exactly that.
///
/// # The rule is per SIDE, not "raw everywhere"
///
/// EACH SIDE COMPARES THE BYTES THAT SIDE PUT ON THE WIRE. This function is the
/// peer's side. OUR side keeps lowercasing — see `Service::our_proposal` — and
/// that is not an inconsistency: [`crate::wire::MessageBuilder`]'s `write_name`
/// lowercases on transmit, so lowercased bytes ARE what we send, and a peer
/// comparing against us compares those. Making our side "raw" too would make our
/// comparison bytes differ from our own wire bytes and open a second asymmetry
/// while looking like a fix.
///
/// LOAD-BEARING COUPLING: this correctness argument depends on
/// `MessageBuilder::write_name` lowercasing. If transmission ever stops
/// lowercasing, `Service::our_proposal` must stop lowercasing with it, or the
/// two sides diverge again.
pub(crate) fn rdata_for_tiebreak<'s>(
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
    Rdata::Nsec(n) => scratch.extend_from_slice(n.type_bitmap_slice()),
    Rdata::Other(bytes) => scratch.extend_from_slice(bytes),
  }
  Ok(scratch.as_slice())
}

/// Write the labels of `name` into `out` as lowercased bytes joined by `'.'`.
/// No length prefixes and no trailing dot are emitted.
/// Propagates any [`crate::error::ParseError`] from the label iterator
/// (pointer cycle, forward pointer, truncation, etc.).
#[allow(dead_code)]
fn write_canonical_name(
  name: &crate::wire::NameRef<'_>,
  out: &mut std::vec::Vec<u8>,
) -> Result<(), crate::error::ParseError> {
  let mut first = true;
  for label in name.labels() {
    let label = label?;
    if !first {
      out.push(b'.');
    }
    for &b in label {
      out.push(b.to_ascii_lowercase());
    }
    first = false;
  }
  Ok(())
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
/// INSTANCE name to the Additional section, asserting the exact set of record
/// types that exist there — `{SRV, TXT}`. A querier asking the instance name
/// for any other type then receives an authoritative "no such record" instead
/// of waiting out a retransmission timeout. The NSEC "Next Domain Name" is the
/// owner name itself (§6.1), and the cache-flush bit is set (the instance SRV
/// and TXT are unique records, §10.2).
///
/// Only the instance NSEC is emitted — deliberately NOT a host NSEC. The
/// instance name is owned by exactly one service (a duplicate instance name is
/// a §9 conflict that triggers a rename), so `{SRV, TXT}` is provably the
/// complete RRset and the negative is always accurate. The HOST name, by
/// contrast, can be shared by several local services that advertise DIFFERENT
/// address families (e.g. one IPv4-only, one IPv6-only — see the shared-host
/// goodbye logic). This per-service encoder sees only its own `ServiceRecords`,
/// so it cannot prove the host's complete address-family set; emitting a
/// cache-flushed host NSEC from that partial view could publish a false
/// negative (deny AAAA while a sibling actually owns it). Proving host
/// completeness needs endpoint-wide union state the proto layer does not have,
/// so the host NSEC is omitted rather than risk an inaccurate authoritative
/// denial.
///
/// Best-effort: the NSEC is an optional hint, so if it does not fit
/// the remaining buffer the builder is rolled back to before it and the
/// positive answers already written are sent unchanged — adding the hint must
/// never turn a deliverable response into a dropped one.
fn push_service_nsec<const COMP_N: usize>(
  b: &mut MessageBuilder<'_, COMP_N>,
  records: &ServiceRecords,
) {
  let checkpoint = b.checkpoint();
  if b
    .push_nsec_additional(
      records.instance(),
      records.ttl_secs(),
      &[ResourceType::Srv.to_u16(), ResourceType::Txt.to_u16()],
      true,
    )
    .is_err()
  {
    b.restore(checkpoint);
  }
}

/// Write an unsolicited announcement: SRV, TXT, A, AAAA records.
pub(crate) fn write_announce(
  records: &ServiceRecords,
  out: &mut [u8],
) -> Result<usize, EncodeError> {
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
  push_service_nsec(&mut b, records);
  b.finish()
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
  // went on the wire (previously misclassified as instance-XOR-host by
  // the echoed question name, under/over-withdrawing on a later goodbye).
  let emitted = EmittedRecords {
    ptr: true,
    srv: true,
    txt: true,
    a: records.a_addrs_slice().to_vec(),
    aaaa: records.aaaa_addrs_slice().to_vec(),
    subtypes: !records.subtype_names().is_empty(),
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
#[derive(Clone, Debug, Default)]
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
}

impl EmittedRecords {
  /// True when nothing positive-TTL reached the wire (every record was §7.1
  /// suppressed → a header-only response): the caller must not send it and
  /// latches no goodbye ownership.
  pub fn is_empty(&self) -> bool {
    !self.ptr
      && !self.srv
      && !self.txt
      && !self.subtypes
      && self.a.is_empty()
      && self.aaaa.is_empty()
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
  ) -> Self {
    Self {
      ptr,
      srv,
      txt,
      a,
      aaaa,
      subtypes,
    }
  }

  /// OR another report's INSTANCE records (PTR/SRV/TXT/subtypes) into this one.
  ///
  /// Ownership is a union of what reached the wire, so merging two reports for
  /// the SAME name is the same operation the goodbye latch performs. Host
  /// addresses are deliberately not merged: the only caller is the RFC 6763 §9
  /// rename handoff, which withdraws instance records exclusively (the host name
  /// is invariant across an instance rename).
  pub(crate) fn merge_instance(&mut self, other: &Self) {
    self.ptr |= other.ptr;
    self.srv |= other.srv;
    self.txt |= other.txt;
    self.subtypes |= other.subtypes;
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

  // PTR — canonical: lowercase label bytes joined by '.', no length prefixes.
  {
    scratch.clear();
    for (i, label) in records
      .instance()
      .as_str()
      .trim_end_matches('.')
      .split('.')
      .enumerate()
    {
      if i > 0 {
        scratch.push(b'.');
      }
      for &b in label.as_bytes() {
        scratch.push(b.to_ascii_lowercase());
      }
    }
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
  // MUST use the same wire-form encoding as rdata_for_identity
  // (which parses incoming SRV records via write_canonical_wire_name). Using
  // dot-joined plain bytes here while rdata_for_identity uses wire-form
  // means SRV KAS hints never match — the hashes diverge.
  {
    scratch.clear();
    scratch.extend_from_slice(&records.priority().to_be_bytes());
    scratch.extend_from_slice(&records.weight().to_be_bytes());
    scratch.extend_from_slice(&records.port().to_be_bytes());
    super::write_canonical_wire_name(records.host().as_str(), &mut scratch);
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
  // NSEC is not a goodbye-able owned record, so it stays out of `emitted`.
  if !emitted.is_empty() {
    push_service_nsec(&mut b, records);
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

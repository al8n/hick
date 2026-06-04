//! Assemble outgoing probes, announcements, and responses.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{
  constants::{MDNS_IPV4_GROUP, MDNS_PORT},
  error::EncodeError,
  records::ServiceRecords,
  wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, Rdata, ResourceClass, ResourceType},
};

/// Build a canonical byte representation of a record's rdata for use in
/// hashing (KAS-suppression). The canonical form is the same regardless of
/// whether the rdata was read from a compressed wire message or assembled
/// locally, so that storage (from an incoming `KnownAnswer`) and filtering
/// (of outgoing records) always hash identically.
///
/// The result is appended into `scratch`; the returned slice references `scratch`.
///
/// Returns `Err` on any label-iteration error (pointer cycle, forward pointer,
/// truncated name, etc.). Callers should drop the hint/record on error rather
/// than storing a potentially incorrect partial hash.
pub(crate) fn canonical_rdata_for_hash<'s>(
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
/// `canonical_rdata_for_hash`).
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
/// This is used for SRV target encoding in `canonical_rdata_for_hash` so that
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
  // TXT — collect segments into a Vec to avoid lifetime issues with the closure
  let txt: std::vec::Vec<std::vec::Vec<u8>> = records.txt_segments().map(|s| s.to_vec()).collect();
  b.push_txt_authority(records.instance(), records.ttl_secs(), &txt)?;
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
  let txt: std::vec::Vec<std::vec::Vec<u8>> = records.txt_segments().map(|s| s.to_vec()).collect();
  b.push_txt_answer(records.instance(), records.ttl_secs(), &txt, true)?;
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
  let txt: std::vec::Vec<std::vec::Vec<u8>> = records.txt_segments().map(|s| s.to_vec()).collect();
  b.push_txt_answer(records.instance(), ttl, &txt, false)?;
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
/// EXISTING [`MessageBuilder`]. Factored out of [`write_goodbye`] so a single
/// goodbye datagram can withdraw more than one name (the current instance + an
/// in-flight rename's OLD instance) in the SAME message — see
/// [`write_goodbye_with_rename`].
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

/// Write a goodbye for the CURRENT instance (per-record + host-address selected,
/// exactly like [`write_goodbye`]) and, when `rename` is `Some`, ALSO append the
/// OLD instance name's TTL=0 PTR/SRV/TXT/subtype withdrawals into the SAME
/// datagram.
///
/// This is the teardown-during-rename path: after a §9 conflict
/// rename A→B the service re-announces B and confirms B's instance + host
/// records on the wire while A's rename goodbye is still draining (spaced
/// resends). A retire/unregister in that window must withdraw BOTH — B's current
/// records (so they don't linger until TTL) AND A's old instance records (so the
/// renamed-away name doesn't ghost). Both go into one message: the current
/// goodbye first, then the old-name instance records appended (TTL=0). The
/// old-name records are instance-only — a rename never withdraws host A/AAAA
/// (the host name is invariant across an instance rename).
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_goodbye_with_rename(
  records: &ServiceRecords,
  out: &mut [u8],
  include_ptr: bool,
  include_srv: bool,
  include_txt: bool,
  include_subtypes: bool,
  a_addrs: impl Iterator<Item = Ipv4Addr>,
  aaaa_addrs: impl Iterator<Item = Ipv6Addr>,
  rename: Option<(&ServiceRecords, &EmittedRecords)>,
) -> Result<usize, EncodeError> {
  let header = Header::new().with_flags(
    crate::wire::Flags::new()
      .with_response()
      .with_authoritative(),
  );
  let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> = MessageBuilder::try_new(out, header)?;
  // Current instance + (sibling-filtered) host records.
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
  // The OLD instance name's records (instance-only, no host A/AAAA) appended
  // into the SAME message — mirrors `write_rename_goodbye`'s per-record select.
  if let Some((old_records, owned)) = rename {
    push_goodbye_records(
      &mut b,
      old_records,
      owned.ptr,
      owned.srv,
      owned.txt,
      owned.subtypes,
      core::iter::empty(),
      core::iter::empty(),
    )?;
  }
  b.finish()
}

/// Write a RENAME goodbye: withdraws ONLY the instance
/// records the OLD name actually advertised — `owned.ptr` / `owned.srv` /
/// `owned.txt` (PTR/SRV/TXT, all TTL 0). §7.1 known-answer suppression may have
/// put only a SUBSET of them on the wire before the rename, so withdrawing all
/// three unconditionally could flush a peer's matching same-name record this
/// responder never sent. It deliberately OMITS the host A/AAAA: a conflict
/// rename invalidates only the instance name, while the host address records
/// remain valid (the renamed service, and any other local service sharing the
/// host name, still use them).
#[inline]
pub(crate) fn write_rename_goodbye(
  records: &ServiceRecords,
  owned: &EmittedRecords,
  out: &mut [u8],
) -> Result<usize, EncodeError> {
  write_goodbye(
    records,
    out,
    owned.ptr,
    owned.srv,
    owned.txt,
    owned.subtypes,
    core::iter::empty(),
    core::iter::empty(),
  )
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
  // MUST use the same wire-form encoding as canonical_rdata_for_hash
  // (which parses incoming SRV records via write_canonical_wire_name). Using
  // dot-joined plain bytes here while canonical_rdata_for_hash uses wire-form
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
    let txt: std::vec::Vec<std::vec::Vec<u8>> =
      records.txt_segments().map(|s| s.to_vec()).collect();
    if !hint_matches(ResourceType::Txt, &scratch) {
      // TXT — unique record: set cache-flush bit.
      b.push_txt_answer(records.instance(), records.ttl_secs(), &txt, true)?;
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
mod tests {
  use super::canonical_rdata_for_hash;
  use crate::wire::{A, AAAA, Ptr, Rdata, Srv, Txt};

  #[test]
  fn canonical_a_is_4_bytes() {
    let a = A::try_from_rdata(&[192, 168, 1, 10]).unwrap();
    let mut scratch = std::vec::Vec::new();
    let out = canonical_rdata_for_hash(&Rdata::A(a), &mut scratch).unwrap();
    assert_eq!(out, [192u8, 168, 1, 10].as_slice());
  }

  #[test]
  fn write_announce_filtered_reports_emitted_groups() {
    // the encoder must report which owner groups it actually put on
    // the wire, so the caller latches goodbye ownership only for those — a
    // known-answer-suppressed response must NOT be treated as advertising
    // records it omitted.
    let mut r = crate::records::ServiceRecords::new(
      crate::Name::try_from_str("_ipp._tcp.local.").unwrap(),
      crate::Name::try_from_str("p._ipp._tcp.local.").unwrap(),
      crate::Name::try_from_str("h.local.").unwrap(),
      631,
      120,
    );
    r.add_a(core::net::Ipv4Addr::new(192, 168, 1, 1));
    let mut buf = [0u8; 1500];

    // Nothing suppressed → every instance record + the host address emitted.
    let (_, e) = super::write_announce_filtered(&r, &mut buf, |_, _| false).unwrap();
    assert!(
      e.ptr && e.srv && e.txt && e.a == [core::net::Ipv4Addr::new(192, 168, 1, 1)],
      "all records: every record reported emitted"
    );

    // Suppress only A/AAAA → instance records emitted, no host address.
    let (_, e) = super::write_announce_filtered(&r, &mut buf, |rt, _| {
      matches!(
        rt,
        crate::wire::ResourceType::A | crate::wire::ResourceType::AAAA
      )
    })
    .unwrap();
    assert!(
      e.ptr && e.srv && e.txt && e.a.is_empty() && e.aaaa.is_empty(),
      "host suppressed: only instance records emitted"
    );

    // Suppress only SRV → PTR + TXT + A emitted, SRV NOT (per-record case).
    let (_, e) = super::write_announce_filtered(&r, &mut buf, |rt, _| {
      matches!(rt, crate::wire::ResourceType::Srv)
    })
    .unwrap();
    assert!(
      e.ptr && !e.srv && e.txt && e.a == [core::net::Ipv4Addr::new(192, 168, 1, 1)],
      "SRV suppressed: PTR/TXT/A emitted, SRV not"
    );

    // Suppress everything → nothing emitted (a header-only response).
    let (_, e) = super::write_announce_filtered(&r, &mut buf, |_, _| true).unwrap();
    assert!(
      e.is_empty(),
      "all suppressed: nothing emitted (header-only)"
    );
  }

  #[test]
  fn canonical_aaaa_is_16_bytes() {
    use core::net::Ipv6Addr;
    let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let rdata = addr.octets();
    let rec = AAAA::try_from_rdata(&rdata).unwrap();
    let mut scratch = std::vec::Vec::new();
    let out = canonical_rdata_for_hash(&Rdata::AAAA(rec), &mut scratch).unwrap();
    assert_eq!(out.len(), 16);
    assert_eq!(out, &addr.octets());
  }

  #[test]
  fn canonical_txt_roundtrips_wire_form() {
    // Wire form: 0x07 "key=val" 0x01 "x"
    let raw: &[u8] = &[7, b'k', b'e', b'y', b'=', b'v', b'a', b'l', 1, b'x'];
    let txt = Txt::from_rdata(raw);
    let mut scratch = std::vec::Vec::new();
    let out = canonical_rdata_for_hash(&Rdata::Txt(txt), &mut scratch).unwrap();
    assert_eq!(out, raw, "canonical TXT must match wire bytes verbatim");
  }

  #[test]
  fn canonical_txt_malformed_segment_returns_err() {
    // Segment claims 10 bytes but only 2 follow — should return Err, not silently truncate.
    let raw: &[u8] = &[10, b'a', b'b'];
    let txt = Txt::from_rdata(raw);
    let mut scratch = std::vec::Vec::new();
    assert!(
      canonical_rdata_for_hash(&Rdata::Txt(txt), &mut scratch).is_err(),
      "malformed TXT segment must produce an Err"
    );
  }

  #[test]
  fn canonical_ptr_is_lowercase_dotted_labels() {
    // Build a minimal DNS message containing the PTR rdata "MyPrinter._ipp._tcp.local."
    // as uncompressed length-prefixed labels so Ptr can parse it.
    let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
    for label in &[b"MyPrinter".as_slice(), b"_ipp", b"_tcp", b"local"] {
      msg.push(label.len() as u8);
      msg.extend_from_slice(label);
    }
    msg.push(0u8); // root label
    let rdata_len = msg.len();
    let ptr = Ptr::try_from_message(&msg, 0, rdata_len).unwrap();
    let mut scratch = std::vec::Vec::new();
    let out = canonical_rdata_for_hash(&Rdata::Ptr(ptr), &mut scratch).unwrap();
    // Expected: "myprinter._ipp._tcp.local" (lowercase, dot-separated, no trailing dot)
    assert_eq!(out, b"myprinter._ipp._tcp.local".as_slice());
  }

  #[test]
  fn canonical_ptr_forward_pointer_returns_err() {
    // Build a message where the PTR rdata is a compression pointer that points
    // forward (to an offset >= itself). NameRef::try_parse accepts it (it only
    // checks that both pointer bytes exist), but NameLabels::next() rejects it
    // with ParseError::PointerForward. This is the canonical example of a
    // malformed peer-supplied name that the old `.flatten()` would silently
    // swallow, producing an empty hash.
    //
    // Layout: [ 0xC0, 0x00 ]  — a pointer at offset 0 that targets offset 0.
    // target (0) >= cursor (0) → PointerForward error during label iteration.
    let msg: std::vec::Vec<u8> = std::vec![0xC0u8, 0x00];
    let ptr = Ptr::try_from_message(&msg, 0, msg.len()).unwrap();
    let mut scratch = std::vec::Vec::new();
    assert!(
      canonical_rdata_for_hash(&Rdata::Ptr(ptr), &mut scratch).is_err(),
      "forward compression pointer in PTR target must produce an Err"
    );
  }

  #[test]
  fn canonical_srv_starts_with_priority_weight_port() {
    // Build SRV rdata: priority=0, weight=0, port=631, target="printer.local."
    let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
    msg.extend_from_slice(&0u16.to_be_bytes()); // priority
    msg.extend_from_slice(&0u16.to_be_bytes()); // weight
    msg.extend_from_slice(&631u16.to_be_bytes()); // port
    for label in &[b"printer".as_slice(), b"local"] {
      msg.push(label.len() as u8);
      msg.extend_from_slice(label);
    }
    msg.push(0u8); // root
    let rdata_len = msg.len();
    let srv = Srv::try_from_message(&msg, 0, rdata_len).unwrap();
    let mut scratch = std::vec::Vec::new();
    let out = canonical_rdata_for_hash(&Rdata::Srv(srv), &mut scratch).unwrap();
    // First 6 bytes: priority(0,0) weight(0,0) port(2,119 = 631 big-endian)
    assert_eq!(&out[..2], &0u16.to_be_bytes()); // priority
    assert_eq!(&out[2..4], &0u16.to_be_bytes()); // weight
    assert_eq!(&out[4..6], &631u16.to_be_bytes()); // port
    // Rest: wire-form target name "printer.local." →
    // \x07printer\x05local\x00  (length-prefixed labels, root terminator)
    let expected: &[u8] = &[
      7, b'p', b'r', b'i', b'n', b't', b'e', b'r', 5, b'l', b'o', b'c', b'a', b'l', 0,
    ];
    assert_eq!(
      &out[6..],
      expected,
      "SRV target must use wire-form label encoding"
    );
  }

  /// RFC 6762 §8.1: probe messages MUST carry the proposed unique records in
  /// the authority section. Verify `write_probe` produces a packet with
  /// question count=1, unicast-response bit set, and authority count>=3
  /// (SRV + TXT + at least one A record).
  #[test]
  fn write_probe_includes_authority_records_and_unicast_bit() {
    use crate::{
      Name,
      records::ServiceRecords,
      wire::{MessageReader, ResourceType},
    };
    use core::net::Ipv4Addr;

    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 631, 120);
    recs.add_a(Ipv4Addr::new(192, 168, 1, 5));

    let mut buf = [0u8; 512];
    let n = super::write_probe(&recs, &mut buf).unwrap();
    let msg = MessageReader::try_parse(&buf[..n]).unwrap();

    assert_eq!(
      msg.header().question_count(),
      1,
      "probe must have exactly 1 question"
    );
    // SRV + TXT + A = 3 authority records minimum.
    assert!(
      msg.header().authority_count() >= 3,
      "probe with an A address must have >=3 authority records, got {}",
      msg.header().authority_count()
    );

    // Verify the question uses the unicast-response bit (RFC §5.4).
    let q = msg.questions().next().unwrap().unwrap();
    assert!(
      q.unicast_response_requested(),
      "probe question must have the unicast-response bit set"
    );

    // Verify authority contains at least one SRV record.
    let has_srv = msg.authority().any(|r| {
      r.map(|rec| rec.rtype() == ResourceType::Srv)
        .unwrap_or(false)
    });
    assert!(
      has_srv,
      "probe authority section must contain an SRV record"
    );
  }

  /// RFC 4034 §4.1.2 window-block-0 membership test for an NSEC type bitmap.
  fn bitmap_has(slice: &[u8], t: u16) -> bool {
    if slice.len() < 2 || slice[0] != 0 {
      return false;
    }
    let len = slice[1] as usize;
    let bytes = &slice[2..(2 + len).min(slice.len())];
    let byte_idx = (t / 8) as usize;
    let mask = 0x80u8 >> (t % 8);
    bytes.get(byte_idx).is_some_and(|b| b & mask != 0)
  }

  fn dotted(nr: &crate::wire::NameRef<'_>) -> std::string::String {
    let mut s = std::string::String::new();
    for label in nr.labels() {
      let label = label.unwrap();
      if label.is_empty() {
        break;
      }
      if !s.is_empty() {
        s.push('.');
      }
      for &b in label {
        s.push(b.to_ascii_lowercase() as char);
      }
    }
    s
  }

  /// RFC 6762 §6.1: an announcement asserts the INSTANCE RRset via an NSEC
  /// record (Additional section) — a querier asking the instance name for any
  /// type other than SRV/TXT then gets an authoritative negative instead of
  /// waiting out a retransmit. Verifies the single NSEC is the instance NSEC
  /// ({SRV, TXT}, not A/AAAA), its next-name equals the owner, cache-flush is
  /// set, and that NO host NSEC is emitted: the per-service encoder cannot prove
  /// the shared host's complete address set, so it must not publish a host
  /// negative a same-host sibling could contradict.
  #[test]
  fn write_announce_emits_instance_nsec_negative_response() {
    use crate::{
      Name,
      records::ServiceRecords,
      wire::{MessageReader, Rdata, ResourceType},
    };
    use core::net::Ipv4Addr;

    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
    recs.add_a(Ipv4Addr::new(192, 168, 1, 5)); // IPv4 only.

    let mut buf = [0u8; 1500];
    let n = super::write_announce(&recs, &mut buf).unwrap();
    let msg = MessageReader::try_parse(&buf[..n]).unwrap();

    assert_eq!(
      msg.header().additional_count(),
      1,
      "exactly one NSEC — instance only, no host NSEC"
    );

    let r = msg.additional().next().unwrap().unwrap();
    assert_eq!(r.rtype(), ResourceType::Nsec);
    assert_eq!(
      dotted(r.name()),
      "myprinter._ipp._tcp.local",
      "the sole NSEC is owned by the instance name, never the host"
    );
    let Rdata::Nsec(nsec) = r.rdata_view().unwrap() else {
      panic!("additional must parse as NSEC");
    };
    assert!(
      nsec.next_name().equals_ignoring_case(r.name()),
      "§6.1: NSEC next-name equals the owner"
    );
    assert!(
      r.cache_flush(),
      "instance SRV/TXT are unique → cache-flush set"
    );
    let bm = nsec.type_bitmap_slice();
    assert!(bitmap_has(bm, 33), "instance NSEC asserts SRV (33)");
    assert!(bitmap_has(bm, 16), "instance NSEC asserts TXT (16)");
    assert!(!bitmap_has(bm, 1), "instance NSEC must NOT assert A");
    assert!(!bitmap_has(bm, 28), "instance NSEC must NOT assert AAAA");

    // no NSEC may be owned by the (shared) host name.
    for add in msg.additional() {
      assert_ne!(
        dotted(add.unwrap().name()),
        "printer.local",
        "must not emit a host-name NSEC from partial per-service state"
      );
    }
  }

  /// The §6.1 instance NSEC also rides on the KAS-filtered response path, and
  /// stays instance-only even for a dual-stack host (no host NSEC).
  #[test]
  fn write_announce_filtered_emits_instance_nsec_only() {
    use crate::{
      Name,
      records::ServiceRecords,
      wire::{MessageReader, Rdata},
    };
    use core::net::{Ipv4Addr, Ipv6Addr};

    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("p._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
    recs.add_a(Ipv4Addr::new(192, 168, 1, 5));
    recs.add_aaaa(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

    let mut buf = [0u8; 1500];
    let (n, _emitted) = super::write_announce_filtered(&recs, &mut buf, |_, _| false).unwrap();
    let msg = MessageReader::try_parse(&buf[..n]).unwrap();
    assert_eq!(msg.header().additional_count(), 1, "instance NSEC only");

    let r = msg.additional().next().unwrap().unwrap();
    assert_eq!(
      dotted(r.name()),
      "p._ipp._tcp.local",
      "owner is the instance"
    );
    let Rdata::Nsec(nsec) = r.rdata_view().unwrap() else {
      panic!("additional must be NSEC");
    };
    let bm = nsec.type_bitmap_slice();
    assert!(
      bitmap_has(bm, 33) && bitmap_has(bm, 16),
      "asserts SRV + TXT"
    );
    for add in msg.additional() {
      assert_ne!(
        dotted(add.unwrap().name()),
        "h.local",
        "no host NSEC even for a dual-stack host"
      );
    }
  }

  /// the §6.1 NSEC is an OPTIONAL Additional-section hint. When the
  /// positive answers fit but the NSEC does not, the responder must still send
  /// the answers (NSEC rolled back/omitted) — adding the hint must never turn a
  /// deliverable response into a dropped one.
  #[test]
  fn nsec_omitted_when_it_does_not_fit_but_answers_still_send() {
    use crate::{
      Name,
      records::ServiceRecords,
      wire::{MessageReader, ResourceType},
    };
    use core::net::Ipv4Addr;

    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst, host, 631, 120);
    recs.add_a(Ipv4Addr::new(192, 168, 1, 5));

    // Baseline: full message including the instance NSEC.
    let mut big = [0u8; 1500];
    let n_full = super::write_announce(&recs, &mut big).unwrap();
    let full = MessageReader::try_parse(&big[..n_full]).unwrap();
    assert_eq!(full.header().additional_count(), 1, "baseline NSEC present");
    let answers = full.header().answer_count();

    // A buffer 8 bytes short of the full message: the answers fit, but the
    // ~20-byte NSEC cannot. (NSEC is well over 8 bytes, so this reliably keeps
    // every answer while excluding the hint.)
    let cut = n_full - 8;
    let mut small = std::vec![0u8; cut];
    let n = super::write_announce(&recs, &mut small).unwrap();
    let msg = MessageReader::try_parse(&small[..n]).unwrap();

    assert_eq!(
      msg.header().additional_count(),
      0,
      "NSEC omitted when it does not fit"
    );
    assert_eq!(
      msg.header().answer_count(),
      answers,
      "every positive answer must still be present"
    );
    assert!(
      msg
        .answers()
        .any(|r| r.map(|x| x.rtype() == ResourceType::Srv).unwrap_or(false)),
      "positive SRV answer must survive even when NSEC is dropped"
    );
  }
}

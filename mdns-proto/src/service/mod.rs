//! Service state machine — probing, announcing, response generation.

#[cfg(any(feature = "alloc", feature = "std"))]
mod respond;
mod schedule;
mod state;

/// Which of OUR owner names a known-answer's record name matched. §7.1
/// suppression is per RRset, and an RRset is identified by (name, type, class,
/// rdata). A known-answer with our rtype + rdata but a DIFFERENT owner name is a
/// DIFFERENT RRset and must NOT suppress our record — otherwise a querier could
/// silence our `host.local A x` by sending a same-rdata `_svc._tcp.local A x`.
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KasOwner {
  /// The shared service-type name (owns the PTR).
  ServiceType,
  /// The service instance name (owns SRV + TXT).
  Instance,
  /// The host name (owns A + AAAA).
  Host,
}

/// A single observed known-answer hint. KAS suppression checks records
/// against this list before emitting.
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone, Copy)]
struct KasHint<I> {
  owner: KasOwner,
  rtype: crate::wire::ResourceType,
  rdata_hash: u64,
  expires_at: I,
}

/// Number of KAS hints we'll remember at once (per service).
#[cfg(any(feature = "alloc", feature = "std"))]
const KAS_RING_SIZE: usize = 16;

/// Cap on the number of distinct questioner sources tracked per
/// response cycle.  Mirrors `MAX_PEER_PROBES` — bursts of
/// queries from more than this many distinct sources within one
/// jitter window get the excess sources rejected (no hint storage
/// for them), which is conservative but bounded.
#[cfg(any(feature = "alloc", feature = "std"))]
const MAX_QUESTIONER_SRCS: usize = 8;

/// Maximum legacy unicast responses queued per response cycle. Each
/// distinct legacy querier gets its own reply; beyond this cap, excess legacy
/// queriers in the same window are dropped (bounded against a flood).
#[cfg(any(feature = "alloc", feature = "std"))]
const MAX_LEGACY_RESPONSES: usize = 8;

/// A pending RFC 6762 §6.7 legacy unicast response: a non-mDNS querier (source
/// port != 5353) gets a direct reply that echoes its query ID + question.
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
struct LegacyResp {
  dst: core::net::SocketAddr,
  query_id: u16,
  /// The matched owned name to echo in the response's question section (our
  /// own canonical name; case-insensitively equal to the querier's qname). For
  /// a meta reply (`is_meta`) this is the `_services._dns-sd._udp.<domain>`
  /// meta-query name.
  name: crate::Name,
  qtype: crate::wire::ResourceType,
  qclass: crate::wire::ResourceClass,
  /// this is an RFC 6763 §9 service-type enumeration reply — emit the
  /// shared meta-PTR (`<meta> -> service_type`) rather than the instance record
  /// set. A legacy resolver isn't on the multicast group, so the §9 reply it
  /// needs must go out as a unicast echo too.
  is_meta: bool,
}

/// Maximum number of peer-probe records buffered per source for a single
/// tiebreak decision (RFC §8.2). Incoming records beyond this cap are silently
/// dropped.
#[cfg(any(feature = "alloc", feature = "std"))]
const MAX_PEER_PROBE_RECORDS: usize = 16;

/// Maximum number of distinct peer sources we track per tiebreak round.
/// Records from sources beyond this cap are silently dropped.
#[cfg(any(feature = "alloc", feature = "std"))]
const MAX_PEER_PROBES: usize = 8;

/// minimum interval between conflict-driven re-probes of an
/// Established/Announcing service (RFC 6762 §9 conflict rate-limiting). A
/// conflict flood cannot reset us to Probing faster than this, so a hostile
/// peer cannot prevent the service from ever (re)establishing.
#[cfg(any(feature = "alloc", feature = "std"))]
const CONFLICT_REPROBE_MIN_INTERVAL: core::time::Duration = core::time::Duration::from_secs(1);

/// how many times the conflict-rename goodbye for the OLD instance
/// name is (re)sent for loss resilience (RFC 6762 §8.4 / §10.1 recommend
/// sending a goodbye more than once). Drained across successive `poll_transmit`
/// calls.
#[cfg(any(feature = "alloc", feature = "std"))]
const RENAME_GOODBYE_SENDS: u8 = 2;

/// spacing between successive conflict-rename goodbyes, so the
/// resends are not drained as a single same-tick burst (which a correlated loss
/// burst could take out together).
#[cfg(any(feature = "alloc", feature = "std"))]
const RENAME_GOODBYE_INTERVAL: core::time::Duration = core::time::Duration::from_secs(1);

/// One record from a peer's simultaneous probe, retained for the RFC §8.2
/// tiebreak comparison (lexicographic comparison of proposed RR sets).
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
struct PeerRecord {
  rtype: crate::wire::ResourceType,
  /// Canonical byte form of the rdata (same encoding used by KAS hashing).
  canonical: std::vec::Vec<u8>,
}

/// A per-source bucket of probe records observed during the current probe round.
/// Each distinct peer source gets its own bucket so that the RFC §8.2 tiebreak
/// compares against each peer independently (we lose if ANY peer wins).
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug)]
struct PeerProbe {
  src: core::net::SocketAddr,
  records: std::vec::Vec<PeerRecord>,
}

/// Write a DNS name in canonical wire form (length-prefixed labels, root
/// terminator). Used for SRV target encoding in RFC §8.2 tiebreak comparison.
/// This produces byte-identical output for both OUR outgoing SRV and for a
/// peer SRV parsed via `canonical_rdata_for_hash`, ensuring the bytewise
/// comparison is correct.
#[cfg(any(feature = "alloc", feature = "std"))]
fn write_canonical_wire_name(name_str: &str, out: &mut std::vec::Vec<u8>) {
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

/// FNV-1a hash of rdata bytes — used to dedupe KAS hints without storing rdata.
#[cfg(any(feature = "alloc", feature = "std"))]
fn hash_rdata(bytes: &[u8]) -> u64 {
  const FNV_BASIS: u64 = 0xcbf29ce484222325;
  const FNV_PRIME: u64 = 0x100000001b3;
  let mut h: u64 = FNV_BASIS;
  for &b in bytes {
    h ^= b as u64;
    h = h.wrapping_mul(FNV_PRIME);
  }
  h
}

#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(unused_imports)]
pub(crate) use respond::multicast_dst;
#[allow(unused_imports)]
pub(crate) use schedule::{announce_deadline, probe_deadline, re_announce_deadline};
pub use state::ServiceState;

#[cfg(any(feature = "alloc", feature = "std"))]
use rand::SeedableRng;

#[cfg(any(feature = "alloc", feature = "std"))]
use crate::error::{HandleTimeoutError, TransmitError};
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::event::{ServiceEvent, ServiceUpdate};
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::records::ServiceRecords;
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::transmit::Transmit;
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::{Instant, Pool, ServiceHandle};

#[cfg(any(feature = "alloc", feature = "std"))]
type Rng = rand::rngs::StdRng;

/// Build a new instance-name string by appending (or replacing) a `-N` suffix
/// on the first DNS label.
///
/// `current` is the full FQDN of the instance (e.g. `"myprinter._ipp._tcp.local."`).
/// `attempt` is the rename counter (1, 2, …).
///
/// For a name like `"myprinter._ipp._tcp.local."` and attempt `2` the result
/// is `"myprinter-2._ipp._tcp.local."`.  Any existing `-N` suffix on the
/// instance label is stripped first so repeated conflicts don't accumulate.
#[cfg(any(feature = "alloc", feature = "std"))]
fn rename_with_suffix(current: &str, attempt: u32) -> std::string::String {
  use std::string::ToString;
  // Strip optional trailing dot so we can work with the plain label sequence.
  let (body, trailing_dot) = match current.strip_suffix('.') {
    Some(b) => (b, true),
    None => (current, false),
  };
  // Split off the first label (the instance name) from the rest of the FQDN.
  let (instance, rest) = match body.split_once('.') {
    Some((i, r)) => (i, Some(r)),
    None => (body, None),
  };
  // Strip any existing "-N" suffix from the instance label.
  let base_instance = match instance.rsplit_once('-') {
    Some((prefix, n)) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => prefix,
    _ => instance,
  };
  let mut out = std::string::String::new();
  out.push_str(base_instance);
  out.push('-');
  out.push_str(&attempt.to_string());
  if let Some(r) = rest {
    out.push('.');
    out.push_str(r);
  }
  if trailing_dot {
    out.push('.');
  }
  out
}

/// RFC 6762 §8.2 tiebreak comparison.
///
/// Returns `true` if WE should lose (i.e. we must rename): the peer's
/// proposed RR set is lexicographically >= ours when both sets are
/// sorted and concatenated in canonical form. A tie (equal sets) also
/// counts as a loss (§8.2.1 — "the host MUST rename itself").
///
/// Compares against EACH peer bucket independently; returns `true` (we lose)
/// if ANY single peer's set is >= ours. This prevents a peer that claims a
/// smaller set from masking a different peer that actually wins.
///
/// The local set is restricted to records owned by the service INSTANCE
/// (SRV + TXT only) per RFC §8.2, which compares records "owned by the
/// conflicting name". A/AAAA records are owned by the host name and are
/// excluded from both sides.
#[cfg(any(feature = "alloc", feature = "std"))]
fn compare_rr_sets_we_lose(
  our: &crate::records::ServiceRecords,
  peer_probes: &[PeerProbe],
) -> bool {
  // Build OUR canonical RR set restricted to SRV + TXT (instance-owned records).
  // RFC §8.2 says compare records owned by the conflicting NAME; the conflicting
  // name is the service instance, which owns SRV and TXT — NOT A/AAAA (those
  // are owned by the host name).
  let mut our_set: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
  // SRV — priority(2 BE) + weight(2 BE) + port(2 BE) + wire-form target name.
  // Wire form: length-octet + label bytes, repeated, terminated by 0x00.
  {
    let mut buf = std::vec::Vec::new();
    buf.extend_from_slice(&crate::wire::ResourceType::Srv.to_u16().to_be_bytes());
    buf.extend_from_slice(&our.priority().to_be_bytes());
    buf.extend_from_slice(&our.weight().to_be_bytes());
    buf.extend_from_slice(&our.port().to_be_bytes());
    write_canonical_wire_name(our.host().as_str(), &mut buf);
    our_set.push(buf);
  }
  // TXT — always include (matches what write_probe emits unconditionally).
  // write_probe sends a TXT authority record even with no segments, so a
  // peer comparing against our probe sees the TXT we sent; omitting it from our
  // local comparison set would bias the tiebreak. An empty TXT
  // canonicalizes (like the wire form) to the rtype prefix + a single
  // zero-length string (one 0x00), so both sides agree byte-for-byte.
  {
    let mut buf = std::vec::Vec::new();
    buf.extend_from_slice(&crate::wire::ResourceType::Txt.to_u16().to_be_bytes());
    respond::write_canonical_txt(our.txt_segments(), &mut buf);
    our_set.push(buf);
  }
  our_set.sort();
  let our_concat: std::vec::Vec<u8> = our_set.into_iter().flatten().collect();

  // For EACH peer bucket: if that peer's sorted set >= ours, we lose.
  for probe in peer_probes {
    let mut peer_set: std::vec::Vec<std::vec::Vec<u8>> = probe
      .records
      .iter()
      .map(|p| {
        let mut buf = std::vec::Vec::new();
        buf.extend_from_slice(&p.rtype.to_u16().to_be_bytes());
        buf.extend_from_slice(&p.canonical);
        buf
      })
      .collect();
    peer_set.sort();
    let peer_concat: std::vec::Vec<u8> = peer_set.into_iter().flatten().collect();
    // We LOSE when peer_concat >= our_concat (tie = loss per §8.2.1).
    if peer_concat >= our_concat {
      return true;
    }
  }
  false
}

/// What kind of transmit is pending for a service.
///
/// Capturing the kind at deadline-fire time (before state is advanced) ensures
/// `poll_transmit` encodes the correct packet type even when state has already
/// transitioned (e.g., Probing(2) → Announcing(0) on the final probe tick).
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PendingTransmitKind {
  /// Send a probe (state was Probing(_) when the deadline fired).
  Probe,
  /// Send an unsolicited announcement (state was Announcing(_) or Established
  /// firing the periodic re-announce deadline). KAS filtering is NOT applied —
  /// RFC 6762 §7.1 known-answer suppression only applies to question responses,
  /// not to unsolicited multicast announcements.
  Announcement,
  /// Send a jittered question response (the response_pending path in Established
  /// or Announcing(_) state). KAS filtering IS applied (RFC 6762 §7.1).
  Response,
}

/// The commit token stamped by `poll_transmit` and resolved by
/// `note_transmit_result`. Unlike [`PendingTransmitKind`] (which is
/// queued at deadline-fire time), this carries what was ACTUALLY encoded, so a
/// response that known-answer-suppression (§7.1) trimmed latches goodbye
/// ownership only for the concrete records it really put on the wire
/// (per record, not per group).
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone)]
enum AwaitingConfirm {
  /// A probe is awaiting its delivery result (§8.1 sequence advance). A probe is
  /// a QUESTION — it advertises no records, so it latches no goodbye ownership.
  Probe,
  /// An unsolicited announcement is awaiting confirmation (§8.3 phase advance).
  /// Carries the concrete records it emitted (a full announcement: all of
  /// PTR/SRV/TXT plus every host address) so a confirmed send latches exactly
  /// those for goodbye ownership.
  Announcement(respond::EmittedRecords),
  /// A question/legacy response is awaiting confirmation. Carries the concrete
  /// records actually emitted (§7.1 KAS may have trimmed any subset), so only
  /// those latch goodbye ownership on a confirmed send.
  Response(respond::EmittedRecords),
  /// A conflict-rename goodbye (TTL=0 withdrawal of the OLD instance records) is
  /// awaiting confirmation. Its resend budget (`pending_rename_goodbye.remaining`)
  /// is spent ONLY on a confirmed send — an all-family-busy attempt re-arms it
  /// instead of consuming the withdrawal. It withdraws records it never
  /// re-advertises, so it latches NO new goodbye ownership.
  RenameGoodbye,
}

/// Goodbye ownership: which CONCRETE records peers may have cached FROM US, and
/// therefore what a graceful goodbye (TTL=0) must withdraw. The granularity is
/// per record — each instance-owned record (PTR/SRV/TXT) independently, and each
/// host-owned address (A/AAAA) independently — matching what
/// [`Service::encode_goodbye`] withdraws (host addresses are further filtered
/// against sibling-retained addresses).
///
/// INVARIANT: a record becomes "advertised" ONLY through a CONFIRMED send that
/// actually emitted THAT record ([`Self::record_emitted`], driven by the
/// encoder's per-record report via `note_transmit_result`). A send that never
/// reaches the link — or whose record was known-answer-suppressed (§7.1) —
/// advertises nothing, so a later goodbye never withdraws a record we did not
/// put on the wire (which could otherwise flush a peer's matching shared
/// record). Per-record (not per-group) granularity closes the over-withdrawal
/// class where §7.1 trims a subset of a group or a legacy reply emits a whole
/// group the per-group latch mis-attributed.
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Default, Clone)]
struct GoodbyeOwnership {
  /// The instance PTR (service-type → instance) has been advertised. RESET on a
  /// conflict rename (the new instance name has not been advertised).
  ptr: bool,
  /// The instance SRV has been advertised. Reset on rename.
  srv: bool,
  /// The instance TXT has been advertised. Reset on rename.
  txt: bool,
  /// The RFC 6763 §7.1 subtype PTRs (`<sub>._sub.<type>` → instance) have been
  /// advertised. Instance-associated (target = instance), so RESET on rename and
  /// withdrawn with the instance records. All-or-nothing — subtype PTRs are not
  /// KAS-filtered, so they are always emitted together.
  subtypes: bool,
  /// Host A addresses advertised FROM US, tracked per address. SURVIVES a
  /// conflict rename: the host name is invariant across instance renames, so
  /// peers keep caching the host records.
  a: std::vec::Vec<core::net::Ipv4Addr>,
  /// Host AAAA addresses advertised FROM US, tracked per address. Survives rename.
  aaaa: std::vec::Vec<core::net::Ipv6Addr>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl GoodbyeOwnership {
  /// Latch the concrete records a confirmed-delivered send actually emitted — the
  /// SOLE way ownership is gained (besides being reset to none on rename).
  fn record_emitted(&mut self, e: &respond::EmittedRecords) {
    self.ptr |= e.ptr();
    self.srv |= e.srv();
    self.txt |= e.txt();
    self.subtypes |= e.subtypes();
    for ip in e.a_slice() {
      if !self.a.contains(ip) {
        self.a.push(*ip);
      }
    }
    for ip in e.aaaa_slice() {
      if !self.aaaa.contains(ip) {
        self.aaaa.push(*ip);
      }
    }
  }
  /// Drop INSTANCE ownership (PTR/SRV/TXT) on a conflict rename; host A/AAAA
  /// ownership persists (the host name does not change on an instance rename).
  #[inline]
  fn reset_instance(&mut self) {
    self.ptr = false;
    self.srv = false;
    self.txt = false;
    self.subtypes = false;
  }
  /// Whether ANY instance-owned record (PTR/SRV/TXT or a subtype PTR) has been
  /// advertised.
  #[inline]
  fn any_instance(&self) -> bool {
    self.ptr || self.srv || self.txt || self.subtypes
  }
  /// Whether ANY host-owned address (A/AAAA) has been advertised.
  #[inline]
  fn any_host(&self) -> bool {
    !self.a.is_empty() || !self.aaaa.is_empty()
  }
}

/// Service state machine. One per registered service.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub struct Service<I, TQ, EV> {
  handle: ServiceHandle,
  state: ServiceState,
  records: ServiceRecords,
  /// The next scheduled lifecycle deadline (probe, announce, re-announce).
  /// Never modified by response scheduling — only advanced by lifecycle logic.
  lifecycle_deadline: Option<I>,
  /// The jittered question-response deadline, if any (RFC 6762 §6).
  /// Independent of `lifecycle_deadline`; whichever is earlier fires first.
  /// Set directly by `handle_event(Question)`; cleared when it fires in
  /// `handle_timeout`. `response_deadline.is_some()` replaces the old
  /// `response_pending` + `response_deadline_active` flags.
  response_deadline: Option<I>,
  probe_count: u8,
  announce_count: u8,
  rename_attempt: u32,
  /// Up to 2 pending transmits (a response can ride alongside an announcement
  /// when both deadlines fire at the same `now`).  `poll_transmit` drains one
  /// per call in queue order, so the driver loop emits both in the same poll
  /// cycle by calling `poll_transmit` until it returns `Ok(None)`.
  pending_transmits: [Option<PendingTransmitKind>; 2],
  rng: Rng,
  pending_tx: TQ,
  pending_updates: EV,
  /// Most-recently-seen `now`, cached for use by `poll_transmit`'s KAS
  /// filtering closure. Updated by both `handle_timeout` and `handle_event`
  /// (`handle_event` now takes `now` directly).
  last_now: Option<I>,
  /// Ring buffer of observed known-answer hints (RFC 6762 §7.1).
  kas_hints: [Option<KasHint<I>>; KAS_RING_SIZE],
  /// Next slot index for writing a new KAS hint (wraps at KAS_RING_SIZE).
  kas_next_slot: usize,
  /// sources that have issued a Question in the current
  /// response cycle.  KAS hints are only accepted from sources in
  /// this set — otherwise an attacker could inject hints during a
  /// legitimate questioner's jitter window and suppress the
  /// response.  Cleared alongside `kas_hints` when the Response
  /// fires.  Bounded by `MAX_QUESTIONER_SRCS`.
  questioner_srcs: std::vec::Vec<core::net::SocketAddr>,
  /// Per-source buckets of peer-proposed records observed during the current
  /// probe round, buffered for RFC §8.2 tiebreak comparison on the next
  /// `handle_timeout` call. Each entry holds records from a distinct peer source
  /// so that the tiebreak compares against each peer independently.
  peer_probes: std::vec::Vec<PeerProbe>,
  /// Set when a tiebreak decision is pending on the next `handle_timeout`.
  tiebreak_pending: bool,
  /// Which owner groups peers may have cached from us, i.e. what a goodbye must
  /// withdraw. The SOLE source of truth for goodbye ownership; see
  /// [`GoodbyeOwnership`] for the invariants (confirmed-send-driven, instance
  /// resets on rename, host persists).
  goodbye: GoodbyeOwnership,
  /// the commit token for the datagram `poll_transmit`
  /// most recently produced — `Some(kind)` while that send is awaiting a
  /// delivery result, `None` otherwise. This is the structural heart of the
  /// confirm-on-send invariant: `poll_transmit` ONLY stamps this token and
  /// advances no lifecycle state; ALL lifecycle progression happens in
  /// [`Self::note_transmit_result`], keyed on the token. Because of that a send
  /// that never reaches the link (all sockets error) advances nothing — neither
  /// the goodbye-ownership latches (`announce_emitted` / `host_advertised`) for
  /// an announcement, nor the probe sequence (RFC 6762 §8.1) for a probe.
  awaiting_confirm: Option<AwaitingConfirm>,
  /// queued legacy unicast responses (RFC 6762 §6.7) for
  /// non-mDNS queriers (source port != 5353). Each is drained by
  /// `poll_transmit` into its own unicast, query-shaped datagram. QU-bit
  /// queriers (§5.4) are on the multicast group and are served by the normal
  /// multicast response, so they do NOT go here. Bounded by
  /// [`MAX_LEGACY_RESPONSES`].
  pending_legacy: std::vec::Vec<LegacyResp>,
  /// instant of the last conflict-driven revert-to-probe, used to
  /// rate-limit RFC 6762 §9 re-probing under a conflict flood.
  last_conflict_reprobe: Option<I>,
  /// a snapshot of the OLD (previously
  /// announced) records, a remaining-sends counter, and WHICH instance records
  /// the old name actually advertised, for a TTL=0 goodbye when a conflict
  /// renames an ANNOUNCED service. Without this the old PTR/SRV/TXT linger in
  /// peer caches until TTL, producing a ghost/duplicate service. The third
  /// element carries the per-record ownership (`EmittedRecords` with the
  /// instance bits set, addresses empty) so `write_rename_goodbye` withdraws
  /// only the records §7.1 KAS actually let onto the wire — never a record this
  /// responder didn't send. Drained first by `poll_transmit` and re-sent
  /// [`RENAME_GOODBYE_SENDS`] times for loss resilience (RFC 6762 §8.4 / §10.1).
  /// `None` when the renamed name had never been announced.
  pending_rename_goodbye: Option<(crate::records::ServiceRecords, u8, respond::EmittedRecords)>,
  /// deadline at which the NEXT rename goodbye may be sent. The first
  /// send is due immediately (set to `now` on rename); after each send it is
  /// pushed out by [`RENAME_GOODBYE_INTERVAL`] so the resends are temporally
  /// independent (a single loss burst can't drop them all) rather than a
  /// same-tick burst. Surfaced via `poll_timeout`.
  rename_goodbye_deadline: Option<I>,
  /// §9: jittered deadline for a pending RFC 6763 service-type
  /// enumeration (`_services._dns-sd._udp.<domain>`) reply. Set when a meta-query
  /// arrives; `poll_transmit` emits a standalone shared meta-PTR when it fires.
  /// Independent of `response_deadline` — the meta reply carries no instance
  /// records and latches no goodbye ownership, so it stays isolated from the
  /// normal response/confirm cycle.
  meta_response_deadline: Option<I>,
  /// sources that issued a §9 service-type enumeration meta-query in the
  /// current meta cycle. A meta known-answer is only honoured from a source in
  /// this set (mirrors `questioner_srcs`), so an off-cycle peer cannot
  /// inject a known-answer that suppresses our meta reply. Bounded by
  /// `MAX_QUESTIONER_SRCS`; cleared when the meta reply fires or is suppressed.
  meta_questioner_srcs: std::vec::Vec<core::net::SocketAddr>,
  /// (RFC 6763 §9 + §7.1): set when a meta questioner's known-answer
  /// section already carries the meta-PTR for OUR service type — our pending
  /// meta reply is then suppressed. Reset each meta cycle.
  meta_known_answered: bool,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<I, TQ, EV> Service<I, TQ, EV>
where
  I: Instant,
  TQ: Pool<Transmit>,
  EV: Pool<ServiceUpdate>,
{
  /// Construct a new Service.
  ///
  /// When `probe` is `true` (RFC 6762 §8.1, the conformant default) the service
  /// starts in `Init` and probes for name uniqueness before announcing. When
  /// `false` the caller asserts the name is already unique (§8.1 permits
  /// skipping probing in that case), so the service starts directly in
  /// `Announcing(0)` and announces without the probe sequence. A later §9
  /// conflict still reverts it to probing to resolve the collision.
  #[allow(dead_code)]
  pub(crate) fn try_new(
    handle: ServiceHandle,
    records: ServiceRecords,
    now: I,
    rng_seed: [u8; 32],
    probe: bool,
  ) -> Self {
    let mut rng = Rng::from_seed(rng_seed);
    let (state, lifecycle_deadline) = if probe {
      (ServiceState::Init, probe_deadline(now, 0, &mut rng))
    } else {
      (ServiceState::Announcing(0), announce_deadline(now, 0))
    };
    Self {
      handle,
      state,
      records,
      lifecycle_deadline,
      response_deadline: None,
      probe_count: 0,
      announce_count: 0,
      rename_attempt: 0,
      pending_transmits: [None, None],
      rng,
      pending_tx: TQ::new(),
      pending_updates: EV::new(),
      last_now: Some(now),
      kas_hints: [None; KAS_RING_SIZE],
      kas_next_slot: 0,
      questioner_srcs: std::vec::Vec::new(),
      peer_probes: std::vec::Vec::new(),
      tiebreak_pending: false,
      goodbye: GoodbyeOwnership::default(),
      awaiting_confirm: None,
      pending_legacy: std::vec::Vec::new(),
      last_conflict_reprobe: None,
      pending_rename_goodbye: None,
      rename_goodbye_deadline: None,
      meta_response_deadline: None,
      meta_questioner_srcs: std::vec::Vec::new(),
      meta_known_answered: false,
    }
  }

  /// Returns the handle assigned at registration.
  #[inline(always)]
  pub const fn handle(&self) -> ServiceHandle {
    self.handle
  }
  /// Returns the current state.
  #[inline(always)]
  pub const fn state(&self) -> ServiceState {
    self.state
  }
  /// Returns the canonical name of this service.
  #[inline(always)]
  pub fn name(&self) -> &crate::Name {
    self.records.instance()
  }
  /// Returns the records this service advertises.
  #[inline(always)]
  pub const fn records(&self) -> &ServiceRecords {
    &self.records
  }

  /// Whether this service has advertised (announced) its host A/AAAA records
  /// and they may still be cached by peers.
  ///
  /// Unlike the instance-level announce state, this latch survives a conflict
  /// rename (the host name does not change). The driver consults it to decide
  /// whether a same-host sibling genuinely owns the shared host records: a
  /// merely-registered (still probing / never announced) sibling has put
  /// nothing into peer caches and so does NOT keep the withdrawing service from
  /// retracting the host addresses, whereas a renamed-but-previously-announced
  /// sibling DOES.
  ///
  /// also requires the service to actually carry host A/AAAA — an
  /// address-less service advertises no host records and so owns none.
  #[inline(always)]
  pub fn advertises_host(&self) -> bool {
    // per-address ownership is non-empty ONLY if we confirmed-emitted at
    // least one host address, which in turn requires the service to carry one —
    // so this subsumes the earlier explicit "has addresses" guard.
    self.goodbye.any_host()
  }

  /// The host IPv4 addresses this service has actually ADVERTISED (confirmed-
  /// emitted), per address. This is the set a sibling truly owns in peer
  /// caches — NOT [`ServiceRecords::a_addrs_slice`], which is the configured set
  /// (a §7.1 KAS-filtered send may have emitted only a subset). The driver
  /// builds its shared-host retention set from this so a withdrawing service
  /// retracts only addresses no remaining service actually advertised.
  #[inline]
  pub fn advertised_a_addrs(&self) -> &[core::net::Ipv4Addr] {
    &self.goodbye.a
  }

  /// The host IPv6 addresses this service has actually ADVERTISED, per address
  /// (the AAAA counterpart of [`Self::advertised_a_addrs`]).
  #[inline]
  pub fn advertised_aaaa_addrs(&self) -> &[core::net::Ipv6Addr] {
    &self.goodbye.aaaa
  }

  /// Report the delivery result of the datagram most recently produced by
  /// [`Self::poll_transmit`] (the confirm-on-send chokepoint).
  ///
  /// This is the SOLE place service lifecycle state advances. `poll_transmit`
  /// only encodes bytes and stamps a commit token (`awaiting_confirm`); the
  /// driver then calls this with `delivered = true` when at least one socket
  /// send succeeded (`used > 0`). Behaviour is keyed on the token:
  ///
  /// * **Probe, delivered** — advance the §8.1 probe sequence (next probe, or
  ///   enter `Announcing(0)` after the third). A name is therefore claimed only
  ///   once a probe has actually reached the link.
  /// * **Probe, NOT delivered** — re-arm the same probe WITHOUT advancing, so a
  ///   service whose probes never leave the host never announces (the RFC 6762
  ///   §8.1 guarantee; the fix).
  /// * **Announcement, delivered** — latch the goodbye-ownership guards
  ///   (`announce_emitted` / `host_advertised`) and advance the §8.3
  ///   announce phase, reaching `Established` after the second.
  /// * **Announcement, NOT delivered** — re-arm without advancing; the
  ///   announcement is retried.
  /// * **Response / nothing pending** — no lifecycle state to advance.
  pub fn note_transmit_result(&mut self, now: I, delivered: bool) {
    let kind = match self.awaiting_confirm.take() {
      Some(k) => k,
      None => return,
    };
    match kind {
      AwaitingConfirm::Probe => {
        if let ServiceState::Probing(n) = self.state {
          if !delivered {
            // §8.1: the probe never reached the link — do NOT advance the
            // sequence. Re-arm the SAME probe from post-send time so it
            // retries, rather than the service progressing toward Announcing
            // with nothing on the wire.
            self.lifecycle_deadline = probe_deadline(now, n, &mut self.rng);
          } else if n >= 2 {
            // Third probe confirmed (§8.1: exactly three) → begin announcing.
            self.state = ServiceState::Announcing(0);
            self.probe_count = 3;
            self.lifecycle_deadline = announce_deadline(now, 0);
          } else {
            // Probe confirmed → schedule the next one PROBE_INTERVAL later.
            let new_n = n.saturating_add(1);
            self.state = ServiceState::Probing(new_n);
            self.probe_count = new_n;
            self.lifecycle_deadline = probe_deadline(now, new_n, &mut self.rng);
          }
        }
      }
      AwaitingConfirm::Announcement(emitted) => {
        if !delivered {
          // The announcement never reached the link — re-arm without advancing.
          // Retry at the §8.3 inter-announce interval, anchored to
          // post-send time. This MUST also cover the periodic
          // `Established` re-announce — otherwise a single transient send failure
          // leaves the next attempt a full re-announce interval (~80% of TTL)
          // away, during which peers expire the records and the service silently
          // disappears. A short 1 s retry keeps the records alive.
          if matches!(
            self.state,
            ServiceState::Announcing(_) | ServiceState::Established
          ) {
            self.lifecycle_deadline = announce_deadline(now, 1);
          }
          return;
        }
        // Confirmed announcement → latch goodbye ownership for the records it
        // carried (peers can only have cached our records once a send truly
        // reached the link). Driven by the encoder's per-record report, same as
        // a response: a full announcement emits all of
        // PTR/SRV/TXT plus every host address.
        self.goodbye.record_emitted(&emitted);
        if let ServiceState::Announcing(n) = self.state {
          if n >= 1 {
            // Second announcement confirmed → the §8.3 startup sequence is
            // complete: become Established and notify the caller exactly once.
            self.state = ServiceState::Established;
            self.announce_count = 2;
            let _ = self.pending_updates.insert(ServiceUpdate::Established);
            self.lifecycle_deadline = re_announce_deadline(now, self.records.ttl_secs());
          } else {
            // First announcement confirmed → schedule the second one (§8.3: ≥1 s
            // later).
            let new_n = n.saturating_add(1);
            self.state = ServiceState::Announcing(new_n);
            self.announce_count = new_n;
            self.lifecycle_deadline = announce_deadline(now, new_n);
          }
        }
      }
      AwaitingConfirm::Response(emitted) => {
        // a DELIVERED response (multicast question reply or §6.7
        // legacy unicast reply) put our positive-TTL records on the wire, so
        // peers may now cache them — even before the first §8.3 announcement is
        // confirmed (a query can arrive during `Announcing(0)`). Latch the
        // goodbye-ownership guards so a later unregister/conflict actually
        // withdraws those records.
        //
        // latch ONLY the concrete records this response actually
        // emitted. Known-answer suppression (§7.1) can trim any subset — down to
        // individual PTR/SRV/TXT and individual addresses — so latching a whole
        // group would let a later TTL=0 goodbye withdraw records this service
        // never put on the wire, potentially cache-flushing a peer's matching
        // shared record. NOT a lifecycle PHASE change.
        if delivered {
          self.goodbye.record_emitted(&emitted);
        }
      }
      AwaitingConfirm::RenameGoodbye => {
        if delivered {
          // The withdrawal reached the link → spend ONE resend, then schedule the
          // next (RENAME_GOODBYE_INTERVAL apart) or finish.
          if let Some((_, remaining, _)) = self.pending_rename_goodbye.as_mut() {
            *remaining = remaining.saturating_sub(1);
            if *remaining == 0 {
              self.pending_rename_goodbye = None;
              self.rename_goodbye_deadline = None;
            } else {
              self.rename_goodbye_deadline = now.checked_add_duration(RENAME_GOODBYE_INTERVAL);
              if self.rename_goodbye_deadline.is_none() {
                self.pending_rename_goodbye = None;
              }
            }
          }
        } else {
          // Nothing reached the link — re-arm the SAME withdrawal at the resend
          // interval (a FUTURE deadline, not `now`, so it is not re-offered within
          // this same pump and busy-spin) WITHOUT spending the budget.
          self.rename_goodbye_deadline = now.checked_add_duration(RENAME_GOODBYE_INTERVAL);
          if self.rename_goodbye_deadline.is_none() {
            self.pending_rename_goodbye = None;
          }
        }
      }
    }
  }

  /// Convenience wrapper for a CONFIRMED delivery — equivalent to
  /// `note_transmit_result(now, true)`. Retained so call sites (and tests) that
  /// always represent a successful send stay terse; all advancement logic lives
  /// in [`Self::note_transmit_result`].
  #[inline]
  pub fn note_transmit_delivered(&mut self, now: I) {
    self.note_transmit_result(now, true);
  }

  /// Encode a TTL=0 goodbye (RFC 6762 §10.1) for graceful withdrawal.
  ///
  /// The instance records (PTR/SRV/TXT) and the host A/AAAA are withdrawn
  /// independently, since they are owned by different names:
  ///
  /// * Instance records are withdrawn only if the CURRENT instance has actually
  ///   emitted an announcement (gated on `announce_emitted`, not on
  ///   lifecycle state — `Announcing(0)` is reached before the first
  ///   announcement, and budget pressure can delay sends). Until then peers
  ///   cannot have cached them, and a goodbye would risk withdrawing a
  ///   different responder's record for the same name.
  /// * Host A/AAAA are withdrawn PER ADDRESS: each of this
  ///   service's host addresses is retracted UNLESS it appears in
  ///   `retained_host_addrs` — the set of addresses some OTHER local service
  ///   still advertises for the same host name. Same-host services may carry
  ///   different/overlapping address sets, so withdrawing a shared address
  ///   would wrongly evict it from peer caches. Only addresses this service
  ///   actually advertised count (gated on `host_advertised`, which
  ///   survives a conflict rename), so a renamed-but-not-yet-reannounced
  ///   service still withdraws the addresses it previously announced.
  ///
  /// Returns `Ok(None)` when nothing is withdrawable (nothing was cached).
  /// This is mechanism only: the caller decides how many times / how often.
  pub fn encode_goodbye(
    &self,
    buf: &mut [u8],
    retained_host_addrs: &[core::net::IpAddr],
  ) -> Result<Option<usize>, TransmitError> {
    self.encode_goodbye_filtered(buf, |addr| retained_host_addrs.contains(&addr))
  }

  /// Like [`Self::encode_goodbye`], but the shared-host retention set is supplied
  /// as a PREDICATE rather than a materialised slice: `is_retained(addr)` returns
  /// whether some OTHER same-host service still advertises `addr` (so this service
  /// must NOT withdraw it). A driver that would otherwise build an O(siblings)
  /// `Vec` of retained addresses on every unregister can instead pass an
  /// allocation-free closure that checks its service table on the fly — keeping a
  /// constrained (`no_std`) withdrawal path heap-stable regardless of how many
  /// same-host siblings exist. Semantics are otherwise identical to
  /// [`Self::encode_goodbye`].
  pub fn encode_goodbye_filtered(
    &self,
    buf: &mut [u8],
    is_retained: impl Fn(core::net::IpAddr) -> bool,
  ) -> Result<Option<usize>, TransmitError> {
    // withdraw exactly the records we confirmed-emitted — each of
    // PTR/SRV/TXT independently, and host addresses from the per-address
    // ownership set (NOT the full records slice). §7.1 KAS may have put only a
    // subset on the wire; withdrawing more would cache-flush a peer's matching
    // shared record.
    let include_ptr = self.goodbye.ptr;
    let include_srv = self.goodbye.srv;
    let include_txt = self.goodbye.txt;
    let include_subtypes = self.goodbye.subtypes;
    // Of the addresses we advertised, withdraw any NOT retained by a same-host
    // sibling (per-address diff). Evaluate the predicate as filtered ITERATORS,
    // not materialised Vecs, so encoding a goodbye allocates nothing proportional
    // to the advertised-address count — the writer streams straight into `buf`
    //. A cheap predicate-only pass answers "is anything withdrawable?".
    let any_a = self
      .goodbye
      .a
      .iter()
      .any(|ip| !is_retained(core::net::IpAddr::V4(*ip)));
    let any_aaaa = self
      .goodbye
      .aaaa
      .iter()
      .any(|ip| !is_retained(core::net::IpAddr::V6(*ip)));
    if !include_ptr && !include_srv && !include_txt && !include_subtypes && !any_a && !any_aaaa {
      return Ok(None);
    }
    respond::write_goodbye(
      &self.records,
      buf,
      include_ptr,
      include_srv,
      include_txt,
      include_subtypes,
      self
        .goodbye
        .a
        .iter()
        .copied()
        .filter(|ip| !is_retained(core::net::IpAddr::V4(*ip))),
      self
        .goodbye
        .aaaa
        .iter()
        .copied()
        .filter(|ip| !is_retained(core::net::IpAddr::V6(*ip))),
    )
    .map(Some)
    .map_err(|_| {
      TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(
        buf.len(),
        buf.len(),
      ))
    })
  }

  /// Take any pending conflict-rename goodbye: encode the queued
  /// withdrawal of the OLD instance records (instance-only, no host A/AAAA —
  /// see `respond::write_rename_goodbye`) into `buf`, clear the pending
  /// state, and return its length.
  ///
  /// `poll_transmit` normally drives these resends on a timer, but a service
  /// removed mid-rename never gets polled again — its proto state is dropped.
  /// The driver calls this on removal to hand the withdrawal off to its own
  /// goodbye queue so the old name is still retracted from peer caches.
  ///
  /// Peek-then-pop (matching `poll_transmit`'s invariant):
  /// encode from the still-queued record first and clear the pending state ONLY
  /// after a successful encode. Returns `Ok(None)` when nothing is pending; a
  /// too-small `buf` surfaces `Err(BufferTooSmall)` and PRESERVES the pending
  /// withdrawal so a larger-buffer retry still emits it, rather than silently
  /// destroying it.
  pub fn take_pending_rename_goodbye(
    &mut self,
    buf: &mut [u8],
  ) -> Result<Option<usize>, TransmitError> {
    let (old, owned) = match self.pending_rename_goodbye.as_ref() {
      Some((old, _, owned)) => (old, owned),
      None => return Ok(None),
    };
    match respond::write_rename_goodbye(old, owned, buf) {
      Ok(n) => {
        self.pending_rename_goodbye = None;
        self.rename_goodbye_deadline = None;
        Ok(Some(n))
      }
      Err(_) => Err(TransmitError::BufferTooSmall(
        crate::error::BufferTooSmallDetail::new(buf.len(), buf.len()),
      )),
    }
  }

  /// Returns the next deadline at which `handle_timeout` should be called.
  ///
  /// This is the minimum of `lifecycle_deadline` and `response_deadline`
  /// (either or both may be `None`). The caller should drive `handle_timeout`
  /// when this instant is reached.
  pub fn poll_timeout(&self) -> Option<I> {
    // a queued legacy unicast response is due immediately (no jitter).
    if !self.pending_legacy.is_empty() {
      return self.last_now;
    }
    // Earliest of: lifecycle, response, and the rename-goodbye resend deadline
    // (so a Sans-I/O caller wakes to send each spaced resend).
    let mut best: Option<I> = None;
    for d in [
      self.lifecycle_deadline,
      self.response_deadline,
      self.rename_goodbye_deadline,
      self.meta_response_deadline,
    ]
    .into_iter()
    .flatten()
    {
      best = Some(match best {
        Some(b) if b <= d => b,
        _ => d,
      });
    }
    best
  }

  /// Push a transmit kind onto the tail of the FIFO queue.
  ///
  /// Invariant: the queue is left-packed — slot 0 is always `Some` whenever
  /// the queue is non-empty, and slot 1 is `Some` only if slot 0 is.  This
  /// makes `peek_pending` a cheap slot-0 read and keeps FIFO order across
  /// pop / push interleavings.
  ///
  /// If both slots are already occupied the entry is silently dropped.  Under
  /// normal scheduling at most one lifecycle event + one response are queued
  /// per tick, so overflow should not occur.
  fn push_pending(&mut self, kind: PendingTransmitKind) {
    if self.pending_transmits[0].is_none() {
      self.pending_transmits[0] = Some(kind);
    } else if self.pending_transmits[1].is_none() {
      self.pending_transmits[1] = Some(kind);
    }
    // Both slots full — drop.
  }

  /// Pop the head of the FIFO queue, compacting the tail down.
  ///
  /// a previous implementation cleared whichever slot held the head
  /// (leaving a hole at index 0 when the head was popped from there), then
  /// `push_pending` re-filled that hole with a NEWER item — overtaking the
  /// older item still parked in slot 1.  Compacting on pop preserves true
  /// FIFO order: shift slot 1 down to slot 0 every time we drain slot 0.
  fn pop_pending(&mut self) -> Option<PendingTransmitKind> {
    let head = self.pending_transmits[0].take();
    if head.is_some() {
      // Shift the tail (slot 1) into the head position so the queue stays
      // left-packed.  If slot 1 was None this is a no-op.
      self.pending_transmits[0] = self.pending_transmits[1].take();
    }
    head
  }

  /// Peek at the head of the FIFO queue without removing it.
  ///
  /// Relies on the left-packed invariant maintained by `push_pending` and
  /// `pop_pending`: if anything is queued, it is in slot 0.
  fn peek_pending(&self) -> Option<PendingTransmitKind> {
    self.pending_transmits[0]
  }

  /// Drain a pending app-level update, if any.
  pub fn poll(&mut self) -> Option<ServiceUpdate> {
    let entry = self.pending_updates.iter().next().map(|(k, _)| k)?;
    let upd = self.pending_updates.try_remove(entry);
    if upd.is_some() {
      crate::trace::debug!(
        target: "mdns_proto::service",
        handle = self.handle.raw(),
        update = ?upd,
        "Service::poll emitted update"
      );
    }
    upd
  }

  /// OUR canonical rdata for `rtype`, in the SAME byte format
  /// `respond::canonical_rdata_for_hash` produces for a peer record, so a §9
  /// conflict check can tell identical (consistent) rdata from a real conflict.
  /// SRV → priority+weight+port (BE) + lowercased wire-form host; TXT →
  /// length-prefixed segments. Other types → empty (never matched as conflicts).
  fn our_canonical_record_for(&self, rtype: crate::wire::ResourceType) -> std::vec::Vec<u8> {
    let mut out = std::vec::Vec::new();
    match rtype {
      crate::wire::ResourceType::Srv => {
        out.extend_from_slice(&self.records.priority().to_be_bytes());
        out.extend_from_slice(&self.records.weight().to_be_bytes());
        out.extend_from_slice(&self.records.port().to_be_bytes());
        write_canonical_wire_name(self.records.host().as_str(), &mut out);
      }
      crate::wire::ResourceType::Txt => {
        // empty TXT → single zero-length string (one 0x00), matching
        // both our wire form and a peer's compliant empty TXT canonicalization.
        respond::write_canonical_txt(self.records.txt_segments(), &mut out);
      }
      _ => {}
    }
    out
  }

  /// clear pending response-CYCLE state — queued legacy unicast
  /// replies and the KAS-hint / questioner-source suppression set. Called when a
  /// response cycle is cancelled: on a §9 revert-to-probe (we must NOT answer
  /// for a name we are re-verifying — `pending_legacy` is drained by
  /// `poll_transmit` before any state check) and on a conflict rename. Does NOT
  /// touch `announce_emitted` — see [`Self::reset_advertised_name_state`].
  fn clear_response_cycle_state(&mut self) {
    self.pending_legacy.clear();
    self.kas_hints = [None; KAS_RING_SIZE];
    self.kas_next_slot = 0;
    self.questioner_srcs.clear();
    // §9: a pending meta-query reply belongs to the response cycle of the
    // old (Established) name — drop it on a revert-to-probe / rename so we don't
    // answer the meta-query while not authoritative.
    self.meta_response_deadline = None;
    self.meta_questioner_srcs.clear();
    self.meta_known_answered = false;
  }

  /// clear all per-advertised-name generation state on a conflict-
  /// driven RENAME. The NEW instance name has not been announced, so the
  /// instance goodbye must not fire for it (host ownership persists — the host
  /// name is unchanged); the response-cycle state tied to the OLD
  /// name must not carry over either.
  fn reset_advertised_name_state(&mut self) {
    self.goodbye.reset_instance();
    self.clear_response_cycle_state();
  }

  /// whether `record` (an A/AAAA owned by our host name) carries an
  /// address WE advertise — CONSISTENT rdata (our own multicast echo, or another
  /// instance correctly sharing the host), not a §9 conflict.
  ///
  /// a LINK-LOCAL address (IPv4 169.254/16, IPv6 fe80::/10) is scoped
  /// to a single interface, so the same raw address on a DIFFERENT interface is
  /// a genuine conflict. `HostConflict` carries no receive interface to
  /// disambiguate, so we do NOT suppress link-local matches — we surface them.
  /// (Our own echo is already filtered upstream by self-loopback detection, so
  /// surfacing a link-local match never re-reports our own packet.) A different
  /// address, or malformed/unparseable rdata, is also treated as a conflict.
  fn host_record_is_ours(&self, record: &crate::wire::Ref<'_>) -> bool {
    match record.rdata_view() {
      Ok(crate::wire::Rdata::A(a)) => {
        let addr = a.addr();
        !addr.is_link_local() && self.records.a_addrs_slice().contains(&addr)
      }
      Ok(crate::wire::Rdata::AAAA(a)) => {
        let addr = a.addr();
        let link_local = (addr.segments()[0] & 0xffc0) == 0xfe80;
        !link_local && self.records.aaaa_addrs_slice().contains(&addr)
      }
      _ => false,
    }
  }

  /// Process an event routed to this service by the Endpoint.
  ///
  /// `now` is the current time; it is cached so that `handle_event` can
  /// compute KAS-hint expiration times and schedule the jittered response
  /// deadline without needing `handle_timeout` to have fired first.
  pub fn handle_event(&mut self, event: ServiceEvent<'_>, now: I) {
    // always refresh last_now so that subsequent calls (e.g.
    // Question→response_deadline, KnownAnswer→expiry) use a current reference
    // even when handle_timeout has not recently fired.
    self.last_now = Some(now);
    match (self.state, event) {
      (ServiceState::Probing(_) | ServiceState::Init, ServiceEvent::ProbeConflict(pc)) => {
        // RFC 6762 §8.2 SIMULTANEOUS-PROBE tiebreak: don't rename immediately.
        // Buffer the peer's proposed record into a per-source bucket so the next
        // handle_timeout can compare per-peer and rename only if any peer wins.
        // (Post-establishment §9 conflicts use a SEPARATE arm below — the
        // lexicographic tiebreak is wrong for §9.)

        // Only SRV and TXT records are owned by the conflicting instance
        // name and contribute to the RFC §8.2 tiebreak. NSEC, A, AAAA, Unknown
        // etc. are owned by different names or carry no tiebreak semantics.
        // Drop anything that isn't SRV or TXT silently.
        if !matches!(
          pc.record().rtype(),
          crate::wire::ResourceType::Srv | crate::wire::ResourceType::Txt
        ) {
          return;
        }

        // Canonicalize FIRST. Only create/find a bucket on success.
        // This prevents malformed records from consuming a peer-probe slot and
        // exhausting the MAX_PEER_PROBES cap before any legitimate record lands.
        let view = match pc.record().rdata_view() {
          Ok(v) => v,
          Err(_) => return, // malformed rdata — drop without touching buckets
        };
        let mut scratch = std::vec::Vec::new();
        let canonical = match respond::canonical_rdata_for_hash(&view, &mut scratch) {
          Ok(c) => c.to_vec(),
          Err(_) => return, // canonicalization error — drop without touching buckets
        };
        let rtype = pc.record().rtype();

        let src = pc.src();
        // Find existing bucket for this source, or create a new one.
        let bucket_idx = self.peer_probes.iter().position(|b| b.src == src);
        let bucket_idx = match bucket_idx {
          Some(i) => i,
          None => {
            // No existing bucket; only create if under the cap.
            if self.peer_probes.len() >= MAX_PEER_PROBES {
              return; // too many peer sources — drop
            }
            self.peer_probes.push(PeerProbe {
              src,
              records: std::vec::Vec::new(),
            });
            self.peer_probes.len().saturating_sub(1)
          }
        };
        let bucket = match self.peer_probes.get_mut(bucket_idx) {
          Some(b) => b,
          None => return,
        };
        if bucket.records.len() >= MAX_PEER_PROBE_RECORDS {
          return; // bucket full — drop
        }
        bucket.records.push(PeerRecord { rtype, canonical });
        self.tiebreak_pending = true;
      }
      (
        ServiceState::Announcing(_) | ServiceState::Established,
        ServiceEvent::ProbeConflict(pc),
      ) => {
        // RFC 6762 §9 post-establishment conflict — NOT the §8.2
        // lexicographic probe tiebreak. A §9 conflict is the same name/type/
        // class with DIFFERENT rdata; an identical record is consistent and
        // MUST be ignored (otherwise a benign duplicate / our own echo would
        // force a healthy service to rename). A genuine conflict triggers
        // re-verification: revert to Probing, which re-announces the name on
        // success (active defense) and renames via the §8.2 tiebreak only if
        // the conflict persists during re-probe.
        if !matches!(
          pc.record().rtype(),
          crate::wire::ResourceType::Srv | crate::wire::ResourceType::Txt
        ) {
          return;
        }
        let view = match pc.record().rdata_view() {
          Ok(v) => v,
          Err(_) => return,
        };
        let mut scratch = std::vec::Vec::new();
        let peer_canonical = match respond::canonical_rdata_for_hash(&view, &mut scratch) {
          Ok(c) => c,
          Err(_) => return,
        };
        // Identical rdata → consistent, not a conflict (§9). Ignore.
        if peer_canonical
          == self
            .our_canonical_record_for(pc.record().rtype())
            .as_slice()
        {
          return;
        }
        // Rate-limit (§9): don't thrash on a conflict flood — if we reverted to
        // re-probe within the last interval, ignore further conflicts. (Once we
        // are back in Probing, subsequent conflicts route through the §8.2 arm.)
        if let Some(last) = self.last_conflict_reprobe
          && let Some(elapsed) = now.checked_duration_since(last)
          && elapsed < CONFLICT_REPROBE_MIN_INTERVAL
        {
          return;
        }
        // Genuine §9 conflict: revert to Probing to re-verify the SAME name
        // (do NOT rename yet — peers still hold our records, so `announce_emitted`
        // stays set for goodbye-on-unregister). But we MUST stop
        // serving the name while it is unverified — clear the cancelled response
        // cycle (queued legacy replies drained before any state check, plus KAS
        // / questioner suppression state) so the re-probe window doesn't answer
        // the very name we reverted to re-verify.
        self.last_conflict_reprobe = Some(now);
        self.state = ServiceState::Init;
        self.probe_count = 0;
        self.announce_count = 0;
        self.pending_transmits = [None, None];
        self.response_deadline = None;
        self.clear_response_cycle_state();
        self.lifecycle_deadline = probe_deadline(now, 0, &mut self.rng);
      }
      (ServiceState::Established | ServiceState::Announcing(_), ServiceEvent::Question(sq)) => {
        let src = sq.src();
        // RFC 6763 §9 service-type enumeration meta-query: reply with a shared
        // PTR `_services._dns-sd._udp.<domain>. -> <service_type>`. The reply
        // advertises no instance records and latches no goodbye ownership, so it
        // is fully independent of the normal response cycle below (§9).
        // A 5353 querier is on the multicast group → schedule a jittered
        // MULTICAST reply; a legacy (non-5353) resolver is NOT on the group, so
        // it gets a UNICAST meta echo instead.
        if crate::endpoint::is_meta_query_name(sq.question().qname()) {
          if src.port() != crate::constants::MDNS_PORT {
            if self.pending_legacy.len() < MAX_LEGACY_RESPONSES
              && let Ok(meta) = crate::Name::try_from_str(crate::endpoint::DNS_SD_META_QUERY_NAME)
            {
              let query_id = sq.query_id();
              let qtype = sq.question().qtype();
              let qclass = sq.question().qclass();
              let dup = self
                .pending_legacy
                .iter()
                .any(|l| l.dst == src && l.query_id == query_id && l.is_meta);
              if !dup {
                self.pending_legacy.push(LegacyResp {
                  dst: src,
                  query_id,
                  name: meta,
                  qtype,
                  qclass,
                  is_meta: true,
                });
              }
            }
          } else {
            use rand_core::Rng as _;
            // record this meta questioner so a later meta known-answer
            // from the SAME source can suppress our reply (§9 + §7.1). Mirrors
            // the normal cycle's `questioner_srcs` gate.
            if !self.meta_questioner_srcs.contains(&src)
              && self.meta_questioner_srcs.len() < MAX_QUESTIONER_SRCS
            {
              self.meta_questioner_srcs.push(src);
            }
            // RFC 6762 §7.2: a TC-bit meta-query is also spreading its known
            // answers across packets (a large service-type enumeration can carry
            // many known PTRs), so delay 400–500 ms instead of 20–120 ms.
            let jitter_ms = if sq.truncated() {
              400u32.saturating_add(self.rng.next_u32() % 101) // [400, 500]
            } else {
              20u32.saturating_add(self.rng.next_u32() % 101) // [20, 120]
            };
            if let Some(due) =
              now.checked_add_duration(core::time::Duration::from_millis(u64::from(jitter_ms)))
            {
              self.meta_response_deadline = Some(match self.meta_response_deadline {
                Some(existing) if existing <= due => existing,
                _ => due,
              });
            }
          }
          return;
        }
        // RFC 6762 §6.7 legacy unicast. A querier whose source port
        // is not 5353 is a non-mDNS resolver — NOT joined to the multicast
        // group, so a multicast response never reaches it. Queue a direct,
        // query-shaped unicast reply (echoing its query ID + question) drained
        // by `poll_transmit`. This is independent of the multicast response
        // cycle below, and one entry per distinct querier.
        if src.port() != crate::constants::MDNS_PORT {
          if self.pending_legacy.len() < MAX_LEGACY_RESPONSES {
            let qname = sq.question().qname();
            // Echo our matching name: case-insensitively equal to the
            // querier's qname, but byte-correct since it is our own
            // validated Name (avoids lossy NameRef→Name reconstruction).
            let echo = if crate::endpoint::names_match(self.records.service_type(), qname) {
              Some(self.records.service_type().clone())
            } else if crate::endpoint::names_match(self.records.instance(), qname) {
              Some(self.records.instance().clone())
            } else if crate::endpoint::names_match(self.records.host(), qname) {
              Some(self.records.host().clone())
            } else {
              // a legacy subtype browse (`<sub>._sub.<type>`). Echo the
              // matched subtype name — write_legacy_response emits the subtype
              // PTR as part of the full record set, so the resolver gets it.
              self
                .records
                .subtype_names()
                .iter()
                .find(|s| crate::endpoint::names_match(s, qname))
                .cloned()
            };
            if let Some(name) = echo {
              let qtype = sq.question().qtype();
              let qclass = sq.question().qclass();
              let query_id = sq.query_id();
              // dedup on the FULL request key, not just `dst` — a
              // resolver reuses one socket for distinct transactions (A+AAAA,
              // different query IDs), and each must get its own ID-echoing
              // reply. Only a verbatim duplicate (e.g. a retransmit) coalesces.
              let dup = self.pending_legacy.iter().any(|l| {
                l.dst == src
                  && l.query_id == query_id
                  && l.qtype == qtype
                  && l.qclass == qclass
                  && l.name == name
              });
              if !dup {
                self.pending_legacy.push(LegacyResp {
                  dst: src,
                  query_id,
                  name,
                  qtype,
                  qclass,
                  is_meta: false,
                });
              }
            }
          }
          return;
        }

        // Item 2: schedule a jittered MULTICAST response (RFC 6762 §6 — 20–120
        // ms for shared records). QU-bit queriers (§5.4) are group members, so
        // this multicast reply serves them too. The deadline uses `now` so it
        // stays independent of the lifecycle deadline, and multiple
        // questions in the window coalesce onto the earliest deadline.
        //
        // RFC 6762 §7.2 (multipacket known-answer suppression): a query with the
        // TC bit set means the querier is spreading its known-answer list across
        // multiple packets. Delay 400–500 ms instead of 20–120 ms so the
        // follow-up known-answer packets (routed as `KnownAnswer` hints from the
        // same source) arrive and accumulate before we decide what to suppress.
        use rand_core::Rng as _;
        let jitter_ms = if sq.truncated() {
          400u32.saturating_add(self.rng.next_u32() % 101) // [400, 500]
        } else {
          20u32.saturating_add(self.rng.next_u32() % 101) // [20, 120]
        };
        let wait = core::time::Duration::from_millis(u64::from(jitter_ms));
        let new_rd = match now.checked_add_duration(wait) {
          Some(t) => t,
          None => return,
        };
        self.response_deadline = Some(match self.response_deadline {
          Some(existing) if existing <= new_rd => existing,
          _ => new_rd,
        });
        // record the questioner's source so KAS hints from this same
        // source can be accepted in the current response cycle (bounded).
        if !self.questioner_srcs.contains(&src) && self.questioner_srcs.len() < MAX_QUESTIONER_SRCS
        {
          self.questioner_srcs.push(src);
        }
      }
      (_, ServiceEvent::KnownAnswer(ka)) => {
        // (RFC 6763 §9 + §7.1): a known-answer whose OWNER is the DNS-SD
        // service-type enumeration meta name can only ever suppress our meta
        // reply — never one of our normal RRsets — so handle it here and return.
        // Suppress only when our meta reply is pending, the source is a meta
        // questioner from this cycle (questioner-source gate), the record is an IN
        // PTR above the §7.1 half-TTL threshold, and its target is OUR service
        // type. A meta-owned record that fails any check suppresses nothing.
        if crate::endpoint::is_meta_query_name(ka.record().name()) {
          if self.meta_response_deadline.is_some()
            && self.meta_questioner_srcs.contains(&ka.src())
            && ka.record().rclass().is_in()
            && ka.record().rtype() == crate::wire::ResourceType::Ptr
            && ka.record().ttl().saturating_mul(2) >= self.records.ttl_secs()
            && let Ok(crate::wire::Rdata::Ptr(p)) = ka.record().rdata_view()
            && crate::endpoint::names_match(self.records.service_type(), p.target())
          {
            self.meta_known_answered = true;
          }
          return;
        }
        // KAS hints are tied to the response cycle initiated by
        // a Question.  RFC 6762 §7.1 specifies known-answer suppression
        // as a per-query mechanism: the hint applies to the response
        // we are about to send for THIS query.  Without that scope, a
        // hostile peer could pre-seed long-TTL hints that suppress
        // responses to UNRELATED future queriers.
        //
        // tighten the gate further by also requiring the
        // hint's source to be one that issued a Question in the
        // current response cycle.  Without this, an attacker could
        // wait for a legitimate Question to schedule
        // response_deadline and then inject hints from a different
        // source during the jitter window, suppressing the response
        // to the legitimate questioner.  The hints from an attacker
        // who never asked a question are now silently dropped.
        if self.response_deadline.is_none() {
          return;
        }
        if !self.questioner_srcs.contains(&ka.src()) {
          return;
        }
        // class is part of RRset identity. We only ever emit CLASS=IN
        // records, so a known-answer in a different class (e.g. CLASS=ANY or
        // CHAOS) is NOT the same RRset and MUST NOT suppress our IN response —
        // otherwise a querier could send a matching-rdata wrong-class answer to
        // silence us (§7.1). `rclass()` already strips the cache-flush bit.
        if !ka.record().rclass().is_in() {
          return;
        }

        // Item 5: store the KAS hint with expiration based on the record's TTL.
        // `now` is available directly (parameter).
        let last_now = now;

        // RFC 6762 §7.1 half-TTL rule: a known-answer MUST NOT suppress our
        // record if the querier's remaining TTL is less than half of our
        // authoritative TTL — their cache is about to expire, so suppressing
        // would force them to re-query before we re-announce.
        let querier_ttl = ka.record().ttl();
        let our_ttl = self.records.ttl_secs();
        if querier_ttl.saturating_mul(2) < our_ttl {
          // Querier's record is below the half-TTL threshold — don't suppress.
          return;
        }

        let ttl = core::time::Duration::from_secs(u64::from(ka.record().ttl()));
        let expires_at = match last_now.checked_add_duration(ttl) {
          Some(t) => t,
          None => return,
        };
        // Use canonical rdata bytes so the hash matches what write_announce_filtered
        // produces, regardless of wire-level name compression in the incoming packet.
        // Drop the hint on any parse error rather than storing an incorrect hash.
        let view = match ka.record().rdata_view() {
          Ok(v) => v,
          Err(_) => return, // malformed rdata — drop the hint
        };
        let mut scratch = std::vec::Vec::new();
        let canonical = match respond::canonical_rdata_for_hash(&view, &mut scratch) {
          Ok(c) => c,
          Err(_) => return, // canonicalization error (e.g. pointer cycle) — drop the hint
        };
        let rdata_hash = hash_rdata(canonical);
        // a known-answer may only suppress an RRset WE own, so bind the
        // hint to which of our owner names its record name matches. A KA whose
        // name is none of ours suppresses nothing (dropped here); one whose name
        // matches but under the wrong type (e.g. `_svc._tcp.local A x`) is kept
        // but will never match a candidate, because the filter pairs each
        // candidate's owner-kind with its rtype.
        let owner = if crate::endpoint::names_match_record(self.records.service_type(), ka.record())
        {
          KasOwner::ServiceType
        } else if crate::endpoint::names_match_record(self.records.instance(), ka.record()) {
          KasOwner::Instance
        } else if crate::endpoint::names_match_record(self.records.host(), ka.record()) {
          KasOwner::Host
        } else {
          return; // not one of our RRset names — cannot suppress any of our records
        };
        let hint = KasHint {
          owner,
          rtype: ka.record().rtype(),
          rdata_hash,
          expires_at,
        };
        if let Some(slot) = self.kas_hints.get_mut(self.kas_next_slot) {
          *slot = Some(hint);
          self.kas_next_slot = self.kas_next_slot.saturating_add(1) % KAS_RING_SIZE;
        }
      }
      (_, ServiceEvent::HostConflict(hc)) => {
        // RFC 6762 §9 only treats DIFFERENT rdata as a conflict. A
        // host A/AAAA whose address is one WE advertise is consistent (our own
        // multicast echo, or another instance correctly sharing the host) — not
        // a conflict. Ignore it; surface HostConflict only for a genuinely
        // different address.
        if self.host_record_is_ours(hc.record()) {
          return;
        }
        // A peer is claiming our host name (A/AAAA owner) with a DIFFERENT
        // address. Unlike an instance-name conflict we do NOT auto-rename —
        // renaming only the instance would leave the host conflict unresolved,
        // and multiple services may share one host so renaming all of them would
        // be incorrect. Surface the event to the caller via
        // ServiceUpdate::HostConflict; the caller must intervene (e.g. choose a
        // new host name and re-register).
        let _ = self.pending_updates.insert(ServiceUpdate::HostConflict);
      }
      _ => {}
    }
  }

  /// Drive timer-based transitions. Returns Ok unless arithmetic overflowed.
  #[allow(clippy::arithmetic_side_effects)]
  pub fn handle_timeout(&mut self, now: I) -> Result<(), HandleTimeoutError> {
    // Cache latest `now` for use by poll_transmit's KAS filtering closure.
    // handle_event now receives `now` directly, so this is only needed
    // for the filtering closure in poll_transmit.
    self.last_now = Some(now);

    // Item 5: prune expired KAS hints.
    for slot in self.kas_hints.iter_mut() {
      if let Some(hint) = slot
        && hint.expires_at <= now
      {
        *slot = None;
      }
    }

    // RFC 6762 §8.2 tiebreak: if a ProbeConflict was buffered since the last
    // timeout, compare our proposed RR set against the peer's. Only rename if
    // we lose (or tie — RFC §8.2.1 treats a tie as a loss). The §8.2
    // lexicographic tiebreak applies ONLY to Init/Probing (simultaneous
    // probing). Post-establishment (§9) conflicts are handled separately in
    // `handle_event` (revert-to-probe), not via this tiebreak.
    if self.tiebreak_pending && matches!(self.state, ServiceState::Init | ServiceState::Probing(_))
    {
      self.tiebreak_pending = false;
      let we_lose = compare_rr_sets_we_lose(&self.records, &self.peer_probes);
      self.peer_probes.clear();
      if we_lose {
        // if the OLD name had been announced, peers have its
        // PTR/SRV/TXT cached — withdraw them with a TTL=0 goodbye BEFORE
        // switching names, or they linger as a ghost/duplicate until TTL.
        // Snapshot the old records now (records are about to be mutated /
        // instance ownership about to be reset). Probe-time names that were
        // never announced have nothing cached, so no goodbye.
        if self.goodbye.any_instance() {
          // capture WHICH instance records the old name actually put on
          // the wire (§7.1 KAS may have emitted only a subset), so the rename
          // goodbye withdraws exactly those — not all of PTR/SRV/TXT, which
          // could flush a peer's matching same-name record we never sent. Host
          // A/AAAA are not withdrawn by a rename (the host name is unchanged).
          let owned = respond::EmittedRecords::new(
            self.goodbye.ptr,
            self.goodbye.srv,
            self.goodbye.txt,
            std::vec::Vec::new(),
            std::vec::Vec::new(),
            self.goodbye.subtypes,
          );
          self.pending_rename_goodbye = Some((self.records.clone(), RENAME_GOODBYE_SENDS, owned));
          self.rename_goodbye_deadline = Some(now); // first send due immediately
        }
        self.rename_attempt = self.rename_attempt.saturating_add(1);
        let new_name_str =
          rename_with_suffix(self.records.instance().as_str(), self.rename_attempt);
        match crate::Name::try_from_str(&new_name_str) {
          Ok(new_name) => {
            self.records.set_instance(new_name.clone());
            let _ = self.pending_updates.insert(ServiceUpdate::Renamed(
              crate::event::ServiceRenamed::new(new_name),
            ));
            self.state = ServiceState::Init;
            self.probe_count = 0;
            self.announce_count = 0;
            self.pending_transmits = [None, None];
            self.response_deadline = None;
            self.lifecycle_deadline = probe_deadline(now, 0, &mut self.rng);
            // the new name has NOT been announced yet, and the
            // old name's per-advertised-name state must not leak into it —
            // otherwise a later unregister/local-collision could goodbye a
            // never-announced name, and queued legacy replies / KAS hints
            // would advertise/suppress under the wrong (un-probed) name.
            self.reset_advertised_name_state();
          }
          Err(_) => {
            // rename failed (the suffixed name isn't a valid DNS
            // name) — give up. Mirror the success-branch cleanup so no stale
            // transmit / response-cycle work can still be drained by
            // poll_transmit after we've declared Conflicting.
            self.state = ServiceState::Conflicting;
            let _ = self.pending_updates.insert(ServiceUpdate::Conflict);
            self.lifecycle_deadline = None;
            self.pending_transmits = [None, None];
            self.response_deadline = None;
            self.goodbye.reset_instance();
            self.clear_response_cycle_state();
          }
        }
        return Ok(());
      }
      // We win: continue probing as if no conflict happened.
    }

    // Drain BOTH deadlines if both are due at `now`. The old
    // code returned early after firing response_deadline, silently skipping
    // lifecycle_deadline if it was also due. Now we check both independently,
    // push each kind into the two-slot queue via push_pending, and drain them
    // in poll_transmit one-by-one.  Both transmits are preserved — the old
    // single-slot design would drop the lifecycle transmit when both fired.

    // Step 1: check response deadline.
    let response_fired = if let Some(rd) = self.response_deadline {
      if now >= rd {
        self.response_deadline = None;
        true
      } else {
        false
      }
    } else {
      false
    };

    // Step 2: check lifecycle deadline (Init-synthesis + normal fire path).
    // For the Init state: if lifecycle_deadline is None (e.g. renamed before
    // first handle_timeout), synthesise a fresh probe deadline now.
    if self.state == ServiceState::Init && self.lifecycle_deadline.is_none() {
      self.lifecycle_deadline = probe_deadline(now, 0, &mut self.rng);
      // lifecycle didn't "fire" a transmit here — just scheduled; fall through.
    }

    let lifecycle_fired = if let Some(due) = self.lifecycle_deadline {
      if now >= due {
        // Advance lifecycle state and push a transmit kind into the queue via
        // push_pending.  The state advance MUST happen regardless of whether
        // the response deadline also fired at the same tick.
        match self.state {
          ServiceState::Init => {
            // Enter Probing phase; schedule the first probe delay.
            // No transmit yet — the probe fires when the delay elapses.
            self.state = ServiceState::Probing(0);
            self.lifecycle_deadline = probe_deadline(now, 0, &mut self.rng);
            // Init→Probing(0) schedules the NEXT deadline; no transmit this tick.
            false // no lifecycle transmit this tick
          }
          ServiceState::Probing(n) => {
            // a probe deadline fired — ENQUEUE the probe and re-arm a
            // fallback retry deadline, but do NOT advance the probe sequence
            // here. The §8.1 progression (next probe, or entering Announcing
            // after the third) happens in `note_transmit_result` ONLY once the
            // driver confirms the probe actually reached the link — mirroring
            // the Announcing arm below. An unconfirmed probe is retried at the
            // probe interval instead of the service silently marching toward
            // Announcing with nothing on the wire (RFC 6762 §8.1: a name must be
            // probed before it is claimed).
            self.push_pending(PendingTransmitKind::Probe);
            self.lifecycle_deadline = probe_deadline(now, n, &mut self.rng);
            true
          }
          ServiceState::Announcing(_) => {
            // an announce deadline fired — schedule the announcement
            // transmit but do NOT advance the phase here. The phase progression
            // and the Established update happen on CONFIRMED delivery
            // (`note_transmit_delivered`); peers learn of us only once a send
            // actually reaches the link. Re-arm at the announce interval so an
            // unconfirmed (all-socket-failed) send is retried rather than the
            // service silently progressing to Established with nothing on the
            // wire. A confirmed send overwrites this deadline.
            self.push_pending(PendingTransmitKind::Announcement);
            self.lifecycle_deadline = announce_deadline(now, 1);
            true
          }
          ServiceState::Established => {
            // The lifecycle deadline that fired is the periodic re-announce.
            self.push_pending(PendingTransmitKind::Announcement);
            self.lifecycle_deadline = re_announce_deadline(now, self.records.ttl_secs());
            true
          }
          ServiceState::Conflicting => {
            // No automatic progression — caller must intervene.
            false
          }
        }
      } else {
        false
      }
    } else {
      false
    };

    // Step 3: push a Response transmit if the response deadline fired.
    // The lifecycle arm already pushed its transmit (Probe/Announcement) above
    // via push_pending.  When both fire at the same tick, BOTH entries land in
    // the two-slot queue and poll_transmit drains them one-by-one.  This
    // preserves both transmits — the old single-slot design would silently drop
    // the lifecycle transmit by overwriting it with Response (fix).
    if response_fired {
      self.push_pending(PendingTransmitKind::Response);
    }
    let _ = lifecycle_fired; // used for clarity

    Ok(())
  }

  /// Produce the next outgoing datagram, if any. Writes into `buf`.
  ///
  /// Returns `Ok(None)` when the transmit queue is empty.  The caller should
  /// loop on this method until it returns `Ok(None)` to drain all pending
  /// transmits (at most 2 can be queued when both a response deadline and a
  /// lifecycle deadline fired at the same `now`).
  pub fn poll_transmit(
    &mut self,
    now: I,
    buf: &mut [u8],
  ) -> Result<Option<Transmit>, TransmitError> {
    // the commit token is a SINGLE slot. If a previously produced
    // datagram has not yet been confirmed via `note_transmit_result`, do NOT
    // hand out (and silently overwrite the token of) another one — that would
    // lose the first send's pending confirmation and mis-apply the next result
    // to the wrong datagram. Returning `Ok(None)` makes the documented
    // "poll until Ok(None)" drain contract enforce poll→confirm→poll ordering
    // for EVERY Sans-I/O caller, not just the tokio driver (which already
    // confirms after each send). The token is cleared by `note_transmit_result`
    // (`.take()`), so the next poll after a confirm proceeds normally; a probe/
    // announce/response branch below re-stamps it, while the early-return
    // datagrams (rename goodbye, legacy) only stamp where they own lifecycle/
    // ownership state.
    if self.awaiting_confirm.is_some() {
      return Ok(None);
    }
    // withdraw the OLD instance records first —
    // when a conflict renamed an announced service, peers still cache the old
    // PTR/SRV/TXT. Emit a TTL=0 multicast goodbye for ONLY the old instance
    // records (write_rename_goodbye omits the still-valid host A/AAAA) before
    // the new-name probe. The first send is due immediately; subsequent sends
    // are gated by `rename_goodbye_deadline` (RENAME_GOODBYE_INTERVAL apart) so
    // the resends are temporally independent, not a same-tick burst.
    if self.pending_rename_goodbye.is_some()
      && self.rename_goodbye_deadline.is_some_and(|due| now >= due)
    {
      // peek-then-pop — encode WITHOUT consuming, so a transient
      // too-small buffer preserves the withdrawal (surfaced as BufferTooSmall,
      // matching probe/announce/response) instead of silently dropping it.
      let encoded = match self.pending_rename_goodbye.as_ref() {
        Some((old, _, owned)) => respond::write_rename_goodbye(old, owned, buf),
        None => Ok(0), // unreachable (guarded by is_some above)
      };
      match encoded {
        Ok(n) => {
          // Confirm-on-send: stamp the commit token and DEFER spending the resend
          // budget (and scheduling the next resend) to `note_transmit_result`. An
          // all-family-busy send must NOT consume the withdrawal — the budget is
          // spent only on a delivered send, and a failed one re-arms it.
          self.awaiting_confirm = Some(AwaitingConfirm::RenameGoodbye);
          return Ok(Some(Transmit::new(respond::multicast_dst(), None, n)));
        }
        Err(_) => {
          return Err(TransmitError::BufferTooSmall(
            crate::error::BufferTooSmallDetail::new(buf.len(), buf.len()),
          ));
        }
      }
    }
    // §9: emit a pending service-type enumeration reply (a single shared
    // meta-PTR). Standalone like the rename goodbye — stamps NO awaiting_confirm
    // (it advertises no instance records and is never withdrawn), so it gates no
    // lifecycle/goodbye state. An un-encodable reply (near-MTU) is dropped, not
    // surfaced as an error, so a remote meta-query can't poison the service.
    if self.meta_response_deadline.is_some_and(|due| now >= due) {
      // Consume the meta cycle up-front: clear the deadline, the questioner set,
      // and the suppression flag regardless of outcome.
      self.meta_response_deadline = None;
      // (§9 + §7.1): suppress our redundant meta reply if a meta
      // questioner already holds our service-type PTR (sent it as a
      // known-answer). Only when EXACTLY ONE meta questioner coalesced
      // this window — mirrors the guard for the normal response path. With several
      // coalesced meta queriers a single source that already has our type must
      // NOT suppress the multicast reply the others still need.
      let suppressed = self.meta_known_answered && self.meta_questioner_srcs.len() == 1;
      self.meta_questioner_srcs.clear();
      self.meta_known_answered = false;
      if !suppressed
        && let Ok(meta) = crate::Name::try_from_str(crate::endpoint::DNS_SD_META_QUERY_NAME)
        && let Ok(n) = respond::write_meta_response(&self.records, &meta, buf)
      {
        return Ok(Some(Transmit::new(respond::multicast_dst(), None, n)));
      }
      // Suppressed, or name build (impossible) / encode failed — drop the reply
      // (state already cleared above), do not poison; fall through to the queue.
    }
    // drain legacy unicast responses (RFC 6762 §6.7) first — one
    // query-shaped, ID-echoing, TTL-capped datagram per legacy querier, sent
    // to its source.
    if let Some(legacy) = self.pending_legacy.first() {
      // a §9 meta reply emits only the shared meta-PTR (no instance
      // records, no goodbye ownership); a normal reply emits the full record set
      // and reports the EmittedRecords to latch on a confirmed delivery.
      let encoded = if legacy.is_meta {
        respond::write_legacy_meta_response(
          &self.records,
          legacy.query_id,
          &legacy.name,
          legacy.qtype,
          legacy.qclass,
          buf,
        )
        .map(|n| (n, None::<respond::EmittedRecords>))
      } else {
        respond::write_legacy_response(
          &self.records,
          legacy.query_id,
          &legacy.name,
          legacy.qtype,
          legacy.qclass,
          buf,
        )
        .map(|(n, emitted)| (n, Some(emitted)))
      };
      match encoded {
        Ok((n, emitted)) => {
          let resp = self.pending_legacy.remove(0);
          // a §6.7 legacy reply puts positive-TTL records on
          // the wire — the FULL record set, since legacy replies are not
          // KAS-filtered. Stamp the Response commit token with exactly what the
          // encoder reported it emitted; a confirmed delivery then latches
          // goodbye ownership for those records via `note_transmit_result`. A
          // meta reply (`emitted` is None) latches nothing — the meta-PTR is
          // shared and never withdrawn.
          self.awaiting_confirm = emitted.map(AwaitingConfirm::Response);
          return Ok(Some(Transmit::new(resp.dst, None, n)));
        }
        // a legacy reply echoes the question, so it can exceed the
        // buffer for a near-MTU service whose normal announcement still fits.
        // DROP the un-encodable entry rather than (a) leaving it stuck at the
        // head blocking all transmits, or (b) surfacing BufferTooSmall — which
        // the driver counts as a SERVICE encode failure and would use to
        // unregister an otherwise-healthy service. A remote query
        // must not be able to poison the service. The legacy querier simply
        // gets no reply (it retries / falls back); the service is untouched.
        Err(_) => {
          let _ = self.pending_legacy.remove(0);
          // Fall through to the normal (announce/probe/response) queue.
        }
      }
    }
    // PEEK without removing — if encoding fails the kind stays in the queue so
    // the caller can retry with a larger buffer.
    let kind = match self.peek_pending() {
      Some(k) => k,
      None => return Ok(None),
    };
    // which owner groups a Response actually emitted (after KAS).
    let mut resp_emitted = respond::EmittedRecords::default();
    let n = match kind {
      PendingTransmitKind::Probe => respond::write_probe(&self.records, buf).map_err(|_| {
        TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(
          buf.len(),
          buf.len(),
        ))
      })?,
      PendingTransmitKind::Announcement => {
        // Unsolicited announcements (Announcing(_) phase and periodic re-announce
        // from Established) are sent without KAS filtering. RFC 6762 §7.1
        // known-answer suppression only applies to question responses.
        respond::write_announce(&self.records, buf).map_err(|_| {
          TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(
            buf.len(),
            buf.len(),
          ))
        })?
      }
      PendingTransmitKind::Response => {
        // Jittered question responses normally apply KAS filtering
        // (RFC 6762 §7.1) — skip records the querier already holds.
        //
        // when MULTIPLE questioners coalesced in the same
        // response window, hints from one source must NOT suppress
        // records that another source needs.  Per-source KAS state
        // is a deeper refactor; this defensive simplification
        // disables KAS filtering entirely for coalesced responses.
        // The cost is sending a few extra records the single hinter
        // already had; the gain is closing the cross-source DoS
        // path where peer B's hint suppresses peer A's answer.
        let single_questioner = self.questioner_srcs.len() <= 1;
        let hints = self.kas_hints;
        let last_now = self.last_now;
        let (encoded, emitted) =
          respond::write_announce_filtered(&self.records, buf, |rtype, rdata| {
            if !single_questioner {
              return false;
            }
            let h = hash_rdata(rdata);
            let now_ref = match last_now {
              Some(t) => t,
              None => return false,
            };
            // a hint may only suppress the RRset it actually names. Map
            // this candidate's owner to its kind (PTR↦service-type, SRV/TXT↦
            // instance, A/AAAA↦host) and require the hint to share it — so a
            // same-rtype/same-rdata known-answer under a DIFFERENT owner name
            // cannot silence our record.
            let owner = match rtype {
              crate::wire::ResourceType::Ptr => KasOwner::ServiceType,
              crate::wire::ResourceType::Srv | crate::wire::ResourceType::Txt => KasOwner::Instance,
              crate::wire::ResourceType::A | crate::wire::ResourceType::AAAA => KasOwner::Host,
              _ => return false,
            };
            hints.iter().any(|slot| match slot {
              Some(hint) => {
                hint.owner == owner
                  && hint.rtype == rtype
                  && hint.rdata_hash == h
                  && hint.expires_at > now_ref
              }
              None => false,
            })
          })
          .map_err(|_| {
            TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(
              buf.len(),
              buf.len(),
            ))
          })?;
        resp_emitted = emitted;
        encoded
      }
    };
    // Encoding succeeded — NOW remove from the queue (peek-then-pop).
    let kind = self.peek_pending();
    self.pop_pending();
    // the datagram has been
    // ENCODED, but no lifecycle state advances here. Map the queued kind to the
    // commit token the driver resolves via `note_transmit_result` — the SOLE
    // place probe/announce progression AND goodbye-ownership latching happen,
    // and only on a confirmed send.
    self.awaiting_confirm = match kind {
      Some(PendingTransmitKind::Probe) => Some(AwaitingConfirm::Probe),
      Some(PendingTransmitKind::Announcement) => {
        // A full (unfiltered) announcement carries every instance record
        // (PTR/SRV/TXT) and every host address — §7.1 known-answer suppression
        // does NOT apply to unsolicited announcements. Latch goodbye ownership
        // for exactly that record set, same path as a response.
        Some(AwaitingConfirm::Announcement(respond::EmittedRecords::new(
          true,
          true,
          true,
          self.records.a_addrs_slice().to_vec(),
          self.records.aaaa_addrs_slice().to_vec(),
          !self.records.subtype_names().is_empty(),
        )))
      }
      Some(PendingTransmitKind::Response) => {
        // KAS state is per-response-cycle — clear the hint ring
        // and questioner set now that this Response consumed it.
        self.kas_hints = [None; KAS_RING_SIZE];
        self.questioner_srcs.clear();
        // / §7.1: if KAS suppressed EVERY record the response is
        // header-only — do not put an empty response on the wire, and latch
        // nothing (a header-only datagram advertises nothing to withdraw).
        if resp_emitted.is_empty() {
          return Ok(None);
        }
        // Latch goodbye ownership only for the concrete records actually emitted.
        Some(AwaitingConfirm::Response(resp_emitted))
      }
      None => None,
    };
    let _ = self.pending_tx.iter().next(); // silence unused-field warning
    // Multicast response — serves QM and QU (§5.4) group members. Legacy unicast
    // queriers are handled separately via `pending_legacy`.
    Ok(Some(Transmit::new(respond::multicast_dst(), None, n)))
  }
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(all(any(feature = "alloc", feature = "std"), feature = "slab"))]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::panic,
  clippy::indexing_slicing,
  clippy::arithmetic_side_effects
)]
mod tests;

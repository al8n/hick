//! Service state machine — probing, announcing, response generation.

cfg_heap! {
  use crate::trace::*;

  mod respond;
}
pub(crate) mod schedule;
mod state;

cfg_heap! {
  use crate::backend::{RdataBuf, rdata_from_vec};
}

cfg_heap! {
  /// Which of OUR owner names a known-answer's record name matched. §7.1
  /// suppression is per RRset, and an RRset is identified by (name, type, class,
  /// rdata). A known-answer with our rtype + rdata but a DIFFERENT owner name is a
  /// DIFFERENT RRset and must NOT suppress our record — otherwise a querier could
  /// silence our `host.local A x` by sending a same-rdata `_svc._tcp.local A x`.
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
  #[derive(Debug, Clone, Copy)]
  struct KasHint<I> {
    owner: KasOwner,
    rtype: crate::wire::ResourceType,
    rdata_hash: u64,
    expires_at: I,
  }

  /// Number of KAS hints we'll remember at once (per service).
  const KAS_RING_SIZE: usize = 16;

  /// Cap on the number of distinct questioner sources tracked per
  /// response cycle.  Mirrors `MAX_PEER_PROBES` — bursts of
  /// queries from more than this many distinct sources within one
  /// jitter window get the excess sources rejected (no hint storage
  /// for them), which is conservative but bounded.
  const MAX_QUESTIONER_SRCS: usize = 8;

  /// Maximum legacy unicast responses queued per response cycle. Each
  /// distinct legacy querier gets its own reply; beyond this cap, excess legacy
  /// queriers in the same window are dropped (bounded against a flood).
  const MAX_LEGACY_RESPONSES: usize = 8;

  /// A pending RFC 6762 §6.7 legacy unicast response: a non-mDNS querier (source
  /// port != 5353) gets a direct reply that echoes its query ID + question.
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
  const MAX_PEER_PROBE_RECORDS: usize = 16;

  /// Maximum number of distinct peer sources we track per tiebreak round.
  /// Records from sources beyond this cap are silently dropped.
  const MAX_PEER_PROBES: usize = 8;

  /// minimum interval between conflict-driven re-probes of an
  /// Established/Announcing service (RFC 6762 §9 conflict rate-limiting). A
  /// conflict flood cannot reset us to Probing faster than this, so a hostile
  /// peer cannot prevent the service from ever (re)establishing.
  const CONFLICT_REPROBE_MIN_INTERVAL: core::time::Duration = core::time::Duration::from_secs(1);

  /// One record from a peer's simultaneous probe, retained for the RFC §8.2
  /// tiebreak comparison (lexicographic comparison of proposed RR sets).
  #[derive(Debug, Clone)]
  struct PeerRecord {
    rtype: crate::wire::ResourceType,
    /// Canonical byte form of the rdata (same encoding used by KAS hashing).
    canonical: RdataBuf,
  }

  /// A per-source bucket of probe records observed during the current probe round.
  /// Each distinct peer source gets its own bucket so that the RFC §8.2 tiebreak
  /// compares against each peer independently (we lose if ANY peer wins).
  #[derive(Debug)]
  struct PeerProbe {
    src: core::net::SocketAddr,
    records: std::vec::Vec<PeerRecord>,
  }
}

cfg_heap! {
  /// Write a DNS name in canonical wire form (length-prefixed labels, root
  /// terminator). Used for SRV target encoding in RFC §8.2 tiebreak comparison.
  /// This produces byte-identical output for both OUR outgoing SRV and for a
  /// peer SRV parsed via `canonical_rdata_for_hash`, ensuring the bytewise
  /// comparison is correct.
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
}

cfg_heap! {
  #[allow(unused_imports)]
  pub(crate) use respond::{EmittedRecords, multicast_dst, write_goodbye};
}
#[allow(unused_imports)]
pub(crate) use schedule::{
  FamilyPatience, MAX_PARTIAL_ROUNDS, PhaseAdvance, announce_deadline, classify_advance,
  compose_announce_deadline, partial_announce_deadline, probe_deadline, re_announce_deadline,
  stalest_refresh_due,
};
pub use state::ServiceState;

cfg_heap! {
  use core::time::Duration;

  use rand::SeedableRng;

  use crate::error::{HandleTimeoutError, TransmitError};
  use crate::event::{ServiceEvent, ServiceUpdate};
  use crate::records::ServiceRecords;
  use crate::transmit::{FamilyDelivery, Transmit, TransmitDelivery, TransmitObligation};
  use crate::{Instant, Pool, ServiceHandle};

  type Rng = rand::rngs::StdRng;
}

cfg_heap! {
  /// Build a new instance-name string by appending (or replacing) a `-N` suffix
  /// on the first DNS label.
  ///
  /// `current` is the full FQDN of the instance (e.g. `"myprinter._ipp._tcp.local."`).
  /// `attempt` is the rename counter (1, 2, …).
  ///
  /// For a name like `"myprinter._ipp._tcp.local."` and attempt `2` the result
  /// is `"myprinter-2._ipp._tcp.local."`.  Any existing `-N` suffix on the
  /// instance label is stripped first so repeated conflicts don't accumulate.
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
          buf.extend_from_slice(&p.canonical[..]);
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
}

cfg_heap! {
  /// What kind of transmit is pending for a service.
  ///
  /// Capturing the kind at deadline-fire time (before state is advanced) ensures
  /// `poll_transmit` encodes the correct packet type even when state has already
  /// transitioned (e.g., Probing(2) → Announcing(0) on the final probe tick).
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
  /// `note_transmit_outcome`. Unlike [`PendingTransmitKind`] (which is
  /// queued at deadline-fire time), this carries what was ACTUALLY encoded, so a
  /// response that known-answer-suppression (§7.1) trimmed latches goodbye
  /// ownership only for the concrete records it really put on the wire
  /// (per record, not per group).
  ///
  /// # Token lifecycle across every state-mutating entry point
  ///
  /// The confirm-before-anything contract on [`Service::poll_transmit`] means no
  /// state-mutating entry point may run while a token is live, so for a compliant
  /// driver every row below except `poll_transmit` and `note_transmit_outcome` is
  /// unreachable. The core cannot type-check the ordering, though, and a
  /// violation must stay defined rather than silently corrupting state in
  /// release — so each entry point still declares what it does to a live token.
  /// Every cell marked "rewrite" is a BACKSTOP: unreachable for a compliant
  /// driver, and what happens if the contract is broken.
  ///
  /// The counter column covers all three pieces of per-round state: the
  /// per-family patience (`partial_rounds`, a [`FamilyPatience`] each), the §8.3
  /// ladder exponent (`partial_announce_streak`), and the per-family refresh
  /// anchors (`last_delivered`). "zeroed" means `FamilyPatience::default()` — the
  /// count, the coverage bit, and the good-standing latch together.
  ///
  /// | entry point | live token | partial counters (`partial_rounds` / `partial_announce_streak` / `last_delivered`) | deadlines |
  /// |---|---|---|---|
  /// | `handle_event` §8.2 probe-conflict buffer | untouched — buffering a peer record is not a lifecycle move | untouched | untouched |
  /// | `handle_event` §9 same-name revert (`Init`) | backstop: **rewrite** → `Stale`, name unchanged | `partial_rounds` zeroed (fresh §8.1 sequence); streak untouched — same name, same §8.3 ladder; `last_delivered` untouched, since peers still hold THESE records under THIS name and each family still races the same TTL | `response_deadline` cleared, `lifecycle_deadline` = fresh probe |
  /// | `handle_event` Question / KnownAnswer / HostConflict | untouched — none of them regress a phase | untouched | `response_deadline` / `meta_response_deadline` only |
  /// | `handle_timeout` §8.2 tiebreak → rename (`Init`) | backstop: **rewrite** → `Stale`, old-name records captured | all three cleared by `reset_advertised_name_state` — a NEW name starts every sequence over, and no family is owed a refresh of a name it has never heard | `response_deadline` cleared, `lifecycle_deadline` = fresh probe |
  /// | `handle_timeout` §8.2 tiebreak → `Conflicting` (invalid new name) | backstop: **rewrite** → `Stale`, old-name records captured | streak zeroed; `partial_rounds` / `last_delivered` untouched — terminal, nothing left to excuse and nothing left to schedule | all cleared |
  /// | `handle_timeout` `Init` → `Probing(0)` | untouched — a forward step, and it emits nothing | untouched | re-armed |
  /// | `handle_timeout` `Probing`/`Announcing`/`Established` fire | untouched; backstop: `push_lifecycle_pending` queues NOTHING while a token is live, so no lifecycle transmit outlives the confirm | untouched | re-armed |
  /// | `handle_timeout` `Conflicting` | untouched — no progression | untouched | untouched |
  /// | `poll_transmit` | refuses (`Ok(None)`) while one is live — the single slot is what matches one confirm to one datagram | untouched | untouched |
  /// | `note_transmit_outcome` | consumed (`.take()`) | per the confirm arms; only the Probe and Announcement arms touch patience, and only the Announcement arm touches `last_delivered` | per the confirm arms |
  /// | `withdrawal_snapshot` | untouched — a pure read of the latch, and it asserts rather than reporting a short goodbye | untouched | untouched |
  /// | `take_rename_goodbye_handoff` | untouched — pure `.take()` of the handoff field | untouched | untouched |
  ///
  /// Teardown is the row where the contract is doing the most work.
  /// [`Service::withdrawal_snapshot`] can only report what a confirm has already
  /// latched, so a datagram outstanding across a teardown would put records in
  /// peer caches that the §10.1 goodbye then never withdraws — and those records'
  /// TTLs would only START at that late transmission, so the exposure is not
  /// bounded by the teardown at all. Confirming before tearing down is what makes
  /// the snapshot complete.
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
    /// those latch goodbye ownership on a confirmed send.  The second field is
    /// the count of records §7.1 KAS suppressed from THIS response (partial
    /// suppression); it is bumped into `answers_suppressed_kas` ONLY on a
    /// confirmed delivery so a socket failure cannot inflate the counter.
    Response(respond::EmittedRecords, u64),
    /// A RFC 6763 §9 service-type enumeration meta-response (multicast or legacy
    /// unicast) is awaiting confirmation. The meta-PTR is a shared record — it
    /// advertises no instance-owned records and is never withdrawn — so a confirmed
    /// delivery bumps `responses_tx` WITHOUT touching goodbye ownership or any
    /// lifecycle state.
    MetaResponse,
    /// A datagram whose LIFECYCLE meaning a regression to [`ServiceState::Init`]
    /// has voided: it was encoded for a generation of the state machine that a
    /// RFC 6763 §9 same-name revert-to-probe, or a RFC 6762 §8.2 conflict rename,
    /// has since replaced.
    ///
    /// The datagram itself is real and may well be delivered, so the token keeps
    /// exactly the two facts that outlive the generation — which counter the send
    /// earned, and WHOSE records it put on the wire — and drops everything else.
    /// See [`Service::stale_live_commit_token`] for why the second fact is
    /// captured at the regression rather than reconstructed at confirm time.
    Stale {
      /// The wire fact the datagram still earns on delivery.
      fact: StaleWireFact,
      /// Where a delivered confirm must latch the records it carried.
      records: StaleRecords,
    },
  }

  /// Which counter a regression-voided datagram's confirm still owes.
  ///
  /// Only the counters: every LIFECYCLE effect of the original token is void. The
  /// distinction is the code's own documented split between wire facts and
  /// lifecycle facts — `responses_tx` reflects every datagram that left the host,
  /// and `probes_tx` / `announcements_tx` mean "confirmed delivered by every
  /// obligated link" — neither of which says anything about which generation the
  /// datagram belonged to.
  #[cfg_attr(not(feature = "stats"), allow(dead_code))]
  #[derive(Debug, Clone, Copy, Eq, PartialEq)]
  enum StaleWireFact {
    /// RFC 6762 §8.1 probe: `probes_tx` on a fully-delivered confirm.
    Probe,
    /// §8.3 unsolicited announcement: `announcements_tx` on a fully-delivered
    /// confirm.
    Announcement,
    /// §6 multicast or §6.7 legacy-unicast response: `responses_tx` on ANY
    /// delivery, plus the §7.1 partial-suppression count the response carried.
    Response(u64),
  }

  /// Which name a regression-voided datagram advertised, and therefore where a
  /// delivered confirm must latch its records so they can still be withdrawn.
  #[derive(Debug, Clone)]
  enum StaleRecords {
    /// Nothing to latch. A probe is a QUESTION (§8.1) — it advertises no records
    /// at all — and it is the only stale datagram that carries none.
    None,
    /// The service STILL holds the name these records were emitted under (the §9
    /// same-name revert-to-probe): they latch into the live `goodbye` exactly as
    /// they would have without the regression.
    SameName(respond::EmittedRecords),
    /// The service has RENAMED AWAY from the name these instance records were
    /// emitted under. `records` is the OLD name, cloned at the regression site
    /// before `ServiceRecords::set_instance` overwrote it, so the detached
    /// old-name §10.1 goodbye can still withdraw them.
    OldName {
      /// The OLD instance name's records.
      records: ServiceRecords,
      /// What the datagram actually emitted under that name.
      emitted: respond::EmittedRecords,
    },
  }

  impl AwaitingConfirm {
    /// The [`TransmitObligation`] this token implies, i.e. whether
    /// [`Service::note_transmit_outcome`] will re-arm the datagram until every
    /// obligated link accepts it.
    ///
    /// Derived from the token — what was actually ENCODED — and never from
    /// `self.state`. Two things make the state wrong here. The periodic
    /// `Established` re-announce advances no phase yet is still re-armed on the
    /// RFC 6762 §8.3 doubling ladder while a link keeps missing it, so a
    /// phase-derived tag would call it fire-and-forget. And the state can advance
    /// between the deadline firing and the datagram being encoded — the drift
    /// [`PendingTransmitKind`] already exists to absorb.
    #[inline]
    fn obligation(&self) -> TransmitObligation {
      match self {
        // Re-armed until every obligated link hears it: the §8.1 probe sequence
        // and the §8.3 announcement (startup phase AND periodic re-announce).
        Self::Probe | Self::Announcement(_) => TransmitObligation::Sustained,
        // A response is emitted once for the question that provoked it and is
        // never re-armed, so no link can pin anything by missing it. A
        // regression-voided datagram belongs to a generation that no longer
        // exists, so nothing will ever re-arm it either. (Unreachable in
        // practice: `stamped_obligation` reads the token `poll_transmit` just
        // stamped, and `poll_transmit` never stamps `Stale`.)
        Self::Response(_, _) | Self::MetaResponse | Self::Stale { .. } => {
          TransmitObligation::OneShot
        }
      }
    }

    /// The minimum wire gap this token's datagram owes each family it is fanned
    /// onto ([`Transmit::min_family_gap`]).
    ///
    /// Kind-dependent, and read from the token for the same reason the
    /// obligation is: it describes what was actually ENCODED, not what
    /// `self.state` has since become.
    ///
    /// * A probe is RFC 6762 §8.1's, spaced [`schedule::rfc::PROBE_INTERVAL`]
    ///   apart and explicitly exempt from the one-second rule §6 applies to
    ///   records — §8.1's own sequence would be illegal under it.
    /// * An unsolicited announcement — the §8.3 burst and the periodic
    ///   `Established` re-announce alike — is not exempt: §6 forbids
    ///   re-multicasting a record on an interface inside
    ///   [`schedule::rfc::ANNOUNCE_INTERVAL`] of the last time it went out on
    ///   that same interface, and §8.3's own floor says the same.
    /// * Everything else is one-shot and ungated (see
    ///   [`Transmit::min_family_gap`]).
    #[inline]
    fn min_family_gap(&self) -> Duration {
      match self {
        Self::Probe => schedule::rfc::PROBE_INTERVAL,
        Self::Announcement(_) => schedule::rfc::ANNOUNCE_INTERVAL,
        Self::Response(_, _) | Self::MetaResponse | Self::Stale { .. } => Duration::ZERO,
      }
    }
  }

  /// Goodbye ownership: which CONCRETE records peers may have cached FROM US, and
  /// therefore what a graceful goodbye (TTL=0) must withdraw. The granularity is
  /// per record — each instance-owned record (PTR/SRV/TXT) independently, and each
  /// host-owned address (A/AAAA) independently — matching what the endpoint's
  /// withdrawal (built from [`Service::withdrawal_snapshot`]) withdraws (host
  /// addresses are further filtered against sibling-retained addresses).
  ///
  /// INVARIANT: a record becomes "advertised" ONLY through a CONFIRMED send that
  /// actually emitted THAT record ([`Self::record_emitted`], driven by the
  /// encoder's per-record report via `note_transmit_outcome`). A send that never
  /// reaches the link — or whose record was known-answer-suppressed (§7.1) —
  /// advertises nothing, so a later goodbye never withdraws a record we did not
  /// put on the wire (which could otherwise flush a peer's matching shared
  /// record). Per-record (not per-group) granularity closes the over-withdrawal
  /// class where §7.1 trims a subset of a group or a legacy reply emits a whole
  /// group the per-group latch mis-attributed.
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

  impl GoodbyeOwnership {
    /// Latch the concrete records a confirmed-delivered send actually emitted — the
    /// SOLE way ownership is gained (besides being reset to none on rename).
    fn record_emitted(&mut self, e: &respond::EmittedRecords) {
      self.ptr |= e.ptr();
      self.srv |= e.srv();
      self.txt |= e.txt();
      self.subtypes |= e.subtypes();
      self.record_host_emitted(e);
    }
    /// Latch ONLY the host-owned addresses of a confirmed-delivered send.
    ///
    /// Used when the send's INSTANCE records belong to a name the service has
    /// since renamed away from: the host name is invariant across an instance
    /// rename, so those addresses really are cached under a name this service
    /// still holds and stay its to withdraw, while the instance records go to the
    /// detached old-name goodbye instead.
    fn record_host_emitted(&mut self, e: &respond::EmittedRecords) {
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
}

cfg_heap! {
  /// A point-in-time snapshot of everything the [`crate::Endpoint`] needs to re-encode
  /// the TTL=0 goodbye for a service being withdrawn.
  ///
  /// Produced by [`Service::withdrawal_snapshot`] and consumed by the endpoint's
  /// withdrawal state machine. Each resend round calls the
  /// encoder with the same snapshot so the goodbye is idempotent over multiple
  /// attempts (RFC 6762 §10.1 recommends at least two sends for loss resilience).
  ///
  /// The `#[cfg]` gate matches the goodbye code it supports — the goodbye path is
  /// only compiled when heap allocation is available.
  #[derive(Debug, Clone)]
  pub struct WithdrawalSnapshot {
    /// The service records (names, port, TXT) for this withdrawal. Carried so
    /// the encoder can re-encode PTR/SRV/TXT at TTL=0 without a live `Service`.
    pub records: crate::records::ServiceRecords,
    /// Which record kinds (PTR/SRV/TXT/subtypes) this service actually put on the
    /// wire (per-record, not per-group). Mirrors the [`GoodbyeOwnership`] latch
    /// semantics: only records that reached a peer cache need to be withdrawn.
    /// `pub(crate)` because `EmittedRecords` is a crate-internal type; the
    /// endpoint (same crate) reads this directly.
    // `allow(dead_code)`: the field is read by the endpoint withdrawal state
    // machine; suppress the false positive here.
    #[allow(dead_code)]
    pub(crate) owned: respond::EmittedRecords,
    /// Host A (IPv4) addresses this service confirmed-emitted. The endpoint will
    /// further filter these against same-host siblings before re-encoding.
    pub host_a: std::vec::Vec<core::net::Ipv4Addr>,
    /// Host AAAA (IPv6) addresses this service confirmed-emitted.
    pub host_aaaa: std::vec::Vec<core::net::Ipv6Addr>,
  }
}

cfg_heap! {
  /// The one-shot §9 conflict-rename goodbye handoff: the OLD instance name's
  /// records plus the per-record ownership of what that name actually advertised.
  ///
  /// Produced by
  /// [`Service::take_rename_goodbye_handoff`] the instant a conflict rename
  /// happens, and handed straight to
  /// [`Endpoint::enqueue_rename_withdrawal`](crate::Endpoint::enqueue_rename_withdrawal),
  /// which turns it into an independent DETACHED withdrawal item (the renamed-away
  /// old name's TTL=0 goodbye). It is **opaque** to the driver — both fields are
  /// crate-internal (`EmittedRecords` is `pub(crate)`) — so a driver only ever
  /// moves the whole value between the two calls, exactly like
  /// [`WithdrawalSnapshot`]. A rename never withdraws host A/AAAA (the host name is
  /// invariant), so this carries no host addresses.
  ///
  /// The `#[cfg]` gate matches the goodbye code it supports.
  #[derive(Debug, Clone)]
  pub struct RenameGoodbyeHandoff {
    /// The OLD instance name's records (names, port, TXT), captured BEFORE the
    /// rename mutated the instance name. `pub(crate)`: the endpoint (same crate)
    /// reads it directly.
    pub(crate) records: crate::records::ServiceRecords,
    /// Which instance records (PTR/SRV/TXT/subtypes) the OLD name actually put on
    /// the wire — only these are withdrawn (§7.1 KAS can suppress a subset). The
    /// address lists are always empty (a rename never withdraws host A/AAAA).
    /// `pub(crate)`: `EmittedRecords` is a crate-internal type.
    pub(crate) owned: respond::EmittedRecords,
  }
}

cfg_heap! {
  /// Unforgeable proof of [`Service::has_fully_announced`] — the reclaim-cancel
  /// gate of
  /// [`Endpoint::note_service_announced`](crate::Endpoint::note_service_announced).
  ///
  /// There is NO public constructor and no `From<bool>`: the only way a driver can
  /// obtain a value is to ask the `Service` that owns the fact. That is the whole
  /// purpose of the type. The gate's predecessor took a plain `bool`, and every
  /// shipped driver filled it with [`Service::advertises_instance`] — the
  /// ANY-delivered exposure latch, which is a different fact and makes the cancel
  /// unsound (a v4-only announcement, or an RFC 6762 §6.7 legacy unicast reply,
  /// would retire a goodbye the unserved family still needs). A `bool` parameter
  /// cannot reject that; this type can, at compile time.
  ///
  /// The distinction matters more here than at the other confirm boundaries
  /// because this is the ONE migration leg with no compile-time forcing function:
  /// deleting the boolean confirm METHODS makes every other call site fail to
  /// compile, whereas a same-arity `bool` parameter whose MEANING changed would
  /// silently survive both the driver migration and any external upgrade.
  ///
  /// The token also NAMES the service it was minted from, and
  /// [`Endpoint::note_service_announced`](crate::Endpoint::note_service_announced)
  /// takes no separate handle. An unforgeable fact is still transplantable while
  /// the subject is a second argument: a genuine `true` from service A, paired
  /// with service B's handle, would cancel B's reclaimable goodbye while an
  /// obligated family still needs it. Carrying the subject inside the proof makes
  /// that pairing unrepresentable rather than merely validated.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  #[must_use]
  pub struct FullyAnnounced {
    handle: ServiceHandle,
    fully_announced: bool,
  }

  impl FullyAnnounced {
    /// Wrap the fact together with the service it is a fact ABOUT.
    /// Crate-internal: [`Service::has_fully_announced`] is the sole caller, which
    /// is what makes the type unforgeable outside this crate.
    #[inline(always)]
    pub(crate) const fn new(handle: ServiceHandle, fully_announced: bool) -> Self {
      Self {
        handle,
        fully_announced,
      }
    }

    /// The service this fact is about — the [`Service`] that minted it. The
    /// endpoint routes on this instead of a caller-supplied handle, so the fact
    /// and its subject cannot be separated.
    #[inline(always)]
    pub(crate) const fn handle(self) -> ServiceHandle {
      self.handle
    }

    /// Whether a complete announcement of the service's current instance name has
    /// reached every obligated link.
    #[inline(always)]
    pub const fn get(self) -> bool {
      self.fully_announced
    }
  }
}

cfg_heap! {
  /// Service state machine. One per registered service.
  ///
  /// Driving one means honouring two call-ordering contracts: drain
  /// [`Service::poll_transmit`] until it returns `Ok(None)`, and confirm each
  /// datagram it hands out — via [`Service::note_transmit_outcome`] — before
  /// invoking any other state-mutating entry point on this service.
  /// [`Service::poll_transmit`] documents the second one in full.
  pub struct Service<I, TQ, EV> {
  handle: ServiceHandle,
  state: ServiceState,
  records: ServiceRecords,
  #[cfg(feature = "stats")]
  stats: Option<std::sync::Arc<hick_trace::stats::Stats>>,
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
  /// Whether a COMPLETE §8.3 announcement of the CURRENT instance name has
  /// reached every obligated link. Set ONLY by an `AllDelivered` announcement
  /// confirm; reset by a §9 conflict rename alongside
  /// [`GoodbyeOwnership::reset_instance`], because the new name has announced
  /// nothing. Distinct from `goodbye.any_instance()`, which is an ANY-delivered
  /// exposure latch: see [`Service::has_fully_announced`] for why the endpoint's
  /// reclaim-cancel needs the all-delivered fact and not the exposure one.
  fully_announced: bool,
  /// Consecutive `PartiallyDelivered` announcement confirms since the last phase
  /// advance — the exponent of the RFC §8.3 doubling ladder
  /// (`partial_announce_deadline`). A partial announcement puts a real datagram
  /// on the served link's wire every re-arm, so its repetition must respect
  /// §8.3's "increases by at least a factor of two with every response sent";
  /// a fully-failed send reaches no wire and so neither uses nor advances this.
  partial_announce_streak: u8,
  /// Per family ([0] = v4, [1] = v6): consecutive LIFECYCLE confirms (§8.1 probe
  /// or §8.3 announcement) in which THAT family was obligated and missed a
  /// datagram some other family carried — the core's own patience, bounded by
  /// `MAX_PARTIAL_ROUNDS`. Reaching the bound EXCUSES that family, so the phase
  /// advances from exactly where it stood instead of pinning forever, and takes it
  /// out of good standing so it stops driving the refresh schedule below until it
  /// delivers again.
  ///
  /// Per family rather than per round because those disagree exactly where it
  /// matters: two families alternating under a capacity-one transport look
  /// identical to one chronically dead family through a shared counter, and the
  /// first must not be excused at all.
  ///
  /// It lives beside the per-kind confirm arms that maintain it, so a §6 response
  /// or a §9 meta reply — never re-armed, so evidence of nothing — structurally
  /// cannot touch it. Reset by that family's OWN delivery and by it ceasing to be
  /// obligated; left ALONE by a wholly-failed round (see `classify_advance`); and
  /// zeroed wherever the lifecycle regresses to `Init`, which starts a fresh
  /// §8.1 sequence.
  partial_rounds: [FamilyPatience; 2],
  /// Per family ([0] = v4, [1] = v6): when this family last had an ANNOUNCEMENT
  /// delivered to it — the event that refreshes the record TTLs in that family's
  /// peer caches. `None` means the family is not obligated (no socket for it).
  ///
  /// Each family races its OWN copy of the TTL, so the periodic re-announce is
  /// scheduled off the stalest of these rather than off the last round: under a
  /// capacity-one transport every round is partial while each family is served
  /// only every other one, so a round-anchored schedule refreshes each family at
  /// TWICE the periodic interval and its records expire from every peer cache
  /// while every per-round invariant still holds.
  ///
  /// Only the announcement confirm arm writes it. A probe advertises nothing, and
  /// a §6 response refreshes one querier's cache with whatever §7.1 left of it —
  /// neither is a refresh this schedule may count on.
  ///
  /// A family that becomes obligated at runtime is anchored at THAT moment rather
  /// than left `None`: unanchored reads as "not obligated" and would defer it
  /// silently, while anchoring it in the past would read as infinitely stale and
  /// re-arm every confirm at the §8.3 floor.
  last_delivered: [Option<I>; 2],
  /// the commit token for the datagram `poll_transmit`
  /// most recently produced — `Some(kind)` while that send is awaiting a
  /// delivery result, `None` otherwise. This is the structural heart of the
  /// confirm-on-send invariant: `poll_transmit` ONLY stamps this token and
  /// advances no lifecycle state; ALL lifecycle progression happens in
  /// [`Self::note_transmit_outcome`], keyed on the token. Because of that a send
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
  /// One-shot handoff of the OLD instance name's TTL=0 goodbye when a §9 conflict
  /// renames an ANNOUNCED service. Set at the rename site (`handle_timeout`) with
  /// the OLD records and WHICH instance records that name actually advertised
  /// (`EmittedRecords` with the instance bits set, addresses empty — a rename
  /// never withdraws host A/AAAA, the host name is invariant). The Service no
  /// longer drains this itself: the driver takes it via
  /// [`Self::take_rename_goodbye_handoff`] immediately after observing the
  /// `Renamed` update and hands it to
  /// [`crate::Endpoint::enqueue_rename_withdrawal`], which models the old-name
  /// goodbye as an INDEPENDENT detached withdrawal item (its own per-family debt,
  /// schedule, and loss-resilience resends). `None` when the renamed name had
  /// never advertised an instance record (nothing for peers to evict) or after
  /// the handoff has been taken.
  rename_goodbye_handoff: Option<RenameGoodbyeHandoff>,
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
  /// Test-only: silence [`Service::assert_no_live_commit_token`] so a test can
  /// drive the entry points the way a NON-COMPLIANT driver would and pin what
  /// the release-mode backstops actually do. Those backstops only exist for a
  /// driver that breaks the contract, so the assertion that catches such a
  /// driver in debug builds would otherwise make them untestable. `cfg(test)`:
  /// it does not exist in a shipped build and no public API sets it.
  #[cfg(test)]
  contract_assertions_off: bool,
  }
}

cfg_heap! {
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
      #[cfg(feature = "stats")]
      stats: None,
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
      fully_announced: false,
      partial_announce_streak: 0,
      partial_rounds: [FamilyPatience::default(); 2],
      last_delivered: [None, None],
      awaiting_confirm: None,
      pending_legacy: std::vec::Vec::new(),
      last_conflict_reprobe: None,
      rename_goodbye_handoff: None,
      meta_response_deadline: None,
      meta_questioner_srcs: std::vec::Vec::new(),
      meta_known_answered: false,
      #[cfg(test)]
      contract_assertions_off: false,
    }
  }

  /// Test-only: opt this service out of the debug-build contract assertions.
  ///
  /// The only callers are the backstop tests, which must reproduce a
  /// non-compliant driver to observe what release builds do when the contract is
  /// broken.
  #[cfg(test)]
  pub(crate) fn disable_contract_assertions(&mut self) {
    self.contract_assertions_off = true;
  }

  /// Attach the shared [`hick_trace::stats::Stats`] handle from the owning
  /// [`crate::endpoint::Endpoint`]. No allocation — the Arc is cloned from the
  /// endpoint's existing single Arc. Called immediately after construction by
  /// `Endpoint::try_register_service` so that all per-service counters accumulate
  /// into the endpoint-level stats. Before this is called, stats bumps are no-ops
  /// (the field is `None`).
  #[cfg(feature = "stats")]
  pub(crate) fn set_stats(&mut self, stats: std::sync::Arc<hick_trace::stats::Stats>) {
    self.stats = Some(stats);
  }

  /// Borrow the stats handle if one has been attached.
  #[cfg(feature = "stats")]
  #[inline]
  fn stat(&self) -> Option<&hick_trace::stats::Stats> {
    self.stats.as_deref()
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

  /// Whether this service has CONFIRMED-EMITTED at least one INSTANCE record
  /// (PTR/SRV/TXT) on the wire — i.e. it has truly advertised its name, not merely
  /// probed for it. Unlike [`Self::advertises_host`] this is set even for an
  /// address-less service.
  ///
  /// This is the ANY-delivered EXPOSURE latch: it answers "may some peer hold
  /// these records?", which is what a §10.1 goodbye must retract. It is
  /// deliberately NOT the reclaim-cancel gate — that is
  /// [`Self::has_fully_announced`], which requires EVERY obligated link to have
  /// heard a complete announcement. See that method for why substituting this one
  /// there is unsound, and why the fact is handed out wrapped so it cannot be.
  #[inline(always)]
  pub fn advertises_instance(&self) -> bool {
    self.goodbye.any_instance()
  }

  /// Whether a COMPLETE §8.3 announcement of the CURRENT instance name has
  /// reached EVERY obligated link — i.e. at least one announcement resolved
  /// [`TransmitDelivery::all_delivered`].
  ///
  /// This is the reclaim-cancel gate the driver ferries into
  /// [`Endpoint::note_service_announced`](crate::Endpoint::note_service_announced):
  /// only once every link the driver still obligates has heard the reclaiming
  /// name may that name's renamed-away predecessor stop sending its TTL=0
  /// goodbye. For every such link §10.2's cache-flush announcement supersedes the
  /// stale unique records, so the goodbye has nothing left to do.
  ///
  /// It is deliberately NOT [`Self::advertises_instance`], which latches on ANY
  /// delivery and would make the gate unsound in two ways: a v4-only (partial)
  /// announcement would cancel a goodbye the v6 zone still needs, and — because
  /// an RFC 6762 §6.7 legacy UNICAST reply has a single obligated link and so
  /// reports `AllDelivered` by construction — a mere unicast reply would satisfy
  /// any "advertises_instance() && all_delivered()" formula without ever having
  /// multicast the name. Only the Announcement confirm arm sets this, so no
  /// response of any kind can.
  ///
  /// The result is wrapped in [`FullyAnnounced`] precisely so that the wrong fact
  /// cannot be substituted at the call site; use [`FullyAnnounced::get`] to read
  /// it. The token is stamped with THIS service's handle, so it also cannot be
  /// applied to a different service.
  ///
  /// Reset by a §9 conflict rename: the new name has announced nothing.
  #[inline(always)]
  pub const fn has_fully_announced(&self) -> FullyAnnounced {
    FullyAnnounced::new(self.handle, self.fully_announced)
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

  /// Report the delivery outcome of the datagram most recently produced by
  /// [`Self::poll_transmit`] (the confirm-on-send chokepoint).
  ///
  /// # Contract
  ///
  /// Must be called before ANY other state-mutating entry point for this service
  /// — see [`Self::poll_transmit`], which documents the ordering and why a
  /// datagram the transport refuses is dropped and confirmed rather than parked.
  ///
  /// This is the SOLE place service lifecycle state advances and the SOLE place
  /// goodbye ownership latches. `poll_transmit` only encodes bytes and stamps a
  /// commit token (`awaiting_confirm`); the driver then reports how the fan-out
  /// went. Two invariants key every arm below:
  ///
  /// * **Goodbye ownership latches iff [`TransmitDelivery::any_delivered`]** —
  ///   peers reachable over any link that accepted the datagram may hold the
  ///   records it carried (RFC 6762 §10.1), whether or not every link did.
  /// * **Phase takes full credit iff [`TransmitDelivery::all_delivered`]** — a
  ///   link that never saw the probe has not been asked (§8.1) and one that
  ///   never saw the announcement has not been told (§8.3). The phase can also
  ///   advance WITHOUT that credit, via the two bounded escapes described below.
  ///
  /// Behaviour per commit token:
  ///
  /// * **Probe, all delivered** — advance the §8.1 probe sequence (next probe,
  ///   or enter `Announcing(0)` after the third). A name is therefore claimed
  ///   only once its probe reached every obligated link.
  /// * **Probe, otherwise** — re-arm the SAME probe without advancing. A probe
  ///   is a question: it advertises nothing, so a partial probe latches nothing
  ///   either. Probes are exempt from the doubling ladders — §8.1's own 250 ms
  ///   cadence governs them, and §6's one-second rule explicitly carves probing
  ///   out.
  /// * **Announcement, all delivered** — latch goodbye ownership for the records
  ///   it emitted, mark [`Self::has_fully_announced`], and advance the §8.3
  ///   phase, reaching `Established` after the second.
  /// * **Announcement, partially delivered** — latch ownership (the served
  ///   family heard it) but do NOT advance; re-arm on the composed rule in
  ///   `arm_announcement`, since every such retry puts another real datagram on
  ///   that family's wire and some family is now falling behind on its TTL.
  /// * **Announcement, none delivered** — nothing reached any wire: latch
  ///   nothing, advance nothing, retry flat at the §8.3 one-second interval.
  /// * **Response / meta-response** — exposure is an any-delivered fact and no
  ///   phase exists, so partial and full delivery behave identically.
  /// * **Stale** — the datagram belongs to a generation a regression to
  ///   [`ServiceState::Init`] replaced. It still counts its wire fact, and its
  ///   records still latch somewhere they can be withdrawn from, but it advances
  ///   no phase, moves no deadline, and touches no counter of the generation that
  ///   replaced it.
  /// * **Nothing pending** — no-op.
  ///
  /// # Drain contract for the rename goodbye handoff
  ///
  /// A driver MUST call [`Self::take_rename_goodbye_handoff`] after EVERY call to
  /// this method, not only after observing
  /// [`ServiceUpdate::Renamed`](crate::event::ServiceUpdate). A confirm that
  /// resolves a datagram parked across a §9 conflict rename can INSTALL a handoff
  /// — the old name's records really are in peer caches and something must
  /// withdraw them — and by then the `Renamed` update is long since drained, so
  /// nothing else will ever look. The call is free and returns `None` for a
  /// driver that confirms each datagram before polling the next one, which is
  /// every driver that cannot park.
  ///
  /// # Advancing without a fully-delivered round
  ///
  /// A partially-delivered datagram is re-armed LOSSLESSLY — the same probe
  /// index, the same announcement content — so the phase has two further ways to
  /// move, and neither is a delivery:
  ///
  /// * **Covered.** Every obligated family has carried this datagram at some
  ///   point since the phase last advanced. Under a capacity-one transport the
  ///   families take turns, so no single round ever reaches both while both are
  ///   in fact being served; without this the producer would sit in `Probing(0)`
  ///   forever, because a family's patience resets on its own delivery and
  ///   neither could ever spend it.
  /// * **Excused.** Every family still owed the datagram has spent
  ///   `MAX_PARTIAL_ROUNDS` re-arms on it. The phase advances from exactly where
  ///   it stood, without that family, and the family stops driving the per-family
  ///   refresh schedule until it delivers again.
  ///
  /// Neither takes any of the credit a delivery earns, and that is the whole of
  /// the distinction:
  ///
  /// * [`Self::has_fully_announced`] stays shut — no ONE announcement was
  ///   confirmed by every obligated family, so a renamed-away name's §10.1
  ///   goodbye must keep going;
  /// * the §8.3 doubling ladder is preserved, and the re-arm is never EARLIER
  ///   than the rung the served family already earned;
  /// * `probes_tx` / `announcements_tx` do not count it — those counters mean
  ///   "confirmed delivered by every obligated link", so such a round is visible
  ///   as an advance the counters never recorded.
  ///
  /// Goodbye ownership is unaffected either way: both are still `any_delivered`,
  /// so the records they put on a wire stay owned and retractable.
  ///
  /// An all-miss round reaches none of this: it leaves every family's patience
  /// untouched, which is what keeps a phase from ever advancing out of silence.
  pub fn note_transmit_outcome(&mut self, now: I, delivery: TransmitDelivery) {
    let kind = match self.awaiting_confirm.take() {
      Some(k) => k,
      None => return,
    };
    match kind {
      AwaitingConfirm::Probe => {
        if let ServiceState::Probing(n) = self.state {
          let advance = classify_advance(&mut self.partial_rounds, delivery);
          if matches!(advance, PhaseAdvance::Partial | PhaseAdvance::Failed) {
            // §8.1: the probe did not reach every obligated link — do NOT
            // advance the sequence. Re-arm the SAME probe from post-send time so
            // it retries, rather than the service progressing toward Announcing
            // while a link that has never been asked might already hold the name.
            self.lifecycle_deadline = probe_deadline(now, n, &mut self.rng);
          } else {
            // Only a genuine delivery counts: `probes_tx` means "reached every
            // obligated link", so an excused advance must not inflate it.
            #[cfg(feature = "stats")]
            if matches!(advance, PhaseAdvance::Delivered)
              && let Some(s) = self.stat()
            {
              s.probes_tx(1);
            }
            if n >= 2 {
              // Third probe confirmed (§8.1: exactly three) → begin announcing.
              self.state = ServiceState::Announcing(0);
              self.probe_count = 3;
              self.lifecycle_deadline = announce_deadline(now, 0);
              match advance {
                // A fresh §8.3 announcement sequence starts from the bottom rung.
                PhaseAdvance::Delivered => self.partial_announce_streak = 0,
                // An excused advance earns no reset: the served link is still on
                // whatever rung it climbed to, and §8.3 forbids the next
                // unsolicited response from coming sooner than the last one did.
                // The rung itself does not move — a probe is a question, not an
                // unsolicited response, so it is not a step on that ladder.
                _ => self.arm_on_partial_ladder(now),
              }
            } else {
              // Probe confirmed → schedule the next one PROBE_INTERVAL later.
              // Probes stay off the ladders whether or not this one was excused:
              // §8.1's own 250 ms cadence governs them and §6's one-second rule
              // explicitly carves probing out.
              let new_n = n.saturating_add(1);
              self.state = ServiceState::Probing(new_n);
              self.probe_count = new_n;
              self.lifecycle_deadline = probe_deadline(now, new_n, &mut self.rng);
            }
          }
        }
      }
      AwaitingConfirm::Announcement(emitted) => {
        let advance = self.classify_announcement(now, delivery);
        if matches!(advance, PhaseAdvance::Failed) {
          // The announcement never reached ANY link — re-arm without advancing
          // and latch nothing. Retry at the §8.3 inter-announce interval,
          // anchored to post-send time. This MUST also cover the periodic
          // `Established` re-announce — otherwise a single transient send failure
          // leaves the next attempt a full re-announce interval (~80% of TTL)
          // away, during which peers expire the records and the service silently
          // disappears. A short 1 s retry keeps the records alive.
          //
          // The §8.3 doubling ladder deliberately does NOT apply here: nothing
          // hit any wire, so §8.3 counts no unsolicited response to space out,
          // and the streak is neither used nor advanced. The delay a failed round
          // adds is pure extra spacing on top of whatever rung the ladder is on.
          if matches!(
            self.state,
            ServiceState::Announcing(_) | ServiceState::Established
          ) {
            self.lifecycle_deadline = announce_deadline(now, 1);
          }
          return;
        }
        // At least one obligated link accepted it → peers reachable over that
        // link may now hold these records, so latch goodbye ownership for
        // exactly what the encoder reported it emitted (a full announcement
        // carries all of PTR/SRV/TXT plus every host address). This is the
        // ANY-delivered half of the invariant pair and happens BEFORE the
        // all-delivered phase check below: partial delivery owns what it exposed
        // even though it advances nothing.
        self.goodbye.record_emitted(&emitted);
        if matches!(advance, PhaseAdvance::Partial) {
          // §8.3 phase does NOT advance — some obligated family has not been told.
          // The re-arm is lossless: `announce_count` and the state are untouched,
          // so the first all-delivered confirm resumes from here.
          self.arm_announcement(now, advance);
          self.partial_announce_streak = self.partial_announce_streak.saturating_add(1);
          return;
        }
        // The phase advances. Only a genuine delivery earns the credit that goes
        // with it: `announcements_tx` counts datagrams confirmed by every
        // obligated family, and the reclaim-cancel gate asserts that ONE complete
        // announcement reached all of them — neither of which a covered or an
        // excused round produced.
        if matches!(advance, PhaseAdvance::Delivered) {
          #[cfg(feature = "stats")]
          if let Some(s) = self.stat() {
            s.announcements_tx(1);
          }
          // The ladder resets — the next partial streak starts from the bottom
          // rung.
          self.partial_announce_streak = 0;
          // THE reclaim-cancel gate (see `has_fully_announced`): a complete
          // announcement of the current name has now reached every obligated link.
          self.fully_announced = true;
        }
        if let ServiceState::Announcing(n) = self.state {
          if n >= 1 {
            // Second announcement confirmed → the §8.3 startup sequence is
            // complete: become Established and notify the caller exactly once.
            self.state = ServiceState::Established;
            self.announce_count = 2;
            let _ = self.pending_updates.insert(ServiceUpdate::Established);
            self.lifecycle_deadline = re_announce_deadline(now, self.records.ttl_secs());
            debug!(
              target: "mdns_proto::service",
              handle = self.handle.raw(),
              "service: Announcing → Established"
            );
            #[cfg(feature = "stats")]
            if let Some(s) = self.stat() {
              s.services_established(1);
            }
          } else {
            // First announcement confirmed → schedule the second one (§8.3: ≥1 s
            // later).
            let new_n = n.saturating_add(1);
            self.state = ServiceState::Announcing(new_n);
            self.announce_count = new_n;
            self.lifecycle_deadline = announce_deadline(now, new_n);
            debug!(
              target: "mdns_proto::service",
              handle = self.handle.raw(),
              announce_n = new_n,
              "service: Announcing — first announcement confirmed, scheduling second"
            );
          }
        }
        self.arm_announcement(now, advance);
        if advance.advances_without_delivery() {
          // §8.3: the round still put a real unsolicited response on the served
          // family's wire, so the ladder is CARRIED ACROSS the advance point
          // rather than reset by it.
          self.partial_announce_streak = self.partial_announce_streak.saturating_add(1);
        }
      }
      AwaitingConfirm::Response(emitted, _kas_suppressed_count) => {
        #[cfg(feature = "stats")]
        let kas_suppressed_count = _kas_suppressed_count;
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
        //
        // answers_suppressed_kas (partial suppression) is also deferred here:
        // a socket failure must not inflate the suppression counter — the
        // records were encoded but never left the host, so from the network's
        // perspective they were NOT suppressed.
        //
        // Exposure is an ANY-delivered fact and a response carries no lifecycle
        // phase, so a partial delivery is handled exactly like a full one: one
        // link's peers heard the records, and that is the whole question here.
        if delivery.any_delivered() {
          #[cfg(feature = "stats")]
          if let Some(s) = self.stat() {
            s.responses_tx(1);
            if kas_suppressed_count > 0 {
              s.answers_suppressed_kas(kas_suppressed_count);
            }
          }
          self.goodbye.record_emitted(&emitted);
        }
      }
      AwaitingConfirm::MetaResponse => {
        // A §9 meta-response (multicast or legacy) put a shared meta-PTR on the
        // wire.  No instance-owned records were emitted, so goodbye ownership is
        // NOT touched.  Any delivery bumps responses_tx so the *_tx counters
        // reflect every datagram that left the host; there is no phase here, so
        // partial and full delivery are the same event.
        if delivery.any_delivered() {
          #[cfg(feature = "stats")]
          if let Some(s) = self.stat() {
            s.responses_tx(1);
          }
        }
      }
      AwaitingConfirm::Stale {
        fact: _fact,
        records,
      } => {
        // A regression to `Init` voided this datagram's place in the lifecycle,
        // not the fact that it left the host. So the WIRE facts still count —
        // `responses_tx` reflects every datagram that left the host, and
        // `answers_suppressed_kas` is deferred to delivery precisely so it counts
        // encode-facts that reached the wire — while every LIFECYCLE fact is left
        // alone: no phase moves, no deadline is re-armed, and neither
        // `partial_rounds` nor `partial_announce_streak` is read or written,
        // because both now describe the generation that replaced this one.
        // `classify_advance` is deliberately not called here for that reason.
        #[cfg(feature = "stats")]
        if let Some(s) = self.stat() {
          match _fact {
            // `probes_tx` / `announcements_tx` mean "confirmed delivered by every
            // obligated link", so they hold to that bar here too.
            StaleWireFact::Probe if delivery.all_delivered() => s.probes_tx(1),
            StaleWireFact::Announcement if delivery.all_delivered() => s.announcements_tx(1),
            StaleWireFact::Response(kas) if delivery.any_delivered() => {
              s.responses_tx(1);
              if kas > 0 {
                s.answers_suppressed_kas(kas);
              }
            }
            _ => {}
          }
        }
        if !delivery.any_delivered() {
          return;
        }
        match records {
          // A probe is a QUESTION (§8.1): it advertised nothing, so there is
          // nothing to withdraw — and the sequence it was a step of no longer
          // exists, so it must not advance the fresh one either. That advance is
          // the §8.1 violation this arm removes: `Init → Probing(0)` costs no
          // datagram, so a parked old-generation probe confirming into it would
          // claim the name after TWO probes on the wire instead of three.
          StaleRecords::None => {}
          // The name did not change (§9 same-name revert-to-probe): peers hold
          // these records under the very name this service still owns, so
          // ownership latches exactly as it would have without the regression.
          // Discarding it would trade a false withdrawal for a MISSING one at
          // unregister, which is the worse of the two.
          StaleRecords::SameName(emitted) => self.goodbye.record_emitted(&emitted),
          StaleRecords::OldName { records, emitted } => {
            // The host name is invariant across an instance rename, so the
            // addresses this datagram carried are cached under a name the service
            // still holds: they latch into the live goodbye as usual.
            self.goodbye.record_host_emitted(&emitted);
            // The instance records are not. `self.records` names the NEW
            // instance, so `withdrawal_snapshot` would encode them under a name
            // that never carried them — they belong to the OLD name's detached
            // §10.1 goodbye instead.
            let instance = respond::EmittedRecords::new(
              emitted.ptr(),
              emitted.srv(),
              emitted.txt(),
              std::vec::Vec::new(),
              std::vec::Vec::new(),
              emitted.subtypes(),
            );
            if instance.is_empty() {
              // §7.1 trimmed every instance record: the old name put nothing in
              // any peer cache, so it has nothing to withdraw.
              return;
            }
            match &mut self.rename_goodbye_handoff {
              Some(h) => h.owned.merge_instance(&instance),
              // The driver takes the handoff the instant it observes `Renamed`,
              // and a parked confirm lands after that by construction, so
              // installing a fresh one is the ordinary case rather than the
              // exception. Draining it is the drain contract documented above.
              None => {
                self.rename_goodbye_handoff = Some(RenameGoodbyeHandoff {
                  records,
                  owned: instance,
                });
              }
            }
          }
        }
      }
    }
  }

  /// Void the LIFECYCLE meaning of a live commit token at a regression to
  /// [`ServiceState::Init`], capturing WHOSE records the parked datagram put on
  /// the wire.
  ///
  /// The capture has to happen HERE, at the regression, because the fact does not
  /// survive to confirm time: by then `records` names the new instance,
  /// `goodbye` has been reset, and `rename_goodbye_handoff` has very likely
  /// already been drained — drivers take it the instant they observe
  /// `Renamed`, while a parked confirm lands later by construction. A token that
  /// only knew it was stale could tell that it must not advance, but not whose
  /// records it exposed, which is the one fact that decides between withdrawing
  /// them and stranding them in every peer cache on the link.
  ///
  /// The token is REWRITTEN, never dropped. The single-token slot is what matches
  /// one confirm to one datagram by ordering: clearing it would let
  /// `poll_transmit` stamp a fresh token that the parked datagram's confirm then
  /// resolves against the wrong send.
  ///
  /// `renamed_from` is the OLD instance name's records when the regression
  /// RENAMES (cloned before `ServiceRecords::set_instance`), and `None` when the
  /// name is unchanged.
  ///
  /// # Two regressions in a row
  ///
  /// Safe by construction: `poll_transmit` returns `Ok(None)` while a token is
  /// live, so between two regressions no datagram is produced and no confirm can
  /// arrive. The second regression therefore finds exactly the token the first
  /// rewrote, over an unchanged `goodbye` — in particular a rename that follows a
  /// rename finds `goodbye.any_instance()` still `false` from the first, installs
  /// no competing handoff, and leaves the older name's capture intact. Only a
  /// SAME-name capture needs updating when a rename follows it, since the name it
  /// referred to has just been left behind.
  fn stale_live_commit_token(&mut self, renamed_from: Option<ServiceRecords>) {
    let (fact, emitted) = match self.awaiting_confirm.take() {
      None => return,
      Some(AwaitingConfirm::Probe) => (StaleWireFact::Probe, None),
      Some(AwaitingConfirm::Announcement(e)) => (StaleWireFact::Announcement, Some(e)),
      Some(AwaitingConfirm::Response(e, kas)) => (StaleWireFact::Response(kas), Some(e)),
      // The §9 meta-PTR names the SERVICE TYPE, which no instance rename or
      // same-name revert touches, and it latches no ownership at all. Nothing
      // about it can go stale, so it is put back exactly as it was.
      Some(token @ AwaitingConfirm::MetaResponse) => {
        self.awaiting_confirm = Some(token);
        return;
      }
      // Already voided by an earlier regression. Its wire fact is unchanged; only
      // a rename moves its records, and only if they were attributed to the name
      // being renamed away from.
      Some(AwaitingConfirm::Stale { fact, records }) => {
        let records = match (records, renamed_from) {
          (StaleRecords::SameName(emitted), Some(records)) => {
            StaleRecords::OldName { records, emitted }
          }
          (records, _) => records,
        };
        self.awaiting_confirm = Some(AwaitingConfirm::Stale { fact, records });
        return;
      }
    };
    let records = match (emitted, renamed_from) {
      (None, _) => StaleRecords::None,
      (Some(emitted), None) => StaleRecords::SameName(emitted),
      (Some(emitted), Some(records)) => StaleRecords::OldName { records, emitted },
    };
    self.awaiting_confirm = Some(AwaitingConfirm::Stale { fact, records });
  }

  /// Re-arm `lifecycle_deadline` on the rung the RFC 6762 §8.3 partial ladder has
  /// already earned, DISCARDING whatever schedule the phase change pre-armed.
  ///
  /// Only an EXCUSED advance OUT OF PROBING needs this. The phase moves without
  /// the family that kept missing and re-arms on the fresh phase's own schedule —
  /// `announce_deadline`'s flat 1 s — while the served family has been climbing the
  /// doubling ladder all along. §8.3 forbids the next unsolicited response from
  /// coming sooner than the last one did, so the flat interval is the wrong one and
  /// the earned rung replaces it.
  ///
  /// A streak of zero means the ladder is not engaged (the patience bound was
  /// spent on probes, which are questions and take no rung), so the advance's own
  /// deadline stands unchanged.
  fn arm_on_partial_ladder(&mut self, now: I) {
    if self.partial_announce_streak == 0 {
      return;
    }
    self.lifecycle_deadline =
      partial_announce_deadline(now, self.partial_announce_streak, self.records.ttl_secs());
  }

  /// Apply the core's per-family patience to one ANNOUNCEMENT confirm and record
  /// what each family did with it.
  ///
  /// The anchors are maintained here, beside the counter they are read with, so
  /// the two can never describe different rounds. Their rules are the presence
  /// trichotomy, one clause each:
  ///
  /// * **Delivered** — this family's peers have a fresh copy of the records, so
  ///   its TTL race restarts now.
  /// * **Missed** — the anchor stands, and the growing gap is precisely what pulls
  ///   the next announcement in. An UNANCHORED family is anchored here instead:
  ///   that is the runtime `Unobligated` → obligated transition (a socket that
  ///   just appeared), and it is owed its first refresh within one interval, not
  ///   immediately and not never.
  /// * **Unobligated** — no socket, so nothing is owed and nothing may be stale.
  ///   Clearing it is also what makes the transition above detectable.
  fn classify_announcement(&mut self, now: I, delivery: TransmitDelivery) -> PhaseAdvance {
    let advance = classify_advance(&mut self.partial_rounds, delivery);
    for (anchor, family) in self
      .last_delivered
      .iter_mut()
      .zip(delivery.families().iter())
    {
      match family {
        FamilyDelivery::Delivered => *anchor = Some(now),
        FamilyDelivery::Missed => {
          if anchor.is_none() {
            *anchor = Some(now);
          }
        }
        FamilyDelivery::Unobligated => *anchor = None,
      }
    }
    advance
  }

  /// Install the deadline for the next §8.3 unsolicited response after a confirm
  /// that reached at least one family.
  ///
  /// ONE composed rule covers every such confirm: **the phase's own schedule,
  /// pulled in to whenever the stalest obligated family in good standing is next
  /// owed a refresh, and never sooner than §8.3's one-second minimum.**
  ///
  /// The phase's own schedule is the §8.3 spacing — the doubling ladder while
  /// announcing, the periodic refresh once `Established` — and the per-family
  /// term is the TTL bound. Composing them subsumes two arms this used to need:
  ///
  /// * the honest-partial re-arm, which climbed the ladder to keep the served
  ///   family's spacing legal but measured staleness per ROUND, so alternating
  ///   families each fell a full interval behind;
  /// * the excused re-arm, which REPLACED `Established`'s pre-armed periodic
  ///   deadline with the earned rung so the missing family was not stranded a
  ///   whole refresh interval away. A family in good standing now pulls the
  ///   deadline in by itself, and one that has spent the core's patience is
  ///   deliberately no longer chased — chasing it is what floods the healthy
  ///   family at the one-second floor.
  ///
  /// `Established` is where the ladder retires: the announcement burst is over,
  /// the periodic refresh is the rate limit, and the ladder's cap was that same
  /// rate all along.
  fn arm_announcement(&mut self, now: I, advance: PhaseAdvance) {
    let ttl_secs = self.records.ttl_secs();
    let base = match self.state {
      ServiceState::Established => re_announce_deadline(now, ttl_secs),
      ServiceState::Announcing(_) => match advance {
        PhaseAdvance::Partial => {
          partial_announce_deadline(now, self.partial_announce_streak, ttl_secs)
        }
        PhaseAdvance::Covered | PhaseAdvance::Excused if self.partial_announce_streak > 0 => {
          partial_announce_deadline(now, self.partial_announce_streak, ttl_secs)
        }
        // A delivery, or an excusal off the bottom rung, keeps the schedule the
        // phase change itself just armed.
        _ => self.lifecycle_deadline,
      },
      _ => return,
    };
    let due = stalest_refresh_due(&self.last_delivered, &self.partial_rounds, ttl_secs);
    self.lifecycle_deadline = compose_announce_deadline(now, base, due);
  }

  /// The [`TransmitObligation`] of the datagram whose commit token is currently
  /// stamped — the tag [`Self::poll_transmit`] hands the driver.
  ///
  /// A pure function of the token, so the tag always describes what
  /// [`Self::note_transmit_outcome`] will actually do with the confirm. A
  /// datagram that stamped NO token obligates nothing at all (the confirm is a
  /// no-op), so it reports `OneShot`.
  #[inline]
  fn stamped_obligation(&self) -> TransmitObligation {
    match &self.awaiting_confirm {
      Some(token) => token.obligation(),
      None => TransmitObligation::OneShot,
    }
  }

  /// The per-family minimum wire gap of the datagram whose commit token is
  /// currently stamped — the value [`Self::poll_transmit`] hands the driver on
  /// [`Transmit::min_family_gap`].
  ///
  /// A pure function of the token, for the same reason [`Self::stamped_obligation`]
  /// is. A datagram that stamped NO token is fire-and-forget and ungated.
  #[inline]
  fn stamped_min_family_gap(&self) -> Duration {
    match &self.awaiting_confirm {
      Some(token) => token.min_family_gap(),
      None => Duration::ZERO,
    }
  }

  /// Capture everything the endpoint needs to re-encode a TTL=0 goodbye for
  /// this service without holding the [`Service`] alive.
  ///
  /// **Always captures the CURRENT confirmed-emitted state:** the current
  /// `ServiceRecords`, which instance record kinds (PTR/SRV/TXT/subtypes) were
  /// actually put on the wire, and which host A/AAAA addresses were
  /// confirmed-emitted. The endpoint further filters host addresses against
  /// same-host siblings before encoding the actual goodbye datagram.
  ///
  /// The OLD instance name of an in-flight §9 conflict rename is NOT carried
  /// here. A rename now hands its old-name goodbye off via
  /// [`Self::take_rename_goodbye_handoff`] the instant it happens, and the driver
  /// enqueues it as an INDEPENDENT detached withdrawal item
  /// ([`crate::Endpoint::enqueue_rename_withdrawal`]). A teardown during that
  /// window is therefore simply two independent items — the detached old-name
  /// item already enqueued, plus the route-attached current-name item this
  /// snapshot produces — with no `snapshot.rename` inheritance.
  ///
  /// # Contract
  ///
  /// Must NOT be called while a datagram from [`Self::poll_transmit`] is still
  /// awaiting its [`Self::note_transmit_outcome`]. This snapshot reports only
  /// what a confirm has already latched, so an outstanding datagram's records are
  /// missing from it: peers would cache records the goodbye never withdraws, and
  /// their TTLs would only start at that late transmission — an exposure the
  /// teardown does not bound. See [`Self::poll_transmit`] for the full contract.
  ///
  /// Debug builds assert it HERE, at the teardown itself, because this is the one
  /// place the violation is otherwise silent: the goodbye is simply built short,
  /// and no later step can tell that it was.
  pub fn withdrawal_snapshot(&mut self) -> WithdrawalSnapshot {
    self.assert_no_live_commit_token("Service::withdrawal_snapshot");
    // Snapshot the CURRENT goodbye-ownership latch (the live name's records).
    // After a rename the current name is the freshly re-announced one, and its
    // confirmed instance + host records still need withdrawing; the OLD name is
    // handled separately as its own detached item.
    let owned = respond::EmittedRecords::new(
      self.goodbye.ptr,
      self.goodbye.srv,
      self.goodbye.txt,
      std::vec::Vec::new(), // addresses are passed separately below
      std::vec::Vec::new(),
      self.goodbye.subtypes,
    );
    WithdrawalSnapshot {
      records: self.records.clone(),
      owned,
      host_a: self.goodbye.a.clone(),
      host_aaaa: self.goodbye.aaaa.clone(),
    }
  }

  /// Take the one-shot §9 rename goodbye handoff, if a conflict rename installed
  /// one (the OLD instance name advertised ≥1 instance record and so still needs
  /// a TTL=0 withdrawal so peers evict it).
  ///
  /// Returns the OLD name's `ServiceRecords` plus the per-record ownership
  /// (`EmittedRecords` with the instance bits the old name actually put on the
  /// wire; host A/AAAA empty — a rename never withdraws host addresses). The
  /// driver MUST call this immediately after observing
  /// [`ServiceUpdate::Renamed`](crate::event::ServiceUpdate) from [`Self::poll`]
  /// and hand the result to [`crate::Endpoint::enqueue_rename_withdrawal`], which
  /// models the old-name goodbye as an independent detached withdrawal item. The
  /// field is consumed (`.take()`) so the handoff happens exactly once. Returns
  /// `None` when the renamed name had never advertised an instance record.
  pub fn take_rename_goodbye_handoff(&mut self) -> Option<RenameGoodbyeHandoff> {
    self.rename_goodbye_handoff.take()
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
    // Earliest of: lifecycle, response, and the meta-response deadline. The §9
    // rename goodbye is no longer drained by the Service — it is handed off to
    // the endpoint as a detached withdrawal item — so it contributes no wakeup
    // here.
    let mut best: Option<I> = None;
    for d in [
      self.lifecycle_deadline,
      self.response_deadline,
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

  /// Fail loudly, in debug builds, when a state-mutating entry point runs while
  /// a datagram produced by [`Self::poll_transmit`] is still awaiting its
  /// [`Self::note_transmit_outcome`].
  ///
  /// The confirm-before-anything contract documented on [`Self::poll_transmit`]
  /// is not something the core can type-check, so this is where a driver that
  /// breaks it discovers the fact — in its own test suite, at the offending call,
  /// instead of through corrupted lifecycle state in release. It compiles out of
  /// release builds, where the structural backstops (the single-slot refusal in
  /// `poll_transmit`, [`Self::push_lifecycle_pending`], and the `Stale` token
  /// rewrite) absorb the violation.
  #[inline]
  fn assert_no_live_commit_token(&self, entry_point: &str) {
    #[cfg(test)]
    if self.contract_assertions_off {
      return;
    }
    debug_assert!(
      self.awaiting_confirm.is_none(),
      "{entry_point} was called while a datagram from Service::poll_transmit is \
       still awaiting Service::note_transmit_outcome",
    );
  }

  /// Queue a LIFECYCLE transmit (a §8.1 probe or a §8.3 announcement), unless a
  /// datagram is still awaiting its delivery result.
  ///
  /// A live commit token means the previous datagram's lifecycle effect has not
  /// been applied yet, and [`Self::note_transmit_outcome`] re-arms
  /// `lifecycle_deadline` from post-confirm time for exactly the phase the
  /// confirm lands the service in. Queuing another lifecycle transmit here would
  /// outlive that confirm and then ignore the deadline it installed: the queue
  /// is drained by position, not by deadline, so the entry fires as soon as the
  /// token clears. A queued `Probe` also carries no sequence index, so several
  /// accumulated entries would advance the §8.1 sequence at ~0 ms spacing rather
  /// than at §8.1's 250 ms cadence.
  ///
  /// The confirm's own re-arm governs instead. This is unreachable for a driver
  /// that honours the confirm-before-anything contract documented on
  /// [`Self::poll_transmit`] — nothing may call `handle_timeout` while a token is
  /// live — and is the structural backstop for one that does not.
  fn push_lifecycle_pending(&mut self, kind: PendingTransmitKind) {
    if self.awaiting_confirm.is_some() {
      return;
    }
    self.push_pending(kind);
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
      debug!(
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
    // The NEW name has announced nothing, so it cannot yet supersede the old
    // name's in-flight goodbye — the reclaim-cancel gate must re-earn its `true`.
    self.fully_announced = false;
    // A fresh name restarts the §8.3 announcement sequence at the bottom rung.
    self.partial_announce_streak = 0;
    // …and restarts the §8.1 sequence, so the patience already spent waiting for
    // a lagging family under the OLD name may not excuse a probe of the new one.
    self.partial_rounds = [FamilyPatience::default(); 2];
    // The NEW name has been announced to nobody, so no family is owed a refresh
    // of it. Each is re-anchored by its first announcement round under this name.
    self.last_delivered = [None, None];
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
  ///
  /// # Contract
  ///
  /// Must NOT be called while a datagram from [`Self::poll_transmit`] is still
  /// awaiting its [`Self::note_transmit_outcome`] — an inbound RFC 6762 §9
  /// conflict processed in that window regresses the exact state the pending
  /// confirm is about to apply. See [`Self::poll_transmit`] for the full
  /// contract; debug builds assert it.
  pub fn handle_event(&mut self, event: ServiceEvent<'_>, now: I) {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("service", handle = self.handle.raw()).entered();
    self.assert_no_live_commit_token("Service::handle_event");
    // always refresh last_now so that subsequent calls (e.g.
    // Question→response_deadline, KnownAnswer→expiry) use a current reference
    // even when handle_timeout has not recently fired.
    self.last_now = Some(now);
    trace!(
      target: "mdns_proto::service",
      handle = self.handle.raw(),
      state = ?self.state,
      event = ?core::mem::discriminant(&event),
      "service: handle_event"
    );
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
          Ok(c) => rdata_from_vec(c.to_vec()),
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
        warn!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          state = ?self.state,
          rtype = ?pc.record().rtype(),
          "service: ProbeConflict (§9 post-establishment) — reverting to probe"
        );
        #[cfg(feature = "stats")]
        if let Some(s) = self.stat() {
          s.conflicts(1);
        }
        self.last_conflict_reprobe = Some(now);
        self.state = ServiceState::Init;
        self.probe_count = 0;
        self.announce_count = 0;
        self.pending_transmits = [None, None];
        self.response_deadline = None;
        // A parked datagram belongs to the generation this revert just replaced,
        // so its confirm must not advance the fresh §8.1 sequence. The NAME is
        // unchanged, so whatever it emitted still latches into `goodbye` —
        // see `stale_live_commit_token`.
        self.stale_live_commit_token(None);
        // A fresh §8.1 sequence: the patience already spent waiting for a lagging
        // link must not excuse a probe of the name we are re-verifying. This is
        // the SAME name, so unlike a rename the per-advertised-name state stays
        // put — `fully_announced` in particular. Ferrying it into the re-probe is
        // sound: the only thing it can do is cancel a renamed-away predecessor's
        // §10.1 goodbye, and any goodbye this name could cancel was already
        // cancelled when it first fully announced. A NEW same-name detached
        // goodbye cannot appear meanwhile — the endpoint's name guard rejects a
        // same-name registration while this service holds the route.
        self.partial_rounds = [FamilyPatience::default(); 2];
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
          trace!(
            target: "mdns_proto::service",
            handle = self.handle.raw(),
            rtype = ?ka.record().rtype(),
            "service: KnownAnswer hint stored (§7.1 KAS)"
          );
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
        warn!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          state = ?self.state,
          rtype = ?hc.record().rtype(),
          "service: HostConflict — peer claimed our host name with different rdata"
        );
        #[cfg(feature = "stats")]
        if let Some(s) = self.stat() {
          s.conflicts(1);
        }
        let _ = self.pending_updates.insert(ServiceUpdate::HostConflict);
      }
      _ => {}
    }
  }

  /// Drive timer-based transitions. Returns Ok unless arithmetic overflowed.
  ///
  /// # Contract
  ///
  /// Must NOT be called while a datagram from [`Self::poll_transmit`] is still
  /// awaiting its [`Self::note_transmit_outcome`]: the confirm installs the
  /// deadline for the phase it lands the service in, so a lifecycle deadline
  /// fired before it would queue a transmit that then ignores that deadline. See
  /// [`Self::poll_transmit`] for the full contract; debug builds assert it, and
  /// the lifecycle queue refuses to accept an entry under a live token in
  /// release.
  #[allow(clippy::arithmetic_side_effects)]
  pub fn handle_timeout(&mut self, now: I) -> Result<(), HandleTimeoutError> {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("service", handle = self.handle.raw()).entered();
    self.assert_no_live_commit_token("Service::handle_timeout");
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
        warn!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          state = ?self.state,
          rename_attempt = self.rename_attempt.saturating_add(1),
          "service: probe tiebreak lost (§8.2) — renaming"
        );
        #[cfg(feature = "stats")]
        if let Some(s) = self.stat() {
          s.conflicts(1);
          s.renames(1);
        }
        if self.goodbye.any_instance() {
          // capture WHICH instance records the old name actually put on
          // the wire (§7.1 KAS may have emitted only a subset), so the rename
          // goodbye withdraws exactly those — not all of PTR/SRV/TXT, which
          // could flush a peer's matching same-name record we never sent. Host
          // A/AAAA are not withdrawn by a rename (the host name is unchanged).
          // Captured BEFORE `set_instance(new_name)` below, so `self.records`
          // still names the OLD instance. The Service no longer drains this —
          // it is handed off (`take_rename_goodbye_handoff`) to the endpoint as
          // an independent detached withdrawal item.
          let owned = respond::EmittedRecords::new(
            self.goodbye.ptr,
            self.goodbye.srv,
            self.goodbye.txt,
            std::vec::Vec::new(),
            std::vec::Vec::new(),
            self.goodbye.subtypes,
          );
          self.rename_goodbye_handoff = Some(RenameGoodbyeHandoff {
            records: self.records.clone(),
            owned,
          });
        }
        self.rename_attempt = self.rename_attempt.saturating_add(1);
        let new_name_str =
          rename_with_suffix(self.records.instance().as_str(), self.rename_attempt);
        // Capture the OLD name BEFORE `set_instance` overwrites it — a live
        // commit token's records are cached under this name and nowhere else, and
        // by confirm time nothing here still says so.
        let renamed_from = self.records.clone();
        match crate::Name::try_from_str(&new_name_str) {
          Ok(new_name) => {
            self.stale_live_commit_token(Some(renamed_from));
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
            //
            // The name is NOT mutated on this branch, but `goodbye.reset_instance`
            // below moves its ownership into the handoff installed above, so a
            // parked datagram's records must go to the same place: treating this
            // as a rename-away is what keeps a late confirm from re-latching
            // ownership the handoff now holds (a double withdrawal) and from
            // opening the reclaim-cancel gate on a terminal service.
            self.stale_live_commit_token(Some(renamed_from));
            self.state = ServiceState::Conflicting;
            let _ = self.pending_updates.insert(ServiceUpdate::Conflict);
            self.lifecycle_deadline = None;
            self.pending_transmits = [None, None];
            self.response_deadline = None;
            self.goodbye.reset_instance();
            self.fully_announced = false;
            self.partial_announce_streak = 0;
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
            debug!(
              target: "mdns_proto::service",
              handle = self.handle.raw(),
              "service: Init → Probing(0)"
            );
            // Init→Probing(0) schedules the NEXT deadline; no transmit this tick.
            false // no lifecycle transmit this tick
          }
          ServiceState::Probing(n) => {
            // a probe deadline fired — ENQUEUE the probe and re-arm a
            // fallback retry deadline, but do NOT advance the probe sequence
            // here. The §8.1 progression (next probe, or entering Announcing
            // after the third) happens in `note_transmit_outcome` ONLY once the
            // driver confirms the probe actually reached the link — mirroring
            // the Announcing arm below. An unconfirmed probe is retried at the
            // probe interval instead of the service silently marching toward
            // Announcing with nothing on the wire (RFC 6762 §8.1: a name must be
            // probed before it is claimed).
            debug!(
              target: "mdns_proto::service",
              handle = self.handle.raw(),
              probe_n = n,
              "service: Probing — enqueueing probe"
            );
            self.push_lifecycle_pending(PendingTransmitKind::Probe);
            self.lifecycle_deadline = probe_deadline(now, n, &mut self.rng);
            true
          }
          ServiceState::Announcing(_n) => {
            // an announce deadline fired — schedule the announcement
            // transmit but do NOT advance the phase here. The phase progression
            // and the Established update happen on CONFIRMED delivery
            // (`note_transmit_outcome`); peers learn of us only once a send
            // actually reaches the link. Re-arm at the announce interval so an
            // unconfirmed (all-socket-failed) send is retried rather than the
            // service silently progressing to Established with nothing on the
            // wire. A confirmed send overwrites this deadline.
            debug!(
              target: "mdns_proto::service",
              handle = self.handle.raw(),
              announce_n = _n,
              "service: Announcing — enqueueing announcement"
            );
            self.push_lifecycle_pending(PendingTransmitKind::Announcement);
            self.lifecycle_deadline = announce_deadline(now, 1);
            true
          }
          ServiceState::Established => {
            // The lifecycle deadline that fired is the periodic re-announce.
            debug!(
              target: "mdns_proto::service",
              handle = self.handle.raw(),
              "service: Established — enqueueing periodic re-announce"
            );
            self.push_lifecycle_pending(PendingTransmitKind::Announcement);
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
  ///
  /// # The confirm-before-anything contract
  ///
  /// > Once this method returns a datagram, NO other state-mutating entry point
  /// > for this service — [`Self::handle_event`], [`Self::handle_timeout`],
  /// > [`Self::withdrawal_snapshot`] or any other teardown step — may be invoked
  /// > until that datagram's [`Self::note_transmit_outcome`]. `poll_transmit`
  /// > itself is excepted: it refuses (`Ok(None)`) while a datagram is
  /// > outstanding, which is what makes one confirm resolve exactly one datagram.
  ///
  /// A driver therefore does `poll_transmit` → send → `note_transmit_outcome` as
  /// one indivisible step. A send the transport cannot accept right now is
  /// **dropped and confirmed** — every family missed — not parked:
  /// every re-armed datagram is re-encoded from live state on the next poll, so
  /// dropping one costs nothing but the re-encode.
  ///
  /// The reason parking looks attractive is a fidelity that does not exist.
  /// "Delivered" at this layer already means only *the kernel accepted the
  /// datagram synchronously* — a successful `sendto` says nothing about whether
  /// anything reached the wire, let alone a peer, and UDP offers no way to learn
  /// otherwise. Deferring the confirm to report a truer answer therefore buys
  /// nothing, while everything the interim breaks is real: `poll_transmit` stamps
  /// a commit token before returning, and that token is the ONLY record of what
  /// the encoded bytes mean. An entry point that runs while it is live regresses
  /// or re-encodes the very state the pending confirm is about to apply — a §9
  /// conflict processed between the poll and the confirm voids the datagram's
  /// whole generation, and a teardown between them takes a
  /// [`Self::withdrawal_snapshot`] that cannot know about records the unconfirmed
  /// datagram is putting in peer caches, so the goodbye never withdraws them and
  /// their TTL only starts counting once that late datagram lands.
  ///
  /// The core cannot type-check the ordering, so it is enforced by cheap
  /// backstops rather than assumed: a `debug_assert!` at each entry point fails a
  /// non-compliant driver loudly in its own test suite, and in release the single
  /// slot above, the lifecycle queue's own token check, and the `Stale` token
  /// rewrite keep the damage defined. All are unreachable for a compliant driver.
  ///
  /// Precedent for call-ordering contracts on this type: the drain-to-`Ok(None)`
  /// rule above, and the rename-handoff drain contract on
  /// [`Self::note_transmit_outcome`].
  pub fn poll_transmit(
    &mut self,
    now: I,
    buf: &mut [u8],
  ) -> Result<Option<Transmit>, TransmitError> {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("service", handle = self.handle.raw()).entered();
    // the commit token is a SINGLE slot. If a previously produced
    // datagram has not yet been confirmed via `note_transmit_outcome`, do NOT
    // hand out (and silently overwrite the token of) another one — that would
    // lose the first send's pending confirmation and mis-apply the next result
    // to the wrong datagram. Returning `Ok(None)` makes the documented
    // "poll until Ok(None)" drain contract enforce poll→confirm→poll ordering
    // for EVERY Sans-I/O caller, not just the tokio driver (which already
    // confirms after each send). The token is cleared by `note_transmit_outcome`
    // (`.take()`), so the next poll after a confirm proceeds normally; a probe/
    // announce/response branch below re-stamps it, while the early-return
    // datagram (legacy unicast) only stamps where it owns lifecycle/ownership
    // state.
    if self.awaiting_confirm.is_some() {
      return Ok(None);
    }
    // §9: emit a pending service-type enumeration reply (a single shared
    // meta-PTR). It stamps a `MetaResponse` commit token — every datagram this
    // method returns stamps exactly one token, which is what makes one outcome
    // per datagram well defined — but that token gates no lifecycle or goodbye
    // state: the meta-PTR is shared, advertises no instance records, and is never
    // withdrawn, so its confirm only counts `responses_tx`. An un-encodable reply
    // (near-MTU) is dropped, not surfaced as an error, so a remote meta-query
    // can't poison the service.
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
        // Stamp the MetaResponse token so note_transmit_outcome can count
        // responses_tx on a confirmed delivery.  No goodbye ownership is
        // latched (the meta-PTR is shared and never withdrawn).
        self.awaiting_confirm = Some(AwaitingConfirm::MetaResponse);
        return Ok(Some(Transmit::new(
          respond::multicast_dst(),
          None,
          n,
          self.stamped_obligation(),
          self.stamped_min_family_gap(),
        )));
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
          // goodbye ownership for those records via `note_transmit_outcome`. A
          // meta reply (`emitted` is None) uses MetaResponse — shared PTR, no
          // goodbye ownership — but still counts responses_tx on delivery.
          // Legacy replies are not KAS-filtered, so the partial-suppression
          // count is always 0.
          self.awaiting_confirm = match emitted {
            Some(e) => Some(AwaitingConfirm::Response(e, 0)),
            None => Some(AwaitingConfirm::MetaResponse),
          };
          return Ok(Some(Transmit::new(
            resp.dst,
            None,
            n,
            self.stamped_obligation(),
            self.stamped_min_family_gap(),
          )));
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
    // Per-response KAS suppression count (incremented inside the filter closure
    // via shared Cell, then bumped into stats after encoding).
    #[cfg(feature = "stats")]
    let kas_suppressed = core::cell::Cell::new(0u64);
    let n = match kind {
      PendingTransmitKind::Probe => {
        let n = respond::write_probe(&self.records, buf).map_err(|_| {
          warn!(
            target: "mdns_proto::service",
            handle = self.handle.raw(),
            "service: poll_transmit probe BufferTooSmall"
          );
          TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(
            buf.len(),
            buf.len(),
          ))
        })?;
        debug!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          bytes = n,
          "service: poll_transmit emitting probe"
        );
        // probes_tx is bumped in note_transmit_outcome on confirmed delivery.
        n
      }
      PendingTransmitKind::Announcement => {
        // Unsolicited announcements (Announcing(_) phase and periodic re-announce
        // from Established) are sent without KAS filtering. RFC 6762 §7.1
        // known-answer suppression only applies to question responses.
        let n = respond::write_announce(&self.records, buf).map_err(|_| {
          warn!(
            target: "mdns_proto::service",
            handle = self.handle.raw(),
            "service: poll_transmit announcement BufferTooSmall"
          );
          TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(
            buf.len(),
            buf.len(),
          ))
        })?;
        debug!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          bytes = n,
          "service: poll_transmit emitting announcement"
        );
        // announcements_tx is bumped in note_transmit_outcome on confirmed delivery.
        n
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
            let suppressed = hints.iter().any(|slot| match slot {
              Some(hint) => {
                hint.owner == owner
                  && hint.rtype == rtype
                  && hint.rdata_hash == h
                  && hint.expires_at > now_ref
              }
              None => false,
            });
            #[cfg(feature = "stats")]
            if suppressed {
              kas_suppressed.set(kas_suppressed.get().saturating_add(1));
            }
            suppressed
          })
          .map_err(|_| {
            warn!(
              target: "mdns_proto::service",
              handle = self.handle.raw(),
              "service: poll_transmit response BufferTooSmall"
            );
            TransmitError::BufferTooSmall(crate::error::BufferTooSmallDetail::new(
              buf.len(),
              buf.len(),
            ))
          })?;
        resp_emitted = emitted;
        debug!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          bytes = encoded,
          "service: poll_transmit emitting response"
        );
        encoded
      }
    };
    // Encoding succeeded — NOW remove from the queue (peek-then-pop).
    let kind = self.peek_pending();
    self.pop_pending();
    // the datagram has been
    // ENCODED, but no lifecycle state advances here. Map the queued kind to the
    // commit token the driver resolves via `note_transmit_outcome` — the SOLE
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
        // §7.1: if KAS suppressed EVERY record the response is header-only —
        // do not put an empty response on the wire, and latch nothing (a
        // header-only datagram advertises nothing to withdraw).
        //
        // Full suppression: no datagram leaves the host, so there is no
        // delivery to wait for. Count answers_suppressed_kas immediately at
        // the point of suppression — this is a genuine suppression event, not
        // a send failure. Document: this is the ONLY counter bump in
        // poll_transmit that is NOT deferred to note_transmit_outcome, because
        // Ok(None) means no datagram (and thus no AwaitingConfirm token) is
        // ever produced.
        if resp_emitted.is_empty() {
          #[cfg(feature = "stats")]
          if let Some(s) = self.stat() {
            let suppressed = kas_suppressed.get();
            if suppressed > 0 {
              s.answers_suppressed_kas(suppressed);
            }
          }
          return Ok(None);
        }
        // Partial suppression: carry the suppressed count in the AwaitingConfirm
        // token and defer the answers_suppressed_kas bump to note_transmit_outcome
        // so a socket failure does NOT inflate the counter.
        // responses_tx is also deferred there.
        #[cfg(feature = "stats")]
        let partial_suppressed = kas_suppressed.get();
        #[cfg(not(feature = "stats"))]
        let partial_suppressed = 0u64;
        // Latch goodbye ownership only for the concrete records actually emitted.
        Some(AwaitingConfirm::Response(resp_emitted, partial_suppressed))
      }
      None => None,
    };
    let _ = self.pending_tx.iter().next(); // silence unused-field warning
    // Multicast response — serves QM and QU (§5.4) group members. Legacy unicast
    // queriers are handled separately via `pending_legacy`.
    Ok(Some(Transmit::new(
      respond::multicast_dst(),
      None,
      n,
      self.stamped_obligation(),
      self.stamped_min_family_gap(),
    )))
  }
}
}

#[cfg(test)]
#[cfg(all(any(feature = "alloc", feature = "std"), feature = "slab"))]
mod tests;

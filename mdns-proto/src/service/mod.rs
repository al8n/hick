//! Service state machine — probing, announcing, response generation.

cfg_heap! {
  use crate::trace::*;

  /// `pub(crate)` for the PATH only. The seal this module keeps is that nothing
  /// outside it picks an `RdataForm` for §8.2 — see its own documentation — and
  /// that is enforced by what it exports (a finished `Verdict`), not by where it
  /// can be named from. The endpoint's routing tests adjudicate real datagrams
  /// through `adjudicate` rather than restating the fold, which is the whole
  /// point of `routing_over_approximates_what_the_fold_adjudicates`.
  pub(crate) mod proposal;
  mod respond;
}
pub(crate) mod schedule;
mod state;

cfg_heap! {}

cfg_heap! {
  /// A single observed known-answer hint. §7.1 suppression checks each
  /// candidate record against this list before emitting it.
  ///
  /// THERE IS NO OWNER FIELD, and that absence is the rule. RFC 6762 §7.1
  /// identifies an RRset by (name, type, class, rdata), so a hint may suppress
  /// one of our records only when it names the very owner that record sits at —
  /// and [`respond::emitted_owner_name`] already answered that from the rtype
  /// when the hint was ADMITTED, rejecting anything arriving at another name. A
  /// stored hint is therefore a hint at the owner its rtype implies, and
  /// matching the rtype IS matching the owner.
  ///
  /// While the owner was carried here it was classified TWICE by two different
  /// rules — by name on the way in, by rtype on the way out — and the two
  /// disagreed wherever a service's instance name is also its host name.
  #[derive(Debug, Clone, Copy)]
  struct KasHint<I> {
    rtype: crate::wire::ResourceType,
    rdata_hash: u64,
    expires_at: I,
  }

  /// Number of KAS hints we'll remember at once (per service).
  const KAS_RING_SIZE: usize = 16;

  /// Cap on the number of distinct questioner sources tracked per
  /// response cycle.  Bursts of
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

  /// minimum interval between conflict-driven re-probes of an
  /// Established/Announcing service (RFC 6762 §9 conflict rate-limiting). A
  /// conflict flood cannot reset us to Probing more than once per interval.
  ///
  /// # That is a RATE bound, and it is not a guarantee of progress
  ///
  /// It does not follow, and this comment used to say it did, that the service
  /// eventually (re)establishes. A peer that watches for each first probe and
  /// answers it immediately with conflicting authoritative data for the CURRENT
  /// renamed instance restarts the sequence before probes two and three ever go
  /// out. Those conflicts arrive PRE-AUTHORITATIVELY — §8.1's rename and §8.2's
  /// deferral adjudicate them, and this interval guards neither; it guards the
  /// §9 established-state revert only. So a peer willing to conflict with every
  /// name this service attempts keeps it out of `Announcing` indefinitely, and
  /// no responder-side rule can stop that: denying a name on the local link is
  /// something a same-link adversary can simply do.
  ///
  /// What the two limits bound between them is the COST of being denied. Once
  /// §8.1's floor is latched, the loop turns roughly once per five seconds
  /// instead of several times a second.
  ///
  /// This is NOT the §8.1 flood limit below it, and both are live at once. This
  /// one bounds how often an ESTABLISHED name may be sent back to probing at
  /// all; §8.1's bounds how soon each restarted probe SEQUENCE may begin,
  /// whatever sent it back. A §9 revert therefore meets both — this interval
  /// decides whether the revert happens, and [`CONFLICT_BACKOFF_MIN_WAIT`]
  /// floors the probe deadline that the revert, once allowed, arms.
  ///
  /// THE TWO ARE SCOPED DIFFERENTLY, and each to what its own sentence is about.
  /// This one is per record set, which is the right scope for it — §9's reset is
  /// about a specific conflicted record. §8.1's is stated on the HOST, so it is
  /// counted across every record set one endpoint routes for; see
  /// [`CONFLICT_BURST_LEN`].
  const CONFLICT_REPROBE_MIN_INTERVAL: core::time::Duration = core::time::Duration::from_secs(1);

  /// RFC 6762 §8.1's flood limit lives on the [`Endpoint`](crate::Endpoint) —
  /// see [`ConflictFlood`], which owns the fifteen-in-ten history, and
  /// [`CONFLICT_BURST_LEN`], which states the rule and its scope. A `Service` is
  /// handed the verdict at the two points that need it: the regress that starts
  /// a fresh probe sequence, and the commit point where a probe would go out.
  // `CONFLICT_BURST_LEN` / `CONFLICT_BURST_WINDOW` are in scope for the doc
  // links above and below, which is the whole reason the rule's three numbers
  // are named rather than spelled out here.
  #[allow(unused_imports)]
  pub(crate) use crate::endpoint::flood::{
    CONFLICT_BACKOFF_MIN_WAIT, CONFLICT_BURST_LEN, CONFLICT_BURST_WINDOW, ConflictFlood,
  };
}

cfg_heap! {

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
  pub(crate) use respond::{
    EmittedRecords, INSTANCE_CANONICAL_RTYPES, RecordSection, canonical_rdata_forms,
    instance_rtype_exposed, multicast_dst, transmitted_envelope, transmitted_rdata_forms,
    write_goodbye,
  };
}
#[allow(unused_imports)]
pub(crate) use schedule::{
  FamilyPatience, MAX_PARTIAL_ROUNDS, PhaseAdvance, announce_deadline, classify_advance,
  compose_announce_deadline, partial_announce_deadline, probe_deadline, probe_retry_deadline,
  re_announce_deadline, stalest_refresh_due,
};
pub use state::ServiceState;

cfg_heap! {
  use core::time::Duration;

  use rand::SeedableRng;

  use crate::error::{HandleTimeoutError, TransmitError};
  use crate::event::{DatagramId, ServiceEvent, ServiceUpdate};
  use crate::records::ServiceRecords;
  use crate::transmit::{
    FamilyAttempt, FamilyDelivery, Transmit, TransmitConfirm, TransmitDelivery, TransmitObligation,
  };
  use crate::{Instant, Pool, ServiceHandle};

  type Rng = rand::rngs::StdRng;
}

cfg_heap! {
  /// The instance names this endpoint ALREADY HOLDS, handed to a rename so it
  /// picks one that is free.
  ///
  /// A rename used to choose blind and let the caller discover the collision:
  /// the `Service` mutated its own records, emitted `Renamed`, and a driver then
  /// offered the new name to the route table, which could refuse it. Every
  /// driver had to carry the same reconciliation for that refusal — retire the
  /// renamer, synthesize a `Conflict`, take the old name's goodbye handoff and
  /// enqueue it as a NAME-HOLDING item so the dead service's records were
  /// retracted before the name could be reused — and each driver had to get all
  /// of it right.
  ///
  /// Now the endpoint owns the `Service`, so the names in use and the name being
  /// chosen are readable in ONE borrow, and the rename simply does not choose a
  /// taken one. The collision arm has no state that can reach it.
  ///
  /// It is a borrowed slice rather than the route table itself because the route
  /// holding the `Service` is mutably borrowed while the rename runs — the names
  /// are collected first, on the tick a rename is actually imminent.
  #[derive(Debug, Clone, Copy)]
  pub(crate) struct NamesInUse<'a> {
    names: &'a [crate::Name],
  }

  impl<'a> NamesInUse<'a> {
    /// Every instance name this endpoint holds EXCEPT the renaming service's own
    /// — a route never collides with itself.
    #[inline(always)]
    pub(crate) const fn new(names: &'a [crate::Name]) -> Self {
      Self { names }
    }

    /// Nothing is held. Used by tests that drive a `Service` with no route table
    /// behind it.
    ///
    /// Gated to match its only callers — [`Service::tick_for_test`] and
    /// `service/tests.rs`, whose `mod tests;` declaration carries this same
    /// predicate. A `cfg_attr(not(test), allow(dead_code))` silenced only the
    /// non-test build and left it compiled, and dead, in any `test` build that
    /// reached this heap tier without `slab`.
    #[cfg(all(test, any(feature = "alloc", feature = "std"), feature = "slab"))]
    pub(crate) const EMPTY: Self = Self { names: &[] };

    /// DNS-name equality, not string equality: a name differing only in the
    /// optional trailing root dot is the SAME owner on the wire, so a string
    /// test would let a rename claim a name the route table already holds. See
    /// [`crate::Name::same_owner`].
    #[inline]
    pub(crate) fn holds(&self, candidate: &crate::Name) -> bool {
      self.names.iter().any(|n| n.same_owner(candidate))
    }

    /// How many names must be stepped over at worst. Each rename attempt yields
    /// a distinct suffix, so one more attempt than this always reaches a free
    /// name — which is what makes the search terminate without a magic bound.
    #[inline(always)]
    fn len(&self) -> usize {
      self.names.len()
    }
  }

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
    ///
    /// The third is the ONE token variant whose destination class is not fixed:
    /// a jittered multicast reply and a §6.7 legacy unicast reply are both
    /// positive-TTL sends of this service's records and both stamp this token.
    /// The confirm needs to tell them apart — see [`SendClass`] — and by then
    /// the destination is gone, so it is captured here at the stamp.
    Response(respond::EmittedRecords, u64, SendClass),
    /// A RFC 6763 §9 service-type enumeration meta-response (multicast or legacy
    /// unicast) is awaiting confirmation. The meta-PTR is a shared record — it
    /// advertises no instance-owned records and is never withdrawn — so a confirmed
    /// delivery bumps `responses_tx` WITHOUT touching goodbye ownership or any
    /// lifecycle state.
    MetaResponse,
    /// A datagram whose LIFECYCLE meaning a regression to [`ServiceState::Init`]
    /// has voided: it was encoded for a generation of the state machine that a
    /// RFC 6762 §9 same-name revert-to-probe, a §8.2 tiebreak deferral, or a §8.1
    /// conflict rename has since replaced.
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
    /// they would have without the regression — including into the half that
    /// depends on [`SendClass`], which a regression does not change.
    SameName {
      /// What the parked datagram emitted.
      emitted: respond::EmittedRecords,
      /// Where it went. Carried for the same reason
      /// [`AwaitingConfirm::Response`] carries it: the confirm latches by
      /// destination class and cannot re-derive one.
      class: SendClass,
    },
    /// The service has RENAMED AWAY from the name these instance records were
    /// emitted under. `records` is the OLD name, cloned at the regression site
    /// before `ServiceRecords::set_instance` overwrote it, so the detached
    /// old-name §10.1 goodbye can still withdraw them.
    ///
    /// NO PATH BUILDS THIS TODAY, and the reason is worth stating so a change
    /// that re-opens one is recognised as doing so. Building it needs a rename
    /// over a LIVE commit token; the only rename is §8.1's, which needs
    /// `probe_on_wire`; every regression that could park a record-carrying token
    /// (the §9 revert, the §8.2 deferral) clears `probe_on_wire`; and a parked
    /// token makes `poll_transmit` return `Ok(None)`, so no probe can be sent to
    /// re-open it. A §8.2 arm that renamed without needing `probe_on_wire` would
    /// be the way through; RFC 6762 §8.2's deferral is what removes it.
    /// `no_rename_is_reachable_with_an_announcement_parked_across_a_section9_revert`
    /// asserts the closure. Kept as a backstop rather than deleted: the argument
    /// rests on four separate invariants, and the failure it guards against —
    /// records stranded in every peer cache under a name nothing will ever
    /// withdraw — is not one to re-derive under a future edit.
    OldName {
      /// The OLD instance name's records.
      records: ServiceRecords,
      /// What the datagram actually emitted under that name.
      emitted: respond::EmittedRecords,
      /// Where it went. See [`Self::SameName`].
      class: SendClass,
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
        Self::Response(..) | Self::MetaResponse | Self::Stale { .. } => TransmitObligation::OneShot,
      }
    }

    /// The minimum gap this token's datagram owes each family it is fanned
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
        Self::Response(..) | Self::MetaResponse | Self::Stale { .. } => Duration::ZERO,
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
  ///
  /// # …and PER FAMILY, for the same reason
  ///
  /// Every latch here is a `[v4, v6]` mask rather than a bool, because delivery
  /// is per family and "peers may hold this record from us" is therefore a
  /// per-family fact. A fan-out is two sends and either may be refused, so an
  /// announcement IPv6 never carried put nothing in any IPv6 peer's cache. Two
  /// things go wrong the moment the pair is collapsed into one bit:
  ///
  /// * the §10.1 goodbye withdraws records on a family that never heard them,
  ///   which can cache-flush a peer's matching shared record — the very class
  ///   the per-record granularity above exists to close, one level down;
  /// * `Endpoint::relinquished_asserts` disowns an IPv6 arrival as an echo of an
  ///   IPv4-only transmission. It cannot be one — a loopback copy comes back
  ///   over a socket that carried the datagram out — so the screen would be
  ///   silencing a GENUINE peer's §8.1 or §9 conflict.
  ///
  /// # …and TWICE, because the two readers ask different questions
  ///
  /// See [`GoodbyeOwnership`]. This type is one destination class's answer; the
  /// wrapper holds two of them.
  #[derive(Debug, Default, Clone)]
  struct RecordExposure {
    /// Which families the instance PTR (service-type → instance) has been
    /// advertised on. RESET on a conflict rename (the new instance name has not
    /// been advertised).
    ptr: [bool; 2],
    /// Which families the instance SRV has been advertised on. Reset on rename.
    srv: [bool; 2],
    /// Which families the instance TXT has been advertised on. Reset on rename.
    txt: [bool; 2],
    /// Which families the RFC 6763 §7.1 subtype PTRs (`<sub>._sub.<type>` →
    /// instance) have been advertised on. Instance-associated (target =
    /// instance), so RESET on rename and withdrawn with the instance records.
    /// All-or-nothing per send — subtype PTRs are not KAS-filtered, so they are
    /// always emitted together.
    subtypes: [bool; 2],
    /// Host A addresses advertised FROM US, tracked per address — the UNION over
    /// families, which is what [`Service::advertised_a_addrs`] reports for the
    /// endpoint's sibling-address retention (a union question: an address ANY
    /// live sibling still advertises must not be withdrawn). SURVIVES a conflict
    /// rename: the host name is invariant across instance renames, so peers keep
    /// caching the host records.
    a: std::vec::Vec<core::net::Ipv4Addr>,
    /// Which families carried `a[i]`, index for index. Only [`Self::latch_addr`]
    /// writes either vector, so the two cannot desync; [`Self::project`] reads
    /// them through `zip`, which stops at the shorter one, so a missing mask
    /// reads as "no family carried it" — the direction that withdraws less and
    /// screens less.
    a_on: std::vec::Vec<[bool; 2]>,
    /// Host AAAA addresses advertised FROM US, tracked per address. Survives rename.
    aaaa: std::vec::Vec<core::net::Ipv6Addr>,
    /// Which families carried `aaaa[i]`, index for index. See [`Self::a_on`].
    aaaa_on: std::vec::Vec<[bool; 2]>,
    /// Which families the RFC 6762 §6.1 instance NSEC has gone out on. Reset on
    /// rename (the NSEC is owned by the INSTANCE name).
    ///
    /// Not part of [`Self::any_instance`], and no goodbye withdraws it: this
    /// latch is the record set's EXPOSURE, and the NSEC is exposed without being
    /// retractable. `Endpoint::relinquished_asserts` is what reads it — a
    /// relinquished set must disown an echo of every identity it transmitted,
    /// and an instance NSEC is one of the three
    /// [`respond::canonical_rdata_forms`] can name.
    nsec: [bool; 2],
  }

  impl RecordExposure {
    /// Latch the concrete records a confirmed send actually emitted, on the
    /// families that actually accepted it — the SOLE way ownership is gained
    /// (besides being reset to none on rename).
    ///
    /// `on` comes from [`TransmitDelivery::delivered_on`], never from
    /// `any_delivered`: a family that missed the datagram put nothing in its
    /// peers' caches and must not be recorded as having done so.
    fn record_emitted(&mut self, e: &respond::EmittedRecords, on: [bool; 2]) {
      or_on(&mut self.ptr, e.ptr(), on);
      or_on(&mut self.srv, e.srv(), on);
      or_on(&mut self.txt, e.txt(), on);
      or_on(&mut self.subtypes, e.subtypes(), on);
      or_on(&mut self.nsec, e.nsec(), on);
      self.record_host_emitted(e, on);
    }
    /// Latch ONLY the host-owned addresses of a confirmed send, on the families
    /// that accepted it.
    ///
    /// Used when the send's INSTANCE records belong to a name the service has
    /// since renamed away from: the host name is invariant across an instance
    /// rename, so those addresses really are cached under a name this service
    /// still holds and stay its to withdraw, while the instance records go to the
    /// detached old-name goodbye instead.
    fn record_host_emitted(&mut self, e: &respond::EmittedRecords, on: [bool; 2]) {
      if !any_family(on) {
        // No family carried it, so nothing was exposed. Returning early keeps
        // the ADDRESS LIST — the union `Service::advertised_a_addrs` reports —
        // free of addresses whose mask says no family carried them, which would
        // otherwise make a sibling retain an address no peer ever heard.
        return;
      }
      for ip in e.a_slice() {
        Self::latch_addr(&mut self.a, &mut self.a_on, *ip, on);
      }
      for ip in e.aaaa_slice() {
        Self::latch_addr(&mut self.aaaa, &mut self.aaaa_on, *ip, on);
      }
    }
    /// Push or update one address and its family mask, keeping the two vectors
    /// index for index. The ONLY writer of either.
    fn latch_addr<T: Copy + PartialEq>(
      addrs: &mut std::vec::Vec<T>,
      masks: &mut std::vec::Vec<[bool; 2]>,
      ip: T,
      on: [bool; 2],
    ) {
      if let Some(i) = addrs.iter().position(|x| *x == ip) {
        if let Some(mask) = masks.get_mut(i) {
          or_on(mask, true, on);
        }
        return;
      }
      addrs.push(ip);
      masks.push(on);
    }
    /// Drop INSTANCE ownership (PTR/SRV/TXT) on a conflict rename; host A/AAAA
    /// ownership persists (the host name does not change on an instance rename).
    #[inline]
    fn reset_instance(&mut self) {
      self.ptr = [false; 2];
      self.srv = [false; 2];
      self.txt = [false; 2];
      self.subtypes = [false; 2];
      // The §6.1 NSEC is owned by the instance name, so it goes with them: the
      // NEW name has put no NSEC on the wire, and the OLD name's is carried away
      // by the rename handoff.
      self.nsec = [false; 2];
    }
    /// Whether ANY instance-owned record (PTR/SRV/TXT or a subtype PTR) has been
    /// advertised, on any family.
    #[inline]
    fn any_instance(&self) -> bool {
      any_family(self.ptr) || any_family(self.srv) || any_family(self.txt)
        || any_family(self.subtypes)
    }
    /// Whether ANY host-owned address (A/AAAA) has been advertised, on any family.
    #[inline]
    fn any_host(&self) -> bool {
      !self.a.is_empty() || !self.aaaa.is_empty()
    }
    /// What ONE family carried, as the same [`respond::EmittedRecords`] the
    /// encoders report.
    ///
    /// This projection is what keeps the family dimension cheap everywhere else:
    /// a withdrawal snapshot, a rename handoff, a withdrawal item and a
    /// relinquished row all carry `[EmittedRecords; 2]`, so every consumer reads
    /// its own family's half — with no new
    /// vocabulary, and with no way to read the wrong half, because the pair is
    /// only ever taken apart through
    /// [`Family::pick_ref`](crate::transmit::Family::pick_ref).
    fn project(&self, family: crate::transmit::Family) -> respond::EmittedRecords {
      respond::EmittedRecords::new(
        family.pick(self.ptr),
        family.pick(self.srv),
        family.pick(self.txt),
        family_addrs(&self.a, &self.a_on, family),
        family_addrs(&self.aaaa, &self.aaaa_on, family),
        family.pick(self.subtypes),
        family.pick(self.nsec),
      )
    }
    /// This latch as the `[v4, v6]` exposure pair every relinquishment,
    /// withdrawal snapshot and rename handoff carries.
    fn per_family(&self) -> [respond::EmittedRecords; 2] {
      [
        self.project(crate::transmit::Family::V4),
        self.project(crate::transmit::Family::V6),
      ]
    }
  }

  /// WHERE a confirmed positive send actually went, kept because the answer
  /// decides whether a delayed ECHO of those bytes can exist at all.
  ///
  /// It is a fact about the DATAGRAM, so it is captured where every other such
  /// fact is — on the commit token [`Service::poll_transmit`] stamps — rather
  /// than reconstructed at confirm time, when the destination is gone.
  #[derive(Debug, Clone, Copy, Eq, PartialEq)]
  enum SendClass {
    /// The RFC 6762 §6 multicast group. A copy comes back over a socket that
    /// carried the datagram out — kernel loopback, or the 802.11 base-station
    /// re-broadcast §8.2 names — so these bytes can arrive again as a MULTICAST
    /// datagram, which is the only kind this endpoint adjudicates.
    Multicast,
    /// A §6.7 legacy reply, addressed to ONE resolver's ephemeral port. Nothing
    /// puts it on the group, so no multicast copy of these bytes ever existed.
    Unicast,
  }

  /// The two exposure questions, kept apart because their answers differ and
  /// only one of them may ever be read as multicast-echo provenance.
  ///
  /// Both are "which records did a confirmed send emit, on which family", and
  /// for a long time one latch answered both. It cannot: an RFC 6762 §6.7 legacy
  /// reply is a positive-TTL send of the FULL record set, and it goes to one
  /// off-group resolver's ephemeral port.
  ///
  /// * WHAT MAY BE IN A PEER'S CACHE FROM US, and therefore what a §10.1 goodbye
  ///   owes a retraction for, is [`Self::all`]. The legacy querier's cache holds
  ///   those records exactly as a multicast listener's would, so the unicast
  ///   send counts here, and so does everything else this latch feeds:
  ///   `advertises_instance` (row B′'s "the previous generation advertised"),
  ///   `advertises_host`, and the sibling-retained address union.
  /// * WHAT COULD STILL BE ECHOING BACK AT US is [`Self::multicast`], and it is
  ///   strictly narrower. `Endpoint::relinquished_asserts` screens a MULTICAST
  ///   arrival, and a datagram that was never on the group cannot produce one —
  ///   so a set whose only positive send was a legacy reply must disown nothing.
  ///   Answering `all` there labelled a GENUINE peer's multicast A/AAAA as this
  ///   endpoint's own relinquished history and suppressed the host conflict for
  ///   the whole retention window, on the strength of bytes no multicast socket
  ///   ever carried.
  ///
  /// One type with two halves rather than two fields on `Service`, so a mutator
  /// cannot be applied to one and forgotten on the other: every writer here
  /// takes the [`SendClass`] and updates both by the same rule.
  #[derive(Debug, Default, Clone)]
  struct GoodbyeOwnership {
    /// Every confirmed positive send, whatever its destination class.
    all: RecordExposure,
    /// The MULTICAST subset of [`Self::all`] — never larger, and the only half
    /// the relinquished-history screen may read.
    multicast: RecordExposure,
  }

  impl GoodbyeOwnership {
    /// Latch what a confirmed send emitted into `all`, and into `multicast` only
    /// when the datagram was actually multicast.
    fn record_emitted(&mut self, e: &respond::EmittedRecords, on: [bool; 2], class: SendClass) {
      self.all.record_emitted(e, on);
      if matches!(class, SendClass::Multicast) {
        self.multicast.record_emitted(e, on);
      }
    }
    /// The host-only counterpart of [`Self::record_emitted`], for a send whose
    /// INSTANCE records belong to a name the service has since renamed away
    /// from.
    fn record_host_emitted(
      &mut self,
      e: &respond::EmittedRecords,
      on: [bool; 2],
      class: SendClass,
    ) {
      self.all.record_host_emitted(e, on);
      if matches!(class, SendClass::Multicast) {
        self.multicast.record_host_emitted(e, on);
      }
    }
    /// Drop INSTANCE ownership on a conflict rename — in BOTH halves, since the
    /// new name has put nothing on any wire by any means.
    #[inline]
    fn reset_instance(&mut self) {
      self.all.reset_instance();
      self.multicast.reset_instance();
    }
    /// Whether ANY instance-owned record has been advertised, on any family, BY
    /// ANY MEANS. A legacy querier that cached our SRV holds this name's records
    /// as surely as a multicast listener does.
    #[inline]
    fn any_instance(&self) -> bool {
      self.all.any_instance()
    }
    /// Whether ANY host-owned address has been advertised, by any means.
    #[inline]
    fn any_host(&self) -> bool {
      self.all.any_host()
    }
    /// The `[v4, v6]` exposure pair a §10.1 goodbye is owed for.
    fn per_family(&self) -> [respond::EmittedRecords; 2] {
      self.all.per_family()
    }
    /// The `[v4, v6]` exposure pair the relinquished-history screen may read —
    /// multicast-positive emissions only. See [`Self::multicast`].
    fn per_family_multicast(&self) -> [respond::EmittedRecords; 2] {
      self.multicast.per_family()
    }
  }

  /// OR `on` into `mask` when `emitted`, leaving it untouched otherwise.
  ///
  /// A helper rather than five copies of the same two-element loop, and a
  /// deliberate one: the mistake it exists to make hard is ORing a delivery mask
  /// into a record the message did not carry.
  #[inline]
  fn or_on(mask: &mut [bool; 2], emitted: bool, on: [bool; 2]) {
    if !emitted {
      return;
    }
    for (slot, delivered) in mask.iter_mut().zip(on) {
      *slot |= delivered;
    }
  }

  /// Whether either half of a family mask is set.
  #[inline]
  const fn any_family(mask: [bool; 2]) -> bool {
    let [v4, v6] = mask;
    v4 || v6
  }

  /// Split one message's INSTANCE-only report into the `[v4, v6]` exposure pair,
  /// crediting each family only with what it actually accepted.
  ///
  /// The rename handoff's own projection: the live latch has already been reset
  /// for the new name, so the old name's exposure cannot be read back off it and
  /// has to be built from the confirm that carried it.
  fn per_family_instance(
    instance: &respond::EmittedRecords,
    on: [bool; 2],
  ) -> [respond::EmittedRecords; 2] {
    let credit = |carried: bool| {
      if carried {
        instance.clone()
      } else {
        respond::EmittedRecords::default()
      }
    };
    let [v4, v6] = on;
    [credit(v4), credit(v6)]
  }

  /// The addresses of `addrs` whose parallel mask names `family`.
  ///
  /// `zip` stops at the shorter vector, so an address with no mask contributes
  /// nothing — it reads as "no family carried this", which under-withdraws and
  /// under-screens rather than the reverse.
  fn family_addrs<T: Copy>(
    addrs: &[T],
    masks: &[[bool; 2]],
    family: crate::transmit::Family,
  ) -> std::vec::Vec<T> {
    addrs
      .iter()
      .zip(masks)
      .filter(|(_, mask)| family.pick(**mask))
      .map(|(ip, _)| *ip)
      .collect()
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
  pub(crate) struct WithdrawalSnapshot {
    /// The service records (names, port, TXT) for this withdrawal. Carried so
    /// the encoder can re-encode PTR/SRV/TXT at TTL=0 without a live `Service`.
    pub records: crate::records::ServiceRecords,
    /// What this service actually put on each family's wire — `[v4, v6]`, per
    /// record and per host address, mirroring the [`GoodbyeOwnership`] latch it
    /// is projected from. Only records that reached a peer cache need to be
    /// withdrawn, and only from the family whose peers cached them.
    ///
    /// A PAIR rather than one report, because delivery is per family: a fan-out
    /// is two sends and either may be refused, so an announcement IPv6 never
    /// carried left nothing in any IPv6 peer's cache. The endpoint seeds each
    /// family's §10.1 goodbye debt from its own half, and
    /// `Endpoint::relinquished_asserts` screens an arrival against the half its
    /// own family transmitted.
    ///
    /// `pub(crate)` because `EmittedRecords` is a crate-internal type; the
    /// endpoint (same crate) reads this directly, and a driver only ever moves
    /// the whole snapshot.
    pub(crate) owned: [respond::EmittedRecords; 2],
    /// The MULTICAST subset of [`Self::owned`], and the ONLY half
    /// `Endpoint::relinquished_asserts` may read.
    ///
    /// A §6.7 legacy reply is a positive-TTL send of the full record set to one
    /// resolver's ephemeral port. Its records are in that resolver's cache, so
    /// they are `owned` and the §10.1 goodbye owes them a retraction — but no
    /// multicast copy of those bytes ever existed, so a MULTICAST arrival
    /// matching them cannot be an echo of ours. Answering `owned` there labelled
    /// a genuine peer's record as this endpoint's own relinquished history and
    /// suppressed the host conflict for the whole retention window. See
    /// `GoodbyeOwnership`.
    pub(crate) multicast: [respond::EmittedRecords; 2],
  }

  impl WithdrawalSnapshot {
    /// Test-only: a snapshot whose WHOLE exposure was multicast.
    ///
    /// It is what "this service announced" means — RFC 6762 §8.3's unsolicited
    /// response is a §6 multicast by construction — so it is the shape almost
    /// every fixture wants, and naming it once keeps the assumption visible.
    /// A fixture that is ABOUT the split states both halves itself.
    ///
    /// Gated to match its only caller: every call site lives in
    /// `endpoint/tests.rs`, whose `mod tests;` declaration itself requires
    /// `all(test, feature = "std", feature = "slab")`, a strict subset of the
    /// heap tier this `cfg_heap!` block grants. A bare `#[cfg(test)]` left this
    /// compiled — and, under `-D warnings`, "never used" — in any `test` build
    /// that reached the heap tier via `alloc` or `no-atomic` alone, or via
    /// `std` without `slab`.
    #[cfg(all(test, feature = "std", feature = "slab"))]
    pub(crate) fn announced(
      records: crate::records::ServiceRecords,
      owned: [respond::EmittedRecords; 2],
    ) -> Self {
      Self {
        records,
        multicast: owned.clone(),
        owned,
      }
    }
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
  pub(crate) struct RenameGoodbyeHandoff {
    /// The OLD instance name's records (names, port, TXT), captured BEFORE the
    /// rename mutated the instance name. `pub(crate)`: the endpoint (same crate)
    /// reads it directly.
    pub(crate) records: crate::records::ServiceRecords,
    /// Which instance records (PTR/SRV/TXT/subtypes) the OLD name actually put on
    /// EACH family's wire — `[v4, v6]`, only these are withdrawn (§7.1 KAS can
    /// suppress a subset, and a fan-out's two sends can differ in what each
    /// family accepted). The address lists are always empty (a rename never
    /// withdraws host A/AAAA). `pub(crate)`: `EmittedRecords` is a crate-internal
    /// type.
    pub(crate) owned: [respond::EmittedRecords; 2],
    /// The MULTICAST subset of [`Self::owned`] — see
    /// [`WithdrawalSnapshot::multicast`] for why the two are not one field.
    pub(crate) multicast: [respond::EmittedRecords; 2],
  }

  impl RenameGoodbyeHandoff {
    /// Test-only: a handoff whose WHOLE exposure was multicast. See
    /// [`WithdrawalSnapshot::announced`], including for why the gate below is
    /// narrower than a bare `#[cfg(test)]`.
    #[cfg(all(test, feature = "std", feature = "slab"))]
    pub(crate) fn announced(
      records: crate::records::ServiceRecords,
      owned: [respond::EmittedRecords; 2],
    ) -> Self {
      Self {
        records,
        multicast: owned.clone(),
        owned,
      }
    }
  }
}

cfg_heap! {
  /// Unforgeable proof of [`Service::has_fully_announced`] — the reclaim-cancel
  /// gate of
  /// [`Endpoint::note_service_transmit_outcome`](crate::Endpoint::note_service_transmit_outcome).
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
  /// [`Endpoint::note_service_transmit_outcome`](crate::Endpoint::note_service_transmit_outcome)
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
    #[allow(dead_code)]
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
  /// One per registered service, OWNED by the
  /// [`Endpoint`](crate::Endpoint) that registered it and driven through that
  /// endpoint's `*_service*` accessors. [`Endpoint::service`](crate::Endpoint::service)
  /// hands out this read-only view: the name it is probing for or holds, its
  /// lifecycle state, its records, and what it has confirmed-advertised.
  ///
  /// Driving one means honouring two call-ordering contracts, both stated on
  /// [`Endpoint::poll_service_transmit`](crate::Endpoint::poll_service_transmit):
  /// drain it until it returns `Ok(None)`, and confirm each datagram it hands
  /// out — via
  /// [`Endpoint::note_service_transmit_outcome`](crate::Endpoint::note_service_transmit_outcome)
  /// — before invoking any other state-mutating entry point for this service.
  pub struct Service<I, TQ, EV> {
  handle: ServiceHandle,
  state: ServiceState,
  /// Whether to keep sending the periodic re-announce.  When `true` (the
  /// default) the service runs the full RFC 6762 lifecycle: §8.1 probes, §8.3
  /// startup announcements and the periodic re-announce that keeps peers'
  /// caches fresh.  When `false` the service is a non-announcing responder: it
  /// still probes and announces once at startup (RFC 6762 §8.1/§8.3), but the
  /// periodic re-announce is suppressed, so after the startup burst nothing is
  /// put on the wire unless an explicit query asks for its records.  Set via
  /// `EndpointConfig::with_re_announce(false)`.
  re_announce: bool,
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
  /// Most-recently-seen `now`, kept for [`Self::poll_timeout`] — the one
  /// clock-sensitive method with no `now` of its own. It answers "due
  /// immediately" by naming an instant in the past, and this is the only
  /// instant it has. Set at construction and refreshed by `handle_timeout` and
  /// `handle_event`.
  ///
  /// It is NOT a clock for anything that receives one. A method given `now`
  /// reads its parameter: this field only tracks the last call that happened to
  /// carry an instant, and a caller may poll any number of times in between, so
  /// it is a lower bound on the real time and never the real time.
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
  /// Whether a probe for the CURRENT instance name has reached at least one
  /// link — i.e. whether RFC 6762 §8.1's conflict window has opened for it.
  ///
  /// §8.1: "Apparently conflicting Multicast DNS responses received *before* the
  /// first probe packet is sent MUST be silently ignored (see discussion of
  /// stale probe packets in Section 8.2)." Until this is set, an inbound
  /// `ProbeConflict` is dropped rather than buffered for the §8.2 tiebreak —
  /// otherwise a peer's probe (or a switch's echo of a probe sent moments ago)
  /// can decide a tiebreak against a name we have never once claimed on the
  /// wire, and the service renames having transmitted nothing at all.
  ///
  /// Latched on the first probe confirm that any family accepted, because a
  /// probe every link refused is a packet that was not sent.
  ///
  /// Per §8.1 SEQUENCE, so every fresh probing generation closes it again: a
  /// §8.2 rename (via [`Service::reset_advertised_name_state`], which clears the
  /// rest of the per-advertised-name generation state with it) and a §9
  /// revert-to-probing alike. §9 says to "go through the startup steps described
  /// above in Section 8", and §8.1's rule is scoped to the first probe packet of
  /// the sequence it introduces — not to the first one the name ever sent.
  probe_on_wire: bool,
  /// Whether an instance record of the CURRENT probing generation has been
  /// confirmed onto the wire.
  ///
  /// Distinct from `goodbye.any_instance()`, and the distinction is the whole
  /// point. Goodbye ownership answers "what must a §10.1 withdrawal retract",
  /// so a §9 revert deliberately KEEPS it — peers still hold the previous
  /// generation's records under this same name. The conflict rules ask a
  /// different question: RFC 6762 §9 sends a conflicted responder "through the
  /// startup steps described above in Section 8", and throughout those steps
  /// §8.1/§8.2 govern however loudly the PREVIOUS generation advertised.
  ///
  /// Reusing the goodbye latch for both made a §9 re-probe's conflict handling a
  /// function of the driver's loop order all over again: `is_preauthoritative`
  /// was true in `Probing(3)` and false the moment a timer-first driver stepped
  /// to `Announcing(0)`, purely because the OLD generation's ownership was still
  /// latched — so an RX-first driver renamed on a winning proposal and a
  /// timer-first driver ignored the same one.
  ///
  /// Cleared wherever a generation starts — a §8.2 rename and a §9 revert — and
  /// set only by a confirmed emission of THIS generation's instance records. A
  /// stale confirm for a datagram the previous generation encoded does not set
  /// it: those records reached peers, which is why goodbye still owns them, but
  /// the generation now probing has claimed nothing.
  ///
  /// "Instance records" is [`respond::EmittedRecords::claims_instance_name`],
  /// which is SRV or TXT and nothing else. The service-type PTR and the RFC 6763
  /// §7.1 subtype PTRs are owned by shared names, so emitting them claims no
  /// instance — and a §7.1 known-answer-filtered response can emit exactly those
  /// alone. Counting them here closed the pre-authoritative window with nothing
  /// instance-owned on the link at all, and the next winning `ProbeProposal` went
  /// unadjudicated.
  generation_advertised: bool,
  /// Set when some peer's COMPLETE §8.2 proposal beat ours this round.
  ///
  /// An accumulated verdict, not a buffer. Each proposal arrives whole and is
  /// folded into this the moment it does, so there is nothing to retain, no cap
  /// to exhaust, and no partial list that a timeout could adjudicate early.
  tiebreak_lost: bool,
  /// Set when a conflicting authoritative RESPONSE arrived inside RFC 6762
  /// §8.1's probing window, so the next `handle_timeout` must defer to the host
  /// that already owns this name and rename.
  ///
  /// Separate from `tiebreak_lost` because the two are different rules with
  /// different inputs and different outcomes. §8.2's tiebreak resolves two hosts
  /// probing at once, neither of which owns the name, and can be WON. §8.1's
  /// deferral is not a comparison at all: an existing responder answered, so the
  /// name is taken whatever our records sort like. This one therefore outranks a
  /// pending tiebreak wherever both are set.
  probe_defeated: bool,
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
  /// The bound is charged once per stretch of failure, not once per phase: the
  /// excusal sets `FamilyPatience::stalled` and a family carrying that latch is
  /// excusable on sight, so a link that is chronically dead costs one round per
  /// phase rather than `MAX_PARTIAL_ROUNDS + 1` — and the healthy link is not made
  /// to pay for it in §8.3 ladder rungs.
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
  /// When the CURRENT RFC 6762 §8 startup sequence began — set at construction
  /// and re-set by every regress that starts a fresh one.
  ///
  /// It anchors §8.1's five-second flood floor, and it is anchored to the
  /// SEQUENCE rather than re-derived from each tick's `now` because the floor is
  /// re-evaluated at more than one point. A relative `now + 5 s` re-applied at
  /// the commit point would push the probe five seconds further out every time
  /// it was consulted; an absolute `start + 5 s` converges — once `now` has
  /// reached it the wait is served, so it costs at most one re-arm per arm.
  sequence_started_at: I,
  /// RFC 6762 §8.1 count eligibility for ONE received datagram, captured at the
  /// first conflict that datagram produces: `(which datagram, was this
  /// generation's first probe already on the wire)`.
  ///
  /// # Why the answer is per DATAGRAM and not per record
  ///
  /// §8.1's gate on counting — "apparently conflicting Multicast DNS responses
  /// received *before* the first probe packet is sent MUST be silently ignored"
  /// — is a question about the instant the datagram ARRIVED. One datagram
  /// carries many records, and an earlier record of it can move the very state a
  /// later record's gate reads: an established service whose instance and host
  /// names differ is sent through §9's revert by a conflicting SRV at its
  /// instance name, which shuts `probe_on_wire`, so a conflicting A at its host
  /// name two records later was read as pre-authoritative and not counted. The
  /// declared key is `(datagram, contested owner)` and those are two owners, so
  /// the count depended on the order the two records happened to appear in.
  ///
  /// Captured once and re-read for the rest of that datagram, which is the rule
  /// this crate already applies to the clock one field over: the router's `now`
  /// is "not re-read per record. The datagram is one event with one processing
  /// instant." Eligibility is the same kind of fact about the same event.
  ///
  /// Keyed by [`DatagramId`], so the next datagram simply replaces the capture
  /// and no lifecycle transition has to remember to clear it.
  ///
  /// It gates COUNTING and nothing else. WHICH conflict rule a record falls
  /// under is still decided from live state, because a regress genuinely does
  /// shut §8.1's window for the generation it starts — see
  /// [`Service::restart_probe_cycle`].
  flood_eligibility: Option<(DatagramId, bool)>,
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
  /// (RFC 6763 §9 + §7.1): when a meta questioner's known-answer section
  /// already carries the meta-PTR for OUR service type, the instant that
  /// known answer STOPS being one — the arriving record's own TTL counted from
  /// the instant its event carried. Our pending meta reply is suppressed only
  /// while `now` is still before it. Reset each meta cycle.
  ///
  /// A deadline rather than a flag for the same reason `KasHint::expires_at` is
  /// one: §7.1 licenses withholding only a record the querier STILL holds, and a
  /// conforming Sans-I/O caller may queue the meta reply and poll it with no
  /// `handle_event` or `handle_timeout` in between, so an unconditional flag
  /// could silence a service-type enumeration whose known answer had already
  /// lapsed — leaving the querier with no answer at all, from us or from anyone.
  meta_known_answered: Option<I>,
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
  ///
  /// When `re_announce` is `false` the service is a non-announcing responder: it
  /// runs the startup steps above exactly once — probing (§8.1) if `probe` is
  /// `true`, then the two §8.3 announcements — and afterwards never sends
  /// unsolicited traffic. The periodic re-announce is suppressed, so once the
  /// startup burst is confirmed peers' cached records expire at their TTL and
  /// the service is only findable by an explicit query.  `re_announce` and
  /// `probe` are orthogonal: `re_announce` controls the post-startup
  /// re-announce, `probe` controls whether the name is verified before it is
  /// claimed.
  ///
  /// `flood` is the endpoint's RFC 6762 §8.1 history, and it floors this
  /// service's FIRST probe exactly as it floors every restarted sequence's.
  /// "Each successive additional probe attempt" belongs to the host, so a record
  /// set registered while the limit is in force does not get to start at §8.1's
  /// ordinary 0-250 ms delay — that is the bypass a per-record-set counter could
  /// not close, since a fresh `Service` always began with an empty history.
  #[allow(dead_code)]
  pub(crate) fn try_new(
    handle: ServiceHandle,
    records: ServiceRecords,
    now: I,
    rng_seed: [u8; 32],
    probe: bool,
    re_announce: bool,
    flood: &ConflictFlood<I>,
  ) -> Self {
    let mut rng = Rng::from_seed(rng_seed);
    let (state, lifecycle_deadline) = if probe {
      let base = probe_deadline(now, 0, &mut rng);
      // The floor, applied at the one point a fresh sequence has: its start.
      // `None` when the clock cannot express `now + 5 s` is the same fail-closed
      // answer the regress gives — every instant such a clock can name is sooner
      // than the wait §8.1 mandates, so there is no deadline this may arm. The
      // service is then parked in `Init`, and `handle_timeout`'s `Init`
      // re-schedule re-evaluates it on every tick.
      let deadline = if flood.in_force(now) {
        now
          .checked_add_duration(CONFLICT_BACKOFF_MIN_WAIT)
          .map(|floor| base.map_or(floor, |d| d.max(floor)))
      } else {
        base
      };
      (ServiceState::Init, deadline)
    } else {
      // A non-probing service makes no probe attempt for §8.1 to space out.
      (ServiceState::Announcing(0), announce_deadline(now, 0))
    };
    Self {
      handle,
      state,
      re_announce,
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
      probe_on_wire: false,
      probe_defeated: false,
      tiebreak_lost: false,
      generation_advertised: false,
      goodbye: GoodbyeOwnership::default(),
      fully_announced: false,
      partial_announce_streak: 0,
      partial_rounds: [FamilyPatience::default(); 2],
      last_delivered: [None, None],
      awaiting_confirm: None,
      pending_legacy: std::vec::Vec::new(),
      last_conflict_reprobe: None,
      sequence_started_at: now,
      flood_eligibility: None,
      rename_goodbye_handoff: None,
      meta_response_deadline: None,
      meta_questioner_srcs: std::vec::Vec::new(),
      meta_known_answered: None,
      #[cfg(test)]
      contract_assertions_off: false,
    }
  }

  /// Test-only: take `new_name` without going through a conflict.
  ///
  /// The shipped rename is inside [`Service::handle_timeout`], where §8.1's
  /// defeat is spent; this is for endpoint fixtures whose subject is what a
  /// rename does to the WITHDRAWAL lifecycle — which name is reserved, which
  /// goodbye survives — and which have no reason to stage a probe sequence and a
  /// peer's defence to get there.
  #[cfg(test)]
  pub(crate) fn rename_for_test(&mut self, new_name: crate::Name) {
    self.records.set_instance(new_name);
    self.reset_advertised_name_state();
  }

  /// Test-only: build a `Service` with no endpoint behind it and therefore an
  /// EMPTY RFC 6762 §8.1 flood history.
  ///
  /// The flood limit is the endpoint's, and these tests exercise one record
  /// set's own state machine. An empty history is "the limit is not in force",
  /// which is what every test that is not about the limit means. The limit's own
  /// behaviour is pinned against the endpoint API, where it lives.
  #[cfg(all(test, any(feature = "alloc", feature = "std"), feature = "slab"))]
  pub(crate) fn for_test(
    handle: ServiceHandle,
    records: ServiceRecords,
    now: I,
    rng_seed: [u8; 32],
    probe: bool,
    re_announce: bool,
  ) -> Self {
    Self::try_new(
      handle,
      records,
      now,
      rng_seed,
      probe,
      re_announce,
      &ConflictFlood::new(),
    )
  }

  /// Test-only: drive a timeout with an empty flood history and an empty
  /// name-in-use set. See [`Service::for_test`]; the name set is empty because
  /// there is no route table, so every rename candidate is free.
  #[cfg(all(test, any(feature = "alloc", feature = "std"), feature = "slab"))]
  pub(crate) fn tick_for_test(&mut self, now: I) -> Result<(), HandleTimeoutError> {
    self.handle_timeout(now, &ConflictFlood::new(), &NamesInUse::EMPTY)
  }

  /// Test-only: dispatch one event with an empty flood history. See
  /// [`Service::for_test`].
  #[cfg(all(test, any(feature = "alloc", feature = "std"), feature = "slab"))]
  pub(crate) fn feed_for_test(&mut self, event: ServiceEvent<'_>, now: I) {
    self.handle_event(event, now, &mut ConflictFlood::new());
  }

  /// Test-only: opt this service out of the debug-build contract assertions.
  ///
  /// The only callers are the backstop tests, which must reproduce a
  /// non-compliant driver to observe what release builds do when the contract is
  /// broken.
  #[cfg(test)]
  #[cfg(all(any(feature = "alloc", feature = "std"), feature = "slab"))]
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
  /// reached EVERY obligated link — i.e. at least one announcement was accepted
  /// by every family that was obligated to carry it.
  ///
  /// This is the reclaim-cancel gate the driver ferries into
  /// [`Endpoint::note_service_transmit_outcome`](crate::Endpoint::note_service_transmit_outcome):
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
  /// The result is wrapped in [`FullyAnnounced`] so that the wrong fact cannot be
  /// substituted where this one is meant; use [`FullyAnnounced::get`] to read it.
  /// The endpoint reads the fact off the service itself when it decides whether
  /// a detached old-name goodbye has been superseded, so the token never travels
  /// between calls and cannot be paired with another service's handle at all.
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
    &self.goodbye.all.a
  }

  /// The host IPv6 addresses this service has actually ADVERTISED, per address
  /// (the AAAA counterpart of [`Self::advertised_a_addrs`]).
  #[inline]
  pub fn advertised_aaaa_addrs(&self) -> &[core::net::Ipv6Addr] {
    &self.goodbye.all.aaaa
  }

  /// Report what each address family's transport did with the datagram most
  /// recently produced by [`Self::poll_transmit`] (the confirm-on-send
  /// chokepoint), and take back the two conclusions the core draws from it.
  ///
  /// The driver reports I/O-world facts only — see [`FamilyAttempt`], which also
  /// states plainly that this is a TRUST boundary rather than a proof. Every
  /// protocol meaning below is read into them HERE: the presence trichotomy, the
  /// confirm anchor, and whether the producer can ever carry these bytes.
  ///
  /// # The anchor
  ///
  /// `now` is used only as the FALLBACK for a round no family accepted. When some
  /// family did, the confirm is anchored at the EARLIEST acceptance across
  /// families. Earliest is the only safe fold: it can only understate how fresh a
  /// family's peers are, so the next transmission lands sooner than strictly
  /// needed, whereas the latest — or the driver's own post-fan-out reading —
  /// would backdate every family by however long the slowest one took and push a
  /// healthy family's next send past its records' TTL.
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
  /// * **Goodbye ownership latches iff SOME obligated family accepted it** —
  ///   peers reachable over any link that accepted the datagram may hold the
  ///   records it carried (RFC 6762 §10.1), whether or not every link did. This
  ///   is the fact handed back as [`TransmitConfirm::any_delivered`].
  /// * **Phase takes full credit iff EVERY obligated family accepted it** — a
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
  ///   `MAX_PARTIAL_ROUNDS` re-arms on it, or spent them on an earlier phase and
  ///   not delivered since. The phase advances from exactly where it stood,
  ///   without that family, and the family stops driving the per-family refresh
  ///   schedule until it delivers again — at which point it is owed the whole
  ///   bound afresh.
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
  ///
  /// # Retirement
  ///
  /// [`TransmitConfirm::retire_producer`] is `true` when no transport can ever
  /// carry these bytes AND the datagram is one the core keeps re-arming — a §8.1
  /// probe or a §8.3 announcement. Such a service would otherwise probe or
  /// announce forever with nothing on any wire and never reach `Established`, and
  /// no patience bound rescues it: the core's patience excuses a MISSING family,
  /// not a round that can succeed on none of them. A §6 / §6.7 / RFC 6763 §9
  /// reply never retires anything.
  pub(crate) fn note_transmit_outcome(
    &mut self,
    now: I,
    v4: FamilyAttempt<I>,
    v6: FamilyAttempt<I>,
  ) -> TransmitConfirm {
    let kind = match self.awaiting_confirm.take() {
      Some(k) => k,
      None => return TransmitConfirm::NOTHING,
    };
    let delivery = FamilyAttempt::project(v4, v6);
    // THE anchor, folded here rather than by the driver: earliest acceptance
    // across families, falling back to the driver's own instant for a round that
    // reached no wire. See [`FamilyAttempt::anchor`].
    let now = FamilyAttempt::anchor(v4, v6, now);
    // A datagram no transport can ever carry retires the producer only if the
    // core will offer it again. Probes and announcements are `Sustained`;
    // responses are `OneShot` and cost exactly one unanswered question. A stale
    // datagram is judged by the same obligation its own generation carried: the
    // replacement generation re-encodes the same records, so the bytes that were
    // impossible stay impossible.
    let sustained = matches!(
      kind,
      AwaitingConfirm::Probe
        | AwaitingConfirm::Announcement(_)
        | AwaitingConfirm::Stale {
          fact: StaleWireFact::Probe | StaleWireFact::Announcement,
          ..
        }
    );
    let confirm = TransmitConfirm::new(
      delivery.any_delivered(),
      sustained && FamilyAttempt::undeliverable(v4, v6),
    );
    self.settle_confirm(now, kind, delivery);
    confirm
  }

  /// Test-only: confirm from a projected delivery SHAPE, discarding the verdict.
  ///
  /// The lifecycle tests are about what the core does with an all / partial /
  /// none round, not about how an I/O outcome projects onto one, and naming the
  /// shape is what keeps them readable. The projection, the anchor fold and the
  /// retirement decision have their own tests, which build attempts explicitly
  /// and read the [`TransmitConfirm`] this one drops.
  #[cfg(test)]
  #[allow(dead_code)]
  pub(crate) fn note_delivery(&mut self, now: I, delivery: TransmitDelivery) {
    let (v4, v6) = delivery.as_attempts(now);
    let _ = self.note_transmit_outcome(now, v4, v6);
  }

  /// The body of [`Self::note_transmit_outcome`], once the commit token is spent
  /// and the attempts are projected. Split out so the projection, the anchor fold
  /// and the retirement decision read as one block above the lifecycle arms they
  /// feed.
  fn settle_confirm(&mut self, now: I, kind: AwaitingConfirm, delivery: TransmitDelivery) {
    match kind {
      AwaitingConfirm::Probe => {
        // §8.1's conflict window opens at the FIRST probe packet that is sent,
        // and only a family that accepted the datagram sent one. Latched before
        // the phase check below because the window is a fact about the wire, not
        // about which phase the confirm found us in.
        if delivery.any_delivered() {
          self.probe_on_wire = true;
        }
        if let ServiceState::Probing(n) = self.state {
          let advance = classify_advance(&mut self.partial_rounds, delivery);
          if matches!(advance, PhaseAdvance::Partial | PhaseAdvance::Failed) {
            // §8.1: the probe did not reach every obligated link — do NOT
            // advance the sequence. Re-arm the SAME probe from post-send time so
            // it retries, rather than the service progressing toward Announcing
            // while a link that has never been asked might already hold the name.
            //
            // A RETRY, not an initial schedule: `probe_deadline(now, 0, ..)` would
            // hand probe 0 §8.1's random 0–250 ms *initial* delay, so a
            // partially-delivered probe 0 could go back on the wire less than
            // 250 ms after the copy that was delivered. The spacing is about
            // transmissions, so every re-arm owes `PROBE_INTERVAL` regardless of
            // index — see `probe_retry_deadline`.
            self.lifecycle_deadline = probe_retry_deadline(now);
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
              // Third probe confirmed (§8.1: exactly three) — but probing is NOT
              // over. §8.1 keeps the conflict window open for 250 ms past it:
              // "If, by 250 ms after the third probe, no conflicting Multicast
              // DNS responses have been received, the host may move to the next
              // step, announcing", and the deferral rule it states just above
              // runs "from the time the first probe packet is sent until 250 ms
              // after the third probe".
              //
              // `Probing(3)` is that settling window. Both conflict arms match
              // `Probing(_)`, so a peer's tentative probe still reaches the §8.2
              // tiebreak and a conflicting response still latches the §8.1
              // deferral — where flipping straight to `Announcing` sent the
              // first through the "we own this, defend it" return and the second
              // through §9's revert, and let two contenders whose third probes
              // are a few ms apart both announce.
              self.state = ServiceState::Probing(3);
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
              // Whatever §8.3 scheduling chose above, it may not bring the
              // announcement forward of §8.1's window — `FIRST_ANNOUNCE_DELAY`
              // is zero, so without this the settling state would end the moment
              // it began. A ladder rung further out than 250 ms already
              // satisfies §8.1 and is left alone.
              if let Some(settled) = now.checked_add_duration(schedule::rfc::PROBE_INTERVAL) {
                self.lifecycle_deadline = match self.lifecycle_deadline {
                  Some(d) if d > settled => Some(d),
                  _ => Some(settled),
                };
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
        // At least one obligated link accepted it → peers reachable over THAT
        // link may now hold these records, so latch goodbye ownership for
        // exactly what the encoder reported it emitted (a full announcement
        // carries all of PTR/SRV/TXT plus every host address), ON EXACTLY THE
        // FAMILIES THAT ACCEPTED IT. This is the ANY-delivered half of the
        // invariant pair and happens BEFORE the all-delivered phase check below:
        // partial delivery owns what it exposed even though it advances nothing
        // — and owns it only where it exposed it.
        self
          .goodbye
          // §8.3's unsolicited announcement is §6 multicast by construction.
          .record_emitted(&emitted, delivery.delivered_on(), SendClass::Multicast);
        // …and this generation has now claimed the name, which is what the
        // conflict rules key on. Ownership and CLAIM are different questions
        // over the same report — see `EmittedRecords::claims_instance_name` and
        // `generation_advertised`. (A full announcement always carries SRV and
        // TXT, so this is unconditional here in practice; it is written as the
        // shared predicate so the rule has one definition, not two.)
        self.generation_advertised |= emitted.claims_instance_name();
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
      AwaitingConfirm::Response(emitted, _kas_suppressed_count, class) => {
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
          self
            .goodbye
            .record_emitted(&emitted, delivery.delivered_on(), class);
          // …and this generation has claimed the name only if a record the
          // INSTANCE owns reached the wire. The two lines above and below are
          // deliberately different questions over the same report: goodbye
          // ownership counts every record a peer may now cache from us, INCLUDING
          // the shared service-type and subtype PTRs, while the §8 conflict rules
          // key on whether this name was claimed — which a shared PTR does not do.
          //
          // A §7.1 known-answer-filtered response CAN emit the shared PTRs alone
          // (a querier that already holds our SRV and TXT), and it is reachable
          // in `Announcing(0)` after a failed announcement. Counting that closed
          // `is_preauthoritative`'s window with no instance-owned record anywhere
          // on the link, and the next winning `ProbeProposal` was then dropped
          // unadjudicated — a §8.2 loss silently not taken.
          self.generation_advertised |= emitted.claims_instance_name();
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
          // Ownership only. A stale confirm belongs to the generation this
          // revert replaced, so it does NOT set `generation_advertised`: those
          // records are in peer caches (hence the latch) but the generation now
          // probing has claimed nothing, and §9 puts it back through §8's
          // startup steps regardless.
          StaleRecords::SameName { emitted, class } => {
            self
              .goodbye
              .record_emitted(&emitted, delivery.delivered_on(), class);
          }
          StaleRecords::OldName {
            records,
            emitted,
            class,
          } => {
            // The host name is invariant across an instance rename, so the
            // addresses this datagram carried are cached under a name the service
            // still holds: they latch into the live goodbye as usual.
            self
              .goodbye
              .record_host_emitted(&emitted, delivery.delivered_on(), class);
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
              // The §6.1 NSEC is owned by the OLD instance name too, so it
              // travels with the instance half rather than with the addresses.
              emitted.nsec(),
            );
            if instance.is_empty() {
              // §7.1 trimmed every instance record: the old name put nothing in
              // any peer cache, so it has nothing to withdraw.
              return;
            }
            // The old name's exposure is per family for the same reason the
            // live latch is: only the families that ACCEPTED this datagram put
            // these instance records in a peer cache, so only they owe the old
            // name's §10.1 goodbye and only they can hold an echo of it.
            let instance = per_family_instance(&instance, delivery.delivered_on());
            // …and its MULTICAST half is the same projection over a datagram
            // that actually went to the group, or nothing at all. A §6.7 legacy
            // reply parked across a rename put the old name's records in one
            // resolver's cache — so the detached goodbye still owes them — and
            // put no copy of them on the group, so no echo of them exists.
            let instance_multicast = match class {
              SendClass::Multicast => instance.clone(),
              SendClass::Unicast => [
                respond::EmittedRecords::default(),
                respond::EmittedRecords::default(),
              ],
            };
            match &mut self.rename_goodbye_handoff {
              Some(h) => {
                for (held, new) in h.owned.iter_mut().zip(&instance) {
                  held.merge_instance(new);
                }
                for (held, new) in h.multicast.iter_mut().zip(&instance_multicast) {
                  held.merge_instance(new);
                }
              }
              // The driver takes the handoff the instant it observes `Renamed`,
              // and a parked confirm lands after that by construction, so
              // installing a fresh one is the ordinary case rather than the
              // exception. Draining it is the drain contract documented above.
              None => {
                self.rename_goodbye_handoff = Some(RenameGoodbyeHandoff {
                  records,
                  owned: instance,
                  multicast: instance_multicast,
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
      Some(AwaitingConfirm::Announcement(e)) => (
        StaleWireFact::Announcement,
        // An unsolicited announcement is §6 multicast by construction.
        Some((e, SendClass::Multicast)),
      ),
      Some(AwaitingConfirm::Response(e, kas, class)) => (StaleWireFact::Response(kas), Some((e, class))),
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
          (StaleRecords::SameName { emitted, class }, Some(records)) => StaleRecords::OldName {
            records,
            emitted,
            class,
          },
          (records, _) => records,
        };
        self.awaiting_confirm = Some(AwaitingConfirm::Stale { fact, records });
        return;
      }
    };
    let records = match (emitted, renamed_from) {
      (None, _) => StaleRecords::None,
      (Some((emitted, class)), None) => StaleRecords::SameName { emitted, class },
      (Some((emitted, class)), Some(records)) => StaleRecords::OldName {
        records,
        emitted,
        class,
      },
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
  /// term is the TTL bound. Composing them subsumes the two separate re-arms
  /// this would otherwise need, each of which is wrong on its own:
  ///
  /// * an honest-partial re-arm that climbs the ladder to keep the served
  ///   family's spacing legal, but measures staleness per ROUND, so alternating
  ///   families each fall a full interval behind;
  /// * an excused re-arm that REPLACES `Established`'s pre-armed periodic
  ///   deadline with the earned rung so the missing family is not stranded a
  ///   whole refresh interval away. Under the composed rule a family in good
  ///   standing pulls the deadline in by itself, and one that has spent the
  ///   core's patience is deliberately not chased — chasing it is what floods
  ///   the healthy family at the one-second floor.
  ///
  /// `Established` is where the ladder retires: the announcement burst is over,
  /// the periodic refresh is the rate limit, and the ladder's cap was that same
  /// rate all along.
  fn arm_announcement(&mut self, now: I, advance: PhaseAdvance) {
    let ttl_secs = self.records.ttl_secs();
    let base = match self.state {
      ServiceState::Established => {
        // A non-announcing responder's §8.3 startup burst is its LAST
        // unsolicited traffic: peers' copies of the records are left to expire
        // at the TTL, after which the service is findable only by explicit
        // query.  No deadline means the lifecycle never fires again.
        if !self.re_announce {
          self.lifecycle_deadline = None;
          return;
        }
        re_announce_deadline(now, ttl_secs)
      }
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

  /// The per-family minimum gap of the datagram whose commit token is
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
  pub(crate) fn withdrawal_snapshot(&mut self) -> WithdrawalSnapshot {
    self.assert_no_live_commit_token("Service::withdrawal_snapshot");
    // Snapshot the CURRENT goodbye-ownership latch (the live name's records).
    // After a rename the current name is the freshly re-announced one, and its
    // confirmed instance + host records still need withdrawing; the OLD name is
    // handled separately as its own detached item.
    WithdrawalSnapshot {
      records: self.records.clone(),
      // Per family, and whole: each half carries that family's instance records
      // AND that family's host addresses, so the endpoint's goodbye debt and the
      // relinquished-RRset screen both read one exposure rather than reassembling
      // two.
      owned: self.goodbye.per_family(),
      // The screen's half, narrowed to what actually went to the group.
      multicast: self.goodbye.per_family_multicast(),
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
  pub(crate) fn take_rename_goodbye_handoff(&mut self) -> Option<RenameGoodbyeHandoff> {
    self.rename_goodbye_handoff.take()
  }

  /// Is this service's RFC 6762 §8 startup sequence PARKED — nothing armed,
  /// nothing queued, and nothing in flight?
  ///
  /// The one way to reach it is a clock that cannot represent a wait the
  /// protocol mandates: §8.1's five-second flood floor, or the ordinary probe
  /// interval at the very end of a bounded clock. Failing closed is the required
  /// answer there — every instant such a clock can name is sooner than the wait —
  /// so being stuck is what compliance looks like, and the whole of what is left
  /// is to say so rather than to look idle.
  ///
  /// It is DERIVED and not latched. Every conjunct is a fact about the service's
  /// own fields at the instant it is asked, so a flag would have to be spent at
  /// each of the several places a deadline is armed and could go stale at any of
  /// them — and the failure mode of a stale one is a service that reports itself
  /// parked forever, which is the very stall this exists to report.
  ///
  /// `Announcing`, `Established` and `Conflicting` are excluded because none of
  /// them owes a probe: a terminal state has nothing to schedule, and a service
  /// past its probe sequence re-arms from its own confirms. A pending transmit or
  /// a live commit token means there is work the driver has still to draw, so the
  /// service is not silent whatever its deadline says.
  fn startup_parked(&self) -> bool {
    self.lifecycle_deadline.is_none()
      && self.pending_transmits.iter().all(Option::is_none)
      && self.awaiting_confirm.is_none()
      && !self.probe_on_wire
      && matches!(
        self.state,
        ServiceState::Init | ServiceState::Probing(_)
      )
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
    // An unresolved conflict classification is due immediately too, and for a
    // stronger reason: until it is spent `poll_transmit` will not claim this
    // name, so a distant lifecycle deadline would stall the service rather than
    // merely delay a reply.
    if self.conflict_classified_unresolved() {
      return self.last_now;
    }
    // A PARKED startup sequence is due immediately as well, and this is the only
    // thing that keeps the caller awake for it. Nothing is armed, so every
    // deadline below is `None` and a driver that folded them would park on some
    // other producer — or sleep — and never call `handle_timeout` again, which is
    // where the park is reported. The wakeup is what turns a silent stall into a
    // repeating `HandleTimeoutError::Overflow`, and it stops of its own accord
    // the moment a deadline can be armed. See [`Self::startup_parked`].
    if self.startup_parked() {
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
  pub(crate) fn poll(&mut self) -> Option<ServiceUpdate> {
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
  /// [`RdataForm::FOLDED`](crate::wire::RdataForm::FOLDED) produces for a peer
  /// record, so a §9 conflict check can tell identical (consistent) rdata from a
  /// real conflict. SRV → priority+weight+port (BE) + lowercased wire-form host;
  /// TXT → length-prefixed segments; NSEC → see [`respond::our_nsec_identities`].
  ///
  /// The arms are EXACTLY the record types this service emits under its instance
  /// name, because that is what "identical to ours" can be true of. NSEC joined
  /// them when conflict routing widened past SRV/TXT: `write_announce` and
  /// `write_response` both ride an instance NSEC in the Additional section, so a
  /// byte-identical twin sends one too, and without this arm that twin's NSEC —
  /// alone, with matching SRV and TXT correctly screened out — read as a
  /// conflicting response and renamed us.
  ///
  /// A LIST, because one rtype can have more than one indistinguishable
  /// spelling: §9's rule is about proxies and fault-tolerance twins, which are
  /// required to be correct rather than to be this crate, and NSEC is a type
  /// where the two currently differ. See [`respond::our_nsec_identities`].
  ///
  /// Empty → we assert no record of this type at this name, which never matches
  /// a peer record: a peer record canonicalizes to at least one byte for every
  /// type. That is NOT the same as asserting a zero-length one.
  ///
  /// THE rule lives in [`respond::canonical_rdata_forms`], over a bare
  /// `&ServiceRecords`, because the endpoint asks the same question of record
  /// sets this endpoint has RELINQUISHED — sets no live `Service` holds. This is
  /// the `Service`-shaped door onto it, not a second copy.
  fn our_canonical_records_for(
    &self,
    rtype: crate::wire::ResourceType,
  ) -> std::vec::Vec<std::vec::Vec<u8>> {
    respond::canonical_rdata_forms(&self.records, rtype)
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
    self.meta_known_answered = None;
  }

  /// clear the state that is about a NAME, on a conflict-driven RENAME. The NEW
  /// instance name has not been announced, so the instance goodbye must not fire
  /// for it (host ownership persists — the host name is unchanged).
  ///
  /// ONLY the per-NAME facts. Everything about the probing GENERATION —
  /// `probe_on_wire`, both §8 latches, `generation_advertised`, `partial_rounds`,
  /// the response cycle — belongs to [`Service::restart_probe_cycle`], which
  /// every regress path runs including this one, and which a rename calls just
  /// before this. Setting them in both places is harmless while the two agree,
  /// and is exactly the drift that makes a regress path's post-state hard to
  /// reason about, so each fact has one owner. The test for whether
  /// something belongs here: would a SAME-name regress (§9's revert, §8.2's
  /// deferral) want it? If yes it is the generation's, not the name's —
  /// `fully_announced` is the canonical example of one that is genuinely the
  /// name's.
  fn reset_advertised_name_state(&mut self) {
    self.goodbye.reset_instance();
    // The NEW name has announced nothing, so it cannot yet supersede the old
    // name's in-flight goodbye — the reclaim-cancel gate must re-earn its `true`.
    self.fully_announced = false;
    // A fresh name restarts the §8.3 announcement sequence at the bottom rung.
    self.partial_announce_streak = 0;
    // The NEW name has been announced to nobody, so no family is owed a refresh
    // of it. Each is re-anchored by its first announcement round under this name.
    self.last_delivered = [None, None];
  }

  /// whether `record` (an A/AAAA owned by our host name) carries an
  /// address WE advertise — CONSISTENT rdata (our own multicast echo, or another
  /// instance correctly sharing the host), which RFC 6762 §9 makes no conflict
  /// at all.
  ///
  /// FOUR answers, not two, and the body says why each of the other three is
  /// not `Different`: an address we hold is `Identical`, LINK-LOCAL INCLUDED;
  /// rdata that will not decode is `Invalid`; an RRtype we publish no record of
  /// at this name is `UnownedRrtype`; and only a decodable address we do not
  /// hold is `Different`.
  ///
  /// It does not assume the record came from a peer. A self-echo DOES reach
  /// here — [`Provenance::OwnEchoLikely`](crate::Provenance::OwnEchoLikely)
  /// adjudicates — and an echo of what this service still publishes answers
  /// `Identical` by this test, rather than by any upstream suppression.
  fn classify_host_rdata(&self, record: &crate::wire::Ref<'_>) -> PeerRdata {
    match record.rdata_view() {
      // A LINK-LOCAL CARVE-OUT USED TO LIVE HERE, and it was wrong. Matching
      // link-local addresses were reported as conflicts on the reasoning that
      // "the same raw address on a different interface is a real conflict". But
      // on the SAME link an identical address is exactly what §9 excludes, and
      // across DIFFERENT links a link-local address is not routable, so no
      // observer sees a collision either way. It cost a terminal, caller-visible
      // retirement in precisely the fault-tolerance case §9 exists to protect.
      //
      // What would have to exist for it to return: per-address interface scope
      // on `ServiceRecords`, so "we advertise fe80::1 on eth0" could be
      // distinguished from "a peer advertises fe80::1 on wlan0". `ServiceRecords`
      // cannot express that today, and adding it belongs with host-name
      // ownership (#92) rather than here. Carrying `interface_index` through
      // `HostConflict` alone would not help: without per-address scope on OUR
      // side there is nothing to compare it against.
      //
      // PER RRTYPE, because §9's conflict is "the same name, RRTYPE and rrclass,
      // but inconsistent rdata". An IPv4-only service holds no AAAA RRset at its
      // host name and an IPv6-only one holds no A RRset, so the other family's
      // record is not that service's record at all — `contains` over an empty
      // slice answers "differing" for it, which is how a same-host sibling's
      // first announcement retired a service over an address it never published.
      Ok(crate::wire::Rdata::A(a)) => {
        let ours = self.records.a_addrs_slice();
        if ours.is_empty() {
          PeerRdata::UnownedRrtype
        } else {
          PeerRdata::from_identical(ours.contains(&a.addr()))
        }
      }
      Ok(crate::wire::Rdata::AAAA(a)) => {
        let ours = self.records.aaaa_addrs_slice();
        if ours.is_empty() {
          PeerRdata::UnownedRrtype
        } else {
          PeerRdata::from_identical(ours.contains(&a.addr()))
        }
      }
      // Rdata that will not parse tells us NOTHING about whether it conflicts,
      // so it must not be reported as differing — that is a terminal
      // `HostConflict` driven by a record nobody could read.
      Err(_) => PeerRdata::Invalid,
      // A readable non-address type at the host name: the host arm's own rtype
      // gate decides what to do with it.
      Ok(_) => PeerRdata::Different,
    }
  }

  /// Whether an authoritative RESPONSE carries exactly the rdata this service
  /// already proposes for that rtype — RFC 6762's "not a conflict at all".
  ///
  /// §9 states the rule as a property of the records rather than of any phase:
  /// "resource records with identical rdata are never considered inconsistent,
  /// even if they originate from different hosts. This is to permit use of
  /// proxies and other fault-tolerance mechanisms that may cause more than one
  /// responder to be capable of issuing identical answers on the network."
  /// §8.2.1 says the same thing about the probing path — two devices advertising
  /// identical sets is "sometimes done for fault tolerance, and there is, in
  /// fact, no conflict".
  ///
  /// A malformed or unparseable record is NOT ours: it falls through to the
  /// matrix, whose arms drop it.
  ///
  /// No rtype pre-screen. Which types can be "ours" is
  /// [`Service::our_canonical_records_for`]'s question, and it answers it by
  /// enumerating what this service actually emits at its instance name; a type
  /// it does not emit yields no forms at all, which no peer record equals. A
  /// screen here would be a second, independently-maintained copy of that list —
  /// and when conflict routing widened past SRV/TXT it was the copy that went
  /// stale, so a twin's identical instance NSEC read as a conflicting response.
  fn classify_instance_rdata(&self, record: &crate::wire::Ref<'_>) -> PeerRdata {
    let rtype = record.rtype();
    // NOT `Different`. A record whose rdata will not decode is one this service
    // cannot reason about at all, and reporting it as differing is what made a
    // malformed SRV response a real §8.1 probe defeat.
    //
    // `canonical_rdata_folded` is THE decoder — the same one §8.2's fold runs,
    // under a different `RdataForm`. That is what keeps this answer and the
    // tiebreak's agreeing about which records are readable at all: while the two
    // paths held separate serializers, an undecodable NS at this name abandoned
    // the §8.2 comparison but reached here as ordinary DIFFERING rdata, and
    // differing rdata at a name we are probing is an §8.1 defeat.
    let Ok(peer_canonical) = record.canonical_rdata_folded() else {
      return PeerRdata::Invalid;
    };
    let ours = self.our_canonical_records_for(rtype);
    // NO FORMS means "we assert no record of this type at this name", which is
    // not the same as "we assert a zero-length one" — and a peer CAN send
    // zero-length rdata for an unknown type, whose identity bytes are also
    // empty. Without this, that record would compare equal to nothing at all and
    // be waved through as ours.
    PeerRdata::from_identical(ours.iter().any(|form| form.as_slice() == &*peer_canonical))
  }

  /// THE one way this service re-enters RFC 6762 §8's startup steps.
  ///
  /// Three rules send it back there: §9's revert-to-probe, §8.2's one-second
  /// deferral, and §8.1's rename. Each REPLACES the current generation, and
  /// "replaced" is a conjunction of a dozen facts rather than a state name — so
  /// while each site spelled the conjunction out for itself, each site could
  /// omit a different conjunct, and they did. The §8.2 deferral alone was found
  /// incomplete three separate times: once for not clearing the response cycle,
  /// once for not staling the live commit token, once for a queued probe that
  /// outran it.
  ///
  /// An assertion over the conjuncts was the first fix and is kept — as this
  /// function's single exit check — but it is not the fix. It catches a missing
  /// conjunct in a test that happens to drive the path; this makes a conjunct
  /// impossible to miss, because a caller has none to spell. A FOURTH regress
  /// path added later gets the whole set by construction.
  ///
  /// It is also where RFC 6762 §8.1's flood limit is APPLIED, for the same
  /// reason: all three rules are conflict-driven probe attempts, this is where
  /// each one gets its start time, and a fourth added later inherits the limit
  /// without knowing it exists. The limit is not COUNTED here — the endpoint
  /// counted the conflict at receipt, in the same borrow that classified it, so
  /// by the time a regress runs the verdict is already final. See
  /// [`ConflictFlood`] and [`CONFLICT_BURST_LEN`].
  ///
  /// What every caller passes, and nothing else:
  ///
  /// * `now` — the instant the conflict is being RESOLVED at. It becomes this
  ///   sequence's `sequence_started_at` and anchors the deadline arithmetic,
  ///   including §8.1's five-second floor.
  /// * `deadline` — when the fresh §8.1 sequence may begin, IF the flood limit
  ///   is not in force; when it is, the later of this and `now +
  ///   CONFLICT_BACKOFF_MIN_WAIT`. §9 and a rename pass the randomized
  ///   `probe_deadline`; §8.2's loser passes `now + TIEBREAK_DEFER_WAIT`, which
  ///   is the one second it "defers to the winning host by waiting".
  /// * `renamed_from` — `Some(old records)` ONLY when the name is changing, so a
  ///   parked datagram's confirm latches ownership under the name it actually
  ///   advertised. `None` for the two SAME-name regressions, where ownership
  ///   latches exactly as it would have without the regression.
  ///
  /// Callers keep only what is genuinely their own: §9 also stamps
  /// `last_conflict_reprobe` (its own rate limit), and a rename also calls
  /// `set_instance` and `reset_advertised_name_state` (per-advertised-NAME state,
  /// which a same-name regression must NOT reset — see `fully_announced`).
  /// Returns `Err(HandleTimeoutError::Overflow)` when the clock could not
  /// represent the wait §8.1 owes and the sequence was therefore parked with no
  /// deadline — the fail-closed outcome, reported rather than left to look like
  /// ordinary idleness. See [`Service::apply_backoff_floor`].
  fn restart_probe_cycle(
    &mut self,
    now: I,
    deadline: Option<I>,
    renamed_from: Option<ServiceRecords>,
    flood: &ConflictFlood<I>,
  ) -> Result<(), HandleTimeoutError> {
    // A parked datagram belongs to the generation this regress replaces, so its
    // confirm must not advance the fresh §8.1 sequence: `Init → Probing(0)` costs
    // no datagram, so an old probe confirming into it would claim the name after
    // TWO probes on the wire where §8.1 requires three. Taken FIRST, while
    // `self.records` still names the generation being replaced — by confirm time
    // nothing else says which name its records went out under.
    self.stale_live_commit_token(renamed_from);
    self.state = ServiceState::Init;
    self.probe_count = 0;
    self.announce_count = 0;
    // §8.1's window is SHUT again. Its rule is scoped to "the first probe packet"
    // of the sequence it introduces, not to the first one this name ever sent, so
    // a conflicting response arriving before the restarted sequence reaches the
    // wire is one §8.1 requires be ignored.
    self.probe_on_wire = false;
    // Both classifications are spent by definition: this regress IS their
    // resolution, and leaving one live would re-fire it against the fresh
    // sequence — and keep `poll_transmit` withholding forever.
    //
    // Today's two callers have already spent them before arriving here
    // (`handle_timeout` takes them to decide WHICH regress this is; §9's arm is
    // only reachable when neither is set), so this pair is the one conjunct no
    // mutation probe can currently observe. It stays anyway, and that is the
    // whole argument for a single regress operation: a caller added later
    // inherits the complete post-state without having to know it must spend a
    // latch first. `assert_generation_replaced` is what holds the line.
    self.probe_defeated = false;
    self.tiebreak_lost = false;
    // This generation has advertised nothing, however loudly the one it replaces
    // did. `goodbye` deliberately still owns what reached peer caches; these are
    // different questions (see `generation_advertised`).
    self.generation_advertised = false;
    self.pending_transmits = [None, None];
    self.response_deadline = None;
    // A fresh §8.1 sequence: patience already spent waiting for a lagging link
    // must not excuse a probe of the sequence that replaces it.
    self.partial_rounds = [FamilyPatience::default(); 2];
    // …and we must not ANSWER for a name that is back under verification.
    // `pending_legacy` is drained by `poll_transmit` ahead of every state check,
    // so a §6.7 reply queued while announcing would otherwise put the full
    // positive-TTL record set on the wire during the regress.
    self.clear_response_cycle_state();
    // A fresh §8 sequence starts HERE, so §8.1's five-second floor is anchored
    // here: "If fifteen conflicts occur within any ten-second period, then the
    // host MUST wait at least five seconds before each successive additional
    // probe attempt." The caller's schedule is a FLOOR away from, never a
    // ceiling on, what it asked for — §8.2's one-second deferral is still owed
    // in full, it is simply not enough on its own once the limit is in force.
    self.sequence_started_at = now;
    self.lifecycle_deadline = self.apply_backoff_floor(now, deadline, flood);
    #[cfg(debug_assertions)]
    self.assert_generation_replaced();
    if self.lifecycle_deadline.is_none() {
      return Err(HandleTimeoutError::Overflow);
    }
    Ok(())
  }

  /// Raise a sequence's start time to RFC 6762 §8.1's five-second floor when the
  /// endpoint's flood limit is in force — and arm NOTHING when the clock cannot
  /// represent that floor.
  ///
  /// # An ABSOLUTE floor, anchored to the sequence
  ///
  /// The floor is `sequence_started_at + CONFLICT_BACKOFF_MIN_WAIT`, not
  /// `now + CONFLICT_BACKOFF_MIN_WAIT`, because this is consulted at more than
  /// one instant in one sequence: the regress that starts it, and again at the
  /// commit point where the first probe would go out. A relative floor
  /// re-evaluated at the second point would push the probe five seconds further
  /// out every time it was consulted, so a service whose flood never quite stops
  /// would never probe at all. An absolute one converges — once `now` has
  /// reached it the wait is served and the deadline passes through untouched —
  /// which bounds the deferral to one re-arm per arm. At the regress the two
  /// agree, because the regress sets `sequence_started_at = now` first.
  ///
  /// # Failing closed is the whole of the overflow rule
  ///
  /// [`crate::Instant`] returns `Option` from `checked_add_duration`, so a
  /// BOUNDED clock is part of the contract this crate publishes, not a
  /// pathological case — a wrapping millisecond counter is an ordinary choice
  /// for a bare-metal driver, and a bare-metal driver is where an unthrottled
  /// flood costs the most. When the floor does not exist on that clock, every
  /// instant the clock CAN express is sooner than the wait §8.1 mandates. There
  /// is therefore no deadline this may legally arm, and `None` — do not
  /// schedule, do not transmit — is the only answer that is never sooner than
  /// the floor.
  ///
  /// What it must NOT do is retain the caller's deadline as a consolation. That
  /// is at most 250 ms out on the rename and §9 paths and about a second on
  /// §8.2, so it discarded the MUST at exactly the moment the limiter existed to
  /// hold one back.
  ///
  /// Saturating to the furthest representable instant is not the fix either, and
  /// was considered: at the end of the clock that instant can be `now` itself,
  /// which schedules the probe immediately — the flood, arriving by the door
  /// meant to stop it.
  ///
  /// Read-only in every sense: the ring belongs to the endpoint and this only
  /// reads its verdict, and the verdict is re-derived per read, so a quiet
  /// window that has already released the latch is never observed as in force.
  ///
  /// This never DEFERS a sequence the limit is not holding: with the limit off
  /// the caller's deadline is returned untouched, overflow and all.
  fn apply_backoff_floor(
    &self,
    now: I,
    deadline: Option<I>,
    flood: &ConflictFlood<I>,
  ) -> Option<I> {
    if !flood.in_force(now) {
      return deadline;
    }
    let floor = self
      .sequence_started_at
      .checked_add_duration(CONFLICT_BACKOFF_MIN_WAIT)?;
    Some(match deadline {
      Some(d) => d.max(floor),
      // Unreachable while every caller's own wait is shorter than the floor —
      // a clock that cannot express `start + 1 s` cannot express `start + 5 s`
      // either — and correct if one ever is not.
      None => floor,
    })
  }

  /// May a conflict carried by `datagram` be COUNTED against RFC 6762 §8.1's
  /// flood limit? Decided once per datagram, at the first conflict it produces,
  /// and re-read for every later record of it.
  ///
  /// See [`Service::flood_eligibility`] for why the answer belongs to the
  /// datagram rather than to each record.
  fn flood_eligible(&mut self, datagram: DatagramId) -> bool {
    match self.flood_eligibility {
      Some((seen, eligible)) if seen == datagram => eligible,
      _ => {
        let eligible = self.probe_on_wire;
        self.flood_eligibility = Some((datagram, eligible));
        eligible
      }
    }
  }

  /// RFC 6762 §8.1's five-second floor, applied at the WIRE COMMIT BOUNDARY —
  /// the last point a queued first probe can still be held back.
  ///
  /// # Why a third application, and why this one is final
  ///
  /// The floor is applied where a fresh sequence is SCHEDULED
  /// ([`Service::apply_backoff_floor`]) and again where a probe is ENQUEUED
  /// ([`Service::handle_timeout`]'s commit-point check). Neither is the wire. A
  /// probe enqueued while the limit was off survives the `Endpoint::handle` that
  /// folds in the fifteenth conflict of a burst — a conflict about some OTHER
  /// record set, since §8.1 counts for the whole host — and the latch that
  /// engages there is one the queued datagram was never tested against. The
  /// probe would then leave inside the five seconds §8.1 mandates while breaking
  /// no documented contract, which is what the endpoint-wide limit's "exact, not
  /// best-effort" claim rules out.
  ///
  /// `Endpoint::poll_service_transmit` is where the datagram is handed to the
  /// caller for sending, so it is where the last test belongs; there is no later
  /// point, and this check does not move again.
  ///
  /// # First probes only, and the floor stays ABSOLUTE
  ///
  /// Only while `!probe_on_wire`: §8.1 spaces the START of each successive probe
  /// SEQUENCE, not the packets inside one already committed to. The floor is
  /// `sequence_started_at + CONFLICT_BACKOFF_MIN_WAIT`, never `now + …`,
  /// because this point is reached repeatedly while the limit holds — a relative
  /// floor re-derived here would push the probe five seconds further out at
  /// every poll and a service under a persistent flood would never probe at all.
  /// An absolute one converges: once `now` has reached it the wait is served and
  /// the probe goes out.
  ///
  /// # It cannot strand the commit token
  ///
  /// This runs BEFORE [`Service::poll_transmit`] stamps anything and refuses to
  /// act while a token is live, so the deferral never leaves the single commit
  /// slot outstanding and the documented poll → confirm → poll ordering is
  /// untouched. The queued probe is DROPPED rather than parked at the head of
  /// the queue: every datagram this crate emits is re-encoded from live state on
  /// the next poll, so re-arming costs only the re-encode, while a probe left in
  /// slot 0 would also block the entry behind it.
  ///
  /// # A clock that cannot represent the floor PARKS the sequence
  ///
  /// The probe is dropped and no deadline is armed, which is the required
  /// fail-closed outcome: every instant such a clock can name is sooner than the
  /// wait §8.1 mandates. What that must not be is SILENT. This method returns no
  /// error, so the report is left to the two methods that can make one —
  /// [`Service::poll_timeout`], which reports a parked sequence as due
  /// immediately so the caller keeps coming back, and
  /// [`Service::handle_timeout`], which re-evaluates the floor and returns
  /// [`HandleTimeoutError::Overflow`] for as long as it cannot be armed.
  ///
  /// Leaving the existing deadline alone is not enough on its own, and that was
  /// the defect: the enqueue arm queues the probe FIRST and only then assigns
  /// `probe_deadline(..)`, which is itself `None` at the end of a bounded clock.
  /// Dropping the probe then removed the service's only pending work from a
  /// `Probing` state with no deadline behind it, and nothing woke the caller
  /// again — not even after the flood expired. See [`Service::startup_parked`],
  /// which is the state this leaves and the state both reports read.
  pub(crate) fn defer_first_probe_under_flood(&mut self, now: I, flood: &ConflictFlood<I>) {
    if self.awaiting_confirm.is_some()
      || self.probe_on_wire
      || !matches!(self.peek_pending(), Some(PendingTransmitKind::Probe))
      || !flood.in_force(now)
    {
      return;
    }
    match self
      .sequence_started_at
      .checked_add_duration(CONFLICT_BACKOFF_MIN_WAIT)
    {
      Some(floor) if floor > now => {
        let _ = self.pop_pending();
        self.lifecycle_deadline = Some(floor);
        debug!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          "service: §8.1 flood limit latched after this probe was queued — \
           dropping it and re-arming to the sequence's five-second floor"
        );
      }
      // The wait has been served: the probe goes out on this poll.
      Some(_) => {}
      None => {
        let _ = self.pop_pending();
      }
    }
  }

  /// Make this service INERT for the RFC 6762 §10.1 withdrawal about to begin:
  /// discard every queued positive-TTL datagram and every deadline that could
  /// produce one.
  ///
  /// The goodbye is the endpoint's own withdrawal item, not this queue, and it
  /// is the only thing this name may still put on a link. Anything left here is
  /// a positive-TTL claim to a name whose goodbye SNAPSHOT has already been
  /// taken, so transmitting it would place records in peer caches that no
  /// goodbye can ever retract — they would sit there until their own TTL ran
  /// out. The §6.7 legacy queue goes too: a legacy reply is the FULL positive
  /// record set, as much a claim to the name as an announcement.
  ///
  /// Called from `Endpoint::begin_withdrawal`, where `withdrawing` is set. From
  /// that point the endpoint's own accessors refuse to drive this service at all,
  /// so this leaves no state that is merely unreachable — it leaves none.
  pub(crate) fn quiesce_for_withdrawal(&mut self) {
    self.pending_transmits = [None, None];
    self.lifecycle_deadline = None;
    self.response_deadline = None;
    // `pending_legacy`, the KAS ring, the questioner sets and the §9 meta-reply
    // deadline, in the one place that owns clearing them.
    self.clear_response_cycle_state();
  }

  /// The post-state [`Service::restart_probe_cycle`] owes, checked as a SET on
  /// the way out of it.
  ///
  /// Kept after the callers were unified, because it is what makes the
  /// unification self-checking: the conjuncts are established in one place, and
  /// this asserts that place established all of them. It is the guard against
  /// the NEXT edit to that function, not against its callers — they can no
  /// longer omit anything.
  ///
  /// 1. the lifecycle is back at the start — `Init`, no probes or announcements
  ///    counted;
  /// 2. §8.1's window is SHUT;
  /// 3. no classification is left live — both latches spent, or this transition
  ///    would immediately re-fire and `poll_transmit` would withhold forever;
  /// 4. the transmit queue is empty, so nothing the replaced generation
  ///    scheduled can still be drained;
  /// 5. no response is scheduled for a name that is back under verification;
  /// 6. this generation has advertised nothing;
  /// 7. any datagram still awaiting a confirm has been STALED, so its confirm
  ///    lands as a wire fact and never as a lifecycle advance of the fresh
  ///    sequence — except a `MetaResponse`, which never had a lifecycle meaning
  ///    to void: the RFC 6763 §9 meta-PTR is shared, claims nothing about this
  ///    instance, and its confirm only counts `responses_tx`;
  /// 8. the service is still on a clock — a regress that armed no deadline would
  ///    strand it — UNLESS the clock cannot represent the wait §8.1's flood
  ///    limit owes, in which case arming nothing is the REQUIRED outcome and
  ///    being stranded is what failing closed looks like. The disjunct is the
  ///    rule, not a hole in it: without it, a bounded clock reaching its end
  ///    turns network input into a debug-build panic. See
  ///    [`Service::apply_backoff_floor`].
  ///
  /// Debug-only: these are internal consistency facts and a release build pays
  /// nothing for them. `cargo test` builds with debug assertions on, so every
  /// test that drives any regress path checks the whole set.
  #[cfg(debug_assertions)]
  fn assert_generation_replaced(&self) {
    debug_assert_eq!(self.state, ServiceState::Init, "regress: state");
    debug_assert_eq!(self.probe_count, 0, "regress: probe_count");
    debug_assert_eq!(self.announce_count, 0, "regress: announce_count");
    debug_assert!(!self.probe_on_wire, "regress: probe_on_wire");
    debug_assert!(
      !self.conflict_classified_unresolved(),
      "regress: a classification is still live"
    );
    debug_assert!(
      self.pending_transmits.iter().all(Option::is_none),
      "regress: queued transmit"
    );
    debug_assert!(
      self.response_deadline.is_none(),
      "regress: scheduled response"
    );
    debug_assert!(
      !self.generation_advertised,
      "regress: the replaced generation's claim is still latched"
    );
    debug_assert!(
      self.awaiting_confirm.as_ref().is_none_or(|c| matches!(
        c,
        AwaitingConfirm::Stale { .. } | AwaitingConfirm::MetaResponse
      )),
      "regress: a live commit token still carries lifecycle meaning"
    );
    debug_assert!(
      self.lifecycle_deadline.is_some()
        || self
          .sequence_started_at
          .checked_add_duration(CONFLICT_BACKOFF_MIN_WAIT)
          .is_none(),
      "regress: no lifecycle deadline"
    );
  }

  /// Will the next [`Service::handle_timeout`] RENAME this service?
  ///
  /// Read by the endpoint one statement before it drives that timeout, so the
  /// instance names the rename must avoid can be collected from the route table
  /// while the route holding this service is not yet mutably borrowed — and on
  /// no other tick, since collecting them costs a clone per live route.
  ///
  /// It is the §8.1 defeat latch and nothing else: a §8.2 loss re-probes the
  /// SAME name and a §9 revert re-verifies it, so neither needs a free one.
  #[inline(always)]
  pub(crate) const fn rename_imminent(&self) -> bool {
    self.probe_defeated
  }

  /// Whether a conflict has been CLASSIFIED pre-authoritative and not yet
  /// resolved — the stored witness that connects the classification in
  /// [`Service::handle_event`] to the decision in [`Service::handle_timeout`].
  ///
  /// The two sites must not re-derive [`Service::is_preauthoritative`]
  /// independently: state moves between them, so the same predicate at two
  /// sites is not the same answer. A queued announcement is enough to make them
  /// disagree — pass one closes §8.1's settling window, pass two queues the
  /// first announcement, drains the conflicting response that sets a latch, then
  /// transmits and confirms that announcement; by the next timeout the service
  /// is advertised, a re-derived predicate is false, and the existing owner's
  /// response is silently never spent. So the latches themselves ARE the
  /// classification, and they are spent on their own terms.
  ///
  /// While one is live, [`Service::poll_transmit`] emits NOTHING from the queue
  /// — announcement, question response, legacy reply, and probe alike. Claiming
  /// a name whose ownership is under adjudication is what turns an unresolved
  /// conflict into two owners, and a §8.2 loser owes a full second of silence
  /// before it may probe again, so the queue pauses whole rather than by kind.
  /// The shared §9 meta-PTR is unaffected: it asserts nothing about this
  /// instance.
  fn conflict_classified_unresolved(&self) -> bool {
    self.probe_defeated || self.tiebreak_lost
  }


  /// Whether this name is still PRE-AUTHORITATIVE: rows A and B of the §8
  /// conflict matrix on [`Service::handle_preauthoritative_conflict`].
  ///
  /// True while nothing of this name has been announced — so RFC 6762 §9's
  /// "has a unique record for which it is currently authoritative" is false and
  /// §8.1/§8.2 still govern. `Announcing(0)` qualifies because §8.1's settling
  /// window exits on a TIMEOUT while conflicts arrive on RX, and the four
  /// drivers order those two differently (`hick-compio` randomizes it per
  /// iteration), so keying on the state name alone would make the decision a
  /// function of the driver's loop.
  ///
  /// Used by BOTH the classification in [`Service::handle_event`] and the
  /// decision site in [`Service::handle_timeout`] that spends the latches it
  /// sets. They must agree: classifying a conflict as §8.1/§8.2 and then
  /// declining to spend its latch loses the conflict entirely.
  fn is_preauthoritative(&self) -> bool {
    match self.state {
      ServiceState::Init | ServiceState::Probing(_) => true,
      ServiceState::Announcing(0) => {
        !self.generation_advertised && self.awaiting_confirm.is_none()
      }
      _ => false,
    }
  }

  /// Resolve a conflict on a name this service has NOT yet put in any peer's
  /// cache, under RFC 6762 §8.1 and §8.2.
  ///
  /// # The precondition, before the table
  ///
  /// **Identical rdata is never a conflict, in any phase.** §9: "resource
  /// records with identical rdata are never considered inconsistent, even if
  /// they originate from different hosts. This is to permit use of proxies and
  /// other fault-tolerance mechanisms that may cause more than one responder to
  /// be capable of issuing identical answers on the network." §8.2.1 says it for
  /// the probing path too.
  ///
  /// It is checked once in [`Service::handle_event`], above the dispatch, and
  /// deliberately NOT as a column of the table below. The rule went missing
  /// three separate times — the §8.2.1 tie, the §9 post-establishment path, and
  /// the probing path — precisely because it was restated per-arm; a rule that
  /// keeps going missing in individual arms is one that wants stating above
  /// them. Splitting each `AuthoritativeResponse` cell into consistent and
  /// inconsistent halves would restate it four times and leave the fifth arm
  /// free to forget it again.
  ///
  /// It screens RESPONSES only. A tentative probe's records are §8.2.1's input
  /// as a LIST, and dropping members would hand the comparator a list the peer
  /// never proposed; the fold already answers "identical lists" with "no
  /// conflict". Host records have the same rule with a documented
  /// exception — see [`Service::host_record_is_ours`], where a link-local
  /// address is scope-ambiguous and is surfaced rather than screened.
  ///
  /// # The §8 conflict matrix
  ///
  /// Read with the precondition above already applied: every cell below is
  /// about a record whose rdata DIFFERS from ours (or, for a tentative probe, a
  /// proposal that may or may not tie as a whole list).
  ///
  /// The whole table, because an unenumerated cell is a cell decided by
  /// accident. The rows are the only three phases that change a decision, and
  /// they are named by what is TRUE OF THE WIRE rather than by the state enum,
  /// because that is what each RFC rule actually keys on — a state name drifts
  /// from it.
  ///
  /// The two instance columns are two TYPES, not two values of one field: a
  /// peer's tentative proposal arrives as `ProbeProposal` carrying a whole
  /// Authority Section, and an authoritative record arrives as `ProbeConflict`.
  /// The rules take different units of input, so they take different events, and
  /// a partial proposal is unrepresentable rather than screened for.
  /// `ConflictOrigin` survives only on `HostConflict`, whose shape is per record.
  ///
  /// | phase | instance / `ProbeProposal` (§8.2) | instance / `ProbeConflict` (response) | host / TentativeProbe | host / AuthoritativeResponse |
  /// |---|---|---|---|---|
  /// | **A. nothing of ours on the link** (`Init`/`Probing(_)`, `!probe_on_wire`) | §8.2: buffer the proposal | §8.1: silently ignore — "responses received *before* the first probe packet is sent MUST be silently ignored" | ignore (filed gap) | §9: surface terminal `HostConflict` |
  /// | **B. probed, nothing announced** (`Init`/`Probing(_)`, or `Announcing(0)` with no announcement latched or in flight) | §8.2: buffer the proposal | §8.1: defer to the existing host, `probe_defeated` → rename. No comparison. History-labelled: §8.2's regress instead — see below | ignore (filed gap) | §9: surface terminal `HostConflict` |
  /// | **B′. previous generation advertised, current one re-probing** (§9 revert: `goodbye.any_instance()` but `!generation_advertised`) | §8.2: buffer the proposal | §8.1: defer → rename; history-labelled as row B | ignore (filed gap) | §9: surface terminal `HostConflict` |
  /// | **C. advertised** (`generation_advertised`) | not §9 — defend by answering the probe's own question (§8.1) | §9: revert to probing; the history label buys no exemption | ignore (filed gap) | §9: surface terminal `HostConflict` |
  /// | **D. terminal** (`Conflicting`) | ignore | ignore | ignore | §9: surface terminal `HostConflict` — see below |
  ///
  /// # Row D's host column is NOT "ignore"
  ///
  /// The `HostConflict` arm is `(_, ServiceEvent::HostConflict(hc))` — a
  /// wildcard state, gated only by the [`ConflictOrigin`](crate::event::ConflictOrigin)
  /// test — so a `Conflicting` service surfaces the terminal update like any
  /// other.
  ///
  /// `Conflicting` is the INSTANCE name's terminal state and nothing else. It is
  /// entered from exactly one place — when §8.1's rename cannot produce a valid
  /// suffixed name — and says nothing whatever about the HOST name, which is a
  /// different name, invariant across renames, and shareable with other local
  /// services. Whether a peer is claiming it is an independent fact, and one a
  /// caller told to "rename and restart" needs: re-registering under a fresh
  /// instance name with the same host walks straight back into it.
  ///
  /// Making it "ignore" would also put a lifecycle dependence into the ONE
  /// column that has none. The host name is never probed here, so
  /// `is_preauthoritative` has nothing to say about it and rows A through C
  /// already answer identically; row D would become the sole exception, to save
  /// a duplicate that is benign anyway — `pending_updates` is a set, and a
  /// caller already told about this service is not told twice.
  ///
  /// # The history label crosses the table, and does NOT read the same in every cell
  ///
  /// A `ProbeConflict` may carry [`crate::event::ConflictHistory::Relinquished`]:
  /// its rdata repeats a set this endpoint recently transmitted and gave up. The
  /// label is a FACT the endpoint alone can state and a DECISION only this table
  /// can make, because what a match licenses depends entirely on what the cell
  /// would otherwise do:
  ///
  /// | cell | with the label | why |
  /// |---|---|---|
  /// | **B / B′, instance `ProbeConflict`** | §8.2's regress instead of §8.1's rename — `tiebreak_lost`, one second, SAME name | reversible, and the re-probe is the only thing that can tell a ghost from a twin |
  /// | **C, instance `ProbeConflict`** | nothing — §9's revert runs exactly as it would unlabelled | that revert already IS the re-verification: same name, rate-limited, reversible. Dropping it instead consumes a conforming peer's whole BOUNDED §8.3 burst inside the window, and nothing replays a conflict at expiry |
  /// | **any host / AuthoritativeResponse** | the `HostConflict` is dropped, in the router | terminal and caller-visible, and the HOST NAME is never probed — there is no re-probe whose silence could convict a ghost |
  ///
  /// The last row drops an EVENT, not a record. Where a route's instance name IS
  /// its host name the router tests the host rule first but does not let it
  /// consume a labelled A/AAAA: the record is also a member of the §8.2 proposal
  /// this service is probing with, so it falls through and arrives as a labelled
  /// `ProbeConflict`, read by rows B / B′ and C exactly as the table says. Only
  /// the unlabelled record is the host rule's alone.
  ///
  /// AND IT FALLS THROUGH WEARING BOTH ROLES —
  /// [`ConflictRole::InstanceAndHost`](crate::event::ConflictRole) — because the
  /// last row's own reason does not reach this owner. It suppresses on the
  /// premise that nothing can re-verify a labelled host record, and that premise
  /// is FALSE where the host name is also the instance name: `write_probe` asks
  /// ANY for exactly this owner and proposes exactly these A/AAAA, so the
  /// re-probe the host cell lacks is the one this service already runs. The role
  /// is what carries the host rule's proven authority across the fall-through,
  /// and two gates read it:
  ///
  /// * the identical-rdata precondition classifies the record as a HOST record,
  ///   so an address this service publishes is §9's "never inconsistent" rather
  ///   than a conflict the instance classifier cannot even read;
  /// * row C's instance-authority gate — `canonical_rdata_forms`, whose domain
  ///   is SRV / TXT / NSEC — is not asked of it, because the authority in
  ///   question is the host name's. Asking it drops every labelled A/AAAA the
  ///   moment the service announces, so the same peer response would be handled
  ///   in rows B / B′ and discarded in row C.
  ///
  /// What the label is NOT is "this record was ours". That question has no
  /// answer at the instant of the lookup: §9 protects a fault-tolerance twin
  /// "capable of issuing identical answers", and such a twin's defence is
  /// byte-identical to our own ghost's echo. A row B that acted as though a
  /// match settled it would never let the record reach a service at all, and a
  /// successor could then probe and announce clean over an incumbent that was
  /// defending correctly — inside the retention window, with nothing replaying
  /// the lost defences afterwards. Deferring asks the only question that CAN
  /// separate them, and asks it of the future rather than of a table.
  ///
  /// Where each decision lives: rows A and B are this method, plus the
  /// `probe_defeated` / `tiebreak_lost` latches it
  /// sets and the single decision site in [`Service::handle_timeout`] that
  /// spends them. Row C's instance column is the `Announcing`/`Established`
  /// arm; its defence is routed by the endpoint as a `Question` (including
  /// under `answer_questions(false)`, which exempts a probe for a unique name).
  /// The host column is the `HostConflict` arm.
  ///
  /// Row B′ is the easiest row to leave out, because two obligations run
  /// together there. §9 deliberately KEEPS goodbye ownership across its revert,
  /// because peers still hold the previous generation's records under this same
  /// name and a §10.1 withdrawal must still retract them. But §9 also sends the
  /// responder "through the startup steps described above in Section 8", so the
  /// CONFLICT rules are §8's again while the withdrawal obligation is unchanged.
  /// One latch cannot answer both questions, which is why
  /// `generation_advertised` is separate from `goodbye.any_instance()`.
  ///
  /// # A classification and its decision are joined by a stored witness
  ///
  /// Not by re-deriving a predicate at each site. State moves between them, so
  /// the same predicate asked twice is not the same answer, and this crate has
  /// been wrong that way three separate ways:
  ///
  /// * the classification arm and the decision site keyed on DIFFERENT
  ///   predicates, so a conflict was classified and its latch never spent;
  /// * they keyed on the same predicate and still disagreed, because an
  ///   announcement was queued, transmitted and confirmed in between;
  /// * and the predicate itself read a latch belonging to a previous
  ///   generation (row B′).
  ///
  /// So the latches ARE the classification. [`Service::handle_timeout`] spends
  /// them on their own terms and never re-derives
  /// [`Service::is_preauthoritative`], and
  /// [`Service::conflict_classified_unresolved`] keeps the interval between the
  /// two empty of claims to this name — no announcement, question response, or
  /// legacy reply — so nothing can move the answer while it is pending.
  ///
  /// # Why the rows are not the state enum
  ///
  /// `Probing(3)` is §8.1's 250 ms settling window, and the state leaves it on a
  /// TIMEOUT while conflicts arrive on RX. A driver that fires timeouts before
  /// draining already-queued RX — `hick-smoltcp`'s `pump` does — would hand row
  /// B's traffic to row C purely on that ordering. And the four drivers do not
  /// agree: `hick-mio` and `hick-reactor` drain RX first, `hick-smoltcp` fires
  /// timers first, and `hick-compio` races them in an unbiased `futures::select!`
  /// whose winner is randomized per iteration — so no contract could be written
  /// that all four satisfy. This crate already refuses that dependency
  /// elsewhere by name (see `Query`'s deadline handling and
  /// `duplicate_suppresses_due_retry_independent_of_driver_order`), and refuses
  /// it here the same way: row B is keyed on what has been ANNOUNCED, not on the
  /// state name and not on the clock. Nothing has been announced whichever order
  /// the driver chose, so the classification is the same either way.
  ///
  /// "Nothing announced" is `!goodbye.any_instance()` — the confirm-driven
  /// ownership latch this crate uses for every other "is it really on the wire"
  /// question — plus no datagram in flight. A compliant driver never has one
  /// here (`handle_event`'s confirm-before-anything contract), so that conjunct
  /// only distinguishes the backstop case where the contract is broken, and it
  /// keeps a service with an announcement it has emitted but not confirmed on
  /// the §9 side where its own records may already be cached.
  ///
  /// # There are no caps
  ///
  /// A peer's proposal arrives whole and is folded into a verdict on arrival, so
  /// nothing is retained between events and there is no per-round proposal cap
  /// or per-proposal record cap. That is deliberate: a bound on our memory is a
  /// fact about US, and while proposals were buffered a full buffer could be
  /// read as a lexicographic verdict about the WIRE. Capacity exhaustion is now
  /// unrepresentable rather than guarded against.
  fn handle_preauthoritative_conflict(&mut self, pc: &crate::event::ProbeConflict<'_>) {
    // RFC 6762 §8.1: "Apparently conflicting Multicast DNS RESPONSES received
    // *before* the first probe packet is sent MUST be silently ignored (see
    // discussion of stale probe packets in Section 8.2)." Nothing of ours has
    // been on the link, so nothing on the link can be a reply to us, and §8.2's
    // stale-packet discussion is explicit that what arrives may be a probe "sent
    // moments ago by this host itself ... echoed back after a short delay by
    // some Ethernet switches".
    if !self.probe_on_wire {
      trace!(
        target: "mdns_proto::service",
        handle = self.handle.raw(),
        state = ?self.state,
        src = %pc.src(),
        "service: conflicting response before our first probe reached the wire — ignoring (§8.1)"
      );
      return;
    }
    // Inside the window, §8.1 admits no comparison at all: "During probing, from
    // the time the first probe packet is sent until 250 ms after the third
    // probe, if any conflicting Multicast DNS response is received, then the
    // probing host MUST defer to the existing host, and SHOULD choose new names
    // for some or all of its resource records as appropriate." The peer has
    // ALREADY claimed this name; we are still asking. Lexicographic ordering is
    // §8.2's rule for two hosts probing SIMULTANEOUSLY, where neither owns the
    // name — applying it here would let a later-sorting newcomer keep probing
    // toward a name an existing responder holds, and then take it.
    //
    // THE HISTORY-LABELLED DEFEAT.
    //
    // The record repeats rdata this endpoint recently transmitted and gave up
    // (see [`crate::event::ConflictHistory`]), so it is EITHER our own delayed
    // echo — a rename or unregister whose records are still in flight — OR a §9
    // fault-tolerance twin defending the name with the bytes we published until
    // that relinquishment. At this instant those two ARE the same datagram and
    // no lookup can separate them: §9 exists precisely to protect the twin, and
    // the twin's defence is byte-for-byte what the ghost's echo would be.
    //
    // Only FUTURE behaviour separates them, and §8.2 already knows how to ask.
    // "It defers to the winning host by waiting one second, and then begins
    // probing for this record again" — and §8.2 names this very case as its
    // reason, a probe "maybe from the host itself … echoed back after a short
    // delay by some Ethernet switches and some 802.11 base stations". A GHOST
    // cannot answer that re-probe, so the name is claimed a second later. A LIVE
    // INCUMBENT answers it, and once the label lapses with the retention window
    // that defeat renames us — §8.1 honoured, late rather than never.
    //
    // Latching §8.2's regress rather than §8.1's rename is the whole difference,
    // and it is a REGRESS, not a suppression. Dropping this record in the
    // endpoint before any service saw it would let a successor probe and
    // announce clean over an incumbent that was defending its name correctly: a
    // defence that reaches no service is not delayed, it is unappealable. A
    // deferral costs a second and claims nothing in the meantime, because
    // `conflict_classified_unresolved` withholds every claim to this name until
    // the latch is spent.
    if pc.history().is_relinquished() {
      trace!(
        target: "mdns_proto::service",
        handle = self.handle.raw(),
        state = ?self.state,
        src = %pc.src(),
        "service: conflicting response repeats rdata this endpoint relinquished — deferring one second and re-probing the SAME name (§8.2)"
      );
      self.tiebreak_lost = true;
      return;
    }
    // Latched rather than acted on, because renaming is a lifecycle move and
    // `handle_event` makes none: `handle_timeout` owns the single rename path,
    // and routing both defeats through it keeps one implementation of it.
    trace!(
      target: "mdns_proto::service",
      handle = self.handle.raw(),
      state = ?self.state,
      src = %pc.src(),
      "service: conflicting response during probing — deferring to the existing host (§8.1)"
    );
    self.probe_defeated = true;
  }

  /// Fold one peer's COMPLETE RFC 6762 §8.2 proposal into this round's verdict.
  ///
  /// The comparison itself lives in [`proposal`] — the module that owns BOTH
  /// sides' serializers, because §8.2 only resolves a name if the two hosts
  /// compute the same function over the same two lists, which makes them a
  /// matched pair. This method's whole job is to turn its [`Verdict`] into
  /// lifecycle state and a trace: it does not, and cannot, serialize a record
  /// itself. That is the point of the split — reaching for the wrong
  /// canonicalizer is what silently broke the tiebreak twice, and outside
  /// `proposal` the right one is no longer nameable.
  ///
  /// An abandonment is a NON-VERDICT, not a win for either side: the peer's
  /// Authority Section was not a list §8.2.1 could sort, so this round records
  /// nothing and the §8.1 sequence continues untouched.
  ///
  /// Returns whether the PEER won, which is the only outcome that costs this
  /// service a probe attempt and so the only one RFC 6762 §8.1's flood limit
  /// counts.
  fn handle_probe_proposal(&mut self, pp: &crate::event::ProbeProposal<'_>) -> bool {
    match proposal::adjudicate(pp, &self.records) {
      proposal::Verdict::PeerWins => {
        trace!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          state = ?self.state,
          src = %pp.src(),
          "service: peer proposal beats ours (§8.2.1) — losing this round"
        );
        self.tiebreak_lost = true;
        true
      }
      proposal::Verdict::WeHold => false,
      proposal::Verdict::Abandoned(_why) => {
        trace!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          state = ?self.state,
          src = %pp.src(),
          why = ?_why,
          "service: proposal is not a list §8.2.1 can sort — abandoning it with no verdict"
        );
        false
      }
    }
  }


  /// Process an event routed to this service by the Endpoint.
  ///
  /// Crate-internal, and reached only from `RouteEvents::next` — the endpoint
  /// dispatches a service event inside its own routing borrow, exactly as it
  /// already applied a query answer inside one. That is what makes `now` here
  /// the datagram's RECEIPT instant rather than whenever a caller got round to
  /// forwarding the event, and it is what lets `flood` be counted at the same
  /// instant the conflict is classified.
  ///
  /// `now` is the current time; it is cached so that `handle_event` can
  /// compute KAS-hint expiration times and schedule the jittered response
  /// deadline without needing `handle_timeout` to have fired first.
  ///
  /// # What goes into `flood`, and what does not
  ///
  /// §8.1 counts CONFLICTS, and only this method can tell one from a record that
  /// merely matched a name: identical rdata is never a conflict, undecodable
  /// rdata is not one either way, a type this service asserts nothing of at that
  /// name is not its RRset, and a response arriving before this name's first
  /// probe packet is one §8.1 requires be ignored. So the count is taken HERE,
  /// after classification, and never at the router's emission points — where all
  /// four of those are still indistinguishable from a genuine conflict.
  ///
  /// Counted:
  ///
  /// * a pre-authoritative `ProbeConflict`, once this generation's first probe
  ///   has reached a link (`probe_on_wire`) — including a history-labelled one,
  ///   which regresses this service exactly as an unlabelled one does;
  /// * a `ProbeProposal` whose §8.2.1 verdict is `PeerWins`, which is the only
  ///   verdict that costs a probe attempt. `WeHold` and an abandonment leave the
  ///   sequence running and cost nothing to space out;
  /// * an established §9 conflict — counted BEFORE §9's own re-probe interval
  ///   decides whether to revert, because §8.1 counts what OCCURRED and a
  ///   conflict that rule drops still occurred;
  /// * a `HostConflict` from an authoritative response, once `probe_on_wire`.
  ///
  /// Not counted: everything screened above, a peer's tentative probe for a host
  /// name (not §9's conflict at all), and a `HostConflict` surfaced before this
  /// name's first probe reached the wire — that one is TERMINAL and is still
  /// surfaced, but §8.1's flood limit spaces probe attempts, and a service the
  /// caller must now intervene on makes none.
  ///
  /// # Contract
  ///
  /// Must NOT be called while a datagram from [`Self::poll_transmit`] is still
  /// awaiting its [`Self::note_transmit_outcome`] — an inbound RFC 6762 §9
  /// conflict processed in that window regresses the exact state the pending
  /// confirm is about to apply. See [`Self::poll_transmit`] for the full
  /// contract; debug builds assert it.
  pub(crate) fn handle_event(
    &mut self,
    event: ServiceEvent<'_>,
    now: I,
    flood: &mut ConflictFlood<I>,
  ) {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("service", handle = self.handle.raw()).entered();
    self.assert_no_live_commit_token("Service::handle_event");
    // Refresh the instant `poll_timeout` reports as "due immediately" — an
    // event can make a service due (a Question arms `response_deadline`) with
    // no `handle_timeout` between it and the next `poll_timeout`. The arms
    // below read this method's `now`, not this field.
    self.last_now = Some(now);
    // §8.1 COUNT ELIGIBILITY, settled here rather than in the arm that reads it.
    //
    // It is a fact about the datagram, so it must be captured before any arm of
    // any record of that datagram has had the chance to move the state it is
    // about — and the arm that does move it is not the arm that reads it. An
    // established service's §9 revert (the `ProbeConflict` arm below) shuts
    // §8.1's window, and it is the `HostConflict` arm of a LATER record that
    // then finds it shut. Capturing at every conflict-bearing event, not only
    // at the two that gate on the answer, is what makes the capture belong to
    // the first record of the datagram whichever arm that record takes.
    //
    // The same rule the router applies to the clock: its `now` is "not re-read
    // per record. The datagram is one event with one processing instant." See
    // [`Service::flood_eligibility`].
    if let Some(datagram) = event.datagram() {
      let _ = self.flood_eligible(datagram);
    }
    trace!(
      target: "mdns_proto::service",
      handle = self.handle.raw(),
      state = ?self.state,
      event = ?core::mem::discriminant(&event),
      "service: handle_event"
    );
    // RFC 6762's "identical rdata is never a conflict", stated ONCE here rather
    // than inside individual arms — which is how the rule kept going missing.
    // It was applied to the §8.2.1 list comparison and to the §9
    // post-establishment path, and NOT to the probing path, so an established
    // fault-tolerant peer defending with byte-identical records made a second
    // identical responder rename itself away the moment its first probe hit the
    // wire. That is the very case §9 names as the reason for the rule: proxies
    // and fault-tolerance mechanisms "capable of issuing identical answers".
    //
    // A precondition, not a table cell: it holds in every phase, so splitting
    // each `AuthoritativeResponse` cell in two would restate one rule four times
    // and leave the fifth arm free to forget it again.
    //
    // RESPONSES only, and that is now a property of the TYPE: a peer's tentative
    // proposal arrives as `ProbeProposal` and is §8.2.1's input as a LIST, where
    // dropping members would hand the comparator a list the peer never made.
    // THREE answers, not two. A peer's record is identical to ours, genuinely
    // different, or NOT DECODABLE AT ALL — and collapsing the third into
    // "different" is what let malformed data drive a real §8.1 defeat: a QR=1
    // IN/SRV response whose target is a cyclic or forward pointer set
    // `probe_defeated` and RENAMED the service, and repeating it gave unbounded
    // suffix churn and eventually a terminal conflict. An attacker needed one
    // malformed record and no knowledge of our rdata at all.
    //
    // The established §9 arm already dropped the same invalid data instead of
    // reverting on it, so the two halves of one rule disagreed. Now the
    // classification is made ONCE, here, and invalid stops before every conflict
    // arm rather than in some of them.
    let peer_rdata = match &event {
      // BY ROLE, not by event type. A `ProbeConflict` whose owner is this
      // service's HOST name as well as its instance name carries an A/AAAA that
      // BOTH roles own, and the instance classifier cannot read it: its rule is
      // `canonical_rdata_forms`, whose domain is SRV / TXT / NSEC, so it answers
      // `Different` for every address — including one this service publishes at
      // that very name, which §9 and §8.2.1 both call no conflict at all. The
      // host classifier is the one that can compare an address against an
      // address, and the routing fan-out has already proved this route
      // authoritative for that RRset at that name.
      ServiceEvent::ProbeConflict(pc) if pc.role().is_instance_and_host() => {
        self.classify_host_rdata(pc.record())
      }
      ServiceEvent::ProbeConflict(pc) => self.classify_instance_rdata(pc.record()),
      // The HOST half of the same rule, stated in the same place rather than a
      // fourth time inside its own arm. It is the last of the four places this
      // rule went missing: the §8.2.1 tie, the §9 post-establishment path, the
      // probing path, and here — and it had the identical invalid-reads-as-
      // differing defect, where a malformed A/AAAA at our host name surfaced a
      // TERMINAL, caller-visible `HostConflict`.
      ServiceEvent::HostConflict(hc) => self.classify_host_rdata(hc.record()),
      _ => PeerRdata::Different,
    };
    match peer_rdata {
      PeerRdata::Identical => {
        trace!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          state = ?self.state,
          "service: record carries rdata we already advertise — never a conflict (§9)"
        );
        return;
      }
      PeerRdata::Invalid => {
        trace!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          state = ?self.state,
          "service: record's rdata will not decode — not a conflict either way, dropping it"
        );
        return;
      }
      PeerRdata::UnownedRrtype => {
        trace!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          state = ?self.state,
          "service: we publish no record of this rrtype at this name — not our RRset (§9)"
        );
        return;
      }
      PeerRdata::Different => {}
    }
    match (self.state, event) {
      // Pre-authoritative: nothing of this name is announced, so RFC 6762
      // §8.1/§8.2 govern. See the conflict matrix on
      // [`Service::handle_preauthoritative_conflict`], and note that the same
      // predicate gates the decision site in `handle_timeout` — classifying a
      // conflict here and then declining to spend its latch there would lose it.
      (_, ServiceEvent::ProbeConflict(pc)) if self.is_preauthoritative() => {
        // §8.1 ignores a conflicting response received before this generation's
        // first probe packet is sent, and a conflict this service is required to
        // ignore is not one the host may count. `handle_preauthoritative_conflict`
        // applies the same gate to the record itself — from LIVE state, because
        // whether to act on the record is a question about the generation now
        // running, while whether to COUNT it is a question about the datagram
        // that arrived. See [`Service::flood_eligibility`].
        if self.flood_eligible(pc.datagram()) {
          flood.accept(now, pc.datagram(), self.records.instance());
        }
        self.handle_preauthoritative_conflict(&pc);
      }
      // §8.2's tiebreak, and its only input. Folded on arrival; a proposal that
      // reaches a service already past adjudication is simply not compared,
      // which is the same answer the old buffer would have reached by never
      // being spent.
      (_, ServiceEvent::ProbeProposal(pp)) if self.is_preauthoritative() => {
        // ONLY a loss is a conflict for §8.1 to space out: `WeHold` and an
        // abandonment leave the §8.1 sequence running untouched, so neither
        // costs the probe attempt the limit exists to slow down.
        if self.handle_probe_proposal(&pp) {
          flood.accept(now, pp.datagram(), self.records.instance());
        }
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
        //
        // A RESPONSE is what §9 is about, and the definition is the whole
        // sentence: "A conflict occurs when a Multicast DNS responder has a
        // unique record for which it is currently authoritative, and it
        // receives a Multicast DNS RESPONSE message containing a record with
        // the same name, rrtype and rrclass, but inconsistent rdata." A peer
        // merely PROBING this name is not that, and needs no origin test to
        // exclude: it arrives as `ProbeProposal`, which this arm does not match,
        // so §9's "receives a Multicast DNS response message" is satisfied by
        // the event TYPE rather than by a check. The right answer to such a
        // probe is to defend the name, which §8.1 requires and which the
        // `Question` arm does from the same datagram — answering the probe's
        // question is what makes the prober back off. Letting the probe's
        // Authority record through here instead would regress an established
        // service to probing on demand: any host that probes our name could stop
        // us serving it, and could then take it from us on the §8.2 tiebreak
        // that the re-probe runs.
        //
        // The rtype screen is §9's OWN — "a unique record for which it is
        // CURRENTLY AUTHORITATIVE … with the same name, rrtype and rrclass" —
        // and it is applied HERE rather than in the router because the router
        // cannot see lifecycle state. §8.1 needs every type at this name
        // delivered (a peer's existing A/AAAA/NSEC is a conflicting response for
        // a name we are PROBING), so the router routes every type and the narrow
        // rule lives where it is true: on the established side.
        //
        // "Authoritative for" is asked of the RECORD SET, through the same
        // function the classifier just used, rather than of a hand-written list
        // of rrtypes. A hand-written `Srv | Txt` goes stale the moment
        // `canonical_rdata_forms` gains an arm, as it did for NSEC: a peer's
        // authoritative, cache-flushed NSEC at this instance name with DIFFERENT
        // rdata is classified as conflicting and then dropped here for being an
        // NSEC, so an NSEC-only response leaves duplicate ownership of this name
        // undetected until unrelated SRV/TXT traffic arrives. A shared PTR is
        // still
        // excluded, and by the rule rather than by a special case: it is owned
        // by the service-type name, so this set asserts no form of it.
        //
        // ASKED OF THE ROLE THE RECORD ARRIVED UNDER. `canonical_rdata_forms`
        // answers for the INSTANCE name's RRsets; a record that is also this
        // service's host record is authoritative under the HOST name, and that
        // authority was proved by the routing fan-out's host rule and re-checked
        // by `classify_host_rdata` above (a type we hold no RRset of there is
        // `UnownedRrtype` and never reaches this arm). Asking the instance
        // question of it returns "we assert no record of this type at this
        // name" for an address we assert at exactly this name, so the §9 reset
        // this cell exists to run would never run — the record handled while
        // probing, where §8.1 admits every type, and silently dropped the moment
        // the service announced. See [`crate::event::ConflictRole`].
        if pc.role().is_instance()
          && self
            .our_canonical_records_for(pc.record().rtype())
            .is_empty()
        {
          return;
        }
        // THE HISTORY LABEL BUYS NOTHING HERE, and its absence is the decision.
        //
        // This cell dropped a labelled record for one round, on the premise that
        // §9 self-heals because a real incumbent's traffic recurs. THAT PREMISE
        // IS FALSE, and §8.3 is what falsifies it: a conforming responder
        // announces AT LEAST TWICE, one second apart, MAY continue to eight
        // times with the interval at least doubling each time, and is then
        // SILENT until something queries it. A screen that consumes a burst
        // landing wholly inside the retention window consumes every copy there
        // was, and nothing replays a conflict when the window lapses — so
        // duplicate ownership of an ADVERTISED name stood until unrelated
        // traffic happened to arrive, which is §9's "MUST immediately reset its
        // conflicted unique record to probing state" not happening at all.
        // Reaching that costs a peer nothing to arrange: packet loss over the
        // successor's probes is enough, and then the incumbent's next response
        // lands here rather than pre-authoritatively.
        //
        // The label could not be spent as a suppression here for the same reason
        // it could not be spent as one pre-authoritatively: a match says these
        // bytes left this endpoint, not that this datagram did, and §9's
        // fault-tolerance twin publishes them BY DESIGN. What differs between
        // the two cells is only which reversible move the label buys — §8.2's
        // one-second regress there, §9's own revert here — and both put the
        // question to the network, which is the only place an answer exists.
        //
        // So our OWN delayed echo costs the revert below: the same name,
        // rate-limited by `CONFLICT_REPROBE_MIN_INTERVAL`, claiming nothing
        // while it runs, and ending in a re-announcement because a ghost cannot
        // answer the re-probe. It cannot cost the name — `probe_defeated` is the
        // only path to a rename, and the pre-authoritative cell never latches it
        // on a labelled record.
        //
        // A record whose rdata will not decode is not one this service can
        // reason about; drop it rather than revert on it. The identical-rdata check
        // is the precondition above `match (self.state, event)`, so every arm
        // gets it.
        if pc.record().canonical_rdata_folded().is_err() {
          return;
        }
        // COUNTED HERE, above §9's own rate limit. §8.1 counts conflicts that
        // OCCUR, and a conflict the interval below declines to act on still
        // occurred — while #139's counter, which counted regresses, missed every
        // one of them. Everything §9 would drop for NOT being a conflict has
        // already returned above: identical rdata, undecodable rdata, and a type
        // this service asserts no record of at this name.
        flood.accept(now, pc.datagram(), self.records.instance());
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
        // §9 sends this service through a FRESH §8 startup sequence — "MUST
        // immediately reset its conflicted unique record to probing state, and
        // go through the startup steps described above in Section 8" — which is
        // exactly what `restart_probe_cycle` is. The NAME is unchanged (§9
        // re-verifies what we still own), so `renamed_from` is `None` and a
        // parked datagram's records still latch into `goodbye` under this name.
        //
        // Shutting §8.1's window is part of that regress and it is also what
        // stops ONE datagram being scored as two: a driver dispatches a
        // response's records one at a time, so a response carrying a differing
        // TXT and then a differing SRV reverts on the TXT and hands the SRV
        // straight to the arm above — which would adjudicate a peer "list"
        // holding only the SRV, a fragment of what the peer actually sent. With
        // the window shut, the SRV is a response arriving before the restarted
        // sequence's first probe, and §8.1 says to ignore it.
        //
        // Note what is NOT reset with it: the per-advertised-NAME state, and
        // `fully_announced` in particular. This is the same name, so unlike a
        // rename it carries over — the only thing it can do is cancel a
        // renamed-away predecessor's §10.1 goodbye, and any goodbye this name
        // could cancel was already cancelled when it first fully announced.
        let deadline = probe_deadline(now, 0, &mut self.rng);
        // The parked outcome CANNOT be returned: `handle_event` has no error
        // channel, and `ServiceUpdate` has no variant that means "this service
        // is parked because its clock cannot express a mandated wait" — inventing
        // one is a public-API decision, not this fix's. A `warn!` is what the
        // path can honestly offer; `handle_timeout` reports it properly on every
        // other route into this function, including the next tick of this one,
        // whose `Init` re-schedule re-evaluates the same floor.
        if self.restart_probe_cycle(now, deadline, None, flood).is_err() {
          warn!(
            target: "mdns_proto::service",
            handle = self.handle.raw(),
            "service: §9 revert parked — the clock cannot express §8.1's mandated wait"
          );
        }
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
            // Date the hint, exactly as the ordinary §7.1 path dates a
            // `KasHint`: the arriving record's own TTL from the instant this
            // event carries. The half-TTL test above says the answer is fresh
            // ENOUGH to suppress; it does not say for how long, and
            // `poll_transmit` runs on a clock of its own.
            //
            // An un-representable deadline drops the hint rather than counting
            // as valid: a TTL that overflows the clock is not evidence the
            // querier holds anything, and failing to suppress costs one
            // redundant but truthful meta-PTR, where suppressing wrongly costs
            // the enumeration entirely.
            let ttl = core::time::Duration::from_secs(u64::from(ka.record().ttl()));
            if let Some(expires_at) = now.checked_add_duration(ttl) {
              self.meta_known_answered = Some(expires_at);
            }
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

        // The hint expires on the arriving record's own TTL, counted from the
        // instant this event carries.
        let ttl = core::time::Duration::from_secs(u64::from(ka.record().ttl()));
        let expires_at = match now.checked_add_duration(ttl) {
          Some(t) => t,
          None => return,
        };
        // Use canonical rdata bytes so the hash matches what write_announce_filtered
        // produces, regardless of wire-level name compression in the incoming packet.
        // Drop the hint on any decode error rather than storing an incorrect hash.
        let canonical = match ka.record().canonical_rdata_folded() {
          Ok(c) => c,
          Err(_) => return, // malformed rdata / pointer cycle — drop the hint
        };
        let rdata_hash = hash_rdata(&canonical);
        // A known-answer may only suppress the RRset it actually NAMES — §7.1
        // identifies one by name, type, class and rdata — so bind the hint by
        // asking `respond::emitted_owner_name` which of our names a record of
        // THIS rtype sits at, then requiring the arriving record to carry that
        // name. A type these encoders never write has no such owner, and a
        // record at any other name is a different RRset; either way it can
        // suppress nothing, so it is dropped here rather than stored to be
        // filtered out later.
        //
        // Deriving the owner from the RTYPE is what keeps this side and the
        // emit-side filter from disagreeing: they read ONE rule, so the filter
        // needs no owner test of its own. Classifying by NAME here — walking our
        // three names in a precedence order, first match consuming — is what
        // broke where the instance name IS the host name: an inbound A took the
        // instance arm because that name matched first, while the A candidate
        // was owned by the host, and §7.1 suppression for host addresses could
        // never fire.
        let Some(owner) = respond::emitted_owner_name(&self.records, ka.record().rtype()) else {
          return; // a type these encoders never write — nothing of ours to suppress
        };
        if !crate::endpoint::names_match_record(owner, ka.record()) {
          return; // a different owner name is a different RRset (§7.1)
        }
        let hint = KasHint {
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
        // §9 defines a conflict over a RESPONSE, and this update is TERMINAL:
        // every driver retires and withdraws the service on it. A peer's
        // tentative probe for a host name is that peer asking whether the name
        // is free, not a claim that it owns it — and honouring it here would let
        // one ordinary probe retire every service sharing that host name, the
        // same denial of service the instance path closes. It is not lost, only
        // deferred: a prober that goes on to win announces, and that
        // announcement is a response which does surface here.
        //
        // KNOWN GAP, wider than this arm and deliberately not closed here: this
        // responder has no host-name ownership protocol at all. `write_probe`
        // asks its ANY question for the INSTANCE name only, while putting the
        // host A/AAAA in the Authority Section — so the host name is proposed
        // but never probed, and no peer's `Question` arm matches it unless that
        // peer happens to share the instance name too.
        //
        // Two consequences follow from the gap, and the origin test below
        // neither causes nor closes them. A peer probing instance B with OUR
        // host H gets no defence from us, because our question-matching never
        // sees a question for H. And two fresh peers proposing the same H never
        // tiebreak their host RRsets, so both can announce it. What the origin
        // test decides is only WHEN the loser finds out. A peer's PROBE does not
        // retire us — that would let any host retire every service sharing a
        // host name — its ANNOUNCEMENT does: a response, which is what §9
        // defines the conflict over, and the same end state by the legitimate
        // route.
        //
        // Closing the gap means probing the host name in its own right and
        // giving host records the ownership handling instance records have:
        // immediate non-terminal defence when established, full A/AAAA RRset
        // comparison when probing, and both under
        // `answer_questions(false)`. That is a protocol this crate does not
        // implement, not a rule it applies to the wrong input.
        if !hc.origin().is_authoritative_response() {
          trace!(
            target: "mdns_proto::service",
            handle = self.handle.raw(),
            state = ?self.state,
            rtype = ?hc.record().rtype(),
            "service: peer probe for our host name — not a §9 conflict, ignoring"
          );
          return;
        }
        // RFC 6762 §9 only treats DIFFERENT rdata as a conflict. A
        // host A/AAAA whose address is one WE advertise is consistent (our own
        // multicast echo, or another instance correctly sharing the host) — not
        // a conflict. Ignore it; surface HostConflict only for a genuinely
        // different address. The identical-rdata check is the precondition above
        // `match (self.state, event)`, so every arm gets it.

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
        // COUNTED under the HOST name, which is what makes one arriving A/AAAA
        // at a shared host name ONE conflict for the endpoint however many
        // services publish that name — and two contested host names in one
        // datagram two. The instance-role conflicts above key on the instance
        // name for the same reason, and a service whose instance name IS its
        // host name therefore counts SRV and A from one datagram once.
        //
        // Gated on the DATAGRAM's eligibility, exactly as the pre-authoritative
        // instance cell is. Before this name's first probe reached a link, §8.1
        // has us ignore conflicting responses; this one is still SURFACED,
        // because it is terminal and the caller must intervene, but it spaces
        // out no probe attempt because a `Conflicting` service makes none.
        //
        // Reading live `probe_on_wire` here made one datagram's count depend on
        // the order of its records: a conflicting SRV at the instance name runs
        // §9's revert, which shuts §8.1's window, so a conflicting A at the host
        // name behind it went uncounted while the same pair in the other order
        // counted twice. See [`Service::flood_eligibility`].
        if self.flood_eligible(hc.datagram()) {
          flood.accept(now, hc.datagram(), self.records.host());
        }
        let _ = self.pending_updates.insert(ServiceUpdate::HostConflict);
      }
      _ => {}
    }
  }

  /// Drive timer-based transitions. Returns Ok unless arithmetic overflowed.
  ///
  /// [`HandleTimeoutError::Overflow`] also covers the case where a mandated WAIT
  /// cannot be represented rather than a deadline merely failing to compute:
  /// when RFC 6762 §8.1's flood limit is in force and `now + 5 s` does not exist
  /// on this clock, the restarted probe sequence is parked with no deadline —
  /// see the backoff floor the restart path applies — and this reports that
  /// rather than leaving it indistinguishable from an idle tick. The condition is
  /// re-evaluated on every subsequent call, so the error repeats for as long as
  /// the service stays parked and stops when it can be scheduled again.
  ///
  /// A sequence parked from `Probing` reports the same way and is re-scheduled
  /// the same way, which is what closes the one route to a silent stall: the
  /// wire-boundary floor can drop a queued first probe whose enqueue left no
  /// deadline behind it (see
  /// [`Service::defer_first_probe_under_flood`]), and [`Service::poll_timeout`]
  /// is what keeps the caller coming back to hear about it.
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
  pub(crate) fn handle_timeout(
    &mut self,
    now: I,
    flood: &ConflictFlood<I>,
    taken: &NamesInUse<'_>,
  ) -> Result<(), HandleTimeoutError> {
    #[cfg(feature = "tracing")]
    let _span = hick_trace::trace_span!("service", handle = self.handle.raw()).entered();
    self.assert_no_live_commit_token("Service::handle_timeout");
    // Refresh the instant `poll_timeout` reports as "due immediately"; every
    // other clock-sensitive path is handed a `now` of its own and reads that.
    self.last_now = Some(now);

    // Item 5: prune expired KAS hints.
    for slot in self.kas_hints.iter_mut() {
      if let Some(hint) = slot
        && hint.expires_at <= now
      {
        *slot = None;
      }
    }

    // The ONE place a probing service gives up its name, fed by the two RFC 6762
    // rules that can take it — which are different rules, over different inputs,
    // and only one of them is a comparison. Both apply ONLY to Init/Probing;
    // post-establishment (§9) conflicts are handled in `handle_event`
    // (revert-to-probe), never here.
    //
    // §8.1, `probe_defeated`: a conflicting authoritative RESPONSE arrived
    // inside the probing window, so an existing responder already owns this
    // name. "The probing host MUST defer to the existing host, and SHOULD choose
    // new names." Not a comparison — it outranks a pending tiebreak, because a
    // host that owns the name outranks one still asking for it.
    //
    // §8.2, `tiebreak_lost`: another host is probing for the same name at the
    // same time, neither owns it, and the lexicographically later proposed
    // record LIST wins. A tie is §8.2.1's "there is, in fact, no conflict" and
    // leaves the probe sequence running.
    //
    // The two rules do DIFFERENT things and each is implemented as written: a
    // §8.2 loser "defers to the winning host by waiting one second, and then
    // begins probing for this record again" — it keeps the name, so a stale echo
    // of our own earlier probe cannot cost us one — while a §8.1 defeat renames,
    // which is exactly what §8.1 prescribes for it.
    // Spends the STORED classification. Deliberately not re-derived from
    // `is_preauthoritative()`: `handle_event` already decided this conflict was
    // pre-authoritative, and re-asking here lets an announcement that slipped
    // out in between answer differently. `poll_transmit` is what makes "in
    // between" empty of claims to this name.
    if self.conflict_classified_unresolved() {
      let defeated_by_owner = core::mem::take(&mut self.probe_defeated);
      let lost_tiebreak = core::mem::take(&mut self.tiebreak_lost);
      // No arrival instant is carried across: the endpoint counted this conflict
      // into its flood history at RECEIPT, inside the same `handle` borrow that
      // classified it, so nothing here has to re-date it. That also ends the
      // undercount the carried instant papered over — a §8.2 loss superseded by
      // a §8.1 defeat before either was spent used to yield ONE ring entry for
      // two received conflicts, because the ring was written per regress rather
      // than per conflict.
      // TWO WAYS TO LOSE, AND THEY DO DIFFERENT THINGS. Neither is re-derived
      // here; both were decided when the conflict was classified.
      //
      // §8.2 — `lost_tiebreak`: another host was probing for this name at the
      // same time and its proposal sorted later. NEITHER host owns the name yet,
      // so the loser does not give it up: "it defers to the winning host by
      // waiting one second, and then begins probing for this record again."
      // Handled below WITHOUT renaming.
      //
      // §8.1 — `defeated_by_owner`: a conflicting authoritative response arrived
      // inside the probing window, so someone already HOLDS the name. "The
      // probing host MUST defer to the existing host, and SHOULD choose new
      // names." That is a rename, and it outranks a tiebreak deferral: a host
      // that owns the name outranks one still asking for it.
      if !defeated_by_owner && lost_tiebreak {
        // §8.2's deferral. The name is kept, the §8.1 sequence restarts from the
        // beginning after one second, and `poll_transmit` withholds every claim
        // to the name until then because the classification is still unresolved.
        //
        // This TERMINATES, which is what makes the deferral safe: §8.2 explains
        // that "if the winning simultaneous probe was from a real other host on
        // the network, then after one second it will have completed its probing,
        // and will answer subsequent probes." That answer is a RESPONSE, which
        // is `defeated_by_owner` above, which renames. Telling the two apart is
        // what `ConflictOrigin` is for: an unconditional defer would otherwise
        // loop against a real owner forever.
        //
        // A HISTORY-LABELLED defeat reaches this same branch, and its
        // termination argument is a DIFFERENT one, because the incumbent's next
        // defence carries the same rdata and so carries the same label: the
        // label is what lapses, not the traffic. It lapses on a deadline fixed
        // when the record was relinquished — `EndpointConfig::
        // relinquished_retention` past the last resident copy of that set — so
        // the loop is bounded by the window rather than by the peer, and the
        // first unlabelled defence after it renames. Within the window nothing
        // is claimed: the classification stays unresolved between rounds, and
        // `poll_transmit` withholds every claim to the name while it is. So the
        // cost of a wrong guess here is latency, bounded and self-clearing,
        // where the cost of the drop it replaces was the name itself.
        //
        // And if the "winner" was only a stale echo of our own earlier probe,
        // the retry goes unanswered and we keep the name. That is the whole
        // reason §8.2 waits instead of renaming, and renaming here caused
        // needless goodbye and cache churn on transient traffic.
        warn!(
          target: "mdns_proto::service",
          handle = self.handle.raw(),
          state = ?self.state,
          "service: lost the §8.2 tiebreak — deferring one second and re-probing the SAME name"
        );
        #[cfg(feature = "stats")]
        if let Some(s) = self.stat() {
          s.conflicts(1);
        }
        // The SAME regress the §9 revert runs, differing only in WHEN the fresh
        // sequence may begin: §8.2's loser "defers to the winning host by
        // waiting one second". The NAME is kept — that is the whole point of the
        // deferral — so `renamed_from` is `None` and a parked datagram's records
        // still latch into `goodbye` under it.
        return self.restart_probe_cycle(
          now,
          now.checked_add_duration(schedule::rfc::TIEBREAK_DEFER_WAIT),
          None,
          flood,
        );
      }
      if defeated_by_owner {
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
          defeated_by_owner,
          "service: probe lost — renaming (§8.1 deferral to an existing owner, or §8.2 tiebreak)"
        );
        #[cfg(feature = "stats")]
        if let Some(s) = self.stat() {
          s.conflicts(1);
          s.renames(1);
        }
        // `|| nsec` covers the one exposure a §10.1 goodbye cannot: a
        // §7.1-filtered response that emitted only host addresses still carried
        // the instance NSEC, so the OLD name has an identity on the wire while
        // owning no retractable instance record. The handoff is what carries
        // that fact to `Endpoint::enqueue_rename_withdrawal`, which retains it —
        // and the goodbye ITEM is still not created, because `owned.is_empty()`
        // decides that and an NSEC is not withdrawable.
        if self.goodbye.any_instance() || any_family(self.goodbye.all.nsec) {
          // capture WHICH instance records the old name actually put on
          // the wire (§7.1 KAS may have emitted only a subset), so the rename
          // goodbye withdraws exactly those — not all of PTR/SRV/TXT, which
          // could flush a peer's matching same-name record we never sent. Host
          // A/AAAA are not withdrawn by a rename (the host name is unchanged).
          // Captured BEFORE `set_instance(new_name)` below, so `self.records`
          // still names the OLD instance. The Service no longer drains this —
          // it is handed off (`take_rename_goodbye_handoff`) to the endpoint as
          // an independent detached withdrawal item.
          // Per family, because the old name's exposure is: an announcement
          // only IPv4 accepted put nothing under that name in an IPv6 peer's
          // cache, so IPv6 owes it no goodbye and cannot hold an echo of it.
          // The instance-only projection of one exposure pair — applied to BOTH
          // halves, because the screen's half narrows by destination class and
          // by nothing else. The old name's records reached one legacy
          // resolver's cache whether or not they reached the group, so `owned`
          // still owes them a §10.1 retraction; only `multicast` decides whether
          // an echo of them can exist.
          let instance_only = |e: &respond::EmittedRecords| {
            respond::EmittedRecords::new(
              e.ptr(),
              e.srv(),
              e.txt(),
              std::vec::Vec::new(),
              std::vec::Vec::new(),
              e.subtypes(),
              e.nsec(),
            )
          };
          let owned = self.goodbye.per_family().map(|e| instance_only(&e));
          let multicast = self
            .goodbye
            .per_family_multicast()
            .map(|e| instance_only(&e));
          self.rename_goodbye_handoff = Some(RenameGoodbyeHandoff {
            records: self.records.clone(),
            owned,
            multicast,
          });
        }
        // PICK A NAME THIS ENDPOINT DOES NOT ALREADY HOLD. `taken` is the route
        // table's own answer, read in the same call, so the name this rename
        // settles on is one the route table will accept — there is no second
        // party to refuse it and no collision arm to write. Each attempt yields a
        // distinct suffix, so stepping over at most `taken.len()` of them always
        // reaches a free one; the loop cannot spin.
        let chosen = {
          let mut found = None;
          for _ in 0..=taken.len() {
            self.rename_attempt = self.rename_attempt.saturating_add(1);
            let candidate =
              rename_with_suffix(self.records.instance().as_str(), self.rename_attempt);
            match crate::Name::try_from_str(&candidate) {
              Ok(name) if taken.holds(&name) => continue,
              Ok(name) => {
                found = Some(name);
                break;
              }
              // The suffixed name is not a valid DNS name (too long, most
              // likely). A longer suffix cannot help, so stop here.
              Err(_) => break,
            }
          }
          found
        };
        // Capture the OLD name BEFORE `set_instance` overwrites it — a live
        // commit token's records are cached under this name and nowhere else, and
        // by confirm time nothing here still says so.
        let renamed_from = self.records.clone();
        // Carried out of the match rather than propagated with `?`: the rename's
        // remaining work — the new name, the `Renamed` update, the per-name reset
        // — is owed whether or not the restarted sequence could be scheduled.
        let mut outcome: Result<(), HandleTimeoutError> = Ok(());
        match chosen {
          Some(new_name) => {
            // The SAME regress as §9 and §8.2 — this is the third caller, and
            // the only one that changes the name. `renamed_from` carries the OLD
            // records so a parked datagram's confirm latches ownership under the
            // name it actually advertised; `set_instance` runs INSIDE the regress
            // window, between the stale-token capture the regress does first and
            // the per-name reset below.
            let deadline = probe_deadline(now, 0, &mut self.rng);
            outcome = self.restart_probe_cycle(now, deadline, Some(renamed_from), flood);
            self.records.set_instance(new_name.clone());
            let _ = self.pending_updates.insert(ServiceUpdate::Renamed(
              crate::event::ServiceRenamed::new(new_name),
            ));
            // The NEW name has announced nothing, and the old name's
            // per-advertised-NAME state must not leak into it — otherwise a later
            // unregister/local-collision could goodbye a never-announced name,
            // and queued legacy replies / KAS hints would advertise/suppress
            // under the wrong (un-probed) name. This is what a rename does and
            // the two SAME-name regressions must NOT: `fully_announced` is about
            // a NAME, and their name did not change.
            self.reset_advertised_name_state();
          }
          None => {
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
        return outcome;
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
    // A PARKED startup sequence — nothing armed, nothing queued, nothing in
    // flight — is re-scheduled here, and this is the only place that can be.
    //
    // `Probing(n)` and not only `Init`. The `Init` case is the older one (a
    // rename before the first `handle_timeout`, or a construction whose floor was
    // unrepresentable), but a probe sequence can be left with nothing armed from
    // `Probing` too: the enqueue arm below queues the probe FIRST and only then
    // assigns `probe_deadline(..)`, which is itself `None` at the end of a
    // bounded clock — and the wire-boundary floor then drops that queued probe.
    // With the recovery reading `Init` alone, such a service kept its state, lost
    // its only pending work, and was never called again.
    //
    // Through the SAME floor the regress used. This is the one path that can
    // fabricate a start time for a sequence that has none, so it is also the
    // one path that could hand a latched flood a fresh 0-250 ms delay and undo
    // the wait §8.1 mandates. With the floor applied it re-evaluates instead:
    // `None` again while the clock still cannot express the mandated wait, and a
    // properly floored deadline once it can.
    if self.startup_parked() {
      let base = probe_deadline(now, 0, &mut self.rng);
      self.lifecycle_deadline = self.apply_backoff_floor(now, base, flood);
      // lifecycle didn't "fire" a transmit here — just scheduled; fall through.
    }

    // RFC 6762 §8.1's flood floor, re-read AT THE COMMIT POINT.
    //
    // The regress that started this sequence already floored its deadline, but
    // the limit can latch AFTER that: the fifteenth conflict of a burst can
    // arrive in the 0-250 ms between a service being scheduled and its probe
    // going out — including on a service registered a moment ago, whose first
    // probe "each successive additional probe attempt" also covers. So the
    // verdict is read again here, where a probe would actually be enqueued,
    // rather than only where one was scheduled.
    //
    // That is what makes the rule ORDER-INDEPENDENT. The fifteenth conflict is
    // folded inside `Endpoint::handle`, synchronously, before the iterator
    // yields anything — so a service due at that same instant reads the true
    // verdict whether the driver ticks timers first or routes the datagram
    // first, and neither order can put a probe on the wire inside the five
    // seconds §8.1 mandates.
    //
    // Only while `!probe_on_wire`: once this generation's first probe has
    // reached a link the sequence is committed, and §8.1's floor is a floor on
    // STARTING a probe sequence, not a stall between its second and third
    // packets.
    let mut parked = false;
    if !self.probe_on_wire
      && matches!(
        self.state,
        ServiceState::Init | ServiceState::Probing(_)
      )
      && self.lifecycle_deadline.is_some_and(|due| now >= due)
      && flood.in_force(now)
    {
      match self
        .sequence_started_at
        .checked_add_duration(CONFLICT_BACKOFF_MIN_WAIT)
      {
        // Re-armed to the ABSOLUTE floor and NOTHING is enqueued. Absolute, so
        // this costs one re-arm per arm rather than sliding the probe forward
        // every tick the limit stays in force.
        Some(floor) if floor > now => self.lifecycle_deadline = Some(floor),
        // The wait has been served — fall through and probe.
        Some(_) => {}
        // Fail closed, exactly as the regress does: every instant this clock can
        // express is sooner than the wait §8.1 mandates, so there is no deadline
        // that may be armed and no probe that may go out.
        None => {
          self.lifecycle_deadline = None;
          parked = true;
        }
      }
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
          // §8.1's settling window has closed with no conflict: "If, by 250 ms
          // after the third probe, no conflicting Multicast DNS responses have
          // been received, the host may move to the next step, announcing." The
          // deadline that fired already carries whatever §8.3 spacing the third
          // probe's confirm chose, so the announcement goes out on this tick
          // rather than waiting again.
          //
          // Placed ABOVE the general `Probing(n)` arm: `Probing(3)` is a
          // settling state, not a fourth probe, and §8.1 permits exactly three.
          ServiceState::Probing(n) if n >= 3 => {
            debug!(
              target: "mdns_proto::service",
              handle = self.handle.raw(),
              "service: §8.1 settling window closed — Probing(3) → Announcing(0)"
            );
            self.state = ServiceState::Announcing(0);
            // A free step that emits nothing, exactly like `Init → Probing(0)`:
            // the wait this state exists to impose has just been served, and any
            // §8.3 ladder spacing the third probe's confirm chose was served with
            // it, so the announcement is due now and the `Announcing` arm below
            // queues it on the next tick.
            self.lifecycle_deadline = announce_deadline(now, 0);
            false
          }
          ServiceState::Probing(n) => {
            // a probe deadline fired — ENQUEUE the probe and re-arm a
            // fallback retry deadline, but do NOT advance the probe sequence
            // here. The §8.1 progression (next probe, or entering the §8.1
            // settling window after the third) happens in `note_transmit_outcome`
            // ONLY once the driver confirms the probe actually reached the link —
            // mirroring the Announcing arm below. An unconfirmed probe is retried
            // at the probe interval instead of the service silently marching
            // toward Announcing with nothing on the wire (RFC 6762 §8.1: a name
            // must be probed before it is claimed).
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

    // ONE rule, stated once at the one exit the early returns do not take: a
    // service left with nothing armed because a wait the protocol mandates is
    // unrepresentable on this clock is parked, not idle — and a caller that
    // cannot tell the two apart will wait forever for a service that will never
    // move. The conflict block's own returns carry the same verdict up from
    // `restart_probe_cycle`.
    //
    // `parked` covers the commit-point floor above, which can leave a queued
    // RESPONSE behind it — work the driver will still draw, so
    // [`Self::startup_parked`] does not call that service parked even though its
    // probe sequence is. The predicate covers the re-schedule and every other way
    // this method can exit with a startup sequence that owes a probe and has
    // nothing to draw it from, including the wire boundary's drop of a queued
    // first probe on an earlier pass.
    if parked || self.startup_parked() {
      return Err(HandleTimeoutError::Overflow);
    }
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
  pub(crate) fn poll_transmit(
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
      // Expiry is judged against THIS call's `now`, never a cached one, and
      // never on the flag alone — see the field. A known answer that has lapsed
      // by the time the jittered reply is polled suppresses nothing.
      let suppressed = self.meta_known_answered.is_some_and(|until| now < until)
        && self.meta_questioner_srcs.len() == 1;
      self.meta_questioner_srcs.clear();
      self.meta_known_answered = None;
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
    // A §6.7 legacy reply puts the FULL positive-TTL record set on the wire, so
    // it is as much a claim to this name as an announcement. Withheld on the
    // same terms while a conflict is under adjudication; the queue is untouched
    // and drains once the classification is spent.
    if let Some(legacy) = self
      .pending_legacy
      .first()
      .filter(|_| !self.conflict_classified_unresolved())
    {
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
            // §6.7 LEGACY UNICAST: one resolver's ephemeral port, never the
            // group — so these bytes can produce no multicast echo, and the
            // relinquished-history screen must not answer for them.
            Some(e) => Some(AwaitingConfirm::Response(e, 0, SendClass::Unicast)),
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
    // A classified, unresolved conflict withholds EVERY queued datagram of the
    // generation under adjudication — probe included. The queue is left intact —
    // this is a pause, not a drop — and `poll_timeout` reports the service due
    // immediately so the next `handle_timeout` spends the classification and
    // either renames or defers.
    //
    // # Why the probe is no longer excepted
    //
    // "A probe is a question and asserts nothing" is true, and it is not the
    // rule. §8.2 does not tell the loser to stop ASSERTING; it tells it to STOP:
    // "it defers to the winning host by waiting one second, and then begins
    // probing for this record again". A probe queued by `handle_timeout` before
    // the winning proposal arrived is a probe of the generation that just lost,
    // and this method is the only thing standing between it and the wire —
    // `handle_timeout` clears `pending_transmits`, but a permitted call order
    // (queue `Probe`, `handle_event` a winning `ProbeProposal`, `poll_transmit`)
    // reaches the wire first. The loser then keeps probing through the very
    // second it owes, and against a real winner that is a race it may win.
    //
    // Stated as one rule over the whole queue rather than a list of kinds,
    // because the list is what went stale: withholding `Announcement` and
    // `Response` was correct for §8.1's pending rename and simply had no entry
    // for the deferral §8.2 gained. Enumerating what may pass invites the same
    // omission; nothing of a superseded generation may pass.
    //
    // The two things this does NOT gate are unaffected by construction: a §6.7
    // legacy reply is withheld by its own filter above (it is drained before the
    // queue is even peeked), and the §9 meta-PTR is a SHARED record that asserts
    // nothing about this instance.
    if self.conflict_classified_unresolved() {
      trace!(
        target: "mdns_proto::service",
        handle = self.handle.raw(),
        state = ?self.state,
        kind = ?kind,
        "service: withholding a datagram of a generation under §8 adjudication"
      );
      return Ok(None);
    }
    // which owner groups a Response actually emitted (after KAS).
    let mut resp_emitted = respond::EmittedRecords::default();
    // Whether an Announcement's best-effort §6.1 instance NSEC survived into the
    // encoded message — read by the `AwaitingConfirm::Announcement` arm below,
    // which is where an announcement's emitted set is built.
    let mut announce_nsec = false;
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
        let (n, nsec) = respond::write_announce(&self.records, buf).map_err(|_| {
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
        // The §6.1 NSEC is best-effort — `write_announce` rolls it back rather
        // than fail when the buffer is full — so exposure is latched from what
        // the encoder REPORTS, never from the fact that it was asked for.
        announce_nsec = nsec;
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
        let (encoded, emitted) =
          respond::write_announce_filtered(&self.records, buf, |rtype, rdata| {
            if !single_questioner {
              return false;
            }
            let h = hash_rdata(rdata);
            // Expiry is judged against THIS call's `now`, never a cached one. A
            // hint suppresses on the claim that the querier still holds the
            // record, and that claim expires on the clock the caller is holding:
            // a conforming Sans-I/O caller may queue a response and poll it with
            // no `handle_event` or `handle_timeout` in between, so any cached
            // instant can sit arbitrarily far behind the real one and keep an
            // expired hint alive. Over-suppression is the terminal direction —
            // §7.1 licenses withholding only a record the querier still has, and
            // nobody else will send this one — so the parameter is the only
            // admissible reading.
            //
            // A hint may only suppress the RRset it actually names, and a stored
            // hint was already bound to the owner name its rtype sits at — see
            // `respond::emitted_owner_name`, which is what admitted it. So
            // matching the rtype here IS matching the owner, and there is no
            // second classification left to disagree with the first.
            let suppressed = hints.iter().any(|slot| match slot {
              Some(hint) => hint.rtype == rtype && hint.rdata_hash == h && hint.expires_at > now,
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
          announce_nsec,
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
        Some(AwaitingConfirm::Response(
          resp_emitted,
          partial_suppressed,
          SendClass::Multicast,
        ))
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

cfg_heap! {
  /// What a peer's record says about ours: it matches, it differs, we hold no
  /// RRset of that type at all, or it could not be read.
  ///
  /// The last two are the answers that have to exist. Folding "unreadable" into
  /// "differs" is a fail-OPEN default that hands an attacker a rename for the
  /// price of one malformed record, and it is the same class as the two
  /// `.flatten()` defects on this branch — an error becoming an ordinary answer.
  /// Folding "we hold none" into "differs" is the same mistake about ownership
  /// rather than readability.
  #[derive(Debug, Copy, Clone, Eq, PartialEq)]
  enum PeerRdata {
    /// The rdata would not parse or canonicalize. It supports NO conclusion, so
    /// it must reach neither the §8.1 deferral nor the §9 revert.
    Invalid,
    /// We assert NO record of this rrtype at this name, so §9's "same name,
    /// rrtype and rrclass" test has nothing of ours to be inconsistent with.
    ///
    /// Not [`Self::Different`]: differing means we hold that RRset and the
    /// peer's copy of it disagrees. Holding none is a statement about
    /// OWNERSHIP, and folding it into "differs" is what retired an IPv6-only
    /// service over a same-host sibling's A record — an address it never
    /// published and never could.
    ///
    /// Only the HOST path produces it. At the INSTANCE name a type we do not
    /// publish is deliberately `Different`: a probe asks type ANY, so §8.1's
    /// "any conflicting response" covers every type at a name we are claiming.
    /// The host name is not probed at all — see the `HostConflict` arm of
    /// `Service::handle_event` — which is exactly why only §9 governs it.
    UnownedRrtype,
    /// Byte-identical to what we advertise — RFC 6762 §9's "resource records
    /// with identical rdata are never considered inconsistent".
    Identical,
    /// Decoded, and genuinely not ours. Only this may drive a conflict.
    Different,
  }

  impl PeerRdata {
    const fn from_identical(identical: bool) -> Self {
      if identical { Self::Identical } else { Self::Different }
    }
  }
}

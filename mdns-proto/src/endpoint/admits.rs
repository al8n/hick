//! What one inbound datagram is permitted to do, decided once in
//! [`Endpoint::handle`](super::Endpoint::handle) and carried on
//! [`RouteEvents`](super::RouteEvents) so every arm gates on the same answer.

use super::Provenance;

/// Whether this datagram's questions may be ANSWERED, and how widely.
///
/// Two independent things reduce a datagram to defence: an endpoint configured
/// not to answer questions at all, and a datagram this endpoint half-believes it
/// sent itself. They fold into one value here so the routing arm has one local
/// to consult rather than two conditions to combine correctly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Answering {
  /// Every matching question routes to its service — discovery included.
  All,
  /// Only RFC 6762 §8.1's duty: a probe for a UNIQUE name this endpoint already
  /// holds is answered, so a conforming prober cannot take an advertised name.
  /// Discovery questions stay suppressed.
  DefenceOnly,
  /// No question routes anywhere.
  None,
}

/// The permissions one datagram carries, by the duty each one governs.
///
/// # Why four permissions rather than one boolean
///
/// The suppression this replaces was all-or-nothing, so a datagram this endpoint
/// merely SUSPECTED was its own echo silently deleted whatever it carried —
/// including an RFC 6762 §8.2 proposal, an §8.1 defeat or a §9 conflict. Those
/// two mistakes are not symmetric (see [`Provenance`]), and only a split
/// permission can be wrong in the cheap direction on purpose.
///
/// # The table
///
/// | [`Provenance`] | `observation` | `quieting` | `adjudication` | `answering` |
/// |---|---|---|---|---|
/// | `OwnEcho` | deny | deny | deny | `None` |
/// | `OwnEchoLikely` | deny | deny | **allow** | **`DefenceOnly`** |
/// | `NotFromUs` | allow | allow | allow | `All` / `DefenceOnly` |
/// | `Unknown`, heuristic fired | deny | deny | **allow** | **`DefenceOnly`** |
/// | `Unknown`, otherwise | allow | allow | allow | `All` / `DefenceOnly` |
///
/// `untrusted_response` — a QR=1 datagram from a non-5353 source port — is a
/// different trust axis and is ANDed in independently rather than folded into
/// [`Provenance`], because it says nothing about who sent the datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Admits {
  /// RFC 6762 §10 passive cache population, eager query-answer collection, and
  /// the informational `ToQuery` routing that reports it.
  observation: bool,
  /// The two ways another host's traffic QUIETS ours: §7.1 known-answer
  /// suppression, and §7.3 duplicate-question suppression of our own retransmit.
  quieting: bool,
  /// The §8.2 `ProbeProposal` tiebreak, and the §8.1 / §9 `ProbeConflict` /
  /// `HostConflict` paths. The permission whose false NEGATIVE costs a name
  /// permanently.
  adjudication: bool,
  /// Whether questions route to services — see [`Answering`].
  answering: Answering,
}

impl Admits {
  /// Everything denied: nothing about this datagram may reach any state machine.
  const fn nothing() -> Self {
    Self {
      observation: false,
      quieting: false,
      adjudication: false,
      answering: Answering::None,
    }
  }

  /// Everything allowed, with questions answered as widely as the endpoint's own
  /// configuration permits.
  const fn everything(answer_questions: bool) -> Self {
    Self {
      observation: true,
      quieting: true,
      adjudication: true,
      answering: if answer_questions {
        Answering::All
      } else {
        Answering::DefenceOnly
      },
    }
  }

  /// Decide this datagram's permissions.
  ///
  /// `matched_advertised` is the opt-in advertised-source guess
  /// (`EndpointConfig::trust_advertised_src_as_self`), already resolved against
  /// the receiving interface; `untrusted_response` is the §6.7 source-port gate
  /// on QR=1 datagrams.
  pub(crate) const fn for_datagram(
    provenance: Provenance,
    matched_advertised: bool,
    answer_questions: bool,
    untrusted_response: bool,
  ) -> Self {
    let admits = match provenance {
      // Content match, ORDERED against our own `sendto`. Nothing else could
      // have put these bytes on the wire between the send and the stamp, so the
      // claim is as strong as a claim about one's own log gets and everything
      // is suppressed.
      Provenance::OwnEcho => Self::nothing(),

      // ── THE ADJUDICATION CELL ──────────────────────────────────────────────
      //
      // A content match with NOTHING ordering it. A byte-identical datagram from
      // a conforming twin — RFC 6762 §9's fault-tolerance case, "more than one
      // responder … capable of issuing identical answers" — matches exactly this
      // way, so this tier CANNOT be trusted with a name.
      //
      // Suppressing adjudication here costs a name permanently and silently:
      // two conforming hosts both keep it, which is the outcome the whole §8
      // mechanism exists to prevent. NOT suppressing it costs, at worst, §8.2's
      // one-second deferral. The mistakes are not symmetric, so the unsure tier
      // routes to the conflict path.
      //
      // What makes that safe is that our OWN echo, adjudicated as if it were a
      // peer's, is a no-op — and that rests on FOUR invariants, none of them
      // local to this file. Each is recorded with the change that would
      // invalidate it; whoever makes such a change must re-argue this cell.
      //
      //  1. BYTE-SYMMETRY of `service::proposal::our_proposal` with
      //     `service::respond::write_probe`. A QR=0 probe echo folds our own
      //     transmitted bytes against our own comparison list, the two lists
      //     tie, and §8.2.1 calls a tie "there is, in fact, no conflict".
      //     INVALIDATED BY: either side changing what it emits or normalises
      //     without the other — `MessageBuilder::write_name` ceasing to
      //     lowercase, an empty TXT rendered differently, or the addresses
      //     `write_probe` places under the host name moving.
      //
      //  2. The IDENTICAL-RDATA PRECONDITION in `Service::handle_event`, applied
      //     ONCE before every conflict arm. A QR=1 announcement echo carries
      //     rdata identical to ours, so it is dropped as "never a conflict" (§9)
      //     ahead of every arm rather than in some of them.
      //     INVALIDATED BY: moving that classification back inside individual
      //     arms, or admitting a conflict arm that runs before it.
      //
      //  3. A CONFLICT CANDIDATE CARRYING RDATA THIS ENDPOINT RECENTLY
      //     TRANSMITTED AND RELINQUISHED IS LABELLED
      //     `ConflictHistory::Relinquished` BY THE CONFLICT FAN-OUT, and what
      //     that label buys depends on the RECEIVING CELL — on the lifecycle
      //     phase and the consequence together, not on the label alone. The
      //     screen is `Endpoint::relinquished_asserts`, consulted once per
      //     record in `RouteEvents::relinquished_screens`; the spending is
      //     `Service::handle_event`'s.
      //
      //     THE AXIOM "MATCH IMPLIES OURS" IS FALSE, and everything below is
      //     downstream of that. A match says these bytes left this endpoint
      //     recently and were given up. It does NOT say the datagram carrying
      //     them now is ours. A conforming §9 fault-tolerance twin — the case §9
      //     exists to protect, "more than one responder … capable of issuing
      //     identical answers" — publishes byte-identical records BY DESIGN, so
      //     its authoritative defence of the name and our own ghost's echo are
      //     the same datagram at the instant of the lookup. Seven review rounds
      //     hardened this screen's bookkeeping — exposure, rdata form, family,
      //     per-family windows, ceilings — and none of them could harden this,
      //     because it is not a bookkeeping defect. It is a false premise.
      //
      //     WHAT IS UNVERIFIABLE HERE, stated so nobody re-derives it: an
      //     INSTANTANEOUS history lookup cannot learn what only a RE-PROBE can
      //     find out. A ghost cannot answer a probe; a live incumbent can. That
      //     is the only discriminator that exists, it is a fact about the FUTURE,
      //     and no amount of recorded past substitutes for it. Do not add a
      //     field, a window or a tier in the hope of settling provenance from
      //     the record — ask the network.
      //
      //     SO THE CELLS DIFFER, by what a wrong guess costs and whether
      //     anything can revisit it:
      //
      //       * PRE-AUTHORITATIVE INSTANCE (`ProbeConflict`, rows B / B′ of the
      //         conflict matrix): DELIVERED, labelled, and spent as §8.2's
      //         one-second regress — `tiebreak_lost`, same name, re-probe —
      //         instead of §8.1's rename. This is the cell that was broken. It
      //         used to suppress, and suppression is what let a successor B
      //         probe and announce clean over a live incumbent P: A and P assert
      //         identical R1, A relinquishes, B reuses the owner with R2, and
      //         every authoritative R1 defence P sends matches A's history and
      //         is discarded — while B completes probing and announcing well
      //         inside the retention window and nothing replays P's lost
      //         defences at expiry. Deferring instead asks §8.2's own question,
      //         which §8.2 poses for exactly this input ("maybe from the host
      //         itself … echoed back after a short delay by some Ethernet
      //         switches"): against a GHOST the retry goes unanswered and the
      //         name is claimed a second later; against a TWIN INCUMBENT the
      //         retry is answered, and a defence renames us once the label
      //         lapses. §8.1 is honoured late rather than never, and nothing is
      //         claimed in between — `conflict_classified_unresolved` withholds
      //         every claim to the name while the latch is pending.
      //       * ESTABLISHED INSTANCE (`ProbeConflict`, row C): DELIVERED, and
      //         the label buys NOTHING — §9's revert-to-probing runs exactly as
      //         it would on an unlabelled record, on the same name and behind
      //         `CONFLICT_REPROBE_MIN_INTERVAL`. This cell DROPPED the record
      //         for one round, recorded here as a deliberate non-change on the
      //         premise that §9 self-heals because a live incumbent's traffic
      //         recurs. THAT PREMISE WAS FALSE, and §8.3 is what falsifies it: a
      //         conforming responder announces AT LEAST TWICE, one second apart,
      //         MAY continue to eight times with the interval at least doubling
      //         each time, and is then SILENT until something queries it. A
      //         screen that consumes a burst landing wholly inside the retention
      //         window consumes EVERY COPY THERE WAS, and nothing replays a
      //         conflict when the window lapses — so §9's "MUST
      //         immediately reset its conflicted unique record to probing state"
      //         was not honoured late, it was not honoured at all, and duplicate
      //         ownership of an ADVERTISED name stood until unrelated traffic
      //         happened to arrive. Nor was the cell hard to reach: packet loss
      //         over the successor's probes is enough to let it finish, and the
      //         incumbent's next response then lands in row C instead of row B.
      //         What our own delayed echo costs instead is that revert — one
      //         rate-limited re-verification of a name we still hold, claiming
      //         nothing while it runs, ending in a re-announcement because a
      //         ghost cannot answer the re-probe. It cannot cost the name:
      //         `probe_defeated` is the only path to a rename and the
      //         pre-authoritative cell never latches it on a labelled record.
      //       * HOST (`HostConflict`, every row): DROPPED, in the router, and
      //         the screen stays fully load-bearing there. The consequence is
      //         TERMINAL and caller-visible, and THE HOST NAME IS NEVER PROBED —
      //         so there is no re-probe whose silence could convict a ghost, and
      //         no cheap reversible move to spend the label on. When host-name
      //         probing lands, this cell must be re-argued: it is the one place
      //         the false axiom is still being relied on, and it is relied on
      //         only because nothing better exists yet.
      //         WHAT IS DROPPED IS THE EVENT, NOT THE RECORD, and the two are
      //         only the same thing while one name wears one role. The fan-out
      //         tests the host rule first, so where a route's INSTANCE name IS
      //         its host name a labelled A/AAAA matched the host branch and left
      //         the loop — and A/AAAA under that name are members of the §8.2
      //         proposal that service is probing with, which §8.1 owes a
      //         deferral on as "any conflicting Multicast DNS response". A live
      //         incumbent answering every probe was therefore discarded by role
      //         precedence while the successor ran to Established: the
      //         pre-authoritative usurpation again, entered through the other
      //         door. So a labelled record whose owner is also the route's
      //         instance name FALLS THROUGH to the instance rule and is
      //         delivered as a labelled `ProbeConflict`; a route with no second
      //         role to fall through to is skipped as before. Precedence chooses
      //         which EVENT a record becomes and may not decide it is no
      //         conflict at all.
      //         AND THE FALL-THROUGH CARRIES THE HOST ROLE WITH IT
      //         (`ConflictRole::InstanceAndHost`), because THIS CELL'S OWN
      //         PREMISE IS FALSE FOR THIS OWNER. "The host name is never probed"
      //         is what licenses the drop; when the host name IS the instance
      //         name it is being probed, by an ANY question proposing exactly
      //         these A/AAAA, so the re-verification the host cell lacks already
      //         exists here and §9's reversible same-name reset can spend it.
      //         Suppressing the host CONSEQUENCE does not unprove the host
      //         AUTHORITY — the route publishes an RRset of that rrtype at that
      //         name, which is §9's "currently authoritative" in as many words —
      //         and delivering the record stripped of it made the two lifecycle
      //         cells disagree about the same datagram: rows B / B′ deferred on
      //         it, while row C asked `canonical_rdata_forms` (SRV, TXT, NSEC —
      //         never an address) whether we assert it and dropped it silently.
      //         Handled while probing, discarded once announced, and a live
      //         incumbent's whole BOUNDED §8.3 burst consumed in between. So the
      //         role travels with the record, the identical-rdata precondition
      //         classifies it as a HOST record (an address we publish is §9's
      //         "never inconsistent", which the instance classifier cannot even
      //         read), and row C's instance-authority gate is not asked of it.
      //
      //     TRANSMITTED, not merely configured, and the distinction is the
      //     invariant's own boundary: the screen answers only for the record
      //     IDENTITIES a confirmed positive authoritative send actually emitted
      //     (`Service`'s `GoodbyeOwnership` latch, carried on
      //     `WithdrawalSnapshot` / `RenameGoodbyeHandoff`). A record no
      //     transport accepted has no echo of ours to disown, so retaining it
      //     could only discard a GENUINE incumbent's records and let a same-name
      //     successor announce over a peer that already holds the name — the
      //     opposite error, and the worse one. A relinquishment with no exposure
      //     at all therefore retains nothing.
      //     AND TRANSMITTED BY MULTICAST, which is where the exposure record
      //     stops being one fact and becomes two. "A peer may hold this record
      //     FROM US" and "a copy of these bytes may still be ECHOING" were one
      //     latch, and an RFC 6762 §6.7 LEGACY REPLY separates them: it is a
      //     confirmed positive send of the FULL record set, so the first is true
      //     of it and the §10.1 goodbye owes it a retraction — and it is
      //     addressed to ONE resolver's ephemeral port, so the second is not,
      //     because nothing re-broadcasts it to the group and this screen is
      //     only ever asked about a MULTICAST arrival. A service whose only
      //     positive send was such a reply therefore has no echo of its own
      //     anywhere, and a row built from the wider fact disowned a GENUINE
      //     peer's multicast A/AAAA — suppressing the host conflict for the
      //     whole window — on the strength of bytes no multicast socket ever
      //     carried. So `GoodbyeOwnership` keeps BOTH halves, every layer the
      //     exposure crosses carries both, and only the narrower one reaches
      //     this screen. The two are not interchangeable in either direction:
      //     narrowing the goodbye's half would strand records in a legacy
      //     querier's cache that nothing ever retracts.
      //
      //     THE REST OF THE CLAIM, AND WHAT HOLDS IT UP. This screen's answer
      //     means "these exact bytes left this endpoint, on this family, by
      //     multicast, in this generation, in this section, with this
      //     cache-flush bit, and could still be echoing". Six qualifiers have
      //     been added to it in five rounds — configured vs transmitted, which
      //     family, whose, which destination class, which section, which
      //     cache-flush bit — each because the record had claimed something it
      //     could not justify. The dimensions BELOW are the ones where it still
      //     could, and they are written down because three of them are true only
      //     by an assumption made somewhere else:
      //
      //       * INTERFACE, and its IPv6 SCOPE half. The exposure's finest
      //         spatial grain is `[v4, v6]`. `Transmit` carries no interface
      //         (`src_ip` is `None` at every construction in this crate),
      //         `TransmitDelivery` is two `FamilyDelivery`s, and
      //         `EmittedRecords::aaaa` is a bare `Ipv6Addr` list even though
      //         `ServiceRecords` knows each AAAA's scope id. The ARRIVAL side
      //         knows more than the screen is told: `Received::interface_index`
      //         reaches `Endpoint::handle` from PKTINFO and feeds ONLY
      //         `src_matches_advertised` — `RouteEvents` is never given it, so
      //         the screen reads `Family::of(src)` alone. This is sound TODAY
      //         only because each family is one socket, which is a modelling
      //         limitation and not a fact about mDNS. The moment a driver joins
      //         the group on two interfaces per family, a record sent on one
      //         link disowns an arrival on the other that cannot be its echo,
      //         and closing it is a TWO-SIDED change: the send side must record
      //         a link and the receive side must carry the one it already has.
      //       * TIME, in the SOURCE-1 half. Sources 2 and 3 test their own
      //         expiry; the resident-withdrawal-item source does not, so an item
      //         screens for its whole residency. That is bounded by
      //         `WITHDRAWAL_CEILING` plus however long the driver takes to call
      //         `drain_completed_withdrawals` — a CALLER contract, not a bound
      //         this module holds. A driver that stops draining leaves an item
      //         screening past any window.
      //       * TTL, which the canonical rdata form deliberately excludes, so a
      //         §6.7-capped record and an announced one are byte-identical here.
      //         That is right — §9's rule is over rdata — but it also means a
      //         TTL=0 goodbye echo of our own bytes compares EQUAL, and what
      //         stops it reaching this screen is the routing iterator's TTL=0
      //         drop, three sites upstream, not anything here.
      //       * PROBE vs ANNOUNCEMENT is already NARROWER than the claim, and
      //         should stay so: `AwaitingConfirm::Probe` latches no exposure, so
      //         `write_probe`'s Authority SRV / TXT / A / AAAA are outside this
      //         record entirely. The resulting under-claim — our own probe echo
      //         is never screened — is harmless because of invariant 1's
      //         byte-symmetry on the instance half and the `HostConflict` arm's
      //         `ConflictOrigin` gate on the host half, NOT because of anything
      //         here. The envelope below now makes the same under-claim TWICE
      //         over, since no rrtype is inside it in the Authority section, and
      //         `the_envelope_is_the_one_the_encoders_actually_write` pins that
      //         from the probe's side — but the reason it is harmless is still
      //         the one above.
      //
      //     AND IN THE WIRE ENVELOPE THE ENCODER WROTE — the SECTION, and the
      //     RFC 6762 §10.2 CACHE-FLUSH BIT. Both were open, both are now
      //     enforced, and they are one qualifier in one place:
      //     `respond::transmitted_envelope`, kept beside
      //     `transmitted_rdata_forms` because "what this endpoint transmitted"
      //     gets ONE description. `relinquished::asserts` and
      //     `relinquished::identity_asserts` both ask it, so the two tiers
      //     cannot answer differently, and `RouteEvents::relinquished_screens`
      //     supplies the section off the SAME `RecordSlot` it caches under.
      //     THE RULE IT ENFORCES: a class-IN record is this endpoint's echo only
      //     if it arrives in the section this crate writes that rrtype in — the
      //     ANSWER section for SRV / TXT / A / AAAA, the ADDITIONAL section for
      //     the §6.1 instance NSEC, and no rrtype in the AUTHORITY section at
      //     all — carrying the cache-flush bit those encoders set.
      //     NEITHER CAN REJECT A REAL ECHO, which is why the narrowing is free.
      //     An echo is a re-DELIVERY of a datagram, not a re-encoding of it: the
      //     header counts that place a record in its section are ours and the
      //     bit is bit 15 of the record's own class field, so a genuine echo
      //     arrives in the section we wrote it in with the bit we set. A
      //     mismatch therefore says "not our echo", and the two readings of that
      //     agree — a conforming responder bundling its address into Additional
      //     beside the SRV (RFC 6763 §12's own advice, and ordinary browse
      //     traffic), or something that RE-ENCODED our bytes, which is a §9 twin
      //     or a replaying peer and may not be disowned either.
      //     WHAT THE SECTION HALF COST WHILE IT WAS OPEN: the terminal
      //     `HostConflict`, on ordinary traffic and with no crafted case. QR=1
      //     conflict routing walks Answer, Authority AND Additional into
      //     `next_service_conflict`, and the host cell SUPPRESSES rather than
      //     labels, so a peer's Additional-section A at our relinquished address
      //     raised nothing at all for the whole retention window. The
      //     cache-flush half ranks below it only because exploiting that one
      //     needs a peer that declines to set a bit §10.2 asks it to set.
      //     AND ONE OF THE TWO IS TRUE BY RULE, THE OTHER BY ACCIDENT, which is
      //     the distinction a future change breaks first. The NSEC's section is
      //     a rule with one home: `push_service_nsec` is the builder's only
      //     `push_nsec_additional` caller and both positive multicast encoders
      //     go through it. That A / AAAA / SRV / TXT are ANSWERS is an ACCIDENT
      //     of how `write_announce` and `write_announce_filtered` happen to be
      //     written — RFC 6763 §12 positively recommends the Additional-section
      //     bundle this crate declines to write, so the day an encoder adopts it
      //     the description must move with it. `the_envelope_is_the_one_the_
      //     encoders_actually_write` runs both encoders and puts every record
      //     they emit to the envelope at the section it actually landed in, so
      //     the accident fails a test rather than silently losing the screen.
      //     THE DESCRIPTION IS DERIVED FROM THE RRTYPE, NOT STORED PER ROW, and
      //     that is deliberate: the exact tier keeps a whole `ServiceRecords`
      //     plus `EmittedRecords` and has nowhere to put a per-identity section,
      //     so storing one in the compact tier alone would let the two tiers
      //     disagree about the same generation — the error this invariant
      //     forbids by name. The cost is that an encoder change applies
      //     RETROACTIVELY to rows retained before it, for at most one retention
      //     window; that is the change's own re-argument to make, and it is
      //     listed below.
      //     AND IN THE EXACT RDATA FORM THE ENCODER WROTE, which is the same
      //     boundary one dimension further in and the place the two screens part
      //     company. The exposure says which RRTYPES went out; it does not say
      //     which SPELLING of one, and `respond::canonical_rdata_forms` names
      //     more than one for NSEC on purpose — the accurate `{SRV, TXT, A,
      //     AAAA}` bitmap a CONFORMING responder publishes where the instance
      //     name is also the host name, which this crate's encoder never writes.
      //     Accepting it is right for the LIVE classifier, which asks whether a
      //     peer's record is CONSISTENT with what we publish now and must not
      //     rename a §9 fault-tolerance twin that is merely more correct than we
      //     are. History asks something narrower and purely factual — these
      //     exact bytes left this endpoint, on this family, in this generation —
      //     and a form we never encoded did not. So both tiers read
      //     `respond::transmitted_rdata_forms`, the history half of that
      //     function, and the leniency stops at the classifier. Expanding an
      //     exposure BOOLEAN through the live list converts semantic
      //     compatibility into wire provenance, and a genuine twin's conforming
      //     NSEC read as an old self-echo withholds the decisive §8.1 / §9
      //     conflict against a successor for the whole window.
      //     AND TRANSMITTED ON THE FAMILY THE CANDIDATE ARRIVED ON. Exposure is
      //     a `[v4, v6]` pair at every layer it crosses — the latch, the
      //     snapshot, the rename handoff, the withdrawal item, the retained row
      //     and its compact identity — and the screen reads only the arriving
      //     family's half. A multicast datagram travels back over a socket that
      //     carried it out, so a generation IPv4 accepted and IPv6 refused can
      //     hold no IPv6 echo, and an aggregate answering for both would silence
      //     a GENUINE peer's §8.1 or §9 conflict purely for agreeing with a
      //     transmission that family never saw. A fan-out is two sends and
      //     either may be refused, so that is an ordinary partial round rather
      //     than an exotic case — the same fact `hick-smoltcp`'s `sent_on` mask
      //     keeps one layer down, for the same reason.
      //     AND FOR AS LONG AS THAT FAMILY'S OWN WINDOW LASTS, which is a
      //     SECOND per-family fact and only the compact tier has to carry it.
      //     An exact row is one generation given up at one instant, so its two
      //     halves lapse together and one expiry states that correctly; a
      //     compact identity MERGES ACROSS GENERATIONS on `(owner, rrtype,
      //     rdata)`, a key that says nothing about when or where, so the same
      //     rdata retained first from IPv4 and later from IPv6 is one row
      //     describing two transmissions with two deadlines. A single expiry
      //     beside a presence mask writes the later one onto both families, and
      //     an IPv4 peer asserting that rdata after the IPv4 generation's window
      //     closed was still disowned — the two tiers then disagreeing about the
      //     same generations. The window therefore lives IN the mask:
      //     `[Option<I>; 2]`, `None` for a family that never carried the
      //     identity, and a merge may only ever extend the half its own
      //     generation reached.
      //     A WITHDRAWAL ITEM'S EXPOSURE MAY NARROW, and only narrow. A
      //     reclaimable detached item trims to the shared records a same-name
      //     replacement's announcement cannot supersede, so it answers for less
      //     than it once emitted; what it stops answering for, the row
      //     `Endpoint::enqueue_rename_withdrawal` retained at the RENAME still
      //     holds, which is why that retain is unconditional and taken before
      //     the item exists. The direction is the whole of the argument — an
      //     exposure that claimed MORE than a confirmed send emitted is the
      //     error this invariant forbids.
      //     Invariant 2 holds only while our records have not changed under a
      //     recorded send, and a self-echo that outlives such a change IS
      //     reachable — not through RFC 6762 §8.4 record updating, which is
      //     unimplemented, but through SERVICE REPLACEMENT, which crosses
      //     generations rather than mutating one. A withdrawing route is skipped
      //     by the host address-set guard on purpose (invariant 4), so a
      //     replacement may take host `H` with address set `A2` while the route
      //     that held `H` with `A1` is still draining its §10.1 goodbye. A
      //     delayed positive-TTL echo of `A1` carries rdata no live route holds,
      //     so invariant 2 does not stop it; the withdrawing route is skipped by
      //     every conflict fan-out too, leaving the REPLACEMENT as its only
      //     recipient and a TERMINAL `ServiceUpdate::HostConflict` as the
      //     result. Same-instance reuse with changed SRV/TXT reaches a false
      //     §8.1 probe defeat the same way.
      //     Invariant 3 is that gap closed WHERE §9 already put the rule:
      //     "identical rdata is never a conflict", asked of the sets this
      //     ENDPOINT recently published as well as of the receiving service's
      //     own. Service B structurally cannot know that `A1` was ours; only the
      //     endpoint can, so the endpoint STATES it — over withdrawal items
      //     still resident and a retention list of what has lapsed, ONE ROW PER
      //     RELINQUISHED GENERATION, each living to its own expiry. See the
      //     `endpoint::relinquished` module. Stating is all it does: the endpoint
      //     cannot see lifecycle state, so it labels and the service decides,
      //     which is what keeps one fact from being read as three different
      //     decisions.
      //     THE LIST'S CEILING DROPS NOTHING AND DISABLES NOTHING. Every live
      //     row is an obligation still owed, so reaching
      //     `MAX_RELINQUISHED_RRSETS` evicts none of them; the relinquishment is
      //     recorded COMPACTLY instead, decomposed into the `(owner name,
      //     rrtype, canonical rdata)` identities it transmitted — each carrying
      //     the window PER FAMILY, since that tier merges generations and their
      //     windows are not shared — which is the whole of what this screen ever
      //     asks. THE DEGRADATION IS BOUNDED TO
      //     THE IDENTITY THAT COULD NOT BE RECORDED: at
      //     `MAX_RELINQUISHED_IDENTITIES` the identities that do not fit are not
      //     recorded and nothing already held is disturbed. An endpoint-wide
      //     fallback is forbidden here and the argument is one of SCALE, not of
      //     kind — this cell held a quarantine that answered `true` for every
      //     candidate once the ceiling was reached, and withholding one
      //     generation's conflicts risks that generation while withholding every
      //     conflict guarantees false negatives at every name the endpoint
      //     holds, including names it could still have adjudicated perfectly
      //     well. On-link peers set the relinquishment rate through §9 re-probes
      //     and §8.1 renames, which carry no fifteen-in-ten-seconds backoff, so
      //     "fill the table, then probe over an incumbent" was reachable.
      //     Neither ceiling is a name-reuse embargo — registration and rename are
      //     untouched — and neither pauses §8.2 or the §8.1 defence, since
      //     neither consults the screen.
      //     THE DRIVER-SIDE GENERATION BINDING IS NOW DEFENCE IN DEPTH, NOT THE
      //     LOAD-BEARING MECHANISM, and moving the weight off it was the point.
      //     Every driver-side RECOGNITION of such an echo is defeasible, three
      //     ways, none of which the crate can bound: a replaying on-link peer
      //     reproduces every signal a send log weighs (family, exact bytes,
      //     source port 5353, age — and a kernel receive stamp adds none, since
      //     it only rejects arrivals BEFORE our send); one send is credited once
      //     per family while the medium may deliver several copies, so the copy
      //     that loses the race reads `NotFromUs` with no attacker involved; and
      //     recognition state is evicted under traffic while the obligation is
      //     per copy. Three consecutive rounds patched recognition and each left
      //     the class open. This invariant depends on none of it.
      //     STILL OPEN: an in-place record update is a SECOND route to a
      //     self-echo carrying rdata we no longer hold. It does not cross a
      //     lifecycle seam, so nothing feeds the screen for it. Implementing
      //     §8.4 must call `Endpoint::retain_relinquished` with the superseded
      //     set, and must re-argue this cell rather than merely add the API.
      //     INVALIDATED BY: a relinquishment that reaches none of
      //     `Endpoint::drain_completed_withdrawals`,
      //     `Endpoint::enqueue_rename_withdrawal` or
      //     `Endpoint::unregister_service` — a new teardown path that frees a
      //     route without draining its withdrawal item, or a rename whose
      //     old-name handoff is not enqueued; a conflict event built
      //     anywhere other than `RouteEvents::next_host_conflict` /
      //     `next_service_conflict`, which are the two sites that consult the
      //     screen; THE LABEL BEING SPENT AS A SUPPRESSION IN THE
      //     PRE-AUTHORITATIVE INSTANCE CELL AGAIN — a `ProbeConflict` dropped
      //     for carrying `ConflictHistory::Relinquished`, whether in the router
      //     or in `handle_preauthoritative_conflict`, restores the usurpation
      //     this cell was rewritten to close; THE HOST BRANCH OF
      //     `next_service_conflict` CONSUMING A LABELLED RECORD THAT IS ALSO THE
      //     ROUTE'S INSTANCE NAME — a `continue` taken there without first asking
      //     `names_match_record(route.name(), r)` restores that same usurpation
      //     through role precedence, which is a suppression wearing an
      //     ordering's clothes; the same cell latching
      //     `probe_defeated` rather than `tiebreak_lost` on a labelled record,
      //     which renames on a switch echo and gives up the name §8.2 keeps; THE
      //     ESTABLISHED INSTANCE CELL SCREENING ON THE LABEL AGAIN — a
      //     `ProbeConflict` dropped, deferred, or exempted by any other means in
      //     the `Announcing | Established` arm for carrying
      //     `ConflictHistory::Relinquished`, which withholds §9's immediate
      //     reset from a peer whose §8.3 burst is BOUNDED and never repeated, so
      //     the retention window swallows the conflict entire rather than
      //     delaying it; the §8.2 deferral ceasing to hold the name — the bound
      //     on the labelled loop is the retention window lapsing, not the peer
      //     falling silent, and it is only safe because
      //     `conflict_classified_unresolved` claims nothing while it runs; a
      //     retention window (`EndpointConfig::relinquished_retention`)
      //     shorter than the driver's own self-send recency window, which would
      //     leave a stretch where the echo is neither recognised nor screened;
      //     `relinquished::asserts` drifting from
      //     `Service::classify_host_rdata` / `classify_instance_rdata`, so that
      //     one of the two answers "ours" and the other "differing" for the same
      //     record; a record type gaining a `respond::canonical_rdata_forms` arm
      //     without the matching `respond::instance_rtype_exposed` row,
      //     `respond::INSTANCE_CANONICAL_RTYPES` entry or
      //     `respond::transmitted_rdata_forms` arm, any of which silently drops
      //     that type out of one of the two tiers; EITHER TIER READING A FORM
      //     THIS CRATE DOES NOT ENCODE — `relinquished::asserts` or
      //     `relinquished::identities` reaching `canonical_rdata_forms` instead
      //     of `transmitted_rdata_forms`, `transmitted_rdata_forms` widening to
      //     a form `write_announce` / `write_probe` / `push_service_nsec` never
      //     writes, or `respond::emitted_nsec_identity` drifting from the bitmap
      //     `push_service_nsec` actually emits; EITHER TIER READING AN ENVELOPE
      //     THIS CRATE DOES NOT WRITE — `respond::transmitted_envelope` widened
      //     to a section or a cleared cache-flush bit no positive MULTICAST
      //     encoder produces (a §6.7 legacy reply clears the bit, and it is
      //     outside the exposure this screen reads for a different reason
      //     already), a call site passing the ITERATOR's `section` phase in
      //     place of the visited record's own `RecordSlot::section`, or
      //     `asserts` / `identity_asserts` ceasing to ask it, which un-narrows
      //     one tier and makes the two disagree; AN ENCODER MOVING A
      //     SCREEN-ELIGIBLE RECORD BETWEEN SECTIONS OR DROPPING ITS CACHE-FLUSH
      //     BIT WITHOUT MOVING `transmitted_envelope` WITH IT — `write_announce`
      //     or `write_announce_filtered` adopting RFC 6763 §12's
      //     Additional-section address bundle, or a second
      //     `push_nsec_additional` call site appearing, either of which stops
      //     the screen recognising this endpoint's own echo (and note the
      //     description is per RRTYPE, so the change applies retroactively to
      //     rows already retained, for up to one retention window);
      //     `relinquished::
      //     identities` decomposing a set into anything but what
      //     `relinquished::asserts` would have answered for, which makes the
      //     tiers disagree about the same generation; the exposure inputs
      //     ceasing to mean "confirmed emitted BY MULTICAST ON THAT FAMILY" —
      //     `GoodbyeOwnership` latching from anything but a delivered send, a
      //     latch keyed on `TransmitDelivery::any_delivered` rather than
      //     `delivered_on`, any layer collapsing the `[v4, v6]` exposure pair
      //     back into one aggregate, or a screen call site that does not pass
      //     the ARRIVING datagram's family — or a retain site passing a
      //     CONFIGURED record set in place of the snapshot's; THE TWO EXPOSURE
      //     HALVES BEING COLLAPSED BACK INTO ONE — a screen or retain site
      //     reading `WithdrawalSnapshot::owned` / `RenameGoodbyeHandoff::owned`
      //     / `WithdrawalItem::owned` where it owes the `multicast` half, a
      //     `SendClass` derived from lifecycle state rather than carried on the
      //     commit token that named the destination, a positive send stamping
      //     `SendClass::Multicast` for a datagram not addressed to the group, or
      //     the goodbye's half narrowed to the screen's, which strands a legacy
      //     querier's cached records with nothing to retract them; A COMPACT
      //     IDENTITY'S PER-FAMILY WINDOW reduced to one expiry — whether beside
      //     a presence mask or on its own — or a merge that writes a
      //     generation's expiry onto a family that generation did not reach, or
      //     a compaction that drops a row still live on ONE family; the retention
      //     list dropping an UNEXPIRED row again, whether by merging two
      //     generations onto one owner pair or by evicting at the ceiling; or
      //     ANY capacity path answering for a record it cannot name — an
      //     eviction that lets a peer pick the victim by filling the table, or a
      //     return to an endpoint-wide fallback; or A DRIVER MAPPING A SUPERSEDED
      //     CREDIT BACK TO `Provenance::OwnEcho` — `hick-smoltcp`'s
      //     `SelfLog::Superseded`, or `SelfSendMatch::Superseded` in `hick-mio`,
      //     `hick-compio` and `hick-reactor` — which re-imposes the false axiom
      //     one layer below this file, where nothing here can see it, and for
      //     every copy rather than one.
      //     The driver-side binding — a credit bound to the record generation it
      //     was sent under, and a superseded credit KEPT rather than discarded —
      //     is still owed, and still documented on `Provenance::OwnEchoLikely`.
      //     What it buys now is the second half of the harm: a stale echo that
      //     reaches this arm also POPULATES THE CACHE with records we no longer
      //     publish and QUIETS our own traffic, and invariant 3 governs
      //     adjudication only. Losing it re-opens that, not the terminal
      //     conflict.
      //     AND IT BUYS EXACTLY THAT, WHICH IS WHY A SUPERSEDED CREDIT REPORTS
      //     `OwnEchoLikely` AND NOT `OwnEcho`. THE FALSE AXIOM ABOVE HAS A
      //     DRIVER-SIDE TWIN, and it is the same sentence: a byte match proves
      //     CONTENT, not origin. A superseded entry is deliberately
      //     non-consuming, so reporting it as `OwnEcho` denied observation,
      //     quieting, adjudication AND the §8.1 defence to EVERY copy of those
      //     bytes for the credit's whole lifetime — and an old local responder
      //     and a live §9 twin publish them alike, while a peer may simply replay
      //     them. A successor could then finish probing while an incumbent's
      //     defences were being deleted one layer below this file. The tier a
      //     content match earns is `OwnEchoLikely` whatever generation it
      //     matched, because staleness is a fact about OUR records and not
      //     evidence about the sender: it may buy the denials that protect US and
      //     not the one that costs a PEER its name. What `OwnEcho` used to stand
      //     in front of — our own withdrawn generation terminally retiring the
      //     service that replaced it — this invariant already holds, and holds
      //     better: the labelled `HostConflict` is dropped in the fan-out and the
      //     labelled pre-authoritative instance conflict defers instead of
      //     renaming, both on local lifecycle rather than on recognition. Two
      //     mechanisms were doing one job and only one of them could do it
      //     correctly.
      //     WHY THAT IS SAFE, stated as the check rather than the conclusion: a
      //     stale self-echo reaching adjudication under `OwnEchoLikely` reaches
      //     no irreversible outcome. The terminal `ServiceUpdate::HostConflict`
      //     needs a QR=1 positive-TTL A/AAAA at a live route's host name — a
      //     goodbye is TTL=0 and the fan-out drops it, and a QR=0 probe echo
      //     carries `ConflictOrigin::TentativeProbe`, which the `HostConflict`
      //     arm ignores — so it needs an ANNOUNCEMENT echo, whose generation
      //     either is still published (invariant 2 drops it as identical) or was
      //     relinquished under a confirmed send (invariant 3 labels it and the
      //     fan-out drops it). `ServiceUpdate::Renamed` and the terminal
      //     `Conflicting` are both reached only through `probe_defeated`, which a
      //     labelled record never latches. What is left is §8.2's regress and
      //     §9's re-verify — same name, reversible, claiming nothing while
      //     pending — and one redundant truthful §8.1 defence.
      //
      //  4. Two live routes sharing a HOST NAME publish the SAME address set FOR
      //     EACH RRTYPE THEY BOTH PUBLISH — enforced at registration and rename
      //     by `Endpoint`'s host address-set guard — and a route publishing no
      //     record of an RRtype receives no conflict for that type at all, in
      //     the routing fan-out and in `Service::classify_host_rdata` alike.
      //     Without BOTH halves, a sibling service's echoed announcement reaches
      //     THIS service as an A/AAAA at its own host name with rdata it does not
      //     hold — invariant 2 does not save it, because the classifier compares
      //     against the RECEIVING service's records — and surfaces a TERMINAL
      //     `ServiceUpdate::HostConflict` on every sibling echo. §9 scopes the
      //     conflict by rrtype, so the guard cannot be tightened to a
      //     whole-address-set match without banning the legitimate
      //     IPv4-only-plus-IPv6-only pair, and cannot be relaxed per rrtype
      //     without the fan-out's matching half.
      //     INVALIDATED BY: relaxing either half, or adding any path that lets a
      //     live route's host name or address set change without re-checking it.
      //
      // ANSWERING stays open to defence for the reason §8.1 gives: "it is
      // important that when a device receives a probe query for a name that it
      // is currently using, it SHOULD generate its response to defend that name
      // immediately". Wrongly defending against our own probe is ZERO HARMFUL
      // false positives rather than zero: our own probe's question reaches our
      // own service only while it is `Probing`, and the `Question` arm requires
      // `Established | Announcing`. Two benign residuals remain — a probe echo
      // processed after the `Probing(3)` → `Announcing` transition makes the
      // service answer its own probe (one redundant truthful response, no state
      // effect), and the pathological configuration where one service's host
      // name IS another's instance name.
      //
      // OBSERVATION and QUIETING are denied, and that asymmetry is the point: a
      // false positive there poisons our own cache with our own records and lets
      // our own echo defer our own query's retransmit. Those are the two places
      // where believing a peer is the MORE harmful error, so the unsure tier
      // errs the other way in each.
      Provenance::OwnEchoLikely => Self {
        observation: false,
        quieting: false,
        adjudication: true,
        answering: Answering::DefenceOnly,
      },

      // A negative claim about the caller's own send log, and a better one than
      // any source-address guess — so `matched_advertised` is deliberately NOT
      // consulted. `src_matches_advertised` matches any co-resident host
      // publishing an address we publish, INCLUDING a peer that has taken it.
      Provenance::NotFromUs => Self::everything(answer_questions),

      // The caller has nothing to say, so the opt-in heuristic is all there is.
      Provenance::Unknown => {
        if matched_advertised {
          Self {
            observation: false,
            quieting: false,
            // ADJUDICATION SURVIVES THE HEURISTIC. Everything else it decides is
            // a convenience — a cache write not made, a retransmit not deferred
            // — but a deleted §8.2 proposal is a name lost permanently. A
            // source-address guess must not be able to buy that, so this cell
            // allows adjudication whatever the guess says.
            adjudication: true,
            // AND SO DOES THE §8.1 DEFENCE, for the same reason and by the same
            // rule as the `OwnEchoLikely` row above: "when a device receives a
            // probe query for a name that it is currently using, it SHOULD
            // generate its response to defend that name immediately".
            //
            // This guess is WEAKER than that row's evidence, not stronger. It
            // matches any co-resident host publishing an address we publish, so
            // a second responder on this machine shares the source address and
            // its legitimate probe lands here. `Answering::None` skipped that
            // probe's question entirely; the QR=0 proposal riding with it has no
            // conflict effect on an ESTABLISHED service — §8.2 is the
            // pre-authoritative path — so nothing else stopped the peer, and it
            // finished probing onto a name we already hold.
            //
            // Defending when we should not have is at worst one redundant
            // truthful response: `DefenceOnly` releases nothing but a probe for
            // a UNIQUE name we already own, and our own probe's question reaches
            // our own service only while it is `Probing`, which the `Question`
            // arm does not answer. Discovery stays suppressed either way.
            answering: Answering::DefenceOnly,
          }
        } else {
          Self::everything(answer_questions)
        }
      }
    };
    // The independent axis, ANDed in last so the all-denied test below sees the
    // final answer. A response from an ephemeral source port is an off-path /
    // legacy-unicast artifact whatever its provenance says.
    if untrusted_response {
      Self::nothing()
    } else {
      admits
    }
  }

  /// Whether every permission is denied, so this datagram can produce no effect
  /// at all.
  ///
  /// It is a WHOLE-DATAGRAM reject: `Endpoint::handle` bumps `packets_dropped`
  /// and skips the section-validation latch on exactly this condition, and the
  /// routing iterator starts pre-drained rather than walking four sections that
  /// can yield nothing. That fast path is not an optimisation to weigh — an
  /// endpoint whose driver has no source-port gate of its own reaches this arm
  /// from the network.
  pub(crate) const fn all_denied(&self) -> bool {
    !self.observation
      && !self.quieting
      && !self.adjudication
      && matches!(self.answering, Answering::None)
  }

  /// RFC 6762 §10 cache population and query-answer collection.
  pub(crate) const fn observation(&self) -> bool {
    self.observation
  }

  /// RFC 6762 §7.1 known answers and §7.3 duplicate-question suppression.
  ///
  /// No row of the table separates this from [`Self::observation`] — both are
  /// the "believe what this datagram says about the link" half, and every row
  /// denies or allows them together. They are named apart because the DUTIES are
  /// different: one populates a cache, the other silences this endpoint. A later
  /// tier can move one without rediscovering which call sites meant which.
  pub(crate) const fn quieting(&self) -> bool {
    self.quieting
  }

  /// RFC 6762 §8.2 proposals and §8.1 / §9 conflicts.
  pub(crate) const fn adjudication(&self) -> bool {
    self.adjudication
  }

  /// How widely this datagram's questions may be answered.
  pub(crate) const fn answering(&self) -> Answering {
    self.answering
  }
}

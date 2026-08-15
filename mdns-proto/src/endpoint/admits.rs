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
      //  3. EVERY DATAGRAM THIS ARM MAY TREAT AS OUR OWN ECHO WAS SENT UNDER
      //     THE RECORD GENERATION THIS ENDPOINT STILL PUBLISHES. Invariant 2
      //     holds only while our records have not changed under a recorded
      //     send, and a self-echo that outlives such a change IS reachable —
      //     not through RFC 6762 §8.4 record updating, which is unimplemented,
      //     but through SERVICE REPLACEMENT, which crosses generations rather
      //     than mutating one. A withdrawing route is skipped by the host
      //     address-set guard on purpose (invariant 4), so a replacement may
      //     take host `H` with address set `A2` while the route that held `H`
      //     with `A1` is still draining its §10.1 goodbye. A delayed
      //     positive-TTL echo of `A1` is still matched as ours and carries
      //     rdata no live route holds, so invariant 2 does not stop it; the
      //     withdrawing route is skipped by every conflict fan-out too, leaving
      //     the REPLACEMENT as its only recipient and a TERMINAL
      //     `ServiceUpdate::HostConflict` as the result. Same-instance reuse
      //     with changed SRV/TXT reaches a false §8.1 probe defeat the same
      //     way.
      //     What keeps such an echo out of THIS arm is driver-side, and it is
      //     the one invariant here the crate cannot check for itself: a
      //     self-send credit is bound to the record generation it was sent
      //     under, and a credit from a superseded generation is DEMOTED to
      //     `OwnEcho` — the only tier that denies adjudication — rather than
      //     discarded. Demoted, because discarding it makes the same echo read
      //     as no credit at all, hence `NotFromUs`, hence full adjudication AND
      //     full observation: the same failure, louder.
      //     STILL OPEN: an in-place record update is a SECOND route to a
      //     self-echo carrying rdata we no longer hold, and no generation
      //     advance covers it. Implementing §8.4 must re-argue this cell, not
      //     merely add the API.
      //     INVALIDATED BY: a driver that stops superseding its credits at the
      //     SERVICE LIFECYCLE SEAMS — a service registration, and the
      //     `begin_withdrawal` that retires a route however that retirement was
      //     reached (caller unregister, shutdown, rename collision, internal
      //     retirement) — or that discards a superseded credit instead of
      //     demoting it.
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

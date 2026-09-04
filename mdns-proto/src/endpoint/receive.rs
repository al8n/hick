//! Inbound datagram demux (`handle`) + transmit / timeout polling.

use super::*;

impl<I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS> Endpoint<I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS>
where
  I: Instant,
  R: Rng,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute<I, TQ, EvS>>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
  TQ: Pool<Transmit>,
  EvS: Pool<ServiceUpdate>,
{
  /// Is `addr` advertised by any registered service?  Used by `handle` to
  /// detect multicast-loopback datagrams whose source address matches an
  /// IP we are publishing.  Linear scan over routes;
  /// bounded by the number of registered services + their per-route
  /// address slice.
  ///
  /// `interface_index` is the receiving interface index (from PKTINFO),
  /// used for IPv6 link-local scope matching: without it, the
  /// same `fe80::*` advertised on a different interface would falsely
  /// classify a peer packet as self.  For IPv4 and for non-link-local
  /// IPv6 the scope check is bypassed.
  pub(crate) fn src_matches_advertised(&self, addr: IpAddr, interface_index: u32) -> bool {
    match addr {
      IpAddr::V4(v4) => self
        .services
        .iter()
        .any(|(_, route)| route.a_addrs().contains(&v4)),
      IpAddr::V6(v6) => {
        // Link-local IPv6 addresses (fe80::/10) are scoped per interface;
        // global / unique-local addresses are not.
        let is_link_local = matches!(v6.segments()[0], 0xfe80..=0xfebf);
        self.services.iter().any(|(_, route)| {
          let addrs = route.aaaa_addrs();
          let scopes = route.aaaa_scopes();
          // Defensive: `aaaa_scopes` is the parallel scope slice, but if a
          // future code path produces an unbalanced length we degrade to
          // the bare-address match rather than mismatch-and-panic.
          for (i, a) in addrs.iter().enumerate() {
            if *a != v6 {
              continue;
            }
            if !is_link_local {
              return true;
            }
            let scope = scopes.get(i).copied().unwrap_or(0);
            if scope == 0 || scope == interface_index {
              return true;
            }
          }
          false
        })
      }
    }
  }

  /// Process an incoming datagram. Returns an iterator over routing
  /// decisions; the iterator borrows from `rx`'s payload and from `self`.
  ///
  /// # Contract
  ///
  /// The routing decisions this yields are fed to
  /// [`Service::handle_event`](crate::service::Service::handle_event) /
  /// [`Query::handle_event`](crate::query::Query::handle_event), so the
  /// confirm-before-anything contract reaches the receive path too: do not drive
  /// this loop for a service or query whose datagram from `poll_transmit` has not
  /// been confirmed via `note_transmit_outcome`. A driver that sends and confirms
  /// as one step satisfies this by construction. See
  /// [`Service::poll_transmit`](crate::service::Service::poll_transmit).
  ///
  /// `now` is the instant this datagram is PROCESSED at, and every effect it has
  /// is anchored to that one reading: cached records expire from it, an active
  /// query whose `QuerySpec::with_timeout` window has already shut as of `now`
  /// collects nothing from this datagram and suppresses no RFC 6762 §7.3 retry
  /// slot for it, and the returned iterator withholds that query's (informational)
  /// answer routing on the same comparison. A caller that defers `handle`
  /// therefore defers the whole datagram, rather than having part of it land in
  /// one epoch and part in another.
  ///
  /// So `now` carries a bound the CALLER holds, not only schedules this crate
  /// owns, and a driver that samples it once for a whole receive drain hands the
  /// last datagram of that drain a reading from before the first. Under a query's
  /// `max_answers` cap that is not laxity in the caller's favour: an answer
  /// admitted past the window EVICTS one collected inside it. Read the clock per
  /// datagram, adjacent to this call.
  ///
  /// `rx` carries the datagram itself together with what the caller can say
  /// about it — its source, its [`Provenance`], and optionally the receiving
  /// interface and that interface's own address. See [`Received`] for why the
  /// bytes and their provenance arrive as one value.
  ///
  /// [`Received::with_local_ip`] is TRACE-ONLY, and the name is the only reason
  /// it looks like a self signal. A source IP equal to it suppresses nothing:
  /// PKTINFO's local receive address is host/interface level, so every same-host
  /// mDNS sender egresses from the same interface IP, and treating `src ==
  /// local_ip` as self would suppress legitimate co-resident peers and hide
  /// same-host name conflicts. The self question is answered by
  /// [`Received::provenance`], and — for callers that keep no send log — by the
  /// interface-scoped advertised-source guess behind
  /// [`EndpointConfig::with_trust_advertised_src_as_self`].
  ///
  /// [`EndpointConfig::with_trust_advertised_src_as_self`]: crate::EndpointConfig::with_trust_advertised_src_as_self
  #[allow(clippy::type_complexity)]
  pub fn handle<'a, 'e>(
    &'e mut self,
    now: I,
    rx: Received<'a>,
  ) -> Result<RouteEvents<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS>, HandleError> {
    let Received {
      src,
      data,
      provenance,
      local_ip,
      interface_index,
    } = rx;
    // `None` and `0` are the same instruction to `src_matches_advertised` —
    // "no receiving interface known, so match only scope-0 AAAA entries" — and
    // the `Option` exists so a caller states which one it means.
    let interface_index = interface_index.unwrap_or(0);
    #[cfg(feature = "tracing")]
    let _span = trace_span!("handle", src = %src, len = data.len()).entered();
    #[cfg(feature = "stats")]
    {
      self.stats.packets_rx(1);
      #[allow(clippy::cast_possible_truncation)]
      self.stats.bytes_rx(data.len() as u64);
    }

    let reader = MessageReader::try_parse(data).map_err(|e| {
      warn!(
        target: "mdns_proto::endpoint",
        src = %src,
        "handle: failed to parse incoming datagram"
      );
      #[cfg(feature = "stats")]
      self.stats.parse_errors(1);
      HandleError::Parse(e)
    })?;
    if !reader.header().flags().opcode().is_query() {
      #[cfg(feature = "stats")]
      self.stats.packets_dropped(1);
      return Err(HandleError::InvalidOpcode(reader.header().flags().opcode()));
    }
    if !reader.header().flags().response_code().is_no_error() {
      #[cfg(feature = "stats")]
      self.stats.packets_dropped(1);
      return Err(HandleError::InvalidResponseCode(
        reader.header().flags().response_code(),
      ));
    }
    let is_response = reader.header().flags().is_response();
    // Self-loopback detection. The AUTHORITATIVE per-Endpoint self signal is the
    // caller's [`Provenance`]. The driver computes it by content-matching the
    // datagram against packets it recently sent, ordered by the kernel receive
    // timestamp — facilities that live naturally in the std I/O layer, not in
    // this `no_std` protocol core. Routing our own multicast loopback as a peer
    // packet would cause false ProbeConflicts (self-rename), false
    // HostConflicts, spurious KAS suppression, and double cache writes, so a
    // datagram the caller claims as its own is suppressed as far as its tier
    // warrants: entirely for `OwnEcho`, and for `OwnEchoLikely` only in §10
    // cache population and §7.1/§7.3 quieting — that tier still adjudicates and
    // still answers an §8.1 defence. `Admits::for_datagram` is where the split
    // and its reasons live.
    //
    // `local_ip` is NOT consulted, deliberately. PKTINFO's local receive address
    // is HOST/interface-level — every same-host mDNS sender egresses from the
    // same interface IP, so `src == local_ip` would suppress legitimate
    // co-resident peers and hide same-host name conflicts. It is carried for
    // tracing; `interface_index` is real input, but only to the opt-in
    // advertised-source check below, which is interface-scoped for IPv6
    // link-local.
    //
    // `src_matches_advertised` is that OPT-IN fallback
    // (`EndpointConfig::trust_advertised_src_as_self`, default off) for
    // single-process / sync callers whose provenance is `Unknown`.
    let matched_advertised = self.config.trust_advertised_src_as_self()
      && self.src_matches_advertised(src.ip(), interface_index);
    // RFC 6762 — a Multicast DNS RESPONSE (QR=1) is only
    // trustworthy when it originates from UDP source port 5353. A response
    // from an ephemeral port is an off-path/legacy-unicast artifact that must
    // not be allowed to populate the cache, answer active queries, or drive
    // service conflicts. QUERIES (QR=0) are exempt — legacy unicast queriers
    // legitimately use ephemeral source ports (RFC 6762 §6.7) and we must
    // still respond to them. It is a claim about the SOURCE PORT, not about who
    // sent the datagram, so it is a second axis ANDed into the permissions
    // rather than another `Provenance`.
    let untrusted_response = is_response && src.port() != crate::constants::MDNS_PORT;
    // THE decision, taken once. Every gate below — and every arm of the routing
    // iterator, which carries this value — reads it rather than recomputing a
    // condition that could drift.
    let admits = Admits::for_datagram(
      provenance,
      matched_advertised,
      self.config.answer_questions(),
      untrusted_response,
    );
    // A datagram nothing may act on.
    let inert = admits.all_denied();

    // Single eager section-validation latch.
    // Walk ALL FOUR sections (questions, answers, authority, additional) once
    // to detect whether any record in any section fails to parse.  If so,
    // bump `parse_errors(1)` exactly once per datagram.
    //
    // Precedence rule (exactly-one reject counter invariant):
    //   `packets_dropped` takes precedence over malformed-section `parse_errors`,
    //   and the two are mutually exclusive BY CONSTRUCTION: both are gated on
    //   `Admits::all_denied`, in opposite directions, computed once above.  An
    //   all-denied datagram is rejected wholesale — no permission it carries
    //   admits anything — so `packets_dropped` is the sole meaningful reject
    //   counter and the malformation is moot; running the latch for one would
    //   bump BOTH and break the exactly-one-reject-per-`packets_rx` invariant.
    //
    //   The test is taken AFTER `untrusted_response` is ANDed in, which is what
    //   keeps both directions true: a datagram denied on that axis alone is
    //   still a whole-datagram reject and must still count as a drop, exactly as
    //   a self-loopback one does.
    //
    //   A PARTIALLY permitted datagram is not a drop.  It is processed — some of
    //   its sections route, and it can raise a §8.2 proposal or an §8.1 defence —
    //   so it takes the not-suppressed rows below, and a malformed section in it
    //   is counted as a parse error like any other processed datagram's.
    //
    // Counters per case:
    //   • all-denied (self-loopback and/or untrusted QR=1), malformed or not
    //       → `packets_dropped(1)` only (latch skipped)
    //   • anything admitted, malformed section
    //       → `parse_errors(1)` only (latch fires)
    //   • anything admitted, well-formed
    //       → 0 reject counters (latch fires, finds nothing)
    //   • header parse fail / invalid opcode / invalid rcode
    //       → their own single counter (unchanged, precede this point)
    //
    // The latch also catches errors in sections skipped by the routing iterator:
    //   • `answer_questions=false` → Questions arm skipped; latch still walks it
    //   • non-5353 source port → Authority conflict-routing skipped; latch walks
    //     authority regardless (port gate governs routing, not byte-validity)
    //   • a denied PERMISSION → that arm yields nothing; latch walks its section
    //     regardless, on the same reasoning — a permission governs routing, not
    //     byte-validity
    //
    // Protocol-behaviour contract: this validation ONLY adds accounting.
    // It does NOT introduce new drops or change which records get processed
    // by the routing iterator — lenient routing (process valid parts) is
    // preserved.
    //
    // `packets_dropped` counts only WHOLE-DATAGRAM rejects: invalid opcode,
    // invalid rcode, and an all-denied datagram. A section-level suppression —
    // the routing iterator's Authority gate on a non-5353 source, say — leaves
    // the datagram's other sections routing, so it is not a drop and bumps
    // nothing. The Authority arm restates this where it applies it.
    #[cfg(feature = "stats")]
    if !inert {
      let mut section_parse_error = false;
      // Questions: walk regardless of `answer_questions` config —
      // a malformed question byte-stream is a datagram-level error.
      if !section_parse_error {
        for q in reader.questions() {
          if q.is_err() {
            section_parse_error = true;
            break;
          }
        }
      }
      // Answers + Additional: chained, matching the eager walk below.
      if !section_parse_error {
        for r in reader.answers().chain(reader.additional()) {
          if r.is_err() {
            section_parse_error = true;
            break;
          }
        }
      }
      // Authority: walk regardless of `src.port()` — the port gate only
      // governs conflict routing, not whether the bytes are well-formed.
      if !section_parse_error {
        for r in reader.authority() {
          if r.is_err() {
            section_parse_error = true;
            break;
          }
        }
      }
      if section_parse_error {
        self.stats.parse_errors(1);
      }
    }

    trace!(
      target: "mdns_proto::endpoint",
      src = %src,
      local_ip = ?local_ip,
      interface_index,
      is_response,
      matched_advertised,
      provenance = ?provenance,
      admits = ?admits,
      data_len = data.len(),
      "handle: routing inbound packet"
    );
    if inert {
      debug!(
        target: "mdns_proto::endpoint",
        src = %src,
        provenance = ?provenance,
        matched_advertised,
        untrusted_response,
        "handle: dropped a datagram nothing admits"
      );
      #[cfg(feature = "stats")]
      self.stats.packets_dropped(1);
    }
    // + cache population: walk the answer section ONCE, eagerly
    // applying side effects so that dropping the returned `RouteEvents`
    // iterator early cannot lose state:
    //   1. populate the passive-observation cache (RFC 6762 §10);
    //   2. for response packets (QR=1), apply `QueryEvent::Answer` to
    //      every name/type-compatible owned `Query` state machine.
    //
    // Iterating answers a single time and dispatching both side effects
    // here keeps the receive path allocation-free w.r.t. fan-out
    // bookkeeping (no Vec of matching keys — `Pool::iter_mut` lets us
    // mutate matching queries in-place).
    //
    // Both are RFC 6762 §10 OBSERVATION: believing what this datagram says about
    // the link. `RouteEvents`' `ToQuery` fan-out reports what happened here, so
    // it reads the same permission — the two must not disagree, or the caller is
    // told about a collection that did not occur.
    if admits.observation() {
      let populate_cache = self.config.populate_cache();
      // per-packet tracking of `(name, rtype)` pairs that have
      // already had their cache-flush eviction applied.  RFC 6762 §10.2
      // says that on cache-flush the receiver should consider all OTHER
      // cached records for the same `(name, rtype)` to be expired —
      // crucially, "other" excludes the records arriving in the same
      // datagram.  The previous implementation evicted on every
      // cache-flush record, so a multi-A announcement for one host
      // (all A records share `(name, rtype)` and the cache-flush bit)
      // saw the 2nd record evict the 1st, the 3rd evict the 2nd, etc.
      // — only the last A survived.
      //
      // Track which `(name, rtype)` pairs have been flushed in this
      // packet; for subsequent records of the same RRSet, insert with
      // cache_flush=false so they all land together.
      // per-packet flush marker keys on (name, rtype, rclass).
      // Class is part of the cache identity, so the dedup
      // tracker must include it too — otherwise a non-IN cache_flush
      // record in the same packet would consume the marker and the
      // subsequent IN cache_flush would be downgraded to non-flush,
      // leaving stale IN siblings alive past the §10.2 grace window.
      let mut flushed_in_packet: std::vec::Vec<(Name, ResourceType, ResourceClass)> =
        std::vec::Vec::new();
      // process the ANSWER section AND the ADDITIONAL section
      // together. Standard DNS-SD responders carry the SRV/TXT/A/AAAA that
      // accompany a PTR answer in the Additional section (RFC 6763 §12); a
      // querier must cache them and apply them to active queries, exactly like
      // answer records. They share the per-packet cache-flush tracker. (QR=0
      // additionals are skipped below by the same is_response gates as QR=0
      // answers — additionals are never known-answer hints.)
      for r in reader.answers().chain(reader.additional()) {
        let r = match r {
          Ok(r) => r,
          // Malformed record — the single upfront section-validation latch
          // (above, before routing) has already bumped `parse_errors(1)` for
          // this datagram.  Do NOT bump it again here — that would double-count.
          // Stop walking: a malformed record means subsequent cursors are
          // unreliable (the MessageReader's skip_records / skip_questions
          // helpers return None on failure, and the Records iterator latches
          // remaining=0 after the first error).
          Err(_) => {
            break;
          }
        };

        // eager query state update.  Apply this answer to every
        // matching owned Query in a single mutable pass.  iter_mut is
        // O(N_queries) per record, total O(N_answers × N_queries) —
        // identical to the previous lazy approach, but unconditional
        // (no longer depends on the caller draining the iterator).
        //
        // skip queries that have already delivered their
        // terminal `QueryUpdate` to the caller.  Such queries are
        // retained in the pool ONLY so the caller can drain
        // `collected_answers` — they MUST be frozen: late matching
        // responses that arrive between `poll_query` returning terminal
        // and the caller's eventual `cancel_query` must not mutate
        // collected_answers or trigger FIFO eviction of pre-terminal
        // results.
        if is_response {
          // answers_rx counts only actual QR=1 response records, not
          // QR=0 known-answer hints which should not inflate the counter.
          #[cfg(feature = "stats")]
          self.stats.answers_rx(1);
          for (_, q) in self.queries.iter_mut() {
            // skip on `is_done` AND `terminal_emitted`, not
            // just the latter.  `handle_query_timeout` flips
            // `done = true` BEFORE `poll_query` flips
            // `terminal_emitted` — without the `is_done` arm, an
            // answer arriving in that gap would still mutate
            // `collected_answers`.
            if q.is_done() || q.terminal_emitted() {
              continue;
            }
            if names_match_record(q.qname(), &r) && qry_query_accepts(q, &r) {
              // `now` is this datagram's processing instant, and every effect it
              // has is anchored to it — the cache entry inserted below expires
              // from the same reading. A query whose `QuerySpec::with_timeout`
              // window has shut as of `now` refuses the answer (see
              // `Query::handle_event`), which is what keeps the result set from
              // depending on whether this drain runs before or after the
              // caller's timer pump.
              q.handle_event(QueryEvent::Answer(r), now);
            }
          }
        }

        // gate passive cache population on QR=1.  RFC 6762
        // answer-section records in QUERY packets (QR=0) are
        // known-answer hints, NOT authoritative records — they
        // suppress redundant responses but must not feed the cache.
        // Without this gate a hostile querier could:
        //   * insert forged rdata into the cache (positive-TTL QR=0
        //     answer), or
        //   * delete cached records via TTL=0 QR=0 answers, or
        //   * clamp legitimate cached siblings via QR=0 cache_flush.
        if !populate_cache || !is_response {
          continue;
        }
        // Build an owned Name directly from the wire label sequence. Bails
        // (drops the record) on a malformed label, non-UTF-8 bytes — DNS-SD
        // names are UTF-8 (RFC 6763 §4.1) — or a length violation. Avoids the
        // throwaway presentation `String` the old loop assembled, and unlike a
        // `byte as char` join never Latin-1-mangles a multi-byte UTF-8 label.
        let name = match Name::from_wire_labels(r.name().labels()) {
          Some(n) => n,
          None => continue,
        };
        // cache rdata in canonical, case-FOLDED,
        // decompressed wire form. The cache's identity test (dedup, TTL=0
        // goodbye removal, cache-flush sibling clamp) compares raw rdata bytes,
        // so a PTR/SRV/NSEC stored with one compression pointer — or one case —
        // would never match the same logical record re-encoded differently in a
        // refresh or goodbye, leaving stale entries until TTL (and letting case
        // variants bloat the bounded cache). Canonicalizing + case-folding both
        // the stored and incoming bytes makes those comparisons encoding- and
        // case-independent (the cache never surfaces rdata for display). A
        // malformed / over-length name-bearing record is dropped, not cached.
        let rdata = match r.canonical_rdata_folded() {
          Ok(v) => v,
          Err(_) => continue,
        };
        let ttl = core::time::Duration::from_secs(u64::from(r.ttl()));

        // dedup cache-flush within this packet.  Only the FIRST
        // positive-TTL record per `(name, rtype)` with the cache-flush
        // bit triggers eviction of pre-existing entries; subsequent
        // records of the same RRSet insert with cache_flush=false so
        // they land alongside the first.
        //
        // TTL=0 records must NOT consume the per-packet flush
        // marker.  `Cache::try_insert` handles `ttl == 0` (goodbye /
        // deletion) BEFORE its cache-flush branch — it removes only
        // the exact rdata and performs no RRSet eviction.  If a TTL=0
        // record set `flushed_in_packet[(name, rtype)]`, a subsequent
        // positive-TTL cache_flush record for the same RRSet would be
        // downgraded to `cache_flush=false`, leaving older siblings
        // stale until expiry.  Gate on `ttl != 0`.
        let rtype = r.rtype();
        // thread the wire rclass into the cache so non-IN class
        // records don't collide with IN entries.  The cache-flush high
        // bit is already consumed via r.cache_flush(); r.rclass()
        // returns the remaining class value (typically IN).
        let rclass = r.rclass();
        // per-packet flush dedup keys on (name, rtype, rclass),
        // not just (name, rtype) — otherwise a class-A flush record in
        // the same packet would suppress a class-B flush record for
        // the same name/type.
        let do_flush = r.cache_flush()
          && r.ttl() != 0
          && !flushed_in_packet
            .iter()
            .any(|(n, t, c)| n.as_str() == name.as_str() && *t == rtype && *c == rclass);
        let _ = self
          .cache
          .try_insert(name.clone(), rtype, rclass, rdata, ttl, now, do_flush);
        if do_flush {
          flushed_in_packet.push((name, rtype, rclass));
        }
      }
    }

    // RFC 6762 §7.3 duplicate-question suppression (querier side). When another
    // host multicasts the SAME QM question this endpoint has an active query
    // for — and that query carries NO known answers (empty Answer section, TC
    // clear, so it cannot be suppressing records we still need) — treat our own
    // planned query as already sent and defer its next (re)transmit. The peer's
    // query elicits the same multicast answers, which we receive too, so we
    // avoid adding a redundant query to the link. It is one of the two ways
    // another host's traffic QUIETS ours, so the suppression below reads that
    // permission — deferring our own query's retransmit on our own echo is one
    // of the two places where believing a peer is the more harmful error.
    //
    // questions_rx is bumped for EVERY question in any QR=0 query from port 5353
    // (multicast querier), regardless of whether the answer section is empty.
    // Queries that carry a known-answer section (TC=0, answer_count>0) are still
    // genuine queries whose questions deserve to be counted; only the
    // duplicate-suppression side effect is gated on answer_count==0.
    //
    // The COUNT reads `observation`, the permission that also gates `answers_rx`
    // in the eager pass above: both tally what this endpoint took as a report
    // about the link, so a datagram it does not believe should inflate neither.
    if admits.observation() && !is_response && src.port() == crate::constants::MDNS_PORT {
      #[cfg(feature = "stats")]
      for q in reader.questions() {
        match q {
          Ok(_) => self.stats.questions_rx(1),
          Err(_) => break,
        }
      }
    }

    // only a query from UDP source port 5353 counts. A query from an
    // ephemeral port is a legacy/one-shot resolver (RFC 6762 §6.7) whose request
    // may be answered by UNICAST straight to it — answers we would never see —
    // so suppressing our own multicast query on its behalf could silently lose
    // us the response.
    if admits.quieting()
      && !is_response
      && src.port() == crate::constants::MDNS_PORT
      && reader.header().answer_count() == 0
      && !reader.header().flags().is_truncated()
    {
      for q in reader.questions() {
        let q = match q {
          Ok(q) => q,
          Err(_) => break,
        };
        // A QU (unicast-response) question is answered unicast to the asker, so
        // it does NOT elicit the multicast answers our query needs — only a
        // shared QM question is a genuine duplicate of ours. Class-gate to IN.
        if q.unicast_response_requested() || !q.qclass().is_in() {
          continue;
        }
        for (_, query) in self.queries.iter_mut() {
          if query.is_done() {
            continue;
          }
          // Same question: identical qtype + qclass and a case-insensitive
          // qname match (an ANY query is only a duplicate of another ANY).
          if query.qtype() == q.qtype()
            && query.qclass() == q.qclass()
            && names_match(query.qname(), q.qname())
          {
            #[cfg(feature = "stats")]
            let suppressed = query.note_duplicate_question(now);
            #[cfg(not(feature = "stats"))]
            let _suppressed = query.note_duplicate_question(now);
            #[cfg(feature = "stats")]
            if suppressed {
              self.stats.duplicate_questions_suppressed(1);
            }
          }
        }
      }
    }

    // One datagram, one §8.2 proposal. Bumped per accepted datagram so a
    // service can tell a peer's retransmission from a second proposal by the
    // same peer; see `DatagramId`.
    self.datagram_seq = self.datagram_seq.wrapping_add(1);
    Ok(RouteEvents {
      src,
      reader,
      now,
      is_response,
      datagram: crate::event::DatagramId::new(self.datagram_seq),
      proposal_service_cursor: None,
      question_idx: 0,
      service_cursor: 0,
      answer_idx: 0,
      authority_idx: 0,
      pending_query: None,
      answer_query_cursor: None,
      answer_service_cursor: None,
      answer_service_done: false,
      authority_service_cursor: None,
      additional_idx: 0,
      additional_service_cursor: None,
      additional_service_done: false,
      additional_query_cursor: None,
      relinquished_screen: None,
      admits,
      // A datagram no permission admits yields zero events, and is handed back
      // PRE-DRAINED rather than walked. The per-arm gates below would each
      // decline it, but only after four sections had been iterated to produce
      // nothing — and an endpoint whose driver has no source-port gate of its
      // own reaches this from the network, so the walk is attacker-reachable
      // work. We still construct a valid iterator so the caller's loop runs
      // cleanly.
      section: if inert {
        Section::Done
      } else {
        Section::Questions
      },
      endpoint: self,
    })
  }

  /// Drain endpoint-level transmits. mDNS-side most transmits come from
  /// Service/Query — Endpoint rarely emits anything itself.
  pub fn poll_transmit(
    &mut self,
    _now: I,
    _buf: &mut [u8],
  ) -> Result<Option<Transmit>, TransmitError> {
    Ok(None)
  }

  /// Next deadline (next cache expiration), if any.
  pub fn poll_timeout(&self) -> Option<I> {
    let cache = self.cache.next_expiration();
    // Endpoint-owned withdrawals have no driver-side `Service` to report their
    // deadlines, so the endpoint surfaces the earliest time a withdrawal needs
    // to be pumped (`next_at`) or force-completed (`ceiling_at`) — otherwise the
    // driver could park past a due goodbye round.
    #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
    let withdrawal = self.next_withdrawal_deadline();
    #[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
    let withdrawal: Option<I> = None;
    match (cache, withdrawal) {
      (Some(c), Some(w)) => Some(c.min(w)),
      (Some(c), None) => Some(c),
      (None, w) => w,
    }
  }

  cfg_heap! {
    /// The earliest time an in-flight withdrawal needs to be pumped (`next_at`) or
    /// force-completed (`ceiling_at`), or `None` when no withdrawal is pending.
    ///
    /// Unlike [`Self::poll_timeout`] this EXCLUDES cache and query deadlines, so a
    /// last-handle shutdown flush can sleep precisely on the next withdrawal action
    /// — and exit as soon as none remain — instead of parking on unrelated cache
    /// expiry (or the driver's wall-clock backstop) after every goodbye is sent.
    pub fn next_withdrawal_deadline(&self) -> Option<I> {
      self
        .withdrawals
        .iter()
        .map(|(_, w)| w.next_at.min(w.ceiling_at))
        .min()
    }

    /// Whether any endpoint-owned withdrawal is still in flight (its TTL=0 goodbye
    /// not yet fully sent or force-completed). A shutdown flush loops until this is
    /// `false`, rather than on the aggregate driver deadline.
    pub fn has_pending_withdrawals(&self) -> bool {
      !self.withdrawals.is_empty()
    }
  }

  /// Drive timer-based work (cache TTL sweep, and reclaiming lapsed
  /// relinquished record sets).
  pub fn handle_timeout(&mut self, now: I) -> Result<(), HandleTimeoutError> {
    // Hygiene only: a lapsed row already screens nothing (see
    // `Endpoint::relinquished_asserts`), so this reclaims memory rather than
    // deciding anything. It is here and not on `poll_timeout` for that reason —
    // nothing needs waking for it.
    #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
    self.sweep_relinquished(now);
    let n = self.cache.sweep_expired(now);
    if n > 0 {
      let _ = self
        .pending_events
        .insert(EndpointEventEntry(EndpointEvent::CacheExpired));
    }
    Ok(())
  }

  /// Drain a pending endpoint-level event.
  pub fn poll(&mut self) -> Option<EndpointEvent> {
    let key = self.pending_events.iter().next().map(|(k, _)| k)?;
    self.pending_events.try_remove(key).map(|e| e.0)
  }
}

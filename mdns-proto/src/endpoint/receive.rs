//! Inbound datagram demux (`handle`) + transmit / timeout polling.

use super::*;

impl<I, R, C, SR, QS, EV, AN, EvQ> Endpoint<I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: Rng,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
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
  /// decisions; the iterator borrows from `data` and from `self`.
  ///
  /// `local_ip` is the address of the interface that received the datagram
  /// (as reported by IP_PKTINFO / IPV6_PKTINFO on Unix).  When the packet's
  /// source IP equals `local_ip` the datagram is treated as a self-originated
  /// multicast loopback: cache population and event routing are both
  /// suppressed so we do not interpret our own probes/announcements as peer
  /// conflicts, KAS hints, or query answers.
  ///
  /// `interface_index` is the receiving interface index (typically
  /// `if_nametoindex(3)` / PKTINFO `ipi_ifindex` / `ipi6_ifindex`).  It
  /// disambiguates IPv6 link-local self-loopback on multi-homed hosts:
  /// a peer reusing the same `fe80::*` on a different interface
  /// must NOT be classified as self.  Pass `0` if the receiving interface
  /// is unknown — link-local self-loopback detection then degrades
  /// gracefully (matches only AAAA entries registered with
  /// [`ServiceRecords::add_aaaa`] or [`add_aaaa_scoped`] with scope `0`).
  ///
  /// `caller_is_self` is the AUTHORITATIVE self-loopback signal:
  /// pass `true` when the I/O layer has determined — by content-matching
  /// the datagram against a recent outgoing packet, ordered by the kernel
  /// receive timestamp — that this is our OWN multicast loopback. When
  /// `true`, all side effects are suppressed (no peer-conflict, KAS, cache
  /// writes, or query answers). Callers that cannot make that
  /// determination (sync / single-process responders) pass `false` and may
  /// instead opt into the coarser advertised-source fallback via
  /// [`EndpointConfig::with_trust_advertised_src_as_self`].
  ///
  /// [`add_aaaa_scoped`]: crate::records::ServiceRecords::add_aaaa_scoped
  /// [`ServiceRecords::add_aaaa`]: crate::records::ServiceRecords::add_aaaa
  /// [`EndpointConfig::with_trust_advertised_src_as_self`]: crate::EndpointConfig::with_trust_advertised_src_as_self
  #[allow(clippy::type_complexity)]
  pub fn handle<'a, 'e>(
    &'e mut self,
    now: I,
    src: SocketAddr,
    local_ip: IpAddr,
    interface_index: u32,
    data: &'a [u8],
    caller_is_self: bool,
  ) -> Result<RouteEvents<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ>, HandleError> {
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
    // Self-loopback detection. The AUTHORITATIVE per-Endpoint self
    // signal is provided by the CALLER via `caller_is_self`. The driver
    // computes it by content-matching the datagram against packets it
    // recently sent, ordered by the kernel receive timestamp — facilities
    // that live naturally in the std I/O layer, not in this `no_std`
    // protocol core. Routing our own multicast loopback as a peer packet
    // would cause false ProbeConflicts (self-rename), false HostConflicts,
    // spurious KAS suppression, and double cache writes, so we suppress all
    // side effects when the caller flags the datagram as self.
    //
    // we deliberately do NOT use `src == local_ip` as a self
    // signal. PKTINFO's local receive address is HOST/interface-level —
    // every same-host mDNS sender egresses from the same interface IP, so
    // `src == local_ip` would suppress legitimate co-resident peers and
    // hide same-host name conflicts. `local_ip` / `interface_index` remain
    // available for the opt-in advertised-source check below, which is
    // interface-scoped for IPv6 link-local.
    //
    // `src_matches_advertised` is an OPT-IN fallback
    // (`EndpointConfig::trust_advertised_src_as_self`, default off) for
    // single-process / sync callers that cannot supply `caller_is_self`.
    let _ = local_ip;
    let matched_advertised = self.config.trust_advertised_src_as_self()
      && self.src_matches_advertised(src.ip(), interface_index);
    let is_self_packet = caller_is_self || matched_advertised;
    // RFC 6762 — a Multicast DNS RESPONSE (QR=1) is only
    // trustworthy when it originates from UDP source port 5353. A response
    // from an ephemeral port is an off-path/legacy-unicast artifact that must
    // not be allowed to populate the cache, answer active queries, or drive
    // service conflicts. QUERIES (QR=0) are exempt — legacy unicast queriers
    // legitimately use ephemeral source ports (RFC 6762 §6.7) and we must
    // still respond to them. We fold the untrusted-response case into the
    // same all-side-effects suppression as a self packet.
    let untrusted_response = is_response && src.port() != crate::constants::MDNS_PORT;
    let suppress_side_effects = is_self_packet || untrusted_response;

    // ── Single eager section-validation latch ──────────────────────────────
    // Walk ALL FOUR sections (questions, answers, authority, additional) once
    // to detect whether any record in any section fails to parse.  If so,
    // bump `parse_errors(1)` exactly once per datagram.
    //
    // Precedence rule (exactly-one reject counter invariant):
    //   Suppression (`packets_dropped`) takes precedence over malformed-section
    //   `parse_errors`.  A suppressed datagram (self-loopback or untrusted
    //   QR=1 response from a non-5353 source) is dropped wholesale — we never
    //   process it — so `packets_dropped` is the sole meaningful reject counter
    //   and the malformation is moot.  Running the latch for a suppressed packet
    //   would bump BOTH `parse_errors` AND `packets_dropped`, violating the
    //   exactly-one-reject-per-packets_rx invariant.  Therefore the latch only
    //   runs when `!suppress_side_effects`.
    //
    // Counters per case:
    //   • suppressed (self-loopback or untrusted QR=1), malformed or not
    //       → `packets_dropped(1)` only (latch skipped)
    //   • not-suppressed, malformed section
    //       → `parse_errors(1)` only (latch fires)
    //   • not-suppressed, well-formed
    //       → 0 reject counters (latch fires, finds nothing)
    //   • header parse fail / invalid opcode / invalid rcode
    //       → their own single counter (unchanged, precede this point)
    //
    // The latch also catches errors in sections skipped by the routing iterator:
    //   • `answer_questions=false` → Questions arm skipped; latch still walks it
    //   • non-5353 source port → Authority conflict-routing skipped; latch walks
    //     authority regardless (port gate governs routing, not byte-validity)
    //
    // Protocol-behaviour contract: this validation ONLY adds accounting.
    // It does NOT introduce new drops or change which records get processed
    // by the routing iterator — lenient routing (process valid parts) is
    // preserved.
    //
    // NOTE on non-5353-source authority suppression: a well-formed
    // authority record from a non-5353 source is suppressed by the routing
    // iterator's Authority gate, but the DATAGRAM is still processed (its
    // question/answer/additional sections are still routed).  A section-level
    // suppression where the datagram's OTHER sections continue to be
    // processed is NOT a datagram drop, so no `packets_dropped` is bumped.
    // `packets_dropped` counts only whole-datagram rejects (invalid opcode,
    // invalid rcode, self-loopback, untrusted response).  A code comment
    // in the Authority arm documents this decision.
    #[cfg(feature = "stats")]
    if !suppress_side_effects {
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
      local_ip = %local_ip,
      interface_index,
      is_response,
      is_self_packet,
      data_len = data.len(),
      "handle: routing inbound packet"
    );
    if suppress_side_effects {
      debug!(
        target: "mdns_proto::endpoint",
        src = %src,
        is_self_packet,
        untrusted_response,
        "handle: suppressed self/untrusted packet"
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
    if !suppress_side_effects {
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
              q.handle_event(QueryEvent::Answer(r));
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
    // avoid adding a redundant query to the link. Self / untrusted packets are
    // already excluded by `suppress_side_effects`.
    //
    // questions_rx is bumped for EVERY question in any QR=0 query from port 5353
    // (multicast querier), regardless of whether the answer section is empty.
    // Queries that carry a known-answer section (TC=0, answer_count>0) are still
    // genuine queries whose questions deserve to be counted; only the
    // duplicate-suppression side effect is gated on answer_count==0.
    if !suppress_side_effects && !is_response && src.port() == crate::constants::MDNS_PORT {
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
    if !suppress_side_effects
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

    Ok(RouteEvents {
      src,
      reader,
      is_response,
      question_idx: 0,
      service_cursor: 0,
      answer_idx: 0,
      authority_idx: 0,
      pending_query: None,
      pending_service_event: None,
      answer_query_cursor: None,
      answer_service_cursor: None,
      answer_service_done: false,
      authority_service_cursor: None,
      additional_idx: 0,
      additional_service_cursor: None,
      additional_service_done: false,
      additional_query_cursor: None,
      // a self-packet OR an untrusted response (QR=1
      // from a non-5353 source port) yields zero events. We still construct
      // a valid (but pre-drained) iterator so the caller's loop runs cleanly.
      section: if suppress_side_effects {
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
    #[cfg(any(feature = "alloc", feature = "std"))]
    let withdrawal = self.next_withdrawal_deadline();
    #[cfg(not(any(feature = "alloc", feature = "std")))]
    let withdrawal: Option<I> = None;
    match (cache, withdrawal) {
      (Some(c), Some(w)) => Some(c.min(w)),
      (Some(c), None) => Some(c),
      (None, w) => w,
    }
  }

  /// The earliest time an in-flight withdrawal needs to be pumped (`next_at`) or
  /// force-completed (`ceiling_at`), or `None` when no withdrawal is pending.
  ///
  /// Unlike [`Self::poll_timeout`] this EXCLUDES cache and query deadlines, so a
  /// last-handle shutdown flush can sleep precisely on the next withdrawal action
  /// — and exit as soon as none remain — instead of parking on unrelated cache
  /// expiry (or the driver's wall-clock backstop) after every goodbye is sent.
  #[cfg(any(feature = "alloc", feature = "std"))]
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
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub fn has_pending_withdrawals(&self) -> bool {
    !self.withdrawals.is_empty()
  }

  /// Drive timer-based work (cache TTL sweep).
  pub fn handle_timeout(&mut self, now: I) -> Result<(), HandleTimeoutError> {
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

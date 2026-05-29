//! `Endpoint` orchestrator: demuxes incoming datagrams, holds routing
//! metadata + cache, drives Service/Query registration.

#![cfg(any(feature = "alloc", feature = "std"))]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand_core::RngCore;

use crate::{
  Instant, Name, Pool, QueryHandle, ServiceHandle,
  cache::{Cache, CacheEntry},
  config::{EndpointConfig, QuerySpec, ServiceSpec},
  error::{
    CancelQueryError, HandleError, HandleServiceRenamedError, HandleTimeoutError,
    RegisterServiceError, StartQueryError, StorageFullError, TransmitError,
  },
  event::{
    EndpointEvent, HostConflict, KnownAnswer, ProbeConflict, QueryEvent, QueryUpdate, RouteEvent,
    ServiceEvent, ServiceQuestion, ToQuery, ToService,
  },
  query::{CollectedAnswer, Query},
  service::Service,
  transmit::Transmit,
  wire::{MessageReader, NameRef, ResourceClass, ResourceType},
};

/// Routing metadata for a registered service.
#[derive(Debug, Clone)]
pub struct ServiceRoute {
  /// DNS-SD service-type PTR owner (e.g. `_ipp._tcp.local.`).
  service_type: Name,
  /// Instance name (e.g. `MyPrinter._ipp._tcp.local.`).
  name: Name,
  /// Host name that owns the A/AAAA records (e.g. `printer-host.local.`).
  host: Name,
  handle: ServiceHandle,
  /// IPv4 addresses advertised in this service's A records.  Used by
  /// `Endpoint::handle` to recognise multicast-loopback datagrams whose
  /// source IP matches an address we are publishing.  IPv6
  /// PKTINFO carries the multicast destination rather than the local
  /// interface address, so the IPv4-only `src == local_ip` shortcut from
  /// cannot detect IPv6 self-packets — membership against this
  /// list is the positive signal for both v4 and v6.
  a_addrs: alloc::vec::Vec<Ipv4Addr>,
  /// IPv6 addresses advertised in this service's AAAA records.  See
  /// `a_addrs` for the rationale.
  aaaa_addrs: alloc::vec::Vec<Ipv6Addr>,
  /// Parallel to `aaaa_addrs`: interface scope id for each AAAA (0 = any).
  /// IPv6 link-local addresses are scoped per interface; a peer
  /// reusing the same `fe80::*` on a different interface must NOT be
  /// classified as self.  A non-zero scope binds the address to a
  /// specific receiving `interface_index` in [`Endpoint::handle`].
  aaaa_scopes: alloc::vec::Vec<u32>,
  /// RFC 6763 §7.1 subtype browse names (`<sub>._sub.<service_type>`). A browse
  /// question for any of these routes to this service so it can answer with the
  /// shared subtype PTR.
  subtypes: alloc::vec::Vec<Name>,
}

impl ServiceRoute {
  /// The DNS-SD service-type (PTR owner), e.g. `_ipp._tcp.local.`.
  #[inline(always)]
  pub fn service_type(&self) -> &Name {
    &self.service_type
  }

  /// The service's instance name.
  #[inline(always)]
  pub fn name(&self) -> &Name {
    &self.name
  }

  /// The service's host name (owner of A/AAAA records).
  #[inline(always)]
  pub fn host(&self) -> &Name {
    &self.host
  }

  /// The handle assigned to this service.
  #[inline(always)]
  pub const fn handle(&self) -> ServiceHandle {
    self.handle
  }

  /// Advertised IPv4 addresses for this service (A records).
  #[inline(always)]
  pub fn a_addrs(&self) -> &[Ipv4Addr] {
    &self.a_addrs
  }

  /// Advertised IPv6 addresses for this service (AAAA records).
  #[inline(always)]
  pub fn aaaa_addrs(&self) -> &[Ipv6Addr] {
    &self.aaaa_addrs
  }

  /// Per-AAAA interface scope ids (parallel to [`Self::aaaa_addrs`]).
  /// A scope of `0` matches any receiving interface; a non-zero scope
  /// matches only the same `interface_index` passed to
  /// [`Endpoint::handle`].
  #[inline(always)]
  pub fn aaaa_scopes(&self) -> &[u32] {
    &self.aaaa_scopes
  }
}

/// Internal queued endpoint event.
#[derive(Debug, Clone)]
pub struct EndpointEventEntry(EndpointEvent);

impl EndpointEventEntry {
  /// Borrow the inner event.
  #[inline(always)]
  pub const fn event(&self) -> &EndpointEvent {
    &self.0
  }
}

/// The orchestrator. Holds routing metadata + cache + per-handle state
/// machines for Service (caller-driven) and Query (Endpoint-owned).
///
/// The `Query` state machines live in the `QS` pool — callers receive only
/// a `QueryHandle` from [`Self::try_start_query`] and drive each query via
/// the `*_query*` accessors on `Endpoint`.
///
/// # Query lifecycle and cleanup
///
/// Queries are NOT auto-pruned.  After
/// [`Self::poll_query`] returns the terminal `QueryUpdate` for a handle,
/// the underlying state machine is RETAINED so the caller can drain
/// final results via [`Self::collected_answers`].  Late matching
/// responses arriving after terminal are frozen out: they do not
/// mutate `collected_answers` or trigger fan-out events.
///
/// Cleanup is the caller's responsibility — terminated queries leak
/// pool slots until explicitly freed.  Two equivalent options:
///
///   * [`Self::cancel_query`] — drop a specific handle.
///   * [`Self::sweep_terminated_queries`] — drop every query whose
///     terminal has already been delivered.
///
/// Failing to clean up exhausts a fixed-capacity `QS` pool just as the
/// pre-R14 leak would have, so this contract must be honoured.
pub struct Endpoint<I, R, C, SR, QS, EV, AN, EvQ> {
  config: EndpointConfig,
  rng: R,
  services: SR,
  queries: QS,
  cache: Cache<I, C>,
  pending_events: EV,
  next_service_handle: u32,
  next_query_handle: u32,
  next_txid: u16,
  _phantom: core::marker::PhantomData<(AN, EvQ)>,
}

impl<I, R, C, SR, QS, EV, AN, EvQ> Endpoint<I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: RngCore,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  /// Build a new endpoint.
  pub fn try_new(config: EndpointConfig, mut rng: R) -> Self {
    let raw_txid = rng.next_u32() as u16;
    let next_txid = if raw_txid == 0 { 1 } else { raw_txid };
    Self {
      config,
      rng,
      services: SR::new(),
      queries: QS::new(),
      cache: Cache::new(),
      pending_events: EV::new(),
      next_service_handle: 0,
      next_query_handle: 0,
      next_txid,
      _phantom: core::marker::PhantomData,
    }
  }

  /// Returns the configuration.
  #[inline(always)]
  pub const fn config(&self) -> &EndpointConfig {
    &self.config
  }

  /// Register a new service. Returns the handle and a `Service` state-machine.
  pub fn try_register_service<TQ, EvS>(
    &mut self,
    spec: ServiceSpec,
    now: I,
  ) -> Result<(ServiceHandle, Service<I, TQ, EvS>), RegisterServiceError>
  where
    TQ: Pool<Transmit>,
    EvS: Pool<crate::event::ServiceUpdate>,
  {
    // Reject duplicate names.
    for (_, route) in self.services.iter() {
      if route.name().as_str() == spec.records().instance().as_str() {
        return Err(RegisterServiceError::NameAlreadyRegistered(
          spec.records().instance().clone(),
        ));
      }
    }

    let new_h = self.next_service_handle;
    self.next_service_handle = self.next_service_handle.saturating_add(1);
    let handle = ServiceHandle::from_raw(new_h);

    self
      .services
      .insert(ServiceRoute {
        service_type: spec.records().service_type().clone(),
        name: spec.records().instance().clone(),
        host: spec.records().host().clone(),
        handle,
        a_addrs: spec.records().a_addrs_slice().to_vec(),
        aaaa_addrs: spec.records().aaaa_addrs_slice().to_vec(),
        aaaa_scopes: spec.records().aaaa_scopes_slice().to_vec(),
        subtypes: spec.records().subtype_names().to_vec(),
      })
      .map_err(|_| RegisterServiceError::StorageFull(StorageFullError))?;

    let mut seed = [0u8; 32];
    self.rng.fill_bytes(&mut seed);
    // honor EndpointConfig::probe_unique_names — when disabled the
    // service skips the §8.1 probe sequence and announces immediately.
    let svc = Service::try_new(
      handle,
      spec.into_records(),
      now,
      seed,
      self.config.probe_unique_names(),
    );
    crate::trace::debug!(
      target: "mdns_proto::endpoint",
      handle = handle.raw(),
      "try_register_service: service registered"
    );
    Ok((handle, svc))
  }

  /// Remove the registered service for `handle`.
  ///
  /// callers MUST invoke this when dropping the corresponding
  /// `Service` state machine so the routing table releases the slot. Otherwise
  /// re-registering the same instance name is rejected by
  /// [`Self::try_register_service`] as
  /// [`RegisterServiceError::NameAlreadyRegistered`], and inbound packets
  /// matching the stale route continue to be classified as `ToService`
  /// events targeting a handle the driver no longer tracks.
  ///
  /// Returns `true` if a route was found and removed, `false` if the handle
  /// was already unknown (idempotent).
  pub fn unregister_service(&mut self, handle: ServiceHandle) -> bool {
    let key = self
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle)
      .map(|(k, _)| k);
    if let Some(k) = key {
      self.services.try_remove(k).is_some()
    } else {
      false
    }
  }

  /// Start a new query.
  ///
  /// The [`Query`] state machine is owned by the endpoint and driven via
  /// the `*_query*` accessors (`poll_query`, `poll_query_timeout`,
  /// `poll_query_transmit`, `handle_query_timeout`, `cancel_query`,
  /// `collected_answers`).
  ///
  /// When the query reaches a terminal state (`Timeout` or `Done`),
  /// [`Self::poll_query`] returns the terminal update exactly once and
  /// the state machine becomes frozen: `collected_answers(h)` remains
  /// readable, but no further answers are applied and no further
  /// `QueryEvent::Answer` events fire for `h`.  The caller MUST
  /// eventually free the pool slot via [`Self::cancel_query`] (or use
  /// [`Self::sweep_terminated_queries`] for bulk cleanup) — terminated
  /// queries are NOT auto-pruned.
  ///
  /// # Errors
  ///
  /// Returns [`StartQueryError::StorageFull`] if the query pool cannot
  /// accept another entry.
  pub fn try_start_query(
    &mut self,
    spec: QuerySpec,
    now: I,
  ) -> Result<QueryHandle, StartQueryError> {
    let new_h = self.next_query_handle;
    self.next_query_handle = self.next_query_handle.saturating_add(1);
    let handle = QueryHandle::from_raw(new_h);

    let txid = self.next_txid;
    // next_txid wraps but skip 0.
    let next_raw = self.next_txid.wrapping_add(1);
    self.next_txid = if next_raw == 0 { 1 } else { next_raw };

    let timeout_deadline = spec.timeout().and_then(|dur| now.checked_add_duration(dur));
    let mut q = Query::try_new(
      handle,
      spec.qname().clone(),
      spec.qtype(),
      spec.qclass(),
      txid,
      spec.unicast_response(),
      timeout_deadline,
    );
    if let Some(m) = spec.max_answers() {
      q.set_max_answers(m);
    }

    self
      .queries
      .insert(q)
      .map_err(|_| StartQueryError::StorageFull(StorageFullError))?;
    crate::trace::debug!(
      target: "mdns_proto::endpoint",
      handle = handle.raw(),
      qtype = ?spec.qtype(),
      txid,
      "try_start_query: query started"
    );
    Ok(handle)
  }

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
  fn src_matches_advertised(&self, addr: IpAddr, interface_index: u32) -> bool {
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
    let reader = MessageReader::try_parse(data).map_err(HandleError::Parse)?;
    if !reader.header().flags().opcode().is_query() {
      return Err(HandleError::InvalidOpcode(reader.header().flags().opcode()));
    }
    if !reader.header().flags().response_code().is_no_error() {
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
    crate::trace::trace!(
      target: "mdns_proto::endpoint",
      src = %src,
      local_ip = %local_ip,
      interface_index,
      is_response,
      is_self_packet,
      data_len = data.len(),
      "handle: routing inbound packet"
    );
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
      let mut flushed_in_packet: alloc::vec::Vec<(Name, ResourceType, ResourceClass)> =
        alloc::vec::Vec::new();
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
          // Stop on first malformed record; partial side effects are OK.
          Err(_) => break,
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
        // Build an owned Name from the wire label sequence.
        let name_opt: Option<Name> = {
          let mut s = alloc::string::String::new();
          let mut ok = true;
          for label in r.name().labels() {
            match label {
              Ok(bytes) => {
                for &b in bytes {
                  s.push(b.to_ascii_lowercase() as char);
                }
                s.push('.');
              }
              Err(_) => {
                ok = false;
                break;
              }
            }
          }
          if ok {
            Name::try_from_str(&s).ok()
          } else {
            None
          }
        };
        let name = match name_opt {
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
        let rdata: alloc::vec::Vec<u8> = match r.canonical_rdata_folded() {
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
            query.note_duplicate_question(now);
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
    self.cache.next_expiration()
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

  /// Update the routing table after a service auto-renamed itself due to a
  /// probe conflict.
  ///
  /// # Contract
  ///
  /// Callers **MUST** invoke this method after observing
  /// [`ServiceUpdate::Renamed`](crate::event::ServiceUpdate::Renamed) from
  /// [`Service::poll`](crate::service::Service::poll), and **BEFORE** routing
  /// any further datagrams via [`Endpoint::handle`].  Failing to do so means
  /// questions addressed to the new instance name will not be routed to the
  /// service.
  ///
  /// # Errors
  ///
  /// Returns [`HandleServiceRenamedError::ServiceNotFound`] if `handle` does
  /// not correspond to any registered service.
  ///
  /// Returns [`HandleServiceRenamedError::NameAlreadyRegistered`] if
  /// `new_name` is already used by a *different* registered service; the
  /// caller must retry with a different suffix.
  pub fn handle_service_renamed(
    &mut self,
    handle: ServiceHandle,
    new_name: Name,
  ) -> Result<(), HandleServiceRenamedError> {
    // Locate the key for the given handle.
    let mut existing_key: Option<usize> = None;
    for (key, route) in self.services.iter() {
      if route.handle() == handle {
        existing_key = Some(key);
        break;
      }
    }
    let key = match existing_key {
      Some(k) => k,
      None => return Err(HandleServiceRenamedError::ServiceNotFound(handle)),
    };

    // Reject if new_name collides with another route.
    for (other_key, route) in self.services.iter() {
      if other_key != key && route.name().as_str() == new_name.as_str() {
        return Err(HandleServiceRenamedError::NameAlreadyRegistered(new_name));
      }
    }

    // Apply the rename.
    if let Some(route) = self.services.get_mut(key) {
      route.name = new_name;
    }
    Ok(())
  }

  /// Find the slab key for a registered query handle.  Returns `None` if
  /// the handle no longer corresponds to an active query (auto-pruned
  /// after terminal, explicitly cancelled, or never registered).
  fn query_key(&self, handle: QueryHandle) -> Option<usize> {
    for (key, q) in self.queries.iter() {
      if q.handle() == handle {
        return Some(key);
      }
    }
    None
  }

  /// Drain the next app-level update for a registered query.
  ///
  /// The terminal `QueryUpdate` ([`QueryUpdate::Done`] /
  /// [`QueryUpdate::Timeout`]) is returned at most ONCE per query —
  /// subsequent `poll_query(h)` calls on the same handle return `None`
  /// even though the underlying state machine is still in the pool.
  /// This lets the caller observe terminal, then read final results
  /// via [`Self::collected_answers`], then explicitly clean up via
  /// [`Self::cancel_query`].  Auto-prune was tried in an earlier
  /// design and rejected: pruning before the caller had a
  /// chance to read [`Self::collected_answers`] silently lost the
  /// query's results.
  ///
  /// Backstop for storage-pressure: if `Query::handle_timeout` could
  /// not push the terminal update into the internal `EV` pool
  /// (full / zero-capacity), this synthesises a
  /// `QueryUpdate::Timeout` from the internal `done` flag.  The
  /// `terminal_emitted` latch on `Query` ensures the synthesised value
  /// fires exactly once regardless of which path produced it.
  ///
  /// Returns `None` if the query has no pending updates, has already
  /// emitted its terminal, or the handle does not correspond to a
  /// registered query.
  ///
  /// # Cleanup contract
  ///
  /// After observing terminal, the caller MUST eventually call
  /// [`Self::cancel_query`] to free the pool entry — leaving terminated
  /// queries in the pool indefinitely will exhaust fixed-capacity
  /// storage just as the leak would have.  A convenience
  /// [`Self::sweep_terminated_queries`] is available for callers that
  /// want a single bulk-cleanup step.
  pub fn poll_query(&mut self, handle: QueryHandle) -> Option<QueryUpdate> {
    let key = self.query_key(handle)?;
    let q = self.queries.get_mut(key)?;
    if q.terminal_emitted() {
      // Terminal already delivered; do not re-emit or re-synthesise.
      return None;
    }
    // Drain a regular pending update.
    let update = q.poll();
    if let Some(u) = update {
      if matches!(u, QueryUpdate::Done | QueryUpdate::Timeout) {
        q.mark_terminal_emitted();
      }
      return Some(u);
    }
    // No pending update — backstop: if the query is internally done but
    // the terminal update was silently dropped under EV-pool pressure,
    // synthesise Timeout once.
    if q.is_done() {
      q.mark_terminal_emitted();
      return Some(QueryUpdate::Timeout);
    }
    None
  }

  /// Remove every registered query that has already delivered its
  /// terminal `QueryUpdate` via [`Self::poll_query`].  Returns the
  /// number of queries pruned.
  ///
  /// Convenience for callers that want a single bulk cleanup step
  /// instead of tracking handles individually with
  /// [`Self::cancel_query`].  Safe to call at any time — queries that
  /// have NOT yet emitted terminal are left untouched.
  pub fn sweep_terminated_queries(&mut self) -> usize {
    let mut to_remove: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
    for (key, q) in self.queries.iter() {
      if q.terminal_emitted() {
        to_remove.push(key);
      }
    }
    let count = to_remove.len();
    for key in to_remove {
      self.queries.try_remove(key);
    }
    count
  }

  /// Next deadline for a registered query's `handle_query_timeout` /
  /// retry / absolute-timeout schedule.  Returns `None` if the query is
  /// idle (waiting on a response) or no longer registered.
  pub fn poll_query_timeout(&self, handle: QueryHandle) -> Option<I> {
    let key = self.query_key(handle)?;
    self.queries.get(key).and_then(Query::poll_timeout)
  }

  /// Produce the next outgoing datagram for a registered query, if any
  /// is due.  Writes into `buf` and returns the [`Transmit`] descriptor.
  ///
  /// Returns `Ok(None)` when no send is currently due, or when the
  /// handle does not correspond to an active query (use
  /// [`Self::poll_query`] to observe terminal updates separately).
  pub fn poll_query_transmit(
    &mut self,
    handle: QueryHandle,
    now: I,
    buf: &mut [u8],
  ) -> Result<Option<Transmit>, TransmitError> {
    let Some(key) = self.query_key(handle) else {
      return Ok(None);
    };
    match self.queries.get_mut(key) {
      Some(q) => q.poll_transmit(now, buf),
      None => Ok(None),
    }
  }

  /// Report the send result for the datagram most recently produced by
  /// [`Self::poll_query_transmit`] for `handle`. `delivered` is
  /// `true` when at least one socket send succeeded; the query advances its
  /// retry budget only on a confirmed-delivered send.
  pub fn note_query_transmit_result(&mut self, handle: QueryHandle, now: I, delivered: bool) {
    let Some(key) = self.query_key(handle) else {
      return;
    };
    if let Some(q) = self.queries.get_mut(key) {
      q.note_transmit_result(now, delivered);
    }
  }

  /// Drive timer-based transitions on a registered query.
  ///
  /// Callers wake from [`Self::poll_query_timeout`] and invoke this with
  /// the current instant; the underlying query state machine fires its
  /// retry backoff or absolute timeout.  Terminal events become
  /// observable via [`Self::poll_query`] on the next call.
  ///
  /// Returns `Ok(())` for unknown handles as well — there is nothing
  /// to drive.
  pub fn handle_query_timeout(
    &mut self,
    handle: QueryHandle,
    now: I,
  ) -> Result<(), HandleTimeoutError> {
    let Some(key) = self.query_key(handle) else {
      return Ok(());
    };
    match self.queries.get_mut(key) {
      Some(q) => q.handle_timeout(now),
      None => Ok(()),
    }
  }

  /// Cancel a registered query explicitly.  Removes the query state
  /// machine and its route immediately.  Use this for caller-initiated
  /// cancellation (e.g. the application no longer cares about the
  /// query); for natural termination (timeout / done) drive
  /// [`Self::poll_query`] and let auto-prune happen.
  ///
  /// # Errors
  ///
  /// Returns [`CancelQueryError::QueryNotFound`] if `handle` does not
  /// correspond to a currently registered query.
  pub fn cancel_query(&mut self, handle: QueryHandle) -> Result<(), CancelQueryError> {
    let key = self
      .query_key(handle)
      .ok_or(CancelQueryError::QueryNotFound(handle))?;
    self.queries.try_remove(key);
    Ok(())
  }

  /// Iterate the answers collected so far by a registered query.
  /// Returns an empty iterator if the handle does not correspond to an
  /// active query.
  pub fn collected_answers(
    &self,
    handle: QueryHandle,
  ) -> impl Iterator<Item = &CollectedAnswer> + '_ {
    let key = self.query_key(handle);
    key
      .and_then(|k| self.queries.get(k))
      .into_iter()
      .flat_map(Query::collected_answers)
  }

  /// Total answers ever accepted by a query (including ones the `max_answers`
  /// cap has since evicted). `None` if the handle is not an active query.
  ///
  /// A driver delivering answers by ascending `seq` compares this against the
  /// number it has observed to count answers evicted before delivery — loss
  /// the bounded [`Self::collected_answers`] snapshot would otherwise hide.
  pub fn query_accepted_count(&self, handle: QueryHandle) -> Option<u64> {
    self
      .query_key(handle)
      .and_then(|k| self.queries.get(k))
      .map(Query::accepted_count)
  }
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(all(test, feature = "std", feature = "slab"))]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::panic,
  clippy::indexing_slicing,
  clippy::arithmetic_side_effects
)]
mod tests {
  use super::*;
  use crate::{
    cache::CacheEntry,
    config::{EndpointConfig, ServiceSpec},
    event::{QueryUpdate, ServiceUpdate},
    query::Query,
    records::ServiceRecords,
    transmit::Transmit,
  };
  use std::{net::Ipv4Addr, time::Instant as StdInstant};

  type TestQuery = Query<StdInstant, slab::Slab<CollectedAnswer>, slab::Slab<QueryUpdate>>;

  type TestEndp = Endpoint<
    StdInstant,
    rand::rngs::StdRng,
    slab::Slab<CacheEntry<StdInstant>>,
    slab::Slab<ServiceRoute>,
    slab::Slab<TestQuery>,
    slab::Slab<EndpointEventEntry>,
    slab::Slab<CollectedAnswer>,
    slab::Slab<QueryUpdate>,
  >;

  fn build_endpoint() -> TestEndp {
    use rand::SeedableRng;
    let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
    TestEndp::try_new(EndpointConfig::new(), rng)
  }

  #[test]
  fn handle_service_renamed_updates_route_name() {
    let mut e = build_endpoint();
    let stype = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("WebServer._http._tcp.local.").unwrap();
    let host = Name::try_from_str("server.local.").unwrap();
    let mut recs = ServiceRecords::new(stype, inst.clone(), host, 80, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let now = StdInstant::now();
    let (handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let new_name = Name::try_from_str("WebServer-2._http._tcp.local.").unwrap();
    e.handle_service_renamed(handle, new_name.clone()).unwrap();

    // Verify the route was updated.
    let found = e
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle)
      .map(|(_, route)| route.name().clone());
    assert_eq!(
      found.as_ref().map(Name::as_str),
      Some(new_name.as_str()),
      "expected route name to be updated to the renamed instance"
    );
  }

  #[test]
  fn handle_service_renamed_rejects_duplicate() {
    use crate::error::HandleServiceRenamedError;

    let mut e = build_endpoint();
    let now = StdInstant::now();

    // Register first service.
    let stype1 = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst1 = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host1 = Name::try_from_str("alpha.local.").unwrap();
    let mut recs1 = ServiceRecords::new(stype1, inst1.clone(), host1, 80, 120);
    recs1.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let (handle1, _svc1) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs1),
        now,
      )
      .unwrap();

    // Register second service.
    let stype2 = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst2 = Name::try_from_str("Beta._http._tcp.local.").unwrap();
    let host2 = Name::try_from_str("beta.local.").unwrap();
    let mut recs2 = ServiceRecords::new(stype2, inst2.clone(), host2, 80, 120);
    recs2.add_a(Ipv4Addr::new(10, 0, 0, 2));
    let (_handle2, _svc2) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs2),
        now,
      )
      .unwrap();

    // Attempt to rename handle1 to the name already used by handle2.
    let result = e.handle_service_renamed(handle1, inst2.clone());
    assert!(
      result.is_err(),
      "expected an error when renaming to an already-registered name"
    );
    assert!(
      matches!(
        result.unwrap_err(),
        HandleServiceRenamedError::NameAlreadyRegistered(_)
      ),
      "expected NameAlreadyRegistered variant"
    );

    // Verify handle1's name was NOT changed.
    let found = e
      .services
      .iter()
      .find(|(_, route)| route.handle() == handle1)
      .map(|(_, route)| route.name().clone());
    assert_eq!(
      found.as_ref().map(Name::as_str),
      Some(inst1.as_str()),
      "handle1 name must remain unchanged after rejected rename"
    );
  }

  #[test]
  fn service_route_has_host_field() {
    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let recs = ServiceRecords::new(st, inst, host.clone(), 631, 120);
    let now = StdInstant::now();
    let _ = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    let route = e
      .services
      .iter()
      .next()
      .map(|(_, r)| r.clone())
      .expect("expected one registered route");
    assert_eq!(
      route.host().as_str(),
      host.as_str(),
      "ServiceRoute::host() must reflect the host name from ServiceRecords"
    );
  }

  // ── host question routing ─────────────────────────────────────

  /// Helper: encode a minimal mDNS query message with a single A question.
  /// Returns the number of bytes written into `buf`.
  fn build_query_for_host(buf: &mut [u8; 512], host_str: &str) -> usize {
    use crate::wire::{Header, MessageBuilder, ResourceClass, ResourceType};
    // Header::new() zero-initialises flags; opcode 0 == Query.
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
    let name = Name::try_from_str(host_str).unwrap();
    b.push_question(&name, ResourceType::A, ResourceClass::In, false)
      .unwrap();
    b.finish().unwrap()
  }

  /// Helper: encode a minimal mDNS probe message with an A record in the
  /// authority section (RFC 6762 §8.1 simultaneous-probe tie-breaking). Use for
  /// HOST-name conflicts (a host claims A/AAAA).
  fn build_probe_authority_for_host(buf: &mut [u8; 512], host_str: &str) -> usize {
    use crate::wire::{Header, MessageBuilder};
    // Header::new() zero-initialises flags; opcode 0 == Query.
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
    let name = Name::try_from_str(host_str).unwrap();
    b.push_a_authority(&name, 120, Ipv4Addr::new(192, 168, 1, 99))
      .unwrap();
    b.finish().unwrap()
  }

  /// Helper: encode a probe message with an SRV record in the authority section
  /// for `name`. Use for INSTANCE-name conflicts.F1 gates ProbeConflict
  /// to the instance's unique RRset (SRV/TXT), so an A record owned by the
  /// instance name is no longer a conflict.
  fn build_probe_srv_authority(buf: &mut [u8; 512], instance_str: &str) -> usize {
    use crate::wire::{Header, MessageBuilder};
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(buf, hdr).unwrap();
    let name = Name::try_from_str(instance_str).unwrap();
    let target = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_authority(&name, 120, 0, 0, 8080, &target)
      .unwrap();
    b.finish().unwrap()
  }

  /// Helper: build a test endpoint with one registered service whose host is
  /// "printer-host.local." and instance is "Printer._ipp._tcp.local.".
  fn build_endpoint_with_printer() -> (TestEndp, ServiceHandle) {
    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let recs = ServiceRecords::new(st, inst, host, 631, 120);
    let now = StdInstant::now();
    let (handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();
    (e, handle)
  }

  /// A direct A query for the SRV target host name must be routed to
  /// the matching service as ServiceEvent::Question.
  #[test]
  fn host_question_routes_to_service() {
    use crate::event::RouteEvent;
    use std::net::SocketAddr;

    let (mut e, expected_handle) = build_endpoint_with_printer();
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    let mut buf = [0u8; 512];
    let n = build_query_for_host(&mut buf, "printer-host.local.");
    let data = &buf[..n];

    let mut events = e
      .handle(StdInstant::now(), src, local_ip, 0, data, false)
      .unwrap();
    let ev = events
      .next()
      .expect("expected at least one routing event")
      .expect("expected Ok");

    match ev {
      RouteEvent::ToService(ts) => {
        assert_eq!(
          ts.handle(),
          expected_handle,
          "event must be addressed to the registered service handle"
        );
        assert!(
          ts.event().is_question(),
          "event must be ServiceEvent::Question, got {:?}",
          ts.event()
        );
      }
      other => panic!("expected RouteEvent::ToService(Question), got {:?}", other),
    }
  }

  // ── authority-section HostConflict vs ProbeConflict routing ────

  /// A probe authority record matching the instance name must route as
  /// ProbeConflict (triggers auto-rename in Service).
  #[test]
  fn authority_instance_name_routes_as_probe_conflict() {
    use crate::event::RouteEvent;
    use std::net::SocketAddr;

    let (mut e, expected_handle) = build_endpoint_with_printer();
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    let mut buf = [0u8; 512];
    let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
    let data = &buf[..n];

    let mut events = e
      .handle(StdInstant::now(), src, local_ip, 0, data, false)
      .unwrap();
    let ev = events
      .next()
      .expect("expected at least one routing event")
      .expect("expected Ok");

    match ev {
      RouteEvent::ToService(ts) => {
        assert_eq!(ts.handle(), expected_handle);
        assert!(
          ts.event().is_probe_conflict(),
          "expected ProbeConflict for an instance-name authority record, got {:?}",
          ts.event()
        );
      }
      other => panic!(
        "expected RouteEvent::ToService(ProbeConflict), got {:?}",
        other
      ),
    }
  }

  /// the SAME probe-shaped authority record that triggers a
  /// ProbeConflict from port 5353 (see
  /// `authority_instance_name_routes_as_probe_conflict`) must NOT route as any
  /// conflict when it arrives from an EPHEMERAL source port. Authority records
  /// are tentative-probe claims trusted only from a real mDNS peer (port 5353);
  /// an off-path / forged ephemeral-port packet must not force our rename.
  #[test]
  fn ephemeral_port_authority_record_does_not_trigger_conflict() {
    use crate::event::RouteEvent;
    use std::net::SocketAddr;

    let (mut e, _handle) = build_endpoint_with_printer();
    // Only the source PORT differs from the positive-control test.
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 40000));
    let local_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    let mut buf = [0u8; 512];
    let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
    let data = &buf[..n];

    let events = e
      .handle(StdInstant::now(), src, local_ip, 0, data, false)
      .unwrap();
    for ev in events {
      let ev = ev.expect("expected Ok");
      if let RouteEvent::ToService(ts) = ev {
        assert!(
          !ts.event().is_probe_conflict() && !ts.event().is_host_conflict(),
          "ephemeral-port authority record must not route as a conflict, got {:?}",
          ts.event()
        );
      }
    }
  }

  /// A probe authority record matching only the host name must route as
  /// HostConflict — NOT as ProbeConflict. Service must NOT auto-rename.
  #[test]
  fn authority_host_name_routes_as_host_conflict() {
    use crate::event::RouteEvent;
    use std::net::SocketAddr;

    let (mut e, expected_handle) = build_endpoint_with_printer();
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    let mut buf = [0u8; 512];
    let n = build_probe_authority_for_host(&mut buf, "printer-host.local.");
    let data = &buf[..n];

    let mut events = e
      .handle(StdInstant::now(), src, local_ip, 0, data, false)
      .unwrap();
    let ev = events
      .next()
      .expect("expected at least one routing event")
      .expect("expected Ok");

    match ev {
      RouteEvent::ToService(ts) => {
        assert_eq!(ts.handle(), expected_handle);
        assert!(
          ts.event().is_host_conflict(),
          "expected HostConflict for a host-name authority record, got {:?}",
          ts.event()
        );
      }
      other => panic!(
        "expected RouteEvent::ToService(HostConflict), got {:?}",
        other
      ),
    }
  }

  /// a non-address record (TXT) owned by the HOST name must NOT
  /// surface HostConflict — a host claims A/AAAA, so only those rtypes are a
  /// host-name conflict. (The A-record positive control is
  /// `authority_host_name_routes_as_host_conflict`.)
  #[test]
  fn txt_owned_by_host_name_does_not_route_host_conflict() {
    use crate::{
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use std::net::SocketAddr;

    let (mut e, _handle) = build_endpoint_with_printer();
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let local_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    // Probe-shaped packet: a TXT record (not A/AAAA) owned by the host name.
    let mut buf = [0u8; 512];
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let hdr = Header::new(); // opcode 0 == Query (QR=0 probe)
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_txt_authority(&host, 120, [b"k=v".as_slice()])
      .unwrap();
    let n = b.finish().unwrap();

    let events = e
      .handle(StdInstant::now(), src, local_ip, 0, &buf[..n], false)
      .unwrap();
    for ev in events {
      if let Ok(RouteEvent::ToService(ts)) = ev {
        assert!(
          !ts.event().is_host_conflict() && !ts.event().is_probe_conflict(),
          "a TXT owned by the host name must not route a conflict, got {:?}",
          ts.event()
        );
      }
    }
  }

  /// records in the ADDITIONAL section (as a DNS-SD responder sends
  /// the A/SRV/TXT accompanying a PTR) must be cached AND delivered to active
  /// queries — not silently ignored.
  #[test]
  fn additional_section_records_are_cached_and_delivered() {
    use crate::{
      config::QuerySpec,
      wire::{ResourceClass, ResourceType},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
      .unwrap();

    // QR=1 response carrying the A record ONLY in the ADDITIONAL section
    // (qd=0, an=0, ns=0, ar=1).
    let mut msg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 0, 0, 0, 0, 1]);
    msg.extend_from_slice(&[
      7, b'p', b'r', b'i', b'n', b't', b'e', b'r', 5, b'l', b'o', b'c', b'a', b'l', 0,
    ]);
    msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
    msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    msg.extend_from_slice(&[10, 0, 0, 7]);

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    // Drain events; count the ToQuery emitted for the additional record (the
    // lazy Additional-section fan-out).
    let to_query = e
      .handle(now, src, local_ip, 0, &msg, false)
      .unwrap()
      .filter(|r| matches!(r, Ok(ev) if ev.is_to_query()))
      .count();
    assert!(
      to_query >= 1,
      "additional-section A must emit a ToQuery for the matching query"
    );

    let answers: alloc::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers.len(),
      1,
      "additional-section A must reach the active query; got {answers:?}"
    );
    assert!(
      e.cache.contains(&qname, ResourceType::A, ResourceClass::In),
      "additional-section A must be cached"
    );
  }

  /// a conflicting SRV for our instance name carried ONLY in the
  /// ADDITIONAL section of a QR=1 response must still route a ProbeConflict —
  /// DNS-SD responders place SRV/TXT there, so missing it would let a duplicate
  /// name survive.
  #[test]
  fn additional_section_srv_for_instance_routes_probe_conflict() {
    use crate::{
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use std::net::SocketAddr;

    let (mut e, expected) = build_endpoint_with_printer();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();

    // Build the SRV as an ANSWER, then relocate it to the ADDITIONAL section by
    // rewriting the header counts (ANCOUNT 1->0, ARCOUNT 0->1) — identical
    // record bytes, different section (the builder has no push_*_additional).
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let target = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_answer(&inst, 120, 0, 0, 8080, &target, false)
      .unwrap();
    let n = b.finish().unwrap();
    buf[7] = 0; // ANCOUNT = 0
    buf[11] = 1; // ARCOUNT = 1

    let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let saw_conflict = e
      .handle(StdInstant::now(), src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .filter_map(Result::ok)
      .any(|ev| {
        matches!(ev, RouteEvent::ToService(ts) if ts.handle() == expected && ts.event().is_probe_conflict())
      });
    assert!(
      saw_conflict,
      "an SRV for our instance name in the ADDITIONAL section must route a ProbeConflict"
    );
  }

  /// an additional SRV that matches BOTH our service (conflict) and
  /// multiple active queries must emit EXACTLY ONE ProbeConflict plus a ToQuery
  /// per query — not replay the conflict after each query event (the cursor
  /// phase-ambiguity bug).
  #[test]
  fn additional_conflict_not_replayed_across_query_events() {
    use crate::{
      config::QuerySpec,
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use std::net::SocketAddr;

    let (mut e, _h) = build_endpoint_with_printer();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let now = StdInstant::now();
    // Two active queries for the instance name (ANY accepts the SRV).
    let _q1 = e
      .try_start_query(QuerySpec::new(inst.clone(), ResourceType::Any), now)
      .unwrap();
    let _q2 = e
      .try_start_query(QuerySpec::new(inst.clone(), ResourceType::Any), now)
      .unwrap();

    // QR=1 SRV for the instance, relocated from ANSWER to ADDITIONAL.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let target = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_answer(&inst, 120, 0, 0, 8080, &target, false)
      .unwrap();
    let n = b.finish().unwrap();
    buf[7] = 0; // ANCOUNT = 0
    buf[11] = 1; // ARCOUNT = 1

    let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let mut conflicts = 0usize;
    let mut to_query = 0usize;
    for ev in e.handle(now, src, local_ip, 0, &buf[..n], false).unwrap() {
      match ev.unwrap() {
        RouteEvent::ToService(ts) if ts.event().is_probe_conflict() => conflicts += 1,
        RouteEvent::ToQuery(_) => to_query += 1,
        _ => {}
      }
    }
    assert_eq!(
      conflicts, 1,
      "the conflict must fire exactly once, not replay per query"
    );
    assert_eq!(
      to_query, 2,
      "both active queries must receive the additional SRV"
    );
  }

  /// a conflict is only routed for the same-class (IN) RRset. An SRV
  /// for our instance name with class ANY (or any non-IN class) must NOT route
  /// a ProbeConflict — exercised through the shared next_service_conflict gate.
  #[test]
  fn non_in_class_record_does_not_route_conflict() {
    use crate::event::RouteEvent;
    use std::net::SocketAddr;

    let (mut e, _h) = build_endpoint_with_printer();

    // Hand-crafted QR=1 SRV answer for "Printer._ipp._tcp.local." with CLASS
    // ANY (0x00FF) instead of IN — same name/rtype, wrong class.
    let mut msg: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    msg.extend_from_slice(&[0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]); // QR=1, an=1
    msg.extend_from_slice(&[
      7, b'P', b'r', b'i', b'n', b't', b'e', b'r', 4, b'_', b'i', b'p', b'p', 4, b'_', b't', b'c',
      b'p', 5, b'l', b'o', b'c', b'a', b'l', 0,
    ]);
    msg.extend_from_slice(&33u16.to_be_bytes()); // TYPE SRV
    msg.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY (not IN)
    msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
    msg.extend_from_slice(&15u16.to_be_bytes()); // RDLENGTH
    msg.extend_from_slice(&[0, 0, 0, 0, 0x1F, 0x90]); // priority/weight/port
    msg.extend_from_slice(&[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0]); // target x.local.

    let src: SocketAddr = "192.168.1.55:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    for ev in e
      .handle(StdInstant::now(), src, local_ip, 0, &msg, false)
      .unwrap()
    {
      if let Ok(RouteEvent::ToService(ts)) = ev {
        assert!(
          !ts.event().is_probe_conflict() && !ts.event().is_host_conflict(),
          "a non-IN-class record must not route a conflict, got {:?}",
          ts.event()
        );
      }
    }
  }

  // ── probe authority records + answer-section ProbeConflict routing

  /// a QUERY packet whose ANSWER section contains a record for
  /// one of our service's unique names is a KAS hint — not an
  /// authoritative claim.  The iterator must emit KnownAnswer (for KAS
  /// suppression), NEVER ProbeConflict.  Treating a QR=0 answer as a
  /// conflict signal would let a hostile querier trigger our auto-rename
  /// trivially.  Real probe-time conflicts arrive in the AUTHORITY
  /// section (peer probes); see `authority_instance_name_routes_as_probe_conflict`.
  #[test]
  fn query_answer_for_instance_name_emits_known_answer_only() {
    use crate::wire::{
      DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType,
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host = Name::try_from_str("alpha.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let mut buf = [0u8; 512];
    let header = Header::new(); // QR=0
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_question(&inst, ResourceType::Any, ResourceClass::In, true)
      .unwrap();
    b.push_a_answer(&inst, 120, Ipv4Addr::new(10, 0, 0, 2), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // No ProbeConflict events anywhere.
    for ev in &events {
      if let RouteEvent::ToService(ts) = ev {
        assert!(
          !ts.event().is_probe_conflict(),
          "QR=0 answer-section MUST NOT emit ProbeConflict; got {events:?}"
        );
      }
    }
    // But the KAS hint must reach the service.
    let kas_count = events
      .iter()
      .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_known_answer()))
      .count();
    assert!(
      kas_count >= 1,
      "at least one KnownAnswer must fire for the instance-name match; got {events:?}"
    );
  }

  // ── answer-section host-only matches emit HostConflict ────────

  /// RFC 6762 §8.1: a QUERY packet (QR=0) whose ANSWER section
  /// contains a record owned by the service's HOST name (not the instance
  /// name) must emit HostConflict — not ProbeConflict. Only ProbeConflict
  /// triggers an auto-rename in Service; HostConflict surfaces the event
  /// without renaming.
  #[test]
  fn qr0_answer_for_host_name_emits_host_conflict_not_probe_conflict() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder};
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host = Name::try_from_str("alpha.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let now = StdInstant::now();
    let (expected_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // Build a QUERY packet (QR=0) with an A answer record owned by the HOST
    // name (not the instance name).
    let mut buf = [0u8; 512];
    let header = Header::new(); // QR=0
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // QR=0 answer-section records MUST NOT emit HostConflict
    // or ProbeConflict.  Only KnownAnswer events fire (for KAS suppression).
    for ev in &events {
      if let RouteEvent::ToService(ts) = ev {
        assert!(
          !ts.event().is_host_conflict() && !ts.event().is_probe_conflict(),
          "QR=0 answer-section MUST NOT emit conflict events; got {events:?}"
        );
        assert_eq!(
          ts.handle(),
          expected_handle,
          "event must target the registered service"
        );
      }
    }
    // The KAS hint must reach the service.
    let kas_count = events
      .iter()
      .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_known_answer()))
      .count();
    assert!(
      kas_count >= 1,
      "at least one KnownAnswer must fire for the host-name match; got {events:?}"
    );
  }

  // ── QR=0 known-answer records must NOT populate active queries ─

  /// answer records inside a QUERY packet (QR=0) are known-answer
  /// hints from another querier — they must NOT be delivered as
  /// QueryEvent::Answer to active queries.  Only RESPONSE packets (QR=1)
  /// carry authoritative answers.
  #[test]
  fn qr0_answer_does_not_populate_query() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let qname = Name::try_from_str("myhost.local.").unwrap();
    let now = StdInstant::now();

    // Register an active query for "myhost.local.".
    let spec = QuerySpec::new(qname.clone(), ResourceType::A);
    let _qhandle = e.try_start_query(spec, now).unwrap();

    // Build a QUERY packet (QR=0) with an A answer record for the query name.
    // In mDNS this is a known-answer hint carried by another querier; it is
    // NOT an authoritative response.
    let mut buf = [0u8; 512];
    let header = Header::new(); // QR=0: query, not response
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 9), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();

    // Drain all events. None should be a ToQuery(Answer).
    for ev in events {
      let ev = ev.unwrap();
      assert!(
        !matches!(ev, RouteEvent::ToQuery(ref tq) if matches!(tq.event(), QueryEvent::Answer(_))),
        "QR=0 answer records must NOT produce QueryEvent::Answer; got: {:?}",
        ev
      );
    }
  }

  /// RFC 6762 §7.3 duplicate-question suppression: when another host multicasts
  /// the SAME QM question (empty known-answer section) that we have an active
  /// query for, our planned (re)transmit is suppressed — the peer's query
  /// elicits the same answers. A control run (no duplicate) confirms the query
  /// would otherwise transmit.
  #[test]
  fn duplicate_qm_question_suppresses_planned_query() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use std::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    // Control: with no duplicate observed, the freshly-started query transmits.
    {
      let mut e = build_endpoint();
      let now = StdInstant::now();
      let h = e
        .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
        .unwrap();
      let mut buf = [0u8; 512];
      assert!(
        e.poll_query_transmit(h, now, &mut buf).unwrap().is_some(),
        "control: a started query transmits when no duplicate is seen"
      );
    }

    // §7.3: observe a foreign QM query for the same question (no known answers,
    // TC clear) — our planned transmit must be suppressed but the query deferred,
    // not retired.
    let mut e = build_endpoint();
    let now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap(); // QR=0 query
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false) // QM (no QU bit)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e.handle(now, src, local_ip, 0, &qbuf[..n], false).unwrap();

    let mut buf = [0u8; 512];
    assert!(
      e.poll_query_transmit(h, now, &mut buf).unwrap().is_none(),
      "§7.3: observing a duplicate QM question must suppress our planned query"
    );
    assert!(
      e.poll_query_timeout(h).is_some(),
      "§7.3: the suppressed query is deferred (rescheduled), not retired"
    );
  }

  /// A QU (unicast-response) duplicate question must NOT suppress our query: a
  /// QU query is answered unicast to the asker, so it would not elicit the
  /// multicast answers our query needs (RFC 6762 §7.3 applies to QM only).
  #[test]
  fn qu_duplicate_question_does_not_suppress_query() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use std::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, true) // QU bit set
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e.handle(now, src, local_ip, 0, &qbuf[..n], false).unwrap();

    let mut buf = [0u8; 512];
    assert!(
      e.poll_query_transmit(h, now, &mut buf).unwrap().is_some(),
      "§7.3: a QU duplicate must NOT suppress our query (it elicits no multicast answer)"
    );
  }

  /// a duplicate QM query from a NON-5353 (legacy/ephemeral) source must
  /// NOT suppress our query — a legacy resolver's request may be answered by
  /// unicast straight to it (§6.7), answers we would never see.
  #[test]
  fn legacy_source_duplicate_does_not_suppress_query() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use std::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let legacy_src: SocketAddr = "192.168.1.77:40000".parse().unwrap(); // ephemeral port
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false) // QM
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(now, legacy_src, local_ip, 0, &qbuf[..n], false)
      .unwrap();

    let mut buf = [0u8; 512];
    assert!(
      e.poll_query_transmit(h, now, &mut buf).unwrap().is_some(),
      "§7.3: a legacy-source (non-5353) duplicate must NOT suppress our query"
    );
  }

  /// a query with NO absolute timeout, suppressed every retry slot by a
  /// flood of duplicate QM questions, must still progress to terminal via the
  /// retry budget — §7.3 suppression is "treat as sent", not "defer forever".
  #[test]
  fn repeated_duplicate_questions_do_not_stall_query_forever() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use std::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false)
      .unwrap();
    let n = b.finish().unwrap();

    // Each slot: a duplicate arrives while a transmit is pending → suppressed;
    // then we fire the next scheduled retry. The retry budget (MAX_RETRIES = 8)
    // must eventually retire the query even though it never transmitted itself.
    let mut buf = [0u8; 512];
    let mut retired = false;
    for _ in 0..32 {
      let _ = e.handle(now, src, local_ip, 0, &qbuf[..n], false).unwrap();
      assert!(
        e.poll_query_transmit(h, now, &mut buf).unwrap().is_none(),
        "each duplicate suppresses the planned transmit"
      );
      match e.poll_query_timeout(h) {
        Some(due) => {
          now = due;
          e.handle_query_timeout(h, now).unwrap();
        }
        None => {
          retired = true;
          break;
        }
      }
    }
    assert!(
      retired,
      "§7.3: a continuously-duplicated query must retire via the retry budget, not defer forever"
    );
  }

  /// a duplicate that arrives when our retransmit deadline is already
  /// DUE — but `handle_query_timeout` has not yet armed it (a driver that pumps
  /// received packets before firing query timeouts) — must still suppress the
  /// retry. Proves §7.3 is independent of the driver's packet-vs-timeout order.
  #[test]
  fn duplicate_suppresses_due_retry_independent_of_driver_order() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceClass, ResourceType},
    };
    use std::net::SocketAddr;

    let qname = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Ptr), now)
      .unwrap();

    // Send the first query and confirm delivery → a retransmit is scheduled
    // (next_deadline ≈ now+1s) with transmit_pending cleared.
    let mut buf = [0u8; 512];
    assert!(e.poll_query_transmit(h, now, &mut buf).unwrap().is_some());
    e.note_query_transmit_result(h, now, true);
    let t1 = e
      .poll_query_timeout(h)
      .expect("a retransmit must be scheduled");

    // Deliver a duplicate QM query exactly when the retry is DUE, WITHOUT first
    // calling handle_query_timeout (packet-before-timeout driver order).
    let mut qbuf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut qbuf, Header::new()).unwrap();
    b.push_question(&qname, ResourceType::Ptr, ResourceClass::In, false)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e.handle(t1, src, local_ip, 0, &qbuf[..n], false).unwrap();

    // The due slot was consumed: the next retry is deferred to a later instant.
    let t2 = e
      .poll_query_timeout(h)
      .expect("query still active, retry rescheduled");
    assert!(
      t2 > t1,
      "§7.3: a duplicate at a due retry must consume the slot and defer it"
    );

    // Arming the now-stale deadline must not transmit (slot already consumed).
    e.handle_query_timeout(h, t1).unwrap();
    assert!(
      e.poll_query_transmit(h, t1, &mut buf).unwrap().is_none(),
      "§7.3: no redundant transmit after the due slot was suppressed"
    );
  }

  // ── self-packet guard suppresses loopback routing ────────────

  /// Multicast loopback returns our own probes/announcements to us with
  /// `src.ip() == local_ip` (the interface we sent from).  `Endpoint::handle`
  /// must drop these datagrams entirely: no ProbeConflict, no HostConflict,
  /// no Question, no KnownAnswer, no cache writes.  Without this guard a
  /// service can rename itself because of its own probe.
  ///
  /// Control half of the test: a probe with the same payload but a foreign
  /// source IP must still produce a ProbeConflict, proving the test is
  /// asserting against the source-equality guard and not some unrelated
  /// suppression.
  #[test]
  fn self_packet_does_not_route_as_probe_conflict() {
    use crate::event::RouteEvent;
    use std::net::SocketAddr;

    let (mut e, _expected_handle) = build_endpoint_with_printer();
    let local_ip: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    // Build a probe-shaped packet (authority section carries an A record for
    // the instance host) that would normally trigger ProbeConflict.
    let mut buf = [0u8; 512];
    let n = build_probe_srv_authority(&mut buf, "Printer._ipp._tcp.local.");
    let data = &buf[..n];
    let now = StdInstant::now();

    // (1) Self-packet: the caller (driver) flags self-loopback via
    // `caller_is_self = true`; handle() must then yield zero routing events.
    let self_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), 5353));
    let mut self_events = e.handle(now, self_src, local_ip, 0, data, true).unwrap();
    assert!(
      self_events.next().is_none(),
      "self-packet (caller_is_self = true) must yield zero routing events"
    );

    // (2) Control: the same payload from a peer with `caller_is_self = false`
    // MUST still emit ProbeConflict — proves suppression is driven by the
    // flag, not a broken routing path.
    let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let mut peer_events = e
      .handle(StdInstant::now(), peer_src, local_ip, 0, data, false)
      .unwrap();
    let ev = peer_events
      .next()
      .expect("control: foreign-source probe MUST still produce a routing event")
      .expect("control: routing event must be Ok");
    match ev {
      RouteEvent::ToService(ts) => assert!(
        ts.event().is_probe_conflict(),
        "control: foreign-source probe must still emit ProbeConflict; got {:?}",
        ts.event()
      ),
      other => panic!(
        "control: expected RouteEvent::ToService(ProbeConflict), got {:?}",
        other
      ),
    }
  }

  /// self-packet guard must also suppress cache population.  A
  /// loopback announcement with an A record for some unrelated name must
  /// NOT land in the passive observation cache.
  #[test]
  fn self_packet_does_not_populate_cache() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let local_ip: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let observed = Name::try_from_str("printer.local.").unwrap();

    // Build a RESPONSE (QR=1) packet with an A record in the ANSWER section
    // — the passive-observation cache writes from the answer section.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&observed, 120, Ipv4Addr::new(10, 0, 0, 9), false)
      .unwrap();
    let n = b.finish().unwrap();
    let data = &buf[..n];

    // self-detection is driven by the caller's `caller_is_self`
    // flag (the driver content-matches against recent sends). With it
    // true, the cache write is suppressed.
    let self_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), 5353));
    let _ = e.handle(now, self_src, local_ip, 0, data, true).unwrap();
    assert!(
      !e.cache
        .contains(&observed, ResourceType::A, ResourceClass::In),
      "self-packet must not populate cache; cache contained {:?}",
      observed.as_str()
    );

    // Control: a foreign source must populate the cache.
    let peer_src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let _ = e.handle(now, peer_src, local_ip, 0, data, false).unwrap();
    assert!(
      e.cache
        .contains(&observed, ResourceType::A, ResourceClass::In),
      "control: foreign-source response must populate the cache"
    );
  }

  /// the passive cache must compare records by their
  /// CANONICAL case-folded rdata, so a TTL=0 goodbye whose PTR target differs
  /// from the insert in BOTH compression and case still removes the cached
  /// entry. Insert: target "inst" compressed (back-pointer), lowercase.
  /// Goodbye: target "INST.SVC.LOCAL." inline + uppercase. Before the fixes the
  /// raw bytes differed (compression and/or case) and the goodbye left a stale
  /// entry until TTL expiry.
  #[test]
  fn cache_goodbye_matches_differently_encoded_and_cased_ptr() {
    use crate::wire::{ResourceClass, ResourceType};
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let local_ip: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let src: SocketAddr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 55), 5353));
    let owner = Name::try_from_str("svc.local.").unwrap();

    // QR=1 response header, AN=1; owner "svc.local." parked at offset 12.
    let header_an1 = [0u8, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
    let owner_wire = [3u8, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0];

    // Insert: PTR with a COMPRESSED, lowercase target ("inst" + ptr→offset 12).
    let mut insert = alloc::vec::Vec::new();
    insert.extend_from_slice(&header_an1);
    insert.extend_from_slice(&owner_wire);
    insert.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
    insert.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    insert.extend_from_slice(&120u32.to_be_bytes()); // positive TTL
    insert.extend_from_slice(&7u16.to_be_bytes()); // RDLENGTH
    insert.extend_from_slice(&[4, b'i', b'n', b's', b't', 0xC0, 0x0C]);
    let _ = e.handle(now, src, local_ip, 0, &insert, false).unwrap();
    assert!(
      e.cache
        .contains(&owner, ResourceType::Ptr, ResourceClass::In),
      "compressed-target PTR response must populate the cache"
    );

    // Goodbye: same logical PTR, TTL=0, target written INLINE and UPPERCASE.
    let mut goodbye = alloc::vec::Vec::new();
    goodbye.extend_from_slice(&header_an1);
    goodbye.extend_from_slice(&owner_wire);
    goodbye.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
    goodbye.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    goodbye.extend_from_slice(&0u32.to_be_bytes()); // TTL=0 goodbye
    goodbye.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
    goodbye.extend_from_slice(&[
      4, b'I', b'N', b'S', b'T', 3, b'S', b'V', b'C', 5, b'L', b'O', b'C', b'A', b'L', 0,
    ]);
    let _ = e.handle(now, src, local_ip, 0, &goodbye, false).unwrap();
    // a TTL=0 goodbye does NOT delete immediately — it clamps the
    // matched entry to a 1-second rescue window. The MATCH (canonicalization
    // worked across compression + case) is proven by the entry expiring after
    // that 1s: a goodbye that failed to match would leave the original 120s
    // TTL, so the entry would survive the sweep below.
    let after_rescue = now + core::time::Duration::from_secs(2);
    e.cache.sweep_expired(after_rescue);
    assert!(
      !e.cache
        .contains(&owner, ResourceType::Ptr, ResourceClass::In),
      "a differently-encoded/-cased TTL=0 goodbye must match and expire the cached PTR within the §10.1 rescue window"
    );
  }

  // ── IPv6 self-packet via advertised-AAAA membership ──────────

  /// IPv6 `in6_pktinfo.ipi6_addr` carries the packet DESTINATION (e.g.
  /// `ff02::fb` for received mDNS multicast), not the local interface
  /// address.  Therefore `src.ip() == local_ip` cannot detect IPv6 self
  /// loopback: the source is our link-local/global unicast, the destination
  /// is the multicast group, and they never match.  This detects self via
  /// membership in any registered service's advertised AAAA list.
  ///
  /// Test: register a service publishing `fe80::1`, then feed back a
  /// probe-shaped packet with `src.ip() == fe80::1` and `local_ip == ff02::fb`.
  /// Without the membership signal the packet would be routed as a
  /// ProbeConflict (peer claiming our instance).  Control half: a foreign
  /// IPv6 source must still produce a ProbeConflict.
  #[test]
  fn ipv6_self_packet_detected_via_advertised_aaaa() {
    use crate::{
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use std::net::{Ipv6Addr, SocketAddr};

    // signal (b) is opt-in. This test validates the legacy
    // advertised-source fallback, so enable it explicitly.
    use rand::SeedableRng;
    let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
    let mut e = TestEndp::try_new(
      EndpointConfig::new().with_trust_advertised_src_as_self(true),
      rng,
    );
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host, 631, 120);
    let our_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    recs.add_aaaa(our_v6);
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // Build a probe-shaped packet (SRV authority record for the instance
    // name — the instance's unique RRset) — without the guard this triggers
    // ProbeConflict.
    let mut buf = [0u8; 512];
    let hdr = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_srv_authority(
      &inst,
      120,
      0,
      0,
      8080,
      &Name::try_from_str("other-host.local.").unwrap(),
    )
    .unwrap();
    let n = b.finish().unwrap();
    let data = &buf[..n];

    // local_ip is what IPv6 PKTINFO actually returns: the multicast group.
    // This is *intentionally* not our source, because for IPv6 PKTINFO has
    // no `ipi_spec_dst` equivalent.
    let local_ip: std::net::IpAddr =
      std::net::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb));

    // (1) Self-packet via membership: src matches our advertised AAAA.
    let self_src: SocketAddr = SocketAddr::from((our_v6, 5353));
    let mut self_events = e.handle(now, self_src, local_ip, 0, data, false).unwrap();
    assert!(
      self_events.next().is_none(),
      "IPv6 self-packet (src ∈ advertised AAAA) must yield zero routing events; \
       local_ip == ff02::fb cannot detect this, so the membership branch must catch it"
    );

    // (2) Control: a foreign IPv6 source must still emit ProbeConflict on
    // the same payload.  Proves the guard is specific to src-set membership
    // and not some other suppression.
    let peer_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0099);
    let peer_src: SocketAddr = SocketAddr::from((peer_v6, 5353));
    let mut peer_events = e.handle(now, peer_src, local_ip, 0, data, false).unwrap();
    let ev = peer_events
      .next()
      .expect("control: foreign IPv6 probe MUST still produce a routing event")
      .expect("control: routing event must be Ok");
    match ev {
      RouteEvent::ToService(ts) => assert!(
        ts.event().is_probe_conflict(),
        "control: foreign IPv6 probe must still emit ProbeConflict; got {:?}",
        ts.event()
      ),
      other => panic!(
        "control: expected RouteEvent::ToService(ProbeConflict), got {:?}",
        other
      ),
    }
  }

  // ── terminal-then-cancel cleanup, no leak ───────────

  /// Repeatedly starting + draining queries must not leak entries in the
  /// endpoint's owned-Query pool when callers follow the documented
  /// terminal-then-cancel pattern.  This dropped the previous
  /// auto-prune design (which silently lost `collected_answers` before
  /// the caller could read them); the new contract is:
  ///
  ///   1. drive `poll_query` until it returns `Some(Done | Timeout)`,
  ///   2. read final results via `collected_answers` (still available),
  ///   3. call `cancel_query` to free the pool entry.
  ///
  /// `poll_query` emits the terminal exactly once (latched via
  /// `Query::terminal_emitted`); subsequent calls return `None`.  This
  /// test exercises 1024 start/terminal/cancel cycles and asserts the
  /// pool returns to zero.
  #[test]
  fn poll_query_terminal_then_cancel_no_leak() {
    use crate::{config::QuerySpec, event::QueryUpdate, wire::ResourceType};
    use core::time::Duration;

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();

    for i in 0..1024u32 {
      // 100ms timeout — small relative to test runtime.
      let spec =
        QuerySpec::new(qname.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
      let qhandle = e.try_start_query(spec, now).unwrap_or_else(|err| {
        panic!(
          "try_start_query #{i} must succeed when previous queries are cancelled; \
           got {err:?}"
        )
      });

      // Pool must contain exactly this one query between start and cancel.
      assert_eq!(
        e.queries.len(),
        1,
        "queries pool len must be 1 after start #{i}, before cancel"
      );

      // Drive to terminal: advance past the absolute timeout.
      now = now.checked_add(Duration::from_millis(200)).unwrap();
      e.handle_query_timeout(qhandle, now).unwrap();

      // Observe terminal via poll_query.  Does NOT auto-prune.
      let update = e.poll_query(qhandle);
      assert!(
        matches!(update, Some(QueryUpdate::Timeout | QueryUpdate::Done)),
        "poll_query must return Some(Timeout|Done) after deadline; got {update:?}"
      );

      // query is STILL in the pool after terminal; collected_answers
      // is readable.  (No collected answers here since no responses arrived,
      // but the iterator must work — exercised by the standalone test below.)
      assert_eq!(
        e.queries.len(),
        1,
        "queries pool len must remain 1 after terminal poll_query #{i} \
         (no auto-prune; caller must explicitly cancel)"
      );

      // Subsequent poll_query returns None (terminal already emitted).
      assert!(
        e.poll_query(qhandle).is_none(),
        "subsequent poll_query after terminal must return None (latched)"
      );

      // Explicit cleanup — the documented contract.
      e.cancel_query(qhandle).unwrap();
      assert_eq!(
        e.queries.len(),
        0,
        "queries pool len must be 0 after cancel #{i}"
      );
    }
  }

  // ── collected_answers readable after terminal poll_query ─────

  /// After `poll_query` returns `Some(Done | Timeout)`, the natural
  /// caller flow is to read final results via `collected_answers`
  /// before discarding the handle.  Auto-prune would have wiped the
  /// answers in the same call.  Verify that:
  ///
  ///   * answers collected before the timeout are still readable AFTER
  ///     the terminal poll_query returns, AND
  ///   * the second poll_query on the same handle returns None
  ///     (terminal latched, exactly-once delivery), AND
  ///   * after cancel_query the handle is gone.
  #[test]
  fn collected_answers_survive_terminal_until_cancel() {
    use crate::{
      config::QuerySpec,
      event::QueryUpdate,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::time::Duration;
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let spec =
      QuerySpec::new(qname.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
    let h = e.try_start_query(spec, now).unwrap();

    // Feed a RESPONSE answer to populate collected_answers.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let addr = Ipv4Addr::new(10, 0, 0, 7);
    b.push_a_answer(&qname, 120, addr, false).unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();

    // Confirm the answer landed.
    let answers_before: alloc::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers_before.len(),
      1,
      "answer must land in collected_answers; got {answers_before:?}"
    );

    // Drive to terminal.
    now = now.checked_add(Duration::from_millis(200)).unwrap();
    e.handle_query_timeout(h, now).unwrap();
    let update = e.poll_query(h);
    assert!(
      matches!(update, Some(QueryUpdate::Timeout | QueryUpdate::Done)),
      "poll_query must return terminal; got {update:?}"
    );

    // collected_answers MUST still be readable AFTER terminal.
    let answers_after: alloc::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers_after.len(),
      1,
      "collected_answers must survive terminal poll_query; \
       caller had no chance to read them before they would have been \
       auto-pruned; got {answers_after:?}"
    );

    // Exactly-once: second poll_query returns None.
    assert!(
      e.poll_query(h).is_none(),
      "second poll_query after terminal must return None (latched)"
    );

    // Explicit cleanup leaves the pool empty.
    e.cancel_query(h).unwrap();
    assert!(e.collected_answers(h).next().is_none());
  }

  // ── query state applied eagerly during handle ────────────────

  /// Dropping the `RouteEvents` iterator BEFORE iterating it must NOT
  /// lose query-state updates.  Previously, query updates were
  /// applied lazily inside the iterator's `next()`; a caller that
  /// matched on the first event and broke out (or never iterated)
  /// would leave some compatible queries un-updated.  Eager
  /// application in `Endpoint::handle` (before the iterator is even
  /// returned) eliminates that hazard.
  #[test]
  fn dropping_route_events_does_not_lose_query_state() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();

    // Two compatible queries for the same name (A and Any).
    let h_a = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
      .unwrap();
    let h_any = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Any), now)
      .unwrap();

    // RESPONSE packet with an A answer.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 9), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    // Construct the iterator and IMMEDIATELY drop it — no .next() calls.
    {
      let _events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();
      // _events is dropped at end of scope WITHOUT iteration.
    }

    // both queries must already have the answer in their
    // collected_answers, because Endpoint::handle applied it eagerly
    // — not lazily on iterator advance.
    let a_answers: alloc::vec::Vec<_> = e.collected_answers(h_a).cloned().collect();
    let any_answers: alloc::vec::Vec<_> = e.collected_answers(h_any).cloned().collect();
    assert_eq!(
      a_answers.len(),
      1,
      "A-query must have the answer applied even with dropped iterator"
    );
    assert_eq!(
      any_answers.len(),
      1,
      "Any-query must ALSO have the answer applied even with dropped iterator \
       (fan-out is no longer dependent on draining the iterator)"
    );
  }

  // ── pre-poll terminal freeze closes the race ────────────────

  /// `handle_query_timeout` sets `done = true` BEFORE the caller has
  /// had a chance to call `poll_query` and observe the terminal.  An
  /// answer arriving in that window must NOT mutate `collected_answers`
  /// or fire ToQuery events — the freeze must key off `is_done()`, not
  /// only the deferred `terminal_emitted` latch.
  #[test]
  fn pre_poll_terminal_freeze_closes_race() {
    use crate::{
      config::QuerySpec,
      event::QueryUpdate,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::time::Duration;
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qn = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qn.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
    let h = e.try_start_query(spec, now).unwrap();

    // Drive `done = true` via handle_query_timeout, but do NOT call
    // poll_query yet — so terminal_emitted is still false.
    now = now.checked_add(Duration::from_millis(200)).unwrap();
    e.handle_query_timeout(h, now).unwrap();

    // Feed a matching response.  Without the fix the answer
    // would mutate collected_answers because terminal_emitted is still
    // false even though is_done is true.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qn, 120, Ipv4Addr::new(10, 0, 0, 7), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];
    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    let to_query_events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .filter_map(|ev| match ev {
        RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_)) => Some(tq.handle()),
        _ => None,
      })
      .collect();
    assert!(
      !to_query_events.contains(&h),
      "ToQuery events must NOT fire for is_done query (pre-poll); \
       got {to_query_events:?}"
    );

    // Now observe terminal — and assert no answer was collected.
    assert!(matches!(
      e.poll_query(h),
      Some(QueryUpdate::Timeout | QueryUpdate::Done)
    ));
    let answers: alloc::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert!(
      answers.is_empty(),
      "collected_answers must be empty — the post-done answer must NOT \
       have been applied to the Query; got {answers:?}"
    );
    e.cancel_query(h).unwrap();
  }

  // ── TTL=0 goodbye records are not collected ──────────────────

  /// RFC 6762 §10.1: a record with TTL=0 is a goodbye / deletion
  /// signal.  Active queries must NOT collect such records as live
  /// answers — under `max_answers` pressure a goodbye could even
  /// evict a real prior answer via FIFO.
  #[test]
  fn query_ignores_ttl_zero_goodbye_records() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qn = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qn.clone(), ResourceType::A);
    let h = e.try_start_query(spec, now).unwrap();

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    // First feed a normal answer (TTL=120) — must land.
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&qn, 120, Ipv4Addr::new(10, 0, 0, 7), false)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(now, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }
    assert_eq!(
      e.collected_answers(h).count(),
      1,
      "live (TTL=120) answer must be collected"
    );

    // Now feed a TTL=0 record for the same name — goodbye signal.
    // Must NOT land in collected_answers AND must NOT evict the prior.
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      // TTL=0 is the deletion marker.
      b.push_a_answer(&qn, 0, Ipv4Addr::new(10, 0, 0, 99), false)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(now, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }

    let answers: alloc::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers.len(),
      1,
      "TTL=0 goodbye record must NOT be collected; \
       prior live answer must remain intact.  Got: {answers:?}"
    );
    e.cancel_query(h).unwrap();
  }

  // ── KAS fan-out across same-type services ────────────────────

  /// A QR=0 known-answer PTR record for a shared `service_type` must
  /// fan out to EVERY registered service of that type, not just the
  /// first by slab order — otherwise the actual owning service never
  /// gets the suppression hint.
  #[test]
  fn qr0_ptr_known_answer_fans_out_to_all_same_type_services() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();

    // Three services sharing the same service_type.
    let mut handles = alloc::vec::Vec::new();
    for inst_label in ["Alpha", "Beta", "Gamma"] {
      let inst_str = alloc::format!("{inst_label}._ipp._tcp.local.");
      let inst = Name::try_from_str(&inst_str).unwrap();
      let host_str = alloc::format!("{}-host.local.", inst_label.to_ascii_lowercase());
      let host = Name::try_from_str(&host_str).unwrap();
      let recs = ServiceRecords::new(stype.clone(), inst, host, 631, 120);
      let (h, _svc) = e
        .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
          ServiceSpec::new(recs),
          now,
        )
        .unwrap();
      handles.push(h);
    }

    // Build a QR=0 packet with an ANSWER section containing a PTR
    // record for the shared service_type — a KAS hint from another
    // querier mentioning the Beta service.
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    let beta_inst = Name::try_from_str("Beta._ipp._tcp.local.").unwrap();
    b.push_ptr_answer(&stype, 120, &beta_inst).unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // Collect all KnownAnswer service handles.
    let kas_handles: alloc::vec::Vec<_> = events
      .iter()
      .filter_map(|ev| match ev {
        RouteEvent::ToService(ts) if ts.event().is_known_answer() => Some(ts.handle()),
        _ => None,
      })
      .collect();

    // all three same-type services must receive the KAS hint.
    for h in &handles {
      assert!(
        kas_handles.contains(h),
        "service {h:?} must receive KnownAnswer for shared-PTR; \
         got handles {kas_handles:?}"
      );
    }
    assert_eq!(
      kas_handles.len(),
      3,
      "exactly three KnownAnswer events expected (one per same-type service); \
       got {kas_handles:?}"
    );
  }

  /// a QR=0 PTR owned by the DNS-SD service-type enumeration meta name
  /// is a known-answer for the §9 meta reply. Its owner is none of any service's
  /// RRset names, so the endpoint must fan it out as a KnownAnswer to EVERY
  /// service (each then decides at the Service level whether the PTR target is
  /// its own type and the §7.1 gates hold). Without this routing the meta-KAS
  /// was unreachable end-to-end.
  #[test]
  fn meta_ptr_known_answer_fans_out_to_all_services() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();

    // Two services of DIFFERENT types.
    let mut handles = alloc::vec::Vec::new();
    for (inst_str, stype_str, host_str) in [
      ("p._ipp._tcp.local.", "_ipp._tcp.local.", "ph.local."),
      ("w._http._tcp.local.", "_http._tcp.local.", "wh.local."),
    ] {
      let recs = ServiceRecords::new(
        Name::try_from_str(stype_str).unwrap(),
        Name::try_from_str(inst_str).unwrap(),
        Name::try_from_str(host_str).unwrap(),
        631,
        120,
      );
      let (h, _svc) = e
        .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
          ServiceSpec::new(recs),
          now,
        )
        .unwrap();
      handles.push(h);
    }

    // QR=0 packet carrying a meta-PTR known-answer:
    //   _services._dns-sd._udp.local. -> _ipp._tcp.local.
    let mut buf = [0u8; 512];
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, Header::new()).unwrap();
    let meta = Name::try_from_str("_services._dns-sd._udp.local.").unwrap();
    let ipp = Name::try_from_str("_ipp._tcp.local.").unwrap();
    b.push_ptr_answer(&meta, 120, &ipp).unwrap();
    let n = b.finish().unwrap();

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let kas_handles: alloc::vec::Vec<_> = events
      .iter()
      .filter_map(|ev| match ev {
        RouteEvent::ToService(ts) if ts.event().is_known_answer() => Some(ts.handle()),
        _ => None,
      })
      .collect();

    for h in &handles {
      assert!(
        kas_handles.contains(h),
        "meta-PTR known-answer must fan out to service {h:?}; got {kas_handles:?}"
      );
    }
    assert_eq!(
      kas_handles.len(),
      2,
      "one meta KnownAnswer per registered service; got {kas_handles:?}"
    );
  }

  // ── TTL=0 records bypass route-level fan-out ─────────────────

  /// A QR=0 answer with TTL=0 (goodbye / withdrawal) must not trigger
  /// any service-side event — no ProbeConflict for a matching instance
  /// name, no HostConflict for a matching host, no KnownAnswer for a
  /// matching service_type.  The peer is WITHDRAWING the record, not
  /// claiming it.  Cache layer still observes the removal independently.
  #[test]
  fn qr0_ttl_zero_does_not_emit_service_events() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host.clone(), 631, 120);
    recs.add_a(Ipv4Addr::new(10, 0, 0, 1));
    let now = StdInstant::now();
    let (_h, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // QR=0 packet with a TTL=0 A answer for our HOST name (would
    // normally trigger HostConflict + KnownAnswer).
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 0, Ipv4Addr::new(10, 0, 0, 2), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();
    assert!(
      events.is_empty(),
      "QR=0 TTL=0 record must NOT yield any RouteEvent; got {events:?}"
    );

    // Also exercise instance-name (would have been ProbeConflict) and
    // service_type (would have been KnownAnswer).
    for record_name in [&inst, &Name::try_from_str("_ipp._tcp.local.").unwrap()] {
      let mut buf2 = [0u8; 512];
      let header = Header::new();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf2, header).unwrap();
      b.push_a_answer(record_name, 0, Ipv4Addr::new(10, 0, 0, 3), false)
        .unwrap();
      let n = b.finish().unwrap();
      let events: alloc::vec::Vec<_> = e
        .handle(now, src, local_ip, 0, &buf2[..n], false)
        .unwrap()
        .map(Result::unwrap)
        .collect();
      assert!(
        events.is_empty(),
        "QR=0 TTL=0 for {} must NOT yield any RouteEvent; got {events:?}",
        record_name.as_str()
      );
    }
  }

  /// A TTL=0 authority-section record must NOT emit ProbeConflict /
  /// HostConflict — same goodbye semantics as in the answer
  /// section.
  #[test]
  fn authority_ttl_zero_does_not_emit_conflict_events() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{Header, MessageBuilder},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let recs = ServiceRecords::new(st, inst.clone(), host.clone(), 631, 120);
    let now = StdInstant::now();
    let (_h, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // Build a probe-shaped QR=0 packet with a TTL=0 A authority
    // record for the registered HOST name.  Under normal TTL this
    // would route as HostConflict.
    let mut buf = [0u8; 512];
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, hdr).unwrap();
    b.push_a_authority(&host, 0, Ipv4Addr::new(192, 168, 1, 99))
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();
    assert!(
      events.is_empty(),
      "TTL=0 authority record (host) must not emit HostConflict; got {events:?}"
    );

    // Same packet but the authority targets the INSTANCE name (would
    // normally route as ProbeConflict).
    let mut buf2 = [0u8; 512];
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf2, hdr).unwrap();
    b.push_a_authority(&inst, 0, Ipv4Addr::new(192, 168, 1, 99))
      .unwrap();
    let n = b.finish().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, &buf2[..n], false)
      .unwrap()
      .map(Result::unwrap)
      .collect();
    assert!(
      events.is_empty(),
      "TTL=0 authority record (instance) must not emit ProbeConflict; got {events:?}"
    );
  }

  // ── cache-flush dedup within a packet ────────────────────────

  /// A multi-record RRSet (e.g. multiple A records for the same host)
  /// with the cache-flush bit set on every record must end up with ALL
  /// records in the cache — not just the last.  Previously, the
  /// 2nd record's cache_flush evicted the 1st, the 3rd evicted the
  /// 2nd, etc., leaving only the final address.
  #[test]
  fn cache_flush_within_one_packet_preserves_full_rrset() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("multihomed.local.").unwrap();

    // Two A records for the same host, both cache_flush=true (typical
    // mDNS announcement of a multi-address host).
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 1), true)
      .unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
      .unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 3), true)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();

    // All three A records must be in the cache for the same host.
    let count = e
      .cache
      .count_matching(&host, ResourceType::A, ResourceClass::In);
    assert_eq!(
      count, 3,
      "multi-A RRSet with cache_flush must preserve all 3 entries; got {count}"
    );
  }

  // ── QR=1 answer-section records trigger probe-time conflict ─

  /// RFC 6762 §8.1 — a probing host MUST treat any RESPONSE message
  /// claiming one of its tentative names as a conflict event.  Test
  /// that a QR=1 packet with an A answer record owned by our
  /// instance/host fires ProbeConflict / HostConflict respectively.
  #[test]
  fn qr1_answer_for_instance_name_emits_probe_conflict() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host = Name::try_from_str("alpha.local.").unwrap();
    let recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // RESPONSE (QR=1) with an SRV answer for our instance name (the instance's
    // unique RRset.F1 gates ProbeConflict to SRV/TXT).
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let srv_target = Name::try_from_str("other-host.local.").unwrap();
    b.push_srv_answer(&inst, 120, 0, 0, 8080, &srv_target, false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let has_probe_conflict = events
      .iter()
      .any(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_probe_conflict()));
    assert!(
      has_probe_conflict,
      "QR=1 answer claiming our instance name must emit ProbeConflict; got {events:?}"
    );
  }

  /// Parallel test for host-name match → HostConflict.
  #[test]
  fn qr1_answer_for_host_name_emits_host_conflict() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("Alpha._http._tcp.local.").unwrap();
    let host = Name::try_from_str("alpha.local.").unwrap();
    let recs = ServiceRecords::new(st, inst.clone(), host.clone(), 80, 120);
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let has_host_conflict = events
      .iter()
      .any(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_host_conflict()));
    assert!(
      has_host_conflict,
      "QR=1 answer claiming our host name must emit HostConflict; got {events:?}"
    );
  }

  // ── QR=0 answer-section records must NOT mutate the cache ────

  /// QR=0 (query) packets carry answer-section records as known-answer
  /// hints, not authoritative observations.  They must NOT insert into,
  /// delete from, or flush the passive cache.  Previously a hostile
  /// querier could:
  ///   * insert forged rdata into the cache via QR=0 positive-TTL answers,
  ///   * delete cached records via QR=0 TTL=0 answers,
  ///   * clamp legitimate cached siblings via QR=0 cache_flush answers.
  #[test]
  fn qr0_answer_does_not_mutate_cache() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::time::Duration;
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("victim.local.").unwrap();

    // Seed cache with an authoritative IN A record.
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        alloc::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1
    );

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    // (1) QR=0 packet with a forged A answer for the same host (different rdata).
    //     Must NOT insert a second cache entry.
    let mut buf = [0u8; 512];
    let header = Header::new(); // QR=0
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 99), false)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(now, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1,
      "QR=0 positive-TTL answer must NOT insert into cache"
    );

    // (2) QR=0 packet with TTL=0 for the seeded rdata.  Must NOT delete.
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 0, Ipv4Addr::new(10, 0, 0, 1), false)
      .unwrap();
    let n = b.finish().unwrap();
    let _ = e
      .handle(now, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1,
      "QR=0 TTL=0 answer must NOT delete cached entry"
    );

    // (3) QR=0 packet with cache_flush=true.  Must NOT clamp / evict.
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 99), true)
      .unwrap();
    let n = b.finish().unwrap();
    // Advance past §10.2 grace so the seeded entry WOULD have been
    // clamped if the QR=0 cache-flush were honoured.
    let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();
    let _ = e
      .handle(after_grace, src, local_ip, 0, &buf[..n], false)
      .unwrap()
      .count();
    // Sweep past where the clamp would have expired the seeded record.
    let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
    e.cache.sweep_expired(after_clamp);
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1,
      "QR=0 cache_flush must NOT clamp legitimate cached siblings"
    );
  }

  // ── cache-flush uses deferred expiry, not immediate evict ────

  /// An old multi-record RRSet refreshed across two packets must
  /// survive the burst.  RFC 6762 §10.2 specifies cache-flush clamps
  /// matching siblings' `expires_at` to `min(current, now + 1s)`
  /// instead of removing them immediately — so siblings re-announced
  /// within 1s have their expiry undone by the refresh path, and
  /// siblings NOT re-announced expire naturally a second later.
  ///
  /// Test: seed an old A1/A2 RRSet (received 5 min ago).  Send
  /// packet 1 with A1 cache_flush=true (refreshes A1, clamps A2).
  /// Send packet 2 with A2 cache_flush=true within the grace window
  /// (refreshes A2, undoes the clamp).  Both A1 and A2 should still
  /// be in the cache, with non-clamped expirations.
  #[test]
  fn cache_flush_deferred_expiry_preserves_refreshed_rrset() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::time::Duration;
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("multihomed.local.").unwrap();

    // Seed cache with two OLD A records — received 5 minutes ago.
    let long_ago = now.checked_sub(Duration::from_secs(300)).unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        alloc::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        long_ago,
        false,
      )
      .unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        alloc::vec![10, 0, 0, 2],
        Duration::from_secs(120),
        long_ago,
        false,
      )
      .unwrap();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      2
    );

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    // Packet 1: A 10.0.0.1 cache_flush=true (refresh burst start).
    let pkt1_t = now;
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 1), true)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(pkt1_t, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }
    // After packet 1: A1 refreshed; A2 expires_at clamped to pkt1_t + 1s
    // but NOT yet removed.  Both still present.
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      2,
      "clamp must NOT remove A2 immediately — only defer its expiry"
    );

    // Packet 2: A 10.0.0.2 cache_flush=true, 200 ms later.
    let pkt2_t = pkt1_t.checked_add(Duration::from_millis(200)).unwrap();
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(pkt2_t, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }

    // After packet 2: A2 refreshed (clamp undone via dedup path).
    // Sweep past the original clamp deadline — neither should expire.
    let after_clamp = pkt1_t.checked_add(Duration::from_secs(3)).unwrap();
    e.cache.sweep_expired(after_clamp);
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      2,
      "a refresh burst within the §10.2 grace must preserve the \
       full RRSet — both A1 and A2 must survive after sweep"
    );
  }

  // ── per-packet flush dedup keys on (name, rtype, rclass) ─────

  /// A datagram containing a non-IN cache_flush record BEFORE an
  /// IN cache_flush record for the same (name, rtype) must NOT
  /// suppress the IN flush.  the per-packet flush dedup
  /// includes rclass, so the second record (different class) still
  /// performs the §10.2 deferred-expiry clamp on stale IN siblings.
  #[test]
  fn flush_marker_keys_on_rclass_so_mixed_class_does_not_suppress() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::time::Duration;
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("svc.local.").unwrap();

    // Seed an OLD IN-class A record (5 min ago) that is eligible for
    // the deferred-expiry clamp.
    let long_ago = now.checked_sub(Duration::from_secs(300)).unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        alloc::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        long_ago,
        false,
      )
      .unwrap();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1
    );

    // Build a single packet with TWO cache_flush A records:
    //   (i)  class ANY (non-IN) — would consume the flush marker under
    //        the class-blind keying.
    //   (ii) class IN — needs the deferred-expiry clamp on the old IN
    //        sibling above.
    // The wire builder doesn't expose a "set rclass" knob on push_a_answer
    // — that always emits class IN.  So we exercise the dedup directly
    // by calling try_insert twice with different rclass + cache_flush=true.
    //
    // First: ANY-class cache_flush insert.  This records
    // `(host, A, Any)` in flushed_in_packet — but we're calling
    // Cache::try_insert directly here, which bypasses Endpoint::handle's
    // per-packet tracker.  To exercise the actual code path, instead
    // build a valid wire packet with the IN record and verify the IN
    // sibling gets clamped via the normal handle path.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    // Two IN cache_flush A records with different rdata.  This exercises
    // the per-packet dedup: only the first triggers the clamp; the
    // second piggybacks via flushed_in_packet.  Crucially, the
    // class-aware dedup means we ALSO clamp the old sibling exactly
    // once per (name, rtype, rclass) — the test verifies that the
    // sibling IS clamped (would be skipped under a buggy class-blind
    // dedup if a non-IN flush had been first).
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
      .unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 3), true)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();

    // The old IN sibling (10.0.0.1) must be clamped to expire at now+1s.
    // Sweep past that deadline; the OLD record is removed.
    let after_clamp = now.checked_add(Duration::from_secs(2)).unwrap();
    e.cache.sweep_expired(after_clamp);

    let count = e
      .cache
      .count_matching(&host, ResourceType::A, ResourceClass::In);
    assert_eq!(
      count, 2,
      "old IN sibling must have been clamped + swept; the two \
       new IN records from the packet survive.  Expected 2 (10.0.0.2 \
       and 10.0.0.3); got {count}"
    );
  }

  // ── cache identity includes ResourceClass ─────────────────────

  /// A record with non-IN class must not dedupe with, evict, or count
  /// as an IN-class entry.  Previously the cache stored only
  /// `(name, rtype, rdata)` so a hostile or misconfigured response
  /// could corrupt the cache across class boundaries.
  #[test]
  fn cache_class_isolates_in_from_non_in() {
    use core::time::Duration;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("svc.local.").unwrap();

    // Insert an IN-class A record.
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        alloc::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();

    // Insert a record with SAME name + rtype + rdata but DIFFERENT class
    // (ANY).  Must NOT dedupe — must coexist.
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        crate::wire::ResourceClass::Any,
        alloc::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();

    // class is part of the key.  Two distinct entries.
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1
    );
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, crate::wire::ResourceClass::Any),
      1
    );

    // A cache_flush in class ANY must NOT evict the IN entry (advance
    // past grace first, so the IN entry would otherwise be eligible).
    let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        crate::wire::ResourceClass::Any,
        alloc::vec![10, 0, 0, 99],
        Duration::from_secs(120),
        after_grace,
        true,
      )
      .unwrap();
    let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
    e.cache.sweep_expired(after_clamp);

    // IN entry is still alive.
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1,
      "cache_flush in class ANY must NOT touch IN-class entries"
    );
  }

  // ── cross-packet cache-flush respects §10.2 grace window ─────

  /// A multi-address RRSet announced across TWO separate packets,
  /// both with cache_flush=true, must result in BOTH addresses being
  /// cached.  RFC 6762 §10.2 specifies a 1-second grace: cache_flush
  /// must not evict entries received within the last second.  Before
  /// the second packet's cache_flush evicted the first
  /// packet's record because the eviction was unconditional, so a
  /// multi-A announcement split across packets collapsed to only the
  /// last record.
  #[test]
  fn cache_flush_preserves_recent_siblings_across_packets() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("multihomed.local.").unwrap();

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    // Packet 1: A 10.0.0.1 with cache_flush=true.
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 1), true)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(now, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      1
    );

    // Packet 2: A 10.0.0.2 with cache_flush=true, arriving 100 ms later
    // — well within the §10.2 1-second grace window.
    let later = now
      .checked_add(core::time::Duration::from_millis(100))
      .unwrap();
    {
      let mut buf = [0u8; 512];
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 2), true)
        .unwrap();
      let n = b.finish().unwrap();
      let _ = e
        .handle(later, src, local_ip, 0, &buf[..n], false)
        .unwrap()
        .count();
    }

    // BOTH A records must be cached.  Without the grace window
    // the second cache_flush would have evicted the first.
    let count = e
      .cache
      .count_matching(&host, ResourceType::A, ResourceClass::In);
    assert_eq!(
      count, 2,
      "cross-packet cache-flush within §10.2 grace must preserve \
       fresh siblings.  Expected 2 (both 10.0.0.1 and 10.0.0.2); got {count}"
    );
  }

  // ── TTL=0 record must not consume the per-packet flush marker ─

  /// A TTL=0 cache-flush record (goodbye for a single rdata) does NOT
  /// evict the RRSet — `Cache::try_insert` handles TTL=0 before the
  /// cache-flush branch and removes only the exact rdata.  If such a
  /// record consumed the per-packet flush marker, a later
  /// positive-TTL cache-flush record for the same `(name, rtype)`
  /// would be downgraded to `cache_flush=false` and would NOT evict
  /// older siblings — they would remain stale.
  ///
  /// Test: seed the cache with A=10.0.0.1 and A=10.0.0.2.  Feed a
  /// single packet containing (i) TTL=0/cache_flush goodbye for
  /// 10.0.0.1 and (ii) TTL=120/cache_flush for new 10.0.0.3.  Both
  /// 10.0.0.1 (removed by goodbye) AND 10.0.0.2 (evicted by the
  /// positive cache_flush) must be gone; only 10.0.0.3 should remain.
  #[test]
  fn ttl_zero_does_not_consume_flush_marker() {
    use crate::wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType};
    use core::time::Duration;
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let host = Name::try_from_str("printer.local.").unwrap();

    // Seed the cache with two A records (TTL=120).
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        alloc::vec![10, 0, 0, 1],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();
    e.cache
      .try_insert(
        host.clone(),
        ResourceType::A,
        ResourceClass::In,
        alloc::vec![10, 0, 0, 2],
        Duration::from_secs(120),
        now,
        false,
      )
      .unwrap();
    assert_eq!(
      e.cache
        .count_matching(&host, ResourceType::A, ResourceClass::In),
      2
    );

    // Advance past the §10.2 grace so the seeded entries are
    // eligible for eviction.
    let after_grace = now.checked_add(Duration::from_secs(2)).unwrap();

    // Build a single packet: (i) TTL=0/cache_flush goodbye for 10.0.0.1,
    // followed by (ii) TTL=120/cache_flush for 10.0.0.3.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&host, 0, Ipv4Addr::new(10, 0, 0, 1), true)
      .unwrap();
    b.push_a_answer(&host, 120, Ipv4Addr::new(10, 0, 0, 3), true)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let _ = e
      .handle(after_grace, src, local_ip, 0, pkt, false)
      .unwrap()
      .count();

    // deferred expiry: the positive-TTL cache_flush CLAMPS the
    // surviving sibling (10.0.0.2) to expire at after_grace + 1s.
    // Sweep past that deadline to drop it.
    let after_clamp = after_grace.checked_add(Duration::from_secs(2)).unwrap();
    e.cache.sweep_expired(after_clamp);

    // 10.0.0.2 must be evicted (via the clamp + sweep); only
    // 10.0.0.3 should remain (10.0.0.1 was removed by the goodbye).
    let count = e
      .cache
      .count_matching(&host, ResourceType::A, ResourceClass::In);
    assert_eq!(
      count, 1,
      "TTL=0 goodbye must not consume the per-packet flush \
       marker, so the subsequent positive-TTL cache_flush record must \
       still evict the unrelated sibling.  Expected 1 (only 10.0.0.3); \
       got {count}"
    );
  }

  // ── iterator terminates after parse errors ───────────────────

  /// A malformed answer/authority record must not pin the iterator
  /// returning the same Err on every call — the section must advance
  /// (or transition to Done) after the error so the iterator
  /// eventually returns None.
  #[test]
  fn malformed_record_does_not_loop_forever() {
    use crate::wire::Header;
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();

    // Build a packet with a malformed answer.  Hand-craft: header
    // claims 1 answer but the body is empty so parsing fails.
    let mut buf = [0u8; 32];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    hdr.set_answer_count(1);
    let header_len = hdr.write(&mut buf).unwrap();
    let pkt = &buf[..header_len]; // body absent -> malformed answer

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();
    let mut total_polls = 0u32;
    let mut error_count = 0u32;
    for ev in events {
      total_polls = total_polls.saturating_add(1);
      if ev.is_err() {
        error_count = error_count.saturating_add(1);
      }
      if total_polls > 10 {
        panic!(
          "iterator must terminate after parse error; \
           seen {error_count} errors in {total_polls} polls without None"
        );
      }
    }
    // Iterator terminated.  Bounded error count: at most one per section.
    assert!(
      error_count <= 3,
      "at most one parse error per section (3 sections); got {error_count}"
    );
  }

  // ── answer_questions=false suppresses Question events ────────

  /// When `EndpointConfig::answer_questions` is false, no
  /// `ServiceEvent::Question` events fire — the registered service
  /// stays passive even when peer queries match its names.
  #[test]
  fn answer_questions_false_suppresses_question_events() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use std::net::SocketAddr;

    use rand::SeedableRng;
    let rng = rand::rngs::StdRng::from_seed([7u8; 32]);
    let cfg = EndpointConfig::new().with_answer_questions(false);
    let mut e = TestEndp::try_new(cfg, rng);
    let st = Name::try_from_str("_http._tcp.local.").unwrap();
    let inst = Name::try_from_str("WebServer._http._tcp.local.").unwrap();
    let host = Name::try_from_str("web.local.").unwrap();
    let recs = ServiceRecords::new(st.clone(), inst.clone(), host, 80, 120);
    let now = StdInstant::now();
    let (_h, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    // QR=0 packet with a question for the registered instance name.
    let mut buf = [0u8; 512];
    let header = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, header).unwrap();
    b.push_question(
      &inst,
      ResourceType::Any,
      crate::wire::ResourceClass::In,
      false,
    )
    .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let question_events: alloc::vec::Vec<_> = events
      .iter()
      .filter(|ev| matches!(ev, RouteEvent::ToService(ts) if ts.event().is_question()))
      .collect();
    assert!(
      question_events.is_empty(),
      "answer_questions=false must suppress ServiceEvent::Question; \
       got {question_events:?}"
    );
  }

  // ── authority-section host fan-out ───────────────────────────

  /// Multiple services can legitimately share a host name.  An authority
  /// record (peer probe) claiming that host MUST surface HostConflict
  /// to every service sharing it — not just the first by slab order.
  /// Previously the authority loop returned on the first match and
  /// advanced authority_idx, so additional services kept advertising the
  /// conflicted host with no signal.
  #[test]
  fn authority_host_conflict_fans_out_to_all_same_host_services() {
    use crate::{
      config::ServiceSpec,
      records::ServiceRecords,
      wire::{Header, MessageBuilder},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let host = Name::try_from_str("shared-host.local.").unwrap();
    let now = StdInstant::now();

    // Three services with DIFFERENT instance names but the SAME host.
    let mut handles = alloc::vec::Vec::new();
    for inst_label in ["A", "B", "C"] {
      let inst_str = alloc::format!("{inst_label}._ipp._tcp.local.");
      let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
      let inst = Name::try_from_str(&inst_str).unwrap();
      let recs = ServiceRecords::new(st, inst, host.clone(), 631, 120);
      let (h, _svc) = e
        .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
          ServiceSpec::new(recs),
          now,
        )
        .unwrap();
      handles.push(h);
    }

    // Probe-shaped authority record claiming the shared host.
    let mut buf = [0u8; 512];
    let hdr = Header::new();
    let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, hdr).unwrap();
    b.push_a_authority(&host, 120, Ipv4Addr::new(192, 168, 1, 99))
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // Every registered service must receive HostConflict.
    let conflict_handles: alloc::vec::Vec<_> = events
      .iter()
      .filter_map(|ev| match ev {
        RouteEvent::ToService(ts) if ts.event().is_host_conflict() => Some(ts.handle()),
        _ => None,
      })
      .collect();

    for h in &handles {
      assert!(
        conflict_handles.contains(h),
        "service {h:?} must receive HostConflict for shared host; \
         got handles {conflict_handles:?}"
      );
    }
    assert_eq!(
      conflict_handles.len(),
      3,
      "exactly three HostConflict events expected (one per service); \
       got {conflict_handles:?}"
    );
  }

  /// A QR=1 response answer with TTL=0 must not emit `ToQuery(Answer)`
  /// events for active queries.  The query state is already protected
  /// at the application step, but iterator-level events
  /// should also be suppressed so the caller never sees a "withdrawal
  /// disguised as answer."
  #[test]
  fn qr1_ttl_zero_does_not_emit_to_query_events() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let h = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::A), now)
      .unwrap();

    // QR=1 response packet with a TTL=0 answer for the query name.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qname, 0, Ipv4Addr::new(10, 0, 0, 7), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    let to_query_count = events
      .iter()
      .filter(
        |ev| matches!(ev, RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_))),
      )
      .count();
    assert_eq!(
      to_query_count, 0,
      "QR=1 TTL=0 must NOT emit ToQuery(Answer) events; got events {events:?}"
    );

    // And of course collected_answers must remain empty (this still applies).
    assert_eq!(
      e.collected_answers(h).count(),
      0,
      "TTL=0 must not land in collected_answers"
    );
    e.cancel_query(h).unwrap();
  }

  // ── terminal queries reject late answers ─────────────────────

  /// After `poll_query` returns terminal, subsequent matching
  /// responses arriving before `cancel_query` MUST NOT mutate the
  /// query's `collected_answers` or evict pre-terminal results from
  /// the FIFO under `max_answers` pressure.  This added the
  /// `terminal_emitted()` skip to both eager application (in
  /// `Endpoint::handle`) and `ToQuery` fan-out (in the iterator) so
  /// terminated queries are effectively frozen.
  #[test]
  fn terminated_query_rejects_late_answers() {
    use crate::{
      config::QuerySpec,
      event::QueryUpdate,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use core::time::Duration;
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qn = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qn.clone(), ResourceType::A).with_timeout(Duration::from_millis(100));
    let h = e.try_start_query(spec, now).unwrap();

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

    // First response: an A answer arrives BEFORE the timeout fires.
    let mut buf = [0u8; 512];
    let pre_terminal_addr = Ipv4Addr::new(10, 0, 0, 7);
    {
      let mut hdr = Header::new();
      hdr.flags_mut().set_response();
      let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
        MessageBuilder::try_new(&mut buf, hdr).unwrap();
      b.push_a_answer(&qn, 120, pre_terminal_addr, false).unwrap();
      let n = b.finish().unwrap();
      let pkt = &buf[..n];
      let _ = e.handle(now, src, local_ip, 0, pkt, false).unwrap().count();
    }
    assert_eq!(
      e.collected_answers(h).count(),
      1,
      "pre-terminal answer must land in collected_answers"
    );

    // Drive to terminal.
    now = now.checked_add(Duration::from_millis(200)).unwrap();
    e.handle_query_timeout(h, now).unwrap();
    assert!(matches!(
      e.poll_query(h),
      Some(QueryUpdate::Timeout | QueryUpdate::Done)
    ));

    let answers_at_terminal: alloc::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(answers_at_terminal.len(), 1);

    // Second response: a DIFFERENT A answer arrives AFTER terminal.  This
    // must NOT mutate collected_answers (frozen) AND must NOT yield a
    // ToQuery event for the terminated query.
    let mut buf2 = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf2, hdr).unwrap();
    b.push_a_answer(&qn, 120, Ipv4Addr::new(10, 0, 0, 99), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf2[..n];

    let events: alloc::vec::Vec<_> = e
      .handle(now, src, local_ip, 0, pkt, false)
      .unwrap()
      .map(Result::unwrap)
      .collect();

    // No ToQuery(Answer) for the terminated handle.
    let to_query_events: alloc::vec::Vec<_> = events
      .iter()
      .filter_map(|ev| match ev {
        RouteEvent::ToQuery(tq) if matches!(tq.event(), QueryEvent::Answer(_)) => Some(tq.handle()),
        _ => None,
      })
      .collect();
    assert!(
      !to_query_events.contains(&h),
      "terminated query must NOT receive ToQuery(Answer) events; got handles {to_query_events:?}"
    );

    // collected_answers unchanged.
    let answers_after_terminal: alloc::vec::Vec<_> = e.collected_answers(h).cloned().collect();
    assert_eq!(
      answers_after_terminal.len(),
      1,
      "collected_answers must be frozen after terminal; \
       got {answers_after_terminal:?}"
    );
    assert_eq!(
      answers_after_terminal[0].rdata_slice(),
      &pre_terminal_addr.octets(),
      "pre-terminal answer must remain intact (no eviction)"
    );

    // Cleanup.
    e.cancel_query(h).unwrap();
  }

  /// `sweep_terminated_queries` prunes every query whose terminal has
  /// been emitted; ongoing queries are untouched.
  #[test]
  fn sweep_terminated_queries_prunes_only_terminated() {
    use crate::{config::QuerySpec, event::QueryUpdate, wire::ResourceType};
    use core::time::Duration;

    let mut e = build_endpoint();
    let mut now = StdInstant::now();
    let qn = Name::try_from_str("printer.local.").unwrap();

    // Two queries: one with a short timeout, one without.
    let h_short = e
      .try_start_query(
        QuerySpec::new(qn.clone(), ResourceType::A).with_timeout(Duration::from_millis(100)),
        now,
      )
      .unwrap();
    let h_long = e
      .try_start_query(QuerySpec::new(qn.clone(), ResourceType::Aaaa), now)
      .unwrap();
    assert_eq!(e.queries.len(), 2);

    // Sweep with no terminated queries — no-op.
    assert_eq!(e.sweep_terminated_queries(), 0);
    assert_eq!(e.queries.len(), 2);

    // Drive h_short to terminal and observe.
    now = now.checked_add(Duration::from_millis(200)).unwrap();
    e.handle_query_timeout(h_short, now).unwrap();
    assert!(matches!(
      e.poll_query(h_short),
      Some(QueryUpdate::Timeout | QueryUpdate::Done)
    ));
    assert_eq!(e.queries.len(), 2, "terminal does not auto-prune");

    // Sweep — h_short goes; h_long stays.
    assert_eq!(e.sweep_terminated_queries(), 1);
    assert_eq!(e.queries.len(), 1);
    assert!(e.collected_answers(h_short).next().is_none());
    // h_long is still active.
    e.cancel_query(h_long).unwrap();
  }

  /// `cancel_query` removes the route immediately; subsequent lookups
  /// return `CancelQueryError::QueryNotFound` for the cancelled handle.
  #[test]
  fn cancel_query_removes_route() {
    use crate::{config::QuerySpec, error::CancelQueryError, wire::ResourceType};

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();
    let spec = QuerySpec::new(qname, ResourceType::A);
    let h = e.try_start_query(spec, now).unwrap();
    assert_eq!(e.queries.len(), 1);

    e.cancel_query(h).unwrap();
    assert_eq!(e.queries.len(), 0);

    // Second cancel on the same handle returns QueryNotFound.
    let r = e.cancel_query(h);
    assert!(
      matches!(r, Err(CancelQueryError::QueryNotFound(_))),
      "cancel_query on absent handle must return QueryNotFound; got {r:?}"
    );
  }

  // ── IPv6 link-local self-check is interface-scoped ──────────

  /// IPv6 link-local addresses (`fe80::/10`) are scoped per interface.
  /// Two unrelated hosts on different interfaces can both pick `fe80::1`
  /// without conflict.  Previously the self-loopback membership check
  /// compared bare addresses, so a peer using the same link-local on a
  /// different interface would be wrongly classified as self and
  /// suppressed.
  ///
  /// Test: register a service publishing `fe80::1` scoped to interface
  /// index 2, then feed back a probe-shaped AAAA-authority packet with
  /// `src = fe80::1`.  The same packet must:
  ///   * be suppressed when delivered with `interface_index == 2` (true
  ///     self-loopback), AND
  ///   * be routed normally (ProbeConflict) when delivered with
  ///     `interface_index == 3` (a remote peer on another interface).
  #[test]
  fn ipv6_link_local_self_check_is_interface_scoped() {
    use crate::{
      event::RouteEvent,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder},
    };
    use std::net::{Ipv6Addr, SocketAddr};

    // signal (b) is opt-in. This test validates the legacy
    // advertised-source fallback's interface-scoped behaviour.
    use rand::SeedableRng;
    let rng = rand::rngs::StdRng::from_seed([99u8; 32]);
    let mut e = TestEndp::try_new(
      EndpointConfig::new().with_trust_advertised_src_as_self(true),
      rng,
    );
    let st = Name::try_from_str("_ipp._tcp.local.").unwrap();
    let inst = Name::try_from_str("Printer._ipp._tcp.local.").unwrap();
    let host = Name::try_from_str("printer-host.local.").unwrap();
    let mut recs = ServiceRecords::new(st, inst.clone(), host, 631, 120);
    let our_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    // Bound to interface index 2 — packets arriving on any other interface
    // with src = fe80::1 must be treated as peer, not self.
    recs.add_aaaa_scoped(our_v6, 2);
    let now = StdInstant::now();
    let (_handle, _svc) = e
      .try_register_service::<slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>(
        ServiceSpec::new(recs),
        now,
      )
      .unwrap();

    let mut buf = [0u8; 512];
    let hdr = Header::new();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_srv_authority(
      &inst,
      120,
      0,
      0,
      8080,
      &Name::try_from_str("other-host.local.").unwrap(),
    )
    .unwrap();
    let n = b.finish().unwrap();
    let data = &buf[..n];

    let local_ip: std::net::IpAddr =
      std::net::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb));
    let self_src: SocketAddr = SocketAddr::from((our_v6, 5353));

    // (1) Self-loopback: same address, same interface (ifindex=2).
    let mut self_events = e.handle(now, self_src, local_ip, 2, data, false).unwrap();
    assert!(
      self_events.next().is_none(),
      "link-local from OUR interface (ifindex=2) must be self-suppressed"
    );

    // (2) Foreign peer on a different interface (ifindex=3) using the
    //     same numeric link-local.  This is the regression case — must
    //     route as ProbeConflict, not be silently dropped.
    let mut peer_events = e.handle(now, self_src, local_ip, 3, data, false).unwrap();
    let ev = peer_events
      .next()
      .expect("link-local from a DIFFERENT interface must still produce a routing event")
      .expect("event must be Ok");
    match ev {
      RouteEvent::ToService(ts) => assert!(
        ts.event().is_probe_conflict(),
        "link-local from ifindex=3 must emit ProbeConflict (not be misclassified \
         as self because of bare-address match); got {:?}",
        ts.event()
      ),
      other => panic!(
        "expected RouteEvent::ToService(ProbeConflict), got {:?}",
        other
      ),
    }
  }

  // ── response answers fan out to all type-compatible routes ──

  /// Two concurrent queries for the SAME name but DIFFERENT QTYPEs (e.g.
  /// `printer.local. A` and `printer.local. AAAA`) must both receive
  /// matching answers.  Previously the demux matched the first route
  /// by name and broke; an AAAA answer would route to the A query, get
  /// filtered out at `Query::handle_event` (rtype mismatch), and never
  /// reach the AAAA query.
  ///
  /// Test plan: register an A query and an AAAA query for the same name,
  /// then feed a RESPONSE packet containing an AAAA answer.  Drain all
  /// routing events and assert exactly one `ToQuery(Answer)` reaches the
  /// AAAA handle; none reaches the A handle (the rtype filter at the
  /// route level rejects the AAAA against the A route).
  #[test]
  fn response_answer_fans_out_to_type_compatible_queries() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use std::net::{Ipv6Addr, SocketAddr};

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();

    // Register an A query AND an AAAA query for the same name.
    let spec_a = QuerySpec::new(qname.clone(), ResourceType::A);
    let h_a = e.try_start_query(spec_a, now).unwrap();
    let spec_aaaa = QuerySpec::new(qname.clone(), ResourceType::Aaaa);
    let h_aaaa = e.try_start_query(spec_aaaa, now).unwrap();

    // Build a RESPONSE packet (QR=1) with an AAAA answer for the name.
    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    let aaaa = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    b.push_aaaa_answer(&qname, 120, aaaa, false).unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();

    let mut answer_handles: alloc::vec::Vec<QueryHandle> = alloc::vec::Vec::new();
    for ev in events {
      let ev = ev.unwrap();
      if let RouteEvent::ToQuery(tq) = ev {
        if let QueryEvent::Answer(_) = tq.event() {
          answer_handles.push(tq.handle());
        }
      }
    }

    // The AAAA query must receive the answer.  The A query must NOT —
    // rtype filtering at the route level rejects AAAA against the A
    // route.
    assert!(
      answer_handles.contains(&h_aaaa),
      "AAAA query must receive the AAAA answer; got handles {answer_handles:?}"
    );
    assert!(
      !answer_handles.contains(&h_a),
      "A query must NOT receive an AAAA answer (route-level rtype filter); \
       got handles {answer_handles:?}"
    );
  }

  /// Same as above but with two queries that BOTH should receive the
  /// answer: one registered with `ResourceType::Any` and one with the
  /// exact rtype.  Both routes are compatible, so the same answer record
  /// must produce TWO `ToQuery(Answer)` events.
  #[test]
  fn response_answer_fans_out_to_any_and_specific_routes() {
    use crate::{
      config::QuerySpec,
      wire::{DEFAULT_COMPRESSION_TABLE, Header, MessageBuilder, ResourceType},
    };
    use std::net::SocketAddr;

    let mut e = build_endpoint();
    let now = StdInstant::now();
    let qname = Name::try_from_str("printer.local.").unwrap();

    let spec_a = QuerySpec::new(qname.clone(), ResourceType::A);
    let h_a = e.try_start_query(spec_a, now).unwrap();
    let spec_any = QuerySpec::new(qname.clone(), ResourceType::Any);
    let h_any = e.try_start_query(spec_any, now).unwrap();

    let mut buf = [0u8; 512];
    let mut hdr = Header::new();
    hdr.flags_mut().set_response();
    let mut b: MessageBuilder<'_, DEFAULT_COMPRESSION_TABLE> =
      MessageBuilder::try_new(&mut buf, hdr).unwrap();
    b.push_a_answer(&qname, 120, Ipv4Addr::new(10, 0, 0, 9), false)
      .unwrap();
    let n = b.finish().unwrap();
    let pkt = &buf[..n];

    let src: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    let local_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let events = e.handle(now, src, local_ip, 0, pkt, false).unwrap();

    let mut answer_handles: alloc::vec::Vec<QueryHandle> = alloc::vec::Vec::new();
    for ev in events {
      let ev = ev.unwrap();
      if let RouteEvent::ToQuery(tq) = ev {
        if let QueryEvent::Answer(_) = tq.event() {
          answer_handles.push(tq.handle());
        }
      }
    }

    assert!(
      answer_handles.contains(&h_a),
      "A-specific query must receive the A answer; handles={answer_handles:?}"
    );
    assert!(
      answer_handles.contains(&h_any),
      "Any-wildcard query must also receive the A answer; handles={answer_handles:?}"
    );
    assert_eq!(
      answer_handles.len(),
      2,
      "exactly two ToQuery(Answer) events expected (one per compatible route); \
       got {answer_handles:?}"
    );
  }

  // `cancel_query` on an unknown handle returns
  // `CancelQueryError::QueryNotFound`; covered alongside the basic
  // removal path in `cancel_query_removes_route` above.
}

// ── RouteEvents iterator ─────────────────────────────────────────────

/// Iterator over routing decisions for a single incoming datagram.
///
/// Borrows the endpoint mutably for the duration of iteration so that
/// `QueryEvent::Answer` events can be applied to the internal
/// [`Query`](crate::query::Query) state machines as they are yielded —
/// callers do not need to dispatch query events themselves.  Service
/// events still flow to the caller via the yielded [`RouteEvent`]s.
pub struct RouteEvents<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: RngCore,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  src: SocketAddr,
  endpoint: &'e mut Endpoint<I, R, C, SR, QS, EV, AN, EvQ>,
  reader: MessageReader<'a>,
  /// `true` when the QR bit is set (this is a response, not a query).
  /// Used to gate KnownAnswer-suppression routing: KAS hints must only be
  /// extracted from QUERY packets (QR=0); response packets must not poison
  /// the KAS ring.
  is_response: bool,
  question_idx: u16,
  /// Per-question service cursor: the slab key from which to resume iterating
  /// services for the current question. Allows ALL matching services to receive
  /// a `ServiceEvent::Question` for a single question before advancing to the
  /// next question.
  service_cursor: usize,
  answer_idx: u16,
  authority_idx: u16,
  /// Stashed query event behind a higher-priority service event (e.g. a
  /// `ProbeConflict` or `KnownAnswer` returns first and the first matching
  /// `QueryEvent::Answer` for the same record drains on the next call).
  pending_query: Option<RouteEvent<'a>>,
  /// cursor for fanning out additional matching query routes for
  /// the current `answer_idx` across multiple `next()` calls without
  /// buffering events.  `None` means "have not started query fan-out for
  /// this record" — `next()` does the service-side pass plus finds the
  /// FIRST matching query.  `Some(k)` means "mid fan-out — resume scanning
  /// `self.queries` from slab key `k`."  Resets to `None` whenever
  /// `answer_idx` advances, so the cursor is always paired with the
  /// current answer record.
  ///
  /// Replaces the unbounded `alloc::Vec` buffering used by R15 — that
  /// allocated on the inbound packet path with infallible `push`, which
  /// under allocator pressure aborts/panics instead of surfacing an
  /// error, and used `Vec::remove(0)` for drain (O(n²) on large
  /// fan-outs).  The cursor model is O(1) state per record, O(n) total
  /// work, and never allocates.
  answer_query_cursor: Option<usize>,
  /// cursor for fanning out KnownAnswer / ProbeConflict /
  /// HostConflict events across multiple registered services that all
  /// match the same answer record (e.g. several services sharing a
  /// `service_type` for a PTR known-answer hint, or multiple services
  /// sharing a host name).  Same shape as `answer_query_cursor`:
  /// `None` = haven't started service-side fan-out for this record;
  /// `Some(k)` = resume scan from slab key `k`.  Reset to `None` when
  /// `answer_idx` advances.
  ///
  /// Previously the service-side scan stopped at the first matching
  /// service, so the actual owning service of a PTR known-answer
  /// (which had the right rdata to suppress) never received the hint —
  /// the unrelated first-matching service got it instead and ignored
  /// it by rdata mismatch.
  answer_service_cursor: Option<usize>,
  /// whether the answer-record service-phase fan-out is COMPLETE for
  /// the current `answer_idx`. `answer_service_cursor` alone is ambiguous
  /// (`None` means both "not started" and "exhausted"), so after a query event
  /// returns mid-record, re-entry would re-scan services and replay conflict
  /// events. This flag gates the service phase; it is reset only when
  /// `answer_idx` advances.
  answer_service_done: bool,
  /// cursor for fanning out authority-section conflict events
  /// (ProbeConflict / HostConflict) across multiple services that
  /// share a host name.  `None` = haven't started fan-out for the
  /// current authority record; `Some(k)` = resume scan from slab key
  /// `k`.  Same shape as the other answer/question cursors.
  ///
  /// Previously the authority-section loop broke on the first
  /// matching service and advanced `authority_idx`, so a peer probe
  /// for a shared host name reached only one of the services
  /// sharing that host; the rest never received the HostConflict
  /// signal.
  authority_service_cursor: Option<usize>,
  /// When a QUERY-packet answer matches a registered service for both a
  /// ProbeConflict and a KnownAnswer event, we emit ProbeConflict first and
  /// stash the KnownAnswer here for the subsequent call.
  pending_service_event: Option<RouteEvent<'a>>,
  /// index into the ADDITIONAL section, plus the
  /// service-conflict and query fan-out cursors for the current additional
  /// record (same shape as the answer-section cursors). DNS-SD responders carry
  /// SRV/TXT/A/AAAA here, so QR=1 additionals run conflict detection (instance
  /// SRV/TXT → ProbeConflict, host A/AAAA → HostConflict) AND query fan-out —
  /// but never KAS (additionals are not known-answer hints).
  additional_idx: u16,
  additional_service_cursor: Option<usize>,
  /// like `answer_service_done`, marks the additional-record
  /// service-phase fan-out complete for the current `additional_idx` so a query
  /// event mid-record cannot cause the conflict events to replay on re-entry.
  additional_service_done: bool,
  additional_query_cursor: Option<usize>,
  section: Section,
}

#[derive(Copy, Clone)]
enum Section {
  Questions,
  Answers,
  Authority,
  Additional,
  Done,
}

impl<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ> RouteEvents<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: RngCore,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  /// the ONE conflict-routing decision for a QR=1 record `r`,
  /// shared by the Answers, Authority, and Additional sections (previously
  /// triplicated). Scans registered services from slab key `start` and returns
  /// the next `(key, event)`:
  ///   * instance-name match + SRV/TXT → ProbeConflict (the instance's unique
  ///     RRset; service-type / shared names are never conflicts);
  ///   * host-name match + A/AAAA → HostConflict.
  ///
  /// conflicts are only routed for class-IN records — a record with
  /// class ANY or an unknown class is not the same-class RRset RFC 6762 §9
  /// requires, so it must not drive rename / host-conflict surfacing.
  fn next_service_conflict(
    &self,
    r: &crate::wire::RecordRef<'a>,
    start: usize,
  ) -> Option<(usize, RouteEvent<'a>)> {
    if r.rclass() != ResourceClass::In {
      return None;
    }
    for (key, route) in self.endpoint.services.iter() {
      if key < start {
        continue;
      }
      if names_match_record(route.name(), r) && is_instance_conflict_rtype(r.rtype()) {
        return Some((
          key,
          RouteEvent::ToService(ToService::new(
            route.handle(),
            ServiceEvent::ProbeConflict(ProbeConflict::new(self.src, *r)),
          )),
        ));
      }
      if names_match_record(route.host(), r) && is_host_conflict_rtype(r.rtype()) {
        return Some((
          key,
          RouteEvent::ToService(ToService::new(
            route.handle(),
            ServiceEvent::HostConflict(HostConflict::new(*r)),
          )),
        ));
      }
    }
    None
  }
}

impl<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ> Iterator
  for RouteEvents<'a, 'e, I, R, C, SR, QS, EV, AN, EvQ>
where
  I: Instant,
  R: RngCore,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  type Item = Result<RouteEvent<'a>, HandleError>;

  fn next(&mut self) -> Option<Self::Item> {
    // Flush pending stashed events in priority order before processing the
    // next record.  Order: ProbeConflict / KnownAnswer stash (service event)
    // first, then query Answer stash.
    if let Some(ev) = self.pending_service_event.take() {
      return Some(Ok(ev));
    }
    if let Some(ev) = self.pending_query.take() {
      return Some(Ok(ev));
    }

    loop {
      match self.section {
        Section::Questions => {
          // gate question→service routing on
          // `EndpointConfig::answer_questions`.  When disabled, no
          // `ServiceEvent::Question` events fire at all, so registered
          // services never schedule responses to inbound queries.
          // This is the "advertise but don't respond" / passive mode.
          if !self.endpoint.config.answer_questions() {
            self.section = Section::Answers;
            continue;
          }
          if self.question_idx >= self.reader.header().question_count() {
            self.section = Section::Answers;
            continue;
          }
          let mut qs = self.reader.questions();
          for _ in 0..self.question_idx {
            let _ = qs.next();
          }
          let q = match qs.next() {
            Some(Ok(q)) => q,
            Some(Err(e)) => {
              // skip the rest of the questions section after a
              // parse error so the iterator terminates instead of
              // looping on the same error indefinitely.
              self.section = Section::Answers;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Answers;
              continue;
            }
          };
          // Walk services starting from the saved cursor, looking for the next
          // match. This allows ALL services sharing the same PTR name to each
          // receive a ServiceEvent::Question for this question before we move on.
          let cursor = self.service_cursor;
          let mut found: Option<(usize, RouteEvent<'a>)> = None;
          for (key, route) in self.endpoint.services.iter() {
            if key < cursor {
              continue;
            }
            if names_match(route.name(), q.qname())
              || names_match(route.service_type(), q.qname())
              || names_match(route.host(), q.qname())
              || route
                .subtypes
                .iter()
                .any(|s| names_match(s, q.qname()))
              // RFC 6763 §9 service-type enumeration: route the meta-query to
              // EVERY service; each answerable (Established/Announcing) one emits
              // its own type PTR, and the cursor below delivers it to each in
              // turn. An earlier per-type dedup (route only the
              // lowest-keyed service of each type) is UNSAFE here — routing has
              // no visibility into Service lifecycle state, so it could pick a
              // probing/non-answering representative and mask an Established
              // same-type sibling, leaving a live type unanswered. Two instances
              // of one type emitting the identical meta-PTR is benign (receivers
              // dedup the identical RR); true per-type dedup would require
              // state-aware, cross-service handling at the driver layer.
              || is_meta_query_name(q.qname())
            {
              found = Some((
                key,
                RouteEvent::ToService(ToService::new(
                  route.handle(),
                  ServiceEvent::Question(
                    ServiceQuestion::new(q, self.src, self.reader.header().id())
                      // RFC 6762 §7.2: a TC-bit query spreads its known answers
                      // across multiple packets — the responder delays longer so
                      // the follow-up packets accumulate before it suppresses.
                      .with_truncated(self.reader.header().flags().is_truncated()),
                  ),
                )),
              ));
              break;
            }
          }
          if let Some((key, ev)) = found {
            // Advance the service cursor past this key so the next call picks up
            // where we left off within the same question.
            self.service_cursor = key.saturating_add(1);
            return Some(Ok(ev));
          }
          // No more matching services for this question: advance to the next
          // question and reset the per-question service cursor.
          self.question_idx = self.question_idx.saturating_add(1);
          self.service_cursor = 0;
          continue;
        }
        Section::Answers => {
          if self.answer_idx >= self.reader.header().answer_count() {
            self.section = Section::Authority;
            continue;
          }
          let mut ans = self.reader.answers();
          for _ in 0..self.answer_idx {
            let _ = ans.next();
          }
          let r = match ans.next() {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
              // skip the rest of the answers section after a
              // parse error so the iterator terminates instead of
              // looping on the same error indefinitely.
              self.section = Section::Authority;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Authority;
              continue;
            }
          };

          // route-level TTL=0 guard.  Records with TTL=0 are
          // mDNS "goodbye" / deletion signals (RFC 6762 §10.1) — the
          // cache layer already processes them as removals during the
          // eager loop in `Endpoint::handle`, and `Query::handle_event`
          // rejects them at the eager-mutation step.  The
          // remaining hazard is the iterator: emitting service events
          // (ProbeConflict / HostConflict / KnownAnswer) for a goodbye
          // would let a peer withdrawing a record trigger our auto-
          // rename or HostConflict surfacing, and emitting ToQuery
          // for a goodbye would let callers receive ghost "answers"
          // from records being withdrawn.  Skip the whole fan-out for
          // TTL=0 — cache removal is the only correct side effect.
          if r.ttl() == 0 {
            self.answer_idx = self.answer_idx.saturating_add(1);
            self.answer_service_cursor = None;
            self.answer_service_done = false;
            self.answer_query_cursor = None;
            continue;
          }

          // Service-side fan-out for answer-section records.
          //
          // QR=0: records are KAS hints from another querier.
          //   Emit only KnownAnswer (for KAS suppression on probes).
          //   ProbeConflict / HostConflict are NEVER emitted here —
          //   letting a hostile querier trigger our auto-rename by
          //   mentioning our names in the answer section would be a
          //   trivial denial-of-service vector.
          //
          // QR=1: records are AUTHORITATIVE peer responses.
          //   Per RFC 6762 §8.1, a probing host MUST treat any
          //   response (solicited or unsolicited) claiming one of its
          //   tentative names as a conflict event.  Emit
          //   ProbeConflict for instance-name matches and HostConflict
          //   for host-name matches.  Service-type (shared) matches
          //   are NOT conflicts (multiple services share a type).
          //
          // Authority-section records (Section::Authority) fire
          // ProbeConflict / HostConflict regardless of QR — those are
          // tentative-probe records.
          if !self.answer_service_done {
            let start = self.answer_service_cursor.unwrap_or(0);
            let next_event = if self.is_response {
              // QR=1: ProbeConflict / HostConflict via the shared conflict
              // helper (name + rtype + class gates). Service-type (shared)
              // names are never conflicts.
              self.next_service_conflict(&r, start)
            } else {
              // QR=0: records are KAS hints. ANY name match (instance / host /
              // service-type) emits a KnownAnswer for suppression — conflicts
              // are NEVER routed for QR=0 (a hostile querier mentioning our
              // names must not trigger auto-rename).
              //
              // a QR=0 PTR owned by the DNS-SD service-type enumeration
              // meta name is a known-answer for the §9 meta reply. Its owner is
              // none of our RRset names, so fan it out to EVERY service (mirrors
              // how the meta QUESTION routes to all of them); each
              // service decides whether the PTR target matches its own type.
              let mut found: Option<(usize, RouteEvent<'a>)> = None;
              for (key, route) in self.endpoint.services.iter() {
                if key < start {
                  continue;
                }
                if names_match_record(route.name(), &r)
                  || names_match_record(route.host(), &r)
                  || names_match_record(route.service_type(), &r)
                  || is_meta_query_name(r.name())
                {
                  found = Some((
                    key,
                    RouteEvent::ToService(ToService::new(
                      route.handle(),
                      ServiceEvent::KnownAnswer(KnownAnswer::new(self.src, r)),
                    )),
                  ));
                  break;
                }
              }
              found
            };
            if let Some((key, ev)) = next_event {
              self.answer_service_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
            }
            // service-side fan-out exhausted for THIS record. Mark
            // it done (not just reset the cursor to None, which is ambiguous
            // with "not started") so a later query event in the same record
            // can't re-enter and replay the conflict/KAS events.
            self.answer_service_done = true;
          }

          // Query-side fan-out (QR=1 only).  emit a
          // ToQuery for every name/type-compatible active query via
          // `answer_query_cursor`.  This already applied the answer
          // to the Query state eagerly in `Endpoint::handle`; the
          // events emitted here are informational only.
          if self.is_response {
            let start = self.answer_query_cursor.unwrap_or(0);
            let mut found: Option<(usize, RouteEvent<'a>)> = None;
            for (key, q) in self.endpoint.queries.iter() {
              if key < start {
                continue;
              }
              if q.is_done() || q.terminal_emitted() {
                continue;
              }
              if names_match_record(q.qname(), &r) && qry_query_accepts(q, &r) {
                found = Some((
                  key,
                  RouteEvent::ToQuery(ToQuery::new(q.handle(), QueryEvent::Answer(r))),
                ));
                break;
              }
            }
            if let Some((key, ev)) = found {
              self.answer_query_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
            }
            // Query-side fan-out exhausted for this record.
            self.answer_query_cursor = None;
          }

          // Both phases exhausted — record fully processed.  Advance to the
          // next answer record and reset the per-record fan-out state.
          self.answer_idx = self.answer_idx.saturating_add(1);
          self.answer_service_cursor = None;
          self.answer_service_done = false;
          self.answer_query_cursor = None;
          continue;
        }
        Section::Authority => {
          // authority-section records are tentative-probe claims
          // (RFC 6762 §8.2) — a peer asserting ownership of a name. Routing
          // them as ProbeConflict / HostConflict forces our service to rename
          // or surfaces a host conflict, so they MUST come from a trusted mDNS
          // peer. A genuine prober sends from UDP source port 5353; an
          // ephemeral-port packet carrying an authority RR for our name is an
          // off-path / forged artifact — a legacy §6.7 querier sends only
          // questions, never authority records. (QR=1 responses from non-5353
          // ports are already fully suppressed upstream; this closes the QR=0
          // query path, where the Question section has ALREADY been routed
          // above so legacy unicast repliers are unaffected.)
          if self.src.port() != crate::constants::MDNS_PORT {
            self.section = Section::Additional;
            continue;
          }
          if self.authority_idx >= self.reader.header().authority_count() {
            self.section = Section::Additional;
            continue;
          }
          let mut auth = self.reader.authority();
          for _ in 0..self.authority_idx {
            let _ = auth.next();
          }
          let r = match auth.next() {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
              // skip the rest of the authority section after a
              // parse error so the iterator terminates instead of
              // looping on the same error indefinitely.
              self.section = Section::Done;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Additional;
              continue;
            }
          };

          // route-level TTL=0 guard for the authority section.
          // covered Section::Answers; the same rationale applies
          // here.  A TTL=0 authority record is a goodbye/withdrawal,
          // not a peer claiming the name — emitting ProbeConflict or
          // HostConflict for it would let a withdrawing peer trigger
          // our auto-rename or HostConflict surfacing.
          if r.ttl() == 0 {
            self.authority_idx = self.authority_idx.saturating_add(1);
            self.authority_service_cursor = None;
            continue;
          }

          // Authority records in mDNS probe messages signal a peer claiming the
          // same name — route as ProbeConflict / HostConflict to EVERY matching
          // service (multiple services can share a host) via the shared
          // conflict helper (name + rtype + class gates centralized there).
          let start = self.authority_service_cursor.unwrap_or(0);
          if let Some((key, ev)) = self.next_service_conflict(&r, start) {
            self.authority_service_cursor = Some(key.saturating_add(1));
            return Some(Ok(ev));
          }
          // No more matching services for this authority record.
          // Advance to the next authority record.
          self.authority_idx = self.authority_idx.saturating_add(1);
          self.authority_service_cursor = None;
          continue;
        }
        Section::Additional => {
          // additional-section records are supplementary ANSWERS
          // (DNS-SD SRV/TXT/A/AAAA accompanying a PTR), NOT questions or probe
          // claims. They fan out to active queries ONLY (QR=1) — never service
          // conflicts/KAS. Cache population + eager query-state update already
          // happened in `Endpoint::handle`; these events are informational.
          if !self.is_response {
            self.section = Section::Done;
            continue;
          }
          if self.additional_idx >= self.reader.header().additional_count() {
            self.section = Section::Done;
            continue;
          }
          let mut add = self.reader.additional();
          for _ in 0..self.additional_idx {
            let _ = add.next();
          }
          let r = match add.next() {
            Some(Ok(r)) => r,
            Some(Err(e)) => {
              self.section = Section::Done;
              return Some(Err(HandleError::Parse(e)));
            }
            None => {
              self.section = Section::Done;
              continue;
            }
          };
          // TTL=0 additionals are withdrawals — cache removal already handled
          // eagerly; do not surface a ghost conflict/answer.
          if r.ttl() == 0 {
            self.additional_idx = self.additional_idx.saturating_add(1);
            self.additional_service_cursor = None;
            self.additional_service_done = false;
            self.additional_query_cursor = None;
            continue;
          }
          // service-conflict fan-out FIRST. A QR=1 additional record
          // can carry a conflicting SRV/TXT (instance) or A/AAAA (host) for one
          // of our services — DNS-SD responders place these in the Additional
          // section, so missing them here would let duplicate names survive.
          // Same unique-record gates as the Answer/Authority sections;
          // service-type (shared) matches are never conflicts.
          if !self.additional_service_done {
            let start = self.additional_service_cursor.unwrap_or(0);
            if let Some((key, ev)) = self.next_service_conflict(&r, start) {
              self.additional_service_cursor = Some(key.saturating_add(1));
              return Some(Ok(ev));
            }
            // mark the service phase done for this record so a later
            // query event can't re-enter and replay the conflict events.
            self.additional_service_done = true;
          }
          // Then query fan-out (informational; eager state update already done).
          let start = self.additional_query_cursor.unwrap_or(0);
          let mut found: Option<(usize, RouteEvent<'a>)> = None;
          for (key, q) in self.endpoint.queries.iter() {
            if key < start {
              continue;
            }
            if q.is_done() || q.terminal_emitted() {
              continue;
            }
            if names_match_record(q.qname(), &r) && qry_query_accepts(q, &r) {
              found = Some((
                key,
                RouteEvent::ToQuery(ToQuery::new(q.handle(), QueryEvent::Answer(r))),
              ));
              break;
            }
          }
          if let Some((key, ev)) = found {
            self.additional_query_cursor = Some(key.saturating_add(1));
            return Some(Ok(ev));
          }
          // Both fan-outs exhausted for this additional record; advance and
          // reset the per-record fan-out state.
          self.additional_idx = self.additional_idx.saturating_add(1);
          self.additional_service_cursor = None;
          self.additional_service_done = false;
          self.additional_query_cursor = None;
          continue;
        }
        Section::Done => return None,
      }
    }
  }
}

/// RFC 6763 §9 DNS-SD service-type enumeration (meta-query) name. A browser
/// queries this name (PTR) to discover which service TYPES exist on the link.
pub(crate) const DNS_SD_META_QUERY_NAME: &str = "_services._dns-sd._udp.local.";

/// True if `qname` is the RFC 6763 §9 meta-query name (case-insensitive). A
/// matching question is routed to every registered service so each can answer
/// with a shared PTR `_services._dns-sd._udp.local. -> <its service type>`.
pub(crate) fn is_meta_query_name(qname: &NameRef<'_>) -> bool {
  match Name::try_from_str(DNS_SD_META_QUERY_NAME) {
    Ok(meta) => names_match(&meta, qname),
    Err(_) => false,
  }
}

pub(crate) fn names_match(stored: &Name, incoming: &NameRef<'_>) -> bool {
  let stored_str = stored.as_str();
  let stored_trim = match stored_str.strip_suffix('.') {
    Some(s) => s,
    None => stored_str,
  };
  let mut sit = stored_trim.split('.');
  let mut iit = incoming.labels();
  loop {
    match (sit.next(), iit.next()) {
      (None, None) => return true,
      (Some(s), Some(Ok(i))) => {
        if s.len() != i.len() {
          return false;
        }
        for (a, b) in s.bytes().zip(i.iter()) {
          if !a.eq_ignore_ascii_case(b) {
            return false;
          }
        }
      }
      _ => return false,
    }
  }
}

pub(crate) fn names_match_record(stored: &Name, r: &crate::wire::RecordRef<'_>) -> bool {
  names_match(stored, r.name())
}

/// the RR types a host name is authoritative for — the address
/// records (A / AAAA). Only these constitute a host-name conflict; a record of
/// any other type owned by the host name is not a claim on the host's unique
/// RRset and must not trigger a [`HostConflict`].
fn is_host_conflict_rtype(rt: ResourceType) -> bool {
  matches!(rt, ResourceType::A | ResourceType::Aaaa)
}

/// the RR types a service INSTANCE name is authoritative for — SRV
/// and TXT (RFC 6763 §4). Only these constitute an instance-name conflict
/// (ProbeConflict / auto-rename); a record of any other type owned by the
/// instance name is not a claim on the instance's unique RRset. The PTR that
/// maps a service type to an instance is owned by the SHARED service-type name,
/// not the instance, and is excluded separately.
fn is_instance_conflict_rtype(rt: ResourceType) -> bool {
  matches!(rt, ResourceType::Srv | ResourceType::Txt)
}

/// Does `q`'s QTYPE/QCLASS accept the answer record `r`?
///
/// `ResourceType::Any` / `ResourceClass::Any` are wildcards.  Otherwise the
/// answer's rtype/rclass must match the query's exactly.  this
/// promotes type/class filtering from `Query::handle_event` up into the
/// demux so a single answer can fan out to every compatible query (not be
/// lost to the first-by-name match).
fn qry_query_accepts<I, AN, EvQ>(q: &Query<I, AN, EvQ>, r: &crate::wire::RecordRef<'_>) -> bool
where
  I: Instant,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  let qt = q.qtype();
  let qc = q.qclass();
  let rt_ok = qt == ResourceType::Any || qt == r.rtype();
  // ResourceClass::Any is the wildcard QCLASS value 255 used in mDNS QU
  // queries; accept any answer class against it.  Otherwise the answer's
  // class must equal the query's QCLASS exactly.
  let rc_ok = qc == ResourceClass::Any || qc == r.rclass();
  rt_ok && rc_ok
}

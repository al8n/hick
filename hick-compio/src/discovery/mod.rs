//! DNS-SD service discovery — data types and parsing helpers.
//!
//! This module hosts the public types ([`ServiceEntry`], [`QueryParam`]) and the
//! crate-internal helpers (`push_capped`, `fold`, `parse_name`,
//! `parse_srv`, `parse_txt`, `name_from_ref`) that the resolver state
//! machine and [`Lookup`] handle build on. The
//! [`Endpoint::browse`](crate::Endpoint::browse) /
//! [`lookup`](crate::Endpoint::lookup) /
//! [`resolve_host`](crate::Endpoint::resolve_host) /
//! [`resolve_instance`](crate::Endpoint::resolve_instance) APIs wire these
//! together to drive the RFC 6763 browse → resolve chain.

use std::{
  collections::{HashMap, HashSet, VecDeque},
  sync::Arc,
};

use core::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  time::Duration,
};

use bytes::Bytes;
use futures::future::select_all;
use mdns_proto::{
  Name, QuerySpec,
  wire::{A, AAAA, NameRef, Ptr, ResourceType, Srv, Txt},
};
use smol_str::SmolStr;

use crate::{
  endpoint::Endpoint,
  query::{Query, QueryEvent},
};

#[cfg(test)]
mod tests;

/// Default cap on the number of distinct instances a lookup tracks, so a chatty
/// or hostile responder flooding PTR answers cannot grow the in-progress state
/// without bound. Used by [`QueryParam::new`].
pub const DEFAULT_MAX_ENTRIES: usize = 64;

/// Cap on the addresses kept per host per family (and per instance), so a
/// responder flooding distinct A/AAAA records for one host cannot grow the
/// address vectors without limit.
pub(crate) const MAX_ADDRS_PER_HOST: usize = 16;

/// A resolved DNS-SD service instance.
///
/// Produced by the resolver once the instance has SRV (host + port), TXT, and
/// at least one address.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
  pub(crate) instance: Name,
  pub(crate) host: Name,
  pub(crate) port: u16,
  pub(crate) ipv4: Arc<[Ipv4Addr]>,
  pub(crate) ipv6: Arc<[Ipv6Addr]>,
  pub(crate) txt: Arc<[Bytes]>,
}

impl ServiceEntry {
  /// The fully-qualified service instance name (the PTR target), e.g.
  /// `myprinter._ipp._tcp.local.`.
  #[inline]
  pub const fn instance_name(&self) -> &Name {
    &self.instance
  }

  /// The target host the SRV record points at, e.g. `printer.local.`.
  #[inline]
  pub const fn host(&self) -> &Name {
    &self.host
  }

  /// The service port from the SRV record.
  #[inline]
  pub const fn port(&self) -> u16 {
    self.port
  }

  /// The host's IPv4 addresses (may be empty if only IPv6 resolved).
  #[inline]
  pub fn ipv4_addresses(&self) -> &[Ipv4Addr] {
    &self.ipv4
  }

  /// The host's IPv6 addresses (may be empty if only IPv4 resolved).
  #[inline]
  pub fn ipv6_addresses(&self) -> &[Ipv6Addr] {
    &self.ipv6
  }

  /// All resolved addresses (IPv4 first, then IPv6).
  pub fn addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
    self
      .ipv4
      .iter()
      .copied()
      .map(IpAddr::V4)
      .chain(self.ipv6.iter().copied().map(IpAddr::V6))
  }

  /// The raw TXT record segments (each a length-prefixed `key=value` string in
  /// DNS-SD usage, but treated as opaque bytes since TXT data may be binary). A
  /// service with no metadata has a single empty segment (RFC 6763 §6.1).
  #[inline]
  pub fn txt(&self) -> &[Bytes] {
    &self.txt
  }
}

/// Parameters for a DNS-SD browse / lookup.
#[derive(Debug, Clone)]
pub struct QueryParam {
  pub(crate) service: Name,
  pub(crate) timeout: Duration,
  pub(crate) resolve_timeout: Option<Duration>,
  pub(crate) unicast_response: bool,
  pub(crate) max_entries: usize,
}

impl QueryParam {
  /// Browse the given fully-qualified service type, e.g.
  /// `Name::try_from_str("_ipp._tcp.local.")`.
  #[inline(always)]
  pub const fn new(service: Name) -> Self {
    Self {
      service,
      timeout: Duration::from_secs(1),
      resolve_timeout: None,
      unicast_response: false,
      max_entries: DEFAULT_MAX_ENTRIES,
    }
  }

  /// How long the browse (the PTR query) runs before terminating.
  #[must_use]
  #[inline(always)]
  pub const fn with_timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  /// How long each per-instance resolve query (SRV / TXT / A / AAAA) runs.
  /// Defaults to the browse timeout when unset.
  #[must_use]
  #[inline(always)]
  pub const fn with_resolve_timeout(mut self, timeout: Duration) -> Self {
    self.resolve_timeout = Some(timeout);
    self
  }

  /// Request unicast responses on the issued queries (RFC 6762 §5.4). Defaults
  /// to `false` (standard multicast browse).
  #[must_use]
  #[inline(always)]
  pub const fn with_unicast_response(mut self, unicast: bool) -> Self {
    self.unicast_response = unicast;
    self
  }

  /// Cap on the number of distinct instances tracked; instances discovered
  /// beyond it are dropped. Defaults to [`DEFAULT_MAX_ENTRIES`]. A value of
  /// `0` is treated as `1`.
  #[must_use]
  #[inline(always)]
  pub const fn with_max_entries(mut self, max: usize) -> Self {
    self.max_entries = if max == 0 { 1 } else { max };
    self
  }
}

/// Push `item` into `v` if it is new (by equality) and `v` is still under
/// [`MAX_ADDRS_PER_HOST`]. Returns `true` if it was added (so the caller can
/// decide to (re)emit), `false` if it was a duplicate or the cap was reached.
pub(crate) fn push_capped<T: PartialEq>(v: &mut Vec<T>, item: T) -> bool {
  if v.len() >= MAX_ADDRS_PER_HOST || v.contains(&item) {
    return false;
  }
  v.push(item);
  true
}

/// Case-fold a [`Name`] to its lookup key. DNS names are case-insensitive
/// (RFC 6762 §16), so the lower-cased string form is the canonical key for
/// the resolver's per-instance / per-host maps.
pub(crate) fn fold(name: &Name) -> SmolStr {
  // `Name` is already stored canonical-lowercase (RFC 6762 §16), so a plain
  // `SmolStr::new` suffices — and inlines names ≤23 bytes, whereas collecting
  // from a `char` iterator always takes SmolStr's heap path.
  SmolStr::new(name.as_str())
}

/// Decode an owner-less wire-form domain name (a decompressed PTR/SRV target as
/// stored in a [`mdns_proto::CollectedAnswer`]) into an owned [`Name`].
///
/// Returns `None` for any name the [`Name`] type cannot represent faithfully:
/// a label containing a `.` (which is always treated as a separator by
/// [`Name`]) or a non-ASCII byte. Such inputs are skipped rather than silently
/// corrupted.
fn name_from_ref(nr: &NameRef<'_>) -> Option<Name> {
  let mut buf = String::new();
  for label in nr.labels() {
    let label = label.ok()?;
    if label.is_empty() {
      break; // root terminator
    }
    if label.iter().any(|&b| b >= 0x80 || b == b'.') {
      return None; // not representable by `Name` without corruption
    }
    // Verified ASCII above, so this slice is always valid UTF-8.
    buf.push_str(core::str::from_utf8(label).ok()?);
    buf.push('.');
  }
  if buf.is_empty() {
    return None;
  }
  Name::try_from_str(&buf).ok()
}

/// Parse a PTR rdata slice (a decompressed wire-form name) into a [`Name`].
/// Returns `None` for a malformed or unrepresentable target.
pub(crate) fn parse_name(rdata: &[u8]) -> Option<Name> {
  let ptr = Ptr::try_from_message(rdata, 0, rdata.len()).ok()?;
  name_from_ref(ptr.target())
}

/// Parse an SRV rdata slice into `(target host, port)`. Returns `None` for a
/// malformed record or an unrepresentable target host name.
pub(crate) fn parse_srv(rdata: &[u8]) -> Option<(Name, u16)> {
  let srv = Srv::try_from_message(rdata, 0, rdata.len()).ok()?;
  let host = name_from_ref(srv.target())?;
  Some((host, srv.port()))
}

/// Parse a TXT rdata slice into its length-prefixed segments
/// (RFC 1035 §3.3.14 + RFC 6763 §6). Drops a malformed tail rather than
/// failing the whole record.
pub(crate) fn parse_txt(rdata: &[u8]) -> Vec<Bytes> {
  Txt::from_rdata(rdata)
    .segments()
    .map_while(Result::ok)
    .map(Bytes::copy_from_slice)
    .collect()
}

/// Which resolve step an answer belongs to. The string is the case-folded key
/// of the owning instance (SRV/TXT) or host (A/AAAA).
#[derive(Clone)]
#[allow(clippy::upper_case_acronyms)] // `AAAA` mirrors the DNS record-type name
pub(crate) enum Step {
  Ptr,
  Srv(SmolStr),
  Txt(SmolStr),
  A(SmolStr),
  AAAA(SmolStr),
}

/// A follow-up query the driver should launch as a result of feeding the
/// [`Resolver`] an answer.
#[derive(Clone)]
pub(crate) struct Start {
  pub(crate) name: Name,
  pub(crate) step: Step,
}

impl Start {
  pub(crate) const fn qtype(&self) -> ResourceType {
    match self.step {
      Step::Srv(_) => ResourceType::Srv,
      Step::Txt(_) => ResourceType::Txt,
      Step::A(_) => ResourceType::A,
      Step::AAAA(_) => ResourceType::AAAA,
      Step::Ptr => ResourceType::Ptr,
    }
  }
}

/// Addresses already learned for a host, so a later instance whose SRV resolves
/// to the same host picks them up even though the A/AAAA answer has come and
/// gone (the shared-host, SRV-after-A ordering).
#[derive(Default)]
pub(crate) struct HostAddrs {
  pub(crate) ipv4: Vec<Ipv4Addr>,
  pub(crate) ipv6: Vec<Ipv6Addr>,
}

/// In-progress aggregation of one service instance.
pub(crate) struct Builder {
  pub(crate) instance: Name,
  pub(crate) host: Option<Name>,
  pub(crate) host_key: Option<SmolStr>,
  /// Whether an SRV record has been seen. Tracked separately from `port`
  /// because `0` is a valid SRV port (the full `u16` range is parsed and the
  /// registration API does not reject it), so it cannot double as a sentinel.
  pub(crate) has_srv: bool,
  pub(crate) port: u16,
  pub(crate) ipv4: Vec<Ipv4Addr>,
  pub(crate) ipv6: Vec<Ipv6Addr>,
  pub(crate) txt: Option<Vec<Bytes>>,
  pub(crate) emitted: bool,
}

impl Builder {
  fn new(instance: Name) -> Self {
    Self {
      instance,
      host: None,
      host_key: None,
      has_srv: false,
      port: 0,
      ipv4: Vec::new(),
      ipv6: Vec::new(),
      txt: None,
      emitted: false,
    }
  }

  /// Complete once it has an SRV (host + port), TXT, and at least one address.
  fn complete(&self) -> bool {
    self.has_srv && self.txt.is_some() && !(self.ipv4.is_empty() && self.ipv6.is_empty())
  }

  fn finalize(&self) -> Option<ServiceEntry> {
    Some(ServiceEntry {
      instance: self.instance.clone(),
      host: self.host.clone()?,
      port: self.port,
      ipv4: self.ipv4.as_slice().into(),
      ipv6: self.ipv6.as_slice().into(),
      txt: self.txt.as_deref()?.into(),
    })
  }
}

/// Pure browse/resolve aggregation state machine — no I/O. The lookup driver
/// feeds it parsed answers and launches the follow-up queries it requests.
pub(crate) struct Resolver {
  pub(crate) builders: HashMap<SmolStr, Builder>,
  pub(crate) host_addrs: HashMap<SmolStr, HostAddrs>,
  pub(crate) hosts_queried: HashSet<SmolStr>,
  pub(crate) ready: VecDeque<ServiceEntry>,
  /// Cap on distinct instances tracked.
  pub(crate) max_entries: usize,
  /// Cap on distinct hosts A/AAAA-queried. Set equal to `max_entries`: honest
  /// browsing has at most one host per instance, so this never bites a real
  /// responder, but it bounds an instance that floods distinct SRV targets
  /// (which would otherwise grow `hosts_queried`/`host_addrs` and the in-flight
  /// A/AAAA sub-query set without limit).
  pub(crate) max_hosts: usize,
  pub(crate) dropped: u64,
}

impl Resolver {
  pub(crate) fn new(max_entries: usize) -> Self {
    Self {
      builders: HashMap::new(),
      host_addrs: HashMap::new(),
      hosts_queried: HashSet::new(),
      ready: VecDeque::new(),
      max_entries,
      max_hosts: max_entries,
      dropped: 0,
    }
  }

  /// A newly discovered instance: register it (subject to the cap) and request
  /// its SRV + TXT resolves.
  pub(crate) fn on_ptr(&mut self, instance: Name) -> Vec<Start> {
    let key = fold(&instance);
    if self.builders.contains_key(&key) {
      return Vec::new(); // already discovered
    }
    if self.builders.len() >= self.max_entries {
      self.dropped = self.dropped.saturating_add(1);
      return Vec::new();
    }
    self
      .builders
      .insert(key.clone(), Builder::new(instance.clone()));
    vec![
      Start {
        name: instance.clone(),
        step: Step::Srv(key.clone()),
      },
      Start {
        name: instance,
        step: Step::Txt(key),
      },
    ]
  }

  /// An instance's SRV: record host + port, adopt any addresses already learned
  /// for that host, and request A/AAAA the first time we see the host — subject
  /// to the distinct-host cap, which bounds an SRV-target flood.
  pub(crate) fn on_srv(&mut self, inst_key: &str, host: Name, port: u16) -> Vec<Start> {
    let host_key = fold(&host);
    let cached = self
      .host_addrs
      .get(&host_key)
      .map(|h| (h.ipv4.clone(), h.ipv6.clone()));
    let mut changed = false;
    if let Some(b) = self.builders.get_mut(inst_key) {
      let host_changed = b.host_key.as_deref() != Some(host_key.as_str());
      // SRV retargeting the instance to a DIFFERENT host invalidates the old
      // host's addresses — drop them before adopting the new host's, so a
      // re-emit never yields an entry whose host is the new target but whose
      // addresses still belong to the old one.
      if host_changed {
        b.ipv4.clear();
        b.ipv6.clear();
      }
      // A host or port change to an already-surfaced instance must re-emit
      // even when the new host's addresses are already cached — no fresh
      // A/AAAA event will arrive to trigger the re-emit, so without this the
      // consumer keeps a stale host/port.
      changed = host_changed || b.port != port;
      b.has_srv = true;
      b.host = Some(host.clone());
      b.host_key = Some(host_key.clone());
      b.port = port;
      if let Some((v4, v6)) = cached {
        for a in v4 {
          push_capped(&mut b.ipv4, a);
        }
        for a in v6 {
          push_capped(&mut b.ipv6, a);
        }
      }
    }
    self.try_emit(inst_key, changed);
    if self.hosts_queried.contains(&host_key) {
      return Vec::new(); // already querying this host
    }
    if self.hosts_queried.len() >= self.max_hosts {
      // SRV-target flood guard: refuse to query an unbounded set of hosts.
      // Counted so the resulting partial view is observable via `dropped`.
      self.dropped = self.dropped.saturating_add(1);
      return Vec::new();
    }
    self.hosts_queried.insert(host_key.clone());
    vec![
      Start {
        name: host.clone(),
        step: Step::A(host_key.clone()),
      },
      Start {
        name: host,
        step: Step::AAAA(host_key),
      },
    ]
  }

  pub(crate) fn on_txt(&mut self, inst_key: &str, segs: Vec<Bytes>) {
    let mut changed = false;
    if let Some(b) = self.builders.get_mut(inst_key) {
      // A TXT change to an already-surfaced instance must re-emit so the
      // consumer sees the new metadata; a duplicate TXT must not (no spurious
      // re-emit on a refresh that carries the same payload).
      changed = b.txt.as_deref() != Some(segs.as_slice());
      b.txt = Some(segs);
    }
    self.try_emit(inst_key, changed);
  }

  pub(crate) fn on_addr(&mut self, host_key: &str, addr: IpAddr) {
    let cache = self.host_addrs.entry(SmolStr::from(host_key)).or_default();
    match addr {
      IpAddr::V4(a) => {
        push_capped(&mut cache.ipv4, a);
      }
      IpAddr::V6(a) => {
        push_capped(&mut cache.ipv6, a);
      }
    }
    let keys: Vec<SmolStr> = self
      .builders
      .iter()
      .filter(|(_, b)| b.host_key.as_deref() == Some(host_key))
      .map(|(k, _)| k.clone())
      .collect();
    for k in keys {
      let added = match self.builders.get_mut(&k) {
        Some(b) => match addr {
          IpAddr::V4(a) => push_capped(&mut b.ipv4, a),
          IpAddr::V6(a) => push_capped(&mut b.ipv6, a),
        },
        None => false,
      };
      if added {
        self.try_emit(&k, true);
      }
    }
  }

  pub(crate) fn try_emit(&mut self, inst_key: &str, allow_reemit: bool) {
    if let Some(b) = self.builders.get_mut(inst_key) {
      if !b.complete() {
        return;
      }
      if !b.emitted {
        if let Some(e) = b.finalize() {
          b.emitted = true;
          self.ready.push_back(e);
        }
      } else if allow_reemit && let Some(e) = b.finalize() {
        self.ready.push_back(e);
      }
    }
  }

  pub(crate) fn take_ready(&mut self) -> Option<ServiceEntry> {
    self.ready.pop_front()
  }
}

/// A running DNS-SD lookup.
///
/// Call [`Self::next`] to receive resolved [`ServiceEntry`] values as they
/// complete; it returns `None` once every query (browse + resolves) has timed
/// out and the resolver has drained.  Resolution progresses while
/// [`Self::next`] is awaited — the lookup races the underlying sub-queries
/// concurrently via [`futures::future::select_all`], so the first query with
/// a buffered answer is processed without waiting on the others.
///
/// An instance may be yielded more than once as additional addresses resolve
/// (e.g. a late AAAA after the entry was first surfaced on its A address); a
/// later yield for the same [`ServiceEntry::instance_name`] supersedes the
/// earlier one.  Dropping the `Lookup` cancels every in-flight sub-query.
pub struct Lookup {
  pub(crate) endpoint: Endpoint,
  pub(crate) queries: Vec<(Query, Step)>,
  pub(crate) resolver: Resolver,
  pub(crate) resolve_timeout: Duration,
  pub(crate) unicast: bool,
  pub(crate) finished: bool,
}

impl Lookup {
  /// Wait for the next resolved service instance, or `None` when the lookup
  /// is finished (every sub-query has terminated and the resolver has
  /// drained).
  ///
  /// The borrow on `&mut self` matches the single-consumer mailbox contract
  /// inherited from [`Query::next`]: at most one [`Self::next`] is in flight
  /// per [`Lookup`].
  pub async fn next(&mut self) -> Option<ServiceEntry> {
    loop {
      if let Some(e) = self.resolver.take_ready() {
        return Some(e);
      }
      if self.finished || self.queries.is_empty() {
        self.finished = true;
        return None;
      }
      // Race every live sub-query so a buffered answer on any of them is
      // processed without parking on the rest.  Awaiting `queries[0].next()`
      // sequentially would starve queries 1..N (the plan's known bug).
      let (result, idx) = {
        let futs: Vec<_> = self
          .queries
          .iter()
          .map(|(q, _)| Box::pin(q.next()))
          .collect();
        let (result, idx, _remaining) = select_all(futs).await;
        // `_remaining` drops here, releasing the immutable borrow on
        // `self.queries`, so the swap_remove below is sound.
        (result, idx)
      };
      match result {
        Some(QueryEvent::Answer(answer)) => {
          let step = self.queries[idx].1.clone();
          let starts = feed(&mut self.resolver, step, QueryEvent::Answer(answer));
          self.launch_starts(starts).await;
        }
        Some(QueryEvent::Terminal(_)) | None => {
          self.queries.swap_remove(idx);
          if self.queries.is_empty() {
            self.finished = true;
          }
        }
      }
    }
  }

  async fn launch_starts(&mut self, starts: Vec<Start>) {
    for start in starts {
      let qtype = start.qtype();
      let step = start.step;
      let spec = QuerySpec::new(start.name, qtype)
        .with_timeout(self.resolve_timeout)
        .with_unicast_response(self.unicast);
      // A `StartQueryError::StorageFull` here just means we can't make
      // forward progress on this sub-step; the other live queries continue,
      // and the resolver still terminates when they drain.
      if let Ok(q) = self.endpoint.start_query(spec).await {
        self.queries.push((q, step));
      }
    }
  }
}

/// Decode one tagged answer, fold it into `resolver`, and return any
/// follow-up queries it requests.  Shared by [`Lookup::next`] and the
/// one-shot [`Endpoint::resolve_instance`] convenience.
pub(crate) fn feed(resolver: &mut Resolver, step: Step, event: QueryEvent) -> Vec<Start> {
  let answer = match event {
    QueryEvent::Answer(a) => a,
    QueryEvent::Terminal(_) => return Vec::new(),
  };
  match step {
    Step::Ptr => {
      if answer.rtype() != ResourceType::Ptr {
        return Vec::new();
      }
      match parse_name(answer.rdata_slice()) {
        Some(instance) => resolver.on_ptr(instance),
        None => Vec::new(),
      }
    }
    Step::Srv(inst_key) => {
      if answer.rtype() != ResourceType::Srv {
        return Vec::new();
      }
      match parse_srv(answer.rdata_slice()) {
        Some((host, port)) => resolver.on_srv(&inst_key, host, port),
        None => Vec::new(),
      }
    }
    Step::Txt(inst_key) => {
      if answer.rtype() != ResourceType::Txt {
        return Vec::new();
      }
      resolver.on_txt(&inst_key, parse_txt(answer.rdata_slice()));
      Vec::new()
    }
    Step::A(host_key) => {
      if answer.rtype() == ResourceType::A
        && let Ok(r) = A::try_from_rdata(answer.rdata_slice())
      {
        resolver.on_addr(&host_key, IpAddr::V4(r.addr()));
      }
      Vec::new()
    }
    Step::AAAA(host_key) => {
      if answer.rtype() == ResourceType::AAAA
        && let Ok(r) = AAAA::try_from_rdata(answer.rdata_slice())
      {
        resolver.on_addr(&host_key, IpAddr::V6(r.addr()));
      }
      Vec::new()
    }
  }
}

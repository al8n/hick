//! DNS-SD service discovery — browse a service type and resolve each instance
//! into a fully-populated [`ServiceEntry`].
//!
//! This is the high-level client layer over [`Endpoint::start_query`]. A
//! [`Lookup`] performs the RFC 6763 browse → resolve chain:
//!
//! 1. **Browse** (§4.1): a PTR query for the service type
//!    (`_service._proto.local.`) yields the names of the published instances.
//! 2. **Resolve** (§5): for each instance, an SRV query gives the target host
//!    and port and a TXT query gives the metadata.
//! 3. **Address** (§5): A / AAAA queries against the SRV target host give the
//!    reachable addresses.
//!
//! An instance is surfaced as a [`ServiceEntry`] once it has a port (SRV), TXT
//! data, and at least one address. Each step is a real [`crate::Query`], so
//! retransmission, caching, and TTL handling are inherited from the
//! proto/driver layers; the whole lookup is bounded by the per-query timeouts
//! and by [`QueryParam::with_max_entries`], and is cancelled by dropping the
//! [`Lookup`].
//!
//! # Design
//!
//! Modeled on quinn's `ConnectionDriver`: a spawned [`LookupDriver`] task owns
//! the browse/resolve sub-queries and the aggregation state machine, and pushes
//! resolved entries into shared state ([`LookupQueue`]) that the [`Lookup`]
//! handle drains — mirroring the [`crate::Query`] mailbox/doorbell split. Driving
//! the aggregation in its own task (rather than only while the caller awaits
//! [`Lookup::next`]) means the sub-query mailboxes are drained promptly, so a
//! slow consumer cannot stall resolution; the shared queue stays bounded by
//! coalescing repeated snapshots of an instance.
//!
//! Instance/host names that the [`Name`] type cannot represent faithfully — a
//! label containing a `.` or a non-ASCII byte — are skipped rather than
//! silently corrupted (`Name` is an ASCII, dot-separated, no-escaping type).

use std::{
  collections::{HashMap, HashSet, VecDeque},
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  sync::{Arc, Mutex, MutexGuard},
  time::{Duration, Instant},
};

use async_channel::{Receiver, Sender};
use bytes::Bytes;
use futures::{
  FutureExt, StreamExt, pin_mut, select_biased,
  stream::{BoxStream, SelectAll},
};
use mdns_proto::{
  Name, QuerySpec,
  wire::{A, AAAA, NameRef, Ptr, ResourceType, Srv, Txt},
};
use smol_str::SmolStr;

use crate::{
  Endpoint, QueryEvent,
  error::StartQueryError,
  query::{DroppedHandle, Query},
};

/// Default cap on the number of distinct instances a [`Lookup`] tracks, so a
/// chatty or hostile responder flooding PTR answers cannot grow the builder map
/// or the in-flight sub-query set without bound.
pub const DEFAULT_MAX_ENTRIES: usize = 64;

/// Cap on the addresses kept per host per family (and per instance), so a
/// responder flooding distinct A/AAAA records for one host cannot grow the
/// address vectors (in the host cache or any builder) without bound.
const MAX_ADDRS_PER_HOST: usize = 16;

/// A resolved DNS-SD service instance.
///
/// Produced by [`Lookup::next`] once the instance's SRV (host + port), TXT, and
/// at least one address have been collected.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
  instance: Name,
  host: Name,
  port: u16,
  ipv4: Arc<[Ipv4Addr]>,
  ipv6: Arc<[Ipv6Addr]>,
  txt: Arc<[Bytes]>,
}

impl ServiceEntry {
  /// The fully-qualified service instance name (the PTR target), e.g.
  /// `myprinter._ipp._tcp.local.`.
  #[inline]
  pub fn instance_name(&self) -> &Name {
    &self.instance
  }

  /// The target host the SRV record points at, e.g. `printer.local.`.
  #[inline]
  pub fn host(&self) -> &Name {
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

/// Parameters for a [`Lookup`] / browse.
#[derive(Debug, Clone)]
pub struct QueryParam {
  service: Name,
  timeout: Duration,
  resolve_timeout: Option<Duration>,
  unicast_response: bool,
  max_entries: usize,
}

impl QueryParam {
  /// Browse the given fully-qualified service type, e.g.
  /// `Name::try_from_str("_ipp._tcp.local.")`.
  pub fn new(service: Name) -> Self {
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
  pub const fn with_timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  /// How long each per-instance resolve query (SRV / TXT / A / AAAA) runs.
  /// Defaults to the browse timeout.
  #[must_use]
  pub const fn with_resolve_timeout(mut self, timeout: Duration) -> Self {
    self.resolve_timeout = Some(timeout);
    self
  }

  /// Request unicast responses on the issued queries (RFC 6762 §5.4). Defaults
  /// to `false` (standard multicast browse).
  #[must_use]
  pub const fn with_unicast_response(mut self, unicast: bool) -> Self {
    self.unicast_response = unicast;
    self
  }

  /// Cap on the number of distinct instances tracked; instances discovered
  /// beyond it are dropped (counted by [`Lookup::dropped`]). Defaults to
  /// `DEFAULT_MAX_ENTRIES`. A value of `0` is treated as `1`.
  #[must_use]
  pub const fn with_max_entries(mut self, max: usize) -> Self {
    self.max_entries = if max == 0 { 1 } else { max };
    self
  }
}

/// Which resolve step an answer belongs to. The string is the case-folded key
/// of the owning instance (SRV/TXT) or host (A/AAAA).
#[derive(Clone)]
#[allow(clippy::upper_case_acronyms)] // `AAAA` mirrors the DNS record-type name
enum Step {
  Ptr,
  Srv(SmolStr),
  Txt(SmolStr),
  A(SmolStr),
  AAAA(SmolStr),
}

/// One answer, tagged with the resolve step that produced it.
struct Tagged {
  step: Step,
  event: QueryEvent,
}

/// A follow-up query the driver should launch as a result of feeding the
/// [`Resolver`] an answer.
#[derive(Clone)]
struct Start {
  name: Name,
  step: Step,
}

impl Start {
  const fn qtype(&self) -> ResourceType {
    match self.step {
      Step::Srv(_) => ResourceType::Srv,
      Step::Txt(_) => ResourceType::Txt,
      Step::A(_) => ResourceType::A,
      Step::AAAA(_) => ResourceType::AAAA,
      Step::Ptr => ResourceType::Ptr,
    }
  }
}

/// In-progress aggregation of one service instance.
struct Builder {
  instance: Name,
  host: Option<Name>,
  host_key: Option<SmolStr>,
  /// Whether an SRV record has been seen. Tracked separately from `port`
  /// because `0` is a valid SRV port (the full `u16` range is parsed and the
  /// registration API does not reject it), so it cannot double as a sentinel.
  has_srv: bool,
  port: u16,
  ipv4: Vec<Ipv4Addr>,
  ipv6: Vec<Ipv6Addr>,
  txt: Option<Vec<Bytes>>,
  emitted: bool,
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

/// Addresses already learned for a host, so a later instance whose SRV resolves
/// to the same host picks them up even though the A/AAAA answer has come and
/// gone (the shared-host, SRV-after-A ordering).
#[derive(Default)]
struct HostAddrs {
  ipv4: Vec<Ipv4Addr>,
  ipv6: Vec<Ipv6Addr>,
}

/// Pure browse/resolve aggregation state machine — no I/O. The [`LookupDriver`]
/// feeds it parsed answers and launches the follow-up queries it requests.
struct Resolver {
  builders: HashMap<SmolStr, Builder>,
  host_addrs: HashMap<SmolStr, HostAddrs>,
  hosts_queried: HashSet<SmolStr>,
  ready: VecDeque<ServiceEntry>,
  /// Cap on distinct instances tracked.
  max_entries: usize,
  /// Cap on distinct hosts A/AAAA-queried. Set equal to `max_entries`: honest
  /// browsing has at most one host per instance, so this never bites a real
  /// responder, but it bounds an instance that floods distinct SRV targets
  /// (which would otherwise grow `hosts_queried`/`host_addrs` and the in-flight
  /// A/AAAA sub-query set without limit).
  max_hosts: usize,
  dropped: u64,
}

impl Resolver {
  fn new(max_entries: usize) -> Self {
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
  fn on_ptr(&mut self, instance: Name) -> Vec<Start> {
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
  fn on_srv(&mut self, inst_key: &str, host: Name, port: u16) -> Vec<Start> {
    let host_key = fold(&host);
    let cached = self.host_addrs.get(&host_key);
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
      // A host or port change to an already-surfaced instance must re-emit even
      // when the new host's addresses are already cached — no fresh A/AAAA event
      // will arrive to trigger the re-emit, so without this the consumer keeps a
      // stale host/port.
      changed = host_changed || b.port != port;
      b.has_srv = true;
      b.host = Some(host.clone());
      b.host_key = Some(host_key.clone());
      b.port = port;
      if let Some(addrs) = cached {
        for &a in &addrs.ipv4 {
          push_capped(&mut b.ipv4, a);
        }
        for &a in &addrs.ipv6 {
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

  fn on_txt(&mut self, inst_key: &str, segs: Vec<Bytes>) {
    let mut changed = false;
    if let Some(b) = self.builders.get_mut(inst_key) {
      // A TXT change to an already-surfaced instance must re-emit so the
      // consumer sees the new metadata; a duplicate TXT must not (no spurious
      // re-emit). First TXT flips this from `None`, driving the first emit once
      // the instance is otherwise complete.
      changed = b.txt.as_deref() != Some(segs.as_slice());
      b.txt = Some(segs);
    }
    self.try_emit(inst_key, changed);
  }

  /// An A/AAAA answer for a host: cache it (capped) and apply it to every
  /// instance whose SRV already pointed at that host. A newly-added address may
  /// re-emit an already-surfaced instance with the fuller address set.
  ///
  /// Only called for a host we actually launched A/AAAA queries for (a step key
  /// from a query we started), so `host_addrs` stays bounded by `hosts_queried`.
  fn on_addr(&mut self, host_key: &str, addr: IpAddr) {
    let cache = self.host_addrs.entry(SmolStr::from(host_key)).or_default();
    match addr {
      IpAddr::V4(a) => push_capped(&mut cache.ipv4, a),
      IpAddr::V6(a) => push_capped(&mut cache.ipv6, a),
    };
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

  /// Emit the instance if it is complete: the first time it completes, or — when
  /// `allow_reemit` — again with an updated snapshot (e.g. a late AAAA after the
  /// entry was first surfaced on its A address).
  fn try_emit(&mut self, inst_key: &str, allow_reemit: bool) {
    if let Some(b) = self.builders.get_mut(inst_key) {
      if !b.complete() {
        return;
      }
      if !b.emitted {
        if let Some(entry) = b.finalize() {
          b.emitted = true;
          self.ready.push_back(entry);
        }
      } else if allow_reemit && let Some(entry) = b.finalize() {
        self.ready.push_back(entry);
      }
    }
  }

  fn take_ready(&mut self) -> Option<ServiceEntry> {
    self.ready.pop_front()
  }
}

/// Bounded, instance-coalescing queue of resolved entries shared between the
/// spawned [`LookupDriver`] (which fills it) and the [`Lookup`] handle (which
/// drains it via [`Lookup::next`]). Mirrors the [`crate::Query`] mailbox.
struct LookupQueue {
  ready: VecDeque<ServiceEntry>,
  /// Set once the driver task has finished (all sub-queries terminated, or the
  /// handle was dropped). A drained-empty queue with `done` set is end-of-stream.
  done: bool,
  /// Snapshot of the resolver's drop counter, surfaced via [`Lookup::dropped`].
  dropped: u64,
}

impl LookupQueue {
  #[inline(always)]
  const fn new() -> Self {
    Self {
      ready: VecDeque::new(),
      done: false,
      dropped: 0,
    }
  }

  /// Enqueue a resolved entry, coalescing by instance so a slow consumer cannot
  /// grow the queue past the live instance set: a newer snapshot for an instance
  /// supersedes any still-pending one (matching the "later yield supersedes
  /// earlier" contract on [`Lookup::next`]).
  fn enqueue(&mut self, entry: ServiceEntry) {
    if let Some(slot) = self
      .ready
      .iter_mut()
      .find(|e| e.instance.as_str() == entry.instance.as_str())
    {
      *slot = entry;
    } else {
      self.ready.push_back(entry);
    }
  }
}

/// Lock the shared queue, recovering the guard if a previous holder panicked
/// (the lock is never held across a fallible operation, so the data is sound).
fn lock(q: &Mutex<LookupQueue>) -> MutexGuard<'_, LookupQueue> {
  q.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Spawned task that owns the browse/resolve sub-queries and the [`Resolver`],
/// feeding resolved entries into the shared [`LookupQueue`]. Quinn's
/// `ConnectionDriver`, scoped to a single lookup.
struct LookupDriver {
  endpoint: Endpoint,
  streams: SelectAll<BoxStream<'static, Tagged>>,
  resolver: Resolver,
  /// Drop counter of the browse (PTR) query. Surplus instances evicted by the
  /// PTR query's bounded answer pool before [`Resolver::on_ptr`] sees them are
  /// counted here rather than in `resolver.dropped`; folding both into
  /// [`Lookup::dropped`] keeps the partial-view signal complete.
  ptr_drops: DroppedHandle,
  queue: Arc<Mutex<LookupQueue>>,
  /// Capacity-1 wakeup the consumer parks on; rung after the queue changes.
  doorbell: Sender<()>,
  /// Closes when the [`Lookup`] handle is dropped, which stops the task and
  /// (by dropping the sub-query [`Query`] handles) cancels every sub-query.
  cancel: Receiver<()>,
  resolve_timeout: Duration,
  unicast: bool,
}

impl LookupDriver {
  async fn run(mut self) {
    loop {
      // Wait for the next answer or for the handle to be dropped. The futures
      // borrow disjoint fields; act on `self` only after the select resolves
      // (mirrors the main driver loop's borrow discipline).
      let tagged = {
        let next = self.streams.next().fuse();
        let stop = self.cancel.recv().fuse();
        pin_mut!(next, stop);
        select_biased! {
          _ = stop => None,   // handle dropped → stop
          t = next => t,      // Some(answer), or None when all sub-queries end
        }
      };
      match tagged {
        Some(t) => self.process(t).await,
        None => break,
      }
    }
    // Signal end-of-stream and wake any parked consumer.
    {
      let mut q = lock(&self.queue);
      q.done = true;
      q.dropped = self.dropped_total();
    }
    let _ = self.doorbell.try_send(());
  }

  /// Feed one answer to the resolver, launch any follow-up queries it requests,
  /// then flush newly-resolved entries to the consumer.
  async fn process(&mut self, tagged: Tagged) {
    for start in feed(&mut self.resolver, tagged) {
      // Launch inline. If the handle was dropped mid-launch the `start_query`
      // round-trip still completes promptly (the main driver replies regardless),
      // and the next loop iteration's `cancel` arm stops the task.
      self.launch(start).await;
    }
    self.flush();
  }

  /// Total observable drops surfaced via [`Lookup::dropped`]: instances refused
  /// by the resolver caps plus surplus PTR answers the browse query's bounded
  /// answer pool evicted before the resolver could see them (disjoint counts).
  fn dropped_total(&self) -> u64 {
    self.resolver.dropped.saturating_add(self.ptr_drops.get())
  }

  /// Move newly-resolved entries into the shared queue and wake the consumer.
  fn flush(&mut self) {
    let mut woke = false;
    let mut q = lock(&self.queue);
    while let Some(entry) = self.resolver.take_ready() {
      q.enqueue(entry);
      woke = true;
    }
    q.dropped = self.dropped_total();
    drop(q);
    if woke {
      let _ = self.doorbell.try_send(());
    }
  }

  /// Start a resolve sub-query and fold its answers into the merged stream.
  async fn launch(&mut self, start: Start) {
    let qtype = start.qtype();
    let spec = QuerySpec::new(start.name, qtype)
      .with_timeout(self.resolve_timeout)
      .with_unicast_response(self.unicast);
    if let Ok(query) = self.endpoint.start_query(spec).await {
      self.streams.push(tagged_stream(query, start.step));
    }
  }
}

/// A running DNS-SD lookup.
///
/// Call [`Self::next`] to receive resolved [`ServiceEntry`] values as they
/// complete; it returns `None` once every query (browse + resolves) has timed
/// out. Resolution is driven by a spawned `LookupDriver` task, so it proceeds
/// even between calls to `next`. Dropping the `Lookup` stops that task and
/// cancels all of its in-flight queries.
pub struct Lookup {
  queue: Arc<Mutex<LookupQueue>>,
  /// Capacity-1 wakeup the driver rings after filling the queue.
  doorbell: async_channel::Receiver<()>,
  /// Held only so dropping the `Lookup` closes the driver's `cancel` channel.
  _cancel: async_channel::Sender<()>,
}

impl Lookup {
  /// Wait for the next resolved service instance, or `None` when the lookup is
  /// finished (all queries timed out).
  ///
  /// An instance may be yielded more than once as additional addresses resolve
  /// (e.g. a late AAAA after the entry was first surfaced on its A address); a
  /// later yield for the same [`ServiceEntry::instance_name`] supersedes the
  /// earlier one. Single-consumer: takes `&mut self`, so there is at most one
  /// in-flight `next()` per `Lookup`, matching the single-waiter doorbell.
  pub async fn next(&mut self) -> Option<ServiceEntry> {
    loop {
      {
        let mut q = lock(&self.queue);
        if let Some(entry) = q.ready.pop_front() {
          return Some(entry);
        }
        if q.done {
          return None;
        }
      }
      // Nothing ready: park until the driver rings. A closed doorbell means the
      // driver task exited — do one final drain (entries or the `done` flag it
      // set just before exiting are already visible under the lock).
      if self.doorbell.recv().await.is_err() {
        return lock(&self.queue).ready.pop_front();
      }
    }
  }

  /// Number of discoveries dropped because a bound was reached: the
  /// distinct-instance cap ([`QueryParam::with_max_entries`]), the distinct-host
  /// cap that bounds an SRV-target flood, or surplus PTR answers evicted by the
  /// browse query's bounded answer pool before they could be tracked. A non-zero
  /// value means the result set is a partial view.
  pub fn dropped(&self) -> u64 {
    lock(&self.queue).dropped
  }
}

impl Endpoint {
  /// Browse for instances of a DNS-SD service type, resolving each into a
  /// [`ServiceEntry`]. See [`Lookup`] and [`QueryParam`].
  pub async fn browse(&self, param: QueryParam) -> Result<Lookup, StartQueryError> {
    let resolve_timeout = param.resolve_timeout.unwrap_or(param.timeout);
    let ptr_spec = QuerySpec::new(param.service, ResourceType::Ptr)
      .with_timeout(param.timeout)
      .with_unicast_response(param.unicast_response)
      // Size the PTR answer pool to the requested instance cap so a max_entries
      // above the query's default answer cap is actually reachable, and the
      // Resolver — not the query's answer pool — is what bounds and counts
      // instances (`Lookup::dropped`). Without this, surplus PTR answers would be
      // evicted before `on_ptr` could track or count them.
      .with_max_answers(param.max_entries);
    // Start the browse query up front so a start failure surfaces synchronously
    // to the caller rather than vanishing inside the spawned task.
    let ptr_query = self.start_query(ptr_spec).await?;
    // Capture the browse query's drop counter before it is moved into the
    // merged stream, so the driver can fold its evictions into `Lookup::dropped`.
    let ptr_drops = ptr_query.dropped_handle();

    let mut streams = SelectAll::new();
    streams.push(tagged_stream(ptr_query, Step::Ptr));

    let queue = Arc::new(Mutex::new(LookupQueue::new()));
    let (doorbell_tx, doorbell_rx) = async_channel::bounded(1);
    let (cancel_tx, cancel_rx) = async_channel::bounded(1);

    let driver = LookupDriver {
      endpoint: self.clone(),
      streams,
      resolver: Resolver::new(param.max_entries),
      ptr_drops,
      queue: Arc::clone(&queue),
      doorbell: doorbell_tx,
      cancel: cancel_rx,
      resolve_timeout,
      unicast: param.unicast_response,
    };
    self.spawn_lookup(driver.run())?;

    Ok(Lookup {
      queue,
      doorbell: doorbell_rx,
      _cancel: cancel_tx,
    })
  }

  /// Convenience for [`Self::browse`] with default parameters and the given
  /// browse timeout.
  pub async fn lookup(&self, service: Name, timeout: Duration) -> Result<Lookup, StartQueryError> {
    self
      .browse(QueryParam::new(service).with_timeout(timeout))
      .await
  }

  /// Resolve a host name to its addresses via mDNS A / AAAA queries (RFC 6762),
  /// without the DNS-SD browse/resolve chain.
  ///
  /// Issues both queries and collects every advertised address for the
  /// `timeout` window (the answer window for multicast responses), returning
  /// them IPv4 first then IPv6, deduplicated and capped per family. The result
  /// is empty if nothing answers. Unlike [`Self::resolve_instance`] this does
  /// not require — or interpret — DNS-SD records; it is the multicast analogue
  /// of resolving a hostname.
  pub async fn resolve_host(
    &self,
    host: Name,
    timeout: Duration,
  ) -> Result<Vec<IpAddr>, StartQueryError> {
    let host_key = fold(&host);
    let a = self
      .start_query(QuerySpec::new(host.clone(), ResourceType::A).with_timeout(timeout))
      .await?;
    let aaaa = self
      .start_query(QuerySpec::new(host, ResourceType::AAAA).with_timeout(timeout))
      .await?;
    let mut streams = SelectAll::new();
    streams.push(tagged_stream(a, Step::A(host_key.clone())));
    streams.push(tagged_stream(aaaa, Step::AAAA(host_key)));

    // Drive both queries to their terminal (the timeout), gathering addresses.
    // The consumer here is this future itself, so the streams drain promptly.
    let mut ipv4: Vec<Ipv4Addr> = Vec::new();
    let mut ipv6: Vec<Ipv6Addr> = Vec::new();
    while let Some(tagged) = streams.next().await {
      let ans = match tagged.event {
        QueryEvent::Answer(a) => a,
        QueryEvent::Terminal(_) => continue,
      };
      match ans.rtype() {
        ResourceType::A => {
          if let Ok(r) = A::try_from_rdata(ans.rdata_slice()) {
            push_capped(&mut ipv4, r.addr());
          }
        }
        ResourceType::AAAA => {
          if let Ok(r) = AAAA::try_from_rdata(ans.rdata_slice()) {
            push_capped(&mut ipv6, r.addr());
          }
        }
        _ => {}
      }
    }
    Ok(
      ipv4
        .into_iter()
        .map(IpAddr::V4)
        .chain(ipv6.into_iter().map(IpAddr::V6))
        .collect(),
    )
  }

  /// Resolve a *known* DNS-SD service instance directly into a [`ServiceEntry`],
  /// skipping the PTR browse step (e.g.
  /// `Name::try_from_str("Office._ipp._tcp.local.")`).
  ///
  /// Issues SRV + TXT for the instance and A / AAAA for the SRV target host, and
  /// returns the first complete resolution — host + port, TXT, and at least one
  /// address — or `None` if it does not complete within `timeout`. Use
  /// [`Self::browse`] instead when the instance names are not known in advance.
  pub async fn resolve_instance(
    &self,
    instance: Name,
    timeout: Duration,
  ) -> Result<Option<ServiceEntry>, StartQueryError> {
    // One deadline shared across stages: follow-up A/AAAA queries get the
    // REMAINING budget, not a fresh full `timeout`, so the whole call stays
    // bounded by `timeout` as documented (an SRV arriving late can't grant the
    // address queries a second full window).
    // `checked_add` so a pathological `timeout` (e.g. `Duration::MAX`) cannot
    // panic the way `Instant + Duration` would. An overflow means "no effective
    // deadline", so each stage just receives the full (huge) `timeout`, which
    // `QuerySpec` clamps with its own checked arithmetic.
    let deadline = Instant::now().checked_add(timeout);
    let remaining = || deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
    let mut resolver = Resolver::new(1);
    let mut streams = SelectAll::new();
    // Seed the resolver with the instance and issue its SRV + TXT (no PTR).
    for start in resolver.on_ptr(instance) {
      streams.push(self.launch_resolve(start, remaining()).await?);
    }
    // Drive inline until the instance completes or every sub-query times out.
    while let Some(tagged) = streams.next().await {
      for start in feed(&mut resolver, tagged) {
        streams.push(self.launch_resolve(start, remaining()).await?);
      }
      if let Some(entry) = resolver.take_ready() {
        return Ok(Some(entry));
      }
    }
    Ok(resolver.take_ready())
  }

  /// Start a resolve sub-query and wrap it as a tagged stream. Used by the
  /// one-shot resolve conveniences, which drive the merged streams inline rather
  /// than via a spawned [`LookupDriver`].
  async fn launch_resolve(
    &self,
    start: Start,
    timeout: Duration,
  ) -> Result<futures::stream::BoxStream<'static, Tagged>, StartQueryError> {
    let qtype = start.qtype();
    let query = self
      .start_query(QuerySpec::new(start.name, qtype).with_timeout(timeout))
      .await?;
    Ok(tagged_stream(query, start.step))
  }
}

/// Decode one tagged answer, fold it into `resolver`, and return any follow-up
/// queries it requests. Shared by the streaming [`LookupDriver`] and the
/// one-shot [`Endpoint::resolve_instance`] convenience.
fn feed(resolver: &mut Resolver, tagged: Tagged) -> Vec<Start> {
  let answer = match tagged.event {
    QueryEvent::Answer(a) => a,
    QueryEvent::Terminal(_) => return Vec::new(),
  };
  match tagged.step {
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
      if let Ok(r) = A::try_from_rdata(answer.rdata_slice())
        && answer.rtype() == ResourceType::A
      {
        resolver.on_addr(&host_key, IpAddr::V4(r.addr()));
      }
      Vec::new()
    }
    Step::AAAA(host_key) => {
      if let Ok(r) = AAAA::try_from_rdata(answer.rdata_slice())
        && answer.rtype() == ResourceType::AAAA
      {
        resolver.on_addr(&host_key, IpAddr::V6(r.addr()));
      }
      Vec::new()
    }
  }
}

/// Wrap a [`Query`] as a `'static` stream of [`Tagged`] answers for the given
/// resolve step. The stream ends when the query reaches its terminal.
fn tagged_stream(query: Query, step: Step) -> futures::stream::BoxStream<'static, Tagged> {
  futures::stream::unfold((query, step), |(mut query, step)| async move {
    let event = query.next().await?;
    let tagged = Tagged {
      step: step.clone(),
      event,
    };
    Some((tagged, (query, step)))
  })
  .boxed()
}

/// Push `item` into `v` if it is new and `v` is under [`MAX_ADDRS_PER_HOST`].
/// Returns `true` if it was added (so the caller can decide to (re)emit).
fn push_capped<T: PartialEq>(v: &mut Vec<T>, item: T) -> bool {
  if v.len() >= MAX_ADDRS_PER_HOST || v.contains(&item) {
    return false;
  }
  v.push(item);
  true
}

/// Case-fold a name to its lookup key (DNS names are case-insensitive,
/// RFC 6762 §16).
fn fold(name: &Name) -> SmolStr {
  // `Name` is already stored canonical-lowercase (RFC 6762 §16), so a plain
  // `SmolStr::new` suffices — and inlines names ≤23 bytes, whereas collecting
  // from a `char` iterator always takes SmolStr's heap path.
  SmolStr::new(name.as_str())
}

/// Decode an owner-less wire-form domain name (a decompressed PTR/SRV target as
/// stored in a [`mdns_proto::CollectedAnswer`]) into an owned [`Name`].
///
/// Returns `None` for any name the [`Name`] type cannot represent faithfully:
/// a label containing a `.` (always a separator) or a non-ASCII byte (mangled
/// by `Name`). Such instances are skipped rather than silently corrupted.
fn name_from_ref(nr: &NameRef<'_>) -> Option<Name> {
  let mut s = String::new();
  for label in nr.labels() {
    let label = label.ok()?;
    if label.is_empty() {
      break; // root terminator
    }
    if label.iter().any(|&b| b >= 0x80 || b == b'.') {
      return None; // not representable by `Name` without corruption
    }
    // Verified ASCII above, so this is always valid UTF-8.
    s.push_str(core::str::from_utf8(label).ok()?);
    s.push('.');
  }
  if s.is_empty() {
    return None;
  }
  Name::try_from_str(&s).ok()
}

/// Parse a PTR rdata slice (a decompressed wire-form name) into a [`Name`].
fn parse_name(rdata: &[u8]) -> Option<Name> {
  let ptr = Ptr::try_from_message(rdata, 0, rdata.len()).ok()?;
  name_from_ref(ptr.target())
}

/// Parse an SRV rdata slice into `(target host, port)`.
fn parse_srv(rdata: &[u8]) -> Option<(Name, u16)> {
  let srv = Srv::try_from_message(rdata, 0, rdata.len()).ok()?;
  let host = name_from_ref(srv.target())?;
  Some((host, srv.port()))
}

/// Parse a TXT rdata slice into its segments (dropping a malformed tail).
fn parse_txt(rdata: &[u8]) -> Vec<Bytes> {
  Txt::from_rdata(rdata)
    .segments()
    .map_while(Result::ok)
    .map(Bytes::copy_from_slice)
    .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

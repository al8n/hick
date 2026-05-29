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
  time::Duration,
};

use futures::{FutureExt, StreamExt, pin_mut, select_biased, stream::SelectAll};
use mdns_proto::{
  Name, QuerySpec,
  wire::{ARecord, AaaaRecord, NameRef, PtrRecord, ResourceType, SrvRecord, TxtRecord},
};

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
  ipv4: Vec<Ipv4Addr>,
  ipv6: Vec<Ipv6Addr>,
  txt: Vec<Vec<u8>>,
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
  pub fn txt(&self) -> &[Vec<u8>] {
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
  /// [`DEFAULT_MAX_ENTRIES`]. A value of `0` is treated as `1`.
  #[must_use]
  pub const fn with_max_entries(mut self, max: usize) -> Self {
    self.max_entries = if max == 0 { 1 } else { max };
    self
  }
}

/// Which resolve step an answer belongs to. The string is the case-folded key
/// of the owning instance (SRV/TXT) or host (A/AAAA).
#[derive(Clone)]
enum Step {
  Ptr,
  Srv(String),
  Txt(String),
  A(String),
  Aaaa(String),
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
      Step::Aaaa(_) => ResourceType::Aaaa,
      Step::Ptr => ResourceType::Ptr,
    }
  }
}

/// In-progress aggregation of one service instance.
struct Builder {
  instance: Name,
  host: Option<Name>,
  host_key: Option<String>,
  port: u16,
  ipv4: Vec<Ipv4Addr>,
  ipv6: Vec<Ipv6Addr>,
  txt: Option<Vec<Vec<u8>>>,
  emitted: bool,
}

impl Builder {
  fn new(instance: Name) -> Self {
    Self {
      instance,
      host: None,
      host_key: None,
      port: 0,
      ipv4: Vec::new(),
      ipv6: Vec::new(),
      txt: None,
      emitted: false,
    }
  }

  /// Complete once it has a port (SRV), TXT, and at least one address.
  fn complete(&self) -> bool {
    self.port != 0 && self.txt.is_some() && !(self.ipv4.is_empty() && self.ipv6.is_empty())
  }

  fn finalize(&self) -> Option<ServiceEntry> {
    Some(ServiceEntry {
      instance: self.instance.clone(),
      host: self.host.clone()?,
      port: self.port,
      ipv4: self.ipv4.clone(),
      ipv6: self.ipv6.clone(),
      txt: self.txt.clone()?,
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
  builders: HashMap<String, Builder>,
  host_addrs: HashMap<String, HostAddrs>,
  hosts_queried: HashSet<String>,
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
        step: Step::Aaaa(host_key),
      },
    ]
  }

  fn on_txt(&mut self, inst_key: &str, segs: Vec<Vec<u8>>) {
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
    let cache = self.host_addrs.entry(host_key.to_owned()).or_default();
    match addr {
      IpAddr::V4(a) => push_capped(&mut cache.ipv4, a),
      IpAddr::V6(a) => push_capped(&mut cache.ipv6, a),
    };
    let keys: Vec<String> = self
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
      } else if allow_reemit {
        if let Some(entry) = b.finalize() {
          self.ready.push_back(entry);
        }
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
  fn new() -> Self {
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
  streams: SelectAll<futures::stream::BoxStream<'static, Tagged>>,
  resolver: Resolver,
  /// Drop counter of the browse (PTR) query. Surplus instances evicted by the
  /// PTR query's bounded answer pool before [`Resolver::on_ptr`] sees them are
  /// counted here rather than in `resolver.dropped`; folding both into
  /// [`Lookup::dropped`] keeps the partial-view signal complete.
  ptr_drops: DroppedHandle,
  queue: Arc<Mutex<LookupQueue>>,
  /// Capacity-1 wakeup the consumer parks on; rung after the queue changes.
  doorbell: async_channel::Sender<()>,
  /// Closes when the [`Lookup`] handle is dropped, which stops the task and
  /// (by dropping the sub-query [`Query`] handles) cancels every sub-query.
  cancel: async_channel::Receiver<()>,
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
    for start in self.feed(tagged) {
      // Launch inline. If the handle was dropped mid-launch the `start_query`
      // round-trip still completes promptly (the main driver replies regardless),
      // and the next loop iteration's `cancel` arm stops the task.
      self.launch(start).await;
    }
    self.flush();
  }

  /// Decode `tagged`, feed the resolver, and return the follow-up queries.
  fn feed(&mut self, tagged: Tagged) -> Vec<Start> {
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
          Some(instance) => self.resolver.on_ptr(instance),
          None => Vec::new(),
        }
      }
      Step::Srv(inst_key) => {
        if answer.rtype() != ResourceType::Srv {
          return Vec::new();
        }
        match parse_srv(answer.rdata_slice()) {
          Some((host, port)) => self.resolver.on_srv(&inst_key, host, port),
          None => Vec::new(),
        }
      }
      Step::Txt(inst_key) => {
        if answer.rtype() != ResourceType::Txt {
          return Vec::new();
        }
        self
          .resolver
          .on_txt(&inst_key, parse_txt(answer.rdata_slice()));
        Vec::new()
      }
      Step::A(host_key) => {
        if let Ok(r) = ARecord::try_from_rdata(answer.rdata_slice()) {
          if answer.rtype() == ResourceType::A {
            self.resolver.on_addr(&host_key, IpAddr::V4(r.addr()));
          }
        }
        Vec::new()
      }
      Step::Aaaa(host_key) => {
        if let Ok(r) = AaaaRecord::try_from_rdata(answer.rdata_slice()) {
          if answer.rtype() == ResourceType::Aaaa {
            self.resolver.on_addr(&host_key, IpAddr::V6(r.addr()));
          }
        }
        Vec::new()
      }
    }
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
    q.dropped = self.resolver.dropped;
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
/// out. Resolution is driven by a spawned [`LookupDriver`] task, so it proceeds
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
fn fold(name: &Name) -> String {
  name.as_str().to_ascii_lowercase()
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
  let ptr = PtrRecord::try_from_message(rdata, 0, rdata.len()).ok()?;
  name_from_ref(ptr.target())
}

/// Parse an SRV rdata slice into `(target host, port)`.
fn parse_srv(rdata: &[u8]) -> Option<(Name, u16)> {
  let srv = SrvRecord::try_from_message(rdata, 0, rdata.len()).ok()?;
  let host = name_from_ref(srv.target())?;
  Some((host, srv.port()))
}

/// Parse a TXT rdata slice into its segments (dropping a malformed tail).
fn parse_txt(rdata: &[u8]) -> Vec<Vec<u8>> {
  TxtRecord::from_rdata(rdata)
    .segments()
    .map_while(Result::ok)
    .map(<[u8]>::to_vec)
    .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::*;

  /// Encode a single label sequence as a decompressed wire-form name.
  fn wire_name(labels: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for l in labels {
      out.push(u8::try_from(l.len()).unwrap());
      out.extend_from_slice(l);
    }
    out.push(0);
    out
  }

  fn ptr_rdata(labels: &[&[u8]]) -> Vec<u8> {
    wire_name(labels)
  }

  fn srv_rdata(port: u16, host: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_be_bytes()); // priority
    out.extend_from_slice(&0u16.to_be_bytes()); // weight
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&wire_name(host));
    out
  }

  #[test]
  fn name_reconstruction_rejects_unrepresentable_labels() {
    // Plain ASCII labels round-trip (case-folded).
    assert_eq!(
      parse_name(&ptr_rdata(&[b"MyPrinter", b"_ipp", b"_tcp", b"local"]))
        .unwrap()
        .as_str(),
      "myprinter._ipp._tcp.local."
    );
    // A label containing a literal '.' cannot be represented — skip it.
    assert!(parse_name(&ptr_rdata(&[b"weird.name", b"_tcp", b"local"])).is_none());
    // A non-ASCII (UTF-8) label cannot round-trip through `Name` — skip it.
    assert!(parse_name(&ptr_rdata(&[b"caf\xc3\xa9", b"local"])).is_none());
  }

  #[test]
  fn flood_is_capped_and_observable() {
    let mut r = Resolver::new(2);
    let mk = |n: &str| Name::try_from_str(n).unwrap();
    assert_eq!(r.on_ptr(mk("a._x._tcp.local.")).len(), 2); // SRV + TXT
    assert_eq!(r.on_ptr(mk("b._x._tcp.local.")).len(), 2);
    // Third instance is over the cap: no follow-ups, counted as dropped.
    assert!(r.on_ptr(mk("c._x._tcp.local.")).is_empty());
    assert_eq!(r.builders.len(), 2);
    assert_eq!(r.dropped, 1);
    // A duplicate of an existing instance is ignored without counting a drop.
    assert!(r.on_ptr(mk("a._x._tcp.local.")).is_empty());
    assert_eq!(r.dropped, 1);
  }

  #[test]
  fn shared_host_srv_after_a_still_resolves() {
    // Two instances share one host. The host's A answer arrives BEFORE the
    // second instance's SRV — the second instance must still pick up the
    // address from the host cache and complete.
    let mut r = Resolver::new(16);
    let i1 = Name::try_from_str("i1._x._tcp.local.").unwrap();
    let i2 = Name::try_from_str("i2._x._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let k1 = fold(&i1);
    let k2 = fold(&i2);
    let hk = fold(&host);

    r.on_ptr(i1);
    r.on_ptr(i2);
    // i1 resolves: host + port, then its host gets an address.
    r.on_srv(&k1, host.clone(), 8080);
    r.on_txt(&k1, vec![b"a=1".to_vec()]);
    r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    // i1 is now complete.
    let first = r.take_ready().expect("i1 should complete");
    assert_eq!(first.instance_name().as_str(), "i1._x._tcp.local.");
    assert_eq!(first.ipv4_addresses(), [Ipv4Addr::new(10, 0, 0, 1)]);

    // i2's SRV arrives AFTER the A answer. It must adopt the cached address.
    r.on_srv(&k2, host, 8081);
    r.on_txt(&k2, vec![b"b=2".to_vec()]);
    let second = r
      .take_ready()
      .expect("i2 should complete from the host cache");
    assert_eq!(second.instance_name().as_str(), "i2._x._tcp.local.");
    assert_eq!(second.port(), 8081);
    assert_eq!(second.ipv4_addresses(), [Ipv4Addr::new(10, 0, 0, 1)]);
  }

  #[test]
  fn srv_parse_extracts_host_and_port() {
    let (host, port) = parse_srv(&srv_rdata(631, &[b"printer", b"local"])).unwrap();
    assert_eq!(host.as_str(), "printer.local.");
    assert_eq!(port, 631);
  }

  #[test]
  fn entry_incomplete_without_address_or_port_or_txt() {
    let mut r = Resolver::new(16);
    let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let k = fold(&inst);
    let hk = fold(&host);
    r.on_ptr(inst);
    // Only an address + port, no TXT yet → not complete.
    r.on_srv(&k, host, 9000);
    r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    assert!(r.take_ready().is_none(), "must not emit without TXT");
    // TXT arrives → now complete.
    r.on_txt(&k, vec![Vec::new()]); // empty TXT (single empty segment) counts
    assert!(r.take_ready().is_some(), "complete once TXT present");
  }

  #[test]
  fn address_fans_out_to_all_instances_on_shared_host() {
    // Three instances share one host; the host's single A answer must complete
    // all of them (each already had SRV + TXT).
    let mut r = Resolver::new(16);
    let host = Name::try_from_str("h.local.").unwrap();
    let hk = fold(&host);
    for label in ["i1", "i2", "i3"] {
      let inst = Name::try_from_str(&format!("{label}._x._tcp.local.")).unwrap();
      let k = fold(&inst);
      r.on_ptr(inst);
      r.on_srv(&k, host.clone(), 7000);
      r.on_txt(&k, vec![b"k=v".to_vec()]);
    }
    assert!(
      r.take_ready().is_none(),
      "incomplete until an address arrives"
    );
    r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let mut emitted = HashSet::new();
    while let Some(e) = r.take_ready() {
      assert_eq!(e.ipv4_addresses(), [Ipv4Addr::new(192, 0, 2, 1)]);
      emitted.insert(e.instance_name().as_str().to_owned());
    }
    assert_eq!(emitted.len(), 3, "all three shared-host instances resolve");
  }

  #[test]
  fn late_address_reemits_updated_entry() {
    // An entry first surfaces on its A address; a later AAAA re-emits it with
    // the fuller address set rather than being dropped.
    let mut r = Resolver::new(16);
    let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let k = fold(&inst);
    let hk = fold(&host);
    r.on_ptr(inst);
    r.on_srv(&k, host, 7000);
    r.on_txt(&k, vec![b"k=v".to_vec()]);
    r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let first = r.take_ready().expect("first emit on A");
    assert_eq!(first.ipv4_addresses().len(), 1);
    assert!(first.ipv6_addresses().is_empty());
    // Late AAAA → re-emit with both families.
    r.on_addr(&hk, IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
    let second = r.take_ready().expect("re-emit on late AAAA");
    assert_eq!(second.ipv4_addresses().len(), 1);
    assert_eq!(second.ipv6_addresses().len(), 1);
    // A duplicate address must NOT re-emit again.
    r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert!(
      r.take_ready().is_none(),
      "duplicate address must not re-emit"
    );
  }

  #[test]
  fn addresses_capped_per_host() {
    // A responder flooding distinct A records for one host cannot grow the
    // address vector past MAX_ADDRS_PER_HOST.
    let mut r = Resolver::new(16);
    let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let k = fold(&inst);
    let hk = fold(&host);
    r.on_ptr(inst);
    r.on_srv(&k, host, 7000);
    r.on_txt(&k, vec![b"k=v".to_vec()]);
    for i in 0..(MAX_ADDRS_PER_HOST as u32 + 8) {
      let o = i.to_be_bytes();
      r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(10, o[1], o[2], o[3])));
    }
    let mut last = None;
    while let Some(e) = r.take_ready() {
      last = Some(e);
    }
    assert_eq!(
      last.expect("at least one emit").ipv4_addresses().len(),
      MAX_ADDRS_PER_HOST
    );
  }

  #[test]
  fn srv_target_flood_is_capped() {
    // One instance whose SRV target host changes on every answer (a hostile or
    // pathological responder) must not grow the host-query set without bound.
    let mut r = Resolver::new(4); // max_hosts == max_entries == 4
    let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
    let k = fold(&inst);
    r.on_ptr(inst);
    let mut launched = 0usize;
    for i in 0..20u16 {
      let host = Name::try_from_str(&format!("h{i}.local.")).unwrap();
      launched += r.on_srv(&k, host, 8000 + i).len();
    }
    // At most max_hosts distinct hosts get A+AAAA launches (2 starts each).
    assert_eq!(r.hosts_queried.len(), 4);
    assert_eq!(r.host_addrs.len(), 0, "no addresses arrived yet");
    assert_eq!(launched, 4 * 2);
    // The 16 over-cap target hosts are counted so the partial view is observable.
    assert_eq!(r.dropped, 16);
  }

  #[test]
  fn srv_retarget_drops_old_host_addresses() {
    // An instance first resolves on host h1 (address A1). A later SRV retargets
    // it to host h2; once h2's address arrives, the re-emitted entry must carry
    // h2 and ONLY h2's address — never the stale h1 address.
    let mut r = Resolver::new(16);
    let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
    let h1 = Name::try_from_str("h1.local.").unwrap();
    let h2 = Name::try_from_str("h2.local.").unwrap();
    let k = fold(&inst);
    let hk1 = fold(&h1);
    let hk2 = fold(&h2);
    r.on_ptr(inst);
    r.on_srv(&k, h1, 8000);
    r.on_txt(&k, vec![b"k=v".to_vec()]);
    r.on_addr(&hk1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let first = r.take_ready().expect("resolves on h1");
    assert_eq!(first.host().as_str(), "h1.local.");
    assert_eq!(first.ipv4_addresses(), [Ipv4Addr::new(10, 0, 0, 1)]);

    // Retarget to h2; the old h1 address must be dropped immediately.
    r.on_srv(&k, h2, 8000);
    // h2's address arrives → re-emit with h2 and only the h2 address.
    r.on_addr(&hk2, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let second = r.take_ready().expect("re-emits on h2 address");
    assert_eq!(second.host().as_str(), "h2.local.");
    assert_eq!(
      second.ipv4_addresses(),
      [Ipv4Addr::new(10, 0, 0, 2)],
      "stale h1 address must not survive the retarget"
    );
  }

  #[test]
  fn txt_change_after_emit_reemits() {
    // A TXT update after the instance was surfaced must re-emit with the new
    // metadata (a responder may refresh TXT while the lookup is still running);
    // a duplicate TXT must not.
    let mut r = Resolver::new(16);
    let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
    let host = Name::try_from_str("h.local.").unwrap();
    let k = fold(&inst);
    let hk = fold(&host);
    r.on_ptr(inst);
    r.on_srv(&k, host, 7000);
    r.on_txt(&k, vec![b"v=1".to_vec()]);
    r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let first = r.take_ready().expect("first emit");
    assert_eq!(first.txt(), [b"v=1".to_vec()]);
    // Changed TXT → re-emit with the new metadata.
    r.on_txt(&k, vec![b"v=2".to_vec()]);
    let second = r.take_ready().expect("re-emit on TXT change");
    assert_eq!(second.txt(), [b"v=2".to_vec()]);
    // Duplicate TXT → no re-emit.
    r.on_txt(&k, vec![b"v=2".to_vec()]);
    assert!(r.take_ready().is_none(), "duplicate TXT must not re-emit");
  }

  #[test]
  fn srv_retarget_to_cached_host_reemits() {
    // An already-emitted instance retargets to a host whose addresses are
    // ALREADY cached (shared with another instance). No fresh A/AAAA event will
    // arrive, so the SRV change itself must re-emit the new host/port + adopted
    // address rather than leaving the consumer with a stale entry.
    let mut r = Resolver::new(16);
    let i1 = Name::try_from_str("i1._x._tcp.local.").unwrap();
    let i2 = Name::try_from_str("i2._x._tcp.local.").unwrap();
    let shared = Name::try_from_str("shared.local.").unwrap();
    let other = Name::try_from_str("other.local.").unwrap();
    let k1 = fold(&i1);
    let k2 = fold(&i2);
    let shk = fold(&shared);
    let ohk = fold(&other);

    // i1 resolves on `shared`, populating the host-address cache.
    r.on_ptr(i1);
    r.on_srv(&k1, shared.clone(), 8000);
    r.on_txt(&k1, vec![b"a=1".to_vec()]);
    r.on_addr(&shk, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
    r.take_ready().expect("i1 resolves on shared");

    // i2 first resolves on a DIFFERENT host.
    r.on_ptr(i2);
    r.on_srv(&k2, other, 9000);
    r.on_txt(&k2, vec![b"b=2".to_vec()]);
    r.on_addr(&ohk, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)));
    let i2_first = r.take_ready().expect("i2 resolves on other");
    assert_eq!(i2_first.host().as_str(), "other.local.");

    // i2's SRV now retargets to `shared` (already cached, already queried).
    let starts = r.on_srv(&k2, shared, 9001);
    assert!(
      starts.is_empty(),
      "shared host already queried — no new A/AAAA launched"
    );
    let i2_re = r
      .take_ready()
      .expect("i2 must re-emit on the cached host without a fresh address event");
    assert_eq!(i2_re.host().as_str(), "shared.local.");
    assert_eq!(i2_re.port(), 9001);
    assert_eq!(
      i2_re.ipv4_addresses(),
      [Ipv4Addr::new(10, 0, 0, 9)],
      "adopts the shared host's cached address, not the stale one"
    );
  }

  #[test]
  fn srv_txt_mutation_after_emit_stays_bounded() {
    // After an instance is surfaced, further SRV/TXT answers (new target hosts,
    // changed metadata) must not grow the host-query set past the cap or panic.
    let mut r = Resolver::new(2); // max_hosts == 2
    let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
    let h1 = Name::try_from_str("h1.local.").unwrap();
    let k = fold(&inst);
    let hk1 = fold(&h1);
    r.on_ptr(inst);
    r.on_srv(&k, h1, 8000);
    r.on_txt(&k, vec![b"k=v".to_vec()]);
    r.on_addr(&hk1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert!(r.take_ready().is_some(), "instance completes on h1");

    // SRV now mutates to a flood of new target hosts, and TXT keeps changing.
    for i in 0..10u16 {
      let h = Name::try_from_str(&format!("m{i}.local.")).unwrap();
      r.on_srv(&k, h, 9000 + i);
      r.on_txt(&k, vec![format!("v={i}").into_bytes()]);
    }
    // h1 took one host slot; at most one more (cap 2) is ever queried.
    assert!(r.hosts_queried.len() <= 2, "host set stays bounded");
    assert!(r.host_addrs.len() <= 2, "host cache stays bounded");
  }
}

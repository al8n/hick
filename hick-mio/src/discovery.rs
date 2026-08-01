//! DNS-SD service discovery — browse a service type and resolve each instance
//! into a fully-populated [`ServiceEntry`].
//!
//! A lookup performs the RFC 6763 browse → resolve chain:
//!
//! 1. **Browse** (§4.1): a PTR query for the service type
//!    (`_service._proto.local.`) yields the names of the published instances.
//! 2. **Resolve** (§5): for each instance, an SRV query gives the target host
//!    and port and a TXT query gives the metadata.
//! 3. **Address** (§5): A / AAAA queries against the SRV target host give the
//!    reachable addresses.
//!
//! An instance surfaces as an [`Event::Lookup`] once it has a port (SRV), TXT
//! data, and at least one address; [`Event::LookupDone`] ends the lookup at its
//! deadline, once [`QueryParam::with_max_entries`] instances have surfaced, or
//! once every sub-query has terminated.
//!
//! # Why this is so much smaller than `hick-reactor`'s
//!
//! `hick-reactor/src/discovery.rs` needs a spawned `LookupDriver` task, a shared
//! `LookupQueue`, a mailbox/doorbell split, and a `SelectAll` over sub-query
//! streams, because its sub-queries are independently-polled async streams that
//! must be drained even when the consumer is not awaiting. Here
//! [`Mdns::tick`](crate::Mdns::tick) already owns everything and runs to
//! completion on every loop iteration, so all of that collapses into one
//! aggregation state machine ([`LookupCtx`]) advanced as `tick`'s stage 6. The
//! chain semantics and the completeness rule are the sibling's; none of its
//! concurrency machinery is.
//!
//! # Sub-query ownership
//!
//! A lookup owns its PTR/SRV/TXT/A/AAAA sub-queries, and **their answers must
//! never reach the caller as [`Event::QueryAnswer`]** for handles the caller
//! never asked for. Ownership is recorded on the query context itself:
//! [`QueryCtx::owner`] is `Some(LookupHandle)` for a sub-query and `None` for a
//! query the caller started through
//! [`Mdns::start_query`](crate::Mdns::start_query).
//!
//! One map, one flag, and the split is a single branch in each of the two places
//! a query becomes a caller-visible event — `push_updates` and the encode-error
//! retirement inside `drain_transmits`. Every *other* pipeline stage (sweep,
//! deadline firing, the transmit drain) keeps driving both kinds identically,
//! which is what stops a sub-query from silently not transmitting.
//!
//! Instance/host names that the [`Name`] type cannot represent faithfully — a
//! label containing a `.` or a non-ASCII byte — are skipped rather than silently
//! corrupted (`Name` is an ASCII, dot-separated, no-escaping type).

use std::{
  collections::{HashMap, HashSet, VecDeque},
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  time::{Duration, Instant as StdInstant},
};

use bytes::Bytes;
use mdns_proto::{
  CollectedAnswer, Name, QueryHandle, QuerySpec,
  wire::{A, AAAA, NameRef, Ptr, ResourceType, Srv, Txt},
};
use slab::Slab;
use smol_str::SmolStr;

use crate::{
  endpoint::{Mdns, QueryCtx},
  error::StartQueryError,
  event::Event,
  proto::ProtoEndpoint,
};

/// Default cap on the number of distinct instances one lookup tracks, so a
/// chatty or hostile responder flooding PTR answers cannot grow the partial map
/// or the in-flight sub-query set without bound.
pub const DEFAULT_MAX_ENTRIES: usize = 64;

/// Cap on the addresses kept per host per family (and per instance), so a
/// responder flooding distinct A/AAAA records for one host cannot grow the
/// address vectors without bound.
const MAX_ADDRS_PER_HOST: usize = 16;

/// A resolved DNS-SD service instance, delivered as [`Event::Lookup`].
///
/// Produced once the instance has an SRV (host + port), TXT data, and at least
/// one address. Each instance is reported **once** per lookup: unlike
/// `hick-reactor`'s streaming `Lookup`, there is no re-emission with a fuller
/// address set, so a caller sees the snapshot as of the moment the instance
/// first became complete.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
  instance: Name,
  host: Name,
  port: u16,
  ipv4: Box<[Ipv4Addr]>,
  ipv6: Box<[Ipv6Addr]>,
  txt: Box<[Bytes]>,
}

impl ServiceEntry {
  /// The fully-qualified service instance name (the PTR target), e.g.
  /// `myprinter._ipp._tcp.local.`.
  ///
  /// For a [`Mdns::resolve_host`] lookup there is no DNS-SD instance, so this is
  /// the host that was resolved.
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
  ///
  /// `0` for a [`Mdns::resolve_host`] lookup, which asks no SRV question.
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
  /// service with no metadata has a single empty segment (RFC 6763 §6.1); a
  /// [`Mdns::resolve_host`] lookup, which asks no TXT question, has none at all.
  #[inline]
  pub fn txt(&self) -> &[Bytes] {
    &self.txt
  }
}

/// Parameters for a browse ([`Mdns::browse`]).
#[derive(Debug, Clone)]
pub struct QueryParam {
  service: Name,
  timeout: Duration,
  max_entries: usize,
}

impl QueryParam {
  /// Browse the given fully-qualified service type, e.g.
  /// `Name::try_from_str("_ipp._tcp.local.")`.
  pub fn new(service: Name) -> Self {
    Self {
      service,
      timeout: Duration::from_secs(1),
      max_entries: DEFAULT_MAX_ENTRIES,
    }
  }

  /// How long the lookup runs before [`Event::LookupDone`] ends it.
  ///
  /// The same budget bounds every sub-query: a resolve started part-way through
  /// gets the **remaining** time, never a fresh full window, so the whole lookup
  /// stays inside this deadline.
  ///
  /// A timeout so large that `Instant::now() + timeout` overflows means *no*
  /// effective deadline, here and on every sub-query. Such a lookup ends only
  /// when its sub-queries do, or when the caller calls
  /// [`Mdns::cancel_lookup`] — it is not silently clamped.
  #[must_use]
  pub const fn with_timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  /// Cap on the number of distinct instances tracked; instances discovered
  /// beyond it are dropped. Defaults to [`DEFAULT_MAX_ENTRIES`]. A value of `0`
  /// is treated as `1`.
  ///
  /// Also the cap on distinct SRV *target hosts* the lookup will address-query,
  /// which is what bounds an instance that floods distinct SRV targets. Honest
  /// browsing has at most one host per instance, so it never bites a real
  /// responder.
  #[must_use]
  pub const fn with_max_entries(mut self, max: usize) -> Self {
    self.max_entries = if max == 0 { 1 } else { max };
    self
  }

  /// The service type this browse asks for.
  #[inline]
  pub const fn service(&self) -> &Name {
    &self.service
  }

  /// How long the lookup runs. See [`Self::with_timeout`].
  #[inline]
  pub const fn timeout(&self) -> Duration {
    self.timeout
  }

  /// The distinct-instance cap. See [`Self::with_max_entries`].
  #[inline]
  pub const fn max_entries(&self) -> usize {
    self.max_entries
  }
}

/// Identifies one running lookup, minted by [`Mdns::browse`] and friends.
///
/// **A stale handle is inert, never an alias.** A lookup's slab slot is freed
/// when it reports [`Event::LookupDone`] or is passed to
/// [`Mdns::cancel_lookup`], and the next lookup may well be minted onto that
/// same slot — so the handle pairs the slot with a `generation` tag that tells
/// its occupants apart, and every method that resolves one checks both. Holding
/// a handle past its terminal is therefore harmless: it addresses nothing,
/// exactly like a stale [`mdns_proto::QueryHandle`].
///
/// Opaque and [`Copy`]; compare handles for equality, do not read them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LookupHandle {
  /// The lookup slab slot.
  key: usize,
  /// Which occupant of `key` this handle names. Minted once per lookup from
  /// [`Lookups::next_generation`], which is what distinguishes this lookup from
  /// every other one that occupies the same slot; see that field for the
  /// wrap-around bound.
  generation: u64,
}

/// Which resolve step an answer belongs to. The string is the case-folded key of
/// the owning instance (SRV/TXT) or host (A/AAAA).
#[derive(Debug, Clone)]
enum Step {
  Ptr,
  Srv(SmolStr),
  Txt(SmolStr),
  A(SmolStr),
  /// The AAAA step. Spelled in mixed case so the enum needs no
  /// `clippy::upper_case_acronyms` exemption.
  Aaaa(SmolStr),
}

impl Step {
  fn qtype(&self) -> ResourceType {
    match self {
      Self::Ptr => ResourceType::Ptr,
      Self::Srv(_) => ResourceType::Srv,
      Self::Txt(_) => ResourceType::Txt,
      Self::A(_) => ResourceType::A,
      Self::Aaaa(_) => ResourceType::AAAA,
    }
  }
}

/// A follow-up sub-query the aggregation asked for, waiting to be started.
#[derive(Debug)]
struct Start {
  name: Name,
  step: Step,
}

/// In-progress aggregation of one service instance.
#[derive(Debug, Default)]
struct PartialEntry {
  /// The DNS-SD instance name, or `None` for a [`Mdns::resolve_host`] partial,
  /// which has no instance identity — the SRV target host is its identity
  /// instead. Only [`Self::take_complete`] resolves that fallback, so an
  /// instance discovered by PTR always keeps its own name.
  instance: Option<Name>,
  host: Option<Name>,
  /// Case-folded `host`, so an A/AAAA answer can find every partial on that host.
  host_key: Option<SmolStr>,
  /// Whether an SRV record has been seen. Tracked separately from `port`
  /// because `0` is a valid SRV port, so it cannot double as a sentinel.
  has_srv: bool,
  port: u16,
  ipv4: Vec<Ipv4Addr>,
  ipv6: Vec<Ipv6Addr>,
  txt: Option<Vec<Bytes>>,
  emitted: bool,
}

impl PartialEntry {
  /// A partial for an instance discovered by PTR.
  fn new(instance: Name) -> Self {
    Self {
      instance: Some(instance),
      ..Self::default()
    }
  }

  /// Record the SRV host and port.
  ///
  /// SRV retargeting the instance to a **different** host invalidates the old
  /// host's addresses, so they are dropped before the new host's are adopted: an
  /// entry must never carry the new target's name with the old target's
  /// addresses.
  fn set_srv(&mut self, host: Name, port: u16) {
    let key = fold(&host);
    if self.host_key.as_deref() != Some(key.as_str()) {
      self.ipv4.clear();
      self.ipv6.clear();
    }
    self.has_srv = true;
    self.host_key = Some(key);
    self.host = Some(host);
    self.port = port;
  }

  fn set_txt(&mut self, segments: Vec<Bytes>) {
    self.txt = Some(segments);
  }

  fn add_v4(&mut self, addr: Ipv4Addr) {
    push_capped(&mut self.ipv4, addr);
  }

  fn add_v6(&mut self, addr: Ipv6Addr) {
    push_capped(&mut self.ipv6, addr);
  }

  /// The completeness rule: an SRV (host + port), TXT data, and at least one
  /// address. Yields the entry the first time all three hold and `None` ever
  /// after, so one instance is reported exactly once.
  fn take_complete(&mut self) -> Option<ServiceEntry> {
    if self.emitted || !self.has_srv || self.txt.is_none() {
      return None;
    }
    if self.ipv4.is_empty() && self.ipv6.is_empty() {
      return None;
    }
    let host = self.host.clone()?;
    let instance = self.instance.clone().unwrap_or_else(|| host.clone());
    let txt: Box<[Bytes]> = self.txt.as_deref().unwrap_or(&[]).into();
    let ipv4: Box<[Ipv4Addr]> = self.ipv4.as_slice().into();
    let ipv6: Box<[Ipv6Addr]> = self.ipv6.as_slice().into();
    self.emitted = true;
    Some(ServiceEntry {
      instance,
      host,
      port: self.port,
      ipv4,
      ipv6,
      txt,
    })
  }
}

/// Addresses already learned for a host, so a later instance whose SRV resolves
/// to the same host picks them up even though the A/AAAA answer has come and
/// gone (the shared-host, SRV-after-A ordering).
#[derive(Debug, Default)]
struct HostAddrs {
  ipv4: Vec<Ipv4Addr>,
  ipv6: Vec<Ipv6Addr>,
}

/// One running lookup: the browse/resolve aggregation state machine plus the
/// sub-queries it owns. Pure apart from the sub-query handles — it starts
/// nothing itself, it only *asks* (via [`Self::pending`]), which is what makes
/// the whole chain testable without binding a socket.
#[derive(Debug)]
pub(crate) struct LookupCtx {
  /// Which occupant of this slab slot the context is — stamped by
  /// [`Lookups::insert`], which is the only thing that mints a
  /// [`LookupHandle`]. The `0` [`Self::new`] leaves here is a placeholder that
  /// never escapes: a context not in the slab has no handle to be confused with.
  generation: u64,
  /// When [`Event::LookupDone`] is due. `None` only if the requested timeout
  /// overflows [`StdInstant`], which means "no effective deadline".
  deadline: Option<StdInstant>,
  /// The requested timeout, the fallback budget for a sub-query started when
  /// there is no deadline to measure the remainder against.
  timeout: Duration,
  /// Cap on distinct instances tracked, and on distinct hosts address-queried.
  max_entries: usize,
  /// Instances reported so far. Reaching `max_entries` ends the lookup.
  emitted: usize,
  /// Sub-queries started so far, so a lookup that has not started any yet is not
  /// mistaken for one whose sub-queries have all ended.
  launched: usize,
  /// Case-folded instance key → aggregation state.
  partials: HashMap<SmolStr, PartialEntry>,
  /// Case-folded host key → addresses learned for it.
  host_addrs: HashMap<SmolStr, HostAddrs>,
  /// Hosts already A/AAAA-queried, capped at `max_entries`.
  hosts_queried: HashSet<SmolStr>,
  /// The sub-queries this lookup owns, and which step each one serves.
  subqueries: HashMap<QueryHandle, Step>,
  /// Follow-up sub-queries the aggregation asked for, drained by the driver.
  pending: Vec<Start>,
  /// Completed instances waiting to be pushed onto the event queue.
  ready: VecDeque<ServiceEntry>,
}

impl LookupCtx {
  fn new(param: QueryParam, now: StdInstant) -> Self {
    Self {
      generation: 0,
      // `checked_add` so a pathological timeout (e.g. `Duration::MAX`) cannot
      // panic the way `Instant + Duration` would; an overflow means "no
      // effective deadline", and the lookup then ends when its sub-queries do.
      deadline: now.checked_add(param.timeout),
      timeout: param.timeout,
      max_entries: param.max_entries,
      emitted: 0,
      launched: 0,
      partials: HashMap::new(),
      host_addrs: HashMap::new(),
      hosts_queried: HashSet::new(),
      subqueries: HashMap::new(),
      pending: Vec::new(),
      ready: VecDeque::new(),
    }
  }

  /// When this lookup must be woken, for [`Mdns::next_timeout`] to fold in.
  const fn deadline(&self) -> Option<StdInstant> {
    self.deadline
  }

  /// The budget for a sub-query started now: what is left of the lookup's own
  /// deadline, never a fresh full window.
  fn remaining(&self, now: StdInstant) -> Duration {
    self
      .deadline
      .map_or(self.timeout, |d| d.saturating_duration_since(now))
  }

  /// Seed a bare host resolve: one partial whose SRV is synthetic (the queried
  /// host, port `0`) and whose TXT is empty, so the completeness rule reduces to
  /// "at least one address", plus the A/AAAA sub-queries for it.
  fn seed_host(&mut self, host: Name) {
    let key = fold(&host);
    let mut partial = PartialEntry::default();
    partial.set_srv(host.clone(), 0);
    partial.set_txt(Vec::new());
    self.partials.insert(key.clone(), partial);
    self.hosts_queried.insert(key.clone());
    self.pending.push(Start {
      name: host.clone(),
      step: Step::A(key.clone()),
    });
    self.pending.push(Start {
      name: host,
      step: Step::Aaaa(key),
    });
  }

  /// A newly discovered instance: track it (subject to the cap) and ask for its
  /// SRV + TXT resolves.
  fn on_ptr(&mut self, instance: Name) {
    let key = fold(&instance);
    if self.partials.contains_key(&key) {
      return; // already discovered
    }
    if self.partials.len() >= self.max_entries {
      hick_trace::debug!("a lookup refused an instance past its max_entries cap");
      return;
    }
    self
      .partials
      .insert(key.clone(), PartialEntry::new(instance.clone()));
    self.pending.push(Start {
      name: instance.clone(),
      step: Step::Srv(key.clone()),
    });
    self.pending.push(Start {
      name: instance,
      step: Step::Txt(key),
    });
  }

  /// An instance's SRV: record host + port, adopt any addresses already learned
  /// for that host, and ask for A/AAAA the first time we see the host — subject
  /// to the distinct-host cap, which bounds an SRV-target flood.
  fn on_srv(&mut self, inst_key: &str, host: Name, port: u16) {
    let host_key = fold(&host);
    // The lookup cannot miss: a `Step::Srv` key is minted only by `on_ptr`, for
    // an instance it has just inserted, and a partial is never removed. Asserted
    // so a reader does not conclude an *untracked* instance can reach here; the
    // `if let` is the release-build fallback, not an expected path.
    debug_assert!(
      self.partials.contains_key(inst_key),
      "on_srv reached with an instance key `on_ptr` never tracked"
    );
    if let Some(partial) = self.partials.get_mut(inst_key) {
      partial.set_srv(host.clone(), port);
      if let Some(cached) = self.host_addrs.get(&host_key) {
        for &addr in &cached.ipv4 {
          partial.add_v4(addr);
        }
        for &addr in &cached.ipv6 {
          partial.add_v6(addr);
        }
      }
    }
    if self.hosts_queried.contains(&host_key) {
      return; // already querying this host
    }
    if self.hosts_queried.len() >= self.max_entries {
      hick_trace::debug!("a lookup refused an SRV target past its distinct-host cap");
      return;
    }
    self.hosts_queried.insert(host_key.clone());
    self.pending.push(Start {
      name: host.clone(),
      step: Step::A(host_key.clone()),
    });
    self.pending.push(Start {
      name: host,
      step: Step::Aaaa(host_key),
    });
  }

  fn on_txt(&mut self, inst_key: &str, segments: Vec<Bytes>) {
    // Same invariant as `on_srv`: a `Step::Txt` key names a tracked instance.
    debug_assert!(
      self.partials.contains_key(inst_key),
      "on_txt reached with an instance key `on_ptr` never tracked"
    );
    if let Some(partial) = self.partials.get_mut(inst_key) {
      partial.set_txt(segments);
    }
  }

  /// An A/AAAA answer for a host: cache it (capped) and apply it to every
  /// partial whose SRV already pointed at that host.
  ///
  /// Only reached for a host we actually launched A/AAAA queries for, so
  /// `host_addrs` stays bounded by `hosts_queried`.
  fn on_addr(&mut self, host_key: &str, addr: IpAddr) {
    let cached = self.host_addrs.entry(SmolStr::from(host_key)).or_default();
    match addr {
      IpAddr::V4(a) => push_capped(&mut cached.ipv4, a),
      IpAddr::V6(a) => push_capped(&mut cached.ipv6, a),
    }
    for partial in self
      .partials
      .values_mut()
      .filter(|p| p.host_key.as_deref() == Some(host_key))
    {
      match addr {
        IpAddr::V4(a) => partial.add_v4(a),
        IpAddr::V6(a) => partial.add_v6(a),
      }
    }
  }

  /// Fold one sub-query answer into the aggregation.
  ///
  /// The resource type is re-checked against the step even though the proto
  /// layer only collects answers matching the question, so a responder cannot
  /// steer an answer into the wrong parser.
  fn feed(&mut self, step: &Step, answer: &CollectedAnswer) {
    match step {
      Step::Ptr => {
        if answer.rtype() == ResourceType::Ptr
          && let Some(instance) = parse_name(answer.rdata_slice())
        {
          self.on_ptr(instance);
        }
      }
      Step::Srv(inst_key) => {
        if answer.rtype() == ResourceType::Srv
          && let Some((host, port)) = parse_srv(answer.rdata_slice())
        {
          self.on_srv(inst_key, host, port);
        }
      }
      Step::Txt(inst_key) => {
        if answer.rtype() == ResourceType::Txt {
          self.on_txt(inst_key, parse_txt(answer.rdata_slice()));
        }
      }
      Step::A(host_key) => {
        if answer.rtype() == ResourceType::A
          && let Ok(record) = A::try_from_rdata(answer.rdata_slice())
        {
          self.on_addr(host_key, IpAddr::V4(record.addr()));
        }
      }
      Step::Aaaa(host_key) => {
        if answer.rtype() == ResourceType::AAAA
          && let Ok(record) = AAAA::try_from_rdata(answer.rdata_slice())
        {
          self.on_addr(host_key, IpAddr::V6(record.addr()));
        }
      }
    }
  }

  /// Move every newly-complete instance into the ready queue, counting it
  /// against [`QueryParam::with_max_entries`].
  fn collect_ready(&mut self) {
    let Self {
      partials,
      ready,
      emitted,
      ..
    } = self;
    for partial in partials.values_mut() {
      if let Some(entry) = partial.take_complete() {
        *emitted = emitted.saturating_add(1);
        ready.push_back(entry);
      }
    }
  }

  fn take_ready(&mut self) -> Option<ServiceEntry> {
    self.ready.pop_front()
  }

  /// Whether the lookup is over: the entry cap reached, the deadline due, or
  /// every sub-query it ever started has terminated with none left to start.
  ///
  /// The `launched` term is what keeps a lookup that has not started its first
  /// sub-query yet from being mistaken for one whose sub-queries have all ended.
  fn is_finished(&self, now: StdInstant) -> bool {
    if self.emitted >= self.max_entries {
      return true;
    }
    if self.deadline.is_some_and(|d| now >= d) {
      return true;
    }
    self.launched > 0 && self.subqueries.is_empty() && self.pending.is_empty()
  }
}

/// Every running lookup, plus the scratch the aggregation stage reuses so a
/// steady-state tick allocates nothing.
#[derive(Debug, Default)]
pub(crate) struct Lookups {
  slab: Slab<LookupCtx>,
  /// Source of the generation tag stamped into each [`LookupHandle`]. `wrapping`
  /// rather than `saturating`: saturating would make every handle minted after
  /// the counter tops out share one generation, which is precisely the aliasing
  /// this tag exists to rule out, whereas wrapping needs the same slot to be
  /// reused exactly 2^64 lookups later to collide. `EventQueue::next_generation`
  /// (`crate::event`) is the same decision for the same reason.
  next_generation: u64,
  /// Sub-query handles of the lookup currently being advanced, snapshotted so
  /// its map can be mutated while walking it.
  handles: Vec<QueryHandle>,
  /// Lookups that finished this tick, torn down once the slab walk ends.
  finished: Vec<LookupHandle>,
}

impl Lookups {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// Install a lookup and mint the one handle that names it.
  ///
  /// The only site that constructs a [`LookupHandle`] from scratch — everything
  /// else either receives one from the caller or rebuilds it from a context
  /// already in the slab — so this is the one place a generation is minted.
  fn insert(&mut self, mut ctx: LookupCtx) -> LookupHandle {
    let generation = self.next_generation;
    self.next_generation = self.next_generation.wrapping_add(1);
    ctx.generation = generation;
    LookupHandle {
      key: self.slab.insert(ctx),
      generation,
    }
  }

  fn get_mut(&mut self, handle: LookupHandle) -> Option<&mut LookupCtx> {
    get_checked(&mut self.slab, handle)
  }

  fn remove(&mut self, handle: LookupHandle) -> Option<LookupCtx> {
    remove_checked(&mut self.slab, handle)
  }

  /// Every running lookup's deadline, for [`Mdns::next_timeout`] to fold in.
  pub(crate) fn deadlines(&self) -> impl Iterator<Item = StdInstant> + '_ {
    self.slab.iter().filter_map(|(_, ctx)| ctx.deadline())
  }

  #[cfg(test)]
  pub(crate) fn is_empty(&self) -> bool {
    self.slab.is_empty()
  }
}

/// Resolve a handle to its lookup, or `None` if the handle is stale.
///
/// **The generation check, and the only copy of it.** Every path that turns a
/// [`LookupHandle`] back into a context goes through this or
/// [`remove_checked`], so a future call site cannot resolve a handle without
/// verifying it — the same "one place" discipline as [`cancel_subqueries`].
/// A free function over the slab so the split-borrowed tick stage can use it too.
fn get_checked(slab: &mut Slab<LookupCtx>, handle: LookupHandle) -> Option<&mut LookupCtx> {
  slab
    .get_mut(handle.key)
    .filter(|ctx| ctx.generation == handle.generation)
}

/// Take a handle's lookup out of the slab, or `None` if the handle is stale.
///
/// Checks **before** removing: a stale handle must never evict the live occupant
/// of the slot it used to name.
fn remove_checked(slab: &mut Slab<LookupCtx>, handle: LookupHandle) -> Option<LookupCtx> {
  get_checked(slab, handle)?;
  slab.try_remove(handle.key)
}

impl Mdns {
  /// Browse for instances of a DNS-SD service type, resolving each into a
  /// [`ServiceEntry`].
  ///
  /// Nothing goes on the wire until the next [`tick`](Self::tick). Each resolved
  /// instance arrives as [`Event::Lookup`] and the lookup ends with exactly one
  /// [`Event::LookupDone`]; both surface through
  /// [`next_event`](Self::next_event). The sub-queries this starts are owned by
  /// the lookup — their answers and terminals are **never** reported as
  /// [`Event::QueryAnswer`] or [`Event::QueryTerminal`].
  ///
  /// # Errors
  ///
  /// [`StartQueryError::StorageFull`] when the proto query pool cannot accept
  /// the browse (PTR) query. Follow-up resolves that the pool later refuses are
  /// not an error: the lookup simply reports what it could resolve.
  ///
  /// [`StartQueryError::Other`] for a proto failure this crate does not map
  /// explicitly yet — propagated from the sub-query start, like `StorageFull`.
  pub fn browse(&mut self, param: QueryParam) -> Result<LookupHandle, StartQueryError> {
    let now = StdInstant::now();
    // Size the PTR answer pool to the requested instance cap so a `max_entries`
    // above the query's default answer cap is actually reachable, and the
    // aggregation — not the query's answer pool — is what bounds instances.
    let spec = QuerySpec::new(param.service.clone(), ResourceType::Ptr)
      .with_timeout(param.timeout)
      .with_max_answers(param.max_entries);
    let handle = self.lookups.insert(LookupCtx::new(param, now));
    match self.start_subquery(handle, spec, Step::Ptr, now) {
      Ok(()) => Ok(handle),
      Err(e) => {
        self.cancel_lookup(handle);
        Err(e)
      }
    }
  }

  /// [`browse`](Self::browse) with default parameters and the given timeout.
  ///
  /// # Errors
  ///
  /// As [`browse`](Self::browse) — both [`StartQueryError::StorageFull`] and
  /// [`StartQueryError::Other`], for the same reasons.
  pub fn lookup(
    &mut self,
    service: Name,
    timeout: Duration,
  ) -> Result<LookupHandle, StartQueryError> {
    self.browse(QueryParam::new(service).with_timeout(timeout))
  }

  /// Resolve a host name to its addresses via mDNS A / AAAA queries (RFC 6762),
  /// without the DNS-SD browse/resolve chain.
  ///
  /// Reports one [`Event::Lookup`] as soon as an address is known, then
  /// [`Event::LookupDone`]. The entry's [`ServiceEntry::host`] and
  /// [`ServiceEntry::instance_name`] are both `host`, its
  /// [`port`](ServiceEntry::port) is `0` and its [`txt`](ServiceEntry::txt) is
  /// empty — there is no SRV or TXT question in a bare host resolve.
  ///
  /// # Errors
  ///
  /// [`StartQueryError::StorageFull`] when the proto query pool cannot accept
  /// the A / AAAA queries, and [`StartQueryError::Other`] for a proto failure
  /// this crate does not map explicitly yet.
  ///
  /// **All-or-nothing on those two, unlike [`browse`](Self::browse).** `browse`
  /// starts one query and treats every later resolve as best effort, but both of
  /// this lookup's legs are started up front — so if A starts and AAAA is
  /// refused, the working A leg is cancelled too and the whole call fails,
  /// rather than returning a lookup that can only ever see one family. The
  /// deliberate trade: a partial result here would be indistinguishable from a
  /// host that genuinely has no AAAA.
  pub fn resolve_host(
    &mut self,
    host: Name,
    timeout: Duration,
  ) -> Result<LookupHandle, StartQueryError> {
    let now = StdInstant::now();
    let param = QueryParam::new(host.clone())
      .with_timeout(timeout)
      .with_max_entries(1);
    let mut ctx = LookupCtx::new(param, now);
    ctx.seed_host(host);
    self.start_seeded(ctx, now)
  }

  /// Resolve a *known* DNS-SD service instance directly into a [`ServiceEntry`],
  /// skipping the PTR browse step (e.g.
  /// `Name::try_from_str("Office._ipp._tcp.local.")`).
  ///
  /// Issues SRV + TXT for the instance and A / AAAA for the SRV target host, and
  /// reports one [`Event::Lookup`] followed by [`Event::LookupDone`]. Use
  /// [`browse`](Self::browse) instead when the instance names are not known in
  /// advance.
  ///
  /// # Errors
  ///
  /// [`StartQueryError::StorageFull`] when the proto query pool cannot accept
  /// the SRV / TXT queries, and [`StartQueryError::Other`] for a proto failure
  /// this crate does not map explicitly yet.
  ///
  /// **All-or-nothing on those two, unlike [`browse`](Self::browse)** — see
  /// [`resolve_host`](Self::resolve_host) for the reasoning. Neither SRV nor TXT
  /// alone can ever complete an instance, so a lookup missing one of them could
  /// only ever time out empty; failing the call says so immediately. The A/AAAA
  /// legs that follow are best effort, as in `browse`.
  pub fn resolve_instance(
    &mut self,
    instance: Name,
    timeout: Duration,
  ) -> Result<LookupHandle, StartQueryError> {
    let now = StdInstant::now();
    let param = QueryParam::new(instance.clone())
      .with_timeout(timeout)
      .with_max_entries(1);
    let mut ctx = LookupCtx::new(param, now);
    ctx.on_ptr(instance);
    self.start_seeded(ctx, now)
  }

  /// Stop a lookup and cancel every sub-query it owns.
  ///
  /// No [`Event::LookupDone`] is produced: the caller asked for this, so there is
  /// nothing to report back — the same contract as
  /// [`cancel_query`](Self::cancel_query). Entries already queued stay queued and
  /// are still delivered by [`next_event`](Self::next_event).
  ///
  /// Cancelling the sub-queries is the point: a leaked one would keep
  /// retransmitting its question after the caller stopped listening.
  ///
  /// Unknown and already-finished handles are accepted and ignored — but see
  /// [`LookupHandle`] on retaining one past its terminal.
  pub fn cancel_lookup(&mut self, handle: LookupHandle) {
    let Self {
      endpoint,
      queries,
      lookups,
      ..
    } = self;
    let Some(ctx) = lookups.remove(handle) else {
      return;
    };
    cancel_subqueries(endpoint, queries, &ctx);
  }

  /// Install a pre-seeded lookup and start the sub-queries it asked for,
  /// unwinding the whole lookup if any of them cannot start.
  ///
  /// Starting them here rather than leaving them to the next `tick` is what lets
  /// a pool-full failure surface synchronously to the caller instead of turning
  /// into a lookup that silently resolves nothing.
  fn start_seeded(
    &mut self,
    ctx: LookupCtx,
    now: StdInstant,
  ) -> Result<LookupHandle, StartQueryError> {
    let handle = self.lookups.insert(ctx);
    match self.launch_pending(handle, now) {
      Ok(()) => Ok(handle),
      Err(e) => {
        self.cancel_lookup(handle);
        Err(e)
      }
    }
  }

  /// Start every sub-query the aggregation has asked for.
  ///
  /// Best effort: a refused start is skipped and the rest are still attempted,
  /// so one pool-full does not silently abandon the other legs. The first error
  /// is reported for the constructors, which unwind on it.
  fn launch_pending(
    &mut self,
    owner: LookupHandle,
    now: StdInstant,
  ) -> Result<(), StartQueryError> {
    let Some(ctx) = self.lookups.get_mut(owner) else {
      return Ok(());
    };
    let remaining = ctx.remaining(now);
    let starts = core::mem::take(&mut ctx.pending);
    let mut first_err = None;
    for Start { name, step } in starts {
      let spec = QuerySpec::new(name, step.qtype()).with_timeout(remaining);
      if let Err(e) = self.start_subquery(owner, spec, step, now)
        && first_err.is_none()
      {
        first_err = Some(e);
      }
    }
    match first_err {
      Some(e) => Err(e),
      None => Ok(()),
    }
  }

  /// Start one lookup-owned sub-query.
  ///
  /// # Errors
  ///
  /// [`StartQueryError::StorageFull`] when the proto query pool refuses it, and
  /// when the owning lookup is already gone — in which case the query just
  /// started is cancelled again rather than left running unowned.
  /// [`StartQueryError::Other`] for a proto failure this crate does not map
  /// explicitly yet.
  fn start_subquery(
    &mut self,
    owner: LookupHandle,
    spec: QuerySpec,
    step: Step,
    now: StdInstant,
  ) -> Result<(), StartQueryError> {
    // `From`, never `map_err(|_| StorageFull)`: see `Mdns::start_query`.
    let sub = self.endpoint.try_start_query(spec, now)?;
    let Self {
      endpoint,
      queries,
      lookups,
      tx_queue,
      work_pending,
      ..
    } = self;
    let Some(ctx) = get_checked(&mut lookups.slab, owner) else {
      // Nothing owns it, so nothing would ever consume its answers or stop it
      // retransmitting. Unreachable in practice; free it rather than leak it.
      let _ = endpoint.cancel_query(sub);
      return Err(StartQueryError::StorageFull);
    };
    register_subquery(queries, ctx, owner, sub, step, tx_queue.join());
    // A freshly started query has a question pending immediately and no proto
    // deadline announcing it, exactly as in `start_query`.
    *work_pending = true;
    Ok(())
  }

  /// Stage 6 of [`tick`](Self::tick): advance every lookup.
  ///
  /// Runs after `push_updates`, which deliberately skips lookup-owned queries —
  /// this is the only stage that consumes their answers and terminals, so a
  /// sub-query answer has no path to the caller's event queue.
  ///
  /// # Termination
  ///
  /// No budget of its own, like `push_updates`: every loop is bounded by state
  /// the caller created or by a cap. The slab walk is bounded by the lookups the
  /// caller started; the sub-query walk by `max_entries`; the launch loop by the
  /// `pending` list, which only grows for a *new* instance (capped at
  /// `max_entries`) or a *new* host (capped the same way) and is drained here in
  /// full; and the emit loop by the entries the aggregation just produced.
  pub(crate) fn advance_lookups(&mut self, now: StdInstant) {
    let Self {
      endpoint,
      queries,
      lookups,
      events,
      tx_queue,
      work_pending,
      ..
    } = &mut *self;
    let Lookups {
      slab,
      handles,
      finished,
      // This stage never mints a handle from scratch — it rebuilds each one from
      // the context already in the slab — so it needs no generation source.
      next_generation: _,
    } = lookups;
    finished.clear();

    for (key, ctx) in slab.iter_mut() {
      // Minted from the context in front of us, so it always names this exact
      // occupant of `key` — no stale handle can enter the pipeline here.
      let handle = LookupHandle {
        key,
        generation: ctx.generation,
      };
      // A sub-query the pipeline retired (an encode failure) or swept is gone
      // from `queries`; this is where the lookup learns of it. Without the
      // reconcile the lookup would wait on a leg that can never answer.
      ctx.subqueries.retain(|sub, _| queries.contains_key(sub));

      handles.clear();
      handles.extend(ctx.subqueries.keys().copied());
      for &sub in handles.iter() {
        let Some(step) = ctx.subqueries.get(&sub).cloned() else {
          continue;
        };
        let last_seq = queries.get(&sub).map_or(0, |q| q.last_seq);
        // `collected_answers` is the proto layer's BOUNDED snapshot: its
        // `max_answers` cap evicts oldest entries before we scan, so answers
        // accepted since the last scan but no longer present were lost before
        // the aggregation could see them. Count them rather than let the
        // resulting partial view be silent.
        let accepted = endpoint.query_accepted_count(sub).unwrap_or(last_seq);
        let expected = accepted.saturating_sub(last_seq);
        if expected > 0 {
          let mut delivered = 0u64;
          for answer in endpoint
            .collected_answers(sub)
            .filter(|a| a.seq() >= last_seq)
          {
            ctx.feed(&step, answer);
            delivered = delivered.saturating_add(1);
          }
          if let Some(qctx) = queries.get_mut(&sub) {
            qctx.last_seq = accepted;
          }
          events.record_dropped(expected.saturating_sub(delivered));
        }
        // `poll_query` yields Some only at the terminal. Free the pool slot at
        // once: a terminated sub-query left resident would occupy proto storage
        // for the rest of the lookup.
        if endpoint.poll_query(sub).is_some() {
          let _ = endpoint.cancel_query(sub);
          queries.remove(&sub);
          ctx.subqueries.remove(&sub);
        }
      }

      // Start the follow-ups the answers above asked for, in the SAME tick.
      // `mem::take` first: the launch mutates `ctx.subqueries`, so nothing may
      // still borrow `ctx.pending`. A refused start is skipped rather than
      // fatal — the lookup reports what it can resolve and ends when its
      // remaining sub-queries do.
      let remaining = ctx.remaining(now);
      for Start { name, step } in core::mem::take(&mut ctx.pending) {
        let spec = QuerySpec::new(name, step.qtype()).with_timeout(remaining);
        match endpoint.try_start_query(spec, now) {
          Ok(sub) => {
            register_subquery(queries, ctx, handle, sub, step, tx_queue.join());
            *work_pending = true;
          }
          Err(_e) => {
            hick_trace::debug!("a lookup could not start a resolve sub-query: query pool is full");
          }
        }
      }

      ctx.collect_ready();
      while let Some(entry) = ctx.take_ready() {
        events.push_terminal(Event::Lookup { handle, entry });
      }

      if ctx.is_finished(now) {
        finished.push(handle);
      }
    }

    // Deliberately after the walk: `slab` cannot be mutated while it is being
    // iterated, and a finished lookup must take its sub-queries with it.
    for handle in finished.drain(..) {
      if let Some(ctx) = remove_checked(slab, handle) {
        cancel_subqueries(endpoint, queries, &ctx);
      }
      events.push_terminal(Event::LookupDone { handle });
    }
  }
}

/// Stop every sub-query a lookup owns and free its proto pool slot.
///
/// **The one place a lookup's legs are cancelled**, shared by
/// [`Mdns::cancel_lookup`] and the tick stage's teardown, so neither path can
/// leak a sub-query that keeps retransmitting its question with nothing left to
/// consume the answers. Takes the context by reference because both callers have
/// already removed it from the slab.
fn cancel_subqueries(
  endpoint: &mut ProtoEndpoint,
  queries: &mut HashMap<QueryHandle, QueryCtx>,
  ctx: &LookupCtx,
) {
  for &sub in ctx.subqueries.keys() {
    let _ = endpoint.cancel_query(sub);
    queries.remove(&sub);
  }
}

/// Record a freshly started sub-query as owned by `owner`.
///
/// **The one place [`QueryCtx::owner`] is ever set to `Some`.** A query context
/// carrying an owner is skipped by the two pipeline sites that turn a query into
/// a caller-visible event, so this single call is what keeps a lookup's answers
/// and terminals out of the caller's event queue.
///
/// A free function over the two maps it needs, so both the `&mut self`
/// constructors and the split-borrowed tick stage can use it.
///
/// `tx_seq` comes from [`TxQueue::join`](crate::driver::TxQueue::join): a
/// sub-query joins the transmit queue's tail exactly like a caller's own query,
/// so a lookup that launches a burst of resolves cannot displace anything
/// already waiting.
fn register_subquery(
  queries: &mut HashMap<QueryHandle, QueryCtx>,
  ctx: &mut LookupCtx,
  owner: LookupHandle,
  sub: QueryHandle,
  step: Step,
  tx_seq: u64,
) {
  queries.insert(
    sub,
    QueryCtx {
      last_seq: 0,
      owner: Some(owner),
      tx_seq,
      wire_gate: crate::driver::FamilyWireGate::default(),
    },
  );
  ctx.subqueries.insert(sub, step);
  ctx.launched = ctx.launched.saturating_add(1);
}

/// Push `item` into `v` if it is new and `v` is under [`MAX_ADDRS_PER_HOST`].
///
/// Silent about whether it pushed: unlike `hick-reactor`'s, this aggregation
/// never re-emits an already-reported instance, so no caller has anything to do
/// with "was this address new".
fn push_capped<T: PartialEq>(v: &mut Vec<T>, item: T) {
  if v.len() >= MAX_ADDRS_PER_HOST || v.contains(&item) {
    return;
  }
  v.push(item);
}

/// Case-fold a name to its lookup key (DNS names are case-insensitive,
/// RFC 6762 §16).
fn fold(name: &Name) -> SmolStr {
  // `Name` is already stored canonical-lowercase, so a plain `SmolStr::new`
  // suffices — and inlines names ≤23 bytes.
  SmolStr::new(name.as_str())
}

/// Decode an owner-less wire-form domain name (a decompressed PTR/SRV target as
/// stored in a [`CollectedAnswer`]) into an owned [`Name`].
///
/// Returns `None` for any name the [`Name`] type cannot represent faithfully: a
/// label containing a `.` (always a separator) or a non-ASCII byte (mangled by
/// `Name`). Such names are skipped rather than silently corrupted — and traced
/// at debug level, because RFC 6763 §4.1.1 instance names are UTF-8 display
/// strings, so a real link drops a real fraction of its instances here, and a
/// caller with no trace cannot tell one from an instance that never answered.
fn name_from_ref(nr: &NameRef<'_>) -> Option<Name> {
  let mut s = String::new();
  for label in nr.labels() {
    let label = label.ok()?;
    if label.is_empty() {
      break; // root terminator
    }
    if label.iter().any(|&b| b >= 0x80 || b == b'.') {
      hick_trace::debug!(
        "a lookup skipped a name `Name` cannot represent (a label with a `.`, or a non-ASCII byte)"
      );
      return None;
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
mod tests;

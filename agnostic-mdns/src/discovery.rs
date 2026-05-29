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
//! data, and at least one address — matching the completeness rule of the
//! original client. Each step is a real [`crate::Query`], so retransmission,
//! caching, and TTL handling are inherited from the proto/driver layers; the
//! whole lookup is bounded by the per-query timeouts and is cancelled by
//! dropping the [`Lookup`].

use std::{
  collections::{HashMap, HashSet, VecDeque},
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  time::Duration,
};

use futures::{StreamExt, stream::SelectAll};
use mdns_proto::{
  Name, QuerySpec,
  wire::{ARecord, AaaaRecord, NameRef, PtrRecord, ResourceType, SrvRecord, TxtRecord},
};

use crate::{Endpoint, QueryEvent, error::StartQueryError, query::Query};

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
  /// `My Printer._ipp._tcp.local.`.
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

/// A running DNS-SD lookup.
///
/// Call [`Self::next`] to receive resolved [`ServiceEntry`] values as they
/// complete; it returns `None` once every query (browse + resolves) has timed
/// out. Dropping the `Lookup` cancels all of its in-flight queries.
pub struct Lookup {
  endpoint: Endpoint,
  streams: SelectAll<futures::stream::BoxStream<'static, Tagged>>,
  builders: HashMap<String, Builder>,
  hosts_queried: HashSet<String>,
  ready: VecDeque<ServiceEntry>,
  resolve_timeout: Duration,
  unicast: bool,
}

impl Lookup {
  /// Wait for the next resolved service instance, or `None` when the lookup is
  /// finished (all queries timed out).
  pub async fn next(&mut self) -> Option<ServiceEntry> {
    loop {
      if let Some(entry) = self.ready.pop_front() {
        return Some(entry);
      }
      let tagged = self.streams.next().await?;
      self.process(tagged).await;
    }
  }

  async fn process(&mut self, tagged: Tagged) {
    let answer = match tagged.event {
      QueryEvent::Answer(a) => a,
      QueryEvent::Terminal(_) => return,
    };
    match tagged.step {
      Step::Ptr => {
        if answer.rtype() != ResourceType::Ptr {
          return;
        }
        let Some(instance) = parse_name(answer.rdata_slice()) else {
          return;
        };
        let key = fold(&instance);
        if self.builders.contains_key(&key) {
          return; // already discovered this instance
        }
        self
          .builders
          .insert(key.clone(), Builder::new(instance.clone()));
        self
          .start(instance.clone(), ResourceType::Srv, Step::Srv(key.clone()))
          .await;
        self
          .start(instance, ResourceType::Txt, Step::Txt(key))
          .await;
      }
      Step::Srv(inst_key) => {
        if answer.rtype() != ResourceType::Srv {
          return;
        }
        let Some((host, port)) = parse_srv(answer.rdata_slice()) else {
          return;
        };
        let host_key = fold(&host);
        if let Some(b) = self.builders.get_mut(&inst_key) {
          b.host = Some(host.clone());
          b.host_key = Some(host_key.clone());
          b.port = port;
        }
        if self.hosts_queried.insert(host_key.clone()) {
          self
            .start(host.clone(), ResourceType::A, Step::A(host_key.clone()))
            .await;
          self
            .start(host, ResourceType::Aaaa, Step::Aaaa(host_key))
            .await;
        }
        self.maybe_emit(&inst_key);
      }
      Step::Txt(inst_key) => {
        if answer.rtype() != ResourceType::Txt {
          return;
        }
        let segs = parse_txt(answer.rdata_slice());
        if let Some(b) = self.builders.get_mut(&inst_key) {
          b.txt = Some(segs);
        }
        self.maybe_emit(&inst_key);
      }
      Step::A(host_key) => {
        if answer.rtype() != ResourceType::A {
          return;
        }
        let Some(addr) = ARecord::try_from_rdata(answer.rdata_slice())
          .ok()
          .map(|r| r.addr())
        else {
          return;
        };
        for inst_key in self.builders_for_host(&host_key) {
          if let Some(b) = self.builders.get_mut(&inst_key) {
            if !b.ipv4.contains(&addr) {
              b.ipv4.push(addr);
            }
          }
          self.maybe_emit(&inst_key);
        }
      }
      Step::Aaaa(host_key) => {
        if answer.rtype() != ResourceType::Aaaa {
          return;
        }
        let Some(addr) = AaaaRecord::try_from_rdata(answer.rdata_slice())
          .ok()
          .map(|r| r.addr())
        else {
          return;
        };
        for inst_key in self.builders_for_host(&host_key) {
          if let Some(b) = self.builders.get_mut(&inst_key) {
            if !b.ipv6.contains(&addr) {
              b.ipv6.push(addr);
            }
          }
          self.maybe_emit(&inst_key);
        }
      }
    }
  }

  /// Instance keys whose SRV target host matches `host_key`.
  fn builders_for_host(&self, host_key: &str) -> Vec<String> {
    self
      .builders
      .iter()
      .filter(|(_, b)| b.host_key.as_deref() == Some(host_key))
      .map(|(k, _)| k.clone())
      .collect()
  }

  /// Emit the instance as a [`ServiceEntry`] if it just became complete.
  fn maybe_emit(&mut self, inst_key: &str) {
    if let Some(b) = self.builders.get_mut(inst_key) {
      if !b.emitted && b.complete() {
        if let Some(entry) = b.finalize() {
          b.emitted = true;
          self.ready.push_back(entry);
        }
      }
    }
  }

  /// Start a resolve sub-query and fold its answers into the merged stream.
  async fn start(&mut self, name: Name, qtype: ResourceType, step: Step) {
    let spec = QuerySpec::new(name, qtype)
      .with_timeout(self.resolve_timeout)
      .with_unicast_response(self.unicast);
    if let Ok(query) = self.endpoint.start_query(spec).await {
      self.streams.push(tagged_stream(query, step));
    }
  }
}

impl Endpoint {
  /// Browse for instances of a DNS-SD service type, resolving each into a
  /// [`ServiceEntry`]. See [`Lookup`] and [`QueryParam`].
  pub async fn browse(&self, param: QueryParam) -> Result<Lookup, StartQueryError> {
    let resolve_timeout = param.resolve_timeout.unwrap_or(param.timeout);
    let ptr_spec = QuerySpec::new(param.service, ResourceType::Ptr)
      .with_timeout(param.timeout)
      .with_unicast_response(param.unicast_response);
    let ptr_query = self.start_query(ptr_spec).await?;
    let mut streams = SelectAll::new();
    streams.push(tagged_stream(ptr_query, Step::Ptr));
    Ok(Lookup {
      endpoint: self.clone(),
      streams,
      builders: HashMap::new(),
      hosts_queried: HashSet::new(),
      ready: VecDeque::new(),
      resolve_timeout,
      unicast: param.unicast_response,
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

/// Case-fold a name to its lookup key (DNS names are case-insensitive,
/// RFC 6762 §16).
fn fold(name: &Name) -> String {
  name.as_str().to_ascii_lowercase()
}

/// Decode an owner-less wire-form domain name (a decompressed PTR/SRV target as
/// stored in a [`mdns_proto::CollectedAnswer`]) into an owned [`Name`].
fn name_from_ref(nr: &NameRef<'_>) -> Option<Name> {
  let mut s = String::new();
  for label in nr.labels() {
    let label = label.ok()?;
    if label.is_empty() {
      break; // root terminator
    }
    s.push_str(&String::from_utf8_lossy(label));
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

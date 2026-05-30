//! Caller-side handle for an mDNS endpoint.

use core::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  time::Duration,
};
use std::{rc::Rc, time::Instant};

use futures::future::select_all;
use mdns_proto::{
  Name, QuerySpec, ServiceSpec,
  wire::{ARecord, AaaaRecord, ResourceType},
};
use mdns_udp::{
  MulticastOptionsV4, MulticastOptionsV6, try_bind_v4, try_bind_v6, try_join_v4, try_join_v6,
};

use crate::{
  discovery::{Lookup, QueryParam, Resolver, ServiceEntry, Step, feed, fold, push_capped},
  driver::{EndpointInner, run},
  error::{RegisterError, ServerError, StartQueryError},
  options::ServerOptions,
  query::{Query, QueryEvent},
  service::Service,
  socket::Socket,
};

/// Handle to a running mDNS endpoint.
///
/// Cloneable; every clone shares the same underlying driver task. The driver
/// task is spawned at [`Self::server`] time and exits when the last clone
/// (and every derived [`Service`] / [`Query`] handle) is dropped — detected
/// via `Rc::strong_count(&inner) == 1` inside the driver loop.
#[derive(Clone)]
pub struct Endpoint {
  pub(crate) inner: Rc<EndpointInner>,
}

impl Endpoint {
  /// Bind the multicast sockets configured in `opts` and spawn the driver
  /// task on the current compio runtime.
  pub async fn server(opts: ServerOptions) -> Result<Self, ServerError> {
    if !opts.ipv4() && !opts.ipv6() {
      return Err(ServerError::NoFamilyEnabled);
    }

    let interface_index = match opts.interface_index() {
      Some(i) => i,
      None => pick_default_interface_index(opts.ipv4(), opts.ipv6()).ok_or_else(|| {
        ServerError::Io(std::io::Error::new(
          std::io::ErrorKind::NotFound,
          "no multicast-capable interface found",
        ))
      })?,
    };

    // Gracefully degrade — if the chosen interface lacks one of the
    // requested families, bind only the family it can support rather than
    // failing the entire endpoint.
    let iface_has_v4 = match getifs::interface_by_index(interface_index) {
      Ok(Some(i)) => matches!(i.ipv4_addrs(), Ok(ref a) if !a.is_empty()),
      _ => false,
    };
    let iface_has_v6 = match getifs::interface_by_index(interface_index) {
      Ok(Some(i)) => matches!(i.ipv6_addrs(), Ok(ref a) if !a.is_empty()),
      _ => false,
    };
    let bind_v4 = opts.ipv4() && iface_has_v4;
    let bind_v6 = opts.ipv6() && iface_has_v6;
    if !bind_v4 && !bind_v6 {
      return Err(ServerError::Io(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "interface has no address in any requested family",
      )));
    }

    let std_v4 = if bind_v4 {
      let s = try_bind_v4(MulticastOptionsV4::new(interface_index)).map_err(ServerError::BindV4)?;
      // Fail construction on a join error: a bound-but-unjoined socket can send
      // but never receives multicast, making the endpoint silently
      // non-functional. Mirrors the reactor's fatal-join setup.
      try_join_v4(&s, interface_index).map_err(ServerError::JoinV4)?;
      s.set_nonblocking(true).map_err(ServerError::Io)?;
      Some(s)
    } else {
      None
    };

    let std_v6 = if bind_v6 {
      let s = try_bind_v6(MulticastOptionsV6::new(interface_index)).map_err(ServerError::BindV6)?;
      try_join_v6(&s, interface_index).map_err(ServerError::JoinV6)?;
      s.set_nonblocking(true).map_err(ServerError::Io)?;
      Some(s)
    } else {
      None
    };

    let sock_v4 = if let Some(s) = std_v4 {
      Some(Rc::new(
        Socket::from_std(s).await.map_err(ServerError::WrapSocket)?,
      ))
    } else {
      None
    };
    let sock_v6 = if let Some(s) = std_v6 {
      Some(Rc::new(
        Socket::from_std(s).await.map_err(ServerError::WrapSocket)?,
      ))
    } else {
      None
    };

    let inner = EndpointInner::new(
      *opts.endpoint_config(),
      opts.max_payload_size(),
      opts.max_recv_packet_size(),
    );

    // Populate the §11 source-address fallback's local-subnet snapshot and
    // pin the bound interface index under a brief borrow.
    {
      let mut st = inner.state.borrow_mut();
      st.bound_interface = interface_index;
      st.local_subnets = collect_local_subnets(interface_index);
    }

    let driver_fut = run(inner.clone(), sock_v4, sock_v6);
    compio_runtime::spawn(driver_fut).detach();

    Ok(Self { inner })
  }

  /// Register a new service.
  ///
  /// Returns a [`Service`] handle for receiving [`ServiceUpdate`] events;
  /// dropping the handle implicitly unregisters the service. Drop encodes
  /// the RFC 6762 §10.1 goodbye records and tears down the proto state
  /// synchronously; the driver task then multicasts the queued TTL=0
  /// datagrams a few times for loss resilience.
  ///
  /// [`ServiceUpdate`]: mdns_proto::ServiceUpdate
  pub async fn register_service(&self, spec: ServiceSpec) -> Result<Service, RegisterError> {
    let now = std::time::Instant::now();
    let handle = {
      let mut st = self.inner.state.borrow_mut();
      st.register_service(spec, now)
        .map_err(RegisterError::from)?
    };
    // Durable wake: a bare `notify()` can be lost across the driver's
    // send-awaits, leaving newly-registered work unobserved (see
    // `EndpointInner::dirty`). `mark_dirty` sets the level flag AND notifies.
    self.inner.mark_dirty();
    Ok(Service {
      inner: self.inner.clone(),
      handle,
    })
  }

  /// Start a query against the endpoint.
  ///
  /// Returns a [`Query`] handle for receiving [`QueryEvent`]
  /// events; dropping the handle implicitly cancels the query (the driver
  /// removes the proto state machine on its next loop iteration).
  pub async fn start_query(&self, spec: QuerySpec) -> Result<Query, StartQueryError> {
    let now = std::time::Instant::now();
    let handle = {
      let mut st = self.inner.state.borrow_mut();
      st.start_query(spec, now)
        .map_err(|_| StartQueryError::StorageFull)?
    };
    // Durable wake (see `register_service` / `EndpointInner::dirty`): critical
    // for a timeout-less `QuerySpec`, whose first transmit is the ONLY thing
    // that would schedule a deadline — if this wake is lost and no deadline
    // exists yet, the driver would otherwise park forever.
    self.inner.mark_dirty();
    Ok(Query {
      inner: self.inner.clone(),
      handle,
      terminal_delivered: core::cell::Cell::new(false),
    })
  }

  /// Browse for instances of a DNS-SD service type, resolving each into a
  /// [`ServiceEntry`].  See [`Lookup`] and [`QueryParam`].
  pub async fn browse(&self, param: QueryParam) -> Result<Lookup, StartQueryError> {
    let resolve_timeout = param.resolve_timeout.unwrap_or(param.timeout);
    // Size the PTR answer pool to the requested instance cap so a `max_entries`
    // above the proto's default answer cap is actually reachable; without this
    // surplus PTR answers would be evicted before the resolver could track
    // them.
    let ptr_spec = QuerySpec::new(param.service, ResourceType::Ptr)
      .with_timeout(param.timeout)
      .with_unicast_response(param.unicast_response)
      .with_max_answers(param.max_entries);
    let ptr_query = self.start_query(ptr_spec).await?;
    Ok(Lookup {
      endpoint: self.clone(),
      queries: vec![(ptr_query, Step::Ptr)],
      resolver: Resolver::new(param.max_entries),
      resolve_timeout,
      unicast: param.unicast_response,
      finished: false,
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
  /// them IPv4 first then IPv6, deduplicated and capped per family.  The
  /// result is empty if nothing answers.  Unlike [`Self::resolve_instance`]
  /// this does not require — or interpret — DNS-SD records; it is the
  /// multicast analogue of resolving a hostname.
  pub async fn resolve_host(
    &self,
    host: Name,
    timeout: Duration,
  ) -> Result<Vec<IpAddr>, StartQueryError> {
    // One deadline shared across both queries: the call stays bounded by
    // `timeout` even if launching the second sub-query takes some of it.
    // `checked_add` so `Duration::MAX` cannot panic the way `Instant + Duration`
    // would.
    let deadline = Instant::now().checked_add(timeout);
    let remaining = || deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
    let host_key = fold(&host);
    let qa = self
      .start_query(QuerySpec::new(host.clone(), ResourceType::A).with_timeout(remaining()))
      .await?;
    let qaaaa = self
      .start_query(QuerySpec::new(host, ResourceType::Aaaa).with_timeout(remaining()))
      .await?;
    let mut ipv4: Vec<Ipv4Addr> = Vec::new();
    let mut ipv6: Vec<Ipv6Addr> = Vec::new();
    let mut queries: Vec<(Query, Step)> = vec![
      (qa, Step::A(host_key.clone())),
      (qaaaa, Step::Aaaa(host_key)),
    ];
    while !queries.is_empty() {
      let (result, idx) = {
        let futs: Vec<_> = queries.iter().map(|(q, _)| Box::pin(q.next())).collect();
        let (result, idx, _remaining) = select_all(futs).await;
        (result, idx)
      };
      match result {
        Some(QueryEvent::Answer(ans)) => match &queries[idx].1 {
          Step::A(_) if ans.rtype() == ResourceType::A => {
            if let Ok(r) = ARecord::try_from_rdata(ans.rdata_slice()) {
              push_capped(&mut ipv4, r.addr());
            }
          }
          Step::Aaaa(_) if ans.rtype() == ResourceType::Aaaa => {
            if let Ok(r) = AaaaRecord::try_from_rdata(ans.rdata_slice()) {
              push_capped(&mut ipv6, r.addr());
            }
          }
          _ => {}
        },
        Some(QueryEvent::Terminal(_)) | None => {
          queries.swap_remove(idx);
        }
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

  /// Resolve a *known* DNS-SD service instance directly into a
  /// [`ServiceEntry`], skipping the PTR browse step (e.g.
  /// `Name::try_from_str("Office._ipp._tcp.local.")`).
  ///
  /// Issues SRV + TXT for the instance and A / AAAA for the SRV target host,
  /// and returns the first complete resolution — host + port, TXT, and at
  /// least one address — or `None` if it does not complete within `timeout`.
  /// Use [`Self::browse`] instead when the instance names are not known in
  /// advance.
  pub async fn resolve_instance(
    &self,
    instance: Name,
    timeout: Duration,
  ) -> Result<Option<ServiceEntry>, StartQueryError> {
    // Shared deadline so an SRV arriving late cannot grant the A/AAAA
    // follow-ups a second full `timeout` window.
    let deadline = Instant::now().checked_add(timeout);
    let remaining = || deadline.map_or(timeout, |d| d.saturating_duration_since(Instant::now()));
    let mut resolver = Resolver::new(1);
    let mut queries: Vec<(Query, Step)> = Vec::new();
    for start in resolver.on_ptr(instance) {
      let qtype = start.qtype();
      let q = self
        .start_query(QuerySpec::new(start.name, qtype).with_timeout(remaining()))
        .await?;
      queries.push((q, start.step));
    }
    loop {
      if let Some(e) = resolver.take_ready() {
        return Ok(Some(e));
      }
      if queries.is_empty() {
        return Ok(None);
      }
      let (result, idx) = {
        let futs: Vec<_> = queries.iter().map(|(q, _)| Box::pin(q.next())).collect();
        let (result, idx, _remaining) = select_all(futs).await;
        (result, idx)
      };
      match result {
        Some(QueryEvent::Answer(_)) => {
          let step = queries[idx].1.clone();
          let event = result.expect("matched Some above");
          for start in feed(&mut resolver, step, event) {
            let qtype = start.qtype();
            let q = self
              .start_query(QuerySpec::new(start.name, qtype).with_timeout(remaining()))
              .await?;
            queries.push((q, start.step));
          }
        }
        Some(QueryEvent::Terminal(_)) | None => {
          queries.swap_remove(idx);
        }
      }
    }
  }
}

/// Wake the driver when an `Endpoint` clone is dropped so it can promptly
/// observe `Rc::strong_count(&inner) == 1` and exit (per the T9 exit-condition
/// contract). Without this notify, the driver would only notice the dropped
/// handle the next time it woke for a recv / timer event.
impl Drop for Endpoint {
  fn drop(&mut self) {
    self.inner.notify.notify();
  }
}

/// Snapshot the local IPv4 / IPv6 subnets owned by `iface_index`. Used by
/// the §11 on-link source-address fallback when the kernel did not deliver
/// an IPv4 TTL / IPv6 hop-limit cmsg.
fn collect_local_subnets(iface_index: u32) -> Vec<(core::net::IpAddr, u8)> {
  let mut out: Vec<(core::net::IpAddr, u8)> = Vec::new();
  if iface_index == 0 {
    return out;
  }
  if let Ok(Some(i)) = getifs::interface_by_index(iface_index) {
    if let Ok(v4s) = i.ipv4_addrs() {
      for n in v4s.iter() {
        out.push((core::net::IpAddr::V4(n.addr()), n.prefix_len()));
      }
    }
    if let Ok(v6s) = i.ipv6_addrs() {
      for n in v6s.iter() {
        out.push((core::net::IpAddr::V6(n.addr()), n.prefix_len()));
      }
    }
  }
  out
}

/// Pick a default interface index when the caller didn't pin one. Mirrors
/// the algorithm in `mdns-reactor::endpoint::pick_default_interface_index`:
/// prefer a non-loopback, multicast-up interface that satisfies every
/// requested family; fall back through looser predicates ending at the
/// loopback interface.
fn pick_default_interface_index(want_v4: bool, want_v6: bool) -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  let has_v4 = |i: &getifs::Interface| matches!(i.ipv4_addrs(), Ok(ref v) if !v.is_empty());
  let has_v6 = |i: &getifs::Interface| matches!(i.ipv6_addrs(), Ok(ref v) if !v.is_empty());
  let multicast_up_non_loopback = |i: &getifs::Interface| -> bool {
    let f = i.flags();
    f.contains(getifs::Flags::UP)
      && f.contains(getifs::Flags::MULTICAST)
      && !f.contains(getifs::Flags::LOOPBACK)
      && i.index() != 0
  };
  let loopback_up = |i: &getifs::Interface| -> bool {
    i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP)
  };
  let strict =
    |i: &&getifs::Interface| -> bool { (!want_v4 || has_v4(i)) && (!want_v6 || has_v6(i)) };
  let loose = |i: &&getifs::Interface| -> bool { (want_v4 && has_v4(i)) || (want_v6 && has_v6(i)) };
  ifs
    .iter()
    .find(|i| multicast_up_non_loopback(i) && strict(i))
    .or_else(|| {
      ifs
        .iter()
        .find(|i| multicast_up_non_loopback(i) && loose(i))
    })
    .or_else(|| ifs.iter().find(|i| loopback_up(i) && strict(i)))
    .or_else(|| ifs.iter().find(|i| loopback_up(i) && loose(i)))
    .map(|i| i.index())
}

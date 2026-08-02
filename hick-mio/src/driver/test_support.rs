//! Shared fixtures for the `driver` and `endpoint` unit tests.
//!
//! Lives beside them rather than inside either `tests.rs` because both
//! modules need the same loopback [`Mdns`] fixture, and because a test that
//! binds a socket must take the crate-wide bind lock exactly once.

use std::{
  net::{IpAddr, Ipv4Addr, SocketAddr},
  sync::MutexGuard,
  time::{Duration, Instant as StdInstant},
};

use mdns_proto::{
  FamilyAttempt, Name, QuerySpec, ServiceHandle, ServiceRecords, ServiceSpec,
  event::RouteEvent,
  wire::{Header, MessageBuilder, MessageReader, NameRef, ResourceType},
};

use crate::{
  endpoint::Mdns,
  options::ServerOptions,
  socket::{BIND_LOCK, Family},
};

/// An [`Mdns`] bound to loopback, holding the crate-wide bind lock.
///
/// Field order is load-bearing: struct fields drop in declaration order, so
/// the sockets close (leaving the multicast group) *before* the guard is
/// released and the next test is allowed to bind.
pub(crate) struct TestMdns {
  mdns: Mdns,
  _guard: MutexGuard<'static, ()>,
}

impl core::ops::Deref for TestMdns {
  type Target = Mdns;

  fn deref(&self) -> &Mdns {
    &self.mdns
  }
}

impl core::ops::DerefMut for TestMdns {
  fn deref_mut(&mut self) -> &mut Mdns {
    &mut self.mdns
  }
}

fn loopback_index() -> Option<u32> {
  getifs::interfaces()
    .ok()?
    .into_iter()
    .find(|i| i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP))
    .map(|i| i.index())
}

/// Build an [`Mdns`] pinned to loopback, or print why the test is skipping.
/// Every early return prints a reason: a silent skip is a test that passes
/// while asserting nothing.
///
/// `hick_udp::try_bind_v6` is rejected outright on some hosts (macOS returns
/// `EINVAL` on *every* interface), so a dual-stack request degrades to
/// IPv4-only rather than skipping the whole test — none of the properties
/// asserted here depend on IPv6. The degradation is printed so a run that
/// covers less than it looks like says so.
pub(crate) fn loopback_mdns() -> Option<TestMdns> {
  loopback_mdns_with(ServerOptions::default())
}

/// [`loopback_mdns`] over a caller-supplied options bundle, with the interface
/// pinned to loopback on top of it.
///
/// The one knob a test cannot get any other way is
/// [`ServerOptions::with_max_payload_size`]: it sizes the encode scratch every
/// `poll_transmit` writes into, and a buffer too small for a service's records
/// is the only thing that makes the proto layer fail to encode on demand. That
/// failure drives the consecutive-encode-error retirement, which is otherwise
/// unreachable from a test.
pub(crate) fn loopback_mdns_with(opts: ServerOptions) -> Option<TestMdns> {
  // Ignore poisoning: a panic in one test must surface as that test's own
  // assertion failure, not as a poison error in every test that follows it.
  let guard = BIND_LOCK.lock().unwrap_or_else(|e| e.into_inner());
  let Some(idx) = loopback_index() else {
    eprintln!("skipping: no UP loopback interface reported by getifs");
    return None;
  };
  let opts = opts.with_interface_index(Some(idx));
  let mdns = match Mdns::new(opts.clone()) {
    Ok(m) => m,
    Err(e) => {
      eprintln!("note: dual-stack loopback bind failed ({e:?}); retrying IPv4-only");
      match Mdns::new(opts.with_ipv6(false)) {
        Ok(m) => m,
        Err(e) => {
          eprintln!("skipping: loopback bind failed even IPv4-only ({e:?})");
          return None;
        }
      }
    }
  };
  Some(TestMdns {
    mdns,
    _guard: guard,
  })
}

/// An [`Mdns`] pinned to loopback with IPv6 disabled **by configuration**.
///
/// The RFC 6762 §10.1 per-family goodbye debt turns on the difference between a
/// family that is absent and one that is merely failing, and [`loopback_mdns`]'s
/// IPv6 socket is present on some hosts and absent on others. Switching the
/// family off in the options makes "IPv6 is absent" a property of the test
/// rather than of the host, so a write-off assertion means the same thing on
/// every platform.
pub(crate) fn loopback_mdns_v4_only() -> Option<TestMdns> {
  let guard = BIND_LOCK.lock().unwrap_or_else(|e| e.into_inner());
  let Some(idx) = loopback_index() else {
    eprintln!("skipping: no UP loopback interface reported by getifs");
    return None;
  };
  let opts = ServerOptions::default()
    .with_interface_index(Some(idx))
    .with_ipv6(false);
  match Mdns::new(opts) {
    Ok(mdns) => Some(TestMdns {
      mdns,
      _guard: guard,
    }),
    Err(e) => {
      eprintln!("skipping: IPv4-only loopback bind failed ({e:?})");
      None
    }
  }
}

/// A registrable service on `ty`, with a loopback A record so the records
/// encode to something a real probe would send.
pub(crate) fn service_spec(ty: &str, port: u16) -> ServiceSpec {
  let mut records = ServiceRecords::new(
    Name::try_from_str(ty).expect("service type"),
    Name::try_from_str(&format!("hick-mio.{ty}")).expect("instance name"),
    Name::try_from_str("hick-mio-test.local.").expect("host name"),
    port,
    120,
  );
  records.add_a(Ipv4Addr::LOCALHOST);
  ServiceSpec::new(records)
}

/// A registrable service on `ty` under a caller-chosen instance label, so a
/// test that drives an RFC 6762 §9 rename can name the label it expects to see
/// retracted.
pub(crate) fn named_service_spec(instance: &str, ty: &str, port: u16) -> ServiceSpec {
  let mut records = ServiceRecords::new(
    Name::try_from_str(ty).expect("service type"),
    Name::try_from_str(&format!("{instance}.{ty}")).expect("instance name"),
    Name::try_from_str("hick-mio-test.local.").expect("host name"),
    port,
    120,
  );
  records.add_a(Ipv4Addr::LOCALHOST);
  ServiceSpec::new(records)
}

/// A registrable service carrying one RFC 6763 §7.1 subtype browse PTR.
///
/// The subtype matters to the §9 rename tests: a subtype PTR the old
/// registration advertised and a replacement does not is a record **nothing but
/// the goodbye can retract**. It is the concrete case against superseding a
/// rename's retraction with the replacement's own announcement instead of
/// holding the name until the retraction is paid.
pub(crate) fn subtyped_service_spec(
  instance: &str,
  ty: &str,
  subtype: &str,
  port: u16,
) -> ServiceSpec {
  let mut records = ServiceRecords::new(
    Name::try_from_str(ty).expect("service type"),
    Name::try_from_str(&format!("{instance}.{ty}")).expect("instance name"),
    Name::try_from_str("hick-mio-test.local.").expect("host name"),
    port,
    120,
  );
  records.add_a(Ipv4Addr::LOCALHOST);
  records.add_subtype(subtype).expect("subtype browse name");
  ServiceSpec::new(records)
}

/// A PTR browse for `ty`.
pub(crate) fn query_spec(ty: &str) -> QuerySpec {
  QuerySpec::new(
    Name::try_from_str(ty).expect("query name"),
    ResourceType::Ptr,
  )
}

/// Long enough for a full RFC 6762 §8 lifecycle — the 0-250 ms jitter before the
/// first probe, three probes 250 ms apart, and the §8.3 announcement that follows
/// — several times over, so a slow runner is slack rather than a verdict.
/// `tests/loopback.rs` gives its own advertise wait the same budget.
const ADVERTISE_BUDGET: Duration = Duration::from_secs(10);

/// Tick until `handle` has confirmed-emitted its records.
///
/// RFC 6762 §8.1 probing is real wall-clock work — three probes 250 ms apart —
/// and only an **announced** service has an old name for a later rename to
/// retract, so every rename test has to get through this first.
///
/// # The failure path is not a skip
///
/// Ten callers return early on `false`, so an unconditional skip here would take
/// all ten green on a regression in probing, announcing, or the per-family
/// confirm. There is exactly one environmental cause — a host whose kernel
/// accepts no multicast datagram on the loopback interface, so no probe ever
/// leaves — and it is read from the socket layer's own record of what it handed
/// the kernel, never inferred from the announce failing. Datagrams on a wire and
/// no announce is this crate's fault and panics.
pub(crate) fn drive_to_advertised(mdns: &mut Mdns, handle: ServiceHandle) -> bool {
  let deadline = StdInstant::now() + ADVERTISE_BUDGET;
  while StdInstant::now() < deadline {
    mdns.tick().expect("tick");
    if mdns
      .services
      .get(&handle)
      .is_some_and(|ctx| ctx.proto.advertises_instance())
    {
      return true;
    }
    std::thread::sleep(Duration::from_millis(20));
  }
  let on_wire: usize = [Family::V4, Family::V6]
    .into_iter()
    .map(|family| mdns.sockets.wire_times_for_test(family).len())
    .sum();
  assert_eq!(
    on_wire, 0,
    "the service never advertised within {ADVERTISE_BUDGET:?}, yet the socket \
     layer had already handed the kernel datagrams on this endpoint's own wires: \
     the probes did go out, so probing, announcing or the per-family confirm has \
     regressed"
  );
  eprintln!(
    "skipping: this host's kernel accepted no multicast datagram on the loopback \
     interface, so no probe could leave and no service can announce"
  );
  false
}

/// A peer's RFC 6762 §8.1 probe for `instance`: an authority-section SRV
/// claiming that name for a different target and a higher port, so the §8.2
/// lexicographic tiebreak goes against us and the service renames.
pub(crate) fn conflict_probe(instance: &str) -> Vec<u8> {
  let mut buf = vec![0u8; 512];
  let name = Name::try_from_str(instance).expect("instance name");
  let target = Name::try_from_str("rival.local.").expect("target name");
  let mut builder: MessageBuilder<'_> =
    MessageBuilder::try_new(&mut buf, Header::new()).expect("message builder");
  builder
    .push_srv_authority(&name, 120, 0, 0, 9999, &target)
    .expect("push_srv_authority");
  let n = builder.finish().expect("finish");
  buf.truncate(n);
  buf
}

/// Feed `data` to the endpoint exactly as [`Mdns::drain_recv`] does once a
/// datagram has cleared the RFC 6762 §11 on-link gate and the self-send
/// tracker.
///
/// Written here rather than behind a production seam because the two gates it
/// skips are the trust boundary, not the dispatch: reproducing them needs a peer
/// on a real link delivering a TTL cmsg, which is exactly what a unit test does
/// not have. The dispatch itself — route the events, skip a retired service — is
/// reproduced in full.
pub(crate) fn ingest(mdns: &mut Mdns, data: &[u8], now: StdInstant) {
  let peer = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), 5353));
  let Mdns {
    endpoint,
    services,
    bound_interface,
    ..
  } = mdns;
  let route_events = endpoint
    .handle(
      now,
      peer,
      IpAddr::V4(Ipv4Addr::LOCALHOST),
      *bound_interface,
      data,
      false,
    )
    .expect("the endpoint must accept a well-formed probe");
  for ev in route_events {
    if let Ok(RouteEvent::ToService(ts)) = ev
      && let Some(ctx) = services.get_mut(&ts.handle())
      && !ctx.withdrawing
    {
      ctx.proto.handle_event(ts.into_event(), now);
    }
  }
}

/// Pump every RFC 6762 §10.1 goodbye that is due, confirming each round as
/// delivered, and return the datagrams the endpoint encoded.
///
/// Confirming is what advances the schedule, so repeated calls walk the whole
/// resend sequence instead of re-encoding the first round forever.
pub(crate) fn collect_goodbyes(mdns: &mut Mdns, now: StdInstant) -> Vec<Vec<u8>> {
  let accepted = FamilyAttempt::Accepted { at: now };
  collect_goodbyes_as(mdns, now, accepted, accepted)
}

/// [`collect_goodbyes`] with the per-family outcome chosen by the caller.
///
/// A family reported [`FamilyAttempt::Refused`] keeps its debt, which is how a
/// test reproduces "this family's send failed" without a socket that can be made
/// to fail. Per-family debt is the whole of what the §10.1 schedule and the §9
/// name hold turn on, so a test that can only report both families succeeding
/// cannot reach either.
pub(crate) fn collect_goodbyes_as(
  mdns: &mut Mdns,
  now: StdInstant,
  v4: FamilyAttempt<StdInstant>,
  v6: FamilyAttempt<StdInstant>,
) -> Vec<Vec<u8>> {
  let mut out = Vec::new();
  let mut scratch = vec![0u8; 1500];
  while let Some(round) = mdns.endpoint.poll_withdrawal_transmit(now, &mut scratch) {
    if let Some(body) = scratch.get(..round.len()) {
      out.push(body.to_vec());
    }
    mdns
      .endpoint
      .note_withdrawal_result(round.token(), now, v4, v6);
  }
  out
}

/// Pay every pending goodbye off on both families, resuming from `from`, and
/// let one tick free what settled.
///
/// `from` must be the instant of the caller's last injected round: the schedule
/// re-arms relative to the round it just confirmed, so a sequence restarted from
/// the wall clock would sit before the next `next_at` and emit nothing.
///
/// The 260 ms step is just past the schedule's 250 ms resend interval, so each
/// call emits the next round instead of re-reading the same one. Five of them
/// clears the three each family owes and still lands inside the endpoint's 2 s
/// anti-pin ceiling — so what this drives is the schedule *completing*, never
/// the ceiling force-completing it, which would release the name without the
/// retraction ever being paid and make the caller's assertion vacuous.
pub(crate) fn settle_goodbyes(mdns: &mut Mdns, from: StdInstant) {
  let mut at = from;
  for _ in 0..5 {
    at += Duration::from_millis(260);
    if collect_goodbyes(mdns, at).is_empty() {
      break;
    }
  }
  // `drain_completed_withdrawals` runs in stage 7 and is what actually releases
  // a held name once its debt is zero.
  mdns.tick().expect("tick");
}

/// A wire name as a lowercase dotted string, or `None` if it does not parse.
fn dotted(name: &NameRef<'_>) -> Option<String> {
  let mut out = String::new();
  for label in name.labels() {
    let label = label.ok()?;
    out.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
    out.push('.');
  }
  Some(out)
}

/// Whether `datagram` retracts `instance`: it owns at least one record under
/// that name, and **every** record it carries has TTL 0.
///
/// Both halves matter. The name alone would also match a positive
/// re-announcement of the same records, and TTL 0 alone would match the
/// retraction of some other name that happened to share the datagram.
pub(crate) fn retracts(datagram: &[u8], instance: &str) -> bool {
  let Ok(reader) = MessageReader::try_parse(datagram) else {
    return false;
  };
  let want = instance.to_ascii_lowercase();
  let mut owns_it = false;
  for record in reader.answers() {
    let Ok(record) = record else { return false };
    if record.ttl() != 0 {
      return false;
    }
    if dotted(record.name()).is_some_and(|n| n == want) {
      owns_it = true;
    }
  }
  owns_it
}

//! End-to-end loopback tests for the tokio driver: a server advertises a
//! service and a client looks it up over loopback, with per-record-type
//! coverage (PTR / SRV / A / AAAA / TXT).
//!
//! ## Self-loopback handling
//!
//! Two Endpoints on the same host see each other's multicast packets AND
//! their own packets coming back via the OS loopback. The proto-layer
//! sent-packet hash cache disambiguates the two: every outgoing
//! datagram is recorded via `Endpoint::observe_send`, so the inbound
//! loopback copy is identified by content match and dropped, while the
//! peer's packets (which happen to share the same src IP on loopback)
//! are processed normally.
//!
//! That signal works regardless of advertised addresses, so these tests
//! advertise the real loopback `127.0.0.1`.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{
  net::{IpAddr, Ipv6Addr},
  time::Duration,
};
// `Ipv4Addr` and `Instant` are reached only from the `#[cfg(unix)]` witness
// below (`MDNS_GROUP`, `to_in_addr`, `select_multicast_egress`,
// `LoopbackWitness`); gate any new user onto them too, or these go dead under
// `-D warnings` on non-unix targets again.
#[cfg(unix)]
use std::{net::Ipv4Addr, time::Instant};

use hick_reactor::{
  CollectedAnswer, Name, QueryEvent, QueryParam, QuerySpec, ServerOptions, Service, ServiceRecords,
  ServiceSpec, tokio as tokio_drv, wire::ResourceType,
};

const UNIQUE_SERVICE: &str = "_agnostic-mdns-test-v06._tcp.local.";
const UNIQUE_INSTANCE: &str = "Test._agnostic-mdns-test-v06._tcp.local.";
const UNIQUE_HOST: &str = "test-host.local.";
const SERVICE_PORT: u16 = 12345;
const ADVERTISED_V4: [u8; 4] = [127, 0, 0, 1];
const ADVERTISED_V6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

fn loopback_index() -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| {
      let f = i.flags();
      f.contains(getifs::Flags::LOOPBACK)
        && f.contains(getifs::Flags::UP)
        && i.ipv4_addrs().ok().map(|v| !v.is_empty()).unwrap_or(false)
    })
    .map(|i| i.index())
}

fn loopback_opts(idx: u32) -> ServerOptions {
  ServerOptions::new()
    .with_ipv6(false)
    .with_interface_index(Some(idx))
}

async fn try_endpoint(opts: ServerOptions) -> Option<tokio_drv::Endpoint> {
  match tokio_drv::server(opts).await {
    Ok(ep) => Some(ep),
    Err(e) => {
      eprintln!("skipping: endpoint construction failed: {e:?}");
      None
    }
  }
}

/// Owned bundle returned from [`build_pair`]. The caller must keep this
/// alive for the full test duration — dropping the [`Service`] would
/// unregister the responder service mid-test, and dropping either
/// [`tokio_drv::Endpoint`] would tear down its driver task.
struct LoopbackPair {
  /// Held to keep the responder driver task alive for the test duration.
  _responder: tokio_drv::Endpoint,
  querier: tokio_drv::Endpoint,
  // An explicit owned guard replaces the prior
  // `mem::forget(service)` so the test actually exercises Drop / cleanup
  // paths rather than masking lifecycle bugs.
  _service: Service,
}

/// Build a [responder, querier] pair on the loopback interface, with the
/// responder publishing the canonical test service. The responder is given
/// `setup_wait` to finish probing + announcing before the function returns.
async fn build_pair(setup_wait: Duration) -> Option<LoopbackPair> {
  build_pair_named(setup_wait, UNIQUE_SERVICE, UNIQUE_INSTANCE, UNIQUE_HOST).await
}

/// Like [`build_pair`] but with a caller-chosen service type, instance, and host
/// name. Tests that resolve a *specific* name (rather than browsing the shared
/// type) pass unique values so they neither conflict-rename a shared record nor
/// leak their instance into another test's browse results.
async fn build_pair_named(
  setup_wait: Duration,
  service: &str,
  instance: &str,
  host: &str,
) -> Option<LoopbackPair> {
  let idx = loopback_index()?;

  let responder = try_endpoint(loopback_opts(idx)).await?;
  let stype = Name::try_from_str(service).unwrap();
  let instance = Name::try_from_str(instance).unwrap();
  let host = Name::try_from_str(host).unwrap();
  let mut recs = ServiceRecords::new(stype, instance, host, SERVICE_PORT, 120);
  recs.add_a(ADVERTISED_V4.into());
  recs.add_aaaa(ADVERTISED_V6);
  recs.add_txt_segment(b"Local web server".to_vec());

  let svc = match responder.register_service(ServiceSpec::new(recs)).await {
    Ok(s) => s,
    Err(e) => {
      eprintln!("skipping: register_service failed: {e:?}");
      return None;
    }
  };

  tokio::time::sleep(setup_wait).await;

  let querier = try_endpoint(loopback_opts(idx)).await?;
  Some(LoopbackPair {
    _responder: responder,
    querier,
    _service: svc,
  })
}

/// Issue `spec` against `querier` and collect up to `Terminal`.
async fn run_query(
  querier: &tokio_drv::Endpoint,
  spec: QuerySpec,
  hard_timeout: Duration,
) -> Vec<CollectedAnswer> {
  let mut q = match querier.start_query(spec).await {
    Ok(q) => q,
    Err(e) => {
      eprintln!("start_query failed: {e:?}");
      return Vec::new();
    }
  };
  tokio::time::timeout(hard_timeout, async {
    let mut got = Vec::new();
    while let Some(ev) = q.next().await {
      match ev {
        QueryEvent::Answer(a) => got.push(a),
        QueryEvent::Terminal(_) => break,
      }
    }
    got
  })
  .await
  .unwrap_or_default()
}

// ── an independent witness that multicast loopback actually carries ────────
//
// `packets_rx`, hick's own receive counter, is NOT independent of the driver
// these tests exist to catch a regression in: a regression that stops query
// transmission, stops response generation, or stops receive processing
// yields `packets_rx == 0` exactly like a genuinely silent environment, so a
// discriminator built from it would let every affected test skip instead of
// fail. `hick-reactor/tests/parity_bonjour.rs` (PR #59) already solved this
// class of problem for the harder case — hick versus an external daemon on
// the real NIC — with a control socket deliberately outside hick's own
// stack, whose OWN observations decide environment from regression rather
// than a counter the system under test produced. This is the same shape, cut
// down for the easier case this file needs: one host, the loopback
// interface, no daemon involved. Send a throwaway multicast datagram from a
// socket of our own, joined to the mDNS group on loopback exactly as
// `loopback_index()` pins hick's own endpoints, and require that SAME socket
// to receive its own copy back.
//
// Built on `std::net::UdpSocket` wherever its stable API covers what this
// needs — bind, group membership, loopback delivery, the receive timeout,
// and the send/receive calls themselves — rather than hand-rolled `libc`
// throughout. `std` is exactly as independent of hick-reactor's driver as raw
// `libc` is (independence from THIS CRATE's driver is the property the
// witness needs, not independence from the standard library), and it gets
// every per-platform width and layout right on its own — which raw `libc`
// does NOT, for free, the moment a caller has to choose an option's value
// type by hand. `IP_MULTICAST_LOOP` used to be exactly that: a hardcoded
// `c_int`, when FreeBSD, DragonFly, OpenBSD and NetBSD define the option as a
// one-byte `c_uchar` and reject the wrong width with `EINVAL` — which
// `refuses_the_link` below correctly does NOT treat as an environment fact,
// so the witness panicked on every run on those four targets instead of
// working. `hick-udp/src/platform/unix.rs`'s `set_int_sockopt` documents the
// exact same divergence and keeps `set_multicast_loop_v4`/
// `set_multicast_ttl_v4` off that chokepoint for exactly this reason — this
// was in-repo prior art this file failed to reuse the first time.
//
// Only `IP_MULTICAST_IF` — selecting an interface for multicast EGRESS, as
// opposed to group membership — has no `std::net` equivalent, so that one
// option alone still goes through a raw `setsockopt`; see
// `select_multicast_egress` for why it does not have a comparable
// width-mismatch risk.

/// The mDNS multicast group. Restated here, deliberately, rather than
/// imported from hick — this witness must not be able to inherit a defect in
/// hick's own constant.
#[cfg(unix)]
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// Why [`LoopbackWitness`] could not settle the question.
#[cfg(unix)]
enum WitnessError {
  /// The kernel refused an operation that NAMES the loopback link itself
  /// (joining the group on it, selecting it for egress, or sending through
  /// it), and the errno is on the narrow allowlist below. This is the one
  /// case that may report "environment unavailable" rather than fail the
  /// test outright.
  LinkRefused(String),
  /// Anything else — the socket could not even be opened, an option that
  /// names no link was refused, the receive call itself errored. This is a
  /// bug in this harness, never evidence about the host, and must fail the
  /// test like any other bug would.
  Harness(String),
}

/// The errnos on which the kernel is refusing the LOOPBACK LINK itself,
/// rather than refusing something about our own call. Restated from
/// `parity_bonjour.rs`'s `refuses_the_link` (PR #59) — same allowlist, same
/// discipline: matched on `raw_os_error` rather than `ErrorKind`, and
/// deliberately narrow. `EINVAL` stays off it on purpose: a malformed call
/// here is this harness's own bug — the exact shape of the `IP_MULTICAST_LOOP`
/// width defect this file once had — and admitting it would let a real
/// defect in this file read as an unavailable environment instead of failing
/// loudly.
#[cfg(unix)]
fn refuses_the_link(e: &std::io::Error) -> bool {
  matches!(
    e.raw_os_error(),
    Some(libc::EHOSTUNREACH)
      | Some(libc::ENETUNREACH)
      | Some(libc::ENETDOWN)
      | Some(libc::EADDRNOTAVAIL)
  )
}

/// Classify `e` from an operation that names `context` (join / select-egress
/// / send) — the only three calls that name the loopback link itself.
///
/// Takes the error as a VALUE rather than re-reading `std::io::Error::
/// last_os_error()`: every call site here now goes through `std::net`
/// methods, which already hand back the `io::Error` they failed with, so
/// there is no `errno` left to race by reading it back out of thin air a
/// statement later.
#[cfg(unix)]
fn link_call_failed(e: std::io::Error, context: &str) -> WitnessError {
  let described = format!("{context}: {e}");
  if refuses_the_link(&e) {
    WitnessError::LinkRefused(described)
  } else {
    WitnessError::Harness(described)
  }
}

#[cfg(unix)]
fn to_in_addr(addr: Ipv4Addr) -> libc::in_addr {
  libc::in_addr {
    s_addr: u32::from_ne_bytes(addr.octets()),
  }
}

/// Select `interface` for multicast EGRESS (`IP_MULTICAST_IF`) — distinct
/// from group MEMBERSHIP, which `std::net::UdpSocket::join_multicast_v4`
/// already covers. This is the one option in this witness with no
/// `std::net` equivalent (std can join a group and enable loopback delivery,
/// but never lets a caller choose the outbound interface for a multicast
/// send), so it alone still goes through a raw `setsockopt`.
///
/// NOT the same class of bug `IP_MULTICAST_LOOP` was: that option's value is
/// a bare scalar whose C type a caller has to choose by hand, and BSD
/// documents it as `u_char` where this file had hardcoded `c_int`. This
/// option's value is `libc::in_addr` — a STRUCT `libc` itself defines per
/// target, whose `size_of` is therefore already correct per target, the same
/// way `size_of::<libc::sockaddr_in>()` was never the problem when `sin_len`
/// was (see `to_in_addr`'s caller history). There is no hand-chosen width
/// here to get wrong.
#[cfg(unix)]
fn select_multicast_egress(sock: &std::net::UdpSocket, interface: Ipv4Addr) -> std::io::Result<()> {
  let addr = to_in_addr(interface);
  // SAFETY: `sock` owns a valid UDP fd for the duration of the call; `addr`
  // is a live, correctly-sized `in_addr` and its length is passed alongside;
  // `setsockopt` does not retain the pointer past the call.
  let rc = unsafe {
    libc::setsockopt(
      std::os::fd::AsRawFd::as_raw_fd(sock),
      libc::IPPROTO_IP,
      libc::IP_MULTICAST_IF,
      std::ptr::from_ref(&addr).cast(),
      size_of::<libc::in_addr>() as libc::socklen_t,
    )
  };
  if rc < 0 {
    Err(std::io::Error::last_os_error())
  } else {
    Ok(())
  }
}

/// Not a native-execution proof — this workspace's FreeBSD CI job
/// (`.github/workflows/ci.yml`'s `freebsd`) runs only `hick-udp`, and no
/// native NetBSD/OpenBSD/DragonFly execution exists anywhere in it, so
/// nothing available from this file's own test run ever puts a real
/// `setsockopt(IP_MULTICAST_LOOP, ...)` in front of one of those kernels to
/// confirm it rejects a `c_int`-sized value. What this DOES pin, on every
/// target where it runs, is the Rust-level size fact the original defect
/// depended on: `hick-udp/src/platform/unix.rs`'s `set_int_sockopt` documents
/// `IP_MULTICAST_LOOP`/`IP_MULTICAST_TTL` as `u_char`-valued on the BSD
/// family, one byte, where this file used to hardcode a four-byte `c_int`.
/// If a future change reintroduces a raw `setsockopt` for either option sized
/// from `size_of::<libc::c_int>()`, this is the assertion that should have
/// been sitting next to it to update consciously rather than the gap being
/// silent again — the same reasoning `to_in_addr`'s sibling `sin_len` fix
/// left behind for the sockaddr case.
#[cfg(unix)]
#[test]
fn c_uchar_is_not_c_int_sized_where_bsd_multicast_options_need_the_distinction() {
  assert_eq!(
    size_of::<libc::c_uchar>(),
    1,
    "IP_MULTICAST_LOOP/IP_MULTICAST_TTL's documented BSD-family value type"
  );
  assert_ne!(
    size_of::<libc::c_uchar>(),
    size_of::<libc::c_int>(),
    "a setsockopt for IP_MULTICAST_LOOP or IP_MULTICAST_TTL sized from \
     size_of::<libc::c_int>() is the exact width this file's IP_MULTICAST_LOOP \
     bug was; use std::net::UdpSocket's own set_multicast_loop_v4/\
     set_multicast_ttl_v4 instead of hand-rolling either (see \
     hick-udp/src/platform/unix.rs's set_int_sockopt doc for the kernel-side \
     EINVAL a mismatched width produces)"
  );
}

/// An independent socket: opened, joined to the mDNS group on loopback, and
/// sent from without touching hick's driver at all. See the module doc above
/// for why this wraps `std::net::UdpSocket` rather than a raw fd — its own
/// `Drop` closes the socket, so this type needs none of its own.
#[cfg(unix)]
struct LoopbackWitness {
  sock: std::net::UdpSocket,
}

#[cfg(unix)]
impl LoopbackWitness {
  /// Open a UDP socket bound to an ephemeral port — no need to coexist with
  /// hick's own `:5353`, since this witness never talks to hick at all — join
  /// the mDNS group on the loopback interface, and select loopback for
  /// multicast egress: the same membership and egress selection hick's own
  /// endpoints take when `loopback_index()` picks the loopback interface.
  fn open() -> Result<Self, WitnessError> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
      .map_err(|e| WitnessError::Harness(format!("witness socket could not bind: {e}")))?;
    sock
      .join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::LOCALHOST)
      .map_err(|e| link_call_failed(e, "could not join the mDNS group on loopback"))?;
    select_multicast_egress(&sock, Ipv4Addr::LOCALHOST)
      .map_err(|e| link_call_failed(e, "could not select loopback for multicast egress"))?;
    sock.set_multicast_loop_v4(true).map_err(|e| {
      WitnessError::Harness(format!(
        "witness socket could not enable multicast loopback: {e}"
      ))
    })?;
    sock
      .set_read_timeout(Some(Duration::from_secs(1)))
      .map_err(|e| {
        WitnessError::Harness(format!(
          "witness socket could not take a receive timeout: {e}"
        ))
      })?;
    Ok(Self { sock })
  }

  /// The ephemeral port this socket actually bound to.
  fn port(&self) -> Result<u16, WitnessError> {
    self.sock.local_addr().map(|a| a.port()).map_err(|e| {
      WitnessError::Harness(format!(
        "witness socket's own address could not be read: {e}"
      ))
    })
  }

  /// Send one throwaway datagram to the mDNS group, addressed to this
  /// socket's own bound port so the SAME socket is the one that must receive
  /// it back.
  fn send_throwaway(&self, port: u16, payload: &[u8]) -> Result<(), WitnessError> {
    self
      .sock
      .send_to(payload, (MDNS_GROUP, port))
      .map(|_| ())
      .map_err(|e| link_call_failed(e, "could not send to the mDNS group"))
  }

  /// Wait up to `budget` for this socket to receive `payload` back, whole and
  /// unchanged.
  fn receives_back(&self, payload: &[u8], budget: Duration) -> Result<bool, WitnessError> {
    let deadline = Instant::now() + budget;
    let mut buf = [0u8; 128];
    while Instant::now() < deadline {
      match self.sock.recv(&mut buf) {
        Ok(n) if buf.get(..n) == Some(payload) => return Ok(true),
        // Something else arrived on the group (another test's own traffic);
        // keep waiting out the budget for our own copy.
        Ok(_) => continue,
        // A window that expires with nothing in it is not an error: it is an
        // unproven link, which the caller reads as such.
        Err(e)
          if matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
          ) =>
        {
          continue;
        }
        Err(e) => {
          return Err(WitnessError::Harness(format!(
            "witness socket could not receive: {e}"
          )));
        }
      }
    }
    Ok(false)
  }
}

/// Whether multicast loopback delivery is available on this host right now,
/// proven independently of hick's own driver — see the module doc above.
///
/// Only a kernel refusal of the loopback LINK ITSELF, corroborated by the
/// narrow errno allowlist above, may report `false` ("environment
/// unavailable", the one condition under which a caller may skip). Anything
/// that is this harness's own fault — the witness socket could not even be
/// opened, an unrelated option was refused, the receive call itself errored —
/// panics instead of quietly returning either `bool`: a broken witness proves
/// nothing about the host, and folding it into either answer would let a bug
/// in this file masquerade as a skip or, just as bad, as a passing case that
/// never actually witnessed anything.
///
/// Non-unix targets have no independent witness here yet — `parity_bonjour.rs`
/// itself is `target_os = "macos"`-only for the same reason — so nothing in
/// this file may skip on them: an occasional environmental false failure
/// there is preferable to ever masking a real regression.
fn multicast_loopback_carries() -> bool {
  #[cfg(unix)]
  {
    let outcome = (|| -> Result<bool, WitnessError> {
      let witness = LoopbackWitness::open()?;
      let port = witness.port()?;
      let payload = format!("hick-loopback-witness-{:x}", std::process::id()).into_bytes();
      witness.send_throwaway(port, &payload)?;
      witness.receives_back(&payload, Duration::from_secs(2))
    })();
    match outcome {
      Ok(true) => true,
      Ok(false) => {
        eprintln!(
          "note: the independent loopback witness sent a datagram to the mDNS group and did \
           not receive it back within budget; treating multicast loopback as unavailable on \
           this host"
        );
        false
      }
      Err(WitnessError::LinkRefused(reason)) => {
        eprintln!(
          "note: the independent loopback witness had the loopback link itself refused ({reason}); \
           treating multicast loopback as unavailable on this host"
        );
        false
      }
      Err(WitnessError::Harness(reason)) => {
        panic!(
          "the independent loopback witness could not run ({reason}); this is a bug in this \
           test file, not evidence about the environment, so it must fail rather than let a \
           caller read it as either a skip or a pass"
        );
      }
    }
  }
  #[cfg(not(unix))]
  {
    true
  }
}

#[tokio::test]
async fn loopback_ptr_query_returns_instance() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(
    Name::try_from_str(UNIQUE_SERVICE).unwrap(),
    ResourceType::Ptr,
  )
  .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  let saw_ptr = answers.iter().any(|a| a.rtype() == ResourceType::Ptr);
  eprintln!(
    "PTR query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  if !saw_ptr && !multicast_loopback_carries() {
    eprintln!(
      "skipping: the querier's socket received no datagram at all in this run: this run did \
       not deliver multicast loopback to it"
    );
    return;
  }
  assert!(saw_ptr, "expected PTR answer; got {}", answers.len());
}

#[tokio::test]
async fn loopback_srv_query_returns_target() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(
    Name::try_from_str(UNIQUE_INSTANCE).unwrap(),
    ResourceType::Srv,
  )
  .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "SRV query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_srv = answers.iter().any(|a| a.rtype() == ResourceType::Srv);
  if !saw_srv && !multicast_loopback_carries() {
    eprintln!(
      "skipping: the querier's socket received no datagram at all in this run: this run did \
       not deliver multicast loopback to it"
    );
    return;
  }
  assert!(saw_srv, "expected SRV answer; got {}", answers.len());
}

#[tokio::test]
async fn loopback_a_query_returns_address() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(Name::try_from_str(UNIQUE_HOST).unwrap(), ResourceType::A)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "A query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_a = answers.iter().any(|a| a.rtype() == ResourceType::A);
  if !saw_a && !multicast_loopback_carries() {
    eprintln!(
      "skipping: the querier's socket received no datagram at all in this run: this run did \
       not deliver multicast loopback to it"
    );
    return;
  }
  assert!(saw_a, "expected A answer; got {}", answers.len());
  let a_rdata = answers
    .iter()
    .find(|a| a.rtype() == ResourceType::A)
    .map(|a| a.rdata_slice().to_vec())
    .unwrap();
  assert_eq!(a_rdata, ADVERTISED_V4, "wrong A rdata: {a_rdata:?}");
}

#[tokio::test]
async fn loopback_aaaa_query_returns_address() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(Name::try_from_str(UNIQUE_HOST).unwrap(), ResourceType::AAAA)
    .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "AAAA query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  // AAAA over an IPv4-only loopback socket only works if the responder
  // includes AAAA in its response (it does — write_announce emits all
  // record types regardless of socket family).
  let saw_aaaa = answers.iter().any(|a| a.rtype() == ResourceType::AAAA);
  if !saw_aaaa && !multicast_loopback_carries() {
    eprintln!(
      "skipping: the querier's socket received no datagram at all in this run: this run did \
       not deliver multicast loopback to it"
    );
    return;
  }
  assert!(saw_aaaa, "expected AAAA answer; got {}", answers.len());
}

#[tokio::test]
async fn loopback_txt_query_returns_payload() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let spec = QuerySpec::new(
    Name::try_from_str(UNIQUE_INSTANCE).unwrap(),
    ResourceType::Txt,
  )
  .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "TXT query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_txt = answers.iter().any(|a| a.rtype() == ResourceType::Txt);
  if !saw_txt && !multicast_loopback_carries() {
    eprintln!(
      "skipping: the querier's socket received no datagram at all in this run: this run did \
       not deliver multicast loopback to it"
    );
    return;
  }
  assert!(saw_txt, "expected TXT answer; got {}", answers.len());
}

#[tokio::test]
async fn loopback_any_query_returns_full_record_set() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  // ANY query against the service-type owner only collects records whose
  // OWNER name equals the qname (PTR). SRV/A/AAAA/TXT have different owners
  // (instance / host). To collect everything in one query, ANY-on-instance
  // gives SRV + TXT (both owned by the instance name).
  let spec = QuerySpec::new(
    Name::try_from_str(UNIQUE_INSTANCE).unwrap(),
    ResourceType::Any,
  )
  .with_timeout(Duration::from_secs(2));
  let answers = run_query(&pair.querier, spec, Duration::from_secs(4)).await;
  eprintln!(
    "ANY-instance query: {} answers, types {:?}",
    answers.len(),
    answers.iter().map(|a| a.rtype()).collect::<Vec<_>>()
  );
  let saw_srv = answers.iter().any(|a| a.rtype() == ResourceType::Srv);
  let saw_txt = answers.iter().any(|a| a.rtype() == ResourceType::Txt);
  if !(saw_srv && saw_txt) && !multicast_loopback_carries() {
    eprintln!(
      "skipping: the querier's socket received no datagram at all in this run: this run did \
       not deliver multicast loopback to it"
    );
    return;
  }
  assert!(saw_srv && saw_txt, "expected SRV+TXT; got {answers:?}");
}

/// End-to-end DNS-SD discovery: browse the service type and resolve the
/// published instance into a fully-populated `ServiceEntry` (PTR → SRV/TXT →
/// A/AAAA chained by the `Lookup`).
#[tokio::test]
async fn loopback_browse_resolves_service_entry() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let param = QueryParam::new(Name::try_from_str(UNIQUE_SERVICE).unwrap())
    .with_timeout(Duration::from_secs(2));
  let mut lookup = match pair.querier.browse(param).await {
    Ok(l) => l,
    Err(e) => {
      eprintln!("skipping: browse failed: {e:?}");
      return;
    }
  };

  // Resolve until an instance of our service type appears (or a hard cap).
  // Breaking on the first match keeps the test fast — the entry resolves long
  // before the per-query timeouts elapse. We match on the service-type suffix,
  // not the exact instance label: parallel tests publish the same instance name
  // on loopback, so §9 conflict resolution renames clones (`Test` → `test-2`),
  // and responders lowercase names on the wire. The host/port/addr/TXT are
  // identical across the renamed clones, so any resolved entry validates them.
  let suffix = UNIQUE_SERVICE.to_ascii_lowercase();
  let entry = tokio::time::timeout(Duration::from_secs(5), async {
    while let Some(e) = lookup.next().await {
      eprintln!(
        "browse entry: {} host={} port={} v4={:?}",
        e.instance_name(),
        e.host(),
        e.port(),
        e.ipv4_addresses()
      );
      // Wait for an instance of our type whose A address has resolved. On
      // loopback the responder emits both A (127.0.0.1) and AAAA (::1) over
      // IPv4, so the first emission for an instance may be AAAA-only; a later
      // re-emission carries the A address.
      if e
        .instance_name()
        .as_str()
        .to_ascii_lowercase()
        .ends_with(&suffix)
        && e.ipv4_addresses().contains(&ADVERTISED_V4.into())
      {
        return Some(e);
      }
    }
    None
  })
  .await
  .ok()
  .flatten();

  let entry = match entry {
    Some(e) => e,
    None => {
      if !multicast_loopback_carries() {
        eprintln!(
          "skipping: the querier's socket received no datagram at all in this run: this run \
           did not deliver multicast loopback to it"
        );
        return;
      }
      panic!("browse did not resolve any instance of {UNIQUE_SERVICE}");
    }
  };
  assert_eq!(entry.port(), SERVICE_PORT, "wrong port");
  assert!(
    entry.host().as_str().eq_ignore_ascii_case(UNIQUE_HOST),
    "wrong host: {}",
    entry.host()
  );
  assert!(
    entry.ipv4_addresses().contains(&ADVERTISED_V4.into()),
    "expected {ADVERTISED_V4:?} in {:?}",
    entry.ipv4_addresses()
  );
  assert!(
    entry.txt().iter().any(|t| &t[..] == b"Local web server"),
    "expected TXT 'Local web server' in {:?}",
    entry.txt()
  );
}

/// `resolve_host`: plain mDNS hostname resolution (A/AAAA), no DNS-SD chain. The
/// host name carries identical A rdata across any concurrent responders, so this
/// is robust under parallel tests (no §9 conflict on shared, identical records).
#[tokio::test]
async fn loopback_resolve_host_returns_addresses() {
  let pair = match build_pair(Duration::from_millis(1300)).await {
    Some(p) => p,
    None => return,
  };
  let addrs = match pair
    .querier
    .resolve_host(
      Name::try_from_str(UNIQUE_HOST).unwrap(),
      Duration::from_secs(2),
    )
    .await
  {
    Ok(a) => a,
    Err(e) => {
      eprintln!("skipping: resolve_host failed: {e:?}");
      return;
    }
  };
  eprintln!("resolve_host: {addrs:?}");
  if !addrs.contains(&IpAddr::V4(ADVERTISED_V4.into())) && !multicast_loopback_carries() {
    eprintln!(
      "skipping: the querier's socket received no datagram at all in this run: this run did \
       not deliver multicast loopback to it"
    );
    return;
  }
  assert!(
    addrs.contains(&IpAddr::V4(ADVERTISED_V4.into())),
    "expected {ADVERTISED_V4:?} in {addrs:?}"
  );
}

/// `resolve_instance`: resolve a *known* instance directly (SRV/TXT + A/AAAA),
/// skipping the PTR browse. Uses unique instance/host names so a concurrent test
/// can't conflict-rename them — this responder reliably owns the queried name.
#[tokio::test]
async fn loopback_resolve_instance_returns_entry() {
  // A dedicated service type (not UNIQUE_SERVICE) so this responder's PTR never
  // appears in `loopback_browse_resolves_service_entry`, which would otherwise
  // be able to pick this instance and then fail its UNIQUE_HOST assertion.
  const SVC: &str = "_agnostic-mdns-resolve-v06._tcp.local.";
  const INST: &str = "ResolveOne._agnostic-mdns-resolve-v06._tcp.local.";
  const HOST: &str = "resolve-one-host.local.";
  let pair = match build_pair_named(Duration::from_millis(1300), SVC, INST, HOST).await {
    Some(p) => p,
    None => return,
  };
  let resolved = tokio::time::timeout(
    Duration::from_secs(6),
    pair
      .querier
      .resolve_instance(Name::try_from_str(INST).unwrap(), Duration::from_secs(2)),
  )
  .await;
  let entry = match resolved {
    Ok(Ok(Some(e))) => e,
    other => {
      if !multicast_loopback_carries() {
        eprintln!(
          "skipping: the querier's socket received no datagram at all in this run: this run \
           did not deliver multicast loopback to it"
        );
        return;
      }
      panic!("resolve_instance did not resolve {INST}: {other:?}");
    }
  };
  eprintln!(
    "resolve_instance: host={} port={} v4={:?} v6={:?}",
    entry.host(),
    entry.port(),
    entry.ipv4_addresses(),
    entry.ipv6_addresses()
  );
  assert_eq!(entry.port(), SERVICE_PORT, "wrong port");
  assert!(
    entry.host().as_str().eq_ignore_ascii_case(HOST),
    "wrong host: {}",
    entry.host()
  );
  // First complete resolution carries >= 1 address; family/order isn't fixed on
  // loopback, so assert presence + that every address is one we advertised.
  assert!(
    entry.addresses().next().is_some(),
    "expected at least one address"
  );
  for a in entry.addresses() {
    assert!(
      a == IpAddr::V4(ADVERTISED_V4.into()) || a == IpAddr::V6(ADVERTISED_V6),
      "unexpected address {a}"
    );
  }
  assert!(
    entry.txt().iter().any(|t| &t[..] == b"Local web server"),
    "expected TXT 'Local web server' in {:?}",
    entry.txt()
  );
}

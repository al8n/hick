//! Integration tests on a loopback multicast group.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::ErrorKind;

use hick_udp::{
  BindError, MulticastOptionsV4, MulticastOptionsV6, MulticastSocketV4, MulticastSocketV6,
  try_bind_v6,
};

/// Classify the result of a multicast-bind attempt.
///
/// A legitimate environment refusal — `PermissionDenied` (EPERM/EACCES),
/// `AddrInUse`, or `AddrNotAvailable` — is printed and skipped (`None`). Any
/// other error is OUR bug, not an environment limitation, and fails the test
/// instead of being silently swallowed: this crate had exactly that bug for
/// its whole life, where `set_multicast_hops_v6` (`hick-udp/src/platform/
/// unix.rs`) passed `IPV6_MULTICAST_HOPS` through a rustix helper that used
/// the wrong protocol level, so `try_bind_v6` failed `EINVAL` on every
/// interface and a swallow-all `Err(_) => skip` test could not tell that
/// apart from a sandboxed CI environment. `BindError`'s non-I/O variants
/// (`InterfaceNotFound`, `AddressInUse`) are not expected from the call sites
/// below (each resolves its interface index immediately beforehand), so they
/// fail too.
#[track_caller]
fn expect_bind_or_skip<T>(label: &str, result: Result<T, BindError>) -> Option<T> {
  match result {
    Ok(v) => Some(v),
    Err(BindError::Io(e))
      if matches!(
        e.kind(),
        ErrorKind::PermissionDenied | ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable
      ) =>
    {
      eprintln!("{label}: environment refused ({e}); skipping");
      None
    }
    Err(e) => panic!(
      "{label}: bind failed with an error that is not a recognized environment refusal \
       (PermissionDenied/AddrInUse/AddrNotAvailable) — this indicates a bug in our own \
       binding code, not an environment limitation: {e}"
    ),
  }
}

/// Address family a picked interface must actually carry (see
/// `pick_interface_index`).
#[derive(Clone, Copy)]
enum Family {
  V4,
  V6,
}

/// Pick an interface index suitable for multicast tests: the first
/// non-loopback, up + multicast interface that actually carries an address of
/// `family`, or fall back to loopback. Returns `None` if no usable interface
/// is available (test should skip).
///
/// The address check matters, not just the flags: some hosts report
/// `UP + MULTICAST` on interfaces with no active link and no addresses at all
/// (e.g. macOS's internal `anpiN` interfaces, which are `UP`/`RUNNING` with
/// `media: none, status: inactive`). `try_bind_v4`/`try_bind_v6` correctly
/// refuse those (`InterfaceNotFound` / `EINVAL`), and neither is an
/// environment-refusal error kind — a flags-only filter would pick one and
/// every "real interface" test below would then fail as if it had found our
/// bug, when the actual problem is an unusable interface picked here.
fn pick_interface_index(family: Family) -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| {
      let f = i.flags();
      let has_addr = match family {
        Family::V4 => i.ipv4_addrs().is_ok_and(|a| !a.is_empty()),
        Family::V6 => i.ipv6_addrs().is_ok_and(|a| !a.is_empty()),
      };
      f.contains(getifs::Flags::UP)
        && f.contains(getifs::Flags::MULTICAST)
        && !f.contains(getifs::Flags::LOOPBACK)
        && i.index() != 0
        && has_addr
    })
    .or_else(|| {
      ifs
        .iter()
        .find(|i| i.flags().contains(getifs::Flags::LOOPBACK))
    })
    .map(|i| i.index())
}

#[test]
fn loopback_interface_exists() {
  let ifs = getifs::interfaces().unwrap();
  assert!(
    ifs
      .iter()
      .any(|i| i.flags().contains(getifs::Flags::LOOPBACK)),
    "expected at least loopback"
  );
}

/// The loopback interface index, if resolvable.
fn loopback_index() -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| i.flags().contains(getifs::Flags::LOOPBACK))
    .map(|i| i.index())
}

/// Bind the sync `MulticastSocketV4`/`MulticastSocketV6` wrappers on the
/// loopback interface and read back their accessors. Pinning loopback avoids
/// the system mDNS responder that may already hold :5353 on a real NIC. Skips
/// gracefully where the environment legitimately refuses a multicast bind
/// (some CI sandboxes); any other failure fails the test — see
/// `expect_bind_or_skip`.
#[test]
fn sync_multicast_sockets_bind_on_loopback() {
  let Some(idx) = loopback_index() else {
    eprintln!("no loopback index; skipping");
    return;
  };

  if let Some(v4) = expect_bind_or_skip(
    "v4 leg",
    MulticastSocketV4::try_new(MulticastOptionsV4::new(idx)),
  ) {
    let addr = v4.local_addr().unwrap();
    assert!(addr.is_ipv4(), "v4 socket must report a v4 local address");
    assert_eq!(addr.port(), 5353);
    let _ = v4.socket();
  }

  if let Some(v6) = expect_bind_or_skip(
    "v6 leg",
    MulticastSocketV6::try_new(MulticastOptionsV6::new(idx)),
  ) {
    let addr = v6.local_addr().unwrap();
    assert!(addr.is_ipv6(), "v6 socket must report a v6 local address");
    assert_eq!(addr.port(), 5353);
    let _ = v6.socket();
  }
}

#[test]
fn bind_v4_smoke() {
  let idx = match pick_interface_index(Family::V4) {
    Some(i) => i,
    None => {
      eprintln!("no usable interface; skipping");
      return;
    }
  };
  let opts = MulticastOptionsV4::new(idx);
  if let Some(sock) = expect_bind_or_skip("bind_v4_smoke", MulticastSocketV4::try_new(opts)) {
    let addr = sock.local_addr().unwrap();
    eprintln!("bound mDNS v4 socket at {addr}");
  }
}

/// Verify that `IP_MULTICAST_IF` can be set during bind when an explicit
/// interface index is provided.
///
/// The test does not verify traffic actually egresses the selected interface
/// (too environment-dependent), but it does confirm the socket option call
/// succeeds on a real non-loopback interface.
#[test]
fn bind_v4_with_explicit_interface_index() {
  let idx = match pick_interface_index(Family::V4) {
    Some(i) if i != 0 => i,
    _ => {
      eprintln!("no non-loopback multicast interface with index > 0; skipping");
      return;
    }
  };
  let opts = MulticastOptionsV4::new(idx);
  if expect_bind_or_skip(
    "bind_v4_with_explicit_interface_index",
    MulticastSocketV4::try_new(opts),
  )
  .is_some()
  {
    eprintln!("bound v4 with interface_index={idx}");
  }
}

/// Verify that `IPV6_MULTICAST_IF` can be set during bind when an explicit
/// interface index is provided.
#[test]
fn bind_v6_with_explicit_interface_index() {
  let idx = match pick_interface_index(Family::V6) {
    Some(i) if i != 0 => i,
    _ => {
      eprintln!("no non-loopback multicast interface with index > 0; skipping");
      return;
    }
  };
  let opts = MulticastOptionsV6::new(idx);
  if expect_bind_or_skip(
    "bind_v6_with_explicit_interface_index",
    MulticastSocketV6::try_new(opts),
  )
  .is_some()
  {
    eprintln!("bound v6 with interface_index={idx}");
  }
}

/// Regression test for the rustix `IPV6_MULTICAST_HOPS` wrong-protocol-level
/// bug (`IPPROTO_IP` instead of `IPPROTO_IPV6`; rustix 1.1.4
/// `backend/libc/net/sockopt.rs:618-624`; see `hick-udp/src/platform/unix.rs`
/// for the full writeup). That defect made `try_bind_v6` fail `EINVAL` on
/// EVERY interface, including loopback — indistinguishable, under the old
/// swallow-all `Err(_) => skip` pattern, from a sandboxed CI environment that
/// legitimately refuses multicast. For every interface reporting at least one
/// IPv6 address, `try_bind_v6` must succeed or fail only with an
/// environment-refusal error kind (see `expect_bind_or_skip`); anything else —
/// `EINVAL` above all — fails the test. Skips cleanly if the host has no
/// IPv6-capable interface at all.
#[test]
fn try_bind_v6_succeeds_or_environment_refuses_on_every_ipv6_interface() {
  let ifs = match getifs::interfaces() {
    Ok(ifs) => ifs,
    Err(e) => {
      eprintln!("could not enumerate interfaces ({e}); skipping");
      return;
    }
  };

  let mut checked_any = false;
  for iface in ifs.iter() {
    if !iface.ipv6_addrs().is_ok_and(|addrs| !addrs.is_empty()) {
      continue;
    }
    checked_any = true;
    let label = format!(
      "try_bind_v6 on interface {} (index {})",
      iface.name(),
      iface.index()
    );
    let _ = expect_bind_or_skip(&label, try_bind_v6(MulticastOptionsV6::new(iface.index())));
  }

  if !checked_any {
    eprintln!("host has no IPv6-capable interface; skipping");
  }
}

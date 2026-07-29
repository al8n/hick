//! Integration tests on a loopback multicast group.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::ErrorKind;

use hick_udp::{
  BindError, MulticastOptionsV4, MulticastOptionsV6, MulticastSocketV4, MulticastSocketV6,
  try_bind_v6,
};

/// Whether `e` represents a legitimate environment refusal rather than our
/// own bug: `PermissionDenied` (EPERM/EACCES), `AddrInUse`, `AddrNotAvailable`
/// — or, on Unix only, `EAFNOSUPPORT` (errno-matched, not a broad `ErrorKind`:
/// this is what a host with IPv6 disabled at the kernel level reports for an
/// `AF_INET6` socket, e.g. Linux's `net.ipv6.conf.all.disable_ipv6=1`, and
/// `std` does not map it to any of the three `ErrorKind`s above). Anything
/// else — `EINVAL` above all — is our own bug, never an environment
/// limitation: this crate had exactly that bug for its whole life, where
/// `set_multicast_hops_v6` (`hick-udp/src/platform/unix.rs`) passed
/// `IPV6_MULTICAST_HOPS` through a rustix helper that used the wrong protocol
/// level, so `try_bind_v6` failed `EINVAL` on every interface and a
/// swallow-all `Err(_) => skip` test could not tell that apart from a
/// sandboxed CI environment.
fn is_environment_refusal(e: &std::io::Error) -> bool {
  if matches!(
    e.kind(),
    ErrorKind::PermissionDenied | ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable
  ) {
    return true;
  }
  #[cfg(unix)]
  if e.raw_os_error() == Some(libc::EAFNOSUPPORT) {
    return true;
  }
  false
}

/// Classify the result of a multicast-bind attempt via
/// [`is_environment_refusal`]: a refusal is printed and skipped (`None`); any
/// other error is OUR bug and fails the test instead of being silently
/// swallowed. `BindError`'s non-I/O variants (`InterfaceNotFound`,
/// `AddressInUse`) are not expected from the call sites below (each resolves
/// its interface index immediately beforehand), so they fail too.
#[track_caller]
fn expect_bind_or_skip<T>(label: &str, result: Result<T, BindError>) -> Option<T> {
  match result {
    Ok(v) => Some(v),
    Err(BindError::Io(e)) if is_environment_refusal(&e) => {
      eprintln!("{label}: environment refused ({e}); skipping");
      None
    }
    Err(e) => panic!(
      "{label}: bind failed with an error that is not a recognized environment refusal \
       — this indicates a bug in our own binding code, not an environment limitation: {e}"
    ),
  }
}

/// Address family a picked interface must actually carry (see
/// `pick_interface_index`/`loopback_index`).
#[derive(Clone, Copy)]
enum Family {
  V4,
  V6,
}

impl Family {
  /// Whether `iface` carries at least one address of this family.
  ///
  /// An address-enumeration error is never treated as a match, but it is also
  /// never silently conflated with a genuinely empty address list: it is
  /// printed, so a host where `ipv4_addrs`/`ipv6_addrs` itself errors (as
  /// opposed to one that simply has no addresses of that family) is visible
  /// on stderr instead of looking identical to "no address" — the same kind
  /// of silent narrowing this whole file exists to remove.
  fn is_carried_by(self, iface: &getifs::Interface) -> bool {
    let (name, result) = match self {
      Family::V4 => ("IPv4", iface.ipv4_addrs().map(|a| !a.is_empty())),
      Family::V6 => ("IPv6", iface.ipv6_addrs().map(|a| !a.is_empty())),
    };
    result.unwrap_or_else(|e| {
      eprintln!(
        "could not enumerate {name} addresses on interface {}: {e}",
        iface.name()
      );
      false
    })
  }
}

/// Pick an interface index suitable for multicast tests: the first
/// non-loopback, up + multicast interface that actually carries an address of
/// `family`, or fall back to a loopback interface that also carries one.
/// Returns `None` if no usable interface is available (test should skip).
///
/// The address check matters, not just the flags: some hosts report
/// `UP + MULTICAST` on interfaces with no active link and no addresses at all
/// (e.g. macOS's internal `anpiN` interfaces: `UP`/`RUNNING` with
/// `media: none, status: inactive`). `try_bind_v4` has an explicit, guaranteed
/// contract for this: `ipv4_addr_for_index` resolves no address, so it
/// returns `BindError::InterfaceNotFound`. `try_bind_v6` has no equivalent
/// resolution step and NO guaranteed error kind for an addressless interface
/// — do not assume it is `EINVAL`, and do not treat "an addressless interface
/// was picked" as license to widen `is_environment_refusal`'s allowlist: a
/// real `EINVAL` from `try_bind_v6` may be exactly this crate's
/// wrong-protocol-level rustix bug, and only the allowlisted error kinds may
/// decide that — never a guess about the cause. A flags-only filter would
/// pick one of these unusable interfaces, and every "real interface" test
/// below would then fail as if it had found our bug, when the actual problem
/// is the interface picked here.
///
/// The fallback also requires `family` on the loopback candidate: on a host
/// with IPv6 disabled at the kernel level (e.g. Linux
/// `net.ipv6.conf.all.disable_ipv6=1`), `lo` carries no `::1`, and binding it
/// anyway would fail with an error `is_environment_refusal` may not
/// recognize — so a family-blind fallback would make the v6 tests depend on
/// the runner having IPv6 at all, exactly the dependency this test suite
/// should not have.
fn pick_interface_index(family: Family) -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| {
      let f = i.flags();
      f.contains(getifs::Flags::UP)
        && f.contains(getifs::Flags::MULTICAST)
        && !f.contains(getifs::Flags::LOOPBACK)
        && i.index() != 0
        && family.is_carried_by(i)
    })
    .or_else(|| {
      ifs
        .iter()
        .find(|i| i.flags().contains(getifs::Flags::LOOPBACK) && family.is_carried_by(i))
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

/// The loopback interface index, if it carries an address of `family`.
/// Returns `None` if there is no loopback interface at all, or it exists but
/// doesn't carry that family (e.g. IPv6 disabled at the kernel level, so `lo`
/// has no `::1` — see `pick_interface_index`'s doc for why this must be
/// family-aware rather than assuming loopback always has both).
fn loopback_index(family: Family) -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| i.flags().contains(getifs::Flags::LOOPBACK) && family.is_carried_by(i))
    .map(|i| i.index())
}

/// Bind the sync `MulticastSocketV4`/`MulticastSocketV6` wrappers on the
/// loopback interface and read back their accessors. Pinning loopback avoids
/// the system mDNS responder that may already hold :5353 on a real NIC. Skips
/// gracefully where the environment legitimately refuses a multicast bind, or
/// has no loopback address of a given family (some CI sandboxes); any other
/// failure fails the test — see `expect_bind_or_skip`. The two legs resolve
/// their loopback index independently since a host can have one family but
/// not the other on `lo`.
#[test]
fn sync_multicast_sockets_bind_on_loopback() {
  match loopback_index(Family::V4) {
    Some(idx) => {
      if let Some(v4) = expect_bind_or_skip(
        "v4 leg",
        MulticastSocketV4::try_new(MulticastOptionsV4::new(idx)),
      ) {
        let addr = v4.local_addr().unwrap();
        assert!(addr.is_ipv4(), "v4 socket must report a v4 local address");
        assert_eq!(addr.port(), 5353);
        let _ = v4.socket();
      }
    }
    None => eprintln!("no IPv4-capable loopback index; skipping v4 leg"),
  }

  match loopback_index(Family::V6) {
    Some(idx) => {
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
    None => eprintln!("no IPv6-capable loopback index; skipping v6 leg"),
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
/// environment-refusal error kind (see `is_environment_refusal`); anything
/// else — `EINVAL` above all — fails the test. Skips cleanly if the host has
/// no IPv6-capable interface at all.
///
/// Reports how many of the checked interfaces actually bound, not just that
/// none of them failed: on a fully sandboxed host every leg legitimately
/// skips and the test would otherwise pass green without showing the fix did
/// anything observable. The final line makes "every interface bound" and
/// "every interface refused" distinguishable without re-running with
/// `--nocapture` and reading each per-interface line.
#[test]
fn try_bind_v6_succeeds_or_environment_refuses_on_every_ipv6_interface() {
  let ifs = match getifs::interfaces() {
    Ok(ifs) => ifs,
    Err(e) => {
      eprintln!("could not enumerate interfaces ({e}); skipping");
      return;
    }
  };

  let mut checked = 0u32;
  let mut bound = 0u32;
  for iface in ifs.iter() {
    if !Family::V6.is_carried_by(iface) {
      continue;
    }
    checked += 1;
    let label = format!(
      "try_bind_v6 on interface {} (index {})",
      iface.name(),
      iface.index()
    );
    if expect_bind_or_skip(&label, try_bind_v6(MulticastOptionsV6::new(iface.index()))).is_some() {
      bound += 1;
    }
  }

  if checked == 0 {
    eprintln!("host has no IPv6-capable interface; skipping");
  } else {
    eprintln!("try_bind_v6 succeeded on {bound}/{checked} IPv6-capable interface(s)");
  }
}

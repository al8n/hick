//! Integration tests on a loopback multicast group.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::ErrorKind;

use hick_udp::{
  BindError, MulticastOptionsV4, MulticastOptionsV6, MulticastSocketV4, MulticastSocketV6,
  try_bind_v6,
};

// ============================================================================
// PAIRED CLASSIFIER — this function has a sibling copy, `is_environment_refusal`,
// in `hick-udp/src/multicast.rs` (the library's own unit tests). The two must
// classify identically. If you change the allowlist here (add/remove an
// `ErrorKind` or a raw-errno arm), make the SAME change there, and vice
// versa. See that copy's doc for why this crate keeps two copies rather than
// sharing one definition.
// ============================================================================
/// Whether `e` represents a legitimate environment refusal rather than our
/// own bug: `PermissionDenied` (EPERM/EACCES), `AddrInUse`, `AddrNotAvailable`
/// — or an errno-matched "address family not supported" on the two platform
/// families this crate compiles for: Unix `EAFNOSUPPORT`, or Windows
/// `WSAEAFNOSUPPORT`. Both are errno-matched, not a broad `ErrorKind`, and
/// deliberately so: this is what a host with IPv6 disabled reports for an
/// `AF_INET6` socket (e.g. Linux's `net.ipv6.conf.all.disable_ipv6=1`, or an
/// IPv6-unavailable Windows runner), and `std` does not map either to any of
/// the three `ErrorKind`s above — Windows' `WSAEAFNOSUPPORT` in particular
/// maps to no NAMEABLE stable `ErrorKind` at all (std's internal bookkeeping
/// calls that bucket `Uncategorized`, but that variant is
/// `#[unstable]`/`#[doc(hidden)]`, so it cannot be matched from this crate —
/// which is exactly why this is a raw `raw_os_error()` comparison, not an
/// `ErrorKind` one). Anything else — `EINVAL`/`WSAEINVAL` above all — is our
/// own bug, never an environment limitation: this crate had exactly that bug
/// for its whole life, where `set_multicast_hops_v6`
/// (`hick-udp/src/platform/unix.rs`) passed `IPV6_MULTICAST_HOPS` through a
/// rustix helper that used the wrong protocol level, so `try_bind_v6` failed
/// `EINVAL` on every interface and a swallow-all `Err(_) => skip` test could
/// not tell that apart from a sandboxed CI environment. Do NOT widen this to
/// `ErrorKind::Uncategorized` or `ErrorKind::InvalidInput` to "simplify" the
/// Windows case — either would re-admit `EINVAL`/`WSAEINVAL`.
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
  #[cfg(windows)]
  if e.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEAFNOSUPPORT) {
    return true;
  }
  false
}

// PAIRED CLASSIFIER TESTS — `hick-udp/src/multicast.rs` has an identical
// `is_environment_refusal_classifier_tests` module for its own copy. Extend
// both whenever a new platform/errno is added to either classifier.
mod is_environment_refusal_classifier_tests {
  use super::is_environment_refusal;

  #[cfg(windows)]
  #[test]
  fn recognizes_wsaeafnosupport() {
    let e =
      std::io::Error::from_raw_os_error(windows_sys::Win32::Networking::WinSock::WSAEAFNOSUPPORT);
    assert!(
      is_environment_refusal(&e),
      "WSAEAFNOSUPPORT (10047) must be recognized as an environment refusal, or an \
       IPv6-unavailable Windows runner fails these tests instead of skipping them"
    );
  }

  #[cfg(windows)]
  #[test]
  fn rejects_wsaeinval() {
    let e = std::io::Error::from_raw_os_error(windows_sys::Win32::Networking::WinSock::WSAEINVAL);
    assert!(
      !is_environment_refusal(&e),
      "WSAEINVAL (10022) must never be classified as an environment refusal"
    );
  }

  #[cfg(unix)]
  #[test]
  fn recognizes_eafnosupport() {
    let e = std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT);
    assert!(
      is_environment_refusal(&e),
      "EAFNOSUPPORT must be recognized as an environment refusal"
    );
  }

  #[cfg(unix)]
  #[test]
  fn rejects_einval() {
    let e = std::io::Error::from_raw_os_error(libc::EINVAL);
    assert!(
      !is_environment_refusal(&e),
      "EINVAL must never be classified as an environment refusal — it is the exact errno the \
       rustix wrong-protocol-level bug produced on macOS, which this whole branch exists to \
       stop silently skipping"
    );
  }
}

/// Classify the result of a multicast-bind attempt via
/// [`is_environment_refusal`]: a refusal is printed and skipped (`None`); any
/// other error is OUR bug and fails the test instead of being silently
/// swallowed. `BindError`'s non-I/O variants (e.g. `InterfaceNotFound`) are
/// not expected from the call sites below (each resolves its interface index
/// immediately beforehand), so they fail too.
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

/// Read back the kernel's actual `IPV6_MULTICAST_HOPS` value for `sock` via a
/// direct `libc::getsockopt` call at the CORRECT level (`IPPROTO_IPV6`).
///
/// Deliberately does NOT use `rustix::net::sockopt::ipv6_multicast_hops`:
/// that getter carries the identical wrong-protocol-level defect as the
/// setter this whole fix exists to work around (rustix 1.1.4
/// `backend/libc/net/sockopt.rs:624`, `backend/linux_raw/net/sockopt.rs:575`
/// — both read `IPPROTO_IP`/`IPV6_MULTICAST_HOPS` instead of
/// `IPPROTO_IPV6`/`IPV6_MULTICAST_HOPS`). On Linux, `IPPROTO_IP` optname 18 is
/// `IP_PASSSEC` — a live, unrelated boolean option — so reading back through
/// rustix's getter would report that socket's own collateral state as if it
/// were the hop limit: the exact trap a future reader would fall into, since
/// it looks like a normal, working read-back while actually validating
/// nothing about the real `IPPROTO_IPV6` hop limit at all. Route around
/// rustix here too, for the read, not just the write.
///
/// This is what makes the regression test below able to catch the bug on
/// Linux: there, the wrong-level `setsockopt` call does not fail (unlike
/// macOS's `EINVAL`) because `IPPROTO_IP`/18 is a valid, settable option
/// (`IP_PASSSEC`) — it just silently leaves the real IPv6 multicast hop limit
/// at its default of 1 instead of the 255 RFC 6762 §11 requires, which a bare
/// `try_bind_v6(...).is_ok()` assertion cannot detect. Reading the value back
/// through the correct level can.
///
/// `hick_udp` itself now performs the identical read-back internally (see
/// `crate::multicast::verify_multicast_hops_v6` in `hick-udp/src/
/// multicast.rs`) and fails the bind outright on a mismatch, so every check
/// below that compares against this helper is, by construction, redundant
/// with a check the library already made before returning `Ok`. It stays: an
/// external, independent read-back is still worth having as defense in
/// depth, and it is what lets this suite assert the OBSERVABLE property
/// (`bind succeeded` ⇒ `hops are correct`) without reaching into the
/// library's internals.
///
/// What this integration-test crate still cannot do is drive the library's
/// verification down its failure path FROM HERE: no input reachable through
/// the public API (`MulticastOptionsV6`/`try_bind_v6`) can make the setter
/// and the verifier disagree on a correctly functioning kernel, since
/// `try_bind_v6_inner` hands them the same `opts.hops()` value. That failure
/// path — both the comparison logic in isolation, and the full production
/// call sequence via a dedicated `#[cfg(test)]` seam
/// (`FORCE_APPLIED_HOPS_V6`) — is exercised by
/// `verify_multicast_hops_v6_rejects_a_kernel_value_that_drifted_from_the_request`
/// and `try_bind_v6_rejects_a_mismatch_forced_through_production_wiring` in
/// `hick-udp/src/multicast/tests.rs`, which have access to the crate's
/// private internals that this file, as a separate integration-test crate,
/// does not.
#[cfg(unix)]
fn read_multicast_hops_v6(sock: &std::net::UdpSocket) -> std::io::Result<u8> {
  use std::os::fd::AsRawFd;

  let mut value: libc::c_int = 0;
  let mut len: libc::socklen_t = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
  // SAFETY: `sock` is a valid, open UDP socket for the duration of this call.
  // `value` and `len` are live locals sized exactly for a `c_int`-valued
  // option; getsockopt writes back at most `len` bytes into `value` and
  // updates `len` to the size it actually wrote, both within the buffer we
  // provided. No pointer is retained past the call.
  let rc = unsafe {
    libc::getsockopt(
      sock.as_raw_fd(),
      libc::IPPROTO_IPV6,
      libc::IPV6_MULTICAST_HOPS,
      core::ptr::addr_of_mut!(value).cast(),
      core::ptr::addr_of_mut!(len),
    )
  };
  if rc != 0 {
    return Err(std::io::Error::last_os_error());
  }
  Ok(value as u8)
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
/// contract for this: an interface that resolves no IPv4 address gives
/// `BindError::InterfaceNotFound`. `try_bind_v6` guarantees that only for an
/// index that names NO INTERFACE; an interface that exists and reports no IPv6
/// address is a warned proceed there, so that bind may well succeed, and if it
/// fails it fails further downstream with NO guaranteed error kind — do not
/// assume it is `EINVAL`, and do not treat "an addressless interface was
/// picked" as license to widen `is_environment_refusal`'s allowlist: a real
/// `EINVAL` from `try_bind_v6` may be exactly this crate's
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
  let expected_hops = opts.hops();
  if let Some(sock) = expect_bind_or_skip(
    "bind_v6_with_explicit_interface_index",
    MulticastSocketV6::try_new(opts),
  ) {
    // Assert the OBSERVABLE effect, not just that the bind call returned Ok:
    // see `read_multicast_hops_v6` for why a bare success check cannot catch
    // the Linux form of the rustix bug.
    #[cfg(unix)]
    {
      let actual_hops = read_multicast_hops_v6(sock.socket()).unwrap_or_else(|e| {
        panic!(
          "bind_v6_with_explicit_interface_index: bind succeeded but could not read back \
           IPV6_MULTICAST_HOPS: {e}"
        )
      });
      assert_eq!(
        actual_hops, expected_hops,
        "bind_v6_with_explicit_interface_index: IPV6_MULTICAST_HOPS was not actually applied \
         — kernel reports {actual_hops}, expected {expected_hops}. A sockopt call can report \
         success while silently hitting an unrelated option instead of the real hop limit."
      );
    }
    #[cfg(not(unix))]
    let _ = &sock;
    eprintln!("bound v6 with interface_index={idx}, expected hops={expected_hops}");
  }
}

/// Regression test for the rustix `IPV6_MULTICAST_HOPS` wrong-protocol-level
/// bug (`IPPROTO_IP` instead of `IPPROTO_IPV6`; rustix 1.1.4
/// `backend/libc/net/sockopt.rs:618-624`; see `hick-udp/src/platform/unix.rs`
/// for the full writeup). That defect made `try_bind_v6` fail `EINVAL` on
/// EVERY interface, including loopback, on macOS/BSD — indistinguishable,
/// under the old swallow-all `Err(_) => skip` pattern, from a sandboxed CI
/// environment that legitimately refuses multicast.
///
/// On Linux the SAME defect is silent, not loud, and a bare "did the call
/// return Ok" check cannot catch it: `IPV6_MULTICAST_HOPS` is 18 there, and
/// `IPPROTO_IP`/18 is `IP_PASSSEC`, a real, settable, unrelated boolean
/// option — so the wrong-level `setsockopt` call succeeds, `try_bind_v6`
/// returns `Ok`, and the real IPv6 multicast hop limit silently stays at its
/// default of 1 instead of the 255 RFC 6762 §11 requires (conforming
/// receivers, including this crate's own on-link check, drop anything else).
/// This is why every bind below is followed by an OBSERVABLE-effect check —
/// see `read_multicast_hops_v6` — not just a success check: for every
/// interface reporting at least one IPv6 address, `try_bind_v6` must succeed
/// with the requested hop limit actually applied, or fail only with an
/// environment-refusal error kind (see `is_environment_refusal`); anything
/// else — `EINVAL`, or a successful bind with the wrong hop limit — fails the
/// test. Skips cleanly if the host has no IPv6-capable interface at all.
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
    let opts = MulticastOptionsV6::new(iface.index());
    let expected_hops = opts.hops();
    let label = format!(
      "try_bind_v6 on interface {} (index {}, expecting hops={expected_hops})",
      iface.name(),
      iface.index()
    );
    if let Some(sock) = expect_bind_or_skip(&label, try_bind_v6(opts)) {
      bound += 1;
      // Assert the OBSERVABLE effect, not just that the call returned Ok —
      // see this function's doc and `read_multicast_hops_v6` for why: on
      // Linux, the wrong-level bug silently succeeds without ever touching
      // the real hop limit.
      #[cfg(unix)]
      {
        let actual_hops = read_multicast_hops_v6(&sock).unwrap_or_else(|e| {
          panic!("{label}: bind succeeded but could not read back IPV6_MULTICAST_HOPS: {e}")
        });
        assert_eq!(
          actual_hops, expected_hops,
          "{label}: IPV6_MULTICAST_HOPS was not actually applied — kernel reports \
           {actual_hops}, expected {expected_hops}. A sockopt call can report success while \
           silently hitting an unrelated option (e.g. Linux IPPROTO_IP/18 = IP_PASSSEC) \
           instead of the real hop limit."
        );
      }
      #[cfg(not(unix))]
      let _ = &sock;
    }
  }

  if checked == 0 {
    eprintln!("host has no IPv6-capable interface; skipping");
  } else {
    eprintln!("try_bind_v6 succeeded on {bound}/{checked} IPv6-capable interface(s)");
  }
}

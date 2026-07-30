use super::is_environment_refusal;

// What this module exists to guard against: an IPv6-unavailable Windows
// runner reports WSAEAFNOSUPPORT, which maps to no named, stable
// `ErrorKind` (std's internal bookkeeping calls this bucket
// `Uncategorized`, but that variant is `#[unstable]`/`#[doc(hidden)]` and
// cannot be named from this crate — which is exactly why the fix is a raw
// `raw_os_error()` match, not a broadened `ErrorKind` match). Without the
// `#[cfg(windows)]` arm in `is_environment_refusal`, this case fell through
// to `false`, and every all-platform unit test that binds v6 with no
// preceding IPv6-availability check would panic instead of skipping.
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

// The overcorrection this module ALSO guards against: broadening the
// allowlist to catch WSAEAFNOSUPPORT must not accidentally catch
// WSAEINVAL too — that is Windows' shape of the ORIGINAL defect this whole
// branch exists to stop hiding (rustix passing the wrong protocol level
// produced EINVAL on macOS; the equivalent wrong-level mistake on Windows
// would produce WSAEINVAL). A skip arm that swallows this recreates the
// original defect, just on a different platform.
#[cfg(windows)]
#[test]
fn rejects_wsaeinval() {
  let e = std::io::Error::from_raw_os_error(windows_sys::Win32::Networking::WinSock::WSAEINVAL);
  assert!(
    !is_environment_refusal(&e),
    "WSAEINVAL (10022) must never be classified as an environment refusal"
  );
}

// Unix-side mirror of the two Windows tests above, for symmetry: proves
// the allowlist is complete AND not overcorrected on this platform family
// too, with an executable check rather than only a source-level audit.
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

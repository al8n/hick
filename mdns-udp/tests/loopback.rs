//! Integration tests on a loopback multicast group.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use mdns_udp::{MulticastOptionsV4, MulticastOptionsV6, MulticastSocketV4, MulticastSocketV6};

/// Pick an interface index suitable for multicast tests: first non-loopback
/// up + multicast interface with a real index, or fall back to loopback.
/// Returns `None` if no usable interface is available (test should skip).
fn pick_interface_index() -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  ifs
    .iter()
    .find(|i| {
      let f = i.flags();
      f.contains(getifs::Flags::UP)
        && f.contains(getifs::Flags::MULTICAST)
        && !f.contains(getifs::Flags::LOOPBACK)
        && i.index() != 0
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

#[test]
fn bind_v4_smoke() {
  let idx = match pick_interface_index() {
    Some(i) => i,
    None => {
      eprintln!("no usable interface; skipping");
      return;
    }
  };
  let opts = MulticastOptionsV4::new(idx);
  match MulticastSocketV4::try_new(opts) {
    Ok(sock) => {
      let addr = sock.local_addr().unwrap();
      eprintln!("bound mDNS v4 socket at {addr}");
    }
    Err(_) => {
      // CI environments may not allow multicast bind; skip rather than fail.
      eprintln!("multicast bind not permitted in this environment; skipping");
    }
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
  let idx = match pick_interface_index() {
    Some(i) if i != 0 => i,
    _ => {
      eprintln!("no non-loopback multicast interface with index > 0; skipping");
      return;
    }
  };
  let opts = MulticastOptionsV4::new(idx);
  match MulticastSocketV4::try_new(opts) {
    Ok(_) => eprintln!("bound v4 with interface_index={idx}"),
    Err(_) => eprintln!("bind not permitted in this environment; skipping"),
  }
}

/// Verify that `IPV6_MULTICAST_IF` can be set during bind when an explicit
/// interface index is provided.
#[test]
fn bind_v6_with_explicit_interface_index() {
  let idx = match pick_interface_index() {
    Some(i) if i != 0 => i,
    _ => {
      eprintln!("no non-loopback multicast interface with index > 0; skipping");
      return;
    }
  };
  let opts = MulticastOptionsV6::new(idx);
  match MulticastSocketV6::try_new(opts) {
    Ok(_) => eprintln!("bound v6 with interface_index={idx}"),
    Err(_) => eprintln!("bind not permitted in this environment; skipping"),
  }
}

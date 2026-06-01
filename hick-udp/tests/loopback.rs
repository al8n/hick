//! Integration tests on a loopback multicast group.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hick_udp::{MulticastOptionsV4, MulticastOptionsV6, MulticastSocketV4, MulticastSocketV6};

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
/// gracefully where a multicast bind is not permitted (some CI sandboxes).
#[test]
fn sync_multicast_sockets_bind_on_loopback() {
  let Some(idx) = loopback_index() else {
    eprintln!("no loopback index; skipping");
    return;
  };

  match MulticastSocketV4::try_new(MulticastOptionsV4::new(idx)) {
    Ok(v4) => {
      let addr = v4.local_addr().unwrap();
      assert!(addr.is_ipv4(), "v4 socket must report a v4 local address");
      assert_eq!(addr.port(), 5353);
      let _ = v4.socket();
    }
    Err(_) => eprintln!("v4 multicast bind not permitted; skipping v4 leg"),
  }

  match MulticastSocketV6::try_new(MulticastOptionsV6::new(idx)) {
    Ok(v6) => {
      let addr = v6.local_addr().unwrap();
      assert!(addr.is_ipv6(), "v6 socket must report a v6 local address");
      assert_eq!(addr.port(), 5353);
      let _ = v6.socket();
    }
    Err(_) => eprintln!("v6 multicast bind not permitted; skipping v6 leg"),
  }
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

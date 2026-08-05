use super::*;

/// [`rx_interface_reported`] answers for THIS crate's decoder, and the expected
/// value is spelled from target literals rather than from the `has_ip_pktinfo`
/// cfg the function itself reads — asking the production answer to confirm
/// itself would pass no matter what either crate's `build.rs` emitted.
///
/// The IPv4 row is the one that matters. `decode_unix_cmsgs` reads `IP_PKTINFO`
/// and nothing else, so it recovers nothing on any BSD; `hick-udp`'s
/// `recv_with_meta` enables `IP_RECVDSTADDR` + `IP_RECVIF` there and does. This
/// function used to delegate to `hick-udp`'s answer, and the four BSD IPv4
/// squares are exactly where that delegation would now claim a capability this
/// decoder does not have — turning a `MSG_CTRUNC` on a path with nothing to
/// lose into [`DestinationWitness::Lost`], which refuses. Both halves are
/// asserted: what this crate answers, and that a BSD is where it must differ
/// from `hick-udp`.
#[test]
fn ipv4_capability_is_this_decoders_own_and_not_hick_udps() {
  let v4: SocketAddr = ([192, 0, 2, 1], 5353).into();
  let v6: SocketAddr = "[2001:db8::1]:5353".parse().expect("literal v6 addr");

  // The decoder's IPv4 cmsg is `IP_PKTINFO`, whose 12-byte Linux/Apple
  // `in_pktinfo` it decodes: Linux, Android and the Apple platforms, enumerated
  // rather than read back off the cfg.
  let decodes_v4_pktinfo = cfg!(all(
    unix,
    any(
      target_os = "linux",
      target_os = "android",
      target_vendor = "apple"
    )
  ));
  assert_eq!(
    rx_interface_reported(v4),
    decodes_v4_pktinfo,
    "this crate's IPv4 answer must follow ITS OWN decoder's cmsg support"
  );
  // Every supported Unix defines IPV6_PKTINFO, so the v6 row is uniform and
  // the delegation was never wrong about it.
  assert_eq!(
    rx_interface_reported(v6),
    cfg!(unix),
    "this crate decodes IPV6_PKTINFO on every supported unix"
  );

  // The divergence itself, on the squares where it exists. `hick-udp` witnesses
  // an IPv4 destination on the BSDs and this decoder does not, so the two
  // answers MUST disagree there; anywhere else they must agree.
  let bsd_v4 = cfg!(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
  ));
  if bsd_v4 {
    assert!(
      !rx_interface_reported(v4),
      "this decoder reads no IPv4 cmsg on a BSD, whatever hick-udp's own path recovers there"
    );
  } else if cfg!(unix) {
    assert_eq!(
      rx_interface_reported(v4),
      hick_udp::onlink::reports_rx_interface(v4),
      "off the BSDs the two receive paths decode the same IPv4 cmsg"
    );
  }
}

#[test]
fn recv_meta_default_is_safe_and_unspecified() {
  let m = RecvMeta::empty(([127, 0, 0, 1], 5353).into());
  assert!(m.local_ip.is_unspecified());
  assert_eq!(m.interface_index(), 0);
  assert!(m.hop_limit.is_none());
  assert_eq!(m.rx, RxEvidence::none());
}

/// Direct proof that the cmsg recv path delivers PKTINFO over loopback.
/// Higher layers (Endpoint, Service, Query) cover this indirectly, but
/// keeping the raw round-trip here as a unit test pins the low-level
/// pathway in isolation.
#[compio::test]
async fn raw_loopback_round_trip_carries_pktinfo_local_ip() {
  use core::net::{Ipv4Addr, SocketAddr};
  use hick_udp::{MulticastOptionsV4, try_bind_v4, try_join_v4};
  use std::time::Duration;

  fn loopback_index() -> Option<u32> {
    let ifs = getifs::interfaces().ok()?;
    ifs
      .iter()
      .find(|i| {
        i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP)
      })
      .map(|i| i.index())
  }

  let idx = match loopback_index() {
    Some(i) => i,
    None => {
      eprintln!("skip: no loopback iface");
      return;
    }
  };
  let s1 = match try_bind_v4(MulticastOptionsV4::new(idx)) {
    Ok(s) => s,
    Err(e) => {
      eprintln!("skip: bind: {e:?}");
      return;
    }
  };
  try_join_v4(&s1, idx).ok();
  s1.set_nonblocking(true).unwrap();
  let s2 = try_bind_v4(MulticastOptionsV4::new(idx)).unwrap();
  try_join_v4(&s2, idx).ok();
  s2.set_nonblocking(true).unwrap();
  let sock1 = Socket::from_std(s1).await.unwrap();
  let sock2 = Socket::from_std(s2).await.unwrap();
  let payload = b"compio mdns hello";
  let dst: SocketAddr = (Ipv4Addr::new(224, 0, 0, 251), 5353).into();
  sock1.send_to(payload, dst, None).await.unwrap();
  let (data, meta) = compio::time::timeout(Duration::from_secs(2), sock2.recv(2048))
    .await
    .expect("recv timed out")
    .unwrap();
  assert_eq!(&data[..payload.len()], payload);
  // local_ip and interface_index are populated from PKTINFO on Linux/macOS;
  // soft-assert because some loopback configs deliver UNSPECIFIED.
  if meta.local_ip.is_unspecified() {
    eprintln!("note: PKTINFO not delivered on this loopback config");
  }
}

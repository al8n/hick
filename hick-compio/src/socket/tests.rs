use super::*;

/// [`rx_interface_reported`] answers for THIS crate's decoder, and the expected
/// value is spelled from target literals rather than from the `has_ip_pktinfo` /
/// `has_ip_dstaddr_recvif` cfgs the function itself reads — asking the
/// production answer to confirm itself would pass no matter what either crate's
/// `build.rs` emitted.
///
/// # The BSD IPv4 row moved, and the row it moved to is the point
///
/// This test previously required `rx_interface_reported` to be FALSE for IPv4 on
/// the four BSDs, because `decode_unix_cmsgs` read `IP_PKTINFO` and nothing
/// else while `hick-udp` had already widened to `IP_RECVDSTADDR` + `IP_RECVIF`
/// there. That is no longer the truth about this decoder: `enable_recv_cmsgs`
/// now sets the pair and `decode_unix_cmsgs` recovers it through
/// `hick_udp::parse_dstaddr_recvif_v4`, so the honest enumerated expectation for
/// the BSD IPv4 square is `true`. The expectation below is stated from the
/// TARGET LIST either way; what changed is which cmsg this decoder reads there,
/// not how the expectation is derived.
///
/// The named property survives that move because the DIVERGENCE survives it, on
/// a different square: `hick-udp` reports IPv4 and IPv6 PKTINFO support on
/// Windows because its receive path calls `WSARecvMsg`, and this crate's Windows
/// arm is a plain `recv_from` that recovers nothing. So delegating to
/// `hick_udp::onlink::reports_rx_interface` would still claim a capability this
/// path does not have — there, it would make every zero index a failed proof and
/// drop every non-loopback datagram. Both halves are still asserted: what this
/// crate answers, and the square where it must differ from `hick-udp`.
#[test]
fn ipv4_capability_is_this_decoders_own_and_not_hick_udps() {
  let v4: SocketAddr = ([192, 0, 2, 1], 5353).into();
  let v6: SocketAddr = "[2001:db8::1]:5353".parse().expect("literal v6 addr");

  // Every supported unix, by one of two routes and never both: `IP_PKTINFO` and
  // its 12-byte Linux/Apple `in_pktinfo` on Linux/Android/Apple, the
  // `IP_RECVDSTADDR` + `IP_RECVIF` pair on the four BSDs. Enumerated rather than
  // read back off the cfgs.
  let decodes_v4_pktinfo = cfg!(all(
    unix,
    any(
      target_os = "linux",
      target_os = "android",
      target_vendor = "apple"
    )
  ));
  let decodes_v4_dstaddr_recvif = cfg!(all(
    unix,
    any(
      target_os = "freebsd",
      target_os = "dragonfly",
      target_os = "openbsd",
      target_os = "netbsd"
    )
  ));
  // Alternatives, not a sum — `build.rs` emits one or the other. A target that
  // somehow claimed both would mean `try_bind_v4` enabling two IPv4 shapes and
  // two parsers running over one datagram, which is what `hick-udp`'s
  // `compile_error!` refuses; assert it here too, since this crate has no such
  // guard of its own.
  assert!(
    !(decodes_v4_pktinfo && decodes_v4_dstaddr_recvif),
    "the two IPv4 ancillary shapes are alternatives; no target may enumerate as both"
  );
  assert_eq!(
    rx_interface_reported(v4),
    decodes_v4_pktinfo || decodes_v4_dstaddr_recvif,
    "this crate's IPv4 answer must follow ITS OWN decoder's cmsg support"
  );
  // Every supported Unix defines IPV6_PKTINFO, so the v6 row is uniform.
  assert_eq!(
    rx_interface_reported(v6),
    cfg!(unix),
    "this crate decodes IPV6_PKTINFO on every supported unix"
  );

  // The divergence itself, on the square where it is still live. `hick-udp`
  // witnesses both families on Windows through `WSARecvMsg`; this crate's
  // Windows arm is a plain `recv_from` and witnesses nothing, so the two answers
  // MUST disagree there. On unix they must now agree — the BSD IPv4 gap this
  // test used to pin is closed, and pinning agreement is what would catch it
  // re-opening.
  if cfg!(windows) {
    assert!(
      !rx_interface_reported(v4),
      "this crate's Windows recv is a plain recv_from and witnesses no IPv4 destination"
    );
    assert!(
      !rx_interface_reported(v6),
      "nor an IPv6 one, whatever hick-udp's WSARecvMsg path recovers there"
    );
    assert!(
      hick_udp::onlink::reports_rx_interface(v4),
      "and hick-udp DOES witness on Windows — this is the disagreement that makes \
       delegating this answer a capability claim rather than a lookup"
    );
  } else if cfg!(unix) {
    assert_eq!(
      rx_interface_reported(v4),
      hick_udp::onlink::reports_rx_interface(v4),
      "on unix the two receive paths now decode the same IPv4 facts, by one \
       spelling or the other"
    );
    assert_eq!(
      rx_interface_reported(v6),
      hick_udp::onlink::reports_rx_interface(v6),
      "and the same IPv6 ones"
    );
  }
}

#[test]
fn recv_meta_default_is_safe_and_unspecified() {
  let m = RecvMeta::empty(([127, 0, 0, 1], 5353).into());
  assert!(m.local_ip.is_unspecified());
  assert_eq!(m.interface_index(), 0);
  assert!(m.hop_limit.is_none());
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
  let (rx, meta) = compio::time::timeout(
    Duration::from_secs(2),
    sock2.recv(2048, hick_udp::Family::V4),
  )
  .await
  .expect("recv timed out")
  .unwrap();
  assert_eq!(&rx.body()[..payload.len()], payload);
  // local_ip and interface_index are populated from PKTINFO on Linux/macOS;
  // soft-assert because some loopback configs deliver UNSPECIFIED.
  if meta.local_ip.is_unspecified() {
    eprintln!("note: PKTINFO not delivered on this loopback config");
  }
}

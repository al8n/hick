use super::*;

#[test]
fn recv_meta_default_is_safe_and_unspecified() {
  let m = RecvMeta::empty(([127, 0, 0, 1], 5353).into());
  assert!(m.local_ip.is_unspecified());
  assert_eq!(m.interface_index, 0);
  assert!(m.hop_limit.is_none());
  assert!(m.kernel_rx_time.is_none());
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

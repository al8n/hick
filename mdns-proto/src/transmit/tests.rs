use core::{
  net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
  time::Duration,
};

use super::{FamilyDelivery, Transmit, TransmitDelivery, TransmitObligation};

#[test]
fn accessors_return_constructed_fields() {
  let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
  let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
  let gap = Duration::from_millis(250);
  let t = Transmit::new(dst, Some(src), 42, TransmitObligation::Sustained, gap);
  assert_eq!(t.dst(), dst);
  assert_eq!(t.src_ip(), Some(src));
  assert_eq!(t.size(), 42);
  assert_eq!(t.obligation(), TransmitObligation::Sustained);
  assert_eq!(
    t.min_family_gap(),
    gap,
    "the wire-spacing rule is carried per datagram, because it is kind-dependent \
     and no driver may pick it"
  );
  let one_shot = Transmit::new(dst, None, 1, TransmitObligation::OneShot, Duration::ZERO);
  assert_eq!(
    one_shot.obligation(),
    TransmitObligation::OneShot,
    "the tag is carried per datagram, not derived from the destination"
  );
  assert_eq!(
    one_shot.min_family_gap(),
    Duration::ZERO,
    "a datagram the core never re-arms is ungated: a gate could only drop it"
  );
}

#[test]
fn delivery_projects_the_two_independent_facts() {
  // `any_delivered` (goodbye ownership, RFC 6762 §10.1) and `all_delivered`
  // (lifecycle phase, §8.1/§8.3, and the §5.2 query budget) are DIFFERENT
  // questions, and they differ exactly on the partial row. A one-bit confirm
  // cannot express that row, which is why both shipped boolean policies were
  // wrong in one direction or the other.
  assert!(TransmitDelivery::ALL.any_delivered());
  assert!(TransmitDelivery::ALL.all_delivered());

  assert!(TransmitDelivery::V4_ONLY.any_delivered());
  assert!(!TransmitDelivery::V4_ONLY.all_delivered());
  assert!(TransmitDelivery::V6_ONLY.any_delivered());
  assert!(!TransmitDelivery::V6_ONLY.all_delivered());

  assert!(!TransmitDelivery::NONE.any_delivered());
  assert!(!TransmitDelivery::NONE.all_delivered());
}

#[test]
fn an_unobligated_family_is_neither_a_miss_nor_a_delivery() {
  // The whole reason `Unobligated` cannot collapse into `Missed`. A v4-only host
  // is FULLY delivered on v4 alone — it owes nothing on a family it has no socket
  // for — so its lifecycle advances exactly as a dual-stack host's does.
  let v4_only_host = TransmitDelivery::new(FamilyDelivery::Delivered, FamilyDelivery::Unobligated);
  assert!(v4_only_host.any_delivered());
  assert!(
    v4_only_host.all_delivered(),
    "an absent family was never obligated, so its absence is not a missed delivery"
  );

  // …and an EMPTY obligated set is never a vacuous "all": nothing was delivered,
  // so nothing may latch or advance.
  let no_sockets = TransmitDelivery::new(FamilyDelivery::Unobligated, FamilyDelivery::Unobligated);
  assert!(!no_sockets.any_delivered());
  assert!(!no_sockets.all_delivered());
}

#[test]
fn all_delivered_implies_any_delivered_across_every_shape() {
  // Exhaustive over the 3×2 shapes: `all && !any` must not be representable.
  let families = [
    FamilyDelivery::Unobligated,
    FamilyDelivery::Delivered,
    FamilyDelivery::Missed,
  ];
  for v4 in families {
    for v6 in families {
      let d = TransmitDelivery::new(v4, v6);
      assert!(
        !d.all_delivered() || d.any_delivered(),
        "all_delivered must imply any_delivered for ({v4}, {v6})"
      );
      assert_eq!(d.v4(), v4, "the accessor must return what was constructed");
      assert_eq!(d.v6(), v6, "the accessor must return what was constructed");
    }
  }
}

/// Render a `Display` value into a fixed stack buffer. This module is compiled on
/// EVERY feature tier, including the bare no-heap one, so it cannot reach for
/// `format!`.
struct StackWriter {
  buf: [u8; 32],
  len: usize,
}

impl StackWriter {
  fn render(value: impl core::fmt::Display) -> Self {
    use core::fmt::Write as _;
    let mut w = Self {
      buf: [0u8; 32],
      len: 0,
    };
    write!(&mut w, "{value}").unwrap();
    w
  }

  fn as_str(&self) -> &str {
    core::str::from_utf8(&self.buf[..self.len]).unwrap()
  }
}

impl core::fmt::Write for StackWriter {
  fn write_str(&mut self, s: &str) -> core::fmt::Result {
    let end = self.len + s.len();
    self.buf.get_mut(self.len..end).ok_or(core::fmt::Error)?[..].copy_from_slice(s.as_bytes());
    self.len = end;
    Ok(())
  }
}

#[test]
fn family_slugs_are_stable_and_distinct() {
  assert_eq!(FamilyDelivery::Unobligated.as_str(), "unobligated");
  assert_eq!(FamilyDelivery::Delivered.as_str(), "delivered");
  assert_eq!(FamilyDelivery::Missed.as_str(), "missed");
  // Display is defined as the slug (parity with `WithdrawalSend`).
  for family in [
    FamilyDelivery::Unobligated,
    FamilyDelivery::Delivered,
    FamilyDelivery::Missed,
  ] {
    assert_eq!(StackWriter::render(family).as_str(), family.as_str());
  }
}

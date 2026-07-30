use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use super::{Transmit, TransmitObligation, TransmitOutcome};

#[test]
fn accessors_return_constructed_fields() {
  let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
  let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
  let t = Transmit::new(dst, Some(src), 42, TransmitObligation::Sustained);
  assert_eq!(t.dst(), dst);
  assert_eq!(t.src_ip(), Some(src));
  assert_eq!(t.size(), 42);
  assert_eq!(t.obligation(), TransmitObligation::Sustained);
  assert_eq!(
    Transmit::new(dst, None, 1, TransmitObligation::OneShot).obligation(),
    TransmitObligation::OneShot,
    "the tag is carried per datagram, not derived from the destination"
  );
}

#[test]
fn outcome_projects_the_two_independent_facts() {
  // The whole point of the enum: `any_delivered` (goodbye ownership, RFC 6762
  // §10.1) and `all_delivered` (lifecycle phase, §8.1/§8.3, and the §5.2 query
  // budget) are DIFFERENT questions, and they differ exactly on the partial row.
  // A one-bit confirm cannot express that row, which is why both shipped boolean
  // policies were wrong in one direction or the other.
  assert!(TransmitOutcome::AllDelivered.any_delivered());
  assert!(TransmitOutcome::AllDelivered.all_delivered());

  assert!(TransmitOutcome::PartiallyDelivered.any_delivered());
  assert!(!TransmitOutcome::PartiallyDelivered.all_delivered());

  assert!(!TransmitOutcome::NoneDelivered.any_delivered());
  assert!(!TransmitOutcome::NoneDelivered.all_delivered());
}

#[test]
fn outcome_variants_are_the_total_partition_of_any_and_all() {
  // Exhaustive by construction: `all && !any` is not representable, so the three
  // variants are every reachable (any, all) combination. A fourth variant would
  // have to duplicate one of these.
  for outcome in [
    TransmitOutcome::AllDelivered,
    TransmitOutcome::PartiallyDelivered,
    TransmitOutcome::NoneDelivered,
  ] {
    assert!(
      !outcome.all_delivered() || outcome.any_delivered(),
      "all_delivered must imply any_delivered for {outcome}"
    );
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
fn outcome_slugs_are_stable_and_distinct() {
  assert_eq!(TransmitOutcome::AllDelivered.as_str(), "all_delivered");
  assert_eq!(
    TransmitOutcome::PartiallyDelivered.as_str(),
    "partially_delivered"
  );
  assert_eq!(TransmitOutcome::NoneDelivered.as_str(), "none_delivered");
  // Display is defined as the slug (parity with `WithdrawalSend`).
  for outcome in [
    TransmitOutcome::AllDelivered,
    TransmitOutcome::PartiallyDelivered,
    TransmitOutcome::NoneDelivered,
  ] {
    assert_eq!(StackWriter::render(outcome).as_str(), outcome.as_str());
  }
}

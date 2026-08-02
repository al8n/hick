use core::{
  net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
  time::Duration,
};

use super::{FamilyAttempt, FamilyDelivery, Transmit, TransmitDelivery, TransmitObligation};
use crate::Instant;

/// A monotonic tick, so the attempt tests run on EVERY feature tier — including
/// the bare no-heap one, where `std::time::Instant` does not exist.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Tick(u64);

impl Instant for Tick {
  fn checked_add_duration(self, dur: Duration) -> Option<Self> {
    u64::try_from(dur.as_nanos())
      .ok()
      .and_then(|n| self.0.checked_add(n))
      .map(Self)
  }

  fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
    self.0.checked_sub(earlier.0).map(Duration::from_nanos)
  }
}

/// Every shape a driver can report, so each matrix below is exhaustive rather
/// than sampled. `Refused` appears twice because its two `permanent` values are
/// two different facts, and the whole retirement decision turns on which.
const EVERY_ATTEMPT: [FamilyAttempt<Tick>; 7] = [
  FamilyAttempt::Accepted { at: Tick(7) },
  FamilyAttempt::Refused { permanent: false },
  FamilyAttempt::Refused { permanent: true },
  FamilyAttempt::GateShut,
  FamilyAttempt::NoSocket,
  FamilyAttempt::NotAddressed,
  FamilyAttempt::WouldBlock,
];

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
    "the per-family spacing rule is carried per datagram, because it is \
     kind-dependent and no driver may pick it"
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

#[test]
fn an_attempt_projects_onto_exactly_one_presence() {
  // THE mapping, stated once. It used to be written out in each driver, and every
  // historical failing-versus-absent defect was a copy of it getting one row
  // wrong.
  assert_eq!(
    FamilyAttempt::Accepted { at: Tick(1) }.delivery(),
    FamilyDelivery::Delivered,
    "an acceptance is a delivery, and it is the only thing that is"
  );
  for missed in [
    FamilyAttempt::<Tick>::Refused { permanent: false },
    FamilyAttempt::Refused { permanent: true },
    FamilyAttempt::GateShut,
    FamilyAttempt::WouldBlock,
  ] {
    assert_eq!(
      missed.delivery(),
      FamilyDelivery::Missed,
      "{}: the family had the datagram and did not carry it, so it is obligated \
       and behind — reporting it absent would let the phase advance without it",
      missed.as_str()
    );
  }
  for absent in [FamilyAttempt::<Tick>::NoSocket, FamilyAttempt::NotAddressed] {
    assert_eq!(
      absent.delivery(),
      FamilyDelivery::Unobligated,
      "{}: the family was never offered the datagram, so its absence is not a \
       failure and a single-stack host stays fully delivered on the family it has",
      absent.as_str()
    );
  }
}

#[test]
fn a_permanently_refused_family_is_still_only_missed() {
  // The one collapse that would be convenient and is wrong: "and there is no
  // point re-arming it" is a DIFFERENT question, and the presence trichotomy has
  // no room for it. Answering it inside the projection would report a family with
  // a live socket as one that owes nothing.
  assert_eq!(
    FamilyAttempt::<Tick>::Refused { permanent: true }.delivery(),
    FamilyAttempt::<Tick>::Refused { permanent: false }.delivery(),
    "permanence changes what the PRODUCER should do, never what the family did"
  );
}

#[test]
fn the_confirm_anchors_at_the_earliest_acceptance() {
  let early = Tick(10);
  let late = Tick(40);
  let fallback = Tick(99);
  let accepted = |at| FamilyAttempt::Accepted { at };

  // An anchor may only ever UNDERSTATE how fresh a family's peers are: the
  // earliest acceptance schedules the next refresh sooner than strictly needed,
  // while the latest would push a healthy family's refresh past its records' own
  // TTL. Both orders, because the fold must not depend on which family is which.
  assert_eq!(
    FamilyAttempt::anchor(accepted(early), accepted(late), fallback),
    early
  );
  assert_eq!(
    FamilyAttempt::anchor(accepted(late), accepted(early), fallback),
    early
  );

  // One family accepted: that acceptance, not the driver's later reading.
  for other in EVERY_ATTEMPT {
    if matches!(other, FamilyAttempt::Accepted { .. }) {
      continue;
    }
    assert_eq!(
      FamilyAttempt::anchor(accepted(early), other, fallback),
      early,
      "{}: one acceptance anchors the round",
      other.as_str()
    );
    assert_eq!(
      FamilyAttempt::anchor(other, accepted(early), fallback),
      early,
      "{}: and it does so from either side",
      other.as_str()
    );
  }

  // No acceptance anywhere: there is nothing to anchor, so the re-arm is spaced
  // from the driver's own attempt instant. The core reads no clock and cannot
  // supply one itself.
  for v4 in EVERY_ATTEMPT {
    for v6 in EVERY_ATTEMPT {
      if matches!(v4, FamilyAttempt::Accepted { .. })
        || matches!(v6, FamilyAttempt::Accepted { .. })
      {
        continue;
      }
      assert_eq!(FamilyAttempt::anchor(v4, v6, fallback), fallback);
    }
  }
}

#[test]
fn undeliverable_is_every_offered_family_refusing_the_size_and_nothing_less() {
  // Pure arithmetic over one round, so it is pinned identically on a host with
  // one socket and on one with two. The two directions it can be wrong in cost
  // very different things — `true` retires a live registration, `false` leaves it
  // re-arming a datagram forever — so the whole 7x7 matrix is enumerated rather
  // than sampled.
  for v4 in EVERY_ATTEMPT {
    for v6 in EVERY_ATTEMPT {
      // Stated independently of the implementation: SOME family called the
      // datagram permanently too large, and every family that was offered it at
      // all said the same.
      let offered = [v4, v6]
        .into_iter()
        .filter(|a| !matches!(a, FamilyAttempt::NoSocket | FamilyAttempt::NotAddressed));
      let want = offered
        .clone()
        .any(|a| matches!(a, FamilyAttempt::Refused { permanent: true }))
        && offered.count()
          == [v4, v6]
            .into_iter()
            .filter(|a| matches!(a, FamilyAttempt::Refused { permanent: true }))
            .count();
      assert_eq!(
        FamilyAttempt::undeliverable(v4, v6),
        want,
        "v4={} v6={}: a datagram is permanently undeliverable only when every \
         family that was offered it refused its SIZE",
        v4.as_str(),
        v6.as_str()
      );
    }
  }

  // The rows worth naming, so a future edit that flips one fails against a
  // sentence rather than against a loop.
  let refused = FamilyAttempt::<Tick>::Refused { permanent: true };
  let case = FamilyAttempt::undeliverable;
  assert!(
    case(refused, refused),
    "both families refused the size: nothing can ever carry it"
  );
  assert!(
    case(refused, FamilyAttempt::NoSocket),
    "a family with no socket is no evidence to the contrary — the one family this \
     host HAS refused it"
  );
  assert!(
    case(refused, FamilyAttempt::NotAddressed),
    "nor is a family this datagram was never for"
  );
  assert!(
    !case(refused, FamilyAttempt::Refused { permanent: false }),
    "the other family may clear, so the round is mixed and must be waited for"
  );
  assert!(
    !case(refused, FamilyAttempt::GateShut),
    "a gated family carries the SAME datagram on its next round"
  );
  assert!(
    !case(refused, FamilyAttempt::WouldBlock),
    "an unwritable socket submitted nothing and may accept the same bytes next round"
  );
  assert!(
    !case(refused, FamilyAttempt::Accepted { at: Tick(1) }),
    "one family put it on a wire, so it is manifestly deliverable"
  );
  assert!(
    !case(FamilyAttempt::NoSocket, FamilyAttempt::NoSocket),
    "no socket anywhere is an empty obligated set, not a refusal"
  );
}

#[test]
fn attempt_slugs_are_stable_and_distinct() {
  let slugs = EVERY_ATTEMPT.map(|a| a.as_str());
  for (i, a) in slugs.iter().enumerate() {
    for (j, b) in slugs.iter().enumerate() {
      assert!(
        i == j || a != b,
        "every reported outcome needs its own slug, or a trace cannot tell two apart"
      );
    }
  }
  assert_eq!(
    FamilyAttempt::<Tick>::Refused { permanent: true }.as_str(),
    "refused_permanent",
    "the permanence is what a reader of a trace line needs to see"
  );
}

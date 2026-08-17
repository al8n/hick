use crate::{
  Family,
  interfaces::{
    force_enumeration_error_for_test, has_addr_in, is_acceptable_mdns_interface,
    is_loopback_fallback_interface, pick_default_interface_index, qualifies, rank_candidates,
    tier,
  },
  onlink::collect_local_subnets,
};

use super::fallback_qualifies;
use getifs::Flags;

const INDEX: u32 = 7;

fn up_running_multicast() -> Flags {
  Flags::UP | Flags::RUNNING | Flags::MULTICAST
}

// ── the acceptable-link predicate ─────────────────────────────────────────────

#[test]
fn an_up_running_multicast_interface_qualifies() {
  assert!(qualifies(INDEX, up_running_multicast()));
  assert_eq!(tier(INDEX, up_running_multicast()), Some(0));
}

#[test]
fn a_running_interface_that_is_not_up_does_not_qualify() {
  let f = Flags::RUNNING | Flags::MULTICAST;
  assert!(!qualifies(INDEX, f));
  assert_eq!(tier(INDEX, f), None);
}

#[test]
fn an_up_interface_that_is_not_running_does_not_qualify() {
  // UP without RUNNING is a link with no carrier — a Wi-Fi NIC with no
  // association — which can never complete the multicast join.
  let f = Flags::UP | Flags::MULTICAST;
  assert!(!qualifies(INDEX, f));
  assert_eq!(tier(INDEX, f), None);
}

#[test]
fn an_interface_without_multicast_does_not_qualify() {
  let f = Flags::UP | Flags::RUNNING;
  assert!(!qualifies(INDEX, f));
  assert_eq!(tier(INDEX, f), None);
}

#[test]
fn a_multicast_loopback_is_a_fallback_not_a_link() {
  // `lo` reports MULTICAST on Linux and macOS, so excluding it must be
  // explicit rather than "fails the multicast check".
  let f = up_running_multicast() | Flags::LOOPBACK;
  assert!(!qualifies(INDEX, f));
  assert!(fallback_qualifies(INDEX, f));
  assert_eq!(tier(INDEX, f), Some(2));
}

#[test]
fn a_loopback_without_multicast_is_still_a_fallback() {
  let f = Flags::UP | Flags::RUNNING | Flags::LOOPBACK;
  assert!(!qualifies(INDEX, f));
  assert!(fallback_qualifies(INDEX, f));
  assert_eq!(tier(INDEX, f), Some(2));
}

#[test]
fn a_loopback_that_is_not_running_is_no_fallback_either() {
  let f = Flags::UP | Flags::LOOPBACK;
  assert!(!qualifies(INDEX, f));
  assert!(!fallback_qualifies(INDEX, f));
  assert_eq!(tier(INDEX, f), None);
}

#[test]
fn a_non_loopback_interface_is_not_a_fallback() {
  assert!(!fallback_qualifies(INDEX, up_running_multicast()));
}

#[test]
fn index_zero_is_no_interface() {
  assert!(!qualifies(0, up_running_multicast()));
  assert!(!fallback_qualifies(0, Flags::UP | Flags::RUNNING | Flags::LOOPBACK));
  assert_eq!(tier(0, Flags::UP | Flags::RUNNING | Flags::LOOPBACK), None);
}

#[test]
fn point_to_point_is_refused_on_android_and_admitted_elsewhere() {
  let f = up_running_multicast() | Flags::POINTOPOINT;
  if cfg!(target_os = "android") {
    assert!(!qualifies(INDEX, f));
    assert_eq!(tier(INDEX, f), None);
  } else {
    assert!(qualifies(INDEX, f));
    assert_eq!(tier(INDEX, f), Some(0));
  }
}

// ── the default interface picker ──────────────────────────────────────────────

#[test]
fn pick_default_interface_index_runs_for_every_family_combo() {
  // Exercises the strict/loose, non-loopback/loopback fallback chain. The
  // chosen index is environment dependent, so only the shape is asserted: any
  // family combination yields an Option, and a returned index resolves to a
  // (possibly empty) subnet list.
  for (v4, v6) in [(true, true), (true, false), (false, true), (false, false)] {
    if let Some(idx) = pick_default_interface_index(v4, v6).expect("enumerating interfaces") {
      let _ = collect_local_subnets(idx);
    }
  }
}

#[test]
fn the_default_interface_picker_reports_a_failed_address_enumeration() {
  // Host precondition, checked before the behaviour runs: the picker only
  // probes interfaces whose flags already qualify them, so a host with no
  // acceptable mDNS interface has nothing to fail on.
  let Ok(ifs) = getifs::interfaces() else {
    eprintln!("skipping: this host will not enumerate its interfaces at all");
    return;
  };
  let qualifies = |i: &getifs::Interface| {
    is_acceptable_mdns_interface(i) || is_loopback_fallback_interface(i)
  };
  if !ifs.iter().any(qualifies) {
    eprintln!("skipping: no acceptable mDNS interface for the picker to consider");
    return;
  }
  let _forced = force_enumeration_error_for_test(Family::V6);
  let err = pick_default_interface_index(true, true).expect_err(
    "a candidate whose addresses could not be read must not be ranked as if it had none",
  );
  assert_ne!(
    err.kind(),
    std::io::ErrorKind::NotFound,
    "NotFound is the nothing-qualified answer; a failed read must not borrow it"
  );
  assert!(
    err.to_string().contains("IPv6"),
    "the message must name the family that could not be read, got {err}"
  );
}

#[test]
fn a_failed_address_enumeration_is_not_a_missing_address() {
  let Some(idx) = getifs::interfaces().ok().and_then(|ifs| {
    ifs.into_iter()
      .find(|i| i.flags().contains(getifs::Flags::UP))
      .map(|i| i.index())
  }) else {
    eprintln!("skipping: no UP interface reported by getifs");
    return;
  };
  let iface = getifs::interface_by_index(idx)
    .expect("looking up an UP interface")
    .expect("the index just read back must name an interface");
  {
    let _forced = force_enumeration_error_for_test(Family::V6);
    assert!(
      has_addr_in(&iface, Family::V4).is_ok(),
      "forcing IPv6 to fail must leave the IPv4 probe alone"
    );
    let err = has_addr_in(&iface, Family::V6).expect_err("forced IPv6 read must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_ne!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
    assert!(
      err.to_string().contains("IPv6") && err.to_string().contains(&idx.to_string()),
      "the message must name the family and interface, got {err}"
    );
  }
  assert!(
    has_addr_in(&iface, Family::V6).is_ok(),
    "the guard must disarm the injection"
  );
}

/// The injection is scoped to the family asked for, so the two probes stay
/// distinguishable — a hook that failed both would pass the tests above while
/// proving nothing about which accessor the error came from.
#[test]
fn the_forced_enumeration_error_is_scoped_to_one_family_and_disarms_on_drop() {
  let Some(idx) = getifs::interfaces().ok().and_then(|ifs| {
    ifs.into_iter()
      .find(|i| {
        i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP)
      })
      .map(|i| i.index())
  }) else {
    eprintln!("skipping: no UP loopback interface reported by getifs");
    return;
  };
  let iface = getifs::interface_by_index(idx)
    .expect("looking up the loopback interface")
    .expect("the loopback index just read back must name an interface");
  {
    let _forced = force_enumeration_error_for_test(Family::V6);
    assert!(
      has_addr_in(&iface, Family::V4).is_ok(),
      "forcing IPv6 to fail must leave the IPv4 probe alone"
    );
    assert!(has_addr_in(&iface, Family::V6).is_err());
  }
  assert!(
    has_addr_in(&iface, Family::V6).is_ok(),
    "the guard must disarm the injection, or it leaks into whatever runs next \
     on this thread"
  );
}

// ── an error is retained only while it could still change the answer ─────────
//
// The rule above is about which failures are real; this one is about which
// failures are relevant. An enumeration error only means something to a decision
// that needed the answer, and two conditions settle that before the syscall is
// made: the family has to have been requested, and the tier the candidate can
// still reach has to outrank the interface already chosen. Propagating one that
// meets neither is a bind refused on information it could not have used. The
// reach narrows as a candidate's own families come back absent, so the second
// condition is asked between its probes as well as before the first.
//
// The walk is driven over synthetic `(tier, index, name)` candidates because
// `getifs::Interface` has no constructor a test can reach, and because which
// candidates get probed must not depend on what NICs the host happens to have.
// The name is what a failing probe is aimed at.

fn probe_failing<'a>(
  failing: &'static str,
  asked: &'a mut Vec<(&'static str, Family)>,
) -> impl FnMut(&&'static str, Family) -> std::io::Result<bool> + 'a {
  move |name, family| {
    asked.push((name, family));
    if *name == failing {
      return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    Ok(true)
  }
}

#[test]
fn a_failure_in_a_family_nobody_requested_does_not_fail_the_pick() {
  let mut asked = Vec::new();
  let picked = rank_candidates([(0, 7, "eth0")], true, false, |name, family| {
    asked.push((*name, family));
    match family {
      Family::V6 => Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
      Family::V4 => Ok(true),
    }
  });
  assert_eq!(
    picked.expect("an IPv6 read the caller never asked for cannot fail an IPv4-only pick"),
    Some(7)
  );
  assert_eq!(
    asked,
    vec![("eth0", Family::V4)],
    "a family that was not requested must not be probed at all: the short \
     circuit is what makes the failure unreachable rather than merely ignored"
  );
}

#[test]
fn a_failure_after_an_unbeatable_candidate_does_not_fail_the_pick() {
  let mut asked = Vec::new();
  let picked = rank_candidates(
    [(0, 7, "eth0"), (0, 8, "eth1")],
    true,
    true,
    probe_failing("eth1", &mut asked),
  );
  assert_eq!(
    picked.expect("nothing can outrank a tier-0 winner, so nothing after it may fail the pick"),
    Some(7),
    "first-seen-wins within a tier: the incumbent keeps the pick"
  );
  assert_eq!(
    asked,
    vec![("eth0", Family::V4), ("eth0", Family::V6)],
    "a candidate that cannot beat the incumbent must not be probed, or a failure \
     with no bearing on the answer is back to aborting the bind"
  );
}

#[test]
fn a_failure_on_a_candidate_that_could_outrank_the_winner_still_surfaces() {
  let mut asked = Vec::new();
  let err = rank_candidates(
    [(2, 1, "lo"), (0, 8, "eth0")],
    true,
    true,
    probe_failing("eth0", &mut asked),
  )
  .expect_err(
    "a candidate that could outrank the winner must not be ranked on an answer \
     nobody obtained: that binds the wrong link and looks like a working \
     responder until nothing is ever discovered",
  );
  assert_eq!(
    err.kind(),
    std::io::ErrorKind::PermissionDenied,
    "the platform's own kind must be carried over, not flattened, got {err:?}"
  );
  assert!(
    asked.contains(&("eth0", Family::V4)),
    "the higher-ranked candidate must actually have been probed"
  );
}

#[test]
fn a_failure_after_the_first_probe_cost_the_strict_tier_does_not_fail_the_pick() {
  let mut asked = Vec::new();
  let picked = rank_candidates(
    [(0, 7, "eth0"), (0, 8, "eth1")],
    true,
    true,
    |name, family| {
      asked.push((*name, family));
      match (*name, family) {
        ("eth0", Family::V4) => Ok(true),
        ("eth0", Family::V6) => Ok(false),
        ("eth1", Family::V4) => Ok(false),
        _ => Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
      }
    },
  );
  assert_eq!(
    picked.expect(
      "a probe whose answer can no longer beat the incumbent must not be made, let alone \
       abort the pick"
    ),
    Some(7),
    "first-seen-wins within a tier: the incumbent keeps the pick"
  );
  assert_eq!(
    asked,
    vec![
      ("eth0", Family::V4),
      ("eth0", Family::V6),
      ("eth1", Family::V4)
    ],
    "the tier a candidate can still reach is re-weighed between its own probes, not just \
     before the first"
  );
}

#[test]
fn the_tier_a_probe_is_weighed_against_is_the_candidates_own() {
  let mut asked = Vec::new();
  let picked = rank_candidates(
    [(2, 1, "lo0"), (2, 9, "lo1")],
    true,
    true,
    |name, family| {
      asked.push((*name, family));
      match (*name, family) {
        ("lo0", Family::V4) => Ok(true),
        ("lo0", Family::V6) => Ok(false),
        ("lo1", Family::V4) => Ok(false),
        _ => Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
      }
    },
  );
  assert_eq!(
    picked.expect(
      "a tier-3 incumbent is no more beatable by a second tier-3 candidate than a tier-1 \
       one is"
    ),
    Some(1)
  );
  assert_eq!(
    asked,
    vec![
      ("lo0", Family::V4),
      ("lo0", Family::V6),
      ("lo1", Family::V4)
    ],
    "the loose tier a failed family leaves within reach is relative to the candidate's own \
     base, so the second probe must be skipped here too"
  );
}

#[test]
fn a_failure_after_a_first_probe_that_left_the_pick_in_reach_still_surfaces() {
  let mut asked = Vec::new();
  let err = rank_candidates(
    [(2, 1, "lo"), (0, 8, "eth0")],
    true,
    true,
    |name, family| {
      asked.push((*name, family));
      match (*name, family) {
        ("lo", Family::V4) => Ok(true),
        ("lo", Family::V6) => Ok(false),
        ("eth0", Family::V4) => Ok(false),
        _ => Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
      }
    },
  )
  .expect_err(
    "skipping a probe is sound only while its answer cannot matter; here it decides the \
     pick, and ranking the candidate as having no IPv6 address binds a link nobody read",
  );
  assert_eq!(
    err.kind(),
    std::io::ErrorKind::PermissionDenied,
    "the platform's own kind must be carried over, not flattened, got {err:?}"
  );
  assert!(
    asked.contains(&("eth0", Family::V4)),
    "the higher-ranked candidate must actually have been probed"
  );
}

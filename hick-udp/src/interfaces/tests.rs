use crate::{
  Family,
  interfaces::{
    force_enumeration_error_for_test, has_addr_in, pick_default_interface_index, qualifies,
    rank_candidates, tier,
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
//
// The strict filter (`require_running = true`) is what
// `is_acceptable_mdns_interface` / `is_loopback_fallback_interface` /
// `acceptable_mdns_interfaces` expose. `tier` is the default picker's, and
// takes no such parameter: what the strict filter refuses for want of a
// carrier it ranks instead, which the next section covers.

#[test]
fn an_up_running_multicast_interface_qualifies() {
  assert!(qualifies(INDEX, up_running_multicast(), true));
  assert_eq!(tier(INDEX, up_running_multicast()), Some(0));
}

#[test]
fn a_running_interface_that_is_not_up_does_not_qualify() {
  let f = Flags::RUNNING | Flags::MULTICAST;
  assert!(!qualifies(INDEX, f, true));
  assert_eq!(tier(INDEX, f), None);
}

#[test]
fn an_up_interface_that_is_not_running_does_not_qualify() {
  // UP without RUNNING is a link with no carrier — a Wi-Fi NIC with no
  // association — which can never complete the multicast join. The strict
  // filter refuses it; the default picker ranks it below a link that has a
  // carrier rather than refusing it (see the next section).
  let f = Flags::UP | Flags::MULTICAST;
  assert!(!qualifies(INDEX, f, true));
  assert_eq!(tier(INDEX, f), Some(2));
}

#[test]
fn an_interface_without_multicast_does_not_qualify() {
  let f = Flags::UP | Flags::RUNNING;
  assert!(!qualifies(INDEX, f, true));
  assert_eq!(tier(INDEX, f), None);
}

#[test]
fn a_multicast_loopback_is_a_fallback_not_a_link() {
  // `lo` reports MULTICAST on Linux and macOS, so excluding it must be
  // explicit rather than "fails the multicast check".
  let f = up_running_multicast() | Flags::LOOPBACK;
  assert!(!qualifies(INDEX, f, true));
  assert!(fallback_qualifies(INDEX, f, true));
  assert_eq!(tier(INDEX, f), Some(4));
}

#[test]
fn a_loopback_without_multicast_is_still_a_fallback() {
  let f = Flags::UP | Flags::RUNNING | Flags::LOOPBACK;
  assert!(!qualifies(INDEX, f, true));
  assert!(fallback_qualifies(INDEX, f, true));
  assert_eq!(tier(INDEX, f), Some(4));
}

#[test]
fn a_loopback_that_is_not_running_is_no_fallback_either() {
  // Strict again: an UP loopback with no carrier is no fallback for the strict
  // filter. The lenient picker still falls back to it — see the next section.
  let f = Flags::UP | Flags::LOOPBACK;
  assert!(!qualifies(INDEX, f, true));
  assert!(!fallback_qualifies(INDEX, f, true));
  assert_eq!(tier(INDEX, f), Some(4));
}

#[test]
fn a_non_loopback_interface_is_not_a_fallback() {
  assert!(!fallback_qualifies(INDEX, up_running_multicast(), true));
}

#[test]
fn index_zero_is_no_interface() {
  assert!(!qualifies(0, up_running_multicast(), true));
  assert!(!fallback_qualifies(
    0,
    Flags::UP | Flags::RUNNING | Flags::LOOPBACK,
    true
  ));
  assert_eq!(tier(0, Flags::UP | Flags::RUNNING | Flags::LOOPBACK), None);
}

#[test]
fn point_to_point_is_refused_on_android_and_admitted_elsewhere() {
  let f = up_running_multicast() | Flags::POINTOPOINT;
  if cfg!(target_os = "android") {
    assert!(!qualifies(INDEX, f, true));
    assert_eq!(tier(INDEX, f), None);
  } else {
    assert!(qualifies(INDEX, f, true));
    assert_eq!(tier(INDEX, f), Some(0));
  }
}

// ── the default picker ranks RUNNING rather than requiring it ────────────────

// The strict filter above refuses links with no carrier (`UP` but not
// `RUNNING`). Requiring `RUNNING` in the picker too regressed hosts whose links
// are up but not reported running into "no multicast-capable interface found",
// so it must not refuse them — but ignoring the flag made a dead link a full
// tier-0 candidate, and first-seen wins within a tier, so an unplugged `eth0`
// enumerated before a working `wlan0` won a pick that nothing migrates. The
// flag is a rank instead: tier 0 with a carrier, tier 2 without, tier 4
// loopback.

#[test]
fn the_picker_admits_an_up_interface_that_is_not_running_at_a_worse_tier() {
  let f = Flags::UP | Flags::MULTICAST;
  assert!(!qualifies(INDEX, f, true));
  assert!(qualifies(INDEX, f, false));
  assert_eq!(tier(INDEX, f), Some(2));
}

#[test]
fn the_picker_still_falls_back_to_an_up_loopback_that_is_not_running() {
  let f = Flags::UP | Flags::LOOPBACK;
  assert!(!fallback_qualifies(INDEX, f, true));
  assert!(fallback_qualifies(INDEX, f, false));
  assert_eq!(tier(INDEX, f), Some(4));
}

#[test]
fn the_picker_still_refuses_everything_but_a_missing_carrier() {
  // Only `RUNNING` was demoted to a rank; everything else that makes an
  // interface usable for mDNS still keeps it out of the pick entirely.
  let down = Flags::RUNNING | Flags::MULTICAST;
  assert!(!qualifies(INDEX, down, false));
  assert_eq!(tier(INDEX, down), None);
  let no_multicast = Flags::UP | Flags::RUNNING;
  assert!(!qualifies(INDEX, no_multicast, false));
  assert_eq!(tier(INDEX, no_multicast), None);
  let loopback = up_running_multicast() | Flags::LOOPBACK;
  assert!(!qualifies(INDEX, loopback, false));
  assert!(fallback_qualifies(INDEX, loopback, false));
  let f = up_running_multicast() | Flags::POINTOPOINT;
  if cfg!(target_os = "android") {
    assert!(!qualifies(INDEX, f, false));
    assert_eq!(tier(INDEX, f), None);
  } else {
    assert!(qualifies(INDEX, f, false));
    assert_eq!(tier(INDEX, f), Some(0));
  }
}

/// Rank synthetic links exactly as the picker does — `tier` decides each base
/// and `rank_candidates` the winner — with `addrs` answering for each index.
/// Synthetic because `getifs::Interface` has no constructor a test can reach,
/// and because which link wins must not depend on the host's own NICs.
fn picked(
  links: &[(u32, Flags)],
  want_v4: bool,
  want_v6: bool,
  addrs: impl Fn(u32, Family) -> bool,
) -> Option<u32> {
  rank_candidates(
    links
      .iter()
      .filter_map(|&(index, flags)| Some((tier(index, flags)?, index, index))),
    want_v4,
    want_v6,
    |index, family| Ok(addrs(*index, family)),
  )
  .expect("a probe that cannot fail cannot fail the pick")
}

#[test]
fn a_link_with_a_carrier_wins_in_either_enumeration_order() {
  // `eth0` is up, multicast-capable and holds both requested families, but its
  // cable is out; `wlan0` is associated and working. As equal tier-0
  // candidates, enumeration order alone decided this, and the pick is a
  // snapshot nothing migrates.
  let unplugged = Flags::UP | Flags::MULTICAST;
  let working = up_running_multicast();
  let both = |_: u32, _: Family| true;
  assert_eq!(
    picked(&[(3, unplugged), (4, working)], true, true, both),
    Some(4)
  );
  assert_eq!(
    picked(&[(4, working), (3, unplugged)], true, true, both),
    Some(4)
  );
}

#[test]
fn a_link_with_no_carrier_still_outranks_loopback() {
  let unplugged = Flags::UP | Flags::MULTICAST;
  let lo = Flags::UP | Flags::RUNNING | Flags::LOOPBACK;
  let both = |_: u32, _: Family| true;
  assert_eq!(
    picked(&[(1, lo), (3, unplugged)], true, true, both),
    Some(3)
  );
  assert_eq!(
    picked(&[(3, unplugged), (1, lo)], true, true, both),
    Some(3)
  );
}

#[test]
fn a_host_with_nothing_running_still_gets_a_bind() {
  // The availability property the lenient filter exists for, and the whole
  // reason `RUNNING` is ranked rather than required: a host whose links are
  // momentarily down must not be told "no multicast-capable interface found"
  // for the life of the process.
  let both = |_: u32, _: Family| true;
  assert_eq!(
    picked(&[(3, Flags::UP | Flags::MULTICAST)], true, true, both),
    Some(3)
  );
  assert_eq!(
    picked(&[(1, Flags::UP | Flags::LOOPBACK)], true, true, both),
    Some(1)
  );
}

#[test]
fn a_carrier_outranks_a_family_only_the_dead_link_serves() {
  // Why the bases are two apart: `rank_candidates` lifts a candidate by one per
  // requested family it has no address in, and that must never lift a link with
  // no carrier past one that has it. An address on a link that cannot transmit
  // the group join at all buys nothing.
  let unplugged = Flags::UP | Flags::MULTICAST;
  let working = up_running_multicast();
  let v4_only_on_the_working_link = |index: u32, family: Family| index != 4 || family == Family::V4;
  assert_eq!(
    picked(
      &[(3, unplugged), (4, working)],
      true,
      true,
      v4_only_on_the_working_link
    ),
    Some(4)
  );
  assert_eq!(
    picked(
      &[(4, working), (3, unplugged)],
      true,
      true,
      v4_only_on_the_working_link
    ),
    Some(4)
  );
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
  // probes interfaces its own (lenient) flags tier accepts, so a host with no
  // such interface has nothing to fail on. Mirrors the picker's rule rather
  // than the strict link filter, or a host with only UP-not-RUNNING links
  // would skip a path the picker really walks.
  let Ok(ifs) = getifs::interfaces() else {
    eprintln!("skipping: this host will not enumerate its interfaces at all");
    return;
  };
  let picker_qualifies = |i: &getifs::Interface| tier(i.index(), i.flags()).is_some();
  if !ifs.iter().any(picker_qualifies) {
    eprintln!("skipping: no interface the picker would consider");
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
    ifs
      .into_iter()
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
    ifs
      .into_iter()
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

/// A guard restores the injection it replaced on drop, so nested injections
/// compose: dropping the inner one leaves the outer one armed, exactly as a
/// stack of guards should.
#[test]
fn the_forced_enumeration_error_restores_the_injection_it_replaced() {
  let Some(idx) = getifs::interfaces().ok().and_then(|ifs| {
    ifs
      .into_iter()
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
    let outer = force_enumeration_error_for_test(Family::V4);
    {
      let inner = force_enumeration_error_for_test(Family::V6);
      assert!(has_addr_in(&iface, Family::V6).is_err());
      drop(inner);
    }
    assert!(
      has_addr_in(&iface, Family::V4).is_err(),
      "dropping the inner guard must restore the outer injection, not disarm it"
    );
    assert!(
      has_addr_in(&iface, Family::V6).is_ok(),
      "the inner family's injection must be gone after its guard drops"
    );
    drop(outer);
  }
  assert!(
    has_addr_in(&iface, Family::V4).is_ok(),
    "dropping the outer guard must leave the thread clean"
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

// The two above turn on a family read BEFORE the failing one, which is the only
// order the fixed probe sequence used to handle: the tier already out of reach
// when the syscall fails. These two are the other order — the failing probe
// comes first, so what the candidate can still reach is unsettled at the moment
// it fails and only the family read next can say whether the answer nobody
// obtained could have changed the pick. Same candidates and the same four
// probes either way; the second family's answer is the entire difference
// between discarding the failure and raising it.

#[test]
fn a_failure_a_later_family_proves_irrelevant_does_not_fail_the_pick() {
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
        ("eth1", Family::V6) => Ok(false),
        _ => Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
      }
    },
  );
  assert_eq!(
    picked.expect(
      "eth1 ties the incumbent at tier 1 if its IPv4 was there and serves no requested \
       family at all if it was not, so no answer to the read that failed could have \
       changed the pick"
    ),
    Some(7),
    "first-seen-wins within a tier: the incumbent keeps the pick"
  );
  assert_eq!(
    asked,
    vec![
      ("eth0", Family::V4),
      ("eth0", Family::V6),
      ("eth1", Family::V4),
      ("eth1", Family::V6)
    ],
    "a failed probe must not end its candidate: the family read after it is what proves \
     the failure could not have mattered"
  );
}

#[test]
fn a_failure_a_later_family_leaves_decisive_still_surfaces() {
  let mut asked = Vec::new();
  let err = rank_candidates(
    [(0, 7, "eth0"), (0, 8, "eth1")],
    true,
    true,
    |name, family| {
      asked.push((*name, family));
      match (*name, family) {
        ("eth0", Family::V4) => Ok(true),
        ("eth0", Family::V6) => Ok(false),
        ("eth1", Family::V6) => Ok(true),
        _ => Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
      }
    },
  )
  .expect_err(
    "eth1 has the IPv6 the incumbent lacks, so the IPv4 nobody could read is exactly what \
     decides tier 0 against a tier-1 tie; ranking it as having no IPv4 binds a link on an \
     answer that was never obtained",
  );
  assert_eq!(
    err.kind(),
    std::io::ErrorKind::PermissionDenied,
    "the platform's own kind must be carried over, not flattened, got {err:?}"
  );
  assert_eq!(
    asked,
    vec![
      ("eth0", Family::V4),
      ("eth0", Family::V6),
      ("eth1", Family::V4),
      ("eth1", Family::V6)
    ],
    "the deferred failure is decided once the candidate's remaining families are read, so \
     the same probes run as in the discarding case"
  );
}

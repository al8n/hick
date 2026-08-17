//! What counts as an mDNS link, how to rank those links, and how to pick the
//! default one — the interface knowledge every driver and every app shares.
//!
//! The three hosted drivers (`hick-reactor`, `hick-compio`, `hick-mio`) and any
//! caller that wants one endpoint per NIC share a single definition here, so the
//! non-obvious rules that decide whether an interface can carry mDNS live in
//! exactly one place instead of three drivers plus every app:
//!
//! * **Up AND running.** `UP` is administrative; a multicast group join has to
//!   transmit IGMP/MLD, which cannot work on an interface that is up but has no
//!   carrier — a Wi-Fi NIC with no association, a NIC with its cable out.
//!   `RUNNING` is "resources allocated" (Linux `IFF_RUNNING`), i.e. the link
//!   actually has a carrier. Requiring both is the `FlagRunning` check Syncthing
//!   added to its beacon's multicast listener (syncthing/syncthing#10504):
//!   `FlagUp` alone admits interfaces that can never complete the join.
//! * **Multicast-capable, and NOT loopback.** mDNS is multicast; an interface
//!   without multicast support cannot participate, and loopback is not a link
//!   peers are ever on. Loopback exists only as the default picker's last-resort
//!   fallback — see [`interfaces::is_loopback_fallback_interface`] — so a
//!   responder can still run on a host with no real NIC; it is deliberately
//!   absent from [`interfaces::acceptable_mdns_interfaces`].
//! * **Not point-to-point on Android.** Cellular (LTE/5G) interfaces are
//!   point-to-point on Android, and binding mDNS to one wakes the cellular
//!   radio, which drains battery. VPN TUN interfaces are also point-to-point
//!   but do not support multicast anyway, so nothing usable is lost. This is
//!   the other half of syncthing/syncthing#10504, which skips point-to-point
//!   interfaces on Android in its local-discovery beacon.
//!
//! # Snapshots
//!
//! `getifs` offers no change notification on any supported platform, so both
//! functions return snapshots: re-run them after an interface comes up or goes
//! down, and rebuild any endpoint pinned to a link that vanished.

use std::io;

use crate::Family;

/// Whether `iface` can carry mDNS traffic as a real link.
///
/// See the [module docs](self) for the three rules. Loopback is never one of
/// these — it is the picker's separate fallback (see
/// [`is_loopback_fallback_interface`]) and is deliberately not returned by
/// [`acceptable_mdns_interfaces`]. Shared by the drivers' default interface
/// picker, so a pick and a consumer's own enumeration can never disagree.
pub fn is_acceptable_mdns_interface(iface: &getifs::Interface) -> bool {
  qualifies(iface.index(), iface.flags())
}

/// Whether `iface` is the loopback fallback the default interface picker ranks
/// last.
///
/// Loopback is not a link peers are on, so it is absent from
/// [`acceptable_mdns_interfaces`]; this separate rule is what the pickers use
/// so a host with no real NIC still gets a responder (and tests can run with
/// no network). It applies the same `UP` + `RUNNING` requirements as
/// [`is_acceptable_mdns_interface`].
pub fn is_loopback_fallback_interface(iface: &getifs::Interface) -> bool {
  fallback_qualifies(iface.index(), iface.flags())
}

/// The default picker's tier for `iface`: `Some(0)` for an acceptable
/// non-loopback link, `Some(2)` for the loopback fallback, or `None` when the
/// interface can never carry mDNS.
///
/// The two tiers are ranked so that lower wins — a loopback fallback can never
/// displace a real link, however the candidates are ordered — and
/// [`pick_default_interface_index`] derives each candidate's
/// `(tier, index, interface)` triple from this single answer. Shared with the
/// other drivers and with consumers that rank interfaces themselves, so a pick
/// and an app's own ranking can never disagree.
pub fn interface_tier(iface: &getifs::Interface) -> Option<u8> {
  tier(iface.index(), iface.flags())
}

/// Enumerate every interface that can carry mDNS traffic as a real link.
///
/// A convenience over [`getifs::interfaces()`] filtered by
/// [`is_acceptable_mdns_interface`], for callers that want one endpoint per
/// NIC: pass each returned interface's index to the server options of whichever
/// driver you use. Loopback is deliberately excluded — see the module docs. A
/// snapshot — re-run it to observe interface changes.
pub fn acceptable_mdns_interfaces() -> io::Result<Vec<getifs::Interface>> {
  Ok(
    getifs::interfaces()?
      .into_iter()
      .filter(is_acceptable_mdns_interface)
      .collect(),
  )
}

/// Pick the default interface index to bind when the caller pinned none.
///
/// Prefers an up, running, multicast-capable, non-loopback interface that
/// satisfies **all** requested families, then one that satisfies at least one,
/// then the same two rules over loopback. The loose fallback matters: without
/// it an IPv4-only NIC on a host with no global IPv6 would be rejected even
/// though it serves `with_ipv4(true).with_ipv6(true)` over v4 perfectly well.
///
/// # `Ok(None)` is "nothing qualified"; an error is an error
///
/// The three answers are distinct and the return type keeps them so.
/// Enumerating the interfaces can fail, and so can reading one candidate's
/// addresses, and neither is evidence that no interface qualifies — folding
/// either into `None` produced a `NotFound` naming the wrong cause, or, worse,
/// ranked a candidate as having no address in a family nobody managed to read
/// and picked a different NIC. A responder bound to the wrong link looks
/// exactly like a working one until nothing is ever discovered, so the failure
/// is raised where a caller can see it and pin an interface instead.
pub fn pick_default_interface_index(want_v4: bool, want_v6: bool) -> io::Result<Option<u32>> {
  let ifs = getifs::interfaces()
    .map_err(|e| io::Error::new(e.kind(), format!("enumerating network interfaces: {e}")))?;
  rank_candidates(
    ifs
      .iter()
      .filter_map(|i| Some((interface_tier(i)?, i.index(), i))),
    want_v4,
    want_v6,
    |iface, family| has_addr_in(iface, family),
  )
}

/// Rank already-classified candidates and return the winner's interface index.
///
/// `candidates` yields `(tier_base, index, subject)`, where `subject` is
/// whatever `has_addr` needs to read that candidate's addresses.
///
/// One pass over four preference tiers, lowest wins, first-seen wins within a
/// tier. Probes for a family only while its answer can still outrank the
/// incumbent.
fn rank_candidates<S>(
  candidates: impl IntoIterator<Item = (u8, u32, S)>,
  want_v4: bool,
  want_v6: bool,
  mut has_addr: impl FnMut(&S, Family) -> io::Result<bool>,
) -> io::Result<Option<u32>> {
  let mut best: Option<(u8, u32)> = None;
  'candidates: for (tier_base, index, subject) in candidates {
    let mut reachable = tier_base;
    let mut serves_any = false;
    for (family, wanted) in [(Family::V4, want_v4), (Family::V6, want_v6)] {
      if best.is_some_and(|(seen, _)| reachable >= seen) {
        continue 'candidates;
      }
      let serves = wanted && has_addr(&subject, family)?;
      serves_any |= serves;
      if wanted && !serves {
        reachable = tier_base.saturating_add(1);
      }
    }
    if !serves_any && reachable > tier_base {
      continue;
    }
    if best.is_none_or(|(seen, _)| reachable < seen) {
      best = Some((reachable, index));
    }
  }
  Ok(best.map(|(_, index)| index))
}

/// Address presence for `family`. `false` only means Ok(empty); Err is not
/// absence.
///
/// The error carries the interface index and the family it could not read, on
/// top of the kind the platform reported, because "permission denied" alone
/// names neither.
pub fn has_addr_in(iface: &getifs::Interface, family: Family) -> io::Result<bool> {
  let index = iface.index();
  let (label, addrs) = match family {
    Family::V4 => ("IPv4", iface.ipv4_addrs().map(|a| !a.is_empty())),
    Family::V6 => ("IPv6", iface.ipv6_addrs().map(|a| !a.is_empty())),
  };
  #[cfg(any(test, feature = "test-support"))]
  let addrs = match forced_enumeration_error() {
    Some(forced) if forced == family => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    _ => addrs,
  };
  addrs.map_err(|e| {
    io::Error::new(
      e.kind(),
      format!("reading the {label} addresses of interface {index}: {e}"),
    )
  })
}

/// Make `family`'s address enumeration fail inside [`has_addr_in`] on this
/// thread until the returned guard is dropped.
///
/// A guard rather than a pair of calls, so a failing assertion cannot leave the
/// injection armed for whatever else runs on this thread. Thread-local rather
/// than global so tests running in parallel cannot see each other's injection —
/// libtest gives every `#[test]` its own thread.
///
/// The condition is otherwise unreachable: `getifs` reads addresses straight
/// from the kernel and no healthy host refuses. It is also exactly the
/// condition whose mishandling the picker has had to fix repeatedly, so it must
/// not go untested. Behind `test-support` so no shipped build can reach it.
#[cfg(any(test, feature = "test-support"))]
pub fn force_enumeration_error_for_test(family: Family) -> ForcedEnumerationError {
  FORCED_ENUMERATION_ERROR.with(|c| c.set(Some(family)));
  ForcedEnumerationError
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
  static FORCED_ENUMERATION_ERROR: core::cell::Cell<Option<Family>> =
    const { core::cell::Cell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
fn forced_enumeration_error() -> Option<Family> {
  FORCED_ENUMERATION_ERROR.with(core::cell::Cell::get)
}

/// Disarms [`force_enumeration_error_for_test`]'s injection on drop.
#[cfg(any(test, feature = "test-support"))]
pub struct ForcedEnumerationError;

#[cfg(any(test, feature = "test-support"))]
impl Drop for ForcedEnumerationError {
  fn drop(&mut self) {
    FORCED_ENUMERATION_ERROR.with(|c| c.set(None));
  }
}

/// The decision behind [`is_acceptable_mdns_interface`], split out of it so
/// the rules can be unit-tested without a `getifs::Interface` (which has no
/// public constructor).
fn qualifies(index: u32, flags: getifs::Flags) -> bool {
  // Index 0 is "no specific interface": the drivers use it as the unbound
  // marker, and `IP_MULTICAST_IF` cannot name it.
  if index == 0 {
    return false;
  }
  if !flags.contains(getifs::Flags::UP) || !flags.contains(getifs::Flags::RUNNING) {
    return false;
  }
  if cfg!(target_os = "android") && flags.contains(getifs::Flags::POINTOPOINT) {
    // Cellular on Android; binding mDNS to it wakes the radio and drains the
    // battery. See the module docs.
    return false;
  }
  // `!LOOPBACK` is explicit rather than implied: `lo` reports `MULTICAST` on
  // Linux and macOS, so "has multicast" alone would admit it. Loopback is the
  // fallback predicate's business, not a link.
  flags.contains(getifs::Flags::MULTICAST) && !flags.contains(getifs::Flags::LOOPBACK)
}

/// The decision behind [`is_loopback_fallback_interface`].
fn fallback_qualifies(index: u32, flags: getifs::Flags) -> bool {
  index != 0
    && flags.contains(getifs::Flags::LOOPBACK)
    && flags.contains(getifs::Flags::UP)
    && flags.contains(getifs::Flags::RUNNING)
}

/// The decision behind [`interface_tier`], split out so it can be unit-tested
/// without a `getifs::Interface`.
fn tier(index: u32, flags: getifs::Flags) -> Option<u8> {
  if qualifies(index, flags) {
    Some(0)
  } else if fallback_qualifies(index, flags) {
    Some(2)
  } else {
    None
  }
}

#[cfg(test)]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::arithmetic_side_effects,
  clippy::indexing_slicing
)]
mod tests;

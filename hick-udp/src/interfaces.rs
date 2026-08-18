//! What counts as an mDNS link, how to rank those links, and how to pick the
//! default one — the interface knowledge every driver and every app shares.
//!
//! The three hosted drivers (`hick-reactor`, `hick-compio`, `hick-mio`) and any
//! caller that wants one endpoint per NIC share a single definition here, so the
//! non-obvious rules that decide whether an interface can carry mDNS live in
//! exactly one place instead of three drivers plus every app:
//!
//! * **Up, and running for a real link.** `UP` is administrative; a multicast
//!   group join has to transmit IGMP/MLD, which cannot work on an interface
//!   that is up but has no carrier — a Wi-Fi NIC with no association, a NIC
//!   with its cable out. `RUNNING` is "resources allocated" (Linux
//!   `IFF_RUNNING`), i.e. the link actually has a carrier. The strict link
//!   filter — [`interfaces::is_acceptable_mdns_interface`] and
//!   [`interfaces::acceptable_mdns_interfaces`] — requires both, the
//!   `FlagRunning` check Syncthing added to its beacon's multicast listener
//!   (syncthing/syncthing#10504): `FlagUp` alone admits interfaces that can
//!   never complete the join. The default interface picker
//!   ([`interfaces::pick_default_interface_index`]) treats `RUNNING` as a
//!   **rank** instead: a link with a carrier outranks one without, but one
//!   without is still a candidate, so a host whose links are up but not
//!   running gets a default bind instead of "no multicast-capable interface
//!   found" — and never at the cost of a working link enumerated after it.
//! * **Multicast-capable, and NOT loopback.** mDNS is multicast; an interface
//!   without multicast support cannot participate, and loopback is not a link
//!   peers are ever on. Loopback exists only as the default picker's last-resort
//!   fallback — see [`interfaces::is_loopback_fallback_interface`] — so a
//!   responder can still run on a host with no real NIC; it is deliberately
//!   absent from [`interfaces::acceptable_mdns_interfaces`].
//! * **Not point-to-point on Android.** Cellular (LTE/5G) interfaces are
//!   point-to-point on Android, and binding mDNS to one wakes the cellular
//!   radio, which drains battery. This is the other half of
//!   syncthing/syncthing#10504, which skips point-to-point interfaces on
//!   Android in its local-discovery beacon.
//!
//!   The rule is POLICY, not a capability test, and it is a heuristic in both
//!   directions. VPN TUN interfaces are point-to-point too and are refused by
//!   the same rule; that is deliberate — we do not want mDNS crossing a VPN
//!   tunnel — and NOT because they cannot carry it: Linux's
//!   `tun_net_initialize` sets `IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST`,
//!   so a TUN does advertise multicast. In the other direction the rule misses
//!   some cellular links: `qmi_wwan_netdev_setup` only sets `IFF_POINTOPOINT`
//!   on its raw-IP path, while its 802.3 path calls `ether_setup` and yields
//!   `IFF_BROADCAST | IFF_MULTICAST` with no `IFF_POINTOPOINT`, so a QMI link
//!   in Ethernet mode is not caught. Raw-IP is the norm on modern Android, so
//!   the gap is narrow, but this rule should not be read as identifying every
//!   cellular interface — that needs platform network capabilities, which this
//!   crate cannot reach.
//!
//! # Snapshots
//!
//! `getifs` offers no change notification on any supported platform, so the
//! functions here return snapshots: re-run them after an interface comes up or
//! goes down, and rebuild any endpoint pinned to a link that vanished.

use std::io;

use crate::Family;

/// Whether `iface` can carry mDNS traffic as a real link, right now.
///
/// See the [module docs](self) for the rules. This is the **strict** filter: it
/// requires the link to be `RUNNING` as well as `UP`, because a multicast group
/// join has to transmit IGMP/MLD on a link that actually has a carrier. Loopback
/// is never one of these — it is the picker's separate fallback (see
/// [`is_loopback_fallback_interface`]) and is deliberately not returned by
/// [`acceptable_mdns_interfaces`].
///
/// The default interface picker ([`pick_default_interface_index`]) is
/// deliberately **more lenient** than this predicate: an interface that fails
/// here only for want of a carrier is still a candidate there, ranked below
/// every link that has one, so it is what the picker returns when nothing
/// better exists.
pub fn is_acceptable_mdns_interface(iface: &getifs::Interface) -> bool {
  qualifies(iface.index(), iface.flags(), true)
}

/// Whether `iface` is the loopback fallback the default interface picker ranks
/// last.
///
/// Loopback is not a link peers are on, so it is absent from
/// [`acceptable_mdns_interfaces`]; this separate rule is what the pickers use
/// so a host with no real NIC still gets a responder (and tests can run with
/// no network). It applies the same `UP` + `RUNNING` requirements as
/// [`is_acceptable_mdns_interface`] — and, like that predicate, is stricter
/// than the default picker, which accepts an `UP` loopback without `RUNNING`.
pub fn is_loopback_fallback_interface(iface: &getifs::Interface) -> bool {
  fallback_qualifies(iface.index(), iface.flags(), true)
}

/// Enumerate every interface that can carry mDNS traffic as a real link.
///
/// A convenience over [`getifs::interfaces()`] filtered by
/// [`is_acceptable_mdns_interface`], for callers that want one endpoint per
/// NIC: pass each returned interface's index to the server options of whichever
/// driver you use. Loopback is deliberately excluded — see the module docs. A
/// snapshot — re-run it to observe interface changes.
///
/// Note that this is the strict filter: it requires `RUNNING`, so it can return
/// fewer interfaces than the default interface picker
/// ([`pick_default_interface_index`]) would consider.
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
/// Prefers an up, multicast-capable, non-loopback interface with a carrier,
/// then the same link without one, then loopback; within each, one that
/// satisfies **all** requested families ranks above one that satisfies at
/// least one. The loose fallback matters: without it an IPv4-only NIC on a
/// host with no global IPv6 would be rejected even though it serves
/// `with_ipv4(true).with_ipv6(true)` over v4 perfectly well.
///
/// Unlike [`is_acceptable_mdns_interface`] and [`acceptable_mdns_interfaces`],
/// this picker does **not** require `RUNNING` — it ranks it. Refusing a
/// carrier-less link outright would strand a host whose links are momentarily
/// down on "no multicast-capable interface found"; admitting one as an equal,
/// which is what ignoring the flag amounted to, let an `eth0` with its cable
/// out beat a working `wlan0` enumerated after it, purely on first-seen order
/// and for the life of a pick nothing migrates. A link that can transmit now
/// therefore outranks one that cannot in either enumeration order, and a host
/// with nothing running still gets a bind. Consumers that want only links that
/// can transmit right now should use the strict filter instead.
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
      .filter_map(|i| Some((tier(i.index(), i.flags())?, i.index(), i))),
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
/// One pass over six preference tiers, lowest wins, first-seen wins within a
/// tier. Probes for a family only while its answer can still outrank the
/// incumbent, and weighs a probe that fails the same way: the candidate's
/// remaining requested families are read first, and the failure is raised only
/// if the candidate could still have won whichever answer that probe was going
/// to give.
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
    let mut deferred: Option<io::Error> = None;
    for (family, wanted) in [(Family::V4, want_v4), (Family::V6, want_v6)] {
      if best.is_some_and(|(seen, _)| reachable >= seen) {
        continue 'candidates;
      }
      if !wanted {
        continue;
      }
      match has_addr(&subject, family) {
        Ok(true) => serves_any = true,
        Ok(false) => reachable = tier_base.saturating_add(1),
        // A read nobody completed is weighed as if it had said "present":
        // that is the answer that ranks this candidate highest, so it is the
        // one that decides whether the failure could have mattered at all.
        // Keep reading rather than propagating — a family read after it
        // coming back absent puts the pick out of this candidate's reach and
        // settles the failure as irrelevant, which is information that only
        // arrives after the syscall failed.
        Err(e) => {
          serves_any = true;
          deferred.get_or_insert(e);
        }
      }
    }
    if !serves_any && reachable > tier_base {
      continue;
    }
    // `reachable` and `serves_any` now describe the best this candidate could
    // have done with any failed probe answered its own way, so this asks
    // whether it could still have won, not whether it won.
    let could_win = best.is_none_or(|(seen, _)| reachable < seen);
    if let Some(e) = deferred {
      // It could not have won on either answer, so the walk from here is the
      // one the successful read would have produced: this candidate is not the
      // incumbent in either world. Raising the failure would refuse a bind
      // over information the pick could not have used.
      if !could_win {
        continue;
      }
      return Err(e);
    }
    if could_win {
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
/// The guard remembers the injection it replaced and restores it on drop, so
/// nested injections compose: `let outer = force(...); let inner = force(...);
/// drop(inner);` leaves the outer in force. The guard is `!Send`, so dropping
/// it on another thread is a compile error rather than a way to leave the
/// arming thread injected forever.
///
/// The condition is otherwise unreachable: `getifs` reads addresses straight
/// from the kernel and no healthy host refuses. It is also exactly the
/// condition whose mishandling the picker has had to fix repeatedly, so it must
/// not go untested. Behind `test-support` so no shipped build can reach it.
#[cfg(any(test, feature = "test-support"))]
pub fn force_enumeration_error_for_test(family: Family) -> ForcedEnumerationError {
  let prev = FORCED_ENUMERATION_ERROR.with(|c| c.replace(Some(family)));
  ForcedEnumerationError {
    prev,
    _not_send: core::marker::PhantomData,
  }
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

/// The live [`force_enumeration_error_for_test`] injection on this thread.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub struct ForcedEnumerationError {
  /// The injection this guard replaced; restored on drop so nested injections
  /// compose instead of one guard's drop disarming an outer one.
  prev: Option<Family>,
  /// The guard's `Drop` restores the *arming* thread's TLS, so it must be
  /// dropped on that thread. A raw pointer is neither `Send` nor `Sync`, which
  /// makes the guard `!Send` and `!Sync`: moving it to another thread is a
  /// compile error rather than an injection left armed forever on the thread
  /// that armed it.
  _not_send: core::marker::PhantomData<*const ()>,
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for ForcedEnumerationError {
  fn drop(&mut self) {
    FORCED_ENUMERATION_ERROR.with(|c| c.set(self.prev));
  }
}

/// The decision behind [`is_acceptable_mdns_interface`], split out of it so
/// the rules can be unit-tested without a `getifs::Interface` (which has no
/// public constructor). `require_running` separates the strict link filter
/// (true) from the weaker question [`tier`] asks in order to rank a link with
/// no carrier below one that has it (false).
fn qualifies(index: u32, flags: getifs::Flags, require_running: bool) -> bool {
  // Index 0 is "no specific interface": the drivers use it as the unbound
  // marker, and `IP_MULTICAST_IF` cannot name it.
  if index == 0 {
    return false;
  }
  if !flags.contains(getifs::Flags::UP)
    || (require_running && !flags.contains(getifs::Flags::RUNNING))
  {
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

/// The decision behind [`is_loopback_fallback_interface`]. `require_running`
/// separates the strict filter (true) from the picker's lenient variant
/// (false), exactly as in [`qualifies`].
fn fallback_qualifies(index: u32, flags: getifs::Flags, require_running: bool) -> bool {
  index != 0
    && flags.contains(getifs::Flags::LOOPBACK)
    && flags.contains(getifs::Flags::UP)
    && (!require_running || flags.contains(getifs::Flags::RUNNING))
}

/// The decision behind [`pick_default_interface_index`]'s per-candidate base
/// tier, split out so it can be unit-tested without a `getifs::Interface`
/// (which has no public constructor). Tier 0 is a non-loopback link with a
/// carrier — exactly what the strict filter accepts — tier 2 the same link
/// without one, tier 4 the loopback fallback; `rank_candidates` later lifts
/// each by one per requested family the candidate has no address in, so the
/// effective order is 0..=5 and lower still wins.
///
/// Two apart rather than one, so that a family a candidate cannot serve never
/// costs it more than a carrier does: an address on a link that cannot
/// transmit the group join at all buys nothing.
///
/// There is no `require_running` here because both answers are wanted: it is
/// what separates tier 0 from tier 2, and a link with no carrier loses to one
/// that has it rather than being refused.
fn tier(index: u32, flags: getifs::Flags) -> Option<u8> {
  if qualifies(index, flags, true) {
    Some(0)
  } else if qualifies(index, flags, false) {
    Some(2)
  } else if fallback_qualifies(index, flags, false) {
    Some(4)
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

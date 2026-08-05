//! RFC 6762 §11 on-link ingress: the EVIDENCE this crate collects, and the rule
//! it hands the evidence to.
//!
//! The rule itself is [`hick_onlink`] — `no_std`, no dependencies, pure over
//! [`core::net`] — and is re-exported here in full, so `hick_udp::onlink` stays
//! the one import a driver on this crate's receive path needs. What lives HERE
//! is everything the rule deliberately does not do:
//!
//! * [`collect_local_subnets`] and [`is_loopback_interface`] read the bound
//!   interface through `getifs`, which is what fills a [`BoundLink`] in;
//! * [`refresh_subnets_if_stale`] and [`SUBNET_REFRESH_INTERVAL`] are the
//!   freshness policy the three hosted drivers share, and it needs a monotonic
//!   clock;
//! * [`reports_rx_interface`] answers the capability question for THIS crate's
//!   own [`recv_with_meta`](crate::recv_with_meta) — and for nothing else.
//!
//! The split is not cosmetic. A rule that read a clock or an interface table
//! could not run on the bare-metal drivers, which have neither; and a driver
//! that hand-copied the rule to get around that is exactly how `hick-smoltcp`
//! came to carry a §11 gate two hardening rounds behind this one. See
//! [`hick_onlink`] for the rule, its per-platform capability table, and what
//! each of its residuals costs.

use std::{
  net::{IpAddr, SocketAddr},
  time::{Duration, Instant},
};

pub use hick_onlink::{
  Admit, BoundLink, DestinationWitness, IfaceWitness, LinkDelivery, Refuse, Verdict, admits_ingress,
};

/// Whether **this crate's own** [`recv_with_meta`](crate::recv_with_meta)
/// reports the interface a datagram from `src`'s address family arrived on. The
/// family is the peer's because the sockets are `IPV6_V6ONLY`, so a peer's
/// family is always the receiving socket's.
///
/// Only a driver that reads its datagrams through this crate may pass the result
/// straight to [`admits_ingress`]. A driver with its own receive path must
/// answer for that path instead — see this module's header.
pub const fn reports_rx_interface(src: SocketAddr) -> bool {
  match src {
    SocketAddr::V4(_) => crate::reports_rx_interface_v4(),
    SocketAddr::V6(_) => crate::reports_rx_interface_v6(),
  }
}

/// Addresses + prefix lengths configured on the bound interface. Scoped to the
/// BOUND interface only — not every local NIC — so the §11 fallback cannot be
/// widened by an unrelated interface's subnet. An `iface_index` of `0` names no
/// interface and so enumerates nothing; it must never stand in for "every NIC".
///
/// # `addr()`, not a network address, and both §11 arms depend on that
///
/// Each entry pairs the interface's **assigned** address with its prefix length.
/// The source arm reads it as an address *and mask*, which is §11's own unicast
/// comparison. `is_bound_address` reads the address alone, which is how a
/// recovered destination is recognised as one addressed to this host. So this
/// one enumeration answers both of §11's arms and there is nothing to derive.
///
/// # A failed enumeration is deliberately read as "no evidence"
///
/// Every fallible read below collapses to *nothing collected*, which is the
/// opposite direction from a driver's bind, where the same collapse is a defect:
/// there a failed family read masquerades as a family with no address and
/// silently binds the wrong thing, so it propagates. Here the caller is the
/// §11 trust boundary and the answer it needs is a yes or a no, and
/// `src_on_local_link` admits a source **only** on positive on-link evidence —
/// so an empty list is a refusal there, and a refusal is what an interface
/// nobody could read must produce. Returning a `Result` here would only move the
/// same decision one frame up.
///
/// The cost is the fail-closed one and it is bounded: while the read fails, a
/// global-address on-link peer is treated as off-link and dropped. Group
/// destinations and a loopback-bound endpoint's own traffic short-circuit
/// before this list decides anything.
///
/// An EMPTY list is read as "could not enumerate" at the destination test and as
/// "no prefix matches" at the source test, which are not in tension: [the arm
/// that takes it](admits_ingress) hands such a destination to the source arm,
/// and the source arm then refuses everything but a loopback-bound endpoint's
/// own traffic. A PARTIAL list — one family read succeeded and the other did not
/// — is not distinguished from an interface that genuinely holds no address of
/// that family, and both fail closed for that family at both arms.
///
/// # What this does NOT enumerate, named rather than implied
///
/// **Anycast addresses.** `ipv4_addrs`/`ipv6_addrs` are the only accessors
/// `getifs` 0.6.1 offers, and on Linux its netlink reader consumes `IFA_LOCAL`
/// and `IFA_ADDRESS` only (`src/linux/netlink.rs`) while Linux carries anycast
/// under a separate `IFA_ANYCAST` attribute; on Windows its
/// `FirstAnycastAddress` walk is present but commented out behind a TODO
/// (`src/windows.rs`). So an address the host will accept locally-delivered
/// traffic for is missing from this list, `is_bound_address` refuses it, and a
/// datagram unicast to it takes no §11 arm. This is a **dependency gap at the
/// pinned version**, not a decision here: nothing in this crate can reach the
/// attribute, and both consumers work unchanged once `getifs` reports it. A
/// loopback-BOUND endpoint is unaffected — `is_bound_address` holds the whole
/// `127.0.0.0/8` block for it regardless of what was enumerated.
pub fn collect_local_subnets(iface_index: u32) -> Vec<(IpAddr, u8)> {
  #[cfg(feature = "test-support")]
  if let Some(forced) = forced_enumeration(iface_index) {
    return forced;
  }
  let mut out = Vec::new();
  if iface_index == 0 {
    return out;
  }
  let Ok(Some(iface)) = getifs::interface_by_index(iface_index) else {
    return out;
  };
  if let Ok(v4) = iface.ipv4_addrs() {
    out.extend(v4.iter().map(|n| (IpAddr::V4(n.addr()), n.prefix_len())));
  }
  if let Ok(v6) = iface.ipv6_addrs() {
    out.extend(v6.iter().map(|n| (IpAddr::V6(n.addr()), n.prefix_len())));
  }
  out
}

/// How long a snapshot of the bound interface's prefixes may be trusted before
/// it is read again.
///
/// §11's unicast arm compares a source against the receiving interface's
/// configuration **as it is**, not as it was when the socket bound. An address
/// can change under a live endpoint — DHCP lease loss into APIPA, a renumbered
/// subnet, a second address added — and a snapshot taken once at construction
/// then gets it wrong in both directions at once: current-prefix traffic is
/// refused, and the obsolete prefix stays admissible.
///
/// One second is chosen because the cost of being wrong is bounded by it and the
/// cost of being right is a single interface enumeration per interval. mDNS
/// answers are not latency-critical at this granularity, and a peer whose
/// address just changed re-announces for far longer than that.
pub const SUBNET_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Re-read `iface_index`'s prefixes into `subnets` if `refreshed_at` has aged
/// past [`SUBNET_REFRESH_INTERVAL`]. Returns whether a read happened.
///
/// The drivers own the storage — this crate owns the §11 rule and its
/// freshness policy, so all three share one interval and one decision instead of
/// three that drift. Call it before consulting [`admits_ingress`]; the clock is
/// read here, at the liveness decision, rather than taken from a caller.
///
/// # Cost
///
/// One monotonic clock read and a comparison per call. An enumeration — one
/// netlink or routing-socket round trip — at most once per interval, whatever
/// the datagram rate. `getifs` offers no change notification on any supported
/// platform, so polling is the only mechanism available without writing a
/// per-platform address-event listener.
pub fn refresh_subnets_if_stale(
  iface_index: u32,
  subnets: &mut Vec<(IpAddr, u8)>,
  refreshed_at: &mut Instant,
) -> bool {
  refresh_subnets_if_stale_at(iface_index, subnets, refreshed_at, Instant::now())
}

/// [`refresh_subnets_if_stale`] with the clock supplied, so a test can age a
/// snapshot without sleeping to it. Production reaches the decision through
/// [`refresh_subnets_if_stale`], which reads the clock itself.
#[cfg(feature = "test-support")]
pub fn refresh_subnets_if_stale_at(
  iface_index: u32,
  subnets: &mut Vec<(IpAddr, u8)>,
  refreshed_at: &mut Instant,
  now: Instant,
) -> bool {
  refresh_at_inner(iface_index, subnets, refreshed_at, now)
}

#[cfg(not(feature = "test-support"))]
fn refresh_subnets_if_stale_at(
  iface_index: u32,
  subnets: &mut Vec<(IpAddr, u8)>,
  refreshed_at: &mut Instant,
  now: Instant,
) -> bool {
  refresh_at_inner(iface_index, subnets, refreshed_at, now)
}

fn refresh_at_inner(
  iface_index: u32,
  subnets: &mut Vec<(IpAddr, u8)>,
  refreshed_at: &mut Instant,
  now: Instant,
) -> bool {
  if now.saturating_duration_since(*refreshed_at) < SUBNET_REFRESH_INTERVAL {
    return false;
  }
  *subnets = collect_local_subnets(iface_index);
  *refreshed_at = now;
  true
}

/// Whether `iface_index` names the loopback interface, which is what opens the
/// §11 loopback exception ([`BoundLink::is_loopback`]).
///
/// Resolved once at bind time by the driver, never inside the rule. An index of
/// `0`, an interface that could not be read, or one without the loopback flag
/// all answer `false` — the exception is a widening, so anything unproven must
/// not open it.
pub fn is_loopback_interface(iface_index: u32) -> bool {
  if iface_index == 0 {
    return false;
  }
  matches!(
    getifs::interface_by_index(iface_index),
    Ok(Some(ref iface)) if iface.flags().contains(getifs::Flags::LOOPBACK)
  )
}

#[cfg(test)]
mod tests;

#[cfg(feature = "test-support")]
mod forced {
  use super::IpAddr;
  use std::cell::RefCell;

  /// The forced answer: which interface it applies to, and its prefixes.
  type Forced = Option<(u32, Vec<(IpAddr, u8)>)>;

  thread_local! {
    static FORCED: RefCell<Forced> = const { RefCell::new(None) };
    static LAST: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
  }

  /// Make [`collect_local_subnets`] on this thread answer `subnets` for
  /// `iface_index`, and an EMPTY list for any other index, instead of reading
  /// the host.
  ///
  /// The only way to drive an interface RENUMBERING through a driver's real
  /// receive path: a test cannot change the host's addressing, and a snapshot
  /// swapped in by hand would prove the field is read rather than that the
  /// refresh reads it.
  ///
  /// Keyed on the index ON PURPOSE. An answer independent of the interface
  /// asked for would keep a test green while production refreshed interface 0,
  /// or a foreign interface — which is precisely the wrong-field wiring such a
  /// test exists to detect. [`last_enumerated_interface_for_test`] exposes what
  /// was actually asked, so the test can assert it rather than infer it.
  ///
  /// Thread-local so concurrent tests do not collide, and behind `test-support`
  /// so no shipped build can reach it.
  ///
  /// [`collect_local_subnets`]: super::collect_local_subnets
  /// [`last_enumerated_interface_for_test`]: super::last_enumerated_interface_for_test
  pub fn force_enumeration_for_test(forced: Option<(u32, Vec<(IpAddr, u8)>)>) {
    FORCED.with(|f| *f.borrow_mut() = forced);
    LAST.with(|l| l.set(None));
  }

  /// The interface index most recently passed to [`collect_local_subnets`] on
  /// this thread, or `None` if it has not been called since the last
  /// [`force_enumeration_for_test`].
  ///
  /// [`collect_local_subnets`]: super::collect_local_subnets
  pub fn last_enumerated_interface_for_test() -> Option<u32> {
    LAST.with(std::cell::Cell::get)
  }

  pub(super) fn forced_enumeration(iface_index: u32) -> Option<Vec<(IpAddr, u8)>> {
    LAST.with(|l| l.set(Some(iface_index)));
    FORCED.with(|f| {
      f.borrow().as_ref().map(|(want, subnets)| {
        if *want == iface_index {
          subnets.clone()
        } else {
          // A different interface genuinely has different addresses. Answering
          // the caller's own snapshot here is what would hide a refresh aimed at
          // the wrong one.
          Vec::new()
        }
      })
    })
  }
}

#[cfg(feature = "test-support")]
use forced::forced_enumeration;
#[cfg(feature = "test-support")]
pub use forced::{force_enumeration_for_test, last_enumerated_interface_for_test};

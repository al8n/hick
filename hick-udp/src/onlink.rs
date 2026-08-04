//! ## The second regime's residual is much larger, and is not the above
//!
//! Everything in this section so far is about a receive path that RECOVERS a
//! destination. Where none is recovered, what remains depends on whether the
//! target reports a delivery class at all:
//!
//! | square | IPv4 broadcast | foreign multicast group |
//! |---|---|---|
//! | `hick-udp` IPv4, **OpenBSD/NetBSD** | refused (`MSG_BCAST`) | **admitted, any source** |
//! | `hick-compio` unix IPv4, **OpenBSD/NetBSD** | refused (`MSG_BCAST`) | **admitted, any source** |
//! | `hick-udp` IPv4, **FreeBSD/DragonFly** | **admitted, in-prefix source** | takes the source arm |
//! | `hick-compio` unix IPv4, **FreeBSD/DragonFly** | **admitted, in-prefix source** | takes the source arm |
//! | `hick-compio` **Windows** (`recv_from`) | **admitted, in-prefix source** | takes the source arm |
//!
//! The bold cells are live: R10 on the first two rows, R11/R12 on the last
//! three. No wording elsewhere in this module should be read as covering them.
//! The `None` arms of [`admits_ingress`] state them in full.
//!
//! What moves a square out of this regime is its own destination recovery, and
//! there are three separate pieces of work because there are three decoders:
//!
//! * `hick-udp`'s `multicast::parse_dstaddr_recvif_v4` and
//!   `multicast::parse_netbsd_pktinfo_v4` — written and unit-tested, no callers,
//!   sockopts never set; see `hick-udp/build.rs` for the per-target evidence a
//!   flip needs. This covers `hick-mio` and `hick-reactor`;
//! * the same work again in `hick-compio/src/socket/unix.rs` behind that crate's
//!   own `has_ip_pktinfo` in `hick-compio/build.rs`. `hick-compio` does not call
//!   `recv_with_meta`, so `hick-udp`'s flip does nothing for it;
//! * a `WSARecvMsg` receive path for `hick-compio` on Windows.
//!
//! All three are tracked separately.
//!
//! RFC 6762 §11 on-link trust boundary.
//!
//! The whole rule, once, for every driver that reads datagrams off a real
//! socket. It is a pure function of facts the kernel reported — peer address,
//! IP header destination, multicast delivery flag, hop limit, receive interface
//! — plus the configuration the caller holds, which arrives as a [`BoundLink`]
//! and an `iface_reported` flag. Nothing here reads a socket, a clock or a
//! driver's state, and nothing here is tunable: §11 is a fixed standard, so a
//! driver supplies the CONFIGURATION and this module owns the RULE.
//!
//! # Capability is the DRIVER's, not the platform's
//!
//! `iface_reported` is a parameter and never a constant read inside the rule.
//! Whether a receive interface comes back is a property of **the receive path a
//! driver actually runs**, not of the operating system: a driver that calls
//! `recvfrom` recovers no provenance on a platform whose `recvmsg` would have
//! supplied it, and a rule that assumed otherwise would fail every datagram
//! closed and leave that driver silently deaf. [`reports_rx_interface`] answers
//! the question for THIS crate's own `recv_with_meta`; a driver with its own
//! receive path must answer it for that path.
//!
//! It lives here because this is the shared socket layer for every driver with a
//! [`RecvMeta`](crate::RecvMeta) to hand it, and because four hand-written
//! copies of an admission boundary is how they came to disagree.
//!
//! # What this boundary does and does not guarantee
//!
//! §11 states its receive test exhaustively — *"The test for whether a response
//! originated on the local link is done in two ways"* — and both ways are about
//! the DESTINATION address, not the TTL:
//!
//! * a destination of `224.0.0.251` or `FF02::FB` is *"necessarily deemed to
//!   have originated on the local link, regardless of source IP address"*,
//!   which the RFC calls *essential* for overlaid subnets and for hosts
//!   physically on one link but misconfigured onto unrelated addresses;
//! * a unicast destination puts the source address to `(I & M) == (P & M)`
//!   against an address configured on *"the interface receiving the packet"*,
//!   or, for IPv6, to the on-link prefixes on that interface.
//!
//! **Inbound TTL is not one of them, and this module does not test it.** The
//! RFC mentions receive-side TTL exactly once, to explain why responses SHOULD
//! be SENT at 255: backwards compatibility with 2004-draft queriers that
//! discarded anything else. That sentence describes obsolete implementations in
//! the past tense; it does not instruct a reader to do the same. Queries carry
//! no IP-TTL requirement anywhere in the document.
//!
//! Sending at 255 is untouched — that SHOULD is real, and this workspace honours
//! it on every transmit.
//!
//! ## The stages, in the order [`admits_ingress`] performs them
//!
//! **1. The link (`arrived_on_bound_interface`) — ours, not the RFC's.** §11
//! does not prescribe an interface gate, but its unicast arm is defined over
//! "the interface receiving the packet" and its group arm concludes about the
//! link of arrival, so the RFC's model is already interface-scoped. This makes
//! that enforceable for a wildcard-bound socket on a multi-homed host, which is
//! the shape mDNS requires. Two things can name the link: the receive interface
//! index, and an IPv6 source's scope id. Then, in order:
//!
//! * a bound interface of `0` means this endpoint knows no link of its own, so
//!   it can forbid nothing — pass;
//! * otherwise every NONZERO witness must equal the bound interface. One
//!   disagreement refuses outright, and no later stage overturns it;
//! * if at least one witness was present and agreed — pass;
//! * with NO witness at all, three sub-cases, and this is where "absent
//!   provenance" stops being one condition:
//!   * a loopback-BOUND endpoint with a loopback source — pass;
//!   * `iface_reported == true` — REFUSE. The path could have named the link and
//!     did not: a failed proof rather than silence. A missing or truncated
//!     `PKTINFO` lands here;
//!   * `iface_reported == false` — pass. The path never had one to give.
//!
//! **2. The destination partition — TWO REGIMES, and everything below is about
//! the first.** §11 picks its arm by the IP header destination, so a receive
//! path that recovers one and a receive path that does not are governed by
//! different rules. Which square a driver is on decides which:
//!
//! `hick-compio` decodes its own ancillary data (`hick-compio/src/socket/unix.rs`,
//! gated by `hick-compio/build.rs`) rather than calling this crate's
//! `recv_with_meta`, and its `has_ip_pktinfo` covers Linux/Android/Apple only —
//! the same targets, by the same reasoning, as this crate's. So it is a SECOND
//! decoder with the SAME gap, and both are listed per family and per target:
//!
//! | receive path | family | targets | destination |
//! |---|---|---|---|
//! | `hick-udp` `recv_with_meta` | IPv6 | all supported unix | recovered |
//! | `hick-udp` `recv_with_meta` | IPv4 | Linux/Android, Apple, Windows | recovered |
//! | `hick-udp` `recv_with_meta` | IPv4 | **FreeBSD, DragonFly, OpenBSD, NetBSD** | **none** |
//! | `hick-compio` unix decoder | IPv6 | all supported unix | recovered |
//! | `hick-compio` unix decoder | IPv4 | Linux/Android, Apple | recovered |
//! | `hick-compio` unix decoder | IPv4 | **FreeBSD, DragonFly, OpenBSD, NetBSD** | **none** |
//! | `hick-compio` Windows | both | Windows (`recv_from`) | **none** |
//!
//! Any receive whose PKTINFO cmsg was absent or truncated is in the second
//! regime too, on any square.
//!
//! **With a destination recovered**, §11 names exactly two kinds and a
//! recovered one is sorted by what it **is**, never by what it is not:
//!
//! * either mDNS group admits, regardless of source address;
//! * an address **this endpoint holds** is what §11 means by a response
//!   *"received via unicast"* — the datagram was addressed to this host — and
//!   takes stage 3. Held means enumerated on the bound interface, or, for a
//!   loopback-BOUND endpoint, anywhere in RFC 1122 §3.2.1.3's `127.0.0.0/8` (or
//!   `::1`), which is a block and not one address. See `is_bound_address`;
//! * §11 offers no arm for any other destination, so it is REFUSED.
//!
//! That third line is the whole of the rule for everything else, and it is why
//! this partition carries no list of classes to keep current. A foreign
//! multicast group, an IPv4 broadcast in every one of its forms — limited
//! `255.255.255.255`, the prefix's all-ones host address, or the arbitrary
//! address an operator gave `ip addr add … broadcast …` — a martian, the
//! unspecified address and another host's address on our own subnet are all
//! refused for ONE reason: none of them is an address this endpoint holds.
//! Four consecutive reviews found one more class that a residual defined as
//! "none of the above" had absorbed. There is no residual of that shape left.
//!
//! [`BoundLink::local_addrs`] is what answers the question, and it already carries
//! the answer: [`collect_local_subnets`] stores each interface address `getifs`
//! reports, paired with its prefix length — the ASSIGNED address, not a masked
//! network — so "is this destination one of ours" is a lookup rather than a
//! computation. An **empty** snapshot is the one exception and it is documented
//! at the decision site in [`admits_ingress`].
//!
//! **With no destination recovered** none of that runs, and saying otherwise is
//! how a review round found this module claiming more than it delivers. What is
//! left is the kernel's own delivery class ([`LinkDelivery`]), which OpenBSD and
//! NetBSD alone report:
//!
//! * [`LinkDelivery::Broadcast`] is REFUSED. It is exact negative evidence —
//!   §11 gives a broadcast no arm — so those two targets lose the IPv4
//!   broadcast class here as well as in the first regime;
//! * [`LinkDelivery::Multicast`] admits, and it names no group, so **any**
//!   foreign group is admitted there from any source. That is the R10 class and
//!   no flag can close it;
//! * everything else takes the source arm, so on every square with no delivery
//!   class either — `hick-udp` and `hick-compio` IPv4 on **FreeBSD/DragonFly**,
//!   and `hick-compio` on **Windows** — an IPv4 **broadcast** is still admitted
//!   for an in-prefix source. That is the R11/R12 class, live on those three.
//!
//! The `None` arms of [`admits_ingress`] carry the full statement and what
//! closes the rest.
//!
//! **3. §11's source arm, for a destination this interface HOLDS.** A loopback
//! source is on-link only for a loopback-bound endpoint. EVERY other source —
//! routable or link-local, witnessed or not — is matched against the addresses
//! and masks configured on the bound interface, and its on-link IPv6 prefixes.
//! There is no third arm: a witness settles which link a datagram arrived on,
//! never whether its source belongs to a prefix this interface carries.
//!
//! Stages 2 and 3 read the SAME snapshot, which is what makes the pair coherent:
//! the destination against its addresses, the source against its addresses and
//! masks. An endpoint that cannot say which addresses it holds therefore fails
//! both, and that is the empty-snapshot case above.
//!
//! ## What each receive path supplies, and therefore which stages it reaches
//!
//! | receive path | interface index | IPv6 scope | destination | `MSG_MCAST` |
//! |---|---|---|---|---|
//! | this crate's `recv_with_meta`, IPv6, all targets | yes | yes | yes | OpenBSD/NetBSD only |
//! | this crate's `recv_with_meta`, IPv4 Linux/Apple/Windows | yes | n/a | yes | no |
//! | this crate's `recv_with_meta`, IPv4 FreeBSD/DragonFly | **no** | n/a | **no** | no |
//! | this crate's `recv_with_meta`, IPv4 OpenBSD/NetBSD | **no** | n/a | **no** | **yes** |
//! | `hick-compio` unix | as above | yes | yes | as above |
//! | `hick-compio` Windows | **no** | **yes** | **no** | **no** |
//!
//! `MSG_MCAST` is a property of the target rather than of the family: OpenBSD
//! and NetBSD bind it and every other supported target does not, so IPv6 gets it
//! there too.
//!
//! `hick-compio` on Windows is the one that is easy to get wrong, and a
//! "provenance-less" label gets it wrong: its `recvfrom` recovers no interface
//! index, but it does recover the peer `sockaddr_in6`, and every supported
//! platform — Windows included — fills `sin6_scope_id` from the receiving
//! interface for a link-local source. So a link-local IPv6 peer IS witnessed and
//! fully isolated there; a scopeless IPv6 peer and every IPv4 peer are not.
//!
//! ## What removing the TTL test costs, stated plainly
//!
//! Refusing a hop limit other than 255 was, in isolation, a real check: a
//! datagram that crossed a router cannot arrive at 255, so it blocked the blind
//! routed spoof carrying a forged in-prefix source. Removing it admits exactly
//! that one new row — routed unicast, forged in-prefix source, through an edge
//! that does not filter it. That row is RFC 6762 §11's own accepted residual:
//! its unicast test asks only whether the source is *apparently* on a local
//! subnet, so the RFC knows its test is forgeable and accepts it. The interface
//! gate above still applies, and §21 is explicit that this mechanism does not
//! defend against an on-link antagonist at all.
//!
//! What the check cost in exchange was larger and far more ordinary. Refusing
//! anything but 255 refused **conforming traffic**: §5.5 direct unicast queries,
//! which arrive at whatever unicast TTL the sender's stack defaults to (64 or
//! 128); group queries from stacks left at the socket-default multicast TTL of
//! 1; and it applied a TTL test to **queries at all**, which not even the 2004
//! draft did. It also sat ahead of the group arm, so an exact-group datagram at
//! any other TTL was dropped — the case §11 says is *necessarily* local
//! regardless of source, and calls essential. Admitting on 255 was the mirror
//! defect: it returned before the destination or the prefix was examined, so a
//! witnessed out-of-prefix unicast was admitted where `§11` expects a receiver to
//! ignore it. Both are conformance defects; only the second was ever adjacent to
//! security, and the sender it admitted was already provably on the bound link.
//!
//! There is no knob. Nothing here is tunable, and a unicast-arm-only variant
//! would still refuse §5.5's default-TTL queries.
//!
//! ## The residual, stated plainly
//!
//! Where stage 1 passes for want of evidence, the cross-interface class is
//! **narrowed, not closed**: admission then rests on values the SENDER chooses —
//! reaching the group, or sourcing from inside one of the bound interface's
//! prefixes, which a second NIC sharing that prefix satisfies legitimately and
//! an adjacent sender satisfies by choosing an in-prefix address. Where the path
//! also recovers no destination evidence, §11-mandated group traffic from an
//! off-prefix peer is REFUSED, which is a conformance loss in the other
//! direction. Both follow from the same missing fact.
//!
//! One further gap is known and not yet closed: §11's IPv6 arm is defined over
//! the on-link prefixes of the receiving interface, *"learned via IPv6 router
//! advertisements or otherwise configured on the host"*.
//! [`collect_local_subnets`] enumerates only prefixes this host holds an address
//! in, so an on-link prefix learned from a router advertisement that this host
//! took no address from is not consulted, and a peer inside it is refused by the
//! source arm. The group arm carries the ordinary multicast case regardless.
//!
//! The destination partition has residuals of its own. They are the mirror of
//! the old ones: it admits only what the snapshot names, so what it gets wrong
//! it gets wrong by refusing rather than by admitting.
//!
//! * a **stale** snapshot — non-empty, but taken before an address was added —
//!   refuses unicast to that new address until the next refresh, so the window
//!   is bounded by [`SUBNET_REFRESH_INTERVAL`] and closes itself. The same
//!   staleness already governed the source arm; this puts the destination side
//!   on the same clock;
//! * a snapshot that enumerated ONE family (a per-family read failed, or the
//!   interface genuinely holds no address of the other family) refuses every
//!   unicast destination in the missing family. The source arm already refuses
//!   every source in it, so this is the same fail-closed at a second gate and
//!   not a new one;
//! * an **anycast** address is held by the host and absent from the snapshot,
//!   so it is refused. `getifs` 0.6.1 reads `IFA_ADDRESS`/`IFA_LOCAL` and not
//!   Linux's separate `IFA_ANYCAST`, and leaves Windows'
//!   `FirstAnycastAddress` commented out; there is no accessor to reach them
//!   through at the pinned version, so this is a dependency gap rather than a
//!   decision. `is_bound_address` needs no change once `getifs` surfaces them.
//!
//! `127.255.255.255` on a loopback-BOUND endpoint is **no longer** in this list.
//! RFC 1122 §3.2.1.3 makes the whole of `127.0.0.0/8` this host's own, so it is
//! held along with every other address in the block and takes the source arm.
//! That closes an argument three review rounds ran: the previous partition
//! refused it by deriving a broadcast from `127.0.0.1/8`, which is a capability
//! a loopback interface does not have, and the positive partition first refused
//! it as "not the one address enumerated", which is a reading RFC 1122 settles
//! against. See `is_bound_address`.
//!
//! ## The second regime's residual is much larger, and is not the above
//!
//! Everything in this section so far is about a receive path that RECOVERS a
//! destination. On the three squares that do not — `recv_with_meta` IPv4 on
//! FreeBSD/DragonFly, the same on OpenBSD/NetBSD, and `hick-compio` on Windows
//! — an IPv4 broadcast is indistinguishable from a unicast and is admitted for
//! an in-prefix source, and on the OpenBSD/NetBSD square a foreign multicast
//! group is admitted for ANY source. Those are live, they are the R10 and
//! R11/R12 classes, and no wording in this module should be read as covering
//! them. The `None` arms of [`admits_ingress`] state them in full and record why
//! `MSG_BCAST` is not the answer.
//!
//! Wiring the BSD IPv4 ancillary parsers (`multicast::parse_dstaddr_recvif_v4`,
//! `multicast::parse_netbsd_pktinfo_v4` — written and unit-tested, no callers,
//! sockopts never set; see `hick-udp/build.rs` for the per-target evidence a
//! flip needs) and a `WSARecvMsg` receive path for `hick-compio` is what moves
//! those squares into the first regime. Both are tracked separately.
//!
//! It lives here because this is the shared socket layer for every driver with a
//! [`RecvMeta`](crate::RecvMeta) to hand it, and because four hand-written
//! copies of an admission boundary is how they came to disagree.

use core::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::{
  constants::{MDNS_IPV4_GROUP, MDNS_IPV6_GROUP},
  multicast::LinkDelivery,
};

/// The link an endpoint bound, as the §11 boundary needs to know it.
///
/// This is the CONFIGURATION half of the boundary and it is the driver's: every
/// field is resolved once at bind time and handed over, so the rule itself
/// performs no lookup and holds no state. [`collect_local_subnets`] and
/// [`is_loopback_interface`] are the two reads a driver makes to fill it in.
///
/// # Two lists, because §11 asks two different questions
///
/// [`Self::local_addrs`] answers *"is this destination an address WE hold"* —
/// §11's "received via unicast". [`Self::onlink_prefixes`] answers *"is this
/// source inside a prefix that is ON-LINK on the receiving interface"* — §11's
/// source comparison, which the RFC defines over prefixes *"learned via IPv6
/// router advertisements or otherwise configured on the host"*.
///
/// **They are separate fields because they are separate facts, and today they
/// are populated from the same enumeration anyway.** [`Self::new`] aliases them
/// deliberately and says so. That aliasing is wrong in both directions for IPv6
/// and the split is what gives each direction somewhere to be fixed:
///
/// * an address assigned by SLAAC from a prefix advertised with **A=1, L=0** is
///   in `local_addrs` and its /64 is *not* on-link, yet the alias makes the
///   source arm treat that /64 as on-link — a false POSITIVE, and one the
///   removed inbound-TTL test used to mask on metadata-capable paths;
/// * an on-link prefix advertised with **L=1, A=0**, which this host takes no
///   address from, appears in neither list — a false NEGATIVE.
///
/// Use [`Self::with_onlink_prefixes`] to supply the second list from a real
/// on-link source; nothing in this workspace does yet.
#[derive(Debug, Clone, Copy)]
pub struct BoundLink<'a> {
  iface: u32,
  is_loopback: bool,
  local_addrs: &'a [(IpAddr, u8)],
  onlink_prefixes: &'a [(IpAddr, u8)],
}

impl<'a> BoundLink<'a> {
  /// `iface` is the interface index this endpoint bound, `is_loopback` says
  /// whether that interface is the loopback one (see [`is_loopback_interface`]),
  /// and `local_addrs` are the addresses configured on it (see
  /// [`collect_local_subnets`]).
  ///
  /// **This constructor ALIASES the two lists**: the addresses this host holds
  /// are also handed to the source arm as if they were the interface's on-link
  /// prefixes. That is what every driver in this workspace does today and what
  /// the code did before the fields were split; it is stated here rather than
  /// left for a reader to discover, because the two are not the same fact. See
  /// this type's own documentation for the two directions it is wrong in, and
  /// [`Self::with_onlink_prefixes`] for the constructor that stops aliasing
  /// them.
  #[inline]
  pub const fn new(iface: u32, is_loopback: bool, local_addrs: &'a [(IpAddr, u8)]) -> Self {
    Self {
      iface,
      is_loopback,
      local_addrs,
      onlink_prefixes: local_addrs,
    }
  }

  /// The two lists from separate sources: `local_addrs` for the destination
  /// test, `onlink_prefixes` for §11's source comparison.
  ///
  /// Nothing in this workspace calls it yet — it exists so that supplying real
  /// on-link prefixes is a change to a driver's bind and refresh, and not a
  /// change to this boundary's shape. A caller that reads a route table for
  /// them must decide what an unreadable table means; the fail-closed reading
  /// (an empty list, so the source arm admits nothing) is the one consistent
  /// with [`collect_local_subnets`].
  #[inline]
  pub const fn with_onlink_prefixes(
    iface: u32,
    is_loopback: bool,
    local_addrs: &'a [(IpAddr, u8)],
    onlink_prefixes: &'a [(IpAddr, u8)],
  ) -> Self {
    Self {
      iface,
      is_loopback,
      local_addrs,
      onlink_prefixes,
    }
  }

  /// The bound interface index. `0` means this endpoint does not know its own
  /// link, which makes the interface gate permissive — see
  /// `arrived_on_bound_interface`.
  #[inline]
  pub const fn iface(&self) -> u32 {
    self.iface
  }

  /// Whether the bound interface is the loopback one. It is the ONLY thing that
  /// opens the loopback exception; a loopback SOURCE address never opens it by
  /// itself.
  #[inline]
  pub const fn is_loopback(&self) -> bool {
    self.is_loopback
  }

  /// The addresses configured on the bound interface, and nothing else's — the
  /// set a destination must be in for §11 to call the datagram one *"received
  /// via unicast"*. Read by `is_bound_address` and by nothing else.
  ///
  /// Each entry's prefix length is carried for the OTHER role's sake; the
  /// destination test compares addresses and never masks.
  #[inline]
  pub const fn local_addrs(&self) -> &'a [(IpAddr, u8)] {
    self.local_addrs
  }

  /// The prefixes the bound interface treats as ON-LINK — what §11's source
  /// comparison is defined over. Read by `src_on_local_link` and by nothing
  /// else.
  ///
  /// [`Self::new`] aliases this to [`Self::local_addrs`], which is an
  /// approximation and not an identity; see this type's documentation.
  #[inline]
  pub const fn onlink_prefixes(&self) -> &'a [(IpAddr, u8)] {
    self.onlink_prefixes
  }
}

/// The IPv6 scope id a peer carries, or `0` for a peer that carries none. An
/// IPv4 peer has no zone, so its only witness is the cmsg index.
#[inline]
const fn scope_of(src: SocketAddr) -> u32 {
  match src {
    SocketAddr::V6(a) => a.scope_id(),
    SocketAddr::V4(_) => 0,
  }
}

/// Whether a datagram from `src`, delivered on interface `pkt_iface`, belongs to
/// the link this endpoint bound.
///
/// `iface_reported` says whether the CALLER's receive path reports a receive
/// interface for `src`'s address family at all. It is a parameter rather than a
/// constant read here because the answer belongs to that path and not to the
/// platform — see this module's header — and because the decision must be
/// testable on every host, not only on one whose capabilities happen to match
/// the case under test.
///
/// # Why this gate exists on top of §11
///
/// §11's own arms answer "did this originate on a local link", never "on WHICH
/// link". Both mDNS sockets are wildcard bound — they have to be, to receive
/// multicast addressed to a group rather than to an address — so on a
/// multi-homed host every NIC's port-5353 traffic is delivered to them, and the
/// group arm admits every copy of it "regardless of source IP address".
/// Admitting those puts an adjacent network inside this endpoint's trust
/// boundary: it can seed the cache, provoke RFC 6762 §8.2 conflict handling and
/// the §9 rename that follows, and elicit our records onto a network the caller
/// never asked to advertise on. An endpoint serves exactly one interface — the
/// index its caller pinned, or the default its driver resolved at bind — so
/// anything else is off its link by construction, whatever its hop limit says.
/// Applied to BOTH §11 branches, and before the self-send match, because a
/// foreign-link datagram must not even be offered a take-once credit.
///
/// # Two witnesses, not one
///
/// The receive interface is not the only thing that names the link a datagram
/// came from: an IPv6 source address carries a **scope id**, and the platforms
/// this crate supports all preserve it into the peer address (this crate's
/// `sockaddr_storage_to_socketaddr` and its Windows twin). So both are
/// consulted, and **every nonzero witness must equal `link.iface()`** —
/// including when they disagree with each other. A datagram whose PKTINFO says
/// our own interface and whose scope id says another has already contradicted
/// itself; a trust boundary resolves that against the sender, not for it.
///
/// # The three exceptions, all deliberate
///
/// **A loopback source is admitted from any interface only when the ENDPOINT is
/// bound to the loopback interface**, and never on the strength of the source
/// address alone. The exception exists because a loopback-pinned endpoint's own
/// suppression depends on receiving its own multicast back, and a platform is
/// free to report that copy as having arrived somewhere other than the socket's
/// egress interface — so every loopback fixture in this workspace, and any
/// caller pinned to the loopback interface, runs entirely on traffic sourced
/// from `127.0.0.1`/`::1`. It is scoped to `link.is_loopback()` because a
/// loopback SOURCE is not self-evidently local: Linux's `route_localnet` lets an
/// operator stop treating `127/8` as martian on a real NIC, at which point an
/// adjacent sender can spoof `127.0.0.1` at hop limit 255 and an address-only
/// exemption would hand it the whole boundary. The residual is a loopback-BOUND
/// endpoint, which is a fixture or a deliberately host-local responder rather
/// than something serving a physical link. The same narrowing, for the same
/// reason, applies in `src_on_local_link`.
///
/// **`link.iface() == 0` is permissive**, meaning this endpoint does not know
/// its own link and so can prove nothing about anyone else's. Production never
/// reaches it: a driver's bind either takes the caller's index or picks a
/// default, then fails the bind outright if that index names no interface, so a
/// live endpoint always has a real one.
///
/// **No witness at all is admitted only where the caller's receive path never
/// had one to give.** With `iface_reported == false` a zero index is that path's
/// silence — IPv4 on FreeBSD/DragonFly/OpenBSD/NetBSD, which define no usable
/// `IP_PKTINFO`, and any driver reading datagrams with `recvfrom` — and
/// rejecting silence would take mDNS off the air there entirely. With
/// `iface_reported == true` the path does
/// answer this question, so a zero index is a datagram the kernel declined to
/// place: no longer absent evidence but a failed proof, and this fails closed on
/// it.
///
/// Admitting silence is NOT the end of the matter, and this function is not the
/// place that settles it: a datagram that passes here must still satisfy one of
/// §11's own two arms.
fn arrived_on_bound_interface(
  src: SocketAddr,
  link: BoundLink<'_>,
  pkt_iface: u32,
  iface_reported: bool,
) -> bool {
  if link.iface() == 0 {
    return true;
  }
  // The witnesses are read FIRST and nothing overrules them. A present, nonzero
  // witness is evidence the kernel attached to this datagram; a source ADDRESS
  // is a claim the sender wrote. No exception below may let the second answer
  // over the first.
  let mut witnessed = false;
  for witness in [pkt_iface, scope_of(src)] {
    if witness == 0 {
      continue;
    }
    witnessed = true;
    if witness != link.iface() {
      return false;
    }
  }
  if witnessed {
    return true;
  }
  // Nothing named the link. Only now may a loopback-BOUND endpoint take its own
  // loopback traffic on the source address, and only because the loopback
  // interface IS its link.
  if link.is_loopback() && src.ip().is_loopback() {
    return true;
  }
  !iface_reported
}

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

/// Whether `dst` is one of the two mDNS link-local multicast groups, the
/// destination RFC 6762 §11 says establishes local-link origin on its own.
///
/// Exactly these two and nothing else. The nearest neighbours in the same
/// link-local blocks — `224.0.0.252` and `ff02::1:3` — are LLMNR's groups, not
/// ours, and this is a trust boundary rather than a link-local scope test: §11
/// names these two addresses, so widening it to "any link-local multicast"
/// would hand the exemption to every other protocol sharing the link.
fn is_mdns_group(dst: IpAddr) -> bool {
  match dst {
    IpAddr::V4(a) => a == MDNS_IPV4_GROUP,
    IpAddr::V6(a) => a == MDNS_IPV6_GROUP,
  }
}

/// The whole ingress trust boundary for one datagram: the link it arrived on,
/// then RFC 6762 §11.
///
/// One function so the interface gate and §11's own arms cannot drift apart.
/// The interface check runs **first** and applies to both arms: §11 answers
/// "did this originate on a local link", never "on WHICH link", and a
/// wildcard-bound socket on a multi-homed host is handed every NIC's copy.
///
/// `src` is the whole peer [`SocketAddr`], not its [`IpAddr`]: for an IPv6 peer
/// the scope id is half of what names the link it came from, and taking the
/// address alone silently discards it.
///
/// # §11 selects the fallback's arm by DESTINATION, not by source
///
/// §11 states the local-link test two ways, and the IP header's destination
/// picks between them. A datagram addressed to `224.0.0.251` or `FF02::FB` is
/// *"necessarily deemed to have originated on the local link, regardless of
/// source IP address"* — which the RFC calls *"essential to allow devices to
/// work correctly and reliably in unusual configurations, such as multiple
/// logical IP subnets overlayed on a single link, or in cases of severe
/// misconfiguration"*. Only a **unicast** destination sends the source address
/// to the subnet check.
///
/// A caller holding the unicast arm alone and applying it to both drops an
/// on-link host sourcing from a prefix we do not share exactly where §11 says it
/// must not. Every datagram takes this path — there is no branch that skips it —
/// so the loss would be total rather than rare wherever the destination is not
/// recovered. See the section below for which targets those are.
///
/// The group arm sits INSIDE the fallback rather than ahead of it. It replaces
/// the source-prefix *guess*, the only thing §11 ever offered it as an
/// alternative to. And the interface check still runs first and still gates both
/// arms: a group destination proves a datagram was link-local to SOME link,
/// never that it was ours, and a wildcard-bound socket on a multi-homed host is
/// handed every NIC's copy.
///
/// # Where the destination comes from, and why not `local_ip`
///
/// `destination` is [`RecvMeta::destination`](crate::RecvMeta::destination),
/// which reports the IP header destination or nothing at all. It is NOT
/// [`RecvMeta::local_ip`](crate::RecvMeta::local_ip): on Unix IPv4 that accessor
/// deliberately returns `in_pktinfo.ipi_spec_dst`, the receiving interface's own
/// unicast address, because self-send detection on a multi-homed host needs it —
/// and a local unicast address never equals a group, so every multicast arrival
/// would read as "unicast" and go to the source-prefix test §11 says must not
/// decide it.
///
/// There is no branch that skips this reading, so getting it wrong is not a
/// corner case: every arrival on every target would take the source-prefix arm.
/// On OpenBSD/NetBSD there is no IPv4 PKTINFO parse at all, the destination
/// degrades to `None`, and the kernel's multicast flag is the only thing left to
/// reach the group arm with — against precisely the overlaid-subnet multicast
/// §11 calls "essential" to admit.
///
/// # Two regimes, and the contract differs between them
///
/// **`destination` is `Some`.** A recovered destination is matched against the
/// two mDNS groups and then against the addresses this endpoint holds. Anything
/// else takes no §11 arm and is REFUSED — a foreign multicast group, an IPv4
/// broadcast in any form, a martian, the unspecified address, a neighbour's
/// address on our own subnet. That guarantee is this function's, in full, for
/// every driver on a square that recovers a destination.
///
/// **`destination` is `None`.** None of the above holds, and this is a promise
/// this function does not make on those squares — `recv_with_meta` for IPv4 on
/// FreeBSD, DragonFly, OpenBSD and NetBSD; `hick-compio` on Windows, which
/// reads with `recv_from`; and any receive whose PKTINFO cmsg was absent or
/// truncated. `MSG_MCAST` stands in on the OpenBSD/NetBSD square and answers
/// "some group" rather than which, so a foreign group is admitted there with no
/// source test at all; everywhere else on those squares an IPv4 broadcast is
/// indistinguishable from a unicast and is admitted for an in-prefix source.
///
/// A caller that needs the first regime's guarantee must be on a square that
/// supplies a destination. The `None` arms below say what closes the gap, and
/// why the available `MSG_BCAST` bit is not it.
pub fn admits_ingress(
  src: SocketAddr,
  destination: Option<IpAddr>,
  delivery: Option<LinkDelivery>,
  link: BoundLink<'_>,
  pkt_iface: u32,
  iface_reported: bool,
) -> bool {
  // Ours: scope "the local link" to the link this endpoint bound. §11 does not
  // prescribe it, but its unicast arm is defined over "the interface receiving
  // the packet", so the RFC's test is already interface-scoped — this is what
  // makes that model enforceable for a wildcard-bound socket on a multi-homed
  // host.
  if !arrived_on_bound_interface(src, link, pkt_iface, iface_reported) {
    return false;
  }
  // §11 partitions by DESTINATION and names exactly two kinds. Each arm below
  // says what a destination IS. Nothing here is spelled as "everything that is
  // not one of the classes named above", which is the shape that admitted a
  // foreign multicast group, then an IPv4 limited broadcast, then a directed
  // one, then an operator-configured broadcast address — four rounds of
  // subtracting one more class from a residual that kept another.
  match destination {
    // Arm one, verbatim: "necessarily deemed to have originated on the local
    // link, regardless of source IP address".
    Some(dst) if is_mdns_group(dst) => true,
    // Arm two: §11 scopes its source comparison to a response "received via
    // unicast", and a datagram received via unicast BY US is one addressed to
    // an address of ours. So the destination is matched against the receiving
    // interface's own configuration, which is the same configuration the
    // source is about to be matched against.
    Some(dst) if is_bound_address(dst, link) => {
      src_on_local_link(src, link, pkt_iface, iface_reported)
    }
    // An EMPTY snapshot is the one place the arm above must not be believed,
    // and this is the deliberate choice at this site.
    //
    // "Not one of our addresses" and "we could not enumerate our addresses"
    // are different facts and an empty list is the second one:
    // `collect_local_subnets` collapses every failed read to *nothing
    // collected*, so a transient interface-enumeration failure would otherwise
    // silence every unicast destination at once. That matches how
    // `arrived_on_bound_interface` already reads a bound interface of `0` —
    // an endpoint that cannot say what it holds forbids nothing on the
    // strength of not having said it.
    //
    // This is a fallback and NOT a fail-open, and the bound is exact: with an
    // empty snapshot `src_on_local_link`'s prefix comparison has nothing to
    // match, so it admits a loopback source for a loopback-BOUND endpoint that
    // also passed stage 1, and refuses every other source outright. The whole
    // of what this arm can admit is a loopback-bound endpoint's own traffic —
    // which is exactly the endpoint whose interface a driver is most likely to
    // fail to enumerate, and the shape every loopback fixture in this
    // workspace runs on.
    //
    // A STALE snapshot is a different case and gets no exception: non-empty
    // means the enumeration succeeded, so a destination missing from it is a
    // real "not ours" until the next refresh. That fails closed for at most
    // `SUBNET_REFRESH_INTERVAL` and heals itself; see this module's header.
    Some(_) if link.local_addrs().is_empty() => {
      src_on_local_link(src, link, pkt_iface, iface_reported)
    }
    // §11 offers no arm for any other destination, and this is a trust
    // boundary, so it is refused rather than handed to the arm next door.
    Some(_) => false,
    // ── A DIFFERENT REGIME STARTS HERE ────────────────────────────────────
    //
    // No destination recovered, on one of five named receive squares:
    // **`hick-udp`'s `recv_with_meta` for IPv4 on FreeBSD/DragonFly** and **on
    // OpenBSD/NetBSD**; **`hick-compio`'s own unix decoder for IPv4 on those
    // same four targets** — its `build.rs` enables `has_ip_pktinfo` for
    // Linux/Android/Apple only, exactly as `hick-udp`'s does, so it is a
    // separate decoder with the same gap and not a share of this crate's — and
    // **`hick-compio` on Windows**, which reads with `recv_from` and gets no
    // ancillary data at all. Any receive whose PKTINFO cmsg was absent or
    // truncated lands here too.
    //
    // NOTHING IN THE `Some` ARMS APPLIES HERE. The positive partition needs a
    // destination to be positive about; below there is none, so these arms are
    // a coarser rule with a residual of their own, and every claim this module
    // makes about refusing a destination it does not hold is a claim about the
    // `Some` arms only.
    //
    // A link-layer BROADCAST is refused. `MSG_BCAST` is definitive NEGATIVE
    // evidence and it is exact rather than approximate: the delivery was
    // neither unicast to an address this host holds nor multicast to a group,
    // and §11 offers a broadcast no arm at all — so this needs no destination
    // address to decide, which is the whole reason it can be decided here.
    //
    // # Why this is read, having once been declined
    //
    // The declined argument was that closing it grants an attacker nothing,
    // because a sender able to reach us by broadcast could reach us by unicast
    // or by the group instead. That is wrong. A broadcast is blind one-to-many
    // delivery and follows its OWN routing and filtering policy — including
    // directed-broadcast forwarding where an operator has enabled it — while a
    // unicast needs an exact destination address the sender must already know,
    // and the mDNS group is not an equivalent routed path. The three routes
    // have different reachability, so a sender who has the broadcast one may
    // have neither substitute, and refusing it removes reach rather than
    // relabelling it.
    //
    // # What it does and does not close
    //
    // It closes the IPv4 broadcast class on the OpenBSD/NetBSD squares — the
    // only two of the five where `libc` binds the flag. It closes nothing on
    // FreeBSD/DragonFly (no binding) or on `hick-compio`'s Windows square
    // (`recv_from` returns no `msg_flags` to read), and those three keep it.
    //
    // It also leaves, on the very squares it does close, the R10 class beside
    // it: the multicast arm below admits ANY group from ANY source with no
    // prefix test, because "which group" is not a bit and no flag can carry it.
    // That is a reason those squares are not fully closed, not a reason to
    // leave a closable part of them open.
    //
    // The full closure is the destination itself: `hick-udp`'s
    // `multicast::parse_dstaddr_recvif_v4` and `parse_netbsd_pktinfo_v4` (both
    // written and unit-tested, no callers, sockopts never set — see
    // `hick-udp/build.rs` for the per-target evidence a flip needs), the SAME
    // work again in `hick-compio/src/socket/unix.rs` behind that crate's own
    // `has_ip_pktinfo`, and a `WSARecvMsg` receive path for `hick-compio` on
    // Windows. Each moves its square into the first regime entirely — broadcast,
    // foreign group, martian and neighbour address at once. All are tracked
    // separately; none is done here.
    None if delivery == Some(LinkDelivery::Broadcast) => false,
    None if delivery == Some(LinkDelivery::Multicast) => true,
    None => src_on_local_link(src, link, pkt_iface, iface_reported),
  }
}

/// Whether `dst` is an address this endpoint **holds** — what makes a datagram
/// one RFC 6762 §11 calls *"received via unicast"*.
///
/// The loopback block is decided FIRST and totally; every other destination is
/// held only by being in the interface's enumerated configuration.
///
/// # The loopback block is `127.0.0.0/8` entire, per RFC 1122 §3.2.1.3
///
/// That section assigns the WHOLE of `127.0.0.0/8` as "the internal host
/// loopback address", and `::1` is its IPv6 counterpart. A host may address
/// itself at any of the sixteen million, and a stack that loops such a datagram
/// back delivers it with a destination [`collect_local_subnets`] never reported:
/// `getifs` returns the one address the interface was *configured* with, which
/// is `127.0.0.1` on every ordinary system. Exact equality therefore refused
/// `127.0.0.2` — a legitimate unicast destination for this host, and not a
/// broadcast, a martian or a neighbour's address.
///
/// **Scoping it to a loopback-BOUND endpoint is the whole safety argument.** On
/// a real NIC a `127/8` destination is a martian and stays refused, so this
/// widens nothing an off-link sender can reach; and reaching the source arm is
/// not admission — `src_on_local_link` still requires the source to be this
/// endpoint's own loopback traffic or inside a configured prefix. It is the same
/// narrowing `arrived_on_bound_interface` and `src_on_local_link` already apply
/// to a loopback SOURCE, for the same reason.
///
/// ## The check is FIRST because the snapshot is a second way in
///
/// Asking `link.is_loopback() && dst.is_loopback()` and then falling through to
/// snapshot equality is not the rule above — it is that rule OR "the snapshot
/// happens to contain it". A NIC-bound endpoint whose interface carries both
/// `192.168.1.2/24` and `127.0.0.1/8` — one `ifconfig` away, and the ordinary
/// shape of a snapshot taken from a host rather than a fixture — then holds
/// `127.0.0.1` after all, and an in-prefix source reaches the source arm with a
/// loopback destination on a real NIC. So a loopback destination returns
/// `link.is_loopback()` and returns it *before* any snapshot is consulted: for
/// this class the binding is the whole answer, in both directions.
///
/// It is also what settles `127.255.255.255`, which three review rounds argued
/// over: it is an ordinary member of the block, so it is held and it reaches the
/// source arm. Deriving a "broadcast" from `127.0.0.1/8` and refusing it was
/// wrong twice over — a loopback interface has no broadcast capability for the
/// derivation to be about, and the address is not special within the block.
///
/// # Why an address lookup, and not a computation
///
/// [`collect_local_subnets`] stores what `getifs` reports for each interface
/// address: `n.addr()`, the ASSIGNED address, paired with `n.prefix_len()`.
/// Not a masked network address. So the set of addresses a datagram could have
/// been unicast to on this interface is already in [`BoundLink::local_addrs`], and
/// asking whether the destination is in it is a comparison against data the
/// caller collected rather than an inference from a prefix.
///
/// That is the whole reason this file no longer computes a broadcast address.
/// Deriving one from `addr/prefix` was wrong in three directions at once, and
/// each was found separately: the all-ones host address of `127.0.0.1/8` and of
/// a point-to-point interface is not a broadcast, because those interfaces have
/// no broadcast capability, so a legitimate destination was refused; an
/// operator may set a broadcast address that is NOT the all-ones host address
/// (`ip addr add 192.168.1.5/24 broadcast 192.168.1.200` is legal), so the real
/// one stayed in the admitted set; and a `/31` or `/32` has no broadcast at all,
/// so the arithmetic needed exclusions that were themselves load-bearing. None
/// of it is needed to answer the only question §11 asks: was this addressed to
/// us.
///
/// # The prefix length is deliberately not read
///
/// It is §11's SOURCE test that compares against an address *and mask*; the
/// destination test is identity. A destination inside one of our prefixes but
/// not equal to an address we hold — another host's address on our own subnet,
/// or the subnet's broadcast — was addressed to somebody else, and a datagram
/// we were handed anyway (a promiscuous or misrouted delivery) is not one §11
/// gives an arm to.
///
/// # The gap this leaves, named rather than implied
///
/// An address the host holds but `getifs` does not report is refused. The
/// concrete case is **anycast**: Linux carries `IFA_ANYCAST` as an attribute
/// distinct from `IFA_ADDRESS`/`IFA_LOCAL`, and `getifs` 0.6.1 — the pinned
/// version — reads only the latter two (`src/linux/netlink.rs`), while its
/// Windows backend leaves `FirstAnycastAddress` commented out behind a TODO
/// (`src/windows.rs`). There is no accessor to reach them through, so this
/// cannot be closed here; it needs `getifs` to surface anycast addresses, after
/// which they join [`collect_local_subnets`] and this function needs no change.
/// Until then a locally delivered anycast destination takes no §11 arm and is
/// refused. See [`collect_local_subnets`].
fn is_bound_address(dst: IpAddr, link: BoundLink<'_>) -> bool {
  // The loopback class is answered here and does not fall through: a snapshot
  // containing `127.0.0.1/8` alongside a NIC's own address must not hold a
  // loopback destination for a NIC-BOUND endpoint. See above.
  if dst.is_loopback() {
    return link.is_loopback();
  }
  link.local_addrs().iter().any(|&(addr, _)| addr == dst)
}

/// Whether `addr` falls inside `net/prefix`. Mismatched families never match.
fn addr_in_subnet(net: IpAddr, prefix: u8, addr: IpAddr) -> bool {
  match (net, addr) {
    (IpAddr::V4(n), IpAddr::V4(a)) => prefix_match(&n.octets(), &a.octets(), prefix, 32),
    (IpAddr::V6(n), IpAddr::V6(a)) => prefix_match(&n.octets(), &a.octets(), prefix, 128),
    _ => false,
  }
}

fn prefix_match(net: &[u8], addr: &[u8], prefix: u8, max: u8) -> bool {
  if prefix > max {
    return false;
  }
  let full = usize::from(prefix / 8);
  let rem = prefix % 8;
  if net.get(..full) != addr.get(..full) {
    return false;
  }
  if rem == 0 {
    return true;
  }
  // `rem` is 1..=7 here, so the shift distance is 1..=7 and no operation below
  // can overflow. Spelled with the wrapping forms so the trust boundary carries
  // no panicking arithmetic even on a caller that reaches it some other way.
  let mask = 0xffu8.wrapping_shl(u32::from(8u8.wrapping_sub(rem)));
  match (net.get(full), addr.get(full)) {
    (Some(n), Some(a)) => (n & mask) == (a & mask),
    // Unreachable with this module's callers: both slices are whole
    // `Ipv4Addr`/`Ipv6Addr` octet arrays and `prefix <= max` was checked above,
    // so a non-zero `rem` always leaves `full` in range. `false` regardless,
    // because this file is the RFC 6762 §11 trust boundary and a partial byte
    // it cannot compare is not evidence of a match. Failing open here would
    // admit an off-link source on a slice this function never proved anything
    // about.
    _ => false,
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

/// §11's **unicast** arm — PRIVATE, and deliberately so.
///
/// It is one stage of a sequence and is correct only when reached through
/// `admits_ingress`, which has already settled which link the datagram arrived
/// on. Called directly it ignores `pkt_iface` and `iface_reported` for every
/// source but loopback, so a foreign-scoped `fe80::` peer with a matching
/// `fe80::/64` prefix would come back `true`. The hoist made it public by
/// accident; a helper that only behaves when someone else went first has no
/// business on a crate's surface.
///
/// Trust a source that is link-local on the receiving
/// interface, or that falls inside a subnet configured on the bound interface.
///
/// Reached only through [`admits_ingress`], which has already required the
/// datagram to have arrived on the bound interface AND its destination to be one
/// of this interface's own addresses — so as far as this platform can report, it
/// was addressed to this host rather than to a group, a broadcast or a neighbour.
/// §11 scopes this source check to a response *"received via unicast"*, because a
/// group destination settles the question by itself and a source prefix could
/// only overrule it wrongly.
///
/// The one other way in is an EMPTY snapshot, where the destination test has
/// nothing to answer from; see the arm that takes it in [`admits_ingress`]. This
/// function is what bounds that fallback: with no prefixes to match, the
/// comparison below admits nothing, and the loopback arm above admits only a
/// loopback-BOUND endpoint's own traffic.
///
/// The link-local arm below keeps its own copy of the interface check anyway:
/// this is the trust boundary, it costs one integer comparison, and a caller
/// that reaches this function by some other route must not silently lose it. It
/// delegates to `arrived_on_bound_interface` rather than restating the rule,
/// so the copy cannot become a weaker copy — a bare `pkt_iface` test admits a
/// link-local source carrying a foreign scope id.
///
/// A loopback source answers to the same link evidence as a link-local one, for
/// the reason `arrived_on_bound_interface` gives: the source address alone is
/// forgeable onto a real NIC wherever an operator has stopped treating `127/8`
/// as martian, so only a loopback-BOUND endpoint is exempt from proving where
/// its traffic came from.
fn src_on_local_link(
  src: SocketAddr,
  link: BoundLink<'_>,
  pkt_iface: u32,
  iface_reported: bool,
) -> bool {
  let ip = src.ip();
  // Link-local is deliberately NOT classified here any more. It used to select a
  // branch of its own, which was a third arm §11 does not have; every
  // non-loopback source now takes the same prefix comparison, and an interface
  // holding a link-local address reports the matching prefix for it.
  if ip.is_loopback() {
    // Our own traffic, and only for the endpoint whose link the loopback
    // interface actually IS. To anyone else a loopback source is not evidence
    // of anything — it is an address a sender wrote, deliverable onto a real
    // NIC wherever an operator has stopped treating `127/8` as martian.
    // Whether a witness contradicts it is `arrived_on_bound_interface`'s
    // question, asked there rather than restated here.
    return link.is_loopback() && arrived_on_bound_interface(src, link, pkt_iface, iface_reported);
  }
  // EVERY other source — routable or link-local, witnessed or not — answers to
  // §11's unicast test as the RFC states it: the source address against the
  // addresses and masks configured on the receiving interface, or its on-link
  // IPv6 prefixes.
  //
  // §11 has exactly two arms and this is the second of them. A witnessed
  // link-local source used to return here on the witness alone, which was a
  // THIRD arm the RFC does not have: it admitted `169.254.7.7` on an interface
  // configured only for `192.168.1.0/24`, where §11 requires the prefix
  // comparison for every non-group destination. A witness settles which LINK a
  // datagram arrived on — stage 1's question — and never whether its source
  // belongs to a prefix this interface carries.
  //
  // Link-local is not excluded from the test either, in the other direction: §11
  // names no exception for `169.254/16`, and an infrastructure-less link is
  // where mDNS is most load-bearing. A host there holds a `169.254/16` address,
  // so the prefix is configured and its peers match it. IPv6 needs no special
  // case for the same reason — an interface with a link-local address carries
  // `fe80::/64`, which is precisely one of the "on-link IPv6 prefixes on the
  // interface receiving the packet" §11 points at.
  //
  // An empty subnet list makes this `false`, so a source with no matching
  // prefix is dropped — fail-CLOSED per §11.
  //
  // The residual is the same-prefix one, and it is the same for a link-local
  // source as for any other: where nothing witnessed the link, a second NIC
  // sharing the prefix satisfies this legitimately and an adjacent sender
  // satisfies it by choosing an in-prefix source. See this module's header.
  link
    .onlink_prefixes()
    .iter()
    .any(|&(net, pfx)| addr_in_subnet(net, pfx, ip))
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

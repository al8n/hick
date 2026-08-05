//! Emits capability `cfg`s for the receive-side ancillary (cmsg) features hick-udp
//! uses, so the per-function `#[cfg]`s reference ONE central availability matrix
//! instead of hand-maintained `target_os` lists (which repeatedly drifted out of
//! sync with what `libc` actually defines).
//!
//! Supported targets are capped by the `getifs` dependency (linux/android,
//! apple, freebsd/dragonfly, openbsd/netbsd, windows); illumos/solaris/fuchsia
//! and other Unixes are intentionally out of scope and get none of these cfgs.
//!
//! Capability → enabling libc constants (verified against libc 0.2):
//!   * has_ip_pktinfo IP_PKTINFO / IP_RECVPKTINFO (+ in_pktinfo parse)
//!   * has_ip_dstaddr_recvif IP_RECVDSTADDR + IP_RECVIF, the BSD spelling of
//!     the same two facts — the IP header destination and the receiving
//!     interface — carried in two separate cmsgs instead of one struct
//!   * has_ipv6_pktinfo IPV6_PKTINFO + IPV6_RECVPKTINFO
//!   * has_recv_hoplimit IP_RECVTTL + IPV6_HOPLIMIT + IPV6_RECVHOPLIMIT, for
//!     the `RecvMeta::hop_limit` diagnostic; no §11 decision reads it
//!   * has_msg_mcast MSG_MCAST, the `recvmsg` result flag saying the datagram
//!     was delivered as a multicast rather than to this host alone
//!   * has_msg_bcast MSG_BCAST, its sibling saying the datagram was delivered
//!     as a link-layer broadcast — negative evidence RFC 6762 §11 gives no arm
//!     to, and what still decides a netbsdlike IPv4 datagram whose cmsg the
//!     kernel declined to emit
//!   * has_recv_timestamp SO_TIMESTAMP[NS] + SCM_TIMESTAMP[NS]
//!   * recv_timestamp_ns the timestamp cmsg is nanosecond SO_TIMESTAMPNS
//!     (Linux/Android); otherwise it is microsecond SO_TIMESTAMP.
//!
//! One further cfg — `ipv4_rx_netbsd_pktinfo` — is NOT a capability and is
//! listed apart from the matrix above on purpose: it only decides whether this
//! crate compiles one extra IPv4 ancillary PARSER, and nothing consults it to
//! decide what a receiver may conclude. Its sibling `ipv4_rx_dstaddr_recvif`
//! WAS such a selector and has been promoted to the `has_ip_dstaddr_recvif`
//! capability above; see that emit site for the evidence the promotion rests
//! on, and for why NetBSD takes the promoted pair rather than its own
//! `IP_PKTINFO`.
//!
//! Every cfg here answers "does `libc` BIND this constant for the target",
//! which is not the same question as "can the target report this". Where the
//! two diverge the comment at the emit site says so, because a fail-open
//! exemption justified on "the platform provably cannot answer" is unearned
//! when the real gap is a binding this crate has not reached for.

fn main() {
  println!("cargo:rerun-if-changed=build.rs");

  // Declare every cfg we may emit so the `unexpected_cfgs` lint (the crate
  // builds under `-D warnings`) recognises them whether or not they fire.
  for name in [
    "has_ip_pktinfo",
    "has_ip_dstaddr_recvif",
    "has_ipv6_pktinfo",
    "has_recv_hoplimit",
    "has_msg_mcast",
    "has_msg_bcast",
    "has_recv_timestamp",
    "recv_timestamp_ns",
    "ipv4_rx_netbsd_pktinfo",
  ] {
    println!("cargo::rustc-check-cfg=cfg({name})");
  }

  let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
  let vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();

  // Target families (mirrors getifs' own grouping). `target_vendor = "apple"`
  // covers macos/ios/tvos/watchos/visionos uniformly.
  let apple = vendor == "apple";
  let linux_like = os == "linux" || os == "android";
  let freebsdlike = os == "freebsd" || os == "dragonfly";
  let netbsdlike = os == "openbsd" || os == "netbsd";

  // IPv4 PKTINFO: only Linux/Android/Apple, which share the 12-byte in_pktinfo
  // layout (ipi_ifindex / ipi_spec_dst / ipi_addr) that `parse_pktinfo_v4`
  // decodes. The BSDs are excluded: FreeBSD/OpenBSD/DragonFly have no IP_PKTINFO
  // at all, and NetBSD's in_pktinfo is a DIFFERENT 8-byte layout (ipi_addr /
  // ipi_ifindex) the shared parser would misread as too-short. They recover the
  // same two facts through `has_ip_dstaddr_recvif` just below instead.
  if linux_like || apple {
    println!("cargo::rustc-cfg=has_ip_pktinfo");
  }
  // The BSD spelling of IPv4 receive metadata, and a CAPABILITY: two separate
  // cmsgs, `IP_RECVDSTADDR` carrying a bare `struct in_addr` — the IP header
  // destination, `ip->ip_dst` — and `IP_RECVIF` carrying a variable-length
  // `struct sockaddr_dl` whose `sdl_index` is the receiving interface. Not an
  // `in_pktinfo` in either case. `libc` binds both for every BSD here:
  // freebsdlike (src/unix/bsd/freebsdlike/mod.rs:921,925), OpenBSD
  // (src/unix/bsd/netbsdlike/openbsd/mod.rs:1049,1051) and NetBSD
  // (src/unix/bsd/netbsdlike/netbsd/mod.rs:954,956).
  //
  // This drives `multicast::parse_dstaddr_recvif_v4`, the matching
  // `platform::set_recv_dstaddr_recvif_v4` enable + read-back, and
  // `reports_rx_interface_v4()`. Setting it INVERTS the ingress rule a receiver
  // applies to a datagram with no interface witness — "no witness ⇒ admit"
  // becomes "no witness ⇒ drop" (see `onlink::arrived_on_bound_interface`) — so
  // a silently wrong parse would not degrade, it would make the responder deaf
  // on IPv4 while still looking healthy. That is what the standing rule below
  // exists for.
  //
  // NETBSD TAKES THIS PAIR AND NOT ITS OWN `IP_PKTINFO`, deliberately. NetBSD is
  // the one BSD that also defines IP_PKTINFO/IP_RECVPKTINFO
  // (netbsd/mod.rs:957-958) and `multicast::parse_netbsd_pktinfo_v4` decodes it,
  // but `ip_savecontrol` (sys/netinet/ip_input.c) emits INP_RECVDSTADDR at
  // :1366 — BEFORE the `ifp = m_get_rcvif_psref(m, &psref); if (ifp == NULL)
  // return;` at :1381-1387 — and INP_RECVPKTINFO at :1389 and INP_RECVIF at
  // :1398, both AFTER it. A datagram whose receive interface has detached
  // therefore keeps its destination under IP_RECVDSTADDR and loses it entirely
  // under IP_PKTINFO. The destination is the fact RFC 6762 §11 partitions on
  // and the interface only scopes the link, so the pair strictly dominates:
  // where PKTINFO would witness nothing, the pair still witnesses the group.
  // `ipv4_rx_netbsd_pktinfo` below keeps that parser compiled and unwired.
  //
  // ── THE STANDING RULE ────────────────────────────────────────────────────
  // No capability constant is added or flipped without these four items
  // written HERE, at the emit site, with how each was established. Items 1-3
  // are the enable, the group destination and the unicast destination; item 4
  // is that MSG_CTRUNC stays clear once the new cmsgs join the ones already
  // enabled. Evidence from one target is not evidence for another: `IP_RECVIF`
  // is 20 on FreeBSD/DragonFly/NetBSD but 30 on OpenBSD, and `struct
  // sockaddr_dl` has a different trailing shape — and so a different size — on
  // each of them.
  //
  //   1. THE ENABLE. `setsockopt(IPPROTO_IP, IP_RECVDSTADDR|IP_RECVIF, 1)`
  //      returns 0 on a wildcard-bound 0.0.0.0:5353 socket joined to
  //      224.0.0.251. Executed by `bsd_ipv4_bind_enables_the_receive_metadata_pair`,
  //      which binds through `try_bind_v4` — so through the real enable — joins
  //      the group, and then reads BOTH options back with `getsockopt` and
  //      requires each non-zero. DragonFly/OpenBSD/NetBSD have no runner, so the
  //      same check also runs ON EVERY PRODUCTION BIND: `set_recv_dstaddr_recvif_v4`
  //      fails the bind on a non-zero return and `verify_rx_dstaddr_recvif_v4`
  //      fails it unless the kernel reports both set. That read-back is safe to
  //      make load-bearing because all four kernels handle these two options
  //      under the GET direction as well as the SET one — FreeBSD
  //      `sys/netinet/ip_output.c` `ip_ctloutput` (`OPTSET(INP_RECVDSTADDR)` /
  //      `optval = OPTBIT(INP_RECVDSTADDR)`, same for INP_RECVIF), DragonFly the
  //      same shape, OpenBSD's `PRCO_SETOPT`/`PRCO_GETOPT` case lists, NetBSD's
  //      `ip_ctloutput`. A getsockopt that could return ENOPROTOOPT would have
  //      made this a bind outage on three untested targets, which is why it was
  //      read out of each kernel before being relied on.
  //   2. THE GROUP DESTINATION. A datagram to 224.0.0.251 yields destination
  //      224.0.0.251, and a receive interface index equal to the index of the
  //      NIC that carried it. The address half is `ip_savecontrol` copying
  //      `ip->ip_dst` — the IP header destination verbatim, with no rewrite on
  //      the local-delivery path — in all four kernels: FreeBSD def. :1143 /
  //      emit :1238-1240, OpenBSD :1860 / :1873-1875, NetBSD :1522 / :1531-1533
  //      (:1366-1371 in trunk), DragonFly :2193 / :2205-2207. Executed by
  //      `bsd_ipv4_recv_witnesses_the_group_and_a_unicast_destination`, which
  //      asserts the exact group address rather than "is multicast", and by
  //      `bsd_ipv4_recv_witnesses_the_interface_that_carried_the_datagram`, which
  //      asserts the index equals `getifs`' index for the egress NIC and — where
  //      the host has more than one — that different NICs yield DIFFERENT
  //      indices, since telling "arrived elsewhere" from "platform never says" is
  //      the whole value of the flip. A single-NIC host prints that half as NOT
  //      covered rather than passing it vacuously.
  //   3. THE UNICAST DESTINATION. A datagram to one of the host's own addresses
  //      yields THAT address, so the §11 group arm is not taken for a unicast
  //      arrival. Same kernel lines as item 2 — one `ip->ip_dst` copy serves both
  //      — and executed by the same test as the group half, on the SAME socket,
  //      which is what pins that the two readings cannot collapse onto each
  //      other. It asserts the recovered destination equals the host address and
  //      is NOT the group.
  //   4. NO TRUNCATION. Measured, not asserted:
  //      `control_buffer_holds_every_cmsg_this_target_enables` sums
  //      `libc::CMSG_SPACE` over every cmsg this crate enables for the target it
  //      is compiled for — at the widest payload each can carry — and fails if
  //      the total does not fit `CmsgBuf`, then again if it does not fit twice
  //      over. On FreeBSD/amd64 the worst case is 152 bytes against a 512-byte
  //      buffer, of which IP_RECVIF's padded `sockaddr_dl` is 72. The buffer was
  //      already 512; what this change adds is the measurement, so the figure in
  //      `CmsgBuf`'s doc stops being a claim and starts being a test.
  //
  // WHERE ITEMS 1-3 HAVE ACTUALLY EXECUTED, stated exactly. ci.yml's `freebsd`
  // job names all six tests in `REQUIRED_TESTS`, so FreeBSD 14.4 is covered per
  // run. The other three targets are covered by the on-bind read-back in item 1
  // and by nothing else — no runner exists for them, and the kernel reading
  // above is source, not execution. During development the same three tests were
  // also run on macOS by temporarily emitting this cfg for `apple` (XNU binds
  // IP_RECVDSTADDR=7 / IP_RECVIF=20 with the same `sockaddr_dl` prefix, and its
  // `ip_savecontrol` is the FreeBSD one): all three passed and IP_RECVIF
  // distinguished six interfaces. That is a cross-check of THIS crate's code
  // against a fourth BSD-derived kernel, and deliberately not one of the items
  // above — Apple is not a target this cfg is emitted for, and evidence from one
  // target is not evidence for another.
  if freebsdlike || netbsdlike {
    println!("cargo::rustc-cfg=has_ip_dstaddr_recvif");
  }
  // NetBSD's `IP_RECVPKTINFO`-enabled `IP_PKTINFO` cmsg, carrying its own 8-byte
  // `in_pktinfo` (`ipi_addr` then `ipi_ifindex`) rather than the 12-byte
  // Linux/Apple layout `parse_pktinfo_v4` decodes. A PARSER SELECTOR and not a
  // capability — read by `#[cfg]` on `parse_netbsd_pktinfo_v4` and its layout
  // assertions, and by nothing that decides what a receiver may conclude.
  //
  // It stays compiled and unwired on purpose. The psref ordering documented
  // above makes it the strictly weaker of NetBSD's two shapes, so promoting it
  // would be a regression, not a second option; keeping it costs one `pub`
  // function and buys the `const _` assertions that pin NetBSD's `in_pktinfo`
  // layout, which are what would catch that struct changing under us.
  if os == "netbsd" {
    println!("cargo::rustc-cfg=ipv4_rx_netbsd_pktinfo");
  }
  // IPv6 PKTINFO: every supported Unix defines both IPV6_PKTINFO and
  // IPV6_RECVPKTINFO.
  if linux_like || apple || freebsdlike || netbsdlike {
    println!("cargo::rustc-cfg=has_ipv6_pktinfo");
  }
  // Inbound TTL/Hop-Limit receive cmsg, surfaced as a DIAGNOSTIC on
  // `RecvMeta::hop_limit`. RFC 6762 §11's receive test is stated exhaustively
  // and both ways are about the destination address, so nothing admits or
  // refuses on this value and a target without the cmsg loses no admission
  // capability. Off on netbsdlike because `libc` BINDS none of
  // IP_RECVTTL/IPV6_HOPLIMIT/IPV6_RECVHOPLIMIT for OpenBSD or NetBSD — a
  // binding gap rather than a platform incapability, both being KAME-derived
  // stacks that report the hop limit exactly as RFC 3542 specifies.
  if linux_like || apple || freebsdlike {
    println!("cargo::rustc-cfg=has_recv_hoplimit");
  }
  // MSG_MCAST: the `recvmsg` result flag saying the datagram arrived as a
  // multicast rather than addressed to this host. Bound only for netbsdlike
  // (src/unix/bsd/netbsdlike/mod.rs:577, value 0x200) among the targets this
  // crate supports. It is coarse — it names no group — and it is no longer the
  // only destination evidence on the OpenBSD/NetBSD IPv4 square:
  // `has_ip_dstaddr_recvif` now witnesses the address itself there. What it
  // still covers is the DECLINED datagram, where the kernel emitted no cmsg and
  // flagged no truncation; RFC 6762 §11 selects its two local-link tests by
  // destination, so a coarse answer beats none.
  if netbsdlike {
    println!("cargo::rustc-cfg=has_msg_mcast");
  }
  // MSG_BCAST: the sibling result flag saying the datagram arrived as a
  // link-layer BROADCAST. Bound for netbsdlike and nobody else
  // (src/unix/bsd/netbsdlike/mod.rs:576, value 0x100, one line above the
  // MSG_MCAST above), and read from the same `msg_flags` word in the same
  // decode.
  //
  // NOT one of the flips the block above sets an evidence bar for, and the
  // distinction is worth stating. That bar exists because promoting
  // `has_ip_pktinfo` INVERTS what an absent interface witness means, so a
  // silently wrong parse turns into silent deafness. This cfg sets no sockopt,
  // parses no cmsg and touches no witness rule: it reads one more bit of a word
  // `recvmsg` already returns and this crate already reads, and it can only make
  // `admits_ingress` refuse a datagram the kernel called a broadcast — which
  // §11 gives no arm to whatever else is true of it. The one way it could cost
  // availability is a kernel that sets MSG_BCAST on group traffic, and
  // `msg_link_delivery` resolves that contradiction toward MSG_MCAST for
  // exactly that reason.
  if netbsdlike {
    println!("cargo::rustc-cfg=has_msg_bcast");
  }
  // Kernel receive-timestamp cmsg (all supported Unix).
  if linux_like || apple || freebsdlike || netbsdlike {
    println!("cargo::rustc-cfg=has_recv_timestamp");
  }
  // Linux/Android deliver nanosecond SO_TIMESTAMPNS; the BSDs/Apple deliver
  // microsecond SO_TIMESTAMP.
  if linux_like {
    println!("cargo::rustc-cfg=recv_timestamp_ns");
  }
}

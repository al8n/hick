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
//!   * has_ipv6_pktinfo IPV6_PKTINFO + IPV6_RECVPKTINFO
//!   * has_recv_hoplimit IP_RECVTTL + IPV6_HOPLIMIT + IPV6_RECVHOPLIMIT, for
//!     the `RecvMeta::hop_limit` diagnostic; no §11 decision reads it
//!   * has_msg_mcast MSG_MCAST, the `recvmsg` result flag saying the datagram
//!     was delivered as a multicast rather than to this host alone
//!   * has_msg_bcast MSG_BCAST, its sibling saying the datagram was delivered
//!     as a link-layer broadcast — negative evidence RFC 6762 §11 gives no arm
//!     to, and the only exact destination fact the netbsdlike IPv4 square has
//!   * has_recv_timestamp SO_TIMESTAMP[NS] + SCM_TIMESTAMP[NS]
//!   * recv_timestamp_ns the timestamp cmsg is nanosecond SO_TIMESTAMPNS
//!     (Linux/Android); otherwise it is microsecond SO_TIMESTAMP.
//!
//! Two further cfgs — `ipv4_rx_dstaddr_recvif` and `ipv4_rx_netbsd_pktinfo` —
//! are NOT capabilities and are listed apart from the matrix above on purpose:
//! they only decide which IPv4 ancillary PARSER this crate compiles for a BSD
//! target. Nothing consults them to decide what a receiver may conclude. See
//! their emit site for the distinction and for the evidence a promotion needs.
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
    "has_ipv6_pktinfo",
    "has_recv_hoplimit",
    "has_msg_mcast",
    "has_msg_bcast",
    "has_recv_timestamp",
    "recv_timestamp_ns",
    "ipv4_rx_dstaddr_recvif",
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
  // ipi_ifindex) the shared parser would misread as too-short. All of
  // them degrade to an unspecified local address + interface index 0, exactly
  // as the IPv4 path already does elsewhere.
  //
  // That degradation is this crate's, not the platforms'. `libc` binds
  // IP_RECVDSTADDR + IP_RECVIF for every BSD here — freebsdlike
  // (src/unix/bsd/freebsdlike/mod.rs:921,925), OpenBSD
  // (src/unix/bsd/netbsdlike/openbsd/mod.rs:1049,1051) and NetBSD
  // (src/unix/bsd/netbsdlike/netbsd/mod.rs:954,956) — plus
  // IP_PKTINFO/IP_RECVPKTINFO for NetBSD (netbsd/mod.rs:957-958). The parsers
  // for those shapes now exist (`multicast::parse_dstaddr_recvif_v4` and
  // `multicast::parse_netbsd_pktinfo_v4`, selected by the two cfgs below), but
  // NOTHING CALLS THEM: `recv_with_meta` still takes the degraded path, so an
  // IPv4 datagram on these targets has no recovered destination,
  // `RecvMeta::destination` returns `None`, and RFC 6762 §11's group arm is
  // still selected by the coarser `has_msg_mcast` flag below.
  if linux_like || apple {
    println!("cargo::rustc-cfg=has_ip_pktinfo");
  }
  // The two BSD IPv4 receive-metadata shapes, as PARSER SELECTORS — read by
  // `#[cfg]` on the parsers themselves and by nothing else. Deliberately not
  // named `has_*`: `reports_rx_interface_v4()` reads `has_ip_pktinfo`, and
  // widening it to these would be a behaviour change, not a compile-target
  // change. Keeping them apart is the point.
  //
  //   * ipv4_rx_dstaddr_recvif — FreeBSD/DragonFly/OpenBSD: two separate
  //     cmsgs, `IP_RECVDSTADDR` carrying a bare `struct in_addr` (the IP
  //     header destination, `ip->ip_dst`) and `IP_RECVIF` carrying a
  //     variable-length `struct sockaddr_dl` whose `sdl_index` is the
  //     receiving interface. Not an `in_pktinfo` in either case. NetBSD binds
  //     this pair too but takes the single-cmsg route below instead.
  //   * ipv4_rx_netbsd_pktinfo — NetBSD only: `IP_RECVPKTINFO` enables an
  //     `IP_PKTINFO` cmsg carrying NetBSD's own 8-byte `in_pktinfo`
  //     (`ipi_addr` then `ipi_ifindex`), which is NOT the 12-byte
  //     Linux/Apple layout `parse_pktinfo_v4` decodes.
  //
  // WHY THE PARSERS LAND WITHOUT THE FLIP. Setting `has_ip_pktinfo` for these
  // targets inverts the ingress rule a receiver applies to a datagram with no
  // interface witness: "no witness ⇒ admit" becomes "no witness ⇒ drop" (see
  // `hick-mio`'s `arrived_on_bound_interface`). A parse that is silently wrong
  // would then not degrade — it would make the responder deaf on IPv4 while
  // still looking healthy. Unit tests over synthesized cmsg buffers prove the
  // BYTE LAYOUT and nothing else; they cannot prove the kernel delivers these
  // cmsgs at all. CI now runs them on a real FreeBSD (ci.yml's `freebsd` job),
  // which settles the layout on that one target and leaves every item below
  // untouched; DragonFly, OpenBSD and NetBSD are still only cross-COMPILED. So
  // the parsers ship inert and the flip is a separate change, per target, once
  // a real host of that target shows:
  //   1. the enabling setsockopt (`IP_RECVDSTADDR` + `IP_RECVIF`, or
  //      `IP_RECVPKTINFO`) returns 0 on a wildcard-bound 0.0.0.0:5353 socket
  //      joined to 224.0.0.251;
  //   2. a multicast datagram to that group yields destination 224.0.0.251 and
  //      an interface index equal to `if_nametoindex` of the NIC that carried
  //      it — checked on a NIC that is NOT the bound one as well, since the
  //      whole value of the flip is telling "arrived elsewhere" from "platform
  //      never says";
  //   3. a unicast datagram to one of the host's own addresses yields THAT
  //      address as the destination, so the group arm is not taken for unicast;
  //   4. `MSG_CTRUNC` stays clear with the existing 256-byte control buffer once
  //      these cmsgs join the timestamp/TTL ones already enabled.
  // Evidence from one target is not evidence for another: `IP_RECVIF` is 20 on
  // FreeBSD/DragonFly/NetBSD but 30 on OpenBSD, and `struct sockaddr_dl` has a
  // different trailing shape (and so a different size) on each of them.
  if freebsdlike || os == "openbsd" {
    println!("cargo::rustc-cfg=ipv4_rx_dstaddr_recvif");
  }
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
  // crate supports. It is coarse — it names no group — but on OpenBSD/NetBSD
  // IPv4 it is the ONLY destination evidence there is, and RFC 6762 §11 selects
  // its two local-link tests by destination.
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

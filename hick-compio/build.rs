//! Emits capability `cfg`s for the receive-side ancillary (cmsg) features
//! hick-compio uses, so the per-function `#[cfg]`s reference ONE central
//! availability matrix instead of hand-maintained `target_os` lists (which
//! repeatedly drifted out of sync with what `libc` actually defines).
//!
//! This matrix is kept identical to `hick-udp/build.rs` on purpose: both crates
//! decode the same cmsg families against the same `libc` constants, so sharing
//! one matrix (down to the emitted cfg names) keeps the two recv paths in step.
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
//!     the hop-limit diagnostic; no §11 decision reads it
//!   * has_recv_timestamp SO_TIMESTAMP[NS] + SCM_TIMESTAMP[NS]
//!   * recv_timestamp_ns the timestamp cmsg is nanosecond SO_TIMESTAMPNS
//!     (Linux/Android); otherwise it is microsecond SO_TIMESTAMP.
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
    "has_recv_timestamp",
    "recv_timestamp_ns",
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
  // layout (ipi_ifindex / ipi_spec_dst / ipi_addr) that the v4 decoder reads.
  // The BSDs are excluded: FreeBSD/OpenBSD/DragonFly have no IP_PKTINFO at all,
  // and NetBSD's in_pktinfo is a DIFFERENT 8-byte layout (ipi_addr /
  // ipi_ifindex) the shared parser would misread as too-short. They recover the
  // same two facts through `has_ip_dstaddr_recvif` just below instead.
  if linux_like || apple {
    println!("cargo::rustc-cfg=has_ip_pktinfo");
  }
  // The BSD spelling of IPv4 receive metadata, and a CAPABILITY: two separate
  // cmsgs, `IP_RECVDSTADDR` carrying a bare `struct in_addr` — the IP header
  // destination, `ip->ip_dst` — and `IP_RECVIF` carrying a variable-length
  // `struct sockaddr_dl` whose `sdl_index` is the receiving interface. `libc`
  // binds both for every BSD here: freebsdlike
  // (src/unix/bsd/freebsdlike/mod.rs:921,925), OpenBSD
  // (src/unix/bsd/netbsdlike/openbsd/mod.rs:1049,1051) and NetBSD
  // (src/unix/bsd/netbsdlike/netbsd/mod.rs:954,956).
  //
  // This drives `socket::unix::enable_recv_cmsgs`' IPv4 arm, the
  // `hick_udp::parse_dstaddr_recvif_v4` call in `decode_unix_cmsgs`, and
  // `socket::rx_interface_reported`'s IPv4 answer. Setting it INVERTS the
  // ingress rule this driver applies to a datagram with no interface witness —
  // "no witness ⇒ admit" becomes "no witness ⇒ drop" (see
  // `hick_udp::onlink::arrived_on_bound_interface`) — so a silently wrong parse
  // would not degrade, it would make the responder deaf on IPv4 while still
  // looking healthy. That is what the standing rule below exists for.
  //
  // THE EMIT CONDITION IS `hick-udp/build.rs`' VERBATIM, and must stay so. This
  // crate calls `hick_udp::parse_dstaddr_recvif_v4`, which exists only where
  // THAT crate emits the same cfg, so a divergence is a missing-function
  // compile error naming the parser rather than a silent capability drift. That
  // is the intended failure mode: the two matrices are kept identical on
  // purpose (see this file's header), and the one place a mismatch could hide
  // is the one place the compiler now refuses it.
  //
  // NETBSD TAKES THIS PAIR AND NOT ITS OWN `IP_PKTINFO`, deliberately, for the
  // reason set out at `hick-udp/build.rs`'s emit site: `ip_savecontrol`
  // (sys/netinet/ip_input.c) emits INP_RECVDSTADDR at :1366 — BEFORE the
  // `ifp = m_get_rcvif_psref(m, &psref); if (ifp == NULL) return;` at :1381-1387
  // — and INP_RECVPKTINFO at :1389 after it, so a datagram whose receive
  // interface has detached keeps its destination under IP_RECVDSTADDR and loses
  // it entirely under IP_PKTINFO. This crate has no NetBSD `in_pktinfo` parser
  // at all and needs none.
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
  //      returns 0 on the AF_INET socket `Socket::from_std` wraps. Executed by
  //      `bsd_ipv4_enable_recv_cmsgs_sets_the_receive_metadata_pair`, which calls
  //      the PRODUCTION `enable_recv_cmsgs` on a wildcard-bound v4 socket and
  //      then reads BOTH options back with `getsockopt`, requiring each
  //      non-zero. That read-back is safe to make load-bearing because all four
  //      kernels handle these two options under the GET direction as well as the
  //      SET one, cited per kernel at `hick-udp/build.rs`'s item 1. This crate's
  //      enable is a SECOND one: every endpoint socket also passes through
  //      `hick_udp::try_bind_v4` (see `endpoint.rs`), whose own
  //      `verify_rx_dstaddr_recvif_v4` fails the bind unless the kernel reports
  //      both set — so on the production path the pair is enabled and checked
  //      once per crate. This crate still sets it because `Socket::from_std` is
  //      public and wraps any bound socket, and a capability constant that is
  //      only true for sockets bound elsewhere is not this path's capability.
  //   2. THE GROUP DESTINATION. A datagram to 224.0.0.251 yields destination
  //      224.0.0.251 and a receive interface index equal to the index of the NIC
  //      that carried it. Executed END TO END by
  //      `bsd_ipv4_recv_witnesses_the_group_destination`, which sends over
  //      loopback multicast and reads through this driver's own `Socket::recv` —
  //      compio's `recv_msg` and `decode_unix_cmsgs`, not `recv_with_meta` — and
  //      asserts the exact group address rather than "is multicast". That the
  //      KERNEL fills `IP_RECVDSTADDR` with `ip->ip_dst` verbatim is one kernel
  //      fact established once, at `hick-udp/build.rs`'s item 2 (FreeBSD def.
  //      :1143 / emit :1238-1240, OpenBSD :1860 / :1873-1875, NetBSD :1522 /
  //      :1531-1533, DragonFly :2193 / :2205-2207); what is THIS crate's is the
  //      decode and the wiring, which is what the test above executes.
  //   3. THE UNICAST DESTINATION. A datagram to one of the host's own addresses
  //      yields THAT address, so the §11 group arm is not taken for a unicast
  //      arrival. Executed by
  //      `bsd_ipv4_recv_witnesses_a_unicast_destination`, on an EPHEMERAL-port
  //      socket whose only enable is this crate's own `enable_recv_cmsgs` — so
  //      it is item 1 end to end as well as item 3. It asserts the recovered
  //      destination equals the host address and is NOT the group. Ephemeral
  //      rather than 5353 because `try_bind_v4` sets SO_REUSEPORT there, and a
  //      UNICAST datagram to a reuse group is delivered to exactly one member of
  //      it — which on any host running another responder is not necessarily us.
  //   4. NO TRUNCATION. Measured, not asserted:
  //      `control_buffer_holds_every_cmsg_this_target_enables` sums
  //      `libc::CMSG_SPACE` over every cmsg this crate enables for the target it
  //      is compiled for — at the widest payload each can carry — and fails if
  //      the total does not fit `AlignedCtrlBuf`, then again if it does not fit
  //      twice over. On FreeBSD/amd64 the worst case is 152 bytes, of which
  //      IP_RECVIF's padded `sockaddr_dl` is 72. THE BUFFER WAS 256 AND IS NOW
  //      512: 152 fits either way, but 2x headroom does not fit in 256, and this
  //      crate's buffer had no measurement behind its old figure at all.
  //
  // WHERE ITEMS 1-3 HAVE ACTUALLY EXECUTED, stated exactly. ci.yml's `freebsd`
  // job names all three in `REQUIRED_COMPIO_EVIDENCE`, so FreeBSD 14.4 is
  // covered per run. DragonFly, OpenBSD and NetBSD have no runner: what stands
  // in for them is `hick_udp::try_bind_v4`'s on-bind read-back, which every
  // endpoint socket goes through and which fails the bind rather than reporting
  // a capability it does not have. During development the same three tests were
  // also run on macOS by temporarily emitting this cfg for `apple` in BOTH
  // crates' build.rs (XNU binds IP_RECVDSTADDR=7 / IP_RECVIF=20 with the same
  // `sockaddr_dl` prefix, and its `ip_savecontrol` is the FreeBSD one): all
  // three passed. That is a cross-check of THIS crate's code against a fourth
  // BSD-derived kernel, and deliberately not one of the items above — Apple is
  // not a target this cfg is emitted for, and evidence from one target is not
  // evidence for another.
  if freebsdlike || netbsdlike {
    println!("cargo::rustc-cfg=has_ip_dstaddr_recvif");
  }
  // IPv6 PKTINFO: every supported Unix defines both IPV6_PKTINFO and
  // IPV6_RECVPKTINFO.
  if linux_like || apple || freebsdlike || netbsdlike {
    println!("cargo::rustc-cfg=has_ipv6_pktinfo");
  }
  // Inbound TTL/Hop-Limit receive cmsg, surfaced as a DIAGNOSTIC only: RFC 6762
  // §11's receive test is about the destination address and reads no TTL, so a
  // target without this cmsg loses no admission capability. Absent on netbsdlike
  // (OpenBSD/NetBSD don't define IP_RECVTTL/IPV6_HOPLIMIT/IPV6_RECVHOPLIMIT).
  if linux_like || apple || freebsdlike {
    println!("cargo::rustc-cfg=has_recv_hoplimit");
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

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
//!   * has_recv_hoplimit IP_RECVTTL + IPV6_HOPLIMIT + IPV6_RECVHOPLIMIT (§11)
//!   * has_msg_mcast MSG_MCAST, the `recvmsg` result flag saying the datagram
//!     was delivered as a multicast rather than to this host alone
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
    "has_ipv6_pktinfo",
    "has_recv_hoplimit",
    "has_msg_mcast",
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
  // layout (ipi_ifindex / ipi_spec_dst / ipi_addr) that `parse_pktinfo_v4`
  // decodes. The BSDs are excluded: FreeBSD/OpenBSD/DragonFly have no IP_PKTINFO
  // at all, and NetBSD's in_pktinfo is a DIFFERENT 8-byte layout (ipi_addr /
  // ipi_ifindex) the shared parser would misread as too-short. All of
  // them degrade to an unspecified local address + interface index 0, exactly
  // as the IPv4 path already does elsewhere.
  //
  // That degradation is this crate's, not the platforms'. `libc` binds
  // IP_RECVDSTADDR, IP_RECVIF and IP_RECVTTL for freebsdlike
  // (src/unix/bsd/freebsdlike/mod.rs:921-926) and IP_PKTINFO/IP_RECVPKTINFO for
  // NetBSD (src/unix/bsd/netbsdlike/netbsd/mod.rs:957-958); the receive paths
  // for them are simply unimplemented here. Until they exist, an IPv4 datagram
  // on these targets has no recovered destination, `RecvMeta::destination`
  // returns `None`, and RFC 6762 §11's group arm has to be selected by the
  // coarser `has_msg_mcast` flag below.
  if linux_like || apple {
    println!("cargo::rustc-cfg=has_ip_pktinfo");
  }
  // IPv6 PKTINFO: every supported Unix defines both IPV6_PKTINFO and
  // IPV6_RECVPKTINFO.
  if linux_like || apple || freebsdlike || netbsdlike {
    println!("cargo::rustc-cfg=has_ipv6_pktinfo");
  }
  // RFC 6762 §11 TTL/Hop-Limit receive cmsg. Off on netbsdlike because `libc`
  // BINDS none of IP_RECVTTL/IPV6_HOPLIMIT/IPV6_RECVHOPLIMIT for OpenBSD or
  // NetBSD — a binding gap, NOT a platform incapability. Both are KAME-derived
  // stacks that report the hop limit exactly as RFC 3542 specifies, so a
  // receiver there is degraded by what this crate can reach through `libc`, not
  // by what the kernel knows. Stated precisely because the §11 fail-open rule
  // ("no hop limit ⇒ we can prove neither on-link nor off-link") is a real
  // exemption on Windows, where the sockopt genuinely does not exist, and only
  // an accident of bindings here.
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

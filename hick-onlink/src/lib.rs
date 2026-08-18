#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::panic,
  clippy::panic_in_result_fn,
  clippy::indexing_slicing,
  clippy::arithmetic_side_effects,
  clippy::unreachable,
  clippy::todo,
  clippy::unimplemented
)]
//!
//! # The rule, in full
//!
//! [`admits_ingress`] is a pure function of what the receive path WITNESSED —
//! peer address, IP header destination, link-layer delivery class, receive
//! interface — plus the configuration the caller holds, which arrives as a
//! [`BoundLink`]. Nothing here reads a socket, a clock or a driver's state, and
//! nothing here is tunable: §11 is a fixed standard, so a driver supplies the
//! CONFIGURATION and this crate owns the RULE.
//!
//! COLLECTING that configuration is deliberately somebody else's job: it needs
//! an interface enumerator and a monotonic clock, and neither exists on every
//! target this rule runs on. `hick-udp` does it for the hosted drivers —
//! `collect_local_subnets`, `is_loopback_interface`, `refresh_subnets_if_stale`
//! and the one `SUBNET_REFRESH_INTERVAL` all three share — while a bare-metal
//! caller hands over what its own stack already holds. Where the prose below
//! names one of those, it names `hick-udp`'s.
//!
//! # The inputs are WITNESSES, and absence has three different meanings
//!
//! [`admits_ingress`] used to take an `Option<IpAddr>` destination and a
//! `(pkt_iface: u32, iface_reported: bool)` pair. Both spelled ABSENCE as the
//! quiet value — `None`, `0` — and absence selected the widest arm. That is the
//! wrong shape for a trust boundary, because a missing fact is three distinct
//! facts and only one of them is a statement about the platform:
//!
//! * **[`DestinationWitness::Witnessed`] / [`IfaceWitness::Witnessed`]** — the path
//!   recovered it for this datagram. `Witnessed(0)` is unrepresentable for an
//!   interface index ([`NonZeroU32`]), so no driver can pass "I do not know"
//!   positionally into the permissive arm;
//! * **`Lost`** — the path witnesses this fact, and OUR OWN control buffer was
//!   too small (`MSG_CTRUNC`). A bug on this side of the boundary, and the one
//!   absence that REFUSES;
//! * **`Declined`** — the path witnesses this fact, the kernel emitted nothing
//!   and flagged no truncation. Not our bug and not the sender's: every BSD
//!   allocates its ancillary mbufs with `M_NOWAIT` and silently skips the cmsg
//!   when the allocation fails, still delivering the datagram. Refusing here
//!   would make the responder go deaf under exactly the mbuf exhaustion a flood
//!   causes, so this DEGRADES to the source-prefix arm and is counted;
//! * **`Blind`** — this path cannot witness the fact by construction. Declared
//!   ONCE per receive path, never inferred per datagram.
//!
//! [`DestinationWitness::Lost`] and [`DestinationWitness::Declined`] are the same missing cmsg read
//! two ways, and the flag that tells them apart is `MSG_CTRUNC` — see
//! `hick-udp`'s `recv_with_meta`, which is the only thing in that crate that may
//! mint either.
//!
//! # Capability is the RECEIVE PATH's, not the platform's
//!
//! [`DestinationWitness::Blind`] and [`IfaceWitness::Blind`] are the receive path's own
//! declaration, never a constant read inside the rule. Whether a destination or
//! a receive interface comes back is a property of **the path a driver actually
//! runs**, not of the operating system: a driver calling `recvfrom` recovers no
//! provenance on a platform whose `recvmsg` would have supplied it, and a rule
//! that assumed otherwise would fail every datagram closed and leave that driver
//! silently deaf. `hick-udp`'s `reports_rx_interface` answers the capability
//! question for that crate's own `recv_with_meta`; a driver with its own receive
//! path must answer it for that path, and mint its own witnesses from the
//! answer.
//!
//! # One capability table, and it is the only one in this module
//!
//! Which witnesses a square can mint at all. Everything else this module says
//! about platforms is a consequence of this table and must not restate it:
//!
//! | receive path | family | targets | destination | interface | `MSG_MCAST`/`MSG_BCAST` |
//! |---|---|---|---|---|---|
//! | `hick-udp` `recv_with_meta` | IPv6 | all supported unix | witnessed | witnessed | OpenBSD/NetBSD only |
//! | `hick-udp` `recv_with_meta` | IPv4 | Linux/Android, Apple | witnessed | witnessed | no |
//! | `hick-udp` `recv_with_meta` | IPv4 | FreeBSD, DragonFly | witnessed | witnessed | no |
//! | `hick-udp` `recv_with_meta` | IPv4 | OpenBSD, NetBSD | witnessed | witnessed | **yes** |
//! | `hick-udp` `recv_with_meta` | both | Windows | witnessed | witnessed | no |
//! | `hick-compio` unix decoder | IPv6 | all supported unix | witnessed | witnessed | OpenBSD/NetBSD only |
//! | `hick-compio` unix decoder | IPv4 | Linux/Android, Apple | witnessed | witnessed | no |
//! | `hick-compio` unix decoder | IPv4 | the four BSDs | witnessed | witnessed | OpenBSD/NetBSD only |
//! | `hick-compio` Windows (`recv_from`) | both | Windows | **blind** | **blind** | **no** |
//!
//! An IPv6 peer's **scope id** is a second interface witness and it is carried on
//! `src` rather than in this table: every supported platform — Windows included —
//! fills `sin6_scope_id` from the receiving interface for a link-local source, so
//! a link-local IPv6 peer is witnessed even where the row above says blind. A
//! scopeless IPv6 peer and every IPv4 peer are not.
//!
//! `hick-compio` decodes its own ancillary data (`hick-compio/src/socket/unix.rs`,
//! gated by `hick-compio/build.rs`) rather than calling `recv_with_meta`, so it
//! is a SECOND decoder and never a share of `hick-udp`'s — its
//! `socket::rx_interface_reported` answers from its own cfgs for exactly that
//! reason, and a flip in one crate moves no row of the other.
//!
//! The BSD IPv4 rows are witnessed on BOTH paths now, and each got there by its
//! own work. `hick-udp`'s `try_bind_v4` enables `IP_RECVDSTADDR` + `IP_RECVIF`
//! and `multicast::parse_dstaddr_recvif_v4` reads the pair, behind the
//! `has_ip_dstaddr_recvif` capability whose four evidence items are written at
//! its emit site in `hick-udp/build.rs` — which covers `hick-mio` and
//! `hick-reactor`. `hick-compio` then enables the same pair in its own
//! `socket::unix::enable_recv_cmsgs` and calls that same parser from
//! `decode_unix_cmsgs`, behind ITS OWN `has_ip_dstaddr_recvif` with its own four
//! evidence items in `hick-compio/build.rs`. **Not `has_ip_pktinfo`**, which an
//! earlier draft of this list predicted: no BSD defines a usable one — NetBSD's
//! `in_pktinfo` is a different 8-byte layout — so the pair is the only spelling
//! available there.
//!
//! One piece of work remains, and it moves the last blind row:
//!
//! * a `WSARecvMsg` receive path for `hick-compio` on Windows. `hick-udp`'s
//!   `platform::windows` already has the `WSAIoctl`/`WSAID_WSARECVMSG` dance;
//!   `hick-compio` simply does not call it, and reads with `recv_from` instead.
//!
//! # What a blind square costs, stated once
//!
//! On a row whose destination is blind, none of the destination partition's
//! guarantees hold — it needs a destination to be positive about. What is left is
//! the kernel's coarse [`LinkDelivery`], and the residual is exactly:
//!
//! * where `MSG_BCAST` is bound (OpenBSD/NetBSD), an IPv4 broadcast is REFUSED;
//! * where `MSG_MCAST` is bound, **any** foreign multicast group is admitted from
//!   **any** source, because the flag names no group;
//! * where neither is bound — `hick-compio` on **Windows**, now the only
//!   structurally blind row in the table, plus any FreeBSD/DragonFly datagram
//!   that reaches this residual through `Declined` — an IPv4 broadcast is
//!   indistinguishable from a unicast and is admitted for an in-prefix source.
//!
//! A datagram whose witness was `Declined` lands in that same residual for one
//! datagram, and [`Admit::BlindSourceOnLink`] is what makes it countable. That is
//! now the ONLY way a `recv_with_meta` square reaches the residual: no row of
//! this crate's own receive path is structurally blind any more, so what used to
//! be four permanent squares is a per-datagram degradation the kernel has to
//! cause.
//!
//! # Where `Declined` can actually occur, read out of each kernel
//!
//! `Declined` DEGRADES where the old rule refused, so which squares can reach it
//! is a security question and not a curiosity. The mbuf argument that justifies
//! the arm is a BSD argument and it does not transfer, so each square is
//! answered from its own source — and the two ways to reach it are kept apart,
//! because only one of them is "the cmsg went missing":
//!
//! | square | cmsg ABSENT, `MSG_CTRUNC` clear | cmsg PRESENT, index `0` |
//! |---|---|---|
//! | Linux/Android IPv4 | **unreachable** | **reachable** |
//! | Linux/Android IPv6 | guard exists, trigger unproven | not via that guard |
//! | Apple IPv4 | **unreachable** — datagram dropped instead | not applicable |
//! | Apple IPv6 | **unreachable** — datagram dropped instead | **reachable** |
//! | FreeBSD/DragonFly/OpenBSD/NetBSD IPv6 | **reachable, and wired today** | reachable |
//! | FreeBSD/DragonFly/OpenBSD/NetBSD IPv4 | **reachable, and wired today** | **reachable** |
//! | Windows (`WSARecvMsg`) | no documented case | undocumented |
//!
//! **The BSD IPv4 row can decline each witness SEPARATELY**, and no other row
//! can. `IP_RECVDSTADDR` and `IP_RECVIF` are two cmsgs built by two
//! `sbcreatecontrol` calls, not two fields of one struct, so an mbuf shortage
//! can take either without the other; NetBSD adds a deterministic form of the
//! same split, emitting `IP_RECVDSTADDR` before its
//! `m_get_rcvif_psref() == NULL` early return and `IP_RECVIF` after it. The
//! reachable state is therefore `Witnessed` destination with `Declined`
//! interface: the destination partition still decides in full and only the link
//! scoping is lost, which is the same narrow widening Linux IPv4 has. The
//! reverse — interface without destination — is possible too and costs only the
//! partition, landing in the residual for that one datagram. Both are why
//! `parse_dstaddr_recvif_v4` returns what it recovered instead of insisting on
//! the pair.
//!
//! **Linux cannot lose a cmsg silently.** `put_cmsg` (`net/core/scm.c`) writes
//! straight into the CALLER's control buffer — there is no allocation to fail —
//! and every path that cannot fit the message sets `MSG_CTRUNC` and returns.
//! `ip_cmsg_recv_offset` (`net/ipv4/ip_sockglue.c`) calls
//! `ip_cmsg_recv_pktinfo` unconditionally once `IP_CMSG_PKTINFO` is set, so an
//! enabled sockopt always emits. An absent IPv4 PKTINFO with the flag clear is
//! not a state Linux produces.
//!
//! **Linux CAN emit the cmsg and decline to name an interface.**
//! `ipv4_pktinfo_prepare` sets `pktinfo->ipi_ifindex = 0` and
//! `ipi_spec_dst = 0` in its `else` branch — taken when `skb_rtable(skb)` is
//! `NULL` — while `ip_cmsg_recv_pktinfo` overwrites `info.ipi_addr` from
//! `ip_hdr(skb)->daddr` regardless. The datagram therefore arrives with its
//! DESTINATION witnessed and its INTERFACE zero, which is
//! [`IfaceWitness::Declined`]: the kernel answered, and its answer was "I do not
//! know which". **That is the reachable widening on Linux**, and it is far
//! narrower than a blind square — the whole destination partition still runs, so
//! a foreign group and a destination this endpoint does not hold are both still
//! refused, and only the link SCOPING is lost.
//!
//! **Apple drops rather than under-reports.** `ip_savecontrol`
//! (`bsd/netinet/ip_input.c`) and `ip6_savecontrol_v4`
//! (`bsd/netinet6/ip6_input.c`) check every `sbcreatecontrol` result for `NULL`
//! and, on failure, `goto no_mbufs` / return `ENOBUFS` after bumping
//! `ipstat.ips_pktdropcntrl` / `ip6stat.ip6s_pktdropcntrl`. The datagram is
//! discarded, so a caller never sees one with the cmsg missing. Apple's IPv6
//! path does have the zero-index form —
//! `pi6.ipi6_ifindex = (m && m->m_pkthdr.rcvif) ? m->m_pkthdr.rcvif->if_index : 0`
//! — so it reaches `Declined` the same way Linux IPv4 does.
//!
//! **The BSDs are the case the arm exists for, and it is LIVE TODAY.**
//! `ip6_savecontrol` (`sys/netinet6/ip6_input.c`) calls
//! `sbcreatecontrol(&pi6, sizeof(struct in6_pktinfo), …, M_NOWAIT)` and guards
//! the result with a bare `if (*mp) mp = &(*mp)->m_next;` — no `else`, no error,
//! no counter — while `sbcreatecontrol` (`sys/kern/uipc_sockbuf.c`) returns
//! `NULL` whenever `m_get`/`m_getcl` fails. The datagram is still delivered.
//! IPv6 PKTINFO is enabled on every supported unix and `try_bind_v6` fails the
//! bind rather than continuing without it, so this is a WIRED square: under the
//! mbuf exhaustion a flood causes, a BSD host silently loses BOTH witnesses on
//! arbitrary datagrams. Refusing there is deafness on demand, which is the whole
//! reason `Declined` is not `Lost`.
//!
//! **Linux IPv6 has a suppression guard whose trigger this module has not
//! proven.** `ip6_datagram_recv_common_ctl` (`net/ipv6/datagram.c`) wraps its
//! `put_cmsg` in `if (src_info.ipi6_ifindex >= 0)`, so a negative index would
//! omit the whole cmsg with no `MSG_CTRUNC`. Reading the source did not
//! establish a reachable negative value on an `IPV6_V6ONLY` socket, so it is
//! recorded as possible-but-unproven rather than claimed either way. A negative
//! that reached a decoder ANYWAY — past that guard, or from a kernel that has
//! no such guard — is an absence and not an interface, which is
//! [`IfaceWitness::from_reporting_path_signed`]'s whole subject.
//!
//! **Windows documents truncation and nothing else.** `WSARecvMsg` defines
//! `MSG_CTRUNC` as *"the control (ancillary) data was truncated"*, and states
//! that with `IP_PKTINFO`/`IPV6_PKTINFO` enabled a control object *will* carry
//! the `in_pktinfo`/`in6_pktinfo`. Its one documented omission — a DUAL-STACK
//! socket with only `IPV6_PKTINFO` set, where IPv4 arrivals "may not" get one —
//! cannot arise here: `IPV6_V6ONLY` is set at bind and the IPv4 socket enables
//! `IP_PKTINFO` itself.
//!
//! **So the arm is not dead where it cannot fire.** On the squares where an
//! ABSENT cmsg is unreachable, `recv_with_meta` still constructs `Declined` for
//! a parse that recovered nothing — a malformed or short cmsg is not something a
//! trust boundary may assume away, and the same code serves the BSD square where
//! it IS live. What those squares must not do is REFUSE on it: the only way to
//! reach it there is a kernel or a decoder behaving unexpectedly, and that is
//! not evidence about the sender. The zero-index form, meanwhile, is reachable
//! on the primary platforms and is where their widening actually lands.
//!
//! # The residual: an mDNS group refused for want of link scoping
//!
//! §11 arm one's *"regardless of source IP address"* exemption is granted only
//! to a datagram something SCOPED to the bound link — see [`admits_ingress`] for
//! why the exemption in particular needs it. Where nothing scoped it, the
//! datagram takes the arm it would have taken with no destination witness at
//! all, and on a target that binds no `MSG_MCAST` that is §11's source arm. An
//! OFF-PREFIX sender is then refused: [`Refuse::UnscopedGroupSourceOffLink`],
//! which is exactly the overlaid-subnet peer the RFC calls the exemption
//! essential for. **This is a known conformance cost, and it is the deliberate
//! side of a trade.**
//!
//! | row | reaches the unscoped square | residual |
//! |---|---|---|
//! | FreeBSD/DragonFly IPv4 + IPv6 | **yes — flood-inducible** | **off-prefix group senders REFUSED** |
//! | OpenBSD/NetBSD IPv4 + IPv6 | **yes — flood-inducible** | none: `MSG_MCAST` admits, see below |
//! | Linux/Android IPv4 | rare, NOT unreachable — `ipv4_pktinfo_prepare`'s `else` branch zeroes `ipi_ifindex` when `skb_rtable(skb)` is `NULL` | off-prefix group senders REFUSED |
//! | Apple IPv6 | index `0`, same shape | off-prefix group senders REFUSED |
//! | Apple IPv4, Linux/Android IPv6, Windows | not established | none known |
//!
//! **OpenBSD and NetBSD carry no residual, and the reason is monotonicity rather
//! than luck.** An unscoped group destination takes the same coarse
//! [`LinkDelivery`] arm the blind square takes, so where `MSG_MCAST` is bound it
//! is ADMITTED — as [`Admit::UnscopedMdnsGroup`], never as arm one. Routing it
//! straight to the source arm instead made this square REFUSE what the strictly
//! less-informed square beside it ADMITTED, which is incoherent: an attacker who
//! can make one cmsg go missing can make both go missing and be admitted anyway,
//! so the refusal stopped nobody and taxed legitimate peers in full. **FreeBSD
//! and DragonFly bind no `MSG_MCAST` and so keep the residual.**
//!
//! **The destination partition is untouched by any of this.** Only a destination
//! that IS an mDNS group takes the unscoped arm. A foreign group, an IPv4
//! broadcast, a martian and a neighbour's address are matched by the arms below
//! it and refused BY NAME, with the coarse flag never consulted — the flag
//! admits "any group" only where no group was witnessed.
//!
//! **Why this way round.** The alternative is what this crate did before: grant
//! the exemption whenever the link witness is absent. That admits a
//! wildcard-bound socket's copy of ANOTHER NIC's group traffic, from any source,
//! into the cache and §9 conflict handling — a durable write from a link the
//! sender has no business reaching, silent, and persisting after the flood that
//! produced it stops. The refusal costs an off-prefix peer a datagram while the
//! shortage lasts, and an mbuf shortage means the host is already dropping
//! datagrams wholesale, so it is an increment on an outage already in progress.
//! **Neither state is §11-clean**: granting the exemption unscoped satisfies the
//! RFC's letter by handing it to datagrams §11 never meant it for, because §11
//! assumes one link and these sockets are wildcard-bound across many. One of the
//! two also hands out write access.
//!
//! **It is counted, not merely argued.** [`Verdict::is_unscoped_group_refusal`]
//! is the availability cost and [`Verdict::is_unscoped_group_admit`] is the
//! residual exposure; the hosted drivers feed them to
//! `mdns_ingress_unscoped_group_refusals` and
//! `mdns_ingress_unscoped_group_admits`. Sustained movement in the first on a
//! BSD row is this attack in progress.
//!
//! **This residual is about ADMISSION, not about trust downstream.** Everything
//! above concerns whether a datagram crosses the boundary. What an admitted
//! datagram may then DO is not graded here and is not graded anywhere: every
//! hosted driver reduces the verdict to [`Verdict::is_admit`] and hands the
//! datagram to the same `mdns-proto` `Endpoint::handle` path, so
//! [`Admit::UnscopedMdnsGroup`] reaches cache, §9 conflict and known-answer
//! processing with exactly the trust [`Admit::MdnsGroup`] does. The names and
//! counters here are an observation, not a capability boundary.
//!
//! The mechanism, so the next reader does not go looking for a lever that is not
//! there: `Endpoint::handle` has ONE trust input, a boolean latch shared with
//! self-loopback and untrusted-response suppression, and it DROPS a datagram
//! wholesale rather than restricting what it may touch. A tier therefore has to
//! be introduced rather than threaded, must cover [`Admit::BlindMulticastDelivery`]
//! in the same change — restricting one and not the other would break the
//! monotonicity above — and is tracked as its own work. Note also that the cheap
//! driver-side substitute is wrong: dropping RESPONSES on an unscoped admission
//! needs no protocol change, but a response is exactly what §11 arm one exists
//! to admit, so it reinstates the availability cost on the square the
//! coarse-delivery arm resolved while leaving conflict handling reachable from a
//! query's authority section.
//!
//! **What would close it.** Not granting the exemption unscoped — that is the
//! failure above. Link provenance the datagram cannot lose: a receive socket
//! genuinely restricted to one interface, so that every datagram on it is on
//! that link by construction and no cmsg is needed to prove it. `libc` binds
//! `SO_BINDTODEVICE` for Linux/Android (requiring `CAP_NET_RAW`) and
//! `IP_BOUND_IF`/`IPV6_BOUND_IF` for Apple, so those rows are closable. It binds
//! **no such option for FreeBSD, DragonFly, OpenBSD or NetBSD at any privilege
//! level**, and Windows' `IP_UNICAST_IF` selects the egress interface only. The
//! four kernels that silently omit cmsgs are exactly the four with no
//! socket-level substitute, so the residual's home is also the one place this
//! layer cannot reach; closing it there is a deployment-level answer (jail/VNET,
//! rdomain) or a different socket API.
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
//!   it can forbid nothing — pass. It also PROVES nothing, which is a separate
//!   fact and is why stage 1 answers with three states rather than two: §11 arm
//!   one is granted there, and stage 3's `fe80::/64` seed is not fed by it;
//! * otherwise every NONZERO witness must equal the bound interface. One
//!   disagreement refuses outright ([`Refuse::ForeignLink`]), and no later stage
//!   overturns it;
//! * if at least one witness was present and agreed — pass;
//! * with NO witness at all, the [`IfaceWitness`] itself decides, and this is
//!   where "absent provenance" stops being one condition:
//!   * a loopback-BOUND endpoint with a loopback source — pass;
//!   * [`IfaceWitness::Lost`] — REFUSE ([`Refuse::LinkWitnessLost`]). Our control
//!     buffer was too small, which is this side's bug, not the sender's;
//!   * [`IfaceWitness::Declined`] — pass. The kernel skipped the cmsg on this
//!     datagram, and refusing an mbuf shortage is how a responder goes deaf under
//!     a flood;
//!   * [`IfaceWitness::Blind`] — pass. The path never had one to give.
//!
//! **2. The destination partition — TWO REGIMES, and everything below is about
//! the first.** §11 picks its arm by the IP header destination, so a
//! [`DestinationWitness::Witnessed`] datagram and one that is `Blind`, `Declined` or
//! `Lost` are governed by different rules. Which square a driver is on decides
//! which — see the one capability table above.
//!
//! **With a destination witnessed**, §11 names exactly two kinds and a witnessed
//! one is sorted by what it **is**, never by what it is not:
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
//! [`Refuse`] then NAMES which class it was, so a refusal is countable rather
//! than merely negative. Naming happens strictly after the verdict and cannot
//! change it: `classify_unheld` is reached only on the arm that had already
//! refused. [`Refuse::DestinationNotHeld`] is what is left once every named
//! class is taken, and its count is the size of the conformance gap this
//! partition still carries.
//!
//! [`BoundLink::local_addrs`] is what answers the question, and it already carries
//! the answer: `hick-udp`'s `collect_local_subnets` stores each interface address `getifs`
//! reports, paired with its prefix length — the ASSIGNED address, not a masked
//! network — so "is this destination one of ours" is a lookup rather than a
//! computation. An **empty** snapshot is the one exception and it is documented
//! at the decision site in [`admits_ingress`].
//!
//! **With no destination witnessed** none of that runs, and saying otherwise is
//! how a review round found this module claiming more than it delivers.
//! [`DestinationWitness::Lost`] refuses outright — see below. `Blind` and `Declined` take
//! the same arm, and what is left there is the kernel's own delivery class
//! ([`LinkDelivery`]), which OpenBSD and NetBSD alone report:
//!
//! * [`LinkDelivery::Broadcast`] is REFUSED. It is exact negative evidence —
//!   §11 gives a broadcast no arm — so those two targets lose the IPv4
//!   broadcast class here as well as in the first regime;
//! * [`LinkDelivery::Multicast`] admits, and it names no group, so **any**
//!   foreign group is admitted there from any source, and no flag can close it;
//! * everything else takes the source arm, so on every square with no delivery
//!   class either — `hick-compio` on **Windows** — an IPv4 **broadcast** is still
//!   admitted for an in-prefix source. BOTH FreeBSD/DragonFly IPv4 rows left this
//!   list when they started witnessing the destination, `hick-udp`'s through
//!   `recv_with_meta` and `hick-compio`'s through its own decoder: each now
//!   refuses a broadcast in the first regime, by address, and reaches this one
//!   only for a datagram whose cmsg the kernel declined.
//!
//! **[`DestinationWitness::Lost`] is the one absence that refuses**, and it is deliberately
//! not the one an attacker can provoke. `MSG_CTRUNC` says the kernel had the fact
//! and OUR buffer could not hold it; `recv_with_meta` sizes that buffer at 512
//! bytes against a worst case of about 152, so the flag is a defect report rather
//! than a live class. The absence a flood DOES provoke is `Declined` — every BSD
//! builds its ancillary mbufs with `M_NOWAIT` and skips the cmsg without an
//! error, a counter, or a truncation flag, when the allocation fails
//! (FreeBSD `kern/uipc_sockbuf.c`'s `sbcreatecontrol` returns `NULL`; NetBSD's
//! `kern/uipc_socket2.c` likewise; XNU is the counter-example and returns
//! `ENOBUFS`). Refusing THAT would take the responder off the air precisely
//! during the traffic that caused it, so it degrades and is counted instead.
//!
//! **3. §11's source arm, for a destination this interface HOLDS.** A loopback
//! source is on-link only for a loopback-bound endpoint. EVERY other source —
//! routable or link-local, witnessed or not — is matched against the addresses
//! and masks configured on the bound interface, and its on-link IPv6 prefixes.
//! There is no third arm: a witness settles which link a datagram arrived on,
//! never whether its source belongs to a prefix this interface carries.
//!
//! `fe80::/64` is one of those on-link prefixes on every interface, whether or
//! not this host holds an address in it (RFC 5942 §3, RFC 4861's Prefix List) —
//! and because it is on EVERY interface, matching it says the sender is on some
//! link and nothing about whether it is ours. So it is the one prefix that
//! requires stage 1 to have ESTABLISHED the link (`LinkProvenance`) before it
//! may decide, and where the link is unproven the source falls through to the
//! collected prefixes and decides exactly as it did before that prefix existed.
//! See `src_on_local_link`.
//!
//! Stages 2 and 3 read the SAME snapshot, which is what makes the pair coherent:
//! the destination against its addresses, the source against its addresses and
//! masks. An endpoint that cannot say which addresses it holds therefore fails
//! both, and that is the empty-snapshot case above.
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
//! **`fe80::/64` is the sharpest instance of that residual and it is not the
//! seed's.** Every NIC carries a link-local address, so on a host that
//! enumerates one the COLLECTED list already contains `fe80::<iid>/64` and an
//! unprovenanced link-local peer from a second NIC matches it — which is the
//! same-prefix residual above, exactly as it stood before the seed existed. The
//! seed does not widen it: it is gated on `LinkProvenance::Established`, so on
//! the unprovenanced square this rule decides byte for byte as it did without
//! it. Closing THAT needs the collected list to stop reporting a prefix as
//! interface-specific when it is not, which is the deferred Prefix List work
//! named above and not something this arm can do.
//!
//! One further gap is known and not yet closed: §11's IPv6 arm is defined over
//! the on-link prefixes of the receiving interface, *"learned via IPv6 router
//! advertisements or otherwise configured on the host"*.
//! `hick-udp`'s `collect_local_subnets` enumerates only prefixes this host holds an address
//! in, so an on-link prefix learned from a router advertisement that this host
//! took no address from is not consulted, and a peer inside it is refused by the
//! source arm. The group arm carries the ordinary multicast case regardless.
//!
//! **That gap is the RA/route half of RFC 5942 and it is still open. Only the
//! link-local half is closed, and only where stage 1 established the link.**
//! `fe80::/64` is seeded by `src_on_local_link` as
//! a constant, so it no longer depends on `getifs` reporting an assigned
//! link-local address at a `/64` — which is what it depended on, and which a
//! `/128` report or an interface without one silently broke. Everything else in
//! the Prefix List still arrives as an assigned address or not at all, so RFC
//! 5942 §4 rule 1's *"MUST NOT implicitly cause a prefix derived from that
//! address to be treated as on-link"* is still violated for every OTHER prefix,
//! in both directions: an assigned GUA `/64` is still read as on-link evidence,
//! and an `L=1, A=0` prefix this host holds no address in is still invisible.
//! Closing that needs a real Prefix List — netlink on Linux, and a different
//! per-platform mechanism on Apple and on each BSD, with no shared abstraction
//! — and is deliberately deferred rather than half-done here.
//!
//! The destination partition has residuals of its own. They are the mirror of
//! the old ones: it admits only what the snapshot names, so what it gets wrong
//! it gets wrong by refusing rather than by admitting.
//!
//! * a **stale** snapshot — non-empty, but taken before an address was added —
//!   refuses unicast to that new address until the next refresh, so the window
//!   is bounded by `hick-udp`'s `SUBNET_REFRESH_INTERVAL` and closes itself. The same
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
//! The blind squares' residual is stated once, under the capability table at the
//! top of this module, and is not restated here — that duplication is how two
//! copies of it came to disagree inside one file.

use core::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
  num::NonZeroU32,
};

/// The IPv4 mDNS link-local multicast group, `224.0.0.251` (RFC 6762 §3).
///
/// One of the exactly two addresses §11 deems on-link by destination alone. It
/// is defined here, in the crate that decides on it, so the rule and every
/// driver that re-exports it cannot come to hold different literals.
pub const MDNS_IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The IPv6 mDNS link-local multicast group, `ff02::fb` (RFC 6762 §3). The IPv6
/// half of [`MDNS_IPV4_GROUP`]'s pair.
pub const MDNS_IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// The base of the IPv6 link-local prefix, which every interface treats as
/// on-link whether or not a router said so and whether or not this host holds an
/// address in it. Paired with [`LINK_LOCAL_V6_PREFIX_LEN`] and read by
/// `src_on_local_link`, which explains why it is a constant here rather than an
/// entry a caller supplies.
const LINK_LOCAL_V6_NET: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);

/// **64, and deliberately not 10.** RFC 4291 §2.4's assignment table names the
/// link-local unicast TYPE as `FE80::/10`, but §2.5.6 gives the address itself a
/// format, and that format fixes the next 54 bits:
///
/// ```text
/// |   10     |
/// |  bits    |         54 bits         |          64 bits           |
/// +----------+-------------------------+----------------------------+
/// |1111111010|           0             |       interface ID         |
/// +----------+-------------------------+----------------------------+
/// ```
///
/// Ten prefix bits plus 54 zero bits is one fixed 64-bit value, so the set of
/// well-formed link-local addresses is exactly `fe80::/64`. RFC 4862 §5.3 builds
/// them the same way — the address is *"formed by combining the well-known
/// link-local prefix FE80::0 \[RFC4291\] (of appropriate length) with an
/// interface identifier"*, where *"the bits in the address to the right of the
/// link-local prefix are set to all zeroes"* before the interface identifier
/// replaces the rightmost N.
///
/// Seeding `/10` would therefore hand this rule's ON-LINK answer to
/// `fe80:1234::…`, an address no conforming stack can autoconfigure or assign,
/// on 54 bits of evidence nothing in the subnet model provides. It is a strictly
/// wider claim than the model makes and this is a trust boundary, so the seed is
/// the narrow one the format defines.
const LINK_LOCAL_V6_PREFIX_LEN: u8 = 64;

/// How the link layer delivered a datagram, where the receive path can tell.
///
/// This is the coarse stand-in for an IP header destination on the receive
/// squares that witness none — see [`DestinationWitness`]. It names the
/// DELIVERY, never the address: [`Self::Multicast`] does not say which group,
/// which is why RFC 6762 §11's group arm can be over-approximated by it and its
/// unicast arm cannot be replaced by it.
///
/// Not `#[non_exhaustive]` on purpose. Every value is a decision in a trust
/// boundary, so a fourth class must break every `match` that admits or refuses
/// on this type rather than fall into a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkDelivery {
  /// Addressed to this host rather than to a group or a broadcast address.
  ///
  /// It does NOT say to which of this host's addresses; where the IP header
  /// destination itself was witnessed, use that instead.
  Unicast,
  /// Delivered to a multicast group — but not to WHICH group. A datagram
  /// addressed to `224.0.0.251` and one addressed to LLMNR's `224.0.0.252` are
  /// the same value here.
  Multicast,
  /// Delivered as a link-layer broadcast: `255.255.255.255`, a subnet-directed
  /// broadcast, or whatever address the interface was configured to answer
  /// broadcasts on.
  ///
  /// Definitive NEGATIVE evidence, which is what makes it worth carrying: the
  /// delivery was neither unicast to an address this host holds nor multicast to
  /// an mDNS group, so RFC 6762 §11 offers it no arm at all — without ever
  /// naming the address.
  Broadcast,
}

/// What the receive path witnessed about the IP-header DESTINATION of one
/// datagram.
///
/// RFC 6762 §11 selects its local-link test by the destination, so this is the
/// fact the whole partition turns on. It replaces an `Option<IpAddr>`, where
/// `None` had to stand for three unrelated things at once — and did, silently,
/// selecting the widest arm for all three.
///
/// **A driver does not compute this.** It is minted by a receive path, which is
/// the only place that knows both what the platform can report and what the
/// kernel actually reported for this datagram. See [`Self::from_reporting_path`]
/// and [`Self::blind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestinationWitness {
  /// The path recovered the IP header destination for this datagram.
  ///
  /// This is the ONLY value the destination partition can be positive about, and
  /// everything [`admits_ingress`] guarantees about refusing a destination this
  /// endpoint does not hold is a guarantee about this variant.
  Witnessed(IpAddr),
  /// This path witnesses destinations, and OUR OWN control buffer was too small
  /// to hold the ancillary data (`MSG_CTRUNC`).
  ///
  /// A failed proof, not a capability statement — and the failure is on this
  /// side of the boundary. It REFUSES ([`Refuse::DestinationWitnessLost`]),
  /// which is safe precisely because it is not attacker-reachable: the flag
  /// means the kernel HAD the fact and our buffer could not take it, and
  /// `recv_with_meta` sizes that buffer at 512 bytes against a worst case of
  /// about 152. Reaching this variant in production is a bug report.
  Lost,
  /// This path witnesses destinations, the kernel emitted none for this
  /// datagram, and it flagged no truncation.
  ///
  /// The kernel DECLINED. Every BSD builds its ancillary mbufs with `M_NOWAIT`
  /// and, when the allocation fails, skips the cmsg with no error, no counter
  /// and no `MSG_CTRUNC` — the datagram is still delivered. Mbuf exhaustion is
  /// usually caused by a flood, so refusing here would make a responder go
  /// silently deaf exactly while it is under attack. This DEGRADES to the same
  /// source-prefix arm [`Self::Blind`] takes, and [`Admit::BlindSourceOnLink`]
  /// plus [`Self::is_declined`] are what make that countable.
  Declined,
  /// This path cannot witness destinations by construction.
  ///
  /// Declared ONCE per receive path from a compile-time capability, never
  /// inferred per datagram — that inference is what made every truncated cmsg
  /// look like a platform that never reports one. See the capability table at
  /// the top of this module for which squares declare it.
  Blind,
}

impl DestinationWitness {
  /// The witness a path that DOES recover destinations mints for ONE datagram:
  /// what it parsed, and whether the kernel set `MSG_CTRUNC`.
  ///
  /// A recovered destination is a recovered destination whatever the flag says —
  /// truncation only matters when it cost us the fact. With nothing recovered the
  /// flag is the whole difference between our bug ([`Self::Lost`]) and the
  /// kernel's shortage ([`Self::Declined`]), and the two lead to opposite
  /// verdicts, so the rule is written here once rather than at each receive path.
  #[inline]
  #[must_use]
  pub const fn from_reporting_path(destination: Option<IpAddr>, control_truncated: bool) -> Self {
    match destination {
      Some(dst) => Self::Witnessed(dst),
      None if control_truncated => Self::Lost,
      None => Self::Declined,
    }
  }

  /// The declaration a path that recovers NO destination makes — once, from its
  /// own compile-time capability, for every datagram it will ever produce.
  ///
  /// Spelled as a constructor rather than as a bare variant so the one-per-path
  /// contract has a name a review can grep for.
  #[inline]
  #[must_use]
  pub const fn blind() -> Self {
    Self::Blind
  }

  /// Whether this is [`DestinationWitness::Witnessed`].
  #[inline]
  #[must_use]
  pub const fn is_witnessed(&self) -> bool {
    matches!(self, Self::Witnessed(..))
  }
  /// Whether this is [`DestinationWitness::Lost`].
  #[inline]
  #[must_use]
  pub const fn is_lost(&self) -> bool {
    matches!(self, Self::Lost)
  }
  /// Whether this is [`DestinationWitness::Declined`].
  #[inline]
  #[must_use]
  pub const fn is_declined(&self) -> bool {
    matches!(self, Self::Declined)
  }
  /// Whether this is [`DestinationWitness::Blind`].
  #[inline]
  #[must_use]
  pub const fn is_blind(&self) -> bool {
    matches!(self, Self::Blind)
  }

  /// The witnessed destination, or `None` for every kind of absence.
  ///
  /// For LOGGING and for callers that need the address itself. It is deliberately
  /// not what [`admits_ingress`] reads: collapsing the three absences back into
  /// one `Option` is the shape this type exists to remove.
  #[inline]
  #[must_use]
  pub const fn witnessed_destination(self) -> Option<IpAddr> {
    match self {
      Self::Witnessed(dst) => Some(dst),
      Self::Lost | Self::Declined | Self::Blind => None,
    }
  }
}

/// What the receive path witnessed about the interface a datagram ARRIVED on.
///
/// Replaces the `(pkt_iface: u32, iface_reported: bool)` pair, whose four
/// combinations spelled three states and let a driver pass "I do not know"
/// positionally into the permissive arm. The mapping is
/// `(n, _) => Witnessed(n)`, `(0, true) => Lost` or [`Self::Declined`] depending
/// on `MSG_CTRUNC`, `(0, false) => Blind`.
///
/// [`NonZeroU32`] is the point of the type: index `0` names no interface on any
/// supported platform, so `Witnessed(0)` must be unrepresentable rather than
/// merely discouraged.
///
/// An IPv6 peer's scope id is a SECOND witness to the same question and is not
/// carried here — it rides on the peer address, which the rule already takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IfaceWitness {
  /// The kernel named the receiving interface for this datagram.
  Witnessed(NonZeroU32),
  /// This path reports interfaces, and OUR OWN control buffer was too small
  /// (`MSG_CTRUNC`). REFUSES — see [`DestinationWitness::Lost`], which is the
  /// same flag read for the other half of the same MESSAGE. `MSG_CTRUNC` rides
  /// on the message header and not on any one cmsg, so it is a single fact about
  /// the whole receive however many cmsgs carried the two halves.
  Lost,
  /// This path reports interfaces, the kernel named none for this datagram, and
  /// flagged no truncation. DEGRADES exactly as
  /// [`DestinationWitness::Declined`] does.
  ///
  /// # Why it degrades — and why the two halves are SEPARATE values
  ///
  /// ## The coupling argument, which appeals to no kernel behaviour at all
  ///
  /// A single `PKTINFO` cmsg carries both facts in ONE message: `in_pktinfo`
  /// holds `ipi_addr` beside `ipi_ifindex`, `in6_pktinfo` holds `ipi6_addr`
  /// beside `ipi6_ifindex`. Presence is therefore decided once — for the cmsg,
  /// never per field — so a cmsg that is absent, or too short to read, cannot
  /// take the interface while leaving the destination. **That is a property of
  /// the payload SHAPE**, it holds whatever a target does when it cannot deliver
  /// one, and it is the entire basis for not splitting the two absences on those
  /// paths. Refusing on this half while degrading on that one would leave the
  /// degradation unreachable there.
  ///
  /// ## There is no shared failure mechanism — do not appeal to one
  ///
  /// The targets behave differently when the cmsg cannot be delivered, so any
  /// sentence resting on a common failure mode is wrong for at least one of
  /// them. This doc has had two goes at that sentence: the first attributed
  /// `sbcreatecontrol` allocate-or-skip to every target, and the second replaced
  /// it with a per-target summary of the header's audit. The summary had drifted
  /// from the audit in three of its four entries before the round that added it
  /// was over — a family qualifier dropped here, a scope widened there — because
  /// nothing but care was holding the two copies equal.
  ///
  /// **So this states no kernel behaviour at all, and the omission is the
  /// point.** What a kernel can and cannot leave out is written down in exactly
  /// one place: this module's header, under "Where `Declined` can actually
  /// occur, read out of each kernel", with the reachability table above it. That
  /// audit covers Linux/Android, Apple, the BSDs and Windows, per address family
  /// wherever the families differ — which they do. Read it there. A summary here
  /// would be a second statement of facts only the header establishes, kept true
  /// by nothing a compiler checks, which is the arrangement that has now failed
  /// twice in this file.
  ///
  /// None of it reaches the coupling argument above, which is why that argument
  /// is stated over the payload shape and not over any kernel's behaviour.
  ///
  /// ## A cmsg that IS present and names no interface is a DIFFERENT case
  ///
  /// It must not be folded into the one above: nothing went missing, so the
  /// coupling argument does not apply and is not needed. `ipi_ifindex = 0`
  /// arrives with the destination witnessed out of the very same struct — live
  /// on Linux IPv4 (`ipv4_pktinfo_prepare`'s `else` branch) and Apple IPv6 — so
  /// only the link scoping is lost; see [`Self::from_reporting_path`]. A
  /// NEGATIVE index is the same absence on the same terms; see
  /// [`Self::from_reporting_path_signed`]. Both reach this variant, and neither
  /// is an absent cmsg.
  ///
  /// ## BSD IPv4 is TWO cmsgs, and the shape invariant does not reach it
  ///
  /// BSD IPv4 uses `IP_RECVDSTADDR` + `IP_RECVIF`: TWO cmsgs built
  /// by two `sbcreatecontrol` calls, not two fields of one struct. An mbuf
  /// shortage can take either without the other, and NetBSD adds a deterministic
  /// form of the same split — `ip_savecontrol` emits `IP_RECVDSTADDR` before its
  /// `m_get_rcvif_psref() == NULL` early return and `IP_RECVIF` after it, so a
  /// detached receive interface loses one and keeps the other every time. Every
  /// combination below is reachable:
  ///
  /// | which of the pair arrived | `MSG_CTRUNC` clear | `MSG_CTRUNC` set |
  /// |---|---|---|
  /// | both | `Witnessed` + `Witnessed` | `Witnessed` + `Witnessed` |
  /// | `IP_RECVDSTADDR` only | `Witnessed` + `Declined` | `Witnessed` + **`Lost`** |
  /// | `IP_RECVIF` only | `Declined` + `Witnessed` | **`Lost`** + `Witnessed` |
  /// | neither | `Declined` + `Declined` | **`Lost`** + **`Lost`** |
  ///
  /// (destination + interface, in that order.) A driver may be MORE conservative
  /// than the right-hand column: `hick-udp`'s `recv_with_meta` reports `Lost` for
  /// both halves under `MSG_CTRUNC` without parsing at all, while `hick-compio`
  /// keeps a half the kernel delivered whole. Both are sound — a partially
  /// copied cmsg is short and no decoder here will read one — and this rule has
  /// to decide correctly for either.
  ///
  /// **So do not collapse the per-half handling.** `Lost` REFUSES and `Declined`
  /// DEGRADES, and on this path one half can be each at the same time; a
  /// maintainer who takes "they always arrive together" from the
  /// single-`PKTINFO` paragraph above and folds the two together re-opens
  /// exactly that distinction on the path that most needs it. `hick-compio`'s
  /// `bsd_ipv4_decode_spells_each_absent_half_by_whose_failure_it_was` pins the
  /// partial rows against real cmsg bytes.
  ///
  /// ## Which squares produce which of the two events
  ///
  /// The two are the sections above — a cmsg MISSING, and a cmsg PRESENT that
  /// names no interface — and the reachability table in this module's header
  /// says which squares reach each. Absent is live on BSD IPv6 and on the BSD
  /// IPv4 pair; present-with-no-interface is live on Linux IPv4 and Apple IPv6.
  /// The header is the sourced version of both; this variant states what they
  /// MEAN, not where they come from.
  Declined,
  /// This path cannot report interfaces by construction. Declared once per
  /// receive path.
  Blind,
}

impl IfaceWitness {
  /// The witness a path that DOES report interfaces mints for ONE datagram: the
  /// index as the kernel gave it, and whether the kernel set `MSG_CTRUNC`.
  ///
  /// A `0` index from a reporting path is an ABSENCE and never an interface, so
  /// it can only become [`Self::Lost`] or [`Self::Declined`] — never
  /// `Witnessed(0)`.
  ///
  /// # A zero index INSIDE a present cmsg is `Declined`, deliberately
  ///
  /// This is not a corner case and it is not the same event as a missing cmsg.
  /// Linux's `ipv4_pktinfo_prepare` (`net/ipv4/ip_sockglue.c`) sets
  /// `pktinfo->ipi_ifindex = 0` in its `else` branch, taken when
  /// `skb_rtable(skb)` is `NULL`, and `ip_cmsg_recv_pktinfo` emits the cmsg
  /// anyway with `ipi_addr` filled from `ip_hdr(skb)->daddr`. Apple's
  /// `ip6_savecontrol_v4` has the same shape:
  /// `pi6.ipi6_ifindex = (m && m->m_pkthdr.rcvif) ? m->m_pkthdr.rcvif->if_index : 0`.
  ///
  /// The kernel ANSWERED, and its answer was "no interface". That is a decline
  /// and not a failed proof: nothing was lost on our side, and there is nothing
  /// a larger control buffer would fix — so [`Self::Lost`] would be a false
  /// accusation against this side's own sizing. It is also the only form of
  /// `Declined` reachable on the primary platforms (see the reachability table
  /// in this module's header).
  ///
  /// On the single-`PKTINFO` paths the datagram still carries the DESTINATION
  /// out of that very cmsg, so §11's destination partition decides it in full
  /// and only the link scoping is lost. **That is a property of those paths and
  /// not of this constructor.** BSD IPv4 recovers the destination from a
  /// SEPARATE cmsg (`IP_RECVDSTADDR`), which may itself be absent — see
  /// [`Self::Declined`] for the four reachable combinations — so a zero index
  /// there says nothing about whether a destination was witnessed. The caller
  /// mints the two halves independently for exactly that reason.
  #[inline]
  #[must_use]
  pub const fn from_reporting_path(index: u32, control_truncated: bool) -> Self {
    match NonZeroU32::new(index) {
      Some(idx) => Self::Witnessed(idx),
      None if control_truncated => Self::Lost,
      None => Self::Declined,
    }
  }

  /// [`Self::from_reporting_path`] for a path whose kernel field for the index
  /// is SIGNED, where a NEGATIVE index is an absence on exactly the same terms
  /// as `0`.
  ///
  /// # The field is signed more widely than one target
  ///
  /// Linux's uapi declares `int ipi_ifindex` in `struct in_pktinfo` and
  /// `int ipi6_ifindex` in `struct in6_pktinfo`. `libc` binds the v4 field as
  /// `c_int` on Linux AND Android, and the v6 field as `c_uint` everywhere
  /// except Android — where `c_int` is the binding that matches the header the
  /// others widen away. So the signedness is the C ABI's and not one target's
  /// quirk, and a decoder reading the field as `u32` misreads a negative on any
  /// of them.
  ///
  /// # Why a negative is `Declined` and not `Witnessed` or [`Self::Lost`]
  ///
  /// `Witnessed` is out by construction. A negative reinterpreted as `u32` is a
  /// FABRICATED index — `-1` becomes `4294967295`, which names no interface any
  /// host has, and `arrived_on_bound_interface` would take it as the kernel's
  /// positive statement of arrival, disagree with the bound index and REFUSE
  /// ([`Refuse::ForeignLink`]) on a fact no kernel ever stated. [`NonZeroU32`]
  /// is here to make "not an interface" unrepresentable, and `4294967295` is no
  /// more an interface than `0` is.
  ///
  /// [`Self::Lost`] is out for the reason `0` is not `Lost`: it accuses THIS
  /// side's control buffer, and no buffer size changes the sign of a field the
  /// kernel already delivered — the same false accusation
  /// [`Self::from_reporting_path`] refuses to make for a zero index. A negative
  /// therefore joins `0` in the one absence, which the truncation flag then
  /// partitions exactly as it does there, and the datagram keeps the DESTINATION
  /// that same cmsg witnessed, so only the link scoping is lost.
  ///
  /// The "same cmsg" holds here and is not the loose claim it would be on
  /// [`Self::from_reporting_path`]: a signed index is an `in_pktinfo` /
  /// `in6_pktinfo` field, so every caller of THIS constructor is on a
  /// single-`PKTINFO` path. BSD IPv4's `IP_RECVIF` carries an unsigned
  /// `sockaddr_dl::sdl_index` and goes through the unsigned constructor.
  ///
  /// Neither kernel is known to hand one over: Linux's
  /// `ip6_datagram_recv_common_ctl` wraps its `put_cmsg` in
  /// `if (src_info.ipi6_ifindex >= 0)`, so a negative would omit the cmsg
  /// rather than deliver it (see this module's header), and every BSD signals
  /// "no receive interface" with `0`. This is what the boundary does if one
  /// arrives regardless.
  ///
  /// # Callers whose field is genuinely unsigned
  ///
  /// They reinterpret it (`as i32`), which is exact for every index a supported
  /// kernel assigns: Linux's `ifindex` is a positive `int`, and the BSDs count
  /// `if_index` up from `1`. No kernel here reaches `2^31`, and an index that
  /// did would DEGRADE to `Declined` rather than fabricate a witness — the
  /// direction this boundary is required to err in.
  #[inline]
  #[must_use]
  pub const fn from_reporting_path_signed(index: i32, control_truncated: bool) -> Self {
    // A negative collapses onto `0` so the truncation partition is written
    // once, in `from_reporting_path`, and cannot come to disagree with itself.
    let index = if index < 0 { 0 } else { index as u32 };
    Self::from_reporting_path(index, control_truncated)
  }

  /// The declaration a path that reports NO interface makes — once, from its own
  /// compile-time capability, for every datagram it will ever produce.
  #[inline]
  #[must_use]
  pub const fn blind() -> Self {
    Self::Blind
  }

  /// Whether this is [`IfaceWitness::Witnessed`].
  #[inline]
  #[must_use]
  pub const fn is_witnessed(&self) -> bool {
    matches!(self, Self::Witnessed(..))
  }
  /// Whether this is [`IfaceWitness::Lost`].
  #[inline]
  #[must_use]
  pub const fn is_lost(&self) -> bool {
    matches!(self, Self::Lost)
  }
  /// Whether this is [`IfaceWitness::Declined`].
  #[inline]
  #[must_use]
  pub const fn is_declined(&self) -> bool {
    matches!(self, Self::Declined)
  }
  /// Whether this is [`IfaceWitness::Blind`].
  #[inline]
  #[must_use]
  pub const fn is_blind(&self) -> bool {
    matches!(self, Self::Blind)
  }

  /// The witnessed index, or `None` for every kind of absence. For logging, and
  /// for the witness loop in `arrived_on_bound_interface`.
  #[inline]
  #[must_use]
  pub const fn witnessed_index(self) -> Option<NonZeroU32> {
    match self {
      Self::Witnessed(idx) => Some(idx),
      Self::Lost | Self::Declined | Self::Blind => None,
    }
  }

  /// The witnessed index, or `0` where nothing was witnessed.
  ///
  /// **Never for THIS crate's admission decision.** It flattens the three
  /// absences this type exists to keep apart, and [`admits_ingress`] does not
  /// accept a `u32` at all, so it cannot be reached from there. It is for the
  /// layers below the trust boundary that take an interface index as a
  /// ROUTING hint — the protocol core's `handle` among them — where `0`
  /// already means "unknown".
  ///
  /// That routing hint is not always inert, though: with
  /// `mdns-proto`'s `EndpointConfig::with_trust_advertised_src_as_self`
  /// enabled, `handle` passes it on to `src_matches_advertised`, which reads
  /// it to scope IPv6 link-local self-classification — and that classification
  /// gates whether a datagram is suppressed as this endpoint's own echo, which
  /// **is** an admission-adjacent decision, just not one this crate makes. The
  /// three absences this method flattens are not distinguishable to that
  /// caller either: `Lost`, `Declined`, and `Blind` all arrive there as the
  /// same `0`, "unknown".
  #[inline]
  #[must_use]
  pub const fn index_or_zero(self) -> u32 {
    match self.witnessed_index() {
      Some(idx) => idx.get(),
      None => 0,
    }
  }
}

/// What [`admits_ingress`] decided, and on WHICH arm.
///
/// A boolean said only that a datagram was dropped. Every arm below is a
/// separate claim about §11, several of them are known residuals, and two of
/// them ([`Admit::BlindSourceOnLink`], [`Refuse::DestinationNotHeld`]) are the
/// conformance gaps this workspace is trying to measure — so the arm has to
/// survive out of the function rather than being collapsed at the return.
///
/// Not `#[non_exhaustive]`, for the same reason [`LinkDelivery`] is not: every
/// value is a decision in a trust boundary, so a new one must break every
/// `match` that counts or asserts on it rather than fall into a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
  /// The datagram passed the boundary, on the named arm.
  Admit(Admit),
  /// The datagram was refused, for the named reason.
  Refuse(Refuse),
}

impl Verdict {
  /// Whether this is [`Verdict::Admit`].
  #[inline]
  #[must_use]
  pub const fn is_admit(&self) -> bool {
    matches!(self, Self::Admit(..))
  }
  /// Whether this is [`Verdict::Refuse`].
  #[inline]
  #[must_use]
  pub const fn is_refuse(&self) -> bool {
    matches!(self, Self::Refuse(..))
  }

  /// Whether this admission rested on **no destination witness at all** — the
  /// blind/degraded source-prefix arm, where the destination partition's
  /// guarantees do not hold.
  ///
  /// The counter a driver should keep for the conformance gap on its blind
  /// squares, and the one that makes a `Declined` cmsg visible instead of silent.
  #[inline]
  #[must_use]
  pub const fn is_degraded_admit(self) -> bool {
    matches!(
      self,
      Self::Admit(Admit::BlindSourceOnLink | Admit::BlindMulticastDelivery)
    )
  }

  /// Whether an mDNS-group datagram was ADMITTED without anything scoping it to
  /// the bound link — on the coarse multicast flag or on §11's source arm.
  ///
  /// The residual exposure of granting the group arm's fallback at all: these
  /// admissions did not prove they reached this endpoint on its own link. Not
  /// folded into [`Self::is_degraded_admit`], whose subject is an admission with
  /// no DESTINATION witness; here the destination is witnessed and it is ours.
  #[inline]
  #[must_use]
  pub const fn is_unscoped_group_admit(self) -> bool {
    matches!(self, Self::Admit(Admit::UnscopedMdnsGroup))
  }

  /// Whether an mDNS-group datagram was REFUSED for want of link scoping.
  ///
  /// The availability cost of the rule above, and the counter that turns it from
  /// an argument into an observation: §11 says to admit this datagram and this
  /// endpoint did not. See [`Refuse::UnscopedGroupSourceOffLink`].
  #[inline]
  #[must_use]
  pub const fn is_unscoped_group_refusal(self) -> bool {
    matches!(self, Self::Refuse(Refuse::UnscopedGroupSourceOffLink))
  }

  /// Whether this refusal is the RESIDUAL one: a witnessed destination that no
  /// named class describes and that this endpoint does not hold.
  ///
  /// Counting it is what makes the residual measurable rather than merely
  /// argued about — see [`Refuse::DestinationNotHeld`].
  #[inline]
  #[must_use]
  pub const fn is_residual_refusal(self) -> bool {
    matches!(self, Self::Refuse(Refuse::DestinationNotHeld))
  }
}

/// Which §11 arm admitted a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Admit {
  /// §11 arm one, verbatim: a destination of `224.0.0.251` or `FF02::FB` is
  /// *"necessarily deemed to have originated on the local link, regardless of
  /// source IP address"*.
  MdnsGroup,
  /// The witnessed destination IS an mDNS group, but nothing scoped the
  /// datagram to the link this endpoint bound, so §11 arm one's *"regardless of
  /// source IP address"* exemption was WITHHELD and the source arm admitted
  /// instead.
  ///
  /// The exemption is the one admission in this whole boundary that tests
  /// nothing the datagram carries about its origin. What makes it safe here is
  /// not §11 — §11 grants it unconditionally — but this crate's scoping of it to
  /// the bound link, and that scoping needs the link to have been named. A
  /// wildcard-bound socket on a multi-homed host is handed every NIC's copy of
  /// the group traffic, so granting the exemption unscoped admits another link's
  /// datagram into the cache and §9 conflict handling with no proof of
  /// provenance at all.
  ///
  /// Withheld, the datagram is not refused — it takes exactly the arm a datagram
  /// with NO destination witness would have taken: the kernel's coarse
  /// [`LinkDelivery`] where there is one, and §11's source arm otherwise. So a
  /// square carrying more evidence can never do worse than the square below it,
  /// and the cost falls on an off-prefix sender on a target with no
  /// `MSG_MCAST` — FreeBSD and DragonFly. The destination is still read by every
  /// NEGATIVE arm: a foreign group or a broadcast is refused by name here
  /// exactly as it is when the exemption is granted. See [`admits_ingress`].
  ///
  /// Counted separately from [`Self::MdnsGroup`] because they are different
  /// claims: one is arm one, the other is the source rule standing in for it.
  ///
  /// # What this variant does NOT buy
  ///
  /// **It is an observation, not a capability boundary.** This distinction is
  /// about ADMISSION — whether the datagram crosses the boundary at all — and
  /// says nothing about what an admitted datagram may then DO. Every hosted
  /// driver reduces the verdict to [`Verdict::is_admit`] and hands the datagram
  /// to the same `mdns-proto` `Endpoint::handle` path as [`Self::MdnsGroup`], so
  /// an unscoped admission reaches cache, RFC 6762 §9 conflict and known-answer
  /// processing with exactly the trust a scoped one does.
  ///
  /// That is not an oversight at the call sites. `Endpoint::handle` has ONE
  /// trust input and it is a boolean — the latch that also carries self-loopback
  /// and untrusted-response suppression — and it is all-or-nothing: it discards
  /// the datagram wholesale and counts it as dropped rather than restricting
  /// what it may touch. So there is no graded tier to route this variant into,
  /// and expressing one means INTRODUCING a trust model rather than passing a
  /// value that already exists. That work is separate, and it has to cover
  /// [`Self::BlindMulticastDelivery`] in the same change: restricting one and
  /// not the other would break the monotonicity that
  /// [`admits_ingress`]'s unscoped arm is built on.
  ///
  /// **The obvious cheap substitute is wrong, and it is worth knowing why.** A
  /// driver can read `QR` from the raw header before `handle` — every hosted one
  /// already does, for §11's source-port rule — so it could drop RESPONSES on an
  /// unscoped admission without touching `mdns-proto` at all. But a response is
  /// exactly what §11 arm one exists to admit, so that reinstates the
  /// availability cost on the very square the coarse-delivery arm was added to
  /// resolve, and it still leaves conflict handling reachable from a QUERY,
  /// whose authority section drives §8.1 tiebreaking. Partial security, full
  /// availability cost.
  ///
  /// Until the tier exists, what this variant draws is visible in
  /// [`Verdict::is_unscoped_group_admit`] and in logs, and nowhere else.
  UnscopedMdnsGroup,
  /// §11 arm two: the witnessed destination is an address this endpoint HOLDS —
  /// a response *"received via unicast"* — and the source passed the on-link
  /// comparison.
  HeldDestination,
  /// The interface snapshot was EMPTY, so "not one of our addresses" was never a
  /// fact this endpoint established; the destination test deferred to the source
  /// arm and the source arm admitted. Bounded to a loopback-bound endpoint's own
  /// traffic — see the arm that takes it in [`admits_ingress`].
  UnenumeratedDestination,
  /// No destination was witnessed and the kernel's coarse [`LinkDelivery`] said
  /// multicast. It names no GROUP, so this admits any foreign group from any
  /// source: a residual that no flag can close.
  BlindMulticastDelivery,
  /// No destination was witnessed, no delivery class settled it, and §11's
  /// source arm alone admitted.
  ///
  /// **The degraded admission.** It is the standing behaviour on a structurally
  /// blind square, and the one-datagram fallback wherever a kernel declined to
  /// emit a cmsg — [`DestinationWitness::Declined`] tells those two apart at the call site,
  /// and this variant is what makes the admission itself countable.
  BlindSourceOnLink,
}

impl Admit {
  /// Whether this is [`Admit::MdnsGroup`].
  #[inline]
  #[must_use]
  pub const fn is_mdns_group(&self) -> bool {
    matches!(self, Self::MdnsGroup)
  }
  /// Whether this is [`Admit::UnscopedMdnsGroup`].
  ///
  /// Worth its own counter: sustained movement here is a path that witnesses
  /// destinations but keeps failing to name the link — a kernel declining
  /// `IP_RECVIF` under mbuf pressure, which a flood causes — and each one is an
  /// admission §11 would have granted unconditionally and this crate did not.
  #[inline]
  #[must_use]
  pub const fn is_unscoped_mdns_group(&self) -> bool {
    matches!(self, Self::UnscopedMdnsGroup)
  }
  /// Whether this is [`Admit::HeldDestination`].
  #[inline]
  #[must_use]
  pub const fn is_held_destination(&self) -> bool {
    matches!(self, Self::HeldDestination)
  }
  /// Whether this is [`Admit::UnenumeratedDestination`].
  #[inline]
  #[must_use]
  pub const fn is_unenumerated_destination(&self) -> bool {
    matches!(self, Self::UnenumeratedDestination)
  }
  /// Whether this is [`Admit::BlindMulticastDelivery`].
  #[inline]
  #[must_use]
  pub const fn is_blind_multicast_delivery(&self) -> bool {
    matches!(self, Self::BlindMulticastDelivery)
  }
  /// Whether this is [`Admit::BlindSourceOnLink`].
  #[inline]
  #[must_use]
  pub const fn is_blind_source_on_link(&self) -> bool {
    matches!(self, Self::BlindSourceOnLink)
  }
}

/// Why a datagram was refused. Each variant is one class, so a refusal can be
/// counted and asserted rather than only observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refuse {
  /// A nonzero witness — the receive interface index, or an IPv6 source's scope
  /// id — named a link other than the one this endpoint bound. Stage 1, and no
  /// later stage overturns it.
  ForeignLink,
  /// Nothing witnessed the link, and the interface witness was
  /// [`IfaceWitness::Lost`]: our own control buffer was too small.
  LinkWitnessLost,
  /// The destination witness was [`DestinationWitness::Lost`]: our own control buffer was
  /// too small. Distinct from [`Self::LinkWitnessLost`] because the two halves
  /// can come from different cmsgs on the BSD `IP_RECVDSTADDR`/`IP_RECVIF`
  /// pair, and a driver that sees only one of them should be able to say which.
  DestinationWitnessLost,
  /// The witnessed destination is a multicast group that is not one of the two
  /// mDNS groups — LLMNR's `224.0.0.252` / `ff02::1:3`, or any other. §11 names
  /// exactly two addresses and this is a trust boundary, not a link-local scope
  /// test.
  ForeignGroup,
  /// The witnessed destination is a broadcast by its own definition: the IPv4
  /// limited broadcast `255.255.255.255` (RFC 919). A subnet-directed broadcast
  /// is NOT named here — identifying one needs arithmetic over a prefix that is
  /// wrong in three separate ways (see `is_bound_address`) — so it lands in
  /// [`Self::DestinationNotHeld`] and is refused there.
  BroadcastAddressed,
  /// No destination was witnessed and the kernel's coarse [`LinkDelivery`] said
  /// broadcast. Exact NEGATIVE evidence that needs no address: §11 gives a
  /// broadcast no arm at all.
  BroadcastDelivery,
  /// The witnessed destination is the unspecified address (`0.0.0.0` / `::`),
  /// which §11 gives no arm and which is not an address any endpoint holds.
  UnspecifiedDestination,
  /// The witnessed destination is in RFC 1122 §3.2.1.3's `127.0.0.0/8` (or is
  /// `::1`) and this endpoint is NOT bound to the loopback interface, so the
  /// block is not its own and the destination is a martian.
  ///
  /// Scoped to the BINDING rather than to the address: Linux's `route_localnet`
  /// lets an operator stop treating `127/8` as martian on a real NIC, at which
  /// point an address-only exemption would hand an adjacent spoofer the whole
  /// boundary.
  LoopbackDestinationOffLoopbackBinding,
  /// The witnessed destination is an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
  ///
  /// Classified rather than left to fall through: `::ffff:224.0.0.251` is **not**
  /// [`core::net::Ipv6Addr::is_multicast`], so a residual defined as "everything
  /// else" would absorb an mDNS group in disguise without ever naming it. It is
  /// unreachable on this workspace's sockets — `IPV6_V6ONLY` is set at bind on
  /// both Unix and Windows — which is a reason to name it, not a reason to let it
  /// land in a terminal bucket by accident.
  Ipv4MappedDestination,
  /// The witnessed destination is none of the classes above and is not an address
  /// this endpoint holds: a neighbour's address on our own subnet, a
  /// subnet-directed or operator-configured broadcast, a martian, an anycast
  /// address `getifs` does not surface.
  ///
  /// **The residual.** §11 offers it no arm, so it is refused; counting it is
  /// what makes the size of the gap an observation rather than an argument.
  DestinationNotHeld,
  /// §11's source arm refused: the source is neither this loopback-bound
  /// endpoint's own traffic nor inside any prefix the bound interface carries.
  SourceOffLink,
  /// The witnessed destination IS an mDNS group, nothing scoped the datagram to
  /// the bound link, and §11's source arm then refused it.
  ///
  /// **The availability cost of scoping arm one, made countable.** §11 requires
  /// a group datagram be admitted *"regardless of source IP address"*; this
  /// endpoint could not establish that the datagram reached it on the link it
  /// bound, so it fell back to the source test and the sender was off-prefix —
  /// which is precisely the overlaid-subnet peer the RFC calls the exemption
  /// essential for.
  ///
  /// Separate from [`Self::SourceOffLink`] because the two are different events
  /// with different remedies. That one is §11 working as written. This one is a
  /// datagram §11 says to admit, refused for want of link evidence a kernel
  /// declined to supply — and every BSD declines under the ancillary-mbuf
  /// shortage a flood causes, so sustained movement here is an availability
  /// attack in progress rather than a misconfigured peer.
  ///
  /// Reachable on FreeBSD and DragonFly, which bind no `MSG_MCAST`; OpenBSD and
  /// NetBSD reach the coarse multicast arm instead and admit. See this module's
  /// header for the residual and which rows carry it.
  UnscopedGroupSourceOffLink,
}

impl Refuse {
  /// Whether this is [`Refuse::ForeignLink`].
  #[inline]
  #[must_use]
  pub const fn is_foreign_link(&self) -> bool {
    matches!(self, Self::ForeignLink)
  }
  /// Whether this is [`Refuse::UnscopedGroupSourceOffLink`].
  #[inline]
  #[must_use]
  pub const fn is_unscoped_group_source_off_link(&self) -> bool {
    matches!(self, Self::UnscopedGroupSourceOffLink)
  }
  /// Whether this is [`Refuse::LinkWitnessLost`].
  #[inline]
  #[must_use]
  pub const fn is_link_witness_lost(&self) -> bool {
    matches!(self, Self::LinkWitnessLost)
  }
  /// Whether this is [`Refuse::DestinationWitnessLost`].
  #[inline]
  #[must_use]
  pub const fn is_destination_witness_lost(&self) -> bool {
    matches!(self, Self::DestinationWitnessLost)
  }
  /// Whether this is [`Refuse::ForeignGroup`].
  #[inline]
  #[must_use]
  pub const fn is_foreign_group(&self) -> bool {
    matches!(self, Self::ForeignGroup)
  }
  /// Whether this is [`Refuse::BroadcastAddressed`].
  #[inline]
  #[must_use]
  pub const fn is_broadcast_addressed(&self) -> bool {
    matches!(self, Self::BroadcastAddressed)
  }
  /// Whether this is [`Refuse::BroadcastDelivery`].
  #[inline]
  #[must_use]
  pub const fn is_broadcast_delivery(&self) -> bool {
    matches!(self, Self::BroadcastDelivery)
  }
  /// Whether this is [`Refuse::UnspecifiedDestination`].
  #[inline]
  #[must_use]
  pub const fn is_unspecified_destination(&self) -> bool {
    matches!(self, Self::UnspecifiedDestination)
  }
  /// Whether this is [`Refuse::LoopbackDestinationOffLoopbackBinding`].
  #[inline]
  #[must_use]
  pub const fn is_loopback_destination_off_loopback_binding(&self) -> bool {
    matches!(self, Self::LoopbackDestinationOffLoopbackBinding)
  }
  /// Whether this is [`Refuse::Ipv4MappedDestination`].
  #[inline]
  #[must_use]
  pub const fn is_ipv4_mapped_destination(&self) -> bool {
    matches!(self, Self::Ipv4MappedDestination)
  }
  /// Whether this is [`Refuse::DestinationNotHeld`].
  #[inline]
  #[must_use]
  pub const fn is_destination_not_held(&self) -> bool {
    matches!(self, Self::DestinationNotHeld)
  }
  /// Whether this is [`Refuse::SourceOffLink`].
  #[inline]
  #[must_use]
  pub const fn is_source_off_link(&self) -> bool {
    matches!(self, Self::SourceOffLink)
  }
}

/// The link an endpoint bound, as the §11 boundary needs to know it.
///
/// This is the CONFIGURATION half of the boundary and it is the driver's: every
/// field is resolved once at bind time and handed over, so the rule itself
/// performs no lookup and holds no state. On a hosted driver `hick-udp`'s
/// `collect_local_subnets` and `is_loopback_interface` are the two reads that
/// fill it in; a bare-metal caller supplies what its own stack holds.
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
///
/// # `fe80::/64` is in neither list and is on-link regardless
///
/// The one on-link prefix that is not evidence a caller gathers: RFC 5942 §3
/// makes it the IPv6 default and RFC 4861 makes it permanent, so
/// `src_on_local_link` seeds it as a constant and NEITHER constructor can add,
/// remove or narrow it. That is deliberate — it was previously reached only
/// because an interface holding a link-local address happened to report
/// `fe80::<iid>/64`, which is the false positive above wearing a right answer,
/// and which a `/128` report or an interface with no link-local address of its
/// own silently turns into a false negative.
///
/// So a caller building `onlink_prefixes` from a route table need not include
/// it, and including it changes nothing.
///
/// It is also the one on-link prefix that is **not specific to this interface**,
/// which is why `src_on_local_link` consults it only once stage 1 has
/// established the link. Everything a caller puts in these lists is read as
/// evidence about the BOUND interface; a caller that adds a prefix which is in
/// fact on every interface weakens that reading, and no gate here can tell.
#[derive(Debug, Clone, Copy)]
pub struct BoundLink<'a> {
  iface: u32,
  is_loopback: bool,
  local_addrs: &'a [(IpAddr, u8)],
  onlink_prefixes: &'a [(IpAddr, u8)],
}

impl<'a> BoundLink<'a> {
  /// `iface` is the interface index this endpoint bound, `is_loopback` says
  /// whether that interface is the loopback one (`hick-udp`'s
  /// `is_loopback_interface`, for a hosted driver),
  /// and `local_addrs` are the addresses configured on it (see
  /// `hick-udp`'s `collect_local_subnets`).
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
  /// with `hick-udp`'s `collect_local_subnets`.
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
  ///
  /// Permissive is not the same as PROVEN, and the two are kept apart: a zero
  /// grants §11 arm one's exemption (nothing can be foreign to a link nobody
  /// named) and never feeds the `fe80::/64` seed in `src_on_local_link` (which
  /// needs a link for the datagram to have arrived on). A caller that wants the
  /// second states its interface index, which it can do; being structurally
  /// single-link is not something this type can check.
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
  ///
  /// It is not the WHOLE of what `src_on_local_link` treats as on-link:
  /// `fe80::/64` is seeded there unconditionally and appears in no list. An
  /// accessor that returned it would have to fabricate a slice, and this crate
  /// has no allocator.
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

/// Whether a datagram from `src`, arriving under `iface`, belongs to the link
/// this endpoint bound. `None` passes; `Some(reason)` refuses and names it.
///
/// [`IfaceWitness`] carries both the index and what its absence MEANS, because
/// the meaning belongs to the receive path and not to the platform — see this
/// module's header — and because the decision must be testable on every host,
/// not only on one whose capabilities happen to match the case under test.
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
/// # The exceptions, all deliberate
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
/// **With NO witness at all, the kind of absence decides, and only one of the
/// three refuses.** [`IfaceWitness::Blind`] is the path's silence — `hick-compio`'s
/// Windows `recv_from` arm, and any driver reading datagrams with `recvfrom` —
/// and rejecting silence would
/// take mDNS off the air there entirely. [`IfaceWitness::Declined`] is the
/// kernel skipping a cmsg it could not allocate, which is an availability event
/// and not evidence about the sender, so it degrades the same way.
/// [`IfaceWitness::Lost`] is the one that fails closed: our own control buffer
/// was too small, the kernel HAD the fact, and that is a defect on this side.
///
/// The split matters because the previous rule refused both of the last two.
/// Every BSD allocates its ancillary mbufs with `M_NOWAIT` and silently skips
/// the cmsg — no error, no counter, no truncation flag — while still delivering
/// the datagram, and mbuf exhaustion is normally CAUSED by a flood. A blanket
/// refusal therefore made the responder go completely deaf, silently, exactly
/// when it was under attack. Availability is chosen there, and the fallback is
/// not a new one: it is the standing behaviour of every structurally blind
/// square.
///
/// # THE TRADE, written down rather than left to be rediscovered
///
/// Degrading on [`IfaceWitness::Declined`] costs something real, and it is not
/// the same cost as degrading on the destination witness. **This gate is the
/// only thing that scopes §11's GROUP arm to the link this endpoint bound.** A
/// group destination proves a datagram was link-local to SOME link, never to
/// ours, so once this gate passes for want of evidence a foreign NIC's
/// `224.0.0.251` traffic is admitted on the group arm with no source test at
/// all.
///
/// **The attack.** An adjacent sender who can exhaust the receiving host's mbuf
/// pool — flooding is the ordinary way — makes a BSD kernel skip `PKTINFO` on
/// arbitrary datagrams, including their own. Their cross-NIC traffic then
/// arrives here with no witness, this gate passes it, and either the group arm
/// takes it outright or the source-prefix arm takes it on an in-prefix source
/// they simply choose. Under the previous rule that traffic was refused. This is
/// a genuine widening and it is attacker-INFLUENCED, even though the loss of any
/// individual cmsg is not attacker-chosen.
///
/// **Why availability wins anyway.** The alternative is not "refuse the
/// attacker": it is refuse EVERYTHING, because the shortage is host-wide and
/// hits every datagram equally. So the choice is between an endpoint that admits
/// some off-link traffic during a flood and an endpoint that answers nothing
/// during a flood — including the queries it exists to answer, and including its
/// own loopback echo, which its RFC 6762 §8.2 conflict handling and its
/// self-send suppression both depend on. §21 is explicit that this mechanism
/// does not defend against an on-link antagonist at all, and the degraded arm is
/// exactly the rule four supported targets run permanently. An availability
/// failure an adjacent host can trigger at will is the worse of the two.
///
/// **What an operator watches.** `ingress_degraded_admits` counts every
/// admission taken with no destination witness, and `ingress_witness_declined`
/// counts every datagram whose cmsg the kernel skipped or could not name an
/// interface for. On a Linux, Apple or Windows square the first should sit at
/// zero and the second should be rare — see the reachability table in this
/// module's header — so sustained movement in either is this attack, or a kernel
/// doing something that table does not describe. Neither is a rate a healthy
/// host produces, and that is what makes them worth alerting on.
///
/// **What would close it.** Not refusing here — that is the failure above.
/// Binding one socket per interface instead of wildcard-binding would make the
/// link a property of the SOCKET rather than of a cmsg, and no ancillary-data
/// shortage could take it away. That is a different endpoint design, and it is
/// not tracked as part of this boundary.
///
/// Admitting an absence is NOT the end of the matter, and this function is not
/// the place that settles it: a datagram that passes here must still satisfy one
/// of §11's own two arms.
fn arrived_on_bound_interface(
  src: SocketAddr,
  link: BoundLink<'_>,
  iface: IfaceWitness,
) -> Result<LinkProvenance, Refuse> {
  if link.iface() == 0 {
    // This endpoint named no interface, so there is no link to scope TO. The
    // scoping forbids nothing here, and therefore withholds nothing either: an
    // exemption is withheld because a rule could not be applied, never because
    // the rule does not exist. `hick-smoltcp` runs permanently on this square —
    // one interface, nothing to compare a witness against — and withholding
    // there would take §11 arm one away from that driver forever in exchange
    // for no scoping at all.
    //
    // It is its OWN state and not `Established`, because those are two different
    // facts and only one of them is evidence. "Nothing here can be foreign" is
    // what arm one needs; "this datagram arrived on OUR link" is what the seeded
    // `fe80::/64` needs, and a zero cannot supply it — there is no *our link*
    // for it to be about. Returning `Established` here gave the seed a proof
    // nobody produced: `BoundLink::new(0, …)` with a `fe80::x%7` source and no
    // link-local prefix enumerated was ADMITTED, where the same inputs on a
    // bound endpoint are refused.
    //
    // The two callers a zero conflates — one that binds no interface by
    // construction, one that could not resolve an index — are not
    // distinguishable here, and this is deliberately the conservative collapse
    // rather than an attempt to tell them apart: telling them apart would only
    // matter in order to give one of them MORE, and "I am structurally
    // single-link" is a guarantee this type cannot check. A caller that wants
    // the seed says so by naming its interface.
    return Ok(LinkProvenance::Unbound);
  }
  // The witnesses are read FIRST and nothing overrules them. A present witness is
  // evidence the kernel attached to this datagram; a source ADDRESS is a claim
  // the sender wrote. No exception below may let the second answer over the
  // first.
  //
  // EITHER witness scopes the datagram, which is why this is a loop and not a
  // read of `iface` alone: an IPv6 peer's scope id names the link independently
  // of any cmsg, so a v6 datagram whose `IPV6_PKTINFO` the kernel declined can
  // still be scoped by the address family itself.
  let mut witnessed = false;
  for witness in [iface.witnessed_index(), NonZeroU32::new(scope_of(src))] {
    let Some(witness) = witness else {
      continue;
    };
    witnessed = true;
    if witness.get() != link.iface() {
      return Err(Refuse::ForeignLink);
    }
  }
  if witnessed {
    return Ok(LinkProvenance::Established);
  }
  // Nothing named the link. Only now may a loopback-BOUND endpoint take its own
  // loopback traffic on the source address, and only because the loopback
  // interface IS its link — which is exactly the scoping the exemption needs, so
  // this passes as SCOPED rather than merely as not-refused.
  if link.is_loopback() && src.ip().is_loopback() {
    return Ok(LinkProvenance::Established);
  }
  match iface {
    IfaceWitness::Lost => Err(Refuse::LinkWitnessLost),
    // The kernel DECLINED on a path that normally names the link. Admission
    // continues — that is the availability invariant this function is built
    // around and nothing here inverts it — but nothing scoped this datagram, so
    // §11 arm one's source exemption is not available to it.
    //
    // This is the state an attacker can MANUFACTURE, which is what separates it
    // from `Blind` below. Every BSD builds its ancillary mbufs with `M_NOWAIT`
    // and skips one it cannot allocate; a flood exhausts them; and the datagrams
    // that would have carried link proof arrive without it. Granting the
    // exemption here hands the attacker an unconditional admit from any NIC,
    // paid for with the flood they were running anyway.
    // ... and a path that names a link for NO datagram is the same answer, not a
    // softer one. `a_declined_witness_decides_exactly_as_a_blind_one` is the
    // invariant that says so, and it survives this change intact — precisely
    // because withholding is not refusing. Both spellings route the datagram to
    // §11's source arm, which is where a `Blind` DESTINATION has always sent it,
    // so the availability argument that invariant rests on is untouched: nothing
    // here makes a responder deaf that was not already deaf to the same sender.
    //
    // Splitting them was tried and rejected. `Declined` is the attacker-inducible
    // one — flood the host, exhaust its `M_NOWAIT` mbufs, and the link proof
    // stops arriving — which is a reason it is URGENT, not a reason to grant an
    // unbacked exemption to the structurally blind square beside it. Granting
    // there buys nothing checkable and costs the one equality this input model
    // is built on.
    IfaceWitness::Declined | IfaceWitness::Blind => Ok(LinkProvenance::Unproven),
    // Unreachable: a `Witnessed` index is nonzero, so it set `witnessed` above
    // and returned. Spelled as a pass rather than a panic because this crate
    // denies `clippy::unreachable` on a trust boundary, and because refusing
    // here would refuse a datagram whose witness AGREED with the binding.
    IfaceWitness::Witnessed(_) => Ok(LinkProvenance::Established),
  }
}

/// Whether this datagram's LINK was established: the one fact every admission
/// that weighs nothing about the sender is allowed to rest on.
///
/// Produced by [`arrived_on_bound_interface`] — the ONE place that decides what
/// scoped a datagram to this endpoint's link — so the gate cannot come to
/// disagree with itself about what "our link" means. The alternative, letting
/// each receive path encode "witnessed but unscoped" into the witness it hands
/// over, was rejected: the rule is over the PAIR of witnesses, both of which
/// arrive here anyway, and pushing it outward gives it one site per decoder to
/// be forgotten at. It was forgotten at exactly one of them once already.
///
/// # Two consumers, and they are NOT the same question
///
/// It was named `GroupExemption` while §11 arm one was its only reader. It has a
/// second now, and the rename is the point rather than tidiness — both readers
/// are admissions that establish nothing about the SENDER, so both need the LINK
/// to have been settled by something else:
///
/// * §11 arm one's *"regardless of source IP address"* exemption
///   ([`Admit::MdnsGroup`]), which weighs no source at all. What it needs is
///   *"nothing here can be foreign"*;
/// * the seeded `fe80::/64` on-link prefix in `src_on_local_link`, which every
///   interface carries — so matching it says the sender is on SOME link and
///   never on OURS. What it needs is *"this datagram arrived on our link"*.
///
/// **Those two coincide everywhere except at a bound interface of zero**, which
/// is why there are three states and not two. A zero satisfies the first
/// vacuously — an endpoint that named no link can call nothing foreign — and
/// cannot satisfy the second at all, because there is no *our link* for a
/// datagram to have arrived on. Collapsing them handed the seed a proof nobody
/// produced; [`Self::Unbound`] is that distinction made unrepresentable.
///
/// A collected prefix needs neither, and deliberately so: `192.168.1.0/24` is a
/// prefix the BOUND interface reports, so matching it is §11's own *"apparently
/// on a local subnet"* evidence, weak and forgeable exactly as the RFC says and
/// specific to this link. `fe80::/64` is on every link there has ever been, so
/// it carries none of that and must not be read as if it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkProvenance {
  /// Something named the link and it agreed with the binding — a receive
  /// interface index, an IPv6 source's scope id, or a loopback-bound endpoint's
  /// own loopback traffic. The datagram arrived on the link this endpoint bound,
  /// as far as anything on this host can report, and BOTH consumers may read it.
  Established,
  /// This endpoint bound no interface (`iface() == 0`), so there is no link to
  /// scope to and nothing can be foreign to it. §11 arm one's exemption is
  /// granted — withholding it would take arm one away from every single-link
  /// caller forever in exchange for no scoping at all — and the seeded
  /// `fe80::/64` is NOT available, because a prefix that is on every link plus a
  /// binding that names no link is two absences, not a proof.
  ///
  /// It covers two callers this type cannot tell apart: one that binds no
  /// interface by construction (`hick-smoltcp`, `hick-embassy`) and one that
  /// could not resolve an index. Both get the conservative answer, and a caller
  /// that wants the seed earns it by naming its interface — which is a thing it
  /// can do, unlike proving to this crate that it is structurally single-link.
  Unbound,
  /// Nothing named the link, on an endpoint that bound one to scope to. The
  /// datagram is not refused on that account; it takes §11's source arm, and
  /// there only prefixes SPECIFIC to the bound interface may decide it.
  Unproven,
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
/// # Arm one's exemption is a PRIVILEGE, and it is scoped
///
/// Arm one admits with no test on anything the datagram carries about its
/// origin. Every other admission in this function weighs something — an address
/// this endpoint holds, a source inside a prefix it carries. So arm one is the
/// one place where "did this reach us on OUR link" is the entire remaining
/// question, and it is answered by the interface check above.
///
/// That check REFUSES a witness naming another link, and it deliberately does
/// not refuse an ABSENT one: a kernel that skipped a cmsg under mbuf pressure
/// must not take a responder off the air. Those two are not the same answer, and
/// collapsing them is what let a datagram with no link evidence take arm one.
/// So the check reports which of the two it was, and arm one is granted only on
/// the first. On the second the datagram takes §11's source arm instead
/// ([`Admit::UnscopedMdnsGroup`]) — admitted if it is on-prefix, refused if it
/// is not, which is the same rule a datagram with no destination witness takes.
///
/// **The destination is still read.** Withholding the exemption costs the
/// datagram arm one and nothing else: the negative arms below match the same
/// address and refuse a foreign group, a broadcast, a martian or a neighbour's
/// address by name exactly as they do when the exemption is granted. An earlier
/// attempt rewrote the destination witness itself at one receive path, which
/// erased the address along with the privilege and reopened every class those
/// arms close. The privilege and the classification are separate, and this is
/// where they are separated.
///
/// # Where the destination comes from, and why not `local_ip`
///
/// `destination` is
/// `hick-udp`'s `RecvMeta::destination_witness`, which reports what the receive
/// path witnessed about the IP header destination. It is NOT that type's
/// `local_ip`: on
/// Unix IPv4 that accessor deliberately returns `in_pktinfo.ipi_spec_dst`, the
/// receiving interface's own unicast address, because self-send detection on a
/// multi-homed host needs it — and a local unicast address never equals a group,
/// so every multicast arrival would read as "unicast" and go to the
/// source-prefix test §11 says must not decide it.
///
/// There is no branch that skips this reading, so getting it wrong is not a
/// corner case: every arrival on every target would take the source-prefix arm.
/// The BSD IPv4 squares reach it through `IP_RECVDSTADDR` rather than PKTINFO —
/// a bare `struct in_addr` with no `ipi_spec_dst` twin to confuse it with, so
/// `local_ip` is UNSPECIFIED there and this accessor is the only destination
/// there is. Where a kernel declines the cmsg for one datagram, OpenBSD and
/// NetBSD still have the coarse multicast flag to reach the group arm with, and
/// FreeBSD/DragonFly have nothing — against precisely the overlaid-subnet
/// multicast §11 calls "essential" to admit.
///
/// # Two regimes, and the contract differs between them
///
/// **[`DestinationWitness::Witnessed`].** The destination is matched against the two mDNS
/// groups and then against the addresses this endpoint holds. Anything else
/// takes no §11 arm and is REFUSED — a foreign multicast group, an IPv4
/// broadcast in any form, a martian, the unspecified address, a neighbour's
/// address on our own subnet — and [`Refuse`] names which. That guarantee is
/// this function's, in full, for every driver on a square that witnesses a
/// destination, and it does NOT depend on the interface witness: an unscoped
/// datagram loses arm one's exemption and keeps every one of these refusals.
///
/// **[`DestinationWitness::Blind`] and [`DestinationWitness::Declined`].** None of the above holds,
/// and this is a promise this function does not make there. `MSG_MCAST` stands
/// in on the OpenBSD/NetBSD square and answers "some group" rather than which, so
/// a foreign group is admitted with no source test at all; everywhere else an
/// IPv4 broadcast is indistinguishable from a unicast and is admitted for an
/// in-prefix source. [`Admit::BlindSourceOnLink`] is what makes an admission
/// there countable.
///
/// **[`DestinationWitness::Lost`].** Refused outright: our own control buffer was too
/// small, which is a defect on this side rather than a fact about the sender.
///
/// A caller that needs the first regime's guarantee must be on a square that
/// witnesses a destination; see the capability table in this module's header for
/// which those are, and what closes the rest.
pub fn admits_ingress(
  src: SocketAddr,
  destination: DestinationWitness,
  delivery: Option<LinkDelivery>,
  link: BoundLink<'_>,
  iface: IfaceWitness,
) -> Verdict {
  // Ours: scope "the local link" to the link this endpoint bound. §11 does not
  // prescribe it, but its unicast arm is defined over "the interface receiving
  // the packet", so the RFC's test is already interface-scoped — this is what
  // makes that model enforceable for a wildcard-bound socket on a multi-homed
  // host.
  // Read ONCE and carried to every arm that needs it. Two admissions rest on it
  // — §11 arm one's source exemption, and the seeded `fe80::/64` in
  // `src_on_local_link` — and they must not be able to disagree about what
  // established this datagram's link. See [`LinkProvenance`].
  let provenance = match arrived_on_bound_interface(src, link, iface) {
    Ok(provenance) => provenance,
    Err(refusal) => return Verdict::Refuse(refusal),
  };
  // §11 partitions by DESTINATION and names exactly two kinds. Each arm below
  // says what a destination IS. Nothing here is spelled as "everything that is
  // not one of the classes named above", which is the shape that admitted a
  // foreign multicast group, then an IPv4 limited broadcast, then a directed
  // one, then an operator-configured broadcast address — four rounds of
  // subtracting one more class from a residual that kept another.
  match destination {
    // Arm one, verbatim: "necessarily deemed to have originated on the local
    // link, regardless of source IP address" — and it is granted only to a
    // datagram something SCOPED to this endpoint's link.
    //
    // The exemption is the one admission in this boundary that tests nothing
    // about where the datagram came from. §11 grants it unconditionally; what
    // makes it safe HERE is this crate's scoping of it to the bound link, so a
    // datagram nothing scoped has not earned it. Withholding is not refusing:
    // the datagram falls to §11's source arm, the same test it would take with
    // no destination at all, and every NEGATIVE arm below still reads the
    // address — a foreign group and a broadcast are refused by name whichever
    // way this goes.
    //
    // Stated over the WITNESS PAIR rather than over any receive path's cmsg
    // shape. The pair arises on the BSD `IP_RECVDSTADDR`/`IP_RECVIF` split, on
    // a Linux/Apple `IP_PKTINFO` carrying a zero `ipi_ifindex`, and on
    // `IPV6_PKTINFO` the same way; a rule written at one decoder would have
    // closed one of those and left the others standing, which is what happened.
    // `Unbound` grants it exactly as `Established` does, and for a reason that
    // is about arm one rather than about evidence: an endpoint that named no
    // link cannot call this datagram's link foreign. It is spelled out rather
    // than folded in because the SEED reads the same value and must not treat
    // the two alike — see [`LinkProvenance`].
    DestinationWitness::Witnessed(dst) if is_mdns_group(dst) => match provenance {
      LinkProvenance::Established | LinkProvenance::Unbound => Verdict::Admit(Admit::MdnsGroup),
      LinkProvenance::Unproven => unscoped_group_arm(src, delivery, link, iface, provenance),
    },
    // Arm two: §11 scopes its source comparison to a response "received via
    // unicast", and a datagram received via unicast BY US is one addressed to
    // an address of ours. So the destination is matched against the receiving
    // interface's own configuration, which is the same configuration the
    // source is about to be matched against.
    DestinationWitness::Witnessed(dst) if is_bound_address(dst, link) => source_arm(
      src,
      link,
      iface,
      provenance,
      Admit::HeldDestination,
      Refuse::SourceOffLink,
    ),
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
    // **The fallback is for the class the missing snapshot would have decided,
    // and for no other.** A failed enumeration is ignorance about which
    // addresses THIS HOST HOLDS. It is not ignorance about what an address IS,
    // and the two were conflated here: every witnessed destination was deferred,
    // so an empty snapshot turned `ff02::1` — the all-nodes group, which §11
    // gives no arm and which no enumeration was ever consulted about — into
    // protocol input for any source the arm went on to admit.
    //
    // So the destination is CLASSIFIED first, and only [`Refuse::DestinationNotHeld`]
    // — the residual, meaning "syntactically a unicast address, and whether it
    // is one of ours is exactly what we could not read" — is deferred. Every
    // class `classify_unheld` NAMES is decided from the address and the binding
    // alone: a foreign group, the limited broadcast, the unspecified address, an
    // IPv4-mapped one, a `127/8` destination on a NIC-bound endpoint. None of
    // them needs the snapshot, so none of them may be excused by its absence.
    //
    // This is strictly NARROWING and that is what makes it safe to reorder a
    // trust boundary's arms: the old arm deferred every class to `source_arm`,
    // the new one defers a subset, and the classes it stops deferring are
    // refused rather than admitted. The exhaustiveness of `classify_unheld` is
    // therefore load-bearing here in one direction only — a class nobody has
    // named yet lands in the residual and is deferred, which is what ALL of them
    // did before.
    //
    // What remains admissible is the fallback's whole point, and the bound is
    // exact: a loopback source for a loopback-BOUND endpoint that also passed
    // stage 1 — the endpoint whose interface a driver is most likely to fail to
    // enumerate, and the shape every loopback fixture in this workspace runs on
    // — plus an IPv6 source inside the seeded `fe80::/64`, which needs
    // `LinkProvenance::Established` and so is not the blind square's to take.
    // Every other source is refused outright, because the COLLECTED comparison
    // has nothing in it to match.
    //
    // A STALE snapshot is a different case and gets no exception: non-empty
    // means the enumeration succeeded, so a destination missing from it is a
    // real "not ours" until the next refresh. That fails closed for at most
    // `SUBNET_REFRESH_INTERVAL` and heals itself; see this module's header.
    DestinationWitness::Witnessed(dst) if link.local_addrs().is_empty() => {
      match classify_unheld(dst, link) {
        Refuse::DestinationNotHeld => source_arm(
          src,
          link,
          iface,
          provenance,
          Admit::UnenumeratedDestination,
          Refuse::SourceOffLink,
        ),
        named => Verdict::Refuse(named),
      }
    }
    // §11 offers no arm for any other destination, and this is a trust
    // boundary, so it is refused rather than handed to the arm next door.
    // `classify_unheld` runs strictly AFTER that decision and only names which
    // class it was; it cannot change the verdict, and the refusal above does not
    // depend on the naming being exhaustive.
    DestinationWitness::Witnessed(dst) => Verdict::Refuse(classify_unheld(dst, link)),
    // Our own control buffer was too small. The kernel HAD the destination and
    // this side could not take it: a defect report rather than evidence about
    // the sender, and the one absence that fails closed. `recv_with_meta` sizes
    // its buffer so this cannot be provoked from the wire — see `DestinationWitness::Lost`.
    DestinationWitness::Lost => Verdict::Refuse(Refuse::DestinationWitnessLost),
    // ── A DIFFERENT REGIME STARTS HERE ────────────────────────────────────
    //
    // No destination witnessed. Either this path never witnesses one — see the
    // capability table in this module's header for which squares those are — or
    // the kernel declined to emit the cmsg for THIS datagram, which every BSD
    // does silently under mbuf pressure. The two are the same rule from here on
    // and differ only in what they are counted as.
    //
    // NOTHING IN THE `Witnessed` ARMS APPLIES HERE. The positive partition needs
    // a destination to be positive about; below there is none, so these arms are
    // a coarser rule with a residual of their own, and every claim this module
    // makes about refusing a destination it does not hold is a claim about the
    // `Witnessed` arms only.
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
    // only two where `libc` binds the flag. It closes nothing on
    // FreeBSD/DragonFly (no binding) or on `hick-compio`'s Windows square
    // (`recv_from` returns no `msg_flags` to read), and those keep it.
    //
    // It also leaves, on the very squares it does close, the foreign-group class
    // beside it: the multicast arm below admits ANY group from ANY source with
    // no prefix test, because "which group" is not a bit and no flag can carry
    // it. That is a reason those squares are not fully closed, not a reason to
    // leave a closable part of them open.
    //
    // The full closure is the destination itself; the one piece of work that
    // still reaches it is named once, in this module's header.
    DestinationWitness::Declined | DestinationWitness::Blind => match delivery {
      Some(LinkDelivery::Broadcast) => Verdict::Refuse(Refuse::BroadcastDelivery),
      Some(LinkDelivery::Multicast) => Verdict::Admit(Admit::BlindMulticastDelivery),
      // `Unicast` says only "neither of those", so the source arm still decides;
      // `None` is a target that binds no flag at all and says nothing.
      Some(LinkDelivery::Unicast) | None => source_arm(
        src,
        link,
        iface,
        provenance,
        Admit::BlindSourceOnLink,
        Refuse::SourceOffLink,
      ),
    },
  }
}

/// §11's source arm as a [`Verdict`]: `admit` when the source is on-link,
/// [`Refuse::SourceOffLink`] when it is not.
///
/// Four arms of [`admits_ingress`] end here and each supplies its OWN [`Admit`]
/// — a destination this endpoint holds, a snapshot that enumerated nothing, a
/// datagram with no destination witness, and an mDNS group nothing scoped to
/// this endpoint's link — because they are four different claims that happen to
/// share one test. Sharing the refusal is safe; sharing the admission would
/// erase the distinction the counters exist for.
///
/// `provenance` is carried rather than recomputed: it is [`LinkProvenance`], the
/// same value §11 arm one reads, and `src_on_local_link` needs it for the one
/// on-link prefix that is not specific to the bound interface. Passing it means
/// the two consumers cannot come to disagree about what established the link,
/// which is the whole reason that type has one producer.
fn source_arm(
  src: SocketAddr,
  link: BoundLink<'_>,
  iface: IfaceWitness,
  provenance: LinkProvenance,
  admit: Admit,
  refuse: Refuse,
) -> Verdict {
  if src_on_local_link(src, link, iface, provenance) {
    Verdict::Admit(admit)
  } else {
    Verdict::Refuse(refuse)
  }
}

/// What becomes of an mDNS-group destination whose link nothing scoped: the
/// SAME arm a datagram with no destination witness at all would have taken.
///
/// # Monotonicity, which is the whole reason this is not just `source_arm`
///
/// This square carries strictly MORE evidence than the square below it — the
/// group address itself, on top of whatever the coarse [`LinkDelivery`] says —
/// and a rule where more evidence produces a worse outcome for a legitimate peer
/// is incoherent whichever way it errs. Sending it straight to the source arm
/// did exactly that on OpenBSD and NetBSD: the destination-only datagram was
/// REFUSED for an off-prefix sender while the neither-cmsg datagram beside it was
/// ADMITTED on `MSG_MCAST`. An attacker who can make one cmsg go missing can make
/// both go missing, so that refusal stopped nobody who mattered and taxed the
/// off-prefix peers §11 calls essential in full.
///
/// This is NOT the rule that was rejected in the other direction — using a coarse
/// signal to grant what finer evidence just failed to earn. That rule is about
/// UPGRADING on worse information and it still holds: the exemption
/// ([`Admit::MdnsGroup`]) is not granted here, and the flag never buys arm one.
/// What the flag buys is exactly what it buys one arm down, no more, so this
/// square can never do worse than the less-informed square below it.
///
/// # It does not re-open the destination partition
///
/// Only a destination `is_mdns_group` reaches this function; the caller's guard
/// sees to that. A foreign multicast group, an IPv4 broadcast, a martian and a
/// neighbour's address are all still matched by the arms BELOW the caller's and
/// refused by name — [`Refuse::ForeignGroup`], [`Refuse::BroadcastAddressed`],
/// [`Refuse::DestinationNotHeld`] — with the coarse flag never consulted. The
/// flag admits "any group" only where no group was witnessed; here the group is
/// witnessed and it is ours.
///
/// # FreeBSD and DragonFly are not resolved by this
///
/// They bind no `MSG_MCAST`, so `delivery` is `None` there and this returns them
/// to the source test — which is where the availability residual lives, named in
/// this module's header and counted as
/// [`Refuse::UnscopedGroupSourceOffLink`].
/// # The seeded `fe80::/64` cannot be reached from here, by construction
///
/// This function is selected only when [`LinkProvenance::Unproven`] — that is
/// what "nothing scoped it" means — so the `provenance` it forwards is that
/// value and `src_on_local_link`'s seed is unreachable on this path. It is
/// forwarded rather than restated for exactly that reason: a literal here would
/// be a second place for the fact to be got wrong, and this is the path PR #88
/// spent four rounds establishing may not admit on anything but the bound
/// interface's own prefixes.
fn unscoped_group_arm(
  src: SocketAddr,
  delivery: Option<LinkDelivery>,
  link: BoundLink<'_>,
  iface: IfaceWitness,
  provenance: LinkProvenance,
) -> Verdict {
  match delivery {
    // Definitive NEGATIVE evidence, and it decides here for the same reason it
    // decides one arm down: §11 gives a link-layer broadcast no arm at all.
    Some(LinkDelivery::Broadcast) => Verdict::Refuse(Refuse::BroadcastDelivery),
    // The kernel says this was delivered to a group and the address says WHICH
    // group, and it is ours. That is not arm one — nothing scoped the link — but
    // it is exactly what the same flag is worth to the datagram beside this one.
    Some(LinkDelivery::Multicast) => Verdict::Admit(Admit::UnscopedMdnsGroup),
    // No flag, or one that says only "neither of those": §11's source arm, and
    // its refusal is named so the availability cost is measurable.
    Some(LinkDelivery::Unicast) | None => source_arm(
      src,
      link,
      iface,
      provenance,
      Admit::UnscopedMdnsGroup,
      Refuse::UnscopedGroupSourceOffLink,
    ),
  }
}

/// NAME the class of a witnessed destination this endpoint does not hold.
///
/// Nothing here has to be exhaustive to be safe: an unnamed class lands in
/// [`Refuse::DestinationNotHeld`], which is a refusal exactly like the named
/// ones. That is the whole reason it is safe to classify at all — four review
/// rounds found a class that a residual defined as "none of the above" had
/// absorbed, and the fix was to make the residual REFUSE rather than to keep
/// enumerating. This function does not reintroduce that shape; it only labels
/// what the refusal was about.
///
/// # Two callers, and the second one DECIDES on the answer
///
/// The refusal arm calls it to label a verdict already reached, and nothing it
/// returns can change that verdict. The EMPTY-SNAPSHOT arm calls it to ask a
/// different question: *would the missing enumeration have decided this?* Only
/// [`Refuse::DestinationNotHeld`] — the residual, and by construction the only
/// class whose membership turns on the addresses this host holds — is deferred
/// to the source arm there; every NAMED class is refused on the spot.
///
/// That works because every branch below reads the ADDRESS and, for the loopback
/// label, the BINDING — never [`BoundLink::local_addrs`]. So the names are
/// exactly the classes an empty snapshot leaves decidable, and the residual is
/// exactly the class it does not. **Any future class added here must keep that
/// property**: name it only if the address and the binding settle it, or the
/// empty-snapshot arm will start refusing something it cannot actually know.
/// Adding one that is snapshot-dependent fails closed rather than open, which is
/// the right direction for the mistake to run in but is still a mistake.
///
/// The loopback label is scoped to the BINDING, not to the address, exactly as
/// `is_bound_address` decides it: a `127/8` destination on a real NIC is a
/// martian, and Linux's `route_localnet` makes it deliverable by an adjacent
/// spoofer, so the binding is what the label — like the decision — turns on.
fn classify_unheld(dst: IpAddr, link: BoundLink<'_>) -> Refuse {
  match dst {
    IpAddr::V4(a) => {
      if a.is_loopback() && !link.is_loopback() {
        Refuse::LoopbackDestinationOffLoopbackBinding
      } else if a.is_unspecified() {
        Refuse::UnspecifiedDestination
      } else if a == Ipv4Addr::BROADCAST {
        // RFC 919's limited broadcast, and the only broadcast an address names
        // by itself. A subnet-directed one needs arithmetic over a prefix, which
        // `is_bound_address` documents as wrong in three separate directions, so
        // it is deliberately left to the residual.
        Refuse::BroadcastAddressed
      } else if a.is_multicast() {
        Refuse::ForeignGroup
      } else {
        Refuse::DestinationNotHeld
      }
    }
    IpAddr::V6(a) => {
      if a.is_loopback() && !link.is_loopback() {
        Refuse::LoopbackDestinationOffLoopbackBinding
      } else if a.is_unspecified() {
        Refuse::UnspecifiedDestination
      } else if a.to_ipv4_mapped().is_some() {
        // BEFORE the multicast test, and that ordering is the point:
        // `::ffff:224.0.0.251` is not `Ipv6Addr::is_multicast`, so an
        // unclassified v4-mapped address would be an mDNS group wearing a shape
        // no test here recognises. `IPV6_V6ONLY` keeps it off this workspace's
        // sockets, which is a reason to name it rather than a reason to let it
        // fall into a terminal bucket by accident.
        Refuse::Ipv4MappedDestination
      } else if a.is_multicast() {
        Refuse::ForeignGroup
      } else {
        Refuse::DestinationNotHeld
      }
    }
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
/// back delivers it with a destination an interface enumeration never reports:
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
/// `hick-udp`'s `collect_local_subnets` stores what `getifs` reports for each interface
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
/// which they join the collected snapshot and this function needs no change.
/// Until then a locally delivered anycast destination takes no §11 arm and is
/// refused. See `hick-udp`'s `collect_local_subnets`.
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

/// §11's **unicast** arm — PRIVATE, and deliberately so.
///
/// It is one stage of a sequence and is correct only when reached through
/// `admits_ingress`, which has already settled which link the datagram arrived
/// on. Called directly it ignores `iface` for every source but loopback, so a
/// foreign-scoped `fe80::` peer with a matching `fe80::/64` prefix would come
/// back `true`. The hoist made it public by accident; a helper that only behaves
/// when someone else went first has no business on a crate's surface.
///
/// Trust a source that falls inside a prefix the bound interface treats as
/// on-link. That is the caller-supplied list, plus `fe80::/64`, which RFC 5942
/// §3 and RFC 4861 put on every interface's Prefix List permanently and which is
/// therefore seeded here rather than collected — and which, for that same
/// reason, decides only when `provenance` is [`LinkProvenance::Established`].
/// See the body for why a prefix that is on every link cannot stand in for
/// knowing which link this was.
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
/// nothing to answer from — and only for a destination whose class the snapshot
/// would have decided; see the arm that takes it in [`admits_ingress`]. This
/// function is what bounds that fallback, and the bound has exactly two members:
/// the loopback arm below admits a loopback-BOUND endpoint's own traffic, and
/// the `fe80::/64` seed admits an IPv6 link-local source on a link stage 1
/// established. The collected comparison still admits nothing, because there is
/// nothing in it to match.
///
/// The loopback arm below keeps its own copy of the interface check anyway:
/// this is the trust boundary, it costs one integer comparison, and a caller
/// that reaches this function by some other route must not silently lose it. It
/// delegates to `arrived_on_bound_interface` rather than restating the rule,
/// so the copy cannot become a weaker copy — a bare `pkt_iface` test admits a
/// link-local source carrying a foreign scope id. The seed keeps no such copy
/// and needs none: it is a prefix comparison like the collected ones, and stage
/// 1 is the only thing in this rule that decides link membership.
///
/// A loopback source answers to the same link evidence as a link-local one, for
/// the reason `arrived_on_bound_interface` gives: the source address alone is
/// forgeable onto a real NIC wherever an operator has stopped treating `127/8`
/// as martian, so only a loopback-BOUND endpoint is exempt from proving where
/// its traffic came from.
fn src_on_local_link(
  src: SocketAddr,
  link: BoundLink<'_>,
  iface: IfaceWitness,
  provenance: LinkProvenance,
) -> bool {
  let ip = src.ip();
  // Link-local is not classified by its WITNESS here, and that is the third arm
  // §11 does not have — a matching receive index or scope id admitting a source
  // on its own. It is classified by its PREFIX, below, like every other source;
  // what is special about `fe80::/64` is only that the prefix is on the
  // interface unconditionally, which is a fact about IPv6 and not about this
  // datagram.
  if ip.is_loopback() {
    // Our own traffic, and only for the endpoint whose link the loopback
    // interface actually IS. To anyone else a loopback source is not evidence
    // of anything — it is an address a sender wrote, deliverable onto a real
    // NIC wherever an operator has stopped treating `127/8` as martian.
    // Whether a witness contradicts it is `arrived_on_bound_interface`'s
    // question, asked there rather than restated here.
    // `is_ok` and not a test on the exemption: this asks only whether the link
    // evidence REFUSED. Whether §11 arm one's source exemption was earned is a
    // question for the destination arms, and a loopback source is being weighed
    // here precisely because it did not take one of them.
    return link.is_loopback() && arrived_on_bound_interface(src, link, iface).is_ok();
  }
  // `fe80::/64` is on-link on EVERY interface, and this is the one entry of the
  // on-link list that is a constant of the IPv6 subnet model rather than
  // something a caller collected. RFC 5942 §3: *"In IPv6, by default, a host
  // treats only the link-local prefix as on-link."* RFC 4861's Prefix List
  // definition says how long for: *"The link-local prefix is considered to be on
  // the prefix list with an infinite invalidation timer regardless of whether
  // routers are advertising a prefix for it."*
  //
  // So this is not a third arm and not a witness talking. It is §11's second arm
  // — the source against *"the on-link prefixes on the interface receiving the
  // packet"* — run against a prefix that is on that interface unconditionally.
  //
  // # And it is exactly why the LINK has to have been established first
  //
  // "On the interface receiving the packet" is half the sentence, and this
  // prefix is the one place the two halves come apart. Every other entry in the
  // list is a prefix the BOUND interface reports, so matching one is evidence
  // about THIS link — weak and forgeable, which §11 knows and accepts.
  // `fe80::/64` is on every link there has ever been, so matching it is evidence
  // that the sender is on SOME link and none whatever that it is ours. Consulted
  // without [`LinkProvenance`], it would admit a datagram that arrived on
  // another NIC of this same host, on a blind or degraded path, purely for being
  // link-local — and RFC 4291's no-forwarding rule does not save that, because
  // no router is involved in a datagram delivered to the wrong interface of the
  // machine it was addressed to.
  //
  // `Unproven` therefore falls THROUGH to the collected comparison below rather
  // than refusing: the seed is an addition to §11's second arm and never a
  // subtraction from it, so an unprovenanced datagram decides exactly as it did
  // before this prefix existed. That is what keeps PR #88's squares as #88 left
  // them — the unscoped-group path is `Unproven` by construction, so it cannot
  // reach this at all.
  //
  // A witnessed link-local source with no matching prefix is STILL refused when
  // its address is not link-local, and a link-local source on a foreign link is
  // still refused by stage 1, which is where link membership is decided.
  //
  // # Why this is not read out of `onlink_prefixes` instead
  //
  // It used to be, by accident. An interface holding a link-local address makes
  // `getifs` report `fe80::<iid>` with the prefix length the platform assigned
  // it, and on the machines this was tried on that length was 64 — so the
  // comparison below matched link-local peers and nobody noticed the rule
  // depended on it. Three ways that fails: DHCPv6 and several stacks report a
  // host address as `/128`, in which case the comparison matches only the ONE
  // peer holding our own address; an interface with no link-local address of its
  // own reports no such prefix at all; and an enumeration that failed reports
  // nothing whatsoever. All three then refuse a link-local peer that the subnet
  // model says is on-link — a §11 unicast response, and a QU response in
  // particular, dropped for a reason the RFCs do not offer.
  //
  // It is also what RFC 5942 §4 rule 1 forbids inferring in the other direction:
  // *"The assignment of an IPv6 address … MUST NOT implicitly cause a prefix
  // derived from that address to be treated as on-link and added to the Prefix
  // List."* Deriving the link-local prefix from an assigned link-local address
  // is that inference, even where it happens to land on the right answer. The
  // seed here derives it from nothing.
  //
  // IPv4 gets no counterpart. RFC 5942 is an IPv6 document, `169.254.0.0/16` is
  // not on-link by default anywhere in IPv4's model, and an IPv4 host on such a
  // link holds a `169.254/16` address and so reports the prefix — see
  // `an_unwitnessed_ipv4_link_local_source_is_refused`.
  if matches!(provenance, LinkProvenance::Established)
    && addr_in_subnet(IpAddr::V6(LINK_LOCAL_V6_NET), LINK_LOCAL_V6_PREFIX_LEN, ip)
  {
    return true;
  }
  // EVERY other source — routable, IPv4 link-local, witnessed or not — answers
  // to §11's unicast test as the RFC states it: the source address against the
  // addresses and masks configured on the receiving interface, or its on-link
  // IPv6 prefixes.
  //
  // §11 has exactly two arms and this is the second of them. A witnessed
  // link-local source used to return here on the witness alone, which was a
  // THIRD arm the RFC does not have: it admitted `169.254.7.7` on an interface
  // configured only for `192.168.1.0/24`, where §11 requires the prefix
  // comparison for every non-group destination. A witness settles which LINK a
  // datagram arrived on — stage 1's question — and never whether its source
  // belongs to a prefix this interface carries. The seed above did not reinstate
  // that arm: it names a PREFIX, so `169.254.7.7` and a global IPv6 source are
  // refused there exactly as before, whatever witnessed them.
  //
  // IPv4 link-local is not excluded from the test either, in the other
  // direction: §11 names no exception for `169.254/16`, and an
  // infrastructure-less link is where mDNS is most load-bearing. A host there
  // holds a `169.254/16` address, so the prefix is configured and its peers
  // match it — which is why IPv4 needs no seed and does not get one.
  //
  // An empty subnet list makes this `false`, so a source with no matching
  // prefix is dropped — fail-CLOSED per §11. The seed above is the one thing
  // an empty list no longer silences, and it is bounded to `fe80::/64`.
  //
  // The residual is the same-prefix one: where nothing witnessed the link, a
  // second NIC sharing the prefix satisfies this legitimately and an adjacent
  // sender satisfies it by choosing an in-prefix source. See this module's
  // header.
  link
    .onlink_prefixes()
    .iter()
    .any(|&(net, pfx)| addr_in_subnet(net, pfx, ip))
}

#[cfg(test)]
mod tests;

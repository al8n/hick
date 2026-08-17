<div align="center">
<h1>hick-udp</h1>
</div>
<div align="center">

Cross-platform multicast UDP helpers for mDNS — synchronous, `std`-only.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/hick-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
<img alt="LoC" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fal8n%2F327b2a8aef9003246e45c6e47fe63937%2Fraw%2Fhick-udp" height="22">
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/hick/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/hick?style=for-the-badge&token=6R3QFWRWHL&logo=codecov" height="22">][codecov-url]

[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-hick--udp-66c2a5?style=for-the-badge&labelColor=555555&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/hick-udp?style=for-the-badge&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pg0KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDE5LjAuMCwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPg0KPHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCINCgkgdmlld0JveD0iMCAwIDUxMiA1MTIiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0yNTYsMEwzMS41MjgsMTEyLjIzNnYyODcuNTI4TDI1Niw1MTJsMjI0LjQ3Mi0xMTIuMjM2VjExMi4yMzZMMjU2LDB6IE0yMzQuMjc3LDQ1Mi41NjRMNzQuOTc0LDM3Mi45MTNWMTYwLjgxDQoJCQlsMTU5LjMwMyw3OS42NTFWNDUyLjU2NHogTTEwMS44MjYsMTI1LjY2MkwyNTYsNDguNTc2bDE1NC4xNzQsNzcuMDg3TDI1NiwyMDIuNzQ5TDEwMS44MjYsMTI1LjY2MnogTTQzNy4wMjYsMzcyLjkxMw0KCQkJbC0xNTkuMzAzLDc5LjY1MVYyNDAuNDYxbDE1OS4zMDMtNzkuNjUxVjM3Mi45MTN6IiBmaWxsPSIjRkZGIi8+DQoJPC9nPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPC9zdmc+DQo=" height="22">][crates-url]
[<img alt="crates.io" src="https://img.shields.io/crates/d/hick-udp?color=critical&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBzdGFuZGFsb25lPSJubyI/PjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCI+PHN2ZyB0PSIxNjQ1MTE3MzMyOTU5IiBjbGFzcz0iaWNvbiIgdmlld0JveD0iMCAwIDEwMjQgMTAyNCIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHAtaWQ9IjM0MjEiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkzIiB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj48ZGVmcz48c3R5bGUgdHlwZT0idGV4dC9jc3MiPjwvc3R5bGU+PC9kZWZzPjxwYXRoIGQ9Ik00NjkuMzEyIDU3MC4yNHYtMjU2aDg1LjM3NnYyNTZoMTI4TDUxMiA3NTYuMjg4IDM0MS4zMTIgNTcwLjI0aDEyOHpNMTAyNCA2NDAuMTI4QzEwMjQgNzgyLjkxMiA5MTkuODcyIDg5NiA3ODcuNjQ4IDg5NmgtNTEyQzEyMy45MDQgODk2IDAgNzYxLjYgMCA1OTcuNTA0IDAgNDUxLjk2OCA5NC42NTYgMzMxLjUyIDIyNi40MzIgMzAyLjk3NiAyODQuMTYgMTk1LjQ1NiAzOTEuODA4IDEyOCA1MTIgMTI4YzE1Mi4zMiAwIDI4Mi4xMTIgMTA4LjQxNiAzMjMuMzkyIDI2MS4xMkM5NDEuODg4IDQxMy40NCAxMDI0IDUxOS4wNCAxMDI0IDY0MC4xOTJ6IG0tMjU5LjItMjA1LjMxMmMtMjQuNDQ4LTEyOS4wMjQtMTI4Ljg5Ni0yMjIuNzItMjUyLjgtMjIyLjcyLTk3LjI4IDAtMTgzLjA0IDU3LjM0NC0yMjQuNjQgMTQ3LjQ1NmwtOS4yOCAyMC4yMjQtMjAuOTI4IDIuOTQ0Yy0xMDMuMzYgMTQuNC0xNzguMzY4IDEwNC4zMi0xNzguMzY4IDIxNC43MiAwIDExNy45NTIgODguODMyIDIxNC40IDE5Ni45MjggMjE0LjRoNTEyYzg4LjMyIDAgMTU3LjUwNC03NS4xMzYgMTU3LjUwNC0xNzEuNzEyIDAtODguMDY0LTY1LjkyLTE2NC45MjgtMTQ0Ljk2LTE3MS43NzZsLTI5LjUwNC0yLjU2LTUuODg4LTMwLjk3NnoiIGZpbGw9IiNmZmZmZmYiIHAtaWQ9IjM0MjIiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkwIiBjbGFzcz0iIj48L3BhdGg+PC9zdmc+&style=for-the-badge" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge&fontColor=white&logoColor=f5c076&logo=data:image/svg+xml;base64,PCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KDTwhLS0gVXBsb2FkZWQgdG86IFNWRyBSZXBvLCB3d3cuc3ZncmVwby5jb20sIFRyYW5zZm9ybWVkIGJ5OiBTVkcgUmVwbyBNaXhlciBUb29scyAtLT4KPHN2ZyBmaWxsPSIjZmZmZmZmIiBoZWlnaHQ9IjgwMHB4IiB3aWR0aD0iODAwcHgiIHZlcnNpb249IjEuMSIgaWQ9IkNhcGFfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgdmlld0JveD0iMCAwIDI3Ni43MTUgMjc2LjcxNSIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSIgc3Ryb2tlPSIjZmZmZmZmIj4KDTxnIGlkPSJTVkdSZXBvX2JnQ2FycmllciIgc3Ryb2tlLXdpZHRoPSIwIi8+Cg08ZyBpZD0iU1ZHUmVwb190cmFjZXJDYXJyaWVyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KDTxnIGlkPSJTVkdSZXBvX2ljb25DYXJyaWVyIj4gPGc+IDxwYXRoIGQ9Ik0xMzguMzU3LDBDNjIuMDY2LDAsMCw2Mi4wNjYsMCwxMzguMzU3czYyLjA2NiwxMzguMzU3LDEzOC4zNTcsMTM4LjM1N3MxMzguMzU3LTYyLjA2NiwxMzguMzU3LTEzOC4zNTcgUzIxNC42NDgsMCwxMzguMzU3LDB6IE0xMzguMzU3LDI1OC43MTVDNzEuOTkyLDI1OC43MTUsMTgsMjA0LjcyMywxOCwxMzguMzU3UzcxLjk5MiwxOCwxMzguMzU3LDE4IHMxMjAuMzU3LDUzLjk5MiwxMjAuMzU3LDEyMC4zNTdTMjA0LjcyMywyNTguNzE1LDEzOC4zNTcsMjU4LjcxNXoiLz4gPHBhdGggZD0iTTE5NC43OTgsMTYwLjkwM2MtNC4xODgtMi42NzctOS43NTMtMS40NTQtMTIuNDMyLDIuNzMyYy04LjY5NCwxMy41OTMtMjMuNTAzLDIxLjcwOC0zOS42MTQsMjEuNzA4IGMtMjUuOTA4LDAtNDYuOTg1LTIxLjA3OC00Ni45ODUtNDYuOTg2czIxLjA3Ny00Ni45ODYsNDYuOTg1LTQ2Ljk4NmMxNS42MzMsMCwzMC4yLDcuNzQ3LDM4Ljk2OCwyMC43MjMgYzIuNzgyLDQuMTE3LDguMzc1LDUuMjAxLDEyLjQ5NiwyLjQxOGM0LjExOC0yLjc4Miw1LjIwMS04LjM3NywyLjQxOC0xMi40OTZjLTEyLjExOC0xNy45MzctMzIuMjYyLTI4LjY0NS01My44ODItMjguNjQ1IGMtMzUuODMzLDAtNjQuOTg1LDI5LjE1Mi02NC45ODUsNjQuOTg2czI5LjE1Miw2NC45ODYsNjQuOTg1LDY0Ljk4NmMyMi4yODEsMCw0Mi43NTktMTEuMjE4LDU0Ljc3OC0zMC4wMDkgQzIwMC4yMDgsMTY5LjE0NywxOTguOTg1LDE2My41ODIsMTk0Ljc5OCwxNjAuOTAzeiIvPiA8L2c+IDwvZz4KDTwvc3ZnPg==" height="22">

</div>

## Introduction

`hick-udp` is the shared platform layer for the [hick] mDNS family. It sets up
the multicast UDP sockets mDNS needs and parses the ancillary data required to
answer correctly on multi-homed hosts. It does **no async** of its own: it
hands you a configured `std::net::UdpSocket`, and each async driver wraps that
in its own runtime-native socket type.

It provides:

- **Socket setup** — bind a multicast UDP socket to a chosen interface, join /
  leave the mDNS group (`224.0.0.251` / `ff02::fb`, port `5353`), and set
  TTL / multicast-loop / hop-limit options.
- **Interface selection** — enumerate the interfaces that can actually carry
  mDNS: `UP` **and** `RUNNING`, multicast-capable and non-loopback, and never a
  point-to-point cellular interface on Android. One endpoint per NIC is a
  single `interfaces::acceptable_mdns_interfaces()` call; the drivers' default
  interface picker applies the same rule via `interfaces::interface_tier()`,
  with loopback kept only as its last-resort fallback
  (`interfaces::is_loopback_fallback_interface`).
- **Ancillary parsing** — recover the local address a datagram arrived on via
  `IP_PKTINFO` / `IPV6_PKTINFO`, plus TTL / hop-limit / timestamp control
  messages, through `recv_with_meta`.
- **Sync wrappers** — `MulticastSocketV4` / `MulticastSocketV6` for callers
  that don't need an async runtime at all.

Cross-platform across Linux, macOS, the BSDs, and Windows; a `build.rs`
capability matrix gates the platform-specific `cmsg` paths.

## Platform capabilities

mDNS sockets are wildcard bound — they must be, to receive traffic addressed to
a multicast group rather than to an address — so on a multi-homed host every
NIC's port-5353 traffic is delivered to them. Answering only for the interface
you chose therefore depends on the kernel reporting **which** interface each
datagram arrived on, and not every platform can.

`reports_rx_interface_v4()` and `reports_rx_interface_v6()` state that per
family, at compile time:

| Target | IPv4 receive interface | IPv6 receive interface |
|---|---|---|
| Linux, Android | yes (`IP_PKTINFO`) | yes (`IPV6_PKTINFO`) |
| macOS, iOS, tvOS, watchOS, visionOS | yes (`IP_PKTINFO`) | yes (`IPV6_PKTINFO`) |
| Windows | yes (`IP_PKTINFO` via `WSARecvMsg`) | yes (`IPV6_PKTINFO`) |
| FreeBSD, DragonFly, OpenBSD, NetBSD | yes (`IP_RECVDSTADDR` + `IP_RECVIF`) | yes (`IPV6_PKTINFO`) |

Every supported target, in both families, and the last row gets there by a
different spelling rather than by `IP_PKTINFO`: FreeBSD, DragonFly and OpenBSD
do not define that option at all, and NetBSD's `in_pktinfo` is a different
8-byte layout that the shared parser reads as truncated. All four instead emit
the IP header destination as a bare `struct in_addr` under `IP_RECVDSTADDR` and
the receiving interface as a `struct sockaddr_dl` under `IP_RECVIF`.
`try_bind_v4` enables the pair and `multicast::parse_dstaddr_recvif_v4` reads
it, behind the `has_ip_dstaddr_recvif` capability cfg. NetBSD takes that pair
rather than its own `IP_RECVPKTINFO` deliberately: its `ip_savecontrol` emits
`IP_RECVDSTADDR` before the early return for a detached receive interface and
`IP_PKTINFO` after it, so the pair still witnesses the destination exactly where
the single cmsg witnesses nothing. `multicast::parse_netbsd_pktinfo_v4` stays
compiled and unwired for that reason.

**Setup fails; a missing control message only degrades.** The two are worth
keeping apart, because only one of them is loud.

A `setsockopt` that returns an error fails the bind — `try_bind_v4` /
`try_bind_v6` propagate it rather than continuing best-effort. On the four BSDs
the pair is additionally read back with `getsockopt` on every bind
(`verify_rx_dstaddr_recvif_v4`), and a zero for either option fails the bind
too: that is the false success no return code would show, and DragonFly, OpenBSD
and NetBSD have no CI runner anywhere in this workspace, so the read-back is what
stands in for execution on them. `build.rs` records, at the
`has_ip_dstaddr_recvif` emit site, the four evidence items the capability rests
on and where each has run.

A datagram that arrives with **no control message at all** is a different thing,
and it does **not** fail closed. `recv_with_meta` reports it as a `Declined`
witness, and `hick-onlink`'s rule treats `Declined` exactly like `Blind`: it
passes the interface stage and takes the residual arm — the kernel's
`LinkDelivery` class where the target reports one, and RFC 6762 §11's
source-prefix rule otherwise. The isolation **degrades** for that datagram; it is
not refused. That is deliberate: every BSD builds its ancillary mbufs with
`M_NOWAIT` and skips the cmsg with no error, no counter and no truncation flag
when the allocation fails, so refusing there would take a responder off the air
during exactly the flood that caused the shortage. The one absence that *does*
refuse is `Lost` — `MSG_CTRUNC`, meaning the kernel had the fact and **our**
buffer could not hold it — and `CmsgBuf` is sized (512 bytes against a worst case
near 152) so that flag is a defect report rather than something the wire can
provoke.

Those two facts together are why the enable is checked rather than assumed. An
enable that failed silently would **not** make the responder deaf. It would cost
a **refusal**, permanently and quietly, while the endpoint went on answering —
and which refusal depends on which option went missing, because the BSD row is
two cmsgs rather than one:

| lost | destination | interface | what stops refusing |
|---|---|---|---|
| `IP_PKTINFO` / `IPV6_PKTINFO` (one cmsg) | `Declined` | `Declined` | the interface stage *and* the whole destination partition |
| `IP_RECVDSTADDR` only | `Declined` | still witnessed | `ForeignGroup`, `BroadcastAddressed`, `DestinationNotHeld`, … — `ForeignLink` still works |
| `IP_RECVIF` only | still witnessed | `Declined` | `ForeignLink` for IPv4 — every destination refusal still fires |

None of those is "isolating nothing", and none is silent: an IPv6 peer's scope id
remains a second interface witness, and the drivers count every degraded
admission on `ingress_witness_declined`. What survives on the destination side
depends entirely on the kernel's coarse delivery class, so it is enumerated
rather than summarised — a general sentence here has been wrong three times:

| kernel `LinkDelivery` | where it occurs | verdict with no destination witness |
|---|---|---|
| `Broadcast` | OpenBSD / NetBSD only (`MSG_BCAST`) | **refused**, `BroadcastDelivery` |
| `Multicast` | OpenBSD / NetBSD only (`MSG_MCAST`) | **admitted**, `BlindMulticastDelivery` — any source, any group, and the source arm never runs |
| `Unicast` | OpenBSD / NetBSD only | source arm — `SourceOffLink` refuses an out-of-prefix source |
| absent (`None`) | every other supported target | source arm — `SourceOffLink` refuses an out-of-prefix source |

The `Multicast` row is the one that keeps catching people out: `admits_ingress`
answers it immediately, so an out-of-prefix multicast source is **admitted** and
`SourceOffLink` never gets a say.

What justifies failing the bind is narrower than any of that and still enough:
losing **either** witness dimension is a permanent, per-socket loss of half the
trust boundary that no return code reported, and the read-back is the only thing
that sees it.

## Installation

```toml
[dependencies]
hick-udp = "0.5"
```

## Feature flags

| Feature | Description |
|---------|-------------|
| `tracing` | Emit `tracing` warn events on socket bind or multicast-join failures. |
| `stats` | Enable `hick-trace` stats counters (forwarded from the driver layer; `no_std`-safe). |
| `metrics` | Bridge stats counters to the [`metrics`] facade. Implies `stats`. |
| `test-support` | Expose the self-send tracker's clock seams so a *dependent* crate's tests can place a claim or a loop top without sleeping to it. Belongs in `dev-dependencies`; a shipped build must not enable it, or a caller could hand the tracker a clock reading taken somewhere other than the decision it feeds. |

## Observability

When `tracing` is enabled, `hick-udp` emits `WARN`-level `tracing` events
when a socket bind or multicast group join fails. These help diagnose
interface-selection and permission issues without requiring a debugger.

## The hick family

[`hick`] (facade) · [`mdns-proto`] (Sans-I/O core) · **`hick-udp`** (this crate)
· [`hick-reactor`] (tokio / smol driver) · [`hick-compio`] (compio driver) ·
[`hick-smoltcp`] (smoltcp engine) · [`hick-embassy`] (embassy driver).

## License

`hick-udp` is under the terms of both the MIT license and the Apache License
(Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2025 Al Liu.

[`hick`]: https://crates.io/crates/hick
[`mdns-proto`]: https://crates.io/crates/mdns-proto
[`hick-reactor`]: https://crates.io/crates/hick-reactor
[`hick-compio`]: https://crates.io/crates/hick-compio
[`hick-smoltcp`]: https://crates.io/crates/hick-smoltcp
[`hick-embassy`]: https://crates.io/crates/hick-embassy
[`metrics`]: https://crates.io/crates/metrics
[hick]: https://github.com/al8n/hick
[Github-url]: https://github.com/al8n/hick/
[CI-url]: https://github.com/al8n/hick/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/hick/
[doc-url]: https://docs.rs/hick-udp
[crates-url]: https://crates.io/crates/hick-udp

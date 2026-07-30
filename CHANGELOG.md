# RELEASED

## Dual-stack partial delivery (`TransmitOutcome`) (July 30th, 2026)

Published crates: `mdns-proto` 0.4.0, `hick` 0.3.0, `hick-reactor` 0.3.0,
`hick-compio` 0.3.0, `hick-smoltcp` 0.3.0, `hick-embassy` 0.3.0.

`mdns-proto`'s confirm APIs took a single boolean doing two jobs — advancing
the RFC 6762 lifecycle phase (§8.1 probing / §8.3 announcing, plus the §5.2
query retry budget) and latching §10.1 TTL=0 goodbye ownership — which is
unsound the moment a dual-stack multicast transmit succeeds on one address
family and fails on the other: there is no truthful bool to pass. This release
replaces the boolean with a lossless three-way outcome and fixes the resulting
conformance and stranding defects in every released async driver.

BREAKING

- `mdns-proto`: new `TransmitOutcome` enum (`AllDelivered` / `PartiallyDelivered`
  / `NoneDelivered`) reports the shape of a multicast fan-out instead of
  collapsing it to one bool. `Service::note_transmit_outcome` /
  `Query::note_transmit_outcome` / `Endpoint::note_query_transmit_outcome` are
  now the sole confirm entry points; the boolean shims they were added
  alongside — `note_transmit_result` (on both `Service` and `Query`) and
  `Endpoint::note_query_transmit_result` — are removed. Lifecycle phase and the
  query retry budget now advance only on `TransmitOutcome::all_delivered()`;
  goodbye ownership latches on the weaker `any_delivered()` — the two facts a
  single bool could never carry independently, and exactly where the removed
  boolean API was unsound for a dual-stack send.
- `mdns-proto`: new `FullyAnnounced` newtype (opaque; no public constructor)
  replaces the raw `bool` parameter of the reclaim-cancel confirm, which is
  renamed `Endpoint::note_service_announced` (from `note_service_advertised`,
  removed). The old bool's meaning had drifted to "the all-delivered
  announcement fact," but nothing stopped a driver from passing the
  any-delivered exposure latch (`Service::advertises_instance()`) instead —
  which every released driver did, until this release (see FIXES).
  `FullyAnnounced` has no public constructor, so that substitution no longer
  compiles. The token also carries the `ServiceHandle` it was minted from and
  `note_service_announced` takes no separate handle, so one service's proof
  cannot be applied to another (which would cancel that other name's goodbye
  while an obligated family still needed it).
- `mdns-proto`: new `TransmitObligation` enum (`Sustained` / `OneShot`), carried
  on every `Transmit` and readable via `Transmit::obligation()`;
  `Transmit::new` takes it as a fourth argument. It states whether the core will
  re-arm that datagram until every obligated link accepts it, and a driver's
  bounded obligation policy applies to `Sustained` datagrams only. The tag is a
  function of what was encoded, not of the service's lifecycle phase: the
  periodic `Established` re-announce advances no phase yet is still re-armed on
  the §8.3 ladder, and `Query::poll_transmit` has no service phase at all.
- A driver capable of reporting `PartiallyDelivered` **must** implement a
  bounded obligation policy (write-off / degradation of the missing family) —
  normative on `TransmitOutcome`'s rustdoc. All four drivers in this workspace
  ship one (see FIXES).

FIXES (dependent-crate behaviour; visible without any source change on the
caller's part)

- All four drivers (`hick-reactor`, `hick-compio`, `hick-smoltcp`,
  `hick-embassy`): a partially-delivered dual-stack transmit no longer advances
  the §8.1 probe sequence or the §8.3 announce phase, and no longer burns a
  §5.2 query retry. Previously any single successful socket send (e.g. IPv4
  only) advanced the lifecycle even though the other family was never probed —
  an RFC 6762 §8.1 conformance defect. A service on a host where one family is
  unreachable now takes longer to establish instead of establishing a name it
  never defended on that family.
- All four drivers: the reclaim-cancel gate is now the all-delivered
  announcement fact, not any single delivery. A replacement service reclaiming
  a renamed-away name no longer cancels that name's still-draining TTL=0
  goodbye until it has announced on every family the driver still obligates —
  previously a single-family announcement, or even an RFC 6762 §6.7 legacy
  unicast reply, could cancel it. Fixes stranded peers on the unserved family
  holding withdrawn records until positive TTL.
- All four drivers: new bounded-obligation policy — after two consecutive
  partially-delivered fan-outs for the same service or query, the third
  excuses the still-missing families for that one confirm so the phase
  advances anyway. A permanently half-reachable link now still reaches
  `Established` (at roughly 3x the round count) instead of pinning in probing
  forever.
- All four drivers: the bounded-obligation counter now sees lifecycle datagrams
  only. Responses (the §6 multicast reply, the §6.7 legacy unicast reply, the
  RFC 6763 §9 meta reply) are never re-armed, so feeding their confirms to the
  counter corrupted it in both directions: a unicast reply has one obligated
  family and is all-delivered by construction, so it RESET the counter — a
  service answering legacy queriers between lifecycle rounds held it at zero and
  the bound never fired, pinning the service on a chronically half-broken link;
  and a partially-delivered multicast response PRELOADED it, so the next partial
  probe was excused and §8.1 advanced although one family never heard the probe.
  Drivers also clear the counter when they observe `ServiceUpdate::Renamed`,
  mirroring the core's own rename reset of its §8.3 partial-announce ladder.
- `hick-smoltcp` / `hick-embassy`: a PRESENT but unbound (or unaddressable) UDP
  socket is now `SendError::Busy`, not `SendError::Unsupported`. `Unsupported`
  removes a family from the obligated set, so a bound-IPv4 + present-but-unbound
  -IPv6 fan-out projected to `AllDelivered` and advanced §8.1 probing as though
  the node had no IPv6 at all. It now projects to `PartiallyDelivered` and the
  family is retried.
- `hick-reactor` / `hick-compio` only: RFC 6762 §6.7 legacy unicast replies no
  longer record a self-send credit. A unicast reply never loops back to its
  sender, so the credit could never be consumed; under a legacy-query flood
  the 65,536-entry tracker filled with dead entries and began refusing genuine
  multicast credits, causing the responder to ingest its own loopback as peer
  traffic.

The dependent crates (`hick`, `hick-reactor`, `hick-compio`, `hick-smoltcp`,
`hick-embassy`) bump to 0.3.0 to track the `mdns-proto` 0.4 public dependency;
`hick-udp` and `hick-trace` are unaffected.

## Drop the `heapless` tier (June 8th, 2026)

Published crates: `mdns-proto` 0.3.0, `hick` 0.2.0, `hick-reactor` 0.2.0,
`hick-compio` 0.2.0, `hick-smoltcp` 0.2.0, `hick-embassy` 0.2.0.

BREAKING

- Removed `mdns-proto`'s `heapless` feature and its no-allocator owned-storage
  tier. Owning variable-length protocol data without an allocator is inherently
  either fat (a fixed `heapless::String<255>` inline per name) or complex (an
  in-buffer sub-allocator), so the rule is now simply: **owning a `Name` /
  `ServiceSpec` and building messages requires an allocator** (`alloc` / `std` /
  `no-atomic`); the bare `--no-default-features` tier is **parse-only** (the
  borrowed `wire::NameRef`). This drops the large fixed-capacity inline structs
  that were a poor fit for `no_std` stack budgets.
- As a result the internal `cfg_storage` / `cfg_heap` macro split collapses
  (both predicates are now `any(alloc, std, no-atomic)`), and `Name`,
  `QuerySpec`, `ServiceUpdate`, and `MessageBuilder` are gated on the allocator
  tiers.

The dependent crates (`hick`, `hick-reactor`, `hick-compio`, `hick-smoltcp`,
`hick-embassy`) bump to 0.2.0 to track the `mdns-proto` 0.3 public dependency.
`hick-udp` and `hick-trace` are unaffected.

## Bare-metal no-atomic tier (June 6th, 2026)

Published crates: `mdns-proto` 0.2.1, `hick` 0.1.1, `hick-smoltcp` 0.1.1,
`hick-embassy` 0.1.1.

Support for bare-metal cores **without native atomic CAS** (Cortex-M0+ /
thumbv6m / RP2040), fixing a build failure on those targets (#40). The default
`atomic` tier is unchanged, so existing builds are unaffected.

FEATURES

- `mdns-proto` gains a `no-atomic` storage tier: the same alloc-backed
  `Endpoint`, but the refcounted `Name` / rdata use `portable-atomic`'s `Arc`
  (cheap clone via a `critical-section` impl the binary provides) instead of
  `smol_str` + `bytes`, which require native pointer-width atomics.
- `hick-smoltcp` and `hick-embassy` gain `atomic` (default) vs `no-atomic`
  feature tiers. Build for RP2040-class targets with
  `--no-default-features --features no-atomic`.
- The `hick` facade gains `smoltcp-no-atomic` / `embassy-no-atomic` features
  that reach the no-atomic tier through the umbrella crate.

FIXES

- `hick-embassy` and the rest of the bare-metal stack now build for
  `thumbv6m-none-eabi`; previously `mdns-proto`'s alloc tier pulled `smol_str`
  (`alloc::sync::Arc`) and `bytes` (atomic refcount), neither available without
  native atomic CAS (#40).

## 0.1.0 (June 6th, 2026)

First public release of the `hick` mDNS / DNS-SD family (the project formerly
known as `agnostic-mdns`), rebuilt on a Sans-I/O protocol core with pluggable
async drivers.

Published crates: `hick` 0.1.0, `mdns-proto` 0.2.0, `hick-udp` 0.1.0,
`hick-reactor` 0.1.0, `hick-compio` 0.1.0, `hick-smoltcp` 0.1.0,
`hick-embassy` 0.1.0, `hick-trace` 0.1.0.

FEATURES

- Sans-I/O mDNS / DNS-SD protocol core (`mdns-proto`), `no_std`-capable on
  `alloc` or `heapless`, with a `#![forbid(unsafe_code)]` core.
- Runtime-agnostic async drivers: `tokio` and `smol` via `hick-reactor`, and
  `compio` (thread-per-core) via `hick-compio`.
- Bare-metal drivers over smoltcp: `hick-smoltcp` (runtime-agnostic engine) and
  `hick-embassy` (embassy-net async driver), both `no_std` + `alloc`.
- RFC 6762 / 6763 conformance: probing and announcing, name-conflict detection
  with automatic renaming, known-answer and duplicate-question suppression,
  TTL-accurate caching, and TTL=0 goodbyes on withdrawal.
- Multicast UDP socket layer (`hick-udp`) over rustix on unix and
  socket2 + windows-sys on Windows.
- Observability via `hick-trace`: opt-in `tracing`, `metrics`, `stats`, and
  `defmt`.

MSRV: Rust 1.91 (edition 2024). Licensed under MIT OR Apache-2.0.

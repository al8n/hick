# RELEASED

## Dual-stack partial delivery (`TransmitDelivery`) (July 30th, 2026)

Published crates: `mdns-proto` 0.4.0, `hick` 0.3.0, `hick-reactor` 0.3.0,
`hick-compio` 0.3.0, `hick-smoltcp` 0.3.0, `hick-embassy` 0.3.0.

`mdns-proto`'s confirm APIs took a single boolean doing two jobs — advancing
the RFC 6762 lifecycle phase (§8.1 probing / §8.3 announcing, plus the §5.2
query retry budget) and latching §10.1 TTL=0 goodbye ownership — which is
unsound the moment a dual-stack multicast transmit succeeds on one address
family and fails on the other: there is no truthful bool to pass. This release
replaces the boolean with a lossless PER-FAMILY confirm and fixes the resulting
conformance and stranding defects in every released async driver.

BREAKING

- `mdns-proto`: new `TransmitDelivery` struct, carrying one `FamilyDelivery`
  (`Unobligated` / `Delivered` / `Missed`) per address family, reports what each
  family did with a multicast fan-out instead of collapsing it to one bool.
  `Service::note_transmit_outcome` / `Query::note_transmit_outcome` /
  `Endpoint::note_query_transmit_outcome` are now the sole confirm entry points;
  the boolean shims they were added alongside — `note_transmit_result` (on both
  `Service` and `Query`) and `Endpoint::note_query_transmit_result` — are
  removed. Lifecycle phase and the query retry budget advance only on
  `TransmitDelivery::all_delivered()`; goodbye ownership latches on the weaker
  `any_delivered()` — the two facts a single bool could never carry
  independently, and exactly where the removed boolean API was unsound for a
  dual-stack send.
- `mdns-proto`: the periodic §8.3 re-announce is scheduled PER FAMILY, off the
  stalest obligated family in good standing rather than off the last round. Each
  family holds its own copy of the records in its own peers' caches and so races
  its own TTL. A driver with room for one datagram per round serves the
  longest-blocked family first (which is now normative on `TransmitDelivery`), so
  the families alternate: every round is partial while each family is refreshed
  only every OTHER round, at twice the periodic interval — past the TTL for every
  TTL below 128 s, including the conventional 120 s. Records expired cyclically
  on BOTH families while every per-round invariant still held. Every obligated
  family in good standing is now re-announced within `max(0.8·TTL, 2 s)` of its
  last delivery. A family with no socket is excluded rather than read as
  infinitely stale (which would re-arm a single-stack host at the §8.3 one-second
  floor forever), and a family that has spent the core's patience stops driving
  the schedule until it delivers again (which would otherwise hold the deadline
  permanently in the past and flood the healthy family at the same floor).
- `mdns-proto`: the partial-delivery patience bound is counted PER FAMILY. A
  shared counter cannot tell "one family has missed twice" from "two families
  missed one round each while taking turns", and those need opposite answers.
  A phase also advances when every obligated family has carried the CURRENT
  datagram at some point since the last advance: a re-arm is lossless, so the
  same probe index reaching one family in one round and the other in the next has
  been asked on both. That is the only way a capacity-one transport ever
  advances, since under it no single round reaches both families and no family
  ever spends its patience. Neither shape takes the credit a delivery earns —
  `Service::has_fully_announced` still requires ONE datagram confirmed by every
  obligated family.
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
  re-arm that datagram until every obligated link accepts it, which is what a
  driver needs to know to decide what a PERMANENT send failure costs: a
  `Sustained` datagram that can never be sent would be re-offered forever and so
  retires its producer, while an undeliverable `OneShot` reply costs one
  unanswered question. The tag is a function of what was encoded, not of the
  service's lifecycle phase: the periodic `Established` re-announce advances no
  phase yet is still re-armed on the §8.3 ladder, and `Query::poll_transmit` has
  no service phase at all.
- The bound on repeated partial delivery lives in `mdns-proto`, not in drivers.
  Repeated partial delivery re-arms indefinitely, so the core bounds how many
  consecutive re-arms one producer spends waiting for a family that never accepts
  and then advances the phase without it. A driver reports the honest per-family
  facts and nothing else. The split is normative on `TransmitDelivery`'s rustdoc:
  the driver owns the obligated set and link death — and MUST offer every
  obligated family on every round, preferring the longest-blocked one under a
  constrained slot — while the core owns its own patience and its own
  schedule.
- Confirm before anything else. Once `Service::poll_transmit` /
  `Query::poll_transmit` returns a datagram, no other state-mutating entry point
  for that service or query — `handle_event`, `handle_timeout`,
  `withdrawal_snapshot` / teardown — may run until its `note_transmit_outcome`;
  `poll_transmit` itself is excepted and refuses while one is outstanding. A
  driver that cannot send right now DROPS the datagram and confirms
  as carried by no family in the same call rather than parking it: "delivered" here
  already means only that the kernel accepted the datagram synchronously, so a
  deferred confirm buys no fidelity while leaving the pending token's lifecycle
  meaning undecided. Normative on `Service::poll_transmit`'s rustdoc, asserted in
  debug builds. All four drivers in this workspace already comply.
- `mdns-proto`: `Endpoint::try_register_service` rejects a record TTL below
  `constants::MIN_SERVICE_TTL_SECS` (2 s) with the new
  `RegisterServiceError::TtlTooSmall`. A TTL-0 positive record is the RFC 6762
  §10.1 goodbye encoding — it deletes the record from peer caches instead of
  publishing it — and TTL 1 refreshes at 0.8 s, inside §8.3's one-second floor on
  unsolicited responses. Both also truncate the ~80 %-of-TTL periodic refresh to
  a zero-second interval, which re-armed an `Established` service at `now` and
  repumped an announcement every tick. The TTL is rejected rather than clamped.

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
- `mdns-proto`: bounded patience — after two consecutive partially-delivered
  lifecycle confirms for the same service or query, the third is EXCUSED and the
  phase advances without the link that keeps missing. A permanently
  half-reachable link now still reaches `Established` — after ~30 s, since the
  served link's announcements stay on §8.3's doubling ladder throughout —
  instead of pinning in probing forever. An excused advance is not a
  delivery: it does not set `Service::has_fully_announced`, does not reset the
  §8.3 / §5.2 doubling ladder (and never re-arms EARLIER than the rung the served
  link already earned), and does not bump `probes_tx` / `announcements_tx` —
  those counters mean "confirmed delivered by every obligated link", so a
  permanently half-broken host no longer reports a healthy startup.
  A round that reached no wire leaves every count untouched, so an alternating
  partial/failed pattern cannot evade the bound — and no phase can ever advance
  out of silence, which is what §8.1 requires of anything that claims a name. The count is reset wherever the lifecycle
  regresses to `Init` — both the §9 conflict rename and the RFC 6763 §9 same-name
  revert-to-probe, the latter of which emits no `ServiceUpdate` and so was
  unreachable from a driver.
- Because the count lives inside the per-kind confirm arms, a response (the §6
  multicast reply, the §6.7 legacy unicast reply, the RFC 6763 §9 meta reply)
  structurally cannot move it. Those datagrams are never re-armed, so counting
  them corrupts the bound in both directions: a unicast reply has one obligated
  family and is all-delivered by construction, so it would RESET the count — a
  service answering legacy queriers between lifecycle rounds would hold it at
  zero and the bound would never fire; and a partially-delivered multicast
  response would PRELOAD it, so the next partial probe would be excused and §8.1
  would advance although one family never heard the probe.
- `hick-smoltcp` / `hick-embassy`: a multicast RESPONSE that is permanently
  undeliverable (too large for every reachable socket) no longer retires the
  service. It resolves as delivered by no family — nothing latched, nothing advanced,
  the querier re-asks — matching the adjacent unicast branch. Previously any
  on-link peer could tear down a healthy established service by asking it a
  question whose answer did not fit the TX buffer: the service was marked
  errored, surfaced `Conflict`, and began withdrawing. An undeliverable
  `Sustained` datagram (probe, announcement, query) still retires its producer,
  which is the case that reasoning was written for.
- `hick-smoltcp` / `hick-embassy`: a PRESENT but unbound (or unaddressable) UDP
  socket is now `SendError::Busy`, not `SendError::Unsupported`. `Unsupported`
  removes a family from the obligated set, so a bound-IPv4 + present-but-unbound
  -IPv6 fan-out read as all-delivered and advanced §8.1 probing as though the node
  had no IPv6 at all. That family now reports `FamilyDelivery::Missed` and is
  retried.
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

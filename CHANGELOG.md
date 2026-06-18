# RELEASED

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

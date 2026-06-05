# RELEASED

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

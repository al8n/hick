# hick-trace

Tracing-or-noop diagnostic macro shim and backend-agnostic stats/metrics
primitives for the hick mDNS stack.

`hick-trace` is an internal support crate: all of the mDNS crates in the
[hick] family depend on it, and downstream code normally enables its features
indirectly through those crates (e.g. `hick/tracing`, `mdns-proto/stats`).

## Macros

Five log-level macros are always available as `hick_trace::<name>!(...)`:
`trace!`, `debug!`, `info!`, `warn!`, `error!`. When the `tracing` Cargo
feature is enabled they delegate to the real [`tracing`] crate; otherwise
they discard every argument without emitting code.

Three span macros — `trace_span!`, `debug_span!`, `info_span!` — follow the
same pattern. Without `tracing` they return a `NoopSpan` that supports
`.entered()` / `.enter()`, so call sites compile in both configurations.

## Feature flags

| Feature | Description |
|---------|-------------|
| `tracing` | Delegate macros to the real [`tracing`] crate (emit structured events/spans). |
| `stats` | Enable [`stats::Stats`] and [`stats::StatsSnapshot`]: `no_std`-safe atomic counters and gauges. Requires `portable-atomic` on targets without native 64-bit atomics. |
| `metrics` | Forward every counter/gauge update to the [`metrics`] facade (Prometheus/StatsD exporters). Implies `stats`; requires `std`. |

## `stats` module

`stats::Stats` owns one `AtomicU64` per metric. Call `stats.snapshot()` to
get a `StatsSnapshot` (plain `Copy` struct of `u64` fields). All loads use
`Relaxed` ordering — sufficient for periodic reporting.

**Counters**: `packets_rx`, `packets_tx`, `bytes_rx`, `bytes_tx`,
`packets_dropped`, `parse_errors`, `send_errors`, `questions_rx`,
`answers_rx`, `answers_collected`, `answers_suppressed_kas`,
`duplicate_questions_suppressed`, `responses_tx`, `probes_tx`,
`announcements_tx`, `goodbyes_tx`, `conflicts`, `renames`,
`cache_inserts`, `cache_refreshes`, `cache_evictions`, `cache_expirations`,
`queries_started`, `queries_done`, `queries_timeout`,
`services_registered`, `services_established`.

**Gauges**: `cache_size`, `queries_active`, `services_active` (each with
`incr_*` / `decr_*` / `set_*` methods).

## Feature-forwarding in downstream crates

Each crate in the hick family (`mdns-proto`, `hick-reactor`, `hick-compio`,
`hick-smoltcp`, `hick-embassy`, `hick-udp`) exposes the same feature names
(`tracing`, `stats`, `metrics`) and forwards them to `hick-trace`. The
[`hick`] facade additionally exposes `defmt` for the bare-metal drivers.

## License

`hick-trace` is under the terms of both the MIT license and the Apache License
(Version 2.0).

See [LICENSE-APACHE](../LICENSE-APACHE), [LICENSE-MIT](../LICENSE-MIT) for details.

Copyright (c) 2025 Al Liu.

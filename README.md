<div align="center">
<h1>hick</h1>
</div>
<div align="center">

Batteries-included, runtime-agnostic **mDNS / DNS-SD** for Rust — a Sans-I/O
protocol core with pluggable async drivers.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/hick-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
<img alt="LoC" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fal8n%2F327b2a8aef9003246e45c6e47fe63937%2Fraw%2Fhick" height="22">
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/hick/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/hick?style=for-the-badge&token=6R3QFWRWHL&logo=codecov" height="22">][codecov-url]

[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-hick-66c2a5?style=for-the-badge&labelColor=555555&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/hick?style=for-the-badge&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pg0KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDE5LjAuMCwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPg0KPHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCINCgkgdmlld0JveD0iMCAwIDUxMiA1MTIiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0yNTYsMEwzMS41MjgsMTEyLjIzNnYyODcuNTI4TDI1Niw1MTJsMjI0LjQ3Mi0xMTIuMjM2VjExMi4yMzZMMjU2LDB6IE0yMzQuMjc3LDQ1Mi41NjRMNzQuOTc0LDM3Mi45MTNWMTYwLjgxDQoJCQlsMTU5LjMwMyw3OS42NTFWNDUyLjU2NHogTTEwMS44MjYsMTI1LjY2MkwyNTYsNDguNTc2bDE1NC4xNzQsNzcuMDg3TDI1NiwyMDIuNzQ5TDEwMS44MjYsMTI1LjY2MnogTTQzNy4wMjYsMzcyLjkxMw0KCQkJbC0xNTkuMzAzLDc5LjY1MVYyNDAuNDYxbDE1OS4zMDMtNzkuNjUxVjM3Mi45MTN6IiBmaWxsPSIjRkZGIi8+DQoJPC9nPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPC9zdmc+DQo=" height="22">][crates-url]
[<img alt="crates.io" src="https://img.shields.io/crates/d/hick?color=critical&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBzdGFuZGFsb25lPSJubyI/PjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCI+PHN2ZyB0PSIxNjQ1MTE3MzMyOTU5IiBjbGFzcz0iaWNvbiIgdmlld0JveD0iMCAwIDEwMjQgMTAyNCIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHAtaWQ9IjM0MjEiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkzIiB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj48ZGVmcz48c3R5bGUgdHlwZT0idGV4dC9jc3MiPjwvc3R5bGU+PC9kZWZzPjxwYXRoIGQ9Ik00NjkuMzEyIDU3MC4yNHYtMjU2aDg1LjM3NnYyNTZoMTI4TDUxMiA3NTYuMjg4IDM0MS4zMTIgNTcwLjI0aDEyOHpNMTAyNCA2NDAuMTI4QzEwMjQgNzgyLjkxMiA5MTkuODcyIDg5NiA3ODcuNjQ4IDg5NmgtNTEyQzEyMy45MDQgODk2IDAgNzYxLjYgMCA1OTcuNTA0IDAgNDUxLjk2OCA5NC42NTYgMzMxLjUyIDIyNi40MzIgMzAyLjk3NiAyODQuMTYgMTk1LjQ1NiAzOTEuODA4IDEyOCA1MTIgMTI4YzE1Mi4zMiAwIDI4Mi4xMTIgMTA4LjQxNiAzMjMuMzkyIDI2MS4xMkM5NDEuODg4IDQxMy40NCAxMDI0IDUxOS4wNCAxMDI0IDY0MC4xOTJ6IG0tMjU5LjItMjA1LjMxMmMtMjQuNDQ4LTEyOS4wMjQtMTI4Ljg5Ni0yMjIuNzItMjUyLjgtMjIyLjcyLTk3LjI4IDAtMTgzLjA0IDU3LjM0NC0yMjQuNjQgMTQ3LjQ1NmwtOS4yOCAyMC4yMjQtMjAuOTI4IDIuOTQ0Yy0xMDMuMzYgMTQuNC0xNzguMzY4IDEwNC4zMi0xNzguMzY4IDIxNC43MiAwIDExNy45NTIgODguODMyIDIxNC40IDE5Ni45MjggMjE0LjRoNTEyYzg4LjMyIDAgMTU3LjUwNC03NS4xMzYgMTU3LjUwNC0xNzEuNzEyIDAtODguMDY0LTY1LjkyLTE2NC45MjgtMTQ0Ljk2LTE3MS43NzZsLTI5LjUwNC0yLjU2LTUuODg4LTMwLjk3NnoiIGZpbGw9IiNmZmZmZmYiIHAtaWQ9IjM0MjIiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkwIiBjbGFzcz0iIj48L3BhdGg+PC9zdmc+&style=for-the-badge" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge&fontColor=white&logoColor=f5c076&logo=data:image/svg+xml;base64,PCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KDTwhLS0gVXBsb2FkZWQgdG86IFNWRyBSZXBvLCB3d3cuc3ZncmVwby5jb20sIFRyYW5zZm9ybWVkIGJ5OiBTVkcgUmVwbyBNaXhlciBUb29scyAtLT4KPHN2ZyBmaWxsPSIjZmZmZmZmIiBoZWlnaHQ9IjgwMHB4IiB3aWR0aD0iODAwcHgiIHZlcnNpb249IjEuMSIgaWQ9IkNhcGFfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgdmlld0JveD0iMCAwIDI3Ni43MTUgMjc2LjcxNSIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSIgc3Ryb2tlPSIjZmZmZmZmIj4KDTxnIGlkPSJTVkdSZXBvX2JnQ2FycmllciIgc3Ryb2tlLXdpZHRoPSIwIi8+Cg08ZyBpZD0iU1ZHUmVwb190cmFjZXJDYXJyaWVyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KDTxnIGlkPSJTVkdSZXBvX2ljb25DYXJyaWVyIj4gPGc+IDxwYXRoIGQ9Ik0xMzguMzU3LDBDNjIuMDY2LDAsMCw2Mi4wNjYsMCwxMzguMzU3czYyLjA2NiwxMzguMzU3LDEzOC4zNTcsMTM4LjM1N3MxMzguMzU3LTYyLjA2NiwxMzguMzU3LTEzOC4zNTcgUzIxNC42NDgsMCwxMzguMzU3LDB6IE0xMzguMzU3LDI1OC43MTVDNzEuOTkyLDI1OC43MTUsMTgsMjA0LjcyMywxOCwxMzguMzU3UzcxLjk5MiwxOCwxMzguMzU3LDE4IHMxMjAuMzU3LDUzLjk5MiwxMjAuMzU3LDEyMC4zNTdTMjA0LjcyMywyNTguNzE1LDEzOC4zNTcsMjU4LjcxNXoiLz4gPHBhdGggZD0iTTE5NC43OTgsMTYwLjkwM2MtNC4xODgtMi42NzctOS43NTMtMS40NTQtMTIuNDMyLDIuNzMyYy04LjY5NCwxMy41OTMtMjMuNTAzLDIxLjcwOC0zOS42MTQsMjEuNzA4IGMtMjUuOTA4LDAtNDYuOTg1LTIxLjA3OC00Ni45ODUtNDYuOTg2czIxLjA3Ny00Ni45ODYsNDYuOTg1LTQ2Ljk4NmMxNS42MzMsMCwzMC4yLDcuNzQ3LDM4Ljk2OCwyMC43MjMgYzIuNzgyLDQuMTE3LDguMzc1LDUuMjAxLDEyLjQ5NiwyLjQxOGM0LjExOC0yLjc4Miw1LjIwMS04LjM3NywyLjQxOC0xMi40OTZjLTEyLjExOC0xNy45MzctMzIuMjYyLTI4LjY0NS01My44ODItMjguNjQ1IGMtMzUuODMzLDAtNjQuOTg1LDI5LjE1Mi02NC45ODUsNjQuOTg2czI5LjE1Miw2NC45ODYsNjQuOTg1LDY0Ljk4NmMyMi4yODEsMCw0Mi43NTktMTEuMjE4LDU0Ljc3OC0zMC4wMDkgQzIwMC4yMDgsMTY5LjE0NywxOTguOTg1LDE2My41ODIsMTk0Ljc5OCwxNjAuOTAzeiIvPiA8L2c+IDwvZz4KDTwvc3ZnPg==" height="22">

</div>

## Introduction

`hick` is the high-level entry point to the **hick** mDNS family. It wires the
Sans-I/O protocol core ([`mdns-proto`]) to a ready-to-use async driver
([`hick-reactor`]) so you can publish and discover services on the local
network in a few lines, with `tokio` out of the box.

mDNS (Multicast DNS, [RFC 6762]) and DNS-SD ([RFC 6763]) let peers discover one
another on a local link with no central DNS server — the basis of "zeroconf"
service discovery. Note that many cloud and shared-infrastructure networks
restrict multicast, so mDNS is best suited to office, home, or private
networks.

## The family

The crates split protocol logic from I/O, mirroring the `quinn` layering:

| Crate | Role |
|-------|------|
| [`hick`] | this crate — batteries-included facade (core + default driver) |
| [`mdns-proto`] | Sans-I/O protocol state machines (`no_std`-capable) |
| [`hick-udp`] | multicast UDP socket setup |
| [`hick-reactor`] | runtime-agnostic async driver (`tokio` & `smol`) |
| [`hick-compio`] | `compio` (thread-per-core) async driver |
| [`hick-smoltcp`] | bare-metal mDNS engine over smoltcp (`no_std` + `alloc`) |
| [`hick-embassy`] | embassy async driver, built on `hick-smoltcp` (`no_std` + `alloc`) |

## Installation

```toml
[dependencies]
hick = "0.1" # tokio runtime by default
```

For `smol` instead of `tokio`:

```toml
[dependencies]
hick = { version = "0.1", default-features = false, features = ["smol"] }
```

For the `compio` (completion-based, thread-per-core) runtime, depend on
[`hick-compio`] directly.

For bare-metal (`no_std`) targets, enable the `smoltcp` (engine) or `embassy`
(async driver) features, or depend on [`hick-smoltcp`] / [`hick-embassy`].

## Example

Common, runtime-agnostic types (`Name`, `QuerySpec`, `ServiceSpec`, …) live at the
crate root; the runtime-pinned entry point and driver handles live in the per-runtime
module (`hick::tokio`, `hick::smol`).

```rust,ignore
use hick::{Name, QuerySpec, ServiceRecords, ServiceSpec, wire::ResourceType};
use hick::tokio::{server, QueryEvent, ServerOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start the driver, pinned to the tokio runtime.
    let endpoint = server(ServerOptions::default()).await?;

    // Advertise a service. Keep the returned handle alive to keep advertising;
    // dropping it withdraws the service (TTL=0 goodbye) and unregisters it.
    let mut records = ServiceRecords::new(
        Name::try_from_str("_http._tcp.local.")?,            // service type
        Name::try_from_str("My Device._http._tcp.local.")?,  // instance
        Name::try_from_str("my-device.local.")?,             // host
        80,                                                  // port
        120,                                                 // TTL (seconds)
    );
    records.add_a([192, 168, 1, 10].into());
    let _service = endpoint.register_service(ServiceSpec::new(records)).await?;

    // Discover services of a type on the local link.
    let mut query = endpoint
        .start_query(QuerySpec::new(
            Name::try_from_str("_ipp._tcp.local.")?,
            ResourceType::Ptr,
        ))
        .await?;
    while let Some(event) = query.next().await {
        match event {
            QueryEvent::Answer(answer) => println!("{answer:?}"),
            QueryEvent::Terminal(_) => break,
        }
    }
    Ok(())
}
```

## Feature flags

- `tokio` *(default)* — drive the `tokio` runtime via [`hick-reactor`].
- `smol` — drive the `smol` runtime.
- `compio` — drive the `compio` (thread-per-core) runtime via [`hick-compio`].
- `smoltcp` — expose the bare-metal [`hick-smoltcp`] engine (`no_std` + `alloc`).
- `embassy` — expose the [`hick-embassy`] async driver (`no_std` + `alloc`).
- `tracing` — forward structured `tracing` spans/events from every enabled driver and the proto core.
- `stats` — enable `no_std`-safe atomic counters; read a snapshot via `endpoint.stats()`.
- `metrics` — bridge counters to the [`metrics`] facade (Prometheus/StatsD exporters). Implies `stats`.
- `defmt` — forward `defmt` log events to the bare-metal drivers (`hick-smoltcp` / `hick-embassy`). Has no effect when only std drivers are enabled.

## Observability

### `tracing` — structured events and spans

Add `features = ["tracing"]` and install a subscriber in `main`:

```rust,ignore
fn main() {
    tracing_subscriber::fmt().init();
    // … start your endpoint …
}
```

The driver task and `mdns-proto` emit `tracing` events at `DEBUG` / `INFO` /
`WARN` level during probing, service registration, conflict resolution, cache
updates, and query completion.

### `metrics` — Prometheus / StatsD counters

Add `features = ["metrics"]` and install a recorder before starting the
endpoint:

```rust,ignore
// Example using the prometheus exporter from the `metrics-exporter-prometheus` crate:
metrics_exporter_prometheus::PrometheusBuilder::new().install().unwrap();
```

All mDNS counters (packets, bytes, cache hits, queries, …) are forwarded
automatically under `mdns_*` metric names.

### `stats` — polling counters without a recorder

When you only need periodic read-outs without a full metrics exporter,
enable `stats` and call `endpoint.stats()`:

```rust,ignore
use hick::tokio::{server, ServerOptions};

let endpoint = server(ServerOptions::default()).await?;
// … run for a while …
let snap = endpoint.stats();
println!("rx={} tx={} cache_size={}", snap.packets_rx, snap.packets_tx, snap.cache_size);
```

`stats()` returns a `hick_trace::stats::StatsSnapshot` — a plain `Copy`
struct of `u64` fields covering packets, bytes, cache, queries, services,
probes, conflicts, and more. See the [`hick-trace`] crate for the full list.

### `defmt` — bare-metal embedded logging

For `no_std` targets using `hick-smoltcp` or `hick-embassy`, enable `defmt`
instead of (or alongside) `stats`. Log events are forwarded through the
`defmt` framework. On std drivers this feature is a no-op.

Per-crate observability details: [`hick-trace`] (shim) · [`mdns-proto`] ·
[`hick-reactor`] · [`hick-compio`] · [`hick-smoltcp`] · [`hick-embassy`] ·
[`hick-udp`].

## License

`hick` is under the terms of both the MIT license and the Apache License
(Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2025 Al Liu.

[`hick`]: https://crates.io/crates/hick
[`mdns-proto`]: https://crates.io/crates/mdns-proto
[`hick-trace`]: https://crates.io/crates/hick-trace
[`hick-udp`]: https://crates.io/crates/hick-udp
[`hick-reactor`]: https://crates.io/crates/hick-reactor
[`hick-compio`]: https://crates.io/crates/hick-compio
[`hick-smoltcp`]: https://crates.io/crates/hick-smoltcp
[`hick-embassy`]: https://crates.io/crates/hick-embassy
[`metrics`]: https://crates.io/crates/metrics
[RFC 6762]: https://www.rfc-editor.org/rfc/rfc6762
[RFC 6763]: https://www.rfc-editor.org/rfc/rfc6763
[Github-url]: https://github.com/al8n/hick/
[CI-url]: https://github.com/al8n/hick/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/hick/
[doc-url]: https://docs.rs/hick
[crates-url]: https://crates.io/crates/hick

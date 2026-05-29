# mdns-proto

Sans-I/O mDNS protocol state machines: no_std-capable, no_alloc-capable, panic-free.

This crate implements the full RFC 6762 protocol behavior (probing, conflict resolution, periodic announcement, known-answer suppression, cache coherency, response generation) as deterministic state machines that do no I/O of their own. Callers feed datagrams and timer ticks in via `handle` / `handle_timeout` and drain outbound datagrams via `poll_transmit` — the same shape as `quinn-proto`.

## Target audiences

- **`std`** users on tokio, smol, or async-std (via the companion `mdns-reactor` crate, or any driver of their choosing).
- **`no_std + alloc`** users on Embassy, RTIC, ESP-IDF, wasm32.
- **`no_std + no_alloc`** users on bare-metal microcontrollers without a heap.

## Status

This crate is currently mid-rewrite on the `refactor/sansio` branch. The protocol state machines land in the wire (plan 2) and state-machine (plan 3) implementation phases. This 0.5 release ships only the type abstractions; functional behaviour follows in subsequent point releases.

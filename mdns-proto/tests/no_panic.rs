//! Smoke harness that fails to link if any reachable code from these functions
//! pulls in a panic landing pad.
//!
//! Currently opt-in via the `test-no-panic` feature because the std-feature
//! build pulls in `thiserror`/`derive_more`/`smol_str` Display paths that the
//! `no-panic` link-time check flags (formatter macros include OOM-panic
//! landing pads). The cargo-bloat scan in CI is the primary panic-freedom
//! enforcement; this harness is a stretch-goal stricter check.
//!
//! Run with: `cargo test -p mdns-proto --release --features test-no-panic --test no_panic`
//!
//! Only meaningful in optimized (release) builds: `no-panic`'s link-time
//! assertion fires on the panic landing pads that survive a non-optimized
//! build, so this is gated to `not(debug_assertions)`. It is also skipped on
//! macOS (the trick reports spurious "detected panic" undefined symbols against
//! the macOS linker) and under coverage instrumentation (`cargo llvm-cov` sets
//! `--cfg coverage`, whose injected counters defeat dead-code elimination of the
//! panic paths). Run it with
//! `cargo test -p mdns-proto --release --features test-no-panic --test no_panic`;
//! the cargo-bloat scan is the primary panic-freedom gate in CI.

#![cfg(all(
  feature = "std",
  feature = "test-no-panic",
  not(target_os = "macos"),
  not(coverage),
  not(debug_assertions)
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use mdns_proto::wire::{MessageReader, NameRef};

#[no_panic::no_panic]
fn try_parse_message(buf: &[u8]) -> bool {
  MessageReader::try_parse(buf).is_ok()
}

#[no_panic::no_panic]
fn try_parse_name(buf: &[u8]) -> bool {
  NameRef::try_parse(buf, 0).is_ok()
}

#[test]
fn no_panic_paths_link() {
  let buf = [0u8; 64];
  let _ = try_parse_message(&buf);
  let _ = try_parse_name(&buf);
}

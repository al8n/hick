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

#![cfg(all(feature = "std", feature = "test-no-panic"))]
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

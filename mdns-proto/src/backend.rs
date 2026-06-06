//! Storage-backend type aliases — the refcounted byte / `Arc` flavor selected by
//! the `alloc`/`std` (native-atomic) vs `no-atomic` (portable-atomic) feature.
//!
//! - **atomic** (`alloc`/`std`): [`bytes::Bytes`] rdata + [`alloc::sync::Arc`]
//!   (`std` here is the `extern crate alloc as std` alias), cheap-clone via
//!   native atomics.
//! - **no-atomic** (`no-atomic`): [`portable_atomic_util::Arc<[u8]>`] rdata +
//!   `portable_atomic_util::Arc`, cheap-clone via `portable-atomic` + a
//!   `critical-section` impl — for cores without native atomic CAS (Cortex-M0+).
//!
//! No `Bytes`-specific zero-copy slicing is used anywhere, so `Arc<[u8]>` is a
//! drop-in. `RdataBuf` is built from an owned byte buffer via [`rdata_from_vec`].

// `alloc`/`std` take precedence over `no-atomic` (matching name.rs's NameInner),
// so `--all-features` (which turns on both) resolves to a single, consistent
// atomic backend rather than mixing `Bytes` names with `Arc<[u8]>` rdata.
#[cfg(any(feature = "alloc", feature = "std"))]
mod imp {
  pub(crate) use bytes::Bytes as RdataBuf;
  pub(crate) use std::sync::Arc as Shared;

  /// Seal an owned byte buffer into a cheap-clone `RdataBuf`.
  pub(crate) fn rdata_from_vec(v: std::vec::Vec<u8>) -> RdataBuf {
    RdataBuf::from(v)
  }
}

#[cfg(all(feature = "no-atomic", not(any(feature = "alloc", feature = "std"))))]
mod imp {
  pub(crate) use portable_atomic_util::Arc as Shared;

  /// Refcounted, read-only rdata bytes (portable-atomic `Arc<[u8]>`).
  pub(crate) type RdataBuf = portable_atomic_util::Arc<[u8]>;

  /// Seal an owned byte buffer into a cheap-clone `RdataBuf`.
  pub(crate) fn rdata_from_vec(v: std::vec::Vec<u8>) -> RdataBuf {
    // `Arc<[u8]>` has `From<Vec<u8>>` but no `From<Box<[u8]>>`, so feed the `Vec`
    // directly.
    RdataBuf::from(v)
  }
}

cfg_heap! {
  pub(crate) use imp::{RdataBuf, Shared, rdata_from_vec};
}

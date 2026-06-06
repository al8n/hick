//! Internal `cfg` macros that bundle a feature gate with its matching docs.rs
//! `doc(cfg(...))` badge, so each storage-tier predicate lives in exactly one
//! place. Wrapping items in one of these is equivalent to writing both
//! `#[cfg(PRED)]` and `#[cfg_attr(docsrs, doc(cfg(PRED)))]` on each — but the
//! predicate cannot drift between the two (the source of past tier bugs), and a
//! new item can never silently omit its docs.rs badge.
//!
//! They wrap *items* (`mod` / `use` / `fn` / `struct` / `enum` / `impl` / `const`
//! / `type`) and methods. Struct fields, function parameters, `match` arms and
//! statements are not items, so a handful of those keep an explicit `#[cfg(...)]`.

// Which helpers are invoked depends on the active feature tier — e.g. `cfg_stats`
// is only used inside the heap-gated `endpoint` module, so it is dead in a
// `heapless`-only build.
#![allow(unused_macros)]

// Items that need a heap allocator — the dynamic-storage (Endpoint) tier:
// `alloc`, `std`, or the `no-atomic` (portable-atomic) tier. Mirrors the
// `NameInner` heap arms; deliberately excludes `heapless`.
macro_rules! cfg_heap {
  ($($item:item)*) => {
    $(
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "alloc", feature = "std", feature = "no-atomic")))
      )]
      $item
    )*
  };
}

// Items available on *any* storage tier that can hold a `Name`: the heap tiers
// (`alloc` / `std` / `no-atomic`) plus fixed-capacity `heapless`.
macro_rules! cfg_storage {
  ($($item:item)*) => {
    $(
      #[cfg(any(
        feature = "alloc",
        feature = "std",
        feature = "heapless",
        feature = "no-atomic"
      ))]
      #[cfg_attr(
        docsrs,
        doc(cfg(any(
          feature = "alloc",
          feature = "std",
          feature = "heapless",
          feature = "no-atomic"
        )))
      )]
      $item
    )*
  };
}

// Items gated on the `stats` counter feature.
macro_rules! cfg_stats {
  ($($item:item)*) => {
    $(
      #[cfg(feature = "stats")]
      #[cfg_attr(docsrs, doc(cfg(feature = "stats")))]
      $item
    )*
  };
}

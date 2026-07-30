#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]
#![allow(unexpected_cfgs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
// Panic-freedom restriction lints are a PRODUCTION concern (this is a no_std /
// no-panic-capable core); test code legitimately uses unwrap/expect/panic/etc.,
// so gate the denies on `not(test)` (mirrors the `unsafe_code` split above).
#![cfg_attr(
  not(test),
  deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::arithmetic_side_effects,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::string_slice
  )
)]

#[cfg(all(not(feature = "std"), any(feature = "alloc", feature = "no-atomic")))]
extern crate alloc as std;

#[cfg(feature = "std")]
extern crate std;

// `cfg_heap!` / `cfg_stats!` — declared first so they are in textual scope for
// every module below.
#[macro_use]
mod macros;

/// Protocol-level constants (RFC 1035 + RFC 6762 limits).
pub mod constants;

mod trace;

cfg_heap! {
  // Refcounted byte / `Arc` storage-backend aliases (atomic vs portable-atomic).
  mod backend;
}

/// Pluggable backing storage for protocol state machines.
pub mod pool;

pub use pool::Pool;

/// Monotonic time abstraction.
pub mod time;

pub use time::Instant;

#[cfg(feature = "slab")]
#[cfg_attr(docsrs, doc(cfg(feature = "slab")))]
pub use slab;

/// Opaque handles for services and queries.
pub mod handle;

pub use handle::{QueryHandle, ServiceHandle};

/// Owned, canonical DNS name.
pub mod name;

pub use name::{LabelTooLongDetail, NameError, NameTooLongDetail};

cfg_heap! {
  /// Owned, canonical DNS name root re-export.
  pub use name::Name;
}

/// Cross-cutting error types.
pub mod error;

pub use error::{
  BufferTooShortDetail, BufferTooSmallDetail, EncodeError, HandleError, HandleTimeoutError,
  ParseError, PointerForwardDetail, RdlengthOverrunDetail, StartQueryError, StorageFullError,
  TransmitError,
};

cfg_heap! {
  pub use error::{CancelQueryError, HandleServiceRenamedError, RegisterServiceError};
}

/// mDNS wire format — panic-free parser and encoder.
pub mod wire;

/// Event types between Endpoint, Service, and Query.
pub mod event;
/// Outgoing-datagram descriptor and its delivery outcome.
pub mod transmit;

pub use event::{
  EndpointEvent, HostConflict, KnownAnswer, ProbeConflict, QueryEvent, QueryUpdate, RouteEvent,
  ServiceEvent, ServiceQuestion, ToQuery, ToService,
};
pub use transmit::{Transmit, TransmitOutcome};

cfg_heap! {
  pub use event::{ServiceRenamed, ServiceUpdate};
}

/// Configuration types.
pub mod config;

cfg_heap! {
  /// Records published by a registered Service.
  pub mod records;
}

pub use config::EndpointConfig;

cfg_heap! {
  pub use records::ServiceRecords;
  pub use config::ServiceSpec;
}

cfg_heap! {
  pub use config::QuerySpec;
}

cfg_heap! {
  /// Passive record cache.
  pub mod cache;
  pub use cache::{Cache, CacheEntry};
}

/// Service state machine.
pub mod service;

pub use service::ServiceState;

cfg_heap! {
  pub use service::{FullyAnnounced, Service};

  /// Query state machine.
  pub mod query;
  pub use query::{CollectedAnswer, Query};

  /// Endpoint orchestrator.
  pub mod endpoint;
  pub use endpoint::{
    Endpoint, EndpointEventEntry, RouteEvents, ServiceRoute, WithdrawalSend, WithdrawalToken,
  };
}

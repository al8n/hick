#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]
#![allow(unexpected_cfgs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(
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
)]

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc as std;

#[cfg(feature = "std")]
extern crate std;

/// Protocol-level constants (RFC 1035 + RFC 6762 limits).
pub mod constants;

mod trace;

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

#[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
#[cfg_attr(
  docsrs,
  doc(cfg(any(feature = "alloc", feature = "std", feature = "heapless")))
)]
pub use name::Name;

/// Cross-cutting error types.
pub mod error;

pub use error::{
  BufferTooShortDetail, BufferTooSmallDetail, EncodeError, HandleError, HandleTimeoutError,
  ParseError, PointerForwardDetail, RdlengthOverrunDetail, StartQueryError, StorageFullError,
  TransmitError,
};

#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub use error::{CancelQueryError, HandleServiceRenamedError, RegisterServiceError};

/// mDNS wire format — panic-free parser and encoder.
pub mod wire;

/// Event types between Endpoint, Service, and Query.
pub mod event;
/// Outgoing-datagram descriptor.
pub mod transmit;

pub use event::{
  EndpointEvent, HostConflict, KnownAnswer, ProbeConflict, QueryEvent, QueryUpdate, RouteEvent,
  ServiceEvent, ServiceQuestion, ToQuery, ToService,
};
pub use transmit::Transmit;

#[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
#[cfg_attr(
  docsrs,
  doc(cfg(any(feature = "alloc", feature = "std", feature = "heapless")))
)]
pub use event::{ServiceRenamed, ServiceUpdate};

/// Configuration types.
pub mod config;
/// Records published by a registered Service.
pub mod records;

pub use config::EndpointConfig;

#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub use records::ServiceRecords;

#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub use config::ServiceSpec;

#[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
#[cfg_attr(
  docsrs,
  doc(cfg(any(feature = "alloc", feature = "std", feature = "heapless")))
)]
pub use config::QuerySpec;

/// Passive record cache.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub mod cache;

#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub use cache::{Cache, CacheEntry};

/// Service state machine.
pub mod service;

pub use service::ServiceState;

#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub use service::Service;

/// Query state machine.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub mod query;

#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub use query::{CollectedAnswer, Query};

/// Endpoint orchestrator.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub mod endpoint;

#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub use endpoint::{
  Endpoint, EndpointEventEntry, RouteEvents, ServiceRoute, WithdrawalSend, WithdrawalToken,
};

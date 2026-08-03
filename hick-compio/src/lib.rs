#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

pub(crate) mod driver;
pub(crate) mod onlink;
pub(crate) mod socket;

pub mod discovery;
pub mod endpoint;
pub mod error;
pub mod options;
pub mod query;
pub mod service;
#[cfg(all(test, feature = "tracing", not(miri)))]
mod trace_cov;

pub use discovery::{DEFAULT_MAX_ENTRIES, Lookup, QueryParam, ServiceEntry};
pub use endpoint::Endpoint;
pub use error::{CancelError, RegisterError, ServerError, StartQueryError};
pub use options::ServerOptions;
pub use query::{Query, QueryEvent};
pub use service::Service;

// Re-export the `mdns-proto` types the public surface uses, mirroring
// `hick-reactor`.
pub use mdns_proto::{
  CollectedAnswer, Name, QueryHandle, QuerySpec, QueryUpdate, ServiceHandle, ServiceRecords,
  ServiceSpec, ServiceUpdate, wire,
};

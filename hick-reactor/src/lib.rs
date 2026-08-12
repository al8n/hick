#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

mod command;
mod discovery;
mod driver;
mod endpoint;
mod error;
mod options;
mod proto;
mod query;
mod service;
#[cfg(all(test, feature = "tracing", not(miri)))]
mod trace_cov;

pub use discovery::{Lookup, QueryParam, ServiceEntry};
// Mandatory degradation state: readable with default features, no `tracing`
// subscriber and no `stats` opt-in. See the type's own doc for why that
// property is the point of it.
pub use driver::DeafFamilies;
pub use endpoint::Endpoint;
pub use error::{CancelError, RegisterError, ServerError, StartQueryError};
pub use options::ServerOptions;
pub use query::{Query, QueryEvent};
pub use service::Service;

// Re-export the mdns-proto types callers need to interact with this crate.
pub use mdns_proto::{
  CollectedAnswer, EndpointConfig, Name, QueryHandle, QuerySpec, ServiceHandle, ServiceRecords,
  ServiceRenamed, ServiceSpec, ServiceUpdate, config, error as proto_error, event, wire,
};

/// Per-runtime adapter for the [`tokio`] runtime.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio {
  use crate::options::ServerOptions;

  /// `tokio`-backed mDNS [`Endpoint`](crate::Endpoint).
  pub type Endpoint = crate::Endpoint;

  /// Construct an mDNS endpoint pinned to the `tokio` runtime.
  ///
  /// Equivalent to [`crate::Endpoint::server::<agnostic_net::tokio::Net>`].
  #[inline]
  pub async fn server(opts: ServerOptions) -> Result<Endpoint, crate::ServerError> {
    Endpoint::server::<agnostic_net::tokio::Net>(opts).await
  }
}

/// Per-runtime adapter for the [`smol`] runtime.
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub mod smol {
  use crate::options::ServerOptions;

  /// `smol`-backed mDNS [`Endpoint`](crate::Endpoint).
  pub type Endpoint = crate::Endpoint;

  /// Construct an mDNS endpoint pinned to the `smol` runtime.
  ///
  /// Equivalent to [`crate::Endpoint::server::<agnostic_net::smol::Net>`].
  #[inline]
  pub async fn server(opts: ServerOptions) -> Result<Endpoint, crate::ServerError> {
    Endpoint::server::<agnostic_net::smol::Net>(opts).await
  }
}

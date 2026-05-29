//! `agnostic-mdns` — async mDNS driver.
//!
//! Layered on [`mdns-proto`] (Sans-I/O state machines) and [`mdns-udp`]
//! (multicast socket setup). The driver task is generic over an
//! [`agnostic_net::Net`] implementation, so a single codebase serves both
//! `tokio` and `smol` runtimes.
//!
//! ```ignore
//! use agnostic_mdns::{ServerOptions, tokio::Endpoint};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let endpoint = Endpoint::server(ServerOptions::default()).await?;
//! let mut query = endpoint
//!     .start_query(mdns_proto::QuerySpec::new(
//!         mdns_proto::Name::try_from_str("_ipp._tcp.local.")?,
//!         mdns_proto::wire::ResourceType::Any,
//!     ))
//!     .await?;
//! while let Some(event) = query.next().await {
//!     match event {
//!         agnostic_mdns::QueryEvent::Answer(a) => println!("{:?}", a),
//!         agnostic_mdns::QueryEvent::Terminal(_) => break,
//!     }
//! }
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
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

pub use discovery::{Lookup, QueryParam, ServiceEntry};
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

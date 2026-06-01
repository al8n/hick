//! Public error types surfaced by the async API.

use mdns_proto::{Name, error::RegisterServiceError as ProtoRegisterError};

/// Errors raised while constructing or running an [`Endpoint`](crate::Endpoint).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
  /// At least one of IPv4 / IPv6 must be enabled in [`ServerOptions`](crate::ServerOptions).
  #[error("ServerOptions has neither IPv4 nor IPv6 enabled")]
  NoFamilyEnabled,

  /// Binding the IPv4 multicast socket failed.
  #[error("bind v4: {0}")]
  BindV4(hick_udp::BindError),

  /// Binding the IPv6 multicast socket failed.
  #[error("bind v6: {0}")]
  BindV6(hick_udp::BindError),

  /// Wrapping the bound socket as an async UDP socket failed.
  #[error("wrap socket: {0}")]
  WrapSocket(std::io::Error),

  /// I/O error during endpoint setup (e.g. setting non-blocking mode).
  #[error(transparent)]
  Io(#[from] std::io::Error),
}

/// Errors raised by [`Endpoint::register_service`](crate::Endpoint::register_service).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegisterError {
  /// A service with the same instance name is already registered.
  #[error("name already registered: {0}")]
  NameAlreadyRegistered(Name),

  /// The proto service pool is full.
  #[error("service pool is full")]
  StorageFull,

  /// The driver task is no longer running.
  #[error("endpoint driver is gone")]
  DriverGone,
}

impl From<ProtoRegisterError> for RegisterError {
  fn from(e: ProtoRegisterError) -> Self {
    match e {
      ProtoRegisterError::NameAlreadyRegistered(n) => Self::NameAlreadyRegistered(n),
      ProtoRegisterError::StorageFull(_) => Self::StorageFull,
      _ => Self::StorageFull,
    }
  }
}

/// Errors raised by [`Endpoint::start_query`](crate::Endpoint::start_query).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartQueryError {
  /// The proto query pool is full.
  #[error("query pool is full")]
  StorageFull,

  /// The driver task is no longer running.
  #[error("endpoint driver is gone")]
  DriverGone,
}

/// Errors raised by [`Query::cancel`](crate::Query::cancel) and [`Service::unregister`](crate::Service::unregister).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CancelError {
  /// The driver task is no longer running.
  #[error("endpoint driver is gone")]
  DriverGone,
}

//! Public error types surfaced by the async API.

use mdns_proto::{Name, error::RegisterServiceError as ProtoRegisterError};

/// Errors raised while constructing or running an [`Endpoint`](crate::Endpoint).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
  /// At least one of IPv4 / IPv6 must be enabled in
  /// [`ServerOptions`](crate::ServerOptions).
  #[error("ServerOptions has neither IPv4 nor IPv6 enabled")]
  NoFamilyEnabled,

  /// Binding the IPv4 multicast socket failed.
  #[error("bind v4: {0}")]
  BindV4(hick_udp::BindError),

  /// Binding the IPv6 multicast socket failed.
  #[error("bind v6: {0}")]
  BindV6(hick_udp::BindError),

  /// Joining the IPv4 mDNS multicast group failed. The socket bound but never
  /// joined `224.0.0.251`, so it could send but not receive multicast — a
  /// silent failure if ignored, hence surfaced at construction.
  #[error("join v4: {0}")]
  JoinV4(hick_udp::JoinError),

  /// Joining the IPv6 mDNS multicast group failed (`ff02::fb`). See
  /// [`Self::JoinV4`].
  #[error("join v6: {0}")]
  JoinV6(hick_udp::JoinError),

  /// Wrapping the bound socket as an async UDP socket failed.
  #[error("wrap socket: {0}")]
  WrapSocket(std::io::Error),

  /// I/O error during endpoint setup (e.g. setting non-blocking mode).
  #[error(transparent)]
  Io(#[from] std::io::Error),
}

/// Errors raised by
/// [`Endpoint::register_service`](crate::Endpoint::register_service).
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

  /// A future, currently-unknown variant of
  /// [`ProtoRegisterError`](mdns_proto::error::RegisterServiceError) that
  /// the conversion arm did not recognise. The wrapped string is the proto
  /// error's `Display` output so callers can still log it meaningfully.
  ///
  /// Reachable only if `mdns-proto` grows a new `RegisterServiceError`
  /// variant before this crate is updated to map it explicitly.
  #[error("unexpected proto register error: {0}")]
  Other(String),
}

impl From<ProtoRegisterError> for RegisterError {
  fn from(e: ProtoRegisterError) -> Self {
    // `ProtoRegisterError` is `#[non_exhaustive]`, so we MUST keep a
    // catch-all. We enumerate every variant that exists today by name so
    // adding a new proto variant trips a `// future:` review here rather
    // than silently mis-mapping. Unknown future variants surface as
    // [`Self::Other`] — preserving their `Display` — instead of being
    // squashed into [`Self::StorageFull`] (which would lie about the
    // failure mode).
    match e {
      ProtoRegisterError::NameAlreadyRegistered(n) => Self::NameAlreadyRegistered(n),
      ProtoRegisterError::StorageFull(_) => Self::StorageFull,
      // future: map any new ProtoRegisterError variant to a dedicated
      // RegisterError arm here instead of falling through to `Other`.
      other => Self::Other(other.to_string()),
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

/// Errors raised by query cancellation and service unregistration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CancelError {
  /// The driver task is no longer running.
  #[error("endpoint driver is gone")]
  DriverGone,
}

//! Public error types surfaced by the synchronous API.

use mdns_proto::{
  Name,
  error::{RegisterServiceError as ProtoRegisterError, StartQueryError as ProtoStartQueryError},
};

/// Errors raised while constructing an [`Mdns`](crate::Mdns) endpoint.
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

  /// A [`ServerOptions`](crate::ServerOptions) buffer size outside
  /// [`MIN_BUFFER_SIZE`](crate::ServerOptions::MIN_BUFFER_SIZE)`..=`[`MAX_BUFFER_SIZE`](crate::ServerOptions::MAX_BUFFER_SIZE).
  ///
  /// Reported **before any socket is bound**, so a configuration this endpoint
  /// cannot serve costs nothing and leaves nothing behind. `setting` names the
  /// [`ServerOptions`](crate::ServerOptions) setter to correct.
  ///
  /// Both sizes reach an allocation, and both setters take a bare `usize`: an
  /// externally-sourced configuration carrying `usize::MAX` used to abort the
  /// process on a capacity overflow rather than return anything at all.
  #[error("{setting} of {requested} bytes is outside the supported range {min}..={max}")]
  BufferSizeUnsupported {
    /// The [`ServerOptions`](crate::ServerOptions) setter whose value was
    /// refused.
    setting: &'static str,
    /// The size that setter was given.
    requested: usize,
    /// [`ServerOptions::MIN_BUFFER_SIZE`](crate::ServerOptions::MIN_BUFFER_SIZE).
    min: usize,
    /// [`ServerOptions::MAX_BUFFER_SIZE`](crate::ServerOptions::MAX_BUFFER_SIZE).
    max: usize,
  },

  /// The allocator refused one of the endpoint's two scratch buffers.
  ///
  /// Distinct from [`Self::BufferSizeUnsupported`] because the cause is: the
  /// size asked for is one this endpoint would serve, and the machine could not
  /// supply the memory. Reserved fallibly for exactly that reason — the bound
  /// above makes each buffer at most 64 KiB, which is not the same as saying an
  /// allocation of it cannot fail.
  #[error("allocating the {setting} of {requested} bytes failed: {source}")]
  BufferAllocation {
    /// The [`ServerOptions`](crate::ServerOptions) setter that sized the buffer.
    setting: &'static str,
    /// The size that setter was given.
    requested: usize,
    /// What the allocator reported.
    #[source]
    source: std::collections::TryReserveError,
  },

  /// I/O error during endpoint setup (e.g. setting non-blocking mode).
  #[error(transparent)]
  Io(#[from] std::io::Error),
}

/// Errors raised by [`Mdns::register_service`](crate::Mdns::register_service).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegisterError {
  /// A service with the same instance name is already registered.
  #[error("name already registered: {0}")]
  NameAlreadyRegistered(Name),

  /// The proto service pool is full.
  #[error("service pool is full")]
  StorageFull,

  /// [`Mdns::shutdown`](crate::Mdns::shutdown) has been called.
  ///
  /// Every service live at that moment began its RFC 6762 §10.1 goodbye, and
  /// the caller is looping towards [`is_idle`](crate::Mdns::is_idle). A
  /// registration accepted now would advertise a service that nothing will ever
  /// withdraw, so it is refused instead.
  #[error("the endpoint is shutting down")]
  ShuttingDown,

  /// A future, currently-unknown variant of
  /// [`ProtoRegisterError`](mdns_proto::error::RegisterServiceError) that the
  /// conversion arm did not recognise. The wrapped string is the proto error's
  /// `Display` output, so a caller can still log what actually went wrong.
  ///
  /// Reachable only if `mdns-proto` grows a new `RegisterServiceError` variant
  /// before this crate is updated to map it explicitly.
  #[error("unexpected proto register error: {0}")]
  Other(String),
}

impl From<ProtoRegisterError> for RegisterError {
  fn from(e: ProtoRegisterError) -> Self {
    // `ProtoRegisterError` is `#[non_exhaustive]`, so a catch-all is mandatory.
    // Every variant that exists today is enumerated by name, so a new proto
    // variant trips the `// future:` review below instead of being silently
    // mis-mapped. Unknown variants surface as [`Self::Other`] — preserving
    // their `Display` — rather than being squashed into [`Self::StorageFull`],
    // which would tell the caller "the service pool is full" about an unrelated
    // cause and send a caller that retries on it into a loop. Same shape as
    // `hick-compio/src/error.rs`.
    match e {
      ProtoRegisterError::NameAlreadyRegistered(n) => Self::NameAlreadyRegistered(n),
      ProtoRegisterError::StorageFull(_) => Self::StorageFull,
      // future: map any new ProtoRegisterError variant to a dedicated
      // RegisterError arm here instead of falling through to `Other`.
      other => Self::Other(other.to_string()),
    }
  }
}

/// Errors raised by [`Mdns::start_query`](crate::Mdns::start_query) and by the
/// DNS-SD lookups that start sub-queries of their own
/// ([`browse`](crate::Mdns::browse), [`lookup`](crate::Mdns::lookup),
/// [`resolve_host`](crate::Mdns::resolve_host),
/// [`resolve_instance`](crate::Mdns::resolve_instance)).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartQueryError {
  /// The proto query pool is full.
  #[error("query pool is full")]
  StorageFull,

  /// A future, currently-unknown variant of
  /// [`ProtoStartQueryError`](mdns_proto::error::StartQueryError) that the
  /// conversion arm did not recognise. The wrapped string is the proto error's
  /// `Display` output. See [`RegisterError::Other`] for why this exists.
  #[error("unexpected proto start-query error: {0}")]
  Other(String),
}

impl From<ProtoStartQueryError> for StartQueryError {
  fn from(e: ProtoStartQueryError) -> Self {
    // Same rule as `RegisterError`'s conversion: enumerate today's variants by
    // name and preserve an unknown one's `Display` rather than reporting a full
    // query pool that is not full.
    match e {
      ProtoStartQueryError::StorageFull(_) => Self::StorageFull,
      // future: map any new ProtoStartQueryError variant to a dedicated
      // StartQueryError arm here instead of falling through to `Other`.
      other => Self::Other(other.to_string()),
    }
  }
}

/// Failure from [`Mdns::tick`](crate::Mdns::tick).
///
/// Named for the one call that produces it, like every other error type here.
/// A bare `Error` would read as this crate's umbrella error, which it is not:
/// construction fails with [`ServerError`], registration with [`RegisterError`],
/// and query start-up with [`StartQueryError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TickError {
  /// An unrecoverable socket error.
  #[error(transparent)]
  Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests;

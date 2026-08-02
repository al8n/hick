//! Caller-facing endpoint construction options.

use mdns_proto::EndpointConfig;

/// Build-time configuration for an mDNS [`Mdns`](crate::Mdns) endpoint.
///
/// The defaults bind on **one** interface for both IPv4 and IPv6: the first
/// up + multicast-capable, non-loopback interface reported by
/// [`getifs::interfaces`] that has a usable address for each enabled
/// family, falling back to the loopback interface if no other is eligible.
/// Use [`Self::with_interface_index`] to pin a specific interface.
///
/// Multi-interface binding (one socket pair per interface) is not yet
/// supported — callers who need to advertise on several NICs should
/// construct one [`Mdns`](crate::Mdns) per interface.
#[derive(Debug, Clone)]
pub struct ServerOptions {
  pub(crate) ipv4: bool,
  pub(crate) ipv6: bool,
  pub(crate) interface_index: Option<u32>,
  pub(crate) max_payload_size: usize,
  pub(crate) max_recv_packet_size: usize,
  pub(crate) endpoint_config: EndpointConfig,
}

impl Default for ServerOptions {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl ServerOptions {
  /// The smallest [`Self::max_payload_size`] or [`Self::max_recv_packet_size`]
  /// an [`Mdns`](crate::Mdns) will accept: one DNS header.
  ///
  /// A buffer that cannot hold the fixed 12-byte header cannot hold a message
  /// either — nothing could ever be encoded into it or parsed out of it — so it
  /// is refused at construction rather than turned into an endpoint that can
  /// only fail.
  pub const MIN_BUFFER_SIZE: usize = mdns_proto::wire::HEADER_SIZE;

  /// The largest [`Self::max_payload_size`] or [`Self::max_recv_packet_size`] an
  /// [`Mdns`](crate::Mdns) will accept: the biggest UDP payload either address
  /// family can carry.
  ///
  /// A 16-bit IPv6 payload-length field less the 8-byte UDP header, which is 20
  /// bytes above the IPv4 ceiling and therefore the larger of the two. Above it
  /// a datagram cannot exist on any UDP socket, so the extra capacity could
  /// never be filled by a receive nor emptied by a send — while below it the
  /// setting stays useful, including the narrow band an IPv4 socket cannot carry
  /// (see `SendOutcome::TooLarge`).
  ///
  /// It is also what keeps the two buffers a bounded allocation. Both were sized
  /// by an unvalidated `usize` and allocated infallibly, so a configuration
  /// carrying `usize::MAX` — or any size the allocator could not satisfy — ended
  /// the process instead of returning
  /// [`ServerError`](crate::ServerError::BufferSizeUnsupported).
  pub const MAX_BUFFER_SIZE: usize = crate::socket::max_udp_payload(crate::socket::Family::V6);

  /// Build a new options bundle with defaults.
  ///
  /// The single source of truth for those defaults; [`Default`] delegates here.
  #[inline]
  pub const fn new() -> Self {
    Self {
      ipv4: true,
      ipv6: true,
      interface_index: None,
      max_payload_size: 1500,
      max_recv_packet_size: 9000,
      endpoint_config: EndpointConfig::new(),
    }
  }

  /// Whether IPv4 is enabled.
  #[inline]
  pub const fn ipv4(&self) -> bool {
    self.ipv4
  }

  /// Enable or disable IPv4.
  ///
  /// At least one family must remain enabled: with both off,
  /// [`Mdns::new`](crate::Mdns::new) returns
  /// [`ServerError::NoFamilyEnabled`](crate::ServerError::NoFamilyEnabled).
  #[inline]
  #[must_use]
  pub const fn with_ipv4(mut self, enable: bool) -> Self {
    self.ipv4 = enable;
    self
  }

  /// Whether IPv6 is enabled.
  #[inline]
  pub const fn ipv6(&self) -> bool {
    self.ipv6
  }

  /// Enable or disable IPv6. See [`Self::with_ipv4`] on disabling both.
  #[inline]
  #[must_use]
  pub const fn with_ipv6(mut self, enable: bool) -> Self {
    self.ipv6 = enable;
    self
  }

  /// The pinned interface index, if any.
  #[inline]
  pub const fn interface_index(&self) -> Option<u32> {
    self.interface_index
  }

  /// Pin the listener to a specific interface (by OS index). When `None`
  /// (the default), the first multicast-capable, non-loopback interface is
  /// picked.
  #[inline]
  #[must_use]
  pub const fn with_interface_index(mut self, idx: Option<u32>) -> Self {
    self.interface_index = idx;
    self
  }

  /// Maximum outgoing-packet buffer size. RFC 6762 §17 recommends staying
  /// within the path MTU on send (~1500 bytes for Ethernet).
  #[inline]
  pub const fn max_payload_size(&self) -> usize {
    self.max_payload_size
  }

  /// Override the maximum outgoing packet size.
  ///
  /// Must be within [`Self::MIN_BUFFER_SIZE`]`..=`[`Self::MAX_BUFFER_SIZE`].
  /// This setter accepts anything, so that it stays `const`; the bound is
  /// checked by [`Mdns::new`](crate::Mdns::new), which reports
  /// [`ServerError::BufferSizeUnsupported`](crate::ServerError::BufferSizeUnsupported)
  /// before it binds a socket.
  #[inline]
  #[must_use]
  pub const fn with_max_payload_size(mut self, size: usize) -> Self {
    self.max_payload_size = size;
    self
  }

  /// Maximum size of an inbound mDNS datagram that we will fully receive
  /// without truncation. RFC 6762 §17 says implementations MUST be prepared
  /// to receive messages up to 9000 bytes (jumbo-frame-sized) even though
  /// outgoing messages should fit in the path MTU.
  #[inline]
  pub const fn max_recv_packet_size(&self) -> usize {
    self.max_recv_packet_size
  }

  /// Override the recv buffer size. Bounded exactly as
  /// [`Self::with_max_payload_size`] is.
  #[inline]
  #[must_use]
  pub const fn with_max_recv_packet_size(mut self, size: usize) -> Self {
    self.max_recv_packet_size = size;
    self
  }

  /// The proto-layer [`EndpointConfig`].
  #[inline]
  pub const fn endpoint_config(&self) -> &EndpointConfig {
    &self.endpoint_config
  }

  /// Override the proto-layer [`EndpointConfig`].
  #[inline]
  #[must_use]
  pub const fn with_endpoint_config(mut self, cfg: EndpointConfig) -> Self {
    self.endpoint_config = cfg;
    self
  }
}

#[cfg(test)]
mod tests;

//! Caller-facing construction options for [`Endpoint`](crate::Endpoint).
//!
//! Mirrors the public shape of `mdns-reactor::ServerOptions` so callers can
//! move between the two crates without re-learning the surface.

use mdns_proto::EndpointConfig;

/// Build-time configuration for an mDNS [`Endpoint`](crate::Endpoint).
///
/// The defaults bind on **one** interface for both IPv4 and IPv6: the first
/// up + multicast-capable, non-loopback interface reported by
/// [`getifs::interfaces`] that has a usable address for each enabled family,
/// falling back to the loopback interface if no other is eligible. Use
/// [`Self::with_interface_index`] to pin a specific interface.
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
  /// Build a new options bundle with defaults.
  #[inline]
  pub fn new() -> Self {
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

  /// Whether IPv6 is enabled.
  #[inline]
  pub const fn ipv6(&self) -> bool {
    self.ipv6
  }

  /// The pinned interface index, if any.
  #[inline]
  pub const fn interface_index(&self) -> Option<u32> {
    self.interface_index
  }

  /// Maximum outgoing-packet buffer size. RFC 6762 §17 recommends staying
  /// within the path MTU on send (~1500 bytes for Ethernet).
  #[inline]
  pub const fn max_payload_size(&self) -> usize {
    self.max_payload_size
  }

  /// Maximum size of an inbound mDNS datagram that we will fully receive
  /// without truncation. RFC 6762 §17 says implementations MUST be prepared
  /// to receive messages up to 9000 bytes.
  #[inline]
  pub const fn max_recv_packet_size(&self) -> usize {
    self.max_recv_packet_size
  }

  /// The proto-layer [`EndpointConfig`].
  #[inline]
  pub const fn endpoint_config(&self) -> &EndpointConfig {
    &self.endpoint_config
  }

  /// Enable or disable IPv4. At least one of v4/v6 must remain enabled.
  #[inline]
  #[must_use]
  pub const fn with_ipv4(mut self, enable: bool) -> Self {
    self.ipv4 = enable;
    self
  }

  /// Enable or disable IPv6.
  #[inline]
  #[must_use]
  pub const fn with_ipv6(mut self, enable: bool) -> Self {
    self.ipv6 = enable;
    self
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

  /// Override the maximum outgoing-packet buffer size.
  #[inline]
  #[must_use]
  pub const fn with_max_payload_size(mut self, size: usize) -> Self {
    self.max_payload_size = size;
    self
  }

  /// Override the inbound receive buffer size.
  #[inline]
  #[must_use]
  pub const fn with_max_recv_packet_size(mut self, size: usize) -> Self {
    self.max_recv_packet_size = size;
    self
  }

  /// Override the proto-layer [`EndpointConfig`].
  #[inline]
  #[must_use]
  pub fn with_endpoint_config(mut self, cfg: EndpointConfig) -> Self {
    self.endpoint_config = cfg;
    self
  }
}

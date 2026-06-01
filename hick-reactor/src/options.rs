//! Caller-facing endpoint construction options.

use mdns_proto::EndpointConfig;

/// Build-time configuration for an mDNS [`Endpoint`](crate::Endpoint).
///
/// The defaults bind on **one** interface for both IPv4 and IPv6: the first
/// up + multicast-capable, non-loopback interface reported by
/// [`getifs::interfaces`] that has a usable address for each enabled
/// family, falling back to the loopback interface if no other is eligible.
/// Use [`Self::with_interface_index`] to pin a specific interface.
///
/// Multi-interface binding (one socket pair per interface) is not yet
/// supported — callers who need to advertise on several NICs should
/// construct one [`Endpoint`](crate::Endpoint) per interface.
#[derive(Debug, Clone)]
pub struct ServerOptions {
  pub(crate) ipv4: bool,
  pub(crate) ipv6: bool,
  pub(crate) interface_index: Option<u32>,
  pub(crate) max_payload_size: usize,
  pub(crate) max_recv_packet_size: usize,
  pub(crate) update_channel_capacity: usize,
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
      update_channel_capacity: 64,
      endpoint_config: EndpointConfig::new(),
    }
  }

  /// Whether IPv4 is enabled.
  #[inline]
  pub const fn ipv4(&self) -> bool {
    self.ipv4
  }

  /// Disable IPv4. At least one of v4/v6 must remain enabled.
  #[inline]
  pub fn with_ipv4(mut self, enable: bool) -> Self {
    self.ipv4 = enable;
    self
  }

  /// Whether IPv6 is enabled.
  #[inline]
  pub const fn ipv6(&self) -> bool {
    self.ipv6
  }

  /// Disable IPv6.
  #[inline]
  pub fn with_ipv6(mut self, enable: bool) -> Self {
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
  pub fn with_interface_index(mut self, idx: Option<u32>) -> Self {
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
  #[inline]
  pub fn with_max_payload_size(mut self, size: usize) -> Self {
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

  /// Override the recv buffer size.
  #[inline]
  pub fn with_max_recv_packet_size(mut self, size: usize) -> Self {
    self.max_recv_packet_size = size;
    self
  }

  /// Capacity of the per-handle update channel that the driver writes to.
  ///
  /// **Deprecated**: per-handle channels are now unbounded
  /// so that critical events (Established/Renamed/Conflict/HostConflict/
  /// Terminal) cannot be silently dropped under backpressure. This value
  /// is preserved for API compatibility but has no effect.
  #[inline]
  #[deprecated(note = "per-handle channels are unbounded; this setting has no effect")]
  pub const fn update_channel_capacity(&self) -> usize {
    self.update_channel_capacity
  }

  /// Override the per-handle update channel capacity. **No-op** —
  /// see [`Self::update_channel_capacity`].
  #[inline]
  #[deprecated(note = "per-handle channels are unbounded; this setting has no effect")]
  pub fn with_update_channel_capacity(mut self, cap: usize) -> Self {
    self.update_channel_capacity = cap;
    self
  }

  /// The proto-layer [`EndpointConfig`].
  #[inline]
  pub const fn endpoint_config(&self) -> &EndpointConfig {
    &self.endpoint_config
  }

  /// Override the proto-layer [`EndpointConfig`].
  #[inline]
  pub fn with_endpoint_config(mut self, cfg: EndpointConfig) -> Self {
    self.endpoint_config = cfg;
    self
  }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
  use mdns_proto::EndpointConfig;

  use super::ServerOptions;

  #[test]
  fn builders_and_accessors_roundtrip() {
    let o = ServerOptions::default()
      .with_ipv4(false)
      .with_ipv6(true)
      .with_interface_index(Some(3))
      .with_max_payload_size(1400)
      .with_max_recv_packet_size(8000)
      .with_update_channel_capacity(128)
      .with_endpoint_config(EndpointConfig::new());
    assert!(!o.ipv4());
    assert!(o.ipv6());
    assert_eq!(o.interface_index(), Some(3));
    assert_eq!(o.max_payload_size(), 1400);
    assert_eq!(o.max_recv_packet_size(), 8000);
    assert_eq!(o.update_channel_capacity(), 128); // deprecated no-op getter
    let _ = o.endpoint_config();
  }
}

//! Caller-facing construction options for [`Endpoint`](crate::Endpoint).
//!
//! Mirrors the public shape of `hick-reactor::ServerOptions` so callers can
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
  ///
  /// # This is not an isolation guarantee on every platform
  ///
  /// Both mDNS sockets are wildcard bound — they must be, to receive traffic
  /// addressed to a multicast group — so the kernel delivers every interface's
  /// port-5353 traffic to them and the RFC 6762 §11 ingress boundary is what
  /// scopes it back to this index. That boundary can only do so where the
  /// receive path recovers the datagram's provenance: an interface index or an
  /// IPv6 scope id. Where it does, traffic from another interface is refused
  /// outright.
  ///
  /// It does NOT where the path recovers none: IPv4 on FreeBSD, DragonFly,
  /// OpenBSD and NetBSD, and on **Windows**, where this crate's receive path is
  /// a plain `recv_from` that recovers no ancillary data.
  ///
  /// Windows is split by source rather than uniform, and it is worth being
  /// exact: `recv_from` still recovers the peer `sockaddr_in6`, and Windows
  /// fills `sin6_scope_id` from the receiving interface for a link-local
  /// address. A link-local IPv6 peer therefore IS witnessed and fully isolated
  /// there; a scopeless IPv6 peer and every IPv4 peer are not.
  ///
  /// On those squares admission falls back to RFC 6762 §11's own source rules,
  /// which weigh values the SENDER controls. An adjacent sender that sources
  /// from inside this interface's prefix is admitted, as is a second NIC
  /// sharing that prefix — legitimately. The exposure is narrowed, not removed,
  /// and no rule over those inputs could remove it.
  ///
  /// Whether §11's group arm is available there is a separate question and the
  /// two do not move together: it needs a recovered IP header destination or the
  /// kernel's multicast flag. Where both are absent, group traffic §11 requires
  /// be accepted is refused whenever the sender's prefix is not one of ours.
  ///
  /// The boundary is a STAGED decision and no summary of two of its inputs
  /// describes it — an interface index of zero means opposite things depending
  /// on whether this path could have supplied one. The inbound TTL decides
  /// nothing: §11's receive test is stated exhaustively and both ways are about
  /// the destination address. [`hick_udp::onlink`] states the stages in order
  /// and what each receive path supplies.
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

#[cfg(test)]
mod tests;

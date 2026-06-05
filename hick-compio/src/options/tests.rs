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
    .with_endpoint_config(EndpointConfig::new());
  assert!(!o.ipv4());
  assert!(o.ipv6());
  assert_eq!(o.interface_index(), Some(3));
  assert_eq!(o.max_payload_size(), 1400);
  assert_eq!(o.max_recv_packet_size(), 8000);
  let _ = o.endpoint_config();
}

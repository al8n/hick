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

#[test]
fn defaults_match_documented_values() {
  let o = ServerOptions::new();
  assert!(o.ipv4());
  assert!(o.ipv6());
  assert_eq!(o.interface_index(), None);
  assert_eq!(o.max_payload_size(), 1500);
  assert_eq!(o.max_recv_packet_size(), 9000);
}

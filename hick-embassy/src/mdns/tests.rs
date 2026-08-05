use embassy_net::{IpAddress, IpCidr};
use mdns_proto::{
  EndpointConfig, Name, QuerySpec, ServiceRecords, ServiceSpec, wire::ResourceType,
};
use rand::{SeedableRng, rngs::StdRng};

use super::MdnsState;

fn state() -> MdnsState<StdRng> {
  MdnsState::new(EndpointConfig::new(), StdRng::seed_from_u64(7))
}

/// Drives the synchronous handle API (everything except the async `run` loop,
/// which needs a network `Stack`). Each call exercises the `RefCell<Engine>` +
/// wake-`Signal` delegation; `now()` resolves via the dev-only embassy-time driver.
#[test]
fn handle_api_register_query_poll_cancel() {
  let s = state();
  s.set_local_addrs(&[IpCidr::new(IpAddress::v4(192, 168, 1, 10), 24)]);

  let mut recs = ServiceRecords::new(
    Name::try_from_str("_http._tcp.local.").unwrap(),
    Name::try_from_str("Dev._http._tcp.local.").unwrap(),
    Name::try_from_str("dev.local.").unwrap(),
    80,
    120,
  );
  recs.add_a([192, 168, 1, 10].into());
  let sh = s.register_service(ServiceSpec::new(recs)).unwrap();
  let _ = s.poll_service_update(sh);

  let qh = s
    .start_query(QuerySpec::new(
      Name::try_from_str("_http._tcp.local.").unwrap(),
      ResourceType::Ptr,
    ))
    .unwrap();
  let _ = s.poll_query_update(qh);
  assert!(s.collected_answers(qh).is_empty());
  assert_eq!(s.query_accepted_count(qh), Some(0));
  let _ = s.poll_endpoint_event();

  s.cancel_query(qh);
  s.unregister_service(sh);
}

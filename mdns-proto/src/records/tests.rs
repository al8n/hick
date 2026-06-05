use super::*;

#[test]
fn build_and_inspect() {
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let i = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  let h = Name::try_from_str("my-host.local.").unwrap();
  let mut r = ServiceRecords::new(stype, i.clone(), h.clone(), 631, 120);
  r.add_a(Ipv4Addr::new(192, 168, 1, 10));
  r.add_txt_segment(b"path=/printer".to_vec());
  assert_eq!(r.port(), 631);
  assert_eq!(r.a_addrs_slice().len(), 1);
  assert_eq!(r.txt_segments().count(), 1);
  assert_eq!(r.service_type().as_str(), "_ipp._tcp.local.");
  assert_eq!(r.instance().as_str(), "myprinter._ipp._tcp.local.");
  assert_eq!(r.host().as_str(), "my-host.local.");
}

#[test]
fn srv_field_setters_update_fields() {
  let mut r = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("P._ipp._tcp.local.").unwrap(),
    Name::try_from_str("h.local.").unwrap(),
    631,
    120,
  );
  r.set_priority(5).set_weight(7).set_ttl_secs(45);
  assert_eq!(r.priority(), 5);
  assert_eq!(r.weight(), 7);
  assert_eq!(r.ttl_secs(), 45);
}

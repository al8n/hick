use std::collections::HashSet;

use super::*;

#[test]
fn push_capped_dedups_and_bounds() {
  let mut v: Vec<u32> = Vec::new();
  for i in 0..(MAX_ADDRS_PER_HOST as u32 + 8) {
    push_capped(&mut v, i);
  }
  assert_eq!(v.len(), MAX_ADDRS_PER_HOST);
  let added = push_capped(&mut v, 0); // duplicate
  assert!(!added);
}

#[test]
fn fold_lowercases_ascii() {
  let n = mdns_proto::Name::try_from_str("Foo.Local.").unwrap();
  assert_eq!(fold(&n), "foo.local.");
}

/// Encode a single label sequence as a decompressed wire-form name.
fn wire_name(labels: &[&[u8]]) -> Vec<u8> {
  let mut out = Vec::new();
  for l in labels {
    out.push(u8::try_from(l.len()).unwrap());
    out.extend_from_slice(l);
  }
  out.push(0);
  out
}

fn ptr_rdata(labels: &[&[u8]]) -> Vec<u8> {
  wire_name(labels)
}

fn srv_rdata(port: u16, host: &[&[u8]]) -> Vec<u8> {
  let mut out = Vec::new();
  out.extend_from_slice(&0u16.to_be_bytes()); // priority
  out.extend_from_slice(&0u16.to_be_bytes()); // weight
  out.extend_from_slice(&port.to_be_bytes());
  out.extend_from_slice(&wire_name(host));
  out
}

#[test]
fn name_reconstruction_rejects_unrepresentable_labels() {
  // Plain ASCII labels round-trip (case-folded).
  assert_eq!(
    parse_name(&ptr_rdata(&[b"MyPrinter", b"_ipp", b"_tcp", b"local"]))
      .unwrap()
      .as_str(),
    "myprinter._ipp._tcp.local."
  );
  // A label containing a literal '.' cannot be represented — skip it.
  assert!(parse_name(&ptr_rdata(&[b"weird.name", b"_tcp", b"local"])).is_none());
  // A non-ASCII (UTF-8) label cannot round-trip through `Name` — skip it.
  assert!(parse_name(&ptr_rdata(&[b"caf\xc3\xa9", b"local"])).is_none());
}

#[test]
fn flood_is_capped_and_observable() {
  let mut r = Resolver::new(2);
  let mk = |n: &str| Name::try_from_str(n).unwrap();
  assert_eq!(r.on_ptr(mk("a._x._tcp.local.")).len(), 2); // SRV + TXT
  assert_eq!(r.on_ptr(mk("b._x._tcp.local.")).len(), 2);
  // Third instance is over the cap: no follow-ups, counted as dropped.
  assert!(r.on_ptr(mk("c._x._tcp.local.")).is_empty());
  assert_eq!(r.builders.len(), 2);
  assert_eq!(r.dropped, 1);
  // A duplicate of an existing instance is ignored without counting a drop.
  assert!(r.on_ptr(mk("a._x._tcp.local.")).is_empty());
  assert_eq!(r.dropped, 1);
}

#[test]
fn shared_host_srv_after_a_still_resolves() {
  // Two instances share one host. The host's A answer arrives BEFORE the
  // second instance's SRV — the second instance must still pick up the
  // address from the host cache and complete.
  let mut r = Resolver::new(16);
  let i1 = Name::try_from_str("i1._x._tcp.local.").unwrap();
  let i2 = Name::try_from_str("i2._x._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let k1 = fold(&i1);
  let k2 = fold(&i2);
  let hk = fold(&host);

  r.on_ptr(i1);
  r.on_ptr(i2);
  // i1 resolves: host + port, then its host gets an address.
  r.on_srv(&k1, host.clone(), 8080);
  r.on_txt(&k1, vec![b"a=1".to_vec().into()]);
  r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
  // i1 is now complete.
  let first = r.take_ready().expect("i1 should complete");
  assert_eq!(first.instance_name().as_str(), "i1._x._tcp.local.");
  assert_eq!(first.ipv4_addresses(), [Ipv4Addr::new(10, 0, 0, 1)]);

  // i2's SRV arrives AFTER the A answer. It must adopt the cached address.
  r.on_srv(&k2, host, 8081);
  r.on_txt(&k2, vec![b"b=2".to_vec().into()]);
  let second = r
    .take_ready()
    .expect("i2 should complete from the host cache");
  assert_eq!(second.instance_name().as_str(), "i2._x._tcp.local.");
  assert_eq!(second.port(), 8081);
  assert_eq!(second.ipv4_addresses(), [Ipv4Addr::new(10, 0, 0, 1)]);
}

#[test]
fn srv_parse_extracts_host_and_port() {
  let (host, port) = parse_srv(&srv_rdata(631, &[b"printer", b"local"])).unwrap();
  assert_eq!(host.as_str(), "printer.local.");
  assert_eq!(port, 631);
}

#[test]
fn entry_incomplete_without_address_or_port_or_txt() {
  let mut r = Resolver::new(16);
  let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let k = fold(&inst);
  let hk = fold(&host);
  r.on_ptr(inst);
  // Only an address + port, no TXT yet → not complete.
  r.on_srv(&k, host, 9000);
  r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
  assert!(r.take_ready().is_none(), "must not emit without TXT");
  // TXT arrives → now complete.
  r.on_txt(&k, vec![Bytes::new()]); // empty TXT (single empty segment) counts
  assert!(r.take_ready().is_some(), "complete once TXT present");
}

#[test]
fn address_fans_out_to_all_instances_on_shared_host() {
  // Three instances share one host; the host's single A answer must complete
  // all of them (each already had SRV + TXT).
  let mut r = Resolver::new(16);
  let host = Name::try_from_str("h.local.").unwrap();
  let hk = fold(&host);
  for label in ["i1", "i2", "i3"] {
    let inst = Name::try_from_str(&format!("{label}._x._tcp.local.")).unwrap();
    let k = fold(&inst);
    r.on_ptr(inst);
    r.on_srv(&k, host.clone(), 7000);
    r.on_txt(&k, vec![b"k=v".to_vec().into()]);
  }
  assert!(
    r.take_ready().is_none(),
    "incomplete until an address arrives"
  );
  r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
  let mut emitted = HashSet::new();
  while let Some(e) = r.take_ready() {
    assert_eq!(e.ipv4_addresses(), [Ipv4Addr::new(192, 0, 2, 1)]);
    emitted.insert(e.instance_name().as_str().to_owned());
  }
  assert_eq!(emitted.len(), 3, "all three shared-host instances resolve");
}

#[test]
fn late_address_reemits_updated_entry() {
  // An entry first surfaces on its A address; a later AAAA re-emits it with
  // the fuller address set rather than being dropped.
  let mut r = Resolver::new(16);
  let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let k = fold(&inst);
  let hk = fold(&host);
  r.on_ptr(inst);
  r.on_srv(&k, host, 7000);
  r.on_txt(&k, vec![b"k=v".to_vec().into()]);
  r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
  let first = r.take_ready().expect("first emit on A");
  assert_eq!(first.ipv4_addresses().len(), 1);
  assert!(first.ipv6_addresses().is_empty());
  // Late AAAA → re-emit with both families.
  r.on_addr(&hk, IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
  let second = r.take_ready().expect("re-emit on late AAAA");
  assert_eq!(second.ipv4_addresses().len(), 1);
  assert_eq!(second.ipv6_addresses().len(), 1);
  // A duplicate address must NOT re-emit again.
  r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
  assert!(
    r.take_ready().is_none(),
    "duplicate address must not re-emit"
  );
}

#[test]
fn addresses_capped_per_host() {
  // A responder flooding distinct A records for one host cannot grow the
  // address vector past MAX_ADDRS_PER_HOST.
  let mut r = Resolver::new(16);
  let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let k = fold(&inst);
  let hk = fold(&host);
  r.on_ptr(inst);
  r.on_srv(&k, host, 7000);
  r.on_txt(&k, vec![b"k=v".to_vec().into()]);
  for i in 0..(MAX_ADDRS_PER_HOST as u32 + 8) {
    let o = i.to_be_bytes();
    r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(10, o[1], o[2], o[3])));
  }
  let mut last = None;
  while let Some(e) = r.take_ready() {
    last = Some(e);
  }
  assert_eq!(
    last.expect("at least one emit").ipv4_addresses().len(),
    MAX_ADDRS_PER_HOST
  );
}

#[test]
fn srv_target_flood_is_capped() {
  // One instance whose SRV target host changes on every answer (a hostile or
  // pathological responder) must not grow the host-query set without bound.
  let mut r = Resolver::new(4); // max_hosts == max_entries == 4
  let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
  let k = fold(&inst);
  r.on_ptr(inst);
  let mut launched = 0usize;
  for i in 0..20u16 {
    let host = Name::try_from_str(&format!("h{i}.local.")).unwrap();
    launched += r.on_srv(&k, host, 8000 + i).len();
  }
  // At most max_hosts distinct hosts get A+AAAA launches (2 starts each).
  assert_eq!(r.hosts_queried.len(), 4);
  assert_eq!(r.host_addrs.len(), 0, "no addresses arrived yet");
  assert_eq!(launched, 4 * 2);
  // The 16 over-cap target hosts are counted so the partial view is observable.
  assert_eq!(r.dropped, 16);
}

#[test]
fn srv_retarget_drops_old_host_addresses() {
  // An instance first resolves on host h1 (address A1). A later SRV retargets
  // it to host h2; once h2's address arrives, the re-emitted entry must carry
  // h2 and ONLY h2's address — never the stale h1 address.
  let mut r = Resolver::new(16);
  let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
  let h1 = Name::try_from_str("h1.local.").unwrap();
  let h2 = Name::try_from_str("h2.local.").unwrap();
  let k = fold(&inst);
  let hk1 = fold(&h1);
  let hk2 = fold(&h2);
  r.on_ptr(inst);
  r.on_srv(&k, h1, 8000);
  r.on_txt(&k, vec![b"k=v".to_vec().into()]);
  r.on_addr(&hk1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
  let first = r.take_ready().expect("resolves on h1");
  assert_eq!(first.host().as_str(), "h1.local.");
  assert_eq!(first.ipv4_addresses(), [Ipv4Addr::new(10, 0, 0, 1)]);

  // Retarget to h2; the old h1 address must be dropped immediately.
  r.on_srv(&k, h2, 8000);
  // h2's address arrives → re-emit with h2 and only the h2 address.
  r.on_addr(&hk2, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
  let second = r.take_ready().expect("re-emits on h2 address");
  assert_eq!(second.host().as_str(), "h2.local.");
  assert_eq!(
    second.ipv4_addresses(),
    [Ipv4Addr::new(10, 0, 0, 2)],
    "stale h1 address must not survive the retarget"
  );
}

#[test]
fn srv_port_zero_still_completes() {
  // Port 0 is a valid SRV port; an instance advertising it must still surface
  // once it has SRV (presence), TXT, and an address — `0` is not a "missing
  // SRV" sentinel.
  let mut r = Resolver::new(16);
  let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let k = fold(&inst);
  let hk = fold(&host);
  r.on_ptr(inst);
  r.on_srv(&k, host, 0);
  r.on_txt(&k, vec![b"k=v".to_vec().into()]);
  r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
  let e = r
    .take_ready()
    .expect("an SRV with port 0 must still complete");
  assert_eq!(e.port(), 0);
  assert_eq!(e.ipv4_addresses(), [Ipv4Addr::new(10, 0, 0, 1)]);
}

#[test]
fn txt_change_after_emit_reemits() {
  // A TXT update after the instance was surfaced must re-emit with the new
  // metadata (a responder may refresh TXT while the lookup is still running);
  // a duplicate TXT must not.
  let mut r = Resolver::new(16);
  let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let k = fold(&inst);
  let hk = fold(&host);
  r.on_ptr(inst);
  r.on_srv(&k, host, 7000);
  r.on_txt(&k, vec![b"v=1".to_vec().into()]);
  r.on_addr(&hk, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
  let first = r.take_ready().expect("first emit");
  assert_eq!(first.txt(), [Bytes::from_static(b"v=1")]);
  // Changed TXT → re-emit with the new metadata.
  r.on_txt(&k, vec![b"v=2".to_vec().into()]);
  let second = r.take_ready().expect("re-emit on TXT change");
  assert_eq!(second.txt(), [Bytes::from_static(b"v=2")]);
  // Duplicate TXT → no re-emit.
  r.on_txt(&k, vec![b"v=2".to_vec().into()]);
  assert!(r.take_ready().is_none(), "duplicate TXT must not re-emit");
}

#[test]
fn srv_retarget_to_cached_host_reemits() {
  // An already-emitted instance retargets to a host whose addresses are
  // ALREADY cached (shared with another instance). No fresh A/AAAA event will
  // arrive, so the SRV change itself must re-emit the new host/port + adopted
  // address rather than leaving the consumer with a stale entry.
  let mut r = Resolver::new(16);
  let i1 = Name::try_from_str("i1._x._tcp.local.").unwrap();
  let i2 = Name::try_from_str("i2._x._tcp.local.").unwrap();
  let shared = Name::try_from_str("shared.local.").unwrap();
  let other = Name::try_from_str("other.local.").unwrap();
  let k1 = fold(&i1);
  let k2 = fold(&i2);
  let shk = fold(&shared);
  let ohk = fold(&other);

  // i1 resolves on `shared`, populating the host-address cache.
  r.on_ptr(i1);
  r.on_srv(&k1, shared.clone(), 8000);
  r.on_txt(&k1, vec![b"a=1".to_vec().into()]);
  r.on_addr(&shk, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
  r.take_ready().expect("i1 resolves on shared");

  // i2 first resolves on a DIFFERENT host.
  r.on_ptr(i2);
  r.on_srv(&k2, other, 9000);
  r.on_txt(&k2, vec![b"b=2".to_vec().into()]);
  r.on_addr(&ohk, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)));
  let i2_first = r.take_ready().expect("i2 resolves on other");
  assert_eq!(i2_first.host().as_str(), "other.local.");

  // i2's SRV now retargets to `shared` (already cached, already queried).
  let starts = r.on_srv(&k2, shared, 9001);
  assert!(
    starts.is_empty(),
    "shared host already queried — no new A/AAAA launched"
  );
  let i2_re = r
    .take_ready()
    .expect("i2 must re-emit on the cached host without a fresh address event");
  assert_eq!(i2_re.host().as_str(), "shared.local.");
  assert_eq!(i2_re.port(), 9001);
  assert_eq!(
    i2_re.ipv4_addresses(),
    [Ipv4Addr::new(10, 0, 0, 9)],
    "adopts the shared host's cached address, not the stale one"
  );
}

#[test]
fn srv_txt_mutation_after_emit_stays_bounded() {
  // After an instance is surfaced, further SRV/TXT answers (new target hosts,
  // changed metadata) must not grow the host-query set past the cap or panic.
  let mut r = Resolver::new(2); // max_hosts == 2
  let inst = Name::try_from_str("i._x._tcp.local.").unwrap();
  let h1 = Name::try_from_str("h1.local.").unwrap();
  let k = fold(&inst);
  let hk1 = fold(&h1);
  r.on_ptr(inst);
  r.on_srv(&k, h1, 8000);
  r.on_txt(&k, vec![b"k=v".to_vec().into()]);
  r.on_addr(&hk1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
  assert!(r.take_ready().is_some(), "instance completes on h1");

  // SRV now mutates to a flood of new target hosts, and TXT keeps changing.
  for i in 0..10u16 {
    let h = Name::try_from_str(&format!("m{i}.local.")).unwrap();
    r.on_srv(&k, h, 9000 + i);
    r.on_txt(&k, vec![format!("v={i}").into_bytes().into()]);
  }
  // h1 took one host slot; at most one more (cap 2) is ever queried.
  assert!(r.hosts_queried.len() <= 2, "host set stays bounded");
  assert!(r.host_addrs.len() <= 2, "host cache stays bounded");
}

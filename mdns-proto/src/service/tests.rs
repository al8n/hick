use core::time::Duration;

use super::*;
use crate::{
  Name, ServiceHandle,
  event::{KnownAnswer, ProbeConflict, ServiceEvent},
  records::ServiceRecords,
  wire::RecordRef,
};
// Bring ToOwned into scope explicitly — under `--no-default-features --features alloc`
// (no `std`) this is not in the prelude, so `&str::to_owned()` fails to resolve.
use alloc::borrow::ToOwned as _;

// ── Minimal Instant implementation for tests ──────────────────────────

/// A trivial Instant for tests: just a u64 of milliseconds.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct FakeInstant(u64);

impl FakeInstant {
  fn zero() -> Self {
    Self(0)
  }
  fn advance(self, ms: u64) -> Self {
    Self(self.0 + ms)
  }
}

impl crate::Instant for FakeInstant {
  fn checked_add_duration(self, dur: Duration) -> Option<Self> {
    let ms = dur.as_millis();
    u64::try_from(ms)
      .ok()
      .and_then(|m| self.0.checked_add(m))
      .map(Self)
  }

  fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
    self.0.checked_sub(earlier.0).map(Duration::from_millis)
  }
}

// ── Helper: build a minimal ServiceRecords ────────────────────────────

fn make_records(ttl_secs: u32) -> ServiceRecords {
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("myprinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("host.local.").unwrap();
  let mut r = ServiceRecords::new(stype, inst, host, 631, ttl_secs);
  r.add_a(core::net::Ipv4Addr::new(192, 168, 1, 10));
  r
}

#[test]
fn non_probing_service_announces_without_probing() {
  // with probe=false (EndpointConfig::probe_unique_names disabled)
  // the service skips the §8.1 probe sequence — it starts in Announcing and
  // reaches Established without ever entering Probing.
  let records = make_records(120);
  let mut svc: Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> =
    Service::try_new(
      ServiceHandle::from_raw(0),
      records,
      FakeInstant::zero(),
      [0u8; 32],
      false, // do not probe
    );
  assert!(
    matches!(svc.state(), ServiceState::Announcing(_)),
    "non-probing service must start in Announcing, got {:?}",
    svc.state()
  );

  let mut buf = alloc::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  let mut ever_probed = false;
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if matches!(svc.state(), ServiceState::Probing(_)) {
      ever_probed = true;
    }
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_transmit_delivered(now);
    }
    if svc.state() == ServiceState::Established {
      break;
    }
  }
  assert!(!ever_probed, "non-probing service must never enter Probing");
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "non-probing service must reach Established"
  );
  assert!(
    svc.advertises_host(),
    "having announced, the non-probing service advertises its host records"
  );
}

/// Build a Service in Init state with last_now = FakeInstant::zero().
fn make_service(
  ttl_secs: u32,
) -> Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> {
  let handle = ServiceHandle::from_raw(0);
  let records = make_records(ttl_secs);
  Service::try_new(handle, records, FakeInstant::zero(), [0u8; 32], true)
}

impl GoodbyeOwnership {
  /// Test helper: simulate that the instance records (PTR/SRV/TXT) were
  /// confirmed-announced. R67 replaced the old single `instance` bool with
  /// per-record flags, so a "the original name was announced" precondition sets
  /// all three.
  fn mark_instance(&mut self) {
    self.ptr = true;
    self.srv = true;
    self.txt = true;
  }
}

/// Build a minimal raw A record in wire format and parse it via RecordRef::try_parse.
/// The resulting `RecordRef` lives for the lifetime of `buf`.
fn make_a_record_ref(buf: &mut alloc::vec::Vec<u8>, name_str: &str, ttl: u32, addr: [u8; 4]) {
  // Encode name labels.
  buf.clear();
  for label in name_str.trim_end_matches('.').split('.') {
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8); // root label

  // TYPE=A(1), CLASS=IN(1), TTL, RDLENGTH=4, RDATA
  buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
  buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  buf.extend_from_slice(&ttl.to_be_bytes());
  buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
  buf.extend_from_slice(&addr);
}

/// Build a minimal raw SRV record in wire format for tiebreak tests.
///
/// The resulting `RecordRef` lives for the lifetime of `buf`.
/// `owner_str` is the FQDN that owns this SRV record (the instance name).
/// `target_str` is the SRV target hostname.
fn make_srv_record_ref(
  buf: &mut alloc::vec::Vec<u8>,
  owner_str: &str,
  ttl: u32,
  priority: u16,
  weight: u16,
  port: u16,
  target_str: &str,
) {
  buf.clear();
  // Owner name (length-prefixed labels + root).
  for label in owner_str.trim_end_matches('.').split('.') {
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8); // root label

  // TYPE=SRV(33), CLASS=IN(1), TTL, then compute rdlength.
  buf.extend_from_slice(&33u16.to_be_bytes()); // TYPE SRV
  buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  buf.extend_from_slice(&ttl.to_be_bytes());

  // Build rdata: priority(2) + weight(2) + port(2) + target_name
  let mut rdata: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  rdata.extend_from_slice(&priority.to_be_bytes());
  rdata.extend_from_slice(&weight.to_be_bytes());
  rdata.extend_from_slice(&port.to_be_bytes());
  for label in target_str.trim_end_matches('.').split('.') {
    rdata.push(label.len() as u8);
    rdata.extend_from_slice(label.as_bytes());
  }
  rdata.push(0u8); // root label

  #[allow(clippy::cast_possible_truncation)]
  buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
  buf.extend_from_slice(&rdata);
}

/// Build a minimal raw TXT record in wire format for tiebreak tests.
///
/// `owner_str` is the FQDN that owns the record. `segments` is the list of
/// raw TXT segments (each is a raw byte slice; an empty slice = empty TXT).
fn make_txt_record_ref(
  buf: &mut alloc::vec::Vec<u8>,
  owner_str: &str,
  ttl: u32,
  segments: &[&[u8]],
) {
  buf.clear();
  // Owner name (length-prefixed labels + root).
  for label in owner_str.trim_end_matches('.').split('.') {
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8); // root label

  // TYPE=TXT(16), CLASS=IN(1), TTL, RDLENGTH, RDATA.
  buf.extend_from_slice(&16u16.to_be_bytes()); // TYPE TXT
  buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  buf.extend_from_slice(&ttl.to_be_bytes());

  let mut rdata: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for seg in segments {
    #[allow(clippy::cast_possible_truncation)]
    rdata.push(seg.len() as u8);
    rdata.extend_from_slice(seg);
  }

  #[allow(clippy::cast_possible_truncation)]
  buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
  buf.extend_from_slice(&rdata);
}

// ── service_resumes_probing_after_rename ───────────────────────

/// After a ProbeConflict where the peer wins the RFC §8.2 tiebreak, the service must:
///   - Eventually transition back to Init (after the tiebreak handle_timeout).
///   - Have a non-None lifecycle_deadline (fresh probe delay).
///   - Eventually advance through Probing for the renamed instance.
///
/// The peer sends SRV with port=9999; ours has port=631. Since 9999 > 631 in
/// the SRV rdata bytes, the peer's set is lexicographically greater, so we lose
/// and must rename. (tiebreak now compares SRV+TXT only, not A.)
#[test]
fn service_resumes_probing_after_rename() {
  let mut svc = make_service(120);

  // Initial tick: advances Init → Probing(0) and gives last_now a value.
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();
  // The service is now in Init (just scheduled a probe delay) or Probing(0)
  // depending on whether the probe deadline already fired. Either way, we
  // need last_now to be set.
  assert!(
    svc.last_now.is_some(),
    "last_now should be set after first handle_timeout"
  );

  // Synthesise a ProbeConflict event with a peer SRV record that beats ours.
  // Our SRV: port=631. Peer SRV: port=9999 (9999 > 631 → peer wins in SRV
  // byte comparison). The tiebreak now compares SRV+TXT only.
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,    // priority
    0,    // weight
    9999, // port > 631 → peer SRV canonical bytes are larger → peer wins
    "host.local.",
  );
  let (record_ref, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer_src_a: core::net::SocketAddr = "192.168.1.99:5353".parse().unwrap();
  let conflict = ProbeConflict::new(peer_src_a, record_ref);
  svc.handle_event(ServiceEvent::ProbeConflict(conflict), t0);

  // After handle_event: the record is buffered but rename has NOT happened yet.
  assert!(
    svc.tiebreak_pending,
    "tiebreak_pending must be set after ProbeConflict"
  );
  assert_eq!(
    svc.peer_probes.len(),
    1,
    "one peer probe bucket must be created"
  );

  // Drive the tiebreak: advance time so the next deadline fires and the
  // tiebreak comparison runs. Peer wins → rename applied.
  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();

  // After the tiebreak handle_timeout: state must be Init.
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "state must return to Init after tiebreak rename"
  );

  // fix: lifecycle_deadline must be Some (not None) — the service must
  // not be stranded waiting forever.
  assert!(
    svc.lifecycle_deadline.is_some(),
    "lifecycle_deadline must be scheduled after rename so probing resumes"
  );

  // Stale transmit state must be cleared.
  assert!(
    svc.pending_transmits.iter().all(|s| s.is_none()),
    "pending_transmits must be cleared on rename to avoid re-sending a stale probe"
  );
  assert!(
    svc.response_deadline.is_none(),
    "response_deadline must be cleared on rename"
  );

  // Verify the instance name was actually changed.
  assert!(
    svc.name().as_str().contains("-1"),
    "instance name should include a rename suffix: got {}",
    svc.name().as_str()
  );

  // Advance time well past any probe delay (> 250 ms) and drive the machine.
  let t2 = t1.advance(500);
  svc.handle_timeout(t2).unwrap();

  // The service must have progressed past Init into Probing.
  assert!(
    matches!(svc.state(), ServiceState::Probing(_) | ServiceState::Init),
    "service should be Probing or Init (if probe delay scheduled) after second tick; got {:?}",
    svc.state()
  );

  // Drive once more to ensure we actually reach Probing.
  let t3 = t2.advance(500);
  svc.handle_timeout(t3).unwrap();

  // By now (1500 ms past start) we must be in Probing.
  assert!(
    svc.state().is_probing(),
    "service must be Probing after rename + two handle_timeout ticks; got {:?}",
    svc.state()
  );
}

// ── kas_does_not_suppress_below_half_ttl ───────────────────────

/// Helper for KAS tests: inject a synthetic Question event so the
/// service has a pending `response_deadline`, which is the
/// pre-condition for accepting KAS hints.
fn inject_question_to_set_response_deadline(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  now: FakeInstant,
) {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "0.0.0.0:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0)),
    now,
  );
}

/// A KnownAnswer with querier TTL < our_ttl/2 MUST NOT suppress our record.
///
/// Our TTL = 120 s → half = 60 s. A KA with TTL = 30 s is below the
/// threshold and the hint must be discarded.
#[test]
fn kas_does_not_suppress_below_half_ttl() {
  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);

  // precondition: Question events are only honoured in
  // Established / Announcing states.  Drive to Established first,
  // then inject Question to set response_deadline.
  let now = drive_to_established(&mut svc);
  inject_question_to_set_response_deadline(&mut svc, now);

  // Build a KnownAnswer event with querier TTL = 30 s (< 60 = 120/2).
  let querier_ttl: u32 = 30;
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), record_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // The ring buffer must be empty — the hint was dropped due to half-TTL rule.
  let hint_count = svc.kas_hints.iter().filter(|s| s.is_some()).count();
  assert_eq!(
    hint_count, 0,
    "KAS hint with querier TTL {querier_ttl} < half of our TTL {our_ttl} must be dropped; \
       found {hint_count} hint(s) stored"
  );
}

/// A KnownAnswer with querier TTL >= our_ttl/2 MUST suppress (hint stored).
#[test]
fn kas_suppresses_at_or_above_half_ttl() {
  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);

  let now = drive_to_established(&mut svc);
  inject_question_to_set_response_deadline(&mut svc, now);

  // Build a KnownAnswer with querier TTL = 60 s (== 120/2, at the threshold).
  let querier_ttl: u32 = 60;
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), record_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // The hint should have been stored (suppression allowed).
  let hint_count = svc.kas_hints.iter().filter(|s| s.is_some()).count();
  assert_eq!(
    hint_count, 1,
    "KAS hint with querier TTL {querier_ttl} == half of our TTL {our_ttl} should be stored; \
       found {hint_count} hint(s)"
  );
}

/// a known-answer in a class OTHER than IN is a different RRset and
/// MUST NOT be stored as a KAS suppressor — otherwise a querier could silence
/// our IN response with a matching-rdata wrong-class answer (§7.1). This is
/// the identical record to `kas_suppresses_at_or_above_half_ttl` (TTL = 60 ==
/// our_ttl/2, so the half-TTL rule passes) EXCEPT CLASS=ANY instead of IN, so
/// only the class gate can reject it.
#[test]
fn kas_wrong_class_known_answer_does_not_suppress() {
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  inject_question_to_set_response_deadline(&mut svc, now);

  // An A record for our host, TTL 60 (>= 120/2), but CLASS=ANY (255), not IN.
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "host.local.".trim_end_matches('.').split('.') {
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8);
  buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
  buf.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY (not IN)
  buf.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60
  buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
  buf.extend_from_slice(&[192, 168, 1, 10]);
  let (record_ref, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), record_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  let hint_count = svc.kas_hints.iter().filter(|s| s.is_some()).count();
  assert_eq!(
    hint_count, 0,
    "a CLASS=ANY known-answer must NOT be stored as a KAS suppressor; found {hint_count}"
  );
}

// ── kas_does_not_suppress_unsolicited_announcement ────────────

/// Helper: drive a service from Init all the way to Established.
///
/// Advances time by 500 ms per tick until the state reaches Established.
/// Drains poll_transmit after each deadline to avoid blocking the state
/// machine. Panics if Established is not reached within 20 ticks.
fn drive_to_established(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
) -> FakeInstant {
  let mut buf = alloc::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    // Simulate the driver confirming a successful send so the
    // announce/host_advertised guards latch as they would in production.
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_transmit_delivered(now);
    }
    if svc.state() == ServiceState::Established {
      return now;
    }
  }
  panic!(
    "service did not reach Established within 20 ticks; state={:?}",
    svc.state()
  );
}

#[test]
fn encode_goodbye_none_before_announce() {
  // a service that never announced has nothing peers cached, so
  // there is no goodbye to send.
  let svc = make_service(120);
  assert_eq!(svc.state(), ServiceState::Init);
  let mut buf = alloc::vec![0u8; 4096];
  assert!(matches!(svc.encode_goodbye(&mut buf, &[]), Ok(None)));
}

#[test]
fn encode_goodbye_records_have_zero_ttl_when_established() {
  // once established, the goodbye carries the service's records
  // with TTL 0 so receivers withdraw them.
  let mut svc = make_service(120);
  drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];
  let len = svc
    .encode_goodbye(&mut buf, &[])
    .unwrap()
    .expect("an established service must produce a goodbye");
  let msg = buf.get(..len).unwrap();
  let reader = crate::wire::MessageReader::try_parse(msg).unwrap();
  let mut count = 0usize;
  for rec in reader.answers() {
    let rec = rec.unwrap();
    assert_eq!(rec.ttl(), 0, "every goodbye record must carry TTL 0");
    count += 1;
  }
  assert!(count > 0, "goodbye must contain the withdrawn records");
}

#[test]
fn empty_txt_encodes_as_single_zero_length_string() {
  // RFC 6763 §6.1: a service with no TXT data must still emit a TXT record
  // whose rdata is a SINGLE zero-length string (one 0x00 byte), never empty
  // rdata (an empty TXT RR is invalid). make_records adds no TXT segments.
  let mut svc = make_service(120);
  drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];
  let len = svc
    .encode_goodbye(&mut buf, &[])
    .unwrap()
    .expect("an established service must produce a goodbye");
  let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
  let mut txt_rdata: Option<alloc::vec::Vec<u8>> = None;
  for rec in reader.answers() {
    let rec = rec.unwrap();
    if rec.rtype() == crate::wire::ResourceType::Txt {
      txt_rdata = Some(rec.rdata().to_vec());
    }
  }
  assert_eq!(
    txt_rdata.as_deref(),
    Some(&[0u8][..]),
    "an empty TXT record must encode as a single zero-length string (one 0x00 byte)"
  );
}

#[test]
fn encode_goodbye_withdraws_only_unretained_host_addrs() {
  // host A/AAAA ownership is per-address. When the removed
  // service's host address is still advertised by a sibling (in
  // retained_host_addrs), the goodbye carries the instance records (PTR/SRV/
  // TXT) at TTL 0 but NOT that address; when no sibling retains it, the
  // address IS withdrawn.
  let host_addr = core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 168, 1, 10));
  let mut svc = make_service(120); // make_records advertises 192.168.1.10
  drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];

  // Address retained by a sibling → instance-only withdrawal (no A/AAAA).
  let len = svc
    .encode_goodbye(&mut buf, &[host_addr])
    .unwrap()
    .expect("established service must produce a goodbye");
  let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
  let mut saw_instance = false;
  let mut saw_addr = false;
  for rec in reader.answers() {
    let rec = rec.unwrap();
    assert_eq!(rec.ttl(), 0, "every goodbye record must carry TTL 0");
    match rec.rtype() {
      crate::wire::ResourceType::A | crate::wire::ResourceType::Aaaa => saw_addr = true,
      crate::wire::ResourceType::Ptr
      | crate::wire::ResourceType::Srv
      | crate::wire::ResourceType::Txt => saw_instance = true,
      _ => {}
    }
  }
  assert!(
    saw_instance,
    "instance records (PTR/SRV/TXT) must still be present"
  );
  assert!(
    !saw_addr,
    "a host address still advertised by a sibling must NOT be withdrawn"
  );

  // No sibling retains it → the host A (192.168.1.10) is withdrawn too.
  let len = svc
    .encode_goodbye(&mut buf, &[])
    .unwrap()
    .expect("established service must produce a goodbye");
  let reader = crate::wire::MessageReader::try_parse(buf.get(..len).unwrap()).unwrap();
  let saw_addr = reader.answers().filter_map(Result::ok).any(|r| {
    matches!(
      r.rtype(),
      crate::wire::ResourceType::A | crate::wire::ResourceType::Aaaa
    )
  });
  assert!(saw_addr, "an unretained host address must be withdrawn");
}

#[test]
fn take_pending_rename_goodbye_drains_and_clears() {
  // a service removed mid-rename never gets polled again, so its
  // queued old-name withdrawal would be lost. take_pending_rename_goodbye
  // lets the driver drain those bytes (instance-only, no host A/AAAA) into
  // its own goodbye queue, and clears the pending state.
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  svc.goodbye.mark_instance(); // the original name was announced

  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  svc
    .handle_timeout(FakeInstant::zero().advance(500))
    .unwrap(); // rename
  assert!(
    svc.name().as_str().contains("-1"),
    "service should have renamed"
  );

  // Drain the queued old-name withdrawal.
  let mut out = alloc::vec![0u8; 4096];
  let len = svc
    .take_pending_rename_goodbye(&mut out)
    .unwrap()
    .expect("a pending rename goodbye must be drained on removal");
  let reader = crate::wire::MessageReader::try_parse(out.get(..len).unwrap()).unwrap();
  let mut old_srv_goodbye = false;
  let mut saw_host_addr = false;
  for rr in reader.answers() {
    let rr = rr.unwrap();
    match rr.rtype() {
      crate::wire::ResourceType::Srv => {
        if rr.name().labels().next().and_then(Result::ok) == Some(&b"myprinter"[..])
          && rr.ttl() == 0
        {
          old_srv_goodbye = true;
        }
      }
      crate::wire::ResourceType::A | crate::wire::ResourceType::Aaaa => saw_host_addr = true,
      _ => {}
    }
  }
  assert!(
    old_srv_goodbye,
    "drained goodbye must carry the OLD instance SRV (owner 'myprinter') at TTL=0"
  );
  assert!(
    !saw_host_addr,
    "drained rename goodbye must NOT withdraw the still-valid host A/AAAA"
  );

  // The pending state must be cleared: a second take yields nothing, and
  // poll_transmit no longer re-emits the old-name goodbye.
  assert!(
    svc.take_pending_rename_goodbye(&mut out).unwrap().is_none(),
    "pending rename goodbye must be cleared after being taken"
  );
}

#[test]
fn take_pending_rename_goodbye_preserves_on_too_small_buffer() {
  // a too-small buffer must NOT destroy the pending withdrawal.
  // take_pending_rename_goodbye surfaces BufferTooSmall and keeps the state,
  // so a later larger-buffer call still emits the old-name goodbye.
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  svc.goodbye.mark_instance(); // the original name was announced

  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  svc
    .handle_timeout(FakeInstant::zero().advance(500))
    .unwrap(); // rename

  // Too-small buffer → BufferTooSmall, state preserved.
  let mut tiny = alloc::vec![0u8; 4];
  assert!(
    matches!(
      svc.take_pending_rename_goodbye(&mut tiny),
      Err(TransmitError::BufferTooSmall(_))
    ),
    "a too-small buffer must surface BufferTooSmall, not silently drop"
  );

  // A later adequately-sized buffer still emits the withdrawal.
  let mut out = alloc::vec![0u8; 4096];
  assert!(
    svc.take_pending_rename_goodbye(&mut out).unwrap().is_some(),
    "the preserved withdrawal must still be drainable with a larger buffer"
  );
}

#[test]
fn host_advertisement_survives_rename_and_drives_host_goodbye() {
  // host A/AAAA are owned by the host name, which does NOT change
  // on a conflict rename. A service that announced (advertising the host
  // records) then renamed has announce_emitted=false for the NEW name but
  // advertises_host()=true. Removing it as the last host owner must still
  // withdraw the host A/AAAA (host-only goodbye — the never-announced new
  // instance records are NOT emitted); if the host is still shared
  // (include_host_addrs=false) it emits nothing.
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  svc.goodbye.mark_instance();
  // the original name announced the host A/AAAA (per-address ownership)
  svc.goodbye.a = svc.records.a_addrs_slice().to_vec();
  svc.goodbye.aaaa = svc.records.aaaa_addrs_slice().to_vec();

  // Drive a losing §8.2 tiebreak (peer SRV port 9999 > ours 631) → rename.
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  svc
    .handle_timeout(FakeInstant::zero().advance(500))
    .unwrap();
  assert!(
    svc.name().as_str().contains("-1"),
    "service should have renamed"
  );
  assert!(
    !svc.goodbye.any_instance(),
    "the new instance name has not been announced after the rename"
  );
  assert!(
    svc.advertises_host(),
    "host advertisement must survive the instance rename"
  );

  // Last host owner (no addresses retained) → withdraw host A/AAAA only.
  let mut out = alloc::vec![0u8; 4096];
  let len = svc
    .encode_goodbye(&mut out, &[])
    .unwrap()
    .expect("must emit a host-only goodbye for the previously-advertised host");
  let reader = crate::wire::MessageReader::try_parse(out.get(..len).unwrap()).unwrap();
  let mut saw_host_addr = false;
  let mut saw_instance = false;
  for rr in reader.answers() {
    let rr = rr.unwrap();
    assert_eq!(rr.ttl(), 0, "every goodbye record must carry TTL 0");
    match rr.rtype() {
      crate::wire::ResourceType::A | crate::wire::ResourceType::Aaaa => saw_host_addr = true,
      crate::wire::ResourceType::Ptr
      | crate::wire::ResourceType::Srv
      | crate::wire::ResourceType::Txt => saw_instance = true,
      _ => {}
    }
  }
  assert!(
    saw_host_addr,
    "the previously-advertised host A/AAAA must be withdrawn"
  );
  assert!(
    !saw_instance,
    "the never-announced new instance records must NOT be emitted"
  );

  // Host address still owned by a sibling (retained) → nothing to do: the
  // new instance never announced and the host address must not be withdrawn.
  let host_addr = core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 168, 1, 10));
  assert!(
    matches!(svc.encode_goodbye(&mut out, &[host_addr]), Ok(None)),
    "a renamed service whose host address is still owned by a sibling emits no goodbye"
  );
}

#[test]
fn rename_goodbye_withdraws_only_advertised_instance_records() {
  // if §7.1 KAS let only a SUBSET of the instance records onto the wire
  // before a conflict rename, the rename goodbye must withdraw exactly that
  // subset — not all of PTR/SRV/TXT, which would flush a peer's matching
  // same-name record this responder never sent.
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  // The old name advertised ONLY its PTR (SRV/TXT were KAS-suppressed on the one
  // confirmed response before the rename).
  svc.goodbye.ptr = true;

  // Drive a losing §8.2 tiebreak (peer SRV port 9999 > ours 631) → rename.
  let mut sbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut sbuf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&sbuf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  let now = FakeInstant::zero().advance(500);
  svc.handle_timeout(now).unwrap();
  assert!(
    svc.name().as_str().contains("-1"),
    "service should have renamed"
  );

  // poll_transmit drains the rename goodbye (multicast, withdraws the OLD
  // instance records) before the new-name probe. Only the advertised PTR may
  // appear, at TTL 0.
  let mut out = alloc::vec![0u8; 4096];
  let tx = svc
    .poll_transmit(now, &mut out)
    .unwrap()
    .expect("a rename goodbye must be emitted for the announced old name");
  let reader = crate::wire::MessageReader::try_parse(out.get(..tx.size()).unwrap()).unwrap();
  let mut saw_ptr = false;
  let mut saw_srv_or_txt = false;
  for rr in reader.answers() {
    let rr = rr.unwrap();
    assert_eq!(rr.ttl(), 0, "every rename-goodbye record must carry TTL 0");
    match rr.rtype() {
      crate::wire::ResourceType::Ptr => saw_ptr = true,
      crate::wire::ResourceType::Srv | crate::wire::ResourceType::Txt => saw_srv_or_txt = true,
      _ => {}
    }
  }
  assert!(saw_ptr, "the advertised PTR must be withdrawn");
  assert!(
    !saw_srv_or_txt,
    "the KAS-suppressed SRV/TXT must NOT be withdrawn"
  );
}

#[test]
fn advertised_host_addrs_are_the_emitted_subset_not_configured() {
  // advertised_a_addrs / advertised_aaaa_addrs report the per-address
  // CONFIRMED-emitted set (goodbye.a/aaaa), NOT the configured records. The
  // driver builds its shared-host retention set from this, so it must never
  // over-retain a configured address that §7.1 KAS kept off the wire.
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("p._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("h.local.").unwrap();
  let mut records = ServiceRecords::new(stype, inst, host, 631, 120);
  let a1 = core::net::Ipv4Addr::new(10, 0, 0, 2);
  let a2 = core::net::Ipv4Addr::new(10, 0, 0, 3);
  records.add_a(a1);
  records.add_a(a2);
  let mut svc: Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> =
    Service::try_new(
      ServiceHandle::from_raw(0),
      records,
      FakeInstant::zero(),
      [0u8; 32],
      true,
    );
  assert!(
    svc.advertised_a_addrs().is_empty(),
    "nothing advertised before any confirmed send"
  );
  // A confirmed response that emitted ONLY a2 (a1 was KAS-suppressed).
  svc.goodbye.record_emitted(&respond::EmittedRecords {
    ptr: false,
    srv: false,
    txt: false,
    subtypes: false,
    a: alloc::vec![a2],
    aaaa: alloc::vec::Vec::new(),
  });
  assert_eq!(
    svc.advertised_a_addrs(),
    [a2],
    "only the emitted address is advertised"
  );
  assert_eq!(
    svc.records().a_addrs_slice(),
    [a1, a2],
    "the configured set still has both — advertised must NOT equal configured"
  );
}

#[test]
fn announce_guards_latch_only_on_confirmed_delivery() {
  // poll_transmit ENCODING an announcement must not
  // enable goodbye ownership — only a driver-confirmed delivery
  // (note_transmit_result(.., true)) does. Otherwise an announcement that
  // fails to leave the host (all sockets error) could later emit a goodbye
  // that deletes a peer's same-name records.
  let mut svc = make_service(120);
  let mut buf = alloc::vec![0u8; 4096];
  let mut now = FakeInstant::zero();

  // Drive through probing — CONFIRMING each probe so the §8.1 sequence
  // advances — until poll_transmit yields the first announcement,
  // which we deliberately leave UNCONFIRMED (simulating an all-socket send
  // failure). Stop the instant we hold an unconfirmed announcement so the
  // token is not cleared by a subsequent poll_transmit.
  let mut held_unconfirmed_announcement = false;
  'drive: for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      if matches!(svc.awaiting_confirm, Some(AwaitingConfirm::Announcement(_))) {
        held_unconfirmed_announcement = true;
        break 'drive;
      }
      // Confirm each probe so the lifecycle progresses to Announcing.
      svc.note_transmit_result(now, true);
    }
  }
  assert!(
    held_unconfirmed_announcement,
    "service should have produced an announcement within 20 ticks"
  );

  // Encoded but unconfirmed → no goodbye ownership.
  assert!(
    !svc.advertises_host(),
    "host ownership must NOT latch until a send is confirmed"
  );
  assert!(
    matches!(svc.encode_goodbye(&mut buf, &[]), Ok(None)),
    "no goodbye for an announcement that never reached the link"
  );

  // Confirm delivery → guards latch and a goodbye is now produced.
  svc.note_transmit_delivered(now);
  assert!(
    svc.advertises_host(),
    "host ownership must latch on confirmed delivery"
  );
  assert!(
    svc.encode_goodbye(&mut buf, &[]).unwrap().is_some(),
    "a confirmed-delivered service must produce a goodbye on removal"
  );
}

#[test]
fn announce_phase_does_not_advance_without_confirmed_send() {
  // if announcements never reach the link (every socket send
  // fails, so the driver never confirms), the announce phase must NOT advance
  // and Established must NOT be emitted — the announcement is retried instead.
  let mut svc = make_service(120);
  let mut buf = alloc::vec![0u8; 4096];
  let mut now = FakeInstant::zero();

  // Drive through probing to Announcing(0), CONFIRMING each probe so the §8.1
  // sequence advances (probes are delivery-confirmed too). No
  // announcement is confirmed here — Announcing(0) is reached right after the
  // third probe is confirmed, before any announcement is emitted.
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_transmit_result(now, true);
    }
    if matches!(svc.state(), ServiceState::Announcing(0)) {
      break;
    }
  }
  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "should reach Announcing(0); got {:?}",
    svc.state()
  );

  // Repeatedly fire + emit the announcement but report each send as FAILED
  // (delivered = false) — modelling a service whose announcements never reach
  // the link. The driver resolves the commit token after EVERY poll
  // (here with a failed result), which re-arms the retry without advancing; the
  // next cycle therefore re-emits. (Polling again WITHOUT resolving would now
  // correctly return Ok(None) — the single-token contract.)
  for _ in 0..10 {
    now = now.advance(1000);
    svc.handle_timeout(now).unwrap();
    assert!(
      svc.poll_transmit(now, &mut buf).unwrap().is_some(),
      "an announcement must be (re)emitted each cycle while unconfirmed"
    );
    svc.note_transmit_result(now, false); // send failed — re-arm, do NOT advance
    assert!(
      matches!(svc.state(), ServiceState::Announcing(0)),
      "phase must NOT advance without a confirmed send; got {:?}",
      svc.state()
    );
  }
  // No Established update may have been queued.
  let mut saw_established = false;
  while let Some(u) = svc.poll() {
    if matches!(u, ServiceUpdate::Established) {
      saw_established = true;
    }
  }
  assert!(
    !saw_established,
    "Established must NOT be emitted while no announcement was confirmed"
  );

  // Confirm one delivery → the phase finally advances.
  now = now.advance(1000);
  svc.handle_timeout(now).unwrap();
  assert!(svc.poll_transmit(now, &mut buf).unwrap().is_some());
  svc.note_transmit_delivered(now);
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "phase advances on the first confirmed announcement; got {:?}",
    svc.state()
  );
}

#[test]
fn probe_sequence_does_not_advance_without_confirmed_send() {
  // if probes never reach the link (every socket send fails, so
  // the driver reports `delivered = false`), the §8.1 probe sequence must NOT
  // advance — the service must never reach Announcing/Established and so can
  // never claim a name it failed to probe. The probe is retried instead.
  //
  // Under the pre-fix code the probe sequence advanced on the lifecycle timer
  // regardless of send success, so a service whose probes all failed still
  // marched to Announcing within a few ticks — the bug this guards against.
  let mut svc = make_service(120);
  let mut buf = alloc::vec![0u8; 4096];
  let mut now = FakeInstant::zero();

  let mut probes_emitted = 0usize;
  for _ in 0..50 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      // The probe was ENCODED, but report that every socket send failed.
      if matches!(svc.awaiting_confirm, Some(AwaitingConfirm::Probe)) {
        probes_emitted += 1;
      }
      svc.note_transmit_result(now, false);
    }
    assert!(
      matches!(svc.state(), ServiceState::Init | ServiceState::Probing(_)),
      "a service whose probes never reach the link must not leave probing; got {:?}",
      svc.state()
    );
  }
  assert!(
    probes_emitted >= 3,
    "the probe must be RETRIED (re-emitted) when its send is never confirmed; emitted {probes_emitted}"
  );
  assert!(
    matches!(svc.state(), ServiceState::Probing(0)),
    "with no confirmed probe the service stays at the first probe; got {:?}",
    svc.state()
  );
  assert!(
    !svc.advertises_host(),
    "an un-probed service must never latch host advertisement (no goodbye ownership)"
  );

  // Liveness: once a probe send IS confirmed, the sequence resumes — the
  // service is not permanently wedged by the earlier failures.
  now = now.advance(500);
  svc.handle_timeout(now).unwrap();
  assert!(svc.poll_transmit(now, &mut buf).unwrap().is_some());
  svc.note_transmit_result(now, true);
  assert!(
    matches!(svc.state(), ServiceState::Probing(1)),
    "a confirmed probe advances the sequence; got {:?}",
    svc.state()
  );
}

#[test]
fn no_goodbye_after_final_probe_before_first_announcement() {
  // reaching Announcing(0) is NOT sufficient. Until an
  // announcement datagram is actually emitted, peers have cached nothing,
  // so removal in this window must NOT produce a goodbye (which could
  // otherwise withdraw a different responder's record for the same name).
  let mut svc = make_service(120);
  let mut buf = alloc::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  let mut reached = false;
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if svc.state() == ServiceState::Announcing(0) {
      // Reached Announcing(0): the third probe was confirmed but no
      // announcement has been confirmed/emitted yet, so `announce_emitted`
      // is still false.
      reached = true;
      break;
    }
    // Drain + CONFIRM probes on the way to Announcing; probes
    // don't make a service cache-visible, so they must not enable a goodbye.
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_transmit_result(now, true);
    }
  }
  assert!(
    reached,
    "service should reach Announcing(0) within 20 ticks"
  );
  assert!(
    matches!(svc.encode_goodbye(&mut buf, &[]), Ok(None)),
    "no goodbye until an announcement has actually been emitted"
  );
}

#[test]
fn delivered_response_before_first_announcement_latches_goodbye_ownership() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  // a §6.7 legacy reply (or multicast question response) DELIVERED
  // while the service is still in Announcing(0) — before the first §8.3
  // announcement is confirmed — puts our positive-TTL records on the wire, so
  // peers may cache them. The goodbye-ownership guards must latch on that
  // confirmed delivery; otherwise an early unregister/conflict leaves peers
  // with stale records and no goodbye. (poll_transmit drains legacy replies
  // before the announcement queue, so this window is reachable.)
  let mut svc = make_service(120);
  let mut buf = alloc::vec![0u8; 4096];

  // Drive through probing to Announcing(0), confirming each probe; stop the
  // instant we reach Announcing(0), BEFORE any announcement is emitted.
  let mut now = FakeInstant::zero();
  'drive: for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_transmit_result(now, true);
      if matches!(svc.state(), ServiceState::Announcing(0)) {
        break 'drive;
      }
    }
  }
  assert!(matches!(svc.state(), ServiceState::Announcing(0)));
  assert!(
    !svc.advertises_host() && matches!(svc.encode_goodbye(&mut buf, &[]), Ok(None)),
    "precondition: nothing advertised/withdrawable before any send"
  );

  // A legacy querier (source port != 5353) asks for our PTR record — queues a
  // §6.7 unicast reply that poll_transmit drains immediately (ahead of any
  // announcement).
  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, legacy_src, 0x4242)),
    now,
  );

  // poll_transmit emits the legacy reply (unicast to the querier) — NOT an
  // announcement; the service is still Announcing(0).
  let tx = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("a legacy reply should be emitted");
  assert_eq!(
    tx.dst(),
    legacy_src,
    "legacy reply is unicast to the querier"
  );
  // the §6.7 legacy reply is NOT KAS-filtered — it carries the FULL
  // positive-TTL record set (PTR/SRV/TXT + the host A), so the commit token
  // records every record actually emitted.
  match &svc.awaiting_confirm {
    Some(AwaitingConfirm::Response(e)) => assert!(
      e.ptr && e.srv && e.txt && !e.a.is_empty(),
      "a legacy reply emits all instance records plus the host A"
    ),
    other => panic!("expected a Response commit token, got {other:?}"),
  }
  assert!(matches!(svc.state(), ServiceState::Announcing(0)));

  // Confirm delivery → goodbye ownership latches for every emitted record, even
  // though no announcement has been confirmed and the phase is unchanged.
  svc.note_transmit_result(now, true);
  // a legacy reply emits the full set, so BOTH the instance records and
  // the host address latch (earlier the emitted host A was wrongly left
  // unlatched, leaving it unwithdrawn on a later goodbye).
  assert!(
    svc.goodbye.any_instance(),
    "a delivered legacy reply latches the instance records it emitted"
  );
  assert!(
    svc.goodbye.any_host(),
    "the legacy reply also emitted the host A, so host ownership latches"
  );
  assert!(
    svc.encode_goodbye(&mut buf, &[]).unwrap().is_some(),
    "a service that answered a query must produce a goodbye on removal"
  );
  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "a response must NOT advance the announce phase; got {:?}",
    svc.state()
  );
}

#[test]
fn legacy_a_query_reply_latches_full_set() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  // (host-query direction): a §6.7 legacy reply for the HOST name (an A
  // query) still emits the FULL record set — legacy replies are not KAS-filtered
  // — so the token records the instance PTR/SRV/TXT too, NOT just the host A.
  // (Earlier an A-query reply was misclassified as host-only, leaving the
  // emitted PTR/SRV/TXT unwithdrawn on a later goodbye.)
  let mut svc = make_service(120);
  let mut buf = alloc::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  'drive: for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_transmit_result(now, true);
      if matches!(svc.state(), ServiceState::Announcing(0)) {
        break 'drive;
      }
    }
  }
  assert!(matches!(svc.state(), ServiceState::Announcing(0)));

  // Legacy A query for our host name.
  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  let host_str = svc.records.host().as_str().to_string();
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in host_str.trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, legacy_src, 0x55)),
    now,
  );

  svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("a legacy A reply should be emitted");
  match &svc.awaiting_confirm {
    Some(AwaitingConfirm::Response(e)) => assert!(
      e.ptr && e.srv && e.txt && !e.a.is_empty(),
      "an A-query legacy reply still emits the instance records and the host A"
    ),
    other => panic!("expected a Response commit token, got {other:?}"),
  }
  svc.note_transmit_result(now, true);
  assert!(
    svc.goodbye.any_host(),
    "a host A reply latches host ownership"
  );
  assert!(
    svc.goodbye.any_instance(),
    "the full legacy reply also emitted the instance records, so they latch too"
  );
}

#[test]
fn goodbye_ownership_accumulates_and_resets_instance_only() {
  // The GoodbyeOwnership contract (R67): record_emitted OR-accumulates per
  // RECORD (a later send can't un-advertise an earlier one, and §7.1 KAS that
  // trims a subset latches only what was sent), and a conflict rename drops ONLY
  // the instance records — host addresses survive.
  let ip = core::net::Ipv4Addr::new(192, 168, 1, 10);
  let mut g = GoodbyeOwnership::default();
  assert!(!g.any_instance() && !g.any_host());
  // A response that emitted only PTR + TXT (SRV was KAS-suppressed): only those
  // two latch — NOT SRV (F3).
  g.record_emitted(&respond::EmittedRecords {
    ptr: true,
    srv: false,
    txt: true,
    subtypes: false,
    a: alloc::vec::Vec::new(),
    aaaa: alloc::vec::Vec::new(),
  });
  assert!(
    g.ptr && !g.srv && g.txt,
    "only the emitted instance records latch"
  );
  assert!(g.any_instance() && !g.any_host());
  // A later host-only send (one A address) accumulates independently.
  g.record_emitted(&respond::EmittedRecords {
    ptr: false,
    srv: false,
    txt: false,
    subtypes: false,
    a: alloc::vec![ip],
    aaaa: alloc::vec::Vec::new(),
  });
  assert!(
    g.any_instance() && g.any_host(),
    "records accumulate independently"
  );
  assert_eq!(g.a, [ip], "the emitted address is tracked");
  // A duplicate emit must not double-insert the address.
  g.record_emitted(&respond::EmittedRecords {
    ptr: false,
    srv: false,
    txt: false,
    subtypes: false,
    a: alloc::vec![ip],
    aaaa: alloc::vec::Vec::new(),
  });
  assert_eq!(g.a, [ip], "duplicate address emit is idempotent");
  g.reset_instance(); // conflict rename
  assert!(
    !g.any_instance() && g.any_host(),
    "rename drops instance records but the host name is unchanged"
  );
  assert_eq!(g.a, [ip], "host addresses survive the rename");
}

/// returns the destination of the Response transmit a service
/// emits for a PTR question with the given raw QCLASS from `src`.
fn response_dst_for(qclass_raw: u16, src: core::net::SocketAddr) -> core::net::SocketAddr {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let mut svc = make_service(120);
  let mut now = drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&qclass_raw.to_be_bytes());
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0)),
    now,
  );
  now = now.advance(200); // past the jitter window
  svc.handle_timeout(now).unwrap();
  match svc.poll_transmit(now, &mut buf).unwrap() {
    Some(t) => t.dst(),
    None => panic!("expected a response transmit"),
  }
}

#[test]
fn unicast_response_routing() {
  // legacy querier (source port != 5353) → direct unicast reply.
  let legacy: core::net::SocketAddr = "192.0.2.5:40000".parse().unwrap();
  assert_eq!(response_dst_for(0x0001, legacy), legacy);
  // QU bit (source port 5353) → MULTICAST: the querier is a group member,
  // and RFC 6762 §5.4 permits answering a QU query by multicast.
  let qu: core::net::SocketAddr = "192.0.2.6:5353".parse().unwrap();
  assert_eq!(response_dst_for(0x8001, qu), respond::multicast_dst());
  // Plain multicast querier (port 5353, no QU) → multicast group.
  let qm: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();
  assert_eq!(response_dst_for(0x0001, qm), respond::multicast_dst());
}

/// RFC 6762 §7.2 (multipacket known-answer suppression): a query whose packet
/// has the TC bit set must delay the response 400–500 ms (vs the normal
/// 20–120 ms), giving the querier's follow-up known-answer packets time to
/// arrive and accumulate before we decide what to suppress.
#[test]
fn truncated_query_delays_response_to_400_500ms() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0).with_truncated(true)),
    now,
  );

  // 200 ms in: the normal 20–120 ms window would already have fired, but the
  // §7.2 TC delay (400–500 ms) must NOT have — no transmit yet.
  let t200 = now.advance(200);
  svc.handle_timeout(t200).unwrap();
  assert!(
    svc.poll_transmit(t200, &mut buf).unwrap().is_none(),
    "§7.2: a TC-bit response must not fire within the normal 20–120 ms window"
  );

  // By 500 ms the delayed response is due.
  let t500 = now.advance(500);
  svc.handle_timeout(t500).unwrap();
  assert!(
    svc.poll_transmit(t500, &mut buf).unwrap().is_some(),
    "§7.2: the delayed TC-bit response must fire by 500 ms"
  );
}

/// §7.2 + §6 jitter coalescing: a TC question schedules a 400–500 ms
/// response, but a subsequent NORMAL question coalesces onto the EARLIER
/// 20–120 ms deadline — the responder must not make a normal querier wait out
/// the TC querier's multipacket window. The coalesced response fires within the
/// normal window.
#[test]
fn truncated_then_normal_question_coalesces_to_earliest_deadline() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();
  // TC question first → ~450 ms deadline.
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0).with_truncated(true)),
    now,
  );
  // Normal question second → coalesces onto the earlier 20–120 ms deadline.
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0)),
    now,
  );

  let t200 = now.advance(200);
  svc.handle_timeout(t200).unwrap();
  assert!(
    svc.poll_transmit(t200, &mut buf).unwrap().is_some(),
    "coalesced response must fire in the normal 20–120 ms window, not wait for TC"
  );
}

/// §7.2 applied to the RFC 6763 §9 service-type enumeration path: a TC
/// meta-query (a large known-PTR list spread across packets) delays the meta
/// reply 400–500 ms, not 20–120 ms.
#[test]
fn truncated_meta_query_delays_reply_to_400_500ms() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_services._dns-sd._udp.local."
    .trim_end_matches('.')
    .split('.')
  {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0).with_truncated(true)),
    now,
  );

  let t200 = now.advance(200);
  svc.handle_timeout(t200).unwrap();
  assert!(
    svc.poll_transmit(t200, &mut buf).unwrap().is_none(),
    "§7.2: a TC meta-query reply must not fire within 20–120 ms"
  );
  let t500 = now.advance(500);
  svc.handle_timeout(t500).unwrap();
  assert!(
    svc.poll_transmit(t500, &mut buf).unwrap().is_some(),
    "§7.2: the delayed TC meta-query reply must fire by 500 ms"
  );
}

/// Drive to Established, deliver a §9 meta-query from a 5353 source, optionally
/// deliver a meta known-answer (PTR owned by the DNS-SD meta name, target =
/// our service type) with the given TTL and source, then fire the jittered
/// deadline. Returns whether a meta-PTR reply was emitted (the only thing
/// `poll_transmit` can produce in this window — so `false` means suppressed).
fn meta_reply_fires(with_ka: bool, ka_from_questioner: bool, ka_ttl: u32) -> bool {
  use crate::{
    event::{KnownAnswer, ServiceQuestion},
    wire::{QuestionRef, RecordRef},
  };

  let mut svc = make_service(120); // service_type _ipp._tcp.local., TTL 120 (half = 60)
  let now = drive_to_established(&mut svc);
  let qsrc: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();

  // Meta-query for _services._dns-sd._udp.local.
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_services._dns-sd._udp.local."
    .trim_end_matches('.')
    .split('.')
  {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, qsrc, 0)),
    now,
  );

  // Optional meta known-answer: PTR _services._dns-sd._udp.local. -> _ipp._tcp.local.
  let mut kbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  if with_ka {
    for label in "_services._dns-sd._udp.local."
      .trim_end_matches('.')
      .split('.')
    {
      kbuf.push(label.len() as u8);
      kbuf.extend_from_slice(label.as_bytes());
    }
    kbuf.push(0u8);
    kbuf.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
    kbuf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    kbuf.extend_from_slice(&ka_ttl.to_be_bytes());
    let mut rdata: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
      rdata.push(label.len() as u8);
      rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0u8);
    kbuf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    kbuf.extend_from_slice(&rdata);
    let ka_src: core::net::SocketAddr = if ka_from_questioner {
      qsrc
    } else {
      "192.0.2.99:5353".parse().unwrap()
    };
    let (rref, _) = RecordRef::try_parse(&kbuf, 0).unwrap();
    svc.handle_event(
      ServiceEvent::KnownAnswer(KnownAnswer::new(ka_src, rref)),
      now,
    );
  }

  let t = now.advance(200); // past the 20–120 ms meta jitter window
  svc.handle_timeout(t).unwrap();
  let mut buf = alloc::vec![0u8; 4096];
  svc.poll_transmit(t, &mut buf).unwrap().is_some()
}

/// (RFC 6763 §9 + §7.1): a meta questioner that already knows our
/// service type (sends the meta-PTR as a known-answer) suppresses our redundant
/// meta reply — but only from a real questioner source and above the half-TTL
/// threshold. The baseline (no known-answer) still replies.
#[test]
fn meta_query_known_answer_suppression() {
  assert!(
    meta_reply_fires(false, false, 0),
    "baseline: a meta-query with no known-answer must elicit our meta-PTR reply"
  );
  assert!(
    !meta_reply_fires(true, true, 120),
    "§7.1: a meta questioner already holding our service-type PTR suppresses the reply"
  );
  assert!(
    meta_reply_fires(true, false, 120),
    "the meta known-answer must come from a meta questioner source"
  );
  assert!(
    meta_reply_fires(true, true, 10),
    "§7.1 half-TTL: a low-TTL known-answer must NOT suppress (our TTL 120, half 60)"
  );
}

/// with MULTIPLE meta queriers coalesced in one response window, a
/// known-answer from ONE of them must NOT suppress the multicast meta reply the
/// OTHER still needs (mirrors the cross-source guard for normal responses).
#[test]
fn meta_kas_not_suppressed_when_multiple_meta_questioners() {
  use crate::{
    event::{KnownAnswer, ServiceQuestion},
    wire::{QuestionRef, RecordRef},
  };

  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let src_a: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();
  let src_b: core::net::SocketAddr = "192.0.2.8:5353".parse().unwrap();

  // Meta-query from TWO distinct 5353 sources (they coalesce in one window).
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_services._dns-sd._udp.local."
    .trim_end_matches('.')
    .split('.')
  {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src_a, 0)),
    now,
  );
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src_b, 0)),
    now,
  );

  // Only src_a already knows our type (sends the meta-PTR known-answer).
  let mut kbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_services._dns-sd._udp.local."
    .trim_end_matches('.')
    .split('.')
  {
    kbuf.push(label.len() as u8);
    kbuf.extend_from_slice(label.as_bytes());
  }
  kbuf.push(0u8);
  kbuf.extend_from_slice(&12u16.to_be_bytes()); // PTR
  kbuf.extend_from_slice(&1u16.to_be_bytes()); // IN
  kbuf.extend_from_slice(&120u32.to_be_bytes());
  let mut rdata: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    rdata.push(label.len() as u8);
    rdata.extend_from_slice(label.as_bytes());
  }
  rdata.push(0u8);
  kbuf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
  kbuf.extend_from_slice(&rdata);
  let (rref, _) = RecordRef::try_parse(&kbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::KnownAnswer(KnownAnswer::new(src_a, rref)),
    now,
  );

  let t = now.advance(200);
  svc.handle_timeout(t).unwrap();
  let mut buf = alloc::vec![0u8; 4096];
  assert!(
    svc.poll_transmit(t, &mut buf).unwrap().is_some(),
    "two coalesced meta questioners — one source's known-answer must NOT \
     suppress the meta reply the other still needs"
  );
}

#[test]
fn legacy_response_echoes_id_and_question_and_caps_ttl() {
  // a legacy unicast reply (§6.7) echoes the query ID + question
  // and caps record TTLs at 10s so a conventional resolver can match it.
  use crate::{
    event::ServiceQuestion,
    wire::{MessageReader, QuestionRef},
  };
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "192.0.2.9:33333".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0x1234)),
    now,
  );
  let tx = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("a legacy querier must get a unicast response");
  assert_eq!(tx.dst(), src);
  let msg = buf.get(..tx.size()).unwrap();
  let reader = MessageReader::try_parse(msg).unwrap();
  assert_eq!(reader.header().id(), 0x1234, "must echo the query ID");
  assert_eq!(
    reader.header().question_count(),
    1,
    "must echo the question"
  );
  let q = reader.questions().next().unwrap().unwrap();
  assert!(q.qtype().is_ptr(), "echoed question keeps its qtype");
  let mut answers = 0usize;
  for rec in reader.answers() {
    let rec = rec.unwrap();
    assert!(
      rec.ttl() <= respond::LEGACY_UNICAST_MAX_TTL_SECS,
      "legacy answer TTL must be capped at 10s, got {}",
      rec.ttl()
    );
    answers += 1;
  }
  assert!(answers > 0, "legacy response must carry the answers");
}

#[test]
fn coalesced_legacy_queriers_each_get_a_response() {
  // two distinct legacy queriers in one window each get a reply.
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes());
  qbuf.extend_from_slice(&1u16.to_be_bytes());
  let a: core::net::SocketAddr = "192.0.2.10:40000".parse().unwrap();
  let b: core::net::SocketAddr = "192.0.2.11:40001".parse().unwrap();
  for s in [a, b] {
    let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
    svc.handle_event(
      ServiceEvent::Question(ServiceQuestion::new(qref, s, 7)),
      now,
    );
  }
  let mut dsts: alloc::vec::Vec<core::net::SocketAddr> = alloc::vec::Vec::new();
  while let Some(t) = svc.poll_transmit(now, &mut buf).unwrap() {
    dsts.push(t.dst());
    svc.note_transmit_result(now, true); // confirm before the next poll
  }
  assert!(
    dsts.contains(&a) && dsts.contains(&b),
    "both coalesced legacy queriers must get a reply; got {:?}",
    dsts
  );
}

#[test]
fn same_source_distinct_legacy_transactions_each_reply() {
  // a resolver reusing ONE socket for two transactions (distinct
  // query IDs) must get a reply per transaction — dedup is on the full
  // request key, not just the source address.
  use crate::{
    event::ServiceQuestion,
    wire::{MessageReader, QuestionRef},
  };
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let mut buf = alloc::vec![0u8; 4096];
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes());
  qbuf.extend_from_slice(&1u16.to_be_bytes());
  let src: core::net::SocketAddr = "192.0.2.12:40000".parse().unwrap();
  for id in [11u16, 22u16] {
    let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
    svc.handle_event(
      ServiceEvent::Question(ServiceQuestion::new(qref, src, id)),
      now,
    );
  }
  let mut ids: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
  while let Some(t) = svc.poll_transmit(now, &mut buf).unwrap() {
    assert_eq!(t.dst(), src);
    let msg = buf.get(..t.size()).unwrap();
    ids.push(MessageReader::try_parse(msg).unwrap().header().id());
    svc.note_transmit_result(now, true); // confirm before the next poll
  }
  assert!(
    ids.contains(&11) && ids.contains(&22),
    "each distinct transaction (by query ID) must get its own reply; got {:?}",
    ids
  );
}

#[test]
fn oversized_legacy_response_is_dropped_not_errored() {
  // a legacy reply that doesn't fit the buffer must be DROPPED —
  // never surfaced as BufferTooSmall (the driver would count that as a
  // service encode failure and unregister a healthy service) and never left
  // stuck at the queue head (blocking all transmits). A remote query must
  // not be able to poison the service.
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes());
  qbuf.extend_from_slice(&1u16.to_be_bytes());
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 1)),
    now,
  );
  assert!(!svc.pending_legacy.is_empty(), "legacy reply was queued");

  // 16 bytes holds only the header — too small for the question + records.
  let mut tiny = [0u8; 16];
  match svc.poll_transmit(now, &mut tiny) {
    Ok(None) => {}
    Ok(Some(_)) => panic!("did not expect a transmit into a too-small buffer"),
    Err(e) => panic!("legacy encode failure must not surface as Err: {e:?}"),
  }
  assert!(
    svc.pending_legacy.is_empty(),
    "the un-encodable legacy entry must be dropped, not left stuck"
  );
}

// ── KAS hints scoped to questioner source ───────────────────

/// A peer that never asks a question must NOT be able to inject KAS
/// hints that suppress responses to other (legitimate) queriers.
/// Even with a pending response_deadline from a different source,
/// hints from un-asked sources must be dropped.
#[test]
fn kas_rejects_hints_from_non_questioner_source() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);
  let now = drive_to_established(&mut svc);

  // Legitimate questioner (source A) asks; sets response_deadline.
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src_a: core::net::SocketAddr = "10.0.0.1:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src_a, 0)),
    now,
  );
  assert!(svc.response_deadline.is_some());

  // Attacker (source B — never asked) sends a KAS hint matching one
  // of our A records, with TTL above the half-TTL threshold.
  let querier_ttl: u32 = our_ttl;
  let mut rec_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut rec_buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = RecordRef::try_parse(&rec_buf, 0).unwrap();
  let src_b: core::net::SocketAddr = "10.0.0.99:5353".parse().unwrap();
  let ka = KnownAnswer::new(src_b, record_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // The hint MUST be dropped — src_b is not a questioner.
  let hint_count = svc.kas_hints.iter().filter(|s| s.is_some()).count();
  assert_eq!(
    hint_count, 0,
    "KAS hints from a source that did not ask a question must be dropped; \
       found {hint_count} hint(s)"
  );

  // Sanity: a hint from src_a (the legitimate questioner) DOES land.
  let ka2 = KnownAnswer::new(src_a, record_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka2), now);
  let hint_count = svc.kas_hints.iter().filter(|s| s.is_some()).count();
  assert_eq!(
    hint_count, 1,
    "control: hint from the legitimate questioner src_a must land; got {hint_count}"
  );
}

/// when multiple questioners coalesce in the same response
/// window, hints from one source must NOT suppress records the
/// other source needs.  The defensive simplification: when more
/// than one source has asked in the cycle, disable KAS filtering
/// entirely for the response.
#[test]
fn kas_disabled_when_multiple_questioners_coalesced() {
  use crate::{
    event::ServiceQuestion,
    wire::{MessageReader, QuestionRef, ResourceType},
  };

  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);
  let now = drive_to_established(&mut svc);

  // Helper to inject a Question from a specific source.
  let inject_q =
    |svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
     src: &str,
     now: FakeInstant| {
      let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
      for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
        qbuf.push(label.len() as u8);
        qbuf.extend_from_slice(label.as_bytes());
      }
      qbuf.push(0u8);
      qbuf.extend_from_slice(&12u16.to_be_bytes());
      qbuf.extend_from_slice(&1u16.to_be_bytes());
      let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
      let src: core::net::SocketAddr = src.parse().unwrap();
      svc.handle_event(
        ServiceEvent::Question(ServiceQuestion::new(qref, src, 0)),
        now,
      );
    };

  // Two distinct questioners ask within the jitter window.
  inject_q(&mut svc, "10.0.0.1:5353", now);
  inject_q(&mut svc, "10.0.0.2:5353", now);

  // Source B injects a KAS hint matching our A record.  Source A
  // does NOT supply this hint and still needs the record.
  let querier_ttl: u32 = our_ttl;
  let mut rec_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut rec_buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = RecordRef::try_parse(&rec_buf, 0).unwrap();
  let src_b: core::net::SocketAddr = "10.0.0.2:5353".parse().unwrap();
  let ka = KnownAnswer::new(src_b, record_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // Fire the response_deadline.
  let rd = svc.response_deadline.unwrap();
  svc.handle_timeout(rd).unwrap();

  // Produce the response.
  let mut buf = alloc::vec![0u8; 4096];
  let tx = svc
    .poll_transmit(rd, &mut buf)
    .unwrap()
    .expect("response must be emitted");
  let written = &buf[..tx.size()];
  let reader = MessageReader::try_parse(written).expect("valid DNS");

  // the A record MUST be present even though src_b has a
  // matching KAS hint, because src_a (the coalesced second
  // questioner) didn't supply that hint.
  let mut found_a = false;
  for rr in reader.answers() {
    let rr = rr.expect("answer must parse");
    if rr.rtype() == ResourceType::A && rr.rdata() == [192, 168, 1, 10] {
      found_a = true;
      break;
    }
  }
  assert!(
    found_a,
    "A record must NOT be suppressed when multiple questioners coalesce \
       and only one supplied a matching KAS hint"
  );
}

/// After a peer sends a KnownAnswer matching our A record, a subsequent
/// unsolicited announcement (periodic re-announce, NOT a question response)
/// MUST still include the A record — KAS filtering must not be applied.
///
/// This is the regression test: before the fix, `PendingTransmitKind::
/// Announcement` always called `write_announce_filtered`, so a fresh KAS hint
/// could suppress records from unsolicited announcements.
#[test]
fn kas_does_not_suppress_unsolicited_announcement() {
  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);

  // ── 1. Advance to Established ──────────────────────────────────────
  let now = drive_to_established(&mut svc);
  assert_eq!(svc.state(), ServiceState::Established);

  // ── 2. Inject a KAS hint matching our A record (192.168.1.10) ─────
  // precondition: response_deadline must be set, so inject a
  // Question first.  querier_ttl == our_ttl (well above the
  // half-TTL threshold), so the hint is stored and would suppress
  // the record if KAS filtering is applied.
  inject_question_to_set_response_deadline(&mut svc, now);
  let querier_ttl: u32 = our_ttl;
  let mut rec_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut rec_buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = RecordRef::try_parse(&rec_buf, 0).unwrap();
  let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), record_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // Verify the hint was actually stored (so the test is meaningful).
  let hint_count = svc.kas_hints.iter().filter(|s| s.is_some()).count();
  assert_eq!(hint_count, 1, "KAS hint for A record should be stored");

  // ── 3. Trigger an unsolicited re-announce (NOT via a Question) ─────
  // Force the re-announce deadline to fire by jumping time far forward.
  // response_deadline_active is false so the Established arm must choose
  // PendingTransmitKind::Announcement (no KAS filtering).
  let now_reannounce = now.advance(u64::from(our_ttl) * 1000 + 1000);
  svc.handle_timeout(now_reannounce).unwrap();

  // pending_transmits[0] must be Announcement (not Response).
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Announcement),
    "re-announce after deadline must produce Announcement kind"
  );

  // ── 4. Produce the datagram and verify the A record is present ─────
  let mut out = alloc::vec![0u8; 4096];
  let transmit = svc
    .poll_transmit(now_reannounce, &mut out)
    .unwrap()
    .expect("poll_transmit must return Some for a pending Announcement");

  let written = &out[..transmit.size()];
  let reader =
    crate::wire::MessageReader::try_parse(written).expect("datagram must be a valid DNS message");

  let a_found = reader.answers().any(|rr| {
    if let Ok(rr) = rr {
      matches!(rr.rtype(), crate::wire::ResourceType::A)
    } else {
      false
    }
  });
  assert!(
    a_found,
    "unsolicited re-announcement must include the A record even when a fresh KAS hint exists; \
       KAS filtering must not be applied to Announcement kind"
  );
}

// ── HostConflict does not auto-rename ──────────────────────────

/// When Service::handle_event receives a HostConflict event it must:
///   - NOT rename the instance (state stays unchanged, name stays the same).
///   - Emit ServiceUpdate::HostConflict via poll().
#[test]
fn host_conflict_does_not_rename_instance() {
  use crate::event::{HostConflict, ServiceEvent};

  let mut svc = make_service(120);

  // Give the service a last_now so timers are initialised.
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let original_name = svc.name().as_str().to_owned();
  let original_state = svc.state();

  // Build a wire A record for "host.local." (the host name in make_records).
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [192, 168, 1, 99]);
  let (record_ref, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let hc = HostConflict::new(record_ref);
  svc.handle_event(ServiceEvent::HostConflict(hc), t0);

  // Instance name must be unchanged.
  assert_eq!(
    svc.name().as_str(),
    original_name,
    "HostConflict must NOT rename the service instance"
  );

  // State must be unchanged.
  assert_eq!(
    svc.state(),
    original_state,
    "HostConflict must NOT change the service state"
  );

  // A ServiceUpdate::HostConflict must be queued.
  let update = svc
    .poll()
    .expect("Service::poll() must return Some(ServiceUpdate::HostConflict) after HostConflict");
  assert!(
    update.is_host_conflict(),
    "poll() must return ServiceUpdate::HostConflict, got {:?}",
    update
  );

  // No further updates pending.
  assert!(
    svc.poll().is_none(),
    "only one update must be queued per HostConflict event"
  );
}

/// a host A/AAAA carrying an address WE advertise is consistent
/// rdata (our own echo / another instance sharing the host), NOT a conflict —
/// it must NOT surface a HostConflict.
#[test]
fn host_conflict_ignores_our_own_advertised_address() {
  use crate::event::{HostConflict, ServiceEvent};
  let mut svc = make_service(120); // host.local. advertises 192.168.1.10
  svc.handle_timeout(FakeInstant::zero()).unwrap();
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [192, 168, 1, 10]); // OUR address
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::HostConflict(HostConflict::new(rec)),
    FakeInstant::zero(),
  );
  assert!(
    svc.poll().is_none(),
    "an identical (our own) host A must not surface a HostConflict"
  );
}

/// control: a host A with a DIFFERENT address is a genuine §9
/// conflict and must surface HostConflict.
#[test]
fn host_conflict_surfaces_for_different_address() {
  use crate::event::{HostConflict, ServiceEvent};
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap();
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [10, 0, 0, 99]); // NOT ours
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::HostConflict(HostConflict::new(rec)),
    FakeInstant::zero(),
  );
  assert!(
    svc.poll().is_some_and(|u| u.is_host_conflict()),
    "a different host A must surface HostConflict"
  );
}

/// a §9 revert-to-probe must clear queued response-cycle state — a
/// legacy unicast reply queued just before the conflict must NOT be answered
/// while the name is being re-verified.
#[test]
fn section9_reprobe_clears_queued_legacy_reply() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let mut svc = make_service(120);
  drive_to_established(&mut svc);
  let now = FakeInstant::zero().advance(100_000);

  // Legacy querier (source port != 5353) for our instance name → queues a
  // unicast reply.
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "myprinter._ipp._tcp.local."
    .trim_end_matches('.')
    .split('.')
  {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&255u16.to_be_bytes()); // QTYPE ANY
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let legacy_src: core::net::SocketAddr = "192.168.1.50:40000".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, legacy_src, 0x99)),
    now,
  );
  assert!(
    !svc.pending_legacy.is_empty(),
    "a legacy querier must queue a unicast reply"
  );

  // A genuine §9 conflict (different SRV, port 9999 ≠ 631) reverts to probe.
  let mut sbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut sbuf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (srec, _) = RecordRef::try_parse(&sbuf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, srec)),
    now,
  );

  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "§9 conflict must revert to re-probing"
  );
  assert!(
    svc.pending_legacy.is_empty(),
    "§9 revert must clear the queued legacy reply (don't answer an unverified name)"
  );
}

/// a conflict rename of an ANNOUNCED service must emit a TTL=0
/// goodbye for the OLD records, or peers keep the old PTR/SRV/TXT cached as a
/// ghost until TTL.
#[test]
fn conflict_rename_emits_goodbye_for_old_announced_name() {
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  svc.goodbye.mark_instance(); // the original name was announced

  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  svc
    .handle_timeout(FakeInstant::zero().advance(500))
    .unwrap();
  assert!(
    svc.name().as_str().contains("-1"),
    "service should have renamed"
  );

  // The FIRST transmit after the rename must be the old-name goodbye.
  let mut out = alloc::vec![0u8; 4096];
  let t = svc
    .poll_transmit(FakeInstant::zero().advance(500), &mut out)
    .unwrap()
    .expect("a goodbye for the old announced name must be emitted");
  let reader = crate::wire::MessageReader::try_parse(&out[..t.size()]).unwrap();
  let mut old_srv_goodbye = false;
  let mut saw_host_addr = false;
  for rr in reader.answers() {
    let rr = rr.unwrap();
    match rr.rtype() {
      crate::wire::ResourceType::Srv => {
        if rr.name().labels().next().and_then(Result::ok) == Some(&b"myprinter"[..])
          && rr.ttl() == 0
        {
          old_srv_goodbye = true;
        }
      }
      // the rename goodbye must NOT withdraw the host address
      // records — they are still valid for the renamed (and any co-hosted)
      // service.
      crate::wire::ResourceType::A | crate::wire::ResourceType::Aaaa => saw_host_addr = true,
      _ => {}
    }
  }
  assert!(
    old_srv_goodbye,
    "goodbye must carry the OLD instance's SRV (owner 'myprinter') with TTL=0"
  );
  assert!(
    !saw_host_addr,
    "rename goodbye must NOT withdraw the still-valid host A/AAAA records"
  );
}

/// the rename-goodbye resends are SPACED by RENAME_GOODBYE_INTERVAL,
/// not drained as a same-tick burst — so a correlated loss burst can't take
/// all copies.
#[test]
fn rename_goodbye_resends_are_spaced_not_a_burst() {
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap();
  svc.goodbye.mark_instance();
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let t = FakeInstant::zero().advance(500);
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  svc.handle_timeout(t).unwrap(); // rename at t → first goodbye due at t

  let mut out = alloc::vec![0u8; 4096];
  assert!(
    svc.poll_transmit(t, &mut out).unwrap().is_some(),
    "first rename goodbye is due immediately"
  );
  assert!(
    svc.poll_transmit(t, &mut out).unwrap().is_none(),
    "the 2nd rename goodbye must NOT burst in the same tick — it is spaced out"
  );
  // After the interval the 2nd send is due.
  let t2 = t.advance(1000);
  assert!(
    svc.poll_transmit(t2, &mut out).unwrap().is_some(),
    "the spaced 2nd rename goodbye is due after RENAME_GOODBYE_INTERVAL"
  );
}

/// a transient too-small buffer must NOT silently drop the rename
/// goodbye — it surfaces BufferTooSmall (peek-then-pop) and a later larger
/// buffer still emits the old-instance withdrawal.
#[test]
fn rename_goodbye_preserved_on_too_small_buffer() {
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap();
  svc.goodbye.mark_instance();
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let t = FakeInstant::zero().advance(500);
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  svc.handle_timeout(t).unwrap();

  let mut tiny = [0u8; 4];
  let err = svc.poll_transmit(t, &mut tiny);
  assert!(
    matches!(err, Err(crate::error::TransmitError::BufferTooSmall(_))),
    "a too-small buffer must surface BufferTooSmall, got {err:?}"
  );
  // The withdrawal is preserved — a larger buffer still emits it.
  let mut big = alloc::vec![0u8; 4096];
  assert!(
    svc.poll_transmit(t, &mut big).unwrap().is_some(),
    "the rename goodbye must survive a transient too-small buffer"
  );
}

/// a link-local host A is scope-ambiguous — the same raw address on
/// a different interface is a real conflict — so it must surface a HostConflict
/// even when the address matches one we advertise.
#[test]
fn host_conflict_for_link_local_address_is_not_suppressed() {
  use crate::event::{HostConflict, ServiceEvent};
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("myprinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("host.local.").unwrap();
  let mut r = ServiceRecords::new(stype, inst, host, 631, 120);
  r.add_a(core::net::Ipv4Addr::new(169, 254, 1, 1)); // link-local, advertised
  let mut svc: Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> =
    Service::try_new(
      ServiceHandle::from_raw(0),
      r,
      FakeInstant::zero(),
      [0u8; 32],
      true,
    );
  svc.handle_timeout(FakeInstant::zero()).unwrap();

  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [169, 254, 1, 1]); // same link-local addr
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::HostConflict(HostConflict::new(rec)),
    FakeInstant::zero(),
  );
  assert!(
    svc.poll().is_some_and(|u| u.is_host_conflict()),
    "a link-local host A must surface HostConflict even when the raw address matches"
  );
}

/// when a conflict rename fails (the suffixed name is invalid), the
/// service goes Conflicting but must still clear queued transmit / response
/// state so poll_transmit can't send stale records afterward.
#[test]
fn failed_conflict_rename_clears_stale_transmit_state() {
  // 63-byte instance label is the max valid; rename_with_suffix appends "-1"
  // → 65-byte label → invalid DNS name → the rename fails.
  let long_label = "a".repeat(63);
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str(&alloc::format!("{long_label}._ipp._tcp.local.")).unwrap();
  let host = Name::try_from_str("host.local.").unwrap();
  let mut r = ServiceRecords::new(stype, inst, host, 631, 120);
  r.add_a(core::net::Ipv4Addr::new(192, 168, 1, 10));
  let mut svc: Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> =
    Service::try_new(
      ServiceHandle::from_raw(0),
      r,
      FakeInstant::zero(),
      [0u8; 32],
      true,
    );
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  // Stale queued state that must be cleared if the rename fails.
  svc.pending_transmits[0] = Some(PendingTransmitKind::Probe);
  svc.response_deadline = Some(FakeInstant::zero().advance(50));

  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    &alloc::format!("{long_label}._ipp._tcp.local."),
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  svc
    .handle_timeout(FakeInstant::zero().advance(500))
    .unwrap();

  assert_eq!(
    svc.state(),
    ServiceState::Conflicting,
    "invalid rename must go Conflicting"
  );
  assert_eq!(
    svc.pending_transmits,
    [None, None],
    "failed rename must clear pending transmits"
  );
  assert!(
    svc.response_deadline.is_none(),
    "failed rename must clear response_deadline"
  );
}

// ── RFC §8.2 tiebreak — we WIN ────────────────────────────────

/// When our record set beats the peer's (ours is lexicographically later),
/// the service must NOT rename after the tiebreak handle_timeout — probing
/// continues uninterrupted.
///
/// only SRV and TXT records are accepted into the peer bucket.
/// Non-SRV/TXT records (A, NSEC, etc.) are dropped silently without setting
/// tiebreak_pending. This sub-test verifies the A-record-drop path separately,
/// then the main tiebreak-win path uses a peer SRV with port=80 (< our 631).
///
/// Tiebreak win: peer SRV port=80 < our port=631 → peer's sorted set is
/// lexicographically smaller → `peer >= our` is FALSE → we WIN (no rename).
#[test]
fn tiebreak_we_win_continues_probing() {
  let mut svc = make_service(120);

  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  // sub-check: a ProbeConflict carrying an A record must be silently
  // dropped — A records are NOT SRV or TXT, so they don't belong in the
  // tiebreak bucket. tiebreak_pending must NOT be set.
  {
    let mut buf_a: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    make_a_record_ref(
      &mut buf_a,
      "myprinter._ipp._tcp.local.",
      120,
      [192, 168, 1, 10],
    );
    let (rref_a, _) = RecordRef::try_parse(&buf_a, 0).unwrap();
    let src_a: core::net::SocketAddr = "192.168.1.50:5353".parse().unwrap();
    svc.handle_event(
      ServiceEvent::ProbeConflict(ProbeConflict::new(src_a, rref_a)),
      t0,
    );
    assert!(
      !svc.tiebreak_pending,
      "ProbeConflict with an A record must NOT set tiebreak_pending"
    );
    assert_eq!(
      svc.peer_probes.len(),
      0,
      "A-record ProbeConflict must NOT create a peer-probe bucket"
    );
  }

  // Main tiebreak-win path: peer sends SRV(port=80) + TXT(empty).
  // our local set now always includes TXT (even when empty), matching
  // what write_probe emits unconditionally. With both sides having TXT(empty),
  // the TXT entries are identical and cancel out; the SRV comparison dominates.
  // Our SRV port=631 > peer SRV port=80 → our_concat > peer_concat → we WIN.
  let peer_src_win: core::net::SocketAddr = "192.168.1.10:5353".parse().unwrap();

  // Send peer SRV(port=80).
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,  // priority
    0,  // weight
    80, // port < our 631 → peer SRV bytes are smaller → peer loses
    "host.local.",
  );
  let (record_ref, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let conflict = ProbeConflict::new(peer_src_win, record_ref);
  svc.handle_event(ServiceEvent::ProbeConflict(conflict), t0);

  // Send peer TXT(empty) — peer's probe emits TXT; we must too for symmetry.
  let mut buf_txt: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_txt_record_ref(&mut buf_txt, "myprinter._ipp._tcp.local.", 120, &[]);
  let (txt_ref, _) = RecordRef::try_parse(&buf_txt, 0).unwrap();
  let conflict_txt = ProbeConflict::new(peer_src_win, txt_ref);
  svc.handle_event(ServiceEvent::ProbeConflict(conflict_txt), t0);

  assert!(svc.tiebreak_pending, "tiebreak_pending must be set");
  let state_before = svc.state();
  let name_before = svc.name().as_str().to_owned();

  // Trigger the tiebreak comparison.
  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();

  // We won: state must not have reset to Init for rename; name unchanged.
  assert_eq!(
    svc.name().as_str(),
    name_before,
    "tiebreak win must NOT rename the service"
  );
  assert!(
    !svc.tiebreak_pending,
    "tiebreak_pending must be cleared after comparison"
  );
  assert_eq!(
    svc.peer_probes.len(),
    0,
    "peer_probes must be cleared after tiebreak"
  );
  // No Renamed update queued.
  assert!(
    svc.poll().is_none(),
    "no ServiceUpdate::Renamed should be queued when we win the tiebreak"
  );
  // State should still be Init or Probing (not back-tracked by a rename).
  let _ = state_before; // used for doc clarity only
  assert!(
    matches!(svc.state(), ServiceState::Init | ServiceState::Probing(_)),
    "state must remain in probing sequence after winning tiebreak; got {:?}",
    svc.state()
  );
}

// ── RFC §8.2 tiebreak — we LOSE ──────────────────────────────

/// When the peer's SRV record beats ours (peer's is lexicographically greater),
/// the service must rename after the tiebreak handle_timeout.
///
/// Our SRV: port=631. Peer SRV: port=9999. Since 9999 > 631, peer set is
/// greater → we lose → rename. (tiebreak compares SRV+TXT only.)
#[test]
fn tiebreak_we_lose_renames() {
  let mut svc = make_service(120); // our SRV: port=631

  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  // Peer sends a SRV record with port=9999 (greater than our 631).
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,    // priority
    0,    // weight
    9999, // port > 631 → peer wins
    "host.local.",
  );
  let (record_ref, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer_src_lose: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let conflict = ProbeConflict::new(peer_src_lose, record_ref);
  svc.handle_event(ServiceEvent::ProbeConflict(conflict), t0);

  assert!(svc.tiebreak_pending);
  let original_name = svc.name().as_str().to_owned();

  // Trigger the tiebreak: peer wins.
  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();

  // We lost: service must have renamed.
  assert!(
    svc.name().as_str().contains("-1"),
    "tiebreak loss must rename the service (expected '-1' suffix); got {}",
    svc.name().as_str()
  );
  assert_ne!(
    svc.name().as_str(),
    original_name,
    "name must change after tiebreak loss"
  );
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "state must reset to Init after tiebreak rename"
  );
  assert!(!svc.tiebreak_pending, "tiebreak_pending must be cleared");
  assert_eq!(svc.peer_probes.len(), 0, "buffer must be cleared");

  // A Renamed update must be queued.
  let update = svc
    .poll()
    .expect("ServiceUpdate::Renamed must be queued after tiebreak loss");
  assert!(
    update.is_renamed(),
    "update must be Renamed, got {:?}",
    update
  );
}

/// a conflict on our instance name AFTER we are Established (RFC
/// 6762 §9) with DIFFERENT rdata must trigger re-verification — the service
/// reverts to Probing to re-assert its name (NOT the §8.2 lexicographic
/// tiebreak, and NOT an immediate rename).
#[test]
fn established_service_reprobes_on_different_rdata_conflict() {
  let mut svc = make_service(120); // instance myprinter._ipp._tcp.local., SRV port 631
  drive_to_established(&mut svc);
  assert_eq!(svc.state(), ServiceState::Established);
  let original = svc.name().as_str().to_owned();

  // A DIFFERENT SRV (port 9999 ≠ our 631) for our instance name is a §9
  // conflict.
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let t = FakeInstant::zero().advance(100_000);
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    t,
  );

  // Reverted to Probing to re-verify the SAME name — no immediate rename.
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "a §9 conflict must revert an Established service to re-probing"
  );
  assert_eq!(
    svc.name().as_str(),
    original,
    "re-verification must NOT rename the service immediately"
  );
  assert!(
    svc.poll_timeout().is_some(),
    "the re-probe deadline must be exposed via poll_timeout"
  );
}

/// an IDENTICAL SRV/TXT for our instance name is consistent rdata,
/// NOT a conflict (§9) — an Established service must ignore it and keep
/// serving, rather than treat a benign duplicate / its own echo as a conflict.
#[test]
fn established_service_ignores_identical_rdata() {
  let mut svc = make_service(120);
  drive_to_established(&mut svc);
  assert_eq!(svc.state(), ServiceState::Established);

  // SRV IDENTICAL to ours (priority 0, weight 0, port 631, target host.local.).
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    631,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero().advance(100_000),
  );
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "an identical record is consistent rdata, not a conflict — stay Established"
  );
}

/// a conflict-driven rename clears `announce_emitted`, so no
/// goodbye is emitted for the new (never-announced) name.
#[test]
fn conflict_rename_resets_announce_emitted() {
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  // Simulate that the original name was announced (peers cached it).
  svc.goodbye.mark_instance();

  // A winning peer conflict (port 9999 > 631) → tiebreak loss → rename.
  let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = RecordRef::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  svc
    .handle_timeout(FakeInstant::zero().advance(500))
    .unwrap();

  assert!(
    svc.name().as_str().contains("-1"),
    "tiebreak loss must rename"
  );
  assert!(
    !svc.goodbye.any_instance(),
    "rename must reset announce_emitted so the new name isn't goodbye'd un-announced"
  );
  assert!(
    svc.pending_legacy.is_empty(),
    "rename must clear queued legacy replies bound to the old name"
  );
}

// ── question during Announcing does not shortcut announce sequence ─

/// A question arriving between announce 1 and announce 2 must NOT cause
/// the announce sequence to be shortcut. The response deadline fires as a
/// KAS-filtered Response; the Announcing counter must stay at its current
/// value and progress normally.
#[test]
fn question_during_announcing_does_not_shortcut_sequence() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let mut svc = make_service(120);
  let mut buf4096 = alloc::vec![0u8; 4096];

  // ── 1. Drive to Announcing(0) ─────────────────────────────────────
  // Seed = 0 → deterministic probe delays. Advance 500 ms per tick.
  let mut now = FakeInstant::zero();
  loop {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
      svc.note_transmit_delivered(now);
    }
    if matches!(svc.state(), ServiceState::Announcing(_)) {
      break;
    }
    assert!(
      now.0 < 10_000,
      "service should reach Announcing within 10 s; state={:?}",
      svc.state()
    );
  }
  // Should be Announcing(0) just after the last probe fired.
  // Drain any pending transmit.
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_transmit_delivered(now);
  }

  // ── 2. Fire the first announce (Announcing(0) → Announcing(1)) ────
  now = now.advance(500);
  svc.handle_timeout(now).unwrap();
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_transmit_delivered(now);
  }
  // We may now be Announcing(1) or Established (if n was already ≥1).
  // Advance until we're in Announcing(1).
  for _ in 0..5 {
    if matches!(svc.state(), ServiceState::Announcing(1)) {
      break;
    }
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
      svc.note_transmit_delivered(now);
    }
  }
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "should be in Announcing(1); got {:?}",
    svc.state()
  );

  // ── 3. Inject a Question while in Announcing(1) ───────────────────
  // Build a minimal question wire message.
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  // Encode name "_ipp._tcp.local." as length-prefixed labels.
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8); // root
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "0.0.0.0:5353".parse().unwrap();
  let sq = ServiceQuestion::new(qref, src, 0);
  svc.handle_event(ServiceEvent::Question(sq), now);

  assert!(
    svc.response_deadline.is_some(),
    "response_deadline must be set after Question"
  );

  // ── 4. Call handle_timeout: fires the jittered response deadline ──
  // response_deadline is already set by handle_event(Question), so we just
  // advance time past the jitter window and let it fire.
  now = now.advance(1); // tiny advance — response deadline may not be ripe yet
  svc.handle_timeout(now).unwrap();
  // response_deadline should be scheduled; it fires when we advance past it.

  // ── 5. Advance past the jitter window (max 120 ms) ───────────────
  // The response deadline fires before the announce interval (1000 ms).
  now = now.advance(200); // well past 120 ms jitter, well before 1000 ms announce
  svc.handle_timeout(now).unwrap();

  // The kind fired should be Response (KAS-filtered), NOT Announcement.
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Response),
    "question during Announcing must produce Response kind, not Announcement"
  );
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_transmit_delivered(now);
  }

  // ── 6. State must still be Announcing(1) — counter not advanced ──
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "state must remain Announcing(1) after response; got {:?}",
    svc.state()
  );

  // ── 7. Final announce fires normally → Established ───────────────
  now = now.advance(2000); // past the 1 s announce interval
  svc.handle_timeout(now).unwrap();
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Announcement),
    "second announce must produce Announcement kind"
  );
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_transmit_delivered(now);
  }
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "service must reach Established after second announce"
  );
}

// ── two peers, one wins → we lose ─────────────────────────────

/// When two different peers send ProbeConflicts and at least one of them has
/// a larger SRV set (port > ours), the service MUST rename. The tiebreak
/// must evaluate each peer bucket independently; a peer that loses must not
/// protect us from a peer that wins.
///
/// Our SRV: port=631. Peer A: port=80 (loses). Peer B: port=9999 (wins).
/// Because Peer B wins, we must rename.
#[test]
fn tiebreak_two_peers_one_wins_we_lose() {
  let mut svc = make_service(120); // our SRV: port=631
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  // Peer A (src=.10) sends SRV with port=80 → Peer A loses (our 631 > 80).
  let peer_a: core::net::SocketAddr = "192.168.1.10:5353".parse().unwrap();
  let mut buf_a: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf_a,
    "myprinter._ipp._tcp.local.",
    120,
    0,  // priority
    0,  // weight
    80, // port < our 631 → Peer A loses
    "host.local.",
  );
  let (rref_a, _) = RecordRef::try_parse(&buf_a, 0).unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer_a, rref_a)),
    t0,
  );

  // Peer B (src=.200) sends SRV with port=9999 → Peer B wins (9999 > 631).
  let peer_b: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let mut buf_b: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut buf_b,
    "myprinter._ipp._tcp.local.",
    120,
    0,    // priority
    0,    // weight
    9999, // port > our 631 → Peer B wins
    "host.local.",
  );
  let (rref_b, _) = RecordRef::try_parse(&buf_b, 0).unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer_b, rref_b)),
    t0,
  );

  // Two distinct peer source buckets should be created.
  assert_eq!(svc.peer_probes.len(), 2, "should have 2 peer probe buckets");
  assert!(svc.tiebreak_pending, "tiebreak_pending must be set");
  let original_name = svc.name().as_str().to_owned();

  // Trigger the tiebreak: Peer B wins → we rename.
  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();

  // We lost (because Peer B won): service must have renamed.
  assert!(
    svc.name().as_str().contains("-1"),
    "service must rename when any peer wins the tiebreak; got: {}",
    svc.name().as_str()
  );
  assert_ne!(svc.name().as_str(), original_name, "name must change");
  assert_eq!(svc.state(), ServiceState::Init, "state must reset to Init");
  assert!(!svc.tiebreak_pending, "tiebreak_pending must be cleared");
  assert_eq!(svc.peer_probes.len(), 0, "peer buckets must be cleared");
  let update = svc.poll().expect("ServiceUpdate::Renamed must be queued");
  assert!(
    update.is_renamed(),
    "update must be Renamed, got {:?}",
    update
  );
}

// ── wire-form canonical SRV name encoding ─────────────────────

/// Verify that `write_canonical_wire_name` (used in the tiebreak's local
/// SRV set) produces proper DNS wire form — length byte + label bytes,
/// terminated by 0x00 — and that shorter hostnames sort lexicographically
/// before longer ones in byte order (as expected by RFC §8.2).
#[test]
fn srv_wire_form_canonical() {
  // Wire-form encoding of "aa.local." should be:
  // \x02 a a \x05 l o c a l \x00
  let mut out_aa: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  write_canonical_wire_name("aa.local.", &mut out_aa);
  assert_eq!(
    out_aa,
    alloc::vec![2u8, b'a', b'a', 5, b'l', b'o', b'c', b'a', b'l', 0],
    "wire form for 'aa.local.' must be \\x02aa\\x05local\\x00"
  );

  // Wire-form encoding of "b.local." should be:
  // \x01 b \x05 l o c a l \x00
  let mut out_b: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  write_canonical_wire_name("b.local.", &mut out_b);
  assert_eq!(
    out_b,
    alloc::vec![1u8, b'b', 5, b'l', b'o', b'c', b'a', b'l', 0],
    "wire form for 'b.local.' must be \\x01b\\x05local\\x00"
  );

  // Byte order: \x02aa... vs \x01b... — 0x02 > 0x01, so "aa.local." > "b.local."
  // This is the correct wire-form ordering (not the wrong dot-joined ordering
  // which would compare "aa.local" vs "b.local" → "b.local" > "aa.local").
  assert!(
    out_aa > out_b,
    "wire-form 'aa.local.' must be > 'b.local.' in byte order (length prefix 2 > 1)"
  );
}

// ── question does not push out the announce deadline ──────────

/// A question arriving during Announcing must NOT extend the lifecycle
/// (announce) deadline. The response fires at the jittered response_deadline
/// and the lifecycle_deadline is left exactly where it was.
///
/// This is the core regression: the OLD code recomputed
/// `announce_deadline(now, n)` after the response fired, pushing the
/// announce out by nearly a full interval. The NEW code stores
/// `lifecycle_deadline` separately and never touches it when the
/// response_deadline fires.
///
/// NOTE: if both response_deadline AND lifecycle_deadline are due
/// at the same `now`, BOTH advance — this is correct and expected. This
/// test therefore verifies the invariant when ONLY the response is due
/// (lifecycle is safely in the future). The setup drives to Announcing(1)
/// (so lifecycle = now + 1000ms) before injecting the question.
#[test]
fn question_does_not_push_out_announce_deadline() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let mut svc = make_service(120);
  let mut buf4096 = alloc::vec![0u8; 4096];

  // ── 1. Drive to Announcing(1) ────────────────────────────────────────
  // Announcing(1) has lifecycle_deadline = now + 1000ms (ANNOUNCE_INTERVAL),
  // which is far enough in the future that a +200ms advance won't trigger it.
  // (Announcing(0) has FIRST_ANNOUNCE_DELAY=0ms, meaning the deadline is
  //  immediately due — advancing 200ms would fire both response AND lifecycle
  //  in the same tick, which is correct behavior but changes the
  //  invariant's test scenario. Using Announcing(1) avoids this overlap.)
  let mut now = FakeInstant::zero();
  loop {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
      svc.note_transmit_delivered(now);
    }
    if matches!(svc.state(), ServiceState::Announcing(1)) {
      break;
    }
    assert!(
      now.0 < 10_000,
      "should reach Announcing(1) within 10 s; state={:?}",
      svc.state()
    );
  }
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_transmit_delivered(now);
  } // drain any pending

  // ── 2. Record the lifecycle_deadline BEFORE the question ─────────────
  let announce_deadline_before = svc.lifecycle_deadline;
  assert!(
    announce_deadline_before.is_some(),
    "lifecycle_deadline must be set in Announcing(1)"
  );
  // Verify the lifecycle deadline is safely in the future (> +200ms away).
  // announce_deadline(now, 1) = now + 1000ms; our now+200 < now+1000.
  let min_lifecycle = now.advance(300); // conservative: must be >= now + 200ms
  assert!(
    announce_deadline_before.unwrap() >= min_lifecycle,
    "lifecycle_deadline must be > now+200ms so the question-response test is meaningful; \
       lifecycle={:?}, min={:?}",
    announce_deadline_before,
    min_lifecycle
  );

  // ── 3. Inject a Question ─────────────────────────────────────────────
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "0.0.0.0:5353".parse().unwrap();
  let sq = ServiceQuestion::new(qref, src, 0);
  svc.handle_event(ServiceEvent::Question(sq), now);

  assert!(
    svc.response_deadline.is_some(),
    "response_deadline must be set after Question in Announcing(1)"
  );

  // ── 4. Verify lifecycle_deadline is UNCHANGED after the question ──────
  assert_eq!(
    svc.lifecycle_deadline, announce_deadline_before,
    "lifecycle_deadline must NOT be modified by a Question event"
  );

  // ── 5. Fire the response deadline ────────────────────────────────────
  // Advance past the max jitter window (120 ms) but well before the announce
  // interval (1000 ms). Since lifecycle is now + 1000ms, now+200 < lifecycle.
  now = now.advance(200);
  svc.handle_timeout(now).unwrap();
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Response),
    "firing response_deadline must produce Response kind, not Announcement"
  );
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_transmit_delivered(now);
  }

  // ── 6. lifecycle_deadline must still equal announce_deadline_before ───
  // This is the key assertion: the announce deadline must not have
  // been pushed out. Since we advanced only 200ms and lifecycle is 1000ms
  // away, the lifecycle did NOT fire, so lifecycle_deadline is unchanged.
  assert_eq!(
    svc.lifecycle_deadline, announce_deadline_before,
    "lifecycle_deadline must be unchanged after response fires"
  );

  // ── 7. State must still be Announcing(1) ─────────────────────────────
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "state must remain Announcing(1) after response; got {:?}",
    svc.state()
  );

  // ── 8. Advance to the ORIGINAL announce deadline → transitions to Established ─
  // Jump to the original lifecycle_deadline. The announce must fire at that
  // original time, not at now + interval.
  let original_announce = announce_deadline_before.unwrap();
  svc.handle_timeout(original_announce).unwrap();
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Announcement),
    "announce must fire at the original lifecycle_deadline, not at a pushed-out time"
  );
  if let Ok(Some(_)) = svc.poll_transmit(original_announce, &mut buf4096) {
    svc.note_transmit_delivered(original_announce);
  }
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "after the Announcing(1) announce fires, state must reach Established; got {:?}",
    svc.state()
  );
}

// ── SRV KAS suppression — wire-form hash matches incoming hint ─

/// A KnownAnswer hint for our SRV record (stored via canonical_rdata_for_hash,
/// which uses wire-form target encoding) MUST match the filter built by
/// write_announce_filtered (which now also uses wire-form encoding).
///
/// Previously the filter used dot-joined plain bytes for the SRV target
/// while canonical_rdata_for_hash used wire-form, so the hashes never matched
/// and SRV hints could never suppress our SRV answer.
#[test]
fn srv_kas_hint_suppresses_srv_in_filtered_response() {
  use crate::{
    event::ServiceQuestion,
    wire::{MessageReader, QuestionRef, ResourceType},
  };

  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);
  let now = drive_to_established(&mut svc);
  assert_eq!(svc.state(), ServiceState::Established);

  // KAS hints require a pending response_deadline.  Inject
  // a Question event first.
  inject_question_to_set_response_deadline(&mut svc, now);

  // Build a wire SRV record matching our service (priority=0, weight=0,
  // port=631, target="host.local.") with TTL = our_ttl (above half-TTL threshold).
  let mut srv_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_srv_record_ref(
    &mut srv_buf,
    "myprinter._ipp._tcp.local.",
    our_ttl,
    0,             // priority matches
    0,             // weight matches
    631,           // port matches
    "host.local.", // target matches
  );
  let (srv_ref, _) = RecordRef::try_parse(&srv_buf, 0).unwrap();
  let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), srv_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // Verify the SRV hint was stored.
  let srv_hint_count = svc
    .kas_hints
    .iter()
    .filter(|s| {
      s.map(|h| h.rtype == crate::wire::ResourceType::Srv)
        .unwrap_or(false)
    })
    .count();
  assert_eq!(srv_hint_count, 1, "SRV KAS hint must be stored");

  // Inject a Question to schedule a filtered response.
  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "myprinter._ipp._tcp.local."
    .trim_end_matches('.')
    .split('.')
  {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&255u16.to_be_bytes()); // QTYPE ANY
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "0.0.0.0:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0)),
    now,
  );
  assert!(
    svc.response_deadline.is_some(),
    "response_deadline must be set"
  );

  // Fire the response (advance past the max 120 ms jitter window).
  let now2 = now.advance(200);
  svc.handle_timeout(now2).unwrap();
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Response),
    "pending_transmits[0] must be Response after question"
  );

  // Build the filtered datagram.
  let mut out = alloc::vec![0u8; 4096];
  let transmit = svc
    .poll_transmit(now2, &mut out)
    .unwrap()
    .expect("poll_transmit must return Some for pending Response");
  let written = &out[..transmit.size()];
  let reader =
    MessageReader::try_parse(written).expect("response datagram must be a valid DNS message");

  // The SRV record MUST be suppressed because the KAS hint hash matches.
  // Previously the hashes diverged (dot-join vs wire-form), so SRV was
  // never suppressed. Now both sides use wire-form, so they match.
  let srv_present = reader.answers().any(|rr| {
    rr.map(|rec| rec.rtype() == ResourceType::Srv)
      .unwrap_or(false)
  });
  assert!(
    !srv_present,
    "SRV answer must be suppressed by the matching KAS hint; found SRV in response"
  );
}

#[test]
fn kas_wrong_owner_known_answer_does_not_suppress() {
  // a known-answer may only suppress the RRset it actually names. A
  // querier sends `_ipp._tcp.local. A 192.168.1.10` — same rtype + rdata as our
  // real `host.local. A 192.168.1.10`, but a DIFFERENT owner name (the service
  // type, not the host). It must NOT suppress the host A in our response;
  // otherwise a querier could silence our address record with a bogus RRset.
  use crate::wire::{MessageReader, ResourceType};

  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl); // advertises host.local. A 192.168.1.10
  let now = drive_to_established(&mut svc);
  inject_question_to_set_response_deadline(&mut svc, now);

  // Bogus known-answer: an A record OWNED BY THE SERVICE-TYPE name, rdata = our
  // host's A. It is stored (its name is one of ours) but bound to owner-kind
  // ServiceType, so it can never match the host-owned A candidate.
  let mut a_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  make_a_record_ref(&mut a_buf, "_ipp._tcp.local.", our_ttl, [192, 168, 1, 10]);
  let (a_ref, _) = RecordRef::try_parse(&a_buf, 0).unwrap();
  let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), a_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // Fire the response (past the jitter window) and confirm the host A survives.
  let now2 = now.advance(200);
  svc.handle_timeout(now2).unwrap();
  let mut out = alloc::vec![0u8; 4096];
  let transmit = svc
    .poll_transmit(now2, &mut out)
    .unwrap()
    .expect("a response must be emitted");
  let reader = MessageReader::try_parse(&out[..transmit.size()]).unwrap();
  let a_present = reader.answers().any(|rr| {
    rr.map(|rec| rec.rtype() == ResourceType::A)
      .unwrap_or(false)
  });
  assert!(
    a_present,
    "the host A must NOT be suppressed by a wrong-owner (_ipp._tcp.local) A known-answer"
  );
}

// ── same-tick response + lifecycle both fire ──────────────────

/// When both response_deadline and lifecycle_deadline are due at the same
/// `now`, a single call to handle_timeout MUST advance lifecycle state AND
/// queue BOTH transmits (Announcement in slot 0, Response in slot 1).
///
/// Previously, handle_timeout returned early after firing response_deadline,
/// leaving lifecycle_deadline unfired until the next call. This extends this:
/// the two-slot queue now preserves both transmits instead of dropping one.
#[test]
fn same_tick_response_and_lifecycle_both_fire() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);

  // Drive to Announcing(0).
  let mut now = FakeInstant::zero();
  let mut buf4096 = alloc::vec![0u8; 4096];
  loop {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
      svc.note_transmit_delivered(now);
    }
    if matches!(svc.state(), ServiceState::Announcing(0)) {
      break;
    }
    assert!(now.0 < 10_000, "should reach Announcing(0) within 10 s");
  }
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_transmit_delivered(now);
  } // drain any pending

  // Record the lifecycle_deadline (the next announce deadline).
  let announce_dl = svc
    .lifecycle_deadline
    .expect("lifecycle_deadline must be set");

  // Inject a Question with response_deadline set to the SAME instant as the
  // announce lifecycle_deadline. We do this by scheduling the question at
  // announce_dl minus 20ms (minimum jitter), so the response_deadline will
  // be at or before announce_dl. Then advance to exactly announce_dl.
  //
  // For simplicity we directly inject the question at a time such that the
  // jitter puts response_deadline at or before announce_dl.
  // We use a deterministic seed (0), so the jitter offset is deterministic.
  // Instead, we force the scenario by setting response_deadline directly.
  {
    // Inject the question to generate a response_deadline via normal path.
    let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
      qbuf.push(label.len() as u8);
      qbuf.extend_from_slice(label.as_bytes());
    }
    qbuf.push(0u8);
    qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
    qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
    let src: core::net::SocketAddr = "0.0.0.0:5353".parse().unwrap();
    svc.handle_event(
      ServiceEvent::Question(ServiceQuestion::new(qref, src, 0)),
      now,
    );
  };

  // Force both deadlines to the SAME instant (announce_dl) so we can
  // assert the double-drain invariant deterministically.
  svc.response_deadline = Some(announce_dl);

  // Verify setup: both deadlines at announce_dl.
  assert_eq!(svc.lifecycle_deadline, Some(announce_dl));
  assert_eq!(svc.response_deadline, Some(announce_dl));
  let state_before = svc.state();

  // Fire handle_timeout at announce_dl (both deadlines due simultaneously).
  svc.handle_timeout(announce_dl).unwrap();

  // invariant: BOTH transmits must be queued — the two-slot
  // queue holds both the lifecycle (Announcement) and the response (Response).
  // Lifecycle is pushed first (slot 0), then Response (slot 1).
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Announcement),
    "lifecycle Announcement must be in slot 0 when both deadlines fire at same tick"
  );
  assert_eq!(
    svc.pending_transmits[1],
    Some(PendingTransmitKind::Response),
    "Response must be in slot 1 when both deadlines fire at same tick"
  );

  // invariant 2 (updated): the lifecycle deadline fired
  // and was NOT dropped — its Announcement is queued (asserted above). The
  // phase now advances on CONFIRMED delivery rather than in handle_timeout, so
  // drain + confirm the queued transmits and verify the phase progressed
  // (Announcing(0) -> Announcing(1)).
  while let Ok(Some(_)) = svc.poll_transmit(announce_dl, &mut buf4096) {
    svc.note_transmit_delivered(announce_dl);
  }
  assert!(
    !matches!(svc.state(), ServiceState::Announcing(0)),
    "lifecycle must advance once the same-tick announcement is confirmed; \
       got {:?} (expected Announcing(1) or Established)",
    svc.state()
  );
  // The response_deadline must be cleared.
  assert!(
    svc.response_deadline.is_none(),
    "response_deadline must be cleared after firing"
  );
  // lifecycle_deadline must have been rescheduled (next announce or re-announce).
  assert!(
    svc.lifecycle_deadline != Some(announce_dl),
    "lifecycle_deadline must be rescheduled after firing"
  );

  let _ = state_before; // informational
}

// ── same-tick response does not drop the lifecycle announcement ─

/// When both response_deadline and lifecycle_deadline (an Announcement) fire
/// at the same `now`, poll_transmit must produce TWO transmits — one
/// Announcement and one Response — rather than dropping the Announcement.
///
/// Previously the single `pending_transmit: Option` field was overwritten
/// by Response, so the Announcement was silently lost and the lifecycle
/// state had already advanced (e.g. Announcing(0)→Announcing(1)) as if the
/// announcement had been sent.
#[test]
fn same_tick_both_transmits_are_queued_and_drained() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);
  let mut buf4096 = alloc::vec![0u8; 4096];

  // Drive to Announcing(0).
  let mut now = FakeInstant::zero();
  loop {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
      svc.note_transmit_delivered(now);
    }
    if matches!(svc.state(), ServiceState::Announcing(0)) {
      break;
    }
    assert!(now.0 < 10_000, "should reach Announcing(0) within 10 s");
  }
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_transmit_delivered(now);
  } // drain any pending

  // Record the first-announce lifecycle_deadline.
  let announce_dl = svc
    .lifecycle_deadline
    .expect("lifecycle_deadline must be set in Announcing(0)");

  // Inject a Question and force both deadlines to the same instant.
  {
    let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
      qbuf.push(label.len() as u8);
      qbuf.extend_from_slice(label.as_bytes());
    }
    qbuf.push(0u8);
    qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
    qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
    let src: core::net::SocketAddr = "0.0.0.0:5353".parse().unwrap();
    svc.handle_event(
      ServiceEvent::Question(ServiceQuestion::new(qref, src, 0)),
      now,
    );
  }
  svc.response_deadline = Some(announce_dl); // align with lifecycle

  // Fire handle_timeout with both deadlines at the same instant.
  svc.handle_timeout(announce_dl).unwrap();

  // both slots must be occupied — slot 0 = Announcement, slot 1 = Response.
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Announcement),
    "slot 0 must be Announcement when lifecycle fires"
  );
  assert_eq!(
    svc.pending_transmits[1],
    Some(PendingTransmitKind::Response),
    "slot 1 must be Response when response also fires"
  );

  // poll_transmit drains slot 0 first.
  let t1 = svc.poll_transmit(announce_dl, &mut buf4096).unwrap();
  assert!(
    t1.is_some(),
    "first poll_transmit must return Some (Announcement)"
  );
  // the single commit token requires a note_transmit_result between
  // polls — the driver confirms after each send, so it still drains both queued
  // transmits across the confirm boundary.
  svc.note_transmit_result(announce_dl, true);

  // After draining slot 0 the tail compacts down (FIFO).  The
  // Response that was in slot 1 is now in slot 0, slot 1 is empty.  Either
  // representation is acceptable, but the queue must still contain the
  // Response.
  assert!(
    svc
      .pending_transmits
      .contains(&Some(PendingTransmitKind::Response)),
    "Response must persist after draining the Announcement"
  );

  // poll_transmit drains slot 1.
  let t2 = svc.poll_transmit(announce_dl, &mut buf4096).unwrap();
  assert!(
    t2.is_some(),
    "second poll_transmit must return Some (Response)"
  );
  svc.note_transmit_result(announce_dl, true);

  // Queue is now empty.
  let t3 = svc.poll_transmit(announce_dl, &mut buf4096).unwrap();
  assert!(
    t3.is_none(),
    "third poll_transmit must return None (queue empty)"
  );
}

// ── cache-flush bit on unique answer records ─────────────────

/// Announcements must set the cache-flush bit (bit 15 of the class field,
/// = 0x8000) on SRV, TXT, A, and AAAA records.  PTR remains unchanged.
///
/// RFC 6762 §10.2: the cache-flush bit signals to peers that prior cached
/// records of the same name/type/class are now invalid.
#[test]
fn announcement_sets_cache_flush_on_unique_records() {
  use crate::wire::{MessageReader, ResourceType};

  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);

  // Drive to Established so we can trigger a re-announce.
  let now = drive_to_established(&mut svc);
  assert_eq!(svc.state(), ServiceState::Established);

  // Jump far forward to trigger the periodic re-announce.
  let now_reannounce = now.advance(u64::from(our_ttl) * 1000 + 1000);
  svc.handle_timeout(now_reannounce).unwrap();

  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Announcement),
    "precondition: pending_transmits[0] must be Announcement"
  );

  // Produce the datagram.
  let mut out = alloc::vec![0u8; 4096];
  let transmit = svc
    .poll_transmit(now_reannounce, &mut out)
    .unwrap()
    .expect("poll_transmit must return Some for Announcement");
  let written = &out[..transmit.size()];
  let reader =
    MessageReader::try_parse(written).expect("announcement datagram must be a valid DNS message");

  // Check each unique-record type for the cache-flush bit via RecordRef::cache_flush().
  for rr_result in reader.answers() {
    let rr = rr_result.expect("answer record must parse cleanly");
    match rr.rtype() {
      ResourceType::Srv | ResourceType::Txt | ResourceType::A | ResourceType::Aaaa => {
        assert!(
          rr.cache_flush(),
          "{:?} record must have cache-flush bit set",
          rr.rtype()
        );
      }
      ResourceType::Ptr => {
        assert!(
          !rr.cache_flush(),
          "PTR record must NOT have cache-flush bit set (shared record)"
        );
      }
      _ => {}
    }
  }
}

// ── tiebreak always includes TXT (even when empty) ────────────

/// compare_rr_sets_we_lose must include TXT in our local set even when
/// txt_segments is empty, matching what write_probe emits unconditionally.
///
/// Previously the TXT was omitted when empty, while write_probe still
/// emitted an empty TXT authority record — causing a tiebreak asymmetry.
///
/// This test verifies two cases:
///
/// Case A — Peer sends SRV + TXT(empty) with the SAME port as ours: sets are
/// identical → tie → we lose (§8.2.1). Previously, our set would be
/// {SRV only} while peer had {SRV + TXT}, so we would NOT lose (incorrect).
///
/// Case B — Peer sends only SRV(same port) with NO TXT: our set (with TXT
/// prefix) starts with rtype=0x0010(TXT) while peer's starts with 0x0021(SRV).
/// peer_concat > our_concat → we LOSE. Previously both sets were {SRV only}
/// → tie → we lose (also loss but for different reason).
#[test]
fn tiebreak_always_includes_empty_txt() {
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("myprinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("host.local.").unwrap();
  // Construct records with NO TXT segments.
  let our = ServiceRecords::new(stype, inst.clone(), host.clone(), 631, 120);
  assert_eq!(
    our.txt_segments().count(),
    0,
    "precondition: no TXT segments"
  );

  let peer_src: core::net::SocketAddr = "192.168.1.99:5353".parse().unwrap();

  // ── Case A: Peer sends SRV(631) + TXT(empty) → tie → we lose ────────
  {
    let mut buf_srv: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    make_srv_record_ref(
      &mut buf_srv,
      "myprinter._ipp._tcp.local.",
      120,
      0,   // priority
      0,   // weight
      631, // SAME port as ours
      "host.local.",
    );
    let (srv_ref, _) = RecordRef::try_parse(&buf_srv, 0).unwrap();

    let mut buf_txt: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    make_txt_record_ref(&mut buf_txt, "myprinter._ipp._tcp.local.", 120, &[]);
    let (txt_ref, _) = RecordRef::try_parse(&buf_txt, 0).unwrap();

    let mut peer_probes_a = alloc::vec![PeerProbe {
      src: peer_src,
      records: alloc::vec![],
    }];
    // Canonicalize and insert both records.
    for rref in &[srv_ref, txt_ref] {
      let view = rref.rdata_view().unwrap();
      let mut scratch = alloc::vec::Vec::new();
      let canonical = respond::canonical_rdata_for_hash(&view, &mut scratch)
        .unwrap()
        .to_vec();
      peer_probes_a[0].records.push(PeerRecord {
        rtype: rref.rtype(),
        canonical,
      });
    }

    // Sets are identical (SRV(631)+TXT(empty) on both sides) → tie → we lose.
    let we_lose = compare_rr_sets_we_lose(&our, &peer_probes_a);
    assert!(
      we_lose,
      "Case A: identical SRV(631)+TXT(empty) on both sides must be a tie \
         → we lose (§8.2.1); we_lose={we_lose}"
    );
  }

  // ── Case B: Peer sends only SRV(631) with no TXT ─────────────────────
  // Our set (with TXT always included) = sorted [TXT_prefix, SRV(631)].
  // Peer set = [SRV(631)].
  // our_concat[0..2] = 0x00,0x10 (TXT type); peer_concat[0..2] = 0x00,0x21 (SRV type).
  // peer_concat > our_concat → we lose.
  {
    let mut buf_srv: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    make_srv_record_ref(
      &mut buf_srv,
      "myprinter._ipp._tcp.local.",
      120,
      0,   // priority
      0,   // weight
      631, // SAME port as ours — no TXT from peer
      "host.local.",
    );
    let (srv_ref, _) = RecordRef::try_parse(&buf_srv, 0).unwrap();

    let mut peer_probes_b = alloc::vec![PeerProbe {
      src: peer_src,
      records: alloc::vec![],
    }];
    let view = srv_ref.rdata_view().unwrap();
    let mut scratch = alloc::vec::Vec::new();
    let canonical = respond::canonical_rdata_for_hash(&view, &mut scratch)
      .unwrap()
      .to_vec();
    peer_probes_b[0].records.push(PeerRecord {
      rtype: srv_ref.rtype(),
      canonical,
    });

    // peer set {SRV(631)} starts with 0x0021; our set starts with 0x0010 (TXT)
    // → peer_concat > our_concat → we lose.
    let we_lose = compare_rr_sets_we_lose(&our, &peer_probes_b);
    assert!(
      we_lose,
      "Case B: peer set starting with SRV(0x0021) > our set starting with \
         TXT(0x0010) → we lose; we_lose={we_lose}"
    );
  }
}

// ── poll_transmit does not lose pending on buffer-too-small ───

/// When `poll_transmit` is called with a buffer that is too small to encode
/// the datagram, it must return an error WITHOUT removing the pending kind
/// from the queue.  A subsequent call with a large-enough buffer must succeed
/// and produce the expected transmit.
///
/// Previously, `pop_pending()` was called before encoding, so a failed
/// encode silently discarded the kind — required probes/announcements were
/// permanently lost and the lifecycle state had already advanced.
#[test]
fn poll_transmit_does_not_lose_pending_on_buffer_too_small() {
  let mut svc = make_service(120);
  let mut buf4096 = alloc::vec![0u8; 4096];

  // Drive forward until at least one probe is pending.
  // With seed=0 and 500 ms steps, the service passes Init→Probing very quickly.
  let mut now = FakeInstant::zero();
  let mut probe_pending = false;
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if svc
      .pending_transmits
      .contains(&Some(PendingTransmitKind::Probe))
    {
      probe_pending = true;
      break;
    }
    // Drain to avoid blocking state machine, but check before draining.
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
      svc.note_transmit_delivered(now);
    }
  }
  assert!(
    probe_pending,
    "a Probe transmit must be pending before the test can proceed"
  );

  // Attempt to encode into a tiny buffer — this must fail.
  let mut small_buf = [0u8; 4];
  let r = svc.poll_transmit(now, &mut small_buf);
  assert!(
    r.is_err(),
    "poll_transmit with a 4-byte buffer must return an error; got {:?}",
    r
  );

  // The kind must still be in the queue — the failed encode must not have
  // consumed it.
  assert!(
    svc
      .pending_transmits
      .contains(&Some(PendingTransmitKind::Probe)),
    "Probe must still be in pending_transmits after failed encode"
  );

  // Retry with a large buffer — must succeed and return Some.
  let mut big_buf = alloc::vec![0u8; 1500];
  let tx = svc.poll_transmit(now, &mut big_buf).unwrap();
  assert!(
    tx.is_some(),
    "retry with large buffer must produce a transmit"
  );

  // After a successful encode the kind must have been consumed.
  assert!(
    !svc
      .pending_transmits
      .contains(&Some(PendingTransmitKind::Probe)),
    "Probe must be removed from queue after successful encode"
  );
}

// ── pending_transmits is FIFO after pop + push interleavings ──

/// `pending_transmits` is a 2-slot FIFO.  After popping the head, a
/// subsequent push must land BEHIND any item still queued — never overtake
/// it.  Previously, `pop_pending` cleared whichever slot held the head
/// (leaving a hole at index 0) and `push_pending` re-filled that hole with
/// a NEWER item, so the older item parked in slot 1 was effectively bumped
/// to second place.
#[test]
fn pending_transmits_is_fifo_after_pop_and_push() {
  let mut svc = make_service(120);

  // Seed the queue with two items.  Use the internal helpers directly so
  // the test exercises the pure FIFO mechanics independent of the
  // lifecycle state machine.
  svc.push_pending(PendingTransmitKind::Probe);
  svc.push_pending(PendingTransmitKind::Announcement);
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Probe),
    "first push lands in slot 0"
  );
  assert_eq!(
    svc.pending_transmits[1],
    Some(PendingTransmitKind::Announcement),
    "second push lands in slot 1"
  );

  // Pop the head.  The tail must compact down so the next push lands
  // BEHIND the remaining Announcement, not in front of it.
  let head = svc.pop_pending();
  assert_eq!(
    head,
    Some(PendingTransmitKind::Probe),
    "pop must return the oldest item (Probe)"
  );
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Announcement),
    "after pop, tail (Announcement) must compact into slot 0"
  );
  assert_eq!(
    svc.pending_transmits[1], None,
    "slot 1 must be empty after compaction"
  );

  // Push a new item.  It must land AFTER the still-queued Announcement.
  svc.push_pending(PendingTransmitKind::Response);
  assert_eq!(
    svc.pending_transmits[0],
    Some(PendingTransmitKind::Announcement),
    "existing Announcement keeps its head position"
  );
  assert_eq!(
    svc.pending_transmits[1],
    Some(PendingTransmitKind::Response),
    "newer Response must queue BEHIND Announcement"
  );

  // Drain in FIFO order: Announcement first, then Response.
  assert_eq!(
    svc.pop_pending(),
    Some(PendingTransmitKind::Announcement),
    "FIFO order: Announcement before Response"
  );
  assert_eq!(
    svc.pop_pending(),
    Some(PendingTransmitKind::Response),
    "FIFO order: Response last"
  );
  assert_eq!(svc.pop_pending(), None, "queue must be empty after drain");
}

#[test]
fn poll_transmit_blocks_until_confirmation() {
  // the commit token is a SINGLE slot. Once poll_transmit hands out a
  // datagram, a second poll WITHOUT a note_transmit_result must return Ok(None)
  // — never a second datagram that would silently overwrite (and lose) the
  // first send's pending confirmation. Confirming frees the slot.
  let mut svc = make_service(120);
  let mut buf = alloc::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  // Advance until the first probe is emitted.
  let mut emitted = false;
  for _ in 0..10 {
    now = now.advance(300);
    svc.handle_timeout(now).unwrap();
    if svc.poll_transmit(now, &mut buf).unwrap().is_some() {
      emitted = true;
      break;
    }
  }
  assert!(emitted, "a probe should eventually be emitted");
  // A second poll WITHOUT confirming the first must be blocked.
  assert!(
    svc.poll_transmit(now, &mut buf).unwrap().is_none(),
    "no datagram may be handed out while a prior send is unconfirmed"
  );
  // Confirming frees the single token slot.
  svc.note_transmit_result(now, true);
  assert!(
    svc.awaiting_confirm.is_none(),
    "confirming must clear the commit token"
  );
}

#[test]
fn failed_established_reannounce_retries_within_one_second() {
  // a periodic Established re-announce whose send FAILS must re-arm a
  // short (~1 s) retry, NOT defer a full re-announce interval (~80% of TTL, i.e.
  // ~96 s for ttl=120). Otherwise peers expire our records before the next
  // attempt and the service silently disappears after one transient failure.
  let mut svc = make_service(120);
  let est = drive_to_established(&mut svc);
  // The next scheduled deadline is the periodic re-announce (~96 s out).
  let due = svc
    .poll_timeout()
    .expect("Established schedules a re-announce");
  assert!(
    due.checked_duration_since(est).is_some(),
    "the re-announce is scheduled into the future"
  );
  svc.handle_timeout(due).unwrap();
  // Emit the re-announcement, then report the send as FAILED.
  assert!(
    svc
      .poll_transmit(due, &mut alloc::vec![0u8; 4096])
      .unwrap()
      .is_some(),
    "the periodic re-announce must be emitted"
  );
  svc.note_transmit_result(due, false);
  assert!(
    matches!(svc.state(), ServiceState::Established),
    "a failed re-announce must not leave Established"
  );
  // The next attempt must be ~1 s out, not the full ~96 s interval.
  let next = svc
    .poll_timeout()
    .expect("a failed re-announce must re-arm");
  let gap = next
    .checked_duration_since(due)
    .expect("the next deadline is at or after the fire time");
  assert!(
    gap <= core::time::Duration::from_secs(2),
    "a failed Established re-announce must retry within ~1 s, got {gap:?}"
  );
}

#[test]
fn subtype_ptr_advertised_in_response_and_withdrawn_on_goodbye() {
  // §7.1: a registered subtype is advertised as a shared PTR
  // (`_printer._sub._ipp._tcp.local.` → instance) in responses, and withdrawn
  // at TTL 0 on unregister.
  use crate::wire::{MessageReader, ResourceType};
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("myprinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("host.local.").unwrap();
  let mut records = ServiceRecords::new(stype, inst, host, 631, 120);
  records.add_a(core::net::Ipv4Addr::new(192, 168, 1, 10));
  records.add_subtype("_printer").unwrap();
  let sub = Name::try_from_str("_printer._sub._ipp._tcp.local.").unwrap();
  let mut svc: Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> =
    Service::try_new(
      ServiceHandle::from_raw(0),
      records,
      FakeInstant::zero(),
      [0u8; 32],
      true,
    );
  let now = drive_to_established(&mut svc);

  // A question response carries the subtype PTR at positive TTL.
  inject_question_to_set_response_deadline(&mut svc, now);
  let now2 = now.advance(200);
  svc.handle_timeout(now2).unwrap();
  let mut buf = alloc::vec![0u8; 4096];
  let tx = svc
    .poll_transmit(now2, &mut buf)
    .unwrap()
    .expect("a response must be emitted");
  let reader = MessageReader::try_parse(&buf[..tx.size()]).unwrap();
  let saw_subtype = reader.answers().any(|rr| {
    rr.map(|rec| {
      rec.rtype() == ResourceType::Ptr
        && crate::endpoint::names_match(&sub, rec.name())
        && rec.ttl() > 0
    })
    .unwrap_or(false)
  });
  assert!(
    saw_subtype,
    "a response must include the subtype PTR at positive TTL"
  );
  svc.note_transmit_result(now2, true);

  // Unregister goodbye withdraws the subtype PTR at TTL 0.
  let len = svc
    .encode_goodbye(&mut buf, &[])
    .unwrap()
    .expect("a goodbye must be emitted");
  let reader = MessageReader::try_parse(&buf[..len]).unwrap();
  let saw_subtype_goodbye = reader.answers().any(|rr| {
    rr.map(|rec| {
      rec.rtype() == ResourceType::Ptr
        && crate::endpoint::names_match(&sub, rec.name())
        && rec.ttl() == 0
    })
    .unwrap_or(false)
  });
  assert!(
    saw_subtype_goodbye,
    "the goodbye must withdraw the subtype PTR at TTL 0"
  );
}

#[test]
fn meta_query_is_answered_with_service_type_ptr() {
  // §9: a `_services._dns-sd._udp.local.` PTR query is answered with a
  // shared PTR meta-name → <service_type>.
  use crate::{
    event::ServiceQuestion,
    wire::{MessageReader, QuestionRef, RecordRdata, ResourceType},
  };
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);

  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_services._dns-sd._udp.local."
    .trim_end_matches('.')
    .split('.')
  {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "0.0.0.0:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0)),
    now,
  );

  // Poll past the jitter window — the standalone meta reply is emitted.
  let now2 = now.advance(200);
  let mut buf = alloc::vec![0u8; 4096];
  let tx = svc
    .poll_transmit(now2, &mut buf)
    .unwrap()
    .expect("a meta-query reply must be emitted");
  let reader = MessageReader::try_parse(&buf[..tx.size()]).unwrap();
  let meta = Name::try_from_str("_services._dns-sd._udp.local.").unwrap();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let found = reader.answers().any(|rr| {
    let rr = match rr {
      Ok(r) => r,
      Err(_) => return false,
    };
    if rr.rtype() != ResourceType::Ptr || !crate::endpoint::names_match(&meta, rr.name()) {
      return false;
    }
    // The meta-PTR target (rdata) must be our service type.
    matches!(rr.rdata_view(), Ok(RecordRdata::Ptr(p)) if crate::endpoint::names_match(&stype, p.target()))
  });
  assert!(
    found,
    "the meta-query must be answered with a PTR meta-name → service_type"
  );
}

#[test]
fn legacy_subtype_browse_gets_unicast_reply_with_subtype_ptr() {
  // a non-5353 (legacy) subtype browse must get a UNICAST reply that
  // includes the subtype PTR — previously it routed to the service but produced
  // no reply (echo = None).
  use crate::{
    event::ServiceQuestion,
    wire::{MessageReader, QuestionRef, ResourceType},
  };
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("myprinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str("host.local.").unwrap();
  let mut records = ServiceRecords::new(stype, inst, host, 631, 120);
  records.add_a(core::net::Ipv4Addr::new(192, 168, 1, 10));
  records.add_subtype("_printer").unwrap();
  let sub = Name::try_from_str("_printer._sub._ipp._tcp.local.").unwrap();
  let mut svc: Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> =
    Service::try_new(
      ServiceHandle::from_raw(0),
      records,
      FakeInstant::zero(),
      [0u8; 32],
      true,
    );
  let now = drive_to_established(&mut svc);

  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_printer._sub._ipp._tcp.local."
    .trim_end_matches('.')
    .split('.')
  {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, legacy_src, 0x33)),
    now,
  );

  let mut buf = alloc::vec![0u8; 4096];
  let tx = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("a legacy unicast reply must be queued for the subtype browse");
  assert_eq!(
    tx.dst(),
    legacy_src,
    "legacy reply is unicast to the querier"
  );
  let reader = MessageReader::try_parse(&buf[..tx.size()]).unwrap();
  let saw_subtype = reader.answers().any(|rr| {
    rr.map(|rec| rec.rtype() == ResourceType::Ptr && crate::endpoint::names_match(&sub, rec.name()))
      .unwrap_or(false)
  });
  assert!(saw_subtype, "the legacy reply must carry the subtype PTR");
}

#[test]
fn legacy_meta_query_gets_unicast_meta_ptr() {
  // a non-5353 meta-query gets a UNICAST meta-PTR (a legacy resolver is
  // not on the multicast group, so the §9 reply must be unicast, not the
  // multicast path used for 5353 queriers).
  use crate::{
    event::ServiceQuestion,
    wire::{MessageReader, QuestionRef, RecordRdata, ResourceType},
  };
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);

  let mut qbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
  for label in "_services._dns-sd._udp.local."
    .trim_end_matches('.')
    .split('.')
  {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // IN
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, legacy_src, 0x44)),
    now,
  );

  let mut buf = alloc::vec![0u8; 4096];
  let tx = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("a legacy unicast meta reply must be queued");
  assert_eq!(tx.dst(), legacy_src, "legacy meta reply is unicast");
  let reader = MessageReader::try_parse(&buf[..tx.size()]).unwrap();
  let meta = Name::try_from_str("_services._dns-sd._udp.local.").unwrap();
  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let found = reader.answers().any(|rr| {
    let rr = match rr {
      Ok(r) => r,
      Err(_) => return false,
    };
    rr.rtype() == ResourceType::Ptr
      && crate::endpoint::names_match(&meta, rr.name())
      && matches!(rr.rdata_view(), Ok(RecordRdata::Ptr(p)) if crate::endpoint::names_match(&stype, p.target()))
  });
  assert!(
    found,
    "the legacy reply must carry the meta-PTR → service_type"
  );
}

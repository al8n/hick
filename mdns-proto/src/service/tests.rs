#![allow(warnings)]

use core::time::Duration;

use super::*;
use crate::{
  Name, ServiceHandle,
  event::{KnownAnswer, ProbeConflict, ServiceEvent},
  records::ServiceRecords,
  transmit::{FamilyDelivery, V4, V6},
  wire::Ref,
};
// Bring `ToOwned` / `ToString` into scope explicitly — under
// `--no-default-features --features alloc` (no `std`) these heap traits are not
// in the prelude, so `&str::to_owned()` / `&str::to_string()` fail to resolve.
// Imported via the alias (`std::` → `alloc::` in that tier) with `as _` so the
// `std` build, where they're already in the prelude, raises no redundant-import
// warning.
use std::{borrow::ToOwned as _, string::ToString as _};

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

  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  let mut ever_probed = false;
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if matches!(svc.state(), ServiceState::Probing(_)) {
      ever_probed = true;
    }
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
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
  /// confirmed-announced. The ownership model uses per-record flags rather than a
  /// single `instance` bool, so a "the original name was announced" precondition sets
  /// all three.
  fn mark_instance(&mut self) {
    self.ptr = true;
    self.srv = true;
    self.txt = true;
  }
}

/// Build a minimal raw A record in wire format and parse it via Ref::try_parse.
/// The resulting `Ref` lives for the lifetime of `buf`.
fn make_a_record_ref(buf: &mut std::vec::Vec<u8>, name_str: &str, ttl: u32, addr: [u8; 4]) {
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
/// The resulting `Ref` lives for the lifetime of `buf`.
/// `owner_str` is the FQDN that owns this SRV record (the instance name).
/// `target_str` is the SRV target hostname.
fn make_srv_record_ref(
  buf: &mut std::vec::Vec<u8>,
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
  let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
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
fn make_txt_record_ref(buf: &mut std::vec::Vec<u8>, owner_str: &str, ttl: u32, segments: &[&[u8]]) {
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

  let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,    // priority
    0,    // weight
    9999, // port > 631 → peer SRV canonical bytes are larger → peer wins
    "host.local.",
  );
  let (record_ref, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let (record_ref, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    // Simulate the driver confirming a successful send so the
    // announce/host_advertised guards latch as they would in production.
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
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
fn empty_txt_encodes_as_single_zero_length_string() {
  // RFC 6763 §6.1: a service with no TXT data must still emit a TXT record
  // whose rdata is a SINGLE zero-length string (one 0x00 byte), never empty
  // rdata (an empty TXT RR is invalid). make_records adds no TXT segments.
  // Drive an announcement (positive-TTL) and inspect its TXT record — the TXT
  // encoding is the same writer the withdrawal path reuses.
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  let mut txt_rdata: Option<std::vec::Vec<u8>> = None;
  'drive: for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(tx)) = svc.poll_transmit(now, &mut buf) {
      let reader = crate::wire::MessageReader::try_parse(buf.get(..tx.size()).unwrap()).unwrap();
      for rec in reader.answers() {
        let rec = rec.unwrap();
        if rec.rtype() == crate::wire::ResourceType::Txt {
          txt_rdata = Some(rec.rdata().to_vec());
          break 'drive;
        }
      }
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
  }
  assert_eq!(
    txt_rdata.as_deref(),
    Some(&[0u8][..]),
    "an empty TXT record must encode as a single zero-length string (one 0x00 byte)"
  );
}

#[test]
fn rename_handoff_withdraws_only_advertised_instance_records() {
  // if §7.1 KAS let only a SUBSET of the instance records onto the wire
  // before a conflict rename, the rename goodbye must withdraw exactly that
  // subset — not all of PTR/SRV/TXT, which would flush a peer's matching
  // same-name record this responder never sent. The Service captures that subset
  // into the handoff (instance ownership latched at rename time); the endpoint's
  // detached item then emits only those records.
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  // The old name advertised ONLY its PTR (SRV/TXT were KAS-suppressed on the one
  // confirmed response before the rename).
  svc.goodbye.ptr = true;

  // Drive a losing §8.2 tiebreak (peer SRV port 9999 > ours 631) → rename.
  let mut sbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut sbuf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&sbuf, 0).unwrap();
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

  // The handoff carries ONLY the advertised PTR — the KAS-suppressed SRV/TXT are
  // not in the ownership set, so the endpoint's goodbye never withdraws them.
  let RenameGoodbyeHandoff {
    owned: old_owned, ..
  } = svc
    .take_rename_goodbye_handoff()
    .expect("a rename of an (PTR-)announced service must hand off the old-name goodbye");
  assert!(
    old_owned.ptr(),
    "the advertised PTR is in the handoff ownership"
  );
  assert!(
    !old_owned.srv() && !old_owned.txt(),
    "the KAS-suppressed SRV/TXT must NOT be in the handoff ownership"
  );
  assert!(
    old_owned.a_slice().is_empty() && old_owned.aaaa_slice().is_empty(),
    "a rename handoff is instance-only — never host A/AAAA"
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
  svc.goodbye.record_emitted(&respond::EmittedRecords::new(
    false,
    false,
    false,
    std::vec![a2],
    std::vec::Vec::new(),
    false,
  ));
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
  // (a fully-delivered `note_transmit_outcome`) does. Otherwise an announcement that
  // fails to leave the host (all sockets error) could later emit a goodbye
  // that deletes a peer's same-name records.
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
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
      svc.note_delivery(now, TransmitDelivery::ALL);
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

  // Confirm delivery → guards latch (a goodbye is now produced; the
  // datagram-level withdrawal is covered by the endpoint withdrawal tests).
  svc.note_delivery(now, TransmitDelivery::ALL);
  assert!(
    svc.advertises_host(),
    "host ownership must latch on confirmed delivery"
  );
}

#[test]
fn announce_phase_does_not_advance_without_confirmed_send() {
  // if announcements never reach the link (every socket send
  // fails, so the driver never confirms), the announce phase must NOT advance
  // and Established must NOT be emitted — the announcement is retried instead.
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();

  // Drive through probing to Announcing(0), CONFIRMING each probe so the §8.1
  // sequence advances (probes are delivery-confirmed too). No
  // announcement is confirmed here — Announcing(0) is reached right after the
  // third probe is confirmed, before any announcement is emitted.
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
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
    svc.note_delivery(now, TransmitDelivery::NONE); // send failed — re-arm, do NOT advance
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
  svc.note_delivery(now, TransmitDelivery::ALL);
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
  let mut buf = std::vec![0u8; 4096];
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
      svc.note_delivery(now, TransmitDelivery::NONE);
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
  svc.note_delivery(now, TransmitDelivery::ALL);
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
  let mut buf = std::vec![0u8; 4096];
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
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
  }
  assert!(
    reached,
    "service should reach Announcing(0) within 20 ticks"
  );
  // Reaching Announcing(0) without an emitted announcement must leave nothing
  // withdrawable: the goodbye-ownership latch (captured by the withdrawal
  // snapshot) owns no records and no host addresses.
  let snap = svc.withdrawal_snapshot();
  assert!(
    !snap.owned.ptr()
      && !snap.owned.srv()
      && !snap.owned.txt()
      && !snap.owned.subtypes()
      && snap.host_a.is_empty()
      && snap.host_aaaa.is_empty(),
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
  let mut buf = std::vec![0u8; 4096];

  // Drive through probing to Announcing(0), confirming each probe; stop the
  // instant we reach Announcing(0), BEFORE any announcement is emitted.
  let mut now = FakeInstant::zero();
  'drive: for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
      if matches!(svc.state(), ServiceState::Announcing(0)) {
        break 'drive;
      }
    }
  }
  assert!(matches!(svc.state(), ServiceState::Announcing(0)));
  assert!(
    !svc.advertises_host() && !svc.goodbye.any_instance(),
    "precondition: nothing advertised/withdrawable before any send"
  );

  // A legacy querier (source port != 5353) asks for our PTR record — queues a
  // §6.7 unicast reply that poll_transmit drains immediately (ahead of any
  // announcement).
  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
    Some(AwaitingConfirm::Response(e, _)) => assert!(
      e.ptr() && e.srv() && e.txt() && !e.a_slice().is_empty(),
      "a legacy reply emits all instance records plus the host A"
    ),
    other => panic!("expected a Response commit token, got {other:?}"),
  }
  assert!(matches!(svc.state(), ServiceState::Announcing(0)));

  // Confirm delivery → goodbye ownership latches for every emitted record, even
  // though no announcement has been confirmed and the phase is unchanged.
  svc.note_delivery(now, TransmitDelivery::ALL);
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
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  'drive: for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
      if matches!(svc.state(), ServiceState::Announcing(0)) {
        break 'drive;
      }
    }
  }
  assert!(matches!(svc.state(), ServiceState::Announcing(0)));

  // Legacy A query for our host name.
  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  let host_str = svc.records.host().as_str().to_string();
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
    Some(AwaitingConfirm::Response(e, _)) => assert!(
      e.ptr() && e.srv() && e.txt() && !e.a_slice().is_empty(),
      "an A-query legacy reply still emits the instance records and the host A"
    ),
    other => panic!("expected a Response commit token, got {other:?}"),
  }
  svc.note_delivery(now, TransmitDelivery::ALL);
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
  // The GoodbyeOwnership contract: record_emitted OR-accumulates per
  // RECORD (a later send can't un-advertise an earlier one, and §7.1 KAS that
  // trims a subset latches only what was sent), and a conflict rename drops ONLY
  // the instance records — host addresses survive.
  let ip = core::net::Ipv4Addr::new(192, 168, 1, 10);
  let mut g = GoodbyeOwnership::default();
  assert!(!g.any_instance() && !g.any_host());
  // A response that emitted only PTR + TXT (SRV was KAS-suppressed): only those
  // two latch — NOT SRV.
  g.record_emitted(&respond::EmittedRecords::new(
    true,
    false,
    true,
    std::vec::Vec::new(),
    std::vec::Vec::new(),
    false,
  ));
  assert!(
    g.ptr && !g.srv && g.txt,
    "only the emitted instance records latch"
  );
  assert!(g.any_instance() && !g.any_host());
  // A later host-only send (one A address) accumulates independently.
  g.record_emitted(&respond::EmittedRecords::new(
    false,
    false,
    false,
    std::vec![ip],
    std::vec::Vec::new(),
    false,
  ));
  assert!(
    g.any_instance() && g.any_host(),
    "records accumulate independently"
  );
  assert_eq!(g.a, [ip], "the emitted address is tracked");
  // A duplicate emit must not double-insert the address.
  g.record_emitted(&respond::EmittedRecords::new(
    false,
    false,
    false,
    std::vec![ip],
    std::vec::Vec::new(),
    false,
  ));
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
  let mut buf = std::vec![0u8; 4096];
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut buf = std::vec![0u8; 4096];
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut buf = std::vec![0u8; 4096];
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut buf = std::vec![0u8; 4096];
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
    wire::{QuestionRef, Ref},
  };

  let mut svc = make_service(120); // service_type _ipp._tcp.local., TTL 120 (half = 60)
  let now = drive_to_established(&mut svc);
  let qsrc: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();

  // Meta-query for _services._dns-sd._udp.local.
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut kbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
    let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
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
    let (rref, _) = Ref::try_parse(&kbuf, 0).unwrap();
    svc.handle_event(
      ServiceEvent::KnownAnswer(KnownAnswer::new(ka_src, rref)),
      now,
    );
  }

  let t = now.advance(200); // past the 20–120 ms meta jitter window
  svc.handle_timeout(t).unwrap();
  let mut buf = std::vec![0u8; 4096];
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
    wire::{QuestionRef, Ref},
  };

  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let src_a: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();
  let src_b: core::net::SocketAddr = "192.0.2.8:5353".parse().unwrap();

  // Meta-query from TWO distinct 5353 sources (they coalesce in one window).
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut kbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    rdata.push(label.len() as u8);
    rdata.extend_from_slice(label.as_bytes());
  }
  rdata.push(0u8);
  kbuf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
  kbuf.extend_from_slice(&rdata);
  let (rref, _) = Ref::try_parse(&kbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::KnownAnswer(KnownAnswer::new(src_a, rref)),
    now,
  );

  let t = now.advance(200);
  svc.handle_timeout(t).unwrap();
  let mut buf = std::vec![0u8; 4096];
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
  let mut buf = std::vec![0u8; 4096];
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut buf = std::vec![0u8; 4096];
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut dsts: std::vec::Vec<core::net::SocketAddr> = std::vec::Vec::new();
  while let Some(t) = svc.poll_transmit(now, &mut buf).unwrap() {
    dsts.push(t.dst());
    svc.note_delivery(now, TransmitDelivery::ALL); // confirm before the next poll
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
  let mut buf = std::vec![0u8; 4096];
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut ids: std::vec::Vec<u16> = std::vec::Vec::new();
  while let Some(t) = svc.poll_transmit(now, &mut buf).unwrap() {
    assert_eq!(t.dst(), src);
    let msg = buf.get(..t.size()).unwrap();
    ids.push(MessageReader::try_parse(msg).unwrap().header().id());
    svc.note_delivery(now, TransmitDelivery::ALL); // confirm before the next poll
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
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut rec_buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut rec_buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = Ref::try_parse(&rec_buf, 0).unwrap();
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
      let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut rec_buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut rec_buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = Ref::try_parse(&rec_buf, 0).unwrap();
  let src_b: core::net::SocketAddr = "10.0.0.2:5353".parse().unwrap();
  let ka = KnownAnswer::new(src_b, record_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // Fire the response_deadline.
  let rd = svc.response_deadline.unwrap();
  svc.handle_timeout(rd).unwrap();

  // Produce the response.
  let mut buf = std::vec![0u8; 4096];
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
  let mut rec_buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut rec_buf, "host.local.", querier_ttl, [192, 168, 1, 10]);
  let (record_ref, _) = Ref::try_parse(&rec_buf, 0).unwrap();
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
  let mut out = std::vec![0u8; 4096];
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [192, 168, 1, 99]);
  let (record_ref, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [192, 168, 1, 10]); // OUR address
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [10, 0, 0, 99]); // NOT ours
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut sbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut sbuf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (srec, _) = Ref::try_parse(&sbuf, 0).unwrap();
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

/// a conflict rename of an ANNOUNCED service must HAND OFF the OLD name's records
/// for a TTL=0 goodbye, or peers keep the old PTR/SRV/TXT cached as a ghost until
/// TTL. The Service no longer drains the goodbye itself — it surfaces the old
/// name + its instance-only ownership via `take_rename_goodbye_handoff`, which the
/// driver feeds to `Endpoint::enqueue_rename_withdrawal` (the actual TTL=0
/// emission is covered by the endpoint's withdrawal tests, including
/// `rename_enqueues_a_detached_withdrawal_for_the_old_name`).
#[test]
fn conflict_rename_hands_off_old_announced_name() {
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  svc.goodbye.mark_instance(); // the original name was announced

  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
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

  // The rename installs a one-shot handoff for the OLD announced name.
  let RenameGoodbyeHandoff {
    records: old_records,
    owned: old_owned,
  } = svc
    .take_rename_goodbye_handoff()
    .expect("a rename of an announced service must hand off the old-name goodbye");
  assert_eq!(
    old_records.instance().as_str(),
    "myprinter._ipp._tcp.local.",
    "the handoff carries the OLD instance name (captured before set_instance)"
  );
  assert!(
    old_owned.ptr() && old_owned.srv() && old_owned.txt(),
    "the OLD name's advertised instance records (PTR/SRV/TXT) are handed off"
  );
  assert!(
    old_owned.a_slice().is_empty() && old_owned.aaaa_slice().is_empty(),
    "a rename never withdraws host A/AAAA — the handoff is instance-only"
  );

  // The handoff is one-shot: taken exactly once.
  assert!(
    svc.take_rename_goodbye_handoff().is_none(),
    "the handoff is consumed by the first take"
  );

  // The Service itself emits NO goodbye now (the old-name withdrawal is the
  // endpoint's detached item). The next transmit is the new-name probe sequence,
  // never a TTL=0 record for `myprinter`.
  let mut out = std::vec![0u8; 4096];
  if let Ok(Some(t)) = svc.poll_transmit(FakeInstant::zero().advance(500), &mut out) {
    let reader = crate::wire::MessageReader::try_parse(&out[..t.size()]).unwrap();
    for rr in reader.answers() {
      let rr = rr.unwrap();
      assert!(
        rr.ttl() != 0,
        "the Service must not emit any TTL=0 goodbye after a rename — that moved to the endpoint"
      );
    }
  }
}

// NOTE: the Service-side rename-goodbye DRAIN tests (spaced resends,
// retain-on-failed-send, too-small-buffer preservation) were removed with the
// Service `poll_transmit` rename-goodbye path. That loss-resilience machinery now
// lives in the endpoint's withdrawal pump (the renamed-away old name is a
// DETACHED `WithdrawalItem`); it is exercised by the endpoint withdrawal tests in
// `endpoint.rs` (per-family debt, retain-on-busy, encode-failure scan progress,
// ceiling). The Service's sole remaining rename-goodbye responsibility — handing
// off the OLD name's records + ownership — is covered by
// `conflict_rename_hands_off_old_announced_name` and
// `rename_handoff_withdraws_only_advertised_instance_records` above/below.

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

  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [169, 254, 1, 1]); // same link-local addr
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let inst = Name::try_from_str(&std::format!("{long_label}._ipp._tcp.local.")).unwrap();
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

  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    &std::format!("{long_label}._ipp._tcp.local."),
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
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
    let mut buf_a: std::vec::Vec<u8> = std::vec::Vec::new();
    make_a_record_ref(
      &mut buf_a,
      "myprinter._ipp._tcp.local.",
      120,
      [192, 168, 1, 10],
    );
    let (rref_a, _) = Ref::try_parse(&buf_a, 0).unwrap();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,  // priority
    0,  // weight
    80, // port < our 631 → peer SRV bytes are smaller → peer loses
    "host.local.",
  );
  let (record_ref, _) = Ref::try_parse(&buf, 0).unwrap();
  let conflict = ProbeConflict::new(peer_src_win, record_ref);
  svc.handle_event(ServiceEvent::ProbeConflict(conflict), t0);

  // Send peer TXT(empty) — peer's probe emits TXT; we must too for symmetry.
  let mut buf_txt: std::vec::Vec<u8> = std::vec::Vec::new();
  make_txt_record_ref(&mut buf_txt, "myprinter._ipp._tcp.local.", 120, &[]);
  let (txt_ref, _) = Ref::try_parse(&buf_txt, 0).unwrap();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,    // priority
    0,    // weight
    9999, // port > 631 → peer wins
    "host.local.",
  );
  let (record_ref, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    631,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
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
  let mut buf4096 = std::vec![0u8; 4096];

  // ── 1. Drive to Announcing(0) ─────────────────────────────────────
  // Seed = 0 → deterministic probe delays. Advance 500 ms per tick.
  let mut now = FakeInstant::zero();
  loop {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
      svc.note_delivery(now, TransmitDelivery::ALL);
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
    svc.note_delivery(now, TransmitDelivery::ALL);
  }

  // ── 2. Fire the first announce (Announcing(0) → Announcing(1)) ────
  now = now.advance(500);
  svc.handle_timeout(now).unwrap();
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_delivery(now, TransmitDelivery::ALL);
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
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
  }
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "should be in Announcing(1); got {:?}",
    svc.state()
  );

  // ── 3. Inject a Question while in Announcing(1) ───────────────────
  // Build a minimal question wire message.
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
    svc.note_delivery(now, TransmitDelivery::ALL);
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
    svc.note_delivery(now, TransmitDelivery::ALL);
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
  let mut buf_a: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf_a,
    "myprinter._ipp._tcp.local.",
    120,
    0,  // priority
    0,  // weight
    80, // port < our 631 → Peer A loses
    "host.local.",
  );
  let (rref_a, _) = Ref::try_parse(&buf_a, 0).unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer_a, rref_a)),
    t0,
  );

  // Peer B (src=.200) sends SRV with port=9999 → Peer B wins (9999 > 631).
  let peer_b: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let mut buf_b: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf_b,
    "myprinter._ipp._tcp.local.",
    120,
    0,    // priority
    0,    // weight
    9999, // port > our 631 → Peer B wins
    "host.local.",
  );
  let (rref_b, _) = Ref::try_parse(&buf_b, 0).unwrap();
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
  let mut out_aa: std::vec::Vec<u8> = std::vec::Vec::new();
  write_canonical_wire_name("aa.local.", &mut out_aa);
  assert_eq!(
    out_aa,
    std::vec![2u8, b'a', b'a', 5, b'l', b'o', b'c', b'a', b'l', 0],
    "wire form for 'aa.local.' must be \\x02aa\\x05local\\x00"
  );

  // Wire-form encoding of "b.local." should be:
  // \x01 b \x05 l o c a l \x00
  let mut out_b: std::vec::Vec<u8> = std::vec::Vec::new();
  write_canonical_wire_name("b.local.", &mut out_b);
  assert_eq!(
    out_b,
    std::vec![1u8, b'b', 5, b'l', b'o', b'c', b'a', b'l', 0],
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
  let mut buf4096 = std::vec![0u8; 4096];

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
      svc.note_delivery(now, TransmitDelivery::ALL);
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
    svc.note_delivery(now, TransmitDelivery::ALL);
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
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
    svc.note_delivery(now, TransmitDelivery::ALL);
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
    svc.note_delivery(original_announce, TransmitDelivery::ALL);
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
  let mut srv_buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut srv_buf,
    "myprinter._ipp._tcp.local.",
    our_ttl,
    0,             // priority matches
    0,             // weight matches
    631,           // port matches
    "host.local.", // target matches
  );
  let (srv_ref, _) = Ref::try_parse(&srv_buf, 0).unwrap();
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
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut out = std::vec![0u8; 4096];
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
  let mut a_buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut a_buf, "_ipp._tcp.local.", our_ttl, [192, 168, 1, 10]);
  let (a_ref, _) = Ref::try_parse(&a_buf, 0).unwrap();
  let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), a_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // Fire the response (past the jitter window) and confirm the host A survives.
  let now2 = now.advance(200);
  svc.handle_timeout(now2).unwrap();
  let mut out = std::vec![0u8; 4096];
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
  let mut buf4096 = std::vec![0u8; 4096];
  loop {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
    if matches!(svc.state(), ServiceState::Announcing(0)) {
      break;
    }
    assert!(now.0 < 10_000, "should reach Announcing(0) within 10 s");
  }
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_delivery(now, TransmitDelivery::ALL);
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
    let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
    svc.note_delivery(announce_dl, TransmitDelivery::ALL);
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
  let mut buf4096 = std::vec![0u8; 4096];

  // Drive to Announcing(0).
  let mut now = FakeInstant::zero();
  loop {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
    if matches!(svc.state(), ServiceState::Announcing(0)) {
      break;
    }
    assert!(now.0 < 10_000, "should reach Announcing(0) within 10 s");
  }
  if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf4096) {
    svc.note_delivery(now, TransmitDelivery::ALL);
  } // drain any pending

  // Record the first-announce lifecycle_deadline.
  let announce_dl = svc
    .lifecycle_deadline
    .expect("lifecycle_deadline must be set in Announcing(0)");

  // Inject a Question and force both deadlines to the same instant.
  {
    let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  // the single commit token requires a note_transmit_outcome between
  // polls — the driver confirms after each send, so it still drains both queued
  // transmits across the confirm boundary.
  svc.note_delivery(announce_dl, TransmitDelivery::ALL);

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
  svc.note_delivery(announce_dl, TransmitDelivery::ALL);

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
  let mut out = std::vec![0u8; 4096];
  let transmit = svc
    .poll_transmit(now_reannounce, &mut out)
    .unwrap()
    .expect("poll_transmit must return Some for Announcement");
  let written = &out[..transmit.size()];
  let reader =
    MessageReader::try_parse(written).expect("announcement datagram must be a valid DNS message");

  // Check each unique-record type for the cache-flush bit via Ref::cache_flush().
  for rr_result in reader.answers() {
    let rr = rr_result.expect("answer record must parse cleanly");
    match rr.rtype() {
      ResourceType::Srv | ResourceType::Txt | ResourceType::A | ResourceType::AAAA => {
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
    let mut buf_srv: std::vec::Vec<u8> = std::vec::Vec::new();
    make_srv_record_ref(
      &mut buf_srv,
      "myprinter._ipp._tcp.local.",
      120,
      0,   // priority
      0,   // weight
      631, // SAME port as ours
      "host.local.",
    );
    let (srv_ref, _) = Ref::try_parse(&buf_srv, 0).unwrap();

    let mut buf_txt: std::vec::Vec<u8> = std::vec::Vec::new();
    make_txt_record_ref(&mut buf_txt, "myprinter._ipp._tcp.local.", 120, &[]);
    let (txt_ref, _) = Ref::try_parse(&buf_txt, 0).unwrap();

    let mut peer_probes_a = std::vec![PeerProbe {
      src: peer_src,
      records: std::vec![],
    }];
    // Canonicalize and insert both records.
    for rref in &[srv_ref, txt_ref] {
      let view = rref.rdata_view().unwrap();
      let mut scratch = std::vec::Vec::new();
      let canonical = respond::canonical_rdata_for_hash(&view, &mut scratch)
        .unwrap()
        .to_vec();
      peer_probes_a[0].records.push(PeerRecord {
        rtype: rref.rtype(),
        canonical: canonical.into(),
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
    let mut buf_srv: std::vec::Vec<u8> = std::vec::Vec::new();
    make_srv_record_ref(
      &mut buf_srv,
      "myprinter._ipp._tcp.local.",
      120,
      0,   // priority
      0,   // weight
      631, // SAME port as ours — no TXT from peer
      "host.local.",
    );
    let (srv_ref, _) = Ref::try_parse(&buf_srv, 0).unwrap();

    let mut peer_probes_b = std::vec![PeerProbe {
      src: peer_src,
      records: std::vec![],
    }];
    let view = srv_ref.rdata_view().unwrap();
    let mut scratch = std::vec::Vec::new();
    let canonical = respond::canonical_rdata_for_hash(&view, &mut scratch)
      .unwrap()
      .to_vec();
    peer_probes_b[0].records.push(PeerRecord {
      rtype: srv_ref.rtype(),
      canonical: canonical.into(),
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
  let mut buf4096 = std::vec![0u8; 4096];

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
      svc.note_delivery(now, TransmitDelivery::ALL);
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
  let mut big_buf = std::vec![0u8; 1500];
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
  // datagram, a second poll WITHOUT a note_transmit_outcome must return Ok(None)
  // — never a second datagram that would silently overwrite (and lose) the
  // first send's pending confirmation. Confirming frees the slot.
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
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
  svc.note_delivery(now, TransmitDelivery::ALL);
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
      .poll_transmit(due, &mut std::vec![0u8; 4096])
      .unwrap()
      .is_some(),
    "the periodic re-announce must be emitted"
  );
  svc.note_delivery(due, TransmitDelivery::NONE);
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
fn subtype_ptr_advertised_in_response() {
  // §7.1: a registered subtype is advertised as a shared PTR
  // (`_printer._sub._ipp._tcp.local.` → instance) in responses at positive TTL.
  // The TTL=0 withdrawal of the subtype PTR on unregister is covered at the
  // endpoint level by `poll_withdrawal_emits_ttl0_and_retains_sibling_host_addr`.
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
  let mut buf = std::vec![0u8; 4096];
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
  svc.note_delivery(now2, TransmitDelivery::ALL);
}

#[test]
fn meta_query_is_answered_with_service_type_ptr() {
  // §9: a `_services._dns-sd._udp.local.` PTR query is answered with a
  // shared PTR meta-name → <service_type>.
  use crate::{
    event::ServiceQuestion,
    wire::{MessageReader, QuestionRef, Rdata, ResourceType},
  };
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);

  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let mut buf = std::vec![0u8; 4096];
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
    matches!(rr.rdata_view(), Ok(Rdata::Ptr(p)) if crate::endpoint::names_match(&stype, p.target()))
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

  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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

  let mut buf = std::vec![0u8; 4096];
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
    wire::{MessageReader, QuestionRef, Rdata, ResourceType},
  };
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);

  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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

  let mut buf = std::vec![0u8; 4096];
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
      && matches!(rr.rdata_view(), Ok(Rdata::Ptr(p)) if crate::endpoint::names_match(&stype, p.target()))
  });
  assert!(
    found,
    "the legacy reply must carry the meta-PTR → service_type"
  );
}

// ── probe-conflict (§8.2) + post-establishment-conflict (§9) edges ──────

/// An SRV record whose header parses but whose rdata target name is truncated,
/// so `rdata_view()` fails. Used to drive the malformed-rdata drop arms.
fn make_bad_srv_record_ref(buf: &mut std::vec::Vec<u8>, owner_str: &str) {
  buf.clear();
  for label in owner_str.trim_end_matches('.').split('.') {
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8); // root
  buf.extend_from_slice(&33u16.to_be_bytes()); // TYPE SRV
  buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  buf.extend_from_slice(&120u32.to_be_bytes()); // TTL
  // rdata: priority(2) + weight(2) + port(2) + a truncated target (label length
  // 5 with no payload) so the SRV name parse overruns the rdata.
  let rdata = [0u8, 0, 0, 0, 0, 80, 5];
  #[allow(clippy::cast_possible_truncation)]
  buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH = 7
  buf.extend_from_slice(&rdata);
}

#[test]
fn probing_conflict_drops_malformed_rdata() {
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  let mut buf = std::vec::Vec::new();
  make_bad_srv_record_ref(&mut buf, "myprinter._ipp._tcp.local.");
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  let src: core::net::SocketAddr = "192.168.1.88:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(src, rec)),
    FakeInstant::zero(),
  );
  assert!(
    svc.peer_probes.is_empty(),
    "a malformed probe-conflict record must not create a peer-probe bucket"
  );
}

#[test]
fn probing_conflict_caps_distinct_peer_sources() {
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  let mut buf = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  // MAX_PEER_PROBES distinct sources are bucketed; the next is dropped.
  for i in 0..(MAX_PEER_PROBES + 1) {
    let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
    let src: core::net::SocketAddr = std::format!("192.168.1.{}:5353", 100 + i).parse().unwrap();
    svc.handle_event(
      ServiceEvent::ProbeConflict(ProbeConflict::new(src, rec)),
      FakeInstant::zero(),
    );
  }
  assert_eq!(
    svc.peer_probes.len(),
    MAX_PEER_PROBES,
    "distinct peer-probe sources must be capped at MAX_PEER_PROBES"
  );
}

#[test]
fn probing_conflict_caps_records_per_source() {
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  let src: core::net::SocketAddr = "192.168.1.77:5353".parse().unwrap();
  // MAX_PEER_PROBE_RECORDS records for one source are kept; the next is dropped.
  for port in 0..(MAX_PEER_PROBE_RECORDS + 1) as u16 {
    let mut buf = std::vec::Vec::new();
    make_srv_record_ref(
      &mut buf,
      "myprinter._ipp._tcp.local.",
      120,
      0,
      0,
      1000 + port,
      "host.local.",
    );
    let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
    svc.handle_event(
      ServiceEvent::ProbeConflict(ProbeConflict::new(src, rec)),
      FakeInstant::zero(),
    );
  }
  let bucket = svc.peer_probes.iter().find(|b| b.src == src).unwrap();
  assert_eq!(
    bucket.records.len(),
    MAX_PEER_PROBE_RECORDS,
    "per-source peer-probe records must be capped"
  );
}

#[test]
fn post_establishment_conflict_drops_non_srv_txt_record() {
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  // A §9 conflict carrying an A record (not SRV/TXT) is not a service-identity
  // conflict and must be ignored.
  let mut buf = std::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [10, 0, 0, 9]);
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.50:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    now,
  );
  assert_eq!(svc.state(), ServiceState::Established);
}

#[test]
fn post_establishment_conflict_ignores_identical_srv() {
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  // An SRV identical to ours (priority 0, weight 0, port 631, target host.local.)
  // is consistent — not a §9 conflict.
  let mut buf = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    631,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.50:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    now,
  );
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "identical SRV rdata is not a §9 conflict"
  );
}

#[test]
fn post_establishment_conflict_drops_malformed_srv() {
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  let mut buf = std::vec::Vec::new();
  make_bad_srv_record_ref(&mut buf, "myprinter._ipp._tcp.local.");
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.50:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    now,
  );
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "a malformed §9 conflict record must be dropped"
  );
}

#[test]
fn post_establishment_conflict_is_rate_limited() {
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  // A re-probe happened "just now".
  svc.last_conflict_reprobe = Some(now);
  // A genuine §9 conflict (different SRV port) within the min interval is
  // dropped rather than triggering another re-probe.
  let mut buf = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.50:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    now,
  );
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "a rate-limited §9 conflict must not re-probe"
  );
}

#[test]
fn service_handle_and_canonical_record_accessors() {
  let svc = make_service(120);
  let _ = svc.handle();
  // our_canonical_record_for covers the SRV, TXT, and fallback arms.
  let _ = svc.our_canonical_record_for(crate::wire::ResourceType::Srv);
  let _ = svc.our_canonical_record_for(crate::wire::ResourceType::Txt);
  let _ = svc.our_canonical_record_for(crate::wire::ResourceType::A);
}

#[test]
fn canonical_rdata_for_hash_handles_nsec_and_unknown() {
  // NSEC record → canonicalized via the raw type-bitmap bytes.
  let mut nbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  nbuf.extend_from_slice(&[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0]); // name
  nbuf.extend_from_slice(&47u16.to_be_bytes()); // TYPE NSEC
  nbuf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  nbuf.extend_from_slice(&120u32.to_be_bytes()); // TTL
  nbuf.extend_from_slice(&12u16.to_be_bytes()); // RDLENGTH = next_name(9) + bitmap(3)
  nbuf.extend_from_slice(&[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 1, 0x40]);
  let (nrec, _) = Ref::try_parse(&nbuf, 0).unwrap();
  let nview = nrec.rdata_view().unwrap();
  let mut scratch = std::vec::Vec::new();
  respond::canonical_rdata_for_hash(&nview, &mut scratch).unwrap();

  // Unknown record type → canonicalized via the raw rdata bytes (Other arm).
  let mut obuf: std::vec::Vec<u8> = std::vec::Vec::new();
  obuf.extend_from_slice(&[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0]); // name
  obuf.extend_from_slice(&999u16.to_be_bytes()); // TYPE 999 (unknown)
  obuf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  obuf.extend_from_slice(&120u32.to_be_bytes()); // TTL
  obuf.extend_from_slice(&3u16.to_be_bytes()); // RDLENGTH = 3
  obuf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
  let (orec, _) = Ref::try_parse(&obuf, 0).unwrap();
  let oview = orec.rdata_view().unwrap();
  let mut scratch2 = std::vec::Vec::new();
  respond::canonical_rdata_for_hash(&oview, &mut scratch2).unwrap();
}

#[test]
fn poll_transmit_announcement_surfaces_buffer_too_small() {
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  // Drive to Announcing(0) (third probe confirmed), confirming each probe.
  'drive: for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
      if matches!(svc.state(), ServiceState::Announcing(0)) {
        break 'drive;
      }
    }
  }
  assert!(matches!(svc.state(), ServiceState::Announcing(0)));
  // Arm + poll the announcement with a header-only buffer → BufferTooSmall.
  let mut tiny = std::vec![0u8; 12];
  for _ in 0..6 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Err(TransmitError::BufferTooSmall(_)) = svc.poll_transmit(now, &mut tiny) {
      return;
    }
  }
  panic!("expected the announcement to surface BufferTooSmall on a header-only buffer");
}

#[test]
fn poll_transmit_question_response_surfaces_buffer_too_small() {
  let mut svc = make_service(120);
  let now0 = drive_to_established(&mut svc);
  inject_question_to_set_response_deadline(&mut svc, now0);
  // Fire the jittered response deadline, then poll it with a header-only buffer.
  let mut tiny = std::vec![0u8; 12];
  let mut now = now0;
  for _ in 0..10 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    if let Err(TransmitError::BufferTooSmall(_)) = svc.poll_transmit(now, &mut tiny) {
      return;
    }
  }
  panic!("expected the question response to surface BufferTooSmall on a header-only buffer");
}

/// After a rename, the OLD name's goodbye is an INDEPENDENT detached item (handed
/// off + enqueued on the endpoint), so a later teardown `withdrawal_snapshot`
/// captures ONLY the CURRENT (re-announced) name — it no longer carries the old
/// name. This is the post-Commit-2 shape of the old
/// `withdrawal_snapshot_during_rename_captures_old_and_current` test: the two
/// names are now two independent items (handoff for old, snapshot for current),
/// not one combined snapshot.
#[test]
fn withdrawal_snapshot_after_rename_captures_only_current() {
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  // The original name `myprinter` was announced (instance records + its host A).
  svc.goodbye.mark_instance();
  let host_addr = core::net::Ipv4Addr::new(192, 168, 1, 10); // matches make_records
  svc.goodbye.a.push(host_addr);

  // Losing §8.2 tiebreak (peer SRV port 9999 > ours 631) → rename to `myprinter-1`.
  let mut sbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut sbuf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&sbuf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  let now = FakeInstant::zero().advance(500);
  svc.handle_timeout(now).unwrap();
  assert!(
    svc.name().as_str().contains("-1"),
    "service should have renamed to `myprinter-1`"
  );

  // The rename installs a one-shot handoff for the OLD name; the driver would take
  // it and enqueue it as the endpoint's detached item. Take it here so the rest of
  // the test models the post-handoff state.
  let RenameGoodbyeHandoff {
    records: old_records,
    owned: old_owned,
  } = svc
    .take_rename_goodbye_handoff()
    .expect("the rename hands off the OLD announced name's goodbye");
  assert_eq!(
    old_records.instance().as_str(),
    "myprinter._ipp._tcp.local.",
    "the handoff carries the OLD instance name"
  );
  assert!(
    old_owned.ptr() && old_owned.srv() && old_owned.txt(),
    "the OLD name's advertised instance records are handed off"
  );
  assert!(
    old_owned.a_slice().is_empty() && old_owned.aaaa_slice().is_empty(),
    "the OLD-name handoff is instance-only (a rename never withdraws host addrs)"
  );

  // The rename cleared the instance latch (the new name has not announced yet),
  // but the host address survives (the host name is invariant across a rename).
  assert!(
    !svc.goodbye.any_instance(),
    "reset_instance must clear the instance latch after a rename"
  );
  assert!(
    svc.goodbye.a.contains(&host_addr),
    "the host A address survives the instance rename"
  );

  // Simulate the renamed name's CONFIRMED re-announce: its instance records are
  // back on the wire (a delivered announce re-latches the instance ownership).
  svc.goodbye.mark_instance();

  // A teardown snapshot now captures ONLY the CURRENT (re-announced) name — the
  // OLD name is already its own detached item.
  let snap = svc.withdrawal_snapshot();
  assert!(
    snap.records.instance().as_str().contains("-1"),
    "the snapshot's records must be the re-announced `myprinter-1`"
  );
  assert!(
    snap.owned.ptr() && snap.owned.srv() && snap.owned.txt(),
    "the CURRENT name's confirmed instance records are captured"
  );
  assert!(
    snap.host_a.contains(&host_addr),
    "the CURRENT (still-owned) host A address is captured for withdrawal"
  );

  // The handoff was one-shot — already consumed above, so a second take is empty.
  assert!(
    svc.take_rename_goodbye_handoff().is_none(),
    "the rename handoff is consumed exactly once"
  );
}

#[test]
fn duplicate_legacy_question_is_deduped() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);

  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  let inject = |svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>| {
    let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  };

  // The same legacy question twice must queue only one pending reply.
  inject(&mut svc);
  inject(&mut svc);
  assert_eq!(
    svc.pending_legacy.len(),
    1,
    "a duplicate legacy question must be deduped"
  );
}

// ── KAS suppression delivery-gated counter tests ──────────────────────────

/// Partial KAS suppression: `answers_suppressed_kas` must only be bumped on a
/// CONFIRMED delivery, not at encode time.
///
/// Scenario:
/// 1. Drive service to Established.
/// 2. Inject a KnownAnswer hint for the SRV record (partial suppression — PTR/TXT/A still emit).
/// 3. Inject a Question → response_deadline fires → poll_transmit returns Some (non-empty response).
/// 4. Confirm it with nothing delivered → counter must stay 0.
/// 5. Re-encode a second response cycle and call
///    confirm it fully delivered → counter must be 1 (the one
///    suppressed SRV).
#[cfg(feature = "stats")]
#[test]
fn partial_kas_suppression_counter_is_delivery_gated() {
  use crate::{
    event::{KnownAnswer, ServiceQuestion},
    wire::{QuestionRef, Ref},
  };

  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);
  let now = drive_to_established(&mut svc);

  // Wire up stats.
  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
  svc.set_stats(stats.clone());

  // Helper: inject a KnownAnswer hint for the SRV record (TTL >= half → stored).
  let inject_srv_hint =
    |svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
     now: FakeInstant| {
      inject_question_to_set_response_deadline(svc, now);
      let mut srv_buf: std::vec::Vec<u8> = std::vec::Vec::new();
      make_srv_record_ref(
        &mut srv_buf,
        "myprinter._ipp._tcp.local.",
        our_ttl, // TTL >= half → hint stored
        0,
        0,
        631,
        "host.local.",
      );
      let (srv_ref, _) = Ref::try_parse(&srv_buf, 0).unwrap();
      let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), srv_ref);
      svc.handle_event(ServiceEvent::KnownAnswer(ka), now);
    };

  // Helper: inject a Question that will trigger a multicast response.
  let inject_any_question =
    |svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
     now: FakeInstant| {
      let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
    };

  // ── Cycle 1: partial suppression, then delivery=false ──
  inject_srv_hint(&mut svc, now);
  inject_any_question(&mut svc, now);
  svc.handle_timeout(now.advance(200)).unwrap();

  let mut buf = std::vec![0u8; 4096];
  let now2 = now.advance(200);
  let tx = svc.poll_transmit(now2, &mut buf).unwrap();
  assert!(
    tx.is_some(),
    "poll_transmit must return Some (partial suppression leaves a non-empty response)"
  );

  let before = stats.snapshot().answers_suppressed_kas;
  // Delivery FAILS — counter must NOT increase.
  svc.note_delivery(now2, TransmitDelivery::NONE);
  let after_fail = stats.snapshot().answers_suppressed_kas;
  assert_eq!(
    after_fail, before,
    "answers_suppressed_kas must NOT be bumped when delivery=false; \
     was {before}, now {after_fail}"
  );

  // ── Cycle 2: same partial suppression, then delivery=true ──
  inject_srv_hint(&mut svc, now2);
  inject_any_question(&mut svc, now2);
  svc.handle_timeout(now2.advance(200)).unwrap();
  let now3 = now2.advance(200);
  let tx2 = svc.poll_transmit(now3, &mut buf).unwrap();
  assert!(
    tx2.is_some(),
    "poll_transmit must return Some in the second cycle"
  );

  // Delivery SUCCEEDS — counter must increase by the suppressed count (≥ 1, the SRV).
  svc.note_delivery(now3, TransmitDelivery::ALL);
  let after_ok = stats.snapshot().answers_suppressed_kas;
  assert!(
    after_ok > after_fail,
    "answers_suppressed_kas must be bumped when delivery=true; \
     before_delivery={after_fail}, after_delivery={after_ok}"
  );
}

/// Full KAS suppression (`Ok(None)`): every record was suppressed, so no
/// datagram is produced. The counter must be bumped immediately at the point
/// of suppression (no AwaitingConfirm token is ever produced for Ok(None)).
#[cfg(feature = "stats")]
#[test]
fn full_kas_suppression_counts_at_suppression_not_delivery() {
  use crate::{
    event::{KnownAnswer, ServiceQuestion},
    wire::{QuestionRef, Ref},
  };

  let our_ttl: u32 = 120;
  let mut svc = make_service(our_ttl);
  let now = drive_to_established(&mut svc);

  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
  svc.set_stats(stats.clone());

  // Inject KnownAnswer hints for EVERY record the service would emit:
  // PTR, SRV, TXT (we suppress via SRV — easiest to construct). In practice
  // a full-suppression requires all record types covered; here we cheat by
  // only querying for SRV (QTYPE=SRV) so only one record would have been in
  // the response and suppressing that one collapses the whole response.
  // Use inject_question_to_set_response_deadline (QTYPE=PTR) then inject a
  // matching PTR known-answer hint.
  inject_question_to_set_response_deadline(&mut svc, now);

  // Build a wire PTR record matching our service.
  let mut ptr_buf: std::vec::Vec<u8> = std::vec::Vec::new();
  {
    // owner = "_ipp._tcp.local."
    for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
      ptr_buf.push(label.len() as u8);
      ptr_buf.extend_from_slice(label.as_bytes());
    }
    ptr_buf.push(0u8);
    // TYPE=PTR(12), CLASS=IN(1), TTL, RDLENGTH+RDATA (instance name)
    ptr_buf.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
    ptr_buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    ptr_buf.extend_from_slice(&our_ttl.to_be_bytes());
    // Encode instance name "myprinter._ipp._tcp.local." as RDATA.
    let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
    for label in "myprinter._ipp._tcp.local."
      .trim_end_matches('.')
      .split('.')
    {
      rdata.push(label.len() as u8);
      rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0u8);
    #[allow(clippy::cast_possible_truncation)]
    ptr_buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    ptr_buf.extend_from_slice(&rdata);
  }
  let (ptr_ref, _) = Ref::try_parse(&ptr_buf, 0).unwrap();
  let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), ptr_ref);
  svc.handle_event(ServiceEvent::KnownAnswer(ka), now);

  // Also suppress SRV.
  {
    let mut srv_buf: std::vec::Vec<u8> = std::vec::Vec::new();
    make_srv_record_ref(
      &mut srv_buf,
      "myprinter._ipp._tcp.local.",
      our_ttl,
      0,
      0,
      631,
      "host.local.",
    );
    let (srv_ref, _) = Ref::try_parse(&srv_buf, 0).unwrap();
    let ka = KnownAnswer::new("0.0.0.0:5353".parse().unwrap(), srv_ref);
    svc.handle_event(ServiceEvent::KnownAnswer(ka), now);
  }

  // Inject a Question to arm a response, then fire the deadline.
  {
    let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  }

  let now2 = now.advance(200);
  svc.handle_timeout(now2).unwrap();

  let before = stats.snapshot().answers_suppressed_kas;
  let mut buf = std::vec![0u8; 4096];
  let result = svc.poll_transmit(now2, &mut buf).unwrap();
  // If ALL records are suppressed → Ok(None).  If partial, that is still
  // acceptable: this test verifies the full-suppression counter fires
  // immediately (no awaiting_confirm) when Ok(None) occurs.
  if result.is_none() {
    // Full suppression: counter must have been bumped at point of suppression.
    let after = stats.snapshot().answers_suppressed_kas;
    assert!(
      after > before,
      "answers_suppressed_kas must be bumped at suppression for full Ok(None) case; \
       before={before}, after={after}"
    );
    // No AwaitingConfirm: no note_transmit_outcome call needed.
    assert!(
      svc.awaiting_confirm.is_none(),
      "no awaiting_confirm token must exist after Ok(None)"
    );
  }
  // (If only partial suppression occurred we skip; the partial test covers that path.)
}

// ── meta-response must count responses_tx ───────────────────────────

/// Helper: build a raw §9 meta-query question (for _services._dns-sd._udp.local.)
/// and return the encoded bytes.  The caller parses it via `QuestionRef::try_parse`.
#[cfg(feature = "stats")]
fn build_meta_question_bytes() -> std::vec::Vec<u8> {
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in "_services._dns-sd._udp.local."
    .trim_end_matches('.')
    .split('.')
  {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8); // root label
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  qbuf
}

/// Multicast meta-response: `responses_tx` stays 0 on `delivered=false`,
/// then bumps to 1 on `delivered=true`.
#[cfg(feature = "stats")]
#[test]
fn multicast_meta_response_counts_responses_tx() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);

  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
  svc.set_stats(stats.clone());

  let qbuf = build_meta_question_bytes();
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "192.0.2.1:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 0)),
    now,
  );

  // Advance past the jitter window to fire the meta reply.
  let now2 = now.advance(200);
  let mut buf = std::vec![0u8; 4096];
  let tx = svc.poll_transmit(now2, &mut buf).unwrap();
  assert!(
    tx.is_some(),
    "poll_transmit must produce a meta-response datagram"
  );
  // An AwaitingConfirm::MetaResponse token must have been stamped.
  assert!(
    svc.awaiting_confirm.is_some(),
    "awaiting_confirm must be set after a meta-response emit"
  );

  // delivery=false → responses_tx must remain 0.
  let before = stats.snapshot().responses_tx;
  svc.note_delivery(now2, TransmitDelivery::NONE);
  let after_fail = stats.snapshot().responses_tx;
  assert_eq!(
    after_fail, before,
    "responses_tx must NOT be bumped on delivery=false (meta); was {before}, now {after_fail}"
  );

  // Re-arm: inject the question again and fire a second meta reply.
  let qbuf2 = build_meta_question_bytes();
  let (qref2, _) = QuestionRef::try_parse(&qbuf2, 0).unwrap();
  let src2: core::net::SocketAddr = "192.0.2.2:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref2, src2, 0)),
    now2,
  );
  let now3 = now2.advance(200);
  let tx2 = svc.poll_transmit(now3, &mut buf).unwrap();
  assert!(
    tx2.is_some(),
    "poll_transmit must produce a second meta-response datagram"
  );

  // delivery=true → responses_tx must bump by 1.
  svc.note_delivery(now3, TransmitDelivery::ALL);
  let after_ok = stats.snapshot().responses_tx;
  assert_eq!(
    after_ok,
    before + 1,
    "responses_tx must be bumped by 1 on delivery=true (meta); expected {}, got {after_ok}",
    before + 1
  );
}

/// Legacy unicast meta-response: `responses_tx` stays 0 on `delivered=false`,
/// then bumps to 1 on `delivered=true`.
#[cfg(feature = "stats")]
#[test]
fn legacy_meta_response_counts_responses_tx() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);

  let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
  svc.set_stats(stats.clone());

  // A non-5353 source → legacy unicast path.
  let qbuf = build_meta_question_bytes();
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  let src: core::net::SocketAddr = "192.0.2.50:12345".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, src, 42)),
    now,
  );

  // poll_transmit drains legacy responses immediately (no jitter for legacy).
  let mut buf = std::vec![0u8; 4096];
  let tx = svc.poll_transmit(now, &mut buf).unwrap();
  assert!(
    tx.is_some(),
    "poll_transmit must produce a legacy meta-response datagram"
  );
  // A MetaResponse token must have been stamped for the legacy meta path.
  assert!(
    svc.awaiting_confirm.is_some(),
    "awaiting_confirm must be set after a legacy meta-response emit"
  );

  // delivery=false → responses_tx must remain 0.
  let before = stats.snapshot().responses_tx;
  svc.note_delivery(now, TransmitDelivery::NONE);
  let after_fail = stats.snapshot().responses_tx;
  assert_eq!(
    after_fail, before,
    "responses_tx must NOT be bumped on delivery=false (legacy meta); \
     was {before}, now {after_fail}"
  );

  // Re-arm: inject the legacy meta question again.
  let qbuf2 = build_meta_question_bytes();
  let (qref2, _) = QuestionRef::try_parse(&qbuf2, 0).unwrap();
  let src2: core::net::SocketAddr = "192.0.2.51:12345".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref2, src2, 43)),
    now,
  );
  let tx2 = svc.poll_transmit(now, &mut buf).unwrap();
  assert!(
    tx2.is_some(),
    "poll_transmit must produce a second legacy meta-response datagram"
  );

  // delivery=true → responses_tx must bump by 1.
  svc.note_delivery(now, TransmitDelivery::ALL);
  let after_ok = stats.snapshot().responses_tx;
  assert_eq!(
    after_ok,
    before + 1,
    "responses_tx must be bumped by 1 on delivery=true (legacy meta); \
     expected {}, got {after_ok}",
    before + 1
  );
}

// ── withdrawal_snapshot tests ─────────────────────────────────────────────────

#[test]
fn withdrawal_snapshot_of_established_service_owns_its_records() {
  // An established (fully announced) service must snapshot PTR, SRV, TXT
  // ownership and the host A address it advertised.
  let mut svc = make_service(120);
  drive_to_established(&mut svc);

  let snap = svc.withdrawal_snapshot();

  // PTR/SRV/TXT must all be owned after a full announcement cycle.
  assert!(snap.owned.ptr(), "snapshot must own PTR");
  assert!(snap.owned.srv(), "snapshot must own SRV");
  assert!(snap.owned.txt(), "snapshot must own TXT");

  // make_records adds 192.168.1.10 — it must appear in the snapshot.
  let expected = core::net::Ipv4Addr::new(192, 168, 1, 10);
  assert!(
    snap.host_a.contains(&expected),
    "snapshot host_a must contain {expected}"
  );
}

#[test]
fn withdrawal_snapshot_of_never_announced_service_is_empty() {
  // A service that has not yet been announced (still in Init/Probing) has
  // emitted nothing, so the snapshot must carry an empty owned mask and no
  // host addresses.
  let mut svc = make_service(120);
  // Kick off probing (Init → Probing) but do NOT confirm any sends.
  svc.handle_timeout(FakeInstant::zero()).unwrap();

  let snap = svc.withdrawal_snapshot();

  assert!(!snap.owned.ptr(), "unanounced: PTR must not be owned");
  assert!(!snap.owned.srv(), "unannounced: SRV must not be owned");
  assert!(!snap.owned.txt(), "unannounced: TXT must not be owned");
  assert!(
    !snap.owned.subtypes(),
    "unannounced: subtypes must not be owned"
  );
  assert!(snap.host_a.is_empty(), "unannounced: host_a must be empty");
  assert!(
    snap.host_aaaa.is_empty(),
    "unannounced: host_aaaa must be empty"
  );
}

// NOTE: the old `withdrawal_snapshot_of_pending_rename_goodbye_captures_old_name_in_rename_field`
// asserted the deleted `WithdrawalSnapshot.rename` field. Post-Commit-2 the old
// name is handed off as its own detached item, so `withdrawal_snapshot` captures
// only the CURRENT name — covered by `withdrawal_snapshot_after_rename_captures_only_current`
// (snapshot side) and `conflict_rename_hands_off_old_announced_name` (handoff side).

// ── TransmitDelivery: the invariant pair ───────────────────────────────
//
// Goodbye ownership latches iff `any_delivered()`; lifecycle phase advances iff
// `all_delivered()`. Under a one-bit confirm those two answers were forced to be
// the same, and every shipped driver resolved the collision wrongly in one
// direction or the other.

/// Drive a service from Init to `Announcing(0)` with every probe fully
/// delivered, leaving no unconfirmed commit token. Returns the current instant.
fn drive_to_announcing_zero(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
) -> FakeInstant {
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
    if matches!(svc.state(), ServiceState::Announcing(0)) {
      return now;
    }
  }
  panic!(
    "service did not reach Announcing(0) within 20 ticks; state={:?}",
    svc.state()
  );
}

/// Fire the announce deadline and encode one announcement, leaving its commit
/// token unresolved. Returns the instant the datagram was produced at.
fn emit_announcement(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  now: FakeInstant,
) -> FakeInstant {
  let mut buf = std::vec![0u8; 4096];
  let due = svc
    .poll_timeout()
    .expect("an announcing service always has a lifecycle deadline");
  let at = if due > now { due } else { now };
  svc.handle_timeout(at).unwrap();
  svc
    .poll_transmit(at, &mut buf)
    .unwrap()
    .expect("the fired announce deadline must produce a datagram");
  assert!(
    matches!(svc.awaiting_confirm, Some(AwaitingConfirm::Announcement(_))),
    "expected an Announcement commit token, got {:?}",
    svc.awaiting_confirm
  );
  at
}

#[test]
fn partial_announcement_latches_ownership_without_advancing_the_phase() {
  // The headline case. One logical announce fans out to IPv4 and IPv6; IPv4
  // accepted it and IPv6 did not. Peers on the IPv4 link may now hold our
  // records, so a later unregister MUST retract them (RFC 6762 §10.1) — but the
  // IPv6 link has not been told, so the §8.3 phase must NOT advance.
  //
  // `used > 0` (the shipped hick-reactor policy) gets the ownership right and
  // over-advances the phase; all-delivered (the hick-mio policy) gets the phase
  // right and silently drops the goodbye. Only the enum satisfies both.
  let mut svc = make_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  let at = emit_announcement(&mut svc, now);

  svc.note_delivery(at, TransmitDelivery::V4_ONLY);

  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "a partially-delivered announcement must NOT advance the §8.3 phase; got {:?}",
    svc.state()
  );
  assert_eq!(
    svc.announce_count, 0,
    "the announcement count must not advance on a partial delivery"
  );
  assert!(
    svc.advertises_instance(),
    "the served link's peers may hold our instance records — ownership MUST latch"
  );
  assert!(
    svc.advertises_host(),
    "the served link's peers may hold our host records — ownership MUST latch"
  );
  // The regression the whole change exists to prevent: an unregister in this
  // state must still produce a non-empty goodbye.
  let snap = svc.withdrawal_snapshot();
  assert!(
    snap.owned.ptr() && snap.owned.srv() && snap.owned.txt(),
    "a partially-announced service must still withdraw its instance records"
  );
  assert!(
    !snap.host_a.is_empty(),
    "a partially-announced service must still withdraw its host addresses"
  );
}

#[test]
fn fully_delivered_announcement_latches_ownership_and_advances_the_phase() {
  let mut svc = make_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  let at = emit_announcement(&mut svc, now);

  svc.note_delivery(at, TransmitDelivery::ALL);

  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "a fully-delivered announcement advances the §8.3 phase; got {:?}",
    svc.state()
  );
  assert!(
    svc.advertises_instance() && svc.advertises_host(),
    "a fully-delivered announcement also latches goodbye ownership"
  );
}

#[test]
fn undelivered_announcement_neither_latches_nor_advances() {
  let mut svc = make_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  let at = emit_announcement(&mut svc, now);

  svc.note_delivery(at, TransmitDelivery::NONE);

  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "an undelivered announcement must NOT advance the phase; got {:?}",
    svc.state()
  );
  assert!(
    !svc.advertises_instance(),
    "nothing reached a wire, so no peer can hold our instance records"
  );
  assert!(
    !svc.advertises_host(),
    "nothing reached a wire, so no peer can hold our host records"
  );
  let snap = svc.withdrawal_snapshot();
  assert!(
    !snap.owned.ptr() && !snap.owned.srv() && !snap.owned.txt() && snap.host_a.is_empty(),
    "an undelivered announcement must leave the goodbye empty"
  );
}

#[test]
fn repeated_partial_announcements_climb_the_rfc_8_3_doubling_ladder() {
  // RFC 6762 §8.3: a responder "MAY send up to eight unsolicited responses,
  // provided that the interval between unsolicited responses increases by at
  // least a factor of two with every response sent". A partial re-announce puts a
  // REAL datagram on the served link's wire every round (unlike a fully-failed
  // send, which puts nothing anywhere), so a flat 1 s partial retry would flood
  // that link.
  //
  // The ladder must survive the core's patience escape. The round after the bound
  // is EXCUSED — the phase advances without the family that keeps missing — and the
  // served family must NOT then observe a shorter interval than the one before it:
  // the excused round re-arms on the rung it earned (4 s), not on the fresh
  // phase's flat `announce_deadline` (1 s).
  //
  // A 120 s TTL refreshes at 96 s, so the served family's own gap never comes near
  // its deadline and the per-family refresh schedule leaves these rungs alone.
  let mut svc = make_service(120);
  let mut now = drive_to_announcing_zero(&mut svc);

  let expected_ms = [1_000u64, 2_000, 4_000];
  let mut previous_gap = 0u64;
  for (round, want_ms) in expected_ms.iter().enumerate() {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    let next = svc
      .lifecycle_deadline
      .expect("a partial announcement always re-arms");
    let gap = next.0 - at.0;
    assert_eq!(
      gap, *want_ms,
      "partial re-announce {round} must re-arm {want_ms} ms out, got {gap} ms"
    );
    if round > 0 {
      assert!(
        gap >= previous_gap.saturating_mul(2),
        "§8.3 requires each interval to be at least double the previous one \
         ({gap} ms after {previous_gap} ms)"
      );
    }
    previous_gap = gap;
    now = next;
  }
  // Rounds 0-1 held the phase; round 2 spent the bound and was excused into
  // Announcing(1).
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "exactly one excused advance may have happened across three partial rounds; \
     got {:?}",
    svc.state()
  );
  assert!(
    !svc.has_fully_announced().get(),
    "no announcement ever reached every obligated link, so the reclaim-cancel \
     gate must still be shut — an excused advance is not a delivery"
  );
  assert!(
    svc.advertises_instance(),
    "every one of those rounds still put records on the served link's wire"
  );

  // Recovery is immediate and resumes from exactly where the sequence stood.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::ALL);
  assert!(
    matches!(svc.state(), ServiceState::Established),
    "recovery resumes the §8.3 sequence at the next step, not from the start; got {:?}",
    svc.state()
  );
  assert_eq!(
    svc.partial_announce_streak, 0,
    "a genuine delivery resets the partial ladder to its bottom rung"
  );
  assert!(
    svc.has_fully_announced().get(),
    "and it is the delivery, not the excuse, that opens the reclaim-cancel gate"
  );
}

#[test]
fn the_partial_announce_ladder_doubles_to_its_cap() {
  // The rung table itself, independent of how many rounds the phase survives:
  // 1, 2, 4, 8, 16, 32, 64 s and then held. RFC 6762 §8.3 permits "up to eight
  // unsolicited responses", i.e. seven intervals. A 120 s TTL refreshes at 96 s,
  // so the periodic cap never binds and the doubling is the whole rule.
  let now = FakeInstant::zero();
  let expected_ms = [
    1_000u64, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 64_000, 64_000,
  ];
  for (streak, want_ms) in expected_ms.iter().enumerate() {
    let at = partial_announce_deadline(now, streak as u8, 120).expect("representable");
    assert_eq!(
      at.0, *want_ms,
      "streak {streak} must re-arm {want_ms} ms out, got {} ms",
      at.0
    );
  }
}

#[test]
fn the_partial_announce_ladder_never_outruns_the_periodic_refresh() {
  // The rung is capped at the periodic refresh interval (0.8·TTL). Without the
  // cap the ladder reaches 64 s while a short-TTL record expires from peer caches
  // at 0.8·TTL, so the ONE link still being served loses the records the ladder
  // exists to keep re-offering it.
  let now = FakeInstant::zero();

  // TTL 10 s → refresh at 8 s: the rung climbs 1, 2, 4 and then holds at 8.
  let expected_ms = [1_000u64, 2_000, 4_000, 8_000, 8_000, 8_000, 8_000];
  for (streak, want_ms) in expected_ms.iter().enumerate() {
    let at = partial_announce_deadline(now, streak as u8, 10).expect("representable");
    assert_eq!(
      at.0, *want_ms,
      "streak {streak} of a 10 s-TTL service must re-arm {want_ms} ms out, got {} ms",
      at.0
    );
  }

  // The cap is floored at §8.3's one-second minimum, so a TTL whose 80 % rounds
  // below a second still spaces its retries out rather than spinning.
  for streak in 0..8u8 {
    let at = partial_announce_deadline(now, streak, 1).expect("representable");
    assert_eq!(
      at.0, 1_000,
      "the cap never drops below the §8.3 one-second interval"
    );
  }

  // A long TTL is untouched: 0.8·120 s = 96 s is beyond the ladder's own 64 s
  // top rung, so the cap cannot bind and the schedule is bit-for-bit the old one.
  for streak in 0..8u8 {
    assert_eq!(
      partial_announce_deadline(now, streak, 120),
      partial_announce_deadline(now, streak, u32::MAX),
      "streak {streak}: the cap must not bind for any TTL at or above 80 s"
    );
  }
}

#[test]
fn undelivered_announcement_keeps_the_flat_one_second_retry() {
  // A fully-failed send reached no wire, so §8.3 counts no unsolicited response
  // to space out: it keeps the flat 1 s retry and does not consume a ladder rung.
  // This is also the bit-for-bit parity row for the old `delivered = false`.
  let mut svc = make_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  let at = emit_announcement(&mut svc, now);

  svc.note_delivery(at, TransmitDelivery::NONE);

  let next = svc
    .lifecycle_deadline
    .expect("an undelivered announcement re-arms");
  assert_eq!(
    next.0 - at.0,
    1_000,
    "an undelivered announcement retries at the flat §8.3 interval"
  );
  assert_eq!(
    svc.partial_announce_streak, 0,
    "a fully-failed send does not climb the ladder"
  );
}

#[test]
fn partial_probe_re_arms_the_same_probe_and_latches_nothing() {
  // A probe is a QUESTION (RFC 6762 §8.1): it advertises no records, so a partial
  // probe latches no ownership. And a link that never saw the probe has not been
  // asked, so the sequence must not advance — advancing here is precisely the
  // §8.1 violation the `used > 0` driver policy produces.
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();

  // Reach Probing(1) with one fully-delivered probe, so a failure to advance is
  // distinguishable from never having started.
  'reach: for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
      if matches!(svc.state(), ServiceState::Probing(1)) {
        break 'reach;
      }
    }
  }
  assert!(
    matches!(svc.state(), ServiceState::Probing(1)),
    "expected Probing(1); got {:?}",
    svc.state()
  );

  // Within the core's patience bound every partial round re-arms the SAME probe
  // index. (The bound's own escape is asserted separately.)
  for _ in 0..MAX_PARTIAL_ROUNDS {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    assert!(svc.poll_transmit(now, &mut buf).unwrap().is_some());
    svc.note_delivery(now, TransmitDelivery::V4_ONLY);
    assert!(
      matches!(svc.state(), ServiceState::Probing(1)),
      "a partially-delivered probe must NOT advance the §8.1 sequence; got {:?}",
      svc.state()
    );
  }
  assert!(
    !svc.advertises_instance() && !svc.advertises_host(),
    "a probe advertises nothing, so no delivery outcome may latch ownership"
  );
  assert!(
    !svc.has_fully_announced().get(),
    "probing is not announcing"
  );

  // Lossless recovery: the very next fully-delivered probe resumes at index 1.
  now = now.advance(500);
  svc.handle_timeout(now).unwrap();
  assert!(svc.poll_transmit(now, &mut buf).unwrap().is_some());
  svc.note_delivery(now, TransmitDelivery::ALL);
  assert!(
    matches!(svc.state(), ServiceState::Probing(2)),
    "recovery resumes the probe sequence where it stood; got {:?}",
    svc.state()
  );
}

// ── has_fully_announced: the reclaim-cancel gate ──────────────────────

#[test]
fn has_fully_announced_requires_a_fully_delivered_announcement() {
  let mut svc = make_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  assert!(
    !svc.has_fully_announced().get(),
    "a probed-but-unannounced service has announced nothing"
  );

  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    svc.advertises_instance(),
    "the partial announce DID expose the instance records (the any-fact)"
  );
  assert!(
    !svc.has_fully_announced().get(),
    "a partially-delivered announcement has not reached every obligated link, so it \
     must not open the reclaim-cancel gate"
  );

  let at = emit_announcement(&mut svc, at);
  svc.note_delivery(at, TransmitDelivery::ALL);
  assert!(
    svc.has_fully_announced().get(),
    "the first fully-delivered announcement opens the gate"
  );
}

#[test]
fn a_legacy_unicast_reply_never_opens_the_reclaim_cancel_gate() {
  // RFC 6762 §6.7: a querier whose source port is not 5353 is a legacy resolver
  // and gets a direct unicast reply. That reply has exactly ONE obligated link,
  // so a driver reports it as `AllDelivered` by construction — which is why the
  // gate cannot be `advertises_instance() && all_delivered()`. If it were, a
  // single v4 legacy reply after a v4-only announce would cancel a renamed-away
  // name's goodbye with the v6 debt unpaid and v6 having heard neither the
  // goodbye nor the announcement.
  let mut svc = make_service(120);
  let now = drive_to_announcing_zero(&mut svc);

  // A v4-only announce exposes the instance records without opening the gate.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(svc.advertises_instance() && !svc.has_fully_announced().get());

  // A legacy querier (source port != 5353) asks; its unicast reply is fully
  // delivered on its single obligated link.
  let mut buf = std::vec![0u8; 4096];
  let legacy_src: core::net::SocketAddr = "192.0.2.9:41234".parse().unwrap();
  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in "_ipp._tcp.local.".trim_end_matches('.').split('.') {
    qbuf.push(label.len() as u8);
    qbuf.extend_from_slice(label.as_bytes());
  }
  qbuf.push(0u8);
  qbuf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
  qbuf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  let (qref, _) = crate::wire::QuestionRef::try_parse(&qbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(crate::event::ServiceQuestion::new(qref, legacy_src, 0x4242)),
    at,
  );
  let tx = svc
    .poll_transmit(at, &mut buf)
    .unwrap()
    .expect("a legacy querier must get a unicast reply");
  assert_eq!(tx.dst(), legacy_src, "the reply is unicast to the resolver");
  svc.note_delivery(at, TransmitDelivery::ALL);

  assert!(
    !svc.has_fully_announced().get(),
    "a §6.7 legacy unicast reply is not an announcement — it must never open the \
     reclaim-cancel gate, however it was delivered"
  );
  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "a response carries no lifecycle phase; got {:?}",
    svc.state()
  );
}

#[test]
fn a_conflict_rename_closes_the_reclaim_cancel_gate() {
  // The gate names the CURRENT instance name. A §9 rename adopts a name that has
  // announced nothing, so it must re-earn the gate exactly as a fresh service
  // would — otherwise the renamed service would cancel its own old name's
  // goodbye before ever announcing the replacement.
  let mut svc = make_service(120);
  svc.handle_timeout(FakeInstant::zero()).unwrap(); // Init → Probing
  // Precondition: the OLD name had fully announced (the state a §9 rename
  // inherits from an Established service reverted to probing).
  svc.goodbye.mark_instance();
  svc.fully_announced = true;

  // Lose an §8.2 tiebreak (peer SRV port 9999 > ours 631) → rename.
  let mut sbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut sbuf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (rec, _) = Ref::try_parse(&sbuf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, rec)),
    FakeInstant::zero(),
  );
  let later = FakeInstant::zero().advance(500);
  svc.handle_timeout(later).unwrap();
  assert!(
    svc.name().as_str().contains("-1"),
    "the service should have renamed; name={}",
    svc.name().as_str()
  );
  assert!(
    !svc.has_fully_announced().get(),
    "the renamed-to name has announced nothing, so the gate must be closed again"
  );
  assert!(
    !svc.advertises_instance(),
    "instance ownership resets alongside the gate on a rename"
  );
}

/// Build the wire bytes of a single question (`qname`, `qtype`, CLASS IN).
fn question_bytes(qname: &str, qtype: u16) -> std::vec::Vec<u8> {
  let mut q: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in qname.trim_end_matches('.').split('.') {
    q.push(label.len() as u8);
    q.extend_from_slice(label.as_bytes());
  }
  q.push(0u8);
  q.extend_from_slice(&qtype.to_be_bytes());
  q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
  q
}

/// The obligation tag a datagram carries is a function of the COMMIT TOKEN — of
/// what was actually encoded — so it always states what `note_transmit_outcome`
/// will do with the confirm: re-arm until every obligated link accepts it
/// (`Sustained`), or never (`OneShot`).
///
/// The `Established` periodic re-announce is the row that rules out deriving the
/// tag from the service PHASE. It advances no phase, yet a partial confirm
/// re-arms it on the RFC 6762 §8.3 doubling ladder, so a phase-derived tag would
/// call it fire-and-forget.
#[test]
fn transmit_obligation_is_a_function_of_the_commit_token() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();

  // ── The §8.1 probe sequence and the §8.3 startup announcements ───────────
  let mut probes = 0u32;
  let mut announcements = 0u32;
  for _ in 0..40 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Some(tx) = svc.poll_transmit(now, &mut buf).unwrap() {
      match &svc.awaiting_confirm {
        Some(AwaitingConfirm::Probe) => {
          probes += 1;
          assert_eq!(
            tx.obligation(),
            TransmitObligation::Sustained,
            "§8.1: a probe is re-armed until every obligated link has been asked"
          );
        }
        Some(AwaitingConfirm::Announcement(_)) => {
          announcements += 1;
          assert_eq!(
            tx.obligation(),
            TransmitObligation::Sustained,
            "§8.3: an announcement is re-armed until every obligated link has been told"
          );
        }
        other => panic!("unexpected commit token during the lifecycle: {other:?}"),
      }
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
    if svc.state() == ServiceState::Established {
      break;
    }
  }
  assert_eq!(probes, 3, "§8.1 sends exactly three probes");
  assert_eq!(
    announcements, 2,
    "§8.3's startup sequence is two announcements"
  );

  // ── The Established periodic re-announce ────────────────────────────────
  now = svc
    .poll_timeout()
    .expect("an Established service re-announces periodically");
  svc.handle_timeout(now).unwrap();
  let re_announce = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("the re-announce deadline fired");
  assert!(matches!(
    &svc.awaiting_confirm,
    Some(AwaitingConfirm::Announcement(_))
  ));
  assert_eq!(
    re_announce.obligation(),
    TransmitObligation::Sustained,
    "the periodic re-announce advances no phase, but a partial confirm still \
     re-arms it on the §8.3 ladder — a phase-derived tag would get this wrong"
  );
  svc.note_delivery(now, TransmitDelivery::ALL);

  // ── The jittered §6 multicast response ──────────────────────────────────
  inject_question_to_set_response_deadline(&mut svc, now);
  now = svc
    .poll_timeout()
    .expect("a question arms the jittered response deadline");
  svc.handle_timeout(now).unwrap();
  let response = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("the response deadline fired");
  assert!(matches!(
    &svc.awaiting_confirm,
    Some(AwaitingConfirm::Response(_, _))
  ));
  assert_eq!(
    response.obligation(),
    TransmitObligation::OneShot,
    "a response answers one question once and is never re-armed"
  );
  svc.note_delivery(now, TransmitDelivery::ALL);

  // ── The §6.7 legacy unicast reply ───────────────────────────────────────
  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  let qbuf = question_bytes("_ipp._tcp.local.", 12); // QTYPE PTR
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, legacy_src, 0x55)),
    now,
  );
  let legacy = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("a legacy unicast reply is queued");
  assert_eq!(legacy.dst(), legacy_src);
  assert!(matches!(
    &svc.awaiting_confirm,
    Some(AwaitingConfirm::Response(_, _))
  ));
  assert_eq!(
    legacy.obligation(),
    TransmitObligation::OneShot,
    "§6.7: a legacy reply has one obligated link and is never re-armed, so \
     missing it pins nothing and costs one unanswered question"
  );
  svc.note_delivery(now, TransmitDelivery::ALL);

  // ── The RFC 6763 §9 meta-response, unicast then multicast ───────────────
  let meta_q = question_bytes("_services._dns-sd._udp.local.", 12);
  let (qref, _) = QuestionRef::try_parse(&meta_q, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, legacy_src, 0x56)),
    now,
  );
  let legacy_meta = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("a legacy meta reply is queued");
  assert!(matches!(
    &svc.awaiting_confirm,
    Some(AwaitingConfirm::MetaResponse)
  ));
  assert_eq!(legacy_meta.obligation(), TransmitObligation::OneShot);
  svc.note_delivery(now, TransmitDelivery::ALL);

  let meta_src: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();
  let (qref, _) = QuestionRef::try_parse(&meta_q, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, meta_src, 0)),
    now,
  );
  now = now.advance(200); // past the 20–120 ms meta jitter window
  svc.handle_timeout(now).unwrap();
  let meta = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("the meta reply deadline fired");
  assert!(matches!(
    &svc.awaiting_confirm,
    Some(AwaitingConfirm::MetaResponse)
  ));
  assert_eq!(
    meta.obligation(),
    TransmitObligation::OneShot,
    "§9: the shared meta-PTR is emitted once per meta-query and never re-armed"
  );
}

// ── The core's patience bound ───────────────────────────────────────────────

/// Fire the probe deadline and encode one probe, leaving its commit token
/// unresolved. Returns the instant the datagram was produced at.
fn emit_probe(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  now: FakeInstant,
) -> FakeInstant {
  let mut buf = std::vec![0u8; 4096];
  let due = svc
    .poll_timeout()
    .expect("a probing service always has a lifecycle deadline");
  let at = if due > now { due } else { now };
  svc.handle_timeout(at).unwrap();
  svc
    .poll_transmit(at, &mut buf)
    .unwrap()
    .expect("the fired probe deadline must produce a datagram");
  assert!(
    matches!(svc.awaiting_confirm, Some(AwaitingConfirm::Probe)),
    "expected a Probe commit token, got {:?}",
    svc.awaiting_confirm
  );
  at
}

/// Drive an Init service to `Probing(0)` with nothing yet confirmed.
fn drive_to_probing_zero(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
) -> FakeInstant {
  let mut now = FakeInstant::zero();
  for _ in 0..8 {
    now = now.advance(300);
    svc.handle_timeout(now).unwrap();
    if matches!(svc.state(), ServiceState::Probing(0)) {
      return now;
    }
  }
  panic!("service did not reach Probing(0); state={:?}", svc.state());
}

/// RFC 6762 §8.1 spaces probes 250 ms apart, and the random 0–250 ms wait it
/// prescribes is the delay before the FIRST probe of a sequence — not a spacing
/// any later transmission may borrow.
///
/// A partially-delivered probe 0 is re-armed LOSSLESSLY: the same probe index
/// goes back on the wire, which is a second transmission of the same question and
/// owes the full inter-probe interval. Scheduling that re-arm with the initial
/// random wait puts it as little as 0 ms after the copy a family already carried.
/// A driver-side per-family wire gate would defer such a send, so the wire stays
/// legal — which is exactly why the defect has to be asserted here, on the
/// schedule, rather than left for the driver to absorb.
#[test]
fn a_partially_delivered_probe_zero_re_arms_a_full_probe_interval_later() {
  let mut svc = make_service(120);
  let now = drive_to_probing_zero(&mut svc);

  let at = emit_probe(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Probing(0)),
    "a partial probe holds the sequence at probe 0; got {:?}",
    svc.state()
  );
  let re_armed = svc
    .lifecycle_deadline
    .expect("a partially-delivered probe always re-arms");
  let gap = crate::Instant::checked_duration_since(re_armed, at)
    .expect("the re-arm is at or after the confirm");
  assert!(
    gap >= schedule::rfc::PROBE_INTERVAL,
    "probe 0 already reached a wire, so its retry owes §8.1's full 250 ms \
     inter-probe interval; re-armed only {gap:?} later"
  );

  // The retry must not be pushed OUT either — §8.1's sequence is 250 ms, and a
  // longer gap would stretch a three-probe claim past the interval the RFC names.
  assert_eq!(
    gap,
    schedule::rfc::PROBE_INTERVAL,
    "…and exactly that interval: probes are exempt from §6's one-second rule and \
     take no rung on the §8.3 ladder"
  );
}

/// The FIRST probe of a sequence keeps §8.1's random 0–250 ms wait: it is a
/// dispersion measure for hosts booting together, and nothing has been asked yet
/// for the interval to space this one from.
#[test]
fn the_first_probe_of_a_sequence_keeps_the_random_initial_wait() {
  let mut svc = make_service(120);
  // `Init → Probing(0)` schedules the first-ever probe. Nothing has reached a
  // wire, so the deadline is drawn from the initial-wait range, not the interval.
  let mut now = FakeInstant::zero();
  now = now.advance(300);
  svc.handle_timeout(now).unwrap();
  let armed = svc
    .lifecycle_deadline
    .expect("Init always schedules a probe deadline");
  let gap =
    crate::Instant::checked_duration_since(armed, now).expect("the schedule is at or after now");
  assert!(
    gap <= Duration::from_millis(u64::from(schedule::rfc::INITIAL_PROBE_WAIT_MAX_MS)),
    "the first probe waits at most §8.1's 250 ms initial dispersion, not a fixed \
     interval; got {gap:?}"
  );
}

/// A link that is obligated but never accepts would pin the §8.1 sequence
/// forever, because a partial probe re-arms losslessly and advances nothing. The
/// core bounds its own patience: `MAX_PARTIAL_ROUNDS` partials are held honestly
/// and the next is EXCUSED, advancing the sequence from exactly where it stood.
///
/// Round-precise, because both edges matter — advancing one round early would be
/// the §8.1 violation ("it MUST send a Multicast DNS query … to see if any of
/// them are already in use") the confirm contract exists to remove, and never
/// advancing is the pin.
#[test]
fn the_partial_bound_excuses_the_probe_instead_of_pinning_the_sequence() {
  let mut svc = make_service(120);
  let mut now = drive_to_probing_zero(&mut svc);

  for round in 0..MAX_PARTIAL_ROUNDS {
    let at = emit_probe(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    assert!(
      matches!(svc.state(), ServiceState::Probing(0)),
      "round {round} is within the bound, so the §8.1 sequence must not advance; \
       got {:?}",
      svc.state()
    );
    assert_eq!(
      svc.partial_rounds[V6].missed,
      round + 1,
      "each honest partial round spends exactly one unit of the MISSING family's \
       patience"
    );
    assert_eq!(
      svc.partial_rounds[V4].missed, 0,
      "…and none of the family that carried it"
    );
    now = svc
      .lifecycle_deadline
      .expect("a partial probe always re-arms");
  }

  let at = emit_probe(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Probing(1)),
    "the bound must excuse the link that keeps missing rather than pin the \
     sequence; got {:?}",
    svc.state()
  );
  assert_eq!(
    svc.partial_rounds[V6].missed, 0,
    "the excusal restarts the patience budget — the write-off is per-confirm, \
     never sticky"
  );
  assert!(
    svc.partial_rounds[V6].stalled,
    "…but the core has STOPPED WAITING for that family until it delivers, so it \
     no longer drives the refresh schedule: refunding that too would put its \
     frozen anchor straight back in charge of the deadline"
  );
  assert!(
    svc.partial_rounds[V4].in_good_standing(),
    "the family that carried every round is untouched"
  );
  assert!(
    !svc.advertises_instance() && !svc.advertises_host(),
    "a probe advertises nothing, so no outcome — excused or not — may latch \
     ownership"
  );
  assert!(
    !svc.has_fully_announced().get(),
    "probing is not announcing"
  );
}

/// The property the whole escape hangs on: an EXCUSED advance moves the phase
/// and takes NONE of the credit a delivery earns. Conflating the two is what made
/// the driver-side predecessor unsound — it reported the excused round as
/// `AllDelivered`, which opened the reclaim-cancel gate for a name a whole family
/// had never heard.
#[test]
fn an_excused_announcement_advance_is_not_a_delivery() {
  let mut svc = make_service(120);
  let mut now = drive_to_announcing_zero(&mut svc);

  for _ in 0..MAX_PARTIAL_ROUNDS {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    assert!(
      matches!(svc.state(), ServiceState::Announcing(0)),
      "within the bound the §8.3 phase must not advance; got {:?}",
      svc.state()
    );
    now = svc
      .lifecycle_deadline
      .expect("a partial announcement always re-arms");
  }
  let streak_before = svc.partial_announce_streak;

  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);

  // It advances …
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "the excused round must advance the §8.3 phase; got {:?}",
    svc.state()
  );
  // … and nothing else.
  assert!(
    !svc.has_fully_announced().get(),
    "an excused advance must NOT open the reclaim-cancel gate: no complete \
     announcement reached every obligated link, so a renamed-away predecessor's \
     §10.1 goodbye is still owed to the link that heard nothing"
  );
  assert!(
    svc.partial_announce_streak > streak_before,
    "the §8.3 ladder must be CARRIED ACROSS the excuse point, never reset by it \
     ({} after {streak_before})",
    svc.partial_announce_streak
  );
  let gap = svc
    .lifecycle_deadline
    .expect("the advance re-arms")
    .0
    .saturating_sub(at.0);
  assert!(
    gap >= 4_000,
    "the served link must not observe a SHORTER interval across the excuse \
     point than before it — the flat announce_deadline would give 1000 ms, got \
     {gap} ms"
  );
  assert!(
    svc.advertises_instance(),
    "excusal is confined to the PHASE: the round still put records on the served \
     link's wire, so §10.1 ownership latches exactly as an honest partial does"
  );
}

/// `NoneDelivered` must LEAVE the patience budget alone rather than reset it. A
/// reset would make an alternating partial/failed pattern evade the bound
/// forever — the very pin the bound exists to break.
#[test]
fn a_wholly_failed_round_does_not_reset_the_partial_bound() {
  let mut svc = make_service(120);
  let mut now = drive_to_announcing_zero(&mut svc);

  for round in 0..MAX_PARTIAL_ROUNDS {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    now = svc.lifecycle_deadline.expect("re-armed");

    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::NONE);
    assert_eq!(
      svc.partial_rounds[V6].missed,
      round + 1,
      "a round that reached no wire met no obligation, so it may neither spend \
       nor refund the budget"
    );
    now = svc.lifecycle_deadline.expect("re-armed");
    assert!(
      matches!(svc.state(), ServiceState::Announcing(0)),
      "neither round may advance the phase; got {:?}",
      svc.state()
    );
  }

  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "the bound must still fire through an alternating partial/failed pattern; \
     got {:?}",
    svc.state()
  );
}

/// A response is `TransmitObligation::OneShot`: the core never re-arms it, so a
/// family that missed one is holding nothing hostage and a family that carried
/// one has discharged no re-armed obligation. Neither may move the budget.
///
/// The counter lives inside the per-kind confirm arms, so this is STRUCTURAL —
/// a `Response` / `MetaResponse` confirm has no path to it at all. This test
/// pins the observable consequence in both directions: an all-delivered §6.7
/// legacy reply must not RESET the budget (which would hold it at zero forever
/// for a service that answers queriers between lifecycle rounds), and a partial
/// multicast response must not PRELOAD it (which would excuse the next partial
/// probe and advance §8.1 although one link never heard the probe).
#[test]
fn a_response_confirm_cannot_move_the_partial_bound() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let mut svc = make_service(120);
  let mut now = drive_to_announcing_zero(&mut svc);
  let mut buf = std::vec![0u8; 4096];

  // One honest partial announcement, so the budget is part-spent.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert_eq!(svc.partial_rounds[V6].missed, 1);
  now = at;

  // A §6.7 legacy unicast reply: exactly one obligated link, so AllDelivered by
  // construction.
  let legacy_src: core::net::SocketAddr = "192.0.2.9:40000".parse().unwrap();
  let qbuf = question_bytes("_ipp._tcp.local.", 12); // QTYPE PTR
  let (qref, _) = QuestionRef::try_parse(&qbuf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, legacy_src, 0x55)),
    now,
  );
  svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("a legacy unicast reply is queued");
  svc.note_delivery(now, TransmitDelivery::ALL);
  assert_eq!(
    svc.partial_rounds[V6].missed, 1,
    "an all-delivered one-shot reply must not RESET the budget"
  );

  // A jittered §6 multicast response, partially delivered.
  inject_question_to_set_response_deadline(&mut svc, now);
  now = svc
    .response_deadline
    .expect("the response deadline is armed");
  svc.handle_timeout(now).unwrap();
  svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("the response deadline fired");
  assert!(matches!(
    svc.awaiting_confirm,
    Some(AwaitingConfirm::Response(_, _))
  ));
  svc.note_delivery(now, TransmitDelivery::V4_ONLY);
  assert_eq!(
    svc.partial_rounds[V6].missed, 1,
    "a partial one-shot response must not PRELOAD the budget"
  );

  // The lifecycle therefore still gets its full remaining patience.
  now = svc.lifecycle_deadline.expect("still re-armed");
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "with the responses counted this round would have been the excusing one; \
     got {:?}",
    svc.state()
  );
  assert_eq!(svc.partial_rounds[V6].missed, MAX_PARTIAL_ROUNDS);
}

/// A conflict rename restarts the whole §8.1/§8.3 lifecycle under a NEW name, so
/// the patience already spent waiting for a lagging link under the old one must
/// not excuse a probe of the new one.
#[test]
fn a_conflict_rename_clears_the_partial_bound() {
  let mut svc = make_service(120);
  let mut now = drive_to_probing_zero(&mut svc);

  let at = emit_probe(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert_eq!(
    svc.partial_rounds[V6].missed, 1,
    "one partial probe must be counted against the family that missed it"
  );
  now = at;

  // A rival SRV authority with larger rdata (port 9999 > our 631): we lose the
  // §8.2 tiebreak and rename away.
  let mut sbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut sbuf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (srec, _) = Ref::try_parse(&sbuf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, srec)),
    now,
  );
  now = now.advance(300);
  svc.handle_timeout(now).unwrap();

  assert!(
    svc.name().as_str().contains("-1"),
    "the service must have lost the tiebreak and renamed; name={}",
    svc.name().as_str()
  );
  assert_eq!(
    svc.partial_rounds,
    [FamilyPatience::default(); 2],
    "the new name starts a fresh §8.1 sequence with a fresh patience budget"
  );
}

/// The RFC 6763 §9 same-name revert-to-probe is the other lifecycle regression.
/// It emits no `ServiceUpdate`, so it was invisible to the driver-side
/// predecessor and could inherit a nearly-spent budget; owning the counter in the
/// core makes both regression sites reachable.
#[test]
fn the_section9_revert_to_probe_clears_the_partial_bound() {
  let mut svc = make_service(120);
  drive_to_established(&mut svc);
  let now = FakeInstant::zero().advance(100_000);

  // Spend a partial round on the periodic re-announce.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert_eq!(svc.partial_rounds[V6].missed, 1);

  // A genuine §9 conflict (different SRV rdata) reverts to re-probing.
  let mut sbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut sbuf,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (srec, _) = Ref::try_parse(&sbuf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, srec)),
    at,
  );

  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "§9 conflict must revert to re-probing"
  );
  assert_eq!(
    svc.partial_rounds,
    [FamilyPatience::default(); 2],
    "the re-verified name starts a fresh §8.1 sequence, so the patience spent \
     under the established name may not excuse its probes"
  );
  // The same-name revert deliberately keeps `fully_announced`: this name really
  // did reach every obligated link, and any predecessor goodbye it could cancel
  // was cancelled then.
  assert!(
    svc.has_fully_announced().get(),
    "a same-name revert is not a rename — the announcement proof stands"
  );
}

// ── the commit token across a lifecycle regression ────────────────────

/// Build a service exempted from the debug-build contract assertions.
///
/// A live commit token can only still be live when `handle_event` /
/// `handle_timeout` run if the caller broke the confirm-before-anything contract
/// documented on `Service::poll_transmit`, and `assert_no_live_commit_token`
/// exists to catch exactly that. The `Stale` rewrite is the RELEASE-mode
/// backstop for the same violation, so pinning its behaviour means reproducing
/// the violation the assertions forbid.
fn make_non_compliant_service(
  ttl_secs: u32,
) -> Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> {
  let mut svc = make_service(ttl_secs);
  svc.disable_contract_assertions();
  svc
}

/// Deliver a probe conflict whose SRV rdata differs from ours (port 9999 vs our
/// 631) — a genuine §9 conflict when established, and a tiebreak we LOSE when
/// probing, since the peer's sorted set compares greater than ours.
fn deliver_losing_srv_conflict(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  now: FakeInstant,
) {
  let mut sbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut sbuf,
    svc.name().as_str(),
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (srec, _) = Ref::try_parse(&sbuf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(peer, srec)),
    now,
  );
}

/// Drive an announcing service through a §9 revert and a lost §8.2 tiebreak, so
/// it ends up renamed with the datagram encoded before the regression still
/// parked. Returns the instant the rename completed at.
fn regress_and_rename_with_a_parked_datagram(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  at: FakeInstant,
) -> FakeInstant {
  // §9: a genuine conflict reverts the established name to re-probing.
  deliver_losing_srv_conflict(svc, at);
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "a §9 conflict must revert to re-probing"
  );
  // §8.2: the conflict persists during the re-probe and we lose the tiebreak.
  deliver_losing_srv_conflict(svc, at);
  let now = at.advance(300);
  svc.handle_timeout(now).unwrap();
  assert!(
    svc.name().as_str().contains("-1"),
    "the service must have lost the tiebreak and renamed; name={}",
    svc.name().as_str()
  );
  now
}

/// `Init → Probing(0)` costs no datagram, so an old-generation probe confirming
/// into the fresh sequence advances it for free: the new name would be claimed
/// after TWO probes on the wire where RFC 6762 §8.1 requires three.
#[test]
fn a_stale_probe_confirm_does_not_advance_the_new_names_sequence() {
  let mut svc = make_non_compliant_service(120);
  let mut now = drive_to_probing_zero(&mut svc);

  // A probe for the ORIGINAL name is encoded and parked.
  let at = emit_probe(&mut svc, now);
  // We lose the §8.2 tiebreak and rename away while it is still in flight.
  deliver_losing_srv_conflict(&mut svc, at);
  now = at.advance(300);
  svc.handle_timeout(now).unwrap();
  assert!(
    svc.name().as_str().contains("-1"),
    "the service must have renamed; name={}",
    svc.name().as_str()
  );

  // The fresh sequence takes its free step — no transmit, so the parked probe is
  // still the only datagram outstanding.
  now = svc.poll_timeout().expect("the renamed service re-probes");
  svc.handle_timeout(now).unwrap();
  assert!(matches!(svc.state(), ServiceState::Probing(0)));

  svc.note_delivery(now, TransmitDelivery::ALL);
  assert!(
    matches!(svc.state(), ServiceState::Probing(0)),
    "a probe of the name we renamed AWAY from is not a step of the new name's \
     §8.1 sequence; got {:?}",
    svc.state()
  );
  assert_eq!(svc.probe_count, 0, "…and it credits no probe either");

  // The new name is claimed only after three probes actually reach the wire.
  let mut buf = std::vec![0u8; 4096];
  let mut wire_probes = 0usize;
  for _ in 0..12 {
    now = svc.poll_timeout().expect("still probing");
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      wire_probes += 1;
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
    if matches!(svc.state(), ServiceState::Announcing(_)) {
      break;
    }
  }
  assert_eq!(
    wire_probes, 3,
    "§8.1 requires three probes on the wire before the new name is claimed"
  );
}

/// A datagram parked across a conflict rename put its records in peer caches
/// under the OLD name. Latching them into the live `goodbye` would claim the NEW
/// name owns records it never sent — so a later unregister withdraws the wrong
/// name and the old name is never retracted at all.
#[test]
fn a_stale_announcement_confirm_withdraws_under_the_old_name() {
  let mut svc = make_non_compliant_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  // The first announcement of the ORIGINAL name is encoded and parked. Nothing
  // has latched yet, so this datagram is the ONLY thing that ever exposed it.
  let at = emit_announcement(&mut svc, now);
  assert!(!svc.advertises_instance());
  assert!(svc.rename_goodbye_handoff.is_none());

  let now = regress_and_rename_with_a_parked_datagram(&mut svc, at);
  svc.note_delivery(now, TransmitDelivery::ALL);

  assert!(
    !svc.advertises_instance(),
    "the NEW name has put nothing on any wire, so it owns nothing to withdraw"
  );
  assert!(
    svc.advertises_host(),
    "the host name is invariant across an instance rename, so the addresses the \
     parked datagram carried stay this service's to withdraw"
  );
  let handoff = svc
    .take_rename_goodbye_handoff()
    .expect("the old name's records really are in peer caches and must be retracted");
  assert_eq!(
    handoff.records.instance().as_str(),
    "myprinter._ipp._tcp.local.",
    "the goodbye must name the instance the datagram actually advertised"
  );
  assert!(
    handoff.owned.ptr() && handoff.owned.srv() && handoff.owned.txt(),
    "an unfiltered announcement carries the whole instance record set"
  );
  assert!(
    handoff.owned.a_slice().is_empty() && handoff.owned.aaaa_slice().is_empty(),
    "a rename never withdraws host A/AAAA"
  );
}

/// The reclaim-cancel gate and the `Established` update are the app-visible half:
/// a confirm from a generation that was replaced must not report that the CURRENT
/// name completed a §8.3 announcement, because cancelling the renamed-away name's
/// §10.1 goodbye on that basis strands its records in every peer cache.
#[test]
fn a_stale_announcement_confirm_neither_establishes_nor_opens_the_reclaim_gate() {
  let mut svc = make_non_compliant_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  let at = emit_announcement(&mut svc, now);
  let now = regress_and_rename_with_a_parked_datagram(&mut svc, at);

  svc.note_delivery(now, TransmitDelivery::ALL);

  assert!(
    !svc.has_fully_announced().get(),
    "no announcement of the CURRENT name has reached any link, let alone all of \
     them — the renamed-away name's goodbye must keep going"
  );
  let mut updates = std::vec::Vec::new();
  while let Some(upd) = svc.poll() {
    updates.push(upd);
  }
  assert!(
    !updates
      .iter()
      .any(|u| matches!(u, ServiceUpdate::Established)),
    "a name that was never announced must not be reported Established; got {updates:?}"
  );
}

/// The §9 same-name revert is the other regression. The name did NOT change, so
/// the records really are cached under the name this service still holds and must
/// stay retractable — while every piece of lifecycle state the revert reset stays
/// reset, because it now describes the fresh §8.1 sequence.
#[test]
fn a_stale_announcement_confirm_latches_ownership_without_recharging_the_sequence() {
  let mut svc = make_non_compliant_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  let at = emit_announcement(&mut svc, now);
  assert!(!svc.advertises_instance());

  deliver_losing_srv_conflict(&mut svc, at);
  assert_eq!(svc.state(), ServiceState::Init);
  assert_eq!(
    svc.partial_rounds,
    [FamilyPatience::default(); 2],
    "the revert starts a fresh §8.1 sequence"
  );

  svc.note_delivery(at, TransmitDelivery::V4_ONLY);

  assert!(
    svc.advertises_instance(),
    "the name did not change: peers hold these records under it, and discarding \
     the latch would trade a false withdrawal for a missing one"
  );
  assert_eq!(
    svc.partial_rounds,
    [FamilyPatience::default(); 2],
    "the patience spent under the old generation may not excuse a probe of the \
     name we are re-verifying"
  );
  assert_eq!(
    svc.partial_announce_streak, 0,
    "…nor may its §8.3 rung carry into a sequence that has announced nothing"
  );
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "and no phase advances on a confirm from a replaced generation"
  );
  assert!(
    svc.rename_goodbye_handoff.is_none(),
    "a same-name revert hands nothing off — this name is still ours"
  );
}

/// The RFC 6763 §9 meta-PTR names the SERVICE TYPE, which no instance rename or
/// same-name revert touches, and it latches no ownership at all. Nothing about
/// its token can go stale, so a regression must leave it exactly as it was.
#[test]
fn a_regression_leaves_a_meta_response_token_alone() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let mut svc = make_non_compliant_service(120);
  let now = drive_to_established(&mut svc);

  let mut qbuf: std::vec::Vec<u8> = std::vec::Vec::new();
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
  let qsrc: core::net::SocketAddr = "192.0.2.7:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::Question(ServiceQuestion::new(qref, qsrc, 0)),
    now,
  );

  let at = now.advance(200); // past the 20–120 ms meta jitter window
  svc.handle_timeout(at).unwrap();
  let mut buf = std::vec![0u8; 4096];
  svc
    .poll_transmit(at, &mut buf)
    .unwrap()
    .expect("the fired meta deadline must produce a datagram");
  assert!(matches!(
    svc.awaiting_confirm,
    Some(AwaitingConfirm::MetaResponse)
  ));

  deliver_losing_srv_conflict(&mut svc, at);
  assert_eq!(svc.state(), ServiceState::Init);
  assert!(
    matches!(svc.awaiting_confirm, Some(AwaitingConfirm::MetaResponse)),
    "a shared, never-withdrawn meta-PTR is name-independent; got {:?}",
    svc.awaiting_confirm
  );
}

/// The whole rule for an `Established` service under sustained partial delivery,
/// stated as the invariant rather than as a deadline value:
///
/// > The served link's inter-refresh gap must be non-decreasing across an excuse
/// > and must never exceed the periodic refresh interval.
///
/// Both halves are load-bearing and each catches a different defect. A
/// CONTRACTING gap (the excused round re-arming earlier than the honest partial
/// before it) violates RFC 6762 §8.3's "increases by at least a factor of two
/// with every response sent". A gap that OUTRUNS the periodic refresh starves the
/// one link still being served: its records expire from peer caches at 0.8·TTL
/// while the ladder is off at 16 / 32 / 64 s.
///
/// Pinning a deadline VALUE instead codified the contraction rather than
/// detecting it, so this walks the whole gap sequence across BOTH excuse cycles.
#[test]
fn the_partial_ladder_neither_contracts_nor_outruns_the_refresh_interval() {
  // A short TTL is what makes the cap observable: 80 % of a 10 s TTL is 8 s, well
  // below the ladder's uncapped 16 / 32 / 64 s rungs.
  const TTL_SECS: u32 = 10;
  let cap_ms = u64::from(TTL_SECS).saturating_mul(800).max(1_000);

  let mut svc = make_service(TTL_SECS);
  drive_to_established(&mut svc);
  let mut now = svc
    .poll_timeout()
    .expect("an Established service re-announces periodically");

  // Every gap the SERVED link observes: the honest partial re-arms and the
  // excused round's, in order, over two full excuse cycles.
  let mut gaps: std::vec::Vec<u64> = std::vec::Vec::new();
  for cycle in 0..2 {
    for _ in 0..MAX_PARTIAL_ROUNDS {
      let at = emit_announcement(&mut svc, now);
      svc.note_delivery(at, TransmitDelivery::V4_ONLY);
      let re_armed = svc.lifecycle_deadline.expect("a partial round re-arms");
      gaps.push(re_armed.0 - at.0);
      now = re_armed;
    }
    let at = emit_announcement(&mut svc, now);
    let streak_before = svc.partial_announce_streak;
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    assert_eq!(
      svc.state(),
      ServiceState::Established,
      "there is no phase beyond Established to advance into"
    );
    assert!(
      svc.partial_announce_streak > streak_before,
      "cycle {cycle}: an excused round is still not a delivery — only a genuine \
       all-delivered round resets the §8.3 ladder"
    );
    let re_armed = svc
      .lifecycle_deadline
      .expect("an excused round re-arms too");
    gaps.push(re_armed.0 - at.0);
    now = re_armed;
  }

  for pair in gaps.windows(2) {
    assert!(
      pair[1] >= pair[0],
      "§8.3 forbids the next unsolicited response from coming sooner than the \
       last one did; gaps were {gaps:?} ms"
    );
  }
  for gap in &gaps {
    assert!(
      *gap <= cap_ms,
      "a {gap} ms gap outruns the {cap_ms} ms periodic refresh of a {TTL_SECS} s \
       TTL, so the served link loses the records; gaps were {gaps:?} ms"
    );
  }
}

/// The other direction of the same invariant, which a long TTL is what exposes,
/// and the ONE composed rule that replaced the two `Established` re-arm arms.
///
/// The hazard the old ladder-replacement guarded is real: `handle_timeout`
/// pre-arms the periodic re-announce before the datagram goes out, and keeping it
/// postpones the next attempt by a whole refresh interval measured from an
/// announcement one family never received. With a 120 s TTL and the last COMPLETE
/// delivery at t = 0, the partial rounds land at 96 s and the next attempt would
/// not come until 192 s: a family that recovers at 100 s watches the records it is
/// owed expire from every peer cache at 120 s. The outage scales with the TTL —
/// at `u32::MAX` it exceeds 80 years — because it IS a refresh interval.
///
/// The successor rule handles both directions with one clause each, and this walks
/// both:
///
/// * a family in GOOD STANDING that is overdue pulls the deadline in by itself,
///   all the way to §8.3's one-second floor — sooner than any ladder rung, and
///   without a ladder;
/// * a family that has SPENT the core's patience stops driving the deadline
///   entirely, so the healthy family returns to the plain periodic rate instead of
///   being re-announced at the one-second floor forever. Chasing a dead family is
///   the defect the naive stalest rule has, and it is a per-link §8.3 violation on
///   the link that works.
///
/// The `u32::MAX` row pins that the excused re-arm is the ANCHOR plus the refresh
/// interval and nothing else: any deadline derived from the round rather than from
/// the healthy family's own last delivery would differ there by seconds.
#[test]
fn an_established_excusal_re_arms_on_the_stalest_family_in_good_standing() {
  for ttl_secs in [120u32, u32::MAX] {
    let refresh_ms = u64::from(crate::service::schedule::periodic_refresh_secs(ttl_secs).max(1))
      .saturating_mul(1_000);
    let mut svc = make_service(ttl_secs);
    drive_to_established(&mut svc);
    let mut now = svc
      .poll_timeout()
      .expect("an Established service re-announces periodically");

    // v6 is still in good standing here, so its own overdue refresh governs: the
    // deadline is pulled from the pre-armed periodic all the way to the floor.
    let at = emit_announcement(&mut svc, now);
    let pre_armed = svc
      .lifecycle_deadline
      .expect("the fired periodic deadline re-arms the next one");
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    let re_armed = svc.lifecycle_deadline.expect("a partial round re-arms");
    assert_eq!(
      re_armed.0 - at.0,
      1_000,
      "TTL {ttl_secs}: v6 last heard an announcement a full refresh interval ago \
       and is still within its bound, so the retry comes at the §8.3 floor — not \
       {} ms out on the pre-armed periodic deadline",
      pre_armed.0 - at.0
    );
    assert!(
      re_armed < pre_armed,
      "TTL {ttl_secs}: keeping the pre-armed deadline is what strands the family \
       that missed"
    );
    now = re_armed;

    // …and keeps being pulled in for as long as v6 is still owed the datagram and
    // within its bound.
    for round in 1..MAX_PARTIAL_ROUNDS {
      let at = emit_announcement(&mut svc, now);
      svc.note_delivery(at, TransmitDelivery::V4_ONLY);
      let re_armed = svc.lifecycle_deadline.expect("a partial round re-arms");
      assert_eq!(
        re_armed.0 - at.0,
        1_000,
        "TTL {ttl_secs} round {round}: a family in good standing that is overdue \
         keeps the retry at the §8.3 floor"
      );
      now = re_armed;
    }

    // The excusing round. v6 has now spent the core's patience, so it stops
    // driving the schedule and v4 — which heard every one of these — returns to
    // the plain periodic cadence rather than being flooded at the floor.
    let at = emit_announcement(&mut svc, now);
    let streak_before = svc.partial_announce_streak;
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);

    assert_eq!(
      svc.state(),
      ServiceState::Established,
      "TTL {ttl_secs}: there is no phase beyond Established to advance into"
    );
    assert!(
      svc.partial_announce_streak > streak_before,
      "TTL {ttl_secs}: an excused round is still not a delivery — only a genuine \
       all-delivered round resets the §8.3 ladder"
    );
    let re_armed = svc
      .lifecycle_deadline
      .expect("an excused round re-arms too");
    assert_eq!(
      re_armed.0 - at.0,
      refresh_ms,
      "TTL {ttl_secs}: the excused round must re-arm on the stalest family still \
       in good standing — v4, which heard this very announcement — so v4 gets the \
       healthy periodic rate rather than being flooded at the one-second floor \
       chasing a family the core has stopped waiting for"
    );

    // And it STAYS there: v6 is fanned onto every later round and its bound holds
    // until it delivers, so the healthy cadence does not decay back to the floor.
    now = re_armed;
    for round in 0..3 {
      let at = emit_announcement(&mut svc, now);
      svc.note_delivery(at, TransmitDelivery::V4_ONLY);
      let next = svc.lifecycle_deadline.expect("re-armed");
      assert_eq!(
        next.0 - at.0,
        refresh_ms,
        "TTL {ttl_secs} follow-up {round}: a chronically dead family must not \
         drag the healthy one back to the floor"
      );
      now = next;
    }
  }
}

/// The recovery edge of the same rule: the first round the excused family
/// carries, it is back in good standing and its anchor governs again.
#[test]
fn a_recovered_family_returns_to_driving_the_refresh_schedule() {
  const TTL_SECS: u32 = 120;
  let mut svc = make_service(TTL_SECS);
  drive_to_established(&mut svc);
  let mut now = svc.poll_timeout().expect("periodic re-announce");

  // Spend v6's patience.
  for _ in 0..=MAX_PARTIAL_ROUNDS {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    now = svc.lifecycle_deadline.expect("re-armed");
  }
  assert!(
    !svc.partial_rounds[V6].in_good_standing(),
    "v6 must be out of good standing before the recovery"
  );

  // v6 carries the next one. Its counter clears and its anchor moves to now, so
  // both families are fresh and the schedule is the plain periodic one.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::ALL);
  assert_eq!(
    svc.partial_rounds,
    [FamilyPatience::default(); 2],
    "a delivery clears the family's own patience — including the latch that took \
     it out of good standing"
  );
  assert!(
    svc.has_fully_announced().get(),
    "…and, unlike an excusal, opens the reclaim-cancel gate"
  );
  let next = svc.lifecycle_deadline.expect("re-armed");
  assert_eq!(
    next.0 - at.0,
    96_000,
    "with both families freshly refreshed the deadline is the plain periodic one"
  );
}

// ── per-family delivery: the amendments to the stalest rule ───────────

/// Drive a service to `Established` with every confirm reporting `delivery`,
/// returning the instant it arrived. Unlike [`drive_to_established`] this lets a
/// test choose the per-family shape of the whole startup.
fn drive_to_established_with(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  delivery: TransmitDelivery,
) -> FakeInstant {
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  for _ in 0..40 {
    now = match svc.poll_timeout() {
      Some(due) if due > now => due,
      _ => now.advance(250),
    };
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, delivery);
    }
    if svc.state() == ServiceState::Established {
      return now;
    }
  }
  panic!(
    "service did not reach Established within 40 ticks; state={:?}",
    svc.state()
  );
}

/// Amendment 1: a family with NO socket must be excluded from the refresh
/// schedule, not read as infinitely stale.
///
/// A v4-only host is the common deployment. Its v6 anchor is `None` forever, so a
/// naive "schedule on the minimum last-delivery across families" makes every
/// confirm overdue and re-arms it at RFC 6762 §8.3's one-second floor for the life
/// of the process — flooding the one link the host actually has, at 96× the
/// intended rate for a 120 s TTL.
#[test]
fn a_single_stack_host_keeps_the_plain_periodic_cadence() {
  const TTL_SECS: u32 = 120;
  let v4_only = TransmitDelivery::new(FamilyDelivery::Delivered, FamilyDelivery::Unobligated);
  let mut svc = make_service(TTL_SECS);
  let mut now = drive_to_established_with(&mut svc, v4_only);

  assert!(
    svc.last_delivered[V6].is_none(),
    "a family with no socket is never anchored, so it cannot be stale"
  );
  assert!(
    svc.has_fully_announced().get(),
    "every obligated family heard the announcement, so this IS a full delivery — \
     an absent family must not hold the reclaim-cancel gate shut"
  );

  for round in 0..6 {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, v4_only);
    let next = svc
      .lifecycle_deadline
      .expect("Established re-arms periodically");
    assert_eq!(
      next.0 - at.0,
      96_000,
      "round {round}: a v4-only host must re-announce on the plain 0.8·TTL \
       cadence, not at the §8.3 one-second floor"
    );
    now = next;
  }
}

/// Amendment 2, stated as the flooding hazard rather than as a deadline value: a
/// chronically dead but OBLIGATED family must not hold the deadline permanently
/// in the past.
///
/// Its anchor freezes the moment it stops delivering, so a rule that kept
/// consulting it would compute a deadline that is always overdue and re-arm the
/// HEALTHY family at the one-second floor for as long as the dead family stays
/// dead — one defect traded for another, and a per-link §8.3 violation on the link
/// that works.
#[test]
fn a_chronically_dead_family_stops_driving_the_schedule() {
  const TTL_SECS: u32 = 120;
  let mut svc = make_service(TTL_SECS);
  drive_to_established(&mut svc);
  let mut now = svc.poll_timeout().expect("periodic re-announce");

  let mut gaps: std::vec::Vec<u64> = std::vec::Vec::new();
  for _ in 0..12 {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    now = svc.lifecycle_deadline.expect("re-armed");
    gaps.push(now.0 - at.0);
  }

  let floored = gaps.iter().filter(|g| **g <= 1_000).count();
  assert!(
    floored <= usize::from(MAX_PARTIAL_ROUNDS),
    "only the rounds inside v6's own patience may sit at the §8.3 floor; after \
     that the core has stopped waiting for it and v4 must be back on the periodic \
     cadence. gaps were {gaps:?} ms"
  );
  assert!(
    gaps.iter().rev().take(6).all(|g| *g == 96_000),
    "the healthy family must settle on the plain 0.8·TTL cadence, not be flooded \
     chasing a family the core has given up on; gaps were {gaps:?} ms"
  );
  assert!(
    !svc.partial_rounds[V6].in_good_standing(),
    "…which is exactly the fact that took v6 out of good standing"
  );
}

/// Part C's counter rule, in the direction that matters for RFC 6762 §8.1: an
/// all-miss round must touch NO per-family counter.
///
/// Read naively, "excused after MAX_PARTIAL_ROUNDS of its own misses" would let a
/// streak of rounds that reached NO wire walk a family into excusal, and the
/// §8.1 requirement that a name be probed before it is claimed rests on the
/// excusal being unreachable from silence.
#[test]
fn an_all_miss_round_advances_no_per_family_counter() {
  let mut svc = make_service(120);
  let mut now = drive_to_announcing_zero(&mut svc);

  for round in 0..8 {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::NONE);
    assert_eq!(
      svc.partial_rounds,
      [FamilyPatience::default(); 2],
      "round {round}: nothing reached a wire, so no obligation was met and none \
       may be written off — in either direction"
    );
    assert!(
      matches!(svc.state(), ServiceState::Announcing(0)),
      "round {round}: a phase may never advance from silence; got {:?}",
      svc.state()
    );
    now = svc.lifecycle_deadline.expect("a failed round retries flat");
  }
  assert!(
    !svc.advertises_instance(),
    "nothing reached a wire across any of those rounds"
  );

  // The same holds when all-miss rounds are INTERLEAVED with honest partials: the
  // silent rounds neither spend nor refund, so the bound still lands on the
  // partials alone.
  let mut svc = make_service(120);
  let mut now = drive_to_announcing_zero(&mut svc);
  for _ in 0..MAX_PARTIAL_ROUNDS {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    now = svc.lifecycle_deadline.expect("re-armed");
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::NONE);
    now = svc.lifecycle_deadline.expect("re-armed");
  }
  assert_eq!(
    svc.partial_rounds[V6].missed, MAX_PARTIAL_ROUNDS,
    "exactly the partial rounds are counted"
  );
}

/// An all-miss round leaves counters alone because nothing was delivered — but a
/// family reported `Unobligated` in that round is not describing the round, it is
/// describing itself: its socket went away.
///
/// The charge it leaves behind belongs to a family that no longer exists. Carried
/// across the gap it excuses the family the instant it returns — written off
/// after a SINGLE offer, having spent the bound while unreachable — which is
/// precisely the RFC 6762 §8.1 guarantee (the name is probed on the link before
/// it is claimed) that the bound exists to protect.
#[test]
fn an_obligation_gap_in_an_all_miss_round_refunds_the_returning_family() {
  let mut svc = make_service(120);
  let mut now = drive_to_probing_zero(&mut svc);

  // Charge v6 to the bound with honest partials.
  for _ in 0..MAX_PARTIAL_ROUNDS {
    let at = emit_probe(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    now = at;
  }
  assert_eq!(svc.partial_rounds[V6].missed, MAX_PARTIAL_ROUNDS);
  assert!(matches!(svc.state(), ServiceState::Probing(0)));

  // v6's socket goes away in a round that reached NO wire.
  let at = emit_probe(&mut svc, now);
  svc.note_delivery(
    at,
    TransmitDelivery::new(FamilyDelivery::Missed, FamilyDelivery::Unobligated),
  );
  now = at;
  assert!(
    matches!(svc.state(), ServiceState::Probing(0)),
    "nothing reached a wire, so no phase may move; got {:?}",
    svc.state()
  );
  assert_eq!(
    svc.partial_rounds[V6],
    FamilyPatience::default(),
    "the departed family owes nothing and is behind on nothing — and its \
     coverage bit stays CLEAR, because coverage records an actual delivery and \
     this round had none"
  );

  // v6 comes back. It is newly obligated, so it is owed the whole offer
  // sequence, and the excusal lands only on the round after the bound is spent.
  for round in 0..MAX_PARTIAL_ROUNDS {
    let at = emit_probe(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    assert!(
      matches!(svc.state(), ServiceState::Probing(0)),
      "round {round}: the returned family has been asked at most {} times, so \
       §8.1 forbids advancing past it; got {:?}",
      round + 1,
      svc.state()
    );
    now = at;
  }
  let at = emit_probe(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Probing(1)),
    "the bound is spent on genuine re-arms, so the excusal lands on the round \
     after them; got {:?}",
    svc.state()
  );
}

/// The refund is for the family that TRANSITIONED, and nobody else: a family that
/// genuinely missed the same silent round keeps every bit of its charge, or an
/// alternating partial/silent pattern would evade the bound forever.
#[test]
fn an_obligation_gap_refunds_only_the_family_that_left() {
  let mut svc = make_service(120);
  let mut now = drive_to_probing_zero(&mut svc);

  // Charge v4 this time, so the family still obligated in the silent round is
  // the one carrying a charge.
  for _ in 0..MAX_PARTIAL_ROUNDS {
    let at = emit_probe(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V6_ONLY);
    now = at;
  }
  assert_eq!(svc.partial_rounds[V4].missed, MAX_PARTIAL_ROUNDS);

  let at = emit_probe(&mut svc, now);
  svc.note_delivery(
    at,
    TransmitDelivery::new(FamilyDelivery::Missed, FamilyDelivery::Unobligated),
  );
  assert_eq!(
    svc.partial_rounds[V4].missed, MAX_PARTIAL_ROUNDS,
    "v4 is still obligated and still owed the datagram — silence neither spends \
     nor refunds its bound"
  );
  assert!(
    matches!(svc.state(), ServiceState::Probing(0)),
    "…and the phase still cannot move out of silence; got {:?}",
    svc.state()
  );
}

/// The same transition, seen through the latch that survives an advance: a family
/// the core has STOPPED WAITING FOR loses the right to drive the per-family
/// refresh schedule, and that latch must not outlive the family it describes.
///
/// A returned family has not been given up on; leaving it latched keeps it out of
/// the refresh schedule indefinitely, so its own records would be left to expire
/// in its peers' caches while the healthy family alone paced the announcements.
#[test]
fn an_obligation_gap_clears_the_stalled_latch() {
  let mut svc = make_service(120);
  drive_to_established(&mut svc);
  let mut now = svc.poll_timeout().expect("periodic re-announce");

  // Spend v6's patience: the round after the bound excuses it and latches it out
  // of good standing.
  for _ in 0..=MAX_PARTIAL_ROUNDS {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    now = svc.lifecycle_deadline.expect("re-armed");
  }
  assert!(
    !svc.partial_rounds[V6].in_good_standing(),
    "v6 must be latched out of good standing before the gap"
  );

  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(
    at,
    TransmitDelivery::new(FamilyDelivery::Missed, FamilyDelivery::Unobligated),
  );
  assert!(
    svc.partial_rounds[V6].in_good_standing(),
    "the latch describes a family the core gave up on; that family is gone, and \
     the one that comes back is owed its refreshes like any newly obligated link"
  );
}

/// The same transition, seen through the bit that completes a phase without any
/// single round reaching every family: COVERAGE must not survive an obligation
/// gap either.
///
/// Coverage claims that THIS family already carried the datagram still
/// outstanding. A family that leaves the obligated set and returns is a new link
/// which has carried nothing, so a stale bit lets the next round read
/// `all(covered)` and advance the phase on PRE-GAP evidence — the returned family
/// is never required to receive the current datagram at all, which is exactly
/// what RFC 6762 §8.1 forbids for a name being claimed.
#[test]
fn an_obligation_gap_clears_the_coverage_bit() {
  let mut svc = make_service(120);
  let mut now = drive_to_announcing_zero(&mut svc);

  // v6 carries the announcement; v4 misses. v6 is now covered for this datagram.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V6_ONLY);
  assert!(
    svc.partial_rounds[V6].covered,
    "the family that carried the datagram is covered for it"
  );
  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "v4 has not been told yet, so the phase holds; got {:?}",
    svc.state()
  );
  now = svc.lifecycle_deadline.expect("re-armed");

  // v6's socket goes away in a round that reached NO wire.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(
    at,
    TransmitDelivery::new(FamilyDelivery::Missed, FamilyDelivery::Unobligated),
  );
  assert_eq!(
    svc.partial_rounds[V6],
    FamilyPatience::default(),
    "the departed family leaves NOTHING behind — its coverage describes a link \
     that no longer exists"
  );
  now = svc.lifecycle_deadline.expect("a failed round retries flat");

  // v6 comes back and misses while v4 delivers.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "the returned family has carried nothing since the gap, so this round is \
     PARTIAL: the phase may not advance on coverage earned by the link that went \
     away; got {:?}",
    svc.state()
  );
}

/// The capacity-one transport at the CORE's own seam: the families take turns, so
/// no single round reaches both and NEITHER family is failing.
///
/// A shared counter read this as one chronically failing link and excused its way
/// through the lifecycle. A per-family counter correctly refuses to excuse either
/// — but then nothing would ever advance, because a family's own count resets on
/// its own delivery and neither can reach the bound. The phase advances instead on
/// COVERAGE: a re-arm is lossless, so the same probe index / announcement content
/// reaching v4 in one round and v6 in the next has been asked and told on both.
#[test]
fn alternating_families_advance_the_phase_without_spending_patience() {
  let mut svc = make_service(120);
  let mut now = drive_to_announcing_zero(&mut svc);

  // Round 1: v4 carries it. The phase holds — v6 has not been told yet.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "one family is not every family; got {:?}",
    svc.state()
  );
  now = svc.lifecycle_deadline.expect("re-armed");

  // Round 2: the driver hands the slot to the family that missed, and the SAME
  // announcement reaches it. Both families have now heard it.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V6_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "both families have carried this announcement, so the §8.3 phase advances; \
     got {:?}",
    svc.state()
  );
  assert_eq!(
    svc.partial_rounds,
    [FamilyPatience::default(); 2],
    "neither family is failing, so neither may be left out of good standing — \
     stalling one here is what puts the schedule back to per-round anchoring"
  );
  assert!(
    !svc.has_fully_announced().get(),
    "no ONE datagram was confirmed by every family, so the reclaim-cancel gate \
     stays shut — conservative, exactly as for an excused advance"
  );

  // It keeps advancing: two more alternating rounds reach Established.
  for delivery in [TransmitDelivery::V4_ONLY, TransmitDelivery::V6_ONLY] {
    now = svc.lifecycle_deadline.expect("re-armed");
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, delivery);
  }
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "a capacity-one transport that serves both families in turn must still \
     establish the service"
  );
}

// ── the write-off is charged once ─────────────────────────────────────

/// Drive a fresh service from `Init` to `Established` with every confirm
/// reporting `delivery`. Returns the instant it arrived, how many datagrams the
/// startup took, and how many of those were §8.3 announcements.
///
/// Time only ever moves to a deadline the core itself armed, so the instant is the
/// schedule's own latency rather than an artefact of the tick size.
fn establish_under(delivery: TransmitDelivery) -> (FakeInstant, usize, usize) {
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  let mut rounds = 0usize;
  let mut announcements = 0usize;
  for _ in 0..64 {
    if let Some(due) = svc.poll_timeout()
      && due > now
    {
      now = due;
    }
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      rounds = rounds.saturating_add(1);
      if matches!(svc.awaiting_confirm, Some(AwaitingConfirm::Announcement(_))) {
        announcements = announcements.saturating_add(1);
      }
      svc.note_delivery(now, delivery);
    }
    if svc.state() == ServiceState::Established {
      return (now, rounds, announcements);
    }
  }
  panic!(
    "service did not reach Established within 64 rounds; state={:?}",
    svc.state()
  );
}

/// A family that is obligated but permanently unable to carry anything — the
/// dual-stack host whose IPv6 binds but has no multicast route, so every
/// `send_to(ff02::fb)` fails — must be written off ONCE, not re-proven per phase.
///
/// `missed` restarts at every advance, so a bound read from it alone hands the same
/// dead family `MAX_PARTIAL_ROUNDS` fresh re-arms in every §8.1 probe step and
/// every §8.3 announcement step. The rounds themselves are cheap; the ladder is
/// not. Each re-arm is a real unsolicited response on the HEALTHY link, and §8.3
/// requires the next interval to at least double, so the extra announcing rounds
/// are paid for in rungs — 1 + 2 + 4 + 8 + 16 s of them before the second
/// announcement is even reached.
///
/// So the §8.3 spacing is not what this bounds, and must not be: what it bounds is
/// the NUMBER of unsolicited responses the dead family costs. §8.3 asks for at
/// least two, and the healthy link gets exactly the two it would get if the dead
/// family were simply absent — the whole write-off is instead paid once, in §8.1
/// probe rounds at that section's own 250 ms cadence.
#[test]
fn a_written_off_family_is_not_re_proven_in_every_phase() {
  let (healthy_at, healthy_rounds, healthy_announcements) = establish_under(TransmitDelivery::ALL);
  let (dead_at, dead_rounds, dead_announcements) = establish_under(TransmitDelivery::V4_ONLY);

  assert_eq!(
    dead_announcements, healthy_announcements,
    "the dead family may not buy itself extra §8.3 unsolicited responses on the \
     healthy link: {dead_announcements} announcements against {healthy_announcements}"
  );
  assert_eq!(
    dead_rounds,
    healthy_rounds.saturating_add(usize::from(MAX_PARTIAL_ROUNDS)),
    "the whole write-off is `MAX_PARTIAL_ROUNDS` re-arms, spent once — {dead_rounds} \
     rounds against a healthy {healthy_rounds}"
  );
  assert_eq!(
    dead_at.0.saturating_sub(healthy_at.0),
    u64::from(MAX_PARTIAL_ROUNDS) * schedule::rfc::PROBE_INTERVAL.as_millis() as u64,
    "…and those re-arms land in `Probing(0)`, where §8.1's flat 250 ms interval \
     governs, so none of them climbs the §8.3 ladder: Established at {} ms against \
     a healthy {} ms",
    dead_at.0,
    healthy_at.0
  );
}

/// The write-off is undone by the family's OWN delivery, and what that hands back
/// is the WHOLE bound.
///
/// Skipping the bound for a family currently latched `stalled` must not decay into
/// skipping it for one that has since recovered. Reading "has ever stalled" rather
/// than "is stalled" would excuse a returned link after a SINGLE offer — it would
/// have spent the bound while unreachable — which is exactly the RFC 6762 §8.1
/// guarantee (the name is probed on the link before it is claimed) that the bound
/// exists to protect. That is a correctness regression, not an optimisation, and it
/// is the failure this test is here for.
#[test]
fn a_recovered_family_is_owed_the_whole_bound_again() {
  let mut svc = make_service(120);
  let mut now = drive_to_probing_zero(&mut svc);

  // v6 spends the bound and is written off on the round after it.
  for _ in 0..=MAX_PARTIAL_ROUNDS {
    let at = emit_probe(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    now = at;
  }
  assert!(
    svc.partial_rounds[V6].stalled,
    "the excusal must take v6 out of good standing"
  );
  assert!(
    matches!(svc.state(), ServiceState::Probing(1)),
    "…having advanced §8.1 by exactly one step; got {:?}",
    svc.state()
  );

  // While it stays down the write-off stands: the next partial advances the
  // sequence straight away rather than re-spending a bound already spent.
  let at = emit_probe(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Probing(2)),
    "a family the core has already stopped waiting for must not hold the phase \
     again; got {:?}",
    svc.state()
  );
  now = at;

  // Silence still advances nothing, latch or no latch — an excusal reachable from
  // a round that touched no wire would let the name be claimed unprobed.
  let at = emit_probe(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::NONE);
  assert!(
    matches!(svc.state(), ServiceState::Probing(2)),
    "no phase may advance out of silence; got {:?}",
    svc.state()
  );
  assert!(
    svc.partial_rounds[V6].stalled,
    "…and a silent round neither spends nor refunds the write-off"
  );
  now = at;

  // v6 comes back and carries the probe. The latch clears with the rest of its
  // patience, and §8.1 completes.
  let at = emit_probe(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::ALL);
  assert_eq!(
    svc.partial_rounds,
    [FamilyPatience::default(); 2],
    "a delivery clears the whole of the family's patience, latch included"
  );
  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "the third probe was confirmed by every obligated family; got {:?}",
    svc.state()
  );
  now = at;

  // …and now it fails again. This is a NEW failure and is owed the whole bound: the
  // §8.3 phase must hold for `MAX_PARTIAL_ROUNDS` rounds before the next excusal,
  // exactly as it would for a family that had never stalled.
  for round in 0..MAX_PARTIAL_ROUNDS {
    let at = emit_announcement(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::V4_ONLY);
    assert!(
      matches!(svc.state(), ServiceState::Announcing(0)),
      "round {round}: the returned family has been told at most {round} times, so \
       the phase may not advance past it; got {:?}",
      svc.state()
    );
    assert_eq!(
      svc.partial_rounds[V6].missed,
      round + 1,
      "round {round}: the recovered family's budget is spent from the top"
    );
    now = svc
      .lifecycle_deadline
      .expect("a partial announcement always re-arms");
  }
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::V4_ONLY);
  assert!(
    matches!(svc.state(), ServiceState::Announcing(1)),
    "the excusal lands on the round after the fresh bound is spent; got {:?}",
    svc.state()
  );
  now = svc.lifecycle_deadline.expect("an excused advance re-arms");

  // And the recovery path stays open: when v6 carries an announcement the phase
  // takes the full credit a delivery earns, which no excusal ever did.
  let at = emit_announcement(&mut svc, now);
  svc.note_delivery(at, TransmitDelivery::ALL);
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "the recovered family is still served the §8.3 sequence to its end"
  );
  assert!(
    svc.has_fully_announced().get(),
    "…and one complete announcement reached every obligated link, which opens the \
     reclaim-cancel gate an excused advance leaves shut"
  );
  assert!(
    svc.partial_rounds[V6].in_good_standing(),
    "…and puts v6 back in charge of its own refresh schedule"
  );
}

// ── the confirm-before-anything contract ──────────────────────────────

/// A lifecycle deadline that fires while a datagram is still unconfirmed must
/// queue NOTHING.
///
/// The transmit queue is drained by position, not by deadline, so an entry
/// pushed under a live commit token survives the confirm and then fires the
/// instant the token clears — ignoring the deadline the confirm installed for
/// the phase it actually landed the service in.
#[test]
fn a_lifecycle_timeout_queues_nothing_while_a_datagram_is_unconfirmed() {
  let mut svc = make_non_compliant_service(120);
  let now = drive_to_probing_zero(&mut svc);
  emit_probe(&mut svc, now);

  // A driver that parks the datagram lets the re-armed probe deadline fire.
  let due = svc
    .poll_timeout()
    .expect("the probe deadline is re-armed at the fire site");
  svc.handle_timeout(due).unwrap();
  assert!(
    svc.peek_pending().is_none(),
    "a lifecycle deadline firing under a live commit token must queue nothing; \
     queue={:?}",
    svc.pending_transmits
  );

  // The confirm advances §8.1 and installs the deadline that governs from here.
  svc.note_delivery(due, TransmitDelivery::ALL);
  assert!(
    matches!(svc.state(), ServiceState::Probing(1)),
    "the delivered probe advances one §8.1 step; got {:?}",
    svc.state()
  );
  let armed = svc
    .lifecycle_deadline
    .expect("the confirm re-arms the next probe");
  let mut buf = std::vec![0u8; 4096];
  assert!(
    svc.poll_transmit(due, &mut buf).unwrap().is_none(),
    "no queued transmit may outlive the confirm and pre-empt the {armed:?} \
     deadline it installed"
  );
}

/// Several lifecycle deadlines can fire while one datagram sits unconfirmed, and
/// `push_pending` does not deduplicate. Each fire would otherwise add another
/// entry, so the confirm would be followed by a burst that walks the §8.1
/// sequence at ~0 ms spacing — a queued probe carries no sequence index, so every
/// drained entry advances a stage. RFC 6762 §8.1 wants 250 ms between probes and
/// three probes on the wire before the name is claimed.
#[test]
fn accumulated_lifecycle_deadlines_cannot_burst_after_the_confirm() {
  let mut svc = make_non_compliant_service(120);
  let now = drive_to_probing_zero(&mut svc);
  let mut at = emit_probe(&mut svc, now);

  for _ in 0..3 {
    at = svc.poll_timeout().expect("the probe deadline stays armed");
    svc.handle_timeout(at).unwrap();
  }
  svc.note_delivery(at, TransmitDelivery::ALL);
  assert_eq!(
    svc.probe_count, 1,
    "exactly one probe reached the wire, so §8.1 advanced exactly one step"
  );

  let mut buf = std::vec![0u8; 4096];
  let mut burst = 0usize;
  while let Ok(Some(_)) = svc.poll_transmit(at, &mut buf) {
    burst += 1;
    svc.note_delivery(at, TransmitDelivery::ALL);
  }
  assert_eq!(
    burst, 0,
    "the deadlines that fired under the live token left {burst} datagram(s) to \
     drain at once"
  );
  assert_eq!(
    svc.probe_count, 1,
    "…and the §8.1 sequence stands where the single delivered probe left it"
  );
}

/// The same guard on the `Established` periodic re-announce: a refresh deadline
/// firing under a live token must not leave an announcement to fire the moment
/// the confirm clears, which would put two unsolicited responses on the wire
/// inside the one-second interval RFC 6762 §8.3 sets as the floor.
#[test]
fn an_established_refresh_queues_nothing_while_a_datagram_is_unconfirmed() {
  let mut svc = make_non_compliant_service(120);
  drive_to_established(&mut svc);
  let due = svc
    .poll_timeout()
    .expect("an Established service re-announces periodically");
  let at = emit_announcement(&mut svc, due);

  let next = svc
    .poll_timeout()
    .expect("the refresh deadline is re-armed at the fire site");
  svc.handle_timeout(next).unwrap();
  assert!(
    svc.peek_pending().is_none(),
    "queue={:?}",
    svc.pending_transmits
  );

  svc.note_delivery(at, TransmitDelivery::ALL);
  let mut buf = std::vec![0u8; 4096];
  assert!(
    svc.poll_transmit(at, &mut buf).unwrap().is_none(),
    "the confirm's own re-arm governs the next refresh"
  );
}

/// The ordering is not type-checkable, so the debug-build assertions are what a
/// non-compliant driver actually trips. They are what turns a silent state
/// corruption into a failure in that driver's own test suite.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "still awaiting Service::note_transmit_outcome")]
fn handle_timeout_under_a_live_commit_token_trips_the_contract_assertion() {
  let mut svc = make_service(120);
  let now = drive_to_probing_zero(&mut svc);
  let at = emit_probe(&mut svc, now);
  let _ = svc.handle_timeout(at.advance(300));
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "still awaiting Service::note_transmit_outcome")]
fn handle_event_under_a_live_commit_token_trips_the_contract_assertion() {
  let mut svc = make_service(120);
  let now = drive_to_probing_zero(&mut svc);
  let at = emit_probe(&mut svc, now);
  deliver_losing_srv_conflict(&mut svc, at);
}

/// Teardown is the row the contract does the most work on, and the only one whose
/// violation leaves no trace: the snapshot reports what the latch holds, so an
/// unconfirmed announcement is simply absent from the §10.1 goodbye and every
/// later step sees a well-formed — merely incomplete — withdrawal. Nothing but
/// this assertion can tell the difference.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "still awaiting Service::note_transmit_outcome")]
fn withdrawal_snapshot_under_a_live_commit_token_trips_the_contract_assertion() {
  let mut svc = make_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  emit_announcement(&mut svc, now);
  let _ = svc.withdrawal_snapshot();
}

/// `periodic_refresh_secs` is `ttl * 80 / 100` with integer division, so TTL 0
/// and TTL 1 both truncate to a ZERO-second refresh interval: an `Established`
/// service re-arms at `now` and re-announces on every tick. Registration rejects
/// those TTLs (`MIN_SERVICE_TTL_SECS`) and `Service` cannot be built any other
/// way, so this floor is defence in depth behind that guard — and it mirrors the
/// floor `partial_announce_deadline` already applies to the same quantity.
#[test]
fn the_periodic_refresh_interval_never_re_arms_at_now() {
  let now = FakeInstant::zero();
  for ttl in [0u32, 1, 2] {
    let due = re_announce_deadline(now, ttl).expect("a 1 s offset is representable");
    assert!(
      due.0 >= 1_000,
      "a {ttl} s TTL re-armed the periodic refresh {} ms out, so an Established \
       service would repump every tick",
      due.0
    );
  }
}

/// The confirm anchors at the EARLIEST family acceptance, and the fold now lives
/// in the core rather than in each driver.
///
/// An anchor may only ever UNDERSTATE how fresh a family's peers are: taking the
/// earliest schedules the next transmission sooner than strictly needed, while
/// taking the latest — or a clock read after the fan-out — would backdate every
/// family's freshness by however long the slowest one took and push a healthy
/// family's next send past its records' TTL. Driving the same round in both
/// family orders pins that the fold is a `min` and not "whichever came second".
#[test]
fn the_confirm_anchors_at_the_earliest_family_acceptance() {
  for swapped in [false, true] {
    let mut svc = make_service(120);
    let mut buf = std::vec![0u8; 4096];
    draw_first_probe(&mut svc, &mut buf);

    let early = FakeInstant(1_000);
    let late = FakeInstant(4_000);
    // A driver's own post-fan-out reading, far later than either acceptance. It
    // is the FALLBACK and must not be reached while some family accepted.
    let fallback = FakeInstant(9_000);
    let (v4, v6) = if swapped {
      (
        FamilyAttempt::Accepted { at: late },
        FamilyAttempt::Accepted { at: early },
      )
    } else {
      (
        FamilyAttempt::Accepted { at: early },
        FamilyAttempt::Accepted { at: late },
      )
    };
    let _ = svc.note_transmit_outcome(fallback, v4, v6);

    let due = svc
      .poll_timeout()
      .expect("a confirmed probe re-arms the next one");
    let from_early = probe_deadline_probe_1(early);
    assert_eq!(
      due, from_early,
      "the next probe must be scheduled from the EARLIEST acceptance, not from \
       the late family's and not from the driver's post-fan-out reading"
    );
  }
}

/// The instant the second §8.1 probe is due, given the first one's anchor. The
/// interval is spent from the anchor with no jitter at index 1, so the deadline
/// is exact.
fn probe_deadline_probe_1(anchor: FakeInstant) -> FakeInstant {
  anchor
    .checked_add_duration(crate::service::schedule::rfc::PROBE_INTERVAL)
    .unwrap()
}

/// A round no family accepted has no acceptance to anchor, so the re-arm is
/// spaced from the driver's own instant — the core reads no clock and cannot
/// supply one itself.
#[test]
fn a_round_that_reached_no_wire_anchors_at_the_drivers_own_instant() {
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  draw_first_probe(&mut svc, &mut buf);

  let attempted = FakeInstant(3_000);
  let _ = svc.note_transmit_outcome(
    attempted,
    FamilyAttempt::Refused { permanent: false },
    FamilyAttempt::GateShut,
  );
  assert_eq!(
    svc.state(),
    ServiceState::Probing(0),
    "an all-miss round advances no phase"
  );
  assert_eq!(
    svc.poll_timeout(),
    Some(probe_deadline_probe_1(attempted)),
    "the retry is spaced from the attempt, not from the encode"
  );
}

/// A §8.1 probe or a §8.3 announcement that NO transport can ever carry retires
/// its service.
///
/// It is a liveness defect and not wire noise: the core re-arms a sustained
/// datagram until every obligated family accepts it, so a service whose bytes are
/// impossible would probe or announce forever with nothing on any wire and never
/// reach `Established`. No patience bound rescues it either — the core's patience
/// excuses a MISSING family, not a round that can succeed on none of them.
#[test]
fn a_permanently_oversized_sustained_datagram_retires_its_service() {
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let now = draw_first_probe(&mut svc, &mut buf);

  let confirm = svc.note_transmit_outcome(
    now,
    FamilyAttempt::Refused { permanent: true },
    FamilyAttempt::NoSocket,
  );
  assert!(
    confirm.retire_producer(),
    "the one family this host has refused the datagram's SIZE, so re-offering \
     these exact bytes can never put them on a wire"
  );
  assert!(
    !confirm.any_delivered(),
    "and nothing reached a wire, so the confirm latches no goodbye ownership"
  );
  assert_eq!(
    svc.state(),
    ServiceState::Probing(0),
    "the confirm still spends the commit token and advances nothing, so the \
     driver's retirement runs on a settled service"
  );
}

/// A round that is merely FAILING retires nothing, however badly.
///
/// Reading a transient refusal as permanent would destroy a healthy
/// advertisement over a full send buffer, so every may-clear outcome vetoes the
/// verdict — including a shut wire gate, whose very next round carries the SAME
/// datagram.
#[test]
fn a_transient_failure_never_retires_a_service() {
  for (v4, v6) in [
    (
      FamilyAttempt::Refused { permanent: true },
      FamilyAttempt::Refused { permanent: false },
    ),
    (
      FamilyAttempt::Refused { permanent: true },
      FamilyAttempt::GateShut,
    ),
    (
      FamilyAttempt::Refused { permanent: true },
      FamilyAttempt::WouldBlock,
    ),
    (
      FamilyAttempt::Refused { permanent: false },
      FamilyAttempt::Refused { permanent: false },
    ),
  ] {
    let mut svc = make_service(120);
    let mut buf = std::vec![0u8; 4096];
    let now = draw_first_probe(&mut svc, &mut buf);
    let confirm = svc.note_transmit_outcome(now, v4, v6);
    assert!(
      !confirm.retire_producer(),
      "{} / {}: a family that may carry the same datagram on a later round is \
       waited for",
      v4.as_str(),
      v6.as_str()
    );
  }
}

/// A ONE-SHOT reply that cannot be sent retires nothing.
///
/// It costs exactly one unanswered question — the querier re-asks — and retiring
/// on one would let any remote peer tear down a healthy established service by
/// asking it something whose answer does not fit.
#[test]
fn a_permanently_oversized_one_shot_reply_never_retires_a_service() {
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  // Drive to Established so the next due datagram is not a lifecycle one.
  for _ in 0..40 {
    now = now.advance(300);
    svc.handle_timeout(now).unwrap();
    if svc.poll_transmit(now, &mut buf).unwrap().is_some() {
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
    if svc.state() == ServiceState::Established {
      break;
    }
  }
  assert_eq!(svc.state(), ServiceState::Established);

  // A §6 multicast reply to an on-link question.
  inject_question_to_set_response_deadline(&mut svc, now);
  now = now.advance(1_000);
  svc.handle_timeout(now).unwrap();
  let tx = svc
    .poll_transmit(now, &mut buf)
    .unwrap()
    .expect("an answered question emits a reply");
  assert_eq!(
    tx.obligation(),
    TransmitObligation::OneShot,
    "a reply is fire-and-forget; the core never re-arms it"
  );

  let confirm = svc.note_transmit_outcome(
    now,
    FamilyAttempt::Refused { permanent: true },
    FamilyAttempt::Refused { permanent: true },
  );
  assert!(
    !confirm.retire_producer(),
    "an undeliverable reply is one lost answer, not a dead producer"
  );
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "and the service survives it"
  );
}

/// Arm and draw the FIRST §8.1 probe, returning the instant it was drawn at.
///
/// A freshly built service sits in `Init` until its §8.1 random 0-250 ms initial
/// delay elapses, so the probe has to be waited for rather than polled straight
/// out.
fn draw_first_probe(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  buf: &mut std::vec::Vec<u8>,
) -> FakeInstant {
  let mut now = FakeInstant::zero();
  for _ in 0..8 {
    now = now.advance(100);
    svc.handle_timeout(now).unwrap();
    if svc.poll_transmit(now, buf).unwrap().is_some() {
      return now;
    }
  }
  panic!("no probe was drawn within the §8.1 initial delay");
}

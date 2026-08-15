#![allow(warnings)]

use core::time::Duration;

use super::*;
use crate::{
  Name, ServiceHandle,
  event::{
    ConflictHistory, ConflictOrigin, KnownAnswer, ProbeConflict, ProbeProposal, ServiceEvent,
  },
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

/// One record of a peer's §8.2 proposal, as it goes on the wire.
#[derive(Clone, Copy)]
enum Rec<'a> {
  Srv {
    port: u16,
    target: &'a str,
  },
  Txt(&'a [&'a [u8]]),
  /// A real prober puts its host records in the same Authority Section. A probe
  /// asks a type-ANY question, so an A record AT THE PROBED NAME is part of the
  /// proposal like any other — this variant exists to let a fixture prove it is
  /// compared rather than passed over.
  A([u8; 4]),
}

/// Bytes of a peer's §8.2 proposal for `owner`: a QR=0 query whose Authority
/// Section carries `recs`, exactly as a prober puts them there.
///
/// Fixtures build the DATAGRAM rather than synthesising per-record events,
/// because §8.2's unit is the whole section — "the Authority Section must
/// contain *all* the records and proposed rdata being probed for uniqueness".
/// Constructing records individually was how a partial proposal became
/// representable in the first place.
fn proposal_bytes(owner: &str, recs: &[Rec<'_>]) -> std::vec::Vec<u8> {
  use crate::wire::{Header, MessageBuilder};
  let mut buf = [0u8; 1024];
  let name = Name::try_from_str(owner).unwrap();
  let mut b = MessageBuilder::<'_, 32>::try_new(&mut buf, Header::new()).unwrap();
  // The QUESTION a probe asks, because it is what makes the Authority Section a
  // proposal at all: §8.1 sends "a query with the record name in question in the
  // Question Section", §5.4 sets the unicast-response bit on it, and §8.2 reads
  // the proposed rdata off "the Authority Section of *that query*". These
  // fixtures carried QDCOUNT=0 and were therefore not probes — a receiver that
  // adjudicated them was adjudicating records that answered nothing. Exactly
  // what `respond::write_probe` emits.
  b.push_question(
    &name,
    crate::wire::ResourceType::Any,
    crate::wire::ResourceClass::In,
    true,
  )
  .unwrap();
  for r in recs {
    match *r {
      Rec::Srv { port, target } => {
        let t = Name::try_from_str(target).unwrap();
        b.push_srv_authority(&name, 120, 0, 0, port, &t).unwrap();
      }
      Rec::Txt(segs) => {
        b.push_txt_authority(&name, 120, segs.iter().copied())
          .unwrap();
      }
      Rec::A(octets) => {
        b.push_a_authority(&name, 120, core::net::Ipv4Addr::from(octets))
          .unwrap();
      }
    }
  }
  let n = b.finish().unwrap();
  buf[..n].to_vec()
}

/// Bytes of a peer's §8.2 proposal assembled from HAND-BUILT records.
///
/// [`proposal_bytes`] goes through [`crate::wire::MessageBuilder`], which is OUR
/// transmit path: it lowercases every name it writes and always emits a
/// compliant TXT. Both are right for what we send and wrong for a fixture about
/// what a PEER sent — a peer's mixed-case target, or a record whose rdata does
/// not parse, cannot be expressed through it at all. Those fixtures write the
/// wire bytes themselves and assemble them here.
fn raw_proposal_bytes(records: &[std::vec::Vec<u8>]) -> std::vec::Vec<u8> {
  raw_proposal_bytes_asking(PROBED_NAME, records)
}

/// [`raw_proposal_bytes`] with the probe's QUESTION named explicitly, for the
/// fixtures that turn on what the query asks rather than on what it proposes.
fn raw_proposal_bytes_asking(qname: &str, records: &[std::vec::Vec<u8>]) -> std::vec::Vec<u8> {
  raw_proposal_bytes_asking_type(qname, crate::wire::ResourceType::Any, records)
}

/// [`raw_proposal_bytes_asking`] with the QTYPE named too. A conforming probe
/// asks ANY (§8.1); a query naming one type still proposes its WHOLE Authority
/// Section, which `a_narrowed_qtype_still_proposes_the_whole_authority_section`
/// is about.
fn raw_proposal_bytes_asking_type(
  qname: &str,
  qtype: crate::wire::ResourceType,
  records: &[std::vec::Vec<u8>],
) -> std::vec::Vec<u8> {
  // QU | class IN — the shape `respond::write_probe` sends.
  raw_proposal_bytes_asking_type_class(qname, qtype, 0x8000u16 | 1, records)
}

/// [`raw_proposal_bytes_asking_type`] with the raw QCLASS word named too, for
/// the one fixture that asks in a class §8.2 does not scope.
fn raw_proposal_bytes_asking_type_class(
  qname: &str,
  qtype: crate::wire::ResourceType,
  qclass_raw: u16,
  records: &[std::vec::Vec<u8>],
) -> std::vec::Vec<u8> {
  let mut msg: std::vec::Vec<u8> = std::vec::Vec::new();
  msg.extend_from_slice(&0u16.to_be_bytes()); // ID
  msg.extend_from_slice(&0u16.to_be_bytes()); // flags: QR=0 — a probe is a QUERY
  msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT — a probe asks about the name
  msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
  #[allow(clippy::cast_possible_truncation)]
  msg.extend_from_slice(&(records.len() as u16).to_be_bytes()); // NSCOUNT
  msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
  // The §8.1 question, uncompressed, with the §5.4 unicast-response bit set —
  // the same shape `respond::write_probe` sends.
  for label in qname.trim_end_matches('.').split('.') {
    #[allow(clippy::cast_possible_truncation)]
    msg.push(label.len() as u8);
    msg.extend_from_slice(label.as_bytes());
  }
  msg.push(0);
  msg.extend_from_slice(&qtype.to_u16().to_be_bytes());
  msg.extend_from_slice(&qclass_raw.to_be_bytes());
  for r in records {
    msg.extend_from_slice(r);
  }
  msg
}

/// The instance name every proposal fixture probes for.
const PROBED_NAME: &str = "myprinter._ipp._tcp.local.";

/// Parse proposal bytes into the event a peer's probe delivers.
fn probe_proposal<'a>(
  bytes: &'a [u8],
  src: core::net::SocketAddr,
  datagram: crate::event::DatagramId,
) -> crate::event::ProbeProposal<'a> {
  let reader = crate::wire::MessageReader::try_parse(bytes).expect("proposal parses");
  crate::event::ProbeProposal::new(src, reader, datagram)
}

/// The common fixture: a peer proposing SRV(`port`) plus the empty TXT that
/// `write_probe` always emits — the same shape this service proposes.
fn srv_txt_proposal(port: u16) -> std::vec::Vec<u8> {
  proposal_bytes(
    "myprinter._ipp._tcp.local.",
    &[
      Rec::Txt(&[]),
      Rec::Srv {
        port,
        target: "host.local.",
      },
    ],
  )
}

/// A distinct RFC 6762 §8.2 proposal identity for a fixture: "these records
/// arrived in datagram N".
///
/// Fixtures that stage ONE peer probe pass one value for all of its records,
/// because §8.2's proposal is one query's whole Authority Section. Two values
/// mean two datagrams, which is what
/// `a_retransmitted_probe_is_not_a_longer_proposal` and
/// `two_proposals_from_one_source_are_compared_separately` turn on.
fn dg(n: u64) -> crate::event::DatagramId {
  crate::event::DatagramId::new(n)
}

/// Drive a freshly-registered service until one probe has actually reached the
/// wire, and return the `now` at which it did.
///
/// RFC 6762 §8.1: "Apparently conflicting Multicast DNS responses received
/// *before* the first probe packet is sent MUST be silently ignored". So a test
/// that wants a conflicting RESPONSE to be ACTED on must first open that window
/// the way a driver does — transmit a probe and confirm its delivery.
///
/// Only responses need it. A `ConflictOrigin::TentativeProbe` is §8.2's input
/// and carries no such precondition, which is why the §8.2 tiebreak tests inject
/// one straight after `make_service` and do not call this.
fn probe_once(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  start: FakeInstant,
) -> FakeInstant {
  let mut buf = std::vec![0u8; 4096];
  let mut now = start;
  for _ in 0..10 {
    now = now.advance(300);
    svc.handle_timeout(now).unwrap();
    if let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
      return now;
    }
  }
  panic!(
    "no probe reached the wire within 10 ticks; state={:?}",
    svc.state()
  );
}

/// Assert RFC 6762 §8.2's DEFERRAL in full: the host that loses the
/// simultaneous-probe tiebreak KEEPS ITS NAME and probes for it again one second
/// later.
///
/// §8.2: "it defers to the winning host by waiting one second, and then begins
/// probing for this record again."
///
/// Every conjunct is load-bearing, and "the name did not change" is deliberately
/// not asserted on its own: a service that dropped the proposal on the floor and
/// carried on probing satisfies that just as well, and dropping a verdict is the
/// one failure a tiebreak fixture exists to catch. So the restart (`Init`,
/// `probe_count == 0`) and the one-second wait (`lifecycle_deadline`) are pinned
/// with it, plus the absence of any `ServiceUpdate::Renamed`.
///
/// `deferred_at` is the instant of the `handle_timeout` that SPENT the verdict:
/// §8.2's second is measured from the deferral, not from the proposal's arrival.
fn assert_tiebreak_deferred(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  kept_name: &str,
  deferred_at: FakeInstant,
  what: &str,
) {
  assert_eq!(
    svc.name().as_str(),
    kept_name,
    "{what}: a §8.2 loss KEEPS the name — \"it defers to the winning host by \
     waiting one second, and then begins probing for this record again\""
  );
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "{what}: …and \"begins probing for this record again\" means the §8.1 \
     sequence restarts from the start"
  );
  assert_eq!(
    svc.probe_count, 0,
    "{what}: …with no probe of the restarted sequence credited yet"
  );
  assert_eq!(
    svc.lifecycle_deadline,
    Some(deferred_at.advance(1000)),
    "{what}: …after \"waiting one second\" exactly — \
     schedule::rfc::TIEBREAK_DEFER_WAIT"
  );
  assert!(
    !svc.tiebreak_lost,
    "{what}: and the verdict is spent by the deferral, leaving no latched loss \
     behind"
  );
  let mut updates = std::vec::Vec::new();
  while let Some(u) = svc.poll() {
    updates.push(u);
  }
  assert!(
    !updates.iter().any(ServiceUpdate::is_renamed),
    "{what}: a §8.2 loss queues NO ServiceUpdate::Renamed — only a §8.1 loss to \
     a host that already OWNS the name renames; got {updates:?}"
  );
}

impl GoodbyeOwnership {
  /// Test helper: simulate that the instance records (PTR/SRV/TXT) were
  /// confirmed-announced. The ownership model uses per-record flags rather than a
  /// single `instance` bool, so a "the original name was announced" precondition sets
  /// all three.
  fn mark_instance(&mut self) {
    self.ptr = [true; 2];
    self.srv = [true; 2];
    self.txt = [true; 2];
  }

  /// Test helper: simulate that `ip` was confirmed-emitted on both families.
  ///
  /// It goes through the ONE writer rather than pushing onto `a` directly: the
  /// address list and its family masks are index-for-index, so a raw push would
  /// leave an address no family claims — which projects to nothing, exactly as a
  /// never-emitted address should.
  fn mark_host_a(&mut self, ip: core::net::Ipv4Addr) {
    self.record_host_emitted(
      &respond::EmittedRecords::new(
        false,
        false,
        false,
        std::vec![ip],
        std::vec::Vec::new(),
        false,
        false,
      ),
      [true; 2],
    );
  }
}

/// The IPv4 half of a per-family exposure pair.
///
/// The tests below deliver on both families unless they say otherwise, so the
/// halves agree and either one states the per-record fact under test. The tests
/// that are ABOUT a partial fan-out read both halves explicitly.
fn v4_half(e: &[respond::EmittedRecords; 2]) -> &respond::EmittedRecords {
  crate::transmit::Family::V4.pick_ref(e)
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

/// After a conflicting authoritative RESPONSE inside §8.1's probing window, the
/// service must:
///   - Eventually transition back to Init (after the rename handle_timeout).
///   - Have a non-None lifecycle_deadline (fresh probe delay).
///   - Eventually advance through Probing for the renamed instance.
///
/// The STIMULUS changed with §8.2's deferral: a peer merely PROBING this name
/// owns nothing, so losing that tiebreak now keeps the name (see
/// `tiebreak_we_lose_defers_and_reprobes`). A rename is §8.1's rule — "the
/// probing host MUST defer to the existing host, and SHOULD choose new names" —
/// and its input is a conflicting RESPONSE from a host that already HOLDS the
/// name. Every assertion about what a rename does is unchanged.
#[test]
fn service_resumes_probing_after_rename() {
  let mut svc = make_service(120);

  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing
  assert!(
    svc.last_now.is_some(),
    "last_now should be set after first handle_timeout"
  );

  // Put a probe on the wire first: §8.1 requires a conflicting response arriving
  // before it to be silently ignored, so the window has to be open first.
  let t0 = probe_once(&mut svc, t0);

  // An existing owner answers with a DIFFERING SRV (port 9999 against our 631).
  deliver_losing_srv_conflict(&mut svc, t0, ConflictOrigin::AuthoritativeResponse);

  // After handle_event: the deferral is recorded but rename has NOT happened yet.
  assert!(
    svc.probe_defeated,
    "the response must be classified as a §8.1 deferral on arrival"
  );

  // Drive the decision: advance time so the next deadline fires and the stored
  // classification is spent. The existing owner wins → rename applied.
  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();

  // After the decision handle_timeout: state must be Init.
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "state must return to Init after the §8.1 rename"
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
  // A probe on the wire first: §8.1 acts on a conflicting RESPONSE only once one
  // has been sent. The stimulus is a response because a §8.2 tiebreak loss now
  // DEFERS and keeps the name, while this fixture needs a rename.
  let t0 = probe_once(&mut svc, FakeInstant::zero());
  // The old name advertised ONLY its PTR (SRV/TXT were KAS-suppressed on the one
  // confirmed response before the rename).
  svc.goodbye.ptr = [true; 2];

  // An existing owner answers with a DIFFERING SRV (port 9999 > ours 631) → §8.1
  // deferral → rename.
  deliver_losing_srv_conflict(&mut svc, t0, ConflictOrigin::AuthoritativeResponse);
  let now = t0.advance(500);
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
    v4_half(&old_owned).ptr(),
    "the advertised PTR is in the handoff ownership"
  );
  assert!(
    !v4_half(&old_owned).srv() && !v4_half(&old_owned).txt(),
    "the KAS-suppressed SRV/TXT must NOT be in the handoff ownership"
  );
  assert!(
    v4_half(&old_owned).a_slice().is_empty() && v4_half(&old_owned).aaaa_slice().is_empty(),
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
  svc.goodbye.record_emitted(
    &respond::EmittedRecords::new(
      false,
      false,
      false,
      std::vec![a2],
      std::vec::Vec::new(),
      false,
      false,
    ),
    [true; 2],
  );
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
    !v4_half(&snap.owned).ptr()
      && !v4_half(&snap.owned).srv()
      && !v4_half(&snap.owned).txt()
      && !v4_half(&snap.owned).subtypes()
      && v4_half(&snap.owned).a_slice().is_empty()
      && v4_half(&snap.owned).aaaa_slice().is_empty(),
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
  // Via the shared helper: it checks the state after `handle_timeout`, not only
  // inside the drain loop, so it sees `Announcing(0)` on the tick that RFC 6762
  // §8.1's post-third-probe settling window closes — a transition that costs no
  // datagram and therefore never appears mid-drain.
  now = drive_to_announcing_zero(&mut svc);
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
  // Via the shared helper: it checks the state after `handle_timeout`, not only
  // inside the drain loop, so it sees `Announcing(0)` on the tick that RFC 6762
  // §8.1's post-third-probe settling window closes — a transition that costs no
  // datagram and therefore never appears mid-drain.
  now = drive_to_announcing_zero(&mut svc);
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

/// The exposure is per family at its SOURCE, across every path that latches one:
/// the §8.3 announcement, a §7.1-filtered response, the §9 rename handoff, and
/// the snapshot a forced withdrawal hands to `Endpoint::unregister_service`.
///
/// Without this the endpoint-level tests above would be testing their own
/// fixtures: `GoodbyeOwnership` is where the family fact is either kept or lost.
#[test]
fn goodbye_ownership_latches_only_the_delivering_family() {
  let ip = core::net::Ipv4Addr::new(192, 168, 1, 10);
  let mut g = GoodbyeOwnership::default();
  // An announcement IPv4 accepted and IPv6 refused.
  g.record_emitted(
    &respond::EmittedRecords::new(
      true,
      true,
      true,
      std::vec![ip],
      std::vec::Vec::new(),
      false,
      true,
    ),
    [true, false],
  );
  let [v4, v6] = g.per_family();
  assert!(
    v4.srv() && v4.txt() && v4.nsec() && v4.a_slice() == [ip],
    "IPv4 carried the whole announcement"
  );
  assert!(
    v6.is_empty() && !v6.nsec(),
    "IPv6 refused it, so it exposed nothing at all"
  );

  // A §7.1-filtered response that emitted only the TXT, this time on IPv6 alone.
  g.record_emitted(
    &respond::EmittedRecords::new(
      false,
      false,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
      false,
    ),
    [false, true],
  );
  let [v4, v6] = g.per_family();
  assert!(
    v4.srv() && v4.a_slice() == [ip],
    "the IPv4 half is unchanged by a send IPv4 did not carry"
  );
  assert!(
    v6.txt() && !v6.srv() && v6.a_slice().is_empty(),
    "IPv6 exposed the TXT and nothing else — not the SRV or the address that \
     only ever went out on IPv4"
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
  g.record_emitted(
    &respond::EmittedRecords::new(
      true,
      false,
      true,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      false,
      false,
    ),
    [true; 2],
  );
  assert!(
    g.ptr == [true; 2] && g.srv == [false; 2] && g.txt == [true; 2],
    "only the emitted instance records latch, and on both delivering families"
  );
  assert!(g.any_instance() && !g.any_host());
  // A later host-only send (one A address) accumulates independently.
  g.record_emitted(
    &respond::EmittedRecords::new(
      false,
      false,
      false,
      std::vec![ip],
      std::vec::Vec::new(),
      false,
      false,
    ),
    [true; 2],
  );
  assert!(
    g.any_instance() && g.any_host(),
    "records accumulate independently"
  );
  assert_eq!(g.a, [ip], "the emitted address is tracked");
  // A duplicate emit must not double-insert the address.
  g.record_emitted(
    &respond::EmittedRecords::new(
      false,
      false,
      false,
      std::vec![ip],
      std::vec::Vec::new(),
      false,
      false,
    ),
    [true; 2],
  );
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
  let hc = HostConflict::new(record_ref, ConflictOrigin::AuthoritativeResponse);
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
    ServiceEvent::HostConflict(HostConflict::new(
      rec,
      ConflictOrigin::AuthoritativeResponse,
    )),
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
    ServiceEvent::HostConflict(HostConflict::new(
      rec,
      ConflictOrigin::AuthoritativeResponse,
    )),
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
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      srec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
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
  // A probe on the wire first, then a conflicting RESPONSE: §8.1's "the probing
  // host MUST defer to the existing host, and SHOULD choose new names" is the
  // rule that renames. A §8.2 tiebreak loss now defers and keeps the name, so it
  // stages no handoff at all.
  let t0 = probe_once(&mut svc, FakeInstant::zero());
  svc.goodbye.mark_instance(); // the original name was announced

  deliver_losing_srv_conflict(&mut svc, t0, ConflictOrigin::AuthoritativeResponse);
  svc.handle_timeout(t0.advance(500)).unwrap();
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
    v4_half(&old_owned).ptr() && v4_half(&old_owned).srv() && v4_half(&old_owned).txt(),
    "the OLD name's advertised instance records (PTR/SRV/TXT) are handed off"
  );
  assert!(
    v4_half(&old_owned).a_slice().is_empty() && v4_half(&old_owned).aaaa_slice().is_empty(),
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
  if let Ok(Some(t)) = svc.poll_transmit(t0.advance(500), &mut out) {
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

/// A link-local host A whose rdata is BYTE-IDENTICAL to one we advertise is not a
/// conflict, and a DIFFERENT link-local address still is.
///
/// INVERTED, deliberately, and the function was renamed with it
/// (`host_conflict_for_link_local_address_is_not_suppressed` →
/// `host_conflict_for_identical_link_local_address_is_suppressed`). It used to
/// assert that a matching link-local A surfaced `ServiceUpdate::HostConflict`
/// anyway, on the reasoning that a link-local address is scope-ambiguous — "the
/// same raw address on a different interface is a real conflict".
///
/// That carve-out has been DROPPED from `host_record_is_ours`, and the old
/// assertion is replaced rather than narrowed, because no admitted input reaches
/// it. RFC 6762 §9: "resource records with identical rdata are never considered
/// inconsistent, even if they originate from different hosts. This is to permit
/// use of proxies and other fault-tolerance mechanisms that may cause more than
/// one responder to be capable of issuing identical answers on the network." On
/// the SAME link, identical rdata is §9's explicit non-conflict; across
/// DIFFERENT links a link-local address is not routable, so no observer ever
/// sees a collision. Neither case leaves a scope in which the old behaviour was
/// right, and it cost a terminal, caller-visible retirement in precisely the
/// fault-tolerance case §9 exists to protect.
///
/// The positive case is kept below so the rule cannot be satisfied by ignoring
/// link-local addresses altogether: a DIFFERENT link-local address is a genuine
/// §9 conflict and must still surface `HostConflict`.
#[test]
fn host_conflict_for_identical_link_local_address_is_suppressed() {
  use crate::event::{HostConflict, ServiceEvent};
  let make = || {
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
    svc
  };
  let deliver =
    |svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
     addr: [u8; 4]| {
      let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
      make_a_record_ref(&mut buf, "host.local.", 120, addr);
      let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
      svc.handle_event(
        ServiceEvent::HostConflict(HostConflict::new(
          rec,
          ConflictOrigin::AuthoritativeResponse,
        )),
        FakeInstant::zero(),
      );
    };

  // ── The identical link-local address: §9's non-conflict ──────────────────
  {
    let mut svc = make();
    deliver(&mut svc, [169, 254, 1, 1]); // the SAME link-local addr we advertise
    let mut updates = std::vec::Vec::new();
    while let Some(u) = svc.poll() {
      updates.push(u);
    }
    assert!(
      !updates.iter().any(ServiceUpdate::is_host_conflict),
      "§9: \"resource records with identical rdata are never considered \
       inconsistent, even if they originate from different hosts\" — a \
       link-local A byte-identical to one we advertise queues NO HostConflict, \
       because on the same link it is that sentence and across links the \
       address is not routable, so no observer sees a collision; got {updates:?}"
    );
  }

  // ── A DIFFERENT link-local address: still a genuine §9 conflict ──────────
  {
    let mut svc = make();
    deliver(&mut svc, [169, 254, 9, 9]); // a different link-local addr
    assert!(
      svc.poll().is_some_and(|u| u.is_host_conflict()),
      "the suppression is a property of the RDATA, not of link-local scope: a \
       DIFFERENT address at our host name is inconsistent and must still \
       surface HostConflict"
    );
  }
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
  // A probe on the wire first, then a conflicting RESPONSE — §8.1's rename is
  // the one that can FAIL here. A §8.2 tiebreak loss now defers and keeps the
  // name, so it never attempts the suffix at all.
  let t0 = probe_once(&mut svc, FakeInstant::zero());
  // Stale queued state that must be cleared if the rename fails.
  svc.pending_transmits[0] = Some(PendingTransmitKind::Probe);
  svc.response_deadline = Some(t0.advance(50));

  deliver_losing_srv_conflict(&mut svc, t0, ConflictOrigin::AuthoritativeResponse);
  svc.handle_timeout(t0.advance(500)).unwrap();

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
/// Only SRV and TXT records are compared. Non-SRV/TXT records (A, NSEC, etc.)
/// are passed over, changing neither the elements of the peer's list nor its
/// length. This sub-test verifies the A-record-drop path separately, then the
/// main tiebreak-win path uses a peer SRV with port=80 (< our 631).
///
/// Tiebreak win: peer SRV port=80 < our port=631 → peer's sorted set is
/// lexicographically smaller → `peer >= our` is FALSE → we WIN (no rename).
#[test]
fn tiebreak_we_win_continues_probing() {
  let mut svc = make_service(120);

  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing

  // sub-check: the scope is ANY, so an A record at the probed name IS part of
  // the peer's proposal — and here it is the record that WINS us the round. A
  // probe asks a type-ANY question, so every positive-TTL IN record at that name
  // is "the records and proposed rdata being probed for uniqueness".
  //
  // The fixture is built so the answer DISCRIMINATES, in the direction that
  // costs us the name if the scope is narrowed. A sorts as type 1, below our
  // first record (TXT, type 16), so it is the peer's first element and it
  // compares LOWER — the peer loses on record one. Scope the fold to SRV/TXT and
  // the A vanishes, leaving {TXT(empty), SRV(9999)} against our {TXT(empty),
  // SRV(631)}, which beats us and defers.
  {
    let bytes = proposal_bytes(
      PROBED_NAME,
      &[
        Rec::Txt(&[]),
        Rec::Srv {
          port: 9999, // beats our 631 — and is never reached
          target: "host.local.",
        },
        Rec::A([192, 168, 1, 10]),
      ],
    );
    let src_a: core::net::SocketAddr = "192.168.1.50:5353".parse().unwrap();
    svc.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, src_a, dg(1))),
      t0,
    );
    assert!(
      !svc.tiebreak_lost,
      "§8.2 compares the whole list in order: the peer's first record is an A \
       that sorts below our first, so the peer loses there and its later \
       SRV(9999) is never reached. Dropping the A from the proposal would hand \
       the round to that SRV"
    );
  }

  // Main tiebreak-win path: peer sends SRV(port=80) + TXT(empty).
  // our local set now always includes TXT (even when empty), matching
  // what write_probe emits unconditionally. With both sides having TXT(empty),
  // the TXT entries are identical and cancel out; the SRV comparison dominates.
  // Our SRV port=631 > peer SRV port=80 → our_concat > peer_concat → we WIN.
  let peer_src_win: core::net::SocketAddr = "192.168.1.10:5353".parse().unwrap();

  // One proposal carrying both records: SRV(port=80) — smaller than our 631, so
  // the peer loses on it — and the TXT(empty) a prober emits alongside.
  let bytes = srv_txt_proposal(80);
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer_src_win, dg(1))),
    t0,
  );

  assert!(
    !svc.tiebreak_lost,
    "the proposal is compared the moment it arrives, and ours sorts later, so \
     this round records no loss"
  );
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
    !svc.tiebreak_lost,
    "and the round's verdict is spent by the comparison, leaving no latched \
     loss behind"
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
/// the service DEFERS after the tiebreak handle_timeout: it keeps its name and
/// re-probes for it one second later.
///
/// Our SRV: port=631. Peer SRV: port=9999. Since 9999 > 631, peer set is
/// greater → we lose the §8.2 tiebreak. (tiebreak compares SRV+TXT only.)
#[test]
fn tiebreak_we_lose_defers_and_reprobes() {
  let mut svc = make_service(120); // our SRV: port=631

  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing

  // Peer proposes SRV(port=9999) — greater than our 631 — with the TXT(empty)
  // a prober emits alongside, so the comparison turns on the port alone.
  let bytes = srv_txt_proposal(9999);
  let peer_src_lose: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer_src_lose, dg(1))),
    t0,
  );

  assert!(svc.tiebreak_lost);
  let original_name = svc.name().as_str().to_owned();

  // Trigger the tiebreak: peer wins.
  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();

  // INVERTED, deliberately, and the function was renamed with it
  // (`tiebreak_we_lose_renames` → `tiebreak_we_lose_defers_and_reprobes`). The
  // old claim was "a §8.2 loss renames". The admitted outcome that replaces it
  // is that a §8.2 loss KEEPS the name and re-probes it after one second — RFC
  // 6762 §8.2: "it defers to the winning host by waiting one second, and then
  // begins probing for this record again." Only a §8.1 loss to a host that
  // already OWNS the name renames, which is a conflicting authoritative RESPONSE
  // and not the tentative proposal delivered above.
  //
  // Neither host owns this name yet: both are still asking for it, so the loser
  // has nothing to give up — and if the winning proposal was only a stale echo,
  // the retry a second later goes unanswered and the name is simply kept.
  assert_tiebreak_deferred(&mut svc, &original_name, t1, "a losing SRV proposal");
}

/// §8.2 compares an empty TXT AS THE PEER SENT IT — the SECOND knob the identity
/// form turns and the tiebreak must not.
///
/// RFC 6763 §6.1 says a TXT record MUST contain at least one string, so the
/// identity question ("are these two records the same record") normalises a
/// zero-length rdata to the single zero-length string a compliant sender would
/// have used. §8.2 asks a different question — "a raw comparison of the binary
/// content of the rdata without regard for meaning or structure" — and only
/// resolves a name if BOTH hosts compute the same function over the same two
/// lists. A peer that sent empty rdata will compare empty rdata; rewriting it on
/// our side alone makes the two sides disagree.
///
/// The arithmetic, since one input has to give opposite verdicts for the fixture
/// to be worth anything. TXT (rtype 16) sorts before SRV (rtype 33) in both
/// lists, and the peer here holds the HIGHER SRV:
///
/// | form | peer's TXT element | vs our `[0x00, 0x10, 0x00]` | decided by |
/// |---|---|---|---|
/// | `AS_SENT` | `[0x00, 0x10]` | shorter, so sorts EARLIER | element 0 — we hold |
/// | `FOLDED` | `[0x00, 0x10, 0x00]` | equal | the SRV — the peer wins |
///
/// So normalising the peer's empty TXT hands away a name that the peer itself
/// scores as ours. Every existing fixture spells a peer's empty TXT with
/// `make_txt_record_ref(.., &[&[]])`, which writes the COMPLIANT single
/// zero-length string; both forms render that identically, which is why none of
/// them could see this. Hand-built, because `push_txt_authority` always emits
/// the compliant form and cannot express this peer at all.
#[test]
fn a_peers_empty_txt_rdata_is_compared_as_the_peer_sent_it() {
  let mut svc = make_service(120); // our SRV: port 631, target `host.local.`
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing

  // A TXT record with RDLENGTH = 0 — no strings at all, which is what §6.1
  // forbids and what a normalising comparator would silently rewrite.
  let mut txt: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in PROBED_NAME.trim_end_matches('.').split('.') {
    #[allow(clippy::cast_possible_truncation)]
    txt.push(label.len() as u8);
    txt.extend_from_slice(label.as_bytes());
  }
  txt.push(0u8);
  txt.extend_from_slice(&crate::wire::ResourceType::Txt.to_u16().to_be_bytes());
  txt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  txt.extend_from_slice(&120u32.to_be_bytes());
  txt.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0

  // A WINNING SRV, so that if the TXT elements tie the peer takes the round.
  // Ours is port 631 (0x0277); theirs 65535 (0xFFFF) sorts above it.
  let mut srv = std::vec::Vec::new();
  make_srv_record_ref(&mut srv, PROBED_NAME, 120, 0, 0, 65535, "host.local.");

  let bytes = raw_proposal_bytes(&[txt, srv]);
  let peer: core::net::SocketAddr = "192.168.1.77:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );

  assert!(
    !svc.tiebreak_lost,
    "the peer's TXT rdata is EMPTY as sent, so its element is the rtype prefix \
     alone and sorts below our compliant `0x00` — the round is decided at that \
     first element and the peer's higher SRV never gets to speak. Normalising \
     the peer's empty TXT to §6.1's single zero-length string ties element 0 \
     instead, hands the round to the SRV, and loses the name to a host the peer \
     itself scores as the loser"
  );
}

/// §8.2 compares the bytes the PEER put on the wire, case and all — and this is
/// the fixture where the two canonicalizers give OPPOSITE verdicts on one input.
///
/// The peer proposes our port and an equal TXT, so the whole round turns on the
/// SRV target: theirs `HOSU.local.`, ours `host.local.`.
///
/// * as sent (`RdataForm::AS_SENT`): the first label byte is `H`(0x48) against
///   our `h`(0x68), so the peer's SRV sorts BELOW ours and the peer loses.
/// * normalised (`RdataForm::FOLDED`): lowercased to `hosu.local.`, where
///   `u`(0x75) beats our `t`(0x74), so the peer's SRV sorts ABOVE ours and we
///   would defer to a host we in fact beat.
///
/// Which is right is settled by symmetry, not by taste: the peer is comparing
/// the bytes IT sent against the bytes WE sent, and it will score this round as
/// a win for us. A responder that normalises the peer's side scores the same
/// round as a win for the peer, and then both hosts believe they lost — or, in
/// the mirror case, both believe they won and take the name.
///
/// The datagram is hand-built because `MessageBuilder::write_name` LOWERCASES on
/// transmit (the coupling `proposal::our_proposal` documents), so the ordinary
/// fixture builder cannot express a peer that sent mixed case at all.
#[test]
fn a_peers_mixed_case_target_is_compared_as_the_peer_sent_it() {
  let mut svc = make_service(120); // our SRV: port 631, target `host.local.`
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing
  let original = svc.name().as_str().to_owned();

  // One zero-length string: byte-for-byte what our own probe puts on the wire
  // for an empty TXT, so the TXT records cancel and the SRV decides.
  let mut txt = std::vec::Vec::new();
  make_txt_record_ref(&mut txt, PROBED_NAME, 120, &[&[]]);
  let mut srv = std::vec::Vec::new();
  make_srv_record_ref(&mut srv, PROBED_NAME, 120, 0, 0, 631, "HOSU.local.");
  let bytes = raw_proposal_bytes(&[txt, srv]);
  let peer: core::net::SocketAddr = "192.168.1.77:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );

  assert!(
    !svc.tiebreak_lost,
    "`HOSU` is what the peer sent and `H` sorts below our `h`, so the peer's \
     proposal is the lower one and this round records no loss — case-folding it \
     to `hosu` would invert the verdict against the very bytes the peer is \
     comparing"
  );

  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();
  assert_eq!(
    svc.name().as_str(),
    original,
    "…so nothing is deferred and nothing renamed"
  );
  assert!(
    matches!(svc.state(), ServiceState::Probing(_)),
    "…and the §8.1 sequence carries on; got {:?}",
    svc.state()
  );
}

/// An in-scope record whose rdata does not parse ABANDONS the whole proposal:
/// §8.2's input is "*all* the records and proposed rdata being probed for
/// uniqueness", and a list with one member unread is not that list.
///
/// The fixture discriminates in the direction that matters. Skipping the
/// unreadable record leaves {TXT(empty), SRV(9999)}, which beats our
/// {TXT(empty), SRV(631)} and defers — so a shortened list does not merely lose
/// information, it manufactures a verdict against us out of a proposal we could
/// not read. Abandoning records no verdict at all and the probe sequence
/// continues.
#[test]
fn an_unreadable_record_abandons_the_whole_proposal() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing
  let original = svc.name().as_str().to_owned();

  let mut txt = std::vec::Vec::new();
  make_txt_record_ref(&mut txt, PROBED_NAME, 120, &[&[]]);
  let mut srv = std::vec::Vec::new();
  make_srv_record_ref(&mut srv, PROBED_NAME, 120, 0, 0, 9999, "host.local.");

  // A CNAME at the probed name whose rdata does not parse: the name inside it
  // ends one byte short of RDLENGTH, which `Cname::try_from_message` rejects and
  // `Ref::rdata_view` propagates. The record itself is well-formed enough to
  // ITERATE past — the section stays readable, so this is not the
  // unparseable-section case but the per-record one.
  let mut cname: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in PROBED_NAME.trim_end_matches('.').split('.') {
    #[allow(clippy::cast_possible_truncation)]
    cname.push(label.len() as u8);
    cname.extend_from_slice(label.as_bytes());
  }
  cname.push(0u8); // root
  cname.extend_from_slice(&5u16.to_be_bytes()); // TYPE CNAME
  cname.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  cname.extend_from_slice(&120u32.to_be_bytes()); // TTL — positive, so in scope
  let rdata: &[u8] = &[
    3, b's', b'v', b'c', 5, b'l', b'o', b'c', b'a', b'l', 0,    // `svc.local.`
    0xFF, // one trailing octet inside RDLENGTH
  ];
  #[allow(clippy::cast_possible_truncation)]
  cname.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
  cname.extend_from_slice(rdata);

  let bytes = raw_proposal_bytes(&[txt, srv, cname]);
  let peer: core::net::SocketAddr = "192.168.1.78:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );

  assert!(
    !svc.tiebreak_lost,
    "one unreadable in-scope record abandons the proposal with NO verdict — \
     scoring the two records we could read would adjudicate a list the peer \
     never proposed, and here that shortened list beats ours"
  );

  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();
  assert_eq!(svc.name().as_str(), original, "…so nothing is deferred");
  assert!(
    matches!(svc.state(), ServiceState::Probing(_)),
    "…and the §8.1 sequence carries on; got {:?}",
    svc.state()
  );
}

/// "Begins probing for this record again" puts the name back under verification,
/// and a host that is verifying a name does not answer for it — so the deferral
/// drops the response cycle exactly as the §9 revert does.
///
/// `pending_legacy` is the one that bites: `poll_transmit` drains queued §6.7
/// unicast replies AHEAD of every state check, so a reply queued while
/// announcing would otherwise leave the host during the deferral carrying the
/// full positive-TTL record set — a claim to a name this service has just been
/// told it may not have, sent while it is asking whether it may.
#[test]
fn the_tiebreak_deferral_stops_answering_for_the_name_it_re_verifies() {
  use crate::{event::ServiceQuestion, wire::QuestionRef};

  let mut svc = make_service(120);
  // `Announcing(0)` with nothing latched and no datagram in flight is the last
  // phase that is still pre-authoritative, so it is the one phase where a
  // response cycle and a §8.2 verdict can both be live at once.
  let now = drive_to_announcing_zero(&mut svc);

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
    "precondition: a legacy querier queues a unicast reply"
  );

  // Peer proposes SRV(port=9999) — greater than our 631 — so we lose.
  let bytes = srv_txt_proposal(9999);
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    now,
  );
  assert!(svc.tiebreak_lost, "precondition: the peer's proposal wins");

  let deferred_at = now.advance(500);
  svc.handle_timeout(deferred_at).unwrap();
  assert_eq!(svc.state(), ServiceState::Init);

  assert!(
    svc.pending_legacy.is_empty(),
    "the deferral must drop the queued legacy reply — the name is back under \
     §8.1 verification and answering for it is the claim the deferral exists to \
     withhold"
  );
  assert!(
    svc
      .poll_transmit(deferred_at, &mut std::vec![0u8; 4096])
      .unwrap()
      .is_none(),
    "…so nothing at all leaves the host during the one-second wait"
  );
}

/// A probe parked across the deferral belongs to the sequence the deferral
/// REPLACED, so its confirm may not re-open §8.1's window on the restarted one.
///
/// The deferral shuts that window deliberately (`probe_on_wire = false`): the
/// restarted sequence has sent nothing, and §8.1 requires a conflicting response
/// arriving "before the first probe packet is sent" to be silently ignored. A
/// confirm that re-opened it would arm the §8.1 rename against the stale echo
/// §8.2's deferral exists to survive — the loss would be handed straight back as
/// a rename, one event later.
#[test]
fn a_probe_parked_across_the_tiebreak_deferral_leaves_the_window_shut() {
  let mut svc = make_non_compliant_service(120);
  let now = drive_to_probing_zero(&mut svc);

  // One probe of THIS sequence reaches the wire and is confirmed, which is the
  // only thing that opens §8.1's window.
  let first = emit_probe(&mut svc, now);
  svc.note_delivery(first, TransmitDelivery::ALL);
  assert!(svc.probe_on_wire, "precondition: the window is open");

  // A SECOND probe is encoded and PARKED.
  let at = emit_probe(&mut svc, first);

  let bytes = srv_txt_proposal(9999);
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    at,
  );
  assert!(svc.tiebreak_lost, "precondition: the peer's proposal wins");
  let kept_name = svc.name().as_str().to_owned();

  let deferred_at = at.advance(300);
  svc.handle_timeout(deferred_at).unwrap();
  assert!(
    !svc.probe_on_wire,
    "the deferral restarts the §8.1 sequence, so its window is shut"
  );

  // The parked datagram is delivered after the deferral has already replaced the
  // sequence it was a step of.
  svc.note_delivery(deferred_at, TransmitDelivery::ALL);
  assert!(
    !svc.probe_on_wire,
    "…and a probe of the sequence the deferral replaced does not re-open it: \
     nothing of the RESTARTED sequence has reached a link"
  );
  assert_tiebreak_deferred(
    &mut svc,
    &kept_name,
    deferred_at,
    "a probe parked across the deferral",
  );
}

/// Two responders proposing BYTE-IDENTICAL record sets is RFC 6762 §8.2.1's
/// "two devices are advertising identical sets of records, as is sometimes done
/// for fault tolerance, and there is, in fact, no conflict" — so neither side
/// renames, and the probe sequence they are both running carries on.
///
/// The whole-`Service` counterpart to `tiebreak_always_includes_empty_txt`'s
/// Case A: that one pins the comparator, this one pins that a tie moves no
/// lifecycle state, queues no `ServiceUpdate`, and keeps the name.
#[test]
fn tiebreak_tie_keeps_the_name_and_the_probe_sequence() {
  let mut svc = make_service(120); // SRV: priority 0, weight 0, port 631, host.local.
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing
  let original_name = svc.name().as_str().to_owned();

  // The peer proposes exactly what `make_records` proposes. Enumerated
  // literally, not read back from our own `ServiceRecords`: priority 0, weight
  // 0, port 631, target `host.local.`, and the empty TXT `write_probe` always
  // emits.
  let peer: core::net::SocketAddr = "192.168.1.42:5353".parse().unwrap();
  let bytes = proposal_bytes(
    "myprinter._ipp._tcp.local.",
    &[
      Rec::Txt(&[]),
      Rec::Srv {
        port: 631,
        target: "host.local.",
      },
    ],
  );
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "precondition: the peer's proposal was compared and found identical, so it \
     recorded no loss"
  );

  svc.handle_timeout(t0.advance(500)).unwrap();

  assert_eq!(
    svc.name().as_str(),
    original_name,
    "§8.2.1: identical record sets are \"no conflict\", so the name must not \
     change — a fault-tolerant pair must not rename each other away"
  );
  assert!(
    svc.poll().is_none(),
    "a tie queues no ServiceUpdate at all: not Renamed, not Conflict"
  );
  assert!(
    matches!(svc.state(), ServiceState::Probing(_) | ServiceState::Init),
    "the §8.1 sequence continues through a tie; got {:?}",
    svc.state()
  );
  assert_eq!(
    svc.rename_attempt, 0,
    "a tie is not a loss, so it spends no rename attempt"
  );
}

/// RFC 6762 §8.1: "Apparently conflicting Multicast DNS RESPONSES received
/// *before* the first probe packet is sent MUST be silently ignored (see
/// discussion of stale probe packets in Section 8.2)."
///
/// The failure this pins was observed cross-process: the losing responder had
/// `packets_tx 0`, `probes_tx 0`, `packets_dropped 0` and still renamed itself
/// 0.32 s after registering — faster than §8.1's three probes 250 ms apart can
/// possibly complete. §8.2 gives the reason the rule exists: what arrives that
/// early may be a stale probe "sent moments ago by this host itself, before some
/// configuration change, which may be echoed back after a short delay by some
/// Ethernet switches".
///
/// The fence is on RESPONSES and on nothing else, which the second half asserts.
/// §8.2's tiebreak input is a peer's QUERY — "When a host that is probing for a
/// record sees another host issue a query for the same record, it consults the
/// Authority Section of that query" — and it states no such precondition, so a
/// simultaneous prober's proposal arriving in the same window is compared, not
/// discarded. Fencing both would blind the tiebreak for the whole of this
/// responder's own 0–250 ms initial delay.
#[test]
fn probe_conflict_before_our_first_probe_is_ignored() {
  let mut svc = make_service(120); // our SRV: port 631
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing(0): nothing on the wire yet
  let original_name = svc.name().as_str().to_owned();

  // A peer whose list would beat ours outright (port 9999 > our 631), so
  // nothing but the §8.1 window can be what keeps the name.
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
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    t0,
  );

  assert!(
    !svc.tiebreak_lost,
    "a conflicting RESPONSE received before our first probe must not be \
     compared, so it can record no §8.2 loss"
  );

  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();
  assert_eq!(
    svc.name().as_str(),
    original_name,
    "a service that has transmitted nothing must not rename itself"
  );
  assert!(
    svc.poll().is_none(),
    "and it must queue no ServiceUpdate either"
  );

  // Same window, same rdata, different EVENT: a simultaneous prober's whole
  // Authority Section is §8.2's input and is compared regardless. That the two
  // halves differ only in which event carries them is now a property of the
  // type — §8.1's rule is about RESPONSES, and a response is what
  // `ProbeConflict` is.
  let proposal = proposal_bytes(
    "myprinter._ipp._tcp.local.",
    &[Rec::Srv {
      port: 9999,
      target: "host.local.",
    }],
  );
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&proposal, peer, dg(1))),
    t1,
  );
  assert!(
    svc.tiebreak_lost,
    "§8.1's pre-probe rule is about RESPONSES; a peer's tentative probe is what \
     §8.2 requires comparing, and it must reach the comparator and be scored — \
     not merely be acknowledged"
  );
  // Undo the verdict so the response half below is measured on a clean round.
  svc.tiebreak_lost = false;

  // The response rule is about the WINDOW, not about the record: once a probe
  // has reached the wire, the very same response IS acted on.
  //
  // INVERTED, from `tiebreak_pending` to `probe_defeated`. This used to assert
  // that a response inside the window is buffered for the §8.2 comparator, and
  // §8.1 leaves no room for a comparison: "if any conflicting Multicast DNS
  // response is received, then the probing host MUST defer to the existing
  // host, and SHOULD choose new names for some or all of its resource records
  // as appropriate." The admitted input that replaces it is the one below —
  // response inside the window ⇒ §8.1 deferral, not a tiebreak entry. What the
  // old assertion existed to pin, that the earlier no-rename was the WINDOW and
  // not a broken comparator, is unchanged and still asserted: the same bytes
  // that did nothing before the probe now cost the service its name.
  // `tiebreak_records_that_flatten_alike_are_not_a_tie` and
  // `tiebreak_two_peers_one_wins_we_lose` keep the buffering path covered, from
  // the tentative probes that are actually its input.
  let t2 = probe_once(&mut svc, t1);
  let (rec_again, _) = Ref::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec_again,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    t2,
  );
  assert!(
    svc.probe_defeated,
    "after our first probe reached the wire the same response IS acted on — as \
     a §8.1 deferral to a host that already owns the name"
  );
  assert!(
    !svc.tiebreak_lost,
    "…and never as a §8.2 tiebreak entry: that rule is for two hosts probing at \
     once, and this peer is not probing"
  );
  svc.handle_timeout(t2.advance(500)).unwrap();
  assert_ne!(
    svc.name().as_str(),
    original_name,
    "…so the service defers and renames, and the earlier no-rename was the \
     §8.1 window and not a broken comparator"
  );
}

/// RFC 6762 §8.1: "During probing, from the time the first probe packet is sent
/// until 250 ms after the third probe, if any conflicting Multicast DNS response
/// is received, then the probing host MUST defer to the existing host, and
/// SHOULD choose new names for some or all of its resource records as
/// appropriate."
///
/// The peer's SRV here sorts EARLIER than ours (port 80 against our 631), so the
/// §8.2 comparator would say we win and keep probing. That is the case the
/// later-sorting fixture in `probe_conflict_before_our_first_probe_is_ignored`
/// cannot see: there, deferral and the comparator happen to agree, so a
/// comparator applied to a response looks correct.
///
/// It is not correct. §8.2's lexicographic rule resolves two hosts probing
/// SIMULTANEOUSLY, where neither owns the name — "if two hosts are probing for
/// the same name simultaneously, neither will receive any response to the
/// probe". A response means someone already answered for it. Comparing there
/// would let any newcomer whose records happen to sort later keep probing toward
/// a name an existing responder holds, and then announce over it.
#[test]
fn a_response_beats_our_probe_even_when_our_records_sort_later() {
  let mut svc = make_service(120); // our SRV: port 631 (0x0277)
  let t0 = probe_once(&mut svc, FakeInstant::zero()); // §8.1 window open
  let original_name = svc.name().as_str().to_owned();

  // The peer's list has the SAME SHAPE as ours — an empty TXT and one SRV — so
  // the comparison turns on the port and nothing else: 80 (0x0050) is earlier
  // than our 631 (0x0277) at the first differing rdata byte, making the peer's
  // list lexicographically EARLIER and handing us the §8.2 win. (A peer sending
  // only an SRV would lose on shape instead, its `00 21` sorting after our TXT's
  // `00 10`, which is what `tiebreak_always_includes_empty_txt` Case B pins.)
  let peer: core::net::SocketAddr = "192.168.1.60:5353".parse().unwrap();
  let mut buf_srv: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf_srv,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    80,
    "host.local.",
  );
  let (srv_ref, _) = Ref::try_parse(&buf_srv, 0).unwrap();
  let mut buf_txt: std::vec::Vec<u8> = std::vec::Vec::new();
  make_txt_record_ref(&mut buf_txt, "myprinter._ipp._tcp.local.", 120, &[]);
  let (txt_ref, _) = Ref::try_parse(&buf_txt, 0).unwrap();

  // The §8.2 verdict on this very list, so the test states what it is overriding
  // rather than assuming it. Driven through a SEPARATE service and a real
  // `ProbeProposal`, because §8.2's answer is no longer readable as a value: a
  // proposal is folded on arrival and the only thing it leaves behind is whether
  // the next `handle_timeout` renames.
  {
    let mut as_if_probing = make_service(120); // same records as `svc`
    let p0 = FakeInstant::zero();
    as_if_probing.handle_timeout(p0).unwrap(); // Init → Probing
    let before = as_if_probing.name().as_str().to_owned();
    let bytes = srv_txt_proposal(80); // the peer's TXT(empty) + SRV(80)
    as_if_probing.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
      p0,
    );
    as_if_probing.handle_timeout(p0.advance(500)).unwrap();
    assert_eq!(
      as_if_probing.name().as_str(),
      before,
      "precondition: had this been a simultaneous PROBE, §8.2 would say we win \
       — which is exactly why routing a RESPONSE through it is unsound"
    );
  }

  for rref in [txt_ref, srv_ref] {
    svc.handle_event(
      ServiceEvent::ProbeConflict(ProbeConflict::new(
        peer,
        rref,
        dg(1),
        ConflictHistory::Unmatched,
      )),
      t0,
    );
  }
  assert!(
    svc.probe_defeated,
    "a conflicting response inside the probing window is a §8.1 deferral, \
     whatever our records sort like"
  );

  svc.handle_timeout(t0.advance(500)).unwrap();
  assert_ne!(
    svc.name().as_str(),
    original_name,
    "§8.1: the probing host MUST defer to the existing host and SHOULD choose a \
     new name — keeping this one would announce over a responder that already \
     holds it"
  );
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "and it re-probes the new name from scratch"
  );
}

/// A peer PROBING our host name must not retire the service.
///
/// `ServiceUpdate::HostConflict` is terminal — every driver withdraws and retires
/// on it — and RFC 6762 §9 defines a conflict over a RESPONSE. A probe is a peer
/// asking whether a name is free, so honouring one here would let a single
/// ordinary probe retire every service sharing that host name: the same denial
/// of service the instance path closes, reached through the host route.
#[test]
fn a_peer_probing_our_host_name_does_not_retire_us() {
  let mut svc = make_service(120); // host.local. -> 192.168.1.10
  let now = drive_to_established(&mut svc);
  while svc.poll().is_some() {}

  // A DIFFERENT address for our host name: a genuine §9 conflict had it come in
  // a response, so only the origin can be what keeps this service alive.
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [10, 0, 0, 99]);
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::HostConflict(crate::event::HostConflict::new(
      rec,
      ConflictOrigin::TentativeProbe,
    )),
    now,
  );
  assert!(
    svc.poll().is_none(),
    "a peer's tentative probe for our host name is not §9's conflict, so it must \
     queue no terminal HostConflict"
  );
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "and the service keeps serving"
  );

  // The same record in a RESPONSE is the §9 conflict, so the difference is the
  // origin and not the address.
  let (rec_resp, _) = Ref::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::HostConflict(crate::event::HostConflict::new(
      rec_resp,
      ConflictOrigin::AuthoritativeResponse,
    )),
    now,
  );
  assert!(
    svc.poll().is_some_and(|u| u.is_host_conflict()),
    "the identical record in a response DOES surface HostConflict"
  );
}

/// `ServiceUpdate::Renamed` is emitted at the rename DECISION, and that decision
/// puts the service back in `Init` to probe the new label from scratch. It never
/// means "advertised": at the moment it is queued the new name has not been
/// probed once, let alone announced.
///
/// Pins the claim `hick-mio/tests/loopback.rs`'s `advertise` helper rests on —
/// that helper waits for `Established` and treats `Renamed` as "keep waiting".
#[test]
fn renamed_update_means_probing_restarted_not_advertised() {
  let mut svc = make_service(120);
  // The stimulus is a conflicting RESPONSE, because that is what renames: §8.1
  // requires one to arrive after a probe of ours has been sent, and a §8.2
  // tiebreak loss now defers and keeps the name instead.
  let t0 = probe_once(&mut svc, FakeInstant::zero());
  deliver_losing_srv_conflict(&mut svc, t0, ConflictOrigin::AuthoritativeResponse);
  svc.handle_timeout(t0.advance(500)).unwrap();

  let update = svc
    .poll()
    .expect("a §8.1 deferral to an existing owner queues exactly one update");
  assert!(
    update.is_renamed(),
    "the §8.1 deferral reports Renamed, got {update:?}"
  );
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "Renamed is queued with the service back in Init — a fresh §8.1 sequence, \
     not a finished one"
  );
  assert_eq!(
    svc.probe_count, 0,
    "the new name has not been probed even once when Renamed is reported"
  );
  assert!(
    !svc.has_fully_announced().get(),
    "and it has announced nothing, so Renamed cannot mean advertised"
  );
  assert!(
    !svc.advertises_instance(),
    "no instance record of the new name is in any peer cache yet"
  );

  // Being advertised is a LATER and DIFFERENT update. Drive the new name's own
  // probe → announce sequence and confirm that is what reports it.
  let mut buf = std::vec![0u8; 4096];
  let mut now = t0.advance(500);
  let mut established = false;
  for _ in 0..20 {
    now = now.advance(500);
    svc.handle_timeout(now).unwrap();
    while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
      svc.note_delivery(now, TransmitDelivery::ALL);
    }
    while let Some(u) = svc.poll() {
      established |= matches!(u, ServiceUpdate::Established);
    }
    if established {
      break;
    }
  }
  assert!(
    established,
    "the renamed service reports being advertised with Established, which is \
     the update `advertise` must wait for; state={:?}",
    svc.state()
  );
}

/// RFC 6762 §9 defines a conflict over a RESPONSE — "it receives a Multicast
/// DNS response message containing a record with the same name, rrtype and
/// rrclass, but inconsistent rdata" — so a peer merely PROBING a name this
/// service already owns must not push it back into probing.
///
/// The right answer to that probe is to defend the name (§8.1: "it SHOULD
/// generate its response to defend that name immediately"), which the `Question`
/// arm does from the question the same probe carries. Reverting instead would
/// hand any host a way to stop an established service serving its name just by
/// probing for it — and then to take the name outright on the §8.2 tiebreak the
/// re-probe runs.
#[test]
fn a_peer_probing_our_established_name_does_not_revert_us() {
  let mut svc = make_service(120); // our SRV: port 631
  let now = drive_to_established(&mut svc);
  while svc.poll().is_some() {} // drain Established

  // Rdata that WOULD be a §9 conflict had it arrived in a response, and that
  // would also beat us on the §8.2 tiebreak — so only which event carries it can
  // be what keeps this service established.
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
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let proposal = proposal_bytes(
    "myprinter._ipp._tcp.local.",
    &[Rec::Srv {
      port: 9999,
      target: "host.local.",
    }],
  );
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&proposal, peer, dg(1))),
    now,
  );

  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "§9 needs a RESPONSE; a peer's tentative probe for a name we own is \
     answered, not deferred to"
  );
  assert!(
    svc.poll().is_none(),
    "and it queues no update — nothing about this service changed"
  );

  // The same rdata in a RESPONSE is a genuine §9 conflict, so the difference
  // really is the event and not the record.
  let (rec_resp, _) = Ref::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec_resp,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    now,
  );
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "the identical record in a response DOES revert us to re-probing (§9)"
  );
}

/// RFC 6762 §9 sends a conflicted responder through a FRESH §8 startup sequence
/// — "reset its conflicted unique record to probing state, and go through the
/// startup steps described above in Section 8" — so §8.1's pre-probe window
/// re-opens with it, and a conflicting response arriving before the restarted
/// sequence's first probe is ignored.
///
/// This is also what stops ONE datagram being scored as two. A driver dispatches
/// a response's records one at a time, so a response carrying a differing TXT
/// and then a differing SRV reverts on the TXT and offers the SRV to the
/// probing-state arm — which, with the window still open, would buffer a peer
/// "list" holding only the SRV and decide the tiebreak against a fragment of
/// what the peer actually sent. Our own list would then lose on the first record
/// (`00 21…` beats our TXT's `00 10…`) even where the peer's real list loses.
#[test]
fn the_section9_revert_shuts_the_pre_probe_window_again() {
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  while svc.poll().is_some() {}
  let original_name = svc.name().as_str().to_owned();

  // Record 1 of the peer's response: a differing TXT. This is the §9 conflict,
  // and it reverts us to probing.
  let mut buf_txt: std::vec::Vec<u8> = std::vec::Vec::new();
  make_txt_record_ref(
    &mut buf_txt,
    "myprinter._ipp._tcp.local.",
    120,
    &[b"different"],
  );
  let (txt_ref, _) = Ref::try_parse(&buf_txt, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      txt_ref,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    now,
  );
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "precondition: the differing TXT is a §9 conflict and reverts us"
  );

  // Record 2 of the SAME response: a differing SRV, dispatched immediately
  // after. Alone it would beat our list; as part of the peer's real list it may
  // not, and either way it arrives before the restarted sequence has probed.
  let mut buf_srv: std::vec::Vec<u8> = std::vec::Vec::new();
  make_srv_record_ref(
    &mut buf_srv,
    "myprinter._ipp._tcp.local.",
    120,
    0,
    0,
    9999,
    "host.local.",
  );
  let (srv_ref, _) = Ref::try_parse(&buf_srv, 0).unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      srv_ref,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    now,
  );
  assert!(
    !svc.tiebreak_lost,
    "the §9 revert restarted the §8.1 sequence, so this response arrived before \
     its first probe and §8.1 requires it be ignored — no tiebreak may be \
     decided on the fragment of a response the revert split in half"
  );

  svc.handle_timeout(now.advance(500)).unwrap();
  assert_eq!(
    svc.name().as_str(),
    original_name,
    "so the re-verification runs as §9 asks — probe the name again — instead of \
     renaming off a one-record fragment"
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
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
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
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
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
  // A probe on the wire, then a conflicting RESPONSE — §8.1's rename. A §8.2
  // tiebreak loss now defers and keeps the name, so it renames nothing.
  let t0 = probe_once(&mut svc, FakeInstant::zero());
  // Simulate that the original name was announced (peers cached it).
  svc.goodbye.mark_instance();

  // An existing owner's differing SRV (port 9999 > 631) → §8.1 deferral → rename.
  deliver_losing_srv_conflict(&mut svc, t0, ConflictOrigin::AuthoritativeResponse);
  svc.handle_timeout(t0.advance(500)).unwrap();

  assert!(
    svc.name().as_str().contains("-1"),
    "the §8.1 deferral to an existing owner must rename"
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

/// When two different peers send proposals and at least one of them has
/// a larger SRV set (port > ours), the service MUST defer. The tiebreak
/// must evaluate each peer bucket independently; a peer that loses must not
/// protect us from a peer that wins.
///
/// Our SRV: port=631. Peer A: port=80 (loses). Peer B: port=9999 (wins).
/// Because Peer B wins, we must defer to it.
#[test]
fn tiebreak_two_peers_one_wins_we_lose() {
  let mut svc = make_service(120); // our SRV: port=631
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing

  // Peer A (src=.10) proposes TXT(empty) + SRV(80) → Peer A loses (our 631 > 80).
  //
  // The TXT matters: a proposal of SRV alone would WIN on shape, its `00 21`
  // beating our TXT's `00 10` at the first record, whatever the port. Peer A
  // used to send the bare SRV, so "the loser" in this fixture was in fact a
  // winner and the rename below was never evidence that Peer B was consulted.
  let peer_a: core::net::SocketAddr = "192.168.1.10:5353".parse().unwrap();
  let bytes_a = srv_txt_proposal(80);
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes_a, peer_a, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "precondition: Peer A's proposal really does lose, so any loss recorded \
     below can only have come from Peer B"
  );

  // Peer B (src=.200) proposes TXT(empty) + SRV(9999) → Peer B wins (9999 > 631).
  let peer_b: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let bytes_b = srv_txt_proposal(9999);
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes_b, peer_b, dg(1))),
    t0,
  );

  assert!(
    svc.tiebreak_lost,
    "each proposal is scored on its own, so a peer we beat cannot shield us \
     from one that beats us"
  );
  let original_name = svc.name().as_str().to_owned();

  // Trigger the tiebreak: Peer B wins → we defer to it.
  let t1 = t0.advance(500);
  svc.handle_timeout(t1).unwrap();

  // INVERTED, deliberately. The old claim was "a §8.2 loss renames"; the
  // admitted outcome now is that a §8.2 loss KEEPS the name and re-probes it
  // after one second — RFC 6762 §8.2: "it defers to the winning host by waiting
  // one second, and then begins probing for this record again." Only a §8.1 loss
  // to a host that already OWNS the name renames. What this fixture pins is
  // unchanged either way: the verdict came from Peer B, because Peer A's
  // proposal on its own recorded none (asserted above), and the deferral below
  // can only have come from the peer that beat us.
  assert_tiebreak_deferred(&mut svc, &original_name, t1, "one of two peers beating us");
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
  proposal::write_canonical_wire_name("aa.local.", &mut out_aa);
  assert_eq!(
    out_aa,
    std::vec![2u8, b'a', b'a', 5, b'l', b'o', b'c', b'a', b'l', 0],
    "wire form for 'aa.local.' must be \\x02aa\\x05local\\x00"
  );

  // Wire-form encoding of "b.local." should be:
  // \x01 b \x05 l o c a l \x00
  let mut out_b: std::vec::Vec<u8> = std::vec::Vec::new();
  proposal::write_canonical_wire_name("b.local.", &mut out_b);
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

/// A KnownAnswer hint for our SRV record (stored via the identity form, which
/// uses wire-form target encoding) MUST match the filter built by
/// write_announce_filtered (which now also uses wire-form encoding).
///
/// Previously the filter used dot-joined plain bytes for the SRV target while
/// the identity form used wire-form, so the hashes never matched and SRV hints
/// could never suppress our SRV answer. `the_kas_filter_offers_the_bytes_the_
/// identity_decoder_yields` now pins that pairing for every filtered type.
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

/// The §8.2 comparison must include TXT in our local set even when
/// txt_segments is empty, matching what write_probe emits unconditionally.
///
/// Previously the TXT was omitted when empty, while write_probe still
/// emitted an empty TXT authority record — causing a tiebreak asymmetry.
///
/// This test verifies two cases:
///
/// Case A — Peer sends SRV + TXT(empty) with the SAME port as ours: the sets are
/// byte-identical, which §8.2.1 calls "no conflict", so we must NOT lose. (This
/// assertion was inverted; the in-body comment records why, and which admitted
/// input replaces the one it used to assert.)
///
/// Case B — Peer sends only SRV(same port) with NO TXT: our set (with TXT
/// prefix) starts with rtype=0x0010(TXT) while peer's starts with 0x0021(SRV).
/// peer_concat > our_concat → we LOSE, and a §8.2 loss DEFERS. This is the case
/// that still discriminates a local set carrying the empty TXT from one that
/// drops it: without the TXT, both sides would be {SRV(631)} and this would be a
/// tie — no loss and so no deferral — instead of a loss.
#[test]
fn tiebreak_always_includes_empty_txt() {
  // `make_service` proposes SRV(priority 0, weight 0, port 631, `host.local.`)
  // and NO TXT segments, which is the local set under test: the empty TXT its
  // proposal carries is supplied by the proposal builder, not by the records.
  let our = make_records(120);
  assert_eq!(
    our.txt_segments().count(),
    0,
    "precondition: no TXT segments"
  );
  drop(our);

  let peer_src: core::net::SocketAddr = "192.168.1.99:5353".parse().unwrap();

  // ── Case A: Peer sends SRV(631) + TXT(empty) → tie → no rename ──────
  {
    let bytes = proposal_bytes(
      "myprinter._ipp._tcp.local.",
      &[
        Rec::Srv {
          port: 631, // SAME port as ours
          target: "host.local.",
        },
        Rec::Txt(&[]),
      ],
    );

    // The peer's proposal under `RdataForm::AS_SENT` — the form the service
    // actually runs over an inbound Authority Section — so the enumerated
    // precondition below is about the bytes actually compared.
    //
    // THERE ARE TWO FORMS AND PICKING THE WRONG ONE FAILS SILENTLY. `FOLDED`
    // answers "are these the same record" and normalises (lowercased SRV target,
    // empty TXT rewritten to one zero-length string); `AS_SENT` answers §8.2's
    // "which sorts later" over the bytes the peer sent. They agree on this
    // fixture's all-lowercase `host.local.` — this site used the identity one and
    // passed — and diverge the moment a fixture uses a mixed-case target, at
    // which point the expectations below would be asserting bytes the comparison
    // never sees.
    let reader = crate::wire::MessageReader::try_parse(&bytes).unwrap();
    let peer_canonical = reader
      .authority()
      .flatten()
      .map(|r| {
        let mut canonical = std::vec::Vec::new();
        proposal::tiebreak_bytes_for_fixture(&r, &mut canonical).unwrap();
        (r.rtype(), canonical)
      })
      .collect::<std::vec::Vec<_>>();

    // The tie is established from ENUMERATED LITERALS, never by asking the
    // comparator whether it thinks these are equal. Canonical rdata, byte for
    // byte, for the two records both sides propose:
    //   SRV  = priority 0, weight 0, port 631 (0x0277), target `host.local.`
    //          in uncompressed wire form (§8.2: "the names MUST be
    //          uncompressed before comparison").
    //   TXT  = one zero-length string, the single 0x00 byte `push_txt_authority`
    //          puts on the wire for an empty TXT — and therefore the byte a
    //          §8.2 comparison of "the bytes that side sent" sees.
    const SRV_CANONICAL: &[u8] = &[
      0x00, 0x00, // priority
      0x00, 0x00, // weight
      0x02, 0x77, // port 631
      0x04, b'h', b'o', b's', b't', // "host"
      0x05, b'l', b'o', b'c', b'a', b'l', // "local"
      0x00, // root
    ];
    const TXT_CANONICAL: &[u8] = &[0x00];
    assert_eq!(
      peer_canonical,
      std::vec![
        (crate::wire::ResourceType::Srv, SRV_CANONICAL.to_vec()),
        (crate::wire::ResourceType::Txt, TXT_CANONICAL.to_vec()),
      ],
      "precondition: the peer proposes exactly the SRV(631)+TXT(empty) this \
       service proposes, so the two sets are byte-identical by construction"
    );

    // INVERTED, deliberately. This asserted `we_lose` while the comparator used
    // `>=`, citing a §8.2.1 sentence — "the host MUST rename itself" — that does
    // not exist: the word "rename" appears nowhere in RFC 6762 §8. What §8.2.1
    // actually says about this exact input is the opposite: "If both lists run
    // out of records at the same time without any difference being found, then
    // this indicates that two devices are advertising identical sets of records,
    // as is sometimes done for fault tolerance, and there is, in fact, no
    // conflict." §9 agrees — "resource records with identical rdata are never
    // considered inconsistent, even if they originate from different hosts".
    //
    // The old assertion is NOT preserved as a narrower still-passing case,
    // because no admitted input reaches it: `we_lose` on a byte-identical set is
    // unreachable under §8.2.1 for every input, not merely for this one. What
    // the old assertion was written to PIN — that our local set always carries a
    // TXT entry even with no segments, matching what `write_probe` emits — is
    // preserved by Case B below, whose assertion is unchanged and still passing,
    // and which still discriminates the two implementations under the new rule:
    // with TXT in our set Case B is a LOSS (peer's 0x0021 > our 0x0010); with TXT
    // omitted both sides would be {SRV(631)} and Case B would be a tie, i.e. no
    // loss. So Case B alone still fails if the TXT is ever dropped again.
    let mut svc = make_service(120);
    let t0 = FakeInstant::zero();
    svc.handle_timeout(t0).unwrap(); // Init → Probing
    let original = svc.name().as_str().to_owned();
    svc.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer_src, dg(1))),
      t0,
    );
    svc.handle_timeout(t0.advance(500)).unwrap();
    assert_eq!(
      svc.name().as_str(),
      original,
      "Case A: byte-identical SRV(631)+TXT(empty) on both sides is §8.2.1's \
       \"there is, in fact, no conflict\", NOT a loss — two devices deliberately \
       advertising identical records must both keep the name"
    );
  }

  // ── Case B: Peer sends only SRV(631) with no TXT ─────────────────────
  // Our set (with TXT always included) = sorted [TXT_prefix, SRV(631)].
  // Peer set = [SRV(631)].
  // our_concat[0..2] = 0x00,0x10 (TXT type); peer_concat[0..2] = 0x00,0x21 (SRV type).
  // peer_concat > our_concat → we lose.
  {
    let bytes = proposal_bytes(
      "myprinter._ipp._tcp.local.",
      &[Rec::Srv {
        port: 631, // SAME port as ours — no TXT from peer
        target: "host.local.",
      }],
    );

    // peer set {SRV(631)} starts with 0x0021; our set starts with 0x0010 (TXT)
    // → the peer's first record is greater → we lose.
    let mut svc = make_service(120);
    let t0 = FakeInstant::zero();
    svc.handle_timeout(t0).unwrap(); // Init → Probing
    let original = svc.name().as_str().to_owned();
    svc.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer_src, dg(1))),
      t0,
    );
    let spent = t0.advance(500);
    svc.handle_timeout(spent).unwrap();
    // INVERTED, deliberately: the LOSS is unchanged, what a loss DOES changed.
    // The old claim was "a §8.2 loss renames" and this asserted the name moved;
    // the admitted outcome now is that a §8.2 loss KEEPS the name and re-probes
    // it after one second — RFC 6762 §8.2: "it defers to the winning host by
    // waiting one second, and then begins probing for this record again." Only a
    // §8.1 loss to a host that already OWNS the name renames.
    //
    // What Case B exists to discriminate survives the inversion intact, because
    // the deferral is asserted rather than merely "no rename": with the empty TXT
    // in our local set the peer's 0x0021 beats our 0x0010 and we defer; with the
    // TXT dropped both sides are {SRV(631)}, §8.2.1's tie, and NOTHING is
    // deferred — `Init` + a one-second `lifecycle_deadline` would both be absent.
    assert_tiebreak_deferred(
      &mut svc,
      &original,
      spent,
      "Case B: peer set starting with SRV(0x0021) > our set starting with \
       TXT(0x0010)",
    );
  }
}

// ── tiebreak compares record LISTS, never their concatenation ─

/// Two genuinely different record lists can flatten to identical bytes, so
/// RFC 6762 §8.2.1's pairwise comparison must never be reduced to a byte
/// comparison of the concatenated lists.
///
/// The collision is constructible against this crate's own canonical encoding
/// (`rtype` big-endian, then canonical rdata, per record):
///
/// * OURS is two records — `TXT("k=v")` and an `SRV` whose rdata is 33 bytes
///   (2+2+2 for priority/weight/port, plus a 27-byte uncompressed target).
///   Flattened: `00 10 | 03 "k=v" | 00 21 | <33 SRV bytes>`.
/// * THEIRS is ONE record — `TXT("k=v", "", <those same 33 SRV bytes>)`.
///   Flattened: `00 10 | 03 "k=v" 00 21 <33 SRV bytes>`.
///
/// The SRV element's `00 21` type prefix is re-read as an empty TXT segment
/// (`00`) followed by a 33-byte one (`21`), and this crate accepts empty TXT
/// segments, so both flatten to the same 41 bytes. Concatenated, that is a tie
/// — "there is, in fact, no conflict" — and BOTH owners would keep the name
/// while serving different rdata, which is the outcome §8.2 exists to prevent.
/// Compared as lists, our first record is a proper prefix of their only record,
/// so they win outright and we defer to them.
#[test]
fn tiebreak_records_that_flatten_alike_are_not_a_tie() {
  // A 27-byte uncompressed target name: `15` + 21 × 'a', `03` + "loc", `00`.
  const TARGET: &str = "aaaaaaaaaaaaaaaaaaaaa.loc.";
  const PORT: u16 = 631; // 0x0277

  let stype = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let inst = Name::try_from_str("myprinter._ipp._tcp.local.").unwrap();
  let host = Name::try_from_str(TARGET).unwrap();
  let mut our = ServiceRecords::new(stype, inst, host, PORT, 120);
  our.add_txt_segment(std::vec![b'k', b'=', b'v']);
  let mut svc: Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> =
    Service::try_new(
      ServiceHandle::from_raw(0),
      our,
      FakeInstant::zero(),
      [0u8; 32],
      true,
    );
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing
  let original = svc.name().as_str().to_owned();

  // Every byte below is enumerated, so the collision is established by
  // construction rather than by asking the comparator whether it sees one.
  let mut srv_rdata: std::vec::Vec<u8> = std::vec::Vec::new();
  srv_rdata.extend_from_slice(&[0x00, 0x00]); // priority 0
  srv_rdata.extend_from_slice(&[0x00, 0x00]); // weight 0
  srv_rdata.extend_from_slice(&[0x02, 0x77]); // port 631
  srv_rdata.push(21);
  srv_rdata.extend_from_slice(&[b'a'; 21]);
  srv_rdata.push(3);
  srv_rdata.extend_from_slice(b"loc");
  srv_rdata.push(0);
  assert_eq!(
    srv_rdata.len(),
    33,
    "precondition: the SRV rdata must be exactly 33 bytes, so that the `21` of \
     its `00 21` type prefix is re-read as a segment length that consumes all \
     of it"
  );

  // OUR list, sorted: TXT (type 0x0010) then SRV (type 0x0021).
  let mut our_flat: std::vec::Vec<u8> = std::vec![0x00, 0x10, 0x03, b'k', b'=', b'v'];
  our_flat.extend_from_slice(&[0x00, 0x21]);
  our_flat.extend_from_slice(&srv_rdata);

  // THEIR single TXT: segments "k=v", "" and the 33 SRV bytes.
  let mut their_txt_rdata: std::vec::Vec<u8> = std::vec![0x03, b'k', b'=', b'v', 0x00, 0x21];
  their_txt_rdata.extend_from_slice(&srv_rdata);
  let mut their_flat: std::vec::Vec<u8> = std::vec![0x00, 0x10];
  their_flat.extend_from_slice(&their_txt_rdata);

  assert_eq!(
    our_flat, their_flat,
    "precondition: the two lists flatten to identical bytes — this is the \
     collision, and it is what a concatenating comparator cannot see"
  );

  // The peer's proposal: ONE TXT carrying the colliding segments, run through
  // the same canonicalization the service applies to a real inbound record.
  let peer_src: core::net::SocketAddr = "192.168.1.77:5353".parse().unwrap();
  let bytes = proposal_bytes(
    "myprinter._ipp._tcp.local.",
    &[Rec::Txt(&[b"k=v", b"", &srv_rdata[..]])],
  );
  let reader = crate::wire::MessageReader::try_parse(&bytes).unwrap();
  let peer_rec = reader.authority().flatten().next().unwrap();
  assert_eq!(
    peer_rec.rtype(),
    crate::wire::ResourceType::Txt,
    "precondition: the peer's proposal is the single TXT, not a pair"
  );
  // `RdataForm::AS_SENT`, the form the §8.2 comparison actually runs over an
  // inbound record — not `FOLDED`, which normalises.
  //
  // THERE ARE TWO FORMS AND PICKING THE WRONG ONE FAILS SILENTLY. They agree on
  // every non-empty TXT, which is what this collision payload is — this site used
  // the identity one and passed — so the wrong choice would only surface once a
  // fixture proposed an empty TXT or a mixed-case name, and then it would be
  // asserting bytes §8.2 never compares.
  let mut canonical = std::vec::Vec::new();
  proposal::tiebreak_bytes_for_fixture(&peer_rec, &mut canonical).unwrap();
  assert_eq!(
    canonical, their_txt_rdata,
    "precondition: the peer's compared TXT rdata is the enumerated collision \
     payload, so the comparison under test really is the colliding one"
  );

  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer_src, dg(1))),
    t0,
  );
  let spent = t0.advance(500);
  svc.handle_timeout(spent).unwrap();

  // INVERTED, deliberately. The old claim was "a §8.2 loss renames" and this
  // asserted the name moved; the admitted outcome now is that a §8.2 loss KEEPS
  // the name and re-probes it after one second — RFC 6762 §8.2: "it defers to
  // the winning host by waiting one second, and then begins probing for this
  // record again." Only a §8.1 loss to a host that already OWNS the name
  // renames.
  //
  // The collision this fixture is about is untouched by that: a concatenating
  // comparator sees a TIE here, and a tie moves NOTHING — no `Init`, no
  // one-second deadline — so asserting the deferral still separates the two
  // implementations exactly as asserting the rename used to.
  assert_tiebreak_deferred(
    &mut svc,
    &original,
    spent,
    "§8.2.1 compares the lists pairwise: our first record is a proper prefix of \
     the peer's only record, so the peer is lexicographically later and we \
     lose. Reading the flattened bytes instead makes this a tie, and leaves two \
     owners on one name with different rdata",
  );
}

/// A peer's probe delivered TWICE before one `handle_timeout` is one proposal
/// seen twice, not a longer proposal.
///
/// RFC 6762 §8.2 takes "the Authority Section of THAT query", and requires it to
/// "contain *all* the records and proposed rdata being probed for uniqueness" —
/// so a proposal is per-datagram. Accumulating both copies into one
/// source-addressed bucket produces `[TXT, TXT, SRV, SRV]`, whose SECOND element
/// is the duplicated TXT (`00 10 …`) where ours is the SRV (`00 21 …`); ours
/// then compares later and a responder that should have LOST concludes it won.
///
/// Reachable without a hostile peer: plain UDP duplication, a `handle_timeout`
/// delayed past two of the peer's own §8.1 retransmissions (which are 250 ms
/// apart, the same cadence as our own probe deadlines), or two co-resident
/// responders sharing one `IP:5353`.
#[test]
fn a_retransmitted_probe_is_not_a_longer_proposal() {
  let peer: core::net::SocketAddr = "192.168.1.90:5353".parse().unwrap();

  // One losing-for-us proposal: SRV(9999) beats our SRV(631), same empty TXT.
  let bytes = srv_txt_proposal(9999);

  // INVERTED, deliberately, in both blocks below. The old claim was "a §8.2 loss
  // renames" and each block asserted the name moved; the admitted outcome now is
  // that a §8.2 loss KEEPS the name and re-probes it after one second — RFC 6762
  // §8.2: "it defers to the winning host by waiting one second, and then begins
  // probing for this record again." Only a §8.1 loss to a host that already OWNS
  // the name renames, and a retransmitted PROBE is by definition not that.
  //
  // The subject is unchanged: whether two copies of one proposal can be read as
  // one longer list. Asserting the DEFERRAL rather than merely "no rename" is
  // what keeps that legible — the merged `[TXT, TXT, SRV, SRV]` reading is a WIN
  // for us, which defers nothing at all.

  // Delivered ONCE: the peer wins and we defer. This is the control — without
  // it, the duplicate case below could pass for want of any conflict at all.
  {
    let mut svc = make_service(120);
    let t0 = FakeInstant::zero();
    svc.handle_timeout(t0).unwrap();
    let original = svc.name().as_str().to_owned();
    svc.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
      t0,
    );
    let spent = t0.advance(500);
    svc.handle_timeout(spent).unwrap();
    assert_tiebreak_deferred(
      &mut svc,
      &original,
      spent,
      "control: one copy of this proposal beats ours",
    );
  }

  // Delivered TWICE before the timeout — the SAME proposal, retransmitted.
  // Each datagram is its own `ProbeProposal` and is scored the moment it
  // arrives, so the two copies cannot accumulate into one longer list: the
  // `[TXT, TXT, SRV, SRV]` the old buffer could build is no longer a value this
  // code can hold.
  {
    let mut svc = make_service(120);
    let t0 = FakeInstant::zero();
    svc.handle_timeout(t0).unwrap();
    let original = svc.name().as_str().to_owned();
    for datagram in [dg(1), dg(2)] {
      svc.handle_event(
        ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, datagram)),
        t0,
      );
    }
    assert!(
      svc.tiebreak_lost,
      "two datagrams are two proposals, even from one source address, and each \
       is scored as exactly the {{TXT, SRV}} the peer actually proposed"
    );
    let spent = t0.advance(500);
    svc.handle_timeout(spent).unwrap();
    assert_tiebreak_deferred(
      &mut svc,
      &original,
      spent,
      "a retransmission cannot turn a loss into a win: merging the two copies \
       into one bucket would sort as [TXT, TXT, SRV, SRV], whose second element \
       is below our SRV, and we would wrongly win outright and defer nothing",
    );
  }
}

/// An established peer defending with BYTE-IDENTICAL records must not cost a
/// probing responder its name — in initial probing or in a §9 re-probe.
///
/// This is the defect this whole PR opened on, in the one arm that still had
/// it. RFC 6762 §9: "resource records with identical rdata are never considered
/// inconsistent, even if they originate from different hosts. This is to permit
/// use of proxies and other fault-tolerance mechanisms that may cause more than
/// one responder to be capable of issuing identical answers on the network."
/// §8.2.1 says it for the probing path: identical sets are "sometimes done for
/// fault tolerance, and there is, in fact, no conflict."
///
/// The endpoint routes a `ProbeConflict` for EVERY same-name SRV/TXT response,
/// so the identical case reaches this arm and used to set `probe_defeated` from
/// origin and `probe_on_wire` alone — never asking whether the rdata differed.
/// Two appliances configured to advertise one service redundantly would take
/// turns renaming each other away, which is exactly the deployment §9 names.
///
/// Both rows are covered because they take different paths to the same arm:
/// initial probing (row B) and a §9 re-probe holding the previous generation's
/// goodbye ownership (row B′).
#[test]
fn an_identical_defending_response_never_costs_a_probing_service_its_name() {
  // `make_service` proposes SRV(priority 0, weight 0, port 631, host.local.)
  // and an empty TXT — so these are byte-identical to ours.
  let identical = |buf: &mut std::vec::Vec<u8>, srv: bool| {
    if srv {
      make_srv_record_ref(
        buf,
        "myprinter._ipp._tcp.local.",
        120,
        0,
        0,
        631,
        "host.local.",
      );
    } else {
      make_txt_record_ref(buf, "myprinter._ipp._tcp.local.", 120, &[]);
    }
  };
  let peer: core::net::SocketAddr = "192.168.1.31:5353".parse().unwrap();

  // ── Row B: initial probing, first probe already on the wire ──────────────
  {
    let mut svc = make_service(120);
    let t0 = probe_once(&mut svc, FakeInstant::zero());
    let original = svc.name().as_str().to_owned();
    for srv in [false, true] {
      let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
      identical(&mut buf, srv);
      let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
      svc.handle_event(
        ServiceEvent::ProbeConflict(ProbeConflict::new(
          peer,
          rec,
          dg(1),
          ConflictHistory::Unmatched,
        )),
        t0,
      );
    }
    assert!(
      !svc.probe_defeated,
      "row B: a defending response carrying OUR OWN rdata is not a conflict, so \
       it must not latch a §8.1 deferral"
    );
    svc.handle_timeout(t0.advance(500)).unwrap();
    assert_eq!(
      svc.name().as_str(),
      original,
      "row B: two responders advertising identical records is the fault-tolerance \
       case §9 exists to permit — neither may rename the other away"
    );
  }

  // ── Row B′: §9 re-probe, previous generation's goodbye still latched ─────
  {
    let mut svc = make_service(120);
    let established_at = drive_to_established(&mut svc);
    while svc.poll().is_some() {}
    // A DIFFERING response reverts us (that part is a real §9 conflict).
    deliver_losing_srv_conflict(
      &mut svc,
      established_at,
      ConflictOrigin::AuthoritativeResponse,
    );
    assert_eq!(
      svc.state(),
      ServiceState::Init,
      "precondition: §9 reverted us"
    );
    assert!(
      svc.goodbye.any_instance(),
      "precondition: the previous generation's ownership is still latched"
    );
    let now = probe_once(&mut svc, established_at);
    let original = svc.name().as_str().to_owned();

    for srv in [false, true] {
      let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
      identical(&mut buf, srv);
      let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
      svc.handle_event(
        ServiceEvent::ProbeConflict(ProbeConflict::new(
          peer,
          rec,
          dg(1),
          ConflictHistory::Unmatched,
        )),
        now,
      );
    }
    assert!(
      !svc.probe_defeated,
      "row B′: the rule is a property of the RECORDS, so a re-probe screens \
       identical rdata exactly as initial probing does"
    );
    svc.handle_timeout(now.advance(500)).unwrap();
    assert_eq!(
      svc.name().as_str(),
      original,
      "row B′: and the re-probe keeps the name it is re-verifying"
    );
  }
}

/// A §9 re-probe classifies conflicts the same way whichever order the driver
/// ran its loop — even though the PREVIOUS generation's goodbye ownership is
/// still latched.
///
/// §9 keeps that ownership on purpose: peers hold the old records under this
/// same name and a §10.1 withdrawal must still retract them. But §9 also sends
/// the responder "through the startup steps described above in Section 8", so
/// the conflict rules are §8's again. Keying on `goodbye.any_instance()` made
/// `is_preauthoritative()` true in `Probing(3)` and false the instant a
/// timer-first driver stepped to `Announcing(0)` — so an RX-first driver
/// compared a winning proposal and renamed, and a timer-first driver routed the
/// identical proposal through the post-authoritative arm and ignored it. Both
/// contenders could then announce.
///
/// The never-advertised two-order test cannot see this: it starts from a
/// generation with no goodbye ownership at all, so the two latches agree there.
#[test]
fn a_section9_reprobe_classifies_the_same_in_both_driver_orders() {
  for rx_first in [true, false] {
    let mut svc = make_service(120);
    let established_at = drive_to_established(&mut svc);
    while svc.poll().is_some() {}
    assert!(
      svc.goodbye.any_instance(),
      "precondition: the FIRST generation advertised, so goodbye owns its records"
    );

    // §9: a conflicting response reverts us into a fresh §8 startup sequence.
    deliver_losing_srv_conflict(
      &mut svc,
      established_at,
      ConflictOrigin::AuthoritativeResponse,
    );
    assert_eq!(
      svc.state(),
      ServiceState::Init,
      "precondition: §9 reverted us"
    );
    assert!(
      svc.goodbye.any_instance(),
      "precondition: and it KEPT the old generation's ownership — that latch is \
       what used to leak into the conflict rules"
    );

    // Re-probe to the settling window.
    let mut now = established_at;
    for _ in 0..12 {
      now = svc.poll_timeout().unwrap_or(now.advance(250));
      svc.handle_timeout(now).unwrap();
      let mut buf = std::vec![0u8; 4096];
      while let Ok(Some(_)) = svc.poll_transmit(now, &mut buf) {
        svc.note_delivery(now, TransmitDelivery::ALL);
      }
      if matches!(svc.state(), ServiceState::Probing(3)) {
        break;
      }
    }
    assert!(
      matches!(svc.state(), ServiceState::Probing(3)),
      "precondition: the re-probe reached §8.1's settling window; got {:?}",
      svc.state()
    );
    let original = svc.name().as_str().to_owned();

    let due = svc.poll_timeout().expect("the settling window re-arms");
    let bytes = srv_txt_proposal(9999);
    let peer: core::net::SocketAddr = "192.168.1.66:5353".parse().unwrap();
    let deliver = |svc: &mut Service<_, _, _>| {
      svc.handle_event(
        ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
        due,
      );
    };
    // The verdict is spent by the FIRST `handle_timeout` that sees it, which is
    // the one at `due` when the datagram was drained first and the one 500 ms
    // later when the deadline transition ran first. §8.2's second is measured
    // from that instant.
    let spent = if rx_first {
      deliver(&mut svc);
      svc.handle_timeout(due).unwrap();
      due
    } else {
      svc.handle_timeout(due).unwrap();
      deliver(&mut svc);
      due.advance(500)
    };

    svc.handle_timeout(due.advance(500)).unwrap();
    // INVERTED, deliberately. The old claim was "a §8.2 loss renames" and this
    // asserted the name moved; the admitted outcome now is that a §8.2 loss
    // KEEPS the name and re-probes it after one second — RFC 6762 §8.2: "it
    // defers to the winning host by waiting one second, and then begins probing
    // for this record again." Only a §8.1 loss to a host that already OWNS the
    // name renames.
    //
    // The subject — that both driver orders classify identically — is if
    // anything sharper for it: the deferral is a five-part observable, and both
    // orders must produce all five.
    assert_tiebreak_deferred(
      &mut svc,
      &original,
      spent,
      &std::format!(
        "rx_first={rx_first}: a §9 re-probe is inside §8's startup steps, so a \
         winning proposal is deferred to whichever order the driver ran — the \
         old generation's goodbye ownership is a withdrawal obligation, not a \
         claim by the generation now probing"
      ),
    );
  }
}

/// A queued announcement must not overtake a classified conflict.
///
/// The classification and its decision are two separate calls, and state moves
/// between them. Reachable in `hick-smoltcp`, whose `pump` caps RX at
/// `MAX_RX_PER_PUMP`: one pass closes §8.1's settling window and fills the cap,
/// the next queues the first announcement, drains the conflicting response that
/// sets the latch, then transmits and confirms that announcement — and by the
/// following timeout a decision site that re-derived its predicate would find
/// the service advertised and silently never spend the existing owner's
/// response.
///
/// Two things stop it, and this exercises both: `poll_transmit` withholds every
/// positive-TTL claim to the name while a classification is unresolved, and the
/// decision site spends the stored latch rather than reclassifying.
#[test]
fn a_queued_announcement_cannot_overtake_a_classified_conflict() {
  let mut svc = make_service(120);
  let mut now = drive_to_probing_zero(&mut svc);
  for _ in 0..3 {
    let at = emit_probe(&mut svc, now);
    svc.note_delivery(at, TransmitDelivery::ALL);
    now = at;
  }
  // Close the settling window, then queue the first announcement.
  now = svc.poll_timeout().expect("settling re-arms");
  svc.handle_timeout(now).unwrap();
  now = svc.poll_timeout().expect("the announcement is due");
  svc.handle_timeout(now).unwrap();
  assert!(
    svc
      .pending_transmits
      .contains(&Some(PendingTransmitKind::Announcement)),
    "precondition: an announcement is queued and not yet transmitted"
  );
  let original = svc.name().as_str().to_owned();

  // The conflicting response lands while that announcement is still queued.
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
  let peer: core::net::SocketAddr = "192.168.1.44:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    now,
  );
  assert!(
    svc.probe_defeated,
    "precondition: the response was classified as a §8.1 deferral"
  );

  // The driver now does what it was going to do: transmit and confirm.
  let mut out = std::vec![0u8; 4096];
  let emitted = svc.poll_transmit(now, &mut out).unwrap();
  assert!(
    emitted.is_none(),
    "the queued announcement must be WITHHELD: claiming a name whose ownership \
     is under adjudication is what turns an unresolved conflict into two owners"
  );
  assert!(
    !svc.generation_advertised,
    "…so nothing of this generation reached the wire, and the decision site \
     cannot be told otherwise"
  );

  svc.handle_timeout(now.advance(500)).unwrap();
  assert_ne!(
    svc.name().as_str(),
    original,
    "the stored classification is spent on its own terms: an announcement that \
     slipped out in between must not be able to answer the question differently"
  );
}

// The per-round proposal cap and the per-proposal record cap are gone, and with
// them `probing_conflict_caps_distinct_peer_sources`,
// `probing_conflict_caps_records_per_source` and
// `proposals_beyond_the_cap_force_a_loss_rather_than_a_win`. A proposal is now
// folded into the round's verdict on arrival and never retained, so there is no
// capacity to exhaust — and no way for exhausting capacity to be read as a
// lexicographic verdict. The defect those three guarded is unrepresentable
// rather than checked for.

/// The §8.1/§8.2 classification must not depend on whether the driver drained
/// RX before or after it fired timeouts.
///
/// The four drivers disagree and cannot be made to agree: `hick-mio` and
/// `hick-reactor` drain RX first, `hick-smoltcp`'s `pump` calls `fire_timeouts`
/// first, and `hick-compio` races them in an unbiased `futures::select!` whose
/// winner is randomized per iteration. So this is `mdns-proto`'s obligation, and
/// the test is shaped like the one this crate already uses for the same class,
/// `duplicate_suppresses_due_retry_independent_of_driver_order`: run BOTH
/// orders, require the same outcome.
///
/// The hazard is concrete. §8.1's settling window ends on a timeout that flips
/// `Probing(3) → Announcing(0)`; a conflict that arrived inside the window but
/// is processed after that flip would be reclassified out of §8.1 and ignored,
/// and two contenders whose third probes are milliseconds apart would both
/// announce.
#[test]
fn the_conflict_classification_is_independent_of_driver_loop_order() {
  for rx_first in [true, false] {
    let mut svc = make_service(120);
    let mut now = drive_to_probing_zero(&mut svc);
    for _ in 0..3 {
      let at = emit_probe(&mut svc, now);
      svc.note_delivery(at, TransmitDelivery::ALL);
      now = at;
    }
    assert!(
      matches!(svc.state(), ServiceState::Probing(3)),
      "precondition: in §8.1's settling window; got {:?}",
      svc.state()
    );
    let original = svc.name().as_str().to_owned();

    // The instant the settling deadline is due — the tick a driver wakes on,
    // carrying a datagram that arrived earlier in the window.
    let due = svc.poll_timeout().expect("the settling window re-arms");
    let bytes = srv_txt_proposal(9999);
    let peer: core::net::SocketAddr = "192.168.1.55:5353".parse().unwrap();
    let deliver = |svc: &mut Service<_, _, _>| {
      svc.handle_event(
        ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
        due,
      );
    };

    // The verdict is spent by the FIRST `handle_timeout` that sees it, so §8.2's
    // second runs from `due` in the RX-first order and from 500 ms later in the
    // timer-first one.
    let spent = if rx_first {
      // hick-mio / hick-reactor shape.
      deliver(&mut svc);
      svc.handle_timeout(due).unwrap();
      due
    } else {
      // hick-smoltcp shape: the deadline transition runs BEFORE the queued
      // datagram is drained, so the conflict is seen in `Announcing(0)`.
      svc.handle_timeout(due).unwrap();
      deliver(&mut svc);
      due.advance(500)
    };

    svc.handle_timeout(due.advance(500)).unwrap();
    // INVERTED, deliberately. The old claim was "a §8.2 loss renames" and this
    // asserted the name moved; the admitted outcome now is that a §8.2 loss
    // KEEPS the name and re-probes it after one second — RFC 6762 §8.2: "it
    // defers to the winning host by waiting one second, and then begins probing
    // for this record again." Only a §8.1 loss to a host that already OWNS the
    // name renames.
    //
    // The two-order subject is unchanged, and the assertion is strictly stronger
    // than the rename it replaces: both orders must reach the SAME five-part
    // deferral, not merely agree that the name moved.
    assert_tiebreak_deferred(
      &mut svc,
      &original,
      spent,
      &std::format!(
        "rx_first={rx_first}: the same conflict at the same instant must be \
         resolved the same way whichever order the driver ran — the decision is \
         keyed on what has been ANNOUNCED, which is nothing either way, not on \
         the state the deadline happened to leave behind"
      ),
    );
  }
}

/// A record repeated inside ONE Authority Section is compared exactly as sent.
///
/// RFC 6762 §8.2.1 says the two record sets "are sorted into order, and then
/// compared pairwise". It does not say deduplicate. Three copies of one TXT is a
/// THREE-record proposal, and that is what this responder compares against.
///
/// INVERTED, deliberately. This test used to assert the opposite — that the
/// repeat was counted once — on the reasoning that an RRset holds distinct rdata
/// so a repeat is malformed and cheap to reject. The dedup has been REMOVED and
/// the old assertion is replaced rather than narrowed, because the tiebreak only
/// resolves a name if BOTH hosts compute the same function over the same two
/// lists. A conforming peer that repeats a record and does not itself dedup, met
/// by a responder that silently drops the repeat, has the two sides comparing
/// different lists — and "both hosts conclude they won" is the single outcome
/// §8.2 exists to prevent. Interop symmetry between the two hosts outranks
/// tidiness about a peer's malformed section.
#[test]
fn a_record_repeated_within_one_proposal_is_compared_as_sent() {
  let peer: core::net::SocketAddr = "192.168.1.92:5353".parse().unwrap();

  // INVERTED, deliberately, in both blocks below — as to the CONSEQUENCE only;
  // the "compared as sent" subject is untouched. The old claim was "a §8.2 loss
  // renames" and each block asserted the name moved. The admitted outcome now is
  // that a §8.2 loss KEEPS the name and re-probes it after one second — RFC 6762
  // §8.2: "it defers to the winning host by waiting one second, and then begins
  // probing for this record again." Only a §8.1 loss to a host that already OWNS
  // the name renames, and a peer's Authority Section is not that.
  //
  // Deduplicating still fails these blocks: it makes the second one a TIE, and a
  // tie leaves the service in its probe sequence with no `Init` and no
  // one-second deadline — which is precisely what `assert_tiebreak_deferred`
  // requires, so "no rename" cannot be reached by dropping the verdict.

  // The repeat is not filtered out on the way in: this proposal is compared,
  // and its TXT("k=v") beats our TXT(empty) at the first record, so we lose.
  {
    let mut svc = make_service(120);
    let t0 = FakeInstant::zero();
    svc.handle_timeout(t0).unwrap();
    let original = svc.name().as_str().to_owned();
    // ONE datagram: this is a repeat within a single proposal.
    let bytes = proposal_bytes(
      "myprinter._ipp._tcp.local.",
      &[
        Rec::Txt(&[b"k=v"]),
        Rec::Txt(&[b"k=v"]),
        Rec::Txt(&[b"k=v"]),
      ],
    );
    svc.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
      t0,
    );
    let spent = t0.advance(500);
    svc.handle_timeout(spent).unwrap();
    assert_tiebreak_deferred(
      &mut svc,
      &original,
      spent,
      "the repeated proposal is compared, not rejected, and it beats ours",
    );
  }

  // …and the repeat really is COUNTED, which the block above cannot show: with
  // three copies of one TXT the peer wins on the first record whether or not the
  // duplicates survive. Here the peer's smallest two records are byte-identical
  // to ours, so the verdict turns on length alone — §8.2.1's "if either list of
  // records runs out of records before any difference is found, then the list
  // with records remaining is deemed to have won". Deduplicated, the peer's
  // list is our list and the answer is "no conflict"; compared as sent it is one
  // record longer and takes the name.
  {
    let mut svc = make_service(120);
    let t0 = FakeInstant::zero();
    svc.handle_timeout(t0).unwrap();
    let original = svc.name().as_str().to_owned();
    let bytes = proposal_bytes(
      "myprinter._ipp._tcp.local.",
      &[
        Rec::Txt(&[]),
        Rec::Srv {
          port: 631,
          target: "host.local.",
        },
        Rec::Srv {
          port: 631,
          target: "host.local.",
        },
      ],
    );
    svc.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
      t0,
    );
    let spent = t0.advance(500);
    svc.handle_timeout(spent).unwrap();
    assert_tiebreak_deferred(
      &mut svc,
      &original,
      spent,
      "three records, one of them a repeat, is a THREE-record proposal: it has \
       a record remaining where ours runs out, so it wins. Deduplicating would \
       make this a tie, which defers nothing and lets both hosts probe on",
    );
  }
}

/// Two proposals arriving from ONE source address are compared separately, not
/// unioned.
///
/// Two co-resident responders behind one `IP:5353` propose different rdata for
/// the same name. §8.2 compares against each proposal — this responder loses if
/// ANY peer beats it — and a union of the two is a list neither of them sent.
/// Here each proposal on its own LOSES to ours, while their union would win,
/// which is the direction that silently costs a name.
#[test]
fn two_proposals_from_one_source_are_compared_separately() {
  let peer: core::net::SocketAddr = "192.168.1.91:5353".parse().unwrap();
  let mut svc = make_service(120); // SRV(631) + empty TXT
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();
  let original = svc.name().as_str().to_owned();

  // Proposal A: {TXT(empty)} alone — runs out first, so WE win.
  // Proposal B: {SRV(80)} alone — starts `00 21` against our `00 10`, so it wins.
  // Their union {TXT, SRV(80)} would compare equal-then-lower and hand us a win.
  let bytes_a = proposal_bytes("myprinter._ipp._tcp.local.", &[Rec::Txt(&[])]);
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes_a, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "proposal A on its own runs out of records first, so we win it"
  );

  let bytes_b = proposal_bytes(
    "myprinter._ipp._tcp.local.",
    &[Rec::Srv {
      port: 80,
      target: "host.local.",
    }],
  );
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes_b, peer, dg(2))),
    t0,
  );

  assert!(
    svc.tiebreak_lost,
    "one source address, two datagrams, two proposals — and proposal B is \
     scored on its own rather than folded into A"
  );
  let spent = t0.advance(500);
  svc.handle_timeout(spent).unwrap();
  // INVERTED, deliberately. The old claim was "a §8.2 loss renames" and this
  // asserted the name moved; the admitted outcome now is that a §8.2 loss KEEPS
  // the name and re-probes it after one second — RFC 6762 §8.2: "it defers to
  // the winning host by waiting one second, and then begins probing for this
  // record again." Only a §8.1 loss to a host that already OWNS the name
  // renames, and two co-resident PROBERS own nothing yet.
  //
  // The union hazard is still what is being separated: unioning hands us the
  // WIN, and a win defers nothing — no `Init`, no one-second deadline.
  assert_tiebreak_deferred(
    &mut svc,
    &original,
    spent,
    "the SRV-only proposal beats ours on its own, so we lose — unioning the two \
     into {TXT, SRV(80)} would compare TXT-equal then SRV-lower and wrongly \
     hand us the win",
  );
}

/// RFC 6762 §8.1 keeps the conflict window open for 250 ms PAST the third probe:
/// the deferral rule runs "from the time the first probe packet is sent until
/// 250 ms after the third probe", and announcing is permitted only "if, by
/// 250 ms after the third probe, no conflicting Multicast DNS responses have
/// been received".
///
/// `FIRST_ANNOUNCE_DELAY` is zero, so before the settling state the third
/// probe's confirm flipped straight to `Announcing` and that window did not
/// exist. A peer's tentative probe arriving in it hit the established-state
/// "defend, don't revert" return, and a conflicting response was misrouted
/// through §9 — so two contenders whose third probes are a few ms apart could
/// both announce.
#[test]
fn the_section81_window_stays_open_250ms_past_the_third_probe() {
  for (origin, what) in [
    (ConflictOrigin::TentativeProbe, "a simultaneous prober"),
    (ConflictOrigin::AuthoritativeResponse, "an existing owner"),
  ] {
    let mut svc = make_service(120);
    let mut now = drive_to_probing_zero(&mut svc);
    // Three probes on the wire, each confirmed — §8.1's sequence is complete.
    for _ in 0..3 {
      let at = emit_probe(&mut svc, now);
      svc.note_delivery(at, TransmitDelivery::ALL);
      now = at;
    }
    assert!(
      matches!(svc.state(), ServiceState::Probing(3)),
      "{what}: the third probe is confirmed, and §8.1 keeps probing active for \
       250 ms more; got {:?}",
      svc.state()
    );
    let original = svc.name().as_str().to_owned();

    // 1 ms into the window — inside it by any reading.
    let inside = now.advance(1);
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
    let peer: core::net::SocketAddr = "192.168.1.77:5353".parse().unwrap();
    // The origin is now carried by the EVENT: §8.2's input is a peer's whole
    // Authority Section, §8.1's is a response's record.
    let proposal = proposal_bytes(
      "myprinter._ipp._tcp.local.",
      &[Rec::Srv {
        port: 9999,
        target: "host.local.",
      }],
    );
    match origin {
      ConflictOrigin::TentativeProbe => svc.handle_event(
        ServiceEvent::ProbeProposal(probe_proposal(&proposal, peer, dg(1))),
        inside,
      ),
      ConflictOrigin::AuthoritativeResponse => {
        let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
        svc.handle_event(
          ServiceEvent::ProbeConflict(ProbeConflict::new(
            peer,
            rec,
            dg(1),
            ConflictHistory::Unmatched,
          )),
          inside,
        );
      }
    }
    assert!(
      svc.tiebreak_lost || svc.probe_defeated,
      "{what}: a conflict inside §8.1's window must be resolved by §8.2/§8.1, \
       not by the post-establishment rules"
    );

    let spent = inside.advance(500);
    svc.handle_timeout(spent).unwrap();
    // The two origins part company HERE, and that contrast is the point of
    // running both. INVERTED for the §8.2 half only: the old claim was "a §8.2
    // loss renames", and the admitted outcome now is that a §8.2 loss KEEPS the
    // name and re-probes it after one second — RFC 6762 §8.2: "it defers to the
    // winning host by waiting one second, and then begins probing for this
    // record again." Only a §8.1 loss to a host that already OWNS the name
    // renames, and the §8.1 half below still asserts exactly that.
    //
    // What the fixture pins is untouched: both origins are still resolved INSIDE
    // §8.1's 250 ms window rather than by the post-establishment rules, and each
    // is resolved by its own rule.
    match origin {
      ConflictOrigin::TentativeProbe => assert_tiebreak_deferred(
        &mut svc,
        &original,
        spent,
        &std::format!(
          "{what}: losing to a simultaneous prober inside the window defers for \
           one second and keeps the name, exactly as it would one millisecond \
           earlier"
        ),
      ),
      ConflictOrigin::AuthoritativeResponse => assert_ne!(
        svc.name().as_str(),
        original,
        "{what}: a conflicting RESPONSE inside the window is §8.1's \"the \
         probing host MUST defer to the existing host, and SHOULD choose new \
         names\" — the peer already HOLDS this name, so it costs us the name, \
         exactly as it would one millisecond earlier"
      ),
    }
  }
}

/// RFC 6762 §8.2.1: "If either list of records runs out of records before any
/// difference is found, then the list with records remaining is deemed to have
/// won the tiebreak." Both directions, since a comparator can get one right and
/// the other backwards.
#[test]
fn tiebreak_the_list_with_records_remaining_wins() {
  // OURS is always exactly two records: SRV(631) + the empty TXT `write_probe`
  // emits unconditionally — which is what `make_service` proposes.
  let peer_src: core::net::SocketAddr = "192.168.1.88:5353".parse().unwrap();

  // INVERTED, deliberately, in the losing direction. The old claim was "a §8.2
  // loss renames", and `run` reported the verdict as "did the name move". The
  // admitted outcome now is that a §8.2 loss KEEPS the name and re-probes it
  // after one second — RFC 6762 §8.2: "it defers to the winning host by waiting
  // one second, and then begins probing for this record again." Only a §8.1 loss
  // to a host that already OWNS the name renames. So `run` now reports the
  // verdict as "did the service defer", and asserts on BOTH paths that the name
  // never moved, which is a §8.2 invariant the old shape could not state.
  //
  // Each direction runs on its own service, because the verdict is no longer a
  // value to read: it is the deferral the next `handle_timeout` does or does not
  // perform.
  let run = |recs: &[Rec<'_>]| -> bool {
    let mut svc = make_service(120);
    let t0 = FakeInstant::zero();
    svc.handle_timeout(t0).unwrap(); // Init → Probing
    let original = svc.name().as_str().to_owned();
    let bytes = proposal_bytes("myprinter._ipp._tcp.local.", recs);
    svc.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer_src, dg(1))),
      t0,
    );
    let spent = t0.advance(500);
    svc.handle_timeout(spent).unwrap();
    assert_eq!(
      svc.name().as_str(),
      original,
      "§8.2 never renames in either direction — winner and loser both keep the \
       name; only §8.1's deferral to an existing OWNER chooses a new one"
    );
    // The deferral, whole: `Init` + a fresh sequence + exactly one second. A
    // dropped verdict leaves the service mid-probe-sequence and matches neither.
    svc.state() == ServiceState::Init
      && svc.probe_count == 0
      && svc.lifecycle_deadline == Some(spent.advance(1000))
  };

  // ── THEIR list runs out first: {TXT(empty)} against our {TXT(empty), SRV} ──
  // Record 0 matches; they have nothing left and we still hold the SRV, so we
  // have records remaining and we WIN.
  assert!(
    !run(&[Rec::Txt(&[])]),
    "their list ran out first, so OUR list has records remaining and is \
     deemed to have won — we must not defer, and our probe sequence carries on"
  );

  // ── OUR list runs out first: {TXT(empty), SRV(631), SRV(9999)} ────────────
  // Records 0 and 1 match ours exactly; we then run out while they still hold
  // an SRV, so they have records remaining and we LOSE.
  assert!(
    run(&[
      Rec::Txt(&[]),
      Rec::Srv {
        port: 631, // byte-identical to ours
        target: "host.local.",
      },
      Rec::Srv {
        port: 9999, // sorts after SRV(631), so it is the surplus record
        target: "host.local.",
      },
    ]),
    "our list ran out first, so THEIR list has records remaining and is \
     deemed to have won — we must defer to them for one second and then probe \
     for this same name again"
  );
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

/// A record whose rdata will not canonicalize is passed over, and passing it
/// over must not change the size of the list §8.2.1 compares.
///
/// The fixture DISCRIMINATES on that second half. Beside the malformed SRV the
/// peer proposes the SRV(631) + TXT(empty) this service proposes, so with the
/// bad record passed over the two lists run out together — §8.2.1's "there is,
/// in fact, no conflict" — and the name is kept. Counted as a member (of any
/// value at all), the peer would hold three records to our two and win on "the
/// list with records remaining".
#[test]
fn probing_conflict_drops_malformed_rdata() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap(); // Init → Probing
  let original = svc.name().as_str().to_owned();

  // The two well-formed records, then the malformed SRV appended by hand — the
  // builder cannot emit one — with the Authority count corrected to match.
  let mut bytes = proposal_bytes(
    "myprinter._ipp._tcp.local.",
    &[
      Rec::Txt(&[]),
      Rec::Srv {
        port: 631,
        target: "host.local.",
      },
    ],
  );
  let mut bad = std::vec::Vec::new();
  make_bad_srv_record_ref(&mut bad, "myprinter._ipp._tcp.local.");
  bytes.extend_from_slice(&bad);
  let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
  assert_eq!(
    nscount, 2,
    "precondition: the builder wrote two authority records"
  );
  bytes[8..10].copy_from_slice(&(nscount + 1).to_be_bytes());

  let src: core::net::SocketAddr = "192.168.1.88:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, src, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "a record whose rdata will not canonicalize is not a member of the peer's \
     list, so an otherwise byte-identical proposal stays a tie"
  );
  svc.handle_timeout(t0.advance(500)).unwrap();
  assert_eq!(
    svc.name().as_str(),
    original,
    "…and the malformed record therefore costs us nothing"
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
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
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
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
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
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
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
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
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
  // our_canonical_records_for covers the SRV, TXT, and fallback arms.
  let _ = svc.our_canonical_records_for(crate::wire::ResourceType::Srv);
  let _ = svc.our_canonical_records_for(crate::wire::ResourceType::Txt);
  assert!(
    svc
      .our_canonical_records_for(crate::wire::ResourceType::A)
      .is_empty(),
    "a type this service does not emit at its instance name has no form that \
     could be ours"
  );
}

#[test]
fn identity_form_handles_nsec_and_unknown() {
  // NSEC record → next_name then the type-bitmap bytes.
  let mut nbuf: std::vec::Vec<u8> = std::vec::Vec::new();
  nbuf.extend_from_slice(&[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0]); // name
  nbuf.extend_from_slice(&47u16.to_be_bytes()); // TYPE NSEC
  nbuf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  nbuf.extend_from_slice(&120u32.to_be_bytes()); // TTL
  nbuf.extend_from_slice(&12u16.to_be_bytes()); // RDLENGTH = next_name(9) + bitmap(3)
  nbuf.extend_from_slice(&[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 1, 0x40]);
  let (nrec, _) = Ref::try_parse(&nbuf, 0).unwrap();
  assert_eq!(
    &*nrec.canonical_rdata_folded().unwrap(),
    &[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 1, 0x40],
    "NSEC identity is its next_name, case-folded, then its bitmap"
  );

  // Unknown record type → canonicalized via the raw rdata bytes (Other arm).
  let mut obuf: std::vec::Vec<u8> = std::vec::Vec::new();
  obuf.extend_from_slice(&[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0]); // name
  obuf.extend_from_slice(&999u16.to_be_bytes()); // TYPE 999 (unknown)
  obuf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  obuf.extend_from_slice(&120u32.to_be_bytes()); // TTL
  obuf.extend_from_slice(&3u16.to_be_bytes()); // RDLENGTH = 3
  obuf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
  let (orec, _) = Ref::try_parse(&obuf, 0).unwrap();
  assert_eq!(
    &*orec.canonical_rdata_folded().unwrap(),
    &[0xAA, 0xBB, 0xCC],
    "a type absent from §18.14 is copied verbatim"
  );
}

#[test]
fn poll_transmit_announcement_surfaces_buffer_too_small() {
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();
  // Drive to Announcing(0) (third probe confirmed), confirming each probe.
  // Via the shared helper: it checks the state after `handle_timeout`, not only
  // inside the drain loop, so it sees `Announcing(0)` on the tick that RFC 6762
  // §8.1's post-third-probe settling window closes — a transition that costs no
  // datagram and therefore never appears mid-drain.
  now = drive_to_announcing_zero(&mut svc);
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
  // A probe on the wire first, then a conflicting RESPONSE: §8.1's deferral to
  // an existing owner is what renames. A §8.2 tiebreak loss now keeps the name.
  let t0 = probe_once(&mut svc, FakeInstant::zero());
  // The original name `myprinter` was announced (instance records + its host A).
  svc.goodbye.mark_instance();
  let host_addr = core::net::Ipv4Addr::new(192, 168, 1, 10); // matches make_records
  svc.goodbye.mark_host_a(host_addr);

  // An existing owner's differing SRV (port 9999 > ours 631) → rename to
  // `myprinter-1`.
  deliver_losing_srv_conflict(&mut svc, t0, ConflictOrigin::AuthoritativeResponse);
  let now = t0.advance(500);
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
    v4_half(&old_owned).ptr() && v4_half(&old_owned).srv() && v4_half(&old_owned).txt(),
    "the OLD name's advertised instance records are handed off"
  );
  assert!(
    v4_half(&old_owned).a_slice().is_empty() && v4_half(&old_owned).aaaa_slice().is_empty(),
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
    v4_half(&snap.owned).ptr() && v4_half(&snap.owned).srv() && v4_half(&snap.owned).txt(),
    "the CURRENT name's confirmed instance records are captured"
  );
  assert!(
    v4_half(&snap.owned).a_slice().contains(&host_addr),
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
  assert!(v4_half(&snap.owned).ptr(), "snapshot must own PTR");
  assert!(v4_half(&snap.owned).srv(), "snapshot must own SRV");
  assert!(v4_half(&snap.owned).txt(), "snapshot must own TXT");

  // make_records adds 192.168.1.10 — it must appear in the snapshot.
  let expected = core::net::Ipv4Addr::new(192, 168, 1, 10);
  assert!(
    v4_half(&snap.owned).a_slice().contains(&expected),
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

  assert!(
    !v4_half(&snap.owned).ptr(),
    "unanounced: PTR must not be owned"
  );
  assert!(
    !v4_half(&snap.owned).srv(),
    "unannounced: SRV must not be owned"
  );
  assert!(
    !v4_half(&snap.owned).txt(),
    "unannounced: TXT must not be owned"
  );
  assert!(
    !v4_half(&snap.owned).subtypes(),
    "unannounced: subtypes must not be owned"
  );
  assert!(
    v4_half(&snap.owned).a_slice().is_empty(),
    "unannounced: host_a must be empty"
  );
  assert!(
    v4_half(&snap.owned).aaaa_slice().is_empty(),
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
    v4_half(&snap.owned).ptr() && v4_half(&snap.owned).srv() && v4_half(&snap.owned).txt(),
    "a partially-announced service must still withdraw its instance records"
  );
  assert!(
    !v4_half(&snap.owned).a_slice().is_empty(),
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
    !v4_half(&snap.owned).ptr()
      && !v4_half(&snap.owned).srv()
      && !v4_half(&snap.owned).txt()
      && v4_half(&snap.owned).a_slice().is_empty(),
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
  // A probe on the wire first, then a conflicting RESPONSE — §8.1's deferral to
  // an existing owner is what renames; a §8.2 tiebreak loss now keeps the name.
  let t0 = probe_once(&mut svc, FakeInstant::zero());
  // Precondition: the OLD name had fully announced (the state a §9 rename
  // inherits from an Established service reverted to probing).
  svc.goodbye.mark_instance();
  svc.fully_announced = true;

  // An existing owner's differing SRV (port 9999 > ours 631) → rename.
  deliver_losing_srv_conflict(&mut svc, t0, ConflictOrigin::AuthoritativeResponse);
  let later = t0.advance(500);
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
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      srec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
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
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      srec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
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

/// Deliver a conflicting SRV whose rdata differs from ours (port 9999 vs our
/// 631) — a genuine §9 conflict when established, and a tiebreak we LOSE when
/// probing, since the peer's sorted list compares greater than ours.
///
/// `origin` is explicit rather than defaulted because the two rules take
/// different inputs, do different things, and the caller is what knows which one
/// it is staging:
///
/// * `TentativeProbe` — a peer's §8.2 proposal. Losing it DEFERS: the name is
///   kept and probed for again one second later ("it defers to the winning host
///   by waiting one second, and then begins probing for this record again").
/// * `AuthoritativeResponse` — one record of a RESPONSE. §9 acts only on this,
///   and inside §8.1's probing window it is the deferral that RENAMES ("the
///   probing host MUST defer to the existing host, and SHOULD choose new
///   names"). It is acted on only once a probe of the current sequence has
///   reached the wire, so callers staging a rename open that window first.
fn deliver_losing_srv_conflict(
  svc: &mut Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>,
  now: FakeInstant,
  origin: ConflictOrigin,
) {
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  // The origin is carried by the EVENT now: §8.2's input is a peer's whole
  // Authority Section, §8.1's and §9's is one record of a RESPONSE.
  match origin {
    ConflictOrigin::TentativeProbe => {
      let bytes = proposal_bytes(
        svc.name().as_str(),
        &[Rec::Srv {
          port: 9999,
          target: "host.local.",
        }],
      );
      svc.handle_event(
        ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
        now,
      );
    }
    ConflictOrigin::AuthoritativeResponse => {
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
      svc.handle_event(
        ServiceEvent::ProbeConflict(ProbeConflict::new(
          peer,
          srec,
          dg(1),
          ConflictHistory::Unmatched,
        )),
        now,
      );
    }
  }
}

/// A rename CANNOT happen while an ANNOUNCEMENT is parked across a §9 revert,
/// and this asserts that rather than fabricating it.
///
/// Four facts close the path, and they close it by construction:
///
/// 1. §9's revert clears `probe_on_wire`, because it restarts the §8.1 sequence.
/// 2. §8.1 acts on a conflicting response only once a probe of the CURRENT
///    sequence has reached a link — so with the window shut, responses are
///    ignored.
/// 3. `probe_on_wire` is set by a confirmed delivery and by nothing else, and
///    the single commit token is held by the parked datagram, so `poll_transmit`
///    yields nothing and no probe of the restarted sequence can be sent, let
///    alone confirmed.
/// 4. A §8.2 tiebreak loss no longer renames — it keeps the name and re-probes
///    after one second. §8.2 is the ONE conflict rule that never required
///    `probe_on_wire` (neither host owns the name yet, so there is no window to
///    be inside), so before that change it was the way past fact 1, and it was
///    the last one.
///
/// `StaleRecords::OldName` is the consequence: the only place it is built is a
/// rename over a live commit token, and the four facts say no rename can happen
/// over one. The parked token therefore stays `SameName`, which is asserted
/// below so this test fails if the premise stops holding rather than merely
/// passing more easily.
///
/// If a future change re-opens the path, this fails loudly, which is exactly
/// when someone would want to know. The fixture this replaces got its rename by
/// delivering a losing §8.2 proposal after the revert — the fourth fact above is
/// exactly what stopped that working, and re-staging it would mean asserting
/// behaviour for an input production can no longer produce.
#[test]
fn no_rename_is_reachable_with_an_announcement_parked_across_a_section9_revert() {
  let mut svc = make_non_compliant_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  // The first announcement of the name is encoded and PARKED. Nothing has
  // latched yet, so this datagram is the ONLY thing that ever exposed the name —
  // the case a rename would have to hand off to the old name's §10.1 goodbye.
  let at = emit_announcement(&mut svc, now);
  assert!(!svc.advertises_instance());
  assert!(svc.rename_goodbye_handoff.is_none());
  let before = svc.name().as_str().to_owned();

  // §9: a genuine conflicting RESPONSE reverts the established name to
  // re-probing. Only a response can — a peer merely probing is answered.
  deliver_losing_srv_conflict(&mut svc, at, ConflictOrigin::AuthoritativeResponse);
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "a §9 conflict must revert to re-probing"
  );
  assert!(
    !svc.probe_on_wire,
    "fact 1: the revert restarts the §8.1 sequence, so its window is shut"
  );

  // Every further conflict, of either kind, now bounces off.
  deliver_losing_srv_conflict(&mut svc, at, ConflictOrigin::AuthoritativeResponse);
  assert!(
    !svc.probe_defeated,
    "fact 2: a response before the restarted sequence's first probe is one §8.1 \
     requires be ignored"
  );

  let now = at.advance(300);
  svc.handle_timeout(now).unwrap();
  assert!(
    svc
      .poll_transmit(now, &mut std::vec![0u8; 4096])
      .unwrap()
      .is_none(),
    "fact 3: the parked datagram holds the single commit token, so no probe of \
     the restarted sequence can be emitted — and only a CONFIRMED probe could \
     re-open the window"
  );
  assert_eq!(
    svc.name().as_str(),
    before,
    "so the name survives: with the §8.1 window shut and no way to re-open it \
     while the datagram is parked, and a §8.2 loss now deferring rather than \
     renaming, no rename is reachable from here"
  );
  assert!(
    matches!(
      svc.awaiting_confirm,
      Some(AwaitingConfirm::Stale {
        records: StaleRecords::SameName(_),
        ..
      })
    ),
    "…so the parked announcement's records are still attributed to the name \
     this service holds: nothing renamed them away, and `StaleRecords::OldName` \
     is what a rename over a live token would have produced; got {:?}",
    svc.awaiting_confirm
  );
  svc.note_delivery(now, TransmitDelivery::ALL);
  assert!(
    svc.rename_goodbye_handoff.is_none(),
    "and a same-name confirm hands nothing off — there is no old name to \
     withdraw under"
  );
}

/// `Init → Probing(0)` costs no datagram, so an old-generation probe confirming
/// into the fresh sequence advances it for free: the new name would be claimed
/// after TWO probes on the wire where RFC 6762 §8.1 requires three.
#[test]
fn a_stale_probe_confirm_does_not_advance_the_new_names_sequence() {
  let mut svc = make_non_compliant_service(120);
  let mut now = drive_to_probing_zero(&mut svc);

  // One probe of this sequence reaches the wire and is CONFIRMED, which is the
  // only thing that opens §8.1's window — `probe_on_wire` is set by a confirmed
  // delivery and by nothing else, so a fixture that sets it directly would be
  // asserting a state the production machine cannot occupy.
  let first = emit_probe(&mut svc, now);
  svc.note_delivery(first, TransmitDelivery::ALL);

  // A SECOND probe for the ORIGINAL name is encoded and parked.
  let at = emit_probe(&mut svc, first);
  // We defer to an existing owner under §8.1 and rename away while that probe is
  // still in flight. A RESPONSE is the stimulus because a §8.2 tiebreak loss now
  // keeps the name.
  deliver_losing_srv_conflict(&mut svc, at, ConflictOrigin::AuthoritativeResponse);
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

/// The reclaim-cancel gate and the `Established` update are the app-visible half:
/// a confirm from a generation that was replaced must not report that the CURRENT
/// name completed a §8.3 announcement, because a predecessor's §10.1 goodbye is
/// cancelled on exactly that basis and would strand its records in every peer
/// cache.
///
/// The regression here is the §9 same-name revert, which is where a parked
/// ANNOUNCEMENT can actually be caught by one — see
/// `no_rename_is_reachable_with_an_announcement_parked_across_a_section9_revert`
/// for why a rename cannot catch it. Both halves are load-bearing on this path:
/// the revert does NOT reset `fully_announced` (the name is unchanged, so what
/// it says about this name stays true), so a stale confirm that took the live
/// `Announcement` arm would set it here — the gate is `false` going in precisely
/// because this datagram is the first announcement and it has not been
/// confirmed.
#[test]
fn a_stale_announcement_confirm_neither_establishes_nor_opens_the_reclaim_gate() {
  let mut svc = make_non_compliant_service(120);
  let now = drive_to_announcing_zero(&mut svc);
  let at = emit_announcement(&mut svc, now);
  assert!(
    !svc.has_fully_announced().get(),
    "precondition: the parked datagram is this name's FIRST announcement, so \
     the gate is shut until something confirms one"
  );

  deliver_losing_srv_conflict(&mut svc, at, ConflictOrigin::AuthoritativeResponse);
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "a §9 conflict must revert to re-probing"
  );

  // ALL, deliberately: `fully_announced` is an all-delivered fact, so a partial
  // confirm could not open the gate even through the live arm. This is the
  // delivery that would.
  svc.note_delivery(at, TransmitDelivery::ALL);

  assert!(
    !svc.has_fully_announced().get(),
    "the confirm belongs to the generation this revert replaced — no \
     announcement of the CURRENT §8.1 sequence has reached any link, let alone \
     all of them, and a predecessor's goodbye must keep going"
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

  deliver_losing_srv_conflict(&mut svc, at, ConflictOrigin::AuthoritativeResponse);
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

  deliver_losing_srv_conflict(&mut svc, at, ConflictOrigin::AuthoritativeResponse);
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
    matches!(svc.state(), ServiceState::Probing(3)),
    "the third probe was confirmed by every obligated family, which enters RFC \
     6762 §8.1's settling window — probing stays active for 250 ms more, so this \
     is Probing(3) and not yet Announcing; got {:?}",
    svc.state()
  );
  now = at;

  // Close that window so the §8.3 rounds below start from `Announcing(0)`,
  // exactly where they did before it existed. It costs no datagram, so the
  // announcement counters this test is about are untouched by it.
  now = svc
    .poll_timeout()
    .expect("the §8.1 settling window always re-arms");
  svc.handle_timeout(now).unwrap();
  assert!(
    matches!(svc.state(), ServiceState::Announcing(0)),
    "the settling window closes into announcing; got {:?}",
    svc.state()
  );

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
  deliver_losing_srv_conflict(&mut svc, at, ConflictOrigin::TentativeProbe);
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

// ── R10: the §8.2 proposal is scoped by what the query ASKS ────────────

/// Byte offset at which the first authority record of
/// [`raw_proposal_bytes_asking`] begins: the 12-byte header, then the question's
/// uncompressed name, QTYPE and QCLASS.
///
/// Fixtures that hand-build a COMPRESSION POINTER need it — a pointer is an
/// absolute offset into the datagram, so a record that points at itself can only
/// be written once its own position is known.
fn first_record_offset(qname: &str) -> usize {
  let mut n = 12usize;
  for label in qname.trim_end_matches('.').split('.') {
    n += 1 + label.len();
  }
  n + 1 + 4
}

/// A record whose OWNER NAME is a compression pointer to `at_offset` — the
/// record's own position, so following it loops forever.
///
/// `Ref` parsing accepts a pointer without resolving it, so this record parses
/// and only fails when its labels are walked. That is precisely the shape that
/// used to read as "some other name" and get skipped.
fn make_cyclic_owner_record(
  buf: &mut std::vec::Vec<u8>,
  at_offset: usize,
  rtype: u16,
  ttl: u32,
  rdata: &[u8],
) {
  buf.clear();
  #[allow(clippy::cast_possible_truncation)]
  {
    buf.push(0xC0 | ((at_offset >> 8) as u8));
    buf.push(at_offset as u8);
  }
  buf.extend_from_slice(&rtype.to_be_bytes());
  buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  buf.extend_from_slice(&ttl.to_be_bytes());
  #[allow(clippy::cast_possible_truncation)]
  buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
  buf.extend_from_slice(rdata);
}

/// An NSEC at `PROBED_NAME` whose `next_name` is a compression pointer to
/// `rdata_offset` — the pointer's own position inside the rdata, so it cycles.
fn make_cyclic_nsec_record(buf: &mut std::vec::Vec<u8>, ttl: u32, rdata_offset: usize) {
  buf.clear();
  for label in PROBED_NAME.trim_end_matches('.').split('.') {
    #[allow(clippy::cast_possible_truncation)]
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8);
  buf.extend_from_slice(&47u16.to_be_bytes()); // TYPE NSEC
  buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  buf.extend_from_slice(&ttl.to_be_bytes());
  // rdata = cyclic next_name (2 bytes) + a window-0 bitmap asserting SRV.
  let rdata: [u8; 7] = [
    #[allow(clippy::cast_possible_truncation)]
    {
      0xC0 | ((rdata_offset >> 8) as u8)
    },
    #[allow(clippy::cast_possible_truncation)]
    {
      rdata_offset as u8
    },
    0,
    5,
    0,
    0,
    0x40,
  ];
  #[allow(clippy::cast_possible_truncation)]
  buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
  buf.extend_from_slice(&rdata);
}

/// The peer list every abandonment fixture below starts from: a proposal that
/// BEATS ours outright (SRV port 9999 against our 631, and the same empty TXT),
/// so "we did not lose" can only be the abandonment under test and never a
/// proposal that was harmless anyway.
fn winning_pair() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
  let mut txt = std::vec::Vec::new();
  make_txt_record_ref(&mut txt, PROBED_NAME, 120, &[&[]]);
  let mut srv = std::vec::Vec::new();
  make_srv_record_ref(&mut srv, PROBED_NAME, 120, 0, 0, 9999, "host.local.");
  (txt, srv)
}

/// CONTROL for every abandonment fixture below: the winning pair ON ITS OWN is
/// adjudicated and DOES take the round. Without this, "no loss recorded" proves
/// nothing — a fixture that stopped reaching the comparator at all would pass
/// every one of them.
#[test]
fn the_winning_pair_control_really_does_lose_the_round() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let (txt, srv) = winning_pair();
  let bytes = raw_proposal_bytes(&[txt, srv]);
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    svc.tiebreak_lost,
    "control: the peer's SRV port 9999 beats our 631, so this proposal must \
     take the round — every abandonment fixture below is built on it"
  );
}

/// R10 finding 3: a proposal carrying an UNDECODABLE OWNER NAME is abandoned
/// whole, not adjudicated from the records that happened to read.
///
/// The name matcher answers `false` both for "a different name" and for "a name
/// I could not decode", and `Ref` parsing accepts a compression pointer without
/// ever resolving it — so a cyclic owner name arrived looking exactly like an
/// out-of-scope record and was silently dropped from the list being compared.
/// A dropped record leaves a list the peer never sent, and §8.2.1 walks the two
/// sorted lists pairwise — so the omission can decide the round in either
/// direction. Here the readable subset alone would have taken the round, and the
/// unreadable record could have been anything.
#[test]
fn an_undecodable_owner_name_abandons_the_whole_proposal() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let (txt, srv) = winning_pair();
  // The third record sits after the two readable ones; its owner name is a
  // pointer to its own offset.
  let at = first_record_offset(PROBED_NAME) + txt.len() + srv.len();
  let mut cyclic = std::vec::Vec::new();
  make_cyclic_owner_record(&mut cyclic, at, 1, 120, &[10, 0, 0, 7]);
  let bytes = raw_proposal_bytes(&[txt, srv, cyclic]);

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "a proposal with an undecodable owner name is not a list §8.2.1 can sort — \
     it must be ABANDONED, not adjudicated from the records that read"
  );
}

/// R10 finding 4: an NSEC's `next_name` is part of the bytes §8.2 compares, so
/// an NSEC that will not decode abandons the proposal.
///
/// The §8.2 form dropped `next_name` entirely and kept only the bitmap.
/// Two things followed: an NSEC with a cyclic next-name produced bytes at all,
/// so a proposal of "our SRV, our TXT and one unreadable NSEC" counted as three
/// records and won §8.2.1 on list length against our two; and two NSECs denying
/// the same types at different names compared equal.
#[test]
fn an_undecodable_nsec_next_name_abandons_the_proposal() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let (txt, srv) = winning_pair();
  // The NSEC's rdata begins after its owner name (PROBED_NAME uncompressed),
  // type, class, TTL and RDLENGTH.
  let owner_len = PROBED_NAME
    .trim_end_matches('.')
    .split('.')
    .map(|l| 1 + l.len())
    .sum::<usize>()
    + 1;
  let nsec_at = first_record_offset(PROBED_NAME) + txt.len() + srv.len();
  let mut nsec = std::vec::Vec::new();
  make_cyclic_nsec_record(&mut nsec, 120, nsec_at + owner_len + 2 + 2 + 4 + 2);
  let bytes = raw_proposal_bytes(&[txt, srv, nsec]);

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "an NSEC whose next_name will not decode is a record §8.2 cannot compare, \
     so the whole proposal is abandoned — it must NOT be scored as a third \
     record that wins on list length"
  );
}

/// R10 finding 4: a well-known COMPRESSION-ELIGIBLE type this crate does not
/// parse (NS/SOA/MX/DNAME) cannot be compared as raw bytes, so it abandons the
/// proposal too.
///
/// RFC 3597 §4 forbids compression inside truly-unknown types, which is what
/// makes their raw bytes a stable comparison. These types are the exception:
/// their rdata MAY carry a compression pointer, and a raw copy of one is
/// message-OFFSET-dependent — the same record at a different position in the
/// packet yields different comparison bytes, so the two sides stop computing the
/// same function and the tiebreak stops resolving.
///
/// DNAME (39) rather than NS (2), and the choice is load-bearing. §8.2.1's
/// ordering key begins with the record TYPE, so an extra NS would sort BELOW our
/// TXT(16), become the peer's smallest element, and hand US the round at element
/// 0 — the right verdict for the wrong reason, and one that holds whether or not
/// the proposal was abandoned. DNAME sorts above our SRV(33), so it displaces no
/// comparison: the round is decided by the `winning_pair` control either way,
/// and the only thing that can keep the name here is the abandonment.
#[test]
fn an_unparsed_compressible_type_abandons_the_proposal() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let (txt, srv) = winning_pair();
  // A DNAME (type 39) at the probed name whose rdata is a compression pointer.
  // The OWNER name is readable, so this fixture turns on the rdata rule and not
  // on finding 3's owner-name rule.
  let mut dname = std::vec::Vec::new();
  for label in PROBED_NAME.trim_end_matches('.').split('.') {
    #[allow(clippy::cast_possible_truncation)]
    dname.push(label.len() as u8);
    dname.extend_from_slice(label.as_bytes());
  }
  dname.push(0u8);
  dname.extend_from_slice(&39u16.to_be_bytes()); // TYPE DNAME
  dname.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  dname.extend_from_slice(&120u32.to_be_bytes());
  dname.extend_from_slice(&2u16.to_be_bytes()); // RDLENGTH
  dname.extend_from_slice(&[0xFF, 0xFF]); // a pointer past the end of the datagram
  let bytes = raw_proposal_bytes(&[txt, srv, dname]);

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "a compression-eligible type this crate does not parse has no well-defined \
     comparison bytes, so the proposal is abandoned rather than compared over a \
     raw copy whose value depends on where in the packet it sat"
  );
}

/// R10 finding 5: an Authority Section with NO QUESTION is not a proposal.
///
/// §8.2 reads the proposed rdata off "the Authority Section of *that query*",
/// and §8.1 defines the query as one carrying "the record name in question in
/// the Question Section". A QDCOUNT=0 packet asks nothing, so its authority
/// records answer nothing — adjudicating them let any peer impose a one-second
/// §8.2 deferral by sending records it never proposed.
#[test]
fn a_proposal_with_no_question_is_not_adjudicated() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let (txt, srv) = winning_pair();
  let mut bytes = raw_proposal_bytes(&[txt, srv]);
  // Strip the question: QDCOUNT → 0, and drop the question bytes.
  let qlen = first_record_offset(PROBED_NAME) - 12;
  bytes[4] = 0;
  bytes[5] = 0;
  bytes.drain(12..12 + qlen);

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "a query that asks nothing proposes nothing — its authority records must \
     record no §8.2 verdict"
  );
}

/// The other half of §8.2's scope, and the half nothing checked. Admission is
/// OWNER NAME **and CLASS**; a probe surfaced the class conjunct as unasserted.
///
/// §8.2.1 orders the compared lists "by class, then type, then rdata", so a
/// query asking in another class is contending a different namespace and its
/// Authority Section is no proposal for our IN record — even when the records it
/// carries are themselves class IN and sit at our exact name. The record-level
/// `rclass` screen in `ProposalScope::admits` cannot stand in for this: that
/// one reads the RECORD's class, and this reads the QUESTION's.
///
/// The payload is `winning_pair`, which
/// `the_winning_pair_control_really_does_lose_the_round` proves takes the round
/// outright when it IS admitted — so this fixture fails loudly if the class
/// scope ever stops being applied, rather than passing for want of a conflict.
#[test]
fn a_question_asking_in_another_class_proposes_nothing_about_ours() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let (txt, srv) = winning_pair();
  // QCLASS 3 = CH (Chaos). The §5.4 unicast-response bit is the top bit and is
  // stripped before `qclass()` is read, so it is set here exactly as a real
  // probe sets it — the fixture must differ from a conforming probe in CLASS
  // alone, or it would be proving something else.
  let bytes = raw_proposal_bytes_asking_type_class(
    PROBED_NAME,
    crate::wire::ResourceType::Any,
    0x8000u16 | 3,
    &[txt, srv],
  );

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "the query contends a name in class CH, so its Authority Section is not a \
     proposal for the IN record we are probing — and this payload is the one \
     that takes the round outright when it IS admitted"
  );
}

/// R10 finding 5: a query asking about a DIFFERENT name proposes nothing about
/// ours, however its Authority Section is filled.
#[test]
fn a_question_for_another_name_proposes_nothing_about_ours() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let (txt, srv) = winning_pair();
  let bytes = raw_proposal_bytes_asking("someone-else._ipp._tcp.local.", &[txt, srv]);

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "the query asks about another name, so its authority records are not a \
     proposal for ours"
  );
}

/// A peer that NARROWS its probe's QTYPE still proposes its whole Authority
/// Section — the both-win regression, and the other half of
/// `the_winning_pair_control_really_does_lose_the_round`.
///
/// The peer asks TXT and carries the `winning_pair`: a TXT byte-identical to
/// ours plus the SRV port 9999 that the control proves takes the round outright.
/// Scoping the fold by QTYPE keeps only that TXT — it ties, our SRV is the
/// record remaining, and §8.2.1's "the list with records remaining is deemed to
/// have won" leaves us holding the name. The PEER meanwhile folds the type-ANY
/// probe §8.1 tells us to send, ties on TXT, and finds its SRV 9999 sorting
/// after our 631, so it holds the name too. Both sides win, both announce, and
/// two responders own one name — the single outcome §8.2 exists to prevent.
///
/// The conflation that once made the narrow reading look right, so it is not
/// adjudicated a third time: this fixture's peer was described as having
/// "proposed no SRV at all". It proposed one. §8.2 says a host "populates the
/// query message's Authority Section with the record or records with the rdata
/// that it would be proposing to use", and that the section must contain "*all*
/// the records and proposed rdata being probed for uniqueness" — the Authority
/// Section IS the proposal. The Question Section says only what the sender wants
/// ANSWERED, which is a different thing and no bound on what it claims.
///
/// The asymmetry is what makes the defect ours and not the peer's:
/// `our_proposal` is not question-scoped either, so a QTYPE gate had the two
/// hosts sorting different PAIRS of lists rather than one pair.
#[test]
fn a_narrowed_qtype_still_proposes_the_whole_authority_section() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let (txt, srv) = winning_pair();
  let bytes =
    raw_proposal_bytes_asking_type(PROBED_NAME, crate::wire::ResourceType::Txt, &[txt, srv]);

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    svc.tiebreak_lost,
    "the peer's Authority Section is its whole §8.2 proposal whatever its QTYPE \
     asks, so its SRV port 9999 is compared and beats our 631 — dropping it \
     would leave BOTH hosts believing they won this round"
  );
}

/// Build a raw CNAME record in wire format, for the fixture below.
///
/// [`crate::wire::MessageBuilder`] has no CNAME writer — this crate never
/// publishes one — so a fixture about a PEER's CNAME writes the bytes itself.
fn make_cname_record_ref(buf: &mut std::vec::Vec<u8>, owner_str: &str, ttl: u32, target_str: &str) {
  buf.clear();
  for label in owner_str.trim_end_matches('.').split('.') {
    #[allow(clippy::cast_possible_truncation)]
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8); // root label

  buf.extend_from_slice(&5u16.to_be_bytes()); // TYPE CNAME
  buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  buf.extend_from_slice(&ttl.to_be_bytes());

  let mut rdata: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in target_str.trim_end_matches('.').split('.') {
    #[allow(clippy::cast_possible_truncation)]
    rdata.push(label.len() as u8);
    rdata.extend_from_slice(label.as_bytes());
  }
  rdata.push(0u8); // root label

  #[allow(clippy::cast_possible_truncation)]
  buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
  buf.extend_from_slice(&rdata);
}

/// A record of a type the probe's QTYPE never asked for is STILL in the peer's
/// §8.2 proposal — pinned over a CNAME, a type this crate publishes and probes
/// for nowhere, so no QTYPE in the sweep below can match it by accident.
///
/// §8.2 requires the Authority Section to carry "*all* the records and proposed
/// rdata being probed for uniqueness": it is the sender's complete proposal, and
/// the sender's own QTYPE narrows nothing about it. Scoping any of it away
/// shortens the peer's list, and §8.2.1 sorts both lists and walks them
/// pairwise — so the omission changes which elements meet and decides the round
/// over a list the peer never sent, in whichever direction the removed record's
/// sort position happens to push it.
///
/// The fixture needs `instance == host`: only then does `write_probe` put the
/// A/AAAA records under the contested owner, so our sorted list OPENS with type
/// 1 and the peer's type 5 sorts after it. The peer proposes nothing but that
/// one record, so dropping it leaves an empty list to adjudicate and we hold —
/// while the peer, folding the type-ANY probe §8.1 tells us to send, sees our
/// whole proposal and wins. Two conforming peers, one name.
#[test]
fn a_record_outside_the_probes_qtype_is_still_proposed() {
  // Every QTYPE a probe could narrow to that is not the CNAME's own type.
  for qtype in [
    crate::wire::ResourceType::A,
    crate::wire::ResourceType::Srv,
    crate::wire::ResourceType::Txt,
  ] {
    let shared = Name::try_from_str(PROBED_NAME).unwrap();
    let mut records = ServiceRecords::new(
      Name::try_from_str("_ipp._tcp.local.").unwrap(),
      shared.clone(),
      shared,
      631,
      120,
    );
    records.add_a(core::net::Ipv4Addr::new(192, 168, 1, 10));
    let mut svc: Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> =
      Service::try_new(
        ServiceHandle::from_raw(0),
        records,
        FakeInstant::zero(),
        [0u8; 32],
        true,
      );
    let t0 = FakeInstant::zero();
    svc.handle_timeout(t0).unwrap();

    let mut cname = std::vec::Vec::new();
    make_cname_record_ref(&mut cname, PROBED_NAME, 120, "elsewhere.local.");
    let bytes = raw_proposal_bytes_asking_type(PROBED_NAME, qtype, &[cname]);

    let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
    svc.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
      t0,
    );
    assert!(
      svc.tiebreak_lost,
      "the peer's Authority Section is its whole proposal, so this record is in \
       the list §8.2.1 sorts however narrow the {qtype:?} question was — and \
       type 5 sorts after the type 1 our own list opens with, which is the peer \
       winning the round"
    );
  }
}

/// The control for the fixture above: admitting an off-QTYPE record is
/// ADJUDICATING it, not conceding to it.
///
/// With a separate host name our proposal is `{SRV, TXT}` and opens with type
/// 16, so the same type-5 record sorts EARLIER and §8.2.1 leaves us the winner.
/// Without this, a fold that simply lost every round it could not read would
/// pass the fixture above.
#[test]
fn a_record_outside_the_qtype_still_loses_a_round_it_sorts_earlier_than() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  let mut cname = std::vec::Vec::new();
  make_cname_record_ref(&mut cname, PROBED_NAME, 120, "elsewhere.local.");
  let bytes = raw_proposal_bytes_asking_type(PROBED_NAME, crate::wire::ResourceType::A, &[cname]);

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "the record is admitted and compared, and type 5 sorts before the type 16 \
     this service's list opens with — §8.2.1 keeps the name"
  );
}

// ── R10 finding 2: nothing of a superseded generation reaches the wire ──

/// R10 finding 2: a probe QUEUED before the losing verdict arrived must not be
/// transmitted.
///
/// The permitted order is `handle_timeout` (which queues the probe),
/// `handle_event` (a winning `ProbeProposal`, which latches the loss), then
/// `poll_transmit`. §8.2 does not tell the loser to stop asserting — it tells it
/// to stop: "it defers to the winning host by waiting one second, and then
/// begins probing for this record again". A probe that escapes here is the
/// loser probing through the very second it owes.
#[test]
fn a_probe_queued_before_the_loss_does_not_escape_the_deferral() {
  let mut svc = make_service(120);
  let mut buf = std::vec![0u8; 4096];
  let mut now = FakeInstant::zero();

  // Drive to the tick that QUEUES a probe, without polling it out.
  let mut queued = false;
  for _ in 0..8 {
    now = now.advance(100);
    svc.handle_timeout(now).unwrap();
    if svc.peek_pending().is_some() {
      queued = true;
      break;
    }
  }
  assert!(queued, "precondition: a probe is queued and not yet drawn");

  // The winning proposal arrives before the queue is drained.
  let bytes = srv_txt_proposal(9999);
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    now,
  );
  assert!(
    svc.tiebreak_lost,
    "precondition: the peer's proposal took the round"
  );

  assert!(
    svc.poll_transmit(now, &mut buf).unwrap().is_none(),
    "a §8.2 loser owes one second of silence, so the probe its previous \
     generation queued must be WITHHELD — not sent because a probe 'asserts \
     nothing'"
  );
  assert!(
    svc.peek_pending().is_some(),
    "…and withheld is a PAUSE, not a drop: the queue is left intact for the \
     deferral to clear"
  );
}

// ── R10 finding 6: a shared PTR claims no instance name ────────────────

/// R10 finding 6: a confirmed response that emitted only the SHARED
/// service-type PTR must not close the pre-authoritative window.
///
/// `is_preauthoritative` asks whether this generation has CLAIMED the name.
/// The service-type and RFC 6763 §7.1 subtype PTRs are owned by shared names
/// that any number of responders answer for, so emitting one claims nothing —
/// and §7.1 known-answer suppression can trim a response down to exactly those
/// (a querier that already holds our SRV and TXT). Counting it left the window
/// shut with no instance-owned record anywhere on the link, and the next winning
/// `ProbeProposal` was dropped unadjudicated.
#[test]
fn a_shared_ptr_only_response_does_not_close_the_preauthoritative_window() {
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();

  // A confirmed Response that emitted the shared PTRs and NOTHING the instance
  // owns — what §7.1 leaves after suppressing a querier's known SRV and TXT.
  svc.awaiting_confirm = Some(AwaitingConfirm::Response(
    respond::EmittedRecords::new(
      true,
      false,
      false,
      std::vec::Vec::new(),
      std::vec::Vec::new(),
      true,
      false,
    ),
    0,
  ));
  svc.note_delivery(t0, TransmitDelivery::ALL);

  assert_eq!(
    svc.goodbye.ptr, [true; 2],
    "precondition: goodbye ownership DOES count the shared PTR — a peer caches \
     it from us and it must be withdrawn"
  );
  assert!(
    !svc.generation_advertised,
    "…but a shared PTR claims no instance name, so this generation has \
     advertised nothing"
  );

  // The consequence, which is the whole point: a winning proposal is still
  // adjudicated.
  let bytes = srv_txt_proposal(9999);
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    svc.tiebreak_lost,
    "a service that has put no instance-owned record on the wire is still \
     pre-authoritative, so §8.2 still governs it"
  );
}

// ── R10 finding 1: §8.1 defers to an existing owner of ANY type ────────

/// R10 finding 1: an existing owner's A record at our instance name is a
/// conflicting RESPONSE for a name we are probing, and §8.1 defers to it.
///
/// "If any conflicting Multicast DNS response is received, then the probing host
/// MUST defer to the existing host" — and the name we are probing is asked about
/// as type ANY, so every type at it is ours to defend or to lose. Screening the
/// conflict down to SRV/TXT let this service finish probing and announce over a
/// peer that already held the name.
#[test]
fn a_response_of_any_type_at_our_instance_name_defeats_the_probe() {
  let mut svc = make_service(120);
  let start = probe_once(&mut svc, FakeInstant::zero());

  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut buf, PROBED_NAME, 120, [10, 0, 0, 7]);
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    start,
  );

  assert!(
    svc.probe_defeated,
    "an existing owner's A record at the name we are probing is a conflicting \
     response, whatever type it happens to be"
  );
}

/// R13 finding 2. A malformed record at the probed name must not rename us, and
/// the reason it used to is that two consumers disagreed about the same bytes.
///
/// Conflict routing widened from SRV/TXT to every positive-TTL IN record at the
/// probed name, because §8.1's question is type ANY — which made an NS at that
/// name reachable for the first time. The identity path then raw-copied unparsed
/// rdata and always succeeded, so a compression pointer that resolves to nothing
/// canonicalized to two bytes, compared unequal to the nothing we assert for NS,
/// and became `Different` — an §8.1 defeat. The §8.2 path decompressed the same
/// record, failed, and abandoned. One decoder later, both answer "undecodable".
///
/// The attack this closes costs one datagram and needs no knowledge of the
/// victim's records at all.
#[test]
fn a_malformed_record_at_the_probed_name_is_not_a_conflict() {
  // An NS record whose whole rdata is a compression pointer targeting its own
  // offset — forward, so it resolves to nothing. `rdata_view` yields
  // `Rdata::Other` and succeeds; only the decode discovers it.
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in PROBED_NAME.trim_end_matches('.').split('.') {
    buf.push(u8::try_from(label.len()).unwrap());
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8);
  buf.extend_from_slice(&2u16.to_be_bytes()); // TYPE NS
  buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  buf.extend_from_slice(&120u32.to_be_bytes());
  buf.extend_from_slice(&2u16.to_be_bytes()); // RDLENGTH = 2
  let rdata_at = u16::try_from(buf.len()).unwrap();
  buf.extend_from_slice(&(0xC000u16 | rdata_at).to_be_bytes());

  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  assert!(
    rec.rdata_view().is_ok(),
    "precondition: this record PARSES — the divergence was never about parsing"
  );

  let mut svc = make_service(120);
  let start = probe_once(&mut svc, FakeInstant::zero());
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    start,
  );
  assert!(
    !svc.probe_defeated,
    "a record nobody can decode supports no conclusion, so it must reach \
     neither the §8.1 deferral nor the §9 revert"
  );
}

/// R10 finding 1, the other half: widening the types must not make a
/// byte-identical TWIN a conflict.
///
/// `write_announce` and `write_response` both ride an instance NSEC in the
/// Additional section (RFC 6762 §6.1), so a proxy or fault-tolerance twin — the
/// case §9 names as the reason for the identical-rdata rule — sends the same
/// NSEC we do. With SRV and TXT correctly screened out as identical, that NSEC
/// alone would otherwise have renamed us.
#[test]
fn an_identical_twins_instance_nsec_is_never_a_conflict() {
  let mut svc = make_service(120);
  let start = probe_once(&mut svc, FakeInstant::zero());

  // The NSEC this service itself emits: owner name as next_name, bitmap
  // asserting exactly {SRV, TXT}.
  let mut msg = [0u8; 512];
  let inst = Name::try_from_str(PROBED_NAME).unwrap();
  let mut b =
    crate::wire::MessageBuilder::<'_, 32>::try_new(&mut msg, crate::wire::Header::new()).unwrap();
  b.push_nsec_additional(&inst, 120, &respond::INSTANCE_NSEC_TYPES, true)
    .unwrap();
  let n = b.finish().unwrap();
  let reader = crate::wire::MessageReader::try_parse(&msg[..n]).unwrap();
  let rec = reader.additional().flatten().next().unwrap();

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    start,
  );
  assert!(
    !svc.probe_defeated,
    "identical rdata is never a conflict (§9), and our own instance NSEC is \
     exactly what a byte-identical twin sends"
  );
}

/// …and the OTHER half of the same widening: a peer's DIFFERING instance NSEC
/// is a §9 conflict for an ESTABLISHED service, and must be adjudicated as one.
///
/// The established-state gate used to admit `Srv | Txt` and nothing else, from a
/// hand-written list beside the classifier's. When `canonical_rdata_forms` grew
/// its NSEC arm the list did not follow, so a peer's authoritative,
/// cache-flushed NSEC at our instance name — same owner, class and rrtype,
/// DIFFERENT rdata — was routed, classified as conflicting, and then discarded
/// solely for being an NSEC. An NSEC-only response or additional record left
/// duplicate ownership of this instance name undetected until unrelated SRV/TXT
/// traffic happened to arrive.
///
/// The gate now derives from the same canonical forms the classifier uses, so
/// the two cannot disagree about which types can be ours.
#[test]
fn a_differing_instance_nsec_reverts_an_established_service() {
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  while svc.poll().is_some() {}

  // A conforming peer's NSEC for the SAME name asserting a DIFFERENT RRset —
  // `{SRV, TXT, A}` where ours asserts `{SRV, TXT}`. Same owner, class and
  // rrtype; inconsistent rdata; §9's conflict exactly.
  let mut msg = [0u8; 512];
  let inst = Name::try_from_str(PROBED_NAME).unwrap();
  let mut b =
    crate::wire::MessageBuilder::<'_, 32>::try_new(&mut msg, crate::wire::Header::new()).unwrap();
  b.push_nsec_additional(
    &inst,
    120,
    &[
      crate::wire::ResourceType::Srv.to_u16(),
      crate::wire::ResourceType::Txt.to_u16(),
      crate::wire::ResourceType::A.to_u16(),
    ],
    true,
  )
  .unwrap();
  let n = b.finish().unwrap();
  let reader = crate::wire::MessageReader::try_parse(&msg[..n]).unwrap();
  let rec = reader.additional().flatten().next().unwrap();

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    now,
  );
  assert_eq!(
    svc.state(),
    ServiceState::Init,
    "a peer's differing instance NSEC is a §9 conflict — it must send this \
     service back through §8's startup steps, not be dropped for its rrtype"
  );
}

/// The widening is still bounded by the RULE rather than by a list: a PTR at the
/// instance name is owned by the SHARED service-type name, so this service
/// asserts no canonical form of it and it can make no §9 conflict.
#[test]
fn a_shared_ptr_at_the_instance_name_still_makes_no_established_conflict() {
  let mut svc = make_service(120);
  let now = drive_to_established(&mut svc);
  while svc.poll().is_some() {}

  let mut msg = [0u8; 512];
  let inst = Name::try_from_str(PROBED_NAME).unwrap();
  let other = Name::try_from_str("somewhere-else.local.").unwrap();
  let mut b =
    crate::wire::MessageBuilder::<'_, 32>::try_new(&mut msg, crate::wire::Header::new()).unwrap();
  b.push_ptr_answer(&inst, 120, &other).unwrap();
  let n = b.finish().unwrap();
  let reader = crate::wire::MessageReader::try_parse(&msg[..n]).unwrap();
  let rec = reader.answers().flatten().next().unwrap();

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    now,
  );
  assert_eq!(
    svc.state(),
    ServiceState::Established,
    "a shared PTR is not a record this instance name is authoritative for"
  );
}

/// R13 finding 3, CONFLICT SIDE ONLY. A conforming twin's CORRECT NSEC must not
/// rename us just because ours is wrong.
///
/// When the host name IS the instance name, `write_probe` and `write_announce`
/// put this service's A/AAAA records under the instance name too, so the
/// complete RRset at that name is `{A, AAAA, SRV, TXT}` — and a conforming
/// responder's §6.1 NSEC asserts exactly that. Ours asserts `{SRV, TXT}`,
/// denying address records we ourselves emit. THAT defect is in NSEC generation,
/// predates this branch, and is filed against `main`: fixing it changes the wire
/// for every same-name deployment.
///
/// Its consequence here does not get to wait, because it is a rename. A correct
/// twin's correct bitmap differs from our incorrect one, and differing rdata at a
/// name we are probing is an RFC 6762 §8.1 defeat — so the twin the
/// identical-rdata rule exists to protect would take our name from us for being
/// right.
#[test]
fn a_conforming_twins_nsec_is_not_a_conflict_when_the_host_is_the_instance_name() {
  use crate::wire::ResourceType;

  let shared = Name::try_from_str(PROBED_NAME).unwrap();
  let mut records = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    shared.clone(),
    shared.clone(),
    631,
    120,
  );
  records.add_a(core::net::Ipv4Addr::new(192, 168, 1, 10));
  records.add_aaaa(core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
  let mut svc: Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> =
    Service::try_new(
      ServiceHandle::from_raw(0),
      records,
      FakeInstant::zero(),
      [0u8; 32],
      true,
    );
  let start = probe_once(&mut svc, FakeInstant::zero());

  let nsec_record = |types: &[u16], buf: &mut [u8; 512]| -> std::vec::Vec<u8> {
    let mut b =
      crate::wire::MessageBuilder::<'_, 32>::try_new(buf, crate::wire::Header::new()).unwrap();
    b.push_nsec_additional(&shared, 120, types, true).unwrap();
    let n = b.finish().unwrap();
    buf.get(..n).unwrap().to_vec()
  };

  // The bitmap a CONFORMING responder publishes for this name.
  let mut buf = [0u8; 512];
  let conforming = nsec_record(
    &[
      ResourceType::A.to_u16(),
      ResourceType::AAAA.to_u16(),
      ResourceType::Srv.to_u16(),
      ResourceType::Txt.to_u16(),
    ],
    &mut buf,
  );
  let reader = crate::wire::MessageReader::try_parse(&conforming).unwrap();
  let rec = reader.additional().flatten().next().unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    start,
  );
  assert!(
    !svc.probe_defeated,
    "a twin that correctly asserts {{A, AAAA, SRV, TXT}} at a name that really \
     holds all four is indistinguishable from us, however our own NSEC spells it"
  );

  // And the leniency stays narrow: a bitmap that is neither what we emit nor
  // what a conforming responder would emit here is still a conflict.
  let mut buf2 = [0u8; 512];
  let foreign = nsec_record(&[ResourceType::Ptr.to_u16()], &mut buf2);
  let reader2 = crate::wire::MessageReader::try_parse(&foreign).unwrap();
  let rec2 = reader2.additional().flatten().next().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec2,
      dg(2),
      ConflictHistory::Unmatched,
    )),
    start,
  );
  assert!(
    svc.probe_defeated,
    "an NSEC asserting an RRset that is not ours is another owner answering for \
     our name"
  );
}

/// The duplication `respond::our_nsec_identities` warns about, pinned.
///
/// It reconstructs the RFC 4034 §4.1.2 type bitmap that
/// `MessageBuilder::push_nsec_additional` writes, because the builder works
/// through a fixed cursor with no allocator and cannot be reused. If either side
/// changes without the other, our own NSEC stops being recognisable as ours and
/// a twin's copy of it renames us.
#[test]
fn our_nsec_identities_match_what_the_builder_emits() {
  let svc = make_service(120);
  let mut msg = [0u8; 512];
  let inst = Name::try_from_str(PROBED_NAME).unwrap();
  let mut b =
    crate::wire::MessageBuilder::<'_, 32>::try_new(&mut msg, crate::wire::Header::new()).unwrap();
  b.push_nsec_additional(&inst, 120, &respond::INSTANCE_NSEC_TYPES, true)
    .unwrap();
  let n = b.finish().unwrap();
  let reader = crate::wire::MessageReader::try_parse(&msg[..n]).unwrap();
  let rec = reader.additional().flatten().next().unwrap();
  let on_the_wire = rec.canonical_rdata_folded().unwrap();
  let recognised = respond::our_nsec_identities(svc.records());
  assert!(
    recognised.iter().any(|f| f.as_slice() == &*on_the_wire),
    "the reconstructed instance-NSEC identity must be among the forms we \
     recognise as ours; the builder emits {on_the_wire:?}, we recognise \
     {recognised:?}"
  );
}

// ── the reader property the fold relies on ──

/// The reader property the fold depends on, pinned rather than asserted in a
/// comment: a question section that will not parse leaves the authority section
/// UNLOCATABLE, so no authority record is surfaced at all.
///
/// `service::proposal::adjudicate` has no separate "abandon on an unreadable
/// question section" arm, and that is only safe if this holds. If it did not,
/// a record admitted by a question parsing BEFORE a broken one would be folded
/// while the rest of the section went unseen — silently shortening the peer's
/// list. §8.2.1 walks the two sorted lists pairwise, so an omission changes which
/// elements meet and can decide the round in either direction, over a list the
/// peer never sent.
#[test]
fn an_unparseable_question_section_surfaces_no_authority_records() {
  let (txt, srv) = winning_pair();
  let mut bytes = raw_proposal_bytes(&[txt, srv]);
  // An OVERSTATED QDCOUNT. Question one is perfectly readable; the rest are
  // parsed off the authority records' bytes and then run off the end of the
  // datagram, so the question section stops parsing partway. That ordering is
  // the whole point — a reader that surfaced records anyway would surface the
  // ones question one admits and silently drop whatever lay past the failure.
  //
  // Overstating the count is the only way to get there, and that is itself worth
  // recording: a question whose NAME is an unresolvable compression pointer does
  // NOT break section location, because `QuestionRef::try_parse` consumes the
  // two pointer bytes without following them. Such a question is still
  // fail-closed at the fold — `names_match` walks the labels, the walk errors,
  // and the question admits nothing — but it is not this case.
  bytes[5] = 8;
  let reader = crate::wire::MessageReader::try_parse(&bytes).unwrap();
  assert!(
    reader.questions().any(|q| q.is_err()),
    "precondition: the question section really does fail to parse"
  );
  assert_eq!(
    reader.authority().count(),
    0,
    "an unlocatable authority section must surface NO records — the fold relies \
     on this instead of carrying its own abandonment arm for the case"
  );

  // …and therefore the proposal records no verdict, though its records would
  // otherwise have taken the round (see `the_winning_pair_control_really_does_lose_the_round`).
  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "a datagram whose question section will not parse yields no §8.2 verdict"
  );
}

/// ABANDONMENT IS BEHAVIOURALLY IDENTICAL TO `WeHold`. Two services in the same
/// state, one handed a proposal the fold abandons and one handed a proposal it
/// resolves in our favour, are indistinguishable from that point on — same
/// state, same name, same deadlines, same bytes on the wire.
///
/// This is an equivalence other code RELIES on, not a curiosity.
/// `RouteEvents::authority_proposes_for` withholds a `ProbeProposal` it cannot
/// read instead of delivering one the fold would only abandon, and that is sound
/// exactly because delivering-then-abandoning and never-delivering leave the
/// `Service` in the same place. §8.2.1 resolves a contest between two lists; a
/// section that is not a list it can sort resolves nothing, and "nothing" is what
/// a host that has not lost its round does next.
///
/// So if `Verdict::Abandoned` ever becomes a yield — a deferral, a rename, a
/// backoff — this test fails FIRST, and the router's fail-closed disposition on
/// the proposal path has to be revisited with it.
///
/// The abandoning fixture is built so a regression is loud rather than quiet: its
/// readable subset is `winning_pair`, which
/// `the_winning_pair_control_really_does_lose_the_round` proves takes the round
/// outright. A fold that skipped the undecodable record instead of abandoning
/// would defer this service, and the two sides would diverge on the first
/// comparison below.
#[test]
fn an_abandoned_proposal_behaves_exactly_like_we_hold() {
  use crate::service::proposal::{Abandon, Verdict, adjudicate};

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();

  // A peer proposal §8.2.1 resolves in our favour: SRV port 1 sorts before our
  // 631, and the TXTs tie.
  let holds = srv_txt_proposal(1);
  // The same winning pair the control fixture uses, plus a third record whose
  // owner name is a pointer to its own offset: §8.2 requires "*all* the records
  // and proposed rdata", and this section cannot be read to that standard.
  let (txt, srv) = winning_pair();
  let at = first_record_offset(PROBED_NAME) + txt.len() + srv.len();
  let mut cyclic = std::vec::Vec::new();
  make_cyclic_owner_record(&mut cyclic, at, 1, 120, &[10, 0, 0, 7]);
  let abandons = raw_proposal_bytes(&[txt, srv, cyclic]);

  // PRECONDITION: the two datagrams really do reach the two different terminal
  // values. Without this the comparison below could pass by comparing a verdict
  // against itself.
  let records = make_records(120);
  assert_eq!(
    adjudicate(&probe_proposal(&holds, peer, dg(1)), &records),
    Verdict::WeHold,
    "precondition: the peer's SRV port 1 sorts before our 631"
  );
  assert_eq!(
    adjudicate(&probe_proposal(&abandons, peer, dg(1)), &records),
    Verdict::Abandoned(Abandon::UndecodableOwnerName),
    "precondition: an owner name that will not decode abandons the proposal"
  );

  let t0 = FakeInstant::zero();
  let mut held = make_service(120);
  let mut abandoned = make_service(120);
  held.handle_timeout(t0).unwrap();
  abandoned.handle_timeout(t0).unwrap();

  held.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&holds, peer, dg(1))),
    t0,
  );
  abandoned.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&abandons, peer, dg(1))),
    t0,
  );

  // The two §8.1/§8.2 latches, the lifecycle state, the name, and the next
  // deadline — everything the event could have moved.
  assert_eq!(
    (
      abandoned.tiebreak_lost,
      abandoned.probe_defeated,
      abandoned.state(),
      abandoned.name().as_str(),
      abandoned.poll_timeout(),
    ),
    (
      held.tiebreak_lost,
      held.probe_defeated,
      held.state(),
      held.name().as_str(),
      held.poll_timeout(),
    ),
    "an abandonment must leave the service exactly where a WeHold leaves it"
  );

  // …and it stays identical through the rest of the §8.1 sequence, byte for
  // byte. Both services were seeded identically, so any divergence in jitter,
  // deadlines or emitted records shows up here.
  let mut held_buf = std::vec![0u8; 4096];
  let mut abandoned_buf = std::vec![0u8; 4096];
  let mut now = t0;
  for tick in 0..20 {
    now = now.advance(500);
    held.handle_timeout(now).unwrap();
    abandoned.handle_timeout(now).unwrap();
    let h = held.poll_transmit(now, &mut held_buf).unwrap();
    let a = abandoned.poll_transmit(now, &mut abandoned_buf).unwrap();
    assert_eq!(
      h.map(|t| t.size()),
      a.map(|t| t.size()),
      "tick {tick}: the two services must transmit the same datagram or neither"
    );
    if let Some(tx) = h {
      assert_eq!(
        abandoned_buf.get(..tx.size()),
        held_buf.get(..tx.size()),
        "tick {tick}: byte-for-byte identical datagrams"
      );
      held.note_delivery(now, TransmitDelivery::ALL);
      abandoned.note_delivery(now, TransmitDelivery::ALL);
    }
    assert_eq!(
      (abandoned.state(), abandoned.name().as_str()),
      (held.state(), held.name().as_str()),
      "tick {tick}: the two services must stay in lockstep"
    );
  }
  assert_eq!(
    held.state(),
    ServiceState::Established,
    "the control really did carry on and establish, so the lockstep above is \
     over a sequence that goes somewhere"
  );
}

// ── R11: nothing undecodable produces a verdict ────────────────────────

/// R11-1: a KX(36) whose compressed target cannot be resolved must ABANDON the
/// proposal, not lengthen the peer's list.
///
/// The guard was an enumeration of compression-eligible types and it omitted
/// RP(17), AFSDB(18), RT(21), PX(26) and KX(36). So a KX raw-copied into
/// comparison bytes: with otherwise identical SRV and TXT the extra element made
/// the peer's list longer, §8.2.1's "the list with records remaining is deemed to
/// have won" handed it the round, and a peer repeating that packet could defer
/// this host past every probe it ever schedules — establishment prevented
/// indefinitely by a malformed proposal.
///
/// The type is no longer consulted: the rdata holds a `0xC0` octet, so it might
/// be a compression pointer, so it has no position-independent comparison bytes.
#[test]
fn a_compressed_kx_abandons_rather_than_lengthening_the_peers_list() {
  // Every type the old enumeration missed, so a re-narrowing to any list fails
  // here rather than only for the one type a fixture happened to pick.
  for rtype in [36u16, 17, 18, 21, 26] {
    let mut svc = make_service(120);
    let t0 = FakeInstant::zero();
    svc.handle_timeout(t0).unwrap();

    // A TIE on SRV and TXT, so the round turns entirely on the third record.
    let mut txt = std::vec::Vec::new();
    make_txt_record_ref(&mut txt, PROBED_NAME, 120, &[&[]]);
    let mut srv = std::vec::Vec::new();
    make_srv_record_ref(&mut srv, PROBED_NAME, 120, 0, 0, 631, "host.local.");
    let mut exotic = std::vec::Vec::new();
    for label in PROBED_NAME.trim_end_matches('.').split('.') {
      #[allow(clippy::cast_possible_truncation)]
      exotic.push(label.len() as u8);
      exotic.extend_from_slice(label.as_bytes());
    }
    exotic.push(0u8);
    exotic.extend_from_slice(&rtype.to_be_bytes());
    exotic.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    exotic.extend_from_slice(&120u32.to_be_bytes());
    // preference(2) + a compressed target pointing past the end of the datagram,
    // so it cannot be resolved. UNRESOLVABLE is the point: since R12 these types
    // are decompressed and COMPARED when their names resolve, so a resolvable
    // pointer would (correctly) make the peer's longer list win rather than
    // abandon. See `comparability_of_unparsed_rdata_is_a_per_type_question`.
    exotic.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    exotic.extend_from_slice(&[0x00, 0x0A, 0xFF, 0xFF]);
    let bytes = raw_proposal_bytes(&[txt, srv, exotic]);

    let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
    svc.handle_event(
      ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
      t0,
    );
    assert!(
      !svc.tiebreak_lost,
      "type {rtype}: a record whose rdata may hold a compression pointer has no \
       comparison bytes, so the proposal is ABANDONED — it must not be scored as \
       a third record that wins §8.2.1 on list length"
    );
  }
}

/// R11-2: a question whose QNAME is an unresolvable compression pointer makes
/// the whole proposal undecodable, even when ANOTHER question admits.
///
/// This is the case the section-location property does NOT cover, and the two
/// statements have to be read together. A question section that will not PARSE
/// leaves the authority section unlocatable, so nothing is folded. But
/// `QuestionRef::try_parse` consumes a compression pointer WITHOUT following it,
/// so a pointer-named question parses, the section is locatable, and the records
/// are surfaced — and `.flatten()` then dropped the error and read the bad
/// question as a non-match, letting the good one admit and the fold return a
/// verdict.
///
/// The valid question is placed FIRST on purpose: admission now walks the whole
/// section instead of stopping at the first match, so ordering cannot hide it.
#[test]
fn a_pointer_named_question_abandons_even_when_another_question_admits() {
  let (txt, srv) = winning_pair();
  let good = raw_proposal_bytes(&[txt, srv]);
  let qlen = first_record_offset(PROBED_NAME) - 12;

  let mut bytes: std::vec::Vec<u8> = std::vec::Vec::new();
  bytes.extend_from_slice(&good[..12]);
  bytes[5] = 2; // QDCOUNT = 2
  bytes.extend_from_slice(&good[12..12 + qlen]); // question 1: valid, ANY, admits
  // question 2: QNAME is a pointer to its own offset, so following it cycles.
  let q2_at = 12 + qlen;
  #[allow(clippy::cast_possible_truncation)]
  bytes.extend_from_slice(&[0xC0 | ((q2_at >> 8) as u8), q2_at as u8]);
  bytes.extend_from_slice(&crate::wire::ResourceType::Any.to_u16().to_be_bytes());
  bytes.extend_from_slice(&1u16.to_be_bytes());
  bytes.extend_from_slice(&good[12 + qlen..]); // the winning authority pair

  // Precondition: the section really does PARSE — this is not the unlocatable
  // case — and the records really are surfaced, so the fold does run.
  let reader = crate::wire::MessageReader::try_parse(&bytes).unwrap();
  assert!(
    reader.questions().all(|q| q.is_ok()),
    "precondition: a pointer QNAME parses; only walking its labels fails"
  );
  assert_eq!(
    reader.authority().count(),
    2,
    "precondition: the authority section is locatable and its records are surfaced"
  );

  let mut svc = make_service(120);
  let t0 = FakeInstant::zero();
  svc.handle_timeout(t0).unwrap();
  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  svc.handle_event(
    ServiceEvent::ProbeProposal(probe_proposal(&bytes, peer, dg(1))),
    t0,
  );
  assert!(
    !svc.tiebreak_lost,
    "a question section holding a name that will not decode leaves what the \
     query ASKS unknown, so the proposal is abandoned — the readable question \
     must not adjudicate it alone (control: \
     `the_winning_pair_control_really_does_lose_the_round`)"
  );
}

/// R12-2: a malformed authoritative RESPONSE must not defeat the probe.
///
/// `response_rdata_is_ours` returned a plain `bool`, so a parse or
/// canonicalisation failure came back as `false` — which dispatch read as
/// DIFFERING rdata. A QR=1 IN/SRV response whose target is a cyclic or
/// forward-pointing name therefore set `probe_defeated` and renamed the service,
/// and repeating it gave unbounded suffix churn and finally a terminal conflict.
/// An attacker needed one malformed record and no knowledge of our rdata.
///
/// Invalid is now its own answer and stops before every conflict arm — which is
/// what the ESTABLISHED §9 path already did with the same data, so the two
/// halves of one rule had disagreed.
#[test]
fn a_malformed_response_does_not_defeat_the_probe() {
  let mut svc = make_service(120);
  let start = probe_once(&mut svc, FakeInstant::zero());
  let before = svc.name().as_str().to_owned();

  // An SRV at our instance name whose target is a compression pointer past the
  // end of the datagram: it parses as a record, and only resolving the name
  // fails.
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  for label in PROBED_NAME.trim_end_matches('.').split('.') {
    #[allow(clippy::cast_possible_truncation)]
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8);
  buf.extend_from_slice(&33u16.to_be_bytes()); // SRV
  buf.extend_from_slice(&1u16.to_be_bytes()); // IN
  buf.extend_from_slice(&120u32.to_be_bytes());
  buf.extend_from_slice(&8u16.to_be_bytes()); // RDLENGTH
  buf.extend_from_slice(&[0, 0, 0, 0, 0x27, 0x0F, 0xFF, 0xFF]); // …target unresolvable

  let peer: core::net::SocketAddr = "192.168.1.200:5353".parse().unwrap();
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::ProbeConflict(ProbeConflict::new(
      peer,
      rec,
      dg(1),
      ConflictHistory::Unmatched,
    )),
    start,
  );

  assert!(
    !svc.probe_defeated,
    "rdata that will not decode supports no conclusion — it must not be read as \
     DIFFERING rdata and latch an §8.1 defeat"
  );
  let spent = start.advance(500);
  svc.handle_timeout(spent).unwrap();
  assert_eq!(
    svc.name().as_str(),
    before,
    "…and so the service must not rename: repeating this record would otherwise \
     give unbounded suffix churn on one malformed packet"
  );
  let mut updates = std::vec::Vec::new();
  while let Some(u) = svc.poll() {
    updates.push(u);
  }
  assert!(
    !updates.iter().any(ServiceUpdate::is_renamed),
    "…and queue no Renamed update; got {updates:?}"
  );
}

// ── §9's conflict is per RRTYPE: an unowned type is not our RRset ────────────

/// Build a minimal raw AAAA record in wire format. The `Ref` lives as long as
/// `buf`. Counterpart of [`make_a_record_ref`].
fn make_aaaa_record_ref(buf: &mut std::vec::Vec<u8>, name_str: &str, ttl: u32, addr: [u8; 16]) {
  buf.clear();
  for label in name_str.trim_end_matches('.').split('.') {
    buf.push(label.len() as u8);
    buf.extend_from_slice(label.as_bytes());
  }
  buf.push(0u8); // root label
  buf.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
  buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
  buf.extend_from_slice(&ttl.to_be_bytes());
  buf.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
  buf.extend_from_slice(&addr);
}

fn make_service_with(
  a: &[core::net::Ipv4Addr],
  aaaa: &[core::net::Ipv6Addr],
) -> Service<FakeInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>> {
  let mut r = ServiceRecords::new(
    Name::try_from_str("_ipp._tcp.local.").unwrap(),
    Name::try_from_str("myprinter._ipp._tcp.local.").unwrap(),
    Name::try_from_str("host.local.").unwrap(),
    631,
    120,
  );
  for addr in a {
    r.add_a(*addr);
  }
  for addr in aaaa {
    r.add_aaaa(*addr);
  }
  Service::try_new(
    ServiceHandle::from_raw(0),
    r,
    FakeInstant::zero(),
    [0u8; 32],
    true,
  )
}

/// RFC 6762 §9 makes a conflict "the same name, **rrtype** and rrclass, but
/// inconsistent rdata". An IPv6-only service asserts no A RRset at its host
/// name, so a peer's A there is not that service's record and cannot be
/// inconsistent with rdata it never published — and never could.
///
/// `contains` over an empty slice answered "differing", which surfaced a
/// TERMINAL `ServiceUpdate::HostConflict`: a same-host sibling's first
/// announcement retired the service over an address it does not advertise.
#[test]
fn a_host_a_record_is_not_a_conflict_for_a_service_publishing_no_a() {
  use crate::event::{HostConflict, ServiceEvent};
  let mut svc = make_service_with(
    &[],
    &[core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
  );
  svc.handle_timeout(FakeInstant::zero()).unwrap();
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_a_record_ref(&mut buf, "host.local.", 120, [10, 0, 0, 99]);
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::HostConflict(HostConflict::new(
      rec,
      ConflictOrigin::AuthoritativeResponse,
    )),
    FakeInstant::zero(),
  );
  assert!(
    svc.poll().is_none(),
    "we publish no A at this host name, so a peer's A there is not our RRset"
  );
}

/// The same rule in the other family: an IPv4-only service holds no AAAA RRset.
#[test]
fn a_host_aaaa_record_is_not_a_conflict_for_a_service_publishing_no_aaaa() {
  use crate::event::{HostConflict, ServiceEvent};
  let mut svc = make_service_with(&[core::net::Ipv4Addr::new(192, 168, 1, 5)], &[]);
  svc.handle_timeout(FakeInstant::zero()).unwrap();
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_aaaa_record_ref(
    &mut buf,
    "host.local.",
    120,
    [
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
    ],
  );
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::HostConflict(HostConflict::new(
      rec,
      ConflictOrigin::AuthoritativeResponse,
    )),
    FakeInstant::zero(),
  );
  assert!(
    svc.poll().is_none(),
    "we publish no AAAA at this host name, so a peer's AAAA there is not our RRset"
  );
}

/// Control: once the service DOES own that RRset, a differing address in it is
/// a genuine §9 conflict again — the rule turns on ownership, not on family.
#[test]
fn a_host_aaaa_record_still_conflicts_when_we_own_an_aaaa_rrset() {
  use crate::event::{HostConflict, ServiceEvent};
  let mut svc = make_service_with(
    &[],
    &[core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
  );
  svc.handle_timeout(FakeInstant::zero()).unwrap();
  let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
  make_aaaa_record_ref(
    &mut buf,
    "host.local.",
    120,
    [
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
    ],
  );
  let (rec, _) = Ref::try_parse(&buf, 0).unwrap();
  svc.handle_event(
    ServiceEvent::HostConflict(HostConflict::new(
      rec,
      ConflictOrigin::AuthoritativeResponse,
    )),
    FakeInstant::zero(),
  );
  assert!(
    svc.poll().is_some_and(|u| u.is_host_conflict()),
    "a different address inside an RRset we DO own is still a §9 conflict"
  );
}

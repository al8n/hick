use std::time::{Duration, Instant as StdInstant, SystemTime};

use super::{
  ClockPair, Credit, MAX_SELF_SEND_BYTES, MAX_SELF_SEND_ENTRIES, RxDatagram, SELF_SEND_TTL,
  SelfSendMatch, SelfSendTracker, SendClass, WALL_STEP_TOLERANCE,
};
use crate::Family;

/// Whether a claim consumed a credit at all, at either strength.
///
/// A test whose subject is the take-once bookkeeping — which credit was
/// consumed, which survived — says so through this, so the tier tests stay the
/// only place a strength is asserted and a change to one is not lost in the
/// other. It is deliberately NOT a method on `SelfSendMatch`: a driver mapping
/// an echo onto a trust tier must read the variant, and a public flattener is
/// exactly the collapse the tier exists to prevent.
fn consumed(m: SelfSendMatch) -> bool {
  !matches!(m, SelfSendMatch::NoCredit)
}

/// A fixed wall instant to build ordering fixtures from. Ordering is all this
/// clock decides now, so every test that is not *about* ordering can leave it
/// alone.
fn wall() -> SystemTime {
  SystemTime::UNIX_EPOCH + Duration::from_secs(10)
}

/// A fixed monotonic instant to build ageing fixtures from.
///
/// `StdInstant` has no constructor and no epoch, so a test that needs one far
/// enough from the process start to subtract from has to take it from the clock
/// and add. Everything below adds; nothing subtracts.
fn mono() -> StdInstant {
  StdInstant::now()
}

/// One send's own pre-syscall reading of both clocks, exactly as
/// `BoundSocket::send_attempt` takes it: the wall stamp, and the monotonic
/// partner read immediately after.
fn send_stamps() -> ClockPair {
  ClockPair::new(wall(), mono())
}

/// A claim landing `after` the send, on **both** clocks at once — a run in which
/// the wall clock did nothing but keep up with the monotonic one.
///
/// Every test that is not about a clock step goes through this, so none of them
/// falls back to content-only matching by accident and quietly stops exercising
/// the ordering rule it was written for.
fn claim(sent: ClockPair, after: Duration) -> ClockPair {
  ClockPair::new(sent.wall + after, sent.mono + after)
}

/// Record `body` with the send stamps `sent` and open its claim window at
/// `sent.mono`, which is what one turn of the driver's loop does: the send stage
/// records, and the **next** tick's top seals. Every test whose subject is not
/// the seal itself goes through this, so none of them depends on the unsealed
/// state by accident.
fn recorded_and_sealed(t: &mut SelfSendTracker, family: Family, body: &[u8], sent: ClockPair) {
  t.record(family, body, sent);
  t.seal_at(sent.mono);
}

/// Two SEMANTICALLY DIFFERENT, structurally valid mDNS responses that share one
/// 64-bit FNV-1a fingerprint.
///
/// Both announce `hick.local. IN A`, one at `192.0.2.1` and one at `192.0.2.2`,
/// followed by eight trailing bytes — which `MessageReader` never reads, since
/// it bounds every section by the header counts and never requires the message
/// to be consumed. So the collision is carried entirely in bytes the protocol
/// layer ignores, and the two datagrams differ in exactly the field RFC 6762 §9
/// classifies a host conflict on.
///
/// Found by Pollard rho over the top 56 bits of FNV-1a in **41 seconds**,
/// single-threaded, on the machine this was written on; a full second-preimage
/// against a fixed victim datagram (no attacker influence on our bytes at all)
/// took **15 seconds** by meet-in-the-middle over FNV's invertible state update.
/// Committed as constants rather than searched for at test time, so the test
/// costs nothing to run and does not depend on the search.
const COLLIDING_A: &[u8] = &[
  0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x68, 0x69, 0x63,
  0x6b, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78,
  0x00, 0x04, 0xc0, 0x00, 0x02, 0x01, 0x92, 0xd9, 0x91, 0xc8, 0xf7, 0xb1, 0x9e, 0x00,
];
const COLLIDING_B: &[u8] = &[
  0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x68, 0x69, 0x63,
  0x6b, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78,
  0x00, 0x04, 0xc0, 0x00, 0x02, 0x02, 0xcf, 0x84, 0x80, 0x92, 0x0b, 0x82, 0xd3, 0xac,
];

/// The fingerprint both of the above hash to, kept so this test proves the two
/// bodies really are a collision rather than merely two different byte strings.
fn fnv1a_64(data: &[u8]) -> u64 {
  let mut h = 0xcbf2_9ce4_8422_2325u64;
  for &b in data {
    h ^= u64::from(b);
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
  }
  h
}

/// A credit is the BYTES, not a digest of them.
///
/// The tracker fingerprinted its sends with 64-bit FNV-1a, whose state update is
/// multiplication by an odd constant mod 2⁶⁴ and therefore a bijection — which
/// makes a second-preimage a meet-in-the-middle rather than a search of the
/// output space. An on-link sender who constructs a *different* valid DNS packet
/// with the same fingerprint consumed the take-once credit, and every driver
/// elevated the resulting ordered match to `Provenance::OwnEcho`, whose whole
/// permission row is "deny": the forged datagram's own §8.2 proposal and §9
/// conflict rdata were deleted with it, and the genuine echo arriving behind it
/// found no credit left and reached the protocol layer as peer traffic.
///
/// Exact matching is what makes the standing argument for full suppression true
/// rather than assumed: a datagram that claims a credit now carries the bytes we
/// sent, so its proposal is ours and ties under §8.2.1, and its rdata is ours
/// and is never a §9 conflict.
#[test]
fn a_colliding_datagram_cannot_claim_another_datagrams_credit() {
  assert_ne!(
    COLLIDING_A, COLLIDING_B,
    "the fixture must be two datagrams"
  );
  assert_eq!(
    fnv1a_64(COLLIDING_A),
    fnv1a_64(COLLIDING_B),
    "the fixture must be a real 64-bit FNV-1a collision, or this test proves \
     nothing about the digest it replaced"
  );

  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, COLLIDING_A, sent);
  // Ordered, inside the TTL, right family, right source port: everything the
  // strongest tier asks for, and the ONLY thing separating this datagram from
  // our own echo is its bytes.
  let rx = sent.wall + Duration::from_millis(1);
  let now = claim(sent, Duration::from_millis(1));
  assert_eq!(
    t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, COLLIDING_B, rx),
      now
    ),
    SelfSendMatch::NoCredit,
    "a datagram that merely COLLIDES with ours must not be suppressed as ours"
  );
  // And the credit is still there for the datagram it was actually recorded for.
  assert_eq!(
    t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, COLLIDING_A, rx),
      now
    ),
    SelfSendMatch::Ordered,
    "the genuine echo must still find its credit"
  );
}

#[test]
fn take_once_consumes_the_credit() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  let rx = sent.wall + Duration::from_millis(1);
  let now = claim(sent, Duration::from_millis(1));
  assert!(consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V4, &b"payload"[..], rx),
    now
  )));
  // Second identical datagram is a genuine peer packet: no credit left.
  assert!(!consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V4, &b"payload"[..], rx),
    now
  )));
}

#[test]
fn ordered_mode_rejects_a_packet_stamped_before_our_send() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  // Kernel stamped this BEFORE we sent -> cannot be our loopback.
  let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V4, &b"payload"[..], earlier),
    sent
  )));
  // The credit must survive for the real loopback copy.
  assert!(consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(
      Family::V4,
      &b"payload"[..],
      sent.wall + Duration::from_millis(1)
    ),
    sent
  )));
}

/// Degraded matching is content plus family plus the TTL, and **nothing else**.
///
/// It used to additionally require the reference to be at-or-after the send,
/// described as a clock-went-backwards guard, and that description is the whole
/// problem: the only wall value a degraded claim ever has is a userspace read
/// time, which is at-or-after the send in every case *except* a wall clock that
/// stepped backwards. So the guard could fire on nothing but the step, and
/// firing meant refusing our own echo — a phantom conflict against ourselves and
/// the RFC 6762 §9 rename that follows. There is no reference to weigh here now,
/// which is why the mode takes none.
#[test]
fn degraded_matching_weighs_no_reference_at_all() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  // The wall clock stepped ten seconds backwards between the send and here.
  // Nothing about that changes whether these bytes are the copy we just sent.
  let stepped_back = ClockPair::new(sent.wall - Duration::from_secs(10), sent.mono);
  assert!(consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"payload"[..]),
    stepped_back
  )));
  assert_eq!(t.len(), 0, "and it stays take-once, as in every other mode");
}

#[test]
fn ordered_mode_tolerates_only_the_timestamp_grain() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  // One hundred nanoseconds past the grain is outside the truncation tolerance.
  // The epsilon has to clear two independent resolutions at once:
  //
  //   * the grain, which is `Duration::ZERO` on nanosecond-timestamp targets and
  //     one microsecond on `timeval` ones. Any epsilon above zero is strictly
  //     outside both — 100ns before the send on the first, 1.1us before it on
  //     the second — so the claim lands in the branch that only the grain
  //     comparison can save, and this exercises that comparison rather than only
  //     ever hitting the trivial at-or-after-send case.
  //   * the tick of `SystemTime` itself, which is one nanosecond on the
  //     `timespec` targets but one hundred on Windows, where a `SystemTime` is a
  //     FILETIME and converting a `Duration` into one integer-divides the
  //     subsecond nanoseconds by 100. An epsilon below that tick is absorbed
  //     rather than applied: the subtraction moves nothing, `just_outside_grain`
  //     lands exactly ON the grain, `reference_ordered` rightly tolerates it,
  //     and the assertion below reads its own arithmetic back as a failure.
  //
  // 100ns is the smallest value clearing both — one whole tick of the coarsest
  // `SystemTime` any supported target has — so one epsilon still serves every
  // target without a `cfg`, and it stays an order of magnitude inside the
  // one-microsecond grain, leaving this assertion and the one below it
  // bracketing the boundary tightly.
  let just_outside_grain = sent.wall - crate::RX_TIMESTAMP_GRAIN - Duration::from_nanos(100);
  assert!(!consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V4, &b"payload"[..], just_outside_grain),
    sent
  )));
  // Exactly one grain early is inside the truncation tolerance.
  let within = sent.wall - crate::RX_TIMESTAMP_GRAIN;
  assert!(consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V4, &b"payload"[..], within),
    sent
  )));
  // A full second early is a peer packet the kernel saw before our sendto.
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  let way_early = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
  assert!(!consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V4, &b"payload"[..], way_early),
    sent
  )));
}

#[test]
fn a_credit_older_than_the_ttl_is_a_peer_not_our_echo() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  // Byte-identical and correctly ordered, but the credit has been waiting
  // longer than SELF_SEND_TTL -> a co-resident peer, not our echo.
  let late = claim(sent, SELF_SEND_TTL + Duration::from_millis(1));
  assert!(!consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"payload"[..]),
    late
  )));
  // Exactly at the TTL it still matches.
  assert!(consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"payload"[..]),
    claim(sent, SELF_SEND_TTL)
  )));
}

#[test]
fn the_ttl_upper_bound_applies_to_ordered_mode_too() {
  // Ordered's pre-send grain tolerance must not loosen the TTL upper bound:
  // every other Ordered-mode test in this file places the reference deep inside
  // the window, so a mutant that dropped the age check for Ordered would pass
  // all of them while swallowing a co-resident peer's byte-identical datagram,
  // hours later, as our own echo.
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  let expired = claim(sent, SELF_SEND_TTL + Duration::from_millis(1));
  assert!(!consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(
      Family::V4,
      &b"payload"[..],
      sent.wall + Duration::from_secs(3)
    ),
    expired
  )));
  // Inside the window it still matches.
  assert!(consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(
      Family::V4,
      &b"payload"[..],
      sent.wall + Duration::from_secs(2)
    ),
    claim(sent, SELF_SEND_TTL)
  )));
}

// ── the wall clock is not monotonic, and ordering runs on it ────────────────
//
// `Credit::sent`'s wall half is the only thing that orders an echo against its
// send, and an NTP step, a `settimeofday`, or a VM suspend/resume moves it under
// a credit that is already waiting. These four pin what each of the two clocks
// can and cannot see about that, and which way the claim falls when the wall
// stamp is no longer on the timeline the kernel's receive stamp was taken on.

/// The expensive direction, and the one this pair of stamps exists for.
///
/// The wall clock steps backwards right after the send, so the kernel stamps our
/// own echo *before* the credit that produced it. Weighed on the wall clock
/// alone the echo is a peer datagram that predated our send, and this endpoint
/// ingests its own announcement as peer traffic — a phantom conflict against
/// itself and the RFC 6762 §9 rename that follows. The monotonic partner is what
/// says the interval was 300 microseconds and not minus five seconds.
#[test]
fn a_backwards_wall_step_after_the_send_must_not_reject_our_own_echo() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"announcement", sent);
  const STEP: Duration = Duration::from_secs(5);
  // The kernel stamps the loopback copy 200us of REAL time after the send, on a
  // wall clock that has since moved five seconds backwards.
  let rx = sent.wall - STEP + Duration::from_micros(200);
  // The claim reads both clocks 300us of real time after the send.
  let now = ClockPair::new(
    sent.wall - STEP + Duration::from_micros(300),
    sent.mono + Duration::from_micros(300),
  );
  assert!(
    consumed(t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, &b"announcement"[..], rx),
      now
    )),
    "the two elapsed times disagree by five seconds, so the wall stamp is not on \
     the timeline the receive stamp was taken on and cannot order anything — \
     refusing the credit here is a phantom conflict against ourselves"
  );
}

/// The same machinery, the other direction, so a one-sided implementation fails.
///
/// A forward step makes a datagram the kernel saw *before* our send look ordered
/// after it, and the credit is given up the same way. That direction is the
/// cheap one: a datagram that reaches a credit at all is byte-identical to one
/// we sent, so every record in it carries rdata identical to ours, and RFC 6762
/// §9 defines a conflict as the same name, rrtype and rrclass with *different*
/// rdata. What it can cost is one redundant peer datagram inside the TTL window.
#[test]
fn a_forward_wall_step_after_the_send_also_gives_up_the_ordering_evidence() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"announcement", sent);
  // A datagram the kernel stamped a full second before our send.
  let rx = sent.wall - Duration::from_secs(1);
  // The wall clock jumped five seconds forward while one millisecond of real
  // time passed.
  let now = ClockPair::new(
    sent.wall + Duration::from_secs(5),
    sent.mono + Duration::from_millis(1),
  );
  assert!(
    consumed(t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, &b"announcement"[..], rx),
      now
    )),
    "a five-second forward jump in one millisecond of real time is a step, and a \
     stepped wall stamp orders nothing in either direction"
  );
}

/// A disagreement inside the tolerance is a slewed clock, not a stepped one, and
/// the ordering rule must survive it intact.
///
/// Without this, "treat unusable evidence as our echo" degenerates into treating
/// *every* claim as our echo, and the credit-theft guard `Ordered` exists for is
/// gone on every host whose clock is disciplined at all.
#[test]
fn a_disagreement_inside_the_tolerance_keeps_the_ordering_evidence() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"announcement", sent);
  // The wall clock ran a little ahead of real elapsed time, by less than the
  // tolerance: a slew, which is what a disciplined clock does.
  let now = ClockPair::new(
    sent.wall + WALL_STEP_TOLERANCE - Duration::from_millis(1),
    sent.mono + Duration::from_millis(1),
  );
  assert!(
    !consumed(t.claim_at(
      &RxDatagram::from_stamp_for_test(
        Family::V4,
        &b"announcement"[..],
        sent.wall - Duration::from_secs(1)
      ),
      now
    )),
    "the evidence is still good, so a datagram the kernel saw before our send \
     must not take the credit"
  );
  assert!(
    consumed(t.claim_at(
      &RxDatagram::from_stamp_for_test(
        Family::V4,
        &b"announcement"[..],
        sent.wall + Duration::from_micros(200)
      ),
      now
    )),
    "and our own echo still claims it"
  );
}

/// What a credit's own two stamps can and cannot see, stated as a test.
///
/// They bracket exactly one interval — the send to the claim — so a step that
/// landed *before* the send leaves no trace in them at all, and the credit is
/// weighed with full ordering evidence. That is right for the echo (both the
/// credit and the receive stamp are on the post-step timeline), and it leaves
/// one direction open: a byte-identical peer datagram the kernel queued before
/// the step now looks ordered after our send and can take the credit. That is
/// the cheap direction — byte-identical means identical rdata, which RFC 6762 §9
/// does not call a conflict — and closing it needs evidence this type does not
/// have: a paired reading taken *before* the send, held across the tick, for the
/// record to bracket the send against.
#[test]
fn a_step_before_the_send_leaves_the_credits_own_window_clean() {
  let mut t = SelfSendTracker::new();
  // The clock stepped, and only then did we send: both stamps are already on the
  // post-step timeline, and so is everything after.
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"announcement", sent);
  let now = claim(sent, Duration::from_millis(1));
  assert!(
    !consumed(t.claim_at(
      &RxDatagram::from_stamp_for_test(
        Family::V4,
        &b"announcement"[..],
        sent.wall - Duration::from_secs(1)
      ),
      now
    )),
    "nothing stepped inside this credit's window, so the ordering rule is intact \
     and a datagram stamped before our send is a peer's"
  );
  assert!(
    consumed(t.claim_at(
      &RxDatagram::from_stamp_for_test(
        Family::V4,
        &b"announcement"[..],
        sent.wall + Duration::from_micros(200)
      ),
      now
    )),
    "and our own echo, stamped on the same post-step timeline, still claims it"
  );
}

// ── where the window starts, and where it does not ──────────────────────────
//
// The invariant these five hold: a credit's ageing must not begin until the
// first instant its echo is claimable — the top of the tick after the recording
// tick — and from then on charges real monotonic elapsed time, including caller
// latency. The first four defend the lower end (nothing before the window opens
// may be charged, including the seal's own sweep), the fifth defends the upper
// end (everything after the seal must be).

/// The defect class this anchor exists for, in its purest form.
///
/// A credit is recorded and *nothing* about the driver's own tick can expire
/// it — not a syscall that stalled past the TTL before returning, not a later
/// send in the same tick, not the time the outbound stages took. The tracker is
/// handed no ageing anchor at all, so there is no anchor available for that
/// stretch to be charged to. The window opens when the seal opens it.
#[test]
fn an_unsealed_credit_cannot_expire_however_long_the_recording_tick_ran() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  t.record(Family::V4, b"announcement", sent);
  // Whatever this tick then did — a stalled syscall, a fan-out to the other
  // family, a stage-7 goodbye — it ran well past the TTL.
  let much_later = claim(sent, SELF_SEND_TTL + Duration::from_secs(5));
  assert_eq!(
    t.len(),
    1,
    "an unsealed credit is live regardless of how much time the recording tick \
     went on to spend"
  );
  // Reached defensively, not by the driver: no send stage precedes the receive
  // stage today, so nothing unsealed is visible to a claim. It must be live
  // anyway — a credit with no claim opportunity yet has nothing to have
  // outlived.
  assert!(consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"announcement"[..]),
    much_later
  )));
}

#[test]
fn the_seal_starts_an_unsealed_credit_at_age_zero() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  t.record(Family::V4, b"announcement", sent);
  // The recording tick ran long. The seal that follows is the credit's first
  // claim opportunity, so its age there is zero and the full TTL is ahead of it.
  let opened = SELF_SEND_TTL + Duration::from_secs(5);
  t.seal_at(sent.mono + opened);
  assert!(
    consumed(t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &b"announcement"[..]),
      claim(sent, opened + SELF_SEND_TTL)
    )),
    "a sealed credit gets the whole TTL measured from the seal, not a remainder \
     of it measured from the send"
  );
}

/// The seal's own two phases, and the reading each one spends.
///
/// The sweep runs first and is a bulk one — up to `MAX_SELF_SEND_ENTRIES`
/// credits weighed against the reading it started from — so by the time it
/// returns that reading can be arbitrarily stale. Anchoring the batch it is
/// about to open at that same reading is the defect: the window opens already
/// expired, the very first claim against it is refused, and this endpoint
/// ingests its own loopback as peer traffic — a phantom conflict against itself
/// and the RFC 6762 §9 rename that follows.
///
/// Slept for real, past the TTL, because that is the condition: `seal` reads the
/// monotonic clock itself and `StdInstant` offers no constructor to fake it
/// with. The pause is injected into `seal` rather than into a copy of its body,
/// so a seal that went back to one reading fails here.
#[test]
fn a_stall_inside_the_seal_cannot_expire_the_batch_that_seal_opens() {
  let mut t = SelfSendTracker::new();
  t.record(Family::V4, b"announcement", send_stamps());
  t.pause_next_seal_for_test(STALL_PAST_TTL);
  t.seal();
  assert!(
    consumed(t.claim(&RxDatagram::without_stamp(Family::V4, &b"announcement"[..]))),
    "the whole of the seal's pre-claim work happens before the anchor is read, \
     so a credit recorded by the previous tick is claimable however long that \
     work took — anchoring it at the reading the sweep already spent hands a \
     newly-opened window an anchor from before it"
  );
}

#[test]
fn recording_sweeps_nothing() {
  // The sweep moved to `seal` with the anchor, and this is why: a record-time
  // sweep ages every live credit against whatever instant THIS send reached, so
  // a second fan-out or a stage-7 goodbye later in the same tick could evict a
  // credit whose echo had not yet had one opportunity to claim it.
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"earlier", sent);
  t.record(Family::V4, b"later", sent);
  assert_eq!(t.len(), 2, "a record must never evict anything");
  assert!(
    consumed(t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &b"earlier"[..]),
      sent
    )),
    "the earlier credit is untouched by the later record"
  );
}

#[test]
fn sealing_sweeps_entries_older_than_the_ttl() {
  // Eviction is by TTL relative to the tick that is opening a claim window, not
  // by ring position and not by the arrival of another send.
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"stale", sent);
  assert_eq!(t.len(), 1);
  t.record(Family::V4, b"fresh", sent);
  let much_later = claim(sent, SELF_SEND_TTL + Duration::from_secs(1));
  t.seal_at(much_later.mono);
  // The stale entry was swept by the seal, not merely outvoted.
  assert_eq!(t.len(), 1);
  assert!(!consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"stale"[..]),
    much_later
  )));
  assert!(consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"fresh"[..]),
    much_later
  )));
}

/// The upper end of the invariant, and the reason the seal uses
/// `get_or_insert` rather than an unconditional assignment.
///
/// Post-opportunity time must be charged, caller stalls included: the TTL's
/// other job is bounding FALSE suppression, and a co-resident peer's
/// byte-identical datagram can arrive during a caller stall exactly as it can
/// during a tick. A seal that re-anchored on every tick, or an age counted in
/// ticks rather than in elapsed time, would couple the suppression window to
/// the caller's loop rate and never expire a credit on a slow caller.
///
/// This is also the accepted residual documented on `SELF_SEND_TTL`: a caller
/// that stalls a full TTL between two ticks loses a pending credit. That caller
/// has already broken the once-per-iteration contract, and a gap that size
/// mis-times RFC 6762 probing and §8.3 spacing regardless.
#[test]
fn a_caller_gap_after_the_seal_still_expires_the_credit() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  // The caller went away for longer than the TTL and came back. The credit's
  // window opened at the send's own instant and has now run out.
  let after_the_gap = claim(sent, SELF_SEND_TTL + Duration::from_millis(1));
  assert!(
    !consumed(t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &b"payload"[..]),
      after_the_gap
    )),
    "elapsed time after the first claim opportunity is charged in full, or the \
     false-suppression bound is not a bound at all"
  );
  t.seal_at(after_the_gap.mono);
  assert_eq!(
    t.len(),
    0,
    "and the seal that observes the gap sweeps it, rather than re-anchoring it \
     forward for another whole TTL"
  );
}

#[test]
fn non_matching_body_is_never_taken() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  assert!(!consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"other"[..]),
    sent
  )));
}

/// The dual-stack echo race, deterministically.
///
/// One multicast transmit is two syscalls with **identical bytes** and two
/// separately-stamped credits. The receive rotor does not fix which socket is
/// read first, so the later IPv6 echo can be read before the earlier IPv4 one.
/// Without the family key the IPv6 echo consumes the older IPv4 credit and the
/// IPv4 echo — stamped by the kernel *before* the surviving IPv6 credit — is
/// rejected by `Ordered` matching and ingested as peer traffic.
#[test]
fn an_ipv6_echo_read_first_cannot_steal_the_ipv4_credit() {
  let mut t = SelfSendTracker::new();
  let v4_sent = send_stamps();
  // Ordered, distinct stamps: the fan-out is two syscalls, IPv4 first, and
  // ordering is the only thing that still distinguishes them. Both credits are
  // recorded in one tick and share the next tick's seal, so neither ages ahead
  // of the other.
  let v6_sent = claim(v4_sent, Duration::from_millis(5));
  t.record(Family::V4, b"announcement", v4_sent);
  t.record(Family::V6, b"announcement", v6_sent);
  let top = claim(v4_sent, Duration::from_millis(10));
  t.seal_at(top.mono);

  // The rotor reads IPv6 first. Its kernel stamp is at-or-after the IPv6 send
  // but AFTER the IPv4 send too, so both credits look eligible on content.
  let v6_rx = v6_sent.wall + Duration::from_micros(50);
  assert!(consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V6, &b"announcement"[..], v6_rx),
    top
  )));

  // The IPv4 echo now arrives, stamped between the two sends — before the IPv6
  // credit. It matches only because its own credit is still there.
  let v4_rx = v4_sent.wall + Duration::from_micros(50);
  assert!(
    consumed(t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, &b"announcement"[..], v4_rx),
      top
    )),
    "the IPv4 echo must find its own credit, not one already spent by IPv6"
  );
  assert_eq!(t.len(), 0, "both credits are spent exactly once");
}

/// The same race, with every margin expressed against
/// [`crate::RX_TIMESTAMP_GRAIN`] so the test means the same thing on a
/// **zero-grain** target as on a microsecond one.
///
/// The grain is the only slack `Ordered` has, and on Linux it is exactly zero.
/// So the interesting question is not whether the stolen-credit case is refused
/// by *some* margin, but whether the margin survives a platform that grants
/// none: with the credits interchangeable, the IPv4 echo would be weighed
/// against the IPv6 send, which is a whole inter-syscall gap later than the
/// kernel stamp it carries — outside the grain on every target, and outside
/// **any** grain on the target where the grain is zero. That is a phantom
/// self-conflict and the spurious RFC 6762 §9 rename that follows, with no clock
/// step involved at all.
#[test]
fn the_dual_stack_stamp_race_is_closed_at_every_timestamp_grain() {
  // One inter-syscall gap, and it must be wider than the slack `Ordered` gives,
  // or the grain would absorb the race rather than the family key closing it.
  let gap = crate::RX_TIMESTAMP_GRAIN + Duration::from_micros(1);
  assert!(gap > crate::RX_TIMESTAMP_GRAIN);

  let mut t = SelfSendTracker::new();
  let v4_sent = send_stamps();
  let v6_sent = claim(v4_sent, gap);
  t.record(Family::V4, b"probe", v4_sent);
  t.record(Family::V6, b"probe", v6_sent);
  let top = claim(v6_sent, Duration::from_millis(1));
  t.seal_at(top.mono);

  // The kernel stamps each echo at its own send: `join` polls IPv4 first, so the
  // IPv4 echo's stamp structurally predates the IPv6 credit.
  let v4_rx = v4_sent.wall;
  let v6_rx = v6_sent.wall;
  assert!(
    v6_sent.wall.duration_since(v4_sent.wall).expect("ordered") > crate::RX_TIMESTAMP_GRAIN,
    "the IPv4 echo must sit further before the IPv6 credit than the grain can \
     forgive, or this test would pass without the family key"
  );

  // Drained in the opposite order to the sends.
  assert!(consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V6, &b"probe"[..], v6_rx),
    top
  )));
  assert!(
    consumed(t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, &b"probe"[..], v4_rx),
      top
    )),
    "each echo claims the credit recorded on its own family; unkeyed, the IPv6 \
     echo takes the IPv4 credit and this claim is refused as a peer's"
  );
  assert_eq!(t.len(), 0);
}

/// The family key is a filter, not a tiebreak: a credit recorded for one family
/// is never available to the other, so a peer datagram arriving on the family
/// we did not send on is still seen as a peer.
#[test]
fn a_credit_is_not_visible_to_the_other_family() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  let rx = sent.wall + Duration::from_millis(1);
  assert!(!consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V6, &b"payload"[..], rx),
    sent
  )));
  assert!(consumed(t.claim_at(
    &RxDatagram::from_stamp_for_test(Family::V4, &b"payload"[..], rx),
    sent
  )));
}

#[test]
fn a_backwards_wall_clock_step_cannot_evict_or_expire_a_credit() {
  // Ageing is monotonic, so a wall clock that steps backwards between two sends
  // — an NTP correction, a manual `settimeofday` — can neither sweep a live
  // credit on `seal` nor expire one on `claim`. The wall stamp still has a job
  // (ordering the echo against the send), which is why the step is visible at
  // all; it just no longer decides anyone's lifetime. Losing a credit is worse
  // than over-retaining one: it makes the responder treat its own loopback as a
  // peer and raise a phantom conflict against itself.
  let mut t = SelfSendTracker::new();
  let first = ClockPair::new(SystemTime::UNIX_EPOCH + Duration::from_secs(20), mono());
  recorded_and_sealed(&mut t, Family::V4, b"already-recorded", first);
  // The clock stepped backwards: this send's WALL stamp predates the entry
  // above by ten seconds, while the seal that follows it is a millisecond after.
  let second = ClockPair::new(
    SystemTime::UNIX_EPOCH + Duration::from_secs(10),
    first.mono + Duration::from_millis(1),
  );
  recorded_and_sealed(&mut t, Family::V4, b"clock-stepped-back", second);
  assert_eq!(t.len(), 2, "a wall-clock step must not sweep a live credit");
  assert!(consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"already-recorded"[..]),
    ClockPair::new(first.wall, second.mono)
  )));
}

/// A credit matches only the body it stored: the tracker is content-addressed
/// on the bytes themselves, so a byte-different datagram must not consume
/// another's credit.
#[test]
fn a_credit_matches_only_the_body_it_stored() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V6, b"announcement", sent);
  assert!(!consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V6, &b"other"[..]),
    sent
  )));
  assert!(consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V6, &b"announcement"[..]),
    sent
  )));
}

/// A stall longer than [`SELF_SEND_TTL`], slept for real.
///
/// `record` and `seal` read the monotonic clock themselves — that is the whole
/// point of both the reclaim and the anchor being live rather than taken from
/// anything a caller hands in — so neither the two cap tests below nor
/// `a_stall_inside_the_seal_cannot_expire_the_batch_that_seal_opens` can fake the
/// elapsed time, and `StdInstant` offers no constructor to fake it with. Same
/// value and same reason as `driver/tests.rs`'s `STALL_PAST_TTL`.
const STALL_PAST_TTL: Duration = SELF_SEND_TTL.saturating_add(Duration::from_millis(50));

/// Seed a FULL tracker directly, every entry anchored at `aged_from`.
///
/// Straight into the private `entries` field (visible here: `tests` is a child
/// module of `selfsend`) instead of looping `record()`
/// `MAX_SELF_SEND_ENTRIES` times, so each fixture states the shape it wants
/// rather than arriving at it, and only the single `record()` call under test
/// exercises the cap logic.
fn full_tracker(sent: ClockPair, aged_from: Option<StdInstant>) -> SelfSendTracker {
  SelfSendTracker {
    entries: (0..MAX_SELF_SEND_ENTRIES)
      .map(|i| {
        let body = (i as u64).to_be_bytes().to_vec();
        Credit {
          family: Family::V4,
          // Derived here as `record` derives it, so a fixture cannot seed a
          // class its own bytes disagree with. See `SendClass`.
          class: SendClass::of(&body),
          body,
          generation: 0,
          sent,
          aged_from,
        }
      })
      .collect(),
    // Seeded straight into `entries`, so the byte accounting `admit` reads has
    // to be seeded with it — eight bytes per credit, matching the bodies above.
    bytes: MAX_SELF_SEND_ENTRIES.saturating_mul(8),
    ..SelfSendTracker::new()
  }
}

/// The cap counts credits that are still ALIVE, not corpses.
///
/// An expired sealed entry is removed by nothing but the next `seal`: `claim`
/// refuses it and leaves it resident. So a tracker filled and sealed, whose tick
/// then stalls past the TTL, is `MAX_SELF_SEND_ENTRIES` dead credits — and a
/// send later in that same tick would be refused its credit by entries not one
/// of which could ever match anything again. Its genuine loopback then arrives
/// with nothing to claim, is ingested as peer traffic, and the responder raises
/// a phantom conflict against itself.
#[test]
fn the_cap_reclaims_dead_credits_rather_than_refusing_a_new_one() {
  let sent = send_stamps();
  let mut t = full_tracker(sent, Some(sent.mono));
  // The tick ran on past the TTL after the seal that anchored every one of them.
  std::thread::sleep(STALL_PAST_TTL);
  let later = ClockPair::now();
  t.record(Family::V4, b"later-in-the-same-tick", later);
  assert_eq!(
    t.len(),
    1,
    "every entry was sealed and expired, so the cap had nothing live to protect"
  );
  // And the new credit behaves like any other: sealed at the next tick's top,
  // then claimed by its own echo.
  let top = StdInstant::now();
  t.seal_at(top);
  assert!(
    consumed(t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &b"later-in-the-same-tick"[..]),
      ClockPair::new(later.wall, top)
    )),
    "a tracker full of dead credits must not crowd out a live send's echo \
     suppression"
  );
}

/// The half of the old record-time sweep that must never come back.
///
/// Every entry here is UNSEALED, so however long this tick has been running not
/// one of their echoes has had a single opportunity to claim them. The cap path
/// may not reclaim any of them — it drops the NEW entry instead, which is the
/// cheap direction: one datagram of ours ingested as a peer's, against
/// `MAX_SELF_SEND_ENTRIES` of them.
#[test]
fn the_cap_never_reclaims_an_unsealed_credit() {
  let sent = send_stamps();
  let mut t = full_tracker(sent, None);
  // Long enough that ageing these against the live clock would evict every one.
  std::thread::sleep(STALL_PAST_TTL);
  t.record(Family::V4, b"one-too-many", ClockPair::now());
  assert_eq!(
    t.len(),
    MAX_SELF_SEND_ENTRIES,
    "an unsealed credit has no window open and no age; elapsed time cannot \
     reclaim it, so the cap is still full and the NEW entry is what goes"
  );
  let now = ClockPair::now();
  assert!(!consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"one-too-many"[..]),
    now
  )));
  assert!(
    consumed(t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &0u64.to_be_bytes()[..]),
      now
    )),
    "and the first-seeded credit is still there: the cap never evicts to make \
     room"
  );
}

#[test]
fn the_entry_cap_drops_the_new_entry_not_the_oldest() {
  let sent = send_stamps();
  // Full of credits that are sealed and still well inside their TTL: the
  // reclaim finds nothing to take, so this is the cap rule on its own.
  let mut t = full_tracker(sent, Some(sent.mono));
  assert_eq!(t.len(), MAX_SELF_SEND_ENTRIES);
  t.record(Family::V4, b"one-too-many", sent);
  // One more record() leaves len() at the cap: the new entry was dropped.
  assert_eq!(
    t.len(),
    MAX_SELF_SEND_ENTRIES,
    "the cap drops the NEW entry"
  );
  assert!(!consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &b"one-too-many"[..]),
    sent
  )));
  // The first-seeded entry is still present — the oldest is NOT evicted.
  assert!(consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &0u64.to_be_bytes()[..]),
    sent
  )));
}

// ── the cap's admission decision ────────────────────────────────────────────
//
// The cap is enforced in two steps and only the second is a decision. The bulk
// reclaim weighs up to `MAX_SELF_SEND_ENTRIES` credits against ONE instant read
// before it started, so a credit that was live when it looked at it can be dead
// by the time it returns; deciding the cap on the length that sweep left behind
// refuses a live send's credit in order to keep corpses resident. A refused
// credit is not a lost byte — it is this endpoint ingesting its own loopback as
// peer traffic, a phantom conflict against itself and the RFC 6762 §9 rename
// that follows.

/// Fill a tracker to exactly [`MAX_SELF_SEND_ENTRIES`] with distinct bodies, and
/// open every credit's window at `at`.
fn full_tracker_sealed_at(at: StdInstant) -> SelfSendTracker {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  for i in 0..MAX_SELF_SEND_ENTRIES {
    t.record(Family::V4, &(i as u64).to_le_bytes(), sent);
  }
  t.seal_at(at);
  assert_eq!(
    t.len(),
    MAX_SELF_SEND_ENTRIES,
    "the tracker must start full"
  );
  t
}

/// A sweep that finished before its own findings did. Every credit is dead at
/// the admission decision, and every one of them was live at the instant the
/// sweep weighed it — which is exactly what a 65 536-entry scan does to the
/// reading it started from.
///
/// The sweep's clock is the only thing held still: the admission below reads the
/// live clock here as it does in every build.
#[test]
fn the_cap_admits_against_the_clock_at_the_decision_not_the_sweeps() {
  let base = mono();
  let mut t = full_tracker_sealed_at(base);
  // Real time runs past every credit's TTL while the sweep's reading does not.
  std::thread::sleep(SELF_SEND_TTL + Duration::from_millis(50));
  t.record_with_stale_sweep(Family::V4, b"fresh", send_stamps(), base);
  assert!(
    consumed(t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &b"fresh"[..]),
      ClockPair::now()
    )),
    "every resident credit was already dead when the cap was decided, so the \
     new send must have been given one — refusing it makes this endpoint ingest \
     its own loopback as a peer's datagram"
  );
}

/// The other direction, and the one the cap exists for: a tracker whose credits
/// are all genuinely live still refuses the new one rather than evicting any of
/// them.
#[test]
fn the_cap_still_refuses_when_every_resident_credit_is_live() {
  let base = mono();
  let mut t = full_tracker_sealed_at(base);
  t.record(Family::V4, b"fresh", send_stamps());
  assert_eq!(
    t.len(),
    MAX_SELF_SEND_ENTRIES,
    "a live credit must never be displaced to make room"
  );
  assert!(
    !consumed(t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &b"fresh"[..]),
      ClockPair::now()
    )),
    "the NEW entry is the one dropped at the cap, never a live one"
  );
}

/// Insertion order **is** expiry order, which is what makes the admission above
/// an `O(1)` question instead of a scan that would go stale in turn.
///
/// Asserted over the interleaving that actually occurs: record, seal, record,
/// seal, record — so the anchors run `[t0, t1, unsealed]`, non-decreasing with
/// the unsealed suffix last.
#[test]
fn insertion_order_is_expiry_order() {
  let mut t = SelfSendTracker::new();
  let t0 = mono();
  t.record(Family::V4, b"first", send_stamps());
  t.seal_at(t0);
  t.record(Family::V4, b"second", send_stamps());
  t.seal_at(t0 + Duration::from_millis(10));
  t.record(Family::V4, b"third", send_stamps());
  let anchors = t.anchors_for_test();
  let mut previous: Option<StdInstant> = None;
  let mut unsealed_seen = false;
  for anchor in anchors {
    match anchor {
      Some(at) => {
        assert!(
          !unsealed_seen,
          "an unsealed credit expires never, so nothing sealed may follow one"
        );
        if let Some(prev) = previous {
          assert!(
            at >= prev,
            "anchors must be non-decreasing in storage order"
          );
        }
        previous = Some(at);
      }
      None => unsealed_seen = true,
    }
  }
  assert!(
    unsealed_seen,
    "the last record has not been sealed, so this must have exercised the \
     unsealed suffix"
  );
}

/// The coupled claim consumes the credit its own datagram matches, once, and
/// reports the strength the match ran at.
#[test]
fn claim_consumes_the_credit_and_reports_the_strength_it_ran_at() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  let now = claim(sent, Duration::from_millis(1));
  let echo = RxDatagram::from_stamp_for_test(
    Family::V4,
    &b"payload"[..],
    sent.wall + Duration::from_millis(1),
  );

  assert_eq!(
    t.claim_at(&echo, now),
    SelfSendMatch::Ordered,
    "a stamp at-or-after the send is ordering evidence, and the claim must say so rather than \
     collapsing to a bool"
  );
  // Take-once: a second byte-identical datagram is a
  // peer's, and the tier says so without claiming to know anything about the
  // network.
  assert_eq!(t.claim_at(&echo, now), SelfSendMatch::NoCredit);
}

/// A datagram that carries no stamp is claimed under `Degraded` — a match, and
/// a weaker one. The two positive tiers must not be collapsed by the caller, so
/// they must not be collapsed here either.
#[test]
fn claim_without_a_stamp_reports_degraded() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  let echo = RxDatagram::without_stamp(Family::V4, &b"payload"[..]);
  assert_eq!(
    t.claim_at(&echo, claim(sent, Duration::from_millis(1))),
    SelfSendMatch::Degraded,
    "no timestamp cmsg means no ordering evidence, which is a real match at a lower strength and \
     not a failure"
  );
}

/// The datagram's OWN family is the key. A credit recorded on one socket cannot
/// be claimed by a datagram that arrived on the other — the dual-stack echo race
/// `SelfSendTracker::claim` documents — and with the family carried by the
/// datagram there is no separate argument that could disagree with the body.
#[test]
fn claim_keys_on_the_family_the_datagram_arrived_on() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  let now = claim(sent, Duration::from_millis(1));
  let wrong_socket = RxDatagram::from_stamp_for_test(
    Family::V6,
    &b"payload"[..],
    sent.wall + Duration::from_millis(1),
  );
  assert_eq!(
    t.claim_at(&wrong_socket, now),
    SelfSendMatch::NoCredit,
    "an echo can only arrive on the socket its copy left from"
  );
  assert_eq!(
    t.len(),
    1,
    "and the IPv4 credit must survive for its own echo"
  );
}

/// The body may be borrowed or owned, and a claim cannot tell the difference.
///
/// The `Cow` is there because the drivers carry payloads three ways — a channel
/// hand-off that must own, a reused receive buffer that must not allocate, and a
/// completion-based receive that already owns a `Vec`. Both shapes must reach
/// the same credit.
#[test]
fn a_body_may_be_borrowed_or_owned() {
  let sent = send_stamps();
  let now = claim(sent, Duration::from_millis(1));

  let mut borrowed_side = SelfSendTracker::new();
  recorded_and_sealed(&mut borrowed_side, Family::V4, b"payload", sent);
  let borrowed = RxDatagram::without_stamp(Family::V4, &b"payload"[..]);
  assert_eq!(borrowed.body(), b"payload");
  assert_eq!(
    borrowed_side.claim_at(&borrowed, now),
    SelfSendMatch::Degraded
  );

  let mut owned_side = SelfSendTracker::new();
  recorded_and_sealed(&mut owned_side, Family::V4, b"payload", sent);
  let owned = RxDatagram::without_stamp(Family::V4, b"payload".to_vec());
  assert_eq!(owned.body(), b"payload");
  assert_eq!(owned_side.claim_at(&owned, now), SelfSendMatch::Degraded);
  assert_eq!(
    owned.into_body().into_owned(),
    b"payload".to_vec(),
    "and the payload survives the claim, since a driver still has to hand it to the protocol layer"
  );
}

/// `recv_datagram` slices the body to the length ITS OWN receive reported, so no
/// caller picks one.
///
/// That is the whole of what the mint adds over `from_recv_parts`: the body, the
/// family and the stamp are all decided inside one call, next to the syscall
/// that produced them. Exercised against a real socket rather than a synthesized
/// buffer, because the length under test is the kernel's.
#[cfg(unix)]
#[test]
fn recv_datagram_slices_the_body_to_its_own_receives_length() {
  use std::{net::UdpSocket, os::fd::AsRawFd};

  let receiver = UdpSocket::bind("127.0.0.1:0").expect(
    "binding an ephemeral loopback UDP socket must succeed: this test's subject is a real \
     receive, so a bind that did not happen is a failure and never a skip",
  );
  receiver
    .set_read_timeout(Some(Duration::from_secs(5)))
    .expect(
      "a read timeout must be settable, so a lost datagram fails this test instead of \
             hanging it",
    );
  let addr = receiver
    .local_addr()
    .expect("a bound socket has an address");
  let sender = UdpSocket::bind("127.0.0.1:0").expect("binding the sending socket must succeed");
  let payload = b"one datagram, one length";
  sender
    .send_to(payload, addr)
    .expect("a loopback send to a bound socket must succeed");

  // Deliberately much larger than the datagram: a mint that handed back the
  // buffer, or a caller-chosen length, would show up here as trailing zeros.
  let mut buf = [0u8; 512];
  let (rx, meta) = super::recv_datagram(receiver.as_raw_fd(), &mut buf, Family::V4)
    .expect("the datagram was already queued by the send above");
  assert_eq!(
    rx.body(),
    payload,
    "the body must be exactly the bytes the kernel delivered"
  );
  assert_eq!(
    meta.len(),
    payload.len(),
    "and the meta must agree with the body it was minted beside"
  );
  assert_eq!(rx.family(), Family::V4);
}

// ── the record generation ───────────────────────────────────────────────────
//
// A self-echo is safe to adjudicate only while it still describes records this
// endpoint holds. Service replacement breaks that across generations with no
// RFC 6762 §8.4 record-updating API involved: a route withdrawing at host H no
// longer holds H for the registration guard, so a replacement takes H with a
// different address set while the outgoing goodbye drains, and a delayed echo of
// the old announcement is then differing host rdata against the replacement's
// own records — a terminal `HostConflict` raised by our own past.

/// A credit outlives the generation it was recorded in, and says so.
///
/// The match itself is untouched — same bytes, same family, same ordering
/// evidence, inside the TTL — and that is the point: the credit is still ours.
/// What changes is that it may no longer adjudicate, which the caller reads off
/// the variant.
#[test]
fn a_credit_recorded_before_a_supersede_is_reported_as_superseded() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"announce-generation-one", sent);
  // The service that sent it is retired and a replacement registers.
  t.supersede();
  let rx = sent.wall + Duration::from_millis(1);
  let now = claim(sent, Duration::from_millis(1));
  assert_eq!(
    t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, &b"announce-generation-one"[..], rx),
      now
    ),
    SelfSendMatch::Superseded,
    "an echo of a datagram sent before the records changed must not reach the \
     adjudicating tier"
  );
  assert_eq!(
    t.len(),
    1,
    "and it is a STANDING tombstone: the claim spends nothing"
  );
}

/// THE TOMBSTONE. Every byte-identical copy inside the TTL reads `Superseded`,
/// however many arrive.
///
/// Take-once used to apply here too, so the FIRST copy consumed the credit and
/// every copy behind it read `NoCredit` — `Provenance::NotFromUs` — and was
/// admitted as peer traffic. That second copy needs no attacker: one send is
/// credited once per family while the medium may deliver several copies (kernel
/// loopback plus an 802.11 base-station re-broadcast, which RFC 6762 §8.2 names
/// as an echo source), so the loser of that race wrote records this endpoint no
/// longer publishes into this endpoint's own cache.
///
/// Spending bought nothing in exchange. These bytes assert a record set this
/// endpoint has GIVEN UP: suppressing every copy can only mask an assertion no
/// live route holds, or a byte-identical twin still asserting our withdrawn
/// records — a bounded detection delay — while an attacker "denied" the replay
/// could always have forged the same assertion without our bytes.
#[test]
fn a_superseded_credit_answers_every_copy_of_the_same_datagram() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"withdrawn-announcement", sent);
  t.supersede();
  for round in 1..=5u32 {
    let gap = Duration::from_millis(u64::from(round));
    assert_eq!(
      t.claim_at(
        &RxDatagram::from_stamp_for_test(
          Family::V4,
          &b"withdrawn-announcement"[..],
          sent.wall + gap
        ),
        claim(sent, gap)
      ),
      SelfSendMatch::Superseded,
      "copy {round} of a datagram whose records we no longer publish must not \
       become peer traffic because an earlier copy consumed the credit"
    );
  }
  assert_eq!(t.len(), 1, "no copy spends the tombstone");
}

/// A CURRENT credit is preferred over a superseded one holding the same bytes.
///
/// The same datagram can be recorded on both sides of a generation change — a
/// service re-announcing bytes it also sent before an unrelated service
/// registered. With the tombstone standing, taking the first match in order
/// would let the older superseded copy answer for the whole TTL, and the current
/// tier's take-once — which exists so a conforming RFC 6762 §9 twin becomes
/// visible from its second datagram — would never run at all.
#[test]
fn a_current_credit_wins_over_an_older_superseded_copy_of_itself() {
  let mut t = SelfSendTracker::new();
  let first = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"same-bytes-both-sides", first);
  t.supersede();
  recorded_and_sealed(&mut t, Family::V4, b"same-bytes-both-sides", first);
  let gap = Duration::from_millis(1);
  assert_eq!(
    t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, &b"same-bytes-both-sides"[..], first.wall + gap),
      claim(first, gap)
    ),
    SelfSendMatch::Ordered,
    "the still-current credit decides, not the superseded copy ahead of it"
  );
  assert_eq!(
    t.len(),
    1,
    "and it was the CURRENT one that was spent — the tombstone remains"
  );
  assert_eq!(
    t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, &b"same-bytes-both-sides"[..], first.wall + gap),
      claim(first, gap)
    ),
    SelfSendMatch::Superseded,
    "with the current credit spent, the tombstone answers the next copy"
  );
}

/// The other direction, so the generation cannot silently swallow every claim: a
/// credit recorded AFTER the supersede reports its ordinary tier.
#[test]
fn a_credit_recorded_after_a_supersede_keeps_its_ordinary_tier() {
  let mut t = SelfSendTracker::new();
  t.supersede();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"announce-generation-two", sent);
  let rx = sent.wall + Duration::from_millis(1);
  let now = claim(sent, Duration::from_millis(1));
  assert_eq!(
    t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, &b"announce-generation-two"[..], rx),
      now
    ),
    SelfSendMatch::Ordered
  );
}

/// A supersede does not DROP the credits it retires.
///
/// Dropping them would make exactly the echoes this protects against read as
/// `NoCredit` — full peer traffic, full adjudication — which is the failure it
/// exists to prevent, only louder.
#[test]
fn a_supersede_retires_credits_without_discarding_them() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"still-here", sent);
  t.supersede();
  assert_eq!(t.len(), 1, "the credit must survive the generation change");
  assert_ne!(
    t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &b"still-here"[..]),
      claim(sent, Duration::from_millis(1))
    ),
    SelfSendMatch::NoCredit,
    "a discarded credit would send our own echo to the protocol layer as a \
     peer's datagram, which is strictly worse than not adjudicating it"
  );
}

// ── what the generation may retire, and what it may not ─────────────────────
//
// The generation answers one question: has what this endpoint PUBLISHES changed
// since this datagram was sent? A datagram that asserts records can go stale
// that way. A question cannot — it asserts nothing, so there is nothing in it
// for a registration or a withdrawal to invalidate.

/// A structurally valid mDNS QUERY: one question for `_http._tcp.local. PTR IN`
/// and not a single resource record.
///
/// QR=0 and every record count is zero, which is exactly the shape this
/// workspace's core puts on the wire for a continuous query — `Query::poll_transmit`
/// encodes the question alone, with no RFC 6762 §7.1 known-answer list behind it.
const QUERY_HTTP_PTR: &[u8] = &[
  // ID, flags (QR=0, opcode QUERY), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0.
  0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
  // QNAME `_http._tcp.local.`
  0x05, b'_', b'h', b't', b't', b'p', 0x04, b'_', b't', b'c', b'p', 0x05, b'l', b'o', b'c', b'a',
  b'l', 0x00, //
  // QTYPE = PTR, QCLASS = IN
  0x00, 0x0c, 0x00, 0x01,
];

/// A structurally valid RFC 6762 §8.2 PROBE: `hick.local. ANY IN` asked with the
/// proposed `A` record in the AUTHORITY section.
///
/// QR=0, so it is a query by the header's own bit — and it still asserts, which
/// is why the class cannot be read off that bit alone. The rdata it proposes is
/// exactly what a registration or a withdrawal can make stale.
const PROBE_HICK_A: &[u8] = &[
  // ID, flags (QR=0), QDCOUNT=1, ANCOUNT=0, NSCOUNT=1, ARCOUNT=0.
  0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, //
  // QNAME `hick.local.`, QTYPE = ANY, QCLASS = IN
  0x04, b'h', b'i', b'c', b'k', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00, 0xff, 0x00, 0x01,
  //
  // AUTHORITY: name compressed to offset 12, A, IN, TTL 120, 192.0.2.1
  0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
];

/// A QUESTION SURVIVES A PUBLICATION CHANGE AS A TAKE-ONCE CREDIT.
///
/// The generation was applied to the whole log, so a service registration — or a
/// withdrawal, or a §9 rename — retired every outstanding credit including the
/// ones for datagrams that assert nothing. A superseded credit is deliberately
/// non-consuming, so a query credit became a STANDING TOMBSTONE: every
/// byte-identical copy read `Superseded`, every driver maps that to
/// `Provenance::OwnEcho`, and `OwnEcho` suppresses the whole datagram. A peer's
/// query retransmission from port 5353 — RFC 6762 §5.2 schedules them, so these
/// are ordinary traffic and not a corner case — was then invisible for the rest
/// of the credit's life instead of for the one copy take-once costs.
///
/// Nothing about a question can be made stale by what this endpoint publishes:
/// its records are questions rather than claims, so its echo can carry no rdata
/// we have given up.
#[test]
fn a_question_credit_stays_take_once_across_a_publication_change() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, QUERY_HTTP_PTR, sent);
  // An UNRELATED service registers, withdraws, or renames.
  t.supersede();

  let first = Duration::from_millis(1);
  assert_eq!(
    t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, QUERY_HTTP_PTR, sent.wall + first),
      claim(sent, first)
    ),
    SelfSendMatch::Ordered,
    "a publication change says nothing about a question, so the credit is still \
     current and our own echo takes it"
  );
  assert!(
    t.is_empty(),
    "and taking it SPENDS it — a question left standing as a tombstone would \
     answer every copy for the rest of the TTL"
  );

  let second = Duration::from_millis(2);
  assert_eq!(
    t.claim_at(
      &RxDatagram::from_stamp_for_test(Family::V4, QUERY_HTTP_PTR, sent.wall + second),
      claim(sent, second)
    ),
    SelfSendMatch::NoCredit,
    "so a peer's byte-identical §5.2 retransmission is peer traffic, which is \
     the whole of what take-once buys"
  );
}

/// The boundary is what the datagram ASSERTS, not the header's QR bit: an RFC
/// 6762 §8.2 probe is a query that proposes records, and those records are
/// exactly what a registration or a withdrawal can retire.
///
/// So the tombstone still stands here, and it stands for every copy — the
/// property the previous round bought, which this one must not spend.
#[test]
fn a_probe_is_still_superseded_although_its_header_says_query() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, PROBE_HICK_A, sent);
  t.supersede();
  for round in 1..=3u32 {
    let gap = Duration::from_millis(u64::from(round));
    assert_eq!(
      t.claim_at(
        &RxDatagram::from_stamp_for_test(Family::V4, PROBE_HICK_A, sent.wall + gap),
        claim(sent, gap)
      ),
      SelfSendMatch::Superseded,
      "copy {round} proposes rdata this endpoint may no longer hold, so the \
       tombstone answers it"
    );
  }
  assert_eq!(t.len(), 1, "and no copy spends it");
}

// ── the byte budget ─────────────────────────────────────────────────────────

/// The byte budget refuses the NEW entry, exactly as the entry cap does, and
/// never evicts a live credit to make room.
#[test]
fn the_byte_budget_drops_the_new_entry_not_a_live_one() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  // Two datagrams that together exceed the budget: the first fits, the second
  // cannot, and the first is live.
  let big = std::vec![0xa5u8; MAX_SELF_SEND_BYTES / 2 + 1];
  let other = std::vec![0x5au8; MAX_SELF_SEND_BYTES / 2 + 1];
  recorded_and_sealed(&mut t, Family::V4, &big, sent);
  t.record(Family::V4, &other, sent);
  assert_eq!(t.len(), 1, "the budget drops the NEW entry");
  let now = claim(sent, Duration::from_millis(1));
  assert!(!consumed(t.claim_at(
    &RxDatagram::without_stamp(Family::V4, &other[..]),
    now
  )));
  assert!(
    consumed(t.claim_at(&RxDatagram::without_stamp(Family::V4, &big[..]), now)),
    "the live credit is never displaced"
  );
}

/// Dead credits are reclaimed to make room for a live send's, and the budget is
/// what decides how many — one freed entry slot is not one freed kilobyte.
#[test]
fn the_byte_budget_reclaims_dead_credits_rather_than_refusing_a_new_one() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  for i in 0..4u8 {
    let mut body = std::vec![0x11u8; MAX_SELF_SEND_BYTES / 4];
    body.truncate((MAX_SELF_SEND_BYTES / 4).saturating_sub(usize::from(i)));
    t.record(Family::V4, &body, sent);
  }
  t.seal();
  assert_eq!(t.len(), 4, "the tracker must start at the budget");
  std::thread::sleep(STALL_PAST_TTL);
  // Every resident credit is dead now, so a live send must still get one — and
  // it needs THREE of them reclaimed, not one, to fit.
  let later = ClockPair::now();
  let wide = std::vec![0x22u8; (MAX_SELF_SEND_BYTES / 4).saturating_mul(3)];
  t.record(Family::V4, &wide, later);
  let top = StdInstant::now();
  t.seal_at(top);
  assert!(
    consumed(t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &wide[..]),
      ClockPair::new(later.wall, top)
    )),
    "a budget full of corpses must not crowd out a live send's echo suppression"
  );
}

/// A datagram larger than the whole budget is refused rather than emptying the
/// tracker for something that still would not fit.
#[test]
fn a_datagram_larger_than_the_budget_is_refused_and_takes_nothing_with_it() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"resident", sent);
  let huge = std::vec![0u8; MAX_SELF_SEND_BYTES + 1];
  t.record(Family::V4, &huge, sent);
  assert_eq!(t.len(), 1, "the oversized entry is refused");
  assert!(
    consumed(t.claim_at(
      &RxDatagram::without_stamp(Family::V4, &b"resident"[..]),
      claim(sent, Duration::from_millis(1))
    )),
    "and a refusal leaves the tracker exactly as it found it"
  );
}

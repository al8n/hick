use std::time::{Duration, Instant as StdInstant, SystemTime};

use super::{
  ClockPair, Credit, MAX_SELF_SEND_ENTRIES, RxEvidence, SELF_SEND_TTL, SelfSendTracker,
  WALL_STEP_TOLERANCE, fnv1a,
};
use crate::Family;

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

#[test]
fn hash_is_content_addressed() {
  assert_eq!(fnv1a(b"abc"), fnv1a(b"abc"));
  assert_ne!(fnv1a(b"abc"), fnv1a(b"abd"));
}

#[test]
fn take_once_consumes_the_credit() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  let rx = RxEvidence::from_caller_parsed_cmsg(sent.wall + Duration::from_millis(1));
  let now = claim(sent, Duration::from_millis(1));
  assert!(t.take_at(Family::V4, b"payload", rx, now));
  // Second identical datagram is a genuine peer packet: no credit left.
  assert!(!t.take_at(Family::V4, b"payload", rx, now));
}

#[test]
fn ordered_mode_rejects_a_packet_stamped_before_our_send() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  // Kernel stamped this BEFORE we sent -> cannot be our loopback.
  let earlier =
    RxEvidence::from_caller_parsed_cmsg(SystemTime::UNIX_EPOCH + Duration::from_secs(9));
  assert!(!t.take_at(Family::V4, b"payload", earlier, sent));
  // The credit must survive for the real loopback copy.
  assert!(t.take_at(
    Family::V4,
    b"payload",
    RxEvidence::from_caller_parsed_cmsg(sent.wall + Duration::from_millis(1)),
    sent
  ));
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
  assert!(t.take_at(Family::V4, b"payload", RxEvidence::none(), stepped_back));
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
  assert!(!t.take_at(
    Family::V4,
    b"payload",
    RxEvidence::from_caller_parsed_cmsg(just_outside_grain),
    sent
  ));
  // Exactly one grain early is inside the truncation tolerance.
  let within = sent.wall - crate::RX_TIMESTAMP_GRAIN;
  assert!(t.take_at(
    Family::V4,
    b"payload",
    RxEvidence::from_caller_parsed_cmsg(within),
    sent
  ));
  // A full second early is a peer packet the kernel saw before our sendto.
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  let way_early =
    RxEvidence::from_caller_parsed_cmsg(SystemTime::UNIX_EPOCH + Duration::from_secs(9));
  assert!(!t.take_at(Family::V4, b"payload", way_early, sent));
}

#[test]
fn a_credit_older_than_the_ttl_is_a_peer_not_our_echo() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V4, b"payload", sent);
  // Byte-identical and correctly ordered, but the credit has been waiting
  // longer than SELF_SEND_TTL -> a co-resident peer, not our echo.
  let late = claim(sent, SELF_SEND_TTL + Duration::from_millis(1));
  assert!(!t.take_at(Family::V4, b"payload", RxEvidence::none(), late));
  // Exactly at the TTL it still matches.
  assert!(t.take_at(
    Family::V4,
    b"payload",
    RxEvidence::none(),
    claim(sent, SELF_SEND_TTL)
  ));
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
  assert!(!t.take_at(
    Family::V4,
    b"payload",
    RxEvidence::from_caller_parsed_cmsg(sent.wall + Duration::from_secs(3)),
    expired
  ));
  // Inside the window it still matches.
  assert!(t.take_at(
    Family::V4,
    b"payload",
    RxEvidence::from_caller_parsed_cmsg(sent.wall + Duration::from_secs(2)),
    claim(sent, SELF_SEND_TTL)
  ));
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
  let rx = RxEvidence::from_caller_parsed_cmsg(sent.wall - STEP + Duration::from_micros(200));
  // The claim reads both clocks 300us of real time after the send.
  let now = ClockPair::new(
    sent.wall - STEP + Duration::from_micros(300),
    sent.mono + Duration::from_micros(300),
  );
  assert!(
    t.take_at(Family::V4, b"announcement", rx, now),
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
  let rx = RxEvidence::from_caller_parsed_cmsg(sent.wall - Duration::from_secs(1));
  // The wall clock jumped five seconds forward while one millisecond of real
  // time passed.
  let now = ClockPair::new(
    sent.wall + Duration::from_secs(5),
    sent.mono + Duration::from_millis(1),
  );
  assert!(
    t.take_at(Family::V4, b"announcement", rx, now),
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
    !t.take_at(
      Family::V4,
      b"announcement",
      RxEvidence::from_caller_parsed_cmsg(sent.wall - Duration::from_secs(1)),
      now
    ),
    "the evidence is still good, so a datagram the kernel saw before our send \
     must not take the credit"
  );
  assert!(
    t.take_at(
      Family::V4,
      b"announcement",
      RxEvidence::from_caller_parsed_cmsg(sent.wall + Duration::from_micros(200)),
      now
    ),
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
    !t.take_at(
      Family::V4,
      b"announcement",
      RxEvidence::from_caller_parsed_cmsg(sent.wall - Duration::from_secs(1)),
      now
    ),
    "nothing stepped inside this credit's window, so the ordering rule is intact \
     and a datagram stamped before our send is a peer's"
  );
  assert!(
    t.take_at(
      Family::V4,
      b"announcement",
      RxEvidence::from_caller_parsed_cmsg(sent.wall + Duration::from_micros(200)),
      now
    ),
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
  // stage today, so nothing unsealed is visible to a `take`. It must be live
  // anyway — a credit with no claim opportunity yet has nothing to have
  // outlived.
  assert!(t.take_at(Family::V4, b"announcement", RxEvidence::none(), much_later));
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
    t.take_at(
      Family::V4,
      b"announcement",
      RxEvidence::none(),
      claim(sent, opened + SELF_SEND_TTL)
    ),
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
    t.take(Family::V4, b"announcement", RxEvidence::none()),
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
    t.take_at(Family::V4, b"earlier", RxEvidence::none(), sent),
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
  assert!(!t.take_at(Family::V4, b"stale", RxEvidence::none(), much_later));
  assert!(t.take_at(Family::V4, b"fresh", RxEvidence::none(), much_later));
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
    !t.take_at(Family::V4, b"payload", RxEvidence::none(), after_the_gap),
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
  assert!(!t.take_at(Family::V4, b"other", RxEvidence::none(), sent));
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
  let v6_rx = RxEvidence::from_caller_parsed_cmsg(v6_sent.wall + Duration::from_micros(50));
  assert!(t.take_at(Family::V6, b"announcement", v6_rx, top));

  // The IPv4 echo now arrives, stamped between the two sends — before the IPv6
  // credit. It matches only because its own credit is still there.
  let v4_rx = RxEvidence::from_caller_parsed_cmsg(v4_sent.wall + Duration::from_micros(50));
  assert!(
    t.take_at(Family::V4, b"announcement", v4_rx, top),
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
  let v4_rx = RxEvidence::from_caller_parsed_cmsg(v4_sent.wall);
  let v6_rx = RxEvidence::from_caller_parsed_cmsg(v6_sent.wall);
  assert!(
    v6_sent.wall.duration_since(v4_sent.wall).expect("ordered") > crate::RX_TIMESTAMP_GRAIN,
    "the IPv4 echo must sit further before the IPv6 credit than the grain can \
     forgive, or this test would pass without the family key"
  );

  // Drained in the opposite order to the sends.
  assert!(t.take_at(Family::V6, b"probe", v6_rx, top));
  assert!(
    t.take_at(Family::V4, b"probe", v4_rx, top),
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
  let rx = RxEvidence::from_caller_parsed_cmsg(sent.wall + Duration::from_millis(1));
  assert!(!t.take_at(Family::V6, b"payload", rx, sent));
  assert!(t.take_at(Family::V4, b"payload", rx, sent));
}

#[test]
fn a_backwards_wall_clock_step_cannot_evict_or_expire_a_credit() {
  // Ageing is monotonic, so a wall clock that steps backwards between two sends
  // — an NTP correction, a manual `settimeofday` — can neither sweep a live
  // credit on `seal` nor expire one on `take`. The wall stamp still has a job
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
  assert!(t.take_at(
    Family::V4,
    b"already-recorded",
    RxEvidence::none(),
    ClockPair::new(first.wall, second.mono)
  ));
}

/// A credit matches only the body it fingerprints: the tracker is a content
/// hash, so a byte-different datagram must not consume another's credit.
#[test]
fn a_credit_matches_only_the_body_it_fingerprints() {
  let mut t = SelfSendTracker::new();
  let sent = send_stamps();
  recorded_and_sealed(&mut t, Family::V6, b"announcement", sent);
  assert!(!t.take_at(Family::V6, b"other", RxEvidence::none(), sent));
  assert!(t.take_at(Family::V6, b"announcement", RxEvidence::none(), sent));
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
      .map(|i| Credit {
        family: Family::V4,
        hash: fnv1a(&(i as u64).to_be_bytes()),
        sent,
        aged_from,
      })
      .collect(),
    ..SelfSendTracker::new()
  }
}

/// The cap counts credits that are still ALIVE, not corpses.
///
/// An expired sealed entry is removed by nothing but the next `seal`: `take`
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
    t.take_at(
      Family::V4,
      b"later-in-the-same-tick",
      RxEvidence::none(),
      ClockPair::new(later.wall, top)
    ),
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
  assert!(!t.take_at(Family::V4, b"one-too-many", RxEvidence::none(), now));
  assert!(
    t.take_at(Family::V4, &0u64.to_be_bytes(), RxEvidence::none(), now),
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
  assert!(!t.take_at(Family::V4, b"one-too-many", RxEvidence::none(), sent));
  // The first-seeded entry is still present — the oldest is NOT evicted.
  assert!(t.take_at(Family::V4, &0u64.to_be_bytes(), RxEvidence::none(), sent));
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
    t.take_at(Family::V4, b"fresh", RxEvidence::none(), ClockPair::now()),
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
    !t.take_at(Family::V4, b"fresh", RxEvidence::none(), ClockPair::now()),
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

//! Take-once tracker for our own multicast loopback.
//!
//! Joining the mDNS multicast group and sending to it means the kernel loops
//! our own datagrams straight back to us on the same socket. Without
//! suppression the driver would ingest its own announcements as if they came
//! from a peer, seeing phantom conflicts against itself. [`SelfSendTracker`]
//! fingerprints every datagram we send and consumes the matching credit when
//! the loopback copy arrives — take-once, so a genuine byte-identical
//! datagram from a co-resident peer received afterwards is still seen as a
//! peer, not swallowed as our own echo.
//!
//! `hick-compio/src/selfsend.rs` and `hick-reactor/src/driver/mod.rs` apply
//! the same take-once semantics for their own drivers; this module matches
//! them, and additionally keys every credit to the **address family it was
//! sent on** — see [`SelfSendTracker::take`] for the dual-stack echo race that
//! makes content-and-time matching alone insufficient here.

use std::time::{Duration, Instant as StdInstant, SystemTime};

use crate::socket::Family;

/// How long a recorded send stays eligible to match an inbound loopback,
/// measured from the **first instant its echo could be claimed** rather than
/// from the send. Multicast loopback is delivered on the same host within
/// microseconds, so 2s is generously longer than any real loopback latency,
/// while still short enough that a byte-identical datagram from a co-resident
/// peer arriving later is correctly treated as a peer rather than our echo.
/// Both [`MatchMode`]s are bounded above by this TTL.
///
/// # The clock starts at the first claim opportunity
///
/// **A credit's ageing must not begin until the first instant its echo is
/// claimable — the top of the tick after the recording tick — and from then on
/// charges real monotonic elapsed time, including caller latency.** Both halves
/// are load-bearing.
///
/// Intra-tick outbound time is *structurally* claim-free.
/// [`Mdns::tick`](crate::Mdns::tick) runs its receive stage **before** every
/// stage that sends, so nothing recorded during a tick can be claimed during
/// that same tick; the stretch between a record and the end of its own tick is
/// the driver's own scheduling, and charging it to a window that exists to
/// bound the echo's *flight* is a defect. It expired credits three separate
/// ways before this anchor moved: a stall between a send's pre-syscall stamp
/// and its syscall, a later send in the same tick stalling after an earlier
/// credit was already recorded, and a stage-7 goodbye recorded a full TTL after
/// the stage-4 announcement whose credit was still unclaimed. All three are the
/// one bug, and [`SelfSendTracker::seal`] closes all three at once — by
/// construction, wherever the outbound stages later move to.
///
/// Post-opportunity time, in contrast, **must** be charged, caller stalls
/// included. This TTL's other job is bounding FALSE suppression, and a
/// co-resident peer's byte-identical datagram can arrive during a caller stall
/// just as easily as during a tick. Excluding non-ticking time — ageing by tick
/// count, say — would couple the suppression window to the caller's tick rate,
/// which is wrong in both directions: a fast caller would expire live credits
/// and a slow one would suppress peer traffic indefinitely.
///
/// # Not the echo's arrival time
///
/// Ageing against when the echo *arrived* was considered and rejected. The only
/// arrival stamp is the kernel's rx wall clock, which re-couples this bound to
/// the wall clock and to the pre-syscall stamp — resurrecting the very defect
/// the two-stamp split exists to prevent — and [`MatchMode::Degraded`] has no
/// arrival stamp at all.
///
/// # It is measured on the MONOTONIC clock, and never on the wall clock
///
/// Ageing a credit is a *duration* question — "has this credit been waiting
/// longer than a loopback copy can take?" — and the wall clock answers it
/// wrongly twice over. It steps, so an NTP correction either expires a live
/// credit or keeps a dead one; and the only wall stamp a send has is read
/// **before** its syscall, so every microsecond between that read and the
/// kernel accepting the datagram is charged to the credit's life. Preemption, a
/// signal handler, a page fault, or the `EINTR` retry can each stretch that gap,
/// and a gap past this TTL makes a responder ingest its own announcement as
/// peer traffic — a phantom conflict against itself and the RFC 6762 §9 rename
/// that follows.
///
/// So [`Credit`] carries two stamps that must not be folded together:
/// [`Credit::sent`] orders the echo against the send, and
/// [`Credit::aged_from`] — monotonic, and set at the first claim opportunity —
/// is the only input to this bound. See both field docs for the one direction
/// each may be wrong in.
///
/// # What the false-suppression window really is
///
/// Not this constant alone. A byte-identical co-resident peer datagram can be
/// swallowed as our echo for up to **this TTL, plus the outbound residue of the
/// recording tick, plus one caller gap** — the residue because the credit does
/// not start ageing until the next tick's top, and the caller gap because that
/// top is whenever the caller comes back. On a caller that ticks at any sane
/// rate the extra is negligible against 2s, and it buys the elimination of the
/// under-retention direction, which is the expensive one: over-retaining costs
/// one mistaken peer datagram, while under-retaining makes this responder raise
/// a phantom conflict against **itself** and rename under RFC 6762 §9.
///
/// # Accepted residual
///
/// A caller that stalls for `SELF_SEND_TTL` or longer **after the seal**, with
/// an echo already pending, still expires that credit — between two ticks, or
/// inside the receive stage itself, since both are time the window was open and
/// the claim did not happen. The seal happened, the clock ran, and no claim got
/// to it. A stall that size already violates the once-per-loop-iteration
/// contract on [`Mdns::tick`](crate::Mdns::tick), and degrades RFC 6762 probe
/// timing and §8.3 announcement spacing regardless, so the endpoint is mis-timed
/// either way. It is unfixable without ageing from the echo's arrival time,
/// which the section above rules out and which [`MatchMode::Degraded`] cannot
/// supply at all — and forgiving it is not an option, because the forgiveness
/// would have no bound: the same stall is indistinguishable from the one during
/// which a co-resident peer's byte-identical datagram arrived.
pub(crate) const SELF_SEND_TTL: Duration = Duration::from_secs(2);

/// Memory backstop on live [`SelfSendTracker`] entries. The real bound is
/// [`SELF_SEND_TTL`]; under normal operation the tracker holds only a
/// handful of entries.
///
/// **It counts credits that are still alive.** At the cap,
/// [`SelfSendTracker::record`] first reclaims every entry that is already dead —
/// sealed and past the TTL — and then decides, against a clock read **at the
/// decision** ([`SelfSendTracker::admit`]), whether the new entry still has
/// nowhere to go. It never evicts a live one: a flood of sends must not
/// displace a credit that is still waiting to match its own loopback copy, and
/// equally a heap of corpses must not displace a credit that has not been
/// recorded yet. See [`SelfSendTracker::reclaim_expired_sealed`] for why only
/// the dead half is reclaimable, and [`SelfSendTracker::admit`] for why the
/// reclaim's own length is not an answer to the cap question.
pub(crate) const MAX_SELF_SEND_ENTRIES: usize = 65536;

/// How far the wall clock may disagree with the monotonic clock across a
/// credit's window before that credit's ordering evidence is treated as
/// unusable.
///
/// # What it is measuring
///
/// [`Credit::sent`] is the only thing that orders an echo against its send, and
/// its wall half is not monotonic. An NTP step, a `settimeofday`, a manual clock
/// change, or a VM suspend/resume moves it under a credit that is already
/// waiting, and the stamp then describes a timeline the echo's kernel receive
/// stamp was never taken on. A monotonic stamp cannot replace it — the kernel's
/// receive stamp is itself a realtime value, so there is nothing monotonic to
/// compare it against — so the fix is a second stamp rather than a different
/// one: every credit carries the monotonic partner of its wall stamp, every
/// claim reads both clocks the same way, and the difference of the two elapsed
/// times is what the wall clock did on its own. See [`ClockPair`].
///
/// # Why this size
///
/// It must sit **above** every legitimate disagreement. A disciplined wall clock
/// is slewed rather than stepped, at up to 500 ppm — 1 ms across
/// [`SELF_SEND_TTL`], and 5 ms even across a ten-second caller stall — on top of
/// each clock's own resolution and the few nanoseconds between the paired reads.
///
/// It must sit **below** every real step. `ntpd` slews rather than steps until
/// the offset passes 128 ms; `settimeofday`, a manual clock change and a VM
/// resume are larger still, usually by orders of magnitude.
///
/// # Accepted residual
///
/// A backward step smaller than this is invisible here and can still reject one
/// echo. [`reference_ordered`]'s [`hick_udp::RX_TIMESTAMP_GRAIN`] arm absorbs
/// the truncation-scale end of that range already, and what is left is bounded
/// to a single credit and a single datagram. Tightening it further would buy
/// that back at the price of degrading every claim on a merely slewed host,
/// which is by far the more common condition.
pub(crate) const WALL_STEP_TOLERANCE: Duration = Duration::from_millis(50);

/// One reading of BOTH clocks, taken back to back.
///
/// The pair is the unit, and the halves are never taken apart. A wall stamp is
/// only comparable with another wall stamp taken on the same timeline, and the
/// monotonic partner is the only thing that can say whether that timeline held;
/// a lone wall stamp cannot distinguish two seconds of elapsed time from a
/// two-second step.
///
/// **Both ends read `wall` first and `mono` second**, which is load-bearing
/// twice over. The nanoseconds between the two reads then have the same sign at
/// each end and cancel in the subtraction rather than accumulating into
/// [`WALL_STEP_TOLERANCE`]; and the monotonic read — the one [`SELF_SEND_TTL`]
/// is measured on — stays the last thing that happens before the comparison it
/// feeds, which is the floor [`SelfSendTracker::take`] documents.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ClockPair {
  /// Wall clock. Ordering only — never an age, on either end of the comparison.
  pub(crate) wall: SystemTime,
  /// The monotonic reading taken immediately after [`ClockPair::wall`].
  pub(crate) mono: StdInstant,
}

impl ClockPair {
  /// Read both clocks here, wall first. The only way production reaches a
  /// pair that was not taken from one syscall's own stamps.
  pub(crate) fn now() -> Self {
    Self {
      wall: SystemTime::now(),
      mono: StdInstant::now(),
    }
  }

  /// Adopt two readings a caller already holds.
  ///
  /// The one production caller is
  /// [`SendOutcome::credit_stamp`](crate::socket::SendOutcome::credit_stamp),
  /// whose two stamps are read on consecutive statements immediately before the
  /// `sendto` — which is exactly the adjacency this type needs.
  pub(crate) const fn new(wall: SystemTime, mono: StdInstant) -> Self {
    Self { wall, mono }
  }
}

/// How much ordering evidence a claim actually has.
///
/// It is **derived, never declared**: [`SelfSendTracker::take`] settles it from
/// whether the platform delivered a kernel receive timestamp, and
/// [`evidence_mode`] then weakens it per credit when that credit's own wall
/// stamp did not survive a clock step. No caller can hand in a mode, so no
/// caller can claim ordering evidence that the inputs do not carry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MatchMode {
  /// The reference is a kernel receive timestamp, and the credit's wall stamp
  /// is on the same timeline it was taken on. A datagram is ours only if it was
  /// stamped at-or-after the recorded send — within
  /// [`hick_udp::RX_TIMESTAMP_GRAIN`]. That ordering requirement is what stops
  /// a byte-identical peer datagram the kernel saw *before* our `sendto` from
  /// stealing the take-once credit. The [`SELF_SEND_TTL`] bound is applied
  /// separately, on the monotonic clock.
  Ordered,
  /// There is no ordering evidence to weigh, so matching is content hash plus
  /// family, bounded by [`SELF_SEND_TTL`], and nothing else. **The reference is
  /// not consulted at all** — see [`reference_ordered`] for why weighing one
  /// here could only ever reject our own echo.
  ///
  /// Two routes reach it, and they degrade to the same thing:
  ///
  /// * no kernel receive timestamp was available — Windows, or a Unix kernel
  ///   that delivered no timestamp cmsg — so the only wall value the claim could
  ///   offer is a userspace read time, which says nothing about when the kernel
  ///   saw the datagram;
  /// * the wall clock stepped between the send and the claim, so the credit's
  ///   own wall stamp is not on the timeline the receive stamp was taken on. See
  ///   [`WALL_STEP_TOLERANCE`].
  ///
  /// It is enough to suppress our own loopback in the ordinary single-host case,
  /// but by construction it cannot defend the credit-theft race that `Ordered`
  /// guards against. **That is the cheap direction, and it is chosen
  /// deliberately.**
  ///
  /// # What is given up is narrower than "ordering"
  ///
  /// Ordering only ever *rejects*, and it only ever rejects a datagram the
  /// kernel stamped BEFORE our `sendto`. Anything the kernel saw at or after it
  /// already claims the credit under `Ordered` too — see [`reference_ordered`] —
  /// so the whole of the marginal exposure here is a datagram that was already
  /// queued when the send it claims was made. It still has to arrive on the same
  /// family, from source port 5353 (`Mdns::drain_recv` offers a credit to no
  /// other port, since that is the only port this endpoint sends from), carrying
  /// the same content fingerprint, inside [`SELF_SEND_TTL`].
  ///
  /// # What one costs, and the bound on the fingerprint
  ///
  /// One datagram, once. The case that can arise without an author arranging it
  /// is a co-resident responder's byte-identical copy: every record in it
  /// asserts exactly what we assert, and RFC 6762 §9 defines a conflict as the
  /// same name, rrtype and rrclass with *different* rdata, so suppressing it
  /// cannot suppress a conflict. A query costs the answer to a question we had
  /// just asked ourselves.
  ///
  /// The match is [`fnv1a`] over the body rather than the body, so
  /// "byte-identical" is where the near-certainty is and it is stated rather
  /// than assumed: FNV is not collision-resistant, and a *different* payload
  /// that collides is a payload §9 could read as a conflict. An accidental
  /// collision is ~2⁻⁶⁴ against a tracker holding a handful of credits; a
  /// deliberate one is constructible, but only by the author of the colliding
  /// datagram, who thereby suppresses nothing but their own records. Storing the
  /// body instead would make the claim exact, at up to
  /// [`MAX_SELF_SEND_ENTRIES`] × the configured max payload — 98 MB at the
  /// 1500-byte default and 4.3 GB at the ceiling — which is not a price this
  /// buys anything at.
  ///
  /// # The direction neither mode bounds
  ///
  /// Whatever claims a credit takes it FROM our echo, which then reaches the
  /// protocol layer as peer traffic. `Ordered` narrows that to datagrams the
  /// kernel saw after our send and no further, so an exact replay of our own
  /// bytes defeats both modes equally; it is the standing price of matching on
  /// content at all, bounded by family, port, fingerprint and the TTL.
  ///
  /// Rejecting our own echo is the expensive direction, and it is what settles
  /// the trade: it makes this responder raise a phantom conflict against itself
  /// and rename under §9, and under a clock that keeps stepping it does so
  /// repeatedly.
  Degraded,
}

/// One recorded send, waiting for its multicast loopback copy.
///
/// **Two clocks, two jobs, and they are not interchangeable.** Each stamp is
/// allowed to be wrong in exactly one direction and the two directions do not
/// agree, so folding them back together — which is what this crate did until
/// the delayed-syscall defect — silently breaks whichever consumer needed the
/// other direction.
struct Credit {
  /// The socket the datagram went out on, and therefore the **only** socket
  /// its loopback copy can arrive on.
  family: Family,
  /// FNV-1a of the datagram body.
  hash: u64,
  /// Both clocks, read **before** the `sendto`. Used for **ordering only**: an
  /// echo the kernel stamped at-or-after [`ClockPair::wall`] cannot be a peer
  /// datagram that predated our send.
  ///
  /// EARLY is the safe direction, and pre-syscall is the only way to get it.
  /// The comparison is against the kernel's own receive stamp on the echo, so
  /// `sent.wall <= kernel send time <= echo rx time` must hold; a stamp read
  /// *after* the syscall could outrun the kernel's receive stamp on a copy
  /// already looped back, and the endpoint would ingest its own datagram as a
  /// peer's. It is emphatically **not** an age: see [`Credit::aged_from`].
  ///
  /// [`ClockPair::mono`] is here for exactly one job and no other: it is the
  /// wall stamp's partner, and the difference between the two elapsed times at
  /// claim time is the only way to tell real elapsed time from a wall clock that
  /// moved on its own. It anchors nothing — see [`WALL_STEP_TOLERANCE`] and,
  /// again, [`Credit::aged_from`].
  sent: ClockPair,
  /// Monotonic, and the only input to the [`SELF_SEND_TTL`] bound.
  ///
  /// `None` means "recorded since the last [`SelfSendTracker::seal`], ageing
  /// has not started" — a credit taken this tick, whose echo cannot be claimed
  /// until the next one. [`SelfSendTracker::seal`] fills it in at the top of
  /// that next tick, which is the first instant a claim is possible; see
  /// [`SELF_SEND_TTL`] for why the window may not start any earlier.
  ///
  /// LATE is the safe direction here — the opposite of [`Credit::sent`], and
  /// the whole reason this is a second stamp. Over-retaining a credit costs at
  /// most one byte-identical co-resident peer datagram mistaken for our echo
  /// inside a two-second window; under-retaining one makes this responder raise
  /// a phantom conflict against **itself**. Anchoring the age anywhere inside
  /// the recording tick — at the pre-syscall wall stamp, or even at the
  /// post-syscall monotonic one — gets the unsafe direction: it charges a
  /// stretch in which no claim was structurally possible to a window that was
  /// never meant to cover it.
  aged_from: Option<StdInstant>,
}

/// Content-addressed record of datagrams this endpoint has recently sent, so
/// their multicast loopback copies are recognized instead of being ingested
/// as a peer's traffic. Take-once: [`SelfSendTracker::take`] removes the
/// entry it matches, so a later, genuinely distinct datagram with the same
/// bytes (a co-resident peer) is still seen.
pub(crate) struct SelfSendTracker {
  /// One [`Credit`] per recorded send, insertion ordered and scanned linearly.
  /// [`SELF_SEND_TTL`] and [`MAX_SELF_SEND_ENTRIES`] keep this small enough
  /// that a `Vec` needs no fancier index.
  ///
  /// # Insertion order **is** expiry order, and [`Self::admit`] depends on it
  ///
  /// For any `i < j`, entry `i` expires no later than entry `j` — reading an
  /// unsealed [`Credit::aged_from`] (`None`) as "expires never". So the entry
  /// closest to expiry is always the **front**, and "is any entry dead at this
  /// instant?" is an `O(1)` question rather than a scan that could itself go
  /// stale. That is what makes the cap's admission decision decision-local; see
  /// [`Self::admit`].
  ///
  /// It holds by construction, under every operation this type has:
  ///
  /// * [`Self::record`] appends, and a fresh credit is unsealed — the largest
  ///   expiry there is — so it can only ever go at the back;
  /// * [`Self::seal`] stamps every unsealed credit with one instant. The
  ///   unsealed credits are exactly the suffix appended since the previous seal,
  ///   and the anchor is a monotonic reading taken inside that call — so the
  ///   suffix takes an anchor at or after every anchor already assigned;
  /// * [`Self::take`] and [`Self::reclaim_expired_sealed`] only ever remove, and
  ///   removal preserves relative order.
  ///
  /// The non-decreasing anchor was the one half a caller could break while
  /// [`Self::seal`] still took one, and deleting that parameter is what turned
  /// its contract into a property of the monotonic clock.
  entries: Vec<Credit>,
  /// A stall injected **between the expiry sweep and the read that anchors the
  /// batch the seal is about to open**, consumed by the seal that observes it.
  ///
  /// It stands in for the one thing no test can ask a real host for: a sweep of
  /// [`MAX_SELF_SEND_ENTRIES`] credits, or a preemption anywhere inside it,
  /// running longer than [`SELF_SEND_TTL`]. That stretch is pre-claim time — the
  /// batch's window has not opened yet — so charging it to the batch hands a
  /// newly-opened window an already-expired anchor, and the credit's own echo is
  /// then ingested as peer traffic.
  ///
  /// Injected into [`Self::seal`] itself rather than into a test-only copy of
  /// its body, so a seal that went back to anchoring on the sweep's reading
  /// fails the test instead of passing beside it.
  #[cfg(test)]
  forced_seal_pause: Option<Duration>,
}

impl SelfSendTracker {
  /// Create an empty tracker.
  pub(crate) fn new() -> Self {
    Self {
      entries: Vec::new(),
      #[cfg(test)]
      forced_seal_pause: None,
    }
  }

  /// Record that we just sent `body` on `family`, submitted at `sent` — the
  /// send's own pre-syscall reading of both clocks.
  ///
  /// The credit starts life un-aged ([`Credit::aged_from`] is `None`): its echo
  /// cannot be claimed until the next tick's receive stage, so its clock does
  /// not start until [`Self::seal`] starts it there.
  ///
  /// Pushes only if the tracker is still under [`MAX_SELF_SEND_ENTRIES`] — at
  /// the cap the NEW entry is dropped, never a live one, so a burst of sends
  /// can't displace a credit still waiting to match its loopback.
  ///
  /// # It reclaims dead credits, and ages nothing
  ///
  /// These are two different jobs and only one of them belongs here.
  ///
  /// **Reclaiming.** A sealed credit past [`SELF_SEND_TTL`] is garbage:
  /// [`Self::take`] already refuses it, and nothing but the next [`Self::seal`]
  /// removes it. So a full tracker whose tick then stalls past the TTL is
  /// [`MAX_SELF_SEND_ENTRIES`] corpses, and a later send in that same tick would
  /// be refused a credit by entries that are every one of them dead. A refused
  /// credit is not a lost byte — it is this endpoint ingesting its own loopback
  /// as peer traffic, a phantom conflict against itself and the RFC 6762 §9
  /// rename that follows. So the cap is enforced against what is still alive:
  /// [`Self::reclaim_expired_sealed`] runs first, against a LIVE monotonic
  /// instant read here, on the same clock and with the same rule [`Self::seal`]
  /// uses.
  ///
  /// **Ageing.** Not here, and not from anything this send carries. The
  /// record-time sweep this crate once had aged every existing credit against
  /// whatever instant *this* send happened to reach the kernel at, so a later
  /// send in the same tick — a second fan-out, or a stage-7 goodbye after a
  /// stage-4 announcement — evicted credits whose echoes had not had a single
  /// opportunity to claim them. That half is not coming back: an unsealed credit
  /// has no window open, so [`Self::reclaim_expired_sealed`] retains it
  /// unconditionally however late the clock reads, and [`Self::seal`] remains
  /// the only place a window ever opens.
  ///
  /// The reclaim is gated on the cap rather than run every time: below it there
  /// is nothing to make room for, so the clock read and the scan are both
  /// skipped and the routine sweep stays exactly where the anchor is.
  ///
  /// # The sweep is a sweep; [`Self::admit`] is the decision
  ///
  /// The bulk reclaim above is bounded only by [`MAX_SELF_SEND_ENTRIES`], so it
  /// weighs up to 65 536 credits against **one** instant read before it started.
  /// A credit that was live when the sweep looked at it can be dead by the time
  /// the sweep finishes, and deciding the cap on the length that sweep left
  /// behind is a decision made against a stale reading — the same defect class
  /// that cost this crate seven rounds elsewhere. So the length test is not the
  /// decision: [`Self::admit`] is, and it reads the clock at itself.
  pub(crate) fn record(&mut self, family: Family, body: &[u8], sent: ClockPair) {
    self.record_by(family, body, sent, StdInstant::now);
  }

  /// [`Self::record`] with the **bulk sweep's** clock chosen by the caller, so a
  /// test can hold that reading still while real time runs past it — which is
  /// exactly what a sweep of 65 536 entries does to it.
  ///
  /// `#[cfg(test)]`, permanently. It fakes only the sweep; the admission
  /// decision below reads the live clock in every build, so there is no build in
  /// which the cap is decided against an instant a caller handed in. Same seam
  /// as [`Self::take_at`].
  #[cfg(test)]
  pub(crate) fn record_with_stale_sweep(
    &mut self,
    family: Family,
    body: &[u8],
    sent: ClockPair,
    sweep_now: StdInstant,
  ) {
    self.record_by(family, body, sent, move || sweep_now);
  }

  /// The one body behind [`Self::record`] and [`Self::record_with_stale_sweep`].
  fn record_by(
    &mut self,
    family: Family,
    body: &[u8],
    sent: ClockPair,
    sweep_clock: impl Fn() -> StdInstant,
  ) {
    let hash = fnv1a(body);
    if self.entries.len() >= MAX_SELF_SEND_ENTRIES {
      self.reclaim_expired_sealed(sweep_clock());
    }
    if self.admit() {
      self.entries.push(Credit {
        family,
        hash,
        sent,
        aged_from: None,
      });
    }
  }

  /// Whether a new credit fits **at the instant this decides**, freeing the one
  /// slot it needs when the only thing in the way is a corpse.
  ///
  /// # It takes no instant, and the check it makes is `O(1)`
  ///
  /// Below the cap there is nothing to weigh. At the cap the only room is a dead
  /// credit, and because [`Self::entries`] is expiry-ordered (see that field)
  /// the earliest expiry there is is the **front** — so "is anything dead now?"
  /// is one comparison, and the clock read sits immediately before it with
  /// nothing but that comparison in between. That is the same floor
  /// [`Self::take`] reaches: something must read a clock before something can
  /// compare against it, and there is no work left inside the gap to move out.
  ///
  /// A scan would not do. Weighing every entry against one reading is what the
  /// bulk sweep in [`Self::record`] already does, and it is precisely why the
  /// admission cannot be decided on the length that sweep produced: entries it
  /// found live can expire before it returns, and a second scan would inherit
  /// the same window. The ordering invariant is what replaces the scan with an
  /// exact answer.
  ///
  /// Refusing here is not a lost byte. It is this endpoint ingesting its own
  /// loopback as peer traffic — a phantom conflict against itself and the RFC
  /// 6762 §9 rename that follows — so the direction that must never be taken
  /// wrongly is the refusal.
  fn admit(&mut self) -> bool {
    if self.entries.len() < MAX_SELF_SEND_ENTRIES {
      return true;
    }
    match self.entries.first() {
      // Dead at the instant this decides: reclaim exactly the one slot needed.
      // The removal happens AFTER the decision, so nothing about it can go
      // stale.
      Some(front) if !still_live(StdInstant::now(), front.aged_from) => {
        self.entries.remove(0);
        true
      }
      // The earliest expiry there is has not arrived, so every credit here is
      // live and the NEW one is the one that must give way.
      _ => false,
    }
  }

  /// Drop every credit that has BOTH opened its claim window AND outlived
  /// [`SELF_SEND_TTL`] at monotonic instant `now`. Nothing else, from either
  /// caller, ever.
  ///
  /// The unsealed half is the load-bearing one, and it is why this is a named
  /// routine rather than a `retain` written out twice. A credit whose
  /// [`Credit::aged_from`] is `None` has not started ageing: it has no age to be
  /// past the TTL with, and no claim opportunity it could have missed, so
  /// [`still_live`] answers `true` for it whatever `now` is. That is precisely
  /// the guarantee the seal redesign exists to provide, and reclaiming garbage
  /// must not quietly re-acquire the power to break it — conflating the two is
  /// what made the old record-time sweep a defect rather than a cleanup.
  ///
  /// [`Self::seal`] runs it once per tick as ordinary garbage collection, on a
  /// reading of its own — spent here and not reused to anchor the survivors, who
  /// are anchored at a later reading taken once this has returned.
  /// [`Self::record`] runs it only at [`MAX_SELF_SEND_ENTRIES`], where the
  /// alternative is refusing a live send's credit to keep corpses resident.
  fn reclaim_expired_sealed(&mut self, now: StdInstant) {
    self.entries.retain(|c| still_live(now, c.aged_from));
  }

  /// Open a claim window: expire every credit whose window has run out, and
  /// **then** start the clock on every credit that does not have one yet.
  ///
  /// Called once per tick, at the **top**, immediately before the receive stage
  /// — so the batch it opens is exactly the credits the previous tick recorded,
  /// and the anchor it stamps them with is the first instant at which any of
  /// their echoes can be claimed. That is the only instant [`SELF_SEND_TTL`] may
  /// be measured from: see that constant for why not earlier (the recording
  /// tick's outbound stretch is structurally claim-free) and why not later
  /// (post-opportunity time bounds false suppression and must be charged).
  ///
  /// Top-of-tick rather than end-of-outbound on purpose. An end-of-tick seal
  /// would carry a placement obligation that a future stage placed after it
  /// would silently break, reopening exactly this hole; a top-of-tick seal stays
  /// correct however the outbound stages are reordered. It also gives a credit
  /// age zero at its first claim opportunity, instead of arriving there having
  /// already spent one inter-tick caller gap.
  ///
  /// Ageing here rather than on `record` also means the anchor is taken once per
  /// tick instead of once per send, and always against the monotonic clock — so
  /// a wall-clock step in either direction still cannot evict a live credit. The
  /// reclaim below is shared with [`Self::record`]'s cap path and is the *only*
  /// thing they share: this is where the window opens, and it is the only place
  /// that can open one.
  ///
  /// # It takes no instant, and the two phases do not share a reading
  ///
  /// **A reading is spent by its first consumer**, and this call has two
  /// consumers in a fixed order. The sweep is first, and it is a bulk one:
  /// bounded only by [`MAX_SELF_SEND_ENTRIES`], it weighs up to 65 536 credits
  /// against the reading it started from. Handing that same, already-spent
  /// reading to the anchor is what made a caller-supplied `now` unsound — a long
  /// sweep, or a preemption anywhere inside it, gave a window that had only just
  /// opened an anchor from before it, and the first claim against that credit
  /// then found it expired. A credit lost that way is not a lost byte: it is this
  /// endpoint ingesting its own loopback as peer traffic, a phantom conflict
  /// against itself and the RFC 6762 §9 rename that follows.
  ///
  /// So sealing is batch-oriented. Every piece of pre-claim work — the sweep, and
  /// anything a later pass adds before the anchor — completes first, and the
  /// anchor is read after all of it, because that instant is not a convenient
  /// earlier reading but the thing being defined. The caller's parameter is
  /// deleted rather than moved for the same reason it was deleted from
  /// [`Self::take`]: a parameter is the channel through which a reading taken
  /// somewhere else arrives, and moving the read nearer never removes the
  /// channel.
  ///
  /// The sweep spending a stale reading is harmless in the only direction it can
  /// be wrong: a credit that died while the sweep ran is merely retained until
  /// the next seal, and [`Self::take`] refuses it meanwhile.
  ///
  /// It also settles the non-decreasing-anchor contract this used to state and
  /// rely on a caller for. The anchor is now a monotonic reading taken here, so
  /// each seal's anchor is at or after every anchor already assigned and
  /// [`SelfSendTracker::entries`]'s expiry order — which [`Self::admit`]'s `O(1)`
  /// front check reads — holds by construction.
  pub(crate) fn seal(&mut self) {
    // The sweep completes FIRST, on a reading of its own.
    self.reclaim_expired_sealed(StdInstant::now());
    // Deliberately between the sweep and the anchor: that is the stretch a
    // 65 536-entry sweep, or a preemption inside it, occupies for real.
    #[cfg(test)]
    if let Some(pause) = self.forced_seal_pause.take()
      && !pause.is_zero()
    {
      std::thread::sleep(pause);
    }
    // Read after every piece of pre-claim work above, and nowhere else.
    self.open_window_at(StdInstant::now());
  }

  /// [`Self::seal`] with both phases pinned to `at`, so a test can place a tick
  /// top anywhere without sleeping to it.
  ///
  /// `#[cfg(test)]`, permanently, and the gate is the point: production reaches
  /// a seal only through [`Self::seal`], which reads the clock for each phase
  /// itself, so there is no build in which a caller's instant can anchor a
  /// window. Collapsing the two readings is exactly what makes this usable for
  /// the tests whose subject is *not* the gap between them — `StdInstant` has no
  /// constructor, so a chosen tick top cannot be expressed any other way. The
  /// gap itself is tested through [`Self::pause_next_seal_for_test`], against
  /// the real [`Self::seal`]. Same seam as [`Self::take_at`].
  #[cfg(test)]
  pub(crate) fn seal_at(&mut self, at: StdInstant) {
    self.reclaim_expired_sealed(at);
    self.open_window_at(at);
  }

  /// Stall the next [`Self::seal`] between its sweep and its anchor. See
  /// [`SelfSendTracker::forced_seal_pause`].
  #[cfg(test)]
  pub(crate) fn pause_next_seal_for_test(&mut self, pause: Duration) {
    self.forced_seal_pause = Some(pause);
  }

  /// Start the clock on every credit that does not have one yet, at
  /// `opened_at`.
  ///
  /// `get_or_insert`, never an unconditional assignment: a credit already sealed
  /// keeps its original anchor, or a caller ticking faster than
  /// [`SELF_SEND_TTL`] would push every credit's expiry forward forever and the
  /// false-suppression bound would not be a bound at all.
  fn open_window_at(&mut self, opened_at: StdInstant) {
    for credit in &mut self.entries {
      credit.aged_from.get_or_insert(opened_at);
    }
  }

  /// Consume the tracker entry (if any) recorded for `family` whose content
  /// hash matches `body`, whose recorded send is ordered before `rx`, and whose
  /// claim window is **still open at the instant this call weighs it**. Returns
  /// `true` when a credit was consumed, i.e. `body` is this endpoint's own
  /// loopback rather than a peer's datagram.
  ///
  /// `rx` is the **kernel's** receive timestamp for `body`, or `None` when the
  /// platform delivered no timestamp cmsg. It is the whole of the ordering
  /// evidence, and no caller supplies anything else: [`MatchMode`] is derived
  /// from it here rather than declared, so there is no way to ask for `Ordered`
  /// matching against a stamp that carries no order — a userspace read time
  /// taken at the claim says nothing about when the kernel saw the datagram.
  ///
  /// # It takes no instant, and no caller can supply one
  ///
  /// The monotonic clock the [`SELF_SEND_TTL`] bound is measured on is read
  /// **inside this call, at the [`still_live`] test of the candidate being
  /// weighed** — not at the top of this function, and emphatically not by the
  /// caller. The absent parameter is the fix, and it is structural rather than
  /// another correction.
  ///
  /// A credit's liveness was mis-evaluated six times, each in a different window
  /// between some caller's clock read and this comparison: aged from a
  /// pre-syscall wall stamp, aged before the receive resumed, swept across tick
  /// stages by a later record, frozen at tick entry, counted as occupancy at the
  /// cap while dead, and frozen immediately after `recv` with both admission
  /// gates still to run. Each round closed its window by moving the read nearer,
  /// and each round left the next one. The parameter *is* the defect class: it is
  /// a channel through which a caller hands in an age measured somewhere else,
  /// and moving the read closer never removes the channel. Deleting it does —
  /// the same shape as [`Mdns::deregister`](crate::Mdns::deregister) dropping its
  /// `Registry` so a foreign selector became unrepresentable, and `summarize` in
  /// `driver::sends` taking no `SendHealth` so a link's condition could not reach
  /// the delivery projection.
  ///
  /// **What is left is the instructions between that read and the comparison,
  /// and it is irreducible.** Every possible implementation has it: something
  /// must read a clock before something can compare against it. There is no work
  /// left inside it to move out, so it is the floor rather than a seventh window
  /// — a later pass hunting for one here should stop at this paragraph.
  ///
  /// # Two clocks, two questions, and a third that keeps the first honest
  ///
  /// `rx` answers *ordering* — could the kernel have seen this datagram before
  /// we sent ours? — and is a wall stamp because that is the only clock a kernel
  /// receive timestamp is expressed in. The age is the other question, answered
  /// on the monotonic clock, because an age must not be a wall-clock
  /// subtraction.
  ///
  /// The third question is whether the ordering answer is worth anything, and it
  /// exists because the wall clock is not monotonic. A step between the send and
  /// this claim leaves [`Credit::sent`]'s wall half describing a timeline `rx`
  /// was never taken on, and the credit's own echo then looks like a peer
  /// datagram that predated it. So every claim reads both clocks — see
  /// [`ClockPair`] — and a credit whose two elapsed times disagree past
  /// [`WALL_STEP_TOLERANCE`] is weighed under [`MatchMode::Degraded`] instead of
  /// being refused. See [`evidence_mode`] for the direction that trade takes and
  /// why.
  ///
  /// The tick's own instant is not a substitute for the live read, which is why
  /// [`Mdns::tick`](crate::Mdns::tick) keeps it for the protocol path and hands
  /// it to nothing here. It is taken before the receive stage, so reusing it
  /// charges nothing for the drain's own runtime, for the admission gates each
  /// datagram passes, or for a preemption anywhere among them; a caller stalling
  /// mid-drain would find a credit still live an unbounded time after its window
  /// opened. [`SELF_SEND_TTL`] bounds FALSE suppression and that bound is real
  /// time, so post-opportunity time is charged in full — see that constant.
  /// Erring EARLY is still the safe direction within a live read, since
  /// over-retention is cheap and losing a credit raises a phantom conflict
  /// against ourselves.
  ///
  /// A credit [`Self::seal`] has not reached yet is live whatever the clock
  /// reads. Today that is unreachable — the driver seals at the top of the tick
  /// and no send stage precedes its receive stage, so nothing this call can see
  /// is unsealed — but the rule is stated rather than assumed, so a future stage
  /// that recorded before a receive would over-retain (cheap) instead of
  /// expiring a credit that never had an opportunity (a phantom self-conflict).
  ///
  /// # What may be offered a credit is the caller's half of the match
  ///
  /// This weighs content, family and time, and it never sees where the datagram
  /// came from. Both of this endpoint's sockets are bound to port 5353, so every
  /// datagram it sends leaves from that port and every loopback copy arrives
  /// from it — which makes a different source port proof that the datagram is
  /// not our echo, and something this call cannot discover for itself.
  /// `Mdns::drain_recv` holds that line, beside the RFC 6762 §11 source-port
  /// rule it belongs with: an untrusted RESPONSE is dropped outright there,
  /// while a §6.7 legacy unicast QUERY is kept — it is owed a reply — and simply
  /// never offered here.
  ///
  /// # Why the family is part of the key
  ///
  /// One multicast transmit is **two** syscalls with **identical bytes** and
  /// two separately-stamped credits, and the kernel loops one copy back per
  /// joined socket. Matching on content and time alone makes those two credits
  /// interchangeable, and the receive rotor deliberately does not fix which
  /// socket is read first — so the later (IPv6) echo can be read first, consume
  /// the earlier (IPv4) credit, and leave the IPv4 echo facing a credit stamped
  /// *after* the kernel saw it. `Ordered` matching then rejects it and the
  /// endpoint ingests its own datagram as peer traffic: a phantom conflict
  /// against itself, and the spurious §9 rename that follows.
  ///
  /// A loopback copy can only arrive on the socket it was sent from, so keying
  /// the credit to the family makes each echo match its own credit and nothing
  /// else. That is exact rather than probabilistic, which is why it is
  /// preferred over consuming the newest eligible credit: newest-first only
  /// reorders the same interchangeable set, and a third credit for the same
  /// bytes (a queued copy completing out of order) defeats it again.
  pub(crate) fn take(&mut self, family: Family, body: &[u8], rx: Option<SystemTime>) -> bool {
    self.take_by(family, body, rx, ClockPair::now)
  }

  /// [`Self::take`] against a caller-chosen reading of both clocks, so a test can
  /// place a claim anywhere in a credit's window without sleeping through it,
  /// and can put the wall clock somewhere the monotonic one says it cannot be.
  ///
  /// `#[cfg(test)]`, permanently, and that gate is the entire point: production
  /// reaches the liveness decision only through [`Self::take`], which reads both
  /// clocks itself, so there is no build in which a stale reading can be handed
  /// in. Same seam as `BoundSocket::forced_recv_delays` and
  /// `Sockets::forced_no_rx_time` — a test-only door onto a decision production
  /// makes for itself.
  ///
  /// It is also the only deterministic way to present a wall-clock step: no test
  /// can ask a host to run `settimeofday` under it, and the whole subject of
  /// [`WALL_STEP_TOLERANCE`] is what a claim does when the wall clock moved
  /// between the send and here.
  #[cfg(test)]
  pub(crate) fn take_at(
    &mut self,
    family: Family,
    body: &[u8],
    rx: Option<SystemTime>,
    now: ClockPair,
  ) -> bool {
    self.take_by(family, body, rx, move || now)
  }

  /// The one body behind [`Self::take`] and [`Self::take_at`].
  ///
  /// `clock` is invoked **in the predicate**, at the [`still_live`] test of each
  /// candidate that already matched on family and content — so the production
  /// path's read lands at the decision itself, with nothing between the
  /// monotonic half and the comparison it feeds. Private, and taking a clock
  /// rather than a reading, so the only way to reach it with a value fixed in
  /// advance is the `#[cfg(test)]` door above.
  fn take_by(
    &mut self,
    family: Family,
    body: &[u8],
    rx: Option<SystemTime>,
    clock: impl Fn() -> ClockPair,
  ) -> bool {
    let needle = fnv1a(body);
    match self.entries.iter().position(|c| {
      if c.family != family || c.hash != needle {
        return false;
      }
      let now = clock();
      still_live(now.mono, c.aged_from)
        && reference_ordered(rx, c.sent, evidence_mode(rx, c.sent, now))
    }) {
      Some(pos) => {
        self.entries.remove(pos);
        true
      }
      None => false,
    }
  }

  /// Number of live entries.
  ///
  /// Test-only, permanently: the driver drives the tracker entirely through
  /// [`Self::record`] and [`Self::take`] and never reads its depth, so this
  /// stays `#[cfg(test)]` rather than carrying a dead-code allow that a later
  /// cleanup could mistake for stale — same rule as [`RX_GRAIN_FOR_TEST`].
  #[cfg(test)]
  pub(crate) fn len(&self) -> usize {
    self.entries.len()
  }

  /// Every entry's ageing anchor, in storage order, so a test can assert the
  /// expiry order [`Self::admit`] depends on.
  ///
  /// Test-only, permanently, and for the same reason as [`Self::len`]: the
  /// driver drives this type through `record`, `seal` and `take` and never reads
  /// its layout.
  #[cfg(test)]
  pub(crate) fn anchors_for_test(&self) -> Vec<Option<StdInstant>> {
    self.entries.iter().map(|c| c.aged_from).collect()
  }
}

/// Whether a credit whose window opened at `aged_from` is still inside
/// [`SELF_SEND_TTL`] at monotonic instant `now`.
///
/// The **only** place the TTL is applied, on the **only** clock it may be
/// applied on.
///
/// `None` — a credit recorded since the last [`SelfSendTracker::seal`] — is
/// live unconditionally: its window has not opened, so there is no age to
/// compare and nothing it could have outlived. `saturating_duration_since`
/// likewise reads a `now` before `aged_from` as an age of zero rather than as an
/// expiry: a monotonic clock cannot really run backwards, so an age computed
/// from a reading that predates the anchor is a reading taken out of order
/// rather than an expired credit. Zero is the safe answer either way — it
/// retains the credit.
fn still_live(now: StdInstant, aged_from: Option<StdInstant>) -> bool {
  match aged_from {
    // Unsealed: recorded this tick, and no claim was possible yet.
    None => true,
    Some(from) => now.saturating_duration_since(from) <= SELF_SEND_TTL,
  }
}

/// How much ordering evidence this claim really has about **this** credit.
///
/// Never stronger than the platform supplied, and weaker whenever the credit's
/// own wall stamp did not survive the window: the two elapsed times between
/// `sent` and `now` are the same interval measured on two clocks, so their
/// disagreement is what the wall clock did on its own, and past
/// [`WALL_STEP_TOLERANCE`] the stamp is simply not on the timeline the kernel's
/// receive stamp was taken on.
///
/// # Which way to fail, and what it costs
///
/// Unusable evidence has two possible readings and both cost something.
///
/// Reading it as *not our echo* refuses the credit, and this endpoint then
/// ingests its own announcement as peer traffic: a phantom conflict against
/// itself and the RFC 6762 §9 rename that follows — repeatedly, for as long as
/// the clock keeps stepping, since each step refuses the next echo the same way.
///
/// Reading it as *our echo* lets a stranger carrying the same fingerprint take
/// the credit instead, at a cost of one datagram inside a two-second window. See
/// [`MatchMode::Degraded`] for what that datagram can and cannot be, and for the
/// two things the RFC 6762 §9 rdata test does and does not settle about it.
///
/// So the fall-back is [`MatchMode::Degraded`], which is not a new state: it is
/// what every claim on a platform with no receive-timestamp cmsg already runs
/// under, with the same bound and the same accepted weakness.
fn evidence_mode(rx: Option<SystemTime>, sent: ClockPair, now: ClockPair) -> MatchMode {
  match rx {
    // No kernel receive timestamp: nothing to order against in the first place.
    None => MatchMode::Degraded,
    // The wall clock moved on its own inside this credit's window, so its
    // pre-syscall stamp cannot be compared with a receive stamp any more.
    Some(_) if wall_stepped(sent, now) => MatchMode::Degraded,
    Some(_) => MatchMode::Ordered,
  }
}

/// Whether the wall clock moved on its own — in **either** direction — between
/// the send at `sent` and the claim at `now`.
///
/// Both readings pair a wall stamp with a monotonic one taken immediately after
/// it, so the two elapsed times measure the same interval. Real elapsed time is
/// the monotonic one; everything the wall one does beyond it is the step. A
/// merely slewed clock stays well inside [`WALL_STEP_TOLERANCE`] — see there.
fn wall_stepped(sent: ClockPair, now: ClockPair) -> bool {
  // `saturating_duration_since` reads a `now` before the send as zero elapsed.
  // That can only make the disagreement look larger, and a larger disagreement
  // degrades — which is the cheap direction. See `evidence_mode`.
  let elapsed = now.mono.saturating_duration_since(sent.mono);
  match now.wall.duration_since(sent.wall) {
    // The wall clock is still ahead of the send. Whatever it did beyond real
    // elapsed time, in either direction, is the step.
    Ok(advanced) => advanced.abs_diff(elapsed) > WALL_STEP_TOLERANCE,
    // The wall clock now reads BEFORE the send it stamped, which no amount of
    // elapsed time can produce. The step is that gap plus every bit of real time
    // that passed while the clock was travelling the other way.
    Err(behind) => behind.duration().saturating_add(elapsed) > WALL_STEP_TOLERANCE,
  }
}

/// Whether a kernel receive stamp of `rx` is **ordered after** a send submitted
/// at `sent`, given the evidence `mode` says this claim actually has.
///
/// Ordering only. It deliberately does not bound how far after — that is
/// [`still_live`]'s job, on the monotonic clock, and unifying the two is the
/// defect this split exists to prevent: `sent.wall` is read before the syscall,
/// so any stall between the read and the kernel accepting the datagram would be
/// charged to a TTL measured from it, and a stall past [`SELF_SEND_TTL`] would
/// make the endpoint ingest its own echo as peer traffic.
///
/// [`MatchMode::Degraded`] weighs nothing here, and the missing test is the
/// point rather than an omission. The only wall value a degraded claim could
/// offer is a userspace read time, which is at-or-after the send in every case
/// except one — a wall clock that stepped backwards — so an ordering test
/// against it can only ever fire on the step, and firing means refusing our own
/// echo. That is the expensive direction; see [`evidence_mode`].
fn reference_ordered(rx: Option<SystemTime>, sent: ClockPair, mode: MatchMode) -> bool {
  // `Ordered` is only ever derived from a `Some`, so the absent-stamp arm here
  // is unreachable; it answers `true` rather than panicking, which is the
  // direction [`evidence_mode`] takes for missing evidence anyway.
  let (MatchMode::Ordered, Some(rx)) = (mode, rx) else {
    return true;
  };
  match rx.duration_since(sent.wall) {
    // Receive stamp at-or-after the send: correctly ordered to be our echo.
    Ok(_) => true,
    // Receive stamp BEFORE the send, tolerated only within this target's
    // receive-timestamp truncation grain — that ordering is exactly what stops a
    // byte-identical peer datagram the kernel saw before our sendto from
    // stealing the take-once credit.
    Err(behind) => behind.duration() <= hick_udp::RX_TIMESTAMP_GRAIN,
  }
}

/// Standard 64-bit FNV-1a hash. Used only to fingerprint our own sends for
/// loopback matching, never as a security primitive, so a fast
/// non-cryptographic hash is appropriate.
pub(crate) fn fnv1a(data: &[u8]) -> u64 {
  const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
  const PRIME: u64 = 0x0000_0100_0000_01b3;
  let mut h = OFFSET;
  for &b in data {
    h ^= u64::from(b);
    h = h.wrapping_mul(PRIME);
  }
  h
}

/// [`hick_udp::RX_TIMESTAMP_GRAIN`] under a short name for `selfsend/tests.rs`
/// to assert against. `Duration::ZERO` on nanosecond `SO_TIMESTAMPNS` targets,
/// one microsecond on `timeval` targets — see that constant for the full
/// rationale. Test-only, permanently: unlike the rest of this module it is
/// never consumed by the driver, so it stays `#[cfg(test)]` rather than
/// carrying a dead-code allow that a later cleanup could mistake for stale.
#[cfg(test)]
pub(crate) const RX_GRAIN_FOR_TEST: Duration = hick_udp::RX_TIMESTAMP_GRAIN;

#[cfg(test)]
mod tests;

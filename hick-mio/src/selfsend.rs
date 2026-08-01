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
/// sealed and past the TTL — and declines to add the new entry only if that
/// still leaves no room. It never evicts a live one: a flood of sends must not
/// displace a credit that is still waiting to match its own loopback copy, and
/// equally a heap of corpses must not displace a credit that has not been
/// recorded yet. See [`SelfSendTracker::reclaim_expired_sealed`] for why only
/// the dead half is reclaimable.
pub(crate) const MAX_SELF_SEND_ENTRIES: usize = 65536;

/// How an inbound datagram's timestamp is weighed against a recorded send.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MatchMode {
  /// `reference` is a kernel receive timestamp. A datagram is ours only if it
  /// was stamped at-or-after the recorded send — within
  /// [`hick_udp::RX_TIMESTAMP_GRAIN`]. That ordering requirement is what stops
  /// a byte-identical peer datagram the kernel saw *before* our `sendto` from
  /// stealing the take-once credit. The [`SELF_SEND_TTL`] bound is applied
  /// separately, on the monotonic clock.
  Ordered,
  /// No kernel receive timestamp was available — Windows, or a Unix kernel
  /// that didn't deliver the timestamp cmsg — so `reference` is a userspace
  /// read time carrying no ordering information: matching falls back to
  /// content hash alone, still bounded by [`SELF_SEND_TTL`]. That is enough to
  /// suppress our own loopback in the ordinary single-host case, but by
  /// construction it cannot defend the credit-theft race that `Ordered`'s
  /// pre-send tolerance guards against — the documented degradation on these
  /// platforms.
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
  /// Wall clock, read **before** the `sendto`. Used for **ordering only**: an
  /// echo the kernel stamped at-or-after this cannot be a peer datagram that
  /// predated our send.
  ///
  /// EARLY is the safe direction, and pre-syscall is the only way to get it.
  /// The comparison is against the kernel's own receive stamp on the echo, so
  /// `sent <= kernel send time <= echo rx time` must hold; a stamp read *after*
  /// the syscall could outrun the kernel's receive stamp on a copy already
  /// looped back, and the endpoint would ingest its own datagram as a peer's.
  /// It is emphatically **not** an age: see [`Credit::aged_from`].
  sent: SystemTime,
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
  entries: Vec<Credit>,
}

impl SelfSendTracker {
  /// Create an empty tracker.
  pub(crate) fn new() -> Self {
    Self {
      entries: Vec::new(),
    }
  }

  /// Record that we just sent `body` on `family`, submitted at wall time `sent`.
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
  pub(crate) fn record(&mut self, family: Family, body: &[u8], sent: SystemTime) {
    let hash = fnv1a(body);
    if self.entries.len() >= MAX_SELF_SEND_ENTRIES {
      self.reclaim_expired_sealed(StdInstant::now());
    }
    if self.entries.len() < MAX_SELF_SEND_ENTRIES {
      self.entries.push(Credit {
        family,
        hash,
        sent,
        aged_from: None,
      });
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
  /// [`Self::seal`] runs it once per tick as ordinary garbage collection, on the
  /// instant it is about to anchor the survivors at. [`Self::record`] runs it
  /// only at [`MAX_SELF_SEND_ENTRIES`], where the alternative is refusing a live
  /// send's credit to keep corpses resident.
  fn reclaim_expired_sealed(&mut self, now: StdInstant) {
    self.entries.retain(|c| still_live(now, c.aged_from));
  }

  /// Open a claim window at monotonic instant `now`: expire every credit whose
  /// window has run out, and start the clock on every credit that does not have
  /// one yet.
  ///
  /// Called once per tick, at the **top**, immediately before the receive stage
  /// — so `now` is precisely the first instant at which a credit recorded by the
  /// previous tick can be claimed, which is the only instant [`SELF_SEND_TTL`]
  /// may be measured from. See that constant for why not earlier (the recording
  /// tick's outbound stretch is structurally claim-free) and why not later
  /// (post-opportunity time bounds false suppression and must be charged).
  ///
  /// Top-of-tick rather than end-of-outbound on purpose. An end-of-tick seal
  /// would need its own clock read and would carry a placement obligation that
  /// a future stage placed after it would silently break, reopening exactly this
  /// hole; a top-of-tick seal reuses the instant the tick already took and stays
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
  pub(crate) fn seal(&mut self, now: StdInstant) {
    self.reclaim_expired_sealed(now);
    for credit in &mut self.entries {
      credit.aged_from.get_or_insert(now);
    }
  }

  /// Consume the tracker entry (if any) recorded for `family` whose content
  /// hash matches `body`, whose recorded send is ordered before `reference` per
  /// `mode`, and whose claim window is **still open at the instant this call
  /// weighs it**. Returns `true` when a credit was consumed, i.e. `body` is this
  /// endpoint's own loopback rather than a peer's datagram.
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
  /// # Two clocks, two questions
  ///
  /// `reference` answers *ordering* — could the kernel have seen this datagram
  /// before we sent ours? — and is a wall stamp because that is the only clock a
  /// kernel receive timestamp is expressed in. The age is the other question,
  /// answered on the monotonic clock, because an age must not be a wall-clock
  /// subtraction.
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
  pub(crate) fn take(
    &mut self,
    family: Family,
    body: &[u8],
    reference: SystemTime,
    mode: MatchMode,
  ) -> bool {
    self.take_by(family, body, reference, mode, StdInstant::now)
  }

  /// [`Self::take`] against a caller-chosen `now`, so a test can place a claim
  /// anywhere in a credit's window without sleeping through it.
  ///
  /// `#[cfg(test)]`, permanently, and that gate is the entire point: production
  /// reaches the liveness decision only through [`Self::take`], which reads the
  /// clock itself, so there is no build in which a stale instant can be handed
  /// in. Same seam as `BoundSocket::forced_recv_delays` and
  /// `Sockets::forced_no_rx_time` — a test-only door onto a decision production
  /// makes for itself.
  #[cfg(test)]
  pub(crate) fn take_at(
    &mut self,
    family: Family,
    body: &[u8],
    reference: SystemTime,
    now: StdInstant,
    mode: MatchMode,
  ) -> bool {
    self.take_by(family, body, reference, mode, move || now)
  }

  /// The one body behind [`Self::take`] and [`Self::take_at`].
  ///
  /// `clock` is invoked **in the predicate**, at the [`still_live`] test of each
  /// candidate that already matched on family and content — so the production
  /// path's read lands at the decision itself, with nothing between the two but
  /// the comparison. Private, and taking a clock rather than an instant, so the
  /// only way to reach it with a value fixed in advance is the `#[cfg(test)]`
  /// door above.
  fn take_by(
    &mut self,
    family: Family,
    body: &[u8],
    reference: SystemTime,
    mode: MatchMode,
    clock: impl Fn() -> StdInstant,
  ) -> bool {
    let needle = fnv1a(body);
    match self.entries.iter().position(|c| {
      c.family == family
        && c.hash == needle
        && still_live(clock(), c.aged_from)
        && reference_ordered(reference, c.sent, mode)
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
/// expiry: a monotonic clock cannot really run backwards, and
/// [`SelfSendTracker::seal`]'s own sweep legitimately weighs a credit against
/// the very instant it is about to anchor it at. Zero is the safe answer either
/// way — it retains the credit.
fn still_live(now: StdInstant, aged_from: Option<StdInstant>) -> bool {
  match aged_from {
    // Unsealed: recorded this tick, and no claim was possible yet.
    None => true,
    Some(from) => now.saturating_duration_since(from) <= SELF_SEND_TTL,
  }
}

/// Whether `reference` is **ordered after** a send submitted at `sent`, per
/// `mode`.
///
/// Ordering only. It deliberately does not bound how far after — that is
/// [`still_live`]'s job, on the monotonic clock, and unifying the two is the
/// defect this split exists to prevent: `sent` is read before the syscall, so
/// any stall between the read and the kernel accepting the datagram would be
/// charged to a TTL measured from it, and a stall past [`SELF_SEND_TTL`] would
/// make the endpoint ingest its own echo as peer traffic.
///
/// `Degraded` does not blanket-accept a reference before `sent` — a read-time
/// reference is always at-or-after the send in practice, so that arm is only
/// a clock-went-backwards guard.
fn reference_ordered(reference: SystemTime, sent: SystemTime, mode: MatchMode) -> bool {
  match reference.duration_since(sent) {
    // Reference at-or-after the send: correctly ordered to be our own echo.
    Ok(_) => true,
    // Reference BEFORE the send. Only ordered mode tolerates it, and only
    // within this target's receive-timestamp truncation grain — that ordering
    // is exactly what stops a byte-identical peer datagram the kernel saw
    // before our sendto from stealing the take-once credit.
    Err(behind) => mode == MatchMode::Ordered && behind.duration() <= hick_udp::RX_TIMESTAMP_GRAIN,
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

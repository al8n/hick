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

/// How long a recorded send stays eligible to match an inbound loopback
/// before [`SelfSendTracker::record`] sweeps it. Multicast loopback is
/// delivered on the same host within microseconds, so 2s is generously
/// longer than any real loopback latency, while still short enough that a
/// byte-identical datagram from a co-resident peer arriving later is
/// correctly treated as a peer rather than our echo. Both [`MatchMode`]s are
/// bounded above by this TTL.
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
/// [`Credit::aged_from`] — post-syscall and monotonic — is the only input to
/// this bound. See both field docs for the one direction each may be wrong in.
pub(crate) const SELF_SEND_TTL: Duration = Duration::from_secs(2);

/// Memory backstop on live [`SelfSendTracker`] entries. The real bound is
/// [`SELF_SEND_TTL`]; under normal operation the tracker holds only a
/// handful of entries. At the cap, [`SelfSendTracker::record`] declines to
/// add the new entry rather than evicting the oldest live one — a flood of
/// sends must never displace a credit that is still waiting to match its own
/// loopback copy.
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
  /// Monotonic, read **after** the `sendto` returned success. The only input to
  /// the [`SELF_SEND_TTL`] bound.
  ///
  /// LATE is the safe direction here — the opposite of [`Credit::sent`], and
  /// the whole reason this is a second stamp. Over-retaining a credit costs at
  /// most one byte-identical co-resident peer datagram mistaken for our echo
  /// inside a two-second window; under-retaining one makes this responder raise
  /// a phantom conflict against **itself**. Anchoring the age at the pre-syscall
  /// wall stamp gets the unsafe direction: everything between that read and the
  /// kernel accepting the datagram is charged to a window that was never meant
  /// to cover it.
  aged_from: StdInstant,
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

  /// Record that we just sent `body` on `family`, submitted at wall time `sent`
  /// and accepted by the kernel at monotonic instant `aged_from`.
  ///
  /// The two stamps are the two halves of [`Credit`] and are read at different
  /// points of the same send on purpose — see that type's field docs.
  ///
  /// Sweeps every entry older than [`SELF_SEND_TTL`] relative to THIS send's
  /// `aged_from`, then pushes the new entry only if the tracker is still under
  /// [`MAX_SELF_SEND_ENTRIES`] — at the cap the NEW entry is dropped, never
  /// the oldest, so a burst of sends can't displace a credit still waiting
  /// to match its loopback.
  ///
  /// The sweep reads the monotonic clock, so a wall-clock step in either
  /// direction cannot evict a live credit. That is what the old wall-clock
  /// sweep needed its backwards-step special case for; a monotonic age has no
  /// backwards step to except.
  pub(crate) fn record(
    &mut self,
    family: Family,
    body: &[u8],
    sent: SystemTime,
    aged_from: StdInstant,
  ) {
    let hash = fnv1a(body);
    self.entries.retain(|c| still_live(aged_from, c.aged_from));
    if self.entries.len() < MAX_SELF_SEND_ENTRIES {
      self.entries.push(Credit {
        family,
        hash,
        sent,
        aged_from,
      });
    }
  }

  /// Consume the tracker entry (if any) recorded for `family` whose content
  /// hash matches `body`, whose recorded send is ordered before `reference`
  /// per `mode`, and which is still live at monotonic instant `now`. Returns
  /// `true` when a credit was consumed, i.e. `body` is this endpoint's own
  /// loopback rather than a peer's datagram.
  ///
  /// # Two clocks, two questions
  ///
  /// `reference` answers *ordering* — could the kernel have seen this datagram
  /// before we sent ours? — and is a wall stamp because that is the only clock a
  /// kernel receive timestamp is expressed in. `now` answers *age*, and is
  /// monotonic because an age must not be a wall-clock subtraction. Passing the
  /// tick's own instant makes `now` at-or-before the true read time, which
  /// under-ages the credit — the safe direction, since over-retention is cheap
  /// and losing a credit raises a phantom conflict against ourselves.
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
    now: StdInstant,
    mode: MatchMode,
  ) -> bool {
    let needle = fnv1a(body);
    match self.entries.iter().position(|c| {
      c.family == family
        && c.hash == needle
        && still_live(now, c.aged_from)
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

/// Whether a credit accepted by the kernel at `aged_from` is still inside
/// [`SELF_SEND_TTL`] at monotonic instant `now`.
///
/// The **only** place the TTL is applied, on the **only** clock it may be
/// applied on. `saturating_duration_since` reads a `now` before `aged_from` as
/// an age of zero rather than as an expiry: a monotonic clock cannot really run
/// backwards, and the caller may legitimately pass a `now` sampled at the top
/// of the tick that then recorded the credit. Zero is the safe answer either
/// way — it retains the credit.
fn still_live(now: StdInstant, aged_from: StdInstant) -> bool {
  now.saturating_duration_since(aged_from) <= SELF_SEND_TTL
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

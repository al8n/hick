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

use std::time::{Duration, SystemTime};

use crate::socket::Family;

/// How long a recorded send stays eligible to match an inbound loopback
/// before [`SelfSendTracker::record`] sweeps it. Multicast loopback is
/// delivered on the same host within microseconds, so 2s is generously
/// longer than any real loopback latency, while still short enough that a
/// byte-identical datagram from a co-resident peer arriving later is
/// correctly treated as a peer rather than our echo. Both [`MatchMode`]s are
/// bounded above by this TTL.
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
  /// [`hick_udp::RX_TIMESTAMP_GRAIN`] — and within [`SELF_SEND_TTL`]. That
  /// ordering requirement is what stops a byte-identical peer datagram the
  /// kernel saw *before* our `sendto` from stealing the take-once credit.
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
struct Credit {
  /// The socket the datagram went out on, and therefore the **only** socket
  /// its loopback copy can arrive on.
  family: Family,
  /// FNV-1a of the datagram body.
  hash: u64,
  /// Wall time of the `sendto` that produced it.
  sent: SystemTime,
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

  /// Record that we just sent `body` on `family` at wall time `sent`.
  ///
  /// Sweeps every entry older than [`SELF_SEND_TTL`] relative to THIS send,
  /// then pushes the new entry only if the tracker is still under
  /// [`MAX_SELF_SEND_ENTRIES`] — at the cap the NEW entry is dropped, never
  /// the oldest, so a burst of sends can't displace a credit still waiting
  /// to match its loopback.
  pub(crate) fn record(&mut self, family: Family, body: &[u8], sent: SystemTime) {
    let hash = fnv1a(body);
    self.entries.retain(|c| match sent.duration_since(c.sent) {
      Ok(age) => age <= SELF_SEND_TTL,
      // Recorded AFTER this send: the wall clock stepped backwards between the
      // two. Keep it — over-retaining a credit a clock jump made unmatchable is
      // cheap, whereas dropping one makes the responder ingest its own loopback
      // as a peer and raise a phantom conflict against itself.
      Err(_) => true,
    });
    if self.entries.len() < MAX_SELF_SEND_ENTRIES {
      self.entries.push(Credit { family, hash, sent });
    }
  }

  /// Consume the tracker entry (if any) recorded for `family` whose content
  /// hash matches `body` and whose recorded send time falls inside `mode`'s
  /// match window around `reference`. Returns `true` when a credit was
  /// consumed, i.e. `body` is this endpoint's own loopback rather than a
  /// peer's datagram.
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
    let needle = fnv1a(body);
    match self.entries.iter().position(|c| {
      c.family == family && c.hash == needle && reference_matches(reference, c.sent, mode)
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

/// Whether `reference` falls inside the acceptance window of a send made at
/// `sent`, per `mode`. Both modes are bounded above by [`SELF_SEND_TTL`];
/// `Degraded` does not blanket-accept a reference before `sent` — a read-time
/// reference is always at-or-after the send in practice, so that arm is only
/// a clock-went-backwards guard.
fn reference_matches(reference: SystemTime, sent: SystemTime, mode: MatchMode) -> bool {
  match reference.duration_since(sent) {
    // Reference at-or-after the send: ours while still inside the TTL window.
    Ok(ahead) => ahead <= SELF_SEND_TTL,
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

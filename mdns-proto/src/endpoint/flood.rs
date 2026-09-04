//! RFC 6762 §8.1's conflict-flood limit, counted ENDPOINT-WIDE.

use crate::{Instant, Name, event::DatagramId};

/// How many conflicts RFC 6762 §8.1 counts before its flood limit applies:
///
/// > If fifteen conflicts occur within any ten-second period, then the host
/// > MUST wait at least five seconds before each successive additional probe
/// > attempt.  This is to help ensure that, in the event of software bugs or
/// > other unanticipated problems, errant hosts do not flood the network with
/// > a continuous stream of multicast traffic.
///
/// Fifteen, ten and five are one rule and are kept together because no one of
/// them means anything alone. What is counted is CONFLICTS — not renames and
/// not probes — so the count spans renames and probe restarts, which is what
/// makes it a limit on the rename loop rather than a counter that loop resets.
///
/// # Scope: the ENDPOINT, and the limit is EXACT within its contract
///
/// The ring lives on the [`Endpoint`](crate::Endpoint), so it aggregates across
/// every record set that endpoint routes for, outlives any one
/// [`Service`](crate::Service), and floors a fresh registration's first probe.
///
/// The limit is enforced inside the `Endpoint` and asks nothing of a driver
/// beyond what every sans-I/O method here already requires: each received
/// datagram reaches `Endpoint::handle` with a monotonic `now` taken at receipt,
/// `Endpoint::handle_service_timeout` runs by the instant
/// `Endpoint::poll_service_timeout` reports, and probes leave the host only
/// through `Endpoint::poll_service_transmit`. Within that contract the limit is
/// exact, not best-effort — routing, classification, this ring, the receipt
/// instant and the floor are one state machine under one `&mut self` and one
/// `now`, so no caller sits between counting a conflict and spacing the probe it
/// caused.
///
/// It is ENDPOINT-wide rather than host-wide: a second `Endpoint`, or a second
/// process, on the same machine is outside anything this library can observe,
/// and that is the only sense in which RFC 6762's "host" is approximated.
pub(crate) const CONFLICT_BURST_LEN: usize = 15;

/// The period [`CONFLICT_BURST_LEN`] conflicts must fall inside for §8.1's flood
/// limit to apply — and, once it applies, the span of total quiet that releases
/// it again.
pub(crate) const CONFLICT_BURST_WINDOW: core::time::Duration =
  core::time::Duration::from_secs(10);

/// The floor §8.1 puts under the start of each successive probe sequence once
/// [`CONFLICT_BURST_LEN`] conflicts have fallen inside one
/// [`CONFLICT_BURST_WINDOW`]: "the host MUST wait at least five seconds".
pub(crate) const CONFLICT_BACKOFF_MIN_WAIT: core::time::Duration =
  core::time::Duration::from_secs(5);

/// RFC 6762 §8.1's fifteen-in-ten conflict history for one whole endpoint.
///
/// PLAIN FIELDS, mutated under the `&mut self` the endpoint already holds while
/// routing. Nothing here is shared, atomic or locked: the whole point of the
/// endpoint owning every `Service` is that the ring, the classification that
/// feeds it and the schedule that reads it happen in one borrow at one `now`.
///
/// [`Self::accept`] is the only writer and [`Self::in_force`] the only reader,
/// and the latter re-derives the verdict at every read — so no reader can see a
/// latch that a quiet window has already released, and there is no separate
/// release deadline to arm, miss or leave stale.
pub(crate) struct ConflictFlood<I> {
  /// The instants of the last [`CONFLICT_BURST_LEN`] conflicts this endpoint
  /// ACCEPTED, written round-robin at [`Self::slot`].
  ///
  /// A fixed array and not a growing list, because the question it answers needs
  /// no more: §8.1 asks whether the FIFTEENTH-most-recent conflict is within
  /// [`CONFLICT_BURST_WINDOW`] of now, and a sixteenth timestamp cannot change
  /// that answer.
  ring: [Option<I>; CONFLICT_BURST_LEN],
  /// Next slot to write in [`Self::ring`] (wraps at [`CONFLICT_BURST_LEN`]).
  /// Once the ring has filled, that same slot holds its OLDEST entry — the
  /// fifteenth-most-recent conflict, which is the one §8.1's test reads.
  slot: usize,
  /// Whether fifteen accepted conflicts have fallen inside one window.
  ///
  /// LATCHED rather than recomputed from the ring's span alone, and that is the
  /// whole point. Once the limit spaces probes five seconds apart, conflicts can
  /// only arrive that slowly too — so a condition re-derived purely from the
  /// fifteen-in-ten test would go false two probes later and hand the flood its
  /// speed back, oscillating between a fast burst and a clamped pair for as long
  /// as the peer keeps answering. "Each successive additional probe attempt" is
  /// every one of them, not the next.
  ///
  /// It is released by the flood STOPPING and by nothing else — see
  /// [`Self::in_force`], which is where the release is decided.
  latched: bool,
  /// The datagram [`Self::accepted`] describes, or `None` before the first
  /// conflict. A different id empties `accepted`, so the dedupe set never
  /// outlives the datagram it is about.
  datagram: Option<DatagramId>,
  /// The contested owner names already counted for [`Self::datagram`].
  ///
  /// §8.1 counts conflicts, and one defending datagram carrying SRV, TXT, NSEC
  /// and A for one name is ONE conflict about that name however many records
  /// carry it — while two different contested names in one datagram are two.
  /// So the key is `(datagram, owner name)`, compared by
  /// [`Name::same_owner`] because that is what makes two spellings of one owner
  /// the same conflict on the wire.
  ///
  /// Spent inside [`Self::accept`], AFTER classification and never at emission:
  /// a record the receiving service reads as identical, undecodable, unowned or
  /// arriving before its own first probe is not a conflict at all, so it must
  /// not consume the datagram's one count for that name and leave the genuine
  /// conflict behind it uncounted.
  ///
  /// Bounded by two names per live route — one instance name and one host name —
  /// because a name only reaches here by matching a registered route's own.
  accepted: std::vec::Vec<Name>,
}

impl<I: Copy> ConflictFlood<I> {
  /// An empty history: nothing counted, nothing latched.
  pub(crate) const fn new() -> Self {
    Self {
      ring: [None; CONFLICT_BURST_LEN],
      slot: 0,
      latched: false,
      datagram: None,
      accepted: std::vec::Vec::new(),
    }
  }
}

impl<I: Instant> ConflictFlood<I> {
  /// The most recently accepted conflict, or `None` if none has been.
  fn newest(&self) -> Option<I> {
    // `slot` is the NEXT slot to write, so the newest entry sits one before it —
    // wrapping to the last slot while the ring is still filling from zero, where
    // it reads `None` anyway.
    let newest = self
      .slot
      .checked_sub(1)
      .unwrap_or(CONFLICT_BURST_LEN.saturating_sub(1));
    self.ring.get(newest).copied().flatten()
  }

  /// Count one CLASSIFIED conflict, received at `now` from `datagram` and
  /// contesting `owner`. Returns whether it was counted.
  ///
  /// # The dedupe is spent here, after classification
  ///
  /// A datagram defending one name carries every record it holds at that name,
  /// so counting per record inflates one conflict fourfold. The key is
  /// `(datagram, owner)`: the first classified conflict about an owner counts,
  /// every later record of the same datagram about the same owner does not, and
  /// a second contested name in that same datagram counts again. Two services
  /// sharing a host name see one arriving A/AAAA as two events and the endpoint
  /// counts it once, which is what makes the count the HOST's rather than the
  /// fan-out's.
  ///
  /// # The window boundary, in one place
  ///
  /// The release test uses `>` and the span test `<=`, so the two agree about
  /// exactly ten seconds. They ran in opposite directions before: fourteen
  /// conflicts at `T` and a fifteenth at exactly `T + 10 s` took the release
  /// path — clearing the ring the span test would then have called qualifying —
  /// and fifteen conflicts genuinely inside ten seconds did not engage the
  /// floor.
  ///
  /// The release is tested BEFORE this conflict is folded in and against the
  /// previous newest, so a fresh burst from a peer that had fallen quiet starts
  /// over from an empty ring at §8.1's ordinary schedule, while a burst that is
  /// still going never reaches it at all.
  ///
  /// The clock is assumed monotonic, as [`Instant`] requires. Where it is not,
  /// both tests answer `false`: a `now` that ran backwards neither releases the
  /// history nor completes a burst.
  pub(crate) fn accept(&mut self, now: I, datagram: DatagramId, owner: &Name) -> bool {
    if self.datagram != Some(datagram) {
      self.datagram = Some(datagram);
      self.accepted.clear();
    }
    if self.accepted.iter().any(|n| n.same_owner(owner)) {
      return false;
    }
    self.accepted.push(owner.clone());

    if let Some(newest) = self.newest()
      && now
        .checked_duration_since(newest)
        .is_some_and(|since| since > CONFLICT_BURST_WINDOW)
    {
      self.ring = [None; CONFLICT_BURST_LEN];
      self.slot = 0;
      self.latched = false;
    }
    if let Some(slot) = self.ring.get_mut(self.slot) {
      *slot = Some(now);
      self.slot = self.slot.saturating_add(1) % CONFLICT_BURST_LEN;
    }
    // Once the cursor has advanced it addresses the ring's OLDEST entry: the
    // fifteenth-most-recent conflict, and `None` until fifteen have arrived. If
    // that one is within the window then all fifteen occurred inside a single
    // ten-second period, which is the whole of §8.1's condition.
    if let Some(Some(oldest)) = self.ring.get(self.slot).copied()
      && now
        .checked_duration_since(oldest)
        .is_some_and(|span| span <= CONFLICT_BURST_WINDOW)
    {
      self.latched = true;
    }
    true
  }

  /// Test-only: how many conflicts the ring currently holds. The tests that
  /// pin the dedupe key assert on this directly, because "one datagram, one
  /// count" is a statement about the ring and not about any one service.
  ///
  /// Gated to match its only callers in `endpoint/tests.rs`, whose `mod tests;`
  /// declaration carries this same predicate — a bare `cfg(test)` left it
  /// compiled, and dead, in a `test` build reaching this module without `slab`.
  #[cfg(all(test, feature = "std", feature = "slab"))]
  pub(crate) fn counted(&self) -> usize {
    self.ring.iter().flatten().count()
  }

  /// Is §8.1's five-second floor in force at `now`?
  ///
  /// RE-DERIVED AT EVERY READ, which is what makes the release need no schedule.
  /// The latch is spent only by the flood stopping — a whole
  /// [`CONFLICT_BURST_WINDOW`] in which no conflict was accepted at all — and
  /// that is a question about the newest entry, answerable from the ring at the
  /// instant a reader asks. A separate release deadline would have to be armed
  /// by whoever wrote the ring and honoured by whoever read it, which is exactly
  /// the split this design removes; here no reader can observe a latch a quiet
  /// window has already released.
  ///
  /// A rename does not release it. §8.1 counts what was received, and renaming
  /// is the loop being throttled, so resetting on a rename is the one reset that
  /// would defeat the limit.
  ///
  /// # A `now` that precedes the newest entry FAILS CLOSED
  ///
  /// When the elapsed span cannot be computed because `now` is earlier than the
  /// newest accepted conflict, the floor is reported IN FORCE. The two outcomes
  /// are not symmetric and only one of them can be wrong in a way that matters:
  /// failing open puts a probe on the wire inside the five seconds §8.1 says the
  /// host MUST wait, while failing closed costs one probe a delay of at most
  /// [`CONFLICT_BACKOFF_MIN_WAIT`]. The floor a caller then arms is ABSOLUTE —
  /// `sequence_started_at + 5 s`, not `now + 5 s` — so it converges instead of
  /// sliding, and the next read taken at or after the newest entry either serves
  /// the wait or finds the latch released. A rate limit is the one place where
  /// an unreadable clock belongs on the restrictive side.
  ///
  /// This is not a hypothetical clock fault. [`Instant`] is monotonic, but
  /// nothing obliges a driver to weigh a decision against the SAME reading it
  /// folded the conflict at: a driver that samples one instant for a pass and
  /// then counts the fifteenth conflict of a burst at a later, per-datagram
  /// reading hands this method an instant its own ring already sits ahead of, on
  /// ordinary traffic. That is a defect in the driver and it is fixed there, but
  /// it must not be able to spend the MUST on its way past.
  ///
  /// No conflict recorded AT ALL is a different question and still answers NOT
  /// in force: there is no entry for `now` to precede, and nothing the limit
  /// could be spacing out.
  pub(crate) fn in_force(&self, now: I) -> bool {
    self.latched
      && self.newest().is_some_and(|newest| {
        now
          .checked_duration_since(newest)
          .is_none_or(|since| since <= CONFLICT_BURST_WINDOW)
      })
  }
}

impl<I> core::fmt::Debug for ConflictFlood<I> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("ConflictFlood")
      .field("latched", &self.latched)
      .field("accepted", &self.accepted.len())
      .finish_non_exhaustive()
  }
}

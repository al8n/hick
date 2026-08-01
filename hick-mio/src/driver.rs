//! The caller-driven pipeline: readiness bookkeeping, deadline folding, and
//! the [`Mdns::tick`] stages that advance every state machine.
//!
//! Two properties shape this module, and both come from `hick-mio` being
//! **synchronous**.
//!
//! **All work happens in `tick`.** [`Mdns::handle_io`] records readiness and
//! nothing else. That is what makes the caller's ordering irrelevant: a loop
//! that ticks before draining events is as correct as one that drains first,
//! and a `tick` reached with no mio events at all — the timer-only wakeup —
//! still advances everything.
//!
//! **Every stage must return**, regardless of what the network, the peer, or
//! the socket does. An async driver can await a wedged socket; `tick` cannot.
//! Two different things guarantee it, and the distinction matters when adding a
//! stage:
//!
//! * the I/O stages carry their own explicit budget — `RECV_BUDGET` datagrams
//!   in, `MAX_SEND_CREDITS_PER_DRAIN` out — because their work is driven by a
//!   peer, who is under no obligation to stop;
//! * `push_updates` has **no** budget of its own. Its two drain loops
//!   (`ctx.proto.poll()` and `endpoint.poll()`) terminate because the proto
//!   layer's event slabs are fixed-capacity pools and each poll removes an
//!   entry, and because the only thing that refills them is `drain_recv`, which
//!   *is* budgeted. The bound is the proto layer's, borrowed — not this
//!   module's.
//!
//! The stages also run in a fixed order in which no early return can skip a
//! later one.
//!
//! # The clock rule
//!
//! **Read the clock at the decision, never before it. An instant may be passed
//! in only when that instant *is* the thing being defined, not merely a
//! convenient earlier reading.**
//!
//! **A reading is spent by its first consumer; a decision is spent by its first
//! application.** That sentence is the whole rule's second half and it was
//! missing for eight rounds. It is what makes the two enqueues in
//! [`begin_service_withdrawal`](crate::endpoint::begin_service_withdrawal) two
//! clock reads, and what makes a per-family send admission a question asked
//! inside [`Sockets::send_one`](crate::socket::Sockets::send_one) rather than a
//! `[bool; 2]` computed for the fan-out — see
//! [`FamilyAdmission`](crate::socket::FamilyAdmission).
//!
//! Nine instances across eight adversarial rounds, each in a different place,
//! all one defect: a decision weighed against an instant captured before the
//! work that decision was meant to measure. A credit aged from a pre-syscall
//! stamp. A credit aged before the receive resumed. A credit swept across tick
//! stages by a later record, then frozen at tick entry, then frozen immediately
//! after the read. A goodbye's resend anchor backdated to the top of the tick. A
//! cap admission decided on a length a 65 536-entry sweep had left behind. A
//! withdrawal schedule created from an instant older than the withdrawal. One
//! reading serving two schedule-creating enqueues. One per-family admission mask
//! carried across a syscall to its second application.
//!
//! The rule sorts every instant in this crate into two kinds, and the second
//! kind is small.
//!
//! **A protocol instant may be passed in.** [`Mdns::tick`] reads one at its top
//! and every *protocol* deadline inside that tick is weighed against it — the
//! endpoint's, each service's lifecycle, each query's RFC 6762 §5.2 retry. Those
//! are schedules the core owns and nobody outside it can observe, so one stable
//! value per tick is the point: two stages that disagree about "now" can fire a
//! deadline twice or skip it, while the quantization itself never leaves the
//! core. Nothing real-time may be measured from it.
//!
//! **A real-time instant may not.** Anything answering "how long has actually
//! elapsed", and anything a **caller** was promised in wall-clock terms — a
//! self-send credit's age, a wire's spacing gap, when a withdrawal schedule
//! begins, when its next round is due, whether a lookup's
//! [`QueryParam::with_timeout`](crate::QueryParam::with_timeout) window is still
//! open — is read at the decision by the code that makes it. The strongest form
//! is to take no instant at all, which is what
//! [`SelfSendTracker::take`](crate::selfsend::SelfSendTracker::take),
//! [`send_and_credit`], [`Mdns::push_updates`], [`Mdns::advance_lookups`] and
//! [`Mdns::drain_withdrawals`] all do: a parameter is a channel through which a
//! caller hands in a reading taken somewhere else, and moving the read nearer
//! never removes the channel. Deleting it does.
//!
//! **A deadline comparison is not automatically a protocol deadline.** Which
//! kind an instant is depends on *who was promised it*, never on the `>=` that
//! weighs it — and the two comparisons are written identically, which is what
//! makes the misfiling easy. A lookup's deadline is
//! [`QueryParam::with_timeout`](crate::QueryParam::with_timeout) made absolute:
//! the caller is told that on and after it the lookup consumes no answer, starts
//! no sub-query and surfaces no entry. Weighing that against the tick's instant
//! spends the whole of stages 1 through 5 inside a window the caller was told
//! was shut, and stage 6 is where the tick's reading is at its stalest. So the
//! lookup's own boundary is real-time even though a sub-query's §5.2 ladder,
//! sitting one layer below it, is not.
//!
//! What is left is the instructions between the read and the comparison, and it
//! is irreducible — something must read a clock before something can compare
//! against it.
//!
//! **And one reading may have two uses when they are inverses.** A DNS-SD
//! sub-query is started with an absolute anchor and a relative budget, and the
//! budget is `lookup deadline - anchor` while the proto layer's only use of the
//! anchor is to add the budget back — so the leg lands on its lookup's deadline
//! exactly, however stale the anchor is. Nothing is measured; the reading is an
//! *origin*, and both uses are in the same coordinate system. Deleting that
//! pairing would not close a defect, it would open one: a budget from one read
//! and an anchor from another leave the leg outliving its lookup by the gap. So
//! the reading is taken where both uses are, inside
//! [`LookupCtx::start_subquery_in_window`](crate::discovery::LookupCtx), and no
//! parameter offers a caller the chance to split it. Round eleven audited this
//! site expecting the ninth instance and found the arithmetic instead; what it
//! closed was the four parameter channels around it, not the pairing.
//!
//! # How to look, and how not to
//!
//! **Enumerating capture→consumer pairs is not the method.** Round eight
//! classified all 28 of them, closed seven entry points by deleting the
//! parameter, and wrote that the hunt could stop. Its own diff then contained
//! two more instances, each under a fresh doc comment defending it. The model is
//! what failed, not the diligence: a pair scores each edge separately, so a
//! single reading with *two* consumers is two individually innocent edges, and a
//! decision applied twice is invisible to it entirely. Both survivors were
//! exactly those shapes.
//!
//! So do not audit the pairs. Take each *reading* and each *decision* and ask
//! who spends it — if the answer is more than one place, or one place reached
//! after other work, that is the defect whatever the edges look like. Prefer the
//! form where the question cannot be asked: no parameter, or a capability asked
//! at the point of use, so that a stale answer has no type to live in.

use std::time::{Duration, Instant as StdInstant, SystemTime};

use mdns_proto::{
  QueryHandle, ServiceHandle, ServiceUpdate, TransmitDelivery, TransmitObligation,
  event::RouteEvent,
};

use crate::{endpoint::Mdns, error::TickError, event::Event, onlink, selfsend::MatchMode};

pub(crate) use sends::{FamilyWireGate, SendHealth, send_and_credit};
pub(crate) use withdrawal::GoodbyeLedger;

/// Per-family delivery reporting, the per-family wire gate, and the link-health
/// signal — see the module's own docs.
mod sends;
/// The RFC 6762 §10.1 goodbye stage. A separate responsibility rather than
/// another link in the tick chain — see the module's own docs.
mod withdrawal;

/// Datagrams one [`Mdns::tick`] may ingest before handing control back.
///
/// A tick runs inside the caller's own event loop, so an unbounded drain would
/// let a flooding peer starve every other token the caller is polling. Stopping
/// at the budget leaves the socket's readable flag set, which is exactly what
/// makes [`Mdns::next_timeout`] report zero and the drain resume immediately.
///
/// # It bounds `recv` calls, not syscalls
///
/// This counts iterations of the drain loop, and each one calls
/// [`Sockets::recv`] once — but a single `recv` may itself consume and discard
/// up to [`MAX_DISCARDED_PER_RECV`](crate::socket::MAX_DISCARDED_PER_RECV)
/// unusable datagrams (oversized, unparseable, or `EINTR`) before it returns
/// one this loop can use. **The two budgets multiply**: against a peer
/// interleaving oversized and valid datagrams, one `tick` can issue up to
/// `RECV_BUDGET * MAX_DISCARDED_PER_RECV` ~= 4096 `recvmsg` calls.
///
/// That product is accepted rather than capped. Each discard is one bounded
/// syscall with no allocation and no parsing, the worst case needs a peer
/// flooding the link, and both budgets end the tick with the readable flag
/// still set — so the caller's loop regains control either way. Making the
/// discard budget per-`tick` instead would cap the syscalls but let a burst of
/// oversized datagrams consume the whole allowance and stall the valid
/// datagrams queued behind them until the next tick.
pub(crate) const RECV_BUDGET: usize = 64;

/// Datagrams one [`Mdns::tick`] may put on the wire before handing control
/// back.
///
/// A fairness cap, like [`RECV_BUDGET`]: a very large handle set must not
/// monopolise the loop.
///
/// **This is the per-tick drain budget and nothing else. It is not a self-send
/// credit** — despite both being called credits, this one has no bearing on
/// loopback suppression, which is [`send_and_credit`]'s job and is counted per
/// family, not per datagram. Changing this budget cannot make the tracker miss
/// a loopback copy, and no self-send accounting may ever be derived from it.
///
/// Because every produced datagram costs exactly one unit — see
/// [`datagram_cost`] — this is also, exactly, the number of senders one tick is
/// guaranteed to visit when every one of them is busy, which is what makes
/// [`TxQueue`]'s bound a plain `ceil(senders / 64)` ticks rather than something
/// that depends on how many families happen to be bound.
const MAX_SEND_CREDITS_PER_DRAIN: usize = 64;

/// What one produced datagram costs the drain budget, given the `families_sent`
/// its send report showed.
///
/// **One, always.** The argument is taken and ignored on purpose: this is the
/// single point where a send's syscall count meets the fairness budget, and the
/// answer has to be visible — and testable — rather than spelled out afresh at
/// each drain loop, where "well, it did two syscalls" reads plausible.
///
/// The budget is a fairness quantum, not a syscall counter. A multicast transmit
/// fans out to every bound socket, so charging per successful syscall makes the
/// same logical datagram cost two on a dual-stack host and one on a single-stack
/// one: a busy dual-stack queue would then visit only half as many senders per
/// tick, and the ticks-to-serve bound stated on [`TxQueue`] would silently
/// double with nothing in the code changing. Charging the logical datagram keeps
/// the bound family-independent.
///
/// Charging a datagram whose every family *failed* is what keeps each drain loop
/// terminating inside a call that must return: a wedged socket that never
/// accepts a byte would otherwise be retried forever within one quantum. An
/// async driver can afford to keep retrying inside one pass; `tick` cannot.
///
/// The syscalls stay bounded — at most `bound_families *
/// MAX_SEND_CREDITS_PER_DRAIN` per tick, so 128 on a dual-stack host — just not
/// by *this* counter.
pub(crate) const fn datagram_cost(_families_sent: usize) -> usize {
  1
}

/// Consecutive `Service::poll_transmit` failures tolerated before a
/// registration is treated as structurally unusable.
///
/// The proto layer retries the failed transmit on the next call, so three
/// failures across consecutive ticks means the payload simply cannot be encoded
/// into the configured scratch buffer. The service is retired with a
/// [`ServiceUpdate::Conflict`] so the caller learns why, instead of waiting for
/// an `Established` that can never arrive.
pub(crate) const MAX_CONSECUTIVE_ENCODE_ERRORS: u8 = 3;

/// Bounded wakeup for pending output that no mio event will announce.
///
/// The third arm of [`Mdns::next_timeout`]. Zero would busy-spin; `None` would
/// strand the queue. 50 ms is short enough that a stranded datagram is still
/// timely for mDNS and long enough that a persistently failing `reregister`
/// costs 20 wakeups a second, not a core.
pub(crate) const RETRY_INTEREST_BACKOFF: Duration = Duration::from_millis(50);

/// How many times [`RETRY_INTEREST_BACKOFF`] may double for a family that keeps
/// failing to receive. Four doublings caps the wait at 800 ms.
const MAX_RECV_BACKOFF_DOUBLINGS: u32 = 4;

/// Wakeup for a family whose readiness was retained across a transient receive
/// error, given [`Sockets::recv_error_backoff_level`].
///
/// The flag is still set, so the data behind the error is not lost — but
/// `has_readable` has stopped speaking for that family precisely so a socket
/// erroring on every call does not spin a core at a zero timeout. Something
/// still has to bring the caller back, and this is it.
///
/// It escalates because the two cases it serves are so different. A one-off
/// `ENOBUFS` clears on the very next attempt and wants the same 50 ms as any
/// other lost edge; a socket erroring every single time wants to cost a
/// trickle. Doubling to a 800 ms ceiling covers both, and the caller's folded
/// deadline still caps it, so nothing genuinely scheduled is delayed by it.
fn recv_error_backoff(level: u32) -> Duration {
  RETRY_INTEREST_BACKOFF
    .saturating_mul(1u32 << level.saturating_sub(1).min(MAX_RECV_BACKOFF_DOUBLINGS))
}

/// Physical event-queue length above which [`Mdns::tick`] compacts.
///
/// The event queue's *logical* size is capped by
/// [`EventQueue::ANSWER_CAPACITY`](crate::event::EventQueue::ANSWER_CAPACITY),
/// but an evicted answer leaves a tombstone in the backing store until `pop`
/// reaches it — so a flooding peer plus a caller that does not drain every tick
/// grows physical memory without bound. `tick` is the only producer, so the
/// bound is enforced here. Four times the logical cap leaves ample room for a
/// normal burst before any compaction runs at all.
pub(crate) const EVENT_QUEUE_COMPACT_THRESHOLD: usize =
  4 * crate::event::EventQueue::ANSWER_CAPACITY;

impl Mdns {
  /// How long the caller may block in `Poll::poll` before calling
  /// [`tick`](Self::tick) again. `None` means "block indefinitely".
  ///
  /// The value folds every scheduled deadline — the endpoint's, each
  /// non-retired service's, each running query's, and each running lookup's —
  /// into a duration from now, saturating at zero for a deadline already past.
  /// Three states override that fold:
  ///
  /// * **readable data left over from a budget-capped drain** returns
  ///   [`Duration::ZERO`]. mio's readiness is edge-triggered, so a datagram
  ///   already sitting in the socket buffer will never re-notify and blocking
  ///   would go deaf.
  /// * **work due now that no deadline announces** returns [`Duration::ZERO`]
  ///   too: a query that has never transmitted, a transmit drain that stopped at
  ///   its credit cap or cut a sender off at its round-robin quantum, or a
  ///   service whose `poll_transmit` failed to encode — the core keeps that
  ///   datagram armed and schedules no deadline for one it has already armed. It
  ///   cannot spin — the next tick either performs the work, hands every sender
  ///   another fair share of a whole send budget, or, after a bounded number of
  ///   consecutive failures, retires the service that cannot encode.
  /// * **a socket no edge will announce** returns a bounded 50 ms backoff,
  ///   capped against the folded deadline. Two states reach it, and what they
  ///   share is that mio has no edge left to deliver:
  ///
  ///   1. a **receive** re-arm that failed. The raw `WSARecvMsg` bypasses mio's
  ///      `do_io`, so on Windows that re-arm is the only thing that regenerates
  ///      a readable edge; a failure leaves the family deaf with no deadline of
  ///      its own;
  ///   2. a family whose readiness was retained across a transient receive
  ///      error, which `has_readable` has deliberately stopped speaking for.
  ///
  /// **A refused send needs no arm of its own.** It is reported to the core as
  /// a miss inside the tick that made it, and the core re-arms the same datagram
  /// on a deadline the fold above already sees. That is the whole reason there is
  /// no send-side term here: nothing is parked, so nothing is waiting on an
  /// event that will not come.
  pub fn next_timeout(&self) -> Option<Duration> {
    if self.sockets.has_readable() || self.work_pending {
      return Some(Duration::ZERO);
    }

    let mut best: Option<StdInstant> = self.endpoint.poll_timeout();
    for ctx in self.services.values() {
      // A retired service's proto state machine is finished; its remaining
      // schedule, if any, belongs to the endpoint.
      if ctx.withdrawing {
        continue;
      }
      if let Some(t) = ctx.proto.poll_timeout() {
        best = Some(min_opt(best, t));
      }
    }
    for &handle in self.queries.keys() {
      if let Some(t) = self.endpoint.poll_query_timeout(handle) {
        best = Some(min_opt(best, t));
      }
    }
    // A lookup's own deadline is not any sub-query's: it also ends a lookup
    // whose legs have all been answered, so folding only the sub-queries would
    // let the caller sleep through the `LookupDone` that is already due.
    for t in self.lookups.deadlines() {
      best = Some(min_opt(best, t));
    }

    let now = StdInstant::now();
    let folded = best.map(|t| t.saturating_duration_since(now));
    // Two independent reasons to come back on a timer rather than block, each
    // with its own bound: a socket whose edge is gone, and a family whose
    // readiness was retained across a transient receive error. Whichever is
    // sooner wins, and the folded deadline still caps both.
    let mut backoff = self
      .sockets
      .needs_interest_retry()
      .then_some(RETRY_INTEREST_BACKOFF);
    let level = self.sockets.recv_error_backoff_level();
    if level > 0 {
      let d = recv_error_backoff(level);
      backoff = Some(backoff.map_or(d, |b| b.min(d)));
    }
    match backoff {
      Some(b) => Some(folded.map_or(b, |d| d.min(b))),
      None => folded,
    }
  }

  /// Record readiness for one of our sockets.
  ///
  /// **All** work happens in [`tick`](Self::tick) — this keeps the caller's
  /// ordering irrelevant, so a loop that ticks before draining events is still
  /// correct. Pass only events whose token [`owns`](Self::owns) claims.
  pub fn handle_io(&mut self, ev: &mio::event::Event) {
    self.sockets.note_readiness(ev);
  }

  /// Advance every state machine once. Call this once per event-loop
  /// iteration, whether or not any event arrived.
  ///
  /// The stages run in a fixed order, and the order is the correctness
  /// property:
  ///
  /// 1. **receive** — ingest a bounded batch of datagrams, each through the
  ///    RFC 6762 §11 on-link gate and the self-send tracker, so every later
  ///    stage sees the freshest peer state.
  /// 2. **sweep** — drop contexts whose proto-side state is already gone, so no
  ///    later stage drives a handle that no longer exists.
  /// 3. **timers** — fire every due deadline, which is what *produces* the
  ///    transmits and updates the next two stages drain.
  /// 4. **transmit** — put due datagrams on the wire, take one self-send
  ///    credit per multicast loopback copy they produce, and **confirm each one
  ///    before the next is polled**.
  /// 5. **updates** — move proto-layer updates and collected answers into the
  ///    event queue.
  /// 6. **lookups** — consume every lookup sub-query's answers and terminal,
  ///    advance the DNS-SD aggregation, start the follow-up resolves it asks
  ///    for, and emit resolved entries. The **only** consumer of a sub-query's
  ///    answers, which is what keeps them out of the caller's event queue: stage
  ///    5 deliberately skips any query a lookup owns.
  /// 7. **withdrawals** — pump every due RFC 6762 §10.1 goodbye and GC each
  ///    withdrawal that completed. After stage 5, so a service retired by *this*
  ///    tick begins its goodbye in the same tick rather than a whole loop
  ///    iteration later.
  ///
  /// No stage can be skipped: none of them returns a `Result`. The only
  /// fallible call is the registration retry that closes the tick, and it runs
  /// after every stage rather than between any two of them.
  ///
  /// # Nothing outlives its stage
  ///
  /// There is no completion stage, because there is nothing left over to
  /// complete. Every datagram stage 4 produces is polled, sent, and **confirmed
  /// inside one iteration of stage 4's own loop** — which is what satisfies the
  /// core's confirm-before-anything contract structurally rather than by
  /// convention: no `handle_event`, `handle_timeout`, or teardown can land
  /// between a `poll_transmit` and its confirm, because none of them is reachable
  /// from inside that loop.
  ///
  /// `compact_events` is deliberately **not** one of the numbered stages, and
  /// it runs between 6 and 7 rather than inside 5. Stages 4, 5 and 6 are the
  /// only producers of events, so the end of stage 6 is the first point at
  /// which this tick can grow the queue no further; stage 7 adds nothing to it.
  /// Bounding it earlier would leave stage 6's own output uncompacted for a
  /// whole loop iteration.
  ///
  /// # Errors
  ///
  /// Reports a failure to re-arm a socket's registration — a receive re-arm
  /// that failed earlier in this same tick, which the close of the tick is what
  /// retries. The condition is recoverable and already self-correcting — the
  /// socket layer records the failure, the next tick retries it, and
  /// [`next_timeout`](Self::next_timeout) meanwhile returns a bounded backoff
  /// so the caller comes back — so the right response is to keep ticking, not
  /// to abandon the loop. A re-arm that keeps failing keeps returning this, which
  /// is the difference between a degraded socket the caller can see and one that
  /// has silently gone deaf.
  pub fn tick(&mut self) -> Result<(), TickError> {
    let now = StdInstant::now();
    // Recorded, not consulted: no stage reads it back. See the field.
    #[cfg(test)]
    {
      self.last_tick_instant = Some(now);
    }
    // Hand every family back its transient-receive-error budget. Once per tick
    // is what makes the retry bounded rather than merely repeated.
    self.sockets.begin_recv_round();
    // Open the self-send claim window before the stage that claims from it. It
    // takes no instant and is deliberately not given `now`: the anchor it stamps
    // this batch with is the first moment a credit the previous tick recorded can
    // be claimed, and `SELF_SEND_TTL` may be measured from nothing earlier or
    // later — so it is read inside the seal, after the sweep that precedes it,
    // rather than handed in from here. The outbound stages below all run after
    // stage 1, so the tick that records a credit can never claim it; top of the
    // tick rather than end of the outbound stages so that stays true however
    // stages 4 through 7 are later reordered or added to.
    self.selfsend.seal();
    self.drain_recv(now);
    self.sweep();
    self.fire_timeouts(now);
    self.drain_transmits(now);
    // None of the three below takes `now`, and that is the fix rather than an
    // omission: each contains a decision that is a REAL-TIME question rather
    // than a protocol deadline, and each reads the clock at that decision. See
    // this module's clock rule.
    //
    // For `push_updates` and `drain_withdrawals` the question is when a
    // withdrawal schedule begins and when its rounds are due. For
    // `advance_lookups` it is whether a lookup's `QueryParam::with_timeout`
    // window is still open — a bound the CALLER holds, not a schedule the core
    // owns, so the tick's quantization would be visible in exactly the place it
    // must not be. Being a deadline comparison does not make it the tick's
    // protocol instant; being the core's own schedule is what does, and this
    // one is not. The sub-queries this stage starts anchor themselves too — see
    // `LookupCtx::start_subquery_in_window`.
    self.push_updates();
    self.advance_lookups();
    self.compact_events();
    self.drain_withdrawals();
    self.sockets.end_tick().map_err(TickError::from)
  }

  /// Stage 1: ingest up to [`RECV_BUDGET`] datagrams.
  ///
  /// Each one passes the ingress trust boundary — the interface it arrived on
  /// and the RFC 6762 §11 on-link gate, both in
  /// [`onlink::admits_ingress`] — and then the untrusted-response guard,
  /// *before* it can consume a self-send credit or reach the proto layer.
  fn drain_recv(&mut self, now: StdInstant) {
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();

    for _ in 0..RECV_BUDGET {
      // Disjoint field borrows: the socket we read from, the buffer we read
      // into, and the state machines we feed are all separate fields.
      let Self {
        endpoint,
        services,
        sockets,
        selfsend,
        recv_buf,
        local_subnets,
        bound_interface,
        #[cfg(test)]
        forced_claim_delays,
        ..
      } = &mut *self;

      let Some((meta, family)) = sockets.recv(recv_buf.as_mut_slice()) else {
        return;
      };
      // No second clock read here, and none anywhere else in this loop — do not
      // add one. `now` is the tick's PROTOCOL instant: the core weighs every
      // deadline within a tick against one stable value, so it is what
      // `endpoint.handle` and every stage below receive, unchanged. It is not,
      // and must not become, the age of a self-send credit. `SELF_SEND_TTL` is
      // no deadline but a real-time bound on FALSE suppression, so that age
      // belongs to `SelfSendTracker::take`, which reads it at its own liveness
      // decision and accepts an instant from nobody. An instant captured at this
      // line would already be stale by the two admission gates below — see that
      // method's docs for why the parameter was the defect rather than the fix.
      let Some(data) = recv_buf.get(..meta.len()) else {
        // `recv` never reports more bytes than the buffer holds; a datagram
        // that would not fit was already rejected as truncated.
        continue;
      };

      // The ingress trust boundary, applied BEFORE the proto layer can cache or
      // act on attacker-injected records and BEFORE the take-once credit is
      // consulted: the link the datagram arrived on, then RFC 6762 §11. Both
      // gates live in `onlink::admits_ingress` so neither can be applied to only
      // one of the §11 branches — the interface check in particular, which the
      // hop-limit branch used to skip entirely even though a conforming hop
      // limit says nothing about *whose* link a wildcard-bound socket heard.
      //
      // `destination` is the datagram's IP header destination, which is what
      // selects between §11's two arms where no hop limit was reported, and
      // `multicast_flag` is the kernel's coarser stand-in where no destination
      // was recovered. NOT `local_ip`, which on Unix IPv4 is the receiving
      // interface's own address and can never equal a group — see
      // `admits_ingress` for why reading it here rejected the very traffic §11
      // exists to admit.
      let pkt_iface = sockets.rx_interface(&meta);
      if !onlink::admits_ingress(
        sockets.rx_peer(&meta),
        meta.destination(),
        meta.multicast_flag(),
        meta.hop_limit(),
        local_subnets,
        *bound_interface,
        pkt_iface,
      ) {
        hick_trace::debug!(
          src = %meta.peer(),
          dst = ?meta.destination(),
          multicast_flag = ?meta.multicast_flag(),
          hop_limit = ?meta.hop_limit(),
          interface_index = pkt_iface,
          bound_interface = *bound_interface,
          "dropping an off-link datagram (ingress trust boundary)"
        );
        #[cfg(feature = "stats")]
        {
          stats.packets_rx(1);
          stats.bytes_rx(data.len() as u64);
          stats.packets_dropped(1);
        }
        continue;
      }

      // §11 source-port rule for RESPONSES, enforced before the take-once
      // credit is consulted. An on-link attacker echoing a byte-identical copy
      // of our own datagram from an ephemeral port would otherwise burn the
      // credit, leaving our genuine port-5353 loopback to be ingested as a
      // trusted peer. Queries (QR=0) are exempt: legacy unicast queriers do use
      // ephemeral ports.
      if packet_is_response(data) && meta.peer().port() != hick_udp::constants::MDNS_PORT {
        hick_trace::debug!(
          src = %meta.peer(),
          "dropping an untrusted response (source port != 5353) before the self-send match"
        );
        #[cfg(feature = "stats")]
        {
          stats.packets_rx(1);
          stats.bytes_rx(data.len() as u64);
          stats.packets_dropped(1);
        }
        continue;
      }

      // The credit is looked up under the family this datagram arrived on. A
      // multicast transmit fans out to both sockets with IDENTICAL bytes and
      // two separately-stamped credits, and the rotor does not fix which socket
      // is read first — so without the family key the second echo read can
      // consume the first echo's credit and leave its own owner facing a credit
      // stamped after the kernel saw it. See `SelfSendTracker::take`.
      //
      // A kernel receive timestamp additionally carries ordering information,
      // which is what stops a byte-identical peer datagram the kernel saw
      // BEFORE our send from stealing the credit. Without one there is no
      // ordering to check, so matching degrades to content hash inside the TTL
      // window.
      //
      // The wall stamp only ORDERS the echo against the send. Two clocks answer
      // two questions and this call supplies exactly one of them: the credit's
      // AGE is read inside `take`, at the decision, because everything between
      // the read above and this line — both admission gates, and whatever the
      // scheduler does among them — is elapsed time the credit must be charged.
      #[cfg(test)]
      Self::stall_before_claim(forced_claim_delays);
      let caller_is_self = match sockets.rx_time(&meta) {
        Some(rx) => selfsend.take(family, data, rx, MatchMode::Ordered),
        None => selfsend.take(family, data, SystemTime::now(), MatchMode::Degraded),
      };

      let route_events = match endpoint.handle(
        now,
        meta.peer(),
        meta.local_ip(),
        pkt_iface,
        data,
        caller_is_self,
      ) {
        Ok(it) => it,
        Err(_e) => {
          hick_trace::debug!(error = %_e, src = %meta.peer(), "endpoint.handle failed");
          continue;
        }
      };

      for ev in route_events {
        match ev {
          Ok(RouteEvent::ToService(ts)) => {
            // A retired service's proto no longer has its updates drained, so
            // feeding it events would let a peer grow its event slab unbounded.
            if let Some(ctx) = services.get_mut(&ts.handle())
              && !ctx.withdrawing
            {
              ctx.proto.handle_event(ts.into_event(), now);
            }
          }
          // Query answers are dispatched inside `endpoint.handle`; every other
          // variant is a hook this crate does not consume yet.
          Ok(_) => {}
          Err(_e) => {
            hick_trace::debug!(error = %_e, "route event error mid-datagram; abandoning it");
            break;
          }
        }
      }
    }
  }

  /// Lose the CPU where the drain really can: after a datagram has been read and
  /// admitted, and before the credit check weighs it. See
  /// [`Mdns::forced_claim_delays`].
  #[cfg(test)]
  fn stall_before_claim(stalls: &mut std::collections::VecDeque<Duration>) {
    if let Some(stall) = stalls.pop_front()
      && !stall.is_zero()
    {
      std::thread::sleep(stall);
    }
  }

  /// Stall the next admitted datagrams between admission and the self-send
  /// claim, one entry per datagram. See [`Mdns::forced_claim_delays`].
  #[cfg(test)]
  pub(crate) fn force_claim_delays_for_test(&mut self, stalls: &[Duration]) {
    self.forced_claim_delays = stalls.iter().copied().collect();
  }

  /// Stage 2: drop contexts whose proto-side state is already gone.
  ///
  /// A query the proto layer no longer knows cannot be polled, timed out, or
  /// transmitted for; keeping its context would pin memory and make every later
  /// stage do lookup work for a handle that resolves to nothing.
  ///
  /// **Only queries are swept, and a service must never be added here.** A
  /// service route is released in exactly one place — `drain_completed_withdrawals`
  /// in stage 7 — which frees the route and GCs the driver context together, so a
  /// service context cannot be orphaned. Everything else that ends a service's
  /// life ([`Mdns::unregister_service`], [`Mdns::shutdown`], an internal
  /// retirement) only *begins* a withdrawal: the endpoint deliberately **keeps**
  /// the route while the RFC 6762 §10.1 goodbye is in flight, so it holds the
  /// name against a same-name re-registration.
  ///
  /// That is why reconciling `services` against the proto routing table here
  /// would be wrong rather than tidy — during a withdrawal both sides are still
  /// present on purpose, and the GC belongs to stage 7 ([`Mdns::drain_withdrawals`]).
  fn sweep(&mut self) {
    let Self {
      endpoint, queries, ..
    } = self;
    queries.retain(|handle, _| endpoint.query_accepted_count(*handle).is_some());
  }

  /// Stage 3: fire every deadline that is due.
  ///
  /// This is what produces the transmits and updates stages 4 and 5 drain, so
  /// it must run before them even when nothing was received.
  fn fire_timeouts(&mut self, now: StdInstant) {
    let _ = self.endpoint.handle_timeout(now);
    for ctx in self.services.values_mut() {
      // A retired service's lifecycle is finished; driving its proto is waste.
      if ctx.withdrawing {
        continue;
      }
      let _ = ctx.proto.handle_timeout(now);
    }
    // Split-borrow so the query map is walked in place: `handle_query_timeout`
    // touches only the disjoint `endpoint` field.
    let Self {
      endpoint, queries, ..
    } = &mut *self;
    for &handle in queries.keys() {
      let _ = endpoint.handle_query_timeout(handle, now);
    }
  }

  /// Stage 4: put due datagrams on the wire, one fair share at a time.
  ///
  /// Every registered service and every running query is one [`TxSlot`] in a
  /// **single queue**, served first-waiting-first-served by [`TxQueue`]. That is
  /// the whole of the fairness discipline, and both halves are load-bearing: the
  /// per-slot quantum stops one sender draining the budget, and the queue order
  /// stops the same senders leading every tick. See [`TxQueue`] for the property
  /// it guarantees and why churn cannot defeat it.
  ///
  /// Self-send credits are taken per **family**, not per logical transmit: a
  /// multicast destination fans out to both bound sockets, so the kernel loops
  /// two copies back and the tracker needs two entries. See
  /// [`send_and_credit`], which owns that accounting. The fairness budget is
  /// charged the other way round — [`datagram_cost`] per logical datagram,
  /// family count irrelevant — and the two must never be derived from each
  /// other.
  ///
  /// # Poll, send, confirm — in one iteration
  ///
  /// Every datagram is confirmed before the next `poll_transmit` for that
  /// producer, and no other entry point runs in between. That is the core's
  /// confirm-before-anything contract, held structurally: a family whose socket
  /// refused the datagram is reported `Missed` right here, because a `WouldBlock`
  /// send handed nothing to the kernel and the core re-arms the same probe
  /// index, announcement count, or §5.2 question on its own schedule. Deferring
  /// the confirm to a later stage is what a parked-send table would require, and
  /// it would leave a commit token live across `handle_event`, `handle_timeout`,
  /// a rename, and a teardown.
  fn drain_transmits(&mut self, now: StdInstant) {
    let Self {
      endpoint,
      services,
      queries,
      sockets,
      selfsend,
      send_health,
      events,
      send_buf,
      tx_scratch,
      tx_queue,
      retired_scratch,
      work_pending,
      ..
    } = &mut *self;

    // `HashMap` iteration order is arbitrary and reshuffles on rehash; the
    // sequence each context carries is what puts this list back into queue
    // order, so the collection order here is irrelevant.
    tx_scratch.clear();
    tx_scratch.extend(
      services
        .iter()
        .map(|(&handle, ctx)| (ctx.tx_seq, TxSlot::Service(handle))),
    );
    tx_scratch.extend(
      queries
        .iter()
        .map(|(&handle, ctx)| (ctx.tx_seq, TxSlot::Query(handle))),
    );
    if tx_scratch.is_empty() {
      *work_pending = false;
      return;
    }

    retired_scratch.clear();
    let left_work_behind = tx_queue.serve(
      tx_scratch.as_mut_slice(),
      MAX_SEND_CREDITS_PER_DRAIN,
      // `spent` is charged in DRAIN-budget units — see `datagram_cost`, which
      // is the one place a send's syscall count meets this budget. It is not a
      // self-send credit; `send_and_credit` already took those, per family, and
      // nothing here may be derived from them.
      |slot, quantum, next_seq| match slot {
        TxSlot::Service(handle) => {
          // Requeued the moment its turn is offered, before it can spend any of
          // it. A sender that took its turn goes to the tail whatever it did
          // with it — sent, idle, retired mid-walk — because it is *being
          // offered a turn*, not *using* one, that the queue order is a record
          // of. Skipping the requeue for an idle sender would pin it at the head
          // forever.
          match services.get_mut(&handle) {
            Some(ctx) => {
              ctx.tx_seq = next_seq;
              // Retired, by an earlier slot in this same walk or before it.
              if ctx.withdrawing {
                return (0, false);
              }
            }
            None => return (0, false),
          }
          let mut spent = 0usize;
          let mut hit_encode_error = false;
          let mut capped = loop {
            if spent >= quantum {
              break true;
            }
            let tx = match services.get_mut(&handle) {
              Some(ctx) => match ctx.proto.poll_transmit(now, send_buf.as_mut_slice()) {
                Ok(Some(tx)) => {
                  ctx.encode_failures = 0;
                  tx
                }
                Ok(None) => {
                  ctx.encode_failures = 0;
                  break false;
                }
                Err(_e) => {
                  ctx.encode_failures = ctx.encode_failures.saturating_add(1);
                  hick_trace::warn!(
                    handle = ?handle,
                    error = ?_e,
                    consecutive_failures = ctx.encode_failures,
                    "Service::poll_transmit failed"
                  );
                  hit_encode_error = true;
                  // LEFTOVER WORK, not "nothing due". The core retries the same
                  // datagram on the next `poll_transmit` and schedules no
                  // deadline for one it has already armed, so nothing in
                  // `next_timeout`'s fold speaks for it. Reporting `false` here
                  // cleared `work_pending` and let the caller block in
                  // `Poll::poll` on a datagram sitting in memory — and mio's
                  // readiness is edge-triggered, so no event can ever wake it.
                  // It would also stall the retirement below, which only counts
                  // failures on ticks that reach this arm.
                  break true;
                }
              },
              None => break false,
            };
            let len = tx.size().min(send_buf.len());
            // Read from the transmit BEFORE the send, because the send is what
            // consumes it: `tx` borrows nothing, but the confirm below spends
            // the commit token it belongs to, and after that this datagram is
            // no longer a thing the core is offering.
            let obligation = tx.obligation();
            // The gate is copied out and written back rather than borrowed
            // across the send, so `services` stays free for the confirm below.
            let mut gate = services
              .get(&handle)
              .map(|ctx| ctx.wire_gate)
              .unwrap_or_default();
            let summary = send_and_credit(
              sockets,
              selfsend,
              send_health,
              &mut gate,
              &send_buf[..len],
              tx.dst(),
              tx.min_family_gap(),
            );
            // Confirmed here, before anything else can touch this service:
            // the core holds a commit token from the `poll_transmit` above and
            // every other entry point is forbidden until it is spent. Anchored
            // at the EARLIEST family acceptance, which is the instant the core
            // anchors each delivered family's refresh at; a round that reached
            // no wire has no acceptance and is spaced from the attempt instead.
            let at = summary.accepted_at.unwrap_or_else(StdInstant::now);
            if let Some(ctx) = services.get_mut(&handle) {
              ctx.wire_gate = gate;
            }
            confirm_service(endpoint, services, handle, at, summary.delivery);
            spent = spent.saturating_add(datagram_cost(summary.sent));
            // Every reachable socket refused these bytes as too large, so the
            // datagram is not late — it is impossible. What that costs depends
            // entirely on whether the core will offer it again.
            if summary.undeliverable {
              match obligation {
                // Sustained: a probe or an §8.3 announcement, re-armed until
                // every obligated link accepts it. Nothing ever will, so the
                // service would probe or announce forever with nothing on any
                // wire and never reach `Established` — and no patience bound
                // helps, because the core's own excuses a MISSING family, not a
                // round that can never succeed on any of them. Retire it so the
                // caller sees an actionable terminal instead of a silent stall.
                //
                // AFTER the confirm above, never instead of it: the core holds a
                // commit token from this `poll_transmit`, the honest all-missed
                // confirm is what spends it and latches nothing, and stage 7
                // builds the §10.1 goodbye from what a confirm has latched. A
                // retirement under a live token would build it from a service
                // the core still considers mid-datagram.
                TransmitObligation::Sustained => {
                  hick_trace::warn!(
                    handle = ?handle,
                    len,
                    "no bound family can carry this service's datagram; retiring it with a Conflict"
                  );
                  retire_service(services, events, handle);
                  // Nothing left for this slot: every later stage skips a
                  // withdrawing service, so the datagram is abandoned with the
                  // producer and no zero timeout could come back for it. Same
                  // exit the terminal encode failure below takes, for the same
                  // reason.
                  break false;
                }
                // One-shot: a §6 / §6.7 / RFC 6763 §9 reply, never re-armed. It
                // costs exactly one unanswered question — the querier re-asks —
                // and the confirm above has already resolved it as the miss it
                // was. Retiring here would let any peer tear down a healthy
                // established service by asking it a question whose answer does
                // not fit.
                TransmitObligation::OneShot => {}
              }
            }
          };
          if hit_encode_error
            && services
              .get(&handle)
              .is_some_and(|ctx| ctx.encode_failures >= MAX_CONSECUTIVE_ENCODE_ERRORS)
          {
            hick_trace::warn!(
              handle = ?handle,
              "service exceeded MAX_CONSECUTIVE_ENCODE_ERRORS; retiring it with a Conflict"
            );
            retire_service(services, events, handle);
            // Only a NON-TERMINAL encode failure is leftover work. This one was
            // terminal: the service's proto is never polled again, so the
            // undeliverable datagram is abandoned with it and there is nothing
            // for a zero timeout to come back for. What the retirement did
            // produce — the terminal event, and the RFC 6762 §10.1 goodbye that
            // stage 7 begins from `withdrawing` — both run later in THIS tick,
            // and the goodbye's schedule is the endpoint's, which
            // `next_timeout` already folds. Unconditional because `capped` can
            // only be the `true` this arm's own encode failure set: reaching it
            // requires `hit_encode_error`, and the loop breaks on the quantum or
            // on the failure, never both.
            capped = false;
          }
          (spent, capped)
        }
        TxSlot::Query(handle) => {
          match queries.get_mut(&handle) {
            Some(ctx) => ctx.tx_seq = next_seq,
            // Retired by an earlier slot's cancellation in this same walk.
            None => return (0, false),
          }
          let mut spent = 0usize;
          let capped = loop {
            if spent >= quantum {
              break true;
            }
            let tx = match endpoint.poll_query_transmit(handle, now, send_buf.as_mut_slice()) {
              Ok(Some(tx)) => tx,
              Ok(None) => break false,
              Err(_e) => {
                // The question can never be encoded, so the query would
                // otherwise hang until its absolute timeout with nothing on
                // the wire. Retire it and surface the terminal instead.
                hick_trace::warn!(
                  handle = ?handle,
                  error = ?_e,
                  "Endpoint::poll_query_transmit failed; retiring the query"
                );
                // A lookup's sub-query is consumed by stage 6, never by the
                // caller: drain its terminal so the update pool cannot fill,
                // but do not surface it. The lookup learns the leg is gone
                // when stage 6 reconciles against `queries`.
                let owned_by_lookup = queries.get(&handle).is_some_and(|c| c.owner.is_some());
                endpoint.retire_query(handle);
                if let Some(update) = endpoint.poll_query(handle)
                  && !owned_by_lookup
                {
                  events.push_terminal(Event::QueryTerminal { handle, update });
                }
                retired_scratch.push(handle);
                break false;
              }
            };
            let len = tx.size().min(send_buf.len());
            // Read before the send that consumes it, exactly as the service arm
            // above does. A query's question is always `Sustained` — §5.2 has no
            // one-shot form — so the `debug_assert` states a core contract this
            // arm depends on rather than a local invariant.
            let obligation = tx.obligation();
            debug_assert_eq!(obligation, TransmitObligation::Sustained);
            let mut gate = queries
              .get(&handle)
              .map(|ctx| ctx.wire_gate)
              .unwrap_or_default();
            let summary = send_and_credit(
              sockets,
              selfsend,
              send_health,
              &mut gate,
              &send_buf[..len],
              tx.dst(),
              tx.min_family_gap(),
            );
            if let Some(ctx) = queries.get_mut(&handle) {
              ctx.wire_gate = gate;
            }
            // The proto layer's §5.2 retry budget is spent only on an
            // all-delivered send, so a query never times out having put nothing
            // on the wire — and, on a dual-stack host, never spends the schedule
            // on IPv4 successes while an IPv6-only responder goes unasked.
            // Confirmed here, before the next `poll_query_transmit` for this
            // handle, which is what the core's contract requires. The retry
            // backoff is anchored at the question's own acceptance so the
            // response window a peer is given runs from when it was asked.
            let at = summary.accepted_at.unwrap_or_else(StdInstant::now);
            endpoint.note_query_transmit_outcome(handle, at, summary.delivery);
            spent = spent.saturating_add(datagram_cost(summary.sent));
            // No bound family can carry the question, and the §5.2 budget is
            // spent only on an all-delivered send — so this query would re-ask
            // forever without ever reaching its own retry ceiling. Retire it, on
            // the same terms the un-encodable question above uses, and after the
            // confirm for the same reason the service arm gives.
            if summary.undeliverable && obligation == TransmitObligation::Sustained {
              hick_trace::warn!(
                handle = ?handle,
                len,
                "no bound family can carry this query's question; retiring it"
              );
              let owned_by_lookup = queries.get(&handle).is_some_and(|c| c.owner.is_some());
              endpoint.retire_query(handle);
              if let Some(update) = endpoint.poll_query(handle)
                && !owned_by_lookup
              {
                events.push_terminal(Event::QueryTerminal { handle, update });
              }
              retired_scratch.push(handle);
              break false;
            }
          };
          (spent, capped)
        }
      },
    );

    // Deliberately outside the walk so it runs on EVERY exit path, including
    // the budget-exhausted one: a retired handle left resident would occupy
    // proto storage forever.
    for handle in retired_scratch.drain(..) {
      let _ = endpoint.cancel_query(handle);
      queries.remove(&handle);
    }

    // A budget or a quantum that cut a sender off means a due datagram may still
    // be unsent, and the proto layer schedules no deadline for one it has
    // already armed — so say so rather than letting the caller sleep on it.
    // Recomputed here (not merely set), which is what stops the flag latching: a
    // drain that finished inside its budget clears whatever set it.
    *work_pending = left_work_behind;
  }

  /// Stage 5: move proto-layer updates and collected answers into the event
  /// queue.
  ///
  /// Queries a lookup owns are skipped entirely — no answer, no terminal, no
  /// GC. Stage 6 is their only consumer, so nothing a lookup's sub-query
  /// collects can surface as an [`Event::QueryAnswer`] or
  /// [`Event::QueryTerminal`] for a handle the caller never asked for.
  ///
  /// # It takes no instant
  ///
  /// An observed [`ServiceUpdate::Renamed`] enqueues the old instance name's RFC
  /// 6762 §9 goodbye here, and a withdrawal item's schedule — its first send and
  /// its 2 s anti-pin ceiling — is defined by the instant it is **created**. The
  /// tick's `now` is not that instant: it is read before stages 1 through 4, so
  /// handing it over charges every microsecond of them to a schedule that did
  /// not exist yet. See this module's clock rule, and the live read at the
  /// enqueue below.
  fn push_updates(&mut self) {
    let Self {
      endpoint,
      services,
      queries,
      events,
      query_scratch,
      retired_scratch,
      ..
    } = &mut *self;

    for (&handle, ctx) in services.iter_mut() {
      if ctx.withdrawing {
        continue;
      }
      while let Some(update) = ctx.proto.poll() {
        // A rename must reach the endpoint's routing table BEFORE any further
        // datagram is routed, or questions for the new instance name would not
        // reach this service.
        let renamed_to = match &update {
          ServiceUpdate::Renamed(renamed) => Some(renamed.new_name().clone()),
          _ => None,
        };
        let update = match renamed_to {
          Some(name) => {
            // Nothing the OLD name put in flight can still be outstanding here.
            // Every datagram this service produced was confirmed inside the
            // `poll_transmit` iteration that produced it — stage 4 — so there is
            // no commit token to spend, no queued announcement to cancel, and
            // nothing that could transmit an old-name positive-TTL record after
            // the retraction taken below has been snapshotted without it. That
            // is the property parking cost, and the reason this branch is now
            // just the rename.
            let routed = endpoint.handle_service_renamed(handle, name);
            // RFC 6762 §9: the old instance name's PTR/SRV/TXT are still in every
            // peer's cache, and the proto layer parks their TTL=0 retraction as a
            // ONE-SHOT handoff the instant it renames. Take it on EVERY observed
            // rename — the surviving one as much as the colliding one. A rename
            // whose handoff is never taken leaves the old name advertised until
            // its positive TTL expires, and the next rename overwrites the parked
            // handoff, so the first name's retraction is lost outright.
            if let Some(handoff) = ctx.proto.take_rename_goodbye_handoff() {
              // HELD until the retraction completes, on EVERY rename — the
              // surviving one as much as the colliding one.
              //
              // A reclaimable item is cancelled outright the moment any service
              // confirm-advertises the same name (the endpoint's
              // cancel-on-announce). That cancellation is all-or-nothing while
              // the debt it discards is PER FAMILY: a goodbye that reached IPv4
              // but not IPv6 still owes IPv6, and a replacement whose own
              // announcement succeeded on IPv4 alone counts as advertised. The
              // unpaid IPv6 debt is then dropped, and every peer that saw only
              // the v6 side keeps the old name's records until their positive
              // TTL expires.
              //
              // Superseding the debt instead of holding it cannot be made to
              // work here either, because supersession is not a property the
              // replacement can have: a record the old registration advertised
              // and the new one does not — a subtype PTR it dropped, a TXT key
              // it no longer sets — is retracted by nothing the replacement
              // ever puts on the wire. Only the goodbye retracts it.
              //
              // So the name is held until every bound family has paid, which is
              // the same per-family-debt invariant the withdrawal stage
              // enforces, applied at the reclamation boundary. The cost is
              // bounded by the endpoint's 2 s anti-pin ceiling: a re-registration
              // of a just-vacated name is refused for at most that long, and
              // typically only for the ~750 ms the resend schedule takes.
              //
              // A LIVE read, at the enqueue. This item's whole schedule is
              // defined relative to the instant it is created — `next_at` IS
              // that instant and the anti-pin ceiling is 2 s past it — so the
              // instant handed over has to be the one at which it is actually
              // created. Stages 1 through 4 all ran between the tick's own read
              // and this line; charging them to the ceiling shortens the old
              // name's retraction by exactly that much, and past ~1.75 s of it
              // the next re-arm clamps below the 250 ms §10.1 interval and the
              // item is force-completed with debt still owed.
              endpoint.enqueue_rename_withdrawal(handoff, StdInstant::now(), true);
            }
            match routed {
              Ok(()) => update,
              Err(_e) => {
                // The new name collides with another local registration. The
                // service has already rebranded and cannot be kept, so report the
                // collision as the terminal it is.
                hick_trace::warn!(
                  handle = ?handle,
                  error = ?_e,
                  "auto-rename collided with another registered service; reporting Conflict"
                );
                ServiceUpdate::Conflict
              }
            }
          }
          None => update,
        };
        let terminal = update.is_conflict() || update.is_host_conflict();
        events.push_terminal(Event::Service { handle, update });
        if terminal {
          // Retired: stop transmitting, timing out, and draining it. The
          // context stays resident so the endpoint keeps holding the name.
          ctx.withdrawing = true;
          break;
        }
      }
    }

    query_scratch.clear();
    query_scratch.extend(queries.keys().copied());
    retired_scratch.clear();
    for &handle in query_scratch.iter() {
      let Some(ctx) = queries.get(&handle) else {
        continue;
      };
      // A lookup owns this one: its answers and its terminal belong to stage 6,
      // which is the whole of why they never reach the caller's event queue.
      if ctx.owner.is_some() {
        continue;
      }
      let last_seq = ctx.last_seq;
      // `collected_answers` is the proto layer's BOUNDED snapshot: its
      // `max_answers` cap evicts oldest entries before we scan. Answers
      // accepted since the last scan but no longer present were evicted before
      // delivery, so count them rather than letting them vanish silently.
      let accepted = endpoint.query_accepted_count(handle).unwrap_or(last_seq);
      let expected = accepted.saturating_sub(last_seq);
      if expected > 0
        && let Some(ctx) = queries.get_mut(&handle)
      {
        let mut delivered = 0u64;
        for answer in endpoint
          .collected_answers(handle)
          .filter(|a| a.seq() >= last_seq)
          .cloned()
        {
          events.push_answer(handle, answer);
          delivered = delivered.saturating_add(1);
        }
        ctx.last_seq = accepted;
        events.record_dropped(expected.saturating_sub(delivered));
      }
      // Answers are queued BEFORE the terminal, so the caller observes every
      // collected record ahead of the frame that ends the query.
      if let Some(update) = endpoint.poll_query(handle) {
        events.push_terminal(Event::QueryTerminal { handle, update });
        retired_scratch.push(handle);
      }
    }
    for handle in retired_scratch.drain(..) {
      let _ = endpoint.cancel_query(handle);
      queries.remove(&handle);
    }

    // Endpoint-level events have no caller-facing surface yet; drain them so
    // the pool cannot fill.
    while endpoint.poll().is_some() {}
  }

  /// Bound the event queue's physical footprint.
  ///
  /// The logical queue is capped by `ANSWER_CAPACITY`, but an evicted answer's
  /// slot lives on in the backing store until `pop` reaches it — so a flooding
  /// peer plus a caller that does not drain every tick would grow memory
  /// without bound. `tick` is the only producer, so this is where that is
  /// stopped.
  fn compact_events(&mut self) {
    if self.events.physical_len() > EVENT_QUEUE_COMPACT_THRESHOLD {
      self.events.compact();
    }
  }
}

/// Retire a service the driver cannot transmit for: queue its terminal and mark
/// the context withdrawing.
///
/// The **only** shape a driver-side retirement takes, so the two sites that need
/// one — a payload that can never be encoded, and one no bound family can ever
/// carry — cannot drift into saying different things to the caller.
///
/// Two halves, and each is load-bearing. The [`ServiceUpdate::Conflict`] is what
/// the caller sees instead of waiting for an `Established` that can never
/// arrive; it is pushed as a TERMINAL, so it is not subject to the answer
/// queue's cap. And `withdrawing` is what every later stage reads to stop
/// driving this service's state machine — including stage 7, which is where the
/// route is actually released once the RFC 6762 §10.1 goodbye it begins from
/// this flag has been paid. **The context is deliberately not removed here**:
/// dropping it would strand the queued terminal's route and free the name while
/// the retraction is still owed.
fn retire_service(
  services: &mut std::collections::HashMap<ServiceHandle, crate::endpoint::ServiceCtx>,
  events: &mut crate::event::EventQueue,
  handle: ServiceHandle,
) {
  events.push_terminal(Event::Service {
    handle,
    update: ServiceUpdate::Conflict,
  });
  if let Some(ctx) = services.get_mut(&handle) {
    ctx.withdrawing = true;
  }
}

/// Hand a service its per-family delivery result and, on any delivery, refresh
/// the endpoint's record of what it has actually advertised.
///
/// One function because the two steps must not drift, and because **every** live
/// service confirm goes through it — none can be added that quietly skips the
/// mirror.
///
/// The delivery is handed over **verbatim**. Which family missed is what lets
/// the core schedule the next announcement per link rather than per round, and a
/// driver that folded it into an aggregate — or excused a family on its own
/// round count — would put the core back to refreshing alternating families at
/// twice the periodic interval. Bounding how long the lifecycle waits for a
/// family that keeps missing is the core's own patience, applied inside the
/// confirm. This driver writes no family off: the obligated set it reports turns
/// on which sockets exist and which family the datagram was addressed to, and
/// [`SendHealth`] — a caller-facing health signal — is no input to it.
///
/// `note_service_announced` reads the goodbye-ownership latch that
/// `note_transmit_outcome` has just updated, and it is that latch — not the
/// configured record set — that a sibling service's shared-host retention is
/// computed from. It runs on `any_delivered`, because ownership latches for
/// whatever reached a wire. Its first argument is the reclaim-cancel gate, and
/// it is the ALL-delivered announcement fact the CORE computes, ferried
/// verbatim. It is emphatically not `Service::advertises_instance()`: that latch
/// fires on any delivery by any transmit kind, so a v4-only announcement — or an
/// RFC 6762 §6.7 legacy unicast reply, which has one obligated link and is
/// therefore all-delivered by construction — would cancel a renamed-away name's
/// goodbye that the unserved family still needs. `FullyAnnounced` has no public
/// constructor precisely so that substitution cannot compile, and it names the
/// service it was minted from, so it cannot be applied to a different one.
///
/// `at` is the earliest instant some family accepted the datagram, falling back
/// to post-attempt time for a round that reached no wire: the next deadline must
/// run from when the datagram left, not from when it was encoded.
fn confirm_service(
  endpoint: &mut crate::proto::ProtoEndpoint,
  services: &mut std::collections::HashMap<ServiceHandle, crate::endpoint::ServiceCtx>,
  handle: ServiceHandle,
  at: StdInstant,
  delivery: TransmitDelivery,
) {
  let Some(ctx) = services.get_mut(&handle) else {
    return;
  };
  ctx.proto.note_transmit_outcome(at, delivery);
  if delivery.any_delivered() {
    endpoint.note_service_announced(
      ctx.proto.has_fully_announced(),
      ctx.proto.advertised_a_addrs(),
      ctx.proto.advertised_aaaa_addrs(),
    );
  }
}

/// One participant in [`Mdns::drain_transmits`]'s round-robin: a registered
/// service or a running query.
///
/// Services and queries share **one** queue rather than getting a phase each.
/// Two phases in a fixed order is what let every service be drained before any
/// query was looked at, so a service population that could keep the budget busy
/// meant no query ever transmitted. On one queue both kinds wait together, and
/// a query is at most one queue-length behind.
///
/// Deliberately **not** `Ord`. Nothing about a handle's numeric value may reach
/// the scheduler: ordering senders by identity is what let a caller choosing its
/// own handles choose who gets served. Position comes from [`TxQueue`]'s
/// sequence and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxSlot {
  /// A registered service, drained through its own `mdns-proto` state machine.
  Service(ServiceHandle),
  /// A running query — the caller's own or a lookup's sub-query — drained
  /// through the endpoint.
  Query(QueryHandle),
}

/// The transmit queue: every service and every query, served
/// **first-waiting-first-served**.
///
/// # The property
///
/// *Every sender is served within `ceil(n / MAX_SEND_CREDITS_PER_DRAIN)` ticks
/// of joining the queue, where `n` is the number of senders ahead of it —
/// regardless of registration, cancellation, or any numeric handle value.*
///
/// # How position is represented
///
/// Not as a container. Each context carries a **service sequence**
/// ([`ServiceCtx::tx_seq`](crate::endpoint::ServiceCtx::tx_seq),
/// [`QueryCtx::tx_seq`](crate::endpoint::QueryCtx::tx_seq)) drawn from
/// [`TxQueue::join`], and the queue *is* those sequences in ascending order.
/// `drain_transmits` rebuilds the list from the two maps each tick and sorts it
/// on that key. A sender draws a fresh sequence at exactly two moments — when it
/// is created, and each time it is offered a turn — and a fresh sequence is
/// always larger than every one issued so far, so both moments put it at the
/// **tail**.
///
/// Keeping position on the context rather than in a side container is what makes
/// membership exact: a cancelled sender's context is gone, so it leaves the
/// queue with it — no stale entries to skip, no way for a reused handle to be
/// enqueued twice.
///
/// # Why churn cannot defeat it
///
/// Consider a sender `V` with `p` senders ahead of it.
///
/// * **Newcomers cannot get ahead of it.** A sender joining draws a sequence
///   larger than `V`'s, so it lands behind `V`. Starting a thousand senders does
///   not move `V` one place back.
/// * **Nothing already served can get ahead of it either.** Being served draws a
///   fresh sequence too, so a sender that took its turn goes behind `V` rather
///   than back into contention with it.
/// * **Cancellation only helps.** A cancelled sender vanishes from the queue,
///   which can only shrink `p`.
/// * **Each tick shortens the wait by a whole budget.** A walk either reaches
///   the tail or is stopped by the budget, and it is stopped only after
///   [`MAX_SEND_CREDITS_PER_DRAIN`] senders have each spent at least
///   [`datagram_cost`] — idle senders spend nothing and are simply passed over
///   for free. So `p` falls by at least `MAX_SEND_CREDITS_PER_DRAIN` per tick
///   until it reaches zero.
///
/// `p` is therefore non-increasing under every operation available to a caller
/// and strictly decreasing while the queue is busy, which is the bound above.
///
/// This is what the previous design could not do. It walked a ring sorted by
/// handle from a cursor holding a *handle value*, so when the cursor's sender
/// was cancelled the walk resumed at the first surviving handle above it — a
/// successor the caller picks. Cancelling each tick's visited senders and
/// starting a budget's worth of higher-numbered ones kept the walk permanently
/// inside the newcomers and an older due sender permanently unserved. No cursor
/// whose identity is a value that can disappear can close that, which is why
/// position here is a sequence the caller never supplies and cannot skip.
///
/// # Why a budget alone is not fairness
///
/// [`MAX_SEND_CREDITS_PER_DRAIN`] bounds the work inside one tick. It says
/// nothing about *whose* work that is, and nothing at all about the next tick.
/// Draining each sender to exhaustion means a handful at the front refilling
/// their legacy-response queues from repeated on-link queries can consume the
/// whole budget on every tick forever, while `work_pending` keeps the loop
/// spinning on their behalf. The **per-slot quantum** is what stops that: no
/// sender may spend more than `credits / senders_still_to_visit`, floored at
/// one. Max-min fair, and self-adjusting — an idle sender leaves its share to
/// the ones behind it, so a single busy sender still gets the entire budget and
/// throughput is unchanged from an unfair drain when there is nothing to be
/// unfair about.
///
/// # Cost
///
/// One turn per sender per tick, never more, so a walk costs at most one
/// `poll_transmit` per sender per tick — the same order as the unfair drain it
/// replaces — and cannot spin.
#[derive(Debug)]
pub(crate) struct TxQueue {
  /// The next sequence to issue. Monotonic, and the only source of queue
  /// position.
  next_seq: u64,
}

impl TxQueue {
  pub(crate) const fn new() -> Self {
    Self { next_seq: 0 }
  }

  /// The sequence a sender takes on joining the queue's **tail**: at creation,
  /// and again each time it is offered a turn.
  ///
  /// Saturating rather than wrapping. At one per sender per tick a `u64` cannot
  /// be exhausted in any real deployment, but wrapping would put a newcomer's
  /// sequence *below* a waiting sender's and hand back the queue-jumping this
  /// type exists to prevent; saturating merely collapses the tail into a tie,
  /// which costs fairness among the tied senders and nothing else.
  pub(crate) const fn join(&mut self) -> u64 {
    let seq = self.next_seq;
    self.next_seq = self.next_seq.saturating_add(1);
    seq
  }

  /// Serve one tick's share of the queue, and report whether it left a due
  /// datagram unsent.
  ///
  /// `queue` is `(sequence, sender)` for every live sender, in any order; it is
  /// sorted in place into queue order. Each sender in turn is passed to `visit`
  /// with the quantum it may spend and the fresh sequence that puts it back at
  /// the tail — `visit` must store that sequence — and returns what it spent, in
  /// [`datagram_cost`] units, and whether the quantum cut it off mid-flow.
  ///
  /// Generic over the sender so the fairness discipline can be exercised without
  /// sockets, handles, or the proto layer.
  pub(crate) fn serve<T, F>(&mut self, queue: &mut [(u64, T)], credits: usize, mut visit: F) -> bool
  where
    T: Copy,
    F: FnMut(T, usize, u64) -> (usize, bool),
  {
    // Sequences are unique, so this key is a total order and the sort is
    // deterministic despite being unstable.
    queue.sort_unstable_by_key(|&(seq, _)| seq);
    let mut sched = TxSchedule::new(queue.len(), credits);
    while let Some((idx, quantum)) = sched.next_slot() {
      let Some(&(_, slot)) = queue.get(idx) else {
        break;
      };
      let (spent, capped) = visit(slot, quantum, self.join());
      sched.charge(spent, capped);
    }
    sched.left_work_behind()
  }
}

/// The budget arithmetic of one [`TxQueue::serve`] walk: whose turn is next,
/// what share of what is left it may spend, and when the walk is over.
///
/// Separate from [`TxQueue`] because it holds no position and outlives no tick —
/// it is the *within-tick* half of the discipline, and keeping it apart is what
/// makes "position never depends on a handle" checkable by reading one type.
#[derive(Debug)]
struct TxSchedule {
  /// Senders in the queue. Fixed for the walk.
  len: usize,
  /// Senders offered a turn so far, and therefore the next index.
  visited: usize,
  /// Drain budget still unspent.
  credits: usize,
  /// A sender was cut off by its quantum, so it may still owe a datagram.
  capped: bool,
}

impl TxSchedule {
  const fn new(len: usize, credits: usize) -> Self {
    Self {
      len,
      visited: 0,
      credits,
      capped: false,
    }
  }

  /// The next sender's index and the credits it may spend, or `None` once the
  /// budget is gone or every sender has had its turn.
  ///
  /// Does not advance on its own: [`TxSchedule::charge`] does, once the caller
  /// knows what the sender actually spent.
  fn next_slot(&mut self) -> Option<(usize, usize)> {
    if self.credits == 0 || self.visited >= self.len {
      return None;
    }
    let remaining = self.len.saturating_sub(self.visited);
    // Floored at one so a queue longer than the budget still makes progress
    // (and the walk still terminates); capped at `credits` so the quantum can
    // never promise more than there is.
    let quantum = (self.credits / remaining.max(1)).max(1).min(self.credits);
    Some((self.visited, quantum))
  }

  /// Record what the sender just handed back spent, and whether its quantum cut
  /// it off mid-flow.
  fn charge(&mut self, spent: usize, capped: bool) {
    // `spent <= quantum <= credits` by construction, since every datagram costs
    // the same one unit and the drain loops stop at the quantum. Saturating so a
    // future caller that overshoots cannot underflow the budget into a walk that
    // never ends.
    self.credits = self.credits.saturating_sub(spent);
    self.visited = self.visited.saturating_add(1);
    self.capped |= capped;
  }

  /// Whether this walk left a due datagram unsent, so
  /// [`Mdns::next_timeout`] must not let the caller sleep on it.
  const fn left_work_behind(&self) -> bool {
    self.credits == 0 || self.capped
  }
}

/// The earlier of an optional running minimum and a new deadline.
fn min_opt(prev: Option<StdInstant>, t: StdInstant) -> StdInstant {
  match prev {
    Some(best) if best <= t => best,
    _ => t,
  }
}

/// Whether a datagram's DNS header has the QR bit set. Too short to hold a
/// header counts as "not a response".
fn packet_is_response(data: &[u8]) -> bool {
  data.get(2).is_some_and(|b| b & 0x80 != 0)
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

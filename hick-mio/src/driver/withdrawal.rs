//! The RFC 6762 §10.1 goodbye stage: beginning a withdrawal, pumping each due
//! TTL=0 datagram, and freeing what settled.
//!
//! Split out of [`crate::driver`] because this is a separate responsibility, not
//! another link in the tick chain. The pipeline's stages are ordered — stage 3
//! *produces* what stages 4 and 5 drain, and that ordering is the correctness
//! property, so they belong together. This stage is instead a self-contained
//! lifecycle the endpoint owns and this module transports: it reads no state
//! the other stages produce, and none of them read its.
//!
//! Two things live here that nothing else in the driver does.
//!
//! **Per-family goodbye debt.** A withdrawal is not "sent" until *every bound*
//! family has retracted its records, so the fan-out reports each family's
//! outcome separately and the endpoint tracks a debt per family. The mapping
//! from a socket result to that debt is by socket **presence**, never by error
//! kind — see [`withdrawal_outcome`], which is where a defect would cost a route
//! freed while a bound family's peers still hold stale positive-TTL records.
//!
//! **The context GC.** Every other stage skips a retired service; this is the
//! one that finally drops it, and only once the endpoint reports its withdrawal
//! complete and its route freed.
//!
//! # This stage takes no instant
//!
//! Everything it decides is a REAL-TIME question — when a withdrawal's schedule
//! begins, when its 2 s anti-pin ceiling falls due, which round is due now, and
//! which item has run out — and none of them is a deadline comparison the tick's
//! own instant may stand in for. See the clock rule in [`crate::driver`]'s own
//! docs; the reads are at [`Mdns::drain_withdrawals`] and
//! [`begin_service_withdrawal`](crate::endpoint::begin_service_withdrawal).

use std::{
  net::SocketAddr,
  time::{Duration, Instant as StdInstant},
};

use mdns_proto::endpoint::{WithdrawalSend, WithdrawalToken};

use crate::{
  driver::sends::SendHealth,
  endpoint::Mdns,
  selfsend::SelfSendTracker,
  socket::{Family, FamilyAdmission, MDNS_V4_DST, MDNS_V6_DST, SendOutcome, SendReport, Sockets},
};

/// Goodbye rounds ONE family owes for one withdrawal item.
///
/// Restated here because `mdns-proto`'s own `WITHDRAWAL_SENDS` is crate-private,
/// exactly as the tests restate the §10.1 interval and ceiling. It is the
/// driver's projection of the endpoint's per-family debt and nothing else — the
/// debt itself lives on the endpoint, which is the only thing that spends it.
///
/// **Drift is caught, not hoped away.** `a_withdrawal_costs_exactly_the_rounds_
/// the_driver_projects` drives a withdrawal to completion and asserts the
/// endpoint took exactly this many rounds, so a change to the endpoint's budget
/// fails a test here rather than silently withholding a goodbye a family still
/// owes.
pub(crate) const GOODBYE_ROUNDS_PER_FAMILY: u8 = 3;

/// How long a [`GoodbyeLedger`] row outlives its last round before it is aged
/// out.
///
/// The §10.1 anti-pin ceiling, restated: an item is force-completed 2 s after it
/// is created, and a row is touched every time its item is pumped — so a row
/// untouched for this long cannot belong to a live item (the item's ceiling is
/// at most 2 s past its creation, which is at or before that last touch).
///
/// Ageing a row out early costs one redundant goodbye and never a withheld one,
/// because a forgotten row reads as "this item has paid nothing" and opens both
/// families. That is the direction this bound is allowed to be wrong in.
const GOODBYE_LEDGER_TTL: Duration = Duration::from_secs(2);

/// The driver's projection of each in-flight withdrawal item's **outstanding
/// per-family debt**, so a family that has paid is not offered the next round.
///
/// # Why the driver needs a projection at all
///
/// The endpoint owns the debt and spends it, but its resend schedule is one
/// schedule for the ITEM while the debt is PER FAMILY. Once one family has paid
/// every round and the other is still failing, a `Sent` on the paid family is
/// (correctly) not progress, so the endpoint re-arms the item on its 20 ms
/// retry backoff for the sake of the family that still owes — and a driver that
/// fans every round to both families then puts a redundant TTL=0 goodbye on the
/// paid family's wire every 20 ms until the ceiling. Dozens of multicast
/// datagrams per service, and a per-family spacing of 20 ms where §10.1 asks for
/// 250 ms.
///
/// # It is not a pending-send table
///
/// It holds no datagram, no unresolved send and no commit token; every send
/// still resolves inside the call that makes it. A row is per-item spacing
/// state, exactly like [`FamilyWireGate`](crate::driver::FamilyWireGate) is
/// per-producer spacing state — and, like it, it is written from what the send
/// actually did rather than from what was attempted.
///
/// # Bounded
///
/// One row per item pumped within [`GOODBYE_LEDGER_TTL`], which is bounded by
/// the registrations the caller itself made; no peer can grow it. Rows age out
/// on that bound, and the whole table is dropped the moment the endpoint reports
/// no withdrawal pending.
#[derive(Debug)]
pub(crate) struct GoodbyeLedger {
  /// One row per item this stage has pumped recently. Linear — see the bound
  /// above.
  rows: Vec<GoodbyeRow>,
}

/// One item's projection.
#[derive(Debug, Clone, Copy)]
struct GoodbyeRow {
  /// The endpoint's own key for the item. Never reused, so a row can only ever
  /// name the item it was opened for.
  token: WithdrawalToken,
  /// Rounds each family has actually PUT ON ITS WIRE for this item, `[v4, v6]`.
  /// Only a [`WithdrawalSend::Sent`] counts: a refused or withheld round paid
  /// nothing.
  carried: [u8; 2],
  /// When this row's item was last pumped. The only input to the ageing above.
  touched: StdInstant,
}

impl GoodbyeLedger {
  /// An empty ledger, which is what an endpoint with nothing withdrawing has.
  pub(crate) const fn new() -> Self {
    Self { rows: Vec::new() }
  }

  /// Whether `family` still owes `token` a goodbye.
  ///
  /// An item this stage has not pumped yet owes everything, so an unknown token
  /// owes on both families — the safe direction, and the one a pruned row falls
  /// back to. So does an index this row does not have.
  ///
  /// A withheld family reports [`SendOutcome::Gated`] and therefore
  /// [`WithdrawalSend::Retry`], which leaves its debt exactly as it was. That is
  /// what makes an over-cautious projection cost a redundant datagram while an
  /// over-eager one could never zero a debt it had not paid.
  fn owes(&self, token: WithdrawalToken, family: Family) -> bool {
    match self.rows.iter().find(|row| row.token == token) {
      Some(row) => {
        row.carried.get(family.index()).copied().unwrap_or(0) < GOODBYE_ROUNDS_PER_FAMILY
      }
      None => true,
    }
  }

  /// Fold one round's per-family outcome into `token`'s row, opening it if this
  /// is the item's first round.
  fn note(
    &mut self,
    token: WithdrawalToken,
    at: StdInstant,
    v4: WithdrawalSend,
    v6: WithdrawalSend,
  ) {
    let row = match self.rows.iter_mut().find(|row| row.token == token) {
      Some(row) => row,
      None => {
        self.rows.push(GoodbyeRow {
          token,
          carried: [0, 0],
          touched: at,
        });
        let Some(row) = self.rows.last_mut() else {
          return;
        };
        row
      }
    };
    row.touched = at;
    for (carried, outcome) in row.carried.iter_mut().zip([v4, v6]) {
      if matches!(outcome, WithdrawalSend::Sent) {
        *carried = carried.saturating_add(1);
      }
    }
  }

  /// Drop every row whose item cannot still be live. See
  /// [`GOODBYE_LEDGER_TTL`].
  fn prune(&mut self, now: StdInstant) {
    self
      .rows
      .retain(|row| now.saturating_duration_since(row.touched) < GOODBYE_LEDGER_TTL);
  }

  /// Drop every row, for when the endpoint reports nothing left withdrawing.
  fn clear(&mut self) {
    self.rows.clear();
  }
}

/// One item's outstanding per-family debt as a [`FamilyAdmission`]: **time-free**
/// by construction, and the only admission in this crate that is.
///
/// It reads a ledger nothing mutates while the fan-out runs — [`GoodbyeLedger`]
/// is folded once, after both families, by
/// [`GoodbyeLedger::note`](GoodbyeLedger::note) — so asking per family answers
/// bitwise-identically to the `[bool; 2]` this replaces. The §10.1 behaviour is
/// unchanged in every direction: an unknown token still owes on both families, a
/// withheld family still reports [`SendOutcome::Gated`] and so
/// [`WithdrawalSend::Retry`], and a `Retry` still leaves the debt exactly as it
/// was.
///
/// It speaks the same trait as [`WireGate`](super::sends::WireGate) only so that
/// no send path anywhere has a second shape for "which families may be offered
/// this". A wire gate is spacing and this is debt; see [`send_withdrawal`] for
/// why this stage has one and not the other.
struct Debt<'a> {
  ledger: &'a GoodbyeLedger,
  token: WithdrawalToken,
}

impl FamilyAdmission for Debt<'_> {
  fn admits(&self, family: Family) -> bool {
    self.ledger.owes(self.token, family)
  }
}

impl Mdns {
  /// Stage 7: pump every due RFC 6762 §10.1 goodbye, then free every withdrawal
  /// that completed.
  ///
  /// Follows `hick-reactor/src/driver/mod.rs:1117-1178`. The endpoint owns the
  /// schedule: it encodes each TTL=0 goodbye (recomputing sibling host-address
  /// retention every round), keeps the withdrawing service's route so its name
  /// cannot be re-registered mid-retraction, and reports the handle back only
  /// once the withdrawal settles. This stage is the transport for that, plus the
  /// context GC on completion.
  ///
  /// Also the single place a goodbye is *begun*. `unregister_service` and
  /// `shutdown` hand theirs over directly, but the pipeline retires services on
  /// its own — an encode-failure escalation, a conflict, a rename collision —
  /// and those sites only mark the context. Scanning here for "retired but not
  /// begun" means no retirement site can leak a route by forgetting to start the
  /// goodbye, which is what lets those sites leave a retired service holding its
  /// context and route.
  ///
  /// # Termination
  ///
  /// The pump loop has no budget of its own, like `push_updates`: the bound is
  /// the proto layer's, borrowed. Each iteration takes one due item and reports
  /// its result, and `note_withdrawal_result` re-arms that item strictly past
  /// the instant it is handed (the full 250 ms interval on progress, a 20 ms
  /// backoff otherwise) or zeroes its debt. That instant is never *before* the
  /// stage instant this loop polls against — see the live read below — so no
  /// item can be selected twice at that instant. A past-ceiling item gets
  /// exactly one final attempt, guarded by the proto layer's own `final_attempt`
  /// flag. The number of iterations is therefore bounded by the number of live
  /// withdrawal items, which is bounded by the registrations the caller itself
  /// made — no peer can grow it.
  ///
  /// One stage-local instant serves the whole pass rather than one per
  /// iteration, and that is deliberate: it is what makes the termination
  /// argument above structural instead of a race against how long a fan-out
  /// took.
  pub(crate) fn drain_withdrawals(&mut self) {
    #[cfg(feature = "stats")]
    let stats = self.stats.clone();
    let Self {
      endpoint,
      services,
      sockets,
      selfsend,
      send_health,
      send_buf,
      svc_scratch,
      completed_scratch,
      goodbye_ledger,
      ..
    } = &mut *self;

    svc_scratch.clear();
    svc_scratch.extend(
      services
        .iter()
        .filter(|(_, ctx)| ctx.withdrawing && !ctx.goodbye_begun)
        .map(|(&handle, _)| handle),
    );
    for &handle in svc_scratch.iter() {
      crate::endpoint::begin_service_withdrawal(endpoint, services, handle);
    }

    // THE stage instant, and the only one this pass polls and completes
    // against. Two things about where it is read are load-bearing.
    //
    // **After the scan above**, because every item that scan creates is
    // scheduled from its own creation instant — so a `now` read before it would
    // sit *before* those items' `next_at` and leave a goodbye the endpoint has
    // already decided is due unsent for a whole loop iteration.
    //
    // **Here rather than at the top of the tick.** Stages 1 through 6 all ran in
    // between, and the questions below are real-time ones: whether a resend is
    // due, and whether an item has outlived its 2 s anti-pin ceiling. On the
    // tick's instant this stage weighs both against a reading that predates the
    // whole receive drain, every timer, the transmit fan-out and the update
    // drain.
    let now = StdInstant::now();
    goodbye_ledger.prune(now);

    while let Some((dst, len, token)) =
      endpoint.poll_withdrawal_transmit(now, send_buf.as_mut_slice())
    {
      // Neither of the two checks below is a `debug_assert!`, and that is
      // deliberate. Both encode an `mdns-proto` contract rather than a local
      // invariant, and this loop is reachable from `Drop` — via
      // `best_effort_goodbye_pass`. An assertion that fires while the stack is
      // already unwinding aborts the process, out of a destructor this crate
      // documents as best-effort, over a peer-invisible encoding detail. Each
      // violation is reported and handled instead.

      // The endpoint always hands back the IPv4 multicast marker and leaves the
      // fan-out to us. Same contract `hick-reactor` asserts. Informational
      // only: the fan-out below is unconditional (§10.1 retracts on every
      // joined group), so a different destination costs nothing but a
      // stale-contract warning.
      if !matches!(dst, SocketAddr::V4(a) if a.ip().is_multicast()
        && a.port() == hick_udp::constants::MDNS_PORT)
      {
        hick_trace::warn!(
          dst = %dst,
          "a withdrawal destination is not the IPv4 multicast marker; fanning out to both groups anyway"
        );
      }
      // `len` counts bytes the endpoint wrote into the very buffer just passed
      // in, so it cannot exceed it. Never clamped: a truncated length would put
      // a malformed DNS message on the wire, which is strictly worse than
      // losing the round — and `&send_buf[..len]` would panic outright.
      //
      // Reported as an un-sent round rather than `continue`d past, because a
      // `continue` without a result would leave the item due at this same `now`
      // and spin this loop forever. `Retry` re-arms it on the short backoff,
      // with the endpoint's 2 s anti-pin ceiling as the backstop.
      //
      // The stage instant, deliberately, unlike the delivered round below: this
      // arm reaches no socket and puts nothing on any family's wire, so there is
      // no transmission for a later one to be spaced against. The 20 ms it
      // re-arms on is an encode-retry cadence measured from the poll that
      // produced the failure, not the §10.1 wire interval — and re-arming from
      // the very instant this loop polls against is also what keeps the item off
      // this pass's due list.
      if len > send_buf.len() {
        hick_trace::warn!(
          len,
          scratch = send_buf.len(),
          "a withdrawal encoded more bytes than the scratch holds; dropping the round"
        );
        endpoint.note_withdrawal_result(token, now, WithdrawalSend::Retry, WithdrawalSend::Retry);
        continue;
      }
      // The anchor comes back from the fan-out that measured it — the second
      // clock this stage carries **on purpose**, and the same split `drain_recv`
      // makes for a self-send claim. There is nothing to place: see
      // `send_withdrawal`.
      let (v4, v6, fanned_out_at) = send_withdrawal(
        sockets,
        selfsend,
        send_health,
        &send_buf[..len],
        &Debt {
          ledger: goodbye_ledger,
          token,
        },
      );
      // `send_withdrawal` already bumped packets_tx/bytes_tx per SENT family and
      // send_errors per failed one, inside `Sockets::send_one` itself — see that
      // method's doc. What is missing there is the ROUND-level goodbyes_tx: a
      // delivered round (>= 1 family Sent) owes exactly one, mirroring
      // `hick-reactor/src/driver/mod.rs:1140-1157`, whose comment is explicit
      // that only this counter is added at the round level.
      #[cfg(feature = "stats")]
      if matches!(v4, WithdrawalSend::Sent) || matches!(v6, WithdrawalSend::Sent) {
        stats.goodbyes_tx(1);
      }
      // Both take the SAME instant, and neither may take the other's. The
      // endpoint spends the debt; the ledger only records what reached a wire,
      // so the two can never disagree about which family paid.
      goodbye_ledger.note(token, fanned_out_at, v4, v6);
      endpoint.note_withdrawal_result(token, fanned_out_at, v4, v6);
    }

    // Every family's debt cleared, or the anti-pin ceiling reached: the endpoint
    // frees the route (releasing the name) and reports the handle. GC its
    // context — unconditionally, because any terminal update the retirement
    // queued already sits in the event queue, which outlives the context.
    completed_scratch.clear();
    endpoint.drain_completed_withdrawals(now, completed_scratch);
    while let Some(handle) = completed_scratch.pop() {
      services.remove(&handle);
    }
    // Nothing is withdrawing, so no row can name a live item. The age-out in
    // `prune` is the general bound; this is the exact one, and it keeps the
    // steady state empty.
    if !endpoint.has_pending_withdrawals() {
      goodbye_ledger.clear();
    }
  }
}

/// Fan one RFC 6762 §10.1 goodbye out to **both** multicast groups, take its
/// self-send credits, and report each family's outcome so the endpoint can track
/// per-family goodbye debt.
///
/// Sends through [`Sockets::send_one`] per family rather than
/// [`Sockets::send_to`]: `send_to` derives its fan-out from the destination, and
/// the endpoint hands back only the IPv4 marker, so the withdrawal's "always
/// both groups" rule would be riding on that classification instead of being
/// stated here.
///
/// A goodbye loops back off the joined sockets like any other multicast
/// transmit, so its self-send credits are taken here — one per family that
/// carried it. Skipping them would let the responder ingest its own goodbye as a
/// peer datagram.
///
/// **No wire GATE**, but not unconditional either: `admission` is the
/// outstanding per-family DEBT, projected by [`GoodbyeLedger`] and asked per
/// family inside [`Sockets::send_one`] — see [`Debt`]. The two are different
/// things and the distinction is the whole of why this stage has one and not the
/// other.
///
/// A wire gate is a *spacing* rule — it withholds a datagram a family still owes
/// until its interval has elapsed — and putting one here could only delay a
/// retraction the endpoint has already decided is due, including the one final
/// attempt it makes at the anti-pin ceiling. The debt mask withholds nothing
/// that is owed: a family that has paid every round for this item has no
/// retraction left to make, so offering it the round again is not spacing, it is
/// a redundant multicast datagram. Once the other family is failing and the item
/// is re-arming on its 20 ms backoff, it is dozens of them.
///
/// Erring in the projection's own direction is cheap and one-sided. A family it
/// wrongly withholds reports [`SendOutcome::Gated`] and so
/// [`WithdrawalSend::Retry`], which leaves its debt untouched and its next round
/// scheduled — it can lose a round, never a debt — while a family it wrongly
/// offers costs one extra datagram.
///
/// The family health table is updated exactly as it is for a transmit: a bound
/// socket that keeps refusing goodbyes is failing for the same reason it fails
/// everything else, and [`Mdns::degraded_families`](crate::Mdns::degraded_families)
/// must say so. A family the projection withheld is charged nothing, exactly
/// like a gated transmit: no syscall was made and the deferral is this driver's
/// own.
/// What a goodbye does *not* do is advance any lifecycle: its per-family debt
/// lives on the endpoint, and [`withdrawal_outcome`] settles it at send time.
///
/// # It returns the round's anchor, and the caller may not read its own
///
/// The third return value is the instant this round finished fanning out, read
/// **inside**, after the second `send_one` and before anything else. Both
/// consumers take it: the ledger's row and the endpoint's §10.1 resend schedule,
/// which can then never disagree about which family paid when.
///
/// It is returned rather than read by the caller because **the anchor belongs to
/// whatever measured it**. It used to be a `StdInstant::now()` at the call site
/// under a fourteen-line comment instructing where to put it — before the stats
/// bump, not folded with the stage instant — and an instruction is a thing a
/// later edit moves. As a return value the placement is a property of this
/// function: nothing the caller does afterwards can be charged to the next
/// round's spacing, because nothing the caller does afterwards can be reached
/// before the read. That also excludes strictly more than the old comment asked
/// for — the round-level stats bump, the ledger fold and the endpoint call are
/// all now after it — which is the same intent carried further.
///
/// What it is **not** is the stage's own instant.
/// [`Mdns::drain_withdrawals`]'s `now` is a due-list reference: one stable value
/// this pass weighs `poll_withdrawal_transmit` and `drain_completed_withdrawals`
/// against, which is what bounds the loop. The schedule this anchor re-arms is a
/// real-time SPACING bound on one family's wire, and this stage has no wire gate
/// of its own, so that schedule is the only thing pacing consecutive goodbyes.
/// Re-arming it from the stage instant hands the next round every microsecond
/// this one spent — a stall in either syscall, between them, or from the
/// scheduler — and a total past the 250 ms interval leaves the next round
/// already due, so two goodbyes for one family reach the wire nearly
/// back-to-back. Do not fold the two clocks together.
pub(super) fn send_withdrawal(
  sockets: &mut Sockets,
  selfsend: &mut SelfSendTracker,
  health: &mut SendHealth,
  body: &[u8],
  admission: &impl FamilyAdmission,
) -> (WithdrawalSend, WithdrawalSend, StdInstant) {
  let v4 = sockets.send_one(Family::V4, body, MDNS_V4_DST, admission);
  let v6 = sockets.send_one(Family::V6, body, MDNS_V6_DST, admission);
  // The round's own anchor, returned rather than re-read by the caller, and read
  // HERE: after the last syscall this round makes and before anything else this
  // function or its caller does. See the section above.
  let fanned_out_at = StdInstant::now();
  // `loops_back` is unconditional here, unlike a `send_to` that classifies its
  // destination: this function always sends to the two multicast groups this
  // endpoint joined, so a goodbye always comes back and always owes its credit.
  let report = SendReport {
    v4,
    v6,
    loops_back: true,
  };
  for (family, outcome) in report.per_family() {
    // The same pre-syscall wall stamp `send_and_credit` records, for the same
    // reason: it orders the echo against the send and never ages it. This stage
    // is the sharpest case for keeping the ageing anchor out of `record` — a
    // goodbye pumped here can land an arbitrarily long time after stage 4's
    // announcement in the SAME tick, and a record-time sweep would let it evict
    // that announcement's still-unclaimed credit. See `SelfSendTracker::seal`.
    if let Some(sent) = outcome.credit_stamp() {
      selfsend.record(family, body, sent);
    }
  }
  health.note_fanout(report);
  (
    withdrawal_outcome(v4),
    withdrawal_outcome(v6),
    fanned_out_at,
  )
}

/// Map one family's send to its goodbye debt, **by socket presence, not by
/// error kind**.
///
/// | [`SendOutcome`] | [`WithdrawalSend`] | why |
/// |---|---|---|
/// | `Sent` | `Sent` | on the wire; spend one owed round |
/// | `Failed` | `Retry` | a bound socket did not carry it; the 2 s ceiling is the backstop |
/// | `Gated` | `Retry` | the debt mask withheld it (see [`GoodbyeLedger`]); a deferral is not a write-off |
/// | `NoSocket` | `WriteOff` | nothing bound, so no peers on this family to retract from |
///
/// The `Failed` row is the one worth defending, and it now covers backpressure
/// as well as a hard error: a `WouldBlock` send put nothing on this family's
/// wire, so the debt is unchanged and the next scheduled round is what pays it.
/// Writing the family off instead would zero its debt, so the withdrawal would
/// complete and free the route as soon as the *other* family drained, leaving
/// this family's peers pinned to stale positive-TTL records for the rest of the
/// record's TTL. Keeping the debt costs at most the 2 s ceiling.
///
/// And [`SendOutcome::NoSocket`] exists as its own variant precisely so this row
/// can differ from `Failed`. Conflating them in either direction breaks
/// something: as `Retry`, an unbound family's debt would pin every withdrawal to
/// its full ceiling on a single-stack host; as `WriteOff`, a bound family's
/// transient failure would free the route while it still owed its goodbye.
const fn withdrawal_outcome(outcome: SendOutcome) -> WithdrawalSend {
  match outcome {
    SendOutcome::Sent { .. } => WithdrawalSend::Sent,
    SendOutcome::Gated | SendOutcome::Failed => WithdrawalSend::Retry,
    SendOutcome::NoSocket => WithdrawalSend::WriteOff,
  }
}

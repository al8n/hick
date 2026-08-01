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

use std::{net::SocketAddr, time::Instant as StdInstant};

use mdns_proto::endpoint::WithdrawalSend;

use crate::{
  driver::sends::SendHealth,
  endpoint::Mdns,
  selfsend::SelfSendTracker,
  socket::{ALLOW_BOTH, Family, MDNS_V4_DST, MDNS_V6_DST, SendOutcome, SendReport, Sockets},
};

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
  /// backoff otherwise) or zeroes its debt. That instant is never *before* `now`
  /// — see the live read below — so no item can be selected twice at this `now`.
  /// A past-ceiling item gets exactly one final attempt, guarded by the proto
  /// layer's own `final_attempt` flag. The number of iterations is therefore
  /// bounded by the number of live withdrawal items, which is bounded by the
  /// registrations the caller itself made — no peer can grow it.
  pub(crate) fn drain_withdrawals(&mut self, now: StdInstant) {
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
      crate::endpoint::begin_service_withdrawal(endpoint, services, handle, now);
    }

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
      // The tick's `now`, deliberately, unlike the delivered round below: this
      // arm reaches no socket and puts nothing on any family's wire, so there is
      // no transmission for a later one to be spaced against. The 20 ms it
      // re-arms on is an encode-retry cadence, not the §10.1 wire interval.
      if len > send_buf.len() {
        hick_trace::warn!(
          len,
          scratch = send_buf.len(),
          "a withdrawal encoded more bytes than the scratch holds; dropping the round"
        );
        endpoint.note_withdrawal_result(token, now, WithdrawalSend::Retry, WithdrawalSend::Retry);
        continue;
      }
      let (v4, v6) = send_withdrawal(sockets, selfsend, send_health, &send_buf[..len]);
      // A LIVE monotonic read, and the second clock this stage carries **on
      // purpose** — the same split `drain_recv` makes for a self-send claim, for
      // the same reason.
      //
      // `now` is the tick's PROTOCOL instant: every deadline inside a tick is
      // weighed against one stable value, so it is what `poll_withdrawal_transmit`
      // above and `drain_completed_withdrawals` below still receive, unchanged.
      // The §10.1 resend schedule this call re-arms is not a deadline comparison
      // but a real-time SPACING bound on one family's wire, and this stage is
      // ungated by design — see `send_withdrawal` — so that schedule is the only
      // thing pacing consecutive goodbyes. Re-arming it from `now` hands the
      // next round every microsecond this one spent: a stall in an earlier
      // stage, in either family's syscall, between the two, or from the
      // scheduler. A total past the 250 ms interval leaves the next round
      // already due, and two goodbyes for one family reach the wire nearly
      // back-to-back — exactly the spacing §10.1 asks for and the anti-pin
      // ceiling is separately allowed to cut short.
      //
      // Read before the stats bump, which is not free and would otherwise be
      // charged to the next round's spacing. Do not fold the two clocks
      // together.
      let fanned_out_at = StdInstant::now();
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
/// **Ungated**, hence [`ALLOW_BOTH`]. The per-family wire gate paces a
/// producer's own record set; the §10.1 resend schedule is the endpoint's, has
/// its own 250 ms interval and its own 2 s anti-pin ceiling, and a driver-side
/// gate on top of it could only delay a retraction the endpoint has already
/// decided is due.
///
/// The family health table is updated exactly as it is for a transmit: a bound
/// socket that keeps refusing goodbyes is failing for the same reason it fails
/// everything else, and [`Mdns::degraded_families`](crate::Mdns::degraded_families)
/// must say so. What a goodbye does *not* do is advance any lifecycle: its
/// per-family debt lives on the endpoint, and [`withdrawal_outcome`] settles it
/// at send time.
pub(super) fn send_withdrawal(
  sockets: &mut Sockets,
  selfsend: &mut SelfSendTracker,
  health: &mut SendHealth,
  body: &[u8],
) -> (WithdrawalSend, WithdrawalSend) {
  let v4 = sockets.send_one(Family::V4, body, MDNS_V4_DST, ALLOW_BOTH);
  let v6 = sockets.send_one(Family::V6, body, MDNS_V6_DST, ALLOW_BOTH);
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
  (withdrawal_outcome(v4), withdrawal_outcome(v6))
}

/// Map one family's send to its goodbye debt, **by socket presence, not by
/// error kind**.
///
/// | [`SendOutcome`] | [`WithdrawalSend`] | why |
/// |---|---|---|
/// | `Sent` | `Sent` | on the wire; spend one owed round |
/// | `Failed` | `Retry` | a bound socket did not carry it; the 2 s ceiling is the backstop |
/// | `Gated` | `Retry` | unreachable here — a goodbye is never gated — and a deferral is not a write-off |
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

//! `Service` handle returned by [`Endpoint::register_service`].
//!
//! Holds an [`Rc<EndpointInner>`] + the proto-layer [`ServiceHandle`] + a
//! handle-owned `ServiceMailbox` the driver fills with [`ServiceUpdate`]s.
//! The driver task owns the proto `Service` state machine inside
//! `State.services`; this handle drains the shared mailbox under a brief borrow,
//! then parks on the shared driver notifier when no update is ready.
//!
//! The mailbox is shared `Rc<RefCell<ServiceMailbox>>` between the driver ctx
//! (which fills it) and this handle (which drains it) — the `!Send`,
//! single-thread analogue of the multi-threaded reactor's `Arc<Mutex<_>>`
//! mailbox, mirroring how the compio query path shares driver state via
//! [`Rc`]/[`RefCell`] and wakes through the same `LocalNotify` driver notifier
//! (no separate doorbell channel). Because the mailbox is owned by the HANDLE,
//! not the driver ctx, the terminal retirement update (`Conflict`/`HostConflict`)
//! keeps its own reserved slot and survives an immediate ctx GC: a still-live
//! reader observes it even after the driver removed the ctx.
//!
//! Dropping a [`Service`] flags the service cancelled and wakes the driver; the
//! driver's post-pump sweep then begins the endpoint-owned RFC 6762 §10.1
//! withdrawal (the endpoint holds the route + drives the TTL=0 goodbye resend
//! schedule, freeing the route on completion).
//!
//! [`Endpoint::register_service`]: crate::Endpoint::register_service

use core::cell::RefCell;
use std::{collections::VecDeque, rc::Rc};

use mdns_proto::{ServiceHandle, ServiceUpdate};

use crate::driver::EndpointInner;

/// Upper bound on undelivered NON-terminal service updates buffered per service.
///
/// `Established` is one-time and `Renamed(..)` coalesces to the latest name, so
/// in normal operation the backlog stays at one or two entries. The cap is a
/// backstop: an on-link peer can force endless conflict-renames, and a
/// non-draining caller would otherwise let the buffer grow without bound. Beyond
/// the cap [`ServiceMailbox::push_update`] drops the oldest pending non-terminal
/// update. The terminal retirement update (`Conflict`/`HostConflict`) has its own
/// reserved slot and is never dropped. Matches the reactor driver's
/// `SERVICE_UPDATE_CAPACITY`.
pub(crate) const SERVICE_UPDATE_CAPACITY: usize = 16;

/// Bounded, coalescing delivery buffer shared between the driver task (which
/// fills it) and the [`Service`] handle (which drains it via [`Service::next`]).
///
/// This mirrors the reactor driver's `ServiceMailbox`: non-terminal updates are
/// bounded ([`SERVICE_UPDATE_CAPACITY`]) and coalesced by kind so a flooding peer
/// cannot grow the queue, while the terminal retirement update keeps a dedicated
/// slot so it is delivered even under non-terminal backpressure and survives an
/// immediate ctx GC (the mailbox is owned by the handle, not the driver ctx).
pub(crate) struct ServiceMailbox {
  /// NON-terminal updates (`Established` / `Renamed(..)`), coalesced by kind and
  /// bounded by [`SERVICE_UPDATE_CAPACITY`]. Drained FIFO before the terminal.
  updates: VecDeque<ServiceUpdate>,
  /// RESERVED slot for the terminal retirement update (`Conflict` /
  /// `HostConflict`). Independent of the non-terminal cap and idempotent (first
  /// terminal wins), so it is always deliverable.
  terminal: Option<ServiceUpdate>,
  /// Set once the terminal has been handed to the consumer, so subsequent drains
  /// report end-of-stream rather than waiting forever.
  terminal_delivered: bool,
}

/// Result of draining one update from a [`ServiceMailbox`].
#[cfg_attr(test, derive(Debug))]
enum Drained {
  /// An update is ready for the consumer.
  Update(ServiceUpdate),
  /// No more updates will ever arrive (terminal already delivered).
  Ended,
  /// Nothing ready right now; the consumer should wait for a wakeup.
  Empty,
}

impl ServiceMailbox {
  fn new() -> Self {
    Self {
      updates: VecDeque::new(),
      terminal: None,
      terminal_delivered: false,
    }
  }

  /// Buffer a NON-terminal update (`Established` / `Renamed(..)`), bounding
  /// memory while keeping insertion order:
  ///
  /// * `Renamed` — drop any prior pending `Renamed` and append the new one, so
  ///   only the LATEST name is kept, at its true (most recent) position (the
  ///   caller only needs the current name).
  /// * `Established` — drop any prior pending `Established` and append, keeping
  ///   only the LATEST at its most-recent position, never displacing a pending
  ///   `Renamed`.
  ///
  /// Keeping only the latest `Established` preserves the post-rename confirmation
  /// across an `Established -> Renamed -> Established` sequence (RFC 6762 §9
  /// conflict re-probe): the second `Established` lands AFTER the `Renamed`, so
  /// the caller learns the new name became advertised, while a duplicate or
  /// pre-rename `Established` coalesces away. Renamed churn still coalesces to a
  /// single pending `Renamed`; the [`SERVICE_UPDATE_CAPACITY`] cap is a hard
  /// backstop that drops the oldest pending update if a future non-terminal kind
  /// ever fills it.
  ///
  /// A terminal update passed here is ROUTED to [`Self::set_terminal`] instead
  /// (terminals belong in the reserved slot); the driver routes by kind, so this
  /// is defensive — it guarantees a retirement reason can never be lost in the
  /// bounded ring.
  pub(crate) fn push_update(&mut self, upd: ServiceUpdate) {
    if upd.is_conflict() || upd.is_host_conflict() {
      // Terminals never go into the non-terminal ring; route to the reserved
      // slot instead so the caller can never lose a retirement reason.
      self.set_terminal(upd);
      return;
    }
    if upd.is_renamed() {
      self.updates.retain(|u| !u.is_renamed());
      self.bounded_push_back(upd);
      return;
    }
    if upd.is_established() {
      // Keep only the LATEST `Established`, at its most-recent position: drop any
      // prior `Established`, then append. A post-rename `Established` (the
      // `Established -> Renamed -> Established` lifecycle: established, conflict,
      // auto-rename, re-establish under the new name) therefore lands AFTER the
      // pending `Renamed`, so a slow reader observes "renamed, then established
      // under the new name" — not just that a rename happened.
      // Globally deduping by kind instead kept the EARLIER `Established` at the
      // front and dropped this post-rename one. Bounds the ring to one `Renamed`
      // plus one trailing `Established` under conflict-rename churn.
      self.updates.retain(|u| !u.is_established());
      self.bounded_push_back(upd);
      return;
    }
    // Any future non-terminal kind: append (bounded by the cap).
    self.bounded_push_back(upd);
  }

  /// Append `upd`, evicting the oldest pending non-terminal update first if the
  /// ring is already at capacity (drop-oldest backstop).
  fn bounded_push_back(&mut self, upd: ServiceUpdate) {
    if self.updates.len() >= SERVICE_UPDATE_CAPACITY {
      self.updates.pop_front();
    }
    self.updates.push_back(upd);
  }

  /// Record the terminal retirement update in its reserved slot (idempotent — the
  /// first terminal wins, and a terminal is never recorded after one has already
  /// been delivered).
  pub(crate) fn set_terminal(&mut self, terminal: ServiceUpdate) {
    if self.terminal.is_none() && !self.terminal_delivered {
      self.terminal = Some(terminal);
    }
  }

  /// Number of buffered NON-terminal updates (excludes the reserved terminal
  /// slot). Test-only window into the bound + coalesce behaviour.
  #[cfg(test)]
  pub(crate) fn non_terminal_len(&self) -> usize {
    self.updates.len()
  }

  /// Whether a terminal retirement update is pending in the reserved slot (and
  /// not yet delivered). Test-only.
  #[cfg(test)]
  pub(crate) fn has_terminal(&self) -> bool {
    self.terminal.is_some()
  }

  /// Drain one update (non-terminal first, then the reserved terminal) and report
  /// it to the caller, or `None` at end-of-stream / when empty. Test-only
  /// synchronous peek used by the driver-level tests to assert what was delivered
  /// without awaiting the async [`Service::next`].
  #[cfg(test)]
  pub(crate) fn drain_for_test(&mut self) -> Option<ServiceUpdate> {
    match self.drain() {
      Drained::Update(upd) => Some(upd),
      Drained::Ended | Drained::Empty => None,
    }
  }

  /// Saturate the NON-terminal ring to [`SERVICE_UPDATE_CAPACITY`] with distinct,
  /// non-coalescing entries (bypassing `push_update`'s by-kind coalescing).
  /// Test-only: lets a driver test exercise a FULL non-terminal ring while the
  /// reserved terminal slot stays independently deliverable.
  #[cfg(test)]
  pub(crate) fn fill_non_terminal_to_cap_for_test(&mut self) {
    use mdns_proto::event::ServiceRenamed;
    self.updates.clear();
    for i in 0..SERVICE_UPDATE_CAPACITY {
      self
        .updates
        .push_back(ServiceUpdate::Renamed(ServiceRenamed::new(
          mdns_proto::Name::try_from_str(&format!("fill-{i}._ipp._tcp.local.")).unwrap(),
        )));
    }
  }

  /// Pull the next update for the consumer: non-terminal updates first (FIFO),
  /// then the reserved terminal, then end-of-stream.
  fn drain(&mut self) -> Drained {
    if let Some(upd) = self.updates.pop_front() {
      Drained::Update(upd)
    } else if let Some(terminal) = self.terminal.take() {
      self.terminal_delivered = true;
      Drained::Update(terminal)
    } else if self.terminal_delivered {
      Drained::Ended
    } else {
      Drained::Empty
    }
  }
}

/// A fresh shared mailbox. Both the driver ctx and the [`Service`] handle hold a
/// clone of the returned [`Rc`]; the wakeup is the shared
/// [`crate::driver::LocalNotify`] on [`EndpointInner`] (mirroring the compio
/// query path, which parks on the same notifier — no separate doorbell channel).
pub(crate) fn new_service_mailbox() -> Rc<RefCell<ServiceMailbox>> {
  Rc::new(RefCell::new(ServiceMailbox::new()))
}

/// Handle to a registered service.
///
/// Dropping the handle implicitly unregisters the service: it is flagged
/// cancelled and the driver's post-pump sweep begins the endpoint-owned RFC 6762
/// §10.1 withdrawal — the endpoint holds the route (reserving the name) while it
/// multicasts the TTL=0 goodbye a few times, then frees the route.
pub struct Service {
  pub(crate) inner: Rc<EndpointInner>,
  pub(crate) handle: ServiceHandle,
  /// Handle-owned delivery buffer the driver fills with [`ServiceUpdate`]s. Owned
  /// by the handle (not the driver ctx), so the reserved terminal survives an
  /// immediate ctx GC and is still drained here.
  pub(crate) mailbox: Rc<RefCell<ServiceMailbox>>,
}

impl Service {
  /// The underlying proto-layer [`ServiceHandle`] for this registration.
  #[inline]
  pub const fn handle(&self) -> ServiceHandle {
    self.handle
  }

  /// Wait for the next [`ServiceUpdate`] event, or `None` once the service has
  /// been retired (terminal delivered) or the driver task exited.
  ///
  /// Drains the handle-owned mailbox: non-terminal updates first (FIFO), then the
  /// reserved terminal, then end-of-stream. Mirrors [`crate::Query::next`]'s
  /// wakeup discipline — a brief synchronous borrow, then a park on the shared
  /// driver notifier when nothing is ready.
  pub async fn next(&self) -> Option<ServiceUpdate> {
    loop {
      // Brief synchronous borrow — drain one update, else fall through to park.
      // The borrow is dropped at the end of this block (well before any `.await`).
      // The mailbox is handle-owned, so it stays drainable even if the driver has
      // already GC'd our `ServiceCtx` after delivering the terminal — that is how
      // a retirement `Conflict` survives a same-iteration ctx GC.
      match self.mailbox.borrow_mut().drain() {
        Drained::Update(upd) => return Some(upd),
        Drained::Ended => return None,
        Drained::Empty => {}
      }
      // No update ready: park on the driver's notify. The borrow above is already
      // dropped, so this await never holds a RefCell borrow.
      self.inner.notify.listen().await;
    }
  }
}

impl Drop for Service {
  fn drop(&mut self) {
    // RFC 6762 §10.1 graceful withdrawal is DRIVER-OWNED: flag the service
    // cancelled and let the driver begin the endpoint-owned withdrawal on its next
    // loop iteration (`State::sweep_cancelled_services` →
    // `begin_service_withdrawal`), AFTER any send that was in flight when this
    // handle dropped has latched its records via `note_service_transmit_result`.
    //
    // Snapshotting the withdrawal synchronously here (the previous approach) raced
    // the driver's completion-based send pump: in the thread-per-core model another
    // task can drop this handle while the driver is parked mid-`send_to().await`
    // for THIS service's own announce. Snapshotting at that instant captures state
    // BEFORE the announce latched as advertised, then retires the service — so when
    // the send completes `note_service_transmit_result` is a no-op and a
    // positive-TTL record reaches peers with no withdrawal. Deferring to the
    // post-pump sweep closes that window.
    {
      let mut st = self.inner.state.borrow_mut();
      st.flag_service_unregistered(self.handle);
    }
    // Durable wake (see `EndpointInner::dirty`): the withdrawal sweep + §10.1
    // goodbye run on the next driver settle, which `dirty` guarantees happens even
    // if this notify is lost across the driver's send-awaits.
    self.inner.mark_dirty();
  }
}

#[cfg(test)]
mod tests {
  use mdns_proto::{ServiceUpdate, event::ServiceRenamed};

  use super::*;

  fn renamed(n: &str) -> ServiceUpdate {
    ServiceUpdate::Renamed(ServiceRenamed::new(
      mdns_proto::Name::try_from_str(n).unwrap(),
    ))
  }

  #[test]
  fn mailbox_coalesces_established_and_renamed_by_kind() {
    // Repeated Established collapses to one; rename churn collapses to the LATEST
    // name, kept at its most-recent position.
    let mut mb = ServiceMailbox::new();
    mb.push_update(ServiceUpdate::Established);
    mb.push_update(ServiceUpdate::Established);
    mb.push_update(renamed("a-1._ipp._tcp.local."));
    mb.push_update(renamed("a-2._ipp._tcp.local."));
    mb.push_update(renamed("a-3._ipp._tcp.local."));
    assert_eq!(
      mb.non_terminal_len(),
      2,
      "one Established + one (latest) Renamed"
    );
    // Established stays at the front (inserted first); the single surviving Renamed
    // carries the latest name.
    assert!(matches!(
      mb.drain(),
      Drained::Update(ServiceUpdate::Established)
    ));
    match mb.drain() {
      Drained::Update(ServiceUpdate::Renamed(r)) => {
        assert!(r.new_name().as_str().contains("a-3"))
      }
      other => panic!("expected the latest Renamed; got {other:?}"),
    }
    assert!(matches!(mb.drain(), Drained::Empty));
  }

  #[test]
  fn mailbox_preserves_post_rename_established() {
    // Established -> Renamed -> Established (establish, conflict, auto-rename,
    // re-establish under the new name). A slow reader MUST still observe the
    // post-rename Established AFTER the Renamed, so it learns the new name became
    // advertised — not merely that a rename happened. The earlier
    // (pre-rename) Established coalesces away: it was for the now-stale name.
    let mut mb = ServiceMailbox::new();
    mb.push_update(ServiceUpdate::Established); // established under the orig name
    mb.push_update(ServiceUpdate::Established); // duplicate: coalesces
    mb.push_update(renamed("svc-2._ipp._tcp.local.")); // §9 conflict rename
    mb.push_update(ServiceUpdate::Established); // re-established under svc-2
    assert_eq!(
      mb.non_terminal_len(),
      2,
      "latest Renamed + the trailing post-rename Established"
    );
    // Drains in order: Renamed(svc-2) first, then the post-rename Established.
    match mb.drain() {
      Drained::Update(ServiceUpdate::Renamed(r)) => {
        assert!(r.new_name().as_str().contains("svc-2"))
      }
      other => panic!("expected Renamed(svc-2) first; got {other:?}"),
    }
    assert!(
      matches!(mb.drain(), Drained::Update(ServiceUpdate::Established)),
      "the post-rename Established must survive, after the Renamed"
    );
    assert!(matches!(mb.drain(), Drained::Empty));
  }

  #[test]
  fn mailbox_rename_churn_coalesces_within_cap() {
    // A flood of distinct Renamed updates cannot grow the ring past one entry: the
    // Renamed-coalesce keeps only the latest.
    let mut mb = ServiceMailbox::new();
    for i in 0..(SERVICE_UPDATE_CAPACITY + 64) {
      mb.push_update(renamed(&format!("svc-{i}._ipp._tcp.local.")));
    }
    assert_eq!(
      mb.non_terminal_len(),
      1,
      "rename churn coalesces to a single pending Renamed, well within the cap"
    );
  }

  #[test]
  fn mailbox_hard_cap_drops_oldest() {
    // Drive the hard drop-oldest backstop directly: push distinct non-coalescing
    // entries past the cap via the internal bounded_push_back, then confirm the
    // ring never exceeds the cap and the oldest were evicted.
    let mut mb = ServiceMailbox::new();
    for i in 0..(SERVICE_UPDATE_CAPACITY as u32 + 5) {
      // Use Renamed values but bypass the dedup-retain to fill the ring.
      mb.bounded_push_back(renamed(&format!("svc-{i}._ipp._tcp.local.")));
    }
    assert_eq!(mb.non_terminal_len(), SERVICE_UPDATE_CAPACITY);
    // The first 5 were evicted; the oldest survivor is svc-5.
    match mb.drain() {
      Drained::Update(ServiceUpdate::Renamed(r)) => assert!(
        r.new_name().as_str().contains("svc-5"),
        "oldest survivor is svc-5"
      ),
      other => panic!("expected a Renamed at the head; got {other:?}"),
    }
  }

  #[test]
  fn mailbox_terminal_reserved_under_non_terminal_pressure() {
    // The terminal slot is separate from the bounded non-terminal ring, so a flood
    // never drops it, and it is delivered LAST.
    let mut mb = ServiceMailbox::new();
    for i in 0..(SERVICE_UPDATE_CAPACITY + 64) {
      mb.bounded_push_back(renamed(&format!("svc-{i}._ipp._tcp.local.")));
    }
    mb.set_terminal(ServiceUpdate::Conflict);
    let mut non_terminal = 0usize;
    let mut got_terminal = false;
    loop {
      match mb.drain() {
        Drained::Update(ServiceUpdate::Conflict) => got_terminal = true,
        Drained::Update(_) => non_terminal += 1,
        Drained::Ended | Drained::Empty => break,
      }
    }
    assert_eq!(non_terminal, SERVICE_UPDATE_CAPACITY);
    assert!(
      got_terminal,
      "terminal must survive non-terminal backpressure"
    );
  }

  #[test]
  fn mailbox_set_terminal_is_idempotent_first_wins() {
    let mut mb = ServiceMailbox::new();
    mb.set_terminal(ServiceUpdate::Conflict);
    mb.set_terminal(ServiceUpdate::HostConflict);
    // First terminal wins.
    assert!(matches!(
      mb.drain(),
      Drained::Update(ServiceUpdate::Conflict)
    ));
    assert!(matches!(mb.drain(), Drained::Ended));
  }

  #[test]
  fn mailbox_routes_terminal_pushed_as_update_to_reserved_slot() {
    // Defensive: a terminal handed to push_update lands in the reserved slot, not
    // the non-terminal ring, so it is delivered last and never dropped.
    let mut mb = ServiceMailbox::new();
    mb.push_update(ServiceUpdate::Established);
    mb.push_update(ServiceUpdate::HostConflict);
    assert_eq!(mb.non_terminal_len(), 1, "only Established is in the ring");
    assert!(matches!(
      mb.drain(),
      Drained::Update(ServiceUpdate::Established)
    ));
    assert!(matches!(
      mb.drain(),
      Drained::Update(ServiceUpdate::HostConflict)
    ));
    assert!(matches!(mb.drain(), Drained::Ended));
  }

  #[test]
  fn mailbox_drains_updates_then_terminal_then_ends() {
    let mut mb = ServiceMailbox::new();
    mb.push_update(ServiceUpdate::Established);
    mb.push_update(renamed("svc-1._ipp._tcp.local."));
    mb.set_terminal(ServiceUpdate::Conflict);
    assert!(matches!(
      mb.drain(),
      Drained::Update(ServiceUpdate::Established)
    ));
    assert!(matches!(
      mb.drain(),
      Drained::Update(ServiceUpdate::Renamed(_))
    ));
    assert!(matches!(
      mb.drain(),
      Drained::Update(ServiceUpdate::Conflict)
    ));
    // Terminal is the last update; subsequent drains report end-of-stream.
    assert!(matches!(mb.drain(), Drained::Ended));
    assert!(matches!(mb.drain(), Drained::Ended));
  }

  /// once a service is flagged `errored` (its records can't encode into
  /// `max_payload`), `Service::next` must surface end-of-stream (`None`) after the
  /// reserved terminal `Conflict` is drained — NOT park forever. The terminal read
  /// is wrapped in a timeout so a regression FAILS (times out) instead of hanging
  /// the whole suite.
  #[compio::test]
  async fn errored_service_next_terminates_after_conflict() {
    let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let now = std::time::Instant::now();

    let stype = mdns_proto::Name::try_from_str("_er._tcp.local.").unwrap();
    let inst = mdns_proto::Name::try_from_str("E._er._tcp.local.").unwrap();
    let host = mdns_proto::Name::try_from_str("e.local.").unwrap();
    let mut recs = mdns_proto::ServiceRecords::new(stype, inst, host, 1234, 120);
    recs.add_a([127, 0, 0, 1].into());
    let mailbox = new_service_mailbox();
    let handle = inner
      .state
      .borrow_mut()
      .register_service(mdns_proto::ServiceSpec::new(recs), now, Rc::clone(&mailbox))
      .unwrap();

    // Simulate the escalation the transmit pump performs on persistent encode
    // failure: record the terminal Conflict in the reserved slot and flag the
    // service errored. (The full encode-failure drive is covered by the
    // driver-level unit test; here we exercise the HANDLE terminal contract.)
    {
      mailbox.borrow_mut().set_terminal(ServiceUpdate::Conflict);
      let mut st = inner.state.borrow_mut();
      st.services.get_mut(&handle).unwrap().errored = true;
    }

    let svc = Service {
      inner: Rc::clone(&inner),
      handle,
      mailbox: Rc::clone(&mailbox),
    };

    // First next(): drains the reserved Conflict.
    let first = svc.next().await;
    assert!(
      matches!(first, Some(ServiceUpdate::Conflict)),
      "first next() must surface the queued Conflict, got {first:?}"
    );

    // Second next(): MUST resolve to None (end-of-stream), not park forever. The
    // timeout turns a regression into a failure instead of a hung suite.
    let second = compio::time::timeout(std::time::Duration::from_secs(2), svc.next()).await;
    match second {
      Ok(v) => assert!(
        v.is_none(),
        "next() after the Conflict must be end-of-stream (None), got {v:?}"
      ),
      Err(_) => panic!("Service::next parked forever on an errored service"),
    }

    // Keep the handle alive until here so its Drop (which borrows state) runs after
    // our assertions, not mid-test.
    drop(svc);
  }
}

//! `Service` handle returned by [`Endpoint::register_service`].
//!
//! Holds an [`Rc<EndpointInner>`] + the proto-layer [`ServiceHandle`] + a
//! handle-owned `ServiceMailbox` the driver fills with [`ServiceUpdate`]s.
//! The `Service` state machine lives in the proto endpoint, keyed by that
//! [`ServiceHandle`]; the driver keeps only its own per-service bookkeeping in
//! `State.services`. This handle drains the shared mailbox under a brief borrow,
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
mod tests;

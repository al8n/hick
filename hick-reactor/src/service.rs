//! Caller-side handle for a registered service.

use std::{
  collections::VecDeque,
  sync::{Arc, Mutex, MutexGuard},
};

use mdns_proto::{ServiceHandle, ServiceUpdate};

use crate::{command::Command, error::CancelError};

/// Upper bound on undelivered NON-terminal service updates buffered per
/// service.
///
/// `Established` is one-time and `Renamed(..)` coalesces to the latest name, so
/// in normal operation the backlog stays at one or two entries. The cap is a
/// backstop: an on-link peer can force endless conflict-renames, and a
/// non-draining caller would otherwise let the buffer grow without bound. Beyond
/// the cap [`ServiceMailbox::push_update`] drops the oldest pending non-terminal
/// update. The terminal retirement update (`Conflict`/`HostConflict`) has its
/// own reserved slot and is never dropped.
pub(crate) const SERVICE_UPDATE_CAPACITY: usize = 16;

/// Bounded, coalescing delivery buffer shared between the driver task (which
/// fills it) and the [`Service`] handle (which drains it via [`Service::next`]).
///
/// This mirrors [`crate::query::QueryMailbox`]: non-terminal updates are bounded
/// ([`SERVICE_UPDATE_CAPACITY`]) and coalesced by kind so a flooding peer cannot
/// grow the queue, while the terminal retirement update keeps a dedicated slot
/// so it is delivered even under non-terminal backpressure and survives an
/// immediate ctx GC (the mailbox is owned by the handle, not the driver ctx).
pub(crate) struct ServiceMailbox {
  /// NON-terminal updates (`Established` / `Renamed(..)`), coalesced by kind and
  /// bounded by [`SERVICE_UPDATE_CAPACITY`]. Drained FIFO before the terminal.
  updates: VecDeque<ServiceUpdate>,
  /// RESERVED slot for the terminal retirement update (`Conflict` /
  /// `HostConflict`). Independent of the non-terminal cap and idempotent (first
  /// terminal wins), so it is always deliverable.
  terminal: Option<ServiceUpdate>,
  /// Set once the terminal has been handed to the consumer, so subsequent
  /// drains report end-of-stream rather than waiting forever.
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
  ///   only the LATEST at its most-recent position. A post-rename `Established`
  ///   therefore lands AFTER the pending `Renamed`, so the caller learns the new
  ///   name became advertised after a conflict-rename
  ///   (`Established -> Renamed -> Established`), not merely that a rename
  ///   happened; a duplicate or pre-rename `Established` coalesces away.
  ///
  /// The ring therefore holds at most one `Renamed` plus one trailing
  /// `Established` under conflict-rename churn; the [`SERVICE_UPDATE_CAPACITY`]
  /// cap is a hard backstop that drops the oldest pending update if a future
  /// non-terminal kind ever fills it.
  ///
  /// A terminal update passed here is ignored (terminals belong in
  /// [`Self::set_terminal`]); the driver routes by kind, so this is defensive.
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

  /// Record the terminal retirement update in its reserved slot (idempotent —
  /// the first terminal wins, and a terminal is never recorded after one has
  /// already been delivered).
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

  /// Drain one update (non-terminal first, then the reserved terminal) and
  /// report it to the caller, or `None` at end-of-stream / when empty. Test-only
  /// synchronous peek used by the driver-level tests to assert what was
  /// delivered without awaiting the async [`Service::next`].
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

/// Lock the mailbox, recovering the inner guard if a previous holder panicked
/// (we never hold the lock across a fallible operation, so the data is sound).
fn lock(mailbox: &Mutex<ServiceMailbox>) -> MutexGuard<'_, ServiceMailbox> {
  mailbox
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Handle to a registered service.
///
/// Dropping the handle implicitly unregisters the service.
pub struct Service {
  handle: ServiceHandle,
  mailbox: Arc<Mutex<ServiceMailbox>>,
  /// Capacity-1 wakeup signal: the driver rings it after filling the mailbox.
  /// Closure of the sender (driver dropped our `ServiceCtx`) means no further
  /// updates will arrive.
  doorbell: async_channel::Receiver<()>,
  cmd: async_channel::Sender<Command>,
}

impl Service {
  pub(crate) fn new(
    handle: ServiceHandle,
    mailbox: Arc<Mutex<ServiceMailbox>>,
    doorbell: async_channel::Receiver<()>,
    cmd: async_channel::Sender<Command>,
  ) -> Self {
    Self {
      handle,
      mailbox,
      doorbell,
      cmd,
    }
  }

  /// The underlying proto-layer service handle.
  #[inline]
  pub const fn handle(&self) -> ServiceHandle {
    self.handle
  }

  /// Wait for the next [`ServiceUpdate`]. Returns `None` once the service has
  /// been retired (terminal delivered) or the driver task has exited.
  ///
  /// Single-consumer: this mirrors [`crate::Query::next`]'s wakeup discipline,
  /// where the capacity-1 doorbell assumes a single waiter.
  pub async fn next(&self) -> Option<ServiceUpdate> {
    loop {
      match lock(&self.mailbox).drain() {
        Drained::Update(upd) => return Some(upd),
        Drained::Ended => return None,
        Drained::Empty => {}
      }
      // Nothing buffered: wait for the driver to ring the doorbell. A closed
      // doorbell means the driver dropped our context — do one final drain (a
      // terminal it set just before exiting is still in the mailbox).
      if self.doorbell.recv().await.is_err() {
        return match lock(&self.mailbox).drain() {
          Drained::Update(upd) => Some(upd),
          _ => None,
        };
      }
    }
  }

  // an in-place `rename` API was removed because the proto-layer
  // `Service` exposes no atomic "rename instance" operation. The driver
  // would have to drop the proto Service and reconstruct one with the new
  // ServiceSpec, which changes the underlying `ServiceHandle` and forces a
  // full probing round anyway — better to express that as
  // `unregister` + `Endpoint::register_service(new_spec).await` at the
  // caller site so the handle invalidation is explicit.
  //
  // The auto-rename path (`ServiceUpdate::Renamed`) is still observed via
  // `next().await`; the driver keeps the endpoint's route table in sync
  // before forwarding the event so post-rename queries route correctly.

  /// Explicitly unregister the service. Equivalent to dropping the handle
  /// but returns an error if the driver task has already exited.
  pub async fn unregister(self) -> Result<(), CancelError> {
    self
      .cmd
      .send(Command::UnregisterService {
        handle: self.handle,
      })
      .await
      .map_err(|_| CancelError::DriverGone)?;
    // The Drop impl below will also try_send an Unregister; driver
    // tolerates the second one (no-op since the handle is already gone).
    Ok(())
  }
}

impl Drop for Service {
  fn drop(&mut self) {
    let _ = self.cmd.try_send(Command::UnregisterService {
      handle: self.handle,
    });
  }
}

/// Construct a fresh mailbox plus its capacity-1 doorbell channel. Returns the
/// shared mailbox, the driver-side doorbell sender, and the consumer-side
/// doorbell receiver. Mirrors [`crate::query::new_mailbox`].
pub(crate) fn new_service_mailbox() -> (
  Arc<Mutex<ServiceMailbox>>,
  async_channel::Sender<()>,
  async_channel::Receiver<()>,
) {
  let mailbox = Arc::new(Mutex::new(ServiceMailbox::new()));
  let (doorbell_tx, doorbell_rx) = async_channel::bounded(1);
  (mailbox, doorbell_tx, doorbell_rx)
}

#[cfg(test)]
mod tests;

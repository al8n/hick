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
  /// * `Established` — append only if no `Established` is already pending
  ///   (one-time), never displacing an earlier-queued update.
  ///
  /// The deque therefore holds at most one entry per non-terminal kind
  /// regardless of how much an on-link peer churns conflict-renames; the
  /// [`SERVICE_UPDATE_CAPACITY`] cap is a hard backstop that drops the oldest
  /// pending update if it is ever reached.
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
    // Established (or any future non-terminal kind): dedup by discriminant so
    // the ring holds at most one of each kind.
    let kind = core::mem::discriminant(&upd);
    if !self
      .updates
      .iter()
      .any(|u| core::mem::discriminant(u) == kind)
    {
      self.bounded_push_back(upd);
    }
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
mod tests {
  use super::*;
  use mdns_proto::{ServiceUpdate, event::ServiceRenamed};

  fn renamed(n: &str) -> ServiceUpdate {
    ServiceUpdate::Renamed(ServiceRenamed::new(
      mdns_proto::Name::try_from_str(n).unwrap(),
    ))
  }

  #[test]
  fn mailbox_coalesces_established_and_renamed_by_kind() {
    // Repeated Established collapses to one; rename churn collapses to the
    // LATEST name, kept at its most-recent position.
    let mut mb = ServiceMailbox::new();
    mb.push_update(ServiceUpdate::Established);
    mb.push_update(ServiceUpdate::Established);
    mb.push_update(renamed("a-1._ipp._tcp.local."));
    mb.push_update(renamed("a-2._ipp._tcp.local."));
    mb.push_update(renamed("a-3._ipp._tcp.local."));
    assert_eq!(
      mb.updates.len(),
      2,
      "one Established + one (latest) Renamed"
    );
    // Established stays at the front (inserted first); the single surviving
    // Renamed carries the latest name.
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
  fn mailbox_bounds_non_terminal_backlog_dropping_oldest() {
    // A flood of distinct Renamed updates cannot grow the ring past the cap.
    // (Each distinct name is its own event, but the Renamed-coalesce keeps only
    // the latest — so to actually fill the ring we interleave kinds. Established
    // dedups, so the ring holds the latest Renamed + the one Established; to
    // exercise the hard drop-oldest cap we push distinct names WITHOUT the
    // retain by calling bounded_push_back-equivalent through push_update is not
    // possible — instead assert the coalesced invariant holds the ring tiny.)
    let mut mb = ServiceMailbox::new();
    for i in 0..(SERVICE_UPDATE_CAPACITY + 64) {
      mb.push_update(renamed(&format!("svc-{i}._ipp._tcp.local.")));
    }
    assert_eq!(
      mb.updates.len(),
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
    assert_eq!(mb.updates.len(), SERVICE_UPDATE_CAPACITY);
    // The first 5 were evicted; the oldest survivor is svc-5.
    match mb.drain() {
      Drained::Update(ServiceUpdate::Renamed(r)) => {
        assert!(
          r.new_name().as_str().contains("svc-5"),
          "oldest survivor is svc-5"
        )
      }
      other => panic!("expected a Renamed at the head; got {other:?}"),
    }
  }

  #[test]
  fn mailbox_terminal_reserved_under_non_terminal_pressure() {
    // The terminal slot is separate from the bounded non-terminal ring, so a
    // flood never drops it, and it is delivered LAST.
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
    // Defensive: a terminal handed to push_update lands in the reserved slot,
    // not the non-terminal ring, so it is delivered last and never dropped.
    let mut mb = ServiceMailbox::new();
    mb.push_update(ServiceUpdate::Established);
    mb.push_update(ServiceUpdate::HostConflict);
    assert_eq!(mb.updates.len(), 1, "only Established is in the ring");
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

  // regression: a single consumer parked on the doorbell must receive an ENTIRE
  // batch the driver delivered with one ring — no updates stranded. (Concurrent
  // waiters are out of scope; `Service::next(&self)` is single-consumer by the
  // capacity-1 doorbell discipline, mirroring `Query::next`.)
  #[tokio::test]
  async fn doorbell_wakes_parked_consumer_for_full_batch() {
    let (mailbox, doorbell_tx, doorbell_rx) = new_service_mailbox();
    let mb_consumer = Arc::clone(&mailbox);

    let consumer = tokio::spawn(async move {
      let mut updates = 0usize;
      let mut got_terminal = false;
      loop {
        let drained = lock(&mb_consumer).drain();
        match drained {
          Drained::Update(ServiceUpdate::Conflict) => got_terminal = true,
          Drained::Update(_) => updates += 1,
          Drained::Ended => break,
          Drained::Empty => {
            if doorbell_rx.recv().await.is_err() {
              break;
            }
          }
        }
      }
      (updates, got_terminal)
    });

    // Let the consumer reach the empty-mailbox park before we deliver.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    {
      let mut mb = lock(&mailbox);
      mb.push_update(ServiceUpdate::Established);
      mb.push_update(renamed("svc-1._ipp._tcp.local."));
      mb.set_terminal(ServiceUpdate::Conflict);
    }
    // A single ring for the whole batch — the parked consumer must still drain
    // both non-terminal updates and the terminal.
    let _ = doorbell_tx.try_send(());

    let (updates, got_terminal) = consumer.await.expect("consumer task panicked");
    assert_eq!(updates, 2);
    assert!(got_terminal);
  }
}

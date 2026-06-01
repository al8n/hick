//! `Service` handle returned by [`Endpoint::register_service`].
//!
//! Holds an [`Rc<EndpointInner>`] + the proto-layer [`ServiceHandle`]. The
//! driver task owns the proto `Service` state machine and per-service update
//! queue inside `State.services`; this handle just borrows briefly to pop
//! events or flag cancellation, then parks on the shared driver notifier when
//! no update is ready.
//!
//! Dropping a [`Service`] encodes the RFC 6762 §10.1 goodbye records under a
//! brief synchronous borrow (while the proto state still exists), pushes the
//! encoded datagrams onto the driver's goodbye queue, frees the proto route
//! slot, and wakes the driver — the driver's goodbye pump then multicasts the
//! TTL=0 burst over the bound sockets before the entries drop.
//!
//! [`Endpoint::register_service`]: crate::Endpoint::register_service

use std::rc::Rc;

use mdns_proto::{ServiceHandle, ServiceUpdate};

use crate::driver::EndpointInner;

/// Handle to a registered service.
///
/// Dropping the handle implicitly unregisters the service: the proto-layer
/// goodbye records are encoded immediately, the proto state machine is
/// destroyed, and the driver's goodbye pump multicasts the queued TTL=0
/// datagrams a few times (RFC 6762 §10.1) before the entries drop.
pub struct Service {
  pub(crate) inner: Rc<EndpointInner>,
  pub(crate) handle: ServiceHandle,
}

impl Service {
  /// The underlying proto-layer [`ServiceHandle`] for this registration.
  #[inline]
  pub const fn handle(&self) -> ServiceHandle {
    self.handle
  }

  /// Wait for the next [`ServiceUpdate`] event, or `None` if the service has
  /// been cancelled or the driver task exited.
  pub async fn next(&self) -> Option<ServiceUpdate> {
    loop {
      // Brief synchronous borrow — pop one update, else fall through to park.
      // The borrow is dropped at the end of this block (well before any
      // `.await`). If the driver has removed our service entry the `?`
      // short-circuits to `None`, signalling the handle is dead.
      {
        let mut st = self.inner.state.borrow_mut();
        let ctx = st.services.get_mut(&self.handle)?;
        if let Some(u) = ctx.updates.pop_front() {
          return Some(u);
        }
        // End-of-stream once the service is withdrawn (cancelled) OR
        // structurally dead (errored: its records can't encode into
        // `max_payload`, see `driver::ServiceCtx::errored`). An errored service
        // queues exactly one `Conflict` then is skipped by every driver pump and
        // contributes no deadline or further wake — so after that `Conflict` is
        // drained above, parking again would hang a `while let Some(u) =
        // service.next().await` consumer forever. Surface `None` instead (symmetric with the errored-query terminal in `Query::next`).
        if ctx.cancelled || ctx.errored {
          return None;
        }
      }
      // No update ready: park on the driver's notify. The borrow above is
      // already dropped, so this await never holds a RefCell borrow.
      self.inner.notify.listen().await;
    }
  }
}

impl Drop for Service {
  fn drop(&mut self) {
    // RFC 6762 §10.1 graceful withdrawal is DRIVER-OWNED: flag the service
    // cancelled and let the driver encode the TTL=0 goodbye + free the proto
    // slot on its next loop iteration (`State::sweep_cancelled_services`),
    // AFTER any send that was in flight when this handle dropped has latched
    // its records via `note_service_transmit_result`.
    //
    // Encoding the goodbye synchronously here (the previous approach) raced the
    // driver's completion-based send pump: in the thread-per-core model another
    // task can drop this handle while the driver is parked mid-`send_to().await`
    // for THIS service's own announce. Encoding the goodbye at that instant
    // captures state BEFORE the announce latched as advertised, then removes the
    // service — so when the send completes `note_service_transmit_result` is a
    // no-op and a positive-TTL record reaches peers with no withdrawal. Deferring
    // to the post-pump sweep closes that window.
    {
      let mut st = self.inner.state.borrow_mut();
      st.flag_service_unregistered(self.handle);
    }
    // Durable wake (see `EndpointInner::dirty`): the withdrawal sweep + §10.1
    // goodbye run on the next driver settle, which `dirty` guarantees happens
    // even if this notify is lost across the driver's send-awaits.
    self.inner.mark_dirty();
  }
}

#[cfg(test)]
mod tests {
  use std::rc::Rc;

  use mdns_proto::{Name, ServiceRecords, ServiceSpec, ServiceUpdate};

  use super::Service;
  use crate::driver::EndpointInner;

  /// once a service is flagged `errored` (its records can't encode
  /// into `max_payload`), `Service::next` must surface end-of-stream (`None`)
  /// after the queued `Conflict` is drained — NOT park forever. An errored
  /// service is skipped by every driver pump and contributes no deadline or
  /// further wake, so a `while let Some(u) = service.next().await` consumer that
  /// re-polls after the Conflict would otherwise hang. The terminal read is
  /// wrapped in a timeout so a regression FAILS (times out) instead of hanging
  /// the whole suite.
  #[compio::test]
  async fn errored_service_next_terminates_after_conflict() {
    let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
    let now = std::time::Instant::now();

    let stype = Name::try_from_str("_er._tcp.local.").unwrap();
    let inst = Name::try_from_str("E._er._tcp.local.").unwrap();
    let host = Name::try_from_str("e.local.").unwrap();
    let mut recs = ServiceRecords::new(stype, inst, host, 1234, 120);
    recs.add_a([127, 0, 0, 1].into());
    let handle = inner
      .state
      .borrow_mut()
      .register_service(ServiceSpec::new(recs), now)
      .unwrap();

    // Simulate the escalation the transmit pump performs on persistent encode
    // failure: queue the terminal Conflict and flag the service errored. (The
    // full encode-failure drive is covered by the driver-level unit test;
    // here we exercise the HANDLE terminal contract.)
    {
      let mut st = inner.state.borrow_mut();
      let ctx = st.services.get_mut(&handle).unwrap();
      ctx.updates.push_back(ServiceUpdate::Conflict);
      ctx.errored = true;
    }

    let svc = Service {
      inner: Rc::clone(&inner),
      handle,
    };

    // First next(): drains the queued Conflict.
    let first = svc.next().await;
    assert!(
      matches!(first, Some(ServiceUpdate::Conflict)),
      "first next() must surface the queued Conflict, got {first:?}"
    );

    // Second next(): MUST resolve to None (end-of-stream), not park forever.
    // The timeout turns a regression into a failure instead of a hung suite.
    let second = compio::time::timeout(std::time::Duration::from_secs(2), svc.next()).await;
    match second {
      Ok(v) => assert!(
        v.is_none(),
        "next() after the Conflict must be end-of-stream (None), got {v:?}"
      ),
      Err(_) => panic!("Service::next parked forever on an errored service"),
    }

    // Keep the handle alive until here so its Drop (which borrows state) runs
    // after our assertions, not mid-test.
    drop(svc);
  }
}

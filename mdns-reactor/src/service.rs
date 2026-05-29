//! Caller-side handle for a registered service.

use mdns_proto::{ServiceHandle, ServiceUpdate};

use crate::{command::Command, error::CancelError};

/// Handle to a registered service.
///
/// Dropping the handle implicitly unregisters the service.
pub struct Service {
  handle: ServiceHandle,
  updates: async_channel::Receiver<ServiceUpdate>,
  cmd: async_channel::Sender<Command>,
}

impl Service {
  pub(crate) fn new(
    handle: ServiceHandle,
    updates: async_channel::Receiver<ServiceUpdate>,
    cmd: async_channel::Sender<Command>,
  ) -> Self {
    Self {
      handle,
      updates,
      cmd,
    }
  }

  /// The underlying proto-layer service handle.
  #[inline]
  pub const fn handle(&self) -> ServiceHandle {
    self.handle
  }

  /// Wait for the next [`ServiceUpdate`]. Returns `None` once the channel
  /// closes (driver task exited).
  pub async fn next(&self) -> Option<ServiceUpdate> {
    self.updates.recv().await.ok()
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

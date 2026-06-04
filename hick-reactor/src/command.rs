//! Driver-task command/response channel types.

use std::{
  future::Future,
  pin::Pin,
  sync::{Arc, Mutex},
};

use mdns_proto::{QueryHandle, QuerySpec, ServiceHandle, ServiceSpec};

use crate::{
  error::{RegisterError, StartQueryError},
  query::QueryMailbox,
  service::ServiceMailbox,
};

/// Reply payload for a successful service registration.
pub(crate) struct ServiceRegistered {
  pub(crate) handle: ServiceHandle,
  /// Shared bounded/coalescing update buffer with a reserved terminal slot.
  pub(crate) mailbox: Arc<Mutex<ServiceMailbox>>,
  /// Capacity-1 wakeup the driver rings after filling the mailbox.
  pub(crate) doorbell: async_channel::Receiver<()>,
}

/// Reply payload for a successful query start.
pub(crate) struct QueryStarted {
  pub(crate) handle: QueryHandle,
  /// Shared bounded/coalescing answer + terminal buffer.
  pub(crate) mailbox: Arc<Mutex<QueryMailbox>>,
  /// Capacity-1 wakeup the driver rings after filling the mailbox.
  pub(crate) doorbell: async_channel::Receiver<()>,
}

/// Messages flowing from caller-side handles into the driver task.
pub(crate) enum Command {
  RegisterService {
    spec: ServiceSpec,
    reply: futures::channel::oneshot::Sender<Result<ServiceRegistered, RegisterError>>,
  },
  UnregisterService {
    handle: ServiceHandle,
  },
  StartQuery {
    spec: QuerySpec,
    reply: futures::channel::oneshot::Sender<Result<QueryStarted, StartQueryError>>,
  },
  CancelQuery {
    handle: QueryHandle,
  },
  /// Spawn a detached discovery-lookup driver task from within the driver, so
  /// it inherits the driver's runtime context (see [`crate::Endpoint::browse`]).
  SpawnLookup {
    task: Pin<Box<dyn Future<Output = ()> + Send>>,
  },
}

//! Driver-task command/response channel types.

use std::sync::{Arc, Mutex};

use mdns_proto::{QueryHandle, QuerySpec, ServiceHandle, ServiceSpec};

use crate::{
  error::{RegisterError, StartQueryError},
  query::QueryMailbox,
};

/// Reply payload for a successful service registration.
pub(crate) struct ServiceRegistered {
  pub(crate) handle: ServiceHandle,
  pub(crate) updates: async_channel::Receiver<mdns_proto::ServiceUpdate>,
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
}

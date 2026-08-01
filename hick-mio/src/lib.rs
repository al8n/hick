#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

mod discovery;
mod driver;
mod endpoint;
mod error;
mod event;
mod onlink;
mod options;
mod proto;
mod selfsend;
mod socket;

pub use discovery::{DEFAULT_MAX_ENTRIES, LookupHandle, QueryParam, ServiceEntry};
pub use endpoint::Mdns;
pub use error::{RegisterError, ServerError, StartQueryError, TickError};
pub use event::Event;
pub use options::ServerOptions;

/// The `mio` version this crate is built against.
///
/// Re-exported because this crate's **entire** public surface speaks `mio`
/// types — [`Mdns::register`] takes a [`mio::Registry`] and two
/// [`mio::Token`]s, [`Mdns::handle_io`] takes a [`mio::event::Event`], and
/// [`Mdns::owns`] takes a [`mio::Token`] — so a caller that adds its own `mio`
/// dependency at a different major version gets an unresolvable type mismatch
/// rather than a version error. Depend on `hick_mio::mio` and the versions
/// cannot disagree.
///
/// It also completes the facade: a `hick` user reaching this crate as
/// `hick::mio` otherwise has `Mdns` but no `Poll` to drive it with.
pub use mio;

// Re-export the mdns-proto types callers need to interact with this crate.
//
// `event` is aliased to `proto_event`: this crate's own `event` module (the
// `Event`/`EventQueue` queue) would otherwise collide with mdns-proto's
// `event` module name, exactly like the `error as proto_error` alias below
// avoids colliding with this crate's own `error` module.
pub use mdns_proto::{
  CollectedAnswer, EndpointConfig, Name, QueryHandle, QuerySpec, QueryUpdate, ServiceHandle,
  ServiceRecords, ServiceRenamed, ServiceSpec, ServiceUpdate, config, error as proto_error,
  event as proto_event, wire,
};

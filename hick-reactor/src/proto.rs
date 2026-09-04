//! Concrete type aliases for the `mdns-proto` state-machine stack used by the
//! async driver. Centralising them here keeps signatures elsewhere short.

use std::time::Instant as StdInstant;

use mdns_proto::{
  CollectedAnswer,
  cache::CacheEntry,
  endpoint::{Endpoint, EndpointEventEntry, ServiceRoute},
  event::{QueryUpdate, ServiceUpdate},
  query::Query,
  transmit::Transmit,
};
use rand::rngs::StdRng;
use slab::Slab;

/// The concrete `mdns-proto::Query` instantiation.
pub(crate) type ProtoQuery = Query<StdInstant, Slab<CollectedAnswer>, Slab<QueryUpdate>>;

/// The concrete `mdns-proto::ServiceRoute` instantiation. It OWNS the
/// `Service` state machine, which is why the service pools appear in the
/// route's parameters as well as the endpoint's. The driver never names the
/// `Service` itself: it observes one through the read-only
/// [`ProtoEndpoint::service`] view and drives it through the endpoint's
/// `*_service*` methods.
pub(crate) type ProtoServiceRoute = ServiceRoute<StdInstant, Slab<Transmit>, Slab<ServiceUpdate>>;

/// The concrete `mdns-proto::Endpoint` instantiation.
pub(crate) type ProtoEndpoint = Endpoint<
  StdInstant,
  StdRng,
  Slab<CacheEntry<StdInstant>>,
  Slab<ProtoServiceRoute>,
  Slab<ProtoQuery>,
  Slab<EndpointEventEntry>,
  Slab<CollectedAnswer>,
  Slab<QueryUpdate>,
  Slab<Transmit>,
  Slab<ServiceUpdate>,
>;

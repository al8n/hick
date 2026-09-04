//! Concrete type aliases for the `mdns-proto` state-machine stack used by the
//! mio driver. Centralising them here keeps signatures elsewhere short.

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

/// The concrete `mdns-proto::ServiceRoute` instantiation. A route OWNS the
/// `Service` state machine it routes to — the driver holds no `Service` of its
/// own and reaches one only through the endpoint's `*_service*` methods.
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

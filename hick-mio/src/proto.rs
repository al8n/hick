//! Concrete type aliases for the `mdns-proto` state-machine stack used by the
//! mio driver. Centralising them here keeps signatures elsewhere short.

use std::time::Instant as StdInstant;

use mdns_proto::{
  CollectedAnswer,
  cache::CacheEntry,
  endpoint::{Endpoint, EndpointEventEntry, ServiceRoute},
  event::{QueryUpdate, ServiceUpdate},
  query::Query,
  service::Service,
  transmit::Transmit,
};
use rand::rngs::StdRng;
use slab::Slab;

/// The concrete `mdns-proto::Query` instantiation.
pub(crate) type ProtoQuery = Query<StdInstant, Slab<CollectedAnswer>, Slab<QueryUpdate>>;

/// The concrete `mdns-proto::Service` instantiation.
pub(crate) type ProtoService = Service<StdInstant, Slab<Transmit>, Slab<ServiceUpdate>>;

/// The concrete `mdns-proto::Endpoint` instantiation.
pub(crate) type ProtoEndpoint = Endpoint<
  StdInstant,
  StdRng,
  Slab<CacheEntry<StdInstant>>,
  Slab<ServiceRoute>,
  Slab<ProtoQuery>,
  Slab<EndpointEventEntry>,
  Slab<CollectedAnswer>,
  Slab<QueryUpdate>,
>;

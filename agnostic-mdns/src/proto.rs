//! Concrete type aliases for the `mdns-proto` state-machine stack used by the
//! async driver. Centralising them here keeps signatures elsewhere short.

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

/// The concrete `mdns-proto::Query` instantiation.
pub(crate) type ProtoQuery =
  Query<StdInstant, slab::Slab<CollectedAnswer>, slab::Slab<QueryUpdate>>;

/// The concrete `mdns-proto::Service` instantiation.
pub(crate) type ProtoService = Service<StdInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>;

/// The concrete `mdns-proto::Endpoint` instantiation.
pub(crate) type ProtoEndpoint = Endpoint<
  StdInstant,
  rand::rngs::StdRng,
  slab::Slab<CacheEntry<StdInstant>>,
  slab::Slab<ServiceRoute>,
  slab::Slab<ProtoQuery>,
  slab::Slab<EndpointEventEntry>,
  slab::Slab<CollectedAnswer>,
  slab::Slab<QueryUpdate>,
>;

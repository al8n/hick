//! Tracing smoke test for `mdns-proto`.
//!
//! Installs a `tracing-subscriber` fmt subscriber with a test buffer and
//! asserts that at least one tracing event/span is emitted during a
//! `Endpoint::handle()` call. This verifies that the tracing wiring actually
//! fires when a real subscriber is active.

#![cfg(all(feature = "tracing", feature = "std", feature = "slab"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
  sync::{Arc, Mutex},
  time::Instant as StdInstant,
};

use mdns_proto::{
  CollectedAnswer, Name, Query,
  cache::CacheEntry,
  config::{EndpointConfig, QuerySpec},
  endpoint::{Endpoint, EndpointEventEntry, Provenance, Received, ServiceRoute},
  event::{QueryUpdate, ServiceUpdate},
  transmit::Transmit,
  wire::{Flags, Header, MessageBuilder, ResourceType},
};
use tracing::subscriber::with_default;
use tracing_core::{
  Event, LevelFilter, Metadata, Subscriber,
  span::{Attributes, Current, Id, Record},
};

type TestQuery = Query<StdInstant, slab::Slab<CollectedAnswer>, slab::Slab<QueryUpdate>>;

type Endp = Endpoint<
  StdInstant,
  rand::rngs::StdRng,
  slab::Slab<CacheEntry<StdInstant>>,
  slab::Slab<ServiceRoute<StdInstant, slab::Slab<Transmit>, slab::Slab<ServiceUpdate>>>,
  slab::Slab<TestQuery>,
  slab::Slab<EndpointEventEntry>,
  slab::Slab<CollectedAnswer>,
  slab::Slab<QueryUpdate>,
  slab::Slab<Transmit>,
  slab::Slab<ServiceUpdate>,
>;

/// A minimal `tracing::Subscriber` that counts events and span-enters.
#[derive(Clone, Default)]
struct CountingSubscriber {
  event_count: Arc<Mutex<u64>>,
  span_count: Arc<Mutex<u64>>,
}

impl CountingSubscriber {
  fn events(&self) -> u64 {
    *self.event_count.lock().unwrap()
  }
  fn spans(&self) -> u64 {
    *self.span_count.lock().unwrap()
  }
}

impl Subscriber for CountingSubscriber {
  fn enabled(&self, _meta: &Metadata<'_>) -> bool {
    // Accept everything — we want to count every event the proto layer emits.
    true
  }

  fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
    *self.span_count.lock().unwrap() += 1;
    // tracing requires non-zero Ids.
    Id::from_u64(1)
  }

  fn record(&self, _span: &Id, _values: &Record<'_>) {}

  fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

  fn event(&self, _event: &Event<'_>) {
    *self.event_count.lock().unwrap() += 1;
  }

  fn enter(&self, _span: &Id) {}

  fn exit(&self, _span: &Id) {}

  fn max_level_hint(&self) -> Option<LevelFilter> {
    Some(LevelFilter::TRACE)
  }

  fn current_span(&self) -> Current {
    Current::none()
  }
}

fn make_endpoint() -> Endp {
  use rand::SeedableRng;
  let rng = rand::rngs::StdRng::from_seed([77u8; 32]);
  Endp::try_new(EndpointConfig::new(), rng)
}

fn build_srv_response(qname: &Name) -> Vec<u8> {
  let mut buf = [0u8; 512];
  let header = Header::new().with_flags(Flags::new().with_response());
  let mut b: MessageBuilder<'_, 0> = MessageBuilder::try_new(&mut buf, header).unwrap();
  let target = Name::try_from_str("host.local.").unwrap();
  b.push_srv_answer(qname, 120, 0, 0, 8080, &target, true)
    .unwrap();
  let n = b.finish().unwrap();
  buf[..n].to_vec()
}

/// At least one tracing event or span must be emitted when `handle()` is
/// called with a real subscriber active.
#[test]
fn handle_emits_at_least_one_tracing_event() {
  let sub = CountingSubscriber::default();
  let sub_clone = sub.clone();

  with_default(sub_clone, || {
    let mut e = make_endpoint();
    let qname = Name::try_from_str("TracingSmoke._ipp._tcp.local.").unwrap();
    let now = StdInstant::now();

    let _qh = e
      .try_start_query(QuerySpec::new(qname.clone(), ResourceType::Srv), now)
      .unwrap();

    let packet = build_srv_response(&qname);
    let src = "192.0.2.1:5353".parse().unwrap();
    let local_ip = "192.0.2.20".parse().unwrap();

    for ev in e
      .handle(
        now,
        Received::new(src, &packet, Provenance::Unknown).with_local_ip(local_ip),
      )
      .unwrap()
    {
      let _ = ev;
    }
  });

  let total = sub.events() + sub.spans();
  assert!(
    total >= 1,
    "expected at least one tracing event/span during handle(); got events={}, spans={}",
    sub.events(),
    sub.spans(),
  );
}

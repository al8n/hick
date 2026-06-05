//! Shared mDNS state + the handle API for embassy.

use alloc::vec::Vec;
use core::cell::RefCell;

use embassy_futures::select::{select, select3};
use embassy_net::{IpCidr, udp::UdpSocket};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, signal::Signal};
use embassy_time::{Instant, Timer};
use hick_smoltcp::Engine;
use mdns_proto::{
  CollectedAnswer, EndpointConfig, QueryHandle, QuerySpec, ServiceHandle, ServiceSpec,
  error::{RegisterServiceError, StartQueryError},
  event::{EndpointEvent, QueryUpdate, ServiceUpdate},
};
use rand_core::Rng;

use crate::{
  io::{DualUdp, wait_either_recv},
  time::EmbassyInstant,
};

/// Shared mDNS state: the engine behind a `RefCell`, plus a wake signal.
///
/// Share one instance between the driver task ([`Self::run`]) and the
/// application — via `Rc` or a `&'static` (`StaticCell`). Every method takes
/// `&self` (interior mutability). This is a single-executor (`!Send`) design:
/// the driver and the handle calls cooperate on one executor, so a `RefCell`
/// borrow never spans an `.await`.
pub struct MdnsState<R> {
  engine: RefCell<Engine<EmbassyInstant, R>>,
  wake: Signal<NoopRawMutex, ()>,
}

impl<R: Rng> MdnsState<R> {
  /// Create the shared state from a proto-layer config and an RNG (used for
  /// probe-tiebreak seeds and query transaction ids).
  pub fn new(config: EndpointConfig, rng: R) -> Self {
    Self {
      engine: RefCell::new(Engine::new(config, rng)),
      wake: Signal::new(),
    }
  }

  /// Set the device's local subnets — the RFC 6762 §11 on-link heuristic used when
  /// the transport can't surface the received hop-limit (embassy-net re-exports
  /// smoltcp's `UdpMetadata`, which carries no RX TTL).
  ///
  /// OPTIONAL. With no subnets configured the §11 gate accepts every inbound mDNS
  /// datagram (the groups are link-scoped multicast routers do not forward) rather
  /// than dropping all of it and going deaf. Configure the device's own subnets to
  /// additionally REJECT sources outside them.
  pub fn set_local_subnets(&self, subnets: Vec<IpCidr>) {
    self.engine.borrow_mut().set_local_subnets(subnets);
  }

  /// Register a service; the driver starts probing/announcing it promptly.
  pub fn register_service(&self, spec: ServiceSpec) -> Result<ServiceHandle, RegisterServiceError> {
    let handle = self.engine.borrow_mut().register_service(spec, now())?;
    self.wake.signal(());
    Ok(handle)
  }

  /// Unregister a service and release its route slot.
  pub fn unregister_service(&self, handle: ServiceHandle) {
    self.engine.borrow_mut().unregister_service(handle, now());
    self.wake.signal(());
  }

  /// Start a query / DNS-SD browse.
  pub fn start_query(&self, spec: QuerySpec) -> Result<QueryHandle, StartQueryError> {
    let handle = self.engine.borrow_mut().start_query(spec, now())?;
    self.wake.signal(());
    Ok(handle)
  }

  /// Cancel a query and free its slot.
  pub fn cancel_query(&self, handle: QueryHandle) {
    self.engine.borrow_mut().cancel_query(handle);
    self.wake.signal(());
  }

  /// Snapshot the answers a query has collected so far — the browse / discovery
  /// results — into an owned `Vec`. Empty if `handle` is not an active query. An
  /// OWNED snapshot (not a borrow) because the engine lives behind a `RefCell`
  /// whose guard cannot escape this call. Compare its length against
  /// [`Self::query_accepted_count`] to detect answers the `max_answers` cap evicted
  /// before you read them.
  pub fn collected_answers(&self, handle: QueryHandle) -> Vec<CollectedAnswer> {
    self
      .engine
      .borrow()
      .collected_answers(handle)
      .cloned()
      .collect()
  }

  /// Total answers ever accepted by a query (including ones the `max_answers` cap
  /// has since evicted from [`Self::collected_answers`]). `None` if `handle` is not
  /// an active query.
  pub fn query_accepted_count(&self, handle: QueryHandle) -> Option<u64> {
    self.engine.borrow().query_accepted_count(handle)
  }

  /// Pop one pending update for a registered service.
  pub fn poll_service_update(&self, handle: ServiceHandle) -> Option<ServiceUpdate> {
    self.engine.borrow_mut().poll_service_update(handle)
  }

  /// Pop one pending update for a query.
  pub fn poll_query_update(&self, handle: QueryHandle) -> Option<QueryUpdate> {
    self.engine.borrow_mut().poll_query_update(handle)
  }

  /// Pop one endpoint-level event.
  pub fn poll_endpoint_event(&self) -> Option<EndpointEvent> {
    self.engine.borrow_mut().poll_endpoint_event()
  }

  /// Take a consistent point-in-time snapshot of every I/O counter and gauge.
  #[cfg(feature = "stats")]
  #[cfg_attr(docsrs, doc(cfg(feature = "stats")))]
  pub fn stats(&self) -> hick_trace::stats::StatsSnapshot {
    self.engine.borrow().stats()
  }

  /// Run the mDNS driver loop over the given v4 and/or v6 sockets until the task
  /// is dropped. Never returns; spawn it as an embassy task.
  ///
  /// Each socket must already be bound to port 5353 and joined to the relevant
  /// mDNS group (`224.0.0.251` / `ff02::fb`) via `Stack::join_multicast_group`.
  /// Takes the sockets by `&mut` so it can ENFORCE the RFC 6762 §11 egress hop-limit
  /// (255) once at startup — see [`crate::run`].
  pub async fn run(
    &self,
    mut v4: Option<&mut UdpSocket<'_>>,
    mut v6: Option<&mut UdpSocket<'_>>,
    scratch: &mut [u8],
  ) -> ! {
    // RFC 6762 §11: force hop-limit 255 on egress while we still hold `&mut`.
    if let Some(s) = v4.as_deref_mut() {
      s.set_hop_limit(Some(255));
      #[cfg(feature = "defmt")]
      defmt::debug!("hick-embassy MdnsState: v4 hop-limit set to 255 (RFC 6762 §11)");
    }
    if let Some(s) = v6.as_deref_mut() {
      s.set_hop_limit(Some(255));
      #[cfg(feature = "defmt")]
      defmt::debug!("hick-embassy MdnsState: v6 hop-limit set to 255 (RFC 6762 §11)");
    }
    loop {
      let deadline = {
        let mut engine = self.engine.borrow_mut();
        let mut io = DualUdp::new(v4.as_deref(), v6.as_deref());
        engine.pump(now(), &mut io, scratch)
      };
      // Wake when: a datagram arrives on either socket, the next protocol
      // deadline elapses, or a handle signals new work.
      match deadline {
        Some(d) => {
          #[cfg(feature = "defmt")]
          defmt::trace!("hick-embassy MdnsState: waiting for recv, deadline, or wake signal");
          let _ = select3(
            wait_either_recv(v4.as_deref(), v6.as_deref()),
            Timer::at(d.0),
            self.wake.wait(),
          )
          .await;
        }
        None => {
          #[cfg(feature = "defmt")]
          defmt::trace!("hick-embassy MdnsState: no deadline, waiting for recv or wake signal");
          let _ = select(
            wait_either_recv(v4.as_deref(), v6.as_deref()),
            self.wake.wait(),
          )
          .await;
        }
      }
    }
  }
}

/// The current monotonic instant, wrapped for the proto.
fn now() -> EmbassyInstant {
  EmbassyInstant(Instant::now())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
  use embassy_net::{IpAddress, IpCidr};
  use mdns_proto::{
    EndpointConfig, Name, QuerySpec, ServiceRecords, ServiceSpec, wire::ResourceType,
  };
  use rand::{SeedableRng, rngs::StdRng};

  use super::MdnsState;

  fn state() -> MdnsState<StdRng> {
    MdnsState::new(EndpointConfig::new(), StdRng::seed_from_u64(7))
  }

  /// Drives the synchronous handle API (everything except the async `run` loop,
  /// which needs a network `Stack`). Each call exercises the `RefCell<Engine>` +
  /// wake-`Signal` delegation; `now()` resolves via the dev-only embassy-time driver.
  #[test]
  fn handle_api_register_query_poll_cancel() {
    let s = state();
    s.set_local_subnets(alloc::vec![IpCidr::new(IpAddress::v4(192, 168, 1, 0), 24)]);

    let mut recs = ServiceRecords::new(
      Name::try_from_str("_http._tcp.local.").unwrap(),
      Name::try_from_str("Dev._http._tcp.local.").unwrap(),
      Name::try_from_str("dev.local.").unwrap(),
      80,
      120,
    );
    recs.add_a([192, 168, 1, 10].into());
    let sh = s.register_service(ServiceSpec::new(recs)).unwrap();
    let _ = s.poll_service_update(sh);

    let qh = s
      .start_query(QuerySpec::new(
        Name::try_from_str("_http._tcp.local.").unwrap(),
        ResourceType::Ptr,
      ))
      .unwrap();
    let _ = s.poll_query_update(qh);
    assert!(s.collected_answers(qh).is_empty());
    assert_eq!(s.query_accepted_count(qh), Some(0));
    let _ = s.poll_endpoint_event();

    s.cancel_query(qh);
    s.unregister_service(sh);
  }
}

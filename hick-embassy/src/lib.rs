//! `hick-embassy` — async mDNS / DNS-SD for the embassy runtime.
//!
//! Builds on `hick-smoltcp`'s runtime-agnostic engine: it supplies an
//! embassy-net [`UdpIo`](hick_smoltcp::UdpIo) transport, the `embassy-time`
//! clock bridge, and an async driver future you spawn as an embassy task.
//!
//! `no_std` + `alloc`.
//!
//! # Usage
//!
//! Share one [`MdnsState`] between the driver task and the application (via
//! `Rc` or a `&'static` `StaticCell`):
//!
//! ```ignore
//! use hick_embassy::MdnsState;
//! use mdns_proto::{EndpointConfig, Name, ServiceRecords, ServiceSpec};
//!
//! let state: &'static MdnsState<_> = make_static!(MdnsState::new(EndpointConfig::new(), rng));
//!
//! // Advertise a service.
//! let mut records = ServiceRecords::new(
//!     Name::try_from_str("_http._tcp.local.").unwrap(),
//!     Name::try_from_str("My Device._http._tcp.local.").unwrap(),
//!     Name::try_from_str("mydevice.local.").unwrap(),
//!     80,
//!     120,
//! );
//! records.add_a(my_ipv4_addr);
//! state.register_service(ServiceSpec::new(records)).unwrap();
//!
//! // Bind v4/v6 sockets to :5353 and join the mDNS group(s), then spawn the driver
//! // (it enforces the §11 egress hop-limit 255 itself — pass the sockets by &mut):
//! spawner.must_spawn(mdns_task(state, v4_socket, v6_socket, scratch));
//!
//! #[embassy_executor::task]
//! async fn mdns_task(
//!     state: &'static MdnsState<MyRng>,
//!     v4: &'static mut UdpSocket<'static>,
//!     v6: &'static mut UdpSocket<'static>,
//!     scratch: &'static mut [u8],
//! ) -> ! {
//!     state.run(Some(v4), Some(v6), scratch).await
//! }
//! ```

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod driver;
mod io;
mod mdns;
pub mod time;

pub use driver::run;
pub use io::DualUdp;
pub use mdns::MdnsState;
pub use time::EmbassyInstant;

# mdns-compio

compio-native async mDNS — responder + querier + DNS-SD discovery.
Thread-per-core, completion I/O. Layered on `mdns-proto` (Sans-I/O) and
`mdns-udp` (multicast socket helpers).

```ignore
use mdns_compio::{Endpoint, ServerOptions};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let endpoint = Endpoint::server(ServerOptions::default()).await?;
# Ok(()) }
```

## Design

- `!Send` throughout: no `Arc`, no `Mutex`, no atomics, no MPSC channels.
- One spawned driver future per endpoint, owning the compio `UdpSocket`(s) and
  pumping a `select!` over two in-flight `recv_msg`s (v4 + v6), a `sleep_until`
  timer, and `LocalNotify`.
- Handles (`Query`, `Service`, `Lookup`) hold `Rc<EndpointInner>` and borrow
  shared state directly under short non-`.await` borrows.

## Pinned versions

`compio 0.18.0`, `compio-net 0.11.1`, `compio-io 0.9.1`, `compio-runtime 0.11.0`.
No `rc` dependencies.

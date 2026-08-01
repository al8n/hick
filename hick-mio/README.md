# hick-mio

`hick-mio` is a synchronous mDNS / DNS-SD driver for applications that already
run their own [`mio`] `Poll` event loop. It wires the Sans-I/O protocol core
([`mdns-proto`]) to multicast UDP sockets ([`hick-udp`]) without spawning a
thread or depending on an async runtime: the caller registers `hick-mio`'s
sockets into its own `mio::Registry`, drives `Poll::poll` itself, and calls
`tick()` once per iteration to advance the protocol.

## Example

```no_run
// `mio` is re-exported, so the driver and your event loop cannot end up on
// different major versions of it.
use hick_mio::{
  Mdns, Name, ServerOptions, ServiceRecords, ServiceSpec,
  mio::{Events, Poll, Token},
};

// Dispatch an event on a token this endpoint does not own.
fn my_handler(_ev: &hick_mio::mio::event::Event) {}

// Whatever tells your application to stop serving.
fn should_stop() -> bool {
  false
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
  let mut poll = Poll::new()?;
  let mut events = Events::with_capacity(128);

  let mut mdns = Mdns::new(ServerOptions::default())?;
  mdns.register(poll.registry(), Token(0), Token(1))?;

  // Advertise a service. Keep the handle alive to keep advertising; unregistering
  // it begins its RFC 6762 §10.1 goodbye (see `Mdns::unregister_service`).
  let mut records = ServiceRecords::new(
    Name::try_from_str("_http._tcp.local.")?,
    Name::try_from_str("My Device._http._tcp.local.")?,
    Name::try_from_str("my-device.local.")?,
    80,
    120,
  );
  records.add_a([192, 168, 1, 10].into());
  let _svc = mdns.register_service(ServiceSpec::new(records))?;

  while !should_stop() {
    poll.poll(&mut events, mdns.next_timeout())?;
    for ev in &events {
      if mdns.owns(ev.token()) {
        mdns.handle_io(ev);
      } else {
        my_handler(ev);
      }
    }
    mdns.tick()?;
    while let Some(_event) = mdns.next_event() {
      // Service lifecycle updates, query answers, and lookup results. Drain to
      // empty every iteration: terminals are never evicted, so this drain is
      // the only thing that bounds the queue.
    }
  }

  // Stop CORRECTLY. `shutdown` only BEGINS the RFC 6762 §10.1 TTL=0 goodbyes;
  // this same loop has to keep running until `is_idle` reports they are on the
  // wire. Just dropping `Mdns` instead attempts each goodbye once, non-blocking,
  // and any peer that misses it keeps advertising the service until its record
  // TTL expires — which can be over an hour. See `Mdns::shutdown`.
  mdns.shutdown();
  while !mdns.is_idle() {
    poll.poll(&mut events, mdns.next_timeout())?;
    for ev in &events {
      if mdns.owns(ev.token()) {
        mdns.handle_io(ev);
      } else {
        // Still dispatch your own tokens here. mio readiness is edge-triggered,
        // so an event dropped during the goodbye drain is never re-delivered.
        my_handler(ev);
      }
    }
    mdns.tick()?;
  }
  Ok(())
}
```

[`mio`]: https://crates.io/crates/mio
[`mdns-proto`]: https://crates.io/crates/mdns-proto
[`hick-udp`]: https://crates.io/crates/hick-udp

//! Caller-side handle for an mDNS endpoint.

use agnostic_net::Net;
use mdns_proto::{QuerySpec, ServiceSpec};
use mdns_udp::{
  MulticastOptionsV4, MulticastOptionsV6, try_bind_v4, try_bind_v6, try_join_v4, try_join_v6,
};

use crate::{
  command::{Command, QueryStarted, ServiceRegistered},
  driver::{self, BoundSockets},
  error::{RegisterError, ServerError, StartQueryError},
  options::ServerOptions,
  query::Query,
  service::Service,
};

/// Handle to a running mDNS endpoint.
///
/// Cloneable; every clone shares the same underlying driver task. The driver
/// task is spawned at [`Self::server`] time and exits when the last clone is
/// dropped (the command channel closes).
#[derive(Clone)]
pub struct Endpoint {
  cmd: async_channel::Sender<Command>,
}

impl Endpoint {
  /// Bind the multicast sockets configured in `opts` and spawn the driver
  /// task on the runtime exposed by `N`.
  pub async fn server<N: Net>(opts: ServerOptions) -> Result<Self, ServerError> {
    if !opts.ipv4() && !opts.ipv6() {
      return Err(ServerError::NoFamilyEnabled);
    }

    let interface_index = match opts.interface_index() {
      Some(i) => i,
      None => pick_default_interface_index(opts.ipv4(), opts.ipv6()).ok_or_else(|| {
        ServerError::Io(std::io::Error::new(
          std::io::ErrorKind::NotFound,
          "no multicast-capable interface found",
        ))
      })?,
    };

    // gracefully degrade — if the chosen interface lacks one of
    // the requested families, bind only the family it can support rather
    // than failing the entire endpoint. This makes
    // `with_ipv4(true).with_ipv6(true)` work on hosts with no global v6
    // (the common single-stack case) while still honouring an explicit
    // single-family request.
    let iface_has_v4 = match getifs::interface_by_index(interface_index) {
      Ok(Some(i)) => matches!(i.ipv4_addrs(), Ok(ref a) if !a.is_empty()),
      _ => false,
    };
    let iface_has_v6 = match getifs::interface_by_index(interface_index) {
      Ok(Some(i)) => matches!(i.ipv6_addrs(), Ok(ref a) if !a.is_empty()),
      _ => false,
    };
    let bind_v4 = opts.ipv4() && iface_has_v4;
    let bind_v6 = opts.ipv6() && iface_has_v6;
    if !bind_v4 && !bind_v6 {
      return Err(ServerError::Io(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "interface has no address in any requested family",
      )));
    }

    let v4 = if bind_v4 {
      let std_sock =
        try_bind_v4(MulticastOptionsV4::new(interface_index)).map_err(ServerError::BindV4)?;
      try_join_v4(&std_sock, interface_index).map_err(map_join_to_bind_v4)?;
      std_sock.set_nonblocking(true)?;
      let async_sock = N::UdpSocket::try_from(std_sock).map_err(ServerError::WrapSocket)?;
      Some(async_sock)
    } else {
      None
    };

    let v6 = if bind_v6 {
      let std_sock =
        try_bind_v6(MulticastOptionsV6::new(interface_index)).map_err(ServerError::BindV6)?;
      try_join_v6(&std_sock, interface_index).map_err(map_join_to_bind_v6)?;
      std_sock.set_nonblocking(true)?;
      let async_sock = N::UdpSocket::try_from(std_sock).map_err(ServerError::WrapSocket)?;
      Some(async_sock)
    } else {
      None
    };

    // unbounded so that `Service::drop` / `Query::drop` (which use
    // `try_send` to issue cleanup commands synchronously) cannot silently
    // lose the Unregister/Cancel. Drop only fails on a closed channel, which
    // means the driver task has already exited and there is nothing to
    // clean up.
    let (cmd_tx, cmd_rx) = async_channel::unbounded::<Command>();
    let sockets = BoundSockets {
      v4,
      v6,
      interface_index,
    };
    driver::spawn::<N>(opts, sockets, cmd_rx);

    Ok(Self { cmd: cmd_tx })
  }

  /// Register a new service with the responder. The returned [`Service`]
  /// streams [`ServiceUpdate`](mdns_proto::ServiceUpdate) events; dropping
  /// it unregisters the service.
  pub async fn register_service(&self, spec: ServiceSpec) -> Result<Service, RegisterError> {
    let (reply_tx, reply_rx) = futures::channel::oneshot::channel();
    self
      .cmd
      .send(Command::RegisterService {
        spec,
        reply: reply_tx,
      })
      .await
      .map_err(|_| RegisterError::DriverGone)?;
    let ServiceRegistered { handle, updates } =
      reply_rx.await.map_err(|_| RegisterError::DriverGone)??;
    Ok(Service::new(handle, updates, self.cmd.clone()))
  }

  /// Start a new query. The returned [`Query`] streams
  /// [`QueryEvent`](crate::QueryEvent) values; dropping it cancels the query.
  pub async fn start_query(&self, spec: QuerySpec) -> Result<Query, StartQueryError> {
    let (reply_tx, reply_rx) = futures::channel::oneshot::channel();
    self
      .cmd
      .send(Command::StartQuery {
        spec,
        reply: reply_tx,
      })
      .await
      .map_err(|_| StartQueryError::DriverGone)?;
    let QueryStarted {
      handle,
      mailbox,
      doorbell,
    } = reply_rx.await.map_err(|_| StartQueryError::DriverGone)??;
    Ok(Query::new(handle, mailbox, doorbell, self.cmd.clone()))
  }
}

fn map_join_to_bind_v4(e: mdns_udp::JoinError) -> ServerError {
  match e {
    mdns_udp::JoinError::Io(io) => ServerError::BindV4(mdns_udp::BindError::Io(io)),
    mdns_udp::JoinError::InterfaceNotFound(d) => {
      ServerError::BindV4(mdns_udp::BindError::InterfaceNotFound(d))
    }
    _ => ServerError::Io(std::io::Error::other("unknown JoinError variant")),
  }
}

fn map_join_to_bind_v6(e: mdns_udp::JoinError) -> ServerError {
  match e {
    mdns_udp::JoinError::Io(io) => ServerError::BindV6(mdns_udp::BindError::Io(io)),
    mdns_udp::JoinError::InterfaceNotFound(d) => {
      ServerError::BindV6(mdns_udp::BindError::InterfaceNotFound(d))
    }
    _ => ServerError::Io(std::io::Error::other("unknown JoinError variant")),
  }
}

fn pick_default_interface_index(want_v4: bool, want_v6: bool) -> Option<u32> {
  let ifs = getifs::interfaces().ok()?;
  let has_v4 = |i: &getifs::Interface| matches!(i.ipv4_addrs(), Ok(ref v) if !v.is_empty());
  let has_v6 = |i: &getifs::Interface| matches!(i.ipv6_addrs(), Ok(ref v) if !v.is_empty());
  let multicast_up_non_loopback = |i: &getifs::Interface| -> bool {
    let f = i.flags();
    f.contains(getifs::Flags::UP)
      && f.contains(getifs::Flags::MULTICAST)
      && !f.contains(getifs::Flags::LOOPBACK)
      && i.index() != 0
  };
  let loopback_up = |i: &getifs::Interface| -> bool {
    i.flags().contains(getifs::Flags::LOOPBACK) && i.flags().contains(getifs::Flags::UP)
  };
  // prefer an interface that satisfies ALL requested families;
  // fall back to one that satisfies at least one. Without the loose fallback
  // an IPv4-only NIC on a host with no global IPv6 would be silently
  // rejected even though it can serve `with_ipv4(true).with_ipv6(true)` over
  // v4 perfectly well.
  let strict =
    |i: &&getifs::Interface| -> bool { (!want_v4 || has_v4(i)) && (!want_v6 || has_v6(i)) };
  let loose = |i: &&getifs::Interface| -> bool { (want_v4 && has_v4(i)) || (want_v6 && has_v6(i)) };
  let strict_non_loopback = ifs
    .iter()
    .find(|i| multicast_up_non_loopback(i) && strict(i));
  let loose_non_loopback = ifs
    .iter()
    .find(|i| multicast_up_non_loopback(i) && loose(i));
  let strict_loopback = ifs.iter().find(|i| loopback_up(i) && strict(i));
  let loose_loopback = ifs.iter().find(|i| loopback_up(i) && loose(i));
  strict_non_loopback
    .or(loose_non_loopback)
    .or(strict_loopback)
    .or(loose_loopback)
    .map(|i| i.index())
}

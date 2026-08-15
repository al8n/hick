//! Caller-side handle for an mDNS endpoint.

use std::future::Future;

use agnostic_net::Net;
use async_channel::Sender;
use hick_udp::{
  Family, MulticastOptionsV4, MulticastOptionsV6, try_bind_v4, try_bind_v6, try_join_v4,
  try_join_v6,
};
use mdns_proto::{QuerySpec, ServiceSpec};

use hick_trace::*;

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
  cmd: Sender<Command>,
  /// Shared receive-health flags, written by the per-family receive tasks.
  ///
  /// NOT feature-gated, deliberately: see [`crate::DeafFamilies`] for why a
  /// signal a Cargo feature can delete is not a signal.
  recv_health: std::sync::Arc<crate::driver::RecvHealth>,
  /// Shared stats handle cloned from the driver's proto endpoint. Present
  /// only when the `stats` Cargo feature is enabled.
  #[cfg(feature = "stats")]
  stats: std::sync::Arc<stats::Stats>,
}

/// Ask Winsock, at construction, whether it can supply `WSARecvMsg` for THIS
/// socket.
///
/// # Why the answer is discarded here and resolved again in the receive task
///
/// `hick_udp::resolve_recv_with_meta` issues a real `WSAIoctl` for the socket it
/// is handed, every time, and returns a handle carrying both the pointer and
/// that socket. The receive task resolves its own handle for the same socket and
/// receives through it, so the pointer verified and the pointer used are the
/// same provider's — which is the property that matters, and which a
/// process-wide cache could not offer: Winsock extension pointers are
/// provider-specific and are invoked directly, so one cached globally could
/// certify a socket it had never examined.
///
/// What this call buys on top of the task's own resolution is WHEN the failure
/// lands. A provider that cannot supply the extension is a permanent property of
/// the stack, so it should fail `Endpoint::server` rather than reach a receive
/// loop — where the resolution would sit between peeking a datagram and
/// consuming one, leaving the datagram queued while every retry rediscovered the
/// same gap.
///
/// A no-op everywhere else: no other target resolves anything to receive.
#[inline]
fn verify_recv_capability(sock: &std::net::UdpSocket) -> Result<(), ServerError> {
  #[cfg(windows)]
  {
    use std::os::windows::io::AsSocket;
    hick_udp::resolve_recv_with_meta(sock.as_socket()).map_err(ServerError::Io)?;
  }
  #[cfg(not(windows))]
  let _ = sock;
  Ok(())
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
      None => pick_default_interface_index(opts.ipv4(), opts.ipv6())
        .map_err(ServerError::Io)?
        .ok_or_else(|| {
          ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no multicast-capable interface found",
          ))
        })?,
    };

    // Ok(empty) degrades a family; Err is not absence — see has_addr_in.
    let (bind_v4, bind_v6) = match getifs::interface_by_index(interface_index) {
      Ok(Some(i)) => (
        opts.ipv4() && has_addr_in(&i, Family::V4).map_err(ServerError::Io)?,
        opts.ipv6() && has_addr_in(&i, Family::V6).map_err(ServerError::Io)?,
      ),
      Ok(None) => {
        return Err(ServerError::Io(std::io::Error::new(
          std::io::ErrorKind::NotFound,
          format!("no interface with index {interface_index}"),
        )));
      }
      Err(e) => {
        return Err(ServerError::Io(std::io::Error::new(
          e.kind(),
          format!("looking up interface {interface_index}: {e}"),
        )));
      }
    };
    if !bind_v4 && !bind_v6 {
      return Err(ServerError::Io(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "interface has no address in any requested family",
      )));
    }

    let v4 = if bind_v4 {
      match try_bind_v4(MulticastOptionsV4::new(interface_index)) {
        Ok(std_sock) => {
          debug!(interface_index, "bound v4 mDNS socket");
          match try_join_v4(&std_sock, interface_index) {
            Ok(()) => {
              debug!(interface_index, "joined v4 mDNS multicast group");
            }
            Err(e) => {
              warn!(error = %e, interface_index, "failed to join v4 mDNS multicast group");
              return Err(map_join_to_bind_v4(e));
            }
          }
          std_sock.set_nonblocking(true)?;
          verify_recv_capability(&std_sock)?;
          let async_sock = N::UdpSocket::try_from(std_sock).map_err(ServerError::WrapSocket)?;
          Some(async_sock)
        }
        Err(e) => {
          warn!(error = %e, interface_index, "failed to bind v4 mDNS socket");
          return Err(ServerError::BindV4(e));
        }
      }
    } else {
      None
    };

    let v6 = if bind_v6 {
      match try_bind_v6(MulticastOptionsV6::new(interface_index)) {
        Ok(std_sock) => {
          debug!(interface_index, "bound v6 mDNS socket");
          match try_join_v6(&std_sock, interface_index) {
            Ok(()) => {
              debug!(interface_index, "joined v6 mDNS multicast group");
            }
            Err(e) => {
              warn!(error = %e, interface_index, "failed to join v6 mDNS multicast group");
              return Err(map_join_to_bind_v6(e));
            }
          }
          std_sock.set_nonblocking(true)?;
          verify_recv_capability(&std_sock)?;
          let async_sock = N::UdpSocket::try_from(std_sock).map_err(ServerError::WrapSocket)?;
          Some(async_sock)
        }
        Err(e) => {
          warn!(error = %e, interface_index, "failed to bind v6 mDNS socket");
          return Err(ServerError::BindV6(e));
        }
      }
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
    #[cfg(feature = "stats")]
    let mut stats_slot: Option<std::sync::Arc<stats::Stats>> = None;
    let recv_health = driver::spawn::<N>(
      opts,
      sockets,
      cmd_rx,
      #[cfg(feature = "stats")]
      &mut stats_slot,
    );

    Ok(Self {
      cmd: cmd_tx,
      recv_health,
      #[cfg(feature = "stats")]
      stats: stats_slot.expect("spawn always populates stats_slot when stats feature is enabled"),
    })
  }

  /// Which address families have stopped receiving.
  ///
  /// # The one degradation signal that no Cargo feature can delete
  ///
  /// Each address family is served by its own detached receive task. A task
  /// that gives up — a socket the kernel will never read again, or a transient
  /// condition that has outlasted
  /// `DEAF_AFTER_CONSECUTIVE_TRANSIENT_RECV_ERRORS` — leaves the rest of the
  /// endpoint working: commands are still answered, sends still go out, and the
  /// other family still receives. Without this there is no way to tell that
  /// apart from a quiet link.
  ///
  /// It is a plain value rather than a log line or a counter because the first
  /// attempt at this WAS a log line and a counter, and both compile to nothing
  /// under this crate's default features (`tracing` and `stats` are opt-in).
  ///
  /// A family reported deaf by the transient budget clears itself on the next
  /// successful receive, so this is a live reading and not a latch. One that
  /// failed permanently does not: rebuild the endpoint.
  #[inline]
  pub fn deaf_families(&self) -> crate::DeafFamilies {
    self.recv_health.snapshot()
  }

  /// Return a point-in-time snapshot of the I/O + protocol counters for this
  /// endpoint.
  ///
  /// The snapshot includes both counters incremented by the `mdns-proto` layer
  /// (parse errors, cache operations, service/query lifecycle) and counters
  /// added by the driver layer (raw wire rx/tx byte counts, socket-level send
  /// errors). All counters share the same [`stats::Stats`] instance
  /// so the snapshot is a single consistent view.
  #[cfg(feature = "stats")]
  #[cfg_attr(docsrs, doc(cfg(feature = "stats")))]
  pub fn stats(&self) -> stats::StatsSnapshot {
    self.stats.snapshot()
  }

  /// Hand a detached discovery-lookup driver task to the driver to spawn (via
  /// [`Command::SpawnLookup`]).
  ///
  /// Spawning happens inside the driver task, which always runs in the runtime
  /// context the endpoint was created on. Routing it this way — rather than
  /// spawning from the caller — means `browse()` works from any executor or
  /// thread, even one with no entered runtime of its own, matching the
  /// runtime-agnostic, channel-only nature of the rest of the endpoint API.
  pub(crate) fn spawn_lookup<F>(&self, fut: F) -> Result<(), StartQueryError>
  where
    F: Future<Output = ()> + Send + 'static,
  {
    self
      .cmd
      .try_send(Command::SpawnLookup {
        task: Box::pin(fut),
      })
      .map_err(|_| StartQueryError::DriverGone)
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
    let ServiceRegistered {
      handle,
      mailbox,
      doorbell,
    } = reply_rx.await.map_err(|_| RegisterError::DriverGone)??;
    Ok(Service::new(handle, mailbox, doorbell, self.cmd.clone()))
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

fn map_join_to_bind_v4(e: hick_udp::JoinError) -> ServerError {
  match e {
    hick_udp::JoinError::Io(io) => ServerError::BindV4(hick_udp::BindError::Io(io)),
    hick_udp::JoinError::InterfaceNotFound(d) => {
      ServerError::BindV4(hick_udp::BindError::InterfaceNotFound(d))
    }
    _ => ServerError::Io(std::io::Error::other("unknown JoinError variant")),
  }
}

fn map_join_to_bind_v6(e: hick_udp::JoinError) -> ServerError {
  match e {
    hick_udp::JoinError::Io(io) => ServerError::BindV6(hick_udp::BindError::Io(io)),
    hick_udp::JoinError::InterfaceNotFound(d) => {
      ServerError::BindV6(hick_udp::BindError::InterfaceNotFound(d))
    }
    _ => ServerError::Io(std::io::Error::other("unknown JoinError variant")),
  }
}

/// Pick a default interface index when the caller didn't pin one.
///
/// Dispatches to [`rank_candidates`], which probes a candidate's addresses only
/// while its answer can still outrank the incumbent. An error is propagated
/// when reading a candidate that could change the pick, preserving the rule
/// that transient enumeration failures (e.g. `EINTR`) are hard errors and not
/// mistaken for an absent family.
fn pick_default_interface_index(want_v4: bool, want_v6: bool) -> std::io::Result<Option<u32>> {
  let ifs = getifs::interfaces()
    .map_err(|e| std::io::Error::new(e.kind(), format!("enumerating network interfaces: {e}")))?;
  rank_candidates(
    ifs
      .iter()
      .filter_map(|i| Some((tier_base(i)?, i.index(), i))),
    want_v4,
    want_v6,
    |iface, family| has_addr_in(iface, family),
  )
}

/// The best tier `iface`'s FLAGS alone can qualify it for, or `None` when they
/// disqualify it outright.
///
/// Tier 0 is an up, multicast-capable, non-loopback interface and tier 2 is an
/// up loopback one; each tier's odd neighbour above it is the same interface
/// serving only some of the requested families. Reading no address here is what
/// keeps an interface the picker would never choose from costing a syscall — or
/// failing one.
fn tier_base(iface: &getifs::Interface) -> Option<u8> {
  let f = iface.flags();
  if f.contains(getifs::Flags::UP)
    && f.contains(getifs::Flags::MULTICAST)
    && !f.contains(getifs::Flags::LOOPBACK)
    && iface.index() != 0
  {
    Some(0)
  } else if f.contains(getifs::Flags::LOOPBACK) && f.contains(getifs::Flags::UP) {
    Some(2)
  } else {
    None
  }
}

/// Rank already-classified candidates and return the winner's interface index.
///
/// `candidates` yields `(tier_base, index, subject)`, where `subject` is
/// whatever `has_addr` needs to read that candidate's addresses.
///
/// One pass over four preference tiers, lowest wins, first-seen wins within a
/// tier. Probes for a family only while its answer can still outrank the
/// incumbent.
fn rank_candidates<S>(
  candidates: impl IntoIterator<Item = (u8, u32, S)>,
  want_v4: bool,
  want_v6: bool,
  mut has_addr: impl FnMut(&S, Family) -> std::io::Result<bool>,
) -> std::io::Result<Option<u32>> {
  let mut best: Option<(u8, u32)> = None;
  'candidates: for (tier_base, index, subject) in candidates {
    let mut reachable = tier_base;
    let mut serves_any = false;
    for (family, wanted) in [(Family::V4, want_v4), (Family::V6, want_v6)] {
      if best.is_some_and(|(seen, _)| reachable >= seen) {
        continue 'candidates;
      }
      let serves = wanted && has_addr(&subject, family)?;
      serves_any |= serves;
      if wanted && !serves {
        reachable = tier_base + 1;
      }
    }
    if !serves_any && reachable > tier_base {
      continue;
    }
    if best.is_none_or(|(seen, _)| reachable < seen) {
      best = Some((reachable, index));
    }
  }
  Ok(best.map(|(_, index)| index))
}

/// Address presence for `family`. `false` only means Ok(empty); Err is not absence.
fn has_addr_in(iface: &getifs::Interface, family: Family) -> std::io::Result<bool> {
  let index = iface.index();
  let (label, addrs) = match family {
    Family::V4 => ("IPv4", iface.ipv4_addrs().map(|a| !a.is_empty())),
    Family::V6 => ("IPv6", iface.ipv6_addrs().map(|a| !a.is_empty())),
  };
  #[cfg(test)]
  let addrs = match forced_enumeration_error() {
    Some(forced) if forced == family => {
      Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }
    _ => addrs,
  };
  addrs.map_err(|e| {
    std::io::Error::new(
      e.kind(),
      format!("reading the {label} addresses of interface {index}: {e}"),
    )
  })
}

#[cfg(test)]
thread_local! {
  static FORCED_ENUMERATION_ERROR: core::cell::Cell<Option<Family>> =
    const { core::cell::Cell::new(None) };
}

#[cfg(test)]
fn forced_enumeration_error() -> Option<Family> {
  FORCED_ENUMERATION_ERROR.with(core::cell::Cell::get)
}

#[cfg(test)]
fn force_enumeration_error_for_test(family: Family) -> ForcedEnumerationError {
  FORCED_ENUMERATION_ERROR.with(|c| c.set(Some(family)));
  ForcedEnumerationError
}

#[cfg(test)]
struct ForcedEnumerationError;

#[cfg(test)]
impl Drop for ForcedEnumerationError {
  fn drop(&mut self) {
    FORCED_ENUMERATION_ERROR.with(|c| c.set(None));
  }
}

#[cfg(test)]
mod tests;

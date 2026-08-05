//! Minting the RFC 6762 §11 witnesses from what a bare-metal transport reports.
//!
//! **There is no §11 rule in this file.** The rule is [`hick_onlink`] — one
//! `no_std`, dependency-free function every driver in this workspace reaches —
//! and this module does the only thing a driver may do on top of it: say what
//! its own receive path WITNESSED. A hand-written second copy used to live here
//! and drifted two hardening rounds behind, admitting LLMNR's `224.0.0.252` on a
//! comparison §11 never offers and admitting an IPv4 broadcast for an in-prefix
//! source. Both are refused now because this file no longer decides anything.
//!
//! # What this square witnesses, and what it declares blind
//!
//! * **Destination — WITNESSED, on every datagram.** smoltcp fills
//!   `UdpMetadata::local_address` from the IP header on receive
//!   (`socket/udp.rs`: `local_address: Some(ip_repr.dst_addr())`, and the
//!   field's own documentation says *"Incoming datagrams always have this
//!   set"*). The `Option` is a SEND-direction artifact — an outgoing datagram
//!   may leave the source address to RFC 6724 selection — so
//!   [`RecvMeta::local`](crate::RecvMeta::local) is `None` only for a
//!   [`UdpIo`](crate::UdpIo) that reports one, and the engine DROPS such a
//!   datagram and counts it rather than handing the gate an absence. Absence
//!   selecting the widest arm is precisely the shape [`hick_onlink`]'s typed
//!   witnesses exist to remove, and this path has no absence to model.
//! * **Receive interface — [`IfaceWitness::Blind`], declared once here.** Not
//!   because a datagram lost it, but because the seam has no interface identity
//!   at all: [`UdpIo`](crate::UdpIo) is one interface per implementation, so
//!   there is nothing to compare a witness against. [`BoundLink::new`] is
//!   therefore given interface `0` — an endpoint that does not know its own
//!   link, which forbids nothing at §11's link stage — and the two agree by
//!   construction rather than by coincidence.
//! * **Link delivery — `None`.** Neither smoltcp nor embassy-net surfaces the
//!   `MSG_MCAST`/`MSG_BCAST` equivalents that OpenBSD and NetBSD report. It is
//!   never consulted anyway on this square: the coarse class only decides where
//!   no destination was witnessed, and one always is.
//! * **Loopback binding — `false`.** These transports run a device, not a host
//!   loopback interface, so the §11 loopback exception is never opened. A
//!   loopback SOURCE is refused here exactly as it is on a NIC-bound hosted
//!   endpoint.
//!
//! # What the blind interface costs, stated once
//!
//! §11's link stage is the only thing that scopes the group arm to ONE link, and
//! this square cannot run it. So an implementation that violates
//! [`UdpIo`](crate::UdpIo)'s one-interface contract and aggregates two physical
//! interfaces behind one [`Engine`](crate::Engine) gets a cross-interface source
//! admitted, silently — the source arm compares against a flat list that now
//! covers both. That residual is unchanged from the copy this replaced; it is
//! the documented consequence of violating the contract, and
//! `aggregated_interfaces_defeat_the_source_arm` pins it.
//!
//! Everything else the deleted copy got wrong is closed, because the destination
//! is witnessed on every datagram and [`hick_onlink`]'s witnessed-destination
//! partition admits only what an endpoint HOLDS.

use core::net::{IpAddr, SocketAddr};

use hick_onlink::{BoundLink, DestinationWitness, IfaceWitness, Verdict, admits_ingress};

/// RFC 6762 §11 for one datagram this transport delivered, with `destination`
/// the IP-header address it was addressed to and `local_addrs` the addresses
/// assigned to the device's interface.
///
/// `local_addrs` pairs each ASSIGNED address with its prefix length — the same
/// value `Interface::update_ip_addrs` takes, not a masked network — because §11
/// asks two questions of it: the destination against the addresses alone (was
/// this addressed to US), and the source against the addresses AND masks (is it
/// on a prefix we carry). A masked network answers the first one wrongly for
/// every address the device actually holds. See
/// [`Engine::set_local_addrs`](crate::Engine::set_local_addrs).
#[inline]
pub(crate) fn verdict(
  src: SocketAddr,
  destination: IpAddr,
  local_addrs: &[(IpAddr, u8)],
) -> Verdict {
  admits_ingress(
    src,
    // Always witnessed on this square — see this module's header.
    DestinationWitness::Witnessed(destination),
    // No `MSG_MCAST`/`MSG_BCAST` equivalent on either transport.
    None,
    // Interface `0`: this seam has no interface identity to scope with.
    BoundLink::new(0, false, local_addrs),
    // Declared once, for every datagram this path will ever produce.
    IfaceWitness::blind(),
  )
}

#[cfg(test)]
mod tests;

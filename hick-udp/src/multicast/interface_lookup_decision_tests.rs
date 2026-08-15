//! The three interface-resolution DECISIONS, over values rather than over a
//! socket: which of `getifs`'s three states each site fails on, which it
//! reports, and what a failed enumeration turns into.
//!
//! Driven over values deliberately, the same way
//! `multicast_if_v4_read_back_reports_a_drift_and_a_failed_read` is. CI cannot
//! fabricate an interface that exists and carries no address of a family, and a
//! live assertion that one behaves a particular way would fail on every
//! conforming host — which is the same false positive that made two of these
//! states a report rather than a verdict in the first place.
//!
//! Not `#[cfg(unix)]`, unlike `crate::multicast::tests`: nothing in these
//! decisions is Unix-only, and a Windows host resolves interfaces through the
//! same three states.

use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr},
};

use super::{
  EgressInterfaceV6, InterfaceLookup, check_egress_interface_v6, require_join_addrs_v4,
  require_multicast_if_v4,
};
use crate::error::{BindError, JoinError};

// Documentation addresses (RFC 5737 TEST-NET-1, RFC 3849), so nothing here can
// be mistaken for a real host's address in a log line.
const DOC_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const DOC_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
const IDX: u32 = 7;

/// `try_bind_v6` hard-fails on ONE of the three states and proceeds on the
/// other two.
///
/// The address is evidence and never a payload here — `IPV6_MULTICAST_IF` takes
/// the index — so the only state that stops the bind is the one that is
/// deterministic on its own terms: an index naming no interface. The other two
/// must never become `InterfaceNotFound`, because neither one establishes that
/// the interface is missing: a failed enumeration establishes nothing at all,
/// and an addressless interface is an IPv4-only NIC or one whose RA/SLAAC
/// address has not landed yet, indistinguishable from here.
#[test]
fn egress_interface_v6_fails_only_on_an_index_that_names_no_interface() {
  assert!(
    matches!(
      check_egress_interface_v6(IDX, InterfaceLookup::Found(DOC_V6)),
      Ok(EgressInterfaceV6::Confirmed)
    ),
    "an interface reporting an IPv6 address confirms the request, and there is nothing to report"
  );
  assert!(
    matches!(
      check_egress_interface_v6(
        IDX,
        InterfaceLookup::LookupFailed(io::Error::from(io::ErrorKind::Interrupted)),
      ),
      Ok(EgressInterfaceV6::Unconfirmed)
    ),
    "an interrupted address dump — which getifs returns by design — says nothing about the \
     interface, so the bind proceeds and the failure is reported, never turned into \
     InterfaceNotFound"
  );
  assert!(
    matches!(
      check_egress_interface_v6(IDX, InterfaceLookup::Addressless),
      Ok(EgressInterfaceV6::Addressless)
    ),
    "an interface reporting no IPv6 address is ambiguous, not a verdict: the bind proceeds and \
     reports, because IPV6_MULTICAST_IF takes the index and never needs this address"
  );
  assert!(
    matches!(
      check_egress_interface_v6(IDX, InterfaceLookup::NoSuchInterface),
      Err(BindError::InterfaceNotFound(_))
    ),
    "an index that names no interface is the one deterministic negative of the three, and stays a \
     hard failure"
  );
}

/// `try_bind_v4` hard-fails on all three, and still distinguishes them.
///
/// Every state that yields no address stops the bind because the address is the
/// `IP_MULTICAST_IF` payload. What must not collapse is which error each state
/// reports: a look-up that FAILED carries the platform's own kind out as
/// `BindError::Io`, rather than telling the caller an interface it never
/// managed to read does not exist.
#[test]
fn multicast_if_v4_fails_every_addressless_state_and_keeps_a_failed_look_up_distinct() {
  assert!(
    matches!(
      require_multicast_if_v4(IDX, InterfaceLookup::Found(DOC_V4)),
      Ok(addr) if addr == DOC_V4
    ),
    "the resolved address is what IP_MULTICAST_IF is set to, so it must arrive unchanged"
  );
  assert!(
    matches!(
      require_multicast_if_v4(
        IDX,
        InterfaceLookup::LookupFailed(io::Error::from(io::ErrorKind::PermissionDenied)),
      ),
      Err(BindError::Io(ref e)) if e.kind() == io::ErrorKind::PermissionDenied
    ),
    "a failed enumeration must reach the caller as Io carrying the platform's own kind, never as \
     InterfaceNotFound"
  );
  assert!(
    matches!(
      require_multicast_if_v4(IDX, InterfaceLookup::Addressless),
      Err(BindError::InterfaceNotFound(_))
    ),
    "an interface with no IPv4 address leaves no IP_MULTICAST_IF payload, and stays \
     InterfaceNotFound"
  );
  assert!(
    matches!(
      require_multicast_if_v4(IDX, InterfaceLookup::NoSuchInterface),
      Err(BindError::InterfaceNotFound(_))
    ),
    "an index that names no interface stays InterfaceNotFound"
  );
}

/// `try_join_v4` splits the same way, and this one runs at endpoint
/// construction in all three drivers, where it surfaces as
/// `ServerError::BindV4`.
#[test]
fn join_addrs_v4_reports_a_failed_look_up_as_io_and_keeps_the_kind() {
  assert!(
    matches!(
      require_join_addrs_v4(
        IDX,
        InterfaceLookup::LookupFailed(io::Error::from(io::ErrorKind::Interrupted)),
      ),
      Err(JoinError::Io(ref e)) if e.kind() == io::ErrorKind::Interrupted
    ),
    "an interrupted address dump must reach the caller as Io carrying its kind, not as a claim \
     that the interface is missing"
  );
  assert!(
    matches!(
      require_join_addrs_v4(IDX, InterfaceLookup::Found(vec![DOC_V4])),
      Ok(addrs) if addrs == vec![DOC_V4]
    ),
    "every resolved address is joined, so the list must arrive unchanged"
  );
  assert!(
    matches!(
      require_join_addrs_v4(IDX, InterfaceLookup::Addressless),
      Err(JoinError::InterfaceNotFound(_))
    ),
    "an interface with no IPv4 address has no group membership to add, and stays \
     InterfaceNotFound"
  );
  assert!(
    matches!(
      require_join_addrs_v4(IDX, InterfaceLookup::NoSuchInterface),
      Err(JoinError::InterfaceNotFound(_))
    ),
    "an index that names no interface stays InterfaceNotFound"
  );
}

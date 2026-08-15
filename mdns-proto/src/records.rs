//! Records published by a registered [`Service`].
//!
//! `ServiceRecords` is the durable, post-validation bundle: a name, A/AAAA
//! addresses, the SRV target/port, and the TXT segments. Building the wire
//! response is then a mechanical traversal.

use crate::{
  Name,
  backend::{RdataBuf, Shared, rdata_from_vec},
};
use core::net::{Ipv4Addr, Ipv6Addr};
use std::vec::Vec;

/// Append `item` to a read-only `Shared<[T]>`, returning a freshly sealed slice.
/// `ServiceRecords`' collections are built incrementally via the `add_*`
/// builders then frozen, so the O(n) reseal per append is paid only at build
/// time (n is a handful of addresses / subtypes) — in exchange the derived
/// `ServiceRecords::clone` is O(1) on the withdrawal-snapshot and rename-handoff
/// paths, which previously deep-copied all five collections.
fn arc_push<T: Clone>(slice: &[T], item: T) -> Shared<[T]> {
  slice
    .iter()
    .cloned()
    .chain(core::iter::once(item))
    .collect()
}

/// Records advertised by a single registered service.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct ServiceRecords {
  /// DNS-SD service-type PTR owner (e.g. `_ipp._tcp.local.`). Required for
  /// RFC 6763 discovery — browsers query this name to enumerate instances.
  service_type: Name,
  instance: Name,
  host: Name,
  port: u16,
  priority: u16,
  weight: u16,
  a_addrs: Shared<[Ipv4Addr]>,
  aaaa_addrs: Shared<[Ipv6Addr]>,
  /// Parallel to `aaaa_addrs`: per-AAAA interface scope id (0 = "any").
  ///
  /// Used by [`Endpoint`](crate::endpoint::Endpoint) to disambiguate IPv6
  /// self-loopback when the same link-local address (e.g. `fe80::1`) might
  /// exist on multiple interfaces.  without scope, a peer using
  /// the same link-local on a different interface would be wrongly
  /// classified as self.  Set via [`Self::add_aaaa_scoped`].  Always the
  /// same length as `aaaa_addrs`.
  aaaa_scopes: Shared<[u32]>,
  txt: Shared<[RdataBuf]>,
  /// RFC 6763 §7.1 subtype browse names, e.g. `_printer._sub._ipp._tcp.local.`.
  /// Each is the full `<sub>._sub.<service_type>` name (derived from
  /// `service_type` at [`Self::add_subtype`] time, so it survives an instance
  /// rename — the service type does not change). The service emits a shared PTR
  /// `<browse_name> -> instance` for each, and answers browse queries for them.
  subtypes: Shared<[Name]>,
  ttl_secs: u32,
}

impl ServiceRecords {
  /// Construct a new record bundle with the required fields. Optional fields
  /// (records, txt, priority, weight) start empty/default.
  ///
  /// `service_type` is the DNS-SD PTR owner, e.g. `_ipp._tcp.local.`.
  /// It must be the parent label sequence of `instance`.
  pub fn new(service_type: Name, instance: Name, host: Name, port: u16, ttl_secs: u32) -> Self {
    Self {
      service_type,
      instance,
      host,
      port,
      priority: 0,
      weight: 0,
      a_addrs: Shared::from([]),
      aaaa_addrs: Shared::from([]),
      aaaa_scopes: Shared::from([]),
      txt: Shared::from([]),
      subtypes: Shared::from([]),
      ttl_secs,
    }
  }

  /// The DNS-SD service type (PTR owner), e.g. `_ipp._tcp.local.`.
  #[inline(always)]
  pub fn service_type(&self) -> &Name {
    &self.service_type
  }

  /// The instance name (e.g. `MyPrinter._ipp._tcp.local.`).
  #[inline(always)]
  pub fn instance(&self) -> &Name {
    &self.instance
  }

  /// The SRV target hostname.
  #[inline(always)]
  pub fn host(&self) -> &Name {
    &self.host
  }

  /// The service port.
  #[inline(always)]
  pub const fn port(&self) -> u16 {
    self.port
  }

  /// SRV priority field.
  #[inline(always)]
  pub const fn priority(&self) -> u16 {
    self.priority
  }

  /// SRV weight field.
  #[inline(always)]
  pub const fn weight(&self) -> u16 {
    self.weight
  }

  /// Record TTL in seconds.
  #[inline(always)]
  pub const fn ttl_secs(&self) -> u32 {
    self.ttl_secs
  }

  /// Slice of IPv4 addresses.
  #[inline(always)]
  pub fn a_addrs_slice(&self) -> &[Ipv4Addr] {
    &self.a_addrs
  }

  /// Slice of IPv6 addresses.
  #[inline(always)]
  pub fn aaaa_addrs_slice(&self) -> &[Ipv6Addr] {
    &self.aaaa_addrs
  }

  /// Slice of per-AAAA interface scope ids (one entry per AAAA address;
  /// parallel to [`Self::aaaa_addrs_slice`]).  A scope of `0` means
  /// "unscoped / any interface" — appropriate for global addresses or
  /// when the caller does not know which interface the link-local will
  /// be published on.
  ///
  /// Used by [`Endpoint`](crate::endpoint::Endpoint) to disambiguate
  /// IPv6 link-local self-loopback on multi-homed hosts.
  #[inline(always)]
  pub fn aaaa_scopes_slice(&self) -> &[u32] {
    &self.aaaa_scopes
  }

  /// TXT segments as an iterator over byte slices.
  pub fn txt_segments(&self) -> impl Iterator<Item = &[u8]> {
    // `|b| b.as_ref()` (not `Bytes::as_ref`) so this compiles for both the
    // `bytes::Bytes` and no-atomic `Arc<[u8]>` `RdataBuf` flavors.
    self.txt.iter().map(|b| b.as_ref())
  }

  /// Append an IPv4 address.
  pub fn add_a(&mut self, addr: Ipv4Addr) -> &mut Self {
    self.a_addrs = arc_push(&self.a_addrs, addr);
    self
  }

  /// Append an IPv6 address with an unspecified interface scope.
  ///
  /// Equivalent to [`Self::add_aaaa_scoped`] with `scope_id = 0`.  For
  /// link-local addresses on multi-homed hosts prefer
  /// [`Self::add_aaaa_scoped`] so self-loopback detection can
  /// distinguish your own packets from peer packets that share the
  /// same numeric link-local on another interface.
  pub fn add_aaaa(&mut self, addr: Ipv6Addr) -> &mut Self {
    self.add_aaaa_scoped(addr, 0)
  }

  /// Append an IPv6 address bound to a specific interface scope.
  ///
  /// `scope_id` is typically the receiving interface index (the same
  /// value the host's `if_nametoindex(3)` returns).
  /// `Endpoint::handle` matches self-loopback for link-local sources by
  /// `(address, scope)` so a peer's identical link-local on a
  /// different interface is NOT misclassified as self.
  ///
  /// A `scope_id` of `0` keeps the legacy behaviour (matches any
  /// interface).  For global / unique-local IPv6 the scope is
  /// effectively ignored.
  pub fn add_aaaa_scoped(&mut self, addr: Ipv6Addr, scope_id: u32) -> &mut Self {
    self.aaaa_addrs = arc_push(&self.aaaa_addrs, addr);
    self.aaaa_scopes = arc_push(&self.aaaa_scopes, scope_id);
    self
  }

  /// Append a TXT segment.
  pub fn add_txt_segment(&mut self, segment: Vec<u8>) -> &mut Self {
    self.txt = arc_push(&self.txt, rdata_from_vec(segment));
    self
  }

  /// The RFC 6763 §7.1 subtype browse names registered for this service (each
  /// the full `<subtype>._sub.<service_type>` form).
  #[inline(always)]
  pub fn subtype_names(&self) -> &[Name] {
    &self.subtypes
  }

  /// Register a DNS-SD subtype (RFC 6763 §7.1). `subtype` is the subtype label
  /// (e.g. `"_printer"`); the full browse name `<subtype>._sub.<service_type>`
  /// is derived from the current service type and stored. The service then
  /// advertises a shared PTR `<browse_name> -> instance` and answers browse
  /// queries for it.
  ///
  /// Returns a [`NameError`](crate::name::NameError) if the derived
  /// `<subtype>._sub.<service_type>` is not a valid DNS name (e.g. an over-long
  /// label or total length).
  pub fn add_subtype(&mut self, subtype: &str) -> Result<&mut Self, crate::name::NameError> {
    let browse = std::format!(
      "{}._sub.{}",
      subtype.trim_end_matches('.'),
      self.service_type.as_str()
    );
    let name = Name::try_from_str(&browse)?;
    self.subtypes = arc_push(&self.subtypes, name);
    Ok(self)
  }

  /// Drop every RFC 6763 §7.1 subtype browse name `keep` rejects.
  ///
  /// Crate-internal, and for ONE caller: a detached rename goodbye that a
  /// same-name replacement has PARTLY superseded keeps draining for the subtype
  /// PTRs the replacement does not publish, so its record set must stop naming
  /// the ones it does. See
  /// [`Endpoint::note_service_announced`](crate::Endpoint::note_service_announced).
  ///
  /// This narrows what a set ADVERTISES and nothing else. A subtype PTR is a
  /// shared record at its own browse name, so dropping one drops a record this
  /// set answers for and retracts — never one another set holds. The common case
  /// rebuilds nothing: `keep` accepting every name leaves the sealed slice
  /// untouched, so a set with no subtypes, or one whose subtypes all survive,
  /// pays no allocation.
  pub(crate) fn retain_subtypes(&mut self, keep: impl Fn(&Name) -> bool) {
    if self.subtypes.iter().all(&keep) {
      return;
    }
    self.subtypes = self.subtypes.iter().filter(|n| keep(n)).cloned().collect();
  }

  /// Set SRV priority.
  pub fn set_priority(&mut self, v: u16) -> &mut Self {
    self.priority = v;
    self
  }

  /// Set SRV weight.
  pub fn set_weight(&mut self, v: u16) -> &mut Self {
    self.weight = v;
    self
  }

  /// Set TTL in seconds.
  pub fn set_ttl_secs(&mut self, v: u32) -> &mut Self {
    self.ttl_secs = v;
    self
  }

  /// Replace the instance name (used during conflict-driven rename).
  pub fn set_instance(&mut self, name: Name) -> &mut Self {
    self.instance = name;
    self
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

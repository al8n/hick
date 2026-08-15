//! Cross-cutting error types and their shared detail-struct payloads.
//!
//! Following `rust-type-conventions`: every multi-field error variant is
//! extracted into a `*Detail` named struct (private fields + `const fn`
//! accessors + `derive_more::Display`), and the parent enum carries a
//! newtype variant with `#[error(transparent)]`. Single-field variants
//! become plain newtypes; unit-only variants stay unit.

use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

use crate::{name::LabelTooLongDetail, wire::*};
// `Name`/`QueryHandle`/`ServiceHandle` are only carried by the alloc/std-gated
// error enums below, so gate the import to match (no_std + bare no-default have
// no `Name`).
cfg_heap! {
  use crate::{Name, QueryHandle, ServiceHandle};
}

/// Detail payload for "buffer too short": a parser ran out of bytes.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("buffer too short: needed {needed} bytes at offset {at}, had {have}")]
pub struct BufferTooShortDetail {
  needed: usize,
  at: usize,
  have: usize,
}

impl BufferTooShortDetail {
  /// Creates a new detail payload.
  #[inline(always)]
  pub const fn new(needed: usize, at: usize, have: usize) -> Self {
    Self { needed, at, have }
  }

  /// Bytes the parser needed at the failure point.
  #[inline(always)]
  pub const fn needed(&self) -> usize {
    self.needed
  }

  /// Offset into the input at which the parser stopped.
  #[inline(always)]
  pub const fn at(&self) -> usize {
    self.at
  }

  /// Bytes actually available at the failure point.
  #[inline(always)]
  pub const fn have(&self) -> usize {
    self.have
  }

  /// Returns `true` if the detail struct has no bytes (always false in
  /// practice — zero-byte buffers are typically not validated through this
  /// error type).
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.have == 0
  }
}

/// Detail payload for "output buffer too small" during encoding.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("output buffer too small: needed {needed} bytes, have {have}")]
pub struct BufferTooSmallDetail {
  needed: usize,
  have: usize,
}

impl BufferTooSmallDetail {
  /// Creates a new detail payload.
  #[inline(always)]
  pub const fn new(needed: usize, have: usize) -> Self {
    Self { needed, have }
  }

  /// Bytes the encoder needed.
  #[inline(always)]
  pub const fn needed(&self) -> usize {
    self.needed
  }

  /// Bytes available in the output buffer.
  #[inline(always)]
  pub const fn have(&self) -> usize {
    self.have
  }

  /// Returns `true` if the detail struct has no bytes (always false in
  /// practice — zero-byte buffers are typically not validated through this
  /// error type).
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.have == 0
  }
}

/// Detail payload for [`ParseError::PointerForward`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("compression pointer points forward: ptr {ptr} > current {at}")]
pub struct PointerForwardDetail {
  ptr: u16,
  at: u16,
}

impl PointerForwardDetail {
  /// Creates a new detail payload.
  #[inline(always)]
  pub const fn new(ptr: u16, at: u16) -> Self {
    Self { ptr, at }
  }

  /// The forward-pointing pointer offset.
  #[inline(always)]
  pub const fn ptr(&self) -> u16 {
    self.ptr
  }

  /// The current parsing position.
  #[inline(always)]
  pub const fn at(&self) -> u16 {
    self.at
  }
}

/// Detail payload for [`ParseError::RdlengthOverrun`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("rdlength {rdlen} at offset {at} exceeds remaining {rem} bytes")]
pub struct RdlengthOverrunDetail {
  rdlen: u16,
  at: usize,
  rem: usize,
}

impl RdlengthOverrunDetail {
  /// Creates a new detail payload.
  #[inline(always)]
  pub const fn new(rdlen: u16, at: usize, rem: usize) -> Self {
    Self { rdlen, at, rem }
  }

  /// The resource record data length.
  #[inline(always)]
  pub const fn rdlen(&self) -> u16 {
    self.rdlen
  }

  /// The offset at which the overrun occurred.
  #[inline(always)]
  pub const fn at(&self) -> usize {
    self.at
  }

  /// Remaining bytes available in the input buffer.
  #[inline(always)]
  pub const fn rem(&self) -> usize {
    self.rem
  }
}

/// Errors raised while parsing an mDNS message off the wire.
#[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ParseError {
  /// Parser ran out of input bytes.
  #[error(transparent)]
  BufferTooShort(BufferTooShortDetail),

  /// A label length byte exceeded [`MAX_LABEL_BYTES`](crate::constants::MAX_LABEL_BYTES).
  #[error(transparent)]
  LabelTooLong(LabelTooLongDetail),

  /// A fully-resolved name exceeded [`MAX_NAME_BYTES`](crate::constants::MAX_NAME_BYTES).
  #[error("name exceeds max length {0} bytes")]
  NameTooLong(usize),

  /// A compression pointer chain pointed back to a name still being resolved.
  #[error("name compression pointer cycle detected")]
  PointerCycle,

  /// A compression pointer chain exceeded [`MAX_POINTER_HOPS`](crate::constants::MAX_POINTER_HOPS) hops.
  #[error("name compression pointer chain exceeded {0} hops")]
  PointerChainTooLong(u8),

  /// A compression pointer pointed forward (>= current position), violating RFC 1035 §4.1.4.
  #[error(transparent)]
  PointerForward(PointerForwardDetail),

  /// The top two bits of a label byte did not match a known label kind.
  #[error("unknown label kind in byte {0:#010b}")]
  InvalidLabelKind(u8),

  /// A resource record's `rdlength` ran past the end of the message.
  #[error(transparent)]
  RdlengthOverrun(RdlengthOverrunDetail),

  /// An integer conversion failed.
  #[error(transparent)]
  IntegerConversion(#[from] core::num::TryFromIntError),

  /// A well-known name-bearing RR type (e.g. NS, SOA, MX, DNAME) that this
  /// mDNS/DNS-SD stack does not type-specifically parse. Its RDATA may carry a
  /// compressed/case-varied domain name that cannot be canonicalized for
  /// storage or identity, so callers drop the record rather than cache a
  /// compression-sensitive, non-dedupable entry.
  #[error("unsupported name-bearing record type {0}")]
  UnsupportedNameBearingType(u16),
}

/// Errors raised while encoding an mDNS message onto the wire.
#[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum EncodeError {
  /// Output buffer cannot hold the encoded message.
  #[error(transparent)]
  BufferTooSmall(BufferTooSmallDetail),

  /// An integer conversion failed during encoding.
  #[error(transparent)]
  IntegerConversion(#[from] core::num::TryFromIntError),
}

/// Errors raised by [`Service::handle_timeout`](crate::service::Service::handle_timeout).
#[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum HandleTimeoutError {
  /// A deadline arithmetic operation overflowed.
  #[error("deadline arithmetic overflow")]
  Overflow,
}

/// Errors raised by [`Service::poll_transmit`](crate::service::Service::poll_transmit).
#[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum TransmitError {
  /// The caller-supplied buffer is too small to hold the encoded message.
  #[error(transparent)]
  BufferTooSmall(BufferTooSmallDetail),
}

/// Returned when an internal pool is at capacity.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
#[error("pool capacity exceeded")]
pub struct StorageFullError;

/// Errors raised by [`Endpoint::handle`](crate::endpoint::Endpoint::handle).
#[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum HandleError {
  /// The datagram could not be parsed.
  #[error(transparent)]
  Parse(#[from] ParseError),

  /// The incoming opcode is not `Query` (mDNS only supports Query).
  #[error("incoming opcode `{0}` is not Query")]
  InvalidOpcode(Opcode),

  /// The incoming response code is not `NoError` (mDNS requires NoError).
  #[error("incoming response code `{0}` is not NoError")]
  InvalidResponseCode(ResponseCode),
}

cfg_heap! {
  /// Detail payload for [`RegisterServiceError::ServiceTypeNotParent`].
  #[derive(Debug, Clone, Eq, PartialEq, Hash, Display, thiserror::Error)]
  #[display("service type `{service_type}` is not the parent label sequence of instance `{instance}`")]
  pub struct ServiceTypeNotParentDetail {
    service_type: Name,
    instance: Name,
  }

  impl ServiceTypeNotParentDetail {
    /// Creates a new detail payload.
    #[inline(always)]
    pub const fn new(service_type: Name, instance: Name) -> Self {
      Self { service_type, instance }
    }

    /// The registration's declared service type.
    #[inline(always)]
    pub fn service_type(&self) -> &Name {
      &self.service_type
    }

    /// The registration's instance name.
    #[inline(always)]
    pub fn instance(&self) -> &Name {
      &self.instance
    }
  }

  /// Errors raised by `Endpoint::try_register_service`.
  #[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
  #[unwrap(ref)]
  #[try_unwrap(ref)]
  #[non_exhaustive]
  pub enum RegisterServiceError {
    /// A service with this name is already registered.
    #[error("service `{0}` already registered")]
    NameAlreadyRegistered(crate::Name),

    /// Another live service publishes this HOST name with a DIFFERENT A/AAAA
    /// set. Carries the host name.
    ///
    /// Sharing a host name across services is supported and normal — it is how
    /// several services on one machine advertise one set of addresses. Sharing
    /// it while DISAGREEING about the addresses is not: the two publish
    /// contradictory A/AAAA for one name, and each reads the other's
    /// announcement as a host claiming its own host name with rdata it does not
    /// hold. RFC 6762 §9 makes that a conflict, and there is no auto-rename for
    /// a host name, so it surfaces as a TERMINAL
    /// [`ServiceUpdate::HostConflict`](crate::event::ServiceUpdate::HostConflict)
    /// raised by a sibling on this same machine.
    ///
    /// Register the services with one address set, or give them different host
    /// names.
    #[error("host `{0}` is already published with a different address set")]
    HostAddressesDiffer(crate::Name),

    /// The record TTL is below [`MIN_SERVICE_TTL_SECS`](crate::constants::MIN_SERVICE_TTL_SECS).
    ///
    /// A TTL of 0 is the RFC 6762 §10.1 goodbye encoding — it deletes the record
    /// from peer caches rather than publishing it — and a TTL of 1 refreshes at
    /// 0.8 s, inside §8.3's one-second floor on unsolicited responses, so the
    /// record cannot be kept alive at a legal rate. Carries the rejected TTL.
    #[error("record TTL {0} s is below the {min} s minimum a service can be advertised at", min = crate::constants::MIN_SERVICE_TTL_SECS)]
    TtlTooSmall(u32),

    /// `service_type` is not the parent label sequence of `instance`.
    ///
    /// RFC 6763 §4.1: a Service Instance Name is
    /// `<Instance> . <Service> . <Domain>`, and §4.1.1 stores `<Instance>` as
    /// a single DNS label — so a valid `instance` always has EXACTLY one
    /// label more than its `service_type`. The comparison is
    /// case-insensitive and blind to the optional trailing root dot on either
    /// name, the same rule [`Name::same_owner`] applies to whole-name
    /// equality (see `Name::is_parent_of`).
    #[error(transparent)]
    ServiceTypeNotParent(ServiceTypeNotParentDetail),

    /// The internal routing pool is full.
    #[error(transparent)]
    StorageFull(#[from] StorageFullError),
  }
}

/// Errors raised by `Endpoint::try_start_query`.
#[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum StartQueryError {
  /// The internal routing pool is full.
  #[error(transparent)]
  StorageFull(#[from] StorageFullError),
}

cfg_heap! {
  /// Errors raised by
  /// [`Endpoint::handle_service_renamed`](crate::endpoint::Endpoint::handle_service_renamed).
  #[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
  #[unwrap(ref)]
  #[try_unwrap(ref)]
  #[non_exhaustive]
  pub enum HandleServiceRenamedError {
    /// The new name is already registered to a different service.
    #[error("name `{0}` is already registered to a different service")]
    NameAlreadyRegistered(Name),

    /// Applying the rename would leave this route sharing a HOST name with
    /// another live route that publishes a different A/AAAA set. Carries the
    /// host name. See [`RegisterServiceError::HostAddressesDiffer`].
    ///
    /// **Not reachable today, and deliberately kept.** A rename replaces a
    /// route's INSTANCE name and touches neither its host name nor its
    /// addresses, so it cannot break an invariant registration already
    /// established. The check is the invariant's second enforcement point rather
    /// than dead weight: it becomes reachable the moment a rename is allowed to
    /// carry new records, which is exactly the change that would otherwise
    /// re-open the terminal-`HostConflict`-on-every-sibling-echo path silently.
    #[error("host `{0}` is already published with a different address set")]
    HostAddressesDiffer(Name),

    /// The handle does not refer to a registered service.
    #[error("service handle {0} not found")]
    ServiceNotFound(ServiceHandle),
  }

  /// Errors raised by query-handle lookups on `Endpoint` (`poll_query_*`,
  /// `handle_query_timeout`, `cancel_query`, …) when the handle no longer
  /// corresponds to an active query.  A query disappears from the endpoint
  /// when its terminal update has been drained via `Endpoint::poll_query`
  /// (auto-prune) or after an explicit `Endpoint::cancel_query` call.
  #[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
  #[unwrap(ref)]
  #[try_unwrap(ref)]
  #[non_exhaustive]
  pub enum CancelQueryError {
    /// The handle does not refer to a currently registered query.
    #[error("query handle {0} not found")]
    QueryNotFound(QueryHandle),
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

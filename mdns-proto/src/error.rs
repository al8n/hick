//! Cross-cutting error types and their shared detail-struct payloads.
//!
//! Following `rust-type-conventions`: every multi-field error variant is
//! extracted into a `*Detail` named struct (private fields + `const fn`
//! accessors + `derive_more::Display`), and the parent enum carries a
//! newtype variant with `#[error(transparent)]`. Single-field variants
//! become plain newtypes; unit-only variants stay unit.

use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

use crate::name::LabelTooLongDetail;

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

  /// A label length byte exceeded [`crate::constants::MAX_LABEL_BYTES`].
  #[error(transparent)]
  LabelTooLong(LabelTooLongDetail),

  /// A fully-resolved name exceeded [`crate::constants::MAX_NAME_BYTES`].
  #[error("name exceeds max length {0} bytes")]
  NameTooLong(usize),

  /// A compression pointer chain pointed back to a name still being resolved.
  #[error("name compression pointer cycle detected")]
  PointerCycle,

  /// A compression pointer chain exceeded [`crate::constants::MAX_POINTER_HOPS`] hops.
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

// ── StorageFullError ─────────────────────────────────────────────────

/// Returned when an internal pool is at capacity.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
#[error("pool capacity exceeded")]
pub struct StorageFullError;

// ── HandleError ──────────────────────────────────────────────────────

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
  InvalidOpcode(crate::wire::Opcode),

  /// The incoming response code is not `NoError` (mDNS requires NoError).
  #[error("incoming response code `{0}` is not NoError")]
  InvalidResponseCode(crate::wire::ResponseCode),
}

// ── RegisterServiceError ─────────────────────────────────────────────

/// Errors raised by `Endpoint::try_register_service`.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
#[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum RegisterServiceError {
  /// A service with this name is already registered.
  #[error("service `{0}` already registered")]
  NameAlreadyRegistered(crate::Name),

  /// The internal routing pool is full.
  #[error(transparent)]
  StorageFull(#[from] StorageFullError),
}

// ── StartQueryError ──────────────────────────────────────────────────

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

// ── HandleServiceRenamedError ────────────────────────────────────────

/// Errors raised by
/// [`Endpoint::handle_service_renamed`](crate::endpoint::Endpoint::handle_service_renamed).
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
#[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum HandleServiceRenamedError {
  /// The new name is already registered to a different service.
  #[error("name `{0}` is already registered to a different service")]
  NameAlreadyRegistered(crate::Name),

  /// The handle does not refer to a registered service.
  #[error("service handle {0} not found")]
  ServiceNotFound(crate::ServiceHandle),
}

// ── CancelQueryError ──────────────────────────────────────────────────

/// Errors raised by query-handle lookups on `Endpoint` (`poll_query_*`,
/// `handle_query_timeout`, `cancel_query`, …) when the handle no longer
/// corresponds to an active query.  A query disappears from the endpoint
/// when its terminal update has been drained via `Endpoint::poll_query`
/// (auto-prune) or after an explicit `Endpoint::cancel_query` call.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
#[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum CancelQueryError {
  /// The handle does not refer to a currently registered query.
  #[error("query handle {0} not found")]
  QueryNotFound(crate::QueryHandle),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  #[cfg(feature = "std")]
  use super::ParseError;
  use super::{BufferTooShortDetail, BufferTooSmallDetail};

  #[test]
  fn buffer_too_short_detail_accessors() {
    let d = BufferTooShortDetail::new(4, 12, 1);
    assert_eq!(d.needed(), 4);
    assert_eq!(d.at(), 12);
    assert_eq!(d.have(), 1);
  }

  #[test]
  fn buffer_too_small_detail_accessors() {
    let d = BufferTooSmallDetail::new(100, 32);
    assert_eq!(d.needed(), 100);
    assert_eq!(d.have(), 32);
  }

  #[cfg(feature = "std")]
  #[test]
  fn parse_error_buffer_too_short_display() {
    let e = ParseError::BufferTooShort(BufferTooShortDetail::new(4, 12, 1));
    assert_eq!(
      std::format!("{e}"),
      "buffer too short: needed 4 bytes at offset 12, had 1"
    );
  }

  #[test]
  fn is_empty_and_pointer_rdlength_accessors() {
    use super::{PointerForwardDetail, RdlengthOverrunDetail};
    assert!(!BufferTooShortDetail::new(4, 12, 1).is_empty());
    assert!(BufferTooShortDetail::new(4, 12, 0).is_empty());
    assert!(!BufferTooSmallDetail::new(100, 32).is_empty());
    assert!(BufferTooSmallDetail::new(100, 0).is_empty());

    let p = PointerForwardDetail::new(10, 5);
    assert_eq!(p.ptr(), 10);
    assert_eq!(p.at(), 5);

    let r = RdlengthOverrunDetail::new(20, 12, 4);
    assert_eq!(r.rdlen(), 20);
    assert_eq!(r.at(), 12);
    assert_eq!(r.rem(), 4);
  }
}

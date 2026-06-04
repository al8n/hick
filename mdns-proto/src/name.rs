//! Owned, canonical DNS name.
//!
//! [`Name`] stores names in **canonical lowercase form** (mDNS is
//! case-insensitive per RFC 6762 §16) with a feature-conditional backing:
//! [`smol_str::SmolStr`] under `alloc`/`std`, [`heapless::String<255>`]
//! under `no_alloc` with the `heapless` feature.
//!
//! Under bare `--no-default-features` (neither `alloc`/`std` nor `heapless`
//! enabled) the `Name` type is absent. Callers compiling without backing
//! must enable one of those features before using anything that depends on
//! `Name`.

use crate::constants::{MAX_LABEL_BYTES, MAX_NAME_BYTES};
use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// Detail payload for [`NameError::LabelTooLong`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("label of {len} bytes exceeds max {MAX_LABEL_BYTES}")]
pub struct LabelTooLongDetail {
  len: usize,
}

impl LabelTooLongDetail {
  #[inline(always)]
  pub(crate) const fn new(len: usize) -> Self {
    Self { len }
  }

  /// Bytes in the rejected label.
  #[inline(always)]
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Returns `true` if the rejected label had zero bytes (always false in
  /// practice — a zero-length label produces [`NameError::EmptyLabel`]).
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }
}

/// Detail payload for [`NameError::NameTooLong`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display, thiserror::Error)]
#[display("name of {len} bytes exceeds max {MAX_NAME_BYTES}")]
pub struct NameTooLongDetail {
  len: usize,
}

impl NameTooLongDetail {
  #[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
  #[inline(always)]
  pub(crate) const fn new(len: usize) -> Self {
    Self { len }
  }

  /// Bytes in the rejected name.
  #[inline(always)]
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Returns `true` if the rejected name had zero bytes (always false in
  /// practice — empty names pass validation).
  #[inline(always)]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }
}

/// Reasons a string cannot be accepted as a [`Name`].
#[derive(
  Debug, Clone, Copy, Eq, PartialEq, Hash, IsVariant, Unwrap, TryUnwrap, thiserror::Error,
)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum NameError {
  /// A single label exceeded [`MAX_LABEL_BYTES`].
  #[error(transparent)]
  LabelTooLong(LabelTooLongDetail),

  /// The complete name exceeded [`MAX_NAME_BYTES`].
  #[error(transparent)]
  NameTooLong(NameTooLongDetail),

  /// The input contained an empty label (e.g. consecutive dots).
  #[error("name contains an empty label")]
  EmptyLabel,
}

/// Validates that `s` is a syntactically acceptable DNS name (per-label and
/// total length, no empty internal labels). Trailing `.` (FQDN form) is
/// permitted.
#[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
fn validate_name(s: &str) -> Result<(), NameError> {
  if s.len() > MAX_NAME_BYTES {
    return Err(NameError::NameTooLong(NameTooLongDetail::new(s.len())));
  }
  if s.is_empty() {
    return Ok(());
  }
  let trimmed = match s.strip_suffix('.') {
    Some(rest) => rest,
    None => s,
  };
  // RFC 1035 §3.1 / §2.3.4: the 255-octet limit is on the WIRE form — each
  // label contributes one length octet plus its bytes, terminated by the root
  // (one octet). A presentation string of N bytes encodes to N+2 octets, so a
  // string-length check alone (s.len() <= 255) would wrongly accept names whose
  // wire form is 256–257 octets. Accumulate the wire length and enforce it.
  let mut wire_len: usize = 1; // terminating root label
  for label in trimmed.split('.') {
    if label.is_empty() {
      return Err(NameError::EmptyLabel);
    }
    let len = label.len();
    if len > MAX_LABEL_BYTES as usize {
      return Err(NameError::LabelTooLong(LabelTooLongDetail::new(len)));
    }
    wire_len = wire_len.saturating_add(1).saturating_add(len);
  }
  if wire_len > MAX_NAME_BYTES {
    return Err(NameError::NameTooLong(NameTooLongDetail::new(wire_len)));
  }
  Ok(())
}

// ── Backing-type selection ────────────────────────────────────────────
// Exactly one of these `cfg` arms is active in any valid build. Under
// `--no-default-features` with neither `alloc`/`std` nor `heapless`,
// **none** are active and `Name` itself is absent.

#[cfg(any(feature = "alloc", feature = "std"))]
type NameInner = smol_str::SmolStr;

#[cfg(all(feature = "heapless", not(any(feature = "alloc", feature = "std"))))]
type NameInner = heapless::String<MAX_NAME_BYTES>;

/// Owned, canonical DNS name (lowercased on construction).
#[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
#[cfg_attr(
  docsrs,
  doc(cfg(any(feature = "alloc", feature = "std", feature = "heapless")))
)]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Name(NameInner);

#[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
impl Name {
  /// Returns the canonical lowercase form of this name.
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }

  /// Returns the length in bytes.
  #[inline(always)]
  pub fn len(&self) -> usize {
    self.0.as_str().len()
  }

  /// Returns `true` if this name is empty.
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.0.as_str().is_empty()
  }
}

#[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
impl core::fmt::Display for Name {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

// ── try_from_str — alloc/std path (SmolStr) ───────────────────────────
#[cfg(any(feature = "alloc", feature = "std"))]
const _: () = {
  use std::string::String;

  impl Name {
    /// Constructs a [`Name`] from a string, validating label lengths and
    /// total length, normalizing to canonical lowercase.
    pub fn try_from_str(s: &str) -> Result<Self, NameError> {
      validate_name(s)?;
      // Case-fold ASCII only (DNS case-insensitivity is ASCII-only, RFC 4343)
      // and iterate CHARS so non-ASCII UTF-8 — DNS-SD instance names are UTF-8
      // (RFC 6763 §4.1) — is preserved. `byte as char` would Latin-1-reinterpret
      // each byte and double-encode multi-byte sequences.
      let mut buf = String::with_capacity(s.len());
      for ch in s.chars() {
        buf.push(ch.to_ascii_lowercase());
      }
      Ok(Self(NameInner::from(buf)))
    }
  }
};

// ── try_from_str — no_alloc heapless path ─────────────────────────────
#[cfg(all(feature = "heapless", not(any(feature = "alloc", feature = "std"))))]
const _: () = {
  impl Name {
    /// Constructs a [`Name`] from a string, validating label lengths and
    /// total length, normalizing to canonical lowercase.
    pub fn try_from_str(s: &str) -> Result<Self, NameError> {
      validate_name(s)?;
      // ASCII-only case-fold (RFC 4343); iterate CHARS so non-ASCII UTF-8
      // (RFC 6763 §4.1 instance names) is preserved, not double-encoded.
      let mut buf: NameInner = heapless::String::new();
      for ch in s.chars() {
        buf
          .push(ch.to_ascii_lowercase())
          .map_err(|_| NameError::NameTooLong(NameTooLongDetail::new(s.len())))?;
      }
      Ok(Self(buf))
    }
  }
};

#[cfg(all(test, any(feature = "alloc", feature = "std", feature = "heapless")))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
  use super::{Name, NameError};

  #[test]
  fn empty_input_accepted() {
    let n = Name::try_from_str("").unwrap();
    assert!(n.is_empty());
    assert_eq!(n.as_str(), "");
  }

  #[test]
  fn canonical_lowercase_normalization() {
    let n = Name::try_from_str("My.Local.").unwrap();
    assert_eq!(n.as_str(), "my.local.");
  }

  #[test]
  fn accepts_trailing_dot() {
    let n = Name::try_from_str("foo.local.").unwrap();
    assert_eq!(n.as_str(), "foo.local.");
  }

  #[test]
  fn rejects_label_over_63_bytes() {
    // Use a literal long label rather than `.repeat()` so the test runs
    // under `--no-default-features --features heapless` (no alloc).
    let long = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 65 'a'
    let err = Name::try_from_str(long).unwrap_err();
    assert!(matches!(err, NameError::LabelTooLong(_)));
  }

  #[test]
  fn rejects_empty_label() {
    let err = Name::try_from_str("foo..bar").unwrap_err();
    assert!(matches!(err, NameError::EmptyLabel));
  }

  /// the 255-octet cap is on the WIRE form (string length + 2), so a
  /// name whose presentation string is <= 255 bytes but whose wire form is
  /// 256–257 octets must be rejected. (Needs alloc to build the long strings.)
  #[test]
  #[cfg(any(feature = "alloc", feature = "std"))]
  fn enforces_wire_length_not_string_length() {
    // 4 labels of 63/63/63/61 = 250 label bytes + 3 dots = 253 string bytes →
    // wire form = 253 + 2 = 255 octets → accepted (the boundary).
    let at_limit = std::format!(
      "{}.{}.{}.{}",
      "a".repeat(63),
      "a".repeat(63),
      "a".repeat(63),
      "a".repeat(61)
    );
    assert_eq!(at_limit.len(), 253);
    assert!(
      Name::try_from_str(&at_limit).is_ok(),
      "a name whose wire form is exactly 255 octets must be accepted"
    );

    // 63/63/63/62 = 251 + 3 dots = 254 string bytes → wire form = 256 octets →
    // rejected, even though the string length (254) is <= 255.
    let over_limit = std::format!(
      "{}.{}.{}.{}",
      "a".repeat(63),
      "a".repeat(63),
      "a".repeat(63),
      "a".repeat(62)
    );
    assert_eq!(over_limit.len(), 254);
    let err = Name::try_from_str(&over_limit).unwrap_err();
    assert!(
      matches!(err, NameError::NameTooLong(_)),
      "a name whose wire form exceeds 255 octets must be rejected despite a string length <= 255"
    );
  }
}

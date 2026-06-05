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

    /// Builds a canonical [`Name`] directly from a sequence of raw wire labels
    /// (each the decompressed bytes of one DNS label, no length prefix),
    /// joining them with `.` plus a trailing `.`. Labels are ASCII case-folded
    /// (RFC 4343); non-ASCII bytes are preserved, and the assembled name must
    /// be valid UTF-8 — DNS-SD names are UTF-8 (RFC 6763 §4.1). Returns `None`
    /// on a malformed label (`Err` item), a label containing the `.` separator
    /// byte, non-UTF-8 bytes, or a label/total length violation.
    ///
    /// This is the wire-decode counterpart to [`Name::try_from_str`]: it skips
    /// the throwaway presentation `String` a caller would otherwise assemble
    /// and — unlike a `byte as char` join — never Latin-1-reinterprets a
    /// multi-byte UTF-8 sequence into mojibake.
    ///
    /// Length limits are checked incrementally, before each label is decoded or
    /// pushed, so an oversized iterator is rejected without unbounded allocation.
    pub fn from_wire_labels<'a, E, I>(labels: I) -> Option<Self>
    where
      I: IntoIterator<Item = Result<&'a [u8], E>>,
    {
      // `from_wire_labels` is public and accepts ANY iterator, so the length
      // limits must be enforced incrementally, BEFORE decoding or pushing each
      // label — otherwise a hostile caller could drive allocation proportional
      // to the input for a name that is ultimately rejected (OOM). The bounded
      // `NameRef::labels()` the endpoint passes always satisfies these, so this
      // only rejects out-of-spec callers.
      let mut buf = String::with_capacity(MAX_NAME_BYTES);
      let mut wire_len: usize = 1; // terminating root label (RFC 1035 §3.1)
      for label in labels {
        let label = label.ok()?;
        if label.len() > MAX_LABEL_BYTES as usize {
          return None;
        }
        wire_len = wire_len.saturating_add(1).saturating_add(label.len());
        if wire_len > MAX_NAME_BYTES {
          return None;
        }
        // A wire label may legally carry a literal '.' byte, but `Name` joins
        // labels with '.' as the separator — so a dot-bearing label would alias
        // a different label sequence to the same string (["a.b","local"] would
        // equal ["a","b","local"]) and poison cache identity (insert / TTL=0
        // removal / cache-flush clamp all key on this `Name`). Reject it — the
        // same contract the discovery layer enforces, since `Name` cannot
        // represent a dot-bearing label faithfully.
        if label.contains(&b'.') {
          return None;
        }
        for ch in core::str::from_utf8(label).ok()?.chars() {
          buf.push(ch.to_ascii_lowercase());
        }
        buf.push('.');
      }
      validate_name(&buf).ok()?;
      Some(Self(NameInner::from(buf)))
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

    /// Builds a canonical [`Name`] directly from a sequence of raw wire labels
    /// (each the decompressed bytes of one DNS label, no length prefix),
    /// joining them with `.` plus a trailing `.`. Labels are ASCII case-folded
    /// (RFC 4343); non-ASCII bytes are preserved, and the assembled name must
    /// be valid UTF-8 — DNS-SD names are UTF-8 (RFC 6763 §4.1). Returns `None`
    /// on a malformed label (`Err` item), non-UTF-8 bytes, or a label/total
    /// length violation. Wire-decode counterpart to [`Name::try_from_str`].
    pub fn from_wire_labels<'a, E, I>(labels: I) -> Option<Self>
    where
      I: IntoIterator<Item = Result<&'a [u8], E>>,
    {
      let mut buf: NameInner = heapless::String::new();
      let mut wire_len: usize = 1; // terminating root label (RFC 1035 §3.1)
      for label in labels {
        let label = label.ok()?;
        // Enforce the length limits before decoding (see the alloc/std path);
        // the heapless buffer is already capped at MAX_NAME_BYTES, but this
        // rejects an oversized label without scanning it first.
        if label.len() > MAX_LABEL_BYTES as usize {
          return None;
        }
        wire_len = wire_len.saturating_add(1).saturating_add(label.len());
        if wire_len > MAX_NAME_BYTES {
          return None;
        }
        // Reject a label carrying a literal '.' (see the alloc/std path): with
        // '.' as the join separator a dot-bearing label would alias a different
        // label sequence and poison cache identity.
        if label.contains(&b'.') {
          return None;
        }
        for ch in core::str::from_utf8(label).ok()?.chars() {
          buf.push(ch.to_ascii_lowercase()).ok()?;
        }
        buf.push('.').ok()?;
      }
      validate_name(&buf).ok()?;
      Some(Self(buf))
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
  fn from_wire_labels_preserves_utf8_and_folds_ascii() {
    // "Café" (é = U+00E9 → UTF-8 0xC3 0xA9). A `byte as char` join would
    // Latin-1-double-encode the é; from_wire_labels keeps it intact while
    // ASCII-folding the leading 'C'.
    let labels: [Result<&[u8], core::convert::Infallible>; 2] = [Ok(b"Caf\xc3\xa9"), Ok(b"local")];
    let n = Name::from_wire_labels(labels).unwrap();
    assert_eq!(n.as_str(), "café.local.");
  }

  #[test]
  fn from_wire_labels_rejects_non_utf8() {
    let labels: [Result<&[u8], core::convert::Infallible>; 1] = [Ok(b"\xff\xfe")];
    assert!(Name::from_wire_labels(labels).is_none());
  }

  #[test]
  fn from_wire_labels_rejects_malformed_label() {
    let labels: [Result<&[u8], &str>; 2] = [Ok(b"ok"), Err("truncated")];
    assert!(Name::from_wire_labels(labels).is_none());
  }

  #[test]
  fn from_wire_labels_rejects_dot_bearing_label_so_no_cache_aliasing() {
    // A wire label may legally contain a literal '.' byte. Since `Name` joins
    // labels with '.', a dot-bearing label MUST be rejected — otherwise
    // ["a.b","local"] would alias ["a","b","local"] to the same cache key.
    let dotted: [Result<&[u8], core::convert::Infallible>; 2] = [Ok(b"a.b"), Ok(b"local")];
    assert!(Name::from_wire_labels(dotted).is_none());
    let split: [Result<&[u8], core::convert::Infallible>; 3] = [Ok(b"a"), Ok(b"b"), Ok(b"local")];
    assert_eq!(
      Name::from_wire_labels(split).unwrap().as_str(),
      "a.b.local."
    );
  }

  #[test]
  fn from_wire_labels_bounds_allocation_before_validation() {
    // from_wire_labels is public, so it bounds work itself rather than trusting
    // the caller (NameRef::labels already caps labels at 63 bytes). A label over
    // MAX_LABEL_BYTES is rejected up front, before the name is assembled.
    let long = [b'a'; 64];
    let one: [Result<&[u8], core::convert::Infallible>; 1] = [Ok(&long[..])];
    assert!(Name::from_wire_labels(one).is_none());
    // An accumulated wire length over MAX_NAME_BYTES (here 10 x 63-byte labels)
    // is rejected before the buffer can grow past the 255-octet limit.
    let label = [b'a'; 63];
    let many: [Result<&[u8], core::convert::Infallible>; 10] = [Ok(&label[..]); 10];
    assert!(Name::from_wire_labels(many).is_none());
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

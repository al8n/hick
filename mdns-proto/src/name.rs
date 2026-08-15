//! Owned, canonical DNS name.
//!
//! [`Name`] stores names in **canonical lowercase form** (mDNS is
//! case-insensitive per RFC 6762 §16) with a feature-conditional backing:
//! [`smol_str::SmolStr`] under `alloc`/`std`, or `portable_atomic_util::Arc<str>`
//! under `no-atomic` (cores without native atomic CAS).
//!
//! Under bare `--no-default-features` (none of `alloc`/`std`/`no-atomic`) the
//! owned `Name` type is absent — parse names as the borrowed `NameRef`
//! instead, then enable a backing feature to own them.

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
  cfg_heap! {
  #[inline(always)]
  pub(crate) const fn new(len: usize) -> Self {
    Self { len }
  }
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

cfg_heap! {
/// Validates that `s` is a syntactically acceptable DNS name (per-label and
/// total length, no empty internal labels). Trailing `.` (FQDN form) is
/// permitted.
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
}

// ── Backing-type selection ────────────────────────────────────────────
// Exactly one of these `cfg` arms is active in any valid build. Under
// `--no-default-features` with none of `alloc`/`std`/`no-atomic`, **none** are
// active and `Name` itself is absent.

#[cfg(any(feature = "alloc", feature = "std"))]
type NameInner = smol_str::SmolStr;

// No-atomic alloc tier: a portable-atomic `Arc<str>` (cheap clone without native
// atomic CAS). Same heap-string shape as `SmolStr` minus the small-string
// optimization; built through the same `NameInner::from` path.
#[cfg(all(feature = "no-atomic", not(any(feature = "alloc", feature = "std"))))]
type NameInner = portable_atomic_util::Arc<str>;

cfg_heap! {
/// Owned, canonical DNS name (lowercased on construction).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Name(NameInner);

impl Name {
  /// Returns the canonical lowercase form of this name.
  #[inline(always)]
  pub fn as_str(&self) -> &str {
    // `as_ref` (not `as_str`) so the same body compiles whether `NameInner` is
    // `SmolStr` (alloc/std) or the no-atomic `Arc<str>` (which has no inherent
    // `as_str`).
    self.0.as_ref()
  }

  /// Returns the length in bytes.
  #[inline(always)]
  pub fn len(&self) -> usize {
    self.as_str().len()
  }

  /// Returns `true` if this name is empty.
  #[inline(always)]
  pub fn is_empty(&self) -> bool {
    self.as_str().is_empty()
  }

  /// Do `self` and `other` name the same DNS owner?
  ///
  /// THE equality every guard that decides "are these two registrations the
  /// same name" must ask, and the only copy of the rule.
  ///
  /// [`Self::try_from_str`] canonicalises CASE but deliberately preserves the
  /// optional trailing root dot, which is not part of the name: `device.local`
  /// and `device.local.` are one owner, encode to the same wire bytes (see
  /// `write_canonical_wire_name`) and match the same records at routing time
  /// (`names_match_str` strips it before comparing labels). Derived
  /// `PartialEq`, and any `eq_ignore_ascii_case` over [`Self::as_str`], compare
  /// the STORED strings and so answer `false` for that pair — which is how one
  /// spelling registers past a guard and then collides on the wire anyway.
  ///
  /// Only ONE trailing dot is trimmed, because only one is representable:
  /// `validate_name` rejects the empty label a second dot would create. The
  /// case fold is belt-and-braces — both sides are already lowercase — and is
  /// kept so the answer does not depend on that invariant holding elsewhere.
  pub fn same_owner(&self, other: &Self) -> bool {
    fn trim(s: &str) -> &str {
      match s.strip_suffix('.') {
        Some(rest) => rest,
        None => s,
      }
    }
    trim(self.as_str()).eq_ignore_ascii_case(trim(other.as_str()))
  }

  /// Is `self` the immediate PARENT label sequence of `other` — does `other`
  /// consist of exactly one label followed by `self`?
  ///
  /// This is RFC 6763 §4.1's Service Instance Name structure,
  /// `<Instance> . <Service> . <Domain>`: §4.1.1 stores `<Instance>` "directly
  /// in the DNS as a single DNS label", so a well-formed instance name always
  /// has EXACTLY one label more than its `<Service>.<Domain>` service type —
  /// never zero (that would make them the same owner) and never two or more
  /// (that would need a multi-label `<Instance>`, which §4.1.1 does not
  /// allow). `self.is_parent_of(other)` asks exactly that: drop `other`'s
  /// first label, and ask whether what remains is the same owner as `self`.
  ///
  /// Case-insensitive per label and blind to the optional trailing root dot on
  /// either side, extending [`Self::same_owner`]'s rule from whole-name
  /// equality to this one-label-shorter suffix relation rather than
  /// duplicating it.
  pub fn is_parent_of(&self, other: &Self) -> bool {
    fn trim(s: &str) -> &str {
      match s.strip_suffix('.') {
        Some(rest) => rest,
        None => s,
      }
    }
    match trim(other.as_str()).split_once('.') {
      // `rest` is everything after `other`'s first label — for `self` to be
      // the immediate parent, that must be exactly `self`.
      Some((_first_label, rest)) => trim(self.as_str()).eq_ignore_ascii_case(rest),
      // `other` has only one label: no room for a parent above it.
      None => false,
    }
  }
}

impl core::fmt::Display for Name {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}
}

// Heap-backed construction: active for the `SmolStr` (alloc/std) and the
// no-atomic `Arc<str>` backings. Both build `NameInner` from an owned `String`
// (`std` is the `extern crate alloc as std` alias under `no-atomic`), so a
// single body serves both.
cfg_heap! {
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
}

#[cfg(all(test, any(feature = "alloc", feature = "std", feature = "no-atomic")))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

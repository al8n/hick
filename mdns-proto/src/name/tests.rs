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

/// The very first check in `validate_name` rejects any presentation string
/// longer than MAX_NAME_BYTES outright, before label splitting — distinct from
/// the wire-length accumulation path. A 256-byte input trips this guard and the
/// reported `NameTooLongDetail` carries the offending string length.
#[test]
#[cfg(any(feature = "alloc", feature = "std"))]
fn rejects_string_longer_than_max_name_bytes() {
  let over = "a".repeat(256);
  let err = Name::try_from_str(&over).unwrap_err();
  match err {
    NameError::NameTooLong(detail) => assert_eq!(detail.len(), 256),
    other => panic!("expected NameTooLong, got {other:?}"),
  }
}

#[test]
fn name_len_reports_byte_length() {
  let n = Name::try_from_str("foo.local.").unwrap();
  assert_eq!(n.len(), 10);
  assert_eq!(n.len(), n.as_str().len());
  // The empty name has zero length but is still a valid `Name`.
  let empty = Name::try_from_str("").unwrap();
  assert_eq!(empty.len(), 0);
}

/// `LabelTooLongDetail` is the payload of `NameError::LabelTooLong`; its `len()`
/// reports the rejected label's byte count and `is_empty()` is always false in
/// practice (a zero-length label is reported as `EmptyLabel`, not here).
#[test]
fn label_too_long_detail_accessors() {
  // A single label over MAX_LABEL_BYTES (63). Assert the detail reports the
  // literal's exact byte length rather than a hard-coded constant.
  let long = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 64 'a'
  assert_eq!(long.len(), 64);
  let err = Name::try_from_str(long).unwrap_err();
  match err {
    NameError::LabelTooLong(detail) => {
      assert_eq!(detail.len(), long.len());
      assert!(!detail.is_empty());
    }
    other => panic!("expected LabelTooLong, got {other:?}"),
  }
}

/// `NameTooLongDetail` is the payload of `NameError::NameTooLong`; its `len()`
/// reports the rejected name's byte count and `is_empty()` is always false in
/// practice (empty names pass validation).
#[test]
#[cfg(any(feature = "alloc", feature = "std"))]
fn name_too_long_detail_accessors() {
  // 63/63/63/62 = 251 + 3 dots = 254 string bytes → wire form = 256 octets,
  // exercising the wire-length accumulation path whose detail carries 256.
  let over_limit = std::format!(
    "{}.{}.{}.{}",
    "a".repeat(63),
    "a".repeat(63),
    "a".repeat(63),
    "a".repeat(62)
  );
  let err = Name::try_from_str(&over_limit).unwrap_err();
  match err {
    NameError::NameTooLong(detail) => {
      assert_eq!(detail.len(), 256);
      assert!(!detail.is_empty());
    }
    other => panic!("expected NameTooLong, got {other:?}"),
  }
}

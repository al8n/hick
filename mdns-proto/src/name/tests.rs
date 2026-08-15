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
  // Use a literal long label rather than `.repeat()` so the test stays
  // valid in a parse-only build with no allocator.
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

/// `Name` canonicalises case but PRESERVES the optional trailing root dot, so
/// derived `PartialEq` says `device.local` and `device.local.` are different —
/// while the wire encoder and the routing path both strip it and treat them as
/// one owner. `same_owner` is the equality that agrees with the wire.
#[test]
fn same_owner_ignores_the_optional_root_dot() {
  let dotted = Name::try_from_str("device.local.").unwrap();
  let bare = Name::try_from_str("device.local").unwrap();
  assert_ne!(dotted, bare, "the stored strings genuinely differ");
  assert!(dotted.same_owner(&bare));
  assert!(bare.same_owner(&dotted));
  assert!(dotted.same_owner(&dotted));

  // Case is already folded at construction; assert the comparison does not
  // depend on that holding.
  assert!(
    Name::try_from_str("DEVICE.LOCAL")
      .unwrap()
      .same_owner(&dotted)
  );

  // The root is spelled "" and ONLY "": `validate_name` rejects "." for the
  // empty label the trailing dot leaves behind, which is also why exactly one
  // dot is ever trimmable.
  assert!(matches!(
    Name::try_from_str("."),
    Err(NameError::EmptyLabel)
  ));
  let root = Name::try_from_str("").unwrap();
  assert!(root.same_owner(&root));
  assert!(!root.same_owner(&dotted));

  // A different name stays different, with or without the dot.
  let other = Name::try_from_str("other.local.").unwrap();
  assert!(!dotted.same_owner(&other));
  assert!(!bare.same_owner(&other));
  // …and a shorter name is not a prefix match.
  assert!(!dotted.same_owner(&Name::try_from_str("local.").unwrap()));
}

/// RFC 6763 §4.1: a Service Instance Name is
/// `<Instance> . <Service> . <Domain>`, and §4.1.1 stores `<Instance>` as a
/// SINGLE DNS label — so a service type is the parent of an instance only
/// when the instance has EXACTLY one label more, never zero and never two
/// or more.
#[test]
fn is_parent_of_requires_exactly_one_more_label() {
  let service_type = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let instance = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  assert!(service_type.is_parent_of(&instance));
  // Not symmetric: the child is not the parent of its own parent.
  assert!(!instance.is_parent_of(&service_type));
  // A name is not its own parent (zero extra labels).
  assert!(!service_type.is_parent_of(&service_type));
  // Two extra labels is not "the parent label sequence" — RFC 6763 §4.1.1
  // allows exactly one <Instance> label, not a multi-label prefix.
  let two_extra = Name::try_from_str("a.b._ipp._tcp.local.").unwrap();
  assert!(!service_type.is_parent_of(&two_extra));
  // An unrelated name, even with the right label count, is not a match.
  let unrelated = Name::try_from_str("MyPrinter._http._tcp.local.").unwrap();
  assert!(!service_type.is_parent_of(&unrelated));
}

/// The RFC 6762 §16 case-insensitivity and the optional trailing root dot
/// both apply to `is_parent_of` exactly as they do to [`Name::same_owner`] —
/// a caller must not be able to register past this guard with a spelling
/// that would collide with an already-accepted one on the wire.
#[test]
fn is_parent_of_ignores_case_and_the_optional_root_dot() {
  let lower = Name::try_from_str("_ipp._tcp.local.").unwrap();
  let upper = Name::try_from_str("_IPP._TCP.LOCAL.").unwrap();
  let instance = Name::try_from_str("MyPrinter._ipp._tcp.local.").unwrap();
  let instance_no_dot = Name::try_from_str("MyPrinter._ipp._tcp.local").unwrap();

  assert!(lower.is_parent_of(&instance));
  // Case-folded at construction, so this only proves the comparison itself
  // does not depend on that invariant (belt-and-braces, like `same_owner`).
  assert!(upper.is_parent_of(&instance));
  // A trailing root dot on either name, or neither, is the same owner.
  assert!(lower.is_parent_of(&instance_no_dot));
  let service_type_no_dot = Name::try_from_str("_ipp._tcp.local").unwrap();
  assert!(service_type_no_dot.is_parent_of(&instance));
  assert!(service_type_no_dot.is_parent_of(&instance_no_dot));
}

/// THE regression this predicate exists to fix: the DNS root genuinely is the
/// immediate parent of any single-label name — dropping that name's one
/// label leaves exactly the root. A naive `split_once('.') == None` read of
/// "other has no more labels" must not collapse this case into "no parent
/// exists" (see `nothing_is_the_parent_of_the_root`, which is the case that
/// reasoning is actually correct for).
#[test]
fn root_is_the_parent_of_a_single_label_name() {
  let root = Name::try_from_str("").unwrap();
  let local = Name::try_from_str("local").unwrap();
  assert!(root.is_parent_of(&local));
  // The child's optional trailing dot does not change the answer.
  let local_dot = Name::try_from_str("local.").unwrap();
  assert!(root.is_parent_of(&local_dot));
}

/// The root has zero labels, so — exactly like every other name
/// (`is_parent_of_requires_exactly_one_more_label`'s "a name is not its own
/// parent") — it is not its own parent: there is no label to drop to get
/// from the root back to the root.
#[test]
fn root_is_not_its_own_parent() {
  let root = Name::try_from_str("").unwrap();
  assert!(!root.is_parent_of(&root));
}

/// The root is the topmost owner: it has no label for any candidate parent
/// to have stripped, so nothing is ITS parent — not the root itself, not a
/// single-label name, not a multi-label one. `X.is_parent_of(root)` is
/// `false` for every `X`.
#[test]
fn nothing_is_the_parent_of_the_root() {
  let root = Name::try_from_str("").unwrap();
  let single = Name::try_from_str("local").unwrap();
  let multi = Name::try_from_str("_ipp._tcp.local.").unwrap();
  assert!(!root.is_parent_of(&root));
  assert!(!single.is_parent_of(&root));
  assert!(!multi.is_parent_of(&root));
}

/// Dropping a single-label `other`'s one label always leaves the root, so a
/// NON-root single-label `self` can never be the parent — whether `self` and
/// `other` are the same label or different ones. Only the root qualifies
/// (`root_is_the_parent_of_a_single_label_name`).
#[test]
fn a_single_label_name_is_not_the_parent_of_another_single_label_name() {
  let printer = Name::try_from_str("printer").unwrap();
  let scanner = Name::try_from_str("scanner").unwrap();
  assert!(!printer.is_parent_of(&scanner));
  assert!(!printer.is_parent_of(&printer));
}

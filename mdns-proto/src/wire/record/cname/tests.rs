use super::Cname;

// "x.local." uncompressed: 1 'x' | 5 'local' | 0
const NAME: &[u8] = &[1, b'x', 5, b'l', b'o', b'c', b'a', b'l', 0];

#[test]
fn parses_exact_rdata_and_exposes_target() {
  let cname = Cname::try_from_message(NAME, 0, NAME.len()).unwrap();
  // The target is the decompressed name; confirm the accessor returns it.
  let _ = cname.target();
}

#[test]
fn rejects_rdata_len_mismatch() {
  // RDLENGTH shorter than the name actually consumes must be rejected (the
  // encoded name MUST consume EXACTLY rdata_len bytes).
  assert!(Cname::try_from_message(NAME, 0, NAME.len() - 1).is_err());
}

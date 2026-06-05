use super::*;

// ── PTR parser respects rdata_len boundary ───────────────────

/// Inline name MUST fit within the declared RDLENGTH.  If a record
/// claims `rdlen=5` but the inline target is 20 bytes, the parser
/// MUST reject it — not silently consume bytes past the boundary
/// into the next record.
#[test]
fn ptr_rejects_inline_name_past_rdlength() {
  // label "abcde" (1-byte length + 5-byte label + 1-byte root = 7 bytes)
  let msg: [u8; 7] = [5, b'a', b'b', b'c', b'd', b'e', 0];
  // Honest parse with full rdata_len: succeeds.
  assert!(Ptr::try_from_message(&msg, 0, msg.len()).is_ok());
  // Truncated rdata_len: name doesn't fit, must reject.
  let err = Ptr::try_from_message(&msg, 0, 3).unwrap_err();
  assert!(
    err.is_buffer_too_short(),
    "PTR with inline name past rdlength must return BufferTooShort; got {err:?}"
  );
}

/// PTR RDATA must be EXACTLY one domain name — declaring an
/// `rdata_len` larger than the consumed name bytes (i.e. trailing
/// garbage inside the rdlength) must reject.  Accepting trailing
/// bytes would let a hostile peer canonicalize a malformed
/// known-answer that suppresses a legitimate outgoing record.
#[test]
fn ptr_rejects_trailing_bytes_inside_rdlength() {
  // 7-byte name; declare rdlen = 9 (2 bytes of trailing garbage).
  let msg: [u8; 9] = [5, b'a', b'b', b'c', b'd', b'e', 0, 0xAA, 0xBB];
  let err = Ptr::try_from_message(&msg, 0, 9).unwrap_err();
  assert!(
    err.is_buffer_too_short(),
    "PTR with trailing garbage inside rdlength must reject; got {err:?}"
  );
}

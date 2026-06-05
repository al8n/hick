use super::*;

// ── SRV parser respects rdata_len boundary ───────────────────

/// SRV header is 6 bytes (priority + weight + port).  rdata_len < 6
/// must reject.
#[test]
fn srv_rejects_rdata_shorter_than_header() {
  let msg = [0u8; 16];
  let err = Srv::try_from_message(&msg, 0, 4).unwrap_err();
  assert!(err.is_buffer_too_short());
}

/// Inline target name MUST fit within the declared `rdata_len`.  A
/// truncated rdata_len that doesn't cover the encoded name must yield
/// BufferTooShort.
#[test]
fn srv_rejects_inline_name_past_rdlength() {
  // 6-byte header (priority, weight, port) + 7-byte name = 13 bytes.
  let msg: [u8; 13] = [
    0, 0, 0, 0, 0, 80, // priority, weight, port
    5, b'a', b'b', b'c', b'd', b'e', 0, // name
  ];
  // Full rdata_len succeeds.
  assert!(Srv::try_from_message(&msg, 0, msg.len()).is_ok());
  // Truncated rdata_len just covers the header + 2 bytes of name → reject.
  let err = Srv::try_from_message(&msg, 0, 8).unwrap_err();
  assert!(
    err.is_buffer_too_short(),
    "SRV with inline name past rdlength must return BufferTooShort; got {err:?}"
  );
}

/// SRV RDATA is EXACTLY 6-byte header + one domain name.
/// Trailing bytes inside the declared rdlength must reject.
#[test]
fn srv_rejects_trailing_bytes_inside_rdlength() {
  // 6-byte header + 7-byte name + 2 bytes garbage = 15 bytes.
  let msg: [u8; 15] = [
    0, 0, 0, 0, 0, 80, // priority, weight, port
    5, b'a', b'b', b'c', b'd', b'e', 0, // name
    0xAA, 0xBB, // trailing garbage
  ];
  let err = Srv::try_from_message(&msg, 0, 15).unwrap_err();
  assert!(
    err.is_buffer_too_short(),
    "SRV with trailing garbage inside rdlength must reject; got {err:?}"
  );
}

/// `rdata_len` claims the 6-byte header, but the MESSAGE is too short to hold
/// it at `rdata_offset` — the fixed-header read must fail.
#[test]
fn srv_rejects_message_too_short_for_header() {
  let msg = [0u8; 4]; // fewer than the 6 header bytes are available
  let err = Srv::try_from_message(&msg, 0, 6).unwrap_err();
  assert!(err.is_buffer_too_short());
}

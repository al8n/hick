//! Compression-aware zero-copy DNS name reference.
//!
//! [`NameRef<'a>`] borrows into the full message buffer and iterates labels
//! via [`NameLabels<'a>`]. Pointer chains are bounded by
//! [`crate::constants::MAX_POINTER_HOPS`] and forward pointers (RFC 1035
//! §4.1.4 prohibits them) are rejected.

use crate::{
  constants::{MAX_LABEL_BYTES, MAX_NAME_BYTES, MAX_POINTER_HOPS},
  error::{BufferTooShortDetail, ParseError, PointerForwardDetail},
  name::LabelTooLongDetail,
};

const POINTER_TAG_MASK: u8 = 0b1100_0000;
const POINTER_TAG: u8 = 0b1100_0000;
const POINTER_OFFSET_HI_MASK: u8 = 0b0011_1111;

/// Zero-copy DNS name reference into a message buffer.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct NameRef<'a> {
  message: &'a [u8],
  start: u16,
}

impl<'a> NameRef<'a> {
  /// Parses a name starting at `offset` in `message`. Returns the `NameRef`
  /// and the number of bytes consumed at the *inline* position (i.e. how
  /// far to advance the parser past this name in the original section —
  /// not how long the fully-resolved name is).
  pub fn try_parse(message: &'a [u8], offset: usize) -> Result<(Self, usize), ParseError> {
    let mut cursor = offset;
    loop {
      let kind_byte = match message.get(cursor).copied() {
        Some(b) => b,
        None => {
          return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
            1, cursor, 0,
          )));
        }
      };

      if kind_byte == 0 {
        // Root label terminator.
        let consumed = cursor.saturating_sub(offset).saturating_add(1);
        let start = u16::try_from(offset)?;
        return Ok((Self { message, start }, consumed));
      }

      match kind_byte & POINTER_TAG_MASK {
        0 => {
          // Length-prefixed label.
          let len = kind_byte as usize;
          if kind_byte > MAX_LABEL_BYTES {
            return Err(ParseError::LabelTooLong(LabelTooLongDetail::new(len)));
          }
          let after_len = cursor.saturating_add(1);
          let label_end = after_len.saturating_add(len);
          if message.len() < label_end {
            return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
              len,
              after_len,
              message.len().saturating_sub(after_len),
            )));
          }
          cursor = label_end;
        }
        POINTER_TAG => {
          // Two-byte pointer. Consume them and return.
          let after_first = cursor.saturating_add(1);
          let _second = match message.get(after_first).copied() {
            Some(b) => b,
            None => {
              return Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
                1,
                after_first,
                0,
              )));
            }
          };
          let consumed = after_first.saturating_add(1).saturating_sub(offset);
          let start = u16::try_from(offset)?;
          return Ok((Self { message, start }, consumed));
        }
        _ => {
          return Err(ParseError::InvalidLabelKind(kind_byte));
        }
      }
    }
  }

  /// Returns an iterator over the labels of this name, following pointers
  /// with a bounded hop count.
  pub fn labels(&self) -> NameLabels<'a> {
    NameLabels {
      message: self.message,
      cursor: self.start,
      hops_remaining: MAX_POINTER_HOPS,
      wire_octets: 1, // the eventual root terminator
      done: false,
    }
  }

  /// Returns the byte offset at which this name begins in the message.
  #[inline(always)]
  pub const fn start(&self) -> u16 {
    self.start
  }

  /// Writes this name's labels in DNS wire form (`len`-octet + label bytes …,
  /// terminating root `0x00`), following any compression pointers so the
  /// result is SELF-CONTAINED — it no longer references the source message.
  ///
  /// When `fold_case` is true, ASCII label bytes are lowercased — the canonical
  /// case-insensitive form (RFC 6762 §16) used for record IDENTITY (cache
  /// dedup / TTL=0 removal / cache-flush). When false, case is preserved so a
  /// caller can surface the name for display.
  ///
  /// Enforces the RFC 1035 §3.1 limit: the *fully encoded* name (each length
  /// octet + its label bytes + the root terminator) must be ≤
  /// [`MAX_NAME_BYTES`]. The [`NameLabels`] iterator now bounds the EXPANDED
  /// wire length too, so an over-long name yields
  /// [`ParseError::NameTooLong`] from `label?` below; the redundant tally here
  /// is kept as defense-in-depth. Also errors if the label iterator is
  /// malformed (pointer cycle, forward pointer, or truncation).
  #[cfg(any(feature = "alloc", feature = "std"))]
  pub(crate) fn write_wire(
    &self,
    out: &mut alloc::vec::Vec<u8>,
    fold_case: bool,
  ) -> Result<(), crate::error::ParseError> {
    let mut encoded = 1usize; // the trailing root terminator
    for label in self.labels() {
      let label = label?;
      if label.is_empty() {
        break; // root; terminator appended below
      }
      let len = label.len().min(usize::from(MAX_LABEL_BYTES));
      encoded = encoded.saturating_add(1usize.saturating_add(len));
      if encoded > MAX_NAME_BYTES {
        return Err(crate::error::ParseError::NameTooLong(encoded));
      }
      #[allow(clippy::cast_possible_truncation)]
      out.push(len as u8);
      if fold_case {
        out.extend(
          label
            .iter()
            .take(usize::from(MAX_LABEL_BYTES))
            .map(u8::to_ascii_lowercase),
        );
      } else {
        out.extend(label.iter().take(usize::from(MAX_LABEL_BYTES)).copied());
      }
    }
    out.push(0);
    Ok(())
  }

  /// Compares two names case-insensitively (mDNS rule, RFC 6762 §16).
  pub fn equals_ignoring_case(&self, other: &NameRef<'_>) -> bool {
    let mut a = self.labels();
    let mut b = other.labels();
    loop {
      match (a.next(), b.next()) {
        (None, None) => return true,
        (Some(Ok(la)), Some(Ok(lb))) => {
          if la.len() != lb.len() {
            return false;
          }
          let mut i = 0usize;
          while i < la.len() {
            let ca = match la.get(i) {
              Some(c) => *c,
              None => return false,
            };
            let cb = match lb.get(i) {
              Some(c) => *c,
              None => return false,
            };
            if !ca.eq_ignore_ascii_case(&cb) {
              return false;
            }
            i = i.saturating_add(1);
          }
        }
        _ => return false,
      }
    }
  }
}

/// Iterator over labels of a [`NameRef`], yielding `Result<&[u8], ParseError>`.
pub struct NameLabels<'a> {
  message: &'a [u8],
  cursor: u16,
  hops_remaining: u8,
  /// accumulated EXPANDED wire length — the root terminator (seeded
  /// at 1) plus, per label, one length octet + the label payload. The RFC 1035
  /// §3.1 255-octet cap is on this expanded form, so counting full wire octets
  /// (not just label payload) makes EVERY consumer of `labels()` — including
  /// service canonicalization of peer names — reject an over-long name.
  wire_octets: usize,
  done: bool,
}

impl<'a> Iterator for NameLabels<'a> {
  type Item = Result<&'a [u8], ParseError>;

  #[allow(clippy::arithmetic_side_effects)]
  fn next(&mut self) -> Option<Self::Item> {
    if self.done {
      return None;
    }
    loop {
      let cursor_usize = self.cursor as usize;
      let kind_byte = match self.message.get(cursor_usize).copied() {
        Some(b) => b,
        None => {
          self.done = true;
          return Some(Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
            1,
            cursor_usize,
            0,
          ))));
        }
      };

      if kind_byte == 0 {
        self.done = true;
        return None;
      }

      match kind_byte & POINTER_TAG_MASK {
        0 => {
          let len = kind_byte as usize;
          if kind_byte > MAX_LABEL_BYTES {
            self.done = true;
            return Some(Err(ParseError::LabelTooLong(LabelTooLongDetail::new(len))));
          }
          let after_len = cursor_usize.saturating_add(1);
          let label_end = after_len.saturating_add(len);
          let label = match self.message.get(after_len..label_end) {
            Some(s) => s,
            None => {
              self.done = true;
              return Some(Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
                len,
                after_len,
                self.message.len().saturating_sub(after_len),
              ))));
            }
          };
          // Count the FULL wire length: this label's length octet + payload,
          // on top of the root octet seeded at construction.
          self.wire_octets = self.wire_octets.saturating_add(1usize.saturating_add(len));
          if self.wire_octets > MAX_NAME_BYTES {
            self.done = true;
            return Some(Err(ParseError::NameTooLong(self.wire_octets)));
          }
          let next_cursor_usize = label_end;
          self.cursor = match u16::try_from(next_cursor_usize) {
            Ok(v) => v,
            Err(e) => {
              self.done = true;
              return Some(Err(ParseError::IntegerConversion(e)));
            }
          };
          return Some(Ok(label));
        }
        POINTER_TAG => {
          if self.hops_remaining == 0 {
            self.done = true;
            return Some(Err(ParseError::PointerChainTooLong(MAX_POINTER_HOPS)));
          }
          self.hops_remaining = self.hops_remaining.saturating_sub(1);

          let after_first = cursor_usize.saturating_add(1);
          let second = match self.message.get(after_first).copied() {
            Some(b) => b,
            None => {
              self.done = true;
              return Some(Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
                1,
                after_first,
                0,
              ))));
            }
          };
          let hi = (kind_byte & POINTER_OFFSET_HI_MASK) as u16;
          let target = (hi << 8) | (second as u16);
          if target >= self.cursor {
            self.done = true;
            return Some(Err(ParseError::PointerForward(PointerForwardDetail::new(
              target,
              self.cursor,
            ))));
          }
          self.cursor = target;
          // Loop: resolve the new cursor as a fresh label.
        }
        _ => {
          self.done = true;
          return Some(Err(ParseError::InvalidLabelKind(kind_byte)));
        }
      }
    }
  }
}

#[cfg(test)]
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::{NameRef, ParseError};

  fn build_with_labels(labels: &[&[u8]]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut v = Vec::new();
    for l in labels {
      v.push(l.len() as u8);
      v.extend_from_slice(l);
    }
    v.push(0);
    v
  }

  #[test]
  fn parses_simple_name() {
    let buf = build_with_labels(&[b"foo", b"local"]);
    let (n, consumed) = NameRef::try_parse(&buf, 0).unwrap();
    assert_eq!(consumed, buf.len());
    let labels: alloc::vec::Vec<&[u8]> = n.labels().map(|r| r.unwrap()).collect();
    assert_eq!(labels, alloc::vec![b"foo".as_slice(), b"local".as_slice()]);
  }

  #[test]
  fn rejects_label_over_63() {
    let buf = [64u8]; // length byte = 64 > 63
    let err = NameRef::try_parse(&buf, 0).unwrap_err();
    assert!(matches!(
      err,
      ParseError::InvalidLabelKind(_) | ParseError::LabelTooLong(_)
    ));
  }

  #[test]
  fn labels_iteration_rejects_over_long_expanded_name() {
    // 128 one-byte labels = 257 expanded wire octets (each label is
    // 2 octets: a length byte + 1 payload byte, plus the root). Under the old
    // payload-only tally this summed to 128 and passed, but the EXPANDED wire
    // form exceeds the RFC 1035 §3.1 255-octet cap. try_parse is lazy (no total
    // cap), so the NameRef builds — but iterating labels() (as service
    // canonicalization does) MUST yield NameTooLong so an over-long peer name
    // cannot influence tiebreak / conflict handling.
    let labels: alloc::vec::Vec<&[u8]> = alloc::vec![b"a".as_slice(); 128];
    let buf = build_with_labels(&labels);
    assert_eq!(buf.len(), 257);
    let (n, _) = NameRef::try_parse(&buf, 0).unwrap();
    let mut saw_too_long = false;
    for r in n.labels() {
      if let Err(ParseError::NameTooLong(_)) = r {
        saw_too_long = true;
        break;
      }
    }
    assert!(
      saw_too_long,
      "labels() must reject a name whose expanded wire form exceeds 255 octets"
    );

    // A name at the boundary (wire form exactly 255 octets) iterates cleanly.
    // 126 one-byte labels + root = 126*2 + 1 = 253; add one 1-byte label = 255.
    let ok_labels: alloc::vec::Vec<&[u8]> = alloc::vec![b"a".as_slice(); 127];
    let ok_buf = build_with_labels(&ok_labels); // 127*2 + 1 = 255 octets
    assert_eq!(ok_buf.len(), 255);
    let (n2, _) = NameRef::try_parse(&ok_buf, 0).unwrap();
    assert!(
      n2.labels().all(|r| r.is_ok()),
      "a name whose expanded wire form is exactly 255 octets must iterate cleanly"
    );
  }

  #[test]
  fn rejects_forward_pointer() {
    // Pointer at offset 0 -> target offset 0 (== current cursor): forward.
    let buf = [0xC0u8, 0x00, 0];
    let (n, _) = NameRef::try_parse(&buf, 0).unwrap();
    let first = n.labels().next().unwrap();
    assert!(matches!(first, Err(ParseError::PointerForward(_))));
  }

  #[test]
  fn pointer_resolves_backwards() {
    // Layout:
    //   offset 0: "ab\0"   (3 bytes: 0x02 'a' 'b' 0x00, total 4)
    //   offset 4: pointer to 0
    let mut buf = alloc::vec::Vec::new();
    buf.push(2u8);
    buf.extend_from_slice(b"ab");
    buf.push(0);
    buf.push(0xC0);
    buf.push(0x00);
    let (n, _) = NameRef::try_parse(&buf, 4).unwrap();
    let labels: alloc::vec::Vec<&[u8]> = n.labels().map(|r| r.unwrap()).collect();
    assert_eq!(labels, alloc::vec![b"ab".as_slice()]);
  }

  #[test]
  fn equality_ignoring_case() {
    let buf1 = build_with_labels(&[b"Foo", b"Local"]);
    let buf2 = build_with_labels(&[b"foo", b"LOCAL"]);
    let n1 = NameRef::try_parse(&buf1, 0).unwrap().0;
    let n2 = NameRef::try_parse(&buf2, 0).unwrap().0;
    assert!(n1.equals_ignoring_case(&n2));
  }
}

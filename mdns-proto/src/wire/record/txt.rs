//! TXT record (key=value text segments, RFC 1035 §3.3.14 + RFC 6763 §6).

use crate::error::{BufferTooShortDetail, ParseError};

/// Parsed TXT record rdata. Provides iteration over `(key, value)` segments
/// without copying.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TxtRecord<'a> {
  rdata: &'a [u8],
}

impl<'a> TxtRecord<'a> {
  /// Wraps a slice of TXT rdata.
  pub const fn from_rdata(rdata: &'a [u8]) -> Self {
    Self { rdata }
  }

  /// Iterates over the length-prefixed segments of this TXT record, yielding
  /// each as a raw `&[u8]` (key=value or boolean key per RFC 6763 §6.4).
  pub fn segments(&self) -> TxtSegments<'a> {
    TxtSegments { rest: self.rdata }
  }
}

/// Iterator over TXT segments.
pub struct TxtSegments<'a> {
  rest: &'a [u8],
}

impl<'a> Iterator for TxtSegments<'a> {
  type Item = Result<&'a [u8], ParseError>;

  fn next(&mut self) -> Option<Self::Item> {
    let &len_byte = self.rest.first()?;
    let len = len_byte as usize;
    let after_len = match self.rest.get(1..) {
      Some(s) => s,
      None => {
        self.rest = &[];
        return Some(Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
          1, 0, 0,
        ))));
      }
    };
    let (segment, rest) = match after_len.split_at_checked(len) {
      Some(pair) => pair,
      None => {
        self.rest = &[];
        return Some(Err(ParseError::BufferTooShort(BufferTooShortDetail::new(
          len,
          0,
          after_len.len(),
        ))));
      }
    };
    self.rest = rest;
    Some(Ok(segment))
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
  use super::TxtRecord;

  #[test]
  fn iterates_segments() {
    // "key=val" (7) + "x" (1) + "" (0)
    let rdata: [u8; 11] = [7, b'k', b'e', b'y', b'=', b'v', b'a', b'l', 1, b'x', 0];
    let txt = TxtRecord::from_rdata(&rdata);
    let mut it = txt.segments();
    assert_eq!(it.next().unwrap().unwrap(), b"key=val".as_slice());
    assert_eq!(it.next().unwrap().unwrap(), b"x".as_slice());
    assert_eq!(it.next().unwrap().unwrap(), b"".as_slice());
    assert!(it.next().is_none());
  }

  #[test]
  fn rejects_short_segment() {
    let rdata: [u8; 3] = [10, b'a', b'b']; // claims 10 bytes, only 2 follow
    let txt = TxtRecord::from_rdata(&rdata);
    let err = txt.segments().next().unwrap().unwrap_err();
    assert!(err.is_buffer_too_short());
  }
}

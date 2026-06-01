//! Lazy section-iterator view over a parsed mDNS message.

use super::{HEADER_SIZE, Header, QuestionRef, Ref};
use crate::error::ParseError;

/// Borrowed view over a parsed mDNS message. Lazy iteration; nothing is
/// allocated.
#[derive(Debug, Copy, Clone)]
pub struct MessageReader<'a> {
  message: &'a [u8],
  header: Header,
}

impl<'a> MessageReader<'a> {
  /// Parses just the header; sections are walked on demand via the
  /// iterator methods.
  pub fn try_parse(message: &'a [u8]) -> Result<Self, ParseError> {
    let (header, _rest) = Header::try_parse(message)?;
    Ok(Self { message, header })
  }

  /// Returns the parsed header.
  #[inline(always)]
  pub const fn header(&self) -> &Header {
    &self.header
  }

  /// Iterator over the question section.
  pub fn questions(&self) -> Questions<'a> {
    Questions {
      message: self.message,
      cursor: HEADER_SIZE,
      remaining: self.header.question_count(),
    }
  }

  /// Iterator over the answer section.
  pub fn answers(&self) -> Records<'a> {
    Records::new_after_questions(self.message, &self.header, self.header.answer_count())
  }

  /// Iterator over the authority section (NS records, used in mDNS probes).
  /// Walks past the questions and answer sections to locate authority records.
  pub fn authority(&self) -> Records<'a> {
    Records::new_after_answers(self.message, &self.header, self.header.authority_count())
  }

  /// Iterator over the additional section. Standard DNS-SD responders place
  /// the SRV/TXT/A/AAAA records that accompany a PTR answer here (RFC 6763
  /// §12), so a querier MUST process them to complete discovery. Walks past
  /// the questions, answer, and authority sections.
  pub fn additional(&self) -> Records<'a> {
    Records::new_after_authority(self.message, &self.header, self.header.additional_count())
  }
}

/// Iterator over `QuestionRef`s in the question section.
pub struct Questions<'a> {
  message: &'a [u8],
  cursor: usize,
  remaining: u16,
}

impl<'a> Iterator for Questions<'a> {
  type Item = Result<QuestionRef<'a>, ParseError>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.remaining == 0 {
      return None;
    }
    match QuestionRef::try_parse(self.message, self.cursor) {
      Ok((q, next)) => {
        self.cursor = next;
        self.remaining = self.remaining.saturating_sub(1);
        Some(Ok(q))
      }
      Err(e) => {
        self.remaining = 0;
        Some(Err(e))
      }
    }
  }
}

/// Iterator over `Ref`s in a non-question section.
pub struct Records<'a> {
  message: &'a [u8],
  cursor: usize,
  remaining: u16,
}

/// Skip the question section, returning the cursor at the start of the answer
/// section, or `None` if any question fails to parse — a malformed earlier
/// section means later sections cannot be reliably located.
fn skip_questions(message: &[u8], header: &Header) -> Option<usize> {
  let mut cursor = HEADER_SIZE;
  let mut remaining = header.question_count();
  while remaining > 0 {
    let (_, next) = QuestionRef::try_parse(message, cursor).ok()?;
    cursor = next;
    remaining = remaining.saturating_sub(1);
  }
  Some(cursor)
}

/// Skip `count` resource records starting at `cursor`, returning the cursor
/// after them, or `None` if any record fails to parse.
fn skip_records(message: &[u8], mut cursor: usize, mut count: u16) -> Option<usize> {
  while count > 0 {
    let (_, next) = Ref::try_parse(message, cursor).ok()?;
    cursor = next;
    count = count.saturating_sub(1);
  }
  Some(cursor)
}

impl<'a> Records<'a> {
  /// Position at the answer section (after the questions). Used by
  /// `MessageReader::answers()`.
  fn new_after_questions(message: &'a [u8], header: &Header, count: u16) -> Self {
    Self::at_or_empty(message, count, skip_questions(message, header))
  }

  /// Position at the authority section (after questions + answers). Used by
  /// `MessageReader::authority()`.
  fn new_after_answers(message: &'a [u8], header: &Header, count: u16) -> Self {
    let cursor =
      skip_questions(message, header).and_then(|c| skip_records(message, c, header.answer_count()));
    Self::at_or_empty(message, count, cursor)
  }

  /// Position at the additional section (after questions + answers +
  /// authority). Used by `MessageReader::additional()`.
  fn new_after_authority(message: &'a [u8], header: &Header, count: u16) -> Self {
    let cursor = skip_questions(message, header)
      .and_then(|c| skip_records(message, c, header.answer_count()))
      .and_then(|c| skip_records(message, c, header.authority_count()));
    Self::at_or_empty(message, count, cursor)
  }

  /// Build a `Records` iterator at `cursor` with `count` records, or an EMPTY
  /// iterator when `cursor` is `None` (a preceding section could not
  /// be cleanly skipped, so the cursor is unreliable — surface no records from
  /// a misaligned offset rather than parsing garbage).
  fn at_or_empty(message: &'a [u8], count: u16, cursor: Option<usize>) -> Self {
    match cursor {
      Some(cursor) => Self {
        message,
        cursor,
        remaining: count,
      },
      None => Self {
        message,
        cursor: HEADER_SIZE,
        remaining: 0,
      },
    }
  }
}

impl<'a> Iterator for Records<'a> {
  type Item = Result<Ref<'a>, ParseError>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.remaining == 0 {
      return None;
    }
    match Ref::try_parse(self.message, self.cursor) {
      Ok((r, next)) => {
        self.cursor = next;
        self.remaining = self.remaining.saturating_sub(1);
        Some(Ok(r))
      }
      Err(e) => {
        self.remaining = 0;
        Some(Err(e))
      }
    }
  }
}

#[cfg(all(test, any(feature = "alloc", feature = "std")))]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::panic,
  clippy::indexing_slicing,
  clippy::arithmetic_side_effects
)]
mod tests {
  use super::*;

  /// Build a 12-byte header with the given section counts.
  fn header(qd: u16, an: u16, ns: u16, ar: u16) -> std::vec::Vec<u8> {
    let mut h = std::vec![0u8; HEADER_SIZE];
    h[4..6].copy_from_slice(&qd.to_be_bytes());
    h[6..8].copy_from_slice(&an.to_be_bytes());
    h[8..10].copy_from_slice(&ns.to_be_bytes());
    h[10..12].copy_from_slice(&ar.to_be_bytes());
    h
  }

  #[test]
  fn malformed_question_surfaces_no_authority_or_additional() {
    // QDCOUNT=1 with a truncated question name, plus NSCOUNT=1 and
    // ARCOUNT=1. The question cannot be skipped, so the authority/additional
    // offsets are unknown — NO record may be surfaced from a misaligned cursor.
    let mut msg = header(1, 0, 1, 1);
    msg.push(0x05); // label length 5 with no following bytes => truncated name
    let reader = MessageReader::try_parse(&msg).unwrap();
    assert!(
      reader.authority().next().is_none(),
      "malformed question must surface no authority records"
    );
    assert!(
      reader.additional().next().is_none(),
      "malformed question must surface no additional records"
    );
  }

  #[test]
  fn malformed_answer_surfaces_no_additional() {
    // a well-formed question but a malformed answer (ANCOUNT=1),
    // with ARCOUNT=1. The answer cannot be skipped, so additional iteration
    // must not surface records parsed from the misaligned offset — previously
    // `new_after_authority` ignored the answer-skip failure and walked from the
    // stale cursor.
    let mut msg = header(1, 1, 0, 1);
    // Valid question: root name (0x00) + QTYPE A (0x0001) + QCLASS IN (0x0001).
    msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    // Malformed answer: label length 5 with no following bytes (truncated).
    msg.push(0x05);
    let reader = MessageReader::try_parse(&msg).unwrap();
    // The question itself is still well-formed and iterates.
    assert_eq!(
      reader
        .questions()
        .filter(core::result::Result::is_ok)
        .count(),
      1,
      "the well-formed question must still parse"
    );
    assert!(
      reader.additional().next().is_none(),
      "malformed answer must surface no additional records"
    );
  }

  #[test]
  fn well_formed_additional_is_still_surfaced() {
    // Positive control: a message with a valid question + a valid additional A
    // record (ANCOUNT=0, NSCOUNT=0, ARCOUNT=1) must surface the additional.
    let mut msg = header(1, 0, 0, 1);
    // Question: root name + QTYPE A + QCLASS IN.
    msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    // Additional A record: root name + TYPE A + CLASS IN + TTL + RDLEN 4 + addr.
    msg.extend_from_slice(&[0x00]); // owner name = root
    msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    msg.extend_from_slice(&120u32.to_be_bytes()); // TTL
    msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    msg.extend_from_slice(&[192, 168, 1, 10]); // rdata
    let reader = MessageReader::try_parse(&msg).unwrap();
    let mut it = reader.additional();
    let first = it
      .next()
      .expect("a valid additional record must be surfaced");
    assert!(first.is_ok(), "the additional record must parse");
    assert!(it.next().is_none(), "exactly one additional record");
  }

  #[test]
  fn questions_iterator_yields_error_then_stops_on_truncated_question() {
    // QDCOUNT=1 with a truncated question name (label length 5, no payload).
    let mut msg = header(1, 0, 0, 0);
    msg.push(0x05);
    let reader = MessageReader::try_parse(&msg).unwrap();
    let mut questions = reader.questions();
    assert!(
      matches!(questions.next(), Some(Err(_))),
      "a truncated question must surface a parse error"
    );
    // After the error the iterator latches done and yields nothing further.
    assert!(questions.next().is_none());
  }
}

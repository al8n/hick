//! mDNS wire format — panic-free, no_alloc-capable parser and encoder.
//!
//! Replaces the unmaintained `dns-protocol` crate. Parsing is zero-copy where
//! practical (`NameRef<'a>` borrows into the input datagram); encoding writes
//! into a caller-supplied `&mut [u8]` with a bounded compression table.

// Submodules and re-exports are added incrementally by tasks 3-15 of the
// wire plan. Each task appends its `mod x;` line and one `pub use` line.

mod opcode;
pub use opcode::Opcode;

mod resource_class;
mod resource_type;
mod response_code;

pub use resource_class::{CACHE_FLUSH_BIT, ResourceClass, UNICAST_RESPONSE_BIT};
pub use resource_type::ResourceType;
pub use response_code::ResponseCode;

mod flags;
pub use flags::Flags;

mod header;
pub use header::{HEADER_SIZE, Header};

mod name;
pub use name::{NameLabels, NameRef};

mod question;
pub use question::QuestionRef;

mod record;
pub use record::{ARecord, AaaaRecord, PtrRecord, RecordRdata, RecordRef, SrvRecord, TxtRecord};

mod reader;
pub use reader::{MessageReader, Questions, Records};

mod builder;
#[cfg(any(feature = "alloc", feature = "std", feature = "heapless"))]
#[cfg_attr(
  docsrs,
  doc(cfg(any(feature = "alloc", feature = "std", feature = "heapless")))
)]
pub use builder::{CompressionTable, DEFAULT_COMPRESSION_TABLE, MessageBuilder};

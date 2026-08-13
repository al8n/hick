//! mDNS wire format — panic-free, no_alloc-capable parser and encoder.
//!
//! Replaces the unmaintained `dns-protocol` crate. Parsing is zero-copy where
//! practical (`NameRef<'a>` borrows into the input datagram); encoding writes
//! into a caller-supplied `&mut [u8]` with a bounded compression table.

// Each wire submodule is declared below with its `mod x;` line and a matching
// `pub use` re-export.

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
pub use record::{A, AAAA, Ptr, Rdata, Ref, Srv, Txt};
cfg_heap! {
  pub(crate) use record::rdata_is_position_independent;
}

mod reader;
pub use reader::{MessageReader, Questions, Records};

mod builder;
cfg_heap! {
  pub use builder::{BuilderCheckpoint, CompressionTable, DEFAULT_COMPRESSION_TABLE, MessageBuilder};
}

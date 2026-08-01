use hick_udp::BindError;
use mdns_proto::{Name, error::RegisterServiceError as ProtoRegisterError};

use super::{RegisterError, ServerError, StartQueryError, TickError};

#[test]
fn server_error_display_mentions_subject() {
  let no_family = ServerError::NoFamilyEnabled;
  assert!(!no_family.to_string().is_empty());
  assert!(no_family.to_string().contains("IPv4"));

  let bind_v4 = ServerError::BindV4(BindError::Io(std::io::Error::other("v4 boom")));
  assert!(bind_v4.to_string().contains("bind v4"));
  assert!(bind_v4.to_string().contains("v4 boom"));

  let bind_v6 = ServerError::BindV6(BindError::Io(std::io::Error::other("v6 boom")));
  assert!(bind_v6.to_string().contains("bind v6"));
  assert!(bind_v6.to_string().contains("v6 boom"));
}

#[test]
fn server_error_io_from_conversion() {
  let err: ServerError = std::io::Error::other("disk on fire").into();
  assert!(matches!(err, ServerError::Io(_)));
  assert!(err.to_string().contains("disk on fire"));
}

#[test]
fn register_error_display_mentions_subject() {
  let name = Name::try_from_str("dup._http._tcp.local.").unwrap();
  let dup = RegisterError::NameAlreadyRegistered(name.clone());
  assert!(dup.to_string().contains(name.as_str()));

  let full = RegisterError::StorageFull;
  assert_eq!(full.to_string(), "service pool is full");

  let closing = RegisterError::ShuttingDown;
  assert_eq!(closing.to_string(), "the endpoint is shutting down");
}

#[test]
fn register_error_from_proto_name_already_registered() {
  let name = Name::try_from_str("dup._http._tcp.local.").unwrap();
  let proto_err = ProtoRegisterError::NameAlreadyRegistered(name.clone());
  let err: RegisterError = proto_err.into();
  assert!(matches!(err, RegisterError::NameAlreadyRegistered(n) if n == name));
}

// The conversion's other arm, `ProtoRegisterError::StorageFull(_) => Self::StorageFull`,
// can't get an equivalent round-trip test: its payload
// (`mdns_proto::error::StorageFullError`) is a `#[non_exhaustive]` unit struct with no
// public constructor, so it cannot be built from outside `mdns-proto`.
// `RegisterError::StorageFull`'s own `Display` is still covered above, and
// `StartQueryError::StorageFull` (a separate type with the same message shape) below.
#[test]
fn start_query_error_display_mentions_subject() {
  let full = StartQueryError::StorageFull;
  assert_eq!(full.to_string(), "query pool is full");
}

#[test]
fn tick_error_io_from_conversion() {
  let err: TickError = std::io::Error::other("tick failed").into();
  assert!(matches!(err, TickError::Io(_)));
  assert!(err.to_string().contains("tick failed"));
}

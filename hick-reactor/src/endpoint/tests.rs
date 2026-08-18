use super::{map_join_to_bind_v4, map_join_to_bind_v6};
use crate::error::ServerError;

/// A join I/O failure is surfaced as the matching family's bind I/O error —
/// the driver reports a failed multicast join as a bind failure.
#[test]
fn join_io_error_maps_to_family_bind_io_error() {
  let v4 = map_join_to_bind_v4(std::io::Error::other("boom").into());
  assert!(matches!(
    v4,
    ServerError::BindV4(hick_udp::BindError::Io(_))
  ));
  let v6 = map_join_to_bind_v6(std::io::Error::other("boom").into());
  assert!(matches!(
    v6,
    ServerError::BindV6(hick_udp::BindError::Io(_))
  ));
}

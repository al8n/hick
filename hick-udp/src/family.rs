use std::net::SocketAddr;

/// Which of the two address families a socket, an operation, or a datagram
/// belongs to.
///
/// An mDNS endpoint binds one socket per family and sends the same body to both
/// groups, so "which family" is what separates two otherwise identical
/// operations — and, on the receive side, the only thing that says which socket
/// a datagram could have arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
  /// IPv4.
  V4,
  /// IPv6.
  V6,
}

impl Family {
  /// The family a destination address belongs to.
  #[must_use]
  pub const fn of(dst: SocketAddr) -> Self {
    match dst {
      SocketAddr::V4(_) => Self::V4,
      SocketAddr::V6(_) => Self::V6,
    }
  }

  /// `via_v4` in the shape a receive path and its trace fields want.
  #[must_use]
  pub const fn is_v4(self) -> bool {
    matches!(self, Self::V4)
  }

  /// This family's index in a per-family array: IPv4 first, IPv6 second.
  ///
  /// Stated here once so that every per-family array a caller builds — and every
  /// per-family result it is indexed against — agrees on the order rather than
  /// each site picking its own.
  #[must_use]
  pub const fn index(self) -> usize {
    match self {
      Self::V4 => 0,
      Self::V6 => 1,
    }
  }

  /// The family this one is not.
  #[must_use]
  pub const fn other(self) -> Self {
    match self {
      Self::V4 => Self::V6,
      Self::V6 => Self::V4,
    }
  }
}

#[cfg(test)]
mod tests;

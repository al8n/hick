//! Sync convenience wrappers for callers who don't need async.

use std::net::{SocketAddr, UdpSocket};

use crate::{
  error::{BindError, JoinError},
  multicast::{
    MulticastOptionsV4, MulticastOptionsV6, try_bind_v4, try_bind_v6, try_join_v4, try_join_v6,
  },
};

/// Sync IPv4 multicast socket with mDNS-appropriate options baked in.
pub struct MulticastSocketV4 {
  socket: UdpSocket,
}

impl MulticastSocketV4 {
  /// Bind a new socket and join the mDNS group on the interface specified
  /// by `opts.interface_index()`.
  pub fn try_new(opts: MulticastOptionsV4) -> Result<Self, BindError> {
    let idx = opts.interface_index();
    let socket = try_bind_v4(opts)?;
    try_join_v4(&socket, idx).map_err(|e| match e {
      JoinError::Io(e) => BindError::Io(e),
      JoinError::InterfaceNotFound(d) => BindError::InterfaceNotFound(d),
    })?;
    Ok(Self { socket })
  }

  /// Underlying socket (for direct send/recv).
  #[inline(always)]
  pub const fn socket(&self) -> &UdpSocket {
    &self.socket
  }

  /// Local address bound to.
  pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
    self.socket.local_addr()
  }
}

/// Sync IPv6 multicast socket.
pub struct MulticastSocketV6 {
  socket: UdpSocket,
}

impl MulticastSocketV6 {
  /// Bind a new socket and join the mDNS group on the interface specified
  /// by `opts.interface_index()`.
  pub fn try_new(opts: MulticastOptionsV6) -> Result<Self, BindError> {
    let idx = opts.interface_index();
    let socket = try_bind_v6(opts)?;
    try_join_v6(&socket, idx).map_err(|e| match e {
      JoinError::Io(e) => BindError::Io(e),
      JoinError::InterfaceNotFound(d) => BindError::InterfaceNotFound(d),
    })?;
    Ok(Self { socket })
  }

  /// Underlying socket (for direct send/recv).
  #[inline(always)]
  pub const fn socket(&self) -> &UdpSocket {
    &self.socket
  }

  /// Local address bound to.
  pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
    self.socket.local_addr()
  }
}

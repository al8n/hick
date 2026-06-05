//! RFC 6762 §11 on-link checks.

use core::net::IpAddr;

/// TTL / IPv6 Hop Limit is exactly 255 (anything less crossed a router).
/// When no cmsg was delivered we conservatively treat the datagram as on-link
/// and let the source-address fallback ([`src_on_local_link`]) decide.
#[inline]
pub(crate) fn is_on_link(hop_limit: Option<u8>) -> bool {
  hop_limit.is_none_or(|h| h == 255)
}

/// Source-address fallback for the §11 on-link gate, used when the kernel did
/// not deliver an IPv4 TTL / IPv6 hop-limit cmsg. Loopback is always on-link,
/// link-local sources must match the bound interface (or arrive with no
/// `recv_iface` hint), and globally-routable sources are accepted only if
/// they fall inside one of the cached `local_subnets`.
///
/// Fail-closed for global sources: a routable source with no matching subnet —
/// including the case where subnet enumeration yielded nothing — is treated as
/// off-link and dropped, per §11. We never admit a global source on no
/// evidence that it originated on the local link.
pub(crate) fn src_on_local_link(
  local_subnets: &[(IpAddr, u8)],
  bound_iface: u32,
  recv_iface: u32,
  src: IpAddr,
) -> bool {
  let (is_loopback, is_link_local) = match src {
    IpAddr::V4(v4) => (v4.is_loopback(), v4.is_link_local()),
    IpAddr::V6(v6) => (v6.is_loopback(), (v6.segments()[0] & 0xffc0) == 0xfe80),
  };
  if is_loopback {
    return true;
  }
  if is_link_local {
    return recv_iface == 0 || recv_iface == bound_iface;
  }
  // Global source: admit only with positive on-link evidence. An empty
  // `local_subnets` makes `any` return `false` (fail-closed) — see §11.
  local_subnets
    .iter()
    .any(|&(net, p)| addr_in_subnet(net, p, src))
}

/// `addr ∈ net/prefix` with a bit-mask compare. Mixed v4/v6 pairs are always
/// `false`. A `prefix` of zero matches every address of the matching family.
pub(crate) fn addr_in_subnet(net: IpAddr, prefix: u8, addr: IpAddr) -> bool {
  match (net, addr) {
    (IpAddr::V4(n), IpAddr::V4(a)) => {
      let p = prefix.min(32);
      if p == 0 {
        return true;
      }
      let mask: u32 = u32::MAX.checked_shl(32 - u32::from(p)).unwrap_or(0);
      (u32::from(n) & mask) == (u32::from(a) & mask)
    }
    (IpAddr::V6(n), IpAddr::V6(a)) => {
      let p = prefix.min(128);
      if p == 0 {
        return true;
      }
      let mask: u128 = u128::MAX.checked_shl(128 - u32::from(p)).unwrap_or(0);
      (u128::from(n) & mask) == (u128::from(a) & mask)
    }
    _ => false,
  }
}

#[cfg(test)]
mod tests;

//! Bridge the `embassy-time` clock to the [`mdns_proto::Instant`] trait.

use core::time::Duration;

use embassy_time::{Duration as EmbassyDuration, Instant as RawInstant};
use mdns_proto::Instant as ProtoInstant;

/// An [`embassy_time::Instant`] that implements [`mdns_proto::Instant`].
///
/// `embassy_time::Instant` and the `mdns_proto::Instant` trait are both foreign
/// here, so the orphan rule requires a newtype. The driver wraps each
/// `Instant::now()` reading; the engine is generic over the trait, so this is
/// the `I` type for the embassy path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EmbassyInstant(pub RawInstant);

impl From<RawInstant> for EmbassyInstant {
  #[inline(always)]
  fn from(raw: RawInstant) -> Self {
    Self(raw)
  }
}

impl From<EmbassyInstant> for RawInstant {
  #[inline(always)]
  fn from(wrapped: EmbassyInstant) -> Self {
    wrapped.0
  }
}

/// Read the `embassy-time` clock as an [`mdns_proto::Instant`].
///
/// This is the function both entry points hand to `Engine::pump` AS the clock —
/// not a value sampled ahead of the call. The pump reads it once for the pass and
/// again after each RFC 6762 §10.1 goodbye fan-out, so the goodbye resend spacing
/// is measured from when the socket ACCEPTED the datagram rather than from when
/// the loop iteration started; a pre-sampled instant would charge the pass's own
/// work to the next goodbye.
///
/// Acceptance is where the measurement stops: embassy-net queues the datagram and
/// its network task puts it on the device afterwards, so the spacing this buys is
/// between enqueues (`hick_smoltcp::UdpIo::try_send` says what that does and does
/// not bound).
pub(crate) fn now() -> EmbassyInstant {
  EmbassyInstant(RawInstant::now())
}

impl ProtoInstant for EmbassyInstant {
  #[inline]
  fn checked_add_duration(self, dur: Duration) -> Option<Self> {
    let micros = u64::try_from(dur.as_micros()).ok()?;
    self
      .0
      .checked_add(EmbassyDuration::from_micros(micros))
      .map(Self)
  }

  #[inline]
  fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
    let delta = self.0.checked_duration_since(earlier.0)?;
    Some(Duration::from_micros(delta.as_micros()))
  }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

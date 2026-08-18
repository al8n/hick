//! Tracing-or-noop diagnostic macro shim and backend-agnostic stats/metrics
//! primitives for the hick mDNS stack.
//!
//! # Macros
//!
//! The five macros `trace!`, `debug!`, `info!`, `warn!`, and `error!` are
//! always available as `hick_trace::<name>!(...)`. When the `tracing` Cargo
//! feature is enabled they delegate to the real [`tracing`] crate; otherwise
//! they discard every argument without emitting code.
//!
//! # `stats` / `metrics` feature
//!
//! Enabling `stats` unlocks [`stats::Stats`] and [`stats::StatsSnapshot`]: a
//! set of atomic counters and gauges that are `no_std`-safe. Enabling
//! `metrics` additionally forwards every counter/gauge update to the
//! [`metrics`] facade (requires `std`).

#![cfg_attr(not(feature = "metrics"), no_std)]

// ── Tracing shim ────────────────────────────────────────────────────────────

#[cfg(feature = "tracing")]
pub use tracing::{debug, debug_span, error, info, info_span, trace, trace_span, warn};

/// Token-consuming no-op for all five diagnostic macros when `tracing` is
/// disabled. Every argument expression is type-checked but **never executed**:
/// each value is referenced inside an `if false { }` block, which the compiler
/// eliminates entirely while still seeing the expression as "used" (no
/// `unused_variables` warning, no side effects, no alloc, no panics).
///
/// # Supported forms
///
/// | Form | Example |
/// |------|---------|
/// | Positional format string | `debug!("n={}", n)` |
/// | `key = value` | `debug!(x = val, "msg")` |
/// | `key = %value` (Display) | `debug!(x = %val, "msg")` |
/// | `key = ?value` (Debug) | `debug!(x = ?val, "msg")` |
/// | Bare `%value` / `?value` | `debug!(%val)` |
/// | Bare `ident` shorthand | `debug!(x, "msg")` |
/// | `target: "t", ...` prefix | `debug!(target: "t", x = 1, "m")` |
///
/// # Unsupported forms
///
/// The following `tracing` forms are deliberately **not** supported:
/// `name: "..."`, `parent: span`, dotted field names (`a.b`), and
/// string-literal field keys (`"k" = v`). The codebase stays within the
/// subset above; any violation is caught as a compile error in the default
/// (no-tracing) build.
///
/// # Implementation note
///
/// Each value expression `$val` expands to `if false { let _ = &$val; }`.
/// The compiler eliminates the dead branch during MIR building, so there is
/// zero runtime cost. A plain `let _ = &$val;` (the previous approach)
/// evaluated the expression to produce the reference even though it was
/// discarded, causing side effects (allocs, panics, counter bumps) to run
/// in disabled builds.
#[doc(hidden)]
#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! __hick_trace_noop {
  (target: $tgt:expr, $($rest:tt)*) => {
    { if false { let _ = &$tgt; } $crate::__hick_trace_noop!($($rest)*) }
  };

  ($key:ident = %$val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__hick_trace_noop!($($rest)*) }
  };
  ($key:ident = %$val:expr) => {
    { if false { let _ = &$val; } }
  };

  ($key:ident = ?$val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__hick_trace_noop!($($rest)*) }
  };
  ($key:ident = ?$val:expr) => {
    { if false { let _ = &$val; } }
  };

  ($key:ident = $val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__hick_trace_noop!($($rest)*) }
  };
  ($key:ident = $val:expr) => {
    { if false { let _ = &$val; } }
  };

  // Matches BEFORE the format-string literal arm so that a bare ident that
  // is NOT a string literal is consumed correctly.
  ($key:ident, $($rest:tt)*) => {
    { if false { let _ = &$key; } $crate::__hick_trace_noop!($($rest)*) }
  };
  ($key:ident) => {
    { if false { let _ = &$key; } }
  };

  // ── Bare `%value` ────────────────────────────────────────────────────────
  (%$val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__hick_trace_noop!($($rest)*) }
  };
  (%$val:expr) => {
    { if false { let _ = &$val; } }
  };

  (?$val:expr, $($rest:tt)*) => {
    { if false { let _ = &$val; } $crate::__hick_trace_noop!($($rest)*) }
  };
  (?$val:expr) => {
    { if false { let _ = &$val; } }
  };

  ($fmt:literal $(, $arg:expr)* $(,)?) => {
    { if false { let _ = ::core::format_args!($fmt $(, $arg)*); } }
  };

  () => {{}};
}

#[cfg(not(feature = "tracing"))]
pub use __hick_trace_noop as trace;
#[cfg(not(feature = "tracing"))]
pub use __hick_trace_noop as debug;
#[cfg(not(feature = "tracing"))]
pub use __hick_trace_noop as info;
#[cfg(not(feature = "tracing"))]
pub use __hick_trace_noop as warn;
#[cfg(not(feature = "tracing"))]
pub use __hick_trace_noop as error;

/// No-op span returned when the `tracing` feature is disabled.
///
/// Implements `.entered()` and `.enter()` so that
/// `hick_trace::info_span!(...).entered()` compiles in both tracing and
/// no-tracing builds.
#[cfg(not(feature = "tracing"))]
#[derive(Debug)]
pub struct NoopSpan;

#[cfg(not(feature = "tracing"))]
impl NoopSpan {
  /// Enters the span (no-op). Returns `self` so it acts as a drop-guard.
  #[inline]
  pub fn entered(self) -> Self {
    self
  }
  /// Borrows the span and returns a new no-op guard (matches tracing's API).
  #[inline]
  pub fn enter(&self) -> Self {
    NoopSpan
  }
}

/// Token-consuming no-op for span macros when `tracing` is disabled.
/// Returns a [`NoopSpan`] so callers may use `.entered()` / `.enter()`
/// without compile errors. Uses the same field-consuming grammar as
/// [`__hick_trace_noop`] so variables passed as span fields are not flagged
/// as unused.
#[doc(hidden)]
#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! __hick_trace_noop_span {
  // Strip target prefix.
  (target: $tgt:expr, $($rest:tt)*) => {
    { if false { let _ = &$tgt; } $crate::__hick_trace_noop_span!($($rest)*) }
  };

  // Span name only (the required first argument after an optional target).
  // Any remaining tokens are field key=value pairs — consume them via the
  // diagnostic no-op and return the NoopSpan.
  ($name:literal, $($fields:tt)*) => {
    { $crate::__hick_trace_noop!($($fields)*); $crate::NoopSpan }
  };
  ($name:literal) => {
    $crate::NoopSpan
  };

  // Fallback: consume everything, return NoopSpan.
  ($($tt:tt)*) => {
    { $crate::__hick_trace_noop!($($tt)*); $crate::NoopSpan }
  };
}

#[cfg(not(feature = "tracing"))]
pub use __hick_trace_noop_span as trace_span;
#[cfg(not(feature = "tracing"))]
pub use __hick_trace_noop_span as debug_span;
#[cfg(not(feature = "tracing"))]
pub use __hick_trace_noop_span as info_span;

#[cfg(feature = "stats")]
pub mod stats {
  //! Backend-agnostic atomic counters and gauges for the hick mDNS stack.
  //!
  //! [`Stats`] owns one atomic counter per counter and gauge. All loads and
  //! stores use `Relaxed` ordering (sufficient for monotone counters where
  //! precise cross-thread ordering is not required).
  //!
  //! On targets that have native 64-bit atomics (`target_has_atomic = "64"`)
  //! [`core::sync::atomic::AtomicU64`] is used directly. On 32-bit embedded
  //! targets (e.g. `thumbv7em-none-eabihf`) [`portable_atomic::AtomicU64`]
  //! provides the same API via software emulation.
  //!
  //! When the `metrics` Cargo feature is also enabled, every counter increment
  //! and gauge update additionally forwards the value to the [`metrics`] facade.

  #[cfg(target_has_atomic = "64")]
  use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
  #[cfg(not(target_has_atomic = "64"))]
  use portable_atomic::{AtomicU64, Ordering::Relaxed};

  macro_rules! declare_counters {
    ($($field:ident => $metric:literal),* $(,)?) => {
      $(
        #[inline]
        pub fn $field(&self, by: u64) {
          self.$field.fetch_add(by, Relaxed);
          #[cfg(feature = "metrics")]
          ::metrics::counter!($metric).increment(by);
        }
      )*
    };
  }

  macro_rules! declare_gauges {
    ($(
      $field:ident => $metric:literal :
        incr = $incr:ident,
        decr = $decr:ident,
        set  = $set:ident
    ),* $(,)?) => {
      $(
        #[inline]
        pub fn $incr(&self, by: u64) {
          self.$field.fetch_add(by, Relaxed);
          #[cfg(feature = "metrics")]
          ::metrics::gauge!($metric).increment(by as f64);
        }

        #[inline]
        pub fn $decr(&self, by: u64) {
          self.$field.fetch_sub(by, Relaxed);
          #[cfg(feature = "metrics")]
          ::metrics::gauge!($metric).decrement(by as f64);
        }

        /// Store an absolute value into this gauge.
        ///
        /// Note: values above 2^53 lose precision when forwarded to the
        /// `f64` metrics gauge.
        #[inline]
        pub fn $set(&self, v: u64) {
          self.$field.store(v, Relaxed);
          #[cfg(feature = "metrics")]
          ::metrics::gauge!($metric).set(v as f64);
        }
      )*
    };
  }

  /// Atomic counters and gauges for a single mDNS stack instance.
  ///
  /// Construct via [`Stats::default()`]; all fields start at zero.
  #[derive(Default, Debug)]
  pub struct Stats {
    // ── Counters ──────────────────────────────────────────────────────────
    packets_rx: AtomicU64,
    packets_tx: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    packets_dropped: AtomicU64,
    ingress_witness_declined: AtomicU64,
    ingress_degraded_admits: AtomicU64,
    ingress_residual_refusals: AtomicU64,
    ingress_unscoped_group_admits: AtomicU64,
    ingress_unscoped_group_refusals: AtomicU64,
    parse_errors: AtomicU64,
    send_errors: AtomicU64,
    recv_errors: AtomicU64,
    recv_timestamp_enable_failed: AtomicU64,
    questions_rx: AtomicU64,
    answers_rx: AtomicU64,
    answers_collected: AtomicU64,
    answers_suppressed_kas: AtomicU64,
    duplicate_questions_suppressed: AtomicU64,
    responses_tx: AtomicU64,
    probes_tx: AtomicU64,
    announcements_tx: AtomicU64,
    goodbyes_tx: AtomicU64,
    conflicts: AtomicU64,
    renames: AtomicU64,
    relinquished_host_conflicts_suppressed: AtomicU64,
    cache_inserts: AtomicU64,
    cache_refreshes: AtomicU64,
    cache_evictions: AtomicU64,
    cache_expirations: AtomicU64,
    queries_started: AtomicU64,
    queries_done: AtomicU64,
    queries_timeout: AtomicU64,
    services_registered: AtomicU64,
    services_established: AtomicU64,
    // ── Gauges ────────────────────────────────────────────────────────────
    cache_size: AtomicU64,
    queries_active: AtomicU64,
    services_active: AtomicU64,
  }

  impl Stats {
    declare_counters! {
      packets_rx => "mdns_packets_rx",
      packets_tx => "mdns_packets_tx",
      bytes_rx => "mdns_bytes_rx",
      bytes_tx => "mdns_bytes_tx",
      packets_dropped => "mdns_packets_dropped",
      // ── RFC 6762 §11 ingress, the three facts a boolean verdict hid ──────
      //
      // The kernel declined to emit a receive cmsg it normally emits: the
      // datagram's destination or receive interface went missing without a
      // `MSG_CTRUNC` to explain it. Every BSD builds its ancillary mbufs with
      // `M_NOWAIT` and skips the cmsg on allocation failure with no error and no
      // counter of its own, and mbuf exhaustion is normally caused by a flood —
      // so this is the counter that says "we are being degraded", and it is the
      // only warning a host gets.
      ingress_witness_declined => "mdns_ingress_witness_declined",
      // A datagram ADMITTED with no destination witness at all, on §11's
      // source-prefix arm or on the kernel's coarse multicast flag. The
      // destination partition's guarantees do not hold for these, so the count
      // is the size of the exposure on a blind receive square.
      ingress_degraded_admits => "mdns_ingress_degraded_admits",
      // A datagram REFUSED because its witnessed destination is one this
      // endpoint does not hold and no named class describes — §11's residual.
      // Counted so the conformance gap is an observation rather than an
      // argument.
      ingress_residual_refusals => "mdns_ingress_residual_refusals",
      // A datagram addressed to an mDNS group that was ADMITTED without
      // anything scoping it to the bound link — on the kernel's coarse
      // multicast flag, or on §11's source arm. RFC 6762 §11 arm one's
      // "regardless of source IP address" exemption was NOT granted to these;
      // they are the residual exposure of having a fallback for the group arm
      // at all, so the count is the size of that exposure.
      ingress_unscoped_group_admits => "mdns_ingress_unscoped_group_admits",
      // The other side of the same rule, and the one an operator alerts on: a
      // datagram §11 says to admit "regardless of source IP address", REFUSED
      // because nothing established that it arrived on the link this endpoint
      // bound and its source was off-prefix.
      //
      // Every BSD skips ancillary cmsgs under the mbuf shortage a flood causes,
      // so sustained movement here is an availability attack in progress rather
      // than a misconfigured peer — and without this counter that cost is an
      // argument rather than an observation. Reachable on FreeBSD and DragonFly,
      // which bind no `MSG_MCAST`; OpenBSD and NetBSD admit on the flag instead.
      ingress_unscoped_group_refusals => "mdns_ingress_unscoped_group_refusals",
      parse_errors => "mdns_parse_errors",
      send_errors => "mdns_send_errors",
      // A receive call that failed WITHOUT consuming a datagram — `ENOBUFS`
      // under memory pressure, a Windows `WSAECONNRESET` after an ICMP
      // port-unreachable for one of our own sends, or a socket that has broken
      // structurally. Distinct from `packets_dropped`, which counts datagrams
      // that DID leave the kernel queue and were then discarded.
      //
      // It exists because a driver's receive task can stop reading a family
      // without anything else in the process changing: sends still work, the
      // endpoint still answers commands, and the only symptom is silence. A
      // rising count is the degradation, and a count that stops rising while the
      // endpoint reports no traffic is the deafness.
      recv_errors => "mdns_recv_errors",
      // A best-effort enable of kernel receive timestamps (`SO_TIMESTAMP` /
      // `SO_TIMESTAMPNS`) failed at bind time. Every future receive on that
      // socket then carries `RecvMeta::rx_time: None`, which degrades
      // `hick_udp`'s self-send tracker to content-only matching for the life of
      // the socket — the mechanism that keeps this endpoint's own multicast
      // loopback from being mistaken for a peer — with no error and no log
      // unless this is watched. `hick-udp`'s `try_bind_v4`/`try_bind_v6` are
      // free functions with no per-endpoint `Stats` to write into, so this one
      // is incremented through hick-udp's own process-wide counter instead of
      // by a driver; see `hick_udp::multicast::bind_stats`.
      recv_timestamp_enable_failed => "mdns_recv_timestamp_enable_failed",
      questions_rx => "mdns_questions_rx",
      answers_rx => "mdns_answers_rx",
      answers_collected => "mdns_answers_collected",
      answers_suppressed_kas => "mdns_answers_suppressed_kas",
      duplicate_questions_suppressed => "mdns_duplicate_questions_suppressed",
      responses_tx => "mdns_responses_tx",
      probes_tx => "mdns_probes_tx",
      announcements_tx => "mdns_announcements_tx",
      goodbyes_tx => "mdns_goodbyes_tx",
      conflicts => "mdns_conflicts",
      renames => "mdns_renames",
      // A peer's record matched this endpoint's own recently-relinquished
      // history at a HOST name, and RFC 6762 §9 conflict detection for it was
      // suppressed because the owning route had no INSTANCE role to fall back
      // to. Deliberate and deferred, not a bug: see `mdns-proto`'s
      // `RouteEvents::next_service_conflict` and issue #92 (host-name
      // ownership) for the obligation this counts against — until that lands,
      // this is how the gap is an observation instead of an argument.
      relinquished_host_conflicts_suppressed => "mdns_relinquished_host_conflicts_suppressed",
      cache_inserts => "mdns_cache_inserts",
      cache_refreshes => "mdns_cache_refreshes",
      cache_evictions => "mdns_cache_evictions",
      cache_expirations => "mdns_cache_expirations",
      queries_started => "mdns_queries_started",
      queries_done => "mdns_queries_done",
      queries_timeout => "mdns_queries_timeout",
      services_registered => "mdns_services_registered",
      services_established => "mdns_services_established",
    }

    declare_gauges! {
      cache_size => "mdns_cache_size" :
        incr = incr_cache_size,
        decr = decr_cache_size,
        set  = set_cache_size,
      queries_active => "mdns_queries_active" :
        incr = incr_queries_active,
        decr = decr_queries_active,
        set  = set_queries_active,
      services_active => "mdns_services_active" :
        incr = incr_services_active,
        decr = decr_services_active,
        set  = set_services_active,
    }

    /// Load a consistent snapshot of every counter and gauge.
    ///
    /// Each field is loaded independently with Relaxed ordering; the snapshot
    /// is not guaranteed to reflect a single instant in time but is sufficient
    /// for periodic reporting.
    pub fn snapshot(&self) -> StatsSnapshot {
      StatsSnapshot {
        packets_rx: self.packets_rx.load(Relaxed),
        packets_tx: self.packets_tx.load(Relaxed),
        bytes_rx: self.bytes_rx.load(Relaxed),
        bytes_tx: self.bytes_tx.load(Relaxed),
        packets_dropped: self.packets_dropped.load(Relaxed),
        ingress_witness_declined: self.ingress_witness_declined.load(Relaxed),
        ingress_degraded_admits: self.ingress_degraded_admits.load(Relaxed),
        ingress_residual_refusals: self.ingress_residual_refusals.load(Relaxed),
        ingress_unscoped_group_admits: self.ingress_unscoped_group_admits.load(Relaxed),
        ingress_unscoped_group_refusals: self.ingress_unscoped_group_refusals.load(Relaxed),
        parse_errors: self.parse_errors.load(Relaxed),
        send_errors: self.send_errors.load(Relaxed),
        recv_errors: self.recv_errors.load(Relaxed),
        recv_timestamp_enable_failed: self.recv_timestamp_enable_failed.load(Relaxed),
        questions_rx: self.questions_rx.load(Relaxed),
        answers_rx: self.answers_rx.load(Relaxed),
        answers_collected: self.answers_collected.load(Relaxed),
        answers_suppressed_kas: self.answers_suppressed_kas.load(Relaxed),
        duplicate_questions_suppressed: self.duplicate_questions_suppressed.load(Relaxed),
        responses_tx: self.responses_tx.load(Relaxed),
        probes_tx: self.probes_tx.load(Relaxed),
        announcements_tx: self.announcements_tx.load(Relaxed),
        goodbyes_tx: self.goodbyes_tx.load(Relaxed),
        conflicts: self.conflicts.load(Relaxed),
        renames: self.renames.load(Relaxed),
        relinquished_host_conflicts_suppressed: self
          .relinquished_host_conflicts_suppressed
          .load(Relaxed),
        cache_inserts: self.cache_inserts.load(Relaxed),
        cache_refreshes: self.cache_refreshes.load(Relaxed),
        cache_evictions: self.cache_evictions.load(Relaxed),
        cache_expirations: self.cache_expirations.load(Relaxed),
        queries_started: self.queries_started.load(Relaxed),
        queries_done: self.queries_done.load(Relaxed),
        queries_timeout: self.queries_timeout.load(Relaxed),
        services_registered: self.services_registered.load(Relaxed),
        services_established: self.services_established.load(Relaxed),
        cache_size: self.cache_size.load(Relaxed),
        queries_active: self.queries_active.load(Relaxed),
        services_active: self.services_active.load(Relaxed),
      }
    }
  }

  /// Point-in-time snapshot of every [`Stats`] counter and gauge.
  #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
  #[non_exhaustive]
  pub struct StatsSnapshot {
    // Counters
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub packets_dropped: u64,
    /// A receive cmsg the kernel normally emits was absent with no
    /// `MSG_CTRUNC`: the datagram's RFC 6762 §11 witness was DECLINED rather
    /// than lost or unavailable. See `hick_udp::onlink::DestinationWitness::Declined`.
    pub ingress_witness_declined: u64,
    /// Datagrams admitted with no destination witness at all, where the §11
    /// destination partition's guarantees do not hold.
    pub ingress_degraded_admits: u64,
    /// Datagrams refused because their witnessed destination takes no §11 arm
    /// and no named class describes it.
    pub ingress_residual_refusals: u64,
    /// Datagrams addressed to an mDNS group and admitted with nothing scoping
    /// them to the bound link — the residual exposure of the group arm's
    /// fallback. RFC 6762 §11 arm one was not granted to these.
    pub ingress_unscoped_group_admits: u64,
    /// Datagrams RFC 6762 §11 says to admit "regardless of source IP address",
    /// refused for want of link scoping. The availability cost of that scoping,
    /// and the counter to alert on: every BSD drops ancillary cmsgs under the
    /// mbuf shortage a flood causes.
    pub ingress_unscoped_group_refusals: u64,
    pub parse_errors: u64,
    pub send_errors: u64,
    /// Receive calls that failed without consuming a datagram (see the counter
    /// declaration for why this is not `packets_dropped`).
    pub recv_errors: u64,
    /// A best-effort enable of kernel receive timestamps failed at bind time,
    /// degrading `hick_udp`'s self-send matching to content-only for the life
    /// of that socket. Process-wide rather than per-endpoint: see the
    /// counter's declaration for why `hick-udp` cannot increment a live
    /// endpoint's `Stats` here.
    pub recv_timestamp_enable_failed: u64,
    pub questions_rx: u64,
    pub answers_rx: u64,
    pub answers_collected: u64,
    pub answers_suppressed_kas: u64,
    pub duplicate_questions_suppressed: u64,
    pub responses_tx: u64,
    pub probes_tx: u64,
    pub announcements_tx: u64,
    pub goodbyes_tx: u64,
    pub conflicts: u64,
    pub renames: u64,
    /// A peer's record matched this endpoint's own recently-relinquished
    /// history at a HOST name, and RFC 6762 §9 conflict detection was
    /// suppressed for it because the owning route had no INSTANCE role to
    /// fall back to. Deliberate and deferred pending host-name-ownership
    /// probing and defence (`mdns-proto` issue #92); until then this is the
    /// only field evidence the suppression ever ran.
    pub relinquished_host_conflicts_suppressed: u64,
    pub cache_inserts: u64,
    pub cache_refreshes: u64,
    pub cache_evictions: u64,
    pub cache_expirations: u64,
    pub queries_started: u64,
    pub queries_done: u64,
    pub queries_timeout: u64,
    pub services_registered: u64,
    pub services_established: u64,
    // Gauges
    pub cache_size: u64,
    pub queries_active: u64,
    pub services_active: u64,
  }
}

#[cfg(test)]
mod tests;

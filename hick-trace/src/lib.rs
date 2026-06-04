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
pub use tracing::{debug, error, info, trace, warn};

/// Token-discarding no-op for all five diagnostic macros when `tracing` is
/// disabled. Every argument form accepted by the real macros (structured
/// key-value pairs, positional format strings, bare expressions) is silently
/// consumed by the `$($tt:tt)*` pattern.
#[doc(hidden)]
#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! __hick_trace_noop {
  ($($tt:tt)*) => {{}};
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

// ── Stats / Metrics ─────────────────────────────────────────────────────────

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
    parse_errors: AtomicU64,
    send_errors: AtomicU64,
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
      parse_errors => "mdns_parse_errors",
      send_errors => "mdns_send_errors",
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
        parse_errors: self.parse_errors.load(Relaxed),
        send_errors: self.send_errors.load(Relaxed),
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
  pub struct StatsSnapshot {
    // Counters
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub packets_dropped: u64,
    pub parse_errors: u64,
    pub send_errors: u64,
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
  /// Verify that every macro accepts both structured (key=value) and positional
  /// format-string invocations, and that they compile regardless of whether
  /// `tracing` is enabled.
  #[test]
  fn macros_compile() {
    let _n = 1_usize;
    let _e = "something went wrong";
    crate::trace!(field = 0, "trace structured");
    crate::debug!("n={}", _n);
    crate::info!(field = _n, "info structured");
    crate::warn!("warn positional {}", 42u32);
    crate::error!("e={}", _e);
    // Verify both invocation styles (structured key=value and positional).
    crate::debug!(x = 1u32, "msg");
    crate::warn!(field = 2u32, "msg");
  }

  /// Verify Stats construction, counter increment, gauge incr/decr, and snapshot.
  #[cfg(feature = "stats")]
  #[test]
  fn stats_round_trip() {
    use crate::stats::Stats;

    let s = Stats::default();

    // Increment counters.
    s.packets_rx(3);
    s.parse_errors(1);

    // Gauge increment/decrement.
    s.incr_cache_size(5);
    s.decr_cache_size(2);

    let snap = s.snapshot();
    assert_eq!(snap.packets_rx, 3);
    assert_eq!(snap.parse_errors, 1);
    assert_eq!(snap.cache_size, 3);
    // Untouched fields stay zero.
    assert_eq!(snap.packets_tx, 0);
    assert_eq!(snap.services_established, 0);
  }

  /// Verify StatsSnapshot derives PartialEq and Eq.
  #[cfg(feature = "stats")]
  #[test]
  fn snapshot_eq() {
    use crate::stats::Stats;

    let s = Stats::default();
    let a = s.snapshot();
    let b = s.snapshot();
    assert_eq!(a, b);
  }
}

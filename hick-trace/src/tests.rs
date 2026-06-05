/// Verify span macros compile and that `.entered()` yields a usable drop-guard
/// in both tracing and no-tracing builds.
#[test]
fn span_macros_compile() {
  let _g = crate::trace_span!("my_span", field = 1u32).entered();
  let _g2 = crate::debug_span!("x", a = 1u32).entered();
  let _g3 = crate::info_span!("y").entered();
}

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

/// Correctness gate: the no-op macros must CONSUME their arguments
/// so that non-`_`-prefixed variables used only in macro calls do not
/// trigger `unused_variables` warnings under `-D warnings`.
///
/// This test is compiled under the crate's lint config (which includes
/// `-D warnings` via `[lints] workspace = true`). If any macro expansion
/// leaves a variable unconsumed this test produces a compile error.
#[test]
fn noop_macros_consume_non_underscore_vars() {
  // Non-underscore locals — the test fails to compile if the no-op macros
  // do not consume them.
  let count = 42_u64;
  let err = "oops";
  let detail = core::f64::consts::E; // use a named constant to avoid approx_constant lint

  crate::trace!(count = count, "count is {}", count);
  crate::debug!(err = %err, "error detail: {}", err);
  crate::info!(detail = ?detail, "detail = {}", detail);
  crate::warn!(err = err, count = count, "warn: {} {}", err, count);
  crate::error!("error: {} {} {}", err, count, detail);

  // Display / Debug bare forms.
  crate::debug!(%err);
  crate::warn!(?detail);

  // target: prefix.
  crate::info!(target: "my_target", count = count, "msg");

  // Span macros: fields must also be consumed.
  let span_field = 99_u32;
  let _guard = crate::trace_span!("my_span", field = span_field).entered();
  let _guard2 = crate::debug_span!("x", a = span_field).entered();
  let _guard3 = crate::info_span!("y").entered();
}

/// Correctness gate: a non-literal `target:` expression must not
/// produce an `unused_variables` warning and must not be evaluated.
///
/// Uses a non-underscore-prefixed local whose only use is as the `target:`
/// expression. Under `-D warnings` (enforced by `workspace = true` lints)
/// this would be a compile error if the no-op macro did not consume `$tgt`.
#[cfg(not(feature = "tracing"))]
#[test]
fn noop_macros_consume_non_literal_target() {
  use core::sync::atomic::{AtomicBool, Ordering::SeqCst};

  // A non-underscore local used ONLY as a target expression. This test
  // fails to compile if `target:` is not consumed.
  let tgt = "my_module";
  crate::debug!(target: tgt, "message");
  crate::warn!(target: tgt, x = 1u32, "msg {}", 42u32);

  // Also verify the target expression is NOT evaluated (no side effects).
  static TARGET_EVALED: AtomicBool = AtomicBool::new(false);
  fn make_target() -> &'static str {
    TARGET_EVALED.store(true, SeqCst);
    "side_effect_target"
  }
  crate::info!(target: make_target(), "message");
  assert!(
    !TARGET_EVALED.load(SeqCst),
    "target: expression must not be evaluated in no-op build"
  );
}

/// Correctness gate: the no-op macros must NOT evaluate their
/// argument expressions — side effects must be completely suppressed.
///
/// Uses an `AtomicBool` sentinel and a function that sets it, then asserts
/// the sentinel was never touched after calling all macro forms.
///
/// Gated `cfg(not(feature = "tracing"))` because in tracing builds the
/// real macros DO evaluate their args (that's the whole point), so this
/// invariant only applies to the noop path.
#[cfg(not(feature = "tracing"))]
#[test]
fn noop_macros_do_not_evaluate_args() {
  use core::sync::atomic::{AtomicBool, Ordering::SeqCst};

  static RAN: AtomicBool = AtomicBool::new(false);

  fn side_effect() -> u32 {
    RAN.store(true, SeqCst);
    42
  }

  // key = value form.
  crate::debug!(value = side_effect(), "msg");
  assert!(!RAN.load(SeqCst), "key=value form evaluated side_effect()");

  // positional format-string form.
  crate::debug!("positional {}", side_effect());
  assert!(!RAN.load(SeqCst), "positional form evaluated side_effect()");

  // Display form.
  crate::info!(v = %side_effect(), "msg");
  assert!(!RAN.load(SeqCst), "display form evaluated side_effect()");

  // Debug form.
  crate::warn!(v = ?side_effect(), "msg");
  assert!(!RAN.load(SeqCst), "debug form evaluated side_effect()");

  // Bare %/? form.
  crate::error!(%side_effect());
  assert!(!RAN.load(SeqCst), "bare % form evaluated side_effect()");
  crate::trace!(?side_effect());
  assert!(!RAN.load(SeqCst), "bare ? form evaluated side_effect()");

  // Span macro with side-effecting field.
  let _g = crate::info_span!("s", field = side_effect()).entered();
  assert!(!RAN.load(SeqCst), "span macro evaluated side_effect()");
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

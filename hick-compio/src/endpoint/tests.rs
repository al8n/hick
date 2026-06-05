use super::{collect_local_subnets, pick_default_interface_index};

#[test]
fn collect_local_subnets_is_empty_for_unspecified_index() {
  // Index 0 means "unspecified" — no subnets are collected.
  assert!(collect_local_subnets(0).is_empty());
}

#[test]
fn pick_default_interface_index_runs_for_every_family_combo() {
  // Exercises the strict/loose, non-loopback/loopback fallback chain. The
  // chosen index is environment dependent, so only the shape is asserted: any
  // family combination yields an Option, and a returned index resolves to a
  // (possibly empty) subnet list.
  for (v4, v6) in [(true, true), (true, false), (false, true), (false, false)] {
    if let Some(idx) = pick_default_interface_index(v4, v6) {
      let _ = collect_local_subnets(idx);
    }
  }
}

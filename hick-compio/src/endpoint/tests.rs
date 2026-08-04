use hick_udp::onlink::collect_local_subnets;

use super::pick_default_interface_index;

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

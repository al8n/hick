//! Interop parity: hick <-> Apple Bonjour (mDNSResponder), driven through the
//! built-in macOS `dns-sd` CLI. Exercises both directions on real multicast:
//!
//!   1. hick advertises a service  -> `dns-sd -B` (mDNSResponder) discovers it.
//!   2. `dns-sd -R` advertises      -> hick's `browse` discovers it.
//!
//! hick and mDNSResponder coexist on `:5353` via `SO_REUSEPORT`, exchanging
//! real multicast on the host's default interface (mDNSResponder does not
//! browse loopback, so these run on the real NIC).
//!
//! Gated to macOS + opt-in `HICK_PARITY=1` (set by the dedicated CI parity job)
//! so it never runs — or flakes — during a normal `cargo test`. When the host
//! has no functional mDNS (a CI runner that blocks multicast, where `dns-sd`
//! itself produces nothing), each direction self-skips rather than failing —
//! but it still FAILS on a real regression, i.e. when `dns-sd` CAN see the
//! service and hick cannot.

#![cfg(all(target_os = "macos", feature = "tokio"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{
  io::{BufRead, BufReader},
  net::Ipv4Addr,
  process::{Command, Stdio},
  thread,
  time::Duration,
};

use hick_reactor::{
  Name, QueryParam, ServerOptions, ServiceRecords, ServiceSpec, tokio as tokio_drv,
};

const PARITY_TYPE: &str = "_hick-parity._tcp";

fn parity_enabled() -> bool {
  std::env::var("HICK_PARITY").is_ok()
}

/// Run `dns-sd -B <service_type> local.` for `secs`, then kill it and return the
/// captured stdout lines. An EMPTY result means Bonjour produced no output at
/// all — mDNSResponder is non-functional or the host blocks multicast — which
/// the callers treat as "environment can't run this test" and self-skip.
fn dns_sd_browse(service_type: &str, secs: u64) -> Vec<String> {
  let Ok(mut child) = Command::new("dns-sd")
    .args(["-B", service_type, "local."])
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
  else {
    return Vec::new();
  };
  let Some(stdout) = child.stdout.take() else {
    let _ = child.kill();
    let _ = child.wait();
    return Vec::new();
  };
  let reader = thread::spawn(move || {
    BufReader::new(stdout)
      .lines()
      .map_while(Result::ok)
      .collect::<Vec<_>>()
  });
  thread::sleep(Duration::from_secs(secs));
  let _ = child.kill();
  let _ = child.wait();
  reader.join().unwrap_or_default()
}

/// Direction 1: hick advertises a service; Bonjour's `dns-sd -B` must discover
/// it — i.e. mDNSResponder accepts and parses hick's announcement off the wire.
#[tokio::test]
async fn hick_advertisement_seen_by_bonjour() {
  if !parity_enabled() {
    eprintln!("HICK_PARITY not set; skipping Bonjour parity test");
    return;
  }
  // Distinct label per direction so the two tests never cross-talk via the
  // shared service type, even if mDNSResponder's cache lingers between them.
  let instance = format!("HickAdv-{}", std::process::id());

  let opts = ServerOptions::new().with_ipv6(false);
  let responder = match tokio_drv::server(opts).await {
    Ok(ep) => ep,
    Err(e) => {
      eprintln!("skipping: endpoint construction failed: {e:?}");
      return;
    }
  };
  let stype = Name::try_from_str(&format!("{PARITY_TYPE}.local.")).unwrap();
  let inst = Name::try_from_str(&format!("{instance}.{PARITY_TYPE}.local.")).unwrap();
  let host = Name::try_from_str(&format!("{instance}.local.")).unwrap();
  let mut recs = ServiceRecords::new(stype, inst, host, 8080, 120);
  recs.add_a(Ipv4Addr::new(127, 0, 0, 1));
  recs.add_txt_segment(b"parity=1".to_vec());
  let _svc = responder
    .register_service(ServiceSpec::new(recs))
    .await
    .expect("register_service");

  // Let hick probe + announce before Bonjour browses.
  tokio::time::sleep(Duration::from_millis(1500)).await;

  let lines = dns_sd_browse(PARITY_TYPE, 6);
  for l in &lines {
    eprintln!("dns-sd -B | {l}");
  }
  if lines.is_empty() {
    eprintln!(
      "dns-sd -B produced no output — no functional mDNS (CI runner blocks \
       multicast?); skipping live Bonjour parity"
    );
    return;
  }
  // mDNS names are case-insensitive (RFC 6762 §16) and responders lowercase
  // them on the wire, so match case-insensitively.
  let needle = instance.to_ascii_lowercase();
  assert!(
    lines
      .iter()
      .any(|l| l.to_ascii_lowercase().contains(&needle)),
    "Bonjour (dns-sd -B) is live but did not discover hick's advertised \
     instance {instance:?} ({} output lines)",
    lines.len()
  );
}

/// Direction 2: Bonjour's `dns-sd -R` advertises a service; hick's `browse` must
/// discover it — i.e. hick accepts and parses mDNSResponder's announcement.
#[tokio::test]
async fn bonjour_advertisement_seen_by_hick() {
  if !parity_enabled() {
    eprintln!("HICK_PARITY not set; skipping Bonjour parity test");
    return;
  }
  let instance = format!("BonjourAdv-{}", std::process::id());

  // mDNSResponder registers + announces the service (runs until killed).
  let mut child = Command::new("dns-sd")
    .args(["-R", &instance, PARITY_TYPE, "local.", "8080", "parity=1"])
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn dns-sd -R");
  thread::sleep(Duration::from_secs(2));

  let opts = ServerOptions::new().with_ipv6(false);
  let querier = match tokio_drv::server(opts).await {
    Ok(ep) => ep,
    Err(e) => {
      let _ = child.kill();
      let _ = child.wait();
      eprintln!("skipping: endpoint construction failed: {e:?}");
      return;
    }
  };

  let needle = instance.to_ascii_lowercase();
  let param = QueryParam::new(Name::try_from_str(&format!("{PARITY_TYPE}.local.")).unwrap())
    .with_timeout(Duration::from_secs(3));
  let found = match querier.browse(param).await {
    Ok(mut lookup) => {
      // mDNS names are case-insensitive (RFC 6762 §16); match accordingly.
      tokio::time::timeout(Duration::from_secs(8), async {
        while let Some(e) = lookup.next().await {
          eprintln!("hick browse | {}", e.instance_name());
          if e
            .instance_name()
            .as_str()
            .to_ascii_lowercase()
            .contains(&needle)
          {
            return true;
          }
        }
        false
      })
      .await
      .unwrap_or(false)
    }
    Err(e) => {
      eprintln!("browse failed: {e:?}");
      false
    }
  };

  // If hick missed it, distinguish a real regression from a dead environment by
  // asking dns-sd itself whether the still-running registration is visible on a
  // REAL interface: mDNSResponder reports its own registration on the pseudo
  // interface "-1" (local-only) even when the host has no multicast-capable NIC
  // (a CI runner) — which is NOT evidence that the inter-process multicast hick
  // needs actually works. A discovery on a real interface IS. If even that is
  // absent the host lacks functional mDNS, so self-skip; otherwise hick
  // genuinely failed to parse the announcement.
  let env_live = found || {
    let probe = dns_sd_browse(PARITY_TYPE, 3);
    for l in &probe {
      eprintln!("dns-sd -B (env probe) | {l}");
    }
    // dns-sd `-B` "Add" line: `<time> Add <flags> <if> <domain> <type> <name>`;
    // the interface field is "-1" for the local-only pseudo interface.
    probe.iter().any(|l| {
      let f: Vec<&str> = l.split_whitespace().collect();
      f.len() > 3 && f[1] == "Add" && f[3] != "-1"
    })
  };

  let _ = child.kill();
  let _ = child.wait();

  if !env_live {
    eprintln!(
      "dns-sd -B produced no output — no functional mDNS (CI runner blocks \
       multicast?); skipping live Bonjour parity"
    );
    return;
  }
  assert!(
    found,
    "hick's browse must discover the Bonjour-advertised instance {instance:?} \
     (dns-sd's environment is live)"
  );
}

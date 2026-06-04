//! Interop parity: hick <-> Avahi (`avahi-daemon`), driven through the
//! `avahi-utils` CLIs (`avahi-browse` / `avahi-publish`). Exercises both
//! directions on real multicast:
//!
//!   1. hick advertises a service  -> `avahi-browse` discovers it.
//!   2. `avahi-publish` advertises  -> hick's `browse` discovers it.
//!
//! hick and avahi-daemon coexist on `:5353` via `SO_REUSEPORT` on the host's
//! default interface. Gated to Linux + opt-in `HICK_PARITY=1` (the dedicated CI
//! parity job installs `avahi-daemon` + `avahi-utils`, starts the daemon, and
//! sets it) so it never runs — or flakes — during a normal `cargo test`. When
//! the host has no functional mDNS (a runner that blocks multicast, where
//! `avahi-browse` itself produces nothing), each direction self-skips rather
//! than failing — but it still FAILS on a real regression, i.e. when
//! `avahi-browse` CAN see the service and hick cannot.

#![cfg(all(target_os = "linux", feature = "tokio"))]
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

/// Run `avahi-browse -p -r <service_type>` for `secs`, then kill it and return
/// the captured stdout lines (`-p` parseable, `-r` resolve). An EMPTY result
/// means avahi-daemon is non-functional or the host blocks multicast, which the
/// callers treat as "environment can't run this test" and self-skip.
fn avahi_browse(service_type: &str, secs: u64) -> Vec<String> {
  let Ok(mut child) = Command::new("avahi-browse")
    .args(["-p", "-r", service_type])
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

/// Direction 1: hick advertises a service; Avahi's `avahi-browse` must discover
/// it — i.e. avahi-daemon accepts and parses hick's announcement off the wire.
#[tokio::test]
async fn hick_advertisement_seen_by_avahi() {
  if !parity_enabled() {
    eprintln!("HICK_PARITY not set; skipping Avahi parity test");
    return;
  }
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

  // Let hick probe + announce before Avahi browses.
  tokio::time::sleep(Duration::from_millis(1500)).await;

  let lines = avahi_browse(PARITY_TYPE, 6);
  for l in &lines {
    eprintln!("avahi-browse | {l}");
  }
  if lines.is_empty() {
    eprintln!(
      "avahi-browse produced no output — no functional mDNS (runner blocks \
       multicast?); skipping live Avahi parity"
    );
    return;
  }
  // mDNS names are case-insensitive (RFC 6762 §16); match case-insensitively.
  let needle = instance.to_ascii_lowercase();
  assert!(
    lines
      .iter()
      .any(|l| l.to_ascii_lowercase().contains(&needle)),
    "Avahi (avahi-browse) is live but did not discover hick's advertised \
     instance {instance:?} ({} output lines)",
    lines.len()
  );
}

/// Direction 2: Avahi's `avahi-publish` advertises a service; hick's `browse`
/// must discover it — i.e. hick accepts and parses avahi-daemon's announcement.
#[tokio::test]
async fn avahi_advertisement_seen_by_hick() {
  if !parity_enabled() {
    eprintln!("HICK_PARITY not set; skipping Avahi parity test");
    return;
  }
  let instance = format!("AvahiAdv-{}", std::process::id());

  // avahi-publish registers + announces the service (runs until killed).
  let mut child = Command::new("avahi-publish")
    .args(["-s", &instance, PARITY_TYPE, "8080", "parity=1"])
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn avahi-publish");
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
    Ok(mut lookup) => tokio::time::timeout(Duration::from_secs(8), async {
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
    .unwrap_or(false),
    Err(e) => {
      eprintln!("browse failed: {e:?}");
      false
    }
  };

  // If hick missed it, distinguish a real regression from a dead environment by
  // asking Avahi itself whether the still-running registration is visible: if
  // avahi-browse can't see it either, the host lacks functional mDNS —
  // self-skip; if it CAN, hick genuinely failed to parse the announcement.
  let env_live = found || {
    let probe = avahi_browse(PARITY_TYPE, 3);
    for l in &probe {
      eprintln!("avahi-browse (env probe) | {l}");
    }
    !probe.is_empty()
  };

  let _ = child.kill();
  let _ = child.wait();

  if !env_live {
    eprintln!(
      "avahi-browse produced no output — no functional mDNS (runner blocks \
       multicast?); skipping live Avahi parity"
    );
    return;
  }
  assert!(
    found,
    "hick's browse must discover the Avahi-advertised instance {instance:?} \
     (avahi-browse's environment is live)"
  );
}

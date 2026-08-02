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
//! so it never runs — or flakes — during a normal `cargo test`.
//!
//! ## The premise these tests rest on
//!
//! hick binds **one** interface, and a datagram reaches it only if the daemon's
//! traffic actually crosses that link. Nothing about hick decides whether it
//! does, so direction 2 settles it up front, before any hick code runs.
//!
//! Asking `dns-sd` is not enough. That `dns-sd -B` can see a `dns-sd -R`
//! registration says only that both are clients of the same `mDNSResponder`,
//! talking to it over a local socket; no datagram need ever leave the host. It
//! establishes which interfaces the daemon *claims*, which is a weaker fact than
//! the one the test needs — a virtual NIC can carry the claim and not the
//! traffic.
//!
//! So the claim only narrows the candidates. A socket of our own then settles
//! each in turn: bound beside the daemon on `:5353`, joined to the mDNS group on
//! that one link, it asks the group for the registered service and waits for the
//! answer to come back. Whichever link answers is the one hick is pinned to.
//! Once that round trip is proven, a missed announcement is hick's and the test
//! fails.
//!
//! ## Ending green without asserting
//!
//! A `return` from a test function is a pass, so every early exit is a claim
//! that nothing was wrong. Direction 2 therefore has exactly **one** place that
//! can end successfully without running its assertion, and it takes a
//! [`HostCondition`] — a closed set of facts about the host, each established
//! before the behaviour runs, each one a reason no datagram could have arrived.
//! A harness that could not do its job is never one of them: a missing or
//! failing `dns-sd`, an unreadable pipe, a registration the daemon never
//! confirmed, or an endpoint hick could not build all fail the test, because
//! none of them is evidence about this host's topology.

#![cfg(all(target_os = "macos", feature = "tokio"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{
  fmt,
  io::{BufRead, BufReader},
  net::Ipv4Addr,
  process::{Child, Command, Stdio},
  sync::mpsc,
  thread,
  time::{Duration, Instant},
};

use hick_reactor::{
  Name, QueryParam, ServerOptions, ServiceRecords, ServiceSpec, tokio as tokio_drv,
};

const PARITY_TYPE: &str = "_hick-parity._tcp";

fn parity_enabled() -> bool {
  std::env::var("HICK_PARITY").is_ok()
}

/// A fact about this host that makes the exchange impossible here, and the only
/// reason direction 2 may end without running its assertion.
///
/// Every variant is settled before hick browses and describes the host, not the
/// outcome. The set is closed on purpose: a free-form reason would let the next
/// unexplained green be written as easily as these four.
enum HostCondition {
  /// No UP, multicast-capable interface carries an IPv4 address.
  NoBindableIpv4Interface,
  /// `dns-sd -B` ran and printed nothing at all.
  DaemonAnsweredNothing,
  /// The daemon holds the registration only where no datagram travels.
  RegistrationLocalOnly { advertised: Vec<i32>, bound: u32 },
  /// The daemon's links and the links hick could bind are disjoint.
  NoSharedLink {
    advertised: Vec<u32>,
    bindable: Vec<u32>,
  },
  /// Every shared link was tried with a socket of our own, and none of them
  /// carried an mDNS round trip.
  NoLinkCarriesMdns { tried: Vec<u32> },
}

impl fmt::Display for HostCondition {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::NoBindableIpv4Interface => f.write_str(
        "no UP, multicast-capable interface carries an IPv4 address, so hick has nothing to bind",
      ),
      Self::DaemonAnsweredNothing => f.write_str(
        "`dns-sd -B` printed nothing at all, so mDNSResponder is answering no question here",
      ),
      Self::RegistrationLocalOnly { advertised, bound } => write!(
        f,
        "Bonjour holds the registration on no real link (if column: {advertised:?}) — the \
         local-only pseudo interface is one no datagram crosses — while hick binds interface {}",
        describe_interface(*bound)
      ),
      Self::NoSharedLink {
        advertised,
        bindable,
      } => write!(
        f,
        "Bonjour advertises on interface(s) {}, hick can bind {}; the two share no link, so no \
         announcement can reach hick",
        describe_interfaces(advertised),
        describe_interfaces(bindable)
      ),
      Self::NoLinkCarriesMdns { tried } => write!(
        f,
        "no mDNS round trip crosses any link Bonjour and hick share ({}): a socket of our own, \
         bound beside the daemon and joined to the group on each in turn, asked the group for the \
         service and heard no answer come back",
        describe_interfaces(tried)
      ),
    }
  }
}

fn describe_interfaces(indices: &[u32]) -> String {
  indices
    .iter()
    .map(|i| describe_interface(*i))
    .collect::<Vec<_>>()
    .join(", ")
}

/// A live `dns-sd -R` registration, killed when the test leaves by any path so
/// a failed premise or assertion cannot strand it behind.
struct Registration {
  child: Child,
  /// The instance label mDNSResponder confirmed it registered.
  ///
  /// mDNSResponder renames on conflict, so the requested label is a request and
  /// this is the fact. The interface probe and the final assertion must both
  /// speak of this name, or they can end up describing two registrations.
  label: String,
}

impl Registration {
  /// Confirm mDNSResponder still holds the registration.
  ///
  /// `dns-sd -R` withdraws the service the moment it exits, so any conclusion
  /// drawn about "the registration" after that is a conclusion about nothing —
  /// including the finding that nobody is advertising it.
  fn still_holding(&mut self) -> Result<(), String> {
    match self.child.try_wait() {
      Ok(None) => Ok(()),
      Ok(Some(status)) => Err(format!(
        "`dns-sd -R` exited ({status}) and withdrew the registration"
      )),
      Err(e) => Err(format!("`dns-sd -R` could not be checked on: {e}")),
    }
  }
}

impl Drop for Registration {
  fn drop(&mut self) {
    let _ = stop(&mut self.child);
  }
}

/// How a `dns-sd` child ended.
enum Ended {
  /// It was still running when its window closed, so we ended it. Only then is
  /// what it did or did not print a statement about this host.
  KilledAfterFullWindow,
  /// It quit before we were done with it, at whatever status. Nothing it
  /// printed — or failed to print — describes the host.
  QuitEarly(String),
}

/// End `child` and report how it went, or why we cannot say.
///
/// The order matters. `try_wait` first, because a child that already quit must
/// never be mistaken for one we ended; and the status is re-read afterwards
/// because a child that quits in the instant between the two reports an exit
/// code, while one we killed reports a signal.
fn stop(child: &mut Child) -> Result<Ended, String> {
  if let Some(status) = child
    .try_wait()
    .map_err(|e| format!("the `dns-sd` child could not be checked on: {e}"))?
  {
    return Ok(Ended::QuitEarly(status.to_string()));
  }
  let _ = child.kill();
  let status = child
    .wait()
    .map_err(|e| format!("the `dns-sd` child could not be reaped: {e}"))?;
  match status.code() {
    Some(_) => Ok(Ended::QuitEarly(status.to_string())),
    None => Ok(Ended::KilledAfterFullWindow),
  }
}

const REPLY_PREFIX: &str = "Got a reply for service ";
const REPLY_SUFFIX: &str = ": Name now registered and active";

/// The most one line of `dns-sd` output may cost us. Its lines are short; a
/// stream that never sends a newline must not be buffered without bound.
const MAX_LINE_BYTES: usize = 8 * 1024;

/// Append what still fits under the per-line cap and drop the rest.
fn append_capped(out: &mut Vec<u8>, bytes: &[u8]) {
  let room = MAX_LINE_BYTES.saturating_sub(out.len());
  out.extend_from_slice(&bytes[..room.min(bytes.len())]);
}

/// Read one line into `out`, returning how many bytes the stream gave up.
///
/// Everything past the cap is consumed and discarded rather than retained, so
/// a stream that never sends a newline costs a bounded amount of memory. `Ok(0)`
/// is end of stream.
fn read_capped_line(reader: &mut impl BufRead, out: &mut Vec<u8>) -> std::io::Result<usize> {
  let mut total = 0usize;
  loop {
    let (consumed, complete) = {
      let available = reader.fill_buf()?;
      if available.is_empty() {
        return Ok(total);
      }
      match available.iter().position(|b| *b == b'\n') {
        Some(i) => {
          append_capped(out, &available[..i]);
          (i + 1, true)
        }
        None => {
          append_capped(out, available);
          (available.len(), false)
        }
      }
    };
    reader.consume(consumed);
    total += consumed;
    if complete {
      return Ok(total);
    }
  }
}

/// The instance label from a `dns-sd -R` reply line, if the line is that reply.
///
/// The reply carries the fully-qualified name the daemon settled on, which is
/// the requested label only when nothing collided; on a conflict it is a
/// renamed one such as `Instance (2)`.
fn registered_label(line: &str) -> Option<String> {
  let line = line.trim_end();
  let fqdn = line
    .split_once(REPLY_PREFIX)?
    .1
    .strip_suffix(REPLY_SUFFIX)?;
  let suffix = format!(".{PARITY_TYPE}.local.");
  let split = fqdn.len().checked_sub(suffix.len())?;
  let (label, tail) = (fqdn.get(..split)?, fqdn.get(split..)?);
  (!label.is_empty() && tail.eq_ignore_ascii_case(&suffix)).then(|| label.to_string())
}

/// Watch a `dns-sd -R` child's stdout, reporting the registered name once and
/// then draining until the stream ends.
///
/// Parsing happens here rather than in the caller so at most one message ever
/// crosses the channel: a queue fed by every line would grow without bound, and
/// a receiver that hung up would break the pipe under a registration that is
/// meant to stay live. Draining continues past the report for the same reason —
/// `dns-sd` must never block writing to a pipe nobody reads.
fn watch_registration(mut reader: impl BufRead, tx: mpsc::SyncSender<Result<String, String>>) {
  let mut reported = false;
  let mut buf = Vec::new();
  loop {
    buf.clear();
    match read_capped_line(&mut reader, &mut buf) {
      Ok(0) => return,
      Ok(_) => {
        let line = String::from_utf8_lossy(&buf);
        eprintln!("dns-sd -R | {line}");
        if !reported && let Some(label) = registered_label(&line) {
          let _ = tx.try_send(Ok(label));
          reported = true;
        }
      }
      Err(e) => {
        if !reported {
          let _ = tx.try_send(Err(format!("`dns-sd -R` stdout could not be read: {e}")));
        }
        return;
      }
    }
  }
}

/// Register `instance` through `dns-sd -R`, waiting up to `secs` for the
/// daemon's own reply naming what it registered.
fn register_via_dns_sd(instance: &str, secs: u64) -> Result<Registration, String> {
  let mut child = Command::new("dns-sd")
    .args(["-R", instance, PARITY_TYPE, "local.", "8080", "parity=1"])
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .map_err(|e| format!("`dns-sd -R` could not be spawned: {e}"))?;
  match await_registered_label(&mut child, instance, secs) {
    Ok(label) => Ok(Registration { child, label }),
    Err(reason) => Err(match stop(&mut child) {
      Ok(Ended::QuitEarly(status)) => format!("{reason} (`dns-sd -R` had quit: {status})"),
      _ => reason,
    }),
  }
}

/// Read `child`'s stdout until it reports the name it registered, or `secs`
/// elapse.
fn await_registered_label(child: &mut Child, instance: &str, secs: u64) -> Result<String, String> {
  let stdout = child
    .stdout
    .take()
    .ok_or_else(|| "`dns-sd -R` exposed no stdout to read".to_string())?;
  let (tx, rx) = mpsc::sync_channel(1);
  thread::spawn(move || watch_registration(BufReader::new(stdout), tx));
  match rx.recv_timeout(Duration::from_secs(secs)) {
    Ok(reported) => reported,
    Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
      "`dns-sd -R` did not report {instance:?} registered within {secs}s, so the name \
       mDNSResponder settled on — which may be a renamed one — is unknown"
    )),
    Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!(
      "`dns-sd -R` stopped without reporting {instance:?} registered"
    )),
  }
}

/// The most a whole `dns-sd -B` capture may cost us. Its real output is a
/// handful of lines; anything approaching this is a tool we do not recognise,
/// and reading it to exhaustion would trade the test process for nothing.
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// Collect the lines `reader` yields, within a fixed budget.
///
/// Fails on the first read error and on exceeding the budget. Partial output is
/// not a smaller observation — it is an unusable one, and handing it back as a
/// `Vec` would let it pass for the whole truth.
fn read_capture(mut reader: impl BufRead) -> Result<Vec<String>, String> {
  let mut lines = Vec::new();
  let mut spent = 0usize;
  let mut buf = Vec::new();
  loop {
    buf.clear();
    let read = read_capped_line(&mut reader, &mut buf)
      .map_err(|e| format!("`dns-sd -B` stdout could not be read: {e}"))?;
    if read == 0 {
      return Ok(lines);
    }
    spent = spent.saturating_add(read);
    if spent > MAX_CAPTURE_BYTES {
      return Err(format!(
        "`dns-sd -B` wrote more than {MAX_CAPTURE_BYTES} bytes, far past anything it has to say"
      ));
    }
    lines.push(String::from_utf8_lossy(&buf).into_owned());
  }
}

/// Run `dns-sd -B <service_type> local.` for `secs`, then end it and return the
/// captured stdout lines, or the reason the run taught us nothing at all.
///
/// `Ok` with no lines means the daemon answered nothing across a window we let
/// run to the end and closed ourselves: `dns-sd` block-buffers its piped stdout
/// and flushes only from a reply callback, so a run that discovers nothing loses
/// even its banner to the kill and yields zero bytes. That is a fact about the
/// host. `Err` — the tool missing, quitting on its own at any status, outrunning
/// the capture budget, or leaving an unreadable pipe — is a fact about the
/// harness, and the two must never be collapsed.
fn dns_sd_browse(service_type: &str, secs: u64) -> Result<Vec<String>, String> {
  let mut child = Command::new("dns-sd")
    .args(["-B", service_type, "local."])
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .map_err(|e| format!("`dns-sd -B` could not be spawned: {e}"))?;
  let Some(stdout) = child.stdout.take() else {
    let _ = stop(&mut child);
    return Err("`dns-sd -B` exposed no stdout to read".to_string());
  };
  let reader = thread::spawn(move || read_capture(BufReader::new(stdout)));
  thread::sleep(Duration::from_secs(secs));
  // Ends the child on every path, including the one where the reader gave up on
  // an over-budget stream and stopped draining its pipe.
  let ended = stop(&mut child);
  let lines = match reader.join() {
    Err(_) => return Err("the thread reading `dns-sd -B` stdout panicked".to_string()),
    Ok(Err(e)) => return Err(e),
    Ok(Ok(lines)) => lines,
  };
  match ended? {
    Ended::KilledAfterFullWindow => Ok(lines),
    Ended::QuitEarly(status) => Err(format!(
      "`dns-sd -B` quit on its own ({status}) instead of browsing for its full window"
    )),
  }
}

/// What one `dns-sd -B` run established about the daemon.
///
/// The states are kept apart because they are not the same evidence. Only
/// [`Probe::Seen`] observed the daemon answering, and only there does an
/// interface list mean anything; collapsing the others into "no interfaces"
/// would let a broken tool or a mute daemon pose as a local-only registration.
enum Probe {
  /// `dns-sd` could not be run or read. Nothing was learned about this host.
  Unusable(String),
  /// `dns-sd` ran and printed nothing: the daemon answered no question at all.
  Silent,
  /// `dns-sd` ran and printed events, so the daemon is answering. `ours` holds
  /// the interfaces still carrying our instance once the stream is folded.
  Seen { ours: Vec<i32> },
}

/// Ask the daemon which links it currently holds `instance` on.
fn probe_registration(service_type: &str, instance: &str, secs: u64) -> Probe {
  classify_probe(dns_sd_browse(service_type, secs), instance)
}

/// Decide what one `dns-sd -B` run established, keeping a failed run apart from
/// a mute one and both apart from an answer.
fn classify_probe(run: Result<Vec<String>, String>, instance: &str) -> Probe {
  match run {
    Err(reason) => Probe::Unusable(reason),
    Ok(lines) => {
      for l in &lines {
        eprintln!("dns-sd -B (interface probe) | {l}");
      }
      if lines.is_empty() {
        Probe::Silent
      } else {
        Probe::Seen {
          ours: advertised_interfaces(&lines, instance),
        }
      }
    }
  }
}

/// Whether a name hick reported is exactly the registration under test.
///
/// Substring matching would let an instance sharing our label's prefix satisfy
/// the assertion while the premise had been established for a different
/// registration. mDNS names are case-insensitive (RFC 6762 §16).
fn is_registration_under_test(discovered: &str, expected: &str) -> bool {
  discovered.eq_ignore_ascii_case(expected)
}

/// The interface an IPv4-only hick endpoint binds.
///
/// Mirrors the rule `ServerOptions` documents for its default picker: the first
/// UP, multicast-capable, non-loopback interface carrying an IPv4 address, else
/// the loopback interface. Direction 2 pins the result, so the interface its
/// premise names is the one hick provably bound rather than one inferred after
/// the fact.
///
/// `Ok(None)` is a claim that this host has no such interface, so it is reached
/// only from an enumeration that completed and an address query that answered
/// for every candidate. A query that failed is not an interface that is absent,
/// and reporting one as the other is how a broken lookup becomes a green skip.
fn hick_ipv4_interfaces() -> Result<Vec<(u32, Ipv4Addr)>, String> {
  let ifs = getifs::interfaces()
    .map_err(|e| format!("the host's interface table could not be read: {e}"))?;
  let mut preferred = Vec::new();
  let mut loopback = Vec::new();
  for i in &ifs {
    let flags = i.flags();
    if !flags.contains(getifs::Flags::UP) {
      continue;
    }
    let addrs = i.ipv4_addrs().map_err(|e| {
      format!(
        "the IPv4 addresses of interface {} could not be read: {e}",
        describe_interface(i.index())
      )
    })?;
    let Some(addr) = addrs.first().map(|a| a.addr()) else {
      continue;
    };
    if flags.contains(getifs::Flags::LOOPBACK) {
      loopback.push((i.index(), addr));
    } else if flags.contains(getifs::Flags::MULTICAST) && i.index() != 0 {
      preferred.push((i.index(), addr));
    }
  }
  preferred.extend(loopback);
  Ok(preferred)
}

/// An independent witness that an mDNS round trip crosses one interface.
///
/// A socket of our own, bound to `:5353` beside mDNSResponder and joined to the
/// mDNS group on one specific link. It asks the group a question and waits for
/// the daemon's answer to come back over the wire.
///
/// It deliberately shares nothing with hick. That `dns-sd -B` can see a
/// `dns-sd -R` registration proves only that both are clients of the same
/// daemon, talking to it over a local socket — no datagram need ever leave the
/// host. The link a datagram can actually cross is a different fact, and only a
/// third party sending and receiving on that link establishes it.
struct ControlSocket {
  fd: libc::c_int,
}

impl Drop for ControlSocket {
  fn drop(&mut self) {
    // SAFETY: `fd` is ours, opened in `ControlSocket::open` and closed once.
    unsafe { libc::close(self.fd) };
  }
}

/// One candidate link: an interface index and the address we name it by.
#[derive(Clone, Copy)]
struct Link {
  index: u32,
  addr: Ipv4Addr,
}

/// What the control learned about one link.
enum Witness {
  /// The question went out and the daemon's answer came back over this link.
  Proved,
  /// The question went out; nothing came back inside the budget. The link is
  /// unproven — and, importantly, this process demonstrably *can* send.
  Unproven,
}

/// Why the control could not witness a round trip on a link.
enum ControlFailure {
  /// The kernel refused the **link**, and a fresh look at the interface table
  /// agrees with the story the errno tells. That is the fact
  /// [`HostCondition::NoLinkCarriesMdns`] records, so the candidate is left
  /// unproven and the next one gets its turn.
  LinkUnusable {
    why: String,
    /// Whether this errno is one macOS also returns for a per-process network
    /// policy. Corroborating against the interface cannot separate the two, so
    /// a run made only of these has not ruled policy out.
    policy_ambiguous: bool,
  },
  /// The interface moved under us: it is no longer up, no longer
  /// multicast-capable, or no longer carries the address we named it by. The
  /// candidate list was computed from a table that has since changed, so no
  /// conclusion drawn from it is sound.
  InterfaceChanged(String),
  /// The kernel refused **our code**. Nothing was learned about the link.
  Harness(String),
}

/// What a refusal amounts to, once the errno and a fresh look at the interface
/// are taken together.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
  LinkUnusable,
  InterfaceChanged,
  Harness,
}

/// The errnos on which the kernel is refusing the link rather than our code.
///
/// Deliberately narrow, and matched on `raw_os_error` rather than
/// `ErrorKind` — the same discipline `hick-udp`'s own environment-refusal
/// allowlist keeps — so that nothing widens by accident. `EINVAL` is absent and
/// must stay absent: a malformed sockopt, a wrong address length or a bad
/// descriptor are this harness's bugs, and admitting them would let the test
/// skip past the defects it exists to catch. So are `EPERM`/`EACCES`, which say
/// this process may not do something rather than that this link cannot.
///
/// Applied only where a link is named: joining the group on it, choosing it for
/// output, and sending through it. A receive that simply times out is not an
/// error at all — that is an unproven link, which the caller already handles.
fn refuses_the_link(e: &std::io::Error) -> bool {
  matches!(
    e.raw_os_error(),
    // No route to the mDNS group out of this interface. This is what a runner
    // whose NIC carries no multicast answers to the query send.
    Some(libc::EHOSTUNREACH)
      // The network behind this interface is unreachable, or administratively
      // down: the same statement about the link, one layer up.
      | Some(libc::ENETUNREACH)
      | Some(libc::ENETDOWN)
      // The address that names the interface is no longer assigned to one, so
      // there is no link left to join or send through.
      | Some(libc::EADDRNOTAVAIL)
  )
}

/// Whether this errno is one macOS also returns for a per-process network
/// policy rather than for the link itself.
///
/// XNU answers a policy drop, an interface denial, and a tunnel policy that
/// cannot rebind with the same routing errnos a link that cannot carry gives.
/// Re-reading the interface cannot separate those: under policy the interface
/// is perfectly up, multicast-capable and addressed. `EADDRNOTAVAIL` is not
/// here because it is corroborated directly — the address either is assigned or
/// is not, and policy does not change that.
fn is_policy_ambiguous(e: &std::io::Error) -> bool {
  matches!(
    e.raw_os_error(),
    Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) | Some(libc::ENETDOWN)
  )
}

/// What a refusal means, given its errno and whether the interface it named is
/// still there to have refused.
///
/// The errno alone is not enough. macOS answers a per-process network policy
/// with the same `EHOSTUNREACH`/`ENETUNREACH` a dead link gives, and those look
/// identical from inside a single send, so the allowlist is necessary and not
/// sufficient. Requiring the table to agree removes the causes that the table
/// can see; the one it cannot see — process policy — is dealt with by the
/// caller, which refuses to conclude anything from a run where *every* link
/// refused.
fn verdict_for(e: &std::io::Error, still_present: bool) -> Verdict {
  if !refuses_the_link(e) {
    return Verdict::Harness;
  }
  match (e.raw_os_error(), still_present) {
    // The address is unavailable and the table agrees it is gone.
    (Some(libc::EADDRNOTAVAIL), false) => Verdict::LinkUnusable,
    // The address is unavailable, yet the interface still carries it. The
    // address was not the problem, so this is not the environment's answer.
    (Some(libc::EADDRNOTAVAIL), true) => Verdict::Harness,
    // A routing refusal about a link that is still up, still multicast-capable
    // and still carrying the address: the kernel will not carry for us here.
    (_, true) => Verdict::LinkUnusable,
    (_, false) => Verdict::InterfaceChanged,
  }
}

/// Whether `link` is, right now, still an interface that could have refused.
///
/// Reads the table fresh rather than trusting the snapshot the candidate list
/// was built from.
fn link_still_present(link: Link) -> Result<bool, String> {
  let Some(i) = getifs::interface_by_index(link.index)
    .map_err(|e| format!("interface {} could not be re-read: {e}", link.index))?
  else {
    return Ok(false);
  };
  let flags = i.flags();
  if !flags.contains(getifs::Flags::UP) || !flags.contains(getifs::Flags::MULTICAST) {
    return Ok(false);
  }
  let addrs = i.ipv4_addrs().map_err(|e| {
    format!(
      "the addresses of interface {} could not be re-read: {e}",
      describe_interface(link.index)
    )
  })?;
  Ok(addrs.iter().any(|a| a.addr() == link.addr))
}

/// Classify a failed operation that named `link`.
fn link_failure(context: String, link: Link) -> ControlFailure {
  let e = std::io::Error::last_os_error();
  let described = format!("{context}: {e}");
  if !refuses_the_link(&e) {
    return ControlFailure::Harness(described);
  }
  let still_present = match link_still_present(link) {
    Ok(present) => present,
    // Without a fresh reading there is nothing to corroborate against, and an
    // uncorroborated refusal may not become a host condition.
    Err(why) => return ControlFailure::Harness(format!("{described}; and {why}")),
  };
  match verdict_for(&e, still_present) {
    Verdict::LinkUnusable => ControlFailure::LinkUnusable {
      why: described,
      policy_ambiguous: is_policy_ambiguous(&e),
    },
    Verdict::InterfaceChanged => ControlFailure::InterfaceChanged(format!(
      "{described}; and interface {} is no longer up, multicast-capable, or carrying {}",
      describe_interface(link.index),
      link.addr
    )),
    Verdict::Harness => ControlFailure::Harness(format!(
      "{described}; yet interface {} is unchanged, so the link was not the problem",
      describe_interface(link.index)
    )),
  }
}

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

impl ControlSocket {
  /// Bind `:5353` beside the daemon and join the mDNS group on `interface`.
  ///
  /// Every step is checked, and none of them may be mistaken for a socket that
  /// listened and heard silence. The steps that name the link are classified:
  /// the kernel refusing to join or address that link is the host condition
  /// itself, while anything else is this harness getting it wrong.
  fn open(link: Link) -> Result<Self, ControlFailure> {
    let interface = link.addr;
    // SAFETY: each call below is a plain libc socket operation on our own `fd`,
    // with option values whose types and lengths match what the option expects.
    unsafe {
      let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
      if fd < 0 {
        return Err(ControlFailure::Harness(format!(
          "control socket: {}",
          std::io::Error::last_os_error()
        )));
      }
      let sock = Self { fd };
      // mDNSResponder already holds `:5353`; both reuse options are needed to
      // stand beside it rather than displace it.
      sock.set_int(libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
      sock.set_int(libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;

      let addr = libc::sockaddr_in {
        sin_len: size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: MDNS_PORT.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
      };
      if libc::bind(
        fd,
        std::ptr::from_ref(&addr).cast(),
        size_of::<libc::sockaddr_in>() as libc::socklen_t,
      ) < 0
      {
        return Err(ControlFailure::Harness(format!(
          "control socket could not bind :{MDNS_PORT}: {}",
          std::io::Error::last_os_error()
        )));
      }

      // The membership and the outgoing interface are both named by address:
      // this is the whole point of the control, so both must be this link.
      let mreq = libc::ip_mreq {
        imr_multiaddr: to_in_addr(MDNS_GROUP),
        imr_interface: to_in_addr(interface),
      };
      if libc::setsockopt(
        fd,
        libc::IPPROTO_IP,
        libc::IP_ADD_MEMBERSHIP,
        std::ptr::from_ref(&mreq).cast(),
        size_of::<libc::ip_mreq>() as libc::socklen_t,
      ) < 0
      {
        return Err(link_failure(
          format!("could not join {MDNS_GROUP} on {interface}"),
          link,
        ));
      }
      let out = to_in_addr(interface);
      if libc::setsockopt(
        fd,
        libc::IPPROTO_IP,
        libc::IP_MULTICAST_IF,
        std::ptr::from_ref(&out).cast(),
        size_of::<libc::in_addr>() as libc::socklen_t,
      ) < 0
      {
        return Err(link_failure(
          format!("could not send from {interface}"),
          link,
        ));
      }
      sock.set_int(libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, 1)?;
      sock.set_int(libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, 255)?;
      Ok(sock)
    }
  }

  /// SAFETY: caller guarantees `option` at `level` takes a `c_int`.
  unsafe fn set_int(
    &self,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
  ) -> Result<(), ControlFailure> {
    // SAFETY: `value` is a live `c_int` and its length is passed alongside.
    let rc = unsafe {
      libc::setsockopt(
        self.fd,
        level,
        option,
        std::ptr::from_ref(&value).cast(),
        size_of::<libc::c_int>() as libc::socklen_t,
      )
    };
    if rc < 0 {
      // These options name no link — they configure the socket we opened — so a
      // refusal here is about our own call, never about the environment.
      return Err(ControlFailure::Harness(format!(
        "control socket option {option} at level {level}: {}",
        std::io::Error::last_os_error()
      )));
    }
    Ok(())
  }

  /// Multicast one mDNS question for `service_type` to the group.
  fn ask(&self, link: Link, service_type: &str) -> Result<(), ControlFailure> {
    let query = mdns_ptr_query(&format!("{service_type}.local."));
    let addr = libc::sockaddr_in {
      sin_len: size_of::<libc::sockaddr_in>() as u8,
      sin_family: libc::AF_INET as libc::sa_family_t,
      sin_port: MDNS_PORT.to_be(),
      sin_addr: to_in_addr(MDNS_GROUP),
      sin_zero: [0; 8],
    };
    // The destination is a constant of ours, and macOS answers a malformed one
    // with the same `EHOSTUNREACH` a link that cannot carry gives. Rule that
    // cause out here, where it is cheap and certain, rather than trying to tell
    // the two apart from the errno afterwards.
    assert_eq!(
      usize::from(addr.sin_len),
      size_of::<libc::sockaddr_in>(),
      "the control's destination must be a whole `sockaddr_in`"
    );
    assert_eq!(
      addr.sin_family,
      libc::AF_INET as libc::sa_family_t,
      "the control's destination must be IPv4"
    );
    assert_eq!(
      u16::from_be(addr.sin_port),
      MDNS_PORT,
      "the control's destination must be the mDNS port"
    );
    assert_eq!(
      Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
      MDNS_GROUP,
      "the control's destination must be the mDNS group"
    );
    // SAFETY: `query` and `addr` are live for the call and their lengths match.
    let sent = unsafe {
      libc::sendto(
        self.fd,
        query.as_ptr().cast(),
        query.len(),
        0,
        std::ptr::from_ref(&addr).cast(),
        size_of::<libc::sockaddr_in>() as libc::socklen_t,
      )
    };
    if sent < 0 {
      // The send names the link, so the kernel refusing a route through it is
      // the host condition rather than a fault of ours.
      return Err(link_failure("could not send its query".to_string(), link));
    }
    Ok(())
  }

  /// Wait up to `budget` for a datagram carrying `label`, asking again as it
  /// goes so a missed answer is not mistaken for a link that carries nothing.
  ///
  /// [`Witness::Proved`] is the round trip: mDNSResponder heard the question on
  /// this link and its answer came back over the same one.
  fn hears_answer_for(
    &self,
    link: Link,
    service_type: &str,
    label: &str,
    budget: Duration,
  ) -> Result<Witness, ControlFailure> {
    let timeout = libc::timeval {
      tv_sec: 1,
      tv_usec: 0,
    };
    // SAFETY: `timeout` is a live `timeval` and its length is passed alongside.
    let rc = unsafe {
      libc::setsockopt(
        self.fd,
        libc::SOL_SOCKET,
        libc::SO_RCVTIMEO,
        std::ptr::from_ref(&timeout).cast(),
        size_of::<libc::timeval>() as libc::socklen_t,
      )
    };
    if rc < 0 {
      return Err(ControlFailure::Harness(format!(
        "control socket could not take a receive timeout: {}",
        std::io::Error::last_os_error()
      )));
    }

    let needle = wire_label(label);
    let deadline = Instant::now() + budget;
    let mut buf = [0u8; 9000];
    let mut asked = Instant::now() - Duration::from_secs(1);
    while Instant::now() < deadline {
      if asked.elapsed() >= Duration::from_secs(1) {
        self.ask(link, service_type)?;
        asked = Instant::now();
      }
      // SAFETY: `buf` is a live, owned buffer of exactly the length passed.
      let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
      if n < 0 {
        let e = std::io::Error::last_os_error();
        // A window that expires with nothing in it is not an error: it is a
        // link that did not prove itself, which the caller reads as such.
        match e.kind() {
          std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => continue,
          _ => {
            return Err(ControlFailure::Harness(format!(
              "control socket could not receive: {e}"
            )));
          }
        }
      }
      let received = &buf[..n.max(0) as usize];
      if contains_ignore_ascii_case(received, &needle) {
        return Ok(Witness::Proved);
      }
    }
    Ok(Witness::Unproven)
  }
}

/// What one candidate link's turn came to.
#[derive(Debug, PartialEq, Eq)]
enum Attempt {
  /// The round trip completed on this interface.
  Proved(u32),
  /// The question went out; no answer arrived inside the budget.
  Unproven,
  /// The kernel refused this link, corroborated against the interface table.
  Refused { policy_ambiguous: bool },
}

/// What a run of attempts is entitled to conclude.
#[derive(Debug, PartialEq, Eq)]
enum Reduction {
  /// Bind hick to this interface: the exchange provably crosses it.
  Bind(u32),
  /// Every candidate was tried, none carried, and no refusal could equally have
  /// been a denial rather than a dead link.
  NoLinkCarries,
  /// Nothing proved, and at least one refusal carried an errno macOS also
  /// returns when policy denies the selected egress interface.
  Undecidable,
}

/// Reduce the candidates' outcomes to what may be concluded from them.
///
/// A refusal that policy could equally explain is fatal to the whole run, and
/// deliberately so: macOS evaluates its restrictions against the *selected
/// egress interface*, so a send that succeeded on one interface says nothing
/// about whether another was refused for being unusable or for being
/// disallowed. There is no signal available here that separates them —
/// `getifs` exposes only the standard interface flags, nothing about an
/// interface being expensive, constrained or otherwise restricted — so the run
/// establishes no fact about the host, and failing is the honest answer.
fn reduce(attempts: &[Attempt]) -> Reduction {
  for attempt in attempts {
    if let Attempt::Proved(index) = attempt {
      return Reduction::Bind(*index);
    }
  }
  if attempts.iter().any(|a| {
    matches!(
      a,
      Attempt::Refused {
        policy_ambiguous: true
      }
    )
  }) {
    return Reduction::Undecidable;
  }
  Reduction::NoLinkCarries
}

/// Ask, on `interface` alone, whether an mDNS round trip for `label` completes.
fn witness_round_trip(
  link: Link,
  label: &str,
  budget: Duration,
) -> Result<Witness, ControlFailure> {
  ControlSocket::open(link)?.hears_answer_for(link, PARITY_TYPE, label, budget)
}

fn to_in_addr(addr: Ipv4Addr) -> libc::in_addr {
  libc::in_addr {
    s_addr: u32::from_ne_bytes(addr.octets()),
  }
}

/// The wire form of one DNS label: its length, then its bytes. Searching for
/// this rather than the bare text keeps a passing mention from counting.
fn wire_label(label: &str) -> Vec<u8> {
  let mut out = Vec::with_capacity(label.len() + 1);
  out.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
  out.extend_from_slice(label.as_bytes());
  out
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
  haystack
    .windows(needle.len())
    .any(|w| w.eq_ignore_ascii_case(needle))
}

/// A minimal mDNS query: one PTR question for `name`, asked of the group.
fn mdns_ptr_query(name: &str) -> Vec<u8> {
  let mut out = vec![
    0, 0, // no transaction id, as mDNS asks
    0, 0, // query, no flags
    0, 1, // one question
    0, 0, 0, 0, 0, 0, // no answer, authority or additional records
  ];
  for label in name.split('.').filter(|l| !l.is_empty()) {
    out.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(label.as_bytes());
  }
  out.push(0); // root label
  out.extend_from_slice(&[0, 12]); // PTR
  out.extend_from_slice(&[0, 1]); // IN, answer to the group
  out
}

/// Render an interface index the way the diagnostics report it, resolving the
/// OS name when the index is still present in the interface table.
fn describe_interface(index: u32) -> String {
  match getifs::interface_by_index(index) {
    Ok(Some(i)) => format!("{index} ({})", i.name()),
    _ => format!("{index} (unnamed)"),
  }
}

/// The interfaces still carrying `instance` once `dns-sd -B`'s event stream is
/// folded in order.
///
/// An event line is `<time> <Add|Rmv> <flags> <if> <domain> <type> <instance>`.
/// The stream is a log of changes, not a list: an interface that went away
/// still has its `Add` in the transcript, and reading only the additions would
/// call a link shared long after it stopped being one — turning a lost
/// environment into a false hick regression.
///
/// The interface column is kept signed, exactly as `dns-sd` prints it: `-1` is
/// the local-only pseudo interface, a registration the daemon keeps to itself
/// on no link at all, and only a positive index names somewhere a datagram can
/// travel. Discarding the negative value would make "held on no real link"
/// indistinguishable from "never saw the registration" — the first is a host
/// fact worth skipping on, the second means the probe itself is broken.
fn advertised_interfaces(lines: &[String], instance: &str) -> Vec<i32> {
  let mut active: Vec<i32> = Vec::new();
  for line in lines {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 7 {
      continue;
    }
    let added = match fields[1] {
      "Add" => true,
      "Rmv" => false,
      _ => continue,
    };
    // The instance is the remainder of the line and may contain spaces. mDNS
    // names are case-insensitive (RFC 6762 §16), but nothing weaker than an
    // exact match will do: another instance sharing our prefix is not ours.
    if !fields[6..].join(" ").eq_ignore_ascii_case(instance) {
      continue;
    }
    let Ok(index) = fields[3].parse::<i32>() else {
      continue;
    };
    if added {
      if !active.contains(&index) {
        active.push(index);
      }
    } else {
      active.retain(|i| *i != index);
    }
  }
  active
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

  let lines = dns_sd_browse(PARITY_TYPE, 6).unwrap_or_default();
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
  // The one and only path on which this test ends green without asserting.
  if let Err(condition) = bonjour_to_hick_parity().await {
    eprintln!("skipping: this host cannot carry the exchange — {condition}");
  }
}

/// The live direction-2 exchange.
///
/// `Err` is reserved for the host conditions that make the exchange impossible
/// here; everything else panics, so a harness that could not establish the
/// premise fails the test instead of ending it green.
async fn bonjour_to_hick_parity() -> Result<(), HostCondition> {
  let requested = format!("BonjourAdv-{}", std::process::id());

  // mDNSResponder registers + announces the service (runs until killed), and
  // reports back the name it settled on. Everything downstream speaks of that
  // name: a rename would otherwise leave the probe hunting a registration that
  // does not exist while the assertion judged a different one.
  let mut registration = register_via_dns_sd(&requested, 10)
    .unwrap_or_else(|e| panic!("the parity harness could not register through `dns-sd`: {e}"));
  let instance = registration.label.clone();
  if instance != requested {
    eprintln!("dns-sd renamed {requested:?} to {instance:?}; using the registered name");
  }

  // Settle the premise before hick browses, so it can never be read back out of
  // the outcome: ask mDNSResponder which links it put the registration on, and
  // work out which link hick will bind. Both are host properties — the daemon's
  // interface table and the picker's input — and both are known while hick is
  // still nothing but a set of options.
  let probe = match probe_registration(PARITY_TYPE, &instance, 3) {
    // The daemon is answering, yet reports nothing for a registration it
    // accepted seconds ago. Before spending a longer window on it, establish
    // that there is still a registration to find.
    Probe::Seen { ref ours } if ours.is_empty() => {
      demand_still_holding(&mut registration);
      probe_registration(PARITY_TYPE, &instance, 6)
    }
    settled => settled,
  };
  let advertised = match probe {
    Probe::Unusable(reason) => {
      panic!("the parity harness could not browse with `dns-sd`: {reason}")
    }
    Probe::Silent => {
      demand_still_holding(&mut registration);
      return Err(HostCondition::DaemonAnsweredNothing);
    }
    // Reaching the assertion means the premise mechanism itself is broken: the
    // daemon is answering other questions but will not report a registration it
    // owns, so nothing it says about interfaces can be trusted. Skipping here
    // would hide exactly the blindness this check exists to remove.
    Probe::Seen { ours } => {
      demand_still_holding(&mut registration);
      assert!(
        !ours.is_empty(),
        "mDNSResponder is answering but reported no live `Add` for {instance:?}, its own \
         registration accepted seconds earlier; the interface premise cannot be established"
      );
      ours
    }
  };

  let bindable = hick_ipv4_interfaces()
    .unwrap_or_else(|e| panic!("the parity harness could not read this host's interfaces: {e}"));
  let Some(&(first, _)) = bindable.first() else {
    return Err(HostCondition::NoBindableIpv4Interface);
  };
  let real: Vec<u32> = advertised
    .iter()
    .filter_map(|i| u32::try_from(*i).ok().filter(|i| *i != 0))
    .collect();
  if real.is_empty() {
    demand_still_holding(&mut registration);
    return Err(HostCondition::RegistrationLocalOnly {
      advertised,
      bound: first,
    });
  }
  let shared: Vec<Link> = bindable
    .iter()
    .filter(|(index, _)| real.contains(index))
    .map(|&(index, addr)| Link { index, addr })
    .collect();
  if shared.is_empty() {
    demand_still_holding(&mut registration);
    return Err(HostCondition::NoSharedLink {
      advertised: real,
      bindable: bindable.iter().map(|(i, _)| *i).collect(),
    });
  }

  // A shared interface index is not yet a link a datagram crosses. Prove one
  // with a socket that is not hick's, in hick's own order of preference, and
  // bind hick to the first link that answers. Where several are shared this can
  // exercise a link other than hick's default pick — deliberately: the point of
  // this test is parity with a live Apple responder, and a link the exchange
  // provably crosses is the only place that can be shown.
  demand_still_holding(&mut registration);
  let mut attempts = Vec::new();
  for link in &shared {
    let named = describe_interface(link.index);
    match witness_round_trip(*link, &instance, Duration::from_secs(4)) {
      Ok(Witness::Proved) => {
        eprintln!("control socket on interface {named} proved an mDNS round trip");
        attempts.push(Attempt::Proved(link.index));
        break;
      }
      Ok(Witness::Unproven) => {
        eprintln!("control socket on interface {named} could not prove an mDNS round trip");
        attempts.push(Attempt::Unproven);
      }
      // The kernel refused to carry, and the interface is still there to have
      // refused. Leave the link unproven and give the next candidate its turn.
      Err(ControlFailure::LinkUnusable {
        why,
        policy_ambiguous,
      }) => {
        eprintln!("control socket on interface {named} was refused the link: {why}");
        attempts.push(Attempt::Refused { policy_ambiguous });
      }
      Err(ControlFailure::InterfaceChanged(why)) => panic!(
        "the parity harness cannot conclude anything about interface {named}: the interface \
         table changed under the candidate list — {why}"
      ),
      Err(ControlFailure::Harness(why)) => {
        panic!("the parity harness could not witness interface {named}: {why}")
      }
    }
  }
  let tried = describe_interfaces(&shared.iter().map(|l| l.index).collect::<Vec<_>>());
  let bound = match reduce(&attempts) {
    Reduction::Bind(index) => index,
    Reduction::Undecidable => {
      demand_still_holding(&mut registration);
      panic!(
        "nothing proved a round trip across {tried}, and at least one link was refused with an \
         errno macOS also returns when policy denies the selected egress interface: this run \
         cannot tell a link that will not carry from one this process is not allowed to use"
      )
    }
    Reduction::NoLinkCarries => {
      demand_still_holding(&mut registration);
      return Err(HostCondition::NoLinkCarriesMdns {
        tried: shared.iter().map(|l| l.index).collect(),
      });
    }
  };

  // Let the answer the control just provoked age out before hick asks the same
  // question. A responder must not multicast a record twice within a second
  // (RFC 6762 §6), so querying straight away invites mDNSResponder to suppress
  // the very announcement under test — the control would have made hick look
  // slow at exactly the moment it proved the link was good.
  tokio::time::sleep(Duration::from_millis(1200)).await;

  // The premise holds from here on: a third party has just had this very
  // registration answered over this very link, so nothing below may end this
  // test green quietly.
  let opts = ServerOptions::new()
    .with_ipv6(false)
    .with_interface_index(Some(bound));
  let querier = tokio_drv::server(opts).await.unwrap_or_else(|e| {
    panic!(
      "hick must bind interface {}, the one Bonjour advertises on: {e:?}",
      describe_interface(bound)
    )
  });

  let expected = format!("{instance}.{PARITY_TYPE}.local.");
  let param = QueryParam::new(Name::try_from_str(&format!("{PARITY_TYPE}.local.")).unwrap())
    .with_timeout(Duration::from_secs(3));
  let found = match querier.browse(param).await {
    Ok(mut lookup) => tokio::time::timeout(Duration::from_secs(8), async {
      while let Some(e) = lookup.next().await {
        eprintln!("hick browse | {}", e.instance_name());
        if is_registration_under_test(e.instance_name().as_str(), &expected) {
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

  // A registration withdrawn mid-browse would make `found` false for a reason
  // that is not hick's, so establish it survived before reading anything into
  // the result.
  demand_still_holding(&mut registration);
  assert!(
    found,
    "hick's browse must discover the Bonjour-advertised instance {expected:?} \
     (Bonjour advertises it on interface {}, the one hick bound)",
    describe_interface(bound)
  );
  Ok(())
}

/// Establish that mDNSResponder still holds the registration, or fail.
///
/// Every host condition drawn from the probe is a statement about a service
/// somebody is advertising. Once `dns-sd -R` exits the service is gone, and
/// "nobody is advertising it" stops being news about the host.
fn demand_still_holding(registration: &mut Registration) {
  if let Err(e) = registration.still_holding() {
    panic!("the parity harness lost its registration before it could conclude anything: {e}");
  }
}

/// Re-run this binary's live direction-2 test in a child process with `env`
/// applied, returning everything the harness reported.
///
/// The policy under test belongs to the caller, not to any helper: a broken
/// harness must make the test *fail*. Only the child's exit status can show
/// that, because a helper returning the tidiest possible error still leaves a
/// `return` in the test body looking exactly like a pass.
fn rerun_live_test(env: &[(&str, &str)]) -> std::process::Output {
  Command::new(std::env::current_exe().expect("path to this test binary"))
    .args([
      "bonjour_advertisement_seen_by_hick",
      "--exact",
      "--nocapture",
    ])
    .env("HICK_PARITY", "1")
    .envs(env.iter().copied())
    .output()
    .expect("re-run this test binary")
}

/// Everything the re-run wrote, both streams together.
fn transcript(out: &std::process::Output) -> String {
  format!(
    "{}{}",
    String::from_utf8_lossy(&out.stdout),
    String::from_utf8_lossy(&out.stderr)
  )
}

/// Re-run the live test with `script` standing in for `dns-sd` on `PATH`.
///
/// The shim comes first on the real `PATH` so a script may delegate to the
/// genuine tool for the calls it does not mean to disturb.
fn rerun_live_test_with_shim(tag: &str, script: &str) -> std::process::Output {
  use std::os::unix::fs::PermissionsExt;

  let dir = std::env::temp_dir().join(format!("hick-parity-{tag}-{}", std::process::id()));
  std::fs::create_dir_all(&dir).expect("create the shim directory");
  let shim = dir.join("dns-sd");
  std::fs::write(&shim, script).expect("write the shim");
  std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod the shim");

  let path = format!(
    "{}:{}",
    dir.to_str().expect("shim directory path"),
    std::env::var("PATH").unwrap_or_default()
  );
  let out = rerun_live_test(&[("PATH", path.as_str())]);
  let _ = std::fs::remove_dir_all(&dir);
  out
}

/// Assert the re-run failed for the stated harness reason rather than ending on
/// a host condition.
fn assert_harness_failure(out: &std::process::Output, expected: &str) {
  let log = transcript(out);
  assert!(
    !out.status.success(),
    "a broken harness must fail the parity test, not pass it:\n{log}"
  );
  assert!(
    !log.contains("skipping:"),
    "a harness failure must never be reported as a host condition:\n{log}"
  );
  assert!(
    log.contains(expected),
    "the failure must name its cause ({expected:?}), so the next reader is not left guessing:\n\
     {log}"
  );
}

#[test]
fn a_missing_dns_sd_fails_the_live_test() {
  let out = rerun_live_test(&[("PATH", "/nonexistent")]);
  assert_harness_failure(&out, "`dns-sd -R` could not be spawned");
}

#[test]
fn a_failing_dns_sd_fails_the_live_test() {
  let out = rerun_live_test_with_shim("exit255", "#!/bin/sh\nexit 255\n");
  assert_harness_failure(&out, "exit status: 255");
}

/// A shim line that answers `-R` as a confirmed registration of `$2`.
const SHIM_REPLY: &str = "printf ' 0:00:00.000  Got a reply for service \
                          %s._hick-parity._tcp.local.: Name now registered and active\\n' \"$2\"\n";

#[test]
fn a_silently_successful_browse_fails_the_live_test() {
  // Holds a registration, then answers every browse by succeeding at nothing —
  // the shape that used to read as "this host's daemon has nothing to say".
  let out = rerun_live_test_with_shim(
    "mutebrowse",
    &format!("#!/bin/sh\nif [ \"$1\" = \"-R\" ]; then\n{SHIM_REPLY}exec sleep 60\nfi\nexit 0\n"),
  );
  assert_harness_failure(&out, "quit on its own");
}

#[test]
fn a_withdrawn_registration_fails_the_live_test() {
  // Claims the registration succeeded and exits, taking the service with it, so
  // every later "nobody is advertising it" is about the shim and not the host.
  let out = rerun_live_test_with_shim(
    "withdrawn",
    &format!(
      "#!/bin/sh\nif [ \"$1\" = \"-R\" ]; then\n{SHIM_REPLY}exit 0\nfi\n\
       printf 'Browsing for _hick-parity._tcp.local.\\n'\nexec sleep 60\n"
    ),
  );
  assert_harness_failure(&out, "withdrew the registration");
}

/// A reader that fails before yielding anything.
struct FailsImmediately;

impl std::io::Read for FailsImmediately {
  fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
    Err(std::io::Error::other("stdout read failed"))
  }
}

/// A reader that yields one line and then fails, the shape that would otherwise
/// pass partial output off as a complete observation.
struct FailsAfterOneLine(bool);

impl std::io::Read for FailsAfterOneLine {
  fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    if self.0 {
      return Err(std::io::Error::other("stdout read failed"));
    }
    self.0 = true;
    let line = b" 1:40:11.446  Add        3  7 local. _hick-parity._tcp. BonjourAdv-42\n";
    let n = line.len().min(buf.len());
    buf[..n].copy_from_slice(&line[..n]);
    Ok(n)
  }
}

/// A capture large enough to outrun the budget.
fn over_budget_stream() -> String {
  format!("{}\n", "x".repeat(1023)).repeat(MAX_CAPTURE_BYTES / 1024 + 64)
}

#[test]
fn capture_fails_on_an_immediate_read_error() {
  assert!(read_capture(BufReader::new(FailsImmediately)).is_err());
}

#[test]
fn capture_fails_on_a_read_error_after_output() {
  assert!(read_capture(BufReader::new(FailsAfterOneLine(false))).is_err());
}

#[test]
fn capture_fails_once_it_outruns_its_budget() {
  let outcome = read_capture(std::io::Cursor::new(over_budget_stream()));
  assert!(
    outcome.is_err_and(|e| e.contains("wrote more than")),
    "an over-budget stream must be unusable, never a shorter observation"
  );
}

#[test]
fn a_read_error_is_unusable_rather_than_silent_or_seen() {
  let runs = [
    read_capture(BufReader::new(FailsImmediately)),
    read_capture(BufReader::new(FailsAfterOneLine(false))),
    read_capture(std::io::Cursor::new(over_budget_stream())),
  ];
  for run in runs {
    assert!(matches!(
      classify_probe(run, "BonjourAdv-42"),
      Probe::Unusable(_)
    ));
  }
}

#[test]
fn the_link_allowlist_admits_only_refusals_of_the_link() {
  for errno in [
    libc::EHOSTUNREACH,
    libc::ENETUNREACH,
    libc::ENETDOWN,
    libc::EADDRNOTAVAIL,
  ] {
    assert!(
      refuses_the_link(&std::io::Error::from_raw_os_error(errno)),
      "errno {errno} states this link cannot carry multicast"
    );
  }
}

#[test]
fn the_link_allowlist_keeps_our_own_mistakes_out() {
  // `EINVAL` above all: a malformed option or a wrong length is this harness
  // getting it wrong, and admitting it would let the test skip past its own
  // defects. The permission errors say this process may not act, not that the
  // link cannot carry; the rest are plainly ours.
  for errno in [
    libc::EINVAL,
    libc::EBADF,
    libc::ENOTSOCK,
    libc::ENOPROTOOPT,
    libc::EAFNOSUPPORT,
    libc::EACCES,
    libc::EPERM,
    libc::EADDRINUSE,
    libc::EMSGSIZE,
  ] {
    assert!(
      !refuses_the_link(&std::io::Error::from_raw_os_error(errno)),
      "errno {errno} is a fault of ours and must reach the test as a failure"
    );
  }
}

#[test]
fn the_link_allowlist_ignores_errors_that_carry_no_errno() {
  assert!(!refuses_the_link(&std::io::Error::other("no errno at all")));
}

#[test]
fn an_uncorroborated_refusal_never_becomes_a_host_condition() {
  let refusal = |errno| std::io::Error::from_raw_os_error(errno);
  // A routing refusal is only the link's answer while the link is still there
  // to have given it. If it has gone, the candidate list is stale and nothing
  // it says can be relied on.
  for errno in [libc::EHOSTUNREACH, libc::ENETUNREACH, libc::ENETDOWN] {
    assert_eq!(
      verdict_for(&refusal(errno), false),
      Verdict::InterfaceChanged,
      "errno {errno} on a vanished interface establishes nothing about any link"
    );
    assert_eq!(verdict_for(&refusal(errno), true), Verdict::LinkUnusable);
  }
  // An unavailable address is only the environment's answer if the address is
  // genuinely gone; while the interface still carries it, something else — our
  // own call — refused.
  assert_eq!(
    verdict_for(&refusal(libc::EADDRNOTAVAIL), true),
    Verdict::Harness,
    "an address the interface still carries cannot be the reason it was refused"
  );
  assert_eq!(
    verdict_for(&refusal(libc::EADDRNOTAVAIL), false),
    Verdict::LinkUnusable
  );
  // Corroboration never rescues an errno that was never the link's to give.
  for errno in [libc::EINVAL, libc::EACCES, libc::EPERM] {
    for present in [true, false] {
      assert_eq!(verdict_for(&refusal(errno), present), Verdict::Harness);
    }
  }
}

#[test]
fn a_send_on_one_interface_cannot_vouch_for_a_refusal_on_another() {
  let ambiguous = Attempt::Refused {
    policy_ambiguous: true,
  };
  let corroborated = Attempt::Refused {
    policy_ambiguous: false,
  };

  // The shape that matters: one interface took the query and simply heard
  // nothing, another was refused with an errno policy also produces. macOS
  // applies its restrictions per egress interface, so the first says nothing
  // about the second and the run concludes nothing.
  assert_eq!(
    reduce(&[Attempt::Unproven, ambiguous]),
    Reduction::Undecidable
  );
  assert_eq!(
    reduce(&[Attempt::Refused {
      policy_ambiguous: true
    }]),
    Reduction::Undecidable
  );

  // A refusal corroborated against the interface table needs no such vouching.
  assert_eq!(
    reduce(&[Attempt::Unproven, corroborated]),
    Reduction::NoLinkCarries
  );
  assert_eq!(
    reduce(&[
      Attempt::Refused {
        policy_ambiguous: false
      },
      Attempt::Refused {
        policy_ambiguous: false
      }
    ]),
    Reduction::NoLinkCarries
  );
  assert_eq!(reduce(&[Attempt::Unproven]), Reduction::NoLinkCarries);

  // A proved link settles the run whatever else was seen.
  assert_eq!(
    reduce(&[
      Attempt::Refused {
        policy_ambiguous: true
      },
      Attempt::Proved(7)
    ]),
    Reduction::Bind(7)
  );
}

#[test]
fn the_routing_errnos_are_the_ones_a_policy_could_also_explain() {
  for errno in [libc::EHOSTUNREACH, libc::ENETUNREACH, libc::ENETDOWN] {
    assert!(
      is_policy_ambiguous(&std::io::Error::from_raw_os_error(errno)),
      "errno {errno} is also what a per-process network policy produces"
    );
  }
  // An address that is not assigned is corroborated directly, and no network
  // policy can make an assigned address unassigned.
  assert!(!is_policy_ambiguous(&std::io::Error::from_raw_os_error(
    libc::EADDRNOTAVAIL
  )));
}

#[test]
fn browse_match_accepts_the_registered_instance() {
  assert!(is_registration_under_test(
    "bonjouradv-42._hick-parity._tcp.local.",
    "BonjourAdv-42._hick-parity._tcp.local."
  ));
}

#[test]
fn browse_match_rejects_a_same_prefix_instance() {
  assert!(!is_registration_under_test(
    "bonjouradv-421._hick-parity._tcp.local.",
    "BonjourAdv-42._hick-parity._tcp.local."
  ));
}

/// The reply `dns-sd -R` prints once mDNSResponder accepts a registration.
fn reply_line(label: &str) -> String {
  format!(" 1:40:09.456  {REPLY_PREFIX}{label}.{PARITY_TYPE}.local.{REPLY_SUFFIX}\n")
}

#[test]
fn registered_label_reads_the_daemons_reply() {
  assert_eq!(
    registered_label(&reply_line("BonjourAdv-42")).as_deref(),
    Some("BonjourAdv-42")
  );
}

#[test]
fn registered_label_reads_an_auto_renamed_instance() {
  assert_eq!(
    registered_label(&reply_line("BonjourAdv-42 (2)")).as_deref(),
    Some("BonjourAdv-42 (2)")
  );
}

#[test]
fn registered_label_ignores_lines_that_are_not_the_reply() {
  for line in [
    " 1:40:09.123  ...STARTING...",
    "Registering Service BonjourAdv-42._hick-parity._tcp.local. port 8080",
    &format!(" 1:40:09.456  {REPLY_PREFIX}BonjourAdv-42._other._tcp.local.{REPLY_SUFFIX}"),
    &format!(" 1:40:09.456  {REPLY_PREFIX}.{PARITY_TYPE}.local.{REPLY_SUFFIX}"),
  ] {
    assert!(registered_label(line).is_none(), "accepted {line:?}");
  }
}

/// Run the watcher over `input` to completion and collect what it reported.
fn watch(input: String) -> Vec<Result<String, String>> {
  let (tx, rx) = mpsc::sync_channel(1);
  watch_registration(std::io::Cursor::new(input), tx);
  rx.try_iter().collect()
}

#[test]
fn registration_watcher_reports_through_noisy_output() {
  let mut input = String::new();
  for i in 0..500 {
    input.push_str(&format!(
      " 1:40:09.{i:04}  Add        3  {i} local. _other._tcp. Other-{i}\n"
    ));
  }
  input.push_str(&reply_line("BonjourAdv-42"));
  assert_eq!(watch(input), vec![Ok("BonjourAdv-42".to_string())]);
}

#[test]
fn registration_watcher_drains_output_after_reporting_exactly_once() {
  let mut input = reply_line("BonjourAdv-42");
  for i in 0..500 {
    input.push_str(&reply_line(&format!("Later-{i}")));
  }
  // Returning at all means the watcher consumed to the end rather than stopping
  // at the reply, and one message means the channel can never back up under it.
  assert_eq!(watch(input), vec![Ok("BonjourAdv-42".to_string())]);
}

#[test]
fn registration_watcher_survives_an_overlong_line() {
  let mut input = "x".repeat(64 * 1024);
  input.push('\n');
  input.push_str(&reply_line("BonjourAdv-42"));
  assert_eq!(watch(input), vec![Ok("BonjourAdv-42".to_string())]);
}

/// One `dns-sd -B` event, spaced as the tool prints its columns.
fn event(kind: &str, interface: &str, instance: &str) -> String {
  format!(
    " 1:40:11.446  {kind}        3  {interface} local.               _hick-parity._tcp.   {instance}"
  )
}

#[test]
fn parser_retains_the_local_only_pseudo_interface() {
  let lines = vec![event("Add", "-1", "BonjourAdv-42")];
  assert_eq!(advertised_interfaces(&lines, "BonjourAdv-42"), vec![-1]);
}

#[test]
fn parser_retains_index_zero() {
  let lines = vec![event("Add", "0", "BonjourAdv-42")];
  assert_eq!(advertised_interfaces(&lines, "BonjourAdv-42"), vec![0]);
}

#[test]
fn parser_collects_positive_indices_without_duplicates() {
  let lines = vec![
    event("Add", "1", "BonjourAdv-42"),
    event("Add", "7", "BonjourAdv-42"),
    event("Add", "7", "BonjourAdv-42"),
  ];
  assert_eq!(advertised_interfaces(&lines, "BonjourAdv-42"), vec![1, 7]);
}

#[test]
fn parser_drops_an_interface_that_was_removed() {
  let lines = vec![
    event("Add", "7", "BonjourAdv-42"),
    event("Rmv", "7", "BonjourAdv-42"),
  ];
  assert!(advertised_interfaces(&lines, "BonjourAdv-42").is_empty());
}

#[test]
fn parser_keeps_an_interface_re_added_after_removal() {
  let lines = vec![
    event("Add", "7", "BonjourAdv-42"),
    event("Rmv", "7", "BonjourAdv-42"),
    event("Add", "7", "BonjourAdv-42"),
  ];
  assert_eq!(advertised_interfaces(&lines, "BonjourAdv-42"), vec![7]);
}

#[test]
fn parser_removes_only_the_named_interface() {
  let lines = vec![
    event("Add", "1", "BonjourAdv-42"),
    event("Add", "7", "BonjourAdv-42"),
    event("Rmv", "7", "BonjourAdv-42"),
  ];
  assert_eq!(advertised_interfaces(&lines, "BonjourAdv-42"), vec![1]);
}

#[test]
fn parser_ignores_a_removal_of_an_interface_never_added() {
  let lines = vec![event("Rmv", "7", "BonjourAdv-42")];
  assert!(advertised_interfaces(&lines, "BonjourAdv-42").is_empty());
}

#[test]
fn parser_ignores_events_for_another_instance() {
  let lines = vec![
    event("Add", "7", "BonjourAdv-42"),
    event("Rmv", "7", "SomeoneElse-99"),
  ];
  assert_eq!(advertised_interfaces(&lines, "BonjourAdv-42"), vec![7]);
}

#[test]
fn parser_reports_nothing_when_no_event_names_our_instance() {
  let lines = vec![event("Add", "7", "SomeoneElse-99")];
  assert!(advertised_interfaces(&lines, "BonjourAdv-42").is_empty());
}

#[test]
fn parser_requires_an_exact_instance_match() {
  let lines = vec![event("Add", "7", "BonjourAdv-421")];
  assert!(advertised_interfaces(&lines, "BonjourAdv-42").is_empty());
}

#[test]
fn parser_matches_the_instance_case_insensitively() {
  let lines = vec![event("Add", "7", "BONJOURADV-42")];
  assert_eq!(advertised_interfaces(&lines, "bonjouradv-42"), vec![7]);
}

#[test]
fn parser_ignores_banner_header_and_malformed_lines() {
  let lines = vec![
    "Browsing for _hick-parity._tcp.local.".to_string(),
    "DATE: ---Mon 03 Aug 2026---".to_string(),
    " 1:40:11.445  ...STARTING...".to_string(),
    "Timestamp     A/R    Flags  if Domain               Service Type         Instance Name"
      .to_string(),
    " 1:40:11.446  Add        3  7".to_string(),
    event("Add", "seven", "BonjourAdv-42"),
  ];
  assert!(advertised_interfaces(&lines, "BonjourAdv-42").is_empty());
}

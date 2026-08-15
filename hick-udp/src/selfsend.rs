//! Take-once tracker for our own multicast loopback.
//!
//! Joining the mDNS multicast group and sending to it means the kernel loops
//! our own datagrams straight back to us on the same socket. Without
//! suppression the driver would ingest its own announcements as if they came
//! from a peer, seeing phantom conflicts against itself. [`SelfSendTracker`]
//! keeps the **exact bytes** of every datagram we send and consumes the
//! matching credit when the loopback copy arrives — take-once, so a genuine
//! byte-identical datagram from a co-resident peer received afterwards is still
//! seen as a peer, not swallowed as our own echo.
//!
//! # The match is the bytes, never a digest of them
//!
//! This held a 64-bit FNV-1a fingerprint until a second-preimage against one was
//! demonstrated in **fifteen seconds** on a laptop — meet-in-the-middle over
//! FNV's own invertible state update, with the free trailing bytes that
//! `MessageReader` ignores carrying the solution. The forged datagram was a
//! valid mDNS response announcing a *different* address at the same host name.
//!
//! What that bought an attacker was the whole of a credit: the forged datagram
//! consumed it, was suppressed as our echo, and the genuine echo behind it found
//! nothing left and reached the protocol layer as peer traffic. A digest is the
//! wrong shape for this job whatever its width, because the only thing
//! suppression may safely swallow is a datagram that says exactly what ours
//! said. Under exact matching a forged self-datagram must be byte-identical to
//! ours, so it carries our own RFC 6762 §8.2 proposal and ties under §8.2.1, and
//! its §9 rdata is ours and is "never a conflict" by definition. See
//! [`MAX_SELF_SEND_BYTES`] for what holding the bytes costs.
//!
//! Every credit is keyed to the **address family it was sent on** — see
//! [`SelfSendTracker::claim`] for the dual-stack echo race that makes
//! content-and-time matching alone insufficient.
//!
//! # One implementation, because three drifted
//!
//! This lives here, one layer below the socket drivers, because it was written
//! out three times and the three copies disagreed on seven points — four of them
//! defects: the [`SELF_SEND_TTL`] measured on the wall clock, no wall-step
//! detection, a hard-coded pre-send slack in place of
//! [`crate::RX_TIMESTAMP_GRAIN`], and a sweep that dropped every future-stamped
//! credit. Two of the three carried a comment claiming they matched the others,
//! which is why a cross-reference is not the mechanism that keeps them together
//! and a shared type is.
//!
//! A driver that needs *different* semantics needs its own type rather than a
//! fourth copy of this one. The `no_std` stacks are exactly that case: they own
//! their IP stack, match on exact bytes, and cannot have a [`SystemTime`] at
//! all.
//!
//! # The evidence travels with its datagram
//!
//! A claim weighs a body against a stamp, and the two are only worth anything
//! together: a genuine kernel stamp belonging to some *other* receive is weighed
//! at full strength against whatever body it arrives beside. [`RxDatagram`] is
//! that pair — family, body and stamp in one value that cannot be taken apart —
//! and [`SelfSendTracker::claim`] accepts nothing else. [`recv_datagram`] mints
//! one by performing the receive itself, so on the paths that can use it no
//! caller chooses a length or a time at all.

// The invariants this module turns on live in its private half — the two-stamp
// `Credit`, the expiry-ordered `entries`, the derivation in `evidence_mode`.
// Public docs that state a rule and then name the code enforcing it are worth
// more than public docs that state the rule and stop, and publishing that half
// to satisfy the link checker would put internal seams into this crate's API.
#![allow(rustdoc::private_intra_doc_links)]

use std::{
  borrow::Cow,
  time::{Duration, Instant as StdInstant, SystemTime},
};

use crate::{Family, RX_TIMESTAMP_GRAIN};
// `recv_datagram` is the only code here that names the type, and it performs the
// receive itself — a `recvmsg` this crate only has on Unix. Windows drivers do
// their own receive and mint through `RxDatagram::without_stamp`, so an
// unconditional import would be dead there.
#[cfg(unix)]
use crate::RecvMeta;

/// How long a recorded send stays eligible to match an inbound loopback,
/// measured from the **first instant its echo could be claimed** rather than
/// from the send. Multicast loopback is delivered on the same host within
/// microseconds, so 2s is generously longer than any real loopback latency,
/// while still short enough that a byte-identical datagram from a co-resident
/// peer arriving later is correctly treated as a peer rather than our echo.
/// Both [`MatchMode`]s are bounded above by this TTL.
///
/// # The clock starts at the first claim opportunity
///
/// **A credit's ageing must not begin until the first instant its echo is
/// claimable — the [`SelfSendTracker::seal`] that follows the send and precedes
/// the driver's next receive — and from then on charges real monotonic elapsed
/// time, including caller latency.** Both halves are load-bearing.
///
/// The recording iteration's outbound time is *structurally* claim-free: the
/// stretch between a record and the end of the iteration it was recorded in is
/// the driver's own scheduling, and charging it to a window that exists to bound
/// the echo's *flight* is a defect. It expired credits three separate ways
/// before this anchor moved: a stall between a send's pre-syscall stamp and its
/// syscall, a later send in the same iteration stalling after an earlier credit
/// was already recorded, and a goodbye recorded a full TTL after the
/// announcement whose credit was still unclaimed. All three are the one bug, and
/// [`SelfSendTracker::seal`] closes all three at once — by construction,
/// wherever the outbound stages later move to.
///
/// Post-opportunity time, in contrast, **must** be charged, caller stalls
/// included. This TTL's other job is bounding FALSE suppression, and a
/// co-resident peer's byte-identical datagram can arrive during a caller stall
/// just as easily as during an iteration. Excluding non-running time — ageing by
/// iteration count, say — would couple the suppression window to the driver's
/// loop rate, which is wrong in both directions: a fast loop would expire live
/// credits and a slow one would suppress peer traffic indefinitely.
///
/// # Not the echo's arrival time
///
/// Ageing against when the echo *arrived* was considered and rejected. The only
/// arrival stamp is the kernel's rx wall clock, which re-couples this bound to
/// the wall clock and to the pre-syscall stamp — resurrecting the very defect
/// the two-stamp split exists to prevent — and [`MatchMode::Degraded`] has no
/// arrival stamp at all.
///
/// # It is measured on the MONOTONIC clock, and never on the wall clock
///
/// Ageing a credit is a *duration* question — "has this credit been waiting
/// longer than a loopback copy can take?" — and the wall clock answers it
/// wrongly twice over. It steps, so an NTP correction either expires a live
/// credit or keeps a dead one; and the only wall stamp a send has is read
/// **before** its syscall, so every microsecond between that read and the
/// kernel accepting the datagram is charged to the credit's life. Preemption, a
/// signal handler, a page fault, or the `EINTR` retry can each stretch that gap,
/// and a gap past this TTL makes a responder ingest its own announcement as
/// peer traffic — a phantom conflict against itself and the RFC 6762 §9 rename
/// that follows.
///
/// So [`Credit`] carries two stamps that must not be folded together:
/// [`Credit::sent`] orders the echo against the send, and
/// [`Credit::aged_from`] — monotonic, and set at the first claim opportunity —
/// is the only input to this bound. See both field docs for the one direction
/// each may be wrong in.
///
/// # What the false-suppression window really is
///
/// Not this constant alone. A byte-identical co-resident peer datagram can be
/// swallowed as our echo for up to **this TTL, plus the outbound residue of the
/// recording iteration, plus one caller gap** — the residue because the credit
/// does not start ageing until the seal that follows the send, and the caller gap
/// because a driver reaches that seal when it reaches it. On a loop running at any
/// sane rate the extra is negligible against 2s, and it buys the elimination of
/// the under-retention direction, which is the expensive one: over-retaining
/// costs one mistaken peer datagram, while under-retaining makes this responder
/// raise a phantom conflict against **itself** and rename under RFC 6762 §9.
///
/// # Accepted residual
///
/// A driver that stalls for `SELF_SEND_TTL` or longer **after the seal**, with
/// an echo already pending, still expires that credit — between two iterations,
/// or inside the receive stage itself, since both are time the window was open
/// and the claim did not happen. The seal happened, the clock ran, and no claim
/// got to it. A stall that size degrades RFC 6762 probe timing and §8.3
/// announcement spacing regardless, so the endpoint is mis-timed either way. It
/// is unfixable without ageing from the echo's arrival time,
/// which the section above rules out and which [`MatchMode::Degraded`] cannot
/// supply at all — and forgiving it is not an option, because the forgiveness
/// would have no bound: the same stall is indistinguishable from the one during
/// which a co-resident peer's byte-identical datagram arrived.
pub const SELF_SEND_TTL: Duration = Duration::from_secs(2);

/// Memory backstop on live [`SelfSendTracker`] entries. The real bound is
/// [`SELF_SEND_TTL`]; under normal operation the tracker holds only a
/// handful of entries.
///
/// **It counts credits that are still alive.** At the cap,
/// [`SelfSendTracker::record`] first reclaims every entry that is already dead —
/// sealed and past the TTL — and then decides, against a clock read **at the
/// decision** ([`SelfSendTracker::admit`]), whether the new entry still has
/// nowhere to go. It never evicts a live one: a flood of sends must not
/// displace a credit that is still waiting to match its own loopback copy, and
/// equally a heap of corpses must not displace a credit that has not been
/// recorded yet. See [`SelfSendTracker::reclaim_expired_sealed`] for why only
/// the dead half is reclaimable, and [`SelfSendTracker::admit`] for why the
/// reclaim's own length is not an answer to the cap question.
///
/// It is one of TWO backstops and neither implies the other: this one bounds
/// how many small datagrams may be resident, [`MAX_SELF_SEND_BYTES`] bounds how
/// much memory large ones may hold. Both are checked, and either can be the one
/// that refuses.
pub const MAX_SELF_SEND_ENTRIES: usize = 65536;

/// Memory backstop on the BYTES held in live credits, since a credit now stores
/// the datagram rather than a digest of it.
///
/// # Why storing the bytes is the only sound match, and why it is affordable
///
/// A digest lets a *different* datagram claim the credit, and that is the whole
/// of the danger: a datagram byte-identical to ours carries our own RFC 6762
/// §8.2 proposal (which ties under §8.2.1) and our own §9 rdata (which is "never
/// a conflict"), so suppressing it completely can delete nothing that a
/// conforming responder needed. A colliding datagram carries whatever its author
/// chose. With a 64-bit FNV-1a fingerprint that author needed **fifteen seconds
/// on a laptop** — see this module's header.
///
/// The naive worry about exact matching is
/// [`MAX_SELF_SEND_ENTRIES`] × the largest datagram, which is 98 MB at a
/// 1500-byte MTU and 4.3 GB at the 64 KiB ceiling. That product is not what the
/// tracker holds, because the entry cap is a backstop rather than a working set:
/// a credit lives from its send to its loopback copy, multicast loopback is
/// delivered on the same host in microseconds, and [`SELF_SEND_TTL`] bounds even
/// a lost one at two seconds. The resident set in normal operation is one credit
/// per family per in-flight datagram — a handful.
///
/// So the bound that matters is a byte budget, exactly as `hick-smoltcp`'s
/// no-`std` ring already uses one. This value holds ~715 datagrams at a
/// 1500-byte MTU, or 16 at the 64 KiB ceiling, against a realistic worst case of
/// one announcement per registered service per family recorded before a single
/// seal. It costs one megabyte of resident memory in the pathological case and
/// nothing measurable in the ordinary one.
///
/// # Refusing is the expensive direction here too
///
/// A refused credit is this endpoint ingesting its own loopback as peer traffic
/// — a phantom conflict against itself and the RFC 6762 §9 rename that follows —
/// so this budget, like the entry cap, reclaims dead credits before it refuses a
/// new one and never evicts a live one. See [`SelfSendTracker::admit`].
pub const MAX_SELF_SEND_BYTES: usize = 1 << 20;

/// How far the wall clock may disagree with the monotonic clock across a
/// credit's window before that credit's ordering evidence is treated as
/// unusable.
///
/// # What it is measuring
///
/// [`Credit::sent`] is the only thing that orders an echo against its send, and
/// its wall half is not monotonic. An NTP step, a `settimeofday`, a manual clock
/// change, or a VM suspend/resume moves it under a credit that is already
/// waiting, and the stamp then describes a timeline the echo's kernel receive
/// stamp was never taken on. A monotonic stamp cannot replace it — the kernel's
/// receive stamp is itself a realtime value, so there is nothing monotonic to
/// compare it against — so the fix is a second stamp rather than a different
/// one: every credit carries the monotonic partner of its wall stamp, every
/// claim reads both clocks the same way, and the difference of the two elapsed
/// times is what the wall clock did on its own. See [`ClockPair`].
///
/// # Why this size
///
/// It must sit **above** every legitimate disagreement. A disciplined wall clock
/// is slewed rather than stepped, at up to 500 ppm — 1 ms across
/// [`SELF_SEND_TTL`], and 5 ms even across a ten-second caller stall — on top of
/// each clock's own resolution and the few nanoseconds between the paired reads.
///
/// It must sit **below** every real step. `ntpd` slews rather than steps until
/// the offset passes 128 ms; `settimeofday`, a manual clock change and a VM
/// resume are larger still, usually by orders of magnitude.
///
/// # Accepted residual
///
/// A backward step smaller than this is invisible here and can still reject one
/// echo. [`reference_ordered`]'s [`RX_TIMESTAMP_GRAIN`] arm absorbs
/// the truncation-scale end of that range already, and what is left is bounded
/// to a single credit and a single datagram. Tightening it further would buy
/// that back at the price of degrading every claim on a merely slewed host,
/// which is by far the more common condition.
pub const WALL_STEP_TOLERANCE: Duration = Duration::from_millis(50);

/// One received datagram **and** the evidence about when the kernel saw it, in a
/// value that cannot be taken apart.
///
/// **Association is a property of this type, not an obligation on the caller.**
/// Is this stamp the stamp for the bytes it is being weighed against? Here the
/// question cannot be asked wrongly: [`SelfSendTracker::claim`] takes one value,
/// and the three facts inside it came from one receive. There is nothing to
/// pair, so there is no pairing to get wrong.
///
/// # NOT `Copy`, and NOT `Clone`
///
/// Deliberately, and it is the whole mechanism rather than an oversight. A stamp
/// that cannot be lifted out of its datagram cannot be laid beside another one.
/// The three-argument claim this replaced weighed the family, the body and the
/// evidence independently, over `Copy` evidence and a `Copy` [`RecvMeta`], which
/// is what made a stamp from one receive weighable against another receive's
/// body — both directions live, and neither costing merely a lost byte:
///
/// * a stamp from a **later** receive lets a byte-identical datagram the kernel
///   saw *before* our `sendto` pass the ordering test and take the take-once
///   credit. A real peer's datagram is then swallowed as our loopback — so a
///   conflict it carried is never seen — and our own echo, finding no credit
///   left, reaches the protocol layer as peer traffic;
/// * a stamp from an **earlier** receive rejects the genuine echo, which reaches
///   the protocol layer as peer traffic for the other reason.
///
/// Either way it is a phantom RFC 6762 §9 conflict against ourselves and the
/// rename that follows. **Neither is reachable now**, and that is what the
/// missing traits buy. There is also no public accessor for the stamp: it is
/// read by [`SelfSendTracker::claim`] and by nothing else, so it has no path out
/// of the datagram it arrived with.
///
/// The absence of `Clone` is the whole mechanism, so it is pinned rather than
/// stated — this does not compile, and a derive added later would make it:
///
/// ```compile_fail
/// fn assert_clone<T: Clone>() {}
/// // `Copy` requires `Clone`, so refusing this refuses both.
/// assert_clone::<hick_udp::selfsend::RxDatagram<'static>>();
/// ```
///
/// # What it does NOT settle: origin
///
/// The second question — did a KERNEL write this stamp? — is untouched, and it
/// stays an obligation because nothing here can discharge it. Where this crate
/// performs the receive itself ([`recv_datagram`]) origin is a property of the
/// call, and there is nothing left for a caller to get wrong on those paths at
/// all. Where a driver performs its own, [`RxDatagram::from_recv_parts`] parses
/// the caller's control buffer and **cannot tell a buffer a kernel filled from a
/// buffer a caller encoded**.
///
/// **What changes there is distance, not enforcement, and it is worth being
/// precise about how much.** `hick-compio` is completion-based: it submits its
/// own `recv_msg` and owns the control buffer that comes back, so this crate is
/// not present at its receive and `from_recv_parts` remains a caller contract
/// there — stated as one, in that driver, at the one statement that has to be
/// right. But the obligation shrinks from one that spans a mint, a struct field,
/// a channel and a claim to one statement adjacent to the syscall with both
/// buffers already in scope. Getting it wrong is not a lost byte: a stamp that
/// does not order the datagram against our `sendto` still runs the claim at
/// [`MatchMode::Ordered`] strength, which re-opens the credit-theft window
/// above.
///
/// # No public constructor takes a bare [`SystemTime`]
///
/// Outside `test-support` there is none, and that is load-bearing rather than
/// tidy: [`RecvMeta::rx_time`] is still public, so a constructor accepting a
/// time would re-open the decoupled path in one line — read a stamp off one
/// meta, build a datagram around another body. The two production constructors
/// take a control buffer ([`RxDatagram::from_recv_parts`]) or declare the
/// absence of one ([`RxDatagram::without_stamp`]).
///
/// # Why the body is a [`Cow`]
///
/// Because the drivers carry payloads three ways and a single choice would cost
/// one of them: `hick-reactor` moves the payload across a channel inside its
/// packet type, which a borrowing-only body would make self-referential;
/// `hick-mio` slices from a reused buffer, where an owning-only body would add
/// an allocation that does not exist today; and `hick-compio` already owns a
/// `Vec`. Do not "simplify" it to a bare lifetime or to an owned `Vec`.
///
/// # A reported length longer than the buffer is a DROP
///
/// **This is the one answer, stated once so a driver cannot pick a second.** A
/// receive that reports more bytes than the buffer it was given did not deliver
/// them, so there is no datagram here to weigh: drop it. Never fall back to the
/// whole buffer, and never truncate the report and carry on.
///
/// Both wrong answers hand a body downstream that is not what arrived, and after
/// this type that body is what a self-send credit is keyed on: the claim
/// compares whatever is passed, so a buffer's stale tail is compared into it.
/// The claim then misses the credit our own echo was recorded for — and the echo
/// that follows finds none left and reaches the protocol layer as peer traffic,
/// which is a phantom RFC 6762 §9 conflict against ourselves and the rename that
/// follows. The same bytes are also what the protocol layer parses.
///
/// [`recv_datagram`] enforces it for the paths it serves — it slices the body
/// itself and returns [`std::io::ErrorKind::InvalidData`] rather than a body the
/// receive did not report. A path that mints through [`Self::without_stamp`]
/// does its own receive and must apply the same rule before it constructs one:
/// `hick-reactor`'s plain `recv_from` arm and both Windows arms are exactly
/// those paths.
pub struct RxDatagram<'a> {
  /// The socket the datagram arrived on, and therefore the only family whose
  /// credits it may claim. See [`SelfSendTracker::claim`] for the dual-stack echo
  /// race this key closes.
  family: Family,
  /// The datagram body, exactly as long as the receive reported.
  body: Cow<'a, [u8]>,
  /// The kernel receive timestamp for THIS body, or `None` where the platform
  /// delivered no timestamp cmsg. Read only by [`SelfSendTracker::claim`].
  stamp: Option<SystemTime>,
}

impl<'a> RxDatagram<'a> {
  /// The datagram, with its stamp read out of the control buffer **that
  /// receive** produced — by this crate's parser rather than the caller's.
  ///
  /// For a driver whose I/O model this crate's blocking receive path does not
  /// fit: a completion-based one that submits its own `recvmsg` and owns the
  /// control buffer that comes back, so there is no [`recv_datagram`] to call.
  ///
  /// # What it buys: one reading of the cmsg, and one statement to get wrong
  ///
  /// The stamp comes out of the same parser [`crate::recv_with_meta`] uses, so
  /// every driver in this workspace agrees on what an
  /// `SCM_TIMESTAMP`/`SCM_TIMESTAMPNS` cmsg says — the sub-second field's width
  /// and units, which `SCM_*` type this target delivers, what a short or negative
  /// field means. It is also sound on arbitrary input: every offset is
  /// slice-bounds-checked and each header read unaligned, so a truncated,
  /// misaligned or malformed buffer yields no stamp rather than a misread one.
  ///
  /// And because body and buffer are arguments to the same call, the two are
  /// paired where both are in scope — one statement, next to the syscall —
  /// rather than at a claim somewhere downstream.
  ///
  /// # What it does NOT buy: this crate cannot check where the bytes came from
  ///
  /// **`cmsgs` must be the control buffer a kernel filled for the receive that
  /// produced `body`** — `msg_control` truncated to the reported
  /// `msg_controllen`. Nothing here can verify that. A caller can encode a
  /// well-formed timestamp cmsg carrying a value it invented and get back
  /// ordering evidence for that value; this crate is not present at the
  /// `recvmsg` that would make the buffer true.
  ///
  /// Getting it wrong is not a lost byte. A stamp that does not order the
  /// datagram against our `sendto` — a userspace read time, an invented value, a
  /// buffer kept from an earlier receive — still runs the claim at
  /// [`MatchMode::Ordered`] strength, which re-opens the credit-theft window this
  /// type's own docs describe.
  ///
  /// If you do not have such a buffer, [`Self::without_stamp`] is the correct
  /// answer and costs only the ordering arm. It is also what a buffer with no
  /// timestamp cmsg in it produces: the claim is weighed under
  /// [`MatchMode::Degraded`], never unsound, only weaker.
  #[cfg(unix)]
  #[must_use]
  pub fn from_recv_parts(family: Family, body: impl Into<Cow<'a, [u8]>>, cmsgs: &[u8]) -> Self {
    Self {
      family,
      body: body.into(),
      stamp: crate::multicast::parse_rx_time(cmsgs),
    }
  }

  /// The datagram, declaring that **no kernel receive timestamp is available**
  /// for it.
  ///
  /// Windows, a `recv_from`-shaped receive path that never asks for ancillary
  /// data, and a Unix kernel that delivered no timestamp cmsg all reach the same
  /// state, and it is a state rather than a failure: the claim is weighed under
  /// [`MatchMode::Degraded`] — content, family and [`SELF_SEND_TTL`], with no
  /// ordering test at all. Passing this is never unsound, only weaker.
  ///
  /// It exists as its own constructor because [`Self::from_recv_parts`] is
  /// cmsg-based and Unix-only, and the paths above have no cmsgs to hand it —
  /// not even an empty buffer would be honest, since "the kernel emitted no
  /// timestamp" and "this path never asked for one" are the same answer here but
  /// not the same fact.
  #[must_use]
  pub fn without_stamp(family: Family, body: impl Into<Cow<'a, [u8]>>) -> Self {
    Self {
      family,
      body: body.into(),
      stamp: None,
    }
  }

  /// A datagram carrying a stamp a **test** chose, standing in for one a kernel
  /// wrote.
  ///
  /// The same unverifiable contract [`Self::from_recv_parts`] carries, in the
  /// shape a test can actually use: `rx` is meant to be the value a kernel
  /// stamped on this body, and nothing here can check that. A test wanting a
  /// stamp one millisecond after a credit's send would otherwise hand-encode a
  /// native timestamp cmsg to say so, which is `unsafe`, per-target, and proves
  /// nothing the one-liner does not.
  ///
  /// Behind `test-support` because it is the **only** public door through which
  /// a bare [`SystemTime`] becomes ordering evidence, and a default build must
  /// not have one: [`RecvMeta::rx_time`] is public, so a production constructor
  /// taking a time would let any caller re-assemble the decoupled pair this type
  /// exists to prevent. The gate is a speed bump on the trivial door rather than
  /// a proof that no door exists — [`Self::from_recv_parts`] is safe, public and
  /// reachable from any dependent, at the cost of encoding a real cmsg.
  ///
  /// It is also the only deterministic way to put a stamp at a chosen offset from
  /// a credit's send, which is the whole subject of [`crate::RX_TIMESTAMP_GRAIN`]
  /// and [`WALL_STEP_TOLERANCE`].
  #[cfg(any(test, feature = "test-support"))]
  #[must_use]
  pub fn from_stamp_for_test(
    family: Family,
    body: impl Into<Cow<'a, [u8]>>,
    rx: SystemTime,
  ) -> Self {
    Self {
      family,
      body: body.into(),
      stamp: Some(rx),
    }
  }

  /// The family whose socket carried this datagram.
  #[must_use]
  pub const fn family(&self) -> Family {
    self.family
  }

  /// The datagram body.
  #[must_use]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// Take the body out, consuming the datagram.
  ///
  /// Consuming rather than borrowing because that is the only way to hand the
  /// payload onward without leaving a stamp behind that could be weighed against
  /// something else: once the body is out, the datagram is gone. A driver that
  /// still needs to claim should do so first — [`SelfSendTracker::claim`] borrows.
  #[must_use]
  pub fn into_body(self) -> Cow<'a, [u8]> {
    self.body
  }

  /// The same datagram with its body owned, so it can outlive the buffer it was
  /// received into.
  ///
  /// For a driver that receives on one task and claims on another:
  /// `hick-reactor` reads into a reused buffer and moves the result across a
  /// channel, which a borrowed body cannot cross. It copies only when the body
  /// is still borrowed, and it is exactly the `to_vec` that driver already did
  /// before this type existed.
  ///
  /// # It is not a `Clone` door
  ///
  /// It **consumes** the datagram and carries the same stamp onto the same
  /// bytes, so there is never a second value to lay beside a different body —
  /// which is the whole of what the absent `Clone` buys (see this type's docs).
  /// A `&self` version returning a new datagram would be `Clone` under another
  /// name, and must not be added.
  #[must_use]
  pub fn into_owned(self) -> RxDatagram<'static> {
    RxDatagram {
      family: self.family,
      body: Cow::Owned(self.body.into_owned()),
      stamp: self.stamp,
    }
  }

  /// The stamp, for this module's own weighing. Private, and there is no public
  /// counterpart: see this type's docs for why the stamp has no path out.
  const fn stamp(&self) -> Option<SystemTime> {
    self.stamp
  }
}

// Manual rather than derived, on both halves. The body is printed as a LENGTH
// because a datagram is peer-controlled bytes and a trace line is not the place
// to spill them; the stamp is printed as presence rather than value because
// publishing it in a `Debug` string would hand back exactly what having no
// accessor withholds.
impl core::fmt::Debug for RxDatagram<'_> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("RxDatagram")
      .field("family", &self.family)
      .field("len", &self.body.len())
      .field("stamped", &self.stamp.is_some())
      .finish()
  }
}

/// Receive one datagram on `fd` and mint the [`RxDatagram`] for it, so that the
/// body and the stamp are never separately chosen by a caller.
///
/// The strongest form this crate has, and the reason is narrow: **this crate
/// performs the receive**, so the stamp's origin is a property of the call and
/// the association is a property of the slicing, which happens here. There is no
/// argument a caller can get wrong — no length, no buffer, no time.
///
/// `fd` must be a valid UDP socket fd, and non-blocking if the caller expects
/// [`std::io::ErrorKind::WouldBlock`] rather than a park. The returned
/// [`RecvMeta`] carries everything the receive witnessed — peer, destination,
/// interface, hop limit, delivery class — and the RFC 6762 §11 admission
/// decision is made on it, not on the datagram.
///
/// The buffer is downgraded from `&mut` to a shared borrow of the same lifetime,
/// so the body borrows the caller's buffer with no copy; a driver that needs to
/// own the payload converts afterwards, and one that reuses the buffer holds the
/// datagram only as long as the borrow.
///
/// # Errors
///
/// Whatever [`crate::recv_with_meta`] returns: `WouldBlock` when no datagram is
/// ready, and [`std::io::ErrorKind::InvalidData`] for a datagram too large for
/// `buf` (`MSG_TRUNC`) or an unrecognized peer address family. A datagram that
/// arrived with no ancillary metadata is NOT an error — it degrades, and the
/// resulting claim runs under [`MatchMode::Degraded`].
///
/// `InvalidData` is also what a receive reporting more bytes than `buf` holds
/// produces, because that datagram is dropped rather than approximated — see
/// [`RxDatagram`] for the one answer and why the two approximations are worse
/// than losing it.
#[cfg(unix)]
pub fn recv_datagram<'b>(
  fd: std::os::fd::RawFd,
  buf: &'b mut [u8],
  family: Family,
) -> std::io::Result<(RxDatagram<'b>, RecvMeta)> {
  let meta = crate::recv_with_meta(fd, buf, family.is_v4())?;
  let len = meta.len();
  // The mint slices, so no caller picks a length. `recv_with_meta` clamps the
  // reported length to the buffer it was given, so the error arm is unreachable
  // from here; it is an ERROR rather than a fallback to the whole buffer because
  // this is the one place that answer is written down, and a driver reading it
  // for its own Windows or `recv_from` arm must find the rule and not an
  // approximation. See `RxDatagram`.
  let buf: &'b [u8] = buf;
  let Some(body) = buf.get(..len) else {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "the receive reported more bytes than the buffer holds",
    ));
  };
  Ok((
    RxDatagram {
      family,
      body: Cow::Borrowed(body),
      stamp: meta.rx_time(),
    },
    meta,
  ))
}

/// One reading of BOTH clocks, taken back to back.
///
/// The pair is the unit, and the halves are never taken apart. A wall stamp is
/// only comparable with another wall stamp taken on the same timeline, and the
/// monotonic partner is the only thing that can say whether that timeline held;
/// a lone wall stamp cannot distinguish two seconds of elapsed time from a
/// two-second step.
///
/// **Both ends read `wall` first and `mono` second**, which is load-bearing
/// twice over. The nanoseconds between the two reads then have the same sign at
/// each end and cancel in the subtraction rather than accumulating into
/// [`WALL_STEP_TOLERANCE`]; and the monotonic read — the one [`SELF_SEND_TTL`]
/// is measured on — stays the last thing that happens before the comparison it
/// feeds, which is the floor [`SelfSendTracker::claim`] documents.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClockPair {
  /// Wall clock. Ordering only — never an age, on either end of the comparison.
  pub wall: SystemTime,
  /// The monotonic reading taken immediately after [`ClockPair::wall`].
  pub mono: StdInstant,
}

impl ClockPair {
  /// Read both clocks here, wall first. The only way production reaches a
  /// pair that was not taken from one syscall's own stamps.
  pub fn now() -> Self {
    Self {
      wall: SystemTime::now(),
      mono: StdInstant::now(),
    }
  }

  /// Adopt two readings a caller already holds.
  ///
  /// **The caller owes the adjacency this type is built on**: the two stamps
  /// must be read on consecutive statements, wall first, with nothing between
  /// them. A driver reaches this with the pair its send path took immediately
  /// before the `sendto`; a pair assembled from two readings taken at different
  /// moments is not a [`ClockPair`] and will read as a clock step.
  pub const fn new(wall: SystemTime, mono: StdInstant) -> Self {
    Self { wall, mono }
  }
}

/// How much ordering evidence a claim actually has.
///
/// It is **derived, never declared**: [`SelfSendTracker::claim`] settles it from
/// whether the platform delivered a kernel receive timestamp, and
/// [`evidence_mode`] then weakens it per credit when that credit's own wall
/// stamp did not survive a clock step. No caller can hand in a mode.
///
/// That is structural, not a convention: this type has no public constructor,
/// and no function anywhere — public or private — takes a mode from outside this
/// module. What a claim now does is **report** the mode it derived, through
/// [`SelfSendMatch`], because a driver mapping an echo onto a trust tier needs to
/// know which of the two strengths its suppression actually ran at. So the
/// value escapes; the ability to choose it does not. It stays public so a
/// driver's own documentation can name the two states. A later change that adds
/// a mode PARAMETER to any function undoes the guarantee, whatever this
/// paragraph says.
///
/// # What the derivation bounds, and what it does not
///
/// It bounds what a caller can *declare*. It does not make `Ordered` mean the
/// stamp is a KERNEL's: the derivation reads whether the datagram carries a
/// stamp, and cannot read where that stamp came from. A value a caller invented
/// and encoded as a timestamp cmsg derives `Ordered` and is weighed at full
/// strength. What association it belongs to is settled — the stamp arrived
/// inside the datagram being weighed and could not have come from another
/// receive — but origin remains the caller's obligation wherever the caller owns
/// the `recvmsg`. See [`RxDatagram`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MatchMode {
  /// The reference is a receive timestamp presented as the kernel's for this
  /// datagram, and the credit's wall stamp is on the same timeline it was taken
  /// on. A datagram is ours only if it was
  /// stamped at-or-after the recorded send — within
  /// [`RX_TIMESTAMP_GRAIN`]. That ordering requirement is what stops
  /// a byte-identical peer datagram the kernel saw *before* our `sendto` from
  /// stealing the take-once credit. The [`SELF_SEND_TTL`] bound is applied
  /// separately, on the monotonic clock.
  Ordered,
  /// There is no ordering evidence to weigh, so matching is content hash plus
  /// family, bounded by [`SELF_SEND_TTL`], and nothing else. **The reference is
  /// not consulted at all** — see [`reference_ordered`] for why weighing one
  /// here could only ever reject our own echo.
  ///
  /// Two routes reach it, and they degrade to the same thing:
  ///
  /// * no kernel receive timestamp was available — Windows, or a Unix kernel
  ///   that delivered no timestamp cmsg — so the only wall value the claim could
  ///   offer is a userspace read time, which says nothing about when the kernel
  ///   saw the datagram;
  /// * the wall clock stepped between the send and the claim, so the credit's
  ///   own wall stamp is not on the timeline the receive stamp was taken on. See
  ///   [`WALL_STEP_TOLERANCE`].
  ///
  /// It is enough to suppress our own loopback in the ordinary single-host case,
  /// but by construction it cannot defend the credit-theft race that `Ordered`
  /// guards against. **That is the cheap direction, and it is chosen
  /// deliberately.**
  ///
  /// # What is given up is narrower than "ordering"
  ///
  /// Ordering only ever *rejects*, and it only ever rejects a datagram the
  /// kernel stamped BEFORE our `sendto`. Anything the kernel saw at or after it
  /// already claims the credit under `Ordered` too — see [`reference_ordered`] —
  /// so the whole of the marginal exposure here is a datagram that was already
  /// queued when the send it claims was made. It still has to arrive on the same
  /// family, from source port 5353 (a driver offers a credit to no other port,
  /// since that is the only port an mDNS endpoint sends from — see
  /// [`SelfSendTracker::claim`]), carrying the **same bytes**, inside
  /// [`SELF_SEND_TTL`].
  ///
  /// # What one costs, and why matching on the bytes is what bounds it
  ///
  /// One datagram, once. The case that can arise without an author arranging it
  /// is a co-resident responder's byte-identical copy: every record in it
  /// asserts exactly what we assert, and RFC 6762 §9 defines a conflict as the
  /// same name, rrtype and rrclass with *different* rdata, so suppressing it
  /// cannot suppress a conflict. A query costs the answer to a question we had
  /// just asked ourselves.
  ///
  /// **That argument is only available because the match is the body itself.**
  /// It was a 64-bit FNV-1a fingerprint until a second-preimage against one was
  /// demonstrated in fifteen seconds — a valid mDNS response announcing a
  /// different address at the same host name, with the collision carried in the
  /// trailing bytes `MessageReader` ignores. Under a digest "byte-identical" is
  /// an assumption about the attacker, and every sentence above rests on it; under
  /// exact bytes it is what was compared.
  ///
  /// # The direction neither mode bounds
  ///
  /// Whatever claims a credit takes it FROM our echo, which then reaches the
  /// protocol layer as peer traffic. `Ordered` narrows that to datagrams the
  /// kernel saw after our send and no further, so an exact replay of our own
  /// bytes defeats both modes equally; it is the standing price of matching on
  /// content at all, bounded by family, port, the bytes and the TTL. A replay is
  /// the whole of what is left, and a replay of our own datagram asserts our own
  /// records.
  ///
  /// Rejecting our own echo is the expensive direction, and it is what settles
  /// the trade: it makes this responder raise a phantom conflict against itself
  /// and rename under §9, and under a clock that keeps stepping it does so
  /// repeatedly.
  Degraded,
}

/// What a claim found, and **how much the finding is worth**.
///
/// [`SelfSendTracker::claim`] returns this instead of a `bool` because the two
/// positive answers are not the same claim. `Ordered` says a credit matched AND
/// the kernel stamped the arrival at or after our `sendto`; `Degraded` says a
/// credit matched on content, family and [`SELF_SEND_TTL`] with no ordering
/// evidence weighed at all — which is also what a byte-identical datagram from a
/// conforming co-resident twin looks like. A caller that collapses the two into
/// "it was ours" asserts more than the second one supports; see
/// [`MatchMode::Degraded`] for exactly what is given up and what one mistake
/// costs.
///
/// # Deliberately NOT `#[non_exhaustive]`
///
/// Its consumers map it onto a trust tier, and `#[non_exhaustive]` would force a
/// wildcard arm at every one of those sites — precisely the wrong behaviour for
/// a trust classification. A variant added later would be swept silently into
/// whichever tier that arm names, and nothing would report the
/// misclassification. Exhaustive matching makes a new variant a **compile
/// error** in every driver instead, which is where an author choosing trust
/// levels should be interrupted. Adding a variant here is therefore a breaking
/// change, on purpose.
///
/// # `#[must_use]`, because producing one SPENDS something
///
/// [`SelfSendTracker::claim`] is not a query. It consumes a take-once credit,
/// so discarding what it returns loses the credit *and* the answer: the echo
/// this endpoint was waiting for has been accounted for, and nothing was told
/// what it was. The datagram then reaches the protocol layer at whatever tier
/// the discarding caller passes instead — and the genuine echo behind it, if
/// this was not it, finds no credit left. That is the phantom RFC 6762 §9
/// conflict against ourselves this whole module exists to prevent, reached by
/// an unused expression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use]
pub enum SelfSendMatch {
  /// A credit matched, with ordering evidence: the kernel stamped this arrival
  /// at or after the recorded send. See [`MatchMode::Ordered`].
  Ordered,
  /// A credit matched on content, family and [`SELF_SEND_TTL`], with no ordering
  /// evidence to weigh. See [`MatchMode::Degraded`] — including for why a
  /// conforming twin's byte-identical datagram matches this way too.
  Degraded,
  /// A credit matched, at either strength, but it was recorded **before the
  /// caller last called [`SelfSendTracker::supersede`]** — so these are our bytes
  /// from a generation of our own records that no longer exists, because a
  /// service registered, began withdrawing, or took an RFC 6762 §9 automatic
  /// rename since the send.
  ///
  /// # Why a generation is needed at all
  ///
  /// A self-echo is ordinarily harmless to adjudicate, because it carries rdata
  /// identical to what we still publish and RFC 6762 §9 calls identical rdata
  /// "never a conflict". That reasoning has one precondition — that our records
  /// have not changed under the credit — and *service replacement* breaks it
  /// without any §8.4 record-updating API: a service withdrawing at host `H`
  /// with address set `A1` no longer holds `H` for the registration guard, so a
  /// replacement may take `H` with `A2` while the outgoing goodbye is still
  /// draining. A delayed echo of the old announcement then carries `A1`, is
  /// routed to the replacement, and is classified against **its** records as
  /// differing host rdata — a terminal `HostConflict` raised by our own past
  /// against our own present. Same-instance reuse with changed SRV/TXT reaches a
  /// false probe defeat the same way.
  ///
  /// # What a caller must do with it
  ///
  /// Suppress the datagram completely — the `OwnEcho` tier — and never the
  /// adjudicating one. That is not a claim of stronger evidence: it is that a
  /// superseded echo has nothing left it may safely say. Its §8.2 proposal is a
  /// proposal for a name this endpoint may no longer be defending, and its §9
  /// rdata is rdata this endpoint no longer holds, so the only two things the
  /// adjudicating tier exists to preserve are exactly the two that have gone
  /// stale.
  ///
  /// The cost is bounded the same way every other suppression here is: the
  /// datagram must still be byte-identical to one we sent, on the same family,
  /// from port 5353, inside [`SELF_SEND_TTL`], and take-once means one of them.
  Superseded,
  /// No credit matched. A negative claim about the tracker's OWN records, never
  /// about the network: a credit refused at the cap, or expired past
  /// [`SELF_SEND_TTL`], reads as this exactly as a peer's datagram does.
  NoCredit,
}

impl SelfSendMatch {
  /// The outcome for a credit that matched under `mode`. Private: the mapping is
  /// this module's, and a public `From` impl would put [`MatchMode`] into a
  /// public signature — see that type's derivation guarantee.
  const fn from_mode(mode: MatchMode) -> Self {
    match mode {
      MatchMode::Ordered => Self::Ordered,
      MatchMode::Degraded => Self::Degraded,
    }
  }
}

/// One recorded send, waiting for its multicast loopback copy.
///
/// **Two clocks, two jobs, and they are not interchangeable.** Each stamp is
/// allowed to be wrong in exactly one direction and the two directions do not
/// agree, so folding them back together — which is what this crate did until
/// the delayed-syscall defect — silently breaks whichever consumer needed the
/// other direction.
struct Credit {
  /// The socket the datagram went out on, and therefore the **only** socket
  /// its loopback copy can arrive on.
  family: Family,
  /// The datagram body, kept whole. A claim compares these bytes against the
  /// arriving ones and nothing else — see [`MAX_SELF_SEND_BYTES`] for why the
  /// digest this replaced could not be made safe at any width, and what holding
  /// the bytes costs.
  body: Vec<u8>,
  /// Which generation of this endpoint's own records this datagram was sent
  /// under, taken from [`SelfSendTracker::generation`] at
  /// [`SelfSendTracker::record`].
  ///
  /// A credit whose generation is no longer the tracker's is still OURS —
  /// nothing about the match weakened — but what it says about our records has
  /// expired, so it may be suppressed and must not be adjudicated. See
  /// [`SelfSendMatch::Superseded`].
  generation: u64,
  /// Both clocks, read **before** the `sendto`. Used for **ordering only**: an
  /// echo the kernel stamped at-or-after [`ClockPair::wall`] cannot be a peer
  /// datagram that predated our send.
  ///
  /// EARLY is the safe direction, and pre-syscall is the only way to get it.
  /// The comparison is against the kernel's own receive stamp on the echo, so
  /// `sent.wall <= kernel send time <= echo rx time` must hold; a stamp read
  /// *after* the syscall could outrun the kernel's receive stamp on a copy
  /// already looped back, and the endpoint would ingest its own datagram as a
  /// peer's. It is emphatically **not** an age: see [`Credit::aged_from`].
  ///
  /// [`ClockPair::mono`] is here for exactly one job and no other: it is the
  /// wall stamp's partner, and the difference between the two elapsed times at
  /// claim time is the only way to tell real elapsed time from a wall clock that
  /// moved on its own. It anchors nothing — see [`WALL_STEP_TOLERANCE`] and,
  /// again, [`Credit::aged_from`].
  sent: ClockPair,
  /// Monotonic, and the only input to the [`SELF_SEND_TTL`] bound.
  ///
  /// `None` means "recorded since the last [`SelfSendTracker::seal`], ageing has
  /// not started" — and such a credit is live UNCONDITIONALLY, whatever the clock
  /// reads, because a window that never opened cannot have been missed. That is
  /// why the seal must precede the driver's next receive: an unsealed credit
  /// reaching a claim is not merely young, it is ageless.
  /// [`SelfSendTracker::seal`] fills it in at the first instant a claim is
  /// possible; see
  /// [`SELF_SEND_TTL`] for why the window may not start any earlier.
  ///
  /// LATE is the safe direction here — the opposite of [`Credit::sent`], and
  /// the whole reason this is a second stamp. Over-retaining a credit costs at
  /// most one byte-identical co-resident peer datagram mistaken for our echo
  /// inside a two-second window; under-retaining one makes this responder raise
  /// a phantom conflict against **itself**. Anchoring the age anywhere inside
  /// the recording iteration — at the pre-syscall wall stamp, or even at the
  /// post-syscall monotonic one — gets the unsafe direction: it charges a
  /// stretch in which no claim was structurally possible to a window that was
  /// never meant to cover it.
  aged_from: Option<StdInstant>,
}

/// Content-addressed record of datagrams this endpoint has recently sent, so
/// their multicast loopback copies are recognized instead of being ingested
/// as a peer's traffic. Take-once: [`SelfSendTracker::claim`] removes the
/// entry it matches, so a later, genuinely distinct datagram with the same
/// bytes (a co-resident peer) is still seen.
pub struct SelfSendTracker {
  /// One [`Credit`] per recorded send, insertion ordered and scanned linearly.
  /// [`SELF_SEND_TTL`] and [`MAX_SELF_SEND_ENTRIES`] keep this small enough
  /// that a `Vec` needs no fancier index.
  ///
  /// # Insertion order **is** expiry order, and [`Self::admit`] depends on it
  ///
  /// For any `i < j`, entry `i` expires no later than entry `j` — reading an
  /// unsealed [`Credit::aged_from`] (`None`) as "expires never". So the entry
  /// closest to expiry is always the **front**, and "is any entry dead at this
  /// instant?" is an `O(1)` question rather than a scan that could itself go
  /// stale. That is what makes the cap's admission decision decision-local; see
  /// [`Self::admit`].
  ///
  /// It holds by construction, under every operation this type has:
  ///
  /// * [`Self::record`] appends, and a fresh credit is unsealed — the largest
  ///   expiry there is — so it can only ever go at the back;
  /// * [`Self::seal`] stamps every unsealed credit with one instant. The
  ///   unsealed credits are exactly the suffix appended since the previous seal,
  ///   and the anchor is a monotonic reading taken inside that call — so the
  ///   suffix takes an anchor at or after every anchor already assigned;
  /// * [`Self::claim`] and [`Self::reclaim_expired_sealed`] only ever remove, and
  ///   removal preserves relative order.
  ///
  /// The non-decreasing anchor was the one half a caller could break while
  /// [`Self::seal`] still took one, and deleting that parameter is what turned
  /// its contract into a property of the monotonic clock.
  entries: Vec<Credit>,
  /// Total bytes held in [`Self::entries`], maintained by every path that adds
  /// or removes one, so [`Self::admit`] can weigh [`MAX_SELF_SEND_BYTES`]
  /// without re-summing the whole vector at each send.
  bytes: usize,
  /// Which generation of this endpoint's own records new credits are recorded
  /// under. Advanced only by [`Self::supersede`].
  ///
  /// `u64` at one advance per service registration or withdrawal cannot wrap in
  /// any runtime this endpoint will see, and the comparison is equality rather
  /// than ordering, so even a wrap would need 2⁶⁴ lifecycle events inside one
  /// two-second [`SELF_SEND_TTL`] to alias.
  generation: u64,
  /// How many claim windows this tracker has opened, ever.
  ///
  /// Bumped by [`Self::open_window_at`] — the one place a window opens — and by
  /// nothing else, so it counts seals and is untouched by [`Self::record`] or
  /// [`Self::claim`]. See [`Self::seal_generation`] for what a driver does with
  /// it. `u64` at one increment per loop iteration cannot wrap in any runtime
  /// this endpoint will see.
  seal_generation: u64,
  /// A stall injected **between the expiry sweep and the read that anchors the
  /// batch the seal is about to open**, consumed by the seal that observes it.
  ///
  /// It stands in for the one thing no test can ask a real host for: a sweep of
  /// [`MAX_SELF_SEND_ENTRIES`] credits, or a preemption anywhere inside it,
  /// running longer than [`SELF_SEND_TTL`]. That stretch is pre-claim time — the
  /// batch's window has not opened yet — so charging it to the batch hands a
  /// newly-opened window an already-expired anchor, and the credit's own echo is
  /// then ingested as peer traffic.
  ///
  /// Injected into [`Self::seal`] itself rather than into a test-only copy of
  /// its body, so a seal that went back to anchoring on the sweep's reading
  /// fails the test instead of passing beside it.
  #[cfg(any(test, feature = "test-support"))]
  forced_seal_pause: Option<Duration>,
}

impl Default for SelfSendTracker {
  fn default() -> Self {
    Self::new()
  }
}

impl SelfSendTracker {
  /// Create an empty tracker.
  #[must_use]
  pub fn new() -> Self {
    Self {
      entries: Vec::new(),
      bytes: 0,
      generation: 0,
      seal_generation: 0,
      #[cfg(any(test, feature = "test-support"))]
      forced_seal_pause: None,
    }
  }

  /// Declare that **what this endpoint publishes has changed**, so every credit
  /// already recorded describes a state this endpoint has left.
  ///
  /// # Where a driver must call this
  ///
  /// At **every mutation of what this endpoint publishes**, which is three
  /// events and no more, because RFC 6762 §8.4 record updating is unimplemented
  /// and a `Service` exposes no records mutator:
  ///
  /// * a service registration, which puts a live route's records on the wire
  ///   that no earlier credit knows about;
  /// * the `begin_withdrawal` that retires a route, however that retirement was
  ///   reached (caller unregister, shutdown, rename collision, internal
  ///   retirement);
  /// * the §9 AUTOMATIC RENAME, taken at the driver's own
  ///   `ServiceUpdate::Renamed` — `Service::set_instance` has already rewritten
  ///   that service's records by the time the update is observed.
  ///
  /// The rename is the one that reaches neither of the others when it SUCCEEDS,
  /// and it is owed on the strength of being a MUTATION rather than on a
  /// consequence traced from it. This type holds ONE generation for the whole
  /// log, so the next registration or withdrawal demotes the renamer's stale
  /// credit as well; what the advance at the rename closes is the stretch
  /// between it and that next seam, during which a credit for the abandoned
  /// instance name still claims as current and still adjudicates. Arguing from
  /// reachability instead is what left the rename off this list once already,
  /// and a reachability argument has to be re-made after every change to the
  /// routing.
  ///
  /// **Call it at the site, not once per loop iteration.** The obligation is
  /// relational — no credit recorded before the change may be claimed at the
  /// adjudicating tier after it — and a deferred bump has to be re-argued
  /// against every receive path that could run in between. Advancing it at the
  /// mutation itself is true whatever the loop shape.
  ///
  /// # Erring towards calling it is cheap; erring away is not
  ///
  /// A spurious advance costs at most the adjudication of one byte-identical
  /// in-flight datagram, and a datagram byte-identical to one of ours ties under
  /// §8.2.1 and is "never a conflict" under §9 — so there was nothing there to
  /// lose. A missing advance costs a live service a terminal `HostConflict`
  /// raised by our own withdrawn generation. See [`SelfSendMatch::Superseded`].
  ///
  /// It does NOT drop the credits. Dropping them would make the very echoes this
  /// is protecting against read as [`SelfSendMatch::NoCredit`] — full peer
  /// traffic, full adjudication — which is the failure it exists to prevent,
  /// only louder.
  pub fn supersede(&mut self) {
    self.generation = self.generation.wrapping_add(1);
  }

  /// Record that we just sent `body` on `family`, submitted at `sent` — the
  /// send's own pre-syscall reading of both clocks.
  ///
  /// # `sent` is a contract this type CANNOT enforce
  ///
  /// Stated plainly because the receive side has one form this crate can check
  /// and this side has none: [`recv_datagram`] mints its datagram off a
  /// `recvmsg` this crate performed, so the stamp's origin and its association
  /// with the body are both properties of the call. There is no equivalent here,
  /// and no honest way to build one — **this crate does not own the send**. It
  /// has no
  /// `sendto` to stamp, so whatever it accepted would be a value the caller read,
  /// and wrapping that in a newtype would move the promise without checking it.
  ///
  /// What the caller owes, then, in full:
  ///
  /// * both halves of `sent` are read on **consecutive statements, wall first**,
  ///   with nothing between them — see [`ClockPair`], whose step detection
  ///   measures the two elapsed times against each other and reads any gap
  ///   between the reads as clock movement;
  /// * both are read **before** the `sendto`, never after. Early is the safe
  ///   direction: the comparison is against the kernel's receive stamp on the
  ///   echo, so `sent.wall <= kernel send time <= echo rx time` must hold, and a
  ///   post-syscall stamp can outrun the kernel's stamp on a copy already looped
  ///   back — at which point the endpoint ingests its own datagram as a peer's;
  /// * `family` is the family whose socket carried **this** syscall, not the one
  ///   the destination suggests. A multicast fan-out is two syscalls with
  ///   identical bytes, and each echo can only arrive on the socket its copy left
  ///   from.
  ///
  /// Breaking any of the three degrades or loses suppression rather than
  /// corrupting the tracker; the failure is a phantom RFC 6762 §9 conflict
  /// against ourselves. Nothing below detects it.
  ///
  /// The credit starts life un-aged ([`Credit::aged_from`] is `None`) and is
  /// therefore live unconditionally until sealed: its clock does not start until
  /// the [`Self::seal`] that precedes the driver's next receive starts it.
  ///
  /// Pushes only if the tracker is still under [`MAX_SELF_SEND_ENTRIES`] — at
  /// the cap the NEW entry is dropped, never a live one, so a burst of sends
  /// can't displace a credit still waiting to match its loopback.
  ///
  /// # It reclaims dead credits, and ages nothing
  ///
  /// These are two different jobs and only one of them belongs here.
  ///
  /// **Reclaiming.** A sealed credit past [`SELF_SEND_TTL`] is garbage:
  /// [`Self::claim`] already refuses it, and nothing but the next [`Self::seal`]
  /// removes it. So a full tracker whose loop then stalls past the TTL is
  /// [`MAX_SELF_SEND_ENTRIES`] corpses, and a later send in that same iteration would
  /// be refused a credit by entries that are every one of them dead. A refused
  /// credit is not a lost byte — it is this endpoint ingesting its own loopback
  /// as peer traffic, a phantom conflict against itself and the RFC 6762 §9
  /// rename that follows. So the cap is enforced against what is still alive:
  /// [`Self::reclaim_expired_sealed`] runs first, against a LIVE monotonic
  /// instant read here, on the same clock and with the same rule [`Self::seal`]
  /// uses.
  ///
  /// **Ageing.** Not here, and not from anything this send carries. The
  /// record-time sweep this once had aged every existing credit against whatever
  /// instant *this* send happened to reach the kernel at, so a later send in the
  /// same iteration — a second fan-out, or a goodbye after an announcement —
  /// evicted credits whose echoes had not had a single
  /// opportunity to claim them. That half is not coming back: an unsealed credit
  /// has no window open, so [`Self::reclaim_expired_sealed`] retains it
  /// unconditionally however late the clock reads, and [`Self::seal`] remains
  /// the only place a window ever opens.
  ///
  /// The reclaim is gated on the cap rather than run every time: below it there
  /// is nothing to make room for, so the clock read and the scan are both
  /// skipped and the routine sweep stays exactly where the anchor is.
  ///
  /// # The sweep is a sweep; [`Self::admit`] is the decision
  ///
  /// The bulk reclaim above is bounded only by [`MAX_SELF_SEND_ENTRIES`], so it
  /// weighs up to 65 536 credits against **one** instant read before it started.
  /// A credit that was live when the sweep looked at it can be dead by the time
  /// the sweep finishes, and deciding the cap on the length that sweep left
  /// behind is a decision made against a stale reading. So the length test is not
  /// the decision: [`Self::admit`] is, and it reads the clock at itself.
  pub fn record(&mut self, family: Family, body: &[u8], sent: ClockPair) {
    self.record_by(family, body, sent, StdInstant::now);
  }

  /// [`Self::record`] with the **bulk sweep's** clock chosen by the caller, so a
  /// test can hold that reading still while real time runs past it — which is
  /// exactly what a sweep of 65 536 entries does to it.
  ///
  /// Behind `test-support`, permanently. It fakes only the sweep; the admission
  /// decision below reads the live clock in every build, so there is no build in
  /// which the cap is decided against an instant a caller handed in. Same seam
  /// as [`Self::claim_at`].
  #[cfg(any(test, feature = "test-support"))]
  pub fn record_with_stale_sweep(
    &mut self,
    family: Family,
    body: &[u8],
    sent: ClockPair,
    sweep_now: StdInstant,
  ) {
    self.record_by(family, body, sent, move || sweep_now);
  }

  /// The one body behind [`Self::record`] and [`Self::record_with_stale_sweep`].
  fn record_by(
    &mut self,
    family: Family,
    body: &[u8],
    sent: ClockPair,
    sweep_clock: impl Fn() -> StdInstant,
  ) {
    if self.entries.len() >= MAX_SELF_SEND_ENTRIES
      || self.bytes.saturating_add(body.len()) > MAX_SELF_SEND_BYTES
    {
      self.reclaim_expired_sealed(sweep_clock());
    }
    if self.admit(body.len()) {
      self.bytes = self.bytes.saturating_add(body.len());
      self.entries.push(Credit {
        family,
        body: body.to_vec(),
        generation: self.generation,
        sent,
        aged_from: None,
      });
    }
  }

  /// Whether a new credit fits **at the instant this decides**, freeing the one
  /// slot it needs when the only thing in the way is a corpse.
  ///
  /// # It takes no instant, and each decision it makes is `O(1)`
  ///
  /// Below both caps there is nothing to weigh. At a cap the only room is a dead
  /// credit, and because [`Self::entries`] is expiry-ordered (see that field)
  /// the earliest expiry there is is the **front** — so "is the next candidate
  /// dead now?" is one comparison, and the clock read sits immediately before it
  /// with nothing but that comparison in between. That is the same floor
  /// [`Self::claim`] reaches: something must read a clock before something can
  /// compare against it, and there is no work left inside the gap to move out.
  ///
  /// A scan would not do. Weighing every entry against one reading is what the
  /// bulk sweep in [`Self::record`] already does, and it is precisely why the
  /// admission cannot be decided on the length that sweep produced: entries it
  /// found live can expire before it returns, and a second scan would inherit
  /// the same window. The ordering invariant is what replaces the scan with an
  /// exact answer.
  ///
  /// # The BYTE budget is why this walks rather than looks once
  ///
  /// One dead credit frees one entry slot but only its own length, so
  /// [`MAX_SELF_SEND_BYTES`] can need several. The walk keeps the property that
  /// matters: **each** front is weighed against a clock read taken immediately
  /// before that comparison, so no entry is reclaimed on a reading taken before
  /// some earlier entry's removal. It stops at the first live front, since
  /// expiry order makes every later credit live too.
  ///
  /// Nothing is removed until the answer is `true`. A refusal must leave the
  /// tracker exactly as it found it — reclaiming on the way to saying no would
  /// discard credits to make room for an entry that was never admitted.
  ///
  /// Refusing here is not a lost byte. It is this endpoint ingesting its own
  /// loopback as peer traffic — a phantom conflict against itself and the RFC
  /// 6762 §9 rename that follows — so the direction that must never be taken
  /// wrongly is the refusal.
  fn admit(&mut self, len: usize) -> bool {
    let mut reclaimable = 0usize;
    let mut freed = 0usize;
    loop {
      let entries = self.entries.len().saturating_sub(reclaimable);
      let bytes = self.bytes.saturating_sub(freed);
      if entries < MAX_SELF_SEND_ENTRIES && bytes.saturating_add(len) <= MAX_SELF_SEND_BYTES {
        break;
      }
      match self.entries.get(reclaimable) {
        // Dead at the instant this decides. Counted, not yet removed.
        Some(front) if !still_live(StdInstant::now(), front.aged_from) => {
          freed = freed.saturating_add(front.body.len());
          reclaimable = reclaimable.saturating_add(1);
        }
        // The earliest expiry still outstanding has not arrived, so every credit
        // from here on is live and the NEW one is the one that must give way.
        // `None` lands here too: an empty tracker that still cannot fit `len` is
        // a datagram larger than the whole budget, and refusing it is the only
        // answer that keeps the bound.
        _ => return false,
      }
    }
    if reclaimable > 0 {
      self.entries.drain(..reclaimable);
      self.bytes = self.bytes.saturating_sub(freed);
    }
    true
  }

  /// Drop every credit that has BOTH opened its claim window AND outlived
  /// [`SELF_SEND_TTL`] at monotonic instant `now`. Nothing else, from either
  /// caller, ever.
  ///
  /// The unsealed half is the load-bearing one, and it is why this is a named
  /// routine rather than a `retain` written out twice. A credit whose
  /// [`Credit::aged_from`] is `None` has not started ageing: it has no age to be
  /// past the TTL with, and no claim opportunity it could have missed, so
  /// [`still_live`] answers `true` for it whatever `now` is. That is precisely
  /// the guarantee the seal redesign exists to provide, and reclaiming garbage
  /// must not quietly re-acquire the power to break it — conflating the two is
  /// what made the old record-time sweep a defect rather than a cleanup.
  ///
  /// [`Self::seal`] runs it once per iteration as ordinary garbage collection, on a
  /// reading of its own — spent here and not reused to anchor the survivors, who
  /// are anchored at a later reading taken once this has returned.
  /// [`Self::record`] runs it only at [`MAX_SELF_SEND_ENTRIES`], where the
  /// alternative is refusing a live send's credit to keep corpses resident.
  fn reclaim_expired_sealed(&mut self, now: StdInstant) {
    let mut kept = 0usize;
    self.entries.retain(|c| {
      let live = still_live(now, c.aged_from);
      if live {
        kept = kept.saturating_add(c.body.len());
      }
      live
    });
    self.bytes = kept;
  }

  /// Open a claim window: expire every credit whose window has run out, and
  /// **then** start the clock on every credit that does not have one yet.
  ///
  /// # Where a driver must call this
  ///
  /// **Recording and window-opening must straddle the receive.** A seal must sit
  /// on every path between a [`Self::record`] and the next thing that can claim
  /// what it recorded, with no record in between. Equivalently: whenever a driver
  /// reaches a receive, every credit it holds is already sealed.
  ///
  /// "Once per iteration, at the top" is NOT the contract, and stating it that
  /// way is a trap. It is right only for a loop whose receive is the first thing
  /// after the seal and whose sends all come after that receive — a tick-shaped
  /// driver. In a loop that pumps its sends and *then* parks on a `select!` whose
  /// arms can receive, a top-of-iteration seal sits on the same side of the
  /// receive as the records it is meant to open: this iteration's credits are
  /// still unsealed when the park returns a datagram. An unsealed credit is live
  /// UNCONDITIONALLY (see [`Credit::aged_from`]), so a byte-identical peer
  /// datagram arriving arbitrarily long afterwards is swallowed as our own echo,
  /// and [`SELF_SEND_TTL`] bounds nothing on exactly the path it exists to bound.
  /// Such a driver seals after its pumps and immediately before it arms the
  /// receive.
  ///
  /// The anchor it stamps the batch with is the first instant at which any of
  /// their echoes can be claimed. That is the only instant [`SELF_SEND_TTL`] may
  /// be measured from: see that constant for why not earlier (the recording
  /// stretch is structurally claim-free) and why not later (post-opportunity time
  /// bounds false suppression and must be charged).
  ///
  /// **Never at record time.** That collapses the two moments this split exists
  /// to keep apart, and charges the window a stretch in which no claim was
  /// possible — which is exactly the credit loss the split prevents.
  ///
  /// The placement is an obligation on whoever adds a stage: a send added AFTER
  /// the seal, or a receive added BEFORE it, reopens this hole silently. There is
  /// no placement that survives arbitrary reordering — the rule is relational, not
  /// positional — so a driver's seal call site should name which records it closes
  /// and which receive it precedes.
  ///
  /// Over-retention is bounded by one iteration's duration, and over-retention is
  /// the **cheap** direction: a stale credit can at worst suppress one
  /// byte-identical peer datagram, and take-once bounds it to that. Under-
  /// retention is the expensive one — our own echo ingested as a peer, an RFC
  /// 6762 §9 conflict against ourselves and the rename that follows.
  ///
  /// Ageing here rather than on `record` also means the anchor is taken once per
  /// iteration instead of once per send, and always against the monotonic clock
  /// — so a wall-clock step in either direction still cannot evict a live credit.
  /// The reclaim below is shared with [`Self::record`]'s cap path and is the
  /// *only* thing they share: this is where the window opens, and it is the only
  /// place that can open one.
  ///
  /// # It takes no instant, and the two phases do not share a reading
  ///
  /// **A reading is spent by its first consumer**, and this call has two
  /// consumers in a fixed order. The sweep is first, and it is a bulk one:
  /// bounded only by [`MAX_SELF_SEND_ENTRIES`], it weighs up to 65 536 credits
  /// against the reading it started from. Handing that same, already-spent
  /// reading to the anchor is what made a caller-supplied `now` unsound — a long
  /// sweep, or a preemption anywhere inside it, gave a window that had only just
  /// opened an anchor from before it, and the first claim against that credit
  /// then found it expired. A credit lost that way is not a lost byte: it is this
  /// endpoint ingesting its own loopback as peer traffic, a phantom conflict
  /// against itself and the RFC 6762 §9 rename that follows.
  ///
  /// So sealing is batch-oriented. Every piece of pre-claim work — the sweep, and
  /// anything a later pass adds before the anchor — completes first, and the
  /// anchor is read after all of it, because that instant is not a convenient
  /// earlier reading but the thing being defined. The caller's parameter is
  /// deleted rather than moved for the same reason it was deleted from
  /// [`Self::claim`]: a parameter is the channel through which a reading taken
  /// somewhere else arrives, and moving the read nearer never removes the
  /// channel.
  ///
  /// The sweep spending a stale reading is harmless in the only direction it can
  /// be wrong: a credit that died while the sweep ran is merely retained until
  /// the next seal, and [`Self::claim`] refuses it meanwhile.
  ///
  /// It also settles the non-decreasing-anchor contract this used to state and
  /// rely on a caller for. The anchor is now a monotonic reading taken here, so
  /// each seal's anchor is at or after every anchor already assigned and
  /// [`SelfSendTracker::entries`]'s expiry order — which [`Self::admit`]'s `O(1)`
  /// front check reads — holds by construction.
  pub fn seal(&mut self) {
    // The sweep completes FIRST, on a reading of its own.
    self.reclaim_expired_sealed(StdInstant::now());
    // Deliberately between the sweep and the anchor: that is the stretch a
    // 65 536-entry sweep, or a preemption inside it, occupies for real.
    #[cfg(any(test, feature = "test-support"))]
    if let Some(pause) = self.forced_seal_pause.take()
      && !pause.is_zero()
    {
      std::thread::sleep(pause);
    }
    // Read after every piece of pre-claim work above, and nowhere else.
    self.open_window_at(StdInstant::now());
  }

  /// [`Self::seal`] with both phases pinned to `at`, so a test can place a loop
  /// top anywhere without sleeping to it.
  ///
  /// Behind `test-support`, permanently, and the gate is the point: no default
  /// build has this at all, and production reaches a seal only through
  /// [`Self::seal`], which reads the clock for each phase itself — so there is no
  /// build a driver ships in which a caller's instant can anchor a window. Collapsing the two readings is exactly what makes this usable for
  /// the tests whose subject is *not* the gap between them — `StdInstant` has no
  /// constructor, so a chosen loop top cannot be expressed any other way. The
  /// gap itself is tested through [`Self::pause_next_seal_for_test`], against
  /// the real [`Self::seal`]. Same seam as [`Self::claim_at`].
  #[cfg(any(test, feature = "test-support"))]
  pub fn seal_at(&mut self, at: StdInstant) {
    self.reclaim_expired_sealed(at);
    self.open_window_at(at);
  }

  /// Stall the next [`Self::seal`] between its sweep and its anchor. See
  /// [`SelfSendTracker::forced_seal_pause`].
  #[cfg(any(test, feature = "test-support"))]
  pub fn pause_next_seal_for_test(&mut self, pause: Duration) {
    self.forced_seal_pause = Some(pause);
  }

  /// Start the clock on every credit that does not have one yet, at
  /// `opened_at`.
  ///
  /// `get_or_insert`, never an unconditional assignment: a credit already sealed
  /// keeps its original anchor, or a driver looping faster than
  /// [`SELF_SEND_TTL`] would push every credit's expiry forward forever and the
  /// false-suppression bound would not be a bound at all.
  fn open_window_at(&mut self, opened_at: StdInstant) {
    for credit in &mut self.entries {
      credit.aged_from.get_or_insert(opened_at);
    }
    self.seal_generation = self.seal_generation.wrapping_add(1);
  }

  /// Consume the tracker entry (if any) this datagram is the loopback copy of —
  /// the one recorded for its family, whose stored bytes are **exactly** this
  /// body, whose recorded send is ordered before its stamp, and whose claim
  /// window is **still open at the instant this call weighs it** — and report
  /// **how much the match is worth**.
  ///
  /// # One argument, so there is nothing to pair
  ///
  /// [`RxDatagram`] carries the family, the body and the stamp out of one
  /// receive, and is neither `Copy` nor `Clone`, so the stamp cannot be lifted
  /// out and laid beside another datagram's bytes. **That is a property of the
  /// type rather than an obligation on the caller**, and it is what the three
  /// separate arguments this method replaced could never be: a stamp a kernel
  /// really did write, for some OTHER receive, used to be weighed here at
  /// `Ordered` strength against whatever body it was handed with. Both
  /// mismatches were live — a stamp from a LATER receive lets a byte-identical
  /// datagram the kernel saw *before* our `sendto` take the take-once credit, so
  /// a real peer's datagram is swallowed as our loopback and any conflict it
  /// carried is never seen, while our own echo finds no credit and reaches the
  /// protocol layer as peer traffic; a stamp from an EARLIER receive rejects the
  /// genuine echo outright, reaching the same place by the other route. Either
  /// is a phantom RFC 6762 §9 conflict against ourselves and the rename that
  /// follows.
  ///
  /// What this does NOT settle is **origin**, and that is stated rather than
  /// claimed away: where a driver performs its own receive,
  /// [`RxDatagram::from_recv_parts`] parses a control buffer this crate cannot
  /// prove a kernel filled. On the paths that reach [`recv_datagram`] there is
  /// nothing left for a caller to get wrong at all. See [`RxDatagram`] for
  /// exactly how much distance each shape buys.
  ///
  /// No caller supplies a mode either: [`MatchMode`] is derived here from
  /// whether the datagram carries a stamp, never declared, so there is no way to
  /// ask for `Ordered` matching against a value that carries no order.
  ///
  /// # A tier, not a bool
  ///
  /// [`SelfSendMatch::Ordered`] and [`SelfSendMatch::Degraded`] are both matches
  /// and are not the same claim: only the first weighed evidence that the kernel
  /// saw this datagram at or after our `sendto`, and the second is also what a
  /// conforming co-resident twin's byte-identical datagram produces. A caller
  /// deciding what to suppress should decide on the variant. See
  /// [`SelfSendMatch`], and [`MatchMode::Degraded`] for what the weaker one gives
  /// up.
  ///
  /// [`SelfSendMatch::Superseded`] is the third, and it answers a different
  /// question from the other two: not how strong the match is, but whether what
  /// the datagram ASSERTS is still ours to assert. See [`Self::supersede`].
  ///
  /// # It takes no instant, and no caller can supply one
  ///
  /// The monotonic clock the [`SELF_SEND_TTL`] bound is measured on is read
  /// **inside this call, at the [`still_live`] test of the candidate being
  /// weighed** — not at the top of this function, and emphatically not by the
  /// caller. The absent parameter is the fix, and it is structural rather than
  /// another correction.
  ///
  /// A credit's liveness was mis-evaluated six times, each in a different window
  /// between some caller's clock read and this comparison: aged from a
  /// pre-syscall wall stamp, aged before the receive resumed, swept across loop
  /// stages by a later record, frozen at loop entry, counted as occupancy at the
  /// cap while dead, and frozen immediately after `recv` with both admission
  /// gates still to run. Each round closed its window by moving the read nearer,
  /// and each round left the next one. The parameter *is* the defect class: it is
  /// a channel through which a caller hands in an age measured somewhere else,
  /// and moving the read closer never removes the channel. Deleting it is what
  /// removed the channel.
  ///
  /// **What is left is the instructions between that read and the comparison,
  /// and it is irreducible.** Every possible implementation has it: something
  /// must read a clock before something can compare against it. There is no work
  /// left inside it to move out, so it is the floor rather than a seventh window
  /// — a later pass hunting for one here should stop at this paragraph.
  ///
  /// # Two clocks, two questions, and a third that keeps the first honest
  ///
  /// The datagram's stamp answers *ordering* — could the kernel have seen this
  /// datagram before we sent ours? — and is a wall stamp because that is the only
  /// clock a kernel receive timestamp is expressed in. The age is the other
  /// question, answered on the monotonic clock, because an age must not be a
  /// wall-clock subtraction.
  ///
  /// The third question is whether the ordering answer is worth anything, and it
  /// exists because the wall clock is not monotonic. A step between the send and
  /// this claim leaves [`Credit::sent`]'s wall half describing a timeline the
  /// receive stamp was never taken on, and the credit's own echo then looks like
  /// a peer datagram that predated it. So every claim reads both clocks — see
  /// [`ClockPair`] — and a credit whose two elapsed times disagree past
  /// [`WALL_STEP_TOLERANCE`] is weighed under [`MatchMode::Degraded`] instead of
  /// being refused. See [`evidence_mode`] for the direction that trade takes and
  /// why.
  ///
  /// The driver's own loop instant is not a substitute for the live read, which
  /// is why this takes none: a driver keeps that reading for its protocol path
  /// and hands it to nothing here. It is taken before the receive stage, so
  /// reusing it charges nothing for the drain's own runtime, for the admission
  /// gates each datagram passes, or for a preemption anywhere among them; a
  /// driver stalling mid-drain would find a credit still live an unbounded time
  /// after its window opened. [`SELF_SEND_TTL`] bounds FALSE suppression and that bound is real
  /// time, so post-opportunity time is charged in full — see that constant.
  /// Erring EARLY is still the safe direction within a live read, since
  /// over-retention is cheap and losing a credit raises a phantom conflict
  /// against ourselves.
  ///
  /// A credit [`Self::seal`] has not reached yet is live whatever the clock
  /// reads, and a driver honouring that seal's contract never presents one here:
  /// the seal sits between its records and this claim. The rule is stated rather
  /// than assumed because the failure is silent — an unsealed credit that did
  /// arrive would be retained (cheap) rather than expiring one that never had a
  /// claim opportunity (a phantom self-conflict) — and because "cheap" is not
  /// "free": retention with no bound is the stale-credit suppression
  /// [`Self::has_unsealed`] exists to let a driver assert against.
  ///
  /// # What may be offered a credit is the caller's half of the match
  ///
  /// This weighs content, family and time, and it never sees where the datagram
  /// came from. Both of this endpoint's sockets are bound to port 5353, so every
  /// datagram it sends leaves from that port and every loopback copy arrives
  /// from it — which makes a different source port proof that the datagram is
  /// not our echo, and something this call cannot discover for itself. **The
  /// driver holds that line**, beside the RFC 6762 §11 source-port rule it
  /// belongs with: an untrusted RESPONSE is dropped outright there, while a §6.7
  /// legacy unicast QUERY is kept — it is owed a reply — and simply never offered
  /// here.
  ///
  /// # Why the family is part of the key
  ///
  /// One multicast transmit is **two** syscalls with **identical bytes** and
  /// two separately-stamped credits, and the kernel loops one copy back per
  /// joined socket. Matching on content and time alone makes those two credits
  /// interchangeable, and the receive rotor deliberately does not fix which
  /// socket is read first — so the later (IPv6) echo can be read first, consume
  /// the earlier (IPv4) credit, and leave the IPv4 echo facing a credit stamped
  /// *after* the kernel saw it. `Ordered` matching then rejects it and the
  /// endpoint ingests its own datagram as peer traffic: a phantom conflict
  /// against itself, and the spurious §9 rename that follows.
  ///
  /// A loopback copy can only arrive on the socket it was sent from, so keying
  /// the credit to the family makes each echo match its own credit and nothing
  /// else. That is exact rather than probabilistic, which is why it is
  /// preferred over consuming the newest eligible credit: newest-first only
  /// reorders the same interchangeable set, and a third credit for the same
  /// bytes (a queued copy completing out of order) defeats it again. The family
  /// is the datagram's own, read off the socket it arrived on, so there is no
  /// separate argument that could disagree with the body.
  pub fn claim(&mut self, rx: &RxDatagram<'_>) -> SelfSendMatch {
    self.claim_by(rx.family(), rx.body(), rx.stamp(), ClockPair::now)
  }

  /// [`Self::claim`] against a caller-chosen reading of both clocks, so a test
  /// can place a claim anywhere in a credit's window without sleeping through
  /// it, and can put the wall clock somewhere the monotonic one says it cannot
  /// be.
  ///
  /// Behind `test-support`, permanently, and that gate is the entire point: no
  /// default build has this at all, and production reaches the liveness decision
  /// only through [`Self::claim`], which reads both clocks itself — so there is
  /// no build a driver ships in which a stale reading can be handed in.
  ///
  /// It is also the only deterministic way to present a wall-clock step: no test
  /// can ask a host to run `settimeofday` under it, and the whole subject of
  /// [`WALL_STEP_TOLERANCE`] is what a claim does when the wall clock moved
  /// between the send and here.
  #[cfg(any(test, feature = "test-support"))]
  pub fn claim_at(&mut self, rx: &RxDatagram<'_>, now: ClockPair) -> SelfSendMatch {
    self.claim_by(rx.family(), rx.body(), rx.stamp(), move || now)
  }

  /// The one body behind both claim entry points, production and `test-support`.
  ///
  /// `clock` is invoked **in the loop**, at the [`still_live`] test of each
  /// candidate that already matched on family and content — so the production
  /// path's read lands at the decision itself, with nothing between the
  /// monotonic half and the comparison it feeds. Private, and taking a clock
  /// rather than a reading, so the only way to reach it with a value fixed in
  /// advance is the `test-support` door above.
  ///
  /// The mode that decided the winning candidate is carried out rather than
  /// discarded: it is the whole difference between [`SelfSendMatch::Ordered`] and
  /// [`SelfSendMatch::Degraded`], and it is not recoverable afterwards — the
  /// credit it was derived from has been removed by then, and re-deriving it
  /// would read the clock a second time.
  fn claim_by(
    &mut self,
    family: Family,
    body: &[u8],
    rx: Option<SystemTime>,
    clock: impl Fn() -> ClockPair,
  ) -> SelfSendMatch {
    let mut matched = None;
    for (pos, c) in self.entries.iter().enumerate() {
      // The BYTES, not a digest of them. See `MAX_SELF_SEND_BYTES`.
      if c.family != family || c.body != body {
        continue;
      }
      let now = clock();
      if !still_live(now.mono, c.aged_from) {
        continue;
      }
      let mode = evidence_mode(rx, c.sent, now);
      if reference_ordered(rx, c.sent, mode) {
        matched = Some((pos, mode, c.generation));
        break;
      }
    }
    match matched {
      Some((pos, mode, generation)) => {
        let taken = self.entries.remove(pos);
        self.bytes = self.bytes.saturating_sub(taken.body.len());
        // Take-once first, tier second. A superseded credit is still spent —
        // it was ours and this datagram is it — so the genuine echo behind a
        // replay still finds nothing, exactly as at every other tier.
        if generation == self.generation {
          SelfSendMatch::from_mode(mode)
        } else {
          SelfSendMatch::Superseded
        }
      }
      None => SelfSendMatch::NoCredit,
    }
  }

  /// Number of live entries.
  ///
  /// Behind `test-support`, permanently: a driver drives this type entirely
  /// through [`Self::record`], [`Self::seal`] and [`Self::claim`] and never reads
  /// its depth, so this stays gated rather than becoming ordinary public surface
  /// that a caller could start depending on.
  #[cfg(any(test, feature = "test-support"))]
  #[must_use]
  pub fn len(&self) -> usize {
    self.entries.len()
  }

  /// How many times a claim window has been opened here.
  ///
  /// Advances on every [`Self::seal`], and on nothing else — [`Self::record`] and
  /// [`Self::claim`] leave it alone.
  ///
  /// # What it is for: proving WHEN a driver sealed, not merely that it did
  ///
  /// [`Self::has_unsealed`] answers a question about *state*, and state is not
  /// enough. A driver that seals in its receive arm — after the park, just before
  /// it weighs the datagram — has no unsealed credit by the time anything looks,
  /// yet every credit it holds was anchored an entire park too late, which is the
  /// stale-credit bug [`Self::seal`] describes. The two placements are
  /// indistinguishable from the claim site.
  ///
  /// So a driver reads this at its pre-park boundary and again where it receives,
  /// and requires the two to be **equal**: no window opened in between, therefore
  /// the seal it is relying on happened before the park rather than inside it.
  /// Together with [`Self::has_unsealed`] being false at that same boundary —
  /// everything recorded this iteration is already sealed — that pins both halves
  /// of the contract: sealed, and sealed early enough.
  #[must_use]
  pub const fn seal_generation(&self) -> u64 {
    self.seal_generation
  }

  /// Whether any credit is still **unsealed** — recorded, but with no claim
  /// window opened yet.
  ///
  /// Not behind `test-support`, because this is not a clock seam: it exposes no
  /// instant, accepts none, and cannot change what any claim decides. It is here
  /// so a driver can **check** the one contract [`Self::seal`] states and this
  /// type cannot enforce — that recording and window-opening straddle the
  /// receive — instead of only promising it.
  ///
  /// A driver whose sends all precede its receive (a tick-shaped one) has no
  /// unsealed credit at any receive, and neither does a `select!`-shaped one that
  /// seals after its pumps. Either can assert that:
  ///
  /// ```ignore
  /// debug_assert!(!tracker.has_unsealed(), "seal must precede this receive");
  /// ```
  ///
  /// The assertion is worth making because the failure is silent otherwise: an
  /// unsealed credit is live UNCONDITIONALLY, so a misplaced seal does not fail
  /// fast, it quietly stops [`SELF_SEND_TTL`] from bounding anything.
  #[must_use]
  pub fn has_unsealed(&self) -> bool {
    self.entries.iter().any(|c| c.aged_from.is_none())
  }

  /// Whether no credit is outstanding — "every echo we sent has been claimed".
  ///
  /// Behind `test-support` for the same reason as [`Self::len`].
  #[cfg(any(test, feature = "test-support"))]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }

  /// Every entry's ageing anchor, in storage order, so a test can assert the
  /// expiry order [`Self::admit`] depends on.
  ///
  /// Behind `test-support`, permanently, and for the same reason as
  /// [`Self::len`]: a driver drives this type through `record`, `seal` and `claim`
  /// and never reads its layout.
  #[cfg(any(test, feature = "test-support"))]
  pub fn anchors_for_test(&self) -> Vec<Option<StdInstant>> {
    self.entries.iter().map(|c| c.aged_from).collect()
  }
}

/// Whether a credit whose window opened at `aged_from` is still inside
/// [`SELF_SEND_TTL`] at monotonic instant `now`.
///
/// The **only** place the TTL is applied, on the **only** clock it may be
/// applied on.
///
/// `None` — a credit recorded since the last [`SelfSendTracker::seal`] — is
/// live unconditionally: its window has not opened, so there is no age to
/// compare and nothing it could have outlived. `saturating_duration_since`
/// likewise reads a `now` before `aged_from` as an age of zero rather than as an
/// expiry: a monotonic clock cannot really run backwards, so an age computed
/// from a reading that predates the anchor is a reading taken out of order
/// rather than an expired credit. Zero is the safe answer either way — it
/// retains the credit.
fn still_live(now: StdInstant, aged_from: Option<StdInstant>) -> bool {
  match aged_from {
    // Unsealed: recorded this iteration, and no claim was possible yet.
    None => true,
    Some(from) => now.saturating_duration_since(from) <= SELF_SEND_TTL,
  }
}

/// How much ordering evidence this claim really has about **this** credit.
///
/// Never stronger than the platform supplied, and weaker whenever the credit's
/// own wall stamp did not survive the window: the two elapsed times between
/// `sent` and `now` are the same interval measured on two clocks, so their
/// disagreement is what the wall clock did on its own, and past
/// [`WALL_STEP_TOLERANCE`] the stamp is simply not on the timeline the kernel's
/// receive stamp was taken on.
///
/// # Which way to fail, and what it costs
///
/// Unusable evidence has two possible readings and both cost something.
///
/// Reading it as *not our echo* refuses the credit, and this endpoint then
/// ingests its own announcement as peer traffic: a phantom conflict against
/// itself and the RFC 6762 §9 rename that follows — repeatedly, for as long as
/// the clock keeps stepping, since each step refuses the next echo the same way.
///
/// Reading it as *our echo* lets a stranger carrying the same fingerprint take
/// the credit instead, at a cost of one datagram inside a two-second window. See
/// [`MatchMode::Degraded`] for what that datagram can and cannot be, and for the
/// two things the RFC 6762 §9 rdata test does and does not settle about it.
///
/// So the fall-back is [`MatchMode::Degraded`], which is not a new state: it is
/// what every claim on a platform with no receive-timestamp cmsg already runs
/// under, with the same bound and the same accepted weakness.
fn evidence_mode(rx: Option<SystemTime>, sent: ClockPair, now: ClockPair) -> MatchMode {
  match rx {
    // No kernel receive timestamp: nothing to order against in the first place.
    None => MatchMode::Degraded,
    // The wall clock moved on its own inside this credit's window, so its
    // pre-syscall stamp cannot be compared with a receive stamp any more.
    Some(_) if wall_stepped(sent, now) => MatchMode::Degraded,
    Some(_) => MatchMode::Ordered,
  }
}

/// Whether the wall clock moved on its own — in **either** direction — between
/// the send at `sent` and the claim at `now`.
///
/// Both readings pair a wall stamp with a monotonic one taken immediately after
/// it, so the two elapsed times measure the same interval. Real elapsed time is
/// the monotonic one; everything the wall one does beyond it is the step. A
/// merely slewed clock stays well inside [`WALL_STEP_TOLERANCE`] — see there.
fn wall_stepped(sent: ClockPair, now: ClockPair) -> bool {
  // `saturating_duration_since` reads a `now` before the send as zero elapsed.
  // That can only make the disagreement look larger, and a larger disagreement
  // degrades — which is the cheap direction. See `evidence_mode`.
  let elapsed = now.mono.saturating_duration_since(sent.mono);
  match now.wall.duration_since(sent.wall) {
    // The wall clock is still ahead of the send. Whatever it did beyond real
    // elapsed time, in either direction, is the step.
    Ok(advanced) => advanced.abs_diff(elapsed) > WALL_STEP_TOLERANCE,
    // The wall clock now reads BEFORE the send it stamped, which no amount of
    // elapsed time can produce. The step is that gap plus every bit of real time
    // that passed while the clock was travelling the other way.
    Err(behind) => behind.duration().saturating_add(elapsed) > WALL_STEP_TOLERANCE,
  }
}

/// Whether a kernel receive stamp of `rx` is **ordered after** a send submitted
/// at `sent`, given the evidence `mode` says this claim actually has.
///
/// Ordering only. It deliberately does not bound how far after — that is
/// [`still_live`]'s job, on the monotonic clock, and unifying the two is the
/// defect this split exists to prevent: `sent.wall` is read before the syscall,
/// so any stall between the read and the kernel accepting the datagram would be
/// charged to a TTL measured from it, and a stall past [`SELF_SEND_TTL`] would
/// make the endpoint ingest its own echo as peer traffic.
///
/// [`MatchMode::Degraded`] weighs nothing here, and the missing test is the
/// point rather than an omission. The only wall value a degraded claim could
/// offer is a userspace read time, which is at-or-after the send in every case
/// except one — a wall clock that stepped backwards — so an ordering test
/// against it can only ever fire on the step, and firing means refusing our own
/// echo. That is the expensive direction; see [`evidence_mode`].
fn reference_ordered(rx: Option<SystemTime>, sent: ClockPair, mode: MatchMode) -> bool {
  // `Ordered` is only ever derived from a `Some`, so the absent-stamp arm here
  // is unreachable; it answers `true` rather than panicking, which is the
  // direction [`evidence_mode`] takes for missing evidence anyway.
  let (MatchMode::Ordered, Some(rx)) = (mode, rx) else {
    return true;
  };
  match rx.duration_since(sent.wall) {
    // Receive stamp at-or-after the send: correctly ordered to be our echo.
    Ok(_) => true,
    // Receive stamp BEFORE the send, tolerated only within this target's
    // receive-timestamp truncation grain — that ordering is exactly what stops a
    // byte-identical peer datagram the kernel saw before our sendto from
    // stealing the take-once credit.
    Err(behind) => behind.duration() <= RX_TIMESTAMP_GRAIN,
  }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::expect_used)]
mod tests;

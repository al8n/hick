# UNRELEASED

## A typed trust tier for received datagrams

BREAKING

- `mdns-proto`: `Endpoint::handle` takes a `Received<'a>` bundle instead of five
  loose arguments. It carries the payload together with the caller's
  `Provenance` claim about it, so a driver can no longer pair one datagram's
  self-send verdict with another datagram's bytes. `local_ip` becomes optional
  and is documented as trace-only — it never was a self signal, whatever the old
  doc comment said — and the interface index becomes `Option<u32>` so a driver
  that does not know says so rather than passing the `0` that also spelled
  "unknown".
- `mdns-proto`: `Provenance` replaces the `caller_is_self` boolean, and the
  all-or-nothing suppression it drove is split into four permissions
  (§10 observation, §7.1/§7.3 quieting, §8.1/§8.2/§9 adjudication, and how
  widely questions are answered), gated per routing arm. **A content match with
  no ordering evidence (`OwnEchoLikely`) now ADJUDICATES**: it is
  indistinguishable from a byte-identical datagram sent by a conforming §9
  fault-tolerance twin, and suppressing a §8.2 proposal costs a name permanently
  while routing our own echo to the tiebreak costs at worst §8.2's one-second
  deferral. It still suppresses cache population and duplicate-question
  suppression, where believing a peer is the more harmful error, and answers
  only §8.1 defences.
- `mdns-proto`: the opt-in `trust_advertised_src_as_self` heuristic no longer
  suppresses adjudication, and no longer skips the §8.1 defence of a name this
  endpoint already holds. It matches any co-resident host publishing an address
  we publish — including a peer that has taken it — and a convenience knob must
  not be able to delete a §8 proposal, nor let a conforming prober take an
  advertised name. It still suppresses cache population and duplicate-question
  suppression, and still withholds ordinary discovery questions.
  `Provenance::NotFromUs` declines the heuristic outright: a caller that logs what
  it sends has better evidence than a source address does. A user who enabled the
  knob as a backup for an evicted send-log credit loses that backup, and such an
  echo now runs full effects.
- `mdns-proto`: new `RegisterServiceError::HostAddressesDiffer`. Two live
  services may share a host name — that is how one machine advertises one address
  set from several services — but they may no longer DISAGREE about the addresses
  of an RRTYPE THEY BOTH PUBLISH. Each would otherwise read the other's
  announcement as a host claiming its own host name with rdata it does not hold,
  which §9 makes a conflict and which surfaces as a TERMINAL
  `ServiceUpdate::HostConflict` raised by a sibling on the same machine. That path
  was unreachable only while self-detection suppressed everything, so this guard
  is what makes the adjudication change above safe. `HandleServiceRenamedError`
  gains the matching variant as the invariant's second enforcement point. The
  check is per RRtype because §9's conflict is "the same name, **rrtype** and
  rrclass, but inconsistent rdata": an IPv4-only service and an IPv6-only service
  sharing a host name publish disjoint RRsets and are accepted.
- **`hick-smoltcp` and `hick-embassy` lose all-effects suppression of their own
  loopback.** Their self-send log weighs no ordering evidence — there is no
  kernel receive stamp on a bare-metal path and no wall clock to put one on — so
  a match against the records they STILL publish reports `OwnEchoLikely` and
  never the ordered tier. Their own echo now
  reaches §8.2's tiebreak and §8.1's defence instead of being deleted; it still
  populates no cache entry and quiets no query of ours. That is safe because an
  echo of records still published carries rdata identical to ours, which §9
  makes no conflict at all, and it is the point of the change rather than a side
  effect: their self-detection was never strong enough to justify deleting a §8
  proposal. The one echo for which that does not hold — one sent before a
  service registered, began withdrawing or took a §9 automatic rename, so it
  may assert records no live route holds — reports `OwnEcho` and is suppressed
  whole. That is not a
  stronger claim about the evidence but a weaker claim about what the bytes may
  still say.
- **`hick-smoltcp`'s self-send log becomes take-once, address-family keyed and
  source-port gated**, and `hick-embassy` inherits all three. It is what the
  `OwnEcho` above may not be granted without: exact equality with a past send
  establishes CONTENT and not ORIGIN, so against a non-consuming log a peer
  replaying bytes it captured off the link matched for the whole five-second
  retention window, every copy — and during a same-name replacement an old
  authoritative response really does conflict with the replacement's records
  under §§8.1 and 9, so a flood of them stayed invisible through a whole probing
  window. A recorded entry now owes one loopback copy per family whose socket
  accepted the datagram, a claim SPENDS the copy it matches, and the call site
  offers no credit at all to a datagram from a source port this engine never
  sends from. The family key is separately load-bearing: one multicast is two
  `try_send` calls with identical bytes and one echo per joined socket, and
  without it the first echo read would spend both copies and leave the second to
  reach the proto layer as peer traffic.
- `hick-reactor`, `hick-mio` and `hick-compio` report all three tiers instead of
  two. A claim the kernel's receive stamp ORDERED against our `sendto` stays
  `OwnEcho`; one that matched on content, family and the TTL alone becomes
  `OwnEchoLikely` and adjudicates — that is what a conforming §9 twin's
  byte-identical datagram produces, so it may not be trusted with a name. It is
  the whole of the match on Windows and on any kernel that delivers no timestamp
  cmsg. A match at EITHER strength against a credit recorded before a service
  registered, began withdrawing or took a §9 automatic rename reports `OwnEcho`
  as well, for the reason the bullet above gives: a stale echo may no longer adjudicate anything. No credit,
  or a source port this endpoint never sends from, becomes `NotFromUs` rather
  than `Unknown`, which additionally declines `trust_advertised_src_as_self` on
  these drivers.

OTHER

- `mdns-proto`: `packets_dropped` counts a narrower set of datagrams. It counts
  whole-datagram rejects, which is now "every permission denied" rather than "the
  old suppression boolean was set" — so a datagram that is suppressed in part but
  still adjudicates is no longer counted as a drop, and its sections are walked by
  the parse-error latch like any other processed datagram's. The
  exactly-one-reject-counter-per-`packets_rx` invariant is unchanged and still
  holds in both directions.
- `mdns-proto`: new `Name::same_owner` — DNS-name equality, blind to case and to
  the optional trailing root dot. `Name` canonicalises case at construction but
  preserves the dot, so derived `PartialEq` calls `device.local` and
  `device.local.` different names while the wire encoder and the routing path
  call them one. The host address-set guard compared the stored strings and let
  the second spelling register past it; it now asks `same_owner`.
- `mdns-proto`: the INSTANCE-name guards had the same trailing-root-dot hole, and
  older — the duplicate-name checks in `try_register_service` and
  `handle_service_renamed`, the retract-before-reuse checks against a
  name-holding goodbye, the reclaim-cancel on announce, and the same-host sibling
  address retention that a withdrawal's goodbye honours. Each now asks
  `Name::same_owner`. Two spellings of one instance name can no longer both
  register and probe for it, a held goodbye holds its name however a
  re-registration spells it, and a withdrawing service retains an address its
  same-host sibling still advertises.
- `mdns-proto`: host conflicts are routed and classified by owner **plus
  RRtype**. A route that publishes no record of a record's RRtype at its host
  name is not a party to that RRset — §9's conflict is "the same name, rrtype and
  rrclass, but inconsistent rdata" — so it receives no `HostConflict` for it, and
  `Service` drops one that reaches it by another path. An absent RRtype used to
  read as differing, which surfaced a TERMINAL `ServiceUpdate::HostConflict`:
  a same-host sibling's first announcement retired a service over an address that
  service never published. This is the half that must accompany the per-RRtype
  registration check above; either alone leaves the false terminal conflict
  reachable.

## A receive's evidence travels with the datagram it came from

BREAKING

- `hick-udp`: `RxEvidence` and `SelfSendTracker::take` / `take_at` are removed.
  A claim now takes one `RxDatagram<'a>` — the family, the body and the kernel
  receive stamp out of one receive, in a value that is neither `Copy` nor
  `Clone` and exposes no stamp. The three loose arguments could disagree, and a
  stamp a kernel really did write for a DIFFERENT receive was weighed at full
  `Ordered` strength against whatever body it was handed with; both directions
  ended at a phantom RFC 6762 §9 conflict against this responder itself. That is
  now unrepresentable rather than documented.
- `hick-udp`: new `recv_datagram(fd, buf, family)` performs the receive and
  slices the body to that receive's own reported length, so on the paths that can
  use it no caller picks a length, a buffer or a time at all. A driver that owns
  its own `recvmsg` mints through `RxDatagram::from_recv_parts(family, body,
  cmsgs)`, which pairs the two where both are in scope; that one remains a caller
  contract, because this crate is not present at the syscall that would make the
  control buffer true. `RxDatagram::into_owned` converts a borrowed body for a
  driver that hands the datagram to another task.
- `hick-udp`: a claim reports `SelfSendMatch { Ordered, Degraded, NoCredit }`
  instead of a bool, so a caller can tell a match the kernel's stamp ORDERED
  against our `sendto` from one that matched on content, family and the TTL
  alone — which is also what a conforming §9 twin's byte-identical datagram
  produces. Deliberately not `#[non_exhaustive]`: consumers map it onto a trust
  tier, and a forced wildcard arm would sweep a future variant silently into
  whichever tier that arm names.
- `hick-udp`: `RecvMeta::rx_time` is demoted in its documentation to a
  diagnostic. It is no longer an input to any self-send decision.
- `hick-udp`: `SelfSendMatch` is `#[must_use]`. A claim SPENDS a take-once
  credit, so discarding what it returns loses the credit and the answer both:
  the echo this endpoint was waiting for has been accounted for, nothing was
  told what it was, and the genuine echo behind it — if this was not it — finds
  no credit left.
- `hick-udp`: a claim now matches a credit on the datagram's exact bytes rather
  than a 64-bit FNV-1a digest of them. FNV's state update is an odd-multiplier
  bijection, so a second-preimage is a meet-in-the-middle over it rather than a
  search of the output space: a full second-preimage against a FIXED victim
  datagram — the exact bytes a responder emits, no attacker influence on them —
  took about fifteen seconds on a laptop, with the solution riding in trailing
  bytes `MessageReader` never reads, because it bounds every section by the
  header counts. The forged datagram was a valid mDNS response announcing a
  different address at the same host name, and matching it bought a whole
  credit: every driver elevates an ordered match to `Provenance::OwnEcho`, so
  the forged datagram's own RFC 6762 §8.2 proposal and §9 conflict rdata were
  deleted with it, and the genuine echo behind it found no credit left and
  reached the protocol layer as peer traffic — a phantom conflict against
  ourselves. A wider digest would not have fixed this: full suppression is only
  safe for a datagram that says exactly what ours said, a property no digest
  can carry, only exact bytes. The credit store now holds the body instead of a
  hash, and new `MAX_SELF_SEND_BYTES` (1 MiB) bounds how many bytes those
  bodies may hold, alongside the unchanged `MAX_SELF_SEND_ENTRIES`; neither cap
  implies the other, and either can refuse a new credit.
- `hick-udp`: new `SelfSendMatch::Superseded`, reported for a credit that
  matched — at either strength — but was recorded before the caller last
  called new `SelfSendTracker::supersede`. RFC 6762 §8.4 record updating is
  unimplemented, but SERVICE REPLACEMENT reaches the same state without it: a
  withdrawing route is deliberately not blocked from replacement, so a service
  may take a host name while the route that previously held it is still
  draining its §10.1 goodbye, and a delayed echo of that route's own
  announcement then carries rdata no live route holds. Suppressing such an
  echo is still safe — take-once still spends the credit — but adjudicating it
  is not: its §8.2 proposal is for a name this endpoint may no longer be
  defending, and its §9 rdata is rdata no live route holds. A driver calls
  `supersede` at every mutation of what it publishes — a service registration,
  the withdrawal that retires a route however it was reached, and the §9
  AUTOMATIC RENAME, which `Service::set_instance` has already applied by the
  time the driver sees `ServiceUpdate::Renamed` and which reaches neither of the
  other two when it succeeds — and maps `Superseded` onto `Provenance::OwnEcho`,
  the only
  tier that denies adjudication, rather than discarding the credit: discarding
  would make the same echo read as `NoCredit`, full peer traffic and full
  adjudication, the same failure louder. `SelfSendMatch` stays
  non-`#[non_exhaustive]`, so the new variant is itself the breaking change:
  every existing match over the type must add an arm.

OTHER

- `hick-reactor`: a receive that reports more bytes than the buffer holds is now
  DROPPED. Three sites answered it with the whole buffer — a longer payload than
  arrived, sent downstream — where `hick-mio` already dropped it. That body is
  what a self-send credit is keyed on, so the divergence became load-bearing.
  The rule is stated once, on `hick_udp::selfsend::RxDatagram`, and `recv_datagram`
  reports `InvalidData` rather than approximating.

# RELEASED

## Dual-stack partial delivery (`TransmitDelivery`) (July 30th, 2026)

Published crates: `mdns-proto` 0.4.0, `hick` 0.3.0, `hick-reactor` 0.3.0,
`hick-compio` 0.3.0, `hick-smoltcp` 0.3.0, `hick-embassy` 0.3.0.

`mdns-proto`'s confirm APIs took a single boolean doing two jobs — advancing
the RFC 6762 lifecycle phase (§8.1 probing / §8.3 announcing, plus the §5.2
query retry budget) and latching §10.1 TTL=0 goodbye ownership — which is
unsound the moment a dual-stack multicast transmit succeeds on one address
family and fails on the other: there is no truthful bool to pass. This release
replaces the boolean with a lossless PER-FAMILY confirm and fixes the resulting
conformance and stranding defects in every released async driver.

BREAKING

- `mdns-proto`: new `TransmitDelivery` struct, carrying one `FamilyDelivery`
  (`Unobligated` / `Delivered` / `Missed`) per address family, reports what each
  family did with a multicast fan-out instead of collapsing it to one bool.
  `Service::note_transmit_outcome` / `Query::note_transmit_outcome` /
  `Endpoint::note_query_transmit_outcome` are now the sole confirm entry points;
  the boolean shims they were added alongside — `note_transmit_result` (on both
  `Service` and `Query`) and `Endpoint::note_query_transmit_result` — are
  removed. Lifecycle phase and the query retry budget advance only on
  `TransmitDelivery::all_delivered()`; goodbye ownership latches on the weaker
  `any_delivered()` — the two facts a single bool could never carry
  independently, and exactly where the removed boolean API was unsound for a
  dual-stack send.
- `mdns-proto`: the periodic §8.3 re-announce is scheduled PER FAMILY, off the
  stalest obligated family in good standing rather than off the last round. Each
  family holds its own copy of the records in its own peers' caches and so races
  its own TTL. A driver with room for one datagram per round serves the
  longest-blocked family first (which is now normative on `TransmitDelivery`), so
  the families alternate: every round is partial while each family is refreshed
  only every OTHER round, at twice the periodic interval — past the TTL for every
  TTL below 128 s, including the conventional 120 s. Records expired cyclically
  on BOTH families while every per-round invariant still held. Every obligated
  family in good standing is now re-announced within `max(0.8·TTL, 2 s)` of its
  last delivery. A family with no socket is excluded rather than read as
  infinitely stale (which would re-arm a single-stack host at the §8.3 one-second
  floor forever), and a family that has spent the core's patience stops driving
  the schedule until it delivers again (which would otherwise hold the deadline
  permanently in the past and flood the healthy family at the same floor).
- `mdns-proto`: the partial-delivery patience bound is counted PER FAMILY. A
  shared counter cannot tell "one family has missed twice" from "two families
  missed one round each while taking turns", and those need opposite answers.
  A phase also advances when every obligated family has carried the CURRENT
  datagram at some point since the last advance: a re-arm is lossless, so the
  same probe index reaching one family in one round and the other in the next has
  been asked on both. That is the only way a capacity-one transport ever
  advances, since under it no single round reaches both families and no family
  ever spends its patience. Neither shape takes the credit a delivery earns —
  `Service::has_fully_announced` still requires ONE datagram confirmed by every
  obligated family.
- `mdns-proto`: new `FullyAnnounced` newtype (opaque; no public constructor)
  replaces the raw `bool` parameter of the reclaim-cancel confirm, which is
  renamed `Endpoint::note_service_announced` (from `note_service_advertised`,
  removed). The old bool's meaning had drifted to "the all-delivered
  announcement fact," but nothing stopped a driver from passing the
  any-delivered exposure latch (`Service::advertises_instance()`) instead —
  which every released driver did, until this release (see FIXES).
  `FullyAnnounced` has no public constructor, so that substitution no longer
  compiles. The token also carries the `ServiceHandle` it was minted from and
  `note_service_announced` takes no separate handle, so one service's proof
  cannot be applied to another (which would cancel that other name's goodbye
  while an obligated family still needed it).
- `mdns-proto`: new `TransmitObligation` enum (`Sustained` / `OneShot`), carried
  on every `Transmit` and readable via `Transmit::obligation()`;
  `Transmit::new` takes it as its fourth argument. It states whether the core will
  re-arm that datagram until every obligated link accepts it, which is what a
  driver needs to know to decide what a PERMANENT send failure costs: a
  `Sustained` datagram that can never be sent would be re-offered forever and so
  retires its producer, while an undeliverable `OneShot` reply costs one
  unanswered question. The tag is a function of what was encoded, not of the
  service's lifecycle phase: the periodic `Established` re-announce advances no
  phase yet is still re-armed on the §8.3 ladder, and `Query::poll_transmit` has
  no service phase at all.
- `mdns-proto`: every `Transmit` also carries the minimum time that must separate
  it from its producer's previous datagram ON ONE ADDRESS FAMILY'S WIRE, readable
  via `Transmit::min_family_gap()` and taken by `Transmit::new` as its fifth
  argument. Drivers enforce it as a per-family earliest-next-send gate, reporting
  a deferred family `Missed`. The confirm anchors at the EARLIEST acceptance
  across families — the proven-safe direction for the TTL guarantee — so under
  inter-family skew `s` the core schedules the next datagram one interval after
  the EARLY family's wire time and the LATE family's own gap is `interval − s`:
  an announcement fell under RFC 6762 §6 / §8.3's one-second floor at every TTL
  and a §8.1 probe gap could approach zero. The core cannot see `s`; the driver
  measured it. The VALUE stays in the core because it is kind-dependent — §8.1
  spaces probes 250 ms apart and exempts them from the one-second rule that
  governs announcements and §5.2 query retransmissions — so a driver that picked
  the number itself would have taken protocol policy across the sans-I/O
  boundary. `TransmitObligation::OneShot` datagrams carry `Duration::ZERO` and
  are ungated: the core never re-arms them, so a gate could only drop them.
- The bound on repeated partial delivery lives in `mdns-proto`, not in drivers.
  Repeated partial delivery re-arms indefinitely, so the core bounds how many
  consecutive re-arms one producer spends waiting for a family that never accepts
  and then advances the phase without it. A driver reports the honest per-family
  facts and nothing else. The split is normative on `TransmitDelivery`'s rustdoc:
  the driver owns the obligated set and link death — and MUST offer every
  obligated family on every round, preferring the longest-blocked one under a
  constrained slot — while the core owns its own patience and its own
  schedule.
- Confirm before anything else. Once `Service::poll_transmit` /
  `Query::poll_transmit` returns a datagram, no other state-mutating entry point
  for that service or query — `handle_event`, `handle_timeout`,
  `withdrawal_snapshot` / teardown — may run until its `note_transmit_outcome`;
  `poll_transmit` itself is excepted and refuses while one is outstanding. A
  driver that cannot send right now DROPS the datagram and confirms
  as carried by no family in the same call rather than parking it: "delivered" here
  already means only that the kernel accepted the datagram synchronously, so a
  deferred confirm buys no fidelity while leaving the pending token's lifecycle
  meaning undecided. Normative on `Service::poll_transmit`'s rustdoc, asserted in
  debug builds. All four drivers in this workspace already comply.
- `mdns-proto`: `Endpoint::try_register_service` rejects a record TTL below
  `constants::MIN_SERVICE_TTL_SECS` (2 s) with the new
  `RegisterServiceError::TtlTooSmall`. A TTL-0 positive record is the RFC 6762
  §10.1 goodbye encoding — it deletes the record from peer caches instead of
  publishing it — and TTL 1 refreshes at 0.8 s, inside §8.3's one-second floor on
  unsolicited responses. Both also truncate the ~80 %-of-TTL periodic refresh to
  a zero-second interval, which re-armed an `Established` service at `now` and
  repumped an announcement every tick. The TTL is rejected rather than clamped.

FIXES (dependent-crate behaviour; visible without any source change on the
caller's part)

- All four drivers (`hick-reactor`, `hick-compio`, `hick-smoltcp`,
  `hick-embassy`): a partially-delivered dual-stack transmit no longer advances
  the §8.1 probe sequence or the §8.3 announce phase, and no longer burns a
  §5.2 query retry. Previously any single successful socket send (e.g. IPv4
  only) advanced the lifecycle even though the other family was never probed —
  an RFC 6762 §8.1 conformance defect. A service on a host where one family is
  unreachable now takes longer to establish instead of establishing a name it
  never defended on that family.
- All four drivers: the reclaim-cancel gate is now the all-delivered
  announcement fact, not any single delivery. A replacement service reclaiming
  a renamed-away name no longer cancels that name's still-draining TTL=0
  goodbye until it has announced on every family the driver still obligates —
  previously a single-family announcement, or even an RFC 6762 §6.7 legacy
  unicast reply, could cancel it. Fixes stranded peers on the unserved family
  holding withdrawn records until positive TTL.
- `mdns-proto`: bounded patience — after two consecutive partially-delivered
  lifecycle confirms for the same service or query, the third is EXCUSED and the
  phase advances without the link that keeps missing. A permanently
  half-reachable link now still reaches `Established` — after ~30 s, since the
  served link's announcements stay on §8.3's doubling ladder throughout —
  instead of pinning in probing forever. An excused advance is not a
  delivery: it does not set `Service::has_fully_announced`, does not reset the
  §8.3 / §5.2 doubling ladder (and never re-arms EARLIER than the rung the served
  link already earned), and does not bump `probes_tx` / `announcements_tx` —
  those counters mean "confirmed delivered by every obligated link", so a
  permanently half-broken host no longer reports a healthy startup.
  A round that reached no wire leaves every count untouched, so an alternating
  partial/failed pattern cannot evade the bound — and no phase can ever advance
  out of silence, which is what §8.1 requires of anything that claims a name. The count is reset wherever the lifecycle
  regresses to `Init` — both the §9 conflict rename and the RFC 6763 §9 same-name
  revert-to-probe, the latter of which emits no `ServiceUpdate` and so was
  unreachable from a driver.
- Because the count lives inside the per-kind confirm arms, a response (the §6
  multicast reply, the §6.7 legacy unicast reply, the RFC 6763 §9 meta reply)
  structurally cannot move it. Those datagrams are never re-armed, so counting
  them corrupts the bound in both directions: a unicast reply has one obligated
  family and is all-delivered by construction, so it would RESET the count — a
  service answering legacy queriers between lifecycle rounds would hold it at
  zero and the bound would never fire; and a partially-delivered multicast
  response would PRELOAD it, so the next partial probe would be excused and §8.1
  would advance although one family never heard the probe.
- `hick-smoltcp` / `hick-embassy`: a multicast RESPONSE that is permanently
  undeliverable (too large for every reachable socket) no longer retires the
  service. It resolves as delivered by no family — nothing latched, nothing advanced,
  the querier re-asks — matching the adjacent unicast branch. Previously any
  on-link peer could tear down a healthy established service by asking it a
  question whose answer did not fit the TX buffer: the service was marked
  errored, surfaced `Conflict`, and began withdrawing. An undeliverable
  `Sustained` datagram (probe, announcement, query) still retires its producer,
  which is the case that reasoning was written for.
- `hick-smoltcp` / `hick-embassy`: a PRESENT but unbound (or unaddressable) UDP
  socket is now `SendError::Busy`, not `SendError::Unsupported`. `Unsupported`
  removes a family from the obligated set, so a bound-IPv4 + present-but-unbound
  -IPv6 fan-out read as all-delivered and advanced §8.1 probing as though the node
  had no IPv6 at all. That family now reports `FamilyDelivery::Missed` and is
  retried.
- All four drivers: a family that carried a producer's previous datagram is no
  longer offered the next one until `Transmit::min_family_gap()` has elapsed ON
  ITS OWN WIRE, and is reported `FamilyDelivery::Missed` for the round it is
  deferred. Under inter-family skew the confirm's earliest-acceptance anchor put
  the late family's successive announcements inside RFC 6762 §6 / §8.3's
  one-second floor at every TTL, and could drive a §8.1 probe gap toward zero.
  The core re-arms losslessly, so a deferred family carries the same datagram on
  the next round.
- `hick-reactor`: one driver pass is bounded by an aggregate wall-clock budget
  spanning both the transmit drain and the §10.1 goodbye pump, and resumes at a
  rotating cursor. Producers are awaited serially and the 64-send credit budget
  is charged only per family that actually SENT, so an all-miss fan-out cost zero
  credits while still costing a whole per-attempt bound: a pass of `n`
  simultaneously-due producers with one wedged family ran for `n × 250 ms` with
  the 64-slot packet channel backing up behind it and inbound peer datagrams
  being dropped. The goodbye pump had no budget of any kind. The cursor is what
  keeps the new budget a delay rather than a starvation — without it every pass
  would restart at the front of the handle set and the producers behind the first
  cut would never be reached.
- `mdns-proto`: an obligation gap now clears the returning family's COVERAGE bit
  along with the rest of its state. A family that delivered, ceased to be
  obligated during an all-miss round, and then returned kept a stale claim to
  have carried the datagram still outstanding, so the next round could read
  `all(covered)` and advance the phase on pre-gap evidence — the returned family
  never had to receive the current datagram. Unreachable from the in-tree
  drivers, which fix their obligated set at spawn; the core is a public library
  and a driver whose obligated set varies at runtime is exactly what the
  three-valued `FamilyDelivery` exists to support. A gap containing no confirmed
  round remains invisible to the core by construction.
- `hick-reactor` / `hick-compio` only: RFC 6762 §6.7 legacy unicast replies no
  longer record a self-send credit. A unicast reply never loops back to its
  sender, so the credit could never be consumed; under a legacy-query flood
  the 65,536-entry tracker filled with dead entries and began refusing genuine
  multicast credits, causing the responder to ingest its own loopback as peer
  traffic.

The dependent crates (`hick`, `hick-reactor`, `hick-compio`, `hick-smoltcp`,
`hick-embassy`) bump to 0.3.0 to track the `mdns-proto` 0.4 public dependency;
`hick-udp` and `hick-trace` are unaffected.

## Drop the `heapless` tier (June 8th, 2026)

Published crates: `mdns-proto` 0.3.0, `hick` 0.2.0, `hick-reactor` 0.2.0,
`hick-compio` 0.2.0, `hick-smoltcp` 0.2.0, `hick-embassy` 0.2.0.

BREAKING

- Removed `mdns-proto`'s `heapless` feature and its no-allocator owned-storage
  tier. Owning variable-length protocol data without an allocator is inherently
  either fat (a fixed `heapless::String<255>` inline per name) or complex (an
  in-buffer sub-allocator), so the rule is now simply: **owning a `Name` /
  `ServiceSpec` and building messages requires an allocator** (`alloc` / `std` /
  `no-atomic`); the bare `--no-default-features` tier is **parse-only** (the
  borrowed `wire::NameRef`). This drops the large fixed-capacity inline structs
  that were a poor fit for `no_std` stack budgets.
- As a result the internal `cfg_storage` / `cfg_heap` macro split collapses
  (both predicates are now `any(alloc, std, no-atomic)`), and `Name`,
  `QuerySpec`, `ServiceUpdate`, and `MessageBuilder` are gated on the allocator
  tiers.

The dependent crates (`hick`, `hick-reactor`, `hick-compio`, `hick-smoltcp`,
`hick-embassy`) bump to 0.2.0 to track the `mdns-proto` 0.3 public dependency.
`hick-udp` and `hick-trace` are unaffected.

## Bare-metal no-atomic tier (June 6th, 2026)

Published crates: `mdns-proto` 0.2.1, `hick` 0.1.1, `hick-smoltcp` 0.1.1,
`hick-embassy` 0.1.1.

Support for bare-metal cores **without native atomic CAS** (Cortex-M0+ /
thumbv6m / RP2040), fixing a build failure on those targets (#40). The default
`atomic` tier is unchanged, so existing builds are unaffected.

FEATURES

- `mdns-proto` gains a `no-atomic` storage tier: the same alloc-backed
  `Endpoint`, but the refcounted `Name` / rdata use `portable-atomic`'s `Arc`
  (cheap clone via a `critical-section` impl the binary provides) instead of
  `smol_str` + `bytes`, which require native pointer-width atomics.
- `hick-smoltcp` and `hick-embassy` gain `atomic` (default) vs `no-atomic`
  feature tiers. Build for RP2040-class targets with
  `--no-default-features --features no-atomic`.
- The `hick` facade gains `smoltcp-no-atomic` / `embassy-no-atomic` features
  that reach the no-atomic tier through the umbrella crate.

FIXES

- `hick-embassy` and the rest of the bare-metal stack now build for
  `thumbv6m-none-eabi`; previously `mdns-proto`'s alloc tier pulled `smol_str`
  (`alloc::sync::Arc`) and `bytes` (atomic refcount), neither available without
  native atomic CAS (#40).

## 0.1.0 (June 6th, 2026)

First public release of the `hick` mDNS / DNS-SD family (the project formerly
known as `agnostic-mdns`), rebuilt on a Sans-I/O protocol core with pluggable
async drivers.

Published crates: `hick` 0.1.0, `mdns-proto` 0.2.0, `hick-udp` 0.1.0,
`hick-reactor` 0.1.0, `hick-compio` 0.1.0, `hick-smoltcp` 0.1.0,
`hick-embassy` 0.1.0, `hick-trace` 0.1.0.

FEATURES

- Sans-I/O mDNS / DNS-SD protocol core (`mdns-proto`), `no_std`-capable on
  `alloc` or `heapless`, with a `#![forbid(unsafe_code)]` core.
- Runtime-agnostic async drivers: `tokio` and `smol` via `hick-reactor`, and
  `compio` (thread-per-core) via `hick-compio`.
- Bare-metal drivers over smoltcp: `hick-smoltcp` (runtime-agnostic engine) and
  `hick-embassy` (embassy-net async driver), both `no_std` + `alloc`.
- RFC 6762 / 6763 conformance: probing and announcing, name-conflict detection
  with automatic renaming, known-answer and duplicate-question suppression,
  TTL-accurate caching, and TTL=0 goodbyes on withdrawal.
- Multicast UDP socket layer (`hick-udp`) over rustix on unix and
  socket2 + windows-sys on Windows.
- Observability via `hick-trace`: opt-in `tracing`, `metrics`, `stats`, and
  `defmt`.

MSRV: Rust 1.91 (edition 2024). Licensed under MIT OR Apache-2.0.

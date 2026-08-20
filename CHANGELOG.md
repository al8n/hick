# UNRELEASED

## A persistent same-name peer no longer drives one record set's rename loop unthrottled

- `mdns-proto`: a `Service` now applies RFC 6762 §8.1's flood limit — "if
  fifteen conflicts occur within any ten-second period, then the host MUST wait
  at least five seconds before each successive additional probe attempt" — **to
  its own record set**. Every conflict-driven probe sequence was scheduled with
  §8.1's ordinary 0-250 ms *startup* delay however many renames had already
  happened, so a peer that defends each name the service renames itself to —
  hostile, or merely a misconfigured twin — drove an unbounded rename → announce
  → probe loop, each turn putting packets on the link. The count is of CONFLICTS, which is what
  §8.1 counts, so it deliberately spans renames and probe restarts: resetting it
  on a rename would reset it on the very event being throttled. It is kept in a
  fixed ring of fifteen instants — the condition is exactly "is the
  fifteenth-most-recent conflict within ten seconds of now" — so nothing is
  allocated. Once in force the floor applies to *each* successive attempt and is
  released only by the flood stopping: a whole ten-second window with no
  conflict at all. Re-deriving it per probe instead would come off two turns
  later and hand the flood its speed back, because five-second spacing is itself
  too slow to keep fifteen conflicts inside ten seconds. The floor is applied
  where every restarted sequence gets its start time, so it covers §9's
  revert-to-probing, §8.2's one-second deferral and §8.1's rename alike, and
  raises each only when the limit is in force. §9's own
  `CONFLICT_REPROBE_MIN_INTERVAL` is a different rule over a different quantity
  and is unchanged: it still bounds how often an established name may be sent
  back to probing at all, and a conflict it drops re-probes nothing and is
  counted by neither rule.
- `mdns-proto`: **the scope of that limit is per record set, and §8.1 states its
  obligation on the host.** The counter lives on one `Service`, so what it bounds
  is one record set's restarts, and three ways past it are known and remain open.
  Conflicts are not aggregated across record sets: fifteen entries spaced `d`
  apart span `14·d`, so a service whose restarts are slower than 10/14 ≈ 0.714 s
  never latches at all, and N services contending at that rate put N × 1.4
  restarts per second on the link between them. A freshly registered service
  starts with an empty ring and is not slowed by another service's backoff
  already being in force. And the history dies with the `Service`: a
  `HostConflict` is terminal and is surfaced for the caller to intervene, and the
  usual intervention — unregister, then re-register under a new host name — hands
  the replacement a clean ring, so a loop closed through the driver layer evades
  even the per-record-set latch. Aggregating the ring at the `Endpoint` and
  sharing only the verdict is tracked as **#140**; that will make the limit
  endpoint-wide, which is still not host-wide, because a second `Endpoint`, or a
  second process, on the same machine is beyond anything this library can
  observe.

## A relinquished record set can no longer retire its own replacement

- `mdns-proto`: `Endpoint` screens every conflict candidate against the record
  sets it recently **asserted and relinquished**, not only against the receiving
  service's current records, before any `HostConflict` / `ProbeConflict` is
  built. A withdrawing route stops holding its host name for the registration
  guard, so a replacement may take host `H` with address set `A2` while the route
  that held `H` with `A1` is still draining its RFC 6762 §10.1 goodbye; a delayed
  positive-TTL echo of `A1` — **our own bytes** — was then adjudicated against
  `A2` and retired a live service with a TERMINAL `ServiceUpdate::HostConflict`.
  Same-instance reuse with changed SRV/TXT reached a false §8.1 probe defeat the
  same way. A match cannot settle whether the record really is a delayed echo of
  ours: §9 exists to protect a fault-tolerance twin "capable of issuing identical
  answers", and such a twin's defence is byte-for-byte what our own ghost's echo
  would be, so only FUTURE behaviour — whether a re-probe gets answered — can
  tell them apart. The screen therefore **labels** a match with new
  `ConflictHistory::Relinquished` (read via new `ProbeConflict::history`) rather
  than deciding it outright, and what the label buys depends on what the
  receiving cell would otherwise do: a pre-authoritative instance conflict is
  still delivered, and the service spends the label on RFC 6762 §8.2's existing
  one-second defer-and-re-probe instead of an immediate §8.1 rename — a ghost
  cannot answer the re-probe and a live incumbent can; an **established**
  instance conflict is delivered too and the label buys it **nothing**, because
  §9's revert-to-probing already is a rate-limited re-verification of the same
  name — screening it instead withheld §9's "MUST immediately reset" from a peer
  whose §8.3 announcement burst is bounded and never repeated, so the window
  swallowed the conflict entire rather than delaying it and two responders kept
  one advertised name; and a `HostConflict` is still
  dropped in the fan-out, because it is terminal and caller-visible and the host
  name is never probed, so no re-probe's silence could convict a
  ghost of it (a route whose instance name IS its host name still receives the
  record as a labelled `ProbeConflict`, since A/AAAA under that name also belong
  to that route's own §8.2 proposal). The screen reads two sources: withdrawal
  items still resident (a withdrawing route's own set, and a §9 rename's
  abandoned instance name), and a bounded retention list fed at withdrawal
  completion and at the rename. Service B structurally cannot know the stale set
  was ours; only the endpoint can state that fact, and only the service, which
  alone can see lifecycle phase, can decide what the fact is worth.
- `mdns-proto`: the relinquished-history screen is now fed **only by confirmed
  MULTICAST emissions**, and the exposure record is split in two to say so. "A
  peer may hold this record from us" and "a copy of these bytes may still be
  echoing" were one latch, and an RFC 6762 §6.7 legacy reply separates them: it
  is a real, confirmed, positive-TTL send of the FULL record set, so the first is
  true of it and the §10.1 goodbye owes it a retraction — and it is addressed to
  one resolver's ephemeral port, so the second is not, because nothing
  re-broadcasts it to the group and this screen is only ever asked about a
  multicast arrival. A service whose only positive send was such a reply
  therefore retained a row that disowned every matching multicast record for the
  whole retention window, suppressing a GENUINE peer's terminal
  `ServiceUpdate::HostConflict` on the strength of bytes no multicast socket ever
  carried. `GoodbyeOwnership` now keeps both halves, every layer the exposure
  crosses carries both (`WithdrawalSnapshot`, `RenameGoodbyeHandoff`, the
  withdrawal item, the retained row), and only the narrower one reaches the
  screen. The goodbye's half is unchanged and deliberately still counts the
  unicast send — narrowing it would strand a legacy querier's cached records with
  nothing to retract them — and so are `advertises_instance` /
  `advertises_host` / the sibling-retained address union, which are questions
  about peer caches rather than about echoes.
- `mdns-proto`: a `ProbeConflict` now carries which of the receiving route's
  names its record owns — new `ConflictRole` (`Instance` / `InstanceAndHost`),
  read via new `ProbeConflict::role`. It matters only where one name wears both
  roles. The fan-out tests the host rule first, so a labelled A/AAAA there
  reaches the instance rule by falling through a host rule that MATCHED, and
  that rule had already proved the route authoritative for an A/AAAA RRset at
  that name. Delivering the record stripped of the proof made the two lifecycle
  cells disagree about one datagram: pre-authoritatively it drove §8.2's
  deferral, while an established service asked its instance-authority gate —
  `canonical_rdata_forms`, whose domain is SRV/TXT/NSEC — whether it asserts an
  address there, was told no, and **silently discarded** the record. §9's "MUST
  immediately reset" therefore never ran, and §8.3 bounds the incumbent's burst,
  so the retention window swallowed every copy there was. The host cell's own
  reason for suppressing does not reach this owner either: it suppresses because
  the host name is never probed, and this owner IS probed — `write_probe` asks
  ANY for it and proposes exactly these A/AAAA — so the re-verification the host
  cell lacks already exists. The role now travels with the record; the
  identical-rdata precondition classifies it as a **host** record (so an address
  this service publishes is §9's "never inconsistent", which the instance
  classifier could not read at all and called differing), and the established
  cell reaches §9's reversible same-name reset instead of dropping it. The
  terminal `HostConflict` is still withheld — the fall-through carries the host
  rule's authority, never its verdict.
- `mdns-proto`: new `EndpointConfig::relinquished_retention` /
  `with_relinquished_retention`, defaulting to five seconds — long enough to
  outlast both a driver's self-send recency window and the §10.1 goodbye ceiling.
  `Duration::ZERO` disables the retention half. The residual is stated rather
  than hidden: a real peer asserting, within the window, rdata exactly equal to a
  set we just relinquished at that same owner has a **pre-authoritative** rename,
  or a terminal `HostConflict`, delayed by up to that long, per the cell-by-cell
  rule above — an established instance conflict is not delayed at
  all. It self-corrects, and
  it is not an attack surface — mDNS is unauthenticated, so a forger never
  needed our bytes.
- `mdns-proto`, `hick-udp`, `hick-mio`, `hick-reactor`, `hick-compio`,
  `hick-smoltcp`: the driver-side generation binding — a self-send credit bound
  to the record generation it was sent under, reported as
  `Provenance::OwnEchoLikely` once superseded rather than kept at `OwnEcho` — is
  **defence in depth**, and every doc that said otherwise is corrected. It
  cannot be the load-bearing check: recognising the echo is defeasible three
  independent ways, none of which a driver can close — an on-link peer replaying
  captured bytes reproduces every signal a send log weighs, one send is credited
  once per family while the medium may deliver several copies (kernel loopback
  plus an 802.11 base-station re-broadcast, which §8.2 names), and credits are
  evicted under load. Each leaves the GENUINE echo reading "no credit", hence
  `NotFromUs`, hence fully adjudicated. What the binding still buys is the other
  half of the harm: a stale echo must not populate this endpoint's cache with
  records it no longer publishes, nor quiet its own traffic on their behalf.
- `hick-udp`, `hick-smoltcp`: a SUPERSEDED self-send credit is a **standing
  tombstone** rather than a take-once one. Every byte-identical copy inside the
  recency window reports it, and no claim consumes it; only the TTL and the byte
  budget retire one, so the memory bound is unchanged. Take-once survives at the
  CURRENT tier, where a conforming RFC 6762 §9 twin's datagram must become
  visible from its second one, and where a leaked copy is harmless anyway because
  it asserts rdata still published. Spending a superseded credit bought nothing —
  what those bytes assert is a set this endpoint has given up, so suppressing
  every copy can only delay detecting an assertion no live route holds, and an
  attacker "denied" the replay could forge the same assertion without our bytes —
  and it cost this: one send is credited once per family while the medium may
  deliver several copies, so the copy that spent the credit left the GENUINE echo
  behind it admitted as peer traffic, writing our own withdrawn records into our
  own cache. `hick-udp` also now prefers a CURRENT credit over a superseded copy
  of the same bytes, the rule `hick-smoltcp` already applied, without which a
  standing tombstone would shadow the current tier for the whole window.
- `hick-mio`, `hick-reactor`, `hick-compio`, `hick-smoltcp` (and `hick-embassy`,
  which inherits it): **a service registration no longer advances the self-send
  generation.** The seam is deleted from all four drivers. `supersede` declares
  that what this endpoint publishes has CHANGED, so every credit already recorded
  describes a state it has left — and a registration only INSERTS a route. It
  mutates no record already asserted: RFC 6762 §8.4 record updating is
  unimplemented and a `Service` exposes no records mutator, a duplicate instance
  name and a name a collision goodbye still holds are both refused, and a live
  route publishing the same host name with a different A or AAAA set makes the
  registration fail outright. The negative assertions are covered too — the
  encoder emits exactly one §6.1 NSEC per service, owned by the INSTANCE name, so
  no sibling registration can flip a host-name NSEC's truth. Nothing this
  endpoint had asserted changed truth-value there, so the advance asserted
  something false about its own records. With a superseded credit now a standing
  tombstone, that falsehood was expensive rather than free: one unrelated
  registration denied §10 observation and §7.1/§7.3 quieting to EVERY
  byte-identical copy of a live service's own bytes for the whole recency
  window — to a conforming §9 fault-tolerance twin's identical answers, and to a
  genuine peer's TTL=0 §10.1 goodbye burst, which then reached no cache at all
  and left the entry it exists to retract standing for its FULL original TTL
  instead of §10.1's one-second clamp. The `begin_withdrawal` and §9 automatic
  rename seams are untouched — those really are mutations, and the advance is
  owed at both.
- The residual of the above is stated rather than hidden, in the same spirit as
  `relinquished_retention`'s: there is ONE generation for the whole send log, not
  one per route, so a GENUINE advance still demotes the outstanding credits of
  every service the seam did not touch. Sequential withdrawal is the sharp case —
  tearing down service N+1 demotes service N's just-sent goodbye credit — and the
  harm is the same pair, observation and quieting denied to every copy for the
  rest of the window. Its preconditions are compound: a §9 fault-tolerance twin
  whose datagram is byte-identical to one this endpoint itself sent inside the
  window, plus a lifecycle event inside that same window, plus the whole of the
  twin's burst inside it. Fixing it properly needs a record-set delta computed in
  `mdns-proto`, which becomes mandatory only if §8.4 record updating lands; a
  delta that is wrong UNDER-supersedes, which is the harmful direction, so it is
  not built speculatively.
- **BREAKING:** `Endpoint::unregister_service` — the sans-I/O core's
  force-remove primitive, not the same-named wrapper each of the four bundled
  drivers exposes over the ordinary withdrawal lifecycle — takes two new
  required parameters, `asserted: Option<WithdrawalSnapshot>` and `now: I`, in
  place of just a handle. Force removal frees the owner names the instant it
  returns and sends no goodbye, so it was the one relinquishing path that used
  to feed nothing to the screen above: a service force-removed right after a
  confirmed positive send, with a replacement registered at the same owner
  names in the very next statement, let a delayed echo of the removed
  service's own records reach ordinary conflict adjudication and retire the
  replacement. `asserted` is the removed service's `Service::withdrawal_snapshot`
  — the same value `begin_withdrawal` already took, reporting what a confirmed
  send actually emitted — and `now` anchors the `EndpointConfig::relinquished_retention`
  window the same way it does when a normal withdrawal completes. Pass
  `Some(..)` whenever the `Service` still exists; `None` is only for a caller
  with no `Service` left to ask — the state machine already dropped, or its
  goodbye already drained and retained by `drain_completed_withdrawals` when it
  completed. None of the four bundled drivers call this method directly, so
  this breaks only a direct caller of the `mdns-proto` core — exactly who has
  no wrapper to shield them and no other way to learn of it.
- `hick-trace`: **BREAKING** — `StatsSnapshot` is now `#[non_exhaustive]`, and
  gains the field `relinquished_host_conflicts_suppressed`, with the matching
  `Stats` counter exported as `mdns_relinquished_host_conflicts_suppressed`.
  The attribute is the breaking half: a downstream crate can no longer build a
  `StatsSnapshot` with a struct literal, and that includes functional-update
  syntax — `StatsSnapshot { conflicts: 3, ..Default::default() }` no longer
  compiles outside `hick-trace`. Reads, `Default::default()`, `Clone`/`Copy`
  and comparisons are unaffected, and nothing in this workspace constructed or
  destructured one, so no bundled driver changes. It is deliberate and it is
  the reason to do it in this release: the type exists to be read rather than
  built, it accrues a counter whenever an accepted residual needs to become
  observable, and without the attribute each of those is another breaking
  change to `hick-trace` — which in practice means the counter does not get
  added and the residual stays silent. From here a new counter is additive.
  This is the first breaking change to `hick-trace`, which two earlier entries
  in this file describe as unaffected. What the new counter counts is the one
  place the relinquished screen still
  DROPS a conflict rather than labelling it: a peer's record matching this
  endpoint's own recently-relinquished history at a HOST name, on a route whose
  instance name differs, leaving no instance role to fall through to. That drop
  is deliberate and stays — the host cell has no recoverable, self-verifying
  consequence to spend a label on, the way an instance cell spends one on
  §8.2's defer-and-re-probe, so delivering it anyway would trade an
  unverifiable silent error for an unverifiable loud one at higher frequency,
  and a renamed host does not un-rename. Tracked as issue #92 (host-name
  ownership), which carries the obligation that once the host name gets its own
  probing and defence, this suppression becomes delivery-labelled like the
  instance cells. Until then the counter is the only field evidence the
  suppression ever ran — it was previously silent, which is why it took
  adversarial review rather than a bug report to surface it.

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
  service began withdrawing or took a §9 automatic rename, so it
  may assert records no live route holds — reports the SAME `OwnEchoLikely`
  tier rather than a stronger one: a stale match is no better evidence of
  origin than a current one, so it may buy only the denials that protect this
  endpoint (§10 cache population, §7.1/§7.3 quieting) and never the one that
  costs a PEER its name. What a stale echo's worst reachable outcome once
  turned on is held better and elsewhere — the `relinquished_retention` screen
  above, on this endpoint's own lifecycle rather than on recognising a
  datagram.
- **`hick-smoltcp`'s self-send log becomes take-once, address-family keyed and
  source-port gated**, and `hick-embassy` inherits all three. It is what the
  `OwnEchoLikely` above may not be granted without: exact equality with a past send
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
  began withdrawing or took a §9 automatic rename reports
  `OwnEchoLikely` as well, never `OwnEcho`: staleness is a fact about this
  endpoint's own records, not evidence about the sender, so it may buy the
  denials that protect this endpoint (§10 caching, §7.1/§7.3 quieting) and not
  the one that costs a PEER its name — the reason the bullet above gives. No
  credit, or a source port this endpoint never sends from, becomes `NotFromUs`
  rather than `Unknown`, which additionally declines `trust_advertised_src_as_self`
  on these drivers.

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
  announcement then carries rdata no live route holds. Its credit is kept
  rather than discarded because keeping it still buys what a CURRENT echo's
  credit buys — denial of observation and quieting, so admitting the echo as
  peer traffic cannot write this endpoint's own withdrawn records into its own
  cache or defer its own retransmits on their behalf — but adjudicating it is
  safe rather than merely tolerated: its §8.2 proposal is for a name this
  endpoint may no longer be defending and its §9 rdata is rdata no live route
  holds, yet the worst that could otherwise cause, a stale announcement
  retiring the service that replaced it, is what `mdns-proto`'s
  relinquished-history screen closes independently, on this endpoint's own
  lifecycle rather than on recognising the datagram. A driver calls `supersede`
  at every mutation of what it publishes — a service registration, the
  withdrawal that retires a route however it was reached, and the §9 AUTOMATIC
  RENAME, which `Service::set_instance` has already applied by the time the
  driver sees `ServiceUpdate::Renamed` and which reaches neither of the other
  two when it succeeds — and maps `Superseded` onto `Provenance::OwnEchoLikely`,
  the same tier a CURRENT content-only match gets, rather than discarding the
  credit: discarding would make the same echo read as `NoCredit`, hence
  `NotFromUs`, losing the cache and quieting denials without buying anything
  back, since both tiers adjudicate alike. `SelfSendMatch` stays
  non-`#[non_exhaustive]`, so the new variant is itself the breaking change:
  every existing match over the type must add an arm.

OTHER

- `hick-reactor`: a receive that reports more bytes than the buffer holds is now
  DROPPED. Three sites answered it with the whole buffer — a longer payload than
  arrived, sent downstream — where `hick-mio` already dropped it. That body is
  what a self-send credit is keyed on, so the divergence became load-bearing.
  The rule is stated once, on `hick_udp::selfsend::RxDatagram`, and `recv_datagram`
  reports `InvalidData` rather than approximating.

## A bind can no longer silently misapply an IPv4 multicast socket option

OTHER

- `hick-udp`: `try_bind_v4` now reads `IP_MULTICAST_LOOP` and `IP_MULTICAST_TTL`
  back immediately after setting them, and **fails the bind** with new
  `BindError::MulticastLoopNotApplied` / `BindError::MulticastTtlNotApplied` if
  the kernel accepted the `setsockopt` call but holds a value other than the
  one requested — the same read-back-and-fail policy the existing IPv6 twin,
  `BindError::MulticastHopsNotApplied`, already used. A successful return code
  is not proof the kernel stored the value: a wrong transport width on a target
  where either scalar is a narrower field than this crate assumed, or a future
  change that routes either setter onto a wrong level or constant, can each
  leave `setsockopt` reporting success while the kernel keeps its own default.
  That is worth failing the bind over rather than merely logging: a multicast
  TTL silently held at 0 means nothing this responder ever sends leaves the
  host, a complete and silent failure that is far harder to diagnose in the
  field than a bind refused up front. `BindError` is `#[non_exhaustive]`, so
  this is additive rather than a compile break — but a bind that previously
  succeeded can now fail on an affected host, and nothing in an existing build
  warns of the new failure mode.
- `hick-udp`: `try_bind_v4` also reads `IP_MULTICAST_IF` back, but only WARNS
  on a disagreement rather than failing the bind — deliberately asymmetric with
  the two options above, not an inconsistency to line up with them later. This
  option's GET direction could not be confirmed from source to round-trip
  correctly on FreeBSD, DragonFly, OpenBSD or NetBSD — a kernel may
  legitimately report the interface's primary address, or `INADDR_ANY`, which
  would be indistinguishable here from a real drift — and three of those four
  targets have no runner anywhere in this workspace, so a hard failure would
  risk bricking the IPv4 bind on a conforming host with no way to find out
  first. The historical silent-unset defect this guards against is already
  closed upstream by the pre-existing `BindError::InterfaceNotFound`, which
  fires when the requested interface index names no interface or carries no
  IPv4 address at all (and by `BindError::Io` when that look-up itself failed —
  see below).

## A bind that cannot honour the interface it was given now says so

- `hick-udp`: **BREAKING** — `BindError::AddressInUse` and its
  `AddressInUseDetail` are removed, and `AddressInUseDetail` is no longer
  re-exported from the crate root. Nothing ever constructed the variant: an
  address-in-use failure has always surfaced as `BindError::Io`, so a caller
  matching on `AddressInUse` was matching a branch the library could not
  produce. `BindError` is `#[non_exhaustive]`, but that permits *adding*
  variants rather than removing one, so this can only happen in a major
  release — hence now. A caller that matched it should match `BindError::Io`
  and inspect `ErrorKind::AddrInUse`, which is what the four bundled drivers'
  test helpers already did alongside the dead arm.
- `hick-udp`: `try_bind_v6` now resolves a non-zero interface index before it
  binds, and answers each of the three things that look-up can report on its
  own terms. An index that names **no interface** is rejected with the existing
  `BindError::InterfaceNotFound`, as `try_bind_v4` has done for some time: the
  kernel rejects it too, but as a bare `BindError::Io` no caller can tell from
  any other I/O error. An interface that reports **no IPv6 address**, and a
  look-up that **failed**, are logged and the bind proceeds. That is not a
  softer reading of how much those two matter — `IPV6_MULTICAST_IF` takes the
  interface INDEX, so the address resolved here is evidence and never a
  payload, nothing the bind does needs it, and a refusal on it would be bought
  with no decision. Neither state is a reliable negative either: an addressless
  interface is an IPv4-only NIC *or* one whose RA/SLAAC address has not landed
  yet, and `getifs` returns `EINTR` by design when an address dump is
  interrupted by DHCP, a VPN coming up or interface churn. Link-local-only
  interfaces are unaffected and still bind silently: the "reports any IPv6
  address" predicate includes `fe80::/10`.
- `hick-udp`: `try_bind_v4` and `try_join_v4` now report an interface look-up
  that **failed** as `BindError::Io` / `JoinError::Io`, carrying the platform's
  own error kind plus the index and family, instead of `InterfaceNotFound`.
  Both still fail on an index that names no interface and on one carrying no
  IPv4 address — there the resolved address is the `IP_MULTICAST_IF` payload,
  and each address is its own `IP_ADD_MEMBERSHIP`, so neither can proceed
  without one — but an enumeration that could not be read establishes nothing
  about the interface, and calling it "not found" sent a caller auditing an
  interface nobody managed to read. `try_join_v4` runs at endpoint construction
  in all three drivers that depend on this crate, where it surfaces as
  `ServerError::BindV4`. No new public API in any of this: every error variant
  and detail type used here already existed.
- `mdns-proto`: `Endpoint::try_register_service` now rejects a `ServiceSpec`
  whose `service_type` is not the immediate parent of its instance name,
  with the new `RegisterServiceError::ServiceTypeNotParent` carrying both
  names. `RegisterServiceError` is `#[non_exhaustive]`, so the variant is
  additive. `ServiceRecords::new` has always documented the requirement —
  "It must be the parent label sequence of `instance`" — and, being an
  infallible constructor, could not enforce it; an unrelated pair published a
  PTR whose owner the instance's SRV did not belong to, which is internally
  inconsistent on the wire. Registration is where it is now caught, beside the
  existing TTL check, before the name is reserved. The comparison is a DNS
  owner comparison, not a string suffix test: a service type differing from
  the instance's suffix only in case or in the optional trailing root dot is
  **accepted**. RFC 6763 §4.1.1 stores `<Instance>` as a single DNS label, so
  exactly one extra label is required — `a.b._ipp._tcp.local.` is not a valid
  instance of `_ipp._tcp.local.` even though the type names a real suffix of
  it. New public `ServiceTypeNotParentDetail`. `service_type` being the DNS
  root (the empty name) is rejected separately, as new
  `RegisterServiceError::ServiceTypeIsRoot` carrying the instance name: RFC
  6763 §4.1.2 defines `<Service>` as exactly two labels, so the root can never
  be valid, even though the owner comparison above genuinely treats the root
  as the immediate parent of any single-label instance and so would otherwise
  accept it. Only the root is rejected here; the full two-label `<Service>`
  rule is not otherwise enforced.
- `hick-compio`, `hick-reactor`: an address-enumeration **failure** is no longer
  read as "this interface has no address in that family". Both crates decided
  family support with `matches!(iface.ipv6_addrs(), Ok(a) if !a.is_empty())` and
  a `_ => false` arm, so an interrupted enumeration — `getifs` returns `EINTR`
  by design when a dump is interrupted by DHCP, VPN or interface churn, rather
  than returning a partial list that would silently drop interfaces — became a
  definite "no IPv6". `Ok(empty)` still degrades the family, so a dual-stack
  request keeps working on an IPv4-only host; a failed read now surfaces
  instead of ranking the wrong link. The default-interface picker's signature
  changes from returning an `Option` to a `Result<Option<_>, io::Error>`
  accordingly. Note that `Ok(empty)` remains genuinely ambiguous on BSD, where
  the enumerator skips an individual address whose netmask is non-canonical
  (point-to-point and tunnel interfaces) and returns a silently incomplete
  list — so "no addresses" cannot be distinguished from "an address we could
  not parse", and degrading rather than failing is deliberate. Thanks to
  @myukitty (#128).
- `hick-udp`: `try_bind_v4` and `try_bind_v6` now log a failed best-effort
  enable of kernel receive timestamps (`SO_TIMESTAMP` / `SO_TIMESTAMPNS`) via
  `hick_trace::warn!`, instead of swallowing it silently. A missing timestamp
  degrades `SelfSendTracker` matching to content-only for the life of the
  socket — the mechanism that keeps this endpoint's own multicast loopback
  from being mistaken for a peer — so a kernel that lacks or refuses the
  sockopt now says so, rather than degrading invisibly for the socket's whole
  life. `set_recv_ttl_v4` / `set_recv_hoplimit_v6` are unaffected: those
  remain genuine diagnostics that no admission decision reads, so they stay
  silent. **Known limitation:** no counter accompanies the warning yet.
  `try_bind_v4`/`try_bind_v6` are free functions with no per-endpoint `Stats`
  in reach, so a counter here would need either a process-wide global (a
  shape this crate has deliberately moved away from elsewhere) or a breaking
  change threading a `Stats` reference through their public signatures;
  both are deferred rather than blocking the warning on either.

## One home for interface selection, and an Android point-to-point rule

- `hick-udp`: **new public module** `interfaces`, exporting
  `acceptable_mdns_interfaces`, `is_acceptable_mdns_interface`,
  `is_loopback_fallback_interface`, `pick_default_interface_index` and
  `has_addr_in`. The interface-filtering and default-picking rules previously
  lived in three copies, one each in `hick-mio`, `hick-reactor` and
  `hick-compio`; they are now stated once and the copies are deleted, so a
  driver's pick and a consumer's own enumeration cannot disagree. Callers that
  want one endpoint per NIC can enumerate with `acceptable_mdns_interfaces`
  rather than reimplementing the predicate.
- `hick-udp`: **on Android only**, an interface that is point-to-point is no
  longer accepted. Cellular (LTE/5G) links are point-to-point there, and
  binding mDNS to one wakes the cellular radio and drains the battery; this is
  the other half of syncthing/syncthing#10504. The rule is **policy, not a
  capability test**, and it is a heuristic in both directions — VPN TUN
  interfaces are refused by it deliberately rather than because they cannot
  carry multicast (they can), and a QMI cellular link in 802.3 mode carries no
  point-to-point flag and so is not caught. The module documents both gaps.
- `hick-udp`: the strict enumeration (`acceptable_mdns_interfaces`) requires
  `RUNNING` as well as `UP`, so a link with no carrier is not offered to a
  caller that intends to bind it. `pick_default_interface_index` is
  deliberately **more lenient** and does not require `RUNNING` — it ranks it,
  see below — so a host whose links are momentarily down still gets a default
  bind instead of being stranded on loopback for the life of the process.
  Thanks to @wkornewald (#131, #134).

  Note the standing limitation this makes visible: the default pick is a
  **snapshot** taken once at construction and nothing migrates it, so a device
  that switches between links — a laptop moving between LAN and WiFi, a phone
  between WiFi and cellular — is not handled by it. Multi-interface binding is
  still not supported; see #133, which also records why "one endpoint per
  interface" is not a safe workaround as stated.
- `hick-udp`: a failed address read on a candidate the default picker was about
  to discard anyway no longer aborts `pick_default_interface_index`. Families
  are probed in a fixed order, and the check that skips a candidate which can no
  longer outrank the incumbent ran **before** each probe, against a tier the
  candidate's unread families had not yet settled — so a candidate whose IPv4
  read failed and whose IPv6 was absent ties the incumbent at best and serves no
  requested family at worst, yet its failure was propagated before IPv6 was ever
  read and the bind was refused over an answer the pick could not have used. It
  was order-dependent: probing IPv6 first on the same inputs succeeded. A
  candidate's first failure is now held to the **end of the walk**, where the
  winner is finally known, and raised only if that candidate would have won with
  the family nobody could read weighed as **present** — the answer that ranks it
  highest — so a failure that could have changed the pick still surfaces.
  Judging it where it happens is not enough, because the incumbent at that
  moment is not the winner and there may be no incumbent at all: `lo` is index 1
  and a `getifs` dump comes back in index order, so the loopback fallback is the
  first candidate walked on the usual Linux and macOS host, and a failed read
  there aborted a pick that the real link enumerated after it wins outright.
  Where several candidates could not be read, the held failures are weighed
  against one another as well as against that winner — one whose worst possible
  finish still beats another's best rules that other one out, and one that may
  turn out to serve no requested family at all rules out nothing — and the first
  that could still have won is the one raised. The error carries the interface
  index and the family, so this is what keeps it naming a link the pick could
  really have turned on rather than whichever failure came first (#130).
- `hick-udp`: `pick_default_interface_index` now **ranks** `RUNNING` rather than
  ignoring it. Not requiring a carrier is what keeps a momentarily-down host
  bindable, but ignoring the flag also made a carrier-less link a full tier-0
  candidate, and first-seen wins within a tier — so an `eth0` that is up,
  multicast-capable and addressed with its cable out, enumerated before a
  working `wlan0`, won the pick, and the pick is a snapshot nothing migrates.
  The base tiers are now 0 for a `RUNNING` non-loopback link, 2 for one that is
  up without a carrier and 4 for the loopback fallback; `rank_candidates` still
  lifts each by one per requested family the candidate has no address in, so the
  effective order is 0..=5 and lower still wins. A live link therefore beats a
  dead one in either enumeration order, a dead real link still beats loopback,
  and a host with nothing running still gets a bind rather than "no
  multicast-capable interface found" — the availability property the lenient
  filter exists for, kept strictly rather than by treating every link as equal.
  The strict filter is untouched: `acceptable_mdns_interfaces` and
  `is_acceptable_mdns_interface` still require `RUNNING` (#137).

## Dual-stack partial delivery (`TransmitDelivery`)

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


# RELEASED

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

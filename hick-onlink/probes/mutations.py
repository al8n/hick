#!/usr/bin/env python3
"""Mutation probes for the RFC 6762 §11 ingress gate.

Every probe below is a defect that was actually proposed, shipped, or argued for
during this gate's review, together with the ONE assertion that catches it. The
set existed only in review transcripts until now, which made it indistinguishable
from a set that never existed: three separate agents had to reconstruct it, and
the numbering survived nowhere in the branch. This file is the reconstruction,
made executable — a probe nobody can run is not evidence.

    ./hick-onlink/probes/mutations.py            # run them all
    ./hick-onlink/probes/mutations.py --list     # the table, without building
    ./hick-onlink/probes/mutations.py <name>...  # run named probes

Each probe applies one exact-string edit to a source file, rebuilds, runs the
one named test, and requires that the test FAILS. Then it restores the file.
A probe reports failure — loudly, and with the tree restored — in any of four
ways, and all four are findings rather than noise:

  * the anchor is missing or appears more than once. The code moved and the
    probe is no longer aimed at anything. RE-AIM IT; do not delete it;
  * the mutation does not compile. The probe is stale in a different way — the
    replacement no longer type-checks against the surrounding code;
  * the named test PASSES with the mutation applied. The guard is gone: either
    the assertion stopped covering this defect, or the defect is no longer
    reachable at that call site. This is the finding the file exists for;
  * the pristine tree does not pass its own tests, in which case nothing below
    means anything and the run stops before the first mutation. The same check
    runs again at the END, on the restored tree, because a runner that leaves a
    mutation behind — on disk or in a stale build artifact — is worse than no
    runner at all.

Anchors are exact strings rather than line numbers or patches on purpose: a
patch rots silently against an unrelated edit nearby, while a missing anchor
fails loudly. Keep them short enough to survive reflowing and long enough to be
unique.

RUSTFLAGS is cleared for the child builds. A mutation may legitimately produce
dead code or an unused binding, and under `-D warnings` that would fail the
BUILD — which this runner would then have to distinguish from the test failing,
or wrongly score as a detection.

`cargo-mutants` does not subsume this set and is not a replacement for it. Its
operators substitute function bodies and flip binary/unary operators; several
probes here are statement and match-ARM REORDERINGS — the loopback block moved
after the snapshot lookup, the IPv4-mapped arm removed from ahead of the
multicast test — which no operator it has can generate. Running it as well would
add breadth; it would not add these.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LIB = "hick-onlink/src/lib.rs"


@dataclass(frozen=True)
class Probe:
    """One mutation, and the single assertion that must catch it."""

    name: str
    why: str
    file: str
    find: str
    replace: str
    caught_by: str


PROBES: tuple[Probe, ...] = (
    Probe(
        name="link-gate-precedes-the-group-arm",
        why=(
            "§11 answers 'did this originate on a local link', never 'on WHICH "
            "link'. The interface gate is this workspace's own and must run "
            "FIRST, or a group destination admits every NIC's copy on a "
            "wildcard-bound socket 'regardless of source IP address'."
        ),
        file=LIB,
        find="""  let provenance = match arrived_on_bound_interface(src, link, iface) {
    Ok(provenance) => provenance,
    Err(refusal) => return Verdict::Refuse(refusal),
  };""",
        replace="""  let provenance =
    arrived_on_bound_interface(src, link, iface).unwrap_or(LinkProvenance::Established);""",
        caught_by="a_group_destination_does_not_excuse_a_foreign_interface_or_scope",
    ),
    Probe(
        name="arm-one-needs-the-link-scoping",
        why=(
            "§11 arm one admits 'regardless of source IP address' — the one "
            "admission in this rule that weighs nothing about where the "
            "datagram came from. What makes it safe here is the scoping of it "
            "to the bound link, so granting it to a datagram nothing scoped "
            "admits a wildcard-bound socket's copy of another NIC's group "
            "traffic with no proof of provenance at all."
        ),
        file=LIB,
        find="""    DestinationWitness::Witnessed(dst) if is_mdns_group(dst) => match provenance {
      LinkProvenance::Established | LinkProvenance::Unbound => Verdict::Admit(Admit::MdnsGroup),
      LinkProvenance::Unproven => unscoped_group_arm(src, delivery, link, iface, provenance),
    },""",
        replace="""    DestinationWitness::Witnessed(dst) if is_mdns_group(dst) => {
      let _ = provenance;
      Verdict::Admit(Admit::MdnsGroup)
    }""",
        caught_by="an_unscoped_group_destination_does_not_take_arm_ones_exemption",
    ),
    Probe(
        name="an-unscoped-group-is-never-worse-than-a-blind-one",
        why=(
            "The unscoped group square carries strictly MORE evidence than the "
            "square with no destination witness at all, and must never fare "
            "worse. Send it straight to the source arm and OpenBSD/NetBSD REFUSE "
            "an off-prefix peer that the blind square beside it ADMITS on "
            "MSG_MCAST — punishing partial evidence, while an attacker who can "
            "drop one cmsg can drop both and be admitted anyway."
        ),
        file=LIB,
        find="    Some(LinkDelivery::Multicast) => Verdict::Admit(Admit::UnscopedMdnsGroup),",
        replace="""    Some(LinkDelivery::Multicast) => source_arm(
      src,
      link,
      iface,
      provenance,
      Admit::UnscopedMdnsGroup,
      Refuse::UnscopedGroupSourceOffLink,
    ),""",
        caught_by="an_unscoped_group_destination_does_not_take_arm_ones_exemption",
    ),
    Probe(
        name="an-absent-link-witness-scopes-nothing",
        why=(
            "The other end of the same rule. A kernel that declined the cmsg, "
            "and a path that emits none, both leave the link unnamed — and an "
            "unnamed link cannot be the bound one. Call either of them scoped "
            "and arm one's exemption is granted on the exact squares an "
            "ancillary-mbuf shortage produces, which a flood causes."
        ),
        file=LIB,
        find="    IfaceWitness::Declined | IfaceWitness::Blind => Ok(LinkProvenance::Unproven),",
        replace="    IfaceWitness::Declined | IfaceWitness::Blind => Ok(LinkProvenance::Established),",
        caught_by="an_unscoped_group_destination_does_not_take_arm_ones_exemption",
    ),
    Probe(
        name="scope-id-is-a-second-link-witness",
        why=(
            "An IPv6 source carries a scope id, and every supported platform "
            "fills it from the receiving interface. Reading only the cmsg index "
            "loses the witness on exactly the squares that have no other one, "
            "and lets a datagram that contradicts itself resolve in the "
            "sender's favour."
        ),
        file=LIB,
        find="  for witness in [iface.witnessed_index(), NonZeroU32::new(scope_of(src))] {",
        replace="  for witness in [iface.witnessed_index()] {",
        caught_by="a_conflicting_scope_rejects_whatever_the_index_says",
    ),
    Probe(
        name="iface-witness-lost-refuses",
        why=(
            "`Lost` means MSG_CTRUNC: the kernel HAD the fact and our own "
            "control buffer could not take it. That is a defect on this side, "
            "not evidence about the sender, and it is the one absence that must "
            "fail closed."
        ),
        file=LIB,
        find="    IfaceWitness::Lost => Err(Refuse::LinkWitnessLost),",
        replace="    IfaceWitness::Lost => Ok(LinkProvenance::Unproven),",
        caught_by="an_unreported_interface_is_absent_evidence_and_a_reported_zero_is_a_failed_proof",
    ),
    Probe(
        name="iface-witness-declined-degrades",
        why=(
            "The other half of the pair. Every BSD builds its ancillary mbufs "
            "with M_NOWAIT and silently skips the cmsg when the allocation "
            "fails — under the flood that caused the shortage. Refusing there "
            "takes the responder off the air exactly when it is under attack."
        ),
        file=LIB,
        find="    IfaceWitness::Declined | IfaceWitness::Blind => Ok(LinkProvenance::Unproven),",
        replace="""    IfaceWitness::Declined => Err(Refuse::LinkWitnessLost),
    IfaceWitness::Blind => Ok(LinkProvenance::Unproven),""",
        caught_by="a_declined_witness_decides_exactly_as_a_blind_one",
    ),
    Probe(
        name="destination-witness-lost-refuses",
        why=(
            "The destination half of the same flag, and it refuses for the same "
            "reason. It is safe to fail closed here precisely because "
            "`recv_with_meta` sizes its control buffer at 512 bytes against a "
            "worst case of about 152, so the flag is not attacker-reachable."
        ),
        file=LIB,
        find="    DestinationWitness::Lost => Verdict::Refuse(Refuse::DestinationWitnessLost),",
        replace="    DestinationWitness::Lost => source_arm(src, link, iface, provenance, Admit::BlindSourceOnLink, Refuse::SourceOffLink),",
        caught_by="a_lost_witness_refuses_where_a_declined_one_admits",
    ),
    Probe(
        name="mdns-group-is-two-addresses-not-a-scope",
        why=(
            "§11 names exactly `224.0.0.251` and `FF02::FB`. Widening the test "
            "to 'any multicast' — or to 'any link-local multicast' — hands the "
            "exemption to LLMNR's `224.0.0.252` / `ff02::1:3` and to every other "
            "protocol sharing the link. This is a trust boundary, not a scope "
            "test."
        ),
        file=LIB,
        find="""  match dst {
    IpAddr::V4(a) => a == MDNS_IPV4_GROUP,
    IpAddr::V6(a) => a == MDNS_IPV6_GROUP,
  }""",
        replace="  dst.is_multicast()",
        caught_by="only_the_two_mdns_groups_establish_local_link_origin",
    ),
    Probe(
        name="broadcast-delivery-is-refused",
        why=(
            "Where no destination was witnessed, MSG_BCAST is exact NEGATIVE "
            "evidence and needs no address: §11 offers a broadcast no arm at "
            "all. Declining to read it was argued for on the grounds that a "
            "broadcast sender could reach us another way; a broadcast follows "
            "its own routing and filtering policy, so it may have no substitute."
        ),
        file=LIB,
        find="      Some(LinkDelivery::Broadcast) => Verdict::Refuse(Refuse::BroadcastDelivery),",
        replace="      Some(LinkDelivery::Broadcast) => source_arm(src, link, iface, provenance, Admit::BlindSourceOnLink, Refuse::SourceOffLink),",
        caught_by="a_broadcast_delivery_is_refused_where_no_destination_was_recovered",
    ),
    Probe(
        name="empty-snapshot-arm-is-scoped-to-empty",
        why=(
            "'We could not enumerate our addresses' and 'this is not one of our "
            "addresses' are different facts. Only the FIRST may defer to the "
            "source arm; letting a non-empty snapshot do it restores the "
            "residual four review rounds spent subtracting classes from."
        ),
        file=LIB,
        find="    DestinationWitness::Witnessed(dst) if link.local_addrs().is_empty() => {",
        replace="    DestinationWitness::Witnessed(dst) if !link.local_addrs().is_empty() => {",
        caught_by="a_destination_this_interface_does_not_hold_has_no_section_11_arm",
    ),
    Probe(
        name="held-destination-is-identity-not-prefix",
        why=(
            "§11's SOURCE test compares against an address AND mask; its "
            "destination test is identity. A destination inside one of our "
            "prefixes but not equal to an address we hold — a neighbour's "
            "address, or the subnet's broadcast — was addressed to somebody "
            "else."
        ),
        file=LIB,
        find="  link.local_addrs().iter().any(|&(addr, _)| addr == dst)",
        replace="  link\n    .local_addrs()\n    .iter()\n    .any(|&(addr, pfx)| addr_in_subnet(addr, pfx, dst))",
        caught_by="a_directed_broadcast_is_refused_whatever_subnet_this_link_carries",
    ),
    Probe(
        name="loopback-block-decided-before-the-snapshot",
        why=(
            "Asking `is_loopback() && dst.is_loopback()` and then FALLING "
            "THROUGH to snapshot equality is not the rule — it is that rule OR "
            "'the snapshot happens to contain it'. A NIC-bound endpoint whose "
            "interface carries both its own address and `127.0.0.1/8`, one "
            "ifconfig away, then holds a loopback destination after all."
        ),
        file=LIB,
        find="""  if dst.is_loopback() {
    return link.is_loopback();
  }""",
        replace="""  if dst.is_loopback() && link.is_loopback() {
    return true;
  }""",
        caught_by="a_mixed_snapshot_does_not_let_a_nic_bound_endpoint_hold_the_loopback_block",
    ),
    Probe(
        name="loopback-source-is-scoped-to-the-binding",
        why=(
            "A loopback SOURCE is not self-evidently local. Linux's "
            "`route_localnet` lets an operator stop treating `127/8` as martian "
            "on a real NIC, at which point an address-only exemption hands an "
            "adjacent spoofer the whole boundary."
        ),
        file=LIB,
        find="    return link.is_loopback() && arrived_on_bound_interface(src, link, iface).is_ok();",
        replace="    return true;",
        caught_by="loopback_is_on_link_for_a_loopback_bound_endpoint_and_nobody_else",
    ),
    Probe(
        name="ipv4-mapped-arm-precedes-the-multicast-test",
        why=(
            "`::ffff:224.0.0.251` is NOT `Ipv6Addr::is_multicast`, because "
            "`::ffff:0:0/96` is not `ff00::/8`. Drop the arm and an mDNS group "
            "in disguise lands in a terminal bucket without ever being named — "
            "the exact shape of residual this partition was rewritten to remove."
        ),
        file=LIB,
        find="""      } else if a.to_ipv4_mapped().is_some() {""",
        replace="""      } else if false {""",
        caught_by="an_ipv4_mapped_destination_is_named_rather_than_left_to_the_residual",
    ),
    Probe(
        name="a-negative-index-is-an-absence",
        why=(
            "`ipi_ifindex` is a C `int`. Reinterpreted as `u32`, `-1` becomes "
            "`4294967295` — a FABRICATED index that names no interface, which "
            "the link gate would then take as the kernel's positive statement of "
            "arrival and REFUSE on."
        ),
        file=LIB,
        find="    let index = if index < 0 { 0 } else { index as u32 };",
        replace="    let index = index as u32;",
        caught_by="a_negative_interface_index_is_an_absence_and_never_a_witness",
    ),
    Probe(
        name="an-over-wide-prefix-is-rejected-not-clamped",
        why=(
            "A prefix longer than the address width is not a prefix. Clamping "
            "it to the width turns a nonsense mask into an exact-match rule; "
            "failing open on it would admit any source at all."
        ),
        file=LIB,
        find="""  if prefix > max {
    return false;
  }""",
        replace="""  if prefix > max {
    return true;
  }""",
        caught_by="prefix_beyond_address_width_is_rejected_not_clamped",
    ),
    Probe(
        name="the-link-local-prefix-is-seeded-not-derived",
        why=(
            "RFC 5942 §3 makes `fe80::/64` on-link by default and RFC 4861 makes "
            "it permanent — neither depends on the host holding an address in "
            "it. Delete the seed and the source arm falls back to whatever the "
            "interface enumerated, which is RFC 5942 §4 rule 1's forbidden "
            "inference wearing a right answer: it works only while getifs "
            "reports the link-local address at a /64, and a DHCPv6 /128, an "
            "interface without one, or a failed enumeration then silently stops "
            "matching link-local peers. That costs §11 unicast responses — what "
            "a QU query asks for — and the FreeBSD/DragonFly square PR #88 "
            "routes to the source arm."
        ),
        file=LIB,
        find="""  if matches!(provenance, LinkProvenance::Established)
    && addr_in_subnet(IpAddr::V6(LINK_LOCAL_V6_NET), LINK_LOCAL_V6_PREFIX_LEN, ip)
  {
    return true;
  }""",
        replace="",
        caught_by="the_link_local_prefix_is_on_link_with_no_assigned_address",
    ),
    Probe(
        name="the-link-local-seed-is-a-64-and-not-a-10",
        why=(
            "RFC 4291 §2.4's table names the link-local unicast TYPE `FE80::/10`, "
            "and a reader who stops there seeds /10. §2.5.6 gives the ADDRESS its "
            "format — ten prefix bits, 54 ZERO bits, then a 64-bit interface "
            "identifier — so a conforming link-local address is exactly a member "
            "of `fe80::/64`. A /10 seed answers ON-LINK for `fe80:1234::1`, which "
            "no stack can autoconfigure or assign, on 54 bits of claim the subnet "
            "model never makes."
        ),
        file=LIB,
        find="const LINK_LOCAL_V6_PREFIX_LEN: u8 = 64;",
        replace="const LINK_LOCAL_V6_PREFIX_LEN: u8 = 10;",
        caught_by="the_link_local_seed_is_the_64_bit_prefix_and_not_the_10_bit_block",
    ),
    Probe(
        name="the-seed-needs-the-link-to-have-been-established",
        why=(
            "`fe80::/64` is on-link on EVERY interface, so matching it says the "
            "sender is on some link and nothing about whether it is ours. Drop "
            "the provenance conjunct and the seed decides on a blind or degraded "
            "path: a datagram that arrived on another NIC of this same host is "
            "admitted for being link-local, and PR #88's unscoped-group square — "
            "which routes to the source arm on FreeBSD/DragonFly precisely "
            "BECAUSE nothing scoped it — gets arm one's exemption back under "
            "another name. A prefix never establishes a link."
        ),
        file=LIB,
        find="""  if matches!(provenance, LinkProvenance::Established)
    && addr_in_subnet(IpAddr::V6(LINK_LOCAL_V6_NET), LINK_LOCAL_V6_PREFIX_LEN, ip)
  {""",
        replace="""  if addr_in_subnet(IpAddr::V6(LINK_LOCAL_V6_NET), LINK_LOCAL_V6_PREFIX_LEN, ip) {""",
        caught_by="the_link_local_seed_needs_the_link_to_have_been_established",
    ),
    Probe(
        name="the-seed-gate-closes-the-unscoped-group-path",
        why=(
            "The same defect, caught at the square it matters most on rather "
            "than at the gate. `unscoped_group_arm` is selected BY "
            "`LinkProvenance::Unproven` and forwards it, so the seed is "
            "unreachable there; forge `Established` on the way in and a "
            "link-local sender is admitted at a group destination nothing "
            "scoped, which is exactly what #88 spent four rounds closing."
        ),
        file=LIB,
        find="""    Some(LinkDelivery::Unicast) | None => source_arm(
      src,
      link,
      iface,
      provenance,
      Admit::UnscopedMdnsGroup,""",
        replace="""    Some(LinkDelivery::Unicast) | None => source_arm(
      src,
      link,
      iface,
      LinkProvenance::Established,
      Admit::UnscopedMdnsGroup,""",
        caught_by="the_unscoped_group_path_cannot_reach_the_seed",
    ),
    Probe(
        name="a-zero-binding-does-not-prove-a-link",
        why=(
            "A bound interface of zero satisfies §11 arm one vacuously — an "
            "endpoint that named no link can call none foreign — and proves "
            "NOTHING to the seed, which needs 'this arrived on our link' and has "
            "no our-link to be about. Collapse the two back into `Established` "
            "and `BoundLink::new(0, ...)` admits a `fe80::x%7` source with no "
            "link-local prefix enumerated, which the same inputs on a named "
            "binding refuse. A prefix on every link plus a binding on none is "
            "two absences, not a proof."
        ),
        file=LIB,
        find="    return Ok(LinkProvenance::Unbound);",
        replace="    return Ok(LinkProvenance::Established);",
        caught_by="a_bound_interface_of_zero_grants_arm_one_and_never_the_seed",
    ),
    Probe(
        name="a-zero-binding-still-grants-arm-one",
        why=(
            "The other direction of the same distinction, and it is an "
            "availability property rather than a safety one. Demote a zero "
            "binding to `Unproven` and every single-link caller — hick-smoltcp, "
            "hick-embassy — loses §11 arm one forever in exchange for no scoping "
            "at all, because there was never a second link for the scoping to "
            "separate it from."
        ),
        file=LIB,
        find="    return Ok(LinkProvenance::Unbound);",
        replace="    return Ok(LinkProvenance::Unproven);",
        caught_by="a_bound_interface_of_zero_grants_arm_one_and_never_the_seed",
    ),
    Probe(
        name="the-empty-snapshot-arm-defers-only-the-residual",
        why=(
            "A failed enumeration is ignorance about which addresses this host "
            "HOLDS, never about what an address IS. Defer every witnessed "
            "destination and a transient enumeration failure turns `ff02::1` — "
            "the all-nodes group, which §11 gives no arm and no enumeration was "
            "ever consulted about — into protocol input on UDP/5353 for any "
            "source the arm goes on to admit."
        ),
        file=LIB,
        find="""      match classify_unheld(dst, link) {
        Refuse::DestinationNotHeld => source_arm(""",
        replace="""      match Refuse::DestinationNotHeld {
        Refuse::DestinationNotHeld => source_arm(""",
        caught_by="an_empty_snapshot_refuses_the_destination_classes_it_can_still_decide",
    ),
    Probe(
        name="residual-refusal-counts-only-its-own-arm",
        why=(
            "`Refuse::DestinationNotHeld` is the residual, and its count is the "
            "size of the conformance gap. A counter aimed at a NAMED class "
            "instead reports a gap that is measured but not the one that exists."
        ),
        file=LIB,
        find="    matches!(self, Self::Refuse(Refuse::DestinationNotHeld))",
        replace="    matches!(self, Self::Refuse(Refuse::ForeignGroup))",
        caught_by="the_four_gap_counters_count_exactly_their_own_arms",
    ),
    Probe(
        name="the-unscoped-group-refusal-is-counted-apart",
        why=(
            "The availability cost of scoping arm one has to be measurable or "
            "the trade is an argument. Fold it back into the generic "
            "SourceOffLink and an operator can no longer tell a datagram §11 "
            "said to admit, dropped for want of link evidence, from an ordinary "
            "off-link source — which is the signal that a flood is degrading "
            "this host."
        ),
        file=LIB,
        find="      Refuse::UnscopedGroupSourceOffLink,\n    ),",
        replace="      Refuse::SourceOffLink,\n    ),",
        caught_by="the_four_gap_counters_count_exactly_their_own_arms",
    ),
    Probe(
        name="degraded-admit-counts-both-blind-arms",
        why=(
            "The other gap counter. Both blind arms rest on NO destination "
            "witness, so both are degraded; counting one of them under-reports "
            "the very widening an operator is meant to alert on."
        ),
        file=LIB,
        find="      Self::Admit(Admit::BlindSourceOnLink | Admit::BlindMulticastDelivery)",
        replace="      Self::Admit(Admit::BlindSourceOnLink)",
        caught_by="the_four_gap_counters_count_exactly_their_own_arms",
    ),
)


class ProbeError(Exception):
    """A probe did not do what a probe must do. Always a finding."""


# How far ahead of "now" a rewritten source file is stamped. It must exceed the
# coarsest mtime granularity a checkout might sit on: HFS+ and ext3 store whole
# seconds, exFAT stores two, and this runner was written on a worktree that
# reproduced the failure below on HFS+ within one second.
MTIME_LEAD_SECONDS = 4


def rewrite(path: Path, text: str) -> None:
    """Write `text` to `path` and make cargo treat the file as genuinely newer.

    Cargo calls a unit fresh when no input's mtime is STRICTLY newer than its
    output. On a filesystem that stores whole-second mtimes, a write that lands
    in the same second as the build it is undoing is therefore invisible: cargo
    skips the rebuild and the NEXT run silently executes the binary built from
    the previous mutation. That is not hypothetical — it scored a real detection
    as a survival, and then poisoned this runner's own preflight, twice.

    Stamping a few seconds ahead makes every build below unconditional under any
    granularity. The lead is monotonic in practice because each rewrite is later
    than the last, and it settles as soon as the run ends.
    """
    path.write_text(text)
    ahead = time.time() + MTIME_LEAD_SECONDS
    os.utime(path, (ahead, ahead))


def run(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # A mutation may leave dead code or an unused binding behind. Under
    # `-D warnings` that fails the BUILD, which this runner would then have to
    # tell apart from the test failing — or would wrongly score as a detection.
    env.pop("RUSTFLAGS", None)
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)


def preflight(repo: Path) -> None:
    print("pristine tree: running the whole hick-onlink suite ...", flush=True)
    # Stamp every file a probe touches before building, so this run compiles
    # what is ON DISK. Without it the preflight can inherit a stale artifact —
    # from an interrupted run, or from a checkout whose mtimes cargo already
    # considers current — and certify a tree it never built.
    for name in sorted({probe.file for probe in PROBES}):
        path = repo / name
        rewrite(path, path.read_text())
    got = run(["cargo", "test", "-q", "-p", "hick-onlink", "--lib"], cwd=repo)
    if got.returncode != 0:
        sys.stdout.write(got.stdout)
        sys.stderr.write(got.stderr)
        raise ProbeError(
            "the UNMUTATED tree does not pass its own tests, so no probe below "
            "would mean anything. Fix that first."
        )
    print("pristine tree: green\n", flush=True)


def apply_probe(repo: Path, probe: Probe) -> None:
    target = repo / probe.file
    original = target.read_text()

    hits = original.count(probe.find)
    if hits != 1:
        raise ProbeError(
            f"anchor found {hits} times in {probe.file}, expected exactly 1. "
            f"The code moved and this probe is aimed at nothing — RE-AIM it "
            f"against the guard it is about; do not delete it.\n"
            f"  anchor: {probe.find!r}"
        )

    # Restored by REWRITING, never by copying a file back: `shutil.copy2` would
    # preserve the pre-mutation mtime and hand cargo a source OLDER than the
    # binary it just built from the mutation. See `rewrite` for why the mtime is
    # then pushed forward as well. A crash between the two writes leaves the
    # mutation on disk; `git checkout -- <file>` is the recovery, and `git diff`
    # shows it immediately.
    try:
        rewrite(target, original.replace(probe.find, probe.replace))

        built = run(["cargo", "test", "-q", "-p", "hick-onlink", "--lib", "--no-run"], cwd=repo)
        if built.returncode != 0:
            raise ProbeError(
                "the mutation does not compile, so the probe proves nothing. "
                "Its replacement no longer type-checks against the surrounding "
                "code — re-aim it.\n" + built.stderr[-2000:]
            )

        tested = run(
            [
                "cargo",
                "test",
                "-q",
                "-p",
                "hick-onlink",
                "--lib",
                "--",
                "--exact",
                f"tests::{probe.caught_by}",
            ],
            cwd=repo,
        )
        if "running 1 test" not in tested.stdout:
            raise ProbeError(
                f"no test named `tests::{probe.caught_by}` ran. It was renamed "
                f"or removed; point the probe at whatever guards this now."
            )
        if tested.returncode == 0:
            raise ProbeError(
                f"PROBE SURVIVED: `{probe.caught_by}` still passes with this "
                f"defect applied. Either the assertion stopped covering it or "
                f"the defect is no longer reachable there — both need an answer "
                f"before this file is trusted again."
            )
    finally:
        rewrite(target, original)

    if target.read_text() != original:
        raise ProbeError(f"failed to restore {probe.file} — check `git diff`")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("names", nargs="*", help="probes to run (default: all)")
    parser.add_argument("--list", action="store_true", help="print the table and exit")
    args = parser.parse_args()

    if args.list:
        for probe in PROBES:
            print(f"{probe.name}\n  caught by: {probe.caught_by}\n  {probe.why}\n")
        return 0

    selected = PROBES
    if args.names:
        by_name = {p.name: p for p in PROBES}
        unknown = [n for n in args.names if n not in by_name]
        if unknown:
            print(f"unknown probe(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        selected = tuple(by_name[n] for n in args.names)

    try:
        preflight(REPO)
    except ProbeError as exc:
        print(f"FAIL preflight: {exc}", file=sys.stderr)
        return 1

    failures: list[tuple[str, str]] = []
    for index, probe in enumerate(selected, start=1):
        print(f"[{index}/{len(selected)}] {probe.name} ... ", end="", flush=True)
        try:
            apply_probe(REPO, probe)
        except ProbeError as exc:
            print("FAIL")
            failures.append((probe.name, str(exc)))
        else:
            print(f"caught by {probe.caught_by}")

    # The tree is restored, so it must pass again. This is not ceremony: it is
    # the only check that would have caught the stale-binary defect `rewrite`
    # documents, which left every later run testing a mutation nobody applied.
    try:
        preflight(REPO)
    except ProbeError as exc:
        print(f"FAIL postflight: {exc}", file=sys.stderr)
        failures.append(("postflight", str(exc)))

    print()
    if failures:
        for name, message in failures:
            print(f"FAIL {name}\n  {message}\n", file=sys.stderr)
        print(f"{len(failures)}/{len(selected)} probes failed", file=sys.stderr)
        return 1

    print(f"{len(selected)}/{len(selected)} probes caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())

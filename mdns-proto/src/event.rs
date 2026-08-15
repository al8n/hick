//! Event types flowing between [`Endpoint`],
//! [`Service`], and [`Query`].

use core::net::SocketAddr;

use derive_more::{IsVariant, TryUnwrap, Unwrap};

cfg_heap! {
  use crate::Name;
}
use crate::{
  QueryHandle, ServiceHandle,
  wire::{MessageReader, QuestionRef, Questions, Records, Ref},
};

/// A question routed to a registered service.
#[derive(Debug, Copy, Clone)]
pub struct ServiceQuestion<'a> {
  question: QuestionRef<'a>,
  src: SocketAddr,
  query_id: u16,
  truncated: bool,
}
impl<'a> ServiceQuestion<'a> {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(question: QuestionRef<'a>, src: SocketAddr, query_id: u16) -> Self {
    Self {
      question,
      src,
      query_id,
      truncated: false,
    }
  }
  /// Marks whether the query packet carrying this question had the TC
  /// (truncated) bit set — i.e. the querier is spreading its known-answer list
  /// across multiple packets (RFC 6762 §7.2). The responder uses this to pick a
  /// longer (400–500 ms) response delay so the follow-up known-answer packets
  /// can arrive before it decides what to suppress.
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn with_truncated(mut self, truncated: bool) -> Self {
    self.truncated = truncated;
    self
  }
  /// Returns the DNS question.
  #[inline(always)]
  pub const fn question(&self) -> &QuestionRef<'a> {
    &self.question
  }
  /// `true` if the query packet had the TC bit set (RFC 6762 §7.2 multipacket
  /// known-answer suppression — more known-answer packets follow).
  #[inline(always)]
  pub const fn truncated(&self) -> bool {
    self.truncated
  }
  /// Returns the source socket address of the peer that sent the query.
  #[inline(always)]
  pub const fn src(&self) -> SocketAddr {
    self.src
  }
  /// Returns the DNS transaction ID of the query, echoed in a legacy
  /// unicast response (RFC 6762 §6.7).
  #[inline(always)]
  pub const fn query_id(&self) -> u16 {
    self.query_id
  }
}

/// Where a [`ProbeConflict`]'s record was carried, which is what decides WHICH
/// RFC 6762 rule governs it.
///
/// The two are not interchangeable and the RFC never treats them as such. §8.2
/// takes a peer's tentative proposal — "When a host that is probing for a
/// record sees another host issue a **query** for the same record, it consults
/// the Authority Section of that query" — and resolves it by lexicographic
/// tiebreak. §8.1 and §9 take an authoritative **response**: §8.1's
/// silently-ignore rule before the first probe is written about "Multicast DNS
/// **responses**", and §9 opens "A conflict occurs when … it receives a
/// Multicast DNS **response** message containing a record with the same name,
/// rrtype and rrclass, but inconsistent rdata".
///
/// Collapsing the two applies each rule to the other's input: it lets §8.1's
/// pre-probe fence swallow a simultaneous prober's proposal that §8.2 requires
/// comparing, and it lets a peer merely PROBING a name this responder already
/// owns push it back into probing, which §9 reserves for a response.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, IsVariant)]
#[non_exhaustive]
pub enum ConflictOrigin {
  /// The Authority Section of a peer's QUERY (QR=0): the rdata a simultaneous
  /// prober "would be proposing to use, should its probing be successful"
  /// (RFC 6762 §8.2). This, and only this, is the §8.2 tiebreak's input.
  TentativeProbe,
  /// An authoritative RESPONSE (QR=1) — a peer announcing or defending a name
  /// it owns. §8.1 governs one received while this responder is probing; §9
  /// governs one received after it is established.
  AuthoritativeResponse,
}

/// Whether a [`ProbeConflict`]'s record repeats rdata this endpoint itself
/// recently transmitted and then gave up.
///
/// This is a LABEL, not a decision. The endpoint is the only layer that can know
/// the fact — a service structurally cannot recognise a predecessor's records —
/// but the endpoint cannot see lifecycle state, and the fact means different
/// things in different phases. So the router states it and the service spends
/// it; see the conflict matrix on `Service::handle_preauthoritative_conflict`
/// for the cell-by-cell rule.
///
/// # What it does NOT establish
///
/// That the record came from us. Nothing an instantaneous history lookup can do
/// settles that: RFC 6762 §9 exists to protect a fault-tolerance twin "capable
/// of issuing identical answers", and such a twin's defence is byte-identical to
/// our own ghost's echo. Only FUTURE behaviour separates them — a ghost cannot
/// answer a re-probe and a live incumbent can — which is why the
/// pre-authoritative cell spends this label on §8.2's one-second deferral rather
/// than on discarding the conflict.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, IsVariant)]
#[non_exhaustive]
pub enum ConflictHistory {
  /// The record's rdata matches nothing this endpoint recently transmitted under
  /// this owner name on this address family. It is a peer's record as far as
  /// anything here can tell.
  Unmatched,
  /// The record's rdata repeats a set this endpoint recently transmitted and
  /// relinquished — through a rename, an unregister, or a completed §10.1
  /// goodbye. It may be our own delayed echo; it may equally be a §9 twin that
  /// legitimately publishes the same bytes.
  Relinquished,
}

/// Which of a route's names a [`ProbeConflict`]'s record owns, when one name
/// wears BOTH roles.
///
/// A service may register its instance name as its host name. Every A/AAAA it
/// publishes is then a member of two RRsets at once — the §8.2 proposal its
/// instance role probes with, and the address RRset its host role is
/// authoritative for — and the routing fan-out has to choose ONE event to
/// deliver it as. It tests the host rule first, so the record can only arrive
/// here as a `ProbeConflict` by falling through that rule.
///
/// The fall-through must not lose what the host rule established, because the
/// receiving cell needs it: `Service::handle_event`'s instance-authority gate
/// asks `respond::canonical_rdata_forms`, which names SRV, TXT and NSEC and
/// never an address, so an established service handed a bare instance-role
/// A/AAAA drops it. That answer is right for a name that is ONLY an instance
/// name and wrong for one that is also the host name, where §9's "a unique
/// record for which it is currently authoritative" is plainly true. So the role
/// travels with the record and the gate reads it.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, IsVariant)]
#[non_exhaustive]
pub enum ConflictRole {
  /// The record's owner is this route's INSTANCE name and nothing else — or it
  /// is also the host name, but this route publishes no RRset of that rrtype
  /// there, so the host rule declined it. Either way the instance role is the
  /// only one that can be authoritative for it.
  Instance,
  /// The record's owner is this route's instance name AND its host name, and
  /// this route publishes an RRset of that rrtype at the host name. The record
  /// reaches the instance role only because the host rule's consequence was
  /// withheld; the AUTHORITY the host rule proved is unaffected by that and
  /// travels with it.
  InstanceAndHost,
}

/// Identifies the datagram a [`ProbeConflict`] arrived in.
///
/// RFC 6762 §8.2's tiebreak input is one query's proposal — "the Authority
/// Section of THAT query", and §8.2 requires that section to "contain *all* the
/// records and proposed rdata being probed for uniqueness". So a proposal is a
/// per-DATAGRAM list, and records from two datagrams are two proposals even when
/// they share a source address.
///
/// Merging them by source address alone is unsound in both directions. The same
/// probe delivered twice before one timeout — plain UDP duplication, a delayed
/// timer, or a peer's own §8.1 retransmissions — doubles every member, and a
/// duplicated shorter record then sorts ahead of a longer local one and flips
/// the verdict: `{TXT, SRV}` seen twice compares as `[TXT, TXT, SRV, SRV]`,
/// whose second TXT is below the local SRV, so a losing responder concludes it
/// won. Two co-resident responders sharing one `IP:5353` merge into a union
/// list that is neither host's proposal.
///
/// Opaque and only ever compared for equality: it identifies which datagram, and
/// nothing about ordering or count is meaningful.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct DatagramId(u64);

impl DatagramId {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(raw: u64) -> Self {
    Self(raw)
  }
}

/// An AUTHORITATIVE record observed from a peer that claims this service's
/// **instance** name, triggering conflict resolution.
///
/// Always a response — RFC 6762 §8.1's in-probe deferral and §9's conflict are
/// both defined over one. A peer's tentative §8.2 proposal is a whole Authority
/// Section rather than a record and arrives as [`ProbeProposal`]: the two rules
/// take different units of input, so they take different types.
#[derive(Debug, Copy, Clone)]
pub struct ProbeConflict<'a> {
  src: SocketAddr,
  record: Ref<'a>,
  datagram: DatagramId,
  history: ConflictHistory,
  role: ConflictRole,
}
impl<'a> ProbeConflict<'a> {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(
    src: SocketAddr,
    record: Ref<'a>,
    datagram: DatagramId,
    history: ConflictHistory,
    role: ConflictRole,
  ) -> Self {
    Self {
      src,
      record,
      datagram,
      history,
      role,
    }
  }
  /// Returns which of the receiving route's names this record owns. See
  /// [`ConflictRole`] — it is the authority the routing fan-out's host rule
  /// established, carried across the fall-through that turned a `HostConflict`
  /// into this event.
  #[inline(always)]
  pub const fn role(&self) -> ConflictRole {
    self.role
  }
  /// Returns whether this record repeats rdata this endpoint recently
  /// transmitted and relinquished. See [`ConflictHistory`] — it is a label the
  /// router attaches and the receiving service spends, not a verdict.
  #[inline(always)]
  pub const fn history(&self) -> ConflictHistory {
    self.history
  }
  /// Returns which datagram carried this record. See [`DatagramId`]: one
  /// datagram is one §8.2 proposal, and proposals are never merged across them.
  #[inline(always)]
  pub const fn datagram(&self) -> DatagramId {
    self.datagram
  }
  /// Returns the source address of the peer that sent the conflicting record.
  #[inline(always)]
  pub const fn src(&self) -> SocketAddr {
    self.src
  }
  /// Returns the conflicting DNS record observed from a peer.
  #[inline(always)]
  pub const fn record(&self) -> &Ref<'a> {
    &self.record
  }
}

/// One peer's COMPLETE RFC 6762 §8.2 proposal: the whole Authority Section of a
/// single QR=0 query.
///
/// §8.2 defines its input as a whole — "it consults the Authority Section of
/// that query" — and requires a prober to put its entire proposed set there:
/// "for tiebreaking to work correctly in all cases, the Authority Section must
/// contain *all* the records and proposed rdata being probed for uniqueness".
/// §8.2.1 then sorts and compares the two LISTS.
///
/// So the unit the §8.2 rule is true of is a datagram's section, not a record,
/// and this event carries exactly that. Delivering the section record-by-record
/// made a PARTIAL list representable, and a partial list adjudicates wrong in
/// the direction that costs a name: `write_probe` emits SRV before TXT, so after
/// one record a peer proposing byte-identical records looks like `[SRV]` against
/// a local `[TXT, SRV]`, loses at element 0, and renames a responder that should
/// have tied. Carrying the section whole makes that state unrepresentable rather
/// than guarded against.
///
/// Borrowed and lazy: nothing is copied, and [`Self::authority`] mints a fresh
/// iterator per call.
#[derive(Debug, Copy, Clone)]
pub struct ProbeProposal<'a> {
  src: SocketAddr,
  reader: MessageReader<'a>,
  datagram: DatagramId,
}
impl<'a> ProbeProposal<'a> {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(
    src: SocketAddr,
    reader: MessageReader<'a>,
    datagram: DatagramId,
  ) -> Self {
    Self {
      src,
      reader,
      datagram,
    }
  }
  /// Source address of the peer whose probe this is.
  #[inline(always)]
  pub const fn src(&self) -> SocketAddr {
    self.src
  }
  /// Which datagram carried it. See [`DatagramId`].
  #[inline(always)]
  pub const fn datagram(&self) -> DatagramId {
    self.datagram
  }
  /// The proposal's records: a fresh iterator over the query's Authority
  /// Section. Callers filter it to the names and rtypes they own.
  #[inline(always)]
  pub fn authority(&self) -> Records<'a> {
    self.reader.authority()
  }
  /// The query's Question Section: a fresh iterator, minted per call like
  /// [`Self::authority`].
  ///
  /// The Authority Section alone does not say what is being proposed. RFC 6762
  /// §8.2 reads it as "the Authority Section of that query" — the records are
  /// the proposed rdata for the names *the query asks about*, and §8.1 defines
  /// the query as one "with the record name in question in the Question
  /// Section". An Authority Section read without its questions admits records
  /// that answer nothing: a QDCOUNT=0 packet, or one asking about an unrelated
  /// name, would drive §8.2 purely on records that happen to mention ours.
  ///
  /// So a receiver scopes the proposal to the records that answer a question
  /// this query actually asked about the name being adjudicated.
  #[inline(always)]
  pub fn questions(&self) -> Questions<'a> {
    self.reader.questions()
  }
}

/// A record observed from a peer that claims this service's **host** name
/// (the A/AAAA owner).
///
/// Unlike [`ProbeConflict`], this does NOT trigger an automatic instance
/// rename. The caller must resolve the host-name conflict out-of-band (e.g.
/// by choosing a new host name and re-registering the service).
///
/// [`Self::origin`] carries the same distinction [`ProbeConflict`] does, and
/// for the same reason: §9 defines a conflict over a response, so only an
/// [`ConflictOrigin::AuthoritativeResponse`] may drive the terminal
/// [`ServiceUpdate::HostConflict`] that callers act on. Dropping it here would
/// have let any peer's ordinary probe for a shared host name retire every
/// service using it.
#[derive(Debug, Copy, Clone)]
pub struct HostConflict<'a> {
  record: Ref<'a>,
  origin: ConflictOrigin,
}
impl<'a> HostConflict<'a> {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(record: Ref<'a>, origin: ConflictOrigin) -> Self {
    Self { record, origin }
  }
  /// Returns the conflicting DNS record observed from a peer.
  #[inline(always)]
  pub const fn record(&self) -> &Ref<'a> {
    &self.record
  }
  /// Returns where the record was carried, which decides which RFC 6762 rule
  /// governs it. See [`ConflictOrigin`].
  #[inline(always)]
  pub const fn origin(&self) -> ConflictOrigin {
    self.origin
  }
}

/// A known-answer hint observed in an incoming query, used to suppress
/// our outgoing answers when the asker already has the same record.
///
/// carries `src` so the service can scope the hint to the
/// querier that supplied it.  Hints from sources that did NOT issue a
/// Question in the current response cycle are dropped — without this,
/// an attacker could inject KAS hints during a legitimate questioner's
/// jitter window and suppress the response.
#[derive(Debug, Copy, Clone)]
pub struct KnownAnswer<'a> {
  src: core::net::SocketAddr,
  record: Ref<'a>,
}
impl<'a> KnownAnswer<'a> {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(src: core::net::SocketAddr, record: Ref<'a>) -> Self {
    Self { src, record }
  }
  /// Returns the known-answer DNS record from the incoming query.
  #[inline(always)]
  pub const fn record(&self) -> &Ref<'a> {
    &self.record
  }
  /// Source address of the packet that carried this hint.
  #[inline(always)]
  pub const fn src(&self) -> core::net::SocketAddr {
    self.src
  }
}

/// Events delivered from `Endpoint::handle()` to a `Service`.
#[derive(Debug, Copy, Clone, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ServiceEvent<'a> {
  /// A question targeting this service arrived.
  Question(ServiceQuestion<'a>),
  /// Another peer responded AUTHORITATIVELY for our **instance** name — RFC
  /// 6762 §8.1 while probing, §9 once advertised.
  ProbeConflict(ProbeConflict<'a>),
  /// Another peer is PROBING for our **instance** name, and this carries its
  /// complete §8.2 proposal (that query's whole Authority Section).
  ProbeProposal(ProbeProposal<'a>),
  /// While probing, another peer responded authoritatively for our **host** name
  /// (A/AAAA owner). The service will NOT auto-rename — the caller must
  /// intervene. See [`ServiceUpdate::HostConflict`].
  HostConflict(HostConflict<'a>),
  /// A known-answer hint from an incoming query — caller may use it for
  /// KAS-style suppression of outgoing answers.
  KnownAnswer(KnownAnswer<'a>),
}

/// Events delivered from `Endpoint::handle()` to a `Query`.
#[derive(Debug, Copy, Clone, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum QueryEvent<'a> {
  /// A matching answer record arrived.
  Answer(Ref<'a>),
  /// Query received a truncated response (TC bit). Caller should hold
  /// off cancelling this query — more KAS suppression follows.
  Truncated,
}

/// A routing decision produced by `Endpoint::handle()`.
#[derive(Debug, Copy, Clone)]
pub struct ToService<'a> {
  handle: ServiceHandle,
  event: ServiceEvent<'a>,
}
impl<'a> ToService<'a> {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(handle: ServiceHandle, event: ServiceEvent<'a>) -> Self {
    Self { handle, event }
  }
  /// Returns the service handle this event is addressed to.
  #[inline(always)]
  pub const fn handle(&self) -> ServiceHandle {
    self.handle
  }
  /// Returns a reference to the service event payload.
  #[inline(always)]
  pub const fn event(&self) -> &ServiceEvent<'a> {
    &self.event
  }
  /// Consumes the routing decision and returns the inner event.
  #[inline(always)]
  pub const fn into_event(self) -> ServiceEvent<'a> {
    self.event
  }
}

/// A routing decision produced by `Endpoint::handle()`.
#[derive(Debug, Copy, Clone)]
pub struct ToQuery<'a> {
  handle: QueryHandle,
  event: QueryEvent<'a>,
}
impl<'a> ToQuery<'a> {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(handle: QueryHandle, event: QueryEvent<'a>) -> Self {
    Self { handle, event }
  }
  /// Returns the query handle this event is addressed to.
  #[inline(always)]
  pub const fn handle(&self) -> QueryHandle {
    self.handle
  }
  /// Returns a reference to the query event payload.
  #[inline(always)]
  pub const fn event(&self) -> &QueryEvent<'a> {
    &self.event
  }
  /// Consumes the routing decision and returns the inner event.
  #[inline(always)]
  pub const fn into_event(self) -> QueryEvent<'a> {
    self.event
  }
}

/// A routing decision yielded by `Endpoint::handle()`.
#[derive(Debug, Copy, Clone, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum RouteEvent<'a> {
  /// Route the event to the matched service.
  ToService(ToService<'a>),
  /// Route the event to the matched query.
  ///
  /// Informational: `Endpoint::handle` has already offered this record to the
  /// query named here, so delivering the event applies nothing.
  ///
  /// # What an event means
  ///
  /// The record reached the query fan-out and passed the four screens taken
  /// there, all weighed as of the `now` that `Endpoint::handle` processed the
  /// datagram at: the query had not ended; its terminal `QueryUpdate` had not
  /// already been taken by `Endpoint::poll_query`; the caller's
  /// `QuerySpec::with_timeout` window was still open; and the record matched the
  /// query's name, type and class. Those four are the whole of what the fan-out
  /// decides, so they are the whole of what an event asserts.
  ///
  /// The window screen is the same comparison, against the same reading, that
  /// `Query::handle_event` weighed this record on — so a record refused for
  /// standing past that window is never announced here.
  ///
  /// # What absence means
  ///
  /// Nothing a consumer may reason from. The fan-out is the last stage of a long
  /// inbound path, and a record turned away anywhere earlier never reaches it, so
  /// none of the four screens ever weighed that record and none of them says
  /// anything about its silence. `Endpoint::handle` can reject a datagram
  /// outright or suppress every side effect it would have had; a message that is
  /// not a response carries no answers to route; a record that fails to parse
  /// abandons the rest of its section, and one that fails in an earlier section
  /// strands every later section with it, because a section is located only by
  /// walking the ones ahead of it; a TTL=0 record is a withdrawal, never
  /// announced as an answer. Those are illustrations, not an enumeration: no
  /// event distinguishes them, the set has grown as the receive path has, and a
  /// missing event is evidence for none of them in particular. Do not infer WHY
  /// nothing arrived.
  ///
  /// One bound does hold, and it is the useful one: only answer-section and
  /// additional-section records are ever routed to a query. Question and
  /// authority records go to services alone, so no query is ever told about one.
  ///
  /// The TTL=0 case is worth stating on its own, because its cache effect is
  /// conditional and easy to over-read. The withdrawal reaches the cache only
  /// when population is enabled (`EndpointConfig::with_populate_cache`) and the
  /// record's name and rdata canonicalize; and even then `Cache::try_insert`
  /// mutates nothing unless a matching entry already exists whose expiry is
  /// later than the one-second rescue window it clamps to. A suppressed event is
  /// therefore not evidence that any withdrawal was recorded.
  ///
  /// # What an event does NOT imply
  ///
  /// The four screens decide that the query was OFFERED the record. Whether it
  /// KEPT one is `Query::handle_event`'s separate decision, and that decision
  /// declines for reasons no screen above looks at: a
  /// `QuerySpec::with_max_answers` cap of zero, rdata carrying a domain name
  /// that will not decode, a (type, class, rdata) triple the query already
  /// holds, and an answer pool with no room even after evicting its oldest
  /// entry. At the cap, a record that IS kept also evicts one that was, which no
  /// event reports either.
  ///
  /// So this is a routing decision and not a receipt. A consumer that needs to
  /// know what a query holds must read `Endpoint::collected_answers`.
  ToQuery(ToQuery<'a>),
  /// The endpoint cache observed new or refreshed records as a side effect
  /// of this datagram. Callers can use this as a hint to re-poll queries.
  CacheUpdated,
}

cfg_heap! {
  /// Detail payload for [`ServiceUpdate::Renamed`].
  #[derive(Debug, Clone, Eq, PartialEq)]
  pub struct ServiceRenamed {
    new_name: Name,
  }

  const _: () = {
    impl ServiceRenamed {
      /// Construct a `ServiceRenamed` from a new name.
      ///
      /// Hidden from the documented surface: the proto state machine builds these
      /// internally on a conflict rename, but downstream crates need a way to
      /// synthesize them for tests (mirroring [`crate::CollectedAnswer::from_parts`]).
      #[doc(hidden)]
      #[inline(always)]
      pub fn new(new_name: Name) -> Self {
        Self { new_name }
      }
      /// Returns the new canonical name assigned after conflict resolution.
      #[inline(always)]
      pub fn new_name(&self) -> &Name {
        &self.new_name
      }
    }
  };

  /// App-level events emitted by `Service::poll()`.
  #[allow(clippy::large_enum_variant)]
  #[derive(Debug, Clone, IsVariant, Unwrap, TryUnwrap)]
  #[unwrap(ref)]
  #[try_unwrap(ref)]
  #[non_exhaustive]
  pub enum ServiceUpdate {
    /// Probing completed without conflict; the service is now advertised.
    Established,
    /// Probing detected a conflict; the service rebranded to a new name.
    Renamed(ServiceRenamed),
    /// A conflict cannot be resolved automatically (e.g. tiebreak space
    /// exhausted). The caller must intervene.
    Conflict,
    /// A peer claimed our **host** name (A/AAAA owner) during probing.
    ///
    /// The service does NOT rename itself automatically. The caller must
    /// resolve the conflict by choosing a new host name and re-registering,
    /// or by deferring to the peer.
    HostConflict,
  }
}

/// App-level events emitted by `Query::poll()`.
#[derive(Debug, Clone, Copy, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum QueryUpdate {
  /// Query's retry budget expired without finding a match.
  Timeout,
  /// Query is finished (caller cancelled or completed enough answers).
  Done,
}

/// App-level events emitted by `Endpoint::poll()`.
#[derive(Debug, Copy, Clone, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum EndpointEvent {
  /// A cached record's TTL expired.
  CacheExpired,
}

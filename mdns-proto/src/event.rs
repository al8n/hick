//! Event types flowing between [`Endpoint`],
//! [`Service`], and [`Query`].

use core::net::SocketAddr;

use derive_more::{IsVariant, TryUnwrap, Unwrap};

cfg_heap! {
  use crate::Name;
}
use crate::{
  QueryHandle, ServiceHandle,
  wire::{QuestionRef, Ref},
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

/// A response record observed during another peer's probe — indicates this
/// service's name is in use, triggering conflict resolution.
#[derive(Debug, Copy, Clone)]
pub struct ProbeConflict<'a> {
  src: SocketAddr,
  record: Ref<'a>,
}
impl<'a> ProbeConflict<'a> {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(src: SocketAddr, record: Ref<'a>) -> Self {
    Self { src, record }
  }
  /// Returns the source address of the peer that sent the conflicting probe.
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

/// A response record observed during another peer's probe — indicates this
/// service's **host** name (A/AAAA owner) is already claimed by a peer.
///
/// Unlike [`ProbeConflict`], this does NOT trigger an automatic instance
/// rename. The caller must resolve the host-name conflict out-of-band (e.g.
/// by choosing a new host name and re-registering the service).
#[derive(Debug, Copy, Clone)]
pub struct HostConflict<'a> {
  record: Ref<'a>,
}
impl<'a> HostConflict<'a> {
  #[allow(dead_code)]
  #[inline(always)]
  pub(crate) const fn new(record: Ref<'a>) -> Self {
    Self { record }
  }
  /// Returns the conflicting DNS record observed from a peer.
  #[inline(always)]
  pub const fn record(&self) -> &Ref<'a> {
    &self.record
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
  /// While probing, another peer responded authoritatively for our **instance** name.
  /// The service will auto-rename.
  ProbeConflict(ProbeConflict<'a>),
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
  /// # What the fan-out screened
  ///
  /// One is yielded only for a query that passed all four of the fan-out's
  /// screens, weighed as of the `now` that `Endpoint::handle` processed the
  /// datagram at: the query had not ended; its terminal `QueryUpdate` had not
  /// already been taken by `Endpoint::poll_query`; the caller's
  /// `QuerySpec::with_timeout` window was still open; and the record matched the
  /// query's name, type and class.
  ///
  /// The window screen is the same comparison, against the same reading, that
  /// `Query::handle_event` weighed this record on — so a record refused for
  /// standing past that window is never announced here.
  ///
  /// # What it does NOT imply
  ///
  /// Those four decide that the query was OFFERED the record. Whether it KEPT
  /// one is `Query::handle_event`'s separate decision, and that decision
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

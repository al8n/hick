//! `Endpoint` orchestrator: demuxes incoming datagrams, holds routing
//! metadata + cache, drives Service/Query registration.

#[cfg(all(test, feature = "std", feature = "slab"))]
#[allow(
  clippy::unwrap_used,
  clippy::expect_used,
  clippy::panic,
  clippy::indexing_slicing,
  clippy::arithmetic_side_effects
)]
mod tests;

mod admits;
pub(crate) use admits::{Admits, Answering};
pub(crate) mod flood;
pub(crate) use flood::ConflictFlood;
mod matching;
pub(crate) use matching::*;
mod route;
pub use route::RouteEvents;
pub(crate) use route::Section;
mod query;
mod receive;
mod received;
pub use received::{Provenance, Received};
mod relinquished;
use relinquished::{Relinquished, RelinquishedIdentity};
mod service;
mod withdrawal;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand_core::Rng;

use crate::{
  Instant, Name, Pool, QueryHandle, ServiceHandle,
  cache::{Cache, CacheEntry},
  config::{EndpointConfig, QuerySpec, ServiceSpec},
  error::{
    CancelQueryError, HandleError, HandleTimeoutError, RegisterServiceError,
    ServiceTypeNotParentDetail, StartQueryError, StorageFullError, TransmitError,
  },
  event::{
    ConflictHistory, ConflictOrigin, ConflictRole, EndpointEvent, HostConflict, KnownAnswer,
    ProbeConflict, ProbeProposal, QueryEvent, QueryUpdate, RouteEvent, ServiceEvent,
    ServiceQuestion, ServiceUpdate, ToQuery,
  },
  query::{CollectedAnswer, Query},
  service::{NamesInUse, Service},
  trace::*,
  transmit::{FamilyAttempt, Transmit, TransmitConfirm},
  wire::{MessageReader, NameRef, QuestionRef, ResourceClass, ResourceType},
};

cfg_heap! {
  /// Number of goodbye sends during an orderly withdrawal (RFC 6762 §10.1),
  /// counted PER FAMILY so each reachable family withdraws its records.
  const WITHDRAWAL_SENDS: u8 = 3;

  /// Spacing between successive withdrawal goodbye resends (loss resilience).
  // Used by `poll_withdrawal_transmit`.
  #[allow(dead_code)]
  const WITHDRAWAL_INTERVAL: core::time::Duration = core::time::Duration::from_millis(250);

  /// Back-off added to `next_at` on a missed send (delivery not yet confirmed).
  // Used by `note_withdrawal_result`.
  #[allow(dead_code)]
  const WITHDRAWAL_RETRY_BACKOFF: core::time::Duration = core::time::Duration::from_millis(20);

  /// Hard deadline by which a withdrawal is force-completed regardless of
  /// pending sends, to prevent a stale withdrawing route from pinning the name
  /// slot indefinitely.
  const WITHDRAWAL_CEILING: core::time::Duration = core::time::Duration::from_secs(2);
}

cfg_heap! {
  /// What ONE family's RFC 6762 §10.1 goodbye attempt does to that family's
  /// outstanding debt — the CORE's projection of a [`FamilyAttempt`], reached
  /// only through [`WithdrawalSend::project`].
  ///
  /// Internal for the same reason [`FamilyDelivery`](crate::transmit::FamilyDelivery)
  /// is: a driver able to name a write-off is a driver able to zero a debt that a
  /// bound family still owes, freeing the route while that family's peers stay
  /// pinned to stale positive-TTL records. Two drivers disagreed about exactly
  /// that table before this projection existed.
  #[derive(Clone, Copy, Debug, Eq, PartialEq, derive_more::Display)]
  #[display("{}", self.as_str())]
  pub(crate) enum WithdrawalSend {
    /// The datagram reached the wire on this family — spend one of its owed rounds.
    Sent,
    /// This family did not carry it, and may yet: keep its debt for a later round.
    Retry,
    /// This family has no socket at all, so it has no reachable peers to withdraw
    /// from — write its debt off rather than let it pin the item.
    WriteOff,
  }

  impl WithdrawalSend {
    /// THE withdrawal table: what one family's attempt does to its goodbye debt,
    /// decided by socket PRESENCE and never by error kind.
    ///
    /// | [`FamilyAttempt`] | outcome | why |
    /// |---|---|---|
    /// | `Accepted` | `Sent` | on the wire; spend one owed round |
    /// | `Refused { permanent: false }` | `Retry` | a present socket did not carry it; the §10.1 ceiling is the backstop |
    /// | `Refused { permanent: true }` | `Retry` | same — see below |
    /// | `WouldBlock` | `Retry` | nothing was submitted; the next round pays it |
    /// | `GateShut` | `Retry` | a deferral is not a write-off |
    /// | `NotAddressed` | `Retry` | a goodbye fans onto every joined group, so this is not producible here; keeping the debt is the safe answer if it ever is |
    /// | `NoSocket` | `WriteOff` | nothing bound, so no peers on this family to retract from |
    ///
    /// **A permanent refusal KEEPS the debt**, and the asymmetry with a
    /// positive-TTL transmit is deliberate. There, an undeliverable datagram
    /// retires a producer that would otherwise re-arm it forever, because the
    /// producer is what is unbounded. Here nothing is: the item's own anti-pin
    /// ceiling force-completes it whatever the family answers, so the ONLY thing a
    /// write-off could buy is finishing marginally sooner — at the price of the
    /// exact defect this table exists to prevent. The direction stays one-sided:
    /// **only an absent socket writes a debt off.**
    ///
    /// [`FamilyAttempt::NoSocket`] and [`FamilyAttempt::NotAddressed`] are
    /// separate variants precisely so this row can differ from the failing ones.
    /// Conflating a `NoSocket` family with a failing one breaks something in
    /// either direction: as `Retry`, an unbound family's debt pins every
    /// withdrawal to its full ceiling on a single-stack host; as `WriteOff`, a
    /// bound family's transient failure frees the route while it still owed its
    /// goodbye.
    fn project<I: Instant>(attempt: FamilyAttempt<I>) -> Self {
      match attempt {
        FamilyAttempt::Accepted { .. } => Self::Sent,
        FamilyAttempt::Refused { .. }
        | FamilyAttempt::WouldBlock
        | FamilyAttempt::GateShut
        | FamilyAttempt::NotAddressed => Self::Retry,
        FamilyAttempt::NoSocket => Self::WriteOff,
      }
    }

    /// Test-only: one [`FamilyAttempt`] that projects onto this outcome, so a
    /// withdrawal test can name the debt effect it is about rather than an I/O
    /// outcome it is not. The chosen preimage is the dullest one — see
    /// `TransmitDelivery::as_attempts`, which does the same for a transmit.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) const fn as_attempt<I: Instant>(self, at: I) -> FamilyAttempt<I> {
      match self {
        Self::Sent => FamilyAttempt::Accepted { at },
        Self::Retry => FamilyAttempt::Refused { permanent: false },
        Self::WriteOff => FamilyAttempt::NoSocket,
      }
    }

    /// Canonical lowercase slug for this per-family send outcome.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn as_str(&self) -> &'static str {
      match self {
        Self::Sent => "sent",
        Self::Retry => "retry",
        Self::WriteOff => "write_off",
      }
    }
  }

  /// Opaque identity for a single in-progress `WithdrawalItem`, handed back by
  /// [`Endpoint::poll_withdrawal_transmit`] and round-tripped to
  /// [`Endpoint::note_withdrawal_result`] to confirm exactly that item's send.
  ///
  /// A monotonic counter (`next_withdrawal_token`) mints a fresh value
  /// per item and never reuses one, so a token can only ever name the item it was
  /// minted for (or no item, once that item has been drained). It is deliberately
  /// distinct from [`ServiceHandle`]: one teardown can spawn TWO items (a
  /// route-attached current-name goodbye and a detached old-name rename goodbye),
  /// so the poll/note key cannot be the handle.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
  pub struct WithdrawalToken(u64);

  /// Which address families a withdrawal round is actually FOR — the per-family
  /// RFC 6762 §10.1 goodbye debt still outstanding on the item
  /// [`Endpoint::poll_withdrawal_transmit`] just encoded.
  ///
  /// A driver fans one goodbye datagram onto every family it has bound, but the
  /// debt is per family while the resend schedule is per ITEM: once one family has
  /// paid every round it owed and the other is still failing, the item keeps being
  /// selected for the sake of the family that still owes. Offering the paid family
  /// those rounds retracts records nothing still advertises. That is wire noise
  /// rather than a §10.1 violation — the standard permits the repeats — but it is
  /// noise the core can rule out for free, since the core is the thing that knows.
  ///
  /// # Why an opaque token works here
  ///
  /// Same shape as [`FullyAnnounced`]: `Copy`, no
  /// public constructor, accessors only. A driver reads one; a driver cannot mint
  /// one. That is sound HERE — and not for a send outcome — because outstanding
  /// debt is a fact the **core** owns and spends. A driver has nothing to
  /// contribute to it and no reason to synthesise one, so making the type
  /// unforgeable takes nothing away. A send outcome is the mirror case: the driver
  /// is the only witness, so an unforgeable one would be unconstructible by the
  /// only party that knows the answer.
  ///
  /// # Booleans, not counts
  ///
  /// Each family answers "does it still owe a goodbye", not "how many". One round
  /// puts at most one datagram on one family's wire, so the count above zero is
  /// never actionable at a fan-out — and publishing it would export the §10.1
  /// budget itself, inviting a driver to re-derive "has this family finished?"
  /// from its own copy of a constant the core owns. That reconstruction is exactly
  /// the driver-side shadow this type exists to make unnecessary.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  #[must_use]
  pub struct FamilyDebt {
    v4: bool,
    v6: bool,
  }

  impl FamilyDebt {
    /// Project an item's raw per-family budget onto the owed/paid question.
    /// Crate-internal: [`Endpoint::poll_withdrawal_transmit`] is the sole caller,
    /// which is what makes the type unforgeable outside this crate.
    #[inline(always)]
    pub(crate) const fn new(owed: [u8; 2]) -> Self {
      let [v4, v6] = owed;
      Self {
        v4: v4 > 0,
        v6: v6 > 0,
      }
    }

    /// Whether IPv4 still owes a goodbye for this item.
    #[inline(always)]
    pub const fn v4_owed(self) -> bool {
      self.v4
    }

    /// Whether IPv6 still owes a goodbye for this item.
    #[inline(always)]
    pub const fn v6_owed(self) -> bool {
      self.v6
    }
  }

  /// One due RFC 6762 §10.1 goodbye datagram, as returned by
  /// [`Endpoint::poll_withdrawal_transmit`].
  ///
  /// A named struct rather than a tuple because the fourth member is the one a
  /// driver most easily ignores: [`Self::debt`] says which families the round is
  /// actually for, and a positional `.3` is a poorer prompt to consult it than a
  /// name is. Carrying it ON the transmit — rather than offering it beside one —
  /// is what makes consulting it non-optional: there is no call a driver can
  /// forget to make.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  #[must_use]
  pub struct WithdrawalTransmit {
    dst: SocketAddr,
    len: usize,
    token: WithdrawalToken,
    debt: FamilyDebt,
  }

  // No `is_empty` beside `len`: a returned round always carries a goodbye — the
  // pump completes an item with nothing to retract in place rather than handing
  // it out — so the method could only ever answer `false`. Stating the invariant
  // here is worth more than a public question with one possible answer.
  #[allow(clippy::len_without_is_empty)]
  impl WithdrawalTransmit {
    /// Crate-internal: only the withdrawal pump may describe a round, since both
    /// [`WithdrawalToken`] and [`FamilyDebt`] are core-owned facts.
    #[inline(always)]
    pub(crate) const fn new(
      dst: SocketAddr,
      len: usize,
      token: WithdrawalToken,
      debt: FamilyDebt,
    ) -> Self {
      Self {
        dst,
        len,
        token,
        debt,
      }
    }

    /// The multicast destination marker. The core always names the IPv4 group and
    /// leaves the fan-out to the driver, which retracts on every group it joined.
    #[inline(always)]
    pub const fn dst(&self) -> SocketAddr {
      self.dst
    }

    /// Bytes written into the caller-supplied scratch buffer. Never zero.
    #[inline(always)]
    pub const fn len(&self) -> usize {
      self.len
    }

    /// The item this round belongs to, to be round-tripped to
    /// [`Endpoint::note_withdrawal_result`].
    #[inline(always)]
    pub const fn token(&self) -> WithdrawalToken {
      self.token
    }

    /// Which families still owe a goodbye for this item — the families this round
    /// is for. See [`FamilyDebt`].
    #[inline(always)]
    pub const fn debt(&self) -> FamilyDebt {
      self.debt
    }
  }

  /// In-progress withdrawal state for ONE name (one TTL=0 goodbye lifecycle).
  /// Stored in [`Endpoint::withdrawals`] keyed by an opaque [`WithdrawalToken`].
  /// The `I` type parameter is the [`Instant`] type of the enclosing endpoint.
  ///
  /// A single name — never a dual current+rename pair. A teardown DURING a §9
  /// rename therefore enqueues TWO independent items: a route-attached one for the
  /// current (re-announced) name, and a detached one for the old name still draining
  /// its rename goodbye. Modelling each goodbye as its own item means neither can
  /// starve the other, and two names that each fit `scratch` individually are both
  /// emitted even when their combined message would not.
  ///
  /// `route` carries the item's relationship to a [`ServiceRoute`]:
  ///   * `Some(handle)` — a TEARDOWN item. It HOLDS the route `handle`: the name
  ///     stays blocked against re-registration until the item settles, and on
  ///     completion [`Endpoint::drain_completed_withdrawals`] frees the route
  ///     (releasing the name, decrementing `services_active`) and reports `handle`
  ///     to the driver. Only these items withdraw host A/AAAA (and so honour
  ///     sibling host-address retention).
  ///   * `None` — a DETACHED item (a renamed-away OLD name). It owns no route and
  ///     no host addresses (both halves of `owned` carry empty address lists);
  ///     when it settles it is simply removed, reported to NOBODY.
  ///
  /// Stored as a parallel `Vec` rather than inline on [`ServiceRoute`] because
  /// the relationship is not one-to-one: a teardown DURING a rename owes TWO
  /// goodbyes (a route-attached current-name one and a detached old-name one),
  /// and a detached item outlives — indeed never has — a route at all.
  struct WithdrawalItem<I> {
    /// The service records (names, port, TXT) for this name's goodbye sends.
    // Read by `poll_withdrawal_transmit`.
    #[allow(dead_code)]
    records: crate::records::ServiceRecords,
    /// What this name put on EACH family's wire and still owes a retraction for
    /// — `[v4, v6]`, instance record kinds (PTR/SRV/TXT/subtypes, plus the §6.1
    /// NSEC exposure) and host addresses together. Only these are withdrawn
    /// (§7.1 KAS can suppress a subset, and a fan-out's two sends can differ in
    /// what each family accepted), and only from the family that carried them.
    ///
    /// It starts as the exposure exactly and only ever NARROWS: a reclaimable
    /// detached item is trimmed to the shared records a same-name replacement's
    /// announcement cannot supersede (see
    /// [`Endpoint::note_service_announced`]). Narrowing is the safe direction
    /// for both readers — a goodbye retracts less, and the relinquished screen
    /// disowns less — while widening it past what was emitted is what
    /// `EmittedRecords` exists to prevent.
    ///
    /// A detached item's address lists are ALWAYS empty on both halves
    /// (`route == None`) — a rename never withdraws host A/AAAA, the host name
    /// being invariant across renames.
    #[allow(dead_code)]
    owned: [crate::service::EmittedRecords; 2],
    /// The MULTICAST subset of [`Self::owned`], and the only half
    /// [`Endpoint::relinquished_asserts`] reads from a resident item.
    ///
    /// The two answer different questions over the same records. `owned` is what
    /// a peer may hold FROM US, so it counts an RFC 6762 §6.7 legacy reply: that
    /// resolver's cache holds those records and this goodbye owes them a
    /// retraction. `multicast` is what could still be ECHOING, and a datagram
    /// addressed to one ephemeral port was never on the group, so no multicast
    /// arrival can be a copy of it. Screening on `owned` labelled a GENUINE
    /// peer's multicast A/AAAA as this endpoint's own relinquished history —
    /// suppressing the host conflict for the item's whole residency — on the
    /// strength of bytes no multicast socket ever carried.
    ///
    /// It narrows exactly where `owned` does (see
    /// [`Endpoint::note_service_announced`]), so it is a subset of `owned` at
    /// every instant.
    #[allow(dead_code)]
    multicast: [crate::service::EmittedRecords; 2],
    /// PER-FAMILY goodbye-send debt: `[0]` IPv4, `[1]` IPv6, each initialised to
    /// `WITHDRAWAL_SENDS` for a family that actually carried something and to `0`
    /// for one that did not — a family with nothing in its peers' caches has
    /// nothing to retract, and sending it a TTL=0 goodbye for records it never
    /// heard can cache-flush a peer's matching shared record. A family's counter
    /// is decremented only when THAT family confirms a send
    /// ([`WithdrawalSend::Sent`]) and zeroed on a permanent write-off
    /// ([`WithdrawalSend::WriteOff`]).
    // Read and mutated by `note_withdrawal_result`.
    #[allow(dead_code)]
    owed: [u8; 2],
    /// When the next send is due.  Set to `now` at construction so the first
    /// send fires immediately.
    // Read by `poll_withdrawal_transmit`.
    #[allow(dead_code)]
    next_at: I,
    /// Hard force-complete deadline.  The item is terminated at or after this
    /// instant regardless of debt (anti-pin guard).
    // Read by `drain_completed_withdrawals`.
    #[allow(dead_code)]
    ceiling_at: I,
    /// `true` once a FINAL goodbye has been emitted AT/just-before the ceiling for
    /// a still-owed item.  Without this, a family that becomes
    /// reachable only in the `[last_attempt, ceiling]` window — because the last
    /// backoff overshot `ceiling_at` — would never get a try: `poll_withdrawal_transmit`
    /// only emits while `now < ceiling_at`, so the route would be force-completed
    /// with debt still owed.  When an item is past its ceiling but still owes AND
    /// has not yet been final-attempted, `poll_withdrawal_transmit` emits ONE last
    /// goodbye and sets this flag; `drain_completed_withdrawals` then force-completes
    /// a past-ceiling item only once this is set (or its debt already reached
    /// `[0, 0]`).  The flag also guarantees termination: the past-ceiling branch
    /// fires at most once per item, so the pump loop can never re-select the same
    /// item for another final attempt.
    // Read/written by `poll_withdrawal_transmit`; read by
    // `drain_completed_withdrawals`.
    #[allow(dead_code)]
    final_attempt: bool,
    /// The route this item relates to. `Some(handle)` is a teardown item HOLDING
    /// the route (blocks name-reuse, freed + reported on completion, withdraws host
    /// addresses); `None` is a detached old-name item (no route, no host, completes
    /// silently). See the type-level docs.
    #[allow(dead_code)]
    route: Option<ServiceHandle>,
    /// Whether this DETACHED item must HOLD its instance name against fresh
    /// `try_register_service` reuse until its goodbye completes (`route: None` items
    /// only — a route-attached item already holds via the route table).
    ///
    /// `false` (the default) is a SURVIVING rename's old name: reclaimable, so a
    /// fresh registration of the vacated name cancels the goodbye rather than being
    /// blocked. `true` is a rename-COLLISION teardown's old
    /// name: the service is DEAD, so its stale records must be retracted BEFORE the
    /// name is reused; without the hold, the empty route-attached current-name
    /// withdrawal completes first and a quick re-register cancels the only real
    /// goodbye, leaving peers with stale PTR/SRV/TXT until TTL. A held name is
    /// rejected by BOTH reuse paths — `try_register_service` and
    /// `handle_service_renamed` — and is never cancelled by
    /// [`Endpoint::note_service_announced`], so the dead service's goodbye always
    /// drains before the name can be claimed again.
    #[allow(dead_code)]
    holds_name: bool,
  }
}

/// Routing metadata for a registered service, and the [`Service`] state machine
/// it routes to.
///
/// # Why the state machine lives HERE
///
/// It used to be the caller's: `try_register_service` handed a `Service` back
/// and the driver drove it, while the `Endpoint` kept only the routing metadata.
/// That split put a caller between routing and classification, and three
/// separate defects came out of it — RFC 6762 §8.1's flood limit could not be
/// counted for the host because no single owner saw every conflict; a rename
/// mutated the service's records before the route table could object, so every
/// driver carried its own collision reconciliation; and the instant a conflict
/// was RECEIVED was not the instant it was classified at.
///
/// Holding the `Service` here makes routing, classification, the flood history,
/// the receipt instant and the schedule one state machine under one `&mut self`
/// and one `now`. It is the same shape [`Query`] has always had, driven through
/// the same kind of handle-addressed accessors on [`Endpoint`].
pub struct ServiceRoute<I, TQ, EvS> {
  /// The service state machine this route addresses. Driven ONLY through the
  /// `*_service*` accessors on [`Endpoint`]; [`Endpoint::service`] hands out a
  /// read-only view.
  pub(crate) proto: Service<I, TQ, EvS>,
  /// DNS-SD service-type PTR owner (e.g. `_ipp._tcp.local.`).
  service_type: Name,
  /// Instance name (e.g. `MyPrinter._ipp._tcp.local.`).
  name: Name,
  /// Host name that owns the A/AAAA records (e.g. `printer-host.local.`).
  host: Name,
  handle: ServiceHandle,
  /// IPv4 addresses advertised in this service's A records.  Used by
  /// `Endpoint::handle` to recognise multicast-loopback datagrams whose
  /// source IP matches an address we are publishing.  IPv6
  /// PKTINFO carries the multicast destination rather than the local
  /// interface address, so the IPv4-only `src == local_ip` shortcut from
  /// cannot detect IPv6 self-packets — membership against this
  /// list is the positive signal for both v4 and v6.
  a_addrs: std::vec::Vec<Ipv4Addr>,
  /// IPv6 addresses advertised in this service's AAAA records.  See
  /// `a_addrs` for the rationale.
  aaaa_addrs: std::vec::Vec<Ipv6Addr>,
  /// Parallel to `aaaa_addrs`: interface scope id for each AAAA (0 = any).
  /// IPv6 link-local addresses are scoped per interface; a peer
  /// reusing the same `fe80::*` on a different interface must NOT be
  /// classified as self.  A non-zero scope binds the address to a
  /// specific receiving `interface_index` in [`Endpoint::handle`].
  aaaa_scopes: std::vec::Vec<u32>,
  /// RFC 6763 §7.1 subtype browse names (`<sub>._sub.<service_type>`). A browse
  /// question for any of these routes to this service so it can answer with the
  /// shared subtype PTR.
  subtypes: std::vec::Vec<Name>,
  /// IPv4 host addresses this service has actually CONFIRMED-ADVERTISED on the
  /// wire — the subset of `a_addrs` a peer truly holds in its cache.  EMPTY at
  /// registration (a never-announced service has advertised nothing); the
  /// driver mirrors the live `Service::advertised_a_addrs` set here via
  /// [`Endpoint::note_service_announced`] after each confirmed announce.  This
  /// (NOT the configured `a_addrs`) is what `sibling_retained_addrs` honours so
  /// a withdrawing service only retains addresses a LIVE same-host sibling
  /// genuinely owns in peer caches.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  advertised_a: std::vec::Vec<Ipv4Addr>,
  /// IPv6 host addresses this service has actually CONFIRMED-ADVERTISED.  See
  /// `advertised_a`; this is the AAAA counterpart, also EMPTY at registration.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  advertised_aaaa: std::vec::Vec<Ipv6Addr>,
  /// `true` once [`Endpoint::begin_withdrawal`] has been called for this
  /// service.  The route is kept alive (name guard + dispatch) until the
  /// goodbye sequence completes; this flag lets downstream code distinguish a
  /// live service from one that is in the process of being torn down.
  // Read by `poll_timeout` dispatch skip.
  #[allow(dead_code)]
  withdrawing: bool,
}

impl<I, TQ, EvS> core::fmt::Debug for ServiceRoute<I, TQ, EvS> {
  /// The ROUTING metadata only. The state machine is driven through
  /// [`Endpoint`] and has no `Debug` of its own; a route's identifying facts are
  /// its names and its handle.
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("ServiceRoute")
      .field("handle", &self.handle)
      .field("service_type", &self.service_type)
      .field("name", &self.name)
      .field("host", &self.host)
      .finish_non_exhaustive()
  }
}

impl<I, TQ, EvS> ServiceRoute<I, TQ, EvS> {
  /// The DNS-SD service-type (PTR owner), e.g. `_ipp._tcp.local.`.
  #[inline(always)]
  pub fn service_type(&self) -> &Name {
    &self.service_type
  }

  /// The service's instance name.
  #[inline(always)]
  pub fn name(&self) -> &Name {
    &self.name
  }

  /// The service's host name (owner of A/AAAA records).
  #[inline(always)]
  pub fn host(&self) -> &Name {
    &self.host
  }

  /// The handle assigned to this service.
  #[inline(always)]
  pub const fn handle(&self) -> ServiceHandle {
    self.handle
  }

  /// Advertised IPv4 addresses for this service (A records).
  #[inline(always)]
  pub fn a_addrs(&self) -> &[Ipv4Addr] {
    &self.a_addrs
  }

  /// Advertised IPv6 addresses for this service (AAAA records).
  #[inline(always)]
  pub fn aaaa_addrs(&self) -> &[Ipv6Addr] {
    &self.aaaa_addrs
  }

  /// Per-AAAA interface scope ids (parallel to [`Self::aaaa_addrs`]).
  /// A scope of `0` matches any receiving interface; a non-zero scope
  /// matches only the same `interface_index` passed to
  /// [`Endpoint::handle`].
  #[inline(always)]
  pub fn aaaa_scopes(&self) -> &[u32] {
    &self.aaaa_scopes
  }

  cfg_heap! {
    /// IPv4 host addresses this service has CONFIRMED-ADVERTISED on the wire.
    /// Distinct from [`Self::a_addrs`] (the configured set used for self-/
    /// loopback detection): this is the subset peers actually hold in cache, kept
    /// current by [`Endpoint::note_service_announced`] and consumed by
    /// sibling host-address retention during withdrawal.
    #[inline(always)]
    pub(crate) fn advertised_a(&self) -> &[Ipv4Addr] {
      &self.advertised_a
    }

    /// IPv6 host addresses this service has CONFIRMED-ADVERTISED on the wire (the
    /// AAAA counterpart of [`Self::advertised_a`]).
    #[inline(always)]
    pub(crate) fn advertised_aaaa(&self) -> &[Ipv6Addr] {
      &self.advertised_aaaa
    }
  }
}

cfg_heap! {
  /// Test-only: one [`ServiceEvent`] the router DISPATCHED, flattened into owned
  /// facts.
  ///
  /// A service event never leaves the endpoint, so a routing test cannot observe
  /// one by iterating [`RouteEvents`] any more. It reads this instead: the
  /// routing decision itself — which service, which kind of event, and the few
  /// labels the fan-out attaches — recorded at the moment of dispatch, which is
  /// the same moment the old `RouteEvent::ToService` was constructed.
  ///
  /// Owned rather than borrowed because it outlives the datagram's reader, and
  /// flattened rather than storing the event because `ServiceEvent` borrows the
  /// datagram. `cfg(test)`: it does not exist in a shipped build.
  #[cfg(test)]
  #[derive(Debug, Clone)]
  pub(crate) struct Dispatched {
    handle: ServiceHandle,
    kind: DispatchedKind,
    history: Option<ConflictHistory>,
  }

  /// Test-only: which [`ServiceEvent`] a [`Dispatched`] record describes.
  #[cfg(test)]
  #[derive(Debug, Clone, Copy, Eq, PartialEq, derive_more::IsVariant)]
  pub(crate) enum DispatchedKind {
    Question,
    KnownAnswer,
    ProbeConflict,
    HostConflict,
    ProbeProposal,
  }

  #[cfg(test)]
  impl Dispatched {
    /// Flatten one event at the instant it is dispatched.
    fn new(handle: ServiceHandle, event: &ServiceEvent<'_>) -> Self {
      let (kind, history) = match event {
        ServiceEvent::Question(_) => (DispatchedKind::Question, None),
        ServiceEvent::KnownAnswer(_) => (DispatchedKind::KnownAnswer, None),
        ServiceEvent::ProbeConflict(pc) => (DispatchedKind::ProbeConflict, Some(pc.history())),
        ServiceEvent::HostConflict(_) => (DispatchedKind::HostConflict, None),
        ServiceEvent::ProbeProposal(_) => (DispatchedKind::ProbeProposal, None),
      };
      Self {
        handle,
        kind,
        history,
      }
    }

    /// The service this event was addressed to.
    pub(crate) const fn handle(&self) -> ServiceHandle {
      self.handle
    }

    /// Which event it was. Named `event` because that is the question a routing
    /// test asks of a dispatch, and the answer is the whole of what a
    /// `ServiceEvent` was ever inspected for out here.
    pub(crate) const fn event(&self) -> DispatchedKind {
      self.kind
    }

    /// The RFC 6762 §9 relinquished-history label a conflict carried.
    pub(crate) const fn history(&self) -> Option<ConflictHistory> {
      self.history
    }


  }
}

/// Internal queued endpoint event.
#[derive(Debug, Clone)]
pub struct EndpointEventEntry(EndpointEvent);

impl EndpointEventEntry {
  /// Borrow the inner event.
  #[inline(always)]
  pub const fn event(&self) -> &EndpointEvent {
    &self.0
  }
}

/// The orchestrator. Holds routing metadata + cache + the per-handle state
/// machines for Service and Query, both Endpoint-owned.
///
/// The `Query` state machines live in the `QS` pool and the `Service` state
/// machines inside the [`ServiceRoute`]s of the `SR` pool — callers receive only
/// a [`QueryHandle`] from [`Self::try_start_query`] or a [`ServiceHandle`] from
/// [`Self::try_register_service`], and drive each through the `*_query*` /
/// `*_service*` accessors on `Endpoint`.
///
/// # RFC 6762 §8.1's conflict-flood limit
///
/// > If fifteen conflicts occur within any ten-second period, then the host MUST
/// > wait at least five seconds before each successive additional probe attempt.
///
/// That limit is enforced INSIDE this type and asks nothing of a driver beyond
/// what every sans-I/O method here already requires: each received datagram
/// reaches [`Self::handle`] with a monotonic `now` taken at receipt,
/// [`Self::handle_service_timeout`] runs by the instant
/// [`Self::poll_service_timeout`] reports, and probes leave the host only
/// through [`Self::poll_service_transmit`]. Within that contract the limit is
/// EXACT, not best-effort.
///
/// It is ENDPOINT-WIDE: it aggregates across every record set this endpoint
/// routes for, outlives any one service, and floors a fresh registration's first
/// probe. A second `Endpoint`, or a second process, on the same machine is
/// outside anything this library can observe, and that is the only sense in
/// which RFC 6762's "host" is approximated.
///
/// # Query lifecycle and cleanup
///
/// Queries are NOT auto-pruned.  After
/// [`Self::poll_query`] returns the terminal `QueryUpdate` for a handle,
/// the underlying state machine is RETAINED so the caller can drain
/// final results via [`Self::collected_answers`].  Late matching
/// responses arriving after terminal are frozen out: they do not
/// mutate `collected_answers` or trigger fan-out events.
///
/// Cleanup is the caller's responsibility — terminated queries leak
/// pool slots until explicitly freed.  Two equivalent options:
///
///   * [`Self::cancel_query`] — drop a specific handle.
///   * [`Self::sweep_terminated_queries`] — drop every query whose
///     terminal has already been delivered.
///
/// Failing to clean up exhausts a fixed-capacity `QS` pool just as the
/// leak would have, so this contract must be honoured.
pub struct Endpoint<I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS> {
  config: EndpointConfig,
  rng: R,
  services: SR,
  queries: QS,
  cache: Cache<I, C>,
  pending_events: EV,
  next_service_handle: u32,
  next_query_handle: u32,
  next_txid: u16,
  /// Monotonic per-accepted-datagram counter, stamped onto every conflict a
  /// datagram raises. Its only use is telling one datagram's RFC 6762 §8.2
  /// proposal from the next when both come from the same source address; see
  /// [`DatagramId`](crate::event::DatagramId). Wraps, which is harmless: it is
  /// only ever compared for equality between conflicts buffered inside one
  /// probe round, and 2^64 datagrams cannot arrive within one.
  datagram_seq: u64,
  /// RFC 6762 §8.1's fifteen-in-ten conflict history for this whole endpoint.
  ///
  /// Plain fields under the `&mut self` routing already holds — see
  /// [`ConflictFlood`]. Written by the service dispatch inside
  /// [`RouteEvents::next`], at the RECEIPT instant and after classification;
  /// read by every point that schedules a probe sequence.
  flood: ConflictFlood<I>,
  /// Test-only: how many times the relinquished-history screen was actually RUN,
  /// as opposed to answered from `RouteEvents`' per-record cache. The bound that
  /// cache exists for is a statement about work done, so it is asserted on
  /// directly rather than inferred from a wall clock. `cfg(test)`: absent from a
  /// shipped build.
  #[cfg(test)]
  pub(crate) history_screens: usize,
  /// Test-only: every [`ServiceEvent`] this endpoint has dispatched, in order.
  /// See [`Dispatched`]; a routing test reads this because a service event is no
  /// longer observable from outside. `cfg(test)`: absent from a shipped build.
  #[cfg(test)]
  pub(crate) dispatched: std::vec::Vec<Dispatched>,
  /// Scratch for the instance names a rename must avoid, refilled from the route
  /// table on the ticks a rename is actually imminent.
  ///
  /// Held on the endpoint rather than allocated per rename because the route
  /// holding the renaming `Service` is mutably borrowed while the rename runs,
  /// so the names have to be collected first — and a conflict flood is exactly
  /// when a fresh allocation per tick is least welcome.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  rename_scratch: std::vec::Vec<Name>,
  /// In-progress withdrawal items, keyed by an opaque [`WithdrawalToken`].  Each
  /// entry is ONE name's TTL=0 goodbye lifecycle; a route-attached item keeps its
  /// route in `self.services` alive until the goodbye sequence completes (so the
  /// name guard continues to reject same-name re-registration).
  ///
  /// Stored as a `Vec` rather than as an inline field on [`ServiceRoute`]
  /// because an item need not have a route: a rename's detached old-name goodbye
  /// holds none, and a teardown mid-rename owes two items for one route.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  withdrawals: std::vec::Vec<(WithdrawalToken, WithdrawalItem<I>)>,
  /// Monotonic source of [`WithdrawalToken`] values. Incremented on every item
  /// insert and NEVER reused, so a token names exactly the item it was minted for
  /// (or nothing, once that item drained) — there is no ABA on the poll/note key.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  next_withdrawal_token: u64,
  /// Record sets this endpoint recently ASSERTED AND RELINQUISHED, screened
  /// against every conflict candidate before it reaches a service so our own
  /// past cannot retire our own present. See the [`relinquished`] module for the
  /// whole argument, [`Self::retain_relinquished`] for what feeds it, and
  /// [`EndpointConfig::relinquished_retention`](crate::EndpointConfig::relinquished_retention)
  /// for how long a row lives.
  ///
  /// A `Vec` for the same reason [`Self::withdrawals`] is one: what it records
  /// OUTLIVES the route that asserted it — that is the whole point of a
  /// relinquishment — so it cannot be hung off a route at all.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  relinquished: std::vec::Vec<Relinquished<I>>,
  /// The COMPACT tier of the same screen: the record IDENTITIES of
  /// relinquishments that arrived while
  /// [`relinquished::MAX_RELINQUISHED_RRSETS`] was reached with every row still
  /// live.
  ///
  /// An identity is `(owner name, rrtype, canonical rdata)` — the whole of what
  /// [`Self::relinquished_asserts`] ever asks — so this answers exactly what a
  /// row would have, decomposed once at the relinquishment instead of
  /// regenerated per candidate record. Empty on every normally-operating
  /// endpoint. See [`Self::retain_relinquished`] for why capacity exhaustion
  /// degrades HERE, per identity, rather than endpoint-wide.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  relinquished_identities: std::vec::Vec<RelinquishedIdentity<I>>,
  #[cfg(feature = "stats")]
  stats: std::sync::Arc<hick_trace::stats::Stats>,
  /// Real time to burn inside the next [`Self::poll_query_transmit`], between
  /// the pool scan that resolves the handle and the poll that reads the clock.
  /// That stretch grows with the pool, whose size is the caller's choice and
  /// which this crate puts no ceiling on — but nothing a test can do from
  /// OUTSIDE the call makes it long enough to observe, so a test hands the
  /// endpoint the delay directly.
  /// `cfg(test)`: it does not exist in a shipped build.
  #[cfg(all(test, feature = "std"))]
  pub(crate) query_resolve_stall: Option<core::time::Duration>,
  _phantom: core::marker::PhantomData<(AN, EvQ, TQ, EvS)>,
}

impl<I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS> Endpoint<I, R, C, SR, QS, EV, AN, EvQ, TQ, EvS>
where
  I: Instant,
  R: Rng,
  C: Pool<CacheEntry<I>>,
  SR: Pool<ServiceRoute<I, TQ, EvS>>,
  QS: Pool<Query<I, AN, EvQ>>,
  EV: Pool<EndpointEventEntry>,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
  TQ: Pool<Transmit>,
  EvS: Pool<ServiceUpdate>,
{
  /// Build a new endpoint.
  pub fn try_new(config: EndpointConfig, mut rng: R) -> Self {
    let raw_txid = rng.next_u32() as u16;
    let next_txid = if raw_txid == 0 { 1 } else { raw_txid };
    #[cfg(feature = "stats")]
    let stats = std::sync::Arc::new(hick_trace::stats::Stats::default());
    #[cfg(feature = "stats")]
    let mut cache = Cache::new();
    #[cfg(feature = "stats")]
    cache.set_stats(stats.clone());
    #[cfg(not(feature = "stats"))]
    let cache = Cache::new();
    Self {
      config,
      rng,
      services: SR::new(),
      queries: QS::new(),
      cache,
      pending_events: EV::new(),
      next_service_handle: 0,
      next_query_handle: 0,
      next_txid,
      datagram_seq: 0,
      flood: ConflictFlood::new(),
      #[cfg(test)]
      history_screens: 0,
      #[cfg(test)]
      dispatched: std::vec::Vec::new(),
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      rename_scratch: std::vec::Vec::new(),
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      withdrawals: std::vec::Vec::new(),
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      next_withdrawal_token: 0,
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      relinquished: std::vec::Vec::new(),
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      relinquished_identities: std::vec::Vec::new(),
      #[cfg(feature = "stats")]
      stats,
      #[cfg(all(test, feature = "std"))]
      query_resolve_stall: None,
      _phantom: core::marker::PhantomData,
    }
  }

  cfg_stats! {
    /// Return a point-in-time snapshot of all counters and gauges.
    pub fn stats(&self) -> hick_trace::stats::StatsSnapshot {
      self.stats.snapshot()
    }

    /// Return a cloned handle to the shared [`hick_trace::stats::Stats`] so the I/O driver can
    /// bump transport-level counters (e.g. `bytes_tx`, `packets_tx`).
    pub fn stats_handle(&self) -> std::sync::Arc<hick_trace::stats::Stats> {
      self.stats.clone()
    }
  }

  /// Returns the configuration.
  #[inline(always)]
  pub const fn config(&self) -> &EndpointConfig {
    &self.config
  }
}

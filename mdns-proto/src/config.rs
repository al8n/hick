//! Configuration types passed to Endpoint/Service/Query constructors.

cfg_heap! {
  use core::time::Duration;
}

cfg_heap! {
  use crate::records::ServiceRecords;
}
cfg_heap! {
  use crate::{
    Name,
    wire::{ResourceClass, ResourceType},
  };
}

/// Configuration for an `Endpoint`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EndpointConfig {
  probe_unique_names: bool,
  answer_questions: bool,
  populate_cache: bool,
  trust_advertised_src_as_self: bool,
}

impl EndpointConfig {
  /// Construct with defaults: probe on registration, answer questions, cache
  /// observations, and DO NOT trust advertised-source matching as a self-
  /// loopback signal. The default is appropriate for the supported async
  /// driver, which computes a [`Provenance`](crate::Provenance) from its own
  /// send log for every inbound datagram and passes it to
  /// [`Endpoint::handle`](crate::Endpoint::handle) inside a
  /// [`Received`](crate::Received), and so does not need the lossy fallback.
  /// Callers whose driver keeps no send log — and so can report no better than
  /// [`Provenance::Unknown`](crate::Provenance::Unknown) — should enable
  /// `trust_advertised_src_as_self` to opt into the coarser guess.
  pub const fn new() -> Self {
    Self {
      probe_unique_names: true,
      answer_questions: true,
      populate_cache: true,
      trust_advertised_src_as_self: false,
    }
  }

  /// Whether to probe before claiming a service name.
  #[inline(always)]
  pub const fn probe_unique_names(&self) -> bool {
    self.probe_unique_names
  }

  /// Whether to answer incoming questions for registered services.
  ///
  /// # A probe for a name we own is answered either way
  ///
  /// Disabling this suppresses DISCOVERY: browse and resolve questions, the
  /// shared service-type PTR, and the RFC 6763 §9 meta-query. It does NOT
  /// suppress the RFC 6762 §8.1 defence of a unique name this endpoint has
  /// already claimed — "when a device receives a probe query for a name that it
  /// is currently using, it SHOULD generate its response to defend that name
  /// immediately". A probe query (QR=0, proposed records in the Authority
  /// Section, from port 5353) naming a registered service's INSTANCE or HOST
  /// name still reaches that service.
  ///
  /// Without that exemption a passive endpoint answers nothing, a conforming
  /// peer's probe goes unanswered, and the peer completes probing and claims the
  /// name the endpoint is still advertising — two owners, no resolution. Passive
  /// mode opts out of answering queries, not out of owning the names it
  /// advertises.
  #[inline(always)]
  pub const fn answer_questions(&self) -> bool {
    self.answer_questions
  }

  /// Whether to populate the cache from observed records.
  #[inline(always)]
  pub const fn populate_cache(&self) -> bool {
    self.populate_cache
  }

  /// Set whether to probe before claiming a service name.
  #[must_use]
  pub const fn with_probe_unique_names(mut self, v: bool) -> Self {
    self.probe_unique_names = v;
    self
  }

  /// Set whether to answer incoming questions for registered services.
  ///
  /// See [`Self::answer_questions`]: `false` suppresses discovery, not the
  /// RFC 6762 §8.1 defence of an already-claimed unique name.
  #[must_use]
  pub const fn with_answer_questions(mut self, v: bool) -> Self {
    self.answer_questions = v;
    self
  }

  /// Set whether to populate the cache from observed records.
  #[must_use]
  pub const fn with_populate_cache(mut self, v: bool) -> Self {
    self.populate_cache = v;
    self
  }

  /// Whether to treat any inbound packet whose source IP matches an
  /// advertised A/AAAA record as a self-loopback.
  ///
  /// Default: `false`. A driver reporting
  /// [`Provenance::NotFromUs`](crate::Provenance::NotFromUs) keeps a send log
  /// and found no match in it — better evidence than this guess — so the guess
  /// is not consulted at all under that tier. Under
  /// [`Provenance::Unknown`](crate::Provenance::Unknown), where the driver
  /// keeps no send log, the guess is still consulted: a match answers an RFC
  /// 6762 §8.1 defence of an already-claimed name rather than leaving the
  /// question unanswered, though it still suppresses cache population and
  /// duplicate-question suppression. Enable only for a sync / single-process
  /// responder that keeps no send log and so reports
  /// [`Provenance::Unknown`](crate::Provenance::Unknown).
  #[inline(always)]
  pub const fn trust_advertised_src_as_self(&self) -> bool {
    self.trust_advertised_src_as_self
  }

  /// Set [`Self::trust_advertised_src_as_self`].
  #[must_use]
  pub const fn with_trust_advertised_src_as_self(mut self, v: bool) -> Self {
    self.trust_advertised_src_as_self = v;
    self
  }
}

impl Default for EndpointConfig {
  fn default() -> Self {
    Self::new()
  }
}

cfg_heap! {
  /// Spec for registering a service.
  #[derive(Debug, Clone, Eq, PartialEq)]
  pub struct ServiceSpec {
    records: ServiceRecords,
  }

  impl ServiceSpec {
    /// Wrap a `ServiceRecords` bundle as a spec.
    pub const fn new(records: ServiceRecords) -> Self {
      Self { records }
    }

    /// Borrow the inner records.
    #[inline(always)]
    pub const fn records(&self) -> &ServiceRecords {
      &self.records
    }

    /// Consume the spec, returning the inner records.
    #[inline(always)]
    pub fn into_records(self) -> ServiceRecords {
      self.records
    }
  }
}

cfg_heap! {
  /// Spec for starting a query.
  #[derive(Debug, Clone, Eq, PartialEq)]
  pub struct QuerySpec {
    qname: Name,
    qtype: ResourceType,
    qclass: ResourceClass,
    unicast_response: bool,
    timeout: Option<Duration>,
    max_answers: Option<usize>,
  }

  impl QuerySpec {
    /// Build a new spec for an mDNS query.
    pub fn new(qname: Name, qtype: ResourceType) -> Self {
      Self {
        qname,
        qtype,
        qclass: ResourceClass::In,
        unicast_response: false,
        timeout: None,
        max_answers: None,
      }
    }

    /// The query name.
    #[inline(always)]
    pub fn qname(&self) -> &Name {
      &self.qname
    }

    /// The query resource type.
    #[inline(always)]
    pub const fn qtype(&self) -> ResourceType {
      self.qtype
    }

    /// The query class.
    #[inline(always)]
    pub const fn qclass(&self) -> ResourceClass {
      self.qclass
    }

    /// Whether to request unicast responses (RFC 6762 §5.4).
    #[inline(always)]
    pub const fn unicast_response(&self) -> bool {
      self.unicast_response
    }

    /// The absolute timeout for the query, if set. See [`Self::with_timeout`]
    /// for the boundary it guarantees.
    #[inline(always)]
    pub const fn timeout(&self) -> Option<Duration> {
      self.timeout
    }

    /// Maximum number of collected answers, if explicitly overridden.
    ///
    /// When `None` the `Query` state machine uses its built-in default (256).
    #[inline(always)]
    pub const fn max_answers(&self) -> Option<usize> {
      self.max_answers
    }

    /// Override the query class.
    #[must_use]
    pub const fn with_qclass(mut self, v: ResourceClass) -> Self {
      self.qclass = v;
      self
    }

    /// Request unicast responses (RFC 6762 §5.4).
    #[must_use]
    pub const fn with_unicast_response(mut self, v: bool) -> Self {
      self.unicast_response = v;
      self
    }

    /// Set an absolute timeout for the query, measured from the instant the
    /// query is started.
    ///
    /// # The boundary is ADMISSION, and admission is the COMPARISON
    ///
    /// A question is **admitted** at the instant [`Query::poll_transmit`] reads
    /// the clock, weighs it against `start + timeout`, and finds the window
    /// open. No question is admitted on or after `start + timeout`: the core
    /// withholds the datagram instead, and it re-weighs the deadline at *every*
    /// admission — so a question armed inside the window but drawn outside it
    /// is never committed to at all. The query itself ends on the same
    /// boundary, in [`Query::handle_timeout`], on a wakeup
    /// [`Query::poll_timeout`] publishes — and a query that has ended draws no
    /// question at all.
    ///
    /// The boundary is that comparison and not the moment `poll_transmit`
    /// returns, because the comparison is the last point at which the outcome is
    /// still open. Encoding the question and returning the datagram both happen
    /// after it, both take time, and a second comparison placed before the
    /// return would leave the interval between itself and the return just as
    /// this one leaves the interval before the encode. So the promise is made
    /// where it can be kept, and everything downstream of it is stated below as
    /// overshoot.
    ///
    /// # The same boundary cuts off the ANSWERS
    ///
    /// An answer applied to this query on or after `start + timeout` is refused,
    /// on the same comparison, by [`Query::handle_event`]. The RFC 6762 §7.3
    /// duplicate-question suppression a peer's query would trigger is refused
    /// there too, so past the boundary the query spends no retry slot either.
    ///
    /// Without that, what a caller collected would depend on the internal
    /// ordering of its driver's loop: a receive path that runs ahead of the
    /// timer pump reaches a query no timer has ended yet, so one and the same
    /// response — same arrival, same instant, same deadline already passed —
    /// would land on that driver and be dropped by one whose timers fired first.
    /// And because a collected answer competes for the `max_answers` cap,
    /// letting the late one in can EVICT an answer collected while the window
    /// was open.
    ///
    /// The price is the answer that arrived inside the window and was only
    /// *processed* after it: it is dropped. That answer was never reliably
    /// yours — the tick order that happened to reach the query first is what
    /// would have saved it — so what is given up is a result that survived by
    /// accident, and what is bought is a deadline that means the same thing
    /// whichever driver runs it.
    ///
    /// # It is NOT the instant the datagram leaves
    ///
    /// A question admitted just inside the window may reach the wire well after
    /// it, and this promise deliberately does not claim otherwise. No userspace
    /// precheck can make the handover atomic: a check placed immediately before
    /// `sendto` still leaves the interval between the check and the syscall, and
    /// between the syscall and the wire. Every move of the check shortens that
    /// interval and none of them removes it, so the guarantee is stated where it
    /// can be kept. An enforceable departure boundary would have to come from
    /// the operating system, not from a comparison in this crate.
    ///
    /// What a caller may conclude, then, is not that no question bearing this
    /// `qname` was on the wire after the deadline. It is that the query stopped
    /// *committing* to questions there, and that whatever was still in flight
    /// had already been admitted while the window was open.
    ///
    /// # What bounds the overshoot
    ///
    /// Everything between the comparison and the wire, which is the quantity to
    /// size a window against:
    ///
    /// * **The rest of `poll_transmit`** — building the question into the
    ///   caller's buffer and returning the [`Transmit`] that describes it. A
    ///   fixed, small amount of work on memory the caller already owns, plus
    ///   whatever the host's preemption adds to it.
    /// * **The driver's own path from that return to its `sendto`**, which
    ///   depends on the shape of the path rather than on this crate:
    ///   * A **synchronous** send path — per-family spacing check, syscall, no
    ///     suspension point — overshoots by that stretch plus whatever the
    ///     host's preemption adds. `hick-mio` has this shape.
    ///   * An **awaited** send path additionally carries the socket's own
    ///     latency and the executor's scheduling latency, and can be
    ///     meaningfully longer. How much longer is the driver's to state:
    ///     `hick-reactor` bounds each family's attempt at RFC 6762 §8.1's 250 ms
    ///     inter-probe interval and abandons it there — sound only because
    ///     readiness I/O makes no syscall until the socket is writable — while
    ///     `hick-compio` has no such licence, since cancelling a submitted
    ///     completion-based operation is unreliable, and so awaits every fan-out
    ///     to completion for as long as the kernel takes.
    ///   * A driver whose entry point receives an *instant* rather than a clock
    ///     (`hick-smoltcp` and `hick-embassy`, through `Engine::pump`) weighs
    ///     admission against its caller's reading, so admission there is only as
    ///     fresh as that reading.
    ///
    /// A driver that parked an admitted datagram and sent it on a later pass
    /// would widen this without bound. None of the drivers here do: a pass cut
    /// short by its send budget parks its *cursor*, and a query it did not reach
    /// is polled — and so re-weighed — afresh by the pass that resumes.
    ///
    /// # No effective deadline
    ///
    /// A `timeout` so large that `start + timeout` overflows the caller's
    /// `Instant` leaves the query with no deadline rather than a clamped one:
    /// such a query ends only when its RFC 6762 §5.2 retry budget or the caller
    /// ends it.
    ///
    /// [`Query::poll_transmit`]: crate::Query::poll_transmit
    /// [`Query::handle_event`]: crate::Query::handle_event
    /// [`Query::handle_timeout`]: crate::Query::handle_timeout
    /// [`Query::poll_timeout`]: crate::Query::poll_timeout
    /// [`Transmit`]: crate::Transmit
    #[must_use]
    pub const fn with_timeout(mut self, v: Duration) -> Self {
      self.timeout = Some(v);
      self
    }

    /// Override the maximum number of collected answers for this query.
    ///
    /// When the pool reaches `max`, the oldest entry (FIFO) is evicted to make
    /// room.  Setting `max` to 0 disables answer collection entirely.
    #[must_use]
    pub const fn with_max_answers(mut self, max: usize) -> Self {
      self.max_answers = Some(max);
      self
    }
  }
}

#[cfg(test)]
// QuerySpec / Name need a heap name store, so the test module is
// gated to the tiers where they exist — `--no-default-features` is core-only.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(clippy::unwrap_used)]
mod tests;

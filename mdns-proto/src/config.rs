//! Configuration types passed to Endpoint/Service/Query constructors.

cfg_storage! {
  use core::time::Duration;
}

cfg_heap! {
  use crate::records::ServiceRecords;
}
cfg_storage! {
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
  /// driver, which passes an authoritative self-loopback flag to
  /// [`Endpoint::handle`](crate::Endpoint::handle) (its `caller_is_self`
  /// parameter) for every inbound datagram and so does not need the lossy
  /// fallback. Single-process callers that cannot supply `caller_is_self` should
  /// enable `trust_advertised_src_as_self` to recover the legacy
  /// behaviour.
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
  /// Default: `false`. The driver-side self-send hash cache — surfaced to
  /// the proto via the `caller_is_self` argument of
  /// [`Endpoint::handle`](crate::Endpoint::handle) — supersedes this signal and
  /// avoids the false positives that drop legitimate same-host peer traffic.
  /// Enable only when running a single-process responder that cannot supply
  /// `caller_is_self`.
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

cfg_storage! {
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

    /// The absolute timeout for the query, if set.
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

    /// Set an absolute timeout for the query.
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
// QuerySpec / Name need a heap (or heapless) name store, so the test module is
// gated to the tiers where they exist — `--no-default-features` is core-only.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(clippy::unwrap_used)]
mod tests;

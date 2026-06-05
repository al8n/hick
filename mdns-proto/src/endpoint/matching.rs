//! Name-matching + record-type helpers for the endpoint demux.

use super::*;

/// RFC 6763 §9 DNS-SD service-type enumeration (meta-query) name. A browser
/// queries this name (PTR) to discover which service TYPES exist on the link.
pub(crate) const DNS_SD_META_QUERY_NAME: &str = "_services._dns-sd._udp.local.";

/// True if `qname` is the RFC 6763 §9 meta-query name (case-insensitive). A
/// matching question is routed to every registered service so each can answer
/// with a shared PTR `_services._dns-sd._udp.local. -> <its service type>`.
pub(crate) fn is_meta_query_name(qname: &NameRef<'_>) -> bool {
  // Compare against the &'static meta-query name directly — no need to
  // allocate a `Name` (29 bytes, heap-backed) on every routed question.
  names_match_str(DNS_SD_META_QUERY_NAME, qname)
}

pub(crate) fn names_match(stored: &Name, incoming: &NameRef<'_>) -> bool {
  names_match_str(stored.as_str(), incoming)
}

pub(crate) fn names_match_str(stored_str: &str, incoming: &NameRef<'_>) -> bool {
  let stored_trim = match stored_str.strip_suffix('.') {
    Some(s) => s,
    None => stored_str,
  };
  let mut sit = stored_trim.split('.');
  let mut iit = incoming.labels();
  loop {
    match (sit.next(), iit.next()) {
      (None, None) => return true,
      (Some(s), Some(Ok(i))) => {
        if s.len() != i.len() {
          return false;
        }
        for (a, b) in s.bytes().zip(i.iter()) {
          if !a.eq_ignore_ascii_case(b) {
            return false;
          }
        }
      }
      _ => return false,
    }
  }
}

pub(crate) fn names_match_record(stored: &Name, r: &crate::wire::Ref<'_>) -> bool {
  names_match(stored, r.name())
}

/// the RR types a host name is authoritative for — the address
/// records (A / AAAA). Only these constitute a host-name conflict; a record of
/// any other type owned by the host name is not a claim on the host's unique
/// RRset and must not trigger a [`HostConflict`].
pub(crate) fn is_host_conflict_rtype(rt: ResourceType) -> bool {
  matches!(rt, ResourceType::A | ResourceType::AAAA)
}

/// the RR types a service INSTANCE name is authoritative for — SRV
/// and TXT (RFC 6763 §4). Only these constitute an instance-name conflict
/// (ProbeConflict / auto-rename); a record of any other type owned by the
/// instance name is not a claim on the instance's unique RRset. The PTR that
/// maps a service type to an instance is owned by the SHARED service-type name,
/// not the instance, and is excluded separately.
pub(crate) fn is_instance_conflict_rtype(rt: ResourceType) -> bool {
  matches!(rt, ResourceType::Srv | ResourceType::Txt)
}

/// Does `q`'s QTYPE/QCLASS accept the answer record `r`?
///
/// `ResourceType::Any` / `ResourceClass::Any` are wildcards.  Otherwise the
/// answer's rtype/rclass must match the query's exactly.  this
/// promotes type/class filtering from `Query::handle_event` up into the
/// demux so a single answer can fan out to every compatible query (not be
/// lost to the first-by-name match).
pub(crate) fn qry_query_accepts<I, AN, EvQ>(q: &Query<I, AN, EvQ>, r: &crate::wire::Ref<'_>) -> bool
where
  I: Instant,
  AN: Pool<CollectedAnswer>,
  EvQ: Pool<QueryUpdate>,
{
  let qt = q.qtype();
  let qc = q.qclass();
  let rt_ok = qt == ResourceType::Any || qt == r.rtype();
  // ResourceClass::Any is the wildcard QCLASS value 255 used in mDNS QU
  // queries; accept any answer class against it.  Otherwise the answer's
  // class must equal the query's QCLASS exactly.
  let rc_ok = qc == ResourceClass::Any || qc == r.rclass();
  rt_ok && rc_ok
}

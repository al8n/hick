use mdns_proto::{ServiceUpdate, event::ServiceRenamed};

use super::*;

fn renamed(n: &str) -> ServiceUpdate {
  ServiceUpdate::Renamed(ServiceRenamed::new(
    mdns_proto::Name::try_from_str(n).unwrap(),
  ))
}

#[test]
fn mailbox_coalesces_established_and_renamed_by_kind() {
  // Repeated Established collapses to one; rename churn collapses to the LATEST
  // name, kept at its most-recent position.
  let mut mb = ServiceMailbox::new();
  mb.push_update(ServiceUpdate::Established);
  mb.push_update(ServiceUpdate::Established);
  mb.push_update(renamed("a-1._ipp._tcp.local."));
  mb.push_update(renamed("a-2._ipp._tcp.local."));
  mb.push_update(renamed("a-3._ipp._tcp.local."));
  assert_eq!(
    mb.non_terminal_len(),
    2,
    "one Established + one (latest) Renamed"
  );
  // Established stays at the front (inserted first); the single surviving Renamed
  // carries the latest name.
  assert!(matches!(
    mb.drain(),
    Drained::Update(ServiceUpdate::Established)
  ));
  match mb.drain() {
    Drained::Update(ServiceUpdate::Renamed(r)) => {
      assert!(r.new_name().as_str().contains("a-3"))
    }
    other => panic!("expected the latest Renamed; got {other:?}"),
  }
  assert!(matches!(mb.drain(), Drained::Empty));
}

#[test]
fn mailbox_preserves_post_rename_established() {
  // Established -> Renamed -> Established (establish, conflict, auto-rename,
  // re-establish under the new name). A slow reader MUST still observe the
  // post-rename Established AFTER the Renamed, so it learns the new name became
  // advertised — not merely that a rename happened. The earlier
  // (pre-rename) Established coalesces away: it was for the now-stale name.
  let mut mb = ServiceMailbox::new();
  mb.push_update(ServiceUpdate::Established); // established under the orig name
  mb.push_update(ServiceUpdate::Established); // duplicate: coalesces
  mb.push_update(renamed("svc-2._ipp._tcp.local.")); // §9 conflict rename
  mb.push_update(ServiceUpdate::Established); // re-established under svc-2
  assert_eq!(
    mb.non_terminal_len(),
    2,
    "latest Renamed + the trailing post-rename Established"
  );
  // Drains in order: Renamed(svc-2) first, then the post-rename Established.
  match mb.drain() {
    Drained::Update(ServiceUpdate::Renamed(r)) => {
      assert!(r.new_name().as_str().contains("svc-2"))
    }
    other => panic!("expected Renamed(svc-2) first; got {other:?}"),
  }
  assert!(
    matches!(mb.drain(), Drained::Update(ServiceUpdate::Established)),
    "the post-rename Established must survive, after the Renamed"
  );
  assert!(matches!(mb.drain(), Drained::Empty));
}

#[test]
fn mailbox_rename_churn_coalesces_within_cap() {
  // A flood of distinct Renamed updates cannot grow the ring past one entry: the
  // Renamed-coalesce keeps only the latest.
  let mut mb = ServiceMailbox::new();
  for i in 0..(SERVICE_UPDATE_CAPACITY + 64) {
    mb.push_update(renamed(&format!("svc-{i}._ipp._tcp.local.")));
  }
  assert_eq!(
    mb.non_terminal_len(),
    1,
    "rename churn coalesces to a single pending Renamed, well within the cap"
  );
}

#[test]
fn mailbox_hard_cap_drops_oldest() {
  // Drive the hard drop-oldest backstop directly: push distinct non-coalescing
  // entries past the cap via the internal bounded_push_back, then confirm the
  // ring never exceeds the cap and the oldest were evicted.
  let mut mb = ServiceMailbox::new();
  for i in 0..(SERVICE_UPDATE_CAPACITY as u32 + 5) {
    // Use Renamed values but bypass the dedup-retain to fill the ring.
    mb.bounded_push_back(renamed(&format!("svc-{i}._ipp._tcp.local.")));
  }
  assert_eq!(mb.non_terminal_len(), SERVICE_UPDATE_CAPACITY);
  // The first 5 were evicted; the oldest survivor is svc-5.
  match mb.drain() {
    Drained::Update(ServiceUpdate::Renamed(r)) => assert!(
      r.new_name().as_str().contains("svc-5"),
      "oldest survivor is svc-5"
    ),
    other => panic!("expected a Renamed at the head; got {other:?}"),
  }
}

#[test]
fn mailbox_terminal_reserved_under_non_terminal_pressure() {
  // The terminal slot is separate from the bounded non-terminal ring, so a flood
  // never drops it, and it is delivered LAST.
  let mut mb = ServiceMailbox::new();
  for i in 0..(SERVICE_UPDATE_CAPACITY + 64) {
    mb.bounded_push_back(renamed(&format!("svc-{i}._ipp._tcp.local.")));
  }
  mb.set_terminal(ServiceUpdate::Conflict);
  let mut non_terminal = 0usize;
  let mut got_terminal = false;
  loop {
    match mb.drain() {
      Drained::Update(ServiceUpdate::Conflict) => got_terminal = true,
      Drained::Update(_) => non_terminal += 1,
      Drained::Ended | Drained::Empty => break,
    }
  }
  assert_eq!(non_terminal, SERVICE_UPDATE_CAPACITY);
  assert!(
    got_terminal,
    "terminal must survive non-terminal backpressure"
  );
}

#[test]
fn mailbox_set_terminal_is_idempotent_first_wins() {
  let mut mb = ServiceMailbox::new();
  mb.set_terminal(ServiceUpdate::Conflict);
  mb.set_terminal(ServiceUpdate::HostConflict);
  // First terminal wins.
  assert!(matches!(
    mb.drain(),
    Drained::Update(ServiceUpdate::Conflict)
  ));
  assert!(matches!(mb.drain(), Drained::Ended));
}

#[test]
fn mailbox_routes_terminal_pushed_as_update_to_reserved_slot() {
  // Defensive: a terminal handed to push_update lands in the reserved slot, not
  // the non-terminal ring, so it is delivered last and never dropped.
  let mut mb = ServiceMailbox::new();
  mb.push_update(ServiceUpdate::Established);
  mb.push_update(ServiceUpdate::HostConflict);
  assert_eq!(mb.non_terminal_len(), 1, "only Established is in the ring");
  assert!(matches!(
    mb.drain(),
    Drained::Update(ServiceUpdate::Established)
  ));
  assert!(matches!(
    mb.drain(),
    Drained::Update(ServiceUpdate::HostConflict)
  ));
  assert!(matches!(mb.drain(), Drained::Ended));
}

#[test]
fn mailbox_drains_updates_then_terminal_then_ends() {
  let mut mb = ServiceMailbox::new();
  mb.push_update(ServiceUpdate::Established);
  mb.push_update(renamed("svc-1._ipp._tcp.local."));
  mb.set_terminal(ServiceUpdate::Conflict);
  assert!(matches!(
    mb.drain(),
    Drained::Update(ServiceUpdate::Established)
  ));
  assert!(matches!(
    mb.drain(),
    Drained::Update(ServiceUpdate::Renamed(_))
  ));
  assert!(matches!(
    mb.drain(),
    Drained::Update(ServiceUpdate::Conflict)
  ));
  // Terminal is the last update; subsequent drains report end-of-stream.
  assert!(matches!(mb.drain(), Drained::Ended));
  assert!(matches!(mb.drain(), Drained::Ended));
}

/// once a service is flagged `errored` (its records can't encode into
/// `max_payload`), `Service::next` must surface end-of-stream (`None`) after the
/// reserved terminal `Conflict` is drained — NOT park forever. The terminal read
/// is wrapped in a timeout so a regression FAILS (times out) instead of hanging
/// the whole suite.
#[compio::test]
async fn errored_service_next_terminates_after_conflict() {
  let inner = EndpointInner::new(mdns_proto::EndpointConfig::default(), 1500, 9000);
  let now = std::time::Instant::now();

  let stype = mdns_proto::Name::try_from_str("_er._tcp.local.").unwrap();
  let inst = mdns_proto::Name::try_from_str("E._er._tcp.local.").unwrap();
  let host = mdns_proto::Name::try_from_str("e.local.").unwrap();
  let mut recs = mdns_proto::ServiceRecords::new(stype, inst, host, 1234, 120);
  recs.add_a([127, 0, 0, 1].into());
  let mailbox = new_service_mailbox();
  let handle = inner
    .state
    .borrow_mut()
    .register_service(mdns_proto::ServiceSpec::new(recs), now, Rc::clone(&mailbox))
    .unwrap();

  // Simulate the escalation the transmit pump performs on persistent encode
  // failure: record the terminal Conflict in the reserved slot and flag the
  // service errored. (The full encode-failure drive is covered by the
  // driver-level unit test; here we exercise the HANDLE terminal contract.)
  {
    mailbox.borrow_mut().set_terminal(ServiceUpdate::Conflict);
    let mut st = inner.state.borrow_mut();
    st.services.get_mut(&handle).unwrap().errored = true;
  }

  let svc = Service {
    inner: Rc::clone(&inner),
    handle,
    mailbox: Rc::clone(&mailbox),
  };

  // First next(): drains the reserved Conflict.
  let first = svc.next().await;
  assert!(
    matches!(first, Some(ServiceUpdate::Conflict)),
    "first next() must surface the queued Conflict, got {first:?}"
  );

  // Second next(): MUST resolve to None (end-of-stream), not park forever. The
  // timeout turns a regression into a failure instead of a hung suite.
  let second = compio::time::timeout(std::time::Duration::from_secs(2), svc.next()).await;
  match second {
    Ok(v) => assert!(
      v.is_none(),
      "next() after the Conflict must be end-of-stream (None), got {v:?}"
    ),
    Err(_) => panic!("Service::next parked forever on an errored service"),
  }

  // Keep the handle alive until here so its Drop (which borrows state) runs after
  // our assertions, not mid-test.
  drop(svc);
}

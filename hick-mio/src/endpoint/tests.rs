use mio::{Poll, Token};

use crate::driver::test_support;

#[test]
fn owns_claims_both_reserved_tokens_and_nothing_else() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let poll = Poll::new().expect("mio::Poll");
  assert!(
    !mdns.owns(Token(7)),
    "no token is owned before registration"
  );
  mdns
    .register(poll.registry(), Token(7), Token(8))
    .expect("register");
  assert!(mdns.owns(Token(7)));
  assert!(mdns.owns(Token(8)));
  assert!(!mdns.owns(Token(9)));
}

#[test]
fn register_rejects_one_token_for_both_sockets() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let poll = Poll::new().expect("mio::Poll");
  // One token cannot address two sockets: readiness would be unattributable.
  assert!(mdns.register(poll.registry(), Token(1), Token(1)).is_err());
  assert!(!mdns.owns(Token(1)));
}

#[test]
fn register_twice_without_deregistering_is_rejected() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let poll = Poll::new().expect("mio::Poll");
  mdns
    .register(poll.registry(), Token(1), Token(2))
    .expect("register");
  assert!(mdns.register(poll.registry(), Token(3), Token(4)).is_err());
  // The first registration is untouched by the rejected second one.
  assert!(mdns.owns(Token(1)));
  assert!(!mdns.owns(Token(3)));
}

#[test]
fn deregister_releases_the_tokens_and_allows_re_registration() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let poll = Poll::new().expect("mio::Poll");
  mdns
    .register(poll.registry(), Token(1), Token(2))
    .expect("register");
  mdns.deregister().expect("deregister");
  assert!(!mdns.owns(Token(1)));
  assert!(!mdns.owns(Token(2)));
  mdns
    .register(poll.registry(), Token(3), Token(4))
    .expect("re-register");
  assert!(mdns.owns(Token(3)));
}

#[test]
fn a_fresh_endpoint_has_no_events_and_no_losses() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  assert!(mdns.next_event().is_none());
  assert_eq!(mdns.dropped_events(), 0);
}

#[test]
fn a_duplicate_instance_name_is_rejected() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-dup._tcp.local.",
      8080,
    ))
    .expect("register_service");
  assert!(
    mdns
      .register_service(test_support::service_spec(
        "_hick-mio-dup._tcp.local.",
        8080
      ))
      .is_err(),
    "the same instance name must not register twice"
  );
  assert_eq!(mdns.services.len(), 1);
}

#[test]
fn unregistering_a_service_holds_its_name_until_the_goodbye_settles() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-free._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns.unregister_service(handle);
  // The endpoint keeps the route while the RFC 6762 §10.1 goodbye is in flight:
  // a same-name replacement announcing a fresh positive TTL ahead of our TTL=0
  // retraction would leave peers holding the stale record.
  assert!(
    mdns
      .register_service(test_support::service_spec(
        "_hick-mio-free._tcp.local.",
        8080
      ))
      .is_err(),
    "the name is held until the withdrawal completes"
  );
  // Never announced, so the goodbye owes nothing and settles on the first pass.
  mdns.tick().expect("tick");
  assert!(mdns.services.is_empty());
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-free._tcp.local.",
      8080,
    ))
    .expect("the name must be reusable once the withdrawal completes");
}

#[test]
fn unregistering_an_unknown_handle_is_a_noop() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let handle = mdns
    .register_service(test_support::service_spec(
      "_hick-mio-gone._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns.unregister_service(handle);
  // Idempotent: a second unregister of the same handle must not panic or
  // disturb an unrelated registration.
  mdns.unregister_service(handle);
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-other._tcp.local.",
      8080,
    ))
    .expect("register_service");
  // Two contexts: the withdrawing one, still resident until its goodbye
  // settles, plus the fresh registration.
  assert_eq!(mdns.services.len(), 2);
  mdns.tick().expect("tick");
  assert_eq!(mdns.services.len(), 1);
}

#[test]
fn shutdown_is_idempotent() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-twice._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns.shutdown();
  // A second call must not enqueue a duplicate goodbye schedule, which would
  // double every service's resend budget and delay the route free.
  mdns.shutdown();
  mdns.tick().expect("tick");
  assert!(mdns.is_idle());
  assert!(mdns.services.is_empty());
}

/// `Drop` cannot pump the caller's loop, so it makes ONE best-effort pass:
/// begin every live service's goodbye, put a round on the wire, and free what
/// settled. This drives that pass directly — after it, a never-announced
/// service has nothing left owed and no context.
#[test]
fn the_drop_pass_begins_pumps_and_settles_in_one_go() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-drop._tcp.local.",
      8080,
    ))
    .expect("register_service");
  mdns.best_effort_goodbye_pass();
  assert!(
    !mdns.endpoint.has_pending_withdrawals(),
    "the pass must begin the goodbye, not merely mark the service"
  );
  assert!(mdns.services.is_empty());
}

#[test]
fn dropping_a_live_endpoint_does_not_panic() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  mdns
    .register_service(test_support::service_spec(
      "_hick-mio-dropped._tcp.local.",
      8080,
    ))
    .expect("register_service");
  // The whole point of the degraded path: a caller that never ran the
  // `shutdown` + `is_idle` loop still gets one goodbye attempt, and dropping
  // must stay infallible.
  drop(mdns);
}

#[test]
fn cancelling_an_unknown_query_handle_is_a_noop() {
  let Some(mut mdns) = test_support::loopback_mdns() else {
    return;
  };
  let handle = mdns
    .start_query(test_support::query_spec("_hick-mio-cancel._tcp.local."))
    .expect("start_query");
  mdns.cancel_query(handle);
  mdns.cancel_query(handle);
  assert!(mdns.queries.is_empty());
}

use super::*;

#[test]
fn endpoint_config_builders_and_accessors() {
  let cfg = EndpointConfig::new()
    .with_probe_unique_names(false)
    .with_answer_questions(false)
    .with_populate_cache(false);
  assert!(!cfg.probe_unique_names());
  assert!(!cfg.answer_questions());
  assert!(!cfg.populate_cache());
}

#[test]
fn query_spec_with_qclass_overrides_class() {
  let q = QuerySpec::new(
    Name::try_from_str("_http._tcp.local.").unwrap(),
    ResourceType::Ptr,
  )
  .with_qclass(ResourceClass::Any);
  assert!(q.qclass().is_any());
}

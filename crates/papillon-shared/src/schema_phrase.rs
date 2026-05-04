use heck::ToTitleCase;

/// Convert a schema.org type or action string to a plain-English phrase.
///
/// If an agent has a `description` field, callers should prefer it over this
/// derived phrase — this is a fallback for agents without a description.
pub fn schema_phrase(s: &str) -> String {
    let s = s.trim_start_matches("schema:");
    let s = s.strip_suffix("Action").unwrap_or(s);
    s.to_title_case()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_schema_prefix_and_action_suffix() {
        assert_eq!(schema_phrase("schema:SearchAction"), "Search");
    }

    #[test]
    fn converts_camelcase_return_type() {
        assert_eq!(schema_phrase("schema:SoftwareApplication"), "Software Application");
    }

    #[test]
    fn handles_multi_word_action() {
        assert_eq!(schema_phrase("schema:LodgingReservation"), "Lodging Reservation");
    }

    #[test]
    fn handles_no_prefix() {
        assert_eq!(schema_phrase("SearchAction"), "Search");
    }

    #[test]
    fn handles_plain_word() {
        assert_eq!(schema_phrase("Search"), "Search");
    }

    #[test]
    fn empty_string() {
        assert_eq!(schema_phrase(""), "");
    }
}

#[cfg(test)]
mod execution_target_tests {
    use crate::types::{AgentInfo, AgentLifecycle, ExecutionTarget};

    fn make_agent(endpoint: Option<&str>) -> AgentInfo {
        AgentInfo {
            name: "Test".into(),
            provider_name: "Test".into(),
            provider_did: "did:key:z6Mk".into(),
            capabilities: vec![],
            object_types: vec![],
            requires_disclosure: vec![],
            returns: vec![],
            endpoint: endpoint.map(|s| s.to_string()),
            content_hash: "abc".into(),
            agent_did: None,
            source: "catalog".into(),
            published_to: vec![],
            live: true,
            category: "test".into(),
            execution_target: ExecutionTarget::derive(endpoint),
            lifecycle: AgentLifecycle::Draft,
        }
    }

    #[test]
    fn https_endpoint_is_remote() {
        let a = make_agent(Some("https://api.example.com"));
        assert!(matches!(a.execution_target, ExecutionTarget::Remote(_)));
    }

    #[test]
    fn file_endpoint_is_local() {
        let a = make_agent(Some("file:///usr/local/bin/my-agent"));
        assert!(matches!(a.execution_target, ExecutionTarget::Local(_)));
    }

    #[test]
    fn did_endpoint_is_subagent() {
        let a = make_agent(Some("did:key:z6MkhaXgBZ"));
        assert!(matches!(a.execution_target, ExecutionTarget::SubAgent(_)));
    }

    #[test]
    fn pap_endpoint_is_subagent() {
        let a = make_agent(Some("pap://some-agent"));
        assert!(matches!(a.execution_target, ExecutionTarget::SubAgent(_)));
    }

    #[test]
    fn none_endpoint_is_none_variant() {
        let a = make_agent(None);
        assert!(matches!(a.execution_target, ExecutionTarget::None));
    }
}

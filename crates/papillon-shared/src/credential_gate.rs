//! Credential gate — determines whether an agent's `requires_disclosure` list
//! needs vault credentials, and produces the user-facing disclosure request.

/// The canonical set of param names that represent API credentials.
/// These must come from the vault, never from query text or agent settings.
pub const CREDENTIAL_PARAM_NAMES: &[&str] = &[
    "api_key",
    "apikey",
    "access_key",
    "access_token",
    "key",
    "token",
    "api_token",
    "consumer_key",
    "user_key",
    "wskey",
];

/// Returns true if any item in `requires_disclosure` is a known credential param name.
pub fn needs_vault_credential(requires_disclosure: &[String]) -> bool {
    requires_disclosure
        .iter()
        .any(|s| CREDENTIAL_PARAM_NAMES.contains(&s.as_str()))
}

/// Returns the subset of `requires_disclosure` items that are credential param names.
pub fn credential_params_for(requires_disclosure: &[String]) -> Vec<String> {
    requires_disclosure
        .iter()
        .filter(|s| CREDENTIAL_PARAM_NAMES.contains(&s.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_vantage_needs_vault() {
        let reqs = vec!["query".to_string(), "api_key".to_string()];
        assert!(needs_vault_credential(&reqs));
    }

    #[test]
    fn geo_agent_no_vault_needed() {
        let reqs = vec!["lat".to_string(), "lon".to_string()];
        assert!(!needs_vault_credential(&reqs));
    }

    #[test]
    fn empty_disclosure_no_vault() {
        assert!(!needs_vault_credential(&[]));
    }

    #[test]
    fn credential_params_extracted() {
        let reqs = vec![
            "query".to_string(),
            "api_key".to_string(),
            "lat".to_string(),
        ];
        let creds = credential_params_for(&reqs);
        assert_eq!(creds, vec!["api_key".to_string()]);
    }

    #[test]
    fn all_credential_names_recognized() {
        for name in CREDENTIAL_PARAM_NAMES {
            let reqs = vec![name.to_string()];
            assert!(
                needs_vault_credential(&reqs),
                "'{name}' should be recognized as a credential param"
            );
        }
    }
}

//! Intent routing — shared between backend and frontend.
//!
//! `detect_intent` handles only deterministic cases (bare URLs).
//! Everything else returns `schema:AnalyzeAction` so the orchestrator
//! can route to a discovered NLU agent via federation.

/// Detect intent from a user prompt.
///
/// Returns `(action_type, preferred_agent_name, cleaned_query)`.
///
/// Only bare HTTP/HTTPS URLs are routed deterministically to the Web Page
/// Reader. All other prompts return `("schema:AnalyzeAction", "", prompt)`
/// so `classify_intent()` in the orchestrator can forward them to a
/// federated NLU agent (`schema:AnalyzeAction` → `pap:IntentClassification`).
///
/// `pap://` URIs are resolved upstream by `resolve_pap_uri()` before this
/// function is ever called.
pub fn detect_intent(prompt: &str) -> (&'static str, &'static str, String) {
    let lower = prompt.to_lowercase();

    // Bare URLs are the only deterministic shortcut — handled by Web Page Reader.
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return ("schema:ReadAction", "Web Page Reader", prompt.to_string());
    }

    // Everything else goes to federation-based intent classification.
    ("schema:AnalyzeAction", "", prompt.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_url_direct() {
        let (action, agent, _) = detect_intent("https://example.com");
        assert_eq!(action, "schema:ReadAction");
        assert_eq!(agent, "Web Page Reader");
    }

    #[test]
    fn detect_read_page_http() {
        let (action, agent, query) = detect_intent("http://example.com/page");
        assert_eq!(action, "schema:ReadAction");
        assert_eq!(agent, "Web Page Reader");
        assert_eq!(query, "http://example.com/page");
    }

    #[test]
    fn plain_prompt_routes_to_analyze() {
        let (action, preferred, query) = detect_intent("explain quantum computing");
        assert_eq!(action, "schema:AnalyzeAction");
        assert_eq!(preferred, "");
        assert_eq!(query, "explain quantum computing");
    }

    #[test]
    fn empty_prompt_routes_to_analyze() {
        let (action, _, _) = detect_intent("");
        assert_eq!(action, "schema:AnalyzeAction");
    }

    #[test]
    fn unicode_prompt_routes_to_analyze() {
        let (action, _, _) = detect_intent("中文搜索 🦀");
        assert_eq!(action, "schema:AnalyzeAction");
    }

    #[test]
    fn https_url_routes_to_web_reader() {
        let (action, agent, _) = detect_intent("https://rust-lang.org");
        assert_eq!(action, "schema:ReadAction");
        assert_eq!(agent, "Web Page Reader");
    }
}

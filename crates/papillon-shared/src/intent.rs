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

    // ── URL routing: mixed-case and scheme variants ──────────────────────────

    #[test]
    fn uppercase_https_is_not_a_url_routes_to_analyze() {
        // detect_intent lowercases before checking — HTTPS:// is caught correctly
        let (action, _, _) = detect_intent("HTTPS://example.com");
        assert_eq!(
            action, "schema:ReadAction",
            "uppercase HTTPS:// should still route to ReadAction"
        );
    }

    #[test]
    fn mixed_case_http_routes_to_web_reader() {
        let (action, agent, _) = detect_intent("HTTP://example.com/page");
        assert_eq!(action, "schema:ReadAction");
        assert_eq!(agent, "Web Page Reader");
    }

    #[test]
    fn url_with_path_and_query_string_routes_to_read() {
        let (action, agent, query) =
            detect_intent("https://example.com/search?q=rust&page=2");
        assert_eq!(action, "schema:ReadAction");
        assert_eq!(agent, "Web Page Reader");
        // The original prompt is returned unchanged
        assert_eq!(query, "https://example.com/search?q=rust&page=2");
    }

    #[test]
    fn url_with_fragment_routes_to_read() {
        let (action, _, _) = detect_intent("https://docs.rs/leptos#components");
        assert_eq!(action, "schema:ReadAction");
    }

    #[test]
    fn url_returned_as_cleaned_query_preserves_original_case() {
        // The prompt is returned verbatim (not lowercased)
        let input = "HTTPS://Example.COM/Path";
        let (_, _, query) = detect_intent(input);
        assert_eq!(query, input, "cleaned_query must preserve original casing");
    }

    // ── Non-URL prompts ──────────────────────────────────────────────────────

    #[test]
    fn prompt_starting_with_ftp_routes_to_analyze() {
        // ftp:// is not handled — only http(s):// — so it falls through to analyze
        let (action, _, _) = detect_intent("ftp://files.example.com/file.zip");
        assert_eq!(action, "schema:AnalyzeAction");
    }

    #[test]
    fn prompt_that_contains_https_but_does_not_start_with_it_routes_to_analyze() {
        let (action, _, _) = detect_intent("check out https://example.com");
        assert_eq!(
            action, "schema:AnalyzeAction",
            "URL not at start should not trigger ReadAction"
        );
    }

    #[test]
    fn whitespace_only_prompt_routes_to_analyze() {
        let (action, _, _) = detect_intent("   ");
        assert_eq!(action, "schema:AnalyzeAction");
    }

    #[test]
    fn prompt_with_leading_whitespace_and_url_routes_to_analyze() {
        // Leading whitespace means it doesn't start_with("https://")
        let (action, _, _) = detect_intent("  https://example.com");
        assert_eq!(action, "schema:AnalyzeAction");
    }

    #[test]
    fn very_long_prompt_routes_to_analyze() {
        let long = "a".repeat(10_000);
        let (action, _, _) = detect_intent(&long);
        assert_eq!(action, "schema:AnalyzeAction");
    }

    #[test]
    fn pap_uri_routes_to_analyze_not_read() {
        // pap:// URIs are resolved upstream before detect_intent is called;
        // if they somehow reach here they should NOT route to ReadAction
        let (action, _, _) = detect_intent("pap://flight-search");
        assert_eq!(action, "schema:AnalyzeAction");
    }

    #[test]
    fn pap_discovery_uri_routes_to_analyze() {
        let (action, _, _) = detect_intent("pap+discovery://github.com");
        assert_eq!(action, "schema:AnalyzeAction");
    }

    #[test]
    fn non_url_preferred_agent_is_always_empty() {
        // Non-URL prompts always return empty preferred agent name
        let cases = [
            "search for flights",
            "what is the weather in Paris?",
            "summarize this document",
            "",
            "ftp://example.com",
            "pap://some-agent",
        ];
        for prompt in cases {
            let (_, preferred, _) = detect_intent(prompt);
            assert_eq!(
                preferred, "",
                "non-URL prompt '{prompt}' should have empty preferred agent"
            );
        }
    }

    #[test]
    fn url_prompt_cleaned_query_equals_original_prompt() {
        let url = "https://news.ycombinator.com/item?id=12345";
        let (_, _, query) = detect_intent(url);
        assert_eq!(query, url);
    }

    #[test]
    fn analyze_action_cleaned_query_equals_original_prompt() {
        let prompt = "explain how the PAP handshake works";
        let (_, _, query) = detect_intent(prompt);
        assert_eq!(query, prompt);
    }

    #[test]
    fn newline_in_prompt_routes_to_analyze() {
        let (action, _, _) = detect_intent("https://example.com\nsome extra text");
        // The lowercased form starts with https:// so it still routes to ReadAction
        // The original full string is returned as the cleaned query
        let (_, _, query) = detect_intent("https://example.com\nsome extra text");
        assert_eq!(action, "schema:ReadAction");
        assert!(query.contains('\n'));
    }
}

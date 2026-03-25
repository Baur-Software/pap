//! Intent detection for canvas prompts.
//!
//! Port of `detect_intent()` from `apps/papillion/src/commands/canvas.rs`.
//! Pure string matching — no external dependencies.

/// Detect the Schema.org action type, preferred agent name, and cleaned query
/// from a raw prompt string.
///
/// Returns `(action_type, preferred_agent_name, cleaned_query)`.
pub fn detect_intent(prompt: &str) -> (&'static str, &'static str, String) {
    let lower = prompt.to_lowercase();

    if lower.contains("wikipedia")
        || lower.contains("wiki")
        || lower.contains("article about")
        || lower.contains("tell me about")
    {
        let q = prompt
            .replace("wikipedia", "")
            .replace("wiki", "")
            .replace("article about", "")
            .replace("tell me about", "")
            .trim()
            .to_string();
        (
            "schema:SearchAction",
            "Wikipedia Knowledge",
            if q.is_empty() { prompt.into() } else { q },
        )
    } else if lower.contains("search")
        || lower.contains("find")
        || lower.contains("look up")
        || lower.starts_with("what is")
        || lower.starts_with("who is")
    {
        let q = prompt
            .replace("search", "")
            .replace("find", "")
            .replace("look up", "")
            .trim()
            .to_string();
        (
            "schema:SearchAction",
            "DuckDuckGo Search",
            if q.is_empty() { prompt.into() } else { q },
        )
    } else {
        ("schema:AskAction", "On-Device AI", prompt.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_intent_wiki() {
        let (action, agent, _query) = detect_intent("wikipedia Rust language");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Wikipedia Knowledge");
    }

    #[test]
    fn detect_intent_search() {
        let (action, agent, _query) = detect_intent("search for cats");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "DuckDuckGo Search");
    }

    #[test]
    fn detect_intent_ai_fallback() {
        let (action, agent, query) = detect_intent("explain quantum computing");
        assert_eq!(action, "schema:AskAction");
        assert_eq!(agent, "On-Device AI");
        assert_eq!(query, "explain quantum computing");
    }

    #[test]
    fn detect_intent_tell_me_about() {
        let (action, agent, query) = detect_intent("tell me about photosynthesis");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Wikipedia Knowledge");
        assert!(query.contains("photosynthesis"));
    }

    #[test]
    fn detect_intent_what_is() {
        let (action, _agent, _query) = detect_intent("what is Rust");
        assert_eq!(action, "schema:SearchAction");
    }
}

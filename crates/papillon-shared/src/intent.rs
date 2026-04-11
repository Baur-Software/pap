//! Data-driven intent detection — shared between backend and frontend.
//!
//! One table of rules, one `detect_intent()` function. No more duplicated
//! if-else chains that drift out of sync.

/// A rule mapping user keywords to an agent.
struct IntentRule {
    /// Any of these substrings triggers the rule (case-insensitive).
    keywords: &'static [&'static str],
    /// Any of these prefixes triggers the rule (case-insensitive).
    starts_with: &'static [&'static str],
    /// Schema.org action type.
    action: &'static str,
    /// Preferred agent name.
    agent: &'static str,
    /// Words/phrases stripped from the query before passing to the agent.
    strip: &'static [&'static str],
}

/// Rules are checked in order — first match wins.
/// More specific patterns come before generic ones.
const RULES: &[IntentRule] = &[
    // ── URL detection — must be first (very specific pattern) ──
    // Web Page Reader: the zero-trust bridge agent
    IntentRule {
        keywords: &["read page", "fetch url", "fetch page", "read url"],
        starts_with: &["http://", "https://"],
        action: "schema:ReadAction",
        agent: "Web Page Reader",
        strip: &["read page", "fetch url", "fetch page", "read url"],
    },
    // ── Tier 1: Specific domain agents ──
    // Weather / forecast — requires GeoCoordinates disclosure
    IntentRule {
        keywords: &["weather", "forecast", "temperature"],
        starts_with: &[],
        action: "schema:CheckAction",
        agent: "Open-Meteo Weather",
        strip: &["weather", "forecast", "temperature", " in ", " for "],
    },
    // Currency exchange
    IntentRule {
        keywords: &["convert", "exchange rate", "currency"],
        starts_with: &[],
        action: "schema:TradeAction",
        agent: "Frankfurter Exchange",
        strip: &["convert", "exchange rate", "currency"],
    },
    // Dictionary definitions
    IntentRule {
        keywords: &[
            "define ",
            "definition of",
            "meaning of",
            "what does the word",
        ],
        starts_with: &["define "],
        action: "schema:SearchAction",
        agent: "Free Dictionary",
        strip: &[
            "define ",
            "definition of",
            "meaning of",
            "what does the word",
        ],
    },
    // Country info
    IntentRule {
        keywords: &["country ", "countries", "capital of", "population of"],
        starts_with: &[],
        action: "schema:SearchAction",
        agent: "REST Countries",
        strip: &["country ", "countries", "capital of", "population of"],
    },
    // arXiv / academic papers
    IntentRule {
        keywords: &[
            "arxiv",
            "paper on",
            "papers about",
            "research on",
            "research paper",
        ],
        starts_with: &[],
        action: "schema:SearchAction",
        agent: "arXiv Papers",
        strip: &[
            "arxiv",
            "paper on",
            "papers about",
            "research on",
            "research paper",
        ],
    },
    // GitHub repos
    IntentRule {
        keywords: &["github", "repo ", "repos ", "repository"],
        starts_with: &[],
        action: "schema:SearchAction",
        agent: "GitHub Repos",
        strip: &["github", "repo ", "repos ", "repository"],
    },
    // IP Geolocation — requires IPAddress disclosure
    IntentRule {
        keywords: &["geolocate", "ip address", "ip location"],
        starts_with: &["ip "],
        action: "schema:FindAction",
        agent: "IP Geolocation",
        strip: &["geolocate", "ip address", "ip location", "ip "],
    },
    // Geocoding / place finding
    IntentRule {
        keywords: &["where is", "locate", "geocode", "coordinates of"],
        starts_with: &[],
        action: "schema:FindAction",
        agent: "Nominatim Geocoding",
        strip: &["where is", "locate", "geocode", "coordinates of"],
    },
    // ── Tier 2: Broader domain agents ──
    // Book search
    IntentRule {
        keywords: &["book ", "books by", "isbn", "novel "],
        starts_with: &[],
        action: "schema:SearchAction",
        agent: "Open Library Books",
        strip: &["books by", "book ", "novel "],
    },
    // Hacker News
    IntentRule {
        keywords: &["hacker news", "hackernews", "tech news"],
        starts_with: &["hn "],
        action: "schema:SearchAction",
        agent: "Hacker News",
        strip: &["hacker news", "hackernews", "tech news", "hn "],
    },
    // Wikipedia / articles
    IntentRule {
        keywords: &["wikipedia", "wiki", "article about", "tell me about"],
        starts_with: &[],
        action: "schema:SearchAction",
        agent: "Wikipedia Knowledge",
        strip: &["wikipedia", "wiki", "article about", "tell me about"],
    },
    // ── Catch-all search — last before AI fallback ──
    IntentRule {
        keywords: &["search", "look up"],
        starts_with: &["what is", "who is"],
        action: "schema:SearchAction",
        agent: "DuckDuckGo Search",
        strip: &["search", "look up"],
    },
];

/// Detect intent from a user prompt.
///
/// Returns `(action_type, preferred_agent_name, cleaned_query)`.
/// Falls back to `("schema:AskAction", "On-Device AI", prompt)` if no rule matches.
pub fn detect_intent(prompt: &str) -> (&'static str, &'static str, String) {
    let lower = prompt.to_lowercase();

    // Special case: currency combos like "100 USD EUR" without explicit "convert"
    if is_currency_combo(&lower) {
        let q = clean_query(prompt, &["convert", "exchange rate", "currency"]);
        return ("schema:TradeAction", "Frankfurter Exchange", q);
    }

    for rule in RULES {
        let matched = rule.keywords.iter().any(|kw| lower.contains(kw))
            || rule
                .starts_with
                .iter()
                .any(|prefix| lower.starts_with(prefix));

        if matched {
            let q = clean_query(prompt, rule.strip);
            return (rule.action, rule.agent, q);
        }
    }

    // Fallback: on-device AI
    ("schema:AskAction", "On-Device AI", prompt.to_string())
}

/// Check for implicit currency queries like "USD EUR" or "100 USD to GBP".
fn is_currency_combo(lower: &str) -> bool {
    let has_usd = lower.contains("usd");
    let has_eur = lower.contains("eur");
    let has_gbp = lower.contains("gbp");
    (has_usd && (has_eur || has_gbp)) || (has_eur && has_gbp)
}

/// Strip words from the prompt and clean up whitespace.
fn clean_query(prompt: &str, strip: &[&str]) -> String {
    let mut q = prompt.to_string();
    for word in strip {
        q = q.replace(word, "");
    }
    let q = q.trim().to_string();
    if q.is_empty() {
        prompt.to_string()
    } else {
        q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_wiki() {
        let (action, agent, _) = detect_intent("wikipedia Rust language");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Wikipedia Knowledge");
    }

    #[test]
    fn detect_search() {
        let (action, agent, _) = detect_intent("search for cats");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "DuckDuckGo Search");
    }

    #[test]
    fn detect_ai_fallback() {
        let (action, agent, query) = detect_intent("explain quantum computing");
        assert_eq!(action, "schema:AskAction");
        assert_eq!(agent, "On-Device AI");
        assert_eq!(query, "explain quantum computing");
    }

    #[test]
    fn detect_weather() {
        let (action, agent, _) = detect_intent("weather 48.85,2.35");
        assert_eq!(action, "schema:CheckAction");
        assert_eq!(agent, "Open-Meteo Weather");
    }

    #[test]
    fn detect_currency_explicit() {
        let (action, agent, _) = detect_intent("convert 100 USD EUR");
        assert_eq!(action, "schema:TradeAction");
        assert_eq!(agent, "Frankfurter Exchange");
    }

    #[test]
    fn detect_currency_implicit() {
        let (action, agent, _) = detect_intent("100 USD to EUR");
        assert_eq!(action, "schema:TradeAction");
        assert_eq!(agent, "Frankfurter Exchange");
    }

    #[test]
    fn detect_geocode() {
        let (action, agent, _) = detect_intent("where is Paris");
        assert_eq!(action, "schema:FindAction");
        assert_eq!(agent, "Nominatim Geocoding");
    }

    #[test]
    fn detect_books() {
        let (action, agent, _) = detect_intent("book about rust programming");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Open Library Books");
    }

    #[test]
    fn detect_hackernews() {
        let (action, agent, _) = detect_intent("hacker news rust");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Hacker News");
    }

    #[test]
    fn detect_hn_prefix() {
        let (action, agent, _) = detect_intent("hn rust");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Hacker News");
    }

    #[test]
    fn detect_tell_me_about() {
        let (action, agent, query) = detect_intent("tell me about photosynthesis");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Wikipedia Knowledge");
        assert!(query.contains("photosynthesis"));
    }

    #[test]
    fn detect_what_is() {
        let (action, _, _) = detect_intent("what is Rust");
        assert_eq!(action, "schema:SearchAction");
    }

    // ── New agent intent tests ──

    #[test]
    fn detect_dictionary_define() {
        let (action, agent, query) = detect_intent("define ephemeral");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Free Dictionary");
        assert!(query.contains("ephemeral"));
    }

    #[test]
    fn detect_dictionary_meaning() {
        let (action, agent, _) = detect_intent("meaning of protocol");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Free Dictionary");
    }

    #[test]
    fn detect_country() {
        let (action, agent, _) = detect_intent("country France");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "REST Countries");
    }

    #[test]
    fn detect_capital_of() {
        let (action, agent, _) = detect_intent("capital of Germany");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "REST Countries");
    }

    #[test]
    fn detect_arxiv() {
        let (action, agent, _) = detect_intent("arxiv attention mechanisms");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "arXiv Papers");
    }

    #[test]
    fn detect_research_paper() {
        let (action, agent, _) = detect_intent("paper on zero-knowledge proofs");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "arXiv Papers");
    }

    #[test]
    fn detect_github() {
        let (action, agent, _) = detect_intent("github rust web framework");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "GitHub Repos");
    }

    #[test]
    fn detect_repo() {
        let (action, agent, _) = detect_intent("repo actix-web");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "GitHub Repos");
    }

    #[test]
    fn detect_ip_geolocation() {
        let (action, agent, _) = detect_intent("ip address 8.8.8.8");
        assert_eq!(action, "schema:FindAction");
        assert_eq!(agent, "IP Geolocation");
    }

    #[test]
    fn detect_ip_prefix() {
        let (action, agent, _) = detect_intent("ip 1.1.1.1");
        assert_eq!(action, "schema:FindAction");
        assert_eq!(agent, "IP Geolocation");
    }

    #[test]
    fn detect_url_direct() {
        let (action, agent, _) = detect_intent("https://example.com");
        assert_eq!(action, "schema:ReadAction");
        assert_eq!(agent, "Web Page Reader");
    }

    #[test]
    fn detect_read_page() {
        let (action, agent, _) = detect_intent("read page https://rust-lang.org");
        assert_eq!(action, "schema:ReadAction");
        assert_eq!(agent, "Web Page Reader");
    }

    // ── Edge-input robustness ──

    #[test]
    fn detect_intent_empty_string_falls_back_to_ai() {
        // An empty address bar should never panic and should route to the AI fallback.
        let (action, agent, query) = detect_intent("");
        assert_eq!(action, "schema:AskAction");
        assert_eq!(agent, "On-Device AI");
        assert_eq!(query, "", "clean_query of empty prompt should be empty");
    }

    #[test]
    fn detect_intent_whitespace_only_falls_back_to_ai() {
        // Whitespace-only input has no matching keywords — must not panic.
        let (action, _, _) = detect_intent("   ");
        assert_eq!(action, "schema:AskAction");
    }

    #[test]
    fn detect_intent_unicode_prompt_falls_back_to_ai() {
        // CJK characters and emoji contain no English keywords — safe AI fallback.
        let (action, agent, _) = detect_intent("中文搜索 🦀");
        assert_eq!(action, "schema:AskAction");
        assert_eq!(agent, "On-Device AI");
    }

    #[test]
    fn detect_intent_numbers_only_falls_back_to_ai() {
        // Pure numeric input with no currency codes should not match any rule.
        let (action, _, _) = detect_intent("42 100 3.14");
        assert_eq!(action, "schema:AskAction");
    }

    #[test]
    fn detect_intent_keyword_case_insensitive() {
        // The lowercase comparison must make "WEATHER" behave identically to "weather".
        let (action_lower, agent_lower, _) = detect_intent("weather London");
        let (action_upper, agent_upper, _) = detect_intent("WEATHER London");
        assert_eq!(action_lower, action_upper);
        assert_eq!(agent_lower, agent_upper);
    }
}

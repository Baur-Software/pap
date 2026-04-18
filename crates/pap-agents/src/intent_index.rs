//! BM25 semantic intent classifier — level 2 of the 3-level intent routing chain.
//!
//! ```text
//! 1. Keyword rules (papillon-shared)          ~0µs   — URL detection
//! 2. BM25 semantic index (this module)       ~50µs   — schema.org action classification
//! 3. On-Device / federation NLU             ~100ms  — open-ended prompts
//! ```
//!
//! The index is built from the agent catalog. Each agent's descriptor
//! (name + provider + description + llm_instructions + types) forms a BM25 document.
//! Scores are summed per `schema:` action group; the winning group drives routing.
//!
//! Output is always a `schema:` action type — never free text, no injection surface.

use std::collections::HashMap;

use crate::DynamicAgentDef;

const K1: f32 = 1.5;
const B: f32 = 0.75;

struct AgentDescriptor {
    name: String,
    action: String,
    tokens: Vec<String>,
    len: usize,
}

/// BM25 index over the agent catalog.
pub struct IntentIndex {
    docs: Vec<AgentDescriptor>,
    /// Per-term inverse document frequency (pre-computed).
    idf: HashMap<String, f32>,
    avg_dl: f32,
}

/// Result of a successful BM25 classification.
pub struct IntentMatch {
    /// Schema.org action type, e.g. `"schema:SearchAction"`.
    pub action: String,
    /// Preferred local catalog agent when a confident local match exists.
    /// `None` means the action type is known but no specific local agent
    /// scored above a meaningful threshold — hand off to federation discovery.
    pub agent_name: Option<String>,
    /// Prompt with stop-words stripped (lowercase, whitespace-normalised).
    pub cleaned_query: String,
    /// Fraction of total BM25 score mass captured by the winning action group.
    /// Range 0.0–1.0; caller gates on a threshold (typically 0.25).
    pub confidence: f32,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn build_descriptor(agent: &DynamicAgentDef) -> String {
    let cap = agent.llm_instructions.len().min(200);
    let instructions = &agent.llm_instructions[..cap];
    let object_types = agent
        .object_types
        .iter()
        .map(|t| t.strip_prefix("schema:").unwrap_or(t))
        .collect::<Vec<_>>()
        .join(" ");
    let returns = agent
        .returns
        .iter()
        .map(|t| t.strip_prefix("schema:").unwrap_or(t))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} {} {} {} {} {}",
        agent.name, agent.provider, agent.description, instructions, object_types, returns
    )
}

/// Tokenize text: lowercase, split on non-alphanumeric, filter tokens < 2 chars.
fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(str::to_owned)
        .collect()
}

// ── IntentIndex ───────────────────────────────────────────────────────────────

impl IntentIndex {
    /// Build a BM25 index from a slice of agent definitions.
    /// Zero new dependencies — pure Rust.
    pub fn new(agents: &[DynamicAgentDef]) -> Self {
        let docs: Vec<AgentDescriptor> = agents
            .iter()
            .map(|a| {
                let tokens = tokenize(&build_descriptor(a));
                let len = tokens.len();
                AgentDescriptor {
                    name: a.name.clone(),
                    action: a.action.clone(),
                    tokens,
                    len,
                }
            })
            .collect();

        let n = docs.len();
        let avg_dl = if n == 0 {
            1.0
        } else {
            docs.iter().map(|d| d.len as f32).sum::<f32>() / n as f32
        };

        // Document frequency: count distinct docs that contain each term.
        let mut df: HashMap<String, usize> = HashMap::new();
        for doc in &docs {
            let unique: std::collections::HashSet<&str> =
                doc.tokens.iter().map(String::as_str).collect();
            for term in unique {
                *df.entry(term.to_owned()).or_insert(0) += 1;
            }
        }

        // IDF: ln((N - df + 0.5) / (df + 0.5) + 1), clamped to 0.
        let idf: HashMap<String, f32> = df
            .into_iter()
            .map(|(term, df_t)| {
                let score = ((n as f32 - df_t as f32 + 0.5) / (df_t as f32 + 0.5) + 1.0).ln();
                (term, score.max(0.0))
            })
            .collect();

        Self { docs, idf, avg_dl }
    }

    /// Classify a user prompt.
    ///
    /// Returns `Some(IntentMatch)` when `confidence >= threshold`, `None` otherwise.
    /// Caller falls through to on-device/federation NLU on `None`.
    pub fn classify(&self, prompt: &str, threshold: f32) -> Option<IntentMatch> {
        if self.docs.is_empty() {
            return None;
        }

        let query_tokens = tokenize(prompt);
        if query_tokens.is_empty() {
            return None;
        }

        let cleaned_query = query_tokens.join(" ");

        // BM25 score for each document.
        let scores: Vec<f32> = self
            .docs
            .iter()
            .map(|doc| {
                let dl = doc.len as f32;
                let length_norm = K1 * (1.0 - B + B * dl / self.avg_dl);

                // Term frequency map for this document.
                let tf_map: HashMap<&str, usize> =
                    doc.tokens.iter().fold(HashMap::new(), |mut m, t| {
                        *m.entry(t.as_str()).or_insert(0) += 1;
                        m
                    });

                query_tokens
                    .iter()
                    .map(|term| {
                        let idf = self.idf.get(term.as_str()).copied().unwrap_or(0.0);
                        if idf <= 0.0 {
                            return 0.0;
                        }
                        let tf = *tf_map.get(term.as_str()).unwrap_or(&0) as f32;
                        idf * (tf * (K1 + 1.0)) / (tf + length_norm)
                    })
                    .sum()
            })
            .collect();

        // Aggregate scores by action group; track best individual agent per group.
        let mut action_total: HashMap<&str, f32> = HashMap::new();
        let mut action_best: HashMap<&str, (&str, f32)> = HashMap::new();

        for (i, &score) in scores.iter().enumerate() {
            let action = self.docs[i].action.as_str();
            let name = self.docs[i].name.as_str();
            *action_total.entry(action).or_insert(0.0) += score;
            let entry = action_best.entry(action).or_insert((name, score));
            if score > entry.1 {
                *entry = (name, score);
            }
        }

        // AskAction is Level 3's territory (on-device AI / federation NLU).
        // BM25 never routes there — callers fall through to Level 3 themselves.
        action_total.remove("schema:AskAction");
        action_best.remove("schema:AskAction");

        let total: f32 = action_total.values().sum();
        if total <= 0.0 {
            return None;
        }

        // Winning action group.
        let (&best_action, &best_group_score) = action_total
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))?;

        let confidence = best_group_score / total;

        if confidence < threshold {
            return None;
        }

        let (best_agent_name, agent_score) = action_best[best_action];

        // Return a local agent hint only when it has a non-trivial individual score.
        // Agents with near-zero scores indicate the action group won on aggregate
        // rather than because any single agent is a confident match.
        let agent_name = if agent_score > 0.05 {
            Some(best_agent_name.to_owned())
        } else {
            None
        };

        Some(IntentMatch {
            action: best_action.to_owned(),
            agent_name,
            cleaned_query,
            confidence,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::{DynamicAgentSource, HttpEndpointConfig, HttpMethod};

    fn make_agent(
        name: &str,
        provider: &str,
        description: &str,
        action: &str,
        object_types: &[&str],
        returns: &[&str],
        llm_instructions: &str,
    ) -> DynamicAgentDef {
        DynamicAgentDef {
            agent_did: None,
            schema_version: 1,
            version: "0.1.0".into(),
            name: name.into(),
            provider: provider.into(),
            description: description.into(),
            action: action.into(),
            object_types: object_types.iter().map(|s| s.to_string()).collect(),
            requires_disclosure: vec![],
            returns: returns.iter().map(|s| s.to_string()).collect(),
            endpoint: Some(HttpEndpointConfig {
                url_template: format!("https://example.com/api/{}", name.to_lowercase().replace(' ', "-")),
                method: HttpMethod::Get,
                headers: Default::default(),
                body_template: None,
                response_jsonpath: "$".into(),
                response_schema_type: returns.first().copied().unwrap_or("schema:Thing").into(),
                response_mapping: Default::default(),
                timeout_secs: 5,
            }),
            llm_instructions: llm_instructions.into(),
            subagents: vec![],
            source: DynamicAgentSource::Catalog,
            operator_key_seed: None,
            published_to: vec![],
            catalog_path: None,
            configurable_properties: vec![],
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    /// Build a representative 10-agent catalog that covers the test scenarios.
    fn test_catalog() -> Vec<DynamicAgentDef> {
        vec![
            make_agent(
                "Open-Meteo Weather",
                "Open-Meteo",
                "Real-time weather forecast and temperature data for any location worldwide.",
                "schema:CheckAction",
                &["schema:Place"],
                &["schema:WeatherForecast"],
                "You are a weather assistant. Provide current conditions, temperature, humidity, \
                 wind speed, and forecast. User asks for weather, temperature, climate, forecast.",
            ),
            make_agent(
                "Weather Archive",
                "Meteostat",
                "Historical climate statistics and weather archive data.",
                "schema:CheckAction",
                &["schema:Place"],
                &["schema:WeatherForecast"],
                "You are a historical weather data assistant. Provide archived temperature and \
                 climate records for locations and dates.",
            ),
            make_agent(
                "Etsy Shop Search",
                "Etsy",
                "Search handmade, vintage, and craft items on Etsy marketplace.",
                "schema:SearchAction",
                &["schema:Product"],
                &["schema:Product"],
                "You are a handmade goods discovery assistant. Describe Etsy listings: \
                 product name, maker, materials, price, and craftsmanship details. \
                 Users search for handmade candles, jewelry, art, crafts.",
            ),
            make_agent(
                "DuckDuckGo Search",
                "DuckDuckGo",
                "General web search with zero tracking.",
                "schema:SearchAction",
                &["schema:WebPage"],
                &["schema:SearchResult"],
                "You are a privacy-first web search assistant. Return relevant results \
                 for any query. General search, web lookup, find information.",
            ),
            make_agent(
                "Bundlephobia Bundle Size",
                "Bundlephobia",
                "Check the minified and gzipped bundle size of any npm package.",
                "schema:FindAction",
                &["schema:SoftwareApplication"],
                &["schema:SoftwareApplication"],
                "You are a JavaScript performance assistant. Provide npm package bundle size, \
                 minified, gzipped, tree-shaking support. Users ask for package size, \
                 npm bundle, react bundle, webpack size.",
            ),
            make_agent(
                "Nominatim Geocoding",
                "OpenStreetMap",
                "Geocode addresses and find coordinates for locations.",
                "schema:FindAction",
                &["schema:Place"],
                &["schema:GeoCoordinates"],
                "You are a geocoding assistant. Convert addresses to coordinates. \
                 Find latitude longitude for any location or address.",
            ),
            make_agent(
                "Hotel Booking Lookup",
                "Hotels.com",
                "Search and reserve hotel rooms for any destination and date range.",
                "schema:ReserveAction",
                &["schema:LodgingBusiness"],
                &["schema:LodgingReservation"],
                "You are a hotel booking assistant. Help users find and book hotel rooms. \
                 Users ask to book, reserve, find hotel, lodging in a city.",
            ),
            make_agent(
                "Wikipedia Summary",
                "Wikimedia",
                "Fetch article summaries from Wikipedia for any topic.",
                "schema:SearchAction",
                &["schema:Article"],
                &["schema:Article"],
                "You are a knowledge lookup assistant. Provide Wikipedia article summaries \
                 for topics, concepts, people, and places.",
            ),
            make_agent(
                "Semantic Scholar Papers",
                "Semantic Scholar",
                "Search academic research papers and scholarly articles.",
                "schema:SearchAction",
                &["schema:ScholarlyArticle"],
                &["schema:ScholarlyArticle"],
                "You are a research paper discovery assistant. Find scientific papers, \
                 academic articles, research on any topic.",
            ),
            make_agent(
                "On-Device AI",
                "Papillon",
                "Local language model for open-ended questions and synthesis.",
                "schema:AskAction",
                &["schema:Question"],
                &["schema:Answer"],
                "You are a local AI assistant. Answer open-ended questions, explain concepts, \
                 summarise content, and help with any task requiring language understanding.",
            ),
        ]
    }

    #[test]
    fn weather_in_tokyo_routes_to_check_action() {
        let idx = IntentIndex::new(&test_catalog());
        let m = idx.classify("weather in Tokyo", 0.25).expect("should match");
        assert_eq!(m.action, "schema:CheckAction");
        assert_eq!(m.agent_name.as_deref(), Some("Open-Meteo Weather"));
    }

    #[test]
    fn temperature_tomorrow_routes_to_check_action() {
        let idx = IntentIndex::new(&test_catalog());
        let m = idx
            .classify("what's the temperature tomorrow", 0.25)
            .expect("should match — synonym, no keyword rule");
        assert_eq!(m.action, "schema:CheckAction");
    }

    #[test]
    fn handmade_candles_routes_to_etsy() {
        let idx = IntentIndex::new(&test_catalog());
        let m = idx
            .classify("find me handmade candles", 0.25)
            .expect("should match — no keyword rule for Etsy");
        assert_eq!(m.action, "schema:SearchAction");
        assert_eq!(m.agent_name.as_deref(), Some("Etsy Shop Search"));
    }

    #[test]
    fn npm_bundle_size_routes_to_bundlephobia() {
        let idx = IntentIndex::new(&test_catalog());
        let m = idx
            .classify("npm package size for react", 0.25)
            .expect("should match — no keyword rule coverage");
        assert_eq!(m.action, "schema:FindAction");
        assert_eq!(m.agent_name.as_deref(), Some("Bundlephobia Bundle Size"));
    }

    #[test]
    fn book_hotel_paris_routes_to_reserve_action() {
        let idx = IntentIndex::new(&test_catalog());
        let m = idx
            .classify("book a hotel in Paris", 0.25)
            .expect("should match");
        assert_eq!(m.action, "schema:ReserveAction");
    }

    #[test]
    fn explain_quantum_entanglement_returns_none() {
        let idx = IntentIndex::new(&test_catalog());
        // Open-ended educational query — no strong catalog match → falls through to AI
        let result = idx.classify("explain quantum entanglement", 0.25);
        assert!(
            result.is_none(),
            "expected None (below threshold), got Some({:?})",
            result.as_ref().map(|m| &m.action)
        );
    }

    #[test]
    fn action_grouping_selects_best_agent_within_group() {
        let idx = IntentIndex::new(&test_catalog());
        // Both Etsy and DuckDuckGo are SearchAction; "handmade candles" should score Etsy higher
        let m = idx
            .classify("find handmade candles jewelry", 0.25)
            .expect("should match");
        assert_eq!(m.action, "schema:SearchAction");
        assert_eq!(
            m.agent_name.as_deref(),
            Some("Etsy Shop Search"),
            "Etsy should win over DuckDuckGo for a handmade-goods query"
        );
    }

    #[test]
    fn threshold_gate_returns_none_for_low_confidence() {
        let idx = IntentIndex::new(&test_catalog());
        // Use a very high threshold to force None even for a decent match
        let result = idx.classify("weather in Tokyo", 0.99);
        assert!(
            result.is_none(),
            "threshold 0.99 should reject even good matches"
        );
    }

    #[test]
    fn empty_catalog_returns_none() {
        let idx = IntentIndex::new(&[]);
        assert!(idx.classify("weather", 0.25).is_none());
    }

    #[test]
    fn empty_prompt_returns_none() {
        let idx = IntentIndex::new(&test_catalog());
        assert!(idx.classify("", 0.25).is_none());
    }

    #[test]
    fn cleaned_query_is_lowercase_whitespace_normalised() {
        let idx = IntentIndex::new(&test_catalog());
        let upper = idx.classify("WEATHER IN TOKYO", 0.25);
        let lower = idx.classify("weather in tokyo", 0.25);
        assert!(upper.is_some(), "uppercase should match");
        assert!(lower.is_some(), "lowercase should match");
        assert_eq!(
            upper.unwrap().cleaned_query,
            lower.unwrap().cleaned_query,
            "cleaned_query must be case-insensitive"
        );
    }
}

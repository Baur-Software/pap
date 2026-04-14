//! Personal context aggregation for the PAP orchestrator.
//!
//! [`PersonalContext`] synthesizes a compact JSON-LD summary of the user's
//! interaction history, agent preferences, and declared traits.  This summary
//! is injected as a system-prompt preamble into every orchestrator LLM call,
//! turning a stateless router into a memex-backed personal agent.
//!
//! **Privacy invariant**: all data stays on the principal's device.
//! No fields are sent to external services — the preamble is only consumed by
//! the configured local or self-hosted inference substrate.

#[cfg(feature = "native")]
use crate::db::DatabaseOps;
use serde::{Deserialize, Serialize};

// ── Lightweight summary types ─────────────────────────────────────────────────

/// A distilled view of one completed agent interaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EpisodeSummary {
    pub agent_name: String,
    pub action_type: String,
    /// "success", "failure", or "rejected"
    pub outcome: String,
    /// The original query string, if recorded.
    pub query: Option<String>,
    /// ISO 8601 timestamp.
    pub recorded_at: String,
}

/// Aggregated performance snapshot for a single agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentSummary {
    pub agent_name: String,
    /// Fraction of successful episodes (0.0 – 1.0).
    pub success_rate: f64,
    pub episode_count: i64,
    pub last_used: String,
}

// ── PersonalContext ────────────────────────────────────────────────────────────

/// Aggregated personal context injected into orchestrator LLM system prompts.
///
/// Built from three existing data sources:
/// - Recent episodes from the episode store (interaction history).
/// - Top agent profiles (preference and performance signals).
/// - The user's optional TraitBeacon Schema.org `Person` document (declared traits).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersonalContext {
    /// Up to 5 most recent completed interactions.
    pub recent_episodes: Vec<EpisodeSummary>,
    /// Top 3 agents by total episode count.
    pub top_agents: Vec<AgentSummary>,
    /// The user's advertised Schema.org Person document, if set.
    pub user_traits: Option<serde_json::Value>,
}

impl PersonalContext {
    /// Build a `PersonalContext` from the live database and an optional trait profile.
    ///
    /// Queries:
    /// - [`DatabaseOps::list_episodes`] — last 5 episodes (newest first).
    /// - [`DatabaseOps::list_agent_profiles`] — sorted by `episode_count DESC`, top 3.
    ///
    /// Returns a context that may be empty if neither episodes nor agent profiles
    /// are present; check [`PersonalContext::is_empty`] before injecting.
    #[cfg(feature = "native")]
    pub fn from_db(db: &dyn DatabaseOps, trait_profile: Option<serde_json::Value>) -> Self {
        let recent_episodes = db
            .list_episodes(None, None, 5, None)
            .unwrap_or_default()
            .into_iter()
            .map(|ep| EpisodeSummary {
                agent_name: ep.agent_name,
                action_type: ep.action_type,
                outcome: ep.outcome,
                query: ep.query,
                recorded_at: ep.recorded_at,
            })
            .collect();

        let mut agent_profiles = db.list_agent_profiles().unwrap_or_default();
        // Sort by episode count descending; ties broken by success rate then name.
        agent_profiles.sort_by(|a, b| {
            b.episode_count
                .cmp(&a.episode_count)
                .then(
                    b.success_rate
                        .partial_cmp(&a.success_rate)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then(a.agent_name.cmp(&b.agent_name))
        });
        let top_agents = agent_profiles
            .into_iter()
            .take(3)
            .map(|p| AgentSummary {
                agent_name: p.agent_name,
                success_rate: p.success_rate,
                episode_count: p.episode_count,
                last_used: p.last_used,
            })
            .collect();

        // Treat an empty JSON object `{}` as no traits set.
        let user_traits = trait_profile
            .filter(|v| !v.is_null() && v != &serde_json::Value::Object(serde_json::Map::new()));

        Self {
            recent_episodes,
            top_agents,
            user_traits,
        }
    }

    /// Returns `true` when there is no meaningful context to inject.
    pub fn is_empty(&self) -> bool {
        self.recent_episodes.is_empty() && self.top_agents.is_empty() && self.user_traits.is_none()
    }

    /// Serialize to a compact system-prompt preamble block.
    ///
    /// Returns an empty string when [`PersonalContext::is_empty`] is `true` so
    /// callers can do `if preamble.is_empty() { … }` without special-casing.
    ///
    /// The block is delimited by `[PAP PERSONAL CONTEXT]` / `[END PAP CONTEXT]`
    /// so LLMs can treat it as metadata separate from the task instruction.
    pub fn to_system_preamble(&self) -> String {
        if self.is_empty() {
            return String::new();
        }

        let mut obj = serde_json::Map::new();
        obj.insert(
            "@context".into(),
            serde_json::Value::String("https://schema.org".into()),
        );
        obj.insert(
            "@type".into(),
            serde_json::Value::String("pap:MemexSummary".into()),
        );

        if !self.recent_episodes.is_empty() {
            let episodes: Vec<serde_json::Value> = self
                .recent_episodes
                .iter()
                .map(|ep| {
                    let mut m = serde_json::Map::new();
                    m.insert("agentName".into(), ep.agent_name.as_str().into());
                    m.insert("action".into(), ep.action_type.as_str().into());
                    m.insert("outcome".into(), ep.outcome.as_str().into());
                    if let Some(q) = &ep.query {
                        m.insert("query".into(), q.as_str().into());
                    }
                    serde_json::Value::Object(m)
                })
                .collect();
            obj.insert("recentEpisodes".into(), serde_json::Value::Array(episodes));
        }

        if !self.top_agents.is_empty() {
            let agents: Vec<serde_json::Value> = self
                .top_agents
                .iter()
                .map(|a| {
                    let mut m = serde_json::Map::new();
                    m.insert("name".into(), a.agent_name.as_str().into());
                    m.insert(
                        "successRate".into(),
                        serde_json::Value::Number(
                            serde_json::Number::from_f64((a.success_rate * 100.0).round() / 100.0)
                                .unwrap_or(serde_json::Number::from(0)),
                        ),
                    );
                    m.insert(
                        "episodes".into(),
                        serde_json::Value::Number(a.episode_count.into()),
                    );
                    serde_json::Value::Object(m)
                })
                .collect();
            obj.insert("topAgents".into(), serde_json::Value::Array(agents));
        }

        if let Some(traits) = &self.user_traits {
            obj.insert("userTraits".into(), traits.clone());
        }

        let json_body =
            serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_else(|_| "{}".into());

        format!("[PAP PERSONAL CONTEXT]\n{json_body}\n[END PAP CONTEXT]")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "native")]
mod tests {
    use super::*;
    use crate::db::{native::NativeDatabase, DatabaseOps, Episode};

    fn make_episode(
        id: &str,
        agent_name: &str,
        action_type: &str,
        outcome: &str,
        recorded_at: &str,
    ) -> Episode {
        Episode {
            id: id.to_string(),
            receipt_session_id: "sess-1".to_string(),
            scenario_id: "sc-1".to_string(),
            action_type: action_type.to_string(),
            agent_did_hash: "hash-abc".to_string(),
            agent_name: agent_name.to_string(),
            outcome: outcome.to_string(),
            outcome_detail: None,
            scope_exercised: "[]".to_string(),
            disclosure_refs: "[]".to_string(),
            duration_ms: 100,
            decay_state: "Active".to_string(),
            intent_summary: None,
            result_json: None,
            query: Some(format!("query for {id}")),
            recorded_at: recorded_at.to_string(),
        }
    }

    fn make_profile(
        hash: &str,
        name: &str,
        success_rate: f64,
        episode_count: i64,
    ) -> crate::db::AgentProfile {
        crate::db::AgentProfile {
            agent_did_hash: hash.to_string(),
            agent_name: name.to_string(),
            success_rate,
            avg_quality: 0.8,
            avg_duration_ms: 200.0,
            episode_count,
            minimal_disclosure_refs: "[]".to_string(),
            last_used: "2026-04-01T00:00:00Z".to_string(),
            co_sign_refusals: 0,
        }
    }

    #[test]
    fn from_db_empty() {
        let db = NativeDatabase::open_memory().expect("db");
        let ctx = PersonalContext::from_db(&db, None);
        assert!(ctx.is_empty());
        assert_eq!(ctx.to_system_preamble(), "");
    }

    #[test]
    fn from_db_five_episode_cap() {
        let db = NativeDatabase::open_memory().expect("db");
        for i in 0..7_u8 {
            db.insert_episode(&make_episode(
                &format!("e{i}"),
                "TestAgent",
                "schema:SearchAction",
                "success",
                &format!("2026-04-0{i}T10:00:00Z", i = i + 1),
            ))
            .unwrap();
        }
        let ctx = PersonalContext::from_db(&db, None);
        assert_eq!(ctx.recent_episodes.len(), 5, "should cap at 5 episodes");
    }

    #[test]
    fn preamble_valid_json_ld() {
        let db = NativeDatabase::open_memory().expect("db");
        db.insert_episode(&make_episode(
            "e1",
            "Web Search",
            "schema:SearchAction",
            "success",
            "2026-04-01T10:00:00Z",
        ))
        .unwrap();
        let ctx = PersonalContext::from_db(&db, None);
        let preamble = ctx.to_system_preamble();

        assert!(preamble.starts_with("[PAP PERSONAL CONTEXT]"));
        assert!(preamble.ends_with("[END PAP CONTEXT]"));

        // Extract and parse JSON body between the sentinel lines.
        let lines: Vec<&str> = preamble.lines().collect();
        assert!(lines.len() >= 3);
        let json_body = lines[1];
        let parsed: serde_json::Value =
            serde_json::from_str(json_body).expect("preamble body must be valid JSON");
        assert_eq!(parsed["@type"], "pap:MemexSummary");
        assert!(parsed["recentEpisodes"].is_array());
    }

    #[test]
    fn top_agents_sorted_by_count() {
        let db = NativeDatabase::open_memory().expect("db");
        db.upsert_agent_profile(&make_profile("h-a", "Agent-A", 0.9, 10))
            .unwrap();
        db.upsert_agent_profile(&make_profile("h-b", "Agent-B", 0.8, 30))
            .unwrap();
        db.upsert_agent_profile(&make_profile("h-c", "Agent-C", 0.7, 5))
            .unwrap();

        let ctx = PersonalContext::from_db(&db, None);
        assert_eq!(ctx.top_agents.len(), 3);
        assert_eq!(ctx.top_agents[0].agent_name, "Agent-B"); // 30 episodes
        assert_eq!(ctx.top_agents[1].agent_name, "Agent-A"); // 10 episodes
        assert_eq!(ctx.top_agents[2].agent_name, "Agent-C"); // 5 episodes
    }

    #[test]
    fn user_traits_appears_in_preamble() {
        let db = NativeDatabase::open_memory().expect("db");
        db.insert_episode(&make_episode(
            "e1",
            "Web Search",
            "schema:SearchAction",
            "success",
            "2026-04-01T10:00:00Z",
        ))
        .unwrap();
        let traits = serde_json::json!({
            "@type": "Person",
            "name": "Alice",
            "knowsAbout": ["rust", "privacy"]
        });
        let ctx = PersonalContext::from_db(&db, Some(traits.clone()));
        let preamble = ctx.to_system_preamble();

        let lines: Vec<&str> = preamble.lines().collect();
        let parsed: serde_json::Value = serde_json::from_str(lines[1]).expect("valid JSON");
        assert_eq!(parsed["userTraits"]["name"], "Alice");
    }

    #[test]
    fn empty_trait_object_excluded() {
        let db = NativeDatabase::open_memory().expect("db");
        db.insert_episode(&make_episode(
            "e1",
            "Web Search",
            "schema:SearchAction",
            "success",
            "2026-04-01T10:00:00Z",
        ))
        .unwrap();
        let ctx = PersonalContext::from_db(&db, Some(serde_json::json!({})));
        assert!(
            ctx.user_traits.is_none(),
            "empty object should not be included"
        );
    }
}

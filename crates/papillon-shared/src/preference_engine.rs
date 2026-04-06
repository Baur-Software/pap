//! Local preference-learning engine for the Papillon orchestrator.
//!
//! All data is stored in the principal's local SQLite database.
//! No rows from the `preferences` table are ever transmitted over the network.
//!
//! ## What it learns
//!
//! The engine accumulates signals from the principal's own interactions:
//! - Which agent was **selected** for a given (action_type, schema_type) pair
//! - Whether each session produced a **success** outcome
//! - Which disclosure property refs were **approved** vs **rejected**
//!
//! ## Scoring
//!
//! `preference_score()` returns a value in `[0.0, 1.0]`:
//! - 0.0: no preference data (cold start)
//! - >0.0 and <MIN_EPISODES threshold: keyword-preference level only
//! - >=MIN_EPISODES: full historical score combining success_rate and recency
//!
//! ## Privacy invariant
//!
//! The engine only calls `DatabaseOps` methods marked `#[cfg(feature = "native")]`.
//! No method here initiates a network request.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::{DatabaseOps, PreferenceSignal};

/// Minimum number of selections before the engine considers preference data
/// statistically meaningful enough to influence agent scoring.
const MIN_EPISODES: i64 = 3;

/// Number of days after which recency decay reduces a preference score to half.
/// At 2× this value the contribution is near zero.
const RECENCY_HALF_LIFE_DAYS: f64 = 90.0;

/// Engine that reads and writes preference signals from the local SQLite store.
///
/// Construct with a reference to the database that implements [`DatabaseOps`].
/// All methods are synchronous and non-blocking.
pub struct PreferenceEngine<'a> {
    db: &'a dyn DatabaseOps,
}

impl<'a> PreferenceEngine<'a> {
    /// Create a new `PreferenceEngine` backed by `db`.
    pub fn new(db: &'a dyn DatabaseOps) -> Self {
        Self { db }
    }

    /// Compute a preference score for `agent_did_hash` in the context of
    /// `(action_type, schema_type)`.  Returns `0.0` when no preference
    /// data exists or when the `DatabaseOps` call fails.
    ///
    /// Score components (once ≥ `MIN_EPISODES` selections exist):
    /// - **60%** success rate: `success_count / selection_count`
    /// - **40%** recency factor: exponential decay based on days since last use
    pub fn preference_score(
        &self,
        action_type: &str,
        schema_type: &str,
        agent_did_hash: &str,
    ) -> f64 {
        let signal = match self
            .db
            .get_preference(action_type, schema_type, agent_did_hash)
        {
            Ok(Some(s)) => s,
            _ => return 0.0,
        };

        if signal.selection_count < MIN_EPISODES {
            // Not enough data — return a small positive signal so the agent
            // is still visible but doesn't dominate keyword-matched agents.
            return 0.1 * (signal.selection_count as f64 / MIN_EPISODES as f64);
        }

        let success_rate = signal.success_count as f64 / signal.selection_count as f64;
        let recency = recency_factor(&signal.last_selected);

        0.6 * success_rate + 0.4 * recency
    }

    /// Returns `true` when preference data is meaningful enough to have
    /// influenced agent selection for this (action_type, schema_type) pair.
    pub fn is_preference_guided(&self, action_type: &str, schema_type: &str) -> bool {
        match self
            .db
            .list_preferences_for_schema(action_type, schema_type)
        {
            Ok(signals) => signals.iter().any(|s| s.selection_count >= MIN_EPISODES),
            Err(_) => false,
        }
    }

    /// Record that `agent_did_hash` was selected for `(action_type, schema_type)`.
    ///
    /// Increments `selection_count` and updates `last_selected`.  The row is
    /// created if it does not exist yet.  Errors are silently discarded — the
    /// preference store is advisory, never load-bearing.
    pub fn record_agent_selected(
        &self,
        action_type: &str,
        schema_type: &str,
        agent_did_hash: &str,
        agent_name: &str,
    ) {
        let now = Utc::now().to_rfc3339();
        let existing = self
            .db
            .get_preference(action_type, schema_type, agent_did_hash)
            .ok()
            .flatten();

        let signal = match existing {
            Some(prev) => PreferenceSignal {
                selection_count: prev.selection_count + 1,
                last_selected: now.clone(),
                updated_at: now,
                ..prev
            },
            None => PreferenceSignal {
                id: Uuid::new_v4().to_string(),
                action_type: action_type.to_string(),
                schema_type: schema_type.to_string(),
                agent_did_hash: agent_did_hash.to_string(),
                agent_name: agent_name.to_string(),
                selection_count: 1,
                success_count: 0,
                last_selected: now.clone(),
                approved_scope_refs: "[]".to_string(),
                rejected_scope_refs: "[]".to_string(),
                updated_at: now,
            },
        };

        let _ = self.db.upsert_preference(&signal);
    }

    /// Record the outcome of a session for `(action_type, schema_type, agent_did_hash)`.
    ///
    /// Increments `success_count` when `success` is `true`.  Silently discards
    /// errors — outcomes are advisory.
    pub fn record_outcome(
        &self,
        action_type: &str,
        schema_type: &str,
        agent_did_hash: &str,
        success: bool,
    ) {
        if !success {
            return; // Only success outcomes improve the score.
        }
        let now = Utc::now().to_rfc3339();
        let existing = self
            .db
            .get_preference(action_type, schema_type, agent_did_hash)
            .ok()
            .flatten();

        if let Some(prev) = existing {
            let signal = PreferenceSignal {
                success_count: prev.success_count + 1,
                updated_at: now,
                ..prev
            };
            let _ = self.db.upsert_preference(&signal);
        }
        // If no row exists yet, the outcome will be captured on the next selection.
    }

    /// Record that the principal approved `scope_refs` for `(action_type, schema_type)`.
    ///
    /// Merges the new refs into the existing `approved_scope_refs` JSON array
    /// (deduplicating).  Removes any from `rejected_scope_refs` that are now
    /// being approved.  Silently discards errors.
    pub fn record_scope_approved(
        &self,
        action_type: &str,
        schema_type: &str,
        agent_did_hash: &str,
        scope_refs: &[String],
    ) {
        let now = Utc::now().to_rfc3339();
        let existing = self
            .db
            .get_preference(action_type, schema_type, agent_did_hash)
            .ok()
            .flatten();

        let prev = match existing {
            Some(p) => p,
            None => return, // no row — nothing to update
        };

        let mut approved: Vec<String> =
            serde_json::from_str(&prev.approved_scope_refs).unwrap_or_default();
        let mut rejected: Vec<String> =
            serde_json::from_str(&prev.rejected_scope_refs).unwrap_or_default();

        for r in scope_refs {
            if !approved.contains(r) {
                approved.push(r.clone());
            }
            rejected.retain(|x| x != r);
        }

        let signal = PreferenceSignal {
            approved_scope_refs: serde_json::to_string(&approved).unwrap_or_else(|_| "[]".into()),
            rejected_scope_refs: serde_json::to_string(&rejected).unwrap_or_else(|_| "[]".into()),
            updated_at: now,
            ..prev
        };
        let _ = self.db.upsert_preference(&signal);
    }

    /// Record that the principal rejected `scope_refs` for `(action_type, schema_type)`.
    ///
    /// Merges the new refs into `rejected_scope_refs` and removes them from
    /// `approved_scope_refs`.  Silently discards errors.
    pub fn record_scope_rejected(
        &self,
        action_type: &str,
        schema_type: &str,
        agent_did_hash: &str,
        scope_refs: &[String],
    ) {
        let now = Utc::now().to_rfc3339();
        let existing = self
            .db
            .get_preference(action_type, schema_type, agent_did_hash)
            .ok()
            .flatten();

        let prev = match existing {
            Some(p) => p,
            None => return,
        };

        let mut approved: Vec<String> =
            serde_json::from_str(&prev.approved_scope_refs).unwrap_or_default();
        let mut rejected: Vec<String> =
            serde_json::from_str(&prev.rejected_scope_refs).unwrap_or_default();

        for r in scope_refs {
            if !rejected.contains(r) {
                rejected.push(r.clone());
            }
            approved.retain(|x| x != r);
        }

        let signal = PreferenceSignal {
            approved_scope_refs: serde_json::to_string(&approved).unwrap_or_else(|_| "[]".into()),
            rejected_scope_refs: serde_json::to_string(&rejected).unwrap_or_else(|_| "[]".into()),
            updated_at: now,
            ..prev
        };
        let _ = self.db.upsert_preference(&signal);
    }

    /// Return the intersection of approved scope refs across all agents for
    /// `(action_type, schema_type)` — the mandate properties the principal has
    /// consistently approved for this type of interaction.
    ///
    /// Returns an empty `Vec` when:
    /// - No preference signals exist
    /// - No agent has reached `MIN_EPISODES` selections
    /// - The intersection of approved refs is empty
    pub fn suggested_scopes(&self, action_type: &str, schema_type: &str) -> Vec<String> {
        let signals = match self
            .db
            .list_preferences_for_schema(action_type, schema_type)
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        // Only include agents with enough history.
        let qualified: Vec<_> = signals
            .iter()
            .filter(|s| s.selection_count >= MIN_EPISODES)
            .collect();

        if qualified.is_empty() {
            return Vec::new();
        }

        // Collect all approved ref lists.
        let all_approved: Vec<Vec<String>> = qualified
            .iter()
            .map(|s| {
                serde_json::from_str::<Vec<String>>(&s.approved_scope_refs).unwrap_or_default()
            })
            .filter(|v| !v.is_empty())
            .collect();

        if all_approved.is_empty() {
            return Vec::new();
        }

        // Compute intersection: refs approved across ALL qualified agents.
        let first = all_approved[0].clone();
        all_approved[1..].iter().fold(first, |acc, cur| {
            acc.into_iter().filter(|r| cur.contains(r)).collect()
        })
    }
}

/// Exponential recency decay.
///
/// Returns a value in `(0.0, 1.0]` based on how recently `last_selected` was.
/// Uses a half-life of `RECENCY_HALF_LIFE_DAYS`: a selection today scores 1.0;
/// one `RECENCY_HALF_LIFE_DAYS` days ago scores 0.5.
fn recency_factor(last_selected_rfc3339: &str) -> f64 {
    let last = DateTime::parse_from_rfc3339(last_selected_rfc3339)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let days_ago = (Utc::now() - last).num_days().max(0) as f64;
    // f(d) = 2^(-d / half_life)
    2.0_f64.powf(-days_ago / RECENCY_HALF_LIFE_DAYS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::native::NativeDatabase;
    use crate::db::DatabaseOps;

    fn test_db() -> NativeDatabase {
        NativeDatabase::open_memory().expect("in-memory db")
    }

    #[test]
    fn cold_start_returns_zero() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);
        let score = engine.preference_score("schema:SearchAction", "schema:SearchResult", "hash1");
        assert_eq!(score, 0.0);
    }

    #[test]
    fn below_min_episodes_returns_fractional() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);

        engine.record_agent_selected(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            "DuckDuckGo Search",
        );
        engine.record_agent_selected(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            "DuckDuckGo Search",
        );

        let score = engine.preference_score("schema:SearchAction", "schema:SearchResult", "hash1");
        // 2 selections < MIN_EPISODES (3), so score is small but positive
        assert!(score > 0.0 && score < 0.5);
    }

    #[test]
    fn at_min_episodes_with_perfect_success_scores_high() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);

        for _ in 0..3 {
            engine.record_agent_selected(
                "schema:SearchAction",
                "schema:SearchResult",
                "hash1",
                "DuckDuckGo Search",
            );
            engine.record_outcome("schema:SearchAction", "schema:SearchResult", "hash1", true);
        }

        let score = engine.preference_score("schema:SearchAction", "schema:SearchResult", "hash1");
        // Perfect success rate, recent use → score ≈ 0.6*1.0 + 0.4*1.0 = 1.0
        assert!(score > 0.9, "expected high score, got {score}");
    }

    #[test]
    fn zero_success_still_scores_by_recency() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);

        for _ in 0..3 {
            engine.record_agent_selected(
                "schema:SearchAction",
                "schema:SearchResult",
                "hash1",
                "DuckDuckGo Search",
            );
        }
        // No successes recorded
        let score = engine.preference_score("schema:SearchAction", "schema:SearchResult", "hash1");
        // 0 success_rate + recency ≈ 0.4 * 1.0 = 0.4
        assert!(score > 0.3 && score < 0.5, "expected ~0.4, got {score}");
    }

    #[test]
    fn is_preference_guided_false_below_min_episodes() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);
        engine.record_agent_selected(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            "Agent",
        );
        assert!(!engine.is_preference_guided("schema:SearchAction", "schema:SearchResult"));
    }

    #[test]
    fn is_preference_guided_true_at_threshold() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);
        for _ in 0..3 {
            engine.record_agent_selected(
                "schema:SearchAction",
                "schema:SearchResult",
                "hash1",
                "Agent",
            );
        }
        assert!(engine.is_preference_guided("schema:SearchAction", "schema:SearchResult"));
    }

    #[test]
    fn suggested_scopes_returns_intersection() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);

        // Build up MIN_EPISODES selections for hash1
        for _ in 0..3 {
            engine.record_agent_selected(
                "schema:SearchAction",
                "schema:SearchResult",
                "hash1",
                "Agent1",
            );
        }
        // Record approved scopes for hash1
        engine.record_scope_approved(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            &["schema:name".to_string(), "schema:email".to_string()],
        );

        let scopes = engine.suggested_scopes("schema:SearchAction", "schema:SearchResult");
        assert!(scopes.contains(&"schema:name".to_string()));
        assert!(scopes.contains(&"schema:email".to_string()));
    }

    #[test]
    fn suggested_scopes_empty_below_threshold() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);
        // Only 2 selections — below MIN_EPISODES
        for _ in 0..2 {
            engine.record_agent_selected(
                "schema:SearchAction",
                "schema:SearchResult",
                "hash1",
                "Agent1",
            );
        }
        engine.record_scope_approved(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            &["schema:name".to_string()],
        );

        let scopes = engine.suggested_scopes("schema:SearchAction", "schema:SearchResult");
        assert!(scopes.is_empty());
    }

    #[test]
    fn scope_approve_reject_roundtrip() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);

        for _ in 0..3 {
            engine.record_agent_selected(
                "schema:SearchAction",
                "schema:SearchResult",
                "hash1",
                "Agent",
            );
        }

        engine.record_scope_approved(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            &["schema:name".to_string(), "schema:email".to_string()],
        );
        engine.record_scope_rejected(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            &["schema:email".to_string()],
        );

        let sig = db
            .get_preference("schema:SearchAction", "schema:SearchResult", "hash1")
            .unwrap()
            .unwrap();
        let approved: Vec<String> = serde_json::from_str(&sig.approved_scope_refs).unwrap();
        let rejected: Vec<String> = serde_json::from_str(&sig.rejected_scope_refs).unwrap();
        assert!(approved.contains(&"schema:name".to_string()));
        assert!(!approved.contains(&"schema:email".to_string()));
        assert!(rejected.contains(&"schema:email".to_string()));
    }

    #[test]
    fn recency_factor_recent_is_near_one() {
        let now = Utc::now().to_rfc3339();
        let f = recency_factor(&now);
        assert!(f > 0.99, "recent use should score near 1.0, got {f}");
    }

    #[test]
    fn recency_factor_old_is_low() {
        // 180 days ago → 2^(-180/90) = 2^(-2) = 0.25
        let old = (Utc::now() - chrono::Duration::days(180)).to_rfc3339();
        let f = recency_factor(&old);
        assert!(
            (f - 0.25).abs() < 0.01,
            "180-day-old use should score ~0.25, got {f}"
        );
    }
}

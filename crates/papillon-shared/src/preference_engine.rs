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
//! ## Scoring — Memex(RL)-inspired confidence routing
//!
//! Inspired by [Memex(RL)](https://arxiv.org/abs/2603.04257): the aggregate
//! preference row is a *compact index summary* of past interactions. When that
//! summary is confident (low outcome variance, sufficient sample size), the
//! engine scores directly from it. When the aggregate is uncertain, the engine
//! **dereferences** to the full episode store and computes a recency-weighted
//! success rate from raw records — preserving decision quality without carrying
//! full interaction history in working context.
//!
//! ```text
//! confidence >= MIN_CONFIDENCE  →  score from aggregate (fast path)
//! confidence <  MIN_CONFIDENCE  →  deref to episodes  (full-fidelity path)
//!                                   ↳ fallback: conf × 0.5 if no episodes
//! ```
//!
//! Confidence is derived from the Bernoulli variance of the outcome sequence
//! combined with a sample-size penalty, so:
//! - `conf(3 consistent successes) ≈ 0.45` — just above threshold
//! - `conf(2 selections)           ≈ 0.33` — below threshold → deref
//! - `conf(10 mixed outcomes)      ≈ 0.63` — well above threshold
//!
//! ## Privacy invariant
//!
//! The engine only calls `DatabaseOps` methods marked `#[cfg(feature = "native")]`.
//! No method here initiates a network request.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::{DatabaseOps, PreferenceSignal};

/// Minimum aggregate confidence for the engine to (a) use the stored aggregate
/// score directly and (b) report the selection as "preference-guided".
///
/// Derived from the Bernoulli variance formula — requires roughly 3 consistent
/// selections or more mixed data to exceed this threshold.
const MIN_CONFIDENCE: f64 = 0.40;

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
    /// ## Confidence routing
    ///
    /// The stored aggregate row is a compact index summary (Memex(RL) §3).
    /// When its confidence is sufficient (`≥ MIN_CONFIDENCE`), the score is
    /// computed directly from the aggregate — fast and cheap.  When the
    /// aggregate is uncertain, the engine **dereferences** to the raw episode
    /// store for a recency-weighted success rate from full-fidelity records.
    ///
    /// Score components (fast path — aggregate confidence sufficient):
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

        let conf = confidence_score(signal.selection_count, signal.success_count);

        if conf < MIN_CONFIDENCE {
            // Aggregate is uncertain — dereference to full episode records.
            return self
                .score_from_episodes(action_type, agent_did_hash)
                .unwrap_or(conf * 0.5);
        }

        // Aggregate confidence is sufficient — score directly from summary.
        let success_rate = signal.success_count as f64 / signal.selection_count as f64;
        let recency = recency_factor(&signal.last_selected);
        0.6 * success_rate + 0.4 * recency
    }

    /// Returns `true` when the preference aggregate for at least one agent in
    /// `(action_type, schema_type)` has confidence ≥ `MIN_CONFIDENCE`, meaning
    /// the engine's selection was meaningfully influenced by historical data.
    pub fn is_preference_guided(&self, action_type: &str, schema_type: &str) -> bool {
        match self
            .db
            .list_preferences_for_schema(action_type, schema_type)
        {
            Ok(signals) => signals
                .iter()
                .any(|s| confidence_score(s.selection_count, s.success_count) >= MIN_CONFIDENCE),
            Err(_) => false,
        }
    }

    /// Dereference path: scan recent episodes for `agent_did_hash` and compute
    /// a recency-weighted success rate directly from full-fidelity records.
    ///
    /// Filters to `action_type` episodes, applies the same half-life decay as
    /// `recency_factor`, and returns the weighted success rate.  Returns `None`
    /// when no matching episodes exist — caller decides the fallback.
    fn score_from_episodes(&self, action_type: &str, agent_did_hash: &str) -> Option<f64> {
        // Filter at the DB level so the 20-episode limit covers the right action type.
        let episodes = self
            .db
            .list_episodes(Some(action_type), Some(agent_did_hash), 20, None)
            .ok()?;

        if episodes.is_empty() {
            return None;
        }

        let now = Utc::now();
        let (weighted_success, total_weight) =
            episodes.iter().fold((0.0_f64, 0.0_f64), |(ws, tw), ep| {
                let success = if ep.outcome == "success" { 1.0 } else { 0.0 };
                let ts = DateTime::parse_from_rfc3339(&ep.recorded_at)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now);
                let days_ago = (now - ts).num_days().max(0) as f64;
                let w = 2.0_f64.powf(-days_ago / RECENCY_HALF_LIFE_DAYS);
                (ws + success * w, tw + w)
            });

        if total_weight == 0.0 {
            return None;
        }
        Some(weighted_success / total_weight)
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

    /// True if any prior grant for `(action_type, schema_type)` covers all `required` scopes.
    ///
    /// Returns `true` immediately when `required` is empty (nothing to disclose).
    /// Used to skip the `AwaitingApproval` gate when the principal has already
    /// approved the same scope set for this interaction type.
    pub fn has_approved_scopes(
        &self,
        action_type: &str,
        schema_type: &str,
        required: &[String],
    ) -> bool {
        if required.is_empty() {
            return true;
        }
        let Ok(rows) = self
            .db
            .list_preferences_for_schema(action_type, schema_type)
        else {
            return false;
        };
        rows.iter().any(|r| {
            let approved: Vec<String> =
                serde_json::from_str(&r.approved_scope_refs).unwrap_or_default();
            required.iter().all(|s| approved.contains(s))
        })
    }

    /// Upsert an approval record for `agent_did_hash` in `(action_type, schema_type)`,
    /// creating the row from scratch if it does not exist yet.
    ///
    /// Unlike [`record_scope_approved`], this never silently no-ops on a missing row.
    /// New scope refs are merged (deduplicating) into any existing `approved_scope_refs`.
    /// Errors are silently discarded — the preference store is advisory.
    pub fn save_approved_scopes(
        &self,
        action_type: &str,
        schema_type: &str,
        agent_did_hash: &str,
        agent_name: &str,
        scopes: &[String],
    ) {
        let now = Utc::now().to_rfc3339();
        let existing = self
            .db
            .get_preference(action_type, schema_type, agent_did_hash)
            .ok()
            .flatten();
        let signal = match existing {
            Some(mut s) => {
                let mut approved: Vec<String> =
                    serde_json::from_str(&s.approved_scope_refs).unwrap_or_default();
                for scope in scopes {
                    if !approved.contains(scope) {
                        approved.push(scope.clone());
                    }
                }
                s.approved_scope_refs =
                    serde_json::to_string(&approved).unwrap_or_else(|_| "[]".into());
                s.updated_at = now;
                s
            }
            None => PreferenceSignal {
                id: Uuid::new_v4().to_string(),
                action_type: action_type.to_string(),
                schema_type: schema_type.to_string(),
                agent_did_hash: agent_did_hash.to_string(),
                agent_name: agent_name.to_string(),
                selection_count: 0,
                success_count: 0,
                last_selected: now.clone(),
                approved_scope_refs: serde_json::to_string(scopes).unwrap_or_else(|_| "[]".into()),
                rejected_scope_refs: "[]".to_string(),
                updated_at: now,
            },
        };
        let _ = self.db.upsert_preference(&signal);
    }

    /// Return the intersection of approved scope refs across all agents for
    /// `(action_type, schema_type)` — the mandate properties the principal has
    /// consistently approved for this type of interaction.
    ///
    /// Returns an empty `Vec` when:
    /// - No preference signals exist
    /// - No agent's aggregate confidence meets `MIN_CONFIDENCE`
    /// - The intersection of approved refs is empty
    pub fn suggested_scopes(&self, action_type: &str, schema_type: &str) -> Vec<String> {
        let signals = match self
            .db
            .list_preferences_for_schema(action_type, schema_type)
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        // Only include agents whose aggregate confidence meets the threshold.
        let qualified: Vec<_> = signals
            .iter()
            .filter(|s| confidence_score(s.selection_count, s.success_count) >= MIN_CONFIDENCE)
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

/// Compute an aggregate confidence value in `[0.0, 1.0]` for a preference row.
///
/// Models the outcome sequence as Bernoulli(p) where `p = success_count / n`.
/// The variance of a Bernoulli is `p(1−p)`, maximised at `p = 0.5`.
///
/// Confidence combines two factors:
///
/// ```text
/// bernoulli_conf = 1 − p(1−p)            ∈ [0.75, 1.0]
/// sample_weight  = 1 − exp(−n / 5)       → 1 as n → ∞
/// confidence     = bernoulli_conf × sample_weight
/// ```
///
/// The `sample_weight` term penalises small `n`, so a single extreme outcome
/// (e.g. 1 success out of 1 try) doesn't inflate the confidence score.
///
/// # Examples
/// - `n=1, k=1` → `1.0 × 0.18 = 0.18`  (too few samples)
/// - `n=2, k=0` → `1.0 × 0.33 = 0.33`  (2 failures — certain but small n)
/// - `n=3, k=3` → `1.0 × 0.45 = 0.45`  (3 successes — just above threshold)
/// - `n=5, k=5` → `1.0 × 0.63 = 0.63`  (clearly confident)
/// - `n=3, k=1` → `0.78 × 0.45 = 0.35` (mixed — uncertain)
pub(crate) fn confidence_score(selection_count: i64, success_count: i64) -> f64 {
    if selection_count == 0 {
        return 0.0;
    }
    let n = selection_count as f64;
    let k = success_count.min(selection_count) as f64;
    let p = k / n;
    let bernoulli_conf = 1.0 - p * (1.0 - p); // ∈ [0.75, 1.0]
    let sample_weight = 1.0 - (-n / 5.0).exp(); // saturates near 1 at n ≈ 20
    bernoulli_conf * sample_weight
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
    use crate::db::{DatabaseOps, Episode};

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
        // confidence(2, 0) ≈ 0.33 < MIN_CONFIDENCE → deref path, no episodes → conf * 0.5 ≈ 0.165
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

        // Build up enough selections for hash1 to reach MIN_CONFIDENCE
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
        // Only 2 selections — confidence(2, 0) ≈ 0.33 < MIN_CONFIDENCE
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
    fn deref_path_scores_from_episodes_when_aggregate_uncertain() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);

        // 2 selections → confidence(2, 0) ≈ 0.33 < MIN_CONFIDENCE → deref path triggered
        for _ in 0..2 {
            engine.record_agent_selected(
                "schema:SearchAction",
                "schema:SearchResult",
                "hash1",
                "DuckDuckGo Search",
            );
        }

        // Seed a recent success episode directly so score_from_episodes finds real data
        db.insert_episode(&Episode {
            id: uuid::Uuid::new_v4().to_string(),
            receipt_session_id: "sess-deref".into(),
            scenario_id: "sc-deref".into(),
            action_type: "schema:SearchAction".into(),
            agent_did_hash: "hash1".into(),
            agent_name: "DuckDuckGo Search".into(),
            outcome: "success".into(),
            outcome_detail: None,
            scope_exercised: "[]".into(),
            disclosure_refs: "[]".into(),
            duration_ms: 100,
            decay_state: "Active".into(),
            intent_summary: None,
            result_json: None,
            query: None,
            recorded_at: Utc::now().to_rfc3339(),
        })
        .unwrap();

        let score = engine.preference_score("schema:SearchAction", "schema:SearchResult", "hash1");
        // Deref path: 1 recent success → recency-weighted score ≈ 1.0
        assert!(
            score > 0.5,
            "deref path with a recent success episode should score > 0.5, got {score}"
        );
    }

    #[test]
    fn record_scope_approved_no_op_when_no_row() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);

        // Call without any prior record_agent_selected — should silently no-op
        engine.record_scope_approved(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            &["schema:name".to_string()],
        );

        // No row should have been created
        let sig = db
            .get_preference("schema:SearchAction", "schema:SearchResult", "hash1")
            .unwrap();
        assert!(
            sig.is_none(),
            "record_scope_approved with no row should be a no-op"
        );
    }

    // ── has_approved_scopes ──────────────────────────────────────────────────

    #[test]
    fn has_approved_scopes_empty_required_always_true() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);
        assert!(engine.has_approved_scopes("schema:SearchAction", "schema:SearchResult", &[]));
    }

    #[test]
    fn has_approved_scopes_no_rows_returns_false() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);
        assert!(!engine.has_approved_scopes(
            "schema:SearchAction",
            "schema:SearchResult",
            &["schema:name".to_string()],
        ));
    }

    #[test]
    fn has_approved_scopes_covers_required() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);
        engine.save_approved_scopes(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            "Agent",
            &["schema:name".to_string(), "schema:url".to_string()],
        );
        assert!(engine.has_approved_scopes(
            "schema:SearchAction",
            "schema:SearchResult",
            &["schema:name".to_string()],
        ));
        assert!(engine.has_approved_scopes(
            "schema:SearchAction",
            "schema:SearchResult",
            &["schema:name".to_string(), "schema:url".to_string()],
        ));
        // scope not previously approved → false
        assert!(!engine.has_approved_scopes(
            "schema:SearchAction",
            "schema:SearchResult",
            &["schema:email".to_string()],
        ));
    }

    // ── save_approved_scopes ─────────────────────────────────────────────────

    #[test]
    fn save_approved_scopes_creates_row_when_missing() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);
        // No prior record_agent_selected — row must be created from scratch.
        engine.save_approved_scopes(
            "schema:ReadAction",
            "schema:WebPage",
            "hash_web",
            "Web Page Reader",
            &["schema:url".to_string()],
        );
        let sig = db
            .get_preference("schema:ReadAction", "schema:WebPage", "hash_web")
            .unwrap()
            .expect("row should have been created");
        let approved: Vec<String> = serde_json::from_str(&sig.approved_scope_refs).unwrap();
        assert!(approved.contains(&"schema:url".to_string()));
    }

    #[test]
    fn save_approved_scopes_merges_into_existing_row() {
        let db = test_db();
        let engine = PreferenceEngine::new(&db);
        // Seed an existing row via record_agent_selected.
        engine.record_agent_selected(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            "Agent",
        );
        engine.save_approved_scopes(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            "Agent",
            &["schema:name".to_string()],
        );
        engine.save_approved_scopes(
            "schema:SearchAction",
            "schema:SearchResult",
            "hash1",
            "Agent",
            &["schema:name".to_string(), "schema:email".to_string()],
        );
        let sig = db
            .get_preference("schema:SearchAction", "schema:SearchResult", "hash1")
            .unwrap()
            .unwrap();
        let approved: Vec<String> = serde_json::from_str(&sig.approved_scope_refs).unwrap();
        // Both scopes present, no duplicates.
        assert_eq!(approved.iter().filter(|&s| s == "schema:name").count(), 1);
        assert!(approved.contains(&"schema:email".to_string()));
        // selection_count from the earlier record_agent_selected call is preserved.
        assert_eq!(sig.selection_count, 1);
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

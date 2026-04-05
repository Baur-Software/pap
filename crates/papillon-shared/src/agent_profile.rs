//! Agent profile aggregation from episodes.
//!
//! Queries the episode store to compute live aggregate statistics about each
//! agent: total episodes, success rate, average duration, per-action breakdown,
//! and the ISO 8601 timestamp of the most recent episode.
//!
//! This module is **native-only** because it depends on the `DatabaseOps` trait
//! which requires rusqlite. Feature-gate your imports accordingly.

#[cfg(feature = "native")]
use crate::db::{DatabaseOps, DbError};
use serde::{Deserialize, Serialize};

/// Per-action breakdown recorded for an agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionStats {
    /// The `action_type` value as recorded in the episode (e.g. `"search"`, `"booking"`).
    pub action: String,
    /// Total number of episodes with this action type.
    pub count: u64,
    /// Fraction of those episodes with `outcome = 'success'` (0.0 – 1.0).
    pub success_rate: f64,
}

/// Aggregated performance profile for a single agent, derived from the episode store.
///
/// Profiles are computed on-demand from raw episode rows; they are **not**
/// the pre-computed `agent_profiles` table rows (those live in [`crate::db::AgentProfile`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentProfile {
    /// The agent's DID (or DID hash), sourced from `episodes.agent_did_hash`.
    pub agent_did: String,
    /// Total number of episodes recorded for this agent.
    pub total_episodes: u64,
    /// Fraction of all episodes with `outcome = 'success'` (0.0 – 1.0).
    pub success_rate: f64,
    /// Mean `duration_ms` across all episodes.
    pub avg_duration_ms: f64,
    /// Per-`action_type` breakdown.
    pub actions: Vec<ActionStats>,
    /// RFC 3339 timestamp of the most recently recorded episode, if any.
    pub last_seen: Option<String>,
}

/// Aggregates [`AgentProfile`]s from a live database backend.
///
/// # Example
/// ```ignore
/// use papillon_shared::db::native::NativeDatabase;
/// use papillon_shared::agent_profile::AgentProfileStore;
///
/// let db = NativeDatabase::open_memory()?;
/// let profile = AgentProfileStore::aggregate_profile(&db, "did:key:z6Mk...")?;
/// let top = AgentProfileStore::top_agents(&db, 5)?;
/// ```
pub struct AgentProfileStore;

#[cfg(feature = "native")]
impl AgentProfileStore {
    /// Compute a live [`AgentProfile`] for the given `agent_did` (matched against
    /// `episodes.agent_did_hash`).
    ///
    /// Returns `Err` if the database query fails.  If no episodes exist for
    /// the agent the returned profile will have `total_episodes = 0` and
    /// `last_seen = None`.
    pub fn aggregate_profile(
        db: &dyn DatabaseOps,
        agent_did: &str,
    ) -> Result<AgentProfile, DbError> {
        // Fetch all episodes for this agent (no limit – we own the aggregation).
        let episodes = db.list_episodes(None, Some(agent_did), usize::MAX, None)?;

        if episodes.is_empty() {
            return Ok(AgentProfile {
                agent_did: agent_did.to_string(),
                total_episodes: 0,
                success_rate: 0.0,
                avg_duration_ms: 0.0,
                actions: vec![],
                last_seen: None,
            });
        }

        let total = episodes.len() as u64;
        let successes = episodes.iter().filter(|e| e.outcome == "success").count() as u64;
        let success_rate = successes as f64 / total as f64;

        let avg_duration_ms =
            episodes.iter().map(|e| e.duration_ms as f64).sum::<f64>() / total as f64;

        // Most-recent episode is first because list_episodes orders by recorded_at DESC.
        let last_seen = episodes.first().map(|e| e.recorded_at.clone());

        // Per-action aggregation using a Vec to avoid HashMap.
        let mut action_map: Vec<(String, u64, u64)> = Vec::new(); // (action, total, successes)
        for ep in &episodes {
            if let Some(entry) = action_map.iter_mut().find(|(a, _, _)| a == &ep.action_type) {
                entry.1 += 1;
                if ep.outcome == "success" {
                    entry.2 += 1;
                }
            } else {
                action_map.push((
                    ep.action_type.clone(),
                    1,
                    if ep.outcome == "success" { 1 } else { 0 },
                ));
            }
        }

        // Sort actions by count descending for deterministic output.
        action_map.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        let actions = action_map
            .into_iter()
            .map(|(action, count, suc)| ActionStats {
                action,
                count,
                success_rate: if count == 0 {
                    0.0
                } else {
                    suc as f64 / count as f64
                },
            })
            .collect();

        Ok(AgentProfile {
            agent_did: agent_did.to_string(),
            total_episodes: total,
            success_rate,
            avg_duration_ms,
            actions,
            last_seen,
        })
    }

    /// Return the top `limit` agents sorted by total episode count (descending),
    /// with ties broken by success rate (descending) then agent DID (ascending).
    ///
    /// Fetches **all** episodes and groups them in memory, which is efficient
    /// for the typical Papillon workload (< 100 k episodes).
    pub fn top_agents(db: &dyn DatabaseOps, limit: usize) -> Result<Vec<AgentProfile>, DbError> {
        // Pull all episodes once.
        let episodes = db.list_episodes(None, None, usize::MAX, None)?;

        if episodes.is_empty() {
            return Ok(vec![]);
        }

        // Collect unique agent DIDs (preserving insertion order from the query).
        let mut seen_dids: Vec<String> = Vec::new();
        for ep in &episodes {
            if !seen_dids.contains(&ep.agent_did_hash) {
                seen_dids.push(ep.agent_did_hash.clone());
            }
        }

        // Aggregate per-agent stats without calling back into the DB.
        let mut profiles: Vec<AgentProfile> = seen_dids
            .iter()
            .map(|did| {
                let agent_eps: Vec<_> = episodes
                    .iter()
                    .filter(|e| &e.agent_did_hash == did)
                    .collect();
                let total = agent_eps.len() as u64;
                let successes = agent_eps.iter().filter(|e| e.outcome == "success").count() as u64;
                let success_rate = if total == 0 {
                    0.0
                } else {
                    successes as f64 / total as f64
                };
                let avg_duration_ms = if total == 0 {
                    0.0
                } else {
                    agent_eps.iter().map(|e| e.duration_ms as f64).sum::<f64>() / total as f64
                };

                // Most-recent episode — list_episodes returns DESC so first element per DID is newest.
                let last_seen = agent_eps
                    .iter()
                    .max_by(|a, b| a.recorded_at.cmp(&b.recorded_at))
                    .map(|e| e.recorded_at.clone());

                // Per-action stats.
                let mut action_map: Vec<(String, u64, u64)> = Vec::new();
                for ep in &agent_eps {
                    if let Some(entry) =
                        action_map.iter_mut().find(|(a, _, _)| a == &ep.action_type)
                    {
                        entry.1 += 1;
                        if ep.outcome == "success" {
                            entry.2 += 1;
                        }
                    } else {
                        action_map.push((
                            ep.action_type.clone(),
                            1,
                            if ep.outcome == "success" { 1 } else { 0 },
                        ));
                    }
                }
                action_map.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                let actions = action_map
                    .into_iter()
                    .map(|(action, count, suc)| ActionStats {
                        action,
                        count,
                        success_rate: if count == 0 {
                            0.0
                        } else {
                            suc as f64 / count as f64
                        },
                    })
                    .collect();

                AgentProfile {
                    agent_did: did.clone(),
                    total_episodes: total,
                    success_rate,
                    avg_duration_ms,
                    actions,
                    last_seen,
                }
            })
            .collect();

        // Sort: total_episodes DESC, success_rate DESC, agent_did ASC.
        profiles.sort_by(|a, b| {
            b.total_episodes
                .cmp(&a.total_episodes)
                .then(
                    b.success_rate
                        .partial_cmp(&a.success_rate)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then(a.agent_did.cmp(&b.agent_did))
        });

        profiles.truncate(limit);
        Ok(profiles)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "native")]
mod tests {
    use super::*;
    use crate::db::{native::NativeDatabase, DatabaseOps, Episode};

    fn make_episode(
        id: &str,
        agent_did_hash: &str,
        action_type: &str,
        outcome: &str,
        duration_ms: i64,
        recorded_at: &str,
    ) -> Episode {
        Episode {
            id: id.to_string(),
            receipt_session_id: "sess-1".to_string(),
            scenario_id: "sc-1".to_string(),
            action_type: action_type.to_string(),
            agent_did_hash: agent_did_hash.to_string(),
            agent_name: format!("Agent {agent_did_hash}"),
            outcome: outcome.to_string(),
            outcome_detail: None,
            scope_exercised: "[]".to_string(),
            disclosure_refs: "[]".to_string(),
            duration_ms,
            decay_state: "Active".to_string(),
            intent_summary: None,
            result_json: None,
            query: None,
            recorded_at: recorded_at.to_string(),
        }
    }

    #[test]
    fn aggregate_profile_empty() {
        let db = NativeDatabase::open_memory().expect("db");
        let profile =
            AgentProfileStore::aggregate_profile(&db, "did:key:zNobody").expect("aggregate");

        assert_eq!(profile.agent_did, "did:key:zNobody");
        assert_eq!(profile.total_episodes, 0);
        assert_eq!(profile.success_rate, 0.0);
        assert_eq!(profile.avg_duration_ms, 0.0);
        assert!(profile.actions.is_empty());
        assert!(profile.last_seen.is_none());
    }

    #[test]
    fn aggregate_profile_basic_stats() {
        let db = NativeDatabase::open_memory().expect("db");

        let did = "did:key:zAgent1";
        // 3 episodes: 2 success, 1 failure
        db.insert_episode(&make_episode(
            "e1",
            did,
            "search",
            "success",
            100,
            "2024-01-01T10:00:00Z",
        ))
        .unwrap();
        db.insert_episode(&make_episode(
            "e2",
            did,
            "search",
            "failure",
            200,
            "2024-01-02T10:00:00Z",
        ))
        .unwrap();
        db.insert_episode(&make_episode(
            "e3",
            did,
            "booking",
            "success",
            300,
            "2024-01-03T10:00:00Z",
        ))
        .unwrap();

        let profile = AgentProfileStore::aggregate_profile(&db, did).expect("aggregate");

        assert_eq!(profile.agent_did, did);
        assert_eq!(profile.total_episodes, 3);
        // 2/3 successes
        assert!((profile.success_rate - 2.0 / 3.0).abs() < 1e-9);
        // avg = (100 + 200 + 300) / 3 = 200
        assert!((profile.avg_duration_ms - 200.0).abs() < 1e-9);
        // last_seen should be the most-recent recorded_at
        assert_eq!(profile.last_seen.as_deref(), Some("2024-01-03T10:00:00Z"));
    }

    #[test]
    fn aggregate_profile_action_stats() {
        let db = NativeDatabase::open_memory().expect("db");
        let did = "did:key:zAgent2";

        // 3 search episodes: 2 success, 1 failure
        db.insert_episode(&make_episode(
            "e1",
            did,
            "search",
            "success",
            50,
            "2024-01-01T00:00:00Z",
        ))
        .unwrap();
        db.insert_episode(&make_episode(
            "e2",
            did,
            "search",
            "success",
            60,
            "2024-01-02T00:00:00Z",
        ))
        .unwrap();
        db.insert_episode(&make_episode(
            "e3",
            did,
            "search",
            "failure",
            70,
            "2024-01-03T00:00:00Z",
        ))
        .unwrap();
        // 1 booking episode: success
        db.insert_episode(&make_episode(
            "e4",
            did,
            "booking",
            "success",
            200,
            "2024-01-04T00:00:00Z",
        ))
        .unwrap();

        let profile = AgentProfileStore::aggregate_profile(&db, did).expect("aggregate");

        assert_eq!(profile.actions.len(), 2);

        // actions sorted by count DESC: search(3) before booking(1)
        let search = &profile.actions[0];
        assert_eq!(search.action, "search");
        assert_eq!(search.count, 3);
        assert!((search.success_rate - 2.0 / 3.0).abs() < 1e-9);

        let booking = &profile.actions[1];
        assert_eq!(booking.action, "booking");
        assert_eq!(booking.count, 1);
        assert!((booking.success_rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn top_agents_returns_sorted_by_episode_count() {
        let db = NativeDatabase::open_memory().expect("db");

        // agent-A: 3 episodes
        for i in 0..3 {
            db.insert_episode(&make_episode(
                &format!("a{i}"),
                "agent-A",
                "search",
                "success",
                100,
                &format!("2024-01-0{i}T00:00:00Z", i = i + 1),
            ))
            .unwrap();
        }

        // agent-B: 1 episode
        db.insert_episode(&make_episode(
            "b1",
            "agent-B",
            "booking",
            "failure",
            200,
            "2024-02-01T00:00:00Z",
        ))
        .unwrap();

        // agent-C: 2 episodes
        db.insert_episode(&make_episode(
            "c1",
            "agent-C",
            "payment",
            "success",
            150,
            "2024-03-01T00:00:00Z",
        ))
        .unwrap();
        db.insert_episode(&make_episode(
            "c2",
            "agent-C",
            "payment",
            "success",
            150,
            "2024-03-02T00:00:00Z",
        ))
        .unwrap();

        let top = AgentProfileStore::top_agents(&db, 10).expect("top");

        assert_eq!(top.len(), 3);
        // Sorted by total_episodes DESC: A(3), C(2), B(1)
        assert_eq!(top[0].agent_did, "agent-A");
        assert_eq!(top[0].total_episodes, 3);
        assert_eq!(top[1].agent_did, "agent-C");
        assert_eq!(top[1].total_episodes, 2);
        assert_eq!(top[2].agent_did, "agent-B");
        assert_eq!(top[2].total_episodes, 1);
    }

    #[test]
    fn top_agents_respects_limit() {
        let db = NativeDatabase::open_memory().expect("db");

        for agent in ["alpha", "beta", "gamma", "delta", "epsilon"] {
            db.insert_episode(&make_episode(
                &format!("e-{agent}"),
                agent,
                "search",
                "success",
                100,
                "2024-01-01T00:00:00Z",
            ))
            .unwrap();
        }

        let top = AgentProfileStore::top_agents(&db, 3).expect("top");
        assert_eq!(top.len(), 3);
    }

    #[test]
    fn top_agents_empty_database() {
        let db = NativeDatabase::open_memory().expect("db");
        let top = AgentProfileStore::top_agents(&db, 10).expect("top");
        assert!(top.is_empty());
    }

    #[test]
    fn top_agents_success_rate_tiebreaker() {
        let db = NativeDatabase::open_memory().expect("db");

        // Both agents have 2 episodes; agent-hi has higher success rate.
        db.insert_episode(&make_episode(
            "h1",
            "agent-hi",
            "search",
            "success",
            100,
            "2024-01-01T00:00:00Z",
        ))
        .unwrap();
        db.insert_episode(&make_episode(
            "h2",
            "agent-hi",
            "search",
            "success",
            100,
            "2024-01-02T00:00:00Z",
        ))
        .unwrap();

        db.insert_episode(&make_episode(
            "l1",
            "agent-lo",
            "search",
            "success",
            100,
            "2024-01-01T00:00:00Z",
        ))
        .unwrap();
        db.insert_episode(&make_episode(
            "l2",
            "agent-lo",
            "search",
            "failure",
            100,
            "2024-01-02T00:00:00Z",
        ))
        .unwrap();

        let top = AgentProfileStore::top_agents(&db, 10).expect("top");
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].agent_did, "agent-hi");
        assert!((top[0].success_rate - 1.0).abs() < 1e-9);
        assert_eq!(top[1].agent_did, "agent-lo");
        assert!((top[1].success_rate - 0.5).abs() < 1e-9);
    }
}

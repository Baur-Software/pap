//! Native database implementation using rusqlite.
//!
//! This backend is used on desktop platforms and wraps the standard rusqlite crate.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use super::{AgentProfile, DatabaseOps, DbError, Episode};

/// Persistent SQLite database for Papillion's experience memory.
///
/// Stores episodes (receipt-anchored interaction records), agent profiles,
/// and retention policies. JSON-LD results are stored as JSON columns so
/// `json_extract()` can query into Schema.org typed payloads directly.
pub struct NativeDatabase {
    conn: Mutex<Connection>,
}

impl NativeDatabase {
    /// Open (or create) the database at the given path and run migrations.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)
            .map_err(|e| DbError(format!("db open: {e}")))?;

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database (for tests).
    #[cfg(test)]
    pub fn open_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| DbError(format!("db open: {e}")))?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Run schema migrations. Idempotent — safe to call on every startup.
    fn migrate(&self) -> Result<(), DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS episodes (
                id              TEXT PRIMARY KEY,
                receipt_session_id TEXT NOT NULL,
                scenario_id     TEXT NOT NULL,
                action_type     TEXT NOT NULL,
                agent_did_hash  TEXT NOT NULL,
                agent_name      TEXT NOT NULL,
                outcome         TEXT NOT NULL CHECK(outcome IN ('success', 'failure', 'rejected')),
                outcome_detail  TEXT,
                scope_exercised TEXT NOT NULL DEFAULT '[]',
                disclosure_refs TEXT NOT NULL DEFAULT '[]',
                duration_ms     INTEGER NOT NULL DEFAULT 0,
                decay_state     TEXT NOT NULL DEFAULT 'Active',
                intent_summary  TEXT,
                result_json     TEXT,
                query           TEXT,
                recorded_at     TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_episodes_action_type
                ON episodes(action_type);
            CREATE INDEX IF NOT EXISTS idx_episodes_agent_did_hash
                ON episodes(agent_did_hash);
            CREATE INDEX IF NOT EXISTS idx_episodes_recorded_at
                ON episodes(recorded_at);
            CREATE INDEX IF NOT EXISTS idx_episodes_action_agent_time
                ON episodes(action_type, agent_did_hash, recorded_at);

            CREATE TABLE IF NOT EXISTS agent_profiles (
                agent_did_hash        TEXT PRIMARY KEY,
                agent_name            TEXT NOT NULL,
                success_rate          REAL NOT NULL DEFAULT 0.0,
                avg_quality           REAL NOT NULL DEFAULT 0.0,
                avg_duration_ms       REAL NOT NULL DEFAULT 0.0,
                episode_count         INTEGER NOT NULL DEFAULT 0,
                minimal_disclosure_refs TEXT NOT NULL DEFAULT '[]',
                last_used             TEXT NOT NULL,
                co_sign_refusals      INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS retention_policies (
                name                        TEXT PRIMARY KEY,
                max_full_episodes           INTEGER NOT NULL DEFAULT 10000,
                full_retention_days         INTEGER NOT NULL DEFAULT 90,
                compressed_retention_days   INTEGER NOT NULL DEFAULT 365,
                failure_retention_multiplier REAL NOT NULL DEFAULT 2.0
            );

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
        )
        .map_err(|e| DbError(format!("db migrate: {e}")))?;

        // Insert default retention policy if none exists
        conn.execute(
            "INSERT OR IGNORE INTO retention_policies (name) VALUES ('default')",
            [],
        )
        .map_err(|e| DbError(format!("db default policy: {e}")))?;

        Ok(())
    }
}

impl DatabaseOps for NativeDatabase {
    fn insert_episode(&self, episode: &Episode) -> Result<(), DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        conn.execute(
            "INSERT INTO episodes (
                id, receipt_session_id, scenario_id, action_type,
                agent_did_hash, agent_name, outcome, outcome_detail,
                scope_exercised, disclosure_refs, duration_ms,
                decay_state, intent_summary, result_json, query, recorded_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                episode.id,
                episode.receipt_session_id,
                episode.scenario_id,
                episode.action_type,
                episode.agent_did_hash,
                episode.agent_name,
                episode.outcome,
                episode.outcome_detail,
                episode.scope_exercised,
                episode.disclosure_refs,
                episode.duration_ms,
                episode.decay_state,
                episode.intent_summary,
                episode.result_json,
                episode.query,
                episode.recorded_at,
            ],
        )
        .map_err(|e| DbError(format!("db insert episode: {e}")))?;

        Ok(())
    }

    fn list_episodes(
        &self,
        action_type: Option<&str>,
        agent_did_hash: Option<&str>,
        limit: usize,
        offset: Option<i64>,
    ) -> Result<Vec<Episode>, DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        let mut sql = String::from(
            "SELECT id, receipt_session_id, scenario_id, action_type,
                    agent_did_hash, agent_name, outcome, outcome_detail,
                    scope_exercised, disclosure_refs, duration_ms,
                    decay_state, intent_summary, result_json, query, recorded_at
             FROM episodes WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(at) = action_type {
            sql.push_str(&format!(" AND action_type = ?{}", param_values.len() + 1));
            param_values.push(Box::new(at.to_string()));
        }
        if let Some(adh) = agent_did_hash {
            sql.push_str(&format!(
                " AND agent_did_hash = ?{}",
                param_values.len() + 1
            ));
            param_values.push(Box::new(adh.to_string()));
        }

        sql.push_str(&format!(
            " ORDER BY recorded_at DESC LIMIT ?{}",
            param_values.len() + 1
        ));
        param_values.push(Box::new(limit as i64));

        if let Some(off) = offset {
            sql.push_str(&format!(" OFFSET ?{}", param_values.len() + 1));
            param_values.push(Box::new(off));
        }

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                Ok(Episode {
                    id: row.get(0)?,
                    receipt_session_id: row.get(1)?,
                    scenario_id: row.get(2)?,
                    action_type: row.get(3)?,
                    agent_did_hash: row.get(4)?,
                    agent_name: row.get(5)?,
                    outcome: row.get(6)?,
                    outcome_detail: row.get(7)?,
                    scope_exercised: row.get(8)?,
                    disclosure_refs: row.get(9)?,
                    duration_ms: row.get(10)?,
                    decay_state: row.get(11)?,
                    intent_summary: row.get(12)?,
                    result_json: row.get(13)?,
                    query: row.get(14)?,
                    recorded_at: row.get(15)?,
                })
            })
            .map_err(|e| DbError(format!("db query: {e}")))?;

        let mut episodes = Vec::new();
        for row in rows {
            episodes.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(episodes)
    }

    fn episode_count(&self) -> Result<usize, DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM episodes", [], |row| row.get(0))
            .map_err(|e| DbError(format!("db count: {e}")))?;
        Ok(count as usize)
    }

    fn upsert_agent_profile(&self, profile: &AgentProfile) -> Result<(), DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        conn.execute(
            "INSERT INTO agent_profiles (
                agent_did_hash, agent_name, success_rate, avg_quality,
                avg_duration_ms, episode_count, minimal_disclosure_refs,
                last_used, co_sign_refusals
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(agent_did_hash) DO UPDATE SET
                agent_name = excluded.agent_name,
                success_rate = excluded.success_rate,
                avg_quality = excluded.avg_quality,
                avg_duration_ms = excluded.avg_duration_ms,
                episode_count = excluded.episode_count,
                minimal_disclosure_refs = excluded.minimal_disclosure_refs,
                last_used = excluded.last_used,
                co_sign_refusals = excluded.co_sign_refusals",
            params![
                profile.agent_did_hash,
                profile.agent_name,
                profile.success_rate,
                profile.avg_quality,
                profile.avg_duration_ms,
                profile.episode_count,
                profile.minimal_disclosure_refs,
                profile.last_used,
                profile.co_sign_refusals,
            ],
        )
        .map_err(|e| DbError(format!("db upsert profile: {e}")))?;

        Ok(())
    }

    fn get_agent_profile(
        &self,
        agent_did_hash: &str,
    ) -> Result<Option<AgentProfile>, DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT agent_did_hash, agent_name, success_rate, avg_quality,
                    avg_duration_ms, episode_count, minimal_disclosure_refs,
                    last_used, co_sign_refusals
             FROM agent_profiles WHERE agent_did_hash = ?1",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let mut rows = stmt
            .query_map(params![agent_did_hash], |row| {
                Ok(AgentProfile {
                    agent_did_hash: row.get(0)?,
                    agent_name: row.get(1)?,
                    success_rate: row.get(2)?,
                    avg_quality: row.get(3)?,
                    avg_duration_ms: row.get(4)?,
                    episode_count: row.get(5)?,
                    minimal_disclosure_refs: row.get(6)?,
                    last_used: row.get(7)?,
                    co_sign_refusals: row.get(8)?,
                })
            })
            .map_err(|e| DbError(format!("db query: {e}")))?;

        match rows.next() {
            Some(Ok(profile)) => Ok(Some(profile)),
            Some(Err(e)) => Err(DbError(format!("db row: {e}"))),
            None => Ok(None),
        }
    }

    fn list_agent_profiles(&self) -> Result<Vec<AgentProfile>, DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT agent_did_hash, agent_name, success_rate, avg_quality,
                    avg_duration_ms, episode_count, minimal_disclosure_refs,
                    last_used, co_sign_refusals
             FROM agent_profiles ORDER BY success_rate DESC",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(AgentProfile {
                    agent_did_hash: row.get(0)?,
                    agent_name: row.get(1)?,
                    success_rate: row.get(2)?,
                    avg_quality: row.get(3)?,
                    avg_duration_ms: row.get(4)?,
                    episode_count: row.get(5)?,
                    minimal_disclosure_refs: row.get(6)?,
                    last_used: row.get(7)?,
                    co_sign_refusals: row.get(8)?,
                })
            })
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let mut profiles = Vec::new();
        for row in rows {
            profiles.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(profiles)
    }

    fn get_setting(&self, key: &str) -> Result<Option<String>, DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        let mut stmt = conn
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let mut rows = stmt
            .query_map(params![key], |row| row.get::<_, String>(0))
            .map_err(|e| DbError(format!("db query: {e}")))?;

        match rows.next() {
            Some(Ok(val)) => Ok(Some(val)),
            Some(Err(e)) => Err(DbError(format!("db row: {e}"))),
            None => Ok(None),
        }
    }

    fn set_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| DbError(format!("db set setting: {e}")))?;

        Ok(())
    }

    fn search_by_schema_type(
        &self,
        schema_type: &str,
        limit: usize,
    ) -> Result<Vec<Episode>, DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, receipt_session_id, scenario_id, action_type,
                    agent_did_hash, agent_name, outcome, outcome_detail,
                    scope_exercised, disclosure_refs, duration_ms,
                    decay_state, intent_summary, result_json, query, recorded_at
             FROM episodes
             WHERE result_json IS NOT NULL
             ORDER BY recorded_at DESC",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Episode {
                    id: row.get(0)?,
                    receipt_session_id: row.get(1)?,
                    scenario_id: row.get(2)?,
                    action_type: row.get(3)?,
                    agent_did_hash: row.get(4)?,
                    agent_name: row.get(5)?,
                    outcome: row.get(6)?,
                    outcome_detail: row.get(7)?,
                    scope_exercised: row.get(8)?,
                    disclosure_refs: row.get(9)?,
                    duration_ms: row.get(10)?,
                    decay_state: row.get(11)?,
                    intent_summary: row.get(12)?,
                    result_json: row.get(13)?,
                    query: row.get(14)?,
                    recorded_at: row.get(15)?,
                })
            })
            .map_err(|e| DbError(format!("db query: {e}")))?;

        let mut episodes = Vec::new();
        for row in rows {
            episodes.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }

        let mut filtered = Vec::new();
        for ep in episodes {
            if let Some(result_json) = &ep.result_json {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(result_json) {
                    if let Some(at) = val.get("@type") {
                        if at.as_str() == Some(schema_type) {
                            filtered.push(ep);
                            if filtered.len() >= limit {
                                break;
                            }
                            continue;
                        }
                        if let Some(arr) = at.as_array() {
                            if arr.iter().any(|v| v.as_str() == Some(schema_type)) {
                                filtered.push(ep);
                                if filtered.len() >= limit {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(filtered)
    }

    fn search_text(&self, query: &str, limit: usize) -> Result<Vec<Episode>, DbError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DbError(e.to_string()))?;

        let escaped_query = query.replace('%', "\\%").replace('_', "\\_");
        let pattern = format!("%{escaped_query}%");
        let mut stmt = conn
            .prepare(
                "SELECT id, receipt_session_id, scenario_id, action_type,
                    agent_did_hash, agent_name, outcome, outcome_detail,
                    scope_exercised, disclosure_refs, duration_ms,
                    decay_state, intent_summary, result_json, query, recorded_at
             FROM episodes
             WHERE intent_summary LIKE ?1 ESCAPE '\\' OR query LIKE ?1 ESCAPE '\\'
             ORDER BY recorded_at DESC LIMIT ?2",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let rows = stmt
            .query_map(params![pattern, limit as i64], |row| {
                Ok(Episode {
                    id: row.get(0)?,
                    receipt_session_id: row.get(1)?,
                    scenario_id: row.get(2)?,
                    action_type: row.get(3)?,
                    agent_did_hash: row.get(4)?,
                    agent_name: row.get(5)?,
                    outcome: row.get(6)?,
                    outcome_detail: row.get(7)?,
                    scope_exercised: row.get(8)?,
                    disclosure_refs: row.get(9)?,
                    duration_ms: row.get(10)?,
                    decay_state: row.get(11)?,
                    intent_summary: row.get(12)?,
                    result_json: row.get(13)?,
                    query: row.get(14)?,
                    recorded_at: row.get(15)?,
                })
            })
            .map_err(|e| DbError(format!("db query: {e}")))?;

        let mut episodes = Vec::new();
        for row in rows {
            episodes.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(episodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> NativeDatabase {
        NativeDatabase::open_memory().expect("in-memory db")
    }

    fn sample_episode(id: &str) -> Episode {
        Episode {
            id: id.to_string(),
            receipt_session_id: format!("sess-{id}"),
            scenario_id: "search".to_string(),
            action_type: "schema:SearchAction".to_string(),
            agent_did_hash: "hash-ddg".to_string(),
            agent_name: "DuckDuckGo Search".to_string(),
            outcome: "success".to_string(),
            outcome_detail: Some("5 results".to_string()),
            scope_exercised: r#"["schema:SearchAction"]"#.to_string(),
            disclosure_refs: "[]".to_string(),
            duration_ms: 150,
            decay_state: "Active".to_string(),
            intent_summary: Some("Search for rust sqlite".to_string()),
            result_json: Some(
                r#"{"@type":"SearchResult","name":"Rust SQLite bindings"}"#.to_string(),
            ),
            query: Some("rust sqlite".to_string()),
            recorded_at: "2026-03-21T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn create_and_list_episodes() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();
        db.insert_episode(&sample_episode("ep-2")).unwrap();

        let episodes = db.list_episodes(None, None, 100, None).unwrap();
        assert_eq!(episodes.len(), 2);
    }
}

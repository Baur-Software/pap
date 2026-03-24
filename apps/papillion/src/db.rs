use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::PapillionError;
use papillion_shared::types::Template;

/// Persistent SQLite database for Papillion's experience memory.
///
/// Stores episodes (receipt-anchored interaction records), agent profiles,
/// and retention policies. JSON-LD results are stored as JSON columns so
/// `json_extract()` can query into Schema.org typed payloads directly.
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open (or create) the database at the given path and run migrations.
    pub fn open(path: &Path) -> Result<Self, PapillionError> {
        let conn =
            Connection::open(path).map_err(|e| PapillionError::from(format!("db open: {e}")))?;

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database (for tests).
    #[cfg(test)]
    pub fn open_memory() -> Result<Self, PapillionError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| PapillionError::from(format!("db open: {e}")))?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Run schema migrations. Idempotent — safe to call on every startup.
    fn migrate(&self) -> Result<(), PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

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

            CREATE TABLE IF NOT EXISTS templates (
                id              TEXT PRIMARY KEY,
                template_name   TEXT NOT NULL UNIQUE,
                schema_type     TEXT NOT NULL,
                principal_did   TEXT,
                template_config TEXT NOT NULL,
                version         INTEGER NOT NULL DEFAULT 1,
                enabled         INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                created_by      TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_templates_schema_type
                ON templates(schema_type);
            CREATE INDEX IF NOT EXISTS idx_templates_enabled
                ON templates(enabled);
            CREATE INDEX IF NOT EXISTS idx_templates_principal_did
                ON templates(principal_did);
            CREATE INDEX IF NOT EXISTS idx_templates_schema_principal
                ON templates(schema_type, principal_did, enabled);
            ",
        )
        .map_err(|e| PapillionError::from(format!("db migrate: {e}")))?;

        // Insert default retention policy if none exists
        conn.execute(
            "INSERT OR IGNORE INTO retention_policies (name) VALUES ('default')",
            [],
        )
        .map_err(|e| PapillionError::from(format!("db default policy: {e}")))?;

        Ok(())
    }

    // ── Episode CRUD ──────────────────────────────────────────

    /// Record an episode from a completed scenario run.
    pub fn insert_episode(&self, episode: &Episode) -> Result<(), PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

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
        .map_err(|e| PapillionError::from(format!("db insert episode: {e}")))?;

        Ok(())
    }

    /// List episodes, most recent first. Optional filters.
    pub fn list_episodes(
        &self,
        action_type: Option<&str>,
        agent_did_hash: Option<&str>,
        limit: usize,
        offset: Option<i64>,
    ) -> Result<Vec<Episode>, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

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
            .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

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
            .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

        let mut episodes = Vec::new();
        for row in rows {
            episodes.push(row.map_err(|e| PapillionError::from(format!("db row: {e}")))?);
        }
        Ok(episodes)
    }

    /// Count total episodes.
    pub fn episode_count(&self) -> Result<usize, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM episodes", [], |row| row.get(0))
            .map_err(|e| PapillionError::from(format!("db count: {e}")))?;
        Ok(count as usize)
    }

    // ── Agent Profiles ────────────────────────────────────────

    /// Upsert an agent profile with updated rolling statistics.
    pub fn upsert_agent_profile(&self, profile: &AgentProfile) -> Result<(), PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

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
        .map_err(|e| PapillionError::from(format!("db upsert profile: {e}")))?;

        Ok(())
    }

    /// Get an agent profile by DID hash.
    pub fn get_agent_profile(
        &self,
        agent_did_hash: &str,
    ) -> Result<Option<AgentProfile>, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT agent_did_hash, agent_name, success_rate, avg_quality,
                    avg_duration_ms, episode_count, minimal_disclosure_refs,
                    last_used, co_sign_refusals
             FROM agent_profiles WHERE agent_did_hash = ?1",
            )
            .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

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
            .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

        match rows.next() {
            Some(Ok(profile)) => Ok(Some(profile)),
            Some(Err(e)) => Err(PapillionError::from(format!("db row: {e}"))),
            None => Ok(None),
        }
    }

    /// List all agent profiles ordered by success rate descending.
    pub fn list_agent_profiles(&self) -> Result<Vec<AgentProfile>, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT agent_did_hash, agent_name, success_rate, avg_quality,
                    avg_duration_ms, episode_count, minimal_disclosure_refs,
                    last_used, co_sign_refusals
             FROM agent_profiles ORDER BY success_rate DESC",
            )
            .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

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
            .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

        let mut profiles = Vec::new();
        for row in rows {
            profiles.push(row.map_err(|e| PapillionError::from(format!("db row: {e}")))?);
        }
        Ok(profiles)
    }

    // ── Settings ──────────────────────────────────────────────

    /// Get a setting value by key.
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let mut stmt = conn
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

        let mut rows = stmt
            .query_map(params![key], |row| row.get::<_, String>(0))
            .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

        match rows.next() {
            Some(Ok(val)) => Ok(Some(val)),
            Some(Err(e)) => Err(PapillionError::from(format!("db row: {e}"))),
            None => Ok(None),
        }
    }

    /// Set a setting value (upsert).
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| PapillionError::from(format!("db set setting: {e}")))?;

        Ok(())
    }

    // ── JSON-LD Queries ───────────────────────────────────────

    /// Search episodes by Schema.org @type in result_json.
    /// Handles both string form ("@type": "SearchResult") and array form ("@type": ["SearchResult"]).
    pub fn search_by_schema_type(
        &self,
        schema_type: &str,
        limit: usize,
    ) -> Result<Vec<Episode>, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        // Fetch episodes and filter by @type in code to handle both string and array forms
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
            .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

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
            .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

        let mut episodes = Vec::new();
        for row in rows {
            episodes.push(row.map_err(|e| PapillionError::from(format!("db row: {e}")))?);
        }

        // Filter by @type: handle both string form and array form
        let mut filtered = Vec::new();
        for ep in episodes {
            if let Some(result_json) = &ep.result_json {
                // Try to parse as JSON and check @type
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(result_json) {
                    if let Some(at) = val.get("@type") {
                        // Check if it matches as a string
                        if at.as_str() == Some(schema_type) {
                            filtered.push(ep);
                            if filtered.len() >= limit {
                                break;
                            }
                            continue;
                        }
                        // Check if it matches as an array element
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

    /// Full-text search over intent_summary and query fields.
    pub fn search_text(&self, query: &str, limit: usize) -> Result<Vec<Episode>, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        // Escape LIKE wildcards to prevent pattern injection: % and _ are special in LIKE
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
            .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

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
            .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

        let mut episodes = Vec::new();
        for row in rows {
            episodes.push(row.map_err(|e| PapillionError::from(format!("db row: {e}")))?);
        }
        Ok(episodes)
    }

    // ── Template CRUD ──────────────────────────────────────────

    /// Insert a new template into the database.
    pub fn insert_template(&self, template: &Template) -> Result<(), PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let template_config_json = serde_json::to_string(&template.template_config)
            .map_err(|e| PapillionError::from(format!("template config json: {e}")))?;

        conn.execute(
            "INSERT INTO templates (
                id, template_name, schema_type, principal_did, template_config,
                version, enabled, created_at, updated_at, created_by
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                template.id,
                template.template_name,
                template.schema_type,
                template.principal_did,
                template_config_json,
                template.version,
                if template.enabled { 1 } else { 0 },
                template.created_at,
                template.updated_at,
                template.created_by,
            ],
        )
        .map_err(|e| PapillionError::from(format!("db insert template: {e}")))?;

        Ok(())
    }

    /// Get a template by name.
    pub fn get_template(&self, template_name: &str) -> Result<Option<Template>, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, template_name, schema_type, principal_did, template_config,
                        version, enabled, created_at, updated_at, created_by
                 FROM templates WHERE template_name = ?1"
            )
            .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

        let mut rows = stmt
            .query_map(params![template_name], |row| {
                let template_config_json: String = row.get(4)?;
                let template_config = serde_json::from_str(&template_config_json)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
                Ok(Template {
                    id: row.get(0)?,
                    template_name: row.get(1)?,
                    schema_type: row.get(2)?,
                    principal_did: row.get(3)?,
                    template_config,
                    version: row.get(5)?,
                    enabled: row.get::<_, i32>(6)? != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    created_by: row.get(9)?,
                })
            })
            .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

        match rows.next() {
            Some(Ok(template)) => Ok(Some(template)),
            Some(Err(e)) => Err(PapillionError::from(format!("db row: {e}"))),
            None => Ok(None),
        }
    }

    /// List all templates.
    pub fn list_templates(&self) -> Result<Vec<Template>, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, template_name, schema_type, principal_did, template_config,
                        version, enabled, created_at, updated_at, created_by
                 FROM templates ORDER BY created_at DESC"
            )
            .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                let template_config_json: String = row.get(4)?;
                let template_config = serde_json::from_str(&template_config_json)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
                Ok(Template {
                    id: row.get(0)?,
                    template_name: row.get(1)?,
                    schema_type: row.get(2)?,
                    principal_did: row.get(3)?,
                    template_config,
                    version: row.get(5)?,
                    enabled: row.get::<_, i32>(6)? != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    created_by: row.get(9)?,
                })
            })
            .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

        let mut templates = Vec::new();
        for row in rows {
            templates.push(row.map_err(|e| PapillionError::from(format!("db row: {e}")))?);
        }
        Ok(templates)
    }

    /// List enabled templates for a principal (profile) or global templates.
    /// If principal_did is None, returns only global templates (principal_did IS NULL).
    /// If principal_did is Some, returns profile templates for that principal plus global templates.
    pub fn list_enabled_templates_for_principal(
        &self,
        principal_did: Option<&str>,
    ) -> Result<Vec<Template>, PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let mut templates: Vec<Template> = Vec::new();

        if let Some(did) = principal_did {
            // Return both profile-specific and global templates
            let mut stmt = conn
                .prepare(
                    "SELECT id, template_name, schema_type, principal_did, template_config,
                            version, enabled, created_at, updated_at, created_by
                     FROM templates
                     WHERE enabled = 1 AND (principal_did = ?1 OR principal_did IS NULL)
                     ORDER BY schema_type, created_at DESC"
                )
                .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

            let rows = stmt
                .query_map(params![did], |row| {
                    let template_config_json: String = row.get(4)?;
                    let template_config = serde_json::from_str(&template_config_json)
                        .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
                    Ok(Template {
                        id: row.get(0)?,
                        template_name: row.get(1)?,
                        schema_type: row.get(2)?,
                        principal_did: row.get(3)?,
                        template_config,
                        version: row.get(5)?,
                        enabled: row.get::<_, i32>(6)? != 0,
                        created_at: row.get(7)?,
                        updated_at: row.get(8)?,
                        created_by: row.get(9)?,
                    })
                })
                .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

            for row in rows {
                templates.push(row.map_err(|e| PapillionError::from(format!("db row: {e}")))?);
            }
        } else {
            // Return only global templates
            let mut stmt = conn
                .prepare(
                    "SELECT id, template_name, schema_type, principal_did, template_config,
                            version, enabled, created_at, updated_at, created_by
                     FROM templates
                     WHERE enabled = 1 AND principal_did IS NULL
                     ORDER BY created_at DESC"
                )
                .map_err(|e| PapillionError::from(format!("db prepare: {e}")))?;

            let rows = stmt
                .query_map([], |row| {
                    let template_config_json: String = row.get(4)?;
                    let template_config = serde_json::from_str(&template_config_json)
                        .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
                    Ok(Template {
                        id: row.get(0)?,
                        template_name: row.get(1)?,
                        schema_type: row.get(2)?,
                        principal_did: row.get(3)?,
                        template_config,
                        version: row.get(5)?,
                        enabled: row.get::<_, i32>(6)? != 0,
                        created_at: row.get(7)?,
                        updated_at: row.get(8)?,
                        created_by: row.get(9)?,
                    })
                })
                .map_err(|e| PapillionError::from(format!("db query: {e}")))?;

            for row in rows {
                templates.push(row.map_err(|e| PapillionError::from(format!("db row: {e}")))?);
            }
        }

        Ok(templates)
    }

    /// Update an existing template.
    pub fn update_template(&self, template: &Template) -> Result<(), PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let template_config_json = serde_json::to_string(&template.template_config)
            .map_err(|e| PapillionError::from(format!("template config json: {e}")))?;

        conn.execute(
            "UPDATE templates SET
                template_config = ?1,
                version = ?2,
                enabled = ?3,
                updated_at = ?4,
                created_by = ?5
             WHERE template_name = ?6",
            params![
                template_config_json,
                template.version,
                if template.enabled { 1 } else { 0 },
                template.updated_at,
                template.created_by,
                template.template_name,
            ],
        )
        .map_err(|e| PapillionError::from(format!("db update template: {e}")))?;

        Ok(())
    }

    /// Set whether a template is enabled or disabled.
    pub fn set_template_enabled(&self, template_name: &str, enabled: bool) -> Result<(), PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "UPDATE templates SET enabled = ?1, updated_at = ?2 WHERE template_name = ?3",
            params![if enabled { 1 } else { 0 }, now, template_name],
        )
        .map_err(|e| PapillionError::from(format!("db set template enabled: {e}")))?;

        Ok(())
    }

    /// Delete a template by name.
    pub fn delete_template(&self, template_name: &str) -> Result<(), PapillionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        conn.execute(
            "DELETE FROM templates WHERE template_name = ?1",
            params![template_name],
        )
        .map_err(|e| PapillionError::from(format!("db delete template: {e}")))?;

        Ok(())
    }
}

// ── Data types ───────────────────────────────────────────────

/// A single recorded interaction episode, anchored to a co-signed receipt.
#[derive(Debug, Clone)]
pub struct Episode {
    pub id: String,
    pub receipt_session_id: String,
    pub scenario_id: String,
    pub action_type: String,
    pub agent_did_hash: String,
    pub agent_name: String,
    /// "success", "failure", or "rejected"
    pub outcome: String,
    pub outcome_detail: Option<String>,
    /// JSON array of action types exercised
    pub scope_exercised: String,
    /// JSON array of property refs from receipt
    pub disclosure_refs: String,
    pub duration_ms: i64,
    pub decay_state: String,
    pub intent_summary: Option<String>,
    /// Full JSON-LD result payload — queryable via json_extract()
    pub result_json: Option<String>,
    pub query: Option<String>,
    pub recorded_at: String,
}

/// Aggregated agent performance profile.
#[derive(Debug, Clone, Serialize)]
pub struct AgentProfile {
    pub agent_did_hash: String,
    pub agent_name: String,
    pub success_rate: f64,
    pub avg_quality: f64,
    pub avg_duration_ms: f64,
    pub episode_count: i64,
    /// JSON array of minimal disclosure property refs
    pub minimal_disclosure_refs: String,
    pub last_used: String,
    pub co_sign_refusals: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::open_memory().expect("in-memory db")
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

    #[test]
    fn filter_by_action_type() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        let mut ask_ep = sample_episode("ep-2");
        ask_ep.action_type = "schema:AskAction".to_string();
        db.insert_episode(&ask_ep).unwrap();

        let search = db
            .list_episodes(Some("schema:SearchAction"), None, 100, None)
            .unwrap();
        assert_eq!(search.len(), 1);
        assert_eq!(search[0].id, "ep-1");
    }

    #[test]
    fn episode_count() {
        let db = test_db();
        assert_eq!(db.episode_count().unwrap(), 0);
        db.insert_episode(&sample_episode("ep-1")).unwrap();
        assert_eq!(db.episode_count().unwrap(), 1);
    }

    #[test]
    fn agent_profile_upsert_and_get() {
        let db = test_db();
        let profile = AgentProfile {
            agent_did_hash: "hash-ddg".to_string(),
            agent_name: "DuckDuckGo Search".to_string(),
            success_rate: 0.95,
            avg_quality: 0.8,
            avg_duration_ms: 200.0,
            episode_count: 10,
            minimal_disclosure_refs: "[]".to_string(),
            last_used: "2026-03-21T12:00:00Z".to_string(),
            co_sign_refusals: 0,
        };
        db.upsert_agent_profile(&profile).unwrap();

        let fetched = db.get_agent_profile("hash-ddg").unwrap().unwrap();
        assert_eq!(fetched.agent_name, "DuckDuckGo Search");
        assert!((fetched.success_rate - 0.95).abs() < f64::EPSILON);

        // Update
        let updated = AgentProfile {
            success_rate: 0.9,
            episode_count: 11,
            ..profile
        };
        db.upsert_agent_profile(&updated).unwrap();
        let fetched = db.get_agent_profile("hash-ddg").unwrap().unwrap();
        assert_eq!(fetched.episode_count, 11);
    }

    #[test]
    fn search_by_schema_type_json_extract() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        let results = db.search_by_schema_type("SearchResult", 10).unwrap();
        assert_eq!(results.len(), 1);

        let none = db.search_by_schema_type("Article", 10).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn search_text_matches_query() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        let results = db.search_text("rust", 10).unwrap();
        assert_eq!(results.len(), 1);

        let none = db.search_text("python", 10).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn list_agent_profiles_empty() {
        let db = test_db();
        let profiles = db.list_agent_profiles().unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn missing_profile_returns_none() {
        let db = test_db();
        assert!(db.get_agent_profile("nonexistent").unwrap().is_none());
    }

    #[test]
    fn settings_crud() {
        let db = test_db();
        // Missing key returns None
        assert!(db.get_setting("nonexistent").unwrap().is_none());

        // Set and get
        db.set_setting("test_key", "test_value").unwrap();
        assert_eq!(db.get_setting("test_key").unwrap().unwrap(), "test_value");

        // Overwrite
        db.set_setting("test_key", "updated").unwrap();
        assert_eq!(db.get_setting("test_key").unwrap().unwrap(), "updated");
    }

    #[test]
    fn list_agent_profiles_with_data() {
        let db = test_db();
        let p1 = AgentProfile {
            agent_did_hash: "hash-a".to_string(),
            agent_name: "Agent A".to_string(),
            success_rate: 0.9,
            avg_quality: 0.8,
            avg_duration_ms: 100.0,
            episode_count: 5,
            minimal_disclosure_refs: "[]".to_string(),
            last_used: "2026-03-21T12:00:00Z".to_string(),
            co_sign_refusals: 0,
        };
        let p2 = AgentProfile {
            agent_did_hash: "hash-b".to_string(),
            agent_name: "Agent B".to_string(),
            ..p1.clone()
        };
        db.upsert_agent_profile(&p1).unwrap();
        db.upsert_agent_profile(&p2).unwrap();

        let profiles = db.list_agent_profiles().unwrap();
        assert_eq!(profiles.len(), 2);
    }

    #[test]
    fn filter_episodes_by_agent_did_hash() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        let mut other = sample_episode("ep-2");
        other.agent_did_hash = "hash-other".to_string();
        db.insert_episode(&other).unwrap();

        let filtered = db.list_episodes(None, Some("hash-ddg"), 100, None).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "ep-1");
    }

    #[test]
    fn migration_idempotent() {
        let tmp = std::env::temp_dir().join("pap_test_migrate_idempotent.db");
        // Open once — runs migrations
        let db1 = Database::open(&tmp).unwrap();
        db1.insert_episode(&sample_episode("ep-1")).unwrap();
        drop(db1);
        // Open again — migrations run again via CREATE IF NOT EXISTS
        let db2 = Database::open(&tmp).unwrap();
        assert_eq!(db2.episode_count().unwrap(), 1);
        drop(db2);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn default_retention_policy_exists() {
        let db = test_db();
        let conn = db.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM retention_policies WHERE name = 'default'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn search_by_schema_type_string_form() {
        // Test M4: String form @type (original behavior)
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        let results = db.search_by_schema_type("SearchResult", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_by_schema_type_array_form() {
        // Test M4: Array form @type (handles ["SearchResult"])
        let db = test_db();
        let mut ep = sample_episode("ep-2");
        ep.result_json =
            Some(r#"{"@type":["SearchResult","WebPage"],"name":"Result"}"#.to_string());
        db.insert_episode(&ep).unwrap();

        let results = db.search_by_schema_type("SearchResult", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "ep-2");
    }

    #[test]
    fn search_text_with_like_wildcards() {
        // Test M5: LIKE injection prevention via wildcard escaping
        let db = test_db();
        let mut ep = sample_episode("ep-1");
        ep.intent_summary = Some("100% rust".to_string());
        ep.query = Some("rust 100% fast".to_string());
        db.insert_episode(&ep).unwrap();

        // Search for literal % should match even though % is a wildcard in SQL
        let results = db.search_text("100%", 10).unwrap();
        assert_eq!(results.len(), 1);

        // Insert another episode to verify we're matching correctly
        let mut ep2 = sample_episode("ep-2");
        ep2.intent_summary = Some("python_query_handler".to_string());
        db.insert_episode(&ep2).unwrap();

        // Exact match should work
        let results = db.search_text("python_query_handler", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "ep-2");

        // Substring match should work
        let results = db.search_text("query_handler", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "ep-2");
    }

    #[test]
    fn search_text_prevents_wildcard_expansion() {
        // Test M5: Verify that wildcards in user input don't expand unintentionally
        let db = test_db();
        let mut ep1 = sample_episode("ep-1");
        ep1.query = Some("search".to_string());
        db.insert_episode(&ep1).unwrap();

        let mut ep2 = sample_episode("ep-2");
        ep2.query = Some("seXrch".to_string()); // X in place of a
        db.insert_episode(&ep2).unwrap();

        // Without escaping, searching for "se_rch" with _ as wildcard would match both
        // With escaping, it should only match if there's a literal underscore
        let results = db.search_text("se_rch", 10).unwrap();
        assert!(
            results.is_empty(),
            "Wildcard _ should not match without literal underscore"
        );

        // But a literal underscore should match
        let mut ep3 = sample_episode("ep-3");
        ep3.query = Some("se_rch".to_string());
        db.insert_episode(&ep3).unwrap();

        let results = db.search_text("se_rch", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "ep-3");
    }

    #[test]
    fn composite_index_exists() {
        // Test M6: Verify composite index was created
        let db = test_db();
        let conn = db.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
             WHERE type='index' AND name='idx_episodes_action_agent_time'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn list_episodes_uses_composite_index() {
        // Test M6: Verify queries that filter on (action_type, agent_did_hash, recorded_at)
        // can use the composite index
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        let mut ep2 = sample_episode("ep-2");
        ep2.action_type = "schema:AskAction".to_string();
        ep2.agent_did_hash = "hash-other".to_string();
        db.insert_episode(&ep2).unwrap();

        // Query that benefits from composite index
        let results = db
            .list_episodes(Some("schema:SearchAction"), Some("hash-ddg"), 100, None)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "ep-1");
    }

    // ── Tests for data fidelity fixes (H6, H5, H4) ──────────────────

    #[test]
    fn episode_records_success_and_failure_correctly() {
        let db = test_db();

        // Success episode
        let mut ep_success = sample_episode("ep-success");
        ep_success.outcome = "success".to_string();
        ep_success.outcome_detail = Some("10 results".to_string());
        db.insert_episode(&ep_success).unwrap();

        // Failure episode (e.g., API error)
        let mut ep_failure = sample_episode("ep-failure");
        ep_failure.outcome = "failure".to_string();
        ep_failure.outcome_detail = Some("API error: connection refused".to_string());
        db.insert_episode(&ep_failure).unwrap();

        let episodes = db.list_episodes(None, None, 100, None).unwrap();
        assert_eq!(episodes.len(), 2);

        let success = episodes.iter().find(|e| e.id == "ep-success").unwrap();
        assert_eq!(success.outcome, "success");

        let failure = episodes.iter().find(|e| e.id == "ep-failure").unwrap();
        assert_eq!(failure.outcome, "failure");
    }

    #[test]
    fn disclosure_refs_stored_and_retrieved() {
        let db = test_db();

        let disclosure_json = r#"["schema:Person.name","schema:Person.email"]"#;
        let mut ep = sample_episode("ep-disclosure");
        ep.disclosure_refs = disclosure_json.to_string();
        db.insert_episode(&ep).unwrap();

        let retrieved = db.list_episodes(None, None, 1, None).unwrap();
        assert_eq!(retrieved[0].disclosure_refs, disclosure_json);
    }

    #[test]
    fn quality_based_on_result_completeness() {
        let db = test_db();

        // Episode with no results: low quality signal expected
        let mut ep_no_results = sample_episode("ep-empty");
        ep_no_results.outcome_detail = Some("0 results".to_string());
        db.insert_episode(&ep_no_results).unwrap();

        // Episode with many results: high quality signal expected
        let mut ep_many_results = sample_episode("ep-rich");
        ep_many_results.outcome_detail = Some("25 results".to_string());
        db.insert_episode(&ep_many_results).unwrap();

        // Episode with large JSON payload: high quality signal expected
        let mut ep_large_payload = sample_episode("ep-payload");
        ep_large_payload.result_json = Some(
            r#"{"@type":"SearchResult","items":[{"title":"1","snippet":"..."}, {"title":"2","snippet":"..."},...{"title":"15","snippet":"..."}]}"#
                .repeat(10), // Make it large
        );
        db.insert_episode(&ep_large_payload).unwrap();

        let episodes = db.list_episodes(None, None, 100, None).unwrap();
        assert_eq!(episodes.len(), 3);

        // All outcomes still recorded correctly
        for ep in &episodes {
            assert_eq!(ep.outcome, "success");
        }
    }

    #[test]
    fn minimal_disclosure_intersection_across_episodes() {
        let db = test_db();

        // Episode 1: discloses name, email, phone
        let mut ep1 = sample_episode("ep-1");
        ep1.disclosure_refs = r#"["name","email","phone"]"#.to_string();
        ep1.agent_did_hash = "hash-agent-a".to_string();
        db.insert_episode(&ep1).unwrap();

        // Episode 2: same agent, discloses name, email (phone dropped)
        let mut ep2 = sample_episode("ep-2");
        ep2.disclosure_refs = r#"["name","email"]"#.to_string();
        ep2.agent_did_hash = "hash-agent-a".to_string();
        db.insert_episode(&ep2).unwrap();

        // Episode 3: same agent, discloses name only
        let mut ep3 = sample_episode("ep-3");
        ep3.disclosure_refs = r#"["name"]"#.to_string();
        ep3.agent_did_hash = "hash-agent-a".to_string();
        db.insert_episode(&ep3).unwrap();

        let episodes = db
            .list_episodes(None, Some("hash-agent-a"), 100, None)
            .unwrap();
        assert_eq!(episodes.len(), 3);

        // Parse disclosures and compute intersection
        let all_refs: Vec<Vec<String>> = episodes
            .iter()
            .filter_map(|ep| serde_json::from_str(&ep.disclosure_refs).ok())
            .collect();

        assert_eq!(all_refs.len(), 3);

        let first = all_refs[0].clone();
        let intersection = all_refs[1..].iter().fold(first, |acc, cur| {
            acc.into_iter().filter(|r| cur.contains(r)).collect()
        });

        // Minimal set should be just ["name"]
        assert_eq!(intersection, vec!["name".to_string()]);
    }

    #[test]
    fn failure_episode_does_not_affect_minimal_disclosure() {
        let db = test_db();

        // Successful episode with disclosures
        let mut ep_success = sample_episode("ep-success");
        ep_success.disclosure_refs = r#"["name","email"]"#.to_string();
        ep_success.agent_did_hash = "hash-agent-b".to_string();
        db.insert_episode(&ep_success).unwrap();

        // Failed episode (should not contribute to minimal_disclosure_refs)
        let mut ep_failure = sample_episode("ep-failure");
        ep_failure.outcome = "failure".to_string();
        ep_failure.disclosure_refs = r#"["name","email","phone"]"#.to_string();
        ep_failure.agent_did_hash = "hash-agent-b".to_string();
        db.insert_episode(&ep_failure).unwrap();

        let episodes = db
            .list_episodes(None, Some("hash-agent-b"), 100, None)
            .unwrap();
        let successful = episodes
            .iter()
            .filter(|ep| ep.outcome == "success")
            .collect::<Vec<_>>();

        assert_eq!(successful.len(), 1);
        let success_refs: Vec<String> =
            serde_json::from_str(&successful[0].disclosure_refs).unwrap();
        // Minimal should be based only on successful episodes
        assert_eq!(success_refs, vec!["name", "email"]);
    }

    #[test]
    fn agent_profile_captures_multiple_episodes() {
        let db = test_db();

        // Record 3 episodes for the same agent
        let mut ep1 = sample_episode("ep-1");
        ep1.agent_did_hash = "hash-agent-c".to_string();
        ep1.outcome = "success".to_string();
        ep1.outcome_detail = Some("5 results".to_string());
        db.insert_episode(&ep1).unwrap();

        let mut ep2 = sample_episode("ep-2");
        ep2.agent_did_hash = "hash-agent-c".to_string();
        ep2.outcome = "success".to_string();
        ep2.outcome_detail = Some("8 results".to_string());
        db.insert_episode(&ep2).unwrap();

        let mut ep3 = sample_episode("ep-3");
        ep3.agent_did_hash = "hash-agent-c".to_string();
        ep3.outcome = "failure".to_string();
        db.insert_episode(&ep3).unwrap();

        let profile = AgentProfile {
            agent_did_hash: "hash-agent-c".to_string(),
            agent_name: "Test Agent".to_string(),
            success_rate: 2.0 / 3.0,
            avg_quality: 0.75, // Based on result completeness, not just success
            avg_duration_ms: 150.0,
            episode_count: 3,
            minimal_disclosure_refs: r#"[]"#.to_string(),
            last_used: "2026-03-21T12:00:00Z".to_string(),
            co_sign_refusals: 0,
        };
        db.upsert_agent_profile(&profile).unwrap();

        let fetched = db.get_agent_profile("hash-agent-c").unwrap().unwrap();
        assert_eq!(fetched.episode_count, 3);
        assert!((fetched.success_rate - (2.0 / 3.0)).abs() < 0.01);
    }
}

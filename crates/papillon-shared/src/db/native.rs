//! Native database implementation using rusqlite.
//!
//! This backend is used on desktop platforms and wraps the standard rusqlite crate.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use super::{AgentProfile, DatabaseOps, DbError, Episode};
use crate::types::{
    CanvasBlockRecord, CanvasMessageRecord, CanvasRecord, PipelineInfo, SavedPipeline,
};
use pap_agents::{DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig};

/// Persistent SQLite database for Papillon's experience memory.
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
        let conn = Connection::open(path).map_err(|e| DbError(format!("db open: {e}")))?;

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database (for tests and ephemeral use).
    pub fn open_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory().map_err(|e| DbError(format!("db open: {e}")))?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Run schema migrations. Idempotent — safe to call on every startup.
    fn migrate(&self) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

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
            CREATE INDEX IF NOT EXISTS idx_templates_principal_did
                ON templates(principal_did);
            CREATE INDEX IF NOT EXISTS idx_templates_enabled
                ON templates(enabled);

            CREATE TABLE IF NOT EXISTS agents (
                agent_did TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL DEFAULT 1,
                version TEXT NOT NULL DEFAULT '0.1.0',
                name TEXT NOT NULL,
                provider TEXT NOT NULL,
                description TEXT NOT NULL,
                action TEXT NOT NULL,
                object_types_json TEXT NOT NULL DEFAULT '[]',
                requires_disclosure_json TEXT NOT NULL DEFAULT '[]',
                returns_json TEXT NOT NULL DEFAULT '[]',
                endpoint_json TEXT,
                llm_instructions TEXT NOT NULL DEFAULT '',
                subagents_json TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL CHECK(source IN ('catalog','user_created','generated')),
                operator_key_seed BLOB NOT NULL,
                published_to_json TEXT NOT NULL DEFAULT '[]',
                catalog_path TEXT,
                removed_from_catalog INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_catalog_path
                ON agents(catalog_path) WHERE catalog_path IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_agents_action ON agents(action);
            CREATE INDEX IF NOT EXISTS idx_agents_source ON agents(source);

            CREATE TABLE IF NOT EXISTS conversations (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                is_group    INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chat_messages (
                id              TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL REFERENCES conversations(id),
                author_did      TEXT NOT NULL,
                content         TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                delivered       INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_chat_messages_conv
                ON chat_messages(conversation_id, created_at);

            -- Per-agent setting overrides. Specification comes from the
            -- agent's advertisement (via pap://); values live here.
            -- agent_version pins each override to the version it was
            -- configured against, like Docker image tags.
            CREATE TABLE IF NOT EXISTS agent_settings (
                agent_did_hash TEXT NOT NULL,
                value_name     TEXT NOT NULL,
                value          TEXT NOT NULL,
                agent_version  TEXT NOT NULL DEFAULT '0.1.0',
                updated_at     TEXT NOT NULL,
                PRIMARY KEY (agent_did_hash, value_name)
            );

            CREATE TABLE IF NOT EXISTS canvases (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS canvas_blocks (
                id                  TEXT PRIMARY KEY,
                canvas_id           TEXT NOT NULL REFERENCES canvases(id) ON DELETE CASCADE,
                prompt_text         TEXT,
                schema_type         TEXT,
                content_json        TEXT,
                block_state         TEXT NOT NULL DEFAULT 'resolving',
                episode_id          TEXT,
                agent_did           TEXT,
                mandate_expires_at  TEXT,
                preference_guided   INTEGER NOT NULL DEFAULT 0,
                display_order       INTEGER NOT NULL DEFAULT 0,
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_canvas_blocks_canvas ON canvas_blocks(canvas_id, display_order);

            CREATE TABLE IF NOT EXISTS canvas_messages (
                id          TEXT PRIMARY KEY,
                canvas_id   TEXT NOT NULL REFERENCES canvases(id) ON DELETE CASCADE,
                role        TEXT NOT NULL CHECK(role IN ('user','assistant')),
                content     TEXT NOT NULL,
                block_id    TEXT,
                created_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_canvas_messages_canvas ON canvas_messages(canvas_id, created_at);

            CREATE TABLE IF NOT EXISTS saved_pipelines (
                id            TEXT PRIMARY KEY,
                name          TEXT NOT NULL,
                description   TEXT NOT NULL DEFAULT '',
                pipeline_json TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_saved_pipelines_name ON saved_pipelines(name);

            CREATE TABLE IF NOT EXISTS principal_attributes (
                prop_name  TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                last_used  TEXT NOT NULL
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

        // FTS5 virtual table for full-text search over episode fields.
        // Uses content= so the FTS index mirrors the episodes table without
        // duplicating storage.  The trigger pair keeps the index in sync.
        conn.execute_batch(
            "
            CREATE VIRTUAL TABLE IF NOT EXISTS episodes_fts
                USING fts5(
                    action_type,
                    intent_summary,
                    query,
                    agent_name,
                    content='episodes',
                    content_rowid='rowid',
                    tokenize='unicode61 remove_diacritics 1'
                );

            -- Populate FTS for any rows that exist before this migration ran.
            INSERT OR IGNORE INTO episodes_fts(rowid, action_type, intent_summary, query, agent_name)
                SELECT rowid, action_type, intent_summary, query, agent_name
                FROM episodes
                WHERE rowid NOT IN (SELECT rowid FROM episodes_fts);

            CREATE TRIGGER IF NOT EXISTS episodes_fts_ai
                AFTER INSERT ON episodes BEGIN
                    INSERT INTO episodes_fts(rowid, action_type, intent_summary, query, agent_name)
                        VALUES (new.rowid, new.action_type, new.intent_summary, new.query, new.agent_name);
                END;

            CREATE TRIGGER IF NOT EXISTS episodes_fts_ad
                AFTER DELETE ON episodes BEGIN
                    INSERT INTO episodes_fts(episodes_fts, rowid, action_type, intent_summary, query, agent_name)
                        VALUES ('delete', old.rowid, old.action_type, old.intent_summary, old.query, old.agent_name);
                END;

            CREATE TRIGGER IF NOT EXISTS episodes_fts_au
                AFTER UPDATE ON episodes BEGIN
                    INSERT INTO episodes_fts(episodes_fts, rowid, action_type, intent_summary, query, agent_name)
                        VALUES ('delete', old.rowid, old.action_type, old.intent_summary, old.query, old.agent_name);
                    INSERT INTO episodes_fts(rowid, action_type, intent_summary, query, agent_name)
                        VALUES (new.rowid, new.action_type, new.intent_summary, new.query, new.agent_name);
                END;
            ",
        )
        .map_err(|e| DbError(format!("db migrate fts5: {e}")))?;

        // Preference learning table — all data stays on-device, no network calls.
        // Tracks which agents were selected for which (action_type, schema_type) pairs,
        // approved/rejected scope refs, and session outcomes so the orchestrator can
        // make preference-guided suggestions over time.
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS preferences (
                id                   TEXT PRIMARY KEY,
                action_type          TEXT NOT NULL,
                schema_type          TEXT NOT NULL,
                agent_did_hash       TEXT NOT NULL,
                agent_name           TEXT NOT NULL,
                selection_count      INTEGER NOT NULL DEFAULT 0,
                success_count        INTEGER NOT NULL DEFAULT 0,
                last_selected        TEXT NOT NULL,
                approved_scope_refs  TEXT NOT NULL DEFAULT '[]',
                rejected_scope_refs  TEXT NOT NULL DEFAULT '[]',
                updated_at           TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_preferences_action_schema_agent
                ON preferences(action_type, schema_type, agent_did_hash);

            CREATE INDEX IF NOT EXISTS idx_preferences_action_schema
                ON preferences(action_type, schema_type);
            ",
        )
        .map_err(|e| DbError(format!("db migrate preferences: {e}")))?;

        // Additive column migrations — ALTER TABLE returns an error if the column
        // already exists; we suppress those to keep migrations idempotent.
        let _ = conn.execute(
            "ALTER TABLE agents ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE agents ADD COLUMN version TEXT NOT NULL DEFAULT '0.1.0'",
            [],
        );

        // Dynamic agent definitions persisted as raw JSON blobs. This is a
        // separate table from `agents` so that user-managed lightweight defs
        // (name + JSON) can round-trip without requiring all the columns of
        // the full agents table.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS agent_defs (
                name TEXT PRIMARY KEY,
                json TEXT NOT NULL
            )",
            [],
        )
        .map_err(|e| DbError(format!("db migrate agent_defs: {e}")))?;

        Ok(())
    }

    /// Map a rusqlite `Row` to a `PreferenceSignal`. Column order must match
    /// every SELECT that reads from the `preferences` table.
    fn map_preference_row(row: &rusqlite::Row) -> rusqlite::Result<super::PreferenceSignal> {
        Ok(super::PreferenceSignal {
            id: row.get(0)?,
            action_type: row.get(1)?,
            schema_type: row.get(2)?,
            agent_did_hash: row.get(3)?,
            agent_name: row.get(4)?,
            selection_count: row.get(5)?,
            success_count: row.get(6)?,
            last_selected: row.get(7)?,
            approved_scope_refs: row.get(8)?,
            rejected_scope_refs: row.get(9)?,
            updated_at: row.get(10)?,
        })
    }
}

impl DatabaseOps for NativeDatabase {
    fn insert_episode(&self, episode: &Episode) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

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
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

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
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM episodes", [], |row| row.get(0))
            .map_err(|e| DbError(format!("db count: {e}")))?;
        Ok(count as usize)
    }

    fn upsert_agent_profile(&self, profile: &AgentProfile) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

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

    fn get_agent_profile(&self, agent_did_hash: &str) -> Result<Option<AgentProfile>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

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
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

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
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

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
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| DbError(format!("db set setting: {e}")))?;

        Ok(())
    }

    fn set_agent_setting(
        &self,
        agent_did_hash: &str,
        value_name: &str,
        value: &str,
        agent_version: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO agent_settings (agent_did_hash, value_name, value, agent_version, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(agent_did_hash, value_name)
             DO UPDATE SET value = excluded.value,
                           agent_version = excluded.agent_version,
                           updated_at = excluded.updated_at",
            params![agent_did_hash, value_name, value, agent_version, now],
        )
        .map_err(|e| DbError(format!("db set agent setting: {e}")))?;
        Ok(())
    }

    fn get_agent_settings(
        &self,
        agent_did_hash: &str,
    ) -> Result<std::collections::HashMap<String, super::AgentSettingOverride>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT value_name, value, agent_version FROM agent_settings WHERE agent_did_hash = ?1",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let rows = stmt
            .query_map(params![agent_did_hash], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    super::AgentSettingOverride {
                        value: row.get(1)?,
                        agent_version: row.get(2)?,
                    },
                ))
            })
            .map_err(|e| DbError(format!("db query: {e}")))?;

        let mut result = std::collections::HashMap::new();
        for row in rows {
            let (k, v) = row.map_err(|e| DbError(format!("db row: {e}")))?;
            result.insert(k, v);
        }
        Ok(result)
    }

    fn delete_agent_setting(&self, agent_did_hash: &str, value_name: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute(
            "DELETE FROM agent_settings WHERE agent_did_hash = ?1 AND value_name = ?2",
            params![agent_did_hash, value_name],
        )
        .map_err(|e| DbError(format!("db delete agent setting: {e}")))?;
        Ok(())
    }

    fn search_by_schema_type(
        &self,
        schema_type: &str,
        limit: usize,
    ) -> Result<Vec<Episode>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

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
        // Delegate to the FTS5-backed search_episodes for full-text search.
        self.search_episodes(query, limit)
    }

    fn search_episodes(&self, query: &str, limit: usize) -> Result<Vec<Episode>, DbError> {
        // Guard: queries shorter than 3 characters would match nothing useful
        // (or far too broadly).  Return early to avoid a round-trip.
        if query.trim().len() < 3 {
            return Ok(vec![]);
        }

        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        // Sanitize the FTS5 query string: strip double-quotes so callers do not
        // need to worry about FTS5 query syntax injection.
        let fts_query = query.replace('"', "");

        let mut stmt = conn
            .prepare(
                "SELECT e.id, e.receipt_session_id, e.scenario_id, e.action_type,
                        e.agent_did_hash, e.agent_name, e.outcome, e.outcome_detail,
                        e.scope_exercised, e.disclosure_refs, e.duration_ms,
                        e.decay_state, e.intent_summary, e.result_json, e.query, e.recorded_at
                 FROM episodes_fts
                 JOIN episodes e ON e.rowid = episodes_fts.rowid
                 WHERE episodes_fts MATCH ?1
                 ORDER BY rank
                 LIMIT ?2",
            )
            .map_err(|e| DbError(format!("db prepare fts: {e}")))?;

        let rows = stmt
            .query_map(params![fts_query, limit as i64], |row| {
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
            .map_err(|e| DbError(format!("db fts query: {e}")))?;

        let mut episodes = Vec::new();
        for row in rows {
            episodes.push(row.map_err(|e| DbError(format!("db fts row: {e}")))?);
        }
        Ok(episodes)
    }

    fn query_by_action(&self, action: &str, limit: usize) -> Result<Vec<Episode>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, receipt_session_id, scenario_id, action_type,
                        agent_did_hash, agent_name, outcome, outcome_detail,
                        scope_exercised, disclosure_refs, duration_ms,
                        decay_state, intent_summary, result_json, query, recorded_at
                 FROM episodes
                 WHERE action_type = ?1
                 ORDER BY recorded_at DESC
                 LIMIT ?2",
            )
            .map_err(|e| DbError(format!("db prepare action: {e}")))?;

        let rows = stmt
            .query_map(params![action, limit as i64], |row| {
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
            .map_err(|e| DbError(format!("db action query: {e}")))?;

        let mut episodes = Vec::new();
        for row in rows {
            episodes.push(row.map_err(|e| DbError(format!("db action row: {e}")))?);
        }
        Ok(episodes)
    }

    fn query_templates(
        &self,
        principal_did: Option<&str>,
    ) -> Result<Vec<crate::types::Template>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        let (sql, param_values): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) =
            if let Some(pid) = principal_did {
                (
                    "SELECT id, template_name, schema_type, principal_did,
                            template_config, version, enabled, created_at,
                            updated_at, created_by
                     FROM templates
                     WHERE principal_did = ?1 OR principal_did IS NULL
                     ORDER BY template_name",
                    vec![Box::new(pid.to_string())],
                )
            } else {
                (
                    "SELECT id, template_name, schema_type, principal_did,
                            template_config, version, enabled, created_at,
                            updated_at, created_by
                     FROM templates
                     ORDER BY template_name",
                    vec![],
                )
            };

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let config_json: String = row.get(4)?;
                let template_config: crate::types::TemplateConfig =
                    serde_json::from_str(&config_json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let enabled_int: i64 = row.get(6)?;
                Ok(crate::types::Template {
                    id: row.get(0)?,
                    template_name: row.get(1)?,
                    schema_type: row.get(2)?,
                    principal_did: row.get(3)?,
                    agent_did: None,
                    template_config,
                    version: row.get(5)?,
                    enabled: enabled_int != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    created_by: row.get(9)?,
                })
            })
            .map_err(|e| DbError(format!("db query: {e}")))?;

        let mut templates = Vec::new();
        for row in rows {
            templates.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(templates)
    }

    fn list_enabled_templates_for_principal(
        &self,
        principal_did: Option<&str>,
    ) -> Result<Vec<crate::types::Template>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        let (sql, param_values): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) =
            if let Some(pid) = principal_did {
                (
                    "SELECT id, template_name, schema_type, principal_did,
                            template_config, version, enabled, created_at,
                            updated_at, created_by
                     FROM templates
                     WHERE enabled = 1 AND (principal_did = ?1 OR principal_did IS NULL)
                     ORDER BY template_name",
                    vec![Box::new(pid.to_string())],
                )
            } else {
                (
                    "SELECT id, template_name, schema_type, principal_did,
                            template_config, version, enabled, created_at,
                            updated_at, created_by
                     FROM templates
                     WHERE enabled = 1
                     ORDER BY template_name",
                    vec![],
                )
            };

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let config_json: String = row.get(4)?;
                let template_config: crate::types::TemplateConfig =
                    serde_json::from_str(&config_json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let enabled_int: i64 = row.get(6)?;
                Ok(crate::types::Template {
                    id: row.get(0)?,
                    template_name: row.get(1)?,
                    schema_type: row.get(2)?,
                    principal_did: row.get(3)?,
                    agent_did: None,
                    template_config,
                    version: row.get(5)?,
                    enabled: enabled_int != 0,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    created_by: row.get(9)?,
                })
            })
            .map_err(|e| DbError(format!("db query: {e}")))?;

        let mut templates = Vec::new();
        for row in rows {
            templates.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(templates)
    }

    fn insert_template(&self, template: &crate::types::Template) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        let config_json = serde_json::to_string(&template.template_config)
            .map_err(|e| DbError(format!("serialize template_config: {e}")))?;

        conn.execute(
            "INSERT INTO templates (
                id, template_name, schema_type, principal_did,
                template_config, version, enabled, created_at,
                updated_at, created_by
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                template.id,
                template.template_name,
                template.schema_type,
                template.principal_did,
                config_json,
                template.version,
                template.enabled as i64,
                template.created_at,
                template.updated_at,
                template.created_by,
            ],
        )
        .map_err(|e| DbError(format!("db insert template: {e}")))?;

        Ok(())
    }

    fn update_template(&self, template: &crate::types::Template) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        let config_json = serde_json::to_string(&template.template_config)
            .map_err(|e| DbError(format!("serialize template_config: {e}")))?;

        let rows_changed = conn
            .execute(
                "UPDATE templates SET
                    template_name = ?1, schema_type = ?2, principal_did = ?3,
                    template_config = ?4, version = ?5, enabled = ?6,
                    updated_at = ?7, created_by = ?8
                 WHERE id = ?9",
                params![
                    template.template_name,
                    template.schema_type,
                    template.principal_did,
                    config_json,
                    template.version,
                    template.enabled as i64,
                    template.updated_at,
                    template.created_by,
                    template.id,
                ],
            )
            .map_err(|e| DbError(format!("db update template: {e}")))?;

        if rows_changed == 0 {
            return Err(DbError(format!("Template not found: {}", template.id)));
        }

        Ok(())
    }

    fn delete_template(&self, template_name: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        let rows_changed = conn
            .execute(
                "DELETE FROM templates WHERE template_name = ?1",
                params![template_name],
            )
            .map_err(|e| DbError(format!("db delete template: {e}")))?;

        if rows_changed == 0 {
            return Err(DbError(format!("Template not found: {}", template_name)));
        }

        Ok(())
    }

    fn set_template_enabled(&self, template_name: &str, enabled: bool) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        let rows_changed = conn
            .execute(
                "UPDATE templates SET enabled = ?1 WHERE template_name = ?2",
                params![enabled as i64, template_name],
            )
            .map_err(|e| DbError(format!("db set template enabled: {e}")))?;

        if rows_changed == 0 {
            return Err(DbError(format!("Template not found: {}", template_name)));
        }

        Ok(())
    }

    fn has_enabled_template_for_schema_type(&self, schema_type: &str) -> Result<bool, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM templates WHERE schema_type = ?1 AND enabled = 1",
                params![schema_type],
                |row| row.get(0),
            )
            .map_err(|e| DbError(format!("db query: {e}")))?;
        Ok(count > 0)
    }

    fn insert_agent(&self, def: &DynamicAgentDef) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let agent_did = def.agent_did.as_deref().ok_or_else(|| {
            DbError("insert_agent: agent_did must be set before insert".to_string())
        })?;
        let seed = def.operator_key_seed.ok_or_else(|| {
            DbError("insert_agent: operator_key_seed must be set before insert".to_string())
        })?;
        let object_types_json = serde_json::to_string(&def.object_types)
            .map_err(|e| DbError(format!("serialize object_types: {e}")))?;
        let requires_disclosure_json = serde_json::to_string(&def.requires_disclosure)
            .map_err(|e| DbError(format!("serialize requires_disclosure: {e}")))?;
        let returns_json = serde_json::to_string(&def.returns)
            .map_err(|e| DbError(format!("serialize returns: {e}")))?;
        let endpoint_json = def
            .endpoint
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| DbError(format!("serialize endpoint: {e}")))?;
        let subagents_json = serde_json::to_string(&def.subagents)
            .map_err(|e| DbError(format!("serialize subagents: {e}")))?;
        let published_to_json = serde_json::to_string(&def.published_to)
            .map_err(|e| DbError(format!("serialize published_to: {e}")))?;
        let source_str = match def.source {
            DynamicAgentSource::Catalog => "catalog",
            DynamicAgentSource::UserCreated => "user_created",
            DynamicAgentSource::Generated => "generated",
            DynamicAgentSource::Federation => "federation",
        };
        conn.execute(
            "INSERT INTO agents (
                agent_did, schema_version, version, name, provider, description, action,
                object_types_json, requires_disclosure_json, returns_json,
                endpoint_json, llm_instructions, subagents_json, source,
                operator_key_seed, published_to_json, catalog_path,
                created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10,
                ?11, ?12, ?13, ?14,
                ?15, ?16, ?17,
                ?18, ?19
            )",
            params![
                agent_did,
                def.schema_version,
                def.version,
                def.name,
                def.provider,
                def.description,
                def.action,
                object_types_json,
                requires_disclosure_json,
                returns_json,
                endpoint_json,
                def.llm_instructions,
                subagents_json,
                source_str,
                seed.as_slice(),
                published_to_json,
                def.catalog_path,
                def.created_at,
                def.updated_at,
            ],
        )
        .map_err(|e| DbError(format!("db insert agent: {e}")))?;
        Ok(())
    }

    fn load_all_agents(&self) -> Result<Vec<DynamicAgentDef>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT agent_did, schema_version, version, name, provider, description, action,
                    object_types_json, requires_disclosure_json, returns_json,
                    endpoint_json, llm_instructions, subagents_json, source,
                    operator_key_seed, published_to_json, catalog_path,
                    created_at, updated_at
             FROM agents
             WHERE removed_from_catalog = 0
             ORDER BY name",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                // Column indices: 0=agent_did, 1=schema_version, 2=version,
                // 3=name, 4=provider, 5=description, 6=action,
                // 7=object_types_json, 8=requires_disclosure_json, 9=returns_json,
                // 10=endpoint_json, 11=llm_instructions, 12=subagents_json, 13=source,
                // 14=operator_key_seed, 15=published_to_json, 16=catalog_path,
                // 17=created_at, 18=updated_at
                let source_str: String = row.get(13)?;
                let source = match source_str.as_str() {
                    "catalog" => DynamicAgentSource::Catalog,
                    "user_created" => DynamicAgentSource::UserCreated,
                    "generated" => DynamicAgentSource::Generated,
                    other => {
                        return Err(rusqlite::Error::FromSqlConversionFailure(
                            13,
                            rusqlite::types::Type::Text,
                            format!("unknown source: {other}").into(),
                        ))
                    }
                };
                let seed_blob: Vec<u8> = row.get(14)?;
                let seed_arr: [u8; 32] = seed_blob.try_into().map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        14,
                        rusqlite::types::Type::Blob,
                        "operator_key_seed must be 32 bytes".into(),
                    )
                })?;
                let endpoint_json: Option<String> = row.get(10)?;
                let endpoint = endpoint_json
                    .map(|j| {
                        serde_json::from_str::<HttpEndpointConfig>(&j).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                10,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })
                    })
                    .transpose()?;
                let parse_json_array =
                    |idx: usize, raw: String| -> Result<Vec<String>, rusqlite::Error> {
                        serde_json::from_str::<Vec<String>>(&raw).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                idx,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })
                    };
                Ok(DynamicAgentDef {
                    agent_did: Some(row.get(0)?),
                    schema_version: row.get::<_, i64>(1)? as u32,
                    version: row.get(2)?,
                    name: row.get(3)?,
                    provider: row.get(4)?,
                    description: row.get(5)?,
                    action: row.get(6)?,
                    object_types: parse_json_array(7, row.get(7)?)?,
                    requires_disclosure: parse_json_array(8, row.get(8)?)?,
                    returns: parse_json_array(9, row.get(9)?)?,
                    endpoint,
                    llm_instructions: row.get(11)?,
                    subagents: parse_json_array(12, row.get(12)?)?,
                    source,
                    operator_key_seed: Some(seed_arr),
                    published_to: parse_json_array(15, row.get(15)?)?,
                    catalog_path: row.get(16)?,
                    // configurable_properties are sourced from TOML/advertisement,
                    // not stored in the agents table. Default to empty.
                    configurable_properties: vec![],
                    created_at: row.get(17)?,
                    updated_at: row.get(18)?,
                })
            })
            .map_err(|e| DbError(format!("db query: {e}")))?;

        let mut agents = Vec::new();
        for row in rows {
            agents.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(agents)
    }

    fn update_agent(&self, def: &DynamicAgentDef) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let agent_did = def
            .agent_did
            .as_deref()
            .ok_or_else(|| DbError("update_agent: agent_did must be set".to_string()))?;
        let object_types_json = serde_json::to_string(&def.object_types)
            .map_err(|e| DbError(format!("serialize object_types: {e}")))?;
        let requires_disclosure_json = serde_json::to_string(&def.requires_disclosure)
            .map_err(|e| DbError(format!("serialize requires_disclosure: {e}")))?;
        let returns_json = serde_json::to_string(&def.returns)
            .map_err(|e| DbError(format!("serialize returns: {e}")))?;
        let endpoint_json = def
            .endpoint
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| DbError(format!("serialize endpoint: {e}")))?;
        let subagents_json = serde_json::to_string(&def.subagents)
            .map_err(|e| DbError(format!("serialize subagents: {e}")))?;
        let published_to_json = serde_json::to_string(&def.published_to)
            .map_err(|e| DbError(format!("serialize published_to: {e}")))?;
        let rows_changed = conn
            .execute(
                "UPDATE agents SET
                schema_version = ?1, version = ?2, name = ?3, provider = ?4,
                description = ?5, action = ?6,
                object_types_json = ?7, requires_disclosure_json = ?8,
                returns_json = ?9, endpoint_json = ?10,
                llm_instructions = ?11, subagents_json = ?12,
                published_to_json = ?13, updated_at = ?14
             WHERE agent_did = ?15",
                params![
                    def.schema_version,
                    def.version,
                    def.name,
                    def.provider,
                    def.description,
                    def.action,
                    object_types_json,
                    requires_disclosure_json,
                    returns_json,
                    endpoint_json,
                    def.llm_instructions,
                    subagents_json,
                    published_to_json,
                    def.updated_at,
                    agent_did,
                ],
            )
            .map_err(|e| DbError(format!("db update agent: {e}")))?;
        if rows_changed == 0 {
            return Err(DbError(format!("Agent not found: {agent_did}")));
        }
        Ok(())
    }

    fn delete_agent(&self, agent_did: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let rows_changed = conn
            .execute(
                "DELETE FROM agents WHERE agent_did = ?1",
                params![agent_did],
            )
            .map_err(|e| DbError(format!("db delete agent: {e}")))?;
        if rows_changed == 0 {
            return Err(DbError(format!("Agent not found: {agent_did}")));
        }
        Ok(())
    }

    fn apply_retention_policy(&self) -> Result<super::RetentionStats, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

        // Read the active retention policy.
        let policy_row: Option<(i64, i64, i64, f64)> = conn
            .query_row(
                "SELECT max_full_episodes, full_retention_days, compressed_retention_days,
                         failure_retention_multiplier
                  FROM retention_policies WHERE name = 'default'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| DbError(format!("db read policy: {e}")))?;

        let (max_full, full_days, compressed_days, failure_mult) = match policy_row {
            Some(r) => r,
            None => return Ok(super::RetentionStats::default()), // no policy → no-op
        };

        let mut stats = super::RetentionStats::default();

        // ── Phase 1: Age-based compression ────────────────────────────────
        //
        // Compress Active episodes older than `full_retention_days`.
        // Failures use `failure_retention_multiplier × full_retention_days`.
        //
        // SQLite date arithmetic: julianday('now') - julianday(recorded_at) gives age in days.

        let success_compress_threshold = full_days as f64;
        let failure_compress_threshold = full_days as f64 * failure_mult;

        let compressed_age = conn
            .execute(
                "UPDATE episodes
                    SET decay_state = 'Compressed', result_json = NULL
                  WHERE decay_state = 'Active'
                    AND (
                        (outcome != 'failure'
                         AND julianday('now') - julianday(recorded_at) > ?1)
                        OR
                        (outcome = 'failure'
                         AND julianday('now') - julianday(recorded_at) > ?2)
                    )",
                params![success_compress_threshold, failure_compress_threshold],
            )
            .map_err(|e| DbError(format!("db compress by age: {e}")))?;

        stats.compressed += compressed_age;

        // ── Phase 2: Count-based compression ──────────────────────────────
        //
        // If total Active episodes exceed max_full_episodes, compress the oldest
        // ones (by recorded_at) beyond the cap. Only success/rejected are eligible —
        // failures already get extra time via the age path above.

        let active_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM episodes WHERE decay_state = 'Active' AND outcome != 'failure'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| DbError(format!("db count active: {e}")))?;

        let excess = active_count - max_full;
        if excess > 0 {
            let compressed_count = conn
                .execute(
                    "UPDATE episodes
                        SET decay_state = 'Compressed', result_json = NULL
                      WHERE id IN (
                          SELECT id FROM episodes
                           WHERE decay_state = 'Active' AND outcome != 'failure'
                           ORDER BY recorded_at ASC
                           LIMIT ?1
                      )",
                    params![excess],
                )
                .map_err(|e| DbError(format!("db compress by count: {e}")))?;

            stats.compressed += compressed_count;
        }

        // ── Phase 3: Delete expired compressed episodes ────────────────────
        //
        // Delete Compressed episodes older than `compressed_retention_days`.
        // Failures again use the multiplier.

        let success_delete_threshold = compressed_days as f64;
        let failure_delete_threshold = compressed_days as f64 * failure_mult;

        let deleted = conn
            .execute(
                "DELETE FROM episodes
                  WHERE decay_state = 'Compressed'
                    AND (
                        (outcome != 'failure'
                         AND julianday('now') - julianday(recorded_at) > ?1)
                        OR
                        (outcome = 'failure'
                         AND julianday('now') - julianday(recorded_at) > ?2)
                    )",
                params![success_delete_threshold, failure_delete_threshold],
            )
            .map_err(|e| DbError(format!("db delete expired: {e}")))?;

        stats.deleted += deleted;

        Ok(stats)
    }

    // ── Chat persistence ──────────────────────────────────────────────────

    fn upsert_conversation(&self, conversation: &super::Conversation) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute(
            "INSERT INTO conversations (id, name, is_group, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                name       = excluded.name,
                is_group   = excluded.is_group,
                updated_at = excluded.updated_at",
            params![
                conversation.id,
                conversation.name,
                conversation.is_group as i64,
                conversation.created_at,
                conversation.updated_at,
            ],
        )
        .map_err(|e| DbError(format!("db upsert conversation: {e}")))?;
        Ok(())
    }

    fn list_conversations(&self) -> Result<Vec<super::Conversation>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, name, is_group, created_at, updated_at
                 FROM conversations
                 ORDER BY updated_at DESC",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                let is_group_int: i64 = row.get(2)?;
                Ok(super::Conversation {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    is_group: is_group_int != 0,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            })
            .map_err(|e| DbError(format!("db query conversations: {e}")))?;
        let mut conversations = Vec::new();
        for row in rows {
            conversations.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(conversations)
    }

    fn insert_chat_message(&self, message: &super::ChatMessage) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute(
            "INSERT OR IGNORE INTO chat_messages
                (id, conversation_id, author_did, content, created_at, delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                message.id,
                message.conversation_id,
                message.author_did,
                message.content,
                message.created_at,
                message.delivered as i64,
            ],
        )
        .map_err(|e| DbError(format!("db insert chat message: {e}")))?;
        Ok(())
    }

    fn mark_message_delivered(&self, message_id: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute(
            "UPDATE chat_messages SET delivered = 1 WHERE id = ?1",
            params![message_id],
        )
        .map_err(|e| DbError(format!("db mark delivered: {e}")))?;
        Ok(())
    }

    fn list_chat_messages(
        &self,
        conversation_id: &str,
        limit: usize,
    ) -> Result<Vec<super::ChatMessage>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, conversation_id, author_did, content, created_at, delivered
                 FROM chat_messages
                 WHERE conversation_id = ?1
                 ORDER BY created_at ASC
                 LIMIT ?2",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;
        let rows = stmt
            .query_map(params![conversation_id, limit as i64], |row| {
                let delivered_int: i64 = row.get(5)?;
                Ok(super::ChatMessage {
                    id: row.get(0)?,
                    conversation_id: row.get(1)?,
                    author_did: row.get(2)?,
                    content: row.get(3)?,
                    created_at: row.get(4)?,
                    delivered: delivered_int != 0,
                })
            })
            .map_err(|e| DbError(format!("db query chat messages: {e}")))?;
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(messages)
    }

    // ── Preference Learning ───────────────────────────────────────────────

    fn upsert_preference(&self, signal: &super::PreferenceSignal) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute(
            "INSERT INTO preferences (
                id, action_type, schema_type, agent_did_hash, agent_name,
                selection_count, success_count, last_selected,
                approved_scope_refs, rejected_scope_refs, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(action_type, schema_type, agent_did_hash) DO UPDATE SET
                agent_name           = excluded.agent_name,
                selection_count      = excluded.selection_count,
                success_count        = excluded.success_count,
                last_selected        = excluded.last_selected,
                approved_scope_refs  = excluded.approved_scope_refs,
                rejected_scope_refs  = excluded.rejected_scope_refs,
                updated_at           = excluded.updated_at",
            params![
                signal.id,
                signal.action_type,
                signal.schema_type,
                signal.agent_did_hash,
                signal.agent_name,
                signal.selection_count,
                signal.success_count,
                signal.last_selected,
                signal.approved_scope_refs,
                signal.rejected_scope_refs,
                signal.updated_at,
            ],
        )
        .map_err(|e| DbError(format!("db upsert preference: {e}")))?;
        Ok(())
    }

    fn get_preference(
        &self,
        action_type: &str,
        schema_type: &str,
        agent_did_hash: &str,
    ) -> Result<Option<super::PreferenceSignal>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.query_row(
            "SELECT id, action_type, schema_type, agent_did_hash, agent_name,
                    selection_count, success_count, last_selected,
                    approved_scope_refs, rejected_scope_refs, updated_at
             FROM preferences
             WHERE action_type = ?1 AND schema_type = ?2 AND agent_did_hash = ?3",
            params![action_type, schema_type, agent_did_hash],
            Self::map_preference_row,
        )
        .optional()
        .map_err(|e| DbError(format!("db get preference: {e}")))
    }

    fn list_preferences_for_schema(
        &self,
        action_type: &str,
        schema_type: &str,
    ) -> Result<Vec<super::PreferenceSignal>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, action_type, schema_type, agent_did_hash, agent_name,
                        selection_count, success_count, last_selected,
                        approved_scope_refs, rejected_scope_refs, updated_at
                 FROM preferences
                 WHERE action_type = ?1 AND schema_type = ?2
                 ORDER BY selection_count DESC",
            )
            .map_err(|e| DbError(format!("db prepare preferences: {e}")))?;
        let rows = stmt
            .query_map(params![action_type, schema_type], Self::map_preference_row)
            .map_err(|e| DbError(format!("db query preferences: {e}")))?;
        let mut signals = Vec::new();
        for row in rows {
            signals.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(signals)
    }

    // ── Canvas CRUD ───────────────────────────────────────────────────────

    fn upsert_canvas(&self, canvas: &CanvasRecord) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute(
            "INSERT INTO canvases (id, name, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 updated_at = excluded.updated_at",
            params![canvas.id, canvas.name, canvas.created_at, canvas.updated_at],
        )
        .map_err(|e| DbError(format!("db upsert canvas: {e}")))?;
        Ok(())
    }

    fn list_canvases(&self) -> Result<Vec<CanvasRecord>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, name, created_at, updated_at
                 FROM canvases
                 ORDER BY updated_at DESC",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(CanvasRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_at: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })
            .map_err(|e| DbError(format!("db query canvases: {e}")))?;
        let mut canvases = Vec::new();
        for row in rows {
            canvases.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(canvases)
    }

    fn delete_canvas(&self, id: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute("DELETE FROM canvases WHERE id = ?1", params![id])
            .map_err(|e| DbError(format!("db delete canvas: {e}")))?;
        Ok(())
    }

    fn upsert_canvas_block(&self, block: &CanvasBlockRecord) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute(
            "INSERT INTO canvas_blocks (
                id, canvas_id, prompt_text, schema_type, content_json,
                block_state, episode_id, agent_did, mandate_expires_at,
                preference_guided, display_order, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            ON CONFLICT(id) DO UPDATE SET
                canvas_id = excluded.canvas_id,
                prompt_text = excluded.prompt_text,
                schema_type = excluded.schema_type,
                content_json = excluded.content_json,
                block_state = excluded.block_state,
                episode_id = excluded.episode_id,
                agent_did = excluded.agent_did,
                mandate_expires_at = excluded.mandate_expires_at,
                preference_guided = excluded.preference_guided,
                display_order = excluded.display_order,
                updated_at = excluded.updated_at",
            params![
                block.id,
                block.canvas_id,
                block.prompt_text,
                block.schema_type,
                block.content_json,
                block.block_state,
                block.episode_id,
                block.agent_did,
                block.mandate_expires_at,
                block.preference_guided as i64,
                block.display_order,
                block.created_at,
                block.updated_at,
            ],
        )
        .map_err(|e| DbError(format!("db upsert canvas block: {e}")))?;
        Ok(())
    }

    fn list_canvas_blocks(&self, canvas_id: &str) -> Result<Vec<CanvasBlockRecord>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, canvas_id, prompt_text, schema_type, content_json,
                        block_state, episode_id, agent_did, mandate_expires_at,
                        preference_guided, display_order, created_at, updated_at
                 FROM canvas_blocks
                 WHERE canvas_id = ?1
                 ORDER BY display_order ASC",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;
        let rows = stmt
            .query_map(params![canvas_id], |row| {
                Ok(CanvasBlockRecord {
                    id: row.get(0)?,
                    canvas_id: row.get(1)?,
                    prompt_text: row.get(2)?,
                    schema_type: row.get(3)?,
                    content_json: row.get(4)?,
                    block_state: row.get(5)?,
                    episode_id: row.get(6)?,
                    agent_did: row.get(7)?,
                    mandate_expires_at: row.get(8)?,
                    preference_guided: {
                        let v: i64 = row.get(9)?;
                        v != 0
                    },
                    display_order: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })
            .map_err(|e| DbError(format!("db query canvas blocks: {e}")))?;
        let mut blocks = Vec::new();
        for row in rows {
            blocks.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(blocks)
    }

    fn delete_canvas_block(&self, id: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute("DELETE FROM canvas_blocks WHERE id = ?1", params![id])
            .map_err(|e| DbError(format!("db delete canvas block: {e}")))?;
        Ok(())
    }

    fn insert_canvas_message(&self, msg: &CanvasMessageRecord) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute(
            "INSERT INTO canvas_messages (id, canvas_id, role, content, block_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                msg.id,
                msg.canvas_id,
                msg.role,
                msg.content,
                msg.block_id,
                msg.created_at,
            ],
        )
        .map_err(|e| DbError(format!("db insert canvas message: {e}")))?;
        Ok(())
    }

    fn list_canvas_messages(&self, canvas_id: &str) -> Result<Vec<CanvasMessageRecord>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, canvas_id, role, content, block_id, created_at
                 FROM canvas_messages
                 WHERE canvas_id = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;
        let rows = stmt
            .query_map(params![canvas_id], |row| {
                Ok(CanvasMessageRecord {
                    id: row.get(0)?,
                    canvas_id: row.get(1)?,
                    role: row.get(2)?,
                    content: row.get(3)?,
                    block_id: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .map_err(|e| DbError(format!("db query canvas messages: {e}")))?;
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(messages)
    }

    // ── Saved Pipeline CRUD ───────────────────────────────────────────────

    fn upsert_saved_pipeline(
        &self,
        id: &str,
        name: &str,
        description: &str,
        pipeline: &PipelineInfo,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let pipeline_json = serde_json::to_string(pipeline)
            .map_err(|e| DbError(format!("serialize pipeline: {e}")))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO saved_pipelines (id, name, description, pipeline_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                 name          = excluded.name,
                 description   = excluded.description,
                 pipeline_json = excluded.pipeline_json,
                 updated_at    = excluded.updated_at",
            params![id, name, description, pipeline_json, now, now],
        )
        .map_err(|e| DbError(format!("db upsert saved_pipeline: {e}")))?;
        Ok(())
    }

    fn list_saved_pipelines(&self) -> Result<Vec<SavedPipeline>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, name, description, pipeline_json, created_at, updated_at
                 FROM saved_pipelines
                 ORDER BY created_at DESC",
            )
            .map_err(|e| DbError(format!("db prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                let pipeline_json: String = row.get(3)?;
                let pipeline: PipelineInfo = serde_json::from_str(&pipeline_json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(SavedPipeline {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    pipeline,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })
            .map_err(|e| DbError(format!("db query saved_pipelines: {e}")))?;
        let mut pipelines = Vec::new();
        for row in rows {
            pipelines.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
        }
        Ok(pipelines)
    }

    fn delete_saved_pipeline(&self, id: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute("DELETE FROM saved_pipelines WHERE id = ?1", params![id])
            .map_err(|e| DbError(format!("db delete saved_pipeline: {e}")))?;
        Ok(())
    }

    // ── Dynamic Agent Def CRUD ────────────────────────────────────────────────

    fn upsert_agent_def(&self, name: &str, json: &str) -> Result<(), DbError> {
        // Validate JSON is well-formed before storing
        serde_json::from_str::<serde_json::Value>(json).map_err(|e| {
            DbError(format!(
                "upsert_agent_def: invalid JSON for '{}': {e}",
                name
            ))
        })?;
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO agent_defs (name, json) VALUES (?1, ?2)",
            params![name, json],
        )
        .map_err(|e| DbError(format!("db upsert agent_def: {e}")))?;
        Ok(())
    }

    fn list_agent_defs(&self) -> Result<Vec<String>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT json FROM agent_defs ORDER BY name")
            .map_err(|e| DbError(format!("db prepare agent_defs: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| DbError(format!("db query agent_defs: {e}")))?;
        let mut defs = Vec::new();
        for row in rows {
            defs.push(row.map_err(|e| DbError(format!("db row agent_def: {e}")))?);
        }
        Ok(defs)
    }

    fn get_agent_def(&self, name: &str) -> Result<Option<String>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.query_row(
            "SELECT json FROM agent_defs WHERE name = ?1",
            params![name],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| DbError(format!("db get agent_def: {e}")))
    }

    fn delete_agent_def(&self, name: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.execute("DELETE FROM agent_defs WHERE name = ?1", params![name])
            .map_err(|e| DbError(format!("db delete agent_def: {e}")))?;
        Ok(())
    }

    fn set_principal_attribute(&self, prop: &str, value: &str) -> Result<(), DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO principal_attributes (prop_name, value, last_used) VALUES (?1, ?2, ?3)
             ON CONFLICT(prop_name) DO UPDATE SET value = excluded.value, last_used = excluded.last_used",
            params![prop, value, now],
        )
        .map_err(|e| DbError(format!("db set_principal_attribute: {e}")))?;
        Ok(())
    }

    fn get_principal_attribute(&self, prop: &str) -> Result<Option<String>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        conn.query_row(
            "SELECT value FROM principal_attributes WHERE prop_name = ?1",
            params![prop],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| DbError(format!("db get_principal_attribute: {e}")))
    }

    fn get_all_principal_attributes(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, DbError> {
        let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT prop_name, value FROM principal_attributes ORDER BY last_used DESC")
            .map_err(|e| DbError(format!("db get_all_principal_attributes: {e}")))?;
        let map: Result<std::collections::HashMap<String, String>, _> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| DbError(format!("db get_all_principal_attributes query: {e}")))?
            .map(|r| r.map_err(|e| DbError(format!("db row: {e}"))))
            .collect();
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pap_agents::HttpMethod;

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

    // ── Retention policy tests ───────────────────────────────────────────

    /// Insert an episode with a manually overridden recorded_at timestamp.
    fn old_episode(id: &str, days_ago: i64) -> Episode {
        let ts = chrono::Utc::now() - chrono::Duration::days(days_ago);
        Episode {
            recorded_at: ts.to_rfc3339(),
            ..sample_episode(id)
        }
    }

    fn failure_episode(id: &str, days_ago: i64) -> Episode {
        let ts = chrono::Utc::now() - chrono::Duration::days(days_ago);
        Episode {
            outcome: "failure".to_string(),
            recorded_at: ts.to_rfc3339(),
            ..sample_episode(id)
        }
    }

    #[test]
    fn retention_no_op_when_no_policy_row() {
        // Delete the default policy row that migrate() inserts, then run reducer.
        let db = test_db();
        db.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM retention_policies WHERE name = 'default'", [])
            .unwrap();
        db.insert_episode(&sample_episode("ep-1")).unwrap();
        let stats = db.apply_retention_policy().unwrap();
        assert_eq!(stats.compressed, 0);
        assert_eq!(stats.deleted, 0);
        // episode is untouched
        let eps = db.list_episodes(None, None, 10, None).unwrap();
        assert_eq!(eps[0].decay_state, "Active");
    }

    #[test]
    fn retention_compresses_old_success_episodes() {
        let db = test_db();
        // Policy: full_retention_days=90
        // Insert an episode 100 days old — should be compressed.
        db.insert_episode(&old_episode("old", 100)).unwrap();
        db.insert_episode(&sample_episode("new")).unwrap(); // recorded_at = now, stays Active

        let stats = db.apply_retention_policy().unwrap();
        assert_eq!(stats.compressed, 1);
        assert_eq!(stats.deleted, 0);

        let eps = db.list_episodes(None, None, 10, None).unwrap();
        let old = eps.iter().find(|e| e.id == "old").unwrap();
        let new = eps.iter().find(|e| e.id == "new").unwrap();
        assert_eq!(old.decay_state, "Compressed");
        assert!(
            old.result_json.is_none(),
            "result_json must be nulled after compression"
        );
        assert_eq!(new.decay_state, "Active");
        assert!(
            new.result_json.is_some(),
            "recent episode result_json must be preserved"
        );
    }

    #[test]
    fn retention_failure_episodes_live_longer() {
        let db = test_db();
        // Policy: full_retention_days=90, failure_retention_multiplier=2.0
        // So failures should not be compressed until 180 days.
        // Insert a failure at 100 days — should NOT be compressed yet.
        db.insert_episode(&failure_episode("fail-100", 100))
            .unwrap();
        // Insert a failure at 200 days — SHOULD be compressed.
        db.insert_episode(&failure_episode("fail-200", 200))
            .unwrap();

        let stats = db.apply_retention_policy().unwrap();
        assert_eq!(stats.compressed, 1);

        let eps = db.list_episodes(None, None, 10, None).unwrap();
        let fail100 = eps.iter().find(|e| e.id == "fail-100").unwrap();
        let fail200 = eps.iter().find(|e| e.id == "fail-200").unwrap();
        assert_eq!(
            fail100.decay_state, "Active",
            "100-day failure should still be Active"
        );
        assert_eq!(
            fail200.decay_state, "Compressed",
            "200-day failure should be Compressed"
        );
    }

    #[test]
    fn retention_count_cap_compresses_oldest() {
        let db = test_db();
        // Set max_full_episodes = 2 so that with 4 episodes, 2 oldest get compressed.
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE retention_policies SET max_full_episodes = 2 WHERE name = 'default'",
                [],
            )
            .unwrap();

        // Insert 4 episodes with staggered times (all within 90-day window).
        for i in 1..=4_i64 {
            db.insert_episode(&old_episode(&format!("ep-{i}"), i))
                .unwrap();
        }

        let stats = db.apply_retention_policy().unwrap();
        assert_eq!(stats.compressed, 2); // 2 oldest compressed to get down to cap

        let eps = db.list_episodes(None, None, 10, None).unwrap();
        let active: Vec<_> = eps.iter().filter(|e| e.decay_state == "Active").collect();
        let compressed: Vec<_> = eps
            .iter()
            .filter(|e| e.decay_state == "Compressed")
            .collect();
        assert_eq!(active.len(), 2);
        assert_eq!(compressed.len(), 2);
        // The two oldest (ep-4, ep-3) should be compressed.
        assert!(compressed.iter().any(|e| e.id == "ep-4"));
        assert!(compressed.iter().any(|e| e.id == "ep-3"));
    }

    #[test]
    fn retention_deletes_expired_compressed_episodes() {
        let db = test_db();
        // Policy: compressed_retention_days=365
        // Insert a Compressed episode at 400 days — should be deleted.
        let mut ep = old_episode("stale", 400);
        ep.decay_state = "Compressed".to_string();
        ep.result_json = None;
        db.insert_episode(&ep).unwrap();

        // Also insert a recently-compressed episode — should NOT be deleted.
        let mut recent = old_episode("recent-compressed", 10);
        recent.decay_state = "Compressed".to_string();
        recent.result_json = None;
        db.insert_episode(&recent).unwrap();

        let stats = db.apply_retention_policy().unwrap();
        assert_eq!(stats.deleted, 1);

        let eps = db.list_episodes(None, None, 10, None).unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].id, "recent-compressed");
    }

    #[test]
    fn retention_reducer_is_idempotent() {
        let db = test_db();
        db.insert_episode(&old_episode("ep-1", 100)).unwrap();

        let stats1 = db.apply_retention_policy().unwrap();
        let stats2 = db.apply_retention_policy().unwrap();

        assert_eq!(stats1.compressed, 1);
        // Second run: already Compressed, nothing left to compress.
        assert_eq!(stats2.compressed, 0);
        assert_eq!(stats2.deleted, 0);
    }

    fn sample_template(id: &str, name: &str) -> crate::types::Template {
        crate::types::Template {
            id: id.to_string(),
            template_name: name.to_string(),
            schema_type: "FlightReservation".to_string(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".to_string(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".to_string()),
                },
                fields: vec![crate::types::FieldMapping {
                    path: "name".to_string(),
                    label: Some("Name".to_string()),
                    display: "title".to_string(),
                    condition: None,
                    style: None,
                }],
            },
            version: 1,
            enabled: true,
            created_at: "2026-03-21T12:00:00Z".to_string(),
            updated_at: "2026-03-21T12:00:00Z".to_string(),
            created_by: None,
            agent_did: None,
        }
    }

    #[test]
    fn template_insert_and_query() {
        let db = test_db();
        let t = sample_template("t-1", "flight_tpl");

        db.insert_template(&t).unwrap();

        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].template_name, "flight_tpl");
        assert_eq!(all[0].schema_type, "FlightReservation");
        assert_eq!(all[0].template_config.fields.len(), 1);
    }

    #[test]
    fn template_list_enabled_filters_disabled() {
        let db = test_db();

        let mut enabled = sample_template("t-1", "enabled_tpl");
        enabled.enabled = true;

        let mut disabled = sample_template("t-2", "disabled_tpl");
        disabled.enabled = false;

        db.insert_template(&enabled).unwrap();
        db.insert_template(&disabled).unwrap();

        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 2);

        let enabled_only = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(enabled_only.len(), 1);
        assert_eq!(enabled_only[0].template_name, "enabled_tpl");
    }

    #[test]
    fn template_update() {
        let db = test_db();
        let t = sample_template("t-1", "my_tpl");
        db.insert_template(&t).unwrap();

        let mut updated = t.clone();
        updated.schema_type = "HotelReservation".to_string();
        updated.version = 2;
        db.update_template(&updated).unwrap();

        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].schema_type, "HotelReservation");
        assert_eq!(all[0].version, 2);
    }

    #[test]
    fn template_update_not_found() {
        let db = test_db();
        let t = sample_template("nonexistent", "ghost");
        assert!(db.update_template(&t).is_err());
    }

    #[test]
    fn template_delete() {
        let db = test_db();
        db.insert_template(&sample_template("t-1", "to_delete"))
            .unwrap();

        db.delete_template("to_delete").unwrap();
        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 0);
    }

    #[test]
    fn template_delete_not_found() {
        let db = test_db();
        assert!(db.delete_template("nonexistent").is_err());
    }

    #[test]
    fn template_enable_disable() {
        let db = test_db();
        db.insert_template(&sample_template("t-1", "toggleable"))
            .unwrap();

        db.set_template_enabled("toggleable", false).unwrap();

        let enabled = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(enabled.len(), 0);

        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 1);
        assert!(!all[0].enabled);

        db.set_template_enabled("toggleable", true).unwrap();
        let enabled = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(enabled.len(), 1);
    }

    #[test]
    fn template_enable_not_found() {
        let db = test_db();
        assert!(db.set_template_enabled("nonexistent", true).is_err());
    }

    #[test]
    fn template_principal_filtering() {
        let db = test_db();

        let mut global = sample_template("t-1", "global_tpl");
        global.principal_did = None;

        let mut alice = sample_template("t-2", "alice_tpl");
        alice.principal_did = Some("did:pap:alice".to_string());

        let mut bob = sample_template("t-3", "bob_tpl");
        bob.principal_did = Some("did:pap:bob".to_string());

        db.insert_template(&global).unwrap();
        db.insert_template(&alice).unwrap();
        db.insert_template(&bob).unwrap();

        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 3);

        // Alice sees global + alice = 2
        let alice_tpls = db.query_templates(Some("did:pap:alice")).unwrap();
        assert_eq!(alice_tpls.len(), 2);

        // Bob sees global + bob = 2
        let bob_tpls = db.query_templates(Some("did:pap:bob")).unwrap();
        assert_eq!(bob_tpls.len(), 2);

        // Enabled list for alice = global + alice = 2
        let alice_enabled = db
            .list_enabled_templates_for_principal(Some("did:pap:alice"))
            .unwrap();
        assert_eq!(alice_enabled.len(), 2);
    }

    #[test]
    fn template_config_roundtrips_through_sql() {
        let db = test_db();

        let config = crate::types::TemplateConfig {
            version: 1,
            layout: crate::types::LayoutConfig {
                r#type: "flex".to_string(),
                columns: None,
                direction: Some("column".to_string()),
                spacing: Some("lg".to_string()),
            },
            fields: vec![
                crate::types::FieldMapping {
                    path: "name".to_string(),
                    label: Some("Name".to_string()),
                    display: "title".to_string(),
                    condition: None,
                    style: Some(crate::types::StyleConfig {
                        class_name: Some("bold".to_string()),
                        color: Some("#6c5ce7".to_string()),
                    }),
                },
                crate::types::FieldMapping {
                    path: "offers.0.price".to_string(),
                    label: Some("Price".to_string()),
                    display: "price".to_string(),
                    condition: Some(crate::types::Condition {
                        field: "offers".to_string(),
                        op: "exists".to_string(),
                        value: None,
                    }),
                    style: None,
                },
            ],
        };

        let mut t = sample_template("t-1", "complex_tpl");
        t.template_config = config.clone();
        db.insert_template(&t).unwrap();

        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].template_config, config);
    }

    #[test]
    fn has_enabled_template_for_schema_type_returns_true_when_exists() {
        let db = test_db();
        let t = sample_template("t-1", "flight_tpl");
        db.insert_template(&t).unwrap();

        assert!(db
            .has_enabled_template_for_schema_type("FlightReservation")
            .unwrap());
        assert!(!db
            .has_enabled_template_for_schema_type("HotelReservation")
            .unwrap());
    }

    #[test]
    fn has_enabled_template_for_schema_type_ignores_disabled() {
        let db = test_db();
        let t = sample_template("t-1", "disabled_flight");
        db.insert_template(&t).unwrap();
        db.set_template_enabled("disabled_flight", false).unwrap();

        assert!(!db
            .has_enabled_template_for_schema_type("FlightReservation")
            .unwrap());
    }

    #[test]
    fn auto_generated_template_does_not_overwrite_user_template() {
        let db = test_db();

        // User creates a template first
        let user_template = sample_template("user-1", "user_flight");
        db.insert_template(&user_template).unwrap();

        // Orchestrator checks before inserting
        let exists = db
            .has_enabled_template_for_schema_type("FlightReservation")
            .unwrap();
        assert!(exists);

        // Verify only the user template is in the DB
        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].template_name, "user_flight");
    }

    fn sample_agent_def(agent_did: &str, catalog_path: Option<&str>) -> DynamicAgentDef {
        DynamicAgentDef {
            agent_did: Some(agent_did.to_string()),
            schema_version: 1,
            version: "0.1.0".into(),
            name: format!("Test Agent {agent_did}"),
            provider: "Test Provider".to_string(),
            description: "A test agent".to_string(),
            action: "schema:SearchAction".to_string(),
            object_types: vec!["schema:WebPage".to_string()],
            requires_disclosure: vec![],
            returns: vec!["schema:SearchResult".to_string()],
            endpoint: Some(HttpEndpointConfig {
                url_template: "https://api.example.com/search?q={query}".to_string(),
                method: HttpMethod::Get,
                headers: std::collections::HashMap::new(),
                body_template: None,
                response_jsonpath: "$.results[*]".to_string(),
                response_schema_type: "schema:SearchResult".to_string(),
                response_mapping: std::collections::HashMap::new(),
                timeout_secs: 5,
            }),
            llm_instructions: "You are a search assistant.".to_string(),
            subagents: vec![],
            source: DynamicAgentSource::Catalog,
            operator_key_seed: Some([42u8; 32]),
            published_to: vec![],
            catalog_path: catalog_path.map(|s| s.to_string()),
            configurable_properties: vec![],
            created_at: "2026-04-01T00:00:00Z".to_string(),
            updated_at: "2026-04-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn insert_and_load_agent_round_trip() {
        let db = test_db();
        let def = sample_agent_def("did:key:zTestAgent1", Some("search/test.toml"));
        db.insert_agent(&def).unwrap();
        let agents = db.load_all_agents().unwrap();
        assert_eq!(agents.len(), 1);
        let loaded = &agents[0];
        assert_eq!(loaded.agent_did, def.agent_did);
        assert_eq!(loaded.version, "0.1.0");
        assert_eq!(loaded.name, def.name);
        assert_eq!(loaded.source, DynamicAgentSource::Catalog);
        assert_eq!(loaded.operator_key_seed, Some([42u8; 32]));
        assert_eq!(loaded.catalog_path, Some("search/test.toml".to_string()));
        assert!(loaded.endpoint.is_some());
        let ep = loaded.endpoint.as_ref().unwrap();
        assert_eq!(ep.url_template, "https://api.example.com/search?q={query}");
        assert_eq!(ep.method, HttpMethod::Get);
    }

    #[test]
    fn catalog_path_unique_constraint() {
        let db = test_db();
        let def1 = sample_agent_def("did:key:zAgent1", Some("search/test.toml"));
        let def2 = sample_agent_def("did:key:zAgent2", Some("search/test.toml"));
        db.insert_agent(&def1).unwrap();
        let result = db.insert_agent(&def2);
        assert!(result.is_err(), "duplicate catalog_path should be rejected");
    }

    #[test]
    fn load_agents_excludes_removed() {
        let db = test_db();
        let active = sample_agent_def("did:key:zActive", Some("search/active.toml"));
        db.insert_agent(&active).unwrap();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE agents SET removed_from_catalog = 1 WHERE agent_did = ?1",
                params!["did:key:zActive"],
            )
            .unwrap();
        }
        let agents = db.load_all_agents().unwrap();
        assert_eq!(
            agents.len(),
            0,
            "removed agents must be excluded from load_all_agents"
        );
    }

    #[test]
    fn auto_generated_template_roundtrips_through_db() {
        let db = test_db();
        let content = serde_json::json!({
            "name": "Test Recipe",
            "totalTime": "PT30M",
            "totalPrice": 12.99,
            "url": "https://example.com/recipe"
        });

        let template = crate::template_gen::generate_template_from_json_ld("Recipe", &content);

        assert!(template.template_config.validate().is_ok());

        db.insert_template(&template).unwrap();

        let loaded = db.query_templates(None).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].schema_type, "Recipe");
        assert_eq!(loaded[0].created_by, Some("orchestrator".to_string()));
        assert_eq!(
            loaded[0].template_config.fields.len(),
            template.template_config.fields.len()
        );
    }

    // ── FTS5 search_episodes ──────────────────────────────────────────────

    #[test]
    fn fts5_search_finds_by_query_field() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        // The sample episode has query = "rust sqlite"
        let results = db.search_episodes("sqlite", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "ep-1");
    }

    #[test]
    fn fts5_search_finds_by_intent_summary() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        // The sample episode has intent_summary = "Search for rust sqlite"
        let results = db.search_episodes("rust", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn fts5_search_finds_by_agent_name() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        // The sample episode has agent_name = "DuckDuckGo Search"
        let results = db.search_episodes("DuckDuckGo", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn fts5_search_no_match_returns_empty() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        let results = db.search_episodes("nonexistentterm12345", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn fts5_search_limit_respected() {
        let db = test_db();
        for i in 0..5 {
            db.insert_episode(&sample_episode(&format!("ep-{i}")))
                .unwrap();
        }

        let results = db.search_episodes("sqlite", 3).unwrap();
        assert!(results.len() <= 3);
    }

    #[test]
    fn fts5_search_text_delegates_to_fts() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        // search_text should produce the same results as search_episodes
        let via_text = db.search_text("sqlite", 10).unwrap();
        let via_fts = db.search_episodes("sqlite", 10).unwrap();
        assert_eq!(via_text.len(), via_fts.len());
    }

    // ── query_by_action ───────────────────────────────────────────────────

    #[test]
    fn query_by_action_exact_match() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        // Sample episodes use action_type = "schema:SearchAction"
        let results = db.query_by_action("schema:SearchAction", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "ep-1");
    }

    #[test]
    fn query_by_action_no_match_for_different_action() {
        let db = test_db();
        db.insert_episode(&sample_episode("ep-1")).unwrap();

        let results = db.query_by_action("schema:BookAction", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn query_by_action_limit_respected() {
        let db = test_db();
        for i in 0..5 {
            db.insert_episode(&sample_episode(&format!("ep-{i}")))
                .unwrap();
        }

        let results = db.query_by_action("schema:SearchAction", 3).unwrap();
        assert!(results.len() <= 3);
    }

    #[test]
    fn query_by_action_ordered_by_recorded_at_desc() {
        let db = test_db();

        let ep_old = Episode {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            ..sample_episode("ep-old")
        };
        let ep_new = Episode {
            recorded_at: "2026-06-01T00:00:00Z".to_string(),
            ..sample_episode("ep-new")
        };
        db.insert_episode(&ep_old).unwrap();
        db.insert_episode(&ep_new).unwrap();

        let results = db.query_by_action("schema:SearchAction", 10).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].id, "ep-new");
        assert_eq!(results[1].id, "ep-old");
    }

    // ── Chat persistence tests ────────────────────────────────────────────

    fn sample_conversation(id: &str, is_group: bool) -> super::super::Conversation {
        super::super::Conversation {
            id: id.to_string(),
            name: format!("Room {id}"),
            is_group,
            created_at: "2026-04-01T10:00:00Z".to_string(),
            updated_at: "2026-04-01T10:00:00Z".to_string(),
        }
    }

    fn sample_chat_message(id: &str, conversation_id: &str) -> super::super::ChatMessage {
        super::super::ChatMessage {
            id: id.to_string(),
            conversation_id: conversation_id.to_string(),
            author_did: "did:key:zSender".to_string(),
            content: r#"{"body":{"content":"hello"}}"#.to_string(),
            created_at: format!("2026-04-01T10:0{id}:00Z"),
            delivered: false,
        }
    }

    #[test]
    fn upsert_and_list_conversations() {
        let db = test_db();
        db.upsert_conversation(&sample_conversation("conv-1", false))
            .unwrap();
        db.upsert_conversation(&sample_conversation("conv-2", true))
            .unwrap();
        let convs = db.list_conversations().unwrap();
        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn upsert_conversation_updates_existing() {
        let db = test_db();
        db.upsert_conversation(&sample_conversation("conv-1", false))
            .unwrap();
        let updated = super::super::Conversation {
            name: "Renamed Room".to_string(),
            is_group: true,
            updated_at: "2026-04-02T10:00:00Z".to_string(),
            ..sample_conversation("conv-1", false)
        };
        db.upsert_conversation(&updated).unwrap();
        let convs = db.list_conversations().unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].name, "Renamed Room");
        assert!(convs[0].is_group);
    }

    #[test]
    fn insert_and_list_chat_messages() {
        let db = test_db();
        db.upsert_conversation(&sample_conversation("conv-1", false))
            .unwrap();
        db.insert_chat_message(&sample_chat_message("1", "conv-1"))
            .unwrap();
        db.insert_chat_message(&sample_chat_message("2", "conv-1"))
            .unwrap();
        let msgs = db.list_chat_messages("conv-1", 100).unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(!msgs[0].delivered);
        // ordered oldest-first by created_at
        assert!(msgs[0].created_at <= msgs[1].created_at);
    }

    #[test]
    fn mark_chat_message_delivered() {
        let db = test_db();
        db.upsert_conversation(&sample_conversation("conv-1", false))
            .unwrap();
        db.insert_chat_message(&sample_chat_message("1", "conv-1"))
            .unwrap();
        db.mark_message_delivered("msg-1").unwrap(); // no-op for non-existent is fine
        db.mark_message_delivered("1").unwrap();
        let msgs = db.list_chat_messages("conv-1", 100).unwrap();
        assert!(msgs[0].delivered);
    }

    #[test]
    fn list_messages_respects_limit() {
        let db = test_db();
        db.upsert_conversation(&sample_conversation("conv-1", false))
            .unwrap();
        for i in 0..5_u8 {
            db.insert_chat_message(&sample_chat_message(&i.to_string(), "conv-1"))
                .unwrap();
        }
        let msgs = db.list_chat_messages("conv-1", 3).unwrap();
        assert_eq!(msgs.len(), 3);
    }

    #[test]
    fn insert_chat_message_ignores_duplicate_id() {
        let db = test_db();
        db.upsert_conversation(&sample_conversation("conv-1", false))
            .unwrap();
        db.insert_chat_message(&sample_chat_message("1", "conv-1"))
            .unwrap();
        db.insert_chat_message(&sample_chat_message("1", "conv-1"))
            .unwrap(); // dup
        let msgs = db.list_chat_messages("conv-1", 100).unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn list_messages_scoped_to_conversation() {
        let db = test_db();
        db.upsert_conversation(&sample_conversation("conv-a", false))
            .unwrap();
        db.upsert_conversation(&sample_conversation("conv-b", false))
            .unwrap();
        db.insert_chat_message(&sample_chat_message("1", "conv-a"))
            .unwrap();
        db.insert_chat_message(&sample_chat_message("2", "conv-b"))
            .unwrap();
        let msgs_a = db.list_chat_messages("conv-a", 100).unwrap();
        let msgs_b = db.list_chat_messages("conv-b", 100).unwrap();
        assert_eq!(msgs_a.len(), 1);
        assert_eq!(msgs_b.len(), 1);
        assert_eq!(msgs_a[0].id, "1");
        assert_eq!(msgs_b[0].id, "2");
    }

    // ── Agent settings version pinning ──────────────────────────────

    #[test]
    fn agent_setting_stores_and_retrieves_with_version() {
        let db = test_db();
        db.set_agent_setting("did-hash-1", "safe_search", "true", "0.1.0")
            .unwrap();
        let settings = db.get_agent_settings("did-hash-1").unwrap();
        assert_eq!(settings.len(), 1);
        let s = settings.get("safe_search").unwrap();
        assert_eq!(s.value, "true");
        assert_eq!(s.agent_version, "0.1.0");
    }

    #[test]
    fn agent_setting_upsert_updates_version() {
        let db = test_db();
        db.set_agent_setting("did-hash-1", "safe_search", "true", "0.1.0")
            .unwrap();
        // Agent bumps version → user reconfigures → new version stored
        db.set_agent_setting("did-hash-1", "safe_search", "false", "0.2.0")
            .unwrap();
        let settings = db.get_agent_settings("did-hash-1").unwrap();
        let s = settings.get("safe_search").unwrap();
        assert_eq!(s.value, "false");
        assert_eq!(s.agent_version, "0.2.0");
    }

    #[test]
    fn agent_setting_delete_removes_override() {
        let db = test_db();
        db.set_agent_setting("did-hash-1", "units", "\"imperial\"", "0.1.0")
            .unwrap();
        db.delete_agent_setting("did-hash-1", "units").unwrap();
        let settings = db.get_agent_settings("did-hash-1").unwrap();
        assert!(settings.is_empty());
    }

    #[test]
    fn agent_settings_scoped_by_did_hash() {
        let db = test_db();
        db.set_agent_setting("agent-a", "safe_search", "true", "0.1.0")
            .unwrap();
        db.set_agent_setting("agent-b", "units", "\"metric\"", "1.0.0")
            .unwrap();
        let a = db.get_agent_settings("agent-a").unwrap();
        let b = db.get_agent_settings("agent-b").unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert!(a.contains_key("safe_search"));
        assert!(b.contains_key("units"));
    }

    #[test]
    fn agent_version_round_trips_through_agents_table() {
        let db = test_db();
        let mut def = sample_agent_def("did:key:zVersioned", Some("test/versioned.toml"));
        def.version = "1.2.3".into();
        db.insert_agent(&def).unwrap();
        let agents = db.load_all_agents().unwrap();
        assert_eq!(agents[0].version, "1.2.3");
    }

    // ── Canvas persistence ───────────────────────────────────────────────

    fn sample_canvas(id: &str) -> CanvasRecord {
        CanvasRecord {
            id: id.to_string(),
            name: format!("Canvas {id}"),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn sample_canvas_block(id: &str, canvas_id: &str, order: i64) -> CanvasBlockRecord {
        CanvasBlockRecord {
            id: id.to_string(),
            canvas_id: canvas_id.to_string(),
            prompt_text: Some(format!("query for {id}")),
            schema_type: Some("schema:SearchAction".to_string()),
            content_json: None,
            block_state: "resolving".to_string(),
            episode_id: None,
            agent_did: None,
            mandate_expires_at: None,
            preference_guided: false,
            display_order: order,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn sample_canvas_message(
        id: &str,
        canvas_id: &str,
        role: &str,
        ts_suffix: &str,
    ) -> CanvasMessageRecord {
        CanvasMessageRecord {
            id: id.to_string(),
            canvas_id: canvas_id.to_string(),
            role: role.to_string(),
            content: format!("message content {id}"),
            block_id: None,
            created_at: format!("2026-01-01T00:00:{ts_suffix}Z"),
        }
    }

    #[test]
    fn canvas_upsert_and_list() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        db.upsert_canvas(&sample_canvas("c-2")).unwrap();
        let canvases = db.list_canvases().unwrap();
        assert_eq!(canvases.len(), 2);
        assert!(canvases.iter().any(|c| c.id == "c-1"));
        assert!(canvases.iter().any(|c| c.id == "c-2"));
    }

    #[test]
    fn canvas_upsert_updates_name() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        let mut updated = sample_canvas("c-1");
        updated.name = "Renamed Canvas".to_string();
        db.upsert_canvas(&updated).unwrap();
        let canvases = db.list_canvases().unwrap();
        assert_eq!(canvases.len(), 1);
        assert_eq!(canvases[0].name, "Renamed Canvas");
    }

    #[test]
    fn canvas_delete_removes_canvas() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        db.upsert_canvas(&sample_canvas("c-2")).unwrap();
        db.delete_canvas("c-1").unwrap();
        let canvases = db.list_canvases().unwrap();
        assert_eq!(canvases.len(), 1);
        assert_eq!(canvases[0].id, "c-2");
    }

    #[test]
    fn canvas_block_upsert_and_list() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        db.upsert_canvas_block(&sample_canvas_block("b-1", "c-1", 0))
            .unwrap();
        let blocks = db.list_canvas_blocks("c-1").unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].id, "b-1");
        assert_eq!(blocks[0].prompt_text.as_deref(), Some("query for b-1"));
    }

    #[test]
    fn canvas_block_upsert_updates_state() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        db.upsert_canvas_block(&sample_canvas_block("b-1", "c-1", 0))
            .unwrap();
        let mut resolved = sample_canvas_block("b-1", "c-1", 0);
        resolved.block_state = "resolved".to_string();
        resolved.content_json = Some(r#"{"@type":"SearchResult"}"#.to_string());
        db.upsert_canvas_block(&resolved).unwrap();
        let blocks = db.list_canvas_blocks("c-1").unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_state, "resolved");
        assert!(blocks[0].content_json.is_some());
    }

    #[test]
    fn canvas_blocks_ordered_by_display_order() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        db.upsert_canvas_block(&sample_canvas_block("b-3", "c-1", 2))
            .unwrap();
        db.upsert_canvas_block(&sample_canvas_block("b-1", "c-1", 0))
            .unwrap();
        db.upsert_canvas_block(&sample_canvas_block("b-2", "c-1", 1))
            .unwrap();
        let blocks = db.list_canvas_blocks("c-1").unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].id, "b-1");
        assert_eq!(blocks[1].id, "b-2");
        assert_eq!(blocks[2].id, "b-3");
    }

    #[test]
    fn canvas_block_delete() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        db.upsert_canvas_block(&sample_canvas_block("b-1", "c-1", 0))
            .unwrap();
        db.delete_canvas_block("b-1").unwrap();
        let blocks = db.list_canvas_blocks("c-1").unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn canvas_delete_cascades_to_blocks_and_messages() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        db.upsert_canvas_block(&sample_canvas_block("b-1", "c-1", 0))
            .unwrap();
        db.insert_canvas_message(&sample_canvas_message("m-1", "c-1", "user", "01"))
            .unwrap();
        // Delete the canvas — blocks and messages should cascade
        db.delete_canvas("c-1").unwrap();
        let blocks = db.list_canvas_blocks("c-1").unwrap();
        let msgs = db.list_canvas_messages("c-1").unwrap();
        assert!(
            blocks.is_empty(),
            "blocks should cascade-delete with canvas"
        );
        assert!(
            msgs.is_empty(),
            "messages should cascade-delete with canvas"
        );
    }

    #[test]
    fn canvas_message_insert_and_list() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        db.insert_canvas_message(&sample_canvas_message("m-1", "c-1", "user", "01"))
            .unwrap();
        db.insert_canvas_message(&sample_canvas_message("m-2", "c-1", "assistant", "02"))
            .unwrap();
        let msgs = db.list_canvas_messages("c-1").unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[1].role, "assistant");
    }

    #[test]
    fn canvas_messages_ordered_chronologically() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-1")).unwrap();
        // Insert in reverse order
        db.insert_canvas_message(&sample_canvas_message("m-3", "c-1", "user", "03"))
            .unwrap();
        db.insert_canvas_message(&sample_canvas_message("m-1", "c-1", "user", "01"))
            .unwrap();
        db.insert_canvas_message(&sample_canvas_message("m-2", "c-1", "user", "02"))
            .unwrap();
        let msgs = db.list_canvas_messages("c-1").unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].id, "m-1");
        assert_eq!(msgs[1].id, "m-2");
        assert_eq!(msgs[2].id, "m-3");
    }

    #[test]
    fn canvas_messages_scoped_to_canvas() {
        let db = test_db();
        db.upsert_canvas(&sample_canvas("c-a")).unwrap();
        db.upsert_canvas(&sample_canvas("c-b")).unwrap();
        db.insert_canvas_message(&sample_canvas_message("m-1", "c-a", "user", "01"))
            .unwrap();
        db.insert_canvas_message(&sample_canvas_message("m-2", "c-b", "user", "01"))
            .unwrap();
        let msgs_a = db.list_canvas_messages("c-a").unwrap();
        let msgs_b = db.list_canvas_messages("c-b").unwrap();
        assert_eq!(msgs_a.len(), 1);
        assert_eq!(msgs_b.len(), 1);
        assert_eq!(msgs_a[0].id, "m-1");
        assert_eq!(msgs_b[0].id, "m-2");
    }

    // ── Saved Pipeline tests ──────────────────────────────────────────────

    fn sample_pipeline_info(id: &str) -> crate::types::PipelineInfo {
        crate::types::PipelineInfo {
            id: id.to_string(),
            name: format!("Pipeline {id}"),
            nodes: vec![
                crate::types::PipelineNodeInfo {
                    id: "n-1".to_string(),
                    agent_hash: "hash-a".to_string(),
                    agent_name: "Agent A".to_string(),
                    action_type: "schema:SearchAction".to_string(),
                    node_type: crate::types::PipelineNodeType::Agent,
                    position_x: 0.0,
                    position_y: 0.0,
                    format: Default::default(),
                },
                crate::types::PipelineNodeInfo {
                    id: "n-2".to_string(),
                    agent_hash: "hash-b".to_string(),
                    agent_name: "Agent B".to_string(),
                    action_type: "schema:SearchAction".to_string(),
                    node_type: crate::types::PipelineNodeType::Agent,
                    position_x: 200.0,
                    position_y: 0.0,
                    format: Default::default(),
                },
            ],
            edges: vec![crate::types::PipelineEdgeInfo {
                from_node: "n-1".to_string(),
                to_node: "n-2".to_string(),
            }],
            created_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn saved_pipeline_upsert_and_list() {
        let db = test_db();
        let pipeline = sample_pipeline_info("pipe-1");

        db.upsert_saved_pipeline("sp-1", "My Pipeline", "A test pipeline", &pipeline)
            .unwrap();

        let list = db.list_saved_pipelines().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "sp-1");
        assert_eq!(list[0].name, "My Pipeline");
        assert_eq!(list[0].description, "A test pipeline");
        assert_eq!(list[0].pipeline.nodes.len(), 2);
        assert_eq!(list[0].pipeline.edges.len(), 1);
        assert_eq!(list[0].pipeline.nodes[0].agent_name, "Agent A");
    }

    #[test]
    fn saved_pipeline_update_name() {
        let db = test_db();
        let pipeline = sample_pipeline_info("pipe-1");

        db.upsert_saved_pipeline("sp-1", "Original Name", "desc", &pipeline)
            .unwrap();

        // Upsert again with the same id but a different name — should update.
        db.upsert_saved_pipeline("sp-1", "Updated Name", "new desc", &pipeline)
            .unwrap();

        let list = db.list_saved_pipelines().unwrap();
        assert_eq!(list.len(), 1, "upsert must not insert duplicate rows");
        assert_eq!(list[0].name, "Updated Name");
        assert_eq!(list[0].description, "new desc");
    }

    #[test]
    fn saved_pipeline_delete() {
        let db = test_db();
        let pipeline = sample_pipeline_info("pipe-1");

        db.upsert_saved_pipeline("sp-1", "Pipeline A", "", &pipeline)
            .unwrap();
        db.upsert_saved_pipeline("sp-2", "Pipeline B", "", &pipeline)
            .unwrap();

        let before = db.list_saved_pipelines().unwrap();
        assert_eq!(before.len(), 2);

        db.delete_saved_pipeline("sp-1").unwrap();

        let after = db.list_saved_pipelines().unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, "sp-2");
    }

    #[test]
    fn saved_pipeline_delete_nonexistent_is_noop() {
        let db = test_db();
        // Deleting an id that does not exist must not error.
        db.delete_saved_pipeline("does-not-exist").unwrap();
    }

    // ── agent_defs table tests ────────────────────────────────────────────────

    #[test]
    fn agent_def_upsert_and_get() {
        let db = test_db();
        let json = r#"{"name":"weather","description":"Weather agent"}"#;
        db.upsert_agent_def("weather", json).unwrap();

        let result = db.get_agent_def("weather").unwrap();
        assert_eq!(result, Some(json.to_string()));
    }

    #[test]
    fn agent_def_upsert_replaces_existing() {
        let db = test_db();
        db.upsert_agent_def("weather", r#"{"name":"weather","v":1}"#)
            .unwrap();
        db.upsert_agent_def("weather", r#"{"name":"weather","v":2}"#)
            .unwrap();

        let result = db.get_agent_def("weather").unwrap().unwrap();
        assert!(result.contains("\"v\":2"), "expected v=2 but got {result}");
    }

    #[test]
    fn agent_def_get_missing_returns_none() {
        let db = test_db();
        assert_eq!(db.get_agent_def("nonexistent").unwrap(), None);
    }

    #[test]
    fn agent_def_list_returns_all() {
        let db = test_db();
        db.upsert_agent_def("agent-a", r#"{"name":"agent-a"}"#)
            .unwrap();
        db.upsert_agent_def("agent-b", r#"{"name":"agent-b"}"#)
            .unwrap();

        let defs = db.list_agent_defs().unwrap();
        assert_eq!(defs.len(), 2);
    }

    #[test]
    fn agent_def_delete_removes_entry() {
        let db = test_db();
        db.upsert_agent_def("weather", r#"{"name":"weather"}"#)
            .unwrap();
        db.delete_agent_def("weather").unwrap();

        assert_eq!(db.get_agent_def("weather").unwrap(), None);
        assert_eq!(db.list_agent_defs().unwrap().len(), 0);
    }

    #[test]
    fn agent_def_delete_nonexistent_is_noop() {
        let db = test_db();
        // Must not return an error when the name doesn't exist.
        db.delete_agent_def("nonexistent").unwrap();
    }

    // ── principal_attributes tests ────────────────────────────────────────────

    #[test]
    fn principal_attributes_round_trip() {
        let db = NativeDatabase::open_memory().unwrap();
        db.set_principal_attribute("schema:givenName", "Alice")
            .unwrap();
        let v = db.get_principal_attribute("schema:givenName").unwrap();
        assert_eq!(v, Some("Alice".to_string()));
    }

    #[test]
    fn principal_attributes_upsert() {
        let db = NativeDatabase::open_memory().unwrap();
        db.set_principal_attribute("schema:givenName", "Alice")
            .unwrap();
        db.set_principal_attribute("schema:givenName", "Bob")
            .unwrap();
        let v = db.get_principal_attribute("schema:givenName").unwrap();
        assert_eq!(v, Some("Bob".to_string()));
    }

    #[test]
    fn principal_attributes_missing_returns_none() {
        let db = NativeDatabase::open_memory().unwrap();
        let v = db.get_principal_attribute("schema:nonexistent").unwrap();
        assert_eq!(v, None);
    }

    #[test]
    fn get_all_principal_attributes_returns_all() {
        let db = NativeDatabase::open_memory().unwrap();
        db.set_principal_attribute("schema:givenName", "Alice")
            .unwrap();
        db.set_principal_attribute("schema:departureAirport", "LAX")
            .unwrap();
        let map = db.get_all_principal_attributes().unwrap();
        assert_eq!(map.get("schema:givenName"), Some(&"Alice".to_string()));
        assert_eq!(map.get("schema:departureAirport"), Some(&"LAX".to_string()));
        assert_eq!(map.len(), 2);
    }
}

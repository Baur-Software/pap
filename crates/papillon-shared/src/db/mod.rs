//! Database abstraction layer for Papillon.
//!
//! This module provides a unified interface for database operations that works
//! across desktop (rusqlite) and web (sql.js) targets.
//!
//! The abstraction is implemented via feature flags:
//! - `native`: Uses rusqlite (desktop, default)
//! - `wasm`: Uses sql.js (web)
//! - `wasm` + IndexedDB: Wraps WasmDatabase with browser persistence

#[cfg(feature = "native")]
use crate::types::PipelineInfo;
use crate::types::Template;
#[cfg(feature = "native")]
use crate::types::{CanvasBlockRecord, CanvasMessageRecord, CanvasRecord, SavedPipeline};
#[cfg(feature = "native")]
use pap_agents::DynamicAgentDef;
use serde::{Deserialize, Serialize};

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "wasm")]
pub mod idb;

#[cfg(feature = "wasm")]
pub mod indexed_db;

#[cfg(test)]
mod e2e_tests;

// Re-export the appropriate implementation based on feature flags
#[cfg(feature = "native")]
pub use native::NativeDatabase as Database;

#[cfg(feature = "wasm")]
pub use indexed_db::IndexedDbDatabase as Database;

// ── Data types ───────────────────────────────────────────────

/// A single recorded interaction episode, anchored to a co-signed receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Full JSON-LD result payload
    pub result_json: Option<String>,
    pub query: Option<String>,
    pub recorded_at: String,
}

/// Aggregated agent performance profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Error type for database operations
#[derive(Debug, Clone)]
pub struct DbError(pub String);

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DbError {}

impl<T: Into<String>> From<T> for DbError {
    fn from(err: T) -> Self {
        DbError(err.into())
    }
}

/// Common database trait defining the interface for both native and WASM backends.
pub trait DatabaseOps: Send + Sync {
    /// Record an episode
    fn insert_episode(&self, episode: &Episode) -> Result<(), DbError>;

    /// List episodes with optional filters
    fn list_episodes(
        &self,
        action_type: Option<&str>,
        agent_did_hash: Option<&str>,
        limit: usize,
        offset: Option<i64>,
    ) -> Result<Vec<Episode>, DbError>;

    /// Count total episodes
    fn episode_count(&self) -> Result<usize, DbError>;

    /// Upsert an agent profile
    fn upsert_agent_profile(&self, profile: &AgentProfile) -> Result<(), DbError>;

    /// Get an agent profile by DID hash
    fn get_agent_profile(&self, agent_did_hash: &str) -> Result<Option<AgentProfile>, DbError>;

    /// List all agent profiles
    fn list_agent_profiles(&self) -> Result<Vec<AgentProfile>, DbError>;

    /// Get a setting value
    fn get_setting(&self, key: &str) -> Result<Option<String>, DbError>;

    /// Set a setting value
    fn set_setting(&self, key: &str, value: &str) -> Result<(), DbError>;

    /// Search episodes by Schema.org @type
    fn search_by_schema_type(
        &self,
        schema_type: &str,
        limit: usize,
    ) -> Result<Vec<Episode>, DbError>;

    /// Full-text search over episode fields (delegates to FTS5 on native)
    fn search_text(&self, query: &str, limit: usize) -> Result<Vec<Episode>, DbError>;

    /// FTS5 full-text search over action_type, intent_summary, query, agent_name columns.
    ///
    /// Results are ranked by FTS5 relevance (best match first).  Returns at most
    /// `limit` episodes.  The `query` string uses standard FTS5 match syntax; any
    /// double-quotes are stripped before execution to prevent syntax errors.
    fn search_episodes(&self, query: &str, limit: usize) -> Result<Vec<Episode>, DbError>;

    /// Exact action-type match using the `idx_episodes_action_type` index.
    ///
    /// Returns at most `limit` episodes ordered by `recorded_at DESC`.
    fn query_by_action(&self, action: &str, limit: usize) -> Result<Vec<Episode>, DbError>;

    // ── Template Management ───────────────────────────────────────────────

    /// List all templates (enabled and disabled), optionally filtered by principal
    fn query_templates(&self, principal_did: Option<&str>) -> Result<Vec<Template>, DbError>;

    /// List all templates enabled for a principal (or global if None)
    fn list_enabled_templates_for_principal(
        &self,
        principal_did: Option<&str>,
    ) -> Result<Vec<Template>, DbError>;

    /// Insert a new template
    fn insert_template(&self, template: &Template) -> Result<(), DbError>;

    /// Update an existing template
    fn update_template(&self, template: &Template) -> Result<(), DbError>;

    /// Delete a template by name
    fn delete_template(&self, template_name: &str) -> Result<(), DbError>;

    /// Enable or disable a template
    fn set_template_enabled(&self, template_name: &str, enabled: bool) -> Result<(), DbError>;

    /// Check if any enabled template exists for the given schema type.
    fn has_enabled_template_for_schema_type(&self, schema_type: &str) -> Result<bool, DbError>;

    /// Apply the active retention policy to the episode store.
    ///
    /// Two-phase reducer:
    /// 1. **Compress** — episodes older than `full_retention_days` (or success episodes beyond
    ///    `max_full_episodes`) have their `result_json` nulled and `decay_state` set to
    ///    `"Compressed"`. Failure episodes use `failure_retention_multiplier × full_retention_days`.
    /// 2. **Delete** — episodes already in `"Compressed"` state and older than
    ///    `compressed_retention_days` are permanently removed. Again, failures use the multiplier.
    ///
    /// The policy values are read from the `retention_policies` table (`name = 'default'`).
    /// If no policy row exists the call is a no-op.
    ///
    /// Returns the number of episodes compressed and deleted.
    fn apply_retention_policy(&self) -> Result<RetentionStats, DbError>;

    // ── Agent Settings (per-agent local overrides) ─────────────────────

    /// Store a per-agent setting override pinned to the agent's current version.
    /// The key is (agent_did_hash, value_name). `value` is a JSON-encoded string.
    /// `agent_version` is the semver of the agent when the override was configured.
    fn set_agent_setting(
        &self,
        agent_did_hash: &str,
        value_name: &str,
        value: &str,
        agent_version: &str,
    ) -> Result<(), DbError>;

    /// Retrieve all setting overrides for a specific agent.
    /// Returns a map of value_name → (value, agent_version) so callers can
    /// detect stale overrides when the agent has bumped its version.
    fn get_agent_settings(
        &self,
        agent_did_hash: &str,
    ) -> Result<std::collections::HashMap<String, AgentSettingOverride>, DbError>;

    /// Delete a single agent setting (reset to default from advertisement).
    fn delete_agent_setting(&self, agent_did_hash: &str, value_name: &str) -> Result<(), DbError>;

    // ── Agent Management (native only) ───────────────────────────────────
    // pap-agents pulls in reqwest::blocking → tokio → mio which does not compile
    // for wasm32-unknown-unknown. These methods are only available in the native build.

    /// Insert a new dynamic agent definition.
    #[cfg(feature = "native")]
    fn insert_agent(&self, def: &DynamicAgentDef) -> Result<(), DbError>;

    /// Load all non-removed agent definitions.
    #[cfg(feature = "native")]
    fn load_all_agents(&self) -> Result<Vec<DynamicAgentDef>, DbError>;

    /// Update an existing agent definition in-place (same agent_did).
    #[cfg(feature = "native")]
    fn update_agent(&self, def: &DynamicAgentDef) -> Result<(), DbError>;

    /// Delete an agent by DID. Catalog agents should use removed_from_catalog instead.
    #[cfg(feature = "native")]
    fn delete_agent(&self, agent_did: &str) -> Result<(), DbError>;

    // ── Chat persistence (native only) ────────────────────────────────────

    /// Insert or update a conversation record.
    #[cfg(feature = "native")]
    fn upsert_conversation(&self, conversation: &Conversation) -> Result<(), DbError>;

    /// List all conversations ordered by updated_at descending.
    #[cfg(feature = "native")]
    fn list_conversations(&self) -> Result<Vec<Conversation>, DbError>;

    /// Insert a chat message.
    #[cfg(feature = "native")]
    fn insert_chat_message(&self, message: &ChatMessage) -> Result<(), DbError>;

    /// Mark a message as delivered.
    #[cfg(feature = "native")]
    fn mark_message_delivered(&self, message_id: &str) -> Result<(), DbError>;

    /// List messages for a conversation, oldest first, up to `limit`.
    #[cfg(feature = "native")]
    fn list_chat_messages(
        &self,
        conversation_id: &str,
        limit: usize,
    ) -> Result<Vec<ChatMessage>, DbError>;

    // ── Preference Learning (native only) ─────────────────────────────────
    // All preference data is stored locally. No row is ever transmitted over
    // the network. These methods are native-only because the WASM build has
    // no persistent backing store for preference signals.

    /// Upsert a preference signal row, incrementing selection_count and
    /// updating success_count / scope refs atomically.
    #[cfg(feature = "native")]
    fn upsert_preference(&self, signal: &PreferenceSignal) -> Result<(), DbError>;

    /// Retrieve the preference signal for a specific (action_type, schema_type,
    /// agent_did_hash) triple. Returns `None` if no row exists yet.
    #[cfg(feature = "native")]
    fn get_preference(
        &self,
        action_type: &str,
        schema_type: &str,
        agent_did_hash: &str,
    ) -> Result<Option<PreferenceSignal>, DbError>;

    /// List all preference signals for the given (action_type, schema_type) pair,
    /// ordered by selection_count descending (most preferred first).
    #[cfg(feature = "native")]
    fn list_preferences_for_schema(
        &self,
        action_type: &str,
        schema_type: &str,
    ) -> Result<Vec<PreferenceSignal>, DbError>;

    // ── Canvas CRUD (native only) ─────────────────────────────────────────

    /// Insert or update a canvas record.
    #[cfg(feature = "native")]
    fn upsert_canvas(&self, canvas: &CanvasRecord) -> Result<(), DbError>;

    /// List all canvases, ordered by updated_at descending.
    #[cfg(feature = "native")]
    fn list_canvases(&self) -> Result<Vec<CanvasRecord>, DbError>;

    /// Delete a canvas and all its blocks and messages (CASCADE).
    #[cfg(feature = "native")]
    fn delete_canvas(&self, id: &str) -> Result<(), DbError>;

    /// Insert or update a canvas block record.
    #[cfg(feature = "native")]
    fn upsert_canvas_block(&self, block: &CanvasBlockRecord) -> Result<(), DbError>;

    /// List all blocks for a canvas, ordered by display_order ascending.
    #[cfg(feature = "native")]
    fn list_canvas_blocks(&self, canvas_id: &str) -> Result<Vec<CanvasBlockRecord>, DbError>;

    /// Delete a single canvas block by ID.
    #[cfg(feature = "native")]
    fn delete_canvas_block(&self, id: &str) -> Result<(), DbError>;

    /// Insert a canvas message.
    #[cfg(feature = "native")]
    fn insert_canvas_message(&self, msg: &CanvasMessageRecord) -> Result<(), DbError>;

    /// List all messages for a canvas, ordered by created_at ascending.
    #[cfg(feature = "native")]
    fn list_canvas_messages(&self, canvas_id: &str) -> Result<Vec<CanvasMessageRecord>, DbError>;

    // ── Saved Pipeline CRUD (native only) ────────────────────────────────────

    /// Upsert a saved pipeline (insert or replace by id).
    #[cfg(feature = "native")]
    fn upsert_saved_pipeline(
        &self,
        id: &str,
        name: &str,
        description: &str,
        pipeline: &PipelineInfo,
    ) -> Result<(), DbError>;

    /// List all saved pipelines ordered by created_at DESC.
    #[cfg(feature = "native")]
    fn list_saved_pipelines(&self) -> Result<Vec<SavedPipeline>, DbError>;

    /// Delete a saved pipeline by id. No-op if not found.
    #[cfg(feature = "native")]
    fn delete_saved_pipeline(&self, id: &str) -> Result<(), DbError>;

    // ── Dynamic Agent Def CRUD (available on all targets) ────────────────────
    // Uses a (name, json_string) interface to avoid a hard dependency on
    // pap-agents in the wasm feature set.  Callers are responsible for
    // serialising/deserialising the JSON string to/from their preferred type.

    /// Insert or replace a dynamic agent definition, keyed by name.
    /// `json` must be a valid JSON string representing the full definition.
    fn upsert_agent_def(&self, name: &str, json: &str) -> Result<(), DbError>;

    /// Return the raw JSON strings for all stored agent definitions.
    fn list_agent_defs(&self) -> Result<Vec<String>, DbError>;

    /// Return the raw JSON string for a single agent definition, or `None`.
    fn get_agent_def(&self, name: &str) -> Result<Option<String>, DbError>;

    /// Remove an agent definition by name.  No-op if the name is not found.
    fn delete_agent_def(&self, name: &str) -> Result<(), DbError>;
}

/// A preference signal recording which agent was selected for a given
/// (action_type, schema_type) pair, and the outcomes of those selections.
///
/// All data lives in the local SQLite database — no network calls ever read or
/// write this table.  The `PreferenceEngine` (see `preference_engine` module)
/// reads these rows to bias agent selection toward historically preferred agents
/// and to suggest approved mandate scopes for the same schema type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreferenceSignal {
    /// UUID row identifier.
    pub id: String,
    /// Schema.org action type exercised (e.g. "schema:SearchAction").
    pub action_type: String,
    /// Schema.org type of the agent's return value (e.g. "schema:SearchResult").
    /// Empty string when the agent advertises no specific returns type.
    pub schema_type: String,
    /// SHA-256 of the agent DID — never the raw DID.
    pub agent_did_hash: String,
    /// Human-readable agent name for display purposes only.
    pub agent_name: String,
    /// Number of times this agent was selected for this (action, schema) pair.
    pub selection_count: i64,
    /// Number of sessions that resulted in a "success" outcome.
    pub success_count: i64,
    /// ISO-8601 timestamp of the most recent selection.
    pub last_selected: String,
    /// JSON array of disclosure property refs the user approved for this schema type.
    pub approved_scope_refs: String,
    /// JSON array of disclosure property refs the user rejected for this schema type.
    pub rejected_scope_refs: String,
    /// ISO-8601 timestamp of the most recent update to this row.
    pub updated_at: String,
}

/// Summary of what the retention reducer did in a single pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionStats {
    pub compressed: usize,
    pub deleted: usize,
}

/// A single per-agent setting override, pinned to the agent version
/// it was configured against. When the agent bumps its version, stale
/// overrides are surfaced to the principal rather than silently applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSettingOverride {
    /// JSON-encoded setting value.
    pub value: String,
    /// Semver of the agent when this override was stored.
    pub agent_version: String,
}

// ── Chat types ────────────────────────────────────────────────

/// A chat conversation (1:1 or group room).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    /// Room DID (group) or session_id (1:1).
    pub id: String,
    pub name: String,
    pub is_group: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// A single chat message stored in SQLite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// UUID matching `StreamingMessage.id`.
    pub id: String,
    pub conversation_id: String,
    /// Session DID of the sender.
    pub author_did: String,
    /// JSON: DIDComm basicmessage body.
    pub content: String,
    pub created_at: String,
    pub delivered: bool,
}

//! Database abstraction layer for Papillon.
//!
//! This module provides a unified interface for database operations that works
//! across desktop (rusqlite) and web (sql.js) targets.
//!
//! The abstraction is implemented via feature flags:
//! - `native`: Uses rusqlite (desktop, default)
//! - `wasm`: Uses sql.js (web)
//! - `wasm` + IndexedDB: Wraps WasmDatabase with browser persistence

use crate::types::Template;
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
}

/// Summary of what the retention reducer did in a single pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionStats {
    pub compressed: usize,
    pub deleted: usize,
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

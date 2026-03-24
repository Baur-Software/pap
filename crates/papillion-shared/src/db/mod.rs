//! Database abstraction layer for Papillion.
//!
//! This module provides a unified interface for database operations that works
//! across desktop (rusqlite) and web (sql.js) targets.
//!
//! The abstraction is implemented via feature flags:
//! - `native`: Uses rusqlite (desktop, default)
//! - `wasm`: Uses sql.js (web)

use serde::Serialize;

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export the appropriate implementation based on feature flags
#[cfg(feature = "native")]
pub use native::NativeDatabase as Database;

#[cfg(feature = "wasm")]
pub use wasm::WasmDatabase as Database;

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
    /// Full JSON-LD result payload
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
    fn search_by_schema_type(&self, schema_type: &str, limit: usize) -> Result<Vec<Episode>, DbError>;

    /// Full-text search over episode fields
    fn search_text(&self, query: &str, limit: usize) -> Result<Vec<Episode>, DbError>;
}

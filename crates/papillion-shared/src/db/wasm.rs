//! WASM database implementation using sql.js.
//!
//! This backend is used on web platforms via sql.js, an in-memory SQLite database
//! compiled to WebAssembly. Data persists via browser's IndexedDB (not implemented here,
//! but can be layered on top).

use super::{AgentProfile, DatabaseOps, DbError, Episode};

/// Placeholder WASM database implementation.
///
/// Full sql.js integration requires:
/// 1. Adding sql-js dependency to Cargo.toml
/// 2. Implementing IndexedDB persistence wrapper
/// 3. Exposing the SQL API through web-sys bindings
///
/// For now, this is a stub that returns in-memory data suitable for testing.
pub struct WasmDatabase {
    // In a full implementation, this would hold a sql.js connection
    // conn: Arc<Mutex<sql_js::Database>>,
}

impl WasmDatabase {
    /// Create a new in-memory WASM database
    pub fn new() -> Result<Self, DbError> {
        // TODO: Initialize sql.js module and create connection
        // For now, this is a placeholder
        Ok(Self {})
    }

    /// Create or load from IndexedDB
    pub async fn new_with_persistence(_name: &str) -> Result<Self, DbError> {
        // TODO: Load from IndexedDB if exists, otherwise create new
        Ok(Self {})
    }
}

impl Default for WasmDatabase {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {})
    }
}

impl DatabaseOps for WasmDatabase {
    fn insert_episode(&self, _episode: &Episode) -> Result<(), DbError> {
        // TODO: Implement using sql.js INSERT
        Ok(())
    }

    fn list_episodes(
        &self,
        _action_type: Option<&str>,
        _agent_did_hash: Option<&str>,
        _limit: usize,
        _offset: Option<i64>,
    ) -> Result<Vec<Episode>, DbError> {
        // TODO: Implement using sql.js SELECT
        Ok(Vec::new())
    }

    fn episode_count(&self) -> Result<usize, DbError> {
        // TODO: Implement using sql.js COUNT
        Ok(0)
    }

    fn upsert_agent_profile(&self, _profile: &AgentProfile) -> Result<(), DbError> {
        // TODO: Implement using sql.js INSERT OR REPLACE
        Ok(())
    }

    fn get_agent_profile(&self, _agent_did_hash: &str) -> Result<Option<AgentProfile>, DbError> {
        // TODO: Implement using sql.js SELECT
        Ok(None)
    }

    fn list_agent_profiles(&self) -> Result<Vec<AgentProfile>, DbError> {
        // TODO: Implement using sql.js SELECT
        Ok(Vec::new())
    }

    fn get_setting(&self, _key: &str) -> Result<Option<String>, DbError> {
        // TODO: Implement using sql.js SELECT
        Ok(None)
    }

    fn set_setting(&self, _key: &str, _value: &str) -> Result<(), DbError> {
        // TODO: Implement using sql.js INSERT OR REPLACE
        Ok(())
    }

    fn search_by_schema_type(&self, _schema_type: &str, _limit: usize) -> Result<Vec<Episode>, DbError> {
        // TODO: Implement using sql.js JSON querying
        Ok(Vec::new())
    }

    fn search_text(&self, _query: &str, _limit: usize) -> Result<Vec<Episode>, DbError> {
        // TODO: Implement using sql.js LIKE queries
        Ok(Vec::new())
    }
}

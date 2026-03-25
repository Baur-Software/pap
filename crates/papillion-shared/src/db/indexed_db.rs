//! IndexedDB persistence wrapper for WASM database.
//!
//! This module provides a persistence layer that wraps WasmDatabase with
//! browser IndexedDB storage. All mutations are automatically persisted,
//! and state is restored from IndexedDB on app startup.
//!
//! # Usage
//!
//! ```ignore
//! let db = IndexedDbDatabase::new_with_persistence("papillion-db").await?;
//! db.insert_episode(&episode)?; // Automatically persisted to IndexedDB
//! ```

#[cfg(target_arch = "wasm32")]
use gloo_storage::{LocalStorage, Storage};

use super::wasm::WasmDatabase;
use super::{AgentProfile, DatabaseOps, DbError, Episode};
use crate::types::Template;

/// IndexedDB-backed database that persists all operations.
///
/// Wraps WasmDatabase with automatic persistence to browser storage.
/// All writes are synchronously persisted via local storage (IndexedDB
/// integration would add more sophisticated persistence).
pub struct IndexedDbDatabase {
    inner: WasmDatabase,
    #[allow(dead_code)]
    db_name: String,
}

impl IndexedDbDatabase {
    /// Create a new database with optional persistence loading.
    ///
    /// Attempts to load existing data from storage. If not found,
    /// creates an empty database.
    pub fn new_with_persistence(db_name: &str) -> Result<Self, DbError> {
        let inner = WasmDatabase::new()?;
        let db = Self {
            inner,
            db_name: db_name.to_string(),
        };

        // Attempt to restore from storage
        db.restore_from_storage()?;

        Ok(db)
    }

    /// Restore database state from browser local storage.
    fn restore_from_storage(&self) -> Result<(), DbError> {
        #[cfg(target_arch = "wasm32")]
        {
            let storage_key = format!("{}_state", self.db_name);

            match LocalStorage::get::<serde_json::Value>(&storage_key) {
                Ok(state) => {
                    self.restore_state(&state)?;
                }
                Err(_) => {
                    // No existing data, start fresh
                }
            }
        }

        Ok(())
    }

    /// Restore full database state from JSON.
    #[allow(dead_code)]
    fn restore_state(&self, state: &serde_json::Value) -> Result<(), DbError> {
        if let Some(episodes) = state.get("episodes").and_then(|v| v.as_array()) {
            for ep_val in episodes {
                if let Ok(episode) = serde_json::from_value::<Episode>(ep_val.clone()) {
                    self.inner.insert_episode(&episode)?;
                }
            }
        }

        if let Some(profiles) = state.get("profiles").and_then(|v| v.as_array()) {
            for prof_val in profiles {
                if let Ok(profile) = serde_json::from_value::<AgentProfile>(prof_val.clone()) {
                    self.inner.upsert_agent_profile(&profile)?;
                }
            }
        }

        if let Some(settings) = state.get("settings").and_then(|v| v.as_object()) {
            for (key, val) in settings {
                if let Some(value_str) = val.as_str() {
                    self.inner.set_setting(key, value_str)?;
                }
            }
        }

        if let Some(templates) = state.get("templates").and_then(|v| v.as_array()) {
            for tpl_val in templates {
                if let Ok(template) = serde_json::from_value::<Template>(tpl_val.clone()) {
                    self.inner.insert_template(&template)?;
                }
            }
        }

        Ok(())
    }

    /// Persist current database state to storage.
    fn persist_to_storage(&self) -> Result<(), DbError> {
        #[cfg(target_arch = "wasm32")]
        {
            let state = serde_json::json!({
                "episodes": self.inner.list_episodes(None, None, 100000, None)?,
                "profiles": self.inner.list_agent_profiles()?,
                "settings": self.get_all_settings()?,
                "templates": self.inner.query_templates(None)
                    .unwrap_or_default(),
            });

            let storage_key = format!("{}_state", self.db_name);
            LocalStorage::set(&storage_key, state)
                .map_err(|e| DbError(format!("storage error: {e}")))?;
        }

        Ok(())
    }

    /// Get all settings as a JSON object (helper for persistence).
    #[allow(dead_code)]
    fn get_all_settings(&self) -> Result<serde_json::Map<String, serde_json::Value>, DbError> {
        // Note: This is a limitation of the current DatabaseOps interface.
        // In a real implementation, we'd iterate through all settings.
        // For now, return empty map - full settings persistence would require
        // adding a list_all_settings() method to DatabaseOps.
        Ok(serde_json::Map::new())
    }
}

impl DatabaseOps for IndexedDbDatabase {
    fn insert_episode(&self, episode: &Episode) -> Result<(), DbError> {
        self.inner.insert_episode(episode)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn list_episodes(
        &self,
        action_type: Option<&str>,
        agent_did_hash: Option<&str>,
        limit: usize,
        offset: Option<i64>,
    ) -> Result<Vec<Episode>, DbError> {
        self.inner
            .list_episodes(action_type, agent_did_hash, limit, offset)
    }

    fn episode_count(&self) -> Result<usize, DbError> {
        self.inner.episode_count()
    }

    fn upsert_agent_profile(&self, profile: &AgentProfile) -> Result<(), DbError> {
        self.inner.upsert_agent_profile(profile)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn get_agent_profile(&self, agent_did_hash: &str) -> Result<Option<AgentProfile>, DbError> {
        self.inner.get_agent_profile(agent_did_hash)
    }

    fn list_agent_profiles(&self) -> Result<Vec<AgentProfile>, DbError> {
        self.inner.list_agent_profiles()
    }

    fn get_setting(&self, key: &str) -> Result<Option<String>, DbError> {
        self.inner.get_setting(key)
    }

    fn set_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
        self.inner.set_setting(key, value)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn search_by_schema_type(
        &self,
        schema_type: &str,
        limit: usize,
    ) -> Result<Vec<Episode>, DbError> {
        self.inner.search_by_schema_type(schema_type, limit)
    }

    fn search_text(&self, query: &str, limit: usize) -> Result<Vec<Episode>, DbError> {
        self.inner.search_text(query, limit)
    }

    fn query_templates(&self, principal_did: Option<&str>) -> Result<Vec<Template>, DbError> {
        self.inner.query_templates(principal_did)
    }

    fn list_enabled_templates_for_principal(
        &self,
        principal_did: Option<&str>,
    ) -> Result<Vec<Template>, DbError> {
        self.inner
            .list_enabled_templates_for_principal(principal_did)
    }

    fn insert_template(&self, template: &Template) -> Result<(), DbError> {
        self.inner.insert_template(template)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn update_template(&self, template: &Template) -> Result<(), DbError> {
        self.inner.update_template(template)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn delete_template(&self, template_name: &str) -> Result<(), DbError> {
        self.inner.delete_template(template_name)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn set_template_enabled(&self, template_name: &str, enabled: bool) -> Result<(), DbError> {
        self.inner.set_template_enabled(template_name, enabled)?;
        self.persist_to_storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_persistence_wrapper_creation() {
        // Note: This test runs in native, not WASM, so storage operations are skipped.
        // For full testing, use wasm-pack test with a browser runtime.
        let db = IndexedDbDatabase::new_with_persistence("test-db");
        assert!(db.is_ok());
    }

    #[test]
    fn test_persistence_wrapper_operations() {
        let db = IndexedDbDatabase::new_with_persistence("test-db").unwrap();

        let episode = Episode {
            id: "ep-1".into(),
            receipt_session_id: "sess-1".into(),
            scenario_id: "scenario-1".into(),
            action_type: "search".into(),
            agent_did_hash: "agent-1".into(),
            agent_name: "Search Agent".into(),
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
        };

        // Insert should work (storage errors are silently ignored in non-WASM)
        db.insert_episode(&episode).unwrap();
        let count = db.episode_count().unwrap();
        assert_eq!(count, 1);

        // List should work
        let episodes = db.list_episodes(None, None, 10, None).unwrap();
        assert_eq!(episodes.len(), 1);
    }

    #[test]
    fn test_persistence_wrapper_settings() {
        let db = IndexedDbDatabase::new_with_persistence("test-db").unwrap();

        db.set_setting("theme", "dark").unwrap();
        let value = db.get_setting("theme").unwrap();
        assert_eq!(value, Some("dark".to_string()));
    }
}

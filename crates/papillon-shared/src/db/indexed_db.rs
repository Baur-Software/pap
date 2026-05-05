//! IndexedDB persistence wrapper for WASM database.
//!
//! Wraps [`WasmDatabase`] with real browser IndexedDB storage so the
//! web build survives page reloads.  Every mutation is serialised to
//! JSON and written to IndexedDB asynchronously (fire-and-forget via
//! `spawn_local`).  On startup the async [`open`] constructor loads
//! the snapshot back into memory.
//!
//! Profile isolation is maintained by using one IndexedDB key per
//! principal DID — the caller passes the DID (or a hash of it) as
//! the `db_name` parameter.
//!
//! # Usage
//!
//! ```ignore
//! // Async constructor — loads existing state from IndexedDB
//! let db = IndexedDbDatabase::open("did:key:z6Mk...").await?;
//! db.insert_episode(&episode)?; // automatically persisted
//!
//! // Before tab close or profile switch, await pending writes:
//! db.flush().await?;
//! ```

use super::wasm::WasmDatabase;
use super::{AgentProfile, DatabaseOps, DbError, Episode};
use crate::types::Template;

/// Current snapshot format version. Bump when the schema changes so
/// `restore_state` can detect and migrate old snapshots.
const SNAPSHOT_VERSION: u64 = 2;

/// IndexedDB-backed database that persists all operations.
///
/// Wraps [`WasmDatabase`] (in-memory) and asynchronously serialises the
/// full state to IndexedDB after every write.  Reads are always served
/// from memory for zero-latency access.
pub struct IndexedDbDatabase {
    inner: WasmDatabase,
    #[allow(dead_code)] // used only on wasm32 targets
    db_name: String,
}

impl IndexedDbDatabase {
    /// Synchronous constructor — creates an empty database **without**
    /// loading from IndexedDB.  Useful for tests and non-browser contexts.
    pub fn new_with_persistence(db_name: &str) -> Result<Self, DbError> {
        Ok(Self {
            inner: WasmDatabase::new()?,
            db_name: db_name.to_string(),
        })
    }

    /// Async constructor — creates the database and loads any existing
    /// snapshot from IndexedDB.  This is the primary entry-point for the
    /// web build.
    #[cfg(target_arch = "wasm32")]
    pub async fn open(db_name: &str) -> Result<Self, DbError> {
        let inner = WasmDatabase::new()?;
        let db = Self {
            inner,
            db_name: db_name.to_string(),
        };

        match super::idb::load(db_name).await {
            Ok(Some(json_str)) => match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(state) => db.restore_state(&state)?,
                Err(e) => {
                    web_sys::console::error_1(
                        &format!(
                            "papillon: corrupt snapshot for {:?}, starting fresh: {}",
                            db_name, e
                        )
                        .into(),
                    );
                }
            },
            Ok(None) => { /* first launch for this profile */ }
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("papillon: failed to load from IndexedDB: {:?}", e).into(),
                );
            }
        }

        Ok(db)
    }

    /// Await the most recent IndexedDB write to completion.
    ///
    /// Call this before tab close or profile switch to guarantee the
    /// in-memory state has been flushed to disk.  In normal operation
    /// writes are fire-and-forget for responsiveness.
    #[cfg(target_arch = "wasm32")]
    pub async fn flush(&self) -> Result<(), DbError> {
        let json_str = self.build_snapshot_json()?;
        super::idb::save(&self.db_name, &json_str)
            .await
            .map_err(|e| DbError(format!("flush: {:?}", e)))
    }

    // ── internal helpers ──────────────────────────────────────────

    /// Restore full database state from a JSON snapshot.
    #[allow(dead_code)] // called from open() on wasm32 and from tests
    #[allow(clippy::unused_enumerate_index)] // index used in #[cfg(wasm32)] logging
    fn restore_state(&self, state: &serde_json::Value) -> Result<(), DbError> {
        // Check snapshot version (if missing, assume v1 — the first version)
        let _version = state.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
        // v1 snapshots have no "agents" key — key absence is sufficient for backward
        // compat; no branching on _version is needed.

        if let Some(episodes) = state.get("episodes").and_then(|v| v.as_array()) {
            for (_i, val) in episodes.iter().enumerate() {
                match serde_json::from_value::<Episode>(val.clone()) {
                    Ok(ep) => self.inner.insert_episode(&ep)?,
                    Err(e) => {
                        #[cfg(target_arch = "wasm32")]
                        web_sys::console::warn_1(
                            &format!("papillon: skipping corrupt episode[{}]: {}", _i, e).into(),
                        );
                        let _ = e;
                    }
                }
            }
        }

        if let Some(profiles) = state.get("profiles").and_then(|v| v.as_array()) {
            for (_i, val) in profiles.iter().enumerate() {
                match serde_json::from_value::<AgentProfile>(val.clone()) {
                    Ok(p) => self.inner.upsert_agent_profile(&p)?,
                    Err(e) => {
                        #[cfg(target_arch = "wasm32")]
                        web_sys::console::warn_1(
                            &format!("papillon: skipping corrupt profile[{}]: {}", _i, e).into(),
                        );
                        let _ = e;
                    }
                }
            }
        }

        if let Some(settings) = state.get("settings").and_then(|v| v.as_object()) {
            for (key, val) in settings {
                if let Some(v) = val.as_str() {
                    self.inner.set_setting(key, v)?;
                }
            }
        }

        if let Some(templates) = state.get("templates").and_then(|v| v.as_array()) {
            for (_i, val) in templates.iter().enumerate() {
                match serde_json::from_value::<Template>(val.clone()) {
                    Ok(t) => self.inner.insert_template(&t)?,
                    Err(e) => {
                        #[cfg(target_arch = "wasm32")]
                        web_sys::console::warn_1(
                            &format!("papillon: skipping corrupt template[{}]: {}", _i, e).into(),
                        );
                        let _ = e;
                    }
                }
            }
        }

        if let Some(attrs) = state
            .get("principal_attributes")
            .and_then(|v| v.as_object())
        {
            for (prop, val) in attrs {
                if let Some(v) = val.as_str() {
                    self.inner.set_principal_attribute(prop, v)?;
                }
            }
        }

        // v2+: agent defs stored as {"name": <name>, "json": <raw-json>} objects
        if let Some(agents) = state.get("agents").and_then(|v| v.as_array()) {
            for (_i, val) in agents.iter().enumerate() {
                let name = val.get("name").and_then(|v| v.as_str());
                let json = val.get("json").and_then(|v| v.as_str());
                match (name, json) {
                    (Some(n), Some(j)) => self.inner.upsert_agent_def(n, j)?,
                    _ => {
                        #[cfg(target_arch = "wasm32")]
                        web_sys::console::warn_1(
                            &format!(
                                "papillon: skipping corrupt agent_def[{}]: missing name or json",
                                _i
                            )
                            .into(),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Build the JSON snapshot string for persistence.
    #[allow(dead_code)] // used only on wasm32 targets
    fn build_snapshot_json(&self) -> Result<String, DbError> {
        let settings_map: serde_json::Map<String, serde_json::Value> = self
            .inner
            .list_all_settings()?
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();

        // Serialise agent defs as an array of {name, json} objects so they
        // round-trip without any dependency on the pap-agents crate.
        let agents_array: Vec<serde_json::Value> = self
            .inner
            .list_all_agent_defs()?
            .into_iter()
            .map(|(name, json)| serde_json::json!({ "name": name, "json": json }))
            .collect();

        let state = serde_json::json!({
            "version": SNAPSHOT_VERSION,
            "episodes": self.inner.list_all_episodes()?,
            "profiles": self.inner.list_agent_profiles()?,
            "settings": settings_map,
            "templates": self.inner.list_all_templates()?,
            "agents": agents_array,
            "principal_attributes": self.inner.get_all_principal_attributes()?,
        });

        serde_json::to_string(&state).map_err(|e| DbError(format!("serialize: {e}")))
    }

    /// Serialise the full in-memory state and persist it to IndexedDB.
    ///
    /// The actual IndexedDB write is fire-and-forget (`spawn_local`) so
    /// the synchronous `DatabaseOps` methods return immediately.  Use
    /// [`flush`] to await completion before critical transitions.
    fn persist_to_storage(&self) -> Result<(), DbError> {
        #[cfg(target_arch = "wasm32")]
        {
            let db_name = self.db_name.clone();
            let json_str = self.build_snapshot_json()?;

            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = super::idb::save(&db_name, &json_str).await {
                    web_sys::console::error_1(
                        &format!("papillon: IndexedDB persist error: {:?}", e).into(),
                    );
                }
            });
        }

        Ok(())
    }
}

// ── DatabaseOps delegation ───────────────────────────────────────

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

    fn set_agent_setting(
        &self,
        agent_did_hash: &str,
        value_name: &str,
        value: &str,
        agent_version: &str,
    ) -> Result<(), DbError> {
        self.inner
            .set_agent_setting(agent_did_hash, value_name, value, agent_version)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn get_agent_settings(
        &self,
        agent_did_hash: &str,
    ) -> Result<std::collections::HashMap<String, super::AgentSettingOverride>, DbError> {
        self.inner.get_agent_settings(agent_did_hash)
    }

    fn delete_agent_setting(&self, agent_did_hash: &str, value_name: &str) -> Result<(), DbError> {
        self.inner
            .delete_agent_setting(agent_did_hash, value_name)?;
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

    fn search_episodes(&self, query: &str, limit: usize) -> Result<Vec<Episode>, DbError> {
        self.inner.search_episodes(query, limit)
    }

    fn query_by_action(&self, action: &str, limit: usize) -> Result<Vec<Episode>, DbError> {
        self.inner.query_by_action(action, limit)
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

    fn has_enabled_template_for_schema_type(&self, schema_type: &str) -> Result<bool, DbError> {
        self.inner.has_enabled_template_for_schema_type(schema_type)
    }

    fn apply_retention_policy(&self) -> Result<super::RetentionStats, DbError> {
        self.inner.apply_retention_policy()
    }

    // ── Dynamic Agent Def CRUD ────────────────────────────────────────────────

    fn upsert_agent_def(&self, name: &str, json: &str) -> Result<(), DbError> {
        self.inner.upsert_agent_def(name, json)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn list_agent_defs(&self) -> Result<Vec<String>, DbError> {
        self.inner.list_agent_defs()
    }

    fn get_agent_def(&self, name: &str) -> Result<Option<String>, DbError> {
        self.inner.get_agent_def(name)
    }

    fn delete_agent_def(&self, name: &str) -> Result<(), DbError> {
        self.inner.delete_agent_def(name)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn set_principal_attribute(&self, prop: &str, value: &str) -> Result<(), DbError> {
        self.inner.set_principal_attribute(prop, value)?;
        self.persist_to_storage()?;
        Ok(())
    }

    fn get_principal_attribute(&self, prop: &str) -> Result<Option<String>, DbError> {
        self.inner.get_principal_attribute(prop)
    }

    fn get_all_principal_attributes(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, DbError> {
        self.inner.get_all_principal_attributes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_persistence_wrapper_creation() {
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

        db.insert_episode(&episode).unwrap();
        assert_eq!(db.episode_count().unwrap(), 1);

        let episodes = db.list_episodes(None, None, 10, None).unwrap();
        assert_eq!(episodes.len(), 1);
    }

    #[test]
    fn test_persistence_wrapper_settings() {
        let db = IndexedDbDatabase::new_with_persistence("test-db").unwrap();

        db.set_setting("theme", "dark").unwrap();
        assert_eq!(db.get_setting("theme").unwrap(), Some("dark".to_string()));
    }

    #[test]
    fn test_restore_state_round_trip() {
        let db = IndexedDbDatabase::new_with_persistence("test-db").unwrap();

        // Insert some data
        let episode = Episode {
            id: "ep-rt".into(),
            receipt_session_id: "sess-rt".into(),
            scenario_id: "scenario-rt".into(),
            action_type: "search".into(),
            agent_did_hash: "agent-rt".into(),
            agent_name: "Round Trip Agent".into(),
            outcome: "success".into(),
            outcome_detail: None,
            scope_exercised: "[]".into(),
            disclosure_refs: "[]".into(),
            duration_ms: 42,
            decay_state: "Active".into(),
            intent_summary: Some("test round trip".into()),
            result_json: None,
            query: Some("test".into()),
            recorded_at: "2026-03-24T12:00:00Z".into(),
        };
        db.insert_episode(&episode).unwrap();

        let profile = AgentProfile {
            agent_did_hash: "agent-rt".into(),
            agent_name: "Round Trip Agent".into(),
            success_rate: 0.95,
            avg_quality: 0.90,
            avg_duration_ms: 42.0,
            episode_count: 1,
            minimal_disclosure_refs: "[]".into(),
            last_used: "2026-03-24T12:00:00Z".into(),
            co_sign_refusals: 0,
        };
        db.upsert_agent_profile(&profile).unwrap();
        db.set_setting("theme", "dark").unwrap();

        // Build snapshot via the same method persist_to_storage uses
        let json_str = db.build_snapshot_json().unwrap();
        let state: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Verify version field reflects the current SNAPSHOT_VERSION (2)
        assert_eq!(
            state.get("version").and_then(|v| v.as_u64()),
            Some(SNAPSHOT_VERSION)
        );

        // Create a fresh database and restore
        let db2 = IndexedDbDatabase::new_with_persistence("test-db-2").unwrap();
        db2.restore_state(&state).unwrap();

        assert_eq!(db2.episode_count().unwrap(), 1);
        let eps = db2.list_episodes(None, None, 10, None).unwrap();
        assert_eq!(eps[0].id, "ep-rt");
        assert_eq!(eps[0].intent_summary, Some("test round trip".into()));

        let p = db2.get_agent_profile("agent-rt").unwrap().unwrap();
        assert_eq!(p.success_rate, 0.95);

        assert_eq!(db2.get_setting("theme").unwrap(), Some("dark".to_string()));
    }

    #[test]
    fn test_restore_state_tolerates_corrupt_entries() {
        let state = serde_json::json!({
            "version": 1,
            "episodes": [
                {"id": "good", "receipt_session_id": "s", "scenario_id": "s",
                 "action_type": "search", "agent_did_hash": "a", "agent_name": "A",
                 "outcome": "success", "scope_exercised": "[]", "disclosure_refs": "[]",
                 "duration_ms": 1, "decay_state": "Active", "recorded_at": "2026-01-01T00:00:00Z"},
                {"corrupt": true},
            ],
            "profiles": [{"corrupt": true}],
            "settings": {"key": "val"},
            "templates": [],
        });

        let db = IndexedDbDatabase::new_with_persistence("test-corrupt").unwrap();
        // Should succeed — corrupt entries are skipped, valid ones loaded
        db.restore_state(&state).unwrap();
        assert_eq!(db.episode_count().unwrap(), 1);
        assert_eq!(db.get_setting("key").unwrap(), Some("val".to_string()));
    }

    #[test]
    fn test_profile_isolation_via_db_name() {
        let db_a = IndexedDbDatabase::new_with_persistence("did:key:alice").unwrap();
        let db_b = IndexedDbDatabase::new_with_persistence("did:key:bob").unwrap();

        db_a.set_setting("owner", "alice").unwrap();
        db_b.set_setting("owner", "bob").unwrap();

        // Each instance is independent (in-memory isolation)
        assert_eq!(
            db_a.get_setting("owner").unwrap(),
            Some("alice".to_string())
        );
        assert_eq!(db_b.get_setting("owner").unwrap(), Some("bob".to_string()));
    }

    // ── agent def delegation tests ────────────────────────────────────────────

    #[test]
    fn test_idb_upsert_and_get_agent_def() {
        let db = IndexedDbDatabase::new_with_persistence("test-agent-defs").unwrap();
        let json = r#"{"name":"weather","description":"Weather agent"}"#;
        db.upsert_agent_def("weather", json).unwrap();

        assert_eq!(db.get_agent_def("weather").unwrap(), Some(json.to_string()));
    }

    #[test]
    fn test_idb_list_agent_defs() {
        let db = IndexedDbDatabase::new_with_persistence("test-list-defs").unwrap();
        db.upsert_agent_def("a", r#"{"name":"a"}"#).unwrap();
        db.upsert_agent_def("b", r#"{"name":"b"}"#).unwrap();

        let defs = db.list_agent_defs().unwrap();
        assert_eq!(defs.len(), 2);
    }

    #[test]
    fn test_idb_delete_agent_def() {
        let db = IndexedDbDatabase::new_with_persistence("test-del-defs").unwrap();
        db.upsert_agent_def("weather", r#"{"name":"weather"}"#)
            .unwrap();
        db.delete_agent_def("weather").unwrap();

        assert_eq!(db.get_agent_def("weather").unwrap(), None);
        assert_eq!(db.list_agent_defs().unwrap().len(), 0);
    }

    #[test]
    fn test_idb_agent_defs_snapshot_round_trip() {
        let db = IndexedDbDatabase::new_with_persistence("test-snap-defs").unwrap();
        let json = r#"{"name":"weather","description":"Weather agent"}"#;
        db.upsert_agent_def("weather", json).unwrap();

        // Build + inspect snapshot
        let snapshot_str = db.build_snapshot_json().unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(&snapshot_str).unwrap();

        // Version must be 2
        assert_eq!(snapshot.get("version").and_then(|v| v.as_u64()), Some(2));

        // "agents" array must contain our entry
        let agents = snapshot.get("agents").and_then(|v| v.as_array()).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(
            agents[0].get("name").and_then(|v| v.as_str()),
            Some("weather")
        );
        assert_eq!(agents[0].get("json").and_then(|v| v.as_str()), Some(json));

        // Restore into a fresh db and verify
        let db2 = IndexedDbDatabase::new_with_persistence("test-snap-defs-2").unwrap();
        db2.restore_state(&snapshot).unwrap();

        assert_eq!(
            db2.get_agent_def("weather").unwrap(),
            Some(json.to_string())
        );
    }

    #[test]
    fn test_idb_restore_state_tolerates_corrupt_agent_defs() {
        let state = serde_json::json!({
            "version": 2,
            "episodes": [],
            "profiles": [],
            "settings": {},
            "templates": [],
            "agents": [
                {"name": "good", "json": r#"{"name":"good"}"#},
                {"corrupt": true},
                {"name": "missing_json"},
            ],
        });

        let db = IndexedDbDatabase::new_with_persistence("test-corrupt-defs").unwrap();
        db.restore_state(&state).unwrap();

        // Only "good" has both name and json fields
        assert_eq!(db.list_agent_defs().unwrap().len(), 1);
        assert!(db.get_agent_def("good").unwrap().is_some());
    }
}

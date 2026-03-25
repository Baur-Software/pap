//! WASM database implementation using sql.js.
//!
//! This backend is used on web platforms via sql.js, an in-memory SQLite database
//! compiled to WebAssembly. Data persists via browser's IndexedDB (with wrapper).
//!
//! # Implementation Notes
//!
//! The current implementation uses in-memory Rust data structures backed by `Arc<Mutex<>>`.
//! This provides the full DatabaseOps trait interface for web builds without requiring
//! JavaScript interop (which would need `wasm-bindgen`).
//!
//! Full sql.js integration would require:
//! 1. Add `wasm-bindgen` to dependencies for JS interop
//! 2. Add `web-sys` bindings for IndexedDB API
//! 3. Use `wasm-bindgen` to invoke sql.js methods from Rust
//! 4. Implement IndexedDB wrapper for persistence
//!
//! For MVP, this in-memory backend works offline and persists via browser storage
//! (implemented via IndexedDB wrapper layer above this module).

use super::{AgentProfile, DatabaseOps, DbError, Episode};
use crate::types::Template;
use std::sync::{Arc, Mutex};

/// WASM database implementation with in-memory storage.
///
/// All data is stored in Rust data structures. For production use,
/// wrap this with an IndexedDB persistence layer.
pub struct WasmDatabase {
    /// In-memory episode store
    episodes: Arc<Mutex<Vec<Episode>>>,
    /// In-memory agent profile store
    agent_profiles: Arc<Mutex<Vec<AgentProfile>>>,
    /// In-memory settings store (key-value pairs)
    settings: Arc<Mutex<Vec<(String, String)>>>,
    /// In-memory template store
    templates: Arc<Mutex<Vec<Template>>>,
}

impl WasmDatabase {
    /// Create a new in-memory WASM database
    pub fn new() -> Result<Self, DbError> {
        Ok(Self {
            episodes: Arc::new(Mutex::new(Vec::new())),
            agent_profiles: Arc::new(Mutex::new(Vec::new())),
            settings: Arc::new(Mutex::new(Vec::new())),
            templates: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Create or load from IndexedDB (currently in-memory only)
    ///
    /// TODO: Implement IndexedDB persistence:
    /// - Try to load existing database from IndexedDB by name
    /// - If not found, create new empty database
    /// - Use wasm-bindgen + web-sys to interact with IndexedDB API
    pub async fn new_with_persistence(_name: &str) -> Result<Self, DbError> {
        // For now, just create a new in-memory database
        // Future: load from IndexedDB if exists
        Self::new()
    }
}

impl Default for WasmDatabase {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            episodes: Arc::new(Mutex::new(Vec::new())),
            agent_profiles: Arc::new(Mutex::new(Vec::new())),
            settings: Arc::new(Mutex::new(Vec::new())),
            templates: Arc::new(Mutex::new(Vec::new())),
        })
    }
}

impl DatabaseOps for WasmDatabase {
    fn insert_episode(&self, episode: &Episode) -> Result<(), DbError> {
        let mut episodes = self
            .episodes
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;
        episodes.push(episode.clone());
        Ok(())
    }

    fn list_episodes(
        &self,
        action_type: Option<&str>,
        agent_did_hash: Option<&str>,
        limit: usize,
        offset: Option<i64>,
    ) -> Result<Vec<Episode>, DbError> {
        let episodes = self
            .episodes
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        let mut filtered: Vec<Episode> = episodes
            .iter()
            .filter(|ep| {
                let action_match =
                    action_type.is_none() || action_type == Some(ep.action_type.as_str());
                let agent_match =
                    agent_did_hash.is_none() || agent_did_hash == Some(ep.agent_did_hash.as_str());
                action_match && agent_match
            })
            .cloned()
            .collect();

        // Sort by recorded_at descending
        filtered.sort_by(|a, b| b.recorded_at.cmp(&a.recorded_at));

        // Apply offset and limit
        let start = offset.unwrap_or(0) as usize;
        let end = (start + limit).min(filtered.len());

        Ok(filtered[start..end].to_vec())
    }

    fn episode_count(&self) -> Result<usize, DbError> {
        let episodes = self
            .episodes
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;
        Ok(episodes.len())
    }

    fn upsert_agent_profile(&self, profile: &AgentProfile) -> Result<(), DbError> {
        let mut profiles = self
            .agent_profiles
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        // Find and update or insert
        if let Some(pos) = profiles
            .iter()
            .position(|p| p.agent_did_hash == profile.agent_did_hash)
        {
            profiles[pos] = profile.clone();
        } else {
            profiles.push(profile.clone());
        }

        Ok(())
    }

    fn get_agent_profile(&self, agent_did_hash: &str) -> Result<Option<AgentProfile>, DbError> {
        let profiles = self
            .agent_profiles
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        Ok(profiles
            .iter()
            .find(|p| p.agent_did_hash == agent_did_hash)
            .cloned())
    }

    fn list_agent_profiles(&self) -> Result<Vec<AgentProfile>, DbError> {
        let profiles = self
            .agent_profiles
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;
        Ok(profiles.clone())
    }

    fn get_setting(&self, key: &str) -> Result<Option<String>, DbError> {
        let settings = self
            .settings
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        Ok(settings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone()))
    }

    fn set_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
        let mut settings = self
            .settings
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        // Find and update or insert
        if let Some(pos) = settings.iter().position(|(k, _)| k == key) {
            settings[pos] = (key.to_string(), value.to_string());
        } else {
            settings.push((key.to_string(), value.to_string()));
        }

        Ok(())
    }

    fn search_by_schema_type(
        &self,
        schema_type: &str,
        limit: usize,
    ) -> Result<Vec<Episode>, DbError> {
        let episodes = self
            .episodes
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        let mut filtered: Vec<Episode> = episodes
            .iter()
            .filter(|ep| {
                // Parse result_json to check @type if present
                if let Some(json_str) = &ep.result_json {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
                        if let Some(json_type) = json.get("@type") {
                            if let Some(s) = json_type.as_str() {
                                return s == schema_type;
                            }
                        }
                    }
                }
                false
            })
            .cloned()
            .collect();

        // Sort by recorded_at descending and limit
        filtered.sort_by(|a, b| b.recorded_at.cmp(&a.recorded_at));
        filtered.truncate(limit);

        Ok(filtered)
    }

    fn search_text(&self, query: &str, limit: usize) -> Result<Vec<Episode>, DbError> {
        let episodes = self
            .episodes
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        let query_lower = query.to_lowercase();
        let mut filtered: Vec<Episode> = episodes
            .iter()
            .filter(|ep| {
                let searchable = format!(
                    "{} {} {} {} {}",
                    ep.action_type.to_lowercase(),
                    ep.agent_name.to_lowercase(),
                    ep.intent_summary.as_deref().unwrap_or("").to_lowercase(),
                    ep.query.as_deref().unwrap_or("").to_lowercase(),
                    ep.result_json.as_deref().unwrap_or("").to_lowercase(),
                );
                searchable.contains(&query_lower)
            })
            .cloned()
            .collect();

        // Sort by recorded_at descending and limit
        filtered.sort_by(|a, b| b.recorded_at.cmp(&a.recorded_at));
        filtered.truncate(limit);

        Ok(filtered)
    }

    fn query_templates(&self, principal_did: Option<&str>) -> Result<Vec<Template>, DbError> {
        let templates = self
            .templates
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        let filtered: Vec<Template> = templates
            .iter()
            .filter(|t| {
                principal_did.is_none()
                    || t.principal_did.as_deref() == principal_did
                    || t.principal_did.is_none()
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn list_enabled_templates_for_principal(
        &self,
        principal_did: Option<&str>,
    ) -> Result<Vec<Template>, DbError> {
        let templates = self
            .templates
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        let filtered: Vec<Template> = templates
            .iter()
            .filter(|t| {
                t.enabled
                    && (principal_did.is_none()
                        || t.principal_did.as_deref() == principal_did
                        || t.principal_did.is_none())
            })
            .cloned()
            .collect();

        Ok(filtered)
    }

    fn insert_template(&self, template: &Template) -> Result<(), DbError> {
        let mut templates = self
            .templates
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;
        templates.push(template.clone());
        Ok(())
    }

    fn update_template(&self, template: &Template) -> Result<(), DbError> {
        let mut templates = self
            .templates
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        if let Some(pos) = templates.iter().position(|t| t.id == template.id) {
            templates[pos] = template.clone();
            Ok(())
        } else {
            Err(DbError(format!("Template not found: {}", template.id)))
        }
    }

    fn delete_template(&self, template_name: &str) -> Result<(), DbError> {
        let mut templates = self
            .templates
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        if let Some(pos) = templates
            .iter()
            .position(|t| t.template_name == template_name)
        {
            templates.remove(pos);
            Ok(())
        } else {
            Err(DbError(format!("Template not found: {}", template_name)))
        }
    }

    fn set_template_enabled(&self, template_name: &str, enabled: bool) -> Result<(), DbError> {
        let mut templates = self
            .templates
            .lock()
            .map_err(|e| DbError(format!("db lock: {e}")))?;

        if let Some(template) = templates
            .iter_mut()
            .find(|t| t.template_name == template_name)
        {
            template.enabled = enabled;
            Ok(())
        } else {
            Err(DbError(format!("Template not found: {}", template_name)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_wasm_db_new() {
        let db = WasmDatabase::new();
        assert!(db.is_ok());
    }

    #[test]
    fn test_wasm_db_default() {
        let db = WasmDatabase::default();
        let count = db.episode_count().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_insert_and_list_episodes() {
        let db = WasmDatabase::new().unwrap();

        let episode = Episode {
            id: "ep-1".into(),
            receipt_session_id: "sess-1".into(),
            scenario_id: "scenario-1".into(),
            action_type: "search".into(),
            agent_did_hash: "agent-hash-1".into(),
            agent_name: "Search Agent".into(),
            outcome: "success".into(),
            outcome_detail: None,
            scope_exercised: "[]".into(),
            disclosure_refs: "[]".into(),
            duration_ms: 100,
            decay_state: "Active".into(),
            intent_summary: None,
            result_json: None,
            query: Some("test query".into()),
            recorded_at: Utc::now().to_rfc3339(),
        };

        db.insert_episode(&episode).unwrap();
        let count = db.episode_count().unwrap();
        assert_eq!(count, 1);

        let episodes = db.list_episodes(None, None, 10, None).unwrap();
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].id, "ep-1");
    }

    #[test]
    fn test_list_episodes_with_filters() {
        let db = WasmDatabase::new().unwrap();

        let ep1 = Episode {
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
            recorded_at: "2026-01-01T10:00:00Z".into(),
        };

        let ep2 = Episode {
            id: "ep-2".into(),
            receipt_session_id: "sess-2".into(),
            scenario_id: "scenario-2".into(),
            action_type: "booking".into(),
            agent_did_hash: "agent-2".into(),
            agent_name: "Booking Agent".into(),
            outcome: "success".into(),
            outcome_detail: None,
            scope_exercised: "[]".into(),
            disclosure_refs: "[]".into(),
            duration_ms: 200,
            decay_state: "Active".into(),
            intent_summary: None,
            result_json: None,
            query: None,
            recorded_at: "2026-01-01T11:00:00Z".into(),
        };

        db.insert_episode(&ep1).unwrap();
        db.insert_episode(&ep2).unwrap();

        // Filter by action_type
        let search_episodes = db.list_episodes(Some("search"), None, 10, None).unwrap();
        assert_eq!(search_episodes.len(), 1);
        assert_eq!(search_episodes[0].action_type, "search");

        // Filter by agent_did_hash
        let agent_episodes = db.list_episodes(None, Some("agent-1"), 10, None).unwrap();
        assert_eq!(agent_episodes.len(), 1);
        assert_eq!(agent_episodes[0].agent_did_hash, "agent-1");
    }

    #[test]
    fn test_upsert_agent_profile() {
        let db = WasmDatabase::new().unwrap();

        let profile = AgentProfile {
            agent_did_hash: "agent-1".into(),
            agent_name: "Agent 1".into(),
            success_rate: 0.95,
            avg_quality: 0.92,
            avg_duration_ms: 150.0,
            episode_count: 42,
            minimal_disclosure_refs: "[]".into(),
            last_used: Utc::now().to_rfc3339(),
            co_sign_refusals: 0,
        };

        db.upsert_agent_profile(&profile).unwrap();
        let profiles = db.list_agent_profiles().unwrap();
        assert_eq!(profiles.len(), 1);

        // Update: change success_rate
        let updated = AgentProfile {
            success_rate: 0.98,
            ..profile.clone()
        };

        db.upsert_agent_profile(&updated).unwrap();
        let profiles = db.list_agent_profiles().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].success_rate, 0.98);
    }

    #[test]
    fn test_get_agent_profile() {
        let db = WasmDatabase::new().unwrap();

        let profile = AgentProfile {
            agent_did_hash: "agent-1".into(),
            agent_name: "Agent 1".into(),
            success_rate: 0.95,
            avg_quality: 0.92,
            avg_duration_ms: 150.0,
            episode_count: 42,
            minimal_disclosure_refs: "[]".into(),
            last_used: Utc::now().to_rfc3339(),
            co_sign_refusals: 0,
        };

        db.upsert_agent_profile(&profile).unwrap();
        let found = db.get_agent_profile("agent-1").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().agent_name, "Agent 1");

        let not_found = db.get_agent_profile("agent-999").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_settings() {
        let db = WasmDatabase::new().unwrap();

        db.set_setting("theme", "dark").unwrap();
        let value = db.get_setting("theme").unwrap();
        assert_eq!(value, Some("dark".to_string()));

        // Update
        db.set_setting("theme", "light").unwrap();
        let value = db.get_setting("theme").unwrap();
        assert_eq!(value, Some("light".to_string()));

        // Non-existent key
        let not_found = db.get_setting("nonexistent").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_search_by_schema_type() {
        let db = WasmDatabase::new().unwrap();

        let ep = Episode {
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
            result_json: Some(
                r#"{"@type":"FlightReservation","bookingReference":"ABC123"}"#.into(),
            ),
            query: None,
            recorded_at: Utc::now().to_rfc3339(),
        };

        db.insert_episode(&ep).unwrap();

        let results = db.search_by_schema_type("FlightReservation", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "ep-1");

        let no_match = db.search_by_schema_type("HotelReservation", 10).unwrap();
        assert_eq!(no_match.len(), 0);
    }

    #[test]
    fn test_search_text() {
        let db = WasmDatabase::new().unwrap();

        let ep = Episode {
            id: "ep-1".into(),
            receipt_session_id: "sess-1".into(),
            scenario_id: "scenario-1".into(),
            action_type: "flight_search".into(),
            agent_did_hash: "agent-1".into(),
            agent_name: "Amadeus Flight Agent".into(),
            outcome: "success".into(),
            outcome_detail: None,
            scope_exercised: "[]".into(),
            disclosure_refs: "[]".into(),
            duration_ms: 100,
            decay_state: "Active".into(),
            intent_summary: Some("Find flights to Tokyo".into()),
            result_json: None,
            query: Some("Tokyo to Paris".into()),
            recorded_at: Utc::now().to_rfc3339(),
        };

        db.insert_episode(&ep).unwrap();

        let results = db.search_text("Tokyo", 10).unwrap();
        assert_eq!(results.len(), 1);

        let no_match = db.search_text("nonexistent", 10).unwrap();
        assert_eq!(no_match.len(), 0);
    }

    #[test]
    fn test_template_operations() {
        let db = WasmDatabase::new().unwrap();

        let template = Template {
            id: "t-1".into(),
            template_name: "flight_template".into(),
            schema_type: "FlightReservation".into(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        db.insert_template(&template).unwrap();

        let templates = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].template_name, "flight_template");
    }

    #[test]
    fn test_template_enable_disable() {
        let db = WasmDatabase::new().unwrap();

        let template = Template {
            id: "t-1".into(),
            template_name: "test_template".into(),
            schema_type: "FlightReservation".into(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        db.insert_template(&template).unwrap();

        // Disable the template
        db.set_template_enabled("test_template", false).unwrap();

        let enabled = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(enabled.len(), 0);

        // Re-enable
        db.set_template_enabled("test_template", true).unwrap();
        let enabled = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(enabled.len(), 1);
    }

    #[test]
    fn test_template_delete() {
        let db = WasmDatabase::new().unwrap();

        let template = Template {
            id: "t-1".into(),
            template_name: "to_delete".into(),
            schema_type: "FlightReservation".into(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        db.insert_template(&template).unwrap();
        let templates = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(templates.len(), 1);

        db.delete_template("to_delete").unwrap();
        let templates = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(templates.len(), 0);
    }

    #[test]
    fn test_query_templates_returns_all() {
        let db = WasmDatabase::new().unwrap();

        let enabled = Template {
            id: "t-1".into(),
            template_name: "enabled_template".into(),
            schema_type: "FlightReservation".into(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        let disabled = Template {
            id: "t-2".into(),
            template_name: "disabled_template".into(),
            schema_type: "HotelReservation".into(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: false,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        db.insert_template(&enabled).unwrap();
        db.insert_template(&disabled).unwrap();

        // query_templates returns ALL templates (enabled + disabled)
        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 2);

        // list_enabled only returns the enabled one
        let enabled_only = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(enabled_only.len(), 1);
        assert_eq!(enabled_only[0].template_name, "enabled_template");
    }

    #[test]
    fn test_query_templates_filters_by_principal() {
        let db = WasmDatabase::new().unwrap();

        let global = Template {
            id: "t-1".into(),
            template_name: "global_template".into(),
            schema_type: "FlightReservation".into(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        let alice = Template {
            id: "t-2".into(),
            template_name: "alice_template".into(),
            schema_type: "HotelReservation".into(),
            principal_did: Some("did:pap:alice".into()),
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        let bob = Template {
            id: "t-3".into(),
            template_name: "bob_template".into(),
            schema_type: "PaymentReceipt".into(),
            principal_did: Some("did:pap:bob".into()),
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        db.insert_template(&global).unwrap();
        db.insert_template(&alice).unwrap();
        db.insert_template(&bob).unwrap();

        // Query all = 3
        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 3);

        // Query for alice = global + alice = 2
        let alice_templates = db.query_templates(Some("did:pap:alice")).unwrap();
        assert_eq!(alice_templates.len(), 2);

        // Query for bob = global + bob = 2
        let bob_templates = db.query_templates(Some("did:pap:bob")).unwrap();
        assert_eq!(bob_templates.len(), 2);
    }

    #[test]
    fn test_template_update() {
        let db = WasmDatabase::new().unwrap();

        let template = Template {
            id: "t-1".into(),
            template_name: "my_template".into(),
            schema_type: "FlightReservation".into(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        db.insert_template(&template).unwrap();

        // Update the template
        let mut updated = template.clone();
        updated.schema_type = "HotelReservation".into();
        updated.version = 2;
        db.update_template(&updated).unwrap();

        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].schema_type, "HotelReservation");
        assert_eq!(all[0].version, 2);
    }

    #[test]
    fn test_template_update_not_found() {
        let db = WasmDatabase::new().unwrap();

        let template = Template {
            id: "nonexistent".into(),
            template_name: "ghost".into(),
            schema_type: "FlightReservation".into(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        let result = db.update_template(&template);
        assert!(result.is_err());
    }

    #[test]
    fn test_template_delete_not_found() {
        let db = WasmDatabase::new().unwrap();
        let result = db.delete_template("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_set_template_enabled_not_found() {
        let db = WasmDatabase::new().unwrap();
        let result = db.set_template_enabled("nonexistent", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_disabled_template_survives_query_templates() {
        let db = WasmDatabase::new().unwrap();

        let template = Template {
            id: "t-1".into(),
            template_name: "toggleable".into(),
            schema_type: "FlightReservation".into(),
            principal_did: None,
            template_config: crate::types::TemplateConfig {
                version: 1,
                layout: crate::types::LayoutConfig {
                    r#type: "grid".into(),
                    columns: Some(2),
                    direction: None,
                    spacing: Some("md".into()),
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            created_by: None,
        };

        db.insert_template(&template).unwrap();
        db.set_template_enabled("toggleable", false).unwrap();

        // Disabled template invisible to list_enabled but visible to query_templates
        let enabled = db.list_enabled_templates_for_principal(None).unwrap();
        assert_eq!(enabled.len(), 0);

        let all = db.query_templates(None).unwrap();
        assert_eq!(all.len(), 1);
        assert!(!all[0].enabled);
    }
}

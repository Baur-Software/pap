use super::renderer::BlockRenderer;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// RendererRegistry manages runtime registration of BlockRenderer implementations.
///
/// The registry supports two dispatch tiers:
///
/// 1. **Agent-scoped** — keyed by `(agent_did, schema_type)`. Takes priority.
///    A renderer registered here owns the rendering of a specific agent's output
///    for that type, regardless of what global renderers exist. This is how a
///    UI component agent or a specialized remote agent can assert full control
///    over how its payload looks.
///
/// 2. **Type-global** — keyed by `schema_type` alone. The fallback when no
///    agent-specific renderer matches. All 25+ shipped templates live here.
///
/// Lookup order: agent-scoped → type-global → generic stream renderer (in mod.rs).
pub struct RendererRegistry {
    /// Global schema-type renderers (shipped templates + declarative user templates).
    type_renderers: RwLock<HashMap<String, Arc<dyn BlockRenderer>>>,
    /// Agent-scoped overrides keyed by (agent_did, schema_type).
    agent_type_renderers: RwLock<HashMap<(String, String), Arc<dyn BlockRenderer>>>,
}

impl RendererRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            type_renderers: RwLock::new(HashMap::new()),
            agent_type_renderers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a renderer.
    ///
    /// If the renderer's `agent_id()` is `Some`, it is registered in the
    /// agent-scoped tier for each of its schema types. Otherwise it is
    /// registered globally by schema type.
    pub fn register(&self, renderer: Arc<dyn BlockRenderer>) {
        if let Some(agent_did) = renderer.agent_id() {
            let mut map = self.agent_type_renderers.write().unwrap();
            for schema_type in renderer.schema_types() {
                map.insert(
                    (agent_did.to_string(), schema_type.to_string()),
                    renderer.clone(),
                );
            }
        } else {
            let mut map = self.type_renderers.write().unwrap();
            for schema_type in renderer.schema_types() {
                map.insert(schema_type.to_string(), renderer.clone());
            }
        }
    }

    /// Explicitly register a renderer scoped to a specific agent DID.
    ///
    /// Use this when you have a renderer that doesn't implement `agent_id()`
    /// itself but should be scoped to a particular agent — for example, when
    /// loading agent-scoped declarative templates from the database.
    pub fn register_for_agent(&self, agent_did: &str, renderer: Arc<dyn BlockRenderer>) {
        let mut map = self.agent_type_renderers.write().unwrap();
        for schema_type in renderer.schema_types() {
            map.insert(
                (agent_did.to_string(), schema_type.to_string()),
                renderer.clone(),
            );
        }
    }

    /// Look up a renderer by schema type (type-global tier).
    pub fn get(&self, schema_type: &str) -> Option<Arc<dyn BlockRenderer>> {
        self.type_renderers
            .read()
            .unwrap()
            .get(schema_type)
            .cloned()
    }

    /// Look up a renderer scoped to a specific agent DID and schema type.
    ///
    /// Returns `None` if no agent-specific renderer has been registered for
    /// this `(agent_did, schema_type)` pair. The caller should fall back to
    /// `get(schema_type)` and then to the generic stream renderer.
    pub fn get_for_agent(
        &self,
        agent_did: &str,
        schema_type: &str,
    ) -> Option<Arc<dyn BlockRenderer>> {
        self.agent_type_renderers
            .read()
            .unwrap()
            .get(&(agent_did.to_string(), schema_type.to_string()))
            .cloned()
    }

    /// Load declarative renderers from a list of templates.
    ///
    /// Templates with `agent_did` set are registered in the agent-scoped tier;
    /// global templates (agent_did = None) are registered in the type-global tier.
    /// User templates in either tier override shipped templates for the same key.
    pub fn load_from_templates(&self, templates: Vec<papillon_shared::types::Template>) {
        use crate::components::block_renderer::declarative::DeclarativeRenderer;

        for template in templates {
            if template.enabled {
                // register() routes to the correct tier automatically via renderer.agent_id().
                // Templates with agent_did → Tier 1; global templates → Tier 2.
                let renderer = DeclarativeRenderer::from_template(&template);
                self.register(Arc::new(renderer));
            }
        }
    }

    /// Sorted schema type keys from the type-global tier (Tier 2).
    ///
    /// Agent-scoped (Tier 1) keys are intentionally excluded — they are
    /// per-agent rendering overrides, not broadly useful vocabulary entries
    /// for autocomplete or type enumeration.
    pub fn registered_type_keys(&self) -> Vec<String> {
        let map = self.type_renderers.read().unwrap();
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        keys
    }
}

impl Default for RendererRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_template(
        schema_type: &str,
        agent_did: Option<&str>,
        enabled: bool,
    ) -> papillon_shared::types::Template {
        use papillon_shared::types::{LayoutConfig, TemplateConfig};
        papillon_shared::types::Template {
            id: "test-id".to_string(),
            template_name: "Test Template".to_string(),
            schema_type: schema_type.to_string(),
            principal_did: None,
            agent_did: agent_did.map(|s| s.to_string()),
            template_config: TemplateConfig {
                version: 1,
                layout: LayoutConfig {
                    r#type: "grid".to_string(),
                    columns: Some(1),
                    direction: None,
                    spacing: None,
                },
                fields: vec![],
            },
            version: 1,
            enabled,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            created_by: None,
        }
    }

    #[test]
    fn empty_registry_returns_none() {
        let registry = RendererRegistry::new();
        assert!(registry.get("FlightReservation").is_none());
        assert!(registry.get_for_agent("did:key:abc", "FlightReservation").is_none());
    }

    #[test]
    fn disabled_template_is_not_registered() {
        let registry = RendererRegistry::new();
        registry.load_from_templates(vec![minimal_template("FlightReservation", None, false)]);
        assert!(registry.get("FlightReservation").is_none());
    }

    #[test]
    fn global_template_registers_in_tier2_only() {
        let registry = RendererRegistry::new();
        registry.load_from_templates(vec![minimal_template("Recipe", None, true)]);
        // Tier 2: type-global lookup succeeds
        assert!(registry.get("Recipe").is_some());
        // Tier 1: no agent-scoped entry was registered
        assert!(registry.get_for_agent("did:key:xyz", "Recipe").is_none());
    }

    #[test]
    fn agent_scoped_template_registers_in_tier1_not_tier2() {
        let registry = RendererRegistry::new();
        let did = "did:key:z6MkHabc123";
        registry.load_from_templates(vec![minimal_template("ProductCard", Some(did), true)]);
        // Tier 1: agent-scoped lookup with matching DID succeeds
        assert!(registry.get_for_agent(did, "ProductCard").is_some());
        // Tier 2: global lookup finds nothing (agent-scoped only)
        assert!(registry.get("ProductCard").is_none());
    }

    #[test]
    fn agent_scoped_does_not_match_wrong_agent() {
        let registry = RendererRegistry::new();
        let did_a = "did:key:agent_a";
        let did_b = "did:key:agent_b";
        registry.load_from_templates(vec![minimal_template("Widget", Some(did_a), true)]);
        assert!(registry.get_for_agent(did_a, "Widget").is_some());
        assert!(registry.get_for_agent(did_b, "Widget").is_none());
    }

    #[test]
    fn tier1_and_tier2_coexist_for_same_schema_type() {
        // A global renderer in Tier 2 and an agent-scoped renderer in Tier 1
        // can coexist for the same schema_type without interfering.
        let registry = RendererRegistry::new();
        let did = "did:key:agent_c";
        registry.load_from_templates(vec![
            minimal_template("Event", None, true),      // → Tier 2
            minimal_template("Event", Some(did), true), // → Tier 1
        ]);
        assert!(registry.get("Event").is_some());
        assert!(registry.get_for_agent(did, "Event").is_some());
        // An unregistered agent still gets None from Tier 1
        assert!(registry.get_for_agent("did:key:other", "Event").is_none());
    }

    #[test]
    fn multiple_global_templates_register_independently() {
        let registry = RendererRegistry::new();
        registry.load_from_templates(vec![
            minimal_template("FlightReservation", None, true),
            minimal_template("HotelReservation", None, true),
            minimal_template("JobPosting", None, true),
        ]);
        assert!(registry.get("FlightReservation").is_some());
        assert!(registry.get("HotelReservation").is_some());
        assert!(registry.get("JobPosting").is_some());
        assert!(registry.get("Unknown").is_none());
    }

    #[test]
    fn register_for_agent_scopes_global_renderer_to_a_did() {
        // register_for_agent() explicitly scopes any renderer to a DID,
        // even when the renderer's own agent_id() returns None.
        use crate::components::block_renderer::declarative::DeclarativeRenderer;
        let registry = RendererRegistry::new();
        let template = minimal_template("BookingForm", None, true);
        let renderer: Arc<dyn BlockRenderer> =
            Arc::new(DeclarativeRenderer::from_template(&template));
        let did = "did:key:explicit_scope";
        registry.register_for_agent(did, renderer);
        // Should appear in Tier 1 under the explicitly supplied DID
        assert!(registry.get_for_agent(did, "BookingForm").is_some());
        // Should NOT appear in Tier 2
        assert!(registry.get("BookingForm").is_none());
    }
}

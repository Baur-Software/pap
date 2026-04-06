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
                let renderer = DeclarativeRenderer::from_template(&template);
                if template.agent_did.is_some() {
                    // Agent-scoped: use explicit registration so the renderer
                    // is keyed by (agent_did, schema_type) in the right tier.
                    self.register(Arc::new(renderer));
                } else {
                    self.register(Arc::new(renderer));
                }
            }
        }
    }
}

impl Default for RendererRegistry {
    fn default() -> Self {
        Self::new()
    }
}

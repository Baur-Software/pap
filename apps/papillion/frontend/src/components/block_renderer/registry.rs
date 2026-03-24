use super::renderer::BlockRenderer;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// RendererRegistry manages runtime registration of BlockRenderer implementations.
///
/// This enables a plugin-like pattern where custom renderers can be registered
/// for any schema type, overriding or supplementing the shipped templates.
///
/// The registry is keyed by schema type (e.g., "FlightReservation", "Answer")
/// and maps to arc-wrapped renderer implementations.
pub struct RendererRegistry {
    renderers: RwLock<HashMap<String, Arc<dyn BlockRenderer>>>,
}

impl RendererRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            renderers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a renderer for all schema types it handles.
    ///
    /// If a renderer handles multiple types (e.g., SearchResultsPage and SearchAction),
    /// this method registers it for each type in the list returned by `schema_types()`.
    ///
    /// # Arguments
    /// * `renderer` - The renderer implementation to register
    pub fn register(&self, renderer: Arc<dyn BlockRenderer>) {
        let mut map = self.renderers.write().unwrap();
        for schema_type in renderer.schema_types() {
            map.insert(schema_type.to_string(), renderer.clone());
        }
    }

    /// Look up a renderer by schema type.
    ///
    /// Returns the registered renderer for the given schema type, if one exists.
    ///
    /// # Arguments
    /// * `schema_type` - The schema.org type to look up (e.g., "FlightReservation")
    ///
    /// # Returns
    /// An arc-wrapped renderer if registered, None otherwise
    pub fn get(&self, schema_type: &str) -> Option<Arc<dyn BlockRenderer>> {
        self.renderers.read().unwrap().get(schema_type).cloned()
    }

    /// Load declarative renderers from a list of templates.
    ///
    /// Creates and registers a DeclarativeRenderer for each enabled template.
    /// User templates override shipped templates when they have the same schema_type.
    ///
    /// # Arguments
    /// * `templates` - User-defined templates to load
    pub fn load_from_templates(&self, templates: Vec<papillion_shared::types::Template>) {
        use crate::components::block_renderer::declarative::DeclarativeRenderer;

        for template in templates {
            if template.enabled {
                let renderer = DeclarativeRenderer::from_template(&template);
                self.register(Arc::new(renderer));
            }
        }
    }
}

impl Default for RendererRegistry {
    fn default() -> Self {
        Self::new()
    }
}

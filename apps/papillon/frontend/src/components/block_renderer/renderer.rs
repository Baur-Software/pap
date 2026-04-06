use leptos::prelude::AnyView;
use serde_json::Value;

/// BlockRenderer trait defines the contract for custom schema type renderers.
///
/// Implementations can handle one or more schema.org types and return appropriate
/// visual representations. This enables runtime registration of custom templates
/// and extensibility without modifying core dispatch logic.
pub trait BlockRenderer: Send + Sync {
    /// Render a JSON-LD value of the associated schema type(s).
    ///
    /// # Arguments
    /// * `content` - The JSON-LD object to render
    ///
    /// # Returns
    /// An AnyView containing the rendered Leptos view
    fn render(&self, content: &Value) -> AnyView;

    /// Return the schema type(s) this renderer handles.
    ///
    /// Examples:
    /// - `vec!["FlightReservation"]`
    /// - `vec!["SearchResultsPage", "SearchAction"]` (handles multiple types)
    fn schema_types(&self) -> Vec<&'static str>;

    /// Optional: the agent DID this renderer is scoped to.
    ///
    /// When `Some`, the registry registers this renderer under the
    /// `(agent_did, schema_type)` key, giving it priority over any global
    /// renderer for the same type. When `None` (the default), the renderer
    /// is registered globally by schema type only.
    ///
    /// Use this to give a specific agent full control over how its output
    /// is rendered — independent of the shared schema.org vocabulary mapping.
    fn agent_id(&self) -> Option<&str> {
        None
    }
}

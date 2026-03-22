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
}

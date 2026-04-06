use super::renderer::BlockRenderer;
use leptos::prelude::*;
use papillon_shared::types::{Template, TemplateConfig};
use serde_json::Value;

/// A runtime-loaded declarative renderer that uses template configuration to render JSON-LD content.
///
/// Unlike hardcoded templates, DeclarativeRenderer uses a JSON-LD configuration schema to
/// define field mappings, layout, and styling, enabling users to create templates without code.
///
/// When `agent_did` is set the renderer is registered in the agent-scoped tier of the
/// `RendererRegistry`, giving it priority over any global renderer for the same schema type.
/// This is the mechanism by which a UI component agent — or any agent with a custom payload
/// shape — can declare exactly how its output should appear, without touching the shared
/// schema.org vocabulary mapping.
pub struct DeclarativeRenderer {
    config: TemplateConfig,
    schema_type: String,
    /// When Some, this renderer is scoped to a specific agent DID.
    agent_did: Option<String>,
}

impl DeclarativeRenderer {
    /// Create a new declarative renderer from template configuration.
    pub fn new(config: TemplateConfig, schema_type: &str) -> Self {
        Self {
            config,
            schema_type: schema_type.to_string(),
            agent_did: None,
        }
    }

    /// Create from a Template (uses template_config, schema_type, and agent_did).
    pub fn from_template(template: &Template) -> Self {
        Self {
            config: template.template_config.clone(),
            schema_type: template.schema_type.clone(),
            agent_did: template.agent_did.clone(),
        }
    }

    /// Extract a value from JSON-LD content using a JSON path (simplified for now).
    /// Supports simple paths like "name" and nested paths like "offers.price".
    fn extract_value(&self, content: &Value, path: &str) -> Option<Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = content.clone();

        for part in parts {
            // Try to parse as array index if it's a number
            if let Ok(idx) = part.parse::<usize>() {
                current = current.get(idx).cloned()?;
            } else {
                current = current.get(part).cloned()?;
            }
        }

        Some(current)
    }

    /// Evaluate a condition against the content.
    /// Returns true if the condition is met, false otherwise.
    fn eval_condition(&self, content: &Value, field: &str, op: &str, value: Option<&str>) -> bool {
        match op {
            "exists" => self.extract_value(content, field).is_some(),
            "equals" => {
                if let Some(val) = value {
                    self.extract_value(content, field)
                        .and_then(|v| v.as_str().map(|s| s == val))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            "contains" => {
                if let Some(val) = value {
                    self.extract_value(content, field)
                        .and_then(|v| v.as_str().map(|s| s.contains(val)))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Format a value for display based on the display type.
    fn format_value(&self, value: &Value, display_type: &str) -> String {
        match display_type {
            "title" => value.as_str().unwrap_or("-").to_string(),
            "text" => value.as_str().unwrap_or("-").to_string(),
            "price" => {
                let price = value
                    .as_f64()
                    .or_else(|| value.as_str().and_then(|s| s.parse::<f64>().ok()));
                price
                    .map(|p| format!("${:.2}", p))
                    .unwrap_or_else(|| "\u{2014}".to_string())
            }
            "date" => value.as_str().unwrap_or("-").to_string(),
            "url" => value.as_str().unwrap_or("-").to_string(),
            _ => value.to_string(),
        }
    }

    /// Render a single field with its value.
    fn render_field(
        &self,
        label: Option<&str>,
        value: &Value,
        display_type: &str,
        style: Option<&str>,
    ) -> AnyView {
        let formatted = self.format_value(value, display_type);
        let class = if let Some(s) = style {
            format!("declarative-field {}", s)
        } else {
            "declarative-field".to_string()
        };

        if let Some(lbl) = label {
            view! {
                <div class=class>
                    <span class="declarative-label">{lbl}</span>
                    <span class="declarative-value">{formatted}</span>
                </div>
            }
            .into_any()
        } else {
            view! {
                <div class=class>
                    <span class="declarative-value">{formatted}</span>
                </div>
            }
            .into_any()
        }
    }
}

impl BlockRenderer for DeclarativeRenderer {
    fn render(&self, content: &Value) -> AnyView {
        let mut rendered_fields = Vec::new();

        for field_config in &self.config.fields {
            // Check if condition passes (default: always render)
            let should_render = if let Some(cond) = &field_config.condition {
                self.eval_condition(content, &cond.field, &cond.op, cond.value.as_deref())
            } else {
                true
            };

            if !should_render {
                continue;
            }

            // Extract the value
            if let Some(value) = self.extract_value(content, &field_config.path) {
                let style = field_config
                    .style
                    .as_ref()
                    .and_then(|s| s.class_name.as_deref());
                let field_view = self.render_field(
                    field_config.label.as_deref(),
                    &value,
                    &field_config.display,
                    style,
                );
                rendered_fields.push(field_view);
            }
        }

        let layout_type = &self.config.layout.r#type;
        let class = match layout_type.as_str() {
            "grid" => {
                if let Some(cols) = self.config.layout.columns {
                    format!("declarative-grid grid-cols-{}", cols)
                } else {
                    "declarative-grid".to_string()
                }
            }
            "flex" => {
                let dir = self.config.layout.direction.as_deref().unwrap_or("row");
                format!("declarative-flex flex-{}", dir)
            }
            _ => "declarative-container".to_string(),
        };

        view! {
            <div class=class>
                {rendered_fields}
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        // Return a boxed string sliced as static - this is a workaround since
        // schema_types() returns Vec<&'static str>, but our schema_type is owned.
        // In practice, we'll only call this once during registration, so we can
        // leak the string for the static lifetime.
        vec![Box::leak(self.schema_type.clone().into_boxed_str())]
    }

    fn agent_id(&self) -> Option<&str> {
        self.agent_did.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_template_config() -> TemplateConfig {
        TemplateConfig {
            version: 1,
            layout: papillon_shared::types::LayoutConfig {
                r#type: "grid".to_string(),
                columns: Some(2),
                direction: None,
                spacing: Some("md".to_string()),
            },
            fields: vec![
                FieldMapping {
                    path: "name".to_string(),
                    label: Some("Name".to_string()),
                    display: "title".to_string(),
                    condition: None,
                    style: None,
                },
                FieldMapping {
                    path: "price".to_string(),
                    label: Some("Price".to_string()),
                    display: "price".to_string(),
                    condition: Some(papillon_shared::types::Condition {
                        field: "price".to_string(),
                        op: "exists".to_string(),
                        value: None,
                    }),
                    style: None,
                },
            ],
        }
    }

    #[test]
    fn test_extract_simple_value() {
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Recipe");
        let content = serde_json::json!({
            "name": "Pasta",
            "price": 12.99
        });

        assert_eq!(
            renderer.extract_value(&content, "name"),
            Some(serde_json::json!("Pasta"))
        );
        assert_eq!(
            renderer.extract_value(&content, "price"),
            Some(serde_json::json!(12.99))
        );
    }

    #[test]
    fn test_extract_nested_value() {
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Recipe");
        let content = serde_json::json!({
            "name": "Pasta",
            "offers": {
                "price": 12.99
            }
        });

        assert_eq!(
            renderer.extract_value(&content, "offers.price"),
            Some(serde_json::json!(12.99))
        );
    }

    #[test]
    fn test_condition_exists() {
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Recipe");
        let content = serde_json::json!({
            "name": "Pasta",
            "price": 12.99
        });

        assert!(renderer.eval_condition(&content, "name", "exists", None));
        assert!(renderer.eval_condition(&content, "price", "exists", None));
        assert!(!renderer.eval_condition(&content, "missing", "exists", None));
    }

    #[test]
    fn test_condition_equals() {
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Recipe");
        let content = serde_json::json!({
            "name": "Pasta"
        });

        assert!(renderer.eval_condition(&content, "name", "equals", Some("Pasta")));
        assert!(!renderer.eval_condition(&content, "name", "equals", Some("Pizza")));
    }

    #[test]
    fn test_format_price() {
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Recipe");
        assert_eq!(
            renderer.format_value(&serde_json::json!(12.99), "price"),
            "$12.99"
        );
    }

    #[test]
    fn test_extract_array_index() {
        // Test extracting nested array elements (e.g., results.0.title)
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Recipe");
        let content = serde_json::json!({
            "results": [
                { "title": "First Result", "score": 0.95 },
                { "title": "Second Result", "score": 0.85 }
            ]
        });

        let first_title = renderer.extract_value(&content, "results.0.title");
        assert!(first_title.is_some());
        assert_eq!(first_title.unwrap(), "First Result");

        let second_title = renderer.extract_value(&content, "results.1.title");
        assert!(second_title.is_some());
        assert_eq!(second_title.unwrap(), "Second Result");
    }

    #[test]
    fn test_condition_contains() {
        // Test substring matching in conditions (op: "contains")
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Recipe");
        let content = serde_json::json!({
            "description": "This is a delicious pasta recipe"
        });

        assert!(renderer.eval_condition(&content, "description", "contains", Some("pasta")));
        assert!(renderer.eval_condition(&content, "description", "contains", Some("delicious")));
        assert!(!renderer.eval_condition(&content, "description", "contains", Some("pizza")));
    }

    #[test]
    fn test_format_price_from_string() {
        // Test formatting price values when provided as strings (JSON interchange)
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Recipe");

        // Numeric price
        assert_eq!(
            renderer.format_value(&serde_json::json!(24.50), "price"),
            "$24.50"
        );

        // String price should be parsed
        assert_eq!(
            renderer.format_value(&serde_json::json!("19.99"), "price"),
            "$19.99"
        );
    }

    #[test]
    fn test_format_missing_values() {
        // Test handling of null/missing/invalid values
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Recipe");

        // Null value
        assert_eq!(
            renderer.format_value(&serde_json::json!(null), "price"),
            "—"
        );

        // Missing field returns empty (handled in extract_value)
        let content = serde_json::json!({ "name": "Pasta" });
        let missing = renderer.extract_value(&content, "missing.field");
        assert!(missing.is_none());

        // Empty string
        assert_eq!(renderer.format_value(&serde_json::json!(""), "text"), "");
    }

    // ── from_template / agent_id / schema_types ───────────────────────────────

    fn sample_template(schema_type: &str, agent_did: Option<&str>) -> Template {
        Template {
            id: "tpl-1".to_string(),
            template_name: "Sample".to_string(),
            schema_type: schema_type.to_string(),
            principal_did: None,
            agent_did: agent_did.map(|s| s.to_string()),
            template_config: sample_template_config(),
            version: 1,
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            created_by: None,
        }
    }

    #[test]
    fn from_template_sets_schema_type() {
        let tpl = sample_template("FlightReservation", None);
        let renderer = DeclarativeRenderer::from_template(&tpl);
        assert_eq!(renderer.schema_types(), vec!["FlightReservation"]);
    }

    #[test]
    fn from_template_without_agent_did_returns_none() {
        let tpl = sample_template("Recipe", None);
        let renderer = DeclarativeRenderer::from_template(&tpl);
        assert!(renderer.agent_id().is_none());
    }

    #[test]
    fn from_template_with_agent_did_returns_some() {
        let did = "did:key:z6MkHabc123";
        let tpl = sample_template("ProductCard", Some(did));
        let renderer = DeclarativeRenderer::from_template(&tpl);
        assert_eq!(renderer.agent_id(), Some(did));
    }

    #[test]
    fn new_always_has_no_agent_id() {
        // DeclarativeRenderer::new() never sets agent_did; only from_template() does.
        let renderer = DeclarativeRenderer::new(sample_template_config(), "Event");
        assert!(renderer.agent_id().is_none());
    }

    #[test]
    fn schema_types_returns_single_element_vec() {
        let renderer = DeclarativeRenderer::new(sample_template_config(), "JobPosting");
        let types = renderer.schema_types();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], "JobPosting");
    }
}

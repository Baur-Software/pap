//! Automatic template generation from JSON-LD payloads.
//!
//! When the orchestrator receives agent results for a schema type with no
//! matching template, this module analyzes the JSON-LD structure and produces
//! a declarative [`Template`] that can be persisted and used by the
//! [`DeclarativeRenderer`](crate) for future renders.

use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use crate::types::{FieldMapping, LayoutConfig, Template, TemplateConfig};

/// Sentinel value stored in `created_by` to distinguish auto-generated
/// templates from user-created ones.
pub const ORCHESTRATOR_CREATED_BY: &str = "orchestrator";

/// Generate a [`Template`] from a JSON-LD payload.
///
/// Walks the top-level fields of `content` (skipping `@`-prefixed keys),
/// classifies each by key name and value shape, and produces a
/// [`TemplateConfig`] with appropriate field mappings.
///
/// The generated template uses a flex column layout with "md" spacing.
/// Fields are ordered as they appear in the JSON-LD object. Nested
/// objects are flattened using dot-notation paths (e.g., `"offers.price"`).
pub fn generate_template_from_json_ld(schema_type: &str, content: &Value) -> Template {
    let now = Utc::now().to_rfc3339();
    let mut fields = Vec::new();
    let mut found_title = false;

    if let Some(obj) = content.as_object() {
        collect_fields(obj, "", &mut fields, &mut found_title);
    }

    // Fallback: if no fields were extracted, add a single generic field
    // so the template still passes validation (at least one field required).
    if fields.is_empty() {
        fields.push(FieldMapping {
            path: "value".to_string(),
            label: Some("Value".to_string()),
            display: "text".to_string(),
            condition: None,
            style: None,
        });
    }

    let template_config = TemplateConfig {
        version: 1,
        layout: LayoutConfig {
            r#type: "flex".to_string(),
            columns: None,
            direction: Some("column".to_string()),
            spacing: Some("md".to_string()),
        },
        fields,
    };

    Template {
        id: Uuid::new_v4().to_string(),
        template_name: format!("auto_{}", schema_type),
        schema_type: schema_type.to_string(),
        principal_did: None,
        agent_did: None,
        template_config,
        version: 1,
        enabled: true,
        created_at: now.clone(),
        updated_at: now,
        created_by: Some(ORCHESTRATOR_CREATED_BY.to_string()),
    }
}

/// Recursively collect fields from a JSON-LD object map.
///
/// Uses dot-notation for nested paths (e.g., `"offers.price"`).
/// `found_title` tracks whether a title field has already been assigned
/// so only the first eligible string field becomes `"title"`.
fn collect_fields(
    obj: &serde_json::Map<String, Value>,
    prefix: &str,
    fields: &mut Vec<FieldMapping>,
    found_title: &mut bool,
) {
    for (key, value) in obj {
        if key.starts_with('@') {
            continue;
        }

        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{}.{}", prefix, key)
        };

        match value {
            Value::Null => continue,
            Value::String(s) if s.is_empty() => continue,
            Value::Object(nested) => {
                collect_fields(nested, &path, fields, found_title);
            }
            Value::Array(arr) => {
                // For arrays of objects, sample the first element to infer structure.
                if let Some(Value::Object(first_obj)) = arr.first() {
                    let arr_prefix = format!("{}.0", path);
                    collect_fields(first_obj, &arr_prefix, fields, found_title);
                }
            }
            _ => {
                let display = classify_display(key, value, *found_title);
                if display == "title" {
                    *found_title = true;
                }
                let label = humanize_key(key);

                fields.push(FieldMapping {
                    path,
                    label: Some(label),
                    display,
                    condition: None,
                    style: None,
                });
            }
        }
    }
}

/// Classify the display type for a field based on key name and value shape.
fn classify_display(key: &str, value: &Value, title_taken: bool) -> String {
    let lower_key = key.to_lowercase();

    // Date/time detection by key name
    if lower_key.contains("date") || lower_key.contains("time") {
        if let Some(s) = value.as_str() {
            if looks_like_iso_date(s) {
                return "date".to_string();
            }
        }
        // Key suggests date but value isn't a date string — still treat as date
        // if key is strongly date-like
        if lower_key.ends_with("date")
            || lower_key.ends_with("time")
            || lower_key.starts_with("date")
        {
            return "date".to_string();
        }
    }

    if let Some(s) = value.as_str() {
        // Date detection by value shape (ISO 8601)
        if looks_like_iso_date(s) {
            return "date".to_string();
        }
        if s.starts_with("http://") || s.starts_with("https://") {
            return "url".to_string();
        }
        // First string field becomes the title
        if !title_taken {
            return "title".to_string();
        }
        return "text".to_string();
    }

    // Price detection by key name for numeric values
    if value.is_number() {
        if lower_key.contains("price")
            || lower_key.contains("cost")
            || lower_key.contains("amount")
            || lower_key.contains("total")
        {
            return "price".to_string();
        }
        return "text".to_string();
    }

    // Booleans
    "text".to_string()
}

/// Convert camelCase key to "Title Case" label.
///
/// E.g., `"startDate"` → `"Start Date"`, `"name"` → `"Name"`.
fn humanize_key(key: &str) -> String {
    let mut result = String::with_capacity(key.len() + 4);
    for (i, ch) in key.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push(' ');
        }
        if i == 0 {
            for upper in ch.to_uppercase() {
                result.push(upper);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Check if a string looks like an ISO 8601 date (`YYYY-MM-DD...`).
fn looks_like_iso_date(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 10
        && bytes[0..4].iter().all(|b| b.is_ascii_digit())
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(|b| b.is_ascii_digit())
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generates_template_for_flat_object() {
        // Note: serde_json::Map is a BTreeMap — fields are iterated alphabetically.
        let content = json!({
            "@type": "Recipe",
            "name": "Pasta Carbonara",
            "description": "A classic Italian dish",
            "totalTime": "PT30M"
        });

        let template = generate_template_from_json_ld("Recipe", &content);

        assert_eq!(template.schema_type, "Recipe");
        assert_eq!(template.template_name, "auto_Recipe");
        assert_eq!(
            template.created_by,
            Some(ORCHESTRATOR_CREATED_BY.to_string())
        );
        assert!(template.enabled);
        assert_eq!(template.version, 1);
        assert!(template.principal_did.is_none());
        assert_eq!(template.template_config.layout.r#type, "flex");
        assert_eq!(
            template.template_config.layout.direction,
            Some("column".to_string())
        );

        // 3 fields: description, name, totalTime (@type skipped; BTreeMap order)
        assert_eq!(template.template_config.fields.len(), 3);

        // "description" is alphabetically first string → title
        let desc_field = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "description")
            .expect("should have description");
        assert_eq!(desc_field.display, "title");
        assert_eq!(desc_field.label, Some("Description".to_string()));

        // "name" is second string → text
        let name_field = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "name")
            .expect("should have name");
        assert_eq!(name_field.display, "text");

        // "totalTime" contains "time" → date
        let time_field = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "totalTime")
            .expect("should have totalTime");
        assert_eq!(time_field.display, "date");

        assert!(template.template_config.validate().is_ok());
    }

    #[test]
    fn generates_template_for_nested_object() {
        let content = json!({
            "@type": "Product",
            "name": "Widget",
            "offers": {
                "@type": "Offer",
                "price": 29.99,
                "priceCurrency": "USD"
            }
        });

        let template = generate_template_from_json_ld("Product", &content);

        // name + offers.price + offers.priceCurrency = 3 fields
        assert_eq!(template.template_config.fields.len(), 3);

        let price_field = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "offers.price")
            .expect("should have offers.price field");
        assert_eq!(price_field.display, "price");
        assert_eq!(price_field.label, Some("Price".to_string()));

        assert!(template.template_config.validate().is_ok());
    }

    #[test]
    fn classifies_date_fields_by_key_name() {
        let content = json!({
            "name": "Event",
            "startDate": "2026-04-15T19:00:00Z",
            "endDate": "2026-04-15T22:00:00Z"
        });

        let template = generate_template_from_json_ld("Event", &content);

        let start = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "startDate")
            .expect("should have startDate");
        assert_eq!(start.display, "date");
        assert_eq!(start.label, Some("Start Date".to_string()));

        let end = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "endDate")
            .expect("should have endDate");
        assert_eq!(end.display, "date");
    }

    #[test]
    fn classifies_date_fields_by_value_shape() {
        let content = json!({
            "name": "Trip",
            "departure": "2026-04-15T19:00:00Z",
            "note": "Have fun!"
        });

        let template = generate_template_from_json_ld("Trip", &content);

        let dep = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "departure")
            .expect("should have departure");
        assert_eq!(dep.display, "date");
    }

    #[test]
    fn classifies_url_fields() {
        let content = json!({
            "name": "Website",
            "url": "https://example.com",
            "image": "https://example.com/logo.png"
        });

        let template = generate_template_from_json_ld("WebPage", &content);

        let url_field = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "url")
            .expect("should have url field");
        assert_eq!(url_field.display, "url");

        let image_field = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "image")
            .expect("should have image field");
        assert_eq!(image_field.display, "url");
    }

    #[test]
    fn classifies_price_fields_by_key_name() {
        let content = json!({
            "name": "Product",
            "totalPrice": 199.99,
            "count": 5
        });

        let template = generate_template_from_json_ld("Product", &content);

        let price = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "totalPrice")
            .expect("should have totalPrice");
        assert_eq!(price.display, "price");

        let count = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "count")
            .expect("should have count");
        assert_eq!(count.display, "text");
    }

    #[test]
    fn skips_at_prefixed_keys() {
        let content = json!({
            "@type": "Thing",
            "@context": "https://schema.org",
            "@id": "urn:uuid:123",
            "name": "Test"
        });

        let template = generate_template_from_json_ld("Thing", &content);
        assert_eq!(template.template_config.fields.len(), 1);
        assert_eq!(template.template_config.fields[0].path, "name");
    }

    #[test]
    fn skips_null_and_empty_string_values() {
        let content = json!({
            "name": "Test",
            "empty": "",
            "nothing": null,
            "valid": "data"
        });

        let template = generate_template_from_json_ld("Thing", &content);
        assert_eq!(template.template_config.fields.len(), 2);
        assert_eq!(template.template_config.fields[0].path, "name");
        assert_eq!(template.template_config.fields[1].path, "valid");
    }

    #[test]
    fn handles_array_of_objects() {
        // BTreeMap order: "items" before "name". Within items[0]: "score" before "title".
        let content = json!({
            "name": "Results",
            "items": [
                {"title": "First", "score": 0.95},
                {"title": "Second", "score": 0.85}
            ]
        });

        let template = generate_template_from_json_ld("SearchResult", &content);

        // items.0.score + items.0.title + name = 3 fields
        assert_eq!(template.template_config.fields.len(), 3);

        // items.0.title is the first string encountered (items before name) → title
        let first_title = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "items.0.title")
            .expect("should have items.0.title");
        assert_eq!(first_title.display, "title");

        // "name" comes after items alphabetically and title is taken → text
        let name_field = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "name")
            .expect("should have name");
        assert_eq!(name_field.display, "text");

        assert!(template.template_config.validate().is_ok());
    }

    #[test]
    fn handles_empty_content() {
        let content = json!({});
        let template = generate_template_from_json_ld("Empty", &content);

        // Should create a fallback "Value" field
        assert_eq!(template.template_config.fields.len(), 1);
        assert_eq!(
            template.template_config.fields[0].label,
            Some("Value".to_string())
        );
        assert!(template.template_config.validate().is_ok());
    }

    #[test]
    fn handles_non_object_content() {
        let content = json!("Just a string");
        let template = generate_template_from_json_ld("TextResponse", &content);

        assert_eq!(template.template_config.fields.len(), 1);
        assert!(template.template_config.validate().is_ok());
    }

    #[test]
    fn generated_config_passes_validation_for_complex_payload() {
        let content = json!({
            "@type": "FlightReservation",
            "reservationId": "RES-123",
            "reservationStatus": "Confirmed",
            "reservationFor": {
                "@type": "Flight",
                "flightNumber": "UA123",
                "departureTime": "2026-04-15T19:00:00Z",
                "arrivalTime": "2026-04-15T22:00:00Z",
                "departureAirport": {
                    "name": "SFO",
                    "iataCode": "SFO"
                }
            },
            "totalPrice": 599.99,
            "priceCurrency": "USD",
            "url": "https://airline.com/booking/123"
        });

        let template = generate_template_from_json_ld("FlightReservation", &content);
        let result = template.template_config.validate();
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());

        // Check nested fields were flattened with dot paths
        assert!(template
            .template_config
            .fields
            .iter()
            .any(|f| f.path == "reservationFor.flightNumber"));
        assert!(template
            .template_config
            .fields
            .iter()
            .any(|f| f.path == "reservationFor.departureTime"));
        assert!(template
            .template_config
            .fields
            .iter()
            .any(|f| f.path == "reservationFor.departureAirport.name"));

        // totalPrice should be classified as price
        let price = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "totalPrice")
            .expect("should have totalPrice");
        assert_eq!(price.display, "price");

        // url should be classified as url
        let url = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "url")
            .expect("should have url");
        assert_eq!(url.display, "url");
    }

    #[test]
    fn humanize_key_converts_camel_case() {
        assert_eq!(humanize_key("startDate"), "Start Date");
        assert_eq!(humanize_key("streetAddress"), "Street Address");
        assert_eq!(humanize_key("name"), "Name");
        assert_eq!(humanize_key("totalPrice"), "Total Price");
        assert_eq!(humanize_key("priceCurrency"), "Price Currency");
        assert_eq!(humanize_key("url"), "Url");
    }

    #[test]
    fn iso_date_detection() {
        assert!(looks_like_iso_date("2026-04-15"));
        assert!(looks_like_iso_date("2026-04-15T19:00:00Z"));
        assert!(!looks_like_iso_date("not a date"));
        assert!(!looks_like_iso_date("2026-4-15"));
        assert!(!looks_like_iso_date("short"));
    }

    #[test]
    fn unique_ids_per_generation() {
        let content = json!({"name": "Test"});
        let t1 = generate_template_from_json_ld("Thing", &content);
        let t2 = generate_template_from_json_ld("Thing", &content);
        assert_ne!(t1.id, t2.id);
    }

    #[test]
    fn created_by_is_orchestrator() {
        let content = json!({"name": "Test"});
        let template = generate_template_from_json_ld("Thing", &content);
        assert_eq!(
            template.created_by,
            Some(ORCHESTRATOR_CREATED_BY.to_string())
        );
    }

    #[test]
    fn first_string_field_is_title_rest_are_text() {
        let content = json!({
            "title": "Main Title",
            "subtitle": "Sub Title",
            "body": "Some body text"
        });

        let template = generate_template_from_json_ld("Article", &content);
        let fields = &template.template_config.fields;

        // First string field → title
        assert_eq!(fields[0].display, "title");
        // Rest → text
        assert_eq!(fields[1].display, "text");
        assert_eq!(fields[2].display, "text");
    }

    #[test]
    fn boolean_fields_become_text() {
        let content = json!({
            "name": "Feature",
            "isActive": true,
            "isPublic": false
        });

        let template = generate_template_from_json_ld("Feature", &content);

        let active = template
            .template_config
            .fields
            .iter()
            .find(|f| f.path == "isActive")
            .expect("should have isActive");
        assert_eq!(active.display, "text");
    }

    #[test]
    fn all_price_key_variants_detected() {
        let content = json!({
            "name": "Invoice",
            "price": 10.0,
            "cost": 8.0,
            "amount": 15.0,
            "totalCost": 33.0
        });

        let template = generate_template_from_json_ld("Invoice", &content);

        for path in &["price", "cost", "amount", "totalCost"] {
            let field = template
                .template_config
                .fields
                .iter()
                .find(|f| f.path == *path)
                .unwrap_or_else(|| panic!("should have {path}"));
            assert_eq!(field.display, "price", "field {path} should be price");
        }
    }
}

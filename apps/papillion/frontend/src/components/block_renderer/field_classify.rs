use serde_json::Value;

/// Semantic classification of a JSON-LD field value.
/// Used by the generic renderer to choose visual treatment.
#[derive(Debug, PartialEq)]
pub enum FieldKind {
    /// Plain text, number, or boolean.
    Scalar,
    /// ISO 8601 date/datetime or a key hinting at temporal data.
    DateTime,
    /// Monetary value (key contains "price", "cost", "amount").
    Price,
    /// HTTP(S) URL string.
    Url,
    /// Decentralized identifier (did:key:..., did:web:..., etc.).
    Did,
    /// Nested object with an `@type` field — can be dispatched to a renderer.
    TypedObject { schema_type: String },
    /// Array of items.
    List,
    /// Nested object without `@type`.
    Object,
    /// Null or empty string — skip rendering.
    Empty,
}

/// Classify a JSON-LD field by its key name and value shape.
pub fn classify_field(key: &str, value: &Value) -> FieldKind {
    match value {
        Value::Null => FieldKind::Empty,
        Value::String(s) => classify_string(key, s),
        Value::Number(_) => {
            let lower = key.to_lowercase();
            if lower.contains("price") || lower.contains("cost") || lower.contains("amount") {
                FieldKind::Price
            } else {
                FieldKind::Scalar
            }
        }
        Value::Bool(_) => FieldKind::Scalar,
        Value::Object(map) => {
            if let Some(Value::String(t)) = map.get("@type") {
                FieldKind::TypedObject {
                    schema_type: t.clone(),
                }
            } else {
                FieldKind::Object
            }
        }
        Value::Array(_) => FieldKind::List,
    }
}

fn classify_string(key: &str, s: &str) -> FieldKind {
    if s.is_empty() {
        return FieldKind::Empty;
    }
    let lower_key = key.to_lowercase();
    if lower_key.contains("date") || lower_key.contains("time") || looks_like_iso_date(s) {
        return FieldKind::DateTime;
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return FieldKind::Url;
    }
    if s.starts_with("did:") {
        return FieldKind::Did;
    }
    FieldKind::Scalar
}

/// Check if a string looks like an ISO 8601 date (YYYY-MM-...).
fn looks_like_iso_date(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 10
        && bytes[0..4].iter().all(|b| b.is_ascii_digit())
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(|b| b.is_ascii_digit())
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(|b| b.is_ascii_digit())
}

/// Convert camelCase to "Title Case" for display (e.g., "startDate" -> "Start Date").
pub fn humanize_key(key: &str) -> String {
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

/// Convert camelCase to kebab-case for CSS classes (e.g., "startDate" -> "start-date").
pub fn camel_to_kebab(key: &str) -> String {
    let mut result = String::with_capacity(key.len() + 4);
    for (i, ch) in key.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('-');
        }
        for lower in ch.to_lowercase() {
            result.push(lower);
        }
    }
    result
}

/// Convert PascalCase schema type to lowercase-kebab for CSS (e.g., "PostalAddress" -> "postal-address").
pub fn schema_type_to_css(t: &str) -> String {
    camel_to_kebab(t)
}

/// Format an ISO 8601 datetime string for human display.
/// Falls back to the raw string if parsing is ambiguous.
pub fn format_datetime(val: &Value) -> String {
    let s = match val.as_str() {
        Some(s) => s,
        None => return val.to_string(),
    };

    // Try to produce a cleaner display: "2026-04-15T19:00:00" -> "Apr 15, 2026 7:00 PM"
    // Minimal parsing without pulling in chrono — just clean up the T separator and trailing Z.
    if s.len() >= 10 {
        let date_part = &s[..10];
        let time_part = if s.len() > 11 {
            let t = s[11..].trim_end_matches('Z').trim_end_matches("+00:00");
            // Strip seconds if :00
            if t.ends_with(":00") && t.len() > 5 {
                &t[..t.len() - 3]
            } else {
                t
            }
        } else {
            ""
        };

        if time_part.is_empty() {
            return date_part.to_string();
        }
        return format!("{} {}", date_part, time_part);
    }

    s.to_string()
}

/// Convert a scalar JSON value to a display string.
pub fn scalar_to_string(val: &Value) -> String {
    match val {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string(val).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_empty_string() {
        assert_eq!(classify_field("name", &json!("")), FieldKind::Empty);
    }

    #[test]
    fn classify_null() {
        assert_eq!(classify_field("name", &Value::Null), FieldKind::Empty);
    }

    #[test]
    fn classify_date_by_key() {
        assert_eq!(
            classify_field("startDate", &json!("2026-04-15")),
            FieldKind::DateTime
        );
    }

    #[test]
    fn classify_date_by_value() {
        assert_eq!(
            classify_field("when", &json!("2026-04-15T19:00:00")),
            FieldKind::DateTime
        );
    }

    #[test]
    fn classify_url() {
        assert_eq!(
            classify_field("website", &json!("https://example.com")),
            FieldKind::Url
        );
    }

    #[test]
    fn classify_did() {
        assert_eq!(
            classify_field("id", &json!("did:key:z6MkhaXg...")),
            FieldKind::Did
        );
    }

    #[test]
    fn classify_price_by_key() {
        assert_eq!(classify_field("totalPrice", &json!(299)), FieldKind::Price);
    }

    #[test]
    fn classify_typed_object() {
        let obj = json!({"@type": "Place", "name": "Portland"});
        assert_eq!(
            classify_field("location", &obj),
            FieldKind::TypedObject {
                schema_type: "Place".into()
            }
        );
    }

    #[test]
    fn classify_plain_object() {
        let obj = json!({"name": "Portland"});
        assert_eq!(classify_field("location", &obj), FieldKind::Object);
    }

    #[test]
    fn classify_list() {
        assert_eq!(
            classify_field("items", &json!([1, 2, 3])),
            FieldKind::List
        );
    }

    #[test]
    fn humanize_camel_case() {
        assert_eq!(humanize_key("startDate"), "Start Date");
        assert_eq!(humanize_key("streetAddress"), "Street Address");
        assert_eq!(humanize_key("name"), "Name");
    }

    #[test]
    fn camel_to_kebab_cases() {
        assert_eq!(camel_to_kebab("startDate"), "start-date");
        assert_eq!(camel_to_kebab("PostalAddress"), "postal-address");
    }
}

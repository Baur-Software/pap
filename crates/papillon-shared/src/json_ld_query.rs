//! JSON-LD semantic query support for agent capability filtering.
//!
//! [`JsonLdQuery`] provides a simple, injection-safe query language for matching
//! JSON-LD objects — primarily agent advertisement documents — against a set of
//! `@type` and property constraints.
//!
//! # Query syntax
//!
//! The query string is a whitespace-separated list of `key=value` pairs:
//!
//! | Token | Meaning |
//! |-------|---------|
//! | `@type=schema:SearchAction` | Require the object's `@type` field to equal `schema:SearchAction` |
//! | `propertyName=value` | Require `object["propertyName"] == "value"` |
//!
//! Example:
//!
//! ```text
//! @type=schema:SearchAction provider=Acme
//! ```
//!
//! Matches any JSON-LD object whose `@type` is `"schema:SearchAction"` **and**
//! whose `provider` property equals `"Acme"`.
//!
//! # Design notes
//!
//! * All comparisons are exact string equality (case-sensitive).
//! * `@type` may be a JSON string **or** a JSON array; the filter matches if any
//!   element in the array equals the requested type.
//! * Unknown or malformed tokens are silently ignored so that forward-compatible
//!   query strings do not break older implementations.
//! * This module contains **no unsafe code**, no network I/O, and no HTML
//!   rendering — all JSON-LD content is treated as plain text.

use serde_json::Value;

/// A compiled JSON-LD semantic query.
///
/// Build via [`JsonLdQuery::from_str`], then apply with [`JsonLdQuery::matches`].
#[derive(Debug, Clone, Default)]
pub struct JsonLdQuery {
    /// Optional `@type` constraint.  When `Some`, the object must have a
    /// matching `@type` value (string or array element).
    pub type_filter: Option<String>,

    /// Additional property constraints as `(property_name, expected_value)` pairs.
    ///
    /// All constraints must be satisfied simultaneously (logical AND).
    pub property_filters: Vec<(String, String)>,
}

impl JsonLdQuery {
    /// Parse a simple query string into a [`JsonLdQuery`].
    ///
    /// See the [module-level documentation](self) for the syntax.
    ///
    /// # Errors
    ///
    /// Returns `Err` only if the input string is entirely unparseable (i.e. it
    /// contains no recognisable `key=value` tokens at all).  Individual
    /// malformed tokens are skipped.
    pub fn from_str(query: &str) -> Result<Self, String> {
        let mut result = JsonLdQuery::default();
        let mut parsed_any = false;

        for token in query.split_whitespace() {
            // Each token must be `key=value`; anything else is skipped.
            if let Some((key, value)) = token.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                if key.is_empty() || value.is_empty() {
                    continue;
                }

                parsed_any = true;

                if key == "@type" {
                    result.type_filter = Some(value.to_string());
                } else {
                    result
                        .property_filters
                        .push((key.to_string(), value.to_string()));
                }
            }
        }

        if query.trim().is_empty()
            || parsed_any
            || result.type_filter.is_some()
            || !result.property_filters.is_empty()
        {
            Ok(result)
        } else {
            Err(format!(
                "no valid key=value tokens found in query: {query:?}"
            ))
        }
    }

    /// Return `true` if `json_value` satisfies all constraints in this query.
    ///
    /// An empty query (no `type_filter`, no `property_filters`) matches every value.
    ///
    /// # `@type` matching
    ///
    /// * If the JSON object's `@type` is a **string**, it must equal `type_filter`.
    /// * If it is an **array**, at least one element must equal `type_filter`.
    /// * If the object has no `@type` field and `type_filter` is `Some`, the match
    ///   fails.
    ///
    /// # Property matching
    ///
    /// Each `(property, expected_value)` constraint checks that
    /// `json_value[property]` is a JSON string equal to `expected_value`.
    /// If the property is absent or not a string the constraint fails.
    pub fn matches(&self, json_value: &Value) -> bool {
        // Type filter check
        if let Some(required_type) = &self.type_filter {
            match json_value.get("@type") {
                Some(Value::String(t)) => {
                    if t != required_type {
                        return false;
                    }
                }
                Some(Value::Array(arr)) => {
                    let found = arr
                        .iter()
                        .any(|v| v.as_str() == Some(required_type.as_str()));
                    if !found {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        // Property filter checks
        for (prop, expected) in &self.property_filters {
            match json_value.get(prop.as_str()) {
                Some(Value::String(actual)) => {
                    if actual != expected {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── from_str ────────────────────────────────────────────────────────────

    #[test]
    fn empty_query_parses_to_empty_filter() {
        let q = JsonLdQuery::from_str("").unwrap();
        assert!(q.type_filter.is_none());
        assert!(q.property_filters.is_empty());
    }

    #[test]
    fn type_only_query() {
        let q = JsonLdQuery::from_str("@type=schema:SearchAction").unwrap();
        assert_eq!(q.type_filter.as_deref(), Some("schema:SearchAction"));
        assert!(q.property_filters.is_empty());
    }

    #[test]
    fn property_only_query() {
        let q = JsonLdQuery::from_str("provider=Acme").unwrap();
        assert!(q.type_filter.is_none());
        assert_eq!(q.property_filters.len(), 1);
        assert_eq!(
            q.property_filters[0],
            ("provider".to_string(), "Acme".to_string())
        );
    }

    #[test]
    fn combined_type_and_property_query() {
        let q = JsonLdQuery::from_str("@type=schema:SearchAction provider=Acme").unwrap();
        assert_eq!(q.type_filter.as_deref(), Some("schema:SearchAction"));
        assert_eq!(q.property_filters.len(), 1);
        assert_eq!(q.property_filters[0].0, "provider");
        assert_eq!(q.property_filters[0].1, "Acme");
    }

    #[test]
    fn multiple_property_filters() {
        let q = JsonLdQuery::from_str("provider=Acme region=eu").unwrap();
        assert_eq!(q.property_filters.len(), 2);
    }

    #[test]
    fn malformed_token_is_skipped() {
        // "no-equals" has no '=' so it is skipped; "key=val" is valid
        let q = JsonLdQuery::from_str("no-equals key=val").unwrap();
        assert_eq!(q.property_filters.len(), 1);
        assert_eq!(q.property_filters[0].0, "key");
    }

    #[test]
    fn query_with_no_valid_tokens_returns_err() {
        let result = JsonLdQuery::from_str("no-equals-at-all foo bar");
        assert!(result.is_err());
    }

    // ── matches ─────────────────────────────────────────────────────────────

    #[test]
    fn empty_query_matches_anything() {
        let q = JsonLdQuery::default();
        assert!(q.matches(&json!({"@type": "schema:SearchAction"})));
        assert!(q.matches(&json!({})));
        assert!(q.matches(&json!(null)));
    }

    #[test]
    fn type_filter_matches_string_type() {
        let q = JsonLdQuery::from_str("@type=schema:SearchAction").unwrap();
        assert!(q.matches(&json!({"@type": "schema:SearchAction", "name": "DDG"})));
        assert!(!q.matches(&json!({"@type": "schema:BookAction"})));
        assert!(!q.matches(&json!({})));
    }

    #[test]
    fn type_filter_matches_array_type() {
        let q = JsonLdQuery::from_str("@type=schema:SearchAction").unwrap();
        let obj = json!({"@type": ["schema:Action", "schema:SearchAction"]});
        assert!(q.matches(&obj));

        let obj_no_match = json!({"@type": ["schema:Action", "schema:BookAction"]});
        assert!(!q.matches(&obj_no_match));
    }

    #[test]
    fn property_filter_matches_string_field() {
        let q = JsonLdQuery::from_str("provider=Acme").unwrap();
        assert!(q.matches(&json!({"provider": "Acme"})));
        assert!(!q.matches(&json!({"provider": "Other"})));
        assert!(!q.matches(&json!({})));
    }

    #[test]
    fn property_filter_does_not_match_non_string() {
        let q = JsonLdQuery::from_str("count=5").unwrap();
        // The field is a number, not a string — should not match
        assert!(!q.matches(&json!({"count": 5})));
    }

    #[test]
    fn all_constraints_must_hold() {
        let q = JsonLdQuery::from_str("@type=schema:SearchAction provider=Acme").unwrap();

        // Both satisfied
        assert!(q.matches(&json!({"@type": "schema:SearchAction", "provider": "Acme"})));

        // Only type satisfied
        assert!(!q.matches(&json!({"@type": "schema:SearchAction", "provider": "Other"})));

        // Only property satisfied
        assert!(!q.matches(&json!({"@type": "schema:BookAction", "provider": "Acme"})));

        // Neither satisfied
        assert!(!q.matches(&json!({"@type": "schema:BookAction", "provider": "Other"})));
    }

    #[test]
    fn matches_nested_object_root() {
        // Only root-level properties are checked (no deep traversal).
        let q = JsonLdQuery::from_str("@type=schema:SearchAction").unwrap();
        let nested = json!({
            "@type": "schema:SearchAction",
            "result": {
                "@type": "schema:ItemList"
            }
        });
        assert!(q.matches(&nested));
    }
}

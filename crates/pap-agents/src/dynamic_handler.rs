//! `DynamicAgentHandler` — 6-phase `AgentHandler` for config-driven agents.
//!
//! Phase 4 is hybrid: attempt HTTP endpoint first (if configured), fall back
//! to LLM. Phases 1–3 and 5–6 mirror `SimpleAgent`.
//!
//! # SSRF Defence
//! URL safety is validated at execution time (defence in depth — also enforced
//! at save time by the Tauri command layer). RFC 1918, loopback, link-local,
//! and IP-literal addresses are rejected before any network call.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde_json::Value;

use crate::dynamic::{DynamicAgentDef, HttpMethod};
use crate::llm::{LlmClient, LlmProvider};
use crate::session_store::SessionStore;

struct DynamicSession {
    query: Option<String>,
    /// All scalar properties disclosed in Phase 3 (e.g. api_key from SD-JWT vault, user-explicit params).
    disclosed_props: HashMap<String, String>,
}

pub struct DynamicAgentHandler {
    def: DynamicAgentDef,
    llm_provider: Arc<RwLock<LlmProvider>>,
    sessions: SessionStore<DynamicSession>,
    /// User-configured property values for this agent (e.g. api_token).
    /// Substituted into endpoint header templates at request time.
    agent_props: HashMap<String, String>,
}

impl DynamicAgentHandler {
    pub fn new(def: DynamicAgentDef, llm_provider: Arc<RwLock<LlmProvider>>) -> Self {
        Self {
            def,
            llm_provider,
            sessions: SessionStore::new(),
            agent_props: HashMap::new(),
        }
    }

    /// Construct with pre-loaded agent property values (e.g. from agent settings storage).
    /// Values are substituted into endpoint header templates using `{prop_name}` syntax.
    pub fn new_with_props(
        def: DynamicAgentDef,
        llm_provider: Arc<RwLock<LlmProvider>>,
        agent_props: HashMap<String, String>,
    ) -> Self {
        Self {
            def,
            llm_provider,
            sessions: SessionStore::new(),
            agent_props,
        }
    }

    fn make_llm_client(&self) -> Box<dyn LlmClient> {
        let provider = self.llm_provider.read().unwrap_or_else(|e| e.into_inner());
        (*provider).clone().into_client()
    }
}

/// JSON-escape a string value for safe injection into a JSON body template.
///
/// `serde_json::to_string` wraps the value in outer quotes; this strips them
/// so the result can be placed directly inside an existing `"..."` string in
/// the template. Prevents malformed JSON when the query contains `"`, `\n`, etc.
fn json_escape_str(s: &str) -> String {
    let serialized = serde_json::to_string(s).unwrap_or_default();
    // Strip the surrounding quotes that serde_json adds.
    serialized[1..serialized.len().saturating_sub(1)].to_string()
}

impl AgentHandler for DynamicAgentHandler {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != self.def.action {
            return Err(TransportError::ServerError(format!(
                "Unsupported action: {}",
                token.action
            )));
        }
        let session_id = uuid::Uuid::new_v4().to_string();
        let did = self
            .sessions
            .insert(session_id.clone(), DynamicSession { query: None, disclosed_props: HashMap::new() })?;
        Ok((session_id, did))
    }

    fn handle_did_exchange(
        &self,
        session_id: &str,
        _initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        if !self.sessions.exists(session_id) {
            return Err(TransportError::ServerError("Unknown session".into()));
        }
        Ok(())
    }

    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<Value>,
    ) -> Result<(), TransportError> {
        let mut query: Option<String> = None;
        let mut props: HashMap<String, String> = HashMap::new();

        for disclosure in &disclosures {
            if let Some(obj) = disclosure.as_object() {
                for (key, val) in obj {
                    if key == "@type" {
                        continue;
                    }
                    let str_val = match val {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => continue,
                    };
                    if key == "query" {
                        query = Some(str_val.clone());
                    }
                    props.insert(key.clone(), str_val);
                }
            }
        }

        self.sessions.with_mut(session_id, |data| {
            if let Some(q) = query {
                data.query = Some(q);
            }
            data.disclosed_props.extend(props);
        })?;
        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<Value, TransportError> {
        let query = self
            .sessions
            .with(session_id, |data| data.query.clone())?
            .ok_or_else(|| {
                TransportError::ServerError("No query provided in disclosures".into())
            })?;

        if let Some(endpoint) = &self.def.endpoint {
            // SSRF validation at execution time (defense in depth)
            if !crate::dynamic::is_safe_url(&endpoint.url_template) {
                return Err(TransportError::ServerError(
                    "ssrf blocked: URL failed safety check".into(),
                ));
            }

            // Fix 4: use per-agent configurable timeout instead of hardcoded 5s.
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(endpoint.timeout_secs))
                .build()
                .map_err(|e| TransportError::ServerError(format!("http client init: {e}")))?;

            // Substitute {query} first
            let mut url = endpoint.url_template.replace("{query}", &query);

            // Resolve any remaining {param} placeholders.
            // Priority: (1) disclosed props from Phase 3 (SD-JWT vault claims, user-explicit),
            //           (2) agent_props (loaded from agent_settings at registration),
            //           (3) entity extractor (LLM → heuristic)
            let extra_params = crate::entity_extractor::extract_template_params(&endpoint.url_template);
            if !extra_params.is_empty() {
                let disclosed = self
                    .sessions
                    .with(session_id, |data| data.disclosed_props.clone())?;

                let extractor = crate::entity_extractor::EntityExtractor::new(self.make_llm_client());

                // Build resolved map via extractor (covers LLM + heuristic paths)
                let mut resolved = extractor.resolve(&endpoint.url_template, &query);

                // Override with higher-priority sources: agent_props then disclosed
                for param in &extra_params {
                    if let Some(val) = self.agent_props.get(param) {
                        resolved.insert(param.clone(), val.clone());
                    }
                    if let Some(val) = disclosed.get(param) {
                        resolved.insert(param.clone(), val.clone());
                    }
                }

                for (param, val) in &resolved {
                    url = url.replace(&format!("{{{}}}", param), val);
                }
            }

            // Defense in depth: also validate after template expansion in case
            // {query} substitution changes the host (e.g. injection via fragment).
            if !crate::dynamic::is_safe_url(&url) {
                return Err(TransportError::ServerError(
                    "ssrf blocked: expanded URL failed safety check".into(),
                ));
            }

            // Fix 1: JSON-escape the query before injecting into POST body templates.
            let escaped_query = json_escape_str(&query);

            // Fix 2: Apply configured endpoint headers (supports {prop_name} substitution).
            // Fix 5: Substitute user-configured property values (e.g. {api_token}) in header values.
            let mut builder = match endpoint.method {
                HttpMethod::Get => client.get(&url),
                HttpMethod::Post => {
                    let body = endpoint
                        .body_template
                        .as_deref()
                        .unwrap_or("{}")
                        .replace("{query}", &escaped_query);
                    client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .body(body)
                }
            };

            for (key, value_template) in &endpoint.headers {
                let resolved = self
                    .agent_props
                    .iter()
                    .fold(value_template.clone(), |acc, (name, val)| {
                        acc.replace(&format!("{{{}}}", name), val)
                    });
                builder = builder.header(key.as_str(), resolved);
            }

            let response = builder.send();

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        if let Ok(json_body) = resp.json::<Value>() {
                            // Priority 1: Multi-field response_mapping → proper schema.org
                            if !endpoint.response_mapping.is_empty() {
                                let mapped = build_mapped_response(
                                    &json_body,
                                    &endpoint.response_mapping,
                                    &endpoint.response_schema_type,
                                );
                                let field_count = mapped
                                    .as_object()
                                    .map(|m| m.keys().filter(|k| !k.starts_with('@')).count())
                                    .unwrap_or(0);
                                if field_count > 0 {
                                    return Ok(mapped);
                                }
                            }

                            // Priority 2: Legacy single-field extraction with proper wrapping
                            if let Some(extracted) =
                                extract_jsonpath(&json_body, &endpoint.response_jsonpath)
                            {
                                return Ok(wrap_extracted_value(
                                    extracted,
                                    &endpoint.response_schema_type,
                                ));
                            }
                        }
                    } else {
                        // Non-2xx: the delegated action failed — surface the error.
                        // Falling through to LLM would violate the mandate: the
                        // agent was authorized to execute a specific action, not to
                        // substitute a hallucination when that action fails.
                        let body = resp.text().unwrap_or_default();
                        let user_msg = serde_json::from_str::<serde_json::Value>(&body)
                            .ok()
                            .and_then(|v| {
                                v.get("title")
                                    .or_else(|| v.get("error"))
                                    .and_then(|s| s.as_str())
                                    .map(|s| s.to_string())
                            })
                            .unwrap_or_else(|| format!("HTTP {} — no results found", status.as_u16()));
                        return Err(TransportError::ServerError(user_msg));
                    }
                }
                Err(e) => {
                    return Err(TransportError::ServerError(format!(
                        "network error: {e}"
                    )));
                }
            }
        }

        let client = self.make_llm_client();
        let text = client
            .complete(&self.def.llm_instructions, &query)
            .map_err(|e| TransportError::ServerError(format!("llm: {e}")))?;

        // Fix 3: For intent classification agents, parse LLM output as
        // pap:IntentClassification JSON rather than wrapping in a generic Answer.
        if self
            .def
            .returns
            .first()
            .map(|s| s == "pap:IntentClassification")
            .unwrap_or(false)
        {
            let cleaned = text
                .trim()
                .trim_start_matches("```json")
                .trim_start_matches("```")
                .trim_end_matches("```")
                .trim();
            if let Ok(mut parsed) = serde_json::from_str::<Value>(cleaned) {
                if parsed.get("actionType").is_some() {
                    parsed["@type"] = serde_json::json!("pap:IntentClassification");
                    return Ok(parsed);
                }
            }
        }

        Ok(serde_json::json!({
            "@context": "https://schema.org",
            "@type": "Answer",
            "text": text,
        }))
    }

    fn co_sign_receipt(
        &self,
        mut receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        receipt.executed = self.def.action.clone();
        receipt.returned = self.def.returns.first().cloned().unwrap_or_default();
        let key = self.sessions.signing_key(&receipt.session_id);
        match key {
            Some(k) => receipt.co_sign(&k),
            None => {
                let k = SessionKeypair::generate();
                receipt.co_sign(k.signing_key());
            }
        }
        Ok(receipt)
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        self.sessions.remove(session_id);
        Ok(())
    }
}

/// Build a schema.org object from field-level JSONPath mappings.
fn build_mapped_response(
    json_body: &Value,
    mapping: &HashMap<String, String>,
    schema_type: &str,
) -> Value {
    // Strip schema: prefix for standard types; leave pap: and other namespaces intact.
    let clean_type = schema_type.trim_start_matches("schema:");
    let mut obj = serde_json::Map::new();
    obj.insert("@context".into(), serde_json::json!("https://schema.org"));
    obj.insert("@type".into(), serde_json::json!(clean_type));

    for (property, jsonpath) in mapping {
        if let Some(extracted) = extract_jsonpath(json_body, jsonpath) {
            match &extracted {
                Value::Null => continue,
                Value::String(s) if s.is_empty() => continue,
                _ => {
                    obj.insert(property.clone(), extracted);
                }
            }
        }
    }

    Value::Object(obj)
}

/// Wrap a single extracted value in valid schema.org (legacy fallback).
fn wrap_extracted_value(extracted: Value, schema_type: &str) -> Value {
    let clean_type = schema_type.trim_start_matches("schema:");
    match &extracted {
        Value::Object(map) if map.contains_key("@type") => {
            let mut obj = map.clone();
            obj.entry("@context".to_string())
                .or_insert(serde_json::json!("https://schema.org"));
            Value::Object(obj)
        }
        Value::Object(map) => {
            let mut obj = map.clone();
            obj.insert("@context".into(), serde_json::json!("https://schema.org"));
            obj.insert("@type".into(), serde_json::json!(clean_type));
            Value::Object(obj)
        }
        Value::String(_) => serde_json::json!({
            "@context": "https://schema.org",
            "@type": clean_type,
            "description": extracted,
        }),
        Value::Array(_) => serde_json::json!({
            "@context": "https://schema.org",
            "@type": clean_type,
            "mainEntity": {
                "@type": "ItemList",
                "itemListElement": extracted,
            }
        }),
        _ => serde_json::json!({
            "@context": "https://schema.org",
            "@type": clean_type,
            "value": extracted,
        }),
    }
}

/// Extract a value from a JSON document using a simple JSONPath-like expression.
///
/// Supports dotted field access (e.g. `$.field.nested`) and array indexing
/// (e.g. `$.items[0]`). Does not support wildcards or filter expressions.
pub fn extract_jsonpath(value: &Value, path: &str) -> Option<Value> {
    let path = path.strip_prefix('$').unwrap_or(path);
    let segments: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
    let mut current = value.clone();
    for segment in segments {
        if let Some(bracket_pos) = segment.find('[') {
            let field = &segment[..bracket_pos];
            let index_str = segment
                .get(bracket_pos + 1..segment.len().saturating_sub(1))
                .unwrap_or("");
            let index: usize = index_str.parse().ok()?;
            if !field.is_empty() {
                current = current.get(field)?.clone();
            }
            current = current.get(index)?.clone();
        } else {
            current = current.get(segment)?.clone();
        }
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::{DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig, HttpMethod};
    use serde_json::json;
    use std::collections::HashMap;

    fn make_def_with_endpoint(url_template: &str) -> DynamicAgentDef {
        DynamicAgentDef {
            agent_did: None,
            schema_version: 1,
            version: "0.1.0".into(),
            name: "Test Agent".into(),
            provider: "Test".into(),
            description: "Test".into(),
            action: "schema:SearchAction".into(),
            object_types: vec!["schema:Thing".into()],
            requires_disclosure: vec![],
            returns: vec!["schema:SearchResult".into()],
            endpoint: Some(HttpEndpointConfig {
                url_template: url_template.into(),
                method: HttpMethod::Get,
                headers: HashMap::new(),
                body_template: None,
                response_jsonpath: "$.results[0]".into(),
                response_schema_type: "schema:SearchResultsPage".into(),
                response_mapping: HashMap::new(),
                timeout_secs: 5,
            }),
            llm_instructions: "You are helpful.".into(),
            subagents: vec![],
            source: DynamicAgentSource::UserCreated,
            operator_key_seed: None,
            published_to: vec![],
            catalog_path: None,
            configurable_properties: vec![],
            created_at: "2026-04-01T00:00:00Z".into(),
            updated_at: "2026-04-01T00:00:00Z".into(),
        }
    }

    fn make_def_llm_only() -> DynamicAgentDef {
        DynamicAgentDef {
            agent_did: None,
            schema_version: 1,
            version: "0.1.0".into(),
            name: "LLM Agent".into(),
            provider: "Test".into(),
            description: "Test".into(),
            action: "schema:SearchAction".into(),
            object_types: vec!["schema:Thing".into()],
            requires_disclosure: vec![],
            returns: vec!["schema:Answer".into()],
            endpoint: None,
            llm_instructions: "You are helpful.".into(),
            subagents: vec![],
            source: DynamicAgentSource::UserCreated,
            operator_key_seed: None,
            published_to: vec![],
            catalog_path: None,
            configurable_properties: vec![],
            created_at: "2026-04-01T00:00:00Z".into(),
            updated_at: "2026-04-01T00:00:00Z".into(),
        }
    }

    fn make_token(action: &str) -> CapabilityToken {
        let kp = pap_did::PrincipalKeypair::generate();
        let mut token = CapabilityToken::mint(
            "did:key:test".into(),
            action.into(),
            kp.did(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        token.sign(kp.signing_key()).unwrap();
        token
    }

    #[test]
    fn ssrf_blocked_at_execution() {
        let def = make_def_with_endpoint("http://10.0.0.1/data");
        let handler = DynamicAgentHandler::new(def, Arc::new(RwLock::new(LlmProvider::None)));
        let token = make_token("schema:SearchAction");
        let (sid, _) = handler.handle_token(token).unwrap();
        handler.handle_did_exchange(&sid, "did:key:peer").unwrap();
        handler
            .handle_disclosure(&sid, vec![json!({"query": "test"})])
            .unwrap();
        let result = handler.execute(&sid);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.to_lowercase().contains("ssrf"),
            "Expected 'ssrf' in error, got: {err}"
        );
    }

    #[test]
    fn ssrf_https_private_ip_blocked() {
        assert!(!crate::dynamic::is_safe_url("https://192.168.1.1/api"));
        assert!(!crate::dynamic::is_safe_url("https://172.16.0.1/api"));
        assert!(!crate::dynamic::is_safe_url("https://10.0.0.1/api"));
        assert!(!crate::dynamic::is_safe_url("https://127.0.0.1/api"));
        assert!(!crate::dynamic::is_safe_url("https://localhost/api"));
        assert!(!crate::dynamic::is_safe_url("http://example.com/api"));
    }

    #[test]
    fn ssrf_safe_urls_allowed() {
        assert!(crate::dynamic::is_safe_url("https://api.example.com/v1"));
        assert!(crate::dynamic::is_safe_url(
            "https://world.openfoodfacts.org/search"
        ));
    }

    #[test]
    fn json_escape_str_escapes_quotes() {
        assert_eq!(json_escape_str(r#"say "hello""#), r#"say \"hello\""#);
    }

    #[test]
    fn json_escape_str_escapes_newlines() {
        assert_eq!(json_escape_str("line1\nline2"), r"line1\nline2");
    }

    #[test]
    fn json_escape_str_plain_passthrough() {
        assert_eq!(json_escape_str("simple query"), "simple query");
    }

    #[test]
    fn extract_jsonpath_simple_field() {
        assert_eq!(
            extract_jsonpath(&json!({"name": "Alice"}), "$.name"),
            Some(json!("Alice"))
        );
    }

    #[test]
    fn extract_jsonpath_array_index() {
        assert_eq!(
            extract_jsonpath(&json!({"items": [1, 2, 3]}), "$.items[1]"),
            Some(json!(2))
        );
    }

    #[test]
    fn extract_jsonpath_array_root_index() {
        // HuggingFace NLU response: array at root, e.g. $[0].label
        assert_eq!(
            extract_jsonpath(&json!([{"label": "weather", "score": 0.87}]), "$[0].label"),
            Some(json!("weather"))
        );
    }

    #[test]
    fn extract_jsonpath_missing() {
        assert_eq!(extract_jsonpath(&json!({"a": 1}), "$.b"), None);
    }

    #[test]
    fn extract_jsonpath_nested_field() {
        assert_eq!(
            extract_jsonpath(&json!({"outer": {"inner": "value"}}), "$.outer.inner"),
            Some(json!("value"))
        );
    }

    #[test]
    fn extract_jsonpath_array_index_out_of_bounds() {
        assert_eq!(
            extract_jsonpath(&json!({"items": [1, 2]}), "$.items[5]"),
            None
        );
    }

    #[test]
    fn llm_none_provider_returns_error() {
        let def = make_def_llm_only();
        let handler = DynamicAgentHandler::new(def, Arc::new(RwLock::new(LlmProvider::None)));
        let token = make_token("schema:SearchAction");
        let (sid, _) = handler.handle_token(token).unwrap();
        handler.handle_did_exchange(&sid, "did:key:peer").unwrap();
        handler
            .handle_disclosure(&sid, vec![json!({"query": "hello"})])
            .unwrap();
        assert!(handler.execute(&sid).is_err());
    }

    #[test]
    fn disclosed_props_stored_from_phase3() {
        let def = make_def_llm_only();
        let handler = DynamicAgentHandler::new(def, Arc::new(RwLock::new(LlmProvider::None)));
        let token = make_token("schema:SearchAction");
        let (sid, _) = handler.handle_token(token).unwrap();
        handler.handle_did_exchange(&sid, "did:key:peer").unwrap();

        handler
            .handle_disclosure(
                &sid,
                vec![json!({"@type": "schema:SearchAction", "query": "rust lang", "api_key": "sk-live-xyz"})],
            )
            .unwrap();

        handler
            .sessions
            .with(&sid, |data| {
                assert_eq!(data.query.as_deref(), Some("rust lang"));
                assert_eq!(
                    data.disclosed_props.get("api_key"),
                    Some(&"sk-live-xyz".to_string())
                );
            })
            .unwrap();
    }

    #[test]
    fn wrong_action_rejected() {
        let def = make_def_llm_only();
        let handler = DynamicAgentHandler::new(def, Arc::new(RwLock::new(LlmProvider::None)));
        assert!(handler
            .handle_token(make_token("schema:PayAction"))
            .is_err());
    }

    #[test]
    fn unknown_session_did_exchange_errors() {
        let def = make_def_llm_only();
        let handler = DynamicAgentHandler::new(def, Arc::new(RwLock::new(LlmProvider::None)));
        assert!(handler
            .handle_did_exchange("no-such-session", "did:key:x")
            .is_err());
    }

    #[test]
    fn header_props_substituted() {
        // Verify that {api_token} in a header value is replaced by the configured prop.
        let mut props: HashMap<String, String> = HashMap::new();
        props.insert("api_token".to_string(), "hf_abc123".to_string());
        let template = "Bearer {api_token}".to_string();
        let resolved = props.iter().fold(template, |acc, (name, val)| {
            acc.replace(&format!("{{{}}}", name), val)
        });
        assert_eq!(resolved, "Bearer hf_abc123");
    }

    // ── build_mapped_response tests ──────────────────────────────────────

    #[test]
    fn mapped_response_extracts_multiple_fields() {
        let api_response = json!({
            "Heading": "Rust (programming language)",
            "AbstractText": "Rust is a multi-paradigm language...",
            "AbstractURL": "https://en.wikipedia.org/wiki/Rust_(programming_language)",
            "AbstractSource": "Wikipedia",
            "Image": ""
        });
        let mut mapping = HashMap::new();
        mapping.insert("name".into(), "$.Heading".into());
        mapping.insert("description".into(), "$.AbstractText".into());
        mapping.insert("url".into(), "$.AbstractURL".into());
        mapping.insert("source".into(), "$.AbstractSource".into());
        mapping.insert("image".into(), "$.Image".into());

        let result = build_mapped_response(&api_response, &mapping, "schema:SearchResultsPage");

        assert_eq!(result["@type"], "SearchResultsPage");
        assert_eq!(result["@context"], "https://schema.org");
        assert_eq!(result["name"], "Rust (programming language)");
        assert_eq!(
            result["description"],
            "Rust is a multi-paradigm language..."
        );
        assert_eq!(
            result["url"],
            "https://en.wikipedia.org/wiki/Rust_(programming_language)"
        );
        assert_eq!(result["source"], "Wikipedia");
        assert!(result.get("image").is_none());
    }

    #[test]
    fn mapped_response_pap_type_preserved() {
        // pap:IntentClassification @type should not be stripped of its prefix.
        let api_response = json!({"actionType": "weather", "confidence": 0.87});
        let mut mapping = HashMap::new();
        mapping.insert("actionType".into(), "$.actionType".into());
        mapping.insert("confidence".into(), "$.confidence".into());

        let result = build_mapped_response(&api_response, &mapping, "pap:IntentClassification");
        assert_eq!(result["@type"], "pap:IntentClassification");
        assert_eq!(result["actionType"], "weather");
    }

    #[test]
    fn mapped_response_skips_missing_paths() {
        let api_response = json!({"Heading": "Test"});
        let mut mapping = HashMap::new();
        mapping.insert("name".into(), "$.Heading".into());
        mapping.insert("description".into(), "$.AbstractText".into());

        let result = build_mapped_response(&api_response, &mapping, "schema:Thing");
        assert_eq!(result["name"], "Test");
        assert!(result.get("description").is_none());
    }

    #[test]
    fn mapped_response_skips_null_values() {
        let api_response = json!({"Heading": null, "Text": "hello"});
        let mut mapping = HashMap::new();
        mapping.insert("name".into(), "$.Heading".into());
        mapping.insert("description".into(), "$.Text".into());

        let result = build_mapped_response(&api_response, &mapping, "schema:Thing");
        assert!(result.get("name").is_none());
        assert_eq!(result["description"], "hello");
    }

    // ── wrap_extracted_value tests ───────────────────────────────────────

    #[test]
    fn wrap_string_uses_description_property() {
        let result = wrap_extracted_value(
            json!("A cat is a domesticated species"),
            "schema:SearchResultsPage",
        );
        assert_eq!(result["@type"], "SearchResultsPage");
        assert_eq!(result["description"], "A cat is a domesticated species");
        assert!(result.get("result").is_none());
    }

    #[test]
    fn wrap_object_with_type_preserves_it() {
        let obj = json!({
            "@type": "Person",
            "name": "Alice"
        });
        let result = wrap_extracted_value(obj, "schema:Person");
        assert_eq!(result["@type"], "Person");
        assert_eq!(result["name"], "Alice");
        assert_eq!(result["@context"], "https://schema.org");
    }

    #[test]
    fn wrap_object_without_type_adds_type() {
        let obj = json!({"name": "Bob", "age": 30});
        let result = wrap_extracted_value(obj, "schema:Person");
        assert_eq!(result["@type"], "Person");
        assert_eq!(result["name"], "Bob");
        assert_eq!(result["age"], 30);
    }

    #[test]
    fn wrap_array_creates_item_list() {
        let arr = json!(["item1", "item2"]);
        let result = wrap_extracted_value(arr, "schema:SearchResultsPage");
        assert_eq!(result["@type"], "SearchResultsPage");
        assert_eq!(result["mainEntity"]["@type"], "ItemList");
        assert_eq!(result["mainEntity"]["itemListElement"][0], "item1");
    }

    #[test]
    fn wrap_number_uses_value_property() {
        let result = wrap_extracted_value(json!(42.5), "schema:QuantitativeValue");
        assert_eq!(result["@type"], "QuantitativeValue");
        assert_eq!(result["value"], 42.5);
    }
}

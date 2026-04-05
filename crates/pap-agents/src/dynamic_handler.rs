//! `DynamicAgentHandler` — 6-phase `AgentHandler` for config-driven agents.
//!
//! Phase 4 is hybrid: attempt HTTP endpoint first (if configured), fall back
//! to LLM. Phases 1–3 and 5–6 mirror `SimpleAgent`.
//!
//! # SSRF Defence
//! URL safety is validated at execution time (defence in depth — also enforced
//! at save time by the Tauri command layer). RFC 1918, loopback, link-local,
//! and IP-literal addresses are rejected before any network call.

use std::sync::Arc;
use std::time::Duration;

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde_json::Value;

use crate::dynamic::{DynamicAgentDef, HttpMethod};
use crate::llm::LlmProvider;
use crate::session_store::SessionStore;

struct DynamicSession {
    query: Option<String>,
}

pub struct DynamicAgentHandler {
    def: DynamicAgentDef,
    llm_provider: Arc<LlmProvider>,
    sessions: SessionStore<DynamicSession>,
}

impl DynamicAgentHandler {
    pub fn new(def: DynamicAgentDef, llm_provider: Arc<LlmProvider>) -> Self {
        Self {
            def,
            llm_provider,
            sessions: SessionStore::new(),
        }
    }
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
            .insert(session_id.clone(), DynamicSession { query: None });
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
        let query = disclosures
            .iter()
            .find_map(|d| d.get("query").and_then(|v| v.as_str()))
            .map(String::from);
        if let Some(q) = query {
            self.sessions.with_mut(session_id, |data| {
                data.query = Some(q);
            })?;
        }
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

            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|e| TransportError::ServerError(format!("http client init: {e}")))?;

            let url = endpoint.url_template.replace("{query}", &query);

            let response = match endpoint.method {
                HttpMethod::Get => client.get(&url).send(),
                HttpMethod::Post => {
                    let body = endpoint
                        .body_template
                        .as_deref()
                        .unwrap_or("{}")
                        .replace("{query}", &query);
                    client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .body(body)
                        .send()
                }
            };

            if let Ok(resp) = response {
                if resp.status().is_success() {
                    if let Ok(json_body) = resp.json::<Value>() {
                        if let Some(extracted) =
                            extract_jsonpath(&json_body, &endpoint.response_jsonpath)
                        {
                            return Ok(serde_json::json!({
                                "@context": "https://schema.org",
                                "@type": endpoint.response_schema_type,
                                "result": extracted,
                            }));
                        }
                    }
                }
            }
        }

        let text = call_llm(&self.def.llm_instructions, &query, &self.llm_provider)?;
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

fn call_llm(system: &str, user: &str, provider: &LlmProvider) -> Result<String, TransportError> {
    match provider {
        LlmProvider::None => Err(TransportError::ServerError(
            "LLM fallback unavailable: no provider configured".into(),
        )),
        LlmProvider::BuiltIn { .. } => Err(TransportError::ServerError(
            "LLM fallback unavailable: BuiltIn provider requires app-layer injection".into(),
        )),
        LlmProvider::Ollama { endpoint, model } => {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| TransportError::ServerError(format!("http client: {e}")))?;
            let payload = serde_json::json!({
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user}
                ],
                "stream": false,
            });
            let resp: Value = client
                .post(format!("{endpoint}/api/chat"))
                .json(&payload)
                .send()
                .map_err(|e| TransportError::ServerError(format!("ollama request: {e}")))?
                .json()
                .map_err(|e| TransportError::ServerError(format!("ollama response: {e}")))?;
            resp["message"]["content"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    TransportError::ServerError("ollama: missing message.content".into())
                })
        }
        LlmProvider::Mistral { api_key, model } => call_openai_compatible(
            "https://api.mistral.ai/v1/chat/completions",
            api_key,
            model,
            system,
            user,
        ),
        LlmProvider::OpenAiCompatible {
            endpoint,
            api_key,
            model,
        } => call_openai_compatible(
            &format!("{endpoint}/chat/completions"),
            api_key,
            model,
            system,
            user,
        ),
    }
}

fn call_openai_compatible(
    url: &str,
    api_key: &str,
    model: &str,
    system: &str,
    user: &str,
) -> Result<String, TransportError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| TransportError::ServerError(format!("http client: {e}")))?;
    let payload = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
    });
    let resp: Value = client
        .post(url)
        .bearer_auth(api_key)
        .json(&payload)
        .send()
        .map_err(|e| TransportError::ServerError(format!("llm request: {e}")))?
        .json()
        .map_err(|e| TransportError::ServerError(format!("llm response: {e}")))?;
    resp["choices"][0]["message"]["content"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| {
            TransportError::ServerError("llm: missing choices[0].message.content".into())
        })
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
            }),
            llm_instructions: "You are helpful.".into(),
            subagents: vec![],
            source: DynamicAgentSource::UserCreated,
            operator_key_seed: None,
            published_to: vec![],
            catalog_path: None,
            created_at: "2026-04-01T00:00:00Z".into(),
            updated_at: "2026-04-01T00:00:00Z".into(),
        }
    }

    fn make_def_llm_only() -> DynamicAgentDef {
        DynamicAgentDef {
            agent_did: None,
            schema_version: 1,
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
        let handler = DynamicAgentHandler::new(def, Arc::new(LlmProvider::None));
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
        let handler = DynamicAgentHandler::new(def, Arc::new(LlmProvider::None));
        let token = make_token("schema:SearchAction");
        let (sid, _) = handler.handle_token(token).unwrap();
        handler.handle_did_exchange(&sid, "did:key:peer").unwrap();
        handler
            .handle_disclosure(&sid, vec![json!({"query": "hello"})])
            .unwrap();
        assert!(handler.execute(&sid).is_err());
    }

    #[test]
    fn wrong_action_rejected() {
        let def = make_def_llm_only();
        let handler = DynamicAgentHandler::new(def, Arc::new(LlmProvider::None));
        assert!(handler
            .handle_token(make_token("schema:PayAction"))
            .is_err());
    }

    #[test]
    fn unknown_session_did_exchange_errors() {
        let def = make_def_llm_only();
        let handler = DynamicAgentHandler::new(def, Arc::new(LlmProvider::None));
        assert!(handler
            .handle_did_exchange("no-such-session", "did:key:x")
            .is_err());
    }
}

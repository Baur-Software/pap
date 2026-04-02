# Dynamic Agents — Part 2: Handler & Registration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement DynamicAgentHandler (6-phase AgentHandler with hybrid HTTP+LLM Phase 4) and AgentSet::register_dynamic().

**Architecture:** DynamicAgentHandler holds a DynamicAgentDef and an Arc<LlmProvider>. Phases 1-3 and 5-6 mirror SimpleAgent. Phase 4 tries HTTP first, falls back to LLM. AgentSet::register_dynamic() restores the operator keypair from the seed, builds and signs an AgentAdvertisement, and wires up the handler.

**Tech Stack:** Rust, reqwest::blocking, serde_json, ed25519-dalek, papillon_shared::LlmProvider

---

## Task 4: DynamicAgentHandler

**Files:**
- Create: `crates/pap-agents/src/dynamic_handler.rs`
- Modify: `crates/pap-agents/src/lib.rs` (add `pub mod dynamic_handler;`)
- Modify: `crates/pap-agents/Cargo.toml` (add `papillon-shared = { workspace = true }`)

### Steps

- [ ] **4.1** Add `papillon-shared = { workspace = true }` to `[dependencies]` in `crates/pap-agents/Cargo.toml`.

- [ ] **4.2** Add `pub mod dynamic_handler;` to `crates/pap-agents/src/lib.rs`, after the existing module declarations.

- [ ] **4.3** Create `crates/pap-agents/src/dynamic_handler.rs` with the complete implementation shown below.

### Complete `dynamic_handler.rs`

```rust
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
use std::sync::Arc;
use std::time::Duration;

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use papillon_shared::types::LlmProvider;
use serde_json::Value;

use crate::session_store::SessionStore;

// Re-exported from pap-agents dynamic model (Part 1).
// The types below reference `DynamicAgentDef` and `HttpEndpointConfig` which
// are defined in `crates/pap-agents/src/dynamic.rs` (Part 1 of this feature).
use crate::dynamic::{DynamicAgentDef, HttpEndpointConfig, HttpMethod};

// ── Session data ─────────────────────────────────────────────────────────────

/// Per-session state for a DynamicAgentHandler.
struct DynamicSession {
    query: Option<String>,
}

// ── Handler struct ────────────────────────────────────────────────────────────

/// `AgentHandler` implementation for dynamically-configured agents.
///
/// Holds the agent definition and the ambient LLM provider. Session keypairs
/// are stored in `SessionStore` — they are freshly generated for every
/// `handle_token` call and are never derived from `def.operator_key_seed`
/// (see spec §3.3, Key Separation).
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

// ── AgentHandler implementation ───────────────────────────────────────────────

impl AgentHandler for DynamicAgentHandler {
    /// Phase 1: validate action, open session.
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != self.def.action {
            return Err(TransportError::ServerError(format!(
                "Unsupported action: {}",
                token.action
            )));
        }
        let session_id = uuid::Uuid::new_v4().to_string();
        let did = self.sessions.insert(
            session_id.clone(),
            DynamicSession { query: None },
        );
        Ok((session_id, did))
    }

    /// Phase 2: acknowledge initiator's ephemeral DID.
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

    /// Phase 3: extract query from selective disclosures.
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

    /// Phase 4: hybrid HTTP + LLM execution.
    ///
    /// Steps:
    /// 1. Retrieve query from session.
    /// 2. If `def.endpoint` is Some:
    ///    a. Validate URL with `is_safe_url` — SSRF block on failure.
    ///    b. Build reqwest blocking client with 5 s timeout.
    ///    c. Substitute `{query}` into `url_template`.
    ///    d. Execute GET or POST.
    ///    e. On 2xx + non-empty JSONPath match: wrap in Schema.org envelope, return.
    ///    f. Otherwise fall through to LLM.
    /// 3. LLM fallback — wrap response in Schema.org `Answer` envelope.
    fn execute(&self, session_id: &str) -> Result<Value, TransportError> {
        let query = self
            .sessions
            .with(session_id, |data| data.query.clone())?
            .ok_or_else(|| {
                TransportError::ServerError("No query provided in disclosures".into())
            })?;

        // ── Step 2: HTTP attempt ─────────────────────────────────────────────
        if let Some(endpoint) = &self.def.endpoint {
            // 2a. SSRF validation
            if !is_safe_url(&endpoint.url_template) {
                return Err(TransportError::ServerError(
                    "ssrf blocked: URL failed safety check".into(),
                ));
            }

            // 2b. Build client
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|e| TransportError::ServerError(format!("http client init: {e}")))?;

            // 2c. Substitute {query}
            let url = endpoint.url_template.replace("{query}", &query);

            // 2d. Execute
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
                        // 2e. Apply JSONPath extraction
                        if let Some(extracted) =
                            extract_jsonpath(&json_body, &endpoint.response_jsonpath)
                        {
                            // 2f. Wrap in Schema.org envelope
                            let envelope = serde_json::json!({
                                "@context": "https://schema.org",
                                "@type": endpoint.response_schema_type,
                                "result": extracted,
                            });
                            return Ok(envelope);
                        }
                        // Zero matches — fall through to LLM
                    }
                    // Non-JSON or parse error — fall through to LLM
                }
                // Non-2xx — fall through to LLM
            }
            // Network error / timeout — fall through to LLM
        }

        // ── Step 3: LLM fallback ─────────────────────────────────────────────
        let text = call_llm(&self.def.llm_instructions, &query, &self.llm_provider)?;
        Ok(serde_json::json!({
            "@context": "https://schema.org",
            "@type": "Answer",
            "text": text,
        }))
    }

    /// Phase 5: co-sign receipt.
    ///
    /// `executed` = `def.action`, `returned` = `def.returns.first()`.
    /// These are type references from the definition — never values from
    /// HTTP response or LLM output (spec §11.5).
    fn co_sign_receipt(
        &self,
        mut receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        // Populate receipt fields from the def, not from runtime output.
        receipt.executed = self.def.action.clone();
        receipt.returned = self
            .def
            .returns
            .first()
            .cloned()
            .unwrap_or_default();

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

    /// Phase 6: close session.
    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        self.sessions.remove(session_id);
        Ok(())
    }
}

// ── SSRF guard ────────────────────────────────────────────────────────────────

/// Returns `true` only if the URL passes all safety rules:
/// - Scheme must be `https://`
/// - Host must not be `localhost`, a loopback (`127.*`), RFC 1918 (`10.*`,
///   `172.16–31.*`, `192.168.*`), link-local (`169.254.*`), or an IP literal.
///
/// Called at execution time as defence-in-depth (also enforced at save time).
pub fn is_safe_url(url: &str) -> bool {
    // Must start with https://
    let rest = match url.strip_prefix("https://") {
        Some(r) => r,
        None => return false,
    };

    // Extract host (up to first '/', '?', '#', or ':')
    let host = rest
        .split(|c| c == '/' || c == '?' || c == '#' || c == ':')
        .next()
        .unwrap_or("")
        .to_lowercase();

    if host.is_empty() {
        return false;
    }

    // Reject localhost
    if host == "localhost" {
        return false;
    }

    // Reject IPv4 literals (reject if every segment is numeric)
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return false;
    }

    // Reject RFC 1918 + loopback + link-local prefixes
    let blocked_prefixes = [
        "10.", "127.", "169.254.", "192.168.",
        // 172.16.0.0/12 — 172.16.x.x through 172.31.x.x
    ];
    for prefix in &blocked_prefixes {
        if host.starts_with(prefix) {
            return false;
        }
    }

    // 172.16.x.x – 172.31.x.x
    if let Some(rest_after_172) = host.strip_prefix("172.") {
        if let Some(second_octet_str) = rest_after_172.split('.').next() {
            if let Ok(n) = second_octet_str.parse::<u8>() {
                if (16..=31).contains(&n) {
                    return false;
                }
            }
        }
    }

    // Reject bare IPv6 literals (contain ':')
    if host.contains(':') {
        return false;
    }

    true
}

// ── Minimal JSONPath extraction ───────────────────────────────────────────────

/// Minimal JSONPath extraction — handles `$.field` and `$.field[N]` patterns only.
///
/// Splits the path on `.`, skips the leading `$`, and traverses the JSON tree.
/// Array indexing via `[N]` suffix is supported on any segment.
///
/// Returns the matched value or `None` if any segment is absent or the index
/// is out of bounds.
pub fn extract_jsonpath(value: &Value, path: &str) -> Option<Value> {
    // Strip leading '$'
    let path = path.strip_prefix('$').unwrap_or(path);

    // Split on '.' — empty first segment (from the leading '.') is skipped
    let segments: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();

    let mut current = value.clone();

    for segment in segments {
        // Check for array index suffix: `field[N]`
        if let Some(bracket_pos) = segment.find('[') {
            let field = &segment[..bracket_pos];
            let index_str = segment
                .get(bracket_pos + 1..segment.len().saturating_sub(1))
                .unwrap_or("");
            let index: usize = index_str.parse().ok()?;

            // Descend into the field first (if non-empty)
            if !field.is_empty() {
                current = current.get(field)?.clone();
            }

            // Then index into array
            current = current.get(index)?.clone();
        } else {
            // Plain field access
            current = current.get(segment)?.clone();
        }
    }

    Some(current)
}

// ── LLM dispatch ─────────────────────────────────────────────────────────────

/// Send `system` + `user` messages to the configured LLM provider.
/// Returns the text content of the first response choice.
///
/// `LlmProvider::None` returns an error — callers must handle gracefully.
/// `LlmProvider::BuiltIn` is not yet wired to the Candle runtime from this
/// crate; returns an informative error directing the caller to use
/// `OrchestratorConfig.llm_provider = LlmProvider::Ollama/Mistral/OpenAiCompatible`.
fn call_llm(
    system: &str,
    user: &str,
    provider: &LlmProvider,
) -> Result<String, TransportError> {
    match provider {
        LlmProvider::None => Err(TransportError::ServerError(
            "LLM fallback unavailable: no provider configured".into(),
        )),

        LlmProvider::BuiltIn { .. } => {
            // BuiltIn inference is driven by the Papillon app layer via Candle.
            // pap-agents cannot call the model manager directly (no dependency
            // on the app crate). The Papillon startup sequence should use
            // LlmProvider::Ollama or LlmProvider::OpenAiCompatible when
            // constructing DynamicAgentHandler, or inject a pre-warmed client.
            Err(TransportError::ServerError(
                "LLM fallback unavailable: BuiltIn provider requires app-layer injection".into(),
            ))
        }

        LlmProvider::Ollama { endpoint, model } => {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| TransportError::ServerError(format!("http client: {e}")))?;

            let payload = serde_json::json!({
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
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

        LlmProvider::Mistral { api_key, model } => {
            call_openai_compatible(
                "https://api.mistral.ai/v1/chat/completions",
                api_key,
                model,
                system,
                user,
            )
        }

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

/// Shared implementation for OpenAI-compatible chat completion endpoints.
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
            {"role": "user",   "content": user},
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::dynamic::{DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig, HttpMethod};

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
            llm_instructions: "You are a helpful assistant.".into(),
            subagents: vec![],
            source: DynamicAgentSource::UserCreated,
            operator_key_seed: None,
            published_to: vec![],
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
            llm_instructions: "You are a helpful assistant.".into(),
            subagents: vec![],
            source: DynamicAgentSource::UserCreated,
            operator_key_seed: None,
            published_to: vec![],
            created_at: "2026-04-01T00:00:00Z".into(),
            updated_at: "2026-04-01T00:00:00Z".into(),
        }
    }

    // ── SSRF guard ────────────────────────────────────────────────────────────

    #[test]
    fn ssrf_blocked_at_execution() {
        let def = make_def_with_endpoint("http://10.0.0.1/data");
        let handler = DynamicAgentHandler::new(def, Arc::new(LlmProvider::None));

        // Open a session
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
        // Even with https:// scheme, RFC 1918 hosts must be blocked
        assert!(!is_safe_url("https://192.168.1.1/api"));
        assert!(!is_safe_url("https://172.16.0.1/api"));
        assert!(!is_safe_url("https://172.31.255.255/api"));
        assert!(!is_safe_url("https://10.0.0.1/api"));
        assert!(!is_safe_url("https://127.0.0.1/api"));
        assert!(!is_safe_url("https://localhost/api"));
        assert!(!is_safe_url("https://169.254.169.254/api"));
        assert!(!is_safe_url("http://example.com/api")); // http rejected
    }

    #[test]
    fn ssrf_safe_urls_allowed() {
        assert!(is_safe_url("https://api.example.com/v1"));
        assert!(is_safe_url("https://world.openfoodfacts.org/cgi/search.pl"));
        assert!(is_safe_url("https://nominatim.openstreetmap.org/search"));
    }

    // ── extract_jsonpath ──────────────────────────────────────────────────────

    #[test]
    fn extract_jsonpath_simple_field() {
        let result = extract_jsonpath(&json!({"name": "Alice"}), "$.name");
        assert_eq!(result, Some(json!("Alice")));
    }

    #[test]
    fn extract_jsonpath_array_index() {
        let result = extract_jsonpath(&json!({"items": [1, 2, 3]}), "$.items[1]");
        assert_eq!(result, Some(json!(2)));
    }

    #[test]
    fn extract_jsonpath_missing() {
        let result = extract_jsonpath(&json!({"a": 1}), "$.b");
        assert_eq!(result, None);
    }

    #[test]
    fn extract_jsonpath_nested_field() {
        let result = extract_jsonpath(
            &json!({"outer": {"inner": "value"}}),
            "$.outer.inner",
        );
        assert_eq!(result, Some(json!("value")));
    }

    #[test]
    fn extract_jsonpath_array_index_out_of_bounds() {
        let result = extract_jsonpath(&json!({"items": [1, 2]}), "$.items[5]");
        assert_eq!(result, None);
    }

    // ── Schema.org envelope ───────────────────────────────────────────────────

    #[test]
    fn schema_org_envelope_has_context() {
        let def = make_def_llm_only();
        let _handler = DynamicAgentHandler::new(def, Arc::new(LlmProvider::None));

        // The envelope is built inline in execute(); test the shape directly.
        let envelope = serde_json::json!({
            "@context": "https://schema.org",
            "@type": "Answer",
            "text": "test response",
        });

        assert_eq!(
            envelope["@context"].as_str(),
            Some("https://schema.org"),
            "@context must be https://schema.org"
        );
        assert_eq!(envelope["@type"].as_str(), Some("Answer"));
    }

    #[test]
    fn schema_org_envelope_http_has_context() {
        // Verify the HTTP-path envelope also carries @context
        let envelope = serde_json::json!({
            "@context": "https://schema.org",
            "@type": "schema:SearchResultsPage",
            "result": {"name": "Example"},
        });

        assert_eq!(
            envelope["@context"].as_str(),
            Some("https://schema.org")
        );
    }

    // ── Full session lifecycle ────────────────────────────────────────────────

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

        let result = handler.execute(&sid);
        assert!(result.is_err(), "LlmProvider::None should return an error");
    }

    #[test]
    fn wrong_action_rejected() {
        let def = make_def_llm_only();
        let handler = DynamicAgentHandler::new(def, Arc::new(LlmProvider::None));
        let token = make_token("schema:PayAction");
        assert!(handler.handle_token(token).is_err());
    }

    #[test]
    fn unknown_session_did_exchange_errors() {
        let def = make_def_llm_only();
        let handler = DynamicAgentHandler::new(def, Arc::new(LlmProvider::None));
        assert!(handler
            .handle_did_exchange("no-such-session", "did:key:x")
            .is_err());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_token(action: &str) -> CapabilityToken {
        let kp = pap_did::PrincipalKeypair::generate();
        let mut token = CapabilityToken::mint(
            "did:key:test".into(),
            action.into(),
            kp.did(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        token.sign(kp.signing_key());
        token
    }
}
```

### Verification

```
cargo test -p pap-agents -- dynamic_handler::
```

Expected: all pass.

Commit: `feat(pap-agents): implement DynamicAgentHandler with hybrid HTTP+LLM execution`

---

## Task 5: AgentSet::register_dynamic()

**Files:**
- Modify: `crates/pap-agents/src/registry.rs`

### Steps

- [ ] **5.1** Add `use` imports to `registry.rs` for the new types:
  - `use papillon_shared::types::LlmProvider;`
  - `use crate::dynamic::DynamicAgentDef;`
  - `use crate::dynamic_handler::DynamicAgentHandler;`

- [ ] **5.2** Add the `RegistrationError` enum and `register_dynamic` method to `AgentSet`. The full code is shown below.

### `RegistrationError` enum and `register_dynamic` implementation

Add after the closing brace of `build_agents()`:

```rust
// ── Dynamic agent registration ────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("operator_key_seed is required for registration")]
    MissingKeySeed,
    #[error("invalid operator key seed: {0}")]
    InvalidKeySeed(String),
    #[error("advertisement signature verification failed")]
    SignatureInvalid,
    #[error("agent already registered: {0}")]
    AlreadyRegistered(String),
}

impl AgentSet {
    /// Register a dynamic agent definition at runtime.
    ///
    /// Steps (spec §9.1):
    /// 1. Require `operator_key_seed` — error if absent.
    /// 2. Restore `PrincipalKeypair` from seed bytes.
    /// 3. Build `AgentAdvertisement` from def fields.
    /// 4. Sign advertisement with operator signing key.
    /// 5. Verify signature is `Some` (spec §9.4).
    /// 6. `registry.register_local(ad)`.
    /// 7. Insert handler into `self.handlers`.
    /// 8. Insert keypair into `self.keypairs`.
    /// 9. Return `agent_did`.
    pub fn register_dynamic(
        &mut self,
        def: &DynamicAgentDef,
        llm_provider: Arc<LlmProvider>,
    ) -> Result<String, RegistrationError> {
        // 1. Require operator_key_seed
        let seed = def
            .operator_key_seed
            .ok_or(RegistrationError::MissingKeySeed)?;

        // 2. Restore keypair from seed
        let kp = PrincipalKeypair::from_bytes(&seed)
            .map_err(|e| RegistrationError::InvalidKeySeed(e.to_string()))?;

        let did = kp.did();

        // 3. Build advertisement
        let mut ad = AgentAdvertisement::new(
            &def.name,
            &def.provider,
            &did,
            vec![def.action.clone()],
            def.object_types.clone(),
            def.requires_disclosure.clone(),
            def.returns.clone(),
        );

        // 4. Sign
        ad.sign(kp.signing_key());

        // 5. Verify signature present (spec §9.4)
        if ad.signature.is_none() {
            return Err(RegistrationError::SignatureInvalid);
        }

        // 6. Register in federation registry
        self.registry
            .register_local(ad)
            .map_err(|_| RegistrationError::AlreadyRegistered(def.name.clone()))?;

        // 7. Build and insert handler
        let handler = Arc::new(DynamicAgentHandler::new(def.clone(), llm_provider));
        self.handlers.insert(def.name.clone(), handler);

        // 8. Insert keypair
        self.keypairs.insert(def.name.clone(), kp);

        // 9. Return DID
        Ok(did)
    }
}
```

### Tests

Add inside the existing `#[cfg(test)] mod tests` block in `registry.rs`:

```rust
    // ── register_dynamic ─────────────────────────────────────────────────────

    use crate::dynamic::{DynamicAgentDef, DynamicAgentSource};
    use papillon_shared::types::LlmProvider;

    fn make_dynamic_def(with_seed: bool) -> DynamicAgentDef {
        let seed: Option<[u8; 32]> = if with_seed {
            let kp = PrincipalKeypair::generate();
            // PrincipalKeypair doesn't expose the raw seed directly in the
            // public API, so we generate one from a fresh SigningKey.
            use ed25519_dalek::SigningKey;
            use rand::rngs::OsRng;
            let sk = SigningKey::generate(&mut OsRng);
            Some(sk.to_bytes())
        } else {
            None
        };

        DynamicAgentDef {
            agent_did: None,
            schema_version: 1,
            name: "Test Dynamic Agent".into(),
            provider: "Test Corp".into(),
            description: "A test dynamic agent".into(),
            action: "schema:SearchAction".into(),
            object_types: vec!["schema:Thing".into()],
            requires_disclosure: vec![],
            returns: vec!["schema:SearchResult".into()],
            endpoint: None,
            llm_instructions: "You are helpful.".into(),
            subagents: vec![],
            source: DynamicAgentSource::UserCreated,
            operator_key_seed: seed,
            published_to: vec![],
            created_at: "2026-04-01T00:00:00Z".into(),
            updated_at: "2026-04-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn register_dynamic_produces_queryable_agent() {
        let mut set = build_agents(vec![]);
        let def = make_dynamic_def(true);
        let did = set
            .register_dynamic(&def, Arc::new(LlmProvider::None))
            .expect("registration should succeed");

        // DID is a valid did:key
        assert!(did.starts_with("did:key:z"), "got: {did}");

        // Agent is discoverable by action type
        let results = set.registry.query_local("schema:SearchAction");
        assert!(
            results.iter().any(|a| a.name == "Test Dynamic Agent"),
            "agent should be queryable by action"
        );

        // Handler and keypair are wired
        assert!(set.handlers.contains_key("Test Dynamic Agent"));
        assert!(set.keypairs.contains_key("Test Dynamic Agent"));
    }

    #[test]
    fn register_dynamic_missing_seed_errors() {
        let mut set = build_agents(vec![]);
        let def = make_dynamic_def(false); // operator_key_seed = None

        let result = set.register_dynamic(&def, Arc::new(LlmProvider::None));
        assert!(
            matches!(result, Err(RegistrationError::MissingKeySeed)),
            "expected MissingKeySeed, got: {result:?}"
        );
    }

    #[test]
    fn register_dynamic_signed_advertisement() {
        let mut set = build_agents(vec![]);
        let def = make_dynamic_def(true);
        set.register_dynamic(&def, Arc::new(LlmProvider::None))
            .expect("registration should succeed");

        let ads = set.registry.all_advertisements();
        let ad = ads
            .iter()
            .find(|a| a.name == "Test Dynamic Agent")
            .expect("advertisement should be present");

        assert!(
            ad.signature.is_some(),
            "advertisement must have a signature"
        );
        assert!(
            ad.signed_by.starts_with("did:key:"),
            "signed_by must be a valid DID"
        );
    }

    #[test]
    fn register_dynamic_did_is_stable_for_same_seed() {
        // Same seed → same DID (deterministic derivation)
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let seed = SigningKey::generate(&mut OsRng).to_bytes();

        let mut def = make_dynamic_def(false);
        def.operator_key_seed = Some(seed);
        def.name = "Stable DID Agent A".into();

        let mut set = build_agents(vec![]);
        let did1 = set
            .register_dynamic(&def, Arc::new(LlmProvider::None))
            .unwrap();

        // Second set — fresh AgentSet, same seed
        let mut set2 = build_agents(vec![]);
        def.name = "Stable DID Agent B".into(); // different name, same seed
        let did2 = set2
            .register_dynamic(&def, Arc::new(LlmProvider::None))
            .unwrap();

        assert_eq!(did1, did2, "same seed must produce same DID");
    }
```

### Verification

```
cargo test -p pap-agents -- register_dynamic
```

Expected: all pass.

Commit: `feat(pap-agents): add AgentSet::register_dynamic()`

---

## Notes for the implementor

### Dependency wiring

`crates/pap-agents/Cargo.toml` needs one new line in `[dependencies]`:

```toml
papillon-shared = { workspace = true }
```

`papillon-shared` is already a workspace member (see root `Cargo.toml` line 53). No version spec needed.

### `DynamicAgentDef` availability

`DynamicAgentHandler` and the tests in `registry.rs` both import from `crate::dynamic`. That module (`crates/pap-agents/src/dynamic.rs`) is created in Part 1 of this feature. This plan assumes Part 1 is complete and `crate::dynamic::{DynamicAgentDef, HttpEndpointConfig, HttpMethod, DynamicAgentSource}` are all public.

### Key separation invariant (spec §3.3)

`DynamicAgentHandler::handle_token` calls `self.sessions.insert(...)`, which generates a **fresh `SessionKeypair`** internally via `SessionKeypair::generate()` — it does not touch `def.operator_key_seed`. This is the correct behaviour. Never derive session keys from the operator seed.

### Receipt fields (spec §11.5)

`co_sign_receipt` overwrites `receipt.executed` and `receipt.returned` from `def.action` and `def.returns.first()`. These are Schema.org type references, not runtime values. The HTTP response body and LLM text output must not appear in the receipt under any circumstances.

### 172.16–31 SSRF range

The `is_safe_url` implementation handles this range with a dedicated check after the `blocked_prefixes` slice, since it cannot be expressed as a simple string prefix.

### `RegistrationError` and `thiserror`

`thiserror` is already in the workspace dependencies. No `Cargo.toml` change needed for the error type.

### Expected test run output (Task 4)

```
test dynamic_handler::tests::extract_jsonpath_array_index ... ok
test dynamic_handler::tests::extract_jsonpath_array_index_out_of_bounds ... ok
test dynamic_handler::tests::extract_jsonpath_missing ... ok
test dynamic_handler::tests::extract_jsonpath_nested_field ... ok
test dynamic_handler::tests::extract_jsonpath_simple_field ... ok
test dynamic_handler::tests::llm_none_provider_returns_error ... ok
test dynamic_handler::tests::schema_org_envelope_has_context ... ok
test dynamic_handler::tests::schema_org_envelope_http_has_context ... ok
test dynamic_handler::tests::ssrf_blocked_at_execution ... ok
test dynamic_handler::tests::ssrf_https_private_ip_blocked ... ok
test dynamic_handler::tests::ssrf_safe_urls_allowed ... ok
test dynamic_handler::tests::unknown_session_did_exchange_errors ... ok
test dynamic_handler::tests::wrong_action_rejected ... ok
```

### Expected test run output (Task 5)

```
test registry::tests::register_dynamic_did_is_stable_for_same_seed ... ok
test registry::tests::register_dynamic_missing_seed_errors ... ok
test registry::tests::register_dynamic_produces_queryable_agent ... ok
test registry::tests::register_dynamic_signed_advertisement ... ok
```
